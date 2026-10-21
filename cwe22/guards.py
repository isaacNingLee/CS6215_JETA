"""Checked guard contracts: prove that a FileOutputStream sink is protected by a
directory-containment check, so that Tai-e flows into it can be set aside.

Two restricted checkers from CS6215_proj run on each revision's own source. Neither
executes subject code, reads a fix label or calls an LLM:

* ``path``: java/SourceFacts.java (parse only) plus ``path_contract`` below, a
  straight-line template for ``java.nio.file.Path`` containment: a rejecting
  ``if (!p.startsWith(r))`` on absolute, normalized Paths, where ``r`` is the one
  trusted Path parameter, before ``new java.io.FileOutputStream(p.toFile())``.
  A String prefix of canonical/absolute paths is refuted with a counterexample:
  ``/tmp/outside/probe`` starts with ``/tmp/out`` but is not inside it.
* ``canonical``: java/CanonicalGuardCheck.java (javac-attributed) for
  ``if (!file.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator))``
  rejecting before a direct ``new FileOutputStream(file)`` in the same block, where
  ``file = new File(root, name)`` and ``root`` is the method's one File parameter.

Model: ordinary JDK paths, a trusted root, no symlinks or filesystem races. Any
other code shape is unknown and keeps its flows (fail closed). The canonical
checker was written after inspecting MPXJ, so it is an in-sample extension.
"""
import json
import os
import re
import subprocess
from pathlib import Path

from . import config
from .scoring import TAIE_METHOD

JAVA = Path(__file__).resolve().parent / "java"
CHECKERS = [JAVA / "SourceFacts.java", JAVA / "CanonicalGuardCheck.java"]
MODEL = "JDK POSIX paths; trusted root; no symlinks, filesystem races or custom Path providers"
SINK_TARGET = "<java.io.FileOutputStream: void <init>(java.io.File)>"
SINK_SITE = re.compile(r"(<[^>]+>)\[(\d+)@L(-?\d+)\]")


def compile_checkers(jhome, out):
    """Compile both checkers (Jackson comes from the Tai-e jar); return the java launcher."""
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run([os.path.join(jhome, "bin/javac"), "--release", "17", "-cp", str(config.TAIE_JAR),
                    "-d", str(out)] + [str(p) for p in CHECKERS], check=True, capture_output=True, text=True)
    return [os.path.join(jhome, "bin/java"), "-cp", os.pathsep.join([str(out), str(config.TAIE_JAR)])]


def source_files(checkout):
    """Production sources that allocate a FileOutputStream, the only sink either checker proves."""
    return sorted(p for p in (checkout / "src/main/java").rglob("*.java")
                  if "FileOutputStream" in p.read_text(errors="replace"))


# ---- path template (port of CS6215_proj scripts/guard_contracts.py) ------------------
def call(e):
    if not e or e.get("kind") != "METHOD_INVOCATION":
        return None, None, []
    select = e["select"]
    return select.get("name"), select.get("base"), e["args"]


def ident(e):
    return e.get("name") if e and e.get("kind") == "IDENTIFIER" else None


def path_info(e, env):
    """A deliberately small expression language; no facts are inferred from names."""
    name = ident(e)
    if name:
        return env.get(name)
    op, base, args = call(e)
    info = path_info(base, env) if base else None
    if info and info["type"] == "path":
        if op == "toAbsolutePath" and not args:
            return dict(info, absolute=True)
        if op == "normalize" and not args:
            return dict(info, normalized=True)
        if op == "resolve" and len(args) == 1 and ident(args[0]) in env and env[ident(args[0])]["type"] == "string":
            return dict(info, normalized=False, trusted_root=False)
    return None


def prefix_kind(guard, method):
    """``path_string_prefix`` when both sides of startsWith are canonical/absolute path Strings."""
    _, receiver, args = call(guard["call"])
    if len(args) != 1:
        return "unsupported"
    definitions = {}
    for v in method["variables"]:
        if v["line"] < guard["line"]:
            definitions.setdefault(v["name"], []).append(v.get("value"))

    def file_string(e, visited=()):
        op, _, a = call(e)
        if op in ("getCanonicalPath", "getAbsolutePath") and not a:
            return True
        name = ident(e)
        if name and any(ident(w.get("target")) == name and w["line"] <= guard["line"] for w in method["writes"]):
            return False
        if name and name not in visited and len(definitions.get(name, [])) == 1:
            return file_string(definitions[name][0], visited + (name,))
        return False
    # Separator-suffixed roots and other String prefixes are not classified here.
    return "path_string_prefix" if file_string(receiver) and file_string(args[0]) else "unsupported"


def rejects(node):
    if not node:
        return False
    if node["kind"] == "BLOCK":
        return len(node["statements"]) == 1 and rejects(node["statements"][0])
    return node["kind"] in ("THROW", "RETURN")


def protect_sink(method, guard):
    """Straight-line proof for one explicitly qualified FileOutputStream allocation."""
    if len(method["sinks"]) != 1:
        return False, "Requires exactly one supported filesystem sink"
    sink = method["sinks"][0]
    if sink["type"] != "java.io.FileOutputStream":
        return False, "Parse-only proof requires an explicitly qualified JDK sink"
    if len(sink["args"]) != 1:
        return False, "Unsupported sink overload"
    op, value, args = call(sink["args"][0])
    checked = ident(value)
    if op != "toFile" or args or not checked:
        return False, "Sink must consume the checked local Path via toFile()"
    if sum(p["type"] == "java.nio.file.Path" for p in method["parameters"]) != 1:
        return False, "Requires exactly one explicitly trusted Path root parameter"
    env = {}
    for parameter in method["parameters"]:
        if parameter["type"] == "java.nio.file.Path":
            env[parameter["name"]] = dict(type="path", absolute=False, normalized=False, trusted_root=True)
        elif parameter["type"] in ("String", "java.lang.String"):
            env[parameter["name"]] = dict(type="string")
    seen_guard = False
    for statement in method["body"]["statements"]:
        kind = statement["kind"]
        if kind == "VARIABLE" and statement["line"] < sink["line"]:
            if statement["type"] != "java.nio.file.Path" or statement["name"] in env:
                return False, "Unsupported declaration or shadowed variable"
            info = path_info(statement.get("value"), env)
            if not info:
                return False, "Unsupported path expression"
            env[statement["name"]] = info
            continue
        if kind == "IF":
            condition = statement["condition"]
            if condition.get("kind") != "LOGICAL_COMPLEMENT" or statement["else"] is not None:
                return False, "Requires a single negative containment check without else"
            predicate = condition["operand"]
            name, base, arguments = call(predicate)
            if (name != "startsWith" or len(arguments) != 1 or predicate["line"] != guard["line"]
                    or predicate["text"] != guard["text"]):
                return False, "Guard does not match the checked AST node"
            left, right = ident(base), ident(arguments[0])
            if left != checked or left == right or not right or not rejects(statement["then"]):
                return False, "Wrong checked value/root or nonterminating rejection"
            if not all(env.get(v, {}).get("absolute") and env[v].get("normalized") for v in (left, right)):
                return False, "Both Paths must be absolute and normalized"
            if not env[right].get("trusted_root"):
                return False, "Containment root depends on untrusted input"
            seen_guard = True
            continue
        if statement["line"] <= sink["line"] <= statement["end_line"]:
            # Only a direct allocation, optionally assigned to a local; no nested control flow.
            expression = statement.get("value")
            if kind not in ("VARIABLE", "EXPRESSION_STATEMENT") or not expression or expression != sink:
                return False, "Sink is nested in unsupported control flow or expression"
            return seen_guard, ("Straight-line rejecting guard protects unchanged normalized Path" if seen_guard
                                else "Sink occurs before a validated guard")
        return False, "Unsupported statement before sink (including reassignment/control flow)"
    return False, "Sink not found in supported straight-line block"


def path_contract(method, guard):
    """Contract record for one ``startsWith`` guard inside an ``if`` of ``method``."""
    result = dict(checker="path", cls=method["qualified_class"], method=method["method_name"],
                  guard_line=guard["line"], guard=guard["text"], status="unknown", protects_sink=False)
    if prefix_kind(guard, method) == "path_string_prefix":
        return dict(result, status="refuted", reason="Path String prefix has no directory-component boundary",
                    counterexample=dict(root="/tmp/out", candidate="/tmp/outside/probe"))
    protected, reason = protect_sink(method, guard)
    result.update(status="supported" if protected else "unknown", protects_sink=protected, reason=reason)
    if protected:
        result["sink_line"] = method["sinks"][0]["line"]
    return result


# ---- running both checkers ------------------------------------------------------------
def check(checkout, classpath, java):
    """Contracts of one revision; ``protected`` lists the sinks either checker proves."""
    files = [str(p) for p in source_files(checkout)]
    contracts = []
    if files:
        methods = json.loads(subprocess.run(java + ["SourceFacts"] + files, check=True, capture_output=True,
                                            text=True, timeout=300).stdout)
        contracts += [path_contract(m, g) for m in methods for g in m["guards"]]
        rows = json.loads(subprocess.run(java + ["CanonicalGuardCheck", os.pathsep.join(map(str, classpath))] + files,
                                         check=True, capture_output=True, text=True, timeout=300).stdout)
        contracts += [dict(checker="canonical", cls=r["class"], status="supported" if r["protects_sink"] else "unknown",
                           **{k: v for k, v in r.items() if k != "class"}) for r in rows]
    protected = sorted({(c["cls"].replace("$", "."), c["method"], c["sink_line"], c["checker"])
                        for c in contracts if c["protects_sink"]})
    return dict(model=MODEL, files=[os.path.relpath(f, checkout) for f in files], contracts=contracts,
                protected=[dict(cls=c, method=m, line=l, checker=k) for c, m, l, k in protected])


def sink_key(cls, method, line):
    """Nested classes compared with dots; a constructor is named after its class."""
    cls = cls.replace("$", ".")
    return cls, cls.rsplit(".", 1)[-1] if method == "<init>" else method, int(line)


def guarded(flow, protected, catalogue):
    """True if the flow's sink call is a FileOutputStream(File) allocation at a protected sink.

    The call target is confirmed from the catalogue call site; anything unconfirmed is kept.
    """
    sink = flow[len("TaintFlow{"):-1].split(" -> ")[1]
    match = SINK_SITE.match(sink)
    if not match:
        return False
    signature, index, line = match.groups()
    owner, _, name = TAIE_METHOD.fullmatch(signature).groups()
    if sink_key(owner, name, line) not in {sink_key(p["cls"], p["method"], p["line"]) for p in protected}:
        return False
    site = next((c for c in catalogue["call_sites"] if c["id"] == "{}#{}".format(signature, index)), None)
    return site is not None and SINK_TARGET in (site["declared_target"], site["resolved_target"])
