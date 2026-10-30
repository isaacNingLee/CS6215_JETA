"""Relaxed Tai-e policies: the shared CWE-22 kit plus catalogue candidate sources.

H1 is the frozen kit alone (data/taie/kit, plus the shared string transfers). H2a
adds every catalogue call that could introduce a path-like value; H2b keeps only
the candidates an LLM does not reject. No fix label or manual policy is read. The
candidate rule is the one frozen before any relaxed-hint score in CS6215_proj.
"""
import json
import re
import shutil
from collections import Counter

from . import config
from .scoring import TAIE_METHOD, flow_endpoints

KIT = config.DATA / "taie/kit"
STRING_TRANSFERS = config.DATA / "taie/common/string-transfers.yml"
SELECT_PROMPT = config.DATA / "prompts/relax/select.txt"
BATCH = 25  # candidates per selection request
PAYLOAD_LIMIT = 40000  # characters per selection request

CANDIDATE_RETURNS = {"java.lang.String", "java.io.File", "java.nio.file.Path"}
# Value-transforming utilities; their propagation belongs in transfer rules.
UTILITY_CLASSES = {"java.lang.String", "java.lang.StringBuilder", "java.lang.StringBuffer", "java.lang.Object",
                   "java.lang.Class", "java.lang.Throwable", "java.lang.Integer", "java.lang.Long", "java.lang.Short",
                   "java.lang.Byte", "java.lang.Double", "java.lang.Float", "java.lang.Character", "java.lang.Boolean",
                   "java.io.File", "java.nio.file.Path", "java.nio.file.Paths", "java.nio.file.Files"}
# A call taking one of these is treated as a transformer of its input, not an introducer.
TRANSFORM_PARAMS = {"java.lang.String", "java.lang.CharSequence", "java.io.File", "java.nio.file.Path",
                    "byte[]", "char[]"}
SOURCE_SITE = re.compile(r"\[(\d+)@L-?\d+\] (?:\S+ = )?invoke\w+ (?:\S+)\.([\w$<>]+)\(")


def kit_sources():
    return sorted(set(re.findall(r'method: "(<[^"]+>)"', (KIT / "sources.yml").read_text())))


def is_candidate(method):
    if method["constructor"] or method["return_type"] not in CANDIDATE_RETURNS:
        return False
    cls = method["declaring_class"]
    if cls in UTILITY_CLASSES or cls.endswith(("Exception", "Error")) or method["name"] == "toString":
        return False
    return not TRANSFORM_PARAMS.intersection(method["parameter_types"])


def called_targets(catalogue):
    called = {}
    for call in catalogue["call_sites"]:
        for target in set(call["possible_targets"]) | {call["resolved_target"], call["declared_target"]}:
            called.setdefault(target, []).append(call)
    return called


def candidate_sources(catalogue):
    """Called, value-introducing methods that return a path-like type."""
    called = called_targets(catalogue)
    return sorted(m["signature"] for m in catalogue["methods"] if m["signature"] in called and is_candidate(m))


def source_yaml(signatures):
    if not signatures:
        return "# Candidate sources\nsources: []\n"
    return "# Candidate sources\nsources:\n" + "".join(
        '  - {{ kind: call, method: "{}", index: result }}\n'.format(s) for s in signatures)


def write_policy(directory, extra_sources=None):
    """Manual-free policy: kit files + shared string transfers (+ extra call sources)."""
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    for path in sorted(KIT.glob("*.yml")):
        shutil.copy2(path, directory / path.name)
    shutil.copy2(STRING_TRANSFERS, directory / STRING_TRANSFERS.name)
    extra = sorted(set(extra_sources or []) - set(kit_sources()))
    if extra_sources is not None:
        (directory / "candidate-sources.yml").write_text(source_yaml(extra))
    return extra


def declaring_class(signature):
    return TAIE_METHOD.fullmatch(signature).group(1)


def app_scoped(flows, classes):
    """Application scope: both endpoint methods belong to project or entry classes."""
    return [f for f in flows if all(declaring_class(s) in classes for s in flow_endpoints(f))]


def attribute(flow, catalogue, candidates):
    """Candidate source methods that can explain a flow's source call (over-approximate)."""
    source = flow[len("TaintFlow{"):-1].split(" -> ")[0]
    caller = flow_endpoints(flow)[0]
    match = SOURCE_SITE.search(source)
    if not match:
        raise ValueError("Unsupported source endpoint: " + source)
    index, name = match.groups()
    call = next((c for c in catalogue["call_sites"] if c["id"] == caller + "#" + index), None)
    if call is not None:
        targets = set(call["possible_targets"]) | {call["resolved_target"], call["declared_target"]}
        exact = sorted(targets & set(candidates))
        if exact:
            return exact, "call_site"
    return sorted(c for c in candidates if TAIE_METHOD.fullmatch(c).group(3) == name), "name"


def selection_payload(candidates, catalogues):
    """Up to three catalogue call-site windows per candidate, with citable IDs K1, K2, ..."""
    called = [called_targets(c) for c in catalogues]
    items, sites = [], {}
    for number, signature in enumerate(sorted(candidates), 1):
        calls = []
        for index in called:
            for call in index.get(signature, []):
                if all(call["id"] != c["id"] for c in calls):
                    calls.append(call)
        method = next(m for c in catalogues for m in c["methods"] if m["signature"] == signature)
        shown = []
        for call in calls[:3]:
            kid = "K{}".format(len(sites) + 1)
            sites[kid] = "C{:02d}".format(number)
            shown.append(dict(id=kid, caller=call["caller"], line=call["line"],
                              code=((call.get("source_context") or {}).get("text") or "")[:900]))
        items.append(dict(id="C{:02d}".format(number), signature=signature,
                          declared_in_project=method["project_class"], call_sites=shown))
    payload = dict(scope="Java CWE-22 source selection; candidates already reach a path sink in a static run",
                   project_label="subject", candidates=items)
    if len(json.dumps(payload)) > PAYLOAD_LIMIT:
        raise ValueError("Selection payload exceeds {} characters".format(PAYLOAD_LIMIT))
    return payload, sites


def validate_selection(answer, payload, sites):
    """Every candidate gets one decision; invalid or uncited decisions become unknown."""
    ids = {c["id"] for c in payload["candidates"]}
    rows = answer.get("sources") if isinstance(answer, dict) else None
    decisions = {cid: dict(id=cid, decision="unknown", reason="Missing/invalid review", evidence=[]) for cid in ids}
    if not isinstance(rows, list):
        return decisions, ["Expected sources list"], 0
    counts = Counter(r.get("id") for r in rows if isinstance(r, dict))
    errors, valid = [], 0
    for row in rows:
        try:
            cid = row["id"]
            if cid not in ids or counts[cid] != 1 or row["decision"] not in ("source", "not_source", "unknown"):
                raise ValueError("Invalid/duplicate identity or decision")
            if not isinstance(row.get("reason"), str) or not row["reason"].strip():
                raise ValueError("Missing reason")
            evidence = row.get("evidence")
            if not isinstance(evidence, list) or any(sites.get(e) != cid for e in evidence):
                raise ValueError("Unknown citation for " + cid)
            if row["decision"] != "unknown" and not evidence:
                raise ValueError("Decisive selection needs a citation: " + cid)
            decisions[cid] = row
            valid += 1
        except (ValueError, KeyError, TypeError) as exc:
            errors.append(str(exc))
    errors += ["Missing decision for " + cid for cid in sorted(ids) if counts[cid] == 0]
    return decisions, errors, valid


def selected_sources(payload, decisions):
    """Everything not validly rejected is kept (an omitted candidate counts as unknown)."""
    ids = {c["id"]: c["signature"] for c in payload["candidates"]}
    return sorted(ids[cid] for cid, d in decisions.items() if d["decision"] != "not_source")
