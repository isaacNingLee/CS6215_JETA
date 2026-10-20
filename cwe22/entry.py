"""LLM-written entry drivers that replace the manual adapters.

Per project and model: (1) the model picks at most five entry classes from the
public class list; (2) it writes ``AutoEntry.main`` from their ``javap -public``
signatures; (3) the driver must compile against both revisions, with up to three
repair rounds fed the javac errors (from round two the model is told to delete
calls it cannot fix). No CVE, fix label, manual adapter or manual policy is shown.
"""
import os
import re
import subprocess

from . import config, llm

PROMPTS = config.DATA / "prompts/relax"
MAX_CLASSES = 5
SIGNATURE_LIMIT = 30000
REPAIR_ROUNDS = 3
DECLARATION = re.compile(r"^public (?:\w+ )*(?:class|interface|enum) ([\w.]+)", re.M)
JAVA_BLOCK = re.compile(r"```java\s*([\s\S]*?)```")


def javap(jhome, classpath, classes):
    return subprocess.check_output([os.path.join(jhome, "bin/javap"), "-public", "-cp",
                                    os.pathsep.join(map(str, classpath))] + classes, text=True)


def public_classes(jhome, classpaths):
    """Public top-level classes present in every revision."""
    found = []
    for classpath in classpaths:
        root = classpath[0]
        names = sorted(p.relative_to(root).with_suffix("").as_posix().replace("/", ".")
                       for p in root.rglob("*.class") if "$" not in p.name)
        found.append(set(DECLARATION.findall(javap(jhome, [root], names))))
    return sorted(set.intersection(*found))


def java_block(record):
    match = JAVA_BLOCK.search(llm.answer_text(record))
    if not match or "class AutoEntry" not in match.group(1):
        raise ValueError("No AutoEntry Java block")
    return match.group(1).strip() + "\n"


def compile_errors(source, classpaths, jhome, folder):
    """javac errors of the driver against each revision (empty list: compiles everywhere)."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "AutoEntry.java"
    path.write_text(source)
    errors = []
    for variant, classpath in zip(config.VARIANTS, classpaths):
        result = subprocess.run([os.path.join(jhome, "bin/javac"), "-g", "--release", "17", "-cp",
                                 os.pathsep.join(map(str, classpath)), "-d", str(folder / variant), str(path)],
                                capture_output=True, text=True)
        if result.returncode:
            errors.append(variant + ":\n" + result.stderr[-3000:])
    return errors


def generate(model, folder, driver, classpaths, jhome, build, key):
    """Write ``driver`` (AutoEntry.java) for one project; return a status record.

    ``folder`` keeps one JSON file per request. With ``key`` None nothing is sent
    and the record reports how far saved responses reach.
    """
    record = dict(model=model, status="pending")
    def ask(name, system, user):
        return llm.ask(folder / (name + ".json"), llm.request_body(model, user, system=system), key)

    classes = public_classes(jhome, classpaths)
    record["public_classes"] = len(classes)
    answer = ask("pick", (PROMPTS / "pick.txt").read_text(), "\n".join(classes))
    if answer is None:
        return record
    try:
        picked = [c for c in llm.answer_json(answer).get("classes", []) if c in classes][:MAX_CLASSES]
        if not picked:
            raise ValueError("No listed class was picked")
        text = javap(jhome, classpaths[0], picked)
        record.update(picked=picked, signatures_truncated=len(text) > SIGNATURE_LIMIT)
        user = "Classes and public signatures:\n" + text[:SIGNATURE_LIMIT]
        prompt = (PROMPTS / "driver.txt").read_text()
        answer = ask("driver", prompt, user)
        if answer is None:
            return record
        source = java_block(answer)
        errors = compile_errors(source, classpaths, jhome, build)
        record["attempts"] = [errors]
        for round_ in range(1, REPAIR_ROUNDS + 1):
            if not errors:
                break
            repair = (user + "\n\nYour previous program:\n```java\n" + source + "```\nCompiler errors:\n"
                      + "\n".join(errors)[:6000])
            if round_ >= 2:  # later rounds: prefer deleting an unfixable call to guessing again
                repair += "\n" + (PROMPTS / "prune.txt").read_text()
            answer = ask("repair{}".format(round_), prompt, repair)
            if answer is None:
                return record
            source = java_block(answer)
            errors = compile_errors(source, classpaths, jhome, build)
            record["attempts"].append(errors)
    except (ValueError, KeyError, IndexError, subprocess.SubprocessError) as exc:
        record.update(status="failed", error="{}: {}".format(type(exc).__name__, exc))
        return record
    if errors:
        record.update(status="failed", error="Driver does not compile after {} repair round(s)".format(REPAIR_ROUNDS))
        return record
    driver.parent.mkdir(parents=True, exist_ok=True)
    driver.write_text(source)
    record["status"] = "compiled"
    return record

