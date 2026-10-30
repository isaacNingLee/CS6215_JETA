"""JETA, the proposed pipeline: agreement guard -> Jev judges the hinted answers -> blind checklist (Jev).

For one Tai-e configuration, project, revision and sample k, starting from the agreement
guard's priority tier (agreement.py, JETA stages 1-2, sample k of its readers):

3. **Judge.** Jev (TypeSafe's decision model, OpenRouter's decisions endpoint) reads both
   hinted LLMs' answers to the configuration's hinted prompt (sample k) and the code of each
   tier location, and answers one yes/no question per location (JUDGE_QUESTION). A location
   is kept when p >= 0.5. When a model did not answer that configuration in the relaxation
   run (H2b/E, where each model sees its own configuration), it answers the owner's hinted
   prompt here, with its own saved hinted settings.
4. **Checklist.** DeepSeek writes one CWE-22 checklist per sample from CWE-22's description
   alone (data/prompts/checklist/blind.txt; no subject, code, fix or result is shown): safe
   patterns, each a list of yes/no conditions. Jev answers checklist k for each location's
   code; a location is dropped when some pattern has every condition at p >= 0.5.

Each stage only removes locations; both rules were fixed before any judgement was scored.
What Jev reads for a location: java/MethodContext.java (parse only) on the revision's
checkout, i.e. the method (every overload), the fields and constructors of its class and the
same-class methods it calls; a location outside the project's production source has none
(the judge sees NO_CODE; the checklist keeps it). Every call is saved once and never resent.
"""
import hashlib
import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from . import agreement, config, llm, relax, taie
from .report import f4, pct, ranged
from .subjects import check_dataset, fix_labels, manifest
from .util import capture, read_json, sha256, write_json

BLIND = config.DATA / "prompts/checklist/blind.txt"
CONTEXT = Path(__file__).resolve().parent / "java/MethodContext.java"
AGENTS = ("qwen", "deepseek")  # the hinted LLMs whose answers the judge reads
GENERATOR = "deepseek"  # writes the checklists
JEV = "typesafe/jev-1.13"
DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions"
THRESHOLD = 0.5
CHECKLIST_TASK = ("Java code that a taint analysis reported as a possible path traversal (CWE-22). "
                  "The questions are about the method under review.")
JUDGE_TASK = ("Two agents analysed Java code for path traversal (CWE-22). Their final answers follow, then the "
              "code of each method in question.")
JUDGE_QUESTION = ("True if the agents' final answers conclude that the method {method} is part of a path traversal "
                  "vulnerability (it builds, passes or opens the attacker-controlled path).")
NO_CODE = "(not in the project's production source)"
STAGES = [("guard", "Agreement guard"), ("judged", "+ Jev (hinted answers)"), ("checked", "+ checklist (Jev)")]
VERSION = 1  # bump to recompute cached method contexts


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def fill(template, **values):
    """Templates contain JSON braces, so placeholders are replaced literally."""
    text = template.read_text().rstrip("\n")
    for name, value in values.items():
        text = text.replace("{" + name + "}", value)
    return text


def content(record):
    """An answer's text as the judge sees it (a truncated answer is shown as is)."""
    try:
        text = record["response"]["choices"][0]["message"].get("content") or ""
    except (KeyError, IndexError, TypeError):
        text = ""
    return text.strip() or "(no answer)"


# ---- guard tier and method contexts ---------------------------------------------------------
def guard_tier(agreement_run):
    """(rows by (config, project, variant, sample), sample count) of the agreement guard."""
    predictions = read_json(config.RESULTS / agreement_run / "predictions.json")
    return ({(r["config"], r["project"], r["variant"], r["sample"]): r for r in predictions},
            max(r["sample"] for r in predictions))


def level_configs(levels):
    return [c for c in agreement.configs(list(config.MODELS)) if c[0] in levels]


def wanted(index, cfgs):
    """{(project, variant): {(class, method)}} in the priority tier of any configuration in ``cfgs``."""
    found = {}
    for (cfg, project, variant, _), row in index.items():
        if cfg in cfgs and row["status"] == "predicted":
            found.setdefault((project, variant), set()).update(tuple(x) for x in row["priority"])
    return found


def compile_context(classes):
    jhome = taie.java_home()
    classes.mkdir(parents=True, exist_ok=True)
    subprocess.run([os.path.join(jhome, "bin/javac"), "--release", "17", "-nowarn", "-cp", str(config.TAIE_JAR),
                    "-d", str(classes), str(CONTEXT)], check=True, capture_output=True, text=True)
    return [os.path.join(jhome, "bin/java"), "-cp", os.pathsep.join([str(classes), str(config.TAIE_JAR)]),
            "MethodContext"]


def render_code(rows, checkout, cls, method):
    blocks = ["// File: {}\n// Method under review: {}.{}\n{}".format(
        Path(r["file"]).relative_to(checkout), cls, method, "\n\n".join(m["text"] for m in r["members"]))
        for r in rows if r["members"]]
    return "\n\n".join(blocks) or None


def contexts(out, locations):
    """{(project, variant): {"Class.method": code or None}}; cached in results/<run>/context."""
    stamp = dict(version=VERSION, context_sha256=sha256(CONTEXT))
    java, result = None, {}
    for (project, variant), locs in sorted(locations.items()):
        path = out / "context" / "{}-{}.json".format(project, variant)
        commit = manifest()["subjects"][project][variant]
        cached = read_json(path) if path.is_file() else {}
        if cached.get("stamp") != stamp:
            cached = dict(project=project, variant=variant, commit=commit, stamp=stamp, locations={})
        missing = sorted(l for l in locs if "{}.{}".format(*l) not in cached["locations"])
        if missing:
            checkout = config.SUBJECTS / project / variant
            if capture(["git", "-C", checkout, "rev-parse", "HEAD"]) != commit:
                raise RuntimeError("{} is not at the pinned commit {}".format(checkout, commit))
            if java is None:
                java = compile_context(config.RAW / out.name / "context")
            sources = [(f, f.read_text(errors="replace")) for f in sorted((checkout / "src/main/java").rglob("*.java"))]
            requests = []
            for cls, method in missing:
                declared = re.compile(r"\b(class|interface|enum)\s+{}\b".format(re.escape(cls)))
                requests += [{"file": str(f), "class": cls, "method": method} for f, text in sources
                             if declared.search(text)]
            request = config.RAW / out.name / "context" / "request-{}-{}.json".format(project, variant)
            write_json(request, requests)
            rows = json.loads(subprocess.run(java + [str(request)], check=True, capture_output=True,
                                             text=True).stdout) if requests else []
            for cls, method in missing:
                mine = [r for r in rows if r["class"] == cls and r["method"] == method]
                cached["locations"]["{}.{}".format(cls, method)] = render_code(mine, checkout, cls, method)
            print("  contexts {} {}: {} new location(s)".format(project, variant, len(missing)), flush=True)
            write_json(path, cached)
        result[project, variant] = cached["locations"]
    return result


# ---- the checklist ----------------------------------------------------------------------------
def patterns(record):
    """[(name, [condition, ...]), ...] from a generator answer; ValueError if unusable. An empty
    list is a valid checklist (the writer saw no way the code could be protected): nothing is dropped."""
    rows = llm.answer_json(record).get("safe_patterns")
    if not isinstance(rows, list):
        raise ValueError("No safe_patterns list in the checklist")
    found = []
    for row in rows:
        conditions = row.get("conditions") if isinstance(row, dict) else None
        if not isinstance(conditions, list) or not conditions or \
                not all(isinstance(c, str) and c.strip() for c in conditions):
            raise ValueError("A safe pattern has no yes/no conditions")
        found.append((str(row.get("name", "")).strip(), [c.strip() for c in conditions]))
    return found


def question_ids(found):
    """[[id, ...] per pattern] and {id: condition}."""
    groups = [["p{}_c{}".format(i, j) for j in range(1, len(conditions) + 1)]
              for i, (_, conditions) in enumerate(found, 1)]
    text = {q: c for ids, (_, conditions) in zip(groups, found) for q, c in zip(ids, conditions)}
    return groups, text


def checklist_body(code, found):
    _, text = question_ids(found)
    return dict(model=JEV, state=dict(task=CHECKLIST_TASK, code=code), questions={
        q: dict(type="noul", instructions="True if the answer to this question is yes: " + c) for q, c in text.items()})


class Run:
    def __init__(self, out, relax_run="261020h", baseline=relax.BASELINE):
        self.out = out
        self.relax_dir = config.RESULTS / relax_run
        self.relax = relax.Run(self.relax_dir, list(config.PROJECTS), list(AGENTS), baseline=baseline)

    # ---- hinted answers ----------------------------------------------------------------------
    def answer_path(self, level, cfg, short, project, variant, sample):
        """The saved hinted answer when ``short`` answered ``cfg`` there, else this run's own call."""
        if relax.taie_config(level, short) == cfg:
            return self.relax.cell_path(short, level, project, variant, sample)
        return self.out / "hinted" / cfg / short / "{}-{}-s{}.json".format(project, variant, sample)

    def question(self, level, cfg, project, variant, sample):
        """The hinted request of the model that owns ``cfg``; None when it has no configuration."""
        owner = next(s for s in AGENTS if relax.taie_config(level, s) == cfg)
        return read_json(self.relax.cell_path(owner, level, project, variant, sample)).get("request")

    def settings(self, level, short):
        """``short``'s saved hinted request settings at ``level`` (its budget there)."""
        root = self.relax.baseline if level == "hinted" else self.relax_dir
        arm = "hinted" if level == "hinted" else level
        for path in sorted((root / "llm" / "{}-{}".format(short, arm)).glob("*.json")):
            request = read_json(path).get("request")
            if request:
                return {k: v for k, v in request.items() if k != "messages"}
        raise RuntimeError("No saved hinted request for {} at {}".format(short, level))

    def answers(self, level, cfg, project, variant, sample, key=False):
        """Both hinted answers (records); with ``key`` (None = dry run) a missing one is asked."""
        request = self.question(level, cfg, project, variant, sample)
        records = []
        for short in AGENTS:
            path = self.answer_path(level, cfg, short, project, variant, sample)
            if path.is_file():
                records.append(read_json(path))
            elif request is None or key is False:
                records.append(None)
            else:
                records.append(llm.ask(path, dict(self.settings(level, short), messages=request["messages"]), key))
        return records

    # ---- stage 1: the judge -----------------------------------------------------------------
    def judge_body(self, records, priority, codes):
        names = ["{}.{}".format(*x) for x in priority]
        return dict(model=JEV, state=dict(task=JUDGE_TASK, agent_answers=[content(r) for r in records],
                                          methods={n: codes.get(n) or NO_CODE for n in names}),
                    questions={"m{}".format(i): dict(type="noul", instructions=JUDGE_QUESTION.format(method=n))
                               for i, n in enumerate(names, 1)})

    def judge_path(self, body):
        return self.out / "judge" / "{}.json".format(digest(json.dumps(body, sort_keys=True)))

    def judged(self, level, cfg, project, variant, sample, priority, codes, key=False):
        """(kept, failure); kept is None while a call is missing; a failed judgement keeps everything."""
        if not priority:
            return [], None
        records = self.answers(level, cfg, project, variant, sample, key)
        if any(r is None for r in records):
            return None, None
        body = self.judge_body(records, priority, codes)
        path = self.judge_path(body)
        record = read_json(path) if path.is_file() else (
            None if key is False else llm.ask(path, body, key, url=DECISIONS_URL))
        if record is None:
            return None, None
        try:
            answers = record["response"]["answers"]
            return [x for i, x in enumerate(priority, 1)
                    if float(answers["m{}".format(i)]["noul"]) >= THRESHOLD], None
        except (KeyError, TypeError, ValueError) as exc:
            return list(priority), "judge: {}".format(record.get("error", exc))

    # ---- stage 2: the checklist ---------------------------------------------------------------
    def checklist_path(self, sample):
        return self.out / "checklists" / "blind-s{}.json".format(sample)

    def checklist_answer_path(self, code, sample):
        return self.out / "answers" / "checklist-s{}".format(sample) / "{}.json".format(digest(code))

    def checklist(self, sample):
        """(patterns, failure); (None, None) before the checklist exists; [] if it is empty or unusable."""
        path = self.checklist_path(sample)
        if not path.is_file():
            return None, None
        record = read_json(path)
        try:
            return patterns(record), None
        except (ValueError, KeyError, IndexError) as exc:
            return [], "checklist s{}: {}".format(sample, record.get("error", exc))

    def dropped(self, code, sample, key=False):
        """(dropped, failure); dropped is None while a call is missing. No code: kept."""
        if code is None:
            return False, None
        found, failure = self.checklist(sample)
        if found is None:
            return None, None
        if not found:
            return False, failure
        path = self.checklist_answer_path(code, sample)
        record = read_json(path) if path.is_file() else (
            None if key is False else llm.ask(path, checklist_body(code, found), key, url=DECISIONS_URL))
        if record is None:
            return None, None
        groups, _ = question_ids(found)
        try:
            answers = record["response"]["answers"]
            yes = {q: float(answers[q]["noul"]) >= THRESHOLD for ids in groups for q in ids}
        except (KeyError, TypeError, ValueError) as exc:
            return False, "checklist answer s{}: {}".format(sample, record.get("error", exc))
        return any(all(yes[q] for q in ids) for ids in groups), None

    # ---- the pipeline -------------------------------------------------------------------------
    def stages(self, level, cfg, project, variant, sample, priority, codes, key=False):
        """{stage: locations} for one tier, plus failures; a stage is None while a call is missing."""
        judged, failure = self.judged(level, cfg, project, variant, sample, priority, codes, key)
        failures = [failure] if failure else []
        checked = None
        if judged is not None:
            decisions = [self.dropped(codes.get("{}.{}".format(*x)), sample, key) for x in judged]
            if all(d[0] is not None for d in decisions):
                checked = [x for x, d in zip(judged, decisions) if not d[0]]
                failures += sorted({d[1] for d in decisions if d[1]})
        return dict(guard=list(priority), judged=judged, checked=checked), failures


def tier_cells(index, n, levels, samples):
    """(level, cfg, suffix, project, variant, sample, guard row) for every tier."""
    for level, cfg, suffix in level_configs(levels):
        for p in config.PROJECTS:
            for v in config.VARIANTS:
                for k in range(1, samples + 1):
                    yield level, cfg, suffix, p, v, k, index.get((cfg, p, v, min(k, n)))


def execute(out, agreement_run="261021g", relax_run="261020h", baseline=relax.BASELINE, samples=config.SAMPLES,
            levels=tuple(relax.LEVELS), workers=8, dry_run=False):
    """Make every missing call (hinted answers, judgements, checklists); True when none is missing."""
    run = Run(out, relax_run, baseline)
    index, n = guard_tier(agreement_run)
    codes = contexts(out, wanted(index, {c[1] for c in level_configs(levels)}))
    key = None if dry_run else config.secret("OPENROUTER_API_KEY")
    missing = sum(llm.ask(run.checklist_path(k), llm.request_body(config.MODELS[GENERATOR], fill(BLIND), long=True), key) is None
                  for k in range(1, samples + 1))
    cells = [(level, cfg, p, v, k, [tuple(x) for x in row["priority"]])
             for level, cfg, _, p, v, k, row in tier_cells(index, n, levels, samples)
             if row and row["status"] == "predicted" and row["priority"]]
    # In phases, each call once: tiers share hinted answers, judgements and checklist answers.
    with ThreadPoolExecutor(workers) as pool:
        list(pool.map(lambda c: run.answers(*c[:5], key=key), sorted({c[:5] for c in cells})))
        bodies = {}
        for level, cfg, p, v, k, priority in cells:
            records = run.answers(level, cfg, p, v, k)
            if all(records):
                body = run.judge_body(records, priority, codes[p, v])
                bodies[run.judge_path(body)] = body
        list(pool.map(lambda item: llm.ask(item[0], item[1], key, url=DECISIONS_URL), bodies.items()))
        todo = {}
        for level, cfg, p, v, k, priority in cells:
            judged, _ = run.judged(level, cfg, p, v, k, priority, codes[p, v])
            found, _ = run.checklist(k)
            for x in judged or []:
                code = codes[p, v].get("{}.{}".format(*x))
                if code and found:
                    todo[run.checklist_answer_path(code, k)] = checklist_body(code, found)
        list(pool.map(lambda item: llm.ask(item[0], item[1], key, url=DECISIONS_URL), todo.items()))
    missing += sum(run.stages(level, cfg, p, v, k, priority, codes[p, v])[0]["checked"] is None
                   for level, cfg, p, v, k, priority in cells)
    print("{} nonempty tier(s); {} still incomplete; {} judgement(s), {} checklist answer(s)".format(
        len(cells), missing, len(bodies), len(todo)), flush=True)
    return missing == 0


# ---- scoring ----------------------------------------------------------------------------------
def evaluate(out, agreement_run="261021g", relax_run="261020h", baseline=relax.BASELINE, samples=config.SAMPLES,
             levels=tuple(relax.LEVELS)):
    run = Run(out, relax_run, baseline)
    projects = list(config.PROJECTS)
    index, n = guard_tier(agreement_run)
    codes = contexts(out, wanted(index, {c[1] for c in level_configs(levels)}))
    predictions, failures = [], []
    for level, cfg, suffix, p, v, k, row in tier_cells(index, n, levels, samples):
        entry = dict(level=level, config=cfg, project=p, variant=v, sample=k)
        if row is None or row["status"] == "unscored":
            predictions.append(dict(entry, status="unscored"))
            continue
        result, failed = run.stages(level, cfg, p, v, k, [tuple(x) for x in row["priority"]], codes[p, v])
        predictions.append(dict(entry, status="predicted", **{s: result[s] for s, _ in STAGES}))
        failures += [dict(entry, reason=f) for f in failed]
    # Predictions are written before the labels are loaded.
    write_json(out / "predictions.json", predictions)
    info = manifest()
    check_dataset(info["dataset_commit"])
    labels = {p: fix_labels(info["subjects"][p]["slug"]) for p in projects}
    by_key = {(r["config"], r["project"], r["variant"], r["sample"]): r for r in predictions}

    def loader(cfg, stage):
        def load(p, v, k):
            r = by_key[cfg, p, v, k]
            if r["status"] == "unscored" or r[stage] is None:
                return None, None
            return [tuple(x) for x in r[stage]], None
        return load

    blind = {}
    for k in range(1, samples + 1):
        found, failure = run.checklist(k)
        blind[k] = found if found is not None and not failure else (failure or "not written")
    result = dict(run=out.name, scored_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  dataset_commit=info["dataset_commit"], agreement_run=agreement_run, relax_run=relax_run,
                  baseline=baseline, models={m: config.MODELS[m] for m in AGENTS}, generator=config.MODELS[GENERATOR],
                  judge=JEV, threshold=THRESHOLD, samples=samples, blind_checklists=blind,
                  prompts=dict(blind_sha256=sha256(BLIND), judge_question=JUDGE_QUESTION),
                  context_sha256=sha256(CONTEXT), arms=[], failures=failures)
    for level, cfg, suffix in level_configs(levels):
        for stage, label in STAGES:
            per_sample = agreement.score_arm(loader(cfg, stage), samples, projects, labels)
            result["arms"].append(dict(level=level, config=cfg, stage=stage, label=label + suffix,
                                       samples=per_sample, summary=agreement.summarise(per_sample, projects)))
    result["fix_locations"] = fix_locations(predictions, labels)
    result["cost"] = cost(out)
    write_json(out / "metrics.json", result)
    (out / "REPORT.md").write_text(render(result, labels))
    return result


def fix_locations(predictions, labels):
    """Hinted-level fate of each fix location in the guard tier, per sample."""
    rows = {}
    for r in predictions:
        if r["level"] != "hinted" or r["status"] != "predicted":
            continue
        fixes = {(x["class"], x["method"]) for x in labels[r["project"]]}
        for loc in sorted({tuple(x) for x in r["guard"]} & fixes):
            row = rows.setdefault((r["project"], r["variant"], loc), {})
            row[r["sample"]] = ("dropped by the judge" if loc not in {tuple(x) for x in r["judged"] or []}
                                else "dropped by the checklist" if loc not in {tuple(x) for x in r["checked"] or []}
                                else "kept")
    return [dict(project=p, variant=v, location="{}.{}".format(*loc), samples=[s[k] for k in sorted(s)])
            for (p, v, loc), s in sorted(rows.items())]


def cost(out):
    by_kind = {}
    for kind, folder in (("hinted answer", "hinted"), ("judge (Jev)", "judge"), ("checklist", "checklists"),
                         ("checklist answer (Jev)", "answers")):
        for path in (out / folder).rglob("*.json") if (out / folder).is_dir() else []:
            record = read_json(path)
            usage = (record.get("response") or {}).get("usage") or {}
            row = by_kind.setdefault(kind, dict(calls=0, cost=0.0, failed=0))
            row["calls"] += 1
            row["cost"] += usage.get("cost", 0) or 0
            row["failed"] += "response" not in record
    return by_kind


def render(result, labels):
    n, counts = len(labels), agreement.counts
    lines = ["# Proposed pipeline: agreement guard, Jev judge, blind checklist", "",
             "Run `{}`, scored {}. Dataset commit `{}`. Guard run `{}`; hinted answers from `{}` (first level: "
             "`{}`).".format(result["run"], result["scored_at"], result["dataset_commit"], result["agreement_run"],
                             result["relax_run"], result["baseline"]),
             "Judge and checklist answerer `{}` (yes when p >= {}); checklist writer `{}`.".format(
                 result["judge"], result["threshold"], result["generator"]), "",
             "Stages: the agreement guard's priority tier; **+ Jev (hinted answers)** keeps a location when Jev,",
             "reading both hinted LLMs' answers and the location's code, answers yes to: \"{}\";".format(
                 result["prompts"]["judge_question"]),
             "**+ checklist (Jev)** drops a location when Jev answers yes to every condition of a safe pattern in a",
             "checklist DeepSeek wrote from CWE-22's description alone (one per sample). Sample k uses sample k of",
             "every input.", "",
             "Vulnerable revision: Detected, FDR, F1. Flagged = the patched fix method is still reported on the",
             "fixed revision; Pair-correct = reported on the vulnerable revision and not the fixed one (projects",
             "/{}, per sample). Mean over samples, [min–max] when samples differ.".format(n), "",
             "| Level | Stage | Detected ↑ | Macro FDR ↓ | Macro F1 ↑ | Fixed: flagged ↓ | Pair-correct ↑ |",
             "| --- | --- | --- | ---: | ---: | --- | --- |"]
    for arm in result["arms"]:
        s = arm["summary"]
        name = "**{}**".format(arm["label"]) if arm["stage"] == "checked" else arm["label"]
        if s is None:
            lines.append("| {} | {} | incomplete | – | – | – | – |".format(arm["level"].upper(), name))
            continue
        lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
            arm["level"].upper(), name, counts(s["detected"], n), ranged(s["macro_fdr"], pct),
            ranged(s["macro_f1"], f4), counts(s["flagged"], n), counts(s["pair_correct"], n)))
    lines += ["", "## Fix locations in the guard tier (Hinted level)", "",
              "| Project | Revision | Fix location | Per sample |", "| --- | --- | --- | --- |"]
    lines += ["| {} | {} | `{}` | {} |".format(r["project"], r["variant"], r["location"], "; ".join(r["samples"]))
              for r in result["fix_locations"]]
    lines += ["", "## Blind checklists", ""]
    for sample, found in sorted(result["blind_checklists"].items(), key=lambda x: int(x[0])):
        lines += ["Sample {}:".format(sample), ""]
        if isinstance(found, str):
            lines += ["- " + found, ""]
            continue
        for name, conditions in found:
            lines.append("- **{}**: ".format(name) + " AND ".join(conditions))
        lines.append("")
    lines += ["## Calls", "", "| Kind | Calls | Failed | Reported cost |", "| --- | ---: | ---: | ---: |"]
    lines += ["| {} | {} | {} | ${:.4f} |".format(k, v["calls"], v["failed"], v["cost"])
              for k, v in sorted(result["cost"].items())]
    lines += ["", "Failures, counted as kept locations:", ""]
    lines += sorted({"- {} {} s{} / {} {}: {}".format(f["level"].upper(), f["config"], f["sample"], f["project"],
                                                     f["variant"], f["reason"])
                     for f in result["failures"]}) or ["- none"]
    return "\n".join(lines) + "\n"
