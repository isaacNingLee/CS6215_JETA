"""Checklist filter after the agreement guard: an LLM writes a CWE-22 checklist and a
judge answers it for every location in the guard's priority tier.

A checklist is a list of *safe patterns*, each a list of yes/no conditions where yes means
the code shows that part of a protection. A location is dropped when, for some pattern,
every condition is answered yes (Jev: probability >= 0.5); otherwise it is kept. The
filter only removes locations, and the rule was fixed before any answer was scored.

Arms (each sample k uses checklist sample k and guard sample min(k, guard samples)):

* ``blind-jev``: DeepSeek writes one checklist per sample from CWE-22's description alone
  (data/prompts/checklist/blind.txt): no subject, code, fix or result is shown. Jev
  (TypeSafe's decision model, OpenRouter's decisions endpoint) answers it.
* ``blind-deepseek``: the same checklists answered by DeepSeek (answer.txt), the control
  that separates the checklist from the judge.
* ``local-jev``: DeepSeek writes a checklist for each location from its code (local.txt),
  without deciding; Jev answers it.

What a judge sees for a location: java/MethodContext.java (parse only) on the revision's
checkout, i.e. the method (every overload), the fields and constructors of its class and
the methods of the same class it calls. A location whose class is not in the project's
production source (JDK classes, anonymous classes) has no code and is kept. Every call is
saved once and never resent (llm.ask).
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

PROMPTS = config.DATA / "prompts/checklist"
BLIND, LOCAL, ANSWER = (PROMPTS / name for name in ("blind.txt", "local.txt", "answer.txt"))
CONTEXT = Path(__file__).resolve().parent / "java/MethodContext.java"
GENERATOR = "deepseek"  # writes the checklists; also the control judge
JEV = "typesafe/jev-1.13"
DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions"
THRESHOLD = 0.5
TASK = ("Java code that a taint analysis reported as a possible path traversal (CWE-22). "
        "The questions are about the method under review.")
ARMS = {"blind-jev": "+ blind checklist, Jev", "blind-deepseek": "+ blind checklist, DeepSeek answers (control)",
        "local-jev": "+ per-location checklist, Jev"}
VERSION = 1  # bump to recompute cached method contexts


def digest(code):
    return hashlib.sha256(code.encode()).hexdigest()[:16]


def fill(template, **values):
    """Templates contain JSON braces, so placeholders are replaced literally."""
    text = template.read_text().rstrip("\n")
    for name, value in values.items():
        text = text.replace("{" + name + "}", value)
    return text


# ---- guard tier and method contexts ---------------------------------------------------------
def guard_tiers(agreement_runs):
    """{run: (rows by (config, scoped, project, variant, sample), sample count)} of the guarded arm."""
    tiers = {}
    for name in agreement_runs:
        predictions = read_json(config.RESULTS / name / "predictions.json")
        tiers[name] = ({(r["config"], r["scoped"], r["project"], r["variant"], r["sample"]): r
                        for r in predictions if r["guard"]}, max(r["sample"] for r in predictions))
    return tiers


def level_configs(levels):
    return [c for c in agreement.configs(list(config.MODELS)) if c[0] in levels]


def wanted(tiers, cfgs):
    """{(project, variant): {(class, method)}} in the priority tier of any configuration in ``cfgs``."""
    found = {}
    for index, _ in tiers.values():
        for (cfg, _, project, variant, _), row in index.items():
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
                java = compile_context(config.RAW / out.name / "checklist")
            sources = [(f, f.read_text(errors="replace")) for f in sorted((checkout / "src/main/java").rglob("*.java"))]
            requests = []
            for cls, method in missing:
                declared = re.compile(r"\b(class|interface|enum)\s+{}\b".format(re.escape(cls)))
                requests += [{"file": str(f), "class": cls, "method": method} for f, text in sources
                             if declared.search(text)]
            request = config.RAW / out.name / "checklist" / "request-{}-{}.json".format(project, variant)
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


# ---- checklists and answers -------------------------------------------------------------------
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


def jev_body(code, found):
    _, text = question_ids(found)
    return dict(model=JEV, state=dict(task=TASK, code=code), questions={
        q: dict(type="noul", instructions="True if the answer to this question is yes: " + c) for q, c in text.items()})


def answer_body(code, found):
    _, text = question_ids(found)
    questions = "\n".join("- {}: {}".format(q, c) for q, c in text.items())
    return llm.request_body(config.MODELS[GENERATOR], fill(ANSWER, code=code, questions=questions))


def yes_answers(arm, record, ids):
    """{id: bool} from a judge's saved answer; raise if unusable."""
    if arm.endswith("jev"):
        if "response" not in record:
            raise ValueError(record.get("error", "no response"))
        answers = record["response"]["answers"]
        return {q: float(answers[q]["noul"]) >= THRESHOLD for q in ids}
    answers = llm.answer_json(record).get("answers")
    if not isinstance(answers, dict):
        raise ValueError("No answers object")
    return {q: answers.get(q) is True for q in ids}


class Run:
    def __init__(self, out):
        self.out = out

    def blind_path(self, sample):
        return self.out / "checklists" / "blind-s{}.json".format(sample)

    def local_path(self, code, sample):
        return self.out / "checklists" / "local" / "{}-s{}.json".format(digest(code), sample)

    def answer_path(self, arm, code, sample):
        return self.out / "answers" / "{}-s{}".format(arm, sample) / "{}.json".format(digest(code))

    def checklist(self, arm, code, sample):
        """(patterns, failure); (None, None) before the checklist exists; [] if it is empty or unusable."""
        path = self.blind_path(sample) if arm.startswith("blind") else self.local_path(code, sample)
        if not path.is_file():
            return None, None
        record = read_json(path)
        try:
            return patterns(record), None
        except (ValueError, KeyError, IndexError) as exc:
            return [], "{} checklist s{}: {}".format(arm.split("-")[0], sample, record.get("error", exc))

    def make(self, arm, code, sample, key):
        """Every missing call for one location and sample; returns the number still missing."""
        if arm.startswith("local") and not self.local_path(code, sample).is_file():
            body = llm.request_body(config.MODELS[GENERATOR], fill(LOCAL, code=code))
            if llm.ask(self.local_path(code, sample), body, key) is None:
                return 2
        found, _ = self.checklist(arm, code, sample)
        if found is None:
            return 1
        if not found:
            return 0
        if arm.endswith("jev"):
            record = llm.ask(self.answer_path(arm, code, sample), jev_body(code, found), key, url=DECISIONS_URL)
        else:
            record = llm.ask(self.answer_path(arm, code, sample), answer_body(code, found), key)
        return int(record is None)

    def decide(self, arm, code, sample):
        """(dropped, failure); dropped is None while a call is missing. No code: kept."""
        if code is None:
            return False, None
        found, failure = self.checklist(arm, code, sample)
        if found is None:
            return None, None
        if not found:
            return False, failure
        path = self.answer_path(arm, code, sample)
        if not path.is_file():
            return None, None
        record = read_json(path)
        groups, _ = question_ids(found)
        try:
            yes = yes_answers(arm, record, [q for ids in groups for q in ids])
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            return False, "{} answer s{}: {}".format(arm, sample, record.get("error", exc))
        return any(all(yes[q] for q in ids) for ids in groups), None


def codes_for(out, levels, agreement_runs):
    tiers = guard_tiers(agreement_runs)
    locations = wanted(tiers, {c[1] for c in level_configs(levels)})
    found = contexts(out, locations)
    return tiers, {key: {loc: found[key]["{}.{}".format(*loc)] for loc in locs} for key, locs in locations.items()}


def execute(out, samples=config.SAMPLES, levels=tuple(relax.LEVELS), arms=tuple(ARMS),
            agreement_runs=("261020r", "261020g"), workers=8, dry_run=False):
    """Make every missing call; True when every arm is complete."""
    run = Run(out)
    _, codes = codes_for(out, levels, agreement_runs)
    unique = sorted({c for locs in codes.values() for c in locs.values() if c})
    total = sum(len(locs) for locs in codes.values())
    print("{} location(s) in the guard tier, {} with project code, {} distinct code contexts ({:,} characters)".format(
        total, sum(c is not None for locs in codes.values() for c in locs.values()), len(unique),
        sum(map(len, unique))), flush=True)
    key = None if dry_run else config.secret("OPENROUTER_API_KEY")
    missing = 0
    if any(a.startswith("blind") for a in arms):
        for sample in range(1, samples + 1):
            missing += llm.ask(run.blind_path(sample), llm.request_body(config.MODELS[GENERATOR], fill(BLIND)),
                               key) is None
    tasks = [(arm, code, sample) for arm in arms for code in unique for sample in range(1, samples + 1)]
    with ThreadPoolExecutor(workers) as pool:
        missing += sum(pool.map(lambda t: run.make(*t, key), tasks))
    print("{} call(s) still missing".format(missing), flush=True)
    if dry_run:
        for arm in arms:
            todo = [t for t in tasks if t[0] == arm and not run.answer_path(*t).is_file()]
            gens = [t for t in todo if arm.startswith("local") and not run.local_path(t[1], t[2]).is_file()]
            print("  {}: {} judge call(s), {} generator call(s), {:,} code characters".format(
                arm, len(todo), len(gens), sum(len(t[1]) for t in todo)), flush=True)
    return missing == 0


# ---- scoring ----------------------------------------------------------------------------------
def evaluate(out, samples=config.SAMPLES, levels=tuple(relax.LEVELS), arms=tuple(ARMS),
             agreement_runs=("261020r", "261020g"), debate_run="261020d"):
    run = Run(out)
    projects = list(config.PROJECTS)
    tiers, codes = codes_for(out, levels, agreement_runs)

    def kept(name, cfg, scoped, arm):
        index, n = tiers[name]

        def load(project, variant, sample):
            row = index.get((cfg, scoped, project, variant, min(sample, n)))
            if row is None or row["status"] == "unscored":
                return None, None
            priority = [tuple(x) for x in row["priority"]]
            if arm is None:
                return priority, None
            decisions = [run.decide(arm, codes[project, variant][x], sample) for x in priority]
            if any(d[0] is None for d in decisions):
                return None, None
            return ([x for x, d in zip(priority, decisions) if not d[0]],
                    "; ".join(sorted({d[1] for d in decisions if d[1]})) or None)
        return load

    rows = [(level, cfg, suffix, name, scoped, arm)
            for level, cfg, suffix in level_configs(levels) for name in tiers for scoped in (False, True)
            for arm in (None,) + tuple(arms)]
    # Predictions are written before the labels are loaded.
    predictions = [dict(level=level, config=cfg, guard_run=name, scoped=scoped, arm=arm or "guard", project=p,
                        variant=v, sample=k, kept=kept(name, cfg, scoped, arm)(p, v, k)[0])
                   for level, cfg, _, name, scoped, arm in rows for p in projects for v in config.VARIANTS
                   for k in range(1, samples + 1)]
    write_json(out / "predictions.json", predictions)
    info = manifest()
    check_dataset(info["dataset_commit"])
    labels = {p: fix_labels(info["subjects"][p]["slug"]) for p in projects}
    debate = read_json(config.RESULTS / debate_run / "metrics.json") if (
        config.RESULTS / debate_run / "metrics.json").is_file() else dict(arms=[])
    blind = {}
    for sample in range(1, samples + 1):
        path = run.blind_path(sample)
        if path.is_file():
            try:
                blind[sample] = patterns(read_json(path))
            except (ValueError, KeyError, IndexError) as exc:
                blind[sample] = "unusable: {}".format(exc)
    result = dict(run=out.name, scored_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  dataset_commit=info["dataset_commit"], generator=config.MODELS[GENERATOR], judge=JEV,
                  threshold=THRESHOLD, samples=samples, agreement_runs={n: t[1] for n, t in tiers.items()},
                  debate_run=debate_run, blind_checklists=blind, arms=[], failures=[],
                  prompts_sha256={p.name: sha256(p) for p in (BLIND, LOCAL, ANSWER)},
                  context_sha256=sha256(CONTEXT))
    for level, cfg, suffix, name, scoped, arm in rows:
        loader = kept(name, cfg, scoped, arm)
        per_sample = agreement.score_arm(loader, samples, projects, labels)
        label = "{} ({}{})".format(ARMS[arm] if arm else "Agreement guard", name, ", app scope" if scoped else "")
        result["arms"].append(dict(level=level, config=cfg, guard_run=name, scoped=scoped, arm=arm or "guard",
                                   label=label + suffix, samples=per_sample,
                                   summary=agreement.summarise(per_sample, projects)))
        if arm is None:
            reference = next((a for a in debate["arms"] if a.get("kind") == "filter" and a["config"] == cfg
                              and a["arm"] == "{}-{}-2".format(name, int(scoped))), None)
            if reference:
                result["arms"].append(dict(reference, arm="debate", guard_run=name, scoped=scoped,
                                           label="+ debate filter, from {} ({}{}){}".format(
                                               debate_run, name, ", app scope" if scoped else "", suffix)))
        else:
            result["failures"] += [dict(level=level, arm=arm, guard_run=name, scoped=scoped, sample=k, project=p,
                                        variant=v, reason=f)
                                   for k in range(1, samples + 1) for p in projects for v in config.VARIANTS
                                   for f in [loader(p, v, k)[1]] if f]
    # A checklist arm with no complete row for a configuration was not run there (e.g. --arms blind-jev).
    ran = {(a["config"], a["arm"]) for a in result["arms"] if a["summary"]}
    result["not_run"] = [dict(config=cfg, arm=arm) for _, cfg, _ in level_configs(levels) for arm in arms
                         if (cfg, arm) not in ran]
    result["arms"] = [a for a in result["arms"] if (a["config"], a["arm"]) in ran or a["arm"] not in ARMS]
    result["failures"] = [f for f in result["failures"] if any(
        a["level"] == f["level"] and a["arm"] == f["arm"] for a in result["arms"])]
    result["fix_decisions"] = fix_decisions(run, codes, labels, arms, samples)
    result["dropped"] = dropped(run, codes, arms, samples)
    result["cost"] = cost(out)
    write_json(out / "metrics.json", result)
    (out / "REPORT.md").write_text(render(result, labels))
    return result


def fix_decisions(run, codes, labels, arms, samples):
    """For each fix location in the guard tier: dropped per arm and sample (True = dropped)."""
    rows = []
    for (project, variant), locs in sorted(codes.items()):
        fixes = {(r["class"], r["method"]) for r in labels[project]}
        for loc in sorted(set(locs) & fixes):
            rows.append(dict(project=project, variant=variant, location="{}.{}".format(*loc),
                             code=locs[loc] is not None,
                             arms={a: [run.decide(a, locs[loc], k)[0] for k in range(1, samples + 1)] for a in arms}))
    return rows


def dropped(run, codes, arms, samples):
    """Locations dropped per arm and revision, summed over samples (of locations with code x samples)."""
    rows = []
    for arm in arms:
        for variant in config.VARIANTS:
            decisions = [run.decide(arm, code, k)[0] for (p, v), locs in codes.items() if v == variant
                         for code in locs.values() if code for k in range(1, samples + 1)]
            rows.append(dict(arm=arm, variant=variant, dropped=sum(d is True for d in decisions),
                             judged=sum(d is not None for d in decisions)))
    return rows


def cost(out):
    paths = [p for d in ("checklists", "answers") for p in (out / d).rglob("*.json")]
    by_kind = {}
    for path in paths:
        record = read_json(path)
        kind = "jev" if record["request"].get("model") == JEV else (
            "checklist" if "checklists" in path.parts else "deepseek answer")
        usage = (record.get("response") or {}).get("usage") or {}
        row = by_kind.setdefault(kind, dict(calls=0, cost=0.0, failed=0))
        row["calls"] += 1
        row["cost"] += usage.get("cost", 0) or 0
        row["failed"] += "response" not in record
    return by_kind


def render(result, labels):
    n, counts = len(labels), agreement.counts
    lines = ["# Agreement guard + LLM-written checklist, answered by Jev", "",
             "Run `{}`, scored {}. Dataset commit `{}`. Guard runs: {}.".format(
                 result["run"], result["scored_at"], result["dataset_commit"],
                 ", ".join("`{}` ({} sample(s))".format(k, v) for k, v in result["agreement_runs"].items())),
             "Checklist writer `{}`; judge `{}` (a condition is yes when its probability is >= {}).".format(
                 result["generator"], result["judge"], result["threshold"]), "",
             "A location in the guard's priority tier is dropped when some safe pattern of the checklist has every",
             "condition answered yes; otherwise it is kept (the filter only removes). *Blind*: one checklist per",
             "sample, written from CWE-22's description alone. *Per-location*: written for each location from its",
             "code. The judge sees the method, its class's fields and constructors and the same-class methods it",
             "calls; locations with no project code (JDK, anonymous classes) are kept. The debate filter row is",
             "copied from `{}` for comparison.".format(result["debate_run"]), "",
             "Vulnerable revision: Detected, FDR, F1. Flagged = the patched fix method is still reported on the",
             "fixed revision; Pair-correct = reported on the vulnerable revision and not the fixed one (projects",
             "/{}, per sample). Mean over samples, [min–max] when samples differ.".format(n), "",
             "| Level | Arm | Detected ↑ | Macro FDR ↓ | Macro F1 ↑ | Fixed: flagged ↓ | Pair-correct ↑ |",
             "| --- | --- | --- | ---: | ---: | --- | --- |"]
    for arm in result["arms"]:
        s = arm["summary"]
        name = "**{}**".format(arm["label"]) if arm["arm"] in ARMS else arm["label"]
        if s is None:
            lines.append("| {} | {} | incomplete | – | – | – | – |".format(arm["level"].upper(), name))
            continue
        lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
            arm["level"].upper(), name, counts(s["detected"], n), ranged(s["macro_fdr"], pct),
            ranged(s["macro_f1"], f4), counts(s["flagged"], n), counts(s["pair_correct"], n)))
    lines += ["", "Not run (omitted above): " + (", ".join("{} at {}".format(r["arm"], r["config"])
                                                           for r in result["not_run"]) or "none") + "."]
    arms = [a for a in ARMS if any(r["arm"] == a for r in result["arms"])]
    show = lambda ds: " ".join("–" if d is None else ("drop" if d else "keep") for d in ds)
    lines += ["", "## Fix locations in the guard tier", "",
              "Decision per sample (drop = judged protected). On the vulnerable revision a drop loses the detection;",
              "on the fixed revision it removes the false alarm.", "",
              "| Project | Revision | Fix location | " + " | ".join(arms) + " |",
              "| --- | --- | --- | " + " | ".join("---" for _ in arms) + " |"]
    lines += ["| {} | {} | `{}`{} | {} |".format(r["project"], r["variant"], r["location"],
                                                "" if r["code"] else " (no code)",
                                                " | ".join(show(r["arms"][a]) for a in arms))
              for r in result["fix_decisions"]]
    lines += ["", "## Locations dropped (all locations with code, summed over samples)", "",
              "| Arm | Vulnerable | Fixed |", "| --- | ---: | ---: |"]
    for arm in arms:
        cell = {r["variant"]: "{} / {}".format(r["dropped"], r["judged"]) for r in result["dropped"] if r["arm"] == arm}
        lines.append("| {} | {} | {} |".format(arm, cell["vulnerable"], cell["fixed"]))
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
    failures = sorted({"{} / {}{} s{} / {} {}: {}".format(f["level"].upper(), f["arm"], " app" if f["scoped"] else "",
                                                          f["sample"], f["project"], f["variant"], f["reason"])
                       for f in result["failures"] if f["guard_run"] == next(iter(result["agreement_runs"]))})
    lines += ["- " + f for f in failures] or ["- none"]
    return "\n".join(lines) + "\n"
