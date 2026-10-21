"""Agreement guard, the proposed method of CS6215_proj, on every hint-relaxation level
and on both revisions.

For one Tai-e configuration, project, revision and reader sample:

1. Guard: Tai-e flows whose sink is a FileOutputStream allocation protected by a
   checked guard contract (guards.py) are set aside.
2. Candidates: ``(simple class, method)`` locations of both endpoints of the remaining
   flows (origin Tai-e) and of the CWE-22 findings of two independent vanilla
   readers (origins Qwen and DeepSeek).
3. Selection: the locations Tai-e and at least one reader both report; when there
   are none, every Tai-e location (fallback). This priority tier is the output; the
   other candidates are the review tail, recorded in predictions.json, not scored.

The Tai-e flows of each level come from a hint-relaxation run (relax.py), both all
flows and application scope. Readers are the vanilla arm of a baseline run: sample
k of each model forms sample k here, and a failed reader answer adds no location.
Readers see the production fix file (oracle-selected input), as in CS6215_proj.
Selection reads no fix label, and predictions are written before labels are loaded.

Besides the vulnerable-revision proxies, each arm (also every baseline) is scored on
the fixed revision: *flagged* means the already-patched fix method is still reported,
and *pair-correct* means it is reported on the vulnerable revision but not the fixed.
"""
from datetime import datetime, timezone

from . import config, guards, relax, report, spec, taie
from .report import f4, pct, ranged, spread
from .scoring import aggregate, flow_locations, score
from .subjects import check_dataset, fix_labels, manifest
from .util import read_json, sha256, write_json

READERS = ("qwen", "deepseek")
VERSION = 1  # bump to recompute cached guard contracts


def configs(models):
    """(level, Tai-e configuration, label suffix) for every relaxation level."""
    rows = []
    for level in relax.LEVELS:
        for short in models if level in ("h2b", "e") else models[:1]:
            suffix = {"h2b": " [{} selection]", "e": " [{} driver + selection]"}.get(level, "").format(
                short.capitalize())
            rows.append((level, relax.taie_config(level, short), suffix))
    return rows


# ---- guard contracts --------------------------------------------------------------------
def check_guards(out, projects):
    """Guard contracts per revision; cached in results/<run>/guards while the checkers are unchanged."""
    stamp = dict(version=VERSION, guards_sha256=sha256(config.ROOT / "cwe22/guards.py"),
                 checkers_sha256={p.name: sha256(p) for p in guards.CHECKERS})
    found, java, jhome = {}, None, None
    for project in projects:
        for variant in config.VARIANTS:
            path = out / "guards" / "{}-{}.json".format(project, variant)
            if not (path.is_file() and read_json(path).get("stamp") == stamp):
                if java is None:
                    jhome = taie.java_home()
                    java = guards.compile_checkers(jhome, config.RAW / out.name / "guards")
                checkout, classpath = taie.subject(project, variant, jhome,
                                                   config.RAW / out.name / "build" / "{}-{}".format(project, variant))
                print("  guards {} {}".format(project, variant), flush=True)
                write_json(path, dict(project=project, variant=variant, stamp=stamp,
                                      commit=manifest()["subjects"][project][variant],
                                      **guards.check(checkout, classpath, java)))
            found[project, variant] = read_json(path)
    return found


# ---- predictions ------------------------------------------------------------------------
def static_flows(relax_dir, cfg, project, variant, scoped):
    """Tai-e flows of one configuration; None if not run, [] if the analysis failed."""
    path = relax_dir / "taie" / cfg / "{}-{}.json".format(project, variant)
    if not path.is_file():
        return None, None
    result = read_json(path)
    if result["status"] != "completed":
        return [], "Tai-e {}: {}".format(cfg, result.get("error", "failed")[:160])
    flows = result["flows"]
    if scoped:
        classes = set(taie.project_classes(config.SUBJECTS / project / variant / "target/classes", result["entry"]))
        flows = spec.app_scoped(flows, classes)
        if len(flows) != result["scoped_flows"]:
            raise RuntimeError("Application scope does not reproduce {}".format(path))
    return flows, None


def catalogue(relax_dir, cfg, project, variant):
    path = (config.RAW / relax_dir.name / "cat" / relax.entry_of(cfg) / "{}-{}".format(project, variant)
            / "catalogue.json")
    if not path.is_file():
        raise RuntimeError("Missing catalogue for the guard's sink check: {}".format(path))
    return read_json(path)


def reader_locations(readers_dir, short, project, variant, sample):
    locations, failure, missing = report.load_locations(readers_dir, (short, "vanilla"), project, variant, sample)
    if missing:
        raise RuntimeError("Vanilla {} {} {} s{} is {}".format(short, project, variant, sample, missing))
    return locations, failure and "Vanilla {}: {}".format(short.capitalize(), failure)


def select(static, readers):
    """Priority tier: Tai-e locations that a reader also reports, else every Tai-e location."""
    named = set().union(*readers)
    agreement = set(static) & named
    priority = agreement or set(static)
    return dict(priority=sorted(priority), tail=sorted((set(static) | named) - priority), fallback=not agreement)


def predict(relax_dir, readers_dir, projects, models, samples, contracts):
    """Every agreement prediction, with and without the guard; no label is read here."""
    rows = []
    for level, cfg, _ in configs(models):
        for scoped in (False, True):
            for project in projects:
                for variant in config.VARIANTS:
                    flows, failure = static_flows(relax_dir, cfg, project, variant, scoped)
                    protected = contracts[project, variant]["protected"]
                    if flows and protected:
                        cat = catalogue(relax_dir, cfg, project, variant)
                        kept = [f for f in flows if not guards.guarded(f, protected, cat)]
                    else:
                        kept = flows
                    for sample in range(1, samples + 1):
                        found = [reader_locations(readers_dir, s, project, variant, sample) for s in READERS]
                        failures = [f for f in [failure] + [r[1] for r in found] if f]
                        for guard, chosen in ((False, flows), (True, kept)):
                            row = dict(level=level, config=cfg, scoped=scoped, guard=guard, project=project,
                                       variant=variant, sample=sample, failures=failures)
                            if chosen is None:
                                row["status"] = "unscored"
                            else:
                                row.update(status="predicted", flows=len(chosen), guarded=len(flows) - len(chosen),
                                           **select(flow_locations(chosen), [set(r[0]) for r in found]))
                            rows.append(row)
    return rows


# ---- scoring ------------------------------------------------------------------------------
def score_arm(loader, samples, projects, labels):
    """Vulnerable proxies plus fixed-revision flag and pair-correct, per sample."""
    per_sample = []
    for sample in range(1, samples + 1):
        rows = []
        for project in projects:
            (vuln, vfail), (fixed, ffail) = (loader(project, v, sample) for v in config.VARIANTS)
            if vuln is None or fixed is None:
                rows.append(dict(project=project, status="unscored"))
                continue
            fixes = {(r["class"], r["method"]) for r in labels[project]}
            row = dict(project=project, status="scored", failed=bool(vfail or ffail), **score(vuln, labels[project]))
            row.update(fixed_reported=len({tuple(x) for x in fixed}), flagged=bool({tuple(x) for x in fixed} & fixes))
            row["pair_correct"] = row["detected"] and not row["flagged"]
            rows.append(row)
        summary = aggregate(rows)
        if summary["complete"]:
            summary.update(flagged=sum(r["flagged"] for r in rows), pair_correct=sum(r["pair_correct"] for r in rows))
        per_sample.append(dict(sample=sample, projects=rows, summary=summary))
    return per_sample


def summarise(per_sample, projects):
    if not all(s["summary"]["complete"] for s in per_sample):
        return None
    per_project = {}
    for project in projects:
        rows = [next(r for r in s["projects"] if r["project"] == project) for s in per_sample]
        per_project[project] = dict(samples=len(rows), detected=sum(r["detected"] for r in rows),
                                    flagged=sum(r["flagged"] for r in rows),
                                    pair_correct=sum(r["pair_correct"] for r in rows),
                                    f1=spread(r["f1"] for r in rows), reported=[r["reported"] for r in rows],
                                    fixed_reported=[r["fixed_reported"] for r in rows],
                                    failed=sum(r["failed"] for r in rows))
    return dict({k: [s["summary"][k] for s in per_sample] for k in ("detected", "flagged", "pair_correct")},
                macro_fdr=spread(s["summary"]["macro_fdr"] for s in per_sample),
                macro_f1=spread(s["summary"]["macro_f1"] for s in per_sample), per_project=per_project)


def arms(relax_run, readers_dir, predictions, models, samples):
    """(level, label, kind, sample count, loader); kind is baseline, proposed or control."""
    index = {(r["config"], r["scoped"], r["guard"], r["project"], r["variant"], r["sample"]): r for r in predictions}

    def agreement(cfg, scoped, guard):
        def load(project, variant, sample):
            row = index[cfg, scoped, guard, project, variant, sample]
            if row["status"] == "unscored":
                return None, None
            return [tuple(x) for x in row["priority"]], "; ".join(row["failures"]) or None
        return load

    def vanilla(short):
        def load(project, variant, sample):
            locations, failure, missing = report.load_locations(readers_dir, (short, "vanilla"), project, variant,
                                                                sample)
            return (None, None) if missing else (locations, failure)
        return load

    def taie_arm(cfg, scoped):
        return lambda project, variant, sample: relax.taie_locations(relax_run, cfg, project, variant, scoped)

    def hinted(short, level):
        return lambda project, variant, sample: relax.hinted_locations(relax_run, short, level, project, variant,
                                                                       sample)

    rows = [("–", "Vanilla " + s.capitalize(), "baseline", samples, vanilla(s)) for s in READERS]
    for level in relax.LEVELS:
        level_configs = [c for c in configs(models) if c[0] == level]
        for _, cfg, suffix in level_configs:
            for scoped in (False, True):
                scope = " app scope" if scoped else ""
                rows.append((level, "Tai-e" + scope + suffix, "baseline", 1, taie_arm(cfg, scoped)))
        rows += [(level, "Hinted " + s.capitalize(), "baseline", samples, hinted(s, level)) for s in models]
        for _, cfg, suffix in level_configs:
            for scoped in (False, True):
                scope = " app scope" if scoped else ""
                rows.append((level, "Agreement guard" + scope + suffix, "proposed", samples,
                             agreement(cfg, scoped, True)))
                rows.append((level, "Agreement, no guard" + scope + suffix, "control", samples,
                             agreement(cfg, scoped, False)))
    return rows


def evaluate(out, projects=tuple(config.PROJECTS), models=tuple(config.MODELS), samples=config.SAMPLES,
             relax_run="261020h", readers="261020b"):
    relax_dir, readers_dir = config.RESULTS / relax_run, config.RESULTS / readers
    for path in (relax_dir / "taie", readers_dir / "llm"):
        if not path.is_dir():
            raise RuntimeError("Missing {}".format(path))
    contracts = check_guards(out, projects)
    predictions = predict(relax_dir, readers_dir, projects, models, samples, contracts)
    write_json(out / "predictions.json", predictions)
    # Labels are loaded only after every prediction is saved.
    info = manifest()
    check_dataset(info["dataset_commit"])
    labels = {p: fix_labels(info["subjects"][p]["slug"]) for p in projects}
    result = dict(run=out.name, scored_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  dataset_commit=info["dataset_commit"], relax_run=relax_run, readers_run=readers,
                  models={m: config.MODELS[m] for m in models}, samples=samples,
                  guards={"{}-{}".format(*k): dict(protected=v["protected"], contracts=v["contracts"])
                          for k, v in contracts.items()}, failures=[], arms=[])
    run = relax.Run(relax_dir, list(projects), list(models))
    for level, label, kind, n, loader in arms(run, readers_dir, predictions, models, samples):
        per_sample = score_arm(loader, n, projects, labels)
        if kind == "baseline":  # the agreement arms' inputs are these baselines' outputs
            result["failures"] += [dict(level=level, arm=label, sample=s["sample"] if n > 1 else None, project=p,
                                        variant=v, reason=failure)
                                   for s in per_sample for p in projects for v in config.VARIANTS
                                   for failure in [loader(p, v, s["sample"])[1]] if failure]
        result["arms"].append(dict(level=level, arm=label, kind=kind, samples=per_sample,
                                   summary=summarise(per_sample, projects)))
    result["guard_effect"] = guard_effect(predictions, models)
    write_json(out / "metrics.json", result)
    (out / "REPORT.md").write_text(render(result, projects, labels))
    return result


def guard_effect(predictions, models):
    """Flows the guard sets aside, per configuration and revision (sample 1; Tai-e is deterministic)."""
    rows = []
    for level, cfg, suffix in configs(models):
        for scoped in (False, True):
            picked = [r for r in predictions if r["config"] == cfg and r["scoped"] == scoped and r["guard"]
                      and r["sample"] == 1 and r["status"] == "predicted"]
            total = lambda key: {v: sum(key(r) for r in picked if r["variant"] == v) for v in config.VARIANTS}
            rows.append(dict(level=level, config=cfg, scoped=scoped, suffix=suffix,
                             guarded=total(lambda r: r["guarded"]), flows=total(lambda r: r["flows"] + r["guarded"]),
                             by_project=sorted({"{} {}".format(r["project"], r["variant"])
                                                for r in picked if r["guarded"]})))
    return rows


# ---- report -------------------------------------------------------------------------------
def counts(values, n):
    return ", ".join("{}/{}".format(v, n) for v in values)


def render(result, projects, labels):
    n = len(projects)
    lines = ["# Agreement guard under hint relaxation: vulnerable and fixed revisions", "",
             "Run `{}`, scored {}. Dataset commit `{}`.".format(result["run"], result["scored_at"],
                                                                result["dataset_commit"]),
             "Tai-e flows and hinted-LLM answers from run `{}`; vanilla readers from run `{}`.".format(
                 result["relax_run"], result["readers_run"]),
             "Models: " + ", ".join("{} = `{}`".format(k, v) for k, v in result["models"].items()) + ".", "",
             "**Agreement guard** (proposed, from CS6215_proj): set aside Tai-e flows into a sink protected by a",
             "checked guard contract; then report the locations that Tai-e and at least one independent vanilla",
             "reader (Qwen, DeepSeek) both report, or every Tai-e location when they share none. Sample k uses",
             "sample k of both readers. *Agreement, no guard* is the same rule without step one. Readers see the",
             "production fix file (oracle-selected input). Levels and Tai-e configurations as in `{}`.".format(
                 result["relax_run"]), "",
             "Vulnerable revision: Detected = K > 0, FDR = 1 − K/N, F1 = 2K/(N+K) over `(simple class, method)`",
             "locations. Fixed revision: **Flagged** = the patched fix method is still reported (a false alarm);",
             "**Pair-correct** = reported on the vulnerable revision and not on the fixed one. Counts are projects",
             "(/{}) per sample. Fix-location proxies, not verified vulnerability labels. A failed input reports".format(n),
             "nothing.", "",
             "## Guard contracts", "",
             "Checkers run on production files that allocate a `FileOutputStream`. *path*: `startsWith` guards",
             "(refuted = String prefix without a directory boundary). *canonical*: `FileOutputStream` sinks.", "",
             "| Project | Revision | path: refuted / unknown / supported | canonical: supported / sinks | Protected sinks |",
             "| --- | --- | ---: | ---: | --- |"]
    for project in projects:
        for variant in config.VARIANTS:
            g = result["guards"]["{}-{}".format(project, variant)]
            path = [c for c in g["contracts"] if c["checker"] == "path"]
            canonical = [c for c in g["contracts"] if c["checker"] == "canonical"]
            status = lambda rows, s: sum(c["status"] == s for c in rows)
            lines.append("| {} | {} | {} / {} / {} | {} / {} | {} |".format(
                project, variant, status(path, "refuted"), status(path, "unknown"), status(path, "supported"),
                status(canonical, "supported"), len(canonical),
                ", ".join("`{}.{}` L{} ({})".format(p["cls"].rsplit(".", 1)[-1], p["method"], p["line"], p["checker"])
                          for p in g["protected"]) or "–"))
    lines += ["", "## Summary", "", "Mean over samples, [min–max] when samples differ. Tai-e is deterministic.", "",
              "| Level | Arm | Detected ↑ | Macro FDR ↓ | Macro F1 ↑ | Fixed: flagged ↓ | Pair-correct ↑ |",
              "| --- | --- | --- | ---: | ---: | --- | --- |"]
    for arm in result["arms"]:
        if arm["kind"] == "control":
            continue
        s, name = arm["summary"], ("**{}**".format(arm["arm"]) if arm["kind"] == "proposed" else arm["arm"])
        if s is None:
            lines.append("| {} | {} | incomplete | – | – | – | – |".format(arm["level"].upper(), name))
            continue
        lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
            arm["level"].upper(), name, counts(s["detected"], n), ranged(s["macro_fdr"], pct),
            ranged(s["macro_f1"], f4), counts(s["flagged"], n), counts(s["pair_correct"], n)))
    lines += ["", "## Guard ablation", "",
              "Flows set aside by the guard (vulnerable / fixed, summed over projects), and the agreement rule with",
              "and without them. Identical rows mean the guard changed nothing at that configuration.", "",
              "| Level | Configuration | Flows set aside | Revisions affected | Detected | Macro F1 | Flagged | Pair-correct |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    by_label = {(a["level"], a["arm"]): a["summary"] for a in result["arms"]}
    for g in result["guard_effect"]:
        scope = " app scope" if g["scoped"] else ""
        on, off = (by_label[g["level"], name + scope + g["suffix"]]
                   for name in ("Agreement guard", "Agreement, no guard"))
        if on is None or off is None:
            lines.append("| {} | {}{} | incomplete | | | | | |".format(g["level"].upper(), g["config"], scope))
            continue
        pair = lambda key, fmt: "{} → {}".format(fmt(off[key]), fmt(on[key]))
        lines.append("| {} | {}{} | {} / {} of {} / {} | {} | {} | {} | {} | {} |".format(
            g["level"].upper(), g["config"], scope, g["guarded"]["vulnerable"], g["guarded"]["fixed"],
            g["flows"]["vulnerable"], g["flows"]["fixed"], ", ".join(g["by_project"]) or "–",
            pair("detected", lambda v: counts(v, n)), pair("macro_f1", lambda v: ranged(v, f4)),
            pair("flagged", lambda v: counts(v, n)), pair("pair_correct", lambda v: counts(v, n))))
    lines += ["", "Failed baseline inputs, counted as empty output (the agreement arms read the same failed",
              "readers and Tai-e runs):", ""]
    lines += ["- {} / {}{} / {} {}: {}".format(f["level"].upper(), f["arm"], " s{}".format(f["sample"]) if f["sample"]
                                               else "", f["project"], f["variant"], f["reason"])
              for f in result["failures"]] or ["- none"]
    for project in projects:
        fixes = sorted({"{}.{}".format(r["class"], r["method"]) for r in labels[project]})
        lines += ["", "## {}".format(project), "", "Fix methods: " + ", ".join("`{}`".format(m) for m in fixes), "",
                  "| Level | Arm | Detected | N per sample | F1 ↑ | Fixed N per sample | Flagged ↓ | Pair-correct ↑ |",
                  "| --- | --- | :---: | --- | ---: | --- | :---: | :---: |"]
        for arm in result["arms"]:
            if arm["kind"] == "control":
                continue
            if arm["summary"] is None:
                lines.append("| {} | {} | incomplete | | | | | |".format(arm["level"].upper(), arm["arm"]))
                continue
            p = arm["summary"]["per_project"][project]
            lines.append("| {} | {} | {}/{}{} | {} | {} | {} | {}/{} | {}/{} |".format(
                arm["level"].upper(), arm["arm"], p["detected"], p["samples"],
                " ({} failed)".format(p["failed"]) if p["failed"] else "", ", ".join(map(str, p["reported"])),
                ranged(p["f1"], f4), ", ".join(map(str, p["fixed_reported"])), p["flagged"], p["samples"],
                p["pair_correct"], p["samples"]))
    return "\n".join(lines) + "\n"
