"""Score a run directory and write metrics.json and REPORT.md.

Headline scores use vulnerable revisions only. Fixed-revision outputs are
reported as counts: a finding there is not automatically a false positive.

Tai-e is deterministic and has one sample. Each LLM arm has several independent
samples; every sample is scored on its own, then summarised as mean and range.
Every sample is one request with a fixed token budget. A failed answer (request
error, truncation, empty or malformed JSON) counts as an empty output, i.e.
undetected with F1 0; it is listed in the report, never retried.
"""
import statistics
from datetime import datetime, timezone

from . import config, llm
from .scoring import aggregate, score
from .subjects import check_dataset, fix_labels, manifest
from .util import read_json, write_json


def arms(models, modes):
    yield "Tai-e", None
    for mode in modes:
        for short in models:
            yield "{} {}".format(mode.capitalize(), short.capitalize()), (short, mode)


def load_locations(run_dir, cell, project, variant, sample=1):
    """Return (locations, failure, missing) for one arm/project/revision/sample.

    ``missing`` means the cell cannot be scored (not run, or Tai-e failed), which
    makes the arm incomplete. An LLM ``failure`` yields an empty location list.
    """
    if cell is None:
        path = run_dir / "taie" / "{}-{}.json".format(project, variant)
        if not path.is_file():
            return None, None, "not run"
        result = read_json(path)
        if result["status"] != "completed":
            return None, None, result.get("error", result["status"])
        if not result["target_reachable"]:
            return None, None, "target method unreachable"
        return [tuple(x) for x in result["locations"]], None, None
    path = llm.cell_path(run_dir, cell[0], cell[1], project, variant, sample)
    if not path.is_file():
        return None, None, "not run"
    record = read_json(path)
    if "response" not in record:
        return [], record.get("error", "no response"), None
    try:
        return [tuple(x) for x in llm.cwe22_locations(record["response"])[0]], None, None
    except (ValueError, KeyError, IndexError) as exc:
        return [], str(exc), None


def score_sample(run_dir, name, cell, sample, projects, labels, failures):
    rows, fixed = [], {}
    for project in projects:
        for variant in config.VARIANTS:
            locations, failure, missing = load_locations(run_dir, cell, project, variant, sample)
            if failure:
                failures.append(dict(arm=name, sample=sample, project=project, variant=variant, reason=failure))
            if variant == "fixed":
                fixed[project] = None if missing else len(locations)
                continue
            row = dict(project=project, status="unscored" if missing else "scored")
            if missing:
                row["reason"] = missing
            else:
                row.update(score(locations, labels[project]), locations=[list(x) for x in locations],
                           failure=failure)
            rows.append(row)
    return dict(sample=sample, projects=rows, summary=aggregate(rows), fixed_revision_locations=fixed)


def spread(values):
    """Mean/min/max of the non-None values, or None if there are none."""
    values = [v for v in values if v is not None]
    return dict(mean=statistics.mean(values), min=min(values), max=max(values)) if values else None


def summarise(samples, projects):
    """Across-sample summary; None when any sample is incomplete."""
    if not all(s["summary"]["complete"] for s in samples):
        return None
    per_project = {}
    for project in projects:
        rows = [next(r for r in s["projects"] if r["project"] == project) for s in samples]
        per_project[project] = dict(detected=sum(r["detected"] for r in rows), samples=len(rows),
                                    fdr=spread(r["fdr"] for r in rows), f1=spread(r["f1"] for r in rows),
                                    reported=[r["reported"] for r in rows],
                                    failed=sum(bool(r["failure"]) for r in rows))
    return dict(detected=spread(s["summary"]["detected"] for s in samples),
                macro_fdr=spread(s["summary"]["macro_fdr"] for s in samples),
                macro_f1=spread(s["summary"]["macro_f1"] for s in samples),
                per_project=per_project)


def budgets(run_dir):
    return sorted({read_json(p)["request"]["max_tokens"] for p in (run_dir / "llm").glob("*/*.json")})


def evaluate(run_dir, models=tuple(config.MODELS), modes=tuple(config.MODES), projects=tuple(config.PROJECTS),
             samples=config.SAMPLES):
    info = manifest()
    check_dataset(info["dataset_commit"])
    labels = {p: fix_labels(info["subjects"][p]["slug"]) for p in projects}
    result = dict(run=run_dir.name, scored_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  dataset_commit=info["dataset_commit"], models={m: config.MODELS[m] for m in models},
                  unit="(simple class, method) CWE-22 location; vulnerable revisions only",
                  fix_methods={p: sorted({"{}.{}".format(r["class"], r["method"]) for r in labels[p]})
                               for p in projects},
                  llm_samples=samples, max_tokens=budgets(run_dir), failed_cells=[], arms={})
    for name, cell in arms(models, modes):
        scored = [score_sample(run_dir, name, cell, k, projects, labels, result["failed_cells"])
                  for k in range(1, (1 if cell is None else samples) + 1)]
        result["arms"][name] = dict(samples=scored, summary=summarise(scored, projects))
    write_json(run_dir / "metrics.json", result)
    (run_dir / "REPORT.md").write_text(render(result, projects))
    return result


def pct(value):
    return "n/a" if value is None else "{:.2f}%".format(100 * value)


def ranged(stat, fmt):
    """``mean [min–max]``, or just the value when all samples agree."""
    if stat is None:
        return "n/a"
    if stat["min"] == stat["max"]:
        return fmt(stat["mean"])
    return "{} [{}–{}]".format(fmt(stat["mean"]), fmt(stat["min"]), fmt(stat["max"]))


def f4(value):
    return "{:.4f}".format(value)


def render(result, projects):
    names = list(result["arms"])
    n_projects = len(projects)
    lines = ["# CWE-22 baselines: Tai-e, vanilla LLM and hinted LLM", "",
             "Run `{}`, scored {}. Dataset commit `{}`.".format(result["run"], result["scored_at"],
                                                                result["dataset_commit"]),
             "Models: " + ", ".join("{} = `{}`".format(k, v) for k, v in result["models"].items()) + ".",
             "LLM arms: {} independent samples per cell, max_tokens {}. Tai-e is deterministic (1 run).".format(
                 result["llm_samples"], "/".join(map(str, result["max_tokens"]))), "",
             "Unit: one `(simple class, method)` location on the **vulnerable** revision. N = reported",
             "locations, K = locations that are recorded production fix methods. Detected = K > 0,",
             "FDR = 1 − K/N, F1 = 2K/(N+K) (binary project recall). These are fix-location proxies,",
             "not verified vulnerability labels.", "",
             "## Summary", "",
             "Values are the mean over samples, with [min–max] when samples differ.", "",
             "| Arm | Detected (per sample) | Macro FDR ↓ | Macro F1 ↑ |", "| --- | --- | ---: | ---: |"]
    for name in names:
        arm, s = result["arms"][name], result["arms"][name]["summary"]
        if s is None:
            lines.append("| {} | incomplete | – | – |".format(name))
            continue
        detected = ", ".join("{}/{}".format(x["summary"]["detected"], n_projects) for x in arm["samples"])
        lines.append("| {} | {} | {} | {} |".format(name, detected, ranged(s["macro_fdr"], pct),
                                                    ranged(s["macro_f1"], f4)))
    lines += ["", "Macro FDR averages projects with nonempty output; detection and F1 count all projects.", "",
              "Each sample is one request, never retried. Failed answers count as empty output",
              "(undetected, F1 0, FDR undefined):", ""]
    lines += ["- {} s{} / {} {}: {}".format(f["arm"], f["sample"], f["project"], f["variant"], f["reason"])
              for f in result["failed_cells"]] or ["- none"]
    lines.append("")
    for project in projects:
        lines += ["## {}".format(project), "",
                  "Fix methods: " + ", ".join("`{}`".format(m) for m in result["fix_methods"][project]), "",
                  "| Arm | Detected | N per sample | FDR ↓ | F1 ↑ | F1 per sample | Fixed-revision N |",
                  "| --- | :---: | --- | ---: | ---: | --- | --- |"]
        for name in names:
            arm = result["arms"][name]
            rows = [next(r for r in x["projects"] if r["project"] == project) for x in arm["samples"]]
            fixed = ", ".join("–" if x["fixed_revision_locations"][project] is None
                              else str(x["fixed_revision_locations"][project]) for x in arm["samples"])
            if arm["summary"] is None:
                lines.append("| {} | incomplete | | | | | {} |".format(name, fixed))
                continue
            p = arm["summary"]["per_project"][project]
            detected = "{}/{}".format(p["detected"], p["samples"]) + (
                " ({} failed)".format(p["failed"]) if p["failed"] else "")
            lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
                name, detected, ", ".join(map(str, p["reported"])), ranged(p["fdr"], pct), ranged(p["f1"], f4),
                ", ".join(f4(r["f1"]) for r in rows), fixed))
        lines.append("")
    return "\n".join(lines)
