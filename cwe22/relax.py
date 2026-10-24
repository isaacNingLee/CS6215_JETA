"""Hint relaxation: replace the manual Tai-e configuration step by step, and give the
hinted LLM exactly the configuration Tai-e receives at each step.

Levels (each removes one more human input from the one before):

* hinted  manual adapter + manual per-project policy; the hinted LLM is the prose-hinted
          baseline of a baseline run (``llm`` command: hints.json + sink files)
* h1   manual adapter + shared CWE-22 kit only
* h2a  manual adapter + kit + every catalogue candidate source
* h2b  manual adapter + kit + candidates the model did not reject (per model)
* e    LLM-written entry driver + kit + candidates the model did not reject (per model)

From H1 on, the hinted LLM sees the entry program and the policy files of that level
(data/prompts/relax/hinted.txt) and the production fix file only; the manual
``sink_files`` belong to the manual hint and are not shown. The first level reuses the
hinted baseline unchanged, so the ladder starts from the arm the baselines report.

Every LLM step (pick, driver, repair, selection, hinted answer) is one saved
request with the fixed token budget, never resent. A failed hinted answer, a
failed Tai-e run and a missing driver all count as an empty output (undetected).
A failed selection request keeps every candidate of its batch (conservative).
"""
import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import catalogue, config, entry, llm, spec, taie
from .report import f4, pct, ranged, spread
from .scoring import aggregate, flow_locations, score
from .subjects import check_dataset, fix_labels, manifest
from .util import read_json, sha256, write_json

LEVELS = ["hinted", "h1", "h2a", "h2b", "e"]
LEVEL_NAMES = {"hinted": "Hinted (manual policy)", "h1": "H1 kit only", "h2a": "H2a kit + all candidates",
               "h2b": "H2b kit + LLM-selected sources", "e": "E LLM entry + kit + LLM-selected sources"}
TEMPLATE = config.DATA / "prompts/relax/hinted.txt"
BASELINE = "261021b"  # baseline run whose hinted arm is the first level
TAIE_WORKERS = 3


def taie_config(level, short):
    """Tai-e configuration that the hinted ``short`` model sees at ``level``."""
    return {"hinted": "manual", "h2b": "h2b-" + short, "e": "e-" + short + "-h2b"}.get(level, level)


def entry_of(cfg):
    """``manual`` or ``e-<model>``."""
    return "-".join(cfg.split("-")[:2]) if cfg.startswith("e-") else "manual"


class Run:
    def __init__(self, run_dir, projects, models, jhome=None, baseline=BASELINE):
        self.dir, self.raw = run_dir, config.RAW / run_dir.name
        self.baseline = config.RESULTS / baseline
        self.projects, self.models = projects, models
        self.subjects = manifest()["subjects"]
        self.jhome = jhome
        self.classpaths = {}

    # ---- paths -------------------------------------------------------------
    def policy(self, cfg, project):
        return self.dir / "policies" / cfg / project

    def adapter(self, cfg, project):
        name = entry_of(cfg)
        if name == "manual":
            return config.DATA / "adapters" / (self.subjects[project]["entry"] + ".java")
        return self.dir / "drivers" / name[2:] / project / "AutoEntry.java"

    def taie_path(self, cfg, project, variant):
        return self.dir / "taie" / cfg / "{}-{}.json".format(project, variant)

    def cell_path(self, short, level, project, variant, sample):
        """Hinted answer; the first level's answers are the baseline run's hinted arm."""
        root, arm = (self.baseline, "hinted") if level == "hinted" else (self.dir, level)
        return root / "llm" / "{}-{}".format(short, arm) / "{}-{}-s{}.json".format(project, variant, sample)

    # ---- subjects and catalogues -------------------------------------------
    def prepare_subjects(self):
        self.jhome = self.jhome or taie.java_home()
        for project in self.projects:
            for variant in config.VARIANTS:
                self.classpaths[project, variant] = taie.subject(
                    project, variant, self.jhome, self.raw / "build" / "{}-{}".format(project, variant))

    def catalogues(self, name):
        """Catalogues for every project with an entry program under ``name``."""
        cfg = "h2a" if name == "manual" else name + "-h2a"
        jobs = [(p, v) for p in self.projects for v in config.VARIANTS if self.adapter(cfg, p).is_file()]

        def one(job):
            project, variant = job
            checkout, classpath = self.classpaths[job]
            raw = self.raw / "cat" / name / "{}-{}".format(project, variant)
            print("  catalogue {} {} {}".format(name, project, variant), flush=True)
            return job, catalogue.build(checkout, classpath, self.adapter(cfg, project), raw, self.jhome)

        with ThreadPoolExecutor(TAIE_WORKERS) as pool:
            return dict(pool.map(one, jobs))

    def candidates(self, name, cats):
        path = self.dir / "candidates" / (name + ".json")
        result = {}
        for project in self.projects:
            if (project, "vulnerable") not in cats:
                continue
            per = {v: spec.candidate_sources(cats[project, v]) for v in config.VARIANTS}
            per["union"] = sorted(set(per["vulnerable"]) | set(per["fixed"]))
            result[project] = per
        write_json(path, result)
        return result

    # ---- policies and Tai-e -------------------------------------------------
    def write_policies(self, cfg, sources=None):
        """Write each project's policy once; ``sources`` maps project -> extra sources."""
        for project in self.projects:
            folder = self.policy(cfg, project)
            if folder.is_dir() or not self.adapter(cfg, project).is_file():
                continue
            if cfg == "manual":
                taie.taint_config(project, folder)
            elif cfg == "h1":
                spec.write_policy(folder)
            elif project in (sources or {}):
                spec.write_policy(folder, sources[project])

    def run_taie(self, cfg, heap="4g", timeout=1800):
        jobs = [(p, v) for p in self.projects for v in config.VARIANTS if not self.taie_path(cfg, p, v).is_file()]

        def one(job):
            project, variant = job
            raw = self.raw / "taie" / cfg / "{}-{}".format(project, variant)
            if raw.exists():
                shutil.rmtree(raw)
            adapter, policy = self.adapter(cfg, project), self.policy(cfg, project)
            result = dict(config=cfg, project=project, variant=variant, status="failed",
                          taie_sha256=sha256(config.TAIE_JAR))
            try:
                if not adapter.is_file() or not policy.is_dir():
                    raise RuntimeError("No Tai-e configuration (entry driver or policy missing)")
                classpath = self.classpaths[job][1]
                print("  tai-e {} {} {}".format(cfg, project, variant), flush=True)
                result.update(taie.analyze(project, variant, self.subjects[project], classpath, self.jhome, raw,
                                           heap, timeout, adapter=adapter, policy=policy), status="completed")
                classes = set(taie.project_classes(classpath[0], adapter.stem))
                scoped = spec.app_scoped(result["flows"], classes)
                result.update(scoped_flows=len(scoped), scoped_locations=[list(x) for x in flow_locations(scoped)])
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                result["error"] = "{}: {} (logs: {})".format(type(exc).__name__, exc, raw)
            write_json(self.taie_path(cfg, project, variant), result)
            print("{} {} {}: {}".format(cfg, project, variant, "{} flows, {} scoped".format(
                len(result["flows"]), result["scoped_flows"]) if result["status"] == "completed"
                else result["error"]), flush=True)

        with ThreadPoolExecutor(TAIE_WORKERS) as pool:
            list(pool.map(one, jobs))

    # ---- LLM source selection -----------------------------------------------
    def select(self, name, short, cats, candidates, key):
        """Selected sources per project, or None while responses are missing (dry run)."""
        h2a = "h2a" if name == "manual" else name + "-h2a"
        folder = self.dir / "select" / (short if name == "manual" else name)
        kit = set(spec.kit_sources())
        prompt = spec.SELECT_PROMPT.read_text()
        result, complete = {}, True

        def project_selection(project):
            pool = sorted(set(candidates[project]["union"]) - kit)
            pair = [cats[project, v] for v in config.VARIANTS]
            reaching = set()
            for variant, cat in zip(config.VARIANTS, pair):
                saved = read_json(self.taie_path(h2a, project, variant))
                if saved["status"] != "completed":
                    continue
                classes = set(taie.project_classes(self.classpaths[project, variant][1][0],
                                                   self.adapter(h2a, project).stem))
                for flow in spec.app_scoped(saved["flows"], classes):
                    reaching.update(spec.attribute(flow, cat, pool)[0])
            ordered = sorted(reaching)
            batches = [ordered[i:i + spec.BATCH] for i in range(0, len(ordered), spec.BATCH)]
            row = dict(pool=len(pool), reaching=ordered, selected=[], decisions=[], errors=[], valid=0)
            for number, batch in enumerate(batches, 1):
                label = project if len(batches) == 1 else "{}-b{}".format(project, number)
                try:
                    payload, sites = spec.selection_payload(batch, pair)
                except ValueError as exc:
                    row["errors"].append("{}: {}".format(label, exc))
                    row["selected"] = sorted(set(row["selected"]) | set(batch))
                    continue
                body = llm.request_body(config.MODELS[short], json.dumps(payload), system=prompt)
                record = llm.ask(folder / (label + ".json"), body, key)
                if record is None:
                    return project, None
                try:
                    decisions, errors, valid = spec.validate_selection(llm.answer_json(record), payload, sites)
                    chosen = spec.selected_sources(payload, decisions)
                    names = {c["id"]: c["signature"] for c in payload["candidates"]}
                    row["decisions"] += [dict(d, signature=names[d["id"]]) for d in decisions.values()]
                except ValueError as exc:  # failed request/answer: keep the whole batch
                    errors, valid, chosen = ["{}: {}".format(label, exc)], 0, batch
                row["errors"] += errors
                row["valid"] += valid
                row["selected"] = sorted(set(row["selected"]) | set(chosen))
            print("  select {} {} {}: pool={} reaching={} selected={} errors={}".format(
                name, short, project, len(pool), len(ordered), len(row["selected"]), len(row["errors"])), flush=True)
            return project, row

        with ThreadPoolExecutor(4) as pool:
            for project, row in pool.map(project_selection, [p for p in self.projects if p in candidates]):
                if row is None:
                    complete = False
                else:
                    result[project] = row
        if not complete:
            return None
        write_json(folder / "selection.json", result)
        return {p: r["selected"] for p, r in result.items()}

    # ---- LLM-written entry drivers --------------------------------------------
    def drivers(self, short, key):
        """Write drivers for ``short``; return False while responses are missing (dry run)."""
        name = "e-" + short

        def one(project):
            folder = self.dir / "entry" / short / project
            status = folder / "status.json"
            if status.is_file():
                return read_json(status)
            classpaths = [self.classpaths[project, v][1] for v in config.VARIANTS]
            driver = self.adapter(name + "-h2a", project)
            record = entry.generate(config.MODELS[short], folder, driver, classpaths, self.jhome,
                                    self.raw / "drivers" / short / project, key)
            if record["status"] != "pending":
                write_json(status, record)
            print("  driver {} {}: {}".format(short, project, record["status"]), flush=True)
            return record

        with ThreadPoolExecutor(4) as pool:
            records = list(pool.map(one, self.projects))
        return all(r["status"] != "pending" for r in records)

    # ---- hinted LLM -----------------------------------------------------------
    def hint(self, cfg, project):
        adapter, policy = self.adapter(cfg, project), self.policy(cfg, project)
        if not adapter.is_file() or not policy.is_dir():
            return None
        parts = ["Entry program `{}` (the analysis starts at its `main` method):\n```java\n{}\n```".format(
            adapter.name, adapter.read_text().rstrip())]
        parts += ["Policy file `{}`:\n```yaml\n{}\n```".format(f.name, f.read_text().rstrip())
                  for f in sorted(policy.glob("*.yml"))]
        return "\n\n".join(parts)

    def hinted_prompt(self, cfg, project, variant):
        hint = self.hint(cfg, project)
        if hint is None:
            return None
        files = llm.input_files(project, variant, "vanilla")[:1]  # the fix file only, at every level
        return TEMPLATE.read_text().format(config=hint, files=llm.render_files(files))

    def run_hinted(self, levels, samples, key, workers=8):
        cells = [(s, l, p, v, k) for s in self.models for l in levels for p in self.projects
                 for v in config.VARIANTS for k in range(1, samples + 1)
                 if not self.cell_path(s, l, p, v, k).is_file()]
        print("{} hinted cell(s) to request".format(len(cells)), flush=True)
        if key is None:
            return

        def one(cell):
            short, level, project, variant, sample = cell
            cfg = taie_config(level, short)
            prompt = self.hinted_prompt(cfg, project, variant)
            record = dict(model=config.MODELS[short], level=level, config=cfg, project=project, variant=variant,
                          sample=sample)
            if prompt is None:
                record["error"] = "No Tai-e configuration for {} (entry driver or policy missing)".format(cfg)
            else:
                body = llm.request_body(config.MODELS[short], prompt)
                record.update(llm.ask(self.cell_path(*cell), body, key) or {})
            write_json(self.cell_path(*cell), record)
            try:
                status = "{} location(s)".format(len(llm.cwe22_locations(record["response"])[0]))
            except (ValueError, KeyError, IndexError) as exc:
                status = "failed: {}".format(record.get("error", exc))
            print("{}-{} {} {} s{}: {}".format(short, level, project, variant, sample, status), flush=True)

        with ThreadPoolExecutor(workers) as pool:
            list(pool.map(one, cells))


def execute(run_dir, projects, models, samples=config.SAMPLES, dry_run=False, workers=8, baseline=BASELINE):
    """Run every missing step in order; resumable, and a dry run stops before any request."""
    run = Run(run_dir, projects, models, baseline=baseline)
    key = None if dry_run else config.secret("OPENROUTER_API_KEY")
    run.prepare_subjects()
    cats = run.catalogues("manual")
    found = run.candidates("manual", cats)
    run.write_policies("manual")
    run.write_policies("h1")
    run.write_policies("h2a", {p: c["union"] for p, c in found.items()})
    for cfg in ("manual", "h1", "h2a"):
        run.run_taie(cfg)
    ready = {"manual", "h1", "h2a"}
    for short in models:
        selected = run.select("manual", short, cats, found, key)
        if selected is not None:
            run.write_policies("h2b-" + short, selected)
            run.run_taie("h2b-" + short)
            ready.add("h2b-" + short)
        if not run.drivers(short, key):
            continue
        name = "e-" + short
        e_cats = run.catalogues(name)
        e_found = run.candidates(name, e_cats)
        run.write_policies(name + "-h2a", {p: c["union"] for p, c in e_found.items()})
        run.run_taie(name + "-h2a")
        selected = run.select(name, short, e_cats, e_found, key)
        if selected is not None:
            run.write_policies(name + "-h2b", selected)
            run.run_taie(name + "-h2b")
            ready.add(name + "-h2b")
    # The first level's hinted answers are the baseline run's hinted arm (``llm`` command), never made here.
    levels = [l for l in LEVELS[1:] if all(taie_config(l, s) in ready for s in models)]
    missing = [c for s in models for p in projects for v in config.VARIANTS for c in [run.cell_path(s, LEVELS[0], p, v, 1)]
               if not c.is_file()]
    if missing:
        print("Hinted baseline answers missing (run `llm --run {}`): {}".format(baseline, len(missing)), flush=True)
    if dry_run:
        print("Dry run: Tai-e configurations ready: {}; hinted levels ready: {}".format(sorted(ready), levels))
    run.run_hinted(levels, samples, key, workers)


# ---- scoring -------------------------------------------------------------------
def budgets(run_dir):
    """max_tokens actually sent, per model, read from the saved requests."""
    found = {}
    for path in run_dir.glob("*/**/*.json"):
        request = read_json(path).get("request") if path.name != "metrics.json" else None
        if isinstance(request, dict) and "max_tokens" in request:
            found.setdefault(request["model"], set()).add(request["max_tokens"])
    return {model: "/".join(map(str, sorted(v))) for model, v in sorted(found.items())}


def taie_locations(run, cfg, project, variant, scoped):
    path = run.taie_path(cfg, project, variant)
    if not path.is_file():
        return None, None
    result = read_json(path)
    if result["status"] != "completed":
        return [], result.get("error", "failed")
    return [tuple(x) for x in result["scoped_locations" if scoped else "locations"]], None


def hinted_locations(run, short, level, project, variant, sample):
    path = run.cell_path(short, level, project, variant, sample)
    if not path.is_file():
        return None, None
    record = read_json(path)
    try:
        return [tuple(x) for x in llm.cwe22_locations(record["response"])[0]], None
    except (ValueError, KeyError, IndexError) as exc:
        return [], record.get("error", str(exc))


def arms(models):
    """(level, label, loader args) rows of the report."""
    rows = []
    for level in LEVELS:
        for short in models if level in ("h2b", "e") else models[:1]:
            cfg = taie_config(level, short)
            suffix = {"h2b": " [{} selection]", "e": " [{} driver + selection]"}.get(level, "").format(
                short.capitalize())
            rows.append((level, "Tai-e" + suffix, ("taie", cfg, False)))
            rows.append((level, "Tai-e app scope" + suffix, ("taie", cfg, True)))
        for short in models:
            rows.append((level, "Hinted " + short.capitalize(), ("llm", short, level)))
    return rows


def evaluate(run_dir, projects=tuple(config.PROJECTS), models=tuple(config.MODELS), samples=config.SAMPLES,
             baseline=BASELINE):
    run = Run(run_dir, list(projects), list(models), baseline=baseline)
    info = manifest()
    check_dataset(info["dataset_commit"])
    labels = {p: fix_labels(info["subjects"][p]["slug"]) for p in projects}
    result = dict(run=run_dir.name, scored_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  dataset_commit=info["dataset_commit"], models={m: config.MODELS[m] for m in models},
                  samples=samples, max_tokens=budgets(run_dir), baseline=baseline, failures=[], arms=[])
    for level, label, (kind, a, b) in arms(models):
        per_sample = []
        for sample in range(1, (1 if kind == "taie" else samples) + 1):
            rows, fixed = [], {}
            for project in projects:
                for variant in config.VARIANTS:
                    if kind == "taie":
                        locations, failure = taie_locations(run, a, project, variant, b)
                    else:
                        locations, failure = hinted_locations(run, a, b, project, variant, sample)
                    if failure and not (kind == "taie" and b):  # list each Tai-e failure once
                        result["failures"].append(dict(level=level, arm=label, sample=sample, project=project,
                                                       variant=variant, reason=failure))
                    if variant == "fixed":
                        fixed[project] = None if locations is None else len(locations)
                    elif locations is None:
                        rows.append(dict(project=project, status="unscored"))
                    else:
                        rows.append(dict(project=project, status="scored", failure=failure,
                                         **score(locations, labels[project])))
            per_sample.append(dict(sample=sample, projects=rows, summary=aggregate(rows), fixed=fixed))
        result["arms"].append(dict(level=level, arm=label, samples=per_sample, summary=summarise(per_sample, projects)))
    result["selection"] = {p.parent.name: read_json(p) for p in sorted((run_dir / "select").glob("*/selection.json"))}
    result["drivers"] = {"{}/{}".format(p.parent.parent.name, p.parent.name): read_json(p)
                         for p in sorted((run_dir / "entry").glob("*/*/status.json"))}
    write_json(run_dir / "metrics.json", result)
    (run_dir / "REPORT.md").write_text(render(result, projects, labels))
    return result


def summarise(samples, projects):
    if not all(s["summary"]["complete"] for s in samples):
        return None
    per_project = {}
    for project in projects:
        rows = [next(r for r in s["projects"] if r["project"] == project) for s in samples]
        per_project[project] = dict(detected=sum(r["detected"] for r in rows), samples=len(rows),
                                    fdr=spread(r["fdr"] for r in rows), f1=spread(r["f1"] for r in rows),
                                    reported=[r["reported"] for r in rows], f1s=[r["f1"] for r in rows],
                                    failed=sum(bool(r["failure"]) for r in rows))
    return dict(detected=[s["summary"]["detected"] for s in samples],
                macro_fdr=spread(s["summary"]["macro_fdr"] for s in samples),
                macro_f1=spread(s["summary"]["macro_f1"] for s in samples), per_project=per_project)


def render(result, projects, labels):
    n = len(projects)
    lines = ["# Hint relaxation: Tai-e and hinted LLM", "",
             "Run `{}`, scored {}. Dataset commit `{}`.".format(result["run"], result["scored_at"],
                                                                result["dataset_commit"]),
             "Models: " + ", ".join("{} = `{}`".format(k, v) for k, v in result["models"].items()) + ".",
             "Hinted LLM: {} samples per cell; max_tokens per request: {}. Tai-e is deterministic (1 run).".format(
                 result["samples"], ", ".join("{} {}".format(k, v) for k, v in result["max_tokens"].items())), "",
             "Levels: " + "; ".join("**{}**".format(LEVEL_NAMES[l]) for l in LEVELS) + ".",
             "The first level's hinted LLM is the prose-hinted baseline of run `{}` (manual policy in words, fix".format(
                 result["baseline"]),
             "file and sink files). From H1 on, the hinted LLM sees exactly the entry program and policy files",
             "Tai-e receives, plus the production fix file. H2b and E are per model: each model",
             "selects its own sources (and writes its own driver) and is hinted with that configuration.",
             "*Tai-e app scope* keeps only flows whose two endpoint methods are project or entry code.", "",
             "Unit: `(simple class, method)` on the vulnerable revision; Detected = K > 0, FDR = 1 − K/N,",
             "F1 = 2K/(N+K). Fix-location proxies, not verified vulnerability labels.", "",
             "## Summary", "", "Mean over samples, [min–max] when samples differ.", "",
             "| Level | Arm | Detected | Macro FDR ↓ | Macro F1 ↑ |", "| --- | --- | --- | ---: | ---: |"]
    for arm in result["arms"]:
        s = arm["summary"]
        if s is None:
            lines.append("| {} | {} | incomplete | – | – |".format(arm["level"].upper(), arm["arm"]))
            continue
        lines.append("| {} | {} | {} | {} | {} |".format(arm["level"].upper(), arm["arm"],
                                                         ", ".join("{}/{}".format(d, n) for d in s["detected"]),
                                                         ranged(s["macro_fdr"], pct), ranged(s["macro_f1"], f4)))
    lines += ["", "Failures count as empty output (undetected, F1 0, FDR undefined):", ""]
    lines += ["- {} / {} s{} / {} {}: {}".format(f["level"].upper(), f["arm"], f["sample"], f["project"],
                                                f["variant"], f["reason"]) for f in result["failures"]] or ["- none"]
    if result["selection"]:
        lines += ["", "## Source selection", "",
                  "| Selector | Project | Non-kit candidates | Reaching a sink (H2a) | Kept | Errors |",
                  "| --- | --- | ---: | ---: | ---: | ---: |"]
        for selector, rows in result["selection"].items():
            for project, row in rows.items():
                lines.append("| {} | {} | {} | {} | {} | {} |".format(selector, project, row["pool"],
                                                                       len(row["reaching"]), len(row["selected"]),
                                                                       len(row["errors"])))
    if result["drivers"]:
        lines += ["", "## LLM-written entry drivers", "", "| Model / project | Status | Picked classes | Rounds |",
                  "| --- | --- | --- | ---: |"]
        for name, row in result["drivers"].items():
            lines.append("| {} | {} | {} | {} |".format(name, row["status"] + (": " + row["error"] if row.get(
                "error") else ""), ", ".join(c.rsplit(".", 1)[-1] for c in row.get("picked", [])),
                len(row.get("attempts", []))))
    for project in projects:
        fixes = sorted({"{}.{}".format(r["class"], r["method"]) for r in labels[project]})
        lines += ["", "## {}".format(project), "", "Fix methods: " + ", ".join("`{}`".format(m) for m in fixes), "",
                  "| Level | Arm | Detected | N per sample | FDR ↓ | F1 ↑ | Fixed-revision N |",
                  "| --- | --- | :---: | --- | ---: | ---: | --- |"]
        for arm in result["arms"]:
            fixed = ", ".join("–" if s["fixed"][project] is None else str(s["fixed"][project]) for s in arm["samples"])
            if arm["summary"] is None:
                lines.append("| {} | {} | incomplete | | | | {} |".format(arm["level"].upper(), arm["arm"], fixed))
                continue
            p = arm["summary"]["per_project"][project]
            detected = "{}/{}".format(p["detected"], p["samples"]) + (
                " ({} failed)".format(p["failed"]) if p["failed"] else "")
            lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
                arm["level"].upper(), arm["arm"], detected, ", ".join(map(str, p["reported"])),
                ranged(p["fdr"], pct), ranged(p["f1"], f4), fixed))
    return "\n".join(lines) + "\n"
