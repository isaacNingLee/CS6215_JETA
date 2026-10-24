"""LLMDFA (Wang et al., NeurIPS 2024, "LLMDFA: Analyzing Dataflow in Code with Large Language
Models") as a published baseline, given the Hinted level's inputs.

The pinned upstream engine (data/llmdfa.lock.json) is cloned into $CS6215_WORK/tools/llmdfa with
its own virtualenv. cwe22/llmdfa_runtime.py (ported from CS6215_proj) patches the engine's
boundaries for real repositories, never its source, and routes every model call to OpenRouter;
its DEVIATIONS list every change. cwe22/llmdfa_specs.py renders the CWE-22 source/sink prompt
specs from the same manual policy as Tai-e's and the hinted LLM's, and checks all three agree.

A case is one (model, sample, project, revision). LLMDFA parses the production fix file, the
hinted sink files, the entry class and the project's Tai-e entry adapter (plus their superclass
closure), and roots its analysis at the Tai-e entry point. Each case runs in its own subprocess,
with a cap on requests and dollars; a case that finishes, completed or failed, is final and never
re-run. Scoring counts both endpoints of every validated trace, the unit of every other arm; a
failed case reports nothing (like a failed LLM answer).
"""
import ast
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from . import agreement, config, llmdfa_specs as specs
from .llm import hints
from .report import f4, pct, ranged
from .subjects import check_dataset, fix_file, fix_labels, manifest
from .util import capture, read_json, sha256, write_json

LOCK = config.DATA / "llmdfa.lock.json"
LLMDFA = config.TOOLS / "llmdfa"
VENV = config.TOOLS / "llmdfa-venv"
PYTHON = VENV / "bin/python"
RUNTIME = Path(__file__).resolve().parent / "llmdfa_runtime.py"
PACKAGES = ["setuptools", "tree-sitter==0.20.2", "openai==1.51.0", "tiktoken", "z3-solver==4.13.0.0"]
MODELS = ("qwen", "deepseek")
MAX_REQUESTS = 1200  # per case; the propagator asks one question per (source, sink) pair per function
COST_LIMIT = 3.0  # dollars per case
REQUEST_TIMEOUT = 240  # seconds per request
CASE_TIMEOUT = 5400  # seconds per case


# ---- setup -----------------------------------------------------------------------------------
def git(path, *args):
    return capture(["git", "-C", path] + list(args))


def verify_upstream(lock):
    if git(LLMDFA, "rev-parse", "HEAD") != lock["commit"]:
        raise RuntimeError("Wrong LLMDFA revision; expected " + lock["commit"])
    if git(LLMDFA, "status", "--porcelain", "--untracked-files=no"):
        raise RuntimeError("LLMDFA tracked files have local modifications")
    if git(LLMDFA, "ls-files", "--others", "--exclude-standard", "src"):  # could shadow the pinned code
        raise RuntimeError("LLMDFA src contains untracked files")
    return lock["commit"]


def setup(python=sys.executable):
    """Clone the pinned engine, create its virtualenv and build the tree-sitter grammar."""
    lock = read_json(LOCK)
    if not LLMDFA.exists():
        LLMDFA.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--no-checkout", lock["repository"], str(LLMDFA)], check=True)
        subprocess.run(["git", "-C", str(LLMDFA), "checkout", "--detach", lock["commit"]], check=True)
    verify_upstream(lock)
    if not PYTHON.exists():
        subprocess.run([python, "-m", "venv", str(VENV)], check=True)
        subprocess.run([str(PYTHON), "-m", "pip", "install", "--quiet"] + PACKAGES, check=True)
    grammar = LLMDFA / "lib/build/my-languages.so"
    if not grammar.exists():  # build.py clones tree-sitter-java at the pinned commit
        subprocess.run([str(PYTHON), "build.py"], cwd=str(LLMDFA / "lib"), check=True,
                       env=dict(os.environ, SETUPTOOLS_USE_DISTUTILS="local"))
    vendor = LLMDFA / "lib/vendor/tree-sitter-java"
    if git(vendor, "rev-parse", "HEAD") != lock["tree_sitter_java_commit"]:
        raise RuntimeError("tree-sitter-java is not at the pinned commit")
    print("LLMDFA {} ready in {} ({})".format(lock["commit"][:12], LLMDFA, capture([PYTHON, "--version"])))


# ---- cases -----------------------------------------------------------------------------------
def entry_file(project, variant, entry_class):
    """The file declaring the entry class: a Tai-e adapter (Spark's entry is one), else production source."""
    adapter = config.DATA / "adapters" / (entry_class + ".java")
    if adapter.is_file():
        return adapter
    matches = sorted(p for p in (config.SUBJECTS / project / variant / "src/main/java").rglob(entry_class + ".java"))
    if not matches:
        raise RuntimeError("No file declares entry class {} for {}".format(entry_class, project))
    return matches[0]


def case_files(project, variant, entry_class):
    """Fix file, hinted sink files, entry class and Tai-e adapter, plus their superclass closure."""
    spec = manifest()["subjects"][project]
    subject = config.SUBJECTS / project / variant
    paths = [subject / fix_file(fix_labels(spec["slug"]))]
    paths += [subject / rel for rel in hints()["sink_files"].get(project, [])]
    paths += [entry_file(project, variant, entry_class), config.DATA / "adapters" / (spec["entry"] + ".java")]
    index = {}
    for candidate in sorted((subject / "src/main/java").rglob("*.java")):
        index.setdefault(candidate.stem, []).append(candidate)
    pending, visited = list(paths), set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        for parent in re.findall(r"\bextends\s+([\w.]+)", path.read_text(errors="replace")):
            matches = index.get(parent.rsplit(".", 1)[-1], [])
            if len(matches) > 1:
                raise RuntimeError("Ambiguous superclass source: " + parent)
            for match in matches:
                if match not in paths:
                    paths.append(match)
                    pending.append(match)
    ordered = []
    for path in paths:
        resolved = path.resolve()
        if not resolved.is_file():
            raise RuntimeError("Missing case file: " + str(resolved))
        if resolved not in ordered:
            ordered.append(resolved)
    return ordered


def verify_checkouts(projects):
    """Each checkout is at its pinned commit with unmodified Java sources (LLMDFA reads them)."""
    subjects = manifest()["subjects"]
    for project in projects:
        for variant in config.VARIANTS:
            checkout = config.SUBJECTS / project / variant
            if git(checkout, "rev-parse", "HEAD") != subjects[project][variant]:
                raise RuntimeError("Wrong {} {} checkout; run the taie step first".format(project, variant))
            java = [f for f in git(checkout, "diff", "HEAD", "--name-only", "--").split() if f.endswith(".java")]
            if java:
                raise RuntimeError("{} {} has modified Java sources: {}".format(project, variant, ", ".join(java)))


def arm_dir(out, short, sample):
    return out / "llmdfa" / "{}-s{}".format(short, sample)


def plan_for(out, short, sample, projects):
    """The plan the runtime reads (arm_dir/plan.json); written once and then fixed."""
    path = arm_dir(out, short, sample) / "plan.json"
    if path.is_file():
        return read_json(path)
    lock = read_json(LOCK)
    cases = []
    for project in projects:
        policy = specs.POLICY[project]
        entry_class, entry_method = policy["entry"].split(".")
        for variant in config.VARIANTS:
            files = case_files(project, variant, entry_class)
            cases.append(dict(id="{}-{}".format(variant, project), project=project, variant=variant,
                              entry_class=entry_class, entry_method=entry_method, files=[str(f) for f in files],
                              files_sha256={str(f): sha256(f) for f in files}))
    plan = dict(llmdfa_dir=str(LLMDFA), commit=lock["commit"], model=config.MODELS[short], short=short,
                sample=sample, bug_type=lock["bug_type"], propagator_spec=lock["propagator_spec"],
                validator_spec=lock["validator_spec"], syn_parser=False, fscot=True, syn_solver=False,
                solving_refine_number=3, max_requests=MAX_REQUESTS, cost_limit=COST_LIMIT,
                max_tokens=config.max_tokens(config.MODELS[short]), request_timeout=REQUEST_TIMEOUT,
                case_timeout=CASE_TIMEOUT, cases=cases, policy={p: specs.POLICY[p] for p in projects},
                taie_policy=specs.check_policy_matches_taie(projects),
                deviations=list(runtime_deviations()), configuration=lock["configuration"],
                runtime_sha256=sha256(RUNTIME), specs_sha256=sha256(Path(specs.__file__)))
    write_json(path, plan)
    return plan


def runtime_deviations():
    """DEVIATIONS from the runtime, read without importing LLMDFA."""
    for node in ast.parse(RUNTIME.read_text()).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "DEVIATIONS" for t in node.targets):
            return list(ast.literal_eval(node.value))
    raise RuntimeError("No DEVIATIONS in " + str(RUNTIME))


def run_case(out, short, sample, case, key):
    """Run one case once; returns its result row (also saved as result.json)."""
    work = arm_dir(out, short, sample) / case["id"]
    result_path = work / "result.json"
    if result_path.is_file():
        return read_json(result_path)
    if work.exists():
        return dict(id=case["id"], status="interrupted",
                    error="{} exists without result.json; remove it to run the case again".format(work))
    for path, digest in case["files_sha256"].items():
        if sha256(Path(path)) != digest:
            raise RuntimeError("Case input changed since the plan was written: " + path)
    work.mkdir(parents=True)
    row = dict(id=case["id"], project=case["project"], variant=case["variant"], status="failed")
    env = dict(os.environ, OPENROUTER_API_KEY=key, PYTHONPATH=str(config.ROOT), SETUPTOOLS_USE_DISTUTILS="local",
               PATH=str(PYTHON.parent) + os.pathsep + os.environ.get("PATH", ""))
    started = time.monotonic()
    try:
        completed = subprocess.run([str(PYTHON), str(RUNTIME), str(work), case["id"]], cwd=str(LLMDFA / "src"),
                                   env=env, capture_output=True, text=True, timeout=CASE_TIMEOUT)
        (work / "stdout.txt").write_text(completed.stdout)
        (work / "stderr.txt").write_text(completed.stderr)
        if completed.returncode != 0:
            raise RuntimeError("exit {}: {}".format(completed.returncode, completed.stderr.strip()[-600:]))
        predictions = read_json(work / "predictions.json")
        row.update(status="completed", locations=predictions["locations"], requests=predictions["requests"],
                   analyzed_functions=predictions["analyzed_functions"],
                   truncated_answers=predictions.get("truncated_answers", 0))
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        row["error"] = "{}: {}".format(type(exc).__name__, exc)
    ledger = read_json(work / "ledger.json") if (work / "ledger.json").is_file() else {}
    row.update(seconds=round(time.monotonic() - started, 1), attempts=ledger.get("attempts", 0),
               cost=round(ledger.get("reported_cost", 0.0), 6), response_models=ledger.get("response_models", {}))
    write_json(result_path, row)
    print("  llmdfa {}-s{} {}: {} ({} requests, ${:.4f}, {}s){}".format(
        short, sample, case["id"], row["status"], row["attempts"], row["cost"], row["seconds"],
        "" if row["status"] == "completed" else " " + row["error"][-160:]), flush=True)
    return row


def execute(out, models=MODELS, samples=config.SAMPLES, projects=tuple(config.PROJECTS), workers=4, dry_run=False):
    """Run every case that has no result; True when every case has one."""
    verify_upstream(read_json(LOCK))
    if not PYTHON.exists():
        raise RuntimeError("Run python3 -m cwe22 llmdfa --setup first")
    specs.check_policy_matches_hints(projects)
    verify_checkouts(projects)
    jobs = [(short, sample, case) for short in models for sample in range(1, samples + 1)
            for case in plan_for(out, short, sample, list(config.PROJECTS))["cases"] if case["project"] in projects]
    todo = [j for j in jobs if not (arm_dir(out, j[0], j[1]) / j[2]["id"] / "result.json").is_file()]
    print("{} LLMDFA case(s), {} to run".format(len(jobs), len(todo)), flush=True)
    if dry_run:
        for short, sample, case in todo:
            print("  {}-s{} {}: {} files".format(short, sample, case["id"], len(case["files"])))
        return not todo
    key = config.secret("OPENROUTER_API_KEY")
    with ThreadPoolExecutor(workers) as pool:
        rows = list(pool.map(lambda j: run_case(out, *j, key), todo))
    return all(r["status"] in ("completed", "failed") for r in rows)


# ---- scoring ----------------------------------------------------------------------------------
def evaluate(out, models=MODELS, samples=config.SAMPLES, projects=tuple(config.PROJECTS)):
    projects = list(projects)
    info = manifest()
    check_dataset(info["dataset_commit"])
    labels = {p: fix_labels(info["subjects"][p]["slug"]) for p in projects}

    def result(short, sample, project, variant):
        path = arm_dir(out, short, sample) / "{}-{}".format(variant, project) / "result.json"
        return read_json(path) if path.is_file() else None

    def loader(short):
        def load(project, variant, sample):
            row = result(short, sample, project, variant)
            if row is None or row["status"] == "interrupted":
                return None, None
            if row["status"] != "completed":
                return [], row.get("error", "failed")
            return [tuple(x) for x in row["locations"]], None
        return load

    report = dict(run=out.name, scored_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  dataset_commit=info["dataset_commit"], lock=read_json(LOCK), arms=[], cases=[])
    for short in models:
        per_sample = agreement.score_arm(loader(short), samples, projects, labels)
        report["arms"].append(dict(model=short, label="LLMDFA " + ("Qwen" if short == "qwen" else "DeepSeek"),
                                   samples=per_sample, summary=agreement.summarise(per_sample, projects)))
        for sample in range(1, samples + 1):
            for project in projects:
                for variant in config.VARIANTS:
                    row = result(short, sample, project, variant)
                    report["cases"].append(dict(model=short, sample=sample, project=project, variant=variant,
                                                **({k: row.get(k) for k in ("status", "attempts", "truncated_answers",
                                                                            "cost", "seconds", "error")} if row else
                                                   dict(status="not run"))))
    plans = [arm_dir(out, s, k) / "plan.json" for s in models for k in range(1, samples + 1)]
    report["deviations"] = next((read_json(p)["deviations"] for p in plans if p.is_file()), [])
    write_json(out / "llmdfa" / "metrics.json", report)
    (out / "llmdfa" / "REPORT.md").write_text(render(report, labels))
    return report


def render(report, labels):
    n, counts = len(labels), agreement.counts
    lock = report["lock"]
    lines = ["# LLMDFA baseline (Wang et al., NeurIPS 2024)", "",
             "Run `{}`, scored {}. Dataset commit `{}`. Upstream {} @ `{}`; {}.".format(
                 report["run"], report["scored_at"], report["dataset_commit"], lock["repository"], lock["commit"][:12],
                 lock["configuration"]), "",
             "Inputs as at the Hinted level: the manual per-project source/sink policy (as CWE-22 prompt specs) and",
             "the Tai-e entry point; LLMDFA parses the fix file, the hinted sink files, the entry class and the entry",
             "adapter. Locations are both endpoints of every validated trace. A failed case reports nothing.", "",
             "| Arm | Detected ↑ | Macro FDR ↓ | Macro F1 ↑ | Fixed: flagged ↓ | Pair-correct ↑ |",
             "| --- | --- | ---: | ---: | --- | --- |"]
    for arm in report["arms"]:
        s = arm["summary"]
        if s is None:
            lines.append("| {} | incomplete | – | – | – | – |".format(arm["label"]))
            continue
        lines.append("| {} | {} | {} | {} | {} | {} |".format(
            arm["label"], counts(s["detected"], n), ranged(s["macro_fdr"], pct), ranged(s["macro_f1"], f4),
            counts(s["flagged"], n), counts(s["pair_correct"], n)))
    lines += ["", "## Cases", "", "Cut off: answers that hit the token limit, used as returned (as upstream does).", "",
              "| Model | Sample | Project | Revision | Status | Requests | Cut off | Cost | Seconds |",
              "| --- | ---: | --- | --- | --- | ---: | ---: | ---: | ---: |"]
    for c in report["cases"]:
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            c["model"], c["sample"], c["project"], c["variant"],
            c["status"] + (": " + c["error"][-120:] if c.get("error") else ""), c.get("attempts", ""),
            c.get("truncated_answers", ""),
            "" if c.get("cost") is None else "${:.4f}".format(c["cost"]), c.get("seconds", "")))
    total = sum(c.get("cost") or 0 for c in report["cases"])
    lines += ["", "Total reported cost: ${:.2f}.".format(total), "", "## Deviations from upstream", ""]
    lines += ["- " + d for d in report["deviations"]] or ["- (no plan written)"]
    return "\n".join(lines) + "\n"
