"""Multiagent debate (Du et al., 2023, "Improving Factuality and Reasoning in Language
Models through Multiagent Debate") between the two hinted LLMs.

Round 1 is the hinted arm of a hint-relaxation run (relax.py): at every level, Qwen and
DeepSeek answer the same hinted prompt for each project, revision and sample. At the
first level that is the prose-hinted baseline; from H1 on, the Tai-e configuration plus
the production fix file. In round 2 each model continues its own
conversation with Du et al.'s update prompt (data/prompts/debate/update.txt), which
shows the other model's answer, and answers again. Nothing else is added: no new
question, role, filter or decision rule.

At H2b and E each model's hinted prompt shows its own configuration. To debate one
configuration, the model that did not answer that prompt first answers it in a new
round-1 call. Every call reuses the saved hinted request's settings (temperature,
max_tokens, reasoning) and is saved once and never resent.

Arms per Tai-e configuration: each model's answer before and after the debate, and the
locations both models report (Du et al.'s majority vote, with two agents), before and
after the debate. Scoring is the same as for every other arm (agreement.score_arm).
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import agreement, config, llm, relax
from .report import f4, pct, ranged
from .subjects import check_dataset, fix_labels, manifest
from .util import read_json, sha256, write_json

UPDATE = config.DATA / "prompts/debate/update.txt"
OPPONENT_PROMPT = config.DATA / "prompts/debate/opponent.txt"
AGENTS = ("qwen", "deepseek")
OPPONENT = "deepseek"  # model that plays the opposing agent
LATER_CALLS = 2 * len(AGENTS) + 1  # plain round 2, the opponent, opposed round 2


class Debate:
    def __init__(self, out, relax_run, models=AGENTS, levels=tuple(relax.LEVELS), baseline=relax.BASELINE):
        self.out, self.relax_dir = out, config.RESULTS / relax_run
        self.relax = relax.Run(self.relax_dir, list(config.PROJECTS), list(models), baseline=baseline)
        self.configs = [c for c in agreement.configs(list(models)) if c[0] in levels]

    # ---- paths -------------------------------------------------------------------------
    def hinted_path(self, short, level, project, variant, sample):
        """Saved hinted answer (the first level's are the baseline run's hinted arm)."""
        return self.relax.cell_path(short, level, project, variant, sample)

    def round1_path(self, level, cfg, short, project, variant, sample):
        """The saved hinted answer when ``short`` answered ``cfg`` there, else a new call."""
        if relax.taie_config(level, short) == cfg:
            return self.hinted_path(short, level, project, variant, sample)
        return self.out / "round1" / cfg / short / "{}-{}-s{}.json".format(project, variant, sample)

    def round2_path(self, cfg, short, project, variant, sample, opposed=False):
        return (self.out / ("round2-opposed" if opposed else "round2") / cfg / short /
                "{}-{}-s{}.json".format(project, variant, sample))

    def opponent_path(self, cfg, project, variant, sample):
        return self.out / "opponent" / cfg / "{}-{}-s{}.json".format(project, variant, sample)

    def cells(self, samples):
        return [(level, cfg, p, v, k) for level, cfg, _ in self.configs for p in config.PROJECTS
                for v in config.VARIANTS for k in range(1, samples + 1)]

    # ---- requests ------------------------------------------------------------------------
    def question(self, level, cfg, project, variant, sample):
        """The hinted request of the model that owns ``cfg``; None when it has no configuration."""
        owner = next(s for s in AGENTS if relax.taie_config(level, s) == cfg)
        record = read_json(self.hinted_path(owner, level, project, variant, sample))
        return record.get("request")

    def budget(self, short):
        """The saved hinted run's request settings for ``short`` (same budget in every round)."""
        for path in sorted((self.relax_dir / "llm").glob(short + "-*/*.json")):
            request = read_json(path).get("request")
            if request:
                return {k: v for k, v in request.items() if k != "messages"}
        raise RuntimeError("No saved hinted request for " + short)

    def run_cell(self, cell, key):
        """Both rounds of one cell; returns the number of calls still missing (0 when done)."""
        level, cfg, project, variant, sample = cell
        request = self.question(level, cfg, project, variant, sample)
        if request is None:
            return 0
        first = {}
        for short in AGENTS:
            path = self.round1_path(level, cfg, short, project, variant, sample)
            if path.is_file():
                first[short] = read_json(path)
            else:
                first[short] = llm.ask(path, dict(self.budget(short), messages=request["messages"]), key)
        if any(r is None for r in first.values()):
            return sum(r is None for r in first.values()) + LATER_CALLS
        missing = 0

        def round2(others, opposed):
            nonlocal missing
            for short in AGENTS:
                messages = list(first[short]["request"]["messages"]) + [
                    dict(role="assistant", content=content(first[short])),
                    dict(role="user", content=update_prompt(others(short)))]
                body = dict({k: v for k, v in first[short]["request"].items() if k != "messages"}, messages=messages)
                path = self.round2_path(cfg, short, project, variant, sample, opposed)
                missing += llm.ask(path, body, key) is None

        round2(lambda short: [content(first[o]) for o in AGENTS if o != short], False)
        # The opposing agent argues against both round-1 answers; then each analyst also reads it.
        challenge = OPPONENT_PROMPT.read_text().rstrip("\n").format(
            question=request["messages"][-1]["content"], answers=solutions([content(first[s]) for s in AGENTS]))
        opponent = llm.ask(self.opponent_path(cfg, project, variant, sample),
                           dict(self.budget(OPPONENT), messages=[dict(role="user", content=challenge)]), key)
        if opponent is None:
            return missing + 1 + len(AGENTS)
        round2(lambda short: [content(first[o]) for o in AGENTS if o != short] + [content(opponent)], True)
        return missing

    # ---- answers ---------------------------------------------------------------------------
    def answer(self, round_, level, cfg, short, project, variant, sample):
        """``(locations, failure)``; ``(None, None)`` when the cell was never run."""
        if self.question(level, cfg, project, variant, sample) is None:
            return [], "No Tai-e configuration for " + cfg
        path = (self.round1_path(level, cfg, short, project, variant, sample) if round_ == 1
                else self.round2_path(cfg, short, project, variant, sample, opposed=round_ == "2o"))
        if not path.is_file():
            return None, None
        record = read_json(path)
        try:
            return [tuple(x) for x in llm.cwe22_locations(record["response"])[0]], None
        except (ValueError, KeyError, IndexError) as exc:
            return [], "{} round {}: {}".format(short.capitalize(), round_, record.get("error", exc))


def content(record):
    """An agent's answer text as the other agents see it (a truncated answer is shown as is)."""
    try:
        text = record["response"]["choices"][0]["message"].get("content") or ""
    except (KeyError, IndexError, TypeError):
        text = ""
    return text.strip() or "(no answer)"


def solutions(answers):
    return "".join("\n\n One agent solution: ```{}```".format(a) for a in answers)


def update_prompt(others):
    return UPDATE.read_text().rstrip("\n").format(answers=solutions(others))


def execute(out, relax_run, samples=config.SAMPLES, levels=tuple(relax.LEVELS), workers=8, dry_run=False):
    """Make every missing call; True when the debate is complete."""
    run = Debate(out, relax_run, levels=levels)
    key = None if dry_run else config.secret("OPENROUTER_API_KEY")
    cells = run.cells(samples)
    with ThreadPoolExecutor(workers) as pool:
        missing = list(pool.map(lambda c: run.run_cell(c, key), cells))
    asked = [c for c in cells if run.question(c[0], c[1], c[2], c[3], c[4]) is not None]
    print("{} cells, {} with a hinted question; {} call(s) still missing".format(
        len(cells), len(asked), sum(missing)), flush=True)
    if dry_run:
        new1 = sum(not run.round1_path(l, c, s, p, v, k).is_file() for l, c, p, v, k in asked for s in AGENTS)
        chars = sum(sum(len(m["content"]) for m in run.question(*c)["messages"]) for c in asked)
        print("Dry run: {} new round-1 call(s), {} later call(s); round-1 questions {:,} characters".format(
            new1, len(asked) * LATER_CALLS, chars), flush=True)
    return sum(missing) == 0


# ---- scoring ------------------------------------------------------------------------------
# (arm, label, round); round "2o" is round 2 after the opposing agent.
ARMS = [("r1", "Hinted {}", 1), ("r1-both", "Hinted consensus, no debate", 1),
        ("r2", "Debated {}", 2), ("r2-both", "Debated consensus", 2),
        ("r2o", "Opposed debate {}", "2o"), ("r2o-both", "Opposed debate consensus", "2o")]
# Agreement guard filtered by the hinted answers: keep a location if either model reports it
# (fixed before scoring). Round 1 is the no-debate control.
FILTERS = [(None, "Agreement guard"), (1, "+ hinted filter, no debate"), (2, "+ debate filter"),
           ("2o", "+ opposed debate filter")]


def evaluate(out, relax_run, samples=config.SAMPLES, levels=tuple(relax.LEVELS),
             agreement_runs=("261020r", "261020g")):
    run = Debate(out, relax_run, levels=levels)
    projects = list(config.PROJECTS)
    info = manifest()
    check_dataset(info["dataset_commit"])
    labels = {p: fix_labels(info["subjects"][p]["slug"]) for p in projects}

    def single(round_, level, cfg, short):
        return lambda p, v, k: run.answer(round_, level, cfg, short, p, v, k)

    def both(round_, level, cfg):
        def load(p, v, k):
            answers = [run.answer(round_, level, cfg, s, p, v, k) for s in AGENTS]
            if any(a[0] is None for a in answers):
                return None, None
            return (sorted(set(answers[0][0]) & set(answers[1][0])),
                    "; ".join(a[1] for a in answers if a[1]) or None)
        return load

    def filtered(index, n, level, cfg, scoped, round_):
        """The agreement guard's priority tier, kept only where either model reports the location."""
        def load(p, v, k):
            row = index.get((cfg, scoped, p, v, min(k, n)))
            if row is None or row["status"] == "unscored":
                return None, None
            priority = [tuple(x) for x in row["priority"]]
            if round_ is None:
                return priority, None
            answers = [run.answer(round_, level, cfg, s, p, v, k) for s in AGENTS]
            if any(a[0] is None for a in answers):
                return None, None
            named = set(answers[0][0]) | set(answers[1][0])
            return [x for x in priority if x in named], "; ".join(a[1] for a in answers if a[1]) or None
        return load

    guards = {}
    for name in agreement_runs:
        predictions = read_json(config.RESULTS / name / "predictions.json")
        guards[name] = ({(r["config"], r["scoped"], r["project"], r["variant"], r["sample"]): r
                         for r in predictions if r["guard"]}, max(r["sample"] for r in predictions))
    result = dict(run=out.name, scored_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  dataset_commit=info["dataset_commit"], relax_run=relax_run,
                  models={m: config.MODELS[m] for m in AGENTS}, opponent=OPPONENT, samples=samples,
                  agreement_runs={n: g[1] for n, g in guards.items()},
                  prompts_sha256={p.name: sha256(p) for p in (UPDATE, OPPONENT_PROMPT)}, arms=[], failures=[])
    for level, cfg, suffix in run.configs:
        rows = []
        for arm, label, round_ in ARMS:
            if arm.endswith("both"):
                rows.append(("debate", arm, label, both(round_, level, cfg)))
            else:
                rows += [("debate", arm + "-" + s, label.format(s.capitalize()), single(round_, level, cfg, s))
                         for s in AGENTS]
        for name, (index, n) in guards.items():
            for scoped in (False, True):
                for round_, label in FILTERS:
                    rows.append(("filter", "{}-{}-{}".format(name, int(scoped), round_),
                                 "{} ({}{})".format(label, name, ", app scope" if scoped else ""),
                                 filtered(index, n, level, cfg, scoped, round_)))
        for kind, arm, label, loader in rows:
            per_sample = agreement.score_arm(loader, samples, projects, labels)
            result["arms"].append(dict(level=level, config=cfg, kind=kind, arm=arm, label=label + suffix,
                                       samples=per_sample, summary=agreement.summarise(per_sample, projects)))
            if kind == "debate" and not arm.endswith("both"):
                result["failures"] += [dict(level=level, arm=label + suffix, sample=k, project=p, variant=v, reason=f)
                                       for k in range(1, samples + 1) for p in projects for v in config.VARIANTS
                                       for f in [loader(p, v, k)[1]] if f]
    result["changes"] = changes(run, samples)
    result["cost"] = cost(run)
    write_json(out / "metrics.json", result)
    (out / "REPORT.md").write_text(render(result, labels))
    return result


def changes(run, samples):
    """How often each round 2 changed a model's location set, per configuration."""
    rows = []
    for level, cfg, suffix in run.configs:
        for short in AGENTS:
            row = dict(level=level, config=cfg, suffix=suffix, model=short)
            for round_ in (2, "2o"):
                changed = total = 0
                for _, _, p, v, k in [c for c in run.cells(samples) if c[1] == cfg]:
                    a, b = (run.answer(r, level, cfg, short, p, v, k)[0] for r in (1, round_))
                    if a is not None and b is not None:
                        total += 1
                        changed += set(a) != set(b)
                row[str(round_)] = [changed, total]
            rows.append(row)
    return rows


def cost(run):
    """Usage of every call this debate made (new round 1, round 2, opponent, opposed round 2)."""
    paths = [p for p in run.out.rglob("*.json") if p.parent != run.out]
    usage = [(read_json(p).get("response") or {}).get("usage") or {} for p in paths]
    return dict(calls=len(paths), prompt_tokens=sum(u.get("prompt_tokens", 0) for u in usage),
                completion_tokens=sum(u.get("completion_tokens", 0) for u in usage),
                reported_cost=sum(u.get("cost", 0) or 0 for u in usage))


def render(result, labels):
    n, counts = len(labels), agreement.counts
    c = result["cost"]
    lines = ["# Multiagent debate between the hinted LLMs", "",
             "Run `{}`, scored {}. Dataset commit `{}`. Round 1 is the hinted arm of run `{}`.".format(
                 result["run"], result["scored_at"], result["dataset_commit"], result["relax_run"]),
             "Models: " + ", ".join("{} = `{}`".format(k, v) for k, v in result["models"].items()) +
             "; the opposing agent is {}.".format(result["opponent"].capitalize()), "",
             "Du et al. (2023): both models answer the same hinted prompt (round 1), then each reads the other's",
             "answer through the paper's update prompt and answers again (round 2). *Opposed debate*: an opposing",
             "agent first argues against both round-1 answers (data/prompts/debate/opponent.txt), and each model",
             "reads the other's answer and that argument. *Consensus* keeps the locations both models report.",
             "At H2b and E the bracket names the model whose configuration both models answer.", "",
             "Vulnerable revision: Detected, FDR, F1. Flagged = the patched fix method is still reported on the",
             "fixed revision; Pair-correct = reported on the vulnerable revision and not the fixed one (projects",
             "/{}, per sample).".format(n), "",
             "Calls made by this debate: {:,} (prompt tokens {:,}, completion tokens {:,}, reported cost ${:.4f}).".format(
                 c["calls"], c["prompt_tokens"], c["completion_tokens"], c["reported_cost"])]

    def table(kind, intro):
        out = intro + ["", "| Level | Arm | Detected ↑ | Macro FDR ↓ | Macro F1 ↑ | Fixed: flagged ↓ | Pair-correct ↑ |",
                       "| --- | --- | --- | ---: | ---: | --- | --- |"]
        for arm in (a for a in result["arms"] if a["kind"] == kind):
            s = arm["summary"]
            name = "**{}**".format(arm["label"]) if "2o" in arm["arm"] else arm["label"]
            if s is None:
                out.append("| {} | {} | incomplete | – | – | – | – |".format(arm["level"].upper(), name))
                continue
            out.append("| {} | {} | {} | {} | {} | {} | {} |".format(
                arm["level"].upper(), name, counts(s["detected"], n), ranged(s["macro_fdr"], pct),
                ranged(s["macro_f1"], f4), counts(s["flagged"], n), counts(s["pair_correct"], n)))
        return out

    lines += [""] + table("filter", [
        "## Agreement guard + debate filter", "",
        "The agreement guard's output (runs {}), keeping a location only if either model reports it: before".format(
            ", ".join("`{}` ({} sample(s))".format(k, v) for k, v in result["agreement_runs"].items())),
        "the debate (control), after the debate, and after the opposed debate. A one-sample guard run is paired",
        "with every debate sample. Mean over samples, [min–max] when samples differ."])
    lines += [""] + table("debate", ["## Debate arms", "", "Mean over samples, [min–max] when samples differ."])
    lines += ["", "## Answers changed by the debate", "",
              "| Level | Configuration | Model | Changed by debate | Changed by opposed debate |",
              "| --- | --- | --- | ---: | ---: |"]
    lines += ["| {} | {}{} | {} | {} / {} | {} / {} |".format(
        r["level"].upper(), r["config"], r["suffix"], r["model"].capitalize(), *r["2"], *r["2o"])
        for r in result["changes"]]
    lines += ["", "Failed answers, counted as empty output:", ""]
    lines += ["- {} / {} s{} / {} {}: {}".format(f["level"].upper(), f["arm"], f["sample"], f["project"], f["variant"],
                                                f["reason"]) for f in result["failures"]] or ["- none"]
    return "\n".join(lines) + "\n"
