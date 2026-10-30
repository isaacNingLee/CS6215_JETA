"""Model calls, tokens, charges and time under the Original configuration (paper Table 3, Figure 8).

Every number is read from saved records: OpenRouter's reported ``usage`` (dollars and tokens) and
the wall-clock ``seconds`` that each saved call or analysis recorded. No request is sent.

A *run* is one (project, revision, sample): 6 projects x 2 revisions x 3 samples = 36 runs.

* Tai-e analyses each revision once; its total analysis time is spread over the 36 runs.
* Each direct reader answers once per run; LLMDFA runs once per run (one case).
* JETA's calls at the Original level are both vanilla readers (stage 2), both hinted readers
  (stage 3 evidence), the three blind checklists (one per sample, shared by that sample's runs)
  and the Jev calls of its Original-level tiers (stage 3 judgements and stage 4 checklist
  answers). Its time is the recorded time of all these calls plus Tai-e's, spread over the 36 runs.
"""
from . import config, pipeline, relax
from .util import read_json

RUNS = len(config.PROJECTS) * len(config.VARIANTS) * config.SAMPLES
READERS = [("Vanilla", "vanilla"), ("Hinted", "hinted")]


def usage(record):
    """(input tokens, output tokens, dollars) of one saved chat or Jev decision record."""
    u = (record.get("response") or {}).get("usage") or {}
    return (u.get("prompt_tokens", u.get("input_tokens", 0)), u.get("completion_tokens", u.get("output_tokens", 0)),
            u.get("cost") or 0.0)


def tally(records):
    records = list(records)
    tokens_in, tokens_out, dollars = (sum(x) for x in zip(*map(usage, records))) if records else (0, 0, 0.0)
    return dict(calls=len(records), tokens_in=tokens_in, tokens_out=tokens_out, cost=dollars,
                seconds=sum(r.get("seconds", 0) for r in records))


def reader_records(baseline, short, mode):
    return [read_json(p) for p in sorted((config.RESULTS / baseline / "llm" / "{}-{}".format(short, mode)).glob("*.json"))]


def jev_records(pipeline_run, agreement_run, relax_run, baseline):
    """The Jev calls JETA makes at the Original level: one judgement per nonempty tier and one
    checklist answer per judged location with code (calls shared by several tiers count once)."""
    run = pipeline.Run(config.RESULTS / pipeline_run, relax_run, baseline)
    index, n = pipeline.guard_tier(agreement_run)
    codes = pipeline.contexts(run.out, pipeline.wanted(index, {relax.taie_config("hinted", "qwen")}))
    paths = set()
    for level, cfg, _, p, v, k, row in pipeline.tier_cells(index, n, ["hinted"], config.SAMPLES):
        if not row or row["status"] != "predicted" or not row["priority"]:
            continue
        priority = [tuple(x) for x in row["priority"]]
        paths.add(run.judge_path(run.judge_body(run.answers(level, cfg, p, v, k), priority, codes[p, v])))
        judged, _ = run.judged(level, cfg, p, v, k, priority, codes[p, v])
        for location in judged or []:
            code = codes[p, v].get("{}.{}".format(*location))
            if code:
                paths.add(run.checklist_answer_path(code, k))
    return [read_json(p) for p in sorted(paths) if p.is_file()]


def llmdfa_tally(llmdfa_run, short):
    """LLMDFA cases: requests and dollars from each case's ledger, tokens from its saved responses."""
    cases = sorted((config.RESULTS / llmdfa_run / "llmdfa").glob("{}-s*/*/result.json".format(short)))
    if len(cases) != RUNS:
        raise RuntimeError("Expected {} LLMDFA {} cases, found {}".format(RUNS, short, len(cases)))
    tokens_in = tokens_out = 0
    for case in cases:
        for response in case.parent.glob("requests/*/response.json"):
            u = read_json(response).get("usage") or {}
            tokens_in += u.get("prompt_tokens", 0)
            tokens_out += u.get("completion_tokens", 0)
    rows = [read_json(c) for c in cases]
    return dict(calls=sum(r["attempts"] for r in rows), tokens_in=tokens_in, tokens_out=tokens_out,
                cost=sum(r["cost"] for r in rows), seconds=sum(r["seconds"] for r in rows))


def table(baseline="261021b", relax_run="261020h", agreement_run="261021g", pipeline_run="261021c",
          llmdfa_run="261022l"):
    """{"rows": [(approach, tally + per-run figures)], "jeta_parts": [(component, tally)]}."""
    taie_seconds = sum(read_json(p)["seconds"] for p in (config.RESULTS / baseline / "taie").glob("*.json"))
    rows = [("Tai-e", dict(calls=0, tokens_in=None, tokens_out=None, cost=0.0, seconds=taie_seconds))]
    for label, mode in READERS:
        for short, name in (("qwen", "Qwen"), ("deepseek", "DeepSeek")):
            rows.append(("{} {}".format(label, name), tally(reader_records(baseline, short, mode))))
    rows += [("LLMDFA Qwen", llmdfa_tally(llmdfa_run, "qwen")), ("LLMDFA DeepSeek", llmdfa_tally(llmdfa_run, "deepseek"))]

    checklists = [read_json(p) for p in sorted((config.RESULTS / pipeline_run / "checklists").glob("*.json"))]
    both = ("qwen", "deepseek")
    parts = [("Vanilla readers", tally(r for s in both for r in reader_records(baseline, s, "vanilla"))),
             ("Hinted readers", tally(r for s in both for r in reader_records(baseline, s, "hinted"))),
             ("Checklist writer", tally(checklists)),
             ("Jev calls", tally(jev_records(pipeline_run, agreement_run, relax_run, baseline)))]
    jeta = {k: sum(part[k] for _, part in parts) for k in ("calls", "tokens_in", "tokens_out", "cost", "seconds")}
    jeta["seconds"] += taie_seconds
    rows.append(("JETA", jeta))
    for _, row in rows:
        row.update(cost_per_run_cents=100 * row["cost"] / RUNS, seconds_per_run=row["seconds"] / RUNS)
    return dict(runs=RUNS, rows=rows, jeta_parts=parts)
