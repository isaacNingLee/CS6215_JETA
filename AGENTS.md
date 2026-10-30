# Instructions for coding agents

This repository is the artifact of a course report (JETA, CWE-22 method localisation on six Java
projects). README.md is the full guide; this file holds what an agent needs in order to act safely.

## Reproduce

1. `python3 -m cwe22 setup`: downloads Tai-e, Maven and the pinned dataset into `$CS6215_WORK`
   (default `~/cs6215-work`). Needs git and network.
2. `pip install matplotlib`, then `python3 -m cwe22 paper`: regenerates every table, figure and
   number of the report into `results/paper/` from the saved runs. Needs no API key.
3. `python3 -m unittest discover -s tests -t .`: all tests must pass. `tests/test_paper.py` checks the
   report's headline numbers against the saved runs.
4. To re-score from saved outputs (needs JDK 17), follow README §1 Level B in order.

Before any step that could send model requests (`llm`, `relax`, `pipeline`, `llmdfa` without
`--score`), run it with `--dry-run` first. It should report zero requests for the saved runs
(`261021b`, `261020h`, `261021c`, `261022l`).

## Rules

- **Do not spend money without the user's approval.** Any command without `--dry-run` or `--score`
  may call OpenRouter (needs `OPENROUTER_API_KEY` in `.env`). Never print or commit `.env`.
- **Never delete or edit files under `results/`.** They are the only copy of paid model answers. A
  saved request is reused and never resent; if a new request would differ from a saved one, the run
  stops with "Saved request differs". That error means a setting changed (often a token budget in
  `cwe22/config.py`), not that the saved file is wrong.
- **Keep one fixed method.** Do not add filters, thresholds or stages tuned on these six projects. A
  change suggested by a failure is post-hoc; label it as such and ask before adopting it.
- Predictions are written before labels are loaded (`agreement.evaluate`, `pipeline.evaluate`); keep
  that order.
- Saved runs are named `YYMMDD` + letter. Downstream steps take the upstream run names as flags
  (`--baseline`, `--relax-run`, `--readers`, `--agreement-run`); the defaults are the report's runs.

## Map

- `cwe22/agreement.py` + `cwe22/guards.py`: JETA stages 1-2. `cwe22/pipeline.py`: stages 3-4.
- `cwe22/taie.py`, `cwe22/llm.py`, `cwe22/llmdfa*.py`: baselines. `cwe22/relax.py`: hint relaxation.
- `cwe22/paper.py`, `cwe22/cost.py`, `cwe22/figures.py`: report outputs.
- `data/`: subjects, Tai-e policies and adapters, prompts. `results/<run>/REPORT.md`: per-run detail.
