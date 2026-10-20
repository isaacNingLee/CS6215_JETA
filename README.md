# CS6215

CWE-22 (path traversal) baselines on six CWE-Bench-Java projects:

- **Tai-e** 0.5.4 taint analysis with a manual source/sink/transfer policy and entry adapter per project
- **Vanilla LLM**: the model reads the production fix file and reports any vulnerabilities
- **Hinted LLM**: the model also gets Tai-e's source/sink policy and confirms or rejects that flow

The LLMs are `qwen/qwen3-coder-30b-a3b-instruct` and `deepseek/deepseek-v4-pro`, both via OpenRouter.

Projects: zip4j, zt-zip, Spark, plexus-archiver, plexus-utils, MPXJ. Each has a vulnerable and a fixed revision (see [data/subjects.json](data/subjects.json)).

## Layout

```text
cwe22/            Python package (standard library only)
  config.py       paths, pinned versions, models, .env loading
  workspace.py    downloads Tai-e, Maven and the pinned dataset
  taie.py         checkout -> Maven build -> adapter compile -> Tai-e -> flows
  llm.py          prompts, OpenRouter client, CWE-22 finding extraction
  scoring.py      fix-location proxy metrics
  report.py       metrics.json and REPORT.md for a run
data/
  subjects.json   pinned dataset commit and per-project revisions
  taie/           Tai-e taint policies (common string transfers + per project)
  adapters/       Tai-e entry points (one small main() per project)
  prompts/        frozen vanilla/hinted prompts and per-project hints
results/<run>/    compact, committed results: taie/, llm/, metrics.json, REPORT.md
  261020b         main run: 3 samples, max_tokens 8,000
  261020          earlier single sample at max_tokens 16,000 (score with --samples 1)
tests/            offline unit tests
```

Large, re-downloadable material is kept **outside OneDrive** in `$CS6215_WORK`
(default `~/cs6215-work`): tools, the dataset clone, project checkouts, Maven
output and raw Tai-e logs (`raw/<run>/<project>-<variant>/`).

## Setup

Requirements: macOS or Linux, Python ≥ 3.9, git, JDK 17 (Temurin).

```sh
cp .env.example .env           # then fill in OPENROUTER_API_KEY (and SoCLaaS if needed)
python3 -m cwe22 setup         # Tai-e jar (checksum-pinned), Maven 3.9.8, dataset @ pinned commit
python3 -m unittest discover -s tests -t .
```

`.env` is git-ignored. Never commit keys.

## Running the experiment

```sh
python3 -m cwe22 taie  --run 261020b           # 12 Tai-e analyses (builds checkouts first)
python3 -m cwe22 llm   --run 261020b --dry-run # build prompts only
python3 -m cwe22 llm   --run 261020b           # 3 samples x 48 cells = 144 OpenRouter requests
python3 -m cwe22 score --run 261020b           # writes results/261020b/{metrics.json,REPORT.md}
```

Every step can be resumed. Cells that already have results are skipped, so a rerun never pays again for a completed LLM answer. Use `--projects`, `--variants`, `--models` and `--modes` to run a subset.

## Metrics

The unit is one `(simple class, method)` location on the **vulnerable** revision. Overloads merge, and constructors use the class name.

- Tai-e contributes the enclosing methods of both endpoints of every flow.
- An LLM contributes the methods of findings whose CWE or explanation mentions path traversal.

Let N be the number of locations an arm reports for a project, and K the number of those that are production fix methods in `fix_info.csv`. Then:

- **Detected**: K > 0
- **FDR**: 1 − K/N
- **F1**: 2K/(N+K), using binary project recall as in IRIS §3.6

Macro FDR averages only projects with nonempty output. Detection and macro F1 count all projects.

Hosted LLMs are not deterministic even at temperature 0, so each LLM cell is sampled 3 times (`--samples`). Each sample is scored on its own, and the report gives the mean and [min–max]. Tai-e is deterministic and runs once.

Each sample is one request with a fixed budget of `max_tokens` 8,000, the same as the original CS6215_proj runs, and is never retried. A failed answer counts as empty output: undetected, F1 0, FDR undefined. Failures include a request error, a response truncated at the budget, empty content or malformed JSON. `REPORT.md` lists every failed cell.

Fixed-revision outputs are reported as counts only, not as false positives. All scores are fix-location proxies, not verified vulnerability labels.

Caveat: the LLM arms read the file that the dataset says contains the fix. That gives them oracle-selected input. Tai-e instead analyses the whole program reachable from its entry adapter.
