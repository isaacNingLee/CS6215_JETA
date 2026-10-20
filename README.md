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
  relax.py        hint-relaxation experiment (levels H0-E, Tai-e + hinted LLM)
  spec.py         relaxed policies: kit, candidate sources, LLM source selection
  catalogue.py    Tai-e method catalogue (java/MethodCataloguePlugin.java)
  entry.py        LLM-written entry drivers
data/
  subjects.json   pinned dataset commit and per-project revisions
  taie/           Tai-e taint policies (common string transfers + per project)
  adapters/       Tai-e entry points (one small main() per project)
  taie/kit/       shared CWE-22 kit (no project class; frozen in CS6215_proj)
  prompts/        frozen vanilla/hinted prompts and per-project hints
  prompts/relax/  selection, entry-driver and configuration-hinted prompts
results/<run>/    run outputs: taie/, llm/, metrics.json, REPORT.md
  261020b         main run: 3 samples, max_tokens 8,000
  261020          earlier single sample at max_tokens 16,000 (score with --samples 1)
  261020h         hint relaxation, max_tokens 8,000 for both models
  261020i         hint relaxation, DeepSeek at 16,000 (Qwen parts copied from 261020h)
tests/            offline unit tests
```

Large, re-downloadable material is kept **outside OneDrive** in `$CS6215_WORK`
(default `~/cs6215-work`): tools, the dataset clone, project checkouts, Maven
output and raw Tai-e logs (`raw/<run>/<project>-<variant>/`).

## Setup

Requirements: macOS or Linux, Python ≥ 3.9, git, JDK 17 (Temurin).

`data/` (subjects, Tai-e policies and kit, entry adapters, prompts) and `results/`
are not in git. Download them separately and place them at the repository root
before running anything; the commands below fail with a clear message without
`data/`.

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

Each sample is one request with a fixed `max_tokens` budget per model (`config.MAX_TOKENS`) and is never retried. Run `261020b` used 8,000 for both models, the original CS6215_proj budget; the current setting gives DeepSeek 16,000 because its reasoning tokens count against the budget. Each report states the budget it was run with. A failed answer counts as empty output: undetected, F1 0, FDR undefined. Failures include a request error, a response truncated at the budget, empty content or malformed JSON. `REPORT.md` lists every failed cell.

Fixed-revision outputs are reported as counts only, not as false positives. All scores are fix-location proxies, not verified vulnerability labels.

Caveat: the LLM arms read the file that the dataset says contains the fix. That gives them oracle-selected input. Tai-e instead analyses the whole program reachable from its entry adapter.

## Hint relaxation

`python3 -m cwe22 relax --run 261020i` (add `--dry-run` for the local steps only)
ports the relaxed-hint experiment of CS6215_proj. Each level removes one more human
input from Tai-e's configuration:

| Level | Entry program | Tai-e policy |
| --- | --- | --- |
| H0 | manual adapter | manual per-project policy |
| H1 | manual adapter | shared CWE-22 kit ([data/taie/kit](data/taie/kit)) |
| H2a | manual adapter | kit + every catalogue candidate source |
| H2b | manual adapter | kit + candidates the model did not reject |
| E | driver written by the model | kit + candidates the model did not reject |

- **Candidates** are called methods returning `String`/`File`/`Path` that do not
  transform a path-like argument (the rule frozen in CS6215_proj). The model sees
  only candidates that reach a kit sink in H2a, with up to three call-site windows,
  and must cite a call site to reject one; anything not validly rejected is kept.
- **H2b and E are per model:** Qwen and DeepSeek each select their own sources and
  write their own drivers, and each is hinted with its own configuration.
- **Hinted LLM, fair across levels:** the model sees exactly what Tai-e receives
  (the entry program and every policy file, rendered by one template,
  [data/prompts/relax/hinted.txt](data/prompts/relax/hinted.txt)), plus the
  production fix file. The manual `sink_files` are part of the manual hint, so no
  level shows them; H0 is therefore not the prose-hinted baseline above.
- **Tai-e** is scored on all flows and with an application scope (both endpoint
  methods in project or entry code), since the kit also matches inside the JDK.
- Every LLM step uses the model's fixed `max_tokens` (Qwen 8,000, DeepSeek 16,000) and is never resent. A failed
  hinted answer, failed Tai-e run or missing driver counts as empty output
  (undetected). A failed selection request keeps its whole batch (conservative).

Catalogues, drivers' class files and raw Tai-e output go to `$CS6215_WORK/raw/<run>/`.
