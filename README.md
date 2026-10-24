# CS6215

CWE-22 (path traversal) baselines on six CWE-Bench-Java projects:

- **Tai-e** 0.5.4 taint analysis with a manual source/sink/transfer policy and entry adapter per project
- **Vanilla LLM**: the model reads the production fix file and reports any vulnerabilities
- **Hinted LLM**: the model also gets Tai-e's source/sink policy and confirms or rejects that flow
- **Proposed pipeline**: Tai-e's agreement guard, then Jev judging the hinted answers, then a blind
  CWE-22 checklist answered by Jev ([Proposed pipeline](#proposed-pipeline))

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
  relax.py        hint-relaxation experiment (levels Hinted-E, Tai-e + hinted LLM)
  spec.py         relaxed policies: kit, candidate sources, LLM source selection
  catalogue.py    Tai-e method catalogue (java/MethodCataloguePlugin.java)
  entry.py        LLM-written entry drivers
  agreement.py    pipeline stage 1: agreement guard on every level, both revisions
  guards.py       checked guard contracts (java/SourceFacts.java, java/CanonicalGuardCheck.java)
  pipeline.py     the proposed pipeline: agreement guard -> Jev judge -> blind checklist
                  (java/MethodContext.java extracts the code Jev reads)
  llmdfa.py       LLMDFA (NeurIPS 2024) baseline: setup, cases, scoring
  llmdfa_runtime.py  runs inside LLMDFA's venv; patches the pinned engine's boundaries (from CS6215_proj)
  llmdfa_specs.py    CWE-22 source/sink prompt specs from the manual policy
  paper.py        LaTeX tables for the paper (python3 -m cwe22 paper)
data/
  subjects.json   pinned dataset commit and per-project revisions
  taie/           Tai-e taint policies (common string transfers + per project)
  adapters/       Tai-e entry points (one small main() per project)
  taie/kit/       shared CWE-22 kit (no project class; frozen in CS6215_proj)
  prompts/        frozen vanilla/hinted prompts and per-project hints
  prompts/relax/  selection, entry-driver and configuration-hinted prompts
  prompts/checklist/blind.txt  the checklist writer's prompt (CWE-22's description only)
  llmdfa.lock.json  pinned LLMDFA and tree-sitter-java commits
results/<run>/    run outputs: metrics.json, REPORT.md and the saved inputs
  261021b         baselines (Tai-e, vanilla, hinted): 3 samples, max_tokens 8,000, except 8
                  DeepSeek vanilla answers cut off at 8,000 and asked again at 16,000
                  (6 then completed; fixed MPXJ s2 and s3 hit 16,000 too)
  261020h         hint relaxation: 3 samples, max_tokens 8,000 for both models
  261021g         pipeline stage 1: agreement guard (Tai-e from 261020h, readers from 261021b)
  261021c         the pipeline (stages 2 and 3) at every level
  261022l         LLMDFA baseline: 2 models x 3 samples x 12 cases (llmdfa/; $6.13)
  paper/          paper_tables.tex (appendix) and paper_tables_main.tex
tests/            unit tests (Java tests need JDK 17 and the Tai-e jar)
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
python3 -m cwe22 taie  --run <run>             # 12 Tai-e analyses (builds checkouts first)
python3 -m cwe22 llm   --run <run> --dry-run   # build prompts only
python3 -m cwe22 llm   --run <run>             # 3 samples x 48 cells = 144 OpenRouter requests
python3 -m cwe22 score --run <run>             # writes results/<run>/{metrics.json,REPORT.md}
python3 -m cwe22 relax --run <run>             # hint relaxation (see below)
python3 -m cwe22 agree --run <run>             # pipeline stage 1
python3 -m cwe22 pipeline --run <run>          # pipeline stages 2 and 3
python3 -m cwe22 llmdfa --setup                # pinned LLMDFA + venv + grammar in $CS6215_WORK/tools
python3 -m cwe22 llmdfa --run <run>            # LLMDFA baseline (results/<run>/llmdfa/)
python3 -m cwe22 paper                         # results/paper/*.tex
```

Every step can be resumed. Cells that already have results are skipped, so a rerun never pays again for a completed LLM answer. Use `--projects`, `--variants`, `--models` and `--modes` to run a subset.

## Metrics

The unit is one `(simple class, method)` location on the **vulnerable** revision. Overloads merge, and constructors use the class name.

- Tai-e contributes the enclosing methods of both endpoints of every flow.
- An LLM contributes the methods of findings whose CWE or explanation mentions path traversal.
  Names take `fix_info.csv`'s form, the innermost simple class (`llm.simple_location`):
  `("ZipUtil", "Unpacker.process")` and `("ZipUtil$Unpacker", "process")` are both
  `("Unpacker", "process")`.

Let N be the number of locations an arm reports for a project, and K the number of those that are production fix methods in `fix_info.csv`. Then:

- **Detected**: K > 0
- **FDR**: 1 − K/N
- **F1**: 2K/(N+K), using binary project recall as in IRIS §3.6

Macro FDR averages only projects with nonempty output. Detection and macro F1 count all projects.
The paper tables (`python3 -m cwe22 paper`) instead count a failed or empty output as 100% FDR,
so their FDR can differ from a `REPORT.md`.

Hosted LLMs are not deterministic even at temperature 0, so each LLM cell is sampled 3 times (`--samples`). Each sample is scored on its own, and the report gives the mean and [min–max]. Tai-e is deterministic and runs once.

Each sample is one request with a fixed `max_tokens` budget per model (`config.MAX_TOKENS`) and is never retried. The saved runs used 8,000 for both models, the original CS6215_proj budget (see `261021b` for the exception). The current setting gives DeepSeek 16,000 because its reasoning tokens count against the budget. A saved request is never resent with different parameters, so set DeepSeek back to 8,000 before resuming a saved run; scoring makes no requests and works either way. Each report states the budget it was run with. A failed answer counts as empty output: undetected, F1 0, FDR undefined. Failures include a request error, a response truncated at the budget, empty content or malformed JSON. `REPORT.md` lists every failed cell.

`score` reports fixed-revision outputs as counts only. `agree` and `pipeline` also score them; see [Proposed pipeline](#proposed-pipeline). All scores are fix-location proxies, not verified vulnerability labels.

Caveat: the LLM arms read the file that the dataset says contains the fix. That gives them oracle-selected input. Tai-e instead analyses the whole program reachable from its entry adapter.

## Hint relaxation

`python3 -m cwe22 relax --run <run>` (add `--dry-run` for the local steps only, or
`--score` to rescore a finished run such as `261020h`)
ports the relaxed-hint experiment of CS6215_proj. Each level removes one more human
input from Tai-e's configuration:

| Level | Entry program | Tai-e policy |
| --- | --- | --- |
| Hinted | manual adapter | manual per-project policy (Tai-e configuration `manual`) |
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
- **Hinted LLM:** the first level *is* the hinted baseline above. Its answers are read
  from the baseline run (`--baseline`, default `261021b`), not made again. From H1 on,
  the model sees exactly what Tai-e receives: the entry program and every policy file,
  rendered by one template ([data/prompts/relax/hinted.txt](data/prompts/relax/hinted.txt)),
  plus the production fix file. The manual `sink_files` are part of the manual hint, so
  relaxed levels don't show them.
- **Tai-e** is scored on all flows and with an application scope (both endpoint
  methods in project or entry code), since the kit also matches inside the JDK.
- Every LLM step uses the model's fixed `max_tokens` (`config.MAX_TOKENS`) and is never resent. A failed
  hinted answer, failed Tai-e run or missing driver counts as empty output
  (undetected). A failed selection request keeps its whole batch (conservative).

Catalogues, drivers' class files and raw Tai-e output go to `$CS6215_WORK/raw/<run>/`.

## Proposed pipeline

Three stages run on each Tai-e configuration, project, revision and sample k. Each stage
after the first only removes locations, and every rule was fixed before it was scored.

1. **Agreement guard** (`python3 -m cwe22 agree --run 261021g`, from CS6215_proj; no API call).
   - *Guard:* Tai-e flows into a `FileOutputStream(File)` sink that a checked guard contract
     protects are set aside ([cwe22/guards.py](cwe22/guards.py)): a `java.nio.file.Path`
     containment template, and an attributed `getCanonicalPath().startsWith(root +
     File.separator)` check. A bare String-prefix check is refuted (`/tmp/outside` starts
     with `/tmp/out`); any other shape keeps its flows.
   - *Agreement:* the Tai-e endpoint methods of the remaining flows that at least one
     vanilla reader (Qwen, DeepSeek; sample k of each, from `261021b`) also reports, or
     every Tai-e location when they share none.
2. **Jev judge** (`python3 -m cwe22 pipeline --run 261021c`). Jev (`typesafe/jev-1.13`,
   TypeSafe's decision model on OpenRouter's `/api/alpha/decisions` endpoint) reads both
   hinted LLMs' answers (sample k) to the configuration's hinted prompt and the code of each
   location, and answers one yes/no question per location (`pipeline.JUDGE_QUESTION`). The
   location is kept when p ≥ 0.5. At H2b and E each model's hinted prompt shows its own
   configuration, so the other model first answers the owner's prompt with its saved hinted
   settings (120 calls; 5 DeepSeek answers to Qwen's H2b prompt were cut off at 8,000 tokens
   and appear as "(no answer)").
3. **Blind checklist.** DeepSeek writes one CWE-22 checklist per sample from CWE-22's
   description alone ([data/prompts/checklist/blind.txt](data/prompts/checklist/blind.txt);
   no subject, code, fix or result is shown, and a test checks the prompt): *safe patterns*,
   each a list of yes/no conditions. Jev answers checklist k for each remaining location's
   code; a location is dropped when some pattern has every condition at p ≥ 0.5.

Jev reads the method, its class's fields and constructors and the same-class methods it
calls ([cwe22/java/MethodContext.java](cwe22/java/MethodContext.java), parse only). A location
outside the project's production source (JDK, anonymous classes) has no code: the judge sees
that, and the checklist keeps it.

Every stage is scored on both revisions: the metrics above on the vulnerable revision, and
on the fixed revision **Flagged** (the patched fix method is still reported, a false alarm)
and **Pair-correct** (reported on the vulnerable revision and not on the fixed one).
Predictions are written before labels are loaded.

Hinted level, all flows, means ± SD over 3 runs (paper convention: an empty output counts as
100% FDR):

| Stage | FDR | F1 | Det. | Flag. | P-C |
| --- | --- | --- | --- | --- | --- |
| Agreement guard | 27.4 ±13.7 | 79.5 ±11.5 | 6.0 | 6.0 | 0.0 |
| + Jev (hinted answers) | 5.6 ±9.6 | 96.3 ±6.4 | 6.0 | 6.0 | 0.0 |
| + checklist (Jev) | 5.6 ±9.6 | 96.3 ±6.4 | 6.0 | 4.7 ±0.6 | 1.3 ±0.6 |

- **The stages do different jobs.** The judge removes false locations on vulnerable code; the
  checklist removes fixed-revision flags (fixed MPXJ in 3 of 3 runs, fixed zip4j in 1 of 3)
  and never drops a vulnerable fix location at this level.
- **Under relaxation** (`results/paper/`) the pattern holds at H1–H2b: the judge lowers FDR
  by 11–23 points at a cost of up to 0.7 detected projects, and after the checklist
  pair-correct is 1.0–2.0 (0 for the guard alone). At E the judge costs one detected project
  with Qwen's driver (4.7 → 3.7), and DeepSeek's drivers compiled for only two projects.
- **The guard proves one sink.** On these six projects that is fixed MPXJ's
  `processZipStream`; the zip4j, zt-zip, plexus-archiver and plexus-utils fixes are bare
  String-prefix checks, and Spark's fix guards no file write.
- **Fixed zt-zip, Spark, plexus-archiver and plexus-utils stay flagged** at every stage.

Caveats, as for the whole experiment: the LLM inputs include the oracle-selected fix file;
at the Hinted level they also include per-project prose hints and sink files; the canonical
checker was written after inspecting MPXJ, and the agreement rule was designed on these same
six projects in CS6215_proj (where one saved reader sample gave F1 0.92; fresh samples give
0.80). Nothing has been evaluated on held-out projects.

Guard contracts are cached in `results/<run>/guards/`; method contexts in
`results/<run>/context/`. Every call is saved once and never resent.

## LLMDFA baseline (published work)

`python3 -m cwe22 llmdfa --run 261022l` runs LLMDFA (Wang et al., NeurIPS 2024, "LLMDFA: Analyzing
Dataflow in Code with Large Language Models"): the upstream engine pinned in
[data/llmdfa.lock.json](data/llmdfa.lock.json), cloned with its own virtualenv by `--setup`.
CS6215_proj's wrapper ([cwe22/llmdfa_runtime.py](cwe22/llmdfa_runtime.py)) patches the engine's
boundaries for real repositories, never its source; every change is in its `DEVIATIONS` list and in
each `plan.json`.

- **Inputs, as at the Original hint level.** The manual per-project source/sink policy, rendered as
  CWE-22 prompt specs ([cwe22/llmdfa_specs.py](cwe22/llmdfa_specs.py); checked against
  `data/taie/<project>/policy.yml` and `data/prompts/hints.json`), and the Tai-e entry point. It
  parses the fix file, the hinted sink files, the entry class and the Tai-e adapter, with their
  superclass closure.
- **Settings:** syn_parser off, few-shot CoT on, syn_solver off (it executes model-written Python).
  Both models via OpenRouter at their current budgets (Qwen 8,000, DeepSeek 16,000 tokens), low
  reasoning; at most 1,200 requests and $3 per case.
- **Unit:** both endpoints of every validated trace, scored like every other arm. A failed case
  reports nothing; all 72 cases completed.
- **Deviations added here (2026-10-22):** OpenRouter transport. An answer cut off at the token limit
  is used as returned, as upstream does (Qwen loops on the source prompt; 28 such answers). A null
  answer from a reasoning model that finished normally with its reasoning present is its empty
  answer (DeepSeek, 1,072; each one's reasoning concludes there is no source or sink).

Means ± SD over 3 runs, paper convention (empty output = 100% FDR):

| Arm | FDR | F1 | Det. | Flag. | P-C |
| --- | --- | --- | --- | --- | --- |
| LLMDFA Qwen | 64.4 ±5.4 | 42.1 ±6.9 | 3.3 ±0.6 | 3.0 | 0.3 ±0.6 |
| LLMDFA DeepSeek | 84.3 ±15.3 | 19.4 ±18.2 | 1.7 ±1.5 | 1.7 ±0.6 | 0.7 ±1.2 |
| Hinted Qwen / DeepSeek (same inputs, one prompt) | 27.8 / 30.6 | 72.2 / 77.8 | 4.3 / 5.7 | 5.7 / 4.0 | 0.0 / 1.7 |
| Proposed pipeline (Original hint) | 5.6 ±9.6 | 96.3 ±6.4 | 6.0 | 4.7 ±0.6 | 1.3 ±0.6 |

- **LLMDFA detects fewer projects than one hinted prompt.** Qwen finds zt-zip, plexus-utils and MPXJ
  (and plexus-archiver in one run); it never finds zip4j or Spark. DeepSeek's validator rejects most
  flows: it reports nothing on plexus-archiver and Spark, and misses zip4j's fix method.
- **Its low flagged count is mostly reporting little,** not telling fixed code apart: pair-correct
  stays under 1.
