# JETA: Jev-Enhanced Taint Analysis for Java Path Traversal Reports

Artifact for the CS6215 (NUS, Fall 2026) project report *JETA: Jev-Enhanced Taint Analysis for Java
Path Traversal Reports* (Isaac Ning Lee). It contains the implementation of JETA, the baselines it is
compared with, every input file, every saved model answer and analysis output, and the scripts that
turn them into the report's tables and figures.

**The problem.** We study method-level localisation of Java path traversal (CWE-22). Given a project
revision, report the methods that need to change to fix the vulnerability. Report them on the
vulnerable revision, and stop reporting them once the code is patched.

**The approaches compared**, all on six CWE-Bench-Java projects in vulnerable and fixed revisions:

| Approach | Kind | Where |
| --- | --- | --- |
| Tai-e 0.5.4 taint analysis, manual policy + entry adapter per project | symbolic baseline | [cwe22/taie.py](cwe22/taie.py), [data/taie/](data/taie), [data/adapters/](data/adapters) |
| Vanilla / hinted LLM readers (Qwen3-Coder-30B-A3B, DeepSeek-V4-Pro) | LLM baselines | [cwe22/llm.py](cwe22/llm.py), [data/prompts/](data/prompts) |
| LLMDFA (NeurIPS 2024), pinned upstream engine adapted to these projects | published neuro-symbolic baseline | [cwe22/llmdfa*.py](cwe22/llmdfa.py), [data/llmdfa.lock.json](data/llmdfa.lock.json) |
| **JETA**: guard filter → reader agreement → Jev judgement → blind checklist | **our method** | [cwe22/agreement.py](cwe22/agreement.py), [cwe22/guards.py](cwe22/guards.py), [cwe22/pipeline.py](cwe22/pipeline.py) |
| Hint relaxation: replace Tai-e's manual configuration step by step (H1, H2a, H2b, E) | sensitivity study | [cwe22/relax.py](cwe22/relax.py), [cwe22/spec.py](cwe22/spec.py), [cwe22/entry.py](cwe22/entry.py) |

Headline result (report Table 1). Under the original manual Tai-e configuration, JETA detects a reference
fix method in all six vulnerable projects in each of three samples. Its macro fix-location FDR is
5.6% against Tai-e's 85.5%, and its macro F1 is 96.3% against 77.8% for the strongest baseline
(hinted DeepSeek).

---

## Contents

1. [Reproduce the report](#1-reproduce-the-report) (three levels, from 1 minute to the full experiment)
2. [Where each table and figure comes from](#2-where-each-table-and-figure-comes-from)
3. [Requirements](#3-requirements)
4. [Repository layout](#4-repository-layout)
5. [The method (JETA)](#5-the-method-jeta)
6. [Baselines](#6-baselines)
7. [Hint relaxation](#7-hint-relaxation)
8. [Metrics](#8-metrics)
9. [Settings, sampling and budget](#9-settings-sampling-and-budget)
10. [Known deviations and caveats](#10-known-deviations-and-caveats)
11. [Third-party tools and data](#11-third-party-tools-and-data)

---

## 1. Reproduce the report

All commands run from the repository root. Each step can be resumed: finished cells are skipped,
and a saved model answer is never requested again. Re-running a step therefore never pays twice.

### Level A: regenerate every table, figure and number (about 1 minute, no API key)

```sh
python3 -m cwe22 setup        # downloads Tai-e 0.5.4, Maven 3.9.8 and CWE-Bench-Java @ pinned commit
pip install matplotlib        # only needed for the figures
python3 -m cwe22 paper        # -> results/paper/
python3 -m unittest discover -s tests -t .   # includes tests/test_paper.py, which pins the headline numbers
```

`setup` is needed even here, because the fix-method labels come from CWE-Bench-Java's `fix_info.csv`.
`results/paper/` then holds Tables 1–3 as LaTeX, Figures 5, 6 and 8 as PDF, `numbers.json` (every
number behind the tables and figures, plus the case-study numbers quoted in the text) and
`SUMMARY.md` (the same numbers, readable). Tables 1–3 are token-identical to the LaTeX in the
report.

### Level B: re-score every experiment from the saved outputs (no API key)

This needs JDK 17. The first command checks out and builds the twelve subject revisions with Maven,
then rebuilds the Tai-e method catalogues that the guard check reads. Every model answer it needs is
already saved, so it sends no request.

```sh
python3 -m cwe22 relax --run 261020h --dry-run  # build subjects + catalogues into $CS6215_WORK; reuses every saved answer
python3 -m cwe22 score --run 261021b            # Tai-e, vanilla and hinted readers  -> results/261021b/REPORT.md
python3 -m cwe22 relax --run 261020h --score    # hint relaxation                    -> results/261020h/REPORT.md
python3 -m cwe22 agree --run 261021g            # JETA stages 1-2                    -> results/261021g/REPORT.md
python3 -m cwe22 pipeline --run 261021c --score # JETA stages 3-4                    -> results/261021c/REPORT.md
python3 -m cwe22 llmdfa --run 261022l --score   # LLMDFA baseline                    -> results/261022l/llmdfa/REPORT.md
python3 -m cwe22 paper
```

`pipeline --run 261021c --dry-run` lists any model call that is still missing. For the saved runs
it reports `0 still incomplete`.

### Level C: run everything again with new model calls (OpenRouter key)

The saved runs cost about US$12 in total (see [§9](#9-settings-sampling-and-budget)); LLMDFA alone
ran for about 4 hours.

```sh
cp .env.example .env                            # add OPENROUTER_API_KEY
python3 -m cwe22 taie  --run B                  # Tai-e with the manual configuration (12 analyses)
python3 -m cwe22 llm   --run B                  # vanilla + hinted readers: 2 models x 2 modes x 12 cells x 3 samples
python3 -m cwe22 score --run B
python3 -m cwe22 relax --run H --baseline B     # H1, H2a, H2b, E: policies, source selection, drivers, Tai-e, hinted readers
python3 -m cwe22 agree --run G --relax-run H --readers B
python3 -m cwe22 pipeline --run C --agreement-run G --relax-run H --baseline B
python3 -m cwe22 llmdfa --setup                 # pinned LLMDFA clone, virtualenv and tree-sitter grammar
python3 -m cwe22 llmdfa --run L                 # ~4 h; run detached (nohup) so a closed terminal does not stop it
python3 -m cwe22 paper --baseline B --relax-run H --pipeline-run C --llmdfa-run L
```

Add `--dry-run` to `llm`, `relax`, `pipeline` or `llmdfa` to build prompts and count requests
without sending any. Use `--projects`, `--models`, `--variants` and `--samples` to run a subset.
Hosted models are not deterministic even at temperature 0, so a new run gives different samples,
and its numbers will differ from the report's.

**Token budgets** ([cwe22/config.py](cwe22/config.py)) are the ones the saved runs used.
`MAX_TOKENS` (8,000 for both models) applies to the readers, source selection, entry drivers and
hinted answers. `LONG_MAX_TOKENS` (DeepSeek 16,000) applies to the checklist writer and LLMDFA.
Changing either makes saved requests differ from new ones, and the resumable steps then stop with
"Saved request differs".

---

## 2. Where each table and figure comes from

| Report item | Produced by | Saved inputs |
| --- | --- | --- |
| Table 1 (main comparison) | `paper` → `results/paper/table1_main.tex` | `261021b` (Tai-e, readers), `261022l` (LLMDFA), `261021c` (JETA) |
| Table 2 (stage ablation) | `paper` → `table2_ablation.tex` | `261021g` → `261021c` |
| Table 3 (cost) | `paper` → `table3_cost.tex` ([cwe22/cost.py](cwe22/cost.py)) | saved usage and timing of every call |
| Figure 1 (motivating cases) | `numbers.json` → `cases` | `261021b`, `261021g` |
| Figure 4 (MPXJ checklist scores) | `numbers.json` → `cases.figure4_mpxj_checklist_sample1` | `261021c/answers`, `261021c/checklists` |
| Figure 5 (hint relaxation) | `paper` → `fig5_hint_relaxation.pdf` | `261020h`, `261021c` |
| Figure 6 (pair-correct) | `paper` → `fig6_pair_correct.pdf` | `261020h`, `261021c` |
| Figure 7 (MPXJ success / failure) | `numbers.json` → `cases` | `261020h/taie/e-qwen-h2b`, `261021g`, `261021c` |
| Figure 8 (JETA cost breakdown) | `paper` → `fig8_cost_breakdown.pdf` | as Table 3 |
| Figure 2 (LLM vs. Jev interfaces) | Generated by `jev_interface.py`, maintained with the report's figure sources outside this repository | Fixed MPXJ, sample 1: `p1_c4` in [the saved checklist response](results/261021c/answers/checklist-s1/13299f8acd81ec5e.json), with P(yes) = 0.95 |
| Figure 3 (method overview) | drawn by hand; not data | – |

Figure 2 shows an abbreviated code excerpt and canonicalization question. The LLM reply is an
example; Jev's score is recorded from evaluating the full fixed `InputStreamHelper.processZipStream`
method. The probability of no (0.05) is computed as 1 − P(yes).

The saved runs are named by date and letter (`261021b` = 2026-10-21, run b):

| Run | Contents |
| --- | --- |
| [results/261021b](results/261021b) | Tai-e with the manual configuration; vanilla and hinted readers (3 samples each) |
| [results/261020h](results/261020h) | Hint relaxation: policies, catalogue candidates, source selections, LLM-written entry drivers, Tai-e flows and hinted answers at H1–E |
| [results/261021g](results/261021g) | JETA stages 1–2 (agreement guard) at every level: guard contracts and predictions |
| [results/261021c](results/261021c) | JETA stages 3–4: method contexts, hinted answers to the other model's prompt, Jev judgements, blind checklists and Jev checklist answers |
| [results/261022l](results/261022l) | LLMDFA: 2 models × 3 samples × 12 cases, each with every request and response |
| [results/paper](results/paper) | Tables, figures and numbers of the report |

Each run directory has a `REPORT.md` (human-readable, per-project detail) and a `metrics.json`. Each
`REPORT.md` averages FDR over nonempty outputs only. The report and `results/paper` count an empty
output as 100% FDR, so FDR values can differ between the two; F1 and detections do not.

---

## 3. Requirements

| Need | Version | Used for |
| --- | --- | --- |
| macOS or Linux | – | developed on macOS (Apple silicon) |
| Python | ≥ 3.9 | the `cwe22` package uses the standard library only |
| matplotlib | ≥ 3.5 | figures only ([requirements.txt](requirements.txt)) |
| git | any | dataset and subject checkouts |
| JDK | 17 (Temurin 17.0.20 used) | Maven builds, Tai-e, the Java helpers in [cwe22/java](cwe22/java) |
| Tai-e | 0.5.4, SHA-256-pinned | downloaded by `setup` |
| Maven | 3.9.8, SHA-512-checked | downloaded by `setup` |
| CWE-Bench-Java | commit `afe0ebd` | cloned by `setup`; subjects checked out by `taie` |
| LLMDFA | commit `fca6387`, tree-sitter-java `490d878` | cloned by `llmdfa --setup` into its own virtualenv (tree-sitter 0.20.2, openai 1.51.0, tiktoken, z3-solver 4.13.0.0) |
| OpenRouter API key | – | Level C only. Models: `qwen/qwen3-coder-30b-a3b-instruct`, `deepseek/deepseek-v4-pro`, `typesafe/jev-1.13` (decisions endpoint) |

Large, re-downloadable material lives outside the repository in `$CS6215_WORK` (default
`~/cs6215-work`, about 1.3 GB). It holds the tools, the dataset clone, the subject checkouts and builds,
and raw Tai-e logs and catalogues (`raw/<run>/`). Secrets live only in `.env` (git-ignored; template
[.env.example](.env.example)).

---

## 4. Repository layout

```text
cwe22/                    the experiment, as one Python package (python3 -m cwe22 <command>)
  __main__.py             command line: setup, taie, llm, score, relax, agree, pipeline, llmdfa, paper
  config.py               paths, pinned versions, model IDs, token budgets, .env loading
  workspace.py            setup: downloads Tai-e, Maven and the pinned dataset
  subjects.py             subject manifest and CWE-Bench-Java fix labels
  taie.py                 checkout -> Maven build -> entry adapter -> Tai-e taint analysis -> flows
  llm.py                  OpenRouter client, vanilla/hinted prompts, CWE-22 finding extraction
  scoring.py              method locations from flows; FDR / F1 / detection
  report.py               metrics.json and REPORT.md of the baseline run
  relax.py                hint relaxation (levels Original, H1, H2a, H2b, E)
  spec.py                   shared CWE-22 kit, catalogue candidate sources, LLM source selection
  catalogue.py              Tai-e method catalogue (java/MethodCataloguePlugin.java)
  entry.py                  LLM-written entry drivers (pick classes, write, compile, repair)
  agreement.py            JETA stages 1-2: guard filtering and reader agreement
  guards.py                 checked containment-guard contracts (java/SourceFacts.java, java/CanonicalGuardCheck.java)
  pipeline.py             JETA stages 3-4: Jev judgement and blind checklist (java/MethodContext.java)
  llmdfa.py               LLMDFA baseline: setup, cases, scoring
  llmdfa_runtime.py         runs inside LLMDFA's virtualenv; adapts the pinned engine (DEVIATIONS list)
  llmdfa_specs.py           CWE-22 source/sink prompt specs from the manual policy
  paper.py                Tables 1-3, numbers.json and SUMMARY.md
  cost.py                   Table 3 / Figure 8: calls, tokens, charges and time
  figures.py                Figures 5, 6 and 8 (matplotlib)
  java/                   Java helpers compiled against the Tai-e jar
data/
  subjects.json           dataset commit; per project: CVE slug, vulnerable/fixed commits, entry adapter
  taie/<project>/         manual Tai-e taint policy per project (sources, sinks, transfers)
  taie/common/            shared string-transfer rules
  taie/kit/               shared CWE-22 kit used from H1 on (no project-specific rule)
  adapters/               manual Tai-e entry adapters (one small main() per project)
  prompts/                vanilla.txt, hinted.txt and hints.json (per-project prose hints, sink files)
  prompts/relax/          source selection, entry-driver (pick, driver, prune) and relaxed hinted prompts
  prompts/checklist/blind.txt   the checklist writer's prompt (CWE-22 description only)
  llmdfa.lock.json        pinned LLMDFA and tree-sitter-java commits
results/                  saved runs (see §2); every model request and response is kept
history/                  superseded earlier designs and their reports (report §4.3); see history/README.md
tests/                    unit tests; Java tests skip without JDK 17 + Tai-e; test_paper.py pins the report's numbers
AGENTS.md, CLAUDE.md      instructions for coding agents (Codex, Claude Code)
```

---

## 5. The method (JETA)

JETA refines Tai-e's CWE-22 reports into method-level candidates. For each project revision, Tai-e
configuration and sample *k*, it runs four stages. Each stage only removes methods, so the output
satisfies O ⊆ J ⊆ C ⊆ T. Predictions are written to `predictions.json` before any fix label is loaded.

| Stage | What it does | Code / prompt | Model calls |
| --- | --- | --- | --- |
| 1. Guard filtering | Removes Tai-e flows whose `FileOutputStream(File)` sink is protected by a proven containment guard. Two checkers: a `java.nio.file.Path` template (`!p.startsWith(r)` on normalized absolute paths) and a javac-attributed `getCanonicalPath().startsWith(root + File.separator)` check. A bare String-prefix check is refuted with a counterexample (`/tmp/outside` starts with `/tmp/out`). Any other code shape keeps its flows. | [guards.py](cwe22/guards.py), [java/SourceFacts.java](cwe22/java/SourceFacts.java), [java/CanonicalGuardCheck.java](cwe22/java/CanonicalGuardCheck.java) | none |
| 2. Reader agreement | T = endpoint methods of the remaining flows. Keeps the methods in T that either vanilla reader (sample *k*) also reports, or all of T when they share none. Reader-only methods go to an unscored review tail. | [agreement.py](cwe22/agreement.py) `select` | the vanilla readers (shared with the baseline) |
| 3. Jev judgement | Jev reads both hinted readers' answers (sample *k*) and each candidate's code: the method, its class's fields and constructors, and the same-class methods it calls. It answers one true/false question per method ([`JUDGE_QUESTION`](cwe22/pipeline.py)) and keeps the method at p ≥ 0.5. A failed call keeps everything. | [pipeline.py](cwe22/pipeline.py), [java/MethodContext.java](cwe22/java/MethodContext.java) | 1 Jev call per tier |
| 4. Blind checklist | DeepSeek writes one checklist per sample from the CWE-22 description alone ([blind.txt](data/prompts/checklist/blind.txt); a test checks that it names no subject). A checklist is a list of safe patterns, each a conjunction of yes/no conditions. Jev answers every condition for each remaining method's code, and the method is dropped when all conditions of some pattern reach p ≥ 0.5. | [pipeline.py](cwe22/pipeline.py) `dropped` | 3 checklists; 1 Jev call per method |

At H2b and E each model's hinted prompt shows its own configuration. Stage 3 needs both models'
answers to the same prompt, so the other model first answers the owner's prompt
(`results/261021c/hinted/`, 120 calls).

**What is ours and what is not.** Tai-e, LLMDFA, CWE-Bench-Java and the hosted models (Qwen,
DeepSeek, Jev) are third-party. The following were designed and written for this project: the guard
checkers, the agreement rule, the judge question and its use of reader answers, the blind-checklist
protocol, the per-project Tai-e policies and entry adapters, the reader prompts, the
hint-relaxation ladder (shared kit, candidate-source rule, LLM source selection, LLM entry drivers),
the LLMDFA adaptation layer and all scoring.

**Earlier designs.** The designs tried before JETA (LLM-generated taint policies, generative LLM
filters and judges, multi-agent debate) and the reports behind the report's §4.3 are in
[history/](history/README.md). They are superseded and are not needed to reproduce Tables 1–3.

---

## 6. Baselines

**Tai-e** ([taie.py](cwe22/taie.py)). Tai-e 0.5.4 with `pta=cs:ci;only-app:false;taint-config:<policy>`
and the call graph from pointer analysis. Each project has a manual policy ([data/taie/](data/taie):
sources, sinks and transfers, with no sanitizers) and a manual entry adapter
([data/adapters/](data/adapters)), compiled against the subject's build. A reported flow contributes
the methods enclosing its source and sink. The only source edit is zt-zip's `pom.xml`, which raises
its Java level from 1.5/1.6 to 1.7 because JDK 17 rejects the older levels.

**Vanilla and hinted readers** ([llm.py](cwe22/llm.py)). Each reader sees the production file that
CWE-Bench-Java's fix metadata names, so it gets oracle knowledge of the fix file. The vanilla prompt
asks for CWE findings as JSON ([vanilla.txt](data/prompts/vanilla.txt)). The hinted prompt adds a
prose description of the manual Tai-e policy and entry point ([hinted.txt](data/prompts/hinted.txt),
[hints.json](data/prompts/hints.json)), plus a sink-containing helper file for zip4j and zt-zip. A
finding counts when its CWE or explanation mentions path traversal.

**LLMDFA** ([llmdfa.py](cwe22/llmdfa.py)). The upstream engine is pinned in
[data/llmdfa.lock.json](data/llmdfa.lock.json) and runs in its own virtualenv.
[llmdfa_runtime.py](cwe22/llmdfa_runtime.py) adapts the engine's boundaries to real Java
repositories and OpenRouter without editing its source; every change is listed in its `DEVIATIONS`
and in each case's `plan.json`. LLMDFA gets the Original level's inputs: the manual source/sink
policy as CWE-22 prompt specs ([llmdfa_specs.py](cwe22/llmdfa_specs.py), checked against the Tai-e
policy and the hints), the Tai-e entry point, and the fix file, sink files, entry class and adapter
with their superclass sources. Few-shot CoT is on; parser synthesis and solver synthesis are off,
since the solver executes model-written Python. Each case is capped at 1,200 requests and US$3. Both
endpoints of every validated trace are scored.

---

## 7. Hint relaxation

Each level removes one more human input from Tai-e's configuration. From H1 on, the hinted reader is
shown exactly the entry program and policy files Tai-e receives
([prompts/relax/hinted.txt](data/prompts/relax/hinted.txt)), plus the fix file.

| Level | Entry program | Tai-e policy |
| --- | --- | --- |
| Original | manual adapter | manual per-project policy |
| H1 | manual adapter | shared CWE-22 kit ([data/taie/kit](data/taie/kit)) + string transfers |
| H2a | manual adapter | kit + every catalogue candidate source: called methods returning `String`/`File`/`Path`, excluding constructors, value-transforming utilities and methods taking a path-like argument |
| H2b | manual adapter | kit + the candidates the model did not reject. The model sees only candidates that reach a kit sink at H2a, with up to three call-site windows, and must cite a call site to reject one ([select.txt](data/prompts/relax/select.txt)) |
| E | entry driver written by the model: it picks ≤ 5 public classes, writes `AutoEntry.main`, and gets up to 3 compiler-error repair rounds ([pick](data/prompts/relax/pick.txt), [driver](data/prompts/relax/driver.txt), [prune](data/prompts/relax/prune.txt)) | candidate extraction and selection repeated under that driver |

H2b and E are run per model: Qwen and DeepSeek each select their own sources and write their own
drivers. These form the "Qwen track" and "DeepSeek track" of Figures 5 and 6.

---

## 8. Metrics

The unit is a `(simple class, method)` location. Overloads merge, and a constructor takes its class
name. For project *p* and sample *k*, let N be the number of reported locations and K the number that
are production fix methods in `fix_info.csv` ([scoring.py](cwe22/scoring.py)):

- **Detected**: K > 0. **FDR** = 1 − K/N, or 100% for an empty output (report convention).
  **F1** = 2K/(N+K), which uses binary project recall as in IRIS.
- **Flag.** (fixed revision): a reference fix method is still reported after the patch.
  **Pair-correct (P-C)**: detected on the vulnerable revision and not flagged on the fixed one, in
  the same sample.
- Macro FDR and F1 average the six projects within a sample. Det., Flag. and P-C count projects.
  Means and sample SDs are over the three aligned samples: JETA's sample *k* uses sample *k* of
  every model input. Tai-e is deterministic and runs once.

These are fix-location proxies, not verified vulnerability labels.

---

## 9. Settings, sampling and budget

- All chat requests go through OpenRouter at temperature 0 with `reasoning: {effort: low}`. Each
  sample is one request with a fixed `max_tokens`: 8,000 for both models, except 16,000 for the
  DeepSeek checklist writer and LLMDFA's DeepSeek requests. Only transport errors are retried; a truncated or
  malformed answer counts as an empty output and is never re-asked (the one exception is in §10).
- Jev 1.13 is called through OpenRouter's `/api/alpha/decisions` endpoint with typed `noul`
  (true/false) questions. JETA reads P(true) and applies the 0.5 threshold.
- Three samples per model, prompt, project and revision.
- **Budget.** The study was scoped to six projects and three samples to fit an OpenRouter budget of
  SGD 40. The saved runs record US$12.3 in reported charges: readers $0.92 (`261021b`), relaxation
  $3.73 (`261020h`), JETA stages 3–4 $1.51 (`261021c`) and LLMDFA $6.13 (`261022l`). Table 3
  breaks down the charges at the Original level, where JETA costs $0.980 over 36 runs, mostly for
  reader answers.

---

## 10. Known deviations and caveats

- **DeepSeek re-asks.** In `261021b`, 8 vanilla DeepSeek answers were cut off at 8,000 tokens and
  requested once more at 16,000. Six then completed; fixed MPXJ samples 2 and 3 hit the limit again.
  Every other saved reader request used 8,000 tokens.
- **Truncated answers in JETA.** Five DeepSeek answers to Qwen's H2b prompt were cut off. The Jev
  judge sees them as "(no answer)".
- **Entry drivers.** DeepSeek's E drivers compiled for only 2 of 6 projects (spark, plexus-utils).
  The other four answers were cut off. Qwen's compiled for all six.
- **LLMDFA.** 28 Qwen answers were cut off at the token limit and are used as returned, as upstream
  does. 1,072 DeepSeek null answers that finished normally with reasoning present count as empty
  answers; their reasoning concludes that there is no source or sink.
- **Oracle input.** The direct readers read the benchmark-selected fix file, so their detection does
  not measure repository-wide search.
- **Labels.** Reference fix methods are proxies. Unmatched reports were not adjudicated, and an
  unflagged fixed revision does not prove the code safe.

---

## 11. Third-party tools and data

- Tai-e: <https://github.com/pascal-lab/Tai-e> (v0.5.4 release jar)
- CWE-Bench-Java (IRIS, ICLR 2025): <https://github.com/iris-sast/cwe-bench-java> at commit `afe0ebd0adc237abb46255f9cd479b1d71819136`
- LLMDFA (NeurIPS 2024): <https://github.com/chengpeng-wang/LLMDFA> at commit `fca638790cc0a5cc49afd9d6bc31d1f04efc4af5`
- OpenRouter: <https://openrouter.ai>. Jev (TypeSafe): <https://docs.typesafe.ai/concepts/system-one>
- The six subjects (zip4j, zt-zip, Spark, plexus-archiver, plexus-utils, MPXJ) are fetched from
  their GitHub repositories at the commits in [data/subjects.json](data/subjects.json).
