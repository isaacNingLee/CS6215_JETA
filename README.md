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
  relax.py        hint-relaxation experiment (levels Hinted-E, Tai-e + hinted LLM)
  spec.py         relaxed policies: kit, candidate sources, LLM source selection
  catalogue.py    Tai-e method catalogue (java/MethodCataloguePlugin.java)
  entry.py        LLM-written entry drivers
  agreement.py    agreement guard (proposed method) on every level, both revisions
  guards.py       checked guard contracts (java/SourceFacts.java, java/CanonicalGuardCheck.java)
  debate.py       multiagent debate (Du et al.) between hinted Qwen and hinted DeepSeek
  checklist.py    agreement guard + LLM-written CWE-22 checklist answered by Jev
                  (java/MethodContext.java extracts what the judge reads)
data/
  subjects.json   pinned dataset commit and per-project revisions
  taie/           Tai-e taint policies (common string transfers + per project)
  adapters/       Tai-e entry points (one small main() per project)
  taie/kit/       shared CWE-22 kit (no project class; frozen in CS6215_proj)
  prompts/        frozen vanilla/hinted prompts and per-project hints
  prompts/relax/  selection, entry-driver and configuration-hinted prompts
  prompts/debate/ Du et al. update prompt and the opposing agent's prompt
  prompts/checklist/ checklist writer (blind, per-location) and the control's answer prompt
results/<run>/    run outputs: taie/, llm/, metrics.json, REPORT.md
  261020b         baselines: 3 samples, max_tokens 8,000 for both models
  261020h         hint relaxation: 3 samples, max_tokens 8,000 for both models,
                  plus paper_tables*.tex
  261020g         agreement guard: Tai-e from 261020h, readers from 261020b (3 samples)
  261020r         reproduction check: agreement guard with CS6215_proj's saved readers
                  (llm/ holds copies of them; each record names its source file)
  261020d         debate (plain and with an opposing agent), Hinted level only so far (180 calls, $1.98)
  261021c         checklist filter: blind Jev arm at every level, all arms at Hinted and H1
                  (558 calls, $1.22)
tests/            unit tests (guard-checker tests need JDK 17 and the Tai-e jar)
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

Each sample is one request with a fixed `max_tokens` budget per model (`config.MAX_TOKENS`) and is never retried. Both saved runs used 8,000 for both models, the original CS6215_proj budget. The current setting gives DeepSeek 16,000 because its reasoning tokens count against the budget. A saved request is never resent with different parameters, so set DeepSeek back to 8,000 before resuming either saved run; scoring makes no requests and works either way. Each report states the budget it was run with. A failed answer counts as empty output: undetected, F1 0, FDR undefined. Failures include a request error, a response truncated at the budget, empty content or malformed JSON. `REPORT.md` lists every failed cell.

`score` reports fixed-revision outputs as counts only. `agree` also scores them; see [Agreement guard](#agreement-guard-proposed-method). All scores are fix-location proxies, not verified vulnerability labels.

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
  from the baseline run (`--baseline`, default `261020b`), not made again. From H1 on,
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

## Agreement guard (proposed method)

`python3 -m cwe22 agree --run 261020g` ports the method of CS6215_proj that scored
proxy F1 0.92 and FDR 11% there ("agreement/fallback + checked guards"). It makes no
API call. It reuses the Tai-e flows of a relaxation run (`--relax-run`, default
`261020h`) and the vanilla readers of a baseline run (`--readers`, default `261020b`).
For each Tai-e configuration, revision and reader sample, it does three things:

1. **Guard:** sets aside Tai-e flows into a `FileOutputStream(File)` sink that a checked
   guard contract protects. The two restricted checkers come from CS6215_proj; see
   [cwe22/guards.py](cwe22/guards.py).
   - A `java.nio.file.Path` containment template.
   - An attributed `getCanonicalPath().startsWith(root + File.separator)` check.

   A bare String-prefix check is refuted (`/tmp/outside` starts with `/tmp/out`), and
   any other shape is unknown and keeps its flows.
2. **Candidates:** the endpoint methods of the remaining flows, plus the CWE-22
   methods named by vanilla Qwen and vanilla DeepSeek. Sample k pairs sample k of both
   readers.
3. **Output:** the locations that Tai-e and at least one reader both report. When there
   are none, the output is every Tai-e location. The other candidates are the review
   tail; they are kept in `predictions.json` but not scored.

It runs at every level (Hinted, H1, H2a, H2b and E, with the H2b/E configurations of each
selector model), on all flows and with application scope. Each arm is also run
without the guard, as an ablation.

Every arm, including the baselines, is scored on both revisions:

- **Vulnerable revision:** the metrics above.
- **Fixed revision:**
  - **Flagged:** the patched fix method is still reported, which is a false alarm.
  - **Pair-correct:** the fix method is reported on the vulnerable revision and not on
    the fixed one.

Predictions are written before labels are loaded.

What the runs show:

- **The guard proves one sink.** On these six projects that is fixed MPXJ's
  `processZipStream`. The zip4j, zt-zip, plexus-archiver and plexus-utils fixes are
  bare String-prefix checks, and Spark's fix guards no file write. With application
  scope, the guard clears fixed MPXJ at Hinted–H2b, which is +1 pair-correct project.
  With all flows it does not: the method is still the source endpoint of false flows
  into a JDK-internal sink.
- **The CS6215_proj score belongs to one reader sample.** Run `261020r` gives the
  agreement rule CS6215_proj's saved readers and reproduces its numbers exactly:
  - Hinted (manual policy): 0.9167 / 11.11%
  - Hinted with application scope: 0.9444 / 8.33%
  - H1: 0.7778 / 10.00%
  - H2b: 0.9444 / 8.33%

  With the three fresh samples of `261020g`, the Hinted level averages F1 0.75 [0.66–0.86] and
  FDR 32% [19–43%]. Extra reader locations, and samples where the readers do not
  agree with Tai-e and so fall back to every Tai-e location, account for the gap.
- **Fixed revisions:** the agreement rule still flags 4–6 of 6 projects at every level.
  The one exception is E with DeepSeek's drivers, which compiled for only two
  projects. The readers see only the fix file and do not tell the fixed code from
  the vulnerable code.

The checkers compile into `$CS6215_WORK/raw/<run>/guards/`. Contracts are cached in
`results/<run>/guards/` and recomputed when `guards.py` or a checker changes. The
canonical checker was written after inspecting MPXJ, so its gain is in-sample.

## Multiagent debate between the hinted LLMs

`python3 -m cwe22 debate --run 261020d` (`--relax-run`, default `261020h`; add `--dry-run` to
count calls) runs multiagent debate (Du et al., 2023) between hinted Qwen and hinted
DeepSeek. It adds nothing to the task beyond the paper's update prompt.

- **Round 1** is the hinted arm of the relaxation run: both models answer the same hinted
  prompt for every level, project, revision and sample.
- **Round 2:** each model continues its own conversation with Du et al.'s update prompt
  ([data/prompts/debate/update.txt](data/prompts/debate/update.txt)), which shows the other
  model's answer, and answers again. Only the answer format ("(X)" in the paper, JSON here)
  is adapted.
- **H2b and E:** each model's hinted prompt shows its own configuration. So for each
  configuration, the other model first answers that same prompt in a new round-1 call, and
  then both debate it.
- **Arms per configuration:** each model's answer before and after the debate, plus the
  consensus, i.e. the locations both models report (majority vote with two agents), before
  and after the debate. Scoring is the same as the agreement guard's, on both revisions.
- **Budget:** every call reuses the saved hinted request's settings, including its 8,000-token
  budget, and is never resent.

Run `261020d` covers the Hinted level only so far. The other levels can be added later with
`--levels h1 h2a h2b e`, and saved calls are never resent. Projects are out of 6; each
value is the mean of the 3 samples:

| Arm | Detected | Macro F1 | Fixed: flagged ↓ | Pair-correct ↑ |
| --- | --- | --- | --- | --- |
| Hinted Qwen (round 1) | 4.3 | 0.72 | 5.7 | 0.0 |
| Hinted DeepSeek (round 1) | 5.7 | 0.78 | 4.0 | 1.7 |
| Consensus, no debate | 4.3 | 0.72 | 3.3 | 1.7 |
| Debated Qwen | 5.7 | 0.81 | 4.0 | 1.7 |
| Debated DeepSeek | 5.3 | 0.80 | 4.0 | 1.3 |
| Debated consensus | 5.3 | 0.80 | 4.0 | 1.3 |

- **Qwen converges on DeepSeek.** After the debate it matches DeepSeek's round-1 detection,
  flags and pair-correct, and its F1 rises from 0.72 to 0.81. It changed 20 of its 36
  answers; DeepSeek changed 9.
- **Debate does not beat DeepSeek alone on fixed code.** Debated DeepSeek and the debated
  consensus reach 1.3 pair-correct, against DeepSeek's 1.7 before the debate. Requiring
  both models without a debate flags the fewest fixed projects (3.3), but it detects less
  (4.3).
- **Answer parsing.** In round 2, Qwen often quotes the other agent's JSON before its own
  answer. `llm.parse_findings` therefore falls back to the last JSON object with a
  `findings` key, but only when the whole-span parse fails, so every earlier report is
  unchanged.

### Opposing agent, and the agreement guard + debate filter

- **Opposing agent.** A DeepSeek opponent (`debate.OPPONENT`) gets the hinted question and
  both round-1 answers. Its generic instruction is in
  [data/prompts/debate/opponent.txt](data/prompts/debate/opponent.txt): argue against the
  findings from the code shown, without inventing code. In the opposed round 2, each
  analyst reads the other analyst's answer and the opponent's argument, through Du et
  al.'s update prompt.
- **Filter.** The agreement guard's output (`--agreement-runs`, default `261020r` and
  `261020g`) keeps a location only if either model still reports it. This rule was fixed
  before scoring. The one-sample `261020r` is paired with every debate sample.

Hinted level, all flows (app scope is the same, except that the guard alone starts at
5.0 flagged and 1.0 pair-correct). Means over 3 samples, out of 6 projects:

| Arm | Detected | F1 | FDR | Fixed: flagged ↓ | Pair-correct ↑ |
| --- | --- | --- | --- | --- | --- |
| Agreement guard (`261020r`) | 6.0 | 0.92 | 11% | 6.0 | 0.0 |
| + hinted filter, no debate | 5.7 | 0.94 | 0% | 6.0 | 0.0 |
| + debate filter | 5.7 | 0.94 | 0% | 4.0 | 1.7 |
| + opposed debate filter | 4.7 | 0.78 | 0% | 3.3 | 2.3 |

- **The plain debate is the better trade-off.** It removes the fixed zip4j and MPXJ flags
  and keeps F1 at 0.94.
- **The opposing agent goes further, at a real cost.** It also clears fixed zt-zip and
  Spark in one sample each. But it loses one sample's detection of zt-zip, plexus-archiver
  and plexus-utils. On plexus-archiver the fixed revision stays flagged anyway.
- **Mostly Qwen moves.** The opponent changed 26 of Qwen's 36 answers (detection 2.7/6
  after the opposed debate). DeepSeek changed 9.
- **Both guard runs end up with the same filtered numbers,** because the hinted filter
  removes the extra reader locations that separate them.

## Checklist filter after the agreement guard (Jev)

`python3 -m cwe22 checklist --run <name> [--levels ...] [--arms ...]` filters the agreement
guard's priority tier (`--agreement-runs`, default `261020r` and `261020g`). An LLM writes a
CWE-22 checklist of *safe patterns*. Each pattern is a list of yes/no conditions, where yes
means the code shows that part of a protection. A judge answers the conditions for each
location.

- **Rule.** A location is dropped when some pattern has every condition answered yes;
  otherwise it is kept. For Jev, a condition is yes at probability >= 0.5. The rule was
  fixed before any call, and the filter only removes locations.
- **What the judge reads.** [cwe22/java/MethodContext.java](cwe22/java/MethodContext.java)
  (parse only) extracts the method (every overload), its class's fields and constructors,
  and the same-class methods it calls, from the revision's checkout. JDK and anonymous-class
  locations have no project code and are kept.
- **Jev** is TypeSafe's decision model `typesafe/jev-1.13`. It is served on OpenRouter's
  `/api/alpha/decisions` endpoint, not chat completions. Each condition is one `noul`
  (yes/no) question, and Jev returns a probability for each.

| Arm | Checklist written by | Answered by |
| --- | --- | --- |
| `blind-jev` | DeepSeek, one per sample, from CWE-22's description alone ([blind.txt](data/prompts/checklist/blind.txt)); no subject, code or result shown | Jev |
| `blind-deepseek` (control) | the same checklists | DeepSeek ([answer.txt](data/prompts/checklist/answer.txt)) |
| `local-jev` | DeepSeek, per location from its code, told not to decide ([local.txt](data/prompts/checklist/local.txt)) | Jev |

Run `261021c`, `261020r` guard, all flows. Means over 3 samples, out of 6 projects
(`results/261021c/REPORT.md` also has the app-scope rows and the `261020g` guard):

| Level | Arm | Detected | F1 | FDR | Fixed: flagged ↓ | Pair-correct ↑ |
| --- | --- | --- | --- | --- | --- | --- |
| Hinted | Agreement guard | 6.0 | 0.92 | 11% | 6.0 | 0.0 |
| Hinted | + debate filter (`261020d`) | 5.7 | 0.94 | 0% | 4.0 | 1.7 |
| Hinted | + blind checklist, Jev | 6.0 | 0.92 | 11% | 4.7 | 1.3 |
| Hinted | + blind checklist, DeepSeek answers | 6.0 | 0.92 | 11% | 5.3 | 0.7 |
| Hinted | + per-location checklist, Jev | 5.3 | 0.86 | 15% | 3.3 | 2.0 |
| H1 | Agreement guard | 5.0 | 0.68 | 33% | 5.0 | 0.0 |
| H1 | + blind checklist, Jev | 5.0 | 0.68 | 33% | 4.0 | 1.0 |
| H1 | + blind checklist, DeepSeek answers | 5.0 | 0.68 | 33% | 4.3 | 0.7 |
| H1 | + per-location checklist, Jev | 4.3 | 0.67 | 33% | 3.0 | 1.3 |

- **Blind checklist + Jev never loses a detection.** At every level it dropped 0 of 345
  vulnerable-revision judgements and 4 of 339 fixed ones: fixed MPXJ in 3 of 3 samples
  and fixed zip4j in 1 of 3. At H2a and both H2b configurations, flagged falls from 6.0
  to 4.7 and pair-correct rises from 0 to 1.3, with detection, F1 and FDR unchanged. At E
  it changes little.
- **Jev answers the same checklist better than DeepSeek.** The control clears fewer fixed
  revisions (pair-correct 0.7 vs 1.3), so the gain is not just the checklist.
- **The per-location checklist is the most aggressive.** It also clears fixed Spark in 3 of
  3 samples, but drops vulnerable Spark in 2 of 3. In 8 cells DeepSeek wrote an empty
  checklist (it saw no way the code could be protected), so nothing was dropped there.
  Five generator answers hit the 16k-token limit, and their locations were kept.
- **None clears fixed zt-zip, plexus-archiver or plexus-utils.** Fixed zt-zip, for one,
  checks a canonical String prefix without a separator, and every blind checklist requires
  the separator.
- **Neither filter dominates.** Against the debate filter, blind+Jev keeps every detection
  but leaves the FDR at 11%; the debate removes Spark's extra locations as well.
  DeepSeek arms at H2a–E were not run (about $3).
