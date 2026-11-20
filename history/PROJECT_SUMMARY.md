# Project summary: uncertainty-preserving Tai-e–LLM reconciliation

**Complete six-project proposed-method evaluation:** [combined comparison](SIX_PROJECT_PROPOSED_RESULTS.md).
**17 October interpretation correction:** original conservative fusion scores
proxy F1 0.2881 and FDR 82.51%, with 6/6 matches. The newer priority method's
complete output contains 59 locations and scores proxy F1 0.2272 and FDR 87.04%,
also with 6/6 matches. Its eight-location shortlist scores proxy F1 0.9167 and
FDR 11.11%; that subset score must not be presented as complete-output accuracy.
The report now separates these tables. Reporting only the shortlist would be
a valid filtering policy, without requiring equal output counts across methods,
but the existing binary project-recall proxy does not fully penalize lost
locations. Equal-review-budget baseline comparisons have not been run.
Guard checks tie agreement alone on vulnerable revisions. Ten invalid MPXJ
judge dismissals are retained as uncertain; two reviews have valid citations.
Predictions and numerical scores are unchanged. See the report for the metric
definition, filtering interpretation and patched-reader limitation.

**16 October baseline expansion:** [six-project baseline results](SIX_PROJECT_BASELINE_RESULTS.md).
Tai-e, vanilla Qwen/DeepSeek and policy-hinted Qwen/DeepSeek now include MPXJ.
The cumulative vulnerable-revision comparison is complete: Tai-e matches 6/6
(proxy F1 0.2439); hinted Qwen matches 5/6 (F1 0.8333, FDR 16.67%). Patched vanilla
DeepSeek is explicitly unscored after timeout/token exhaustion. The original
five-project fusion and guard-study units remain separate from these totals.

**16 October extension:** [MPXJ real-project guard case study](GUARD_EXPANSION_RESULTS.md).
A sixth subject supplies a real separator-aware guard. A new attributed checker
retains its vulnerable-route detection (1/1) and removes the repaired-route alarm:
paired-route FDR 50% → 0%, F1 0.667 → 1.0. Deterministic and LLM-only controls tie
the combined arm. This is an in-sample, two-revision result; it is separate from
the original five-project fix-location proxy and is not whole-project accuracy.

**15 October extension:** see [Simple improvements: implementation and results](SIMPLE_IMPROVEMENTS_RESULTS.md).
The new agreement/fallback priority view scores proxy F1 0.9000 and proxy FDR
13.33%, with 5/5 project matches, while preserving the entire remaining review
tail. Checked guard contracts add no metric gain on the original five projects, but prevent two
false dismissals in a separate 14-case component evaluation. These are
development results, not verified real-vulnerability accuracy. The report below
preserves the original 14 October fusion study and its comparison arms.

Status: 14 October 2026. This is the current project summary; the other reports
record individual experiments and earlier designs.

## 1. The result in plain language

We have a small experimental analyzer that combines static taint warnings with
independent LLM findings, then asks an LLM to reconcile them using source code.
When the judge cannot decide, the candidate stays in the output.

**The original conservative fusion improved the aggregate fix-location proxy
over normalized Tai-e while preserving matches in all five projects:**

| Retained comparison | Project matches | Macro proxy F1 ↑ | Macro proxy FDR ↓ |
| --- | ---: | ---: | ---: |
| Manual-policy Tai-e | 5/5 | 0.2593 | 84.41% |
| Original fusion: reports + uncertain | 5/5 | **0.3149** | **80.68%** |

F1 improved by **0.0556**, about **21.4% relatively**. FDR decreased by **3.73
percentage points**. This is a real improvement in the frozen evaluation, not
something erased by later unsuccessful experiments. It is **not yet evidence of
improved verified vulnerability accuracy**, and the score did not improve on
every project.

We retain this original method as the promising course-project prototype. The
later evidence-packet variant is a negative ablation, not the current method.
The selection is retrospective on these development projects, not a held-out
confirmation or a production safety recommendation.

## 2. What the retained method actually does

```text
Manual-policy Tai-e warnings ─┐
Saved vanilla Qwen findings ──┼─> union of unique method locations
Saved vanilla DeepSeek ───────┘        + saved source evidence
                                              |
                                      one Qwen judge/version
                                              |
                          report       uncertain       dismiss
                            keep          keep         exclude from
                                                      scored output
```

There are five projects—zip4j, zt-zip, Spark, plexus-archiver and plexus-utils—and
two versions per project. The judge makes at most ten requests, one per version.
It uses Qwen `qwen/qwen3-coder-30b-a3b-instruct`; the independent saved readers are
that Qwen model and `deepseek/deepseek-v4-pro`. The judge is therefore not an
independent oracle relative to both readers.

Tai-e contributes the enclosing methods at both endpoints of its taint flows.
Readers contribute their CWE-22-related reported methods. We merge these into
unique `(project, simple class, method)` locations, collapsing overloads and
duplicates. The judge sees the origins, flow strings, reader explanations and
bounded source windows—not fix labels or version labels.

The judge produces report/dismiss/uncertain. Decisive judgments need a valid
supplied citation in the candidate's method. Invalid or missing reviews fall
back to uncertain. **A valid citation does not establish a correct explanation.**
All original candidates and raw responses remain archived; experimental
exclusion is not destructive deletion or approved production suppression.

Two operating points are evaluated: reports-only, which drops uncertainty, and
the retained conservative mode, which keeps reports plus uncertainty. They must
not be conflated: the latter preserved five-project match coverage here.

### Is automatic taint specification solved?

**No.** We implemented an earlier specification-generation/refinement prototype,
but generated policies were broad/incomplete and produced excessive warnings.
That code is now recoverably archived. The retained fusion uses manually supplied
Tai-e source/sink/transfer policies. It does not claim to eliminate that dependency.

## 3. How to read the numbers correctly

The five vulnerable revisions receive the numeric proxy scores. Both versions
are analyzed, but fixed versions are **not automatically treated as safe**;
their ground-truth labels remain unresolved and they receive output counts only.

For a project, let N be selected unique method locations and K the selected
locations matching production methods in the pinned dataset's fix information:

- Proxy precision = K/N; proxy FDR = 1 − K/N.
- A project is matched if K > 0. Thus 5/5 means five fix-location matches,
  **not 100% verified vulnerability recall**.
- The inherited metric uses binary project recall. Proxy F1 = 2K/(N+K) when
  K > 0, otherwise zero. It is not standard warning-level recall/F1.
- Macro F1 averages all five projects, including zero-output cases. Macro FDR
  averages only nonempty-output projects; its denominator is shown below.

Unmatched methods are **not established false positives**. Fix information is
not an exhaustive vulnerability annotation. Source endpoints, adapter code and
library endpoints may also inflate the normalized candidate denominator.

The original Tai-e pair-level score was **0.4708** (the early 0.4508 aggregate was
an arithmetic error). The new Tai-e **0.2593** uses a different unit—unique
endpoint methods rather than source–sink pairs. Those two numbers must not be
compared as a regression. Every row in the next table uses the same new unit.

## 4. Consolidated results

| Method | Project matches | Macro proxy F1 | Macro proxy FDR | FDR denominator |
| --- | ---: | ---: | ---: | ---: |
| Tai-e | 5/5 | 0.2593 | 84.41% | 5/5 |
| Saved vanilla Qwen | 3/5 | 0.6000 | 40.00% | 5/5 |
| Saved vanilla DeepSeek | 4/5 | 0.7600 | 26.67% | 5/5 |
| Union without judging | 5/5 | 0.2419 | 86.12% | 5/5 |
| Tai-e agreement with either reader | 4/5 | 0.8000 | 0.00% | 4/5 |
| Original judge: reports only | 4/5 | 0.7000 | 16.67% | 4/5 |
| **Original judge: reports + uncertain (retained)** | **5/5** | **0.3149** | **80.68%** | **5/5** |
| Later packet judge: reports only | 2/5 | 0.4000 | 33.33% | 3/5 |
| Later packet judge: reports + uncertain | 4/5 | 0.1849 | 89.49% | 5/5 |

Agreement is the strongest cheap precision-oriented control here, but it emits
nothing for Spark. It therefore does not dominate the retained fusion if
preserving all five project matches matters. Conversely, the retained fusion
does not beat agreement or DeepSeek on F1 alone.

### Where the retained improvement comes from

| Project | Tai-e N/K | Fusion N/K | Tai-e proxy F1 | Fusion proxy F1 |
| --- | ---: | ---: | ---: | ---: |
| zip4j | 7/1 | 3/1 | 0.2500 | 0.5000 |
| zt-zip | 13/1 | 16/2 | 0.1429 | 0.2222 |
| Spark | 3/1 | 4/1 | 0.5000 | 0.4000 |
| plexus-archiver | 7/1 | 6/1 | 0.2500 | 0.2857 |
| plexus-utils | 12/1 | 11/1 | 0.1538 | 0.1667 |

This is not just warning removal: zt-zip gains another fix-overlapping location
from the independent reader. Spark gains a nonmatching retained location and
gets worse. Overall, selected locations change from 42 to 40 and fix-overlapping
locations from 5 to 6. Of the 40 retained vulnerable-version locations, **34 are
uncertain and only six are reports**. The result depends heavily on retaining
uncertainty, not on the judge verifying most candidates.

Across all ten versions, the original judge produced 14 reports, 10 dismissals
and 71 uncertain outcomes: only 24/95 determinate decisions. Some dismissals had
unsupported explanations, so preserved proxy matches do not prove safe removal
of real vulnerabilities. New judge inference cost was **$0.00520009** and runtime
**102.01 seconds**; these exclude reused Tai-e and vanilla-reader costs.

## 5. What the unsuccessful experiments taught us

| Experiment | Observation | Current decision |
| --- | --- | --- |
| Automatic specification pipeline | Broad/incomplete policies; excessive warnings and expensive review | Archive prototype; manual-policy limitation remains |
| Simple sink-group review | Retained all warnings | Historical baseline |
| Guard-focused review | Incorrect safety claims; lost a project match | Do not adopt |
| Deterministic guard veto | Restored warnings, but did not filter better than baseline | Diagnostic negative ablation |
| Pairwise feasibility review | Retained all 139 pairs across ten versions | Do not add this stage |
| Original independent-reader fusion | Improved normalized Tai-e proxy with 5/5 project matches | Retain for study, not safety-certified deployment |
| Candidate-linked evidence packets | Body coverage 34/95 → 42/95, but poorer scores and response-contract failures | Archive negative ablation |

The packet run cost $0.00905737 and took 110.77 seconds. It left 73/95 candidates
uncertain. The prompt's old JSON example plus new-field addendum was a plausible
contributor to schema noncompliance; extra evidence alone cannot be blamed for
the regression. Context, linking and validation changed together.

Spark illustrates the evaluation and reasoning limits. Its fix-matched
`getInputStream` body is identical in the two pinned versions; an important added
guard is in the constructor. The original judge overlooked supplied sink code;
the packet judge saw it but dismissed delegation to a classloader as irrelevant.
Neither establishes real-world vulnerability status. See the
[Spark diagnosis](SPARK_DISAGREEMENT_DIAGNOSIS.md).

## 6. Contribution, limitations and appropriate report claim

The strongest defensible course-project contribution is a **provenance-aware,
uncertainty-preserving reconciliation prototype with controlled ablations**.
It combines independently generated candidates, checks supplied evidence, and
makes the precision/coverage trade-off measurable instead of silently treating
missing evidence as safety.

Combining an LLM with a static analyzer is not a novelty claim by itself. We have
not established literature-level originality, automatic-specification quality,
verified vulnerability F1, generalization, statistical significance, or safe
automatic suppression. A single run on five repeatedly used development projects
cannot establish those claims. The legacy vanilla readers received files selected
using known fix locations, not blind repository inputs; their original requests
are not fully archived. Both versions' verified ground-truth labels remain
unresolved. These limitations must accompany the result.

Suggested report wording:

> We implement an uncertainty-preserving reconciliation prototype combining
> manual-policy static taint analysis with independent LLM findings. On five
> development projects, the retained configuration improves macro fix-location
> proxy F1 from 0.2593 to 0.3149 and reduces proxy FDR from 84.41% to 80.68%, while
> preserving five-project match coverage. Ablations show that additional review
> and context stages do not reliably improve this trade-off. The results remain
> exploratory because ground truth and deployment-specific exploitability are
> unresolved.

## 7. Code cleanup and reproducibility

The active code keeps the fusion runner, a minimal `fusion_support.py`, baseline
runners/scorers, the catalogue builder/plugin and relevant tests. Original Zip4j
setup tools remain because the historical setup guide still uses them. Retired
generation/refinement/audit/suite/filter/packet code, its tests and prompts were
removed from active folders—not permanently erased.

**41 files are recoverable** from the [cleanup archive](archive/README.md), with
per-file SHA-256s in its manifest. The archive also preserves the old fusion
runner, dependencies and README for historical reproduction. Original result
folders, reports, truth cards, manual configurations, adapters, dependencies and
credentials were not removed. Historical reports may name retired commands;
consult the archive rather than running them against the new active tree.

Verification after cleanup:

- **32 active tests passed**, including eight utility/replay tests. The old full
  212-test suite passed before cleanup; tests for retired components are archived.
- All ten original prompts and serialized evidence inputs match exactly.
- Revalidating all ten saved raw responses reproduces decisions/errors/counts.
- All seven metric arms and their per-project results reproduce exactly.
- No active Python module imports a retired module. A ten-case dry-run succeeds.
- **No paid inference or Tai-e rerun was performed during cleanup.**

Run active checks and prepare inputs without inference:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/run_fusion_pilot.py \
  --plan evaluation/results/suite-plans/20261013T080658Z-9iod4p05/plan.json \
  --baseline evaluation/results/cwe22/20261013T023400Z-_h4dwq08
```

Only adding `--execute` requests new paid inference. The saved-case replay test
skips when local artifacts are absent. Local result folders are Git-ignored;
sharing the source repository alone does not share these experimental artifacts.
Cleanup changes code fingerprints, so strict historical pipeline replay requires
restoring the archived code, not disabling its provenance checks.

### Primary evidence

- [Retained fusion run](results/fusion-pilot/20261014T025408Z-447y9ikk/REPORT.md)
  and [per-project metrics](results/fusion-pilot/20261014T025408Z-447y9ikk/metrics.json).
- [Packet ablation](results/fusion-packets/20261014T040537Z-mrt6s6ws/REPORT.md).
- [Fusion design and qualitative checks](FUSION_PILOT.md),
  [packet evaluation](FUSION_EVIDENCE_PACKETS.md), and
  [earlier lightweight experiments](SIMPLE_PIPELINE.md).
- [Automatic-specification history](AUTOMATIC_SPECIFICATION_REPORT.md) and
  [unresolved case cards](ground-truth/README.md).

The next scientifically useful step is independent review of candidate truth
and dismissal correctness, followed by evaluation on held-out cases—not another
uncontrolled expansion of the judge pipeline. That work is not claimed complete.
