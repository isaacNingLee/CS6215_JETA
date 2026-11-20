# Independent LLM + Tai-e reconciliation pilot

## Question and scope

Does reviewing the union of manual-policy Tai-e and saved, independent vanilla
LLM findings improve location prioritization over either input alone?
This is a small development-set experiment, not a claim of a novel published
algorithm or verified vulnerability detection. The automatic taint-specification
component exists, but its earlier broad/incomplete policies did not establish
usable accuracy. **This pilot still depends on manual Tai-e specifications.**

## Frozen design

Use the five projects and both revisions already analyzed. Reuse manual Tai-e
flows and the Qwen/DeepSeek non-hinted reader outputs; do not rerun discovery or
policy generation. Non-hinted means no taint hints, **not blind discovery**:
the legacy readers received files selected using known fix locations. Original
reader prompts/source hashes are not all archived, and some old summaries lack
an explicit version field. The runner records the legacy-directory mapping and
hashes the raw responses it actually consumes.

Normalize every arm to one `(project, simple class, method)` CWE-22 location.
Tai-e contributes unique source and sink endpoint methods; readers contribute
unique reported locations after the existing CWE-22 keyword filter. Duplicate
reports and overloads collapse. Other vulnerability categories are excluded
from every reader control. This changes both the unit and the denominator from
the original tables: **do not compare these F1 numbers directly with the earlier
pair-level 0.4708 or legacy all-category reader scores.**

The unpaid controls are Tai-e, each reader, the three-way union, and
`Tai-e intersect (Qwen union DeepSeek)`. A Qwen judge reviews each union candidate
as report/dismiss/uncertain, using the independent claims, Tai-e flows and saved
source windows. No fix labels, version labels, evaluator match flags or provider
hidden reasoning are supplied. Agreement is not proof; reader silence is not
evidence of safety. This is location triage, not certification that a taint pair
is infeasible. A judge matching one reader's model is not an independent oracle.

Each decisive judgment must cite a real supplied line in the candidate method.
Invalid, duplicated or missing reviews become uncertain. Missing code stays in
the candidate set. Windows are bounded at 5,500 source characters per method,
approximately 55,000 serialized characters per request, with a 60,000-character
admission guard. The ten prepared inputs contain 95 locations; 61 have no
candidate-method body in the selected catalogue evidence. This limitation is
reported rather than fixed through another expensive evidence-expansion stage.

Budget: ten requests, two workers, 5,000 output tokens, 60-second socket timeout,
no retries, $0.25 reported-cost stopping threshold and ten-minute admission
cutoff. These are soft admission guards: an already-started request can finish
after a guard triggers. Reused discovery and static-analysis costs are not
included in the new judge-call cost.

## Evaluation interpretation

Ground-truth labels remain explicitly unresolved, including fixed versions.
The numeric proxy is computed on the five vulnerable revisions only, after
decisions are saved. Let N be selected unique locations, K the locations matching
production fix-method labels. Proxy precision is K/N, proxy FDR is 1-K/N, and
project detection is `K > 0`. The inherited benchmark formula uses **binary
project recall**, not method-level recall: proxy F1 is `2K/(N+K)` when K > 0,
otherwise zero. This is not standard vulnerability-level F1 and does not establish
that unmatched candidates are actual false positives.

Macro F1 includes all five projects, including zero-output projects. Macro FDR
excludes empty outputs and must be shown with its nonempty-project denominator.
Both fusion operating points are reported: reports-only, and conservative
reports-plus-uncertain. Neither is allowed to hide uncertainty or missing
coverage. Fixed revisions receive output counts, not invented TN/FP labels.

## Reproduction and validation

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/run_fusion_pilot.py \
  --plan evaluation/results/suite-plans/20261013T080658Z-9iod4p05/plan.json \
  --baseline evaluation/results/cwe22/20261013T023400Z-_h4dwq08 \
  --execute
```

Omit `--execute` to archive/check inputs without inference. Before this run,
193 tests passed, including six normalization and citation/fallback tests.
Each case archives requests, raw responses, input hashes, provenance and final
decisions. The run archives per-project proxy scores and an aggregate report.

Run: `results/fusion-pilot/20261014T025408Z-447y9ikk`.

## Result: the judge did not beat the unpaid agreement control

All ten API requests returned, with no retries or unknown billing. New inference
cost **$0.00520009**; preparation plus inference/scoring took **102.01 seconds**.
The run is marked `finished_with_review_failures`, not fully successful review:
of 95 expected judgments, only **37** were structurally valid. The model omitted
36 candidate IDs and attempted 22 decisive judgments without a citation in the
candidate's method; these 58 items fell back to uncertain. Thirteen valid reviews
also explicitly abstained. Final totals: **14 report, 10 dismiss, 71 uncertain**.
Determinate coverage is only **24/95 = 25.3%**, and citation validity is not
semantic correctness.

| Arm (same normalized unit) | Project matches | Macro proxy F1 | Macro proxy FDR | FDR denominator |
| --- | ---: | ---: | ---: | ---: |
| Manual-policy Tai-e | 5/5 | 0.2593 | 84.41% | 5/5 |
| Saved vanilla Qwen | 3/5 | 0.6000 | 40.00% | 5/5 |
| Saved vanilla DeepSeek | 4/5 | 0.7600 | 26.67% | 5/5 |
| Union | 5/5 | 0.2419 | 86.12% | 5/5 |
| Tai-e agreement with either reader | 4/5 | 0.8000 | 0.00% | 4/5 |
| Judge: reports only | 4/5 | 0.7000 | 16.67% | 4/5 |
| Judge: reports + uncertain | 5/5 | 0.3149 | 80.68% | 5/5 |

Agreement emits no Spark location. Its zero proxy FDR therefore must not be
presented as perfect accuracy or preservation of Tai-e's five-project coverage.
Reports-only also emits nothing for Spark. Conservative fusion retains Spark's
fix-overlapping candidate as uncertain, not as an established vulnerability.

The judge improves the normalized Tai-e proxy F1 by 0.0556 under conservative
retention but has not established safe removal. Its reports-only F1 is below
saved DeepSeek (0.7600) and unpaid agreement (0.8000). The method-location
projection produces different numbers from the original pair-level benchmark;
it is not a performance regression in the unchanged Tai-e run itself.

Detailed [run report](results/fusion-pilot/20261014T025408Z-447y9ikk/REPORT.md)
contains all ten version counts; [metrics JSON](results/fusion-pilot/20261014T025408Z-447y9ikk/metrics.json)
contains every per-project score. Numeric fields called `reported_pairs` and
`matched_pairs` are inherited from the existing scorer; **in this report they
count unique method locations, not pairs**.

## Qualitative check: citations alone did not make the judge reliable

Inspection of saved request code and final explanations found clear problems:

- Vulnerable zip4j `UnzipEngine.getOutputStream` was dismissed because it
  supposedly creates an output stream without a file write. The supplied code
  deletes an existing file at S429 and constructs `FileOutputStream(file)` at
  S432. The stated reason does not justify discarding this dangerous operation.
- Vulnerable zip4j `Unzip.checkOutputDirectoryStructure` was dismissed as having
  no path-traversal operation, although supplied lines S196–S202 concatenate an
  entry name into a path and call `mkdirs()` on its parent. Its claimed absence
  of filesystem effects is contradicted by the evidence.
- Zip4j `UnzipEngine.checkCRC` was reported as constructing vulnerable filesystem
  paths. Its cited S272/S278 lines instead insert filenames into exception
  messages. Those citations do not support the claimed filesystem operation.
- Spark `getDescription` was dismissed with a claim that it calls
  `StringUtils.cleanPath()`. That call is absent from the supplied method body.
  The body formats a description, but a potentially reasonable outcome does not
  validate the fabricated rationale.

These are evidence-quality checks, not independent complete vulnerability
annotations. Raw decisions and scored results have **not** been manually edited
to improve the reported numbers. No proposed suppression is adopted in the
default pipeline, and fixed-version reports are not converted into FP labels.

## Decision and next bounded experiment

Do not add this free-form judge as the default filter. Keep it as a negative
ablation and keep the original warning set available. The cheapest promising
next design is **agreement-based prioritization**: show shared locations first
and retain Tai-e-only/disputed locations in an explicit unresolved queue. This
preserves access to all static candidates without calling agreement proof of
safety. It is a useful baseline, not novelty by itself. A course-project
contribution would need a tested improvement beyond it, such as a narrowly
specified evidence check that resolves disagreement without losing fix-location
coverage. That improvement has not been implemented or established by this run.

### Follow-up: Spark diagnosis (no new inference)

[SPARK_DISAGREEMENT_DIAGNOSIS.md](SPARK_DISAGREEMENT_DIAGNOSIS.md) separates entry
scope mismatch, missing constructor context, false missing-code claims by the
judge, and a weak fix-location label. In particular, the fix-matched
`getInputStream` body is identical in the two pinned versions; the relevant new
guard is in its constructor. This does not establish a true-positive rescue for
Spark. Existing scores and unresolved labels are unchanged. The recommended
next component is candidate-linked, bounded evidence packaging, not another
unconstrained judge or a Spark-specific scoring exception.

### Offline evidence-packet implementation

[FUSION_EVIDENCE_PACKETS.md](FUSION_EVIDENCE_PACKETS.md) records the completed
candidate-linking/source-recovery component. All ten inputs were prepared without
inference; candidate-body availability increased from 34/95 to 42/95, with
unchanged candidates, flows and old method windows. Spark now includes its
constructor/guard context. The full 212-test suite passed. No new F1/FDR result
or suppression decision has been produced.

### Subsequent packet evaluation: no improvement

The approved ten-call packet run completed for $0.00905737 in 110.77 seconds.
Reports-only proxy F1 fell from 0.7000 to 0.4000 (2/5 project matches), while
conservative F1 fell from 0.3149 to 0.1849 (4/5). Controls are identical. The run
had both response-contract failures and unsupported semantic judgments; no
default suppression was adopted. See the completed evaluation and failure
accounting in [FUSION_EVIDENCE_PACKETS.md](FUSION_EVIDENCE_PACKETS.md).
