# Candidate-linked evidence packets: offline implementation

Implemented 14 October 2026 after the [Spark diagnosis](SPARK_DISAGREEMENT_DIAGNOSIS.md).
The offline stage below made no inference calls or label/suppression changes.
The subsequently approved ten-call evaluation is recorded at the end.

## What changed

`scripts/prepare_fusion_evidence.py` prepares an opt-in evidence ablation from the
frozen fusion pilot requests. It leaves the old runner, all original candidate
objects, Tai-e flow strings and original method windows unchanged. It has no API
execution mode and does not read credentials or fix labels.

Each candidate now has explicit own-body IDs, supporting-context IDs, a computed
body-availability status, scope and evidence gaps. A local JDK parser
(`scripts/SourceMethodIndex.java`) retrieves exact declared method bodies from
checksum-verified archived Java files, including reader-named methods excluded
from the reachable catalogue. It only parses source: no subject compilation,
annotation processing, execution or dependency downloads. Named nested classes
are indexed; local/anonymous class bodies are not guessed.

Selection rules are shared across all five projects:

- Recover missing candidate bodies before adding supporting context. Ambiguous
  simple class names are marked unresolved; original overload merging is explicit.
- For methods syntactically referring to fields declared in their class, attach
  up to four same-class constructors. These are possible initialization contexts,
  not proven reachable constructor choices or resolved field-write dependencies.
- Attach up to six directly referenced, uniquely name/arity-matched source
  helpers from candidate methods and selected constructors. No recursive walk.
  Unresolved instance receiver types and ambiguous overloads are not guessed.
- Retain the 5,500-character method-body cap and 55,000-character serialized
  evidence cap. Record omitted/partial evidence. Never drop a candidate to fit.

This uses ASTs solely to establish source boundaries and syntactic references;
it does not add a CFG, DFG, type-resolved call graph or safety proof. Missing
library code and deployment assumptions remain unresolved. Parameter/local-name
shadowing can over-select constructor context; that does not authorize a verdict.

The new packet-specific validator requires structured `reason_code` and
`flow_assessment` fields. A `missing_code` claim contradicting supplied body IDs
is invalid and falls back to uncertain. Decisive reviews need a valid citation
in the candidate's own body, not just a constructor/helper or another candidate.
Missing, duplicated and invalid reviews remain uncertain. This checks evidence
consistency, not whether natural-language reasoning or exploitability is true.

## Offline result

Final preparation run:
`results/fusion-evidence/20261014T035516Z-81_jxnwz`.

| Project | Vulnerable bodies before → after | Fixed bodies before → after |
| --- | ---: | ---: |
| zip4j | 7/7 → 7/7 | 7/7 → 7/7 |
| zt-zip | 3/16 → 6/16 | 4/17 → 7/17 |
| spark | 3/5 → 4/5 | 2/5 → 3/5 |
| plexus-archiver | 2/7 → 2/7 | 2/7 → 2/7 |
| plexus-utils | 2/12 → 2/12 | 2/12 → 2/12 |
| Total | 17/47 → 21/47 | 17/48 → 21/48 |

Overall body availability: **34/95 (35.8%) → 42/95 (44.2%)**. Eight recovered
bodies are outside the adapter catalogue, not newly proven reachable findings.
Two existing zip4j candidate windows remain partial and count as available, not
complete. **53/95** candidates still have no body. Do not confuse these numbers
with determinate-review coverage, which has not been remeasured.

All ten inputs fit the cap; the largest is **46,506 characters**. Spark's
`getInputStream` packet explicitly links its existing body and now includes
constructors and `cleanPath`; the fixed packet also includes
`doesNotContainFileColon` and `Assert.state`. The recovered `createRelative`
body is marked outside the adapter catalogue. These additions do not resolve
Spark's real deployment/resource boundary or change its truth label.

Validation: **212 tests passed**, including 19 new evidence tests. Additional
checks on all ten real inputs confirmed unchanged candidates/flows/old windows,
unique method IDs, valid candidate-body links, and size caps. The actual fixed
Spark packet passed guard/normalizer inclusion checks and rejected a synthetic
false `missing_code` judgment. Source parser tests cover misleading braces in
comments/strings, nested classes, overloads and same-line method declarations.

An earlier local preparation run (`20261014T035420Z-plpv8s6k`) is retained as an
intermediate artifact; use the final run above, which includes offset-based
method IDs to distinguish same-line declarations. Both runs were offline.

## Reproduce and next decision

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/prepare_fusion_evidence.py \
  --pilot evaluation/results/fusion-pilot/20261014T025408Z-447y9ikk \
  --plan evaluation/results/suite-plans/20261013T080658Z-9iod4p05/plan.json
```

Use `--java-home` to override the local JDK 17 path. The run archives prepared
requests, input hashes and coverage counts. The prompt addendum separates
source-to-lookup flow from unauthorized-access claims and requires the new
structured fields. The old paid runner is intentionally untouched; a subsequent
evaluation must use the new packet validator, not the old signature-only one.

**Offline cost: $0.** Offline preparation alone produced no new F1/FDR result.
This change combines explicit linking, extra bounded context and stricter
validation; measured changes concern that combined component, not the isolated
effect of AST extraction.

## Approved ten-call evaluation: worse results, do not adopt

Run: [20261014T040537Z-mrt6s6ws](results/fusion-packets/20261014T040537Z-mrt6s6ws/REPORT.md).
All ten calls returned without retries, with known reported billing of
**$0.00905737**, in **110.77 seconds** including validation/scoring. The run is
`finished_with_review_failures`, not a fully valid analysis.

The runner (`scripts/run_fusion_packets.py`) verifies archived input hashes,
unchanged model/inference settings, the frozen prompt addendum, all ten case IDs,
unchanged candidates/flows/old method windows, and the evidence cap before any
inference. It applies the new packet-specific validator. All five unpaid control
arms exactly match their previous per-project scores. The full 212-test suite
passed, and all seven arms' score arithmetic was independently checked after
execution. No prompt, schema, validation threshold or label was changed mid-run
or after seeing the results.

| Configuration | Project matches | Macro proxy F1 | Macro proxy FDR | Nonempty FDR denominator |
| --- | ---: | ---: | ---: | ---: |
| Tai-e, normalized method locations | 5/5 | 0.2593 | 84.41% | 5/5 |
| Vanilla Qwen | 3/5 | 0.6000 | 40.00% | 5/5 |
| Vanilla DeepSeek | 4/5 | 0.7600 | 26.67% | 5/5 |
| Union | 5/5 | 0.2419 | 86.12% | 5/5 |
| Tai-e agreement with either reader | 4/5 | 0.8000 | 0.00% | 4/5 |
| Previous judge: reports only | 4/5 | 0.7000 | 16.67% | 4/5 |
| Packet judge: reports only | 2/5 | 0.4000 | 33.33% | 3/5 |
| Previous judge: reports + uncertain | 5/5 | 0.3149 | 80.68% | 5/5 |
| Packet judge: reports + uncertain | 4/5 | 0.1849 | 89.49% | 5/5 |

These are the unchanged fix-method-location proxies, not verified vulnerability
accuracy. FDR averages have different nonempty denominators; empty outputs still
count as zero in the five-project F1 average. Fixed-version results are counts,
not FP/TN labels. All original manual-policy and preselected-reader-file scope
limitations remain in force.

### Failure accounting

Across 95 expected candidate reviews, the model returned 60 rows:

- 35 candidate IDs were omitted and became uncertain.
- 15 returned rows omitted both new fields (`reason_code`, `flow_assessment`)
  and failed validation: all seven vulnerable zip4j rows and four rows from each
  zt-zip version.
- 10 fixed plexus-utils rows paired decisive decisions with unresolved-evidence
  reason codes and failed validation.
- 35 rows passed structural validation, including 13 explicit uncertain reviews.

Final totals: **10 report, 12 dismiss, 73 uncertain**. Determinate coverage is
**22/95 = 23.2%**, versus 24/95 = 25.3% previously. Thus improved available source
did not improve determinate review coverage in this run.

The prompt retained the old JSON example and added the new required fields in
prose. That is a prompt-contract weakness and a plausible contributor to the
omitted fields, not evidence that the packet's source code is wrong or that AST
context intrinsically hurts accuracy. This run cannot separate that issue from
context/linking effects and model variability. No lenient post-hoc rescoring is
substituted for the frozen validator.

### Spark and semantic reliability

With the method body and constructor/helper context now supplied and explicitly
linked, the vulnerable Spark response passed structural validation but:

- Reported `createRelative` conditionally ("if not properly sanitized") while
  setting `flow_assessment` to unknown; it did not establish the missing security
  boundary identified in the diagnosis.
- Reported `getDescription` for concatenating strings, citing S214, which appends
  a path to a description rather than opening a resource.
- Dismissed `getInputStream` because it delegates to the classloader and does not
  manipulate the path itself, citing its declaration. Delegation is not evidence
  that an untrusted resource lookup cannot cross a security boundary.

That dismissal removes Spark's fix-overlapping location even in the conservative
arm. It does not prove a real vulnerability false negative because Spark's truth
label and deployment assumptions remain unresolved. It does establish that the
new evidence did not rescue the frozen detection proxy and that structurally
valid decisions can still have unsupported reasoning.

### Decision

Do **not** adopt this judge for automatic suppression. Preserve the packets as a
useful evidence artifact and the run as a negative ablation, but stop adding
context/review stages on the assumption that they will improve F1. Agreement
remains the strongest unpaid priority-queue baseline on these development data;
keep disagreements available rather than declaring them safe. No new paid run
or default pipeline change is authorized by this result.

Reproduce the frozen comparison (performs paid inference only with `--execute`):

```sh
python3 scripts/run_fusion_packets.py \
  --evidence evaluation/results/fusion-evidence/20261014T035516Z-81_jxnwz \
  --execute
```

Maximum ten calls, two workers, no retries, 60-second socket timeout, $0.25
reported-cost admission threshold and ten-minute admission cutoff. In-flight
requests may finish after a threshold triggers. These new-call costs exclude
the reused static/reader runs. All artifacts and old scores remain preserved.
