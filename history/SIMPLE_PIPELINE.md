# Simple baseline: Tai-e warnings plus one LLM filter

14 October 2026. User requested simplification and results before more design work.

Pipeline: **existing manual-policy Tai-e → group warnings by sink → one LLM
review per project/version → retain all except validated dismissals**.

This deliberately removes automatic specification generation/refinement,
independent LLM discovery, iterative context expansion and separate per-warning
judge calls. It is a simple warning-filtering baseline, not a claim of novelty
or fully automatic specification inference. It cannot find flaws Tai-e missed.

Reuse the finished 13 October Tai-e suite (no new JVM analyses). Run at most ten
Qwen requests, two at a time, 60-second network timeout, 2,200 output tokens,
40,000 data characters. Stop new calls after ten minutes, $0.25 reported spending
or unknown billing; an already-started concurrent request can still finish.
No paid retries. The monthly key-usage check before this experiment was
$1.327148801, conservatively below a $2 reservation for all prior work; this
small run remains within the user's existing $5 authorization. Reservation is
not actual experiment spend.

Code selection uses warning endpoints plus direct callees, never known fixes or
version labels. Endpoint method bodies are prioritized; long methods get bounded
windows and omissions are explicit. This is not a sound program slice. The model
must return keep/dismiss/uncertain and line-ID citations. Unknown/invalid/missing
reviews retain the original warning. Citation validity does not prove semantics.

Primary quick metrics: before/after warning counts, dismissal rate, valid review
coverage, determinate review coverage, cost and wall time. Also compute the
already-existing **endpoint fix-method-overlap proxy F1** on vulnerable-version
source/sink pairs, using exactly the baseline scorer and matching unit. The fixed
versions are shown separately as warning-persistence observations, not assumed
safe. Verified vulnerability F1 remains unavailable; unresolved labels unchanged.
Proxy labels are loaded only after inference, never passed to the filter.

```sh
python3 scripts/run_simple_filter.py \
  --plan evaluation/results/suite-plans/20261013T080658Z-9iod4p05/plan.json \
  --baseline evaluation/results/cwe22/20261013T023400Z-_h4dwq08 --execute
```

Omit `--execute` for an unpaid packaging check. Every run has request/response
artifacts, conservative decisions, `metrics.json`, and `REPORT.md` under
`evaluation/results/simple-filter/`. Prior heavy runs are preserved unchanged.

## First result — completed

Run: [`results/simple-filter/20261014T005229Z-6wq3lt6_/REPORT.md`](results/simple-filter/20261014T005229Z-6wq3lt6_/REPORT.md).

**10/10 version requests completed, 18/18 group reviews passed the structural
checks, 38.8 seconds, $0.00451689 reported cost, no unknown billing.** All 18
reviews said keep. Across both versions the original 139 pairs were retained;
dismissal rate and warning reduction were both **0%**. Structural review coverage
is not semantic accuracy. All 168 unit tests passed.

| Project | Vulnerable pairs before → after | Fixed pairs before → after | Baseline proxy F1 | Simple-filter proxy F1 |
| --- | ---: | ---: | ---: | ---: |
| zip4j | 9 → 9 | 10 → 10 | 0.2000 | 0.2000 |
| zt-zip | 24 → 24 | 24 → 24 | 0.1538 | 0.1538 |
| spark | 2 → 2 | 2 → 2 | 0.6667 | 0.6667 |
| plexus-archiver | 12 → 12 | 12 → 12 | 0.6667 | 0.6667 |
| plexus-utils | 22 → 22 | 22 → 22 | 0.6667 | 0.6667 |
| Macro average | — | — | **0.4708** | **0.4708** |

The earlier consolidated table's Tai-e average of 0.4508 was an arithmetic error:
the listed project scores average to 0.4708. Proxy matching detected at least one
fix-overlapping pair in 5/5 vulnerable projects, unchanged after filtering. Macro
proxy FDR is 66.11%, unchanged. None of these are verified TP/FP or vulnerability
F1; approved unresolved truth labels are untouched.

**Conclusion:** this simple configuration is inexpensive and operationally
complete, but the LLM adds no filtering benefit in this sample. Its explanations
mostly repeat source-to-sink risk and assert that guards are inadequate; those
assertions have not been independently validated. No automatic-specification or
novelty claim is made. Keep this as the minimal measured baseline before deciding
on any further change; do not infer that all fixed versions are vulnerable.

## Component 2: guard-focused second review

The next incremental experiment keeps the original manual-policy Tai-e warnings,
model, code selection and proxy scorer unchanged. It **reuses** the saved first
pass, then adds one guard-focused request per version (ten additional requests,
two workers). Before executing it verifies equality of the original code evidence
and warning groups. The only additional model input is the prior review; no fix
labels or version flags are supplied. Prior artifacts remain unchanged.

The second reviewer must explain guard placement before the sink, normalization
of the actual destination, and directory-boundary handling. Effective/ineffective
guards need supplied code-line IDs; an ineffective guard needs a hypothetical
bypass argument. A bypass example is not an executed exploit. Missing evidence
produces uncertainty. A dismissal additionally requires a claimed effective
pre-sink guard with citations. These are structural checks, not formal proofs.
Invalid or uncertain reviews retain warnings exactly as in component 1.

This isolates the effect of adding a structured second review, not the effect of
adding more program context. It is a same-model, single-sample comparison, not an
independent oracle or a claim of research novelty. Keep it only if measured
benefit justifies its extra cost; failure to improve is also an experiment result.

```sh
python3 scripts/run_simple_filter.py \
  --plan evaluation/results/suite-plans/20261013T080658Z-9iod4p05/plan.json \
  --baseline evaluation/results/cwe22/20261013T023400Z-_h4dwq08 \
  --guard-review-of evaluation/results/simple-filter/20261014T005229Z-6wq3lt6_ \
  --execute
```

### Component 2 result: did not help

Run: [`results/guard-filter/20261014T021449Z-64a5sgui/REPORT.md`](results/guard-filter/20261014T021449Z-64a5sgui/REPORT.md).

All ten added requests completed, with structurally valid reviews for all 18
sink groups. Incremental wall time **69.9 seconds**; incremental cost
**$0.00530565**. Combined first/second-pass inference cost **$0.00982254** (20
requests). All **172 tests passed**. No paid retries or unresolved billing.

| Configuration | Vulnerable project fix-overlap matches | Proxy macro F1 | Vulnerable pairs retained | Fixed pairs retained |
| --- | ---: | ---: | ---: | ---: |
| Manual-policy Tai-e | 5/5 | 0.4708 | 69 | 70 |
| + Simple LLM filter | 5/5 | 0.4708 | 69 | 70 |
| + Guard-focused second review | 4/5 | 0.4308 | 60 | 14 |

| Project | Vulnerable pairs, simple → guard | Fixed pairs, simple → guard | Proxy F1, simple → guard |
| --- | ---: | ---: | ---: |
| zip4j | 9 → 0 | 10 → 0 | 0.2000 → 0.0000 |
| zt-zip | 24 → 24 | 24 → 0 | 0.1538 → 0.1538 |
| spark | 2 → 2 | 2 → 2 | 0.6667 → 0.6667 |
| plexus-archiver | 12 → 12 | 12 → 12 | 0.6667 → 0.6667 |
| plexus-utils | 22 → 22 | 22 → 0 | 0.6667 → 0.6667 |

**Observed failure:** on vulnerable zip4j the reviewer called directory creation
and string concatenation an effective containment guard. Its cited line was
`String compOutPath = outPath + fileName;`, not a containment check. It also
asserted that `/tmp/../evil.txt` remains under `/tmp`; lexical normalization yields
`/evil.txt`. This is a concrete reasoning error in its explanation, not an
executed exploit or a newly approved case label. Valid citation IDs did not
prevent an unsupported safety claim. All nine zip4j pairs, including its one
fix-overlapping pair, were removed as a result.

Other guard explanations also conflate string-prefix checks with directory
containment. The reduction of fixed-version warnings from 70 to 14 is therefore
**not verified false-positive reduction**. Earlier unresolved ground truth stays
unchanged. Proxy FDR's nonempty-project denominator shrinks from five to four;
do not advertise its lower average as a clean improvement.

**Decision:** preserve this as a failed ablation, not a promoted default. In this
single run, structured second-pass prompting costs more and reduces proxy F1 by
0.0400. The original simple mode remains available unchanged. A possible next
experiment is a small deterministic check on claimed containment guards before
allowing dismissal, but that component is not implemented or evaluated here.

## Component 3: offline deterministic dismissal veto

Implemented after the user approved the next small experiment. Replay the saved
guard reviews; make **zero new LLM requests**. This is a separate offline
postprocessor; it does not rewrite the earlier experiment or change its scores.

```sh
python3 scripts/veto_guard_dismissals.py \
  --from-run evaluation/results/guard-filter/20261014T021449Z-64a5sgui
```

The checker examines guard citations and nearby conditional lines from the exact
saved evidence. It recognizes a narrow subset of Java expressions, not arbitrary
Java. Concatenation and directory creation cannot establish containment. For
direct canonical/absolute path-string prefix checks, a fixed trusted Java helper
checks normal children, parent traversal, and sibling-prefix collisions. It never
executes model-generated Java or creates files. A sibling such as
`../guard-veto-root-sibling/out.txt` passes the bare string-prefix predicate but
lies outside `guard-veto-root`. Normalized `Path.startsWith` rejects that example.
An explicit separator suffix is not misclassified as the tested bare-prefix
predicate. Unknown operations remain unsupported.

These are **predicate-level counterexamples**, not end-to-end program exploits.
Other guards, variable bindings, callers, symlinks and platform assumptions may
matter. Passing finite probes does not prove safety. This initial version issues
no complete safety certificates: refuted or unsupported dismissal claims become
`uncertain`, and the associated warnings are retained. It therefore deliberately
has the same warning-retention behavior as a retain-all policy; its extra output
is diagnostic evidence explaining bad safety arguments, not better filtering.

### Measured result

Final replay: [`results/guard-veto/20261014T022402Z-v86n9_10/REPORT.md`](results/guard-veto/20261014T022402Z-v86n9_10/REPORT.md).
Previous input hashes are unchanged. Runtime **0.35 seconds**, new API cost **$0**.
All **six proposed group dismissals** were vetoed with a recognized non-guard
operation or predicate-level counterexample. This restores 65 warning pairs:
9 vulnerable-version pairs and 56 fixed-version pairs.

| Configuration | Proxy project matches | Proxy macro F1 | Vulnerable pairs | Fixed pairs |
| --- | ---: | ---: | ---: | ---: |
| Tai-e / simple filter | 5/5 | 0.4708 | 69 | 70 |
| + Guard-focused LLM review | 4/5 | 0.4308 | 60 | 14 |
| + Deterministic veto | 5/5 | 0.4708 | 69 | 70 |

Recovered zip4j's lost fix-overlapping warning. **No improvement over the original
Tai-e/simple-filter baseline**, no established false-positive reduction, and no
new approved truth labels. Verified vulnerability F1 remains unavailable.

Validation: **182 tests passed**. Ten new tests cover actual Java predicate
behavior, six synthetic expression categories, nearby guard lookup, comment and
separator-suffix exclusions, unchanged keep/uncertain decisions, and the rule
that finite-test success cannot authorize suppression. These are engineering
regression fixtures, not a held-out accuracy benchmark.

**Conclusion:** this component prevents the observed unsupported suppression and
produces checkable diagnostic evidence. It is a safeguard and failed-review
analysis, not yet an analyzer that outperforms Tai-e. More permissive suppression
would require genuinely checkable guard placement/operand evidence and an
independent evaluation; that work has not been performed in this step.

## Component 4: pairwise flow-feasibility review

User approved reviewing individual source/sink pairs instead of making one
decision for an entire sink group. Use the same saved manual-policy Tai-e
warnings, source snippets, model and proxy scorer. Split the 18 groups into
**139 unique pairs** across ten versions (69 vulnerable / 70 fixed). Every pair
gets its own stable ID. Verify that the original source evidence and groups match
component 1 before changing only their pair-level presentation.

Run one batched request per version, two workers, maximum ten calls, 60-second
network timeout, $0.25 reported-cost stop and ten-minute admission cutoff. The
output limit increases from 2,200 to **6,000 tokens** to fit up to 24 decisions per
request; no additional code is selected. All ten payloads fit 40,000 characters.
No prior guard-review conclusions, fix labels, version labels or proxy matches
enter the prompt. No new generated specs, recursive analysis, or retries.

The model must support an individual flow, identify a concrete contradiction,
or return uncertain. Different methods/variables, unseen aliases, missing code,
and unsupported call-order assumptions are not sufficient reasons for deletion.
Guard-based dismissals are vetoed; this experiment targets flow feasibility, not
guard certification. All missing/invalid/uncertain responses retain warnings.

Valid model dismissals are **proposals only**. The run's initial after-counts and
proxy score describe these provisional proposals. Every proposed removal will
be inspected against the saved code before adoption; unsupported or unresolved
removals will be retained in the reviewed result. Such assistant code review is
not independent gold annotation or a verified whole-program no-flow proof.

```sh
python3 scripts/run_simple_filter.py \
  --plan evaluation/results/suite-plans/20261013T080658Z-9iod4p05/plan.json \
  --baseline evaluation/results/cwe22/20261013T023400Z-_h4dwq08 \
  --pair-review-of evaluation/results/simple-filter/20261014T005229Z-6wq3lt6_ \
  --execute
```

Run directory: `results/pair-filter/20261014T023543Z-wynrjg6l`.
Validation before result inspection: **187 tests passed**, including pair-split
preservation, duplicate rejection, conservative fallback and guard-dismissal veto.

### Component 4 result: no improvement

All ten requests finished in **242.97 seconds**, costing **$0.00775908**. All
**139/139 pair reviews** passed structural validation. Both the raw responses and
validated decisions contain **139 keep, 0 dismiss, 0 uncertain**. Thus no code
adjudication of a proposed removal was necessary; no suppression was adopted.
This is not verification of the 139 keep explanations.

| Configuration | Proxy project matches | Proxy macro F1 | Vulnerable pairs | Fixed pairs |
| --- | ---: | ---: | ---: | ---: |
| Simple sink-group filter | 5/5 | 0.4708 | 69 | 70 |
| Pairwise flow-feasibility review | 5/5 | 0.4708 | 69 | 70 |

No warnings were removed on any project/version. The finer review unit did not
improve this sample's result and increased inference time relative to the
38.8-second simple filter. Output length and response latency differ, so this is
an observed single-run runtime comparison, not an isolated performance estimate.
It remains a manual-policy, bounded-evidence warning-filtering experiment.

Artifacts: [model result](results/pair-filter/20261014T023543Z-wynrjg6l/REPORT.md),
[completed removal review](results/pair-filter/20261014T023543Z-wynrjg6l/REMOVAL_REVIEW.md).
The runner's model-proposal report is preserved; the separate removal-review
record confirms that provisional and reviewed outputs coincide here. Original
guard/veto and baseline experiments remain unchanged. **Decision: do not add
this extra stage to the default pipeline; retain it as a negative ablation.**

## Component 5: independent-reader fusion pilot

The completed ten-call experiment combining saved vanilla Qwen/DeepSeek findings
with manual-policy Tai-e is documented in [FUSION_PILOT.md](FUSION_PILOT.md).
It uses a new, shared **method-location** unit, so its numbers cannot be compared
directly with the pair-level scores above. Reports-only fusion scored 0.7000
proxy macro F1 (4/5 project matches), below the unpaid agreement control's
0.8000 (4/5). Conservative fusion scored 0.3149 (5/5), versus normalized Tai-e
0.2593 (5/5). Only 24/95 locations received determinate judgments; code inspection
found unsupported explanations. No default warning suppression was adopted.
New judge cost was $0.00520009 and runtime 102.01 seconds. Automatic specification
quality and unresolved ground truth remain separate, unsolved limitations.
