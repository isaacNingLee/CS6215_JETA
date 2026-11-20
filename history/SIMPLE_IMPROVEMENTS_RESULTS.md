# Implemented simple improvements: results

15 October 2026. **Agreement with a Tai-e fallback helps prioritize the saved
findings. Checked guard contracts prevent incorrect safety conclusions on
component tests, but add no real-project FDR/F1 improvement in this experiment.**

This implements and evaluates the bounded extensions proposed in
[KNIGHTER_REVIEW.md](KNIGHTER_REVIEW.md). The original experiment stays frozen.
Machine-readable results are in
[SIMPLE_IMPROVEMENTS_METRICS.json](SIMPLE_IMPROVEMENTS_METRICS.json).

## Real-project detection, FDR and F1

All arms use the same saved method-location candidate universe, manual-policy
Tai-e results, and pinned fix-method labels. Vulnerable revisions are scored;
fixed revisions receive counts only because their truth is unresolved.

**These are fix-location proxies, not verified vulnerability metrics.**
Detection means at least one fix-overlapping location per project. FDR is the
fraction of selected locations without fix overlap. F1 retains the old binary
project-recall formula. Macro averages use all five projects here.

| Arm | Project detection | Selected locations | Fix-overlapping locations | Macro proxy FDR ↓ | Macro proxy F1 ↑ |
| --- | ---: | ---: | ---: | ---: | ---: |
| Tai-e | 5/5 (100%) | 42 | 5 | 84.41% | 0.2593 |
| Original conservative fusion | 5/5 (100%) | 40 | 6 | 80.68% | 0.3149 |
| Agreement, otherwise Tai-e | **5/5 (100%)** | **7** | **5** | **13.33%** | **0.9000** |
| Agreement, otherwise union | 5/5 (100%) | 9 | 5 | 16.00% | 0.8667 |
| Tai-e + deterministic guard templates | 5/5 (100%) | 42 | 5 | 84.41% | 0.2593 |
| Agreement/fallback + deterministic guards | 5/5 (100%) | 7 | 5 | 13.33% | 0.9000 |
| Tai-e + LLM-proposed, checked guards | 5/5 (100%) | 42 | 5 | 84.41% | 0.2593 |
| Agreement/fallback + LLM-proposed, checked guards | 5/5 (100%) | 7 | 5 | 13.33% | 0.9000 |
| Entire union, including review tail | 5/5 (100%) | 47 | 6 | 86.12% | 0.2419 |

The agreement rule selects methods reported by Tai-e and either reader. When
there is no agreement in a project/version, it selects Tai-e's candidates.
Selection never reads fix labels. Other candidates stay in the review tail:
the vulnerable versions have seven priority locations and 40 tail locations.
The two tiers have no duplicate IDs and jointly preserve the entire union.

**The 0.9000 score belongs to the priority tier. Keeping the tail does not improve
full-output precision.** Five-project coverage also hides a loss: the second
zt-zip fix-overlapping location moves to the tail. This is a useful operating
point, not evidence of complete recall or safe automatic suppression.

| Project | Tai-e selected/matching | Priority selected/matching | Tai-e proxy F1 | Priority proxy F1 | Priority proxy FDR |
| --- | ---: | ---: | ---: | ---: | ---: |
| zip4j | 7/1 | 1/1 | 0.2500 | 1.0000 | 0% |
| zt-zip | 13/1 | 1/1 | 0.1429 | 1.0000 | 0% |
| spark | 3/1 | 3/1 | 0.5000 | 0.5000 | 66.67% |
| plexus-archiver | 7/1 | 1/1 | 0.2500 | 1.0000 | 0% |
| plexus-utils | 12/1 | 1/1 | 0.1538 | 1.0000 | 0% |

Spark uses the fallback. The other projects use agreement. This rule was
developed after inspecting these subjects, and legacy readers saw fix-selected
files. Neither the new score nor the earlier score establishes generalization.

## Guard component: what was actually implemented

- `selective_fusion.py`: label-independent priority selection with an explicit,
  complete review tail and duplicate-ID checks.
- `SourceFacts.java`: JDK parser extraction of exact method boundaries,
  qualified nested-class names, parameter types, structured statements, prefix
  guards, assignments and filesystem sink allocations. No subject code is run.
- `guard_contracts.py`: a restricted validator for directory containment.
  Bare canonical/absolute path string prefixes receive a concrete counterexample.
  A supported component-aware Path guard must reject the failing branch, check
  the same unchanged normalized absolute Path consumed by the sink, and use a
  trusted root independent of the untrusted String input.
- The support proof is deliberately narrow: one explicitly qualified JDK Path
  root parameter, one explicitly qualified `java.io.FileOutputStream` allocation,
  supported straight-line declarations and a direct rejecting `if`. Complex
  control flow, reassignment, overload ambiguity and cross-method effects stay
  unknown. This is a structural proof for a limited template, not a new general
  CFG/alias analyzer. It assumes ordinary JDK POSIX paths, no symlinks or races.
- `run_guard_experiment.py`: hypothesis proposals by Qwen, deterministic
  validation, frozen predictions before scoring, budgets, response replay,
  provenance and comparison arms. A naive LLM safety arm is evaluated only on
  fixtures. It does not alter the real-project output.
- A contract cache binds complete extracted facts, assumptions, validator code
  hash and JDK identity. The final replay recorded 53 hits and 43 entries;
  this is a correctness/reuse mechanism, not a measured speedup claim.

Candidate identities retain links to precise source methods and Tai-e
signatures. Historical scoring still uses the original normalized locations to
avoid changing the metric while changing the method. The new inventory maps
35/95 candidate locations uniquely, seven ambiguously, and leaves 53 without
source bodies in the archived project sources. This improves visibility of the
evidence gaps; it does not reconstruct missing JDK/library code.

## What the guard evaluation found

No real candidate acquired a supported sink-protection contract. Consequently,
the guard arms change neither FDR nor F1 on the five real projects. The restricted
template and conservative handling of unsupported cases explain this result;
the score was not improved by assuming patched versions are safe.

There is nevertheless a concrete error-prevention result. Qwen proposed **seven
safe containment claims on real-project guards** that the validator refuted:
one in fixed Zip4j, four in fixed zt-zip, one in fixed plexus-archiver, and one in
fixed plexus-utils. They rely on bare string prefixes. Under the predicate's
ordinary path interpretation, `/tmp/outside/probe` starts with `/tmp/out` but
is not within that directory. `PredicateProbe.java` reproduced the distinction
using the installed JDK for both canonical and absolute String prefixes versus
Path component prefixes. It performs path calculations without file output.

These counterexamples refute the proposed general containment predicates. They
are **not end-to-end exploit reproductions or seven newly confirmed bugs**.
The source inventory also contains prefix guards used for other purposes;
rejecting a generic containment contract does not prove those uses incorrect.

## Separate component-test detection metrics

Fourteen authored Java methods provide semantic contrasts: eight unsafe and six
safe under the stated assumptions. They cover missing/wrong/late/partial guards,
unnormalized paths, reassignment, string prefixes, renaming, parentheses, return
versus throw, and two unsupported but safe control-flow forms. They are compiled
to verify valid examples, but their file-output operations are never executed.
The LLM receives opaque method names and no labels.

Here detection, FDR and F1 use ordinary TP/FP/FN counts. Unsupported cases remain
warnings. This is a component evaluation with authored labels, separate from
real-project proxy metrics; the all-warning control is not a new Tai-e run.

| Fixture arm | TP | FP | FN | TN | Detection | FDR ↓ | F1 ↑ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Unfiltered sink candidates | 8 | 6 | 0 | 0 | 100% | 42.86% | 0.7273 |
| LLM safety decisions without validation | 6 | 1 | 2 | 5 | 75% | 14.29% | 0.8000 |
| Deterministic guard templates | 8 | 2 | 0 | 4 | **100%** | **20.00%** | **0.8889** |
| LLM-proposed, checked guard contracts | 8 | 2 | 0 | 4 | **100%** | **20.00%** | **0.8889** |

The naive LLM incorrectly removes `unsafe_not_normalized` and
`unsafe_string_prefix`. Validation retains both. It also recognizes the safe
returning rejection that the naive LLM leaves as a warning. The two remaining
false alarms are safe positive-branch and try-block forms outside the supported
template. The LLM's lower FDR comes at the expense of two missed unsafe cases.

The checked LLM arm **does not beat deterministic templates**. Therefore, this
study provides no evidence that another LLM guard pass is worth adding to the
default pipeline. Keep it as an ablation demonstrating why proposals need
validation. The tests establish bounded behavior, not universal correctness or
held-out detection accuracy.

## Validation, cost and reproduction

The paid run completed 11 requests using `qwen/qwen3-coder-30b-a3b-instruct`,
temperature 0, low reasoning, and a 4,000-token output cap. All response schemas
validated. New reported cost was **$0.00257887**, with no unknown billing.
This excludes reused original Tai-e/reader costs and local compilation.

Paid evidence:
`results/guard-experiment/20261015T041059Z-7yhfygzj`.
The final code was replayed against exactly the same eleven requests/responses:
`results/guard-experiment/20261015T041503Z-bzsgudh1`.
All real-project and fixture metrics match exactly; replay made no API calls.
The final code additionally guards against attacker-derived roots and ambiguous
duplicate source identities; these changes did not change the observed results.

**49 tests pass**, including all original 32 tests and new mutation, parser,
proposal-validation, cache and selection checks. `git diff --check` passes.
No original baseline, model response, truth label or result was overwritten.

Run the implemented deterministic study:

```sh
python3 scripts/run_guard_experiment.py \
  --pilot evaluation/results/fusion-pilot/20261014T025408Z-447y9ikk \
  --baseline evaluation/results/cwe22/20261013T023400Z-_h4dwq08 \
  --plan evaluation/results/suite-plans/20261013T080658Z-9iod4p05/plan.json
```

Append this argument to replay the model-assisted study without inference:

```sh
--replay evaluation/results/guard-experiment/20261015T041059Z-7yhfygzj
```

Use `--execute` instead of `--replay` only for a new paid experiment. The runner
allows at most eleven calls, no automatic retries, and stops further calls when
reported spending reaches $0.25 or billing becomes unknown. The final call can
cross the stopping threshold. Missing/invalid proposals remain unknown.

Each run writes new source facts, proposed/validated contracts, code snapshots,
input hashes, decisions, priority/tail IDs, metrics and a report. A replay checks
exact request equality. Existing local benchmark artifacts and JDK 17 are
required; the tracked summary is not a complete portable dataset bundle.

**Recommended retained configuration:** use agreement with fallback as a
priority view, keep the complete tail, and keep guard validation as a tested
optional diagnostic. Report its zero real-project gain and the LLM false-safety
examples. A fresh, label-independent, reviewed evaluation is needed before
claiming improved vulnerability detection FDR or F1.
