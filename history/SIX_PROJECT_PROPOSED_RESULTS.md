# Six-project comparison including our proposed method

**Corrected interpretation (17 October 2026):** the shortlist’s proxy F1 of 0.9167 describes eight selected locations. The current priority variant also preserves 51 locations for review, so its complete-output proxy F1 is 0.2272. The earlier combined table placed the shortlist score beside complete baseline outputs; that presentation overstated the evidence for overall analyzer accuracy. The recorded predictions and numerical scores are unchanged.

**The two variants have different output scopes:** original fusion retains reports and uncertainty after the reconciliation judge. The priority variant ranks agreement between Tai-e and either independent vanilla reader first, falling back to Tai-e when there is no agreement. It preserves every remaining candidate in a review tail. The review tail means lower-priority candidates, not candidates proved safe.

## Complete reported outputs

| Approach | Project detection | Macro proxy FDR ↓ | Macro proxy F1 ↑ | Output scope |
| --- | ---: | ---: | ---: | --- |
| Tai-e | 6/6 | 85.50% | 0.2439 | All reported CWE-22 locations |
| Vanilla Qwen | 3/6 | 50.00% | 0.5000 | All reported CWE-22 locations |
| Vanilla DeepSeek | 5/6 | 22.22% | 0.8000 | All reported CWE-22 locations |
| Hinted Qwen | 5/6 | 16.67% | 0.8333 | All reported CWE-22 locations |
| Hinted DeepSeek | 5/6 | 30.00% | 0.6667 | All reported CWE-22 locations |
| Ours: original conservative fusion | 6/6 | 82.51% | 0.2881 | Reports + uncertain |
| Ours: full candidate union, including review tail | 6/6 | 87.04% | 0.2272 | Priority + review tail |

All rows use the same fix-method-location proxy. Hinted DeepSeek’s macro FDR covers five nonempty projects; every other row covers six. Detection and macro F1 include all six projects, including empty outputs. Original conservative fusion improves this proxy over Tai-e (0.2881 versus 0.2439 F1). The complete priority-plus-tail output does not (0.2272).

## Shortlist diagnostic: a subset of the current output

| Selection rule | Project detection | Macro proxy FDR ↓ | Macro proxy F1 ↑ | Selected / remaining |
| --- | ---: | ---: | ---: | ---: |
| Agreement/fallback control (priority tier) | 6/6 | 11.11% | 0.9167 | 8 / 51 |
| Ours: agreement/fallback + checked guards (priority tier) | 6/6 | 11.11% | 0.9167 | 8 / 51 |

The priority variant has **8 priority locations with 6 fix matches**, and **51 tail locations with 1 fix match**. Adding the tail adds many unmatched locations, which lowers proxy precision and F1. Unmatched locations are not independently verified false positives. The second zt-zip fix-overlapping location is in the tail.

**Different output counts are allowed.** A method may legitimately report only the eight shortlisted locations as its final predictions and suppress the other 51. That would be a filtering operating point, and it could be compared with complete baseline outputs without forcing equal alert counts. However, this report does not change the current output policy, and such a filtering evaluation must count the relevant locations or vulnerabilities lost through suppression.

If the method continues to expose all 59 locations with eight highlighted, the complete-output table applies. To compare the highlighting benefit, evaluate all methods at the same review budget per project, with a fixed ordering and tie rule, using Precision@k and project Detection@k. **No equal-review-budget baseline comparison has been run**, so the shortlist table alone does not establish superior prioritization against the baselines.

## What the existing F1 proxy measures

For each project, N is the number of selected method locations and K is the number overlapping recorded production fix methods. Precision is K/N and FDR is 1 − K/N for nonempty output. The evaluator uses recall = 1 whenever K > 0 and recall = 0 otherwise, giving proxy F1 = 2K/(N+K) when K > 0 and zero otherwise. Reported F1 is the mean of the six project scores, not a pooled score calculated from the totals above.

**This is binary project detection, not location-level recall.** For example, selecting one of two fix-overlapping zt-zip locations still gets project recall 1. If that selected location is the only output, its proxy F1 is also 1 despite leaving the other match in the tail. The current metric therefore cannot establish that filtering preserves all relevant findings. A location-level evaluation needs a fixed reference set and must count unreported reference locations as false negatives; verified vulnerability F1 additionally needs adjudicated vulnerability labels.

**Supported conclusion:** the shortlist concentrates recorded fix matches and retains at least one in all six development projects. Its 0.9167 is neither the accuracy of the complete output nor verified vulnerability F1.

## Actual MPXJ fusion run

The new run reuses the exact original fusion candidate builder, source-window packaging, judge prompt, validator and selection functions. The only adapter converts the new saved vanilla-response directory layout into the old reader layout using byte-identical copies. It does not replace readers with hinted responses. No historical source code, model response or decision was edited.

- Inputs: the fresh MPXJ Tai-e warning set and both completed **vulnerable vanilla** Qwen/DeepSeek responses from the preceding baseline run.
- Source catalogue: exported from the pinned vulnerable build with the same Tai-e catalogue plugin, without a taint policy or fix labels.
- Candidates: 12; locations without supplied method bodies: 10. Missing code remains explicit; an unsupported decisive answer is downgraded to uncertainty.
- Judge decisions after validation: {'uncertain': 10, 'report': 2}; accepted reviews: 2/12; validation/request errors: ["'M00001'", "'M00001'", "'M00001'", "'M00001'", "'M00001'", "'M00001'", "'M00001'", "'M00001'", "'M00001'", "'M00001'"].
- Judge settings: Qwen `qwen/qwen3-coder-30b-a3b-instruct`, temperature 0, low reasoning, maximum 5,000 output tokens, one request, no retries.
- Predictions and selected/tail IDs were saved before loading fix-method labels.

**Review failure is retained:** only two MPXJ judgments have valid supplied-code citations. Ten judgments reference an absent method ID (`M00001`) and are rejected by the existing validator, leaving those candidates uncertain. The conservative fusion score includes them; this is not twelve successful reviews. The priority rule uses agreement between the independent readers and Tai-e and does not depend on those invalid judge citations.

| MPXJ arm | Selected locations | Fix matches | Proxy FDR | Proxy F1 |
| --- | ---: | ---: | ---: | ---: |
| Ours: original conservative fusion | 12 | 1 | 91.67% | 0.1538 |
| Agreement/fallback control (priority tier) | 1 | 1 | 0.00% | 1.0000 |
| Ours: agreement/fallback + checked guards (priority tier) | 1 | 1 | 0.00% | 1.0000 |
| Ours: full candidate union, including review tail | 12 | 1 | 91.67% | 0.1538 |

On MPXJ, Tai-e and vanilla DeepSeek agree on `InputStreamHelper.processZipStream`. Vanilla Qwen names `writeZipStreamToTempDir`, which is not in the static candidate set and is not the recorded fix location. Consequently, the priority rule selects the extraction method and places the wrapper and other locations in the tail.

The ten library/JDK locations lack method bodies in the original catalogue scope. The conservative method must retain uncertain results for those locations. The priority rule assigns them to the review tail. That difference explains much of the gap between the two variants; it is not proof those locations are harmless.

## Guard contribution and patched-version limitation

The guard-enabled priority arm ties agreement/fallback without guards on the six vulnerable revisions. The old five guard decisions are reused exactly; MPXJ’s vulnerable source inventory contains no containment guard, so no additional guard proposal request is needed and no supported guard removes a candidate. **The shortlist score comes from agreement/fallback selection; guards add no measured gain on these vulnerable revisions.**

The separate [MPXJ guard case study](GUARD_EXPANSION_RESULTS.md) measures removal of a repaired source-to-sink route under its explicit filesystem assumptions. Its two-revision F1 is not averaged into this six-project vulnerable-location score. A protected sink route also does not automatically prove every incident flow at the same method location safe.

A complete two-reader fusion run for **patched** MPXJ remains unavailable: its vanilla DeepSeek baseline failed to return an answer within the configured budget. We do not substitute a hinted reader or treat that missing response as an empty finding set. This does not affect the complete vulnerable-revision aggregate above.

## Per-project diagnostic: complete original fusion versus shortlist

The priority columns score only the shortlist; original fusion scores all retained reports and uncertainty. These are different output scopes.

| Project | Original fusion F1 | Priority F1 | Priority FDR | Priority selected/matching |
| --- | ---: | ---: | ---: | ---: |
| zip4j | 0.5000 | 1.0000 | 0.00% | 1/1 |
| zt-zip | 0.2222 | 1.0000 | 0.00% | 1/1 |
| spark | 0.4000 | 0.5000 | 66.67% | 3/1 |
| plexus-archiver | 0.2857 | 1.0000 | 0.00% | 1/1 |
| plexus-utils | 0.1667 | 1.0000 | 0.00% | 1/1 |
| mpxj | 0.1538 | 1.0000 | 0.00% | 1/1 |

These are macro averages of development-set fix-location proxies. LLM inputs were fix-selected files; Tai-e uses a broader reachable-program scope. They are not exploitability labels or held-out accuracy. The original five predictions and per-project scores were replayed unchanged, rather than replacing historical responses with favorable reruns.

## Artifacts and validation

- New run: `evaluation/results/six-project-fusion/20261016T083749Z-m1it98n7`.
- Exact offline replay: `evaluation/results/six-project-fusion/20261016T084024Z-15lnz5xf`.
- New reconciliation calls: 1; reported incremental cost: $0.00056035; unknown billing: False.
- All 61 tests pass, including candidate preservation, conservative uncertainty handling, tier partition and missing-decision checks. Exact replay reproduces the request, response, decisions and every aggregate score without inference.
- Machine-readable results: [SIX_PROJECT_PROPOSED_METRICS.json](SIX_PROJECT_PROPOSED_METRICS.json).
- Baseline details and earlier API costs: [SIX_PROJECT_BASELINE_RESULTS.md](SIX_PROJECT_BASELINE_RESULTS.md).

```sh
# Reuse the prepared catalogue; --execute makes one fresh judge request.
python3 scripts/run_six_project_fusion.py \
  --catalogue evaluation/results/spec-catalogue/20261016T031053Z-mpxj-vulnerable-l1jh0fsw \
  --execute

# Offline replay of the recorded request/response.
python3 scripts/run_six_project_fusion.py \
  --catalogue evaluation/results/spec-catalogue/20261016T031053Z-mpxj-vulnerable-l1jh0fsw \
  --replay evaluation/results/six-project-fusion/20261016T083749Z-m1it98n7

python3 -m unittest discover -s scripts -p 'test_*.py'
```
