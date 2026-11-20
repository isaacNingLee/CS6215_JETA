# Selective agent debate: implementation and results

20 October 2026. **Corrected final-output comparison:** the user clarified
that only warnings passing the existing priority gate are final predictions.
The review tail is excluded for both the baseline and debate. Under this
policy, debate **ties**, rather than degrades, the current proposed method.
The earlier comparison below used the historical conservative-output variant,
which was the wrong operating point for the user's intended comparison.

| Final-output arm (same gate, tail excluded) | Project matches | Macro proxy F1 | Macro proxy FDR | Locations / fix overlaps |
| --- | ---: | ---: | ---: | ---: |
| Current proposed selection | 6/6 | **0.9167** | **11.11%** | 8 / 6 |
| Selection + fresh single judge | 6/6 | 0.9167 | 11.11% | 8 / 6 |
| Selection + independent review | 6/6 | 0.9167 | 11.11% | 8 / 6 |
| Selection + debate | 6/6 | 0.9167 | 11.11% | 8 / 6 |

The implemented gate is agreement between Tai-e and either saved reader,
falling back to static candidates when no agreement exists. Checked guards
made no selection changes on these six vulnerable revisions, as documented
in the original six-project report. Gate exclusion is not a proof of safety.
The evaluator applies the same gate to every arm; debate cannot promote a
tail warning to the final output. Final selected IDs are saved before labels
are loaded. No inference was repeated for this correction.

All four final-output arms select the same eight locations. One additional
zt-zip fix-overlapping location remains excluded in the tail for all of them.
Thus debate loses no match relative to the current selection, while the
selection itself retains six of seven fix overlaps in the candidate union.
The binary project-detection proxy does not measure that location-level loss.

### Historical conservative-output diagnostic

| Complete-output arm | Project matches | Macro proxy F1 | Macro proxy FDR | Retained locations | Fix-overlapping locations |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original conservative fusion | 6/6 | **0.2881** | **82.51%** | 52 | 7 |
| Fresh single judge | 6/6 | 0.2272 | 87.04% | 59 | 7 |
| Independent analysts + judge | 6/6 | 0.2272 | 87.04% | 59 | 7 |
| Analysts + rebuttal + judge | 6/6 | 0.2272 | 87.04% | 59 | 7 |

For the historical conservative-output policy only, debate lowers proxy F1 by 0.0609 and raises proxy FDR by 4.53 percentage
points relative to the original method. It restores all seven previously
dismissed locations without adding any fix overlap. Unmatched locations are
not established false positives.

**Debate and independent review have identical report/dismiss/uncertain
decisions on every candidate.** Thus the rebuttal round offers no measured
benefit even against the fresh, same-model control. The fresh single judge
also selects the same retained locations, although it reports one more
location instead of leaving it uncertain.

## Implemented experiment

[`debate_fusion.py`](../scripts/debate_fusion.py) implements selective review.
[`run_debate_fusion.py`](../scripts/run_debate_fusion.py) loads and validates
the frozen six-project inputs, archives every request and raw response, runs
bounded inference, and scores only after saving all predictions.

The roles use separate calls to `qwen3-coder-next`, through the project's
existing SoCLaaS connection. This is role-based debate using one model, not a
heterogeneous-model debate experiment.

1. Revisit original uncertain/dismissed candidates with supplied method-local
   source. This selects 11 of 59 candidates across five projects.
2. Obtain independent vulnerability and safety assessments.
3. Judge those assessments without discussion: the independent-review control.
4. Give each analyst the same two initial assessments for one rebuttal round.
5. Judge the revised assessments: the debate arm.

A separate fresh single judge receives the same source evidence. Initial
analysts cannot see each other's answers. Rebuttal analysts cannot see each
other's rebuttals. The judges do not see fix labels or project-version labels.
Original reports and candidates without method bodies retain their decisions.
MPXJ has zero eligible candidates; its ten uncertain candidates lack method
bodies. No new source retrieval or candidate discovery was introduced.

Every decisive review passes the original candidate-local citation validator.
Independent review and debate also share a dismissal veto: both validated
analysts must support dismissal. Citation validity and consensus do not
establish semantic correctness. All invalid/missing reviews remain uncertain.

## What happened

The original output has 8 reports, 44 uncertain decisions and 7 dismissals.
Debate produces 18 reports, 41 uncertain decisions and no dismissals. It
converts three previously retained uncertain candidates into reports and
restores the seven dismissals as reports. All seven original fix-overlapping
locations remain retained.

Some explanations broaden the meaning of a finding. For example, the Spark
`getDescription` debate decision discusses logging/information disclosure and
hypothetical downstream file use, rather than establishing CWE-22 in the
provided method. This illustrates why valid citations and agent agreement
are insufficient to validate a vulnerability claim. Other restored locations
are source/sink helpers on a traversal route; their failure to overlap a fix
method does not prove they are harmless.

Seven validation errors occurred, including wrong-method citations and one
Spark response using a JSON array instead of the required object. The initial
runner exposed an unhandled schema error. Failure handling was repaired,
regression-tested, and the run resumed with all 31 completed responses reused
unchanged. Only four outstanding calls were made; no answer was resampled.
The final evaluation contains all six projects.

## Inference overhead

| Fresh arm | Calls | Prompt tokens | Completion tokens | Total tokens |
| --- | ---: | ---: | ---: | ---: |
| Single judge | 5 | 23,927 | 2,478 | 26,405 |
| Independent review | 15 | 74,978 | 6,935 | 81,913 |
| Debate | 25 | 130,886 | 11,797 | 142,683 |

The entire ablation made **35 unique calls**, sharing the ten initial analyst
calls between independent review and debate. Debate uses about 1.74 times
the independent-review tokens, with identical final decisions. SoCLaaS
responses do not provide a measured dollar cost.

Each debate-stage output cap is 3,000 tokens. The single-judge cap is 15,000,
equal to the sum of the five debate-stage caps per project. This does not
match realized tokens, input tokens, or reasoning compute. The old judge used
an older model, so the original-versus-fresh difference cannot be attributed
solely to debate. The same-model independent-review control isolates the
incremental rebuttal stage more directly.

## Validation and reproduction

Ten new tests and ten existing fusion/selection tests pass. The pinned
dataset revision was checked through Git. Offline replay reproduces every
request, validated stage, arm decision and metric without inference.

```sh
python3 -m unittest discover -s scripts -p 'test_debate*.py'
python3 -m unittest discover -s scripts -p 'test_fusion_pilot.py'
python3 -m unittest discover -s scripts -p 'test_selective_fusion.py'

# Prepare inputs without inference.
python3 scripts/run_debate_fusion.py

# New bounded experiment (35 requests when all five eligible projects run).
python3 scripts/run_debate_fusion.py --execute

# Reproduce the recorded experiment without inference.
python3 scripts/run_debate_fusion.py \
  --replay evaluation/results/debate-fusion/20261020T025015Z-j6iotek0
```

The completed run is
[`20261020T025015Z-j6iotek0`](results/debate-fusion/20261020T025015Z-j6iotek0/REPORT.md).
Its first 31 responses came from the preserved initial attempt
`20261020T024825Z-f8620546`. Machine-readable aggregate scores and decision
changes are also saved in [DEBATE_METRICS.json](DEBATE_METRICS.json).
Full local run artifacts are Git-ignored, consistent with existing experiments.
The corrected final-output replay is
[`20261020T033039Z-2igfrca_`](results/debate-fusion/20261020T033039Z-2igfrca_/REPORT.md);
`DEBATE_METRICS.json` includes its `final_*` arms. All six projects have exactly
the same final selected IDs for the original, independent-review and debate arms.

These remain fix-method-location proxies on repeatedly used development
projects, not verified vulnerability accuracy or held-out evidence. Binary
project detection can hide lost locations, so the evaluator also records lost
original fix matches and retention of fix overlaps within the frozen union.
No original match is lost by the conservative-output debate arm. Under the
clarified final-output policy, only the eight selected locations are predictions;
the tail is not counted as reported warnings.
For the final-output policy, debate ties the current method at greater cost.
This experiment does not rule out benefits from better evidence retrieval,
different models, or other debate protocols; it provides no reason to replace
the retained method with this particular extension.
