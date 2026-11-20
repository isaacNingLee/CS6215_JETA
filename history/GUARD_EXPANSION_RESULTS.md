# Supplemental real-project guard evaluation: MPXJ

16 October 2026. **MPXJ (CVE-2020-35460) is a useful sixth project.** Its patched
extraction method contains a separator-aware canonical-path rejection before a
file-output sink. A small attributed guard-checker extension retains detection
of the vulnerable route and removes the corresponding patched-route alarm.
The original checker alone does not improve the result.

This is a targeted development case study, not a held-out benchmark improvement.
The original five-project scores and the 14 authored component fixtures remain
separate. Adding a project does not turn component fixtures into benchmark cases.

## Selection and provenance

The selection and screened alternatives are recorded in
[guard-expansion-subjects.json](guard-expansion-subjects.json), copied into the
Tai-e suite before analysis or model scoring. Selection used code structure and
the dataset's successful Maven-build record, not evaluation scores. This is
purposive sampling of an informative guard pattern, not random sampling.

| Item | Value |
| --- | --- |
| Dataset revision | `afe0ebd0adc237abb46255f9cd479b1d71819136` |
| Subject | `joniles__mpxj_CVE-2020-35460_8.3.4` |
| Vulnerable revision | `87ea0ba33e901b87c95a18e3703ac51b59e2ee04` |
| Patched revision | `8eaf4225048ea5ba7e59ef4556dab2098fcc4a1d` |
| Route | `InputStreamHelper.processZipStream`: ZIP-entry name to `FileOutputStream(File)` |
| Static entry | `writeZipStreamToTempDir(InputStream)` via an analysis-only adapter |

The [upstream MPXJ patch](https://github.com/joniles/mpxj/commit/8eaf4225048ea5ba7e59ef4556dab2098fcc4a1d)
adds a canonical destination check with a directory separator. Both project
revisions were built without source or POM changes using Java 17 and the existing
Maven/Tai-e runner. The entry allocates its destination through `FileHelper.createTempDir`;
the trusted-root assumption is explicitly scoped to ordinary operation without races.

Other screened candidates:

- **Hutool, CVE-2018-17297:** a bare canonical string prefix duplicates the boundary
  issue already seen in the original projects; it also needs a helper/module analysis.
- **CureKit, CVE-2022-23082:** a useful component-aware `Path.startsWith` repair,
  but the changed method is a boolean helper without a filesystem sink. It is a
  candidate for subsequent interprocedural evaluation, not a second result here.
- **one-java-agent, CVE-2022-25842:** the inspected patch removes an unused unzip
  method rather than adding a guard.

## What changed

The frozen checker returns `unknown` on MPXJ's repaired guard. It requires an
explicitly qualified JDK sink and a straight-line normalized-Path template.
Consequently, selecting a new project alone would not have produced a benefit.

[CanonicalGuardCheck.java](../analysis/guards/CanonicalGuardCheck.java) adds a
separate, deliberately restricted canonical-path contract. It uses javac type
attribution, so imported names resolve to actual JDK methods and constructors.
It requires a trusted `File` root parameter, an output `File` constructed from
that root, canonical strings derived from those same objects, the actual JDK
`File.separator`, and a rejecting negative guard before a direct sink declaration
in the **same block**. That block can be a loop body. Referenced locals must come
from initializers without reassignment. Unknown patterns retain their alarms.

The checker contains no MPXJ names, expected patch labels, or hard-coded source
line numbers. Nevertheless, it was developed after inspecting MPXJ, so this is
an in-sample extension. The old checker is preserved as an ablation.

The supplemental evaluator maps contracts to the exact sink line and method,
persists predictions before applying labels, and keeps every other flow in the
unreviewed output. An optional Qwen call proposes containment contracts using
the previous experiment's prompt; the typed checker decides whether a proposed
contract is supported. Source code, requests, responses, hashes and contracts are
saved in the run directory.

## Labels and real-code execution

The scoring unit is **one selected extraction route per revision**: one vulnerable
positive and one patched negative under the stated model. It is not a count of
all flow pairs, all methods, all vulnerabilities, or test inputs.

[MpxjGuardProbe.java](adapters/mpxj/MpxjGuardProbe.java) invokes the actual compiled
private extraction method with an explicit temporary destination. It changes no
project code. Each test has its own temporary sandbox, and even escaping writes
remain inside that sandbox. This is route-level execution, not execution through
the public entry used for static analysis.

| ZIP entry | Vulnerable revision | Patched revision |
| --- | --- | --- |
| `nested/ok.txt` | Extracted inside root | Extracted inside root |
| `../escape.txt` | Written outside root | Rejected; no file written |
| `../root-extra/escape.txt` | Written to sibling directory | Rejected; no file written |

Source review and the attributed contract support the scoped negative label;
the finite probes corroborate it but do not prove safety for every environment.
Assumptions are ordinary JDK File instances and POSIX semantics, a trusted root,
no symlinks under the extraction root, and no filesystem races. Labels have not
received independent human review. No claim is made about all MPXJ behavior.

## Detection, FDR and F1

All three metrics use the same two revision-route units. Detection is
`TP/(TP+FN)`, FDR is `FP/(TP+FP)`, and F1 is `2TP/(2TP+FP+FN)`.

| Method | TP | FP | FN | TN | Detection | FDR | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Tai-e baseline | 1 | 1 | 0 | 0 | 1/1 | 50% | 0.6667 |
| Tai-e + frozen guard checker | 1 | 1 | 0 | 0 | 1/1 | 50% | 0.6667 |
| Tai-e + attributed canonical checker | 1 | 0 | 0 | 1 | 1/1 | 0% | 1.0000 |
| Tai-e + LLM-only guard assessment | 1 | 0 | 0 | 1 | 1/1 | 0% | 1.0000 |
| Tai-e + LLM proposal + attributed checker | 1 | 0 | 0 | 1 | 1/1 | 0% | 1.0000 |

**This demonstrates real-project applicability of guard handling. It does not
demonstrate superiority over deterministic checking or LLM-only assessment.**
All successful arms tie here. It would be misleading to attribute this gain to
LLM synthesis or claim broad generalization from one development project.

The raw Tai-e runs report 22 vulnerable and 24 patched flow pairs. The selected
route accounts for one and two pairs respectively, collapsed to one route per
revision. The checker protects the patched sink, which occurs in 12 pairs;
those are removed from the guard-filtered view. All 22 vulnerable pairs and 12
other patched pairs remain. The remaining patched pairs target a JDK internal
sink and are not adjudicated here. **Whole-project FDR/F1 is therefore unknown.**
The raw alarms and their disposition are retained for review.

## Relation to the original five projects

The original guard templates found no supported safe sink contract on the five
projects. Several repaired archive cases use bare string-prefix checks, for which
directory-boundary counterexamples remain relevant. MPXJ adds a different pattern
and also exposes an implementation coverage gap, addressed by the new checker.

The original five-project headline F1/FDR figures are vulnerable-revision
**fix-location proxies**. They do not measure removal of an alarm on a genuinely
safe repaired route. This paired-route table answers that different question.
Do not average these numbers with the original proxy scores or the fixture scores.
The main manifest remains the original five; the supplemental manifest contains
MPXJ alone. This preserves the previous experiment while adding a sixth subject.

## Validation and reproduction

52 Python tests pass, including an 18-pattern attributed-checker test covering
missing boundaries, unnormalized paths, wrong branches, wrong sink objects,
reassignment, conditional/caught rejection, sink order and unsupported patterns.
These are additional software checks, not additional benchmark subjects.
The six real-code probe executions are also not six independent CVEs.

One Qwen proposal request was made with at most 1,500 output tokens and no retries;
reported cost was **$0.00007007**. Offline replay reproduces requests, predictions,
probes and scores without another model call.

```sh
python3 scripts/run_cwe_benchmark.py \
  --manifest evaluation/guard-expansion-subjects.json --projects mpxj --repetitions 1

# Substitute the suite path printed by that command. No API call by default.
python3 scripts/evaluate_guard_expansion.py --suite <suite-directory>

# Optional: one fresh paid proposal request.
python3 scripts/evaluate_guard_expansion.py --suite <suite-directory> --execute

# Exact offline replay, using the recorded paid run below.
python3 scripts/evaluate_guard_expansion.py \
  --suite evaluation/results/cwe22/20261016T011625Z-jjzt1hh6 \
  --replay evaluation/results/guard-expansion/20261016T012328Z-_5yv8pga

python3 -m unittest discover -s scripts -p 'test_*.py'
```

Recorded artifacts (large result directories are Git-ignored):

- Static suite: `evaluation/results/cwe22/20261016T011625Z-jjzt1hh6`.
- Paid guard run: `evaluation/results/guard-expansion/20261016T012328Z-_5yv8pga`.
- Final offline replay: `evaluation/results/guard-expansion/20261016T012430Z-6fwe_8y_`.
- Portable summary: [GUARD_EXPANSION_METRICS.json](GUARD_EXPANSION_METRICS.json).

An initial local scoring attempt omitted Tai-e's source-record wrapper in its
route matcher. That run (`20261016T012142Z-6xgaumev`) is marked invalidated and
excluded. The corrected evaluator checks consistency with baseline route
detection, and a regression test covers the record format.
