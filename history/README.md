# Design history (superseded designs)

These reports document the designs we tried before JETA, summarized in §4.3 (Design Iterations) of
the report. They are **superseded**: none of this is part of the method, the reproduction steps, or
the numbers in Tables 1–3. They were written during development in an earlier working repository,
so links inside them to `results/...` run folders and `scripts/...` point to raw outputs and code
that are not included here.

Early experiments used five projects (MPXJ was added on 16 October) and one reader sample.
`SIMPLE_PIPELINE.md` counts Tai-e source–sink **pairs**, a different unit from the report's method
locations, so its pair-level F1 is not comparable with the report.

| §4.3 claim | Source |
| --- | --- |
| (1) Inferred policy: 1,032 source–sink pairs on vulnerable plexus-utils (86 × 12), half from a `String.indexOf` sink rule; seven methods unclassified | [AUTOMATIC_SPECIFICATION_REPORT.md](AUTOMATIC_SPECIFICATION_REPORT.md), "Step 3" |
| (1) 22 pairs under the manual policy | [SIMPLE_PIPELINE.md](SIMPLE_PIPELINE.md), first result table |
| (2) Sink-group review kept all 18 groups and all 139 pairs | [SIMPLE_PIPELINE.md](SIMPLE_PIPELINE.md), "First result" |
| (2) Guard-focused review: fixed-revision pairs 70 → 14, all nine vulnerable zip4j pairs (incl. the fix) removed, `/tmp/../evil.txt` claim | [SIMPLE_PIPELINE.md](SIMPLE_PIPELINE.md), "Component 2 result" |
| (2) Deterministic check rejected all six dismissals | [SIMPLE_PIPELINE.md](SIMPLE_PIPELINE.md), "Component 3" |
| (2) Generative judge: 71 of 95 methods uncertain; macro FDR 84.4% → 80.7% | [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) §4, [FUSION_PILOT.md](FUSION_PILOT.md) |
| (2) More code context: malformed responses, lower scores | [FUSION_EVIDENCE_PACKETS.md](FUSION_EVIDENCE_PACKETS.md) |
| (3) Agreement gate; checked guards prevent two false dismissals in a 14-case component test | [SIMPLE_IMPROVEMENTS_RESULTS.md](SIMPLE_IMPROVEMENTS_RESULTS.md), [GUARD_EXPANSION_RESULTS.md](GUARD_EXPANSION_RESULTS.md) |
| (3) Judge, independent review and multi-agent debate select the same methods as the gate | [DEBATE_RESULTS.md](DEBATE_RESULTS.md), [SIX_PROJECT_PROPOSED_RESULTS.md](SIX_PROJECT_PROPOSED_RESULTS.md) |
| (3) Gate over three reader samples: 79.5% F1, every fixed revision flagged | Reproduced in this repository: `python3 -m cwe22 agree --run 261021g` (report Table 2) |
