# Agreement guard under hint relaxation: vulnerable and fixed revisions

Run `261021g`, scored 2026-10-30T02:12:49+00:00. Dataset commit `afe0ebd0adc237abb46255f9cd479b1d71819136`.
Tai-e flows and hinted-LLM answers from run `261020h`; vanilla readers from run `261021b`.
Models: qwen = `qwen/qwen3-coder-30b-a3b-instruct`, deepseek = `deepseek/deepseek-v4-pro`.

**Agreement guard** (JETA stages 1-2): set aside Tai-e flows into a sink protected by a checked
guard contract; then report the locations that Tai-e and at least one independent vanilla reader
(Qwen, DeepSeek) both report, or every Tai-e location when they share none. Sample k uses sample k
of both readers. Readers see the production fix file (oracle-selected input). Levels and Tai-e
configurations as in `261020h`.

Vulnerable revision: Detected = K > 0, FDR = 1 − K/N, F1 = 2K/(N+K) over `(simple class, method)`
locations. Fixed revision: **Flagged** = the patched fix method is still reported (a false alarm);
**Pair-correct** = reported on the vulnerable revision and not on the fixed one. Counts are projects
(/6) per sample. Fix-location proxies, not verified vulnerability labels. A failed input reports
nothing.

## Guard contracts

Checkers run on production files that allocate a `FileOutputStream`. *path*: `startsWith` guards
(refuted = String prefix without a directory boundary). *canonical*: `FileOutputStream` sinks.

| Project | Revision | path: refuted / unknown / supported | canonical: supported / sinks | Protected sinks |
| --- | --- | ---: | ---: | --- |
| zip4j | vulnerable | 0 / 0 / 0 | 0 / 2 | – |
| zip4j | fixed | 0 / 0 / 0 | 0 / 2 | – |
| zt-zip | vulnerable | 2 / 3 / 0 | 0 / 14 | – |
| zt-zip | fixed | 6 / 3 / 0 | 0 / 14 | – |
| spark | vulnerable | 0 / 0 / 0 | 0 / 0 | – |
| spark | fixed | 0 / 0 / 0 | 0 / 0 | – |
| plexus-archiver | vulnerable | 0 / 1 / 0 | 0 / 9 | – |
| plexus-archiver | fixed | 1 / 1 / 0 | 0 / 9 | – |
| plexus-utils | vulnerable | 0 / 2 / 0 | 0 / 8 | – |
| plexus-utils | fixed | 1 / 2 / 0 | 0 / 8 | – |
| mpxj | vulnerable | 0 / 0 / 0 | 0 / 12 | – |
| mpxj | fixed | 0 / 1 / 0 | 1 / 12 | `InputStreamHelper.processZipStream` L148 (canonical) |

## Summary

Mean over samples, [min–max] when samples differ. Tai-e is deterministic.

| Level | Arm | Detected ↑ | Macro FDR ↓ | Macro F1 ↑ | Fixed: flagged ↓ | Pair-correct ↑ |
| --- | --- | --- | ---: | ---: | --- | --- |
| – | Vanilla Qwen | 4/6, 4/6, 4/6 | 38.52% [26.67%–50.00%] | 0.6074 [0.5556–0.6333] | 5/6, 4/6, 4/6 | 0/6, 1/6, 1/6 |
| – | Vanilla Deepseek | 4/6, 5/6, 5/6 | 25.00% [16.67%–41.67%] | 0.7000 [0.6111–0.7444] | 4/6, 4/6, 4/6 | 1/6, 1/6, 1/6 |
| HINTED | Tai-e | 6/6 | 85.50% | 0.2439 | 6/6 | 0/6 |
| HINTED | Hinted Qwen | 4/6, 4/6, 5/6 | 27.78% [16.67%–33.33%] | 0.7222 [0.6667–0.8333] | 5/6, 6/6, 6/6 | 0/6, 0/6, 0/6 |
| HINTED | Hinted Deepseek | 6/6, 5/6, 6/6 | 30.56% [25.00%–41.67%] | 0.7778 [0.6667–0.8333] | 4/6, 4/6, 4/6 | 2/6, 1/6, 2/6 |
| HINTED | **Agreement guard** | 6/6, 6/6, 6/6 | 27.35% [19.44%–43.16%] | 0.7950 [0.6627–0.8611] | 6/6, 6/6, 6/6 | 0/6, 0/6, 0/6 |
| H1 | Tai-e | 5/6 | 97.12% | 0.0557 | 5/6 | 0/6 |
| H1 | Hinted Qwen | 5/6, 5/6, 5/6 | 19.44% [16.67%–25.00%] | 0.8148 [0.7778–0.8333] | 5/6, 5/6, 5/6 | 0/6, 0/6, 0/6 |
| H1 | Hinted Deepseek | 4/6, 5/6, 4/6 | 7.50% [0.00%–12.50%] | 0.6852 [0.6111–0.7778] | 3/6, 4/6, 4/6 | 2/6, 1/6, 1/6 |
| H1 | **Agreement guard** | 5/6, 5/6, 5/6 | 40.90% [32.76%–57.18%] | 0.6074 [0.4667–0.6778] | 5/6, 5/6, 5/6 | 0/6, 0/6, 0/6 |
| H2A | Tai-e | 6/6 | 96.80% | 0.0619 | 6/6 | 0/6 |
| H2A | Hinted Qwen | 4/6, 5/6, 5/6 | 27.78% [16.67%–41.67%] | 0.7407 [0.6111–0.8333] | 5/6, 5/6, 5/6 | 0/6, 0/6, 0/6 |
| H2A | Hinted Deepseek | 2/6, 5/6, 4/6 | 7.50% [0.00%–12.50%] | 0.5741 [0.3333–0.7778] | 3/6, 3/6, 2/6 | 1/6, 3/6, 3/6 |
| H2A | **Agreement guard** | 5/6, 6/6, 6/6 | 32.78% [24.44%–49.44%] | 0.7145 [0.5663–0.7885] | 6/6, 6/6, 6/6 | 0/6, 0/6, 0/6 |
| H2B | Tai-e [Qwen selection] | 6/6 | 96.78% | 0.0623 | 6/6 | 0/6 |
| H2B | Tai-e [Deepseek selection] | 6/6 | 96.76% | 0.0627 | 6/6 | 0/6 |
| H2B | Hinted Qwen | 5/6, 5/6, 5/6 | 16.67% | 0.8333 | 5/6, 5/6, 5/6 | 0/6, 0/6, 0/6 |
| H2B | Hinted Deepseek | 3/6, 2/6, 4/6 | 19.44% [0.00%–33.33%] | 0.4444 [0.2778–0.6667] | 1/6, 3/6, 5/6 | 2/6, 1/6, 0/6 |
| H2B | **Agreement guard [Qwen selection]** | 5/6, 6/6, 6/6 | 32.78% [24.44%–49.44%] | 0.7145 [0.5663–0.7885] | 6/6, 6/6, 6/6 | 0/6, 0/6, 0/6 |
| H2B | **Agreement guard [Deepseek selection]** | 6/6, 6/6, 6/6 | 32.57% [24.43%–48.87%] | 0.7184 [0.5774–0.7889] | 6/6, 6/6, 6/6 | 0/6, 0/6, 0/6 |
| E | Tai-e [Qwen driver + selection] | 5/6 | 97.35% | 0.0512 | 5/6 | 0/6 |
| E | Tai-e [Deepseek driver + selection] | 1/6 | 98.44% | 0.0101 | 1/6 | 0/6 |
| E | Hinted Qwen | 5/6, 5/6, 5/6 | 25.00% [16.67%–33.33%] | 0.7778 [0.7222–0.8333] | 4/6, 5/6, 5/6 | 1/6, 0/6, 0/6 |
| E | Hinted Deepseek | 1/6, 1/6, 1/6 | 16.67% [0.00%–50.00%] | 0.1481 [0.1111–0.1667] | 1/6, 1/6, 0/6 | 0/6, 0/6, 1/6 |
| E | **Agreement guard [Qwen driver + selection]** | 4/6, 5/6, 5/6 | 49.21% [40.71%–66.23%] | 0.5520 [0.3974–0.6293] | 5/6, 5/6, 5/6 | 0/6, 0/6, 0/6 |
| E | **Agreement guard [Deepseek driver + selection]** | 1/6, 1/6, 1/6 | 58.33% [50.00%–75.00%] | 0.1481 [0.1111–0.1667] | 1/6, 1/6, 1/6 | 0/6, 0/6, 0/6 |

## Flows set aside by the guard

Tai-e flows removed by stage 1 (vulnerable / fixed, summed over projects).

| Level | Configuration | Flows set aside | Revisions affected |
| --- | --- | --- | --- |
| HINTED | manual | 0 / 12 of 91 / 94 | mpxj fixed: 12 of 24 |
| H1 | h1 | 0 / 12 of 1775 / 1799 | mpxj fixed: 12 of 288 |
| H2A | h2a | 0 / 13 of 2671 / 2773 | mpxj fixed: 13 of 312 |
| H2B | h2b-qwen | 0 / 12 of 2532 / 2586 | mpxj fixed: 12 of 288 |
| H2B | h2b-deepseek | 0 / 12 of 2225 / 2279 | mpxj fixed: 12 of 288 |
| E | e-qwen-h2b | 0 / 0 of 11826 / 11887 | – |
| E | e-deepseek-h2b | 0 / 0 of 1152 / 1152 | – |

Failed baseline inputs, counted as empty output (the agreement arms read the same failed
readers and Tai-e runs):

- – / Vanilla Deepseek s2 / mpxj fixed: Incomplete response: finish_reason=length
- – / Vanilla Deepseek s3 / mpxj fixed: Incomplete response: finish_reason=length
- H1 / Hinted Deepseek s1 / zip4j vulnerable: Incomplete response: finish_reason=length
- H1 / Hinted Deepseek s1 / zt-zip fixed: Incomplete response: finish_reason=length
- H1 / Hinted Deepseek s1 / spark vulnerable: Incomplete response: finish_reason=length
- H1 / Hinted Deepseek s2 / zip4j fixed: Incomplete response: finish_reason=length
- H1 / Hinted Deepseek s2 / spark vulnerable: Incomplete response: finish_reason=length
- H1 / Hinted Deepseek s2 / spark fixed: Incomplete response: finish_reason=length
- H1 / Hinted Deepseek s3 / zip4j vulnerable: Incomplete response: finish_reason=length
- H1 / Hinted Deepseek s3 / spark vulnerable: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s1 / zip4j vulnerable: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s1 / zip4j fixed: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s1 / zt-zip vulnerable: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s1 / zt-zip fixed: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s1 / plexus-utils vulnerable: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s2 / zip4j vulnerable: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s2 / zt-zip fixed: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s2 / mpxj fixed: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s3 / zip4j vulnerable: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s3 / zt-zip fixed: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s3 / plexus-utils vulnerable: Incomplete response: finish_reason=length
- H2A / Hinted Deepseek s3 / plexus-utils fixed: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s1 / zip4j vulnerable: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s1 / zip4j fixed: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s1 / zt-zip vulnerable: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s1 / zt-zip fixed: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s1 / plexus-utils vulnerable: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s1 / plexus-utils fixed: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s2 / zip4j vulnerable: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s2 / zt-zip vulnerable: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s2 / zt-zip fixed: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s2 / plexus-archiver vulnerable: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s2 / plexus-utils vulnerable: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s2 / plexus-utils fixed: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s3 / zip4j vulnerable: Incomplete response: finish_reason=length
- H2B / Hinted Deepseek s3 / zip4j fixed: Incomplete response: finish_reason=length
- E / Tai-e [Deepseek driver + selection] / zip4j vulnerable: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/zip4j-vulnerable)
- E / Tai-e [Deepseek driver + selection] / zip4j fixed: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/zip4j-fixed)
- E / Tai-e [Deepseek driver + selection] / zt-zip vulnerable: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/zt-zip-vulnerable)
- E / Tai-e [Deepseek driver + selection] / zt-zip fixed: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/zt-zip-fixed)
- E / Tai-e [Deepseek driver + selection] / plexus-archiver vulnerable: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/plexus-archiver-vulnerable)
- E / Tai-e [Deepseek driver + selection] / plexus-archiver fixed: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/plexus-archiver-fixed)
- E / Tai-e [Deepseek driver + selection] / mpxj vulnerable: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/mpxj-vulnerable)
- E / Tai-e [Deepseek driver + selection] / mpxj fixed: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/mpxj-fixed)
- E / Hinted Deepseek s1 / zip4j vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s1 / zip4j fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s1 / zt-zip vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s1 / zt-zip fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s1 / plexus-archiver vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s1 / plexus-archiver fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s1 / mpxj vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s1 / mpxj fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s2 / zip4j vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s2 / zip4j fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s2 / zt-zip vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s2 / zt-zip fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s2 / plexus-archiver vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s2 / plexus-archiver fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s2 / mpxj vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s2 / mpxj fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s3 / zip4j vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s3 / zip4j fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s3 / zt-zip vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s3 / zt-zip fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s3 / spark fixed: Incomplete response: finish_reason=length
- E / Hinted Deepseek s3 / plexus-archiver vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s3 / plexus-archiver fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s3 / plexus-utils fixed: Incomplete response: finish_reason=length
- E / Hinted Deepseek s3 / mpxj vulnerable: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)
- E / Hinted Deepseek s3 / mpxj fixed: No Tai-e configuration for e-deepseek-h2b (entry driver or policy missing)

## zip4j

Fix methods: `Unzip.initExtractFile`

| Level | Arm | Detected | N per sample | F1 ↑ | Fixed N per sample | Flagged ↓ | Pair-correct ↑ |
| --- | --- | :---: | --- | ---: | --- | :---: | :---: |
| – | Vanilla Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| – | Vanilla Deepseek | 3/3 | 2, 2, 2 | 0.6667 | 1, 1, 1 | 3/3 | 0/3 |
| HINTED | Tai-e | 1/1 | 7 | 0.2500 | 7 | 1/1 | 0/1 |
| HINTED | Hinted Qwen | 1/3 | 1, 1, 1 | 0.3333 [0.0000–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| HINTED | Hinted Deepseek | 2/3 | 2, 2, 2 | 0.4444 [0.0000–0.6667] | 0, 0, 0 | 0/3 | 2/3 |
| HINTED | Agreement guard | 3/3 | 2, 2, 2 | 0.6667 | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Tai-e | 0/1 | 33 | 0.0000 | 33 | 0/1 | 0/1 |
| H1 | Hinted Qwen | 3/3 | 1, 2, 1 | 0.8889 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Hinted Deepseek | 1/3 (3 failed) | 0, 1, 0 | 0.3333 [0.0000–1.0000] | 0, 0, 0 | 0/3 | 1/3 |
| H1 | Agreement guard | 0/3 | 33, 33, 33 | 0.0000 | 33, 33, 33 | 0/3 | 0/3 |
| H2A | Tai-e | 1/1 | 42 | 0.0465 | 42 | 1/1 | 0/1 |
| H2A | Hinted Qwen | 3/3 | 2, 2, 1 | 0.7778 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H2A | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 0, 1, 1 | 2/3 | 0/3 |
| H2A | Agreement guard | 3/3 | 2, 2, 2 | 0.6667 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Tai-e [Qwen selection] | 1/1 | 40 | 0.0488 | 40 | 1/1 | 0/1 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 40 | 0.0488 | 40 | 1/1 | 0/1 |
| H2B | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 0, 1, 0 | 1/3 | 0/3 |
| H2B | Agreement guard [Qwen selection] | 3/3 | 2, 2, 2 | 0.6667 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Agreement guard [Deepseek selection] | 3/3 | 2, 2, 2 | 0.6667 | 1, 1, 1 | 3/3 | 0/3 |
| E | Tai-e [Qwen driver + selection] | 1/1 | 60 | 0.0328 | 60 | 1/1 | 0/1 |
| E | Tai-e [Deepseek driver + selection] | 0/1 (1 failed) | 0 | 0.0000 | 0 | 0/1 | 0/1 |
| E | Hinted Qwen | 3/3 | 1, 2, 1 | 0.8889 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| E | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 0, 0, 0 | 0/3 | 0/3 |
| E | Agreement guard [Qwen driver + selection] | 3/3 | 2, 2, 2 | 0.6667 | 1, 1, 1 | 3/3 | 0/3 |
| E | Agreement guard [Deepseek driver + selection] | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 0, 0, 0 | 0/3 | 0/3 |

## zt-zip

Fix methods: `Unpacker.process`, `Unwraper.getRootName`, `Unwraper.process`

| Level | Arm | Detected | N per sample | F1 ↑ | Fixed N per sample | Flagged ↓ | Pair-correct ↑ |
| --- | --- | :---: | --- | ---: | --- | :---: | :---: |
| – | Vanilla Qwen | 2/3 | 3, 3, 3 | 0.5333 [0.0000–0.8000] | 5, 5, 5 | 0/3 | 2/3 |
| – | Vanilla Deepseek | 2/3 | 1, 3, 3 | 0.5333 [0.0000–0.8000] | 3, 3, 3 | 3/3 | 0/3 |
| HINTED | Tai-e | 1/1 | 13 | 0.1429 | 13 | 1/1 | 0/1 |
| HINTED | Hinted Qwen | 0/3 | 1, 1, 1 | 0.0000 | 1, 1, 1 | 2/3 | 0/3 |
| HINTED | Hinted Deepseek | 3/3 | 2, 2, 2 | 0.6667 | 2, 1, 2 | 3/3 | 0/3 |
| HINTED | Agreement guard | 3/3 | 13, 1, 1 | 0.7143 [0.1429–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Tai-e | 1/1 | 29 | 0.0667 | 29 | 1/1 | 0/1 |
| H1 | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Hinted Deepseek | 3/3 (1 failed) | 1, 2, 1 | 0.8889 [0.6667–1.0000] | 0, 1, 1 | 2/3 | 1/3 |
| H1 | Agreement guard | 3/3 | 29, 1, 1 | 0.6889 [0.0667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H2A | Tai-e | 1/1 | 30 | 0.0645 | 30 | 1/1 | 0/1 |
| H2A | Hinted Qwen | 2/3 | 1, 1, 1 | 0.6667 [0.0000–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H2A | Hinted Deepseek | 2/3 (3 failed) | 0, 1, 1 | 0.6667 [0.0000–1.0000] | 0, 0, 0 | 0/3 | 2/3 |
| H2A | Agreement guard | 3/3 | 30, 1, 1 | 0.6882 [0.0645–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Tai-e [Qwen selection] | 1/1 | 30 | 0.0645 | 30 | 1/1 | 0/1 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 30 | 0.0645 | 30 | 1/1 | 0/1 |
| H2B | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Hinted Deepseek | 1/3 (2 failed) | 0, 0, 1 | 0.3333 [0.0000–1.0000] | 0, 0, 1 | 1/3 | 0/3 |
| H2B | Agreement guard [Qwen selection] | 3/3 | 30, 1, 1 | 0.6882 [0.0645–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Agreement guard [Deepseek selection] | 3/3 | 30, 1, 1 | 0.6882 [0.0645–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| E | Tai-e [Qwen driver + selection] | 1/1 | 38 | 0.0513 | 38 | 1/1 | 0/1 |
| E | Tai-e [Deepseek driver + selection] | 0/1 (1 failed) | 0 | 0.0000 | 0 | 0/1 | 0/1 |
| E | Hinted Qwen | 0/3 | 1, 1, 1 | 0.0000 | 1, 1, 1 | 0/3 | 0/3 |
| E | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 0, 0, 0 | 0/3 | 0/3 |
| E | Agreement guard [Qwen driver + selection] | 3/3 | 38, 1, 1 | 0.6838 [0.0513–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| E | Agreement guard [Deepseek driver + selection] | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 0, 0, 0 | 0/3 | 0/3 |

## spark

Fix methods: `ClassPathResource.ClassPathResource`, `ClassPathResource.equals`, `ClassPathResource.exists`, `ClassPathResource.getInputStream`, `ClassPathResource.getPath`, `ClassPathResource.getURL`

| Level | Arm | Detected | N per sample | F1 ↑ | Fixed N per sample | Flagged ↓ | Pair-correct ↑ |
| --- | --- | :---: | --- | ---: | --- | :---: | :---: |
| – | Vanilla Qwen | 0/3 | 1, 0, 1 | 0.0000 | 1, 1, 1 | 1/3 | 0/3 |
| – | Vanilla Deepseek | 0/3 | 1, 0, 0 | 0.0000 | 0, 0, 0 | 0/3 | 0/3 |
| HINTED | Tai-e | 1/1 | 3 | 0.5000 | 3 | 1/1 | 0/1 |
| HINTED | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| HINTED | Hinted Deepseek | 3/3 | 2, 2, 2 | 1.0000 | 2, 2, 1 | 3/3 | 0/3 |
| HINTED | Agreement guard | 3/3 | 3, 3, 3 | 0.5000 | 3, 3, 3 | 3/3 | 0/3 |
| H1 | Tai-e | 1/1 | 29 | 0.0667 | 29 | 1/1 | 0/1 |
| H1 | Hinted Qwen | 0/3 | 1, 1, 1 | 0.0000 | 1, 1, 1 | 0/3 | 0/3 |
| H1 | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 2, 0, 2 | 2/3 | 0/3 |
| H1 | Agreement guard | 3/3 | 29, 29, 29 | 0.0667 | 29, 29, 29 | 3/3 | 0/3 |
| H2A | Tai-e | 1/1 | 30 | 0.0645 | 30 | 1/1 | 0/1 |
| H2A | Hinted Qwen | 0/3 | 1, 1, 1 | 0.0000 | 1, 1, 1 | 0/3 | 0/3 |
| H2A | Hinted Deepseek | 2/3 | 0, 2, 2 | 0.4444 [0.0000–0.6667] | 2, 0, 0 | 1/3 | 2/3 |
| H2A | Agreement guard | 2/3 | 1, 30, 30 | 0.0430 [0.0000–0.0645] | 30, 30, 30 | 3/3 | 0/3 |
| H2B | Tai-e [Qwen selection] | 1/1 | 30 | 0.0645 | 30 | 1/1 | 0/1 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 29 | 0.0667 | 29 | 1/1 | 0/1 |
| H2B | Hinted Qwen | 0/3 | 1, 1, 1 | 0.0000 | 1, 1, 1 | 0/3 | 0/3 |
| H2B | Hinted Deepseek | 2/3 | 2, 1, 0 | 0.5556 [0.0000–1.0000] | 0, 2, 1 | 2/3 | 1/3 |
| H2B | Agreement guard [Qwen selection] | 2/3 | 1, 30, 30 | 0.0430 [0.0000–0.0645] | 30, 30, 30 | 3/3 | 0/3 |
| H2B | Agreement guard [Deepseek selection] | 3/3 | 29, 29, 29 | 0.0667 | 29, 29, 29 | 3/3 | 0/3 |
| E | Tai-e [Qwen driver + selection] | 1/1 | 52 | 0.1091 | 52 | 1/1 | 0/1 |
| E | Tai-e [Deepseek driver + selection] | 0/1 | 44 | 0.0000 | 44 | 0/1 | 0/1 |
| E | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| E | Hinted Deepseek | 0/3 (1 failed) | 0, 0, 0 | 0.0000 | 0, 0, 0 | 0/3 | 0/3 |
| E | Agreement guard [Qwen driver + selection] | 2/3 | 1, 52, 52 | 0.0727 [0.0000–0.1091] | 52, 52, 52 | 3/3 | 0/3 |
| E | Agreement guard [Deepseek driver + selection] | 0/3 | 44, 44, 44 | 0.0000 | 44, 44, 44 | 0/3 | 0/3 |

## plexus-archiver

Fix methods: `AbstractUnArchiver.extractFile`

| Level | Arm | Detected | N per sample | F1 ↑ | Fixed N per sample | Flagged ↓ | Pair-correct ↑ |
| --- | --- | :---: | --- | ---: | --- | :---: | :---: |
| – | Vanilla Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| – | Vanilla Deepseek | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| HINTED | Tai-e | 1/1 | 7 | 0.2500 | 7 | 1/1 | 0/1 |
| HINTED | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| HINTED | Hinted Deepseek | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| HINTED | Agreement guard | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Tai-e | 1/1 | 32 | 0.0606 | 32 | 1/1 | 0/1 |
| H1 | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Hinted Deepseek | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Agreement guard | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2A | Tai-e | 1/1 | 35 | 0.0556 | 35 | 1/1 | 0/1 |
| H2A | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2A | Hinted Deepseek | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2A | Agreement guard | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Tai-e [Qwen selection] | 1/1 | 35 | 0.0556 | 35 | 1/1 | 0/1 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 35 | 0.0556 | 35 | 1/1 | 0/1 |
| H2B | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Hinted Deepseek | 2/3 (1 failed) | 1, 0, 1 | 0.6667 [0.0000–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Agreement guard [Qwen selection] | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Agreement guard [Deepseek selection] | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| E | Tai-e [Qwen driver + selection] | 1/1 | 38 | 0.0513 | 38 | 1/1 | 0/1 |
| E | Tai-e [Deepseek driver + selection] | 0/1 (1 failed) | 0 | 0.0000 | 0 | 0/1 | 0/1 |
| E | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| E | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 0, 0, 0 | 0/3 | 0/3 |
| E | Agreement guard [Qwen driver + selection] | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| E | Agreement guard [Deepseek driver + selection] | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 0, 0, 0 | 0/3 | 0/3 |

## plexus-utils

Fix methods: `Expand.extractFile`

| Level | Arm | Detected | N per sample | F1 ↑ | Fixed N per sample | Flagged ↓ | Pair-correct ↑ |
| --- | --- | :---: | --- | ---: | --- | :---: | :---: |
| – | Vanilla Qwen | 3/3 | 2, 1, 1 | 0.8889 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| – | Vanilla Deepseek | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| HINTED | Tai-e | 1/1 | 12 | 0.1538 | 12 | 1/1 | 0/1 |
| HINTED | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| HINTED | Hinted Deepseek | 3/3 | 1, 2, 1 | 0.8889 [0.6667–1.0000] | 2, 1, 1 | 3/3 | 0/3 |
| HINTED | Agreement guard | 3/3 | 2, 1, 1 | 0.8889 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Tai-e | 1/1 | 28 | 0.0690 | 28 | 1/1 | 0/1 |
| H1 | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Hinted Deepseek | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Agreement guard | 3/3 | 2, 1, 1 | 0.8889 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H2A | Tai-e | 1/1 | 28 | 0.0690 | 28 | 1/1 | 0/1 |
| H2A | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2A | Hinted Deepseek | 1/3 (2 failed) | 0, 1, 0 | 0.3333 [0.0000–1.0000] | 1, 1, 0 | 2/3 | 0/3 |
| H2A | Agreement guard | 3/3 | 2, 1, 1 | 0.8889 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Tai-e [Qwen selection] | 1/1 | 28 | 0.0690 | 28 | 1/1 | 0/1 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 28 | 0.0690 | 28 | 1/1 | 0/1 |
| H2B | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Hinted Deepseek | 1/3 (2 failed) | 0, 0, 1 | 0.3333 [0.0000–1.0000] | 0, 0, 1 | 1/3 | 0/3 |
| H2B | Agreement guard [Qwen selection] | 3/3 | 2, 1, 1 | 0.8889 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Agreement guard [Deepseek selection] | 3/3 | 2, 1, 1 | 0.8889 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| E | Tai-e [Qwen driver + selection] | 1/1 | 31 | 0.0625 | 31 | 1/1 | 0/1 |
| E | Tai-e [Deepseek driver + selection] | 1/1 | 32 | 0.0606 | 32 | 1/1 | 0/1 |
| E | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| E | Hinted Deepseek | 3/3 (1 failed) | 1, 1, 2 | 0.8889 [0.6667–1.0000] | 1, 1, 0 | 2/3 | 1/3 |
| E | Agreement guard [Qwen driver + selection] | 3/3 | 2, 1, 1 | 0.8889 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |
| E | Agreement guard [Deepseek driver + selection] | 3/3 | 2, 1, 1 | 0.8889 [0.6667–1.0000] | 1, 1, 1 | 3/3 | 0/3 |

## mpxj

Fix methods: `InputStreamHelper.processZipStream`

| Level | Arm | Detected | N per sample | F1 ↑ | Fixed N per sample | Flagged ↓ | Pair-correct ↑ |
| --- | --- | :---: | --- | ---: | --- | :---: | :---: |
| – | Vanilla Qwen | 1/3 | 2, 1, 1 | 0.2222 [0.0000–0.6667] | 1, 1, 1 | 3/3 | 0/3 |
| – | Vanilla Deepseek | 3/3 (2 failed) | 1, 1, 1 | 1.0000 | 0, 0, 0 | 0/3 | 3/3 |
| HINTED | Tai-e | 1/1 | 11 | 0.1667 | 11 | 1/1 | 0/1 |
| HINTED | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| HINTED | Hinted Deepseek | 3/3 | 2, 2, 2 | 0.6667 | 0, 0, 0 | 0/3 | 3/3 |
| HINTED | Agreement guard | 3/3 (2 failed) | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Tai-e | 1/1 | 27 | 0.0714 | 27 | 1/1 | 0/1 |
| H1 | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H1 | Hinted Deepseek | 3/3 | 1, 1, 2 | 0.8889 [0.6667–1.0000] | 0, 1, 0 | 1/3 | 2/3 |
| H1 | Agreement guard | 3/3 (2 failed) | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2A | Tai-e | 1/1 | 27 | 0.0714 | 28 | 1/1 | 0/1 |
| H2A | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2A | Hinted Deepseek | 3/3 (1 failed) | 1, 1, 1 | 1.0000 | 0, 0, 0 | 0/3 | 3/3 |
| H2A | Agreement guard | 3/3 (2 failed) | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Tai-e [Qwen selection] | 1/1 | 27 | 0.0714 | 27 | 1/1 | 0/1 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 27 | 0.0714 | 27 | 1/1 | 0/1 |
| H2B | Hinted Qwen | 3/3 | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Hinted Deepseek | 3/3 | 2, 2, 1 | 0.7778 [0.6667–1.0000] | 0, 0, 1 | 1/3 | 2/3 |
| H2B | Agreement guard [Qwen selection] | 3/3 (2 failed) | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| H2B | Agreement guard [Deepseek selection] | 3/3 (2 failed) | 1, 1, 1 | 1.0000 | 1, 1, 1 | 3/3 | 0/3 |
| E | Tai-e [Qwen driver + selection] | 0/1 | 116 | 0.0000 | 116 | 0/1 | 0/1 |
| E | Tai-e [Deepseek driver + selection] | 0/1 (1 failed) | 0 | 0.0000 | 0 | 0/1 | 0/1 |
| E | Hinted Qwen | 3/3 | 2, 2, 1 | 0.7778 [0.6667–1.0000] | 1, 2, 2 | 2/3 | 1/3 |
| E | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 0, 0, 0 | 0/3 | 0/3 |
| E | Agreement guard [Qwen driver + selection] | 0/3 (2 failed) | 116, 116, 116 | 0.0000 | 116, 116, 116 | 0/3 | 0/3 |
| E | Agreement guard [Deepseek driver + selection] | 0/3 (3 failed) | 0, 0, 0 | 0.0000 | 0, 0, 0 | 0/3 | 0/3 |
