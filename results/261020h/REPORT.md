# Hint relaxation: Tai-e and hinted LLM

Run `261020h`, scored 2026-10-30T02:12:48+00:00. Dataset commit `afe0ebd0adc237abb46255f9cd479b1d71819136`.
Models: qwen = `qwen/qwen3-coder-30b-a3b-instruct`, deepseek = `deepseek/deepseek-v4-pro`.
Hinted LLM: 3 samples per cell; max_tokens per request: deepseek/deepseek-v4-pro 8000, qwen/qwen3-coder-30b-a3b-instruct 8000. Tai-e is deterministic (1 run).

Levels: **Hinted (manual policy)**; **H1 kit only**; **H2a kit + all candidates**; **H2b kit + LLM-selected sources**; **E LLM entry + kit + LLM-selected sources**.
The first level's hinted LLM is the prose-hinted baseline of run `261021b` (manual policy in words, fix
file and sink files). From H1 on, the hinted LLM sees exactly the entry program and policy files
Tai-e receives, plus the production fix file. H2b and E are per model: each model
selects its own sources (and writes its own driver) and is hinted with that configuration.

Unit: `(simple class, method)` on the vulnerable revision; Detected = K > 0, FDR = 1 − K/N,
F1 = 2K/(N+K). Fix-location proxies, not verified vulnerability labels.

## Summary

Mean over samples, [min–max] when samples differ.

| Level | Arm | Detected | Macro FDR ↓ | Macro F1 ↑ |
| --- | --- | --- | ---: | ---: |
| HINTED | Tai-e | 6/6 | 85.50% | 0.2439 |
| HINTED | Hinted Qwen | 4/6, 4/6, 5/6 | 27.78% [16.67%–33.33%] | 0.7222 [0.6667–0.8333] |
| HINTED | Hinted Deepseek | 6/6, 5/6, 6/6 | 30.56% [25.00%–41.67%] | 0.7778 [0.6667–0.8333] |
| H1 | Tai-e | 5/6 | 97.12% | 0.0557 |
| H1 | Hinted Qwen | 5/6, 5/6, 5/6 | 19.44% [16.67%–25.00%] | 0.8148 [0.7778–0.8333] |
| H1 | Hinted Deepseek | 4/6, 5/6, 4/6 | 7.50% [0.00%–12.50%] | 0.6852 [0.6111–0.7778] |
| H2A | Tai-e | 6/6 | 96.80% | 0.0619 |
| H2A | Hinted Qwen | 4/6, 5/6, 5/6 | 27.78% [16.67%–41.67%] | 0.7407 [0.6111–0.8333] |
| H2A | Hinted Deepseek | 2/6, 5/6, 4/6 | 7.50% [0.00%–12.50%] | 0.5741 [0.3333–0.7778] |
| H2B | Tai-e [Qwen selection] | 6/6 | 96.78% | 0.0623 |
| H2B | Tai-e [Deepseek selection] | 6/6 | 96.76% | 0.0627 |
| H2B | Hinted Qwen | 5/6, 5/6, 5/6 | 16.67% | 0.8333 |
| H2B | Hinted Deepseek | 3/6, 2/6, 4/6 | 19.44% [0.00%–33.33%] | 0.4444 [0.2778–0.6667] |
| E | Tai-e [Qwen driver + selection] | 5/6 | 97.35% | 0.0512 |
| E | Tai-e [Deepseek driver + selection] | 1/6 | 98.44% | 0.0101 |
| E | Hinted Qwen | 5/6, 5/6, 5/6 | 25.00% [16.67%–33.33%] | 0.7778 [0.7222–0.8333] |
| E | Hinted Deepseek | 1/6, 1/6, 1/6 | 16.67% [0.00%–50.00%] | 0.1481 [0.1111–0.1667] |

Failures count as empty output (undetected, F1 0, FDR undefined):

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
- E / Tai-e [Deepseek driver + selection] s1 / zip4j vulnerable: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/zip4j-vulnerable)
- E / Tai-e [Deepseek driver + selection] s1 / zip4j fixed: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/zip4j-fixed)
- E / Tai-e [Deepseek driver + selection] s1 / zt-zip vulnerable: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/zt-zip-vulnerable)
- E / Tai-e [Deepseek driver + selection] s1 / zt-zip fixed: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/zt-zip-fixed)
- E / Tai-e [Deepseek driver + selection] s1 / plexus-archiver vulnerable: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/plexus-archiver-vulnerable)
- E / Tai-e [Deepseek driver + selection] s1 / plexus-archiver fixed: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/plexus-archiver-fixed)
- E / Tai-e [Deepseek driver + selection] s1 / mpxj vulnerable: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/mpxj-vulnerable)
- E / Tai-e [Deepseek driver + selection] s1 / mpxj fixed: RuntimeError: No Tai-e configuration (entry driver or policy missing) (logs: /Users/ileening/cs6215-work/raw/261020h/taie/e-deepseek-h2b/mpxj-fixed)
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

## Source selection

| Selector | Project | Non-kit candidates | Reaching a sink (H2a) | Kept | Errors |
| --- | --- | ---: | ---: | ---: | ---: |
| deepseek | zip4j | 5 | 5 | 2 | 0 |
| deepseek | zt-zip | 2 | 1 | 1 | 0 |
| deepseek | spark | 2 | 2 | 0 | 0 |
| deepseek | plexus-archiver | 6 | 6 | 3 | 0 |
| deepseek | plexus-utils | 1 | 0 | 0 | 0 |
| deepseek | mpxj | 2 | 1 | 0 | 0 |
| e-deepseek | spark | 7 | 4 | 4 | 0 |
| e-deepseek | plexus-utils | 2 | 1 | 0 | 0 |
| e-qwen | zip4j | 11 | 8 | 5 | 0 |
| e-qwen | zt-zip | 5 | 2 | 2 | 0 |
| e-qwen | spark | 19 | 11 | 11 | 1 |
| e-qwen | plexus-archiver | 8 | 8 | 8 | 3 |
| e-qwen | plexus-utils | 2 | 1 | 0 | 0 |
| e-qwen | mpxj | 91 | 88 | 58 | 36 |
| qwen | zip4j | 5 | 5 | 3 | 0 |
| qwen | zt-zip | 2 | 1 | 1 | 0 |
| qwen | spark | 2 | 2 | 1 | 0 |
| qwen | plexus-archiver | 6 | 6 | 5 | 0 |
| qwen | plexus-utils | 1 | 0 | 0 | 0 |
| qwen | mpxj | 2 | 1 | 0 | 0 |

## LLM-written entry drivers

| Model / project | Status | Picked classes | Rounds |
| --- | --- | --- | ---: |
| deepseek/mpxj | failed: ValueError: Incomplete response: finish_reason=length | UniversalProjectReader, MPPReader, MPXReader, MSPDIReader, MSPDIWriter | 0 |
| deepseek/plexus-archiver | failed: ValueError: Incomplete response: finish_reason=length |  | 0 |
| deepseek/plexus-utils | compiled | FileUtils, DirectoryScanner, DirectoryWalker, Expand, NioFiles | 1 |
| deepseek/spark | compiled | Spark, StaticFilesConfiguration, ExternalResourceHandler, ExternalResource, AbstractFileResolvingResource | 1 |
| deepseek/zip4j | failed: ValueError: Incomplete response: finish_reason=length | ZipFile, ZipInputStream, ZipOutputStream | 0 |
| deepseek/zt-zip | failed: ValueError: Incomplete response: finish_reason=length |  | 0 |
| qwen/mpxj | compiled | ProjectReader, ProjectWriter, FileHelper, MPPReader, MPXReader | 3 |
| qwen/plexus-archiver | compiled | ArchiverManager, Archiver, UnArchiver, ZipUnArchiver, TarUnArchiver | 1 |
| qwen/plexus-utils | compiled | FileUtils, Expand, DirectoryScanner, AbstractScanner, InputStreamFacade | 1 |
| qwen/spark | compiled | Request, Response, StaticFilesConfiguration, ClassPathResourceHandler, ExternalResourceHandler | 1 |
| qwen/zip4j | compiled | ZipFile, ZipInputStream, ZipOutputStream, Unzip, Zip4jUtil | 2 |
| qwen/zt-zip | compiled | ZipUtil, Zips, ZipEntrySource, ByteSource, FileSource | 3 |

## zip4j

Fix methods: `Unzip.initExtractFile`

| Level | Arm | Detected | N per sample | FDR ↓ | F1 ↑ | Fixed-revision N |
| --- | --- | :---: | --- | ---: | ---: | --- |
| HINTED | Tai-e | 1/1 | 7 | 85.71% | 0.2500 | 7 |
| HINTED | Hinted Qwen | 1/3 | 1, 1, 1 | 66.67% [0.00%–100.00%] | 0.3333 [0.0000–1.0000] | 1, 1, 1 |
| HINTED | Hinted Deepseek | 2/3 | 2, 2, 2 | 66.67% [50.00%–100.00%] | 0.4444 [0.0000–0.6667] | 0, 0, 0 |
| H1 | Tai-e | 0/1 | 33 | 100.00% | 0.0000 | 33 |
| H1 | Hinted Qwen | 3/3 | 1, 2, 1 | 16.67% [0.00%–50.00%] | 0.8889 [0.6667–1.0000] | 1, 1, 1 |
| H1 | Hinted Deepseek | 1/3 (2 failed) | 0, 1, 0 | 0.00% | 0.3333 [0.0000–1.0000] | 0, 0, 0 |
| H2A | Tai-e | 1/1 | 42 | 97.62% | 0.0465 | 42 |
| H2A | Hinted Qwen | 3/3 | 2, 2, 1 | 33.33% [0.00%–50.00%] | 0.7778 [0.6667–1.0000] | 1, 1, 1 |
| H2A | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | n/a | 0.0000 | 0, 1, 1 |
| H2B | Tai-e [Qwen selection] | 1/1 | 40 | 97.50% | 0.0488 | 40 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 40 | 97.50% | 0.0488 | 40 |
| H2B | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2B | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | n/a | 0.0000 | 0, 1, 0 |
| E | Tai-e [Qwen driver + selection] | 1/1 | 60 | 98.33% | 0.0328 | 60 |
| E | Tai-e [Deepseek driver + selection] | 0/1 (1 failed) | 0 | n/a | 0.0000 | 0 |
| E | Hinted Qwen | 3/3 | 1, 2, 1 | 16.67% [0.00%–50.00%] | 0.8889 [0.6667–1.0000] | 1, 1, 1 |
| E | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | n/a | 0.0000 | 0, 0, 0 |

## zt-zip

Fix methods: `Unpacker.process`, `Unwraper.getRootName`, `Unwraper.process`

| Level | Arm | Detected | N per sample | FDR ↓ | F1 ↑ | Fixed-revision N |
| --- | --- | :---: | --- | ---: | ---: | --- |
| HINTED | Tai-e | 1/1 | 13 | 92.31% | 0.1429 | 13 |
| HINTED | Hinted Qwen | 0/3 | 1, 1, 1 | 100.00% | 0.0000 | 1, 1, 1 |
| HINTED | Hinted Deepseek | 3/3 | 2, 2, 2 | 50.00% | 0.6667 | 2, 1, 2 |
| H1 | Tai-e | 1/1 | 29 | 96.55% | 0.0667 | 29 |
| H1 | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H1 | Hinted Deepseek | 3/3 | 1, 2, 1 | 16.67% [0.00%–50.00%] | 0.8889 [0.6667–1.0000] | 0, 1, 1 |
| H2A | Tai-e | 1/1 | 30 | 96.67% | 0.0645 | 30 |
| H2A | Hinted Qwen | 2/3 | 1, 1, 1 | 33.33% [0.00%–100.00%] | 0.6667 [0.0000–1.0000] | 1, 1, 1 |
| H2A | Hinted Deepseek | 2/3 (1 failed) | 0, 1, 1 | 0.00% | 0.6667 [0.0000–1.0000] | 0, 0, 0 |
| H2B | Tai-e [Qwen selection] | 1/1 | 30 | 96.67% | 0.0645 | 30 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 30 | 96.67% | 0.0645 | 30 |
| H2B | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2B | Hinted Deepseek | 1/3 (2 failed) | 0, 0, 1 | 0.00% | 0.3333 [0.0000–1.0000] | 0, 0, 1 |
| E | Tai-e [Qwen driver + selection] | 1/1 | 38 | 97.37% | 0.0513 | 38 |
| E | Tai-e [Deepseek driver + selection] | 0/1 (1 failed) | 0 | n/a | 0.0000 | 0 |
| E | Hinted Qwen | 0/3 | 1, 1, 1 | 100.00% | 0.0000 | 1, 1, 1 |
| E | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | n/a | 0.0000 | 0, 0, 0 |

## spark

Fix methods: `ClassPathResource.ClassPathResource`, `ClassPathResource.equals`, `ClassPathResource.exists`, `ClassPathResource.getInputStream`, `ClassPathResource.getPath`, `ClassPathResource.getURL`

| Level | Arm | Detected | N per sample | FDR ↓ | F1 ↑ | Fixed-revision N |
| --- | --- | :---: | --- | ---: | ---: | --- |
| HINTED | Tai-e | 1/1 | 3 | 66.67% | 0.5000 | 3 |
| HINTED | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| HINTED | Hinted Deepseek | 3/3 | 2, 2, 2 | 0.00% | 1.0000 | 2, 2, 1 |
| H1 | Tai-e | 1/1 | 29 | 96.55% | 0.0667 | 29 |
| H1 | Hinted Qwen | 0/3 | 1, 1, 1 | 100.00% | 0.0000 | 1, 1, 1 |
| H1 | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | n/a | 0.0000 | 2, 0, 2 |
| H2A | Tai-e | 1/1 | 30 | 96.67% | 0.0645 | 30 |
| H2A | Hinted Qwen | 0/3 | 1, 1, 1 | 100.00% | 0.0000 | 1, 1, 1 |
| H2A | Hinted Deepseek | 2/3 | 0, 2, 2 | 50.00% | 0.4444 [0.0000–0.6667] | 2, 0, 0 |
| H2B | Tai-e [Qwen selection] | 1/1 | 30 | 96.67% | 0.0645 | 30 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 29 | 96.55% | 0.0667 | 29 |
| H2B | Hinted Qwen | 0/3 | 1, 1, 1 | 100.00% | 0.0000 | 1, 1, 1 |
| H2B | Hinted Deepseek | 2/3 | 2, 1, 0 | 25.00% [0.00%–50.00%] | 0.5556 [0.0000–1.0000] | 0, 2, 1 |
| E | Tai-e [Qwen driver + selection] | 1/1 | 52 | 94.23% | 0.1091 | 52 |
| E | Tai-e [Deepseek driver + selection] | 0/1 | 44 | 100.00% | 0.0000 | 44 |
| E | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| E | Hinted Deepseek | 0/3 | 0, 0, 0 | n/a | 0.0000 | 0, 0, 0 |

## plexus-archiver

Fix methods: `AbstractUnArchiver.extractFile`

| Level | Arm | Detected | N per sample | FDR ↓ | F1 ↑ | Fixed-revision N |
| --- | --- | :---: | --- | ---: | ---: | --- |
| HINTED | Tai-e | 1/1 | 7 | 85.71% | 0.2500 | 7 |
| HINTED | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| HINTED | Hinted Deepseek | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H1 | Tai-e | 1/1 | 32 | 96.88% | 0.0606 | 32 |
| H1 | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H1 | Hinted Deepseek | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2A | Tai-e | 1/1 | 35 | 97.14% | 0.0556 | 35 |
| H2A | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2A | Hinted Deepseek | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2B | Tai-e [Qwen selection] | 1/1 | 35 | 97.14% | 0.0556 | 35 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 35 | 97.14% | 0.0556 | 35 |
| H2B | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2B | Hinted Deepseek | 2/3 (1 failed) | 1, 0, 1 | 0.00% | 0.6667 [0.0000–1.0000] | 1, 1, 1 |
| E | Tai-e [Qwen driver + selection] | 1/1 | 38 | 97.37% | 0.0513 | 38 |
| E | Tai-e [Deepseek driver + selection] | 0/1 (1 failed) | 0 | n/a | 0.0000 | 0 |
| E | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| E | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | n/a | 0.0000 | 0, 0, 0 |

## plexus-utils

Fix methods: `Expand.extractFile`

| Level | Arm | Detected | N per sample | FDR ↓ | F1 ↑ | Fixed-revision N |
| --- | --- | :---: | --- | ---: | ---: | --- |
| HINTED | Tai-e | 1/1 | 12 | 91.67% | 0.1538 | 12 |
| HINTED | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| HINTED | Hinted Deepseek | 3/3 | 1, 2, 1 | 16.67% [0.00%–50.00%] | 0.8889 [0.6667–1.0000] | 2, 1, 1 |
| H1 | Tai-e | 1/1 | 28 | 96.43% | 0.0690 | 28 |
| H1 | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H1 | Hinted Deepseek | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2A | Tai-e | 1/1 | 28 | 96.43% | 0.0690 | 28 |
| H2A | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2A | Hinted Deepseek | 1/3 (2 failed) | 0, 1, 0 | 0.00% | 0.3333 [0.0000–1.0000] | 1, 1, 0 |
| H2B | Tai-e [Qwen selection] | 1/1 | 28 | 96.43% | 0.0690 | 28 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 28 | 96.43% | 0.0690 | 28 |
| H2B | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2B | Hinted Deepseek | 1/3 (2 failed) | 0, 0, 1 | 0.00% | 0.3333 [0.0000–1.0000] | 0, 0, 1 |
| E | Tai-e [Qwen driver + selection] | 1/1 | 31 | 96.77% | 0.0625 | 31 |
| E | Tai-e [Deepseek driver + selection] | 1/1 | 32 | 96.88% | 0.0606 | 32 |
| E | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| E | Hinted Deepseek | 3/3 | 1, 1, 2 | 16.67% [0.00%–50.00%] | 0.8889 [0.6667–1.0000] | 1, 1, 0 |

## mpxj

Fix methods: `InputStreamHelper.processZipStream`

| Level | Arm | Detected | N per sample | FDR ↓ | F1 ↑ | Fixed-revision N |
| --- | --- | :---: | --- | ---: | ---: | --- |
| HINTED | Tai-e | 1/1 | 11 | 90.91% | 0.1667 | 11 |
| HINTED | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| HINTED | Hinted Deepseek | 3/3 | 2, 2, 2 | 50.00% | 0.6667 | 0, 0, 0 |
| H1 | Tai-e | 1/1 | 27 | 96.30% | 0.0714 | 27 |
| H1 | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H1 | Hinted Deepseek | 3/3 | 1, 1, 2 | 16.67% [0.00%–50.00%] | 0.8889 [0.6667–1.0000] | 0, 1, 0 |
| H2A | Tai-e | 1/1 | 27 | 96.30% | 0.0714 | 28 |
| H2A | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2A | Hinted Deepseek | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 0, 0, 0 |
| H2B | Tai-e [Qwen selection] | 1/1 | 27 | 96.30% | 0.0714 | 27 |
| H2B | Tai-e [Deepseek selection] | 1/1 | 27 | 96.30% | 0.0714 | 27 |
| H2B | Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1, 1, 1 |
| H2B | Hinted Deepseek | 3/3 | 2, 2, 1 | 33.33% [0.00%–50.00%] | 0.7778 [0.6667–1.0000] | 0, 0, 1 |
| E | Tai-e [Qwen driver + selection] | 0/1 | 116 | 100.00% | 0.0000 | 116 |
| E | Tai-e [Deepseek driver + selection] | 0/1 (1 failed) | 0 | n/a | 0.0000 | 0 |
| E | Hinted Qwen | 3/3 | 2, 2, 1 | 33.33% [0.00%–50.00%] | 0.7778 [0.6667–1.0000] | 1, 2, 2 |
| E | Hinted Deepseek | 0/3 (3 failed) | 0, 0, 0 | n/a | 0.0000 | 0, 0, 0 |
