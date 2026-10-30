# CWE-22 baselines: Tai-e, vanilla LLM and hinted LLM

Run `261021b`, scored 2026-10-30T02:12:48+00:00. Dataset commit `afe0ebd0adc237abb46255f9cd479b1d71819136`.
Models: qwen = `qwen/qwen3-coder-30b-a3b-instruct`, deepseek = `deepseek/deepseek-v4-pro`.
LLM arms: 3 independent samples per cell, max_tokens 8000/16000. Tai-e is deterministic (1 run).

Unit: one `(simple class, method)` location on the **vulnerable** revision. N = reported
locations, K = locations that are recorded production fix methods. Detected = K > 0,
FDR = 1 − K/N, F1 = 2K/(N+K) (binary project recall). These are fix-location proxies,
not verified vulnerability labels.

## Summary

Values are the mean over samples, with [min–max] when samples differ.

| Arm | Detected (per sample) | Macro FDR ↓ | Macro F1 ↑ |
| --- | --- | ---: | ---: |
| Tai-e | 6/6 | 85.50% | 0.2439 |
| Vanilla Qwen | 4/6, 4/6, 4/6 | 38.52% [26.67%–50.00%] | 0.6074 [0.5556–0.6333] |
| Vanilla Deepseek | 4/6, 5/6, 5/6 | 25.00% [16.67%–41.67%] | 0.7000 [0.6111–0.7444] |
| Hinted Qwen | 4/6, 4/6, 5/6 | 27.78% [16.67%–33.33%] | 0.7222 [0.6667–0.8333] |
| Hinted Deepseek | 6/6, 5/6, 6/6 | 30.56% [25.00%–41.67%] | 0.7778 [0.6667–0.8333] |

Macro FDR averages projects with nonempty output; detection and F1 count all projects.

Each sample is one request, never retried. Failed answers count as empty output
(undetected, F1 0, FDR undefined):

- Vanilla Deepseek s2 / mpxj fixed: Incomplete response: finish_reason=length
- Vanilla Deepseek s3 / mpxj fixed: Incomplete response: finish_reason=length

## zip4j

Fix methods: `Unzip.initExtractFile`

| Arm | Detected | N per sample | FDR ↓ | F1 ↑ | F1 per sample | Fixed-revision N |
| --- | :---: | --- | ---: | ---: | --- | --- |
| Tai-e | 1/1 | 7 | 85.71% | 0.2500 | 0.2500 | 7 |
| Vanilla Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 1, 1, 1 |
| Vanilla Deepseek | 3/3 | 2, 2, 2 | 50.00% | 0.6667 | 0.6667, 0.6667, 0.6667 | 1, 1, 1 |
| Hinted Qwen | 1/3 | 1, 1, 1 | 66.67% [0.00%–100.00%] | 0.3333 [0.0000–1.0000] | 0.0000, 0.0000, 1.0000 | 1, 1, 1 |
| Hinted Deepseek | 2/3 | 2, 2, 2 | 66.67% [50.00%–100.00%] | 0.4444 [0.0000–0.6667] | 0.6667, 0.0000, 0.6667 | 0, 0, 0 |

## zt-zip

Fix methods: `Unpacker.process`, `Unwraper.getRootName`, `Unwraper.process`

| Arm | Detected | N per sample | FDR ↓ | F1 ↑ | F1 per sample | Fixed-revision N |
| --- | :---: | --- | ---: | ---: | --- | --- |
| Tai-e | 1/1 | 13 | 92.31% | 0.1429 | 0.1429 | 13 |
| Vanilla Qwen | 2/3 | 3, 3, 3 | 55.56% [33.33%–100.00%] | 0.5333 [0.0000–0.8000] | 0.0000, 0.8000, 0.8000 | 5, 5, 5 |
| Vanilla Deepseek | 2/3 | 1, 3, 3 | 55.56% [33.33%–100.00%] | 0.5333 [0.0000–0.8000] | 0.0000, 0.8000, 0.8000 | 3, 3, 3 |
| Hinted Qwen | 0/3 | 1, 1, 1 | 100.00% | 0.0000 | 0.0000, 0.0000, 0.0000 | 1, 1, 1 |
| Hinted Deepseek | 3/3 | 2, 2, 2 | 50.00% | 0.6667 | 0.6667, 0.6667, 0.6667 | 2, 1, 2 |

## spark

Fix methods: `ClassPathResource.ClassPathResource`, `ClassPathResource.equals`, `ClassPathResource.exists`, `ClassPathResource.getInputStream`, `ClassPathResource.getPath`, `ClassPathResource.getURL`

| Arm | Detected | N per sample | FDR ↓ | F1 ↑ | F1 per sample | Fixed-revision N |
| --- | :---: | --- | ---: | ---: | --- | --- |
| Tai-e | 1/1 | 3 | 66.67% | 0.5000 | 0.5000 | 3 |
| Vanilla Qwen | 0/3 | 1, 0, 1 | 100.00% | 0.0000 | 0.0000, 0.0000, 0.0000 | 1, 1, 1 |
| Vanilla Deepseek | 0/3 | 1, 0, 0 | 100.00% | 0.0000 | 0.0000, 0.0000, 0.0000 | 0, 0, 0 |
| Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 1, 1, 1 |
| Hinted Deepseek | 3/3 | 2, 2, 2 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 2, 2, 1 |

## plexus-archiver

Fix methods: `AbstractUnArchiver.extractFile`

| Arm | Detected | N per sample | FDR ↓ | F1 ↑ | F1 per sample | Fixed-revision N |
| --- | :---: | --- | ---: | ---: | --- | --- |
| Tai-e | 1/1 | 7 | 85.71% | 0.2500 | 0.2500 | 7 |
| Vanilla Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 1, 1, 1 |
| Vanilla Deepseek | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 1, 1, 1 |
| Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 1, 1, 1 |
| Hinted Deepseek | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 1, 1, 1 |

## plexus-utils

Fix methods: `Expand.extractFile`

| Arm | Detected | N per sample | FDR ↓ | F1 ↑ | F1 per sample | Fixed-revision N |
| --- | :---: | --- | ---: | ---: | --- | --- |
| Tai-e | 1/1 | 12 | 91.67% | 0.1538 | 0.1538 | 12 |
| Vanilla Qwen | 3/3 | 2, 1, 1 | 16.67% [0.00%–50.00%] | 0.8889 [0.6667–1.0000] | 0.6667, 1.0000, 1.0000 | 1, 1, 1 |
| Vanilla Deepseek | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 1, 1, 1 |
| Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 1, 1, 1 |
| Hinted Deepseek | 3/3 | 1, 2, 1 | 16.67% [0.00%–50.00%] | 0.8889 [0.6667–1.0000] | 1.0000, 0.6667, 1.0000 | 2, 1, 1 |

## mpxj

Fix methods: `InputStreamHelper.processZipStream`

| Arm | Detected | N per sample | FDR ↓ | F1 ↑ | F1 per sample | Fixed-revision N |
| --- | :---: | --- | ---: | ---: | --- | --- |
| Tai-e | 1/1 | 11 | 90.91% | 0.1667 | 0.1667 | 11 |
| Vanilla Qwen | 1/3 | 2, 1, 1 | 83.33% [50.00%–100.00%] | 0.2222 [0.0000–0.6667] | 0.6667, 0.0000, 0.0000 | 1, 1, 1 |
| Vanilla Deepseek | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 0, 0, 0 |
| Hinted Qwen | 3/3 | 1, 1, 1 | 0.00% | 1.0000 | 1.0000, 1.0000, 1.0000 | 1, 1, 1 |
| Hinted Deepseek | 3/3 | 2, 2, 2 | 50.00% | 0.6667 | 0.6667, 0.6667, 0.6667 | 0, 0, 0 |
