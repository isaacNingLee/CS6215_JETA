# LLMDFA baseline (Wang et al., NeurIPS 2024)

Run `261022l`, scored 2026-10-30T02:12:49+00:00. Dataset commit `afe0ebd0adc237abb46255f9cd479b1d71819136`. Upstream https://github.com/chengpeng-wang/LLMDFA.git @ `fca638790cc0`; syn_parser off (no synthesized CWE-22 tree-sitter extractor exists upstream; source/sink come from the generated CWE-22 prompt specs), fscot on, syn_solver off by default.

Inputs as at the Hinted level: the manual per-project source/sink policy (as CWE-22 prompt specs) and
the Tai-e entry point; LLMDFA parses the fix file, the hinted sink files, the entry class and the entry
adapter. Locations are both endpoints of every validated trace. A failed case reports nothing.

| Arm | Detected ↑ | Macro FDR ↓ | Macro F1 ↑ | Fixed: flagged ↓ | Pair-correct ↑ |
| --- | --- | ---: | ---: | --- | --- |
| LLMDFA Qwen | 4/6, 3/6, 3/6 | 35.83% [33.33%–37.50%] | 0.4206 [0.3730–0.5000] | 3/6, 3/6, 3/6 | 1/6, 0/6, 0/6 |
| LLMDFA DeepSeek | 0/6, 2/6, 3/6 | 73.61% [54.17%–100.00%] | 0.1944 [0.0000–0.3611] | 2/6, 2/6, 1/6 | 0/6, 0/6, 2/6 |

## Cases

Cut off: answers that hit the token limit, used as returned (as upstream does).

| Model | Sample | Project | Revision | Status | Requests | Cut off | Cost | Seconds |
| --- | ---: | --- | --- | --- | ---: | ---: | ---: | ---: |
| qwen | 1 | zip4j | vulnerable | completed | 113 | 3 | $0.0241 | 1655.0 |
| qwen | 1 | zip4j | fixed | completed | 141 | 0 | $0.0242 | 939.2 |
| qwen | 1 | zt-zip | vulnerable | completed | 256 | 0 | $0.0331 | 1527.1 |
| qwen | 1 | zt-zip | fixed | completed | 249 | 0 | $0.0350 | 1598.0 |
| qwen | 1 | spark | vulnerable | completed | 9 | 0 | $0.0004 | 21.9 |
| qwen | 1 | spark | fixed | completed | 9 | 0 | $0.0007 | 13.6 |
| qwen | 1 | plexus-archiver | vulnerable | completed | 199 | 1 | $0.0477 | 2271.9 |
| qwen | 1 | plexus-archiver | fixed | completed | 199 | 2 | $0.0459 | 2601.1 |
| qwen | 1 | plexus-utils | vulnerable | completed | 13 | 0 | $0.0025 | 66.1 |
| qwen | 1 | plexus-utils | fixed | completed | 13 | 0 | $0.0018 | 62.7 |
| qwen | 1 | mpxj | vulnerable | completed | 6 | 0 | $0.0005 | 18.6 |
| qwen | 1 | mpxj | fixed | completed | 8 | 0 | $0.0017 | 32.5 |
| qwen | 2 | zip4j | vulnerable | completed | 113 | 3 | $0.0250 | 1513.6 |
| qwen | 2 | zip4j | fixed | completed | 140 | 0 | $0.0255 | 812.5 |
| qwen | 2 | zt-zip | vulnerable | completed | 230 | 4 | $0.0406 | 2478.0 |
| qwen | 2 | zt-zip | fixed | completed | 245 | 2 | $0.0414 | 2298.9 |
| qwen | 2 | spark | vulnerable | completed | 9 | 0 | $0.0006 | 27.3 |
| qwen | 2 | spark | fixed | completed | 9 | 0 | $0.0005 | 32.4 |
| qwen | 2 | plexus-archiver | vulnerable | completed | 187 | 0 | $0.0422 | 1658.3 |
| qwen | 2 | plexus-archiver | fixed | completed | 198 | 2 | $0.0452 | 1945.1 |
| qwen | 2 | plexus-utils | vulnerable | completed | 13 | 0 | $0.0020 | 108.9 |
| qwen | 2 | plexus-utils | fixed | completed | 13 | 0 | $0.0016 | 81.5 |
| qwen | 2 | mpxj | vulnerable | completed | 6 | 0 | $0.0006 | 22.9 |
| qwen | 2 | mpxj | fixed | completed | 8 | 0 | $0.0014 | 52.4 |
| qwen | 3 | zip4j | vulnerable | completed | 113 | 2 | $0.0237 | 1258.5 |
| qwen | 3 | zip4j | fixed | completed | 141 | 2 | $0.0309 | 1440.0 |
| qwen | 3 | zt-zip | vulnerable | completed | 238 | 2 | $0.0394 | 1685.8 |
| qwen | 3 | zt-zip | fixed | completed | 272 | 3 | $0.0485 | 2070.8 |
| qwen | 3 | spark | vulnerable | completed | 9 | 0 | $0.0006 | 16.2 |
| qwen | 3 | spark | fixed | completed | 9 | 0 | $0.0004 | 23.4 |
| qwen | 3 | plexus-archiver | vulnerable | completed | 189 | 1 | $0.0416 | 1901.9 |
| qwen | 3 | plexus-archiver | fixed | completed | 190 | 1 | $0.0425 | 1700.3 |
| qwen | 3 | plexus-utils | vulnerable | completed | 13 | 0 | $0.0022 | 84.8 |
| qwen | 3 | plexus-utils | fixed | completed | 13 | 0 | $0.0015 | 70.4 |
| qwen | 3 | mpxj | vulnerable | completed | 6 | 0 | $0.0006 | 26.2 |
| qwen | 3 | mpxj | fixed | completed | 8 | 0 | $0.0010 | 39.4 |
| deepseek | 1 | zip4j | vulnerable | completed | 105 | 0 | $0.2426 | 1907.0 |
| deepseek | 1 | zip4j | fixed | completed | 112 | 0 | $0.2283 | 2300.2 |
| deepseek | 1 | zt-zip | vulnerable | completed | 177 | 0 | $0.1899 | 1565.4 |
| deepseek | 1 | zt-zip | fixed | completed | 187 | 0 | $0.2098 | 1616.7 |
| deepseek | 1 | spark | vulnerable | completed | 9 | 0 | $0.0060 | 90.4 |
| deepseek | 1 | spark | fixed | completed | 9 | 0 | $0.0069 | 84.8 |
| deepseek | 1 | plexus-archiver | vulnerable | completed | 180 | 0 | $0.4219 | 3387.4 |
| deepseek | 1 | plexus-archiver | fixed | completed | 179 | 0 | $0.4016 | 3301.5 |
| deepseek | 1 | plexus-utils | vulnerable | completed | 13 | 0 | $0.0293 | 278.2 |
| deepseek | 1 | plexus-utils | fixed | completed | 13 | 0 | $0.0223 | 204.8 |
| deepseek | 1 | mpxj | vulnerable | completed | 4 | 0 | $0.0045 | 71.0 |
| deepseek | 1 | mpxj | fixed | completed | 4 | 0 | $0.0040 | 77.6 |
| deepseek | 2 | zip4j | vulnerable | completed | 104 | 0 | $0.2151 | 1511.4 |
| deepseek | 2 | zip4j | fixed | completed | 111 | 0 | $0.2035 | 1775.5 |
| deepseek | 2 | zt-zip | vulnerable | completed | 180 | 0 | $0.2164 | 1646.7 |
| deepseek | 2 | zt-zip | fixed | completed | 182 | 0 | $0.2009 | 1471.5 |
| deepseek | 2 | spark | vulnerable | completed | 9 | 0 | $0.0064 | 87.1 |
| deepseek | 2 | spark | fixed | completed | 9 | 0 | $0.0058 | 50.5 |
| deepseek | 2 | plexus-archiver | vulnerable | completed | 187 | 0 | $0.4677 | 3735.8 |
| deepseek | 2 | plexus-archiver | fixed | completed | 187 | 0 | $0.4117 | 3352.0 |
| deepseek | 2 | plexus-utils | vulnerable | completed | 13 | 0 | $0.0376 | 300.7 |
| deepseek | 2 | plexus-utils | fixed | completed | 13 | 0 | $0.0304 | 236.9 |
| deepseek | 2 | mpxj | vulnerable | completed | 4 | 0 | $0.0101 | 94.0 |
| deepseek | 2 | mpxj | fixed | completed | 4 | 0 | $0.0032 | 22.6 |
| deepseek | 3 | zip4j | vulnerable | completed | 105 | 0 | $0.2114 | 2578.6 |
| deepseek | 3 | zip4j | fixed | completed | 112 | 0 | $0.2184 | 1568.2 |
| deepseek | 3 | zt-zip | vulnerable | completed | 187 | 0 | $0.2562 | 1893.0 |
| deepseek | 3 | zt-zip | fixed | completed | 184 | 0 | $0.2481 | 1851.6 |
| deepseek | 3 | spark | vulnerable | completed | 9 | 0 | $0.0060 | 37.5 |
| deepseek | 3 | spark | fixed | completed | 9 | 0 | $0.0074 | 54.6 |
| deepseek | 3 | plexus-archiver | vulnerable | completed | 179 | 0 | $0.4103 | 2766.1 |
| deepseek | 3 | plexus-archiver | fixed | completed | 187 | 0 | $0.4099 | 2924.0 |
| deepseek | 3 | plexus-utils | vulnerable | completed | 13 | 0 | $0.0451 | 333.6 |
| deepseek | 3 | plexus-utils | fixed | completed | 13 | 0 | $0.0265 | 215.0 |
| deepseek | 3 | mpxj | vulnerable | completed | 6 | 0 | $0.0166 | 115.9 |
| deepseek | 3 | mpxj | fixed | completed | 4 | 0 | $0.0241 | 179.7 |

Total reported cost: $6.13.

## Deviations from upstream

- Superclass source closure added to the hinted file set; nested named classes parsed.
- Callee resolution includes parsed subclasses for inherited virtual calls (conservative).
- LLM endpoints filtered against syntax of the project source/sink policy, with rejection audit.
- Persistent null completions fail the case; returned model IDs are recorded and optionally pinned.
- Scoring uses only the first and last point of each validated trace.
- LLM boundary routed to OpenRouter; upstream silent-"" error handling replaced by a sticky failure.
- TSAnalyzer parses the policy-relevant file set, not a single file.
- Analysis roots seeded from the Tai-e entry point, not from methods named good/bad.
- Source/sink bug-class assertion bypassed; CWE-22 specs are supplied instead of dbz/xss/ci.
- Juliet comment-label oracle unused; scoring is external and matches the other arms.
- find_callee takes the method_invocation name field; upstream used the first identifier, which is the receiver for a qualified call, so no qualified call resolved.
- Each file's own package registered as an implicit import, so same-package calls resolve.
- find_function_returns collects identifiers nested in a returned expression, not only a bare returned identifier.
- Callee descent covers every resolved candidate, matching the reachability search, and memoizes (function, parameter-index) pairs so recursion terminates.
- Searching deferred until every reachable function is summarized, so it cannot read a caller that is still mid-descent.
- Reachability search prunes traces that revisit a value and stops at TRACE_LIMIT.
- A second call site on one source line is dropped rather than asserted on; the count is reported as dropped_call_sites.
- Callee candidates filtered by argument count; name-only matching resolved a call to every same-named overload, including itself, which made traces oscillate.
- Resolved callees sorted for reproducibility; upstream iterated a set of class names.
- Non-ASCII sources are copied with each character widened to its byte count, because upstream slices the decoded text with tree-sitter byte offsets and otherwise misreads every name after the first non-ASCII character.
- The entry point may be an inherited method; upstream sees only declarations.
- A Yes/No prompt answered without a Yes or a No raises instead of re-asking forever in upstream's retry loop; null content that survives the retries fails the case rather than becoming an empty answer.
- An answer cut off at the token limit (finish_reason length, or none) is used as returned, as upstream does (CS6215_proj failed the case); the count is reported as truncated_answers.
- Null content from a reasoning model that finished normally with its reasoning present is its empty answer (DeepSeek returns an empty answer as null), not a provider fault; counted as reasoning_only_answers.
- Transport errors and the provider's null-content bug retried three times with backoff, as the hinted-LLM arm does; every other failure stops the case on the first occurrence.
