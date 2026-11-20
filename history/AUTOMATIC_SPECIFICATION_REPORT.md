# Evidence-grounded automatic taint specifications for Tai-e

Implementation notes and course-report material, 10 October 2026.

## Aim and research positioning

Our target is a small, experimentally defensible neuro-symbolic analyzer for
Java path traversal (CWE-22), not a publication-level claim of a new general
analysis algorithm. Tai-e supplies program structure and symbolic propagation;
an LLM proposes missing taint semantics. We want to study **which inferred rules
cause useful or misleading analysis results**, rather than merely connect two tools.

The broad architecture is prior work: [IRIS](https://arxiv.org/abs/2405.17238)
already combines LLM-inferred taint specifications, static analysis and contextual
review. We use its CWE-Bench-Java dataset and must acknowledge that relationship.
Replacing CodeQL with Tai-e, adding JSON validation, or using a different model
is not by itself a substantive research contribution.
[LLMDFA](https://arxiv.org/abs/2402.10754) is also relevant: it decomposes LLM-driven
dataflow reasoning and delegates selected checks to external tools. Tool checking
of LLM output is therefore not itself new. These references motivate the design;
they do not establish that our proposed extension is unprecedented.

**Proposed course-level contribution, subject to the next design decision:**
an evidence-linked, rule-level audit of inferred taint policies, with controlled
rule-removal experiments. For a policy P and an inferred rule r, compare warnings
W(P) with W(P without r). Associate changed warnings with r's program evidence
and model rationale, then investigate whether those rules explain false alarms
or recover missed flows. This gives a concrete experiment beyond aggregate
"LLM plus static analyzer" scores. No warning difference does not prove a rule
is unnecessary: redundant rules, missing sources, or incomplete reachability
may mask its effect. A warning disappearing does not prove it was false.

This is a proposed extension, **not implemented or demonstrated yet**. A broader
related-work review is needed before making any originality claim. A carefully
scoped new combination, explicit hypothesis and honest ablation study are the
intended course contribution. We will not claim novelty from infrastructure alone.

## Research questions and planned controls

- RQ1: Can catalogue-grounded inference recover useful source/sink/transfer
  policies without project-specific manual API hints?
- RQ2: How often does structural validation reject malformed or ungrounded rules,
  and what semantic mistakes survive those checks?
- RQ3 (proposed extension): Does rule-level warning-dependence auditing help
  explain false positives/negatives and target limited review effort?

First compare manual Tai-e policies, automated policies, and the LLM-only baselines
on matched entry/scope assumptions. For context ablations, keep method inventory,
model, output schema and budget fixed while varying metadata-only versus IR and
call-site context. To isolate validator effects, revalidate the **same saved
proposals** with selected checks disabled in an offline experiment, rather than
change the prompt and validator together. Do not execute malformed policies just
to create an unchecked baseline; count configuration failures as outcomes.

For later rule-removal experiments, cap runs/cost explicitly and evaluate selected
source, sink and transfer effects separately. Human semantic review must be
independent of a desire to reduce warning counts. Do not feed known fixes or
ground-truth labels into inference or use them to select rules at test time.

## Implemented pipeline and boundaries

```text
Pinned built Java project + existing entry adapter
  -> Tai-e pointer analysis WITHOUT a taint configuration
  -> method/call catalogue, project IR, bounded source windows       [step 1]
  -> all catalogue methods in deterministic LLM batches
  -> source/sink/transfer hypotheses with evidence IDs
  -> deterministic structural validation + candidate Tai-e YAML    [step 2]
  -> Tai-e taint run + endpoint attribution                        [step 3 pilot]
  -> rule-level audit / contextual judge                           [proposed]
```

Tai-e can build its pointer-analysis/call-graph facts without a manual taint
specification. Taint analysis itself still needs a specification; step 2
generates that specification. This is **automatic taint-specification inference
under supplied entry points and a shared CWE threat model**, not fully automatic
whole-project security configuration. Entry adapters remain manual.

AST, CFG and DFG are not all passed to the LLM. Step 1 uses Tai-e IR, call targets,
types and source windows; step 2 bounds and packages those facts. No explicit
CFG/DFG export, guard dominance check or path-feasibility proof is implemented.
Full graphs may become useful for a later guard judge but are not prerequisites
for this initial specification stage.

## Step 1: program-fact catalogue

The exporter records reachable project/adapter method bodies and metadata for
their direct API targets. It excludes dependency bodies and unreachable project
methods. Each call retains declared, resolved and possible dispatch targets.
Source snippets are bytecode-line windows, not verified program slices.

Five existing vulnerable-version checkouts were successfully catalogued:

| Project | Methods | Project/adapter bodies | Calls | Calls with source | Calls with no graph targets |
| --- | ---: | ---: | ---: | ---: | ---: |
| zip4j | 433 | 327 | 1,134 | 1,134 | 8 |
| zt-zip | 225 | 105 | 305 | 305 | 3 |
| spark | 100 | 23 | 151 | 151 | 6 |
| plexus-archiver | 88 | 23 | 127 | 127 | 9 |
| plexus-utils | 68 | 14 | 129 | 129 | 26 |

These are coverage counts, not vulnerability results. All five exported zero
explicit skipped project invokedynamic sites; that does not establish full
reflection/native/dynamic-code coverage. Calls with no targets are retained,
not treated as unreachable. Run records preserve commit, tool/build hashes,
adapter, command and the absent taint specification. Fixed-version catalogues
have not yet been generated in this staged workflow.

Code: `analysis/catalogue/MethodCataloguePlugin.java`,
`scripts/build_spec_catalogue.py`. Detailed contract:
[catalogue guide](../analysis/catalogue/README.md).

## Step 2: inference, validation and compilation

The generator uses all catalogue methods, not a manually chosen list of known
security APIs. It sorts methods into bounded batches and selects up to two
incoming and two outgoing call sites for each. Exact bounds, prompt and failure
semantics are documented in the [specification guide](../analysis/specification/README.md).

The LLM must classify every method as proposing rules, no relevant role, or
unknown. Each rule has a rationale and supplied call-site citations. A deterministic
compiler resolves local method IDs to exact Tai-e signatures and slot types.
It rejects invalid indices, primitive slots, nonexistent receivers/results,
unsupported shapes, phantom-class methods and invalid citations. This prevents
certain malformed specifications; it does **not** prove source trust boundaries,
sink sensitivity, transfer semantics, control flow, or vulnerability reachability.

Supported output: call sources, sinks on receiver/arguments, and transfers between
reference slots. No field/array-element rules, entry-parameter sources or sanitizer
rules. In particular, normalization is not promoted to an unconditional sanitizer.
All accepted/rejected proposals and raw responses remain available for auditing.
The output is always named `candidate-taint.yml` to avoid implying verification.

No fix labels, manual taint policies or previous warnings are read. The prompt
does supply CWE-22 and a common attacker model; this is not a no-security-hint
baseline. Model pretraining may still contain the projects. Catalogue context
contains the existing entry adapter, which can constrain the threat model.

Code: `scripts/generate_taint_spec.py`; prompt:
[`analysis/specification/prompt.md`](../analysis/specification/prompt.md).

## Step 2 pilot results

The pilot used Plexus Utils' existing vulnerable-version catalogue and
`qwen/qwen3-coder-30b-a3b-instruct` through OpenRouter (returned provider:
SiliconFlow). Five requests were made, without retries or manual policy repairs.
This is an engineering pilot, not model selection based on detection outcomes.

| Measure | Observed result |
| --- | ---: |
| Methods submitted | 68 |
| Batch sizes | 16, 15, 16, 14, 7 |
| Successfully parsed response batches | 5/5 |
| Methods with a valid classification record | 35/68 |
| Decisions: rules / none / unknown | 21 / 14 / 0 |
| Missing method classifications | 33 |
| Rule proposals structurally accepted, before deduplication | 15 |
| Rule proposals structurally rejected | 15 |
| Unique compiled source / sink / transfer rules | 3 / 7 / 3 |
| Total validation issues (15 rejected rules + 33 missing records) | 48 |
| Prompt / completion tokens (provider-reported) | 60,235 / 3,966 |
| Sum of provider-reported `usage.cost` | 0.00532693 |
| Run status | **incomplete** |
| Generated-policy Tai-e analysis | **not run** |

The cost is the API's recorded numeric cost field, not an independent billing
check or a forecast for future runs. Request wall times were not instrumented in
this pilot. The run returned exit code 1 intentionally: JSON parsing succeeded,
but missing classifications and invalid rules make the policy incomplete.

Of the 15 rejected rules, four cited unavailable/unrelated evidence, ten had
invalid slot positions/receiver/results, and one selected a primitive slot.
These categories report the first failing check; a rule can have multiple faults.
One entire batch returned an empty classification list, despite being given 15
methods. The remaining omissions occurred in later batches. They are not counted
as `none` decisions or negative security findings.

Important observations from inspecting the saved proposals:

- A useful-looking accepted transfer maps argument 1 of `File(File,String)` to
  the constructed `File` receiver. `FileOutputStream(File)` argument 0 was also
  proposed as a sink. These are plausible rules, not yet end-to-end validated.
- The model mixed method identities: the accepted sink on the entry adapter's
  `main(String[])` was justified with a rationale about `Expand.execute()`.
  A related outgoing call can pass citation validation while the rule describes
  the wrong method. Exact ID lookup alone cannot prevent this semantic error.
- It treated the byte buffer passed to `FileOutputStream.write(byte[],int,int)`
  and `FilterInputStream.read(byte[])` as path sinks. Those are content buffers,
  not path-selection arguments; reference-type validation cannot detect that.
- It proposed `FileUtils.resolveFile` as a fresh source as well as a sink. This
  risks confusing path transformation with a trust boundary or sensitive access.
  Such wrapper roles need semantic review rather than automatic acceptance.

Therefore **13 compiled rules does not mean 13 correct rules**, and neither
source/sink non-emptiness nor a parsed response demonstrates detection capability.
We have not edited these rules to match the known vulnerability. The raw outcome
is retained to motivate a measured refinement experiment rather than conceal it.

Live artifact directory (Git-ignored, retained locally):
[`results/automatic-spec/20261010T072616Z-3vh4e4tl/`](results/automatic-spec/20261010T072616Z-3vh4e4tl/).
Its [candidate YAML](results/automatic-spec/20261010T072616Z-3vh4e4tl/candidate-taint.yml)
is a partial diagnostic artifact, **not a recommended production policy**.

An offline replay in
[`results/automatic-spec/20261010T073023Z-3hjdi1pu/`](results/automatic-spec/20261010T073023Z-3hjdi1pu/)
reproduced byte-identical `accepted.json`, `rejected.json` and candidate YAML,
including the incomplete status, with no additional API requests.

Reproduce the pilot inputs (a new live run can yield different outputs):

```bash
python3 scripts/generate_taint_spec.py \
  --catalogue evaluation/results/spec-catalogue/20261010T071921Z-plexus-utils-vulnerable-hl3y92kt/catalogue.json
```

## Validation and reproducibility

Offline tests cover catalogue source mapping; batching/coverage; context truncation;
constructor type-changing transfers; invalid/static/primitive slots; evidence
identity; phantom methods; duplicate, missing and unknown classifications;
abstention; deduplication; and malformed/truncated completions. The test command is:

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Each generation run saves input/prompt/implementation hashes and snapshots,
requests (without credentials), raw responses, usage/provider metadata, proposed
rules, validation decisions, candidate YAML and a generated `REPORT.md`.
An offline replay checks exact request equality before revalidating responses.
Live temperature-zero inference is not guaranteed reproducible across providers.
Generated runs are Git-ignored; archive selected artifacts for the course submission.
This tracked report and the implementation are intended to remain in version control.

At the end of step 2, **31 tests passed**, including mocked live inference,
credential-free dry-run/replay, replay mismatch detection and transport failures.
Prompt-generation dry-runs succeeded for all five existing catalogues (433, 225,
100, 88 and 68 methods respectively), with no additional paid requests. Only
Plexus Utils received live specification inference in this step. YAML loading
and taint propagation in Tai-e remain untested until the next approved stage.

## Evaluation cautions

Do not reuse the earlier table's F1/FDR as a verified warning-level security score:
matching a fix method is a localization proxy, not proof of a true positive.
A fixed-version warning can represent analysis imprecision, another issue, or
an incomplete fix, so it is not automatically a false positive. Deduplicate
and define a common finding unit before comparing systems.

For TP/FP/FN, define a reviewed vulnerability or flow-level oracle and scope;
record failures to build/analyze separately from negative findings. TN is only
meaningful with a defined finite negative universe (for example reviewed benign
test cases); it is not "every method with no warning." Paired vulnerable/fixed
versions are useful controls, not an exhaustive oracle.

The earlier LLM baseline reads fix-identified source files, whereas this workflow
discovers methods under an adapter. That information advantage prevents a clean
head-to-head conclusion unless inputs are matched or the difference is disclosed.
For paired-version experiments, choose a protocol up front: freeze one inferred
policy across revisions (report unresolved signatures) to isolate code changes,
or infer independently and separately report policy drift. Do not conflate them.

Report absolute counts for these five projects, per-project failure modes, API
cost and time. Treat any aggregate improvement as exploratory; five selected
cases cannot support broad statistical claims. For final conclusions, use held-out
cases or additional controlled benign/vulnerable examples, and avoid tuning on
the same five cases without disclosure.

## Step 2b: bounded diagnostic refinement (implemented after approval)

The initial pilot motivated a refinement loop, implemented in
`scripts/refine_taint_spec.py` with the separate
[refinement prompt](../analysis/specification/refinement.md).
It revisits only missing/rejected method classifications. It adds an exact
signature echo, valid reference slots derived from the catalogue, and prior
checker diagnostics. No manually chosen API corrections are supplied.

The loader reconstructs the seed from raw model responses, verifies its catalogue
and prompt hashes and checks request/context consistency. The original seed is
copied into the new run alongside content hashes; the original directory is not
edited. Every request, response, validation decision and method-state transition
is saved. A new classification replaces an earlier one only if its signature and
every proposed rule pass structural validation. Otherwise the entire method is
pending and none of its rules enters the active policy. This atomic rule differs
from step 2's compilation of individual valid rules within a mixed response.

The initial atomic state has **22 resolved methods and 46 pending methods**.
The original 35 classification records included 13 with invalid rules; those 13
plus 33 missing classifications are the repair targets. The 22 fully valid
legacy classifications are retained unchanged, including any semantic mistakes.
They are explicitly marked as not signature-echo-checked. This stage does not
claim to have revalidated all 68 methods under the stronger identity schema.

Default bounds: two rounds, four methods per batch, 24,000 input-data characters
including feedback, 24 attempted requests in total, 4,000 completion tokens per
request, and a 180-second request timeout. Stop before another request if summed
provider-reported cost reaches 0.05, or if a response lacks usable cost metadata.
This cost threshold is not a hard billing cap: the latest request may cross it.
Request and completion-token limits provide hard local bounds. No hidden retry
on network failures is used. The default model remains the seed's Qwen model.

A valid `unknown` is a resolved **abstention**, not a verified negative. Structural
resolution can also increase by choosing `none` rather than emitting rules;
therefore report decisions and rule counts, not only the fraction resolved.
Resolved methods are not retried. Model explanations and cited code can still
disagree even when the signature string matches exactly.

Run commands:

```bash
python3 scripts/refine_taint_spec.py \
  --from-run evaluation/results/automatic-spec/20261010T072616Z-3vh4e4tl --dry-run
python3 scripts/refine_taint_spec.py \
  --from-run evaluation/results/automatic-spec/20261010T072616Z-3vh4e4tl
```

Only Plexus Utils is in this live refinement pilot. Full usage, artifact contracts
and offline replay are in the [specification guide](../analysis/specification/README.md#step-2b-bounded-diagnostic-refinement).

### Step 2b pilot results

The run completed its two-round budget with **61/68 structurally resolved methods**
and **7 pending methods**. It correctly returned `incomplete`, exit code 1, with
stop reason `round_budget`. No extra sampling was performed to obtain a cleaner
result. The 22 legacy classifications stayed unchanged; 39 repaired classifications
passed the stronger signature-echo checks.

| Measure | Initial atomic state | After round 1 | After round 2 |
| --- | ---: | ---: | ---: |
| Structurally resolved methods | 22 | 53 | 61 |
| Pending methods | 46 | 15 | 7 |
| Cumulative refinement requests | 0 | 12 | 16 |

The initial 22 is the number of **fully valid methods**, not the original pilot's
35 partially/fully classified records. Comparing 35 to 61 would mix definitions.

| Final outcome | Value |
| --- | ---: |
| Newly resolved methods | 39/46 |
| Resolved decisions: rules / none / unknown | 22 / 39 / 0 |
| Unique active sources / sinks / transfers | 6 / 9 / 11 |
| Total unique active rules | 26 |
| Live requests / configured limit | 16 / 24 |
| Prompt / completion tokens, provider-reported | 77,295 / 7,342 |
| Sum of provider-reported `usage.cost` | 0.00746641 |
| Wall time measured by runner | 582.25 seconds |
| Returned provider | SiliconFlow |
| Tai-e taint analysis / semantic judge | Not run |

All responses included usable cost metadata; neither the request nor the reported
cost threshold was exhausted. The second-round limit ended the run. This is
additional usage for refinement, excluding the earlier five-request generation
pilot. As before, `usage.cost` is recorded provider metadata, not independently
verified billing. Offline replay incurred no additional API requests.

What improved:

- `ZipEntry.getName()`'s return value was recovered as a source using the supplied
  archive call-site evidence. This is a plausible archive trust-boundary rule.
- Four `File` instance methods (`getAbsoluteFile`, `getCanonicalFile`,
  `getParentFile`, `getPath`) initially used nonexistent argument 0. Round two
  changed their transfers to receiver (`base`) -> result. This is a concrete
  structural repair supported by the method signatures.
- Missing classifications were revisited explicitly. Many methods resolved to
  `none`: 39 final `none` decisions versus 14 in the initial atomic state. Coverage
  improvement is therefore not equivalent to recovering more security rules.

What did **not** improve reliably:

- Newly accepted sinks include argument 0 of `String.indexOf(String)` and
  `String.toLowerCase(Locale)`. Neither argument selects a filesystem/resource
  access; in the latter case it is a locale. Their signatures, types and citations
  pass the current checker, demonstrating a semantic blind spot.
- Previously accepted byte-buffer sinks on `FileOutputStream.write` and
  `FilterInputStream.read` remain unchanged, as required by the narrow repair scope.
- Exact signature echo did not prevent all caller/callee confusion: a proposal
  correctly echoed `Expand.expandFile(File,File)` but described argument 3 from
  a different extraction method. The slot checker rejected it.

The seven remaining pending methods are:

| Method | Last recorded failure |
| --- | --- |
| `StringBuilder.append(char)` | Proposed a primitive-slot transfer unsupported by this DSL |
| `ZipEntry.isDirectory()` | Proposed argument 0 on a zero-argument method |
| `ZipInputStream(InputStream)` | Proposed a constructor result, which does not exist |
| `Expand.expandFile(File,File)` | Proposed argument 3 on a two-argument method (three rejected rules) |
| `FileUtils.<clinit>()` | Invalid classification decision (`source` rather than `rules/none/unknown`) |
| `Os.isFamily(String)` | Invalid classification decision (`transfer`) |
| `Os.setValidFamilies()` | Invalid classification decision (`source`) |

These yield nine recorded validation errors: five slot errors, one primitive-slot
error, and three invalid decision/rule combinations. Only the first failing check
per proposal is recorded, so further defects may remain. Unsupported primitive
propagation is a limitation of the current DSL, not proof that no data dependency
exists. No pending method contributes active rules.

Live artifacts:
[`results/spec-refinement/20261010T132231Z-63skc5_5/`](results/spec-refinement/20261010T132231Z-63skc5_5/),
including the [candidate YAML](results/spec-refinement/20261010T132231Z-63skc5_5/candidate-taint.yml)
and [generated report](results/spec-refinement/20261010T132231Z-63skc5_5/REPORT.md).
The complete original seed, attempts, diagnostics and before/after transitions
are preserved. The candidate policy is **partial and semantically unverified**.

Offline replay in
[`results/spec-refinement/20261010T133240Z-a27hhic_/`](results/spec-refinement/20261010T133240Z-a27hhic_/)
produced byte-identical `state.json`, `history.json` and candidate YAML, including
the incomplete status, with zero API attempts. Reproduce that replay with:

```bash
python3 scripts/refine_taint_spec.py \
  --from-run evaluation/results/automatic-spec/20261010T072616Z-3vh4e4tl \
  --responses-dir evaluation/results/spec-refinement/20261010T132231Z-63skc5_5
```

After step 2b, **46 repository tests pass**. Added tests cover signature mismatch,
atomic quarantine, abstention, unknown-ID contamination, bounded feedback,
request/round/cost limits, transport errors, early stopping, preserving resolved
methods, seed reconstruction/integrity checks, credential-free dry-run/replay and
replay mismatch detection. Tai-e policy loading/propagation remains untested.

### Interpretation and experimental controls

This change simultaneously introduces smaller batches, a revised prompt, a
signature field, explicit reference slots and diagnostic feedback. A before/after
comparison does **not isolate the effect of feedback**, nor establish a novel
algorithm or improved security accuracy. A later experiment should compare:

1. The same pending-method set, same model and same revised schema/slots/context,
   in small batches, without prior proposals or checker diagnostics.
2. The identical setup with diagnostics and bounded retry.

Use matched request/token budgets, report actual consumption, retain every
attempt, and count abstentions and removed rules. Repeated trials are preferable
to interpreting one provider-routed sample as a general result. Semantic review
and subsequent warning-level experiments must be independent of simply reducing
warnings or satisfying the validator. Improvements on this inspected pilot are
development results; a held-out evaluation is still needed.

### Step 2b checkpoint (subsequently approved)

Tai-e execution, warning-level semantic review, rule-removal auditing and any
CFG/DFG-based judge remain separate stages. Refinement only addresses structural
failures; accepted-but-semantic errors are deliberately not patched by hand.
Review the bounded pilot outcome before deciding which stage to implement next.
The next choice is between (a) running the unchanged partial candidate through
Tai-e as a clearly labelled diagnostic baseline, then using warning evidence for
rule-level auditing, or (b) adding a separate semantic rule-audit stage first.
Option (a) preserves a useful baseline for later ablations; it must not be presented
as a finished analyzer or scored as if its rules were verified. The user approved
option (a); its implementation and results follow. No semantic judge was added.

## Step 3: unchanged-policy Tai-e diagnostic

`scripts/run_spec_diagnostic.py` now runs the saved partial policy through Tai-e
and associates actual source/sink records with inferred rules and LLM evidence.
The read-only Java exporter is version-coupled to Tai-e 0.5.4's taint-result API.
See the [diagnostic guide](../analysis/diagnostic/README.md) for usage and checks.

The original Plexus Utils vulnerable revision, compiled artifacts, entry adapter,
Java runtime and Tai-e JAR were checked against the catalogue. The configuration
remained `cs:ci;only-app:false`; no manual taint YAML or generic baseline transfer
file was added. Tai-e's ordinary built-in modelling and implicit entry defaults
still apply. The application itself was not executed and no LLM calls were made.

The generated YAML was copied **byte-for-byte unchanged**. Its SHA-256 is
`7050eb37f681e68506bdb62deae7311498370f3e39006a81fc8ecf9d1afca465`.
All 6 source, 9 sink and 11 transfer rules matched Tai-e's logged resolved
configuration exactly, with no missing/extra rules. Console counts and warning
strings matched the structured exporter. The policy remains incomplete because
seven method classifications are unresolved; successful execution does not erase
that condition or validate its security semantics.

| Diagnostic result | Observed value |
| --- | ---: |
| Reported source–sink pairs | 1,032 |
| Unique reported source points | 86 |
| Unique reported sink points | 12 |
| Project/adapter source -> project/adapter sink | 36 |
| Project/adapter source -> library sink | 72 |
| Library source -> project/adapter sink | 308 |
| Library source -> library sink | 616 |
| Source rules associated with warnings | 5/6 |
| Sink rules associated with warnings | 5/9 |
| Wall time, final diagnostic run | 9.036 seconds |
| Peak process RSS, final diagnostic run | 1,751.38 MiB |

The pairs form a complete **86 x 12** endpoint cross-product. This is a warning
sign of very broad taint mixing under these specifications/settings, not evidence
of 1,032 independent vulnerabilities. It does not identify which transfer caused
that mixing or prove every pair infeasible. The 36 project-to-project pairs are
not automatically true positives, and library-related pairs are not automatically
false positives.

### Which inferred endpoint rules contribute warnings?

Each row below counts the warnings whose actual source/sink record matches that
rule. Source totals and sink totals each sum to 1,032; they should **not** be added
together. A rule can match many call sites, including library calls not shown in
the original bounded project-context prompt.

| Source rule | Slot | Pairs |
| --- | --- | ---: |
| `File(String)` | argument 0 | 600 |
| `System.getProperty(String)` | result | 276 |
| `ZipEntry.getName()` | result | 132 |
| `ZipInputStream.getNextEntry()` | result | 0 |
| `Expand.extractFile(...)` | argument 3 | 12 |
| `FileUtils.resolveFile(File,String)` | argument 1 | 12 |

| Sink rule | Slot | Pairs |
| --- | --- | ---: |
| `PlexusUtilsEntry.main(String[])` | argument 0 | 0 |
| `FileInputStream(File)` | argument 0 | 172 |
| `FileOutputStream(File)` | argument 0 | 172 |
| `FileOutputStream.write(byte[],int,int)` | argument 0 | 0 |
| `FilterInputStream.read(byte[])` | argument 0 | 0 |
| `String.indexOf(String)` | argument 0 | 516 |
| `String.toLowerCase(Locale)` | argument 0 | 0 |
| `Expand.extractFile(...)` | argument 0 | 86 |
| `FileUtils.resolveFile(File,String)` | argument 1 | 86 |

All eleven transfer rules loaded, but their **necessity is not measured**. We
record null transfer dependencies instead of guessing which summaries each warning
used. A separate rule-removal experiment is needed to measure marginal impact;
even then, redundancy can hide a rule's relevance.

### Concrete useful and misleading examples

1. **Useful candidate endpoint pair:** warning `Wd41594888181160e65d5` links
   `Expand.expandFile`'s `ze.getName()` call at `Expand.java:116` to the
   `FileOutputStream(f)` constructor at line 178. Inspection shows the entry name
   is passed to `extractFile`, resolved at line 153 using `FileUtils.resolveFile`,
   then used for the output file. The resolver at `FileUtils.java:1367` handles
   absolute/relative paths and canonicalization but contains no base-directory
   containment check. This is code-supported evidence for a relevant CWE-22
   candidate, not a completed exploitability proof or an adjudicated benchmark TP.

2. **Wrong trust boundary:** warning `Wee2fd6449d994e324ec0` starts at the adapter's
   `new File("analysis-input.zip")`, and `W179b470594ea65135639` at
   `new File("analysis-output")`; both reach the project output-stream sink.
   Those pathname strings are literal constants. The inferred `File(String)`
   source rule introduces taint merely because a path object is constructed;
   it confuses consuming a path with receiving attacker-controlled path data.
   An untrusted archive's *contents* do not make these literal pathname strings
   attacker-controlled. This rule labels 600 pairs at their source endpoint.

3. **Wrong sink semantics:** 516 pairs end at `String.indexOf(String)` calls
   in library string/formatting/hostname code. A string-search argument does not
   itself select a filesystem/resource access. These pairs demonstrate how an
   incorrect sink interpretation dominates raw warning volume. We retain their
   unreviewed status in the output instead of inventing a full warning-level oracle.

4. **No warning does not mean a correct rule:** the previously identified
   byte-buffer sinks and `toLowerCase(Locale)` sink produce zero pairs here.
   Their semantics remain questionable even though they did not increase this
   run's warning count. This distinguishes rule correctness from observed impact.

**Research implication:** inferred rules are global method-level specifications,
but their evidence was drawn from bounded, local call-site windows. Their use on
many unseen library calls exposes an applicability gap worth auditing. The current
experiment supports a failure analysis and motivates evidence-linked rule-impact
experiments; it does not establish a novel algorithm or improved detection accuracy.

### Artifacts and validation

Final diagnostic:
[`results/spec-diagnostic/20261010T134337Z-_j89bi8c/`](results/spec-diagnostic/20261010T134337Z-_j89bi8c/),
with [generated report](results/spec-diagnostic/20261010T134337Z-_j89bi8c/REPORT.md),
[rule attribution](results/spec-diagnostic/20261010T134337Z-_j89bi8c/rules.json),
and [structured warnings](results/spec-diagnostic/20261010T134337Z-_j89bi8c/warnings.json).
All warnings are `unreviewed`; source windows are attached where available.
Tai-e's complete taint-flow graph is retained for later investigation.

An initial integration run in
[`results/spec-diagnostic/20261010T134128Z-sw1ws3qy/`](results/spec-diagnostic/20261010T134128Z-sw1ws3qy/)
also produced 1,032 pairs (13.310 seconds, 1,920.97 MiB peak RSS). After strengthening
the exporter's project-class membership accounting to use all compiled classes,
the final run produced byte-identical `flows.txt` and the same scope counts. These
two integration runs are a consistency check, not a controlled performance study.

**54 repository tests pass**, including unchanged-policy/state checks, exact loaded
rule comparison, unexpected sanitizer rejection, endpoint/rationale mapping,
unmatched/duplicate/count-mismatched warnings and empty-output handling. Two live
Tai-e runs also exercised exporter compilation, policy loading, taint propagation
and consistency checks. No changes were made to the candidate policy.

### Step 3 design checkpoint (subsequently approved)

The next proposed experiment is **independent single-rule removal**, always
restoring the saved baseline before each run. A small initial budget could test
the overbroad `File(String)` source and selected inferred transfer summaries
(particularly `Expand.extractFile`'s argument 3 -> argument 0 transfer). Compare
stable warning IDs and retention of the relevant project endpoint pair; do not
optimize merely for fewer warnings or equate a disappearance with proof of falsity.
This measures rule impact beyond endpoint counts. The user approved the three
independent removals described below; they were implemented as step 4.

No semantic filtering, LLM judge, fixed-version diagnostic, precision/recall/F1
calculation, or controlled rule-removal run has been performed in step 3.

## Step 4: three independent rule-removal experiments

After approval, `scripts/ablate_taint_spec.py` was implemented and run on the saved
Plexus Utils diagnostic baseline. Each variant began with the same original
26-rule policy and removed **exactly one rule**, resulting in 25 rules. Removals
were not cumulative. The baseline's source revision, entry, compiled artifacts,
Tai-e/JDK versions, exporter, heap, timeout and analysis options were held fixed.
All three variants passed the unchanged-input checks and exact loaded-policy check.
No LLM calls, manual replacement rules, semantic filters or policy promotion occurred.

Targets were selected explicitly after inspecting the baseline; this is a small
development experiment, not an automatic selection algorithm or held-out evaluation.
The watched pair was `Wd41594888181160e65d5`, the previously observed
`ZipEntry.getName()` -> project `FileOutputStream(File)` candidate. Its retention
is only a useful regression observation, not a recall metric or an oracle supplied
to inference.

| Independent configuration | Pairs | Lost vs baseline | Added | Watched project pair retained? |
| --- | ---: | ---: | ---: | --- |
| Original policy | 1,032 | — | — | Yes |
| Remove `File(String)` argument-0 source | 432 | 600 | 0 | Yes |
| Remove `Expand.extractFile` argument 3 -> argument 0 transfer | 860 | 172 | 0 | Yes |
| Remove `FileUtils.resolveFile` argument 1 -> result transfer | 946 | 86 | 0 | **No** |

These are warning-ID set differences, not merely differences between counts.
No new warning IDs appeared in any variant. The original policy and baseline
artifacts were hash-checked after the experiment and remained unchanged.

### Interpretation: endpoint deletion versus propagation effects

**Removing the `File(String)` source:** all 600 lost warnings originated at the
removed source rule; **zero additional warnings were lost at other source rules**.
This confirms its large reporting footprint, but the count reduction is explained
by deleting a source definition. It does not demonstrate improved propagation
precision or prove that all retained warnings are valid. The earlier constant-path
examples independently support concern about that source's trust-boundary semantics.

**Removing the `Expand.extractFile` transfer:** the 172 lost pairs split into:

- 86 ending at the project `FileInputStream(srcF)` constructor in `Expand.java:109`.
- 86 ending at argument 0 of the `extractFile(...)` call in `Expand.java:114`.

Those source and sink rules remained configured; their disappearance is therefore
a **non-endpoint marginal effect of removing the transfer**. Inspection of the
method body shows that argument 3 (`entryName`) is used to resolve the extracted
output path, while argument 0 (`srcF`) is the original archive path and is read
in an exception message. The body does not copy the entry name into `srcF`.
The removed summary thus has a concrete semantic problem: it invents propagation
from an entry name into the input archive's `File` object. The observed losses
are consistent with that artificial propagation affecting reports under the
context-insensitive analysis. The relevant output-file pair survived. We do not
use this observation to label all 172 warnings as independently adjudicated FPs.

**Removing the `FileUtils.resolveFile` transfer:** all 86 lost pairs ended at the
project's `FileOutputStream(f)` call at `Expand.java:178`, including the watched
archive-name -> output-file candidate. The method actually constructs and returns
a `File` from its filename argument, so the summary has a plausible semantic basis.
Its removal eliminated reporting of this output path under the current remaining
models. This supports retaining/reviewing it differently from the `extractFile`
summary; it does not prove the summary is universally necessary, fully precise,
or that the watched warning is an exploitability proof.

### Course-project takeaway

The results distinguish three mechanisms that endpoint totals alone could not:

1. Removing an overbroad source removes its own reports without affecting other
   source-origin reports in this configuration.
2. Removing a semantically unsupported transfer changes reports at retained
   endpoints while preserving the candidate of interest.
3. Removing a plausible transfer also reduces warnings, but loses that candidate.

Consequently, "minimize warning count" is not a defensible rule-selection objective.
Rule semantics, evidence and downstream effects need to be considered together.
The implemented contribution so far is an **auditable specification-inference and
bounded counterfactual analysis workflow**, supported by this focused failure
analysis. This is more informative than merely wiring an LLM to Tai-e, but we
still must not claim that single-rule ablation, tool validation or the broad
neuro-symbolic architecture are themselves new research ideas. A comparative,
held-out evaluation of an evidence-guided audit strategy remains future work.

### Artifacts, limits and validation

Suite:
[`results/spec-ablation/20261010T142859Z-_s2s72b_/`](results/spec-ablation/20261010T142859Z-_s2s72b_/),
including the [generated report](results/spec-ablation/20261010T142859Z-_s2s72b_/REPORT.md)
and [CSV summary](results/spec-ablation/20261010T142859Z-_s2s72b_/summary.csv).

| Removed rule ID | Analysis seconds | Peak RSS (MiB) |
| --- | ---: | ---: |
| `R72a0bdc16ff0069f` — File source | 9.534 | 1,400.75 |
| `R9686d9aac0f2bee5` — extractFile transfer | 9.579 | 1,448.34 |
| `R9e0858ccfc598856` — resolveFile transfer | 9.888 | 1,437.47 |

Each run retains the removed rule/proposals, original and variant policies, exact
commands, measurements, loaded rules, raw endpoints, warning IDs and full lost/
added/retained ID sets. The suite records expected policy hashes before execution.
See [the reproducible ablation command](../analysis/diagnostic/README.md#step-4-independent-single-rule-ablations).

There was one analysis per removal. Results depend on this partial policy and one
project/version; they do not establish general performance, precision or recall.
Baseline warning lists matched in two earlier integration runs, but this suite
does not include randomized/repeated or interaction ablations. No-change results
in future experiments may reflect redundant summaries or masking. Individual
warning path dependencies are still not reconstructed; measured marginal effects
must not be confused with a proven runtime path.

**65 tests pass.** New checks cover exact single-rule removal, removal of duplicate
supporting proposals, immutable/independent variants, unknown/duplicate target
rejection, the three-run cap, warning-ID integrity, direct versus non-endpoint
losses, added warnings, watched-pair disappearance, and normalized analysis-option
comparison. The recorded settings of all three live runs were also checked against
the baseline. All original artifacts remain unchanged. No revised policy has been
selected or substituted for the baseline.

### Next design checkpoint

The recommended next stage is a **semantic rule audit** that proposes `keep`,
`reject` or `uncertain` with method-body evidence and the measured impact, but
does not automatically change the policy. This would distinguish semantically
wrong rules from useful summaries before designing any automatic acceptance
strategy. It should be evaluated against a no-impact/evidence-only control and
held-out cases, not trained to preserve this single watched warning. This audit
stage was the next unimplemented checkpoint at the end of Step 4. The user
subsequently approved the advisory implementation described below; no additional
ablations or other-project runs were included in that approval's implementation.

## Step 5 — Evidence-citing semantic audit (12 October 2026)

### Implemented design

[`scripts/audit_taint_spec.py`](../scripts/audit_taint_spec.py) reviews the **26
active rules** in the unchanged plexus-utils policy. The seven unresolved methods
from refinement remain outside this audit. The model is the same Qwen model used
for generation; using the same model is a controlled implementation choice, not
an independent semantic oracle. The
[audit prompt](../analysis/specification/audit.md) specifies `keep`, `reject`, or
`uncertain`, exact rule/method identities, code citations, limitations and an
interpretation of measured impact. See the [reproduction guide](../analysis/specification/SEMANTIC_AUDIT.md).

Each request contains deterministic method/call context, longer project IR and
saved source windows, and rule-removal measurements when available. All 26 rules
receive baseline endpoint counts where applicable; only three have measured
removal effects. `not_measured` is explicit for the other rules. Original model
proposal rationales, human assessments, watched warning IDs/status, fix labels,
and this report are **not** model inputs. This prevents direct leakage of our
case-study answers, but does not remove the selection bias from manually choosing
the three exploratory ablations.

Citation checks require an exact supplied excerpt (at least eight characters
after trimming) and a source/IR/call citation for keep/reject. They check textual
grounding, **not whether the cited evidence entails the recommendation**. Missing
or invalid outputs are not silently converted to `uncertain`. There are no repair
calls, retries, revised policy generation, or Tai-e runs at this stage.

Both standard and evidence-only dry runs completed. The evidence-only data were
checked to be identical except for omitting all impact fields, including baseline
endpoint counts. No paid evidence-only experiment has been run, so this stage
does not establish that impact-aware review outperforms code-only review.

### Qualitative findings: why the audit must remain advisory

Code inspection of the returned recommendations already exposes reasoning
failures even among entries that pass the strict citation checks:

| Rule | Model recommendation | Code-grounded concern |
| --- | --- | --- |
| `R235fcb23b5531f6e`: `File.getAbsoluteFile`, receiver → result | reject | The rationale says the method does not introduce untrusted data, which evaluates a **source** criterion rather than the proposed **transfer**. A transfer need not introduce new external data. |
| `R843094a17de60c12`: `FileOutputStream.write(byte[],int,int)`, sink argument 0 | keep | Argument 0 supplies file **contents**. The path was consumed when constructing the stream; this argument is not a path sink under the chosen CWE-22 model. |
| `R9686d9aac0f2bee5`: `Expand.extractFile`, argument 3 → argument 0 | keep | The response describes propagation from `entryName` into local `File f`, but the actual destination is argument 0, **`srcF`**. `f` is a different object produced by `resolveFile(dir, entryName)`; the cited body does not implement the proposed mutation into `srcF`. |

The `FileInputStream(File)` sink may be appropriate as an API rule, but its audit
rationale incorrectly describes `srcF` as derived from an archive entry. The
saved `Expand.expandFile` body opens `srcF` **before** reading entry names. This
distinguishes a potentially reasonable recommendation from an unsupported
explanation. Similarly, receiving tainted data in a helper is not by itself proof
that every call to that helper should introduce a fresh taint source.

These are concrete reasons not to apply the audit mechanically or report its
accepted recommendations as semantic ground truth. A promising next design
change is explicit, named slot grounding (e.g., `from: 3 = entryName`,
`to: 0 = srcF`) plus a required explanation of that precise relationship. That
would remain a hypothesis to test, not a guaranteed fix or a novelty claim.

### Live pilot results and reproducibility

Live run: [`20261012T005739Z-i806j7h0`](results/spec-audit/20261012T005739Z-i806j7h0/REPORT.md).
The generated report lists every rule; `recommendations.json` includes the exact
citations, rationale, impact interpretation and limitations.

| Outcome | Rules |
| --- | ---: |
| Citation-valid `keep` recommendations | 12 |
| Citation-valid `reject` recommendations | 6 |
| Citation-valid `uncertain` recommendations | 0 |
| Rejected responses: invalid exact citations | 8 |
| Total rules submitted | 26 |

The run is deliberately marked **incomplete**, because only 18/26 recommendations
pass the output/citation contract. All nine planned requests returned responses;
there were no repair attempts. Provider: SiliconFlow; model:
`qwen/qwen3-coder-30b-a3b-instruct`; 53,441 prompt tokens, 10,595 completion tokens;
reported cost **$0.00670747**; elapsed **272.77 seconds**. These figures are for
the semantic audit only, not the entire pipeline.

Citation failures have mixed causes: JSON-escaped call-site strings, omitted
line prefixes, rewritten whitespace, and source text attributed to an IR evidence
unit. They are **not all hallucinated code**. A future evidence-format improvement
should expose call-site source as separately addressable plain-text lines while
preserving strict provenance. The current pilot is preserved unchanged rather
than silently relaxing validation to improve coverage.

Offline replay [`20261012T010352Z-0h485acj`](results/spec-audit/20261012T010352Z-0h485acj/REPORT.md)
reproduced the same recommendations and rejections with zero API calls. An earlier
replay attempt correctly rejected a prompt mismatch caused by a case-insensitive
filesystem collision between `audit.md` and the initially named `AUDIT.md` guide.
The guide now has the distinct name `SEMANTIC_AUDIT.md`; the original prompt was
restored byte-for-byte from the live snapshot. The live process had loaded its
prompt before that collision, so its nine requests used the intended audit
instructions. A regression test now checks that the guide and prompt are distinct.

**84 tests pass**, covering schema/citation checks, missing and duplicate IDs,
per-rule validation, batching, source hash/path checks, dry-run isolation, offline
replay, replay mismatch rejection, request-budget bounds and prompt/guide
separation, alongside all earlier-stage tests. Original input hashes were unchanged.
The active policy remains SHA-256
`7050eb37f681e68506bdb62deae7311498370f3e39006a81fc8ecf9d1afca465`.

### Design checkpoint before the next experiment

Do **not** automatically apply the 18 citation-valid recommendations: the concrete
slot/role mistakes above show why that would be unsafe experimentally. Recommended
next step, subject to user approval: explicit named slot grounding and cleaner
line-addressable evidence, tested against this frozen pilot. Keep rule decisions
advisory. After stabilizing that contract, compare impact-aware versus evidence-only
review under a predeclared protocol on additional subjects. No improved-rule run,
paid evidence-only control, new Tai-e analysis or policy promotion was performed
as part of this step.

## Step 5b — Named-slot, line-cited audit (12 October 2026)

The user approved continued hardening before automatic policy acceptance. The
auditor now defaults to **v2**, with the original v1 format explicitly selectable
for reproduction. No existing experiment directory or taint policy is overwritten.

### Changes and experimental boundary

1. **Exact named slots.** Every rule receives mechanically derived bindings for
   its `index`, `from` and/or `to`, including API argument position, name, type,
   kind and name provenance. The catalogue's parameter-list order determines the
   API position. Its individual variable `index` values do not: for example,
   `extractFile` argument 3 is `entryName`, whose IR variable index is 4; argument
   0 is `srcF`, whose IR variable index is 1. This mapping is extracted from the
   catalogue, not manually encoded for this API. Missing formal names remain
   marked placeholders; call-site actual expressions are mapped separately.
2. **Line-addressable evidence.** Source and IR units expose decoded text for each
   individually identified line. Call-site source is no longer nested inside an
   encoded JSON string. Citations must identify the unit and the precise line;
   line labels are not part of the quoted text. The original method/call selection
   and context bounds are unchanged.
3. **Stronger output contract.** The model must copy the exact binding object and
   explain the specific slots in `slot_reasoning`. Mismatched names/types/slots,
   missing explanations, wrong line IDs and non-verbatim excerpts fail validation.
   Exact copying is not semantic verification: a response can still copy the
   correct slot while reasoning about the wrong value.
4. **Versioned replay.** `--audit-format v1` preserves the frozen request contract;
   v2 requires a new response. The original pilot replayed with identical 12 keep,
   6 reject and 8 invalid outcomes, without API calls. Requests from one format
   cannot be reused as responses to the other.

The [v2 prompt](../analysis/specification/audit-v2.md) explains source/sink/transfer
roles and argument mutation in general terms. It contains no API-specific answer
list, prior manual verdicts, fixed-version labels or watched-warning identity.
All 26 existing rules are submitted to the same model under the same nine-batch,
4,000-output-token, no-retry and $0.05 reported-cost-threshold settings as v1.
Both the evidence presentation and instructions changed, so any observed change
cannot be attributed exclusively to slot naming or citation formatting. This is
a **development comparison on plexus-utils**, not an accuracy or held-out result.

**98 tests pass.** Added tests cover parameter positions versus IR IDs, absent
formal names, inconsistent parameter types, constructor/return slots, exact
binding equality (including boolean versus integer slots), mandatory slot
reasoning, line-specific quotations, embedded quote characters, decoded call-site
source, IR statement/line mapping and rejection of legacy responses as v2 output.
An evidence-only v2 dry run is available; no paid control was run in this step.

### Frozen-pilot comparison: mixed/negative result

New live run:
[`20261012T010937Z-_3o_ccys`](results/spec-audit/20261012T010937Z-_3o_ccys/REPORT.md).

| Contract-valid outcome | Original v1 | Named-slot v2 |
| --- | ---: | ---: |
| Keep | 12 | 8 |
| Reject | 6 | 2 |
| Uncertain | 0 | 1 |
| Not accepted: invalid/incomplete response | 8 | 15 |
| Total rules submitted | 26 | 26 |

These are **output-contract counts, not TP/FP or accuracy**. V1 failed eight
individual exact-citation checks. V2 had five batches that returned only one of
their three requested rules. The strict batch-ID contract therefore rejected all
three entries in each of those batches: ten missing entries plus five returned
entries withheld because the batch was incomplete. The other eleven entries
passed binding and line-citation validation. There were no retries, relaxed
validation, or post-hoc recovery calls. Both runs are explicitly incomplete.

| Development probe | V1 | V2 | Interpretation from source inspection |
| --- | --- | --- | --- |
| `getAbsoluteFile`, receiver → result | reject | keep | V2 no longer rejects a transfer merely because it does not introduce external input. |
| `FileOutputStream.write(byte[],int,int)`, argument 0 sink | keep | keep | Still confuses file contents with path data, despite correctly naming the byte-array argument. |
| `extractFile`, entryName → srcF | keep | keep | V2 copies the correct slots but still cites construction of a different local file as support for mutation into srcF. |
| `String.indexOf(String)`, argument 0 sink | invalid citation | reject | V2 returns a grounded rejection of a string-search argument as a filesystem path sink. |

This comparison demonstrates **better inspectability, not established semantic
improvement**. In particular, correct binding echoes do not prevent erroneous
reasoning about those bindings. Contract-valid coverage decreased from 18/26 to
11/26. That is a result to report, not hide by retuning or repairing the run.

The same model/provider completed nine requests: 72,933 prompt tokens and 11,496
completion tokens, **$0.00832419** reported cost and **278.23 seconds** elapsed.
No Tai-e reruns or policy changes occurred. The source policy remains
`7050eb37f681e68506bdb62deae7311498370f3e39006a81fc8ecf9d1afca465`.
Offline replay
[`20261012T011435Z-bm9_pdo8`](results/spec-audit/20261012T011435Z-bm9_pdo8/REPORT.md)
reproduced the evidence, recommendations and rejections with zero API calls.

### Next design decision: progress to integration without trusting the auditor

Recommended, **not yet implemented or selected**: use the structurally accepted
generated specification as the first end-to-end pipeline's policy, preserve audit
recommendations as advisory evidence, and evaluate automatic rule filtering as a
separate ablation. This permits progress to candidate fusion, the final judge and
evaluation without pretending that the semantic auditor is reliable enough to
serve as an oracle. The specification itself also remains an unverified hypothesis.

An alternative is to spend another development iteration on per-rule requests or
partial-batch recovery and stronger semantic checks before enabling rule filtering.
That may improve coverage, but has not been tested and will not by itself resolve
the two semantic failures above. The user should select the acceptance design
before a revised policy or the next integration stage is implemented.

## Step 6 — Integrated candidates and final judge (12 October 2026)

The user selected the **advisory-only auditor** integration design. Implemented
[`scripts/run_neurosymbolic.py`](../scripts/run_neurosymbolic.py), with the
[reproduction guide](../analysis/pipeline/README.md), independent candidate prompt
and final-judge prompt. This command starts from a saved automatic catalogue and
refined specification. Earlier build/catalogue/generation/refinement commands
remain separate; no already saved model-generated specification is regenerated.

### Implemented behavior

- Run Tai-e with the structurally accepted generated policy **unchanged**, or
  explicitly reuse a checked diagnostic. No manual YAML or semantic rule filter
  is added. Reconstruct saved warnings and verify the loaded configuration.
- Build a common policy/program package without fix-file selection. The LLM
  candidate branch gets that package, not Tai-e warnings, manual hints, previous
  baseline findings or audit recommendations. Branches are information-independent
  but executed sequentially. Tai-e sees bytecode and policy; the LLM sees the same
  policy plus exported code evidence, not identical analysis capabilities.
- Validate candidate call IDs, reference-typed sink slots, source-call references
  and method/line quotations. Preserve invalid output separately from a valid
  empty result. The LLM may propose a code-grounded sink absent from the policy.
- Group candidates at an exact sink call and slot. Preserve every original Tai-e
  warning-pair ID, source endpoint and branch origin. Groups are review units,
  **not asserted vulnerability equivalence classes** or individual TP/FP labels.
- Judge one code-covered group per request, requiring an exact candidate ID,
  code citations, source/sink/guard analysis and limitations. Model decisions are
  `report`, `dismiss` or `uncertain`; absent code, malformed responses and budget
  failures are separately `unreviewed`. A library endpoint outside the saved
  catalogue is retained as unreviewed, never silently classified as safe.
- Save advisory audit recommendations as a separate log, after reconstructing
  them from saved responses. They never change policy, candidate retention or
  model prompts in this integration variant.

The initial implementation duplicated source and IR in the model context. Its
first live run exposed a candidate output limit and two judge-input limits. The
corrected default is **source-first** presentation, with IR used when source is
absent; the complete export remains separately saved. Opaque warning-ID lists
remain in artifacts while the judge receives their count and actual endpoint
evidence. The candidate output budget is 8,000 tokens; each judge remains at
4,000. Exact legacy requests remain reproducible with the full-context option.

This is an implementation correction, **not a controlled ablation**: input
presentation, candidate prompt brevity instructions and output budget changed
together. The failed pilot is preserved. No source code was edited to match model
answers, no labels were introduced, and no results were silently repaired.

### Initial integration pilot (preserved failure record)

Run: [`20261012T020207Z-ctmtaur_`](results/neurosymbolic/20261012T020207Z-ctmtaur_/REPORT.md).
The fresh Tai-e execution loaded all 26 original rules and reproduced **1,032
warning pairs**, in **11.314 seconds**. These grouped into 12 sink/slot locations:
four with code coverage and eight library locations outside the saved catalogue.

The candidate completion hit the 4,000-token limit; no partial JSON was accepted.
Two judge requests exceeded the 200,000-character input cap (by 18 and 57
characters), one returned an invalid quotation, and one produced a contract-valid
`report` for the archive-input `FileInputStream` call. Final status: **incomplete**;
one report and eleven unreviewed groups. That report is a model hypothesis, not a
verified true positive. Three API calls cost **$0.01584037**. No retries occurred
inside the run. The corrected pilot reuses this checked Tai-e output instead of
rerunning or changing the policy.

### Corrected integration pilot: runnable, but not reliable

Run: [`20261012T020748Z-5tw5sci7`](results/neurosymbolic/20261012T020748Z-5tw5sci7/REPORT.md).
This run reused the first pilot's checked Tai-e diagnostic and unchanged policy.
Source-first presentation reduced shared evidence from 176,727 to 123,626
characters. All four covered judge inputs passed the size cap, and the candidate
completion stopped normally within its new 8,000-token allowance. Nevertheless,
the final status is **incomplete**, not a successful detection result.

| Measurement | Corrected pilot |
| --- | ---: |
| Tai-e warning pairs retained | 1,032 |
| Exact sink-call/slot review groups | 12 |
| Raw LLM candidate proposals | 12 |
| Contract-valid LLM candidates | 0 |
| Judge `report` decisions passing the output contract | 1 |
| Judge `dismiss` / `uncertain` decisions | 0 / 0 |
| Unreviewed: invalid judge citations | 3 |
| Unreviewed: library code outside catalogue coverage | 8 |

Eleven candidate proposals cited a method/line combination absent from the
supplied evidence; one selected a primitive-valued sink slot. The validator
rejects a proposal if any required citation is invalid, even when it also contains
a valid quotation. These are rejected proposals, **not twelve false positives**,
and zero accepted candidates is not a valid empty detection result. Three of
the four code-covered judge responses also failed method/line citation checks.

The one contract-valid report, `G37a34646a97255d6a1b0`, illustrates a separate
semantic failure. It claims that the archive-input `FileInputStream(srcF)` at
`Expand.java:109` receives a path derived from `ZipEntry.getName()` at line 116
and `FileUtils.resolveFile(dir, entryName)` at line 153. Source inspection shows
that the archive is opened **before** its entries are read; `srcF` is passed
separately from `entryName`, and the resolved extraction path is local `f`, not
`srcF`. The adapter supplies the archive path as `analysis-input.zip`. Thus the
quoted lines exist, but do not establish the claimed flow. No verified true
positive is claimed. The saved model report remains unchanged for inspection;
this qualitative review does not silently rewrite it or establish benchmark
TP/FP labels for all groups.

The model was `qwen/qwen3-coder-30b-a3b-instruct`, served by SiliconFlow. Five
requests used 235,723 prompt tokens and 5,235 completion tokens, cost
**$0.01796641**, and took **179.98 seconds**. Across the initial and corrected
integration pilots there were eight API requests costing **$0.03380678** and one
fresh Tai-e execution. Earlier specification/audit costs are not included.

Offline replay
[`20261012T104637Z-96t_rm6m`](results/neurosymbolic/20261012T104637Z-96t_rm6m/REPORT.md)
made **zero API calls** and reproduced all ten checked artifacts byte-for-byte:
shared evidence, full program evidence, policy, advisory log, Tai-e warnings,
valid and invalid LLM candidates, grouped candidates, decisions and findings.
Replay's `reported_cost` represents the original responses' recorded usage,
not a new charge. All 1,032 original warning IDs occur exactly once across the
12 groups; input hashes were unchanged. Exit code 1 is expected for these
incomplete runs, including their replay.

The course-project lesson is concrete: checked citations and source/sink slot
identities improve inspectability, but do not enforce a valid data-flow witness.
A possible next design is to require checkable def-use/call-argument edges for
the claimed path, distinguishing unsupported flow from missing evidence. This
is a **proposed, unimplemented extension**, not an established novelty claim or
measured improvement. Any novelty claim still needs comparison with prior work.

### Validation and remaining evaluation work

**116 tests pass**, including candidate identity/slot/citation validation, exact
location fusion and preservation of warning pairs, library coverage boundaries,
judge schema, network-free replay, request budgets, dry-run isolation, partial
branch failure, source-first fallback and immutability, and compact judge inputs.
The original 98 earlier-stage tests remain included.

The analyzer's reported findings are still model judgments. No benchmark TP/FP,
precision, recall or F1 is computed at this stage. The next checkpoint should
freeze ground truth and matching units, treatment of unreviewed groups and failed
runs, fair baseline evidence, held-out subjects and ablations before the final
ten-version experiment suite. The development project remains plexus-utils.

## Step 7 — Evaluation protocol draft (12 October 2026)

Prepared [draft v0.1](NEUROSYMBOLIC_EVALUATION_PROTOCOL.md) after inspecting the
subject manifest, legacy protocol, both existing proxy evaluators, local dataset
fix metadata and current pipeline contracts. This is a **design checkpoint**,
not frozen ground truth, an implemented new scorer, or an experiment result.
No model calls, Tai-e reruns or new paid experiments occurred in this step.

The proposed primary unit is the targeted flaw in one project/version: ten
planned rows across five paired subjects. Reviewed case cards must establish
the flaw and its repair under the supplied adapter before assigning positive
or negative truth. A fixed-version warning is not automatically a false positive;
an unrelated genuine finding does not automatically detect the target CVE.

The protocol separates TP/FP/TN/FN from unresolved decisions and blocks complete
F1 when cases remain unresolved. It reports detection yield and decision coverage
without dropping failed runs. Secondary reviewed-claim precision has its own
denominator and is not combined with case recall. Raw warning pairs and sink
groups remain available as workload diagnostics, not interchangeable findings.

Proposed comparisons are generated-policy Tai-e, code-only CWE-aware LLM,
generated-policy LLM, Tai-e plus judge without the independent LLM branch, and
the full hybrid. Manual-policy Tai-e is a human-informed reference. Exact shared
requests can be reused; changed judge inputs require separate inference.
Specification generation is charged to every workflow that requires it, even
when physically cached in the experiment. Automatic audit-based filtering is
excluded from the primary study.

Plexus-utils is development data. Prior baseline exposure to the other four
projects and fixed versions is disclosed, so none is described as truly unseen.
Historical proxy F1 scores remain unchanged and are not directly comparable.
The next user decision is whether to adopt this protocol before implementing
case cards, a freeze manifest and the scorer. Full-suite budgeting/preflight
and resolution of ground-truth/coverage questions remain prerequisites to runs.
All 116 existing regression tests still pass; this step changed documentation
only and did not implement the proposed scoring rules.

## Step 8 — Offline scorer and evidence-backed case-card drafts (12 October 2026)

The user approved the evaluation design. Implemented
[`prepare_case_truth.py`](../scripts/prepare_case_truth.py) and
[`evaluate_neurosymbolic.py`](../scripts/evaluate_neurosymbolic.py), with
[five case cards and a reproduction guide](ground-truth/README.md).
No new inference, Tai-e run, build, archive extraction or exploit reproduction
occurred. The legacy scores and saved pilot outputs remain unchanged.

### Implemented and checked

- Prepare ten version-specific truth rows with full commit identity, exact
  candidate matching signatures/slots, exclusions, source snapshots, patch
  evidence, adapter hashes and runtime dependency identities. Source bytes are
  checked against each subject's pinned Git HEAD. Separate shallow checkouts
  require snapshot diffs; the script does not fetch additional history.
- Import a saved full-hybrid run, revalidate its accepted candidates, fusion and
  code-citation-valid decisions, check original input hashes and preserve all
  source warning IDs. No invalid model output is repaired during evaluation.
- Prepare the full six-arm by ten-version comparison grid. Missing runs are
  retained explicitly. Matching annotations are independent from truth and
  reviewed-claim labels; a matching allegation on an established negative case
  can count as FP even though the allegation is false.
- Score TP/FP/TN/FN/U+/U−, coverage and detection yields. Complete case F1 is
  withheld for unresolved truth or predictions. Partial runs can retain a valid
  matched alert, but cannot yield a clean negative merely by failing to report.
- Score reviewed-claim precision and review coverage separately. Sink groups
  retain all original pairs; one group verdict does not label every pair.
- Record draft integrity hashes and distinguish saved response cost from replay
  spend. Final experiment freezing, full-workflow costs and baseline execution/
  normalization are explicitly outside this offline scorer implementation.

**146 tests pass** (30 new tests). They cover confusion counts, fixed-case FP
matching, no labels inferred from version names, valid/failed empty outputs,
partial alerts, abstentions, overload/slot/version identity, duplicate outputs
and locations, one case detection despite multiple reports, unresolved truth,
zero denominators, preserved planned denominators, configuration mismatches,
claim-review coverage, snapshot integrity and replay cost accounting.

### Source review uncovered a ground-truth problem

The intended five-positive/five-negative design cannot yet be assumed:

| Subject | Vulnerable source-review proposal | Pinned fixed-version issue |
| --- | --- | --- |
| zip4j | Present, pending final route review | Canonical path string-prefix comparison has no explicit directory boundary. |
| zt-zip | Present, pending final route review | Canonical prefix guard on names containing `..` needs sibling-prefix analysis. |
| plexus-archiver | Present, pending selection/dependency review | Canonical prefix guard; actual plexus-utils dependency also needs checking. |
| plexus-utils | Present, pending final route review | Absolute-path prefix check after resolution lacks an explicit directory boundary. |
| spark | Unresolved | Adapter omits the actual server/resource-boundary context; `file:` rejection alone does not establish full CVE absence. |

For example, the string `/work/analysis-output-other/probe` starts with
`/work/analysis-output` but is not a descendant of that directory. This explains
why the observed guards require scrutiny. It does **not** establish a reproduced
end-to-end bypass in all four products, nor is it a newly assigned vulnerability
claim. The cards separate these concerns from demonstrated program behavior.

All ten machine-readable truth labels remain `unresolved` until independent
review/approval. Four positive proposals are documented in the cards, not
silently installed as gold labels by the assistant. The cards are evaluator-only
and are never added to model evidence. Fixed revisions must not be relabeled
negative merely to obtain a balanced table. Changing revisions or narrowing the
target requires an explicit, uniformly applied protocol amendment.

### Reproduction artifacts and present result

- Ground-truth draft:
  [`20261012T143702Z-m9obodpa`](results/ground-truth/20261012T143702Z-m9obodpa/README.md).
- Review grid using the preserved corrected live pilot:
  [`20261012T143718Z-euq37md9`](results/evaluation-review/20261012T143718Z-euq37md9/suite-index.json).
- Provisional score report:
  [`20261012T143728Z-7270467e`](results/neurosymbolic-metrics/20261012T143728Z-7270467e/REPORT.md).
- Separate replay-import check:
  [`20261012T143728Z-o3dkvngq`](results/neurosymbolic-metrics/20261012T143728Z-o3dkvngq/REPORT.md).

The imported development run retains **1,032 pairs and 12 groups**. One of the
60 planned method/case cells is populated; **59 are missing**, not negatives.
Ten truth rows are unresolved; their repetition across the six methods is not
60 independent ground-truth cases. Case F1 is N/A. These are workflow validation
results, not a new analyzer accuracy experiment. Replay retains the historical
$0.01796641 response usage but correctly records zero new API spend; this step
itself cost zero API calls. The live import's cost describes its original pilot,
not a charge incurred by this scoring step.

The next checkpoint is to resolve the fixed-guard and Spark-scope questions,
then approve the case cards. Remaining implementation includes the missing arm
runners/normalizers and full-suite budget preflight/freeze before paid execution.
The current analyzer's citation and semantic failures remain unresolved; a
working scorer does not make it a reliable analyzer.

## Step 9 — Scope decision and six-arm execution preparation (13 October 2026)

The user requested completion of ground-truth preparation and evaluation
integration, then explicitly chose **"Keep unresolved labels explicit"** rather
than extending the investigation of the fixed versions. The bounded study's
scope is now fixed with unresolved labels retained. This is not approval of
positive/negative exploitability labels. No unsupported TNs or complete F1 will
be manufactured. The five case cards remain the source-review evidence record.

An advisory check also confirmed that Spark's published case concerns remote
static-file disclosure, which is broader than the supplied synthetic adapter;
see the [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2018-9159).
No additional exploit investigation or execution was performed in this step.

### Implemented comparison execution

- [`run_comparison_arms.py`](../scripts/run_comparison_arms.py) implements
  code-only LLM, policy-hinted LLM, automatic-policy Tai-e, Tai-e-plus-judge, and
  the full hybrid. Code-only mode requires no generated specification. The
  remaining modes share the same generated specification and code basis.
- [`run_neurosymbolic_suite.py`](../scripts/run_neurosymbolic_suite.py) prepares
  and freezes the ten-version plan, then coordinates fresh generation/refinement,
  all automatic arms and the existing manual-policy reference when explicitly
  executed. It writes normalized review/scoring inputs as well as stage artifacts.
- A suite-wide inference guard caps API attempts and reserved completion tokens,
  stops on a cumulative reported-cost threshold or unknown billing, and reuses
  only identical complete request bodies. Generation and refinement cannot
  bypass the global guard. Actual spend is recorded separately from logical
  response usage, including exact-request reuse.
- The scorer imports all new arm outputs and normalizes the single-repetition
  manual reference. Missing library endpoint identities remain unreviewed instead
  of disappearing. A normalization limitation is not labeled an engine failure.
- Fixed-version catalogues were exported for all five projects, without taint
  policies or LLM calls. All ten catalogue inputs are now available. The broader
  preflight also exposed and fixed handling of source metadata with no bytecode
  line range; those methods retain IR fallback rather than inventing source lines.

The [comparison runbook](COMPARISON_RUNBOOK.md) contains commands, limits and
remaining interpretation constraints. Live execution requires an explicitly
approved positive dollar threshold; none was supplied during this implementation
step. No paid inference or full live comparison was launched.

### Frozen preflight and the context-size limitation

Plan: [`20261013T015716Z-a0wa4zgs`](results/suite-plans/20261013T015716Z-a0wa4zgs/REPORT.md).
Scope/label artifact:
[`20261013T015016Z-91rg5qjk`](results/ground-truth/20261013T015016Z-91rg5qjk/case-truth.json).

| Project | Vulnerable code characters | Fixed code characters | Both fit the 200,000-character cap? |
| --- | ---: | ---: | --- |
| zip4j | 1,145,765 | 1,153,119 | No |
| zt-zip | 341,972 | 349,480 | No |
| spark | 137,492 | 142,688 | Yes |
| plexus-archiver | 128,812 | 135,988 | Yes |
| plexus-utils | 113,553 | 125,291 | Yes |

These counts are the code-only package; generated policy and candidate evidence
add more data. Passing this check does not guarantee all subsequent judge inputs
fit. The current configuration intentionally keeps the existing cap: it will
record four known code-branch overflows before inference, not silently truncate
them or count failures as clean negatives. Thus this is a frozen **bounded
failure/coverage study**, not a claim that every LLM arm will succeed on all
subjects. Context batching would be a separately documented implementation
change and would require a new plan, not a hidden mid-experiment repair.

The plan has no missing catalogues. Its hard upper bounds are **747 API attempts**
and **3,736,000 reserved completion tokens**, including generation/refinement and
judge variants. These are conservative ceilings, not expected usage, total token
usage or a dollar estimate. Monetary approval remains explicit at execution;
the last request may exceed a reported-cost threshold.

### Verification

**160 tests pass**. New checks exercise all five mode-selection paths, code-only
policy isolation, stable program identity independent of policy completeness,
explicit live authorization, no implicit Tai-e execution in replay, global request/
token/cost limits, exact-request caching, unknown billing, restored inference
hooks, changed frozen-file rejection and manual source-return/sink-slot parsing.

Four modes were also checked against the real saved plexus-utils diagnostic and
responses: auto-Tai-e, policy-LLM, Tai-e-plus-judge and full hybrid. They incur
zero new API calls and preserve the original partial/invalid outcomes. Code-only
mode was dry-run and mock-tested; using a hinted response as its replay would
violate the exact-request contract. A real manual-reference normalization check
retained 12 pairs per plexus-archiver version and 22 per plexus-utils version.

The new four-arm replay review bundle is
[`20261013T015743Z-eh8bs53n`](results/evaluation-review/20261013T015743Z-eh8bs53n/suite-index.json).
It is a development replay check, not four new independent model experiments.
The full live suite and its final human matching/review remain unexecuted.
