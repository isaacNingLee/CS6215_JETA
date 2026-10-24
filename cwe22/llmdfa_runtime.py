"""Run pinned upstream LLMDFA on real-world CWE-22 subjects via the hosted models.

Imported by tests without importing LLMDFA or its optional dependencies.
The upstream source and shipped prompts are never edited; every deviation is a
patch applied here at a module boundary, listed in DEVIATIONS for the record.

Upstream targets Juliet: self-contained single files, analysis roots named
`good`/`bad`, and an oracle reading `POTENTIAL FLAW:` comments. None of that
holds for a real repository, so this module replaces three boundaries:

  model      -- utility.llm.LLM routes to OpenRouter with a sticky failure ledger.
                Upstream returns "" after swallowing an error, which would read
                downstream as "no sources found" rather than as a failed run.
  parsing    -- TSAnalyzer parses the policy-relevant file set instead of one
                file, so the import-driven callee resolution upstream already
                implements can follow a flow across files.
  roots      -- main_ids comes from the project's Tai-e entry point rather than
                from method names, which is where the entry-point half of the
                hint enters (the source/sink half is in llmdfa_specs.py).

Known coverage limits of the upstream engine, unchanged here and reported rather
than worked around: constructors are not collected as methods (TS_parser only
reads `method_declaration`), so call edges through a constructor are invisible,
and intra-procedural summaries assume calls never mutate their arguments.
"""
import json
import os
import re
from pathlib import Path
import sys
import time
import types
import urllib.error

import urllib.request

# Run by LLMDFA's own interpreter with the repository root on PYTHONPATH.
from cwe22 import config, llmdfa_specs as specs
from cwe22.util import read_json, write_json


class support:
    """The few helpers the wrapper needs, on OpenRouter."""
    read = staticmethod(read_json)
    save = staticmethod(write_json)

    @staticmethod
    def infer(body, key, timeout):
        """One OpenRouter chat completion; transport failures raise urllib errors (retried by the caller)."""
        request = urllib.request.Request(config.OPENROUTER_URL, data=json.dumps(body).encode(), method="POST",
                                         headers={"Authorization": "Bearer " + key,
                                                  "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = json.loads(response.read())
        if "error" in raw and not raw.get("choices"):
            raise urllib.error.URLError("provider error: " + json.dumps(raw["error"])[:300])
        return raw

    @staticmethod
    def cost_of(raw):
        """OpenRouter's reported cost in dollars; None when the response has none."""
        cost = (raw.get("usage") or {}).get("cost")
        return float(cost) if isinstance(cost, (int, float)) and cost >= 0 else None

# Every change applied to the pinned upstream engine, for the write-up. The
# first group is adaptation (different task, same engine); the second is
# correctness work the engine needs before it can run on a real repository at
# all, each one found by a crash or a severed flow on these subjects.
DEVIATIONS = (
    'Superclass source closure added to the hinted file set; nested named classes parsed.',
    'Callee resolution includes parsed subclasses for inherited virtual calls (conservative).',
    'LLM endpoints filtered against syntax of the project source/sink policy, with rejection audit.',
    'Persistent null completions fail the case; returned model IDs are recorded and optionally pinned.',
    'Scoring uses only the first and last point of each validated trace.',
    'LLM boundary routed to OpenRouter; upstream silent-"" error handling replaced by a sticky failure.',
    'TSAnalyzer parses the policy-relevant file set, not a single file.',
    'Analysis roots seeded from the Tai-e entry point, not from methods named good/bad.',
    'Source/sink bug-class assertion bypassed; CWE-22 specs are supplied instead of dbz/xss/ci.',
    'Juliet comment-label oracle unused; scoring is external and matches the other arms.',
    'find_callee takes the method_invocation name field; upstream used the first identifier, '
    'which is the receiver for a qualified call, so no qualified call resolved.',
    "Each file's own package registered as an implicit import, so same-package calls resolve.",
    'find_function_returns collects identifiers nested in a returned expression, not only a '
    'bare returned identifier.',
    'Callee descent covers every resolved candidate, matching the reachability search, and '
    'memoizes (function, parameter-index) pairs so recursion terminates.',
    'Searching deferred until every reachable function is summarized, so it cannot read a '
    'caller that is still mid-descent.',
    'Reachability search prunes traces that revisit a value and stops at TRACE_LIMIT.',
    'A second call site on one source line is dropped rather than asserted on; the count is '
    'reported as dropped_call_sites.',
    'Callee candidates filtered by argument count; name-only matching resolved a call to '
    'every same-named overload, including itself, which made traces oscillate.',
    'Resolved callees sorted for reproducibility; upstream iterated a set of class names.',
    'Non-ASCII sources are copied with each character widened to its byte count, because '
    'upstream slices the decoded text with tree-sitter byte offsets and otherwise misreads '
    'every name after the first non-ASCII character.',
    'The entry point may be an inherited method; upstream sees only declarations.',
    'A Yes/No prompt answered without a Yes or a No raises instead of re-asking forever in '
    "upstream's retry loop; null content that survives the retries fails the case rather than becoming an empty "
    'answer.',
    'An answer cut off at the token limit (finish_reason length, or none) is used as returned, as upstream '
    'does (CS6215_proj failed the case); the count is reported as truncated_answers.',
    'Null content from a reasoning model that finished normally with its reasoning present is its empty '
    'answer (DeepSeek returns an empty answer as null), not a provider fault; counted as reasoning_only_answers.',
    "Transport errors and the provider's null-content bug retried three times with backoff, as "
    'the hinted-LLM arm does; every other failure stops the case on the first occurrence.',
)
# Upstream imports these provider SDKs at module scope but only reaches them for
# model names we never pass. Stubbing avoids installing GPU/provider stacks.
OPTIONAL_IMPORTS = ('replicate', 'google.generativeai')
# Longest data-flow trace the reachability search will extend. Cycles are
# pruned separately; this only stops pathological depth on a real call graph.
TRACE_LIMIT = 16


def stub_optional_imports():
    for name in OPTIONAL_IMPORTS:
        if name in sys.modules:
            continue
        module = types.ModuleType(name)
        if '.' in name:
            parent_name, attribute = name.rsplit('.', 1)
            parent = sys.modules.get(parent_name) or types.ModuleType(parent_name)
            setattr(parent, attribute, module)
            sys.modules[parent_name] = parent
        sys.modules[name] = module


def hosted_model(plan, ledger_path, key, infer=support.infer):
    """Build the LLM replacement class plus the ledger the caller must inspect.

    One ledger is shared by every agent in a case, so the request and cost caps
    bound the whole case rather than each stage. A failure is sticky: upstream
    catches broad exceptions at several levels, and without this a dropped
    request would surface as an empty analysis instead of an error.
    """
    state = support.read(ledger_path) if Path(ledger_path).exists() else dict(
        attempts=0, reported_cost=0.0, cost_unknown=False, failed=False)
    ledger = dict(state=state, path=Path(ledger_path), empty_answers=0)

    class HostedLLM:
        def __init__(self, online_model_name, openai_key, temperature, system_role=''):
            self.systemRole = system_role
            self.online_model_name = online_model_name
            self.temperature = temperature

        def infer(self, message, is_measure_cost=True):
            if (state['failed'] or state['cost_unknown'] or
                    state['attempts'] >= plan['max_requests'] or
                    state['reported_cost'] >= plan['cost_limit']):
                state['failed'] = True
                support.save(ledger['path'], state)
                raise RuntimeError('LLMDFA request/cost limit reached or an earlier request failed')
            body = dict(model=plan['model'], temperature=0, max_tokens=plan['max_tokens'],
                        reasoning=dict(effort='low'),
                        messages=[dict(role='system', content=self.systemRole),
                                  dict(role='user', content=message)])
            state['attempts'] += 1
            folder = ledger['path'].parent / 'requests' / '{:05d}'.format(state['attempts'])
            folder.mkdir(parents=True)
            support.save(folder / 'request.json', body)
            # Persist uncertain billing before the call, including interruptions.
            state['cost_unknown'] = True
            support.save(ledger['path'], state)
            try:
                # Retry transport errors and the provider's null-content bug on
                # the schedule the hinted LLM calls use (llm.call), and for
                # the reason it documents ("completion tokens billed but null
                # content returned with finish_reason stop; retrying resolves
                # it"). A case here makes hundreds of requests, so one reset
                # connection or null body would otherwise discard the whole run.
                # Everything else still sticks on the first occurrence.
                attempts = plan.get('transport_attempts', 3)
                raw = None
                for attempt in range(attempts):
                    reason = None
                    try:
                        raw = infer(body, key, plan['request_timeout'])
                        # An empty string is a legitimate answer: both specs
                        # instruct one when a function holds no such value.
                        # Only null content is the provider bug -- unless a reasoning
                        # model finished normally with its reasoning present: that is
                        # its empty answer (DeepSeek returns one as null). Counted.
                        message = raw['choices'][0]['message']
                        if (message.get('content') is None and message.get('reasoning') and
                                raw['choices'][0].get('finish_reason') == 'stop'):
                            message['content'] = ''
                            state['reasoning_only_answers'] = state.get('reasoning_only_answers', 0) + 1
                        if not isinstance(message.get('content'), str):
                            reason = 'null content, finish_reason=' + str(
                                raw['choices'][0].get('finish_reason'))
                    except (urllib.error.URLError, urllib.error.HTTPError,
                            TimeoutError) as exc:
                        # A socket read timeout raises TimeoutError, which is
                        # not a URLError, so it needs naming separately.
                        reason = type(exc).__name__ + ': ' + str(exc)
                    if reason is None:
                        break
                    (folder / 'retries.txt').write_text(
                        'attempt {}: {}\n'.format(attempt + 1, reason), )
                    if attempt + 1 == attempts:
                        if raw is None:
                            raise ValueError('Provider failed after {} attempts: {}'.format(
                                attempts, reason))
                        raise ValueError('Provider returned null content after retries')
                    time.sleep(5 * (attempt + 1))
                support.save(folder / 'response.json', raw)
                cost = support.cost_of(raw)
                state['cost_unknown'] = cost is None
                state['reported_cost'] += cost or 0.0
                choice = raw['choices'][0]
                if choice.get('finish_reason') in ('length', None):
                    # As upstream: a cut-off answer is used as returned (the endpoint
                    # filter drops reported lines without the policy's call). Counted.
                    # Some providers end a cut-off answer with no finish_reason at all.
                    state['truncated_answers'] = state.get('truncated_answers', 0) + 1
                    (folder / 'truncated.txt').write_text('finish_reason={}\n'.format(choice.get('finish_reason')))
                elif choice.get('finish_reason') != 'stop':
                    raise ValueError('Incomplete model completion: ' + str(choice.get('finish_reason')))
                content = choice['message']['content']
                if not isinstance(content, str):
                    content = ''
                if state['cost_unknown']:
                    raise ValueError('Provider did not report cost; stopping further requests')
                returned_model = raw.get('model')
                state.setdefault('response_models', {})[str(returned_model)] = (
                    state.get('response_models', {}).get(str(returned_model), 0) + 1)
                expected = plan.get('expected_response_model')
                if expected and returned_model != expected:
                    raise ValueError('Unexpected response model: ' + str(returned_model))
                usage = raw.get('usage') or {}
                return (content, usage.get('prompt_tokens', 0) if is_measure_cost else 0,
                        usage.get('completion_tokens', 0) if is_measure_cost else 0)
            except Exception as exc:
                state['failed'] = True
                (folder / 'error.txt').write_text(type(exc).__name__ + ': ' + str(exc) + '\n')
                raise
            finally:
                support.save(ledger['path'], state)

    return HostedLLM, ledger


def configure(plan, case, work_dir, key, infer=support.infer):
    """Patch the three boundaries, then build a DFA for this case.

    Order matters: the agents star-import LLM from utility.llm at their own
    import time, so the model class is replaced before engine.DFA is imported.
    """
    root = Path(plan['llmdfa_dir'])
    for path in (root, root / 'src'):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    stub_optional_imports()

    model_class, ledger = hosted_model(plan, work_dir / 'ledger.json', key, infer)
    import utility.llm as llm_module
    llm_module.LLM = model_class

    from engine.DFA import DFA
    from LMAgent.LM_agent import LMAgent
    from TSAgent.TS_analyzer import TSAnalyzer
    from TSAgent.TS_parser import TSParser

    require_decisive_answer(LMAgent)
    nested_classes(TSParser)

    files = ascii_normalized_sources(
        [Path(f).resolve() for f in case['files']], work_dir / 'sources')
    entry_class, entry_method = case['entry_class'], case['entry_method']

    class ProjectAnalyzer(TSAnalyzer):
        """Parse the policy-relevant files and root the analysis at the entry point."""

        def __init__(self, java_file_path, support_files):
            self.java_file_path = java_file_path
            self.ts_parser = TSParser(java_file_path)
            for path in files:
                self.ts_parser.extract_single_file(path)
            self.ts_parser.extract_static_field_from_support_files(support_files)
            self.register_same_package_imports()
            self.main_ids = self.find_entry_points()
            self.tmp_variable_count = 0

        def register_same_package_imports(self):
            """Let a file see its own package's classes, as Java does.

            find_callee resolves a call by collecting the classes declared in
            the caller's file plus those reachable through its import
            statements. Java needs no import for a class in the same package, so
            those calls resolve to nothing: zip4j's
            `Unzip.initExtractFile` -> `UnzipEngine.unzipFile` is invisible,
            which severs the flow before it reaches the sink. Juliet cases are
            one self-contained class, so upstream never needed this.

            Registering each file's own package as an implicit import is enough,
            since find_callee already expands an import prefix to every class in
            the matching package.
            """
            parser = self.ts_parser
            for path in files:
                package = parser.fileToPackage.get(path)
                if package:
                    parser.fileToImports.setdefault(path, set()).add(package)

        def find_entry_points(self):
            """Root at the entry method, accepting an inherited declaration.

            The Tai-e entry names the class a caller invokes, which need not be
            the class that declares the method: plexus-archiver's
            `ZipUnArchiver.extract()` is declared on `AbstractUnArchiver`, and
            upstream only ever sees declarations. Prefer the named class, then
            fall back to any parsed class declaring the method, so an inherited
            entry resolves instead of failing.
            """
            parser = self.ts_parser
            declared = {}
            for class_name, method_ids in parser.classToFunctions.items():
                for method_id in method_ids:
                    if parser.methods[method_id][0] == entry_method:
                        declared.setdefault(class_name, []).append(method_id)
            if entry_class in declared:
                return sorted(declared[entry_class])
            if declared:
                self.inherited_entry_from = sorted(declared)
                return sorted(m for ids in declared.values() for m in ids)
            raise ValueError('Entry point {}.{} not found in the parsed files {}'.format(
                entry_class, entry_method, sorted(parser.classToFunctions)))

    import engine.DFA as dfa_module
    from utility.function import Function, LocalValue, ValueType
    qualified_call_resolution(TSAnalyzer)
    nested_return_values(TSAnalyzer, LocalValue, ValueType)
    dfa_module.TSAnalyzer = ProjectAnalyzer
    DFA = whole_callgraph_dfa(DFA, Function, ValueType)
    counter = allow_multiple_calls_per_line(Function)
    for name, attribute, required in (
            ('LMAgent.spec.src_extractor', 'SrcExtractor', ('model', 'prompt', 'srcs')),
            ('LMAgent.spec.sink_extractor', 'SinkExtractor', ('model', 'prompt', 'sinks'))):
        setattr(dfa_module, attribute, unasserted_extractor(
            name, attribute, required, specs.POLICY[case['project']],
            work_dir / 'rejected-endpoints.json'))

    spec_paths = specs.write_specs(case['project'], work_dir / 'specs')
    dfa = DFA(files[0], [], str(work_dir / 'log'), plan['bug_type'],
              str(spec_paths['source']), str(spec_paths['sink']),
              plan['propagator_spec'], plan['validator_spec'],
              plan['model'], plan['syn_parser'], plan['fscot'], plan['syn_solver'],
              plan['solving_refine_number'], key, 0)
    return dfa, ledger, spec_paths, counter


def ascii_normalized_sources(files, directory):
    """Copy any non-ASCII source with its characters widened to ASCII.

    tree-sitter reports byte offsets, and upstream slices the decoded str with
    them (`source_code[node.start_byte:node.end_byte]`) throughout TS_parser,
    TS_analyzer and the transformer. The two agree only while the file is
    ASCII, which every Juliet case is. zt-zip's ZipUtil.java carries five 'ä'
    characters in javadoc, so from the first one on every extracted name is
    shifted a byte: the class reads as `ipUtil ` instead of `ZipUtil`, no
    method is attributed to it, and the entry point cannot be found.

    Replacing each non-ASCII character with as many ASCII characters as it had
    bytes restores offset agreement for the rest of the file without moving any
    line or identifier. Only comment and string text changes, never structure.
    """
    directory.mkdir(parents=True, exist_ok=True)
    normalized = []
    for index, path in enumerate(files):
        text = Path(path).read_text(errors='replace')
        if text.isascii():
            normalized.append(str(path))
            continue
        widened = ''.join(
            character if character.isascii()
            else '?' * len(character.encode('utf-8'))
            for character in text)
        target = directory / str(index) / Path(path).name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(widened)
        normalized.append(str(target))
    return normalized


def require_decisive_answer(agent_class):
    """Fail loudly when a Yes/No prompt comes back without one.

    The propagator and the validator both sit in `while True:` loops that
    re-ask whenever process_yes_no_list_in_response finds no Yes and no No, so
    an answer that never commits spins until the request cap, silently burning
    the budget. Raising converts that into a clear failure for the case.
    """
    original = agent_class.process_yes_no_list_in_response

    def process_yes_no_list_in_response(response):
        answers = original(response)
        if not answers:
            raise ValueError('Model gave no Yes/No decision: ' + repr(response[:200]))
        return answers

    agent_class.process_yes_no_list_in_response = staticmethod(
        process_yes_no_list_in_response)


def qualified_call_resolution(analyzer_class):
    """Resolve a call by its method name rather than by the receiver's name.

    Upstream takes the first `identifier` child of a method_invocation as the
    callee name. For an unqualified call like `initExtractAll()` that is the
    method, but for `unzipEngine.unzipFile(...)` it is the receiver variable,
    which matches no declared method, so every qualified call resolves to
    nothing. zip4j's flow dies at exactly that edge --
    `Unzip.initExtractFile` -> `UnzipEngine.unzipFile` -- leaving the source and
    the sink in disconnected halves of the call graph.

    Vendored from the pinned revision with three changes: the name comes from
    the node's `name` field; candidates are filtered by argument count, since
    matching on name alone makes `extractAll(path)` resolve to every
    `extractAll` including itself, and the resulting self-edge sends the
    reachability search oscillating between two overloads until the trace is
    nonsense; and the result is sorted so a run is reproducible (upstream
    iterates a set of class names). When no candidate's arity matches -- a
    varargs or a signature the parser reads imperfectly -- every name match is
    kept, so the edge is never lost outright.
    """
    arity_cache = {}

    def declared_arity(parser, method_id):
        if method_id not in arity_cache:
            code = parser.methods[method_id][1]
            tree = parser.parser.parse(bytes(code, 'utf8'))
            count = None
            for node in analyzer_class.find_nodes(tree.root_node, 'formal_parameters'):
                count = sum(child.type in ('formal_parameter', 'spread_parameter')
                            for child in node.children)
                break
            arity_cache[method_id] = count
        return arity_cache[method_id]

    def find_callee(self, method_id, source_code, call_site_node):
        assert call_site_node.type == 'method_invocation'
        name_node = call_site_node.child_by_field_name('name')
        if name_node is None:
            return []
        method_name = source_code[name_node.start_byte:name_node.end_byte]
        arguments = call_site_node.child_by_field_name('arguments')
        argument_count = None
        if arguments is not None:
            argument_count = sum(child.is_named for child in arguments.children)
        parser = self.ts_parser
        file_path = parser.functionToFile[method_id]
        usable_classes = set(parser.fileToClasses.get(file_path, set()))
        for import_item in parser.fileToImports.get(file_path, set()):
            for package_item in parser.packageToClasses:
                if package_item.startswith(import_item):
                    usable_classes |= parser.packageToClasses[package_item]
                if import_item.startswith(package_item):
                    tail_name = import_item.replace(package_item, '').replace('.', '')
                    if tail_name in parser.packageToClasses[package_item]:
                        usable_classes.add(tail_name)
        # Include implementations on parsed subclasses of visible base classes.
        # Name/arity resolution remains conservative, not Java points-to analysis.
        parents = getattr(parser, 'class_parents', {})
        changed = True
        while changed:
            extra = {cls for cls, bases in parents.items() if bases & usable_classes}
            changed = not extra <= usable_classes
            usable_classes |= extra
        callee_ids = []
        for class_name in sorted(usable_classes):
            for candidate in parser.classToFunctions.get(class_name, []):
                if candidate in parser.methods and parser.methods[candidate][0] == method_name:
                    callee_ids.append(candidate)
        if argument_count is None:
            return callee_ids
        matching = [c for c in callee_ids if declared_arity(parser, c) == argument_count]
        return matching or callee_ids

    analyzer_class.find_callee = find_callee


def nested_return_values(analyzer_class, local_value, value_type):
    """Find returned identifiers nested in an expression, not just bare returns.

    Upstream scans only the direct children of a return_statement for an
    identifier, so `return x;` is found but `return a + f(b) + x;` yields no
    return value at all -- the function then has no summary end point and taint
    cannot leave it. This is what silences zip4j, whose tainted entry name
    leaves `UnzipEngine.getOutputFileNameWithPath` through
    `return outPath + System.getProperty(...) + fileName;`. Juliet returns bare
    variables, so upstream never needed the general case.

    Identifiers in the callee-name position are skipped as they name no value;
    anything else in the expression is offered to the propagator, which decides
    whether the return actually depends on it.
    """
    def find_function_returns(source_code, root_node):
        rets, seen = [], set()
        for ret_node in analyzer_class.find_nodes(root_node, 'return_statement'):
            callee_names = set()
            for invocation in analyzer_class.find_nodes(ret_node, 'method_invocation'):
                name = invocation.child_by_field_name('name')
                if name is not None:
                    callee_names.add((name.start_byte, name.end_byte))
            for node in analyzer_class.find_nodes(ret_node, 'identifier'):
                span = (node.start_byte, node.end_byte)
                if span in callee_names:
                    continue
                name = source_code[node.start_byte:node.end_byte]
                line_number = source_code[:node.start_byte].count('\n') + 1
                if (name, line_number) in seen:
                    continue
                seen.add((name, line_number))
                rets.append(local_value(name, line_number, value_type.RET))
        return rets

    analyzer_class.find_function_returns = staticmethod(find_function_returns)


def allow_multiple_calls_per_line(function_class):
    """Keep the first call site on a line instead of asserting there is one.

    Function.line_to_call_site_info is keyed by line number and asserts the key
    is fresh, because upstream's SSI transformer is meant to leave one call per
    line -- its own comment notes it "can not handle long call chains". Real Java
    chains calls constantly, so the assertion fires. The later call sites on a
    line are dropped rather than merged, since merging would attribute one
    call's arguments to another.

    This loses call edges and can only lower what LLMDFA finds, so the count is
    returned and recorded per case rather than being silently absorbed.
    """
    counter = dict(dropped_call_sites=0)
    original = function_class.update_line_to_call_site_info

    def update(self, line_number, call_site_node, args, outputs, callee_ids):
        if line_number in self.line_to_call_site_info:
            counter['dropped_call_sites'] += 1
            return
        return original(self, line_number, call_site_node, args, outputs, callee_ids)

    function_class.update_line_to_call_site_info = update
    return counter


def whole_callgraph_dfa(base, function_class, value_type):
    """Make callee descent agree with the reachability search, and stop cycles.

    Upstream descends into `callee_ids[0]` alone while
    extended_CFL_reachability_search iterates every candidate and indexes
    analyzed_functions directly. Juliet never hits the disagreement: it has no
    overloads, so name-based resolution yields one callee. Real Java does --
    zip4j declares two `ZipFile.extractAll` overloads and an `Unzip.extractAll`,
    all matched by upstream's name-only resolution -- and the search then raises
    KeyError on a callee nobody analyzed.

    Descending into every candidate is the search's own semantics and keeps the
    call graph whole, at the cost of more requests; keeping `[0]` would instead
    follow whichever overload parsed first. Upstream also re-descends
    unconditionally, which does not terminate on recursive real-world code, so
    (function, parameter-index) pairs are analyzed at most once here.

    analyze_function is a vendored copy of the method at the pinned revision,
    because the descent must widen before the search upstream runs in that same
    call. The two deviations are marked inline; nothing else differs.
    """
    class WholeCallgraphDFA(base):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._descended = set()
            self._defer_search = False
            self.truncated_traces = 0

        def analyze_function(self, function_id, start_para_indexes):
            # DEVIATION: analyze each (function, parameter-index) pair once, so
            # recursive real-world code terminates.
            marker = (function_id, frozenset(start_para_indexes))
            if marker in self._descended:
                return
            self._descended.add(marker)

            if self.environment.is_analyzed(function_id):
                current_function = self.environment.analyzed_functions[function_id]
            else:
                (name, original_function) = self.ts_analyzer.ts_parser.methods[function_id]
                current_function = function_class(function_id, name, original_function)
                self.function_transformer.transform(
                    function_id, current_function.original_function)
                current_function.SSI_function = self.function_transformer.SSI
                current_function.SSI_function_without_comments = (
                    self.function_transformer.SSI_without_comments)
                current_function.lined_SSI_function_without_comments = (
                    self.function_transformer.lined_SSI_function_without_comments)
                current_function.parse_tree = self.ts_analyzer.ts_parser.parser.parse(
                    bytes(self.function_transformer.SSI_without_comments, 'utf8'))
                current_function = self.extract_call_meta_data_in_single_function(
                    current_function)

            (summary_srcs, summary_sinks) = self.construct_summary_start_end_points(
                current_function, start_para_indexes)
            reachable_summaries, unreachable_summaries = self.ifp_propagator.apply(
                current_function, summary_srcs, summary_sinks, self.is_fscot)
            current_function.extend_function_summaries(
                reachable_summaries, unreachable_summaries)
            self.environment.set_analyzed_function(function_id, current_function)

            for call_site_node, line_number in current_function.call_site_nodes:
                (_, args, rets, callee_ids) = current_function.line_to_call_site_info[
                    line_number]
                para_indexes = set([])
                for start, end in reachable_summaries:
                    if end.line_number != line_number:
                        continue
                    if end.v_type == value_type.ARG:
                        para_indexes.add(end.index)
                # DEVIATION: upstream descends into callee_ids[0] only, while
                # the search below visits every candidate.
                for callee_id in callee_ids:
                    self.analyze_function(callee_id, para_indexes)

            # DEVIATION: the search's FIELD branch reads callees straight out of
            # caller_callee_map, which records every resolved call site --
            # including a second one on a line that line_to_call_site_info had
            # to drop. Cover those too, so no branch of the search can reach a
            # function that was never summarized.
            for (caller_id, _), callee_ids in list(
                    self.environment.caller_callee_map.items()):
                if caller_id != function_id:
                    continue
                for callee_id in sorted(callee_ids):
                    if not self.environment.is_analyzed(callee_id):
                        self.analyze_function(callee_id, set([]))

            # DEVIATION: searching is deferred to analyze() below.
            if not self._defer_search:
                bug_traces = self.search_from_srcs_in_single_function(function_id)
                self.bug_candidates[function_id] = bug_traces
            return

        def extended_CFL_reachability_search(self, function_id, context_ids, trace):
            """Prune traces that revisit a value, and bound the trace length.

            check_context_realizability only keeps calls and returns balanced;
            nothing stops a trace from cycling, and each step deepcopies the
            trace, so a real call graph recurses until Python gives up. A trace
            that reaches a (function, value) already on it has cycled and can be
            dropped: continuing only re-derives sinks the first visit reaches.
            TRACE_LIMIT then caps pathological depth; hitting it is recorded.
            """
            step = (function_id, str(trace[-1][1]))
            if any((fid, str(value)) == step for fid, value in trace[:-1]):
                return []
            if len(trace) > TRACE_LIMIT:
                self.truncated_traces += 1
                return []
            return super().extended_CFL_reachability_search(
                function_id, context_ids, trace)

        def analyze(self):
            """Summarize every reachable function first, then search.

            Upstream searches at the end of each analyze_function, while that
            function's callers are still mid-descent. The search walks up to a
            caller through RET edges and reads its call sites, so on a real call
            graph it reaches a callee the descent has not reached yet and raises
            KeyError. Summarizing first makes the search order-independent and
            lets it see the whole graph; no summary changes as a result.
            """
            self._defer_search = True
            try:
                for main_id in self.main_ids:
                    self.analyze_function(main_id, set([]))
            finally:
                self._defer_search = False
            for function_id in list(self.environment.analyzed_functions):
                self.bug_candidates[function_id] = (
                    self.search_from_srcs_in_single_function(function_id))

    WholeCallgraphDFA.__name__ = base.__name__
    return WholeCallgraphDFA


def nested_classes(parser_class):
    """Register nested named classes without modifying the pinned upstream tree."""
    if getattr(parser_class, '_nested_classes_patched', False):
        return
    original = parser_class.parse_class_declaration_info

    def parse(self, path, code, package, root):
        self.class_parents = getattr(self, 'class_parents', {})
        def visit(node):
            if node.type == 'class_declaration':
                name_node = node.child_by_field_name('name')
                name = code[name_node.start_byte:name_node.end_byte]
                if name in self.classToFunctions:
                    raise ValueError('Duplicate simple class name is unsupported: ' + name)
                bases = set()
                for child in node.children:
                    if child.type in ('superclass', 'super_interfaces'):
                        bases.update(re.findall(r'[A-Za-z_$][\w$]*',
                                                code[child.start_byte:child.end_byte]))
                self.class_parents[name] = bases - {'extends', 'implements'}
                original(self, path, code, package, types.SimpleNamespace(children=[node]))
            for child in node.children:
                visit(child)
        visit(root)
    parser_class.parse_class_declaration_info = parse
    parser_class._nested_classes_patched = True


def filter_policy_endpoints(function, values, policy, field):
    """Reject invented endpoints using AST call/assignment evidence.

    This is a syntactic guard, not receiver type inference. It checks API names,
    sink argument position, expressions, and line spans. It never adds endpoints.
    """
    code = function.SSI_function_without_comments
    raw = code.encode('utf-8')
    def text(node):
        return raw[node.start_byte:node.end_byte].decode('utf-8') if node else ''
    def compact(value):
        return re.sub(r'\s+', '', value)
    allowed = []
    def add(expression, node):
        if expression:
            allowed.append((compact(expression), node.start_point[0] + 1, node.end_point[0] + 1))
    def visit(node):
        if field == 'srcs' and node.type == 'method_invocation':
            if text(node.child_by_field_name('name')) == policy['source_method']:
                add(text(node), node)
                ancestor = node.parent
                while ancestor and ancestor.type not in ('block', 'method_declaration'):
                    if ancestor.type in ('variable_declarator', 'assignment_expression'):
                        target = ancestor.child_by_field_name('name' if ancestor.type == 'variable_declarator' else 'left')
                        add(text(target), ancestor)
                        break
                    ancestor = ancestor.parent
        if field == 'sinks' and node.type in ('method_invocation', 'object_creation_expression'):
            name = text(node.child_by_field_name('name' if node.type == 'method_invocation' else 'type'))
            if name.rsplit('.', 1)[-1] == policy['sink_call']:
                arguments = node.child_by_field_name('arguments')
                args = arguments.named_children if arguments else []
                if len(args) > policy['sink_arg']:
                    add(text(args[policy['sink_arg']]), node)
        for child in node.children:
            visit(child)
    visit(function.parse_tree.root_node)
    valid, rejected = [], []
    for value in values:
        if any(compact(value.name) == name and start <= value.line_number <= end
               for name, start, end in allowed):
            valid.append(value)
        else:
            rejected.append(dict(method=function.function_name, kind=field,
                                 value=value.name, line=value.line_number,
                                 reason='No matching policy API expression at this line'))
    return valid, rejected


def unasserted_extractor(module_name, attribute, required, policy=None, audit_path=None):
    """Drop the dbz/xss/ci spec-name assertion for the CWE-22 specs.

    The assertion sits at the end of __init__ and guards only the binding of a
    tree-sitter extractor, which is used when syn_parser is on. Renaming the
    specs to satisfy it would label them with another bug class, so the
    assertion is swallowed and the attributes the LLM path needs -- all set
    before it -- are checked instead. syn_parser must stay off; the harness
    pins it to False and the engine would otherwise hit the unbound extractor.
    """
    module = __import__(module_name, fromlist=[attribute])
    base = getattr(module, attribute)

    class Extractor(base):
        def __init__(self, *args, **kwargs):
            try:
                super().__init__(*args, **kwargs)
            except AssertionError:
                pass  # Bug-class name check only; CWE-22 is not one of its three.
            missing = [name for name in required if not hasattr(self, name)]
            if missing:
                raise ValueError('{} left {} uninitialized'.format(
                    attribute, ', '.join(missing)))

        def apply(self, function, is_parse):
            if is_parse:
                raise ValueError('CWE-22 specs have no synthesized extractor; '
                                 'run with syn_parser off')
            result = super().apply(function, is_parse)
            if policy is not None:
                field = 'srcs' if attribute == 'SrcExtractor' else 'sinks'
                valid, rejected = filter_policy_endpoints(function, getattr(self, field), policy, field)
                setattr(self, field, valid)
                if rejected and audit_path:
                    previous = support.read(audit_path) if audit_path.exists() else []
                    support.save(audit_path, previous + rejected)
            return result

    Extractor.__name__ = attribute
    return Extractor


def locations(dfa):
    """Reported flows as (simple class, method) pairs, the other arms' unit.

    Both endpoints of each validated trace are reported, matching the Tai-e
    arm's source-and-sink method locations.
    """
    parser = dfa.ts_analyzer.ts_parser
    owner = {method_id: class_name
             for class_name, method_ids in parser.classToFunctions.items()
             for method_id in method_ids}
    found = set()
    for traces in dfa.bug_reports.values():
        for trace in traces:
            for function_id, _ in (trace[0], trace[-1]):
                name = dfa.environment.analyzed_functions[function_id].function_name
                found.add((owner.get(function_id, ''), name))
    return sorted(found)


def traces(dfa):
    """Full endpoint detail for diagnostics, not for scoring."""
    parser = dfa.ts_analyzer.ts_parser
    owner = {method_id: class_name
             for class_name, method_ids in parser.classToFunctions.items()
             for method_id in method_ids}
    rows = []
    for traces_of_source in dfa.bug_reports.values():
        for trace in traces_of_source:
            rows.append([dict(cls=owner.get(function_id, ''),
                              method=dfa.environment.analyzed_functions[function_id].function_name,
                              value=value.name, line=value.line_number)
                         for function_id, value in trace])
    return rows


def main():
    work_dir = Path(sys.argv[1]).resolve()
    plan = support.read(work_dir.parent / 'plan.json')
    case = next(c for c in plan['cases'] if c['id'] == sys.argv[2])
    key = os.environ.get('OPENROUTER_API_KEY', '')
    if not key:
        raise ValueError('Set OPENROUTER_API_KEY')
    dfa, ledger, _, counter = configure(plan, case, work_dir, key)
    dfa.analyze()
    dfa.validate()
    dfa.report()
    state = ledger['state']
    if state['failed'] or state['cost_unknown']:
        raise RuntimeError('LLMDFA swallowed an inference failure; this case is incomplete')
    support.save(work_dir / 'predictions.json', dict(
        locations=locations(dfa), traces=traces(dfa),
        requests=state['attempts'], response_models=state.get('response_models', {}),
        entry_points=len(dfa.main_ids),
        analyzed_functions=len(dfa.environment.analyzed_functions),
        truncated_traces=dfa.truncated_traces,
        empty_answers=ledger['empty_answers'], truncated_answers=state.get('truncated_answers', 0),
        reasoning_only_answers=state.get('reasoning_only_answers', 0), **counter))


if __name__ == '__main__':
    main()
