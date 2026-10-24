"""Render LLMDFA source/sink prompt specs for CWE-22 from this project's taint policy.

LLMDFA ships one spec pair per bug type (dbz/xss/osci) and none for path
traversal, so the CWE-22 pair is generated here. The policy below is the same
manually-supplied source/sink pairing fed to Tai-e's taint-config.yml and to the
hinted-LLM arm's hints (data/prompts/hints.json), so all three hinted arms trace to one definition;
check_policy_matches_hints() fails loudly if the two drift apart.

Per-project specs, not one pooled CWE-22 spec: the hinted-LLM arm receives the
single project's policy, so pooling all six would hand LLMDFA strictly more than
its comparison arm. Rendered spec text is written next to each run as evidence.

Two parts of the Tai-e policy have no slot in an LLMDFA spec file:
  entry point -- LLMDFA derives analysis roots from main_ids, so the adapter
    (llmdfa_runtime.py) seeds them from ENTRY below instead.
  taint propagators -- Tai-e needs explicit `File(File,String)`/`File(String)`
    models; LLMDFA's propagator prompt (flow/dep_flow_propagator.json) already
    asks a general value-dependency question that subsumes them, so restating
    them would add a rule the other arms' policy does not contain.
"""
import json

from . import config

HINTS = json.loads((config.DATA / "prompts/hints.json").read_text())["hints"]

# source_owner/source_method: the call whose result Tai-e treats as attacker
# controlled. sink_call/sink_arg: the call and argument index Tai-e marks as the
# sink. entry: the Tai-e entry point, consumed by the adapter, not the prompt.
#
# entry is the library method the hint names, except for spark, whose hint puts
# the source (`System.getenv`) in the test entry adapter rather than in library
# code; its Tai-e root is that adapter, matching the suite manifest's
# source_match of `<SparkEntry: void main(java.lang.String[])>`. entry_witness is
# the HINTS substring that evidences the entry when the prose does not spell the
# method out, and is what check_policy_matches_hints looks for.
POLICY = {
    'mpxj': dict(entry='InputStreamHelper.writeZipStreamToTempDir',
                 source_owner='ZipEntry', source_method='getName',
                 source_gloss="an archive entry's filename",
                 sink_call='FileOutputStream', sink_arg=0,
                 sink_gloss='the file being opened for writing'),
    'zip4j': dict(entry='ZipFile.extractAll',
                  source_owner='FileHeader', source_method='getFileName',
                  source_gloss="an archive entry's filename",
                  sink_call='FileOutputStream', sink_arg=0,
                  sink_gloss='the file being opened for writing'),
    'zt-zip': dict(entry='ZipUtil.unpack',
                   source_owner='ZipEntry', source_method='getName',
                   source_gloss="an archive entry's filename",
                   sink_call='FileOutputStream', sink_arg=0,
                   sink_gloss='the file being opened for writing'),
    'spark': dict(entry='SparkEntry.main', entry_witness='entry adapter',
                  source_owner='System', source_method='getenv',
                  source_gloss='an untrusted resource path',
                  sink_call='getResourceAsStream', sink_arg=0,
                  sink_gloss='the resource path being opened'),
    'plexus-archiver': dict(entry='ZipUnArchiver.extract',
                            source_owner='ZipArchiveEntry', source_method='getName',
                            source_gloss="an archive entry's filename",
                            sink_call='FileOutputStream', sink_arg=0,
                            sink_gloss='the file being opened for writing'),
    'plexus-utils': dict(entry='Expand.execute',
                         source_owner='ZipEntry', source_method='getName',
                         source_gloss="an archive entry's filename",
                         sink_call='FileOutputStream', sink_arg=0,
                         sink_gloss='the file being opened for writing'),
}

SYSTEM_ROLE = 'You are a Java programmer and very good at analyzing Java code.'

# Synthetic, mirroring the shape of the shipped dbz/xss/osci examples. Kept free
# of any subject class, method or identifier so the few-shot block cannot leak a
# subject's answer; only the policy rules above name real APIs.
SOURCE_EXAMPLES = [
    'Here are several examples:',
    'Example 1:', 'User:', 'Here is the program:', '```',
    '1.  String name = entry.getName();',
    '2.  File out = new File(dir, name);', '```',
    'System:', '- Src name: name, Line number: 1', '',
    'Example 2:', 'User:', 'Here is the program:', '```',
    '1.  int count = 0;',
    '2.  String label = header.getFileName();',
    '3.  count = count + 1;', '```',
    'System:', '- Src name: label, Line number: 2', '',
    'Example 3:', 'User:', 'Here is the program:', '```',
    '1.  String base = "/tmp/safe";',
    '2.  File target = new File(base);', '```',
    'System:', '', '',
]
SINK_EXAMPLES = [
    'Here are several examples:',
    'Example 1:', 'User:', 'Here is the program:', '```',
    '1.  File out = new File(dir, name);',
    '2.  FileOutputStream stream = new FileOutputStream(out);', '```',
    'System:', '- Sink name: out, Line number: 2', '',
    'Example 2:', 'User:', 'Here is the program:', '```',
    '1.  InputStream in = loader.getResourceAsStream(path);', '```',
    'System:', '- Sink name: path, Line number: 1', '',
    'Example 3:', 'User:', 'Here is the program:', '```',
    '1.  int total = a + b;', '```',
    'System:', '', '',
]
SOURCE_OUTPUT_EXAMPLES = [
    'Here are several examples:',
    'Example 1:', '- Src name: x, Line number: 1', '- Src name: x, Line number: 4',
    'Example 2:', '- Src name: y, Line number: 3',
]
SINK_OUTPUT_EXAMPLES = [
    'Here are several examples:',
    'Example 1:', '- Sink name: a, Line number: 2',
    'Example 2:', '- Sink name: (prefix + name), Line number: 3',
]


def source_spec(policy):
    """Spec for the values Tai-e marks tainted, phrased per-variable per-line."""
    rule = ('- If a variable is assigned the return value of a method named `{m}`'
            ' (called on a `{o}`, yielding {g}), it is a source value.').format(
                m=policy['source_method'], o=policy['source_owner'], g=policy['source_gloss'])
    return {
        'model_role_name': 'Path Traversal Source Extractor',
        'user_role_name': 'Path Traversal Source Extractor',
        'system_role': SYSTEM_ROLE,
        'task': ('Please identify the source values for path traversal (CWE-22) according to'
                 ' the following instructions. The sources indicate attacker-controlled data'),
        'analysis_rules': [rule],
        'analysis_examples': [
            'Example (illustrative only; report values from the program below):',
            '1. String entryName = entry.' + policy['source_method'] + '();',
            '- Src name: entryName, Line number: 1',
            'Negative example: 1. validate();',
            'Answer: an empty string. Never copy example identifiers into the answer.',
        ],
        'meta_prompts': [
            'Now I will give you the program. Please list all the names of sources and the line numbers.',
            'The line numbers should indicate the line where the values of variables can be attacker-controlled.',
            'A variable can occur multiple times if it is assigned by different statements.',
        ],
        'output_constraints': [
            'Do not add extra explanations.',
            'Just list the pairs of variable and line number (where the variable has an'
            ' attacker-controlled value) line by line.',
            'Each line should start with -.',
            'If there is no variable as source, just output an empty string.',
        ],
        'output_examples': SOURCE_OUTPUT_EXAMPLES,
    }


def sink_spec(policy):
    """Spec for the argument Tai-e marks as the sink."""
    call, arg = policy['sink_call'], policy['sink_arg']
    shape = ('a `{c}` constructor call'.format(c=call) if call[0].isupper()
             else 'a `{c}(String)` call'.format(c=call))
    rule = ('- When a variable/expression is used as argument {i} of {s} ({g}), it is a'
            ' sink for path traversal.').format(i=arg, s=shape, g=policy['sink_gloss'])
    return {
        'model_role_name': 'Path Traversal Sink Extractor',
        'user_role_name': 'Path Traversal Sink Extractor',
        'system_role': SYSTEM_ROLE,
        'task': ('Please identify the sink values for path traversal (CWE-22) according to'
                 ' the following instructions.'),
        'analysis_rules': [rule],
        'analysis_examples': [
            'Example (illustrative only; report values from the program below):',
            ('1. Object stream = new ' + call + '(target);' if call[0].isupper()
             else '1. Object stream = loader.' + call + '(target);'),
            '- Sink name: target, Line number: 1',
            'Negative example: 1. validate();',
            'Answer: an empty string. A helper call is not the specified sink API.',
        ],
        'meta_prompts': [
            'Now I will give you the program. Please list all the names of sinks and the line numbers.',
            'The line numbers should indicate the line of the call that consumes the value.',
        ],
        'output_constraints': [
            'Do not add extra explanations.',
            'Just list the pairs of variable/expression and line number line by line.',
            'Each line should start with -.',
            'If there is no variable as sink, just output an empty string.',
        ],
        'output_examples': SINK_OUTPUT_EXAMPLES,
    }


def check_policy_matches_hints(projects=None):
    """Fail if POLICY and the hinted-LLM arm's HINTS prose have drifted apart.

    Both arms must describe one policy. HINTS is prose, so this checks the
    load-bearing identifiers appear in it rather than comparing whole strings.
    """
    for project in sorted(projects or POLICY):
        policy, hint = POLICY[project], HINTS[project]
        for field in ('source_owner', 'source_method', 'sink_call'):
            if policy[field] not in hint:
                raise ValueError('LLMDFA policy {!r} absent from HINTS[{!r}]: {}'.format(
                    field, project, policy[field]))
        witness = policy.get('entry_witness') or policy['entry'].split('.')[-1]
        if witness not in hint:
            raise ValueError('LLMDFA entry point absent from HINTS[{!r}]: {} (witness {!r})'.format(
                project, policy['entry'], witness))
    return True


def taie_policy_endpoints(config_path):
    """Read the source and sink method signatures out of a Tai-e policy.yml.

    Parsed with a reader rather than a YAML dependency: the file is a flat
    sources/sinks/transfers listing and only the `method:` lines are needed.
    """
    section, sources, sinks = None, [], []
    for line in config_path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith('sources:'):
            section = sources
        elif stripped.startswith('sinks:'):
            section = sinks
        elif stripped.startswith('transfers:'):
            section = None
        elif section is not None and 'method:' in stripped:
            signature = stripped.split('method:', 1)[1].strip().strip('",\'')
            section.append(signature)
    return sources, sinks


def check_policy_matches_taie(projects=None):
    """Fail unless POLICY names the same source and sink Tai-e is configured with
    (data/taie/<project>/policy.yml, the manual policy of the Hinted level)."""
    checked = {}
    for project in sorted(projects or POLICY):
        policy = POLICY[project]
        path = config.DATA / "taie" / project / "policy.yml"
        if not path.is_file():
            raise ValueError("No Tai-e policy.yml for " + project)
        sources, sinks = taie_policy_endpoints(path)
        if not sources or not sinks:
            raise ValueError("Tai-e policy for {} lists no source or sink".format(project))
        owner, method = policy["source_owner"], policy["source_method"]
        if not any(("." + owner + ":") in signature or ("<" + owner + ":") in signature for signature in sources):
            raise ValueError("Tai-e source class for {} is {}, policy says {}".format(project, sources, owner))
        if not any(" " + method + "(" in signature for signature in sources):
            raise ValueError("Tai-e source method for {} is {}, policy says {}".format(project, sources, method))
        if not any(policy["sink_call"] in signature for signature in sinks):
            raise ValueError("Tai-e sink for {} is {}, policy says {}".format(project, sinks, policy["sink_call"]))
        checked[project] = dict(sources=sources, sinks=sinks, config=str(path.relative_to(config.ROOT)))
    return checked


def write_specs(project, directory):
    """Write the rendered spec pair and return absolute paths for the engine."""
    check_policy_matches_hints([project])
    directory.mkdir(parents=True, exist_ok=True)
    paths = {}
    for kind, spec in (('source', source_spec(POLICY[project])),
                       ('sink', sink_spec(POLICY[project]))):
        path = directory / ('cwe22_{}_{}.json'.format(project.replace('-', '_'), kind))
        path.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + '\n')
        paths[kind] = path.resolve()
    return paths
