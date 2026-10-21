"""Offline tests for the hint-relaxation pipeline."""
import tempfile
import unittest
from pathlib import Path

from cwe22 import config, entry, relax, spec

FLOW = ("TaintFlow{<a.Unzip: void run(a.H)>[3@L10] $r1 = invokevirtual h.getFileName()/result"
        " -> <a.Out: void <init>(java.io.File)>[1@L5] invokespecial this.<init>(f)/0}")


def method(signature, cls, name, ret="java.lang.String", params=(), ctor=False, project=True):
    return dict(signature=signature, declaring_class=cls, name=name, return_type=ret, parameter_types=list(params),
                constructor=ctor, project_class=project)


GET = "<a.H: java.lang.String getFileName()>"
CATALOGUE = dict(
    methods=[method(GET, "a.H", "getFileName"),
             method("<a.H: java.lang.String fix(java.lang.String)>", "a.H", "fix", params=["java.lang.String"]),
             method("<java.lang.String: java.lang.String trim()>", "java.lang.String", "trim", project=False),
             method("<a.H: int size()>", "a.H", "size", ret="int")],
    call_sites=[dict(id="<a.Unzip: void run(a.H)>#3", caller="<a.Unzip: void run(a.H)>", line=10,
                     declared_target=GET, resolved_target=GET, possible_targets=[GET],
                     source_context=dict(text="10: h.getFileName()"))]
    + [dict(id="x#{}".format(i), caller="<a.Unzip: void run(a.H)>", line=11, declared_target=t, resolved_target=t,
            possible_targets=[t], source_context=None)
       for i, t in enumerate(["<a.H: java.lang.String fix(java.lang.String)>",
                              "<java.lang.String: java.lang.String trim()>", "<a.H: int size()>"])])


class SpecTest(unittest.TestCase):
    def test_candidates_exclude_transformers_utilities_and_non_paths(self):
        self.assertEqual(spec.candidate_sources(CATALOGUE), [GET])

    def test_app_scope_and_attribution(self):
        self.assertEqual(spec.app_scoped([FLOW], {"a.Unzip", "a.Out"}), [FLOW])
        self.assertEqual(spec.app_scoped([FLOW], {"a.Unzip"}), [])
        self.assertEqual(spec.attribute(FLOW, CATALOGUE, [GET]), ([GET], "call_site"))

    def test_selection_keeps_everything_not_validly_rejected(self):
        payload, sites = spec.selection_payload([GET, "<a.H: java.lang.String fix(java.lang.String)>"], [CATALOGUE])
        self.assertEqual(sites, {"K1": "C01", "K2": "C02"})  # sorted: fix, getFileName
        answer = {"sources": [{"id": "C02", "decision": "not_source", "reason": "constant", "evidence": ["K2"]},
                              {"id": "C01", "decision": "not_source", "reason": "uncited", "evidence": []}]}
        decisions, errors, valid = spec.validate_selection(answer, payload, sites)
        self.assertEqual(valid, 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(spec.selected_sources(payload, decisions), ["<a.H: java.lang.String fix(java.lang.String)>"])

    def test_policy_has_kit_and_only_extra_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "p"
            kit = spec.kit_sources()[0]
            self.assertEqual(spec.write_policy(folder, [GET, kit]), [GET])
            names = sorted(p.name for p in folder.glob("*.yml"))
            self.assertEqual(names, ["candidate-sources.yml", "sinks.yml", "sources.yml",
                                     "string-transfers.yml", "transfers.yml"])
            spec.write_policy(folder)
            self.assertNotIn("candidate-sources.yml", [p.name for p in folder.glob("*.yml")])


class RelaxTest(unittest.TestCase):
    def test_levels_map_to_tai_e_configurations(self):
        self.assertEqual([relax.taie_config(l, "qwen") for l in relax.LEVELS],
                         ["manual", "h1", "h2a", "h2b-qwen", "e-qwen-h2b"])
        self.assertEqual([relax.entry_of(c) for c in ("manual", "h2b-qwen", "e-qwen-h2a")], ["manual", "manual", "e-qwen"])

    def test_first_level_is_the_hinted_baseline(self):
        run = relax.Run(Path("/r/relaxrun"), ["zip4j"], ["qwen"], baseline="base")
        self.assertEqual(run.cell_path("qwen", "hinted", "zip4j", "fixed", 2),
                         config.RESULTS / "base/llm/qwen-hinted/zip4j-fixed-s2.json")
        self.assertEqual(run.cell_path("qwen", "h1", "zip4j", "fixed", 2), Path("/r/relaxrun/llm/qwen-h1/zip4j-fixed-s2.json"))

    def test_hint_is_exactly_the_tai_e_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = relax.Run(Path(tmp), ["zip4j"], ["qwen"])
            self.assertIsNone(run.hint("e-qwen-h2b", "zip4j"))
            run.write_policies("manual")
            hint = run.hint("manual", "zip4j")
            self.assertIn("Zip4jEntry.java", hint)
            self.assertIn("FileHeader: java.lang.String getFileName()", hint)
            self.assertNotIn("UnzipEngine.java", hint)  # manual sink_files are not part of the configuration

    def test_driver_extraction(self):
        record = dict(response={"choices": [{"finish_reason": "stop", "message": {
            "content": "x\n```java\npublic class AutoEntry {}\n```"}}]})
        self.assertEqual(entry.java_block(record), "public class AutoEntry {}\n")
        with self.assertRaises(ValueError):
            entry.java_block(dict(error="HTTP 500"))


if __name__ == "__main__":
    unittest.main()
