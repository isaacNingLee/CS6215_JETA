"""Offline tests for the proposed pipeline: the hinted answers it judges, the Jev judge, the blind
checklist and its fixed rule, request shapes, and the method-context extractor (needs JDK 17 and
the Tai-e jar, else it skips). No request is sent."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from cwe22 import config, pipeline
from cwe22.util import write_json
from tests.test_agreement import java_ready

CHECKLIST = {"safe_patterns": [{"name": "contain", "conditions": ["Resolved?", "Checked?"]},
                               {"name": "reject", "conditions": ["Rejects '..'?"]}]}
SETTINGS = {"qwen": dict(model=config.MODELS["qwen"], temperature=0, max_tokens=8000),
            "deepseek": dict(model=config.MODELS["deepseek"], temperature=0, max_tokens=8000)}


def chat(content):
    return {"request": {}, "response": {"choices": [{"finish_reason": "stop", "message": {"content": content}}]}}


def decisions(probabilities):
    return {"request": {}, "response": {"answers": {q: {"type": "noul", "noul": p} for q, p in probabilities.items()}}}


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.results, self.out = root / "results", root / "results" / "run"
        relax_dir = self.results / "relax"
        for short in pipeline.AGENTS:  # H1: both answer the shared prompt; H2b: each answers its own
            for level, prompt in (("h1", "Q h1"), ("h2b", "Q h2b " + short)):
                write_json(relax_dir / "llm" / "{}-{}".format(short, level) / "zip4j-fixed-s1.json",
                           dict(request=dict(SETTINGS[short], messages=[dict(role="user", content=prompt)]),
                                response=chat('{"findings": []}')["response"]))
        self.original = pipeline.config.RESULTS
        pipeline.config.RESULTS = self.results
        self.run = pipeline.Run(self.out, "relax", baseline="relax")
        write_json(self.run.checklist_path(1), chat(json.dumps(CHECKLIST)))

    def tearDown(self):
        pipeline.config.RESULTS = self.original
        self.temp.cleanup()

    def test_blind_prompt_names_no_subject(self):
        text = pipeline.fill(pipeline.BLIND).lower()
        self.assertIn('{"safe_patterns": [', text)
        for word in config.PROJECTS + ["zip", "archive", "entry", "extract", "canonical"]:
            self.assertNotIn(word, text)

    def test_patterns_and_question_ids(self):
        found = pipeline.patterns(chat(json.dumps(CHECKLIST)))
        groups, text = pipeline.question_ids(found)
        self.assertEqual(groups, [["p1_c1", "p1_c2"], ["p2_c1"]])
        self.assertEqual(text["p2_c1"], "Rejects '..'?")
        with self.assertRaises(ValueError):
            pipeline.patterns(chat('{"safe_patterns": [{"name": "x", "conditions": []}]}'))
        self.assertEqual(pipeline.patterns(chat('{"safe_patterns": []}')), [])  # nothing can protect: keep

    def test_checklist_request_is_one_noul_question_per_condition(self):
        body = pipeline.checklist_body("CODE", pipeline.patterns(chat(json.dumps(CHECKLIST))))
        self.assertEqual(body["model"], pipeline.JEV)
        self.assertEqual(body["state"]["code"], "CODE")
        self.assertEqual(body["questions"]["p1_c2"],
                         dict(type="noul", instructions="True if the answer to this question is yes: Checked?"))

    def test_checklist_drops_only_when_every_condition_of_a_pattern_is_yes(self):
        cases = [({"p1_c1": 0.9, "p1_c2": 0.5, "p2_c1": 0.1}, True),   # pattern 1 complete (0.5 counts as yes)
                 ({"p1_c1": 0.9, "p1_c2": 0.49, "p2_c1": 0.1}, False),
                 ({"p1_c1": 0.1, "p1_c2": 0.1, "p2_c1": 0.7}, True)]   # pattern 2 alone
        for probabilities, expected in cases:
            write_json(self.run.checklist_answer_path("CODE", 1), decisions(probabilities))
            self.assertEqual(self.run.dropped("CODE", 1), (expected, None))
        write_json(self.run.checklist_answer_path("CODE", 1), {"request": {}, "error": "HTTP 500"})
        self.assertEqual(self.run.dropped("CODE", 1)[0], False)       # a failed answer keeps the location
        self.assertEqual(self.run.dropped(None, 1), (False, None))    # no project code: kept
        self.assertEqual(self.run.dropped("OTHER", 1), (None, None))  # not answered yet
        write_json(self.run.checklist_path(2), chat('{"safe_patterns": []}'))
        self.assertEqual(self.run.dropped("CODE", 2), (False, None))  # empty checklist: kept

    def test_shared_prompt_reuses_both_saved_answers(self):
        records = self.run.answers("h1", "h1", "zip4j", "fixed", 1)
        self.assertTrue(all(records))
        self.assertFalse((self.out / "hinted").exists())

    def test_other_model_answers_the_owners_configuration(self):
        sent = {}

        def ask(path, body, key, url=None):
            sent[path] = body
            return dict(request=body)
        original, pipeline.llm.ask = pipeline.llm.ask, ask
        try:
            self.assertIsNone(self.run.answers("h2b", "h2b-qwen", "zip4j", "fixed", 1)[1])  # never asks by default
            records = self.run.answers("h2b", "h2b-qwen", "zip4j", "fixed", 1, key="key")
        finally:
            pipeline.llm.ask = original
        path = self.out / "hinted" / "h2b-qwen" / "deepseek" / "zip4j-fixed-s1.json"
        self.assertEqual(list(sent), [path])
        self.assertEqual(sent[path], dict(SETTINGS["deepseek"], messages=[dict(role="user", content="Q h2b qwen")]))
        self.assertEqual(records[0]["request"]["messages"][0]["content"], "Q h2b qwen")  # Qwen's own saved answer

    def test_judge_keeps_locations_jev_ties_to_the_vulnerability(self):
        priority = [("Unzip", "initExtractFile"), ("JarFile", "getBytes")]
        records = self.run.answers("h1", "h1", "zip4j", "fixed", 1)
        body = self.run.judge_body(records, priority, {"Unzip.initExtractFile": "CODE"})
        self.assertEqual(body["model"], pipeline.JEV)
        self.assertEqual(len(body["state"]["agent_answers"]), 2)
        self.assertEqual(body["state"]["methods"], {"Unzip.initExtractFile": "CODE", "JarFile.getBytes": pipeline.NO_CODE})
        self.assertEqual(body["questions"]["m1"]["instructions"],
                         pipeline.JUDGE_QUESTION.format(method="Unzip.initExtractFile"))
        codes = {"Unzip.initExtractFile": "CODE"}
        self.assertEqual(self.run.judged("h1", "h1", "zip4j", "fixed", 1, priority, codes), (None, None))
        write_json(self.run.judge_path(body), decisions({"m1": 0.5, "m2": 0.49}))
        self.assertEqual(self.run.judged("h1", "h1", "zip4j", "fixed", 1, priority, codes),
                         ([("Unzip", "initExtractFile")], None))
        self.assertEqual(self.run.judged("h1", "h1", "zip4j", "fixed", 1, [], codes), ([], None))
        write_json(self.run.judge_path(body), {"request": {}, "error": "HTTP 500"})
        self.assertEqual(self.run.judged("h1", "h1", "zip4j", "fixed", 1, priority, codes)[0], priority)

    def test_stages_apply_the_judge_then_the_checklist(self):
        priority = [("Unzip", "initExtractFile"), ("Unzip", "check")]
        codes = {"Unzip.initExtractFile": "A", "Unzip.check": "B"}
        body = self.run.judge_body(self.run.answers("h1", "h1", "zip4j", "fixed", 1), priority, codes)
        write_json(self.run.judge_path(body), decisions({"m1": 0.9, "m2": 0.9}))
        write_json(self.run.checklist_answer_path("A", 1), decisions({"p1_c1": 0.9, "p1_c2": 0.9, "p2_c1": 0}))
        write_json(self.run.checklist_answer_path("B", 1), decisions({"p1_c1": 0.1, "p1_c2": 0.9, "p2_c1": 0}))
        stages, failures = self.run.stages("h1", "h1", "zip4j", "fixed", 1, priority, codes)
        self.assertEqual(stages, dict(guard=priority, judged=priority, checked=[("Unzip", "check")]))
        self.assertEqual(failures, [])


@unittest.skipUnless(java_ready(), "needs JDK 17 and the Tai-e jar (python3 -m cwe22 setup)")
class MethodContextTest(unittest.TestCase):
    SOURCE = """package p;
class Outer {
  int unrelated() { return 0; }
  static class Unpack {
    private final java.io.File root;
    Unpack(java.io.File root) { this.root = root; }
    void process(String name) throws java.io.IOException { write(name); this.log(name); }
    void process(int x) { }
    private void write(String name) { }
    private void log(String name) { }
    private void other() { }
  }
}
"""

    def test_method_with_fields_constructors_and_same_class_callees(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "src/main/java/p/Outer.java"
            source.parent.mkdir(parents=True)
            source.write_text(self.SOURCE)
            request = root / "request.json"
            write_json(request, [{"file": str(source), "class": "Unpack", "method": "process"},
                                 {"file": str(source), "class": "Unpack", "method": "missing"}])
            java = pipeline.compile_context(root / "classes")
            rows = json.loads(subprocess.run(java + [str(request)], check=True, capture_output=True,
                                             text=True).stdout)
            roles = [(m["role"], m["text"].split("(")[0].split()[-1]) for m in rows[0]["members"]]
            self.assertEqual(roles, [("field", "root;"), ("constructor", "Unpack"), ("method under review", "process"),
                                     ("method under review", "process"), ("called method", "write"),
                                     ("called method", "log")])
            self.assertEqual(rows[1]["members"], [])
            code = pipeline.render_code(rows, root, "Unpack", "process")
            self.assertTrue(code.startswith("// File: src/main/java/p/Outer.java\n// Method under review: Unpack.process"))
            self.assertNotIn("other()", code)
            self.assertIsNone(pipeline.render_code(rows[1:], root, "Unpack", "missing"))


if __name__ == "__main__":
    unittest.main()
