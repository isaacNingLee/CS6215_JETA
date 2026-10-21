"""Offline tests for the checklist filter: checklist parsing, the fixed decision rule, request
shapes and the method-context extractor (needs JDK 17 and the Tai-e jar, else it skips).
No request is sent."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from cwe22 import checklist, config
from cwe22.util import write_json
from tests.test_agreement import java_ready

CHECKLIST = {"safe_patterns": [{"name": "contain", "conditions": ["Resolved?", "Checked?"]},
                               {"name": "reject", "conditions": ["Rejects '..'?"]}]}


def chat(content):
    return {"request": {}, "response": {"choices": [{"finish_reason": "stop", "message": {"content": content}}]}}


def jev(probabilities):
    return {"request": {}, "response": {"answers": {q: {"type": "noul", "noul": p} for q, p in probabilities.items()}}}


class ChecklistTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.run = checklist.Run(Path(self.temp.name))
        write_json(self.run.blind_path(1), chat(json.dumps(CHECKLIST)))

    def tearDown(self):
        self.temp.cleanup()

    def test_prompts_keep_their_json_braces(self):
        text = checklist.fill(checklist.ANSWER, code="CODE", questions="- p1_c1: Q")
        self.assertIn("CODE", text)
        self.assertIn('{"answers": {"<id>": true}}', text)
        self.assertIn('{"safe_patterns": [', checklist.fill(checklist.BLIND))

    def test_blind_prompt_names_no_subject(self):
        text = checklist.fill(checklist.BLIND).lower()
        for word in config.PROJECTS + ["zip", "archive", "entry", "extract", "canonical"]:
            self.assertNotIn(word, text)

    def test_patterns_and_question_ids(self):
        found = checklist.patterns(chat(json.dumps(CHECKLIST)))
        groups, text = checklist.question_ids(found)
        self.assertEqual(groups, [["p1_c1", "p1_c2"], ["p2_c1"]])
        self.assertEqual(text["p2_c1"], "Rejects '..'?")
        with self.assertRaises(ValueError):
            checklist.patterns(chat('{"safe_patterns": [{"name": "x", "conditions": []}]}'))
        self.assertEqual(checklist.patterns(chat('{"safe_patterns": []}')), [])  # nothing can protect: keep

    def test_jev_request_is_one_noul_question_per_condition(self):
        body = checklist.jev_body("CODE", checklist.patterns(chat(json.dumps(CHECKLIST))))
        self.assertEqual(body["model"], checklist.JEV)
        self.assertEqual(body["state"]["code"], "CODE")
        self.assertEqual(sorted(body["questions"]), ["p1_c1", "p1_c2", "p2_c1"])
        self.assertEqual(body["questions"]["p1_c2"],
                         dict(type="noul", instructions="True if the answer to this question is yes: Checked?"))

    def test_dropped_only_when_every_condition_of_a_pattern_is_yes(self):
        cases = [({"p1_c1": 0.9, "p1_c2": 0.5, "p2_c1": 0.1}, True),   # pattern 1 complete (0.5 counts as yes)
                 ({"p1_c1": 0.9, "p1_c2": 0.49, "p2_c1": 0.1}, False),
                 ({"p1_c1": 0.1, "p1_c2": 0.1, "p2_c1": 0.7}, True)]   # pattern 2 alone
        for probabilities, expected in cases:
            write_json(self.run.answer_path("blind-jev", "CODE", 1), jev(probabilities))
            self.assertEqual(self.run.decide("blind-jev", "CODE", 1), (expected, None))

    def test_deepseek_answers_and_failures_keep_the_location(self):
        write_json(self.run.answer_path("blind-deepseek", "CODE", 1),
                   chat('{"answers": {"p1_c1": true, "p1_c2": "yes", "p2_c1": false}}'))
        self.assertEqual(self.run.decide("blind-deepseek", "CODE", 1), (False, None))  # only true counts as yes
        write_json(self.run.answer_path("blind-jev", "CODE", 1), {"request": {}, "error": "HTTP 500"})
        self.assertEqual(self.run.decide("blind-jev", "CODE", 1)[0], False)
        self.assertEqual(self.run.decide("blind-jev", None, 1), (False, None))       # no project code
        self.assertEqual(self.run.decide("blind-jev", "OTHER", 1), (None, None))     # not run yet
        self.assertEqual(self.run.decide("local-jev", "CODE", 1), (None, None))      # no local checklist yet
        write_json(self.run.local_path("CODE", 1), chat('{"safe_patterns": []}'))
        self.assertEqual(self.run.decide("local-jev", "CODE", 1), (False, None))     # empty checklist: kept
        self.assertEqual(self.run.make("local-jev", "CODE", 1, None), 0)

    def test_dry_run_sends_nothing(self):
        self.assertEqual(self.run.make("local-jev", "CODE", 1, None), 2)
        self.assertEqual(self.run.make("blind-jev", "CODE", 1, None), 1)
        self.assertFalse(self.run.answer_path("blind-jev", "CODE", 1).exists())


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
            java = checklist.compile_context(root / "classes")
            rows = json.loads(subprocess.run(java + [str(request)], check=True, capture_output=True,
                                             text=True).stdout)
            roles = [(m["role"], m["text"].split("(")[0].split()[-1]) for m in rows[0]["members"]]
            self.assertEqual(roles, [("field", "root;"), ("constructor", "Unpack"), ("method under review", "process"),
                                     ("method under review", "process"), ("called method", "write"),
                                     ("called method", "log")])
            self.assertEqual(rows[1]["members"], [])
            code = checklist.render_code(rows, root, "Unpack", "process")
            self.assertTrue(code.startswith("// File: src/main/java/p/Outer.java\n// Method under review: Unpack.process"))
            self.assertNotIn("other()", code)
            self.assertIsNone(checklist.render_code(rows[1:], root, "Unpack", "missing"))


if __name__ == "__main__":
    unittest.main()
