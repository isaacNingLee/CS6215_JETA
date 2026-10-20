"""Offline unit tests: python3 -m unittest discover -s tests"""
import tempfile
import unittest
from pathlib import Path

from cwe22 import llm, report, taie
from cwe22.util import write_json
from cwe22.scoring import aggregate, flow_endpoints, flow_locations, score, taie_location

FLOW = ("TaintFlow{<a.b.Unzip: void initExtractFile(a.F)>[3@L10] $r1 = invokevirtual h.getFileName()/result"
        " -> <a.b.UnzipEngine$Inner: void <init>(java.io.File)>[1@L5] invokespecial this.<init>(f)/0}")
LABELS = [dict(**{"class": "Unzip", "method": "initExtractFile", "file": "src/main/java/a/b/Unzip.java"})]


def response(content, finish="stop"):
    return {"choices": [{"finish_reason": finish, "message": {"content": content}}]}


class ScoringTest(unittest.TestCase):
    def test_taie_location_maps_inner_class_and_constructor(self):
        self.assertEqual(taie_location("<a.Outer$Inner: void <init>(int)>"), ("Inner", "Inner"))
        self.assertEqual(taie_location("<a.B: java.lang.String m()>"), ("B", "m"))

    def test_flow_endpoints_and_locations(self):
        self.assertEqual(len(flow_endpoints(FLOW)), 2)
        self.assertEqual(flow_locations([FLOW, FLOW]), [("Inner", "Inner"), ("Unzip", "initExtractFile")])
        with self.assertRaises(ValueError):
            flow_endpoints("not a flow")

    def test_score_matches_proxy_definition(self):
        row = score([("Unzip", "initExtractFile"), ("X", "y"), ("X", "y")], LABELS)
        self.assertEqual((row["reported"], row["matched"], row["detected"]), (2, 1, True))
        self.assertAlmostEqual(row["fdr"], 0.5)
        self.assertAlmostEqual(row["f1"], 2 / 3)
        empty = score([], LABELS)
        self.assertEqual((empty["fdr"], empty["f1"], empty["detected"]), (None, 0.0, False))

    def test_aggregate_excludes_empty_from_fdr_and_flags_incomplete(self):
        rows = [dict(status="scored", **score([("Unzip", "initExtractFile")], LABELS)),
                dict(status="scored", **score([], LABELS))]
        summary = aggregate(rows)
        self.assertEqual((summary["detected"], summary["fdr_projects"]), (1, 1))
        self.assertAlmostEqual(summary["macro_f1"], 0.5)
        self.assertFalse(aggregate(rows + [dict(status="unscored")])["complete"])


class TaieTest(unittest.TestCase):
    def test_parse_console_requires_consistent_count(self):
        self.assertEqual(taie.parse_console("Detected 1 taint flow(s):\n" + FLOW + "\n"), [FLOW])
        with self.assertRaises(RuntimeError):
            taie.parse_console("Detected 2 taint flow(s):\n" + FLOW + "\n")

    def test_only_zt_zip_pom_is_patched(self):
        pom = b"<source>1.5</source><target>1.6</target>"
        self.assertEqual(taie.patched_pom("zt-zip", pom), b"<source>1.7</source><target>1.7</target>")
        self.assertEqual(taie.patched_pom("zip4j", pom), pom)


class LlmTest(unittest.TestCase):
    def test_locations_keep_only_path_traversal_findings(self):
        content = ('Here: {"findings": [{"cwe": "CWE-22", "class": "Unzip", "method": "initExtractFile"},'
                   '{"cwe": "CWE-79", "class": "A", "method": "b", "explanation": "xss"},'
                   '{"cwe": "CWE-20", "class": "C", "method": "d", "explanation": "Zip Slip risk"},'
                   '{"cwe": "CWE-22", "class": "", "method": "x"}]}')
        locations, findings = llm.cwe22_locations(response(content))
        self.assertEqual(locations, [["C", "d"], ["Unzip", "initExtractFile"]])
        self.assertEqual(len(findings), 4)

    def test_incomplete_or_malformed_responses_are_unusable(self):
        for raw in (response('{"findings": []}', finish="length"), response(""),
                    response("no json here"), response('{"findings": ["x"]}')):
            with self.assertRaises(ValueError):
                llm.cwe22_locations(raw)
        self.assertEqual(llm.cwe22_locations(response('{"findings": []}'))[0], [])

    def test_failed_answer_counts_as_empty_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            path = llm.cell_path(run_dir, "deepseek", "vanilla", "zt-zip", "vulnerable", 2)
            write_json(path, dict(response=response("", finish="length")))
            cell = ("deepseek", "vanilla")
            locations, failure, missing = report.load_locations(run_dir, cell, "zt-zip", "vulnerable", 2)
            self.assertEqual((locations, missing), ([], None))
            self.assertIn("length", failure)
            row = score(locations, LABELS)
            self.assertEqual((row["detected"], row["f1"], row["fdr"]), (False, 0.0, None))
            self.assertEqual(report.load_locations(run_dir, cell, "zt-zip", "vulnerable", 1),
                             (None, None, "not run"))

    def test_spread_and_range_formatting(self):
        stat = report.spread([0.5, None, 1.0])
        self.assertEqual((stat["mean"], stat["min"], stat["max"]), (0.75, 0.5, 1.0))
        self.assertIsNone(report.spread([None]))
        self.assertEqual(report.ranged(stat, report.f4), "0.7500 [0.5000–1.0000]")
        self.assertEqual(report.ranged(report.spread([1.0, 1.0]), report.f4), "1.0000")

    def test_prompts_render(self):
        files = [("A.java", "class A {}"), ("B.java", "class B {}")]
        vanilla = llm.build_prompt("vanilla", "zip4j", files)
        self.assertIn("File: A.java", vanilla)
        self.assertNotIn("B.java", vanilla)
        hinted = llm.build_prompt("hinted", "zip4j", files)
        self.assertIn("FileHeader.getFileName()", hinted)
        self.assertIn("File: B.java", hinted)


if __name__ == "__main__":
    unittest.main()
