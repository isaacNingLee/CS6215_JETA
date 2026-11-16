"""Regression test: the saved runs still reproduce the numbers the report quotes (no request is
sent). Needs the CWE-Bench-Java labels (python3 -m cwe22 setup), else it skips."""
import tempfile
import unittest
from pathlib import Path

from cwe22 import config, paper


def dataset_ready():
    return (config.DATASET / "data/fix_info.csv").is_file() and (config.RESULTS / "261021c/predictions.json").is_file()


@unittest.skipUnless(dataset_ready(), "needs the dataset (python3 -m cwe22 setup) and results/")
class PaperNumbersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.out = paper.write(Path(cls.temp.name))
        cls.numbers = __import__("json").loads((cls.out / "numbers.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def macro(self, row):
        return [round(row[k][0], 1) for k in ("fdr", "f1", "det")]

    def test_abstract_and_table1(self):
        table = self.numbers["table1"]
        self.assertEqual(self.macro(table["Tai-e"]["macro"]), [85.5, 24.4, 6.0])
        self.assertEqual(self.macro(table["JETA"]["macro"]), [5.6, 96.3, 6.0])
        self.assertEqual(self.macro(table["Hinted DeepSeek"]["macro"]), [30.6, 77.8, 5.7])
        self.assertEqual(self.macro(table["LLMDFA Qwen"]["macro"]), [64.4, 42.1, 3.3])

    def test_table2_ablation_and_pair_correct(self):
        stages = self.numbers["table2_ablation"]
        self.assertEqual(self.macro(stages["Agreement guard"]), [27.4, 79.5, 6.0])
        self.assertEqual(round(stages["+ blind checklist"]["pc"][0], 1), 1.3)
        self.assertEqual(round(stages["+ blind checklist"]["flag"][0], 1), 4.7)

    def test_hint_relaxation(self):
        jeta = self.numbers["figure5_6_relaxation"]["Qwen"]["+ checklist"]
        self.assertEqual([round(jeta[l]["f1"][0], 1) for l in ("H1", "H2a", "H2b")], [72.2, 84.1, 91.1])
        deepseek = self.numbers["figure5_6_relaxation"]["DeepSeek"]["+ checklist"]
        self.assertEqual(round(deepseek["E"]["det"][0], 1), 1.0)

    def test_cost(self):
        jeta = self.numbers["table3_cost"]["rows"]["JETA"]
        self.assertEqual((jeta["calls"], round(jeta["cost"], 3), round(jeta["seconds_per_run"], 1)), (221, 0.980, 124.2))

    def test_tables_are_written(self):
        for name in ("table1_main.tex", "table2_ablation.tex", "table3_cost.tex", "SUMMARY.md"):
            self.assertTrue((self.out / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
