"""Offline tests for the debate between the hinted LLMs (Du et al.): round-1 reuse, the
update prompt, conversation shape and the dry run. No request is sent."""
import json
import tempfile
import unittest
from pathlib import Path

from cwe22 import config, debate
from cwe22.util import write_json

SETTINGS = {"qwen": dict(model=config.MODELS["qwen"], temperature=0, max_tokens=8000, reasoning=dict(effort="low")),
            "deepseek": dict(model=config.MODELS["deepseek"], temperature=0, max_tokens=8000,
                             reasoning=dict(effort="low"))}


def answer(locations):
    findings = [dict(cwe="CWE-22", **{"class": c, "method": m}, explanation="path traversal") for c, m in locations]
    return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(dict(findings=findings))}}]}


class DebateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.relax, self.out = root / "relax", root / "out"
        for short in debate.AGENTS:
            for level in ("h1", "h2b"):
                prompt = "Q {} {}".format(level, short if level == "h2b" else "shared")
                write_json(self.relax / "llm" / "{}-{}".format(short, level) / "zip4j-fixed-s1.json",
                           dict(request=dict(SETTINGS[short], messages=[dict(role="user", content=prompt)]),
                                response=answer([("Unzip", short)])))
        self.run = debate.Debate(self.out, str(self.relax), levels=("h1", "h2b"))
        self.sent = {}

    def tearDown(self):
        self.temp.cleanup()

    def fake_ask(self, path, body, key):
        if key is None:
            return None
        self.sent[path] = body
        step = path.relative_to(self.out).parts[0]  # round1, round2, opponent or round2-opposed
        record = dict(request=body, response=answer([("Unzip", step + "-" + body["model"].split("/")[0])]))
        write_json(path, record)
        return record

    def run_cell(self, cell, key="key"):
        original, debate.llm.ask = debate.llm.ask, self.fake_ask
        try:
            return self.run.run_cell(cell, key)
        finally:
            debate.llm.ask = original

    def test_update_prompt_is_du_et_al(self):
        text = debate.update_prompt(["A1"])
        self.assertTrue(text.startswith("These are the solutions to the problem from other agents: "))
        self.assertIn("\n\n One agent solution: ```A1```", text)
        self.assertIn("Using the reasoning from other agents as additional advice, can you give an updated answer? "
                      "Examine your solution and that other agents step by step.", text)

    def test_shared_question_reuses_both_hinted_answers(self):
        self.assertEqual(self.run_cell(("h1", "h1", "zip4j", "fixed", 1)), 0)
        self.assertEqual(sorted(p.relative_to(self.out).parts[0] for p in self.sent),
                         ["opponent", "round2", "round2", "round2-opposed", "round2-opposed"])  # no new round 1
        qwen = self.sent[self.run.round2_path("h1", "qwen", "zip4j", "fixed", 1)]
        self.assertEqual([m["role"] for m in qwen["messages"]], ["user", "assistant", "user"])
        self.assertEqual(qwen["messages"][0]["content"], "Q h1 shared")
        self.assertIn('"method": "qwen"', qwen["messages"][1]["content"])     # its own round-1 answer
        self.assertIn('"method": "deepseek"', qwen["messages"][2]["content"])  # the other agent's answer
        self.assertEqual({k: v for k, v in qwen.items() if k != "messages"}, SETTINGS["qwen"])

    def test_other_model_first_answers_the_owners_configuration(self):
        self.assertEqual(self.run_cell(("h2b", "h2b-qwen", "zip4j", "fixed", 1)), 0)
        first = self.sent[self.run.round1_path("h2b", "h2b-qwen", "deepseek", "zip4j", "fixed", 1)]
        self.assertEqual(first["messages"], [dict(role="user", content="Q h2b qwen")])
        self.assertEqual({k: v for k, v in first.items() if k != "messages"}, SETTINGS["deepseek"])
        self.assertEqual(self.run.answer(1, "h2b", "h2b-qwen", "qwen", "zip4j", "fixed", 1), ([("Unzip", "qwen")], None))
        self.assertEqual(self.run.answer(2, "h2b", "h2b-qwen", "qwen", "zip4j", "fixed", 1)[0], [("Unzip", "round2-qwen")])

    def test_opposing_agent_argues_against_both_answers_and_is_read_in_round_two(self):
        self.run_cell(("h1", "h1", "zip4j", "fixed", 1))
        opponent = self.sent[self.run.opponent_path("h1", "zip4j", "fixed", 1)]
        self.assertEqual(opponent["model"], config.MODELS[debate.OPPONENT])
        challenge = opponent["messages"][0]["content"]
        self.assertTrue(challenge.startswith("You are the opposing agent"))
        self.assertIn("Q h1 shared", challenge)
        self.assertIn('"method": "qwen"', challenge)
        self.assertIn('"method": "deepseek"', challenge)
        plain = self.sent[self.run.round2_path("h1", "qwen", "zip4j", "fixed", 1)]["messages"][-1]["content"]
        opposed = self.sent[self.run.round2_path("h1", "qwen", "zip4j", "fixed", 1, opposed=True)]["messages"]
        self.assertNotIn("opponent-deepseek", plain)
        self.assertIn("opponent-deepseek", opposed[-1]["content"])
        self.assertIn('"method": "deepseek"', opposed[-1]["content"])  # the other analyst is still shown
        self.assertEqual(opposed[0]["content"], "Q h1 shared")
        self.assertEqual(self.run.answer("2o", "h1", "h1", "qwen", "zip4j", "fixed", 1)[0],
                         [("Unzip", "round2-opposed-qwen")])

    def test_dry_run_counts_and_sends_nothing(self):
        self.assertEqual(self.run_cell(("h2b", "h2b-deepseek", "zip4j", "fixed", 1), key=None), 1 + debate.LATER_CALLS)
        self.assertEqual(self.sent, {})
        self.assertEqual(self.run.answer(2, "h1", "h1", "qwen", "zip4j", "fixed", 1), (None, None))

    def test_missing_configuration_is_an_empty_answer(self):
        path = self.relax / "llm/qwen-h1/zip4j-fixed-s1.json"
        write_json(path, dict(error="No Tai-e configuration for h1"))
        self.assertEqual(self.run_cell(("h1", "h1", "zip4j", "fixed", 1)), 0)
        self.assertEqual(self.run.answer(1, "h1", "h1", "qwen", "zip4j", "fixed", 1)[0], [])

    def test_round_two_answer_after_a_quoted_answer_parses(self):
        quoted = 'The other agent said `{"findings": []}`, but {not json}. Final:\n{"findings": [' \
                 '{"cwe": "CWE-22", "class": "Unzip", "method": "x", "explanation": "path traversal"}]}'
        self.assertEqual(debate.llm.parse_findings(quoted)[0]["method"], "x")
        self.assertEqual(debate.llm.parse_findings('{"findings": [] } trailing {bad}'), [])
        with self.assertRaises(ValueError):
            debate.llm.parse_findings('see {bad} and {"other": 1} {worse}')

    def test_failed_answer_is_shown_as_no_answer(self):
        self.assertEqual(debate.content(dict(error="HTTP 500")), "(no answer)")
        self.assertEqual(debate.content({"response": {"choices": [{"message": {"content": "  "}}]}}), "(no answer)")


if __name__ == "__main__":
    unittest.main()
