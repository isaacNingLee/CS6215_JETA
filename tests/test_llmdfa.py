"""Offline tests for the LLMDFA baseline: the CWE-22 specs agree with the Tai-e policy and the
hints, the OpenRouter transport, the recorded deviations and the scoring. No request is sent,
and LLMDFA itself is not imported."""
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from cwe22 import config, llmdfa, llmdfa_runtime, llmdfa_specs as specs
from cwe22.util import write_json


class SpecTest(unittest.TestCase):
    def test_policy_matches_the_hints_and_the_taie_policy(self):
        self.assertTrue(specs.check_policy_matches_hints())
        checked = specs.check_policy_matches_taie()
        self.assertEqual(sorted(checked), sorted(config.PROJECTS))
        self.assertIn("getFileName", checked["zip4j"]["sources"][0])

    def test_drifted_policy_is_rejected(self):
        drifted = dict(specs.POLICY["zip4j"], source_method="getName")
        with mock.patch.dict(specs.POLICY, {"zip4j": drifted}):
            with self.assertRaises(ValueError):
                specs.check_policy_matches_taie(["zip4j"])

    def test_specs_name_no_subject(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = specs.write_specs("zip4j", Path(temp))
            text = paths["source"].read_text() + paths["sink"].read_text()
        self.assertIn("getFileName", text)                       # the policy's own API
        for word in ("zip4j", "Unzip", "initExtractFile", "lingala"):
            self.assertNotIn(word, text)


class RuntimeTest(unittest.TestCase):
    def test_deviations_are_recorded_and_name_openrouter(self):
        deviations = llmdfa.runtime_deviations()
        self.assertEqual(deviations, list(llmdfa_runtime.DEVIATIONS))
        self.assertTrue(any("OpenRouter" in d for d in deviations))
        self.assertFalse(any("SoCLaaS" in d for d in deviations))

    def test_cost_and_provider_errors(self):
        self.assertEqual(llmdfa_runtime.support.cost_of({"usage": {"cost": 0.002}}), 0.002)
        self.assertIsNone(llmdfa_runtime.support.cost_of({"usage": {}}))
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({"error": {"code": 502}}).encode()
        with mock.patch("urllib.request.urlopen", return_value=response):
            with self.assertRaises(urllib.error.URLError):  # retried by the wrapper, not a silent answer
                llmdfa_runtime.support.infer(dict(model="m", messages=[]), "key", 10)

    def test_requests_use_the_plans_model_budget_and_low_reasoning(self):
        sent = []

        def infer(body, key, timeout):
            sent.append(body)
            return {"model": body["model"], "usage": {"cost": 0.001, "prompt_tokens": 1, "completion_tokens": 1},
                    "choices": [{"finish_reason": "stop", "message": {"content": "- Src name: n, Line number: 1"}}]}
        plan = dict(model=config.MODELS["deepseek"], max_tokens=16000, max_requests=5, cost_limit=1.0,
                    request_timeout=10)
        with tempfile.TemporaryDirectory() as temp:
            model_class, ledger = llmdfa_runtime.hosted_model(plan, Path(temp) / "ledger.json", "key", infer)
            answer, _, _ = model_class("x", "", 0, "role").infer("question")
        self.assertEqual(answer, "- Src name: n, Line number: 1")
        self.assertEqual({k: sent[0][k] for k in ("model", "temperature", "max_tokens", "reasoning")},
                         dict(model=config.MODELS["deepseek"], temperature=0, max_tokens=16000,
                              reasoning=dict(effort="low")))
        self.assertEqual(ledger["state"]["attempts"], 1)


    def test_cut_off_answer_is_used_as_returned_and_counted(self):
        def infer(body, key, timeout):
            return {"model": body["model"], "usage": {"cost": 0.001},
                    "choices": [{"finish_reason": "length", "message": {"content": "- Src name: a, Line"}}]}
        plan = dict(model="m", max_tokens=10, max_requests=5, cost_limit=1.0, request_timeout=10)
        with tempfile.TemporaryDirectory() as temp:
            model_class, ledger = llmdfa_runtime.hosted_model(plan, Path(temp) / "ledger.json", "key", infer)
            answer, _, _ = model_class("x", "", 0, "role").infer("question")
        self.assertEqual(answer, "- Src name: a, Line")
        self.assertEqual(ledger["state"]["truncated_answers"], 1)
        self.assertFalse(ledger["state"]["failed"])


    def test_null_answer_with_reasoning_is_an_empty_answer(self):
        def infer(body, key, timeout):
            return {"model": body["model"], "usage": {"cost": 0.001},
                    "choices": [{"finish_reason": "stop", "message": {"content": None, "reasoning": "no source"}}]}
        plan = dict(model="m", max_tokens=10, max_requests=5, cost_limit=1.0, request_timeout=10)
        with tempfile.TemporaryDirectory() as temp:
            model_class, ledger = llmdfa_runtime.hosted_model(plan, Path(temp) / "ledger.json", "key", infer)
            answer, _, _ = model_class("x", "", 0, "role").infer("question")
        self.assertEqual(answer, "")
        self.assertEqual(ledger["state"]["reasoning_only_answers"], 1)


class ScoringTest(unittest.TestCase):
    def test_failed_case_reports_nothing_and_completed_cases_score(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "run"
            for project in config.PROJECTS:
                for variant in config.VARIANTS:
                    row = dict(status="completed", locations=[["Unzip", "initExtractFile"]] if variant == "vulnerable"
                               else [])
                    if project == "zt-zip" and variant == "vulnerable":
                        row = dict(status="failed", error="exit 1: boom")
                    write_json(llmdfa.arm_dir(out, "qwen", 1) / "{}-{}".format(variant, project) / "result.json", row)
            report = llmdfa.evaluate(out, models=("qwen",), samples=1)
        summary = report["arms"][0]["summary"]
        self.assertEqual(summary["detected"], [1])        # only zip4j's fix is Unzip.initExtractFile
        self.assertEqual(summary["pair_correct"], [1])    # nothing is reported on any fixed revision
        self.assertEqual(summary["per_project"]["zt-zip"]["failed"], 1)


if __name__ == "__main__":
    unittest.main()
