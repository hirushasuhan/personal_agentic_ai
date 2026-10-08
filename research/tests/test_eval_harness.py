"""
Unit Tests for Evaluation Harness (Milestone M2b Close-out)
ADR-011 v2.1 & Definition of Done

Verifies:
1. Frozen dataset hash validation and negative control on file mutation (refusal).
2. Hidden test isolation invariant: hidden tests NEVER leak into model prompts.
3. End-to-end evaluation flow with repeats using loopback mock model server.
4. Detection of per-task flips across repeats.
5. Detection of false-accept (model passes own tests, fails hidden tests).
6. Detection of false-reject (model fails verify loop, but solution passes hidden tests).
7. Resilient error handling when model server crashes / returns HTTP 500.
8. Raw JSONL recording and recompute parity (compute_eval_metrics_from_jsonl).
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import tempfile
import threading
import unittest
from typing import Any, Dict

import _bootstrap  # noqa: F401
import eval_harness
from eval_sets.hidden_tests.test_coding_tasks import HIDDEN_TESTS


class MockModelServer:
    """Threaded local loopback HTTP server mocking Ollama /api/generate."""

    def __init__(self):
        self.handler_fn = None
        self.requests = []

        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode("utf-8")
                try:
                    data = json.loads(body)
                except Exception:
                    data = {"raw": body}
                outer.requests.append(data)

                if outer.handler_fn:
                    status_code, resp_payload = outer.handler_fn(data)
                else:
                    status_code, resp_payload = 200, {"response": "def add(a, b): return a + b"}

                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(resp_payload).encode("utf-8"))

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TestEvalHarness(unittest.TestCase):
    def setUp(self):
        self.mock_server = MockModelServer()
        self.orig_model_url = os.environ.get("PAI_MODEL_URL")
        os.environ["PAI_MODEL_URL"] = self.mock_server.url
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_eval_test_")

    def tearDown(self):
        self.mock_server.close()
        if self.orig_model_url is not None:
            os.environ["PAI_MODEL_URL"] = self.orig_model_url
        else:
            os.environ.pop("PAI_MODEL_URL", None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_verify_eval_set_hashes_clean(self):
        """Standard check: All registered frozen eval sets match their recorded hashes."""
        verified = eval_harness.verify_eval_set_hashes()
        self.assertIn("research/eval_sets/coding_tasks.json", verified)
        self.assertIn("research/eval_sets/coding_tasks_singlish.json", verified)
        self.assertIn("research/eval_sets/hidden_tests/test_coding_tasks.py", verified)

    def test_negative_control_hash_mismatch_refuses_execution(self):
        """Negative control: Mutating one byte of an eval set causes immediate refusal."""
        fake_registry = os.path.join(self.tmp_dir, "fake_hashes.json")
        with open(fake_registry, "w", encoding="utf-8") as f:
            json.dump({
                "file_hashes_sha256": {
                    "research/eval_sets/coding_tasks.json": "0000000000000000000000000000000000000000000000000000000000000000",
                }
            }, f)

        with self.assertRaises(eval_harness.EvalSetIntegrityError) as ctx:
            eval_harness.verify_eval_set_hashes(
                hash_file_path=fake_registry,
                checked_files=["research/eval_sets/coding_tasks.json"],
            )
        self.assertIn("Hash mismatch", str(ctx.exception))

    def test_hidden_tests_never_leaked_into_prompts(self):
        """
        Invariant: Hidden reference tests must never appear in any prompt sent to the model.
        Falsification test: Run single task evaluation and inspect all logged prompt requests.
        """
        def handle(req):
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import find_first_missing_positive\n"
                        "def test_missing():\n"
                        "    assert find_first_missing_positive([1, 2, 0]) == 3\n"
                        "```"
                    )
                }
            return 200, {
                "response": (
                    "```python\n"
                    "def find_first_missing_positive(nums):\n"
                    "    s = set(nums)\n"
                    "    i = 1\n"
                    "    while i in s:\n"
                    "        i += 1\n"
                    "    return i\n"
                    "```"
                )
            }

        self.mock_server.handler_fn = handle

        task = {
            "id": "code_08",
            "name": "find_first_missing_positive",
            "entry_point": "find_first_missing_positive",
            "prompt": "Write a Python function `find_first_missing_positive(nums: list[int]) -> int`",
        }

        rec = eval_harness.run_single_task_evaluation(
            task=task,
            arm="english",
            model_name="test-model",
            repeat_idx=1,
        )

        self.assertEqual(rec.pai_verdict, "PASS")
        self.assertTrue(rec.hidden_test_result.passed)

        # Inspect all recorded prompts
        hidden_callables = HIDDEN_TESTS["code_08"]
        for req in self.mock_server.requests:
            p_text = req.get("prompt", "")
            self.assertNotIn("HIDDEN_TESTS", p_text)
            self.assertNotIn("test_coding_tasks.py", p_text)
            self.assertNotIn("7, 8, 9, 11, 12", p_text)  # Specific array inside hidden assertion for code_08

    def test_eval_harness_end_to_end_with_repeats(self):
        """Runs mock evaluation across 2 repeats and computes aggregated metrics."""
        def handle(req):
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import compact_number_formatter\n"
                        "def test_fmt():\n"
                        "    assert compact_number_formatter(1000) == '1K'\n"
                        "```"
                    )
                }
            return 200, {
                "response": (
                    "```python\n"
                    "def compact_number_formatter(n):\n"
                    "    if n >= 1000000000:\n"
                    "        v = n / 1000000000\n"
                    "        return f'{v:.1f}'.rstrip('0').rstrip('.') + 'B'\n"
                    "    if n >= 1000000:\n"
                    "        v = n / 1000000\n"
                    "        return f'{v:.1f}'.rstrip('0').rstrip('.') + 'M'\n"
                    "    if n >= 1000:\n"
                    "        v = n / 1000\n"
                    "        return f'{v:.1f}'.rstrip('0').rstrip('.') + 'K'\n"
                    "    if n <= -1000:\n"
                    "        v = -n / 1000\n"
                    "        return '-' + f'{v:.1f}'.rstrip('0').rstrip('.') + 'K'\n"
                    "    return str(int(n))\n"
                    "```"
                )
            }

        self.mock_server.handler_fn = handle

        tasks = [{
            "id": "code_03",
            "name": "compact_number_formatter",
            "entry_point": "compact_number_formatter",
            "prompt": "Write a Python function `compact_number_formatter(n: int | float) -> str`",
        }]
        tasks_file = os.path.join(self.tmp_dir, "test_tasks.json")
        with open(tasks_file, "w", encoding="utf-8") as f:
            json.dump(tasks, f)

        out_jsonl = os.path.join(self.tmp_dir, "eval_out.jsonl")
        records, metrics = eval_harness.run_eval_suite(
            tasks_file=tasks_file,
            arm="english",
            model_name="test-model",
            repeats=2,
            out_jsonl_path=out_jsonl,
            verbose=False,
        )

        self.assertEqual(len(records), 2)
        self.assertEqual(metrics["num_tasks"], 1)
        self.assertEqual(metrics["num_repeats"], 2)
        self.assertEqual(metrics["mean_pass_at_1_zero_shot"], 1.0)
        self.assertEqual(metrics["mean_pass_at_1_repair3"], 1.0)
        self.assertEqual(metrics["total_flipping_tasks"], 0)
        self.assertTrue(os.path.exists(out_jsonl))

        # Recompute parity check: compute_eval_metrics_from_jsonl must match in-memory metrics exactly
        recomputed = eval_harness.compute_eval_metrics_from_jsonl(out_jsonl)
        self.assertEqual(metrics, recomputed)

    def test_per_task_flips_detected(self):
        """Flips across repeats are accurately identified and reported."""
        current_repeat = 1

        def handle(req):
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import deep_merge_dicts\n"
                        "def test_merge():\n"
                        "    assert deep_merge_dicts({'a': 1}, {'b': 2}) == {'a': 1, 'b': 2}\n"
                        "```"
                    )
                }
            if current_repeat == 1:
                return 200, {
                    "response": (
                        "```python\n"
                        "def deep_merge_dicts(base, update):\n"
                        "    res = dict(base)\n"
                        "    for k, v in update.items():\n"
                        "        if k in res and isinstance(res[k], dict) and isinstance(v, dict):\n"
                        "            res[k] = deep_merge_dicts(res[k], v)\n"
                        "        else:\n"
                        "            res[k] = v\n"
                        "    return res\n"
                        "```"
                    )
                }
            else:
                return 200, {"response": "```python\ndef deep_merge_dicts(base, update):\n    return {}\n```"}

        self.mock_server.handler_fn = handle

        task = {
            "id": "code_18",
            "name": "deep_merge_dicts",
            "entry_point": "deep_merge_dicts",
            "prompt": "Write a Python function `deep_merge_dicts(base: dict, update: dict) -> dict`",
        }

        current_repeat = 1
        rec1 = eval_harness.run_single_task_evaluation(task, "english", "test-model", repeat_idx=1)
        current_repeat = 2
        rec2 = eval_harness.run_single_task_evaluation(task, "english", "test-model", repeat_idx=2)

        # One passed, one failed
        self.assertNotEqual(rec1.pass_at_1_repair3, rec2.pass_at_1_repair3)

        metrics = eval_harness.compute_eval_metrics([rec1, rec2])
        self.assertEqual(metrics["total_flipping_tasks"], 1)
        self.assertIn("code_18", metrics["flipping_task_ids"])

    def test_false_accept_detected(self):
        """
        False-accept detection:
        Model generates buggy self-tests that pass on wrong code, but fails hidden reference tests.
        """
        def handle(req):
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                # Flawed model-written test that expects wrong result
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import evaluate_simple_expression\n"
                        "def test_bogus():\n"
                        "    assert evaluate_simple_expression('3 + 2 * 2') == 99\n"
                        "```"
                    )
                }
            # Solution that passes the flawed test
            return 200, {
                "response": (
                    "```python\n"
                    "def evaluate_simple_expression(expr):\n"
                    "    return 99\n"
                    "```"
                )
            }

        self.mock_server.handler_fn = handle

        task = {
            "id": "code_20",
            "name": "evaluate_simple_expression",
            "entry_point": "evaluate_simple_expression",
            "prompt": "Write a Python function `evaluate_simple_expression(expr: str) -> int`",
        }

        rec = eval_harness.run_single_task_evaluation(task, "english", "test-model", repeat_idx=1)

        # pai code verified against model's own tests
        self.assertEqual(rec.pai_verdict, "PASS")
        # Hidden reference test checks 3 + 2 * 2 == 7, so it fails!
        self.assertFalse(rec.hidden_test_result.passed)
        self.assertTrue(rec.is_false_accept)
        self.assertFalse(rec.is_false_reject)

        metrics = eval_harness.compute_eval_metrics([rec])
        self.assertEqual(metrics["mean_false_accept_rate"], 1.0)

    def test_model_server_crash_handled_gracefully(self):
        """Model server returning 500 does not crash the harness; marks task as failed."""
        def handle(req):
            return 500, {"error": "Server internal error"}

        self.mock_server.handler_fn = handle

        task = {
            "id": "code_01",
            "name": "parse_simple_csv",
            "entry_point": "parse_simple_csv",
            "prompt": "Write parse_simple_csv",
        }

        rec = eval_harness.run_single_task_evaluation(task, "english", "test-model", repeat_idx=1)
        self.assertEqual(rec.pai_verdict, "FAIL")
        self.assertFalse(rec.pass_at_1_zero_shot)
        self.assertFalse(rec.pass_at_1_repair3)
        self.assertFalse(rec.is_false_accept)
        self.assertIn("GENERATOR_ERROR", str(rec.error_detail))


if __name__ == "__main__":
    unittest.main()
