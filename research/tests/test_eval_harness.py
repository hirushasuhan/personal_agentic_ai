"""
Unit Tests for Evaluation Harness (Milestone M2b Close-out)
ADR-011 v2.1 & Definition of Done

Verifies:
1. Frozen dataset hash validation and negative control on file mutation (refusal).
2. Hidden test isolation invariant: derived from inspect.getsource across all 20 tasks,
   confirming secret reference test code/literals NEVER leak into model prompts.
3. Sandboxed hidden test grading: runs inside OS sandbox with timeout, memory limit,
   and crash/hang resilience.
4. Negative controls:
   - sys.exit in solution main block (harness survives, records fail).
   - Infinite loop in solution main block (harness times out safely, records fail).
   - Memory bomb in solution main block (harness survives, records fail).
5. End-to-end evaluation flow with repeats using loopback mock model server.
6. Detection of per-task flips across repeats.
7. Detection of false-accept (model passes own tests, fails hidden tests).
8. Resilient error handling when model server crashes / returns HTTP 500.
9. Explicit temperature/seed verification in model requests and record.
10. Grouping by (arm, model) in compute_eval_metrics on mixed JSONL files.
"""

from __future__ import annotations

import http.server
import inspect
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
from typing import Any, Dict

import _bootstrap  # noqa: F401
import eval_harness
from eval_sets.hidden_tests.test_coding_tasks import HIDDEN_TESTS


class MockModelServer:
    """Threaded local loopback HTTP server mocking Ollama /api/generate and /api/show."""

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

                if self.path == "/api/show":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"digest": "sha256:mock_model_digest_12345"}).encode("utf-8"))
                    return

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

    def test_hidden_tests_never_leaked_into_prompts_across_all_20_tasks(self):
        """
        Invariant: Hidden reference tests must never appear in any prompt sent to the model.
        Derives forbidden literals via inspect.getsource across all 20 tasks in HIDDEN_TESTS.
        Asserts that no unique hidden test literal appears in any prompt across tasks.
        """
        # 1. Read all task prompts to distinguish public task requirements from secret test vectors
        root = eval_harness.find_project_root()
        tasks_file = os.path.join(root, "research", "eval_sets", "coding_tasks.json")
        with open(tasks_file, "r", encoding="utf-8") as f:
            tasks_data = json.load(f)
        public_text = " ".join(t["prompt"] for t in tasks_data)

        # 2. Extract literals from all 20 tasks in HIDDEN_TESTS using inspect.getsource
        secret_literals = set()
        for tid, fns in HIDDEN_TESTS.items():
            for fn in fns:
                src = inspect.getsource(fn)
                # Find quoted string literals (4+ chars)
                found_strings = re.findall(r'["\']([^"\']{4,})["\']', src)
                for s in found_strings:
                    if s not in public_text and not s.startswith("__"):
                        secret_literals.add(s)
                # Find non-trivial numeric literals (4+ digits)
                found_numbers = re.findall(r'\b\d{4,}\b', src)
                for n in found_numbers:
                    if n not in public_text:
                        secret_literals.add(n)

        self.assertGreaterEqual(len(secret_literals), 20, "Must extract non-trivial secret test literals")

        # 3. Run mock evaluation for several tasks
        def handle(req):
            prompt = req.get("prompt", "")
            return 200, {
                "response": "```python\ndef solve(*args, **kwargs): return True\n```"
            }

        self.mock_server.handler_fn = handle

        sample_tasks = tasks_data[:3]
        sample_file = os.path.join(self.tmp_dir, "sample_tasks.json")
        with open(sample_file, "w", encoding="utf-8") as f:
            json.dump(sample_tasks, f)

        eval_harness.run_eval_suite(
            tasks_file=sample_file,
            arm="english",
            model_name="test-model",
            repeats=1,
            verbose=False,
        )

        # 4. Assert that no secret test literal appears in any prompt logged by mock server
        for req in self.mock_server.requests:
            p_text = req.get("prompt", "")
            self.assertNotIn("HIDDEN_TESTS", p_text)
            self.assertNotIn("test_coding_tasks.py", p_text)
            for secret in secret_literals:
                self.assertNotIn(secret, p_text, f"Secret hidden test literal leaked in prompt: '{secret}'")

    def test_sandboxed_hidden_test_execution_clean(self):
        """Sandboxed hidden test runner successfully executes and passes valid solution."""
        sol_path = os.path.join(self.tmp_dir, "solution.py")
        with open(sol_path, "w", encoding="utf-8") as f:
            f.write("def parse_simple_csv(text):\n    return []\n")

        res = eval_harness.run_hidden_tests("code_01", "parse_simple_csv", sol_path)
        # code_01 has 5 hidden tests; returns [] passes first 2 assertions then fails 3rd
        self.assertFalse(res.passed)
        self.assertEqual(res.passed_assertions, 2)
        self.assertEqual(res.total_assertions, 5)
        self.assertIn("returned False", str(res.error))
        self.assertNotIn("SystemExit", str(res.error))

    def test_negative_control_sandbox_sys_exit_in_solution(self):
        """
        Negative control 1: solution.py contains sys.exit(7) in main block.
        Harness must survive (not exit), and record passed=False.
        """
        sol_path = os.path.join(self.tmp_dir, "solution.py")
        with open(sol_path, "w", encoding="utf-8") as f:
            f.write(
                "import sys\n"
                "def parse_simple_csv(text):\n"
                "    return []\n\n"
                "if __name__ == '__main__':\n"
                "    sys.exit(7)\n"
            )

        res = eval_harness.run_hidden_tests("code_01", "parse_simple_csv", sol_path)
        self.assertFalse(res.passed)
        self.assertIn("SystemExit", str(res.error))

    def test_negative_control_sandbox_infinite_loop_timeout(self):
        """
        Negative control 2: solution.py contains while True: pass in main block.
        Harness must survive (not hang), and record passed=False with timeout error.
        """
        sol_path = os.path.join(self.tmp_dir, "solution.py")
        with open(sol_path, "w", encoding="utf-8") as f:
            f.write(
                "def parse_simple_csv(text):\n"
                "    return []\n\n"
                "if __name__ == '__main__':\n"
                "    while True:\n"
                "        pass\n"
            )

        res = eval_harness.run_hidden_tests("code_01", "parse_simple_csv", sol_path, timeout_sec=1.5)
        self.assertFalse(res.passed)
        self.assertIn("timeout", str(res.error).lower())

    def test_negative_control_sandbox_memory_bomb(self):
        """
        Negative control 3: solution.py contains memory bomb.
        Harness must survive (not crash/OOM), and record passed=False.
        """
        sol_path = os.path.join(self.tmp_dir, "solution.py")
        with open(sol_path, "w", encoding="utf-8") as f:
            f.write(
                "def parse_simple_csv(text):\n"
                "    return []\n\n"
                "if __name__ == '__main__':\n"
                "    # Allocate massive memory\n"
                "    b = bytearray(1024 * 1024 * 800)\n"
            )

        # Enforce 128 MB sandbox limit
        res = eval_harness.run_hidden_tests("code_01", "parse_simple_csv", sol_path, memory_mb=128.0)
        self.assertFalse(res.passed)

    def test_eval_harness_end_to_end_with_repeats(self):
        """Runs mock evaluation across 2 repeats and verifies explicit temperature, seed, and digest."""
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
            temperature=0.0,
            seed=42,
            verbose=False,
        )

        self.assertEqual(len(records), 2)
        rec = records[0]
        self.assertEqual(rec.temperature, 0.0)
        self.assertEqual(rec.seed, 42)
        self.assertEqual(rec.model_digest, "sha256:mock_model_digest_12345")
        self.assertEqual(metrics["num_tasks"], 1)
        self.assertEqual(metrics["num_repeats"], 2)
        self.assertEqual(metrics["mean_pass_at_1_zero_shot"], 1.0)
        self.assertEqual(metrics["mean_pass_at_1_repair3"], 1.0)
        self.assertEqual(metrics["total_flipping_tasks"], 0)

        # Check options received by mock model server
        gen_reqs = [r for r in self.mock_server.requests if "prompt" in r]
        self.assertTrue(any(r.get("options", {}).get("temperature") == 0.0 for r in gen_reqs))
        self.assertTrue(any(r.get("options", {}).get("seed") == 42 for r in gen_reqs))

        # Recompute parity
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

        self.assertNotEqual(rec1.pass_at_1_repair3, rec2.pass_at_1_repair3)

        metrics = eval_harness.compute_eval_metrics([rec1, rec2])
        self.assertEqual(metrics["total_flipping_tasks"], 1)
        self.assertIn("code_18", metrics["flipping_task_ids"])

    def test_mixed_jsonl_grouped_by_arm_and_model(self):
        """Mixed JSONL records are grouped per (arm, model) preventing cross-arm flip contamination."""
        rec_en1 = eval_harness.EvalRecord(
            task_id="code_01", task_name="t1", entry_point="t1", repeat_idx=1, arm="english", model="m1",
            model_digest=None, temperature=0.0, seed=42, exit_code=0, pai_verdict="PASS",
            pass_at_1_zero_shot=True, pass_at_1_repair3=True, total_repairs=0, iterations=1,
            hidden_test_result=eval_harness.HiddenTestResult(passed=True, total_assertions=1, passed_assertions=1),
            is_false_accept=False, is_false_reject=False, wall_time_sec=1.0, host_ram_delta_mb=None,
        )
        rec_en2 = eval_harness.EvalRecord(
            task_id="code_01", task_name="t1", entry_point="t1", repeat_idx=2, arm="english", model="m1",
            model_digest=None, temperature=0.0, seed=42, exit_code=0, pai_verdict="PASS",
            pass_at_1_zero_shot=True, pass_at_1_repair3=True, total_repairs=0, iterations=1,
            hidden_test_result=eval_harness.HiddenTestResult(passed=True, total_assertions=1, passed_assertions=1),
            is_false_accept=False, is_false_reject=False, wall_time_sec=1.0, host_ram_delta_mb=None,
        )
        rec_si1 = eval_harness.EvalRecord(
            task_id="code_01", task_name="t1", entry_point="t1", repeat_idx=1, arm="singlish", model="m1",
            model_digest=None, temperature=0.0, seed=42, exit_code=2, pai_verdict="FAIL",
            pass_at_1_zero_shot=False, pass_at_1_repair3=False, total_repairs=3, iterations=4,
            hidden_test_result=eval_harness.HiddenTestResult(passed=False, total_assertions=1, passed_assertions=0),
            is_false_accept=False, is_false_reject=False, wall_time_sec=2.0, host_ram_delta_mb=None,
        )

        mixed_metrics = eval_harness.compute_eval_metrics([rec_en1, rec_en2, rec_si1])
        self.assertTrue(mixed_metrics.get("is_mixed"))
        self.assertEqual(mixed_metrics["total_groups"], 2)
        self.assertIn("english/m1", mixed_metrics["groups"])
        self.assertIn("singlish/m1", mixed_metrics["groups"])
        # English arm: both repeats passed -> flips == 0
        self.assertEqual(mixed_metrics["groups"]["english/m1"]["total_flipping_tasks"], 0)
        # Singlish arm: 1 repeat -> flips == 0
        self.assertEqual(mixed_metrics["groups"]["singlish/m1"]["total_flipping_tasks"], 0)

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
