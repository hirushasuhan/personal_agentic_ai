"""
End-to-End Tests for 'pai code' Pipeline with Loopback Mock Model Server
Milestone M2b Step 4 / ADR-011 v2.1

Tests all 7 required scenarios:
1. Zero-shot pass (exit 0, pass_at_1_zero_shot=True, staged files)
2. Pass after one repair (exit 0, pass_at_1_repair3=True, total_repairs=1)
3. Exhausted repairs (exit 2, files not staged)
4. Collision protection (exit 4 without --overwrite, exit 0 with --overwrite)
5. Capability probe & RAM refusal (exit 5)
6. Vacuous tests rejection (exit 1)
7. Generator error handling (exit 2, GENERATOR_ERROR recorded)
8. CLI input validation & AST violations (exit 1)
"""

import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

import _bootstrap  # noqa: F401
import pai


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
                pass  # Suppress HTTP logging

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TestPaiCodeEndToEnd(unittest.TestCase):
    def setUp(self):
        self.mock_server = MockModelServer()
        self.orig_model_url = os.environ.get("PAI_MODEL_URL")
        os.environ["PAI_MODEL_URL"] = self.mock_server.url
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_code_e2e_")

    def tearDown(self):
        self.mock_server.close()
        if self.orig_model_url is not None:
            os.environ["PAI_MODEL_URL"] = self.orig_model_url
        else:
            os.environ.pop("PAI_MODEL_URL", None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_zero_shot_pass(self):
        """Scenario 1: Model generates test and correct solution zero-shot (exit 0)."""
        def handle(req):
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import add\n"
                        "def test_add_positive():\n"
                        "    assert add(1, 2) == 3\n"
                        "def test_add_negative():\n"
                        "    assert add(-2, 2) == 0\n"
                        "```"
                    )
                }
            elif "Write a Python solution" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "def add(a, b):\n"
                        "    return a + b\n"
                        "```"
                    )
                }
            return 200, {"response": ""}

        self.mock_server.handler_fn = handle
        argv = [
            "code",
            "Implement add(a, b)",
            "--out", self.tmp_dir,
            "--model", "test-model",
            "--json",
        ]
        ret = pai.main(argv)
        self.assertEqual(ret, 0, "Zero-shot pass must return exit 0")

        # Staged files must exist
        sol_file = os.path.join(self.tmp_dir, "solution.py")
        test_file = os.path.join(self.tmp_dir, "test_solution.py")
        self.assertTrue(os.path.exists(sol_file))
        self.assertTrue(os.path.exists(test_file))
        with open(sol_file, "r", encoding="utf-8") as f:
            self.assertIn("return a + b", f.read())

    def test_pass_after_one_repair(self):
        """Scenario 2: Initial solution buggy; repaired on iteration 1 (exit 0)."""
        repair_calls = 0

        def handle(req):
            nonlocal repair_calls
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import add\n"
                        "def test_add():\n"
                        "    assert add(2, 3) == 5\n"
                        "    assert add(-1, 1) == 0\n"
                        "```"
                    )
                }
            elif "Write a Python solution" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "def add(a, b):\n"
                        "    return a - b  # Buggy initial\n"
                        "```"
                    )
                }
            elif "Fix the Python solution" in prompt:
                repair_calls += 1
                return 200, {
                    "response": (
                        "```python\n"
                        "def add(a, b):\n"
                        "    return a + b  # Corrected\n"
                        "```"
                    )
                }
            return 200, {"response": ""}

        self.mock_server.handler_fn = handle
        argv = [
            "code",
            "Implement add(a, b)",
            "--out", self.tmp_dir,
            "--model", "test-model",
            "--json",
        ]
        ret = pai.main(argv)
        self.assertEqual(ret, 0, "Pass after repair must return exit 0")
        self.assertEqual(repair_calls, 1, "Exactly one repair call must occur")

        sol_file = os.path.join(self.tmp_dir, "solution.py")
        self.assertTrue(os.path.exists(sol_file))
        with open(sol_file, "r", encoding="utf-8") as f:
            self.assertIn("return a + b", f.read())

    def test_exhausted_repairs_exit_2(self):
        """Scenario 3: Model fails across all repair iterations (exit 2, not staged)."""
        def handle(req):
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import add\n"
                        "def test_add():\n"
                        "    assert add(1, 2) == 3\n"
                        "```"
                    )
                }
            # Solution and repairs always buggy
            return 200, {
                "response": (
                    "```python\n"
                    "def add(a, b):\n"
                    "    return 0  # Persistent bug\n"
                    "```"
                )
            }

        self.mock_server.handler_fn = handle
        argv = [
            "code",
            "Implement add(a, b)",
            "--out", self.tmp_dir,
            "--model", "test-model",
            "--max-repairs", "2",
            "--json",
        ]
        ret = pai.main(argv)
        self.assertEqual(ret, 2, "Exhausted repairs must return exit 2")

        sol_file = os.path.join(self.tmp_dir, "solution.py")
        self.assertFalse(os.path.exists(sol_file), "Failed runs must NOT stage artifacts")

    def test_collision_exit_4(self):
        """Scenario 4: Collision without --overwrite returns exit 4; with --overwrite passes (exit 0)."""
        def handle(req):
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import add\n"
                        "def test_add():\n"
                        "    assert add(1, 2) == 3\n"
                        "```"
                    )
                }
            return 200, {
                "response": (
                    "```python\n"
                    "def add(a, b):\n"
                    "    return a + b\n"
                    "```"
                )
            }

        self.mock_server.handler_fn = handle

        # Pre-create colliding file
        existing_sol = os.path.join(self.tmp_dir, "solution.py")
        with open(existing_sol, "w", encoding="utf-8") as f:
            f.write("# Pre-existing file\n")

        # Without --overwrite: collision exit 4
        argv = [
            "code",
            "Implement add(a, b)",
            "--out", self.tmp_dir,
            "--model", "test-model",
            "--json",
        ]
        ret = pai.main(argv)
        self.assertEqual(ret, 4, "File collision must return exit 4")

        # With --overwrite: successfully replaces, exit 0
        argv_overwrite = [
            "code",
            "Implement add(a, b)",
            "--out", self.tmp_dir,
            "--model", "test-model",
            "--overwrite",
            "--json",
        ]
        ret_ov = pai.main(argv_overwrite)
        self.assertEqual(ret_ov, 0, "Overwrite must succeed with exit 0")
        with open(existing_sol, "r", encoding="utf-8") as f:
            self.assertIn("return a + b", f.read())

    def test_probe_refusal_exit_5(self):
        """Scenario 5: Sandbox capability probe failure or router refusal returns exit 5."""
        # 5a. Sandbox behavioural probe refusal
        with mock.patch("sandbox.probe_system_boundary", return_value=(False, "Mock boundary compromise")):
            with self.assertRaises(SystemExit) as ctx:
                pai.main(["code", "Implement add", "--out", self.tmp_dir, "--model", "test-model"])
            self.assertEqual(ctx.exception.code, 5, "Probe refusal must trigger SystemExit(5)")

        # 5b. Router refusal when no --model override is provided and RAM insufficient
        with mock.patch.object(pai.ModelRouter, "route") as mock_route:
            from router import RouteDecision
            mock_route.return_value = RouteDecision(
                selected_model=None,
                kind="local",
                data_leaves_machine=False,
                task_class="code",
                reason_codes=["INSUFFICIENT_RAM"],
                rejected_models=[],
                switches_count=0,
                thinking_mode=False,
                explanation="Refused: RAM insufficient",
            )
            ret = pai.main(["code", "Implement add", "--out", self.tmp_dir])
            self.assertEqual(ret, 5, "Model router refusal must return exit 5")

    def test_vacuous_tests_exit_1(self):
        """Scenario 6: Vacuous test suite generated by model rejected by stub probe (exit 1)."""
        def handle(req):
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                # Weak suite passing stub 0
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import add\n"
                        "def test_weak():\n"
                        "    assert add(1, 2) is not None\n"
                        "```"
                    )
                }
            return 200, {"response": "def add(a, b): return a + b"}

        self.mock_server.handler_fn = handle
        argv = [
            "code",
            "Implement add(a, b)",
            "--out", self.tmp_dir,
            "--model", "test-model",
            "--json",
        ]
        ret = pai.main(argv)
        self.assertEqual(ret, 1, "Vacuous test suite must return exit 1")

        sol_file = os.path.join(self.tmp_dir, "solution.py")
        self.assertFalse(os.path.exists(sol_file), "Vacuous tests must not stage files")

    def test_generator_error_exit_2(self):
        """Scenario 7: Generator error during repair records GENERATOR_ERROR and returns exit 2."""
        def handle(req):
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import add\n"
                        "def test_add():\n"
                        "    assert add(1, 2) == 3\n"
                        "```"
                    )
                }
            elif "Write a Python solution" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "def add(a, b):\n"
                        "    return 0  # Buggy initial\n"
                        "```"
                    )
                }
            elif "Fix the Python solution" in prompt:
                # Model server crashes or fails on repair
                return 500, {"error": "Internal server crash"}
            return 200, {"response": ""}

        self.mock_server.handler_fn = handle
        argv = [
            "code",
            "Implement add(a, b)",
            "--out", self.tmp_dir,
            "--model", "test-model",
            "--json",
        ]
        ret = pai.main(argv)
        self.assertEqual(ret, 2, "Generator error must return exit 2")

        sol_file = os.path.join(self.tmp_dir, "solution.py")
        self.assertFalse(os.path.exists(sol_file))

    def test_no_work_specified_exit_1(self):
        """Validates that 'pai code' without task or tests exits 1 (never exits 0)."""
        ret = pai.main(["code"])
        self.assertEqual(ret, 1)

    def test_missing_out_dir_exit_1(self):
        """Validates that 'pai code' without --out exits 1."""
        ret = pai.main(["code", "Implement add(a, b)"])
        self.assertEqual(ret, 1)

    def test_ast_guard_rejection_exit_1(self):
        """Validates that solutions violating AST static guard are rejected (exit 1)."""
        def handle(req):
            prompt = req.get("prompt", "")
            if "Write a Python test suite" in prompt:
                return 200, {
                    "response": (
                        "```python\n"
                        "from solution import add\n"
                        "def test_add():\n"
                        "    assert add(1, 2) == 3\n"
                        "```"
                    )
                }
            # Solution contains forbidden imports/calls
            return 200, {
                "response": (
                    "```python\n"
                    "import os\n"
                    "def add(a, b):\n"
                    "    os.system('echo dangerous')\n"
                    "    return a + b\n"
                    "```"
                )
            }

        self.mock_server.handler_fn = handle
        argv = [
            "code",
            "Implement add(a, b)",
            "--out", self.tmp_dir,
            "--model", "test-model",
            "--json",
        ]
        ret = pai.main(argv)
        self.assertEqual(ret, 1, "AST safety violation must return exit 1")


if __name__ == "__main__":
    unittest.main()
