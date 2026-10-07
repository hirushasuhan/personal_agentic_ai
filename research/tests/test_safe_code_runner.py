"""
Unit tests for Safe Code Runner (M1.1 / Track L Sandboxing)
Verifies:
- Subprocess execution & kill-on-timeout
- Network denial
- Scrubbed environment
- Function proxy dispatch
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from safe_code_runner import run_isolated_task_eval, SubprocessFunctionProxy


class TestSafeCodeRunner(unittest.TestCase):
    def test_valid_execution(self):
        code = "def add(a, b):\n    return a + b\n"
        test_fn = lambda f: f(2, 3) == 5 and f(-1, 1) == 0
        passed, msg = run_isolated_task_eval(code, "add", test_fn, timeout_sec=2.0)
        self.assertTrue(passed, f"Expected pass, got: {msg}")

    def test_syntax_error(self):
        code = "def broken(:\n    pass\n"
        test_fn = lambda f: True
        passed, msg = run_isolated_task_eval(code, "broken", test_fn, timeout_sec=2.0)
        self.assertFalse(passed)
        self.assertIn("SyntaxError", msg)

    def test_infinite_loop_timeout_and_process_kill(self):
        code = "def loop_forever():\n    while True:\n        pass\n"
        test_fn = lambda f: f()
        passed, msg = run_isolated_task_eval(code, "loop_forever", test_fn, timeout_sec=1.0)
        self.assertFalse(passed)
        self.assertIn("hard limit exceeded; subprocess killed", msg)

    def test_network_blocked(self):
        code = (
            "import socket\n"
            "def try_net():\n"
            "    s = socket.socket()\n"
            "    return True\n"
        )
        test_fn = lambda f: f()
        passed, msg = run_isolated_task_eval(code, "try_net", test_fn, timeout_sec=2.0)
        self.assertFalse(passed)
        self.assertIn("Network access is blocked", msg)

    def test_environment_scrubbed(self):
        code = (
            "import os\n"
            "def check_env():\n"
            "    # USERPROFILE, PAI secrets should not exist\n"
            "    return os.environ.get('USERPROFILE') is None\n"
        )
        test_fn = lambda f: f() is True
        passed, msg = run_isolated_task_eval(code, "check_env", test_fn, timeout_sec=2.0)
        self.assertTrue(passed, f"Expected pass, got: {msg}")

    def test_class_circular_buffer(self):
        code = (
            "class CircularBuffer:\n"
            "    def __init__(self, cap):\n"
            "        self.cap = cap\n"
            "        self.buf = []\n"
            "    def enqueue(self, item):\n"
            "        if len(self.buf) >= self.cap: return False\n"
            "        self.buf.append(item)\n"
            "        return True\n"
            "    def dequeue(self):\n"
            "        return self.buf.pop(0) if self.buf else None\n"
            "    def is_full(self):\n"
            "        return len(self.buf) == self.cap\n"
            "    def is_empty(self):\n"
            "        return len(self.buf) == 0\n"
        )
        test_fn = lambda cls: cls.execute_steps([
            {"method": "__init__", "args": [2]},
            {"method": "enqueue", "args": [1]},
            {"method": "enqueue", "args": [2]},
            {"method": "is_full"},
            {"method": "enqueue", "args": [3]},
            {"method": "dequeue"},
            {"method": "is_empty"},
        ]) == [True, True, True, True, False, 1, False]
        passed, msg = run_isolated_task_eval(code, "CircularBuffer", test_fn, timeout_sec=2.0)
        self.assertTrue(passed, f"Expected pass, got: {msg}")


if __name__ == "__main__":
    unittest.main()
