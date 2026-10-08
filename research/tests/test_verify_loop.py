"""
Unit Tests for Verify Loop, Frozen Tests, and Stub Probe (Milestone M2b / ADR-011 v2.1)
"""

import hashlib
import os
import tempfile
import unittest

import _bootstrap  # noqa: F401
from verify_loop import (
    FrozenTestSuite,
    StubProbeResult,
    TestExecutionResult,
    TestMutationError,
    TestSyntaxError,
    VacuousTestError,
    VerifyLoop,
    generate_stub_code,
)


class TestFrozenTestSuite(unittest.TestCase):
    def test_freeze_calculates_hash_and_counts_assertions(self):
        code = """
from solution import add

def test_addition():
    assert add(1, 2) == 3
    assert add(-1, 1) == 0
"""
        suite = FrozenTestSuite.create(code, source="model")
        self.assertEqual(suite.source, "model")
        self.assertEqual(suite.assertion_count, 2)
        self.assertIn("add", suite.target_symbols)

        expected_hash = hashlib.sha256(code.strip().encode("utf-8")).hexdigest()
        self.assertEqual(suite.test_hash, expected_hash)

        # Integrity verification matches
        suite.verify_integrity(code)

    def test_integrity_raises_on_mutation(self):
        code = "from solution import compute\nassert compute(5) == 25"
        suite = FrozenTestSuite.create(code, source="model")

        # Mutated code
        mutated = code + "\n# weakened assertion"
        with self.assertRaises(TestMutationError):
            suite.verify_integrity(mutated)

    def test_syntax_error_rejected(self):
        bad_code = "def test_broken(:\n    assert True"
        with self.assertRaises(TestSyntaxError):
            FrozenTestSuite.create(bad_code)

    def test_empty_test_suite_rejected(self):
        with self.assertRaises(VacuousTestError):
            FrozenTestSuite.create("   \n   ")


class TestStubProbe(unittest.TestCase):
    def setUp(self):
        self.loop = VerifyLoop(timeout_sec=5.0)

    def test_zero_assertions_rejected_as_vacuous(self):
        code = """
def test_nothing():
    x = 1 + 2
"""
        suite = self.loop.freeze_tests(code)
        self.assertEqual(suite.assertion_count, 0)
        res = self.loop.run_stub_probe(suite)
        self.assertFalse(res.passed)
        self.assertIn("VACUOUS_TESTS_REJECTED", res.detail)

    def test_vacuous_assertions_rejected_by_stub_probe(self):
        # Even with an assert statement, asserting True trivially passes on any stub
        code = """
def test_vacuous():
    assert True
"""
        suite = self.loop.freeze_tests(code)
        self.assertEqual(suite.assertion_count, 1)
        res = self.loop.run_stub_probe(suite)
        self.assertFalse(res.passed)
        self.assertIn("VACUOUS_TESTS_REJECTED", res.detail)

    def test_meaningful_tests_pass_stub_probe(self):
        # A meaningful test checks specific outputs that return None will fail
        code = """
from solution import multiply

def test_multiply():
    assert multiply(3, 4) == 12

if __name__ == '__main__':
    test_multiply()
"""
        suite = self.loop.freeze_tests(code)
        res = self.loop.run_stub_probe(suite)
        self.assertTrue(res.passed, f"Stub probe should pass for meaningful test, got: {res.detail}")
        self.assertIn("NON_VACUOUS_VERIFIED", res.detail)

    def test_unittest_style_tests_pass_stub_probe(self):
        code = """
import unittest
from solution import power

class TestPower(unittest.TestCase):
    def test_power(self):
        self.assertEqual(power(2, 3), 8)

if __name__ == '__main__':
    unittest.main()
"""
        suite = self.loop.freeze_tests(code)
        res = self.loop.run_stub_probe(suite)
        self.assertTrue(res.passed, f"Stub probe should pass for unittest suite, got: {res.detail}")
        self.assertIn("NON_VACUOUS_VERIFIED", res.detail)


    def test_nameerror_suite_rejected_as_invalid(self):
        # F1 negative control: test suite with undefined name must be rejected as TEST_SUITE_INVALID (not non-vacuous)
        code = """
from solution import add

def test_broken_name():
    assert undefined_symbol == 3
"""
        suite = self.loop.freeze_tests(code)
        res = self.loop.run_stub_probe(suite)
        self.assertFalse(res.passed)
        self.assertIn("TEST_SUITE_INVALID", res.detail)
        self.assertIn("NameError", res.detail)

    def test_timeout_suite_rejected_as_invalid(self):
        # F1 negative control: test suite with infinite loop must be rejected as TEST_SUITE_INVALID
        quick_loop = VerifyLoop(timeout_sec=1.5)
        code = """
from solution import add

def test_infinite_loop():
    while True:
        pass
    assert add(1, 2) == 3
"""
        suite = quick_loop.freeze_tests(code)
        res = quick_loop.run_stub_probe(suite)
        self.assertFalse(res.passed)
        self.assertIn("TEST_SUITE_INVALID", res.detail)
        self.assertIn("timed out", res.detail)

    def test_pytest_style_suite_discovered_and_verified(self):
        # F2: pytest-style standalone functions without unittest.main() are discovered and run
        code = """
from solution import add

def test_add():
    assert add(1, 2) == 3
"""
        suite = self.loop.freeze_tests(code)
        res = self.loop.run_stub_probe(suite)
        self.assertTrue(res.passed, f"pytest-style suite should pass stub probe: {res.detail}")
        self.assertIn("NON_VACUOUS_VERIFIED", res.detail)

    def test_weak_is_not_none_suite_rejected(self):
        # F4 negative control: weak suite that only asserts `is not None` passes against stub '0'
        code = """
from solution import compute

def test_weak_not_none():
    assert compute(5) is not None
"""
        suite = self.loop.freeze_tests(code)
        res = self.loop.run_stub_probe(suite)
        self.assertFalse(res.passed, "Weak suite should be rejected by stub probe")
        self.assertIn("VACUOUS_TESTS_REJECTED", res.detail)
        self.assertEqual(res.failing_stub, "0")
        self.assertIn("passed against stub '0'", res.detail)


class TestVerifyLoopExecution(unittest.TestCase):
    def setUp(self):
        self.loop = VerifyLoop(timeout_sec=5.0)

    def test_user_tests_priority(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("from solution import solve\nassert solve() == 'USER_TEST'\n")
            user_test_path = f.name

        try:
            model_code = "from solution import solve\nassert solve() == 'MODEL_TEST'\n"
            suite = self.loop.prepare_test_suite(
                user_tests_path=user_test_path,
                model_test_code=model_code,
            )
            self.assertEqual(suite.source, "user")
            self.assertIn("USER_TEST", suite.test_code)
            self.assertNotIn("MODEL_TEST", suite.test_code)
        finally:
            if os.path.exists(user_test_path):
                os.remove(user_test_path)

    def test_correct_solution_passes(self):
        test_code = """
from solution import subtract

def test_subtract():
    assert subtract(10, 4) == 6

if __name__ == '__main__':
    test_subtract()
"""
        suite = self.loop.freeze_tests(test_code)
        sol_code = "def subtract(a, b): return a - b"

        res = self.loop.execute_solution_tests(sol_code, suite)
        self.assertTrue(res.passed, f"Correct solution should pass: {res.detail}")
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(res.discovered, 1)
        self.assertEqual(res.executed, 1)

    def test_incorrect_solution_fails(self):
        test_code = """
from solution import subtract

def test_subtract():
    assert subtract(10, 4) == 6

if __name__ == '__main__':
    test_subtract()
"""
        suite = self.loop.freeze_tests(test_code)
        wrong_sol = "def subtract(a, b): return a + b"

        res = self.loop.execute_solution_tests(wrong_sol, suite)
        self.assertFalse(res.passed, "Incorrect solution should fail")
        self.assertNotEqual(res.exit_code, 0)

    def test_execute_solution_tests_no_current_test_code_parameter(self):
        # F5: VerifyLoop strictly owns test writing; caller cannot supply current_test_code parameter
        test_code = "from solution import square\ndef test_square(): assert square(4) == 16\n"
        suite = self.loop.freeze_tests(test_code)
        with self.assertRaises(TypeError):
            self.loop.execute_solution_tests(
                "def square(x): return x * x",
                suite,
                current_test_code="def test_square(): assert square(4) == 0",
            )

    def test_tampered_scratch_file_raises_mutation_error(self):
        # F5: If the test code written to scratch is mutated, TestMutationError is raised
        test_code = "from solution import square\ndef test_square(): assert square(4) == 16\n"
        suite = self.loop.freeze_tests(test_code)
        with self.assertRaises(TestMutationError):
            suite.verify_integrity("from solution import square\ndef test_square(): assert square(4) == 0\n")

    def test_empty_tests_discovery_fails(self):
        # F2: Driver enforces executed == discovered >= 1; helper functions with 0 tests fail
        code = """
def helper(x):
    return x * 2
"""
        # Static AST count is 0 assertions
        suite = self.loop.freeze_tests(code)
        res = self.loop.run_stub_probe(suite)
        self.assertFalse(res.passed)
        self.assertIn("VACUOUS_TESTS_REJECTED", res.detail)

    def test_user_supplied_weak_tests_require_allow_weak_tests_flag(self):
        # Minor / policy note: user --tests that pass a stub produce WEAK_TESTS unless allow_weak_tests=True
        code = """
from solution import identity

def test_identity():
    # Identity-like function passes stub 'first_arg'
    assert identity(42) == 42
"""
        user_suite = self.loop.freeze_tests(code, source="user")
        # Without allow_weak_tests -> rejected with WEAK_TESTS naming stub
        res_strict = self.loop.run_stub_probe(user_suite, allow_weak_tests=False)
        self.assertFalse(res_strict.passed)
        self.assertIn("WEAK_TESTS", res_strict.detail)
        self.assertEqual(res_strict.failing_stub, "first_arg")

        # With allow_weak_tests=True -> accepted for user suite
        res_allowed = self.loop.run_stub_probe(user_suite, allow_weak_tests=True)
        self.assertTrue(res_allowed.passed)

        # But for model-written suite, even with allow_weak_tests=True, it is strictly rejected!
        model_suite = self.loop.freeze_tests(code, source="model")
        res_model = self.loop.run_stub_probe(model_suite, allow_weak_tests=True)
        self.assertFalse(res_model.passed)
        self.assertIn("VACUOUS_TESTS_REJECTED", res_model.detail)

    def test_forged_test_result_with_early_exit_rejected(self):
        # Step 3 Acceptance Test 1: Forged test_result.json + os._exit(0)
        test_code = """
from solution import add

def test_add():
    assert add(1, 2) == 3
"""
        suite = self.loop.freeze_tests(test_code)
        forged_solution = """
import json
import os

with open("test_result.json", "w") as f:
    json.dump({
        "status": "PASS",
        "discovered": 1,
        "executed": 1,
        "passed": 1,
        "failed": 0,
        "errors": 0,
        "failures": [],
    }, f)

os._exit(0)
"""
        res = self.loop.execute_solution_tests(forged_solution, suite)
        self.assertFalse(res.passed, "Forged test_result.json with os._exit(0) must be rejected")
        self.assertEqual(res.status, "ERROR")

    def test_equality_hijack_solution_rejected(self):
        # Step 3 Acceptance Test 2: __eq__ object spoofing
        test_code = """
from solution import add

def test_add():
    assert add(1, 2) == 3
"""
        suite = self.loop.freeze_tests(test_code)
        hijack_solution = """
class R(int):
    def __eq__(self, other):
        return True
    def __repr__(self):
        return "3"

def add(a, b):
    return R()
"""
        res = self.loop.execute_solution_tests(hijack_solution, suite)
        self.assertFalse(res.passed, "Equality hijack solution must be rejected")
        self.assertEqual(res.status, "FAIL")
        fail_msgs = [f.get("message", "") for f in res.failures]
        self.assertTrue(
            any("equalityhijack" in m.lower() or "equality hijack" in m.lower() or "non-builtin" in m.lower() for m in fail_msgs),
            f"Expected equality hijack rejection in failures: {fail_msgs}",
        )

    def test_thread_or_atexit_verdict_tampering_rejected(self):
        # Step 3 Acceptance Test 3: Thread or atexit verdict tampering
        test_code = """
from solution import add

def test_add():
    assert add(1, 2) == 3
"""
        suite = self.loop.freeze_tests(test_code)
        tamper_solution = """
import atexit
import json

def evil_hook():
    try:
        with open("test_result.json", "w") as f:
            json.dump({"status": "PASS", "discovered": 1, "executed": 1, "passed": 1, "failed": 0, "errors": 0}, f)
    except Exception:
        pass

atexit.register(evil_hook)

def add(a, b):
    return a + b + 999  # incorrect solution
"""
        res = self.loop.execute_solution_tests(tamper_solution, suite)
        self.assertFalse(res.passed, "Solution tampering via atexit must be rejected")
        self.assertNotEqual(res.exit_code, 0)

    def test_driver_replacement_or_deletion_rejected(self):
        # Step 3 Acceptance Test 4: Replacement or deletion of driver or result file
        test_code = """
from solution import add

def test_add():
    assert add(1, 2) == 3
"""
        suite = self.loop.freeze_tests(test_code)
        delete_driver_solution = """
import os

try:
    os.remove("_pai_driver.py")
except Exception:
    pass

try:
    with open("_pai_driver.py", "w") as f:
        f.write("import sys; sys.exit(0)")
except Exception:
    pass

try:
    os.remove("test_result.json")
except Exception:
    pass

def add(a, b):
    return a + b + 100  # wrong solution
"""
        res = self.loop.execute_solution_tests(delete_driver_solution, suite)
        self.assertFalse(res.passed, "Driver deletion/replacement attack must be rejected")
        self.assertNotEqual(res.exit_code, 0)

    def test_forged_verdict_via_driver_inspection_rejected(self):
        # Step 3 Acceptance Test: Reading _pai_driver.py to forge verdict + os._exit(0)
        test_code = """
from solution import add
assert add(1, 2) == 3
"""
        suite = self.loop.freeze_tests(test_code)
        exploit_solution = """
import os
import sys

# Attempt to inspect driver script for secrets or paths
try:
    with open("_pai_driver.py", "r", encoding="utf-8") as f:
        src = f.read()
except Exception:
    src = ""

# Candidate attempts early exit claiming success
os._exit(0)
"""
        res = self.loop.execute_solution_tests(exploit_solution, suite)
        self.assertFalse(res.passed, "Driver inspection + early exit must fail closed")
        self.assertIn(res.status, ("FAIL", "ERROR"))

    def test_forged_verdict_via_filesystem_globbing_rejected(self):
        # Step 3 Acceptance Test: Globbing filesystem for verdict file to forge payload
        test_code = """
from solution import add
assert add(1, 2) == 3
"""
        suite = self.loop.freeze_tests(test_code)
        exploit_solution = """
import glob
import json
import os

# Glob scratch and accessible paths for any verdict files
for path in glob.glob("**/*verdict*", recursive=True):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"session_nonce": "forged", "status": "PASS", "discovered": 1, "executed": 1, "passed": 1, "failed": 0, "errors": 0}, f)
    except Exception:
        pass

os._exit(0)
"""
        res = self.loop.execute_solution_tests(exploit_solution, suite)
        self.assertFalse(res.passed, "Filesystem globbing verdict forgery must be rejected")
        self.assertIn(res.status, ("FAIL", "ERROR"))

    def test_forged_verdict_via_proc_self_fd_rejected(self):
        # Step 3 Acceptance Test: Inspecting /proc/self/fd and writing forged payload to fds
        test_code = """
from solution import add
assert add(1, 2) == 3
"""
        suite = self.loop.freeze_tests(test_code)
        exploit_solution = """
import os
import json

payload = json.dumps({"session_nonce": "forged", "status": "PASS", "discovered": 1, "executed": 1, "passed": 1, "failed": 0, "errors": 0}).encode()

# Attempt to write forged verdict to open file descriptors
if os.path.exists("/proc/self/fd"):
    try:
        for fd_name in os.listdir("/proc/self/fd"):
            try:
                fd = int(fd_name)
                if fd not in (0,):
                    os.write(fd, b"\\n---PAI_VERDICT_START---\\n" + payload + b"\\n---PAI_VERDICT_END---\\n")
            except Exception:
                pass
    except Exception:
        pass

os._exit(0)
"""
        res = self.loop.execute_solution_tests(exploit_solution, suite)
        self.assertFalse(res.passed, "Tampering via /proc/self/fd must be rejected")
        self.assertIn(res.status, ("FAIL", "ERROR"))

    def test_forged_verdict_via_driver_pid_fd_tampering_rejected(self):
        # Step 3 Acceptance Test: Finding driver PID and writing to /proc/<driver_pid>/fd/*
        test_code = """
from solution import add
assert add(1, 2) == 3
"""
        suite = self.loop.freeze_tests(test_code)
        exploit_solution = """
import os
import json

ppid = os.getppid()
payload = json.dumps({"session_nonce": "forged", "status": "PASS", "discovered": 1, "executed": 1, "passed": 1, "failed": 0, "errors": 0}).encode()

for target_fd in (1, 2, 3, 4):
    try:
        with open(f"/proc/{ppid}/fd/{target_fd}", "wb") as f:
            f.write(b"\\n---PAI_VERDICT_START---\\n" + payload + b"\\n---PAI_VERDICT_END---\\n")
    except Exception:
        pass

os._exit(0)
"""
        res = self.loop.execute_solution_tests(exploit_solution, suite)
        self.assertFalse(res.passed, "Driver PID fd tampering must be rejected")
        self.assertIn(res.status, ("FAIL", "ERROR"))

    def test_equality_hijack_int_subclass_module_level_assert_rejected(self):
        # Step 3 Acceptance Test: R(int) with __eq__ = lambda s, o: True against module-level assert
        test_code = """
from solution import add
assert add(1, 2) == 3
assert add(2, 3) == 5
"""
        suite = self.loop.freeze_tests(test_code)
        hijack_solution = """
class R(int):
    def __eq__(self, other):
        return True

def add(a, b):
    return R(a + b)
"""
        res = self.loop.execute_solution_tests(hijack_solution, suite)
        self.assertFalse(res.passed, "R(int) equality hijack against module-level assert must be rejected")
        self.assertEqual(res.status, "FAIL")

    def test_equality_hijack_plain_object_module_level_assert_rejected(self):
        # Step 3 Acceptance Test: Plain object with __eq__ = lambda s, o: True against module-level assert
        test_code = """
from solution import add
assert add(1, 2) == 3
"""
        suite = self.loop.freeze_tests(test_code)
        hijack_solution = """
class R:
    def __eq__(self, other):
        return True

def add(a, b):
    return R()
"""
        res = self.loop.execute_solution_tests(hijack_solution, suite)
        self.assertFalse(res.passed, "Plain object equality hijack against module-level assert must be rejected")
        self.assertEqual(res.status, "FAIL")

    def test_equality_hijack_list_subclass_module_level_assert_rejected(self):
        # Step 3 Acceptance Test: R(list) with __eq__ = lambda s, o: True against module-level assert
        test_code = """
from solution import get_items
assert get_items() == [1, 2, 3]
"""
        suite = self.loop.freeze_tests(test_code)
        hijack_solution = """
class R(list):
    def __eq__(self, other):
        return True

def get_items():
    return R([999])
"""
        res = self.loop.execute_solution_tests(hijack_solution, suite)
        self.assertFalse(res.passed, "R(list) equality hijack against module-level assert must be rejected")
        self.assertEqual(res.status, "FAIL")

    def test_positive_control_correct_solution_passes_via_rpc_channel(self):
        # Positive Control: A correct solution passes cleanly through the two-process RPC channel
        test_code = """
from solution import add

assert add(1, 2) == 3
assert add(-1, 1) == 0

def test_positive_addition():
    assert add(10, 20) == 30
"""
        suite = self.loop.freeze_tests(test_code)
        correct_solution = """
def add(a, b):
    return a + b
"""
        res = self.loop.execute_solution_tests(correct_solution, suite)
        self.assertTrue(res.passed, f"Correct solution must pass via RPC channel: detail={res.detail}")
        self.assertEqual(res.status, "PASS")
        self.assertEqual(res.failed, 0)
        self.assertEqual(res.errors, 0)
        self.assertEqual(res.discovered, 2)
        self.assertEqual(res.executed, 2)


if __name__ == "__main__":
    unittest.main()
