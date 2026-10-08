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


if __name__ == "__main__":
    unittest.main()
