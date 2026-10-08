"""
Verify Loop & Frozen Test Harness (Milestone M2b / ADR-011 v2.1)

Enforces:
1. Frozen Model-Written & User Tests:
   Tests are parsed, analyzed for assertions and referenced symbols via Python AST,
   and cryptographically hashed (SHA-256) before any solution is generated or repaired.
   The VerifyLoop strictly owns the test code; read-back file hashing and in-driver
   verification prevent any weakening or mutation during repair loops.
2. Stub Probe with Multi-Valued Stub Family (Fail-Vacuous & Strict Non-Vacuity):
   Tests are executed in the OS sandbox across a full stub family:
   (None, 0, 1, -1, "", [], {}, True, False, first argument, NotImplementedError).
   - If tests pass against ANY stub, the suite is rejected as weak/vacuous (naming the stub).
   - If tests crash, timeout, or raise non-assertion exceptions (NameError, ZeroDivisionError,
     ImportError, etc.), the suite is rejected as TEST_SUITE_INVALID (not non-vacuous).
   - Meaningful tests must fail specifically with AssertionError across the family.
3. Test Discovery & Execution Driver:
   Discovers both standalone functions (pytest-style test_*) and unittest.TestCase classes.
   Executes each test individually, tracks per-test outcomes, and enforces executed == discovered >= 1.
4. User Test Priority:
   User-provided --tests strictly take priority over model-written tests.
5. Isolated Sandbox Execution:
   All stub probes and solution test runs execute strictly inside the OS sandbox.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure research root is on path
_CURR_DIR = os.path.dirname(os.path.abspath(__file__))
if _CURR_DIR not in sys.path:
    sys.path.insert(0, _CURR_DIR)

from sandbox import get_sandbox, is_sandbox_supported


class TestMutationError(RuntimeError):
    """Raised when frozen test code is modified during the verification or repair loop."""
    pass


class VacuousTestError(ValueError):
    """Raised when a candidate test suite passes against a trivial stub implementation."""
    pass


class TestSyntaxError(ValueError):
    """Raised when a candidate test suite has invalid Python syntax."""
    pass


# 11-member diverse stub family for rigorous vacuity testing
STUB_FAMILY: List[Tuple[str, str]] = [
    ("None", "return None"),
    ("0", "return 0"),
    ("1", "return 1"),
    ("-1", "return -1"),
    ("empty_str", 'return ""'),
    ("empty_list", "return []"),
    ("empty_dict", "return {}"),
    ("True", "return True"),
    ("False", "return False"),
    ("first_arg", "return args[0] if len(args) > 0 else None"),
    ("NotImplementedError", 'raise NotImplementedError("Stub probe")'),
]


@dataclass(frozen=True)
class FrozenTestSuite:
    """
    Immutable representation of a frozen test suite.
    Guarantees test code integrity across repair cycles.
    """
    test_code: str
    test_hash: str
    source: str  # "user" or "model"
    target_symbols: Tuple[str, ...] = field(default_factory=tuple)
    assertion_count: int = 0

    @classmethod
    def create(cls, test_code: str, source: str = "model") -> FrozenTestSuite:
        """Parses, counts assertions, extracts referenced symbols, and computes SHA-256 hash."""
        clean_code = test_code.strip()
        if not clean_code:
            raise VacuousTestError("Test suite is empty")

        try:
            tree = ast.parse(clean_code, filename="test_suite.py")
        except SyntaxError as e:
            raise TestSyntaxError(f"Test suite has invalid syntax: {e}") from e

        symbols: Set[str] = set()
        assertions = 0

        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                assertions += 1
            elif isinstance(node, ast.Call):
                # Check for unittest assertions (self.assertEqual, etc.)
                if isinstance(node.func, ast.Attribute) and node.func.attr.startswith("assert"):
                    assertions += 1
                elif isinstance(node.func, ast.Name):
                    symbols.add(node.func.id)
                elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id in ("solution", "sol"):
                        symbols.add(node.func.attr)

            elif isinstance(node, ast.ImportFrom):
                if node.module in ("solution", "sol"):
                    for alias in node.names:
                        symbols.add(alias.name)

        h = hashlib.sha256(clean_code.encode("utf-8")).hexdigest()

        return cls(
            test_code=clean_code,
            test_hash=h,
            source=source,
            target_symbols=tuple(sorted(symbols)),
            assertion_count=assertions,
        )

    def verify_integrity(self, test_code: str) -> None:
        """Verifies that the provided test code strictly matches the frozen SHA-256 hash."""
        current_hash = hashlib.sha256(test_code.strip().encode("utf-8")).hexdigest()
        if current_hash != self.test_hash:
            raise TestMutationError(
                f"Frozen test suite modified! Original hash: {self.test_hash}, attempted hash: {current_hash}"
            )


@dataclass
class StubProbeResult:
    """Outcome of running the stub probe across the stub family."""
    passed: bool  # True = non-vacuous (failed with AssertionError across stubs); False = vacuous/invalid
    detail: str
    failing_stub: Optional[str] = None
    stdout: str = ""
    stderr: str = ""


@dataclass
class TestExecutionResult:
    """Outcome of running a candidate solution against the frozen test suite."""
    passed: bool
    status: str  # "PASS", "FAIL", "ERROR", "timeout", "mutation_error"
    exit_code: int
    discovered: int
    executed: int
    failed: int
    errors: int
    failures: List[Dict[str, Any]]
    stdout: str
    stderr: str
    detail: str
    wall_time_sec: float = 0.0


def generate_stub_code(symbols: Tuple[str, ...], stub_name: str, stub_body: str) -> str:
    """
    Generates a trivial wrong solution stub returning the specified stub value or raising exception.
    """
    lines = [
        f"# Autogenerated Trivial Stub for Stub Probe: {stub_name} (ADR-011 v2.1)",
        "import sys",
        "",
        "class _TrivialStub:",
        "    def __call__(self, *args, **kwargs):",
        f"        {stub_body}",
        "    def __getattr__(self, name):",
        "        return _TrivialStub()",
        "    def __repr__(self):",
        f"        return '<TrivialStub:{stub_name}>'",
        "",
    ]
    for s in symbols:
        lines.append(f"def {s}(*args, **kwargs):")
        lines.append(f"    {stub_body}")
        lines.append("")

    lines.append("def __getattr__(name):")
    lines.append("    return _TrivialStub()")
    lines.append("")

    return "\n".join(lines)


class VerifyLoop:
    """
    Manages frozen test registration, stub family probing,
    and isolated solution execution inside the OS sandbox.
    """

    def __init__(
        self,
        memory_mb: float = 512.0,
        timeout_sec: float = 5.0,
        max_repairs: int = 3,
    ):
        self.memory_mb = memory_mb
        self.timeout_sec = timeout_sec
        self.max_repairs = max_repairs

    def freeze_tests(self, test_code: str, source: str = "model") -> FrozenTestSuite:
        """Parses and freezes test code with cryptographic hashing."""
        return FrozenTestSuite.create(test_code, source=source)

    def prepare_test_suite(
        self,
        user_tests_path: Optional[str] = None,
        model_test_code: Optional[str] = None,
    ) -> FrozenTestSuite:
        """
        Prepares and freezes the test suite.
        User-provided --tests strictly take priority over model-written tests.
        """
        if user_tests_path and os.path.exists(user_tests_path):
            with open(user_tests_path, "r", encoding="utf-8") as f:
                user_code = f.read()
            return self.freeze_tests(user_code, source="user")

        if model_test_code:
            return self.freeze_tests(model_test_code, source="model")

        raise ValueError("No test code provided: neither user_tests_path nor model_test_code was specified")

    def run_stub_probe(self, suite: FrozenTestSuite) -> StubProbeResult:
        """
        Executes the frozen test suite across the full stub family in the sandbox.
        - Must contain at least 1 assertion.
        - Must NOT crash, error, or time out on any stub (rejection: TEST_SUITE_INVALID).
        - Must NOT pass against ANY stub in the stub family (rejection: VACUOUS_TESTS_REJECTED / WEAK).
        - Must fail with substantive AssertionError on the stubs.
        """
        # Static check: 0 assertions is immediately vacuous
        if suite.assertion_count == 0:
            return StubProbeResult(
                passed=False,
                detail="VACUOUS_TESTS_REJECTED: Test suite contains 0 assertions",
                failing_stub=None,
            )

        for stub_name, stub_body in STUB_FAMILY:
            stub_code = generate_stub_code(suite.target_symbols, stub_name, stub_body)
            exec_res = self._execute_in_sandbox(stub_code, suite)

            err_type = ""
            err_msg = ""
            if exec_res.failures:
                err_type = exec_res.failures[0].get("type", "")
                err_msg = exec_res.failures[0].get("message", "")

            if exec_res.status == "timeout":
                return StubProbeResult(
                    passed=False,
                    detail=f"TEST_SUITE_INVALID: Test suite timed out on stub '{stub_name}'",
                    failing_stub=stub_name,
                    stdout=exec_res.stdout,
                    stderr=exec_res.stderr,
                )

            if exec_res.status == "mutation_error":
                return StubProbeResult(
                    passed=False,
                    detail=f"TEST_SUITE_INVALID: Test mutation detected: {exec_res.detail}",
                    failing_stub=stub_name,
                )

            # Check for runtime errors (NameError, ZeroDivisionError, broken import, etc.)
            if exec_res.errors > 0 or exec_res.status == "ERROR":
                if stub_name == "NotImplementedError" and err_type == "NotImplementedError":
                    # The stub specifically raised NotImplementedError, and the test failed on it as expected.
                    pass
                else:
                    return StubProbeResult(
                        passed=False,
                        detail=f"TEST_SUITE_INVALID: Test suite crashed with {err_type}: {err_msg} on stub '{stub_name}'",
                        failing_stub=stub_name,
                        stdout=exec_res.stdout,
                        stderr=exec_res.stderr,
                    )

            # If the test suite PASSED against this stub (0 failures, 0 errors) -> WEAK / VACUOUS!
            if exec_res.passed:
                return StubProbeResult(
                    passed=False,
                    detail=f"VACUOUS_TESTS_REJECTED: Test suite is weak: passed against stub '{stub_name}'",
                    failing_stub=stub_name,
                    stdout=exec_res.stdout,
                    stderr=exec_res.stderr,
                )

            # At least one substantive assertion failed on this stub
            if exec_res.failed == 0 and not (stub_name == "NotImplementedError" and err_type == "NotImplementedError"):
                return StubProbeResult(
                    passed=False,
                    detail=f"TEST_SUITE_INVALID: No assertions failed on stub '{stub_name}' but exit code was non-zero",
                    failing_stub=stub_name,
                )

        # All stubs in the family triggered substantive assertion failures without crashes!
        return StubProbeResult(
            passed=True,
            detail=f"NON_VACUOUS_VERIFIED: Test suite correctly failed with substantive assertions across all {len(STUB_FAMILY)} stubs in family",
            failing_stub=None,
        )

    def execute_solution_tests(
        self,
        solution_code: str,
        frozen_suite: FrozenTestSuite,
    ) -> TestExecutionResult:
        """
        Executes candidate solution against the frozen test suite in the sandbox.
        The VerifyLoop strictly owns test writing and enforces read-back hash verification.
        """
        return self._execute_in_sandbox(solution_code, frozen_suite)

    def _execute_in_sandbox(
        self,
        solution_code: str,
        frozen_suite: FrozenTestSuite,
    ) -> TestExecutionResult:
        """
        Executes solution and frozen test suite inside the OS sandbox using an isolated discovery driver.
        """
        if not is_sandbox_supported():
            raise RuntimeError(f"Sandbox execution not supported on platform: {sys.platform}")

        sb = get_sandbox(memory_mb=self.memory_mb, timeout_sec=self.timeout_sec)
        sb.setup()

        try:
            # 1. Write solution.py into scratch
            sol_path = os.path.join(sb.scratch_dir, "solution.py")
            with open(sol_path, "w", encoding="utf-8") as f:
                f.write(solution_code)

            # 2. Write frozen test_suite.py into scratch
            test_path = os.path.join(sb.scratch_dir, "test_suite.py")
            with open(test_path, "w", encoding="utf-8") as f:
                f.write(frozen_suite.test_code)

            # 3. Read back and verify hash before running
            with open(test_path, "r", encoding="utf-8") as f:
                read_back = f.read()
            read_back_hash = hashlib.sha256(read_back.strip().encode("utf-8")).hexdigest()
            if read_back_hash != frozen_suite.test_hash:
                raise TestMutationError(
                    f"Test file tampering detected in scratch! Expected {frozen_suite.test_hash}, got {read_back_hash}"
                )

            # 4. Generate isolated test discovery and execution driver
            driver_code = f'''
import sys
import os
import inspect
import json
import hashlib
import unittest
import types
import ast

scratch_dir = os.path.dirname(os.path.abspath(__file__))
if scratch_dir not in sys.path:
    sys.path.insert(0, scratch_dir)

sys.argv = ["test_suite.py"]

# In-sandbox read-back hash verification
with open("test_suite.py", "r", encoding="utf-8") as f:
    test_source = f.read()

expected_hash = "{frozen_suite.test_hash}"
actual_hash = hashlib.sha256(test_source.strip().encode("utf-8")).hexdigest()
if actual_hash != expected_hash:
    res = {{
        "status": "mutation_error",
        "error": f"Test hash mismatch inside sandbox: expected {{expected_hash}}, got {{actual_hash}}",
        "discovered": 0,
        "executed": 0,
        "passed": 0,
        "failed": 0,
        "errors": 1,
        "failures": [{{"test_id": "<integrity>", "type": "TestMutationError", "message": "In-sandbox hash mismatch"}}],
    }}
    with open("test_result.json", "w", encoding="utf-8") as f:
        json.dump(res, f)
    sys.exit(2)

# Load test suite into isolated module named 'test_suite'
test_mod = types.ModuleType("test_suite")
test_mod.__file__ = os.path.abspath("test_suite.py")
test_mod.__name__ = "test_suite"
sys.modules["test_suite"] = test_mod

module_error = None

# Execute module-level code (imports, definitions, top-level assertions)
try:
    exec(compile(test_source, "test_suite.py", "exec"), test_mod.__dict__)
except AssertionError as ae:
    module_error = ae
except BaseException as ex:
    module_error = ex

if module_error is not None:
    is_assert = isinstance(module_error, AssertionError)
    res = {{
        "status": "FAIL" if is_assert else "ERROR",
        "discovered": 1,
        "executed": 1,
        "passed": 0,
        "failed": 1 if is_assert else 0,
        "errors": 0 if is_assert else 1,
        "failures": [{{"test_id": "<module>", "type": type(module_error).__name__, "message": str(module_error)}}],
    }}
    with open("test_result.json", "w", encoding="utf-8") as f:
        json.dump(res, f)
    sys.exit(1)

# Discover tests:
# A. Standalone pytest-style functions starting with test
standalone_test_funcs = [
    (name, obj) for name, obj in test_mod.__dict__.items()
    if inspect.isfunction(obj) and name.startswith("test")
]

# B. unittest.TestCase subclasses defined in test_suite
test_case_classes = [
    (name, obj) for name, obj in test_mod.__dict__.items()
    if inspect.isclass(obj) and issubclass(obj, unittest.TestCase) and obj is not unittest.TestCase
]

# C. Top-level assertions via AST inspection
has_module_level_assertions = False
try:
    tree = ast.parse(test_source, "test_suite.py")
    for stmt in tree.body:
        if isinstance(stmt, ast.Assert):
            has_module_level_assertions = True
            break
except Exception:
    pass

passed_count = 0
failed_count = 0
error_count = 0
failures_list = []
discovered_tests = []

if has_module_level_assertions:
    discovered_tests.append("<module>")
    passed_count += 1

# Execute standalone test functions
for name, func in standalone_test_funcs:
    discovered_tests.append(name)
    try:
        func()
        passed_count += 1
    except AssertionError as ae:
        failed_count += 1
        failures_list.append({{"test_id": name, "type": "AssertionError", "message": str(ae)}})
    except BaseException as ex:
        error_count += 1
        failures_list.append({{"test_id": name, "type": type(ex).__name__, "message": str(ex)}})

# Execute TestCase classes
for cls_name, cls in test_case_classes:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(cls)
    for test in suite:
        test_id = f"{{cls_name}}.{{test._testMethodName}}"
        discovered_tests.append(test_id)
        result = unittest.TestResult()
        test.run(result)
        if result.wasSuccessful():
            passed_count += 1
        elif result.failures:
            failed_count += 1
            err_msg = result.failures[0][1]
            failures_list.append({{"test_id": test_id, "type": "AssertionError", "message": err_msg}})
        elif result.errors:
            error_count += 1
            err_msg = result.errors[0][1]
            last_line = err_msg.strip().splitlines()[-1] if err_msg else ""
            err_type = last_line.split(":")[0].strip() if ":" in last_line else "RuntimeError"
            failures_list.append({{"test_id": test_id, "type": err_type, "message": err_msg}})

total_discovered = len(discovered_tests)
total_executed = passed_count + failed_count + error_count

if total_discovered == 0 or total_executed < 1 or total_executed != total_discovered:
    overall_status = "ERROR"
    error_count = max(1, error_count)
    failures_list.append({{
        "test_id": "<driver>",
        "type": "NoTestsDiscoveredError" if total_discovered == 0 else "TestExecutionMismatchError",
        "message": f"Execution mismatch or no tests: discovered={{total_discovered}}, executed={{total_executed}}",
    }})
elif error_count > 0:
    overall_status = "ERROR"
elif failed_count > 0:
    overall_status = "FAIL"
else:
    overall_status = "PASS"

result_data = {{
    "status": overall_status,
    "discovered": total_discovered,
    "executed": total_executed,
    "passed": passed_count,
    "failed": failed_count,
    "errors": error_count,
    "failures": failures_list,
}}

with open("test_result.json", "w", encoding="utf-8") as f:
    json.dump(result_data, f)

if overall_status == "PASS":
    print("PAI_TEST_ALL_PASSED", flush=True)
    sys.exit(0)
else:
    print(f"PAI_TEST_FAILED: failed={{failed_count}}, errors={{error_count}}", flush=True)
    sys.exit(1)
'''
            driver_path = os.path.join(sb.scratch_dir, "_pai_driver.py")
            with open(driver_path, "w", encoding="utf-8") as f:
                f.write(driver_code)

            # 5. Execute test driver inside sandbox
            res = sb.execute(driver_path)

            # Combined output capture
            comb_out = res.stdout or ""
            if hasattr(res, "output_files") and res.output_files and "std_output.txt" in res.output_files:
                comb_out += "\n" + res.output_files["std_output.txt"]

            # Read structured result JSON if generated
            res_json_path = os.path.join(sb.scratch_dir, "test_result.json")
            data: Dict[str, Any] = {}
            if os.path.exists(res_json_path):
                try:
                    with open(res_json_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    pass

            if not data:
                discovered = 0
                executed = 0
                passed_c = 0
                failed_c = 0
                errors_c = 1
                failures_l = [{"test_id": "<integrity>", "type": "DriverTerminatedError", "message": "Test driver terminated without writing results"}]
                status_val = "ERROR"
            else:
                discovered = data.get("discovered", 0)
                executed = data.get("executed", 0)
                passed_c = data.get("passed", 0)
                failed_c = data.get("failed", 0)
                errors_c = data.get("errors", 0)
                failures_l = data.get("failures", [])
                status_val = data.get("status", "ERROR" if res.exit_code != 0 else "PASS")

            if res.status == "timeout":
                return TestExecutionResult(
                    passed=False,
                    status="timeout",
                    exit_code=res.exit_code,
                    discovered=discovered,
                    executed=executed,
                    failed=failed_c,
                    errors=errors_c + 1,
                    failures=failures_l,
                    stdout=comb_out,
                    stderr=res.stderr,
                    detail=f"Execution timed out after {self.timeout_sec}s",
                    wall_time_sec=res.wall_time_sec,
                )

            if status_val == "mutation_error":
                return TestExecutionResult(
                    passed=False,
                    status="mutation_error",
                    exit_code=res.exit_code,
                    discovered=discovered,
                    executed=executed,
                    failed=failed_c,
                    errors=errors_c,
                    failures=failures_l,
                    stdout=comb_out,
                    stderr=res.stderr,
                    detail="In-sandbox test mutation detected",
                    wall_time_sec=res.wall_time_sec,
                )

            is_pass = (
                status_val == "PASS"
                and res.exit_code == 0
                and failed_c == 0
                and errors_c == 0
                and executed > 0
                and executed == discovered
            )
            detail_msg = "All tests passed cleanly in sandbox" if is_pass else f"Test run failed: {failed_c} failures, {errors_c} errors"

            return TestExecutionResult(
                passed=is_pass,
                status=status_val,
                exit_code=res.exit_code,
                discovered=discovered,
                executed=executed,
                failed=failed_c,
                errors=errors_c,
                failures=failures_l,
                stdout=comb_out,
                stderr=res.stderr,
                detail=detail_msg,
                wall_time_sec=res.wall_time_sec,
            )
        finally:
            sb.cleanup()
