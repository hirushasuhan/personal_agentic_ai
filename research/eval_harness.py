"""
Evaluation Harness for Milestone M2b Close-out (ADR-011 v2.1)
Measures verified code generation across repeat runs, computing pass@1, flips, and false-accept/false-reject rates.

Invariants:
1. Always executes through pai code's actual production pipeline (pai.main).
2. Verifies frozen dataset hashes at startup before running; refuses on mismatch.
3. Hidden reference tests (research/eval_sets/hidden_tests/test_coding_tasks.py) are strictly isolated and never passed into any prompt.
4. Hidden test grading executes strictly inside the OS sandbox with timeout, memory limit, and crash/hang resilience.
5. Records raw JSONL outputs allowing independent recomputation on hosts without local model servers.
6. Groups metrics per (arm, model) to prevent cross-arm flip contamination.
7. Explicitly passes temperature and seed, measures model digest and RAM delta (or null).
8. No claims of statistical significance at N=20 sample size.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# Project bootstrap
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

import pai
from eval_sets.hidden_tests.test_coding_tasks import HIDDEN_TESTS
from sandbox import get_sandbox, is_sandbox_supported


class EvalSetIntegrityError(Exception):
    """Raised when frozen eval set hash fails validation against eval_sets_hashes.json."""
    pass


@dataclasses.dataclass
class HiddenTestResult:
    passed: bool
    total_assertions: int
    passed_assertions: int
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "total_assertions": self.total_assertions,
            "passed_assertions": self.passed_assertions,
            "error": self.error,
        }


@dataclasses.dataclass
class EvalRecord:
    task_id: str
    task_name: str
    entry_point: str
    repeat_idx: int
    arm: str
    model: str
    model_digest: Optional[str]
    temperature: Optional[float]
    seed: Optional[int]
    exit_code: int
    pai_verdict: str
    pass_at_1_zero_shot: bool
    pass_at_1_repair3: bool
    total_repairs: int
    iterations: int
    hidden_test_result: HiddenTestResult
    is_false_accept: bool
    is_false_reject: bool
    wall_time_sec: float
    host_ram_delta_mb: Optional[float]
    staged_solution_path: Optional[str] = None
    error_detail: Optional[str] = None
    termination_stage: Optional[str] = None
    is_infra_failure: bool = False
    generated_test_hash: Optional[str] = None
    generated_test_preview: Optional[str] = None
    stub_probe_failure: Optional[Dict[str, Any]] = None
    ast_violations: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_name": self.task_name,
            "entry_point": self.entry_point,
            "repeat_idx": self.repeat_idx,
            "arm": self.arm,
            "model": self.model,
            "model_digest": self.model_digest,
            "temperature": self.temperature,
            "seed": self.seed,
            "exit_code": self.exit_code,
            "pai_verdict": self.pai_verdict,
            "pass_at_1_zero_shot": self.pass_at_1_zero_shot,
            "pass_at_1_repair3": self.pass_at_1_repair3,
            "total_repairs": self.total_repairs,
            "iterations": self.iterations,
            "hidden_test_result": self.hidden_test_result.to_dict(),
            "is_false_accept": self.is_false_accept,
            "is_false_reject": self.is_false_reject,
            "wall_time_sec": round(self.wall_time_sec, 3),
            "host_ram_delta_mb": round(self.host_ram_delta_mb, 2) if self.host_ram_delta_mb is not None else None,
            "staged_solution_path": self.staged_solution_path,
            "error_detail": self.error_detail,
            "termination_stage": self.termination_stage,
            "is_infra_failure": self.is_infra_failure,
            "generated_test_hash": self.generated_test_hash,
            "generated_test_preview": self.generated_test_preview,
            "stub_probe_failure": self.stub_probe_failure,
            "ast_violations": self.ast_violations,
        }


def find_project_root() -> str:
    """Finds repository root directory containing docs/ and research/."""
    cur = os.path.abspath(_DIR)
    while cur and os.path.dirname(cur) != cur:
        if os.path.exists(os.path.join(cur, "docs", "evidence", "eval_sets_hashes.json")):
            return cur
        cur = os.path.dirname(cur)
    return os.path.dirname(_DIR)


def query_model_digest(model_name: str, base_url: Optional[str] = None, timeout: float = 5.0) -> Optional[str]:
    """
    Queries model digest from local model server /api/show or /api/tags, or returns None.
    Does not use parent_model as digest.
    """
    url = base_url or os.environ.get("PAI_MODEL_URL", "http://127.0.0.1:11434")
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = (parts.hostname or "").lower()
        if hostname not in ("127.0.0.1", "localhost", "::1", "[::1]"):
            return None
        # 1. Try /api/show for explicit model digest
        req = urllib.request.Request(
            f"{url}/api/show",
            data=json.dumps({"name": model_name}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            digest = data.get("digest")
            if digest:
                return str(digest)
    except Exception:
        pass

    try:
        # 2. Try /api/tags which lists available models with their digests
        req = urllib.request.Request(
            f"{url}/api/tags",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for m in data.get("models", []):
                name = m.get("name", "")
                if name == model_name or name.split(":")[0] == model_name or model_name.split(":")[0] == name:
                    digest = m.get("digest")
                    if digest:
                        return str(digest)
    except Exception:
        pass

    return None


def verify_eval_set_hashes(
    hash_file_path: Optional[str] = None,
    checked_files: Optional[List[str]] = None,
) -> Dict[str, str]:
    """
    Verifies that the hashes of frozen evaluation files match docs/evidence/eval_sets_hashes.json.
    Refuses to run and raises EvalSetIntegrityError if any hash mismatches or is missing.
    """
    root = find_project_root()
    if hash_file_path is None:
        hash_file_path = os.path.join(root, "docs", "evidence", "eval_sets_hashes.json")

    if not os.path.exists(hash_file_path):
        raise EvalSetIntegrityError(f"Frozen eval set hash registry not found: {hash_file_path}")

    with open(hash_file_path, "r", encoding="utf-8") as f:
        registry = json.load(f)

    file_hashes = registry.get("file_hashes_sha256", {})

    files_to_check = checked_files or [
        "research/eval_sets/coding_tasks.json",
        "research/eval_sets/hidden_tests/test_coding_tasks.py",
        "research/eval_sets/coding_tasks_singlish.json",
    ]

    verified = {}
    for rel_path in files_to_check:
        full_path = os.path.join(root, rel_path.replace("/", os.sep))
        if not os.path.exists(full_path):
            raise EvalSetIntegrityError(f"Eval set file missing from disk: {rel_path} ({full_path})")

        expected_hash = file_hashes.get(rel_path.replace("\\", "/"))
        if not expected_hash:
            raise EvalSetIntegrityError(f"File '{rel_path}' is not registered in {hash_file_path}")

        hasher = hashlib.sha256()
        with open(full_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        actual_hash = hasher.hexdigest()

        if actual_hash != expected_hash:
            raise EvalSetIntegrityError(
                f"Hash mismatch for '{rel_path}'! Expected {expected_hash}, got {actual_hash}. "
                "Frozen eval sets must not be modified."
            )
        verified[rel_path] = actual_hash

    return verified


def run_hidden_tests(
    task_id: str,
    entry_point: str,
    solution_path: str,
    memory_mb: float = 512.0,
    timeout_sec: float = 5.0,
) -> HiddenTestResult:
    """
    Executes hidden reference tests against staged solution.py INSIDE the OS sandbox.
    Never executes solution in the harness process.
    Guarantees isolation against sys.exit, infinite loops, and memory bombs.
    """
    tests_for_task = HIDDEN_TESTS.get(task_id, [])
    if not os.path.exists(solution_path):
        return HiddenTestResult(
            passed=False,
            total_assertions=len(tests_for_task),
            passed_assertions=0,
            error=f"Staged solution file not found at: {solution_path}",
        )

    try:
        with open(solution_path, "r", encoding="utf-8") as f:
            solution_code = f.read()
    except Exception as e:
        return HiddenTestResult(passed=False, total_assertions=len(tests_for_task), passed_assertions=0, error=f"Read error: {e}")

    root = find_project_root()
    hidden_test_file = os.path.join(root, "research", "eval_sets", "hidden_tests", "test_coding_tasks.py")
    if not os.path.exists(hidden_test_file):
        return HiddenTestResult(passed=False, total_assertions=len(tests_for_task), passed_assertions=0, error="test_coding_tasks.py not found")

    with open(hidden_test_file, "r", encoding="utf-8") as f:
        hidden_test_code = f.read()

    sb = get_sandbox(
        memory_mb=memory_mb,
        timeout_sec=timeout_sec,
        max_processes=2,
    )
    sb.setup()

    try:
        # Write solution.py into sandbox scratch
        sol_in_scratch = os.path.join(sb.scratch_dir, "solution.py")
        with open(sol_in_scratch, "w", encoding="utf-8") as f:
            f.write(solution_code)

        # Write test_coding_tasks.py into sandbox scratch
        test_in_scratch = os.path.join(sb.scratch_dir, "test_coding_tasks.py")
        with open(test_in_scratch, "w", encoding="utf-8") as f:
            f.write(hidden_test_code)

        # Write _pai_hidden_runner.py into sandbox scratch
        runner_code = '''
import sys
import os
import json

scratch_dir = os.path.dirname(os.path.abspath(__file__))
if scratch_dir not in sys.path:
    sys.path.insert(0, scratch_dir)

task_id = sys.argv[1]
entry_point = sys.argv[2]

try:
    from test_coding_tasks import HIDDEN_TESTS
except Exception as e:
    print(json.dumps({"passed": False, "total_assertions": 0, "passed_assertions": 0, "error": f"Failed to load HIDDEN_TESTS: {e}"}))
    sys.exit(0)

tests = HIDDEN_TESTS.get(task_id, [])

# Execute solution.py with __name__ == "__main__" so that both module contents
# and any __main__ blocks are evaluated safely inside the sandbox
sol_path = os.path.join(scratch_dir, "solution.py")
ns = {"__name__": "__main__"}
try:
    with open(sol_path, "r", encoding="utf-8") as f:
        src = f.read()
    compiled = compile(src, sol_path, "exec")
    exec(compiled, ns)
except BaseException as e:
    print(json.dumps({"passed": False, "total_assertions": len(tests), "passed_assertions": 0, "error": f"Execution error in solution: {type(e).__name__}: {e}"}))
    sys.exit(0)

fn_or_cls = ns.get(entry_point)
if fn_or_cls is None:
    print(json.dumps({"passed": False, "total_assertions": len(tests), "passed_assertions": 0, "error": f"Entry point '{entry_point}' not found in solution"}))
    sys.exit(0)

passed_count = 0
for idx, test_fn in enumerate(tests):
    try:
        ok = test_fn(fn_or_cls)
    except BaseException as e:
        print(json.dumps({"passed": False, "total_assertions": len(tests), "passed_assertions": passed_count, "error": f"Assertion #{idx+1} raised {type(e).__name__}: {e}"}))
        sys.exit(0)

    if ok:
        passed_count += 1
    else:
        print(json.dumps({"passed": False, "total_assertions": len(tests), "passed_assertions": passed_count, "error": f"Assertion #{idx+1} returned False"}))
        sys.exit(0)

print(json.dumps({"passed": True, "total_assertions": len(tests), "passed_assertions": len(tests), "error": None}))
sys.exit(0)
'''
        runner_path = os.path.join(sb.scratch_dir, "_pai_hidden_runner.py")
        with open(runner_path, "w", encoding="utf-8") as f:
            f.write(runner_code)

        # Execute inside OS sandbox with timeout and memory limits
        res = sb.execute(runner_path, args=[task_id, entry_point])

        # If sandbox exited abnormally or timed out:
        if res.exit_code != 0:
            return HiddenTestResult(
                passed=False,
                total_assertions=len(tests_for_task),
                passed_assertions=0,
                error=f"Sandbox execution failed: {res.status} (exit {res.exit_code}): {res.stderr.strip()[:200]}",
            )

        # Parse JSON output from runner
        out_str = res.stdout.strip()
        last_json = None
        for line in out_str.split("\n"):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    last_json = json.loads(line)
                except Exception:
                    continue

        if not last_json:
            return HiddenTestResult(
                passed=False,
                total_assertions=len(tests_for_task),
                passed_assertions=0,
                error=f"No JSON verdict from sandbox hidden test runner: stdout={out_str[:200]}",
            )

        return HiddenTestResult(
            passed=bool(last_json.get("passed", False)),
            total_assertions=int(last_json.get("total_assertions", 0)),
            passed_assertions=int(last_json.get("passed_assertions", 0)),
            error=last_json.get("error"),
        )
    finally:
        sb.cleanup()


def run_single_task_evaluation(
    task: Dict[str, Any],
    arm: str,
    model_name: str,
    repeat_idx: int,
    timeout_sec: float = 10.0,
    memory_mb: float = 512.0,
    max_repairs: int = 3,
    model_timeout: Optional[float] = None,
    temperature: Optional[float] = 0.0,
    seed: Optional[int] = 42,
) -> EvalRecord:
    """
    Executes a single coding task through the production 'pai code' pipeline,
    records staging output, measures wall clock and host RAM delta, and grades against hidden tests inside sandbox.
    """
    task_id = str(task["id"])
    task_name = str(task.get("name", task_id))
    entry_point = str(task.get("entry_point", task_name))
    task_prompt = str(task["prompt"])

    temp_out = tempfile.mkdtemp(prefix=f"pai_eval_{task_id}_r{repeat_idx}_")
    sol_path = os.path.join(temp_out, "solution.py")

    cmd_args = [
        "code",
        task_prompt,
        "--out", temp_out,
        "--model", model_name,
        "--max-repairs", str(max_repairs),
        "--timeout", str(timeout_sec),
        "--memory-mb", str(memory_mb),
        "--json",
    ]
    if model_timeout is not None:
        cmd_args.extend(["--model-timeout", str(model_timeout)])
    if temperature is not None:
        cmd_args.extend(["--temperature", str(temperature)])
    if seed is not None:
        cmd_args.extend(["--seed", str(seed)])

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    # Measure RAM before
    ram_before: Optional[float] = None
    try:
        from hardware_telemetry import HardwareTelemetry
        telem = HardwareTelemetry()
        ram_before = telem.get_system_snapshot().get("avail_ram_mb")
    except Exception:
        ram_before = None

    start_time = time.monotonic()
    try:
        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
            exit_code = pai.main(cmd_args)
    except Exception as e:
        exit_code = 99
        stderr_buf.write(f"Exception invoking pai.main: {e}\n")

    wall_time = time.monotonic() - start_time
    raw_stdout = stdout_buf.getvalue().strip()

    # Measure RAM after
    host_ram_delta: Optional[float] = None
    if ram_before is not None:
        try:
            ram_after = telem.get_system_snapshot().get("avail_ram_mb")
            if ram_after is not None:
                host_ram_delta = round(abs(ram_before - ram_after), 2)
        except Exception:
            host_ram_delta = None

    # Parse JSON output from 'pai code --json'
    parsed_json: Dict[str, Any] = {}
    if raw_stdout:
        lines = raw_stdout.split("\n")
        for i in range(len(lines)):
            candidate = "\n".join(lines[i:])
            try:
                parsed_json = json.loads(candidate)
                break
            except Exception:
                continue

    pai_passed = (exit_code == 0) and parsed_json.get("success", False)
    pai_verdict = "PASS" if pai_passed else "FAIL"
    pass_zshot = bool(parsed_json.get("pass_at_1_zero_shot", False))
    pass_rep3 = bool(parsed_json.get("pass_at_1_repair3", False))
    repairs_used = int(parsed_json.get("total_repairs", 0) or 0)
    iterations = int(parsed_json.get("iterations", 1) or 1)
    err_type = parsed_json.get("error")
    err_msg = parsed_json.get("detail") or stderr_buf.getvalue().strip() or None
    if err_type and err_msg:
        err_detail = f"{err_type}: {err_msg}"
    elif err_type:
        err_detail = err_type
    else:
        err_detail = err_msg

    # Determine termination stage and infra failure
    is_timeout = bool(parsed_json.get("is_timeout", False)) or ("timed out" in str(err_detail or "").lower())
    is_infra_failure = (err_type == "GENERATOR_ERROR" and is_timeout) or ("http error 5" in str(err_detail or "").lower())

    if pai_passed:
        termination_stage = "accepted_pass"
    elif is_infra_failure:
        termination_stage = "generator_timeout" if is_timeout else "infra_failure"
    elif err_type == "STUB_PROBE_FAILED":
        termination_stage = "pre_solution_stub_probe"
    elif err_type == "AST_SAFETY_VIOLATION":
        termination_stage = "pre_solution_ast_violation"
    elif err_type == "TEST_SUITE_INVALID":
        termination_stage = "pre_solution_test_invalid"
    elif "repair loop exhausted" in str(err_detail or "").lower():
        termination_stage = "repair_exhausted"
    else:
        termination_stage = err_type or "failed"

    # Generated test preview and hash
    gen_test_hash = parsed_json.get("test_hash")
    gen_test_preview = parsed_json.get("test_code_preview")
    if not gen_test_hash and parsed_json.get("test_code"):
        gen_test_hash = hashlib.sha256(parsed_json["test_code"].encode("utf-8")).hexdigest()
        gen_test_preview = "\n".join(parsed_json["test_code"].splitlines()[:40])

    stub_fail_info = None
    if err_type == "STUB_PROBE_FAILED":
        stub_fail_info = {
            "failing_stub": parsed_json.get("failing_stub"),
            "detail": parsed_json.get("detail"),
        }

    ast_violations = parsed_json.get("violations") if err_type == "AST_SAFETY_VIOLATION" else None

    # Grade against hidden reference tests INSIDE THE OS SANDBOX
    staged_sol = parsed_json.get("staged_solution") or (sol_path if os.path.exists(sol_path) else None)
    if staged_sol and os.path.exists(staged_sol):
        hidden_res = run_hidden_tests(
            task_id=task_id,
            entry_point=entry_point,
            solution_path=staged_sol,
            memory_mb=memory_mb,
            timeout_sec=timeout_sec,
        )
    else:
        hidden_res = HiddenTestResult(
            passed=False,
            total_assertions=len(HIDDEN_TESTS.get(task_id, [])),
            passed_assertions=0,
            error="No staged solution produced",
        )

    # False-accept: pai code PASS, but hidden tests FAIL
    is_false_accept = bool(pai_passed and (not hidden_res.passed))

    # False-reject: pai code FAIL, but solution actually passes hidden tests
    is_false_reject = bool((not pai_passed) and hidden_res.passed)

    # Query model digest from model endpoint
    digest = query_model_digest(model_name)

    # Clean up temporary staging directory
    shutil.rmtree(temp_out, ignore_errors=True)

    return EvalRecord(
        task_id=task_id,
        task_name=task_name,
        entry_point=entry_point,
        repeat_idx=repeat_idx,
        arm=arm,
        model=model_name,
        model_digest=digest,
        temperature=temperature,
        seed=seed,
        exit_code=exit_code,
        pai_verdict=pai_verdict,
        pass_at_1_zero_shot=pass_zshot,
        pass_at_1_repair3=pass_rep3,
        total_repairs=repairs_used,
        iterations=iterations,
        hidden_test_result=hidden_res,
        is_false_accept=is_false_accept,
        is_false_reject=is_false_reject,
        wall_time_sec=wall_time,
        host_ram_delta_mb=host_ram_delta,
        staged_solution_path=None,
        error_detail=err_detail,
        termination_stage=termination_stage,
        is_infra_failure=is_infra_failure,
        generated_test_hash=gen_test_hash,
        generated_test_preview=gen_test_preview,
        stub_probe_failure=stub_fail_info,
        ast_violations=ast_violations,
    )


def run_single_task_evaluation_gate_off(
    task: Dict[str, Any],
    arm: str,
    model_name: str,
    repeat_idx: int,
    timeout_sec: float = 10.0,
    memory_mb: float = 512.0,
    model_timeout: Optional[float] = None,
    temperature: Optional[float] = 0.0,
    seed: Optional[int] = 42,
) -> EvalRecord:
    """
    Executes a gate-off baseline evaluation for a single coding task:
    prompts the model directly for the solution without writing model self-tests,
    and grades directly inside the OS sandbox against the hidden reference tests.
    """
    task_id = str(task["id"])
    task_name = str(task.get("name", task_id))
    entry_point = str(task.get("entry_point", task_name))
    task_prompt = str(task["prompt"])

    # Measure RAM before
    ram_before: Optional[float] = None
    try:
        from hardware_telemetry import HardwareTelemetry
        telem = HardwareTelemetry()
        ram_before = telem.get_system_snapshot().get("avail_ram_mb")
    except Exception:
        ram_before = None

    start_time = time.monotonic()

    sol_prompt = (
        f"Write a Python solution for the following task:\n{task_prompt}\n\n"
        "Requirements:\n"
        "- Implement all required functions and classes in module 'solution'.\n"
        f"- The solution must provide entry point '{entry_point}'.\n"
        "- Return ONLY the Python solution code enclosed in ```python ... ``` without explanations.\n"
    )

    temp_out = tempfile.mkdtemp(prefix=f"pai_eval_gateoff_{task_id}_r{repeat_idx}_")
    sol_path = os.path.join(temp_out, "solution.py")

    err_detail = None
    ast_violations = None
    termination_stage = "gate_off_eval"
    is_infra_failure = False

    try:
        raw_sol = pai.call_model_generate(
            model_name=model_name,
            prompt=sol_prompt,
            timeout=model_timeout,
            temperature=temperature,
            seed=seed,
        )
        sol_code = pai.extract_python_code(raw_sol)

        from ast_guard import check_source
        guard_rep = check_source(sol_code)
        if not guard_rep.ok:
            ast_violations = [str(x) for x in guard_rep.violations]
            err_detail = f"AST_SAFETY_VIOLATION: {ast_violations}"
            termination_stage = "pre_solution_ast_violation"
            hidden_res = HiddenTestResult(
                passed=False,
                total_assertions=len(HIDDEN_TESTS.get(task_id, [])),
                passed_assertions=0,
                error=err_detail,
            )
        else:
            with open(sol_path, "w", encoding="utf-8") as f:
                f.write(sol_code)

            hidden_res = run_hidden_tests(
                task_id=task_id,
                entry_point=entry_point,
                solution_path=sol_path,
                memory_mb=memory_mb,
                timeout_sec=timeout_sec,
            )
            if hidden_res.passed:
                termination_stage = "accepted_pass"
            else:
                termination_stage = "hidden_test_failed"
                err_detail = hidden_res.error or "Hidden assertions failed"
    except Exception as e:
        is_timeout = "timeout" in str(e).lower() or "timed out" in str(e).lower()
        is_infra_failure = is_timeout or ("http error" in str(e).lower())
        termination_stage = "generator_timeout" if is_timeout else "infra_failure"
        err_detail = f"GENERATOR_ERROR: {e}"
        hidden_res = HiddenTestResult(
            passed=False,
            total_assertions=len(HIDDEN_TESTS.get(task_id, [])),
            passed_assertions=0,
            error=err_detail,
        )

    wall_time = time.monotonic() - start_time

    # Measure RAM after
    host_ram_delta: Optional[float] = None
    if ram_before is not None:
        try:
            ram_after = telem.get_system_snapshot().get("avail_ram_mb")
            if ram_after is not None:
                host_ram_delta = round(abs(ram_before - ram_after), 2)
        except Exception:
            host_ram_delta = None

    shutil.rmtree(temp_out, ignore_errors=True)
    digest = query_model_digest(model_name)

    passed = hidden_res.passed
    return EvalRecord(
        task_id=task_id,
        task_name=task_name,
        entry_point=entry_point,
        repeat_idx=repeat_idx,
        arm=arm,
        model=model_name,
        model_digest=digest,
        temperature=temperature,
        seed=seed,
        exit_code=0 if passed else 1,
        pai_verdict="PASS" if passed else "FAIL",
        pass_at_1_zero_shot=passed,
        pass_at_1_repair3=passed,
        total_repairs=0,
        iterations=1,
        hidden_test_result=hidden_res,
        is_false_accept=False,
        is_false_reject=False,
        wall_time_sec=wall_time,
        host_ram_delta_mb=host_ram_delta,
        staged_solution_path=None,
        error_detail=err_detail,
        termination_stage=termination_stage,
        is_infra_failure=is_infra_failure,
        generated_test_hash=None,
        generated_test_preview=None,
        stub_probe_failure=None,
        ast_violations=ast_violations,
    )


def _compute_group_metrics(records: List[EvalRecord], arm: str, model: str) -> Dict[str, Any]:
    """Computes aggregated evaluation metrics for a single (arm, model) group."""
    tasks = sorted(list({r.task_id for r in records}))
    repeats = sorted(list({r.repeat_idx for r in records}))
    num_tasks = len(tasks)
    num_repeats = len(repeats)

    per_repeat_stats = []
    for r_idx in repeats:
        r_recs = [r for r in records if r.repeat_idx == r_idx]
        total_r = len(r_recs)
        zshot_count = sum(1 for r in r_recs if r.pass_at_1_zero_shot)
        rep3_count = sum(1 for r in r_recs if r.pass_at_1_repair3)
        fa_count = sum(1 for r in r_recs if r.is_false_accept)
        fr_count = sum(1 for r in r_recs if r.is_false_reject)
        hidden_pass_count = sum(1 for r in r_recs if r.hidden_test_result.passed)
        infra_count = sum(1 for r in r_recs if r.is_infra_failure)
        pre_sol_count = sum(
            1 for r in r_recs
            if (r.termination_stage or "").startswith("pre_solution_")
        )

        per_repeat_stats.append({
            "repeat_idx": r_idx,
            "total_tasks": total_r,
            "pass_at_1_zero_shot_count": zshot_count,
            "pass_at_1_zero_shot_rate": round(zshot_count / total_r, 4) if total_r else 0.0,
            "pass_at_1_repair3_count": rep3_count,
            "pass_at_1_repair3_rate": round(rep3_count / total_r, 4) if total_r else 0.0,
            "hidden_pass_count": hidden_pass_count,
            "hidden_pass_rate": round(hidden_pass_count / total_r, 4) if total_r else 0.0,
            "false_accept_count": fa_count,
            "false_accept_rate": round(fa_count / total_r, 4) if total_r else 0.0,
            "false_reject_count": fr_count,
            "false_reject_rate": round(fr_count / total_r, 4) if total_r else 0.0,
            "infra_failures_count": infra_count,
            "infra_failures_rate": round(infra_count / total_r, 4) if total_r else 0.0,
            "pre_solution_rejections_count": pre_sol_count,
            "pre_solution_rejections_rate": round(pre_sol_count / total_r, 4) if total_r else 0.0,
        })

    # Across-repeats task flips (only valid within same arm/model group)
    flips_by_task = {}
    total_flips = 0
    for tid in tasks:
        tid_recs = sorted([r for r in records if r.task_id == tid], key=lambda x: x.repeat_idx)
        statuses = [r.pass_at_1_repair3 for r in tid_recs]
        has_flip = len(set(statuses)) > 1
        flips_by_task[tid] = {
            "statuses": statuses,
            "flipped": has_flip,
        }
        if has_flip:
            total_flips += 1

    total_records = len(records)
    total_infra = sum(1 for r in records if r.is_infra_failure)
    total_pre_sol = sum(1 for r in records if (r.termination_stage or "").startswith("pre_solution_"))
    stages_breakdown: Dict[str, int] = {}
    for r in records:
        stage = r.termination_stage or "unknown"
        stages_breakdown[stage] = stages_breakdown.get(stage, 0) + 1

    mean_zshot = sum(s["pass_at_1_zero_shot_rate"] for s in per_repeat_stats) / len(per_repeat_stats) if per_repeat_stats else 0.0
    mean_rep3 = sum(s["pass_at_1_repair3_rate"] for s in per_repeat_stats) / len(per_repeat_stats) if per_repeat_stats else 0.0
    mean_fa = sum(s["false_accept_rate"] for s in per_repeat_stats) / len(per_repeat_stats) if per_repeat_stats else 0.0
    mean_fr = sum(s["false_reject_rate"] for s in per_repeat_stats) / len(per_repeat_stats) if per_repeat_stats else 0.0
    mean_infra = sum(s["infra_failures_rate"] for s in per_repeat_stats) / len(per_repeat_stats) if per_repeat_stats else 0.0
    mean_pre_sol = sum(s["pre_solution_rejections_rate"] for s in per_repeat_stats) / len(per_repeat_stats) if per_repeat_stats else 0.0

    return {
        "arm": arm,
        "model": model,
        "num_tasks": num_tasks,
        "num_repeats": num_repeats,
        "total_runs": total_records,
        "mean_pass_at_1_zero_shot": round(mean_zshot, 4),
        "mean_pass_at_1_repair3": round(mean_rep3, 4),
        "mean_false_accept_rate": round(mean_fa, 4),
        "mean_false_reject_rate": round(mean_fr, 4),
        "total_infra_failures": total_infra,
        "infra_failure_rate": round(total_infra / total_records, 4) if total_records else 0.0,
        "pre_solution_rejection_count": total_pre_sol,
        "pre_solution_rejection_rate": round(total_pre_sol / total_records, 4) if total_records else 0.0,
        "termination_stages_breakdown": stages_breakdown,
        "total_flipping_tasks": total_flips,
        "flipping_task_ids": [t for t, v in flips_by_task.items() if v["flipped"]],
        "per_repeat_breakdown": per_repeat_stats,
        "task_flip_details": flips_by_task,
        "significance_disclaimer": "N=20 sample size is descriptive; no claims of statistical significance are made (ADR-011).",
    }


def compute_eval_metrics(records: List[EvalRecord]) -> Dict[str, Any]:
    """
    Computes summary metrics, per-repeat statistics, flips, and rates across evaluation records.
    Strictly groups records by (arm, model) to prevent flip calculation corruption across mixed runs.
    """
    if not records:
        return {"error": "No records provided"}

    grouped: Dict[Tuple[str, str], List[EvalRecord]] = {}
    for r in records:
        key = (r.arm, r.model)
        grouped.setdefault(key, []).append(r)

    group_results = {}
    for (arm, model), group_recs in grouped.items():
        key_name = f"{arm}/{model}"
        group_results[key_name] = _compute_group_metrics(group_recs, arm, model)

    if len(group_results) == 1:
        return list(group_results.values())[0]

    return {
        "is_mixed": True,
        "total_groups": len(group_results),
        "groups": group_results,
        "significance_disclaimer": "N=20 sample size is descriptive; no claims of statistical significance are made (ADR-011).",
    }


def compute_eval_metrics_from_jsonl(jsonl_path: str) -> Dict[str, Any]:
    """Reads raw JSONL run records and computes aggregated metrics grouped by (arm, model)."""
    records = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            h_data = data.get("hidden_test_result", {})
            h_res = HiddenTestResult(
                passed=h_data.get("passed", False),
                total_assertions=h_data.get("total_assertions", 0),
                passed_assertions=h_data.get("passed_assertions", 0),
                error=h_data.get("error"),
            )

            err_detail = data.get("error_detail")
            err_d = str(err_detail or "")
            is_infra = bool(data.get("is_infra_failure", False))
            if not is_infra and ("timed out" in err_d.lower() or "timeout" in err_d.lower()):
                is_infra = True

            term_stage = data.get("termination_stage")
            if not term_stage:
                if data.get("pai_verdict") == "PASS":
                    term_stage = "accepted_pass"
                elif is_infra:
                    term_stage = "generator_timeout"
                elif "STUB_PROBE_FAILED" in err_d:
                    term_stage = "pre_solution_stub_probe"
                elif "AST_SAFETY_VIOLATION" in err_d:
                    term_stage = "pre_solution_ast_violation"
                elif "TEST_SUITE_INVALID" in err_d:
                    term_stage = "pre_solution_test_invalid"
                elif "repair loop exhausted" in err_d.lower():
                    term_stage = "repair_exhausted"
                else:
                    term_stage = "failed"

            rec = EvalRecord(
                task_id=data["task_id"],
                task_name=data.get("task_name", data["task_id"]),
                entry_point=data.get("entry_point", data["task_id"]),
                repeat_idx=int(data["repeat_idx"]),
                arm=data.get("arm", "english"),
                model=data.get("model", "unknown"),
                model_digest=data.get("model_digest"),
                temperature=float(data["temperature"]) if data.get("temperature") is not None else None,
                seed=int(data["seed"]) if data.get("seed") is not None else None,
                exit_code=int(data["exit_code"]),
                pai_verdict=data.get("pai_verdict", "FAIL"),
                pass_at_1_zero_shot=bool(data.get("pass_at_1_zero_shot", False)),
                pass_at_1_repair3=bool(data.get("pass_at_1_repair3", False)),
                total_repairs=int(data.get("total_repairs", 0)),
                iterations=int(data.get("iterations", 1)),
                hidden_test_result=h_res,
                is_false_accept=bool(data.get("is_false_accept", False)),
                is_false_reject=bool(data.get("is_false_reject", False)),
                wall_time_sec=float(data.get("wall_time_sec", 0.0)),
                host_ram_delta_mb=float(data["host_ram_delta_mb"]) if data.get("host_ram_delta_mb") is not None else None,
                staged_solution_path=data.get("staged_solution_path"),
                error_detail=err_detail,
                termination_stage=term_stage,
                is_infra_failure=is_infra,
                generated_test_hash=data.get("generated_test_hash"),
                generated_test_preview=data.get("generated_test_preview"),
                stub_probe_failure=data.get("stub_probe_failure"),
                ast_violations=data.get("ast_violations"),
            )
            records.append(rec)
    return compute_eval_metrics(records)


def run_eval_suite(
    tasks_file: str,
    arm: str,
    model_name: str,
    repeats: int = 3,
    out_jsonl_path: Optional[str] = None,
    timeout_sec: float = 10.0,
    memory_mb: float = 512.0,
    max_repairs: int = 3,
    model_timeout: Optional[float] = None,
    gate_off: bool = False,
    temperature: Optional[float] = 0.0,
    seed: Optional[int] = 42,
    verbose: bool = True,
) -> Tuple[List[EvalRecord], Dict[str, Any]]:
    """
    Executes complete evaluation suite across N repeats and saves raw JSONL records.
    Verifies frozen dataset hashes at startup.
    Supports gated production pipeline or gate-off baseline arm.
    """
    root = find_project_root()
    # 1. Startup hash verification
    verify_eval_set_hashes()

    # 2. Load tasks
    with open(tasks_file, "r", encoding="utf-8") as f:
        tasks = json.load(f)

    if repeats < 1:
        raise ValueError(f"repeats must be >= 1, got {repeats}")

    is_gate_off = gate_off or arm.startswith("gate_off")

    all_records: List[EvalRecord] = []

    jsonl_file = None
    if out_jsonl_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_jsonl_path)), exist_ok=True)
        jsonl_file = open(out_jsonl_path, "w", encoding="utf-8")

    try:
        for r_idx in range(1, repeats + 1):
            if verbose:
                mode_str = "gate-off baseline" if is_gate_off else "gated pipeline"
                print(f"=== Starting Repeat {r_idx} / {repeats} (arm: {arm}, mode: {mode_str}, model: {model_name}) ===")
            for t_idx, task in enumerate(tasks, 1):
                tid = task["id"]
                if verbose:
                    print(f"  [{t_idx}/{len(tasks)}] Evaluating {tid} ({task.get('name')})...", end="", flush=True)
                if is_gate_off:
                    rec = run_single_task_evaluation_gate_off(
                        task=task,
                        arm=arm,
                        model_name=model_name,
                        repeat_idx=r_idx,
                        timeout_sec=timeout_sec,
                        memory_mb=memory_mb,
                        model_timeout=model_timeout,
                        temperature=temperature,
                        seed=seed,
                    )
                else:
                    rec = run_single_task_evaluation(
                        task=task,
                        arm=arm,
                        model_name=model_name,
                        repeat_idx=r_idx,
                        timeout_sec=timeout_sec,
                        memory_mb=memory_mb,
                        max_repairs=max_repairs,
                        model_timeout=model_timeout,
                        temperature=temperature,
                        seed=seed,
                    )
                all_records.append(rec)
                if verbose:
                    print(f" {rec.pai_verdict} (hidden: {'PASS' if rec.hidden_test_result.passed else 'FAIL'}, {rec.wall_time_sec:.1f}s)")

                if jsonl_file:
                    jsonl_file.write(json.dumps(rec.to_dict()) + "\n")
                    jsonl_file.flush()
    finally:
        if jsonl_file:
            jsonl_file.close()

    metrics = compute_eval_metrics(all_records)
    return all_records, metrics


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PAI Evaluation Harness (M2b)")
    parser.add_argument("--run-eval", action="store_true", help="Execute evaluation run")
    parser.add_argument("--tasks", type=str, default=None, help="Path to coding tasks JSON file")
    parser.add_argument("--arm", type=str, default="english", choices=["english", "singlish", "gate_off_english", "gate_off_singlish"], help="Arm name")
    parser.add_argument("--gate-off", action="store_true", help="Run gate-off baseline (direct solution generation without model self-tests)")
    parser.add_argument("--model", type=str, default="qwen2.5-coder:7b", help="Candidate model name")
    parser.add_argument("--repeats", type=int, default=3, help="Number of repeats (default: 3)")
    parser.add_argument("--temperature", type=float, default=0.0, help="Generation temperature (default: 0.0)")
    parser.add_argument("--seed", type=int, default=42, help="Generation seed (default: 42)")
    parser.add_argument("--model-timeout", type=float, default=None, help="Model generation HTTP request timeout in seconds")
    parser.add_argument("--out-jsonl", type=str, default=None, help="Output path for raw JSONL records")
    parser.add_argument("--compute-metrics", type=str, default=None, help="Recompute metrics from raw JSONL file")
    parser.add_argument("--json", action="store_true", help="Output metrics summary in JSON format")

    args = parser.parse_args(argv)

    if args.compute_metrics:
        if not os.path.exists(args.compute_metrics):
            print(f"Error: JSONL file not found: {args.compute_metrics}", file=sys.stderr)
            return 1
        metrics = compute_eval_metrics_from_jsonl(args.compute_metrics)
        print(json.dumps(metrics, indent=2))
        return 0

    if args.run_eval:
        root = find_project_root()
        is_singlish = args.arm in ("singlish", "gate_off_singlish")
        default_tasks = (
            os.path.join(root, "research", "eval_sets", "coding_tasks_singlish.json")
            if is_singlish
            else os.path.join(root, "research", "eval_sets", "coding_tasks.json")
        )
        tasks_path = args.tasks or default_tasks
        out_jsonl = args.out_jsonl or os.path.join(
            root, "docs", "evidence", f"m2b_eval_runs_{args.arm}_{int(time.time())}.jsonl"
        )

        try:
            records, metrics = run_eval_suite(
                tasks_file=tasks_path,
                arm=args.arm,
                model_name=args.model,
                repeats=args.repeats,
                out_jsonl_path=out_jsonl,
                model_timeout=args.model_timeout,
                gate_off=args.gate_off,
                temperature=args.temperature,
                seed=args.seed,
            )
        except EvalSetIntegrityError as e:
            print(f"FATAL: Frozen eval set integrity failure: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error running evaluation suite: {e}", file=sys.stderr)
            return 1

        print("\n" + "=" * 60)
        print(f"EVALUATION COMPLETE ({args.arm.upper()} ARM, {args.repeats} REPEATS)")
        print(f"Raw data recorded: {out_jsonl}")
        print("=" * 60)
        if args.json:
            print(json.dumps(metrics, indent=2))
        else:
            if metrics.get("is_mixed"):
                print(f"Mixed evaluation results across {metrics['total_groups']} groups.")
                for grp, m in metrics["groups"].items():
                    print(f"  Group {grp}: pass@1 (repair<=3): {m['mean_pass_at_1_repair3']*100:.1f}%, flips: {m['total_flipping_tasks']}")
            else:
                print(f"Total tasks evaluated : {metrics['num_tasks']}")
                print(f"Total runs            : {metrics['total_runs']}")
                print(f"pass@1 (zero-shot)    : {metrics['mean_pass_at_1_zero_shot'] * 100:.1f}%")
                print(f"pass@1 (repair<=3)    : {metrics['mean_pass_at_1_repair3'] * 100:.1f}%")
                print(f"False-accept rate     : {metrics['mean_false_accept_rate'] * 100:.1f}%")
                print(f"False-reject rate     : {metrics['mean_false_reject_rate'] * 100:.1f}%")
                print(f"Infra failure rate    : {metrics.get('infra_failure_rate', 0.0) * 100:.1f}% ({metrics.get('total_infra_failures', 0)} runs)")
                print(f"Pre-solution rejects  : {metrics.get('pre_solution_rejection_rate', 0.0) * 100:.1f}% ({metrics.get('pre_solution_rejection_count', 0)} runs)")
                print(f"Flipping tasks count  : {metrics['total_flipping_tasks']}")
                print(f"Significance note     : {metrics['significance_disclaimer']}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
