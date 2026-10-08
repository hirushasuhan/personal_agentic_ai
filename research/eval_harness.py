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
    """Queries model digest from local model server /api/show or returns None."""
    url = base_url or os.environ.get("PAI_MODEL_URL", "http://127.0.0.1:11434")
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = (parts.hostname or "").lower()
        if hostname not in ("127.0.0.1", "localhost", "::1", "[::1]"):
            return None
        req = urllib.request.Request(
            f"{url}/api/show",
            data=json.dumps({"name": model_name}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("digest") or data.get("details", {}).get("parent_model") or None
    except Exception:
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
        if ok:
            passed_count += 1
        else:
            print(json.dumps({"passed": False, "total_assertions": len(tests), "passed_assertions": passed_count, "error": f"Assertion #{idx+1} returned False"}))
            sys.exit(0)
    except BaseException as e:
        print(json.dumps({"passed": False, "total_assertions": len(tests), "passed_assertions": passed_count, "error": f"Assertion #{idx+1} raised {type(e).__name__}: {e}"}))
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

    mean_zshot = sum(s["pass_at_1_zero_shot_rate"] for s in per_repeat_stats) / len(per_repeat_stats) if per_repeat_stats else 0.0
    mean_rep3 = sum(s["pass_at_1_repair3_rate"] for s in per_repeat_stats) / len(per_repeat_stats) if per_repeat_stats else 0.0
    mean_fa = sum(s["false_accept_rate"] for s in per_repeat_stats) / len(per_repeat_stats) if per_repeat_stats else 0.0
    mean_fr = sum(s["false_reject_rate"] for s in per_repeat_stats) / len(per_repeat_stats) if per_repeat_stats else 0.0

    return {
        "arm": arm,
        "model": model,
        "num_tasks": num_tasks,
        "num_repeats": num_repeats,
        "total_runs": len(records),
        "mean_pass_at_1_zero_shot": round(mean_zshot, 4),
        "mean_pass_at_1_repair3": round(mean_rep3, 4),
        "mean_false_accept_rate": round(mean_fa, 4),
        "mean_false_reject_rate": round(mean_fr, 4),
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
                error_detail=data.get("error_detail"),
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
    temperature: Optional[float] = 0.0,
    seed: Optional[int] = 42,
    verbose: bool = True,
) -> Tuple[List[EvalRecord], Dict[str, Any]]:
    """
    Executes complete evaluation suite across N repeats and saves raw JSONL records.
    Verifies frozen dataset hashes at startup.
    """
    root = find_project_root()
    # 1. Startup hash verification
    verify_eval_set_hashes()

    # 2. Load tasks
    with open(tasks_file, "r", encoding="utf-8") as f:
        tasks = json.load(f)

    if repeats < 1:
        raise ValueError(f"repeats must be >= 1, got {repeats}")

    all_records: List[EvalRecord] = []

    jsonl_file = None
    if out_jsonl_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_jsonl_path)), exist_ok=True)
        jsonl_file = open(out_jsonl_path, "w", encoding="utf-8")

    try:
        for r_idx in range(1, repeats + 1):
            if verbose:
                print(f"=== Starting Repeat {r_idx} / {repeats} (arm: {arm}, model: {model_name}) ===")
            for t_idx, task in enumerate(tasks, 1):
                tid = task["id"]
                if verbose:
                    print(f"  [{t_idx}/{len(tasks)}] Evaluating {tid} ({task.get('name')})...", end="", flush=True)
                rec = run_single_task_evaluation(
                    task=task,
                    arm=arm,
                    model_name=model_name,
                    repeat_idx=r_idx,
                    timeout_sec=timeout_sec,
                    memory_mb=memory_mb,
                    max_repairs=max_repairs,
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
    parser.add_argument("--arm", type=str, default="english", choices=["english", "singlish"], help="Arm name")
    parser.add_argument("--model", type=str, default="qwen2.5-coder:7b", help="Candidate model name")
    parser.add_argument("--repeats", type=int, default=3, help="Number of repeats (default: 3)")
    parser.add_argument("--temperature", type=float, default=0.0, help="Generation temperature (default: 0.0)")
    parser.add_argument("--seed", type=int, default=42, help="Generation seed (default: 42)")
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
        default_tasks = (
            os.path.join(root, "research", "eval_sets", "coding_tasks_singlish.json")
            if args.arm == "singlish"
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
                print(f"Flipping tasks count  : {metrics['total_flipping_tasks']}")
                print(f"Significance note     : {metrics['significance_disclaimer']}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
