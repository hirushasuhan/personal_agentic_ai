"""
Safe Isolated Code Runner (Track L / ADR-008 / M1.1 Sandbox Specification)

Enforces:
1. No in-process exec of model code.
2. Subprocess execution with hard timeout and process termination (kill on timeout).
3. Scrubbed environment variables (no credentials, tokens, or repo paths).
4. Empty temporary directory sandbox per execution.
5. Network access strictly blocked via socket interception.
6. Hidden test logic and assertions remain strictly in Process A (the evaluator),
   while untrusted model code runs in Process B (the isolated child process).
"""

import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union


WORKER_SCRIPT = """
import sys
import json
import socket

# 1. Strictly block outbound network access
def _blocked_socket(*args, **kwargs):
    raise PermissionError("Network access is blocked in sandbox")
socket.socket = _blocked_socket

# 2. Helper serialization routines (support tuples and infinities)
def deserialize(val):
    if isinstance(val, dict):
        if "__tuple__" in val and len(val) == 1:
            return tuple(deserialize(x) for x in val["__tuple__"])
        if "__inf__" in val and len(val) == 1:
            return float("inf") if val["__inf__"] > 0 else float("-inf")
        return {k: deserialize(v) for k, v in val.items()}
    if isinstance(val, list):
        return [deserialize(x) for x in val]
    return val

def serialize(val):
    if isinstance(val, tuple):
        return {"__tuple__": [serialize(x) for x in val]}
    if isinstance(val, list):
        return [serialize(x) for x in val]
    if isinstance(val, dict):
        return {k: serialize(v) for k, v in val.items()}
    if isinstance(val, float):
        if val == float("inf"):
            return {"__inf__": 1}
        if val == float("-inf"):
            return {"__inf__": -1}
    return val

def main():
    # Load solution
    scope = {}
    try:
        with open("solution.py", "r", encoding="utf-8") as f:
            code = f.read()
        compiled = compile(code, "solution.py", "exec")
        exec(compiled, scope)
    except Exception as e:
        sys.stdout.write(json.dumps({"status": "compile_error", "error": f"{type(e).__name__}: {e}"}) + "\\n")
        return

    req_raw = sys.stdin.read()
    if not req_raw.strip():
        sys.stdout.write(json.dumps({"status": "error", "error": "Empty input"}) + "\\n")
        return

    try:
        req = json.loads(req_raw)
    except Exception as e:
        sys.stdout.write(json.dumps({"status": "error", "error": f"JSON parse error: {e}"}) + "\\n")
        return

    op = req.get("op", "call")
    entry_point = req.get("entry_point")

    if entry_point not in scope:
        sys.stdout.write(json.dumps({"status": "not_found", "error": f"Entry point '{entry_point}' not defined in output."}) + "\\n")
        return

    if op == "check":
        sys.stdout.write(json.dumps({"status": "ok"}) + "\\n")
        return

    target = scope[entry_point]

    try:
        if op == "call":
            args = deserialize(req.get("args", []))
            kwargs = deserialize(req.get("kwargs", {}))
            result = target(*args, **kwargs)
            sys.stdout.write(json.dumps({"status": "ok", "result": serialize(result)}) + "\\n")
        elif op == "class_ops":
            instance = None
            results = []
            for step in req.get("steps", []):
                m_name = step.get("method")
                m_args = deserialize(step.get("args", []))
                m_kwargs = deserialize(step.get("kwargs", {}))
                if m_name == "__init__":
                    instance = target(*m_args, **m_kwargs)
                    results.append(True)
                else:
                    if instance is None:
                        raise RuntimeError("Instance not initialized")
                    m = getattr(instance, m_name)
                    if callable(m):
                        res = m(*m_args, **m_kwargs)
                    else:
                        res = m
                    results.append(serialize(res))
            sys.stdout.write(json.dumps({"status": "ok", "results": results}) + "\\n")
        else:
            sys.stdout.write(json.dumps({"status": "error", "error": f"Unknown op: {op}"}) + "\\n")
    except Exception as e:
        sys.stdout.write(json.dumps({"status": "runtime_error", "error": f"{type(e).__name__}: {e}"}) + "\\n")

if __name__ == "__main__":
    main()
"""


def _serialize_arg(val: Any) -> Any:
    if isinstance(val, tuple):
        return {"__tuple__": [_serialize_arg(x) for x in val]}
    if isinstance(val, list):
        return [_serialize_arg(x) for x in val]
    if isinstance(val, dict):
        return {k: _serialize_arg(v) for k, v in val.items()}
    if isinstance(val, float):
        if val == float("inf"):
            return {"__inf__": 1}
        if val == float("-inf"):
            return {"__inf__": -1}
    return val


def _deserialize_res(val: Any) -> Any:
    if isinstance(val, dict):
        if "__tuple__" in val and len(val) == 1:
            return tuple(_deserialize_res(x) for x in val["__tuple__"])
        if "__inf__" in val and len(val) == 1:
            return float("inf") if val["__inf__"] > 0 else float("-inf")
        return {k: _deserialize_res(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_deserialize_res(x) for x in val]
    return val


def get_scrubbed_env(tmp_dir: str) -> Dict[str, str]:
    """Returns a minimal clean environment with no user tokens, API keys, or project paths."""
    env = {
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
        "SystemDrive": os.environ.get("SystemDrive", "C:"),
        "PATH": os.path.dirname(sys.executable),
        "TEMP": tmp_dir,
        "TMP": tmp_dir,
        "PYTHONIOENCODING": "utf-8",
    }
    return env


def invoke_isolated_worker(
    tmp_dir: str,
    payload: Dict[str, Any],
    timeout_sec: float = 2.0,
) -> Tuple[bool, Any, str]:
    """
    Executes a single invocation in the isolated child process.
    Returns: (success: bool, result_or_none: Any, error_message: str)
    """
    worker_script_path = os.path.join(tmp_dir, "worker.py")
    env = get_scrubbed_env(tmp_dir)

    payload_json = json.dumps(payload)

    cmd = [sys.executable, "-I", "-B", worker_script_path]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=tmp_dir,
            env=env,
            text=True,
            encoding="utf-8",
        )
        stdout, stderr = proc.communicate(input=payload_json, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=1.0)
        except Exception:
            pass
        return False, None, f"Execution timed out ({timeout_sec}s hard limit exceeded; subprocess killed)"
    except Exception as e:
        return False, None, f"Subprocess execution error: {type(e).__name__}: {e}"

    if not stdout or not stdout.strip():
        err = stderr.strip() if stderr else "Empty output from worker"
        return False, None, f"Worker process crashed: {err}"

    try:
        response = json.loads(stdout.strip())
    except Exception as e:
        return False, None, f"Failed to parse worker response JSON: {e} (stdout: {stdout[:200]})"

    status = response.get("status")
    if status == "ok":
        if "results" in response:
            return True, [_deserialize_res(r) for r in response["results"]], ""
        return True, _deserialize_res(response.get("result")), ""
    elif status in ("compile_error", "not_found", "runtime_error", "error"):
        return False, None, response.get("error", f"Worker returned status '{status}'")
    else:
        return False, None, f"Unknown worker status: {status}"


class SubprocessFunctionProxy:
    """A callable proxy that dispatches function calls to an isolated subprocess."""

    def __init__(self, tmp_dir: str, entry_point: str, timeout_sec: float = 2.0):
        self.tmp_dir = tmp_dir
        self.entry_point = entry_point
        self.timeout_sec = timeout_sec

    def __call__(self, *args, **kwargs) -> Any:
        payload = {
            "op": "call",
            "entry_point": self.entry_point,
            "args": [_serialize_arg(a) for a in args],
            "kwargs": {k: _serialize_arg(v) for k, v in kwargs.items()},
        }
        success, result, err = invoke_isolated_worker(self.tmp_dir, payload, self.timeout_sec)
        if not success:
            raise RuntimeError(err)
        return result


class SubprocessClassProxy:
    """A proxy class for tasks defining a class (e.g. CircularBuffer)."""

    def __init__(self, tmp_dir: str, entry_point: str, timeout_sec: float = 2.0):
        self.tmp_dir = tmp_dir
        self.entry_point = entry_point
        self.timeout_sec = timeout_sec

    def execute_steps(self, steps: List[Dict[str, Any]]) -> List[Any]:
        payload = {
            "op": "class_ops",
            "entry_point": self.entry_point,
            "steps": [
                {
                    "method": s.get("method"),
                    "args": [_serialize_arg(a) for a in s.get("args", [])],
                    "kwargs": {k: _serialize_arg(v) for k, v in s.get("kwargs", {}).items()},
                }
                for s in steps
            ],
        }
        success, results, err = invoke_isolated_worker(self.tmp_dir, payload, self.timeout_sec)
        if not success:
            raise RuntimeError(err)
        return results


def run_isolated_task_eval(
    code_str: str,
    entry_point: str,
    test_evaluator_fn: Any,
    timeout_sec: float = 2.0,
) -> Tuple[bool, str]:
    """
    Evaluates untrusted model code against a hidden test evaluator in an isolated sandbox.
    
    1. Creates a dedicated TemporaryDirectory.
    2. Writes model code to solution.py and worker script to worker.py.
    3. Runs compile check.
    4. Evaluates test_evaluator_fn using SubprocessFunctionProxy / SubprocessClassProxy.
    5. Cleanly destroys temporary sandbox.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Write solution
        sol_path = os.path.join(tmp_dir, "solution.py")
        with open(sol_path, "w", encoding="utf-8") as f:
            f.write(code_str)

        worker_path = os.path.join(tmp_dir, "worker.py")
        with open(worker_path, "w", encoding="utf-8") as f:
            f.write(WORKER_SCRIPT)

        # Pre-check compilation and entry point existence in subprocess
        compile_payload = {"op": "check", "entry_point": entry_point}
        success, _, err = invoke_isolated_worker(tmp_dir, compile_payload, timeout_sec=1.5)
        if not success:
            return False, err

        # Evaluate against the test function
        try:
            if entry_point == "CircularBuffer":
                proxy_cls = SubprocessClassProxy(tmp_dir, entry_point, timeout_sec=timeout_sec)
                outcome = test_evaluator_fn(proxy_cls)
            else:
                proxy_fn = SubprocessFunctionProxy(tmp_dir, entry_point, timeout_sec=timeout_sec)
                outcome = test_evaluator_fn(proxy_fn)

            if outcome is True:
                return True, "Passed"
            else:
                return False, "Hidden test assertion returned False"
        except Exception as e:
            return False, f"Test failure: {e}"
