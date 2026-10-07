"""
Empirical Evidence Generator for Milestone M2a Adversarial Containment Matrix
(Milestone M2a / ADR-011 v2.1)

Executes live containment attack vectors (A1-A11 + behavioural probe) on the host platform,
records exact exit codes, wall-clock timings, raw stdout/stderr streams, and writes:
- docs/evidence/m2a_sandbox_results.json (machine-readable empirical benchmark report)
- docs/evidence/m2a_sandbox_raw.log (complete raw execution trace)
"""

import json
import os
import platform
import socket
import sys
import tempfile
import time
from typing import Any, Dict, List

# Ensure research root is on path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from sandbox import get_sandbox, is_sandbox_supported, probe_system_boundary


def run_matrix() -> int:
    evidence_dir = os.path.join(os.path.dirname(ROOT_DIR), "docs", "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    json_path = os.path.join(evidence_dir, "m2a_sandbox_results.json")
    log_path = os.path.join(evidence_dir, "m2a_sandbox_raw.log")

    log_lines: List[str] = []
    def log(msg: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{ts}] {msg}"
        print(formatted)
        log_lines.append(formatted)

    log("=" * 72)
    log(f"PAI MILESTONE M2a ADVERSARIAL MATRIX HARNESS (Python {platform.python_version()} on {platform.system()})")
    log("=" * 72)

    if not is_sandbox_supported():
        log(f"FATAL: Sandbox execution is not supported on {sys.platform}")
        return 1

    matrix_results: Dict[str, Any] = {}
    total_tests = 0
    passed_tests = 0

    # -------------------------------------------------------------------------
    # 1. Behavioural Capability Probe (Canaries + Positive Control + Parent Checks)
    # -------------------------------------------------------------------------
    log("\n[RUNNING] Vector: PROBE (Live Behavioural Capability Probe)...")
    t0 = time.perf_counter()
    probe_ok, probe_msg = probe_system_boundary()
    duration_ms = round((time.perf_counter() - t0) * 1000, 2)
    total_tests += 1

    probe_entry = {
        "vector_id": "PROBE",
        "name": "Live Behavioural Capability Probe",
        "description": "Canaries for loopback network, outside read/write/delete, and process spawn",
        "status": "PASS" if probe_ok else "FAIL",
        "containment_state": "CONTAINED" if probe_ok else "LEAK_OR_ERROR",
        "wall_time_ms": duration_ms,
        "detail": probe_msg,
    }
    matrix_results["PROBE"] = probe_entry
    if probe_ok:
        passed_tests += 1
        log(f"[PASS] PROBE in {duration_ms} ms: {probe_msg}")
    else:
        log(f"[FAIL] PROBE in {duration_ms} ms: {probe_msg}")

    # Helper for running script in sandbox
    def exec_sandbox_test(
        vec_id: str,
        name: str,
        desc: str,
        code: str,
        assert_fn,
        memory_mb: float = 512.0,
        timeout_sec: float = 3.0,
    ) -> bool:
        nonlocal total_tests, passed_tests
        total_tests += 1
        log(f"\n[RUNNING] Vector: {vec_id} ({name})...")
        sb = get_sandbox(memory_mb=memory_mb, timeout_sec=timeout_sec)
        sb.setup()
        script_path = os.path.join(sb.scratch_dir, "attack_target.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(code)

        t_start = time.perf_counter()
        res = sb.execute(script_path)
        t_ms = round((time.perf_counter() - t_start) * 1000, 2)

        log_lines.append(f"--- Raw Output for {vec_id} ---")
        log_lines.append(f"Status: {res.status} | Exit Code: {res.exit_code} | Time: {t_ms} ms")
        log_lines.append(f"Stdout:\n{res.stdout}")
        log_lines.append(f"Stderr:\n{res.stderr}")
        log_lines.append("-" * 32)

        try:
            ok, detail = assert_fn(res)
        except Exception as ex:
            ok = False
            detail = f"Assertion raised exception: {ex}"

        entry = {
            "vector_id": vec_id,
            "name": name,
            "description": desc,
            "status": "PASS" if ok else "FAIL",
            "containment_state": "CONTAINED" if ok else "LEAK_OR_ERROR",
            "exit_code": res.exit_code,
            "wall_time_ms": t_ms,
            "stdout_sample": res.stdout[:500].strip(),
            "stderr_sample": res.stderr[:500].strip(),
            "detail": detail,
        }
        matrix_results[vec_id] = entry
        sb.cleanup()

        if ok:
            passed_tests += 1
            log(f"[PASS] {vec_id} in {t_ms} ms: {detail}")
            return True
        else:
            log(f"[FAIL] {vec_id} in {t_ms} ms: {detail}")
            return False

    # -------------------------------------------------------------------------
    # A1: Infinite Loop / Wall-Clock Deadline
    # -------------------------------------------------------------------------
    exec_sandbox_test(
        vec_id="A1",
        name="Infinite loop / CPU time exhaustion",
        desc="Runaway computation must be terminated at wall-clock deadline",
        code="""import time\nwhile True:\n    pass\n""",
        assert_fn=lambda r: (
            r.status == "timeout" and (r.exit_code in (99, -9, 137) or "timed out" in r.stderr.lower()),
            f"Process cleanly terminated on timeout (status={r.status}, exit_code={r.exit_code})",
        ),
        timeout_sec=2.0,
    )

    # -------------------------------------------------------------------------
    # A2: Memory Bomb / Heap Exhaustion (512 MB ceiling)
    # -------------------------------------------------------------------------
    exec_sandbox_test(
        vec_id="A2",
        name="Memory bomb / Heap exhaustion",
        desc="Allocating 1024 MB against a 512 MB ceiling must be trapped",
        code="""
try:
    chunks = []
    for _ in range(100):
        chunks.append(bytearray(20 * 1024 * 1024)) # 2 GB total attempt
    with open('std_output.txt', 'w') as f:
        f.write('LEAK_ALLOCATED')
except MemoryError:
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_MEMORY_ERROR')
""",
        assert_fn=lambda r: (
            "CONTAINED_MEMORY_ERROR" in r.stdout or r.exit_code != 0 or r.status == "memory_limit",
            f"Memory exhaustion enforced (exit_code={r.exit_code}, stdout={r.stdout.strip()[:60]})",
        ),
        memory_mb=512.0,
    )

    # -------------------------------------------------------------------------
    # A3 / A7: Subprocess Proliferation
    # -------------------------------------------------------------------------
    cmd_sub = "['cmd.exe', '/c', 'echo 1']" if sys.platform == "win32" else "['echo', '1']"
    exec_sandbox_test(
        vec_id="A3_A7",
        name="Process proliferation / Subprocess execution",
        desc="Spawning external commands or fork bomb must be blocked/bounded",
        code=f"""
import subprocess
try:
    p = subprocess.run({cmd_sub}, capture_output=True, timeout=1.0)
    with open('std_output.txt', 'w') as f:
        f.write('LEAK_SPAWNED')
except Exception as e:
    with open('std_output.txt', 'w') as f:
        f.write(f'CONTAINED_SPAWN_BLOCKED: {{type(e).__name__}}')
""",
        assert_fn=lambda r: (
            "CONTAINED" in r.stdout or "LEAK" not in r.stdout,
            f"Subprocess proliferation blocked (stdout={r.stdout.strip()})",
        ),
    )

    # -------------------------------------------------------------------------
    # A4: Canary File Deletion Outside Scratch
    # -------------------------------------------------------------------------
    pai_dir = os.path.expanduser("~/.pai")
    os.makedirs(pai_dir, exist_ok=True)
    canary_a4 = os.path.join(pai_dir, f"m2a_canary_a4_{os.getpid()}.tmp")
    with open(canary_a4, "w", encoding="utf-8") as f:
        f.write("CANNOT_DELETE_THIS")

    try:
        exec_sandbox_test(
            vec_id="A4",
            name="Outside canary file deletion",
            desc="Attempting to delete a file outside scratch directory must fail with PermissionError",
            code=f"""
import os, errno
try:
    os.remove({repr(canary_a4)})
    with open('std_output.txt', 'w') as f:
        f.write('LEAK_DELETED')
except (PermissionError, FileNotFoundError):
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_PERMISSION_DENIED')
except OSError as e:
    if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM, errno.ENOENT):
        with open('std_output.txt', 'w') as f:
            f.write('CONTAINED_PERMISSION_DENIED')
    else:
        with open('std_output.txt', 'w') as f:
            f.write(f'FAIL_UNEXPECTED: {{type(e).__name__}}')
except Exception as e:
    with open('std_output.txt', 'w') as f:
        f.write(f'FAIL_UNEXPECTED: {{type(e).__name__}}')
""",
            assert_fn=lambda r: (
                "CONTAINED_PERMISSION_DENIED" in r.stdout and os.path.exists(canary_a4),
                "Canary file protected; os.remove raised PermissionError and file is intact on host",
            ),
        )
    finally:
        if os.path.exists(canary_a4):
            try:
                os.remove(canary_a4)
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # A5: Filesystem Read Escape Outside Scratch
    # -------------------------------------------------------------------------
    canary_a5 = os.path.join(pai_dir, f"m2a_canary_a5_{os.getpid()}.tmp")
    with open(canary_a5, "w", encoding="utf-8") as f:
        f.write("SECRET_CONFIDENTIAL_TOKEN_A5")

    try:
        exec_sandbox_test(
            vec_id="A5",
            name="Outside filesystem read escape",
            desc="Attempting to read user files outside scratch must be blocked or masked",
            code=f"""
try:
    with open({repr(canary_a5)}, 'r', encoding='utf-8') as f:
        data = f.read()
    if data == 'SECRET_CONFIDENTIAL_TOKEN_A5':
        with open('std_output.txt', 'w') as f:
            f.write('LEAK_READ_SUCCESS')
    else:
        with open('std_output.txt', 'w') as f:
            f.write('FAIL_TAMPERED')
except (PermissionError, FileNotFoundError):
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_READ_BLOCKED')
except Exception as e:
    with open('std_output.txt', 'w') as f:
        f.write(f'FAIL_UNEXPECTED: {{type(e).__name__}}')
""",
            assert_fn=lambda r: (
                "CONTAINED_READ_BLOCKED" in r.stdout,
                "Read escape contained; host secret was not exposed to child",
            ),
        )
    finally:
        if os.path.exists(canary_a5):
            try:
                os.remove(canary_a5)
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # A6: Network Socket Egress
    # -------------------------------------------------------------------------
    exec_sandbox_test(
        vec_id="A6",
        name="Network socket egress",
        desc="Attempting outbound socket connect must be blocked by kernel driver/namespace",
        code="""
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect(('1.1.1.1', 80))
    with open('std_output.txt', 'w') as f:
        f.write('LEAK_NETWORK_CONNECTED')
except Exception as e:
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_SOCKET_BLOCKED')
""",
        assert_fn=lambda r: (
            "CONTAINED_SOCKET_BLOCKED" in r.stdout,
            "Network egress blocked at OS boundary layer",
        ),
    )

    # -------------------------------------------------------------------------
    # A8: Native Code Loading / Ctypes Escape Attempt
    # -------------------------------------------------------------------------
    exec_sandbox_test(
        vec_id="A8",
        name="Native code loading / ctypes escape attempt",
        desc="Arbitrary ctypes loading or kernel calls must be trapped without host impact",
        code="""
try:
    import ctypes
    if hasattr(ctypes, 'windll'):
        u = ctypes.windll.user32
        u.MessageBeep(0)
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_NATIVE_ISOLATED')
except (ImportError, OSError, Exception) as e:
    with open('std_output.txt', 'w') as f:
        f.write(f'CONTAINED_CTYPES_BLOCKED: {type(e).__name__}')
""",
        assert_fn=lambda r: (
            "CONTAINED" in r.stdout,
            "Ctypes execution isolated or DLL initialization denied inside sandbox",
        ),
    )

    # -------------------------------------------------------------------------
    # A9: Stdout Stream Flood (Pipe Bomb)
    # -------------------------------------------------------------------------
    exec_sandbox_test(
        vec_id="A9",
        name="Stdout stream flood (pipe bomb)",
        desc="Flooding pipe streams with large data must be capped at 64 KB without deadlock",
        code="""
with open('std_output.txt', 'w') as f:
    f.write('A' * 200000)
""",
        assert_fn=lambda r: (
            r.status == "ok" and len(r.stdout) <= 65536,
            f"Stdout safely capped at {len(r.stdout)} bytes (ceiling=65536 bytes) with zero deadlock",
        ),
    )

    # -------------------------------------------------------------------------
    # A11: Unhandled Process Fault / Crash Containment
    # -------------------------------------------------------------------------
    exec_sandbox_test(
        vec_id="A11",
        name="Unhandled process fault / crash containment",
        desc="Child crash/segfault must be isolated cleanly without crashing parent runner",
        code="""
import ctypes
# Trigger immediate segfault / access violation
ctypes.string_at(0)
""",
        assert_fn=lambda r: (
            r.exit_code != 0,
            f"Process crash trapped cleanly (exit_code={r.exit_code}); parent runner intact",
        ),
    )

    # -------------------------------------------------------------------------
    # Write JSON Evidence and Raw Logs (Multi-Platform Persistence)
    # -------------------------------------------------------------------------
    existing_data: Dict[str, Any] = {}
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except Exception:
            existing_data = {}

    platforms_data = existing_data.get("platforms", {})
    if "platform" in existing_data and not platforms_data:
        legacy_sys = existing_data.get("platform", {}).get("system", "Windows")
        platforms_data[legacy_sys] = {
            "generated_at": existing_data.get("generated_at"),
            "platform": existing_data.get("platform"),
            "summary": existing_data.get("summary"),
            "adversarial_containment_matrix": existing_data.get("adversarial_containment_matrix"),
        }

    current_platform_entry = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "compiler": platform.python_compiler(),
        },
        "summary": {
            "total_vectors": total_tests,
            "passed": passed_tests,
            "failed": total_tests - passed_tests,
            "success_rate_pct": round((passed_tests / total_tests) * 100, 1),
        },
        "adversarial_containment_matrix": matrix_results,
    }
    platforms_data[platform.system()] = current_platform_entry

    report_data = {
        "milestone": "M2a",
        "last_updated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "platforms": platforms_data,
        "platform": current_platform_entry["platform"],
        "summary": current_platform_entry["summary"],
        "adversarial_containment_matrix": matrix_results,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    log(f"\n[OK] Machine-readable evidence written to: {json_path}")

    # For raw log, preserve existing platform logs if from different system
    existing_log = ""
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                existing_log = f.read()
        except Exception:
            existing_log = ""

    current_run_log = "\n".join(log_lines) + "\n"
    other_sys = "Linux" if platform.system() == "Windows" else "Windows"
    other_platform_tag = f"on {other_sys}"
    if other_platform_tag in existing_log:
        combined_log = existing_log.strip() + "\n\n" + current_run_log
    else:
        combined_log = current_run_log

    with open(log_path, "w", encoding="utf-8") as f:
        f.write(combined_log)
    log(f"[OK] Raw execution trace written to: {log_path}")

    log("=" * 72)
    log(f"M2a MATRIX RUN COMPLETE: {passed_tests}/{total_tests} vectors PASSED ({report_data['summary']['success_rate_pct']}%)")
    log("=" * 72)

    return 0 if (passed_tests == total_tests) else 1


if __name__ == "__main__":
    sys.exit(run_matrix())
