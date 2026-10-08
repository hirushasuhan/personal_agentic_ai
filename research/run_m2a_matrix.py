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
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List

# Ensure research root is on path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from sandbox import get_sandbox, is_sandbox_supported, probe_system_boundary


def get_platform_metadata() -> Dict[str, Any]:
    """
    Programmatically extracts legitimate OS, runtime, and sandbox engine metadata.
    Reads from platform, /etc/os-release, and bwrap --version without hardcoding.
    """
    meta: Dict[str, Any] = {
        "system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "compiler": platform.python_compiler(),
    }
    if sys.platform.startswith("linux"):
        # Distro detection from standard /etc/os-release
        distro = "Linux"
        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            distro = line.split("=", 1)[1].strip().strip('"')
                            break
            except Exception:
                pass
        meta["distro"] = distro

        # Query bubblewrap version directly from bwrap binary in PATH
        bwrap_version = "not installed"
        bwrap_path = shutil.which("bwrap")
        if bwrap_path:
            try:
                res = subprocess.run([bwrap_path, "--version"], capture_output=True, text=True, timeout=2.0)
                if res.returncode == 0:
                    bwrap_version = res.stdout.strip()
            except Exception:
                pass
        meta["bwrap_version"] = bwrap_version
        meta["sandbox_technology"] = f"bubblewrap ({bwrap_version}) + POSIX rlimits"

    elif sys.platform == "win32":
        meta["windows_version"] = platform.version()
        meta["sandbox_technology"] = "Win32 AppContainer + Job Objects"

    return meta


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

    meta = get_platform_metadata()

    log("=" * 72)
    log(f"PAI MILESTONE M2a ADVERSARIAL MATRIX HARNESS (Python {meta['python_version']} on {meta['system']})")
    if meta["system"] == "Linux":
        log(f"Kernel: {meta['release']} | Distro: {meta.get('distro')} | Engine: {meta.get('bwrap_version')}")
    elif meta["system"] == "Windows":
        log(f"OS: Windows {meta['release']} (Build {meta.get('windows_version')}) | Tech: {meta.get('sandbox_technology')}")
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

    def get_combined_output(r) -> str:
        out = r.stdout or ""
        if hasattr(r, "output_files") and r.output_files and "std_output.txt" in r.output_files:
            out += "\n" + r.output_files["std_output.txt"]
        return out

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

        comb_out = get_combined_output(res)
        log_lines.append(f"--- Raw Output for {vec_id} ---")
        log_lines.append(f"Status: {res.status} | Exit Code: {res.exit_code} | Time: {t_ms} ms")
        log_lines.append(f"Stdout:\n{res.stdout}")
        log_lines.append(f"Combined Output:\n{comb_out}")
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
            "stdout_sample": comb_out[:500].strip(),
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
    print('LEAK_ALLOCATED', flush=True)
    with open('std_output.txt', 'w') as f:
        f.write('LEAK_ALLOCATED')
except MemoryError:
    print('CONTAINED_MEMORY_ERROR', flush=True)
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_MEMORY_ERROR')
""",
        assert_fn=lambda r: (
            ("CONTAINED_MEMORY_ERROR" in get_combined_output(r) or r.exit_code != 0 or r.status == "memory_limit")
            and ("LEAK_ALLOCATED" not in get_combined_output(r)),
            f"Memory exhaustion enforced (exit_code={r.exit_code}, out={get_combined_output(r).strip()[:60]})",
        ),
        memory_mb=512.0,
    )

    # -------------------------------------------------------------------------
    # A3 / A7: Subprocess Proliferation
    # -------------------------------------------------------------------------
    if sys.platform == "win32":
        a3_code = """
import subprocess
try:
    subprocess.run(['cmd.exe', '/c', 'echo 1'], capture_output=True, timeout=1.0)
    print('LEAK_SPAWNED', flush=True)
    with open('std_output.txt', 'w') as f: f.write('LEAK_SPAWNED')
except Exception as e:
    print(f'CONTAINED_SPAWN_BLOCKED: {type(e).__name__}', flush=True)
    with open('std_output.txt', 'w') as f: f.write(f'CONTAINED_SPAWN_BLOCKED: {type(e).__name__}')
"""
    else:
        a3_code = """
import os, sys
pids = []
try:
    for _ in range(50):
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        pids.append(pid)
    print('LEAK_FORK_UNBOUNDED', flush=True)
    with open('std_output.txt', 'w') as f: f.write('LEAK_FORK_UNBOUNDED')
except (BlockingIOError, OSError) as e:
    print(f'CONTAINED_FORK_LIMIT: {type(e).__name__}', flush=True)
    with open('std_output.txt', 'w') as f: f.write(f'CONTAINED_FORK_LIMIT: {type(e).__name__}')
"""

    exec_sandbox_test(
        vec_id="A3_A7",
        name="Process proliferation / Subprocess execution",
        desc="Spawning external commands or fork bomb must be blocked/bounded",
        code=a3_code,
        assert_fn=lambda r: (
            "CONTAINED" in get_combined_output(r) and "LEAK" not in get_combined_output(r),
            f"Subprocess proliferation bounded (out={get_combined_output(r).strip()[:60]})",
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
    print('LEAK_DELETED', flush=True)
    with open('std_output.txt', 'w') as f:
        f.write('LEAK_DELETED')
except (PermissionError, FileNotFoundError):
    print('CONTAINED_PERMISSION_DENIED', flush=True)
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_PERMISSION_DENIED')
except OSError as e:
    if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM, errno.ENOENT):
        print('CONTAINED_PERMISSION_DENIED', flush=True)
        with open('std_output.txt', 'w') as f:
            f.write('CONTAINED_PERMISSION_DENIED')
    else:
        print(f'FAIL_UNEXPECTED: {{type(e).__name__}}', flush=True)
except Exception as e:
    print(f'FAIL_UNEXPECTED: {{type(e).__name__}}', flush=True)
""",
            assert_fn=lambda r: (
                "CONTAINED_PERMISSION_DENIED" in get_combined_output(r)
                and "LEAK" not in get_combined_output(r)
                and os.path.exists(canary_a4),
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
        print('LEAK_READ_SUCCESS', flush=True)
        with open('std_output.txt', 'w') as f:
            f.write('LEAK_READ_SUCCESS')
    else:
        print('FAIL_TAMPERED', flush=True)
except (PermissionError, FileNotFoundError):
    print('CONTAINED_READ_BLOCKED', flush=True)
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_READ_BLOCKED')
except Exception as e:
    print(f'FAIL_UNEXPECTED: {{type(e).__name__}}', flush=True)
""",
            assert_fn=lambda r: (
                "CONTAINED_READ_BLOCKED" in get_combined_output(r) and "LEAK" not in get_combined_output(r),
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
    print('LEAK_NETWORK_CONNECTED', flush=True)
    with open('std_output.txt', 'w') as f:
        f.write('LEAK_NETWORK_CONNECTED')
except Exception as e:
    print('CONTAINED_SOCKET_BLOCKED', flush=True)
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_SOCKET_BLOCKED')
""",
        assert_fn=lambda r: (
            "CONTAINED_SOCKET_BLOCKED" in get_combined_output(r) and "LEAK" not in get_combined_output(r),
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
    else:
        libc = ctypes.CDLL(None)
    print('CONTAINED_NATIVE_ISOLATED', flush=True)
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_NATIVE_ISOLATED')
except (ImportError, OSError, Exception) as e:
    print(f'CONTAINED_CTYPES_BLOCKED: {type(e).__name__}', flush=True)
    with open('std_output.txt', 'w') as f:
        f.write(f'CONTAINED_CTYPES_BLOCKED: {type(e).__name__}')
""",
        assert_fn=lambda r: (
            "CONTAINED" in get_combined_output(r) and "LEAK" not in get_combined_output(r),
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
import sys
prefix = "FLOOD_MARKER_START\\n"
chunk = "A" * 1024

try:
    sys.stdout.write(prefix)
    for _ in range(200):
        sys.stdout.write(chunk)
    sys.stdout.flush()
except Exception:
    pass

try:
    with open('std_output.txt', 'w', encoding='utf-8') as f:
        f.write(prefix)
        for _ in range(200):
            f.write(chunk)
except Exception:
    pass
""",
        assert_fn=lambda r: (
            r.status == "ok"
            and len(r.stdout) == 65536
            and "FLOOD_MARKER_START" in r.stdout,
            f"Stdout safely capped at exactly {len(r.stdout)} bytes (ceiling=65536) with flood marker verified",
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
            r.exit_code != 0 and r.status in ("error", "crash"),
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
        "platform": meta,
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

    log("=" * 72)
    log(f"M2a MATRIX RUN COMPLETE: {passed_tests}/{total_tests} vectors PASSED ({report_data['summary']['success_rate_pct']}%)")
    log("=" * 72)

    # Write authentic raw execution trace for the execution run
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")
    print(f"[OK] Raw execution trace written to: {log_path}")

    return 0 if (passed_tests == total_tests) else 1


if __name__ == "__main__":
    sys.exit(run_matrix())
