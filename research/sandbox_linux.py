"""
Linux Bubblewrap (bwrap) Restricted Execution Sandbox (Milestone M2a / ADR-011 v2.1)

Provides an OS-level security boundary on Linux using bubblewrap (bwrap) and POSIX rlimits:
1. bubblewrap isolation:
   - Unshares network namespace (--unshare-net), blocking all inbound and outbound network sockets.
   - Unshares PID namespace (--unshare-pid), preventing child from signaling host processes.
   - Unshares IPC namespace (--unshare-ipc).
   - Drops all Linux capabilities (--cap-drop ALL).
   - Isolates filesystem: ro-binds /usr, /lib, /lib64, /etc, sys.base_prefix; tmpfs masks /home and /tmp;
     binds scratch directory exclusively as writable.
   - --new-session drops controlling terminal to prevent TIOCSTI keystroke injection.
   - --die-with-parent ensures termination if parent dies.
2. In-sandbox POSIX rlimits (via launcher script):
   - Set inside the sandbox by _pai_launcher.py after bwrap namespace setup to avoid
     RLIMIT_NPROC throttling bwrap's own clone() calls during namespace creation.
   - RLIMIT_AS enforces memory ceiling (default 512 MB).
   - RLIMIT_CPU enforces CPU time budget.
   - RLIMIT_NPROC bounds process count inside sandbox.
   - RLIMIT_FSIZE caps maximum written file size.
3. Behavioural capability probe:
   - Live canary self-test with positive control, parent-side checks, and strict exception handling.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SandboxResult:
    status: str            # "ok", "timeout", "memory_limit", "error", "terminated"
    exit_code: int
    stdout: str
    stderr: str
    wall_time_sec: float
    output_files: Dict[str, str] = None


def is_bwrap_available() -> bool:
    """Checks if bwrap executable is present in PATH."""
    return shutil.which("bwrap") is not None


def is_bwrap_functional() -> bool:
    """
    Checks if bwrap is present AND capable of creating unprivileged namespaces on this host.
    AppArmor or kernel restrictions (e.g. Ubuntu 24.04 apparmor_restrict_unprivileged_userns)
    may deny unprivileged namespace creation.

    Uses absolute path to 'true' and full root ro-bind (or runner-equivalent mounts)
    to avoid ENOENT on merged-/usr hosts where /lib64 and /lib symlinks are required
    for the dynamic linker (ld-linux-*.so).
    """
    bwrap_bin = shutil.which("bwrap")
    if not bwrap_bin:
        return False

    true_bin = shutil.which("true")
    if not true_bin:
        for candidate in ["/usr/bin/true", "/bin/true"]:
            if os.path.exists(candidate):
                true_bin = candidate
                break
    if not true_bin:
        true_bin = "true"

    # Probe command candidate 1: full root ro-bind (most resilient across all distros)
    cmd_root = [
        bwrap_bin,
        "--ro-bind", "/", "/",
        "--proc", "/proc",
        "--dev", "/dev",
        "--unshare-net",
        true_bin,
    ]

    # Probe command candidate 2: runner-equivalent explicit mounts
    cmd_explicit = [
        bwrap_bin,
        "--proc", "/proc",
        "--dev", "/dev",
        "--unshare-net",
    ]
    for ro_path in ["/usr", "/etc"]:
        if os.path.exists(ro_path):
            cmd_explicit.extend(["--ro-bind", ro_path, ro_path])
    for lib_path in ["/lib", "/lib64", "/bin", "/sbin"]:
        if os.path.exists(lib_path):
            if os.path.islink(lib_path):
                try:
                    cmd_explicit.extend(["--symlink", os.readlink(lib_path), lib_path])
                except Exception:
                    pass
            else:
                cmd_explicit.extend(["--ro-bind", lib_path, lib_path])
    cmd_explicit.append(true_bin)

    for probe_cmd in [cmd_root, cmd_explicit]:
        try:
            res = subprocess.run(
                probe_cmd,
                capture_output=True,
                timeout=2.0,
            )
            if res.returncode == 0:
                return True
        except Exception:
            continue

    return False



class LinuxSandbox:
    """
    Manages restricted execution using bubblewrap (bwrap) on Linux hosts.
    """

    def __init__(
        self,
        memory_mb: float = 512.0,
        timeout_sec: float = 5.0,
        scratch_dir: Optional[str] = None,
        max_output_bytes: int = 65536,
        extra_ro_binds: Optional[List[str]] = None,
        extra_writable_dirs: Optional[List[str]] = None,
    ):
        self.memory_mb = min(float(memory_mb), 2048.0)
        self.timeout_sec = min(float(timeout_sec), 30.0)
        self.max_output_bytes = max_output_bytes
        self.scratch_dir = scratch_dir or tempfile.mkdtemp(prefix="pai_sandbox_linux_")
        self._owned_scratch = scratch_dir is None
        self.extra_ro_binds = extra_ro_binds or []
        self.extra_writable_dirs = extra_writable_dirs or []

    def setup(self) -> None:
        """Prepares the scratch directory."""
        os.makedirs(self.scratch_dir, exist_ok=True)

    def cleanup(self) -> None:
        """Cleans up scratch directory."""
        if self._owned_scratch and os.path.exists(self.scratch_dir):
            try:
                shutil.rmtree(self.scratch_dir)
            except Exception:
                pass

    def _prepare_launcher(self, script_path: str) -> str:
        """
        Creates an internal launcher script inside the scratch directory.
        The launcher applies POSIX rlimits inside the sandbox before executing the worker code,
        preventing host-side RLIMIT_NPROC from breaking bwrap's namespace clone() calls.
        """
        mem_bytes = int(self.memory_mb * 1024 * 1024)
        cpu_sec = max(1, int(self.timeout_sec) + 2)
        fsize_bytes = 1048576  # 1 MB file write cap

        launcher_path = os.path.join(self.scratch_dir, "_pai_launcher.py")
        launcher_code = f"""import os, sys
try:
    import resource
    try:
        mem = int({mem_bytes})
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    except Exception:
        pass
    try:
        cpu = max(1, int({cpu_sec}))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    except Exception:
        pass
    try:
        fsize = int({fsize_bytes})
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
    except Exception:
        pass
    try:
        if os.getuid() != 0:
            # Bound process proliferation inside sandbox
            resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
    except Exception:
        pass
except ImportError:
    pass

target = sys.argv[1]
sys.argv = sys.argv[1:]
with open(target, 'rb') as f:
    code = compile(f.read(), target, 'exec')
exec(code, {{'__name__': '__main__', '__file__': target}})
"""
        with open(launcher_path, "w", encoding="utf-8") as f:
            f.write(launcher_code)

        return launcher_path

    def _build_bwrap_args(
        self,
        launcher_path: str,
        script_path: str,
        extra_args: Optional[List[str]] = None,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> list[str]:
        """Constructs the complete bwrap command-line argument list."""
        bwrap_bin = shutil.which("bwrap")
        if not bwrap_bin:
            raise RuntimeError("bwrap binary not found in PATH")

        args = [
            bwrap_bin,
            # Session and terminal safety
            "--new-session",
            "--die-with-parent",
            "--clearenv",
            # Namespace isolation
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            # Capability drop
            "--cap-drop", "ALL",
            # Standard pseudo-filesystems
            "--proc", "/proc",
            "--dev", "/dev",
        ]

        # Read-only bind system libraries and binaries
        for ro_path in ["/usr", "/etc"]:
            if os.path.exists(ro_path):
                args.extend(["--ro-bind", ro_path, ro_path])

        # Handle /lib and /lib64 (may be symlinks to /usr/lib on modern Linux)
        for lib_path in ["/lib", "/lib64", "/bin", "/sbin"]:
            if os.path.exists(lib_path):
                if os.path.islink(lib_path):
                    target = os.readlink(lib_path)
                    args.extend(["--symlink", target, lib_path])
                else:
                    args.extend(["--ro-bind", lib_path, lib_path])

        # Extra caller-specified read-only binds (e.g. for external canary testing)
        for extra_path in self.extra_ro_binds:
            if os.path.exists(extra_path):
                args.extend(["--ro-bind", extra_path, extra_path])

        # Interpreter base prefix access (supports pyenv/venv/custom python paths)
        py_prefix = os.path.abspath(sys.base_prefix)
        if os.path.exists(py_prefix) and not py_prefix.startswith(("/usr", "/lib", "/bin")):
            args.extend(["--ro-bind", py_prefix, py_prefix])

        # Mask sensitive user directories with ephemeral tmpfs
        args.extend([
            "--tmpfs", "/home",
            "--tmpfs", "/tmp",
            "--tmpfs", "/root",
            "--tmpfs", "/run",
        ])

        # Bind scratch directory as the ONLY writable location by default
        scratch_abs = os.path.abspath(self.scratch_dir)
        args.extend(["--bind", scratch_abs, scratch_abs])

        # Bind any dedicated extra writable directories (e.g. verdict channel)
        for ed in self.extra_writable_dirs:
            ed_abs = os.path.abspath(ed)
            args.extend(["--bind", ed_abs, ed_abs])

        # Working directory inside sandbox
        args.extend(["--chdir", scratch_abs])

        # Minimal environment variables
        args.extend([
            "--setenv", "PATH", "/usr/bin:/bin",
            "--setenv", "HOME", scratch_abs,
            "--setenv", "TMPDIR", scratch_abs,
            "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
            "--setenv", "PYTHONUNBUFFERED", "1",
        ])

        # Caller-supplied private environment variables (e.g. secret session nonce and HMAC key)
        if extra_env:
            for k, v in extra_env.items():
                args.extend(["--setenv", str(k), str(v)])

        # Invocation command: python executes the in-sandbox launcher which limits resources and execs script
        python_exe = sys._base_executable if hasattr(sys, "_base_executable") else sys.executable
        args.extend([
            python_exe,
            "-I",
            "-B",
            "-s",
            launcher_path,
            script_path,
        ])
        if extra_args:
            args.extend(extra_args)

        return args

    def execute(
        self,
        script_path: str,
        args: Optional[List[str]] = None,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """
        Executes a Python script inside the bubblewrap sandbox with resource limits.
        """
        if sys.platform != "linux" and not sys.platform.startswith("linux"):
            return SandboxResult(
                status="error",
                exit_code=-1,
                stdout="",
                stderr="LinuxSandbox is only supported on Linux",
                wall_time_sec=0.0,
            )

        launcher_path = self._prepare_launcher(script_path)
        cmd = self._build_bwrap_args(launcher_path, script_path, extra_args=args, extra_env=extra_env)

        start_time = time.monotonic()
        try:
            # Notice: No preexec_fn with RLIMIT_NPROC! bwrap creates namespaces freely;
            # limits are enforced inside the sandbox by _pai_launcher.py.
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )

            try:
                stdout_data, stderr_data = proc.communicate(timeout=self.timeout_sec)
                wall_time = time.monotonic() - start_time
                exit_code = proc.returncode

                # Decode safely and truncate to max_output_bytes
                stdout_str = stdout_data[:self.max_output_bytes].decode("utf-8", errors="replace")
                stderr_str = stderr_data[:self.max_output_bytes].decode("utf-8", errors="replace")

                status = "ok"
                if exit_code != 0:
                    status = "error"
                    # Check for memory exhaustion indicators
                    if "MemoryError" in stderr_str or exit_code in (-9, 137, 134):
                        status = "memory_limit"

                # Collect output files created in scratch dir
                output_files = {}
                for root, _, files in os.walk(self.scratch_dir):
                    for fn in files:
                        p = os.path.join(root, fn)
                        if p != os.path.abspath(script_path) and p != os.path.abspath(launcher_path):
                            try:
                                with open(p, "r", encoding="utf-8", errors="replace") as f:
                                    rel = os.path.relpath(p, self.scratch_dir)
                                    output_files[rel] = f.read()
                            except Exception:
                                pass

                return SandboxResult(
                    status=status,
                    exit_code=exit_code,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    wall_time_sec=wall_time,
                    output_files=output_files,
                )

            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_data, stderr_data = proc.communicate()
                wall_time = time.monotonic() - start_time
                return SandboxResult(
                    status="timeout",
                    exit_code=-9,
                    stdout=stdout_data[:self.max_output_bytes].decode("utf-8", errors="replace"),
                    stderr=stderr_data[:self.max_output_bytes].decode("utf-8", errors="replace") + "\n[Execution timed out]",
                    wall_time_sec=wall_time,
                )

        except Exception as e:
            wall_time = time.monotonic() - start_time
            return SandboxResult(
                status="error",
                exit_code=-1,
                stdout="",
                stderr=f"Sandbox execution failed: {e}",
                wall_time_sec=wall_time,
            )


def probe_linux_boundary() -> Tuple[bool, str]:
    """
    Behavioural Capability Probe for Linux (Bubblewrap Boundary, ADR-011 v2.1).
    Conducts live canary tests with positive control and parent-side verification:
    (a) Canaries placed in locations the sandbox would access if not isolated:
        - Write & Delete canary: in a host directory bound read-only (--ro-bind).
        - Read canary: in host ~/.pai directory masked by --tmpfs /home.
    (b) Positive control: unisolated execution MUST report LEAK for all canaries.
    (c) Parent-side check: parent verifies canary files exist and contents remain unchanged post-run.
    (d) Expected error types only: PermissionError (EROFS/EACCES) for filesystem writes,
        ConnectionRefusedError/TimeoutError/ENETUNREACH for network. Any unexpected exception fails probe.
    (e) In-sandbox subprocess spawning is isolated inside its own PID/mount namespaces;
        process resource limits are verified in adversarial test A3.
    """
    if sys.platform != "linux" and not sys.platform.startswith("linux"):
        return False, "Linux sandbox capability probe is only applicable on Linux hosts"

    if not is_bwrap_functional():
        return False, "bwrap executable not found or unable to create namespaces (unprivileged user namespaces may be restricted)"

    import socket

    # 1. Ephemeral loopback listener
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]

    # 2. Host canary files
    secret_token = f"SECRET_CANARY_LINUX_{uuid.uuid4().hex}"

    # Canary A: Directory bound read-only into sandbox for write/delete tests
    host_ro_canary_dir = tempfile.mkdtemp(prefix="pai_canary_ro_")
    canary_write_file = os.path.join(host_ro_canary_dir, "write_canary.txt")

    # Canary B: Secret file in host user home for read isolation test (masked by tmpfs /home)
    pai_dir = os.path.expanduser("~/.pai")
    os.makedirs(pai_dir, exist_ok=True)
    home_secret_file = os.path.join(pai_dir, f"probe_secret_{uuid.uuid4().hex[:8]}.txt")

    pos_control_dir = tempfile.mkdtemp(prefix="pai_probe_pos_linux_")

    probe_script_code = f"""import os, sys, socket, errno

results = {{}}

# 1. Probe network connect to parent loopback listener
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect(('127.0.0.1', {port}))
    s.close()
    results['loopback_network'] = 'LEAK'
except (ConnectionRefusedError, TimeoutError) as e:
    results['loopback_network'] = 'CONTAINED'
except OSError as e:
    # Network namespace isolation blocks routing (ENETUNREACH, EADDRNOTAVAIL, EPERM)
    if e.errno in (errno.ENETUNREACH, errno.EADDRNOTAVAIL, errno.EPERM, errno.ECONNREFUSED, errno.ETIMEDOUT):
        results['loopback_network'] = 'CONTAINED'
    else:
        results['loopback_network'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'
except Exception as e:
    results['loopback_network'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'

# 2. Probe reading secret file in host home (masked by tmpfs /home)
try:
    with open({repr(home_secret_file)}, 'r', encoding='utf-8') as f:
        data = f.read()
    if data == {repr(secret_token)}:
        results['read_outside'] = 'LEAK'
    else:
        results['read_outside'] = 'FAIL_READ_TAMPERED'
except (FileNotFoundError, PermissionError):
    # Masked by tmpfs /home or access denied
    results['read_outside'] = 'CONTAINED'
except OSError as e:
    if e.errno in (errno.ENOENT, errno.EACCES, errno.EPERM):
        results['read_outside'] = 'CONTAINED'
    else:
        results['read_outside'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'
except Exception as e:
    results['read_outside'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'

# 3. Probe writing to canary file in read-only bound host directory
try:
    with open({repr(canary_write_file)}, 'w', encoding='utf-8') as f:
        f.write('OVERWRITE_ATTEMPT')
    results['write_outside'] = 'LEAK'
except PermissionError:
    # EACCES or EPERM
    results['write_outside'] = 'CONTAINED'
except OSError as e:
    # EROFS (Read-only file system, errno 30) is raised by kernel when writing to ro-bind mount
    if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
        results['write_outside'] = 'CONTAINED'
    else:
        results['write_outside'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'
except Exception as e:
    results['write_outside'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'

# 4. Probe deleting canary file in read-only bound host directory
try:
    os.remove({repr(canary_write_file)})
    results['delete_outside'] = 'LEAK'
except PermissionError:
    # EACCES or EPERM
    results['delete_outside'] = 'CONTAINED'
except OSError as e:
    # EROFS is raised by kernel when deleting from ro-bind mount
    if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
        results['delete_outside'] = 'CONTAINED'
    else:
        results['delete_outside'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'
except Exception as e:
    results['delete_outside'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'

with open('probe_report.txt', 'w', encoding='utf-8') as f:
    for k, v in results.items():
        f.write(f'{{k}}:{{v}}\\n')
"""

    sandbox = LinuxSandbox(
        memory_mb=512.0,
        timeout_sec=5.0,
        extra_ro_binds=[host_ro_canary_dir],
    )

    try:
        # Step A: Positive Control Verification (unisolated execution MUST detect leaks)
        with open(canary_write_file, "w", encoding="utf-8") as f:
            f.write(secret_token)
        with open(home_secret_file, "w", encoding="utf-8") as f:
            f.write(secret_token)

        pos_script = os.path.join(pos_control_dir, "pos_probe.py")
        with open(pos_script, "w", encoding="utf-8") as f:
            f.write(probe_script_code)

        p_proc = subprocess.run(
            [sys.executable, pos_script],
            cwd=pos_control_dir,
            capture_output=True,
            timeout=5.0
        )
        pos_report = os.path.join(pos_control_dir, "probe_report.txt")
        if not os.path.exists(pos_report):
            return False, f"Positive control failed to generate report: {p_proc.stderr.decode('utf-8', errors='replace')}"

        pos_findings = {}
        with open(pos_report, "r", encoding="utf-8") as f:
            for line in f:
                if ":" in line:
                    k, v = line.strip().split(":", 1)
                    pos_findings[k] = v

        for canary_key in ["loopback_network", "read_outside", "write_outside", "delete_outside"]:
            if pos_findings.get(canary_key) != "LEAK":
                return False, f"Positive control failed: '{canary_key}' did not report LEAK unisolated (got {pos_findings.get(canary_key)})"

        # Step B: Reset canaries with fresh token and run inside Bubblewrap Sandbox
        with open(canary_write_file, "w", encoding="utf-8") as f:
            f.write(secret_token)
        with open(home_secret_file, "w", encoding="utf-8") as f:
            f.write(secret_token)

        sandbox.setup()
        probe_target = os.path.join(sandbox.scratch_dir, "probe_script.py")
        with open(probe_target, "w", encoding="utf-8") as f:
            f.write(probe_script_code)

        res = sandbox.execute(probe_target)
        report_file = os.path.join(sandbox.scratch_dir, "probe_report.txt")

        # Step C: Parent-Side Verification of Canary Files
        if not os.path.exists(canary_write_file):
            return False, "Parent verification failed: outside canary write file was deleted"
        with open(canary_write_file, "r", encoding="utf-8") as f:
            if f.read() != secret_token:
                return False, "Parent verification failed: outside canary write file content was modified"

        if not os.path.exists(home_secret_file):
            return False, "Parent verification failed: outside home secret file was deleted"
        with open(home_secret_file, "r", encoding="utf-8") as f:
            if f.read() != secret_token:
                return False, "Parent verification failed: outside home secret file content was modified"

        # Step D: Verify child execution report
        if not os.path.exists(report_file):
            return False, f"Sandbox failed to execute probe script (exit code {res.exit_code}): {res.stderr}"

        findings = {}
        with open(report_file, "r", encoding="utf-8") as f:
            for line in f:
                if ":" in line:
                    k, v = line.strip().split(":", 1)
                    findings[k] = v

        for canary, state in findings.items():
            if state != "CONTAINED":
                return False, f"Boundary compromise: canary '{canary}' was not contained (state: {state})"

        return True, "Linux bwrap boundary verified (all canaries contained, positive control passed, parent checks verified)"

    finally:
        listener.close()
        sandbox.cleanup()
        if os.path.exists(host_ro_canary_dir):
            try:
                shutil.rmtree(host_ro_canary_dir)
            except Exception:
                pass
        if os.path.exists(home_secret_file):
            try:
                os.remove(home_secret_file)
            except Exception:
                pass
        if os.path.exists(pos_control_dir):
            try:
                shutil.rmtree(pos_control_dir)
            except Exception:
                pass
