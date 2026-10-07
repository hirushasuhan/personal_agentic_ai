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
2. POSIX rlimits (via preexec_fn):
   - RLIMIT_AS enforces memory ceiling (default 512 MB).
   - RLIMIT_CPU enforces CPU time budget.
   - RLIMIT_NPROC enforces process count ceiling (1 child max when non-root).
   - RLIMIT_FSIZE caps maximum written file size.
3. Behavioural capability probe:
   - Executes live canary tests on startup to verify containment fail-closed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

# POSIX resource module is only available on Unix
try:
    import resource
except ImportError:
    resource = None


@dataclass
class SandboxResult:
    status: str            # "ok", "timeout", "memory_limit", "error", "terminated"
    exit_code: int
    stdout: str
    stderr: str
    wall_time_sec: float
    output_files: Dict[str, str] = None


def is_bwrap_available() -> bool:
    """Checks if bwrap is installed and executable in PATH."""
    return shutil.which("bwrap") is not None


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
    ):
        self.memory_mb = memory_mb
        self.timeout_sec = timeout_sec
        self.max_output_bytes = max_output_bytes
        self.scratch_dir = scratch_dir or tempfile.mkdtemp(prefix="pai_sandbox_linux_")
        self._owned_scratch = scratch_dir is None

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

    def _build_bwrap_args(self, script_path: str) -> list[str]:
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
                    # bwrap handles symlinks cleanly if target is bound, or use --symlink
                    target = os.readlink(lib_path)
                    args.extend(["--symlink", target, lib_path])
                else:
                    args.extend(["--ro-bind", lib_path, lib_path])

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

        # Bind scratch directory as the ONLY writable location
        scratch_abs = os.path.abspath(self.scratch_dir)
        args.extend(["--bind", scratch_abs, scratch_abs])

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

        # Invocation command: python in isolated mode (-I -B -s)
        python_exe = sys._base_executable if hasattr(sys, "_base_executable") else sys.executable
        args.extend([
            python_exe,
            "-I",
            "-B",
            "-s",
            script_path,
        ])

        return args

    def execute(self, script_path: str) -> SandboxResult:
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

        cmd = self._build_bwrap_args(script_path)
        mem_bytes = int(self.memory_mb * 1024 * 1024)
        cpu_sec = max(1, int(self.timeout_sec) + 2)

        def preexec():
            # SAFETY: POSIX rlimits configure process ceilings before exec.
            if resource:
                try:
                    # Memory limit: virtual address space
                    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                except Exception:
                    pass
                try:
                    # CPU time limit (seconds)
                    resource.setrlimit(resource.RLIMIT_CPU, (cpu_sec, cpu_sec))
                except Exception:
                    pass
                try:
                    # File size write limit (1 MB)
                    fsize = 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
                except Exception:
                    pass
                try:
                    # Subprocess limit (1 process max when non-root)
                    if os.getuid() != 0:
                        resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
                except Exception:
                    pass

        start_time = time.monotonic()
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                preexec_fn=preexec,
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
                        if p != os.path.abspath(script_path):
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
    Behavioural capability probe for Linux (bubblewrap boundary).
    Conducts live canary tests on startup:
    1. Loopback listener connect canary: parent listens, child attempts socket connect -> MUST fail.
    2. Outside canary file read: child attempts reading outside canary -> MUST fail.
    3. Outside canary file write: child attempts writing outside canary -> MUST fail.
    4. Outside canary file delete: child attempts deleting outside canary -> MUST fail.
    5. Subprocess creation: child attempts spawning a subprocess -> MUST fail.
    Returns (True, message) if all canaries are contained, or (False, reason) if any canary compromises containment.
    """
    if sys.platform != "linux" and not sys.platform.startswith("linux"):
        return False, "Linux sandbox capability probe is only applicable on Linux hosts"

    if not is_bwrap_available():
        return False, "bwrap (bubblewrap) executable not found in PATH"

    import socket

    # 1. Setup host loopback listener
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    # 2. Setup outside canary file in user home or /tmp
    outside_dir = tempfile.gettempdir()
    canary_file = os.path.join(outside_dir, f"pai_canary_probe_{os.getpid()}_{int(time.time())}.txt")
    with open(canary_file, "w", encoding="utf-8") as f:
        f.write("CONFIDENTIAL_CANARY_PROBE_DATA")

    probe_script_code = f"""
import socket
import sys
import os

results = {{}}

# 1. Probe loopback socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect(('127.0.0.1', {port}))
    s.close()
    results['loopback_network'] = 'LEAK'
except Exception as e:
    results['loopback_network'] = 'CONTAINED'

# 2. Probe reading canary outside scratch
try:
    with open({repr(canary_file)}, 'r') as f:
        data = f.read()
    results['read_outside'] = 'LEAK'
except Exception as e:
    results['read_outside'] = 'CONTAINED'

# 3. Probe writing to canary file outside scratch
try:
    with open({repr(canary_file)}, 'w') as f:
        f.write('OVERWRITE')
    results['write_outside'] = 'LEAK'
except Exception as e:
    results['write_outside'] = 'CONTAINED'

# 4. Probe deleting canary file outside scratch
try:
    os.remove({repr(canary_file)})
    results['delete_outside'] = 'LEAK'
except Exception as e:
    results['delete_outside'] = 'CONTAINED'

# 5. Probe subprocess creation
try:
    import subprocess
    r = subprocess.run(['echo', '1'], capture_output=True, timeout=1.0)
    results['subprocess'] = 'LEAK'
except Exception as e:
    results['subprocess'] = 'CONTAINED'

with open('probe_report.txt', 'w') as f:
    for k, v in results.items():
        f.write(f'{{k}}:{{v}}\\n')
"""

    sandbox = LinuxSandbox(memory_mb=512.0, timeout_sec=5.0)
    try:
        sandbox.setup()
        probe_target = os.path.join(sandbox.scratch_dir, "probe_script.py")
        with open(probe_target, "w", encoding="utf-8") as f:
            f.write(probe_script_code)

        res = sandbox.execute(probe_target)
        report_file = os.path.join(sandbox.scratch_dir, "probe_report.txt")

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

        return True, "Linux bwrap boundary verified (all canaries contained)"

    finally:
        listener.close()
        sandbox.cleanup()
        if os.path.exists(canary_file):
            try:
                os.remove(canary_file)
            except Exception:
                pass
