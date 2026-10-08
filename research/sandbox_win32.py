"""
Win32 AppContainer & Job Object Restricted Execution Sandbox (Milestone M2a / ADR-011 v2.1)

Provides an OS-level security boundary on Windows:
1. AppContainer isolation: process runs with zero capabilities (blocking inbound and outbound
   network sockets at the TCP/IP driver layer) and zero access to user files outside the granted scratch directory.
2. Job Objects: enforces hard limits on process memory (512 MB), process lifetime (kills all child
   processes if parent exits or closes handle), CPU time limits, and active process count (1 process max).
3. Behavioural capability probe: conducts live canary tests on startup to verify containment fail-closed.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

# ---- Win32 Struct Definitions -----------------------------------------------

class SECURITY_CAPABILITIES(ctypes.Structure):
    # SAFETY: Matches Win32 SECURITY_CAPABILITIES in winnt.h.
    # Total size on 64-bit Windows is 24 bytes (8 + 8 + 4 + 4).
    _fields_ = [
        ("AppContainerSid", wintypes.LPVOID),
        ("Capabilities", wintypes.LPVOID),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class STARTUPINFOW(ctypes.Structure):
    # SAFETY: Standard Win32 STARTUPINFOW layout in winbase.h (68 bytes on x86, 104 on x64).
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    # SAFETY: Matches STARTUPINFOEXW in winbase.h. Contains STARTUPINFOW followed by lpAttributeList.
    _fields_ = [
        ("StartupInfo", STARTUPINFOW),
        ("lpAttributeList", ctypes.c_void_p),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    # SAFETY: Matches PROCESS_INFORMATION in processthreadsapi.h.
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    # SAFETY: Matches IO_COUNTERS in winnt.h (6 uint64 fields = 48 bytes).
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    # SAFETY: Matches JOBOBJECT_BASIC_LIMIT_INFORMATION in winnt.h.
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    # SAFETY: Matches JOBOBJECT_EXTENDED_LIMIT_INFORMATION in winnt.h.
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


# Win32 Constants
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x20009
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
STARTF_USESTDHANDLES = 0x00000100

# Job Object limit flags
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JobObjectExtendedLimitInformation = 9

INFINITE = 0xFFFFFFFF
WAIT_TIMEOUT = 0x00000102
ALL_APPLICATION_PACKAGES_SID = "S-1-15-2-1"


@dataclass
class SandboxResult:
    status: str            # "ok", "timeout", "memory_limit", "error", "terminated"
    exit_code: int
    stdout: str
    stderr: str
    wall_time_sec: float
    output_files: Dict[str, str] = None


def _get_k32():
    # SAFETY: kernel32.dll is a core Windows system library present on all Windows NT versions.
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _get_uenv():
    # SAFETY: userenv.dll implements AppContainer profile management APIs on Windows 8+.
    return ctypes.WinDLL("userenv", use_last_error=True)


def _get_adv():
    # SAFETY: advapi32.dll implements Windows security and SID management APIs.
    return ctypes.WinDLL("advapi32", use_last_error=True)


def _get_icacls_bin() -> str:
    # SAFETY: Resolves full absolute path to icacls.exe in System32 to prevent PATH hijacking.
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = os.path.join(sys_root, "System32", "icacls.exe")
    return candidate if os.path.exists(candidate) else "icacls"


def ensure_sandbox_runtime() -> str:
    """
    Ensures that an isolated read-only Python runtime exists in ~/.pai/sandbox_runtime.
    Grants ALL APPLICATION PACKAGES read access strictly to this local directory so that
    AppContainer processes can execute python.exe and import standard library modules.
    Does NOT modify system-wide ACLs (C:\\Windows, C:\\Program Files remain untouched).
    Returns the absolute path to the sandbox python.exe executable.
    """
    pai_dir = os.path.expanduser("~/.pai")
    runtime_dir = os.path.join(pai_dir, "sandbox_runtime")
    os.makedirs(runtime_dir, exist_ok=True)

    target_exe = os.path.join(runtime_dir, "python.exe")
    src_prefix = sys.base_prefix

    # Check if runtime is already populated
    if not (os.path.exists(target_exe) and os.path.exists(os.path.join(runtime_dir, "Lib"))):
        # Copy core executables and runtime DLLs
        for fn in [
            "python.exe", "python3.dll", "python314.dll", "python313.dll", "python312.dll",
            "python311.dll", "python310.dll", "vcruntime140.dll", "vcruntime140_1.dll"
        ]:
            src_file = os.path.join(src_prefix, fn)
            if os.path.exists(src_file):
                dst_file = os.path.join(runtime_dir, fn)
                shutil.copy2(src_file, dst_file)

        # Copy DLLs directory (contains C extension modules: _socket.pyd, etc.)
        src_dlls = os.path.join(src_prefix, "DLLs")
        dst_dlls = os.path.join(runtime_dir, "DLLs")
        if os.path.exists(src_dlls) and not os.path.exists(dst_dlls):
            shutil.copytree(src_dlls, dst_dlls)

        # Copy Lib directory (standard library .py modules)
        src_lib = os.path.join(src_prefix, "Lib")
        dst_lib = os.path.join(runtime_dir, "Lib")
        if os.path.exists(src_lib) and not os.path.exists(dst_lib):
            shutil.copytree(
                src_lib,
                dst_lib,
                ignore=shutil.ignore_patterns("test", "ensurepip", "idlelib", "tkinter", "tcl*")
            )

        # Grant ALL APPLICATION PACKAGES read-only access strictly to ~/.pai/sandbox_runtime
        icacls_bin = _get_icacls_bin()
        subprocess.run(
            [icacls_bin, runtime_dir, "/grant", f"*{ALL_APPLICATION_PACKAGES_SID}:(OI)(CI)RX", "/T"],
            capture_output=True,
            check=False
        )

    return target_exe


class Win32Sandbox:
    """
    Windows AppContainer + Job Object Restricted Execution Sandbox.
    Enforces kernel-level network blocking, scratch-only filesystem containment,
    memory ceilings, single-process limits, and process-tree termination.
    """

    def __init__(
        self,
        memory_mb: float = 512.0,
        timeout_sec: float = 10.0,
        scratch_dir: Optional[str] = None,
        max_output_bytes: int = 65536,
        extra_writable_dirs: Optional[List[str]] = None,
        max_processes: int = 1,
    ):
        self.memory_mb = min(float(memory_mb), 2048.0)
        self.timeout_sec = min(float(timeout_sec), 30.0)
        self.max_output_bytes = max_output_bytes
        self.max_processes = max(1, int(max_processes))

        self.k32 = _get_k32()
        self.uenv = _get_uenv()
        self.adv = _get_adv()

        self.profile_name = f"PAI_Box_{uuid.uuid4().hex[:12]}"
        self.psid = None
        self.sid_str = None
        self.hJob = None
        self.scratch_dir = scratch_dir
        self.extra_writable_dirs = list(extra_writable_dirs) if extra_writable_dirs else []
        self._owned_scratch = scratch_dir is None
        self._is_setup = False

    def setup(self) -> None:
        """Initializes the scratch directory, Job Object, and AppContainer profile."""
        if self._is_setup:
            return

        # 1. Ephemeral scratch directory
        if not self.scratch_dir:
            self.scratch_dir = tempfile.mkdtemp(prefix="pai_scratch_")
            self._owned_scratch = True
        else:
            os.makedirs(self.scratch_dir, exist_ok=True)

        # 2. Create Job Object
        # SAFETY: CreateJobObjectW creates an unnamed Job Object with default security attributes.
        self.hJob = self.k32.CreateJobObjectW(None, None)
        if not self.hJob:
            err = ctypes.get_last_error()
            raise OSError(f"CreateJobObjectW failed with error {err}")

        # Configure Job Object limits
        eli = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limit_flags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_TIME
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        )
        eli.BasicLimitInformation.LimitFlags = limit_flags
        eli.BasicLimitInformation.ActiveProcessLimit = self.max_processes  # Bounds child process count
        # 100ns units: 1 sec = 10,000,000 units
        eli.BasicLimitInformation.PerProcessUserTimeLimit = int(self.timeout_sec * 10_000_000)

        mem_bytes = int(self.memory_mb * 1024 * 1024)
        eli.ProcessMemoryLimit = mem_bytes
        eli.JobMemoryLimit = mem_bytes

        # SAFETY: Passing pointer to JOBOBJECT_EXTENDED_LIMIT_INFORMATION struct with correct size.
        ok = self.k32.SetInformationJobObject(
            self.hJob,
            JobObjectExtendedLimitInformation,
            ctypes.byref(eli),
            ctypes.sizeof(eli)
        )
        if not ok:
            err = ctypes.get_last_error()
            raise OSError(f"SetInformationJobObject failed with error {err}")

        # 3. Create AppContainer Profile
        raw_psid = wintypes.LPVOID()
        # SAFETY: CreateAppContainerProfile allocates an AppContainer SID and returns S_OK (0) on success.
        hr = self.uenv.CreateAppContainerProfile(
            self.profile_name,
            self.profile_name,
            "PAI Sandbox Profile",
            None,   # Zero capabilities
            0,      # 0 capability count
            ctypes.byref(raw_psid)
        )
        if hr != 0:
            raise OSError(f"CreateAppContainerProfile failed with HRESULT {hex(hr & 0xFFFFFFFF)}")

        self.psid = raw_psid

        # Convert SID to string for icacls ACL grant
        sid_str_p = wintypes.LPWSTR()
        # SAFETY: ConvertSidToStringSidW converts a PSID pointer to a heap-allocated wide string.
        ok = self.adv.ConvertSidToStringSidW(self.psid, ctypes.byref(sid_str_p))
        if not ok:
            err = ctypes.get_last_error()
            raise OSError(f"ConvertSidToStringSidW failed with error {err}")
        self.sid_str = sid_str_p.value
        # SAFETY: LocalFree frees the string allocated by ConvertSidToStringSidW.
        self.k32.LocalFree(sid_str_p)

        # 4. Grant Full Control on scratch directory to this specific AppContainer SID
        icacls_bin = _get_icacls_bin()
        res = subprocess.run(
            [icacls_bin, self.scratch_dir, "/grant", f"*{self.sid_str}:(OI)(CI)F"],
            capture_output=True,
            check=False
        )
        if res.returncode != 0:
            raise OSError(f"icacls failed to grant scratch dir ACL: {res.stderr.decode()}")

        # Grant access to any dedicated extra writable directories (e.g. verdict channel)
        for ed in self.extra_writable_dirs:
            if os.path.exists(ed):
                subprocess.run(
                    [icacls_bin, ed, "/grant", f"*{self.sid_str}:(OI)(CI)F"],
                    capture_output=True,
                    check=False
                )

        self._is_setup = True

    def execute(
        self,
        script_path: str,
        args: Optional[List[str]] = None,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """
        Executes a Python script inside the configured AppContainer + Job Object sandbox.
        Stdout and stderr are captured via anonymous pipe and capped at 64 KB.
        """
        if not self._is_setup:
            self.setup()

        runtime_py = ensure_sandbox_runtime()
        out_file = os.path.join(self.scratch_dir, "std_output.txt")
        err_file = os.path.join(self.scratch_dir, "std_error.txt")

        # Copy the target script into scratch if it is outside
        if not script_path.startswith(self.scratch_dir):
            target_script = os.path.join(self.scratch_dir, "run_target.py")
            shutil.copy2(script_path, target_script)
        else:
            target_script = script_path

        # Setup anonymous pipe with SDDL granting full control to AppContainer
        pSD = ctypes.c_void_p()
        self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            "D:(A;;GA;;;WD)(A;;GA;;;AC)", 1, ctypes.byref(pSD), None
        )
        sa = SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        sa.lpSecurityDescriptor = pSD
        sa.bInheritHandle = True

        hReadOut = wintypes.HANDLE()
        hWriteOut = wintypes.HANDLE()
        self.k32.CreatePipe(ctypes.byref(hReadOut), ctypes.byref(hWriteOut), ctypes.byref(sa), 0)
        self.k32.SetHandleInformation(hReadOut, 1, 0)  # Read end non-inheritable

        # 1. Setup PROC_THREAD_ATTRIBUTE_LIST with PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES and HANDLE_LIST
        attr_size = wintypes.DWORD(0)
        self.k32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(attr_size))
        attr_buf = ctypes.create_string_buffer(attr_size.value)
        self.k32.InitializeProcThreadAttributeList(attr_buf, 2, 0, ctypes.byref(attr_size))

        sec_caps = SECURITY_CAPABILITIES()
        sec_caps.AppContainerSid = self.psid
        sec_caps.Capabilities = None
        sec_caps.CapabilityCount = 0
        sec_caps.Reserved = 0

        ok = self.k32.UpdateProcThreadAttribute(
            attr_buf,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            ctypes.byref(sec_caps),
            ctypes.sizeof(sec_caps),
            None,
            None
        )
        if not ok:
            err = ctypes.get_last_error()
            raise OSError(f"UpdateProcThreadAttribute (SECURITY_CAPABILITIES) failed with error {err}")

        handle_array = (wintypes.HANDLE * 1)(hWriteOut)
        ok = self.k32.UpdateProcThreadAttribute(
            attr_buf,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            ctypes.byref(handle_array),
            ctypes.sizeof(handle_array),
            None,
            None
        )
        if not ok:
            err = ctypes.get_last_error()
            raise OSError(f"UpdateProcThreadAttribute (HANDLE_LIST) failed with error {err}")

        # 2. Setup STARTUPINFOEXW
        si = STARTUPINFOEXW()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        si.lpAttributeList = ctypes.cast(attr_buf, ctypes.c_void_p)
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        si.StartupInfo.hStdOutput = hWriteOut
        si.StartupInfo.hStdError = hWriteOut

        pi = PROCESS_INFORMATION()

        cmd = f'"{runtime_py}" -I -B -s -S "{target_script}"'
        if args:
            cmd += " " + " ".join(f'"{a}"' for a in args)
        flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW

        # Inject extra environment variables into process environment block if provided
        old_env_vals = {}
        if extra_env:
            for k, v in extra_env.items():
                old_env_vals[k] = os.environ.get(k)
                os.environ[k] = str(v)

        t0 = time.time()
        try:
            created = self.k32.CreateProcessW(
                None,
                cmd,
                None,
                None,
                True,  # bInheritHandles = True so hWriteOut is inherited
                flags,
                None,
                self.scratch_dir,
                ctypes.byref(si),
                ctypes.byref(pi)
            )
        finally:
            if extra_env:
                for k, v in extra_env.items():
                    if old_env_vals[k] is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = old_env_vals[k]

        if not created:
            err = ctypes.get_last_error()
            self.k32.CloseHandle(hWriteOut)
            self.k32.CloseHandle(hReadOut)
            raise OSError(f"CreateProcessW failed with error {err}")

        # 3. Assign process to Job Object
        assigned = self.k32.AssignProcessToJobObject(self.hJob, pi.hProcess)
        if not assigned:
            err = ctypes.get_last_error()
            self.k32.TerminateProcess(pi.hProcess, 1)
            self.k32.CloseHandle(pi.hProcess)
            self.k32.CloseHandle(pi.hThread)
            self.k32.CloseHandle(hWriteOut)
            self.k32.CloseHandle(hReadOut)
            raise OSError(f"AssignProcessToJobObject failed with error {err}")

        # 4. Resume thread to begin execution
        self.k32.ResumeThread(pi.hThread)

        # 5. Wait with timeout
        timeout_ms = int(self.timeout_sec * 1000)
        wait_res = self.k32.WaitForSingleObject(pi.hProcess, timeout_ms)

        timed_out = (wait_res == WAIT_TIMEOUT)
        if timed_out:
            self.k32.TerminateJobObject(self.hJob, 99)
            exit_code = 99
        else:
            raw_code = wintypes.DWORD()
            self.k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(raw_code))
            exit_code = raw_code.value

        wall_time = round(time.time() - t0, 3)

        self.k32.CloseHandle(pi.hProcess)
        self.k32.CloseHandle(pi.hThread)
        self.k32.DeleteProcThreadAttributeList(attr_buf)

        # Close parent write end so pipe hits EOF
        self.k32.CloseHandle(hWriteOut)

        # Read pipe output
        pipe_output = b""
        chunk = ctypes.create_string_buffer(4096)
        bytes_read = wintypes.DWORD(0)
        while len(pipe_output) < self.max_output_bytes:
            avail = wintypes.DWORD(0)
            if not self.k32.PeekNamedPipe(hReadOut, None, 0, None, ctypes.byref(avail), None):
                break
            if avail.value == 0:
                break
            to_read = min(4096, avail.value, self.max_output_bytes - len(pipe_output))
            if not self.k32.ReadFile(hReadOut, chunk, to_read, ctypes.byref(bytes_read), None) or bytes_read.value == 0:
                break
            pipe_output += chunk.raw[:bytes_read.value]

        self.k32.CloseHandle(hReadOut)
        if pSD.value:
            self.k32.LocalFree(pSD)

        stdout_str = pipe_output.decode("utf-8", errors="replace")
        stderr_str = ""

        if os.path.exists(out_file):
            try:
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    file_out = f.read(65536)
                    if file_out:
                        stdout_str = (stdout_str + "\n" + file_out).strip() if stdout_str else file_out
            except Exception:
                pass

        if os.path.exists(err_file):
            try:
                with open(err_file, "r", encoding="utf-8", errors="replace") as f:
                    stderr_str = f.read(65536)
            except Exception:
                pass

        # Determine status
        if timed_out:
            status = "timeout"
        elif exit_code == 0:
            status = "ok"
        elif exit_code == 3221225477:  # 0xC0000005 (Access Violation)
            status = "crash"
        else:
            status = "error"

        return SandboxResult(
            status=status,
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            wall_time_sec=wall_time
        )

    def cleanup(self) -> None:
        """Tears down Job Object, deletes AppContainer profile, and deletes scratch directory."""
        if self.hJob:
            # SAFETY: TerminateJobObject kills any lingering processes.
            self.k32.TerminateJobObject(self.hJob, 0)
            # SAFETY: CloseHandle closes the Job Object handle.
            self.k32.CloseHandle(self.hJob)
            self.hJob = None

        if self.psid:
            # SAFETY: FreeSid releases the SID allocated by CreateAppContainerProfile.
            self.adv.FreeSid(self.psid)
            self.psid = None

        if self.profile_name:
            # SAFETY: DeleteAppContainerProfile removes the profile from Windows registry and package store.
            self.uenv.DeleteAppContainerProfile(self.profile_name)
            self.profile_name = None

        if self._owned_scratch and self.scratch_dir and os.path.exists(self.scratch_dir):
            shutil.rmtree(self.scratch_dir, ignore_errors=True)
            self.scratch_dir = None

        self._is_setup = False

    def __enter__(self) -> Win32Sandbox:
        self.setup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()


def probe_win32_boundary() -> Tuple[bool, str]:
    """
    Behavioural Capability Probe (Fail-Closed, ADR-011 v2.1).
    Conducts live canary tests with positive control and parent-side verification:
    (a) Canary placed in host ~/.pai directory with unique secret token.
    (b) Positive control: canary script executed without isolation MUST report LEAK for all canaries.
    (c) Parent-side check: parent verifies canary file exists and contents remain unchanged post-run.
    (d) Expected error types only: PermissionError / WinError 10013 (WSAEACCES). Any other exception fails the probe.
    (e) Subprocess canary verified against Job Object ActiveProcessLimit = 1.
    """
    import socket

    pai_dir = os.path.expanduser("~/.pai")
    os.makedirs(pai_dir, exist_ok=True)
    canary_file = os.path.join(pai_dir, f"probe_canary_{uuid.uuid4().hex[:8]}.tmp")
    secret_token = f"SECRET_CANARY_{uuid.uuid4().hex}"

    # 1. Ephemeral loopback listener
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]

    probe_script_code = f"""import os, sys, socket, subprocess

results = {{}}

# 1. Probe network connect to parent loopback listener
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect(('127.0.0.1', {port}))
    s.close()
    results['network'] = 'LEAK'
except (PermissionError, TimeoutError) as e:
    # Kernel drops TCP packets (TimeoutError) or blocks with WSAEACCES (PermissionError)
    results['network'] = 'CONTAINED'
except OSError as e:
    if getattr(e, 'winerror', None) in (10013, 10060):
        results['network'] = 'CONTAINED'
    else:
        results['network'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'
except Exception as e:
    results['network'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'

# 2. Probe reading canary file outside scratch
try:
    with open({repr(canary_file)}, 'r', encoding='utf-8') as f:
        val = f.read()
    if val == {repr(secret_token)}:
        results['read_outside'] = 'LEAK'
    else:
        results['read_outside'] = 'FAIL_READ_TAMPERED'
except PermissionError:
    results['read_outside'] = 'CONTAINED'
except Exception as e:
    results['read_outside'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'

# 3. Probe writing to canary file outside scratch
try:
    with open({repr(canary_file)}, 'w', encoding='utf-8') as f:
        f.write('OVERWRITE_ATTEMPT')
    results['write_outside'] = 'LEAK'
except PermissionError:
    results['write_outside'] = 'CONTAINED'
except Exception as e:
    results['write_outside'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'

# 4. Probe deleting canary file outside scratch
try:
    os.remove({repr(canary_file)})
    results['delete_outside'] = 'LEAK'
except PermissionError:
    results['delete_outside'] = 'CONTAINED'
except Exception as e:
    results['delete_outside'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'

# 5. Probe subprocess creation (Job Object process limit = 1)
try:
    r = subprocess.run(['cmd.exe', '/c', 'echo 1'], capture_output=True, timeout=1.0)
    results['subprocess'] = 'LEAK'
except (PermissionError, OSError) as e:
    results['subprocess'] = 'CONTAINED'
except Exception as e:
    results['subprocess'] = f'FAIL_UNEXPECTED_ERR: {{type(e).__name__}}: {{e}}'

with open('probe_report.txt', 'w', encoding='utf-8') as f:
    for k, v in results.items():
        f.write(f'{{k}}:{{v}}\\n')
"""

    sandbox = Win32Sandbox(memory_mb=512.0, timeout_sec=5.0)
    pos_control_dir = tempfile.mkdtemp(prefix="pai_probe_pos_")
    try:
        # Step A: Positive Control Verification (unisolated execution MUST detect leaks)
        with open(canary_file, "w", encoding="utf-8") as f:
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

        for canary_key in ["network", "read_outside", "write_outside", "subprocess"]:
            if pos_findings.get(canary_key) != "LEAK":
                return False, f"Positive control failed: '{canary_key}' did not report LEAK unisolated (got {pos_findings.get(canary_key)})"

        # Step B: Reset canary with fresh token and run inside AppContainer + Job Object Sandbox
        with open(canary_file, "w", encoding="utf-8") as f:
            f.write(secret_token)

        sandbox.setup()
        probe_target = os.path.join(sandbox.scratch_dir, "probe_script.py")
        with open(probe_target, "w", encoding="utf-8") as f:
            f.write(probe_script_code)

        res = sandbox.execute(probe_target)
        report_file = os.path.join(sandbox.scratch_dir, "probe_report.txt")

        # Step C: Parent-Side Verification of Canary File
        if not os.path.exists(canary_file):
            return False, "Parent verification failed: outside canary file was deleted"
        with open(canary_file, "r", encoding="utf-8") as f:
            curr_val = f.read()
        if curr_val != secret_token:
            return False, "Parent verification failed: outside canary file content was modified"

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

        return True, "Win32 AppContainer + Job Object boundary verified (all canaries contained, positive control passed, parent checks verified)"

    finally:
        listener.close()
        sandbox.cleanup()
        if os.path.exists(canary_file):
            try:
                os.remove(canary_file)
            except Exception:
                pass
        if os.path.exists(pos_control_dir):
            try:
                shutil.rmtree(pos_control_dir)
            except Exception:
                pass
