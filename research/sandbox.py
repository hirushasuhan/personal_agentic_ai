"""
Unified Restricted Execution Sandbox Runner & Boundary Prober (Milestone M2a / ADR-011 v2.1)

Provides an OS-agnostic facade dispatching to platform-specific sandbox implementations:
- Windows: Win32 AppContainer + Job Objects (sandbox_win32.py)
- Linux: Bubblewrap (bwrap) + POSIX rlimits (sandbox_linux.py)

Fails closed if the platform boundary cannot be created or verified.
"""

import os
import sys
from typing import Any, Optional, Tuple

_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

if sys.platform == "win32":
    from sandbox_win32 import Win32Sandbox as PlatformSandbox
    from sandbox_win32 import probe_win32_boundary as _probe_boundary
    from sandbox_win32 import SandboxResult
elif sys.platform.startswith("linux"):
    from sandbox_linux import LinuxSandbox as PlatformSandbox
    from sandbox_linux import probe_linux_boundary as _probe_boundary
    from sandbox_linux import SandboxResult
else:
    PlatformSandbox = None
    _probe_boundary = None
    from dataclasses import dataclass

    @dataclass
    class SandboxResult:
        status: str
        exit_code: int
        stdout: str
        stderr: str
        wall_time_sec: float
        output_files: dict = None


def get_sandbox(
    memory_mb: float = 512.0,
    timeout_sec: float = 5.0,
    scratch_dir: Optional[str] = None,
    max_output_bytes: int = 65536,
):
    """Returns the platform-specific sandbox instance."""
    if PlatformSandbox is None:
        raise NotImplementedError(f"No sandbox runner available for platform: {sys.platform}")
    return PlatformSandbox(
        memory_mb=memory_mb,
        timeout_sec=timeout_sec,
        scratch_dir=scratch_dir,
        max_output_bytes=max_output_bytes,
    )


def probe_system_boundary() -> Tuple[bool, str]:
    """
    Executes live behavioural capability probe on the current host system.
    Returns (True, message) if boundary containment is verified, or (False, reason) if probe fails.
    """
    if _probe_boundary is None:
        return False, f"Unsupported operating system for sandbox containment: {sys.platform}"
    return _probe_boundary()


def is_sandbox_supported() -> bool:
    """Checks whether the host operating system has an implemented sandbox runner."""
    return PlatformSandbox is not None
