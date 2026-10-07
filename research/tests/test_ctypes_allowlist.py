"""
Policy Test: Ctypes Import Allow-List Enforcement (ADR-011 / Safety Policy)

Enforces that arbitrary Python modules across the repository cannot import
the low-level 'ctypes' module without an explicit architecture review and inclusion
in the approved allow-list.

Approved production modules:
1. hardware_telemetry.py  (Win32 GlobalMemoryStatusEx, GetSystemPowerStatus)
2. memory_probe.py        (Win32 VirtualQueryEx, ProcessMemoryCounters)
3. secure_buffer.py       (C-runtime memset memory zeroization)
4. sandbox_win32.py       (Win32 AppContainer & Job Object restricted runner)
"""

import ast
import os
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APPROVED_CTYPES_MODULES = {
    "hardware_telemetry.py",
    "memory_probe.py",
    "secure_buffer.py",
    "sandbox_win32.py",
}


class TestCtypesAllowlist(unittest.TestCase):
    def test_ctypes_imports_restricted_to_allowlist(self):
        """Ensures only specifically reviewed and approved modules import ctypes."""
        offending_modules = []

        for root, dirs, files in os.walk(ROOT_DIR):
            # Skip test directory, caches, and build artifacts
            if "tests" in root.replace("\\", "/").split("/"):
                continue
            if "__pycache__" in root or ".git" in root:
                continue

            for fname in files:
                if not fname.endswith(".py"):
                    continue

                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        tree = ast.parse(f.read(), filename=fname)
                except Exception:
                    continue

                has_ctypes = False
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name == "ctypes" or alias.name.startswith("ctypes."):
                                has_ctypes = True
                                break
                    elif isinstance(node, ast.ImportFrom):
                        if node.module == "ctypes" or (node.module and node.module.startswith("ctypes.")):
                            has_ctypes = True
                            break

                if has_ctypes and fname not in APPROVED_CTYPES_MODULES:
                    rel_path = os.path.relpath(fpath, ROOT_DIR)
                    offending_modules.append(rel_path)

        self.assertEqual(
            offending_modules,
            [],
            f"Unauthorized 'ctypes' imports detected outside policy allow-list: {offending_modules}. "
            f"Only {sorted(list(APPROVED_CTYPES_MODULES))} are permitted per ADR-011."
        )


if __name__ == "__main__":
    unittest.main()
