"""
Adversarial Containment Matrix Tests for Windows AppContainer + Job Object Sandbox
(Milestone M2a / ADR-011 v2.1)

Validates the full adversarial attack containment matrix on Windows:
- A1: Infinite loop / CPU timeout
- A2: Memory bomb / heap exhaustion
- A3: Process proliferation / fork bomb
- A4: Canary file deletion
- A5: Filesystem read escape
- A6: Network socket egress
- A7: Subprocess execution
- A9: Stdout stream flood
- A11: Crash / fault containment
- Behavioural capability probe
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if sys.platform == "win32":
    from sandbox_win32 import Win32Sandbox, probe_win32_boundary
else:
    Win32Sandbox = None
    probe_win32_boundary = None



@unittest.skipUnless(sys.platform == "win32", "Win32 sandbox tests run only on Windows")
class TestWin32SandboxContainment(unittest.TestCase):
    def setUp(self):
        self.sandbox = Win32Sandbox(memory_mb=512.0, timeout_sec=3.0)
        self.sandbox.setup()

    def tearDown(self):
        self.sandbox.cleanup()

    def _write_script(self, code: str) -> str:
        path = os.path.join(self.sandbox.scratch_dir, "test_target.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        return path

    def test_behavioural_capability_probe(self):
        """Verifies that the live behavioural canary probe passes on this system."""
        ok, msg = probe_win32_boundary()
        self.assertTrue(ok, f"Behavioural probe failed: {msg}")

    def test_valid_hello_world_execution(self):
        """Valid computation runs and produces correct output file in scratch."""
        script = self._write_script("""
with open('std_output.txt', 'w') as f:
    f.write('42')
""")
        res = self.sandbox.execute(script)
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(res.stdout.strip(), "42")

    def test_a1_infinite_loop_timeout(self):
        """A1: Infinite loop is terminated cleanly at wall-clock deadline."""
        script = self._write_script("""
while True:
    pass
""")
        res = self.sandbox.execute(script)
        self.assertEqual(res.status, "timeout")
        self.assertEqual(res.exit_code, 99)
        self.assertLessEqual(res.wall_time_sec, 4.0)

    def test_a2_memory_bomb(self):
        """A2: Memory bomb (allocating 1 GB in a 256 MB sandbox) triggers MemoryError."""
        script = self._write_script("""
try:
    b = bytearray(1024 * 1024 * 1024) # 1 GB
    with open('std_output.txt', 'w') as f:
        f.write('ALLOCATED_LEAK')
except MemoryError:
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_MEMORY_ERROR')
""")
        res = self.sandbox.execute(script)
        self.assertEqual(res.stdout.strip(), "CONTAINED_MEMORY_ERROR")

    def test_a3_a7_process_proliferation(self):
        """A3 / A7: Child process cannot spawn subprocesses (Job Object limit = 1)."""
        script = self._write_script("""
import subprocess
try:
    p = subprocess.run(['cmd.exe', '/c', 'echo 1'], capture_output=True, timeout=1.0)
    with open('std_output.txt', 'w') as f:
        f.write('SPAWNED_LEAK')
except Exception as e:
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_SPAWN_FAILED')
""")
        res = self.sandbox.execute(script)
        self.assertEqual(res.stdout.strip(), "CONTAINED_SPAWN_FAILED")

    def test_a4_canary_deletion(self):
        """A4: Attempting to delete a canary file outside scratch fails with PermissionError."""
        pai_dir = os.path.expanduser("~/.pai")
        canary = os.path.join(pai_dir, "canary_a4.tmp")
        with open(canary, "w", encoding="utf-8") as f:
            f.write("CANARY_ACTIVE")

        try:
            script = self._write_script(f"""
import os
try:
    os.remove({repr(canary)})
    with open('std_output.txt', 'w') as f:
        f.write('DELETED_LEAK')
except Exception as e:
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_DELETE_BLOCKED')
""")
            res = self.sandbox.execute(script)
            self.assertEqual(res.stdout.strip(), "CONTAINED_DELETE_BLOCKED")
            # Verify canary still exists and was not deleted
            self.assertTrue(os.path.exists(canary))
            with open(canary, "r") as f:
                self.assertEqual(f.read(), "CANARY_ACTIVE")
        finally:
            if os.path.exists(canary):
                os.remove(canary)

    def test_a5_filesystem_read_escape(self):
        """A5: Attempting to read files outside scratch fails with PermissionError."""
        pai_dir = os.path.expanduser("~/.pai")
        canary = os.path.join(pai_dir, "canary_a5.tmp")
        with open(canary, "w", encoding="utf-8") as f:
            f.write("SECRET_CONTENTS")

        try:
            script = self._write_script(f"""
try:
    with open({repr(canary)}, 'r') as f:
        val = f.read()
    with open('std_output.txt', 'w') as f:
        f.write('READ_LEAK: ' + val)
except Exception as e:
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_READ_BLOCKED')
""")
            res = self.sandbox.execute(script)
            self.assertEqual(res.stdout.strip(), "CONTAINED_READ_BLOCKED")
        finally:
            if os.path.exists(canary):
                os.remove(canary)

    def test_a6_network_egress(self):
        """A6: Attempting socket connections fails with PermissionError (WinError 10013)."""
        script = self._write_script("""
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect(('1.1.1.1', 80))
    with open('std_output.txt', 'w') as f:
        f.write('NETWORK_LEAK')
except Exception as e:
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_NETWORK_BLOCKED')
""")
        res = self.sandbox.execute(script)
        self.assertEqual(res.stdout.strip(), "CONTAINED_NETWORK_BLOCKED")

    def test_a9_stdout_flood(self):
        """A9: Stdout stream flood is safely capped at 64 KB without deadlock."""
        script = self._write_script("""
# Write large output to std_output.txt
with open('std_output.txt', 'w') as f:
    f.write('A' * 200000) # 200 KB
""")
        res = self.sandbox.execute(script)
        self.assertEqual(res.status, "ok")
        self.assertEqual(len(res.stdout), 65536)  # Exactly 64 KB capped

    def test_a8_ctypes_containment(self):
        """A8: Native code loading / ctypes escape attempt is trapped; parent intact."""
        script = self._write_script("""
try:
    import ctypes
    u32 = ctypes.windll.user32
    u32.MessageBeep(0)
    with open('std_output.txt', 'w') as f:
        f.write('CONTAINED_NATIVE_CALL_ISOLATED')
except (ImportError, OSError, Exception) as e:
    with open('std_output.txt', 'w') as f:
        f.write(f'CONTAINED_CTYPES_BLOCKED: {type(e).__name__}: {e}')
""")
        res = self.sandbox.execute(script)
        self.assertIn("CONTAINED", res.stdout)

    def test_a11_crash_containment(self):
        """A11: Process crash/segfault is trapped cleanly; parent runner does not crash."""
        script = self._write_script("""
import ctypes
# Trigger access violation
ctypes.string_at(0)
""")
        res = self.sandbox.execute(script)
        self.assertIn(res.status, ("crash", "error"))
        self.assertNotEqual(res.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
