"""
Adversarial Containment Matrix Tests for Linux Bubblewrap Sandbox
(Milestone M2a / ADR-011 v2.1)

Validates the full adversarial attack containment matrix on Linux:
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
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if sys.platform.startswith("linux"):
    from sandbox_linux import LinuxSandbox, probe_linux_boundary, is_bwrap_available
else:
    LinuxSandbox = None
    probe_linux_boundary = None
    is_bwrap_available = lambda: False


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux sandbox tests run only on Linux")
class TestLinuxSandboxContainment(unittest.TestCase):
    def setUp(self):
        if not is_bwrap_available():
            self.skipTest("bwrap (bubblewrap) executable not found in PATH")
        self.sandbox = LinuxSandbox(memory_mb=256.0, timeout_sec=3.0)
        self.sandbox.setup()

    def tearDown(self):
        if hasattr(self, "sandbox"):
            self.sandbox.cleanup()

    def _write_script(self, code: str) -> str:
        path = os.path.join(self.sandbox.scratch_dir, "test_target.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        return path

    def test_behavioural_capability_probe(self):
        """Verifies that the live behavioural canary probe passes on this Linux system."""
        ok, msg = probe_linux_boundary()
        self.assertTrue(ok, f"Behavioural probe failed: {msg}")

    def test_valid_hello_world_execution(self):
        """Valid computation runs and produces correct output file in scratch."""
        code = """
with open('result.txt', 'w') as f:
    f.write('SANDBOX_SUCCESS')
print('HELLO_FROM_LINUX_SANDBOX')
"""
        script = self._write_script(code)
        res = self.sandbox.execute(script)
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.exit_code, 0)
        self.assertIn("HELLO_FROM_LINUX_SANDBOX", res.stdout)
        self.assertIn("result.txt", res.output_files)
        self.assertEqual(res.output_files["result.txt"], "SANDBOX_SUCCESS")

    def test_a1_infinite_loop_timeout(self):
        """A1: Infinite loop is terminated cleanly at wall-clock deadline."""
        code = """
import time
while True:
    time.sleep(0.01)
"""
        script = self._write_script(code)
        res = self.sandbox.execute(script)
        self.assertEqual(res.status, "timeout")
        self.assertIn("Execution timed out", res.stderr)

    def test_a2_memory_bomb(self):
        """A2: Memory bomb (allocating 1 GB in a 256 MB sandbox) triggers MemoryError or killed."""
        code = """
chunk = []
for _ in range(100):
    chunk.append(bytearray(20 * 1024 * 1024))
print('ALLOCATED_TOO_MUCH')
"""
        script = self._write_script(code)
        res = self.sandbox.execute(script)
        self.assertNotEqual(res.exit_code, 0)
        self.assertNotIn("ALLOCATED_TOO_MUCH", res.stdout)

    def test_a3_a7_process_proliferation(self):
        """A3 / A7: Child process cannot spawn subprocesses."""
        code = """
import subprocess
try:
    r = subprocess.run(['echo', 'child'], capture_output=True)
    print('SPAWNED_SUBPROCESS')
except Exception as e:
    print(f'CAUGHT_EXPECTED: {e}')
"""
        script = self._write_script(code)
        res = self.sandbox.execute(script)
        self.assertNotIn("SPAWNED_SUBPROCESS", res.stdout)

    def test_a4_canary_deletion(self):
        """A4: Attempting to delete a canary file outside scratch fails."""
        canary_path = os.path.join("/tmp", f"canary_delete_{os.getpid()}.txt")
        with open(canary_path, "w", encoding="utf-8") as f:
            f.write("CANNOT_TOUCH")

        try:
            code = f"""
import os
try:
    os.remove({repr(canary_path)})
    print('DELETED_CANARY')
except Exception as e:
    print('PROTECTED_OK')
"""
            script = self._write_script(code)
            res = self.sandbox.execute(script)
            self.assertNotIn("DELETED_CANARY", res.stdout)
            self.assertTrue(os.path.exists(canary_path))
        finally:
            if os.path.exists(canary_path):
                os.remove(canary_path)

    def test_a5_filesystem_read_escape(self):
        """A5: Attempting to read files outside scratch fails."""
        canary_path = os.path.join(os.path.expanduser("~"), f"secret_{os.getpid()}.txt")
        with open(canary_path, "w", encoding="utf-8") as f:
            f.write("SECRET_KEY_DATA")

        try:
            code = f"""
try:
    with open({repr(canary_path)}, 'r') as f:
        data = f.read()
    print('READ_SUCCESS')
except Exception as e:
    print('READ_BLOCKED')
"""
            script = self._write_script(code)
            res = self.sandbox.execute(script)
            self.assertNotIn("READ_SUCCESS", res.stdout)
        finally:
            if os.path.exists(canary_path):
                os.remove(canary_path)

    def test_a6_network_egress(self):
        """A6: Attempting socket connections fails."""
        code = """
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    s.connect(('1.1.1.1', 80))
    print('NETWORK_EGRESS_SUCCESS')
except Exception as e:
    print('NETWORK_EGRESS_BLOCKED')
"""
        script = self._write_script(code)
        res = self.sandbox.execute(script)
        self.assertNotIn("NETWORK_EGRESS_SUCCESS", res.stdout)

    def test_a9_stdout_flood(self):
        """A9: Stdout stream flood is safely capped at 64 KB without deadlock."""
        code = """
import sys
for _ in range(50000):
    print("A" * 100)
"""
        script = self._write_script(code)
        res = self.sandbox.execute(script)
        self.assertLessEqual(len(res.stdout), 65536)

    def test_a11_crash_containment(self):
        """A11: Process crash/segfault is trapped cleanly; parent runner does not crash."""
        code = """
import ctypes
# Trigger immediate segfault
ctypes.string_at(0)
"""
        script = self._write_script(code)
        res = self.sandbox.execute(script)
        self.assertNotEqual(res.exit_code, 0)
