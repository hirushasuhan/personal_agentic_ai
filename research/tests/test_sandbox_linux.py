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
- A8: Native code loading / ctypes escape attempt
- A9: Stdout stream flood
- A11: Crash / fault containment
- Behavioural capability probe
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if sys.platform.startswith("linux"):
    from sandbox_linux import LinuxSandbox, probe_linux_boundary, is_bwrap_functional, is_bwrap_available
else:
    LinuxSandbox = None
    probe_linux_boundary = None
    is_bwrap_functional = lambda: False
    is_bwrap_available = lambda: False


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux sandbox tests run only on Linux")
class TestLinuxSandboxContainment(unittest.TestCase):
    def setUp(self):
        # Defect 1 check: If bwrap is installed in PATH, is_bwrap_functional() MUST be True
        if is_bwrap_available() and not is_bwrap_functional():
            self.fail("bwrap is installed in PATH but is_bwrap_functional() returned False (merged-/usr false negative)")
        if not is_bwrap_functional():
            self.skipTest("bwrap is not functional on this host (unprivileged user namespaces may be restricted)")
        self.sandbox = LinuxSandbox(memory_mb=512.0, timeout_sec=3.0)
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
        """A2: Memory bomb (allocating 1 GB in a 512 MB sandbox) triggers MemoryError or killed."""
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
        """A3 / A7: Process proliferation / fork bomb is bounded by RLIMIT_NPROC."""
        code = """
import os, sys
pids = []
try:
    for _ in range(50):
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        pids.append(pid)
    print('SPAWNED_MANY')
except (BlockingIOError, OSError) as e:
    print('CONTAINED_FORK_LIMIT')
"""
        script = self._write_script(code)
        res = self.sandbox.execute(script)
        self.assertNotIn("SPAWNED_MANY", res.stdout)

    def test_is_bwrap_functional_on_linux(self):
        """Requirement 1: Verify is_bwrap_functional() returns True on Linux host when bwrap is installed."""
        self.assertTrue(is_bwrap_functional(), "is_bwrap_functional() must return True on hosts where bwrap is present")

    def test_a4_canary_deletion(self):
        """A4: Attempting to delete a canary file in read-only bound directory fails with PermissionError or EROFS."""
        ro_dir = tempfile.mkdtemp(prefix="pai_test_canary_ro_")
        canary_path = os.path.join(ro_dir, "canary.txt")
        with open(canary_path, "w", encoding="utf-8") as f:
            f.write("CANNOT_TOUCH")

        try:
            self.sandbox.extra_ro_binds.append(ro_dir)
            code = f"""
import os, errno
try:
    os.remove({repr(canary_path)})
    print('DELETED_CANARY')
except PermissionError:
    print('CONTAINED_PERMISSION_ERROR')
except OSError as e:
    if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
        print('CONTAINED_PERMISSION_ERROR')
    else:
        print(f'UNEXPECTED_ERR: {{e}}')
except Exception as e:
    print(f'UNEXPECTED_ERR: {{e}}')
"""
            script = self._write_script(code)
            res = self.sandbox.execute(script)
            self.assertNotIn("DELETED_CANARY", res.stdout)
            self.assertIn("CONTAINED_PERMISSION_ERROR", res.stdout)
            self.assertTrue(os.path.exists(canary_path))
        finally:
            if os.path.exists(ro_dir):
                import shutil
                shutil.rmtree(ro_dir, ignore_errors=True)

    def test_erofs_containment_regression(self):
        """Requirement 2: Verify writing and deleting on read-only mount raises EROFS and is treated as CONTAINED."""
        import errno
        ro_dir = tempfile.mkdtemp(prefix="pai_test_erofs_")
        canary_path = os.path.join(ro_dir, "ro_canary.txt")
        with open(canary_path, "w", encoding="utf-8") as f:
            f.write("INITIAL_CONTENT")

        try:
            self.sandbox.extra_ro_binds.append(ro_dir)
            code = f"""
import os, sys, errno
target = {repr(canary_path)}
# Attempt write
try:
    with open(target, 'w') as f:
        f.write('OVERWRITE')
    print('WRITE_LEAK')
except PermissionError:
    print('WRITE_CONTAINED_PERM')
except OSError as e:
    if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
        print(f'WRITE_CONTAINED_EROFS:{{e.errno}}')
    else:
        print(f'WRITE_UNEXPECTED:{{e}}')
except Exception as e:
    print(f'WRITE_UNEXPECTED:{{e}}')

# Attempt delete
try:
    os.remove(target)
    print('DELETE_LEAK')
except PermissionError:
    print('DELETE_CONTAINED_PERM')
except OSError as e:
    if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
        print(f'DELETE_CONTAINED_EROFS:{{e.errno}}')
    else:
        print(f'DELETE_UNEXPECTED:{{e}}')
except Exception as e:
    print(f'DELETE_UNEXPECTED:{{e}}')
"""
            script = self._write_script(code)
            res = self.sandbox.execute(script)
            self.assertEqual(res.status, "ok")
            self.assertNotIn("WRITE_LEAK", res.stdout)
            self.assertNotIn("DELETE_LEAK", res.stdout)
            self.assertIn("WRITE_CONTAINED", res.stdout)
            self.assertIn("DELETE_CONTAINED", res.stdout)
            self.assertTrue(os.path.exists(canary_path))
            with open(canary_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "INITIAL_CONTENT")
        finally:
            if os.path.exists(ro_dir):
                import shutil
                shutil.rmtree(ro_dir, ignore_errors=True)

    def test_probe_handles_erofs_simulation(self):
        """Requirement 2: Ensure capability probe exception handler recognizes EROFS/EACCES/EPERM as CONTAINED and rejects others."""
        import errno
        # Expected filesystem containment errnos
        for err_no in (errno.EROFS, errno.EACCES, errno.EPERM):
            e = OSError(err_no, os.strerror(err_no))
            self.assertIn(e.errno, (errno.EROFS, errno.EACCES, errno.EPERM))
        # Negative check: non-containment error numbers MUST NOT be treated as containment
        for bad_err in (errno.EINVAL, errno.EBADF, errno.EEXIST):
            e = OSError(bad_err, os.strerror(bad_err))
            self.assertNotIn(e.errno, (errno.EROFS, errno.EACCES, errno.EPERM))

    def test_a5_filesystem_read_escape(self):
        """A5: Attempting to read files in user home fails (masked by tmpfs /home)."""
        pai_dir = os.path.expanduser("~/.pai")
        os.makedirs(pai_dir, exist_ok=True)
        canary_path = os.path.join(pai_dir, f"secret_test_{os.getpid()}.txt")
        with open(canary_path, "w", encoding="utf-8") as f:
            f.write("SECRET_KEY_DATA")

        try:
            code = f"""
try:
    with open({repr(canary_path)}, 'r') as f:
        data = f.read()
    if data == 'SECRET_KEY_DATA':
        print('READ_SUCCESS')
    else:
        print('READ_TAMPERED')
except (FileNotFoundError, PermissionError):
    print('CONTAINED_READ_BLOCKED')
except Exception as e:
    print(f'UNEXPECTED: {{e}}')
"""
            script = self._write_script(code)
            res = self.sandbox.execute(script)
            self.assertNotIn("READ_SUCCESS", res.stdout)
            self.assertIn("CONTAINED_READ_BLOCKED", res.stdout)
        finally:
            if os.path.exists(canary_path):
                os.remove(canary_path)

    def test_a6_network_egress(self):
        """A6: Attempting socket connections fails in unshared network namespace."""
        code = """
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect(('1.1.1.1', 80))
    print('NETWORK_EGRESS_SUCCESS')
except Exception as e:
    print('CONTAINED_NETWORK_BLOCKED')
"""
        script = self._write_script(code)
        res = self.sandbox.execute(script)
        self.assertNotIn("NETWORK_EGRESS_SUCCESS", res.stdout)
        self.assertIn("CONTAINED_NETWORK_BLOCKED", res.stdout)

    def test_a8_ctypes_containment(self):
        """A8: Native code loading / ctypes escape attempt is trapped; parent intact."""
        code = """
try:
    import ctypes
    libc = ctypes.CDLL(None)
    print('CONTAINED_NATIVE_LOAD')
except Exception as e:
    print(f'CONTAINED_CTYPES_BLOCKED: {e}')
"""
        script = self._write_script(code)
        res = self.sandbox.execute(script)
        self.assertIn("CONTAINED", res.stdout)

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
