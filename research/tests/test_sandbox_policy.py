import json
import os
import tempfile
import unittest

import _bootstrap  # noqa: F401
from sandbox_policy import SandboxSpec, make_wsb, read_sandbox_results, validate_wsb

SPEC = SandboxSpec(r"C:\work\candidate", r"C:\work\out", r"python C:\pai\input\run_tests.py")


class Wsb(unittest.TestCase):
    def test_generated_config_passes_its_own_validator(self):
        self.assertEqual(validate_wsb(make_wsb(SPEC)), [])

    def test_memory_ceiling_enforced_at_generation(self):
        with self.assertRaises(ValueError):
            make_wsb(SandboxSpec("a", "b", "c", memory_mb=8192))

    def mutated(self, old, new):
        xml = make_wsb(SPEC)
        self.assertIn(old, xml)
        return validate_wsb(xml.replace(old, new))

    def test_networking_enabled_rejected(self):
        self.assertTrue(any("Networking" in x for x in self.mutated("<Networking>Disable", "<Networking>Default")))

    def test_each_isolation_setting_is_mandatory(self):
        for name in ("VGpu", "AudioInput", "VideoInput", "PrinterRedirection", "ClipboardRedirection"):
            self.assertTrue(self.mutated(f"<{name}>Disable", f"<{name}>Enable"), name)
        self.assertTrue(self.mutated("<ProtectedClient>Enable", "<ProtectedClient>Disable"))

    def test_missing_networking_element_rejected(self):
        xml = make_wsb(SPEC).replace("  <Networking>Disable</Networking>\n", "")
        self.assertTrue(any("exactly once" in x for x in validate_wsb(xml)))

    def test_duplicate_override_rejected(self):
        xml = make_wsb(SPEC).replace("</Configuration>", "<Networking>Default</Networking></Configuration>")
        self.assertTrue(validate_wsb(xml))

    def test_input_must_be_read_only(self):
        xml = make_wsb(SPEC).replace("<ReadOnly>true</ReadOnly>", "<ReadOnly>false</ReadOnly>")
        self.assertTrue(any("writable" in x for x in validate_wsb(xml)))

    def test_drive_and_profile_roots_forbidden(self):
        for host in ("C:\\", "C:", "C:\\Users\\hp", "C:\\Windows"):
            xml = make_wsb(SandboxSpec(host, r"C:\work\out", "cmd"))
            self.assertTrue(any("root" in x for x in validate_wsb(xml)), host)

    def test_unknown_elements_fail_closed(self):
        xml = make_wsb(SPEC).replace("</Configuration>", "<SomeFutureNetworkMode>On</SomeFutureNetworkMode></Configuration>")
        self.assertTrue(any("unknown element" in x for x in validate_wsb(xml)))

    def test_xml_tricks_and_garbage(self):
        self.assertTrue(validate_wsb('<!DOCTYPE x [<!ENTITY a "b">]><Configuration/>'))
        self.assertTrue(validate_wsb("not xml"))
        self.assertTrue(validate_wsb("<Other/>"))
        self.assertTrue(validate_wsb("<Configuration>" + "x" * 70000 + "</Configuration>"))

    def test_command_is_escaped(self):
        xml = make_wsb(SandboxSpec("C:\\a\\b", "C:\\a\\c", "cmd /c a & b <x>"))
        self.assertEqual(validate_wsb(xml), [])
        self.assertNotIn("<x>", xml)


class Results(unittest.TestCase):
    GOOD = {"tests_passed": 10, "tests_failed": 0, "benchmark_ms": 12.5, "stdout_tail": "ok"}

    def dir_with(self, files):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        for name, content in files.items():
            with open(os.path.join(d.name, name), "wb") as f:
                f.write(content if isinstance(content, bytes) else json.dumps(content).encode())
        return d.name

    def test_valid(self):
        self.assertEqual(read_sandbox_results(self.dir_with({"results.json": self.GOOD}))["tests_passed"], 10)

    def test_extra_files_rejected(self):
        with self.assertRaises(ValueError):
            read_sandbox_results(self.dir_with({"results.json": self.GOOD, "payload.exe": b"MZ"}))

    def test_wrong_schema_types_and_extra_keys(self):
        for bad in ({**self.GOOD, "extra": 1}, {**self.GOOD, "tests_passed": "10"}, {**self.GOOD, "tests_passed": True},
                    {**self.GOOD, "tests_failed": -1}, [1, 2], {"tests_passed": 1}):
            with self.assertRaises(ValueError, msg=str(bad)):
                read_sandbox_results(self.dir_with({"results.json": bad}))

    def test_oversize_and_garbage(self):
        with self.assertRaises(ValueError):
            read_sandbox_results(self.dir_with({"results.json": b" " * (256 * 1024 + 1)}))
        with self.assertRaises(ValueError):
            read_sandbox_results(self.dir_with({"results.json": b"\xff\xfe not json"}))

    def test_stdout_tail_truncated(self):
        out = read_sandbox_results(self.dir_with({"results.json": {**self.GOOD, "stdout_tail": "x" * 10000}}))
        self.assertEqual(len(out["stdout_tail"]), 4096)

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_symlinked_results_rejected(self):
        d = self.dir_with({})
        target = os.path.join(tempfile.gettempdir(), "pai_secret_target.json")
        with open(target, "w") as f:
            json.dump(self.GOOD, f)
        try:
            os.symlink(target, os.path.join(d, "results.json"))
            with self.assertRaises(ValueError):
                read_sandbox_results(d)
        finally:
            os.unlink(target)


if __name__ == "__main__":
    unittest.main()
