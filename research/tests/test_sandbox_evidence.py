"""
Evidence File and Schema Verification Tests (Milestone M2a / ADR-011 v2.1)

Validates that:
1. docs/evidence/m2a_sandbox_results.json conforms strictly to the schema produced
   by research/run_m2a_matrix.py.
2. Platform metadata is programmatically extracted (e.g. bwrap --version on Linux,
   Windows version on Windows) and matches get_platform_metadata().
3. All adversarial attack vectors in the matrix pass with CONTAINED containment state.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from run_m2a_matrix import get_platform_metadata


class TestSandboxEvidenceSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence_path = os.path.join(os.path.dirname(ROOT_DIR), "docs", "evidence", "m2a_sandbox_results.json")
        cls.raw_log_path = os.path.join(os.path.dirname(ROOT_DIR), "docs", "evidence", "m2a_sandbox_raw.log")

    def test_evidence_file_exists_and_parses(self):
        """Verifies that m2a_sandbox_results.json exists and contains valid JSON."""
        self.assertTrue(os.path.exists(self.evidence_path), f"Evidence JSON not found at: {self.evidence_path}")
        with open(self.evidence_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("milestone"), "M2a")

    def test_platform_metadata_function_contract(self):
        """Verifies get_platform_metadata() extracts required fields for the running host."""
        meta = get_platform_metadata()
        self.assertIn("system", meta)
        self.assertIn("release", meta)
        self.assertIn("architecture", meta)
        self.assertIn("python_version", meta)
        self.assertIn("compiler", meta)

        if sys.platform.startswith("linux"):
            self.assertIn("distro", meta)
            self.assertIn("bwrap_version", meta)
            self.assertIn("sandbox_technology", meta)
            bwrap_bin = shutil.which("bwrap")
            if bwrap_bin:
                proc = subprocess.run([bwrap_bin, "--version"], capture_output=True, text=True, timeout=2.0)
                if proc.returncode == 0:
                    expected_ver = proc.stdout.strip()
                    self.assertEqual(meta["bwrap_version"], expected_ver)
        elif sys.platform == "win32":
            self.assertIn("windows_version", meta)
            self.assertIn("sandbox_technology", meta)
            self.assertEqual(meta["windows_version"], platform.version())

    def test_evidence_json_schema_and_platform_fields(self):
        """Verifies that all recorded platforms in the evidence JSON follow the runner schema."""
        with open(self.evidence_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("platforms", data)
        self.assertIsInstance(data["platforms"], dict)
        self.assertGreaterEqual(len(data["platforms"]), 1, "At least one platform entry must exist")

        expected_vectors = {"PROBE", "A1", "A2", "A3_A7", "A4", "A5", "A6", "A8", "A9", "A11"}

        for plat_name, plat_entry in data["platforms"].items():
            self.assertIn("platform", plat_entry, f"Missing platform block in {plat_name}")
            p_meta = plat_entry["platform"]

            # Universal platform fields
            for req_key in ["system", "release", "architecture", "python_version", "compiler"]:
                self.assertIn(req_key, p_meta, f"Missing '{req_key}' in platform {plat_name}")

            # Platform-specific fields
            if p_meta["system"] == "Linux":
                self.assertIn("distro", p_meta)
                self.assertIn("bwrap_version", p_meta)
            elif p_meta["system"] == "Windows":
                self.assertIn("windows_version", p_meta)
                self.assertIn("sandbox_technology", p_meta)

            # Summary verification
            self.assertIn("summary", plat_entry)
            summary = plat_entry["summary"]
            self.assertEqual(summary["total_vectors"], 10)
            self.assertEqual(summary["passed"], 10)
            self.assertEqual(summary["failed"], 0)
            self.assertEqual(summary["success_rate_pct"], 100.0)

            # Adversarial vectors verification
            self.assertIn("adversarial_containment_matrix", plat_entry)
            matrix = plat_entry["adversarial_containment_matrix"]
            self.assertEqual(set(matrix.keys()), expected_vectors)

            for vec_id, vec_data in matrix.items():
                self.assertEqual(vec_data["status"], "PASS")
                self.assertEqual(vec_data["containment_state"], "CONTAINED")
                self.assertGreater(vec_data["wall_time_ms"], 0)
                self.assertTrue(len(vec_data["detail"]) > 0)

                # Positive marker verification per vector (rejects vacuous passes)
                if vec_id in ("A2", "A3_A7", "A4", "A5", "A6", "A8"):
                    self.assertIn("CONTAINED", vec_data["stdout_sample"], f"Vector {vec_id} must have CONTAINED marker")
                    if vec_id == "A8":
                        self.assertIn("POSITIVE_CONTROL_NATIVE_OK", vec_data["stdout_sample"], "Vector A8 must verify positive control")
                elif vec_id == "A9":
                    self.assertIn("FLOOD_MARKER_START", vec_data["stdout_sample"], "Vector A9 must have FLOOD_MARKER_START")
                elif vec_id == "A1":
                    self.assertIn(vec_data["exit_code"], (99, -9, 137), "Vector A1 must terminate on timeout signal")
                elif vec_id == "A11":
                    self.assertNotEqual(vec_data["exit_code"], 0, "Vector A11 must record non-zero crash exit code")

    def test_raw_log_exists_and_contains_header(self):
        """Verifies that m2a_sandbox_raw.log exists and contains a valid harness banner."""
        self.assertTrue(os.path.exists(self.raw_log_path), f"Raw log not found at: {self.raw_log_path}")
        with open(self.raw_log_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("PAI MILESTONE M2a ADVERSARIAL MATRIX HARNESS", content)
        self.assertIn("M2a MATRIX RUN COMPLETE: 10/10 vectors PASSED (100.0%)", content)


if __name__ == "__main__":
    unittest.main()
