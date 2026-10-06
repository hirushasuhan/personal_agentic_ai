"""
Telemetry Parity Test (VS3)
Part of Personal Agentic AI (PAI).

Validates parity between Python HardwareTelemetry and Rust pai-core --telemetry:
- Available RAM within ±5%
- Memory load percentage within ±3 points
- Identical tier assignment
- Schema v1 field matching
"""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hardware_telemetry import HardwareTelemetry



class TestTelemetryParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Locate pai-core executable
        repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        exe_path = os.path.join(repo_root, "core", "target", "debug", "pai-core.exe")
        if not os.path.exists(exe_path):
            # Try release if debug doesn't exist
            exe_path = os.path.join(repo_root, "core", "target", "release", "pai-core.exe")
        cls.exe_path = exe_path

    def test_rust_binary_exists(self):
        if sys.platform != "win32":
            self.skipTest("Win32 telemetry parity is Windows-specific")
        self.assertTrue(
            os.path.exists(self.exe_path),
            f"pai-core executable not found at {self.exe_path}. Run `cargo build` first.",
        )

    def test_telemetry_parity_live(self):
        if sys.platform != "win32":
            self.skipTest("Win32 telemetry parity is Windows-specific")
        if not os.path.exists(self.exe_path):
            self.skipTest("pai-core binary not built")

        # 1. Run Python telemetry
        py_telem = HardwareTelemetry(cpu_sample_ms=50)
        py_snap = py_telem.get_system_snapshot()

        # 2. Run Rust pai-core telemetry
        proc = subprocess.run(
            [self.exe_path, "--telemetry", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, f"pai-core failed: {proc.stderr}")
        rust_snap = json.loads(proc.stdout)

        # 3. Schema validation
        self.assertEqual(rust_snap.get("schema_version"), 1)
        self.assertEqual(rust_snap.get("platform"), "win32")
        self.assertEqual(rust_snap.get("source"), "win32-kernel32")
        self.assertEqual(rust_snap.get("cpu_cores"), py_snap.get("cpu_cores"))

        # 4. Total RAM parity (should be virtually identical)
        py_tot = py_snap.get("total_ram_gb")
        rust_tot = rust_snap.get("total_ram_gb")
        self.assertIsNotNone(py_tot)
        self.assertIsNotNone(rust_tot)
        self.assertAlmostEqual(py_tot, rust_tot, delta=0.1)

        # 5. Available RAM parity (within ±5%)
        py_avail = py_snap.get("avail_ram_mb")
        rust_avail = rust_snap.get("avail_ram_mb")
        self.assertIsNotNone(py_avail)
        self.assertIsNotNone(rust_avail)
        margin_mb = py_avail * 0.05
        diff_mb = abs(py_avail - rust_avail)
        self.assertLessEqual(
            diff_mb,
            margin_mb,
            f"Available RAM drifted beyond ±5%: Python={py_avail}MB, Rust={rust_avail}MB (diff={diff_mb:.1f}MB, limit={margin_mb:.1f}MB)",
        )

        # 6. Memory load percent (within ±3 points)
        py_load = py_snap.get("memory_load_pct")
        rust_load = rust_snap.get("memory_load_pct")
        self.assertIsNotNone(py_load)
        self.assertIsNotNone(rust_load)
        self.assertLessEqual(
            abs(py_load - rust_load),
            3.0,
            f"Memory load drifted: Python={py_load}%, Rust={rust_load}%",
        )

        # 7. Battery parity
        py_batt = py_snap.get("battery")
        rust_batt = rust_snap.get("battery")
        if py_batt is not None and rust_batt is not None:
            if py_batt.get("percent") is not None and rust_batt.get("percent") is not None:
                self.assertLessEqual(
                    abs(py_batt["percent"] - rust_batt["percent"]),
                    1.0,
                )
            self.assertEqual(py_batt.get("on_ac"), rust_batt.get("on_ac"))

        # 8. Budget Tier parity
        py_tier = (
            py_snap["budget"].compute_tier
            if hasattr(py_snap["budget"], "compute_tier")
            else py_snap["budget"]["compute_tier"]
        )
        self.assertEqual(
            py_tier,
            rust_snap["budget"]["compute_tier"],
            "Compute tier mismatch between Python and Rust live telemetry",
        )



if __name__ == "__main__":
    unittest.main()
