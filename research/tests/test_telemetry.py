import unittest

import _bootstrap  # noqa: F401
import ctypes
from hardware_telemetry import (HardwareTelemetry, MEMORYSTATUSEX, SYSTEM_POWER_STATUS, CONTEXT_BYTES, MiB)


class TierPolicy(unittest.TestCase):
    def setUp(self):
        self.t = HardwareTelemetry(cpu_sample_ms=0)
        self.t.cpu_count = 8

    def tier(self, mb, load, cpu=None, battery=None):
        return self.t._calculate_budget(mb, load, cpu, battery)

    def test_high(self):
        b = self.tier(8000, 40)
        self.assertEqual(b.compute_tier, "HIGH")
        self.assertTrue(b.allow_speculation)
        self.assertEqual(b.thread_pool_limit, 8)
        self.assertEqual(b.max_context_bytes, CONTEXT_BYTES["HIGH"])

    def test_balanced_by_ram_and_by_load(self):
        self.assertEqual(self.tier(1500, 40).compute_tier, "BALANCED")
        self.assertEqual(self.tier(8000, 80).compute_tier, "BALANCED")
        self.assertFalse(self.tier(1500, 40).allow_speculation)
        self.assertEqual(self.tier(1500, 40).thread_pool_limit, 2)

    def test_compressed(self):
        for mb, load in ((300, 40), (8000, 95)):
            b = self.tier(mb, load)
            self.assertEqual(b.compute_tier, "COMPRESSED")
            self.assertEqual(b.thread_pool_limit, 1)
            self.assertEqual(b.max_context_bytes, 2 * MiB)

    def test_boundaries(self):
        self.assertEqual(self.tier(512, 10).compute_tier, "BALANCED")    # 512 is not < 512
        self.assertEqual(self.tier(2048, 10).compute_tier, "HIGH")
        self.assertEqual(self.tier(8000, 74).compute_tier, "HIGH")
        self.assertEqual(self.tier(8000, 75).compute_tier, "BALANCED")

    def test_low_battery_downgrades_and_disables_speculation(self):
        b = self.tier(8000, 40, battery={"percent": 10, "on_ac": False})
        self.assertEqual(b.compute_tier, "BALANCED")
        self.assertFalse(b.allow_speculation)
        self.assertIn("low-battery", b.reasons)

    def test_battery_on_ac_is_ignored(self):
        self.assertEqual(self.tier(8000, 40, battery={"percent": 5, "on_ac": True}).compute_tier, "HIGH")

    def test_saturated_cpu_halves_threads(self):
        b = self.tier(8000, 40, cpu=97)
        self.assertEqual(b.thread_pool_limit, 4)
        self.assertFalse(b.allow_speculation)

    def test_unknown_memory_is_conservative_not_invented(self):
        b = self.tier(None, None)
        self.assertEqual(b.compute_tier, "BALANCED")
        self.assertIn("memory-telemetry-unavailable", b.reasons)


class Snapshot(unittest.TestCase):
    def test_snapshot_shape_and_ipc_json(self):
        import json
        t = HardwareTelemetry(cpu_sample_ms=0)
        snap = t.get_system_snapshot()
        for k in ("schema_version", "source", "cpu_cores", "memory_load_pct", "battery", "budget"):
            self.assertIn(k, snap)
        json.dumps(HardwareTelemetry.to_ipc_dict(snap))  # must be serialisable

    def test_win32_struct_layouts_match_documented_sizes(self):
        self.assertEqual(ctypes.sizeof(MEMORYSTATUSEX), 64)
        self.assertEqual(ctypes.sizeof(SYSTEM_POWER_STATUS), 12)


if __name__ == "__main__":
    unittest.main()
