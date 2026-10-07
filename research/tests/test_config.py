"""
Unit Tests for Configuration and Machine Profile Management (Milestone M1c / ADR-010)
Validates:
1. Threat T22: Detection and immediate rejection of secrets in user configuration.
2. Threat T26: Strict schema validation and profile tampering detection.
3. Clean save/load roundtrips for config.json and machine_profile.json.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    load_machine_profile,
    load_user_config,
    save_machine_profile,
    save_user_config,
    validate_machine_profile,
    validate_user_config,
)


class TestConfigSecurity(unittest.TestCase):
    def test_t22_rejects_credentials_in_config(self):
        """Threat T22: Rejects any configuration containing secret or credential fields."""
        malicious_configs = [
            {"schema_version": 1, "api_key": "sk-12345"},
            {"schema_version": 1, "anthropic_token": "secret"},
            {"schema_version": 1, "openai_secret": "xyz"},
            {"schema_version": 1, "password": "admin"},
            {"schema_version": 1, "allowed_models": ["gpt-4"], "auth": "bearer"},
        ]
        for cfg in malicious_configs:
            valid, err = validate_user_config(cfg)
            self.assertFalse(valid, f"Config {cfg} should be rejected (T22)")
            self.assertTrue(
                "Forbidden secret" in err or "Unknown" in err,
                f"Error message did not mention security concern: {err}",
            )

    def test_t26_rejects_unknown_keys_in_user_config(self):
        """Threat T26: User configuration fails closed on unknown keys."""
        cfg = {
            "schema_version": 1,
            "allowed_models": ["qwen2.5-coder:1.5b"],
            "unrecognized_arbitrary_key": True,
        }
        valid, err = validate_user_config(cfg)
        self.assertFalse(valid)
        self.assertIn("Unknown configuration keys rejected", err)

    def test_t26_rejects_unknown_keys_in_machine_profile(self):
        """Threat T26: Machine profile fails closed on unknown keys."""
        prof = {
            "schema_version": 1,
            "machine_id": "box_1",
            "total_ram_gb": 16.0,
            "cpu_cores": 8,
            "untrusted_field": "injected",
            "calibrated_profiles": {},
        }
        valid, err = validate_machine_profile(prof)
        self.assertFalse(valid)
        self.assertIn("Unknown machine profile keys rejected", err)

    def test_t26_tampered_machine_profile_ram_discrepancy(self):
        """Threat T26: Flags machine profile claiming impossible RAM compared to live hardware."""
        prof = {
            "schema_version": 1,
            "machine_id": "box_1",
            "total_ram_gb": 64.0,  # Claims 64 GB
            "cpu_cores": 8,
            "calibrated_profiles": {},
        }
        # Live system only has 16.0 GB (divergence = 300% > 35%)
        valid, err = validate_machine_profile(prof, live_total_ram_gb=16.0)
        self.assertFalse(valid)
        self.assertIn("Tampered machine profile detected", err)

    def test_machine_profile_delta_exceeding_total_ram_rejected(self):
        """Model delta cannot exceed total machine RAM."""
        prof = {
            "schema_version": 1,
            "machine_id": "box_1",
            "total_ram_gb": 8.0,
            "cpu_cores": 4,
            "calibrated_profiles": {
                "huge_model": {
                    "host_delta_mb": 20000.0,  # 20 GB on 8 GB machine
                }
            },
        }
        valid, err = validate_machine_profile(prof)
        self.assertFalse(valid)
        self.assertIn("exceeds machine total RAM", err)

    def test_clean_save_load_roundtrips(self):
        """Valid configurations save and reload without schema degradation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.json")
            cfg_data = {
                "schema_version": 1,
                "allowed_models": ["qwen2.5-coder:7b", "llama3.2:3b"],
                "preferred_models": {"code": "qwen2.5-coder:7b"},
                "privacy_mode": "local-only",
            }
            save_user_config(cfg_data, cfg_path)
            loaded_cfg = load_user_config(cfg_path)
            self.assertEqual(loaded_cfg, cfg_data)

            prof_path = os.path.join(tmpdir, "machine_profile.json")
            prof_data = {
                "schema_version": 1,
                "machine_id": "laptop_alpha",
                "total_ram_gb": 16.0,
                "cpu_cores": 12,
                "calibrated_profiles": {
                    "qwen2.5-coder:7b": {"host_delta_mb": 1300.0}
                },
            }
            save_machine_profile(prof_data, prof_path)
            loaded_prof = load_machine_profile(prof_path, live_total_ram_gb=16.0)
            self.assertEqual(loaded_prof, prof_data)


if __name__ == "__main__":
    unittest.main()
