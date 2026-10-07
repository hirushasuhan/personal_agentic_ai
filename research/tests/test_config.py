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

    def test_t22_secret_patterns_in_values_rejected(self):
        """Threat T22: Rejects forbidden secret patterns inside configuration values."""
        malicious_value_configs = [
            {"schema_version": 1, "allowed_models": ["sk-1234567890abcdef1234567890"]},
            {"schema_version": 1, "allowed_models": ["ghp_1234567890abcdef1234567890abcdef1234"]},
            {"schema_version": 1, "preferred_models": {"code": "Bearer my_super_secret_token"}},
            {"schema_version": 1, "allowed_models": ["custom_model?api_key=secret123"]},
        ]
        for cfg in malicious_value_configs:
            valid, err = validate_user_config(cfg)
            self.assertFalse(valid, f"Value with secret {cfg} should be rejected")
            self.assertIn("Forbidden secret", err)

    def test_spend_caps_and_enabled_providers_validation(self):
        """Validates types and ranges for spend_caps and enabled_providers."""
        # Negative spend cap rejected
        cfg_neg = {"schema_version": 1, "spend_caps": {"openai": -10.0}}
        valid, err = validate_user_config(cfg_neg)
        self.assertFalse(valid)
        self.assertIn("non-negative number", err)

        # Non-numeric spend cap rejected
        cfg_str_cap = {"schema_version": 1, "spend_caps": {"openai": "unlimited"}}
        valid, err = validate_user_config(cfg_str_cap)
        self.assertFalse(valid)
        self.assertIn("non-negative number", err)

        # Valid spend cap accepted
        cfg_ok_cap = {"schema_version": 1, "spend_caps": {"openai": 25.50}}
        valid, err = validate_user_config(cfg_ok_cap)
        self.assertTrue(valid)

        # Non-string item in enabled_providers rejected
        cfg_bad_prov = {"schema_version": 1, "enabled_providers": [123]}
        valid, err = validate_user_config(cfg_bad_prov)
        self.assertFalse(valid)
        self.assertIn("must be strings", err)

        # Valid enabled_providers accepted
        cfg_ok_prov = {"schema_version": 1, "enabled_providers": ["ollama", "local"]}
        valid, err = validate_user_config(cfg_ok_prov)
        self.assertTrue(valid)

    def test_privacy_mode_allow_cloud_rejected_until_m1d(self):
        """privacy_mode: allow-cloud is strictly rejected until M1d."""
        cfg_cloud = {"schema_version": 1, "privacy_mode": "allow-cloud"}
        valid, err = validate_user_config(cfg_cloud)
        self.assertFalse(valid)
        self.assertIn("cloud providers not implemented until Milestone M1d", err)

        cfg_local = {"schema_version": 1, "privacy_mode": "local-only"}
        valid, err = validate_user_config(cfg_local)
        self.assertTrue(valid)

    def test_foreign_machine_id_and_os_rejected(self):
        """Rejects machine profile calibrated on a different machine or OS."""
        prof = {
            "schema_version": 1,
            "machine_id": "alien_workstation_456",
            "os": "Linux 6.8",
            "total_ram_gb": 16.0,
            "cpu_cores": 8,
            "calibrated_profiles": {},
        }
        # Machine ID mismatch
        valid, err = validate_machine_profile(
            prof,
            live_total_ram_gb=16.0,
            live_machine_id="local_laptop_123",
            live_os="Linux 6.8",
        )
        self.assertFalse(valid)
        self.assertIn("Foreign machine profile detected", err)

        # OS mismatch
        valid_os, err_os = validate_machine_profile(
            prof,
            live_total_ram_gb=16.0,
            live_machine_id="alien_workstation_456",
            live_os="win32",
        )
        self.assertFalse(valid_os)
        self.assertIn("Foreign OS machine profile detected", err_os)

    def test_expired_machine_profile_rejected(self):
        """Rejects machine profiles older than 30 days or past expires_at."""
        # 1. Calibrated 40 days ago
        old_prof = {
            "schema_version": 1,
            "machine_id": "box_1",
            "calibrated_on": "2026-08-01T00:00:00Z",
            "os": "win32",
            "total_ram_gb": 16.0,
            "cpu_cores": 8,
            "calibrated_profiles": {},
        }
        valid, err = validate_machine_profile(old_prof, live_total_ram_gb=16.0)
        self.assertFalse(valid)
        self.assertIn("Machine profile has expired", err)

        # 2. Past expires_at
        expired_prof = {
            "schema_version": 1,
            "machine_id": "box_1",
            "calibrated_on": "2026-10-01T00:00:00Z",
            "expires_at": "2026-10-05T00:00:00Z",  # past
            "os": "win32",
            "total_ram_gb": 16.0,
            "cpu_cores": 8,
            "calibrated_profiles": {},
        }
        valid, err = validate_machine_profile(expired_prof, live_total_ram_gb=16.0)
        self.assertFalse(valid)
        self.assertIn("Machine profile has expired", err)


if __name__ == "__main__":
    unittest.main()
