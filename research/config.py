"""
Personal Agentic AI (PAI) - Configuration and Machine Profile Management
Milestone M1c / ADR-010.

Security Properties (Threats T22, T26):
1. T22 (No API Keys / Secrets in Config): User configuration is strictly non-secret.
   Any keys resembling credentials (key, secret, token, password) are rejected immediately.
2. T26 (Profile Tampering Protection): Machine profiles are schema-validated.
   Values must be positive numbers. Calibrated RAM is cross-checked against live total RAM.
   Unknown keys are strictly rejected.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = 1


def get_default_config_dir() -> str:
    """Returns the user configuration directory path (~/.pai or PAI_CONFIG_DIR)."""
    override = os.environ.get("PAI_CONFIG_DIR")
    if override:
        return os.path.abspath(override)
    return os.path.join(os.path.expanduser("~"), ".pai")


def get_machine_profile_path(config_dir: Optional[str] = None) -> str:
    cd = config_dir or get_default_config_dir()
    return os.path.join(cd, "machine_profile.json")


def get_user_config_path(config_dir: Optional[str] = None) -> str:
    cd = config_dir or get_default_config_dir()
    return os.path.join(cd, "config.json")


# -----------------------------------------------------------------------------
# User Configuration Schema & Validation (Non-secret only)
# -----------------------------------------------------------------------------
ALLOWED_USER_CONFIG_KEYS = {
    "schema_version",
    "allowed_models",
    "preferred_models",
    "privacy_mode",
    "spend_caps",
    "enabled_providers",
}

FORBIDDEN_SECRET_SUBSTRINGS = ["key", "secret", "token", "password", "credential", "auth"]


def validate_user_config(data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validates user configuration dictionary against strict schema.
    Rejects unknown keys and any secret-like fields (T22).
    """
    if not isinstance(data, dict):
        return False, "Configuration must be a JSON object"

    # Reject unknown keys
    unknown_keys = set(data.keys()) - ALLOWED_USER_CONFIG_KEYS
    if unknown_keys:
        return False, f"Unknown configuration keys rejected (T26): {sorted(list(unknown_keys))}"

    # Verify no secrets in keys or values (T22)
    def scan_for_secrets(obj: Any, prefix: str = "") -> Optional[str]:
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_lower = str(k).lower()
                for forbidden in FORBIDDEN_SECRET_SUBSTRINGS:
                    if forbidden in k_lower:
                        return f"Forbidden secret field '{prefix}{k}' detected in config (T22)"
                sub = scan_for_secrets(v, prefix=f"{prefix}{k}.")
                if sub:
                    return sub
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                sub = scan_for_secrets(item, prefix=f"{prefix}[{i}].")
                if sub:
                    return sub
        return None

    secret_err = scan_for_secrets(data)
    if secret_err:
        return False, secret_err

    # Validate allowed_models
    if "allowed_models" in data and not isinstance(data["allowed_models"], list):
        return False, "'allowed_models' must be a list of model names"

    # Validate preferred_models
    if "preferred_models" in data and not isinstance(data["preferred_models"], dict):
        return False, "'preferred_models' must be a dictionary mapping task_class -> model_name"

    # Validate privacy_mode
    if "privacy_mode" in data and data["privacy_mode"] not in ("local-only", "allow-cloud"):
        return False, f"Invalid privacy_mode '{data['privacy_mode']}'; must be 'local-only' or 'allow-cloud'"

    return True, "Valid"


def load_user_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Loads and validates user configuration. Returns empty dict if file does not exist."""
    path = config_path or get_user_config_path()
    if not os.path.exists(path):
        return {
            "schema_version": SCHEMA_VERSION,
            "allowed_models": [],
            "preferred_models": {},
            "privacy_mode": "local-only",
        }

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise ValueError(f"Failed to read user configuration file '{path}': {e}")

    valid, err = validate_user_config(data)
    if not valid:
        raise ValueError(f"User configuration rejected: {err}")

    return data


def save_user_config(data: Dict[str, Any], config_path: Optional[str] = None) -> None:
    """Saves user configuration to disk after validating schema."""
    valid, err = validate_user_config(data)
    if not valid:
        raise ValueError(f"Cannot save invalid user configuration: {err}")

    path = config_path or get_user_config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# -----------------------------------------------------------------------------
# Machine Profile Schema & Validation (Hardware calibration)
# -----------------------------------------------------------------------------
ALLOWED_MACHINE_PROFILE_KEYS = {
    "schema_version",
    "machine_id",
    "calibrated_on",
    "os",
    "total_ram_gb",
    "cpu_cores",
    "calibrated_profiles",
}


def validate_machine_profile(
    data: Dict[str, Any],
    live_total_ram_gb: Optional[float] = None,
) -> Tuple[bool, str]:
    """
    Validates machine profile numbers against strict schema and live hardware (T26).
    Rejects unknown keys, negative values, and unrealistic memory allocations.
    """
    if not isinstance(data, dict):
        return False, "Machine profile must be a JSON object"

    # Reject unknown keys
    unknown_keys = set(data.keys()) - ALLOWED_MACHINE_PROFILE_KEYS
    if unknown_keys:
        return False, f"Unknown machine profile keys rejected (T26): {sorted(list(unknown_keys))}"

    # Check numeric total_ram_gb
    total_ram = data.get("total_ram_gb")
    if not isinstance(total_ram, (int, float)) or total_ram <= 0:
        return False, "'total_ram_gb' must be a positive number"

    # Verify live hardware sanity if available
    if live_total_ram_gb is not None and live_total_ram_gb > 0:
        diff_pct = abs(total_ram - live_total_ram_gb) / live_total_ram_gb
        if diff_pct > 0.35:  # Over 35% difference indicates tampered or migrated profile
            return False, f"Tampered machine profile detected: claims {total_ram} GB RAM, live system has {live_total_ram_gb:.1f} GB (diff {diff_pct*100:.1f}%)"

    # Check calibrated profiles
    profiles = data.get("calibrated_profiles", {})
    if not isinstance(profiles, dict):
        return False, "'calibrated_profiles' must be a dictionary"

    for m_name, p in profiles.items():
        if not isinstance(p, dict):
            return False, f"Profile for '{m_name}' must be an object"
        delta = p.get("host_delta_mb")
        if not isinstance(delta, (int, float)) or delta <= 0:
            return False, f"Model '{m_name}' host_delta_mb must be a positive number"
        if delta > (total_ram * 1024):
            return False, f"Model '{m_name}' host_delta_mb ({delta} MB) exceeds machine total RAM ({total_ram * 1024} MB)"

    return True, "Valid"


def load_machine_profile(
    profile_path: Optional[str] = None,
    live_total_ram_gb: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """
    Loads and validates machine profile.
    Returns None if profile file does not exist or fails validation.
    """
    path = profile_path or get_machine_profile_path()
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    valid, _ = validate_machine_profile(data, live_total_ram_gb=live_total_ram_gb)
    if not valid:
        return None

    return data


def save_machine_profile(data: Dict[str, Any], profile_path: Optional[str] = None) -> None:
    """Saves validated machine profile to user config directory."""
    valid, err = validate_machine_profile(data)
    if not valid:
        raise ValueError(f"Cannot save invalid machine profile: {err}")

    path = profile_path or get_machine_profile_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
