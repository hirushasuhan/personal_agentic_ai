"""
Adaptive Model Router (Milestones M1b / M1b.1 / ADR-008)
Part of Personal Agentic AI (PAI) - Track L (Local Assistant).

Architectural Principles:
1. Graceful Degradation over Quality Ranking: Prioritizes RAM, battery, and CPU fit.
   Quality is only differentiated when exceeding empirical noise margins (e.g. 7B coding 60% vs 40%).
2. Strict Task Class Isolation (Threat T21): Task class is determined solely by CLI / command
   arguments (code, analyze, docs, forecast, web, chat). File or web context is NEVER inspected
   to prevent prompt injection steering. Unknown commands raise an explicit error immediately.
3. Extensible Candidate Architecture (M1d Data Model Readiness):
   Candidates declare `kind` ('local' | 'cloud') and `data_leaves_machine` (bool).
   Host RAM-fit check applies strictly to local models. Route reports always declare
   'Data leaves machine: Yes / No'. Cloud provider execution is deferred to M1d (ADR-010).
4. Admission & Hysteresis Rule:
   available_ram_mb >= host_delta_mb + 512.0 (using 5-run cold median from model_profiles.json).
   Currently resident model bypasses pre-load admission checks (hysteresis).
5. Resident Model Integrity & Allow-List Check:
   The caller's resident_model is validated against the allowed candidate catalog.
   Unvetted names are ignored and cannot bypass RAM checks. Live resident model can be
   queried directly from the model server (/api/ps).
6. Resource-Constrained Eviction for Resident Models:
   Only the RAM check is bypassed by hysteresis. When system resource pressure exists
   (COMPRESSED tier, low battery, or CPU saturation), heavy resident models (7B, 4B) are
   evicted and downgraded to lightweight models across all task paths.
7. Unverified License Transparency (Threat T20):
   Models without unambiguous upstream official license verification (e.g. preview tags)
   are labeled with 'UNVERIFIED_LICENCE' in reason codes.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hardware_telemetry import HardwareBudget, HardwareTelemetry
from config import (
    get_machine_profile_path,
    get_user_config_path,
    load_machine_profile,
    load_user_config,
)


@dataclass
class ModelCandidate:
    name: str
    display_name: str
    kind: str = "local"  # "local" | "cloud"
    data_leaves_machine: bool = False
    host_delta_mb: float = 0.0
    headroom_mb: float = 512.0
    thinking_default: bool = False
    requires_opt_in: bool = False
    opt_in_flag: str = ""
    license_id: str = "Apache-2.0"
    license_status: str = "verified"
    unverified_notice: str = ""
    endpoint: str = ""
    tags: List[str] = field(default_factory=list)

    @property
    def min_available_ram_mb(self) -> float:
        return round(self.host_delta_mb + self.headroom_mb, 1)


@dataclass
class RouteDecision:
    selected_model: Optional[str]
    kind: str  # "local" | "cloud" | "none"
    data_leaves_machine: bool
    task_class: str
    reason_codes: List[str]
    rejected_models: List[Dict[str, str]]
    switches_count: int
    thinking_mode: bool
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def report(self) -> str:
        """Formatted human-readable explanation for --explain-route."""
        lines = [
            "================ ROUTE EXPLANATION ================",
            f"Command / Task Class: {self.task_class}",
            f"Selected Model:       {self.selected_model or 'None (Refusal / Fail-closed)'}",
            f"Model Kind:           {self.kind}",
            f"Data leaves machine:  {'Yes (Cloud inference)' if self.data_leaves_machine else 'No (Local inference)'}",
            f"Thinking Mode:        {self.thinking_mode}",
            f"Switches Incurred:    {self.switches_count}",
            f"Reason Codes:         {', '.join(self.reason_codes) if self.reason_codes else 'None'}",
        ]
        if self.rejected_models:
            lines.append("Rejected Candidates:")
            for item in self.rejected_models:
                for model_name, reason in item.items():
                    lines.append(f"  - {model_name}: {reason}")
        lines.append(f"Explanation:          {self.explanation}")
        lines.append("===================================================")
        return "\n".join(lines)


# Canonical task class aliases (strict CLI origin only)
COMMAND_TO_TASK_CLASS: Dict[str, str] = {
    "code": "code",
    "generate": "code",
    "analyze": "analyze",
    "audit": "analyze",
    "docs": "docs",
    "doc": "docs",
    "summary": "docs",
    "forecast": "forecast",
    "web": "web",
    "chat": "chat",
    "singlish": "chat",
    "explain": "chat",
}

HEAVY_MODELS = {"qwen2.5-coder:7b", "qwen3.5:4b", "gemma4:e2b"}


class ModelRouter:
    """
    Adaptive Model Router for Track L local assistant.
    Adapts model selection to hardware resources, power constraints, and task class.
    """

    def __init__(
        self,
        profiles_path: Optional[str] = None,
        machine_profile_path: Optional[str] = None,
        user_config_path: Optional[str] = None,
        load_system_profile: bool = False,
        live_total_ram_gb: Optional[float] = None,
        live_machine_id: Optional[str] = None,
        live_os: Optional[str] = None,
        reference_profile_mode: bool = False,
    ):
        self.root_dir = os.path.dirname(os.path.abspath(__file__))
        if profiles_path is None:
            profiles_path = os.path.join(self.root_dir, "model_profiles.json")
        self.profiles_path = profiles_path
        self.candidates: Dict[str, ModelCandidate] = {}
        self._load_candidates()

        self.machine_profile_path = machine_profile_path
        self.user_config_path = user_config_path
        self.reference_profile_mode = reference_profile_mode

        # Auto-query live system parameters
        auto_ram = None
        auto_mid = None
        auto_os = None
        try:
            telem = HardwareTelemetry()
            snap = telem.get_system_snapshot()
            if snap.get("total_ram_gb"):
                auto_ram = float(snap["total_ram_gb"])
            auto_mid = f"{platform.node()}_{platform.machine()}"
            auto_os = sys.platform
        except Exception:
            pass

        self.live_total_ram_gb = live_total_ram_gb if live_total_ram_gb is not None else auto_ram
        self.live_machine_id = live_machine_id if live_machine_id is not None else auto_mid
        self.live_os = live_os if live_os is not None else auto_os

        # For machine profile validation:
        # load_system_profile enforces live machine identity
        # custom machine_profile_path validates live identity if explicitly provided
        val_ram = self.live_total_ram_gb if (load_system_profile or live_total_ram_gb is not None) else None
        val_mid = self.live_machine_id if (load_system_profile or live_machine_id is not None) else None
        val_os = self.live_os if (load_system_profile or live_os is not None) else None

        # Load machine profile
        self.machine_profile: Optional[Dict[str, Any]] = None
        if machine_profile_path:
            self.machine_profile = load_machine_profile(
                machine_profile_path,
                live_total_ram_gb=val_ram,
                live_machine_id=val_mid,
                live_os=val_os,
            )
        elif load_system_profile:
            p_path = get_machine_profile_path()
            if os.path.exists(p_path):
                self.machine_profile = load_machine_profile(
                    p_path,
                    live_total_ram_gb=val_ram,
                    live_machine_id=val_mid,
                    live_os=val_os,
                )

        # Load user configuration
        self.user_config: Optional[Dict[str, Any]] = None
        if user_config_path:
            self.user_config = load_user_config(user_config_path)
        elif load_system_profile:
            c_path = get_user_config_path()
            if os.path.exists(c_path):
                self.user_config = load_user_config(c_path)

    def _load_candidates(self) -> None:
        """Loads candidate models from model_profiles.json."""
        if not os.path.exists(self.profiles_path):
            return

        with open(self.profiles_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        profiles = data.get("profiles", {})
        headroom = float(data.get("headroom_mb", 512.0))

        for name, p in profiles.items():
            lic_id = p.get("license_id", "Apache-2.0")
            lic_status = p.get("license_status", "verified")
            req_opt = bool(p.get("requires_opt_in", False) or lic_id == "unverified" or name == "gemma4:e2b")

            self.candidates[name] = ModelCandidate(
                name=name,
                display_name=p.get("display_name", name),
                kind="local",
                data_leaves_machine=False,
                host_delta_mb=float(p.get("host_delta_mb", 1024.0)),
                headroom_mb=headroom,
                thinking_default=bool(p.get("thinking_default", False)),
                requires_opt_in=req_opt,
                opt_in_flag=p.get("opt_in_flag", "gemma4_opt_in" if name == "gemma4:e2b" else ""),
                license_id=lic_id,
                license_status=lic_status,
                unverified_notice=p.get("unverified_notice", ""),
                tags=p.get("tags", []),
            )

    def register_candidate(self, candidate: ModelCandidate) -> None:
        """Dynamically registers a candidate model."""
        self.candidates[candidate.name] = candidate

    @staticmethod
    def resolve_task_class(command: str, context: Optional[str] = None) -> Optional[str]:
        """
        Resolves task class strictly from CLI command name.
        T21 Defense: context is NEVER inspected to infer task class.
        Returns None for unknown/unsupported commands.
        """
        if not command:
            return None
        cmd_clean = command.strip().lower()
        return COMMAND_TO_TASK_CLASS.get(cmd_clean, None)

    def get_live_resident_model(self, base_url: str = "http://127.0.0.1:11434") -> Optional[str]:
        """
        Queries the model server (/api/ps) and returns the verified resident model
        matching the allowed candidate catalog.
        Enforces local loopback check on base_url to prevent SSRF / probing.
        Uses exact name matching and priority resolution for multiple loaded models.
        """
        parts = urllib.parse.urlsplit(base_url)
        hostname = (parts.hostname or "").lower()
        if hostname not in ("127.0.0.1", "localhost", "::1", "[::1]"):
            raise ValueError(f"base_url must be local loopback, got '{base_url}'")

        try:
            ps_url = f"{parts.scheme}://{parts.netloc}/api/ps"
            req = urllib.request.Request(ps_url)
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                data = json.loads(resp.read().decode())
                models = data.get("models", [])
                matching = [
                    m.get("name", "") for m in models
                    if m.get("name", "") in self.candidates
                ]
                if not matching:
                    return None

                priority_order = [
                    "qwen2.5-coder:7b",
                    "qwen3.5:4b",
                    "llama3.2:3b",
                    "qwen2.5-coder:1.5b",
                    "gemma4:e2b",
                ]
                for p in priority_order:
                    if p in matching:
                        return p
                return matching[0]
        except Exception:
            pass
        return None

    def check_candidate_fit(
        self,
        candidate: ModelCandidate,
        avail_ram_mb: Optional[float],
        resident_model: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Evaluates admission fit rule for a model candidate.
        Cloud models bypass local host RAM checks.
        Warm resident models bypass pre-load check via hysteresis.
        Per ADR-010: Uses machine profile if calibrated and plausible,
        otherwise conservative 1.5x multiplier + 512MB headroom.
        """
        if candidate.kind == "cloud":
            return True, "CLOUD_NO_HOST_RAM_REQUIRED"

        # Hysteresis: model already loaded into memory
        if resident_model and resident_model == candidate.name:
            return True, "HYSTERESIS_WARM_BYPASS"

        if avail_ram_mb is None:
            return False, "RAM_TELEMETRY_UNAVAILABLE"

        if self.machine_profile:
            calibrated_profiles = self.machine_profile.get("calibrated_profiles", {})
            if candidate.name in calibrated_profiles:
                cal_delta = float(calibrated_profiles[candidate.name].get("host_delta_mb", candidate.host_delta_mb))
                # Plausibility floor: calibrated delta must be >= 50% of card delta
                plausibility_floor = 0.5 * candidate.host_delta_mb
                if cal_delta >= plausibility_floor:
                    min_req = round(cal_delta + candidate.headroom_mb, 1)
                    if avail_ram_mb >= min_req:
                        return True, f"RAM_FIT (avail {avail_ram_mb:.1f} MB >= req {min_req:.1f} MB [calibrated])"
                    else:
                        return False, f"INSUFFICIENT_RAM (need {min_req:.1f} MB [calibrated], avail {avail_ram_mb:.1f} MB)"
                else:
                    # Implausible calibration delta (< 50% card delta); fall back to conservative 1.5x rule
                    min_req = round(candidate.host_delta_mb * 1.5 + candidate.headroom_mb, 1)
                    if avail_ram_mb >= min_req:
                        return True, f"RAM_FIT (avail {avail_ram_mb:.1f} MB >= req {min_req:.1f} MB [CALIBRATION_IMPLAUSIBLE 1.5x fallback])"
                    else:
                        return False, f"INSUFFICIENT_RAM (need {min_req:.1f} MB [CALIBRATION_IMPLAUSIBLE 1.5x fallback], avail {avail_ram_mb:.1f} MB)"
            else:
                # ADR-010 conservative rule: 1.5x card delta + headroom
                min_req = round(candidate.host_delta_mb * 1.5 + candidate.headroom_mb, 1)
                if avail_ram_mb >= min_req:
                    return True, f"RAM_FIT (avail {avail_ram_mb:.1f} MB >= req {min_req:.1f} MB [uncalibrated 1.5x])"
                else:
                    return False, f"INSUFFICIENT_RAM (need {min_req:.1f} MB [uncalibrated 1.5x], avail {avail_ram_mb:.1f} MB)"

        # When no machine profile exists:
        if self.reference_profile_mode:
            min_req = candidate.min_available_ram_mb
            if avail_ram_mb >= min_req:
                return True, f"RAM_FIT (avail {avail_ram_mb:.1f} MB >= req {min_req:.1f} MB)"
            else:
                return False, f"INSUFFICIENT_RAM (need {min_req:.1f} MB, avail {avail_ram_mb:.1f} MB)"
        else:
            # Uncalibrated machine (ADR-010 conservative rule applies by default)
            min_req = round(candidate.host_delta_mb * 1.5 + candidate.headroom_mb, 1)
            if avail_ram_mb >= min_req:
                return True, f"RAM_FIT (avail {avail_ram_mb:.1f} MB >= req {min_req:.1f} MB [uncalibrated 1.5x])"
            else:
                return False, f"INSUFFICIENT_RAM (need {min_req:.1f} MB [uncalibrated 1.5x], avail {avail_ram_mb:.1f} MB)"


    def route(
        self,
        command: str,
        context: Optional[str] = None,
        budget: Optional[HardwareBudget] = None,
        resident_model: Optional[str] = None,
        gemma4_opt_in: bool = False,
    ) -> RouteDecision:
        """
        Executes adaptive routing decision based on hardware constraints and task class.
        Raises ValueError immediately if command is unknown.
        """
        task_class = self.resolve_task_class(command, context=context)
        if task_class is None:
            valid_cmds = sorted(list(set(COMMAND_TO_TASK_CLASS.keys())))
            raise ValueError(f"Unknown or invalid command / task class: '{command}'. Valid commands are: {valid_cmds}")

        # Extract telemetry parameters
        avail_ram_mb = budget.avail_ram_mb if budget else None
        tier = budget.compute_tier if budget else "BALANCED"
        reasons = list(budget.reasons) if budget else []

        reason_codes: List[str] = []
        rejected_models: List[Dict[str, str]] = []

        def make_decision(
            selected_model: Optional[str],
            kind: str,
            data_leaves_machine: bool,
            codes: List[str],
            switches: int,
            thinking: bool,
            explanation: str,
        ) -> RouteDecision:
            codes_copy = list(codes)
            has_implausible = any(
                "CALIBRATION_IMPLAUSIBLE" in str(r) for r in rejected_models
            )
            if selected_model and selected_model in self.candidates:
                cand = self.candidates[selected_model]
                if self.machine_profile:
                    cal_profiles = self.machine_profile.get("calibrated_profiles", {})
                    if selected_model in cal_profiles:
                        cal_delta = float(cal_profiles[selected_model].get("host_delta_mb", cand.host_delta_mb))
                        if cal_delta < 0.5 * cand.host_delta_mb:
                            if "CALIBRATION_IMPLAUSIBLE" not in codes_copy:
                                codes_copy.append("CALIBRATION_IMPLAUSIBLE")
                            if "UNCALIBRATED" not in codes_copy:
                                codes_copy.append("UNCALIBRATED")
                        else:
                            if "MACHINE_PROFILE_CALIBRATED" not in codes_copy:
                                codes_copy.append("MACHINE_PROFILE_CALIBRATED")
                    else:
                        if "UNCALIBRATED" not in codes_copy:
                            codes_copy.append("UNCALIBRATED")
                elif not self.reference_profile_mode:
                    if "UNCALIBRATED" not in codes_copy:
                        codes_copy.append("UNCALIBRATED")
            elif selected_model is None:
                if not self.reference_profile_mode and not self.machine_profile:
                    if "UNCALIBRATED" not in codes_copy:
                        codes_copy.append("UNCALIBRATED")

            if has_implausible and "CALIBRATION_IMPLAUSIBLE" not in codes_copy:
                codes_copy.append("CALIBRATION_IMPLAUSIBLE")

            return RouteDecision(
                selected_model=selected_model,
                kind=kind,
                data_leaves_machine=data_leaves_machine,
                task_class=task_class,
                reason_codes=codes_copy,
                rejected_models=rejected_models,
                switches_count=switches,
                thinking_mode=thinking,
                explanation=explanation,
            )

        # Check user config allow-list (T21)
        user_allowed = self.user_config.get("allowed_models") if self.user_config else None
        has_user_allowlist = bool(user_allowed and isinstance(user_allowed, list) and len(user_allowed) > 0)

        def is_allowed(m_name: str) -> bool:
            if not has_user_allowlist:
                return True
            return m_name in user_allowed  # type: ignore[operator]

        # Check user preferred model for task class
        user_pref = None
        if self.user_config and "preferred_models" in self.user_config:
            candidate_pref = self.user_config["preferred_models"].get(task_class)
            if candidate_pref and candidate_pref in self.candidates and is_allowed(candidate_pref):
                user_pref = candidate_pref

        # Define candidate preference lists by task class
        if task_class == "code":
            preferred_candidates = ["qwen2.5-coder:7b", "qwen2.5-coder:1.5b"]
        elif task_class == "chat":
            preferred_candidates = ["qwen3.5:4b", "llama3.2:3b", "qwen2.5-coder:1.5b"]
        else:
            # "docs", "analyze", "web", "forecast": unmeasured class in doc benchmarks
            preferred_candidates = ["qwen2.5-coder:7b", "qwen2.5-coder:1.5b", "qwen3.5:4b", "llama3.2:3b"]

        # Validate resident_model against allow-list catalog (cannot spoof arbitrary resident name)
        valid_resident: Optional[str] = None
        if resident_model:
            if resident_model in self.candidates:
                if is_allowed(resident_model):
                    valid_resident = resident_model
                else:
                    rejected_models.append({resident_model: "resident model not in user allowed_models"})
            else:
                rejected_models.append({resident_model: "resident model not in allowed candidate catalog; ignored"})

        # Identify resource pressure conditions
        has_resource_pressure = (
            tier == "COMPRESSED"
            or "low-battery" in reasons
            or "cpu-saturated" in reasons
        )

        # -------------------------------------------------------------
        # 1. User Preferred Model Check
        # -------------------------------------------------------------
        if user_pref and user_pref in self.candidates:
            pref_cand = self.candidates[user_pref]
            if user_pref in HEAVY_MODELS and has_resource_pressure:
                rejected_models.append({user_pref: "preferred model blocked by resource pressure"})
            else:
                fit_pref, msg_pref = self.check_candidate_fit(pref_cand, avail_ram_mb, resident_model=valid_resident)
                if fit_pref:
                    switches = 1 if valid_resident != pref_cand.name else 0
                    p_codes = ["RAM_FIT", "USER_PREFERRED_MODEL"]
                    if pref_cand.license_id == "unverified":
                        p_codes.append("UNVERIFIED_LICENCE")
                    if task_class in ("docs", "analyze", "web", "forecast"):
                        p_codes.append("UNMEASURED_CLASS")
                    return make_decision(
                        selected_model=pref_cand.name,
                        kind=pref_cand.kind,
                        data_leaves_machine=pref_cand.data_leaves_machine,
                        codes=p_codes,
                        switches=switches,
                        thinking=pref_cand.thinking_default,
                        explanation=f"Selected user preferred model '{pref_cand.name}' for task class '{task_class}'.",
                    )
                else:
                    rejected_models.append({user_pref: f"user preferred model does not fit: {msg_pref}"})

        # -------------------------------------------------------------
        # 2. Sticky Resident Check (Avoiding 8-18s Cold Switching Cost)
        # -------------------------------------------------------------
        if valid_resident and valid_resident in self.candidates:
            res_cand = self.candidates[valid_resident]

            # Invariant: Resident models DO NOT bypass power/CPU/tier rules!
            # Heavy resident models (7B, 4B, Gemma) must be evicted under resource pressure.
            if valid_resident in HEAVY_MODELS and has_resource_pressure:
                if tier == "COMPRESSED":
                    rejected_models.append({valid_resident: "resident evicted: tier is COMPRESSED"})
                if "low-battery" in reasons:
                    rejected_models.append({valid_resident: "resident evicted: low battery"})
                if "cpu-saturated" in reasons:
                    rejected_models.append({valid_resident: "resident evicted: cpu load saturated"})
                valid_resident = None
            elif valid_resident in preferred_candidates:
                fit, fit_msg = self.check_candidate_fit(res_cand, avail_ram_mb, resident_model=valid_resident)
                if fit:
                    reason_codes.append("STICKY_RESIDENT")
                    if task_class in ("docs", "analyze", "web", "forecast"):
                        reason_codes.append("UNMEASURED_CLASS")
                    if res_cand.license_id == "unverified":
                        reason_codes.append("UNVERIFIED_LICENCE")
                    reason_codes.append(fit_msg)
                    return make_decision(
                        selected_model=res_cand.name,
                        kind=res_cand.kind,
                        data_leaves_machine=res_cand.data_leaves_machine,
                        codes=reason_codes,
                        switches=0,
                        thinking=res_cand.thinking_default,
                        explanation=f"Retained resident model '{res_cand.name}' to avoid cold loading latency.",
                    )

        # -------------------------------------------------------------
        # 3. Routing Policy: Code Tasks
        # -------------------------------------------------------------
        if task_class == "code":
            c7b = self.candidates.get("qwen2.5-coder:7b")
            c1b = self.candidates.get("qwen2.5-coder:1.5b")

            can_use_7b = True
            c7b_rejection = []

            if c7b and not is_allowed(c7b.name):
                can_use_7b = False
                c7b_rejection.append("NOT_IN_USER_ALLOWED_MODELS")
            if tier == "COMPRESSED":
                can_use_7b = False
                c7b_rejection.append("tier is COMPRESSED (fallback to 1.5B)")
                reason_codes.append("COMPRESSED_FALLBACK")
            if "low-battery" in reasons:
                can_use_7b = False
                c7b_rejection.append("battery level critical / low-battery (power conservation)")
                reason_codes.append("POWER_CONSERVATION")
            if "cpu-saturated" in reasons:
                can_use_7b = False
                c7b_rejection.append("cpu load saturated / throttled")
                reason_codes.append("CPU_THROTTLE_FALLBACK")
            if c7b:
                fit_7b, msg_7b = self.check_candidate_fit(c7b, avail_ram_mb, resident_model=valid_resident)
                if not fit_7b:
                    can_use_7b = False
                    c7b_rejection.append(msg_7b)
                elif "CALIBRATION_IMPLAUSIBLE" in msg_7b:
                    c7b_rejection.append(msg_7b)

            if can_use_7b and c7b:
                switches_count = 1 if valid_resident != c7b.name else 0
                reason_codes.extend(["RAM_FIT", "PRIMARY_CODE_CANDIDATE"])
                return make_decision(
                    selected_model=c7b.name,
                    kind=c7b.kind,
                    data_leaves_machine=c7b.data_leaves_machine,
                    codes=reason_codes,
                    switches=switches_count,
                    thinking=False,
                    explanation=f"Selected primary coding model '{c7b.name}' (sufficient headroom and normal operating conditions).",
                )

            # Record rejection of 7B
            if c7b:
                rejected_models.append({c7b.name: "; ".join(c7b_rejection) if c7b_rejection else "downgraded"})

            # Fallback to 1.5B coding model
            if c1b:
                if not is_allowed(c1b.name):
                    rejected_models.append({c1b.name: "NOT_IN_USER_ALLOWED_MODELS"})
                else:
                    fit_1b, msg_1b = self.check_candidate_fit(c1b, avail_ram_mb, resident_model=valid_resident)
                    if fit_1b:
                        switches_count = 1 if valid_resident != c1b.name else 0
                        reason_codes.extend(["RAM_FIT_FALLBACK", "LIGHTWEIGHT_CODE_CANDIDATE"])
                        return make_decision(
                            selected_model=c1b.name,
                            kind=c1b.kind,
                            data_leaves_machine=c1b.data_leaves_machine,
                            codes=reason_codes,
                            switches=switches_count,
                            thinking=False,
                            explanation=f"Graceful degradation to '{c1b.name}' due to hardware/power/thermal constraints.",
                        )
                    else:
                        rejected_models.append({c1b.name: msg_1b})

            # Refusal: No candidate fits
            reason_codes.append("INSUFFICIENT_HEADROOM")
            return make_decision(
                selected_model=None,
                kind="none",
                data_leaves_machine=False,
                codes=reason_codes,
                switches=0,
                thinking=False,
                explanation="Refused: Available RAM is insufficient for all local coding models.",
            )

        # -------------------------------------------------------------
        # 4. Routing Policy: Chat / Singlish / Explain Tasks
        # -------------------------------------------------------------
        elif task_class == "chat":
            # Check gemma4 opt-in
            cgemma = self.candidates.get("gemma4:e2b")
            if cgemma:
                if not is_allowed(cgemma.name):
                    rejected_models.append({cgemma.name: "NOT_IN_USER_ALLOWED_MODELS"})
                elif not gemma4_opt_in:
                    rejected_models.append({
                        cgemma.name: "OPT_IN_REQUIRED (Gemma consumes 2.93 GB host RAM, requires explicit owner opt-in)"
                    })
                else:
                    fit_gemma, msg_gemma = self.check_candidate_fit(cgemma, avail_ram_mb, resident_model=valid_resident)
                    if fit_gemma and avail_ram_mb and avail_ram_mb >= 3500.0 and not has_resource_pressure:
                        switches_count = 1 if valid_resident != cgemma.name else 0
                        reason_codes.extend(["OWNER_OPT_IN", "RAM_FIT"])
                        if cgemma.license_id == "unverified":
                            reason_codes.append("UNVERIFIED_LICENCE")
                        return make_decision(
                            selected_model=cgemma.name,
                            kind=cgemma.kind,
                            data_leaves_machine=cgemma.data_leaves_machine,
                            codes=reason_codes,
                            switches=switches_count,
                            thinking=False,
                            explanation=f"Selected '{cgemma.name}' under explicit owner opt-in and high RAM.",
                        )
                    else:
                        rejected_models.append({cgemma.name: msg_gemma if not fit_gemma else "resource pressure"})

            # Primary chat candidate: qwen3.5:4b (think: false)
            c4b = self.candidates.get("qwen3.5:4b")
            can_use_4b = True
            c4b_rejection = []

            if c4b and not is_allowed(c4b.name):
                can_use_4b = False
                c4b_rejection.append("NOT_IN_USER_ALLOWED_MODELS")
            if tier == "COMPRESSED":
                can_use_4b = False
                c4b_rejection.append("tier is COMPRESSED")
                reason_codes.append("COMPRESSED_FALLBACK")
            if "low-battery" in reasons:
                can_use_4b = False
                c4b_rejection.append("battery level critical / low-battery")
                reason_codes.append("POWER_CONSERVATION")
            if "cpu-saturated" in reasons:
                can_use_4b = False
                c4b_rejection.append("cpu load saturated")
                reason_codes.append("CPU_THROTTLE_FALLBACK")

            if c4b:
                fit_4b, msg_4b = self.check_candidate_fit(c4b, avail_ram_mb, resident_model=valid_resident)
                if not fit_4b:
                    can_use_4b = False
                    c4b_rejection.append(msg_4b)
                elif "CALIBRATION_IMPLAUSIBLE" in msg_4b:
                    c4b_rejection.append(msg_4b)

            if can_use_4b and c4b:
                switches_count = 1 if valid_resident != c4b.name else 0
                reason_codes.extend(["RAM_FIT", "PRIMARY_CHAT_CANDIDATE"])
                if c4b.license_id == "unverified":
                    reason_codes.append("UNVERIFIED_LICENCE")
                return make_decision(
                    selected_model=c4b.name,
                    kind=c4b.kind,
                    data_leaves_machine=c4b.data_leaves_machine,
                    codes=reason_codes,
                    switches=switches_count,
                    thinking=False,
                    explanation=f"Selected primary chat model '{c4b.name}' with thinking mode disabled.",
                )

            if c4b:
                rejected_models.append({c4b.name: "; ".join(c4b_rejection) if c4b_rejection else "downgraded"})

            # Fallback 1: llama3.2:3b
            c3b = self.candidates.get("llama3.2:3b")
            can_use_3b = True
            c3b_rejection = []

            if c3b and not is_allowed(c3b.name):
                can_use_3b = False
                c3b_rejection.append("NOT_IN_USER_ALLOWED_MODELS")
            if tier == "COMPRESSED":
                can_use_3b = False
                c3b_rejection.append("tier is COMPRESSED")
            if "cpu-saturated" in reasons:
                can_use_3b = False
                c3b_rejection.append("cpu load saturated")

            if c3b and can_use_3b:
                fit_3b, msg_3b = self.check_candidate_fit(c3b, avail_ram_mb, resident_model=valid_resident)
                if not fit_3b:
                    can_use_3b = False
                    c3b_rejection.append(msg_3b)

            if can_use_3b and c3b:
                switches_count = 1 if valid_resident != c3b.name else 0
                reason_codes.extend(["RAM_FIT_FALLBACK", "INTERMEDIATE_CHAT_FALLBACK"])
                return make_decision(
                    selected_model=c3b.name,
                    kind=c3b.kind,
                    data_leaves_machine=c3b.data_leaves_machine,
                    codes=reason_codes,
                    switches=switches_count,
                    thinking=False,
                    explanation=f"Fallback to '{c3b.name}' due to RAM or power constraints on 4B.",
                )

            if c3b:
                rejected_models.append({c3b.name: "; ".join(c3b_rejection) if c3b_rejection else "downgraded"})

            # Fallback 2: qwen2.5-coder:1.5b
            c1b = self.candidates.get("qwen2.5-coder:1.5b")
            if c1b:
                if not is_allowed(c1b.name):
                    rejected_models.append({c1b.name: "NOT_IN_USER_ALLOWED_MODELS"})
                else:
                    fit_1b, msg_1b = self.check_candidate_fit(c1b, avail_ram_mb, resident_model=valid_resident)
                    if fit_1b:
                        switches_count = 1 if valid_resident != c1b.name else 0
                        reason_codes.extend(["LIGHTWEIGHT_FALLBACK"])
                        return make_decision(
                            selected_model=c1b.name,
                            kind=c1b.kind,
                            data_leaves_machine=c1b.data_leaves_machine,
                            codes=reason_codes,
                            switches=switches_count,
                            thinking=False,
                            explanation=f"Lightweight fallback to '{c1b.name}' under heavy memory/power pressure.",
                        )
                    else:
                        rejected_models.append({c1b.name: msg_1b})

            # Refusal
            reason_codes.append("INSUFFICIENT_HEADROOM")
            return make_decision(
                selected_model=None,
                kind="none",
                data_leaves_machine=False,
                codes=reason_codes,
                switches=0,
                thinking=False,
                explanation="Refused: Available RAM is insufficient for all chat candidates.",
            )

        # -------------------------------------------------------------
        # 5. Routing Policy: Docs / Analyze / Web / Forecast Tasks
        # -------------------------------------------------------------
        else:
            # Unmeasured class: doc scores do not discriminate models.
            reason_codes.append("UNMEASURED_CLASS")
            c7b = self.candidates.get("qwen2.5-coder:7b")
            c1b = self.candidates.get("qwen2.5-coder:1.5b")

            can_use_7b = True
            c7b_rejection = []

            if c7b and not is_allowed(c7b.name):
                can_use_7b = False
                c7b_rejection.append("NOT_IN_USER_ALLOWED_MODELS")
            if tier == "COMPRESSED":
                can_use_7b = False
                c7b_rejection.append("tier is COMPRESSED")
                reason_codes.append("COMPRESSED_FALLBACK")
            if "low-battery" in reasons:
                can_use_7b = False
                c7b_rejection.append("battery level critical / low-battery")
                reason_codes.append("POWER_CONSERVATION")
            if "cpu-saturated" in reasons:
                can_use_7b = False
                c7b_rejection.append("cpu load saturated / throttled")
                reason_codes.append("CPU_THROTTLE_FALLBACK")

            if c7b:
                fit_7b, msg_7b = self.check_candidate_fit(c7b, avail_ram_mb, resident_model=valid_resident)
                if not fit_7b:
                    can_use_7b = False
                    c7b_rejection.append(msg_7b)
                elif "CALIBRATION_IMPLAUSIBLE" in msg_7b:
                    c7b_rejection.append(msg_7b)

            if can_use_7b and c7b:
                switches_count = 1 if valid_resident != c7b.name else 0
                reason_codes.append("RAM_FIT")
                return make_decision(
                    selected_model=c7b.name,
                    kind=c7b.kind,
                    data_leaves_machine=c7b.data_leaves_machine,
                    codes=reason_codes,
                    switches=switches_count,
                    thinking=False,
                    explanation=f"Selected '{c7b.name}' for unmeasured class '{task_class}'.",
                )

            if c7b:
                rejected_models.append({c7b.name: "; ".join(c7b_rejection) if c7b_rejection else "downgraded"})

            # Fallback to 1.5B
            if c1b:
                if not is_allowed(c1b.name):
                    rejected_models.append({c1b.name: "NOT_IN_USER_ALLOWED_MODELS"})
                else:
                    fit_1b, msg_1b = self.check_candidate_fit(c1b, avail_ram_mb, resident_model=valid_resident)
                    if fit_1b:
                        switches_count = 1 if valid_resident != c1b.name else 0
                        reason_codes.append("LIGHTWEIGHT_FALLBACK")
                        return make_decision(
                            selected_model=c1b.name,
                            kind=c1b.kind,
                            data_leaves_machine=c1b.data_leaves_machine,
                            codes=reason_codes,
                            switches=switches_count,
                            thinking=False,
                            explanation=f"Selected lightweight '{c1b.name}' for unmeasured class '{task_class}'.",
                        )
                    else:
                        rejected_models.append({c1b.name: msg_1b})

            # Refusal
            reason_codes.append("INSUFFICIENT_HEADROOM")
            return make_decision(
                selected_model=None,
                kind="none",
                data_leaves_machine=False,
                codes=reason_codes,
                switches=0,
                thinking=False,
                explanation=f"Refused: Available RAM is insufficient for '{task_class}'.",
            )

