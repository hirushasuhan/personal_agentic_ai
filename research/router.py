"""
Adaptive Model Router (Milestone M1b / ADR-008)
Part of Personal Agentic AI (PAI) - Track L (Local Assistant).

Architectural Principles:
1. Graceful Degradation over Quality Ranking: Prioritizes RAM, battery, and CPU fit.
   Quality is only differentiated when exceeding empirical noise margins (e.g. 7B coding 60% vs 40%).
2. Strict Task Class Isolation (Threat T21): Task class is determined solely by CLI / command
   arguments (code, analyze, docs, forecast, web, chat). File or web context is NEVER inspected
   to prevent prompt injection steering.
3. Extensible Candidate Architecture (M1b -> M1d):
   Candidates declare `kind` ('local' | 'cloud') and `data_leaves_machine` (bool).
   Host RAM-fit check applies strictly to local models; cloud candidates bypass host RAM checks.
   Route reports always declare 'Data leaves machine: Yes / No'.
4. Admission & Hysteresis Rule:
   available_ram_mb >= host_delta_mb + 512.0 (using 5-run cold median from model_profiles.json).
   Currently resident model bypasses pre-load admission checks (hysteresis).
5. Switching Cost & Stickiness:
   Cold loading incurs 8.7s to 18.25s latency. The router avoids model thrashing by retaining
   the resident model whenever it is fit and in the acceptable set for the task class.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hardware_telemetry import HardwareBudget


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


class ModelRouter:
    """
    Adaptive Model Router for Track L local assistant.
    Adapts model selection to hardware resources, power constraints, and task class.
    """

    def __init__(self, profiles_path: Optional[str] = None):
        self.root_dir = os.path.dirname(os.path.abspath(__file__))
        if profiles_path is None:
            profiles_path = os.path.join(self.root_dir, "model_profiles.json")
        self.profiles_path = profiles_path
        self.candidates: Dict[str, ModelCandidate] = {}
        self._load_candidates()

    def _load_candidates(self) -> None:
        """Loads candidate models from model_profiles.json."""
        if not os.path.exists(self.profiles_path):
            return

        with open(self.profiles_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        profiles = data.get("profiles", {})
        headroom = float(data.get("headroom_mb", 512.0))

        for name, p in profiles.items():
            self.candidates[name] = ModelCandidate(
                name=name,
                display_name=p.get("display_name", name),
                kind="local",
                data_leaves_machine=False,
                host_delta_mb=float(p.get("host_delta_mb", 1024.0)),
                headroom_mb=headroom,
                thinking_default=bool(p.get("thinking_default", False)),
                requires_opt_in=(name == "gemma4:e2b"),
                opt_in_flag="gemma4_opt_in" if name == "gemma4:e2b" else "",
                tags=p.get("tags", []),
            )

    def register_candidate(self, candidate: ModelCandidate) -> None:
        """Dynamically registers a local or cloud candidate model."""
        self.candidates[candidate.name] = candidate

    @staticmethod
    def resolve_task_class(command: str, context: Optional[str] = None) -> str:
        """
        Resolves task class strictly from CLI command name.
        T21 Defense: context is NEVER inspected to infer task class.
        """
        cmd_clean = command.strip().lower() if command else "docs"
        return COMMAND_TO_TASK_CLASS.get(cmd_clean, "docs")

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
        """
        if candidate.kind == "cloud":
            return True, "CLOUD_NO_HOST_RAM_REQUIRED"

        # Hysteresis: model already loaded into memory
        if resident_model and resident_model == candidate.name:
            return True, "HYSTERESIS_WARM_BYPASS"

        if avail_ram_mb is None:
            return False, "RAM_TELEMETRY_UNAVAILABLE"

        min_req = candidate.min_available_ram_mb
        if avail_ram_mb >= min_req:
            return True, f"RAM_FIT (avail {avail_ram_mb:.1f} MB >= req {min_req:.1f} MB)"
        else:
            return False, f"INSUFFICIENT_RAM (need {min_req:.1f} MB, avail {avail_ram_mb:.1f} MB)"

    def route(
        self,
        command: str,
        context: Optional[str] = None,
        budget: Optional[HardwareBudget] = None,
        resident_model: Optional[str] = None,
        gemma4_opt_in: bool = False,
        allow_cloud: bool = False,
    ) -> RouteDecision:
        """
        Executes adaptive routing decision based on hardware constraints and task class.
        """
        task_class = self.resolve_task_class(command, context=context)

        # Extract telemetry parameters
        avail_ram_mb = budget.avail_ram_mb if budget else None
        tier = budget.compute_tier if budget else "BALANCED"
        reasons = list(budget.reasons) if budget else []

        reason_codes: List[str] = []
        rejected_models: List[Dict[str, str]] = []
        switches_count = 0

        # Define candidate preference lists by task class
        if task_class == "code":
            preferred_candidates = ["qwen2.5-coder:7b", "qwen2.5-coder:1.5b"]
        elif task_class == "chat":
            preferred_candidates = ["qwen3.5:4b", "llama3.2:3b", "qwen2.5-coder:1.5b"]
        else:
            # "docs", "analyze", "web", "forecast": unmeasured class in doc benchmarks
            # Accept any loaded code model or general model
            preferred_candidates = ["qwen2.5-coder:7b", "qwen2.5-coder:1.5b", "qwen3.5:4b", "llama3.2:3b"]

        # -------------------------------------------------------------
        # 1. Sticky Resident Check (Avoiding 8-18s Cold Switching Cost)
        # -------------------------------------------------------------
        if resident_model and resident_model in self.candidates:
            res_cand = self.candidates[resident_model]
            if resident_model in preferred_candidates:
                fit, fit_msg = self.check_candidate_fit(res_cand, avail_ram_mb, resident_model=resident_model)
                if fit:
                    # Downgrade check for code tasks: if tier is COMPRESSED or battery low,
                    # resident 7B should still downgrade to 1.5B for power/resource preservation.
                    downgrade_needed = False
                    if task_class == "code" and resident_model == "qwen2.5-coder:7b":
                        if tier == "COMPRESSED":
                            downgrade_needed = True
                            rejected_models.append({resident_model: "resident 7B evicted: tier is COMPRESSED"})
                        elif "low-battery" in reasons:
                            downgrade_needed = True
                            rejected_models.append({resident_model: "resident 7B evicted: low battery"})

                    if not downgrade_needed:
                        reason_codes.append("STICKY_RESIDENT")
                        if task_class in ("docs", "analyze", "web", "forecast"):
                            reason_codes.append("UNMEASURED_CLASS")
                        reason_codes.append(fit_msg)
                        return RouteDecision(
                            selected_model=res_cand.name,
                            kind=res_cand.kind,
                            data_leaves_machine=res_cand.data_leaves_machine,
                            task_class=task_class,
                            reason_codes=reason_codes,
                            rejected_models=rejected_models,
                            switches_count=0,
                            thinking_mode=res_cand.thinking_default,
                            explanation=f"Retained resident model '{res_cand.name}' to avoid cold loading latency.",
                        )

        # -------------------------------------------------------------
        # 2. Routing Policy: Code Tasks
        # -------------------------------------------------------------
        if task_class == "code":
            c7b = self.candidates.get("qwen2.5-coder:7b")
            c1b = self.candidates.get("qwen2.5-coder:1.5b")

            # Try primary 7B coding model
            can_use_7b = True
            c7b_rejection = []

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
                fit_7b, msg_7b = self.check_candidate_fit(c7b, avail_ram_mb, resident_model=resident_model)
                if not fit_7b:
                    can_use_7b = False
                    c7b_rejection.append(msg_7b)

            if can_use_7b and c7b:
                switches_count = 1 if resident_model != c7b.name else 0
                reason_codes.extend(["RAM_FIT", "PRIMARY_CODE_CANDIDATE"])
                return RouteDecision(
                    selected_model=c7b.name,
                    kind=c7b.kind,
                    data_leaves_machine=c7b.data_leaves_machine,
                    task_class=task_class,
                    reason_codes=reason_codes,
                    rejected_models=rejected_models,
                    switches_count=switches_count,
                    thinking_mode=False,
                    explanation=f"Selected primary coding model '{c7b.name}' (sufficient headroom and AC power).",
                )

            # Record rejection of 7B
            if c7b:
                rejected_models.append({c7b.name: "; ".join(c7b_rejection) if c7b_rejection else "downgraded"})

            # Fallback to 1.5B coding model
            if c1b:
                fit_1b, msg_1b = self.check_candidate_fit(c1b, avail_ram_mb, resident_model=resident_model)
                if fit_1b:
                    switches_count = 1 if resident_model != c1b.name else 0
                    reason_codes.extend(["RAM_FIT_FALLBACK", "LIGHTWEIGHT_CODE_CANDIDATE"])
                    return RouteDecision(
                        selected_model=c1b.name,
                        kind=c1b.kind,
                        data_leaves_machine=c1b.data_leaves_machine,
                        task_class=task_class,
                        reason_codes=reason_codes,
                        rejected_models=rejected_models,
                        switches_count=switches_count,
                        thinking_mode=False,
                        explanation=f"Graceful degradation to '{c1b.name}' due to hardware/power constraints.",
                    )
                else:
                    rejected_models.append({c1b.name: msg_1b})

            # Refusal: No candidate fits
            reason_codes.append("INSUFFICIENT_HEADROOM")
            return RouteDecision(
                selected_model=None,
                kind="none",
                data_leaves_machine=False,
                task_class=task_class,
                reason_codes=reason_codes,
                rejected_models=rejected_models,
                switches_count=0,
                thinking_mode=False,
                explanation="Refused: Available RAM is insufficient for all local coding models.",
            )

        # -------------------------------------------------------------
        # 3. Routing Policy: Chat / Singlish / Explain Tasks
        # -------------------------------------------------------------
        elif task_class == "chat":
            # Check gemma4 opt-in
            cgemma = self.candidates.get("gemma4:e2b")
            if cgemma:
                if not gemma4_opt_in:
                    rejected_models.append({
                        cgemma.name: "OPT_IN_REQUIRED (Gemma consumes 2.93 GB host RAM, requires explicit owner opt-in)"
                    })
                else:
                    fit_gemma, msg_gemma = self.check_candidate_fit(cgemma, avail_ram_mb, resident_model=resident_model)
                    if fit_gemma and avail_ram_mb and avail_ram_mb >= 3500.0:
                        switches_count = 1 if resident_model != cgemma.name else 0
                        reason_codes.extend(["OWNER_OPT_IN", "RAM_FIT"])
                        return RouteDecision(
                            selected_model=cgemma.name,
                            kind=cgemma.kind,
                            data_leaves_machine=cgemma.data_leaves_machine,
                            task_class=task_class,
                            reason_codes=reason_codes,
                            rejected_models=rejected_models,
                            switches_count=switches_count,
                            thinking_mode=False,
                            explanation=f"Selected '{cgemma.name}' under explicit owner opt-in and high RAM.",
                        )
                    else:
                        rejected_models.append({cgemma.name: msg_gemma})

            # Primary chat candidate: qwen3.5:4b (think: false)
            c4b = self.candidates.get("qwen3.5:4b")
            if c4b:
                fit_4b, msg_4b = self.check_candidate_fit(c4b, avail_ram_mb, resident_model=resident_model)
                if fit_4b and tier != "COMPRESSED" and "low-battery" not in reasons:
                    switches_count = 1 if resident_model != c4b.name else 0
                    reason_codes.extend(["RAM_FIT", "PRIMARY_CHAT_CANDIDATE"])
                    return RouteDecision(
                        selected_model=c4b.name,
                        kind=c4b.kind,
                        data_leaves_machine=c4b.data_leaves_machine,
                        task_class=task_class,
                        reason_codes=reason_codes,
                        rejected_models=rejected_models,
                        switches_count=switches_count,
                        thinking_mode=False,
                        explanation=f"Selected primary chat model '{c4b.name}' with thinking mode disabled.",
                    )
                else:
                    rejected_models.append({c4b.name: msg_4b if not fit_4b else "tier/battery pressure"})

            # Fallback 1: llama3.2:3b
            c3b = self.candidates.get("llama3.2:3b")
            if c3b:
                fit_3b, msg_3b = self.check_candidate_fit(c3b, avail_ram_mb, resident_model=resident_model)
                if fit_3b and tier != "COMPRESSED":
                    switches_count = 1 if resident_model != c3b.name else 0
                    reason_codes.extend(["RAM_FIT_FALLBACK", "INTERMEDIATE_CHAT_FALLBACK"])
                    return RouteDecision(
                        selected_model=c3b.name,
                        kind=c3b.kind,
                        data_leaves_machine=c3b.data_leaves_machine,
                        task_class=task_class,
                        reason_codes=reason_codes,
                        rejected_models=rejected_models,
                        switches_count=switches_count,
                        thinking_mode=False,
                        explanation=f"Fallback to '{c3b.name}' due to RAM or power constraints on 4B.",
                    )
                else:
                    rejected_models.append({c3b.name: msg_3b if not fit_3b else "tier is COMPRESSED"})

            # Fallback 2: qwen2.5-coder:1.5b
            c1b = self.candidates.get("qwen2.5-coder:1.5b")
            if c1b:
                fit_1b, msg_1b = self.check_candidate_fit(c1b, avail_ram_mb, resident_model=resident_model)
                if fit_1b:
                    switches_count = 1 if resident_model != c1b.name else 0
                    reason_codes.extend(["LIGHTWEIGHT_FALLBACK"])
                    return RouteDecision(
                        selected_model=c1b.name,
                        kind=c1b.kind,
                        data_leaves_machine=c1b.data_leaves_machine,
                        task_class=task_class,
                        reason_codes=reason_codes,
                        rejected_models=rejected_models,
                        switches_count=switches_count,
                        thinking_mode=False,
                        explanation=f"Lightweight fallback to '{c1b.name}' under heavy memory pressure.",
                    )
                else:
                    rejected_models.append({c1b.name: msg_1b})

            # Refusal
            reason_codes.append("INSUFFICIENT_HEADROOM")
            return RouteDecision(
                selected_model=None,
                kind="none",
                data_leaves_machine=False,
                task_class=task_class,
                reason_codes=reason_codes,
                rejected_models=rejected_models,
                switches_count=0,
                thinking_mode=False,
                explanation="Refused: Available RAM is insufficient for all chat candidates.",
            )

        # -------------------------------------------------------------
        # 4. Routing Policy: Docs / Analyze / Web / Forecast Tasks
        # -------------------------------------------------------------
        else:
            # Unmeasured class: doc scores do not discriminate models.
            # Prefer active coding model or general 4B, marked with UNMEASURED_CLASS.
            reason_codes.append("UNMEASURED_CLASS")

            # Selection order: 7B (if fits and high resources) -> 1.5B (lightweight) -> 4B
            c7b = self.candidates.get("qwen2.5-coder:7b")
            if c7b and tier != "COMPRESSED" and "low-battery" not in reasons:
                fit_7b, msg_7b = self.check_candidate_fit(c7b, avail_ram_mb, resident_model=resident_model)
                if fit_7b:
                    switches_count = 1 if resident_model != c7b.name else 0
                    reason_codes.append("RAM_FIT")
                    return RouteDecision(
                        selected_model=c7b.name,
                        kind=c7b.kind,
                        data_leaves_machine=c7b.data_leaves_machine,
                        task_class=task_class,
                        reason_codes=reason_codes,
                        rejected_models=rejected_models,
                        switches_count=switches_count,
                        thinking_mode=False,
                        explanation=f"Selected '{c7b.name}' for unmeasured class '{task_class}'.",
                    )
                else:
                    rejected_models.append({c7b.name: msg_7b})

            # Fallback to 1.5B
            c1b = self.candidates.get("qwen2.5-coder:1.5b")
            if c1b:
                fit_1b, msg_1b = self.check_candidate_fit(c1b, avail_ram_mb, resident_model=resident_model)
                if fit_1b:
                    switches_count = 1 if resident_model != c1b.name else 0
                    reason_codes.append("LIGHTWEIGHT_FALLBACK")
                    return RouteDecision(
                        selected_model=c1b.name,
                        kind=c1b.kind,
                        data_leaves_machine=c1b.data_leaves_machine,
                        task_class=task_class,
                        reason_codes=reason_codes,
                        rejected_models=rejected_models,
                        switches_count=switches_count,
                        thinking_mode=False,
                        explanation=f"Selected lightweight '{c1b.name}' for unmeasured class '{task_class}'.",
                    )
                else:
                    rejected_models.append({c1b.name: msg_1b})

            # Refusal
            reason_codes.append("INSUFFICIENT_HEADROOM")
            return RouteDecision(
                selected_model=None,
                kind="none",
                data_leaves_machine=False,
                task_class=task_class,
                reason_codes=reason_codes,
                rejected_models=rejected_models,
                switches_count=0,
                thinking_mode=False,
                explanation=f"Refused: Available RAM is insufficient for '{task_class}'.",
            )
