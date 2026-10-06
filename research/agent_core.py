"""
Stateless Agent Core (Python Research Prototype)
Part of Personal Agentic AI (PAI) - The Pure Reasoning Engine.

4-phase cognitive cycle:
  1. Perceive (Hardware Telemetry & Resource Budgeting)
  2. Ingest   (Direct Browserless Network Pipeline -> SecureBuffer)
  3. Reason   (pluggable Reasoner; Phase 1 = stub)
  4. Purge    (wipe + VERIFY all ephemeral buffers - runs even if a step raised)
"""

from __future__ import annotations

import gc
import re
import secrets
import time
import tracemalloc
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from hardware_telemetry import HardwareTelemetry, HardwareBudget
from memory_probe import rss_bytes
from network_pipeline import NetworkPipeline
from reasoner import Reasoner, TemplateReasoner
from secure_buffer import SecureBuffer

_TRIGGER = re.compile(
    r"^\s*(?:what is|what are|who is|who was|explain|research|how does|summari[sz]e|tell me about)\s+(.+?)[\s?.!]*$",
    re.IGNORECASE,
)


@dataclass
class PurgeReport:
    buffers_wiped: int = 0
    bytes_wiped: int = 0
    all_zeroed: bool = True            # every buffer verified all-zero before release
    gc_collected: int = 0
    rss_delta_bytes: Optional[int] = None        # process RSS after - before (noisy, informational)
    py_alloc_delta_bytes: Optional[int] = None   # tracemalloc delta (only when tracing is active)


@dataclass
class AgentExecutionResult:
    status: str                      # SUCCESS | DEGRADED (no external context) | ERROR
    user_query: str
    synthesized_output: str
    hardware_tier: str
    telemetry_summary: Dict[str, Any]
    ingested_sources: List[str]
    peak_ephemeral_bytes: int
    memory_purged_successfully: bool
    execution_time_sec: float
    ingestion_note: str = ""
    error: str = ""
    reasoner_name: str = ""
    context_tainted: bool = False    # True if untrusted external data was in the reasoning context (-> capabilities.ToolBroker)
    purge: PurgeReport = field(default_factory=PurgeReport)


class StatelessAgentCore:
    def __init__(self, telemetry: Optional[HardwareTelemetry] = None, network: Optional[NetworkPipeline] = None,
                 reasoner: Optional[Reasoner] = None, lang: str = "en"):
        self.telemetry = telemetry or HardwareTelemetry()
        self.network = network or NetworkPipeline()
        self.reasoner: Reasoner = reasoner or TemplateReasoner()
        self.lang = lang

    def execute_task(self, query: str, topic_hint: Optional[str] = None) -> AgentExecutionResult:
        """Runs one stateless cycle. The purge runs in `finally`, so it also runs when a step raises."""
        t0 = time.perf_counter()
        rss0 = rss_bytes()
        tm0 = tracemalloc.get_traced_memory()[0] if tracemalloc.is_tracing() else None

        buffers: Dict[str, SecureBuffer] = {}
        sources: List[str] = []
        status, note, error, output = "SUCCESS", "", "", ""
        peak = 0
        tainted = False
        tier, summary = "UNKNOWN", {}

        try:
            # 1. PERCEIVE
            snap = self.telemetry.get_system_snapshot()
            budget: HardwareBudget = snap["budget"]
            tier = budget.compute_tier
            summary = {"load_pct": snap["memory_load_pct"], "avail_ram_mb": snap["avail_ram_mb"],
                       "cpu_load_pct": snap["cpu_load_pct"], "tier": tier, "note": budget.throttle_warning,
                       "reasons": list(budget.reasons)}

            # 2. INGEST
            topic = topic_hint or self._extract_topic_intent(query)
            run_nonce = secrets.token_hex(8)
            if topic:
                payload = self.network.query_live_knowledge(topic, max_bytes=budget.max_context_bytes, lang=self.lang)
                src_name = payload.source or "web"
                sources.append(f"lookup '{topic}' ({self.lang}) -> {src_name}")
                if payload.is_valid:
                    buf = SecureBuffer(label="live_context", capacity=budget.max_context_bytes)
                    # Neutralize any attacker-injected [[SRC: tokens in incoming web text
                    safe_text = payload.sanitized_text.replace("[[SRC:", "[ [SRC:")
                    tagged_text = f"[[SRC:{run_nonce}:{src_name}]]\n{safe_text}"
                    buf.write(tagged_text)
                    buffers["live_context"] = buf
                    tainted = True
                    payload.sanitized_text = ""  # drop the extra str reference immediately
                    peak += len(buf)
                else:
                    status, note = "DEGRADED", payload.rejection_reason

            # 3. REASON
            context = buffers["live_context"].text() if "live_context" in buffers else None
            try:
                output = self.reasoner.reason(query, context, budget, nonce=run_nonce)
            except TypeError:
                output = self.reasoner.reason(query, context, budget)
            context = None
            peak += len(output.encode("utf-8"))
        except Exception as e:  # never let a failure skip the purge
            status, error = "ERROR", f"{type(e).__name__}: {e}"
        finally:
            # 4. PURGE
            purge = self._purge(buffers, rss0, tm0)

        return AgentExecutionResult(
            status=status, user_query=query, synthesized_output=output, hardware_tier=tier,
            telemetry_summary=summary, ingested_sources=sources, peak_ephemeral_bytes=peak,
            memory_purged_successfully=purge.all_zeroed and not buffers,
            execution_time_sec=round(time.perf_counter() - t0, 3),
            ingestion_note=note, error=error, reasoner_name=self.reasoner.name, purge=purge,
            context_tainted=tainted,
        )

    # ---------------------------------------------------------------- internals
    @staticmethod
    def _purge(buffers: Dict[str, SecureBuffer], rss0: Optional[int], tm0: Optional[int]) -> PurgeReport:
        rep = PurgeReport()
        for buf in buffers.values():
            rep.bytes_wiped += len(buf)
            rep.all_zeroed &= buf.wipe()
            rep.buffers_wiped += 1
        buffers.clear()
        rep.gc_collected = gc.collect()
        rss1 = rss_bytes()
        if rss0 is not None and rss1 is not None:
            rep.rss_delta_bytes = rss1 - rss0
        if tm0 is not None and tracemalloc.is_tracing():
            rep.py_alloc_delta_bytes = tracemalloc.get_traced_memory()[0] - tm0
        return rep

    @staticmethod
    def _extract_topic_intent(query: str) -> Optional[str]:
        """Intent extractor: only a leading trigger phrase counts, original casing is preserved."""
        m = _TRIGGER.match(query)
        if m and len(m.group(1).strip()) > 2:
            return m.group(1).strip()
        return None


if __name__ == "__main__":
    core = StatelessAgentCore()
    print("Testing StatelessAgentCore with live query...")
    r = core.execute_task("Explain Rust programming language")
    print(r.synthesized_output)
    print("\n--- Execution Telemetry ---")
    print(f"Status: {r.status} {r.ingestion_note or r.error}")
    print(f"Hardware Tier: {r.hardware_tier} (RAM Load: {r.telemetry_summary.get('load_pct')}%)")
    print(f"Sources: {r.ingested_sources}")
    print(f"Peak Ephemeral RAM: {r.peak_ephemeral_bytes} Bytes")
    print(f"Purge verified zeroed: {r.memory_purged_successfully} ({r.purge.bytes_wiped} B in {r.purge.buffers_wiped} buffers)")
    print(f"Execution Latency: {r.execution_time_sec}s")
