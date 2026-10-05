"""
Stateless-purge benchmark that MEASURES instead of asserting.

Runs N cycles against an offline (deterministic) knowledge source, tracks Python-level
allocations with tracemalloc, and passes only if (a) every purge verified all-zero and
(b) retained allocations after warm-up stay under a tolerance. `--online` in main.py
swaps in the real network.
"""

from __future__ import annotations

import tracemalloc
from dataclasses import dataclass, field
from typing import List

from agent_core import StatelessAgentCore
from data_verifier import VerifiedPayload

DEFAULT_QUERIES = [
    "Explain Rust borrow checker",
    "Explain C++ memory alignment",
    "What is Recursive Self Improvement in AI",
    "Explain Mamba State Space Models",
]


class OfflineNetwork:
    """Deterministic stand-in for NetworkPipeline (no sockets). Payload ~ `size_kb` KiB."""

    def __init__(self, size_kb: int = 256):
        self.size_kb = size_kb

    def query_live_knowledge(self, topic: str, max_bytes: int = 1 << 20, lang: str = "en") -> VerifiedPayload:
        sentence = f"{topic} is discussed here with varied vocabulary number %d about systems memory and reasoning. "
        text = "".join(sentence % i for i in range(self.size_kb * 1024 // 100))
        text = text[:max_bytes]
        return VerifiedPayload(True, 0.9, text, len(text), len(text), source="offline")


@dataclass
class BenchmarkReport:
    iterations: int
    all_purges_verified: bool
    retained_bytes_after_warmup: int
    tolerance_bytes: int
    per_iteration_ms: List[float] = field(default_factory=list)
    peak_ephemeral_bytes: int = 0

    @property
    def passed(self) -> bool:
        return self.all_purges_verified and self.retained_bytes_after_warmup <= self.tolerance_bytes


def run_purge_benchmark(agent: StatelessAgentCore, queries: List[str] = None, iterations: int = 8,
                        tolerance_bytes: int = 256 * 1024) -> BenchmarkReport:
    queries = queries or DEFAULT_QUERIES
    started_here = not tracemalloc.is_tracing()
    if started_here:
        tracemalloc.start()
    try:
        agent.execute_task(queries[0])  # warm-up (imports, caches)
        baseline = tracemalloc.get_traced_memory()[0]
        all_ok, peak, times = True, 0, []
        for i in range(iterations):
            res = agent.execute_task(queries[i % len(queries)])
            all_ok &= res.memory_purged_successfully and res.status != "ERROR"
            peak = max(peak, res.peak_ephemeral_bytes)
            times.append(res.execution_time_sec * 1000)
        retained = tracemalloc.get_traced_memory()[0] - baseline
        return BenchmarkReport(iterations, all_ok, retained, tolerance_bytes, times, peak)
    finally:
        if started_here:
            tracemalloc.stop()
