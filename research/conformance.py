"""
Language-neutral conformance vectors (review risk R6, ADR-004).

The Python prototype is the executable specification. Instead of re-reading prose, the Rust core and the
C++ daemon prove they match it by passing these golden vectors:

  conformance/tier_policy_vectors.json  inputs -> expected hardware budget       (telemetry policy)
  conformance/url_policy_vectors.json   URL    -> accept / reject                (outbound policy, IP literals only: no DNS needed)

`python conformance.py` regenerates them; tests/test_conformance.py fails if they drift from the code,
so a policy change is always a deliberate, reviewed vector change.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List

from hardware_telemetry import HardwareTelemetry
from net_guard import UrlRejected, validate_url

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "conformance")

URL_CASES = [
    # (url, expected)  - IP literals only so results never depend on DNS
    ("http://8.8.8.8/", "accept"), ("https://1.1.1.1/dns-query", "accept"), ("https://8.8.8.8:443/x", "accept"),
    ("http://[2606:4700:4700::1111]/", "accept"),
    ("file:///etc/passwd", "reject"), ("ftp://8.8.8.8/", "reject"), ("gopher://8.8.8.8/", "reject"),
    ("javascript:alert(1)", "reject"), ("", "reject"), ("http:///nohost", "reject"),
    ("http://127.0.0.1/", "reject"), ("http://[::1]/", "reject"), ("http://0.0.0.0/", "reject"),
    ("http://10.0.0.5/", "reject"), ("http://172.16.0.1/", "reject"), ("http://192.168.1.1/", "reject"),
    ("http://169.254.169.254/latest/meta-data/", "reject"), ("http://100.64.0.1/", "reject"),
    ("http://224.0.0.1/", "reject"), ("http://[fe80::1]/", "reject"), ("http://[fc00::1]/", "reject"),
    ("http://[::ffff:127.0.0.1]/", "reject"), ("http://[::ffff:10.0.0.1]/", "reject"),
    ("https://user:pw@8.8.8.8/", "reject"), ("https://user@8.8.8.8/", "reject"),
    ("http://8.8.8.8:8080/", "reject"), ("http://8.8.8.8:22/", "reject"), ("http://8.8.8.8:99999/", "reject"),
]


def tier_policy_vectors() -> List[Dict[str, Any]]:
    t = HardwareTelemetry(cpu_sample_ms=0)
    cases: List[Dict[str, Any]] = []

    def add(avail, load, cpu, battery, cores):
        t.cpu_count = cores
        b = t._calculate_budget(avail, load, cpu, battery)
        cases.append({
            "input": {"avail_ram_mb": avail, "memory_load_pct": load, "cpu_load_pct": cpu, "battery": battery, "cpu_cores": cores},
            "expected": {"compute_tier": b.compute_tier, "max_context_bytes": b.max_context_bytes,
                         "allow_speculation": b.allow_speculation, "thread_pool_limit": b.thread_pool_limit,
                         "reasons": b.reasons},
        })

    for avail in (None, 100, 511.9, 512, 1500, 2047.9, 2048, 8000):
        for load in (None, 10, 74, 75, 89, 90, 100):
            add(avail, load, None, None, 8)
    batteries = (None, {"percent": 10, "on_ac": False}, {"percent": 10, "on_ac": True}, {"percent": 50, "on_ac": False})
    for avail in (100, 1500, 8000):
        for load in (10, 80):
            for bat in batteries:
                for cpu in (None, 95):
                    for cores in (1, 2, 8):
                        add(avail, load, cpu, bat, cores)
    return cases


def url_policy_vectors() -> List[Dict[str, str]]:
    out = []
    for url, expected in URL_CASES:
        out.append({"url": url, "expected": expected})
    return out


def evaluate_url(url: str) -> str:
    try:
        validate_url(url)
        return "accept"
    except UrlRejected:
        return "reject"


def write_vectors(directory: str = OUT_DIR) -> None:
    os.makedirs(directory, exist_ok=True)
    for name, data in (("tier_policy_vectors.json", tier_policy_vectors()), ("url_policy_vectors.json", url_policy_vectors())):
        with open(os.path.join(directory, name), "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=1, sort_keys=True)
            f.write("\n")


if __name__ == "__main__":
    write_vectors()
    print(f"wrote {len(tier_policy_vectors())} tier vectors and {len(url_policy_vectors())} URL vectors to {OUT_DIR}")
    sys.exit(0)
