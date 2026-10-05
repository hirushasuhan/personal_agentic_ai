"""
Personal Agentic AI (PAI) - Research Prototype CLI

Interactive:   python main.py
Scriptable:    python main.py --telemetry [--json]
               python main.py --ask "Explain Rust ownership" [--lang si] [--transport raw] [--json]
               python main.py --ask "Summarize" --topic "ශ්‍රී ලංකාව" --lang si   # explicit topic, any language
               python main.py --benchmark [--iterations 8] [--online]
               python main.py --check-code patch.py
"""

import argparse
import json
import sys
from dataclasses import asdict

# Ensure UTF-8 console output if supported (Windows consoles, Sinhala text)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from agent_core import StatelessAgentCore
from ast_guard import check_source
from benchmark import OfflineNetwork, run_purge_benchmark
from hardware_telemetry import HardwareTelemetry, format_snapshot
from local_knowledge import CompositeKnowledge, LocalKnowledge
from network_pipeline import NetworkPipeline
from outbound_policy import DEFAULT_ALLOWED_DOMAINS, OutboundPolicy
from reasoner import LocalLLMReasoner, NeuroSymbolicReasoner, TemplateReasoner

BANNER = """
========================================================================
             PERSONAL AGENTIC AI (PAI) - RESEARCH LAB v0.2
    A Stateless, Hardware-Aware, Recursive Self-Improving Intelligence
========================================================================
    [Pillar 1] Stateless Pure Reasoning Engine   (Reasoner = STUB in Phase 1; ADR-001)
    [Pillar 2] Hardware Self-Awareness Daemon
    [Pillar 3] Direct Network Ingestion Pipeline (SSRF-guarded)
========================================================================
"""


def show_hardware_status(telemetry: HardwareTelemetry, as_json: bool = False) -> None:
    snap = telemetry.get_system_snapshot()
    if as_json:
        print(json.dumps(HardwareTelemetry.to_ipc_dict(snap), indent=2))
        return
    print("\n--- [HARDWARE TELEMETRY SNAPSHOT] ---")
    print(format_snapshot(snap))
    print("-" * 55)


def run_task(agent: StatelessAgentCore, query: str, as_json: bool = False, topic: str = None) -> int:
    result = agent.execute_task(query, topic_hint=topic)
    if as_json:
        print(json.dumps(asdict(result), indent=2, ensure_ascii=False))
        return 0 if result.status != "ERROR" else 1
    print("\n" + "=" * 55)
    print(result.synthesized_output or "(no output)")
    print("=" * 55)
    print(f"Status              : {result.status} {result.ingestion_note or result.error}")
    print(f"Latency             : {result.execution_time_sec}s")
    print(f"Hardware Tier       : {result.hardware_tier}")
    print(f"Peak Ephemeral RAM  : {result.peak_ephemeral_bytes} Bytes")
    p = result.purge
    print(f"Purge (verified)    : {result.memory_purged_successfully} - {p.bytes_wiped} B zeroed in {p.buffers_wiped} buffer(s)")
    print("=" * 55)
    return 0 if result.status != "ERROR" else 1


def run_benchmark(agent_factory, iterations: int, online: bool) -> int:
    print("\n--- [STATELESS PURGE BENCHMARK] ---")
    print(f"Mode: {'ONLINE (real network)' if online else 'OFFLINE (deterministic payloads)'} | iterations: {iterations}")
    rep = run_purge_benchmark(agent_factory(), iterations=iterations)
    print(f"All purges verified zeroed : {rep.all_purges_verified}")
    print(f"Retained Python allocations: {rep.retained_bytes_after_warmup} B (tolerance {rep.tolerance_bytes} B)")
    print(f"Peak ephemeral per task    : {rep.peak_ephemeral_bytes} B")
    print(f"Mean latency               : {sum(rep.per_iteration_ms) / max(1, len(rep.per_iteration_ms)):.1f} ms")
    print("RESULT:", "PASS" if rep.passed else "FAIL")
    return 0 if rep.passed else 1


def run_code_check(path: str) -> int:
    with open(path, encoding="utf-8") as f:
        rep = check_source(f.read())
    print("Tier-1 AST guard:", "PASS" if rep.ok else "REJECT")
    for x in rep.violations:
        print("  violation:", x)
    for x in rep.warnings:
        print("  warning  :", x)
    return 0 if rep.ok else 1


def interactive(telemetry, agent_factory, lang, transport) -> None:
    print(BANNER)
    agent = agent_factory()
    while True:
        print("\nChoose an action:")
        print("  1. Inspect Live Hardware Telemetry")
        print("  2. Run an Agentic Task (Direct HTTP + Reasoning)")
        print("  3. Run Stateless Purge Benchmark (offline)")
        print("  4. Check a Python patch with the Tier-1 AST guard")
        print("  5. Exit")
        try:
            choice = input("\nSelect (1-5): ").strip()
            if choice == "1":
                show_hardware_status(telemetry)
            elif choice == "2":
                q = input("PAI > ").strip()
                if q:
                    run_task(agent, q)
                else:
                    print("Query cannot be empty.")
            elif choice == "3":
                run_benchmark(lambda: StatelessAgentCore(telemetry=telemetry, network=OfflineNetwork()), 8, online=False)
            elif choice == "4":
                run_code_check(input("Path to .py file > ").strip())
            elif choice == "5":
                break
            else:
                print("Invalid choice, please select 1-5.")
        except (EOFError, KeyboardInterrupt):
            break
        except OSError as e:
            print(f"File error: {e}")
    print("\nExiting Personal Agentic AI Research Lab. Goodbye!")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Personal Agentic AI research prototype")
    ap.add_argument("--telemetry", action="store_true", help="print hardware telemetry and exit")
    ap.add_argument("--ask", metavar="QUERY", help="run one stateless task and exit")
    ap.add_argument("--topic", metavar="TOPIC", help="explicit lookup topic for --ask (bypasses the English trigger phrases)")
    ap.add_argument("--model-url", metavar="URL", help="use a LOCAL OpenAI-compatible model server (e.g. http://127.0.0.1:11434/v1); loopback only")
    ap.add_argument("--model", default="local", help="model name sent to the local server")
    ap.add_argument("--offline", action="store_true", help="forbid ALL network access (use --knowledge-dir for local answers)")
    ap.add_argument("--knowledge-dir", metavar="DIR", help="answer from local .txt/.md files first (private, no network)")
    ap.add_argument("--allow-domain", action="append", default=[], metavar="DOMAIN", help="extend the outbound allow-list (repeatable)")
    ap.add_argument("--show-outbound", action="store_true", help="print every outbound request after the run")
    ap.add_argument("--benchmark", action="store_true", help="run the purge benchmark and exit")
    ap.add_argument("--check-code", metavar="FILE", help="run the Tier-1 AST guard on a Python file")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--lang", default="en", help="Wikipedia language edition, e.g. en, si, ta (default en)")
    ap.add_argument("--transport", choices=["urllib", "raw"], default="urllib", help="HTTP transport (raw = experimental)")
    ap.add_argument("--iterations", type=int, default=8, help="benchmark iterations")
    ap.add_argument("--online", action="store_true", help="benchmark against the real network")
    ap.add_argument("--reasoner", choices=["template", "symbolic", "local"], default="template",
                    help="reasoning engine: template (default honest stub; ADR-001), symbolic (experimental research prototype), local (OpenAI-compatible server)")
    args = ap.parse_args(argv)

    telemetry = HardwareTelemetry()
    policy = OutboundPolicy(allowed_domains=DEFAULT_ALLOWED_DOMAINS + tuple(args.allow_domain), offline=args.offline)

    def agent_factory(offline: bool = False) -> StatelessAgentCore:
        if offline:
            net = OfflineNetwork()
        else:
            net = NetworkPipeline(transport=args.transport, policy=policy)
            if args.knowledge_dir:
                net = CompositeKnowledge([LocalKnowledge(args.knowledge_dir), net])

        if args.model_url or args.reasoner == "local":
            reasoner = LocalLLMReasoner(args.model_url or "http://127.0.0.1:11434/v1", args.model)
        elif args.reasoner == "symbolic":
            reasoner = NeuroSymbolicReasoner()
        else:
            reasoner = TemplateReasoner()

        return StatelessAgentCore(telemetry=telemetry, network=net, lang=args.lang, reasoner=reasoner)

    if args.telemetry:
        show_hardware_status(telemetry, args.json)
        return 0
    if args.ask:
        code = run_task(agent_factory(), args.ask, args.json, args.topic)
        if args.show_outbound and not args.json:
            print(policy.format_log())
        return code
    if args.benchmark:
        return run_benchmark(lambda: agent_factory(offline=not args.online), args.iterations, args.online)
    if args.check_code:
        return run_code_check(args.check_code)

    interactive(telemetry, agent_factory, args.lang, args.transport)
    return 0


if __name__ == "__main__":
    sys.exit(main())
