# Personal Agentic AI (PAI)

> **A Stateless, Hardware-Aware, Recursive Self-Improving Personal Intelligence Engine**

**Status (2026-10-05):** Phase 1 (Python research prototype) implemented and hardened — 140 passing unit tests, the seven strategic risks from the review remediated (ADRs 001–006), exit gate pending Windows validation. See [Roadmap](docs/ROADMAP.md) · [Project Review](docs/PROJECT_REVIEW.md) · [Threat Model](docs/THREAT_MODEL.md) · [Decisions (ADRs)](docs/adr/README.md).

---

## 🌟 Executive Summary

**Personal Agentic AI** is a novel, high-efficiency personal intelligence system built from first principles. Unlike conventional Large Language Models (LLMs) that store hundreds of gigabytes of memorized factual knowledge in static weights, Personal Agentic AI is designed around a **Stateless Reasoning Core**. It treats intelligence as an executable logic machine rather than an encyclopedia, acquiring knowledge dynamically via low-level network pipelines and executing autonomously with hardware self-awareness.

The system is developed across a synergistic three-tier language architecture:
1. **Rust (`core/`)**: High-performance, memory-safe stateless reasoning engine and hot-swappable algorithm core.
2. **C / C++ (`hardware/`)**: Low-level hardware telemetry daemon (CPU, GPU, NPU, RAM) and zero-overhead raw socket networking.
3. **Python (`research/`)**: Dynamic research prototyping, agentic tool workflows, data verification pipelines, and algorithmic testbeds.

---

## 🏛️ The Three Architectural Pillars

```
+-------------------------------------------------------------------------+
|                       Personal Agentic AI System                        |
+-------------------------------------------------------------------------+
|  1. Stateless Logic Core (Rust)                                         |
|     - Zero factual memorization footprint                               |
|     - Fast cognitive grammar & intent decomposition                     |
|     - Instant working-memory purge after task execution                 |
+-------------------------------------------------------------------------+
|  2. Hardware Self-Awareness Daemon (C/C++)                              |
|     - Real-time telemetry: CPU load, RAM pressure, NPU/GPU availability |
|     - Dynamic precision throttling (8-bit <-> 4-bit) under pressure     |
|     - Thermal and battery-aware compute budgeting                       |
+-------------------------------------------------------------------------+
|  3. Direct Network Ingestion Pipeline (C++/Rust)                        |
|     - Direct TCP/HTTP/WebSocket sockets bypassing heavy headless browsers|
|     - High-speed binary/text data streaming                             |
|     - Inline heuristic data verification and sanitization               |
+-------------------------------------------------------------------------+
```

1. **Stateless Logic Core**: The AI algorithm does not store factual databases inside weight parameters. It possesses linguistic structure, reasoning paths, and code generation faculties. All facts are ingested dynamically, processed within temporary RAM, and immediately scrubbed upon task completion.
2. **Hardware Self-Awareness**: The agent actively monitors the host machine's hardware state. If host RAM is strained, the engine compresses computation or offloads tasks; if an NPU/GPU is present, it routes matrix algebra to accelerated silicon.
3. **Direct Network Ingestion**: Instead of using heavy headless browsers (Chromium/Puppeteer), the agent speaks directly to internet protocols over raw sockets, parsing raw HTML/JSON directly into working memory in milliseconds.
4. **Safe Recursive Self-Improvement (RSI)**: The AI is engineered with coding as its primary skill. It iteratively improves its own performance through isolated sandboxes, adversarial auditing and scoped verification before a *signed* hot-swap of its executable engine.

> **Security stance:** the project aims for *defense in depth*, not an absolute-security promise. Every guarantee is tied to a named test or a named residual risk in [THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## 📁 Repository Structure

```tree
personal_agentic_ai/
│
├── README.md
├── CHANGELOG.md                  # What changed and why
├── docs/
│   ├── ARCHITECTURE.md           # Architecture, IPC + telemetry schema v1, prototype-vs-production table
│   ├── ROADMAP.md                # Phases 1-5, exit criteria, decision gates, risks
│   ├── RSI_SAFETY_SPEC.md        # Recursive self-improvement safety tiers + known weaknesses
│   ├── PROTOTYPE_SPEC.md         # Python prototype specification (matches the code)
│   ├── THREAT_MODEL.md           # Assets, trust boundaries, threat register T1-T12
│   ├── PROJECT_REVIEW.md         # Review findings, strategic risks, remediation status
│   ├── CONSTITUTION.md           # Safety Constitution v0.1 (hash pinned in the updater's trust root)
│   └── adr/                      # Architecture Decision Records 001-006
│
├── core/                         # Rust Engine (Phase 3)
├── hardware/                     # C / C++ Daemon (Phase 2)
│
└── research/                     # Python Prototype & Verification Lab (Phase 1)
    ├── main.py                   # CLI: interactive menu + scriptable flags
    ├── agent_core.py             # Perceive -> Ingest -> Reason -> Purge loop
    ├── reasoner.py               # Reasoner interface + stub (the future "brain" seam)
    ├── hardware_telemetry.py     # RAM / CPU / battery -> adaptive budget (tier policy)
    ├── network_pipeline.py       # Direct HTTP(S) ingestion (Wikipedia / DuckDuckGo)
    ├── net_guard.py              # Outbound URL policy (SSRF / file:// protection)
    ├── raw_http.py               # Experimental raw socket+TLS client (Phase 2 model)
    ├── data_verifier.py          # Sanitiser, quality scoring, injection screening
    ├── secure_buffer.py          # Wipe-and-verify working memory
    ├── memory_probe.py           # Process RSS probe
    ├── ast_guard.py              # RSI Tier-1 static code gate (prototype)
    ├── capabilities.py           # Deny-by-default tool broker, taint tracking, audit chain (ADR-006)
    ├── outbound_policy.py        # Domain allow-list, offline mode, visible outbound log (ADR-002)
    ├── local_knowledge.py        # Answer from local files, no network (ADR-002)
    ├── sandbox_policy.py         # Windows Sandbox isolation checklist as code (ADR-003)
    ├── ed25519_ref.py            # RFC 8032 verify (stdlib) for release signatures
    ├── updater.py                # Signed-release updater, anti-rollback, pinned Constitution (ADR-005)
    ├── sign_release.py           # Offline signing tool (needs `cryptography`)
    ├── conformance.py            # Golden vectors for the Rust/C++ ports (ADR-004)
    ├── conformance/              # tier_policy_vectors.json, url_policy_vectors.json
    ├── benchmark.py              # Purge benchmark that can fail
    ├── requirements.txt          # Standard library only (psutil/cryptography optional)
    └── tests/                    # 140 unit tests (stdlib unittest)
```

---

## 🚀 Quickstart: Running the Research Prototype

Requires Python 3.8+ (no packages needed).

```powershell
cd research

# Interactive menu
python main.py

# Scriptable
python main.py --telemetry                 # hardware snapshot (add --json for the IPC message)
python main.py --ask "Explain Rust ownership"
python main.py --ask "Summarize" --topic "ශ්‍රී ලංකාව" --lang si   # Sinhala Wikipedia (auto-triggers are English; --topic is explicit)
python main.py --ask "Explain Rust ownership" --model-url http://127.0.0.1:11434/v1 --model llama3.2   # real LOCAL model (loopback only)
python main.py --ask "Explain Rust ownership" --offline --knowledge-dir ~/notes    # no network at all: answer from your own files
python main.py --ask "Explain Rust ownership" --show-outbound                      # print exactly what left this machine
python main.py --benchmark                 # offline purge benchmark (add --online for real network)
python main.py --check-code patch.py       # Tier-1 AST guard on a Python file

# Tests
python -m unittest discover -s tests -v
```

The prototype demonstrates:
* Real-time hardware telemetry (Windows `kernel32`, Linux `/proc`) driving an adaptive compute budget — no invented numbers when a source is unavailable.
* Direct HTTP(S) ingestion with an outbound policy (no `file://`, no private/metadata IPs) and an experimental raw-socket transport.
* Sanitisation, Unicode-aware quality scoring and prompt-injection screening.
* The stateless cycle: **Perceive → Ingest → Reason → Purge**, where the purge is *verified* (buffers read back as all-zero) and runs even when a step fails.
* Privacy controls: domain allow-list, visible outbound log, offline mode, local-first knowledge.
* Blast-radius limits for prompt injection: a capability broker with taint tracking; signed-release updater; Windows Sandbox policy-as-code.

> Without `--model-url` the Reasoner is a **stub** that formats verified context but performs no inference. Point `--model-url` at a model server running on your own machine (llama.cpp, Ollama, LM Studio…) for real answers — loopback addresses only.

---

## 📚 In-Depth Documentation

* [System Architecture & Memory Model](docs/ARCHITECTURE.md)
* [Engineering Roadmap (Phases 1-5)](docs/ROADMAP.md)
* [Recursive Self-Improvement (RSI) Safety Specification](docs/RSI_SAFETY_SPEC.md)
* [Python Research Prototype Specification](docs/PROTOTYPE_SPEC.md)
* [Threat Model](docs/THREAT_MODEL.md)
* [Project Review & Open Decisions](docs/PROJECT_REVIEW.md)
