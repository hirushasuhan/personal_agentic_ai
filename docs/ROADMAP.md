# Engineering Roadmap (Phases 1 - 5)

This roadmap outlines the systematic development of the **Personal Agentic AI (PAI)** from an agile Python research prototype to a fully autonomous, recursive self-improving native intelligence daemon.

_Last reviewed: 2026-10-07. Phase 1 gate closed; Phase 2 slice VS2 (Rust policy conformance) complete and hardened; local assistant and gated own-model tracks added (ADR-008). Risks R1–R7 remediated, R8–R12 opened — see [PROJECT_REVIEW.md](PROJECT_REVIEW.md) and the [ADRs](adr/README.md)._

---

## 🗺️ High-Level Phase Overview

```mermaid
gantt
    title Personal Agentic AI Development Roadmap (dates after 2026-10-07 are planning estimates)
    dateFormat  YYYY-MM-DD
    section Phase 1: Research Prototype
    Python agentic loop, telemetry, hardening (done)  :done, 2026-10-01, 2026-10-05
    Risk remediation R1-R7 (done)                     :done, 2026-10-05, 2026-10-06
    Exit gate: sandbox, local model, CI, signing (done) :done, 2026-10-06, 2026-10-07
    section Phase 2: Native layers
    VS2 Rust tier + URL policy conformance (done)     :done, 2026-10-06, 2026-10-07
    VS3 Rust Win32 telemetry + parity (ADR-009)       :active, 2026-10-08, 2026-11-05
    C++ GPU/NPU probe (VS4, reduced charter)          :2026-11-05, 2026-11-30
    section Track L: Local assistant (ADR-008)
    M1 model bake-off + pai code (generate)           :2026-10-08, 2026-10-29
    M1b adaptive model router                         :2026-10-29, 2026-11-12
    M1c portability, calibration, model selection     :2026-11-12, 2026-11-26
    M1d optional cloud providers (ADR-010)            :2026-11-26, 2026-12-10
    M2 verify loop (restricted runner)                :2026-12-10, 2026-12-31
    M3 pai analyze (folders)                          :2026-12-31, 2027-01-14
    M4 docs, M5 forecast                              :2027-01-14, 2027-02-18
    M6 local web interface, M7 Singlish front-end     :2027-02-18, 2027-04-01
    section Track M: Own model (gated research)
    Stage 0 tokenizer + tiny model (laptop)           :2026-11-15, 2027-01-15
    Self-play data engine + LoRA experiments          :2027-01-15, 2027-03-15
    section Phase 4: Sandboxed RSI
    Sandbox launch + result collection                :2027-02-01, 2027-03-01
    Signed hot-swap engine (Rust)                     :2027-03-01, 2027-04-01
    section Phase 5: Autonomous assistant
    OS control and voice                              :2027-04-01, 2027-06-01
```

---

## 📍 Phase 1: Python Research Prototype & Verification Lab (COMPLETE — exit gate closed 2026-10-07)
**Objective**: Build a working, testable prototype in Python to validate the 3-pillar concepts and the safety ideas before committing them to native compiled languages.

### Deliverables
- [x] Project scaffolding (`core/`, `hardware/`, `research/`, `docs/`).
- [x] `research/hardware_telemetry.py` — Windows `kernel32` + Linux `/proc`, RAM, CPU load, battery, single-source tier policy, JSON IPC form. *(Hardened 2026-10-05: no invented fallback values.)*
- [x] `research/network_pipeline.py` — direct HTTP(S) ingestion, Wikipedia search→summary (multi-language incl. Sinhala), DuckDuckGo fallback, typed errors.
- [x] `research/net_guard.py` — outbound URL policy (SSRF / `file://` protection). *(Added after review finding C1.)*
- [x] `research/raw_http.py` — experimental raw `socket`+`ssl` client modelling the Phase 2 Winsock design.
- [x] `research/data_verifier.py` — HTML-parser sanitiser, byte-safe truncation, Unicode-aware scoring, prompt-injection screening.
- [x] `research/secure_buffer.py`, `memory_probe.py` — wipe-and-verify purge primitive and RSS probe.
- [x] `research/reasoner.py` — `Reasoner` interface + honest stub.
- [x] `research/agent_core.py` — Perceive → Ingest → Reason → Purge with guaranteed purge (`finally`) and a measured `PurgeReport`.
- [x] `research/ast_guard.py` — RSI Tier-1 static gate prototype.
- [x] `research/benchmark.py` — purge benchmark that can actually fail.
- [x] `research/main.py` — interactive CLI + scriptable flags.
- [x] `research/tests/` — 170 unit tests at 2026-10-07 (stdlib `unittest`; 5 skipped on Windows).
- [x] Docs aligned with code; `THREAT_MODEL.md`, `PROJECT_REVIEW.md` added.
- [x] **Risk remediation (second pass)** — each risk has an ADR and tested code:
  - R1 `reasoner.py::LocalLLMReasoner` (ADR-001) · R2 `outbound_policy.py`, `local_knowledge.py` (ADR-002) · R3 claims lint `tests/test_claims.py`
  - R4 `ed25519_ref.py`, `updater.py`, `sign_release.py`, `docs/CONSTITUTION.md` (ADR-005) · R5 `sandbox_policy.py` (ADR-003)
  - R6 `conformance.py` + `conformance/*.json` golden vectors (ADR-004) · R7 `capabilities.py` + `context_tainted` (ADR-006)

### 🚦 Phase 1 Exit Criteria (gate to Phase 2)
All must be true before Phase 2 starts:
- [x] `python -m unittest discover -s tests` is green **on the Windows development machine** (170 tests at the 2026-10-07 check).
- [x] Live ingestion verified on Windows: `main.py --ask "Explain Rust ownership"` and `--lang si`, with both `--transport urllib` and `--transport raw`.
- [x] `main.py --benchmark` passes on Windows; RSS trend recorded in `PROJECT_REVIEW.md`.
- [x] Telemetry JSON schema v1 and the tier-policy table are frozen (they become the C++ daemon's conformance tests).
- [x] CI runs the test suite on Windows (GitHub Actions `windows-latest` run #37520707673 passed).
- [x] Owner confirms the default decisions D1–D4 (ADR-001…004 confirmed).
- [x] **Windows Sandbox smoke test** (ADR-003): verified 7/7 checks passed; recorded in `docs/evidence/sandbox_results.json`.
- [x] Run one real local model through `--model-url` and record RAM/latency per tier (ADR-001; Ollama 1B and 3B GPU offload measured).
- [x] Constitution text reviewed by the owner; signing key generated and public key placed in `research/trust.json` (ADR-005).

### Optional Phase 1 stretch (only if time remains)
- Benchmark two or three candidate local models (size/quantisation) against a small fixed evaluation set to choose the product-path model (ADR-001).
- Fuzz `DataVerifier` (random HTML, huge/unicode inputs) with the stdlib only.

---

## 📍 Phase 2: Native layers — Rust policy core (VS2 done), Win32 telemetry (VS3), C++ probe (VS4)
_Status 2026-10-07: the Rust slice VS2 was completed first (see Phase 3 section); the C++ daemon below has not been started and is now sequenced after VS3 (ADR-004, ADR-009)._

**Objective**: Native low-level Windows daemon for hardware telemetry (reduced C++ charter, ADR-004) and a time-boxed spike to confirm Rust as the network layer.

### Deliverables
- **Hardware Telemetry Daemon (`hardware/telemetry/`)**: Win32 (`GlobalMemoryStatusEx`, `GetSystemTimes`, `GetSystemPowerStatus`), PDH counters, NVIDIA NVML/CUDA/DXGI for GPU/NPU. Publishes **telemetry schema v1** (`ARCHITECTURE.md` §3.1) over `\\.\pipe\pai_telemetry` with an ACL limited to the current user.
- **Conformance**: the daemon must pass `research/conformance/tier_policy_vectors.json` (200 vectors) — a C++ runner for the golden files is part of the deliverable.
- **Memory-protection hooks**: `VirtualLock` for working buffers, disable Windows Error Reporting dumps for the engine process (threat T5).
- **Network spike (2 weeks, decision gate)**: Rust baseline (`hyper`/`rustls`) vs a minimal C++ Winsock/IOCP+TLS client on 100 sequential + 8 concurrent fetches. C++ is adopted only if it is ≥ 20 % better on p95 latency **and** ≥ 30 % lower on peak RSS **and** passes every URL-policy vector (87 at 2026-10-07) including IP pinning (ADR-004). Otherwise networking stays in Rust and the C++ network engine is dropped.

---

## 📍 Phase 3: High-Performance Rust Core Engine
**Objective**: Replace Python orchestration with a zero-cost, memory-safe compiled Rust engine.

### Entry decision: Reasoner strategy — **ADR-001 accepted (default)**
Adopt a local open-weights model behind the `Reasoner` interface (Option A); a custom architecture is a parallel research track that must beat the adopted model on a fixed evaluation to replace it (Option B). The Python `LocalLLMReasoner` already exercises the contract; owner to confirm and choose the model by 2026-11-10.

### Deliverables & Vertical Slices
- **Vertical Slice 2 (VS2) — Stateless Core & Policy Conformance (COMPLETE)**:
  - Pure Rust implementations of resource tier policy (`src/tier.rs`) and outbound URL policy with Canonical Blocked CIDRs (`src/url_policy.rs`).
  - Zero unsafe code blocks (`unsafe = 0`), zero network crate dependencies (strictly `serde` + `serde_json` + `std::net`).
  - Fake telemetry removed from skeleton per ADR-004.
  - Passes 200 tier vectors and 87 URL vectors (28 baseline + 45 edge cases + 14 IPv6-transition and port-format cases added in the 2026-10-07 hardening).
  - Hardening found by independent review (commit `70fd7f6`): IPv6 transition/embedded-IPv4 prefixes (NAT64 `64:ff9b::/96`, `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/23`, IPv4-compatible `::/96`, SIIT, site-local `fec0::/10`) and `192.88.99.0/24` are blocked; leading-zero ports are rejected. Lesson recorded: a differential fuzzer proves two implementations agree, not that the shared policy table is complete — adversarial vectors from an independent source are required.
  - Differential fuzz testing (`python conformance.py --fuzz 10000 --seed 42`): 10,000 cases with 0 mismatches between Python and Rust.
  - Windows CI job verifying `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, and drift checking.
- **VS2 Exit Criteria (Gate to VS3)**:
  - [x] Tier vectors (200) and URL vectors (87) pass 100% in Rust (`pai-core --conformance`).
  - [x] Differential fuzzer passes 10,000 cases with 0 mismatches.
  - [x] No `unsafe` blocks and no fake telemetry in Rust core.
  - [x] Windows CI workflow includes dedicated Rust job.
  - [x] `core/README.md` and `core/Cargo.lock` updated and committed.
- **Vertical Slice 3 (VS3) — Native telemetry first, then the full cycle in Rust** (entry decisions in ADR-009, proposed):
  - Step 3a: `core/src/win32.rs` is the only file allowed to contain `unsafe`; Rust readers must match the Python readers (available RAM within ±5 %, identical tier for identical inputs).
  - Step 3b onward as listed below.
  - Live OS telemetry via Win32 APIs (replacing Python `HardwareTelemetry`).
  - Direct Winsock / `hyper` + `rustls` network pipeline with IP pinning.
  - Local model reasoner integration behind `Reasoner` trait with pre-load headroom hysteresis.
- **Rust Cargo workspace (`core/Cargo.toml`)**: `pai-core`, `pai-telemetry-client`, `pai-network` (default: Rust networking).
- **Stateless Task Planner & Interpreter**: graph-based planner; Rust lifetimes ensure temporary data cannot outlive the reasoning scope.
- **Purge guarantees**: working buffers use the `zeroize` crate (guaranteed non-elided wipe) + `mlock`/`VirtualLock`; this replaces the Python prototype's best-effort purge.
- **Reasoner integration**: model runtime with dynamic precision switching (FP16 → INT8 → INT4) driven by the telemetry tier.
- **Safety plumbing**: `net_guard`/`outbound_policy`, injection screening and the **capability broker** (ADR-006) ported; reasoner receives untrusted context fenced and **without tool access** (threat T3).
- **FFI & IPC**: Rust ↔ C++ bridge; Python reduced to an optional research client.

---

## 📍 Phase 4: Sandboxed Recursive Self-Improvement (RSI)
**Objective**: Enable the AI to write, test, verify and upgrade its own code inside a physically isolated sandbox.

### Entry decision: Sandbox technology — **ADR-003 accepted (default)**
Windows Sandbox (networking disabled, one writable output folder) is primary; a Hyper-V VM without NIC is the fallback; Firecracker-in-WSL2 optional for Linux builds; containers alone are not acceptable. The isolation checklist already exists as code (`research/sandbox_policy.py`). **Gate:** a Windows smoke test must prove a probe inside the sandbox cannot reach the network or host files before any RSI code runs there.

### Deliverables
- **Isolation environment** per the ADR with automated compile + test pipeline and a complete network airgap.
- **Dual-Agent Auditor System**: Generator proposes; a separate Auditor fuzzes and red-teams.
- **Verification scope** (clarified): "formal verification" is applied to *narrow, specified properties* (memory bounds, forbidden API use, I/O contracts), combined with differential testing against the previous version — not to "all behaviour".
- **Signed Hot-Swap Engine (ADR-005)**: prototype in `research/updater.py` (Ed25519 manifest, per-file SHA-256, anti-rollback, pinned Constitution hash, atomic install, rollback). Remaining: run the updater under a separate Windows account with ACL-protected trust root, engine start-up check `trust_root_is_protected()`, key custody + rotation procedure, Rust port.
- Tier-0 (untrusted-input) and Tier-1 (AST guard, prototype in `research/ast_guard.py`) are production-hardened in Rust.

---

## 📍 Phase 5: Autonomous Personal Intelligence Integration
**Objective**: Turn the engine into a personal daily companion working natively within Windows.

### Deliverables
- **OS Control**: Windows UI Automation routed through the **capability broker** (`research/capabilities.py`, ADR-006: deny-by-default grants, taint-aware human confirmation, audit chain) — the main defence against prompt injection (T3) once the model has tools. Remaining: the confirmation UI and real tool adapters.
- **Voice & Ambient Awareness**: local speech-to-text (whisper.cpp) and low-latency responses.
- **Persistent Personal Knowledge Graph**: optional, encrypted local store for *user-approved* memory (explicit exception to statelessness, off by default).
- **Privacy controls**: implemented in Phase 1 (ADR-002) — extend with a GUI view of the outbound log.

---

## 🛤️ Track L: Local assistant `pai` (ADR-008) — runs in parallel with Phase 2/3
**Objective**: a simple local, stateless assistant that analyzes code, documents, web pages and business datasets (with forecasts) and writes and tests code. Full specification: [LOCAL_ASSISTANT_SPEC.md](LOCAL_ASSISTANT_SPEC.md).

| Milestone | Deliverable | Acceptance (summary) |
|-----------|-------------|----------------------|
| M1 | Model bake-off (`qwen2.5-coder:7b`/`1.5b`, `qwen3.5:4b`, `gemma4:e2b` vs `llama3.2:3b`) + `pai code` generate-only | Model cards (licence checked, hash, `host_delta_mb`, latency); frozen sets: 20 coding tasks (pass@1), 10 Singlish prompts, 10 document questions; thinking/truncation behaviour recorded |
| M1.1 | Bake-off hardening (subprocess runner, thinking control, frozen sets, re-measured RAM) | Done in `7795e7b` |
| M1.2 | Standardized RAM measurements & full 20-doc batch evaluation | Done (5-run cold median in `MEASUREMENT_PROCEDURE.md`, all 20 doc tasks scored, run metadata recorded, profiles reconciled with SPDX/HF cards) |
| M1.2 | Bake-off re-run with metadata, standard cold-RAM procedure, 20 document tasks | Done in `bcade6e`; open (M1.3): repeat runs with fixed seed for pass@1 variance, stricter document scoring, licence re-read on official cards |
| M1b | Adaptive model router (task class + machine condition → model, explained) | Done (research/router.py, 15 golden vectors pass, graceful degradation across equal RAM budgets, T21 defense, M1d cloud extensibility) |
| M1c | Portability: `pai setup/doctor/calibrate/models`, machine profile, user model allow-list | Conditionally accepted (research/pai.py CLI, doctor/calibrate/models/route, ADR-010 calibration, T22/T26 defenses, loopback/exact-match fixes, uncalibrated 1.5x rule on fresh machines, plausibility floor < 50%, auto live telemetry & foreign profile rejection, value secret scanning). Illustrative schema example moved to `docs/examples/example_machine_profile.json`; physical second-machine calibration acceptance item remains open pending WSL2 run. Canonical OS matching and strict expiration applied. |
| M1d | Optional cloud providers (ADR-010, proposed) | Mock-server tests: off by default, key never leaks, card hosts only, spend caps, `--offline`, content cannot enable cloud |
| M2 | Verify loop with restricted runner | Design complete: ADR-011 and `docs/M2_VERIFY_LOOP_SPEC.md` (Tier-1 AST guard, Tier-2 OS sandbox via Windows Job Objects/Low Integrity & Linux namespaces/prlimit, 11-attack adversarial matrix, bounded repair N<=3, safe non-overwrite staging `pai code --out`). Implementation pending owner sign-off. |
| M3 | `pai analyze <folder>` | path-escape, injection-in-file, secret-file and size-cap tests pass |
| M4 | `pai docs` (txt/md/csv; PDF after an ADR) | injection and oversize tests pass |
| M5 | `pai forecast` | backtested forecast with interval; refuses on insufficient data; synthetic-series tests |
| M6 | Local web interface | loopback-only, token, Origin/Host checks tested |
| M7 | Singlish front-end | beats rule baseline on a frozen intent set |

Every milestone needs: new tests (including hostile inputs), claims-lint green, CI green, and a threat-register update.

## 🛤️ Track M: Own model (gated research, ADR-008)
Budget: no paid cloud GPU. Stages: **0** bilingual tokenizer + 10–25M-parameter model on the laptop (learn the pipeline, no quality claim); **1** LoRA fine-tune of a small pretrained open base on verified self-play trajectories, scheduled only when the machine is idle on AC power; **2+** only if the promotion gate in ADR-008 is passed (beats the router baseline on frozen evaluations, safety suites not worse, signed release, rollback). Until then the router uses open-weights models and no claim is made that an "own" model exists.

---

## ⚠️ Roadmap Risks (status after the second review pass)

| ID | Risk | Status | Where handled |
|----|------|--------|---------------|
| R1 | Reasoning core size/capability unknown | **Mitigated**: adopt local model; research track separate | ADR-001, `LocalLLMReasoner` |
| R2 | Network queries conflict with "private/local" goal | **Mitigated**: allow-list, visible log, offline, local knowledge | ADR-002 |
| R3 | Absolute-security claims | **Closed**: policy + automatic lint | `THREAT_MODEL.md` §5, `test_claims.py` |
| R4 | "ROM constitution hash" defeatable | **Mitigated (prototype)**: external signing + separate updater | ADR-005 |
| R5 | Firecracker unavailable on Windows | **Decided (default)**: Windows Sandbox (smoke test verified 7/7, `docs/evidence/sandbox_results.json`) | ADR-003 |
| R6 | Three languages, one developer | **Mitigated**: Rust-first networking, C++ reduced, vertical slices, golden vectors | ADR-004 |
| R7 | Prompt injection once the model has tools | **Mitigated (prototype)**: capability broker + taint | ADR-006 |
| R8 | Small local models give wrong answers/code (observed with 1B and 3B) | **Planned mitigation**: verify loop with tests, frozen baselines, grounding checks, no unmeasured quality claims | ADR-008, M1–M2 |
| R9 | Self-training poisons or memorizes data; a bad model regresses the system | **Designed**: self-play data, tainted trajectories excluded, hardware-aware scheduling, promotion gate with rollback | ADR-008, T18 |
| R10 | Untrusted local files and documents (injection, path escape, secrets) | **Planned**: M3/M4 controls and tests | LOCAL_ASSISTANT_SPEC, T15 |
| R11 | Forecasts read as certainties | **Planned**: code-computed numbers, backtest error and intervals shown, refusal on thin data | LOCAL_ASSISTANT_SPEC §M5, T19 |
| R12 | Model supply chain and licences | **Planned**: model cards (licence, SHA-256), explicit allow-list of models | ADR-008, T20 |

Phase 1 exit items are all closed (evidence: `docs/evidence/sandbox_results.json`, `research/model_profiles.json`, CI runs). Open owner decisions: confirm ADR-009 (Rust `unsafe` boundary and toolchains) and the model licences chosen in M1.
