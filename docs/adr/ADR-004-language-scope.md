# ADR-004 — Language scope and delivery order (risk R6)

**Status:** Accepted (default) · **Owner decision D4** · **Date:** 2026-10-05

## Context
Three languages and one developer. Hand-writing Winsock/IOCP + TLS 1.3 in C++ is large, security-critical work with uncertain benefit over mature Rust libraries (`hyper`, `rustls`), and it multiplies the audit surface for the code that touches untrusted bytes.

## Decision
| Layer | Language | Rationale |
|-------|----------|-----------|
| Engine, planner, purge (`zeroize`), capability broker, updater, URL policy, **network client** | **Rust** | Memory safety exactly where untrusted data is parsed |
| Hardware telemetry daemon — GPU/NPU probing (NVML/CUDA/DXGI), PDH counters | **C/C++ (reduced charter)** | Vendor SDKs are native C/C++ |
| Research, golden-vector generation, experiments | **Python** | Fast iteration; stays the executable specification |

The hand-written C++ network engine is **dropped** unless the Phase 2 spike proves it wins on the measured criteria below.

## Spike acceptance criteria (time-box: 2 weeks, Phase 2)
On the same machine, 100 sequential and 8 concurrent Wikipedia-summary fetches. C++ is adopted for networking only if **all** hold versus the Rust baseline: p95 latency ≥ 20 % better · peak RSS ≥ 30 % lower · passes **every** URL-policy vector (incl. IP pinning) · reviewable (< 3 kLOC, no `unsafe`-equivalent patterns without justification). Otherwise Rust.

## Delivery order — vertical slices, one layer at a time
1. **VS1 (done):** Python end-to-end: perceive → ingest → reason (local model) → verified purge.
2. **VS2:** Rust CLI reproduces `--telemetry --json` and passes `conformance/tier_policy_vectors.json` and `url_policy_vectors.json`.
3. **VS3:** Rust runs the full cycle with `LocalLLMReasoner` equivalent; Python becomes a client/test harness.
4. **VS4:** C++ GPU/NPU probe feeds the same JSON schema; passes the same tier vectors.
5. Only then: RSI sandbox integration (Phase 4), OS control (Phase 5).
A slice is finished when its conformance vectors pass in CI; no layer is started before the previous slice ships.

## Conformance mechanism (implemented)
`research/conformance.py` emits 200 tier-policy vectors and 28 URL-policy vectors; `tests/test_conformance.py` fails when code and vectors drift. Native implementations must pass the same files.

## If reversed
Keep the vectors as the contract; add a C++ conformance runner for the network layer and extend the spike criteria to cover maintenance cost.
