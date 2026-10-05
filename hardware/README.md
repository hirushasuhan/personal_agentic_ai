# hardware/ — C/C++ telemetry daemon (Phase 2, reduced charter)

Charter (ADR-004): GPU/NPU probing (NVML/CUDA/DXGI) and PDH counters, published as telemetry schema v1
(`docs/ARCHITECTURE.md` §3.1) on `\\.\pipe\pai_telemetry` with an ACL limited to the current user.

Out of scope unless the Phase 2 spike proves otherwise: a hand-written Winsock/IOCP + TLS network engine.

Acceptance: passes `research/conformance/tier_policy_vectors.json`.
