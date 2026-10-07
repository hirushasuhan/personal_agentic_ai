# Architecture Decision Records

Each ADR answers one risk raised in `../PROJECT_REVIEW.md` (ADR-008/009 answer risks opened later, see the roadmap). **Status "Accepted (default)"** means the recommended option was implemented/adopted so work can proceed; the project owner may overturn it — change the status and follow the "If reversed" note.

| ADR | Risk | Decision | Status |
|-----|------|----------|--------|
| [001](ADR-001-reasoner-strategy.md) | R1 reasoning core | Adopt a local open-weights model behind the `Reasoner` interface; own architecture = research track | Accepted (default) |
| [002](ADR-002-privacy-controls.md) | R2 privacy | Allow-list + visible outbound log + offline mode + local knowledge | Accepted, implemented |
| [003](ADR-003-windows-sandbox.md) | R5 sandbox on Windows | Windows Sandbox primary, Hyper-V VM fallback, policy-as-code | Accepted (smoke test passed 7/7, 2026-10-07) |
| [004](ADR-004-language-scope.md) | R6 scope | Rust owns networking/engine; C++ limited to hardware; golden conformance vectors | Accepted (default) |
| [005](ADR-005-release-trust.md) | R4 Constitution "ROM" | Externally signed releases + separate updater owning the Constitution hash | Accepted, prototyped |
| [006](ADR-006-capabilities-and-taint.md) | R7 prompt injection | Deny-by-default capability broker with taint tracking | Accepted, prototyped |
| [007](ADR-007-symbolic-reasoner.md) | R1 custom reasoning engine | Formal Evidence Atom DAG with dialectic conflict resolution and strict grounding | Accepted (experimental track) |
| [008](ADR-008-local-assistant-and-model-strategy.md) | R8–R12 local assistant, models, self-training | Own system (L1) + pluggable open-weights code brain (L2) + gated own-model fine-tuning (L3); promotion gate | Accepted (owner direction D6) |
| [009](ADR-009-rust-toolchain-and-unsafe-boundary.md) | VS3 native telemetry | `unsafe` only in `win32.rs`; telemetry parity check; MSVC CI is the reference toolchain | Accepted (confirmed by owner) |
| [010](ADR-010-portability-model-selection-and-cloud-providers.md) | Portability, user model choice, optional paid APIs | Per-machine calibration; allow-listed models; opt-in cloud providers with OS-stored keys, spend caps and a visible egress log | Proposed (owner request) |
| [011](ADR-011-restricted-execution-sandbox.md) | T16 restricted runner sandbox & verify loop | Multi-tier containment: Tier-1 AST guard, Tier-2 OS sandbox (AppContainer + Job Objects on Windows; bubblewrap/Landlock + rlimits on Linux) with startup capability probe & fail-closed rule, frozen-test bounded repair (N<=3), non-contaminated test evaluation, race-free exclusive staging (O_EXCL) | Proposed (Milestone M2 requirement, revised v2) |

R3 (absolute-security claims) is handled by a policy and a test rather than an ADR: see `../THREAT_MODEL.md` §5 and `research/tests/test_claims.py`.
