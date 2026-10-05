# Changelog

## [0.3.0] — 2026-10-05 — Strategic risk remediation (R1–R7)

- **R1** `LocalLLMReasoner`: local open-model adapter (loopback-only, fenced context, no tools, tier token caps) — ADR-001.
- **R2** `outbound_policy.py` (allow-list, visible outbound log, offline mode) and `local_knowledge.py` (answer from local files) — ADR-002; CLI `--offline`, `--knowledge-dir`, `--allow-domain`, `--show-outbound`.
- **R3** Claims policy enforced by `tests/test_claims.py`; unfalsifiable phrases removed.
- **R4** Signed-release updater (`ed25519_ref.py`, `updater.py`, `sign_release.py`), `docs/CONSTITUTION.md`, engine-side `trust_root_is_protected()` — ADR-005.
- **R5** `sandbox_policy.py`: Windows Sandbox isolation checklist as code + hostile-output reader — ADR-003.
- **R6** Rust-first language scope, spike criteria, vertical slices (ADR-004); golden conformance vectors (`conformance/`, 200 tier + 28 URL cases); `core/` and `hardware/` charters.
- **R7** `capabilities.py` capability broker with taint tracking and hash-chained audit; `AgentExecutionResult.context_tainted` — ADR-006.
- **Fixed** (found by the new conformance vectors): URL guard accepted multicast / reserved / unspecified addresses (e.g. `224.0.0.1`).
- Tests: 53 → 140. New docs: `docs/adr/`, `docs/CONSTITUTION.md`.

## [0.2.0] — 2026-10-05 — Phase 1 review & hardening

### Security
- **Fixed**: `fetch_url` accepted `file://` URLs (local file read). New `net_guard.py` enforces http/https only, global IPs only, ports 80/443, no URL credentials; re-checked on every redirect.
- **Added**: prompt-injection screening in `DataVerifier` (policy `reject`/`flag`); untrusted-data fencing in the Reasoner contract.
- **Added**: Tier-1 AST guard prototype (`ast_guard.py`) for the RSI safety spec.
- **Fixed**: unbounded `response.read()` on Wikipedia calls; `lang` is now whitelisted before use in a hostname.

### Correctness
- **Fixed**: network errors were fed to the verifier as "knowledge" and reported as "payload too brief". Errors are now typed and reported precisely.
- **Fixed**: the purge was cosmetic (`del` on immutable `str`; `memory_purged_successfully` was always `True`; benchmark printed "zero leakage" unconditionally). Now `SecureBuffer` zeroes and verifies, the purge runs in `finally`, and the benchmark measures retained memory and can fail. <!-- claims-lint: quote -->
- **Fixed**: non-Windows telemetry returned invented 8 GB / 50 % values. Now reads `/proc`, falls back to psutil, then to an explicit "unavailable" + BALANCED.
- **Fixed**: regex HTML stripping replaced by `html.parser`; truncation by bytes; Unicode-aware letter ratio (Sinhala combining marks); compression-ratio spam check.
- **Fixed**: topic extraction (anchored trigger phrase, original casing preserved, Wikipedia search → summary instead of exact-title guess).

### Features
- CPU load and battery telemetry; battery/CPU-aware budget; JSON IPC form (schema v1).
- `--lang` (e.g. Sinhala Wikipedia), `--transport raw` (experimental socket+TLS client), scriptable CLI flags, EOF-safe interactive loop.
- `Reasoner` interface + honest stub.
- 53 unit tests.

### Docs
- Aligned all docs with the code (tier thresholds, timeouts, cycle naming).
- Added `THREAT_MODEL.md`, `PROJECT_REVIEW.md`; ROADMAP gained exit criteria, decision gates (ADRs) and a risk table; ARCHITECTURE gained telemetry schema v1 and a prototype-vs-production table; RSI spec gained implementation status and known weaknesses.

## [0.1.0] — 2026-10-01
- Initial scaffolding, docs and Python prototype.
