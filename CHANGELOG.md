# Changelog

## [0.5.1] — 2026-10-07 — Milestone M1.1 Hardening & Sandboxed Code Runner

### M1.1 Sandboxing & Safe Code Runner
- `research/safe_code_runner.py`: Implemented isolated subprocess execution for model code evaluation.
  - **Zero in-process exec**: Model code is never executed inside the main Python test process.
  - **Subprocess termination**: Hard timeouts enforced via `proc.kill()`, cleanly terminating infinite loops and preventing background CPU exhaustion.
  - **Scrubbed environment**: Child processes receive only minimal OS system variables (`SYSTEMROOT`, `SystemDrive`, `PATH`, `TEMP`, `TMP`), stripping repository paths, credentials, and API keys.
  - **Network isolation**: Socket creation is intercepted and denied inside the sandbox worker.
  - **Test isolation**: Hidden unit test logic and assertions remain strictly in Process A; the untrusted child process receives only inputs via standard IPC.
- `research/eval_m1.py` and `research/run_bakeoff.py`: Integrated `run_isolated_task_eval` to replace all in-process threads. Added `tests/test_safe_code_runner.py` (6 unit tests).

### M1.1 Thinking Mode Control & Model Re-evaluation
- `research/reasoner.py` (`LocalLLMReasoner`): Added native Ollama `/api/chat` integration with `think: Optional[bool]` parameter and accurate thinking detection inspecting API `thinking`/`reasoning` fields.
- Re-evaluated reasoning models with `think: False`:
  - `qwen3.5:4b`: coding pass@1 jumped from 0% to **50% (10/20)**, Singlish score jumped to **70% (14/20)** (highest among all models), latency dropped from 20.91s to 5.57s.
  - `gemma4:e2b`: coding pass@1 jumped from 0% to **55% (11/20)**, Singlish score rose to **65% (13/20)**, latency dropped from 8.57s to 3.62s.
  - Both confirmed as viable candidates for the adaptive model router.

### M1.1 Eval Set Expansion & Cryptographic Freezing
- `research/eval_sets/doc_analysis_tasks.json`: Added 10 harder discriminating tasks (`doc_11`–`doc_20`) testing multi-document cross-referencing, memory headroom calculation, tier exceptions, and policy layer boundaries.
- `docs/evidence/eval_sets_hashes.json`: SHA-256 hashes of all 4 evaluation sets recorded and frozen.
- `research/model_profiles.json`: Corrected cold-start host RAM deltas for `qwen3.5:4b` (1029.1 MB) and `gemma4:e2b` (2386.0 MB); added `licence_checked_on: "2026-10-07"` to all profiles.

### Reviewer notes (not part of the original entry)
- The runner is best-effort containment for evaluation, not an OS-level boundary (T16 stays open for M2): the `socket.socket` replacement can be bypassed, absolute paths and child processes are not restricted, and there is no memory limit.
- `doc_11`-`doc_20` are frozen but not yet scored in `m1_bakeoff_results.json`; RAM figures differ between the bake-off file and `model_profiles.json`.

### Tests
- Python 184 tests passing (14.8s). Rust 13 unit tests passing. Differential fuzz 10,000 cases passing. Clippy clean.

## [0.5.0] — 2026-10-07 — Rust VS3 (Win32 Native Telemetry) & Milestone M1 Multi-Model Bake-Off

### Rust core (slice VS3) — ADR-009
- `core/src/win32.rs`: Native Win32 hardware telemetry implemented using `windows-sys = "0.52"` (`GlobalMemoryStatusEx`, `GetSystemTimes`, `GetSystemPowerStatus`).
- Unsafe isolation boundary strictly enforced: `#![deny(unsafe_code)]` at crate root (`lib.rs`, `main.rs`); zero `unsafe` allowed outside `win32.rs`, with explicit `// SAFETY:` invariant justification on every call.
- Telemetry parity validated against Python (`tests/test_telemetry_parity.py`): measured difference 0.69% (well within the $\pm 5\%$ threshold required by ADR-009).
- CLI flags `--telemetry` and `--telemetry --json` added to `core/src/main.rs`. CI job updated with unsafe isolation regex gate and telemetry parity check.

### Milestone M1 Bake-Off (Track L / ADR-008)
- Frozen evaluation test suite established:
  - **Set 1 (Coding)**: 20 hand-crafted tasks with timeout-guarded hidden test suites (`research/eval_sets/hidden_tests/`) never exposed to models.
  - **Set 2 (Singlish/Sinhala)**: 10 prompts testing colloquial Sinhala/Singlish code comprehension, debugging, security, and architecture (scored 0–2 against rubric).
  - **Set 3 (Document Analysis)**: 10 grounded questions verifying context utilization on PAI architectural specifications.
- 5 models empirically measured and profiled (`docs/evidence/m1_bakeoff_results.json`):
  - `qwen2.5-coder:7b` (Apache 2.0): 13/20 (65%) pass@1 coding, 11/20 (55%) Singlish, 10/10 (100%) doc analysis, 7.13s latency, 4.9 GB footprint.
  - `qwen2.5-coder:1.5b` (Apache 2.0): 9/20 (45%) pass@1 coding, 5/20 (25%) Singlish, 10/10 (100%) doc analysis, 1.34s latency, 1.1 GB footprint.
  - `llama3.2:3b` (Llama Community License): 7/20 (35%) pass@1 coding, 9/20 (45%) Singlish, 10/10 (100%) doc analysis, 1.96s latency, 2.4 GB footprint.
  - `qwen3.5:4b` & `gemma4:e2b` (Apache 2.0): Discovered that default thinking mode exhausts tier-allocated token caps (1024 tokens), leading to truncation and syntax errors on code output.
- `research/model_profiles.json` updated with full host delta and model footprint measurements.

### Tests
- Python 178 tests passing (13.2s). Rust 13 unit tests passing (0.02s). Differential fuzz 10,000 cases passing (0 mismatches). Clippy clean (`-D warnings`).

### Phase 1 exit evidence
- Windows Sandbox smoke test passed 7/7 (`docs/evidence/sandbox_results.json`, ADR-003); two guest profiles on newer Windows builds added to the allowed list.
- Real local models measured on the owner's laptop (Ollama, 1B and 3B, iGPU offload): `research/model_profiles.json`; RAM-fit check uses the measured host delta + 512 MB headroom, evaluated before load only (hysteresis).
- Signing key generated offline; public key in `research/trust.json`. GitHub remote and Windows CI established.

### Security fixes
- **T14** trust-label injection: provenance is accepted only through a per-task random nonce (`[[SRC:<nonce>:<source>]]`); in-band text headers are ignored.
- Negation handling in the symbolic engine fixed (direct-negation conflicts are now detected and lower the grounding score); grounding status renamed `SYNTACTIC_GROUNDING` because it checks citations, not truth.
- Misleading output strings removed or reworded; unconditional "verified" wording dropped.
- Review found that the first explicit URL blocklist missed IPv6 transition/embedded-IPv4 prefixes (NAT64, 6to4, Teredo, SIIT, IPv4-compatible, site-local) and `192.88.99.0/24`; fixed in `70fd7f6`. Leading-zero ports are rejected. A model-loaded check no longer accepts an empty model name.

### Rust core (slice VS2)
- `core/`: pure `tier.rs` and `url_policy.rs`, `unsafe = 0`, dependencies `serde`/`serde_json` only; fake telemetry removed.
- Conformance: 200 tier + 87 URL golden vectors; differential fuzz (10,000 cases) against Python; CI job `rust-core` (fmt, clippy `-D warnings`, test, conformance, drift check, fuzz).
- `docs/NET_POLICY.md`: single documented outbound policy table shared by Python and Rust.

### Documentation and planning
- New: ADR-008 (local assistant and model strategy, owner decision D6), ADR-009 (Rust toolchain and `unsafe` boundary, proposed), `docs/LOCAL_ASSISTANT_SPEC.md`.
- Candidate models for the first bake-off and an adaptive, explainable model router specified (`LOCAL_ASSISTANT_SPEC.md` §3, ADR-008 amendment, T21); milestones M1/M1b added.
- ROADMAP rewritten for the current state (Phase 1 complete, VS2 done, VS3 next, Track L local assistant, Track M gated own model, risks R8–R12).
- THREAT_MODEL v0.2 (T15–T20); RSI spec gains a model/adapter promotion section; PROJECT_REVIEW gains a status and verification log.

### Tests
- Python 170, Rust 10 (unit) at the time of writing.

## [0.3.1] — 2026-10-06
- Sandbox smoke test: exit code is now truthful (0 only after a real in-sandbox pass), probe strengthened (DNS, adapters, host-path invisibility, foreign profiles, drives), results written without BOM; `read_sandbox_results` also tolerates a UTF-8 BOM (PowerShell 5.1).
- `.gitignore` blocks `*.key` / `*.pem`; CI live-network step is non-blocking.

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
