# Changelog

## [0.6.0] — 2026-10-07 — Milestone M2 Design Phase & M1c.2 Profile Refinements

### Milestone M2 Architecture & Design Specification
- **ADR-011 Architecture Decision Record (`docs/adr/ADR-011-restricted-execution-sandbox.md`)**:
  - Multi-tier containment: Tier-1 AST Guard, Tier-2 OS-level Restricted Sandbox Runner, Tier-3 Test Grader, and Safe Output Staging.
  - Cross-platform OS security boundary: Windows Job Objects (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, 512 MB memory limit, 1 active process limit, Low Integrity token stripping) and Linux Namespaces (`CLONE_NEWNET`) with POSIX resource limits (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC`).
  - Bounded iterative repair loop ($N \le 3$) with sanitized diagnostic extraction.
  - Safe atomic output staging with strict refusal to overwrite existing user files without explicit `--overwrite`.
- **Milestone M2 Verify Loop Specification (`docs/M2_VERIFY_LOOP_SPEC.md`)**:
  - Comprehensive contract for `pai code "<task>" --out <dir>`.
  - 11-attack adversarial containment test matrix: infinite loops, memory bombs (10 GB heap allocation), fork bombs, canary file deletion, filesystem breakouts, network socket creation, subprocesses, ctypes native loading, stdout stream floods (pipe bombs), hidden test tampering, and segfault traps.
  - Frozen evaluation plan on `coding_benchmark_v1.json` (Pass@1 baseline vs Pass@3 verify loop).

### M1c.2 Profile Normalization & Evidence Honesty
- **Illustrative Schema Documentation (`docs/examples/example_machine_profile.json`)**: Moved unmeasured secondary profile out of `docs/evidence/` to `docs/examples/` as an explicit schema template; empirical second-machine calibration item remains open pending physical WSL2 run.
- **Canonical Base OS Normalization (`research/config.py`, `research/pai.py`)**: `_canonical_os` compares base platform systems (`windows`, `linux`, `darwin`), preventing routine OS kernel updates from invalidating calibrated profiles. `cmd_calibrate` stores `platform.system()`.
- **Strict Expiration Enforcement (`research/config.py`)**: Profiles without `expires_at` calculate and enforce `calibrated_on + 30 days`. Profiles lacking timestamps are rejected. `_comment` key permitted in machine profiles.
- **Test Suite**: 222 Python unit tests passing (14 in `test_config.py`). Windows vs Linux skips documented (5 skipped on Windows, 2 on Linux).

## [0.5.6] — 2026-10-07 — Milestone M1c.1 Hardening & Probe Defect Resolution

### M1c.1 Router & Profile Hardening
- **Uncalibrated 1.5x Rule on Fresh Machines (`research/router.py`)**: When no machine profile exists, `ModelRouter` applies the ADR-010 conservative multiplier ($1.5 \times \text{card\_delta} + 512.0\text{ MB}$) to local candidates by default, tagging decisions with `UNCALIBRATED`. At 1850 MB free RAM on a fresh machine, 7B (requiring 2470.9 MB) is rejected and 1.5B is selected. Added `reference_profile_mode=True` to preserve frozen golden decision vector conformance tests.
- **Plausibility Floor (`research/router.py`)**: Calibrated deltas $< 50\%$ of card prior (e.g. 1.0 MB for 7B) are rejected by plausibility floor, falling back to conservative 1.5x rule and recording `CALIBRATION_IMPLAUSIBLE` in reason codes and rejection records.
- **Automatic Live Telemetry & Machine Identity (`research/router.py`, `research/config.py`)**: `ModelRouter` and CLI commands query live hardware (`live_total_ram_gb`, `live_machine_id`, `live_os`) automatically. Foreign machine profiles with mismatched machine ID or OS fail closed and fall back to uncalibrated mode. Profiles older than 30 days or past `expires_at` are rejected as expired.
- **Calibration Measurement Hardening (`research/pai.py`)**: `pai calibrate` polls loopback `/api/ps` until candidate model is fully unloaded, followed by 2.0s settling sleep. Runs with non-positive RAM deltas ($\le 0.0\text{ MB}$) are discarded; requires minimum 3 valid runs per model. Emits warning if spread $> 30\%$ median. Computes 30-day `expires_at` timestamp. Saves profile incrementally after each model. `pai doctor` displays `Not calibrated -- run pai calibrate` when uncalibrated.
- **Value-Level Secret Screening (`research/config.py`)**: Configuration scanner screens string values for credentials and token patterns (`sk-`, `ghp_`, `Bearer `, `api_key=`, high-entropy tokens). Validates `spend_caps` (dict of non-negative numbers) and `enabled_providers` (list of strings). Strictly rejects `privacy_mode: allow-cloud` until Milestone M1d.
- **Second-Machine Calibration Evidence (`docs/evidence/second_machine_profile.json`)**: Documented calibration numbers from a secondary Linux environment (superseded: not a measurement, see the entry above and `docs/examples/`).
- **Test Suite**: 219 Python unit tests passing (+9 new tests in `test_config.py` and `test_router.py`). Windows vs Linux skip difference documented (5 skipped on Windows due to symlinks and non-root POSIX tests, 2 skipped on Linux). 13 Rust core tests passing, clippy clean (`-D warnings`). 10,000 differential fuzz cases clean. Telemetry parity passing. All 5 frozen eval set hashes intact.

## [0.5.5] — 2026-10-07 — Milestone M1c Portability, Hardware Calibration, User Configuration, and PAI CLI

### M1c Portability & Machine Profile Calibration (ADR-010)
- **Empirical Hardware Calibration (`research/config.py`)**: Support for non-committed machine profiles (`~/.pai/machine_profile.json`). Calibrated models use empirical 5-run cold deltas (`MACHINE_PROFILE_CALIBRATED`); uncalibrated models apply ADR-010 conservative rule: `required_ram = card_delta * 1.5 + 512.0 MB` with `"UNCALIBRATED"` decision code.
- **Tampering Detection (Threat T26)**: Profiles are validated against live hardware; claimed total RAM deviating >35% from physical RAM is rejected fail-closed.
- **User Configuration & Allow-Lists (Threats T21, T22)**: Schema-validated `~/.pai/config.json` supports non-secret user settings (`allowed_models`, `preferred_models`, `privacy_mode`). Credential scanner immediately rejects forbidden keys/tokens (`key`, `secret`, `token`, `password`, `auth`).
- **Live Resident Probe Hardening**:
  - `get_live_resident_model()` strictly checks `base_url` is local loopback (`127.0.0.1`, `localhost`, `::1`), raising `ValueError` on external hosts to prevent SSRF.
  - Replaced prefix matching with exact name matching (`candidate_name == m_name`) to eliminate tag pollution or spoofing.
  - Multi-model resident list from `/api/ps` resolved deterministically using candidate priority ordering.

### PAI Unified Command Line Interface (`research/pai.py`)
- **`pai doctor [--json]`**: Cross-platform system diagnostics (OS, CPU cores/load, RAM total/avail/pressure, GPU/iGPU probe, battery state, loopback Ollama `/api/ps` probe, candidate eligibility matrix).
- **`pai calibrate [--model, --runs]`**: Automated 5-run cold RAM & latency profiling per `MEASUREMENT_PROCEDURE.md` saving validated machine profile to `~/.pai/machine_profile.json`.
- **`pai models list [--json]`**: Candidate model catalog with display names, licenses, calibration state, min RAM, and live hardware fit.
- **`pai route <command> [--explain-route, --json]`**: Wires `ModelRouter` to CLI.
- **Deferred Execution Commands**: Subcommands `generate`, `analyze`, and `forecast` print explicit guidance that execution is deferred to Milestone M2+, pointing users to `pai route <command>`.

### CI & Verification
- **Linux Portability CI Job**: Added `linux-portability` job to `.github/workflows/windows-ci.yml` running on `ubuntu-latest`.
- **Tests**: 210 Python unit tests passing (up from 191, +19 tests in `test_config.py`, `test_pai_cli.py`, and `test_router.py`). 13 Rust tests passing, clippy clean. 10,000 differential fuzz cases clean.

## [0.5.4] — 2026-10-07 — Milestone M1b.1 Router Hardening & Probing Fixes

### M1b.1 Router Probing Hardening (`research/router.py`)
- **Sticky Resident Eviction**: Enforced that resident models DO NOT bypass CPU load (`cpu-saturated`), low battery, or COMPRESSED tier constraints. Heavy resident models (`qwen2.5-coder:7b`, `qwen3.5:4b`, `gemma4:e2b`) are evicted and downgraded across all code, chat, and document analysis paths.
- **Strict Command Validation**: Unknown or invalid commands raise `ValueError` immediately at entry point; silent fallback to docs/7B eliminated.
- **Resident Model Allow-List Validation**: Callers cannot spoof unvetted resident names to bypass RAM headroom checks; unlisted names are ignored and rejected. Added `get_live_resident_model()` to query `/api/ps` and validate against the allowed catalog.
- **Unverified License Transparency (Threat T20)**: Models with unverified upstream licenses (`qwen3.5:4b`, `gemma4:e2b`) marked as `unverified` in `model_profiles.json` and labeled with `UNVERIFIED_LICENCE` in router decisions.
- **Deferred Cloud Parameter**: Removed misleading `allow_cloud` parameter from `route()`; cloud routing deferred to Milestone M1d (ADR-010).
- **Frozen Golden Vectors**: Expanded to 20 vectors in `research/eval_sets/router_golden_vectors.json` (SHA-256: `69f885ec8f332e20176378c65b0b458961c8b8de0993396950d6c3572b1195bd`), covering CPU-saturated resident eviction, low-battery chat eviction, unmeasured docs CPU saturation, and untrusted resident spoofing defense.
- **Adoption Test Clarification**: Clarified that router matches the best fitting single model for each budget regime without making unmeasured quality claims.
- **Tests**: 191 Python tests passing (5 skipped).

## [0.5.3] — 2026-10-07 — Milestone M1b Adaptive Model Router & M1.3 Hardening

### M1b Adaptive Model Router (`research/router.py`)
- **Graceful Degradation Priority**: Adapts model selection based on host RAM, compute tier, power/battery state, and CPU throttle conditions. Quality ranking is only favored when difference exceeds empirical noise margin (e.g. 7B coding 60% vs 40%).
- **Strict Task Class Isolation (Threat T21)**: Task class derived strictly from CLI command argument (`code`, `analyze`, `docs`, `forecast`, `web`, `chat`); file and web context is never parsed for task routing.
- **Extensible Candidate Architecture (M1d Readiness)**: Candidates declare `kind` (`local` | `cloud`) and `data_leaves_machine` (`bool`). Host RAM-fit check applies exclusively to local models. Route reports include `Data leaves machine: Yes / No`.
- **Hysteresis & Sticky Resident Preservation**: Resident models in memory bypass pre-load checks and are preserved for compatible task classes to avoid cold reload latency (8.7s–18.25s).
- **Owner Opt-In Enforcement**: High-RAM `gemma4:e2b` (2.93 GB host RAM) requires explicit `gemma4_opt_in=True` and $\ge 3500$ MB free RAM; otherwise rejected with `OPT_IN_REQUIRED`.
- **Unmeasured Class Handling**: `docs`, `analyze`, `web`, and `forecast` route to code/general models tagged with `UNMEASURED_CLASS`.
- **Golden Decision Vectors**: Frozen suite of 15 vectors in `research/eval_sets/router_golden_vectors.json` (hash recorded in `eval_sets_hashes.json`).
- **Comprehensive Unit Tests**: `research/tests/test_router.py` (5 tests) covering golden vector conformance, T21 context isolation, cloud candidate extensibility, and equal RAM budget adoption comparisons.

### M1.3 Evaluation & Profiles Hardening
- `research/model_profiles.json`: Reconciled official Hugging Face source repository URLs and license URLs for all profiles. Labeled `model_footprint_mb` and live deltas as informational only (not used by router).
- `research/reasoner.py`: Added `temperature` and `seed` parameters to `LocalLLMReasoner` across both Ollama native and OpenAI endpoints for deterministic evaluations.
- `docs/evidence/eval_sets_hashes.json`: SHA-256 hash for `router_golden_vectors.json` frozen.

## [0.5.2] — 2026-10-07 — Milestone M1.2 Hardening, Standardized RAM Measurements & Full 20-Doc Bake-Off

### M1.2 Standardized Cold-Start RAM Procedure & Empirical Measurements
- `docs/MEASUREMENT_PROCEDURE.md`: Documented reproducible 5-run cold-start RAM measurement standard with mandatory cache flushing (`keep_alive: 0`), process settling (2.0s), and median calculation.
- `research/measure_cold_profile.py`: Automated tool executing the standardized measurement procedure.
- `docs/evidence/cold_ram_measurements.json`: Empirical 5-run dataset across all 5 models:
  - `llama3.2:3b`: Median host delta **740.0 MB** (min 601.5 MB, max 783.5 MB, latency 3.21s).
  - `qwen2.5-coder:1.5b`: Median host delta **590.4 MB** (min 586.3 MB, max 672.4 MB, latency 3.82s).
  - `qwen3.5:4b`: Median host delta **1038.6 MB** (min 1016.9 MB, max 1060.4 MB, latency 8.69s).
  - `gemma4:e2b`: Median host delta **2934.8 MB** (min 2894.4 MB, max 3004.8 MB, latency 14.86s). Solved Ollama footprint anomaly: the 214.4 MB reported by `ollama ps` is discrete VRAM only; remaining weights allocate 2.93 GB of host RAM.
  - `qwen2.5-coder:7b`: Median host delta **1305.9 MB** (min 1289.4 MB, max 1435.5 MB, latency 18.25s).
- `research/model_profiles.json`: Updated schema v2 with official Hugging Face repository URLs, verified SPDX license IDs (`Apache-2.0`, `Llama-3.2-Community`), license URLs, and median host deltas.

### M1.2 Batch Evaluation Harness & Complete Run Metadata
- `research/run_bakeoff.py`:
  - Upgraded to runner version `1.2.0`.
  - Added structured `run_metadata` block recording runner version, execution date, live Ollama version (`0.35.1`), thinking mode setting (`think: False` for reasoning models), cryptographic eval set hashes, and explicit audit list of truncated task IDs (`truncated_tasks`).
  - Scored all 20 document tasks (`doc_01`–`doc_20`), including the 10 discriminating hard questions.
  - Automatic `low_confidence = True` flag when task truncation occurs.
- `docs/evidence/m1_bakeoff_results.json`: Re-evaluated all 5 candidate models with identical harness and isolated subprocess sandboxing:
  - `llama3.2:3b`: 8/20 (40.0%) coding, 11/20 (55.0%) Singlish, 20/20 (100.0%) doc analysis, 2.30s latency, 740.0 MB cold RAM delta. (Truncated on 4 long Singlish prompts).
  - `qwen2.5-coder:1.5b`: 9/20 (45.0%) coding, 4/20 (20.0%) Singlish, 16/20 (80.0%) doc analysis, 1.35s latency, 590.4 MB cold RAM delta. (0 truncations).
  - `qwen3.5:4b`: 8/20 (40.0%) coding, 15/20 (75.0%) Singlish, 20/20 (100.0%) doc analysis, 5.50s latency, 1038.6 MB cold RAM delta. (Truncated on `code_16`).
  - `gemma4:e2b`: 11/20 (55.0%) coding, 17/20 (85.0%) Singlish, 20/20 (100.0%) doc analysis, 4.13s latency, 2934.8 MB cold RAM delta. (Truncated on `code_11`, `code_13`).
  - `qwen2.5-coder:7b`: 12/20 (60.0%) coding, 11/20 (55.0%) Singlish, 19/20 (95.0%) doc analysis, 6.92s latency, 1305.9 MB cold RAM delta. (Truncated on `singlish_01`).

### Tests
- Python: 184 tests pass (5 skipped).
- Rust: 13 unit tests pass. Clippy clean (`-D warnings`).

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
