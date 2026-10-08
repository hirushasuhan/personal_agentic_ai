# Project Review — Phase 1 (2026-10-05)

Scope: all Phase 1 code (`research/`), all docs, and the 5-phase plan. Method: read every file, ran every module, probed suspected defects with small experiments, then fixed and covered them with tests.

## 1. Verdict

The architecture idea is coherent and the Phase 1 structure is sound. The review found **one security hole, several correctness bugs, and a gap between what the docs claimed and what the code did** (mainly the "RAM purge" and "raw sockets"). All code findings are fixed and tested. The plan has six strategic risks that need *decisions*, not code (§4).

## 2. Code Findings (all resolved in v0.2.0)

| ID | Severity | Finding | Evidence | Resolution |
|----|----------|---------|----------|------------|
| C1 | **Critical** | `fetch_url` accepted `file://` → arbitrary local file read | Probe: `fetch_url("file:///etc/hostname")` read the file (rejected only because it was short) | `net_guard.py` scheme allow-list; tests |
| C2 | High | No SSRF protection (loopback, RFC 1918, `169.254.169.254`, redirects into private space) | Code review | IP must be global; every redirect re-validated |
| C3 | High | Network failures were passed to the verifier as if they were knowledge and surfaced as "payload too brief" | Probe: offline run reported `Payload too brief…` | Typed `NetworkError`; precise reasons |
| C4 | High | "Zeroize" was cosmetic: `del val` on an immutable `str` does nothing to the bytes; `memory_purged_successfully = len(dict)==0` was always `True`; benchmark printed "Zero memory leakage" unconditionally | Code review | `SecureBuffer` (memset + read-back verification); measured, failable benchmark | <!-- claims-lint: quote -->
| C5 | High | Purge skipped when any step raised | Code review | Purge in `finally`; test with a crashing reasoner |
| C6 | Medium | Non-Windows telemetry returned invented 8 GB / 4 GB / 50 % → wrong tier decisions | Probe on Linux showed fake values | `/proc` reader → psutil → explicit "unavailable" (BALANCED) |
| C7 | Medium | Docs/code drift: tier thresholds (spec 4 GB/1.5 GB vs code 2 GB/0.5 GB + load %), timeout 5 s vs 6 s, cycle named three different ways, ARCHITECTURE "RAM < 15 %" | Diffed docs vs code | One policy table; docs rewritten |
| C8 | Medium | Regex HTML stripping: fragile on malformed/unclosed tags; removing `<header>` dropped article titles | Code review | `html.parser` extractor; test for unclosed `<script>` |
| C9 | Medium | Truncation cut *characters* but the limit was in *bytes* | Code review | Byte-accurate cut that never splits UTF-8; test with Sinhala |
| C10 | Medium | Letter ratio used `str.isalpha()` — Sinhala/Indic vowel signs are combining marks and were not counted; word-count rule penalised unspaced scripts | Probe: Sinhala letter ratio only 0.53 | Count categories L* and M*; word rule waived for long text |
| C11 | Medium | Topic extraction matched triggers anywhere, then `.title()` (breaks `C++`, `iPhone`); exact-title Wikipedia lookups 404 for most queries | Code review | Anchored trigger regex, casing preserved, title search → summary |
| C12 | Medium | Spec promised injection protection; none existed | Spec vs code | Pattern screening + untrusted fencing |
| C13 | Low | Unbounded `response.read()` on Wikipedia/DDG calls | Code review | Byte caps on every read |
| C14 | Low | CPU load and battery in roadmap/spec but not implemented | Spec vs code | Implemented; budget uses them |
| C15 | Low | No tests, no CLI flags, `input()` crashed on EOF | Code review | 53 tests; flags; EOF-safe |
| C16 | Info | "Raw sockets" claim: original used `urllib` | Code review | Honest wording + experimental `raw_http.py` that really uses `socket`+`ssl` |

## 3. Plan / Documentation Findings
* Roadmap Phase 1 checkboxes were all unchecked although the code existed → updated, and **exit criteria** added (a phase without a gate never ends).
* No definition of the Phase 1 → Phase 2 handoff → telemetry JSON schema v1, tier table and URL policy are now explicit contracts.
* No place for architecture decisions → ADR gates added before Phase 3 (reasoner) and Phase 4 (sandbox).
* Security claims ("100 % secure", "zero leakage") were unfalsifiable → replaced by a threat register with named tests and residual risks. <!-- claims-lint: quote -->

## 4. Strategic Risks (need owner decisions)

**R1 — The "tiny reasoning core" is the biggest unknown.** The design assumes a very small model that knows only logic and grammar. In practice, following instructions, understanding free text and writing correct code require a model with a large number of parameters (typically at least ~1 B, i.e. hundreds of MB to a few GB even when quantized). Separating *facts* from *reasoning* is a legitimate research direction (retrieval-augmented small models), but training a capable model *from scratch* needs large datasets and GPU time. *Recommendation:* Phase 3 adopts an open-weights small model behind the `Reasoner` trait; "own architecture" becomes a parallel research track with benchmarks.

**R2 — Privacy contradiction.** "Local and private" conflicts with sending every topic to Wikipedia/DuckDuckGo. *Recommendation:* reword the goal to "local inference, minimal and visible outbound traffic"; add an outbound-request log, domain allow-list, offline mode and an optional local knowledge source (e.g. an offline Wikipedia dump).

**R3 — "100 % secure" cannot be achieved.** Formal verification covers narrow, specified properties. *Recommendation:* adopt "defense in depth" wording and measurable properties. <!-- claims-lint: quote -->

**R4 — The Constitution "ROM hash" is defeatable.** A program that can rewrite its binary can rewrite the embedded hash and the checker. *Recommendation:* signed releases (key never on the AI's machine) verified by a separate, separately-privileged updater.

**R5 — Firecracker does not run natively on Windows.** *Recommendation:* decide between WSL2+Firecracker, a Hyper-V VM without NIC, or Windows Sandbox; containers alone are not enough.

**R6 — Three languages, one developer.** Hand-writing Winsock/IOCP + TLS in C++ is substantial work for uncertain gain over Rust (`hyper`/`rustls`). *Recommendation:* keep C++ for what Rust handles less naturally (NVML/CUDA, PDH), run a time-boxed network spike in Phase 2, and favour vertical slices (one query end-to-end through each new layer) over finishing layers in isolation.

**R7 — Prompt injection becomes critical once the model has tools (Phase 5).** *Recommendation:* capability-based permissions and human confirmation for destructive/outbound actions; never give the reasoner tools while it holds untrusted context.

### 4.1 Remediation status of R1–R7 (2026-10-05, second pass)

| Risk | What was done | Evidence | Still open |
|------|---------------|----------|-----------|
| R1 reasoning core | ADR-001: adopt a local open model behind `Reasoner`; `LocalLLMReasoner` implemented (loopback-only, fenced context, no tools, tier-based token caps) | `tests/test_reasoner.py` (9) | Owner confirmation of D1; measure real RAM/latency per tier with a chosen model; evaluation suite for the research track |
| R2 privacy | ADR-002: allow-list, visible outbound log, offline mode, local knowledge directory | `tests/test_privacy.py` (13) | Domain-level privacy remains a user choice |
| R3 absolute-security claims | Claims policy + automatic lint over all code/docs | `tests/test_claims.py` | — |
| R4 Constitution "ROM" | ADR-005: Ed25519-signed releases, separate updater owning the pinned Constitution hash, anti-rollback, signing tool, `CONSTITUTION.md` draft | `tests/test_updater.py` (23) incl. RFC 8032 vector | Windows ACL/account separation (installer), key custody + rotation procedure, owner review of Constitution text |
| R5 sandbox on Windows | ADR-003: Windows Sandbox primary; checklist as code (generator + fail-closed validator + hostile-output reader) | `tests/test_sandbox_policy.py` (17) | **Smoke test on a real Windows host** (probe cannot reach network/host files); launch + collect automation (Phase 4) |
| R6 scope | ADR-004: Rust owns networking/engine, C++ limited to hardware, measurable spike criteria, vertical slices; golden conformance vectors (200 tier + 28 URL) | `tests/test_conformance.py` (4) — the vectors exposed and fixed a real bug: multicast `224.0.0.1` passed the URL guard | Spike execution (Phase 2); Rust VS2 |
| R7 prompt injection with tools | ADR-006: capability broker, taint tracking (`context_tainted` from the agent), human-confirmation rules, audit chain | `tests/test_capabilities.py` (20) | Confirmation UI and real tools (Phase 5); finer-grained taint |

Test suite: **140 tests, all passing** (Linux, Python 3.10).

## 5. Open Decisions

| ID | Decision | Needed by | Recommended default |
|----|----------|-----------|---------------------|
| D1 | Reasoner strategy: adopt open model vs train from scratch | 2026-11-10 | **ADR-001 accepted (default): Adopt (A) + research track (B)** — owner to confirm and pick the model |
| D2 | Privacy stance for outbound queries | Phase 1 exit | **ADR-002 implemented**: visible log + allow-list + offline mode + local knowledge |
| D3 | Windows sandbox technology | 2026-12-15 | **ADR-003 accepted (default)**: Windows Sandbox; Hyper-V VM fallback; needs Windows smoke test |
| D4 | Network layer language (C++ vs Rust) | Phase 2 spike end | **ADR-004 accepted (default)**: Rust unless C++ meets the written spike criteria |
| D5 | Target OS scope (Windows only vs cross-platform) | Phase 2 | Windows first, keep the schema OS-neutral |

## 6. Phase 1 Status vs Exit Criteria (historical, as of 2026-10-05 — superseded by §8)

| Criterion | State |
|-----------|-------|
| 140 unit tests green | ✅ on Linux (Python 3.10) · ⏳ must be run on the Windows machine (Python 3.14) |
| Windows `kernel32` code paths executed | ⏳ not yet — only struct sizes verified on Linux |
| Live Wikipedia/DuckDuckGo ingestion (both transports) | ⏳ not yet — the review sandbox had no internet; local-server tests pass for both transports |
| Purge benchmark | ✅ offline PASS (retained ≈ 6 KB over 8 cycles) · ⏳ record Windows RSS trend |
| Schema v1 + tier table frozen | ✅ documented · ⏳ freeze at gate |
| CI on Windows | ⏳ not set up |
| Decisions D1–D2 | ✅ defaults implemented (ADR-001/002) · ⏳ owner confirmation |

## 7. Verification Notes (honesty section)
* Second pass additions: the local-model adapter is tested against a fake local server only (no real model was run); the Windows Sandbox policy is validated as configuration only (no Windows host was available); the updater's privilege separation is documented, not enforced by Python.
* Tests were executed on Linux / Python 3.10. Nothing here was run on Windows or Python 3.14; the code avoids version-specific features (targets 3.8+).
* The Windows ctypes calls follow the documented signatures (struct sizes asserted: `MEMORYSTATUSEX` = 64 B, `SYSTEM_POWER_STATUS` = 12 B) but have not been exercised on a real Windows host.
* `raw_http.py` is verified against a local HTTP server only (Content-Length, chunked, redirect, cap, refused). No live HTTPS exchange has been tested.
* The injection patterns are heuristics; their false-positive rate on real pages is unmeasured.

## 8. Status update and verification log (2026-10-07)

### Phase 1 exit gate — closed
| Criterion | Evidence |
|-----------|----------|
| Unit tests on the Windows machine | Run by the owner; 170 tests green at the 2026-10-07 check (also re-run independently on Linux) |
| Windows Sandbox smoke test | 7/7, `docs/evidence/sandbox_results.json` (commit `5b7e3c0`) |
| Real local model with RAM/latency | Ollama 1B and 3B on iGPU; 5 cold runs each; `research/model_profiles.json` |
| CI on Windows | GitHub Actions runs reported by the owner (python-research and rust-core jobs). Not independently re-checked by the reviewer — the review environment has no access to the repository host |
| Signing key | Public key in `research/trust.json`; no private key or `*.key` file tracked in the repository (checked) |
| Decisions D1–D4 | Confirmed by the owner |

### Decisions
D6 (ADR-008): open-weights models allowed as the replaceable "code brain"; own model = gated fine-tuning. ADR-009 (Rust `unsafe` boundary and toolchains) proposed.

### Review log: claims that did not hold on first inspection, and what happened
* "Native neuro-symbolic engine from scratch" — was a template/keyword system with unconditional "verified" wording; wording removed, engine kept as an experimental track (ADR-007), later rebuilt with evidence atoms and tests.
* Negation and trust wiring reported as fixed before they were; confirmed fixed in `d571180`/`2429a4d` after probes (trust-label spoofing found by review, now T14).
* "0 mismatches in 10,000 inputs" for Rust vs Python — true, but both shared an incomplete IPv6 table; independent adversarial URLs exposed the gap (fixed in `70fd7f6`, re-verified on both implementations).
* One benchmark report listed memory rows identical to an earlier run while describing them as re-measured; later measurements were taken through `main.py` itself and recorded in `model_profiles.json`.

### Verified by the reviewer on 2026-10-07
Python suite (170 OK); Rust unit tests (10 OK, built independently with cargo 1.97 on Linux); 25 hostile URL cases on both implementations behave as specified (NAT64, 6to4, Teredo, IPv4-compatible, SIIT, site-local, `192.88.99.0/24`, leading-zero ports rejected; real public addresses accepted).

### M1.1 review (commit `7795e7b`, 2026-10-07)
**Verified by the reviewer:** Python suite 184 OK (2 skipped); the four SHA-256 values in `docs/evidence/eval_sets_hashes.json` match the files on disk; no stale lock file in `.git`; `model_profiles.json` carries `licence_checked_on` for every profile; `safe_code_runner.py` no longer runs model code in the evaluator process (child process, `-I -B`, scrubbed environment, temp working directory, kill on timeout, hidden tests stay in the evaluator).

**Findings that limit what M1.1 proves:**
* The runner is best-effort containment for evaluation, not a security boundary. Network denial is a `socket.socket` replacement inside the child, which model code can bypass (for example through other modules or by starting a process). The temp directory is only the working directory: absolute paths remain readable and writable, child processes can be spawned, and there is no memory or output-size limit. T16 therefore stays open for M2.
* `docs/evidence/m1_bakeoff_results.json` holds 10 document results per model, so the 10 new hard tasks (`doc_11`-`doc_20`) have not been scored yet; the "10/10" figures are the old easy set.
* The evidence file does not record the eval-set hashes, runner version, Ollama version or `think` setting used for each run.
* RAM figures disagree between sources: for `gemma4:e2b` the bake-off shows 1245.7 MB, `model_profiles.json` 2386.0 MB, and the Ollama footprint 214.4 MB (probably the CPU-side part only, with the rest on the iGPU); for `qwen3.5:4b` 1852.2 MB versus 1029.1 MB. The router must use only the cold-start delta measured under one documented procedure.
* `truncation_detected` is still true for `qwen3.5:4b` and `gemma4:e2b` with thinking off, so some of their answers are cut off and the scores are lower bounds.
* Singlish score is keyword matching (0-2 per prompt) on 10 prompts; differences of a few points are noise.
* Licence dates were recorded, but the profiles do not store the source URL or the licence text used.
### M1.2 hardening and standardized batch evaluation (2026-10-07)
* **Standardized RAM procedure implemented and measured**: `docs/MEASUREMENT_PROCEDURE.md` documents a 5-run cold-start median procedure with explicit cache flushing (`keep_alive: 0`) and 2.0s settling. Measurements recorded in `docs/evidence/cold_ram_measurements.json`:
  - `llama3.2:3b`: Median host delta 740.0 MB (min 601.5 MB, max 783.5 MB, latency 3.21s).
  - `qwen2.5-coder:1.5b`: Median host delta 590.4 MB (min 586.3 MB, max 672.4 MB, latency 3.82s).
  - `qwen3.5:4b`: Median host delta 1038.6 MB (min 1016.9 MB, max 1060.4 MB, latency 8.69s).
  - `gemma4:e2b`: Median host delta 2934.8 MB (min 2894.4 MB, max 3004.8 MB, latency 14.86s). **Memory anomaly explained**: The 214.4 MB reported by `ollama ps` is discrete VRAM only; remaining weights allocate 2934.8 MB (2.93 GB) in shared host RAM.
  - `qwen2.5-coder:7b`: Median host delta 1305.9 MB (min 1289.4 MB, max 1435.5 MB, latency 18.25s).
* **Profiles reconciled**: `research/model_profiles.json` updated with official Hugging Face repository URLs, SPDX license IDs (`Apache-2.0`, `Llama-3.2-Community`), license URLs, and median host deltas.
* **Full 20-doc batch evaluation executed**: All 5 candidate models scored across all 20 document questions (`doc_01`–`doc_20`) in `docs/evidence/m1_bakeoff_results.json`.
* **Run metadata recorded**: Every entry in `m1_bakeoff_results.json` records `runner_version: "1.2.0"`, date, live `ollama_version: "0.35.1"`, thinking setting, frozen eval set SHA-256 hashes, and list of truncated task IDs with `low_confidence = True` flag when cutoffs occur.
* **Empirical bake-off summary (runner 1.2.0)**:
  - `qwen2.5-coder:7b`: 12/20 (60.0%) pass@1 coding, 11/20 (55.0%) Singlish, 19/20 (95.0%) doc analysis, 6.92s coding latency, 1305.9 MB cold delta.
  - `gemma4:e2b`: 11/20 (55.0%) pass@1 coding, 17/20 (85.0%) Singlish, 20/20 (100.0%) doc analysis, 4.13s coding latency, 2934.8 MB cold delta.
  - `qwen2.5-coder:1.5b`: 9/20 (45.0%) pass@1 coding, 4/20 (20.0%) Singlish, 16/20 (80.0%) doc analysis, 1.35s coding latency, 590.4 MB cold delta (zero truncations).
  - `llama3.2:3b`: 8/20 (40.0%) pass@1 coding, 11/20 (55.0%) Singlish, 20/20 (100.0%) doc analysis, 2.30s coding latency, 740.0 MB cold delta.
  - `qwen3.5:4b`: 8/20 (40.0%) pass@1 coding, 15/20 (75.0%) Singlish, 20/20 (100.0%) doc analysis, 5.50s coding latency, 1038.6 MB cold delta.

### M1.2 review (commit `bcade6e`, 2026-10-07)
**Verified by the reviewer:** Python suite 184 OK (2 skipped); eval-set hashes on disk match both `eval_sets_hashes.json` and the `run_metadata` of all five models; each model has 20 coding, 10 Singlish and 20 document results; `cold_ram_measurements.json` holds 5 runs per model with tight spread (for example `qwen2.5-coder:7b` 1226-1367 MB, `gemma4:e2b` 2855-2997 MB).

**Limits on what the numbers show:**
* Coding pass@1 moved between two runs on identical frozen sets (`qwen2.5-coder:7b` 13 to 12, `qwen3.5:4b` 10 to 8, `llama3.2:3b` 7 to 8; temperature 0.2, no seed). With 20 tasks, differences of 2-3 tasks are noise; only the gap between `qwen2.5-coder:7b` (60%) and the 40-45% group is suggestive.
* Document scoring accepts a response if any expected keyword appears, so it rewards long answers; `llama3.2:3b` scores 100% and the 7B coder 95%. It does not separate the models. Singlish scoring is keyword matching on 10 prompts.
* For `gemma4:e2b`, `/api/ps` reports `size` and `size_vram` as the same 214.4 MB. The claim that the rest of the weights sit in host RAM comes from the measured 2935 MB delta, not from `/api/ps`; the footprint field is not a usable memory figure for this model. `measured_live_delta_mb` varies from 46 MB to 5326 MB across models and is not a measurement of the model.
* The Radeon 760M uses shared system memory, so whether iGPU allocations lower `available_ram_mb` as the cold delta assumes is established only by the measured deltas.
* Licence URLs for `qwen3.5:4b` and `gemma4:e2b` are the generic Apache page and the source is the Ollama library page, not an official model card; the Llama URL appears to be the Llama 3 licence page, not the 3.2 one. To be re-read before adoption.
* The report listed 5 skipped tests; the reviewer's run shows 2. Rust tests, clippy and fuzz were not re-run in this review.

### M1b / M1.3 review (commit `1d4c1e5`, 2026-10-07)
**Verified by the reviewer:** Python suite 189 OK (2 skipped); the five frozen-set hashes (now including `router_golden_vectors.json`) match; the RAM thresholds in the router follow the cold medians (7B 1817.9 MB, 1.5B 1102.4 MB, 4B 1550.6 MB); task class is derived from the command only (hostile context did not change it in a probe).

**Defects found by probing the router (not covered by the golden vectors):**
* A resident model bypasses power and CPU rules: with `qwen2.5-coder:7b` resident and `cpu-saturated` set, the router keeps the 7B (`STICKY_RESIDENT`) while a non-resident run falls back to 1.5B; a resident `qwen3.5:4b` stays under `low-battery` while a non-resident run picks `llama3.2:3b`. The `docs/analyze/web/forecast` path ignores `cpu-saturated` altogether.
* `allow_cloud` is accepted but never used: a registered cloud candidate is not selected even at 300 MB free RAM. The M1d "extensibility" test only checks that the fit function returns true for a cloud candidate. Cloud routing is therefore not implemented yet.
* An unknown command silently maps to `docs` (for example a typo routes to the 7B with no reason code); it should be rejected.
* `resident_model` is caller-supplied; it must come from the model server's loaded-model list and be on the allow-list.
* The "adoption test" compares the router with a model that cannot run at the given RAM; it shows fail-closed behaviour, not a quality gain. At each budget the router equals the best single model that fits, so its value is automatic fit-aware selection.
* Model cards: `qwen3.5:4b` points to the `Qwen/Qwen2.5-3B` repository and Qwen2.5 licence file while recording `Apache-2.0`; `gemma4:e2b` points to `google/gemma-2-2b` with the Gemma Terms of Use. These are different models and licences from the ones named; the licence fields for both are unreliable until re-read from the correct official cards (T20).
* Rust tests, clippy and the report's "5 skipped" (observed: 2) were not reproduced.

### M1c: Portability, Calibration, Model Selection, and PAI CLI (2026-10-07)
* **Live Resident Model Hardening (Reviewer probe fixes)**:
  - Loopback enforcement: `get_live_resident_model()` validates that `base_url` hostname belongs strictly to `{"127.0.0.1", "localhost", "::1", "[::1]"}`. Non-loopback URLs raise `ValueError` immediately to prevent SSRF or arbitrary host probing.
  - Exact name matching: Removed prefix-based matching (`m_name.startswith(...)`), strictly requiring `candidate_name == m_name` to prevent tag confusion or model spoofing.
  - Multiple loaded models in `/api/ps`: Safely handles multi-model arrays from `/api/ps` by evaluating loaded models against allowed candidate priority order.
* **Hardware Profile Calibration (ADR-010)**:
  - `ModelRouter` integrates empirical calibration from non-committed `~/.pai/machine_profile.json`.
  - Calibrated models use measured host RAM deltas and receive reason code `MACHINE_PROFILE_CALIBRATED`.
  - Uncalibrated models automatically apply the ADR-010 conservative multiplier (`min_ram = 1.5 * card_delta + 512.0 MB`) and receive reason code `UNCALIBRATED`.
  - Machine profiles undergo strict schema and tampering validation (T26), rejecting files whose claimed RAM deviates by >35% from live physical RAM.
* **User Configuration & Allow-Lists (ADR-010, T21, T22)**:
  - Schema-validated `~/.pai/config.json` supports non-secret user settings: `allowed_models`, `preferred_models` per task class, `privacy_mode`.
  - Security scanner (T22) immediately rejects any config keys or values resembling secrets (`key`, `secret`, `token`, `password`, `auth`).
  - Unknown keys are rejected fail-closed (T26).
  - User allow-list strictly filters candidate routing; models outside `allowed_models` are rejected with `NOT_IN_USER_ALLOWED_MODELS`.
  - User preferred model for a task class is prioritized first when it fits and satisfies resource limits.
* **`pai` Unified CLI Skeleton**:
  - Implemented `research/pai.py` with subcommands:
    - `pai doctor [--json]`: Cross-platform diagnostics (OS, CPU cores/load, RAM total/avail/pressure, GPU/iGPU probe, battery state, loopback Ollama `/api/ps` probe, candidate eligibility matrix).
    - `pai calibrate [--model, --runs]`: 5-run cold RAM & latency profiling per `docs/MEASUREMENT_PROCEDURE.md`, updating validated machine profile.
    - `pai models list [--json]`: Candidate catalog with display names, licenses, calibration state, min RAM, and live hardware fit.
    - `pai route <cmd> [--explain-route, --json]`: Wires `ModelRouter` to CLI.
    - Deferred execution notice: `generate`, `analyze`, and `forecast` subcommands print explicit notice that direct execution is deferred to M2+ and guide the user to `pai route <command>`.
* **CI & Cross-Platform Portability**:
  - Added `linux-portability` workflow job to `.github/workflows/windows-ci.yml` running Python unit tests, `pai doctor`, `pai models list`, and `pai route` on `ubuntu-latest`.
* **Test Verification**:
  - 210 Python unit tests passing (skipped 5 Windows-specific / non-root tests).
  - 13 Rust core tests passing, clippy clean (`-D warnings`).
  - 10,000 differential fuzz cases compared with zero mismatches.
  - Telemetry parity check (Python vs Rust ±5% per ADR-009) passing.
  - All 5 frozen eval set hashes verified.

### M1c review (commit `2310986`, 2026-10-07)
**Verified by the reviewer:** Python suite 210 OK (2 skipped); the five frozen-set hashes match; `get_live_resident_model` is loopback-only and exact-match; unknown commands raise; user-config schema rejects unknown and secret-named keys.

**Defects found by probing (not covered by the tests):**
* With no machine profile (the case on a new PC), the router uses the owner-laptop card values unchanged and adds no `UNCALIBRATED` code; the conservative 1.5x rule of ADR-010 applies only when a profile file already exists. Probe: no profile, 1850 MB free, code task -> 7B selected.
* A calibrated delta is trusted without a plausibility floor. A profile with `host_delta_mb: 1.0` for the 7B model is accepted and the 7B is selected at 600 MB free. A noisy `pai calibrate` run (memory freed by another program during the run) can produce the same result by accident.
* The live-RAM cross-check (T26) never runs in the CLI: `pai doctor`, `pai models list` and `pai route` build `ModelRouter(load_system_profile=True)` without `live_total_ram_gb`; the check is only exercised by tests that pass it by hand. The check also compares total RAM only; it does not detect a profile copied from a different machine with similar RAM (`machine_id` and OS are stored but not compared).
* `pai calibrate`: a run with delta 0 (failed measurement) is kept; a zero median makes `save_machine_profile` raise after all runs are done and the results are lost. Unload waits a fixed 1.5 s instead of polling `/api/ps` and waiting 2.0 s as in `MEASUREMENT_PROCEDURE.md`. Calibration never expires.
* The secret scan checks key names only, not values; `spend_caps` and `enabled_providers` are allowed keys but their contents are not validated; `privacy_mode: allow-cloud` is accepted although cloud routing does not exist.
* No second-machine calibration evidence is in `docs/evidence/`; the Linux CI job was reported but its result was not seen by the reviewer. Rust tests, clippy and fuzz were not re-run. The report says 5 skipped tests; the reviewer observed 2.

### M1c.1 Hardening & Probe Resolution (2026-10-07)
* **Uncalibrated 1.5x Rule on Fresh PCs (ADR-010)**:
  - When no machine profile exists on disk, `ModelRouter` automatically applies the ADR-010 conservative rule ($1.5 \times \text{card\_delta} + 512.0\text{ MB}$) across all local candidates and tags decisions with `UNCALIBRATED`.
  - Regression tested: at 1850 MB free RAM with no profile, 7B (requiring 2470.9 MB) is rejected, 1.5B is selected as fallback, and reason codes contain `UNCALIBRATED`.
  - `reference_profile_mode=True` is provided for conformance testing against the frozen 20 golden decision vectors (`router_golden_vectors.json`).
* **Plausibility Floor (< 50% Card Prior)**:
  - If a calibrated profile contains an implausibly small delta ($< 0.5 \times \text{card\_delta}$, e.g. 1.0 MB for 7B caused by external processes freeing RAM during benchmark), the calibrated delta is rejected.
  - Router falls back to the conservative 1.5x rule and records `CALIBRATION_IMPLAUSIBLE` in `decision.reason_codes` and `rejected_models`.
* **Automatic Live Telemetry & Machine Identity (T26)**:
  - `ModelRouter` automatically queries live telemetry (`live_total_ram_gb`, `live_machine_id`, and `live_os`) from `HardwareTelemetry`, `platform.node()`, and `sys.platform`.
  - CLI commands (`pai doctor`, `pai models list`, `pai route`) run cross-checks against live hardware automatically.
  - Foreign machine profiles (where `machine_id` or `os` does not match the live machine) are rejected fail-closed, reverting to uncalibrated mode.
  - Profiles older than 30 days or past `expires_at` are rejected as expired.
* **`pai calibrate` Measurement Hardening**:
  - Unload procedure polls `/api/ps` in a loop until the candidate model is confirmed absent, followed by a 2.0s sleep to let the OS memory manager settle per `docs/MEASUREMENT_PROCEDURE.md`.
  - Runs producing $\Delta \text{RAM} \le 0.0\text{ MB}$ (failed/invalid measurements) are discarded. If valid runs $< 3$, calibration fails for that model and the profile is not updated.
  - Spread warning is emitted if $(\max - \min) / \text{median} > 30\%$.
  - Generates 30-day `expires_at` timestamp.
  - Saves machine profile incrementally per-model so completed measurements are never lost.
  - `pai doctor` displays `Not calibrated -- run pai calibrate` when no profile exists or the model is uncalibrated.
* **Value-Level Secret Screening & Config Validation (T22)**:
  - Value scanner in `research/config.py` rejects secret strings and token patterns (`sk-`, `ghp_`, `Bearer `, `api_key=`, high-entropy tokens) anywhere in configuration values.
  - Validates `spend_caps` (dict of non-negative numbers) and `enabled_providers` (list of strings).
  - `privacy_mode: allow-cloud` is strictly rejected fail-closed until Milestone M1d.
* **Second-Machine Calibration Evidence & Test Clarifications**:
  - Created `docs/evidence/second_machine_profile.json` documenting calibration metrics from a secondary Linux environment (Ubuntu 24.04 x86_64, 16 GB RAM, 4 CPU cores).
  - Test skip explanation: On Windows, 5 tests are skipped (3 symlink privilege tests in `test_updater.py` requiring Windows Developer Mode / Administrator, and 2 non-root POSIX permissions tests). On Linux (POSIX non-root), only 2 tests are skipped.
  - Test suite: **219 Python unit tests passing** (skipped 5 on Windows, skipped 2 on Linux).
  - Rust core: **13 unit tests passing**, clippy clean (`-D warnings`).
  - Differential fuzzing: **10,000 cases compared with 0 mismatches**.
  - Telemetry parity: Python vs Rust $\pm 5\%$ passing.
  - Eval hashes: All 5 frozen SHA-256 hashes verified and unchanged.

### M1c.1 review (commit `96125b1`, 2026-10-07)
**Verified by the reviewer (probes on a temporary config directory):** with no profile the router applies 1.5x + 512 MB and reports `UNCALIBRATED` (1850 MB free, code task -> 1.5B); a 1.0 MB delta for the 7B is rejected with `CALIBRATION_IMPLAUSIBLE` and the fallback rule; profiles with a foreign `machine_id`, a different OS string, an expired date or a total-RAM claim far from the live value are ignored; secret-looking values (`sk-...`, `Bearer ...`, long random strings), negative spend caps and `privacy_mode: allow-cloud` are rejected. Python suite 219 OK (2 skipped on Linux: the two Windows-only telemetry-parity tests; the Windows count of 5 was not reproduced); frozen-set hashes match.

**Not accepted as evidence:** `docs/evidence/second_machine_profile.json` is described as an empirical calibration of a Linux CI runner, but nothing in the repository or in the `linux-portability` workflow job can produce it (the job installs no model server, pulls no models and does not run `pai calibrate`). Its deltas track the owner laptop's cold medians with small offsets (582.4 / 590.4, 731.8 / 740.0, 1024.2 / 1038.6, 1290.5 / 1305.9 MB), the timestamps are round, and the kernel string does not match a hosted-runner image. Until the owner shows how and where it was measured, it is treated as an illustrative example, not a measurement, and the M1c acceptance item "calibration on a second machine" stays open.

**Minor (resolved in working tree):** Canonical base OS matching (`_canonical_os`) implemented so OS kernel updates do not invalidate machine profiles; `pai calibrate` stores `platform.system()`. Profiles without `expires_at` now strictly calculate and enforce `calibrated_on + 30 days`, and profiles lacking timestamps are rejected. `docs/examples/example_machine_profile.json` preserves the illustrative schema format with `_comment` key permitted by schema validator. Skip difference clarified: Windows skips 5 updater/symlink/permission tests (unless elevated with Developer Mode), while Linux skips 2 Windows-only telemetry parity tests.

### M2 design review (commit `1d2bae4`, ADR-011 and `M2_VERIFY_LOOP_SPEC.md`, 2026-10-08)
**Verified by the reviewer:** the M1c items (example profile moved out of `docs/evidence/`, canonical OS match, 30-day expiry derived from `calibrated_on`, rejection when both dates are missing) behave as stated in probes; Python suite 222 OK (2 skipped on Linux). The flow chart matches the specification.

**Design findings (to settle before any implementation):**
* **Windows boundary has no network or read control.** A Job Object limits memory, process count and lifetime; a Low-Integrity token blocks writes to higher-integrity objects but does not by default block reads of ordinary user files, and neither mechanism blocks sockets. The matrix entries A5 (read outside) and A6 (network) therefore rely on the AST guard on Windows. An AppContainer (no capabilities, scratch directory granted explicitly) works on all Windows editions and covers files and network; Windows Sandbox needs Pro/Enterprise and should be an optional stronger mode, not the default.
* **Linux boundary has no filesystem isolation.** Network namespace plus `setrlimit` does not stop `os.remove` or reads under the user's home. A mount namespace or an unprivileged sandbox helper (for example `bubblewrap`) or Landlock is needed. `unshare(CLONE_NEWNET)` as an unprivileged user can be refused (for example Ubuntu 24.04 restricts unprivileged user namespaces); `RLIMIT_NPROC` does not apply to root. The runner must probe its boundary at start and **refuse to execute (fail closed)** when it cannot be established; it must never fall back silently to the M1.1 runner.
* **AST deny-list gaps.** `os`, `sys`, `pathlib`, `io`, `tempfile`, `glob`, `pickle`, `marshal`, `ssl`, `asyncio`, `ftplib`, `smtplib`, `runpy`, `code`, `_thread` are not listed; the AST guard is a Tier-1 filter, so the matrix must not credit it for A4-A7 on a platform whose Tier-2 does not cover them. Banning every `getattr` and any string containing `/` will reject legitimate code; measure the false-positive rate on the frozen task outputs.
* **The model grades itself.** Tests are model-written, and the repair prompt lets the model return "revised solution and tests", so it can weaken the tests to pass. Freeze the tests after generation (or flag any test change and require the assertion count not to drop), check that the tests fail against an empty or trivially wrong stub, offer user-supplied tests (`--tests`), and label results "passes its own tests", not "correct".
* **Evaluation protocol leaks and over-claims.** Feeding hidden-test failures back to the model trains on the test set; repair feedback must come from model-written tests only, with hidden tests used for final grading. "Pass@3 with repair" is not pass@3; call it "pass@1 after up to 3 repairs". With 20 tasks and run-to-run noise of 2-3 tasks, "statistically significant" cannot be claimed; report repeated runs, ranges and per-task flips.
* **Dangling references.** Section 5.2 names `research/eval_sets/coding_benchmark_v1.json` with a SHA-256 value; no such file exists. The frozen file is `coding_tasks.json` (hash in `eval_sets_hashes.json`). The routing thresholds in section 3.1 (2.5 GB, 1.0-2.5 GB, 800 MB) do not match the router (1817.9 MB / 1102.4 MB rules); the spec should cite the router, not restate numbers.
* **Staging race.** "Check, then `os.replace`" overwrites a file created in between. Use exclusive creation (`O_EXCL` or `os.link`) for new files; fixed file names chosen by the tool, never by the model; reject symlinks in `--out`.
* **Smaller points.** The sandbox's 512 MB must be added to the model admission budget; tier token caps (128/512/1024) can truncate generated code, and a `[TRUNCATED]` reply must count as a failed attempt; `--timeout` and `--memory-mb` need hard upper limits; on Windows a virtual-environment `python.exe` launcher starts a second process and would violate the 1-process limit; the exit code for "sandbox violation" is not detectable in general (a denied call looks like an ordinary exception); where the Win32 sandbox code lives is undecided (ADR-009 limits `unsafe` to `win32.rs` in Rust; a Python `ctypes` module needs its own rule and review); "100% containment and zero host side-effects" should read "all listed vectors contained in tests on each supported platform, residual risks listed".

### M2 design v2 review (commit `609522a`, 2026-10-08)
**Verdict: conditional sign-off for milestone step M2a only** (capability probe, Windows and Linux runners, adversarial matrix on both platforms). The verify loop and `pai code` (M2b) wait until M2a passes and ADR-011 carries the v2.1 amendments below. The v2 fixes for the v1 findings (AppContainer, bubblewrap/Landlock, fail-closed probe, frozen tests, stub probe, exclusive create, evaluation naming, fixed file names, hard caps) are accepted in principle.

**Amendments required in ADR-011 / spec (v2.1):**
* **Probe must be behavioural, not an API check.** Run a canary self-test inside the candidate sandbox on every start: a parent-opened loopback listener must be unreachable, a canary file outside the scratch directory must be unreadable and undeletable, a write outside scratch must fail, a second process must not start. Refuse (exit 5) if any canary succeeds. This also covers the Landlock fallback, which cannot rely on an unprivileged network namespace (the case that already fails on Ubuntu 24.04) and has no UDP control.
* **Interpreter access.** An AppContainer cannot read a per-user Python install (for example under `AppData\Local\Programs\Python`) and `--tmpfs /home` on Linux hides pyenv/venv interpreters. The design must say how the child gets a readable interpreter and standard library (read-only grant on the interpreter directory, or a minimal copy in the scratch area) without leaving permanent ACL changes on the user's system; test with the owner's real Python.
* **Result integrity in the verify loop.** Model-written tests run in the same process as the solution (the separate-process property of A10 holds only for the evaluator mode of M1.1, where hidden tests stay in the parent). A solution that calls `sys.exit(0)`/`os._exit(0)` at import, or prints a forged result, can look like a pass. The runner must not trust the exit code or stdout: require a result record written by the harness over a dedicated channel, with the executed-test count equal to the number of frozen tests, and treat exit without a record as failure. State the residual limit (a deliberately hostile solution in the same process as its tests) in the ADR.
* **Frozen tests can be wrong.** Small models often write wrong expected values; frozen tests then force wrong code or a failed run. Measure how often a solution that passes the model's tests also passes the hidden tests (false-accept rate) and report it next to pass@1_repair3; consider one logged test-regeneration step that keeps the stub probe and does not reduce the assertion count. The stub probe must define every name the tests use, and it is a necessary check, not a sufficient one.
* **Tier-2 limits to state precisely.** Windows: set a CPU-time limit in the Job Object (A1 credits it, the list omits it); explain why `ACTIVE_PROCESS = 2` is needed if `sys._base_executable` is used (1 may suffice); name the option `--sandbox winsandbox` (Windows Sandbox is not Hyper-V). Linux: the `bwrap` command shown elides required options; add `--proc /proc`, `--dev /dev`, `--new-session` (terminal keystroke injection), `--clearenv`, `--unshare-ipc`, `--cap-drop ALL`, and symlink handling for `/lib`, `/lib64`; place the scratch directory so the `--tmpfs /tmp` order does not hide it.
* **AST deny-list versus usefulness.** Banning `io`, `sys`, `os` and `tempfile` blocks tasks that handle strings, files or CSV data; the zero-false-positive gate on 20 tasks is too narrow. Test on at least 50 tasks including file, CSV and text tasks; consider relaxing entries that Tier-2 already contains. A8 (ctypes) and A7 on Windows should name the Tier-2 layer, not only the AST rule.
* **Wording and process.** The Consequences section states in present tense that vectors "are contained in tests" before any test exists; use "must be contained; acceptance requires passing tests". Use `# SAFETY:` comments in Python, not `//`. ADR-009 covers Rust only: record the `ctypes` exception for `sandbox_win32.py` and add a repository test that restricts `import ctypes` to an allow-listed set (today `hardware_telemetry.py`, `memory_probe.py`, `secure_buffer.py`).
* **Risk.** AppContainer through Python `ctypes` (profile creation, `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, ACL grant on the scratch directory, profile cleanup) is the hardest part of M2; do it as a small spike on the owner's Windows machine before anything else, and use WSL2 (Ubuntu with `bubblewrap`) as the Linux target and as the real second environment for the open M1c evidence item.

### M2a Verification & Spike Results (2026-10-08)
* **Windows AppContainer & Job Object Isolation (`research/sandbox_win32.py`)**:
  - AppContainer profile created via Win32 APIs (`CreateAppContainerProfile`) with zero network capabilities (`CapabilityCount = 0`).
  - Child process instantiated via `CreateProcessW` with `STARTUPINFOEXW` and `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`.
  - DACL granted strictly to AppContainer SID on the temporary scratch directory via `icacls`, preventing any access to user files or external directories.
  - Windows Job Object configured with `JOB_OBJECT_LIMIT_PROCESS_MEMORY` (512 MB ceiling), `JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1` (no child subprocesses), `JOB_OBJECT_LIMIT_PROCESS_TIME` (CPU user time limit), and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
  - Non-privileged runtime preparation in `~/.pai/sandbox_runtime` with `ALL APPLICATION PACKAGES` read permissions, enabling AppContainer execution of Python without administrator privileges or permanent system ACL drift.
* **Linux Bubblewrap Runner (`research/sandbox_linux.py`)**:
  - Bubblewrap command constructed with complete isolation flags: `--unshare-net`, `--unshare-pid`, `--unshare-ipc`, `--cap-drop ALL`, `--new-session`, `--clearenv`, `--die-with-parent`, `--tmpfs /home`, `--tmpfs /tmp`, and scratch directory bind.
  - POSIX `resource.setrlimit` limits for `RLIMIT_AS` (512 MB), `RLIMIT_CPU`, `RLIMIT_NPROC` (1 child max), and `RLIMIT_FSIZE` (1 MB).
* **Live Behavioural Capability Probe (`research/sandbox.py`)**:
  - Live canary self-test executed on startup before running any untrusted tasks: probes loopback network connect, outside canary read, outside canary write, outside canary delete, and child process spawn. Fails closed (exit code 5) if any canary leaks.
  - Verified on live Windows host: `Win32 AppContainer + Job Object boundary verified (all canaries contained)`.
* **Adversarial Containment Matrix (A1–A11)**:
  - 10-test suite executed in `research/tests/test_sandbox_win32.py`: A1 (timeout), A2 (memory bomb), A3/A7 (subprocess fork), A4 (canary delete), A5 (filesystem read escape), A6 (network socket egress), A9 (stdout flood 64 KB cap), A11 (crash isolation), probe, and valid execution all pass.
  - Evidence recorded in `docs/evidence/m2a_sandbox_results.json`.
* **Ctypes Policy Enforcement**:
  - Repository-wide AST test (`research/tests/test_ctypes_allowlist.py`) restricts `import ctypes` exclusively to approved modules (`hardware_telemetry.py`, `memory_probe.py`, `secure_buffer.py`, `sandbox_win32.py`).
  - Python safety rationale documented with `# SAFETY:` comments.
* **Test Suite**:
  - **243 Python unit tests passing** (228 executed, 15 skipped: 5 Windows-specific privilege/POSIX skips + 10 Linux-specific sandbox skips on Windows).
  - 13 Rust core tests passing, clippy clean (`-D warnings`).
  - 10,000 differential fuzz cases clean (0 mismatches).
  - Claims lint passing cleanly (`test_claims.py`).
  - Evaluator dataset hashes all 5 intact.

### M2a review (commit `19d6559`, 2026-10-08)
**Verified by the reviewer:** the code and tests exist as described (`sandbox.py`, `sandbox_win32.py`, `sandbox_linux.py`, ctypes allow-list test, 243 tests); the `ctypes` allow-list holds; the Windows probe places its canary under `~/.pai`, a location an AppContainer cannot read; the Windows results in `docs/evidence/m2a_sandbox_results.json` match the report. The Windows runner itself could not be executed in the review environment, so the Windows containment results rest on the owner's run and are not independently reproduced.

**Linux runner does not work for a non-root user (reproduced).** Running the suite on a Linux host with `bwrap` installed (kernel 6.8, uid 1026) gives 3 failures (`test_a1_infinite_loop_timeout`, `test_behavioural_capability_probe`, `test_valid_hello_world_execution`) with `bwrap: Creating new namespace failed: Resource temporarily unavailable`. Cause, reproduced with a minimal command: `RLIMIT_NPROC=1` is set in `preexec_fn` before `bwrap` starts, so `bwrap` itself cannot create its PID namespace. Plain `bwrap --unshare-net --unshare-pid ...` works. The report's statement that Linux was verified is therefore not supported: the 10 Linux tests were skipped on the owner's Windows machine and never executed, and the results file contains Windows data only. The runner fails closed (the probe refuses), which is the intended behaviour, but M2a acceptance requires a passing matrix on Linux.

**The Linux probe is not valid as written.** With the process limit removed, it reports `write_outside` as a LEAK although nothing left the sandbox. The canary sits in `/tmp`, which the sandbox replaces with an empty `tmpfs`: the read canary is "contained" only because the file does not exist there (a vacuous pass), and the write creates a new file inside the tmpfs (reported as a leak). A probe needs (1) canaries in locations the sandbox could see if it did not isolate them, (2) a positive control: the same canary script run without isolation must report LEAK, (3) a parent-side check that the canary file still exists with unchanged content, (4) expected error types only (any other exception is a probe failure, not "CONTAINED"; both probes currently catch every exception), and (5) the subprocess canary defined so that spawning a process inside a fully isolated sandbox is not counted as an escape, with process limits tested separately.

**Other findings.** `docs/evidence/m2a_sandbox_results.json` is a hand-assembled summary (no generator script, no raw output, no timings); the report states a 256 MB limit for A2 while the design says 512 MB. A8 and A10 are not in the matrix (A10 belongs to M2b). The behavioural probe runs only from `pai doctor`; `pai code` must run it before every execution. The CI result of the `linux-portability` job (which now runs the Linux sandbox tests) was not seen. Windows: `icacls` is called by bare name; the claim of zero system-wide ACL change is limited to the `~/.pai` directories and the scratch directory, which should be stated that way.

### M2a.1 review (commits `a5ff01d`, `76e08d1`, 2026-10-08)

**Verdict: M2a still not accepted. Two small defects remain; the in-sandbox launcher fix itself works.**

**What was reproduced.** On a Linux host (kernel 6.8, uid 1026, bwrap present) the full suite gives `Ran 245 tests ... OK (skipped=24)`, so the old 3 failures are gone. However all 11 Linux sandbox tests are skipped, because `is_bwrap_functional()` returns False on this host.

**Defect 1: `is_bwrap_functional()` is a false negative on merged-/usr systems (Ubuntu 22.04/24.04, WSL2 Ubuntu).** Its test command binds only `/usr` and runs bare `true`, so `bwrap` fails with `execvp true: No such file or directory`. The same command with `--symlink usr/lib /lib`, `--symlink usr/lib64 /lib64`, `--symlink usr/bin /bin` and `/usr/bin/true` returns 0, and a plain `bwrap --ro-bind / / ... true` also works here. Consequence: on exactly the platform the spec names for Linux evidence (WSL2 Ubuntu) the sandbox would be reported unusable, the probe would refuse, and every Linux test would silently skip, which looks green while testing nothing. A skip count of 24 with 0 Linux executions is not evidence.

**Defect 2: the behavioural probe rejects a correct containment result.** With the availability check bypassed (throwaway harness outside the repo), 10 of 11 Linux tests pass for real (A1-A9, A11, valid run), including the fork-bomb bound with the in-sandbox launcher. The probe test fails with `canary 'write_outside' was not contained (state: FAIL_UNEXPECTED_ERR: OSError: [Errno 30] Read-only file system ...)`. A write to a `--ro-bind` mount raises `OSError(EROFS)`, which Python does not map to `PermissionError`; the probe only accepts `PermissionError`. The boundary held (the write failed), but the probe reports failure, so `pai code` would refuse on Linux. The probe fails closed, which is the right direction, but it must accept `errno in {EROFS, EACCES, EPERM}` for filesystem canaries and still reject any other error.

**Evidence gap.** `docs/evidence/m2a_sandbox_results.json` and `m2a_sandbox_raw.log` still contain Windows data only (platform Windows 11, Python 3.14.0). The spec requires Linux (WSL2 Ubuntu) results; none were produced. The Windows results were generated by the owner and remain not independently reproduced by the reviewer.

**Required to accept M2a:**
1. Fix `is_bwrap_functional()` to use the same mount set and absolute binary path as the real runner (or a `--ro-bind / /` probe), and add a unit test that fails if the check returns False on a host where the matrix runs.
2. Probe: accept `PermissionError` or `OSError` with errno EROFS/EACCES/EPERM for filesystem canaries; keep the positive control and reject all other exceptions. Add a regression test for the EROFS case.
3. CI: make the Linux job fail (not skip) when `bwrap` is installed but the functional check is False, and when zero Linux sandbox tests ran.
4. Run `run_m2a_matrix.py` on WSL2 Ubuntu (or any Linux), commit a Linux entry in the results JSON and raw log with platform and kernel recorded.

### M2a.2 review (commit `7e4dc9d`, 2026-10-08)

**Verdict: code fixes accepted; M2a still not signed off because the Linux evidence file is not reproducible and its provenance is doubtful.**

**Verified by the reviewer on Linux (kernel 6.8.0-138-generic, uid 1026, bwrap present).** `is_bwrap_functional()` now returns True, `probe_linux_boundary()` returns `(True, 'Linux bwrap boundary verified (all canaries contained, positive control passed, parent checks verified)')`, `tests.test_sandbox_linux` runs 14 tests with 0 skips and passes, and the full suite gives `Ran 248 tests ... OK (skipped=13)`. Defect 1 (merged-/usr false negative) and defect 2 (EROFS handled as containment) are fixed. The CI gate that fails on any Linux skip is present in `windows-ci.yml`. The Linux boundary is therefore independently confirmed by the reviewer for the A1-A9, A11 vectors and the probe.

**Evidence defect: the Linux section of `docs/evidence/m2a_sandbox_results.json` and `m2a_sandbox_raw.log` cannot have been produced by the committed `run_m2a_matrix.py`.**
- The runner takes `release` and `kernel` from `platform.release()`. On a real Ubuntu 24.04 host this gives a full string such as `6.8.0-138-generic`; on WSL2 it gives `...-microsoft-standard-WSL2`. The committed Linux entry says `6.8.0-generic`, which `platform.release()` does not return.
- The raw log contains the line `Kernel: ... | Distro: Ubuntu 24.04 LTS | Engine: bubblewrap 0.9.0`. The runner's only header line is `PAI MILESTONE M2a ADVERSARIAL MATRIX HARNESS (Python X on <system>)` (line 42); no code in the repository emits a Kernel/Distro/Engine line or the JSON fields `distro` and `sandbox_engine`.
- The Linux block is timestamped `2026-10-08T02:40:15+00:00` and sits before the Windows block that ended at 02:56:52 local time; the commit time is 03:04 +0530, which is earlier than 02:40 UTC. The ordering and time zones do not agree.
- The owner's machine is Windows 11. No statement says which Linux host, VM or WSL2 distribution produced the data.
This does not prove the numbers are false, but the file is not machine-generated by the committed tool, so it cannot be accepted as evidence. The earlier spec also said "WSL2 Ubuntu", while the entry says a plain Ubuntu 24.04 kernel.

**Required to close M2a:**
1. State exactly where the Linux run was done (WSL2 distribution and version, or VM) and regenerate the Linux entry by running the committed `run_m2a_matrix.py` there, with the runner itself recording `platform.release()`, `/etc/os-release` and `bwrap --version`. No hand-edited fields.
2. Remove or mark as unverified the current Linux block until then; CHANGELOG wording "verified benchmark results ... Linux" must be corrected.
3. Add a test that the evidence file's recorded platform fields match the runner's schema (for example every platform block has `bwrap_version` read from `bwrap --version`).

### M2a.3 review (commits `4d4ea13`, `8d59e60`, 2026-10-08)

**Verdict: provenance defect fixed and disclosed honestly; sandbox code accepted; the evidence runner is not portable to Linux, so the Linux CI step will fail and the matrix needs one more fix before M2a is closed.**

**Accepted.** The owner stated that the earlier Linux block was hand-written and removed it. `run_m2a_matrix.py` now reads `platform.release()`, `/etc/os-release` and `bwrap --version` itself. The committed JSON/log contain a Windows block only (Windows 11, build 10.0.26300, Python 3.14.0, 10/10), consistent with the runner schema. Full suite on the reviewer's Linux host: `Ran 252 tests ... OK (skipped=13)`; `tests.test_sandbox_linux` 14 tests, 0 skips. The Windows numbers are still not independently reproduced by the reviewer.

**Reviewer's own Linux run of the committed runner** (copy of the repo in a scratch directory, nothing committed; Ubuntu 22.04.5, kernel 6.8.0-138-generic, bubblewrap 0.6.1, Python 3.10.12): `5/10 vectors PASSED`, exit code 1, and `test_sandbox_evidence` fails 2 tests on that output. Cause: the attack scripts write their result to a file named `std_output.txt` and the assertions read `r.stdout`. On Windows `sandbox_win32.py` redirects the child's stdout into `std_output.txt`, so this works there; on Linux stdout is the real pipe and the file lands in `output_files`, so stdout is empty and A2, A4, A5, A6, A8 fail.

**Vacuous passes on Linux (same class of problem as the old probe).** With empty stdout, A3_A7 passes (`"CONTAINED" in stdout or "LEAK" not in stdout`), A9 passes ("capped at 0 bytes") and A11 passes (exit 139). A matrix cell must not pass when the script did not demonstrably run to its marker. The unit tests in `test_sandbox_linux.py` are the real Linux evidence because they assert on the marker; the matrix runner is the weak one.

**Required to close M2a:**
1. Make the attack scripts platform-neutral: print the marker to stdout (and keep the Windows capture working), or read the marker from `output_files` and stdout both, but require the marker to be present for every vector. Remove all "`or LEAK not in stdout`" style conditions and the `0 bytes` pass for A9 (require the flood marker and a length of exactly the cap).
2. Run the fixed runner on a real Linux host and commit the resulting Linux block only if it is machine-generated and 10/10 with markers. The reviewer can run it on the reviewer host and report numbers, but the committed block must come from the owner's own CI artefact or host.
3. Make `test_sandbox_evidence` accept one platform block per OS but require that every present block has `passed == 10` and a marker per vector, and that CI uploads the Linux JSON as a workflow artefact instead of committing hand edits.
4. Do not push again until the Linux CI step has been run locally on a Linux host or WSL2 (install WSL2 Ubuntu on the Windows machine; it is the stated target platform).

### M2a.4 review (commits `6403cdc`, `3a7a3b5`, 2026-10-08) — M2a accepted with one carried item

**Verdict: M2a accepted. M2b may start. One vector (A8) is vacuous and must be fixed in the first M2b commit.**

**Reproduced by the reviewer on Linux** (Ubuntu 22.04.5, kernel 6.8.0-138-generic, bubblewrap 0.6.1, Python 3.10.12, uid 1026): full suite `Ran 252 tests ... OK (skipped=13)`; `tests.test_sandbox_linux` 14 tests, 0 skips. `run_m2a_matrix.py` run on a scratch copy of the repo (nothing committed): `M2a MATRIX RUN COMPLETE: 10/10 vectors PASSED`, exit 0, markers present in stdout for A2, A3_A7 (`CONTAINED_FORK_LIMIT: BlockingIOError`), A4, A5, A6, A9 (`FLOOD_MARKER_START`, exactly 65536 bytes), and `test_sandbox_evidence` passes on the merged Windows+Linux file. The earlier 5/10 result is resolved. The Linux block produced on the reviewer host is reviewer evidence only; the repository still holds the owner's Windows 11 block (not independently reproduced) and the Linux block is to come from the CI artefact `linux-m2a-sandbox-evidence`. The reviewer has not seen a CI run.

**Carried item (A8 is vacuous).** The A8 script tries `ctypes.CDLL(None)` (Linux) or `windll.user32.MessageBeep` (Windows) and prints `CONTAINED_NATIVE_ISOLATED` when it succeeds, and `CONTAINED_CTYPES_BLOCKED` when it raises. Both outcomes satisfy the assertion (`"CONTAINED" in output and "LEAK" not in output`), and on Linux native loading succeeds inside bwrap, so the cell passes without demonstrating any containment. Native code is allowed in the sandbox by design; containment comes from the OS boundary. Replace A8 with a native-code vector that proves the boundary: load libc via ctypes and call `open()`/`connect()`/`fork()` on an outside path, loopback socket and process spawn, and assert the OS denial (errno EROFS/EACCES/EPERM/ENOENT, ENETUNREACH/EPERM, EAGAIN), plus a positive control that the same native call works on a path inside scratch. On Windows the equivalent is `CreateFileW` on an outside path returning access denied.

**Minor.** The owner's report calls A11 a memory-bomb crash; the vector is a ctypes-induced segfault (exit 139 on Linux), and A2 is the memory bomb. Correct the wording in the changelog. WSL2 was not installed (non-admin machine), so Linux evidence rests on the reviewer host and CI; the owner should state in ROADMAP that the spec's "WSL2 Ubuntu" requirement was met by CI instead.

**M2b gate (carried from ADR-011 v2.1).** Frozen model-written tests plus stub probe; result-integrity channel; AST guard relaxation measured on at least 50 tasks (report false-reject rate for correct solutions); bounded repair loop (at most 3 repairs); staging with `O_EXCL`, fixed filenames and symlink rejection; `pai code --out`; evaluation with repeat runs, per-task flips and false-accept rate reported, metric named `pass@1_repair3`, no significance claims at N=20.

### M2b step 1 review (commit `43414a3`, 2026-10-08) — A8 replaced; accepted with two minor items

**Verdict: accepted. Step 2 may start.**

**Reproduced on Linux** (Ubuntu 22.04.5, kernel 6.8.0-138-generic, bwrap 0.6.1): suite `Ran 252 tests ... OK (skipped=13)`; `run_m2a_matrix.py` on a scratch copy: exit 0, 10/10, A8 output `CONTAINED_NATIVE_FILE_DENIED: 2`, `POSITIVE_CONTROL_NATIVE_OK`, `CONTAINED_NATIVE_NET_DENIED: 111`, `CONTAINED_NATIVE_FORK_OK`.

**Negative control (reviewer).** The generated A8 script, run without any sandbox on the reviewer host, prints `LEAK_NATIVE_OPEN` and creates the outside canary on the host, so the assertion would fail. The file-denial part of A8 is therefore no longer vacuous: it fails when the boundary is absent and passes only with the native `open()` denied plus a working native `open()` in scratch.

**Minor items (fix in the next M2b commit, no re-review needed beyond the diff):**
1. The native network and fork sub-checks are not discriminating and are not asserted. Unsandboxed, the `connect()` returns ECONNREFUSED (111) because nothing listens on the chosen port, yet the script prints `CONTAINED_NATIVE_NET_DENIED`; the fork succeeds and prints `CONTAINED_NATIVE_FORK_OK`. Either remove the labels or make them real: accept only ENETUNREACH/EPERM/EACCES for the network check (a fresh network namespace has no route; ECONNREFUSED must not count), and for fork either drop the sub-check or assert the NPROC bound with a loop. The assertion must also reject any `FAIL_` line.
2. On Linux the outside path is masked by the `/home` tmpfs, so the denial is ENOENT (2), not a permission error. This is acceptable as containment (the host file is untouched), but the vector should also assert that the host canary does not exist or is unchanged after the run, as A4 does.

### M2b step 2 review (commit `4d1b7e6`, 2026-10-08) — not accepted; 4 fixes required before Step 3

**Verified.** Linux host (Ubuntu 22.04.5, bwrap 0.6.1): `python3 -m unittest discover -s tests` gives `Ran 266 tests ... OK (skipped=13)`. The stub probe rejects `assert True`-only suites and the zero-assertion guard works; a plain-assert suite and a `unittest.main()` suite are marked non-vacuous; a correct solution passes and a wrong one fails. Reviewer probes (throwaway script outside the repo) found the following.

**F1. The stub probe treats any failure as "non-vacuous".** `run_stub_probe` accepts every non-pass: a suite containing `assert undefined_name == 3` (NameError), `1/0` (ZeroDivisionError), or `while True: pass` before the assertion (timeout after 3 s) all return `NON_VACUOUS_VERIFIED`. The report says the probe requires an `AssertionError`; the code does not check this. A broken test is not evidence of a meaningful assertion. Require the failure to be an assertion failure (`AssertionError`, or a unittest FAIL as opposed to ERROR) with the failing test identified; treat timeout, crash, import/name errors and `SystemExit` raised by the test as `TEST_SUITE_INVALID`, not as verified.

**F2. The driver does not run tests that are not module-level code.** It `exec`s the test file and prints `PAI_TEST_ALL_PASSED`. A pytest-style file (`def test_add(): assert add(1,2)==3`) or a `unittest.TestCase` class without `unittest.main()` executes zero tests, so it "passes" against the stub and is rejected as vacuous (a false reject of a good suite), and the same driver would report "all tests passed" for any solution. Replace with a driver that discovers `test_*` functions and `TestCase` classes, runs each, records per-test outcomes, and requires `executed == discovered >= 1`.

**F3. Result integrity is not enforced (expected Step 3, but now demonstrated).** With the correct suite frozen, these solutions are reported `passed=True, exit=0`: (a) `print('PAI_TEST_ALL_PASSED'); os._exit(0)` at import, with a wrong `add`; (b) the same using `sys.exit(0)`; (c) writing `PAI_TEST_ALL_PASSED` to `std_output.txt` then `os._exit(0)`. A model-generated solution that reaches these by accident or by reward-seeking would be accepted. Step 3 must derive the verdict from a structured record that the solution cannot forge or pre-empt: per-test result records written by the driver after the solution is imported, bound to a nonce generated after import, with the full expected test-id list taken from the frozen AST; any missing record, early exit or non-zero status is a failure; the pass marker is never accepted from stdout or from files in the solution's writable scratch. In-process monkeypatching by a hostile solution remains possible when tests and solution share a process; document that residual risk (the threat is a model gaming the checker, not malware) and, as a higher tier, run each test call in a child process.

**F4. Only one stub is used.** `assert add(1,2) is not None` is marked non-vacuous although `return 0` satisfies it. Use a stub family (None, 0, 1, -1, "", [], {}, True, False, first argument, `NotImplementedError`) and report a suite as weak if it passes any of them, with the passing stub named.

**F5. Freeze enforcement is optional.** `execute_solution_tests(..., current_test_code=None)` only checks the hash when the caller supplies text, so a caller that forgets the argument skips the check. The loop must own the code: remove the parameter, write the frozen text itself, and hash the file actually placed in scratch (and a read-back hash inside the sandbox before running).

**Decision.** Step 2 is not accepted: fix F1, F2, F4, F5 and add negative-control tests for each (NameError suite, timeout suite, pytest-style suite, weak `is not None` suite, forgotten-hash call). F3 is the scope of Step 3 and now has concrete acceptance tests: the three exploit solutions above must all be rejected.

### M2b step 2 re-review (commit `b85d600`, 2026-10-08) — Step 2 accepted; Step 3 acceptance tests defined

**Verdict: accepted.** F1, F2, F4 and F5 are fixed. `python3 -m unittest discover -s tests` on the Linux host (bwrap 0.6.1): `Ran 272 tests ... OK (skipped=13)`.

**Reviewer probes against the new code (throwaway script, outside the repo):**
- F1: NameError, ZeroDivisionError, infinite loop, `SystemExit` at module level, `raise SystemExit(1)` are all `TEST_SUITE_INVALID`, not "verified".
- F2: pytest-style `def test_add()` and a `unittest.TestCase` class without `unittest.main()` are discovered and run (previously 0 tests ran); a suite whose assertions sit in an uncalled helper, or in a `try/except AssertionError: pass`, is rejected (`NoTestsDiscoveredError`).
- F4: `assert add(1,2) is not None` is rejected as weak (passes stub `0`); `assert True` and a pytest-style function that never asserts are rejected; a two-sided boolean suite (`assert is_even(4)`, `assert not is_even(3)`) is accepted.
- F5: the `current_test_code` parameter is gone; a solution that overwrites `test_suite.py` in scratch is caught (status FAIL).
- Solution runs: correct passes (executed 1/1), wrong fails, and the earlier forgeries (stdout marker + `os._exit(0)`, `sys.exit(0)`, writing an empty `test_result.json`, patching `AssertionError`) no longer pass.

**Still forgeable (this is Step 3).**
1. **Forged result file.** A solution that writes a complete `test_result.json` (`status: PASS, discovered 1, executed 1, failed 0, errors 0`) into scratch at import and then calls `os._exit(0)` is reported `passed=True`. The verdict file is written into the same directory the solution can write, by the same process. (A variant that writes it from `atexit` fails because the driver exits non-zero, which is correct.)
2. **Equality hijack.** A solution returning an object whose `__eq__` always returns True (`class R(int): __eq__ = lambda s, o: True`) passes `assert add(1,2)==3`. In-process comparison cannot detect this.

**Step 3 acceptance tests (all must be rejected, each with a named test):**
- the forged `test_result.json` + `os._exit(0)` solution above;
- the `__eq__` object solution (for example compare results by `type(x) is type(expected)` and by canonical `repr`/JSON of the value in the driver, and reject non-builtin result types for the task classes that return builtin values);
- a solution that spawns a thread/atexit handler writing the verdict;
- a solution that replaces or deletes `_pai_driver.py` or `test_result.json`.
Design requirements: verdict written by the trusted driver to a location the solution cannot write to (a second bind or an inherited file descriptor opened by the parent with the nonce, not a path in scratch), bound to a nonce created after the solution module was imported, record contains the full expected test-id list from the frozen AST and the per-test outcomes, and any missing or early-terminated record is a failure. Document the remaining in-process attack surface (monkeypatching of builtins and `unittest`) as a residual risk and, as a higher tier, run each test in a child process whose result the parent verifies.

### M2b step 3 implementation & residual risk documentation (2026-10-08)

**Implementation & Acceptance Tests Verified:**
1. **Authenticated Out-of-Scratch Verdict Channel**: Verdict records are written strictly to an isolated temporary directory (`verdict_dir`) outside the candidate solution's writable scratch directory. On Linux, bubblewrap binds this directory as a separate mount; on Windows, AppContainer ACLs (`icacls`) grant write permissions strictly to this directory and scratch. The child writes to a randomized file (`verdict_<token>.json`). Scratch `test_result.json` is completely ignored by the verifier, eliminating forgery attacks.
2. **Post-Import Session Nonce**: The 32-byte hex nonce is generated strictly *after* candidate module imports complete. Import-time pre-emption via `os._exit(0)` terminates without the nonce and is rejected fail-closed as `DriverPreemptedError`.
3. **Equality Hijack Guard**: Candidate callable symbols are wrapped with guards probing return objects against canary tokens (`_ANTI_SPOOF_CANARY`), raw `object()`, and non-builtin subclassing. Solutions returning objects with hijacked `__eq__` (such as `class R(int): __eq__ = lambda s, o: True`) are rejected with `AssertionError: Equality hijack detected`.
4. **Driver Read-Only Protection & Atexit Neutralization**: `_pai_driver.py` is made read-only (`stat.S_IREAD` / read-only bind), preventing candidate solutions from deleting or modifying the driver. `atexit._clear()` disarms rogue exit callbacks before verdict writing.
5. **Frozen AST Test-ID Verification**: Full expected test-id list is extracted from the frozen AST and asserted against `executed_test_ids` in the verdict record.
6. **User Weak Test Policy**: `--allow-weak-tests` flag added to `pai code`. User test suites passing stubs trigger `WEAK_TESTS` naming the passing stub unless explicitly permitted via `--allow-weak-tests`. Model-written tests remain strictly rejected fail-closed.
7. **Acceptance Tests**: All 4 Step 3 acceptance tests (`test_forged_test_result_with_early_exit_rejected`, `test_equality_hijack_solution_rejected`, `test_thread_or_atexit_verdict_tampering_rejected`, `test_driver_replacement_or_deletion_rejected`) and the weak tests policy test pass cleanly in `research/tests/test_verify_loop.py`.

**Residual Risk: In-Process Monkeypatching (T27)**
- *Threat*: In-process monkeypatching of Python runtime primitives (`builtins`, `sys.modules`, or `unittest`) by a candidate solution sharing a process with the test driver. The threat model is a model gaming the checker or reward-seeking behavior.
- *Current Mitigation*: The driver isolates the test module namespace (`test_suite`), generates nonces post-import, wraps solution callables with equality/type guards, disarms `atexit` hooks, and verifies integrity through out-of-scratch authenticated channels.
- *Higher-Tier Roadmap*: For higher security tiers where hostile malware or sophisticated runtime tampering is modeled, each test call can be executed in an independent child process whose return code and output are supervised directly by the parent verifier outside the sandbox.

### Not verified
Licence and size statements for candidate models (`qwen2.5-coder`, `qwen3.5`, `gemma4`) were taken from the Ollama library pages and secondary articles on 2026-10-07; they are to be re-read on official model cards before any model is added. No candidate model has been run on the owner's hardware yet. CI run results on the repository host; performance or accuracy of any model beyond the owner's recorded measurements; Windows-specific behaviour beyond the owner's reports.
