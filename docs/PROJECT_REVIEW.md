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

### Not verified
Licence and size statements for candidate models (`qwen2.5-coder`, `qwen3.5`, `gemma4`) were taken from the Ollama library pages and secondary articles on 2026-10-07; they are to be re-read on official model cards before any model is added. No candidate model has been run on the owner's hardware yet. CI run results on the repository host; performance or accuracy of any model beyond the owner's recorded measurements; Windows-specific behaviour beyond the owner's reports.
