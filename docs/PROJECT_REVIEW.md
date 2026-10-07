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
* Rust tests (13), clippy and fuzz results were reported by the owner and were not re-run in this review.

### Not verified
Licence and size statements for candidate models (`qwen2.5-coder`, `qwen3.5`, `gemma4`) were taken from the Ollama library pages and secondary articles on 2026-10-07; they are to be re-read on official model cards before any model is added. No candidate model has been run on the owner's hardware yet. CI run results on the repository host; performance or accuracy of any model beyond the owner's recorded measurements; Windows-specific behaviour beyond the owner's reports.
