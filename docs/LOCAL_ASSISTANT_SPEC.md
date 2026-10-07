# Local Assistant (`pai`) — Specification (ADR-008)

_Status: planned, nothing in this document is implemented yet. Written 2026-10-07._

## 1. Purpose and scope
A simple, local, **stateless** assistant that can analyze code projects, documents, web pages and business datasets (with forecasts) and write and test code. It runs on the owner's own machine, talks to a local model server over loopback only, and keeps no conversation history.

Commands (CLI first, local web page later):

| Command | What it does |
|---------|--------------|
| `pai code "<task>" --out <dir>` | Plan, write code, run tests in a restricted runner, repair (bounded), write results to `--out` |
| `pai analyze <folder>` | Read-only analysis of a code project: structure, languages, risks, explanation |
| `pai docs <file> [--ask "<question>"]` | Summary and question answering over txt/md/csv (PDF later) |
| `pai forecast <data.csv> [--horizon N]` | Data checks, backtested forecast with uncertainty range, plain-language explanation |
| `pai web` (M6) | Local web interface on `127.0.0.1` wrapping the same core |

Out of scope for this spec: voice, desktop control (Phase 5), automatic weight updates (see §9).

## 2. Statelessness rules
* No history file, no cache of prompts or file contents. Each run: ingest → reason → output → verified purge (`SecureBuffer`).
* Cloud runs (§10) are not stateless: the provider receives the data, and the output says so.
* Output is written only where the user says (`--out`); existing files are never overwritten (new names, diff shown).
* Model server: requests set `keep_alive: 0` for sensitive runs so the prompt is not left resident in the model process (threat T13). To be verified in M1 by observing `ollama ps`; residual risk stays documented until in-process inference exists.

## 3. Models and the adaptive router (L2)

### 3.1 Candidates (none adopted yet — every row needs measurement on the owner's laptop)
| Model (Ollama tag) | Download | Context | Licence as reported by secondary sources | Notes / risks |
|--------------------|----------|---------|------------------------------------------|----------------|
| `llama3.2:1b`, `llama3.2:3b` | 1.5 / 2.6 GB | 128K | Llama community licence (custom) | **Measured** (RAM Δ ≈ 705 / 761 MB, ~3 s). Wrong facts and code observed. Check the licence before training on its outputs |
| `qwen2.5-coder:1.5b` | ≈ 1 GB | 32K | Apache 2.0 | Cheap low-RAM fallback; code-specific |
| `qwen2.5-coder:7b` | 4.7 GB | 32K | Apache 2.0 | Best coding candidate; may not fit the iGPU entirely (CPU spill). The 3B size has conflicting licence reports — avoid or confirm |
| `qwen3.5:4b` (`2b` later; `9b` too heavy) | 3.3–4.0 GB | 256K | Apache 2.0 | General/analysis/agent-style; thinking mode; multimodal weights add size |
| `gemma4:e2b` (`e4b` only if e2b fits) | 4.3–4.6 GB+ | 128K | Apache 2.0 (Google blog) | Multimodal, thinking mode; reported sizes vary by variant |

Excluded for this hardware or licence reasons: `gpt-oss:20b` (≈ 14 GB), Devstral 24B, `qwen3-coder` 30B, `gemma4` 26B/31B; Llama-family, DeepSeek-Coder-V2, CodeGemma and Codestral for custom/restrictive licences (re-check if needed); DeepSeek-R1 distills (long reasoning output is slow here; the Llama-based 8B inherits the Llama licence).

Licence statements above come from secondary articles. **Before a model is added, its official model card is read, the licence id and date recorded, and the weights' SHA-256 stored (T20).** Vendor benchmark numbers are not used for decisions; the frozen local evaluation is.

Known gotchas to test explicitly: (1) *thinking* tokens can exhaust the tier token cap and produce a truncated, answer-less response — evaluate with thinking off and on; (2) multimodal weights increase size and RAM without benefit; (3) a model that spills from the iGPU to the CPU changes latency and RAM drastically — read `ollama ps`; (4) Sinhala/Singlish quality is unknown for every candidate.

### 3.2 Model card (in `research/model_profiles.json`)
`name`, `source_url`, `licence_id`, `licence_checked_on`, `sha256`, `download_gb`, `context_limit`, `offload` (`gpu` | `mixed` | `cpu`), `host_delta_mb` (max of ≥ 5 cold runs), `latency_cold_s`, `latency_warm_s`, `thinking` (`n/a` | `off_capable` | `always`), `compressed_ok` (safe in the COMPRESSED tier), `evals` (per task class: `code_pass1`, `docs_rubric`, `singlish_score`, `forecast_narration`; absent = unmeasured), `measured_on` (machine, date).

### 3.3 Adaptive model router (design)
Purpose: pick, **per task**, the model that fits the machine's current condition and is best for the task class, and explain why.

**Inputs:** task class (set by the command, not guessed by a model: `code_generate`, `code_repair`, `analyze_code`, `docs_qa`, `forecast_narrate`, `general`), hardware budget (tier, `avail_ram_mb`, AC/battery, CPU load), model cards, user overrides (`--model`, `--offline`, `--prefer-fast`).

**Algorithm (pure, deterministic function):**
1. *Eligibility:* model is on the owner's allow-list, card is complete (licence checked, hash verified), endpoint reachable.
2. *Fit:* already-loaded models pass (hysteresis); otherwise `avail_ram_mb >= host_delta_mb + 512`. In the COMPRESSED tier only `compressed_ok` models are eligible. On battery below the low-battery threshold, or with the CPU saturated, models with `offload != gpu` are excluded.
3. *Score by task class:* rank eligible models by their measured `evals[task_class]`. A model with no measurement for the class is eligible only as a last resort and is labelled "unmeasured". No guessing from model size or reputation.
4. *Tie-breaks:* lower `latency_warm_s`, then lower `host_delta_mb`.
5. *Hysteresis:* keep the currently loaded model unless the best candidate beats it by a configured margin; a swap costs a cold load and RAM churn. One model resident at a time; unload the old one before loading the next.
6. *Thinking policy:* off by default; on only for tasks marked hard, in the HIGH tier, for models that support it, with the token cap raised accordingly.
7. *Fallback chain:* on error, timeout or `finish_reason == "length"` without an answer, try the next eligible model (at most 2 switches); if none remain, return the stub answer labelled as having no model. Never silently use a different model: the output states the model used and the reason codes.
8. *Re-evaluation:* between tasks only, never in the middle of a generation.

**Output:** `RouteDecision { model, thinking, reason_codes[], rejected[(model, reason)], budget_snapshot }`, printable with `--explain-route`, kept only in memory (stateless).

**Security rules:** model names come only from the owner's allow-list; text from files, web pages or the model itself can never name or select a model (T21); the task class is derived from the command, not from the content.

**Required tests / properties:** never selects a model that fails the fit rule or lacks a verified card; lowering available RAM never selects a model with a larger `host_delta_mb`; small RAM fluctuations do not cause swaps (hysteresis); identical inputs give identical decisions; golden decision vectors (so a Rust port can match); hostile content naming a model does not change the choice.

**Adoption test:** the router is kept only if, on the frozen evaluation sets under several simulated RAM budgets, it succeeds on more tasks than the best single model within the same budget. Otherwise the best single model is used and the router is shelved.

### 3.4 Fit rule (implemented for the measured models)
`available_ram_mb >= host_delta_mb + 512`, evaluated before loading only.

## 4. Milestones and acceptance criteria

### M1 — Model bake-off and `pai code` (generate only)
* Pull and test, in this order: `qwen2.5-coder:7b`, `qwen3.5:4b`, then `gemma4:e2b`, with `qwen2.5-coder:1.5b` as the fallback and `llama3.2:3b` as the reference. Check free disk first (≈ 14 GB for all) and remove losers with `ollama rm`.
* For each model record: licence check (official card) and SHA-256; `ollama ps` processor split; `host_delta_mb` (max of ≥ 5 cold runs); cold and warm latency; tokens per second; whether thinking can be switched off; whether output gets truncated at the tier token caps.
* **Frozen evaluation sets (owner-written, versioned):** 20 small coding tasks with hidden unit tests (pass@1); 10 Singlish/Sinhala prompts scored 0–2 by hand; 10 document/analysis questions scored with a short rubric. Model outputs never edit these sets.
* `pai code` generates code with the chosen model; nothing is executed yet.
* Tests: prompt fencing, token caps, RAM-fit refusal, malformed model output, truncation labelling.

### M1b — Adaptive router
Implements §3.3 with its properties and golden decision vectors. Acceptance: the adoption test above; `--explain-route` output; hostile-content test passes.

### M2 — Verify loop
Flow: plan → generate → Tier-1 AST guard → run tests in a restricted runner → on failure feed the error back (max 3 repairs) → write result.
Restricted runner requirements: fresh temp directory; no network (sandboxed process or firewall rule; if not provable, fall back to Windows Sandbox, ADR-003); wall-clock timeout; memory and process limits; scrubbed environment; confirmation prompt before the first run of each task.
Tests (must exist before merging): infinite loop is killed; attempt to delete files outside the temp dir fails; network call fails; fork bomb is bounded; oversized output is truncated.
Residual: AST filtering is not a security boundary (RSI spec §5.1); the runner is.

### M3 — `pai analyze <folder>`
* **Path safety:** allow-listed root folders; resolve real paths and require them to stay inside a root (blocks `..` and symlink escape); extension allow-list; per-file and total size caps tied to the hardware tier; binary files skipped; secrets skipped (`.env`, `*.key`, `*.pem`, `id_rsa*`, token-like patterns) and never sent to the model.
* **Pre-pass without a model:** file tree, language counts, line counts, Python AST (functions, classes, imports), TODO/FIXME list. The model receives this structured summary, not raw dumps.
* **Large projects:** map-reduce (per-file summaries, then a combined analysis), each step inside `max_context_bytes`.
* **Untrusted content:** file text is fenced as untrusted data; analysis output cannot trigger tools (no tools are exposed).
* Tests: file containing "ignore previous instructions", symlink pointing outside the root, 1 GB file, binary file, file with a fake `[[SRC:...]]` marker, Unicode paths.

### M4 — `pai docs`
txt, md, csv first (standard library). PDF later and only after an ADR, because parsing untrusted PDFs enlarges the attack surface.

### M5 — `pai forecast`
* **Input checks:** date column and numeric column(s) detected; missing values, duplicates, outliers and frequency (daily/weekly/monthly) reported before any forecast.
* **Methods ladder** (pure Python, no extra packages at first): naive, seasonal naive, moving average, linear trend, Holt-Winters (additive). The method is chosen by **rolling-origin backtest** (sMAPE and MASE reported).
* **Output:** forecast values, prediction interval derived from backtest residuals, backtest error, method name, data-quality warnings.
* **Refusal rules:** too little data (fewer than two full seasons for seasonal methods, or fewer than a stated minimum of points) → no forecast, with the reason.
* **Language model role:** narrate the computed numbers only; it never invents figures or drivers. Output carries the wording that forecasts are estimates and that unforeseen events are not modelled.
* Tests: known synthetic series (trend, seasonality) recover expected values within tolerance; constant series; series with gaps; single-row file; non-numeric column; adversarial CSV (huge row, formula-like cells, embedded newlines).

### M6 — Local web interface
Binds to `127.0.0.1` only on a random port; per-session token; `Host` and `Origin` checks; no CORS; no server-side history; same core as the CLI (no separate logic); file picker limited to allow-listed roots. Uses the standard library server unless a dependency is justified by an ADR.
Tests: request with a foreign `Origin` rejected; request without token rejected; binding to non-loopback refused; path traversal through the picker rejected.

### M7 — Singlish front-end
Normalizer plus a small intent/tool-call router for Singlish commands. Data: text the owner explicitly provides (consent required); evaluation set frozen separately. Starts rule-based; a small trained classifier only if it beats the rules on the frozen set.

## 10. Portability, model selection and optional cloud providers (ADR-010, proposed)
Goal: the same `pai` works on a stronger or weaker PC, the user chooses which models it may use, and the user may add the API of a main AI provider.

| Command | Purpose |
|---------|---------|
| `pai setup` | First run: detect OS, RAM, CPU, GPU/iGPU, battery; recommend models that fit; write the user configuration; download a model only after explicit consent and SHA-256 check |
| `pai doctor` | Report what was detected, what is missing (model server, models), and why a model is or is not eligible |
| `pai calibrate [--model <name>]` | 5-run cold-start measurement on this machine; writes the local machine profile |
| `pai models list|pull|remove` | Manage the local allow-list; unmeasured models are labelled until `pai bench` |
| `pai providers list|enable|disable|test` | Manage cloud providers (all disabled by default); `test` sends a fixed harmless prompt, never user data |
| `pai keys set|clear <provider>` | Hidden-prompt entry into the OS credential store; never echoes the key |

Run flags: `--offline` (no cloud), `--allow-cloud` (consent for this run), `--prefer local|cloud`, `--budget <amount>`, `--explain-route`.

User configuration (non-secret, schema-validated, unknown keys rejected): model allow-list, enabled providers, preferred model per task class, spend caps, privacy mode (`local-only` default). Secrets never live here.

Router additions: machine-profile numbers replace card numbers when present; `uncalibrated` decisions use the conservative rule of ADR-010; cloud candidates follow decision 7 of ADR-010; every route report includes "data leaves machine: yes/no".

Statelessness: local runs are stateless as in §2; cloud runs are not described as stateless (the provider receives the data).

### M1c — Portability, calibration and model selection
Deliverables: `pai setup`, `pai doctor`, `pai calibrate`, `pai models`, user configuration schema, machine profile, Linux CI job.
Acceptance: calibration on a second machine (or a VM with limited RAM) produces a profile and different router decisions than on the owner laptop; synthetic RAM budgets (1.5, 2.5, 4, 8 GB) give the expected model; uncalibrated models use the conservative rule; a tampered profile or configuration is rejected or re-validated (T26); downloads need consent and a matching SHA-256; hostile content cannot change the selection (T21).

### M1d — Optional cloud providers
Deliverables: provider cards, cloud backend behind `Reasoner`, credential-store wrapper, spend counter, consent flow, outbound-log entries.
Acceptance (all against a local mock provider server, no real key in CI): cloud off by default; key never appears in logs, outputs, evidence files or process arguments (grep test); only card hosts are contacted, cross-host redirect refused, TLS verification on; per-run and per-day caps stop a runaway loop; `--offline` removes cloud candidates; content cannot enable cloud or choose a provider; consent text lists files and byte counts; skipped secret files are never sent.

## 5. Evaluation discipline
* Frozen, versioned evaluation sets (coding tasks, document questions, safety/injection cases, Singlish prompts and intents, forecast series). Training and tuning data never overlap them.
* Every claim in docs or UI about quality cites a measured number from these sets (claims policy, THREAT_MODEL §5).
* Record machine, model, quantization and date with each result.

## 6. Security requirements (cross-cutting)
Deny-by-default capabilities (ADR-006); untrusted data fenced; outbound traffic only through `outbound_policy` with the allow-list (arbitrary domains need an explicit `--allow-domain`); loopback-only endpoint for local models (cloud providers only under §10 and ADR-010); every new input channel gets a threat-register entry (T15–T20) and tests before merge.

## 7. Dependencies
Standard library first. Any added package (for example a PDF parser or a statistics library) needs: pinned version and hash, licence check, an ADR line, and a note in THREAT_MODEL T10.

## 8. Hardware awareness
Tier and RAM-fit decisions come from telemetry. Heavy steps (large analysis, training) are deferred or reduced under pressure instead of failing the machine.

## 9. Own-model track (L3, gated)
Stage 0: bilingual (Sinhala + English) tokenizer and a 10–25M-parameter model to learn the pipeline (laptop). Stage 1: fine-tune a small pretrained open base with LoRA on verified self-play trajectories (hardware-aware scheduler). Later stages only if the promotion gate in ADR-008 is passed. No automatic weight updates before the gate, rollback and signed-release path exist.
