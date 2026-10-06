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
* Output is written only where the user says (`--out`); existing files are never overwritten (new names, diff shown).
* Model server: requests set `keep_alive: 0` for sensitive runs so the prompt is not left resident in the model process (threat T13). To be verified in M1 by observing `ollama ps`; residual risk stays documented until in-process inference exists.

## 3. Models (L2 "code brain")
* Served by Ollama (or another OpenAI-compatible local server) on loopback; reached through `LocalLLMReasoner`.
* Candidates: a small open-weights coder model plus the general model already measured (`llama3.2:3b`). **Check each model's licence before use.**
* Each model has a model card in `research/model_profiles.json`: name, source, licence, SHA-256 of the blob, `host_delta_mb` (max of ≥ 5 cold runs), measured date and machine.
* Fit rule (already implemented for the current models): `available_ram_mb >= host_delta_mb + 512`, evaluated **before** loading only (hysteresis).

## 4. Milestones and acceptance criteria

### M1 — `pai code` (generate only)
* Task → code via the coder model, nothing executed.
* **Baseline:** the owner writes 20 small tasks with hidden unit tests; record pass@1 for each model and for the stub. This frozen set is the yardstick for all later claims.
* Model card + `host_delta_mb` for the new model.
* Tests: prompt fencing, token caps, RAM-fit refusal, malformed model output.

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

## 5. Evaluation discipline
* Frozen, versioned evaluation sets (coding tasks, safety/injection cases, Singlish intents, forecast series). Training and tuning data never overlap them.
* Every claim in docs or UI about quality cites a measured number from these sets (claims policy, THREAT_MODEL §5).
* Record machine, model, quantization and date with each result.

## 6. Security requirements (cross-cutting)
Deny-by-default capabilities (ADR-006); untrusted data fenced; outbound traffic only through `outbound_policy` with the allow-list (arbitrary domains need an explicit `--allow-domain`); loopback-only model endpoint; every new input channel gets a threat-register entry (T15–T20) and tests before merge.

## 7. Dependencies
Standard library first. Any added package (for example a PDF parser or a statistics library) needs: pinned version and hash, licence check, an ADR line, and a note in THREAT_MODEL T10.

## 8. Hardware awareness
Tier and RAM-fit decisions come from telemetry. Heavy steps (large analysis, training) are deferred or reduced under pressure instead of failing the machine.

## 9. Own-model track (L3, gated)
Stage 0: bilingual (Sinhala + English) tokenizer and a 10–25M-parameter model to learn the pipeline (laptop). Stage 1: fine-tune a small pretrained open base with LoRA on verified self-play trajectories (hardware-aware scheduler). Later stages only if the promotion gate in ADR-008 is passed. No automatic weight updates before the gate, rollback and signed-release path exist.
