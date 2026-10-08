# Agent brief: finish Phase 1 core (target 14 working days from 2026-10-09)

You are the implementation agent. An independent reviewer verifies every milestone on Linux (Ubuntu 22.04, Python 3.10, bubblewrap 0.6.1). Read `docs/DEFINITION_OF_DONE.md` first; it is binding. Quality does not drop to gain speed: a milestone that is late is acceptable, a milestone reported as done that fails on the reviewer host is not.

## 0. Rules that apply to every milestone
1. One report per milestone, in this order: (a) what changed (files, commit), (b) trust-boundary table: for each boundary (user input -> ingest -> model prompt -> model output -> file or execution) state the control, the test that falsifies it, and the negative control, (c) test counts on BOTH Windows and Linux (Linux run must be real; WSL2 or Ubuntu), including skipped counts with reasons, (d) what you did NOT verify.
2. No absolute security wording in code, docs or CLI output (claims lint). No secrets in argv, logs or docs.
3. Model output and file content are untrusted data. Anything read from a file, page or CSV that reaches a prompt goes through the shared ingestion module and the untrusted-data envelope (with marker stripping, as in `sanitize_untrusted_diagnostics`).
4. Every new CLI command: spec exit codes, `--json` output, router decision via `ModelRouter`, task class taken from the CLI command only (T21), fail closed when the router refuses.
5. Every new test needs a negative control (a version of the input that must fail). Tests that only pass on one OS must say so with a skip reason, and the other OS must have an equivalent.
6. Do not edit frozen eval sets after hashing. Hashes live in `docs/evidence/eval_sets_hashes.json`; a changed set gets a new name and a new hash, never an overwrite.
7. Python-only for now. No Rust port, no new native code in this brief.

## 1. Work order and day budget
| Days | Item | Notes |
|---|---|---|
| 1-2 | M2b close-out: eval harness (steps 5/6) | repeats (N>=3), per-task flips, false-accept rate, `pass@1_zero_shot` and `pass@1_repair3`, frozen English coding set (20 tasks) + frozen Singlish copy (same 20 tasks, same tests), hashes recorded |
| 2-3 | Shared safe-ingestion module `research/ingest.py` | built before M3/M4/M5, used by all three |
| 3-6 | M3 `pai analyze <folder>` | code-folder analysis |
| 4-7 | M4 `pai docs <file>` (txt, md, csv only) | PDF is deferred |
| 5-8 | M5 `pai forecast <csv>` | can run in parallel with M3/M4 if the ingestion module is done |
| 7-9 | M2c Singlish bridge | enabled only if it beats direct Singlish (see section 3) |
| 9-10 | M7 Singlish response-quality gate | measurement and release gate, no front-end or normalizer |
| 10-12 | Integration: single `pai` entry point, `pai doctor` end to end | |
| 13-14 | Docs freeze, final reports, hash table | Rust-scope decision is made by the reviewer after this |

If an item overruns by more than 1 day, stop and report the cause; do not cut tests to catch up.

## 2. Shared safe-ingestion module (`research/ingest.py`)
Single entry for every file or folder a command reads. Required behaviour, each with a test and a negative control:
- Path handling: resolve with `os.path.realpath`, reject paths outside the user-given root, reject symlinks that leave the root, reject device files, FIFOs and sockets.
- Limits: max file size, max total bytes per run, max file count, max depth; limits are constants in one place and printed in `--json` output.
- Text handling: detect binary (NUL bytes), decode with explicit error policy, normalise newlines, cap line length, strip control characters except newline and tab.
- Never executes, imports or evaluates anything it reads. Folder analysis reads source as text only.
- Output is a list of `IngestedItem(path, kind, text, truncated, sha256)` plus a rejection list with reason codes. Rejections are reported, never silently dropped.
- Prompt assembly helper: wraps content in the untrusted-data envelope, strips the envelope markers from content, and enforces a token or char budget per model card.
- Secrets hygiene: a configurable deny-list of file names (`.env`, `*.pem`, `id_rsa*`, `*.key`) that are skipped and reported by name only, never read.

## 3. Milestones and acceptance tests
**M3 `pai analyze <folder>`**: reads the folder through `ingest.py`, summarises structure, entry points, dependencies and obvious risks; `--question` for a targeted question. Acceptance: (1) fixture repo with a planted prompt injection in a comment and in a README: output must not follow it (test with mock model that echoes instructions and a check on the prompt actually sent); (2) planted symlink to outside the root and a `.env` file: skipped and reported; (3) oversize folder: truncation reported with counts; (4) router refusal returns exit 5; (5) deterministic mock-model e2e like `test_pai_code_e2e.py`.

**M4 `pai docs <file>`** (txt, md, csv): summarise, answer a question, extract a table. Acceptance: same injection and limits tests as M3; CSV with malformed rows, formula-looking cells (`=CMD(...)`) treated as plain text; large CSV is sampled with the sampling method stated in the output; PDF input returns a clear "unsupported, deferred" exit code, not a crash.

**M5 `pai forecast <csv>`**: numbers come from a deterministic Python method (for example seasonal naive and a simple exponential smoothing), never from the model. The model only explains the result. Acceptance: (1) frozen forecast series (at least 3: trend, seasonal, noisy with a gap) with hashes; expected error bounds written before running; (2) baseline comparison (naive) reported on a holdout split with the metric and window stated; (3) missing values, non-numeric cells, unsorted dates, too-short series: each returns a defined error, never a made-up forecast; (4) output states the method, the holdout error and the limits; no claim of accuracy beyond the holdout.

**M2c Singlish bridge**: a Singlish-strong model (candidates: `gemma4:e2b`, `qwen3.5:4b`) rewrites the Singlish instruction into a structured English spec (goal, inputs, outputs, edge cases, constraints) which is sent to `qwen2.5-coder:7b`. Acceptance: run the frozen Singlish coding set under three arms (direct Singlish, bridge, English baseline), N>=3 repeats, report `pass@1_repair3` per arm, flips, and cost (extra RAM, extra seconds). Enable the bridge by default only if it beats direct Singlish by a margin you state in advance and the result repeats; otherwise ship it disabled and say so. The bridge output is untrusted data for the coder (envelope, no tool access). Both models must pass the router admission rule; if both do not fit in memory at once, run them one after the other and report the load cost.

**M7 Singlish quality gate**: fixed set of Singlish prompts for analyze, docs and forecast explanations plus the coding set; score = keyword rubric AND a check that the answer follows the task (not only the keyword list). Gate: documented threshold per model card; a model below it is marked "Singlish not recommended" by the router explanation, not hidden.

## 4. Integration (days 10-12)
- One `pai` entry point: `pai code`, `pai analyze`, `pai docs`, `pai forecast`, `pai doctor`, `pai models`. No separate scripts for users.
- `pai doctor` runs end to end: OS and sandbox capability probe, model availability, RAM admission for each selected model, ingestion limits, one smoke test per command with the mock server, and prints a pass/fail table. Exit code non-zero on any failed check.
- Full suite on Windows and Linux, claims lint, ctypes allow-list test, Rust workspace tests, all green, counts in the final report.

## 5. Deferred (do not start)
M1d cloud providers, M6, PDF ingestion, M1.3, second-machine calibration, Rust port, Phases 2-5, Track M. Mention nothing about them in user-facing output except in `--help` "not yet available".

## 6. Final report (day 14)
Consolidated table: milestone, commit, Windows test count, Linux test count, frozen-set hashes, headline metrics with repeats and flips, open defects, items not verified. Then freeze docs: `docs/ROADMAP.md`, `docs/PROJECT_REVIEW.md`, `CHANGELOG.md`, and a list of security-critical modules (sandbox, verify loop, ingestion, staging) so the reviewer can decide the Rust scope.
