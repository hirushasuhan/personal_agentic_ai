# Python Research Prototype Specification (v0.3)

## 1. Overview & Objective

The **Python Research Prototype** in `research/` is the testbed and reference implementation for **Personal Agentic AI**. It validates the 3-pillar design (Stateless Core, Hardware Telemetry, Direct Network Pipeline) and the safety ideas (sanitisation, injection screening, purge verification, static code gating) before they are re-implemented in Rust and C++.

**What the prototype is — and is not**
* It *is* a verification lab: every claim in the architecture that can be tested in Python is tested, with automated tests (`research/tests/`).
* It is *not* the production engine. Python cannot guarantee memory zeroization (see §5), and the "Reasoner" is a stub (§2.5). Where Python cannot prove a property, the spec says so and points to the phase that will.

**Runtime**: Python 3.8+ (developed on 3.14), standard library only. `psutil` is an optional fallback.

---

## 2. Module Specifications

### 2.1 `hardware_telemetry.py` — Local Resource Inspector
* **Sources (priority order)**: Windows `kernel32` via `ctypes` (`GlobalMemoryStatusEx`, `GetSystemTimes`, `GetSystemPowerStatus`) → Linux `/proc` + `/sys` → `psutil` → *unavailable*. When nothing can be read the snapshot says `source: "unavailable"` and the budget is clamped to BALANCED. **Numbers are never invented.**
* **Metrics**: total/available RAM, memory load %, CPU cores, CPU load % (delta sampling), battery % + AC state.
* **Adaptive Resource Budget — the single source of truth** (constants live at the top of the module):

| Tier | Trigger | Max working context | Threads | Speculation |
|------|---------|--------------------:|---------|-------------|
| `HIGH` | avail RAM ≥ 2048 MB **and** load < 75 % | 64 MB | all cores | allowed |
| `BALANCED` | avail RAM 512–2047 MB **or** load 75–89 % | 16 MB | min(2, cores) | off |
| `COMPRESSED` | avail RAM < 512 MB **or** load ≥ 90 % | 2 MB | 1 | off |

  Modifiers: on battery below 20 % → drop one tier and disable speculation; CPU load ≥ 90 % → disable speculation and halve threads. Each applied rule is recorded in `budget.reasons`.
* **IPC contract**: `HardwareTelemetry.to_ipc_dict()` emits the JSON message that the Phase 2 C++ daemon must reproduce (schema v1, see `ARCHITECTURE.md` §3.1).

### 2.2 `net_guard.py` + `network_pipeline.py` + `raw_http.py` — Direct Ingestion Engine
* **Purpose**: fetch live data without a headless browser (200–500 MB RAM per instance).
* **Outbound policy (`net_guard.validate_url`)**, applied to every URL *and every redirect hop*: `http`/`https` only; no credentials in URL; ports 80/443 only; every resolved IP must be globally routable (blocks loopback, RFC 1918, link-local/cloud-metadata `169.254.169.254`, multicast, reserved).
* **Transports**:
  * `urllib` (default) — battle-tested, guarded redirect handler.
  * `raw` (**experimental**) — `socket` + `ssl`, HTTP/1.1, connects to the *validated IP* with correct TLS SNI (DNS-rebinding safe), Content-Length / chunked / until-close, hard caps on header size, body size and total wall-clock time. This is the executable model for the Phase 2 Winsock/IOCP design. Verified against a local server only.
* **Knowledge lookup**: Wikipedia title search → REST summary (language edition selectable: `--lang si` for Sinhala), then DuckDuckGo Instant Answer fallback. `lang` is whitelisted before it is placed in a hostname.
* **Error handling**: transport failures are *errors* with a precise reason; they are never passed to the verifier as if they were knowledge.
* **Limits**: default 6 s socket timeout; every read byte-capped (`max_bytes`); content types limited to text/JSON/XML.

### 2.3 `data_verifier.py` — Sanitizer & Quality Filter
* **Extraction**: `html.parser`-based text extraction (robust to malformed and unclosed tags). Drops `script, style, svg, noscript, template, iframe, nav, footer, aside, canvas, object, embed`.
* **Truncation**: by *bytes*, never splitting a UTF-8 character.
* **Quality score (0–1)**: Unicode-aware letter ratio (letters **and** combining marks, so Sinhala/Tamil/Hindi are first-class), Shannon entropy, zlib compression ratio (spam/repetition), minimum length (40 chars) and word count (waived for long unspaced scripts).
* **Prompt-injection screening**: pattern heuristics for instruction override, role reassignment, system-prompt exfiltration, chat-template tokens, secret exfiltration, "hide from user". Policy `reject` (default) or `flag`. This is a *speed bump*, not a guarantee — see `THREAT_MODEL.md` T3.
* Output `VerifiedPayload` adds `injection_flags`, `truncated`, `source`.

### 2.4 `secure_buffer.py` + `memory_probe.py` — Purge Primitives
* `SecureBuffer` stores ephemeral data in a `bytearray`, supports a hard capacity, zero-copy `view()`, and `wipe()` which **overwrites with `memset`, verifies every byte is zero, then releases**. `repr()` never prints contents.
* `memory_probe.rss_bytes()` reads process RSS (Windows `GetProcessMemoryInfo`, Linux `/proc/self/statm`, psutil fallback).

### 2.5 `reasoner.py` — The Brain Seam
* `Reasoner` protocol: `reason(query, context, budget) -> str`. `context` is *untrusted* external text.
* `TemplateReasoner` — explicit **stub** (labelled in its output), no inference; default.
* `LocalLLMReasoner` (ADR-001) — OpenAI-compatible **loopback-only** client for llama.cpp / Ollama / LM Studio / vLLM. No redirects or proxies, no tool parameters ever sent, untrusted context fenced (fence markers inside it neutralised), `max_tokens` by hardware tier (1024 / 512 / 128), response size cap. Enabled with `--model-url`.
* Phase 3 replaces both with the Rust engine's model runtime behind the same contract.

### 2.6 `agent_core.py` — Stateless Agentic Loop
The 4-step cycle (the canonical name everywhere in the docs):
1. **Perceive** — read telemetry, derive the budget.
2. **Ingest** — if the query starts with a trigger phrase (*what is, who is, explain, research, how does, summarize, tell me about*), fetch + verify live data into a `SecureBuffer` (capacity = budget context size). A rejected payload degrades the task (`status: DEGRADED`) instead of silently continuing.
3. **Reason** — call the `Reasoner`.
4. **Purge** — in a `finally` block (runs even on errors): wipe every buffer, verify zeroing, `gc.collect()`, record RSS / allocation deltas in a `PurgeReport`.

`memory_purged_successfully` is now `True` only when every buffer was *verified* all-zero.

### 2.7 `ast_guard.py` — RSI Tier-1 Prototype
Static allow-list gate for AI-generated Python: import allow-list, forbidden builtins (`eval, exec, open, getattr, __import__, …`), no dunder access, size/complexity caps, warning on `while True` without `break`. A lint-level filter, **not** a sandbox (Tier 2 is the boundary).

### 2.8 Privacy: `outbound_policy.py`, `local_knowledge.py` (ADR-002)
`OutboundPolicy`: domain allow-list (default `wikipedia.org`, `duckduckgo.com`; `--allow-domain` extends), offline mode, and an in-memory ring-buffer log of every request (allowed and blocked) with the exact URL; never written to disk. `LocalKnowledge` answers from `.txt/.md` files (never leaves the root, symlinks ignored, content verified); `CompositeKnowledge` chains sources (local first).

### 2.9 `capabilities.py` — Tool Broker (ADR-006)
Deny-by-default `Grant`s (roots, expiry, call budget), `Risk` levels, taint rule (untrusted context ⇒ any non-read tool needs a human; no channel ⇒ denied), destructive/outbound always confirmed, hash-chained audit log. `AgentExecutionResult.context_tainted` feeds the broker.

### 2.10 Release trust: `ed25519_ref.py`, `updater.py`, `sign_release.py` (ADR-005)
Signed manifests, per-file SHA-256, anti-rollback counter, pinned Constitution hash (`docs/CONSTITUTION.md`), TOCTOU re-verification, atomic install, verified rollback, engine-side `trust_root_is_protected()` check. Signing happens offline with `sign_release.py` (`cryptography`); the runtime verifier is stdlib-only.

### 2.11 `sandbox_policy.py` — Isolation checklist as code (ADR-003)
`make_wsb()` / `validate_wsb()` (fail-closed) for Windows Sandbox; `read_sandbox_results()` treats the single writable output folder as hostile.

### 2.12 `conformance.py` — Golden vectors (ADR-004)
Generates `conformance/tier_policy_vectors.json` (200 cases) and `url_policy_vectors.json` (28 cases). Rust and C++ ports must pass them; `tests/test_conformance.py` fails on drift.

### 2.13 `benchmark.py` + `main.py`
* `run_purge_benchmark` runs N cycles against an offline deterministic source, tracks retained Python allocations with `tracemalloc`, and **fails** if a purge is unverified or retained memory exceeds the tolerance (a unit test proves it detects an injected leak).
* `main.py` — interactive menu *and* scriptable flags: `--telemetry`, `--ask`, `--benchmark [--online]`, `--check-code`, `--topic`, `--json`, `--lang`, `--transport`, `--model-url/--model`, `--offline`, `--knowledge-dir`, `--allow-domain`, `--show-outbound`.

---

## 3. Testing

```powershell
cd research
python -m unittest discover -s tests -v
```

140 tests cover tier boundaries, battery/CPU rules, Win32 struct sizes, HTML/Unicode/injection verification, URL policy (file://, loopback, metadata IP, credentials, redirects), both transports against a local server (redirect, cap, chunked, binary, 404, refused), SecureBuffer zeroing, purge-on-exception, benchmark leak detection, the AST guard, the local-model adapter (fake server), privacy controls, capability broker, signed updater (incl. RFC 8032 vector), sandbox policy, golden-vector sync, and the claims lint.

**Not covered by automated tests** (must be checked by hand on Windows): the real `kernel32` code paths, live Wikipedia/DuckDuckGo access, a real local model, launching Windows Sandbox, and OS-level privilege separation for the updater.

---

## 4. Phase 1 → Phase 2 Handoff Contracts
* Telemetry JSON schema v1 (`ARCHITECTURE.md` §3.1) — frozen at Phase 1 exit.
* Tier policy table (§2.1) — the C++ daemon must reproduce it bit-for-bit; the Python tests become the daemon's conformance suite.
* Outbound URL policy (§2.2) — re-implemented in the native network layer.
* `Reasoner` contract (§2.5) — implemented by the Rust core in Phase 3.
* Golden conformance vectors (§2.12) — the executable form of the first two contracts.

## 5. Known Limitations of the Python Prototype
1. Python `str`/`bytes` are immutable; a `.text()` copy handed to the reasoner cannot be zeroed. Real guarantees arrive with Rust `zeroize` in Phase 3.
2. RAM can be paged to disk and captured in crash dumps; mitigations (`VirtualLock`, dump control) belong to Phase 2/3.
3. `urllib` re-resolves DNS (rebinding window); the `raw` transport closes it.
4. Injection screening is heuristic (the capability broker limits damage when it fails).
5. Automatic topic detection only understands English trigger phrases; other languages must use `--topic` (multilingual intent detection is a Phase 3 reasoner task).
6. Telemetry sampling is point-in-time; the 100 Hz push model arrives with the daemon.
