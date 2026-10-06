# Threat Model (v0.1 — Phase 1)

PAI ingests untrusted internet data, may eventually rewrite its own code and (Phase 5) drive the desktop. This document lists what we defend, from whom, and what is still open. It is a living document: every phase must update it before exit.

## 1. Assets
* The user's files, credentials and identity on the host.
* The user's queries and working data (privacy).
* The integrity of the engine and of its Safety Constitution.
* Host availability (RAM/CPU/disk).

## 2. Trust Boundaries
```
 Internet (UNTRUSTED) ──► net_guard ──► transport ──► DataVerifier ──► SecureBuffer ──► Reasoner
                                                                                │
 AI-generated code (UNTRUSTED) ──► Tier 1 AST ──► Tier 2 MicroVM ──► Tier 3 Auditor ──► Tier 4 Constitution
```
Everything left of the Reasoner is attacker-controlled until proven otherwise. Generated code is untrusted *even though PAI wrote it*.

## 3. Threat Register

| ID | Threat | Phase 1 status | Mitigation / next step |
|----|--------|----------------|------------------------|
| T1 | **Local file read / SSRF** — a URL such as `file:///…`, `http://127.0.0.1`, or `169.254.169.254` makes the engine read local files or hit internal services | **Fixed** (found in review: `file://` was accepted) | `net_guard`: scheme allow-list, IP must be global, ports 80/443, no credentials; re-validated on each redirect; unit-tested |
| T2 | **DNS rebinding** — name resolves to a public IP at check time, a private one at connect time | Partial | `raw` transport connects to the validated IP; `urllib` still re-resolves. Phase 2/3 native client pins IPs |
| T3 | **Prompt injection via web content** — "ignore previous instructions…" inside a page steers the reasoner | Mitigated (heuristic) + **blast radius limited** (ADR-006) | Screening (default reject) and untrusted-data fencing reduce the odds; the **capability broker** limits the damage if screening fails: deny-by-default grants, path scoping, taint tracking (untrusted context ⇒ every non-read tool needs a human; no confirmation channel ⇒ denied), hash-chained audit. Residual: confirmation UI is Phase 5; taint is per task |
| T4 | **Resource exhaustion** — giant bodies, slow-loris, decompression bombs | Mitigated | Byte caps on every read, total deadline (raw), 6 s socket timeout, `Accept-Encoding: identity`, content-type filter |
| T5 | **Residual data in RAM** after a task | Partial | `SecureBuffer` zeroes + verifies. Open: `str` copies, pagefile/swap, crash dumps. Phase 3: Rust `zeroize`, `VirtualLock`, disable WER dumps for the process |
| T6 | **Query privacy leak** — topics are sent to Wikipedia/DuckDuckGo | **Mitigated by user controls** (ADR-002) | Domain allow-list, visible outbound log (exact URLs), `--offline`, local-first `--knowledge-dir`. Residual: allowed domains still see queries and the IP address; the user chooses offline/local for sensitive topics |
| T7 | **Malicious / drifting self-modification** | Designed; Tier 0/1 + updater + sandbox policy prototyped | `RSI_SAFETY_SPEC.md`; externally signed releases and a separate updater that owns the Constitution hash (ADR-005); Windows Sandbox isolation checklist as code (ADR-003) |
| T8 | **TLS interception / bad certificates** | Mitigated | Default certificate and hostname verification; never disabled |
| T9 | **Telemetry spoofing / IPC abuse** (Phase 2) | Open | Named-pipe ACL restricted to the current user, message schema validation, versioned schema |
| T10 | **Supply chain** | Low | Prototype is stdlib-only; before adding dependencies: pin versions + hashes, review licences |
| T11 | **Hostile sandbox output** — the one writable folder is attacker-controlled | Mitigated (policy as code) | `read_sandbox_results`: exactly one `results.json`, ≤ 256 KB, strict schema, no links/extra files (ADR-003) |
| T12 | **Malicious, tampered or rolled-back update** | Mitigated (prototype) | Ed25519 signature over manifest, per-file SHA-256, anti-rollback counter, pinned Constitution hash, TOCTOU re-verification, atomic install (ADR-005). Residual: OS-level privilege separation is installer work; key custody procedure TBD |
| T13 | **External inference process memory retention** — local model runner (Ollama / llama-server) keeps prompt and generated tokens resident in external process memory and VRAM across tasks | Partial / Residual risk | Python internal buffers zeroized post-task (T5); external model server memory retention bounded by server idle timeout (e.g. keep_alive). Residual: external process memory zeroization is outside the Python agent boundary |
| T14 | **Trust-label injection** — context text claiming a higher-trust source (e.g. `[Source: local_knowledge]`) to influence conflict resolution | **Fixed** | Cryptographic per-task nonce (`secrets.token_hex(8)`); parser accepts `[[SRC:<nonce>:<source>]]` only; in-band text headers ignored; incoming `[[SRC:` tokens neutralized |

## 4. Out of Scope (for now)
Physical access, a compromised OS or kernel, malicious hardware, side-channel attacks.

## 5. Security Claims Policy (enforced by `research/tests/test_claims.py`)
Docs, code comments and UI must not claim "100 % secure". Allowed wording: *defense in depth*, with each guarantee tied to a named test or a named residual risk in the table above. <!-- claims-lint: quote -->
