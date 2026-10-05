# ADR-006 — Capability broker with taint tracking (risk R7)

**Status:** Accepted, prototyped · **Date:** 2026-10-05

## Context
Prompt injection cannot be reliably filtered. Once the reasoner has tools (Phase 5 OS control), a poisoned web page could steer it to read files, send data out or destroy things.

## Decision
All side effects go through `research/capabilities.py::ToolBroker`:
1. **Deny by default** — a tool needs a user-created `Grant`; grants are fixed at construction (no API for tools or models to add one).
2. **Scoped** — path arguments must resolve (symlinks included) inside granted roots; grants may expire and carry call budgets.
3. **Taint tracking** — `StatelessAgentCore` reports `context_tainted=True` whenever untrusted data entered the context. Tainted tasks need **human confirmation for every non-read tool**; with no confirmation channel the call is **denied**.
4. **Always-confirm** — destructive and outbound-network tools need a human even in clean contexts.
5. **Confirmed = executed** — arguments are deep-copied so what the human approved is exactly what runs.
6. **Audit** — every decision (allow and deny) enters a hash-chained, tamper-evident log.
7. The reasoner **never receives tools while holding untrusted context**; actions are proposed, not executed, until the broker approves.

## Tested (`tests/test_capabilities.py`, 20 tests)
Deny-by-default, taint rules, confirmation fail-closed, traversal and symlink escape, expiry/budget, no later grants, audit tamper and deletion detection, and an end-to-end "web page tells the agent to email a file" scenario that is blocked.

## Limits
Taint is binary and per task; a smarter policy (per-field provenance) is future work. The human confirmation UI is Phase 5. The broker is only as strong as the rule that *every* side effect uses it.
