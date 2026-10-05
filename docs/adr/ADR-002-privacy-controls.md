# ADR-002 — Privacy controls for outbound traffic (risk R2)

**Status:** Accepted, implemented · **Owner decision D2** · **Date:** 2026-10-05

## Context
"Private, local" conflicts with sending every topic to Wikipedia/DuckDuckGo. Perfect privacy and live knowledge cannot both be absolute; the user must be in control and able to see what leaves.

## Decision
Reword the goal to **"local inference; minimal, visible, user-controlled outbound traffic."** Implemented:
* **Domain allow-list** (default `wikipedia.org`, `duckduckgo.com`; extend with `--allow-domain`) enforced on every request and redirect hop — `outbound_policy.py`.
* **Visible outbound log:** every request (allowed *and* blocked) with the exact URL, so the user sees the topic text that was sent. In-memory ring buffer only — never written to disk; `--show-outbound` prints it.
* **Offline mode** (`--offline`): all network access refused.
* **Local knowledge** (`--knowledge-dir DIR`): answer from your own `.txt/.md` files first, no network; symlink-escape safe; content still verified (files can carry injected instructions too).

## Residual risk
Allowed domains still learn the queries sent to them; the IP address is visible to them. Mitigation is user choice (offline / local first) not technology.

## Consequences
Default behaviour is unchanged for users who do nothing except gaining the log and allow-list; privacy-sensitive use is `--offline --knowledge-dir`.
