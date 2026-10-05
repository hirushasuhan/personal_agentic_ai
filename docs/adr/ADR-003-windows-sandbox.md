# ADR-003 — Sandbox technology on Windows (risk R5)

**Status:** Accepted (default) — **requires a smoke test on the Windows target** · **Owner decision D3** · **Date:** 2026-10-05

## Context
Firecracker needs Linux + KVM and does not run natively on Windows. Tier 2 of the RSI spec needs a disposable environment with **no network**, tight resource caps and a hostile-output-safe result channel. Containers alone share the host kernel and are not an acceptable sole boundary.

## Options
| Option | Isolation | Disposable | Network off | Effort | Notes |
|--------|-----------|-----------|-------------|--------|-------|
| **Windows Sandbox** (primary) | Hyper-V based | Yes, automatic | `<Networking>Disable` | Low | Needs Windows Pro/Enterprise; config via `.wsb` |
| Hyper-V VM (fallback) | Hyper-V | Via checkpoints | Remove the NIC | Medium | Works on Pro/Enterprise; scriptable via PowerShell |
| Firecracker inside WSL2 | KVM (nested) | Yes | No NIC | High | Nested virtualisation required; Linux-target builds |
| Docker/WSL2 container | Shared kernel | Yes | `--network none` | Low | **Not acceptable alone** |

## Decision
Windows Sandbox is the default; a Hyper-V VM with no virtual NIC is the fallback for Home-edition-incompatible setups; Firecracker-in-WSL2 is an optional later hardening for Linux builds.

## Isolation checklist (enforced as code — `research/sandbox_policy.py`)
Networking, vGPU, audio/video input, printer and clipboard redirection all explicitly **Disable**; ProtectedClient **Enable**; memory ≤ 2048 MB; candidate code mapped **read-only**; **exactly one** writable mapping (the output folder); no drive-root or profile-root mappings; unknown configuration elements are rejected (fail closed). `validate_wsb()` refuses anything else; `make_wsb()` generates a compliant file.

## The one writable channel is hostile
`read_sandbox_results()` accepts exactly one `results.json`, ≤ 256 KB, strict schema, no links or extra files; everything else is rejected before any host code parses it.

## Smoke test (the gate) — how to run
```powershell
cd research
python sandbox_smoke_test.py --launch --wait 180   # exit 0 ONLY if the probe ran inside the sandbox and every check passed
# or manual: double-click the generated .wsb, wait, then:  python sandbox_smoke_test.py --evaluate-only
```
The probe (native PowerShell) checks: no TCP route, DNS fails, no network adapter up, the host staging path is invisible, no foreign user profiles, input mapping is read-only, only drive C: exists. Generating the `.wsb` alone does **not** pass the gate (exit code 2). Record the date and output here when it passes.

## Not yet done (Phase 4)
Launching the sandbox, waiting for completion, collecting results and a Windows smoke test confirming that a probe inside the sandbox cannot reach the network or the host filesystem. Phase 4 must not start without that test.

## If reversed
Swap the technology behind the same checklist: the checklist and the results-validator stay.
