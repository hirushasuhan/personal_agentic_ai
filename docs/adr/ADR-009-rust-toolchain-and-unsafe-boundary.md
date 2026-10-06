# ADR-009 — Rust toolchain targets and the `unsafe` boundary (slice VS3)

**Status:** Accepted (confirmed by owner, 2026-10-07) · **Date:** 2026-10-07
**Relates to:** ADR-004 (language scope and vertical slices)

## Context
* VS2 (pure tier and URL policies) is finished with `unsafe = 0` and only `serde`/`serde_json` as dependencies.
* VS3 replaces the Python telemetry readers with native Win32 calls (`GlobalMemoryStatusEx`, `GetSystemTimes`, `GetSystemPowerStatus`). FFI requires `unsafe`.
* The owner's development machine uses `stable-x86_64-pc-windows-gnu` (WinLibs GCC linker); CI (`windows-latest`) uses `x86_64-pc-windows-msvc`.

## Decision
1. **`unsafe` boundary:** `unsafe` is allowed only in `core/src/win32.rs` (and later one dedicated memory-protection module for `VirtualLock`/`zeroize`). Every `unsafe` block carries a `// SAFETY:` comment stating the invariant it relies on. All other modules keep `#![forbid(unsafe_code)]`-style enforcement (`#![deny(unsafe_code)]` at crate level with a single scoped `#[allow]` in `win32.rs`), and CI greps that no other file contains `unsafe`.
2. **Win32 bindings:** use the `windows-sys` crate (no runtime, thin bindings), version pinned through `Cargo.lock`. Add `cargo audit` (or `cargo deny`) to CI before release builds.
3. **Parity, not just policy:** the 200 tier vectors already prove the *policy*. A separate **telemetry parity check** compares the Rust readers with the Python readers on the same machine: available RAM within ±5 %, memory-load percentage within ±3 points, identical tier when both are given the same input numbers.
4. **Toolchains:** CI (MSVC) is the reference build for releases. The local GNU toolchain is accepted for development. A CI job also builds and tests the GNU target so divergence is detected early. Any behavioural difference between targets is a bug in the code, not an accepted variance.
5. **No fake values:** if a Win32 call fails the field is `null` (the tier policy then falls back to BALANCED with the reason `memory-telemetry-unavailable`), exactly as in the Python implementation.

## Consequences
* A small, auditable `unsafe` surface; reviewers read one file for memory-safety obligations.
* Slightly more CI time (two targets plus the audit step).

## If reversed
Call the Python reader through IPC and keep the Rust crate free of `unsafe` code (slower, adds a process boundary and an extra trust edge).
