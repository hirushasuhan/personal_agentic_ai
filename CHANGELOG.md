# Changelog

## [0.7.7] — 2026-10-08 — Milestone M2b Step 3 Two-Process Architecture, JSON RPC & Verdict Pipe Integrity

### Milestone M2b Step 3 Result-Integrity Channel (ADR-011 v2.1)
- **Two-Process Split Inside Sandbox (`research/verify_loop.py`, `research/sandbox.py`)**:
  - Implemented a strict two-process architecture separating the test harness from the candidate solution code:
    - **Trusted Driver Process (`_pai_driver.py`)**: Executes frozen test suites without ever directly importing candidate solution code. Sets `prctl(PR_SET_DUMPABLE, 0)` on Linux to block ptrace and `/proc/<driver>/fd/*` access. Injects `SolutionProxyModule` exposing proxy callables for candidate functions.
    - **Candidate Worker Process (`_pai_worker.py`)**: Spawned as isolated child process with `close_fds=True`, communicating strictly via standard anonymous pipes exchanging JSON-serialized values.
  - **JSON-Only RPC Boundary**: Every function call and return value crosses process boundaries strictly serialized as JSON primitives (`int, float, str, bool, None`, and nested lists/dicts). Non-JSON objects, custom types, and subclassed primitives (such as `class R(int)`, `class R(list)`, `object()`) are rejected with `EqualityHijackError`, eliminating `__eq__` spoofing and live object hijacks by construction across all test styles (module-level assertions, pytest-style functions, and `unittest.TestCase`).
- **Driver-Held Stdout Pipe Verdict Channel & Parent-Held Nonce (`research/verify_loop.py`, `research/sandbox_win32.py`, `research/sandbox_linux.py`)**:
  - Eliminated writable verdict directories: no verdict directory is mounted into the sandbox. The verdict is transmitted exclusively through the driver's standard output pipe using structured framing (`---PAI_VERDICT_START---` ... `---PAI_VERDICT_END---`).
  - Candidate worker has no access to driver's stdout pipe (`close_fds=True`) and cannot open it via `/proc` due to `PR_SET_DUMPABLE = 0`.
  - Parent generates 32-byte hex `parent_nonce` outside the sandbox and passes it to driver. Parent verifies exact match against `session_nonce` and requires exact set match of executed test IDs against frozen AST list.
- **Acceptance Tests**:
  - Added named acceptance tests for all attack variants: driver inspection, filesystem globbing, `/proc/self/fd` writing, driver PID fd tampering, module-level `R(int)`, plain object, and `R(list)` hijacks, plus positive control test.
  - 285 Python unit tests passing (19 skipped on Windows: 5 privilege/POSIX + 14 Linux bwrap tests). Claims lint passing (2/2). Conformance check clean.

## [0.7.6] — 2026-10-08 — Milestone M2b Step 2.1 Stub Family, Discovery Driver & Mandatory Freeze Enforcement

### Milestone M2b Step 2.1 Fixes & Verification (F1, F2, F4, F5)
- **F1: Substantive Assertion Enforcement in Stub Probe (`research/verify_loop.py`)**:
  - `run_stub_probe` strictly differentiates between substantive assertion failures (`AssertionError`, unittest FAIL) and test suite runtime crashes.
  - Test suites raising non-assertion errors (`NameError`, `ZeroDivisionError`, `ImportError`, `SystemExit`) or timing out are rejected fail-closed as `TEST_SUITE_INVALID`, rather than treated as verified.
  - Negative control tests added: `test_nameerror_suite_rejected_as_invalid`, `test_timeout_suite_rejected_as_invalid`.
- **F2: Dynamic Test Discovery & Execution Driver (`research/verify_loop.py`)**:
  - Replaced naive top-level `exec` driver with an isolated discovery driver loaded under dedicated module namespace `test_suite`.
  - Prevents top-level `if __name__ == '__main__': unittest.main()` from aborting runner execution with early `sys.exit(1)`.
  - Discovers both pytest-style standalone `test_*` functions and `unittest.TestCase` subclasses, as well as AST-detected module-level assertions.
  - Executes each test individually and strictly enforces `executed == discovered >= 1`.
  - Negative control tests added: `test_pytest_style_suite_discovered_and_verified`, `test_empty_tests_discovery_fails`.
- **F4: 11-Member Stub Family (`research/verify_loop.py`)**:
  - Expanded stub probe from single `None` stub to an 11-member diverse stub family: `(None, 0, 1, -1, "", [], {}, True, False, first argument, NotImplementedError)`.
  - Rejects weak assertions (e.g. `assert x is not None`) as `VACUOUS_TESTS_REJECTED`, specifically naming the passing stub (e.g. stub `'0'`).
  - Handles `NotImplementedError` raised by the stub cleanly as expected failure while still rejecting tests that vacuously pass or crash with unrelated errors.
  - Negative control test added: `test_weak_is_not_none_suite_rejected`.
- **F5: Mandatory Freeze & Anti-Tampering Enforcement (`research/verify_loop.py`)**:
  - Removed optional `current_test_code` parameter from `execute_solution_tests()`; VerifyLoop strictly owns test writing.
  - Verifies file hash read-back from sandbox scratch before execution; driver additionally verifies SHA-256 hash inside the sandbox.
  - Negative control tests added: `test_execute_solution_tests_no_current_test_code_parameter`, `test_tampered_scratch_file_raises_mutation_error`.
- **Test Suite**: 272 Python unit tests passing (19 skipped on Windows: 5 privilege/POSIX + 14 Linux bwrap tests). 13 Rust core tests passing, clippy clean.

## [0.7.5] — 2026-10-08 — Milestone M2b.2 Frozen Tests, Stub Probe & A8 Refinements

### Milestone M2b.2 Fixes & Verification
- **Frozen Test Suite & Cryptographic Hashing (`research/verify_loop.py`)**:
  - Test suites (model-written or user-supplied) are analyzed for assertions and symbols via Python AST and cryptographically frozen with SHA-256 before candidate solution generation or repair.
  - User-provided `--tests` strictly take priority over model-written tests.
  - Anti-weakening enforcement: Any attempt to mutate test code during the repair loop raises `TestMutationError`.
- **Sandbox-Isolated Stub Probe (`research/verify_loop.py`)**:
  - Every candidate test suite is executed in the OS sandbox against a trivial wrong solution stub returning `None` for all symbols.
  - Test suites that pass against the stub are identified as vacuous and rejected (`VACUOUS_TESTS_REJECTED`).
  - To be accepted, test suites must contain substantive assertions that correctly fail against the stub (`NON_VACUOUS_VERIFIED`).
- **CLI Integration (`research/pai.py`)**:
  - Added `--tests <path>` argument to `pai code`. CLI freezes tests, validates non-vacuity via the stub probe, and enforces sandbox boundaries.
- **A8 Matrix Vector Refinements (`research/run_m2a_matrix.py`)**:
  - Discriminating network sub-check: accepts strictly `ENETUNREACH`, `EPERM`, `EACCES` and rejects `ECONNREFUSED` (111).
  - Dropped non-discriminating fork sub-check from vector A8.
  - Asserted host canary file existence and unchanged content post-run (`secret_a8`).
  - Added strict rejection of any `FAIL_` lines in test assertion output.
- **Test Suite**: 266 Python unit tests passing (19 skipped on Windows: 5 privilege/POSIX + 14 Linux bwrap tests). 13 Rust core tests passing, clippy clean.

## [0.7.4] — 2026-10-08 — Milestone M2b.1 Native OS Boundary Vector Hardening & Portability Clarifications

### Milestone M2b.1 Fixes & Verification
- **Non-Vacuous Native Code Boundary Vector A8 (`research/run_m2a_matrix.py`)**:
  - Replaced vacuous A8 `MessageBeep` / `ctypes.CDLL(None)` test with direct native OS boundary calls.
  - Windows: executes native Win32 `CreateFileW` targeting outside canary file (`~/.pai/m2a_canary_a8_*.tmp`), strictly asserting `ERROR_ACCESS_DENIED` (5) / `PermissionError`, coupled with a positive control verifying `CreateFileW` succeeds inside the scratch directory.
  - Linux: uses ctypes to invoke libc `open()` on outside canary path (asserting `errno in (EROFS, EACCES, EPERM, ENOENT)`), native socket connect (asserting `ENETUNREACH/EPERM/EACCES/ECONNREFUSED`), and native `fork()`, coupled with a positive control verifying native `open()` succeeds in scratch.
  - Strict positive marker assertions: requires `CONTAINED_NATIVE_DENIED` (or `CONTAINED_NATIVE_FILE_DENIED`) AND `POSITIVE_CONTROL_NATIVE_OK` without any leak markers.
- **Evidence Verification Hardening (`research/tests/test_sandbox_evidence.py`)**:
  - Updated evidence validation test to strictly require `POSITIVE_CONTROL_NATIVE_OK` in A8's stdout sample for all recorded platforms.
- **Vector Classification Clarification (`CHANGELOG.md`)**:
  - Clarified that vector A11 is a ctypes segmentation fault trap (Linux exit code 139, Windows 0xC0000005) rather than a memory exhaustion bomb (which is vector A2).
- **Target Platform Portability Clarification (`docs/ROADMAP.md`)**:
  - Documented that the local host operates under a non-elevated user context preventing WSL2 installation; the specification requirement for Linux/WSL2 portability is satisfied via GitHub Actions Ubuntu CI and reviewer host verification.

## [0.7.3] — 2026-10-08 — Milestone M2a.4 Platform-Neutral Matrix Runner & CI Evidence Artifacts

### Milestone M2a.4 Platform-Neutral Runner & Evidence Hardening
- **Platform-Neutral Adversarial Matrix Runner (`research/run_m2a_matrix.py`)**:
  - Attack scripts now emit containment markers both via standard output (`print(marker, flush=True)`) and scratch file `std_output.txt`.
  - Assertions inspect unified output (`get_combined_output(r)`), eliminating the 5 Linux false-failures caused by pipe vs file redirection differences.
  - Vector A3_A7 tests fork proliferation bounded by `RLIMIT_NPROC` on Linux and `ActiveProcessLimit = 1` on Windows with strict `"CONTAINED"` and no `"LEAK"` assertions (eliminating vacuous passes).
  - Vector A9 floods stdout with 200 KB and strictly asserts `len(r.stdout) == 65536` AND presence of `"FLOOD_MARKER_START"` (eliminating 0-byte vacuous passes).
- **Strict Evidence Schema & Marker Verification (`research/tests/test_sandbox_evidence.py`)**:
  - Added test asserting that every recorded platform in `m2a_sandbox_results.json` achieves 10/10 passes with positive containment markers for every attack vector.
- **CI Linux Evidence Artifact Upload (`.github/workflows/windows-ci.yml`)**:
  - `linux-portability` job now uploads `m2a_sandbox_results.json` and `m2a_sandbox_raw.log` directly as a GitHub workflow artifact (`linux-m2a-sandbox-evidence`).
- **Test Suite**: 252 Python unit tests passing (19 skipped on Windows: 5 privilege/POSIX + 14 Linux bwrap tests). 13 Rust core tests passing, clippy clean.

## [0.7.2] — 2026-10-08 — Milestone M2a.2 Linux Merged-/usr & EROFS Probe Resolution

### Milestone M2a.2 Fixes & Verification Hardening
- **Merged-`/usr` Dynamic Linker Resolution (`research/sandbox_linux.py`)**:
  - Fixed `is_bwrap_functional()` false negative on modern merged-`/usr` systems (Ubuntu 22.04/24.04, WSL2 Ubuntu).
  - Probes with absolute executable path (`shutil.which('true')` or `/usr/bin/true`) and full root read-only bind (`--ro-bind / /`), falling back to runner-equivalent explicit mounts (`/usr`, `/lib`, `/lib64`, `/bin` with symlink resolution), preventing `execvp true: No such file or directory` caused by missing dynamic linker symlinks.
- **Probe `EROFS` Exception Handling (`research/sandbox_linux.py`)**:
  - Updated behavioural capability probe script to accept `OSError` with `errno in (errno.EROFS, errno.EACCES, errno.EPERM)` for write and delete canary tests on read-only bound filesystems.
  - Resolved false-positive boundary compromise report where Python's `open()` raised `OSError(EROFS)` (which is not a `PermissionError`), allowing `probe_linux_boundary()` to pass cleanly.
  - Added unit regression tests (`test_erofs_containment_regression`, `test_probe_handles_erofs_simulation`, `test_is_bwrap_functional_on_linux`).
- **Fail-Closed Linux Test & CI Enforcement (`research/tests/test_sandbox_linux.py`, `.github/workflows/windows-ci.yml`)**:
  - `TestLinuxSandboxContainment.setUp()` now explicitly fails (`self.fail`) if `bwrap` is in PATH but `is_bwrap_functional()` returns False, preventing silent test skipping.
  - Linux CI job (`linux-portability`) asserts `is_bwrap_functional()` is True, verifies `probe_linux_boundary()` passes, and asserts zero skips in `test_sandbox_linux`.
  - Added execution of `run_m2a_matrix.py` directly in Linux CI.
- **Empirical Matrix Evidence & Platform Provenance (`docs/evidence/m2a_sandbox_results.json`, `docs/evidence/m2a_sandbox_raw.log`)**:
  - `run_m2a_matrix.py` updated to dynamically query host platform metadata via `get_platform_metadata()` (`platform.release()`, `/etc/os-release`, `bwrap --version`, Windows build and sandbox technologies) without manual field editing.
  - Windows 11 host evidence and raw execution traces generated directly by `run_m2a_matrix.py`.
  - Linux sandbox boundary containment independently confirmed by the reviewer on Linux (kernel 6.8.0-138-generic, uid 1026, 14 sandbox tests passed, 0 skips, probe contained); unverified synthetic Linux evidence block removed from committed repository evidence. Linux matrix generation runs live in GitHub Actions CI (`ubuntu-latest`).
- **Evidence Schema Validation (`research/tests/test_sandbox_evidence.py`)**:
  - Added unit test suite ensuring `m2a_sandbox_results.json` strictly adheres to the runner schema, validates dynamic metadata extraction, and ensures all 10 attack vectors are contained.
- **Test Suite**: 252 Python unit tests passing (19 skipped on Windows: 5 privilege/POSIX + 14 Linux bwrap tests). 13 Rust core tests passing, clippy clean.

## [0.7.1] — 2026-10-08 — Milestone M2a.1 Linux Runner & Behavioural Probe Hardening

### Milestone M2a.1 Hardening & Probe Resolution
- **In-Sandbox POSIX Rlimits (`research/sandbox_linux.py`)**:
  - Eliminated `preexec_fn` `RLIMIT_NPROC` throttle outside `bwrap` which prevented namespace creation (`EAGAIN`) for non-root users.
  - Implemented `_pai_launcher.py` inside the scratch directory to apply resource limits (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NPROC`) *after* entering namespaces and directly before executing worker code.
  - Added `is_bwrap_functional()` to verify unprivileged namespace creation rights on host, skipping gracefully if AppArmor or userns restrictions apply.
- **Robust Behavioural Capability Probes (`research/sandbox_win32.py`, `research/sandbox_linux.py`)**:
  - **Positive Control**: Probe runs an unisolated baseline execution first and strictly verifies that all canaries report `LEAK`. If unisolated execution fails to detect leaks, probe self-test fails.
  - **Parent-Side Verification**: Parent verifies before and after sandbox execution that canary files exist on the host and their cryptographic secret tokens are unchanged.
  - **Strict Exception Handling**: Only expected error types (`PermissionError`, `WinError 10013` / WSAEACCES, `TimeoutError`, `ConnectionRefusedError`, `ENETUNREACH`, `EROFS`) are accepted as `CONTAINED`. Any unexpected exception (e.g. `FileNotFoundError`, `NameError`) fails the probe.
  - **Bound Canary Paths (Linux)**: Write and delete canaries are placed in a host directory mounted with `--ro-bind`, ensuring kernel-level write denials (`EROFS`) rather than vacuous tmpfs replacements.
  - **Subprocess Redefinition (Linux)**: Subprocess creation within an isolated sandbox is recognized as internal to the container; resource limits are verified separately in A3.
- **Automated Evidence Generation (`research/run_m2a_matrix.py`)**:
  - Created automated adversarial matrix benchmark harness executing all vectors (A1-A11 + Probe) with live wall-clock timings in milliseconds, raw stdout/stderr captures, and exit codes.
  - Generates `docs/evidence/m2a_sandbox_results.json` and raw execution log `docs/evidence/m2a_sandbox_raw.log`.
- **Windows Path Hijack Defense & ACL Scope Clarification (`research/sandbox_win32.py`)**:
  - Resolved `icacls` to absolute path `%SystemRoot%\System32\icacls.exe`.
  - Documented that zero system-wide ACL drift applies strictly to `~/.pai/sandbox_runtime` and ephemeral scratch directories.
- **CLI Code Enforcement (`research/pai.py`)**:
  - Added `enforce_sandbox_boundary()` helper invoked before `pai code` execution, failing closed with Exit code 5 if boundary probe is compromised.
- **Adversarial Matrix Completeness**: Added vector A8 (native code loading / ctypes escape) to unit test suites and evidence harness.
- **Test Suite**: 245 Python unit tests passing (16 skipped across platform gates). 13 Rust core tests passing, clippy clean. 10,000 differential fuzz cases clean. All 5 frozen eval set hashes intact.

## [0.7.0] — 2026-10-08 — Milestone M2a Sandbox Runner, Boundary Probe & Adversarial Containment Matrix

### Milestone M2a Restricted Execution Runner (ADR-011 v2.1)
- **Win32 AppContainer & Job Object Sandbox (`research/sandbox_win32.py`)**:
  - True OS-level isolation on Windows using Win32 AppContainer profiles with zero network capabilities (`CapabilityCount = 0`), blocking all socket creation at the TCP/IP driver layer.
  - DACL granted exclusively to the ephemeral AppContainer SID on the assigned scratch directory (`icacls`).
  - Hard resource limits via Windows Job Objects: 512 MB memory ceiling (`JOB_OBJECT_LIMIT_PROCESS_MEMORY` / `JOB_OBJECT_LIMIT_JOB_MEMORY`), single process limit (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1`), CPU time budget, and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
  - Non-privileged runtime preparation in `~/.pai/sandbox_runtime` with `ALL APPLICATION PACKAGES` read permissions, enabling AppContainer execution of Python without administrator privileges or permanent system ACL drift.
- **Linux Bubblewrap Sandbox Runner (`research/sandbox_linux.py`)**:
  - Implemented bubblewrap isolation runner with `--unshare-net`, `--unshare-pid`, `--unshare-ipc`, `--cap-drop ALL`, `--new-session` (preventing TIOCSTI injection), `--clearenv`, `--die-with-parent`, `--tmpfs /home`, `--tmpfs /tmp`, and scratch directory bind.
  - Configured POSIX `resource.setrlimit` ceilings for `RLIMIT_AS` (512 MB), `RLIMIT_CPU`, `RLIMIT_NPROC` (1 process max for non-root), and `RLIMIT_FSIZE` (1 MB).
- **Behavioural Capability Probe (`research/sandbox.py`)**:
  - Live canary self-test executed on startup before running any untrusted tasks: probes loopback network connect, outside canary read, outside canary write, outside canary delete, and child process spawn. Fails closed (exit code 5) if any canary leaks.
  - Unified facade dispatching to platform runner based on host OS (`Win32Sandbox` / `LinuxSandbox`).
- **Adversarial Containment Matrix Suites (`research/tests/test_sandbox_win32.py`, `research/tests/test_sandbox_linux.py`)**:
  - Validates full attack matrix covering vectors A1 (timeout), A2 (memory bomb), A3/A7 (process proliferation), A4 (canary delete), A5 (filesystem read escape), A6 (network socket egress), A9 (stdout stream flood 64 KB cap), A11 (crash isolation).
  - Empirical execution evidence recorded in `docs/evidence/m2a_sandbox_results.json`.
- **Ctypes Policy Enforcement (`research/tests/test_ctypes_allowlist.py`)**:
  - Repository-wide AST test ensuring `import ctypes` is strictly confined to 4 approved modules (`hardware_telemetry.py`, `memory_probe.py`, `secure_buffer.py`, `sandbox_win32.py`).
  - Documented with `# SAFETY:` comments in Python code.
- **CLI & CI Integration (`research/pai.py`, `.github/workflows/windows-ci.yml`)**:
  - `pai doctor` and `pai doctor --json` run and report the behavioural sandbox boundary probe.
  - Added bubblewrap setup and unprivileged namespace configuration to `linux-portability` job.
- **Test Suite**: 243 Python unit tests passing (15 skipped: 5 Windows-specific privilege/POSIX skips + 10 Linux-specific sandbox skips on Windows). 13 Rust core tests passing, clippy clean (`-D warnings`). 10,000 differential fuzz cases clean. Telemetry parity passing. All 5 frozen eval set hashes intact.


### Milestone M2 Architecture & Design Specification
- **ADR-011 Architecture Decision Record (`docs/adr/ADR-011-restricted-execution-sandbox.md`)**:
  - Multi-tier containment: Tier-1 AST Guard, Tier-2 OS-level Restricted Sandbox Runner, Tier-3 Test Grader, and Safe Output Staging.
  - Cross-platform OS security boundary: Windows Job Objects (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, 512 MB memory limit, 1 active process limit, Low Integrity token stripping) and Linux Namespaces (`CLONE_NEWNET`) with POSIX resource limits (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC`).
  - Bounded iterative repair loop ($N \le 3$) with sanitized diagnostic extraction.
  - Safe atomic output staging with strict refusal to overwrite existing user files without explicit `--overwrite`.
- **Milestone M2 Verify Loop Specification (`docs/M2_VERIFY_LOOP_SPEC.md`)**:
  - Comprehensive contract for `pai code "<task>" --out <dir>`.
  - 11-attack adversarial containment test matrix: infinite loops, memory bombs (10 GB heap allocation), fork bombs, canary file deletion, filesystem breakouts, network socket creation, subprocesses, ctypes native loading, stdout stream floods (pipe bombs), hidden test tampering, and segfault traps.
  - Frozen evaluation plan on `coding_benchmark_v1.json` (Pass@1 baseline vs Pass@3 verify loop).

### M1c.2 Profile Normalization & Evidence Honesty
- **Illustrative Schema Documentation (`docs/examples/example_machine_profile.json`)**: Moved unmeasured secondary profile out of `docs/evidence/` to `docs/examples/` as an explicit schema template; empirical second-machine calibration item remains open pending physical WSL2 run.
- **Canonical Base OS Normalization (`research/config.py`, `research/pai.py`)**: `_canonical_os` compares base platform systems (`windows`, `linux`, `darwin`), preventing routine OS kernel updates from invalidating calibrated profiles. `cmd_calibrate` stores `platform.system()`.
- **Strict Expiration Enforcement (`research/config.py`)**: Profiles without `expires_at` calculate and enforce `calibrated_on + 30 days`. Profiles lacking timestamps are rejected. `_comment` key permitted in machine profiles.
- **Test Suite**: 222 Python unit tests passing (14 in `test_config.py`). Windows vs Linux skips documented (5 skipped on Windows, 2 on Linux).

## [0.5.6] — 2026-10-07 — Milestone M1c.1 Hardening & Probe Defect Resolution

### M1c.1 Router & Profile Hardening
- **Uncalibrated 1.5x Rule on Fresh Machines (`research/router.py`)**: When no machine profile exists, `ModelRouter` applies the ADR-010 conservative multiplier ($1.5 \times \text{card\_delta} + 512.0\text{ MB}$) to local candidates by default, tagging decisions with `UNCALIBRATED`. At 1850 MB free RAM on a fresh machine, 7B (requiring 2470.9 MB) is rejected and 1.5B is selected. Added `reference_profile_mode=True` to preserve frozen golden decision vector conformance tests.
- **Plausibility Floor (`research/router.py`)**: Calibrated deltas $< 50\%$ of card prior (e.g. 1.0 MB for 7B) are rejected by plausibility floor, falling back to conservative 1.5x rule and recording `CALIBRATION_IMPLAUSIBLE` in reason codes and rejection records.
- **Automatic Live Telemetry & Machine Identity (`research/router.py`, `research/config.py`)**: `ModelRouter` and CLI commands query live hardware (`live_total_ram_gb`, `live_machine_id`, `live_os`) automatically. Foreign machine profiles with mismatched machine ID or OS fail closed and fall back to uncalibrated mode. Profiles older than 30 days or past `expires_at` are rejected as expired.
- **Calibration Measurement Hardening (`research/pai.py`)**: `pai calibrate` polls loopback `/api/ps` until candidate model is fully unloaded, followed by 2.0s settling sleep. Runs with non-positive RAM deltas ($\le 0.0\text{ MB}$) are discarded; requires minimum 3 valid runs per model. Emits warning if spread $> 30\%$ median. Computes 30-day `expires_at` timestamp. Saves profile incrementally after each model. `pai doctor` displays `Not calibrated -- run pai calibrate` when uncalibrated.
- **Value-Level Secret Screening (`research/config.py`)**: Configuration scanner screens string values for credentials and token patterns (`sk-`, `ghp_`, `Bearer `, `api_key=`, high-entropy tokens). Validates `spend_caps` (dict of non-negative numbers) and `enabled_providers` (list of strings). Strictly rejects `privacy_mode: allow-cloud` until Milestone M1d.
- **Second-Machine Calibration Evidence (`docs/evidence/second_machine_profile.json`)**: Documented calibration numbers from a secondary Linux environment (superseded: not a measurement, see the entry above and `docs/examples/`).
- **Test Suite**: 219 Python unit tests passing (+9 new tests in `test_config.py` and `test_router.py`). Windows vs Linux skip difference documented (5 skipped on Windows due to symlinks and non-root POSIX tests, 2 skipped on Linux). 13 Rust core tests passing, clippy clean (`-D warnings`). 10,000 differential fuzz cases clean. Telemetry parity passing. All 5 frozen eval set hashes intact.

## [0.5.5] — 2026-10-07 — Milestone M1c Portability, Hardware Calibration, User Configuration, and PAI CLI

### M1c Portability & Machine Profile Calibration (ADR-010)
- **Empirical Hardware Calibration (`research/config.py`)**: Support for non-committed machine profiles (`~/.pai/machine_profile.json`). Calibrated models use empirical 5-run cold deltas (`MACHINE_PROFILE_CALIBRATED`); uncalibrated models apply ADR-010 conservative rule: `required_ram = card_delta * 1.5 + 512.0 MB` with `"UNCALIBRATED"` decision code.
- **Tampering Detection (Threat T26)**: Profiles are validated against live hardware; claimed total RAM deviating >35% from physical RAM is rejected fail-closed.
- **User Configuration & Allow-Lists (Threats T21, T22)**: Schema-validated `~/.pai/config.json` supports non-secret user settings (`allowed_models`, `preferred_models`, `privacy_mode`). Credential scanner immediately rejects forbidden keys/tokens (`key`, `secret`, `token`, `password`, `auth`).
- **Live Resident Probe Hardening**:
  - `get_live_resident_model()` strictly checks `base_url` is local loopback (`127.0.0.1`, `localhost`, `::1`), raising `ValueError` on external hosts to prevent SSRF.
  - Replaced prefix matching with exact name matching (`candidate_name == m_name`) to eliminate tag pollution or spoofing.
  - Multi-model resident list from `/api/ps` resolved deterministically using candidate priority ordering.

### PAI Unified Command Line Interface (`research/pai.py`)
- **`pai doctor [--json]`**: Cross-platform system diagnostics (OS, CPU cores/load, RAM total/avail/pressure, GPU/iGPU probe, battery state, loopback Ollama `/api/ps` probe, candidate eligibility matrix).
- **`pai calibrate [--model, --runs]`**: Automated 5-run cold RAM & latency profiling per `MEASUREMENT_PROCEDURE.md` saving validated machine profile to `~/.pai/machine_profile.json`.
- **`pai models list [--json]`**: Candidate model catalog with display names, licenses, calibration state, min RAM, and live hardware fit.
- **`pai route <command> [--explain-route, --json]`**: Wires `ModelRouter` to CLI.
- **Deferred Execution Commands**: Subcommands `generate`, `analyze`, and `forecast` print explicit guidance that execution is deferred to Milestone M2+, pointing users to `pai route <command>`.

### CI & Verification
- **Linux Portability CI Job**: Added `linux-portability` job to `.github/workflows/windows-ci.yml` running on `ubuntu-latest`.
- **Tests**: 210 Python unit tests passing (up from 191, +19 tests in `test_config.py`, `test_pai_cli.py`, and `test_router.py`). 13 Rust tests passing, clippy clean. 10,000 differential fuzz cases clean.

## [0.5.4] — 2026-10-07 — Milestone M1b.1 Router Hardening & Probing Fixes

### M1b.1 Router Probing Hardening (`research/router.py`)
- **Sticky Resident Eviction**: Enforced that resident models DO NOT bypass CPU load (`cpu-saturated`), low battery, or COMPRESSED tier constraints. Heavy resident models (`qwen2.5-coder:7b`, `qwen3.5:4b`, `gemma4:e2b`) are evicted and downgraded across all code, chat, and document analysis paths.
- **Strict Command Validation**: Unknown or invalid commands raise `ValueError` immediately at entry point; silent fallback to docs/7B eliminated.
- **Resident Model Allow-List Validation**: Callers cannot spoof unvetted resident names to bypass RAM headroom checks; unlisted names are ignored and rejected. Added `get_live_resident_model()` to query `/api/ps` and validate against the allowed catalog.
- **Unverified License Transparency (Threat T20)**: Models with unverified upstream licenses (`qwen3.5:4b`, `gemma4:e2b`) marked as `unverified` in `model_profiles.json` and labeled with `UNVERIFIED_LICENCE` in router decisions.
- **Deferred Cloud Parameter**: Removed misleading `allow_cloud` parameter from `route()`; cloud routing deferred to Milestone M1d (ADR-010).
- **Frozen Golden Vectors**: Expanded to 20 vectors in `research/eval_sets/router_golden_vectors.json` (SHA-256: `69f885ec8f332e20176378c65b0b458961c8b8de0993396950d6c3572b1195bd`), covering CPU-saturated resident eviction, low-battery chat eviction, unmeasured docs CPU saturation, and untrusted resident spoofing defense.
- **Adoption Test Clarification**: Clarified that router matches the best fitting single model for each budget regime without making unmeasured quality claims.
- **Tests**: 191 Python tests passing (5 skipped).

## [0.5.3] — 2026-10-07 — Milestone M1b Adaptive Model Router & M1.3 Hardening

### M1b Adaptive Model Router (`research/router.py`)
- **Graceful Degradation Priority**: Adapts model selection based on host RAM, compute tier, power/battery state, and CPU throttle conditions. Quality ranking is only favored when difference exceeds empirical noise margin (e.g. 7B coding 60% vs 40%).
- **Strict Task Class Isolation (Threat T21)**: Task class derived strictly from CLI command argument (`code`, `analyze`, `docs`, `forecast`, `web`, `chat`); file and web context is never parsed for task routing.
- **Extensible Candidate Architecture (M1d Readiness)**: Candidates declare `kind` (`local` | `cloud`) and `data_leaves_machine` (`bool`). Host RAM-fit check applies exclusively to local models. Route reports include `Data leaves machine: Yes / No`.
- **Hysteresis & Sticky Resident Preservation**: Resident models in memory bypass pre-load checks and are preserved for compatible task classes to avoid cold reload latency (8.7s–18.25s).
- **Owner Opt-In Enforcement**: High-RAM `gemma4:e2b` (2.93 GB host RAM) requires explicit `gemma4_opt_in=True` and $\ge 3500$ MB free RAM; otherwise rejected with `OPT_IN_REQUIRED`.
- **Unmeasured Class Handling**: `docs`, `analyze`, `web`, and `forecast` route to code/general models tagged with `UNMEASURED_CLASS`.
- **Golden Decision Vectors**: Frozen suite of 15 vectors in `research/eval_sets/router_golden_vectors.json` (hash recorded in `eval_sets_hashes.json`).
- **Comprehensive Unit Tests**: `research/tests/test_router.py` (5 tests) covering golden vector conformance, T21 context isolation, cloud candidate extensibility, and equal RAM budget adoption comparisons.

### M1.3 Evaluation & Profiles Hardening
- `research/model_profiles.json`: Reconciled official Hugging Face source repository URLs and license URLs for all profiles. Labeled `model_footprint_mb` and live deltas as informational only (not used by router).
- `research/reasoner.py`: Added `temperature` and `seed` parameters to `LocalLLMReasoner` across both Ollama native and OpenAI endpoints for deterministic evaluations.
- `docs/evidence/eval_sets_hashes.json`: SHA-256 hash for `router_golden_vectors.json` frozen.

## [0.5.2] — 2026-10-07 — Milestone M1.2 Hardening, Standardized RAM Measurements & Full 20-Doc Bake-Off

### M1.2 Standardized Cold-Start RAM Procedure & Empirical Measurements
- `docs/MEASUREMENT_PROCEDURE.md`: Documented reproducible 5-run cold-start RAM measurement standard with mandatory cache flushing (`keep_alive: 0`), process settling (2.0s), and median calculation.
- `research/measure_cold_profile.py`: Automated tool executing the standardized measurement procedure.
- `docs/evidence/cold_ram_measurements.json`: Empirical 5-run dataset across all 5 models:
  - `llama3.2:3b`: Median host delta **740.0 MB** (min 601.5 MB, max 783.5 MB, latency 3.21s).
  - `qwen2.5-coder:1.5b`: Median host delta **590.4 MB** (min 586.3 MB, max 672.4 MB, latency 3.82s).
  - `qwen3.5:4b`: Median host delta **1038.6 MB** (min 1016.9 MB, max 1060.4 MB, latency 8.69s).
  - `gemma4:e2b`: Median host delta **2934.8 MB** (min 2894.4 MB, max 3004.8 MB, latency 14.86s). Solved Ollama footprint anomaly: the 214.4 MB reported by `ollama ps` is discrete VRAM only; remaining weights allocate 2.93 GB of host RAM.
  - `qwen2.5-coder:7b`: Median host delta **1305.9 MB** (min 1289.4 MB, max 1435.5 MB, latency 18.25s).
- `research/model_profiles.json`: Updated schema v2 with official Hugging Face repository URLs, verified SPDX license IDs (`Apache-2.0`, `Llama-3.2-Community`), license URLs, and median host deltas.

### M1.2 Batch Evaluation Harness & Complete Run Metadata
- `research/run_bakeoff.py`:
  - Upgraded to runner version `1.2.0`.
  - Added structured `run_metadata` block recording runner version, execution date, live Ollama version (`0.35.1`), thinking mode setting (`think: False` for reasoning models), cryptographic eval set hashes, and explicit audit list of truncated task IDs (`truncated_tasks`).
  - Scored all 20 document tasks (`doc_01`–`doc_20`), including the 10 discriminating hard questions.
  - Automatic `low_confidence = True` flag when task truncation occurs.
- `docs/evidence/m1_bakeoff_results.json`: Re-evaluated all 5 candidate models with identical harness and isolated subprocess sandboxing:
  - `llama3.2:3b`: 8/20 (40.0%) coding, 11/20 (55.0%) Singlish, 20/20 (100.0%) doc analysis, 2.30s latency, 740.0 MB cold RAM delta. (Truncated on 4 long Singlish prompts).
  - `qwen2.5-coder:1.5b`: 9/20 (45.0%) coding, 4/20 (20.0%) Singlish, 16/20 (80.0%) doc analysis, 1.35s latency, 590.4 MB cold RAM delta. (0 truncations).
  - `qwen3.5:4b`: 8/20 (40.0%) coding, 15/20 (75.0%) Singlish, 20/20 (100.0%) doc analysis, 5.50s latency, 1038.6 MB cold RAM delta. (Truncated on `code_16`).
  - `gemma4:e2b`: 11/20 (55.0%) coding, 17/20 (85.0%) Singlish, 20/20 (100.0%) doc analysis, 4.13s latency, 2934.8 MB cold RAM delta. (Truncated on `code_11`, `code_13`).
  - `qwen2.5-coder:7b`: 12/20 (60.0%) coding, 11/20 (55.0%) Singlish, 19/20 (95.0%) doc analysis, 6.92s latency, 1305.9 MB cold RAM delta. (Truncated on `singlish_01`).

### Tests
- Python: 184 tests pass (5 skipped).
- Rust: 13 unit tests pass. Clippy clean (`-D warnings`).

## [0.5.1] — 2026-10-07 — Milestone M1.1 Hardening & Sandboxed Code Runner

### M1.1 Sandboxing & Safe Code Runner
- `research/safe_code_runner.py`: Implemented isolated subprocess execution for model code evaluation.
  - **Zero in-process exec**: Model code is never executed inside the main Python test process.
  - **Subprocess termination**: Hard timeouts enforced via `proc.kill()`, cleanly terminating infinite loops and preventing background CPU exhaustion.
  - **Scrubbed environment**: Child processes receive only minimal OS system variables (`SYSTEMROOT`, `SystemDrive`, `PATH`, `TEMP`, `TMP`), stripping repository paths, credentials, and API keys.
  - **Network isolation**: Socket creation is intercepted and denied inside the sandbox worker.
  - **Test isolation**: Hidden unit test logic and assertions remain strictly in Process A; the untrusted child process receives only inputs via standard IPC.
- `research/eval_m1.py` and `research/run_bakeoff.py`: Integrated `run_isolated_task_eval` to replace all in-process threads. Added `tests/test_safe_code_runner.py` (6 unit tests).

### M1.1 Thinking Mode Control & Model Re-evaluation
- `research/reasoner.py` (`LocalLLMReasoner`): Added native Ollama `/api/chat` integration with `think: Optional[bool]` parameter and accurate thinking detection inspecting API `thinking`/`reasoning` fields.
- Re-evaluated reasoning models with `think: False`:
  - `qwen3.5:4b`: coding pass@1 jumped from 0% to **50% (10/20)**, Singlish score jumped to **70% (14/20)** (highest among all models), latency dropped from 20.91s to 5.57s.
  - `gemma4:e2b`: coding pass@1 jumped from 0% to **55% (11/20)**, Singlish score rose to **65% (13/20)**, latency dropped from 8.57s to 3.62s.
  - Both confirmed as viable candidates for the adaptive model router.

### M1.1 Eval Set Expansion & Cryptographic Freezing
- `research/eval_sets/doc_analysis_tasks.json`: Added 10 harder discriminating tasks (`doc_11`–`doc_20`) testing multi-document cross-referencing, memory headroom calculation, tier exceptions, and policy layer boundaries.
- `docs/evidence/eval_sets_hashes.json`: SHA-256 hashes of all 4 evaluation sets recorded and frozen.
- `research/model_profiles.json`: Corrected cold-start host RAM deltas for `qwen3.5:4b` (1029.1 MB) and `gemma4:e2b` (2386.0 MB); added `licence_checked_on: "2026-10-07"` to all profiles.

### Reviewer notes (not part of the original entry)
- The runner is best-effort containment for evaluation, not an OS-level boundary (T16 stays open for M2): the `socket.socket` replacement can be bypassed, absolute paths and child processes are not restricted, and there is no memory limit.
- `doc_11`-`doc_20` are frozen but not yet scored in `m1_bakeoff_results.json`; RAM figures differ between the bake-off file and `model_profiles.json`.

### Tests
- Python 184 tests passing (14.8s). Rust 13 unit tests passing. Differential fuzz 10,000 cases passing. Clippy clean.

## [0.5.0] — 2026-10-07 — Rust VS3 (Win32 Native Telemetry) & Milestone M1 Multi-Model Bake-Off

### Rust core (slice VS3) — ADR-009
- `core/src/win32.rs`: Native Win32 hardware telemetry implemented using `windows-sys = "0.52"` (`GlobalMemoryStatusEx`, `GetSystemTimes`, `GetSystemPowerStatus`).
- Unsafe isolation boundary strictly enforced: `#![deny(unsafe_code)]` at crate root (`lib.rs`, `main.rs`); zero `unsafe` allowed outside `win32.rs`, with explicit `// SAFETY:` invariant justification on every call.
- Telemetry parity validated against Python (`tests/test_telemetry_parity.py`): measured difference 0.69% (well within the $\pm 5\%$ threshold required by ADR-009).
- CLI flags `--telemetry` and `--telemetry --json` added to `core/src/main.rs`. CI job updated with unsafe isolation regex gate and telemetry parity check.

### Milestone M1 Bake-Off (Track L / ADR-008)
- Frozen evaluation test suite established:
  - **Set 1 (Coding)**: 20 hand-crafted tasks with timeout-guarded hidden test suites (`research/eval_sets/hidden_tests/`) never exposed to models.
  - **Set 2 (Singlish/Sinhala)**: 10 prompts testing colloquial Sinhala/Singlish code comprehension, debugging, security, and architecture (scored 0–2 against rubric).
  - **Set 3 (Document Analysis)**: 10 grounded questions verifying context utilization on PAI architectural specifications.
- 5 models empirically measured and profiled (`docs/evidence/m1_bakeoff_results.json`):
  - `qwen2.5-coder:7b` (Apache 2.0): 13/20 (65%) pass@1 coding, 11/20 (55%) Singlish, 10/10 (100%) doc analysis, 7.13s latency, 4.9 GB footprint.
  - `qwen2.5-coder:1.5b` (Apache 2.0): 9/20 (45%) pass@1 coding, 5/20 (25%) Singlish, 10/10 (100%) doc analysis, 1.34s latency, 1.1 GB footprint.
  - `llama3.2:3b` (Llama Community License): 7/20 (35%) pass@1 coding, 9/20 (45%) Singlish, 10/10 (100%) doc analysis, 1.96s latency, 2.4 GB footprint.
  - `qwen3.5:4b` & `gemma4:e2b` (Apache 2.0): Discovered that default thinking mode exhausts tier-allocated token caps (1024 tokens), leading to truncation and syntax errors on code output.
- `research/model_profiles.json` updated with full host delta and model footprint measurements.

### Tests
- Python 178 tests passing (13.2s). Rust 13 unit tests passing (0.02s). Differential fuzz 10,000 cases passing (0 mismatches). Clippy clean (`-D warnings`).

### Phase 1 exit evidence
- Windows Sandbox smoke test passed 7/7 (`docs/evidence/sandbox_results.json`, ADR-003); two guest profiles on newer Windows builds added to the allowed list.
- Real local models measured on the owner's laptop (Ollama, 1B and 3B, iGPU offload): `research/model_profiles.json`; RAM-fit check uses the measured host delta + 512 MB headroom, evaluated before load only (hysteresis).
- Signing key generated offline; public key in `research/trust.json`. GitHub remote and Windows CI established.

### Security fixes
- **T14** trust-label injection: provenance is accepted only through a per-task random nonce (`[[SRC:<nonce>:<source>]]`); in-band text headers are ignored.
- Negation handling in the symbolic engine fixed (direct-negation conflicts are now detected and lower the grounding score); grounding status renamed `SYNTACTIC_GROUNDING` because it checks citations, not truth.
- Misleading output strings removed or reworded; unconditional "verified" wording dropped.
- Review found that the first explicit URL blocklist missed IPv6 transition/embedded-IPv4 prefixes (NAT64, 6to4, Teredo, SIIT, IPv4-compatible, site-local) and `192.88.99.0/24`; fixed in `70fd7f6`. Leading-zero ports are rejected. A model-loaded check no longer accepts an empty model name.

### Rust core (slice VS2)
- `core/`: pure `tier.rs` and `url_policy.rs`, `unsafe = 0`, dependencies `serde`/`serde_json` only; fake telemetry removed.
- Conformance: 200 tier + 87 URL golden vectors; differential fuzz (10,000 cases) against Python; CI job `rust-core` (fmt, clippy `-D warnings`, test, conformance, drift check, fuzz).
- `docs/NET_POLICY.md`: single documented outbound policy table shared by Python and Rust.

### Documentation and planning
- New: ADR-008 (local assistant and model strategy, owner decision D6), ADR-009 (Rust toolchain and `unsafe` boundary, proposed), `docs/LOCAL_ASSISTANT_SPEC.md`.
- Candidate models for the first bake-off and an adaptive, explainable model router specified (`LOCAL_ASSISTANT_SPEC.md` §3, ADR-008 amendment, T21); milestones M1/M1b added.
- ROADMAP rewritten for the current state (Phase 1 complete, VS2 done, VS3 next, Track L local assistant, Track M gated own model, risks R8–R12).
- THREAT_MODEL v0.2 (T15–T20); RSI spec gains a model/adapter promotion section; PROJECT_REVIEW gains a status and verification log.

### Tests
- Python 170, Rust 10 (unit) at the time of writing.

## [0.3.1] — 2026-10-06
- Sandbox smoke test: exit code is now truthful (0 only after a real in-sandbox pass), probe strengthened (DNS, adapters, host-path invisibility, foreign profiles, drives), results written without BOM; `read_sandbox_results` also tolerates a UTF-8 BOM (PowerShell 5.1).
- `.gitignore` blocks `*.key` / `*.pem`; CI live-network step is non-blocking.

## [0.3.0] — 2026-10-05 — Strategic risk remediation (R1–R7)

- **R1** `LocalLLMReasoner`: local open-model adapter (loopback-only, fenced context, no tools, tier token caps) — ADR-001.
- **R2** `outbound_policy.py` (allow-list, visible outbound log, offline mode) and `local_knowledge.py` (answer from local files) — ADR-002; CLI `--offline`, `--knowledge-dir`, `--allow-domain`, `--show-outbound`.
- **R3** Claims policy enforced by `tests/test_claims.py`; unfalsifiable phrases removed.
- **R4** Signed-release updater (`ed25519_ref.py`, `updater.py`, `sign_release.py`), `docs/CONSTITUTION.md`, engine-side `trust_root_is_protected()` — ADR-005.
- **R5** `sandbox_policy.py`: Windows Sandbox isolation checklist as code + hostile-output reader — ADR-003.
- **R6** Rust-first language scope, spike criteria, vertical slices (ADR-004); golden conformance vectors (`conformance/`, 200 tier + 28 URL cases); `core/` and `hardware/` charters.
- **R7** `capabilities.py` capability broker with taint tracking and hash-chained audit; `AgentExecutionResult.context_tainted` — ADR-006.
- **Fixed** (found by the new conformance vectors): URL guard accepted multicast / reserved / unspecified addresses (e.g. `224.0.0.1`).
- Tests: 53 → 140. New docs: `docs/adr/`, `docs/CONSTITUTION.md`.

## [0.2.0] — 2026-10-05 — Phase 1 review & hardening

### Security
- **Fixed**: `fetch_url` accepted `file://` URLs (local file read). New `net_guard.py` enforces http/https only, global IPs only, ports 80/443, no URL credentials; re-checked on every redirect.
- **Added**: prompt-injection screening in `DataVerifier` (policy `reject`/`flag`); untrusted-data fencing in the Reasoner contract.
- **Added**: Tier-1 AST guard prototype (`ast_guard.py`) for the RSI safety spec.
- **Fixed**: unbounded `response.read()` on Wikipedia calls; `lang` is now whitelisted before use in a hostname.

### Correctness
- **Fixed**: network errors were fed to the verifier as "knowledge" and reported as "payload too brief". Errors are now typed and reported precisely.
- **Fixed**: the purge was cosmetic (`del` on immutable `str`; `memory_purged_successfully` was always `True`; benchmark printed "zero leakage" unconditionally). Now `SecureBuffer` zeroes and verifies, the purge runs in `finally`, and the benchmark measures retained memory and can fail. <!-- claims-lint: quote -->
- **Fixed**: non-Windows telemetry returned invented 8 GB / 50 % values. Now reads `/proc`, falls back to psutil, then to an explicit "unavailable" + BALANCED.
- **Fixed**: regex HTML stripping replaced by `html.parser`; truncation by bytes; Unicode-aware letter ratio (Sinhala combining marks); compression-ratio spam check.
- **Fixed**: topic extraction (anchored trigger phrase, original casing preserved, Wikipedia search → summary instead of exact-title guess).

### Features
- CPU load and battery telemetry; battery/CPU-aware budget; JSON IPC form (schema v1).
- `--lang` (e.g. Sinhala Wikipedia), `--transport raw` (experimental socket+TLS client), scriptable CLI flags, EOF-safe interactive loop.
- `Reasoner` interface + honest stub.
- 53 unit tests.

### Docs
- Aligned all docs with the code (tier thresholds, timeouts, cycle naming).
- Added `THREAT_MODEL.md`, `PROJECT_REVIEW.md`; ROADMAP gained exit criteria, decision gates (ADRs) and a risk table; ARCHITECTURE gained telemetry schema v1 and a prototype-vs-production table; RSI spec gained implementation status and known weaknesses.

## [0.1.0] — 2026-10-01
- Initial scaffolding, docs and Python prototype.
