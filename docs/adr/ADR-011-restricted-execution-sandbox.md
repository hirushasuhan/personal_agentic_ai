# ADR-011 — Restricted Execution Sandbox & Verify Loop Architecture for Generated Code (v2.1)

**Status:** Proposed (Conditional sign-off for M2a sandbox runner; v2.1 amendments incorporated) · **Owner decision D8 (pending M2a acceptance)** · **Date:** 2026-10-08

## Context
Milestone M2 introduces the automated coding workflow: `pai code "<task>" --out <dir>`. In this workflow, local language models (`qwen2.5-coder:7b`, `qwen2.5-coder:1.5b`) synthesize implementation code and unit tests, followed by execution in a verify-and-repair loop.

Executing model-generated code on the user's workstation is an active execution hazard (Threat T16). Untrusted code may contain accidental bugs (infinite loops, memory leaks, fork bombs) or hostile operations (reading credentials, modifying host files, exfiltrating data over sockets, spawning child subprocesses, loading C libraries).

Following reviewer analysis of design v2, the owner granted **conditional sign-off for M2a only** (the sandbox runner, capability probe, and adversarial test matrix), requiring the following v2.1 amendments prior to full acceptance:
1. **Behavioural Capability Probe**: Static API checks are insufficient. The runner must execute a live behavioural canary self-test inside the candidate sandbox on every start (testing network refusal, file isolation, and process spawn refusal).
2. **Interpreter Access without Permanent ACL Alteration**: AppContainers cannot read per-user Python installations (`%LOCALAPPDATA%\Programs\Python`), and Linux `--tmpfs /home` hides pyenv/venv interpreters. The design must provide readable interpreter and stdlib access without permanent system ACL drift.
3. **Verify Loop Result Integrity**: When solution and model-written tests run in the same process, a solution could call `sys.exit(0)` / `os._exit(0)` at import or forge stdout. The runner must use a separate authenticated result channel and assert executed test count.
4. **False-Accept Quality Measurement**: Frozen tests can contain wrong expected values from small models. Measure the false-accept rate alongside `pass@1_repair3`.
5. **Tier-2 OS Precision**: Windows Job Object CPU-time limits; `ACTIVE_PROCESS = 1` via `sys._base_executable`; rename `--sandbox winsandbox`; Linux `bwrap` flags (`--proc`, `--dev`, `--new-session`, `--clearenv`, `--unshare-ipc`, `--cap-drop ALL`, symlink handling).
6. **AST Deny-List Usability**: Relax memory streams (`io`) and file helpers; evaluate against at least 50 tasks (CSV, file, string). Credit Tier-2 for ctypes and subprocess containment.
7. **Process & Ctypes Policy**: Use `# SAFETY:` in Python. Record explicit ctypes policy exception for `sandbox_win32.py` with an enforcement test. Consequence wording must state requirements, not unverified claims.

## Decisions

### 1. Phased Execution: M2a (Runner Spike) then M2b (Verify Loop)
1. **Milestone M2a**: Implementation and validation of the OS-level sandbox boundary:
   - Behavioural capability probe.
   - Windows runner: AppContainer + Job Object.
   - Linux runner: Bubblewrap / Landlock + POSIX limits.
   - Full A1–A11 adversarial matrix passing with live test logs on both Windows and Linux (WSL2 Ubuntu).
   - Milestone M1c second-machine empirical calibration evidence produced concurrently via WSL2.
2. **Milestone M2b**: Verification loop, test freezing, AST guard, bounded repair state machine, safe staging, and `pai code` CLI integration.

### 2. Behavioural Capability Probe & Fail-Closed Rule
On every runner initialization, PAI conducts a **live behavioural canary self-test** inside a temporary sandbox instance:
1. **Network Probe**: Parent opens a loopback TCP listener on a dynamic ephemeral port. Child process attempts `socket.connect()`. It **must fail** with access denied or network unreachable.
2. **Filesystem Read Probe**: Parent creates a temporary canary file outside the scratch area. Child attempts `open(canary, "r")`. It **must fail** with `PermissionError` or `FileNotFoundError`.
3. **Filesystem Write/Delete Probe**: Child attempts `open(canary, "w")` or `os.remove(canary)`. It **must fail** with `PermissionError`.
4. **Process Spawn Probe**: Child attempts to spawn a subprocess or fork. It **must fail** with access denied or `BlockingIOError`.
5. **Fail-Closed Gate**: If **any** canary check succeeds (meaning containment failed), PAI immediately aborts and refuses execution (**Exit Code 5**):
   ```
   Execution refused: OS sandbox capability probe failed. Boundary is not airtight.
   PAI will not execute model code without verified OS containment.
   ```
   PAI **never** falls back to an unisolated runner.

### 3. Platform Sandbox Boundaries (Tier 2)

#### Windows Host (AppContainer + Job Object default)
1. **AppContainer Isolation**:
   - Child runs under an AppContainer profile with **zero capabilities** (no `internetClient`, no `privateNetworkClientServer`). Sockets blocked at kernel network layer.
   - Filesystem ACLs: AppContainer has zero access to user directories (`C:\Users\...`, `.ssh`, Documents, Desktop).
   - **Interpreter Access**: To allow `python.exe` to run when installed per-user (e.g. `AppData\Local\Programs\Python`), the runner applies a temporary read-only `ACCESS_ALLOWED_ACE` (`GENERIC_READ | GENERIC_EXECUTE`) for the ephemeral AppContainer SID to `sys.base_prefix`. This ACE is strictly removed in a `finally:` cleanup block upon child exit, leaving no permanent system ACL changes.
2. **Windows Job Objects (`JOBOBJECT_EXTENDED_LIMIT_INFORMATION` & `JOBOBJECT_BASIC_LIMIT_INFORMATION`)**:
   - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: Unconditionally terminates all child processes on parent close/exit.
   - `JOB_OBJECT_LIMIT_PROCESS_MEMORY` & `JOB_OBJECT_LIMIT_JOB_MEMORY`: 512 MB ceiling.
   - `PerProcessUserTimeLimit`: Job Object CPU-time limit set to 10 seconds.
   - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`: Set to **1** by directly invoking the base Python binary (`sys._base_executable`), bypassing venv trampoline launchers.
   - `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`: Suppresses WER crash dialogs.
3. **Optional Mode (`--sandbox winsandbox`)**:
   - Windows Sandbox hypervisor VM (ADR-003) is retained as an optional stronger mode for Pro/Enterprise users.

#### Linux Host (Bubblewrap / Landlock + POSIX Limits)
1. **Bubblewrap (`bwrap`) Execution**:
   ```bash
   bwrap --ro-bind /usr /usr \
         --ro-bind /lib /lib \
         --ro-bind /lib64 /lib64 \
         --ro-bind /etc /etc \
         --ro-bind <python_base_prefix> <python_base_prefix> \
         --proc /proc \
         --dev /dev \
         --new-session \
         --clearenv \
         --unshare-ipc \
         --cap-drop ALL \
         --unshare-net \
         --unshare-pid \
         --die-with-parent \
         --tmpfs /home \
         --tmpfs /tmp \
         --bind <scratch_dir> <scratch_dir> \
         python3 -I -B -s -S test_solution.py
   ```
   - Interpreter access: `--ro-bind <python_base_prefix> <python_base_prefix>` explicitly grants read access to pyenv/venv interpreters even when `/home` is masked with tmpfs.
   - Mount order: `<scratch_dir>` is bound after `/tmp` tmpfs so it is never shadowed.
   - `--new-session`: Prevents terminal keystroke injection attacks (`TIOCSTI`).
   - Handles `/lib` and `/lib64` symlinks gracefully.
2. **Landlock LSM Fallback**:
   - Ruleset restricting path access to `<scratch_dir>` and system libraries.
   - Note on limitations: Landlock does not control UDP; if unprivileged netns fails on Ubuntu 24.04, the behavioural capability probe will detect network leakage and fail closed (Exit 5).
3. **POSIX Limits**:
   - `RLIMIT_AS`: 512 MB.
   - `RLIMIT_CPU`: 5 seconds CPU time.
   - `RLIMIT_NPROC`: 1 (when non-root).
   - `RLIMIT_FSIZE`: 1 MB file write cap.

### 4. Verify Loop Result Integrity (M2b)
1. **Independent Result Channel**:
   - Model-written tests run in the same child process as `solution.py`.
   - The runner **does not trust** child exit codes or unauthenticated stdout (preventing forged outputs or `os._exit(0)` bypasses).
   - The test harness writes a structured result file to the scratch directory containing:
     - Nonce generated by parent.
     - Number of executed test cases.
     - Assertion outcomes.
   - Parent validates: result file exists, matches nonce, and `executed_count == frozen_test_count`. Exit without a verified result file is treated as a test failure.
2. **Residual Limit**: A deliberately malicious solution running in the same process as its tests could theoretically monkey-patch test functions in memory. Full isolation between solution and tests is achieved in benchmark grading where tests run in an independent process.

### 5. Test Quality & False-Accept Rate (M2b)
1. **Frozen Tests & Regeneration**:
   - Model tests are frozen after generation to prevent weakening assertions during repair.
   - Allows a single logged test-regeneration step if tests fail the stub probe or if repair fails, under the condition that assertion count cannot decrease.
2. **Stub Probe**:
   - Stub must define every symbol (function, class) referenced by the tests:
     ```python
     def stub_func(*a, **k): raise NotImplementedError("Stub probe")
     ```
   - Must fail against the stub to prove assertions are non-trivial.
3. **False-Accept Quality Metric**:
   - Measures how often a solution passing model-written tests also passes hidden tests:
     $$\text{False-Accept Rate} = \frac{\text{Passed model tests but FAILED hidden tests}}{\text{Total passing model tests}}$$
   - Reported alongside `pass@1_repair3`.

### 6. AST Guard Usability (M2b)
1. **Relaxed Deny-List**:
   - In-memory data structures and streams (`io.StringIO`, `io.BytesIO`) are permitted.
   - Math, string, and CSV manipulation modules (`csv`, `math`, `re`, `json`) are permitted.
   - Dangerous modules remain blocked: `ctypes`, `subprocess`, `socket`, `ssl`, `asyncio`, `multiprocessing`, `threading`, `shutil`, `importlib`, `pickle`, `marshal`.
2. **Evaluation Gate**:
   - Must demonstrate 0% false positives across $\ge 50$ compliant coding tasks (including text, CSV, and memory streams).
3. **Containment Attribution**:
   - In the adversarial matrix, Tier-2 (AppContainer / bwrap / Job Object) is credited as the primary containment layer for process, network, and file operations (A4–A8). Tier-1 is an early heuristic.

### 7. Ctypes Policy & Process Rules
1. **Python `# SAFETY:` Comment Standard**:
   - In accordance with Python conventions, safety comments in Python code must use `# SAFETY:` (not `// SAFETY:`).
2. **Ctypes Policy Exception**:
   - ADR-009 strictly limits `unsafe` in Rust to `win32.rs`.
   - For Python: an explicit policy exception is approved for `research/sandbox_win32.py`.
   - Enforced by a repository test (`research/tests/test_ctypes_allowlist.py`) asserting that `import ctypes` is restricted exclusively to allow-listed modules:
     - `hardware_telemetry.py`
     - `memory_probe.py`
     - `secure_buffer.py`
     - `sandbox_win32.py`

## Consequences & Residual Risks
- **Containment Statement**: All listed vectors **must be contained; acceptance requires passing tests on both Windows and Linux**.
- Residual risks:
  - Windows: AppContainer prevents network and user file access; Job Object constrains CPU/RAM/processes. Residual: Windows kernel vulnerabilities.
  - Linux: Bubblewrap isolates filesystem and network; rlimits constrain RAM/CPU. Residual: In root containers without bubblewrap, PID limits are not enforced by `RLIMIT_NPROC`.
  - In-Process Solution Tampering: In verify loop mode, model solution runs in the same process as model tests; mitigated by separate result channels, but full address-space separation applies in final benchmark grading.
- Claims policy (`docs/THREAT_MODEL.md` §5) strictly enforced: no unfalsifiable claims.

## If Reversed
Revert to M1.1 runner with explicit user disclaimer that code execution lacks OS boundary containment.
