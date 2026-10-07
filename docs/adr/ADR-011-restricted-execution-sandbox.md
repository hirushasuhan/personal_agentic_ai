# ADR-011 — Restricted Execution Sandbox & Verify Loop Architecture for Generated Code (v2)

**Status:** Proposed (Milestone M2 requirement, revised per reviewer findings) · **Owner decision D8 (pending confirmation)** · **Date:** 2026-10-08

## Context
Milestone M2 introduces the automated coding workflow: `pai code "<task>" --out <dir>`. In this workflow, local language models (`qwen2.5-coder:7b`, `qwen2.5-coder:1.5b`) synthesize implementation code along with companion unit tests, followed by execution in a verify-and-repair loop (generate -> static inspect -> execute tests -> repair on failure -> write to disk).

Executing model-generated code on the user's workstation is an active execution hazard (Threat T16). Untrusted code may contain unintentional defects (infinite loops, memory exhaustion, fork bombs) or hostile operations (reading SSH keys/user documents, modifying files, exfiltrating data over sockets, spawning child subprocesses, loading C libraries).

Reviewer analysis of the initial design draft (v1) revealed critical gaps:
1. **Windows Security Gap**: A Windows Job Object constrains CPU, memory, and lifetime, and a Low Integrity token blocks writing to higher integrity objects. However, neither blocks network sockets, and Low Integrity does not block reading normal user files (documents, repository source, browser profiles, credentials). The v1 matrix credited AST guard for read/network isolation, which is static and bypassable.
2. **Linux Security Gap**: A network namespace and `setrlimit` do not isolate the filesystem (`os.remove()` and reading `$HOME` were unchecked). Additionally, unprivileged `unshare(CLONE_NEWNET)` fails on modern kernels with AppArmor user-namespace restrictions (e.g. Ubuntu 24.04), and `RLIMIT_NPROC` is ignored for root users in containers.
3. **Fail-Closed Rule Missing**: The runner lacked a mandatory capability probe; failure to construct the sandbox could lead to silent fallback to the unisolated M1.1 runner.
4. **AST Deny-List Gaps**: 15 critical modules were omitted, while blanket bans on `getattr` or `/` in string literals caused false positives on legitimate code.
5. **Self-Grading Vulnerability**: The model was allowed to return "revised solution and tests" during repair, enabling it to weaken tests to pass vacuously.
6. **Evaluation Leakage**: Feeding hidden benchmark test errors back to the model constitutes test-set leakage; terminology ("pass@3 with repair") was misleading; noise across 20 tasks prevents claims of "statistical significance".
7. **Staging Race**: Check-then-replace allowed TOCTOU overwriting; symlinks in `--out` were unchecked.
8. **Implementation Location**: Decision needed on where OS sandbox code lives under ADR-009 constraints.

## Decisions

### 1. Multi-Tier Defense-in-Depth Architecture
Generated code passes through four sequential gates:
```
AI Output ──► [Tier 1: AST Guard] ──► [Tier 2: OS Restricted Sandbox] ──► [Tier 3: Test Grader] ──► [Safe Staging]
```
Tier 1 provides fast static filtering. Tier 2 provides kernel-enforced execution containment. Tier 3 provides immutable grading. Safe Staging ensures race-free non-overwriting disk writes.

### 2. Platform-Specific OS Containment Boundaries (Tier 2)

#### Windows Host Boundary (AppContainer + Job Object)
To guarantee portability across all Windows editions (including Windows 10/11 Home) without requiring Hyper-V or Pro/Enterprise editions:
1. **AppContainer Isolation**:
   - The child process is launched inside an **AppContainer profile** with **zero capabilities** (omitting `internetClient` and `privateNetworkClientServer`).
   - Network isolation: Blocked at the Windows TCP/IP driver layer. Any attempt to open or bind a socket fails with `WSAEACCES` / `PermissionError`.
   - Filesystem read/write isolation: An AppContainer with default ACLs cannot read or write user home directories, Documents, Desktop, `.ssh`, or registry hives. Read/write access is explicitly granted **only** to the dedicated ephemeral scratch directory (`tempfile.TemporaryDirectory()`).
2. **Windows Job Objects (`CreateJobObjectW`, `SetInformationJobObject`)**:
   - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: Kernel unconditionally kills the child process tree if parent exits.
   - `JOB_OBJECT_LIMIT_PROCESS_MEMORY` & `JOB_OBJECT_LIMIT_JOB_MEMORY`: 512 MB hard ceiling (memory bombs raise `MemoryError`).
   - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`: Set to **2** to accommodate base Python executable launches while preventing fork bombs or process proliferation.
   - `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`: Suppresses interactive Windows Error Reporting dialogs on crashes or segfaults.
3. **Optional Mode (Windows Sandbox / ADR-003)**:
   - For Pro/Enterprise users who want hypervisor isolation, Windows Sandbox remains available as an optional flag (`--sandbox hyperv`), but is **not** the default.

#### Linux Host Boundary (Bubblewrap / Landlock + POSIX Limits)
1. **Filesystem & Network Isolation**:
   - **Primary (Bubblewrap `bwrap`)**: If `bwrap` is installed, spawns worker with:
     `bwrap --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 --ro-bind /etc /etc --tmpfs /home --tmpfs /tmp --bind <scratch_dir> <scratch_dir> --unshare-net --unshare-pid ...`
     Hides `/home` under empty tmpfs, binds root read-only, grants write only to `<scratch_dir>`, and unshares network and PID namespaces.
   - **Kernel LSM Fallback (Landlock + namespaces)**: If `bwrap` is absent, uses Linux Landlock LSM (`PR_SET_NO_NEW_PRIVS` + ruleset) restricting filesystem operations to `<scratch_dir>` and system libraries, combined with unprivileged network namespace unshare.
2. **POSIX Resource Limits (`setrlimit` / `prlimit`)**:
   - `RLIMIT_AS`: 512 MB virtual address space.
   - `RLIMIT_CPU`: 5 seconds CPU time.
   - `RLIMIT_NPROC`: Set to 1 (when non-root) to block fork bombs.
   - `RLIMIT_FSIZE`: 1 MB file write cap.
   - `RLIMIT_NOFILE`: 32 open file descriptor cap.

#### Mandatory Capability Probe & Fail-Closed Rule
At runner initialization, PAI probes whether the platform boundary can be established:
- Windows: Verifies Win32 Job Object and AppContainer APIs are functional.
- Linux: Verifies `bwrap` executable or Landlock syscall availability + network isolation.
- **Fail-Closed Guarantee**: If the OS boundary cannot be created, PAI **refuses to execute (Exit Code 5)** with an explicit message: *"Execution refused: OS sandbox boundary cannot be established on this system. PAI will not execute model code without OS containment."*
- **No Silent Fallback**: The runner will **never** silently fall back to the unisolated M1.1 runner.

### 3. Tier-1 Static AST Guard Refinement
1. **Deny-List Modules (36 modules)**:
   `os`, `sys`, `pathlib`, `io`, `tempfile`, `glob`, `shutil`, `pickle`, `marshal`, `shelve`, `dbm`, `sqlite3`, `ctypes`, `subprocess`, `socket`, `ssl`, `asyncio`, `http`, `urllib`, `requests`, `ftplib`, `smtplib`, `poplib`, `imaplib`, `multiprocessing`, `threading`, `_thread`, `concurrent`, `pty`, `builtins`, `importlib`, `pkgutil`, `runpy`, `code`, `codeop`, `compileall`, `winreg`, `msvcrt`, `fcntl`, `posix`, `resource`, `signal`.
2. **Dynamic Execution Builtins**:
   Rejects calls to `eval`, `exec`, `compile`, `__import__`, `breakpoint`, `globals`, `locals`.
3. **Nuanced Attribute & Path Rules (Avoiding False Positives)**:
   - Does NOT ban `getattr` unconditionally. Bans `getattr` only if accessing private dunder attributes (`__subclasses__`, `__globals__`, `__code__`, `__builtins__`).
   - Does NOT ban `/` in general string literals. Path screening inspects arguments to filesystem functions (`open()`), rejecting strings starting with `/`, drive letters (`C:\`), UNC prefixes (`\\`), or containing `..`.
4. **False-Positive Gate**:
   AST guard must achieve zero false positives on the 20 compliant outputs from the frozen `coding_tasks.json`.
5. **Architectural Credit**:
   AST Guard is credited as a pre-execution heuristic only. Containment credit in the test matrix is assigned strictly to Tier-2 OS primitives.

### 4. Self-Grading Prevention & Test Integrity
1. **Test Freezing**:
   - Initial unit tests generated by the model are **frozen**.
   - The bounded repair loop prompts the model to revise **only `solution.py`**. The test suite is immutable during repair, preventing the model from deleting failing assertions or weakening checks.
2. **Vacuous Pass Check (Trivial Stub Probe)**:
   - Before running tests against the solution, the runner executes the test suite against a trivial dummy stub (`def func(*a, **k): raise NotImplementedError`).
   - If the test suite passes against the dummy stub, it is rejected as vacuous/trivial, triggering a prompt to generate meaningful assertions.
3. **User-Supplied Golden Tests (`--tests <file>`)**:
   - CLI accepts `--tests <file.py>`. When provided, user golden tests are immutable and override/supplement model-generated tests.
4. **Accurate Outcome Labeling**:
   - Success is reported as *"passes model-generated tests"* (or *"passes user-supplied tests"*), never claimed as "proven correct".

### 5. Evaluation Protocol Rigor
1. **No Test Set Leakage**:
   - During the verify loop, repair feedback is extracted exclusively from model-written tests (or `--tests`).
   - Hidden benchmark tests (`research/eval_sets/hidden_tests/test_coding_tasks.py`, SHA-256 `63e1e839...`) are run **only** during final evaluation. Hidden test failures are **never** provided to the repair prompt.
2. **Standardized Metric Naming**:
   - Measured metric is officially named **"pass@1 after $\le 3$ repairs"** (abbreviated `pass@1_repair3`), compared against **"pass@1 zero-shot"**.
3. **Noise and Variance Reporting**:
   - Evaluated on the frozen 20 tasks in `research/eval_sets/coding_tasks.json` (SHA-256 `df026a8b...`).
   - Claims of "statistical significance" are prohibited due to $N=20$ task sample size. Evaluation requires 5 repeated runs with recorded seeds, reporting median pass rate, min-max range, and per-task flip tables.

### 6. Safe Staging & Non-Overwrite Contract
1. **Race-Free Exclusive Creation**:
   - Without `--overwrite`: writes new files using `os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)`. If a file already exists or is created concurrently, fails instantly with `FileExistsError` without overwriting.
   - With `--overwrite`: writes to `.<name>.tmp.<uuid>`, flushes, calls `os.fsync()`, and replaces via `os.replace()`.
2. **Fixed File Names**:
   - Target files are strictly `<out_dir>/solution.py` and `<out_dir>/test_solution.py`. File names are never selected by the model.
3. **Symlink Rejection**:
   - If `--out <dir>` contains or traverses symlinks, PAI aborts fail-closed.

### 7. Resource Caps & Admission Budget
1. **Router Admission Budget**:
   - `pai code` router admission requires: `available_ram_mb >= model_required_ram + sandbox_budget (512 MB)`.
2. **Truncation Handling**:
   - Tier token caps (128 / 512 / 1024) that produce a `[TRUNCATED]` or incomplete code block are treated as failed attempts.
3. **Hard Flag Limits**:
   - `--timeout`: default 10.0s, hard upper cap 30.0s.
   - `--memory-mb`: default 512.0 MB, hard upper cap 2048.0 MB.

### 8. Implementation Code Location Decision
- Per ADR-009, native Rust `unsafe` is strictly confined to `win32.rs`.
- The Windows AppContainer and Job Object implementation will be implemented in a dedicated, audited Python module (`research/sandbox_win32.py`) utilizing `ctypes` with explicit `// SAFETY:` rationale comments for each Win32 API binding, subjected to automated adversarial unit testing.
- Linux containment will reside in `research/sandbox_linux.py`.
- Porting to Rust native binaries is deferred to Phase 3.

## Consequences & Residual Risks
- All listed vectors are contained in tests on each supported platform, with residual risks listed:
  - Windows: AppContainer prevents network and user file access; Job Object constrains CPU/RAM/processes. Residual: Windows kernel vulnerabilities.
  - Linux: Bubblewrap/Landlock isolates filesystem and network; rlimit constrains RAM/CPU. Residual: Root in container without bubblewrap may have incomplete PID isolation.
- Full VM boundary (Windows Sandbox / ADR-003) is retained as an optional Tier-4 defense.
- Absolute claims remain prohibited per `docs/THREAT_MODEL.md` §5.

## Alternatives Considered
- *In-process exec with restricted globals*: Rejected (easily bypassed).
- *Python monkey-patching alone*: Rejected (bypassed via ctypes/reload).
- *Windows Sandbox as default*: Rejected (requires Pro/Enterprise, 10s VM boot latency).
- *Docker container dependency*: Rejected (requires Docker daemon, breaks local zero-dependency model).

## If Reversed
Revert to M1.1 runner with explicit user-facing disclaimer that code execution carries host execution risks.
