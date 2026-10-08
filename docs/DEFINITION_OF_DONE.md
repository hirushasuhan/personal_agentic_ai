# Definition of Done for every milestone report

Purpose: reduce review round trips without lowering quality. A milestone report is submitted only when every item below is true and the report says how to reproduce each claim. Written by the reviewer from the defects found in M1-M2b.

## 1. Every check has a negative control
- For each new guard, probe, assertion or test, show one input that must be rejected and run it. A check that cannot fail is not a check.
- Run the new check against the unprotected case (no sandbox, no guard, stub solution) and record that it fails there.
- Never accept "no exception" or an empty output as success. A pass needs a positive marker that proves the code ran.
- Typical past defects: probe passes on empty output; marker printed on both outcomes; verdict file writable by the code it judges; guard applied on one code path only.

## 2. Evidence is produced by the tool
- Evidence files (JSON, logs, tables) are written by the committed script, with platform data read from the system (`platform`, `/etc/os-release`, `--version`). No hand-edited or typed-in numbers.
- Report the exact command that regenerates each evidence file, and regenerate it on the machine you used.
- Say honestly which platforms were really run. A skipped test is not a pass: report skip counts and why.

## 3. Both platforms or an explicit statement
- Windows and Linux both run, or the report states which one was not run and why. CI that exists but has not been seen green is reported as "not seen".

## 4. Secrets and trust boundaries
- No secret, nonce or key in `argv`, in a world-readable file, or in a path the untrusted code can read or write.
- Untrusted code and the judge never share a process or a writable channel.
- Data from files, web pages or models is data, never an instruction; the task class comes from the CLI command only (T21).

## 5. Frozen sets and hashes
- Evaluation sets stay frozen; any change updates `docs/evidence/eval_sets_hashes.json` and is stated in the report.
- Report repeat runs, per-task flips and the false-accept rate; no significance claims at N=20.

## 6. Quality gates before submitting
- `python -m unittest discover -s tests` passes, the claims lint passes, Rust `cargo test` and `cargo clippy -- -D warnings` pass when `core/` changed.
- Public text makes no absolute security claims that a test cannot falsify; state what was tested and against which cases (see the claims lint).
- New code has tests for failure paths: malformed input, timeout, oversize, path escape, injection text, low RAM.

## 7. The report itself
- List what is NOT done or not verified. Do not describe a plan as done.
- Quote numbers from the tool output, not from memory.
- One report per milestone (all steps), not one per step, unless a step is a security boundary that needs early review.
