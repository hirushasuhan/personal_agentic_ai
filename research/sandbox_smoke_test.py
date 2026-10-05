"""
Windows Sandbox smoke test (ADR-003 gate).

The gate is PASSED only when a probe running INSIDE a generated sandbox writes a results.json that
`read_sandbox_results()` accepts with tests_failed == 0. Generating the .wsb alone proves nothing, so:

  python sandbox_smoke_test.py                  # generate + validate the .wsb, print instructions  -> exit 2 (gate NOT proven)
  python sandbox_smoke_test.py --launch --wait 180   # also start Windows Sandbox and wait for results -> exit 0 only on a real pass

Probe (native PowerShell, nothing to install in the guest) checks: no usable network (TCP, DNS, adapters),
the host's staging path is invisible, the input mapping is read-only, only expected folders are mapped.
Close the sandbox window when finished: it is disposable and everything inside is discarded.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

from sandbox_policy import SandboxSpec, make_wsb, read_sandbox_results, validate_wsb

SANDBOX_EXE = r"C:\Windows\System32\WindowsSandbox.exe"

PROBE_PS1 = r'''# Windows Sandbox probe (runs inside the guest)
$ErrorActionPreference = "Continue"
$script:passed = 0; $script:failed = 0; $script:logs = @()
function Record-Test($name, $ok, $detail) {
    if ($ok) { $script:passed++; $script:logs += "[PASS] ${name}: $detail" }
    else     { $script:failed++; $script:logs += "[FAIL] ${name}: $detail" }
}

# 1. TCP to the internet must not connect
try {
    $c = New-Object System.Net.Sockets.TcpClient
    $iar = $c.BeginConnect("8.8.8.8", 53, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $c.Connected) { Record-Test "network_tcp" $false "connected to 8.8.8.8:53" }
    else { Record-Test "network_tcp" $true "no connection (timed out / refused)" }
    $c.Close()
} catch { Record-Test "network_tcp" $true "unreachable ($($_.Exception.Message))" }

# 2. DNS must fail
try {
    $a = [System.Net.Dns]::GetHostAddresses("example.com")
    Record-Test "network_dns" $false "resolved example.com to $($a[0])"
} catch { Record-Test "network_dns" $true "DNS resolution failed as expected" }

# 3. No network adapter may be up
try {
    $up = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" })
    Record-Test "no_adapter_up" ($up.Count -eq 0) "adapters up: $($up.Count)"
} catch { Record-Test "no_adapter_up" $true "no adapters present ($($_.Exception.Message))" }

# 4. The host's staging directory must not be reachable by its host path
$hostPath = "__HOST_WORK_DIR__"
Record-Test "host_path_invisible" (-not (Test-Path -LiteralPath $hostPath)) "host path $hostPath reachable=$(Test-Path -LiteralPath $hostPath)"

# 5. Host user profile folders other than the sandbox's own must not exist
$others = @(Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users", "WDAGUtilityAccount") })
Record-Test "no_foreign_profiles" ($others.Count -eq 0) "unexpected profile folders: $($others.Name -join ',')"

# 6. Input mapping must be read-only
try {
    Set-Content -Path "C:\pai\input\forbidden.tmp" -Value "x" -ErrorAction Stop
    Record-Test "input_read_only" $false "write to read-only input succeeded"
} catch { Record-Test "input_read_only" $true "write blocked" }

# 7. Only expected file-system drives
$drives = @(Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name)
Record-Test "only_expected_drives" (($drives | Where-Object { $_ -ne "C" }).Count -eq 0) "drives: $($drives -join ',')"

$results = [ordered]@{ tests_passed = $script:passed; tests_failed = $script:failed; benchmark_ms = 1.0; stdout_tail = ($script:logs -join "`n") }
$json = $results | ConvertTo-Json -Compress
New-Item -ItemType Directory -Path C:\pai\output -Force | Out-Null
[System.IO.File]::WriteAllText("C:\pai\output\results.json", $json, (New-Object System.Text.UTF8Encoding($false)))  # no BOM
Write-Output ($script:logs -join "`n")
'''

EXPECTED_MIN_TESTS = 7


def stage(work_dir: str):
    input_dir, output_dir = os.path.join(work_dir, "input"), os.path.join(work_dir, "output")
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir, ignore_errors=True)
    os.makedirs(input_dir)
    os.makedirs(output_dir)
    with open(os.path.join(input_dir, "probe.ps1"), "w", encoding="utf-8") as f:
        f.write(PROBE_PS1.replace("__HOST_WORK_DIR__", work_dir.replace("'", "''")))
    spec = SandboxSpec(input_dir, output_dir,
                       r"powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\pai\input\probe.ps1")
    xml = make_wsb(spec)
    wsb = os.path.join(work_dir, "pai_isolated_test.wsb")
    with open(wsb, "w", encoding="utf-8") as f:
        f.write(xml)
    return wsb, output_dir, validate_wsb(xml)


def evaluate(output_dir: str) -> bool:
    res = read_sandbox_results(output_dir)
    print(res["stdout_tail"])
    ok = res["tests_failed"] == 0 and res["tests_passed"] >= EXPECTED_MIN_TESTS
    print(f"\npassed={res['tests_passed']} failed={res['tests_failed']}  ->  {'GATE PASSED' if ok else 'GATE FAILED'}")
    return ok


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work-dir", default=os.path.join(os.environ.get("TEMP", "/tmp"), "pai_sandbox_smoke"))
    ap.add_argument("--launch", action="store_true", help="start Windows Sandbox with the generated config")
    ap.add_argument("--wait", type=int, default=0, metavar="SECONDS", help="wait for results.json and evaluate it")
    ap.add_argument("--evaluate-only", action="store_true", help="evaluate an existing output folder (after a manual run)")
    a = ap.parse_args(argv)

    if a.evaluate_only:
        return 0 if evaluate(os.path.join(a.work_dir, "output")) else 1

    wsb, out, violations = stage(a.work_dir)
    print(f".wsb validation: {'PASS' if not violations else 'FAIL ' + str(violations)}\nconfig: {wsb}")
    if violations:
        return 1
    if not os.path.exists(SANDBOX_EXE):
        print("Windows Sandbox is not installed/enabled (Windows Features -> Windows Sandbox, then restart). Gate NOT proven.")
        return 2
    if a.launch:
        subprocess.Popen([SANDBOX_EXE, wsb])
        print("Sandbox launching... (close its window when done)")
    else:
        print(f"Double-click {wsb}, wait for the probe to finish, then run:  python sandbox_smoke_test.py --evaluate-only")
    if a.wait:
        deadline = time.time() + a.wait
        path = os.path.join(out, "results.json")
        while time.time() < deadline and not os.path.exists(path):
            time.sleep(2)
        if not os.path.exists(path):
            print("timed out waiting for results.json. Gate NOT proven.")
            return 2
        time.sleep(1)
        return 0 if evaluate(out) else 1
    print("Gate NOT proven yet: no results were evaluated.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
