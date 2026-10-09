"""
Personal Agentic AI (PAI) - Unified Command Line Interface
Milestone M1c / ADR-010: Portability, Hardware Calibration, Model Catalog, and Router CLI.

Subcommands:
  pai doctor                 - System diagnostics (OS, RAM, CPU, GPU/iGPU, battery, Ollama probe, candidate fit)
  pai calibrate [--model]    - Empirical 5-run cold RAM & latency calibration per MEASUREMENT_PROCEDURE.md
  pai models list            - Candidate models catalog, license status, calibration, and live fit
  pai route <command>        - Adaptive Model Router CLI (--explain-route, --json)

Security & Architecture Invariants:
1. Threat T21: Command names strictly determine task classes.
2. Threat T22: No secrets in configuration.
3. Threat T26: Machine profiles strictly validated against live hardware.
4. Loopback enforcement: Model server queries strictly bound to local loopback (127.0.0.1, localhost, ::1).
5. Deferred commands: Execution subcommands (generate, analyze, forecast) deferred to M2+.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (
    get_default_config_dir,
    get_machine_profile_path,
    get_user_config_path,
    load_machine_profile,
    load_user_config,
    save_machine_profile,
    validate_machine_profile,
)
from hardware_telemetry import HardwareTelemetry
from router import ModelRouter


# -----------------------------------------------------------------------------
# Cross-Platform Hardware Diagnostics
# -----------------------------------------------------------------------------
def probe_gpu() -> str:
    """Probes host GPU / iGPU across Windows, Linux, and macOS without blocking."""
    # 1. Check nvidia-smi if installed
    try:
        res = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=1.5,
        )
        if res.returncode == 0 and res.stdout.strip():
            return "; ".join([line.strip() for line in res.stdout.splitlines() if line.strip()])
    except Exception:
        pass

    # 2. Windows: query CIM / WMI
    if sys.platform == "win32":
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.5)
            if res.returncode == 0 and res.stdout.strip():
                gpus = [line.strip() for line in res.stdout.splitlines() if line.strip()]
                if gpus:
                    return ", ".join(gpus)
        except Exception:
            pass

    # 3. Linux: lspci or DRM
    elif sys.platform.startswith("linux"):
        try:
            res = subprocess.run(["lspci"], capture_output=True, text=True, timeout=1.5)
            if res.returncode == 0 and res.stdout.strip():
                gpus = [line.split(":")[-1].strip() for line in res.stdout.splitlines() if any(k in line for k in ("VGA", "3D", "Display"))]
                if gpus:
                    return "; ".join(gpus)
        except Exception:
            pass

    # 4. macOS: system_profiler
    elif sys.platform == "darwin":
        try:
            res = subprocess.run(["system_profiler", "SPDisplaysDataType"], capture_output=True, text=True, timeout=2.5)
            if res.returncode == 0 and res.stdout.strip():
                models = [line.split(":", 1)[1].strip() for line in res.stdout.splitlines() if "Chipset Model:" in line]
                if models:
                    return ", ".join(models)
        except Exception:
            pass

    return "Integrated / Standard Display (No discrete GPU probed)"


def probe_ollama_server(base_url: str = "http://127.0.0.1:11434") -> Dict[str, Any]:
    """Probes local Ollama model server on loopback."""
    parts = urllib.parse.urlsplit(base_url)
    hostname = (parts.hostname or "").lower()
    if hostname not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        raise ValueError(f"Ollama server probe must be local loopback, got '{base_url}'")

    out: Dict[str, Any] = {
        "reachable": False,
        "endpoint": base_url,
        "version": None,
        "resident_models": [],
    }

    try:
        # Check version
        v_req = urllib.request.Request(f"{base_url}/api/version")
        with urllib.request.urlopen(v_req, timeout=1.0) as resp:
            data = json.loads(resp.read().decode())
            out["version"] = data.get("version")
            out["reachable"] = True
    except Exception:
        return out

    try:
        # Check resident models (/api/ps)
        ps_req = urllib.request.Request(f"{base_url}/api/ps")
        with urllib.request.urlopen(ps_req, timeout=1.0) as resp:
            data = json.loads(resp.read().decode())
            for m in data.get("models", []):
                size_mb = round(m.get("size", 0) / (1024 * 1024), 1)
                vram_mb = round(m.get("size_vram", 0) / (1024 * 1024), 1)
                out["resident_models"].append({
                    "name": m.get("name"),
                    "size_mb": size_mb,
                    "vram_mb": vram_mb,
                })
    except Exception:
        pass

    return out


# -----------------------------------------------------------------------------
# Subcommand: doctor
# -----------------------------------------------------------------------------
def cmd_doctor(args: argparse.Namespace) -> int:
    """Runs comprehensive system diagnostics and candidate eligibility check."""
    telem = HardwareTelemetry()
    snap = telem.get_system_snapshot()
    gpu_desc = probe_gpu()
    ollama_status = probe_ollama_server()

    # Router & Profile diagnostics
    router = ModelRouter(load_system_profile=True)
    prof_path = get_machine_profile_path()
    has_profile = os.path.exists(prof_path) and router.machine_profile is not None

    avail_ram = snap.get("avail_ram_mb", 0.0) or 0.0

    # Build candidate eligibility table
    candidates_status = []
    for name, c in router.candidates.items():
        fit, fit_msg = router.check_candidate_fit(c, avail_ram)
        is_calibrated = bool(
            router.machine_profile
            and name in router.machine_profile.get("calibrated_profiles", {})
        )
        if is_calibrated:
            cal_delta = router.machine_profile["calibrated_profiles"][name].get("host_delta_mb")
            req_ram = round(cal_delta + c.headroom_mb, 1)
            cal_status = f"Calibrated ({cal_delta:.1f} MB)"
        elif has_profile:
            req_ram = round(c.host_delta_mb * 1.5 + c.headroom_mb, 1)
            cal_status = "Uncalibrated (1.5x rule)"
        else:
            req_ram = round(c.host_delta_mb * 1.5 + c.headroom_mb, 1)
            cal_status = "Not calibrated -- run pai calibrate"

        candidates_status.append({
            "name": name,
            "display_name": c.display_name,
            "required_ram_mb": req_ram,
            "calibration_status": cal_status,
            "license_id": c.license_id,
            "license_status": c.license_status,
            "eligible": fit,
            "status_message": fit_msg,
        })

    doc_data = {
        "os": {
            "platform": sys.platform,
            "system": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
        },
        "telemetry": HardwareTelemetry.to_ipc_dict(snap),
        "gpu": gpu_desc,
        "ollama": ollama_status,
        "machine_profile": {
            "present": has_profile,
            "path": prof_path if has_profile else None,
        },
        "candidates": candidates_status,
    }

    # 7. Sandbox Execution Boundary Probe (ADR-011 / M2a)
    try:
        from sandbox import is_sandbox_supported, probe_system_boundary
        if is_sandbox_supported():
            s_ok, s_msg = probe_system_boundary()
            doc_data["sandbox"] = {
                "supported": True,
                "verified": s_ok,
                "message": s_msg,
            }
        else:
            doc_data["sandbox"] = {
                "supported": False,
                "verified": False,
                "message": f"Sandbox boundary not supported on {sys.platform}",
            }
    except Exception as e:
        doc_data["sandbox"] = {
            "supported": False,
            "verified": False,
            "message": f"Sandbox capability probe error: {e}",
        }

    if getattr(args, "json", False):
        print(json.dumps(doc_data, indent=2))
        return 0

    # Human-readable output
    print("=" * 64)
    print("               PAI SYSTEM & HARDWARE DOCTOR")
    print("=" * 64)
    print(f"OS Platform          : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python Runtime       : {platform.python_version()} [{sys.executable}]")
    print(f"Telemetry Source     : {snap.get('source')}")
    print(f"CPU Cores / Load     : {snap.get('cpu_cores')} cores / {snap.get('cpu_load_pct', 'n/a')}%")
    print(f"RAM Total / Avail    : {snap.get('total_ram_gb', 'n/a')} GB / {snap.get('avail_ram_gb', 'n/a')} GB ({avail_ram:.1f} MB)")
    print(f"Memory Pressure      : {snap.get('memory_load_pct', 'n/a')}%")
    batt = snap.get("battery")
    batt_str = f"{batt['percent']}% ({'AC' if batt['on_ac'] else 'Battery'})" if batt else "Desktop / Non-battery"
    print(f"Power / Battery      : {batt_str}")
    print(f"GPU / Display        : {gpu_desc}")
    print(f"Compute Tier         : {snap['budget'].compute_tier}")

    print("\n--- Model Server Status (Loopback) ---")
    if ollama_status["reachable"]:
        v_str = f"v{ollama_status['version']}" if ollama_status['version'] else "online"
        print(f"Ollama Server        : Reachable ({v_str}) on {ollama_status['endpoint']}")
        loaded = ollama_status.get("resident_models", [])
        if loaded:
            print("Loaded Models in RAM :")
            for m in loaded:
                print(f"  * {m['name']} (RAM: {m['size_mb']} MB, VRAM: {m['vram_mb']} MB)")
        else:
            print("Loaded Models in RAM : None (cold / idle)")
    else:
        print(f"Ollama Server        : OFFLINE / UNREACHABLE on {ollama_status['endpoint']}")
        print("  Notice: Run 'ollama serve' to enable local inference.")

    print("\n--- Machine Profile & Calibration ---")
    if has_profile:
        print(f"Machine Profile      : Active ({prof_path})")
    else:
        print("Machine Profile      : Not calibrated -- run pai calibrate")
        print("  Recommendation: Run 'pai calibrate' to establish machine-specific baselines.")

    print("\n--- Sandbox Execution Boundary (Milestone M2a) ---")
    sb_info = doc_data.get("sandbox", {})
    if sb_info.get("verified"):
        print(f"Sandbox Boundary     : [VERIFIED FAIL-CLOSED] {sb_info.get('message')}")
    elif sb_info.get("supported"):
        print(f"Sandbox Boundary     : [FAILED] {sb_info.get('message')}")
    else:
        print(f"Sandbox Boundary     : [UNSUPPORTED] {sb_info.get('message')}")

    print("\n--- Candidate Eligibility Report ---")
    print(f"{'Model Name':<22} {'Req RAM':<12} {'Calibration':<24} {'License':<12} {'Fit Status'}")
    print("-" * 80)
    for c in candidates_status:
        fit_lbl = "[ELIGIBLE]" if c["eligible"] else "[INSUFFICIENT RAM]"
        print(f"{c['name']:<22} {c['required_ram_mb']:<10.1f}MB {c['calibration_status']:<24} {c['license_status']:<12} {fit_lbl}")
    print("=" * 64)
    return 0


# -----------------------------------------------------------------------------
# Subcommand: calibrate
# -----------------------------------------------------------------------------
def cmd_calibrate(args: argparse.Namespace) -> int:
    """
    Executes empirical cold RAM & latency profiling per docs/MEASUREMENT_PROCEDURE.md.
    Runs 5 cold runs by default, computes medians, and writes ~/.pai/machine_profile.json.
    """
    model_arg = getattr(args, "model", None)
    num_runs = getattr(args, "runs", 5) or 5
    base_url = "http://127.0.0.1:11434"

    # Verify Ollama server
    ollama_info = probe_ollama_server(base_url)
    if not ollama_info["reachable"]:
        print(f"Error: Model server at {base_url} is unreachable. Please start Ollama before calibrating.")
        return 1

    router = ModelRouter()
    if model_arg:
        if model_arg not in router.candidates:
            print(f"Error: Unknown model '{model_arg}'. Valid candidates are: {list(router.candidates.keys())}")
            return 1
        targets = [model_arg]
    else:
        targets = list(router.candidates.keys())

    telem = HardwareTelemetry()
    snap = telem.get_system_snapshot()
    total_ram_gb = snap.get("total_ram_gb", 16.0) or 16.0
    cpu_cores = snap.get("cpu_cores", 8) or 8

    # Load existing profile if present
    prof_path = get_machine_profile_path()
    existing_prof = load_machine_profile(prof_path, live_total_ram_gb=total_ram_gb) or {
        "schema_version": 1,
        "machine_id": f"{platform.node()}_{platform.machine()}",
        "calibrated_on": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "os": platform.system(),
        "total_ram_gb": total_ram_gb,
        "cpu_cores": cpu_cores,
        "calibrated_profiles": {},
    }

    print(f"Initiating PAI Calibration on {existing_prof['machine_id']} ({num_runs} cold runs each)...")

    def unload(m_name: str) -> None:
        try:
            req = urllib.request.Request(
                f"{base_url}/api/generate",
                data=json.dumps({"model": m_name, "keep_alive": 0}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
        except Exception:
            pass

        # Poll /api/ps until model is confirmed absent from resident memory (up to 10s)
        t_start = time.time()
        while time.time() - t_start < 10.0:
            try:
                ps_req = urllib.request.Request(f"{base_url}/api/ps")
                with urllib.request.urlopen(ps_req, timeout=1.0) as resp:
                    ps_data = json.loads(resp.read().decode())
                    resident_names = [m.get("name", "") for m in ps_data.get("models", [])]
                    if m_name not in resident_names:
                        break
            except Exception:
                break
            time.sleep(0.2)

        # Allow OS memory manager to settle (MEASUREMENT_PROCEDURE.md)
        time.sleep(2.0)

    for m in targets:
        print(f"\nCalibrating '{m}'...")
        runs_data = []
        for r_idx in range(1, num_runs + 1):
            unload(m)
            base_snap = telem.get_system_snapshot()
            base_ram = base_snap.get("avail_ram_mb", 0.0) or 0.0

            prompt = "Write a python function to compute the greatest common divisor of two integers."
            req_data = json.dumps({"model": m, "prompt": prompt, "stream": False, "think": False}).encode("utf-8")
            req = urllib.request.Request(
                f"{base_url}/api/generate",
                data=req_data,
                headers={"Content-Type": "application/json"},
            )
            t0 = time.time()
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    resp.read()
                latency = round(time.time() - t0, 3)
            except Exception as e:
                print(f"  Run {r_idx} failed: {e}")
                continue

            active_snap = telem.get_system_snapshot()
            active_ram = active_snap.get("avail_ram_mb", 0.0) or 0.0
            raw_delta = base_ram - active_ram

            # Discard delta <= 0 runs (failed/invalid measurement)
            if raw_delta <= 0.0:
                print(f"  Run {r_idx}/{num_runs}: Invalid delta ({raw_delta:.1f} MB <= 0.0); discarding run.")
                continue

            delta = round(raw_delta, 1)
            runs_data.append({"run": r_idx, "delta_mb": delta, "latency_sec": latency})
            print(f"  Run {r_idx}/{num_runs}: Baseline={base_ram:.1f} MB, Active={active_ram:.1f} MB -> Delta={delta:.1f} MB, Latency={latency:.2f}s")

        unload(m)

        if len(runs_data) < 3:
            print(f"  Calibration failed for '{m}': only {len(runs_data)} valid runs (minimum 3 required). Profile not updated for this model.")
            continue

        deltas = [rd["delta_mb"] for rd in runs_data]
        latencies = [rd["latency_sec"] for rd in runs_data]
        med_delta = round(statistics.median(deltas), 1)
        med_lat = round(statistics.median(latencies), 2)
        spread_mb = round(max(deltas) - min(deltas), 1)

        # Warn if spread > 30% of median
        if med_delta > 0 and (spread_mb / med_delta) > 0.30:
            print(f"  Warning: High variance across runs (spread {spread_mb:.1f} MB is > 30% of median {med_delta:.1f} MB).")

        cand = router.candidates.get(m)
        if cand and med_delta < 0.5 * cand.host_delta_mb:
            print(f"  Warning: Calibrated median ({med_delta:.1f} MB) is below plausibility floor (< 50% of card delta {cand.host_delta_mb:.1f} MB). Will fall back to conservative rule during routing.")

        now_utc = datetime.now(timezone.utc)
        exp_utc = now_utc + timedelta(days=30)
        now_str = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        exp_str = exp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        existing_prof["calibrated_on"] = now_str
        existing_prof["expires_at"] = exp_str
        existing_prof["calibrated_profiles"][m] = {
            "host_delta_mb": med_delta,
            "latency_sec": med_lat,
            "runs": len(runs_data),
            "spread_mb": spread_mb,
            "calibrated_on": now_str,
        }
        print(f"  Median: {med_delta} MB delta, {med_lat}s latency ({len(runs_data)} valid runs).")

        # Save profile incrementally per-model
        save_machine_profile(existing_prof, prof_path)
        print(f"  Incremental profile saved for '{m}'.")

    print(f"\nCalibration complete. Validated machine profile saved to '{prof_path}'.")
    return 0


# -----------------------------------------------------------------------------
# Subcommand: models list
# -----------------------------------------------------------------------------
def cmd_models_list(args: argparse.Namespace) -> int:
    """Lists candidate model catalog, licenses, calibration status, and current fit."""
    router = ModelRouter(load_system_profile=True)
    telem = HardwareTelemetry()
    snap = telem.get_system_snapshot()
    avail_ram = snap.get("avail_ram_mb", 0.0) or 0.0

    items = []
    for name, c in router.candidates.items():
        is_cal = bool(
            router.machine_profile
            and name in router.machine_profile.get("calibrated_profiles", {})
        )
        if is_cal:
            cal_delta = router.machine_profile["calibrated_profiles"][name].get("host_delta_mb")
            req_ram = round(cal_delta + c.headroom_mb, 1)
            cal_str = f"calibrated ({cal_delta:.1f} MB)"
        elif router.machine_profile:
            req_ram = round(c.host_delta_mb * 1.5 + c.headroom_mb, 1)
            cal_str = "uncalibrated (1.5x rule)"
        else:
            req_ram = round(c.host_delta_mb * 1.5 + c.headroom_mb, 1)
            cal_str = "not calibrated (1.5x rule)"

        fit, _ = router.check_candidate_fit(c, avail_ram)

        # User allow-list check
        user_allowed = router.user_config.get("allowed_models") if router.user_config else None
        in_allowlist = True if not user_allowed else (name in user_allowed)

        items.append({
            "name": name,
            "display_name": c.display_name,
            "kind": c.kind,
            "license_id": c.license_id,
            "license_status": c.license_status,
            "calibration": cal_str,
            "min_ram_mb": req_ram,
            "live_fit": fit,
            "user_allowed": in_allowlist,
        })

    if getattr(args, "json", False):
        print(json.dumps(items, indent=2))
        return 0

    print("=" * 86)
    print("                      PAI CANDIDATE MODELS CATALOG")
    print("=" * 86)
    print(f"{'Model Name':<22} {'License':<14} {'Calibration Status':<26} {'Min RAM':<12} {'Live Fit'}")
    print("-" * 86)
    for it in items:
        fit_lbl = "FIT" if it["live_fit"] else "NO FIT"
        allow_warn = "" if it["user_allowed"] else " [DISABLED BY USER]"
        print(f"{it['name']:<22} {it['license_id']:<14} {it['calibration']:<26} {it['min_ram_mb']:<10.1f}MB {fit_lbl}{allow_warn}")
    print("=" * 86)
    return 0


# -----------------------------------------------------------------------------
# Subcommand: route
# -----------------------------------------------------------------------------
def cmd_route(args: argparse.Namespace) -> int:
    """Executes ModelRouter routing decision and displays result or explanation."""
    cmd_name = getattr(args, "command_name", None)
    if not cmd_name:
        print("Error: Missing command argument. Example: 'pai route code'")
        return 1

    router = ModelRouter(load_system_profile=True)
    telem = HardwareTelemetry()
    snap = telem.get_system_snapshot()
    budget = snap["budget"]

    # Probe resident model safely from loopback
    live_resident = router.get_live_resident_model()
    gemma_opt = getattr(args, "gemma4_opt_in", False)

    try:
        decision = router.route(
            command=cmd_name,
            budget=budget,
            resident_model=live_resident,
            gemma4_opt_in=gemma_opt,
        )
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    if getattr(args, "json", False):
        print(json.dumps(decision.to_dict(), indent=2))
        return 0

    if getattr(args, "explain_route", False):
        print(decision.report())
        return 0

    # Default concise output
    if decision.selected_model:
        print(f"Selected model: {decision.selected_model} (kind: {decision.kind}, task: {decision.task_class})")
    else:
        print(f"Route Refusal: {decision.explanation} (Reason: {', '.join(decision.reason_codes)})")
    return 0


def call_model_generate(
    model_name: str,
    prompt: str,
    base_url: Optional[str] = None,
    timeout: Optional[float] = None,
    temperature: Optional[float] = None,
    seed: Optional[int] = None,
) -> str:
    """
    Invokes local model server via Ollama /api/generate over local loopback.
    Enforces Threat T21 / loopback binding invariants.
    """
    if timeout is None:
        try:
            timeout = float(os.environ.get("PAI_MODEL_TIMEOUT", "120.0"))
        except Exception:
            timeout = 120.0
    url = base_url or os.environ.get("PAI_MODEL_URL", "http://127.0.0.1:11434")
    parts = urllib.parse.urlsplit(url)
    hostname = (parts.hostname or "").lower()
    if hostname not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        raise ValueError(f"Model server endpoint must be local loopback, got '{url}'")

    req_payload: Dict[str, Any] = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "think": False,
    }
    options: Dict[str, Any] = {}
    if temperature is not None:
        options["temperature"] = float(temperature)
    if seed is not None:
        options["seed"] = int(seed)
    if options:
        req_payload["options"] = options

    req_data = json.dumps(req_payload).encode("utf-8")

    req = urllib.request.Request(
        f"{url}/api/generate",
        data=req_data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_json = json.loads(resp.read().decode("utf-8"))
            return str(resp_json.get("response", ""))
    except Exception as e:
        raise RuntimeError(f"Failed to generate from model '{model_name}' at {url}: {e}")


def extract_python_code(raw: str) -> str:
    """Extracts python code block from model response or returns raw text."""
    text = raw.strip()
    if "```python" in text:
        parts = text.split("```python", 1)[1]
        if "```" in parts:
            return parts.split("```", 1)[0].strip()
        return parts.strip()
    if "```" in text:
        parts = text.split("```", 1)[1]
        if "```" in parts:
            return parts.split("```", 1)[0].strip()
        return parts.strip()
    return text


def enforce_sandbox_boundary() -> None:
    """
    Enforces that the host sandbox boundary passes the behavioural capability probe.
    If the boundary is compromised or unavailable, fails closed and exits immediately with code 5 (ADR-011 v2.1).
    """
    from sandbox import is_sandbox_supported, probe_system_boundary
    if not is_sandbox_supported():
        print(f"FATAL: Sandbox boundary is not supported on {sys.platform} (Exit 5).")
        sys.exit(5)
    ok, msg = probe_system_boundary()
    if not ok:
        print(f"FATAL: Sandbox behavioural capability probe failed closed: {msg} (Exit 5).")
        sys.exit(5)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pai",
        description="Personal Agentic AI (PAI) - Privacy-First Local Assistant CLI",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Hardware diagnostics and candidate eligibility")
    p_doc.add_argument("--json", action="store_true", help="Output diagnostics in JSON format")

    # calibrate
    p_cal = subparsers.add_parser("calibrate", help="Empirical 5-run cold RAM & latency calibration")
    p_cal.add_argument("--model", type=str, help="Specific model to calibrate (default: all installed candidates)")
    p_cal.add_argument("--runs", type=int, default=5, help="Number of cold runs (default: 5)")

    # models
    p_models = subparsers.add_parser("models", help="Model catalog management")
    p_models_sub = p_models.add_subparsers(dest="models_action", help="Models action")
    p_models_list = p_models_sub.add_parser("list", help="List candidate models")
    p_models_list.add_argument("--json", action="store_true", help="Output in JSON format")

    # route
    p_route = subparsers.add_parser("route", help="Adaptive Model Router CLI")
    p_route.add_argument("command_name", type=str, help="Command name (code, analyze, docs, forecast, web, chat)")
    p_route.add_argument("--explain-route", action="store_true", help="Print full routing explanation report")
    p_route.add_argument("--json", action="store_true", help="Output route decision in JSON format")
    p_route.add_argument("--gemma4-opt-in", action="store_true", help="Explicit owner opt-in for Gemma 4B")

    # code (M2b verify loop)
    p_code = subparsers.add_parser("code", help="Sandbox-verified code generation (M2b)")
    p_code.add_argument("task", nargs="?", default="", help="Coding task prompt")
    p_code.add_argument("--tests", type=str, help="User-supplied test file (takes priority over model-written tests)")
    p_code.add_argument("--allow-weak-tests", action="store_true", help="Permit user-supplied tests that pass one or more stubs in the stub family")
    p_code.add_argument("--out", type=str, help="Output staging directory (required for artifact generation)")
    p_code.add_argument("--model", type=str, default=None, help="Explicit candidate model override")
    p_code.add_argument("--max-repairs", type=int, default=3, help="Maximum repair iterations (1..5, default: 3)")
    p_code.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds per execution (default: 10.0)")
    p_code.add_argument("--memory-mb", type=float, default=512.0, help="Memory ceiling in MB (default: 512.0)")
    p_code.add_argument("--overwrite", action="store_true", help="Permit overwriting existing files in --out")
    p_code.add_argument("--temperature", type=float, default=None, help="Generation temperature (e.g. 0.0)")
    p_code.add_argument("--seed", type=int, default=None, help="Generation seed for determinism (e.g. 42)")
    p_code.add_argument("--model-timeout", type=float, default=None, help="Model generation HTTP request timeout in seconds")
    p_code.add_argument("--json", action="store_true", help="Output execution diagnostics in JSON format")

    # Deferred execution commands (M2+)
    for deferred in ("generate", "analyze", "forecast"):
        p_def = subparsers.add_parser(deferred, help=f"Direct {deferred} execution (deferred to M2+)")
        p_def.add_argument("args", nargs="*", help="Arguments")

    return parser


def cmd_code(args) -> int:
    enforce_sandbox_boundary()
    if not getattr(args, "json", False):
        print("Sandbox execution boundary verified fail-closed.")

    from ast_guard import check_source
    from verify_loop import (
        FrozenTestSuite,
        TestExecutionResult,
        TestMutationError,
        TestSyntaxError,
        VacuousTestError,
        VerifyLoop,
        sanitize_untrusted_diagnostics,
        stage_artifacts,
    )

    # 1. Validate inputs: command must have work to do
    if not getattr(args, "task", "") and not getattr(args, "tests", None):
        print("Error: No task or tests specified. Provide a task description or --tests file.", file=sys.stderr)
        return 1

    # If generating a solution (task is provided), --out is strictly required
    if getattr(args, "task", "") and not getattr(args, "out", None):
        print("Error: Staging output directory (--out) is required for 'pai code'.", file=sys.stderr)
        return 1

    # 2. Setup VerifyLoop
    timeout_sec = min(30.0, max(1.0, float(getattr(args, "timeout", 10.0) or 10.0)))
    memory_mb = min(2048.0, max(64.0, float(getattr(args, "memory_mb", 512.0) or 512.0)))
    max_repairs = min(5, max(1, int(getattr(args, "max_repairs", 3) or 3)))

    loop = VerifyLoop(
        memory_mb=memory_mb,
        timeout_sec=timeout_sec,
        max_repairs=max_repairs,
    )

    # 3. Handle user-supplied tests first (if provided)
    suite = None
    if getattr(args, "tests", None):
        tests_path = args.tests
        if not os.path.exists(tests_path):
            print(f"Error: Specified test file not found: {tests_path}", file=sys.stderr)
            return 1
        try:
            suite = loop.prepare_test_suite(user_tests_path=tests_path)
        except (VacuousTestError, TestSyntaxError, Exception) as e:
            print(f"Error: Invalid test suite: {e}", file=sys.stderr)
            return 1

        if not getattr(args, "json", False):
            print(f"[TESTS FROZEN] Source: {suite.source} | Hash: {suite.test_hash} | Assertions: {suite.assertion_count}")

        allow_weak = getattr(args, "allow_weak_tests", False)
        probe_res = loop.run_stub_probe(suite, allow_weak_tests=allow_weak)
        if not probe_res.passed:
            if getattr(args, "json", False):
                print(json.dumps({"success": False, "error": "STUB_PROBE_FAILED", "detail": probe_res.detail}, indent=2))
            else:
                print(f"Stub probe failed: {probe_res.detail}", file=sys.stderr)
            return 1

        if not getattr(args, "json", False):
            print(f"[STUB PROBE OK] {probe_res.detail}")

        # If user only requested test suite verification/probing (--tests <path> without task and without --out):
        if not getattr(args, "task", "") and not getattr(args, "out", None):
            return 0

    # 4. From here on, code generation and artifact staging is requested: --out is strictly required
    if not getattr(args, "out", None):
        print("Error: Staging output directory (--out) is required for 'pai code'.", file=sys.stderr)
        return 1

    # 5. Model selection / routing
    model_name = getattr(args, "model", None)
    if not model_name:
        router = ModelRouter(load_system_profile=True)
        decision = router.route("code")
        if not decision.selected_model:
            if getattr(args, "json", False):
                print(json.dumps({
                    "success": False,
                    "error": "ROUTE_REFUSAL",
                    "explanation": decision.explanation,
                    "reason_codes": decision.reason_codes,
                }, indent=2))
            else:
                print(f"Error: Model route refused: {decision.explanation}", file=sys.stderr)
            return 5
        model_name = decision.selected_model

    if not getattr(args, "json", False):
        print(f"Executing verified code generation with model '{model_name}'...")

    # 6. If model-written tests needed: generate, freeze, and probe
    temperature = getattr(args, "temperature", None)
    seed = getattr(args, "seed", None)
    model_timeout = getattr(args, "model_timeout", None)

    if suite is None:
        test_prompt = (
            f"Write a Python test suite for the following task:\n{args.task}\n\n"
            "Requirements:\n"
            "- Tests must test the module named 'solution' (e.g. 'from solution import ...').\n"
            "- Write clear assertions testing functionality and edge cases.\n"
            "- Return ONLY the Python test code enclosed in ```python ... ``` without explanations.\n"
        )
        try:
            raw_tests = call_model_generate(model_name, test_prompt, timeout=model_timeout, temperature=temperature, seed=seed)
        except Exception as e:
            is_timeout = "timeout" in str(e).lower() or "timed out" in str(e).lower()
            if getattr(args, "json", False):
                print(json.dumps({"success": False, "error": "GENERATOR_ERROR", "detail": str(e), "is_timeout": is_timeout}, indent=2))
            else:
                print(f"Error: Model failed to generate test suite: {e}", file=sys.stderr)
            return 2
        test_code = extract_python_code(raw_tests)
        try:
            suite = loop.prepare_test_suite(model_test_code=test_code)
        except (VacuousTestError, TestSyntaxError, Exception) as e:
            if getattr(args, "json", False):
                print(json.dumps({
                    "success": False,
                    "error": "TEST_SUITE_INVALID",
                    "detail": str(e),
                    "test_code": test_code,
                    "test_code_preview": "\n".join(test_code.splitlines()[:40]),
                }, indent=2))
            else:
                print(f"Error: Model generated invalid test suite: {e}", file=sys.stderr)
            return 1

        if not getattr(args, "json", False):
            print(f"[TESTS FROZEN] Source: {suite.source} | Hash: {suite.test_hash} | Assertions: {suite.assertion_count}")

        allow_weak = getattr(args, "allow_weak_tests", False)
        probe_res = loop.run_stub_probe(suite, allow_weak_tests=allow_weak)
        if not probe_res.passed:
            if getattr(args, "json", False):
                print(json.dumps({
                    "success": False,
                    "error": "STUB_PROBE_FAILED",
                    "detail": probe_res.detail,
                    "failing_stub": probe_res.failing_stub,
                    "test_code": suite.test_code,
                    "test_hash": suite.test_hash,
                    "test_code_preview": "\n".join(suite.test_code.splitlines()[:40]),
                }, indent=2))
            else:
                print(f"Stub probe failed: {probe_res.detail}", file=sys.stderr)
            return 1

        if not getattr(args, "json", False):
            print(f"[STUB PROBE OK] {probe_res.detail}")

    # 5. Generate initial candidate solution
    task_desc = args.task or "Implement solution to pass the provided test suite."
    sol_prompt = (
        f"Write a Python solution for the following task:\n{task_desc}\n\n"
        f"The solution must satisfy these tests:\n```python\n{suite.test_code}\n```\n\n"
        "Requirements:\n"
        "- Implement all required functions and classes in module 'solution'.\n"
        "- Return ONLY the Python solution code enclosed in ```python ... ``` without explanations.\n"
    )
    try:
        raw_sol = call_model_generate(model_name, sol_prompt, timeout=model_timeout, temperature=temperature, seed=seed)
    except Exception as e:
        is_timeout = "timeout" in str(e).lower() or "timed out" in str(e).lower()
        if getattr(args, "json", False):
            print(json.dumps({
                "success": False,
                "error": "GENERATOR_ERROR",
                "detail": str(e),
                "is_timeout": is_timeout,
                "test_code": suite.test_code,
                "test_hash": suite.test_hash,
                "test_code_preview": "\n".join(suite.test_code.splitlines()[:40]),
            }, indent=2))
        else:
            print(f"Error: Model failed to generate initial solution: {e}", file=sys.stderr)
        return 2

    initial_solution = extract_python_code(raw_sol)

    # Static AST safety check
    guard_rep = check_source(initial_solution)
    if not guard_rep.ok:
        v_details = [str(x) for x in guard_rep.violations]
        if getattr(args, "json", False):
            print(json.dumps({
                "success": False,
                "error": "AST_SAFETY_VIOLATION",
                "violations": v_details,
                "test_code": suite.test_code if suite else None,
                "test_hash": suite.test_hash if suite else None,
                "test_code_preview": "\n".join(suite.test_code.splitlines()[:40]) if suite else None,
            }, indent=2))
        else:
            print(f"Error: Solution rejected by AST safety guard: {v_details}", file=sys.stderr)
        return 1

    # 6. Define bounded repair generator
    def repair_generator_fn(cur_sol: str, last_res: TestExecutionResult, frz_suite: FrozenTestSuite) -> str:
        sanitized_diag = sanitize_untrusted_diagnostics(last_res)
        rep_prompt = (
            f"Fix the Python solution for the following task:\n{task_desc}\n\n"
            f"Current solution:\n```python\n{cur_sol}\n```\n\n"
            f"Execution diagnostics:\n{sanitized_diag}\n\n"
            f"Tests to satisfy:\n```python\n{frz_suite.test_code}\n```\n\n"
            "Requirements:\n"
            "- Modify the solution so that all tests pass.\n"
            "- Return ONLY the Python code enclosed in ```python ... ``` without explanations.\n"
        )
        raw_rep = call_model_generate(model_name, rep_prompt, timeout=model_timeout, temperature=temperature, seed=seed)
        rep_code = extract_python_code(raw_rep)
        if not rep_code or not rep_code.strip():
            raise ValueError("Model returned empty code during repair")
        rep_guard = check_source(rep_code)
        if not rep_guard.ok:
            raise ValueError(f"Repaired solution violated AST guard: {[str(x) for x in rep_guard.violations]}")
        return rep_code

    # 7. Execute bounded repair loop
    repair_result = loop.run_repair_loop(
        initial_solution,
        suite,
        repair_generator_fn=repair_generator_fn,
        max_repairs=max_repairs,
    )

    # 8. Handle result and safe staging
    test_code_preview = "\n".join(suite.test_code.splitlines()[:40]) if suite else None
    test_hash = suite.test_hash if suite else None

    if repair_result.success:
        try:
            sol_dest, test_dest = stage_artifacts(
                args.out,
                repair_result.final_solution,
                suite.test_code,
                overwrite=getattr(args, "overwrite", False),
            )
        except FileExistsError as e:
            if getattr(args, "json", False):
                print(json.dumps({
                    "success": False,
                    "error": "COLLISION",
                    "detail": str(e),
                    "test_hash": test_hash,
                    "test_code_preview": test_code_preview,
                    "pass_at_1_zero_shot": repair_result.pass_at_1_zero_shot,
                    "pass_at_1_repair3": repair_result.pass_at_1_repair3,
                }, indent=2))
            else:
                print(f"Error: File collision during staging: {e}", file=sys.stderr)
            return 4
        except (ValueError, IsADirectoryError) as e:
            if getattr(args, "json", False):
                print(json.dumps({
                    "success": False,
                    "error": "STAGING_VIOLATION",
                    "detail": str(e),
                    "test_hash": test_hash,
                    "test_code_preview": test_code_preview,
                    "pass_at_1_zero_shot": repair_result.pass_at_1_zero_shot,
                    "pass_at_1_repair3": repair_result.pass_at_1_repair3,
                }, indent=2))
            else:
                print(f"Error: Safe staging safety violation: {e}", file=sys.stderr)
            return 4

        if getattr(args, "json", False):
            print(json.dumps({
                "success": True,
                "status": "PASS",
                "selected_model": model_name,
                "staged_solution": sol_dest,
                "staged_tests": test_dest,
                "test_hash": test_hash,
                "test_code_preview": test_code_preview,
                "pass_at_1_zero_shot": repair_result.pass_at_1_zero_shot,
                "pass_at_1_repair3": repair_result.pass_at_1_repair3,
                "total_repairs": repair_result.total_repairs,
                "iterations": len(repair_result.iterations),
                "temperature": temperature,
                "seed": seed,
                "detail": repair_result.detail,
            }, indent=2))
        else:
            print(f"[VERIFIED PASS] Solution verified and staged to {args.out}")
            print(f"  - Solution: {sol_dest}")
            print(f"  - Tests   : {test_dest}")
            print(f"  - pass@1_zero_shot: {repair_result.pass_at_1_zero_shot}")
            print(f"  - pass@1_repair3  : {repair_result.pass_at_1_repair3}")
            print(f"  - Repairs used    : {repair_result.total_repairs} / {max_repairs}")
        return 0
    else:
        if getattr(args, "json", False):
            print(json.dumps({
                "success": False,
                "status": "FAIL",
                "selected_model": model_name,
                "test_hash": test_hash,
                "test_code_preview": test_code_preview,
                "pass_at_1_zero_shot": repair_result.pass_at_1_zero_shot,
                "pass_at_1_repair3": repair_result.pass_at_1_repair3,
                "total_repairs": repair_result.total_repairs,
                "iterations": len(repair_result.iterations),
                "temperature": temperature,
                "seed": seed,
                "detail": repair_result.detail,
            }, indent=2))
        else:
            print(f"[FAIL] Verification failed: {repair_result.detail}", file=sys.stderr)
        return 2


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 0

    if args.subcommand in ("generate", "analyze", "forecast"):
        print(f"Notice: Direct command execution '{args.subcommand}' is deferred to Milestone M2+.")
        print(f"        Use 'pai route {args.subcommand}' to evaluate adaptive routing decisions.")
        return 0

    if args.subcommand == "code":
        return cmd_code(args)

    if args.subcommand == "doctor":
        return cmd_doctor(args)
    elif args.subcommand == "calibrate":
        return cmd_calibrate(args)
    elif args.subcommand == "models":
        if getattr(args, "models_action", None) == "list" or not getattr(args, "models_action", None):
            return cmd_models_list(args)
        parser.print_help()
        return 1
    elif args.subcommand == "route":
        return cmd_route(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
