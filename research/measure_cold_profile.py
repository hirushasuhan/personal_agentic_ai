"""
Empirical Cold RAM & Latency Profiler for Local Models (ADR-008 & M1)
Measures host available-RAM drop (host_delta_mb) and latency across 5 cold runs.
"""

import json
import time
import urllib.request
import urllib.error
from hardware_telemetry import HardwareTelemetry


def unload_model(model_name: str, base_url: str = "http://127.0.0.1:11434"):
    req = urllib.request.Request(
        f"{base_url}/api/generate",
        data=json.dumps({"model": model_name, "keep_alive": 0}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except Exception as e:
        print(f"Warning on unload: {e}")
    time.sleep(1.0)


def get_loaded_models(base_url: str = "http://127.0.0.1:11434"):
    try:
        with urllib.request.urlopen(f"{base_url}/api/ps", timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("models", [])
    except Exception:
        return []


def run_cold_profiling(model_name: str, num_runs: int = 5, base_url: str = "http://127.0.0.1:11434"):
    telem = HardwareTelemetry()
    runs = []

    print(f"Starting empirical cold profiling for {model_name} ({num_runs} runs)...")

    for i in range(1, num_runs + 1):
        # 1. Ensure model is unloaded
        unload_model(model_name, base_url)
        time.sleep(2.0)  # Allow Windows memory cache to settle

        loaded = get_loaded_models(base_url)
        if any(m.get("name", "").startswith(model_name.split(":")[0]) for m in loaded):
            print(f"Warning: Model still in memory before run {i}, forcing unload...")
            unload_model(model_name, base_url)
            time.sleep(2.0)

        # 2. Baseline available RAM
        base_snap = telem.get_system_snapshot()
        base_ram = base_snap["avail_ram_mb"]

        # 3. Fire prompt and measure latency
        prompt = "Write a python function to compute the greatest common divisor of two integers."
        req_data = json.dumps({"model": model_name, "prompt": prompt, "stream": False}).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/generate",
            data=req_data,
            headers={"Content-Type": "application/json"},
        )

        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            print(f"Run {i} failed: {e}")
            continue
        latency = round(time.time() - t0, 3)

        # 4. Active RAM & footprint
        active_snap = telem.get_system_snapshot()
        active_ram = active_snap["avail_ram_mb"]
        delta = round(max(0.0, base_ram - active_ram), 1)

        ps_info = get_loaded_models(base_url)
        footprint_mb = 0.0
        for m in ps_info:
            if model_name.split(":")[0] in m.get("name", ""):
                footprint_mb = round((m.get("size", 0) or m.get("size_vram", 0)) / (1024 * 1024), 1)

        runs.append({
            "run": i,
            "baseline_ram_mb": base_ram,
            "active_ram_mb": active_ram,
            "host_delta_mb": delta,
            "latency_sec": latency,
            "footprint_mb": footprint_mb,
        })
        print(f"  Run {i}: Baseline={base_ram:.1f}MB, Active={active_ram:.1f}MB -> Delta={delta:.1f}MB, Latency={latency:.2f}s, Footprint={footprint_mb:.1f}MB")

    # Clean up (unload)
    unload_model(model_name, base_url)

    if not runs:
        print("No successful runs!")
        return None

    deltas = [r["host_delta_mb"] for r in runs]
    latencies = [r["latency_sec"] for r in runs]
    footprints = [r["footprint_mb"] for r in runs if r["footprint_mb"] > 0]

    summary = {
        "model": model_name,
        "runs_count": len(runs),
        "host_delta_mb_max": max(deltas),
        "host_delta_mb_avg": round(sum(deltas) / len(deltas), 1),
        "host_delta_mb_min": min(deltas),
        "latency_sec_avg": round(sum(latencies) / len(latencies), 2),
        "model_footprint_mb": max(footprints) if footprints else None,
        "runs": runs,
    }

    print("\nSummary:")
    print(f"  Max host_delta_mb: {summary['host_delta_mb_max']} MB")
    print(f"  Avg host_delta_mb: {summary['host_delta_mb_avg']} MB")
    print(f"  Avg latency:       {summary['latency_sec_avg']} s")
    print(f"  Footprint:         {summary['model_footprint_mb']} MB")
    return summary


if __name__ == "__main__":
    import sys
    model = sys.argv[1] if len(sys.argv) > 1 else "qwen2.5-coder:1.5b"
    run_cold_profiling(model, 5)
