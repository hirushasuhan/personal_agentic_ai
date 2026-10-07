# Hardware Measurement Procedure (ADR-008 / M1.2)

This document specifies the standard, reproducible measurement protocol for local open-weights language models evaluated within the Personal Agentic AI (PAI) architecture on Windows hardware.

---

## 1. Objectives

1. **Host RAM Delta ($\Delta \text{RAM}$)**: Empirically quantify the drop in operating system available physical RAM caused by loading and running the model.
2. **Server Footprint**: Measure the server process memory and iGPU VRAM allocated by the local runner (Ollama) via `/api/ps`.
3. **Execution Latency**: Measure cold and warm inference latencies.
4. **Hysteresis & Refusal Guarantees**: Provide stable numbers for the admission rule:
   $$\text{available\_ram\_mb} \ge \text{host\_delta\_mb} + 512\text{ MB}$$

---

## 2. Standard Measurement Protocol (5-Run Median Cold Start)

For every candidate model, 5 independent cold runs are executed using [`research/measure_cold_profile.py`](file:///C:/Users/hp/Documents/GitHub/personal_agentic_ai/research/measure_cold_profile.py):

1. **Eviction / Unload**:
   - Send HTTP POST to `/api/generate` with `{"model": "<name>", "keep_alive": 0}`.
   - Poll `/api/ps` until the model is confirmed absent from resident memory.
   - Sleep for 2.0 seconds to allow the Windows NT memory manager and paging subsystem to settle and reclaim cached working sets.

2. **Baseline Snapshot**:
   - Query native Win32 `GlobalMemoryStatusEx` (via Rust `core --telemetry --json` or Python `HardwareTelemetry`).
   - Record `baseline_avail_ram_mb`.

3. **Inference Trigger**:
   - Send standardized generation prompt with `think: false` (to prevent non-deterministic internal reasoning loops):
     `"Write a python function to compute the greatest common divisor of two integers."`
   - Measure request round-trip time ($t_{\text{latency}}$).

4. **Active Snapshot & Delta**:
   - Wait 1.0 second for peak memory allocation to stabilize.
   - Record `active_avail_ram_mb`.
   - Calculate run delta:
     $$\Delta \text{RAM} = \max(0.0, \text{baseline\_avail\_ram\_mb} - \text{active\_avail\_ram\_mb})$$

5. **Server Footprint Inspection**:
   - Query `/api/ps` to retrieve:
     - `size`: Total process memory reported by Ollama.
     - `size_vram`: VRAM / unified shared GPU memory reported by Ollama.
   - Note: On unified memory architectures (AMD APUs with Radeon 760M iGPU), Ollama reports only the discrete VRAM slice under `size_vram` (e.g. 214 MB for Gemma 4 e2b), while the remaining layers and model weights occupy shared host system RAM ($\Delta \text{RAM} \approx 2.38\text{ GB}$).

6. **Aggregation**:
   - Repeat steps 1–5 for $N = 5$ iterations.
   - Calculate the **median** $\Delta \text{RAM}$ (`statistics.median`).
   - Store the empirical median in [`research/model_profiles.json`](file:///C:/Users/hp/Documents/GitHub/personal_agentic_ai/research/model_profiles.json) as `host_delta_mb`.

---

## 3. Discrepancy & Anomaly Flagging Rules

- **$\Delta \text{RAM} > \text{footprint}$**: Happens when Ollama offloads part of the model to GPU and part to CPU/system cache, or when unified memory buffers are allocated directly from OS non-paged pool.
- **$\Delta \text{RAM} \ll \text{footprint}$**: Flags that the model was not completely cold-unloaded prior to the baseline snapshot (residual cache hit).
- If any run exhibits an anomaly $> 20\%$ from the median, it is recorded in the raw run log and the median is retained to resist outlier skew.
