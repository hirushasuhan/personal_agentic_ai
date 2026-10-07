"""
Comprehensive Milestone M1 Bake-off Evaluation Harness (Track L / ADR-008)
Evaluates candidate models across:
1. 20 Hand-crafted Coding Tasks (with timeout-guarded hidden tests)
2. 10 Singlish / Sinhala Prompts (scored 0-2 against rubric)
3. 10 Grounded Document / Analysis Tasks
Measures: RAM Delta, Footprint, Latency, pass@1, Singlish score, Doc accuracy, Truncation.
"""

import json
import os
import re
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_sets.hidden_tests.test_coding_tasks import HIDDEN_TESTS
from hardware_telemetry import HardwareBudget, HardwareTelemetry
from reasoner import LocalLLMReasoner, TemplateReasoner


def extract_python_code(raw_text: str) -> str:
    """Extracts python code from markdown code fences or returns raw text."""
    py_matches = re.findall(r"```(?:python|py)\s*\n?([\s\S]*?)```", raw_text, re.IGNORECASE)
    if py_matches:
        valid_blocks = [m.strip() for m in py_matches if m.strip()]
        if valid_blocks:
            return max(valid_blocks, key=len)

    generic_matches = re.findall(r"```(?:\w+)?\s*\n?([\s\S]*?)```", raw_text)
    for m in generic_matches:
        cleaned = m.strip()
        if cleaned and cleaned.lower() not in ("markdown", "python", "py"):
            return cleaned

    return raw_text.strip()


def run_with_timeout(fn: Any, args: tuple = (), timeout: float = 2.0) -> Tuple[bool, Any]:
    """Runs a callable in a worker thread with timeout to contain infinite loops."""
    res_box = [False, None]

    def target():
        try:
            res_box[1] = fn(*args)
            res_box[0] = True
        except Exception as e:
            res_box[1] = e

    t = threading.Thread(target=target)
    t.daemon = True
    t.start()
    t.join(timeout=timeout)

    if t.is_alive():
        return False, TimeoutError(f"Execution exceeded timeout of {timeout}s")
    if isinstance(res_box[1], Exception):
        return False, res_box[1]
    return res_box[0], res_box[1]


from safe_code_runner import run_isolated_task_eval


def evaluate_coding_task(code_str: str, entry_point: str, test_fns: List[Any], timeout_sec: float = 2.0) -> Tuple[bool, str]:
    """Evaluates untrusted model code against hidden unit tests in an isolated sandbox subprocess."""
    for idx, test_fn in enumerate(test_fns):
        passed, msg = run_isolated_task_eval(code_str, entry_point, test_fn, timeout_sec=timeout_sec)
        if not passed:
            return False, f"Hidden test #{idx + 1} failed: {msg}"
    return True, "Passed all hidden tests"


def evaluate_model_bakeoff(
    model_name: str,
    base_url: str = "http://127.0.0.1:11434/v1",
    ollama_base: str = "http://127.0.0.1:11434",
    think: Optional[bool] = None,
) -> Dict[str, Any]:
    think_label = f" (think={think})" if think is not None else ""
    print(f"\n=======================================================")
    print(f"BAKE-OFF EVALUATION: {model_name}{think_label}")
    print(f"=======================================================")

    root_dir = os.path.dirname(os.path.abspath(__file__))
    eval_dir = os.path.join(root_dir, "eval_sets")

    with open(os.path.join(eval_dir, "coding_tasks.json"), "r", encoding="utf-8") as f:
        coding_tasks = json.load(f)
    with open(os.path.join(eval_dir, "singlish_prompts.json"), "r", encoding="utf-8") as f:
        singlish_prompts = json.load(f)
    with open(os.path.join(eval_dir, "doc_analysis_tasks.json"), "r", encoding="utf-8") as f:
        doc_tasks = json.load(f)

    reasoner = LocalLLMReasoner(base_url=base_url, model=model_name, timeout=45.0, think=think)
    telem = HardwareTelemetry()

    # Read initial RAM
    snap_before = telem.get_system_snapshot()
    ram_before = snap_before["avail_ram_mb"]

    budget = HardwareBudget(
        compute_tier="HIGH",
        max_context_bytes=64 * 1024 * 1024,
        allow_speculation=True,
        thread_pool_limit=4,
        throttle_warning="",
        avail_ram_mb=ram_before,
    )

    # 1. Evaluate Coding Tasks (20)
    print("\n[Set 1: Coding Tasks (20)]")
    code_passed = 0
    code_latencies = []
    has_thinking = False
    has_truncation = False
    truncated_tasks = []

    sys_code = "You are an expert Python software engineer. Output ONLY valid Python code inside a ```python block. Do not add markdown wrappers or explanations."

    coding_results = []
    for t in coding_tasks:
        tid = t["id"]
        entry = t["entry_point"]
        prompt = sys_code + "\n\n" + t["prompt"]
        t0 = time.time()
        try:
            resp = reasoner.reason(query=prompt, context=None, budget=budget)
            lat = round(time.time() - t0, 2)
            code_latencies.append(lat)
            if getattr(reasoner, "last_thinking_detected", False) or "<think>" in resp or "</think>" in resp:
                has_thinking = True
            if getattr(reasoner, "last_truncated", False) or "[TRUNCATED:" in resp:
                has_truncation = True
                if tid not in truncated_tasks:
                    truncated_tasks.append(tid)
            code = extract_python_code(resp)
            passed, reason = evaluate_coding_task(code, entry, HIDDEN_TESTS.get(tid, []))
        except Exception as e:
            lat = round(time.time() - t0, 2)
            code_latencies.append(lat)
            passed, reason = False, f"Reasoner error: {e}"
            code = ""

        if passed:
            code_passed += 1
            print(f"  [{tid}] {t['name']}: PASS ({lat}s)")
        else:
            print(f"  [{tid}] {t['name']}: FAIL ({reason}) ({lat}s)")

        coding_results.append({"id": tid, "passed": passed, "reason": reason, "latency": lat})

    # 2. Evaluate Singlish / Sinhala Prompts (10)
    print("\n[Set 2: Singlish / Sinhala Prompts (10)]")
    singlish_results = []
    singlish_total_score = 0

    for s in singlish_prompts:
        sid = s["id"]
        prompt = s["prompt"]
        t0 = time.time()
        try:
            resp = reasoner.reason(query=prompt, context=None, budget=budget)
            lat = round(time.time() - t0, 2)
            if getattr(reasoner, "last_thinking_detected", False) or "<think>" in resp:
                has_thinking = True
            if getattr(reasoner, "last_truncated", False) or "[TRUNCATED:" in resp:
                has_truncation = True
                if sid not in truncated_tasks:
                    truncated_tasks.append(sid)
            # Automated keyword scoring as objective baseline
            kw_matches = [kw for kw in s.get("expected_keywords", []) if kw.lower() in resp.lower()]
            kw_ratio = len(kw_matches) / max(1, len(s.get("expected_keywords", [])))
            if kw_ratio >= 0.75:
                score = 2
            elif kw_ratio >= 0.25:
                score = 1
            else:
                score = 0
        except Exception as e:
            lat = round(time.time() - t0, 2)
            resp = f"Error: {e}"
            score = 0
            kw_matches = []

        singlish_total_score += score
        print(f"  [{sid}] Score={score}/2 (Keywords: {len(kw_matches)}/{len(s.get('expected_keywords', []))}) ({lat}s)")
        singlish_results.append({
            "id": sid,
            "score": score,
            "response_sample": resp[:250],
            "latency": lat,
        })

    # 3. Evaluate Document Analysis Tasks
    print(f"\n[Set 3: Document Analysis Tasks ({len(doc_tasks)})]")
    doc_results = []
    doc_passed = 0

    for d in doc_tasks:
        did = d["id"]
        ctx = d["document_context"]
        q = d["question"]
        t0 = time.time()
        try:
            resp = reasoner.reason(query=q, context=ctx, budget=budget)
            lat = round(time.time() - t0, 2)
            if getattr(reasoner, "last_thinking_detected", False) or "<think>" in resp:
                has_thinking = True
            if getattr(reasoner, "last_truncated", False) or "[TRUNCATED:" in resp:
                has_truncation = True
                if did not in truncated_tasks:
                    truncated_tasks.append(did)
            # Check if ground truth keywords are in the answer
            kws = d.get("ground_truth_keywords", [])
            match = any(kw.lower() in resp.lower() for kw in kws)
        except Exception as e:
            lat = round(time.time() - t0, 2)
            resp = f"Error: {e}"
            match = False

        if match:
            doc_passed += 1
            print(f"  [{did}]: PASS ({lat}s)")
        else:
            print(f"  [{did}]: FAIL ({lat}s)")

        doc_results.append({
            "id": did,
            "passed": match,
            "response": resp[:200],
            "latency": lat,
        })

    # Measure RAM drop and model footprint
    snap_after = telem.get_system_snapshot()
    ram_after = snap_after["avail_ram_mb"]
    ram_delta = round(max(0.0, ram_before - ram_after), 1)

    # Footprint via Ollama ps
    footprint_mb = 0.0
    try:
        import urllib.request
        with urllib.request.urlopen(f"{ollama_base}/api/ps", timeout=2) as r:
            ps_data = json.loads(r.read().decode())
            for m in ps_data.get("models", []):
                if model_name.split(":")[0] in m.get("name", ""):
                    footprint_mb = round((m.get("size", 0) or m.get("size_vram", 0)) / (1024 * 1024), 1)
    except Exception:
        pass

    # Query Ollama version
    ollama_ver = "unknown"
    try:
        import urllib.request
        with urllib.request.urlopen(f"{ollama_base}/api/version", timeout=2) as r:
            ollama_ver = json.loads(r.read().decode()).get("version", "unknown")
    except Exception:
        pass

    # Load frozen eval hashes
    hashes_file = os.path.join(os.path.dirname(root_dir), "docs", "evidence", "eval_sets_hashes.json")
    eval_hashes = {}
    if os.path.exists(hashes_file):
        try:
            with open(hashes_file, "r", encoding="utf-8") as f:
                eval_hashes = json.load(f).get("file_hashes_sha256", {})
        except Exception:
            pass

    # Load standardized 5-run cold median host delta from model_profiles.json
    profiles_path = os.path.join(root_dir, "model_profiles.json")
    model_prof = {}
    if os.path.exists(profiles_path):
        try:
            with open(profiles_path, "r", encoding="utf-8") as f:
                model_prof = json.load(f).get("profiles", {}).get(model_name, {})
        except Exception:
            pass

    standard_host_delta = model_prof.get("host_delta_mb", ram_delta)
    standard_footprint = model_prof.get("model_footprint_mb", footprint_mb)

    avg_code_lat = round(sum(code_latencies) / len(code_latencies), 2) if code_latencies else 0.0

    summary = {
        "model": model_name,
        "run_metadata": {
            "runner_version": "1.2.0",
            "date": "2026-10-07",
            "ollama_version": ollama_ver,
            "think_setting": think,
            "eval_sets_hashes": eval_hashes,
            "truncated_tasks": truncated_tasks,
            "low_confidence": len(truncated_tasks) > 0,
        },
        "pass_at_1_coding": f"{code_passed}/{len(coding_tasks)} ({round(code_passed / max(1, len(coding_tasks)) * 100, 1)}%)",
        "singlish_score": f"{singlish_total_score}/{len(singlish_prompts) * 2} ({round(singlish_total_score / max(1, len(singlish_prompts) * 2) * 100, 1)}%)",
        "doc_analysis_score": f"{doc_passed}/{len(doc_tasks)} ({round(doc_passed / max(1, len(doc_tasks)) * 100, 1)}%)",
        "avg_coding_latency_sec": avg_code_lat,
        "host_ram_delta_mb": standard_host_delta,
        "measured_live_delta_mb": ram_delta,
        "ollama_footprint_mb": standard_footprint,
        "truncation_detected": len(truncated_tasks) > 0,
        "thinking_mode": has_thinking,
        "truncated_tasks": truncated_tasks,
        "coding_results": coding_results,
        "singlish_results": singlish_results,
        "doc_results": doc_results,
    }

    print("\n---------------- SUMMARY ----------------", flush=True)
    print(f"Model:                {model_name}", flush=True)
    print(f"Pass@1 Coding:        {summary['pass_at_1_coding']}", flush=True)
    print(f"Singlish Score:       {summary['singlish_score']}", flush=True)
    print(f"Doc Analysis Score:   {summary['doc_analysis_score']}", flush=True)
    print(f"Avg Coding Latency:   {avg_code_lat}s", flush=True)
    print(f"Host RAM Delta:       {standard_host_delta} MB (standardized median)", flush=True)
    print(f"Live Measured Delta:  {ram_delta} MB", flush=True)
    print(f"Footprint (RAM/VRAM): {standard_footprint} MB", flush=True)
    print(f"Thinking Mode:        {has_thinking}", flush=True)
    print(f"Truncated Tasks:      {truncated_tasks if truncated_tasks else 'None'}", flush=True)
    print(f"Low Confidence Flag:  {summary['run_metadata']['low_confidence']}", flush=True)
    print("-----------------------------------------", flush=True)

    # Save to docs/evidence/m1_bakeoff_results.json
    evidence_dir = os.path.join(os.path.dirname(root_dir), "docs", "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    out_file = os.path.join(evidence_dir, "m1_bakeoff_results.json")

    existing_data = {}
    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except Exception:
            existing_data = {}

    existing_data[model_name] = summary
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=2)
    print(f"Updated results in {out_file}", flush=True)

    return summary


def unload_model(model_name: str, base_url: str = "http://127.0.0.1:11434"):
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{base_url}/api/generate",
            data=json.dumps({"model": model_name, "keep_alive": 0}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except Exception:
        pass
    time.sleep(1.0)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="M1 Bake-off Evaluation")
    parser.add_argument("model", nargs="?", default="qwen2.5-coder:1.5b", help="Model name to evaluate")
    parser.add_argument("--no-think", action="store_true", help="Disable thinking mode (think=False)")
    parser.add_argument("--batch", action="store_true", help="Run batch evaluation over all models")
    args = parser.parse_args()

    think_opt = False if args.no_think else None

    if args.batch:
        models = [
            "llama3.2:3b",
            "qwen2.5-coder:1.5b",
            "qwen3.5:4b",
            "gemma4:e2b",
            "qwen2.5-coder:7b",
        ]
        for m in models:
            unload_model(m)
            time.sleep(2.0)
            try:
                # Use think=False for reasoning models if specified or by default
                m_think = False if (args.no_think or m in ("qwen3.5:4b", "gemma4:e2b")) else None
                evaluate_model_bakeoff(m, think=m_think)
            except Exception as e:
                print(f"Model {m} evaluation failed: {e}", flush=True)
            unload_model(m)
    else:
        evaluate_model_bakeoff(args.model, think=think_opt)

