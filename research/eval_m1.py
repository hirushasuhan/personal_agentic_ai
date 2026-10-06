"""
Milestone M1 Evaluation Runner (Track L / ADR-008)
Measures pass@1 baseline on the frozen 20 hand-crafted coding tasks.
"""

import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from eval_m1_dataset import TASKS
from hardware_telemetry import HardwareBudget
from reasoner import LocalLLMReasoner, TemplateReasoner


def extract_python_code(raw_text: str) -> str:
    """Extracts python code from markdown fence or returns raw code."""
    # Match ```python ... ``` or ``` ... ```
    pattern = r"```(?:python)?\s*([\s\S]*?)```"
    matches = re.findall(pattern, raw_text, re.IGNORECASE)
    if matches:
        return matches[0].strip()
    return raw_text.strip()


def run_single_task_eval(code_str: str, entry_point: str, hidden_tests: List[Any], timeout_sec: float = 3.0) -> Tuple[bool, str]:
    """Executes generated code in an isolated dictionary scope and runs hidden tests."""
    scope: Dict[str, Any] = {}
    try:
        # Pre-compile to catch syntax errors
        compiled = compile(code_str, "<model_code>", "exec")
        exec(compiled, scope)
    except Exception as e:
        return False, f"Execution/Syntax Error: {type(e).__name__}: {e}"

    if entry_point not in scope:
        return False, f"Entry point '{entry_point}' not defined in output."

    target_fn = scope[entry_point]

    # Run each hidden test
    for idx, test_fn in enumerate(hidden_tests):
        try:
            result = test_fn(target_fn)
            if not result:
                return False, f"Hidden test #{idx + 1} assertion returned False"
        except Exception as e:
            return False, f"Hidden test #{idx + 1} raised {type(e).__name__}: {e}"

    return True, "Passed all hidden tests"


def evaluate_model(
    reasoner: Any,
    model_name: str,
    tasks: List[Dict[str, Any]],
    output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    print(f"\n=======================================================")
    print(f"Evaluating model: {model_name} on {len(tasks)} tasks...")
    print(f"=======================================================")

    budget = HardwareBudget(
        compute_tier="HIGH",
        max_context_bytes=64 * 1024 * 1024,
        allow_speculation=True,
        thread_pool_limit=4,
        throttle_warning="",
        avail_ram_mb=4000.0,
    )

    results = []
    passed_count = 0

    system_prefix = (
        "You are an expert Python software engineer.\n"
        "Generate only self-contained, working Python code. Enclose code inside a single ```python markdown block.\n"
        "Do not include any introductory or concluding text.\n\n"
    )

    for task in tasks:
        task_id = task["id"]
        name = task["name"]
        entry_point = task["entry_point"]
        prompt = system_prefix + task["prompt"]

        print(f"[{task_id}] {name}...", end=" ", flush=True)

        t0 = time.time()
        try:
            raw_output = reasoner.reason(query=prompt, context=None, budget=budget)
            latency = round(time.time() - t0, 2)
            code = extract_python_code(raw_output)
            passed, reason = run_single_task_eval(code, entry_point, task["hidden_tests"])
        except Exception as e:
            latency = round(time.time() - t0, 2)
            passed, reason = False, f"Reasoner error: {e}"
            raw_output = ""

        if passed:
            passed_count += 1
            print(f"PASS ({latency}s)")
        else:
            print(f"FAIL ({reason}) ({latency}s)")

        results.append({
            "task_id": task_id,
            "name": name,
            "passed": passed,
            "reason": reason,
            "latency_sec": latency,
            "code_snippet": code[:200] if code else "",
        })

    pass_rate = round((passed_count / len(tasks)) * 100.0, 1)
    summary = {
        "model": model_name,
        "total_tasks": len(tasks),
        "passed_tasks": passed_count,
        "pass_at_1_pct": pass_rate,
        "date": "2026-10-07",
        "results": results,
    }
    print(f"\nFinal Result for {model_name}: {passed_count}/{len(tasks)} passed ({pass_rate}%)")
    return summary


def main():
    base_url = "http://127.0.0.1:11434/v1"
    evidence_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "docs",
        "evidence",
    )
    os.makedirs(evidence_dir, exist_ok=True)

    models_to_test = [
        ("stub", TemplateReasoner()),
        ("llama3.2:1b", LocalLLMReasoner(base_url=base_url, model="llama3.2:1b")),
        ("llama3.2:3b", LocalLLMReasoner(base_url=base_url, model="llama3.2:3b")),
        ("qwen2.5-coder:1.5b", LocalLLMReasoner(base_url=base_url, model="qwen2.5-coder:1.5b")),
    ]

    all_summaries = {}
    for name, reasoner in models_to_test:
        summary = evaluate_model(reasoner, name, TASKS)
        all_summaries[name] = summary

    out_file = os.path.join(evidence_dir, "m1_coding_baseline.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_summaries, f, indent=2)
    print(f"\nSaved comprehensive baseline evaluation to: {out_file}")


if __name__ == "__main__":
    main()
