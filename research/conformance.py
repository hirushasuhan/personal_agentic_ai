"""
Language-neutral conformance vectors and differential fuzzer (review risk R6, ADR-004).

The Python prototype is the executable specification. Instead of re-reading prose, the Rust core and the
C++ daemon prove they match it by passing these golden vectors:

  conformance/tier_policy_vectors.json  inputs -> expected hardware budget
  conformance/url_policy_vectors.json   URL    -> accept / reject (strict subset, canonical IP literals)

Usage:
  python conformance.py                 # Regenerates golden vector files
  python conformance.py --fuzz 10000 --seed 42  # Runs differential fuzz test against pai-core
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
from typing import Any, Dict, List, Tuple

from hardware_telemetry import HardwareTelemetry
from net_guard import UrlRejected, validate_url

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "conformance")

URL_CASES: List[Tuple[str, str]] = [
    # --- Original 28 golden vectors ---
    ("http://8.8.8.8/", "accept"),
    ("https://1.1.1.1/dns-query", "accept"),
    ("https://8.8.8.8:443/x", "accept"),
    ("http://[2606:4700:4700::1111]/", "accept"),
    ("file:///etc/passwd", "reject"),
    ("ftp://8.8.8.8/", "reject"),
    ("gopher://8.8.8.8/", "reject"),
    ("javascript:alert(1)", "reject"),
    ("", "reject"),
    ("http:///nohost", "reject"),
    ("http://127.0.0.1/", "reject"),
    ("http://[::1]/", "reject"),
    ("http://0.0.0.0/", "reject"),
    ("http://10.0.0.5/", "reject"),
    ("http://172.16.0.1/", "reject"),
    ("http://192.168.1.1/", "reject"),
    ("http://169.254.169.254/latest/meta-data/", "reject"),
    ("http://100.64.0.1/", "reject"),
    ("http://224.0.0.1/", "reject"),
    ("http://[fe80::1]/", "reject"),
    ("http://[fc00::1]/", "reject"),
    ("http://[::ffff:127.0.0.1]/", "reject"),
    ("http://[::ffff:10.0.0.1]/", "reject"),
    ("https://user:pw@8.8.8.8/", "reject"),
    ("https://user@8.8.8.8/", "reject"),
    ("http://8.8.8.8:8080/", "reject"),
    ("http://8.8.8.8:22/", "reject"),
    ("http://8.8.8.8:99999/", "reject"),

    # --- Phase 2 VS2 additions (>= 30 new edge case vectors) ---
    # Non-canonical IPv4 formats (dword, hex, octal, partial dotted)
    ("http://2130706433/", "reject"),
    ("http://0x7f.1/", "reject"),
    ("http://127.1/", "reject"),
    ("http://0177.0.0.1/", "reject"),
    ("http://0x7f.0.0.1/", "reject"),
    ("http://1.2.3.04/", "reject"),
    # IPv4-mapped IPv6 edge cases
    ("http://[::ffff:7f00:1]/", "reject"),
    ("http://[::ffff:8.8.8.8]/", "accept"),
    # Authority confusion & credentials
    ("http://8.8.8.8@127.0.0.1/", "reject"),
    ("http://127.0.0.1#@8.8.8.8/", "reject"),
    ("http://8.8.8.8\\@127.0.0.1/", "reject"),
    ("http://8.8.8.8\\test", "reject"),
    # Scheme casing
    ("HTTP://8.8.8.8/", "accept"),
    ("HTTPS://8.8.8.8/", "accept"),
    ("Http://1.1.1.1/", "accept"),
    # Whitespace and control characters
    ("http://8.8.8.8\t/", "reject"),
    ("http://8.8.8.8\n/", "reject"),
    ("http://8.8.8.8\r/", "reject"),
    ("http:// 8.8.8.8/", "reject"),
    ("http://8.8.8.8 /", "reject"),
    # Port variants
    ("http://8.8.8.8:0/", "reject"),
    ("http://8.8.8.8:65536/", "reject"),
    ("http://8.8.8.8:65535/", "reject"),
    ("http://8.8.8.8:1/", "reject"),
    ("http://8.8.8.8:80a/", "reject"),
    ("http://8.8.8.8:80/", "accept"),
    ("https://8.8.8.8:443/", "accept"),
    ("http://8.8.8.8:443/", "accept"),
    ("https://8.8.8.8:80/", "accept"),
    # Reserved & Special IPv4/IPv6 CIDRs
    ("http://255.255.255.255/", "reject"),
    ("http://192.0.2.1/", "reject"),
    ("http://198.51.100.1/", "reject"),
    ("http://203.0.113.1/", "reject"),
    ("http://198.18.0.1/", "reject"),
    ("http://192.0.0.1/", "reject"),
    ("http://240.0.0.1/", "reject"),
    ("http://239.255.255.250/", "reject"),
    ("http://[ff02::1]/", "reject"),
    ("http://[2001:db8::1]/", "reject"),
    ("http://[100::1]/", "reject"),
    ("http://[::]/", "reject"),
    # Public IPs
    ("http://9.9.9.9/", "accept"),
    ("https://1.0.0.1/", "accept"),
    ("http://[2606:4700:4700::1001]/", "accept"),
    # Non-ASCII rejection
    ("http://8.8.8.8/café", "reject"),
]


def tier_policy_vectors() -> List[Dict[str, Any]]:
    t = HardwareTelemetry(cpu_sample_ms=0)
    cases: List[Dict[str, Any]] = []

    def add(avail, load, cpu, battery, cores):
        t.cpu_count = cores
        b = t._calculate_budget(avail, load, cpu, battery)
        cases.append({
            "input": {"avail_ram_mb": avail, "memory_load_pct": load, "cpu_load_pct": cpu, "battery": battery, "cpu_cores": cores},
            "expected": {"compute_tier": b.compute_tier, "max_context_bytes": b.max_context_bytes,
                         "allow_speculation": b.allow_speculation, "thread_pool_limit": b.thread_pool_limit,
                         "reasons": b.reasons},
        })

    for avail in (None, 100, 511.9, 512, 1500, 2047.9, 2048, 8000):
        for load in (None, 10, 74, 75, 89, 90, 100):
            add(avail, load, None, None, 8)
    batteries = (None, {"percent": 10, "on_ac": False}, {"percent": 10, "on_ac": True}, {"percent": 50, "on_ac": False})
    for avail in (100, 1500, 8000):
        for load in (10, 80):
            for bat in batteries:
                for cpu in (None, 95):
                    for cores in (1, 2, 8):
                        add(avail, load, cpu, bat, cores)
    return cases


def url_policy_vectors() -> List[Dict[str, str]]:
    out = []
    for url, expected in URL_CASES:
        out.append({"url": url, "expected": expected})
    return out


def evaluate_url(url: str) -> str:
    try:
        validate_url(url)
        return "accept"
    except UrlRejected:
        return "reject"


def write_vectors(directory: str = OUT_DIR) -> None:
    os.makedirs(directory, exist_ok=True)
    for name, data in (("tier_policy_vectors.json", tier_policy_vectors()), ("url_policy_vectors.json", url_policy_vectors())):
        with open(os.path.join(directory, name), "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=1, sort_keys=True)
            f.write("\n")


# ---------------------------------------------------------------- Differential Fuzzing
def generate_fuzz_dataset(num_cases: int, seed: int) -> Dict[str, Any]:
    rng = random.Random(seed)
    t = HardwareTelemetry(cpu_sample_ms=0)

    tier_cases = []
    half = num_cases // 2
    for _ in range(half):
        avail = None if rng.random() < 0.15 else rng.choice([rng.uniform(0, 10000), 511.9, 512.0, 2047.9, 2048.0])
        load = None if rng.random() < 0.15 else rng.choice([rng.randint(0, 100), 74, 75, 89, 90])
        cpu = None if rng.random() < 0.2 else rng.choice([rng.uniform(0, 100), 89.9, 90.0, 95.0])
        cores = rng.choice([1, 2, 4, 8, 16, 32])
        if rng.random() < 0.3:
            bat = None
        else:
            bat = {
                "percent": None if rng.random() < 0.1 else rng.choice([5, 19, 20, 50, 100]),
                "on_ac": None if rng.random() < 0.1 else rng.choice([True, False]),
            }

        t.cpu_count = cores
        b = t._calculate_budget(avail, load, cpu, bat)
        tier_cases.append({
            "input": {
                "avail_ram_mb": round(avail, 2) if avail is not None else None,
                "memory_load_pct": load,
                "cpu_load_pct": round(cpu, 2) if cpu is not None else None,
                "battery": bat,
                "cpu_cores": cores,
            },
            "expected": {
                "compute_tier": b.compute_tier,
                "max_context_bytes": b.max_context_bytes,
                "allow_speculation": b.allow_speculation,
                "thread_pool_limit": b.thread_pool_limit,
                "reasons": b.reasons,
            },
        })

    # Fuzz URL cases
    url_cases = []
    sample_schemes = ["http", "https", "HTTP", "HTTPS", "ftp", "gopher", "file", "ws", ""]
    sample_ips = [
        "8.8.8.8", "1.1.1.1", "127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254",
        "0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255", "100.64.0.1",
        "192.0.2.1", "198.51.100.1", "203.0.113.1",
        "[::1]", "[::]", "[fe80::1]", "[fc00::1]", "[2606:4700:4700::1111]",
        "[::ffff:127.0.0.1]", "[::ffff:8.8.8.8]", "[::ffff:7f00:1]",
        "2130706433", "0x7f.1", "127.1", "0177.0.0.1", "8.8.8.8:80",
    ]
    sample_ports = ["", ":80", ":443", ":8080", ":0", ":65535", ":65536", ":invalid"]

    for _ in range(num_cases - half):
        scheme = rng.choice(sample_schemes)
        ip = rng.choice(sample_ips)
        port = rng.choice(sample_ports)
        path = rng.choice(["/", "/path", "/query?x=1", "/#frag", ""])

        # Mutations: injection of @, backslash, control chars, whitespace
        mutation = rng.random()
        if mutation < 0.1:
            url = f"{scheme}://user:pw@{ip}{port}{path}" if scheme else f"user:pw@{ip}{port}{path}"
        elif mutation < 0.2:
            url = f"{scheme}://{ip}{port}\\test"
        elif mutation < 0.25:
            url = f"{scheme}://{ip}\t{port}{path}"
        elif mutation < 0.3:
            url = f"{scheme}://{ip}\n{port}{path}"
        else:
            url = f"{scheme}://{ip}{port}{path}" if scheme else f"{ip}{port}{path}"

        expected = evaluate_url(url)
        url_cases.append({"url": url, "expected": expected})

    return {"tier_cases": tier_cases, "url_cases": url_cases}


def run_differential_test(num_cases: int, seed: int) -> int:
    dataset = generate_fuzz_dataset(num_cases, seed)
    fuzz_file = os.path.join(OUT_DIR, "fuzz_vectors.json")
    with open(fuzz_file, "w", encoding="utf-8") as f:
        json.dump(dataset, f)

    core_dir = os.path.join(os.path.dirname(HERE), "core")
    print(f"Generated {len(dataset['tier_cases'])} tier and {len(dataset['url_cases'])} URL fuzz inputs (seed={seed}).")
    print("Running differential verification in pai-core...")

    env = os.environ.copy()
    winlibs = r"C:\Users\hp\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin"
    cargo_bin = os.path.expanduser(r"~/.cargo/bin")
    env["PATH"] = f"{winlibs};{cargo_bin};" + env.get("PATH", "")
    import shutil
    cargo_exe = shutil.which("cargo", path=env["PATH"]) or os.path.join(cargo_bin, "cargo.exe")
    cmd = [cargo_exe, "run", "--quiet", "--", "--differential", fuzz_file]

    proc = subprocess.run(cmd, cwd=core_dir, env=env, capture_output=True, text=True)
    print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)

    if os.path.exists(fuzz_file):
        os.remove(fuzz_file)

    if proc.returncode != 0:
        print("Differential fuzz test FAILED with mismatches!")
        return 1
    print("Differential fuzz test PASSED: 0 mismatches!")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="PAI Conformance Generator & Differential Fuzzer")
    parser.add_argument("--fuzz", type=int, default=0, help="Run differential fuzzer with N inputs")
    parser.add_argument("--seed", type=int, default=42, help="Seed for random fuzzer")
    args = parser.parse_args()

    if args.fuzz > 0:
        sys.exit(run_differential_test(args.fuzz, args.seed))

    write_vectors()
    print(f"wrote {len(tier_policy_vectors())} tier vectors and {len(url_policy_vectors())} URL vectors to {OUT_DIR}")
    sys.exit(0)


if __name__ == "__main__":
    main()
