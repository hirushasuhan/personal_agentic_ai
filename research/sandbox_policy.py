"""
Sandbox isolation policy-as-code (review risk R5, ADR-003).

Tier 2 of the RSI spec needs a disposable, network-less environment for AI-generated code. On Windows the
default technology is **Windows Sandbox** (Pro/Enterprise; disposable, Hyper-V isolated). This module:

  make_wsb()          builds a .wsb configuration that satisfies the isolation checklist
  validate_wsb()      FAILS CLOSED on any .wsb that does not (unknown elements, networking on, writable
                      mappings beyond the single output folder, drive-root mappings, DOCTYPE tricks ...)
  read_sandbox_results()  treats the one writable channel (the output folder) as hostile input:
                      exactly one `results.json`, size-capped, schema-checked, no links / extra files

Prototype scope: the checks are real and unit-tested; launching Windows Sandbox and collecting results
needs a Windows host and is Phase 4 work (it must be smoke-tested on the target machine).
"""

from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List

MAX_WSB_BYTES = 64 * 1024
MAX_MEMORY_MB = 2048            # RSI spec Tier 2: at most 2 GB
MAX_RESULTS_BYTES = 256 * 1024

REQUIRED_SETTINGS = {           # element -> required value
    "Networking": "Disable",
    "VGpu": "Disable",
    "AudioInput": "Disable",
    "VideoInput": "Disable",
    "PrinterRedirection": "Disable",
    "ClipboardRedirection": "Disable",
    "ProtectedClient": "Enable",
}
ALLOWED_ELEMENTS = set(REQUIRED_SETTINGS) | {"Configuration", "MemoryInMB", "MappedFolders", "MappedFolder",
                                              "HostFolder", "SandboxFolder", "ReadOnly", "LogonCommand", "Command"}


@dataclass
class SandboxSpec:
    input_dir: str                      # host folder with the candidate code - mapped READ-ONLY
    output_dir: str                     # host folder for results.json - the ONLY writable mapping
    command: str                        # run at logon inside the sandbox
    memory_mb: int = 2048
    sandbox_input: str = r"C:\pai\input"
    sandbox_output: str = r"C:\pai\output"


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def make_wsb(spec: SandboxSpec) -> str:
    if spec.memory_mb > MAX_MEMORY_MB:
        raise ValueError(f"memory_mb exceeds the {MAX_MEMORY_MB} MB ceiling")
    settings = "\n".join(f"  <{k}>{v}</{k}>" for k, v in REQUIRED_SETTINGS.items())
    return f"""<Configuration>
{settings}
  <MemoryInMB>{spec.memory_mb}</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{_esc(spec.input_dir)}</HostFolder>
      <SandboxFolder>{_esc(spec.sandbox_input)}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{_esc(spec.output_dir)}</HostFolder>
      <SandboxFolder>{_esc(spec.sandbox_output)}</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>{_esc(spec.command)}</Command>
  </LogonCommand>
</Configuration>
"""


def _is_drive_or_profile_root(path: str) -> bool:
    p = path.replace("/", "\\").rstrip("\\").lower()
    if len(p) <= 2 and (len(p) == 0 or p[-1:] == ":"):
        return True
    parts = [x for x in p.split("\\") if x]
    return p in ("c:\\users", "c:\\windows", "c:\\program files", "c:\\program files (x86)", "c:") or (
        len(parts) == 3 and parts[1] == "users")  # C:\Users\<name> itself


def validate_wsb(xml_text: str) -> List[str]:
    """Returns a list of violations; an empty list means the configuration meets the checklist."""
    v: List[str] = []
    if len(xml_text.encode("utf-8")) > MAX_WSB_BYTES:
        return ["configuration too large"]
    low = xml_text.lower()
    if "<!doctype" in low or "<!entity" in low:
        return ["DOCTYPE/ENTITY declarations are not allowed"]
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return [f"not valid XML: {e}"]
    if root.tag != "Configuration":
        return ["root element must be <Configuration>"]

    for el in root.iter():
        if el.tag not in ALLOWED_ELEMENTS:
            v.append(f"unknown element <{el.tag}> (fail closed)")

    for name, required in REQUIRED_SETTINGS.items():
        found = root.findall(name)
        if len(found) != 1:
            v.append(f"<{name}> must appear exactly once (explicitly set to {required})")
        elif (found[0].text or "").strip() != required:
            v.append(f"<{name}> must be {required}")

    mem = root.findall("MemoryInMB")
    if len(mem) != 1 or not (mem[0].text or "").strip().isdigit():
        v.append("<MemoryInMB> must be set once to an integer")
    elif int(mem[0].text.strip()) > MAX_MEMORY_MB:
        v.append(f"<MemoryInMB> exceeds {MAX_MEMORY_MB}")

    folders = root.findall("MappedFolders/MappedFolder")
    if not folders:
        v.append("no mapped input folder: nothing to test")
    writable = 0
    sandbox_paths = set()
    for f in folders:
        host = (f.findtext("HostFolder") or "").strip()
        sbx = (f.findtext("SandboxFolder") or "").strip().lower()
        ro = (f.findtext("ReadOnly") or "").strip().lower()
        if not host or not sbx:
            v.append("MappedFolder needs HostFolder and SandboxFolder")
            continue
        if _is_drive_or_profile_root(host):
            v.append(f"mapping a drive root / profile root is forbidden: {host}")
        if ro not in ("true", "false"):
            v.append(f"ReadOnly must be explicit true/false for {host}")
        if ro != "true":
            writable += 1
        if sbx in sandbox_paths:
            v.append(f"duplicate SandboxFolder {sbx}")
        sandbox_paths.add(sbx)
    if writable > 1:
        v.append(f"{writable} writable mappings; exactly one (the output folder) is allowed")
    if len(root.findall("LogonCommand/Command")) != 1:
        v.append("exactly one <LogonCommand><Command> is required")
    return v


_RESULT_SCHEMA = {"tests_passed": int, "tests_failed": int, "benchmark_ms": (int, float), "stdout_tail": str}


def read_sandbox_results(output_dir: str) -> Dict:
    """The output folder is attacker-controlled: accept ONE small, schema-valid results.json and nothing else."""
    if os.path.islink(output_dir) or not os.path.isdir(output_dir):
        raise ValueError("output directory missing or is a link")
    entries = os.listdir(output_dir)
    if entries != ["results.json"]:
        raise ValueError(f"output folder must contain exactly results.json, found: {sorted(entries)[:5]}")
    path = os.path.join(output_dir, "results.json")
    if os.path.islink(path) or not os.path.isfile(path):
        raise ValueError("results.json is not a regular file")
    if os.path.getsize(path) > MAX_RESULTS_BYTES:
        raise ValueError("results.json too large")
    with open(path, "rb") as f:
        try:
            # utf-8-sig: Windows PowerShell 5.1 `Set-Content -Encoding utf8` writes a BOM; tolerate it.
            data = json.loads(f.read().decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError):
            raise ValueError("results.json is not valid UTF-8 JSON")
    if not isinstance(data, dict) or set(data) != set(_RESULT_SCHEMA):
        raise ValueError("results.json keys do not match the schema")
    for k, t in _RESULT_SCHEMA.items():
        if isinstance(data[k], bool) or not isinstance(data[k], t):
            raise ValueError(f"results.json field {k} has the wrong type")
    if data["tests_passed"] < 0 or data["tests_failed"] < 0 or data["benchmark_ms"] < 0:
        raise ValueError("negative counters")
    data["stdout_tail"] = data["stdout_tail"][-4096:]
    return data
