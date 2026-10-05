"""
Hardware Telemetry Module (Python Research Prototype)
Part of Personal Agentic AI (PAI) - The Hardware Self-Awareness Pillar.

Queries host resources (RAM, CPU load, battery) in real time and converts them
into a dynamic HardwareBudget for the Stateless Reasoning Engine.

Sources, in priority order:
  1. Native OS interface  (Windows: kernel32 via ctypes | Linux: /proc, /sys)
  2. psutil               (optional, any OS)
  3. Conservative fallback - NEVER invented numbers: if nothing can be read the
     budget is clamped to BALANCED and the snapshot says so (source="unavailable").

The tier policy constants below are the single source of truth. The docs
(docs/PROTOTYPE_SPEC.md) and the future C++ daemon must mirror them.
"""

from __future__ import annotations

import os
import sys
import time
import ctypes
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = 1  # IPC contract version (see docs/ARCHITECTURE.md, "Telemetry IPC schema")

MiB = 1024 * 1024

# ---- Tier policy (single source of truth) -----------------------------------
COMPRESSED_AVAIL_MB = 512
COMPRESSED_LOAD_PCT = 90
BALANCED_AVAIL_MB = 2048
BALANCED_LOAD_PCT = 75
LOW_BATTERY_PCT = 20
HOT_CPU_LOAD_PCT = 90

TIER_ORDER = ["HIGH", "BALANCED", "COMPRESSED"]
CONTEXT_BYTES = {"HIGH": 64 * MiB, "BALANCED": 16 * MiB, "COMPRESSED": 2 * MiB}


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_uint32),
        ("dwMemoryLoad", ctypes.c_uint32),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus", ctypes.c_ubyte),        # 0 = battery, 1 = AC, 255 = unknown
        ("BatteryFlag", ctypes.c_ubyte),
        ("BatteryLifePercent", ctypes.c_ubyte),  # 0-100, 255 = unknown
        ("SystemStatusFlag", ctypes.c_ubyte),
        ("BatteryLifeTime", ctypes.c_uint32),
        ("BatteryFullLifeTime", ctypes.c_uint32),
    ]


@dataclass
class HardwareBudget:
    compute_tier: str        # 'HIGH', 'BALANCED', 'COMPRESSED'
    max_context_bytes: int   # Max bytes allowed in working RAM
    allow_speculation: bool  # Whether multi-branch reasoning is permitted
    thread_pool_limit: int   # Concurrency limit
    throttle_warning: str    # Human-readable explanation
    reasons: List[str] = field(default_factory=list)  # Machine-readable downgrade reasons


class HardwareTelemetry:
    def __init__(self, cpu_sample_ms: int = 50):
        self.is_windows = sys.platform == "win32"
        self.is_linux = sys.platform.startswith("linux")
        self.cpu_count = os.cpu_count() or 1
        self.cpu_sample_ms = cpu_sample_ms
        self._prev_cpu: Optional[Tuple[int, int]] = None  # (idle, total)

    # ------------------------------------------------------------------ public
    def get_system_snapshot(self) -> Dict[str, Any]:
        """Queries the OS for current hardware resource statistics."""
        total_b, avail_b, load_pct, source = self._read_memory()
        cpu_load = self._read_cpu_load()
        battery = self._read_battery()

        avail_mb = None if avail_b is None else avail_b / MiB
        budget = self._calculate_budget(avail_mb, load_pct, cpu_load, battery)

        return {
            "schema_version": SCHEMA_VERSION,
            "timestamp": time.time(),
            "source": source,
            "platform": sys.platform,
            "cpu_cores": self.cpu_count,
            "cpu_load_pct": cpu_load,
            "total_ram_gb": None if total_b is None else round(total_b / 1024 ** 3, 2),
            "avail_ram_gb": None if avail_b is None else round(avail_b / 1024 ** 3, 2),
            "avail_ram_mb": None if avail_mb is None else round(avail_mb, 1),
            "memory_load_pct": load_pct,
            "battery": battery,  # {"percent": int|None, "on_ac": bool|None} or None (desktop)
            "budget": budget,
        }

    @staticmethod
    def to_ipc_dict(snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """JSON-serialisable form of a snapshot - the Phase 2 named-pipe message."""
        out = dict(snapshot)
        out["budget"] = asdict(snapshot["budget"])
        return out

    # ----------------------------------------------------------------- policy
    def _calculate_budget(
        self,
        avail_ram_mb: Optional[float],
        load_pct: Optional[int],
        cpu_load_pct: Optional[float] = None,
        battery: Optional[Dict[str, Any]] = None,
    ) -> HardwareBudget:
        """Dynamically adapts the engine's compute parameters based on host resources."""
        reasons: List[str] = []

        if avail_ram_mb is None or load_pct is None:
            tier = "BALANCED"
            reasons.append("memory-telemetry-unavailable")
        elif avail_ram_mb < COMPRESSED_AVAIL_MB or load_pct >= COMPRESSED_LOAD_PCT:
            tier = "COMPRESSED"
            reasons.append("critical-memory")
        elif avail_ram_mb < BALANCED_AVAIL_MB or load_pct >= BALANCED_LOAD_PCT:
            tier = "BALANCED"
            reasons.append("memory-pressure")
        else:
            tier = "HIGH"

        speculation_ok = True
        on_low_battery = (
            battery is not None
            and battery.get("on_ac") is False
            and battery.get("percent") is not None
            and battery["percent"] < LOW_BATTERY_PCT
        )
        if on_low_battery:
            tier = self._downgrade(tier)
            speculation_ok = False
            reasons.append("low-battery")

        cpu_hot = cpu_load_pct is not None and cpu_load_pct >= HOT_CPU_LOAD_PCT
        if cpu_hot:
            speculation_ok = False
            reasons.append("cpu-saturated")

        if tier == "COMPRESSED":
            threads = 1
        elif tier == "BALANCED":
            threads = min(2, self.cpu_count)
        else:
            threads = self.cpu_count
        if cpu_hot:
            threads = max(1, threads // 2)

        notes = {
            "HIGH": "Normal operation. High performance tier enabled.",
            "BALANCED": "Moderate resource pressure. Context bounds strictly capped.",
            "COMPRESSED": "CRITICAL RESOURCE LOAD: emergency compression mode. Immediate RAM zeroization enforced.",
        }
        note = notes[tier]
        if "memory-telemetry-unavailable" in reasons:
            note = "Memory telemetry unavailable: conservative BALANCED budget applied."
        if "low-battery" in reasons:
            note += " Low battery: tier lowered, speculation disabled."
        if "cpu-saturated" in reasons:
            note += " CPU saturated: speculation disabled, threads halved."

        return HardwareBudget(
            compute_tier=tier,
            max_context_bytes=CONTEXT_BYTES[tier],
            allow_speculation=(tier == "HIGH" and speculation_ok),
            thread_pool_limit=threads,
            throttle_warning=note,
            reasons=reasons,
        )

    @staticmethod
    def _downgrade(tier: str) -> str:
        return TIER_ORDER[min(TIER_ORDER.index(tier) + 1, len(TIER_ORDER) - 1)]

    # ------------------------------------------------------------ memory reads
    def _read_memory(self) -> Tuple[Optional[int], Optional[int], Optional[int], str]:
        """Returns (total_bytes, avail_bytes, load_pct, source)."""
        try:
            if self.is_windows:
                return (*self._win_memory(), "win32-kernel32")
            if self.is_linux:
                return (*self._linux_memory(), "linux-procfs")
        except Exception:
            pass  # fall through to psutil
        try:
            import psutil  # optional dependency
            vm = psutil.virtual_memory()
            return vm.total, vm.available, int(vm.percent), "psutil"
        except Exception:
            return None, None, None, "unavailable"

    @staticmethod
    def _win_memory() -> Tuple[int, int, int]:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
        kernel32.GlobalMemoryStatusEx.restype = ctypes.c_int
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            raise OSError(ctypes.get_last_error(), "GlobalMemoryStatusEx failed")  # type: ignore[attr-defined]
        return int(stat.ullTotalPhys), int(stat.ullAvailPhys), int(stat.dwMemoryLoad)

    @staticmethod
    def _linux_memory() -> Tuple[int, int, int]:
        info: Dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="ascii") as f:
            for line in f:
                key, _, rest = line.partition(":")
                parts = rest.split()
                if parts:
                    info[key] = int(parts[0]) * 1024  # kB -> bytes
        total = info["MemTotal"]
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        load = int(round((total - avail) * 100 / total)) if total else 0
        return total, avail, load

    # --------------------------------------------------------------- cpu reads
    def _cpu_times(self) -> Optional[Tuple[int, int]]:
        """Returns cumulative (idle, total) counters, or None if unsupported."""
        try:
            if self.is_windows:
                from ctypes import wintypes
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
                idle, kern, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
                if not kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user)):
                    return None
                to_int = lambda ft: (ft.dwHighDateTime << 32) | ft.dwLowDateTime
                i, k, u = to_int(idle), to_int(kern), to_int(user)
                return i, k + u  # kernel time already includes idle time
            if self.is_linux:
                with open("/proc/stat", "r", encoding="ascii") as f:
                    fields = [int(x) for x in f.readline().split()[1:9]]
                return fields[3] + fields[4], sum(fields)  # idle + iowait, total
        except Exception:
            return None
        return None

    def _read_cpu_load(self) -> Optional[float]:
        cur = self._cpu_times()
        if cur is None:
            try:
                import psutil
                return float(psutil.cpu_percent(interval=self.cpu_sample_ms / 1000 or None))
            except Exception:
                return None
        prev = self._prev_cpu
        if prev is None:
            if self.cpu_sample_ms <= 0:
                self._prev_cpu = cur
                return None
            time.sleep(self.cpu_sample_ms / 1000)
            prev, cur = cur, (self._cpu_times() or cur)
        self._prev_cpu = cur
        d_total = cur[1] - prev[1]
        d_idle = cur[0] - prev[0]
        if d_total <= 0:
            return None
        return round(max(0.0, min(100.0, (1 - d_idle / d_total) * 100)), 1)

    # ------------------------------------------------------------ battery read
    def _read_battery(self) -> Optional[Dict[str, Any]]:
        try:
            if self.is_windows:
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
                kernel32.GetSystemPowerStatus.argtypes = [ctypes.POINTER(SYSTEM_POWER_STATUS)]
                st = SYSTEM_POWER_STATUS()
                if not kernel32.GetSystemPowerStatus(ctypes.byref(st)):
                    return None
                if st.BatteryFlag & 128:  # 128 = no system battery (desktop)
                    return None
                pct = None if st.BatteryLifePercent == 255 else int(st.BatteryLifePercent)
                on_ac = None if st.ACLineStatus == 255 else bool(st.ACLineStatus)
                return {"percent": pct, "on_ac": on_ac}
            if self.is_linux:
                base = "/sys/class/power_supply"
                for name in sorted(os.listdir(base)):
                    if not name.startswith("BAT"):
                        continue
                    with open(f"{base}/{name}/capacity", encoding="ascii") as f:
                        pct = int(f.read().strip())
                    with open(f"{base}/{name}/status", encoding="ascii") as f:
                        status = f.read().strip()
                    return {"percent": pct, "on_ac": status != "Discharging"}
                return None
        except Exception:
            pass
        try:
            import psutil
            b = psutil.sensors_battery()
            if b is not None:
                return {"percent": int(b.percent), "on_ac": bool(b.power_plugged)}
        except Exception:
            pass
        return None


def format_snapshot(snap: Dict[str, Any]) -> str:
    b: HardwareBudget = snap["budget"]
    na = lambda v, unit="": "n/a" if v is None else f"{v}{unit}"
    batt = snap["battery"]
    batt_s = "none (desktop / unreadable)" if batt is None else f"{na(batt['percent'], '%')} ({'AC' if batt['on_ac'] else 'battery'})"
    return "\n".join([
        f"Platform / Source    : {snap['platform']} / {snap['source']}",
        f"CPU Cores / Load     : {snap['cpu_cores']} / {na(snap['cpu_load_pct'], '%')}",
        f"Total RAM            : {na(snap['total_ram_gb'], ' GB')}",
        f"Available RAM        : {na(snap['avail_ram_gb'], ' GB')} ({na(snap['avail_ram_mb'], ' MB')})",
        f"Memory Load          : {na(snap['memory_load_pct'], '%')}",
        f"Battery              : {batt_s}",
        f"Assigned Tier        : {b.compute_tier}",
        f"Max Working Context  : {b.max_context_bytes / MiB:.1f} MB",
        f"Concurrency / Spec.  : {b.thread_pool_limit} threads / speculation={'on' if b.allow_speculation else 'off'}",
        f"Status Note          : {b.throttle_warning}",
    ])


if __name__ == "__main__":
    print("--- Hardware Telemetry Snapshot ---")
    print(format_snapshot(HardwareTelemetry().get_system_snapshot()))
