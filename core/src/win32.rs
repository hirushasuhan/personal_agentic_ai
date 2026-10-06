//! Win32 Native Hardware Telemetry Module (VS3)
//!
//! Provides direct OS queries using Win32 API functions:
//! - `GlobalMemoryStatusEx` for physical and virtual memory
//! - `GetSystemTimes` for CPU utilization
//! - `GetSystemPowerStatus` for battery and AC line status
//!
//! # Safety Invariant Policy (ADR-004 & ADR-009)
//! This is the ONLY file in `core` permitted to contain `unsafe` code.
//! Every `unsafe` block must state its safety justification in a `// SAFETY:` comment.

#![allow(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::tier::{calculate_budget, BatteryInfo, HardwareBudget};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub schema_version: u32,
    pub timestamp: f64,
    pub source: String,
    pub platform: String,
    pub cpu_cores: usize,
    pub cpu_load_pct: Option<f64>,
    pub total_ram_gb: Option<f64>,
    pub avail_ram_gb: Option<f64>,
    pub avail_ram_mb: Option<f64>,
    pub memory_load_pct: Option<f64>,
    pub battery: Option<BatteryInfo>,
    pub budget: HardwareBudget,
}

#[cfg(windows)]
mod imp {
    use std::mem::size_of;
    use std::thread::sleep;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows_sys::Win32::System::Threading::GetSystemTimes;

    use crate::tier::BatteryInfo;

    /// Reads system memory stats via `GlobalMemoryStatusEx`.
    /// Returns `(total_bytes, avail_bytes, load_pct)` if successful, or `None` if failed.
    pub fn read_memory() -> Option<(u64, u64, u32)> {
        let mut stat: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        stat.dwLength = size_of::<MEMORYSTATUSEX>() as u32;

        // SAFETY: `stat` is a properly allocated and aligned MEMORYSTATUSEX struct on the stack,
        // with `dwLength` correctly initialized to `sizeof(MEMORYSTATUSEX)`.
        let ret = unsafe { GlobalMemoryStatusEx(&mut stat) };
        if ret != 0 {
            Some((stat.ullTotalPhys, stat.ullAvailPhys, stat.dwMemoryLoad))
        } else {
            None
        }
    }

    /// Reads system cumulative CPU times via `GetSystemTimes`.
    /// Returns `(idle_time, total_time)` in 100-ns FILETIME ticks.
    pub fn read_cpu_times() -> Option<(u64, u64)> {
        let mut idle: FILETIME = unsafe { std::mem::zeroed() };
        let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
        let mut user: FILETIME = unsafe { std::mem::zeroed() };

        // SAFETY: Pointers passed to `GetSystemTimes` point to valid, aligned, zero-initialized
        // `FILETIME` structures on the stack.
        let ret = unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) };
        if ret != 0 {
            let i = ((idle.dwHighDateTime as u64) << 32) | (idle.dwLowDateTime as u64);
            let k = ((kernel.dwHighDateTime as u64) << 32) | (kernel.dwLowDateTime as u64);
            let u = ((user.dwHighDateTime as u64) << 32) | (user.dwLowDateTime as u64);
            // In Windows, kernel time includes idle time. Total time = kernel + user.
            Some((i, k + u))
        } else {
            None
        }
    }

    /// Measures CPU load percentage by taking two samples `sample_ms` apart.
    pub fn read_cpu_load(sample_ms: u64) -> Option<f64> {
        let t0 = read_cpu_times()?;
        if sample_ms == 0 {
            return None;
        }
        sleep(Duration::from_millis(sample_ms));
        let t1 = read_cpu_times()?;

        let d_total = t1.1.saturating_sub(t0.1);
        let d_idle = t1.0.saturating_sub(t0.0);

        if d_total == 0 {
            return None;
        }

        let load = (1.0 - (d_idle as f64 / d_total as f64)) * 100.0;
        let clamped = load.clamp(0.0, 100.0);
        Some((clamped * 10.0).round() / 10.0)
    }

    /// Reads battery status via `GetSystemPowerStatus`.
    /// Returns `None` if battery is not present (desktop) or if API fails.
    pub fn read_battery() -> Option<BatteryInfo> {
        let mut status: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };

        // SAFETY: `status` is a valid, aligned, zeroed `SYSTEM_POWER_STATUS` structure on the stack.
        let ret = unsafe { GetSystemPowerStatus(&mut status) };
        if ret == 0 {
            return None;
        }

        // Bit 7 (128) indicates no system battery.
        if (status.BatteryFlag & 128) != 0 {
            return None;
        }

        let percent = if status.BatteryLifePercent == 255 {
            None
        } else {
            Some(status.BatteryLifePercent as f64)
        };

        let on_ac = if status.ACLineStatus == 255 {
            None
        } else {
            Some(status.ACLineStatus == 1)
        };

        Some(BatteryInfo { percent, on_ac })
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::tier::BatteryInfo;

    pub fn read_memory() -> Option<(u64, u64, u32)> {
        None
    }

    pub fn read_cpu_times() -> Option<(u64, u64)> {
        None
    }

    pub fn read_cpu_load(_sample_ms: u64) -> Option<f64> {
        None
    }

    pub fn read_battery() -> Option<BatteryInfo> {
        None
    }
}

/// Gathers a complete system hardware telemetry snapshot matching Schema v1.
pub fn get_system_snapshot(cpu_sample_ms: u64) -> SystemSnapshot {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let cores = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);

    let mem_opt = imp::read_memory();
    let cpu_load = imp::read_cpu_load(cpu_sample_ms);
    let battery = imp::read_battery();

    let (total_ram_gb, avail_ram_gb, avail_ram_mb, memory_load_pct, source) = match mem_opt {
        Some((tot_b, avail_b, load_pct)) => {
            let tot_gb = ((tot_b as f64 / (1024.0 * 1024.0 * 1024.0)) * 100.0).round() / 100.0;
            let av_gb = ((avail_b as f64 / (1024.0 * 1024.0 * 1024.0)) * 100.0).round() / 100.0;
            let av_mb = ((avail_b as f64 / (1024.0 * 1024.0)) * 10.0).round() / 10.0;
            (
                Some(tot_gb),
                Some(av_gb),
                Some(av_mb),
                Some(load_pct as f64),
                if cfg!(windows) {
                    "win32-kernel32".to_string()
                } else {
                    "unavailable".to_string()
                },
            )
        }
        None => (None, None, None, None, "unavailable".to_string()),
    };

    let budget = calculate_budget(
        avail_ram_mb,
        memory_load_pct,
        cpu_load,
        battery.clone(),
        cores,
    );

    SystemSnapshot {
        schema_version: SCHEMA_VERSION,
        timestamp: now,
        source,
        platform: if cfg!(windows) {
            "win32".to_string()
        } else {
            "other".to_string()
        },
        cpu_cores: cores,
        cpu_load_pct: cpu_load,
        total_ram_gb,
        avail_ram_gb,
        avail_ram_mb,
        memory_load_pct,
        battery,
        budget,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_generation() {
        let snapshot = get_system_snapshot(10);
        assert_eq!(snapshot.schema_version, 1);
        assert!(snapshot.cpu_cores >= 1);
        assert!(snapshot.timestamp > 0.0);

        #[cfg(windows)]
        {
            assert_eq!(snapshot.source, "win32-kernel32");
            assert_eq!(snapshot.platform, "win32");
            assert!(snapshot.total_ram_gb.is_some());
            assert!(snapshot.avail_ram_mb.is_some());
            assert!(snapshot.memory_load_pct.is_some());
        }
    }

    #[test]
    fn test_memory_read_no_panic() {
        #[cfg(windows)]
        {
            let mem = imp::read_memory();
            assert!(mem.is_some());
            let (tot, avail, load) = mem.unwrap();
            assert!(tot > 0);
            assert!(avail <= tot);
            assert!(load <= 100);
        }
    }

    #[test]
    fn test_cpu_times_monotonic() {
        #[cfg(windows)]
        {
            let t0 = imp::read_cpu_times();
            assert!(t0.is_some());
            std::thread::sleep(std::time::Duration::from_millis(15));
            let t1 = imp::read_cpu_times();
            assert!(t1.is_some());
            let (i0, tot0) = t0.unwrap();
            let (i1, tot1) = t1.unwrap();
            assert!(tot1 >= tot0);
            assert!(i1 >= i0);
        }
    }
}
