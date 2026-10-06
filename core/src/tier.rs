//! Tier policy module (VS2)
//! Direct, pure translation of Python `_calculate_budget`.

use serde::{Deserialize, Serialize};

pub const COMPRESSED_AVAIL_MB: f64 = 512.0;
pub const COMPRESSED_LOAD_PCT: f64 = 90.0;
pub const BALANCED_AVAIL_MB: f64 = 2048.0;
pub const BALANCED_LOAD_PCT: f64 = 75.0;
pub const LOW_BATTERY_PCT: f64 = 20.0;
pub const HOT_CPU_LOAD_PCT: f64 = 90.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputeTier {
    HIGH,
    BALANCED,
    COMPRESSED,
}

impl ComputeTier {
    pub fn downgrade(self) -> Self {
        match self {
            ComputeTier::HIGH => ComputeTier::BALANCED,
            ComputeTier::BALANCED => ComputeTier::COMPRESSED,
            ComputeTier::COMPRESSED => ComputeTier::COMPRESSED,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatteryInfo {
    pub percent: Option<f64>,
    pub on_ac: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardwareBudget {
    pub allow_speculation: bool,
    pub compute_tier: ComputeTier,
    pub max_context_bytes: u64,
    pub reasons: Vec<String>,
    pub thread_pool_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TierInput {
    pub avail_ram_mb: Option<f64>,
    pub memory_load_pct: Option<f64>,
    pub cpu_load_pct: Option<f64>,
    pub battery: Option<BatteryInfo>,
    pub cpu_cores: usize,
}

pub fn calculate_budget(
    avail_ram_mb: Option<f64>,
    memory_load_pct: Option<f64>,
    cpu_load_pct: Option<f64>,
    battery: Option<BatteryInfo>,
    cpu_cores: usize,
) -> HardwareBudget {
    let mut reasons = Vec::new();

    let mut tier = match (avail_ram_mb, memory_load_pct) {
        (Some(avail), Some(load)) => {
            if avail < COMPRESSED_AVAIL_MB || load >= COMPRESSED_LOAD_PCT {
                reasons.push("critical-memory".to_string());
                ComputeTier::COMPRESSED
            } else if avail < BALANCED_AVAIL_MB || load >= BALANCED_LOAD_PCT {
                reasons.push("memory-pressure".to_string());
                ComputeTier::BALANCED
            } else {
                ComputeTier::HIGH
            }
        }
        _ => {
            reasons.push("memory-telemetry-unavailable".to_string());
            ComputeTier::BALANCED
        }
    };

    let mut speculation_ok = true;
    let on_low_battery = match battery {
        Some(ref b) => {
            b.on_ac == Some(false) && b.percent.is_some() && (b.percent.unwrap() < LOW_BATTERY_PCT)
        }
        None => false,
    };
    if on_low_battery {
        tier = tier.downgrade();
        speculation_ok = false;
        reasons.push("low-battery".to_string());
    }

    let cpu_hot = match cpu_load_pct {
        Some(load) => load >= HOT_CPU_LOAD_PCT,
        None => false,
    };
    if cpu_hot {
        speculation_ok = false;
        reasons.push("cpu-saturated".to_string());
    }

    let mut threads = match tier {
        ComputeTier::COMPRESSED => 1,
        ComputeTier::BALANCED => std::cmp::min(2, cpu_cores),
        ComputeTier::HIGH => cpu_cores,
    };
    if cpu_hot {
        threads = std::cmp::max(1, threads / 2);
    }

    let max_context_bytes = match tier {
        ComputeTier::HIGH => 64 * 1024 * 1024,
        ComputeTier::BALANCED => 16 * 1024 * 1024,
        ComputeTier::COMPRESSED => 2 * 1024 * 1024,
    };

    let allow_speculation = tier == ComputeTier::HIGH && speculation_ok;

    HardwareBudget {
        allow_speculation,
        compute_tier: tier,
        max_context_bytes,
        reasons,
        thread_pool_limit: threads,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_inputs_fallback_to_balanced() {
        let budget = calculate_budget(None, None, None, None, 4);
        assert_eq!(budget.compute_tier, ComputeTier::BALANCED);
        assert_eq!(budget.reasons, vec!["memory-telemetry-unavailable"]);
        assert_eq!(budget.max_context_bytes, 16 * 1024 * 1024);
        assert!(!budget.allow_speculation);
        assert_eq!(budget.thread_pool_limit, 2);
    }

    #[test]
    fn test_boundaries() {
        // 511.9 -> COMPRESSED, 512.0 -> BALANCED (at low load)
        let b1 = calculate_budget(Some(511.9), Some(10.0), None, None, 8);
        assert_eq!(b1.compute_tier, ComputeTier::COMPRESSED);

        let b2 = calculate_budget(Some(512.0), Some(10.0), None, None, 8);
        assert_eq!(b2.compute_tier, ComputeTier::BALANCED);

        // 2047.9 -> BALANCED, 2048.0 -> HIGH
        let b3 = calculate_budget(Some(2047.9), Some(10.0), None, None, 8);
        assert_eq!(b3.compute_tier, ComputeTier::BALANCED);

        let b4 = calculate_budget(Some(2048.0), Some(10.0), None, None, 8);
        assert_eq!(b4.compute_tier, ComputeTier::HIGH);
    }

    #[test]
    fn test_battery_downgrade() {
        let bat = Some(BatteryInfo {
            percent: Some(15.0),
            on_ac: Some(false),
        });
        let b = calculate_budget(Some(8000.0), Some(10.0), None, bat, 8);
        assert_eq!(b.compute_tier, ComputeTier::BALANCED);
        assert_eq!(b.reasons, vec!["low-battery"]);
        assert!(!b.allow_speculation);
    }
}
