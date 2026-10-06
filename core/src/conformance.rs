//! Conformance vector runner (VS2)
//! Reads golden vector files and validates that Rust implementations
//! match the Python specification with 0 discrepancies.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::tier::{calculate_budget, HardwareBudget, TierInput};
use crate::url_policy::evaluate_url;

#[derive(Debug, Deserialize)]
pub struct TierVectorCase {
    pub input: TierInput,
    pub expected: HardwareBudget,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UrlVectorCase {
    pub url: String,
    pub expected: String,
}

#[derive(Debug, Deserialize)]
pub struct DifferentialDataset {
    pub tier_cases: Vec<TierVectorCase>,
    pub url_cases: Vec<UrlVectorCase>,
}

pub fn run_tier_conformance(path: &Path) -> Result<usize, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let cases: Vec<TierVectorCase> = serde_json::from_reader(reader)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    let mut failed = 0;
    for (idx, case) in cases.iter().enumerate() {
        let got = calculate_budget(
            case.input.avail_ram_mb,
            case.input.memory_load_pct,
            case.input.cpu_load_pct,
            case.input.battery.clone(),
            case.input.cpu_cores,
        );
        if got != case.expected {
            eprintln!(
                "TIER VECTOR MISMATCH at index {}:\n  Input: {:?}\n  Expected: {:?}\n  Actual:   {:?}",
                idx, case.input, case.expected, got
            );
            failed += 1;
        }
    }

    if failed > 0 {
        Err(format!("{} tier vectors failed", failed))
    } else {
        Ok(cases.len())
    }
}

pub fn run_url_conformance(path: &Path) -> Result<usize, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let cases: Vec<UrlVectorCase> = serde_json::from_reader(reader)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    let mut failed = 0;
    for (idx, case) in cases.iter().enumerate() {
        let got = evaluate_url(&case.url);
        if got != case.expected {
            eprintln!(
                "URL VECTOR MISMATCH at index {}:\n  URL: {}\n  Expected: {}\n  Actual:   {}",
                idx, case.url, case.expected, got
            );
            failed += 1;
        }
    }

    if failed > 0 {
        Err(format!("{} url vectors failed", failed))
    } else {
        Ok(cases.len())
    }
}

pub fn run_all_conformance(dir: &Path) -> Result<(usize, usize), String> {
    let tier_path = dir.join("tier_policy_vectors.json");
    let url_path = dir.join("url_policy_vectors.json");

    let tier_count = run_tier_conformance(&tier_path)?;
    let url_count = run_url_conformance(&url_path)?;

    Ok((tier_count, url_count))
}

pub fn run_differential_validation(path: &Path) -> Result<(usize, usize), String> {
    let file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let dataset: DifferentialDataset = serde_json::from_reader(reader)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    let mut tier_failed = 0;
    for (idx, case) in dataset.tier_cases.iter().enumerate() {
        let got = calculate_budget(
            case.input.avail_ram_mb,
            case.input.memory_load_pct,
            case.input.cpu_load_pct,
            case.input.battery.clone(),
            case.input.cpu_cores,
        );
        if got != case.expected {
            eprintln!(
                "DIFF TIER MISMATCH at index {}:\n  Input: {:?}\n  Expected: {:?}\n  Actual:   {:?}",
                idx, case.input, case.expected, got
            );
            tier_failed += 1;
        }
    }

    let mut url_failed = 0;
    for (idx, case) in dataset.url_cases.iter().enumerate() {
        let got = evaluate_url(&case.url);
        if got != case.expected {
            eprintln!(
                "DIFF URL MISMATCH at index {}:\n  URL: {:?}\n  Expected: {}\n  Actual:   {}",
                idx, case.url, case.expected, got
            );
            url_failed += 1;
        }
    }

    if tier_failed > 0 || url_failed > 0 {
        Err(format!(
            "Differential validation failed: {} tier mismatches, {} URL mismatches",
            tier_failed, url_failed
        ))
    } else {
        Ok((dataset.tier_cases.len(), dataset.url_cases.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn find_conformance_dir() -> PathBuf {
        let candidates = [
            PathBuf::from("../research/conformance"),
            PathBuf::from("research/conformance"),
            PathBuf::from("../../research/conformance"),
        ];
        for c in &candidates {
            if c.exists() && c.join("tier_policy_vectors.json").exists() {
                return c.clone();
            }
        }
        PathBuf::from("../research/conformance")
    }

    #[test]
    fn test_tier_vectors_conformance() {
        let dir = find_conformance_dir();
        let path = dir.join("tier_policy_vectors.json");
        if path.exists() {
            let count = run_tier_conformance(&path).expect("Tier vectors must pass");
            assert!(count >= 200, "Must run at least 200 tier vectors");
        }
    }

    #[test]
    fn test_url_vectors_conformance() {
        let dir = find_conformance_dir();
        let path = dir.join("url_policy_vectors.json");
        if path.exists() {
            let count = run_url_conformance(&path).expect("URL vectors must pass");
            assert!(count >= 28, "Must run at least 28 URL vectors");
        }
    }
}
