//! Personal Agentic AI - Rust Core CLI (VS2 & VS3)
//!
//! Provides:
//! - `--conformance <dir>` runner and `--differential <file>` tester (VS2)
//! - `--telemetry [--json]` native Win32 hardware telemetry inspection (VS3)

#![deny(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process;

use pai_core::conformance::{run_all_conformance, run_differential_validation};
use pai_core::win32::get_system_snapshot;

fn print_help() {
    println!("Personal Agentic AI (PAI) Core v0.1.0 (VS2 & VS3)");
    println!();
    println!("USAGE:");
    println!("    pai-core [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --conformance <DIR>      Run tier and URL policy conformance vectors from DIR");
    println!("                             (defaults to ../research/conformance if omitted)");
    println!("    --differential <FILE>    Run differential fuzz validation dataset from FILE");
    println!("    --telemetry              Query and display host hardware telemetry (Win32)");
    println!("    --json                   Emit JSON output (used with --telemetry)");
    println!("    --help, -h               Print this help message and exit");
    println!("    --version, -v            Print version information and exit");
}

fn print_telemetry_human(snap: &pai_core::win32::SystemSnapshot) {
    println!(
        "PAI Hardware Telemetry Snapshot (Schema v{})",
        snap.schema_version
    );
    println!("--------------------------------------------------");
    println!("Platform:         {}", snap.platform);
    println!("Source:           {}", snap.source);
    println!("CPU Cores:        {}", snap.cpu_cores);
    match snap.cpu_load_pct {
        Some(load) => println!("CPU Load:         {:.1}%", load),
        None => println!("CPU Load:         n/a"),
    }
    match (snap.total_ram_gb, snap.avail_ram_gb, snap.memory_load_pct) {
        (Some(tot), Some(av), Some(load)) => {
            println!(
                "Memory:           {:.2} GB total, {:.2} GB available ({:.0}% load)",
                tot, av, load
            );
        }
        _ => println!("Memory:           unavailable"),
    }
    match snap.battery {
        Some(ref b) => {
            let pct_str = b
                .percent
                .map(|p| format!("{:.0}%", p))
                .unwrap_or_else(|| "unknown".into());
            let ac_str = b
                .on_ac
                .map(|ac| if ac { "on AC" } else { "battery" })
                .unwrap_or("unknown");
            println!("Battery:          {} ({})", pct_str, ac_str);
        }
        None => println!("Battery:          none (desktop/unsupported)"),
    }
    println!("--------------------------------------------------");
    println!("Compute Tier:     {:?}", snap.budget.compute_tier);
    println!("Max Context:      {} bytes", snap.budget.max_context_bytes);
    println!("Speculation:      {}", snap.budget.allow_speculation);
    println!("Thread Limit:     {}", snap.budget.thread_pool_limit);
    if !snap.budget.reasons.is_empty() {
        println!("Reasons:          {}", snap.budget.reasons.join(", "));
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        print_help();
        return;
    }

    let mut i = 1;
    let mut conformance_dir: Option<PathBuf> = None;
    let mut differential_file: Option<PathBuf> = None;
    let mut telemetry_mode = false;
    let mut json_output = false;

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" | "-v" => {
                println!("pai-core 0.1.0");
                return;
            }
            "--telemetry" => {
                telemetry_mode = true;
            }
            "--json" => {
                json_output = true;
            }
            "--conformance" => {
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    conformance_dir = Some(PathBuf::from(&args[i + 1]));
                    i += 1;
                } else {
                    conformance_dir = Some(PathBuf::from("../research/conformance"));
                }
            }
            "--differential" => {
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    differential_file = Some(PathBuf::from(&args[i + 1]));
                    i += 1;
                } else {
                    eprintln!("Error: --differential requires a file path argument");
                    process::exit(1);
                }
            }
            other => {
                eprintln!("Error: Unknown argument '{}'", other);
                print_help();
                process::exit(1);
            }
        }
        i += 1;
    }

    if telemetry_mode {
        let snapshot = get_system_snapshot(50);
        if json_output {
            match serde_json::to_string_pretty(&snapshot) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error: Failed to serialize telemetry snapshot: {}", e);
                    process::exit(1);
                }
            }
        } else {
            print_telemetry_human(&snapshot);
        }
        return;
    }

    if let Some(ref file) = differential_file {
        if !file.exists() {
            eprintln!(
                "Error: Differential dataset file does not exist: {}",
                file.display()
            );
            process::exit(1);
        }

        match run_differential_validation(file) {
            Ok((tier_count, url_count)) => {
                println!(
                    "Differential validation SUCCESS: {} tier cases, {} URL cases compared (0 mismatches).",
                    tier_count, url_count
                );
            }
            Err(err) => {
                eprintln!("Differential validation FAILURE: {}", err);
                process::exit(1);
            }
        }
    }

    if let Some(ref dir) = conformance_dir {
        println!("Running PAI conformance vectors from: {}", dir.display());
        if !dir.exists() {
            eprintln!(
                "Error: Conformance directory does not exist: {}",
                dir.display()
            );
            process::exit(1);
        }

        match run_all_conformance(Path::new(dir)) {
            Ok((tier_count, url_count)) => {
                println!(
                    "Conformance SUCCESS: {} tier vectors, {} URL vectors passed (0 failures).",
                    tier_count, url_count
                );
            }
            Err(err) => {
                eprintln!("Conformance FAILURE: {}", err);
                process::exit(1);
            }
        }
    }
}
