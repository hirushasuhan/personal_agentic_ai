//! Personal Agentic AI - Rust Core CLI (VS2)
//!
//! Provides the `--conformance <dir>` runner and `--differential <file>` tester
//! for language-neutral golden vectors.
//! Fake telemetry from VS1 skeleton has been removed per ADR-004 and the claims policy.

use std::env;
use std::path::{Path, PathBuf};
use std::process;

use pai_core::conformance::{run_all_conformance, run_differential_validation};

fn print_help() {
    println!("Personal Agentic AI (PAI) Core v0.1.0 (VS2)");
    println!();
    println!("USAGE:");
    println!("    pai-core [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --conformance <DIR>      Run tier and URL policy conformance vectors from DIR");
    println!("                             (defaults to ../research/conformance if omitted)");
    println!("    --differential <FILE>    Run differential fuzz validation dataset from FILE");
    println!("    --help, -h               Print this help message and exit");
    println!("    --version, -v            Print version information and exit");
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
