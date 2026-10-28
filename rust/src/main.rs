use clap::Parser;
use sandbox_comparator::formatter::format_markdown_report;
use sandbox_comparator::parsers::parse_auto_report;
use sandbox_comparator::reconciler::EvidenceComparator;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "sandbox-comparator",
    author = "Naman Bhatt <the.namanbhatt109@gmail.com>",
    version = "1.0.0",
    about = "High-performance offline-first malware sandbox comparison and evidence verification engine (Rust Core)"
)]
struct Cli {
    #[arg(
        long,
        default_value = "data/report_format_a_cape.json",
        help = "Path to Report A JSON"
    )]
    report_a: PathBuf,

    #[arg(
        long,
        default_value = "data/report_format_b_falcon.json",
        help = "Path to Report B JSON"
    )]
    report_b: PathBuf,

    #[arg(
        short,
        long,
        help = "Optional output file path to write results"
    )]
    output: Option<PathBuf>,

    #[arg(
        long,
        default_value = "markdown",
        help = "Output format: markdown | json | text"
    )]
    format: String,
}

fn resolve_path(p: &Path) -> PathBuf {
    if p.exists() {
        return p.to_path_buf();
    }
    let parent_attempt = Path::new("..").join(p);
    if parent_attempt.exists() {
        return parent_attempt;
    }
    p.to_path_buf()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "compare" {
        args.remove(1);
    }

    let cli = Cli::parse_from(args);

    let path_a = resolve_path(&cli.report_a);
    let path_b = resolve_path(&cli.report_b);

    if !path_a.exists() {
        eprintln!("Error: Report A file not found: {}", path_a.display());
        std::process::exit(1);
    }
    if !path_b.exists() {
        eprintln!("Error: Report B file not found: {}", path_b.display());
        std::process::exit(1);
    }

    let raw_a_str = fs::read_to_string(&path_a)?;
    let raw_b_str = fs::read_to_string(&path_b)?;

    let raw_a: serde_json::Value = serde_json::from_str(&raw_a_str)?;
    let raw_b: serde_json::Value = serde_json::from_str(&raw_b_str)?;

    let id_a = path_a.file_stem().and_then(|s| s.to_str()).unwrap_or("report_a");
    let id_b = path_b.file_stem().and_then(|s| s.to_str()).unwrap_or("report_b");

    let norm_a = parse_auto_report(&raw_a, id_a);
    let norm_b = parse_auto_report(&raw_b, id_b);

    let comparator = EvidenceComparator::new(&norm_a, &norm_b);
    let comparison = comparator.reconcile();

    let output_text = match cli.format.as_str() {
        "json" => serde_json::to_string_pretty(&comparison)?,
        "text" => {
            format!(
                "=== Evidence-Aware Sandbox Comparison Summary ===\nSample: {}\nFiles Reconciled: {}\nProcesses Reconciled: {}\nNetwork Events Reconciled: {}",
                comparison.sample_sha256,
                comparison.reconciled_files.len(),
                comparison.reconciled_processes.len(),
                comparison.reconciled_network.len()
            )
        }
        _ => format_markdown_report(&comparison),
    };

    if let Some(out_path) = cli.output {
        fs::write(&out_path, &output_text)?;
        println!("Report successfully written to {}", out_path.display());
    } else {
        println!("{}", output_text);
    }

    Ok(())
}
