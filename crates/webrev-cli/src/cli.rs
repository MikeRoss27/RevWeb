// crates/webrev-cli/src/cli.rs
//! Command-line surface (clap derive + `WEBREV_` environment variables).

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// `webrev` — a web reconnaissance and analysis toolkit.
#[derive(Parser)]
#[command(name = "webrev", version, about = "web reconnaissance & analysis toolkit")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Static analysis: fetch seeds + their scripts and extract endpoints.
    Static(ScanArgs),
    /// Dynamic analysis: drive headless Chromium and capture live calls.
    Dynamic(ScanArgs),
    /// Launch the interactive terminal UI.
    Tui(ScanArgs),
    /// Export a stored session as a JSON report.
    Report(ReportArgs),
}

/// Arguments shared by the scanning subcommands.
#[derive(Args)]
pub struct ScanArgs {
    /// Seed URL to analyze (repeatable).
    #[arg(long = "seed", value_name = "URL", required = true)]
    pub seeds: Vec<String>,
    /// In-scope host suffix (repeatable). Defaults to the seeds' hosts.
    #[arg(long = "scope", value_name = "HOST")]
    pub scope: Vec<String>,
    /// Out-of-scope host suffix (repeatable).
    #[arg(long = "exclude", value_name = "HOST")]
    pub exclude: Vec<String>,
    /// Mission name.
    #[arg(long, env = "WEBREV_NAME", default_value = "webrev-mission")]
    pub name: String,
    /// SQLite database path.
    #[arg(long, env = "WEBREV_DB", default_value = "webrev.db")]
    pub db: PathBuf,
    /// Optional egress proxy (e.g. http://127.0.0.1:8080).
    #[arg(long, env = "WEBREV_PROXY")]
    pub proxy: Option<String>,
    /// Extra request header "Name: Value" (repeatable).
    #[arg(long = "header", value_name = "NAME: VALUE")]
    pub headers: Vec<String>,
    /// Cookie "name=value" (repeatable).
    #[arg(long = "cookie", value_name = "NAME=VALUE")]
    pub cookies: Vec<String>,
    /// Bearer token sent as `Authorization: Bearer <token>`.
    #[arg(long, env = "WEBREV_BEARER")]
    pub bearer: Option<String>,
    /// Lower bound of the inter-request delay window, in milliseconds.
    #[arg(long, default_value_t = 150)]
    pub delay_min_ms: u64,
    /// Upper bound of the inter-request delay window, in milliseconds.
    #[arg(long, default_value_t = 600)]
    pub delay_max_ms: u64,
    /// Maximum resources fetched per crawl (hard budget).
    #[arg(long, default_value_t = 50)]
    pub max_pages: usize,
    /// Maximum link-following depth from the seeds (0 = seeds only).
    #[arg(long, default_value_t = 2)]
    pub max_depth: usize,
    /// Maximum concurrent in-flight requests during the crawl.
    #[arg(long, default_value_t = 4)]
    pub max_concurrency: usize,
    /// Dynamic dwell time per seed, in seconds.
    #[arg(long, default_value_t = 8)]
    pub duration_secs: u64,
    /// Report output path used by the TUI's 'r' key.
    #[arg(long, default_value = "webrev-report.json")]
    pub report: PathBuf,
}

/// Arguments for the `report` subcommand.
#[derive(Args)]
pub struct ReportArgs {
    /// Session id (UUID) to export. Defaults to the most recent scan.
    #[arg(long)]
    pub session: Option<String>,
    /// SQLite database path.
    #[arg(long, env = "WEBREV_DB", default_value = "webrev.db")]
    pub db: PathBuf,
    /// Output file; prints to stdout when omitted.
    #[arg(long)]
    pub output: Option<PathBuf>,
}
