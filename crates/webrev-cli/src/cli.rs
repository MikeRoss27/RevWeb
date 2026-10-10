// crates/webrev-cli/src/cli.rs
//! Command-line surface (clap derive + `WEBREV_` environment variables).

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Worked examples, shown at the bottom of `webrev --help`.
const EXAMPLES: &str = "\
EXAMPLES:
  # One-shot: crawl, extract, and write a report (easiest start)
  webrev scan --seed https://app.example.com/

  # One-shot including a dynamic (headless Chromium) pass
  webrev scan --seed https://app.example.com/ --dynamic

  # Authenticated, behind a login, through an intercepting proxy
  webrev scan --seed https://app.example.com/ \\
    --cookie \"session=…\" --header \"X-Env: staging\" --proxy http://127.0.0.1:8080

  # Sit at the end of a recon pipeline (seeds on stdin)
  subfinder -d example.com | httpx | webrev scan

  # Reveal detected secrets in plaintext (authorized work only)
  webrev scan --seed https://app.example.com/ --reveal-secrets

  # Interactive TUI (auto-runs a static scan; press ? for keys)
  webrev tui --seed https://app.example.com/

  # Re-export the latest session as bare URLs for ffuf/nuclei
  webrev report --format urls | ffuf -u FUZZ -w -";

/// `webrev` — a web reconnaissance and analysis toolkit.
#[derive(Parser)]
#[command(
    name = "webrev",
    version,
    about = "webrev · web reconnaissance toolkit",
    long_about = "webrev — map a web application's attack surface from static and \
                  dynamic analysis.\n\nUse only against targets you are explicitly \
                  authorized to test.",
    after_help = EXAMPLES,
    after_long_help = EXAMPLES
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    /// Suppress the startup banner.
    #[arg(long, global = true)]
    pub no_banner: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// One-shot: static scan (optionally + dynamic) then write a report.
    Scan(ScanAllArgs),
    /// Static analysis: fetch seeds + their scripts and extract endpoints.
    Static(ScanArgs),
    /// Dynamic analysis: drive headless Chromium and capture live calls.
    Dynamic(ScanArgs),
    /// Launch the interactive terminal UI.
    Tui(ScanArgs),
    /// Export a stored session as a JSON report.
    Report(ReportArgs),
}

/// Arguments for the one-shot `scan` command: the shared scan options plus a
/// couple of convenience switches that chain the steps together.
#[derive(Args)]
pub struct ScanAllArgs {
    #[command(flatten)]
    pub scan: ScanArgs,
    /// Also run a dynamic (headless Chromium) pass after the static scan,
    /// reusing the same session.
    #[arg(long)]
    pub dynamic: bool,
    /// Report format written at the end of the scan.
    #[arg(long, value_enum, default_value_t = Format::Json)]
    pub format: Format,
    /// Skip writing the end-of-scan report (just populate the database).
    #[arg(long)]
    pub no_report: bool,
}

/// Arguments shared by the scanning subcommands.
#[derive(Args)]
pub struct ScanArgs {
    /// Seed URL to analyze (repeatable). When omitted, seeds are read from
    /// stdin (one URL per line), so `webrev` composes with other tools:
    /// `subfinder -d x.com | httpx | webrev static`.
    #[arg(long = "seed", value_name = "URL")]
    pub seeds: Vec<String>,
    /// Read seed URLs from stdin even if `--seed` was also given (merge both).
    #[arg(long)]
    pub stdin: bool,
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
    /// Record and show detected secrets in PLAINTEXT instead of only their
    /// fingerprint. Dangerous: real credentials are then written to the SQLite
    /// database and included in exported reports. Off by default — enable only
    /// for authorized work where you need the leaked value to triage or report.
    #[arg(long, env = "WEBREV_REVEAL_SECRETS")]
    pub reveal_secrets: bool,
}

/// Output serialization for `report`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Full pretty JSON document (default).
    Json,
    /// One finding per line (JSON Lines) — stream into jq.
    Jsonl,
    /// Bare endpoint URLs, one per line — pipe into ffuf/httpx/nuclei.
    Urls,
    /// Findings as a CSV table.
    Csv,
}

/// Endpoint scope selector for `report`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ScopeSel {
    /// Both internal and external.
    All,
    /// Only in-scope (target) endpoints.
    Internal,
    /// Only third-party endpoints.
    External,
}

/// Minimum confidence selector for `report`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ConfidenceSel {
    Low,
    Medium,
    High,
}

/// Minimum severity selector for `report`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum SeveritySel {
    Info,
    Low,
    Medium,
    High,
    Critical,
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
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Json)]
    pub format: Format,
    /// Restrict endpoint output to a scope.
    #[arg(long, value_enum, default_value_t = ScopeSel::All)]
    pub scope: ScopeSel,
    /// Drop findings below this confidence.
    #[arg(long = "min-confidence", value_enum, default_value_t = ConfidenceSel::Low)]
    pub min_confidence: ConfidenceSel,
    /// Drop findings below this severity (jsonl/csv are ranked by severity).
    #[arg(long = "min-severity", value_enum, default_value_t = SeveritySel::Info)]
    pub min_severity: SeveritySel,
}
