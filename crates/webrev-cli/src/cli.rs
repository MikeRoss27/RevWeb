// crates/webrev-cli/src/cli.rs
//! Command-line surface (clap derive + `WEBREV_` environment variables).

use clap::builder::styling::{Color, RgbColor, Style, Styles};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// `--help` colors: orange headings, cream literals, stone placeholders.
/// clap drops them automatically for pipes and `NO_COLOR`.
const STYLES: Styles = Styles::styled()
    .header(
        Style::new()
            .bold()
            .fg_color(Some(Color::Rgb(RgbColor(229, 101, 63)))),
    )
    .usage(
        Style::new()
            .bold()
            .fg_color(Some(Color::Rgb(RgbColor(229, 101, 63)))),
    )
    .literal(
        Style::new()
            .bold()
            .fg_color(Some(Color::Rgb(RgbColor(250, 244, 232)))),
    )
    .placeholder(Style::new().fg_color(Some(Color::Rgb(RgbColor(163, 154, 146)))));

/// Worked examples, shown at the bottom of `webrev --help`.
const EXAMPLES: &str = "\
EXAMPLES:
  # Web security assessment: static + dynamic + active, then report
  webrev scan --seed https://app.example.com/ --dynamic --active

  # Static inspection: crawl, extract, and write a report
  webrev scan --seed https://app.example.com/

  # One-shot including a dynamic (headless Chromium) pass
  webrev scan --seed https://app.example.com/ --dynamic

  # Add light active probing (headers, CORS, open redirect, fuzzing, IDOR)
  webrev scan --seed https://app.example.com/ --active

  # Authenticated, behind a login, through an intercepting proxy
  webrev scan --seed https://app.example.com/ \\
    --cookie \"session=…\" --header \"X-Env: staging\" --proxy http://127.0.0.1:8080

  # Sit at the end of a recon pipeline (seeds on stdin)
  subfinder -d example.com | httpx | webrev scan

  # Interactive TUI (auto-runs a static scan; press ? for keys)
  webrev tui --seed https://app.example.com/

  # Convert the JSON report to bare URLs for ffuf/nuclei
  webrev report --format urls | ffuf -u FUZZ -w -";

/// `webrev` — a web security analysis and testing toolkit.
#[derive(Parser)]
#[command(
    name = "webrev",
    version,
    styles = STYLES,
    about = "webrev · web security toolkit",
    long_about = "webrev — investigate web applications with static code inspection, dynamic \
                  browser analysis and scoped active security probes.\n\nExtract APIs, secrets \
                  and technology fingerprints; inspect HTTP/WebSocket traffic; probe access \
                  controls, CORS, redirects and injection signals.\n\nUse only against targets \
                  you are explicitly authorized to test.",
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
    /// Analyze and test an application: static, optionally + dynamic/active, then report.
    Scan(ScanAllArgs),
    /// Static analysis: fetch seeds + their scripts and extract endpoints.
    Static(ScanArgs),
    /// Dynamic analysis: drive headless Chromium and capture live calls.
    Dynamic(ScanArgs),
    /// Active analysis: lightweight, opt-in vulnerability probing (security
    /// headers, CORS, cookie flags, sensitive-file exposure, open redirect,
    /// parameter fuzzing, IDOR-lite) against discovered endpoints. Sends
    /// abnormal traffic — authorized targets only.
    Active(ScanArgs),
    /// Launch the interactive terminal UI.
    Tui(ScanArgs),
    /// Convert or filter an existing JSON report.
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
    /// Also run a light active-scan pass (security headers, CORS, cookie
    /// flags, sensitive-file exposure, open redirect, parameter fuzzing,
    /// IDOR-lite) over the endpoints the static/dynamic passes discovered.
    /// Sends abnormal traffic to the target — authorized targets only.
    #[arg(long)]
    pub active: bool,
    /// Report format written at the end of the scan.
    #[arg(long, value_enum, default_value_t = Format::Json)]
    pub format: Format,
    /// Skip writing the end-of-scan report; discard the in-memory session
    /// after printing the scan summary.
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
    /// Shared active request budget, including controls and failed requests.
    #[arg(long, default_value_t = 200)]
    pub max_active_requests: usize,
    /// Maximum link-following depth from the seeds (0 = seeds only).
    #[arg(long, default_value_t = 2)]
    pub max_depth: usize,
    /// Maximum concurrent in-flight requests during the crawl.
    #[arg(long, default_value_t = 4)]
    pub max_concurrency: usize,
    /// Dynamic dwell time per seed, in seconds.
    #[arg(long, default_value_t = 8)]
    pub duration_secs: u64,
    /// Report output path (or the TUI's 'r' key). Use '-' for stdout in CLI scans.
    #[arg(long, default_value = "webrev-report.json")]
    pub report: PathBuf,
}

/// Output serialization for `report`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable triage: vulnerabilities, secrets, technologies and surface.
    Text,
    /// Full pretty JSON document (default).
    Json,
    /// One finding per line (JSON Lines) — stream into jq.
    Jsonl,
    /// Bare endpoint URLs, one per line — pipe into ffuf/httpx/nuclei.
    Urls,
    /// Findings as a CSV table.
    Csv,
    /// Reconstructed OpenAPI 3.1 spec of the discovered surface.
    #[value(name = "openapi")]
    OpenApi,
}

impl From<Format> for webrev_report::ReportFormat {
    fn from(format: Format) -> Self {
        match format {
            Format::Text => Self::Text,
            Format::Json => Self::Json,
            Format::Jsonl => Self::Jsonl,
            Format::Urls => Self::Urls,
            Format::Csv => Self::Csv,
            Format::OpenApi => Self::OpenApi,
        }
    }
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
    /// JSON report to convert or filter.
    #[arg(long, default_value = "webrev-report.json")]
    pub input: PathBuf,
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
