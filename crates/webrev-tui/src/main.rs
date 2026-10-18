// crates/webrev-tui/src/main.rs
//! Thin binary wrapper around `webrev_tui::run`.

use clap::Parser;
use std::path::PathBuf;
use webrev_core::{EgressPolicy, Mission, MissionProfile, OpsecConfig, Scope};
use webrev_tui::{run, TuiOptions};

#[derive(Parser)]
#[command(
    name = "webrev-tui",
    version,
    about = "webrev · interactive web security analysis and testing"
)]
struct Args {
    /// Seed URL to analyze (repeatable).
    #[arg(long = "seed", value_name = "URL")]
    seeds: Vec<String>,
    /// In-scope host suffix (repeatable). Defaults to the seeds' hosts.
    #[arg(long = "scope", value_name = "HOST")]
    scope: Vec<String>,
    /// Mission name.
    #[arg(long, default_value = "webrev-mission")]
    name: String,
    /// Report output path for the 'r' key.
    #[arg(long, default_value = "webrev-report.json")]
    report: PathBuf,
    /// Keep credentials in the exported report (masked by default).
    #[arg(long, env = "WEBREV_REPORT_UNREDACTED", action = clap::ArgAction::SetTrue, value_parser = clap::builder::BoolishValueParser::new())]
    unredacted: bool,
    /// Optional egress proxy (e.g. http://127.0.0.1:8080).
    #[arg(long, env = "WEBREV_PROXY")]
    proxy: Option<String>,
    /// Shared active request budget (the a action), including controls.
    #[arg(long, default_value_t = 200)]
    max_active_requests: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let include = if args.scope.is_empty() {
        args.seeds
            .iter()
            .filter_map(|s| Scope::host_of(s).map(str::to_owned))
            .collect()
    } else {
        args.scope
    };
    let mission = Mission::new(args.name, Scope::new(include, vec![]), args.seeds);
    let opsec = OpsecConfig {
        active: webrev_core::ActiveLimits {
            max_requests: args.max_active_requests,
            ..webrev_core::ActiveLimits::default()
        },
        egress: EgressPolicy {
            proxy: args.proxy,
            allow_direct: true,
        },
        ..OpsecConfig::default()
    };

    run(TuiOptions {
        profile: MissionProfile::new(mission, opsec),
        report_path: args.report,
        redact_report: !args.unredacted,
    })
    .await
}
