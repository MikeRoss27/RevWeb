// crates/webrev-tui/src/main.rs
//! Thin binary wrapper around `webrev_tui::run`.

use clap::Parser;
use std::path::PathBuf;
use webrev_core::{EgressPolicy, Mission, MissionProfile, OpsecConfig, Scope};
use webrev_tui::{run, TuiOptions};

#[derive(Parser)]
#[command(name = "webrev-tui", version, about = "webrev terminal UI")]
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
    /// SQLite database path.
    #[arg(long, env = "WEBREV_DB", default_value = "webrev.db")]
    db: PathBuf,
    /// Report output path for the 'r' key.
    #[arg(long, default_value = "webrev-report.json")]
    report: PathBuf,
    /// Optional egress proxy (e.g. http://127.0.0.1:8080).
    #[arg(long, env = "WEBREV_PROXY")]
    proxy: Option<String>,
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
        egress: EgressPolicy {
            proxy: args.proxy,
            allow_direct: true,
        },
        ..OpsecConfig::default()
    };

    run(TuiOptions {
        profile: MissionProfile::new(mission, opsec),
        db_path: args.db,
        report_path: args.report,
    })
    .await
}
