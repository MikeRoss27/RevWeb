// crates/webrev-cli/src/commands/mod.rs
//! Subcommand handlers. Each is a thin function that builds the mission and
//! drives the appropriate library.

mod dynamic_scan;
mod report;
mod static_scan;

use crate::cli::{Cli, Command, ScanArgs};
use webrev_core::{AuthConfig, EgressPolicy, Mission, MissionProfile, OpsecConfig, Scope};
use webrev_tui::TuiOptions;

/// Translate shared scan arguments into a mission and its opsec config.
/// When no explicit scope is given, the seeds' own hosts become the scope.
fn build_mission(args: &ScanArgs) -> (Mission, OpsecConfig) {
    let include = if args.scope.is_empty() {
        args.seeds
            .iter()
            .filter_map(|s| Scope::host_of(s).map(str::to_owned))
            .collect()
    } else {
        args.scope.clone()
    };
    let scope = Scope::new(include, args.exclude.clone());
    let mission = Mission::new(args.name.clone(), scope, args.seeds.clone());
    let auth = AuthConfig {
        headers: args
            .headers
            .iter()
            .filter_map(|h| h.split_once(':'))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect(),
        cookies: args
            .cookies
            .iter()
            .filter_map(|c| c.split_once('='))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect(),
        bearer: args.bearer.clone(),
    };
    let opsec = OpsecConfig {
        egress: EgressPolicy {
            proxy: args.proxy.clone(),
            allow_direct: true,
        },
        delay_min_ms: args.delay_min_ms,
        delay_max_ms: args.delay_max_ms,
        max_pages: args.max_pages,
        max_depth: args.max_depth,
        max_concurrency: args.max_concurrency.max(1),
        auth,
        ..OpsecConfig::default()
    };
    (mission, opsec)
}

/// Dispatch the parsed CLI to its handler.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Static(args) => static_scan::run(args).await,
        Command::Dynamic(args) => dynamic_scan::run(args).await,
        Command::Report(args) => report::run(args).await,
        Command::Tui(args) => {
            let (mission, opsec) = build_mission(&args);
            webrev_tui::run(TuiOptions {
                profile: MissionProfile::new(mission, opsec),
                db_path: args.db,
                report_path: args.report,
            })
            .await
        }
    }
}
