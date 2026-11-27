// crates/webrev-cli/src/commands/active_scan.rs
//! `webrev active`: lightweight, opt-in vulnerability probing against the
//! mission seeds (a standalone run has no prior recon to draw endpoints
//! from — pair this with `webrev scan --active` to probe everything a
//! static/dynamic pass already discovered).

use super::{build_mission, write_session_report};
use crate::cli::ScanArgs;
use crate::progress::{note, Progress};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use webrev_core::{Endpoint, Finding, Method, Mission, OpsecConfig, Source};
use webrev_pipeline::run_active_scan;
use webrev_storage::{InMemoryStorage, Storage};

pub async fn run(args: ScanArgs) -> anyhow::Result<()> {
    let (mission, opsec) = build_mission(&args)?;
    let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
    storage.create_session(&mission).await?;
    note!("mission '{}' — active scan", mission.name);
    note!("active scanning sends abnormal traffic: authorized targets only.");

    let endpoints: Vec<Endpoint> = mission
        .seeds
        .iter()
        .filter(|s| mission.scope.allows(s))
        .map(|s| Endpoint::new(s.clone(), Method::Get, Source::Html))
        .collect();

    let findings = run_pass(&opsec, &mission, &endpoints, CancellationToken::new()).await?;

    for finding in &findings {
        storage.insert_finding(finding).await?;
    }

    note!("active findings stored: {}", findings.len());
    write_session_report(&mission, storage.as_ref(), &args).await?;
    Ok(())
}

pub(super) async fn run_pass(
    opsec: &OpsecConfig,
    mission: &Mission,
    endpoints: &[Endpoint],
    cancel: CancellationToken,
) -> anyhow::Result<Vec<Finding>> {
    let progress = Progress::start("active");
    progress.stage(&format!("probing {} endpoints", endpoints.len()));
    let scan = run_active_scan(opsec, &mission.scope, mission.id, endpoints, cancel.clone());
    tokio::pin!(scan);
    let result = tokio::select! {
        result = &mut scan => result,
        signal = tokio::signal::ctrl_c() => {
            if signal.is_ok() {
                eprintln!("active scan interrupted; preserving findings and coverage");
                cancel.cancel();
            }
            scan.await
        }
    };
    progress.finish().await;
    Ok(result?)
}
