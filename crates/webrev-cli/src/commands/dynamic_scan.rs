// crates/webrev-cli/src/commands/dynamic_scan.rs
//! `webrev dynamic`: drive headless Chromium for each in-scope seed.

use super::build_mission;
use crate::cli::ScanArgs;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use webrev_browser::{run_dynamic, BrowserProfile};
use webrev_core::{Endpoint, FindingKind, Method};
use webrev_storage::{SqliteStorage, Storage};

pub async fn run(args: ScanArgs) -> anyhow::Result<()> {
    let (mission, opsec) = build_mission(&args);
    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::connect(&args.db).await?);
    storage.create_session(&mission).await?;
    println!("mission '{}' — dynamic scan", mission.name);

    let profile = BrowserProfile::from_opsec(&opsec)?;
    let cancel = CancellationToken::new();
    let mut total = 0usize;

    for seed in &mission.seeds {
        if !mission.scope.allows(seed) {
            eprintln!("skip out-of-scope: {seed}");
            continue;
        }
        println!("dynamic: {seed}");
        let findings = run_dynamic(
            &profile,
            seed,
            Duration::from_secs(args.duration_secs),
            mission.id,
            cancel.clone(),
        )
        .await?;

        for finding in &findings {
            storage.insert_finding(finding).await?;
            if finding.kind == FindingKind::Endpoint {
                let method = finding
                    .value
                    .split_whitespace()
                    .next()
                    .map_or(Method::Unknown, Method::parse);
                let url = finding.url.clone().unwrap_or_else(|| finding.value.clone());
                storage
                    .insert_endpoint(mission.id, &Endpoint::new(url, method, finding.provenance.source))
                    .await?;
            }
        }
        total += findings.len();
    }

    println!("dynamic findings stored: {total}");
    Ok(())
}
