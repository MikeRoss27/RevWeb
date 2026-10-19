// crates/webrev-cli/src/commands/dynamic_scan.rs
//! `webrev dynamic`: drive headless Chromium for each in-scope seed.

use super::{build_mission, write_session_report};
use crate::cli::ScanArgs;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use webrev_browser::{run_dynamic_with_report, BrowserPool, BrowserProfile, InteractionPolicy};
use webrev_core::{Endpoint, FindingKind, Method};
use webrev_storage::{InMemoryStorage, Storage};

pub async fn run(args: ScanArgs) -> anyhow::Result<()> {
    let (mission, opsec) = build_mission(&args)?;
    let storage = InMemoryStorage::new();
    storage.create_session(&mission).await?;
    eprintln!("mission '{}' — dynamic scan", mission.name);
    let total = run_pass_with_policy(
        &opsec,
        &mission,
        args.duration_secs,
        interaction_policy(args.observation_only),
        &CancellationToken::new(),
        &storage,
    )
    .await?;
    eprintln!("dynamic findings stored: {total}");
    write_session_report(&mission, &storage, &args.report, args.redact).await?;
    Ok(())
}

/// Drive a dynamic (headless Chromium) pass over the mission's in-scope seeds,
/// persisting findings/endpoints into the shared session. Returns the count.
pub(super) async fn run_pass(
    opsec: &webrev_core::OpsecConfig,
    mission: &webrev_core::Mission,
    duration_secs: u64,
    cancel: &CancellationToken,
    storage: &dyn Storage,
) -> webrev_core::Result<usize> {
    run_pass_with_policy(
        opsec,
        mission,
        duration_secs,
        InteractionPolicy::Explore,
        cancel,
        storage,
    )
    .await
}

pub(super) fn interaction_policy(observation_only: bool) -> InteractionPolicy {
    if observation_only {
        InteractionPolicy::ObserveOnly
    } else {
        InteractionPolicy::Explore
    }
}

pub(super) async fn run_pass_with_policy(
    opsec: &webrev_core::OpsecConfig,
    mission: &webrev_core::Mission,
    duration_secs: u64,
    policy: InteractionPolicy,
    cancel: &CancellationToken,
    storage: &dyn Storage,
) -> webrev_core::Result<usize> {
    let profile = BrowserProfile::from_opsec(opsec)?
        .with_scope(mission.scope.clone())
        .with_interaction_policy(policy);
    let pool = BrowserPool::new(1);
    let result: webrev_core::Result<usize> = async {
        let mut total = 0usize;
        for seed in &mission.seeds {
            if !mission.scope.allows(seed) {
                eprintln!("skip out-of-scope: {}", webrev_core::redact_url(seed));
                continue;
            }
            eprintln!("dynamic: {}", webrev_core::redact_url(seed));
            let report = run_dynamic_with_report(
                &pool,
                &profile,
                seed,
                Duration::from_secs(duration_secs),
                mission.id,
                cancel.clone(),
            )
            .await?;
            let coverage = report.coverage_finding(mission.id, seed, policy);
            storage.insert_finding(&coverage).await?;
            let findings = report.findings;
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
                        .insert_endpoint(
                            mission.id,
                            &Endpoint::new(url, method, finding.provenance.source),
                        )
                        .await?;
                }
            }
            total += findings.len() + 1;
        }
        Ok(total)
    }
    .await;
    // Close even when navigation or recording a finding fails.
    pool.shutdown().await;
    result
}
