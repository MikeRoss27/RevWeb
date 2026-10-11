// crates/webrev-cli/src/commands/scan.rs
//! `webrev scan`: the one-shot convenience command. Runs the static pipeline,
//! optionally a dynamic pass, then writes a report — all against a single
//! session — so a newcomer gets findings from one command.

use super::build_mission;
use crate::cli::{Format, ScanAllArgs};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use webrev_browser::{run_dynamic, BrowserPool, BrowserProfile};
use webrev_core::{Confidence, Endpoint, FindingKind, Method, Severity, Source};
use webrev_extract::ExtractorRegistry;
use webrev_pipeline::stages::{FetchStage, StaticExtractStage, StoreStage};
use webrev_pipeline::{run_active_scan, PipelineBuilder, StageContext};
use webrev_report::{RenderOptions, ReportFormat, ScopeFilter, SessionReport};
use webrev_storage::{SqliteStorage, Storage};

pub async fn run(args: ScanAllArgs) -> anyhow::Result<()> {
    let ScanAllArgs {
        scan,
        dynamic,
        active,
        format,
        no_report,
    } = args;

    let (mission, opsec) = build_mission(&scan)?;
    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::connect(&scan.db).await?);
    storage.create_session(&mission).await?;
    let mission = Arc::new(mission);
    let opsec = Arc::new(opsec);
    let cancel = CancellationToken::new();
    println!(
        "mission '{}' — scan (static{}{})",
        mission.name,
        if dynamic { " + dynamic" } else { "" },
        if active { " + active" } else { "" }
    );

    // --- static pipeline (fetch → extract → store) ------------------------
    let ctx = StageContext::new(
        Arc::clone(&mission),
        Arc::clone(&opsec),
        Arc::new(ExtractorRegistry::with_defaults_revealing(scan.reveal_secrets)),
        Arc::clone(&storage),
        cancel.clone(),
    );
    let summary = PipelineBuilder::new()
        .add_stage(Arc::new(FetchStage::new()))
        .add_stage(Arc::new(StaticExtractStage::new()))
        .add_stage(Arc::new(StoreStage::new()))
        .run(ctx, Vec::new())
        .await?;
    println!(
        "static:  {} findings stored, {} stage errors",
        summary.findings_emitted, summary.errors
    );

    // --- optional dynamic pass (same session) -----------------------------
    if dynamic {
        let dyn_total =
            dynamic_pass(opsec.as_ref(), &mission, scan.duration_secs, &cancel, &storage).await?;
        println!("dynamic: {dyn_total} findings stored");
    }

    // --- optional active pass (same session, over discovered endpoints) --
    if active {
        eprintln!("active scanning sends abnormal traffic: authorized targets only.");
        // Static extraction only records endpoints *referenced* from a page
        // (fetch/axios/XHR calls, links); the seed page itself never shows
        // up there, so the origin-level checks (headers/CORS/sensitive
        // files) would otherwise silently never run against it.
        let mut endpoints = storage.endpoints_by_session(mission.id).await?;
        let discovered: std::collections::BTreeSet<String> =
            endpoints.iter().map(|e| e.url.clone()).collect();
        for seed in &mission.seeds {
            if mission.scope.allows(seed) && !discovered.contains(seed) {
                endpoints.push(Endpoint::new(seed.clone(), Method::Get, Source::Html));
            }
        }
        let findings =
            run_active_scan(&opsec, &mission.scope, mission.id, &endpoints, cancel.clone()).await?;
        for finding in &findings {
            storage.insert_finding(finding).await?;
        }
        println!("active:  {} findings stored", findings.len());
    }

    // --- end-of-scan report -----------------------------------------------
    if no_report {
        println!(
            "done. export a report with: webrev report --db {}",
            scan.db.display()
        );
        return Ok(());
    }

    let findings = storage.findings_by_session(mission.id).await?;
    let endpoints = storage.endpoints_by_session(mission.id).await?;
    let options = RenderOptions {
        format: match format {
            Format::Json => ReportFormat::Json,
            Format::Jsonl => ReportFormat::Jsonl,
            Format::Urls => ReportFormat::Urls,
            Format::Csv => ReportFormat::Csv,
        },
        scope: ScopeFilter::All,
        min_confidence: Confidence::Low,
        min_severity: Severity::Info,
    };
    let rendered = SessionReport::build((*mission).clone(), findings, endpoints).render(options)?;
    std::fs::write(&scan.report, &rendered)?;
    eprintln!("report written to {}", scan.report.display());
    println!(
        "done. re-export other formats with: webrev report --db {}",
        scan.db.display()
    );
    Ok(())
}

/// Drive a dynamic (headless Chromium) pass over the mission's in-scope seeds,
/// persisting findings/endpoints into the shared session. Returns the count.
async fn dynamic_pass(
    opsec: &webrev_core::OpsecConfig,
    mission: &webrev_core::Mission,
    duration_secs: u64,
    cancel: &CancellationToken,
    storage: &Arc<dyn Storage>,
) -> anyhow::Result<usize> {
    let profile = BrowserProfile::from_opsec(opsec)?;
    let pool = BrowserPool::new(1);
    let mut total = 0usize;
    for seed in &mission.seeds {
        if !mission.scope.allows(seed) {
            eprintln!("skip out-of-scope: {seed}");
            continue;
        }
        println!("dynamic: {seed}");
        let findings = run_dynamic(
            &pool,
            &profile,
            seed,
            Duration::from_secs(duration_secs),
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
                    .insert_endpoint(
                        mission.id,
                        &Endpoint::new(url, method, finding.provenance.source),
                    )
                    .await?;
            }
        }
        total += findings.len();
    }
    Ok(total)
}
