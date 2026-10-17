// crates/webrev-cli/src/commands/scan.rs
//! `webrev scan`: the one-shot convenience command. Runs the static pipeline,
//! optionally a dynamic pass, then writes a report — all against a single
//! session — so a newcomer gets findings from one command.

use super::build_mission;
use crate::cli::{Format, ScanAllArgs};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use webrev_core::{Confidence, Severity};
use webrev_extract::ExtractorRegistry;
use webrev_pipeline::stages::{FetchStage, StaticExtractStage, StoreStage};
use webrev_pipeline::{PipelineBuilder, StageContext};
use webrev_report::{RenderOptions, ScopeFilter, SessionReport};
use webrev_storage::{InMemoryStorage, Storage};

pub async fn run(args: ScanAllArgs) -> anyhow::Result<()> {
    let ScanAllArgs {
        scan,
        dynamic,
        active,
        format,
        no_report,
    } = args;

    let (mission, opsec) = build_mission(&scan)?;
    let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
    storage.create_session(&mission).await?;
    let mission = Arc::new(mission);
    let opsec = Arc::new(opsec);
    let cancel = CancellationToken::new();
    eprintln!(
        "mission '{}' — scan (static{}{})",
        mission.name,
        if dynamic { " + dynamic" } else { "" },
        if active { " + active" } else { "" }
    );

    // --- static pipeline (fetch → extract → store) ------------------------
    let ctx = StageContext::new(
        Arc::clone(&mission),
        Arc::clone(&opsec),
        Arc::new(ExtractorRegistry::with_defaults()),
        Arc::clone(&storage),
        cancel.clone(),
    );
    let summary = PipelineBuilder::new()
        .add_stage(Arc::new(FetchStage::new()))
        .add_stage(Arc::new(StaticExtractStage::new()))
        .add_stage(Arc::new(StoreStage::new()))
        .run(ctx, Vec::new())
        .await?;
    eprintln!(
        "static:  {} findings stored, {} stage errors",
        summary.findings_emitted, summary.errors
    );

    // --- optional dynamic pass (same session) -----------------------------
    if dynamic {
        let dyn_total = super::dynamic_scan::run_pass_with_policy(
            opsec.as_ref(),
            &mission,
            scan.duration_secs,
            super::dynamic_scan::interaction_policy(scan.observation_only),
            &cancel,
            storage.as_ref(),
        )
        .await?;
        eprintln!("dynamic: {dyn_total} findings stored");
    }

    // --- optional active pass (same session, over discovered endpoints) --
    if active {
        eprintln!("active scanning sends abnormal traffic: authorized targets only.");
        let captured = storage.findings_by_session(mission.id).await?;
        let endpoints = webrev_pipeline::active_targets(&mission, &captured);
        let findings =
            super::active_scan::run_pass(&opsec, &mission, &endpoints, cancel.clone()).await?;
        for finding in &findings {
            storage.insert_finding(finding).await?;
        }
        eprintln!("active:  {} findings stored", findings.len());
    }

    // --- end-of-scan report -----------------------------------------------
    let findings = storage.findings_by_session(mission.id).await?;
    let endpoints = storage.endpoints_by_session(mission.id).await?;
    let report = SessionReport::build((*mission).clone(), findings, endpoints);
    if no_report {
        super::output::show(&report)?;
        eprintln!("done. in-memory session discarded; no report written.");
        return Ok(());
    }
    if scan.report != std::path::Path::new("-") {
        super::output::show(&report)?;
    }

    let options = RenderOptions {
        format: format.into(),
        scope: ScopeFilter::All,
        min_confidence: Confidence::Low,
        min_severity: Severity::Info,
    };
    let rendered = report.render(options)?;
    if scan.report == std::path::Path::new("-") {
        super::report::write_stdout(&rendered)?;
        return Ok(());
    }
    std::fs::write(&scan.report, &rendered)?;
    eprintln!("report written to {}", scan.report.display());
    if format == Format::Json {
        eprintln!(
            "done. convert this report with: webrev report --input \"{}\" --format <FORMAT>",
            scan.report.display()
        );
    } else {
        eprintln!("done. in-memory session discarded.");
    }
    Ok(())
}
