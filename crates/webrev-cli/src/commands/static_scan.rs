// crates/webrev-cli/src/commands/static_scan.rs
//! `webrev static`: fetch + extract over the mission seeds.

use super::{build_mission, write_session_report};
use crate::cli::ScanArgs;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use webrev_extract::ExtractorRegistry;
use webrev_pipeline::stages::{FetchStage, StaticExtractStage, StoreStage};
use webrev_pipeline::{PipelineBuilder, StageContext};
use webrev_storage::{InMemoryStorage, Storage};

pub async fn run(args: ScanArgs) -> anyhow::Result<()> {
    let (mission, opsec) = build_mission(&args)?;
    let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
    storage.create_session(&mission).await?;
    eprintln!("mission '{}' — static scan", mission.name);

    let ctx = StageContext::new(
        Arc::new(mission.clone()),
        Arc::new(opsec),
        Arc::new(ExtractorRegistry::with_defaults()),
        Arc::clone(&storage),
        CancellationToken::new(),
    );

    let summary = PipelineBuilder::new()
        .add_stage(Arc::new(FetchStage::new()))
        .add_stage(Arc::new(StaticExtractStage::new()))
        .add_stage(Arc::new(StoreStage::new()))
        .run(ctx, Vec::new())
        .await?;

    eprintln!("stages: {}", summary.stages.join(" -> "));
    eprintln!("findings stored: {}", summary.findings_emitted);
    eprintln!("stage errors:    {}", summary.errors);
    write_session_report(&mission, storage.as_ref(), &args.report, args.redact).await?;
    Ok(())
}
