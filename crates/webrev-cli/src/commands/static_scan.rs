// crates/webrev-cli/src/commands/static_scan.rs
//! `webrev static`: fetch + extract over the mission seeds.

use super::build_mission;
use crate::cli::ScanArgs;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use webrev_extract::ExtractorRegistry;
use webrev_pipeline::stages::{FetchStage, StaticExtractStage, StoreStage};
use webrev_pipeline::{PipelineBuilder, StageContext};
use webrev_storage::{SqliteStorage, Storage};

pub async fn run(args: ScanArgs) -> anyhow::Result<()> {
    let (mission, opsec) = build_mission(&args)?;
    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::connect(&args.db).await?);
    storage.create_session(&mission).await?;
    println!("mission '{}' — static scan", mission.name);

    let ctx = StageContext::new(
        Arc::new(mission),
        Arc::new(opsec),
        Arc::new(ExtractorRegistry::with_defaults_revealing(args.reveal_secrets)),
        Arc::clone(&storage),
        CancellationToken::new(),
    );

    let summary = PipelineBuilder::new()
        .add_stage(Arc::new(FetchStage::new()))
        .add_stage(Arc::new(StaticExtractStage::new()))
        .add_stage(Arc::new(StoreStage::new()))
        .run(ctx, Vec::new())
        .await?;

    println!("stages: {}", summary.stages.join(" -> "));
    println!("findings stored: {}", summary.findings_emitted);
    println!("stage errors:    {}", summary.errors);
    println!(
        "export the report with: webrev report --db {}",
        args.db.display()
    );
    Ok(())
}
