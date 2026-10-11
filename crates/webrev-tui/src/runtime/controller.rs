//! Launch scans and export the live in-memory session.
use crate::app::UiEvent;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{broadcast, mpsc::UnboundedSender};
use tokio_util::sync::CancellationToken;
use webrev_browser::{run_dynamic, BrowserPool, BrowserProfile};
use webrev_core::{Mission, OpsecConfig};
use webrev_extract::ExtractorRegistry;
use webrev_pipeline::{
    stages::{FetchStage, StaticExtractStage, StoreStage},
    PipelineBuilder, PipelineEvent, StageContext,
};
use webrev_report::SessionReport;
use webrev_storage::Storage;

const DYNAMIC_DWELL: Duration = Duration::from_secs(8);

/// Shared handles used to launch scans and export reports.
pub(super) struct Controller {
    pub(super) mission: Arc<Mission>,
    pub(super) opsec: Arc<OpsecConfig>,
    pub(super) registry: Arc<ExtractorRegistry>,
    pub(super) storage: Arc<dyn Storage>,
    pub(super) cancel: CancellationToken,
    pub(super) report_path: PathBuf,
}

impl Controller {
    /// Launch a static pipeline, forwarding its events into `ui_tx`.
    pub(super) fn start_static(&self, ui_tx: UnboundedSender<UiEvent>) {
        let builder = PipelineBuilder::new()
            .add_stage(Arc::new(FetchStage::new()))
            .add_stage(Arc::new(StaticExtractStage::new()))
            .add_stage(Arc::new(StoreStage::new()));
        let mut events = builder.subscribe();
        let ctx = StageContext::new(
            Arc::clone(&self.mission),
            Arc::clone(&self.opsec),
            Arc::clone(&self.registry),
            Arc::clone(&self.storage),
            self.cancel.clone(),
        );

        let forward_tx = ui_tx.clone();
        let forwarding = tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        if forward_tx.send(UiEvent::Pipeline(event)).is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        tokio::spawn(async move {
            let message = match builder.run(ctx, Vec::new()).await {
                Ok(summary) => format!(
                    "static scan done: {} findings, {} errors",
                    summary.findings_emitted, summary.errors
                ),
                Err(e) => format!("static scan error: {e}"),
            };
            let _ = forwarding.await;
            let _ = ui_tx.send(UiEvent::ScanFinished(message));
        });
    }

    /// Launch a dynamic scan of each in-scope seed, persisting and surfacing the
    /// findings as they complete.
    pub(super) fn start_dynamic(&self, ui_tx: UnboundedSender<UiEvent>) {
        let mission = Arc::clone(&self.mission);
        let opsec = Arc::clone(&self.opsec);
        let storage = Arc::clone(&self.storage);
        let cancel = self.cancel.clone();

        tokio::spawn(async move {
            let profile = match BrowserProfile::from_opsec(&opsec) {
                Ok(profile) => profile,
                Err(e) => {
                    let _ = ui_tx.send(UiEvent::ScanFinished(format!(
                        "dynamic: profile error: {e}"
                    )));
                    return;
                }
            };

            let pool = BrowserPool::new(1);
            let mut total = 0usize;
            for seed in &mission.seeds {
                if !mission.scope.allows(seed) {
                    let _ = ui_tx.send(UiEvent::Status(format!(
                        "dynamic: skip out-of-scope {seed}"
                    )));
                    continue;
                }
                match run_dynamic(
                    &pool,
                    &profile,
                    seed,
                    DYNAMIC_DWELL,
                    mission.id,
                    cancel.clone(),
                )
                .await
                {
                    Ok(findings) => {
                        for finding in &findings {
                            let _ = storage.insert_finding(finding).await;
                            let _ = ui_tx.send(UiEvent::Pipeline(PipelineEvent::Finding(
                                Box::new(finding.clone()),
                            )));
                        }
                        total += findings.len();
                    }
                    Err(e) => {
                        let _ =
                            ui_tx.send(UiEvent::Status(format!("dynamic error on {seed}: {e}")));
                    }
                }
            }
            // Close Chromium over CDP and reap it before the task ends, so the
            // pool drop does not kill it abruptly (warning + CDP ConnectionReset).
            pool.shutdown().await;
            let _ = ui_tx.send(UiEvent::ScanFinished(format!(
                "dynamic scan done: {total} findings"
            )));
        });
    }

    /// Build and write the JSON report for the current session.
    pub(super) async fn export_report(&self) -> anyhow::Result<PathBuf> {
        let findings = self.storage.findings_by_session(self.mission.id).await?;
        let endpoints = self.storage.endpoints_by_session(self.mission.id).await?;
        let report = SessionReport::build((*self.mission).clone(), findings, endpoints);
        std::fs::write(&self.report_path, report.to_json()?)?;
        Ok(self.report_path.clone())
    }
}
