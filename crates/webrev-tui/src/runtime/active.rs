//! Active probes share the live session and surface each result in the TUI.
use super::controller::Controller;
use crate::events::UiEvent;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use webrev_pipeline::{run_active_scan, PipelineEvent};

impl Controller {
    pub(super) fn start_active(&self, ui_tx: UnboundedSender<UiEvent>) {
        let mission = Arc::clone(&self.mission);
        let opsec = Arc::clone(&self.opsec);
        let storage = Arc::clone(&self.storage);
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            let result: anyhow::Result<usize> = async {
                let captured = storage.findings_by_session(mission.id).await?;
                let endpoints = webrev_pipeline::active_targets(&mission, &captured);
                let findings =
                    run_active_scan(&opsec, &mission.scope, mission.id, &endpoints, cancel).await?;
                for finding in &findings {
                    storage.insert_finding(finding).await?;
                    let _ = ui_tx.send(UiEvent::Pipeline(PipelineEvent::Finding(Box::new(
                        finding.clone(),
                    ))));
                }
                Ok(findings.len())
            }
            .await;
            let message = match result {
                Ok(count) => {
                    format!("active scan done: {count} findings (signals need verification)")
                }
                Err(e) => format!("active scan error: {e}"),
            };
            let _ = ui_tx.send(UiEvent::ScanFinished(message));
        });
    }
}
