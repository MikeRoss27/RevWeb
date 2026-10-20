//! Launch scans and export the live in-memory session.
use crate::app::{ExportOutcome, UiEvent};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{broadcast, mpsc::UnboundedSender};
use tokio_util::sync::CancellationToken;
use webrev_browser::{run_dynamic, BrowserPool, BrowserProfile};
use webrev_core::{redact_url, Mission, OpsecConfig};
use webrev_extract::ExtractorRegistry;
use webrev_pipeline::{
    stages::{FetchStage, StaticExtractStage, StoreStage},
    PipelineBuilder, PipelineEvent, StageContext,
};
use webrev_report::SessionReport;
use webrev_storage::Storage;

const DYNAMIC_DWELL: Duration = Duration::from_secs(8);

/// Status line for a seed skipped because it is out of scope. Mirrors
/// `webrev dynamic`'s `eprintln!("skip out-of-scope: {}", redact_url(seed))`:
/// the seed may carry userinfo or a query-string token, and the TUI status
/// bar is an on-screen display, not a report, so it gets the same treatment
/// as everything else that stays masked regardless of `--redact`.
fn skip_out_of_scope_message(seed: &str) -> String {
    format!("dynamic: skip out-of-scope {}", redact_url(seed))
}

/// Status line for a dynamic-capture error on `seed`. The seed is redacted
/// for the same reason as [`skip_out_of_scope_message`]; the error itself is
/// `webrev_core::Error`, whose `Display` already redacts embedded URLs at the
/// construction site.
fn dynamic_error_message(seed: &str, err: &webrev_core::WebrevError) -> String {
    format!("dynamic error on {}: {err}", redact_url(seed))
}

/// Shared handles used to launch scans and export reports.
#[derive(Clone)]
pub(super) struct Controller {
    pub(super) mission: Arc<Mission>,
    pub(super) opsec: Arc<OpsecConfig>,
    pub(super) registry: Arc<ExtractorRegistry>,
    pub(super) storage: Arc<dyn Storage>,
    pub(super) cancel: CancellationToken,
    pub(super) report_path: PathBuf,
    pub(super) redact_report: bool,
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
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        if forward_tx.send(UiEvent::Lagged(n)).is_err() {
                            break;
                        }
                    }
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
            let profile = match BrowserProfile::from_opsec(&opsec)
                .map(|p| p.with_scope(mission.scope.clone()))
            {
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
                    let _ = ui_tx.send(UiEvent::Status(skip_out_of_scope_message(seed)));
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
                        let _ = ui_tx.send(UiEvent::Status(dynamic_error_message(seed, &e)));
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

    /// Export the report on a background task and report back with
    /// [`UiEvent::Exported`]. An existing file is only replaced when `overwrite`.
    pub(super) fn spawn_export(&self, overwrite: bool, ui_tx: UnboundedSender<UiEvent>) {
        let this = self.clone();
        tokio::spawn(async move {
            let outcome = this
                .export_report(overwrite)
                .await
                .unwrap_or_else(|e| ExportOutcome::Failed(e.to_string()));
            let _ = ui_tx.send(UiEvent::Exported(outcome));
        });
    }

    /// Build the JSON report for the current session and write it without
    /// blocking the event loop.
    pub(super) async fn export_report(&self, overwrite: bool) -> anyhow::Result<ExportOutcome> {
        let findings = self.storage.findings_by_session(self.mission.id).await?;
        let endpoints = self.storage.endpoints_by_session(self.mission.id).await?;
        let report = SessionReport::build((*self.mission).clone(), findings, endpoints);
        let json = report.export_json(self.redact_report)?;
        let path = self.report_path.clone();
        let written = {
            let path = path.clone();
            tokio::task::spawn_blocking(move || write_report(&path, json.as_bytes(), overwrite))
                .await??
        };
        Ok(if written {
            if self.redact_report {
                ExportOutcome::Written(format!(
                    "report written to {} (credentials masked)",
                    path.display()
                ))
            } else {
                ExportOutcome::Written(format!(
                    "report written to {}: raw, holds captured credentials (--redact to mask)",
                    path.display()
                ))
            }
        } else {
            ExportOutcome::Exists(path.display().to_string())
        })
    }
}

/// Write `bytes` to `path`. Without `overwrite` the file is created exclusively
/// (`Ok(false)` if it exists, no race); with it the data goes to a sibling
/// temp file that is renamed over the target, so a failure never truncates an
/// existing report.
fn write_report(path: &Path, bytes: &[u8], overwrite: bool) -> std::io::Result<bool> {
    use std::io::Write;
    if overwrite {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, bytes)?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        return Ok(true);
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(bytes)?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;
    use webrev_core::WebrevError;

    // The TUI status bar is an on-screen display, not an exported report:
    // per docs/security.md, seeds and tokens here stay masked regardless of
    // `--redact`, the same as the CLI's `eprintln!("skip out-of-scope: {}",
    // redact_url(seed))` / `eprintln!("dynamic: {}", redact_url(seed))`.

    #[test]
    fn skip_message_redacts_userinfo_and_token() {
        let seed = "https://user:hunter2@app.example.com/start?token=abcdEFGH12345678";
        let message = skip_out_of_scope_message(seed);
        assert!(!message.contains("hunter2"), "got: {message}");
        assert!(!message.contains("abcdEFGH12345678"), "got: {message}");
        assert!(message.contains("[REDACTED]"), "got: {message}");
    }

    #[test]
    fn dynamic_error_message_redacts_the_seed() {
        let seed = "https://admin:s3cr3t-pass@app.example.com/";
        let err = WebrevError::Browser("navigation timed out".into());
        let message = dynamic_error_message(seed, &err);
        assert!(!message.contains("s3cr3t-pass"), "got: {message}");
        assert!(message.contains("navigation timed out"), "got: {message}");
    }
}

#[cfg(test)]
mod export_tests {
    use super::write_report;

    #[test]
    fn existing_report_is_kept_until_overwrite_is_confirmed() {
        let dir = std::env::temp_dir().join(format!("webrev-tui-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        let _ = std::fs::remove_file(&path);

        assert!(write_report(&path, b"first", false).unwrap());
        assert!(!write_report(&path, b"second", false).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert!(write_report(&path, b"second", true).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(!dir.join("report.json.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
