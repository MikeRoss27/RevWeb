// crates/webrev-pipeline/src/stages/store.rs
//! Deduplicates with `Finding::dedup_key` before recording in memory through
//! the [`Storage`](webrev_storage::Storage) port. Normalized endpoint exports
//! resolve relative references while finding evidence keeps its original URL.

use crate::events::PipelineEvent;
use crate::stage::{PipelineItem, Stage, StageContext};
use async_trait::async_trait;
use std::collections::BTreeSet;
use tokio::sync::{broadcast, mpsc};
use webrev_core::{normalize_url_with_pattern, Endpoint, FindingKind, Method, Result};

/// The persistence stage. Terminal in the standard pipeline; it forwards each
/// *stored* finding downstream so the engine can count unique results.
pub struct StoreStage;

impl StoreStage {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for StoreStage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Stage for StoreStage {
    fn name(&self) -> &'static str {
        "store"
    }

    async fn run(
        &self,
        ctx: StageContext,
        mut input: mpsc::Receiver<PipelineItem>,
        out: mpsc::Sender<PipelineItem>,
        events: broadcast::Sender<PipelineEvent>,
    ) -> Result<()> {
        let _ = events.send(PipelineEvent::StageStarted {
            stage: self.name().to_owned(),
        });
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut stored = 0usize;
        let mut resolver = crate::targets::EndpointResolver::new(&ctx.mission);

        loop {
            let item = tokio::select! {
                () = ctx.cancel.cancelled() => break,
                maybe = input.recv() => match maybe {
                    Some(item) => item,
                    None => break,
                },
            };

            // The store stage only acts on findings; stray content is ignored.
            let PipelineItem::Finding(finding) = item else {
                continue;
            };

            // Merge repeated resources without dropping distinct facts on one URL.
            if let Err(e) = ctx.storage.insert_finding(&finding).await {
                let _ = events.send(PipelineEvent::Error {
                    stage: self.name().to_owned(),
                    message: format!("insert_finding: {e}"),
                });
                continue;
            }
            // Storage merges provenance and independent evidence even when
            // this stage suppresses duplicate events and endpoint rows.
            let first_seen = seen.insert(finding.dedup_key());
            if !first_seen && finding.kind != FindingKind::Endpoint {
                continue;
            }

            // Fan out to the typed side-tables and emit kind-specific events.
            match finding.kind {
                FindingKind::Endpoint => {
                    let method = finding
                        .value
                        .split_whitespace()
                        .next()
                        .map_or(Method::Unknown, Method::parse);
                    let raw = resolver.resolve(&finding).map_or_else(
                        || finding.url.clone().unwrap_or_else(|| finding.value.clone()),
                        |url| url.to_string(),
                    );
                    let (normalized, inferred_pattern) = normalize_url_with_pattern(&raw);
                    // Classify against the mission scope on the raw (host-bearing)
                    // URL before normalization strips nothing host-relevant.
                    let endpoint_scope = ctx.mission.scope.classify(&raw);
                    let mut endpoint = Endpoint::new(normalized, method, finding.provenance.source)
                        .with_scope(endpoint_scope);
                    if inferred_pattern {
                        endpoint = endpoint.with_inferred_pattern();
                    }
                    if let Err(e) = ctx.storage.insert_endpoint(ctx.session_id, &endpoint).await {
                        let _ = events.send(PipelineEvent::Error {
                            stage: self.name().to_owned(),
                            message: format!("insert_endpoint: {e}"),
                        });
                    }
                }
                FindingKind::Secret => {
                    // `value` is already a fingerprint (see core::sanitize).
                    if let Err(e) = ctx
                        .storage
                        .insert_secret(ctx.session_id, &finding.value)
                        .await
                    {
                        let _ = events.send(PipelineEvent::Error {
                            stage: self.name().to_owned(),
                            message: format!("insert_secret: {e}"),
                        });
                    }
                    let _ = events.send(PipelineEvent::SecretDetected {
                        fingerprint: finding.value.clone(),
                        plaintext: finding.plaintext.clone(),
                    });
                }
                FindingKind::SourceMap
                | FindingKind::Form
                | FindingKind::Link
                | FindingKind::Script
                | FindingKind::Route
                | FindingKind::GraphQl
                | FindingKind::Technology
                | FindingKind::Parameter
                | FindingKind::Config
                | FindingKind::WebSocketFrame
                | FindingKind::WebSocketReplay
                | FindingKind::Vulnerability
                | FindingKind::Idor
                | FindingKind::ScanCoverage
                | FindingKind::GraphQlSchema
                | FindingKind::McpTools => {}
            }

            if !first_seen {
                continue;
            }

            let _ = events.send(PipelineEvent::Finding(Box::new(finding.clone())));
            stored += 1;

            if out.send(PipelineItem::Finding(finding)).await.is_err() {
                // No tail drainer; that is fine for a terminal stage.
                break;
            }
        }

        let _ = events.send(PipelineEvent::StageCompleted {
            stage: self.name().to_owned(),
            emitted: stored,
        });
        Ok(())
    }
}
