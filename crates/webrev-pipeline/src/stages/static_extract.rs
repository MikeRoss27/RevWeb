// crates/webrev-pipeline/src/stages/static_extract.rs
//! Turns fetched `Content` into findings via `webrev-extract`. Performs **no**
//! network or filesystem I/O — all extraction is in-memory and synchronous.

use crate::events::PipelineEvent;
use crate::stage::{PipelineItem, Stage, StageContext};
use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc};
use webrev_core::Result;
use webrev_extract::{extractors::DomSinkExtractor, ExtractInput};

/// The static analysis stage.
pub struct StaticExtractStage;

impl StaticExtractStage {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for StaticExtractStage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Stage for StaticExtractStage {
    fn name(&self) -> &'static str {
        "static-extract"
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
        let mut emitted = 0usize;
        let link_modules = ctx.registry.names().contains(&"dom-sinks");
        let mut modules = Vec::new();

        loop {
            let item = tokio::select! {
                () = ctx.cancel.cancelled() => break,
                maybe = input.recv() => match maybe {
                    Some(item) => item,
                    None => break,
                },
            };

            match item {
                PipelineItem::Content {
                    url,
                    kind,
                    body,
                    headers,
                    bytes,
                } => {
                    let mut extract_input =
                        ExtractInput::new(ctx.session_id, url, kind, body).with_headers(headers);
                    if let Some(bytes) = bytes {
                        extract_input = extract_input.with_bytes(bytes);
                    }
                    for finding in ctx.registry.run(&extract_input) {
                        if out.send(PipelineItem::Finding(finding)).await.is_err() {
                            // Downstream closed: nothing left to do.
                            return Ok(());
                        }
                        emitted += 1;
                    }
                    if link_modules {
                        DomSinkExtractor::retain_module_input(&mut modules, extract_input);
                    }
                    let _ = events.send(PipelineEvent::Progress {
                        stage: self.name().to_owned(),
                        processed: emitted,
                    });
                }
                // Findings produced upstream pass straight through.
                already_finding @ PipelineItem::Finding(_) => {
                    if out.send(already_finding).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }

        if !ctx.cancel.is_cancelled() && !modules.is_empty() && link_modules {
            for finding in DomSinkExtractor::extract_modules(&modules) {
                if out.send(PipelineItem::Finding(finding)).await.is_err() {
                    return Ok(());
                }
                emitted += 1;
            }
        }

        let _ = events.send(PipelineEvent::StageCompleted {
            stage: self.name().to_owned(),
            emitted,
        });
        Ok(())
    }
}
