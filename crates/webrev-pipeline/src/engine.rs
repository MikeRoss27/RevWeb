// crates/webrev-pipeline/src/engine.rs
//! Builds and runs a pipeline: one tokio task per stage, bounded `mpsc`
//! channels between them, and a drained tail channel for the summary.

use crate::events::PipelineEvent;
use crate::stage::{PipelineItem, Stage, StageContext};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use webrev_core::{Result, WebrevError};

/// Capacity of the inter-stage `mpsc` channels.
const CHANNEL_CAPACITY: usize = 1024;
/// Capacity of the `broadcast` event channel.
const EVENT_CAPACITY: usize = 256;

/// Outcome of a completed pipeline run.
#[derive(Debug, Clone)]
pub struct PipelineSummary {
    /// Stage names in execution order.
    pub stages: Vec<String>,
    /// Total items that exited the final stage.
    pub items_out: usize,
    /// Of those, how many were findings (post-deduplication).
    pub findings_emitted: usize,
    /// Number of stages that returned an error.
    pub errors: usize,
}

/// Fluent builder for a staged pipeline.
pub struct PipelineBuilder {
    stages: Vec<Arc<dyn Stage>>,
    events: broadcast::Sender<PipelineEvent>,
}

impl PipelineBuilder {
    #[must_use]
    pub fn new() -> Self {
        let (events, _rx) = broadcast::channel(EVENT_CAPACITY);
        Self {
            stages: Vec::new(),
            events,
        }
    }

    /// Append a stage. Stages run in insertion order.
    #[must_use]
    pub fn add_stage(mut self, stage: Arc<dyn Stage>) -> Self {
        self.stages.push(stage);
        self
    }

    /// Subscribe to pipeline events (e.g. from the TUI) before calling
    /// [`run`](Self::run).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<PipelineEvent> {
        self.events.subscribe()
    }

    /// Clone the event sender, for observers that outlive a single receiver.
    #[must_use]
    pub fn event_sender(&self) -> broadcast::Sender<PipelineEvent> {
        self.events.clone()
    }

    /// Run the pipeline to completion, seeding the first stage with `seed`.
    ///
    /// Returns once every stage task has joined.
    pub async fn run(
        self,
        ctx: StageContext,
        seed: Vec<PipelineItem>,
    ) -> Result<PipelineSummary> {
        let n = self.stages.len();
        if n == 0 {
            return Err(WebrevError::Pipeline("pipeline has no stages".into()));
        }
        let stage_names: Vec<String> =
            self.stages.iter().map(|s| s.name().to_string()).collect();

        // n+1 channels: txs[0]/rxs[0] feeds stage 0; rxs[n] is the drained tail.
        let mut txs = Vec::with_capacity(n + 1);
        let mut rxs = Vec::with_capacity(n + 1);
        for _ in 0..=n {
            let (tx, rx) = mpsc::channel::<PipelineItem>(CHANNEL_CAPACITY);
            txs.push(tx);
            rxs.push(rx);
        }

        // Engine keeps the source sender; the tail receiver is drained below.
        let source_tx = txs.remove(0); // txs[i] is now the OUT sender for stage i
        let mut final_rx = rxs.pop().expect("n+1 >= 2 receivers exist"); // rxs[i] is IN for stage i

        let mut join: JoinSet<(&'static str, Result<()>)> = JoinSet::new();
        for (stage, (in_rx, out_tx)) in self
            .stages
            .into_iter()
            .zip(rxs.into_iter().zip(txs))
        {
            let ctx = ctx.clone();
            let events = self.events.clone();
            join.spawn(async move {
                let name = stage.name();
                let result = stage.run(ctx, in_rx, out_tx, events).await;
                (name, result)
            });
        }

        // Feed the seed, then close the source so stage 0 can terminate.
        for item in seed {
            if source_tx.send(item).await.is_err() {
                break;
            }
        }
        drop(source_tx);

        // Drain the tail concurrently with the stages.
        let mut items_out = 0usize;
        let mut findings_emitted = 0usize;
        while let Some(item) = final_rx.recv().await {
            items_out += 1;
            if matches!(item, PipelineItem::Finding(_)) {
                findings_emitted += 1;
            }
        }

        // All stages have now dropped their senders; collect their results.
        let mut errors = 0usize;
        while let Some(joined) = join.join_next().await {
            match joined {
                Ok((_, Ok(()))) => {}
                Ok((name, Err(e))) => {
                    errors += 1;
                    let _ = self.events.send(PipelineEvent::Error {
                        stage: name.to_owned(),
                        message: e.to_string(),
                    });
                    tracing::warn!(stage = name, error = %e, "stage failed");
                }
                Err(join_err) => {
                    errors += 1;
                    tracing::error!(error = %join_err, "stage task panicked");
                }
            }
        }

        Ok(PipelineSummary {
            stages: stage_names,
            items_out,
            findings_emitted,
            errors,
        })
    }
}

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}
