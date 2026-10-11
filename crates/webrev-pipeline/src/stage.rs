// crates/webrev-pipeline/src/stage.rs
//! The `Stage` abstraction, the item that flows between stages, and the shared
//! context handed to every stage.

use crate::events::PipelineEvent;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use webrev_core::{Finding, Mission, OpsecConfig, Result, SessionId};
use webrev_extract::{ContentKind, ExtractorRegistry};
use webrev_storage::Storage;

/// The unit that travels between stages.
///
/// A bare `Finding` cannot carry a fetched body to the (network-free)
/// extraction stage, so the channel is polymorphic: fetch emits `Content`,
/// extract turns `Content` into `Finding`s, and store consumes `Finding`s.
#[derive(Debug, Clone)]
pub enum PipelineItem {
    /// Raw fetched content awaiting extraction.
    Content {
        url: Option<String>,
        kind: ContentKind,
        /// The raw body text. Empty for binary content (e.g. `ContentKind::Wasm`):
        /// a binary body is never lossily decoded to UTF-8, it is carried in
        /// `bytes` instead.
        body: String,
        /// HTTP response headers, if any (empty for recovered/inline content).
        headers: Vec<(String, String)>,
        /// Raw bytes of this content, when it is binary (e.g. a fetched
        /// `.wasm` module). `None` for text content.
        bytes: Option<Vec<u8>>,
    },
    /// A produced finding flowing toward storage.
    Finding(Finding),
}

/// Shared, cheaply-cloneable handles available to every stage.
#[derive(Clone)]
pub struct StageContext {
    pub mission: Arc<Mission>,
    pub opsec: Arc<OpsecConfig>,
    pub session_id: SessionId,
    pub registry: Arc<ExtractorRegistry>,
    pub storage: Arc<dyn Storage>,
    pub cancel: CancellationToken,
}

impl StageContext {
    #[must_use]
    pub fn new(
        mission: Arc<Mission>,
        opsec: Arc<OpsecConfig>,
        registry: Arc<ExtractorRegistry>,
        storage: Arc<dyn Storage>,
        cancel: CancellationToken,
    ) -> Self {
        let session_id = mission.id;
        Self {
            mission,
            opsec,
            session_id,
            registry,
            storage,
            cancel,
        }
    }
}

/// A single processing stage.
///
/// `run` consumes items from `input`, forwards or produces items on `out`, and
/// publishes progress on `events`. A stage returns when `input` is exhausted
/// (its upstream dropped the sender) or when `ctx.cancel` fires. Dropping `out`
/// on return propagates shutdown downstream.
#[async_trait]
pub trait Stage: Send + Sync {
    /// Stable name used in events and logs.
    fn name(&self) -> &'static str;

    /// Run the stage to completion.
    async fn run(
        &self,
        ctx: StageContext,
        input: mpsc::Receiver<PipelineItem>,
        out: mpsc::Sender<PipelineItem>,
        events: broadcast::Sender<PipelineEvent>,
    ) -> Result<()>;
}
