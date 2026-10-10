// crates/webrev-pipeline/src/events.rs
//! Events broadcast by the pipeline for live observers (the TUI, logs).

use webrev_core::Finding;

/// A progress event. `Clone` because it travels on a `broadcast` channel.
#[derive(Debug, Clone)]
pub enum PipelineEvent {
    /// A stage began running.
    StageStarted { stage: String },
    /// A stage finished, having emitted `emitted` items downstream.
    StageCompleted { stage: String, emitted: usize },
    /// A finding reached storage (post-deduplication).
    Finding(Box<Finding>),
    /// A secret was detected and recorded as a fingerprint (never plaintext).
    SecretDetected { fingerprint: String },
    /// Periodic progress heartbeat from a stage.
    Progress { stage: String, processed: usize },
    /// A recoverable error occurred within a stage.
    Error { stage: String, message: String },
}
