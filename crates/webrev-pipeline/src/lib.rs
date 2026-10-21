// crates/webrev-pipeline/src/lib.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: stage `run` methods document their contract on the `Stage`
// trait; the pipeline types read clearly through the re-exports below; and the
// engine's two `expect`s guard structural invariants (channel count) that
// cannot fail, so a prose `# Panics` note would be misleading.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions
)]

//! `webrev-pipeline`: tokio orchestration that wires the extraction and
//! storage crates together into a cancellable, event-emitting flow.
//!
//! The unit passed between stages is [`PipelineItem`]: either raw fetched
//! [`Content`](PipelineItem::Content) awaiting extraction, or a produced
//! [`Finding`](webrev_core::Finding) flowing toward storage. Each stage runs in
//! its own tokio task, connected by bounded `mpsc` channels; progress is
//! published on a `broadcast` channel the TUI subscribes to.

pub mod active;
pub mod engine;
pub mod events;
pub mod stage;
pub mod stages;

pub use active::{active_targets, bola_candidates, run_active_scan, run_bola_scan, BolaCandidate};
pub use active::{
    run_ws_replay_scan, ws_frame_candidates, WsDirection, WsFrameCandidate, WsMutation,
    MAX_WS_REPLAY_FRAMES,
};
pub use engine::{PipelineBuilder, PipelineSummary};
pub use events::PipelineEvent;
pub use stage::{PipelineItem, Stage, StageContext};

mod dns;
mod targets;
