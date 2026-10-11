// crates/webrev-tui/src/lib.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: this is an application crate (anyhow at the boundary); the
// event loop and scan launchers are inherently long and side-effecting, so a
// handful of noisy pedantic lints are allowed with intent.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]

//! `webrev-tui`: a `ratatui` front-end that runs the pipeline live and renders
//! endpoints, findings, logs, and status across four tabs.
//!
//! Exposed as a library so the `webrev` CLI's `tui` subcommand can launch it,
//! and as a thin binary of its own.

pub mod app;
pub mod brand;
pub mod events;
pub mod ui;

mod runtime;

pub use runtime::{run, TuiOptions};
