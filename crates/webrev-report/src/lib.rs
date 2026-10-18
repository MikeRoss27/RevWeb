// crates/webrev-report/src/lib.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: the only fallible function documents its error inline, and the
// type names read clearly through the re-exports.
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

//! `webrev-report`: serializes a completed session into a JSON report.
//!
//! It is intentionally decoupled from storage: callers pass the already-read
//! [`Finding`](webrev_core::Finding)s and [`Endpoint`](webrev_core::Endpoint)s,
//! so this crate depends only on the domain model and `serde`.

pub mod format;
pub mod graph;
pub mod json;
pub mod openapi;
pub mod redact;
pub mod summary;
pub mod text;

pub use format::{RenderOptions, ReportFormat, ScopeFilter};
pub use json::SessionReport;
pub use summary::Summary;
