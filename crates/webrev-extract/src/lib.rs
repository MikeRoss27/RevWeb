// crates/webrev-extract/src/lib.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: extractors are leaf functions with no fallible public surface
// worth documenting per-call, and `ExtractInput`/`ExtractorRegistry` echo the
// module name only through the public re-exports, which read clearly.
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

//! `webrev-extract`: pure, synchronous extraction of findings from already
//! fetched content. This crate performs **zero network or filesystem I/O** —
//! callers hand it bytes, it hands back [`Finding`](webrev_core::Finding)s —
//! which keeps every extractor trivially unit-testable against fixtures.
//!
//! The entry point is [`ExtractorRegistry`], a priority-ordered set of
//! [`Extractor`]s. The pipeline's static stage owns one registry and feeds it
//! each HTML page and JavaScript file it fetches.

pub mod extractors;
pub mod registry;
pub mod traits;

pub use registry::ExtractorRegistry;
pub use traits::{ContentKind, ExtractInput, Extractor};
