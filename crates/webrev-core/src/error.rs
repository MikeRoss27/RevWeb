// crates/webrev-core/src/error.rs
//! The single error type returned by the `webrev-*` library crates.
//!
//! Binaries (`webrev-cli`, `webrev-tui`) wrap this in `anyhow::Error`; the
//! libraries never do, so callers can match on specific variants.

use thiserror::Error;

/// All failure modes the libraries can surface.
///
/// Network / storage / browser backends carry their own rich error types, but
/// those crates are optional dependencies of `webrev-core`, so we flatten them
/// into owned `String` messages at the boundary. This keeps the domain crate
/// dependency-free while preserving the original diagnostic.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WebrevError {
    /// Wrapping of `std::io` failures (reading fixtures, temp profiles, ...).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A fetch stage could not retrieve a resource.
    #[error("fetch error: {0}")]
    Fetch(String),

    /// An extractor failed to parse its input.
    #[error("parse error: {0}")]
    Parse(String),

    /// The storage backend failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// The headless browser backend failed.
    #[error("browser error: {0}")]
    Browser(String),

    /// A pipeline stage failed or a channel closed unexpectedly.
    #[error("pipeline error: {0}")]
    Pipeline(String),

    /// Invalid or unparseable configuration / input.
    #[error("config error: {0}")]
    Config(String),

    /// A URL was syntactically invalid.
    #[error("invalid url: {0}")]
    InvalidUrl(String),

    /// A target fell outside the mission scope.
    #[error("target out of scope: {0}")]
    OutOfScope(String),
}
