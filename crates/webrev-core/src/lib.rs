// crates/webrev-core/src/lib.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: for an MVP domain crate we do not require a `# Errors`/`# Panics`
// prose section on every fallible function, and type names that echo the module
// name (e.g. `error::WebrevError`) read fine via the crate re-exports below.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions
)]

//! `webrev-core`: the pure domain layer shared by every other crate.
//!
//! It contains no network, filesystem, or async code — only the data model
//! (`Finding`, `Endpoint`, `Mission`), the error type, and two cross-cutting
//! security utilities (`sanitize`, `opsec`) that the rest of the workspace
//! builds on.

pub mod error;
pub mod model;
pub mod security;

pub use error::WebrevError;
pub use model::endpoint::{Endpoint, EndpointScope, Method, Source};
pub use model::finding::{Confidence, Finding, FindingKind, Provenance, Severity};
pub use model::normalize::normalize_url;
pub use model::session::{Mission, Scope, SessionId};
pub use security::auth::AuthConfig;
pub use security::opsec::{
    DnsPolicy, EgressPolicy, MissionProfile, OpsecConfig, RotationPolicy,
};
pub use security::sanitize::{Sanitizer, SessionKey};

/// Convenience alias used throughout the workspace libraries.
pub type Result<T> = std::result::Result<T, WebrevError>;
