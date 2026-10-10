// crates/webrev-core/src/security/mod.rs
//! Cross-cutting security utilities: text/header sanitization and the
//! operational configuration (egress, DNS, rotation, cadence).

pub mod auth;
pub mod opsec;
pub mod sanitize;
