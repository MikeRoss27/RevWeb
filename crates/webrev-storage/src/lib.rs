// crates/webrev-storage/src/lib.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: the `Storage` port's fallible methods document their contract
// on the trait itself rather than per-impl, and `InMemoryStorage`
// echo the module name only through the public re-exports.
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

//! `webrev-storage`: process-local session data behind the [`Storage`] port.
//! [`InMemoryStorage`] holds findings and endpoints until exit. Reports are
//! exported explicitly by the application; this crate never writes to disk.

pub mod backends;
pub mod fingerprint;
pub mod port;

pub use backends::memory::InMemoryStorage;
pub use fingerprint::{compare_targets, TargetFingerprint, TargetMatch};
pub use port::Storage;
