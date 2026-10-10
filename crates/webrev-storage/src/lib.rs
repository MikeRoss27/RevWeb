// crates/webrev-storage/src/lib.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: the `Storage` port's fallible methods document their contract
// on the trait itself rather than per-impl, and `SqliteStorage`/`InMemoryStorage`
// echo the module name only through the public re-exports.
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

//! `webrev-storage`: persistence behind the [`Storage`] port.
//!
//! Two backends implement the same trait:
//! * [`SqliteStorage`] — the real, durable backend (embedded migrations, no
//!   compile-time schema so it needs no `DATABASE_URL`).
//! * [`InMemoryStorage`] — a `BTreeMap`-backed double used by the pipeline
//!   integration tests.

pub mod backends;
pub mod port;

pub use backends::memory::InMemoryStorage;
pub use backends::sqlite::SqliteStorage;
pub use port::Storage;
