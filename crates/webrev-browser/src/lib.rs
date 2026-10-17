// crates/webrev-browser/src/lib.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: the public surface is small and documented inline; error and
// panic contracts of the async entry points are described on the functions,
// and the re-exported type names read clearly.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    // `run_dynamic` is a single sequential driver (launch → inject → dwell →
    // collect); splitting it would scatter the browser lifecycle for no gain.
    clippy::too_many_lines
)]

//! `webrev-browser`: the **only** crate that depends on `chromiumoxide`.
//!
//! It drives a headless Chromium instance for dynamic analysis: a disposable
//! [`BrowserProfile`], a small [`BrowserPool`], injected `fetch`/XHR
//! [`hooks`], CDP network capture into a [`har`] model, and the
//! [`run_dynamic`] entry point that ties them together into a `Vec<Finding>`.
//!
//! The anti-automation touches in the profile (normalising `navigator.webdriver`
//! and friends) exist so that legitimate, authorized analysis is not blocked
//! outright by trivial headless detection; they do not impersonate any specific
//! target or user.

pub mod dynamic;
pub(crate) mod egress_proxy;
pub mod har;
pub mod hooks;
pub mod policy;
pub mod pool;
pub mod profile;

pub use dynamic::{run_dynamic, run_dynamic_with_report};
pub use har::{Har, HarEntry};
pub use policy::{DynamicRunReport, InteractionPolicy, RefusalReason, RefusedRequest};
pub use pool::{BrowserPool, PooledBrowser};
pub use profile::BrowserProfile;
