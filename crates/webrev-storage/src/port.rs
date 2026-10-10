// crates/webrev-storage/src/port.rs
//! The storage port: the only interface the rest of the workspace depends on.

use async_trait::async_trait;
use webrev_core::{Endpoint, Finding, Mission, Result, SessionId};

/// Persistence operations required by the pipeline and report crates.
///
/// All methods return [`webrev_core::Result`]; backends map their native
/// errors into [`webrev_core::WebrevError::Storage`]. Implementations must be
/// `Send + Sync` so a single handle can be shared across pipeline tasks.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Record a session so findings can reference it. Idempotent.
    async fn create_session(&self, mission: &Mission) -> Result<()>;

    /// Persist one finding.
    async fn insert_finding(&self, finding: &Finding) -> Result<()>;

    /// Persist one concrete endpoint for a session.
    async fn insert_endpoint(&self, session: SessionId, endpoint: &Endpoint) -> Result<()>;

    /// Persist a secret **fingerprint** (never plaintext) for a session.
    async fn insert_secret(&self, session: SessionId, fingerprint: &str) -> Result<()>;

    /// The most recently created session, if any. Lets the UX default to "the
    /// last scan" so callers never have to pass a session id by hand.
    async fn latest_session(&self) -> Result<Option<SessionId>>;

    /// All findings recorded for a session, in insertion order.
    async fn findings_by_session(&self, session: SessionId) -> Result<Vec<Finding>>;

    /// All endpoints recorded for a session.
    async fn endpoints_by_session(&self, session: SessionId) -> Result<Vec<Endpoint>>;

    /// Remove every row belonging to a session (findings, endpoints, secrets,
    /// and the session itself).
    async fn cleanup_session(&self, session: SessionId) -> Result<()>;
}
