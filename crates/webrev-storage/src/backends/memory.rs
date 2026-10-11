// crates/webrev-storage/src/backends/memory.rs
//! Process-local [`Storage`] for all scans and the TUI.

use crate::port::Storage;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Mutex;
use webrev_core::{Endpoint, Finding, Mission, Result, SessionId, WebrevError};

#[derive(Default)]
struct State {
    sessions: BTreeMap<SessionId, String>,
    /// Creation order, so `latest_session` can return the newest.
    order: Vec<SessionId>,
    findings: BTreeMap<SessionId, Vec<Finding>>,
    endpoints: BTreeMap<SessionId, Vec<Endpoint>>,
    secrets: BTreeMap<SessionId, Vec<String>>,
}

/// A `BTreeMap`-backed store. Cheap to construct, deterministic iteration
/// order, no filesystem writes.
#[derive(Default)]
pub struct InMemoryStorage {
    state: Mutex<State>,
}

impl InMemoryStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|e| WebrevError::Storage(format!("in-memory lock poisoned: {e}")))
    }
}

#[async_trait]
impl Storage for InMemoryStorage {
    async fn create_session(&self, mission: &Mission) -> Result<()> {
        let mut state = self.lock()?;
        if state
            .sessions
            .insert(mission.id, mission.name.clone())
            .is_none()
        {
            state.order.push(mission.id);
        }
        Ok(())
    }

    async fn latest_session(&self) -> Result<Option<SessionId>> {
        Ok(self.lock()?.order.last().copied())
    }

    async fn insert_finding(&self, finding: &Finding) -> Result<()> {
        self.lock()?
            .findings
            .entry(finding.session_id)
            .or_default()
            .push(finding.clone());
        Ok(())
    }

    async fn insert_endpoint(&self, session: SessionId, endpoint: &Endpoint) -> Result<()> {
        self.lock()?
            .endpoints
            .entry(session)
            .or_default()
            .push(endpoint.clone());
        Ok(())
    }

    async fn insert_secret(&self, session: SessionId, fingerprint: &str) -> Result<()> {
        self.lock()?
            .secrets
            .entry(session)
            .or_default()
            .push(fingerprint.to_owned());
        Ok(())
    }

    async fn findings_by_session(&self, session: SessionId) -> Result<Vec<Finding>> {
        Ok(self
            .lock()?
            .findings
            .get(&session)
            .cloned()
            .unwrap_or_default())
    }

    async fn endpoints_by_session(&self, session: SessionId) -> Result<Vec<Endpoint>> {
        Ok(self
            .lock()?
            .endpoints
            .get(&session)
            .cloned()
            .unwrap_or_default())
    }

    async fn cleanup_session(&self, session: SessionId) -> Result<()> {
        let mut state = self.lock()?;
        state.sessions.remove(&session);
        state.order.retain(|s| *s != session);
        state.findings.remove(&session);
        state.endpoints.remove(&session);
        state.secrets.remove(&session);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{Confidence, FindingKind, Method, Provenance, Scope, Source};

    #[tokio::test]
    async fn round_trips_findings_and_cleans_up() {
        let store = InMemoryStorage::new();
        let mission = Mission::new("t", Scope::default(), vec![]);
        store.create_session(&mission).await.unwrap();

        let f = Finding::new(
            mission.id,
            FindingKind::Endpoint,
            Some("/api/x".into()),
            "GET /api/x",
            Confidence::High,
            Provenance::new(Source::JsAst, None),
        );
        store.insert_finding(&f).await.unwrap();
        store
            .insert_endpoint(
                mission.id,
                &Endpoint::new("/api/x", Method::Get, Source::JsAst),
            )
            .await
            .unwrap();
        store.insert_secret(mission.id, "fp:abc").await.unwrap();

        assert_eq!(
            store.findings_by_session(mission.id).await.unwrap().len(),
            1
        );
        assert_eq!(
            store.endpoints_by_session(mission.id).await.unwrap().len(),
            1
        );

        store.cleanup_session(mission.id).await.unwrap();
        let remaining = store.findings_by_session(mission.id).await.unwrap();
        assert_eq!(remaining, Vec::new());
    }
}
