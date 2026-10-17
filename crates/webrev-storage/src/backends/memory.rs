// crates/webrev-storage/src/backends/memory.rs
//! Process-local [`Storage`] for all scans and the TUI.

use crate::port::Storage;
use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use webrev_core::{Endpoint, Finding, Mission, Result, SessionId, WebrevError};

#[derive(Default)]
struct State {
    sessions: BTreeMap<SessionId, String>,
    /// Creation order, so `latest_session` can return the newest.
    order: Vec<SessionId>,
    findings: BTreeMap<SessionId, Vec<Finding>>,
    /// Fast lookup into `findings`; vectors remain the canonical ordered data.
    finding_indexes: BTreeMap<SessionId, HashMap<String, usize>>,
    endpoints: BTreeMap<SessionId, Vec<Endpoint>>,
    /// Fast lookup into `endpoints`, keyed exactly like endpoint merging.
    endpoint_indexes: BTreeMap<SessionId, HashMap<(String, webrev_core::Method), usize>>,
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
        let mut state = self.lock()?;
        let key = finding.dedup_key();
        let position = state
            .finding_indexes
            .get(&finding.session_id)
            .and_then(|index| index.get(&key))
            .copied();
        let findings = state.findings.entry(finding.session_id).or_default();
        if let Some(position) = position {
            let existing = findings
                .get_mut(position)
                .expect("finding index points to an existing vector entry");
            existing.merge_from(finding.clone());
        } else {
            let position = findings.len();
            findings.push(finding.clone());
            state
                .finding_indexes
                .entry(finding.session_id)
                .or_default()
                .insert(key, position);
        }
        Ok(())
    }

    async fn insert_endpoint(&self, session: SessionId, endpoint: &Endpoint) -> Result<()> {
        let mut state = self.lock()?;
        let key = (endpoint.url.clone(), endpoint.method);
        let position = state
            .endpoint_indexes
            .get(&session)
            .and_then(|index| index.get(&key))
            .copied();
        let endpoints = state.endpoints.entry(session).or_default();
        if let Some(position) = position {
            let existing = endpoints
                .get_mut(position)
                .expect("endpoint index points to an existing vector entry");
            existing.merge_from(endpoint);
        } else {
            let position = endpoints.len();
            endpoints.push(endpoint.clone());
            state
                .endpoint_indexes
                .entry(session)
                .or_default()
                .insert(key, position);
        }
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
        state.finding_indexes.remove(&session);
        state.endpoints.remove(&session);
        state.endpoint_indexes.remove(&session);
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

    #[tokio::test]
    async fn merges_endpoint_observations_by_method_and_url() {
        let store = InMemoryStorage::new();
        let session = SessionId::new();
        let url = "https://example.test/api/users";
        store
            .insert_endpoint(session, &Endpoint::new(url, Method::Get, Source::JsAst))
            .await
            .unwrap();
        store
            .insert_endpoint(session, &Endpoint::new(url, Method::Get, Source::Browser))
            .await
            .unwrap();
        store
            .insert_endpoint(session, &Endpoint::new(url, Method::Post, Source::JsAst))
            .await
            .unwrap();

        let endpoints = store.endpoints_by_session(session).await.unwrap();
        assert_eq!(endpoints.len(), 2);
        let get = endpoints.iter().find(|e| e.method == Method::Get).unwrap();
        assert_eq!(get.source, Source::Browser);
        assert_eq!(get.confidence.score(), 100);
    }

    #[tokio::test]
    async fn indexed_findings_merge_provenance_and_keep_insertion_order() {
        let store = InMemoryStorage::new();
        let session = SessionId::new();
        let first = Finding::new(
            session,
            FindingKind::Endpoint,
            Some("/first".into()),
            "GET /first",
            Confidence::Medium,
            Provenance::new(Source::JsAst, Some("a.js:1".into())),
        );
        let mut repeated = first.clone();
        repeated.provenance = Provenance::new(Source::Browser, Some("/first".into()));
        repeated.provenances = vec![repeated.provenance.clone()];
        let second = Finding::new(
            session,
            FindingKind::Endpoint,
            Some("/second".into()),
            "GET /second",
            Confidence::High,
            Provenance::new(Source::JsRegex, Some("b.js:2".into())),
        );

        store.insert_finding(&first).await.unwrap();
        store.insert_finding(&second).await.unwrap();
        store.insert_finding(&repeated).await.unwrap();

        let findings = store.findings_by_session(session).await.unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].value, "GET /first");
        assert_eq!(findings[1].value, "GET /second");
        assert!(findings[0]
            .provenances
            .contains(&Provenance::new(Source::Browser, Some("/first".into()))));
    }
}
