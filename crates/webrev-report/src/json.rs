// crates/webrev-report/src/json.rs
//! The top-level JSON report document.

use crate::summary::Summary;
use serde::{Deserialize, Serialize};
use webrev_core::{Endpoint, Finding, Mission, Result, WebrevError};

/// A complete, serializable session report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    /// Version of the tool that produced the report.
    pub tool_version: String,
    pub mission: Mission,
    pub summary: Summary,
    pub endpoints: Vec<Endpoint>,
    pub findings: Vec<Finding>,
}

impl SessionReport {
    /// Assemble a report from a mission and its persisted data.
    #[must_use]
    pub fn build(mission: Mission, findings: Vec<Finding>, endpoints: Vec<Endpoint>) -> Self {
        let mut summary = Summary::from_findings(&findings);
        summary.set_endpoint_scopes(&endpoints);
        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            mission,
            summary,
            endpoints,
            findings,
        }
    }

    /// Render the report as pretty-printed JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| WebrevError::Config(format!("serializing report: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{Confidence, FindingKind, Method, Provenance, Scope, Source};

    #[test]
    fn builds_and_serializes_round_trip() {
        let mission = Mission::new("demo", Scope::new(vec!["x.test".into()], vec![]), vec![]);
        let findings = vec![Finding::new(
            mission.id,
            FindingKind::Endpoint,
            Some("/api".into()),
            "GET /api",
            Confidence::High,
            Provenance::new(Source::JsAst, None),
        )];
        let endpoints = vec![Endpoint::new("/api", Method::Get, Source::JsAst)];

        let report = SessionReport::build(mission, findings, endpoints);
        let json = report.to_json().expect("serialize");
        assert!(json.contains("\"total\": 1"));
        assert!(json.contains("\"endpoint\": 1"));

        // Round-trips back into an equal report.
        let parsed: SessionReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.summary, report.summary);
        assert_eq!(parsed.findings.len(), 1);
    }
}
