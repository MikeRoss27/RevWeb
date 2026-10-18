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
    /// Set when credentials were masked on export (see [`SessionReport::redacted`]).
    /// Consumers that replay captured URLs, such as `webrev bola`, refuse such
    /// a report because the original object ids and tokens are gone.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub redacted: bool,
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
            redacted: false,
        }
    }

    /// Pretty JSON for a report that leaves the process: credentials are
    /// masked unless `redact` is false (`--unredacted`).
    pub fn export_json(&self, redact: bool) -> Result<String> {
        if redact {
            self.redacted().to_json()
        } else {
            self.to_json()
        }
    }

    /// Render the report as pretty-printed JSON, exactly as held in memory.
    /// Use [`SessionReport::export_json`] or [`SessionReport::render`] for
    /// anything written to a file, a pipe or a terminal.
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
