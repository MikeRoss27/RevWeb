// crates/webrev-report/src/summary.rs
//! Aggregate counts over a session's findings.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use webrev_core::{Endpoint, Finding};

/// Counters grouped by finding kind and by confidence, plus a grand total.
/// `BTreeMap` keeps the JSON output deterministically ordered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub total: usize,
    pub by_kind: BTreeMap<String, usize>,
    pub by_confidence: BTreeMap<String, usize>,
    pub by_severity: BTreeMap<String, usize>,
    #[serde(default)]
    pub by_status: BTreeMap<String, usize>,
    /// Unique endpoints split by internal (in-scope) vs external (third-party).
    pub endpoints_by_scope: BTreeMap<String, usize>,
    /// Unique endpoints split by best evidence tier (`inferred`/`static`/
    /// `observed`) — the strongest source among every finding that
    /// normalized into that endpoint. See `webrev_core::EndpointConfidence`.
    #[serde(default)]
    pub endpoints_by_evidence_tier: BTreeMap<String, usize>,
}

impl Summary {
    /// Tally a slice of findings.
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self {
            total: findings.len(),
            ..Self::default()
        };
        for finding in findings {
            *summary
                .by_kind
                .entry(finding.kind.slug().to_owned())
                .or_insert(0) += 1;
            *summary
                .by_confidence
                .entry(finding.confidence.slug().to_owned())
                .or_insert(0) += 1;
            *summary
                .by_severity
                .entry(finding.severity().slug().to_owned())
                .or_insert(0) += 1;
            *summary
                .by_status
                .entry(finding.status.slug().to_owned())
                .or_insert(0) += 1;
        }
        summary
    }

    /// Record the internal/external split and best-evidence-tier breakdown
    /// of the session's unique (normalized) endpoints.
    pub fn set_endpoint_scopes(&mut self, endpoints: &[Endpoint]) {
        self.endpoints_by_scope.clear();
        self.endpoints_by_evidence_tier.clear();
        for endpoint in endpoints {
            *self
                .endpoints_by_scope
                .entry(endpoint.scope.slug().to_owned())
                .or_insert(0) += 1;
            *self
                .endpoints_by_evidence_tier
                .entry(endpoint.confidence.slug().to_owned())
                .or_insert(0) += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{Confidence, FindingKind, Provenance, SessionId, Source};

    #[test]
    fn counts_by_kind_and_confidence() {
        let sid = SessionId::new();
        let mk = |kind, conf| {
            Finding::new(
                sid,
                kind,
                Some("/x".into()),
                "v",
                conf,
                Provenance::new(Source::Html, None),
            )
        };
        let findings = vec![
            mk(FindingKind::Endpoint, Confidence::High),
            mk(FindingKind::Endpoint, Confidence::Low),
            mk(FindingKind::Script, Confidence::High),
        ];
        let summary = Summary::from_findings(&findings);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.by_kind["endpoint"], 2);
        assert_eq!(summary.by_kind["script"], 1);
        assert_eq!(summary.by_confidence["high"], 2);
        assert_eq!(summary.by_confidence["low"], 1);
    }

    #[test]
    fn endpoint_evidence_tiers_are_tallied() {
        use webrev_core::{Endpoint, Method};

        let endpoints = vec![
            Endpoint::new("/live", Method::Get, Source::Browser),
            Endpoint::new("/static", Method::Get, Source::JsAst),
            Endpoint::new("/guessed/{id}", Method::Get, Source::JsRegex).with_inferred_pattern(),
        ];
        let mut summary = Summary::default();
        summary.set_endpoint_scopes(&endpoints);
        assert_eq!(summary.endpoints_by_evidence_tier["observed"], 1);
        assert_eq!(summary.endpoints_by_evidence_tier["static"], 1);
        assert_eq!(summary.endpoints_by_evidence_tier["inferred"], 1);
    }
}
