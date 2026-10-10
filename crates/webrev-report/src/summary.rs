// crates/webrev-report/src/summary.rs
//! Aggregate counts over a session's findings.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use webrev_core::Finding;

/// Counters grouped by finding kind and by confidence, plus a grand total.
/// `BTreeMap` keeps the JSON output deterministically ordered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub total: usize,
    pub by_kind: BTreeMap<String, usize>,
    pub by_confidence: BTreeMap<String, usize>,
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
        }
        summary
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
            Finding::new(sid, kind, Some("/x".into()), "v", conf, Provenance::new(Source::Html, None))
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
}
