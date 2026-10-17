//! Keep concrete paths and query strings for probes; route templates are exports.
use std::collections::BTreeSet;
use webrev_core::{Endpoint, Finding, FindingKind, Method, Mission, Source};

/// Resolve captured endpoints within the mission, preserving identifiers and
/// parameters that the normalized endpoint list deliberately drops.
#[must_use]
pub fn active_targets(mission: &Mission, findings: &[Finding]) -> Vec<Endpoint> {
    let mut endpoints = Vec::new();
    let mut distinct = BTreeSet::new();
    let mut resolver = crate::targets::EndpointResolver::new(mission);
    for finding in findings.iter().filter(|f| f.kind == FindingKind::Endpoint) {
        let Some(raw) = finding.url.as_deref() else {
            continue;
        };
        if raw.contains(['{', '}']) {
            continue;
        }
        let Some(mut url) = resolver.resolve(finding) else {
            continue;
        };
        url.set_fragment(None);
        let url = url.to_string();
        let method = finding
            .value
            .split_whitespace()
            .next()
            .map_or(Method::Unknown, Method::parse);
        if mission.scope.allows(&url) && distinct.insert((method, url.clone())) {
            let source = if finding
                .provenances
                .iter()
                .any(|provenance| provenance.source == Source::Browser)
            {
                Source::Browser
            } else {
                finding.provenance.source
            };
            endpoints.push(Endpoint::new(url, method, source));
        }
    }
    for seed in &mission.seeds {
        if mission.scope.allows(seed) && distinct.insert((Method::Get, seed.clone())) {
            endpoints.push(Endpoint::new(seed.clone(), Method::Get, Source::Html));
        }
    }
    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{Confidence, Provenance, Scope};

    #[test]
    fn probes_preserve_query_and_id_and_resolve_document_relative_paths() {
        let mission = Mission::new(
            "fixture",
            Scope::new(vec!["x.test".into()], vec![]),
            vec!["https://x.test/app/".into()],
        );
        let mk = |url: &str| {
            Finding::new(
                mission.id,
                FindingKind::Endpoint,
                Some(url.into()),
                format!("GET {url}"),
                Confidence::High,
                Provenance::new(Source::JsAst, Some("https://x.test/assets/app.js".into())),
            )
        };
        let findings = vec![
            mk("/api/users/123?q=a"),
            mk("search?q=b"),
            mk("https://outside.test/api/1"),
            mk("/api/users/{id}"),
        ];
        let targets = active_targets(&mission, &findings);
        let urls: Vec<_> = targets.iter().map(|e| e.url.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "https://x.test/api/users/123?q=a",
                "https://x.test/app/search?q=b",
                "https://x.test/app/"
            ]
        );
    }

    #[test]
    fn merged_browser_provenance_remains_replay_eligible() {
        let mission = Mission::new(
            "fixture",
            Scope::new(vec!["x.test".into()], vec![]),
            vec!["https://x.test/".into()],
        );
        let mut finding = Finding::new(
            mission.id,
            FindingKind::Endpoint,
            Some("https://x.test/api/users/101".into()),
            "GET https://x.test/api/users/101",
            Confidence::High,
            Provenance::new(Source::JsAst, None),
        );
        finding
            .provenances
            .push(Provenance::new(Source::Browser, None));
        let targets = active_targets(&mission, &[finding]);
        assert_eq!(targets[0].source, Source::Browser);
    }
}
