//! Cross-target correlation of observed technology and API route shapes.
//!
//! A match is a lead for manual investigation, not proof that two targets
//! share a deployment. Callers should pass one profile per authorized target.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use webrev_core::{normalize_url, Endpoint, EndpointScope, Finding, FindingKind};

/// A deterministic, portable summary of one scanned domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetFingerprint {
    /// Domain or URL used to identify this target.
    pub target: String,
    /// Technology findings, retaining their display names and categories.
    pub technologies: BTreeSet<String>,
    /// `METHOD /route/{id}` mapped to its best observed confidence (0–100).
    pub api_routes: BTreeMap<String, u8>,
}

impl TargetFingerprint {
    /// Build a profile from a target's scan observations. Absolute URLs from
    /// unrelated hosts are discarded; relative URLs belong to this target.
    #[must_use]
    pub fn from_scan(
        target: impl Into<String>,
        findings: &[Finding],
        endpoints: &[Endpoint],
    ) -> Self {
        let target = target.into();
        let target_host = host(&target);
        let mut technologies = BTreeSet::new();
        for finding in findings
            .iter()
            .filter(|f| f.kind == FindingKind::Technology)
        {
            let location = finding
                .provenance
                .location
                .as_deref()
                .or(finding.url.as_deref());
            if location.is_none_or(|url| belongs_to_target(url, target_host)) {
                technologies.insert(finding.value.clone());
            }
        }

        let mut api_routes = BTreeMap::new();
        for endpoint in endpoints {
            if endpoint.scope != EndpointScope::Internal
                || !belongs_to_target(&endpoint.url, target_host)
            {
                continue;
            }
            let normalized = normalize_url(&endpoint.url);
            let path = normalized
                .split_once("://")
                .map_or(normalized.as_str(), |(_, rest)| {
                    rest.find('/').map_or("/", |index| &rest[index..])
                });
            if path == "/" || looks_like_asset(path) {
                continue;
            }
            let key = format!("{} {}", endpoint.method, path.to_ascii_lowercase());
            let score = endpoint.confidence.score();
            api_routes
                .entry(key)
                .and_modify(|existing: &mut u8| *existing = (*existing).max(score))
                .or_insert(score);
        }
        Self {
            target,
            technologies,
            api_routes,
        }
    }
}

/// Shared evidence for one pair of targets, ordered by strongest score first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetMatch {
    pub left: String,
    pub right: String,
    pub shared_technologies: Vec<String>,
    pub shared_api_routes: Vec<String>,
    /// Correlation signal from 0 to 100; this is not a probability.
    pub score: u8,
}

/// Compare every pair of distinct targets. Pairs with no shared evidence are
/// omitted. Common vendor detections contribute little to the score.
#[must_use]
pub fn compare_targets(targets: &[TargetFingerprint]) -> Vec<TargetMatch> {
    let mut matches = Vec::new();
    for (i, left) in targets.iter().enumerate() {
        for right in targets.iter().skip(i + 1) {
            if left.target == right.target {
                continue;
            }
            let shared_technologies: Vec<String> = left
                .technologies
                .intersection(&right.technologies)
                .cloned()
                .collect();
            let shared_api_routes: Vec<String> = left
                .api_routes
                .keys()
                .filter(|route| right.api_routes.contains_key(*route))
                .cloned()
                .collect();
            if shared_technologies.is_empty() && shared_api_routes.is_empty() {
                continue;
            }

            let tech_score: u16 = shared_technologies
                .iter()
                .map(|tech| technology_weight(tech))
                .sum::<u16>()
                .min(40);
            let route_score: u16 = shared_api_routes
                .iter()
                .map(|route| {
                    let confidence = left.api_routes[route].min(right.api_routes[route]);
                    // One matching observed route is stronger than several
                    // low-confidence inferred templates.
                    u16::from(confidence) * 30 / 100
                })
                .sum::<u16>()
                .min(60);
            matches.push(TargetMatch {
                left: left.target.clone(),
                right: right.target.clone(),
                shared_technologies,
                shared_api_routes,
                score: u8::try_from(tech_score + route_score).unwrap_or(u8::MAX),
            });
        }
    }
    matches.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.left.cmp(&b.left))
            .then_with(|| a.right.cmp(&b.right))
    });
    matches
}

fn technology_weight(technology: &str) -> u16 {
    let category = technology
        .rsplit_once(" (")
        .map_or("", |(_, category)| category.trim_end_matches(')'));
    match category {
        "analytics" | "observability" | "edge" | "payments" => 2,
        "framework" | "cms" | "commerce" => 8,
        "auth" | "baas/db" | "db" | "backend" | "gateway" | "api" => 10,
        _ => 4,
    }
}

fn host(value: &str) -> Option<&str> {
    let authority = value.split_once("://").map_or(value, |(_, rest)| rest);
    let authority = authority.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let name = authority.split(':').next()?.trim_end_matches('.');
    (!name.is_empty()).then_some(name)
}

fn belongs_to_target(url: &str, target_host: Option<&str>) -> bool {
    if !url.contains("://") {
        return true;
    }
    let (Some(observed), Some(target)) = (host(url), target_host) else {
        return false;
    };
    let observed = observed.to_ascii_lowercase();
    let target = target.to_ascii_lowercase();
    observed == target || observed.ends_with(&format!(".{target}"))
}

fn looks_like_asset(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or_default();
    let extension = last.rsplit_once('.').map(|(_, ext)| ext);
    matches!(
        extension,
        Some(
            "js" | "mjs"
                | "css"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "svg"
                | "ico"
                | "woff"
                | "woff2"
                | "map"
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{Confidence, Method, Provenance, SessionId, Source};

    fn tech(value: &str, location: &str) -> Finding {
        Finding::new(
            SessionId::new(),
            FindingKind::Technology,
            None,
            value,
            Confidence::High,
            Provenance::new(Source::Html, Some(location.into())),
        )
    }

    #[test]
    fn profiles_isolate_hosts_and_normalize_api_routes() {
        let findings = vec![
            tech("Next.js (framework)", "https://a.test/"),
            tech("Cloudflare (edge)", "https://b.test/"),
        ];
        let endpoints = vec![
            Endpoint::new("https://a.test/api/users/123", Method::Get, Source::Browser),
            Endpoint::new("https://a.test/static/app.js", Method::Get, Source::Browser),
            Endpoint::new("https://b.test/api/users/123", Method::Get, Source::Browser),
        ];
        let profile = TargetFingerprint::from_scan("a.test", &findings, &endpoints);
        assert!(profile.technologies.contains("Next.js (framework)"));
        assert!(!profile.technologies.contains("Cloudflare (edge)"));
        assert_eq!(profile.api_routes["GET /api/users/{id}"], 100);
        assert_eq!(profile.api_routes.len(), 1);
    }

    #[test]
    fn shared_api_is_stronger_than_shared_edge_vendor() {
        let common = tech("Cloudflare (edge)", "https://a.test/");
        let a = TargetFingerprint::from_scan(
            "a.test",
            &[common],
            &[Endpoint::new(
                "https://a.test/api/users/1",
                Method::Get,
                Source::Browser,
            )],
        );
        let b = TargetFingerprint::from_scan(
            "b.test",
            &[tech("Cloudflare (edge)", "https://b.test/")],
            &[Endpoint::new(
                "https://b.test/api/users/2",
                Method::Get,
                Source::JsAst,
            )],
        );
        let matches = compare_targets(&[a, b]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].shared_api_routes, ["GET /api/users/{id}"]);
        assert_eq!(matches[0].score, 23);
    }
}
