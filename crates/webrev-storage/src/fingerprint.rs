//! Cross-target correlation of observed technology, API route shapes, and
//! leaked secrets.
//!
//! A match is a lead for manual investigation, not proof that two targets
//! share a deployment. Callers should pass one profile per authorized target.
//!
//! The three signals are not equally strong, and [`TargetMatch`] keeps them
//! distinct rather than folding them into a single opaque number:
//!
//! - **Shared secret plaintext** is the strongest signal this module can
//!   produce: the same credential value appearing in two independently
//!   scanned targets is very unlikely by chance and usually means a shared
//!   backend, a shared build pipeline, or a reused key. It alone is enough
//!   for [`CorrelationTier::Strong`].
//! - **Shared API route shapes** (`METHOD /path/{id}`) observed at
//!   `static`-or-better confidence on both sides (i.e. actually present in
//!   fetched markup/JS, not merely guessed by normalizing a template) are a
//!   moderate signal: it shows the same route structure, which can mean a
//!   shared framework/codebase but can also just mean two unrelated apps
//!   that both expose a conventional REST shape.
//! - **Shared technology detections** alone (e.g. "both run Next.js", "both
//!   sit behind Cloudflare") are the weakest signal. Common frameworks and
//!   edge/CDN vendors are everywhere; this is never presented as strong
//!   evidence of a shared deployment by itself.
//!
//! Secret fingerprints (`Finding::value` for `FindingKind::Secret`) are keyed
//! per scan run ([`webrev_core::SessionKey`]) and are **not** comparable
//! across sessions, so this module compares `Finding::plaintext` instead —
//! the actual detected credential, which the project already treats as the
//! deliverable of a secret finding (see `docs/security.md`) and keeps even
//! in a `--redact`-ed report.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use webrev_core::{
    normalize_url, Endpoint, EndpointConfidence, EndpointScope, Finding, FindingKind,
};

/// A deterministic, portable summary of one scanned domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetFingerprint {
    /// Domain or URL used to identify this target.
    pub target: String,
    /// Technology findings, retaining their display names and categories.
    pub technologies: BTreeSet<String>,
    /// `METHOD /route/{id}` mapped to its best observed confidence (0–100).
    pub api_routes: BTreeMap<String, u8>,
    /// Detected secret plaintext values (not fingerprints — see module docs).
    pub secrets: BTreeSet<String>,
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

        let mut secrets = BTreeSet::new();
        for finding in findings.iter().filter(|f| f.kind == FindingKind::Secret) {
            let location = finding
                .provenance
                .location
                .as_deref()
                .or(finding.url.as_deref());
            if !location.is_none_or(|url| belongs_to_target(url, target_host)) {
                continue;
            }
            if let Some(plaintext) = &finding.plaintext {
                secrets.insert(plaintext.clone());
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
            secrets,
        }
    }
}

/// How strong a pair's combined evidence is, independent of the numeric
/// `score`. This is the qualifier callers should surface first: a shared
/// framework alone must never read as a strong infrastructure link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationTier {
    /// Only technology/vendor detections in common, or shared API route
    /// shapes that were merely inferred (template-normalized) rather than
    /// observed in fetched content on both sides.
    Weak,
    /// At least one shared API route shape seen at `static`-or-better
    /// confidence on both targets: the same route structure actually
    /// present in markup/JS, not guessed.
    Moderate,
    /// At least one identical secret plaintext observed on both targets.
    /// This is treated as near-conclusive evidence of a shared backend,
    /// build pipeline, or reused credential.
    Strong,
}

impl CorrelationTier {
    /// Short stable slug, mirroring `EndpointConfidence::slug`.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Moderate => "moderate",
            Self::Strong => "strong",
        }
    }
}

impl fmt::Display for CorrelationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// Shared evidence for one pair of targets, ordered by strongest tier (then
/// score) first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetMatch {
    pub left: String,
    pub right: String,
    pub shared_technologies: Vec<String>,
    pub shared_api_routes: Vec<String>,
    /// Identical secret plaintext values observed on both targets. Presence
    /// here is what drives [`CorrelationTier::Strong`].
    pub shared_secrets: Vec<String>,
    /// Qualifier for how strong the combined evidence is. Read this before
    /// `score` — it is the honest summary of what was actually observed.
    pub tier: CorrelationTier,
    /// Correlation signal from 0 to 100; this is not a probability. Only
    /// useful to rank matches that share the same `tier`.
    pub score: u8,
}

/// Compare every pair of distinct targets. Pairs with no shared evidence are
/// omitted. Common vendor detections contribute little to the score and
/// never reach [`CorrelationTier::Strong`] or [`CorrelationTier::Moderate`]
/// on their own.
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
            let shared_secrets: Vec<String> =
                left.secrets.intersection(&right.secrets).cloned().collect();
            if shared_technologies.is_empty()
                && shared_api_routes.is_empty()
                && shared_secrets.is_empty()
            {
                continue;
            }

            // A route confirmed at `static`-or-better confidence on *both*
            // sides was actually seen in fetched content, not just guessed
            // from a normalized template; that is the bar for "moderate".
            let has_confirmed_route = shared_api_routes.iter().any(|route| {
                let confidence = left.api_routes[route].min(right.api_routes[route]);
                confidence >= EndpointConfidence::Static.score()
            });
            let tier = if !shared_secrets.is_empty() {
                CorrelationTier::Strong
            } else if has_confirmed_route {
                CorrelationTier::Moderate
            } else {
                CorrelationTier::Weak
            };

            let secret_score: u16 = if shared_secrets.is_empty() { 0 } else { 70 };
            let tech_score: u16 = shared_technologies
                .iter()
                .map(|tech| technology_weight(tech))
                .sum::<u16>()
                .min(10);
            let route_score: u16 = shared_api_routes
                .iter()
                .map(|route| {
                    let confidence = left.api_routes[route].min(right.api_routes[route]);
                    // One matching observed route is stronger than several
                    // low-confidence inferred templates.
                    u16::from(confidence) * 20 / 100
                })
                .sum::<u16>()
                .min(30);
            matches.push(TargetMatch {
                left: left.target.clone(),
                right: right.target.clone(),
                shared_technologies,
                shared_api_routes,
                shared_secrets,
                tier,
                score: u8::try_from((secret_score + tech_score + route_score).min(100))
                    .unwrap_or(u8::MAX),
            });
        }
    }
    matches.sort_by(|a, b| {
        b.tier
            .cmp(&a.tier)
            .then_with(|| b.score.cmp(&a.score))
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

    fn secret(plaintext: &str, location: &str) -> Finding {
        Finding::new(
            SessionId::new(),
            FindingKind::Secret,
            None,
            format!("fp:{plaintext}"),
            Confidence::High,
            Provenance::new(Source::JsRegex, Some(location.into())),
        )
        .with_plaintext(Some(plaintext.into()))
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
        assert_eq!(matches[0].tier, CorrelationTier::Moderate);
        assert!(matches[0].shared_secrets.is_empty());
        assert_eq!(matches[0].score, 16);
    }

    /// Clear positive case: identical stack *and* a shared secret plaintext
    /// is near-conclusive evidence of a shared backend — `Strong`.
    #[test]
    fn shared_secret_and_stack_is_a_strong_signal() {
        let a = TargetFingerprint::from_scan(
            "a.test",
            &[
                tech("Next.js (framework)", "https://a.test/"),
                secret("sk_live_deadbeefcafebabe", "https://a.test/app.js"),
            ],
            &[Endpoint::new(
                "https://a.test/api/users/1",
                Method::Get,
                Source::Browser,
            )],
        );
        let b = TargetFingerprint::from_scan(
            "b.test",
            &[
                tech("Next.js (framework)", "https://b.test/"),
                secret("sk_live_deadbeefcafebabe", "https://b.test/app.js"),
            ],
            &[Endpoint::new(
                "https://b.test/api/users/2",
                Method::Get,
                Source::Browser,
            )],
        );
        let matches = compare_targets(&[a, b]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].tier, CorrelationTier::Strong);
        assert_eq!(
            matches[0].shared_secrets,
            ["sk_live_deadbeefcafebabe".to_owned()]
        );
        assert!(matches[0].score >= 70);
    }

    /// Clear negative case: nothing shared at all produces no match.
    #[test]
    fn no_shared_evidence_produces_no_match() {
        let a = TargetFingerprint::from_scan(
            "a.test",
            &[tech("Django (framework)", "https://a.test/")],
            &[Endpoint::new(
                "https://a.test/api/orders/1",
                Method::Get,
                Source::Browser,
            )],
        );
        let b = TargetFingerprint::from_scan(
            "b.test",
            &[tech("Rails (framework)", "https://b.test/")],
            &[Endpoint::new(
                "https://b.test/api/invoices/2",
                Method::Get,
                Source::Browser,
            )],
        );
        let matches = compare_targets(&[a, b]);
        assert!(matches.is_empty());
    }

    /// Ambiguous case: a common framework alone must never be presented as a
    /// strong (or even moderate) infrastructure link.
    #[test]
    fn shared_tech_alone_is_qualified_as_weak() {
        let a = TargetFingerprint::from_scan(
            "a.test",
            &[tech("Express (framework)", "https://a.test/")],
            &[],
        );
        let b = TargetFingerprint::from_scan(
            "b.test",
            &[tech("Express (framework)", "https://b.test/")],
            &[],
        );
        let matches = compare_targets(&[a, b]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].tier, CorrelationTier::Weak);
        assert!(matches[0].shared_secrets.is_empty());
        assert!(matches[0].shared_api_routes.is_empty());
        assert!(matches[0].score < 20);
    }
}
