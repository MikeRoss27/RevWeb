// crates/webrev-core/src/finding.rs
//! The central unit of output: a `Finding`.
//!
//! Every stage of the pipeline emits `Finding`s; the report crate serializes
//! them; the TUI lists them. Deduplication in the pipeline keys on
//! [`Finding::dedup_key`].

use crate::model::endpoint::{Endpoint, Source};
use crate::model::session::SessionId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The category of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FindingKind {
    /// A reachable API / network endpoint.
    Endpoint,
    /// A credential-like token. The stored `value` is a fingerprint; the
    /// plaintext is kept in `plaintext` only when the operator opts in with
    /// `--reveal-secrets` (see [`crate::sanitize`]).
    Secret,
    /// A `sourceMappingURL` reference to a JS source map.
    SourceMap,
    /// An HTML `<form>` and its action target.
    Form,
    /// A hyperlink (`<a href>`) worth noting.
    Link,
    /// A referenced script resource.
    Script,
    /// A client-side (SPA router) route path.
    Route,
    /// A GraphQL operation (query / mutation / subscription).
    GraphQl,
    /// A detected technology, framework, or SaaS/BaaS (e.g. React, Supabase).
    Technology,
    /// A request parameter / JSON body key / form field name (fuzz wordlist).
    Parameter,
}

impl FindingKind {
    /// Short stable slug, used for dedup keys and JSON/TUI labels.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Secret => "secret",
            Self::SourceMap => "sourcemap",
            Self::Form => "form",
            Self::Link => "link",
            Self::Script => "script",
            Self::Route => "route",
            Self::GraphQl => "graphql",
            Self::Technology => "technology",
            Self::Parameter => "parameter",
        }
    }
}

/// How confident the extractor is that a finding is real and relevant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// How *interesting* a finding is to an operator — orthogonal to [`Confidence`]
/// (which is about certainty). Ordered `Info < Low < Medium < High < Critical`,
/// so findings sort naturally by priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Short stable slug for persistence and JSON/TUI labels.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Fixed-width uppercase tag for aligned table/TUI columns.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW ",
            Self::Medium => "MED ",
            Self::High => "HIGH",
            Self::Critical => "CRIT",
        }
    }
}

impl Confidence {
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Audit trail for a finding: which extractor produced it and (optionally) the
/// precise location it came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Provenance {
    pub source: Source,
    /// Free-form locator, e.g. the script URL or `line:col`.
    pub location: Option<String>,
}

impl Provenance {
    #[must_use]
    pub fn new(source: Source, location: Option<String>) -> Self {
        Self { source, location }
    }
}

/// A single discovered fact about the target application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub session_id: SessionId,
    pub kind: FindingKind,
    /// The associated URL, if any (endpoints, scripts, forms, source maps).
    pub url: Option<String>,
    /// The payload: endpoint path, fingerprint, form action, etc.
    pub value: String,
    pub confidence: Confidence,
    pub provenance: Provenance,
    /// Revealed plaintext for a [`FindingKind::Secret`]. `None` by default; set
    /// only when the operator opts into `--reveal-secrets`, which disables the
    /// fingerprint-only privacy guarantee. Omitted from serialized reports when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<String>,
}

impl Finding {
    #[must_use]
    pub fn new(
        session_id: SessionId,
        kind: FindingKind,
        url: Option<String>,
        value: impl Into<String>,
        confidence: Confidence,
        provenance: Provenance,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id,
            kind,
            url,
            value: value.into(),
            confidence,
            provenance,
            plaintext: None,
        }
    }

    /// Attach a revealed plaintext secret to this finding (builder style).
    ///
    /// Only the secret extractor calls this, and only when `--reveal-secrets`
    /// is set; every other finding leaves `plaintext` at its `None` default.
    #[must_use]
    pub fn with_plaintext(mut self, plaintext: Option<String>) -> Self {
        self.plaintext = plaintext;
        self
    }

    /// Build an endpoint finding from an [`Endpoint`].
    #[must_use]
    pub fn from_endpoint(session_id: SessionId, ep: &Endpoint, confidence: Confidence) -> Self {
        Self::new(
            session_id,
            FindingKind::Endpoint,
            Some(ep.url.clone()),
            format!("{} {}", ep.method, ep.url),
            confidence,
            Provenance::new(ep.source, None),
        )
    }

    /// Derive the finding's [`Severity`] from its kind, confidence, and target.
    ///
    /// Severity is computed on demand (not stored) so the ruleset can evolve
    /// without re-scanning. Secrets rank highest; sensitive endpoints
    /// (admin/debug/config/VCS/etc.) are promoted; low-signal kinds stay info.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self.kind {
            FindingKind::Secret => {
                if self.confidence == Confidence::High {
                    Severity::Critical
                } else {
                    Severity::High
                }
            }
            FindingKind::Endpoint => {
                endpoint_severity(self.url.as_deref().unwrap_or(&self.value))
            }
            FindingKind::GraphQl | FindingKind::SourceMap => Severity::Medium,
            FindingKind::Form | FindingKind::Route => Severity::Low,
            FindingKind::Parameter
            | FindingKind::Link
            | FindingKind::Script
            | FindingKind::Technology => Severity::Info,
        }
    }

    /// Deduplication key: `kind + url` (falling back to the value when there is
    /// no URL). The pipeline inserts these into a `BTreeSet` before storing so
    /// the same endpoint discovered by two extractors is persisted once.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        let locus = self.url.as_deref().unwrap_or(&self.value);
        format!("{}|{}", self.kind.slug(), locus)
    }
}

/// Markers in an endpoint path that signal a sensitive / high-value target.
const SENSITIVE_MARKERS: &[&str] = &[
    "admin", "internal", "debug", "actuator", "/.git", "/.env", "config",
    "backup", "swagger", "api-docs", "graphql", "token", "secret", "password",
    "passwd", "oauth", "/sso", "upload", "console", "phpmyadmin", "wp-admin",
    ".sql", ".bak", "/private",
];

/// True when the path contains a `/v<digits>` version segment (e.g. `/v1/`).
fn has_version_segment(path: &str) -> bool {
    path.split('/').any(|seg| {
        seg.len() >= 2
            && seg.starts_with('v')
            && seg[1..].bytes().all(|b| b.is_ascii_digit())
    })
}

fn endpoint_severity(target: &str) -> Severity {
    let t = target.to_ascii_lowercase();
    if SENSITIVE_MARKERS.iter().any(|m| t.contains(m)) {
        Severity::High
    } else if t.contains("/api") || t.contains("/rest/") || has_version_segment(&t) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::endpoint::Method;
    use crate::model::session::SessionId;

    #[test]
    fn severity_ranks_secrets_and_sensitive_endpoints() {
        let sid = SessionId::new();
        let secret = Finding::new(sid, FindingKind::Secret, None, "fp:x", Confidence::High, Provenance::new(Source::JsRegex, None));
        assert_eq!(secret.severity(), Severity::Critical);

        let mk_ep = |url: &str| Finding::new(sid, FindingKind::Endpoint, Some(url.into()), format!("GET {url}"), Confidence::Low, Provenance::new(Source::JsAst, None));
        assert_eq!(mk_ep("https://x/admin/users").severity(), Severity::High);
        assert_eq!(mk_ep("https://x/api/v1/me").severity(), Severity::Medium);
        assert_eq!(mk_ep("https://x/about").severity(), Severity::Low);

        let param = Finding::new(sid, FindingKind::Parameter, None, "q", Confidence::Low, Provenance::new(Source::JsRegex, None));
        assert_eq!(param.severity(), Severity::Info);
        // Severity ordering is usable for sorting.
        assert!(Severity::Critical > Severity::Info);
    }

    #[test]
    fn dedup_key_ignores_method_and_source() {
        let sid = SessionId::new();
        let a = Finding::from_endpoint(
            sid,
            &Endpoint::new("https://x/api/v1", Method::Get, Source::Html),
            Confidence::Medium,
        );
        let b = Finding::from_endpoint(
            sid,
            &Endpoint::new("https://x/api/v1", Method::Post, Source::JsAst),
            Confidence::High,
        );
        // Same kind + url => same dedup key even though method/source differ.
        assert_eq!(a.dedup_key(), b.dedup_key());
    }

    #[test]
    fn dedup_key_falls_back_to_value() {
        let sid = SessionId::new();
        let f = Finding::new(
            sid,
            FindingKind::Secret,
            None,
            "fp:deadbeef",
            Confidence::High,
            Provenance::new(Source::JsRegex, None),
        );
        assert_eq!(f.dedup_key(), "secret|fp:deadbeef");
    }
}
