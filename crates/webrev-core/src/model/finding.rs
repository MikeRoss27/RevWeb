// crates/webrev-core/src/model/finding.rs
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
    /// detected credential is always kept in `plaintext` for analysis.
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
    /// An embedded configuration constant, feature flag, or app-manifest
    /// setting (e.g. a `baseURL`/`apiVersion` property, a `DEBUG` flag, a web
    /// app manifest's `start_url`).
    Config,
    /// A WebSocket frame payload observed during a dynamic scan. Captured so
    /// an operator can replay the exchange with a tool of their choosing
    /// (webrev itself only observes; it does not resend traffic).
    WebSocketFrame,
    /// An active-probe result: a concrete, observed weakness (missing
    /// security header, CORS misconfiguration, open redirect, reflected or
    /// error-signalled injection, exposed sensitive file). See
    /// [`crate::model::finding::Severity`] for how the specific issue maps
    /// to a priority.
    Vulnerability,
    /// A resource that returned a successful response without the
    /// mission's authentication material attached (IDOR-lite / broken
    /// access control signal).
    Idor,
    /// Actual active-probe coverage, including failed and skipped work.
    ScanCoverage,
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
            Self::Config => "config",
            Self::WebSocketFrame => "ws_frame",
            Self::Vulnerability => "vulnerability",
            Self::Idor => "idor",
            Self::ScanCoverage => "scan_coverage",
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
    /// Detected plaintext for a [`FindingKind::Secret`]. Always populated by
    /// the secret extractor; absent for other kinds of findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Box<super::evidence::ProbeEvidence>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Box<super::evidence::ActiveCoverage>>,
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
            evidence: None,
            coverage: None,
        }
    }

    /// Attach a revealed plaintext secret to this finding (builder style).
    ///
    /// The secret extractor calls this for every detected credential.
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
            FindingKind::Endpoint => endpoint_severity(self.url.as_deref().unwrap_or(&self.value)),
            FindingKind::GraphQl | FindingKind::SourceMap => Severity::Medium,
            FindingKind::Form | FindingKind::Route | FindingKind::WebSocketFrame => Severity::Low,
            FindingKind::Parameter
            | FindingKind::Link
            | FindingKind::Script
            | FindingKind::Technology
            | FindingKind::Config
            | FindingKind::ScanCoverage => Severity::Info,
            // Broken access control is always worth a human look.
            FindingKind::Idor => Severity::High,
            // The specific weakness (encoded in `value` by the active-scan
            // checks) drives severity more than confidence does here: a
            // missing header is advisory, a credentialed CORS reflection is
            // critical.
            FindingKind::Vulnerability => vulnerability_severity(&self.value),
        }
    }

    /// Resource findings deduplicate by kind + URL; other facts also include
    /// their value so distinct proofs on one page survive. Without a URL the
    /// value is the locus. Repeated endpoints from two extractors merge.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        let locus = self.url.as_deref().unwrap_or(&self.value);
        // A page can expose several technologies, credentials, parameters or
        // vulnerabilities. Keeping only kind+URL would silently lose evidence.
        match self.kind {
            FindingKind::Endpoint
            | FindingKind::Link
            | FindingKind::Script
            | FindingKind::Route
            | FindingKind::SourceMap
            | FindingKind::Form => format!("{}|{}", self.kind.slug(), locus),
            _ if self.url.is_some() => format!("{}|{}|{}", self.kind.slug(), locus, self.value),
            _ => format!("{}|{}", self.kind.slug(), locus),
        }
    }
}

/// Markers in an endpoint path that signal a sensitive / high-value target.
const SENSITIVE_MARKERS: &[&str] = &[
    "admin",
    "internal",
    "debug",
    "actuator",
    "/.git",
    "/.env",
    "config",
    "backup",
    "swagger",
    "api-docs",
    "graphql",
    "token",
    "secret",
    "password",
    "passwd",
    "oauth",
    "/sso",
    "upload",
    "console",
    "phpmyadmin",
    "wp-admin",
    ".sql",
    ".bak",
    "/private",
];

/// True when the path contains a `/v<digits>` version segment (e.g. `/v1/`).
fn has_version_segment(path: &str) -> bool {
    path.split('/').any(|seg| {
        seg.len() >= 2 && seg.starts_with('v') && seg[1..].bytes().all(|b| b.is_ascii_digit())
    })
}

/// Map an active-scan vulnerability's `value` text to a severity, by the
/// stable marker phrase each check in `webrev-pipeline::active` writes into
/// it. Keeping the mapping here (next to `endpoint_severity`) means the
/// ruleset can evolve without touching the checks that produce the findings.
fn vulnerability_severity(value: &str) -> Severity {
    let v = value.to_ascii_lowercase();
    if v.contains("cors") && v.contains("credentials") {
        Severity::Critical
    } else if v.contains("sql injection")
        || v.contains("exposed sensitive file")
        || v.contains("template expression evaluation")
        || v.contains("path traversal")
        || v.contains("subdomain takeover")
    {
        Severity::High
    } else if v.contains("open redirect")
        || v.contains("reflected parameter")
        || v.contains("cors misconfiguration")
        || v.contains("crlf")
        || v.contains("graphql introspection")
    {
        Severity::Medium
    } else {
        // SSRF-sink and prototype-pollution leads, missing headers/cookies and
        // other advisory observations remain Low until confirmed dynamically.
        Severity::Low
    }
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
        let secret = Finding::new(
            sid,
            FindingKind::Secret,
            None,
            "fp:x",
            Confidence::High,
            Provenance::new(Source::JsRegex, None),
        );
        assert_eq!(secret.severity(), Severity::Critical);

        let mk_ep = |url: &str| {
            Finding::new(
                sid,
                FindingKind::Endpoint,
                Some(url.into()),
                format!("GET {url}"),
                Confidence::Low,
                Provenance::new(Source::JsAst, None),
            )
        };
        assert_eq!(mk_ep("https://x/admin/users").severity(), Severity::High);
        assert_eq!(mk_ep("https://x/api/v1/me").severity(), Severity::Medium);
        assert_eq!(mk_ep("https://x/about").severity(), Severity::Low);

        let param = Finding::new(
            sid,
            FindingKind::Parameter,
            None,
            "q",
            Confidence::Low,
            Provenance::new(Source::JsRegex, None),
        );
        assert_eq!(param.severity(), Severity::Info);
        // Severity ordering is usable for sorting.
        assert!(Severity::Critical > Severity::Info);
    }

    #[test]
    fn vulnerability_and_idor_severity_ranked_by_weakness() {
        let sid = SessionId::new();
        let mk_vuln = |value: &str| {
            Finding::new(
                sid,
                FindingKind::Vulnerability,
                None,
                value,
                Confidence::High,
                Provenance::new(Source::Active, None),
            )
        };
        assert_eq!(
            mk_vuln("CORS misconfiguration: arbitrary Origin reflected with credentials allowed")
                .severity(),
            Severity::Critical
        );
        assert_eq!(
            mk_vuln("possible SQL injection: database error signature returned").severity(),
            Severity::High
        );
        assert_eq!(
            mk_vuln("open redirect via 'next' parameter").severity(),
            Severity::Medium
        );
        assert_eq!(
            mk_vuln("missing security header(s): X-Frame-Options").severity(),
            Severity::Low
        );
        // Active checks added later map through the same marker phrases.
        assert_eq!(
            mk_vuln(
                "possible path traversal / local file inclusion: /etc/passwd contents returned for 'file' parameter"
            )
            .severity(),
            Severity::High
        );
        assert_eq!(
            mk_vuln("possible subdomain takeover (GitHub Pages)").severity(),
            Severity::High
        );
        assert_eq!(
            mk_vuln(
                "possible CRLF / header injection: injected response header observed via 'q' parameter"
            )
            .severity(),
            Severity::Medium
        );
        assert_eq!(
            mk_vuln("graphql introspection enabled: __schema returned over GET").severity(),
            Severity::Medium
        );
        assert_eq!(
            mk_vuln("possible SSRF sink: parameter accepts a URL ('url', URL value reflected in response)")
                .severity(),
            Severity::Low
        );
        assert_eq!(
            mk_vuln(
                "possible prototype pollution: server error triggered by '__proto__[webrevpp]=1'"
            )
            .severity(),
            Severity::Low
        );

        let idor = Finding::new(
            sid,
            FindingKind::Idor,
            None,
            "no auth required",
            Confidence::Medium,
            Provenance::new(Source::Active, None),
        );
        assert_eq!(idor.severity(), Severity::High);
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

    #[test]
    fn same_page_can_keep_multiple_technologies_and_proofs() {
        for kind in [
            FindingKind::Technology,
            FindingKind::Vulnerability,
            FindingKind::Parameter,
        ] {
            let mk = |value| {
                Finding::new(
                    SessionId::new(),
                    kind,
                    Some("https://x/page".into()),
                    value,
                    Confidence::High,
                    Provenance::new(Source::Html, None),
                )
            };
            assert_ne!(mk("one").dedup_key(), mk("two").dedup_key());
            assert_eq!(mk("one").dedup_key(), mk("one").dedup_key());
        }
    }
}
