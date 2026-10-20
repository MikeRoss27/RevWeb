// crates/webrev-core/src/model/endpoint.rs
//! Network endpoints discovered during analysis, plus their provenance enums.

use serde::{Deserialize, Serialize};
use std::fmt;

/// HTTP method associated with a discovered endpoint.
///
/// `Unknown` is used when a static extractor finds a URL but cannot determine
/// the verb (e.g. a bare string literal in JavaScript).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Unknown,
}

impl Method {
    /// Parse a case-insensitive method token, falling back to [`Method::Unknown`].
    #[must_use]
    pub fn parse(token: &str) -> Self {
        match token.trim().to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Unknown => "UNKNOWN",
        };
        f.write_str(s)
    }
}

/// Where a finding or endpoint originated. Ordered by extraction priority so a
/// `BTreeSet`/sort surfaces the most trustworthy source first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Source {
    /// Discovered by observing live traffic in the headless browser.
    Browser,
    /// Recovered from a JavaScript AST walk (most precise static source).
    JsAst,
    /// Matched a JavaScript regex heuristic.
    JsRegex,
    /// Found in the HTML markup (scripts, links, forms).
    Html,
    /// Referenced by a `sourceMappingURL` comment.
    SourceMap,
    /// Parsed from a JSON manifest (web app manifest, webpack/Vite asset
    /// manifest) discovered during the crawl.
    Manifest,
    /// Produced by an active probe (security-header/CORS/cookie checks,
    /// parameter fuzzing, open-redirect and IDOR-lite detection) rather than
    /// passive observation.
    Active,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Browser => "browser",
            Self::JsAst => "js-ast",
            Self::JsRegex => "js-regex",
            Self::Html => "html",
            Self::SourceMap => "sourcemap",
            Self::Manifest => "manifest",
            Self::Active => "active",
        };
        f.write_str(s)
    }
}

/// Strength of the evidence for an endpoint route. The ordering is intentional:
/// a route inferred from a normalized path is weaker than one present in
/// static assets, which is weaker than a request observed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointConfidence {
    Inferred,
    Static,
    Observed,
}

impl EndpointConfidence {
    /// Stable score for sorting and machine-readable exports.
    #[must_use]
    pub const fn score(self) -> u8 {
        match self {
            Self::Inferred => 30,
            Self::Static => 70,
            Self::Observed => 100,
        }
    }

    /// Short stable slug for CLI/TUI labels and CSV/JSON exports, mirroring
    /// `Confidence::slug` (finding-level) and `EndpointScope::slug`.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Inferred => "inferred",
            Self::Static => "static",
            Self::Observed => "observed",
        }
    }
}

impl fmt::Display for EndpointConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl Source {
    /// Confidence in an endpoint directly discovered from this source.
    #[must_use]
    pub const fn endpoint_confidence(self) -> EndpointConfidence {
        match self {
            Self::Browser | Self::Active => EndpointConfidence::Observed,
            Self::JsAst | Self::JsRegex | Self::Html | Self::SourceMap | Self::Manifest => {
                EndpointConfidence::Static
            }
        }
    }
}

/// Whether an endpoint belongs to the target application (`Internal`) or is a
/// reference to a third-party host outside the mission scope (`External`).
///
/// This splits the recon-relevant attack surface from the noise of CDN,
/// analytics, social, and spec URLs, without discarding the latter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EndpointScope {
    /// Same-origin or in-scope host: part of the target's surface.
    Internal,
    /// Out-of-scope host: a third-party reference.
    External,
}

impl EndpointScope {
    /// Short stable slug for persistence and JSON/TUI labels.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::External => "external",
        }
    }
}

impl fmt::Display for EndpointScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// A concrete request target discovered during analysis.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub method: Method,
    pub source: Source,
    /// Confidence in the route represented by `url`, independent of finding
    /// confidence. A route template inferred by pattern normalization is low.
    #[serde(default = "default_endpoint_confidence")]
    pub confidence: EndpointConfidence,
    /// Internal (in-scope) vs external (third-party). Extractors cannot know
    /// the scope, so this defaults to [`EndpointScope::Internal`] and is set
    /// authoritatively by the store stage via [`Endpoint::with_scope`].
    pub scope: EndpointScope,
}

impl Endpoint {
    #[must_use]
    pub fn new(url: impl Into<String>, method: Method, source: Source) -> Self {
        Self {
            url: url.into(),
            method,
            source,
            confidence: source.endpoint_confidence(),
            scope: EndpointScope::Internal,
        }
    }

    /// Set the in/out-of-scope classification (builder style).
    #[must_use]
    pub fn with_scope(mut self, scope: EndpointScope) -> Self {
        self.scope = scope;
        self
    }

    /// Mark a route template created by replacing volatile path segments.
    #[must_use]
    pub fn with_inferred_pattern(mut self) -> Self {
        self.confidence = EndpointConfidence::Inferred;
        self
    }

    /// Keep the strongest evidence when the same method and normalized URL
    /// are discovered more than once. The caller must match those keys first.
    pub fn merge_from(&mut self, other: &Self) {
        if other.confidence > self.confidence
            || (other.confidence == self.confidence && other.source < self.source)
        {
            self.source = other.source;
            self.confidence = other.confidence;
        }
        if other.scope == EndpointScope::Internal {
            self.scope = EndpointScope::Internal;
        }
    }
}

const fn default_endpoint_confidence() -> EndpointConfidence {
    EndpointConfidence::Static
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_scores_follow_evidence_strength() {
        assert_eq!(
            Endpoint::new("/x", Method::Get, Source::Browser)
                .confidence
                .score(),
            100
        );
        assert_eq!(
            Endpoint::new("/x", Method::Get, Source::JsAst)
                .confidence
                .score(),
            70
        );
        assert_eq!(
            Endpoint::new("/x/{id}", Method::Get, Source::Browser)
                .with_inferred_pattern()
                .confidence
                .score(),
            30
        );
    }

    #[test]
    fn later_live_evidence_promotes_an_endpoint() {
        let mut endpoint = Endpoint::new("/api", Method::Get, Source::JsRegex);
        endpoint.merge_from(&Endpoint::new("/api", Method::Get, Source::Browser));
        assert_eq!(endpoint.confidence, EndpointConfidence::Observed);
        assert_eq!(endpoint.source, Source::Browser);
    }

    /// Once an endpoint has been seen on the wire, later findings from a
    /// weaker source (static JS, or a normalized/inferred template) must not
    /// downgrade it: the best evidence seen so far always wins.
    #[test]
    fn live_evidence_is_not_downgraded_by_weaker_static_evidence() {
        let mut endpoint = Endpoint::new("/api", Method::Get, Source::Browser);
        endpoint.merge_from(&Endpoint::new("/api", Method::Get, Source::JsAst));
        assert_eq!(endpoint.confidence, EndpointConfidence::Observed);
        assert_eq!(endpoint.source, Source::Browser);

        endpoint.merge_from(
            &Endpoint::new("/api/{id}", Method::Get, Source::JsRegex).with_inferred_pattern(),
        );
        assert_eq!(endpoint.confidence, EndpointConfidence::Observed);
        assert_eq!(endpoint.source, Source::Browser);
    }

    /// An endpoint that only ever came from normalization/pattern-guessing
    /// (no direct live or static hit) keeps the lowest evidence tier.
    #[test]
    fn normalization_only_endpoint_keeps_lowest_tier() {
        let endpoint =
            Endpoint::new("/users/{id}", Method::Get, Source::JsRegex).with_inferred_pattern();
        assert_eq!(endpoint.confidence, EndpointConfidence::Inferred);
        assert_eq!(endpoint.confidence.score(), 30);
        assert_eq!(endpoint.confidence.slug(), "inferred");

        let mut merged = endpoint.clone();
        merged.merge_from(
            &Endpoint::new("/users/{id}", Method::Get, Source::Html).with_inferred_pattern(),
        );
        assert_eq!(merged.confidence, EndpointConfidence::Inferred);
    }

    /// Evidence tiers order from weakest to strongest: a route only ever
    /// inferred by normalization < one found literally in static JS/HTML <
    /// one actually observed on the wire.
    #[test]
    fn evidence_tiers_are_ordered_inferred_lt_static_lt_observed() {
        assert!(EndpointConfidence::Inferred < EndpointConfidence::Static);
        assert!(EndpointConfidence::Static < EndpointConfidence::Observed);
        assert!(EndpointConfidence::Inferred < EndpointConfidence::Observed);

        let mut tiers = [
            EndpointConfidence::Observed,
            EndpointConfidence::Inferred,
            EndpointConfidence::Static,
        ];
        tiers.sort();
        assert_eq!(
            tiers,
            [
                EndpointConfidence::Inferred,
                EndpointConfidence::Static,
                EndpointConfidence::Observed,
            ]
        );
    }

    #[test]
    fn slug_round_trips_for_display() {
        assert_eq!(EndpointConfidence::Inferred.to_string(), "inferred");
        assert_eq!(EndpointConfidence::Static.to_string(), "static");
        assert_eq!(EndpointConfidence::Observed.to_string(), "observed");
    }
}
