// crates/webrev-core/src/endpoint.rs
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
            scope: EndpointScope::Internal,
        }
    }

    /// Set the in/out-of-scope classification (builder style).
    #[must_use]
    pub fn with_scope(mut self, scope: EndpointScope) -> Self {
        self.scope = scope;
        self
    }
}
