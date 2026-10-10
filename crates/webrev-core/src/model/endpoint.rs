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
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Browser => "browser",
            Self::JsAst => "js-ast",
            Self::JsRegex => "js-regex",
            Self::Html => "html",
            Self::SourceMap => "sourcemap",
        };
        f.write_str(s)
    }
}

/// A concrete request target discovered during analysis.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub method: Method,
    pub source: Source,
}

impl Endpoint {
    #[must_use]
    pub fn new(url: impl Into<String>, method: Method, source: Source) -> Self {
        Self {
            url: url.into(),
            method,
            source,
        }
    }
}
