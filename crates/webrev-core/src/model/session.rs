// crates/webrev-core/src/session.rs
//! Mission / session identity and scoping rules.

use crate::error::WebrevError;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Opaque identifier for one analysis run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    /// Generate a fresh random session id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Access the underlying UUID (used by the storage layer as a primary key).
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Reconstruct a session id from its textual UUID form.
    pub fn parse(s: &str) -> Result<Self, WebrevError> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|e| WebrevError::Config(format!("invalid session id {s:?}: {e}")))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The authorization boundary for a mission: which hosts may be touched.
///
/// A target is in scope when its host matches at least one `include` suffix and
/// no `exclude` suffix. Matching is host-suffix based (`api.example.com`
/// matches include `example.com`) which keeps the config terse while still
/// letting an operator carve out subdomains via `exclude`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl Scope {
    #[must_use]
    pub fn new(include: Vec<String>, exclude: Vec<String>) -> Self {
        Self { include, exclude }
    }

    /// Extract the host portion of a URL without pulling in a URL-parsing
    /// dependency: everything between the scheme and the first `/`, `?` or `#`,
    /// with any `user:pass@` and `:port` stripped.
    #[must_use]
    pub fn host_of(url: &str) -> Option<&str> {
        let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .filter(|s| !s.is_empty())?;
        let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let host = host_port.split(':').next().filter(|s| !s.is_empty())?;
        Some(host)
    }

    fn host_matches(host: &str, pattern: &str) -> bool {
        host == pattern || host.ends_with(&format!(".{pattern}"))
    }

    /// Whether a given URL is permitted under this scope. An empty `include`
    /// list denies everything (fail-closed), which is the safe default for a
    /// security tool.
    #[must_use]
    pub fn allows(&self, url: &str) -> bool {
        let Some(host) = Self::host_of(url) else {
            return false;
        };
        if self
            .exclude
            .iter()
            .any(|p| Self::host_matches(host, p))
        {
            return false;
        }
        self.include.iter().any(|p| Self::host_matches(host, p))
    }
}

/// A full analysis mission: identity, human name, scope, and seed URLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mission {
    pub id: SessionId,
    pub name: String,
    pub scope: Scope,
    pub seeds: Vec<String>,
}

impl Mission {
    #[must_use]
    pub fn new(name: impl Into<String>, scope: Scope, seeds: Vec<String>) -> Self {
        Self {
            id: SessionId::new(),
            name: name.into(),
            scope,
            seeds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_fail_closed_by_default() {
        let scope = Scope::default();
        assert!(!scope.allows("https://example.com/"));
    }

    #[test]
    fn scope_matches_subdomains_and_excludes() {
        let scope = Scope::new(vec!["example.com".into()], vec!["admin.example.com".into()]);
        assert!(scope.allows("https://example.com/path"));
        assert!(scope.allows("https://api.example.com/v1?x=1"));
        assert!(!scope.allows("https://admin.example.com/"));
        assert!(!scope.allows("https://evil.test/"));
    }

    #[test]
    fn host_parsing_strips_userinfo_and_port() {
        assert_eq!(
            Scope::host_of("https://user:pass@api.example.com:8443/x"),
            Some("api.example.com")
        );
        assert_eq!(Scope::host_of("not a url"), Some("not a url"));
        assert_eq!(Scope::host_of("https:///nohost"), None);
    }
}
