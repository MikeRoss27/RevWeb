// crates/webrev-core/src/model/session.rs
//! Mission / session identity and scoping rules.

use crate::error::WebrevError;
use crate::model::endpoint::EndpointScope;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
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
/// A target is in scope when its host matches an included hostname suffix or
/// IP network and no exclusion matches. Hostname suffixes (`api.example.com`
/// matches `example.com`) and IP/CIDR rules share the serialized string lists
/// for compatibility with existing mission reports.
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
        let host = if host_port.starts_with('[') {
            &host_port[1..host_port.find(']')?]
        } else {
            host_port.split(':').next().filter(|s| !s.is_empty())?
        };
        if host.is_empty() {
            return None;
        }
        Some(host)
    }

    fn host_matches(host: &str, pattern: &str) -> bool {
        if let Ok(network) = pattern.parse::<IpNet>() {
            return host
                .parse::<IpAddr>()
                .is_ok_and(|address| network.contains(&address));
        }
        if let Ok(expected) = pattern.parse::<IpAddr>() {
            return host
                .parse::<IpAddr>()
                .is_ok_and(|actual| actual == expected);
        }
        host.eq_ignore_ascii_case(pattern)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", pattern.to_ascii_lowercase()))
    }

    fn is_network_rule(rule: &str) -> bool {
        rule.parse::<IpNet>().is_ok()
    }

    fn host_rule_matches(host: &str, rule: &str) -> bool {
        !Self::is_network_rule(rule) && Self::host_matches(host, rule)
    }

    fn has_network_include(&self) -> bool {
        self.include.iter().any(|rule| Self::is_network_rule(rule))
    }

    fn has_address_exclude(&self) -> bool {
        self.exclude
            .iter()
            .any(|rule| Self::is_network_rule(rule) || rule.parse::<IpAddr>().is_ok())
    }

    fn allows_without_resolution(&self, url: &str) -> bool {
        let Some(host) = Self::host_of(url) else {
            return false;
        };
        let is_ip = host.parse::<IpAddr>().is_ok();
        let matches = |rule: &str| {
            if is_ip {
                Self::host_matches(host, rule)
            } else {
                Self::host_rule_matches(host, rule)
            }
        };
        !self.exclude.iter().any(|rule| matches(rule))
            && self.include.iter().any(|rule| matches(rule))
    }

    /// URL-level gate. A CIDR entry permits literal IP URLs and allows a
    /// hostname to proceed to DNS validation; the resolver must still filter
    /// every resulting address through [`allows_resolved_ip`](Self::allows_resolved_ip).
    #[must_use]
    pub fn allows(&self, url: &str) -> bool {
        let Some(host) = Self::host_of(url) else {
            return false;
        };
        self.allows_without_resolution(url)
            || (host.parse::<IpAddr>().is_err()
                && self.has_network_include()
                && !self
                    .exclude
                    .iter()
                    .any(|rule| Self::host_rule_matches(host, rule)))
    }

    /// Whether a DNS result is authorized by this scope. A listed hostname
    /// authorizes its DNS routes, subject to explicit CIDR/IP exclusions. A
    /// CIDR can also authorize a destination reached by hostname; only matching
    /// addresses are returned to the HTTP connector.
    #[must_use]
    pub fn allows_resolved_ip(&self, hostname: &str, address: IpAddr) -> bool {
        if self
            .exclude
            .iter()
            .any(|rule| Self::host_rule_matches(hostname, rule))
            || self
                .exclude
                .iter()
                .any(|rule| Self::host_matches(&address.to_string(), rule))
        {
            return false;
        }
        let hostname_included = self
            .include
            .iter()
            .any(|rule| Self::host_rule_matches(hostname, rule));
        let address_included = self
            .include
            .iter()
            .any(|rule| Self::host_matches(&address.to_string(), rule));
        hostname_included || address_included
    }

    /// Browser interception can validate URL hosts, but it cannot apply a
    /// CIDR-only rule to a hostname before Chromium performs DNS resolution.
    #[must_use]
    pub fn allows_browser_url(&self, url: &str) -> bool {
        let Some(host) = Self::host_of(url) else {
            return false;
        };
        if host.parse::<IpAddr>().is_ok() {
            return self.allows(url);
        }
        self.allows_without_resolution(url) && !self.has_address_exclude()
    }

    /// Classify an endpoint URL as internal (in-scope) or external.
    ///
    /// Relative URLs (no `scheme://host`) are same-origin by definition and are
    /// always [`EndpointScope::Internal`]; absolute URLs are internal iff the
    /// scope [`allows`](Self::allows) them.
    #[must_use]
    pub fn classify(&self, url: &str) -> EndpointScope {
        if url.contains("://") && !self.allows_without_resolution(url) {
            EndpointScope::External
        } else {
            EndpointScope::Internal
        }
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

    #[test]
    fn ipv6_scope_keeps_the_full_address_and_dns_matching_ignores_case() {
        assert_eq!(Scope::host_of("http://[::1]:8080/api"), Some("::1"));
        let scope = Scope::new(vec!["::1".into()], vec![]);
        assert!(scope.allows("http://[::1]:8080/"));
        assert!(!scope.allows("http://[2001:db8::1]:8080/"));
        let scope = Scope::new(vec!["EXAMPLE.COM".into()], vec!["Admin.Example.com".into()]);
        assert!(scope.allows("https://Api.example.com/"));
        assert!(!scope.allows("https://admin.example.com/"));
        assert!(!scope.allows("https://evilexample.com/"));
    }

    #[test]
    fn cidr_scope_matches_literal_ipv4_and_ipv6_boundaries() {
        let scope = Scope::new(
            vec!["192.0.2.0/24".into(), "2001:db8:abcd::/48".into()],
            vec![],
        );
        assert!(scope.allows("https://192.0.2.0/"));
        assert!(scope.allows("https://192.0.2.255/"));
        assert!(!scope.allows("https://192.0.3.0/"));
        assert!(scope.allows("http://[2001:db8:abcd::1]/"));
        assert!(!scope.allows("http://[2001:db8:abce::1]/"));
    }

    #[test]
    fn cidr_scope_gates_resolved_hosts_and_exclusions_win() {
        let cidr_scope = Scope::new(vec!["192.0.2.0/24".into()], vec![]);
        assert!(cidr_scope.allows("https://api.outside.test/"));
        assert!(!cidr_scope.allows_browser_url("https://api.outside.test/"));
        assert!(cidr_scope.allows_resolved_ip("api.outside.test", "192.0.2.8".parse().unwrap()));
        assert!(!cidr_scope.allows_resolved_ip("api.outside.test", "198.51.100.8".parse().unwrap()));

        let excluded = Scope::new(vec!["example.test".into()], vec!["192.0.2.128/25".into()]);
        assert!(excluded.allows("https://api.example.test/"));
        assert!(excluded.allows_resolved_ip("api.example.test", "192.0.2.127".parse().unwrap()));
        assert!(!excluded.allows_resolved_ip("api.example.test", "192.0.2.128".parse().unwrap()));
        assert!(!excluded.allows("https://192.0.2.128/"));
    }

    #[test]
    fn domain_scope_does_not_authorize_literal_ip_targets() {
        let scope = Scope::new(vec!["example.test".into()], vec![]);
        assert!(scope.allows("https://api.example.test/"));
        assert!(!scope.allows("http://192.0.2.3/"));
        assert!(!scope.allows_browser_url("http://192.0.2.3/"));
    }

    #[test]
    fn classify_internal_vs_external() {
        let scope = Scope::new(vec!["example.com".into()], vec![]);
        // Relative URLs are same-origin => internal.
        assert_eq!(scope.classify("/api/users"), EndpointScope::Internal);
        // In-scope absolute host => internal.
        assert_eq!(
            scope.classify("https://api.example.com/v1"),
            EndpointScope::Internal
        );
        // Out-of-scope absolute host => external.
        assert_eq!(
            scope.classify("https://cdn.jsdelivr.net/x.js"),
            EndpointScope::External
        );
    }
}
