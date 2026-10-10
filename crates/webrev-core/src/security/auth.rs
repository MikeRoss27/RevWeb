// crates/webrev-core/src/security/auth.rs
//! Authentication material for reaching areas behind a login.
//!
//! Carries custom headers, cookies, and an optional bearer token; both the HTTP
//! fetch client and the headless browser apply [`AuthConfig::effective_headers`]
//! so static and dynamic analysis see the same authenticated context.

use serde::{Deserialize, Serialize};

/// Credentials/headers to attach to every in-scope request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Arbitrary `(name, value)` headers.
    pub headers: Vec<(String, String)>,
    /// Cookies, collapsed into a single `Cookie` header.
    pub cookies: Vec<(String, String)>,
    /// Optional bearer token, sent as `Authorization: Bearer <token>`.
    pub bearer: Option<String>,
}

impl AuthConfig {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty() && self.cookies.is_empty() && self.bearer.is_none()
    }

    /// The full set of headers to send, with `Cookie` and `Authorization`
    /// synthesized from the structured fields.
    #[must_use]
    pub fn effective_headers(&self) -> Vec<(String, String)> {
        let mut out = self.headers.clone();
        if !self.cookies.is_empty() {
            let cookie = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            out.push(("Cookie".to_owned(), cookie));
        }
        if let Some(bearer) = &self.bearer {
            out.push(("Authorization".to_owned(), format!("Bearer {bearer}")));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesizes_cookie_and_bearer() {
        let auth = AuthConfig {
            headers: vec![("X-Env".into(), "staging".into())],
            cookies: vec![("sid".into(), "abc".into()), ("csrf".into(), "xyz".into())],
            bearer: Some("tok".into()),
        };
        let headers = auth.effective_headers();
        assert!(headers.contains(&("X-Env".to_owned(), "staging".to_owned())));
        assert!(headers.contains(&("Cookie".to_owned(), "sid=abc; csrf=xyz".to_owned())));
        assert!(headers.contains(&("Authorization".to_owned(), "Bearer tok".to_owned())));
    }

    #[test]
    fn empty_by_default() {
        assert!(AuthConfig::default().is_empty());
    }
}
