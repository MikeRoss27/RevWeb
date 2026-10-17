// crates/webrev-core/src/security/auth.rs
//! Authentication material for reaching areas behind a login.
//!
//! Carries custom headers, cookies, and an optional bearer token; both the HTTP
//! fetch client and the headless browser apply [`AuthConfig::effective_headers`]
//! so static and dynamic analysis see the same authenticated context.

use serde::{Deserialize, Serialize};

/// Credentials/headers to attach to every in-scope request.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Arbitrary `(name, value)` headers.
    pub headers: Vec<(String, String)>,
    /// Cookies, collapsed into a single `Cookie` header.
    pub cookies: Vec<(String, String)>,
    /// Optional bearer token, sent as `Authorization: Bearer <token>`.
    pub bearer: Option<String>,
}

/// `Debug` shows names only: values (tokens, cookies, header values) must not
/// reach logs or panic messages through `{:?}`. Serialization is unchanged.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field(
                "headers",
                &self.headers.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .field(
                "cookies",
                &self.cookies.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .finish()
    }
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
    fn debug_never_shows_credential_values() {
        let auth = AuthConfig {
            headers: vec![("X-Api-Key".into(), "hdr-secret-1".into())],
            cookies: vec![("sid".into(), "cookie-secret-2".into())],
            bearer: Some("bearer-secret-3".into()),
        };
        let shown = format!("{auth:?} {auth:#?}");
        for secret in ["hdr-secret-1", "cookie-secret-2", "bearer-secret-3"] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
        assert!(shown.contains("X-Api-Key") && shown.contains("sid"));
    }

    #[test]
    fn empty_by_default() {
        assert!(AuthConfig::default().is_empty());
    }

    #[test]
    fn minimal_account_file_deserializes() {
        let auth: AuthConfig = serde_json::from_str(r#"{"bearer":"test-token"}"#).unwrap();
        assert_eq!(auth.bearer.as_deref(), Some("test-token"));
        assert!(auth.headers.is_empty());
        assert!(auth.cookies.is_empty());
    }
}
