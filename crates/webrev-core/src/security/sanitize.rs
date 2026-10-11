// crates/webrev-core/src/security/sanitize.rs
//! Two related security primitives:
//!
//! * [`Sanitizer`] offers explicit text/header scrubbing for library callers.
//!   The scan paths retain original values and do not use these scrubbers.
//! * [`SessionKey`] + [`Sanitizer::fingerprint`] turn a raw secret into a
//!   truncated HMAC-SHA256 for deduplication alongside detected plaintext.
//!   The key is random per session and
//!   never persisted, so fingerprints are not reversible or correlatable across
//!   runs.

use hmac::{Hmac, KeyInit, Mac};
use rand::TryRng;
use regex::Regex;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A per-session HMAC key held only in memory for the lifetime of the run.
#[derive(Clone)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Generate a cryptographically random key from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes)
            .expect("the operating system random source must be available");
        Self(bytes)
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak key material through Debug.
        f.write_str("SessionKey(<redacted>)")
    }
}

/// Redacts secrets from free text and fingerprints known secrets.
pub struct Sanitizer {
    patterns: Vec<Regex>,
}

impl Sanitizer {
    /// Header names whose values are always redacted wholesale.
    const SENSITIVE_HEADERS: [&'static str; 5] = [
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "proxy-authorization",
    ];

    /// Build a sanitizer with a default set of high-signal secret patterns.
    ///
    /// # Panics
    ///
    /// Never in practice: the patterns are compile-time constants validated by
    /// the `sanitizer_patterns_compile` unit test.
    #[must_use]
    pub fn with_default_patterns() -> Self {
        // Each pattern targets a well-known credential shape. They are constant
        // and covered by a test, so `expect` here cannot fire at runtime.
        let raw = [
            // Bearer / JWT-ish tokens
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            // AWS access key id
            r"AKIA[0-9A-Z]{16}",
            // Google API key
            r"AIza[0-9A-Za-z\-_]{35}",
            // Generic "key"/"token"/"secret" = "<value>" assignments, in both
            // code (`apiKey = "..."`) and JSON shape (`"apiKey":"..."`) where
            // the key's own closing quote sits before the separator.
            r#"(?i)(?:api[_-]?key|secret|token|password)["']?\s*[:=]\s*["']?[A-Za-z0-9\-_\.]{12,}"#,
        ];
        let patterns = raw
            .iter()
            .map(|p| Regex::new(p).expect("constant sanitizer pattern must compile"))
            .collect();
        Self { patterns }
    }

    /// Replace every secret-looking substring with `[REDACTED]`.
    #[must_use]
    pub fn scrub(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for re in &self.patterns {
            out = re.replace_all(&out, "[REDACTED]").into_owned();
        }
        out
    }

    /// Redact the value of a sensitive header, passing other headers through.
    #[must_use]
    pub fn scrub_header(&self, name: &str, value: &str) -> String {
        if Self::SENSITIVE_HEADERS
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name))
        {
            "[REDACTED]".to_owned()
        } else {
            self.scrub(value)
        }
    }

    /// Produce a stable, non-reversible fingerprint of a secret: the first 16
    /// hex chars (64 bits) of `HMAC-SHA256(session_key, secret)`, prefixed
    /// `fp:`. Two identical secrets within one session collide (useful for
    /// counting), but the value reveals nothing about the plaintext and does
    /// not survive the session key.
    #[must_use]
    pub fn fingerprint(key: &SessionKey, secret: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
        mac.update(secret.as_bytes());
        let digest = mac.finalize().into_bytes();
        let hexed = hex::encode(digest);
        format!("fp:{}", &hexed[..16])
    }
}

impl Default for Sanitizer {
    fn default() -> Self {
        Self::with_default_patterns()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizer_patterns_compile() {
        // Constructing with_default_patterns compiles all constant regexes.
        let _ = Sanitizer::with_default_patterns();
    }

    #[test]
    fn scrubs_assignments_and_keys() {
        let s = Sanitizer::with_default_patterns();
        let out = s.scrub("const apiKey = 'abcdef0123456789xyz'; ok");
        assert!(out.contains("[REDACTED]"), "got: {out}");
        assert!(out.ends_with("ok"));
    }

    #[test]
    fn scrubs_json_shaped_assignments() {
        // The key's own closing quote sits between the keyword and the
        // separator in JSON, e.g. request/response bodies and WS frames.
        let s = Sanitizer::with_default_patterns();
        let out = s.scrub(r#"{"token":"eyJhbGciOi-not-a-jwt-shape-abcdef"}"#);
        assert!(out.contains("[REDACTED]"), "got: {out}");
        let out = s.scrub(r#"{"accessToken": "raw-session-id-abcdef123456"}"#);
        assert!(out.contains("[REDACTED]"), "got: {out}");
    }

    #[test]
    fn scrubs_sensitive_headers_only() {
        let s = Sanitizer::with_default_patterns();
        assert_eq!(s.scrub_header("Authorization", "Bearer abc"), "[REDACTED]");
        assert_eq!(
            s.scrub_header("Accept", "application/json"),
            "application/json"
        );
    }

    #[test]
    fn fingerprint_is_stable_per_key_and_prefixed() {
        let key = SessionKey::generate();
        let a = Sanitizer::fingerprint(&key, "hunter2");
        let b = Sanitizer::fingerprint(&key, "hunter2");
        assert_eq!(a, b);
        assert!(a.starts_with("fp:"));
        assert_eq!(a.len(), "fp:".len() + 16);
    }

    #[test]
    fn fingerprint_matches_hmac_sha256_vector() {
        // Expected digest independently computed with Python's hmac/sha256.
        let key = SessionKey(std::array::from_fn(|i| u8::try_from(i).unwrap()));
        assert_eq!(
            Sanitizer::fingerprint(&key, "detected credential"),
            "fp:3aac920dc31bd04f"
        );
    }

    #[test]
    fn fingerprint_differs_across_keys() {
        let a = Sanitizer::fingerprint(&SessionKey::generate(), "hunter2");
        let b = Sanitizer::fingerprint(&SessionKey::generate(), "hunter2");
        assert_ne!(a, b);
    }
}
