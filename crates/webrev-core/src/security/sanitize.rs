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
use std::sync::OnceLock;

mod url;
pub use url::redact_url;

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

const REDACTED: &str = "[REDACTED]";

/// Credentials recognised by their structure or vendor prefix wherever they
/// appear: JWTs, AWS and Google keys, GitHub, GitLab, Slack and Stripe tokens.
const KNOWN_TOKENS: &str = concat!(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    r"|(?:AKIA|ASIA)[0-9A-Z]{16}",
    r"|AIza[0-9A-Za-z\-_]{35}",
    r"|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}",
    r"|glpat-[A-Za-z0-9_\-]{20}",
    r"|xox[abprs]-[A-Za-z0-9\-]{10,}",
    r"|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}",
);

fn known_tokens() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(KNOWN_TOKENS).expect("constant sanitizer pattern must compile"))
}

fn contains_known_token(text: &str) -> bool {
    known_tokens().is_match(text)
}

/// Heuristic for a credential-shaped value, independent of the name it is
/// stored under: at least 16 characters from the token alphabet, mixing at
/// least two of lower case, upper case and digits, with enough character
/// variety (Shannon entropy of 3.2 bits per character or more). Plain words,
/// numeric ids, timestamps and `snake_case` identifiers stay readable; opaque
/// hex digests, UUIDs and base64-like blobs are masked. Over-masking in a log
/// line is the safe direction, so the bias is toward redaction.
fn looks_like_secret(value: &str) -> bool {
    const MIN_LEN: usize = 16;
    if value.len() < MIN_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.~+/=%".contains(&b))
    {
        return false;
    }
    let classes = [
        value.bytes().any(|b| b.is_ascii_lowercase()),
        value.bytes().any(|b| b.is_ascii_uppercase()),
        value.bytes().any(|b| b.is_ascii_digit()),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if classes < 2 {
        return false;
    }
    let mut counts = [0u32; 256];
    for b in value.bytes() {
        counts[usize::from(b)] += 1;
    }
    let len = f64::from(u32::try_from(value.len()).unwrap_or(u32::MAX));
    let entropy: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum();
    entropy >= 3.2
}

/// Redacts secrets from free text and fingerprints known secrets.
pub struct Sanitizer {
    patterns: Vec<Regex>,
    /// `name: value` / `"name":"value"` pairs under session- or auth-like names
    /// (`session`, `sid`, `auth`, `cookie`, ...). The value is masked only when
    /// it is credential-shaped, so `"session_timeout": "30000000000000"` and
    /// prose such as `session: connected` are left alone.
    named_values: Regex,
    /// `name: value` pairs whose name is unambiguously a credential (`password`,
    /// `db_password`, `client-secret`, `api_key`, `token`, `sessionid`,
    /// `PHPSESSID`, ...). The value is masked whatever its shape, from four
    /// characters up, except literals such as `true` or `null`.
    credential_values: Regex,
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
            // JWTs and vendor-prefixed keys
            KNOWN_TOKENS,
            // Generic "key"/"token"/"secret" = "<value>" assignments, in both
            // code (`apiKey = "..."`) and JSON shape (`"apiKey":"..."`) where
            // the key's own closing quote sits before the separator.
            r#"(?i)(?:api[_-]?key|secret|token|password)["']?\s*[:=]\s*["']?[A-Za-z0-9\-_\.]{12,}"#,
        ];
        let patterns = raw
            .iter()
            .map(|p| Regex::new(p).expect("constant sanitizer pattern must compile"))
            .collect();
        let named_values = Regex::new(
            r#"(?i)(["']?[A-Za-z0-9_\-]*(?:session|sid|auth|credential|passwd|pwd|jwt|bearer|cookie|csrf|xsrf|signature|hmac|saml|ticket|secret|token|key|pass)[A-Za-z0-9_\-]*["']?\s*[:=]\s*["']?)([A-Za-z0-9\-_.~+/=%]{16,})"#,
        )
        .expect("constant sanitizer pattern must compile");
        let credential_values = Regex::new(
            r#"(?im)((?:^|[^A-Za-z0-9_\-.])["']?[A-Za-z0-9_\-.]*?(?:password|passwd|passphrase|pwd|secret|api[_\-]?key|access[_\-]?token|refresh[_\-]?token|id[_\-]?token|auth[_\-]?token|token|private[_\-]?key|session[_\-]?id|sessid|sid)["']?\s*[:=]\s*["']?)([^\s"'&;,<>{}\[\]()]{4,})"#,
        )
        .expect("constant sanitizer pattern must compile");
        Self {
            patterns,
            named_values,
            credential_values,
        }
    }

    /// Replace every secret-looking substring with `[REDACTED]`.
    #[must_use]
    pub fn scrub(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for re in &self.patterns {
            out = re.replace_all(&out, "[REDACTED]").into_owned();
        }
        let out = self
            .named_values
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                if looks_like_secret(&caps[2]) {
                    format!("{}{REDACTED}", &caps[1])
                } else {
                    caps[0].to_owned()
                }
            })
            .into_owned();
        self.credential_values
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                let literal = ["true", "false", "null", "none", "undefined"]
                    .iter()
                    .any(|l| caps[2].eq_ignore_ascii_case(l));
                if literal {
                    caps[0].to_owned()
                } else {
                    format!("{}{REDACTED}", &caps[1])
                }
            })
            .into_owned()
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
    fn scrubs_session_shaped_values_in_bodies() {
        let s = Sanitizer::with_default_patterns();
        let out = s.scrub(r#"{"session":"Zk3Jq9XvT2bLm8Rw4NpYs7Ad","ok":true}"#);
        assert_eq!(out, r#"{"session":"[REDACTED]","ok":true}"#);
        let out = s.scrub("Set sid=9f86d081884c7d659a2feaa0c55ad015; Path=/");
        assert!(out.contains("sid=[REDACTED]"), "got: {out}");
    }

    #[test]
    fn leaves_session_named_but_ordinary_values_alone() {
        let s = Sanitizer::with_default_patterns();
        for plain in [
            r#"{"session_timeout":"30000000000000"}"#,
            r#"{"sessionState":"connected-successfully"}"#,
            "session: connected-and-healthy",
            r#"{"author":"someone-with-a-long-name"}"#,
        ] {
            assert_eq!(s.scrub(plain), plain);
        }
    }

    #[test]
    fn scrubs_short_values_under_credential_names() {
        let s = Sanitizer::with_default_patterns();
        for (input, expected) in [
            ("password=hunter2", "password=[REDACTED]"),
            (
                r#"{"db_password":"abc1"}"#,
                r#"{"db_password":"[REDACTED]"}"#,
            ),
            ("X-Client-Secret: s3cr", "X-Client-Secret: [REDACTED]"),
            (r#"{"sid": "4242"}"#, r#"{"sid": "[REDACTED]"}"#),
            (
                "Cookie: PHPSESSID=8f2a; theme=dark",
                "Cookie: PHPSESSID=[REDACTED]; theme=dark",
            ),
            (
                r#"{"refresh_token": "1234"}"#,
                r#"{"refresh_token": "[REDACTED]"}"#,
            ),
        ] {
            assert_eq!(s.scrub(input), expected, "input: {input}");
        }
    }

    #[test]
    fn leaves_credential_named_settings_alone() {
        let s = Sanitizer::with_default_patterns();
        for plain in [
            "password_policy: strict",
            r#"{"password": true, "passwordless": "enabled"}"#,
            "tokens: 42",
            r#"{"token_count": 1234}"#,
            "inside: yes",
        ] {
            assert_eq!(s.scrub(plain), plain);
        }
    }

    #[test]
    fn scrubs_off_list_names_and_vendor_tokens() {
        let s = Sanitizer::with_default_patterns();
        let out = s.scrub(r#"{"csrf_mw":"Zk3Jq9XvT2bLm8Rw4NpYs7Ad"}"#);
        assert_eq!(out, r#"{"csrf_mw":"[REDACTED]"}"#);
        let out = s.scrub("x-signature: 9f86d081884c7d659a2feaa0c55ad015");
        assert_eq!(out, "x-signature: [REDACTED]");
        let out = s.scrub("push with ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 now");
        assert_eq!(out, "push with [REDACTED] now");
        let out = s.scrub("slack xoxb-1234567890-abcdefghij ok");
        assert_eq!(out, "slack [REDACTED] ok");
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
