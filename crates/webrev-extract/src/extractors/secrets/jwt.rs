// crates/webrev-extract/src/extractors/secrets/jwt.rs
//! Finds and decodes JSON Web Tokens, and flags obvious token handling in
//! JavaScript.
//!
//! A JWT (`eyJ...` — three base64url segments) has its header and payload
//! base64url-decoded in-process (no network, no crypto) so the reported
//! `value` can summarise the signing algorithm and key claims, e.g.
//! `jwt alg=none sub=1234 exp=9999999999`. The weak `alg:none` and symmetric
//! `alg:HS*` cases are called out explicitly, since both are classic auth
//! bypass / forgery footguns. The raw token is retained as the finding's
//! plaintext.
//!
//! Beyond fully-formed JWTs, a few obvious token-handling patterns
//! (`Bearer <...>`, `authToken = "..."`, `localStorage.setItem('token', …)`)
//! are surfaced as [`FindingKind::Secret`] leads at lower confidence.
//!
//! Decoding is defensive: any segment that is not valid base64url or whose
//! bytes are not a JSON object is skipped, never panicking.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Three dot-separated base64url segments, the first starting `eyJ` (the
/// base64url encoding of `{"`, i.e. a JSON object header). The signature
/// segment may be empty for `alg:none` tokens.
const JWT: &str = r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*";

/// `Bearer <token>` in source or headers.
const BEARER: &str = r"(?i)bearer\s+([A-Za-z0-9\-_.=]{8,})";

/// `authToken = "..."`, `accessToken: '...'`, etc. with a string-literal value.
const TOKEN_ASSIGN: &str = r#"(?i)(auth[_]?token|access[_]?token|id[_]?token|refresh[_]?token|session[_]?token|api[_]?token)\s*[:=]\s*['"]([^'"\s]{6,})['"]"#;

/// `localStorage.setItem('token', …)` / `sessionStorage.setItem("jwt", …)`:
/// a sensitive key persisted to web storage (readable by any XSS). Captures
/// the storage kind, the key, and — when it is a string literal — the value.
const STORAGE_SET: &str = r#"(?i)(local|session)Storage\.setItem\(\s*['"]([^'"]*(?:token|jwt|auth|secret)[^'"]*)['"]\s*,\s*(?:['"]([^'"]*)['"])?"#;

/// JWT and token-handling extractor.
pub struct JwtExtractor {
    jwt: Regex,
    bearer: Regex,
    assign: Regex,
    storage: Regex,
}

impl JwtExtractor {
    /// Build the extractor.
    ///
    /// # Panics
    ///
    /// Never at runtime: all patterns are constants verified by the
    /// `patterns_compile` unit test.
    #[must_use]
    pub fn new() -> Self {
        Self {
            jwt: Regex::new(JWT).expect("jwt pattern is valid"),
            bearer: Regex::new(BEARER).expect("bearer pattern is valid"),
            assign: Regex::new(TOKEN_ASSIGN).expect("token-assign pattern is valid"),
            storage: Regex::new(STORAGE_SET).expect("storage-set pattern is valid"),
        }
    }
}

impl Default for JwtExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode a base64url segment (no padding) to raw bytes. Returns `None` on any
/// character outside the base64url alphabet.
fn base64url_decode(segment: &str) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(segment.len() * 3 / 4 + 3);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in segment.as_bytes() {
        buf = (buf << 6) | u32::from(sextet(b)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Low 8 bits only; the truncation is exactly what decoding wants.
            #[allow(clippy::cast_possible_truncation)]
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Decode a JWT into a human-readable summary, or `None` if it is not a
/// well-formed JWT (header must base64url-decode to a JSON object with `alg`).
fn summarise_jwt(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let header_b64 = parts.next()?;
    let payload_b64 = parts.next()?;

    let header_bytes = base64url_decode(header_b64)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    let alg = header.get("alg")?.as_str()?.to_owned();

    let mut summary = format!("jwt alg={alg}");
    let alg_lower = alg.to_ascii_lowercase();
    if alg_lower == "none" {
        summary.push_str(" [alg:none unsigned]");
    } else if alg_lower.starts_with("hs") {
        summary.push_str(" [alg:HS* symmetric]");
    }

    // Payload claims are best-effort: a JWT remains reportable even if the
    // payload is truncated or not JSON.
    if let Some(payload) = base64url_decode(payload_b64)
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    {
        for claim in [
            "sub", "iss", "aud", "exp", "role", "roles", "scope", "admin",
        ] {
            if let Some(val) = payload.get(claim) {
                let rendered = match val {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let _ = write!(summary, " {claim}={rendered}");
            }
        }
    }

    Some(summary)
}

impl Extractor for JwtExtractor {
    fn name(&self) -> &'static str {
        "jwt"
    }

    fn priority(&self) -> u8 {
        43
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        matches!(input.kind, ContentKind::Html | ContentKind::JavaScript)
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let source = match input.kind {
            ContentKind::Html => Source::Html,
            _ => Source::JsRegex,
        };
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut findings = Vec::new();

        let mut push =
            |dedup: String, value: String, plaintext: Option<String>, confidence: Confidence| {
                if !seen.insert(dedup) {
                    return;
                }
                findings.push(
                    Finding::new(
                        input.session_id,
                        FindingKind::Secret,
                        None,
                        value,
                        confidence,
                        Provenance::new(source, input.url.clone()),
                    )
                    .with_plaintext(plaintext),
                );
            };

        // Fully-formed, decodable JWTs (highest trust).
        for m in self.jwt.find_iter(&input.body) {
            let raw = m.as_str();
            if let Some(summary) = summarise_jwt(raw) {
                push(
                    raw.to_owned(),
                    summary,
                    Some(raw.to_owned()),
                    Confidence::High,
                );
            }
        }

        // `Bearer <token>` (skip if the token is itself an already-reported JWT).
        for cap in self.bearer.captures_iter(&input.body) {
            let token = cap[1].to_owned();
            push(
                token.clone(),
                "bearer token present in source".to_owned(),
                Some(token),
                Confidence::Medium,
            );
        }

        // `authToken = "..."` style assignments.
        for cap in self.assign.captures_iter(&input.body) {
            let keyword = cap[1].to_ascii_lowercase();
            let value = cap[2].to_owned();
            push(
                value.clone(),
                format!("token assignment: {keyword}"),
                Some(value),
                Confidence::Medium,
            );
        }

        // Sensitive keys persisted to web storage.
        for cap in self.storage.captures_iter(&input.body) {
            let storage = cap[1].to_ascii_lowercase();
            let key = cap[2].to_owned();
            let value = cap.get(3).map(|m| m.as_str().to_owned());
            let dedup = value
                .clone()
                .unwrap_or_else(|| format!("{storage}Storage:{key}"));
            push(
                dedup,
                format!("sensitive value persisted to {storage}Storage key '{key}'"),
                value,
                Confidence::Low,
            );
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::SessionId;

    fn run(body: &str) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/app.js".into()),
            ContentKind::JavaScript,
            body,
        );
        JwtExtractor::new().extract(&input)
    }

    #[test]
    fn patterns_compile() {
        let _ = JwtExtractor::new();
    }

    // eyJhbGciOiJub25lIn0 = {"alg":"none"},
    // eyJzdWIiOiIxMjM0IiwiZXhwIjo5OTk5fQ = {"sub":"1234","exp":9999}
    const JWT_NONE: &str = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0IiwiZXhwIjo5OTk5fQ.";
    // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 = {"alg":"HS256","typ":"JWT"}
    const JWT_HS256: &str =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjo5OTk5fQ.abcDEF123_-";

    #[test]
    fn decodes_alg_none_and_claims() {
        let found = run(&format!(r#"const t = "{JWT_NONE}";"#));
        assert_eq!(found.len(), 1);
        let f = &found[0];
        assert_eq!(f.kind, FindingKind::Secret);
        assert_eq!(f.confidence, Confidence::High);
        assert!(f.value.contains("alg=none"));
        assert!(f.value.contains("[alg:none unsigned]"));
        assert!(f.value.contains("sub=1234"));
        assert!(f.value.contains("exp=9999"));
        assert_eq!(f.plaintext.as_deref(), Some(JWT_NONE));
    }

    #[test]
    fn flags_hs_symmetric() {
        let found = run(&format!(r#"authorization: "Bearer {JWT_HS256}""#));
        // The JWT is detected and summarised (the Bearer match dedups on the
        // same raw token).
        let jwt = found
            .iter()
            .find(|f| f.value.starts_with("jwt "))
            .expect("jwt finding");
        assert!(jwt.value.contains("alg=HS256"));
        assert!(jwt.value.contains("[alg:HS* symmetric]"));
    }

    #[test]
    fn detects_token_assignment_and_storage() {
        let js = r#"
            const authToken = "abc123def456";
            localStorage.setItem('access_token', jwtVar);
            sessionStorage.setItem("refresh-jwt", "literalValue");
        "#;
        let found = run(js);
        assert!(found
            .iter()
            .any(|f| f.value == "token assignment: authtoken"
                && f.plaintext.as_deref() == Some("abc123def456")));
        assert!(found
            .iter()
            .any(|f| f.value.contains("localStorage key 'access_token'")));
        assert!(found
            .iter()
            .any(|f| f.value.contains("sessionStorage key 'refresh-jwt'")
                && f.plaintext.as_deref() == Some("literalValue")));
    }

    #[test]
    fn ignores_garbage_and_non_jwt() {
        // `eyJ...` prefix but header is not valid JSON once decoded.
        let js = r#"const x = "eyJnotvalidjson.payloadpart.sig"; const y = "hello.world.foo";"#;
        assert_eq!(run(js), Vec::new());
    }

    #[test]
    fn dedups_within_input() {
        let js = format!(r#"const a = "{JWT_NONE}"; const b = "{JWT_NONE}";"#);
        assert_eq!(run(&js).len(), 1);
    }
}
