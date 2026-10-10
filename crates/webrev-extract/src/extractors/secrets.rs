// crates/webrev-extract/src/extractors/secrets.rs
//! Detects credential-shaped tokens and records them as **fingerprints**.
//!
//! The plaintext secret never leaves this function: each match is immediately
//! reduced to an HMAC-SHA256 fingerprint via a per-run [`SessionKey`] that is
//! never persisted. The resulting finding carries `url = None` (so dedup keys
//! on the fingerprint, not the containing file) and records the file in its
//! provenance instead.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{
    Confidence, Finding, FindingKind, Provenance, Sanitizer, SessionKey, Source,
};

/// Shannon-entropy threshold (bits/char) above which a token looks random.
const ENTROPY_MIN: f64 = 3.8;

/// Minimum number of *distinct* characters an entropy candidate must have.
/// Real credentials draw from a wide alphabet; repetitive strings do not.
const ENTROPY_MIN_DISTINCT: usize = 12;

/// How many bytes before a match to scan for a secret-ish keyword when
/// deciding whether an entropy-only hit deserves a confidence bump.
const CONTEXT_WINDOW: usize = 48;

/// Lowercased substrings that mark a value as a dummy/placeholder rather than a
/// live credential. Industry scanners allowlist these to cut false positives
/// (e.g. AWS's own `AKIAIOSFODNN7EXAMPLE` doc key).
const PLACEHOLDER_MARKERS: &[&str] = &[
    "example", "placeholder", "changeme", "dummy", "your_", "your-", "yourkey",
    "sample", "redacted", "insert_", "replace_", "lorem", "foobar", "xxxx",
    "notreal", "<secret", "<token", "000000", "123456",
];

/// Secret-ish keywords used for the entropy-pass context check.
const SECRET_KEYWORDS: &[&str] = &[
    "key", "secret", "token", "password", "passwd", "auth", "cred", "bearer",
];

/// Regex-based secret scanner, with an entropy fallback for unknown shapes.
pub struct SecretExtractor {
    key: SessionKey,
    patterns: Vec<(Regex, Confidence)>,
    /// Quoted high-entropy candidate tokens (base64/hex-ish, 20..=100 chars).
    entropy_candidate: Regex,
    /// When true, detected secrets carry their plaintext on the finding in
    /// addition to the fingerprint. Opt-in (`--reveal-secrets`); off by default
    /// so the fingerprint-only privacy guarantee holds unless asked otherwise.
    reveal: bool,
}

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    #[allow(clippy::cast_precision_loss)] // counts are small; f64 is exact here
    let len = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            #[allow(clippy::cast_precision_loss)]
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn is_mixed(s: &str) -> bool {
    s.bytes().any(|b| b.is_ascii_alphabetic()) && s.bytes().any(|b| b.is_ascii_digit())
}

/// Count of distinct byte values in `s`.
fn distinct_chars(s: &str) -> usize {
    let mut seen = [false; 256];
    let mut n = 0usize;
    for b in s.bytes() {
        if !seen[b as usize] {
            seen[b as usize] = true;
            n += 1;
        }
    }
    n
}

/// Every byte identical (`"aaaa…"`).
fn is_single_repeated(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(first) => bytes.all(|b| b == first),
        None => false,
    }
}

/// Whole string ascends or descends by one byte value (`"abcdef"`, `"9876"`).
fn is_sequential(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 4 {
        return false;
    }
    let asc = b.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    let desc = b.windows(2).all(|w| w[0] == w[1].wrapping_add(1));
    asc || desc
}

/// Hex of a common digest length (md5/sha1/sha256): almost always an asset,
/// chunk, or content hash in built front-end code, not a credential.
fn is_hex_digest(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A Subresource Integrity hash (`sha256-…` / `sha384-…` / `sha512-…`).
fn is_sri_hash(s: &str) -> bool {
    s.starts_with("sha256-") || s.starts_with("sha384-") || s.starts_with("sha512-")
}

fn looks_like_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    PLACEHOLDER_MARKERS.iter().any(|m| lower.contains(m))
}

/// False positives common to *every* candidate, regardless of how it matched:
/// placeholders, trivially-structured strings, and SRI integrity hashes.
fn is_common_false_positive(value: &str) -> bool {
    looks_like_placeholder(value)
        || is_single_repeated(value)
        || is_sequential(value)
        || is_sri_hash(value)
}

/// Is there a secret-ish keyword in the `CONTEXT_WINDOW` bytes preceding `at`?
/// Used to promote an entropy-only hit from low to medium confidence.
fn near_secret_keyword(body: &str, at: usize) -> bool {
    let start = at.saturating_sub(CONTEXT_WINDOW);
    let window = String::from_utf8_lossy(&body.as_bytes()[start..at]).to_ascii_lowercase();
    SECRET_KEYWORDS.iter().any(|k| window.contains(k))
}

impl SecretExtractor {
    /// Build the scanner with a fresh per-run fingerprint key.
    ///
    /// # Panics
    ///
    /// Never at runtime: all patterns are constants verified by the
    /// `patterns_compile` unit test.
    #[must_use]
    pub fn new(key: SessionKey) -> Self {
        let compile = |p: &str| Regex::new(p).expect("constant secret pattern must compile");
        let patterns = vec![
            // JSON Web Token
            (
                compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
                Confidence::High,
            ),
            // AWS access key id
            (compile(r"(AKIA[0-9A-Z]{16})"), Confidence::High),
            // Google API key
            (compile(r"(AIza[0-9A-Za-z\-_]{35})"), Confidence::High),
            // Slack token
            (compile(r"(xox[baprs]-[0-9A-Za-z-]{10,})"), Confidence::High),
            // GitHub personal access / OAuth / app / refresh token
            (compile(r"(gh[pousr]_[A-Za-z0-9]{36,})"), Confidence::High),
            // GitLab personal access token
            (compile(r"(glpat-[0-9A-Za-z_\-]{20})"), Confidence::High),
            // Stripe live secret / restricted key
            (compile(r"((?:sk|rk)_live_[0-9A-Za-z]{24,})"), Confidence::High),
            // OpenAI / Anthropic-style project key
            (compile(r"(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})"), Confidence::High),
            // SendGrid key
            (compile(r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})"), Confidence::High),
            // npm automation token
            (compile(r"(npm_[A-Za-z0-9]{36})"), Confidence::High),
            // PEM private key header
            (
                compile(r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"),
                Confidence::High,
            ),
            // Generic `key = "value"` assignment (value is captured)
            (
                compile(
                    r#"(?i)(?:api[_-]?key|secret|token|password|access[_-]?key)\s*[:=]\s*["']([A-Za-z0-9\-_\.]{16,})["']"#,
                ),
                Confidence::Medium,
            ),
        ];
        let entropy_candidate = compile(r#"["']([A-Za-z0-9+/=_\-]{20,100})["']"#);
        Self {
            key,
            patterns,
            entropy_candidate,
            reveal: false,
        }
    }

    /// A default-seeded scanner, for convenience in the registry.
    #[must_use]
    pub fn with_random_key() -> Self {
        Self::new(SessionKey::generate())
    }

    /// Opt into retaining the plaintext secret on each finding (builder style).
    ///
    /// **Dangerous**: when `yes` is true the scanner stops being
    /// fingerprint-only, so real credentials flow into findings, the database,
    /// and reports. Wired to the `--reveal-secrets` CLI flag.
    #[must_use]
    pub fn revealing(mut self, yes: bool) -> Self {
        self.reveal = yes;
        self
    }
}

impl Default for SecretExtractor {
    fn default() -> Self {
        Self::with_random_key()
    }
}

impl Extractor for SecretExtractor {
    fn name(&self) -> &'static str {
        "secret"
    }

    fn priority(&self) -> u8 {
        65
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        matches!(input.kind, ContentKind::Html | ContentKind::JavaScript)
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut findings = Vec::new();
        let mut push = |secret: &str, confidence: Confidence, findings: &mut Vec<Finding>| {
            let fingerprint = Sanitizer::fingerprint(&self.key, secret);
            if seen.insert(fingerprint.clone()) {
                // Plaintext is attached only under the opt-in reveal mode; the
                // fingerprint stays the finding's `value` either way, so dedup
                // and storage keys are unchanged.
                let plaintext = self.reveal.then(|| secret.to_owned());
                findings.push(
                    Finding::new(
                        input.session_id,
                        FindingKind::Secret,
                        None,
                        fingerprint,
                        confidence,
                        Provenance::new(Source::JsRegex, input.url.clone()),
                    )
                    .with_plaintext(plaintext),
                );
            }
        };

        // Pass 1: known credential shapes. Even a shape match is dropped when
        // the value is an obvious placeholder/dummy (e.g. the AWS doc key).
        for (regex, confidence) in &self.patterns {
            for cap in regex.captures_iter(&input.body) {
                if let Some(secret) = cap.get(1).or_else(|| cap.get(0)) {
                    if is_common_false_positive(secret.as_str()) {
                        continue;
                    }
                    push(secret.as_str(), *confidence, &mut findings);
                }
            }
        }

        // Pass 2: high-entropy tokens that match no known shape. This is the
        // noisiest path, so it is gated hardest: we drop placeholders, SRI and
        // digest hashes, low-alphabet strings, and anything below the entropy
        // floor. A hit sitting next to a secret-ish keyword is promoted from
        // low to medium confidence (context-aware triage).
        for cap in self.entropy_candidate.captures_iter(&input.body) {
            if let Some(token) = cap.get(1) {
                let value = token.as_str();
                if is_common_false_positive(value)
                    || is_hex_digest(value)
                    || !is_mixed(value)
                    || distinct_chars(value) < ENTROPY_MIN_DISTINCT
                    || shannon_entropy(value) < ENTROPY_MIN
                {
                    continue;
                }
                let confidence = if near_secret_keyword(&input.body, token.start()) {
                    Confidence::Medium
                } else {
                    Confidence::Low
                };
                push(value, confidence, &mut findings);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::SessionId;

    fn run(js: &str) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/app.js".into()),
            ContentKind::JavaScript,
            js,
        );
        SecretExtractor::with_random_key().extract(&input)
    }

    #[test]
    fn patterns_compile() {
        let _ = SecretExtractor::with_random_key();
    }

    #[test]
    fn fingerprints_never_leak_plaintext() {
        // A real-shaped AWS key id (not the `…EXAMPLE` doc key, which is now
        // filtered as a placeholder).
        let secret = "AKIAZ4XB7NMPQR2STUVW";
        let found = run(&format!("const k = '{secret}';"));
        assert!(!found.is_empty());
        for f in &found {
            assert!(f.value.starts_with("fp:"), "value must be a fingerprint");
            assert!(!f.value.contains(secret), "plaintext must never be stored");
            assert_eq!(f.kind, FindingKind::Secret);
            assert!(f.url.is_none(), "secrets dedup on fingerprint, not url");
        }
    }

    #[test]
    fn reveal_mode_attaches_plaintext_but_keeps_fingerprint_value() {
        let secret = "AKIAZ4XB7NMPQR2STUVW";
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/app.js".into()),
            ContentKind::JavaScript,
            format!("const k = '{secret}';"),
        );
        // Default (fingerprint-only): no plaintext ever.
        let hidden = SecretExtractor::with_random_key().extract(&input);
        assert!(hidden.iter().all(|f| f.plaintext.is_none()));

        // Opt-in reveal: value stays a fingerprint, plaintext carries the secret.
        let shown = SecretExtractor::with_random_key().revealing(true).extract(&input);
        assert!(!shown.is_empty());
        for f in &shown {
            assert!(f.value.starts_with("fp:"), "value must still be a fingerprint");
            assert_eq!(f.plaintext.as_deref(), Some(secret));
        }
    }

    #[test]
    fn detects_assignment_and_dedups_within_file() {
        let found = run(r#"apiKey="A1b2C3d4E5f6G7h8"; apiKey="A1b2C3d4E5f6G7h8";"#);
        // Same secret twice => one fingerprint.
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn drops_placeholder_and_example_values() {
        // AWS's own documentation key id, and a generic dummy assignment.
        let found = run(r#"const a = "AKIAIOSFODNN7EXAMPLE"; const t = "token=your_api_key_here";"#);
        assert!(found.is_empty(), "placeholder/example values must not be reported");
    }

    #[test]
    fn drops_sri_and_digest_hashes() {
        // A 40-char SHA-1 asset hash and an SRI integrity value: both benign.
        let sha1 = "a".repeat(10) + "b1c2d3e4f5" + "0011223344" + "aabbccddee"; // 40 hex
        let js = format!(
            r#"var h = "{sha1}"; var i = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w";"#
        );
        let found = run(&js);
        assert!(found.is_empty(), "digest and SRI hashes must be filtered");
    }

    #[test]
    fn keeps_high_entropy_token_and_bumps_on_context() {
        let token = "Rj8Kpz2Wqf4Lm9Xv7Tb3Nc6Hy1Qs5Ad"; // 32 mixed, high entropy
        // Near a keyword → medium; isolated → low.
        let with_ctx = run(&format!(r#"const apiSecret = "{token}";"#));
        assert_eq!(with_ctx.len(), 1);
        assert_eq!(with_ctx[0].confidence, Confidence::Medium);

        let no_ctx = run(&format!(r#"["{token}"]"#));
        assert_eq!(no_ctx.len(), 1);
        assert_eq!(no_ctx[0].confidence, Confidence::Low);
    }

    #[test]
    fn detects_github_and_stripe_shapes() {
        let gh = format!("ghp_{}", "A1b2C3d4E5".repeat(4)); // ghp_ + 40
        let sk = format!("sk_live_{}", "A1b2C3d4E5f6".repeat(2)); // 24
        let found = run(&format!(r#"const g="{gh}"; const s="{sk}";"#));
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| f.confidence == Confidence::High));
    }
}
