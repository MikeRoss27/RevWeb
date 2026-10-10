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

/// Regex-based secret scanner, with an entropy fallback for unknown shapes.
pub struct SecretExtractor {
    key: SessionKey,
    patterns: Vec<(Regex, Confidence)>,
    /// Quoted high-entropy candidate tokens (base64/hex-ish, 20..=100 chars).
    entropy_candidate: Regex,
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
        }
    }

    /// A default-seeded scanner, for convenience in the registry.
    #[must_use]
    pub fn with_random_key() -> Self {
        Self::new(SessionKey::generate())
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
                findings.push(Finding::new(
                    input.session_id,
                    FindingKind::Secret,
                    None,
                    fingerprint,
                    confidence,
                    Provenance::new(Source::JsRegex, input.url.clone()),
                ));
            }
        };

        // Pass 1: known credential shapes.
        for (regex, confidence) in &self.patterns {
            for cap in regex.captures_iter(&input.body) {
                if let Some(secret) = cap.get(1).or_else(|| cap.get(0)) {
                    push(secret.as_str(), *confidence, &mut findings);
                }
            }
        }

        // Pass 2: high-entropy tokens that match no known shape (low confidence
        // because this is heuristic and can flag benign hashes).
        for cap in self.entropy_candidate.captures_iter(&input.body) {
            if let Some(token) = cap.get(1) {
                let token = token.as_str();
                if is_mixed(token) && shannon_entropy(token) >= ENTROPY_MIN {
                    push(token, Confidence::Low, &mut findings);
                }
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
        let secret = "AKIAIOSFODNN7EXAMPLE";
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
    fn detects_assignment_and_dedups_within_file() {
        let found = run(r#"apiKey="abcdef0123456789"; apiKey="abcdef0123456789";"#);
        // Same secret twice => one fingerprint.
        assert_eq!(found.len(), 1);
    }
}
