// crates/webrev-extract/src/extractors/secrets/mod.rs
//! Detects credential-shaped tokens and retains their plaintext for analysis.
//!
//! Each match also receives an HMAC-SHA256 fingerprint via a per-run
//! [`SessionKey`]. The resulting finding carries `url = None` (so dedup keys
//! on the fingerprint, not the containing file) and records the file in its
//! provenance instead.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Sanitizer, SessionKey, Source};

mod heuristics;
mod jwt;
mod patterns;
#[cfg(test)]
mod tests;

pub use jwt::JwtExtractor;

use heuristics::{
    distinct_chars, is_common_false_positive, is_hex_digest, is_mixed, near_secret_keyword,
    shannon_entropy, ENTROPY_MIN, ENTROPY_MIN_DISTINCT,
};

/// Regex-based secret scanner, with an entropy fallback for unknown shapes.
pub struct SecretExtractor {
    key: SessionKey,
    patterns: Vec<(Regex, Confidence)>,
    /// Quoted high-entropy candidate tokens (base64/hex-ish, 20..=100 chars).
    entropy_candidate: Regex,
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
        let (patterns, entropy_candidate) = patterns::compile();
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
                // Keep the fingerprint as the dedup key and retain the value
                // for the operator in every scan.
                let plaintext = Some(secret.to_owned());
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
