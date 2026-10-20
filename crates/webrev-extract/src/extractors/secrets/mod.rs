// crates/webrev-extract/src/extractors/secrets/mod.rs
//! Detects credential-shaped tokens and retains their plaintext for analysis.
//!
//! Each match also receives an HMAC-SHA256 fingerprint via a per-run
//! [`SessionKey`]. The resulting finding carries `url = None` (so dedup keys
//! on the fingerprint, not the containing file) and records the file in its
//! provenance instead.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Sanitizer, SessionKey, Source};

mod heuristics;
mod jwt;
mod patterns;
#[cfg(test)]
mod tests;

pub use jwt::JwtExtractor;

use heuristics::{
    distinct_chars, is_boolean_or_null_literal, is_common_false_positive, is_hex_digest,
    is_identifier_context, is_mixed, near_secret_keyword, shannon_entropy, ENTROPY_MIN,
    ENTROPY_MIN_DISTINCT,
};
use patterns::Patterns;

/// Length window for an entropy-worthy hostname label: short enough that a
/// CDN/build hash (commonly <20 chars) is excluded, long enough that the
/// DNS label limit (63 bytes) is respected.
const HOSTNAME_ENTROPY_LEN: std::ops::RangeInclusive<usize> = 20..=63;

/// Regex-based secret scanner, with an entropy fallback for unknown shapes.
pub struct SecretExtractor {
    key: SessionKey,
    patterns: Patterns,
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
        Self {
            key,
            patterns: patterns::compile(),
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
        matches!(input.kind, ContentKind::Html | ContentKind::JavaScript) || input.url.is_some()
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut findings = Vec::new();
        if matches!(input.kind, ContentKind::Html | ContentKind::JavaScript) {
            self.scan_body(input, &mut seen, &mut findings);
        }
        // Pass 3: the URL's hostname itself. A crawl can turn up a secret
        // baked into a subdomain (a leaked webhook/tunnel host, a key used as
        // a cache-busting label, ...); nothing above looks there, since it
        // only scans `input.body`. Runs for every content kind that has a
        // URL, not just HTML/JavaScript, since the leak lives in the URL, not
        // the fetched body.
        if let Some(host) = input.url.as_deref().and_then(hostname_of) {
            self.scan_hostname(input, &host, &mut seen, &mut findings);
        }
        findings
    }
}

impl SecretExtractor {
    /// Record `secret` as a finding, deduplicated on its fingerprint.
    fn record(
        &self,
        input: &ExtractInput,
        secret: &str,
        confidence: Confidence,
        seen: &mut BTreeSet<String>,
        findings: &mut Vec<Finding>,
    ) {
        let fingerprint = Sanitizer::fingerprint(&self.key, secret);
        if seen.insert(fingerprint.clone()) {
            // Keep the fingerprint as the dedup key and retain the value for
            // the operator in every scan.
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
    }

    /// Passes 1/1b/1c/2: known shapes, generic assignments, short named
    /// values, and the high-entropy fallback — all scanning `input.body`.
    fn scan_body(
        &self,
        input: &ExtractInput,
        seen: &mut BTreeSet<String>,
        findings: &mut Vec<Finding>,
    ) {
        // Pass 1: known credential shapes. Even a shape match is dropped
        // when the value is an obvious placeholder/dummy (e.g. the AWS doc
        // key).
        for (regex, confidence) in &self.patterns.shapes {
            for cap in regex.captures_iter(&input.body) {
                if let Some(secret) = cap.get(1).or_else(|| cap.get(0)) {
                    if is_common_false_positive(secret.as_str())
                        || is_identifier_context(&input.body, secret.start())
                    {
                        continue;
                    }
                    self.record(input, secret.as_str(), *confidence, seen, findings);
                }
            }
        }

        // Pass 1b: generic `key = "value"` assignment or comparison, value
        // 16+ characters (`apiKey = "A1b2C3..."`,
        // `password === "debug-open-sesame"`).
        let (assignment, assignment_confidence) = &self.patterns.assignment;
        for cap in assignment.captures_iter(&input.body) {
            if let Some(secret) = cap.get(1) {
                if is_common_false_positive(secret.as_str())
                    || is_identifier_context(&input.body, secret.start())
                {
                    continue;
                }
                self.record(
                    input,
                    secret.as_str(),
                    *assignment_confidence,
                    seen,
                    findings,
                );
            }
        }

        // Pass 1c: short values under an explicit, unambiguous credential
        // key name (`password = "abc"`, `"sid": "4242"`): too short for
        // entropy scoring, but the key name alone is the signal. Limited to
        // a plain assignment separator (single `:`/`=`, captured in group 1)
        // so an equality *comparison* against a short dictionary word
        // (`password === 'short'`) is left to pass 1b's 16-char floor
        // instead of becoming noise.
        for cap in self.patterns.short_named.captures_iter(&input.body) {
            let (Some(sep), Some(value)) = (cap.get(1), cap.get(2)) else {
                continue;
            };
            if sep.as_str().len() != 1 {
                continue; // ==, ===, !=, !==: an equality comparison.
            }
            let secret = value.as_str();
            if is_boolean_or_null_literal(secret)
                || is_common_false_positive(secret)
                || is_identifier_context(&input.body, value.start())
            {
                continue;
            }
            self.record(input, secret, Confidence::Medium, seen, findings);
        }

        // Pass 2: high-entropy tokens that match no known shape. This is
        // the noisiest path, so it is gated hardest: we drop placeholders,
        // SRI and digest hashes, low-alphabet strings, and anything below
        // the entropy floor. A hit sitting next to a secret-ish keyword is
        // promoted from low to medium confidence (context-aware triage).
        for cap in self.patterns.entropy_candidate.captures_iter(&input.body) {
            if let Some(token) = cap.get(1) {
                let value = token.as_str();
                if is_identifier_context(&input.body, token.start())
                    || is_common_false_positive(value)
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
                self.record(input, value, confidence, seen, findings);
            }
        }
    }

    /// Pass 3: known shapes and entropy-worthy labels in the URL's hostname.
    fn scan_hostname(
        &self,
        input: &ExtractInput,
        host: &str,
        seen: &mut BTreeSet<String>,
        findings: &mut Vec<Finding>,
    ) {
        for (regex, confidence) in &self.patterns.shapes {
            for cap in regex.captures_iter(host) {
                if let Some(secret) = cap.get(1).or_else(|| cap.get(0)) {
                    if is_common_false_positive(secret.as_str()) {
                        continue;
                    }
                    self.record(input, secret.as_str(), *confidence, seen, findings);
                }
            }
        }
        for label in host.split(['.', '-']) {
            if !HOSTNAME_ENTROPY_LEN.contains(&label.len())
                || is_common_false_positive(label)
                || is_hex_digest(label)
                || !is_mixed(label)
                || distinct_chars(label) < ENTROPY_MIN_DISTINCT
                || shannon_entropy(label) < ENTROPY_MIN
            {
                continue;
            }
            self.record(input, label, Confidence::Medium, seen, findings);
        }
    }
}

/// Pull the host out of a URL string, if it parses as one. `None` for a
/// relative path, a malformed URL, or a host-less scheme.
fn hostname_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_owned))
}
