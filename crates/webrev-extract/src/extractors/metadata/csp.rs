// crates/webrev-extract/src/extractors/metadata/csp.rs
//! Passive analysis of security-relevant response headers and the `<meta
//! http-equiv="Content-Security-Policy">` tag: it inspects the *content* of the
//! policy rather than merely noting a header's presence.
//!
//! It surfaces weak Content-Security-Policy directives (`'unsafe-inline'`,
//! `'unsafe-eval'`, wildcard `*` in `default-src`/`script-src`; missing
//! `object-src`/`base-uri`), an absent CSP, and weak or missing
//! `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy`. Each is a
//! [`FindingKind::Config`] surface fact.
//!
//! This is distinct from the pipeline's *active* security-header check, which
//! reports a concrete observed weakness as a [`webrev_core::FindingKind`]
//! vulnerability against a probed URL; here nothing is sent — the policy text
//! already in hand is analysed.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Security-header / CSP surface extractor.
pub struct CspExtractor {
    meta_tag: Regex,
    content_attr: Regex,
}

impl CspExtractor {
    /// Build the extractor.
    ///
    /// # Panics
    ///
    /// Never at runtime: the patterns are constants verified by the
    /// `patterns_compile` unit test.
    #[must_use]
    pub fn new() -> Self {
        Self {
            meta_tag: Regex::new(
                r#"(?i)<meta\b[^>]*http-equiv\s*=\s*['"]content-security-policy['"][^>]*>"#,
            )
            .expect("meta CSP pattern is valid"),
            // The CSP value itself contains single quotes (`'unsafe-inline'`),
            // so the capture must be delimited by the *outer* quote and allow
            // the other quote character inside.
            content_attr: Regex::new(r#"(?i)content\s*=\s*(?:"([^"]*)"|'([^']*)')"#)
                .expect("content attribute pattern is valid"),
        }
    }
}

impl Default for CspExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// First header value whose name matches `name` case-insensitively.
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Analyse one CSP policy string, pushing a finding per weakness. `enforced`
/// distinguishes an enforced policy from a report-only one (reported at Low
/// confidence since it has no runtime effect).
fn analyse_policy(
    policy: &str,
    label: &str,
    enforced: bool,
    mut push: impl FnMut(String, Confidence),
) {
    let mut directives: Vec<(String, Vec<String>)> = Vec::new();
    for raw in policy.split(';') {
        let mut parts = raw.split_whitespace();
        if let Some(name) = parts.next() {
            let tokens: Vec<String> = parts.map(str::to_ascii_lowercase).collect();
            directives.push((name.to_ascii_lowercase(), tokens));
        }
    }

    let find = |name: &str| directives.iter().find(|(d, _)| d == name).map(|(_, t)| t);
    let bump = |c: Confidence| if enforced { c } else { Confidence::Low };

    for dir in ["default-src", "script-src"] {
        if let Some(tokens) = find(dir) {
            if tokens.iter().any(|t| t == "'unsafe-inline'") {
                push(
                    format!("{label} {dir} allows 'unsafe-inline'"),
                    bump(Confidence::Medium),
                );
            }
            if tokens.iter().any(|t| t == "'unsafe-eval'") {
                push(
                    format!("{label} {dir} allows 'unsafe-eval'"),
                    bump(Confidence::Medium),
                );
            }
            if tokens.iter().any(|t| t == "*") {
                push(
                    format!("{label} {dir} allows wildcard *"),
                    bump(Confidence::Medium),
                );
            }
        }
    }

    if find("object-src").is_none() {
        push(
            format!("{label} missing object-src directive"),
            bump(Confidence::Low),
        );
    }
    if find("base-uri").is_none() {
        push(
            format!("{label} missing base-uri directive"),
            bump(Confidence::Low),
        );
    }
}

impl Extractor for CspExtractor {
    fn name(&self) -> &'static str {
        "csp"
    }

    fn priority(&self) -> u8 {
        41
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        !input.headers.is_empty() || input.kind == ContentKind::Html
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut findings = Vec::new();
        let session_id = input.session_id;
        let url = input.url.clone();
        let mut push = |value: String, confidence: Confidence| {
            if !seen.insert(value.clone()) {
                return;
            }
            findings.push(Finding::new(
                session_id,
                FindingKind::Config,
                None,
                value,
                confidence,
                Provenance::new(Source::Html, url.clone()),
            ));
        };

        let header_csp = header(&input.headers, "content-security-policy");
        let report_only = header(&input.headers, "content-security-policy-report-only");

        // CSP delivered via <meta http-equiv>, if this is an HTML body.
        let meta_csp: Option<String> = if input.kind == ContentKind::Html {
            self.meta_tag.find(&input.body).and_then(|tag| {
                self.content_attr
                    .captures(tag.as_str())
                    .and_then(|c| c.get(1).or_else(|| c.get(2)).map(|m| m.as_str().to_owned()))
            })
        } else {
            None
        };

        if let Some(policy) = header_csp {
            analyse_policy(policy, "CSP", true, &mut push);
        }
        if let Some(policy) = &meta_csp {
            analyse_policy(policy, "CSP (meta)", true, &mut push);
        }
        if let Some(policy) = report_only {
            analyse_policy(policy, "CSP-Report-Only (not enforced)", false, &mut push);
        }

        // Header-presence judgements only make sense when we actually received
        // response headers (inline/synthetic content has none).
        if !input.headers.is_empty() {
            if header_csp.is_none() && meta_csp.is_none() {
                push(
                    "no Content-Security-Policy present".to_owned(),
                    Confidence::Medium,
                );
            }
            if header(&input.headers, "x-frame-options").is_none() {
                push(
                    "missing X-Frame-Options header (clickjacking exposure)".to_owned(),
                    Confidence::Low,
                );
            }
            match header(&input.headers, "referrer-policy") {
                None => push("missing Referrer-Policy header".to_owned(), Confidence::Low),
                Some(v) => {
                    let lv = v.trim().to_ascii_lowercase();
                    if lv == "unsafe-url" || lv == "no-referrer-when-downgrade" {
                        push(
                            format!("weak Referrer-Policy: {v} (may leak URLs cross-origin)"),
                            Confidence::Low,
                        );
                    }
                }
            }
            if let Some(v) = header(&input.headers, "permissions-policy") {
                if v.contains("=*") || v.contains("=(*)") {
                    push(
                        "Permissions-Policy grants a feature to all origins (*)".to_owned(),
                        Confidence::Low,
                    );
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

    fn with_headers(headers: Vec<(&str, &str)>) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/".into()),
            ContentKind::Html,
            String::new(),
        )
        .with_headers(
            headers
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        );
        CspExtractor::new().extract(&input)
    }

    fn values(found: &[Finding]) -> Vec<&str> {
        found.iter().map(|f| f.value.as_str()).collect()
    }

    #[test]
    fn patterns_compile() {
        let _ = CspExtractor::new();
    }

    #[test]
    fn flags_weak_csp_directives() {
        let found = with_headers(vec![(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *",
        )]);
        let v = values(&found);
        assert!(v.contains(&"CSP script-src allows 'unsafe-inline'"));
        assert!(v.contains(&"CSP script-src allows 'unsafe-eval'"));
        assert!(v.contains(&"CSP script-src allows wildcard *"));
        assert!(v.contains(&"CSP missing object-src directive"));
        assert!(v.contains(&"CSP missing base-uri directive"));
        assert!(found.iter().all(|f| f.kind == FindingKind::Config));
    }

    #[test]
    fn flags_absent_csp_and_missing_headers() {
        let found = with_headers(vec![("Content-Type", "text/html")]);
        let v = values(&found);
        assert!(v.contains(&"no Content-Security-Policy present"));
        assert!(v.contains(&"missing X-Frame-Options header (clickjacking exposure)"));
        assert!(v.contains(&"missing Referrer-Policy header"));
    }

    #[test]
    fn strong_policy_only_reports_structural_gaps() {
        // object-src and base-uri present, no unsafe tokens -> no weakness
        // findings beyond what is actually missing.
        let found = with_headers(vec![
            (
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'",
            ),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
        ]);
        assert_eq!(values(&found), Vec::<&str>::new());
    }

    #[test]
    fn parses_meta_csp() {
        let html = r#"<head><meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-inline'"></head>"#;
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/".into()),
            ContentKind::Html,
            html,
        );
        let found = CspExtractor::new().extract(&input);
        let v = values(&found);
        assert!(v.contains(&"CSP (meta) script-src allows 'unsafe-inline'"));
        // No response headers were supplied, so no "absent header" noise.
        assert!(!v.iter().any(|s| s.starts_with("missing ")));
        assert!(!v.contains(&"no Content-Security-Policy present"));
    }

    #[test]
    fn report_only_is_low_confidence() {
        let found = with_headers(vec![
            (
                "Content-Security-Policy",
                "default-src 'self'; object-src 'none'; base-uri 'none'",
            ),
            (
                "Content-Security-Policy-Report-Only",
                "script-src 'unsafe-inline'; object-src 'none'; base-uri 'none'",
            ),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
        ]);
        let f = found
            .iter()
            .find(|f| f.value.contains("Report-Only") && f.value.contains("'unsafe-inline'"))
            .expect("report-only finding");
        assert_eq!(f.confidence, Confidence::Low);
    }
}
