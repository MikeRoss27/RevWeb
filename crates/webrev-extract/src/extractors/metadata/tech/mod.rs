// crates/webrev-extract/src/extractors/metadata/tech/mod.rs
//! A lightweight technology fingerprinter: frameworks, and the SaaS/BaaS/DB
//! backends an app talks to (Supabase, Firebase, Hasura, Cognito, ...).
//!
//! Matching is case-insensitive substring search over the resource URL plus its
//! body, which is fast and good enough for recon signalling. Each hit is a
//! `Technology` finding whose value is `"Name (category)"`.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

mod signatures;
#[cfg(test)]
mod tests;

use signatures::all;

/// Technology fingerprint extractor.
pub struct TechExtractor {
    /// `<meta name="generator" content="...">`, attribute order either way —
    /// catches CMS/site-builder/version strings the static marker table
    /// doesn't enumerate by name (`WordPress` plugins, static-site
    /// generators, page builders, ...).
    meta_generator: Regex,
}

impl TechExtractor {
    /// # Panics
    ///
    /// Never at runtime: the pattern is a constant verified by the
    /// `patterns_compile` unit test.
    #[must_use]
    pub fn new() -> Self {
        Self {
            meta_generator: Regex::new(
                r#"(?i)<meta[^>]*name=["']generator["'][^>]*content=["']([^"']{1,120})["']|<meta[^>]*content=["']([^"']{1,120})["'][^>]*name=["']generator["']"#,
            )
            .expect("constant meta-generator pattern must compile"),
        }
    }
}

impl Default for TechExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor for TechExtractor {
    fn name(&self) -> &'static str {
        "tech"
    }

    fn priority(&self) -> u8 {
        55
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        matches!(input.kind, ContentKind::Html | ContentKind::JavaScript)
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let mut haystack = input.url.clone().unwrap_or_default().to_lowercase();
        // Response headers are high-signal for backend/server/edge detection.
        for (name, value) in &input.headers {
            haystack.push(' ');
            haystack.push_str(&format!("{name}: {value}").to_lowercase());
        }
        haystack.push(' ');
        haystack.push_str(&input.body.to_lowercase());

        let mut seen: BTreeSet<&'static str> = BTreeSet::new();
        let mut findings = Vec::new();
        for sig in all() {
            if sig.markers.iter().any(|m| haystack.contains(m)) && seen.insert(sig.name) {
                findings.push(Finding::new(
                    input.session_id,
                    FindingKind::Technology,
                    None,
                    format!("{} ({})", sig.name, sig.category),
                    Confidence::High,
                    Provenance::new(Source::Html, input.url.clone()),
                ));
            }
        }

        // `<meta name="generator">` names something (often with a version)
        // that the static marker table may not enumerate at all — a plugin,
        // a static-site generator, a page builder. Lower confidence than a
        // table hit: it's free-form text supplied by the generator itself,
        // not a structural tell.
        if input.kind == ContentKind::Html {
            if let Some(cap) = self.meta_generator.captures(&input.body) {
                if let Some(value) = cap.get(1).or_else(|| cap.get(2)) {
                    let value = value.as_str().trim();
                    if !value.is_empty() {
                        findings.push(Finding::new(
                            input.session_id,
                            FindingKind::Technology,
                            None,
                            format!("{value} (generator)"),
                            Confidence::Medium,
                            Provenance::new(Source::Html, input.url.clone()),
                        ));
                    }
                }
            }
        }

        findings
    }
}
