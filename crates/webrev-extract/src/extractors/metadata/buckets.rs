// crates/webrev-extract/src/extractors/metadata/buckets.rs
//! Detects exposed cloud object-storage URLs embedded in HTML or JavaScript:
//! AWS S3 (`bucket.s3.amazonaws.com`, `s3.<region>.amazonaws.com/<bucket>`,
//! `bucket.s3.<region>.amazonaws.com`), Google Cloud Storage
//! (`storage.googleapis.com/<bucket>`, `bucket.storage.googleapis.com`) and
//! Azure Blob (`account.blob.core.windows.net`).
//!
//! Each distinct storage URL is reported as an [`FindingKind::Endpoint`] so an
//! operator can probe it for public/listable objects. This is a surface fact,
//! not a proof of misconfiguration, so confidence stays `Medium`.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Matches `http(s)` URLs whose host is a recognised cloud storage endpoint.
/// The host alternation is deliberately anchored to storage services (S3,
/// GCS, Azure Blob) rather than any `amazonaws.com` subdomain, so `ec2.` or
/// `sns.` hosts do not produce noise.
const BUCKET_URL: &str = concat!(
    r"(?i)https?://(?:",
    // AWS S3: s3.amazonaws.com, bucket.s3.amazonaws.com,
    // s3.<region>.amazonaws.com, s3-<region>.amazonaws.com,
    // bucket.s3.<region>.amazonaws.com
    r"(?:[a-z0-9._\-]+\.)?s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com",
    r"|",
    // Google Cloud Storage: storage.googleapis.com, bucket.storage.googleapis.com
    r"(?:[a-z0-9._\-]+\.)?storage\.googleapis\.com",
    r"|",
    // Azure Blob: account.blob.core.windows.net
    r"[a-z0-9._\-]+\.blob\.core\.windows\.net",
    r#")(?:/[^\s"'<>)\\]*)?"#,
);

/// Cloud-storage URL extractor.
pub struct BucketExtractor {
    url: Regex,
}

impl BucketExtractor {
    /// Build the extractor.
    ///
    /// # Panics
    ///
    /// Never at runtime: the pattern is a constant verified by the
    /// `pattern_compiles` unit test.
    #[must_use]
    pub fn new() -> Self {
        Self {
            url: Regex::new(BUCKET_URL).expect("bucket URL pattern is valid"),
        }
    }
}

impl Default for BucketExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Trailing punctuation that is almost always sentence/markup noise rather than
/// part of the URL. Quotes, angle brackets, parens and backslashes are already
/// excluded by the pattern's path character class.
fn trim_trailing(url: &str) -> &str {
    url.trim_end_matches(['.', ',', ';'])
}

impl Extractor for BucketExtractor {
    fn name(&self) -> &'static str {
        "buckets"
    }

    fn priority(&self) -> u8 {
        44
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
        self.url
            .find_iter(&input.body)
            .map(|m| trim_trailing(m.as_str()).to_owned())
            .filter(|url| seen.insert(url.clone()))
            .map(|url| {
                Finding::new(
                    input.session_id,
                    FindingKind::Endpoint,
                    Some(url.clone()),
                    format!("GET {url}"),
                    Confidence::Medium,
                    Provenance::new(source, input.url.clone()),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::SessionId;

    fn run(kind: ContentKind, body: &str) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/app.js".into()),
            kind,
            body,
        );
        BucketExtractor::new().extract(&input)
    }

    #[test]
    fn pattern_compiles() {
        let _ = BucketExtractor::new();
    }

    #[test]
    fn detects_s3_gcs_and_azure() {
        let js = r#"
            const a = "https://my-bucket.s3.amazonaws.com/key.json";
            const b = "https://s3.us-east-1.amazonaws.com/other-bucket/file";
            const c = "https://assets.s3.eu-west-1.amazonaws.com/x.png";
            const d = "https://storage.googleapis.com/public-bucket/data";
            const e = "https://media.storage.googleapis.com/y";
            const f = "https://acct.blob.core.windows.net/container/blob";
        "#;
        let found = run(ContentKind::JavaScript, js);
        let urls: Vec<&str> = found.iter().filter_map(|f| f.url.as_deref()).collect();
        assert!(urls.contains(&"https://my-bucket.s3.amazonaws.com/key.json"));
        assert!(urls.contains(&"https://s3.us-east-1.amazonaws.com/other-bucket/file"));
        assert!(urls.contains(&"https://assets.s3.eu-west-1.amazonaws.com/x.png"));
        assert!(urls.contains(&"https://storage.googleapis.com/public-bucket/data"));
        assert!(urls.contains(&"https://media.storage.googleapis.com/y"));
        assert!(urls.contains(&"https://acct.blob.core.windows.net/container/blob"));
        assert!(found.iter().all(|f| f.kind == FindingKind::Endpoint));
        assert!(found.iter().all(|f| f.value.starts_with("GET https://")));
    }

    #[test]
    fn ignores_unrelated_hosts() {
        let js = r#"
            const u = "https://ec2.amazonaws.com/x";
            const v = "https://example.com/s3/not-a-bucket";
            const w = "https://cdn.example.net/image.png";
        "#;
        assert_eq!(run(ContentKind::JavaScript, js), Vec::new());
    }

    #[test]
    fn dedups_within_input() {
        let js = r#"
            fetch("https://my-bucket.s3.amazonaws.com/a");
            fetch("https://my-bucket.s3.amazonaws.com/a");
        "#;
        assert_eq!(run(ContentKind::JavaScript, js).len(), 1);
    }

    #[test]
    fn trims_trailing_punctuation() {
        let html = r"<p>See https://my-bucket.s3.amazonaws.com/report.pdf.</p>";
        let found = run(ContentKind::Html, html);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].url.as_deref(),
            Some("https://my-bucket.s3.amazonaws.com/report.pdf")
        );
    }
}
