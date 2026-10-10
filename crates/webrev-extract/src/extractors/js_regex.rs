// crates/webrev-extract/src/extractors/js_regex.rs
//! Heuristic endpoint extraction from JavaScript via regular expressions.
//!
//! This is the broad, forgiving complement to the AST extractor: it catches
//! URLs in minified or otherwise unparseable code that the AST walk may reject.
//! Confidence is correspondingly lower.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use webrev_core::{Confidence, Endpoint, Finding, Method, Provenance, Source};

/// Regex-based JavaScript endpoint extractor.
pub struct JsRegexExtractor {
    fetch: Regex,
    axios: Regex,
    xhr: Regex,
    api_path: Regex,
    websocket: Regex,
    absolute: Regex,
}

impl JsRegexExtractor {
    /// # Panics
    ///
    /// Never at runtime: all patterns are constants verified by the
    /// `patterns_compile` unit test.
    #[must_use]
    pub fn new() -> Self {
        // Constant patterns, covered by a test → `expect` cannot fire.
        let c = |p: &str| Regex::new(p).expect("constant js-regex pattern must compile");
        Self {
            fetch: c(r#"fetch\s*\(\s*['"`]([^'"`]+)['"`]"#),
            axios: c(r#"axios\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]"#),
            xhr: c(
                r#"\.open\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"`]\s*,\s*['"`]([^'"`]+)['"`]"#,
            ),
            api_path: c(r#"['"`](/(?:api|v\d|graphql|rest)/[A-Za-z0-9_\-/.]*)['"`]"#),
            websocket: c(r"(wss?://[A-Za-z0-9_\-./:%?=&]+)"),
            absolute: c(r"(https?://[A-Za-z0-9_\-./:%?=&]+)"),
        }
    }

    fn push(out: &mut Vec<Endpoint>, url: &str, method: Method) {
        out.push(Endpoint::new(url, method, Source::JsRegex));
    }
}

/// Hosts whose URLs are XML namespaces / specifications, never reachable
/// application endpoints (e.g. `xmlns="http://www.w3.org/2000/svg"`). These
/// are the dominant false positives from the broad absolute-URL catch-all.
const NON_ENDPOINT_HOSTS: &[&str] = &[
    "www.w3.org",
    "w3.org",
    "schema.org",
    "www.schema.org",
    "purl.org",
    "xmlns.com",
    "ns.adobe.com",
    "gmpg.org",
    "ogp.me",
    "creativecommons.org",
    "www.apache.org",
];

/// True for absolute URLs that are namespace/spec references, not endpoints.
fn is_non_endpoint_url(url: &str) -> bool {
    let host = url
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .unwrap_or("");
    NON_ENDPOINT_HOSTS.contains(&host)
}

impl Default for JsRegexExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor for JsRegexExtractor {
    fn name(&self) -> &'static str {
        "js-regex"
    }

    fn priority(&self) -> u8 {
        70
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        input.kind == ContentKind::JavaScript
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let body = &input.body;
        let mut endpoints: Vec<Endpoint> = Vec::new();

        for cap in self.fetch.captures_iter(body) {
            Self::push(&mut endpoints, &cap[1], Method::Unknown);
        }
        for cap in self.axios.captures_iter(body) {
            Self::push(&mut endpoints, &cap[2], Method::parse(&cap[1]));
        }
        for cap in self.xhr.captures_iter(body) {
            Self::push(&mut endpoints, &cap[2], Method::parse(&cap[1]));
        }
        for cap in self.api_path.captures_iter(body) {
            Self::push(&mut endpoints, &cap[1], Method::Unknown);
        }
        for cap in self.websocket.captures_iter(body) {
            Self::push(&mut endpoints, &cap[1], Method::Unknown);
        }
        for cap in self.absolute.captures_iter(body) {
            // Skip websocket URLs already captured above to avoid duplicate work
            // (the pipeline dedups anyway, but this keeps provenance clean), and
            // drop XML-namespace / specification URIs that are not endpoints.
            if !cap[1].starts_with("ws") && !is_non_endpoint_url(&cap[1]) {
                Self::push(&mut endpoints, &cap[1], Method::Unknown);
            }
        }

        endpoints
            .into_iter()
            .map(|ep| {
                let mut f = Finding::from_endpoint(input.session_id, &ep, Confidence::Low);
                f.provenance = Provenance::new(Source::JsRegex, input.url.clone());
                f
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{FindingKind, SessionId};

    fn run(js: &str) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/app.js".into()),
            ContentKind::JavaScript,
            js,
        );
        JsRegexExtractor::new().extract(&input)
    }

    #[test]
    fn patterns_compile() {
        let _ = JsRegexExtractor::new();
    }

    #[test]
    fn captures_fetch_axios_and_paths() {
        let js = r#"
            fetch("/api/users");
            axios.post("https://api.t/v1/login", body);
            const ws = "wss://t/socket";
        "#;
        let found = run(js);
        let urls: Vec<&str> = found.iter().filter_map(|f| f.url.as_deref()).collect();
        assert!(urls.contains(&"/api/users"));
        assert!(urls.contains(&"https://api.t/v1/login"));
        assert!(urls.contains(&"wss://t/socket"));
        assert!(found.iter().all(|f| f.kind == FindingKind::Endpoint));
        // axios.post resolves a concrete method.
        assert!(found
            .iter()
            .any(|f| f.value.starts_with("POST ") && f.value.contains("/v1/login")));
    }

    #[test]
    fn drops_namespace_and_spec_uris() {
        let js = r#"
            const svg = "http://www.w3.org/2000/svg";
            const ld = "https://schema.org/Organization";
            const real = "https://api.example.com/v1/users";
        "#;
        let urls: Vec<String> = run(js).into_iter().filter_map(|f| f.url).collect();
        assert!(urls.iter().any(|u| u == "https://api.example.com/v1/users"));
        assert!(
            !urls.iter().any(|u| u.contains("w3.org") || u.contains("schema.org")),
            "namespace/spec URIs must not be reported as endpoints"
        );
    }
}
