// crates/webrev-extract/src/extractors/endpoints/js_regex.rs
//! Heuristic endpoint extraction from JavaScript via regular expressions.
//!
//! This is the broad, forgiving complement to the AST extractor: it catches
//! URLs in minified or otherwise unparseable code that the AST walk may reject.
//! Confidence is correspondingly lower.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Endpoint, Finding, FindingKind, Method, Provenance, Source};

/// Regex-based JavaScript endpoint extractor.
pub struct JsRegexExtractor {
    fetch: Regex,
    axios: Regex,
    xhr: Regex,
    websocket_call: Regex,
    http_client: Regex,
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
            websocket_call: c(r#"new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]"#),
            // The search is unanchored: receiver prefixes do not change the
            // captured method/URL. Avoid compiling a Unicode identifier DFA.
            http_client: c(r"http\.(get|post|put|delete|patch)\s*\(\s*`([^`]*)`"),
            // `(?i)`: real-world backends don't always lowercase path
            // segments (`/API/`, `/V1/`, `/GraphQL/`).
            api_path: c(r#"(?i)['"`](/(?:api|v\d|graphql|rest)/[A-Za-z0-9_\-/.]*)['"`]"#),
            // Char class includes `,`, `@`, `+`, `~`: common, legal URL
            // characters (e.g. `?q=a,b`, `user:pass@host`) that would
            // otherwise truncate the match mid-string instead of just
            // being dropped.
            websocket: c(r"(wss?://[A-Za-z0-9_\-./:%?=&,@+~]+)"),
            absolute: c(r"(https?://[A-Za-z0-9_\-./:%?=&,@+~]+)"),
        }
    }

    fn push(out: &mut Vec<Endpoint>, url: &str, method: Method) {
        out.push(Endpoint::new(url, method, Source::JsRegex));
    }
}

/// Mask JavaScript comments while preserving quoted strings and line breaks.
fn without_comments(source: &str) -> String {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Code,
        Single,
        Double,
        Template,
        LineComment,
        BlockComment,
    }

    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut state = State::Code;
    let mut escaped = false;
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        match state {
            State::Code => match byte {
                b'\'' => state = State::Single,
                b'"' => state = State::Double,
                b'`' => state = State::Template,
                b'/' if bytes.get(i + 1) == Some(&b'/') => {
                    output[i] = b' ';
                    output[i + 1] = b' ';
                    i += 1;
                    state = State::LineComment;
                }
                b'/' if bytes.get(i + 1) == Some(&b'*') => {
                    output[i] = b' ';
                    output[i + 1] = b' ';
                    i += 1;
                    state = State::BlockComment;
                }
                _ => {}
            },
            State::Single | State::Double | State::Template => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if matches!(
                    (state, byte),
                    (State::Single, b'\'') | (State::Double, b'"') | (State::Template, b'`')
                ) {
                    state = State::Code;
                }
            }
            State::LineComment => {
                if byte == b'\n' || byte == b'\r' {
                    state = State::Code;
                } else {
                    output[i] = b' ';
                }
            }
            State::BlockComment => {
                if byte == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    output[i] = b' ';
                    output[i + 1] = b' ';
                    i += 1;
                    state = State::Code;
                } else if byte != b'\n' && byte != b'\r' {
                    output[i] = b' ';
                }
            }
        }
        i += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
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
        let body = without_comments(&input.body);
        let mut endpoints: Vec<Endpoint> = Vec::new();
        let mut candidates: BTreeSet<String> = BTreeSet::new();

        for cap in self.fetch.captures_iter(&body) {
            Self::push(&mut endpoints, &cap[1], Method::Unknown);
        }
        for cap in self.axios.captures_iter(&body) {
            Self::push(&mut endpoints, &cap[2], Method::parse(&cap[1]));
        }
        for cap in self.xhr.captures_iter(&body) {
            Self::push(&mut endpoints, &cap[2], Method::parse(&cap[1]));
        }
        for cap in self.websocket_call.captures_iter(&body) {
            Self::push(&mut endpoints, &cap[1], Method::Unknown);
        }
        for cap in self.http_client.captures_iter(&body) {
            if let Some(route) = static_template_route(&cap[2]) {
                Self::push(&mut endpoints, route, Method::parse(&cap[1]));
            }
        }
        for cap in self.api_path.captures_iter(&body) {
            candidates.insert(cap[1].to_owned());
        }
        for cap in self.websocket.captures_iter(&body) {
            candidates.insert(cap[1].to_owned());
        }
        for cap in self.absolute.captures_iter(&body) {
            // Skip websocket URLs already captured above to avoid duplicate work
            // (the pipeline dedups anyway, but this keeps provenance clean), and
            // drop XML-namespace / specification URIs that are not endpoints.
            if !cap[1].starts_with("ws") && !is_non_endpoint_url(&cap[1]) {
                candidates.insert(cap[1].to_owned());
            }
        }
        let called: BTreeSet<String> = endpoints.iter().map(|ep| ep.url.clone()).collect();
        let network_findings = endpoints
            .into_iter()
            .map(|ep| {
                let mut f = Finding::from_endpoint(input.session_id, &ep, Confidence::Low);
                f.provenance = Provenance::new(Source::JsRegex, input.url.clone());
                f
            })
            .collect::<Vec<_>>();
        let static_candidates = candidates
            .into_iter()
            .filter(|s| !called.contains(s))
            .map(|s| {
                Finding::new(
                    input.session_id,
                    FindingKind::Config,
                    None,
                    format!("network URL candidate (regex string): {s}"),
                    Confidence::Low,
                    Provenance::new(Source::JsRegex, input.url.clone()),
                )
            });
        network_findings
            .into_iter()
            .chain(static_candidates)
            .collect()
    }
}

/// Extract only the route portion following a dynamic template origin. The
/// static suffix ends at the next interpolation so runtime values are never
/// presented as known URL text.
fn static_template_route(template: &str) -> Option<&str> {
    let after_expression = template.match_indices('}').find_map(|(index, _)| {
        template
            .get(index + 1..)
            .filter(|tail| tail.starts_with('/'))
    })?;
    let route = after_expression
        .split_once("${")
        .map_or(after_expression, |(static_part, _)| static_part);
    let path = route.split(['?', '#']).next().unwrap_or(route);
    (path.starts_with('/') && path.len() > 1).then_some(route)
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
        assert!(found
            .iter()
            .any(|f| f.kind == FindingKind::Config && f.value.contains("wss://t/socket")));
        assert!(found.iter().any(|f| f.kind == FindingKind::Endpoint));
        // axios.post resolves a concrete method.
        assert!(found
            .iter()
            .any(|f| f.value.starts_with("POST ") && f.value.contains("/v1/login")));
    }

    #[test]
    fn ignores_network_calls_inside_comments() {
        let found = run("// fetch('/api/v4/admin')\nconst ready = true;");
        assert!(
            found.is_empty(),
            "commented code produced findings: {found:?}"
        );
    }

    #[test]
    fn reports_websocket_constructor_as_endpoint() {
        let found = run("new WebSocket('wss://t/socket');");
        assert!(found.iter().any(|f| {
            f.kind == FindingKind::Endpoint && f.url.as_deref() == Some("wss://t/socket")
        }));
    }

    #[test]
    fn absolute_url_keeps_comma_and_at_characters() {
        let js = r#"const u = "https://api.example.com/search?q=a,b&user=me@example.com";"#;
        let found = run(js);
        assert!(found.iter().any(|f| f.kind == FindingKind::Config
            && f.value
                .contains("https://api.example.com/search?q=a,b&user=me@example.com")));
    }

    #[test]
    fn api_path_is_case_insensitive() {
        let js = r#"const u = "/API/V1/Users";"#;
        let found = run(js);
        assert!(found
            .iter()
            .any(|f| f.kind == FindingKind::Config && f.value.contains("/API/V1/Users")));
    }

    #[test]
    fn extracts_angular_httpclient_template_route_and_verb() {
        let found = run(
            "this.http.get(`${this.hostServer}/rest/products/search?q=${criteria}`); this.cache.get(`/products/cache`);",
        );
        assert!(
            found.iter().any(|finding| {
                finding.kind == FindingKind::Endpoint
                    && finding.value == "GET /rest/products/search?q="
                    && finding.confidence == Confidence::Low
            }),
            "findings: {found:?}"
        );
        assert!(!found
            .iter()
            .any(|finding| finding.value.contains("/products/cache")));
    }

    #[test]
    fn httpclient_receiver_prefix_preserves_captures_and_comment_filtering() {
        let extractor = JsRegexExtractor::new();
        let legacy = Regex::new(
            r"(?:[A-Za-z_$][\w$]*\.)*http\.(get|post|put|delete|patch)\s*\(\s*`([^`]*)`",
        )
        .unwrap();
        for receiver in [
            "http",
            "this.http",
            "client_é.http",
            "é.http",
            "a.b.http",
            "myhttp",
            "http2",
            "cache",
        ] {
            for method in ["get", "post", "put", "delete", "patch", "GET", "head"] {
                let body = format!("{receiver}.{method}(`${{base}}/records?q=${{value}}`);");
                let captures = |regex: &Regex| {
                    regex
                        .captures_iter(&body)
                        .map(|capture| (capture[1].to_owned(), capture[2].to_owned()))
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    captures(&extractor.http_client),
                    captures(&legacy),
                    "{body}"
                );
            }
        }
        let findings =
            run("// this.http.get(`${base}/commented`);\n/* é.http.post(`${base}/hidden`); */");
        assert!(findings.is_empty(), "commented calls produced {findings:?}");
    }

    #[test]
    fn drops_namespace_and_spec_uris() {
        let js = r#"
            const svg = "http://www.w3.org/2000/svg";
            const ld = "https://schema.org/Organization";
            const real = "https://api.example.com/v1/users";
        "#;
        let found = run(js);
        assert!(found
            .iter()
            .any(|f| f.value.contains("https://api.example.com/v1/users")));
        assert!(
            !found
                .iter()
                .any(|f| f.value.contains("w3.org") || f.value.contains("schema.org")),
            "namespace/spec URIs must not be reported as endpoints"
        );
    }
}
