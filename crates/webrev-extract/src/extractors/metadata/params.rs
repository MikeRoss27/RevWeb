// crates/webrev-extract/src/extractors/metadata/params.rs
//! Extracts a parameter wordlist: URL query names, HTML form field names, and
//! JSON/object body keys. Useful as fuzzing input for the discovered endpoints.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Parameter-name extractor.
pub struct ParamExtractor {
    query: Regex,
    network_url: Regex,
    html_url: Regex,
    body_object: Regex,
    form_field: Regex,
    json_key: Regex,
}

impl ParamExtractor {
    /// # Panics
    ///
    /// Never at runtime: all patterns are constants verified by `patterns_compile`.
    #[must_use]
    pub fn new() -> Self {
        let compile = |p: &str| Regex::new(p).expect("constant param pattern must compile");
        Self {
            // `?a=1&b[0]=2` → a, b[0]
            query: compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-\[\].]{0,60})="),
            // This unanchored search needs only the `http` suffix; matching
            // optional receiver identifiers adds a Unicode DFA but no captures.
            network_url: compile(
                r#"(?:fetch|axios\.(?:get|post|put|patch|delete)|http\.(?:get|post|put|patch|delete))\s*\(\s*["'`]([^"'`]+)["'`]"#,
            ),
            html_url: compile(r#"(?i)\b(?:href|action)\s*=\s*["']([^"']+)["']"#),
            body_object: compile(
                r"(?s)(?:JSON\.stringify\s*\(|axios\.(?:post|put|patch)\s*\([^,]+,)\s*\{([^}]+)\}",
            ),
            // `<input name="email">`, also select/textarea.
            form_field: compile(
                r#"(?i)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']"#,
            ),
            // Quoted object/JSON keys: `"userId":` (quoted only, to stay
            // precise). Requires the quote to be preceded by `{`/`,`/start
            // of input (an object-literal key position) rather than bare on
            // `"...":`, so a JS ternary (`cond ? "yes" : "no"`) — whose
            // branches are *also* `"quoted string" :`-shaped — doesn't get
            // its branch values reported as bogus parameter names.
            json_key: compile(r#"(?:^|[{,])\s*["']([A-Za-z_$][A-Za-z0-9_$\-.]{1,60})["']\s*:"#),
        }
    }

    fn collect(re: &Regex, body: &str, seen: &mut BTreeSet<String>, out: &mut Vec<String>) {
        for cap in re.captures_iter(body) {
            if let Some(name) = cap.get(1) {
                let name = name.as_str().to_owned();
                if seen.insert(name.clone()) {
                    out.push(name);
                }
            }
        }
    }
}

impl Default for ParamExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor for ParamExtractor {
    fn name(&self) -> &'static str {
        "params"
    }

    fn priority(&self) -> u8 {
        48
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        matches!(input.kind, ContentKind::Html | ContentKind::JavaScript)
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut names: Vec<String> = Vec::new();

        if let Some(url) = &input.url {
            Self::collect(&self.query, url, &mut seen, &mut names);
        }
        for cap in self.network_url.captures_iter(&input.body) {
            Self::collect(&self.query, &cap[1], &mut seen, &mut names);
        }
        for cap in self.body_object.captures_iter(&input.body) {
            Self::collect(
                &self.json_key,
                &format!("{{{}}}", &cap[1]),
                &mut seen,
                &mut names,
            );
        }
        if input.kind == ContentKind::Html {
            for cap in self.html_url.captures_iter(&input.body) {
                Self::collect(&self.query, &cap[1], &mut seen, &mut names);
            }
            Self::collect(&self.form_field, &input.body, &mut seen, &mut names);
        }

        names
            .into_iter()
            .map(|name| {
                Finding::new(
                    input.session_id,
                    FindingKind::Parameter,
                    None,
                    name,
                    Confidence::Low,
                    Provenance::new(Source::JsRegex, input.url.clone()),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::SessionId;

    #[test]
    fn patterns_compile() {
        let _ = ParamExtractor::new();
    }

    #[test]
    fn extracts_query_json_and_form_names() {
        let html = r#"
            <form><input name="email"><input name="csrf_token"></form>
            <script>
              fetch("/api/search?q=1&page=2");
              fetch('/api/users', {body: JSON.stringify({ "userId": 1, "isAdmin": false })});
            </script>"#;
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::Html, html);
        let names: Vec<String> = ParamExtractor::new()
            .extract(&input)
            .into_iter()
            .map(|f| f.value)
            .collect();
        for expected in ["email", "csrf_token", "q", "page", "userId", "isAdmin"] {
            assert!(
                names.contains(&expected.to_owned()),
                "missing {expected}: {names:?}"
            );
        }
        // Deduplicated.
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }

    #[test]
    fn ternary_branches_are_not_reported_as_parameters() {
        let js = r#"const label = cond ? "yes" : "no"; const o = {"realKey": 1};"#;
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, js);
        let names: Vec<String> = ParamExtractor::new()
            .extract(&input)
            .into_iter()
            .map(|f| f.value)
            .collect();
        assert!(!names.contains(&"yes".to_owned()), "got: {names:?}");
        assert!(!names.contains(&"no".to_owned()), "got: {names:?}");
        assert!(!names.contains(&"realKey".to_owned()), "got: {names:?}");
    }

    #[test]
    fn internal_object_keys_and_example_query_strings_are_not_http_parameters() {
        let js = r#"const settings = {"internalFlag": true}; const example = "?debug=1"; fetch('/api?q=ok');"#;
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, js);
        let names: Vec<_> = ParamExtractor::new()
            .extract(&input)
            .into_iter()
            .map(|f| f.value)
            .collect();
        assert_eq!(names, ["q"]);
    }

    #[test]
    fn httpclient_receiver_prefix_preserves_parameter_url_captures() {
        let extractor = ParamExtractor::new();
        let legacy = Regex::new(
            r#"(?:fetch|axios\.(?:get|post|put|patch|delete)|(?:[A-Za-z_$][\w$]*\.)*http\.(?:get|post|put|patch|delete))\s*\(\s*["'`]([^"'`]+)["'`]"#,
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
            "axios",
        ] {
            for method in ["get", "post", "put", "delete", "patch", "GET", "head"] {
                for quote in ['\'', '"', '`'] {
                    let body = format!(
                        "{receiver}.{method}({quote}/records?q=1{quote}); fetch('/next?page=1');"
                    );
                    let captures = |regex: &Regex| {
                        regex
                            .captures_iter(&body)
                            .map(|capture| capture[1].to_owned())
                            .collect::<Vec<_>>()
                    };
                    assert_eq!(
                        captures(&extractor.network_url),
                        captures(&legacy),
                        "{body}"
                    );
                }
            }
        }
    }

    #[test]
    fn extracts_query_parameters_from_angular_httpclient_template_urls() {
        let js = r"return this.http.get(`${this.hostServer}/rest/products/search?q=${criteria}`)";
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, js);
        let names: Vec<_> = ParamExtractor::new()
            .extract(&input)
            .into_iter()
            .map(|finding| finding.value)
            .collect();
        assert_eq!(names, ["q"]);
    }
}
