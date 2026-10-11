// crates/webrev-extract/src/extractors/params.rs
//! Extracts a parameter wordlist: URL query names, HTML form field names, and
//! JSON/object body keys. Useful as fuzzing input for the discovered endpoints.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Parameter-name extractor.
pub struct ParamExtractor {
    query: Regex,
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
            json_key: compile(
                r#"(?:^|[{,])\s*["']([A-Za-z_$][A-Za-z0-9_$\-.]{1,60})["']\s*:"#,
            ),
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

        Self::collect(&self.query, &input.body, &mut seen, &mut names);
        Self::collect(&self.json_key, &input.body, &mut seen, &mut names);
        if input.kind == ContentKind::Html {
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
              const body = { "userId": 1, "isAdmin": false };
            </script>"#;
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::Html, html);
        let names: Vec<String> = ParamExtractor::new()
            .extract(&input)
            .into_iter()
            .map(|f| f.value)
            .collect();
        for expected in ["email", "csrf_token", "q", "page", "userId", "isAdmin"] {
            assert!(names.contains(&expected.to_owned()), "missing {expected}: {names:?}");
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
        assert!(names.contains(&"realKey".to_owned()), "got: {names:?}");
    }
}
