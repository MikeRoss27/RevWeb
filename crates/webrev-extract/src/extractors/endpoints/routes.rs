// crates/webrev-extract/src/extractors/endpoints/routes.rs
//! Detects client-side (SPA router) route paths from JS/HTML.
//!
//! Covers the two dominant shapes: a `path: "/..."` property (React Router v6,
//! Vue Router, Angular route tables) and a JSX `<Route path="/...">`.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Extracts SPA route definitions.
pub struct SpaRouteExtractor {
    path_prop: Regex,
    jsx_route: Regex,
}

impl SpaRouteExtractor {
    /// # Panics
    ///
    /// Never at runtime: both patterns are constants verified by `patterns_compile`.
    #[must_use]
    pub fn new() -> Self {
        let compile = |p: &str| Regex::new(p).expect("constant route pattern must compile");
        Self {
            // `path: "/users/:id"` — only values that start with `/`.
            path_prop: compile(r#"(?i)\bpath\s*:\s*['"`](/[^'"`?\s]*)['"`]"#),
            // `<Route path="/users" ...>` — JSX form (may be relative).
            jsx_route: compile(r#"(?i)<Route[^>]+path\s*=\s*['"`]([^'"`\s]+)['"`]"#),
        }
    }
}

impl Default for SpaRouteExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor for SpaRouteExtractor {
    fn name(&self) -> &'static str {
        "routes"
    }

    fn priority(&self) -> u8 {
        50
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        matches!(input.kind, ContentKind::Html | ContentKind::JavaScript)
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut findings = Vec::new();
        let captures = self
            .path_prop
            .captures_iter(&input.body)
            .chain(self.jsx_route.captures_iter(&input.body));
        for cap in captures {
            if let Some(path) = cap.get(1) {
                let path = path.as_str().to_owned();
                if path.len() > 1 && seen.insert(path.clone()) {
                    findings.push(Finding::new(
                        input.session_id,
                        FindingKind::Route,
                        None,
                        path,
                        Confidence::Low,
                        Provenance::new(Source::JsRegex, input.url.clone()),
                    ));
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

    #[test]
    fn patterns_compile() {
        let _ = SpaRouteExtractor::new();
    }

    #[test]
    fn extracts_path_props_and_jsx_routes() {
        let js = r#"
            const routes = [{ path: "/dashboard" }, { path: "/users/:id" }];
            const jsx = '<Route path="/settings" element={<S/>} />';
        "#;
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, js);
        let found = SpaRouteExtractor::new().extract(&input);
        let paths: Vec<&str> = found.iter().map(|f| f.value.as_str()).collect();
        assert!(paths.contains(&"/dashboard"));
        assert!(paths.contains(&"/users/:id"));
        assert!(paths.contains(&"/settings"));
        assert!(found.iter().all(|f| f.kind == FindingKind::Route));
    }
}
