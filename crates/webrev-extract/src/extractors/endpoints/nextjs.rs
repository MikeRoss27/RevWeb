// crates/webrev-extract/src/extractors/endpoints/nextjs.rs
//! Next.js framework adapter: recovers page routes from data the framework
//! embeds itself, rather than guessing from generic JS patterns.
//!
//! Two sources, both verbatim framework internals rather than heuristics:
//! - `__NEXT_DATA__`: present on every server-rendered page; gives the
//!   current route (`page`) and the `buildId` that names this deployment's
//!   static asset directory.
//! - `self.__BUILD_MANIFEST` / `self.__SSG_MANIFEST`: present only in
//!   `_buildManifest.js` / `_ssgManifest.js`, which Next.js links directly
//!   from the HTML `<head>` as a plain `<script src>` — the crawler already
//!   discovers and fetches those like any other script, so no pipeline
//!   change is needed to reach this content. This is the real value over
//!   [`super::SpaRouteExtractor`]: these are *every* page the build knows
//!   about, whether or not anything the crawler visited links to them.
//!
//! `__BUILD_MANIFEST`'s body is a JS object literal, not strict JSON (it
//! mixes quoted path keys with bare identifiers like `sortedPages`), so it
//! is not parsed as a whole — only the `"<path>": [` shape of each top-level
//! page entry is matched. A build manifest in a shape this doesn't
//! recognize (e.g. a future Next.js format) simply yields no findings;
//! nothing is guessed.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

#[derive(Debug, Deserialize)]
struct NextData {
    page: Option<String>,
    #[serde(rename = "buildId")]
    build_id: Option<String>,
}

/// Next.js framework adapter.
pub struct NextJsExtractor {
    next_data: Regex,
    build_manifest: Regex,
    page_entry: Regex,
    ssg_manifest: Regex,
}

impl NextJsExtractor {
    /// # Panics
    ///
    /// Never at runtime: every pattern is a constant verified by the
    /// `patterns_compile` unit test.
    #[must_use]
    pub fn new() -> Self {
        let compile = |p: &str| Regex::new(p).expect("constant Next.js pattern must compile");
        Self {
            next_data: compile(r#"(?is)<script[^>]*id=["']__NEXT_DATA__["'][^>]*>(.*?)</script>"#),
            build_manifest: compile(r"self\.__BUILD_MANIFEST\s*="),
            page_entry: compile(r#""(/[^"]*)"\s*:\s*\["#),
            // Captures up to the first `)` rather than the first `]`: a page
            // path can itself contain `]` (a dynamic segment like
            // `/blog/[slug]`), so stopping at the first bracket would cut
            // the array short. The array argument itself never contains `)`.
            ssg_manifest: compile(r"(?s)self\.__SSG_MANIFEST\s*=\s*new Set\(\s*(.*?)\s*\)"),
        }
    }
}

impl Default for NextJsExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor for NextJsExtractor {
    fn name(&self) -> &'static str {
        "nextjs"
    }

    fn priority(&self) -> u8 {
        51
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        matches!(input.kind, ContentKind::Html | ContentKind::JavaScript)
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        match input.kind {
            ContentKind::Html => self.extract_next_data(input),
            ContentKind::JavaScript => self.extract_manifests(input),
            _ => Vec::new(),
        }
    }
}

impl NextJsExtractor {
    fn extract_next_data(&self, input: &ExtractInput) -> Vec<Finding> {
        let Some(cap) = self.next_data.captures(&input.body) else {
            return Vec::new();
        };
        let Ok(data) = serde_json::from_str::<NextData>(cap[1].trim()) else {
            return Vec::new();
        };
        let mut findings = Vec::new();
        if let Some(page) = data.page.filter(|p| p.starts_with('/')) {
            findings.push(Finding::new(
                input.session_id,
                FindingKind::Route,
                None,
                page,
                Confidence::High,
                Provenance::new(Source::Html, input.url.clone()),
            ));
        }
        if let Some(build_id) = data.build_id {
            findings.push(Finding::new(
                input.session_id,
                FindingKind::Config,
                None,
                format!("buildId = {build_id}"),
                Confidence::High,
                Provenance::new(Source::Html, input.url.clone()),
            ));
        }
        findings
    }

    fn extract_manifests(&self, input: &ExtractInput) -> Vec<Finding> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut findings = Vec::new();

        if self.build_manifest.is_match(&input.body) {
            for cap in self.page_entry.captures_iter(&input.body) {
                let path = cap[1].to_owned();
                if seen.insert(path.clone()) {
                    findings.push(Finding::new(
                        input.session_id,
                        FindingKind::Route,
                        None,
                        path,
                        Confidence::High,
                        Provenance::new(Source::Manifest, input.url.clone()),
                    ));
                }
            }
        }

        if let Some(cap) = self.ssg_manifest.captures(&input.body) {
            if let Ok(paths) = serde_json::from_str::<Vec<String>>(&cap[1]) {
                for path in paths {
                    if path.starts_with('/') && seen.insert(path.clone()) {
                        findings.push(Finding::new(
                            input.session_id,
                            FindingKind::Route,
                            None,
                            path,
                            Confidence::High,
                            Provenance::new(Source::Manifest, input.url.clone()),
                        ));
                    }
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
        let _ = NextJsExtractor::new();
    }

    #[test]
    fn recovers_current_route_and_build_id_from_next_data() {
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">{"props":{},"page":"/dashboard/[id]","query":{},"buildId":"abc123xyz"}</script>
        </body></html>"#;
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::Html, html);
        let found = NextJsExtractor::new().extract(&input);
        let routes: Vec<&str> = found
            .iter()
            .filter(|f| f.kind == FindingKind::Route)
            .map(|f| f.value.as_str())
            .collect();
        assert_eq!(routes, vec!["/dashboard/[id]"]);
        let configs: Vec<&str> = found
            .iter()
            .filter(|f| f.kind == FindingKind::Config)
            .map(|f| f.value.as_str())
            .collect();
        assert_eq!(configs, vec!["buildId = abc123xyz"]);
    }

    #[test]
    fn ignores_html_without_next_data() {
        let input = ExtractInput::new(
            SessionId::new(),
            None,
            ContentKind::Html,
            "<html><body>plain page</body></html>",
        );
        assert!(NextJsExtractor::new().extract(&input).is_empty());
    }

    #[test]
    fn recovers_every_page_from_build_manifest() {
        let js = r#"
            self.__BUILD_MANIFEST = {
              "/": ["static/chunks/pages/index-abc.js"],
              "/about": ["static/chunks/pages/about-def.js"],
              "/users/[id]": ["static/chunks/pages/users/[id]-ghi.js"],
              sortedPages: ["/", "/about", "/users/[id]"]
            };self.__BUILD_MANIFEST_CB && self.__BUILD_MANIFEST_CB()
        "#;
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, js);
        let found = NextJsExtractor::new().extract(&input);
        let mut routes: Vec<&str> = found.iter().map(|f| f.value.as_str()).collect();
        routes.sort_unstable();
        assert_eq!(routes, vec!["/", "/about", "/users/[id]"]);
        assert!(found.iter().all(|f| f.kind == FindingKind::Route));
    }

    #[test]
    fn recovers_pre_rendered_pages_from_ssg_manifest() {
        let js = r#"self.__SSG_MANIFEST=new Set(["/","/about","/blog/[slug]"]);self.__SSG_MANIFEST_CB&&self.__SSG_MANIFEST_CB()"#;
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, js);
        let found = NextJsExtractor::new().extract(&input);
        let mut routes: Vec<&str> = found.iter().map(|f| f.value.as_str()).collect();
        routes.sort_unstable();
        assert_eq!(routes, vec!["/", "/about", "/blog/[slug]"]);
    }

    #[test]
    fn unrecognized_manifest_shape_yields_nothing_rather_than_guessing() {
        let js = "self.__BUILD_MANIFEST = someFutureFormatFunction();";
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, js);
        assert!(NextJsExtractor::new().extract(&input).is_empty());
    }

    #[test]
    fn plain_javascript_is_ignored() {
        let input = ExtractInput::new(
            SessionId::new(),
            None,
            ContentKind::JavaScript,
            "console.log('hello');",
        );
        assert!(NextJsExtractor::new().extract(&input).is_empty());
    }
}
