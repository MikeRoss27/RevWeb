// crates/webrev-extract/src/registry.rs
//! The priority-ordered collection of extractors.

use crate::extractors::{
    inline_scripts, ConfigExtractor, GraphQlExtractor, HtmlExtractor, JsAstExtractor,
    JsRegexExtractor, ManifestExtractor, ParamExtractor, SecretExtractor, SourceMapExtractor,
    SpaRouteExtractor, TechExtractor,
};
use crate::traits::{ContentKind, ExtractInput, Extractor};
use webrev_core::Finding;

/// An ordered set of extractors. Construct with [`ExtractorRegistry::with_defaults`]
/// for the standard pipeline, or [`ExtractorRegistry::new`] + [`register`] to
/// build a custom set in tests.
///
/// [`register`]: ExtractorRegistry::register
#[derive(Default)]
pub struct ExtractorRegistry {
    extractors: Vec<Box<dyn Extractor>>,
}

impl ExtractorRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The standard registry used by the pipeline: HTML + both JS strategies +
    /// source-map detection, ordered by priority. Detected secrets include plaintext.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        reg.register(Box::new(JsAstExtractor::new()));
        reg.register(Box::new(HtmlExtractor::new()));
        reg.register(Box::new(JsRegexExtractor::new()));
        reg.register(Box::new(SecretExtractor::with_random_key()));
        reg.register(Box::new(SourceMapExtractor::new()));
        reg.register(Box::new(TechExtractor::new()));
        reg.register(Box::new(GraphQlExtractor::new()));
        reg.register(Box::new(SpaRouteExtractor::new()));
        reg.register(Box::new(ParamExtractor::new()));
        reg.register(Box::new(ConfigExtractor::new()));
        reg.register(Box::new(ManifestExtractor::new()));
        reg
    }

    /// Insert an extractor, keeping the collection sorted by descending
    /// priority (stable, so equal priorities retain insertion order).
    pub fn register(&mut self, extractor: Box<dyn Extractor>) {
        self.extractors.push(extractor);
        self.extractors
            .sort_by_key(|e| std::cmp::Reverse(e.priority()));
    }

    /// Names of the registered extractors in priority order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.extractors.iter().map(|e| e.name()).collect()
    }

    /// Run every applicable extractor against `input` and concatenate their
    /// findings (deduplication is the pipeline's responsibility).
    ///
    /// For HTML inputs this also cascades into the inline `<script>` bodies,
    /// running the JavaScript extractors on each so endpoints and source-map
    /// comments embedded in the page are not missed.
    #[must_use]
    pub fn run(&self, input: &ExtractInput) -> Vec<Finding> {
        let mut findings: Vec<Finding> = self
            .extractors
            .iter()
            .filter(|e| e.applies_to(input))
            .flat_map(|e| e.extract(input))
            .collect();

        if input.kind == ContentKind::Html {
            for body in inline_scripts(&input.body) {
                let sub = ExtractInput::new(
                    input.session_id,
                    input.url.clone(),
                    ContentKind::JavaScript,
                    body,
                );
                for extractor in self.extractors.iter().filter(|e| e.applies_to(&sub)) {
                    findings.extend(extractor.extract(&sub));
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_priority_ordered() {
        let reg = ExtractorRegistry::with_defaults();
        let names = reg.names();
        // Descending priority: js-ast (90), html (80), js-regex (70),
        // secret (65), sourcemap (60), tech (55), graphql (52), routes (50),
        // params (48), config (47), manifest (45).
        assert_eq!(
            names,
            vec![
                "js-ast",
                "html",
                "js-regex",
                "secret",
                "sourcemap",
                "tech",
                "graphql",
                "routes",
                "params",
                "config",
                "manifest"
            ]
        );
    }
}
