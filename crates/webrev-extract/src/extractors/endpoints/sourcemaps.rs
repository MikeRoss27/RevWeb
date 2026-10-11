// crates/webrev-extract/src/extractors/endpoints/sourcemaps.rs
//! Detects `sourceMappingURL` annotations, which often expose original,
//! un-minified source (and sometimes paths that reveal further endpoints).

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Source-map reference extractor.
pub struct SourceMapExtractor {
    pattern: Regex,
}

impl SourceMapExtractor {
    /// # Panics
    ///
    /// Never at runtime: the pattern is a constant verified by the
    /// `pattern_compiles` unit test.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // Matches both `//# sourceMappingURL=` and the legacy `//@` form.
            pattern: Regex::new(r"(?m)//[#@]\s*sourceMappingURL=(\S+)")
                .expect("constant sourcemap pattern must compile"),
        }
    }
}

impl Default for SourceMapExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor for SourceMapExtractor {
    fn name(&self) -> &'static str {
        "sourcemap"
    }

    fn priority(&self) -> u8 {
        60
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        input.kind == ContentKind::JavaScript
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        self.pattern
            .captures_iter(&input.body)
            .map(|cap| {
                let map_url = cap[1].to_owned();
                Finding::new(
                    input.session_id,
                    FindingKind::SourceMap,
                    Some(map_url.clone()),
                    map_url,
                    Confidence::High,
                    Provenance::new(Source::SourceMap, input.url.clone()),
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
    fn pattern_compiles() {
        let _ = SourceMapExtractor::new();
    }

    #[test]
    fn detects_both_comment_forms() {
        let js = "console.log(1);\n//# sourceMappingURL=app.js.map\n//@ sourceMappingURL=old.map";
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, js);
        let found = SourceMapExtractor::new().extract(&input);
        let urls: Vec<&str> = found.iter().filter_map(|f| f.url.as_deref()).collect();
        assert_eq!(urls, vec!["app.js.map", "old.map"]);
    }
}
