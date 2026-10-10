// crates/webrev-extract/src/extractors/graphql.rs
//! Detects GraphQL operations (named query / mutation / subscription).

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Extracts named GraphQL operations from JS/HTML.
pub struct GraphQlExtractor {
    operation: Regex,
}

impl GraphQlExtractor {
    /// # Panics
    ///
    /// Never at runtime: the pattern is a constant verified by `pattern_compiles`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            operation: Regex::new(
                r"(?m)\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[({]",
            )
            .expect("constant graphql pattern must compile"),
        }
    }
}

impl Default for GraphQlExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor for GraphQlExtractor {
    fn name(&self) -> &'static str {
        "graphql"
    }

    fn priority(&self) -> u8 {
        52
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        matches!(input.kind, ContentKind::Html | ContentKind::JavaScript)
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        self.operation
            .captures_iter(&input.body)
            .filter_map(|cap| {
                let value = format!("{} {}", &cap[1], &cap[2]);
                seen.insert(value.clone()).then(|| {
                    Finding::new(
                        input.session_id,
                        FindingKind::GraphQl,
                        None,
                        value,
                        Confidence::Medium,
                        Provenance::new(Source::JsRegex, input.url.clone()),
                    )
                })
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
        let _ = GraphQlExtractor::new();
    }

    #[test]
    fn extracts_named_operations() {
        let js = r"
            const Q = gql`query GetUser($id: ID!) { user(id: $id) { name } }`;
            const M = gql`mutation DeletePost { deletePost }`;
        ";
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, js);
        let found = GraphQlExtractor::new().extract(&input);
        let values: Vec<&str> = found.iter().map(|f| f.value.as_str()).collect();
        assert!(values.contains(&"query GetUser"));
        assert!(values.contains(&"mutation DeletePost"));
        assert!(found.iter().all(|f| f.kind == FindingKind::GraphQl));
    }
}
