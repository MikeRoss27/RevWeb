// crates/webrev-extract/src/extractors/endpoints/graphql.rs
//! Detects GraphQL operations (named query / mutation / subscription).

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Extracts named GraphQL operations from JS/HTML.
pub struct GraphQlExtractor {
    operation: Regex,
    /// Matches shipped introspection queries (Apollo codegen's
    /// `IntrospectionQuery`, or a literal `__schema { ... }` selection). Their
    /// presence signals that the target's `/graphql` endpoint is worth
    /// probing manually for a full schema dump — introspection itself needs a
    /// live network request, which is out of scope for a pure extractor.
    introspection: Regex,
}

impl GraphQlExtractor {
    /// # Panics
    ///
    /// Never at runtime: the patterns are constants verified by `pattern_compiles`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            operation: Regex::new(
                r"(?m)\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[({]",
            )
            .expect("constant graphql pattern must compile"),
            introspection: Regex::new(r"\b(IntrospectionQuery|__schema\s*\{|__type\s*\()")
                .expect("constant introspection pattern must compile"),
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
        let mut findings: Vec<Finding> = self
            .operation
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
            .collect();

        if self.introspection.is_match(&input.body) {
            findings.push(Finding::new(
                input.session_id,
                FindingKind::GraphQl,
                None,
                "introspection query shipped client-side".to_owned(),
                Confidence::Medium,
                Provenance::new(Source::JsRegex, input.url.clone()),
            ));
        }

        findings
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

    #[test]
    fn flags_shipped_introspection_query() {
        let js = r"const Q = gql`query IntrospectionQuery { __schema { types { name } } }`;";
        let input = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, js);
        let found = GraphQlExtractor::new().extract(&input);
        assert!(found
            .iter()
            .any(|f| f.value == "introspection query shipped client-side"));
    }
}
