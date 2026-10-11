// crates/webrev-extract/src/extractors/config.rs
//! Detects embedded configuration constants and feature flags in JavaScript:
//! object properties and top-level `const` declarations whose name reads as
//! a config/flag key (`featureFlag`, `DEBUG`, `apiVersion`, `tenantId`, …)
//! bound to a literal value.
//!
//! This complements [`crate::extractors::js_ast::JsAstExtractor`]: that
//! extractor's generic string-literal pass only reports values that are
//! themselves URL/path-shaped, so a boolean feature flag or a bare version
//! string (`"v2"`, `true`, `25`) never surfaces anywhere else.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use swc_core::common::input::StringInput;
use swc_core::common::sync::Lrc;
use swc_core::common::{BytePos, FileName, SourceMap};
use swc_core::ecma::ast::{KeyValueProp, Lit, Pat, PropName, VarDeclarator};
use swc_core::ecma::parser::{EsSyntax, Parser, Syntax};
use swc_core::ecma::visit::{Visit, VisitWith};
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Config/feature-flag-ish substrings, matched case-insensitively against an
/// identifier or object key. Deliberately narrow: broad terms like "config"
/// alone would also match unrelated identifiers (`configureStore`).
const CONFIG_KEY_MARKERS: &[&str] = &[
    "featureflag",
    "feature_flag",
    "flag",
    "enable",
    "disable",
    "debug",
    "environment",
    "apiversion",
    "api_version",
    "tenantid",
    "tenant_id",
    "region",
    "stage",
    "rollout",
    "experiment",
    "maintenance",
];

/// Config-based extractor.
pub struct ConfigExtractor;

impl ConfigExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for ConfigExtractor {
    fn default() -> Self {
        Self::new()
    }
}

fn is_config_key(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    CONFIG_KEY_MARKERS.iter().any(|m| lower.contains(m))
}

/// Render a literal as it would read in source, or `None` for shapes we do
/// not want to report (template strings, regexes, etc. are left to other
/// extractors).
fn literal_value(lit: &Lit) -> Option<String> {
    match lit {
        Lit::Str(s) => Some(s.value.to_string_lossy().into_owned()),
        Lit::Bool(b) => Some(b.value.to_string()),
        Lit::Num(n) => Some(n.value.to_string()),
        _ => None,
    }
}

#[derive(Default)]
struct ConfigVisitor {
    hits: Vec<String>,
}

impl Visit for ConfigVisitor {
    fn visit_key_value_prop(&mut self, prop: &KeyValueProp) {
        let key = match &prop.key {
            PropName::Ident(id) => Some(id.sym.as_ref().to_owned()),
            PropName::Str(s) => Some(s.value.to_string_lossy().into_owned()),
            _ => None,
        };
        if let Some(key) = key {
            if is_config_key(&key) {
                if let swc_core::ecma::ast::Expr::Lit(lit) = &*prop.value {
                    if let Some(value) = literal_value(lit) {
                        self.hits.push(format!("{key} = {value}"));
                    }
                }
            }
        }
        prop.value.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, decl: &VarDeclarator) {
        if let Pat::Ident(id) = &decl.name {
            let name = id.id.sym.as_ref();
            // Either naming convention: `DEBUG_MODE` or `featureFlagX`.
            let is_upper_snake = name.len() > 1
                && name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_' || b.is_ascii_digit());
            if is_upper_snake || is_config_key(name) {
                if let Some(init) = &decl.init {
                    if let swc_core::ecma::ast::Expr::Lit(lit) = &**init {
                        if let Some(value) = literal_value(lit) {
                            self.hits.push(format!("{name} = {value}"));
                        }
                    }
                }
            }
        }
        decl.visit_children_with(self);
    }
}

impl Extractor for ConfigExtractor {
    fn name(&self) -> &'static str {
        "config"
    }

    fn priority(&self) -> u8 {
        47
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        input.kind == ContentKind::JavaScript
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let cm: Lrc<SourceMap> = Lrc::default();
        let fm = cm.new_source_file(Lrc::new(FileName::Anon), input.body.clone());
        let len = u32::try_from(fm.src.len()).unwrap_or(u32::MAX);
        let parser_input = StringInput::new(&fm.src, BytePos(0), BytePos(len));
        let mut parser = Parser::new(Syntax::Es(EsSyntax::default()), parser_input, None);

        let Ok(module) = parser.parse_module() else {
            return Vec::new();
        };

        let mut visitor = ConfigVisitor::default();
        module.visit_with(&mut visitor);

        let mut seen = std::collections::BTreeSet::new();
        visitor
            .hits
            .into_iter()
            .filter(|hit| seen.insert(hit.clone()))
            .map(|value| {
                Finding::new(
                    input.session_id,
                    FindingKind::Config,
                    None,
                    value,
                    Confidence::Medium,
                    Provenance::new(Source::JsAst, input.url.clone()),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::SessionId;

    fn run(js: &str) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/app.js".into()),
            ContentKind::JavaScript,
            js,
        );
        ConfigExtractor::new().extract(&input)
    }

    #[test]
    fn extracts_feature_flags_and_object_config() {
        let js = r#"
            const config = {
                apiVersion: "v2",
                featureFlag: true,
                maxUploadMb: 25,
                title: "not a config key",
            };
        "#;
        let found = run(js);
        let values: Vec<&str> = found.iter().map(|f| f.value.as_str()).collect();
        assert!(values.contains(&"apiVersion = v2"));
        assert!(values.contains(&"featureFlag = true"));
        assert!(!values.iter().any(|v| v.starts_with("title")));
        assert!(found.iter().all(|f| f.kind == FindingKind::Config));
    }

    #[test]
    fn extracts_upper_snake_constants() {
        let js = r#"const DEBUG_MODE = true; const UNRELATED = "fine";"#;
        let found = run(js);
        assert!(found.iter().any(|f| f.value == "DEBUG_MODE = true"));
        assert!(found.iter().any(|f| f.value == "UNRELATED = fine"));
    }

    #[test]
    fn dedups_within_file() {
        let js = r"const a = {debug: true}; const b = {debug: true};";
        assert_eq!(run(js).len(), 1);
    }

    #[test]
    fn unparseable_returns_empty_not_error() {
        assert_eq!(run("function (() {{{ <<< "), Vec::new());
    }
}
