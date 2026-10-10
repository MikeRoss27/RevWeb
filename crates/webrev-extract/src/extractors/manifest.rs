// crates/webrev-extract/src/extractors/manifest.rs
//! Parses JSON documents discovered during the crawl: W3C web app manifests
//! and build-tool asset manifests (webpack `asset-manifest.json`, Vite
//! `manifest.json`). This is the one extractor that reads `ContentKind::Json`
//! — everything else here operates on HTML or JavaScript text.
//!
//! An asset manifest lists every emitted chunk file, including ones no page
//! ever links to directly (a lazy-loaded admin panel, a feature-flagged
//! route). Surfacing those paths recovers surface area a pure HTML/script
//! crawl would miss entirely.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use serde_json::Value;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// JSON manifest extractor.
pub struct ManifestExtractor;

impl ManifestExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for ManifestExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Web app manifest keys worth surfacing as configuration: `start_url` and
/// `scope` can point at an app entry point distinct from the crawled page.
const MANIFEST_CONFIG_KEYS: &[&str] = &["start_url", "scope", "id"];

/// Whether a JSON string value looks like a bundled asset/chunk path rather
/// than ordinary text content.
fn looks_like_asset_path(s: &str) -> bool {
    if s.is_empty() || s.contains(char::is_whitespace) {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    lower.starts_with('/')
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || [".js", ".mjs", ".css"].iter().any(|ext| lower.ends_with(ext))
}

/// Recursively collect every string value that looks like an asset path.
/// Walking generically (rather than matching webpack's or Vite's specific
/// manifest shape) means both are covered, along with any similar format.
fn collect_asset_strings(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::String(s) => {
            if looks_like_asset_path(s) {
                out.insert(s.clone());
            }
        }
        Value::Array(items) => items.iter().for_each(|v| collect_asset_strings(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect_asset_strings(v, out)),
        _ => {}
    }
}

/// A W3C web app manifest has `icons` plus a `name`/`short_name` — distinct
/// enough from a bundler asset manifest to branch the extraction strategy on.
fn is_web_app_manifest(value: &Value) -> bool {
    let Value::Object(map) = value else {
        return false;
    };
    map.contains_key("icons") && (map.contains_key("name") || map.contains_key("short_name"))
}

impl Extractor for ManifestExtractor {
    fn name(&self) -> &'static str {
        "manifest"
    }

    fn priority(&self) -> u8 {
        45
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        input.kind == ContentKind::Json
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let Ok(value) = serde_json::from_str::<Value>(&input.body) else {
            return Vec::new();
        };

        if is_web_app_manifest(&value) {
            let Value::Object(map) = &value else {
                unreachable!("checked by is_web_app_manifest")
            };
            return MANIFEST_CONFIG_KEYS
                .iter()
                .filter_map(|key| map.get(*key).and_then(Value::as_str).map(|s| (*key, s)))
                .map(|(key, s)| {
                    Finding::new(
                        input.session_id,
                        FindingKind::Config,
                        None,
                        format!("{key} = {s}"),
                        Confidence::High,
                        Provenance::new(Source::Manifest, input.url.clone()),
                    )
                })
                .collect();
        }

        // Otherwise: a build-tool asset manifest. Surface every referenced
        // chunk/asset path as a script finding.
        let mut assets = BTreeSet::new();
        collect_asset_strings(&value, &mut assets);
        assets
            .into_iter()
            .map(|path| {
                Finding::new(
                    input.session_id,
                    FindingKind::Script,
                    Some(path.clone()),
                    path,
                    Confidence::Medium,
                    Provenance::new(Source::Manifest, input.url.clone()),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::SessionId;

    fn run(json: &str) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/manifest.json".into()),
            ContentKind::Json,
            json,
        );
        ManifestExtractor::new().extract(&input)
    }

    #[test]
    fn extracts_web_app_manifest_config() {
        let json = r#"{
            "name": "App",
            "short_name": "App",
            "start_url": "/dashboard?src=pwa",
            "scope": "/app/",
            "icons": [{"src": "/icon.png", "sizes": "192x192"}]
        }"#;
        let found = run(json);
        assert!(found
            .iter()
            .any(|f| f.value == "start_url = /dashboard?src=pwa"));
        assert!(found.iter().any(|f| f.value == "scope = /app/"));
        assert!(found.iter().all(|f| f.kind == FindingKind::Config));
    }

    #[test]
    fn extracts_vite_style_chunk_graph() {
        // Vite's `manifest.json`: entry -> { file, imports: [...], css: [...] }.
        let json = r#"{
            "src/main.tsx": {
                "file": "assets/main-ab12cd34.js",
                "imports": ["_AdminPanel-ef56.js"],
                "css": ["assets/main-9f8e.css"]
            },
            "_AdminPanel-ef56.js": {
                "file": "assets/AdminPanel-ef56.js"
            }
        }"#;
        let found = run(json);
        let values: Vec<&str> = found.iter().map(|f| f.value.as_str()).collect();
        assert!(values.contains(&"assets/main-ab12cd34.js"));
        assert!(values.contains(&"assets/AdminPanel-ef56.js"));
        assert!(values.contains(&"assets/main-9f8e.css"));
        assert!(found.iter().all(|f| f.kind == FindingKind::Script));
    }

    #[test]
    fn extracts_webpack_style_flat_manifest() {
        let json = r#"{"main.js": "/static/js/main.a1b2c3d4.js", "main.css": "/static/css/main.e5f6.css"}"#;
        let found = run(json);
        let values: Vec<&str> = found.iter().map(|f| f.value.as_str()).collect();
        assert!(values.contains(&"/static/js/main.a1b2c3d4.js"));
        assert!(values.contains(&"/static/css/main.e5f6.css"));
    }

    #[test]
    fn invalid_json_returns_empty_not_error() {
        assert!(run("not json {{{").is_empty());
    }
}
