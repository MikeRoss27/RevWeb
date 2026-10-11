//! Recover bounded original sources from inline or same-scope source maps.
use super::{
    discovery::{resolve_url, strip_fragment},
    request::fetch_with_retry,
};
use crate::{PipelineEvent, PipelineItem};
use base64::Engine;
use regex::Regex;
use serde::Deserialize;
use tokio::sync::{broadcast, mpsc};
use webrev_core::Scope;
use webrev_extract::ContentKind;

/// The fields of a JS source map we care about for recon.
#[derive(Debug, Default, Deserialize)]
struct SourceMap {
    #[serde(default)]
    sources: Vec<String>,
    #[serde(rename = "sourcesContent", default)]
    sources_content: Vec<Option<String>>,
}

/// Last `sourceMappingURL=` reference in a file (the authoritative one).
pub(super) fn sourcemap_ref(re: &Regex, body: &str) -> Option<String> {
    re.captures_iter(body)
        .last()
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_owned())
}

/// Resolve a `sourceMappingURL` to raw map JSON: decode a `data:` URI or fetch
/// a same-scope `.map` file.
pub(super) async fn fetch_sourcemap_json(
    client: &reqwest::Client,
    base: &str,
    map_ref: &str,
    scope: &Scope,
) -> Option<String> {
    if let Some(rest) = map_ref.strip_prefix("data:") {
        let (meta, data) = rest.split_once(',')?;
        return if meta.contains("base64") {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data)
                .ok()?;
            String::from_utf8(bytes).ok()
        } else {
            Some(data.to_owned())
        };
    }
    let abs = strip_fragment(&resolve_url(base, map_ref)?);
    if !scope.allows(&abs) {
        return None;
    }
    fetch_with_retry(client, &abs)
        .await
        .ok()
        .map(|(_, _, body, _)| body)
}

/// Fetch + parse a source map and emit each recovered original source as JS
/// content (bounded by `budget`). Returns how many sources were emitted.
#[allow(clippy::too_many_arguments)] // a focused helper; grouping would add noise
pub(super) async fn process_sourcemap(
    client: &reqwest::Client,
    out: &mpsc::Sender<PipelineItem>,
    base: &str,
    map_ref: &str,
    scope: &Scope,
    budget: usize,
    events: &broadcast::Sender<PipelineEvent>,
    stage: &str,
) -> usize {
    if budget == 0 {
        return 0;
    }
    let Some(json) = fetch_sourcemap_json(client, base, map_ref, scope).await else {
        return 0;
    };
    let map: SourceMap = match serde_json::from_str(&json) {
        Ok(map) => map,
        Err(e) => {
            let _ = events.send(PipelineEvent::Error {
                stage: stage.to_owned(),
                message: format!("sourcemap parse ({base}): {e}"),
            });
            return 0;
        }
    };

    let mut emitted = 0usize;
    for (i, content) in map.sources_content.into_iter().enumerate() {
        if emitted >= budget {
            break;
        }
        let Some(code) = content else { continue };
        if code.trim().is_empty() {
            continue;
        }
        let name = map
            .sources
            .get(i)
            .cloned()
            .unwrap_or_else(|| format!("{base}#source{i}"));
        if out
            .send(PipelineItem::Content {
                url: Some(name),
                kind: ContentKind::JavaScript,
                body: code,
                headers: Vec::new(),
            })
            .await
            .is_err()
        {
            break;
        }
        emitted += 1;
    }
    emitted
}
