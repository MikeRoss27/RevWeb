//! Resolve and enqueue in-scope resources; classify fetched content.
use super::scheduler::{Candidate, Frontier, ResourceHint};
use regex::Regex;
use std::{collections::BTreeSet, path::Path};
use webrev_core::Scope;
use webrev_extract::ContentKind;

pub(super) fn detect_kind(url: &str, content_type: &str) -> ContentKind {
    let ct = content_type.to_ascii_lowercase();
    // Strip any query/fragment before inspecting the file extension.
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    let is_js_ext = ext.eq_ignore_ascii_case("js") || ext.eq_ignore_ascii_case("mjs");
    let is_json_ext = ext.eq_ignore_ascii_case("json") || ext.eq_ignore_ascii_case("webmanifest");
    let is_wasm_ext = ext.eq_ignore_ascii_case("wasm");
    if ct.contains("application/wasm") || is_wasm_ext {
        ContentKind::Wasm
    } else if ct.contains("javascript") || ct.contains("ecmascript") || is_js_ext {
        ContentKind::JavaScript
    } else if ct.contains("json") || is_json_ext {
        ContentKind::Json
    } else {
        ContentKind::Html
    }
}

/// Resolve `href` against `base`, handling absolute, protocol-relative,
/// root-relative, and document-relative forms without a URL-parsing crate.
pub(super) fn resolve_url(base: &str, href: &str) -> Option<String> {
    let href = href.trim();
    if href.is_empty()
        || href.starts_with('#')
        || href.starts_with("data:")
        || href.starts_with("mailto:")
        || href.starts_with("tel:")
        || href.starts_with("javascript:")
    {
        return None;
    }
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_owned());
    }
    let (scheme, after_scheme) = base.split_once("://")?;
    if let Some(rest) = href.strip_prefix("//") {
        return Some(format!("{scheme}://{rest}"));
    }
    let host = after_scheme.split(['/', '?', '#']).next()?;
    if let Some(path) = href.strip_prefix('/') {
        return Some(format!("{scheme}://{host}/{path}"));
    }
    // Document-relative: replace everything after the base's last '/'.
    let dir = base.rsplit_once('/').map_or(base, |(dir, _)| dir);
    Some(format!("{dir}/{href}"))
}

/// Collect the first capture group of every match (used for `<script src>` and
/// `<a href>` discovery).
pub(super) fn capture_group1(re: &Regex, html: &str) -> Vec<String> {
    re.captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .collect()
}

/// Drop any `#fragment` so the same page is not re-queued under two URLs.
pub(super) fn strip_fragment(url: &str) -> String {
    url.split('#').next().unwrap_or(url).to_owned()
}

/// Resolve, normalize, scope-filter, and enqueue a batch of hrefs at `depth`.
///
/// `seq` is a monotonically increasing discovery counter the caller owns
/// across the whole crawl; it only affects `BestFirst` tie-breaking (oldest
/// discovery wins) and is ignored by `Bfs`.
#[allow(clippy::too_many_arguments)]
pub(super) fn enqueue(
    frontier: &mut Frontier,
    seq: &mut u64,
    visited: &BTreeSet<String>,
    scope: &Scope,
    base: &str,
    hrefs: &[String],
    depth: usize,
    hint: ResourceHint,
) {
    for href in hrefs {
        let Some(abs) = resolve_url(base, href).map(|u| strip_fragment(&u)) else {
            continue;
        };
        if scope.allows(&abs) && !visited.contains(&abs) {
            // A GET to /logout, /delete?id=.. or ?action=unsubscribe can change
            // state. Never crawl such links; they are logged, not fetched.
            if let Some(word) = crate::active::destructive_keyword(&abs) {
                tracing::info!(url = %abs, keyword = word, "crawl link refused: looks state-changing");
                continue;
            }
            frontier.push(Candidate { url: abs, depth }, hint, *seq);
            *seq += 1;
        }
    }
}

#[cfg(test)]
mod destructive_link_tests {
    use super::*;
    use webrev_core::CrawlerStrategy;

    #[test]
    fn crawler_never_enqueues_state_changing_links() {
        let scope = Scope::new(vec!["ex.com".into()], vec![]);
        let mut frontier = Frontier::new(CrawlerStrategy::Bfs);
        let mut seq = 0u64;
        let hrefs = vec![
            "/logout".to_owned(),
            "/items?action=delete&id=2".to_owned(),
            "/unsubscribe".to_owned(),
            "/static/remove.js".to_owned(),
            "/about".to_owned(),
        ];
        enqueue(
            &mut frontier,
            &mut seq,
            &BTreeSet::new(),
            &scope,
            "https://ex.com/",
            &hrefs,
            1,
            ResourceHint::Link,
        );
        let mut urls = Vec::new();
        while let Some(c) = frontier.pop() {
            urls.push(c.url);
        }
        assert_eq!(
            urls,
            ["https://ex.com/static/remove.js", "https://ex.com/about"]
        );
    }
}
