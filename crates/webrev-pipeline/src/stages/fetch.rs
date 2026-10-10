// crates/webrev-pipeline/src/stages/fetch.rs
//! The network source stage: fetches mission seeds (and, one level deep, the
//! same-origin scripts they reference), emitting each body as `Content`.
//!
//! This is the only stage that performs network I/O. It is a *source* stage: it
//! derives work from `ctx.mission.seeds` and ignores its input channel.

use crate::events::PipelineEvent;
use crate::stage::{PipelineItem, Stage, StageContext};
use crate::stages::sleep_with_jitter;
use async_trait::async_trait;
use base64::Engine;
use futures::future::join_all;
use regex::Regex;
use serde::Deserialize;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::redirect::Policy;
use std::collections::{BTreeSet, VecDeque};
use std::path::Path;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use webrev_core::{OpsecConfig, Result, Scope, WebrevError};
use webrev_extract::ContentKind;

/// Hard per-request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Maximum attempts per URL before giving up.
const MAX_ATTEMPTS: u32 = 3;

/// The fetch stage.
pub struct FetchStage;

impl FetchStage {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for FetchStage {
    fn default() -> Self {
        Self::new()
    }
}

fn build_client(opsec: &OpsecConfig) -> Result<reqwest::Client> {
    let ua = opsec
        .rotation
        .user_agent_for(0)
        .unwrap_or("webrev")
        .to_owned();
    let mut builder = reqwest::Client::builder()
        .user_agent(ua)
        .timeout(REQUEST_TIMEOUT)
        .redirect(Policy::limited(5));
    if let Some(proxy) = &opsec.egress.proxy {
        let p = reqwest::Proxy::all(proxy)
            .map_err(|e| WebrevError::Config(format!("invalid proxy {proxy:?}: {e}")))?;
        builder = builder.proxy(p);
    }
    // Authenticated context: attach cookies/headers/bearer to every request.
    let mut headers = HeaderMap::new();
    for (name, value) in opsec.auth.effective_headers() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(name, value);
        }
    }
    if !headers.is_empty() {
        builder = builder.default_headers(headers);
    }
    builder
        .build()
        .map_err(|e| WebrevError::Fetch(format!("building http client: {e}")))
}

fn detect_kind(url: &str, content_type: &str) -> ContentKind {
    let ct = content_type.to_ascii_lowercase();
    // Strip any query/fragment before inspecting the file extension.
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let is_js_ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("js") || e.eq_ignore_ascii_case("mjs"));
    if ct.contains("javascript") || ct.contains("ecmascript") || is_js_ext {
        ContentKind::JavaScript
    } else {
        ContentKind::Html
    }
}

/// Resolve `href` against `base`, handling absolute, protocol-relative,
/// root-relative, and document-relative forms without a URL-parsing crate.
fn resolve_url(base: &str, href: &str) -> Option<String> {
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
fn capture_group1(re: &Regex, html: &str) -> Vec<String> {
    re.captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .collect()
}

/// Drop any `#fragment` so the same page is not re-queued under two URLs.
fn strip_fragment(url: &str) -> String {
    url.split('#').next().unwrap_or(url).to_owned()
}

/// The fields of a JS source map we care about for recon.
#[derive(Debug, Default, Deserialize)]
struct SourceMap {
    #[serde(default)]
    sources: Vec<String>,
    #[serde(rename = "sourcesContent", default)]
    sources_content: Vec<Option<String>>,
}

/// Last `sourceMappingURL=` reference in a file (the authoritative one).
fn sourcemap_ref(re: &Regex, body: &str) -> Option<String> {
    re.captures_iter(body)
        .last()
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_owned())
}

/// Resolve a `sourceMappingURL` to raw map JSON: decode a `data:` URI or fetch
/// a same-scope `.map` file.
async fn fetch_sourcemap_json(
    client: &reqwest::Client,
    base: &str,
    map_ref: &str,
    scope: &Scope,
) -> Option<String> {
    if let Some(rest) = map_ref.strip_prefix("data:") {
        let (meta, data) = rest.split_once(',')?;
        return if meta.contains("base64") {
            let bytes = base64::engine::general_purpose::STANDARD.decode(data).ok()?;
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
        .map(|(_, _, body)| body)
}

/// Fetch + parse a source map and emit each recovered original source as JS
/// content (bounded by `budget`). Returns how many sources were emitted.
#[allow(clippy::too_many_arguments)] // a focused helper; grouping would add noise
async fn process_sourcemap(
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

/// Resolve, normalize, scope-filter, and enqueue a batch of hrefs at `depth`.
fn enqueue(
    queue: &mut VecDeque<(String, usize)>,
    visited: &BTreeSet<String>,
    scope: &Scope,
    base: &str,
    hrefs: &[String],
    depth: usize,
) {
    for href in hrefs {
        let Some(abs) = resolve_url(base, href).map(|u| strip_fragment(&u)) else {
            continue;
        };
        if scope.allows(&abs) && !visited.contains(&abs) {
            queue.push_back((abs, depth));
        }
    }
}

/// Returns `(content_type, response_headers, body)`.
async fn fetch_with_retry(
    client: &reqwest::Client,
    url: &str,
) -> Result<(String, Vec<(String, String)>, String)> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let outcome = client.get(url).send().await;
        match outcome {
            Ok(resp) => {
                let status = resp.status();
                let content_type = resp
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value.to_str().ok().map(|v| (name.as_str().to_owned(), v.to_owned()))
                    })
                    .collect();
                match resp.text().await {
                    Ok(body) => {
                        if status.is_server_error() && attempt < MAX_ATTEMPTS {
                            tokio::time::sleep(Duration::from_millis(200 * u64::from(attempt)))
                                .await;
                            continue;
                        }
                        return Ok((content_type, headers, body));
                    }
                    Err(e) if attempt < MAX_ATTEMPTS => {
                        tokio::time::sleep(Duration::from_millis(200 * u64::from(attempt))).await;
                        let _ = e;
                    }
                    Err(e) => return Err(WebrevError::Fetch(format!("reading {url}: {e}"))),
                }
            }
            Err(e) if attempt < MAX_ATTEMPTS => {
                tokio::time::sleep(Duration::from_millis(200 * u64::from(attempt))).await;
                let _ = e;
            }
            Err(e) => return Err(WebrevError::Fetch(format!("requesting {url}: {e}"))),
        }
    }
}

#[async_trait]
impl Stage for FetchStage {
    fn name(&self) -> &'static str {
        "fetch"
    }

    // The crawl driver (wave assembly → concurrent fetch → per-result
    // discovery/enqueue/sourcemap) reads best as one sequential method.
    #[allow(clippy::too_many_lines)]
    async fn run(
        &self,
        ctx: StageContext,
        _input: mpsc::Receiver<PipelineItem>,
        out: mpsc::Sender<PipelineItem>,
        events: broadcast::Sender<PipelineEvent>,
    ) -> Result<()> {
        let _ = events.send(PipelineEvent::StageStarted {
            stage: self.name().to_owned(),
        });

        // Fail-closed egress: refuse to send traffic directly when the policy
        // requires a proxy but none is set.
        if ctx.opsec.egress.proxy.is_none() && !ctx.opsec.egress.allow_direct {
            return Err(WebrevError::Config(
                "egress policy forbids direct connections but no proxy is configured".into(),
            ));
        }

        let client = build_client(&ctx.opsec)?;
        // Constant patterns; covered by the `resolves_and_discovers` unit test.
        let script_re = Regex::new(r#"(?i)<script[^>]+src\s*=\s*["']([^"']+)["']"#)
            .expect("constant script-src pattern must compile");
        let link_re = Regex::new(r#"(?i)<a[^>]+href\s*=\s*["']([^"']+)["']"#)
            .expect("constant link pattern must compile");
        let sourcemap_re = Regex::new(r"(?im)//[#@]\s*sourceMappingURL=(\S+)")
            .expect("constant sourcemap pattern must compile");

        // Bounded breadth-first crawl. Scripts are enqueued as JS resources
        // (they never spawn further link-following); HTML links are followed up
        // to `max_depth`, and the whole crawl stops at `max_pages`.
        let max_pages = ctx.opsec.max_pages;
        let max_depth = ctx.opsec.max_depth;
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut queue: VecDeque<(String, usize)> = ctx
            .mission
            .seeds
            .iter()
            .map(|s| (strip_fragment(s), 0usize))
            .collect();
        let max_concurrency = ctx.opsec.max_concurrency.max(1);
        let mut processed = 0usize;

        'crawl: while processed < max_pages {
            if ctx.cancel.is_cancelled() {
                break;
            }

            // Assemble the next wave of up to `max_concurrency` fresh, in-scope
            // URLs (dedup + scope filtering happen here, at dequeue time).
            let mut wave: Vec<(String, usize)> = Vec::new();
            while wave.len() < max_concurrency {
                let Some((url, depth)) = queue.pop_front() else {
                    break;
                };
                if !visited.insert(url.clone()) {
                    continue;
                }
                if !ctx.mission.scope.allows(&url) {
                    let _ = events.send(PipelineEvent::Error {
                        stage: self.name().to_owned(),
                        message: format!("out of scope: {url}"),
                    });
                    continue;
                }
                wave.push((url, depth));
            }
            if wave.is_empty() {
                break;
            }

            // Fetch the whole wave concurrently.
            let client_ref = &client;
            let results = join_all(wave.into_iter().map(|(url, depth)| async move {
                let outcome = fetch_with_retry(client_ref, &url).await;
                (url, depth, outcome)
            }))
            .await;

            // Process results sequentially so channel order and the budget stay
            // deterministic.
            for (url, depth, outcome) in results {
                if processed >= max_pages {
                    break 'crawl;
                }
                match outcome {
                    Ok((content_type, resp_headers, body)) => {
                        let kind = detect_kind(&url, &content_type);
                        // Discover references before `body` is moved downstream.
                        let (scripts, links, smap) = if kind == ContentKind::Html {
                            let links = if depth < max_depth {
                                capture_group1(&link_re, &body)
                            } else {
                                Vec::new()
                            };
                            (capture_group1(&script_re, &body), links, None)
                        } else {
                            (Vec::new(), Vec::new(), sourcemap_ref(&sourcemap_re, &body))
                        };

                        if out
                            .send(PipelineItem::Content {
                                url: Some(url.clone()),
                                kind,
                                body,
                                headers: resp_headers,
                            })
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                        processed += 1;

                        enqueue(&mut queue, &visited, &ctx.mission.scope, &url, &scripts, depth);
                        enqueue(&mut queue, &visited, &ctx.mission.scope, &url, &links, depth + 1);

                        if let Some(map_ref) = smap {
                            processed += process_sourcemap(
                                &client,
                                &out,
                                &url,
                                &map_ref,
                                &ctx.mission.scope,
                                max_pages.saturating_sub(processed),
                                &events,
                                self.name(),
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        let _ = events.send(PipelineEvent::Error {
                            stage: self.name().to_owned(),
                            message: e.to_string(),
                        });
                    }
                }
            }

            let _ = events.send(PipelineEvent::Progress {
                stage: self.name().to_owned(),
                processed,
            });
            sleep_with_jitter(&ctx.opsec).await;
        }

        let _ = events.send(PipelineEvent::StageCompleted {
            stage: self.name().to_owned(),
            emitted: processed,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_and_discovers() {
        let re = Regex::new(r#"(?i)<script[^>]+src\s*=\s*["']([^"']+)["']"#).unwrap();
        let html = r#"<script src="/a.js"></script><script src="b/c.js"></script>"#;
        let srcs = capture_group1(&re, html);
        assert_eq!(srcs, vec!["/a.js", "b/c.js"]);

        let base = "https://ex.com/app/index.html";
        assert_eq!(
            resolve_url(base, "/a.js").as_deref(),
            Some("https://ex.com/a.js")
        );
        assert_eq!(
            resolve_url(base, "b/c.js").as_deref(),
            Some("https://ex.com/app/b/c.js")
        );
        assert_eq!(
            resolve_url(base, "//cdn.net/x.js").as_deref(),
            Some("https://cdn.net/x.js")
        );
        assert_eq!(
            resolve_url(base, "https://y.com/z.js").as_deref(),
            Some("https://y.com/z.js")
        );
        assert_eq!(resolve_url(base, "#frag"), None);
    }

    #[test]
    fn enqueue_respects_scope_and_visited() {
        let scope = Scope::new(vec!["ex.com".into()], vec![]);
        let mut queue = VecDeque::new();
        let mut visited = BTreeSet::new();
        visited.insert("https://ex.com/seen".to_owned());
        let hrefs = vec![
            "/new".to_owned(),
            "/seen".to_owned(),             // already visited
            "https://evil.test/x".to_owned(), // out of scope
            "mailto:a@b".to_owned(),        // filtered by resolve_url
        ];
        enqueue(&mut queue, &visited, &scope, "https://ex.com/base", &hrefs, 1);
        let urls: Vec<String> = queue.into_iter().map(|(u, _)| u).collect();
        assert_eq!(urls, vec!["https://ex.com/new"]);
    }

    #[test]
    fn kind_detection() {
        assert_eq!(detect_kind("x.js", ""), ContentKind::JavaScript);
        assert_eq!(
            detect_kind("x", "application/javascript"),
            ContentKind::JavaScript
        );
        assert_eq!(detect_kind("x", "text/html"), ContentKind::Html);
    }
}
