// crates/webrev-pipeline/src/stages/fetch/mod.rs
//! The network source stage: fetches mission seeds (and, one level deep, the
//! same-origin scripts they reference), emitting each body as `Content`.
//!
//! This is the only stage that performs network I/O. It is a *source* stage: it
//! derives work from `ctx.mission.seeds` and ignores its input channel.

mod discovery;
mod request;
mod scheduler;
mod sourcemaps;
#[cfg(test)]
mod tests;

use crate::{
    events::PipelineEvent,
    stage::{PipelineItem, Stage, StageContext},
    stages::sleep_with_jitter,
};
use async_trait::async_trait;
use discovery::{capture_group1, detect_kind, enqueue, strip_fragment};
use futures::future::join_all;
use regex::Regex;
use request::{build_client, fetch_with_retry};
use scheduler::{Frontier, ResourceHint};
use sourcemaps::{process_sourcemap, sourcemap_ref};
use std::collections::BTreeSet;
use tokio::sync::{broadcast, mpsc};
use webrev_core::{Result, WebrevError};
use webrev_extract::ContentKind;

/// The network source stage.
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

        let client = build_client(&ctx.opsec, &ctx.mission.scope)?;
        // Constant patterns; covered by the `resolves_and_discovers` unit test.
        let script_re = Regex::new(r#"(?i)<script[^>]+src\s*=\s*["']([^"']+)["']"#)
            .expect("constant script-src pattern must compile");
        let link_re = Regex::new(r#"(?i)<a[^>]+href\s*=\s*["']([^"']+)["']"#)
            .expect("constant link pattern must compile");
        let sourcemap_re = Regex::new(r"(?im)//[#@]\s*sourceMappingURL=(\S+)")
            .expect("constant sourcemap pattern must compile");
        // Web app manifest (`<link rel="manifest" href="…">`) and service
        // worker registration (`navigator.serviceWorker.register("…")`):
        // neither is a `<script src>` or `<a href>`, so without these the
        // crawler never follows them, missing the SW's own cached-route list
        // and the manifest's `start_url`/`scope`.
        let manifest_re = Regex::new(
            r#"(?i)<link[^>]+rel\s*=\s*["']manifest["'][^>]*href\s*=\s*["']([^"']+)["']"#,
        )
        .expect("constant manifest-link pattern must compile");
        let sw_register_re =
            Regex::new(r#"(?i)serviceWorker\s*\.\s*register\s*\(\s*["']([^"']+)["']"#)
                .expect("constant service-worker pattern must compile");

        // Bounded breadth-first crawl. Scripts are enqueued as JS resources
        // (they never spawn further link-following); HTML links are followed up
        // to `max_depth`, and the whole crawl stops at `max_pages`.
        let max_pages = ctx.opsec.max_pages;
        let max_depth = ctx.opsec.max_depth;
        let max_body_bytes = ctx.opsec.max_body_bytes;
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut frontier = Frontier::seed(
            ctx.opsec.crawler_strategy,
            ctx.mission.seeds.iter().map(|s| strip_fragment(s)),
        );
        // Discovery sequence counter, shared across the whole crawl: only
        // `BestFirst` reads it (oldest-discovered-first tie-break), `Bfs`
        // ignores it entirely.
        let mut discover_seq: u64 = ctx.mission.seeds.len() as u64;
        let max_concurrency = ctx.opsec.max_concurrency.max(1);
        let mut processed = 0usize;
        // Consecutive waves that drew a 429/503. Halves the next wave's
        // concurrency per strike (up to 3x) and stretches the inter-wave
        // delay (see `sleep_with_jitter`), so a WAF/rate limiter slows the
        // crawl down instead of getting hammered at a fixed cadence.
        let mut backoff_strikes: u32 = 0;

        'crawl: while processed < max_pages {
            if ctx.cancel.is_cancelled() {
                break;
            }

            // Assemble the next wave of up to `effective_concurrency` fresh,
            // in-scope URLs (dedup + scope filtering happen here, at dequeue
            // time).
            let effective_concurrency = (max_concurrency >> backoff_strikes.min(3))
                .max(1)
                .min(max_pages - processed);
            let mut wave: Vec<(String, usize)> = Vec::new();
            while wave.len() < effective_concurrency {
                let Some(candidate) = frontier.pop() else {
                    break;
                };
                let (url, depth) = (candidate.url, candidate.depth);
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
                let outcome = fetch_with_retry(client_ref, &url, max_body_bytes).await;
                (url, depth, outcome)
            }))
            .await;

            // Process results sequentially so channel order and the budget stay
            // deterministic.
            let mut wave_rate_limited = false;
            for (url, depth, outcome) in results {
                if processed >= max_pages {
                    break 'crawl;
                }
                match outcome {
                    Ok((content_type, resp_headers, body, bytes, rate_limited)) => {
                        wave_rate_limited |= rate_limited;
                        let kind = detect_kind(&url, &content_type);
                        // Discover references before `body` is moved downstream.
                        // Wasm is binary: none of the HTML/script/sourcemap
                        // regexes apply to it, so skip discovery entirely.
                        let (scripts, links, smap) = if kind == ContentKind::Wasm {
                            (Vec::new(), Vec::new(), None)
                        } else if kind == ContentKind::Html {
                            let links = if depth < max_depth {
                                capture_group1(&link_re, &body)
                            } else {
                                Vec::new()
                            };
                            let mut scripts = capture_group1(&script_re, &body);
                            scripts.extend(capture_group1(&manifest_re, &body));
                            scripts.extend(capture_group1(&sw_register_re, &body));
                            (scripts, links, None)
                        } else {
                            (Vec::new(), Vec::new(), sourcemap_ref(&sourcemap_re, &body))
                        };

                        if out
                            .send(PipelineItem::Content {
                                url: Some(url.clone()),
                                kind,
                                body,
                                headers: resp_headers,
                                bytes,
                            })
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                        processed += 1;

                        enqueue(
                            &mut frontier,
                            &mut discover_seq,
                            &visited,
                            &ctx.mission.scope,
                            &url,
                            &scripts,
                            depth,
                            ResourceHint::Script,
                        );
                        enqueue(
                            &mut frontier,
                            &mut discover_seq,
                            &visited,
                            &ctx.mission.scope,
                            &url,
                            &links,
                            depth + 1,
                            ResourceHint::Link,
                        );

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
                                max_body_bytes,
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

            if wave_rate_limited {
                backoff_strikes = (backoff_strikes + 1).min(5);
                let _ = events.send(PipelineEvent::Error {
                    stage: self.name().to_owned(),
                    message: format!(
                        "rate-limited (429/503); backing off (strike {backoff_strikes})"
                    ),
                });
            } else {
                backoff_strikes = backoff_strikes.saturating_sub(1);
            }

            let _ = events.send(PipelineEvent::Progress {
                stage: self.name().to_owned(),
                processed,
            });
            sleep_with_jitter(&ctx.opsec, backoff_strikes).await;
        }

        let _ = events.send(PipelineEvent::StageCompleted {
            stage: self.name().to_owned(),
            emitted: processed,
        });
        Ok(())
    }
}
