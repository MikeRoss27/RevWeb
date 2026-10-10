// crates/webrev-browser/src/dynamic.rs
//! The dynamic-analysis entry point: drive a page for a bounded dwell time and
//! return the endpoints observed via injected hooks and CDP network capture.

use crate::har::{Har, HarEntry};
use crate::hooks::{self, HookRecord};
use crate::pool::BrowserPool;
use crate::profile::BrowserProfile;
use chromiumoxide::cdp::browser_protocol::emulation::{
    SetGeolocationOverrideParams, SetTimezoneOverrideParams,
};
use chromiumoxide::cdp::browser_protocol::network::{
    EnableParams, EventRequestWillBeSent, EventWebSocketCreated, Headers, SetExtraHttpHeadersParams,
};
use futures::StreamExt;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use webrev_core::{Confidence, Endpoint, Finding, Method, Result, Sanitizer, SessionId, Source};

fn browser_err<E: Display>(e: E) -> webrev_core::WebrevError {
    webrev_core::WebrevError::Browser(e.to_string())
}

/// Interval between active-interaction passes.
const INTERACTION_STEP: Duration = Duration::from_millis(1500);

/// Injected each pass to exercise single-page apps: scroll to trigger lazy
/// loading, then click buttons (never links, to avoid navigating away) so
/// their XHR/fetch calls are captured by the hooks.
const ACTIVE_SCRIPT: &str = r"(() => {
  try { window.scrollTo(0, document.body.scrollHeight); } catch (e) {}
  const els = Array.from(document.querySelectorAll('button, [role=button]')).slice(0, 30);
  for (const el of els) { try { el.click(); } catch (e) {} }
})();";

/// Load `url` under `profile`, let it run for `duration` (or until `cancel`),
/// then return the endpoints the page actually called.
///
/// Findings from the JS hooks are rated [`Confidence::High`] (the page invoked
/// them); those seen only in CDP network traffic are [`Confidence::Medium`].
/// All URLs and headers are sanitized before leaving this function.
pub async fn run_dynamic(
    profile: &BrowserProfile,
    url: &str,
    duration: Duration,
    session: SessionId,
    cancel: CancellationToken,
) -> Result<Vec<Finding>> {
    let pool = BrowserPool::new(4);
    let browser = pool.acquire(profile).await?;
    let page = browser.new_page("about:blank").await?;

    page.evaluate_on_new_document(profile.init_script())
        .await
        .map_err(browser_err)?;
    page.evaluate_on_new_document(hooks::INSTALL_HOOKS.to_owned())
        .await
        .map_err(browser_err)?;

    page.execute(SetTimezoneOverrideParams::new(profile.timezone.clone()))
        .await
        .map_err(browser_err)?;
    if let Some((latitude, longitude)) = profile.geolocation {
        let geo = SetGeolocationOverrideParams::builder()
            .latitude(latitude)
            .longitude(longitude)
            .accuracy(10.0)
            .build();
        page.execute(geo).await.map_err(browser_err)?;
    }
    page.execute(EnableParams::default())
        .await
        .map_err(browser_err)?;

    // Authenticated context: apply cookies/headers/bearer to every request.
    if !profile.auth.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, value) in profile.auth.effective_headers() {
            map.insert(name, serde_json::Value::String(value));
        }
        let headers = Headers::new(serde_json::Value::Object(map));
        page.execute(SetExtraHttpHeadersParams::new(headers))
            .await
            .map_err(browser_err)?;
    }

    // Capture CDP network requests in the background.
    let har = Arc::new(Mutex::new(Har::new()));
    let mut requests = page
        .event_listener::<EventRequestWillBeSent>()
        .await
        .map_err(browser_err)?;
    let har_capture = Arc::clone(&har);
    let collector = tokio::spawn(async move {
        while let Some(event) = requests.next().await {
            let req = &event.request;
            let headers = serde_json::to_value(&req.headers)
                .ok()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            if let Ok(mut har) = har_capture.lock() {
                har.push(HarEntry {
                    method: req.method.clone(),
                    url: req.url.clone(),
                    headers,
                });
            }
        }
    });

    // Capture WebSocket endpoints opened by the page.
    let ws_urls = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut ws_events = page
        .event_listener::<EventWebSocketCreated>()
        .await
        .map_err(browser_err)?;
    let ws_capture = Arc::clone(&ws_urls);
    let ws_collector = tokio::spawn(async move {
        while let Some(event) = ws_events.next().await {
            if let Ok(mut urls) = ws_capture.lock() {
                urls.push(event.url.clone());
            }
        }
    });

    page.goto(url).await.map_err(browser_err)?;

    // Active dwell: repeatedly scroll and click to drive SPA interactions until
    // the deadline or cancellation.
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline && !cancel.is_cancelled() {
        let _ = page.evaluate(ACTIVE_SCRIPT).await;
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(INTERACTION_STEP) => {},
        }
    }

    // Read back the hook log, then stop capturing.
    let raw: String = page
        .evaluate(hooks::COLLECT_HOOKS)
        .await
        .map_err(browser_err)?
        .into_value()
        .map_err(browser_err)?;
    collector.abort();
    ws_collector.abort();

    let sanitizer = Sanitizer::with_default_patterns();
    let mut har = match Arc::try_unwrap(har) {
        Ok(lock) => lock.into_inner().unwrap_or_default(),
        Err(shared) => shared.lock().map(|g| g.clone()).unwrap_or_default(),
    };
    har.sanitize(&sanitizer);

    // Merge hook records (high confidence) with HAR entries (medium),
    // deduplicating on the sanitized URL.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut findings: Vec<Finding> = Vec::new();

    if let Ok(records) = serde_json::from_str::<Vec<HookRecord>>(&raw) {
        for record in records {
            let scrubbed = sanitizer.scrub(&record.url);
            if seen.insert(scrubbed.clone()) {
                let endpoint = Endpoint::new(scrubbed, Method::parse(&record.method), Source::Browser);
                findings.push(Finding::from_endpoint(session, &endpoint, Confidence::High));
            }
        }
    }
    for endpoint in har.endpoints() {
        if seen.insert(endpoint.url.clone()) {
            findings.push(Finding::from_endpoint(session, &endpoint, Confidence::Medium));
        }
    }

    // WebSocket endpoints the page opened.
    let websockets = ws_urls.lock().map(|v| v.clone()).unwrap_or_default();
    for url in websockets {
        let scrubbed = sanitizer.scrub(&url);
        if seen.insert(scrubbed.clone()) {
            let endpoint = Endpoint::new(scrubbed, Method::Get, Source::Browser);
            findings.push(Finding::from_endpoint(session, &endpoint, Confidence::High));
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::OpsecConfig;

    #[tokio::test]
    #[ignore = "requires a local Chromium/Chrome installation"]
    async fn dynamic_run_smoke() {
        let profile = BrowserProfile::from_opsec(&OpsecConfig::default()).expect("profile");
        let findings = run_dynamic(
            &profile,
            "https://example.com/",
            Duration::from_secs(3),
            SessionId::new(),
            CancellationToken::new(),
        )
        .await
        .expect("dynamic run");
        // example.com makes no XHR/fetch, so we only assert the call succeeds.
        let _ = findings;
    }
}
