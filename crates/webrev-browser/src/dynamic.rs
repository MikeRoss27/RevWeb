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
    EnableParams, EventRequestWillBeSent, EventWebSocketCreated, EventWebSocketFrameReceived,
    EventWebSocketFrameSent, Headers, RequestId, SetExtraHttpHeadersParams,
};
use futures::StreamExt;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use webrev_core::{
    Confidence, Endpoint, Finding, FindingKind, Method, Provenance, Result, SessionId, Source,
};

fn browser_err<E: Display>(e: E) -> webrev_core::WebrevError {
    webrev_core::WebrevError::Browser(e.to_string())
}

/// Race a CDP call (navigation/evaluation) against [`CDP_CALL_TIMEOUT`] and
/// `cancel`, so a stalled page or an unresponsive CDP command cannot hang
/// `run_dynamic` past the mission's cancellation/dwell budget.
async fn with_timeout<F, T, E>(cancel: &CancellationToken, fut: F) -> Result<T>
where
    F: std::future::Future<Output = std::result::Result<T, E>>,
    E: Display,
{
    tokio::select! {
        res = tokio::time::timeout(CDP_CALL_TIMEOUT, fut) => match res {
            Ok(inner) => inner.map_err(browser_err),
            Err(_) => Err(webrev_core::WebrevError::Browser(
                "CDP call timed out".to_owned(),
            )),
        },
        () = cancel.cancelled() => Err(webrev_core::WebrevError::Browser(
            "cancelled".to_owned(),
        )),
    }
}

/// Upper bound on any single CDP round-trip (navigation or script
/// evaluation). A page that never finishes loading, or whose JS busy-loops,
/// would otherwise hang `run_dynamic` forever since the dwell-deadline is
/// only checked *between* awaits, not during one.
const CDP_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval between active-interaction passes.
const INTERACTION_STEP: Duration = Duration::from_millis(1500);
/// Settle time after a single attributed click, before the next one: long
/// enough for a typical XHR/fetch fired by the click to reach the hook.
const CLICK_SETTLE: Duration = Duration::from_millis(200);
/// Clickable elements attributed per interaction pass. Bounded so a page with
/// hundreds of buttons does not turn the dwell period into a linear scan.
const MAX_CLICKS_PER_PASS: usize = 10;
/// Captured WebSocket frames are bounded in both count and per-frame length:
/// a chatty socket (live chat, telemetry) should not grow the finding set
/// unboundedly or balloon storage with megabyte payloads.
const MAX_WS_FRAMES: usize = 50;
const MAX_WS_PAYLOAD_CHARS: usize = 500;

/// Scroll to the bottom (to trigger lazy loading) and report how many
/// clickable elements are now on the page.
const COUNT_INTERACTIVE_SCRIPT: &str = r"(() => {
  try { window.scrollTo(0, document.body.scrollHeight); } catch (e) {}
  return document.querySelectorAll('button, [role=button]').length;
})();";

/// Click the `index`-th clickable element (never a link, to avoid navigating
/// away), first setting `window.__webrev_trigger` to a short label derived
/// from the element so any network call the click causes is attributed to it
/// (see [`crate::hooks::INSTALL_HOOKS`]). Returns `false` once `index` is out
/// of range.
fn click_attributed_script(index: usize) -> String {
    format!(
        r"(() => {{
  const els = document.querySelectorAll('button, [role=button]');
  const el = els[{index}];
  if (!el) return false;
  const label = (el.id && ('#' + el.id))
    || el.getAttribute('aria-label')
    || (el.textContent || '').trim().slice(0, 40)
    || el.tagName;
  window.__webrev_trigger = String(label);
  try {{ el.click(); }} catch (e) {{}}
  return true;
}})();"
    )
}

/// Clear the active trigger label once its settle window has elapsed.
const CLEAR_TRIGGER_SCRIPT: &str = "window.__webrev_trigger = null;";

/// Load `url` under `profile`, let it run for `duration` (or until `cancel`),
/// then return the endpoints the page actually called.
///
/// Findings from the JS hooks are rated [`Confidence::High`] (the page invoked
/// them); those seen only in CDP network traffic are [`Confidence::Medium`].
/// Captured URLs and payloads retain their original credential values.
pub async fn run_dynamic(
    pool: &BrowserPool,
    profile: &BrowserProfile,
    url: &str,
    duration: Duration,
    session: SessionId,
    cancel: CancellationToken,
) -> Result<Vec<Finding>> {
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

    // Capture WebSocket endpoints opened by the page, keyed by CDP request id
    // so frames (captured separately below) can be attributed to a URL.
    let ws_sockets = Arc::new(Mutex::new(HashMap::<RequestId, String>::new()));
    let mut ws_events = page
        .event_listener::<EventWebSocketCreated>()
        .await
        .map_err(browser_err)?;
    let ws_capture = Arc::clone(&ws_sockets);
    let ws_collector = tokio::spawn(async move {
        while let Some(event) = ws_events.next().await {
            if let Ok(mut sockets) = ws_capture.lock() {
                sockets.insert(event.request_id.clone(), event.url.clone());
            }
        }
    });

    // Capture WebSocket frame payloads both ways. webrev only observes: it
    // never resends traffic, but the captured payloads let an operator
    // replay the exchange with whichever tool they prefer (Burp, websocat).
    let ws_frames = Arc::new(Mutex::new(Vec::<(RequestId, &'static str, String)>::new()));

    let mut ws_sent_events = page
        .event_listener::<EventWebSocketFrameSent>()
        .await
        .map_err(browser_err)?;
    let frames_sent = Arc::clone(&ws_frames);
    let ws_sent_collector = tokio::spawn(async move {
        while let Some(event) = ws_sent_events.next().await {
            if let Ok(mut frames) = frames_sent.lock() {
                if frames.len() < MAX_WS_FRAMES {
                    frames.push((
                        event.request_id.clone(),
                        "sent",
                        event.response.payload_data.clone(),
                    ));
                }
            }
        }
    });

    let mut ws_recv_events = page
        .event_listener::<EventWebSocketFrameReceived>()
        .await
        .map_err(browser_err)?;
    let frames_recv = Arc::clone(&ws_frames);
    let ws_recv_collector = tokio::spawn(async move {
        while let Some(event) = ws_recv_events.next().await {
            if let Ok(mut frames) = frames_recv.lock() {
                if frames.len() < MAX_WS_FRAMES {
                    frames.push((
                        event.request_id.clone(),
                        "received",
                        event.response.payload_data.clone(),
                    ));
                }
            }
        }
    });

    with_timeout(&cancel, page.goto(url)).await?;

    // Active dwell: repeatedly scroll and click clickable elements one at a
    // time, attributing each click to the UI element that caused it (see
    // `click_attributed_script`), until the deadline or cancellation.
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline && !cancel.is_cancelled() {
        let count: usize = with_timeout(&cancel, page.evaluate(COUNT_INTERACTIVE_SCRIPT))
            .await
            .ok()
            .and_then(|v| v.into_value().ok())
            .unwrap_or(0);
        let clicks = count.min(MAX_CLICKS_PER_PASS);
        for i in 0..clicks {
            if cancel.is_cancelled() || Instant::now() >= deadline {
                break;
            }
            let _ = with_timeout(&cancel, page.evaluate(click_attributed_script(i))).await;
            tokio::select! {
                () = cancel.cancelled() => break,
                () = tokio::time::sleep(CLICK_SETTLE) => {},
            }
            let _ = with_timeout(&cancel, page.evaluate(CLEAR_TRIGGER_SCRIPT)).await;
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(INTERACTION_STEP) => {},
        }
    }

    // Read back the hook log, then stop capturing.
    let raw: String = with_timeout(&cancel, page.evaluate(hooks::COLLECT_HOOKS))
        .await?
        .into_value()
        .map_err(browser_err)?;
    collector.abort();
    ws_collector.abort();
    ws_sent_collector.abort();
    ws_recv_collector.abort();

    let har = match Arc::try_unwrap(har) {
        Ok(lock) => lock.into_inner().unwrap_or_default(),
        Err(shared) => shared.lock().map(|g| g.clone()).unwrap_or_default(),
    };

    // Merge hook records (high confidence) with HAR entries (medium),
    // deduplicating on the original URL.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut findings: Vec<Finding> = Vec::new();

    if let Ok(records) = serde_json::from_str::<Vec<HookRecord>>(&raw) {
        for record in records {
            if seen.insert(record.url.clone()) {
                let endpoint =
                    Endpoint::new(record.url, Method::parse(&record.method), Source::Browser);
                let mut finding = Finding::from_endpoint(session, &endpoint, Confidence::High);
                // Attribute the call to the UI element whose click caused it,
                // when the active-interaction driver recorded one: the
                // before/after diff that turns a flat endpoint list into
                // "clicking Delete Account calls DELETE /api/account".
                if let Some(trigger) = record.trigger {
                    finding.provenance =
                        Provenance::new(Source::Browser, Some(format!("click: {trigger}")));
                }
                findings.push(finding);
            }
        }
    }
    for endpoint in har.endpoints() {
        if seen.insert(endpoint.url.clone()) {
            findings.push(Finding::from_endpoint(
                session,
                &endpoint,
                Confidence::Medium,
            ));
        }
    }

    // WebSocket endpoints the page opened.
    let sockets = ws_sockets.lock().map(|m| m.clone()).unwrap_or_default();
    for socket_url in sockets.values() {
        if seen.insert(socket_url.clone()) {
            let endpoint = Endpoint::new(socket_url.clone(), Method::Get, Source::Browser);
            findings.push(Finding::from_endpoint(session, &endpoint, Confidence::High));
        }
    }

    // WebSocket frame payloads, attributed back to their socket's URL.
    // webrev only observes these; replaying them is left to the operator's
    // tool of choice (Burp, websocat, …).
    let frames = ws_frames.lock().map(|v| v.clone()).unwrap_or_default();
    for (request_id, direction, payload) in frames {
        let socket_url = sockets
            .get(&request_id)
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned());
        let mut payload = payload;
        if payload.chars().count() > MAX_WS_PAYLOAD_CHARS {
            payload = payload
                .chars()
                .take(MAX_WS_PAYLOAD_CHARS)
                .collect::<String>()
                + "…";
        }
        findings.push(Finding::new(
            session,
            FindingKind::WebSocketFrame,
            None,
            payload,
            Confidence::Medium,
            Provenance::new(Source::Browser, Some(format!("{direction} {socket_url}"))),
        ));
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
        let pool = BrowserPool::new(1);
        let findings = run_dynamic(
            &pool,
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
