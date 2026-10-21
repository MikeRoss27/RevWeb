// crates/webrev-browser/src/dynamic.rs
//! The dynamic-analysis entry point: drive a page for a bounded dwell time and
//! return the endpoints observed via injected hooks and CDP network capture.

use crate::har::{Har, HarEntry};
use crate::hooks::{self, HookRecord};
use crate::policy::{
    interaction_refusal, request_refusal, DynamicRunReport, InteractionPolicy, RefusalLog,
    RefusedInteraction,
};
use crate::pool::BrowserPool;
use crate::profile::BrowserProfile;
use chromiumoxide::cdp::browser_protocol::emulation::{
    SetGeolocationOverrideParams, SetTimezoneOverrideParams,
};
use chromiumoxide::cdp::browser_protocol::fetch::{
    ContinueRequestParams, EventRequestPaused, FailRequestParams,
};
use chromiumoxide::cdp::browser_protocol::network::{
    EnableParams, ErrorReason, EventRequestWillBeSent, EventWebSocketCreated,
    EventWebSocketFrameReceived, EventWebSocketFrameSent, Headers, RequestId,
    SetExtraHttpHeadersParams,
};
use futures::StreamExt;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use webrev_core::{
    Confidence, Endpoint, Finding, FindingKind, Method, Provenance, Result, Scope, SessionId,
    Source,
};

fn browser_request_allowed(scope: &Scope, url: &str) -> bool {
    if url.starts_with("about:") || url.starts_with("data:") || url.starts_with("blob:") {
        return true;
    }
    (url.starts_with("http://")
        || url.starts_with("https://")
        || url.starts_with("ws://")
        || url.starts_with("wss://"))
        && !url.split_once("://").is_some_and(|(_, rest)| {
            rest.split('/')
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
        && scope.allows_browser_url(url)
}

/// Capture tasks must stop even if setup, navigation or collection fails.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl AbortOnDrop {
    fn abort(&self) {
        self.0.abort();
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

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
/// Captured HAR requests are bounded the same way: a chatty page (long-polling,
/// analytics beacons) over a long `--duration` dwell should not grow the
/// pre-dedup request log unboundedly.
const MAX_HAR_ENTRIES: usize = 2000;

/// Scroll to the bottom (to trigger lazy loading) and report how many
/// clickable elements are now on the page.
const COUNT_INTERACTIVE_SCRIPT: &str = r"(() => {
  try { window.scrollTo(0, document.body.scrollHeight); } catch (e) {}
  return document.querySelectorAll('button, [role=button]').length;
})();";

/// Maximum refused controls kept as evidence (the total is always counted).
const MAX_REFUSED_INTERACTIONS: usize = 256;

/// Describe the `index`-th clickable element without touching it: a JSON
/// `{"label", "text", "form"}` where `text` joins everything that could reveal
/// intent (id, class, name, value, title, aria-label, onclick, enclosing link
/// and form action) and `form` is true for a control that would submit a
/// non-GET form. Returns `null` once `index` is out of range.
fn describe_script(index: usize) -> String {
    format!(
        r"(() => {{
  const el = document.querySelectorAll('button, [role=button]')[{index}];
  if (!el) return null;
  const form = el.form || el.closest('form');
  const method = form ? String(form.getAttribute('method') || 'get').toLowerCase() : 'get';
  const submits = !!form && (el.tagName !== 'BUTTON' || (el.getAttribute('type') || 'submit').toLowerCase() === 'submit');
  const anchor = el.closest('a');
  const text = [el.id, el.className && el.className.baseVal !== undefined ? el.className.baseVal : el.className,
    el.getAttribute('name'), el.getAttribute('value'), el.getAttribute('title'),
    el.getAttribute('aria-label'), el.getAttribute('onclick'), el.getAttribute('formaction'),
    el.textContent, anchor && anchor.getAttribute('href'), form && form.getAttribute('action')]
    .filter(Boolean).join(' ');
  const label = (el.id && ('#' + el.id)) || el.getAttribute('aria-label')
    || (el.textContent || '').trim().slice(0, 40) || el.tagName;
  return JSON.stringify({{ label: String(label), text: text.slice(0, 2000), form: submits && method !== 'get' }});
}})();"
    )
}

#[derive(serde::Deserialize)]
struct ControlDescription {
    label: String,
    text: String,
    form: bool,
}

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
    Ok(
        run_dynamic_with_report(pool, profile, url, duration, session, cancel)
            .await?
            .findings,
    )
}

/// Run dynamic capture with refusal evidence. Use this API when interpreting
/// coverage: policy-refused intents are recorded separately from endpoints.
/// `ObserveOnly` disables driven interactions and unsafe HTTP methods; it cannot
/// guarantee an application has no side effects on GET or through page scripts.
pub async fn run_dynamic_with_report(
    pool: &BrowserPool,
    profile: &BrowserProfile,
    url: &str,
    duration: Duration,
    session: SessionId,
    cancel: CancellationToken,
) -> Result<DynamicRunReport> {
    let scope = profile.scope.clone().unwrap_or_else(|| {
        Scope::host_of(url)
            .map_or_else(Scope::default, |host| Scope::new(vec![host.into()], vec![]))
    });
    if !browser_request_allowed(&scope, url) {
        return Err(webrev_core::WebrevError::Config(format!(
            "dynamic seed out of scope: {url}"
        )));
    }
    let mut browser = pool.acquire_with_scope(profile, &scope).await?;
    // Reused profiles can have browser-background denials from the previous dwell.
    // Keep this report scoped to the current capture window.
    let _ = browser.take_refusals();
    let page = browser.new_page("about:blank").await?;

    let result = async {
        // Fetch interception pauses every request before network I/O, including
        // redirects, scripts, images and XHR. WebSocket handshakes bypass CDP
        // Fetch interception and are enforced separately by the scoped egress proxy.
        let mut paused = page
            .event_listener::<EventRequestPaused>()
            .await
            .map_err(browser_err)?;
        let intercept_page = page.clone();
        let intercept_scope = scope.clone();
        let refusals = Arc::new(Mutex::new(RefusalLog::default()));
        let captured_refusals = Arc::clone(&refusals);
        let interaction_policy = profile.interaction_policy;
        let interceptor = tokio::spawn(async move {
            while let Some(event) = paused.next().await {
                let refusal = request_refusal(
                    browser_request_allowed(&intercept_scope, &event.request.url),
                    interaction_policy,
                    &event.request.method,
                );
                if let Some(reason) = refusal {
                    if let Ok(mut captured) = captured_refusals.lock() {
                        captured.record(&event.request.url, &event.request.method, reason);
                    }
                }
                let result = if refusal.is_none() {
                    intercept_page
                        .execute(ContinueRequestParams::new(event.request_id.clone()))
                        .await
                        .map(|_| ())
                } else {
                    intercept_page
                        .execute(FailRequestParams::new(
                            event.request_id.clone(),
                            ErrorReason::BlockedByClient,
                        ))
                        .await
                        .map(|_| ())
                };
                if result.is_err() {
                    break;
                }
            }
        });
        let interceptor = AbortOnDrop(interceptor);

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
                    if har.entries.len() < MAX_HAR_ENTRIES {
                        har.push(HarEntry {
                            method: req.method.clone(),
                            url: req.url.clone(),
                            headers,
                        });
                    }
                }
            }
        });
        let collector = AbortOnDrop(collector);

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
        let ws_collector = AbortOnDrop(ws_collector);

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
        let ws_sent_collector = AbortOnDrop(ws_sent_collector);

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
        let ws_recv_collector = AbortOnDrop(ws_recv_collector);

        with_timeout(&cancel, page.goto(url)).await?;

        // Active dwell: repeatedly scroll and click clickable elements one at a
        // time, attributing each click to the UI element that caused it (see
        // `click_attributed_script`), until the deadline or cancellation.
        let deadline = Instant::now() + duration;
        let mut refused_interactions: Vec<RefusedInteraction> = Vec::new();
        let mut refused_interaction_count = 0usize;
        let mut refused_seen: BTreeSet<(String, String)> = BTreeSet::new();
        while Instant::now() < deadline && !cancel.is_cancelled() {
            let count: usize = if profile.interaction_policy == InteractionPolicy::Explore {
                with_timeout(&cancel, page.evaluate(COUNT_INTERACTIVE_SCRIPT))
                    .await
                    .ok()
                    .and_then(|v| v.into_value().ok())
                    .unwrap_or(0)
            } else {
                0
            };
            let clicks = count.min(MAX_CLICKS_PER_PASS);
            for i in 0..clicks {
                if cancel.is_cancelled() || Instant::now() >= deadline {
                    break;
                }
                // Decide before clicking: destructive-looking controls and
                // non-GET form submits are recorded, never clicked.
                let described: Option<ControlDescription> =
                    with_timeout(&cancel, page.evaluate(describe_script(i)))
                        .await
                        .ok()
                        .and_then(|v| v.into_value::<String>().ok())
                        .and_then(|json| serde_json::from_str(&json).ok());
                let Some(control) = described else {
                    // Cannot inspect the control: do not click blind.
                    continue;
                };
                if let Some(reason) = interaction_refusal(&control.text, control.form) {
                    let key = (control.label.clone(), reason.clone());
                    if refused_seen.insert(key) {
                        refused_interaction_count += 1;
                        if refused_interactions.len() < MAX_REFUSED_INTERACTIONS {
                            refused_interactions.push(RefusedInteraction {
                                label: control.label.chars().take(60).collect(),
                                reason,
                            });
                        }
                    }
                    continue;
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
        interceptor.abort();

        let har = match Arc::try_unwrap(har) {
            Ok(lock) => lock.into_inner().unwrap_or_default(),
            Err(shared) => shared.lock().map(|g| g.clone()).unwrap_or_default(),
        };

        // Merge hook records (high confidence) with HAR entries (medium),
        // deduplicating on the original URL.
        let mut seen: BTreeSet<(String, Method)> = BTreeSet::new();
        let mut findings: Vec<Finding> = Vec::new();

        if let Ok(records) = serde_json::from_str::<Vec<HookRecord>>(&raw) {
            for mut record in records {
                if let Ok(resolved) = url::Url::parse(url).and_then(|base| base.join(&record.url)) {
                    record.url = resolved.to_string();
                }
                if request_refusal(
                    browser_request_allowed(&scope, &record.url),
                    interaction_policy,
                    &record.method,
                )
                .is_some()
                {
                    continue;
                }
                if seen.insert((record.url.clone(), Method::parse(&record.method))) {
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
            if request_refusal(
                browser_request_allowed(&scope, &endpoint.url),
                interaction_policy,
                &endpoint.method.to_string(),
            )
            .is_some()
            {
                continue;
            }
            if seen.insert((endpoint.url.clone(), endpoint.method)) {
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
            if !browser_request_allowed(&scope, socket_url) {
                continue;
            }
            if seen.insert((socket_url.clone(), Method::Get)) {
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

        let mut captured = refusals
            .lock()
            .map(|captured| captured.clone())
            .unwrap_or_default();
        captured.merge(browser.take_refusals());
        Ok(DynamicRunReport {
            findings,
            refused_requests: captured.requests,
            refused_request_count: captured.count,
            refused_interactions,
            refused_interaction_count,
        })
    }
    .await;
    // Cleanup uses a fresh token so mission cancellation cannot skip tab closure.
    // A failed close discards the browser rather than returning an active page
    // to the reusable pool.
    let closed = with_timeout(&CancellationToken::new(), page.close()).await;
    if closed.is_err() {
        browser.discard();
    }
    match result {
        Err(error) => Err(error),
        Ok(report) => closed.map(|()| report),
    }
}

#[cfg(test)]
#[path = "dynamic_tests.rs"]
mod tests;
