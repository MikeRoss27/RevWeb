//! Replay and bounded mutation of captured WebSocket frames.
//!
//! `webrev-browser` only *observes* WebSocket traffic during a dynamic scan
//! (see `crates/webrev-browser/src/dynamic.rs`); this module is the active
//! probe that resends a captured frame, under the same guardrails as every
//! other check in `active/`:
//!
//! - Scope fail-closed: the socket URL is checked against [`Scope::allows`]
//!   *and* every resolved address against [`Scope::allows_resolved_ip`]
//!   before a TCP connection is opened, the same two-step gate the HTTP
//!   probes get from the pinned DNS resolver in `crate::dns` (this module
//!   cannot reuse that resolver directly: it is wired into `reqwest`, not a
//!   raw socket, so the check is duplicated here at the `TcpStream::connect`
//!   boundary instead).
//! - Non-destructive by default: a frame whose payload *looks* like a
//!   state-changing action (see [`destructive_frame_keyword`]) is refused,
//!   never sent, mirroring `destructive_keyword` for HTTP URLs.
//! - Bounded: at most [`MAX_WS_REPLAY_FRAMES`] frames are replayed per run.
//! - Every attempt produces a result (`FindingKind::WebSocketReplay` for the
//!   executed probe's own proof, `FindingKind::Idor` only for an actual
//!   cross-account signal) plus `ActiveCoverage`, never a bare "it worked".
//!
//! What this does **not** do (left for a future session, not silently
//! dropped): inject XSS/SQLi payloads into frame fields and look for
//! execution/error signals. A WebSocket frame has no DOM or SQL error
//! channel to observe from a raw client socket the way an HTTP response
//! does, and building that detection well (and testing it honestly) is a
//! separate piece of work from replay/mutation plumbing. The `mutation`
//! field here is a generic literal substring substitution, usable for an
//! IDOR-style identifier swap; a caller who substitutes an XSS/SQLi string
//! gets whatever the server echoes back as a response frame, with no attempt
//! to interpret it as a vulnerability signal.

use super::{
    bola_diff::{body_excerpt, comparison},
    client::idor_finding,
    evidence::attach,
};
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{client::ClientRequestBuilder, protocol::Message},
    MaybeTlsStream, WebSocketStream,
};
use tokio_util::sync::CancellationToken;
use webrev_core::{
    AuthConfig, Confidence, Finding, FindingKind, FindingStatus, OpsecConfig, Provenance,
    ResponseObservation, Result, Scope, SessionId, Source, WebrevError,
};

mod frames;
pub use frames::{
    destructive_frame_keyword, ws_frame_candidates, WsDirection, WsFrameCandidate, WsMutation,
};

/// Hard cap on live connections opened by one `run_ws_replay_scan` call.
/// Deliberately far below `MAX_WS_FRAMES` (the passive capture bound in
/// `webrev-browser`): every replay is a live connection attempt against the
/// target, not a passive observation, so the budget is conservative.
pub const MAX_WS_REPLAY_FRAMES: usize = 10;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for a response after sending, once connected.
const RESPONSE_WINDOW: Duration = Duration::from_secs(3);
const MAX_RESPONSE_FRAMES: usize = 5;
/// Largest response body kept per observation, in characters. Mirrors the
/// bound `transport::EXCERPT_LIMIT`/`bola_diff::BODY_LIMIT` use for HTTP
/// probes, so a WebSocket response proof is capped the same way.
const MAX_RESPONSE_CHARS: usize = 4096;

/// Outcome of attempting one frame (replay or mutation).
enum Attempt {
    /// Connected, sent, and collected whatever response frames arrived
    /// within the window (possibly none).
    Executed {
        sent_payload: String,
        response: Vec<String>,
    },
    /// Refused before connecting: out of scope, wrong scheme, truncated
    /// capture, or a destructive-looking payload.
    Refused(&'static str),
    /// Connection, handshake or send failed.
    Error(String),
}

/// Minimal per-run counters, mirroring `transport::ProbeClient`'s shape
/// closely enough to reuse `super::coverage_finding`, without pulling in its
/// HTTP-only `reqwest::Client`.
#[derive(Default)]
struct WsTracker {
    coverage: webrev_core::ActiveCoverage,
}

impl WsTracker {
    fn new(request_limit: usize) -> Self {
        Self {
            coverage: webrev_core::ActiveCoverage {
                request_limit,
                ..webrev_core::ActiveCoverage::default()
            },
        }
    }

    fn check(&mut self) -> &mut webrev_core::CheckCoverage {
        self.coverage.checks.entry("ws_replay".into()).or_default()
    }

    fn record(&mut self, attempt: &Attempt) {
        let check = self.check();
        check.attempted += 1;
        match attempt {
            Attempt::Executed { .. } => {
                self.coverage.requests += 1;
                self.coverage.responses += 1;
                self.check().executed += 1;
            }
            Attempt::Refused(reason) => {
                self.check().not_executed += 1;
                self.check().refused += 1;
                if *reason == "scope" {
                    self.coverage.out_of_scope += 1;
                    self.check().scope_refused += 1;
                }
                self.check().inconclusive += 1;
            }
            Attempt::Error(message) => {
                tracing::debug!(error = %message, "ws_replay: probe error");
                self.coverage.requests += 1;
                self.coverage.transport_errors += 1;
                self.check().not_executed += 1;
                self.check().errors += 1;
            }
        }
    }

    fn mark_finding(&mut self) {
        self.check().findings += 1;
    }

    fn mark_inconclusive(&mut self) {
        self.check().inconclusive += 1;
    }
}

/// Replay (optionally mutated) up to [`MAX_WS_REPLAY_FRAMES`] captured `Sent`
/// frames under `account_a`. When `account_b` is supplied, the *same*
/// (possibly mutated) payload is also sent under `account_b`; an
/// identical, successful-looking response is reported as a cross-account
/// `Idor` signal with a field diff, the same proof shape `bola.rs` produces
/// for HTTP. Without `account_b`, each executed replay produces a
/// `WebSocketReplay` finding carrying the observed response as reproducibility
/// proof — never a vulnerability claim by itself.
///
/// Returns a signal/proof finding per candidate that fired or executed,
/// plus one `ScanCoverage` finding, same contract as `run_active_scan` and
/// `run_bola_scan`: an incomplete or all-refused run is never silently
/// read as "nothing found".
#[allow(clippy::too_many_arguments)] // a focused entry point; grouping would add noise
pub async fn run_ws_replay_scan(
    opsec: &OpsecConfig,
    scope: &Scope,
    session: SessionId,
    account_a: &AuthConfig,
    account_b: Option<&AuthConfig>,
    candidates: &[WsFrameCandidate],
    mutation: Option<&WsMutation>,
    cancel: CancellationToken,
) -> Result<Vec<Finding>> {
    if opsec.egress.proxy.is_some() {
        // tokio-tungstenite's handshake runs over the raw TCP stream this
        // module connects itself (see `connect_in_scope`); it does not speak
        // HTTP CONNECT or any other proxy protocol. Rather than silently
        // connect direct while the operator believes traffic is proxied,
        // refuse outright. Known limitation, not a TODO for this session.
        return Err(WebrevError::Config(
            "ws_replay does not support the configured egress proxy; it would connect directly, \
             bypassing it. Run without --proxy to use ws_replay, or use Burp/websocat for \
             proxied WebSocket replay."
                .into(),
        ));
    }
    if !opsec.egress.allow_direct {
        return Err(WebrevError::Config(
            "egress policy forbids direct connections and ws_replay cannot use a proxy".into(),
        ));
    }
    let max_frames = MAX_WS_REPLAY_FRAMES.min(opsec.active.max_requests);
    let mut tracker = WsTracker::new(max_frames);
    let mut findings = Vec::new();
    let eligible = candidates
        .iter()
        .filter(|c| c.direction == WsDirection::Sent);
    for candidate in eligible.take(max_frames) {
        if cancel.is_cancelled() {
            tracker.coverage.cancelled = true;
            break;
        }
        let sent_payload = mutation.map_or_else(
            || candidate.payload.clone(),
            |mutation| mutation.apply(&candidate.payload),
        );
        let attempt = attempt_frame(scope, candidate, &sent_payload, account_a, &cancel).await;
        tracker.record(&attempt);
        let Attempt::Executed {
            sent_payload,
            response,
        } = attempt
        else {
            continue;
        };
        let own_a = response.join("\n");
        if let Some(account_b) = account_b {
            let cross = attempt_frame_as(
                scope,
                &candidate.socket_url,
                &sent_payload,
                account_b,
                &cancel,
            )
            .await;
            tracker.coverage.requests += 1;
            let Ok(cross_response) = cross else {
                tracker.coverage.transport_errors += 1;
                tracker.mark_inconclusive();
                continue;
            };
            tracker.coverage.responses += 1;
            let own_b = cross_response.join("\n");
            if let Some(found) = cross_account_signal(
                session,
                &candidate.socket_url,
                &own_a,
                &own_b,
                account_a,
                account_b,
            ) {
                tracker.mark_finding();
                findings.push(found);
            } else {
                tracker.mark_inconclusive();
            }
        } else if !own_a.is_empty() || !response.is_empty() {
            tracker.mark_finding();
            findings.push(replay_finding(
                session,
                &candidate.socket_url,
                &sent_payload,
                &response,
            ));
        } else {
            tracker.mark_inconclusive();
        }
    }
    if candidates
        .iter()
        .filter(|c| c.direction == WsDirection::Sent)
        .count()
        > max_frames
    {
        tracker.coverage.target_limit_reached = true;
    }
    tracker.coverage.cancelled = tracker.coverage.cancelled || cancel.is_cancelled();
    findings.push(super::coverage_finding(session, tracker.coverage));
    Ok(findings)
}

async fn attempt_frame(
    scope: &Scope,
    candidate: &WsFrameCandidate,
    sent_payload: &str,
    account: &AuthConfig,
    cancel: &CancellationToken,
) -> Attempt {
    if candidate.truncated {
        return Attempt::Refused("truncated_capture");
    }
    if let Some(keyword) = destructive_frame_keyword(sent_payload) {
        tracing::debug!(keyword, "ws_replay: refusing destructive-looking frame");
        return Attempt::Refused("destructive");
    }
    if !is_ws_url(&candidate.socket_url) {
        return Attempt::Refused("scheme");
    }
    if !scope.allows(&candidate.socket_url) {
        return Attempt::Refused("scope");
    }
    match attempt_frame_as(scope, &candidate.socket_url, sent_payload, account, cancel).await {
        Ok(response) => Attempt::Executed {
            sent_payload: sent_payload.to_owned(),
            response,
        },
        Err(error) => Attempt::Error(error),
    }
}

fn is_ws_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|parsed| matches!(parsed.scheme(), "ws" | "wss"))
}

/// Connect, send one frame under `account`, collect response frames for
/// [`RESPONSE_WINDOW`], then close. No scope or destructive-content check
/// here: the caller (`attempt_frame`, or the cross-account branch in
/// `run_ws_replay_scan`, which reuses an already-checked socket URL and
/// payload) is responsible for that.
async fn attempt_frame_as(
    scope: &Scope,
    socket_url: &str,
    payload: &str,
    account: &AuthConfig,
    cancel: &CancellationToken,
) -> std::result::Result<Vec<String>, String> {
    let headers = account.effective_headers();
    let mut stream = tokio::select! {
        () = cancel.cancelled() => return Err("cancelled".into()),
        result = connect_in_scope(scope, socket_url, &headers) => result?,
    };
    stream
        .send(Message::Text(payload.to_owned().into()))
        .await
        .map_err(|e| e.to_string())?;
    let mut responses = Vec::new();
    loop {
        if responses.len() >= MAX_RESPONSE_FRAMES {
            break;
        }
        let next = tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(RESPONSE_WINDOW) => break,
            message = stream.next() => message,
        };
        match next {
            Some(Ok(Message::Text(text))) => responses.push(bounded(text.as_str())),
            Some(Ok(Message::Binary(bytes))) => {
                responses.push(bounded(&String::from_utf8_lossy(&bytes)));
            }
            Some(Ok(Message::Close(_))) | None => break,
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error.to_string()),
        }
    }
    let _ = stream.close(None).await;
    Ok(responses)
}

fn bounded(text: &str) -> String {
    if text.chars().count() <= MAX_RESPONSE_CHARS {
        text.to_owned()
    } else {
        text.chars().take(MAX_RESPONSE_CHARS).collect::<String>() + "…"
    }
}

/// Resolve `socket_url`'s host, keep only addresses the scope authorizes
/// (fail-closed: an empty result after filtering is a refusal, not a
/// fallback to the first DNS answer), connect, and perform the WebSocket
/// handshake. TLS (for `wss://`) is negotiated on top of the already
/// scope-checked TCP stream by `client_async_tls_with_config`, so the TLS
/// layer never sees an out-of-scope address either.
async fn connect_in_scope(
    scope: &Scope,
    url_str: &str,
    headers: &[(String, String)],
) -> std::result::Result<WebSocketStream<MaybeTlsStream<TcpStream>>, String> {
    let parsed = reqwest::Url::parse(url_str).map_err(|e| e.to_string())?;
    if !matches!(parsed.scheme(), "ws" | "wss") {
        return Err("not a ws(s) URL".into());
    }
    let host = parsed.host_str().ok_or("missing host")?.to_owned();
    let port = parsed
        .port_or_known_default()
        .ok_or("could not determine port")?;
    let addrs = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| "DNS lookup timed out".to_owned())?
    .map_err(|e| e.to_string())?;
    let address = addrs
        .into_iter()
        .find(|addr| scope.allows_resolved_ip(&host, addr.ip()))
        .ok_or_else(|| format!("no DNS answer for {host} is inside the configured scope"))?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    let uri: tokio_tungstenite::tungstenite::http::Uri = url_str
        .parse()
        .map_err(|_| "invalid WebSocket URI".to_owned())?;
    let mut builder = ClientRequestBuilder::new(uri);
    for (name, value) in headers {
        builder = builder.with_header(name.clone(), value.clone());
    }
    let (stream, _response) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        client_async_tls_with_config(builder, tcp, None, None),
    )
    .await
    .map_err(|_| "WebSocket handshake timed out".to_owned())?
    .map_err(|e| e.to_string())?;
    Ok(stream)
}

/// A plain replay/mutation proof: what was sent and what came back. Never a
/// vulnerability claim; `status` stays `Observed`.
fn replay_finding(
    session: SessionId,
    socket_url: &str,
    sent_payload: &str,
    response: &[String],
) -> Finding {
    let mut finding = Finding::new(
        session,
        FindingKind::WebSocketReplay,
        Some(socket_url.to_owned()),
        format!(
            "replayed WebSocket frame on {socket_url}: {} response frame(s) observed",
            response.len()
        ),
        Confidence::Medium,
        Provenance::new(Source::Active, Some(format!("ws_replay {socket_url}"))),
    );
    let observations = vec![sent_observation(socket_url, sent_payload, response)];
    finding = attach(
        finding,
        "ws_replay",
        None,
        webrev_core::EvidenceVerdict::Observed,
        observations,
        "Verbatim or mutated resend of a captured frame; proves reproducibility only, not a \
         vulnerability. A cross-account comparison (account_b) is required for an access-control \
         signal.",
    );
    finding.status = FindingStatus::Observed;
    finding
}

fn sent_observation(
    socket_url: &str,
    sent_payload: &str,
    response: &[String],
) -> ResponseObservation {
    let body = response.join("\n");
    let (body, body_truncated) = body_excerpt(body.as_bytes());
    ResponseObservation {
        role: "ws replay".into(),
        method: "WS".into(),
        url: socket_url.to_owned(),
        status: 0,
        authenticated: true,
        content_type: String::new(),
        body_bytes: sent_payload.len(),
        excerpt: bounded(sent_payload),
        body,
        body_truncated,
    }
}

/// Build the cross-account `Idor` finding when the same payload, sent under
/// two different accounts, produced byte-identical, non-empty responses.
/// Mirrors `bola::check_pair`'s signal exactly, with the WebSocket responses
/// standing in for the two accounts' HTTP bodies.
fn cross_account_signal(
    session: SessionId,
    socket_url: &str,
    own_a: &str,
    own_b: &str,
    account_a: &AuthConfig,
    account_b: &AuthConfig,
) -> Option<Finding> {
    if own_a.is_empty() || own_b.is_empty() || account_a == account_b {
        return None;
    }
    let b_reads_a = own_a == own_b;
    if !b_reads_a {
        return None;
    }
    let observations = vec![
        ResponseObservation {
            role: "account A response".into(),
            method: "WS".into(),
            url: socket_url.to_owned(),
            status: 0,
            authenticated: true,
            content_type: String::new(),
            body_bytes: own_a.len(),
            excerpt: bounded(own_a),
            body: body_excerpt(own_a.as_bytes()).0,
            body_truncated: body_excerpt(own_a.as_bytes()).1,
        },
        ResponseObservation {
            role: "account B response (same frame)".into(),
            method: "WS".into(),
            url: socket_url.to_owned(),
            status: 0,
            authenticated: true,
            content_type: String::new(),
            body_bytes: own_b.len(),
            excerpt: bounded(own_b),
            body: body_excerpt(own_b.as_bytes()).0,
            body_truncated: body_excerpt(own_b.as_bytes()).1,
        },
    ];
    let mut finding = attach(
        idor_finding(
            session,
            socket_url,
            format!("cross-account WebSocket replay signal on {socket_url}"),
        ),
        "ws_replay_cross_account",
        None,
        webrev_core::EvidenceVerdict::Signal,
        observations,
        "The same WebSocket frame, resent under two different account credentials, produced \
         byte-identical, non-empty responses. Confirm the frame addresses an object owned by \
         account A and that account B has no legitimate access; a broadcast/public message or \
         an unauthenticated echo endpoint can produce this signal without any access-control bug.",
    );
    if let Some(evidence) = finding.evidence.as_mut() {
        evidence.diff = comparison(own_a.as_bytes(), own_b.as_bytes(), b_reads_a, false);
    }
    Some(finding)
}

#[cfg(test)]
mod tests;
