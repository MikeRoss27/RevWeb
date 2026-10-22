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
    destructive::payload_keyword,
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

/// Which side sent a captured frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsDirection {
    Sent,
    Received,
}

/// A captured WebSocket frame, as recorded by `webrev-browser`'s
/// `FindingKind::WebSocketFrame` (`provenance.location` = `"<direction>
/// <socket url>"`, `value` = payload, possibly truncated with a trailing
/// `…`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrameCandidate {
    pub socket_url: String,
    pub direction: WsDirection,
    pub payload: String,
    /// True when the capture truncated this payload (`MAX_WS_PAYLOAD_CHARS`
    /// in `dynamic.rs`). A truncated frame is never replayed: resending a cut
    /// payload is not the frame that was actually observed.
    pub truncated: bool,
}

/// A literal, single-occurrence substring substitution applied to a frame's
/// payload before it is resent. Generic on purpose: this module has no model
/// of any particular frame's JSON schema, so it cannot name "the object id
/// field" the way `bola_diff` can for a URL path segment. The caller supplies
/// the exact substring to replace (typically a captured id) and its
/// replacement (e.g. another account's id, to mirror the BOLA cross-account
/// check over WebSocket instead of HTTP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsMutation {
    pub find: String,
    pub replace: String,
}

impl WsMutation {
    fn apply(&self, payload: &str) -> String {
        payload.replacen(&self.find, &self.replace, 1)
    }
}

/// Extract candidate frames from captured findings. Only `FindingKind::
/// WebSocketFrame` entries are considered; everything else is ignored.
#[must_use]
pub fn ws_frame_candidates(findings: &[Finding]) -> Vec<WsFrameCandidate> {
    findings
        .iter()
        .filter(|f| f.kind == FindingKind::WebSocketFrame)
        .filter_map(|f| {
            let location = f.provenance.location.as_deref()?;
            let (direction, socket_url) = location.split_once(' ')?;
            let direction = match direction {
                "sent" => WsDirection::Sent,
                "received" => WsDirection::Received,
                _ => return None,
            };
            let truncated = f.value.ends_with('…');
            let payload = if truncated {
                f.value.trim_end_matches('…').to_owned()
            } else {
                f.value.clone()
            };
            Some(WsFrameCandidate {
                socket_url: socket_url.to_owned(),
                direction,
                payload,
                truncated,
            })
        })
        .collect()
}

/// Money-shaped field names, scanned on top of `payload_keyword`'s action
/// verbs. A JSON field with one of these names and a numeric value reads as
/// a state-changing amount even without an action verb, e.g.
/// `{"amount":500,"to":"acct_2"}`.
///
/// Heuristic only, with known gaps: it is blind to non-JSON payloads, to an
/// amount carried as a string (`"500.00"`), to a money-shaped key whose
/// value is actually an id or a count, and to any field name it does not
/// list. It can only ever be a denylist, never a proof that a frame is safe.
const MONEY_KEYS: &[&str] = &[
    "amount", "balance", "price", "total", "quantity", "sum", "credit", "debit", "payment",
];

fn money_field(payload: &str) -> Option<&'static str> {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        .and_then(|value| find_money_field(&value))
}

fn find_money_field(value: &serde_json::Value) -> Option<&'static str> {
    match value {
        serde_json::Value::Object(map) => map.iter().find_map(|(key, v)| {
            let lower = key.to_ascii_lowercase();
            MONEY_KEYS
                .iter()
                .find(|money| lower == **money || lower.ends_with(&format!("_{money}")))
                .filter(|_| v.is_number())
                .copied()
                .or_else(|| find_money_field(v))
        }),
        serde_json::Value::Array(items) => items.iter().find_map(find_money_field),
        _ => None,
    }
}

/// Why a frame is refused before anything is sent, if at all. Checked on the
/// payload that would actually be sent (post-mutation), so a mutation cannot
/// be used to smuggle a destructive-looking frame past the guard.
///
/// Documented limits: this is word/field-shape matching, not an
/// understanding of the target's API. A delete endpoint named `/sync` with a
/// payload `{"op":7}` is not recognised; a harmless frame that happens to
/// contain the word "cancel" in an unrelated string is refused anyway. See
/// `destructive::payload_keyword` and [`MONEY_KEYS`] for the exact rules.
#[must_use]
pub fn destructive_frame_keyword(payload: &str) -> Option<&'static str> {
    payload_keyword(payload).or_else(|| money_field(payload))
}

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
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use webrev_core::{EgressPolicy, Provenance as CoreProvenance};

    fn frame_finding(socket_url: &str, direction: &str, value: &str) -> Finding {
        Finding::new(
            SessionId::new(),
            FindingKind::WebSocketFrame,
            None,
            value,
            Confidence::Medium,
            CoreProvenance::new(Source::Browser, Some(format!("{direction} {socket_url}"))),
        )
    }

    #[test]
    fn extracts_sent_and_received_frames_with_truncation_flag() {
        let findings = vec![
            frame_finding("wss://x.test/ws", "sent", r#"{"op":"ping"}"#),
            frame_finding("wss://x.test/ws", "received", "partial-payload…"),
            Finding::new(
                SessionId::new(),
                FindingKind::Endpoint,
                Some("https://x.test/".into()),
                "GET https://x.test/",
                Confidence::High,
                CoreProvenance::new(Source::Browser, None),
            ),
        ];
        let candidates = ws_frame_candidates(&findings);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].direction, WsDirection::Sent);
        assert!(!candidates[0].truncated);
        assert_eq!(candidates[1].direction, WsDirection::Received);
        assert!(candidates[1].truncated);
        assert_eq!(candidates[1].payload, "partial-payload");
    }

    #[test]
    fn destructive_action_verb_is_refused() {
        assert_eq!(
            destructive_frame_keyword(r#"{"op":"delete_account","id":1}"#),
            Some("delete")
        );
        assert_eq!(destructive_frame_keyword(r#"{"op":"get_profile"}"#), None);
    }

    #[test]
    fn money_shaped_field_is_refused_without_an_action_verb() {
        assert_eq!(
            destructive_frame_keyword(r#"{"amount":500,"to":"acct_2"}"#),
            Some("amount")
        );
        assert_eq!(
            destructive_frame_keyword(r#"{"amount":"not-a-number"}"#),
            None,
            "a money-shaped field is only flagged when its own value is numeric"
        );
        assert_eq!(
            destructive_frame_keyword(r#"{"quantity_total":3}"#),
            Some("total"),
            "a composite field name ending in a money key is still caught"
        );
    }

    #[test]
    fn ordinary_telemetry_frame_is_not_flagged() {
        assert_eq!(
            destructive_frame_keyword(r#"{"event":"page_view","path":"/dashboard"}"#),
            None
        );
    }

    #[test]
    fn mutation_replaces_a_single_occurrence() {
        let mutation = WsMutation {
            find: "101".into(),
            replace: "202".into(),
        };
        assert_eq!(
            mutation.apply(r#"{"userId":"101","other":"101"}"#),
            r#"{"userId":"202","other":"101"}"#
        );
    }

    /// Accepts one connection per `TcpStream`, echoing every text frame back
    /// prefixed with `echo:`, for as many connections as a test opens (one
    /// per replay / per account), not just the first.
    async fn echo_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await {
                        while let Some(Ok(message)) = ws.next().await {
                            if let Message::Text(text) = message {
                                let _ = ws.send(Message::Text(format!("echo:{text}").into())).await;
                            }
                        }
                    }
                });
            }
        });
        (format!("ws://127.0.0.1:{port}/ws"), handle)
    }

    fn local_opsec() -> OpsecConfig {
        OpsecConfig {
            egress: EgressPolicy {
                proxy: None,
                allow_direct: true,
            },
            ..OpsecConfig::default()
        }
    }

    #[tokio::test]
    async fn verbatim_replay_produces_a_response_backed_finding() {
        let (url, _server) = echo_server().await;
        let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
        let candidates = vec![WsFrameCandidate {
            socket_url: url,
            direction: WsDirection::Sent,
            payload: r#"{"op":"ping"}"#.into(),
            truncated: false,
        }];
        let findings = run_ws_replay_scan(
            &local_opsec(),
            &scope,
            SessionId::new(),
            &AuthConfig::default(),
            None,
            &candidates,
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let replay = findings
            .iter()
            .find(|f| f.kind == FindingKind::WebSocketReplay)
            .expect("expected a replay finding");
        assert_eq!(replay.status, FindingStatus::Observed);
        let evidence = replay.evidence.as_ref().unwrap();
        assert!(evidence.observations[0].body.contains("echo:"));
        let coverage = findings
            .iter()
            .find(|f| f.kind == FindingKind::ScanCoverage)
            .unwrap();
        assert_eq!(coverage.coverage.as_ref().unwrap().requests, 1);
    }

    #[tokio::test]
    async fn destructive_frame_is_refused_and_never_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // No accept loop: if this module connected anyway, the handshake
        // would hang/fail against a listener that never accepts, and the
        // test would time out instead of completing fast with no finding.
        let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
        let candidates = vec![WsFrameCandidate {
            socket_url: format!("ws://127.0.0.1:{port}/ws"),
            direction: WsDirection::Sent,
            payload: r#"{"op":"delete_account"}"#.into(),
            truncated: false,
        }];
        let findings = run_ws_replay_scan(
            &local_opsec(),
            &scope,
            SessionId::new(),
            &AuthConfig::default(),
            None,
            &candidates,
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!findings
            .iter()
            .any(|f| f.kind == FindingKind::WebSocketReplay));
        let coverage = findings[0].coverage.as_ref().unwrap();
        let check = &coverage.checks["ws_replay"];
        assert_eq!(check.refused, 1);
        assert_eq!(check.executed, 0);
        assert_eq!(coverage.requests, 0);
        drop(listener);
    }

    #[tokio::test]
    async fn out_of_scope_socket_is_refused() {
        let scope = Scope::new(vec!["allowed.test".into()], vec![]);
        let candidates = vec![WsFrameCandidate {
            socket_url: "ws://127.0.0.1:1/ws".into(),
            direction: WsDirection::Sent,
            payload: r#"{"op":"ping"}"#.into(),
            truncated: false,
        }];
        let findings = run_ws_replay_scan(
            &local_opsec(),
            &scope,
            SessionId::new(),
            &AuthConfig::default(),
            None,
            &candidates,
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let coverage = findings[0].coverage.as_ref().unwrap();
        assert_eq!(coverage.out_of_scope, 1);
        assert_eq!(coverage.checks["ws_replay"].scope_refused, 1);
    }

    #[tokio::test]
    async fn truncated_capture_is_refused_not_replayed() {
        let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
        let candidates = vec![WsFrameCandidate {
            socket_url: "ws://127.0.0.1:1/ws".into(),
            direction: WsDirection::Sent,
            payload: "cut-off".into(),
            truncated: true,
        }];
        let findings = run_ws_replay_scan(
            &local_opsec(),
            &scope,
            SessionId::new(),
            &AuthConfig::default(),
            None,
            &candidates,
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!findings
            .iter()
            .any(|f| f.kind == FindingKind::WebSocketReplay));
        let coverage = findings[0].coverage.as_ref().unwrap();
        assert_eq!(coverage.checks["ws_replay"].refused, 1);
    }

    #[tokio::test]
    async fn frame_budget_stops_after_the_limit_and_flags_it() {
        let (url, _server) = echo_server().await;
        let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
        let candidates: Vec<_> = (0..MAX_WS_REPLAY_FRAMES + 3)
            .map(|i| WsFrameCandidate {
                socket_url: url.clone(),
                direction: WsDirection::Sent,
                payload: format!(r#"{{"op":"ping","n":{i}}}"#),
                truncated: false,
            })
            .collect();
        let findings = run_ws_replay_scan(
            &local_opsec(),
            &scope,
            SessionId::new(),
            &AuthConfig::default(),
            None,
            &candidates,
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let replayed = findings
            .iter()
            .filter(|f| f.kind == FindingKind::WebSocketReplay)
            .count();
        assert_eq!(replayed, MAX_WS_REPLAY_FRAMES);
        let coverage = findings
            .iter()
            .find(|f| f.kind == FindingKind::ScanCoverage)
            .unwrap()
            .coverage
            .as_ref()
            .unwrap();
        assert!(coverage.target_limit_reached);
    }

    #[tokio::test]
    async fn cross_account_identical_response_is_reported_as_idor_signal() {
        let (url, _server) = echo_server().await;
        let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
        let candidates = vec![WsFrameCandidate {
            socket_url: url,
            direction: WsDirection::Sent,
            payload: r#"{"op":"get_order","id":"101"}"#.into(),
            truncated: false,
        }];
        let account_a = AuthConfig {
            bearer: Some("token-a".into()),
            ..AuthConfig::default()
        };
        let account_b = AuthConfig {
            bearer: Some("token-b".into()),
            ..AuthConfig::default()
        };
        let findings = run_ws_replay_scan(
            &local_opsec(),
            &scope,
            SessionId::new(),
            &account_a,
            Some(&account_b),
            &candidates,
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let signal = findings
            .iter()
            .find(|f| f.kind == FindingKind::Idor)
            .expect("the echo server answers both accounts identically for the same frame");
        assert_eq!(signal.status, FindingStatus::Suspicious);
        assert!(!signal.evidence.as_ref().unwrap().diff.is_empty());
    }

    #[tokio::test]
    async fn mutation_changing_the_response_is_not_reported_as_a_signal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // A server that answers with the id it was sent: a genuinely
        // per-account response, so mutating the id must NOT produce a
        // cross-account match.
        let handle = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await {
                        if let Some(Ok(Message::Text(text))) = ws.next().await {
                            let _ = ws.send(Message::Text(format!("saw:{text}").into())).await;
                        }
                    }
                });
            }
        });
        let url = format!("ws://127.0.0.1:{port}/ws");
        let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
        let candidates = vec![WsFrameCandidate {
            socket_url: url,
            direction: WsDirection::Sent,
            payload: r#"{"op":"get_order","id":"101"}"#.into(),
            truncated: false,
        }];
        let mutation = WsMutation {
            find: "101".into(),
            replace: "202".into(),
        };
        let account_a = AuthConfig {
            bearer: Some("token-a".into()),
            ..AuthConfig::default()
        };
        let account_b = AuthConfig {
            bearer: Some("token-b".into()),
            ..AuthConfig::default()
        };
        let findings = run_ws_replay_scan(
            &local_opsec(),
            &scope,
            SessionId::new(),
            &account_a,
            Some(&account_b),
            &candidates,
            Some(&mutation),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(
            !findings.iter().any(|f| f.kind == FindingKind::Idor),
            "responses echo the (mutated) request so they differ per account; no signal expected"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn configured_proxy_is_refused_outright() {
        let opsec = OpsecConfig {
            egress: EgressPolicy {
                proxy: Some("http://127.0.0.1:8080".into()),
                allow_direct: false,
            },
            ..OpsecConfig::default()
        };
        let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
        let error = run_ws_replay_scan(
            &opsec,
            &scope,
            SessionId::new(),
            &AuthConfig::default(),
            None,
            &[],
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("proxy"));
    }
}
