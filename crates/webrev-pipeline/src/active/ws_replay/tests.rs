//! Tests for the WebSocket replay probe, split out of `ws_replay.rs` to keep
//! each source file under the repository size gate.

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
