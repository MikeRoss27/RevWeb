use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};
use webrev_core::OpsecConfig;

struct LocalBrowserFixture {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl LocalBrowserFixture {
    fn start() -> Self {
        // Bind only loopback. 127.0.0.2 is a local canary: if Chromium
        // ever sends the excluded request, it reaches this fixture and
        // is recorded instead of leaving the machine.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local browser fixture");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let port = listener.local_addr().expect("fixture address").port();
        let canary_listener =
            TcpListener::bind(("127.0.0.2", port)).expect("bind out-of-scope loopback canary");
        canary_listener
            .set_nonblocking(true)
            .expect("nonblocking canary listener");
        let origin = format!("http://127.0.0.1:{port}");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let stopped = Arc::new(AtomicBool::new(false));
        let stop_worker = Arc::clone(&stopped);
        let worker = thread::spawn(move || {
            while !stop_worker.load(Ordering::Relaxed) {
                let mut accepted = None;
                for candidate in [&listener, &canary_listener] {
                    match candidate.accept() {
                        Ok(connection) => {
                            // Accepted sockets inherit the listener's non-blocking mode on Windows and BSD.
                            connection
                                .0
                                .set_nonblocking(false)
                                .expect("blocking socket");
                            accepted = Some(connection);
                            break;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("fixture accept failed: {error}"),
                    }
                }
                let Some((mut socket, _)) = accepted else {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                };
                let _ = socket.set_read_timeout(Some(Duration::from_secs(1)));
                let mut bytes = Vec::new();
                let mut chunk = [0; 2048];
                while bytes.len() < 8192 && !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => bytes.extend_from_slice(&chunk[..count]),
                    }
                }
                let request = String::from_utf8_lossy(&bytes).into_owned();
                let path = request.split_whitespace().nth(1).unwrap_or("/");
                let method = if request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("Upgrade: websocket"))
                {
                    "UPGRADE"
                } else {
                    request.split_whitespace().next().unwrap_or("UNKNOWN")
                };
                recorded
                    .lock()
                    .expect("request log")
                    .push(format!("{method} {path}"));
                let (content_type, body) = match path {
                    "/" => (
                        "text/html",
                        format!(
                            "<script src='/app.js'></script><img src='http://127.0.0.2:{port}/out-of-scope'><button id='delete' onclick=\"fetch('/click-delete', {{method:'DELETE'}}).catch(() => {{}})\">Delete account</button>"
                        ),
                    ),
                    "/destructive-ui" => (
                        "text/html",
                        "<button id='safe' onclick=\"fetch('/ui-safe')\">Load more</button>\
                         <button onclick=\"fetch('/ui-delete',{method:'DELETE'})\">Remove it</button>\
                         <button aria-label='Sign out' onclick=\"fetch('/ui-signout',{method:'POST'})\">x</button>\
                         <div role='button' onclick=\"fetch('/ui-pay',{method:'POST'})\">Pay now</div>\
                         <form method='post' action='/ui-form-post'><button type='submit'>Save</button></form>"
                            .to_owned(),
                    ),
                    "/websocket-probe" => (
                        "text/html",
                        format!("<script>new WebSocket('ws://127.0.0.1:{port}/ws-in-scope').onerror=()=>{{}}; new WebSocket('ws://127.0.0.2:{port}/ws-out-of-scope').onerror=()=>{{}}; fetch('/probe-executed');fetch('/probe-control');</script>"),
                    ),
                    "/app.js" => (
                        "application/javascript",
                        "fetch('/api/captured').catch(() => {}); fetch('/onload-post', {method:'POST'}).catch(() => {}); fetch('/same'); fetch('/same', {method:'POST'}).catch(() => {});".to_owned(),
                    ),
                    _ => ("text/plain", "ok".to_owned()),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes());
            }
        });
        Self {
            origin,
            requests,
            stopped,
            worker: Some(worker),
        }
    }
}

impl Drop for LocalBrowserFixture {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        self.worker
            .take()
            .expect("fixture worker")
            .join()
            .expect("fixture thread");
    }
}

#[test]
fn browser_scope_filters_subresources_and_redirects() {
    let scope = Scope::new(
        vec!["example.com".into()],
        vec!["excluded.example.com".into()],
    );
    assert!(browser_request_allowed(
        &scope,
        "https://example.com/app.js"
    ));
    assert!(browser_request_allowed(&scope, "wss://example.com/socket"));
    assert!(!browser_request_allowed(
        &scope,
        "https://other.test/app.js"
    ));
    assert!(!browser_request_allowed(
        &scope,
        "https://excluded.example.com/x"
    ));
    assert!(!browser_request_allowed(
        &scope,
        "https://user@example.com/x"
    ));

    let cidr_excluded = Scope::new(vec!["example.com".into()], vec!["192.0.2.7".into()]);
    assert!(
        !browser_request_allowed(&cidr_excluded, "https://example.com/"),
        "Chromium cannot verify a hostname's resolved address before navigation"
    );
    let exact_ip_excluded = Scope::new(vec!["example.com".into()], vec!["192.0.2.7".into()]);
    assert!(!browser_request_allowed(
        &exact_ip_excluded,
        "https://example.com/"
    ));
}

#[tokio::test]
#[ignore = "requires a local Chromium/Chrome installation"]
async fn dynamic_run_smoke() {
    let fixture = LocalBrowserFixture::start();
    let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
    let profile = BrowserProfile::from_opsec(&OpsecConfig::default())
        .expect("profile")
        .with_scope(scope);
    let pool = BrowserPool::new(1);
    let report = run_dynamic_with_report(
        &pool,
        &profile,
        &fixture.origin,
        Duration::from_secs(2),
        SessionId::new(),
        CancellationToken::new(),
    )
    .await
    .expect("dynamic run");
    pool.shutdown().await;

    assert!(report.findings.iter().any(|finding| finding
        .url
        .as_deref()
        .is_some_and(|url| url.ends_with("/api/captured"))));
    let requests = fixture.requests.lock().expect("request log");
    assert!(requests.iter().any(|path| path.ends_with(" /app.js")));
    assert!(requests.iter().any(|path| path.ends_with(" /api/captured")));
    assert!(!requests.iter().any(|path| path.ends_with(" /out-of-scope")));
    assert!(requests.iter().any(|path| path.ends_with(" /onload-post")));
    // Default Explore must not click the "Delete account" button; it records it.
    assert!(!requests.iter().any(|path| path.ends_with(" /click-delete")));
    assert!(report
        .refused_interactions
        .iter()
        .any(|interaction| interaction.reason == "delete"));
    assert!(requests.iter().any(|request| request == "GET /same"));
    assert!(requests.iter().any(|request| request == "POST /same"));
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding
                .url
                .as_deref()
                .is_some_and(|url| url.ends_with("/same")))
            .count(),
        2
    );
    assert!(report
        .refused_requests
        .iter()
        .any(|request| request.url.ends_with("/out-of-scope")
            && request.reason == crate::RefusalReason::OutOfScope));
}

#[tokio::test]
#[ignore = "requires a local Chromium/Chrome installation"]
async fn observation_only_refuses_page_post_and_does_not_click() {
    let fixture = LocalBrowserFixture::start();
    let profile = BrowserProfile::from_opsec(&OpsecConfig::default())
        .expect("profile")
        .with_scope(Scope::new(vec!["127.0.0.1".into()], vec![]))
        .with_interaction_policy(InteractionPolicy::ObserveOnly);
    let pool = BrowserPool::new(1);
    let session = SessionId::new();
    let report = run_dynamic_with_report(
        &pool,
        &profile,
        &fixture.origin,
        Duration::from_secs(2),
        session,
        CancellationToken::new(),
    )
    .await
    .expect("observation capture");
    pool.shutdown().await;
    let requests = fixture.requests.lock().expect("request log");
    assert!(requests.iter().any(|path| path.ends_with(" /api/captured")));
    assert!(!requests.iter().any(|path| path.ends_with(" /onload-post")));
    assert!(!requests.iter().any(|path| path.ends_with(" /click-delete")));
    assert!(!requests.iter().any(|path| path.ends_with(" /out-of-scope")));
    assert!(report
        .refused_requests
        .iter()
        .any(|request| request.method == "POST"
            && request.url.ends_with("/onload-post")
            && request.reason == crate::RefusalReason::MethodRestricted));
    assert!(report
        .refused_requests
        .iter()
        .any(|request| request.url.ends_with("/out-of-scope")
            && request.reason == crate::RefusalReason::OutOfScope));
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.kind == FindingKind::Endpoint
            && finding
                .url
                .as_deref()
                .is_some_and(|url| url.ends_with("/onload-post")
                    || url.ends_with("/out-of-scope")
                    || url.ends_with("/click-delete"))));
    let coverage =
        report.coverage_finding(session, &fixture.origin, InteractionPolicy::ObserveOnly);
    assert_eq!(coverage.kind, FindingKind::ScanCoverage);
    let evidence: serde_json::Value = serde_json::from_str(&coverage.value).expect("coverage JSON");
    assert_eq!(evidence["complete"], false);
    assert_eq!(evidence["policy"], "ObserveOnly");
    assert!(evidence["refused_request_count"].as_u64().expect("count") >= 2);
    assert!(evidence["refused_requests"]
        .as_array()
        .expect("requests")
        .iter()
        .any(|request| request["reason"] == "MethodRestricted" && request["method"] == "POST"));
}

#[tokio::test]
#[ignore = "requires a local Chromium/Chrome installation"]
async fn explore_never_clicks_destructive_controls_and_records_refusals() {
    let fixture = LocalBrowserFixture::start();
    let profile = BrowserProfile::from_opsec(&OpsecConfig::default())
        .expect("profile")
        .with_scope(Scope::new(vec!["127.0.0.1".into()], vec![]));
    assert_eq!(profile.interaction_policy, InteractionPolicy::Explore);
    let pool = BrowserPool::new(1);
    let session = SessionId::new();
    let report = run_dynamic_with_report(
        &pool,
        &profile,
        &format!("{}/destructive-ui", fixture.origin),
        Duration::from_secs(3),
        session,
        CancellationToken::new(),
    )
    .await
    .expect("explore capture");
    pool.shutdown().await;
    let requests = fixture.requests.lock().expect("request log");
    assert!(
        requests.iter().any(|r| r == "GET /ui-safe"),
        "benign control is still exercised: {requests:?}"
    );
    for forbidden in ["/ui-delete", "/ui-signout", "/ui-pay", "/ui-form-post"] {
        assert!(
            !requests.iter().any(|r| r.ends_with(forbidden)),
            "{forbidden} must not be requested: {requests:?}"
        );
    }
    assert_eq!(report.refused_interaction_count, 4);
    let reasons: Vec<_> = report
        .refused_interactions
        .iter()
        .map(|i| i.reason.as_str())
        .collect();
    for expected in ["delete", "sign_out", "pay", "non_get_form"] {
        assert!(
            reasons.iter().any(|r| r.contains(expected)),
            "{expected} in {reasons:?}"
        );
    }
    let coverage = report.coverage_finding(session, &fixture.origin, InteractionPolicy::Explore);
    let evidence: serde_json::Value = serde_json::from_str(&coverage.value).unwrap();
    assert_eq!(evidence["complete"], false);
    assert_eq!(evidence["refused_interaction_count"], 4);
}

/// A diagnostic of actual handshake egress, independent of findings filtering.
/// The fixture responds HTTP 200, so this records attempted upgrades rather than
/// an established WebSocket connection. All listeners are local loopback.
#[tokio::test]
#[ignore = "requires Chromium; diagnostic of WebSocket scope interception"]
async fn websocket_scope_blocks_egress() {
    let fixture = LocalBrowserFixture::start();
    let profile = BrowserProfile::from_opsec(&OpsecConfig::default())
        .expect("profile")
        .with_scope(Scope::new(vec!["127.0.0.1".into()], vec![]));
    let pool = BrowserPool::new(1);
    let report = run_dynamic_with_report(
        &pool,
        &profile,
        &format!("{}/websocket-probe", fixture.origin),
        Duration::from_secs(2),
        SessionId::new(),
        CancellationToken::new(),
    )
    .await
    .expect("diagnostic capture");
    pool.shutdown().await;
    let requests = fixture.requests.lock().expect("request log");
    assert!(
        requests
            .iter()
            .any(|request| request == "GET /probe-executed"),
        "page scripts must execute"
    );
    assert!(
        requests
            .iter()
            .any(|request| request == "UPGRADE /ws-in-scope"),
        "in-scope WS control must reach loopback server"
    );
    let escaped = requests
        .iter()
        .any(|request| request == "UPGRADE /ws-out-of-scope");
    let refused = report
        .refused_requests
        .iter()
        // A ws:// handshake through an HTTP proxy is a CONNECT to host:port, so
        // the refusal carries the out-of-scope authority but not the path.
        .filter(|request| request.url.contains("127.0.0.2"))
        .count();
    let filtered_endpoint_count = report
        .findings
        .iter()
        .filter(|finding| {
            finding
                .url
                .as_deref()
                .is_some_and(|url| url.ends_with("/ws-out-of-scope"))
        })
        .count();
    println!("websocket scope diagnostic: out_of_scope_handshake_received={escaped}; interception_refusals={refused}; exported_out_of_scope_endpoints={filtered_endpoint_count}");
    println!("loopback request evidence: {requests:?}");
    assert!(
        !escaped,
        "scoped egress proxy must refuse the out-of-scope handshake before TCP egress"
    );
    assert!(refused > 0, "refused WS intent must remain in coverage");
    assert_eq!(filtered_endpoint_count, 0);
}

#[tokio::test]
#[ignore = "requires Chromium; tests a candidate WebSocket network guard"]
async fn diagnostic_websocket_cdp_block_patterns() {
    use chromiumoxide::cdp::browser_protocol::network::{BlockPattern, SetBlockedUrLsParams};
    let fixture = LocalBrowserFixture::start();
    let profile = BrowserProfile::from_opsec(&OpsecConfig::default())
        .expect("profile")
        .with_scope(Scope::new(
            vec!["127.0.0.1".into(), "127.0.0.2".into()],
            vec![],
        ));
    let pool = BrowserPool::new(1);
    let browser = pool.acquire(&profile).await.expect("browser");
    let page = browser.new_page("about:blank").await.expect("page");
    let mut paused = page
        .event_listener::<EventRequestPaused>()
        .await
        .expect("request listener");
    let intercept_page = page.clone();
    let interceptor = tokio::spawn(async move {
        while let Some(event) = paused.next().await {
            if intercept_page
                .execute(ContinueRequestParams::new(event.request_id.clone()))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    page.execute(EnableParams::default())
        .await
        .expect("enable network");
    page.execute(
        SetBlockedUrLsParams::builder()
            .url_patterns([
                BlockPattern::new("ws://*:*/*", true),
                BlockPattern::new("wss://*:*/*", true),
                BlockPattern::new("http://127.0.0.1:*/probe-executed", true),
            ])
            .build(),
    )
    .await
    .expect("install WS network block patterns");
    let cancel = CancellationToken::new();
    with_timeout(
        &cancel,
        page.goto(format!("{}/websocket-probe", fixture.origin)),
    )
    .await
    .expect("probe navigation");
    tokio::time::sleep(Duration::from_secs(2)).await;
    interceptor.abort();
    drop(page);
    drop(browser);
    pool.shutdown().await;
    let requests = fixture.requests.lock().expect("request log");
    println!("CDP ws/wss catch-all guard loopback evidence: {requests:?}");
    assert!(
        requests
            .iter()
            .any(|request| request == "GET /probe-control"),
        "page scripts must execute"
    );
    assert!(
        !requests
            .iter()
            .any(|request| request == "GET /probe-executed"),
        "HTTP block control must be blocked by Network.setBlockedURLs"
    );
    let escaped = requests
        .iter()
        .any(|request| request == "UPGRADE /ws-out-of-scope");
    println!("CDP candidate ws_out_of_scope_handshake_received={escaped}; this is diagnostic, not a scope guarantee");
}
