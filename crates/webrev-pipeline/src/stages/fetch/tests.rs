use super::discovery::resolve_url;
use super::request::{is_wasm_response, parse_retry_after, read_bounded, MAX_RETRY_AFTER};
use super::*;
use std::time::Duration;
use webrev_core::Scope;

#[tokio::test]
async fn crawl_client_stops_before_out_of_scope_redirect() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 512];
        let _ = stream.read(&mut request);
        stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://localhost:9/out\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    });
    let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
    let client =
        super::request::build_client(&webrev_core::OpsecConfig::default(), &scope).unwrap();
    let response = client
        .get(format!("http://127.0.0.1:{port}/start"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    server.join().unwrap();
}

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
        "/seen".to_owned(),               // already visited
        "https://evil.test/x".to_owned(), // out of scope
        "mailto:a@b".to_owned(),          // filtered by resolve_url
    ];
    enqueue(
        &mut queue,
        &visited,
        &scope,
        "https://ex.com/base",
        &hrefs,
        1,
    );
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
    assert_eq!(detect_kind("manifest.json", ""), ContentKind::Json);
    assert_eq!(
        detect_kind("x", "application/manifest+json"),
        ContentKind::Json
    );
    assert_eq!(detect_kind("module.wasm", ""), ContentKind::Wasm);
    assert_eq!(detect_kind("x", "application/wasm"), ContentKind::Wasm);
    // Query string / fragment after the extension must not defeat detection.
    assert_eq!(detect_kind("module.wasm?v=2", ""), ContentKind::Wasm);
}

#[test]
fn wasm_response_detected_by_url_or_content_type() {
    assert!(is_wasm_response("https://x/module.wasm", ""));
    assert!(is_wasm_response("https://x/module.wasm?v=2", ""));
    assert!(is_wasm_response("https://x/endpoint", "application/wasm"));
    assert!(is_wasm_response(
        "https://x/endpoint",
        "Application/Wasm; charset=binary"
    ));
    assert!(!is_wasm_response(
        "https://x/app.js",
        "application/javascript"
    ));
    assert!(!is_wasm_response("https://x/app", "text/html"));
}

/// A `.wasm` response must never go through `resp.text()` — that would
/// lossily re-encode arbitrary binary bytes as UTF-8, corrupting the module.
/// This exercises the exact branch `fetch_with_retry` takes: build a response
/// carrying bytes that are not valid UTF-8, confirm `is_wasm_response` routes
/// it to the binary path, and confirm `resp.bytes()` returns them unchanged.
/// A response under the cap is read in full, byte for byte.
#[tokio::test]
async fn read_bounded_passes_through_a_response_under_the_cap() {
    let raw = b"hello world".to_vec();
    let resp = reqwest::Response::from(http::Response::builder().body(raw.clone()).unwrap());
    let (bytes, truncated) = read_bounded(resp, 1024).await.unwrap();
    assert_eq!(bytes, raw);
    assert!(!truncated);
}

/// A response past the cap is truncated to exactly `max_body_bytes`, not
/// read to completion -- the crawl's unbounded-memory gap this closes.
#[tokio::test]
async fn read_bounded_truncates_a_response_past_the_cap() {
    let raw = vec![b'x'; 10_000];
    let resp = reqwest::Response::from(http::Response::builder().body(raw).unwrap());
    let (bytes, truncated) = read_bounded(resp, 100).await.unwrap();
    assert_eq!(bytes.len(), 100);
    assert!(truncated);
}

/// A text body past the cap still decodes (lossily, as `Response::text()`
/// itself falls back to whenever no explicit non-UTF-8 charset is declared)
/// rather than erroring, so extraction still runs on the leading bytes kept.
#[tokio::test]
async fn fetch_with_retry_truncates_instead_of_erroring() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = "A".repeat(10_000);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 512];
        let _ = stream.read(&mut request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
    let client =
        super::request::build_client(&webrev_core::OpsecConfig::default(), &scope).unwrap();
    let (_, _, text, _, _) =
        super::request::fetch_with_retry(&client, &format!("http://127.0.0.1:{port}/big"), 100)
            .await
            .unwrap();
    assert_eq!(text.len(), 100);
    server.join().unwrap();
}

#[tokio::test]
async fn wasm_bytes_are_preserved_not_lossily_decoded() {
    // 0xFF is not valid UTF-8 on its own; a `.text()` read would replace it
    // with U+FFFD, silently corrupting the module.
    let raw: Vec<u8> = vec![0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFE];
    let builder = http::Response::builder()
        .status(200)
        .header("content-type", "application/wasm");
    let resp = reqwest::Response::from(builder.body(raw.clone()).unwrap());

    assert!(is_wasm_response(
        "https://x/module.wasm",
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
    ));

    let bytes = resp.bytes().await.expect("read body as bytes");
    assert_eq!(bytes.to_vec(), raw, "bytes must round-trip exactly");
}

#[test]
fn retry_after_parses_seconds_and_caps_the_wait() {
    let resp = |header: Option<&str>| {
        let mut builder = http::Response::builder().status(429);
        if let Some(v) = header {
            builder = builder.header("retry-after", v);
        }
        reqwest::Response::from(builder.body(Vec::<u8>::new()).unwrap())
    };
    assert_eq!(
        parse_retry_after(&resp(Some("5"))),
        Some(Duration::from_secs(5))
    );
    // Longer than the cap: clamped.
    assert_eq!(
        parse_retry_after(&resp(Some("3600"))),
        Some(MAX_RETRY_AFTER)
    );
    // Missing or non-numeric (HTTP-date form): no delay extracted, caller
    // falls back to its own exponential backoff.
    assert_eq!(parse_retry_after(&resp(None)), None);
    assert_eq!(
        parse_retry_after(&resp(Some("Wed, 21 Oct 2026 07:28:00 GMT"))),
        None
    );
}

#[test]
fn discovers_manifest_link_and_sw_registration() {
    let manifest_re =
        Regex::new(r#"(?i)<link[^>]+rel\s*=\s*["']manifest["'][^>]*href\s*=\s*["']([^"']+)["']"#)
            .unwrap();
    let sw_re = Regex::new(r#"(?i)serviceWorker\s*\.\s*register\s*\(\s*["']([^"']+)["']"#).unwrap();
    let html = r#"<link rel="manifest" href="/manifest.json">
        <script>navigator.serviceWorker.register('/sw.js');</script>"#;
    assert_eq!(capture_group1(&manifest_re, html), vec!["/manifest.json"]);
    assert_eq!(capture_group1(&sw_re, html), vec!["/sw.js"]);
}
