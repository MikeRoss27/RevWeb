use super::discovery::resolve_url;
use super::request::{parse_retry_after, MAX_RETRY_AFTER};
use super::*;
use std::time::Duration;
use webrev_core::Scope;

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
