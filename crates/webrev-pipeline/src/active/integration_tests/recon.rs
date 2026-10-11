//! Wire-level regression fixtures for the recon-style active checks.
use super::{fixture::path, *};

fn has_value(findings: &[Finding], needle: &str) -> bool {
    findings
        .iter()
        .any(|f| f.is_vulnerability() && f.value.contains(needle))
}

#[tokio::test]
async fn path_traversal_requires_a_system_file_body_not_just_a_file_param() {
    let fixture = Fixture::new(|request| {
        if request.contains("passwd") {
            Reply::html("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin")
        } else {
            Reply::html("<html>download portal</html>")
        }
    });
    let findings = scan(&fixture, &["/download?file=report.pdf"], &config()).await;
    assert!(has_value(
        &findings,
        "possible path traversal / local file inclusion"
    ));
    let proof = findings
        .iter()
        .find(|f| f.value.contains("path traversal"))
        .and_then(|f| f.evidence.as_ref())
        .unwrap();
    assert_eq!(proof.verdict, webrev_core::EvidenceVerdict::Observed);
    assert_eq!(proof.check, "path_traversal");
}

#[tokio::test]
async fn traversal_without_a_matching_body_is_not_reported() {
    let fixture = Fixture::new(|_| Reply::html("<html>enter the path to a file</html>"));
    let findings = scan(&fixture, &["/view?path=home"], &config()).await;
    assert!(!has_value(&findings, "path traversal"));
}

#[tokio::test]
async fn crlf_is_only_reported_when_the_injected_header_appears() {
    let fixture = Fixture::new(|request| {
        let mut reply = Reply::html("ok");
        if request.to_ascii_lowercase().contains("x-webrev-injected") {
            reply.headers.push(("X-Webrev-Injected".into(), "1".into()));
        }
        reply
    });
    let findings = scan(&fixture, &["/page?q=home"], &config()).await;
    assert!(has_value(&findings, "possible CRLF / header injection"));

    // A server that never splits the header yields no CRLF finding.
    let safe = Fixture::new(|_| Reply::html("ok"));
    let findings = scan(&safe, &["/page?q=home"], &config()).await;
    assert!(!has_value(&findings, "CRLF"));
}

#[tokio::test]
async fn ssrf_sink_is_a_low_signal_for_a_reflected_external_url() {
    let fixture = Fixture::new(|request| {
        let value = super::fixture::query(request)
            .into_iter()
            .find(|(name, _)| name == "url")
            .map(|(_, v)| v)
            .unwrap_or_default();
        Reply::html(format!("<html>fetching {value}</html>"))
    });
    let findings = scan(&fixture, &["/proxy?url=https://origin.example/"], &config()).await;
    let ssrf = findings
        .iter()
        .find(|f| f.value.contains("possible SSRF sink"))
        .expect("ssrf signal");
    assert_eq!(ssrf.confidence, Confidence::Low);
    assert_eq!(
        ssrf.evidence.as_ref().unwrap().verdict,
        webrev_core::EvidenceVerdict::Signal
    );
    // The probe must never request an internal/metadata host.
    let requests = fixture.requests.lock().unwrap();
    assert!(requests
        .iter()
        .all(|r| !r.contains("169.254.169.254") && !r.to_ascii_lowercase().contains("localhost")));
    assert!(requests.iter().any(|r| r.contains(".invalid")));
}

#[tokio::test]
async fn prototype_pollution_signal_on_a_server_error() {
    let fixture = Fixture::new(|request| {
        if request.contains("webrevpp") {
            Reply {
                status: 500,
                ..Reply::html("internal error")
            }
        } else {
            Reply::html("ok")
        }
    });
    let findings = scan(&fixture, &["/api?x=1"], &config()).await;
    let pp = findings
        .iter()
        .find(|f| f.value.contains("possible prototype pollution"))
        .expect("prototype pollution signal");
    assert_eq!(pp.confidence, Confidence::Low);
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.contains("__proto__") || r.contains("constructor")));
}

#[tokio::test]
async fn graphql_introspection_detected_over_get() {
    let fixture = Fixture::new(|request| {
        if path(request).contains("__schema") {
            Reply::json(r#"{"data":{"__schema":{"types":[{"name":"Query"}]}}}"#)
        } else {
            Reply::json(r#"{"errors":["missing query"]}"#)
        }
    });
    let findings = scan(&fixture, &["/graphql"], &config()).await;
    assert!(has_value(&findings, "graphql introspection enabled"));
}

#[tokio::test]
async fn subdomain_takeover_fingerprinted_at_the_origin_root() {
    let fixture = Fixture::new(|_| Reply::html("There isn't a GitHub Pages site here."));
    let findings = scan(&fixture, &["/"], &config()).await;
    let takeover = findings
        .iter()
        .find(|f| f.value.contains("possible subdomain takeover"))
        .expect("takeover signal");
    assert!(takeover.value.contains("GitHub Pages"));
    assert_eq!(takeover.severity(), webrev_core::Severity::High);
}
