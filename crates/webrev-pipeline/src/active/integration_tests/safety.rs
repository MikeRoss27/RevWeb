//! Non-destructiveness: default active/BOLA behavior on loopback fixtures.
use super::*;

fn request_lines(fixture: &Fixture) -> Vec<String> {
    fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.lines().next().unwrap_or("").to_owned())
        .collect()
}

#[tokio::test]
async fn every_default_active_request_is_a_get_without_internal_targets() {
    let fixture = Fixture::new(|_| Reply::html("ordinary page"));
    let mut opsec = config();
    opsec.auth = AuthConfig {
        cookies: vec![("sid".into(), "a".into())],
        ..AuthConfig::default()
    };
    let findings = scan(
        &fixture,
        &[
            "/page?q=hello&next=/home&file=a.txt&target=https://ok.test/x",
            "/api/users/101",
            "/graphql",
        ],
        &opsec,
    )
    .await;
    let lines = request_lines(&fixture);
    assert!(lines.len() > 10, "probes ran: {}", lines.len());
    let requests = fixture.requests.lock().unwrap();
    for (line, request) in lines.iter().zip(requests.iter()) {
        // The one documented exception (`docs/security.md`, "Probe
        // behavior"): a fixed, literal GraphQL introspection query, sent as
        // a POST only because this fixture's plain-HTML responses never
        // satisfy introspection over GET. Every other probe stays GET.
        let is_graphql_introspection_post =
            line.starts_with("POST ") && request.contains("IntrospectionQuery");
        assert!(
            line.starts_with("GET ") || is_graphql_introspection_post,
            "unexpected non-GET probe sent: {line}"
        );
        for internal in [
            "169.254",
            "metadata",
            "localhost",
            "127.0.0.1",
            "[::1]",
            "file://",
        ] {
            assert!(!line.contains(internal), "internal target in {line}");
        }
    }
    // No request carries a body — i.e. no `Content-Length` header — except
    // the one documented GraphQL introspection POST exception above.
    assert!(requests.iter().all(|r| {
        r.contains("IntrospectionQuery") || !r.to_ascii_lowercase().contains("content-length:")
    }));
    drop(requests);
    assert!(coverage(&findings).requests > 0);
}

#[tokio::test]
async fn destructive_looking_endpoints_are_refused_and_recorded_not_sent() {
    let fixture = Fixture::new(|_| Reply::html("ordinary page"));
    let findings = scan(
        &fixture,
        &[
            "/logout",
            "/account/delete?id=3",
            "/app?action=unsubscribe&id=1",
            "/page?q=hello",
        ],
        &config(),
    )
    .await;
    for line in request_lines(&fixture) {
        assert!(
            !line.contains("logout") && !line.contains("delete") && !line.contains("unsubscribe"),
            "destructive URL reached the wire: {line}"
        );
    }
    let run = coverage(&findings);
    let guard = &run.checks["destructive_url_guard"];
    assert_eq!(guard.refused, 3);
    assert_eq!(guard.not_executed, 3);
    assert_eq!(guard.executed, 0);
    assert!(guard.inconclusive > 0);
    assert!(!run.complete(), "refusal must never read as a clean scan");
    let record = findings.iter().find(|f| f.coverage.is_some()).unwrap();
    assert_eq!(record.status, webrev_core::FindingStatus::Inconclusive);
}

#[tokio::test]
async fn scan_of_only_destructive_endpoints_sends_nothing_and_is_incomplete() {
    let fixture = Fixture::new(|_| panic!("must never connect"));
    let findings = scan(&fixture, &["/logout", "/delete?id=1"], &config()).await;
    let run = coverage(&findings);
    assert_eq!(run.requests, 0);
    assert!(!run.complete());
    assert!(!findings.iter().any(Finding::is_vulnerability));
}

#[tokio::test]
async fn failed_baseline_is_inconclusive_not_secure() {
    let fixture = Fixture::new(|_| Reply {
        status: 500,
        ..Reply::html("error")
    });
    let findings = scan(&fixture, &["/search?q=hello"], &config()).await;
    let run = coverage(&findings);
    assert!(run.checks["parameter_fuzz"].inconclusive > 0);
    assert_eq!(run.checks["parameter_fuzz"].negative, 0);
    assert!(!run.complete());
}

#[tokio::test]
async fn bola_refuses_destructive_candidate_urls_before_any_request() {
    let fixture = Fixture::new(|_| panic!("destructive BOLA candidate must never connect"));
    let candidate = BolaCandidate {
        route: "/api/users/{id}/delete".into(),
        account_a_url: format!("{}/api/users/101/delete", fixture.origin),
        account_b_url: format!("{}/api/users/202/delete", fixture.origin),
    };
    let account = |sid: &str| AuthConfig {
        cookies: vec![("sid".into(), sid.into())],
        ..AuthConfig::default()
    };
    let findings = run_bola_scan(
        &config(),
        &Scope::new(vec!["127.0.0.1".into()], vec![]),
        SessionId::new(),
        &account("a"),
        &account("b"),
        &[candidate],
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let run = coverage(&findings);
    assert_eq!(run.requests, 0);
    assert_eq!(run.checks["destructive_url_guard"].refused, 1);
    assert!(!run.complete());
}
