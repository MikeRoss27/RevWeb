use super::*;

fn auth(sid: &str) -> AuthConfig {
    AuthConfig {
        cookies: vec![("sid".into(), sid.into())],
        ..AuthConfig::default()
    }
}

async fn check_fixture(vulnerable: bool) -> (Vec<Finding>, Vec<String>) {
    let fixture = Fixture::new(move |request| {
        let path = fixture::path(request);
        let is_a = path == "/api/users/101";
        let is_b = path == "/api/users/202";
        let a_session = request.contains("sid=account-a");
        let b_session = request.contains("sid=account-b");
        if !vulnerable && ((is_a && !a_session) || (is_b && !b_session)) {
            let mut reply = Reply::json(r#"{"error":"forbidden"}"#);
            reply.status = 403;
            return reply;
        }
        if is_a {
            Reply::json(r#"{"id":101,"owner":"account-a","private":"alpha"}"#)
        } else if is_b {
            Reply::json(r#"{"id":202,"owner":"account-b","private":"bravo"}"#)
        } else {
            let mut reply = Reply::json(r#"{"error":"missing"}"#);
            reply.status = 404;
            reply
        }
    });
    let urls_a = vec![Endpoint::new(
        format!("{}/api/users/101", fixture.origin),
        Method::Get,
        Source::Browser,
    )];
    let urls_b = vec![Endpoint::new(
        format!("{}/api/users/202", fixture.origin),
        Method::Get,
        Source::Browser,
    )];
    let pairs = bola_candidates(&urls_a, &urls_b);
    assert_eq!(pairs.len(), 1);
    let findings = run_bola_scan(
        &config(),
        &Scope::new(vec!["127.0.0.1".into()], vec![]),
        SessionId::new(),
        &auth("account-a"),
        &auth("account-b"),
        &pairs,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    // Keep only the request line so a failure shows what reached the server.
    let requests = fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|request| request.lines().next().unwrap_or_default().to_owned())
        .collect();
    (findings, requests)
}

#[tokio::test]
async fn detects_readable_private_objects_with_four_controls() {
    let (findings, requests) = check_fixture(true).await;
    assert_eq!(
        requests.len(),
        4,
        "requests seen by the fixture: {requests:?}"
    );
    let signal = findings
        .iter()
        .find(|f| f.kind == FindingKind::Idor)
        .unwrap();
    assert_eq!(signal.evidence.as_ref().unwrap().observations.len(), 4);
    assert!(signal
        .evidence
        .as_ref()
        .unwrap()
        .observations
        .iter()
        .all(|o| o.excerpt.starts_with("sha256=")));
    // The proof is the content: the other account's read shows the object.
    let evidence = signal.evidence.as_ref().unwrap();
    let read = |role: &str| {
        evidence
            .observations
            .iter()
            .find(|o| o.role == role)
            .unwrap_or_else(|| panic!("no {role} observation"))
    };
    assert_eq!(
        read("B reads A object").body,
        r#"{"id":101,"owner":"account-a","private":"alpha"}"#
    );
    assert_eq!(
        read("A reads B object").body,
        r#"{"id":202,"owner":"account-b","private":"bravo"}"#
    );
    assert!(evidence.observations.iter().all(|o| !o.body_truncated));
    assert!(evidence
        .diff
        .contains(&r#"private: "alpha" ≠ "bravo""#.to_owned()));
    assert_eq!(coverage(&findings).requests, 4);
}

#[tokio::test]
async fn protected_objects_produce_no_bola_signal() {
    let (findings, requests) = check_fixture(false).await;
    assert_eq!(
        requests.len(),
        4,
        "requests seen by the fixture: {requests:?}"
    );
    assert!(!findings.iter().any(|f| f.kind == FindingKind::Idor));
}
