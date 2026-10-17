use super::{fixture::path, *};

#[tokio::test]
async fn unsuccessful_requests_still_consume_shared_budget() {
    let fixture = Fixture::new(|_| Reply::html("public page"));
    let mut opsec = config();
    opsec.active.max_requests = 7;
    let findings = scan(&fixture, &["/search?q=hello"], &opsec).await;
    let run = coverage(&findings);
    assert_eq!(run.requests, 7);
    assert!(fixture.requests.lock().unwrap().len() <= 7);
    assert!(run.responses > 0);
    assert!(run.budget_exhausted && !run.complete());
}

#[tokio::test]
async fn concurrent_targets_cannot_overshoot_shared_request_budget() {
    let fixture = Fixture::new(|_| Reply {
        delay_ms: 10,
        ..Reply::html("ordinary page")
    });
    let mut opsec = config();
    opsec.active.max_requests = 3;
    let paths: Vec<String> = (0..30).map(|i| format!("/page{i}?q=x")).collect();
    let findings = scan(
        &fixture,
        &paths.iter().map(String::as_str).collect::<Vec<_>>(),
        &opsec,
    )
    .await;
    let run = coverage(&findings);
    let received = fixture.requests.lock().unwrap().len();
    assert!(run.budget_exhausted);
    assert!(run.requests <= 3);
    assert!(received <= 3, "wire requests {received} exceeded budget 3");
}

#[tokio::test]
async fn active_http_client_resolves_and_connects_through_pinned_dns() {
    let fixture = Fixture::new(|_| Reply::html("ordinary page"));
    let url = fixture.origin.replacen("127.0.0.1", "localhost", 1);
    let endpoint = Endpoint::new(url, Method::Get, Source::Html);
    let findings = run_active_scan(
        &config(),
        &Scope::new(vec!["localhost".into()], vec![]),
        SessionId::new(),
        &[endpoint],
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(!fixture.requests.lock().unwrap().is_empty());
    assert!(coverage(&findings).requests > 0);
}

#[tokio::test]
async fn cidr_scope_never_connects_when_local_dns_is_outside_range() {
    let fixture = Fixture::new(|_| Reply::html("must not be reached"));
    let url = fixture.origin.replacen("127.0.0.1", "localhost", 1);
    let endpoint = Endpoint::new(url, Method::Get, Source::Html);
    let mut opsec = config();
    opsec.active.max_requests = 1;
    let findings = run_active_scan(
        &opsec,
        &Scope::new(vec!["192.0.2.0/24".into()], vec![]),
        SessionId::new(),
        &[endpoint],
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(coverage(&findings).transport_errors > 0);
}

#[tokio::test]
async fn zero_budget_never_connects_and_records_incomplete_coverage() {
    let fixture = Fixture::new(|_| panic!("zero budget must never connect"));
    let mut opsec = config();
    opsec.active.max_requests = 0;
    let findings = scan(&fixture, &["/"], &opsec).await;
    assert_eq!(coverage(&findings).requests, 0);
    assert!(coverage(&findings).budget_exhausted);
}

#[tokio::test]
async fn coverage_distinguishes_selected_negative_and_unselected_checks() {
    let fixture = Fixture::new(|_| Reply::html("ordinary page"));
    let findings = scan(&fixture, &["/page?q=hello"], &config()).await;
    let run = coverage(&findings);
    let origin = &run.checks["origin"];
    assert_eq!(origin.attempted, 1);
    assert_eq!(origin.executed, 1);
    assert_eq!(origin.findings, 0);
    assert!(run.checks["path_traversal"].not_selected > 0);
    assert!(run.checks["parameter_fuzz"].executed > 0);
}

#[tokio::test]
async fn transport_retries_are_counted_and_stop_at_the_same_budget() {
    let fixture = Fixture::new(|_| Reply {
        status: 0,
        ..Reply::html("")
    });
    let mut opsec = config();
    opsec.active.max_requests = 3;
    let findings = scan(&fixture, &["/"], &opsec).await;
    let run = coverage(&findings);
    assert_eq!(run.requests, 3);
    assert_eq!(run.transport_errors, 3);
    assert_eq!(run.responses, 0);
    assert!(run.budget_exhausted && !run.complete());
    let received = fixture.requests.lock().unwrap().len();
    assert!(received > 0 && received <= 3);
}

#[tokio::test]
async fn oversized_body_is_inconclusive_instead_of_a_partial_positive() {
    let fixture = Fixture::new(|_| Reply::html("sqlstate[42000]".repeat(128)));
    let mut opsec = config();
    opsec.active.max_body_bytes = 64;
    let findings = scan(&fixture, &["/search?q=hello"], &opsec).await;
    assert!(coverage(&findings).oversized_responses > 0);
    assert!(!coverage(&findings).complete());
    assert!(!findings.iter().any(Finding::is_vulnerability));
}

#[tokio::test]
async fn cancellation_interrupts_an_inflight_response() {
    let fixture = Fixture::new(|_| Reply {
        delay_ms: 800,
        ..Reply::html("page")
    });
    let opsec = config();
    let cancel = CancellationToken::new();
    let cancelled = cancel.clone();
    let received = fixture.requests.clone();
    tokio::spawn(async move {
        while received.lock().unwrap().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        cancelled.cancel();
    });
    let endpoints = vec![Endpoint::new(
        format!("{}/", fixture.origin),
        Method::Get,
        Source::Html,
    )];
    let findings = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        run_active_scan(
            &opsec,
            &Scope::new(vec!["127.0.0.1".into()], vec![]),
            SessionId::new(),
            &endpoints,
            cancel,
        ),
    )
    .await
    .expect("cancel must interrupt HTTP")
    .unwrap();
    assert!(coverage(&findings).cancelled);
    assert!(coverage(&findings).requests >= 1);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn method_scope_and_redirect_boundaries_apply_before_network() {
    let sink = Fixture::new(|_| Reply::html("redirect destination"));
    let destination = format!("{}/outside", sink.origin);
    let fixture = Fixture::new(move |_| Reply {
        status: 302,
        headers: vec![("Location".into(), destination.clone())],
        ..Reply::html("redirect")
    });
    let endpoints = vec![
        Endpoint::new(
            format!("{}/mutate?q=x", fixture.origin),
            Method::Post,
            Source::Html,
        ),
        Endpoint::new("http://outside.invalid/api?q=x", Method::Get, Source::Html),
        Endpoint::new(format!("{}/", fixture.origin), Method::Get, Source::Html),
    ];
    let findings = run_active_scan(
        &config(),
        &Scope::new(vec!["127.0.0.1".into()], vec![]),
        SessionId::new(),
        &endpoints,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(coverage(&findings).out_of_scope, 1);
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| !path(r).starts_with("/mutate")));
    assert!(coverage(&findings).responses > 0);
    assert_eq!(
        sink.requests.lock().unwrap().len(),
        0,
        "redirect destination must never receive a request"
    );
}

#[tokio::test]
async fn per_target_and_parameter_caps_apply_even_without_findings() {
    let fixture = Fixture::new(|_| Reply::html("public page"));
    let mut opsec = config();
    opsec.active = ActiveLimits {
        max_requests: 1000,
        max_parameters: 1,
        ..ActiveLimits::default()
    };
    let paths: Vec<String> = (0..20)
        .map(|i| format!("/search{i}?q=hello&extra=untested"))
        .collect();
    let findings = scan(
        &fixture,
        &paths.iter().map(String::as_str).collect::<Vec<_>>(),
        &opsec,
    )
    .await;
    let run = coverage(&findings);
    assert!(run.target_limit_reached && run.parameter_limit_reached);
    assert_eq!(run.checks["parameter_fuzz"].attempted, 15);
    assert_eq!(run.checks["template_arithmetic"].attempted, 15);
    assert!(!run.complete());
}
