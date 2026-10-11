use super::*;
use webrev_core::{Confidence, FindingKind, Provenance, SessionId, Source};
use webrev_pipeline::PipelineEvent;

fn app() -> App {
    App::new("m".into(), Scope::new(vec!["x.test".into()], vec![]))
}

fn endpoint_event() -> UiEvent {
    finding_event(FindingKind::Endpoint, Some("/api".into()), "GET /api")
}

fn finding_event(kind: FindingKind, url: Option<String>, value: &str) -> UiEvent {
    let f = Finding::new(
        SessionId::new(),
        kind,
        url,
        value,
        Confidence::High,
        Provenance::new(Source::JsAst, None),
    );
    UiEvent::Pipeline(PipelineEvent::Finding(Box::new(f)))
}

#[test]
fn tab_cycles_both_ways() {
    assert_eq!(Tab::Endpoints.next(), Tab::Findings);
    assert_eq!(Tab::Endpoints.prev(), Tab::Status);
}

#[test]
fn focused_views_keep_the_correct_records_after_filtering_and_sorting() {
    let mut app = app();
    app.apply(finding_event(
        FindingKind::Technology,
        None,
        "React (framework)",
    ));
    app.apply(finding_event(
        FindingKind::Vulnerability,
        Some("/search?q=probe".into()),
        "reflected parameter: possible XSS",
    ));
    app.apply(finding_event(
        FindingKind::Idor,
        Some("/users/123".into()),
        "anonymous success",
    ));
    app.apply(finding_event(FindingKind::Secret, None, "fp:fixture"));
    app.select_tab(Tab::Technologies);
    assert_eq!(app.visible_items().len(), 1);
    assert!(app.visible_items()[0].contains("React (framework)"));
    app.select_tab(Tab::Vulnerabilities);
    app.toggle_sort();
    assert_eq!(app.visible_items().len(), 2);
    assert_eq!(
        app.selected_record().unwrap().kind,
        FindingKind::Vulnerability
    );
    app.filter_push('X');
    assert_eq!(app.visible_items().len(), 1);
    assert_eq!(app.selected_record().unwrap().category(), "XSS");
    app.filter_cancel();
    app.select_tab(Tab::Secrets);
    assert_eq!(app.selected_record().unwrap().kind, FindingKind::Secret);
    assert_eq!(app.category_count("IDOR"), 1);
    assert_eq!(app.category_count("XSS"), 1);
}

#[test]
fn scan_completion_returns_the_ui_to_ready() {
    let mut app = app();
    app.scanning = true;
    app.apply(UiEvent::ScanFinished("active scan done".into()));
    assert!(!app.scanning);
    assert_eq!(app.status, "active scan done");
}

#[test]
fn endpoint_finding_lands_in_both_lists() {
    let mut app = app();
    app.apply(endpoint_event());
    assert_eq!(app.endpoints.len(), 1);
    assert_eq!(app.findings.len(), 1);
}

#[test]
fn endpoints_are_tagged_internal_vs_external() {
    let mut app = app();
    app.apply(finding_event(
        FindingKind::Endpoint,
        Some("https://x.test/a".into()),
        "GET https://x.test/a",
    ));
    app.apply(finding_event(
        FindingKind::Endpoint,
        Some("https://cdn.other/x".into()),
        "GET https://cdn.other/x",
    ));
    assert_eq!(app.internal_endpoints, 1);
    assert_eq!(app.external_endpoints, 1);
    // Lines lead with a severity tag, then the scope tag.
    assert!(app.endpoints[0].contains(" int "));
    assert!(app.endpoints[1].contains(" ext "));
}

#[test]
fn sort_by_severity_orders_high_first() {
    let mut app = app();
    // Info-level param, then a high-severity admin endpoint.
    app.apply(finding_event(FindingKind::Parameter, None, "q"));
    app.apply(finding_event(
        FindingKind::Endpoint,
        Some("https://x.test/admin".into()),
        "GET https://x.test/admin",
    ));
    app.select_tab(Tab::Findings);
    // Natural order: param first.
    assert!(app.visible_items()[0].starts_with("INFO"));
    app.toggle_sort();
    // Severity order: the admin endpoint (HIGH) leads.
    assert!(app.visible_items()[0].starts_with("HIGH"));
}

#[test]
fn selected_record_follows_filter_mapping() {
    let mut app = app();
    app.apply(finding_event(
        FindingKind::Endpoint,
        Some("https://x.test/login".into()),
        "GET https://x.test/login",
    ));
    app.apply(finding_event(
        FindingKind::Endpoint,
        Some("https://x.test/health".into()),
        "GET https://x.test/health",
    ));
    // Filter to the second item; the selection must resolve to its record.
    app.begin_filter();
    for c in "health".chars() {
        app.filter_push(c);
    }
    let record = app.selected_record().expect("a selected record");
    assert!(record.value.contains("/health"));
    // Detail opens only when something is selected.
    app.toggle_detail();
    assert!(app.show_detail);
}

#[test]
fn revealed_secret_shows_plaintext_in_log_and_findings() {
    let mut app = app();
    // The store stage emits a SecretDetected carrying the plaintext.
    app.apply(UiEvent::Pipeline(PipelineEvent::SecretDetected {
        fingerprint: "fp:deadbeefdeadbeef".into(),
        plaintext: Some("AKIAZ4XB7NMPQR2STUVW".into()),
    }));
    assert_eq!(app.secrets, 1);
    assert!(app
        .logs
        .iter()
        .any(|l| l == "[secret] fp:deadbeefdeadbeef = AKIAZ4XB7NMPQR2STUVW"));

    // And the finding line surfaces it inline too.
    let f = Finding::new(
        SessionId::new(),
        FindingKind::Secret,
        None,
        "fp:deadbeefdeadbeef",
        Confidence::High,
        Provenance::new(Source::JsRegex, None),
    )
    .with_plaintext(Some("AKIAZ4XB7NMPQR2STUVW".into()));
    app.apply(UiEvent::Pipeline(PipelineEvent::Finding(Box::new(f))));
    assert!(app
        .findings
        .last()
        .unwrap()
        .contains("AKIAZ4XB7NMPQR2STUVW"));
}

#[test]
fn fingerprint_only_secret_omits_plaintext() {
    let mut app = app();
    app.apply(UiEvent::Pipeline(PipelineEvent::SecretDetected {
        fingerprint: "fp:cafebabecafebabe".into(),
        plaintext: None,
    }));
    assert!(app.logs.iter().any(|l| l == "[secret] fp:cafebabecafebabe"));
    assert!(app.logs.iter().all(|l| !l.contains(" = ")));
}

#[test]
fn filter_narrows_visible_items() {
    let mut app = app();
    app.apply(finding_event(
        FindingKind::Endpoint,
        Some("https://x.test/login".into()),
        "GET https://x.test/login",
    ));
    app.apply(finding_event(
        FindingKind::Endpoint,
        Some("https://x.test/assets/app.js".into()),
        "GET https://x.test/assets/app.js",
    ));
    assert_eq!(app.visible_items().len(), 2);

    app.begin_filter();
    for c in "login".chars() {
        app.filter_push(c);
    }
    assert_eq!(app.visible_items().len(), 1);
    assert!(app.visible_items()[0].contains("login"));

    app.filter_cancel();
    assert_eq!(app.visible_items().len(), 2);
}

#[test]
fn follow_tail_tracks_newest_then_releases_on_scroll_up() {
    let mut app = app();
    app.apply(endpoint_event());
    app.apply(endpoint_event());
    // Following: selection pinned to the last item.
    assert_eq!(app.list_state.selected(), Some(1));

    app.scroll_up();
    assert_eq!(app.list_state.selected(), Some(0));
    // A new arrival no longer moves the selection while scrolled up.
    app.apply(endpoint_event());
    assert_eq!(app.list_state.selected(), Some(0));

    // Jumping back to the bottom re-enables follow.
    app.scroll_to_bottom();
    assert_eq!(app.list_state.selected(), Some(2));
}
