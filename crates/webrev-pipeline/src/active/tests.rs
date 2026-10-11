use super::access::response_shape;
use super::urls::{mutate_parameter, query_parameters};
use super::*;

#[test]
fn origin_of_strips_path_and_query() {
    assert_eq!(
        origin_of("https://ex.com:8443/a/b?x=1"),
        Some("https://ex.com:8443".to_owned())
    );
    assert_eq!(origin_of("not a url"), None);
}

#[test]
fn query_positions_decode_names_without_changing_other_pairs() {
    let url = "https://ex.com/a?q=hello&token=a%2Bb%2Fc&x=a+b&q=other";
    let pairs = query_parameters(url);
    assert_eq!(pairs[1], ("token".into(), "a+b/c".into()));
    assert_eq!(pairs[2], ("x".into(), "a b".into()));
    assert_eq!(
        mutate_parameter(url, 3, "1'><wrv").unwrap(),
        "https://ex.com/a?q=hello&token=a%2Bb%2Fc&x=a+b&q=1%27%3E%3Cwrv"
    );
    assert_eq!(query_parameters("https://ex.com/#ignore?q=x"), []);
    assert_eq!(query_parameters("https://ex.com/?x=1&&y=2").len(), 3);
}

#[test]
fn identifier_segment_detects_numeric_and_uuid() {
    assert!(has_identifier_segment("https://ex.com/users/42"));
    assert!(has_identifier_segment(
        "https://ex.com/orders/550e8400-e29b-41d4-a716-446655440000"
    ));
    assert!(!has_identifier_segment("https://ex.com/about"));
}

#[test]
fn response_shape_ignores_digits_and_whitespace_but_not_structure() {
    let a = response_shape(r#"{"id": 42, "name": "x"}"#);
    let b = response_shape(r#"{"id":  9001, "name": "x"}"#);
    assert_eq!(a, b);
    let unauthorized = response_shape(r#"{"error":"unauthorized"}"#);
    assert_ne!(a, unauthorized);
}

#[test]
fn api_endpoint_heuristic() {
    assert!(looks_like_api_endpoint("https://ex.com/api/users"));
    assert!(looks_like_api_endpoint("https://ex.com/data.json"));
    assert!(looks_like_api_endpoint("https://ex.com/search?q=x"));
    assert!(!looks_like_api_endpoint("https://ex.com/about"));
}

#[test]
fn active_scan_respects_fail_closed_egress() {
    let opsec = OpsecConfig {
        egress: webrev_core::EgressPolicy {
            proxy: None,
            allow_direct: false,
        },
        ..OpsecConfig::default()
    };
    let scope = Scope::new(vec!["ex.com".into()], vec![]);
    let result = tokio_test_block_on(run_active_scan(
        &opsec,
        &scope,
        SessionId::new(),
        &[],
        CancellationToken::new(),
    ));
    assert!(result.is_err());
}

// Minimal blocking helper so this one test doesn't need a `#[tokio::test]`
// runtime just to exercise a synchronous early-return path.
fn tokio_test_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(fut)
}

#[test]
fn cookie_values_cannot_spoof_cookie_attributes() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "set-cookie",
        "session=secure-httponly-samesite".parse().unwrap(),
    );
    let findings =
        super::headers::check_cookie_flags(&headers, true, "https://x/", SessionId::new());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].value.contains("Secure/HttpOnly/SameSite"));
}
