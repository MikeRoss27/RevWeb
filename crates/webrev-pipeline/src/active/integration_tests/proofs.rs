use super::{
    fixture::{evaluate_arithmetic, path, query},
    *,
};

#[tokio::test]
async fn arithmetic_requires_two_results_and_payload_free_control() {
    let fixture = Fixture::new(|request| {
        if path(request).starts_with("/render?") {
            Reply::html(
                query(request)
                    .iter()
                    .map(|(_, v)| evaluate_arithmetic(v))
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        } else {
            Reply::html("<html>public page</html>")
        }
    });
    let findings = scan(&fixture, &["/render?template=hello"], &config()).await;
    let ssti = findings.iter().find(|f| f.category() == "SSTI").unwrap();
    let proof = ssti.evidence.as_ref().unwrap();
    assert_eq!(
        proof.verdict,
        webrev_core::EvidenceVerdict::EvaluationConfirmed
    );
    assert_eq!(proof.observations.len(), 4);
    assert_ne!(proof.observations[1].excerpt, proof.observations[2].excerpt);
    assert_eq!(proof.observations[3].role, "payload_free_control");
    assert!(ssti.assessment().contains("RCE not established"));
    assert!(coverage(&findings).requests >= fixture.requests.lock().unwrap().len());
}

#[tokio::test]
async fn reflection_and_json_are_not_expression_execution_or_xss_proof() {
    let fixture =
        Fixture::new(|request| Reply::json(serde_json::to_string(&query(request)).unwrap()));
    let findings = scan(&fixture, &["/echo?q=hello"], &config()).await;
    assert!(!findings
        .iter()
        .any(|f| matches!(f.category(), "SSTI" | "XSS" | "SQLi")));
    let requests = fixture.requests.lock().unwrap();
    assert!(requests.iter().any(|r| r.contains("wrvFuzz")));
    assert!(requests.iter().any(|r| r.contains("wrvEval")));
    if coverage(&findings).transport_errors > 0 {
        assert!(!coverage(&findings).complete());
    }
}

#[tokio::test]
async fn cached_arithmetic_in_payload_free_control_is_inconclusive() {
    let cache = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let fixture = Fixture::new(move |request| {
        let params = query(request);
        let value = params.first().map_or("", |(_, v)| v.as_str());
        if value.contains("{{") || value.contains("${") {
            let calculated = evaluate_arithmetic(value);
            cache.lock().unwrap().push_str(&calculated);
            Reply::html(calculated)
        } else if value.starts_with("wrvEval") {
            Reply::html(cache.lock().unwrap().clone())
        } else {
            Reply::html("page")
        }
    });
    let findings = scan(&fixture, &["/render?q=hello"], &config()).await;
    assert!(!findings.iter().any(|f| f.category() == "SSTI"));
    assert!(coverage(&findings).checks["template_arithmetic"].inconclusive > 0);
    assert!(!coverage(&findings).complete());
}

#[tokio::test]
async fn refused_probe_is_not_a_positive_or_a_clean_scan() {
    let fixture = Fixture::new(|request| {
        let params = query(request);
        if params.iter().any(|(_, v)| v.contains("wrvFuzz")) {
            Reply {
                status: 403,
                ..Reply::html(format!("sqlstate[blocked] {}", params[0].1))
            }
        } else {
            Reply::html("page")
        }
    });
    let findings = scan(&fixture, &["/search?q=hello"], &config()).await;
    assert!(!findings
        .iter()
        .any(|f| matches!(f.category(), "XSS" | "SQLi")));
    assert!(coverage(&findings).refused_responses > 0);
    assert!(!coverage(&findings).complete());
}

#[tokio::test]
async fn html_and_sql_signals_are_attributed_to_one_parameter_preserving_other_pairs() {
    let fixture = Fixture::new(|request| {
        let params = query(request);
        let value = params
            .iter()
            .find(|(name, _)| name == "q")
            .map_or("", |(_, v)| v.as_str());
        if value.contains("wrvFuzz") {
            Reply::html(format!("sqlstate[42000] {value}"))
        } else {
            Reply::html("mysql_fetch appears in documentation")
        }
    });
    let findings = scan(
        &fixture,
        &["/search?q=hello&token=a%2Bb%2Fc&x=a+b&q=other"],
        &config(),
    )
    .await;
    let sql = findings.iter().find(|f| f.category() == "SQLi").unwrap();
    // A different pre-existing SQL signature must not hide a new SQLSTATE.
    assert!(sql.value.contains("sqlstate["));
    assert!(sql
        .url
        .as_ref()
        .unwrap()
        .contains("token=a%2Bb%2Fc&x=a+b&q=other"));
    assert_eq!(
        sql.evidence.as_ref().unwrap().parameter.as_deref(),
        Some("q (query position 1)")
    );
    assert!(findings
        .iter()
        .any(|f| f.category() == "XSS" && f.confidence == Confidence::Low));
}

#[tokio::test]
async fn dynamic_html_error_pages_do_not_fake_sensitive_files() {
    let fixture = Fixture::new(|request| {
        if path(request) == "/.git/HEAD" {
            Reply::html("ref: refs/heads/main\n")
        } else {
            Reply::html(format!(
                "<!doctype html><html>Missing {} {}</html>",
                path(request),
                "x".repeat(path(request).len() * 9)
            ))
        }
    });
    let findings = scan(&fixture, &["/"], &config()).await;
    let exposures: Vec<_> = findings
        .iter()
        .filter(|f| f.category() == "Exposure")
        .collect();
    assert_eq!(exposures.len(), 1);
    assert!(exposures[0].url.as_ref().unwrap().ends_with("/.git/HEAD"));
    assert_eq!(
        exposures[0].evidence.as_ref().unwrap().verdict,
        webrev_core::EvidenceVerdict::Observed
    );
}

#[tokio::test]
async fn anonymous_comparison_omits_all_headers_and_skips_query_credentials() {
    let fixture = Fixture::new(|request| {
        if path(request).starts_with("/api/users/") {
            Reply::json(r#"{"id":42,"name":"fixture"}"#)
        } else {
            Reply::html("public page")
        }
    });
    let mut opsec = config();
    opsec.auth = AuthConfig {
        cookies: vec![("session".into(), "fixture".into())],
        headers: vec![("X-API-Key".into(), "fixture-key".into())],
        bearer: Some("fixture-bearer".into()),
    };
    let findings = scan(
        &fixture,
        &["/api/users/42", "/api/users/43?access_token=fixture"],
        &opsec,
    )
    .await;
    let idors: Vec<_> = findings.iter().filter(|f| f.category() == "IDOR").collect();
    assert_eq!(idors.len(), 1);
    assert!(!idors[0].evidence.as_ref().unwrap().observations[1].authenticated);
    let requests = fixture.requests.lock().unwrap();
    let anonymous: Vec<_> = requests
        .iter()
        .filter(|r| {
            path(r) == "/api/users/42" && !r.to_ascii_lowercase().contains("authorization:")
        })
        .collect();
    assert_eq!(anonymous.len(), 1);
    assert!(!anonymous[0].to_ascii_lowercase().contains("cookie:"));
    assert!(!anonymous[0].to_ascii_lowercase().contains("x-api-key:"));
}

#[tokio::test]
async fn only_credentialed_cors_reflection_is_a_finding() {
    for credentials in [false, true] {
        let fixture = Fixture::new(move |request| {
            let mut reply = Reply::html("public page");
            if let Some(origin) = request.lines().find_map(|line| {
                line.split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("origin"))
                    .map(|(_, v)| v.trim())
            }) {
                reply
                    .headers
                    .push(("Access-Control-Allow-Origin".into(), origin.into()));
                if credentials {
                    reply
                        .headers
                        .push(("Access-Control-Allow-Credentials".into(), "true".into()));
                }
            }
            reply
        });
        let mut opsec = config();
        opsec
            .auth
            .headers
            .push(("Origin".into(), "https://mission-origin.invalid".into()));
        let findings = scan(&fixture, &["/"], &opsec).await;
        assert_eq!(findings.iter().any(|f| f.category() == "CORS"), credentials);
    }
}
