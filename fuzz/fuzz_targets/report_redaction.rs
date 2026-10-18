// fuzz/fuzz_targets/report_redaction.rs
//! Report export masking. Properties: building, masking and rendering a report
//! whose fields hold arbitrary text never panics in any of the eight formats,
//! and known secrets planted in those fields (plain text, a URL, a JSON
//! document) never reach the output. The report has no secret findings, whose
//! plaintext is kept on purpose, so every canary must be gone everywhere.
#![no_main]

use libfuzzer_sys::fuzz_target;
use webrev_core::{
    Confidence, Endpoint, EvidenceVerdict, Finding, FindingKind, Method, Mission, ProbeEvidence,
    Provenance, ResponseObservation, Scope, Source,
};
use webrev_report::{RenderOptions, ReportFormat, SessionReport};

const PASSWORD: &str = "Zk3Jq9XvLm2Rt7WpYb4Nc8";
const AWS_KEY: &str = "AKIAQ7ZXC9VB2NM4LK8P";
const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUlkxMjM0In0.c2lnbmF0dXJlQ0FOQVJZMTIz";
const SECRETS: [&str; 3] = [PASSWORD, AWS_KEY, JWT];

const FORMATS: [ReportFormat; 8] = [
    ReportFormat::Text,
    ReportFormat::Json,
    ReportFormat::Jsonl,
    ReportFormat::Urls,
    ReportFormat::Csv,
    ReportFormat::OpenApi,
    ReportFormat::Dot,
    ReportFormat::GraphMl,
];

/// Keep only characters that cannot change how the surrounding URL is split.
fn url_safe(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '-' | '_'))
        .take(256)
        .collect()
}

fn finding(mission: &Mission, kind: FindingKind, url: &str, value: String) -> Finding {
    Finding::new(
        mission.id,
        kind,
        Some(url.to_owned()),
        value,
        Confidence::High,
        Provenance::new(Source::JsAst, Some(url.to_owned())),
    )
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // A canary typed into the input bare, under a key name that is not a
    // credential name, is the documented heuristic gap (nothing marks a lone
    // 22-character string as a secret): the property is about planted secrets.
    if SECRETS.iter().any(|secret| text.contains(secret)) {
        return;
    }
    let noise = text.replace('\r', "");
    let safe = url_safe(&text);
    let url = format!(
        "https://user:{PASSWORD}@host.test/{safe}?tok={PASSWORD}&password={PASSWORD}#id_token={PASSWORD}"
    );
    let embedded = format!(
        "{noise}\nAuthorization: Bearer {JWT}\n{AWS_KEY}\napi_key=\"{PASSWORD}\"\nsession: {PASSWORD}\n{noise}"
    );
    let document = serde_json::json!({
        "noise": noise,
        "token": PASSWORD,
        "frames": [AWS_KEY, { "auth": format!("Bearer {JWT}") }],
        "url": url,
    })
    .to_string();

    let mission = Mission::new(
        embedded.clone(),
        Scope::new(vec!["host.test".into()], vec![]),
        vec![url.clone()],
    );
    let mut vulnerability = finding(&mission, FindingKind::Vulnerability, &url, embedded.clone());
    vulnerability.justification = embedded.clone();
    vulnerability.evidence = Some(Box::new(ProbeEvidence {
        check: "fuzz".into(),
        parameter: Some(embedded.clone()),
        verdict: EvidenceVerdict::Observed,
        observations: vec![ResponseObservation {
            role: "probe".into(),
            method: "GET".into(),
            url: url.clone(),
            status: 200,
            authenticated: false,
            content_type: "text/plain".into(),
            body_bytes: embedded.len(),
            excerpt: embedded.clone(),
        }],
        limitation: embedded.clone(),
    }));
    let frame = finding(
        &mission,
        FindingKind::WebSocketFrame,
        &url,
        document.clone(),
    );
    let coverage = finding(&mission, FindingKind::ScanCoverage, &url, document);
    let endpoints = vec![
        Endpoint::new(url.clone(), Method::Get, Source::JsAst),
        Endpoint::new(embedded, Method::Get, Source::JsAst),
    ];
    let report = SessionReport::build(mission, vec![vulnerability, frame, coverage], endpoints);

    for format in FORMATS {
        let opts = RenderOptions {
            format,
            ..RenderOptions::default()
        };
        let Ok(output) = report.render(opts) else {
            continue;
        };
        for secret in SECRETS {
            assert!(
                !output.contains(secret),
                "{format:?} export leaked {secret}: {output}"
            );
        }
    }
});
