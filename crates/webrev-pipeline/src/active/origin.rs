//! Origin-level checks with response evidence and content-aware exposure tests.
use super::{
    client::vuln_finding,
    evidence::attach,
    headers::{check_cookie_flags, check_security_headers},
    transport::ProbeClient,
};
use webrev_core::{Confidence, EvidenceVerdict, Finding, SessionId};

const SENSITIVE_PATHS: &[&str] = &[
    ".env",
    ".git/HEAD",
    ".git/config",
    ".DS_Store",
    "backup.zip",
    "config.php.bak",
];
pub(super) const NONEXISTENT_PROBE_PATH: &str = "__webrev_probe_9f3aqxnever__";

pub(super) async fn check_cors(
    client: &ProbeClient<'_>,
    url: &str,
    session: SessionId,
) -> Option<Finding> {
    let probe_origin = format!("https://wrv-{:016x}.invalid", rand::random::<u64>());
    let response = client.get(url, true, Some(&probe_origin)).await?;
    if !response.status.is_success() {
        return None;
    }
    let acao = response
        .headers
        .get("access-control-allow-origin")?
        .to_str()
        .ok()?;
    if acao != probe_origin {
        return None;
    }
    let credentials = response
        .headers
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    // Public credentialless CORS reflection alone is not an access-control flaw.
    if !credentials {
        return None;
    }
    Some(attach(
        vuln_finding(session, url, "CORS misconfiguration: arbitrary Origin reflected with credentials allowed", Confidence::High),
        "credentialed_cors", None, EvidenceVerdict::Observed,
        vec![response.observation("origin_probe", &format!("Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: true"))],
        "Headers permit credentialed CORS; sensitive data access depends on browser credential policy and response contents.",
    ))
}

pub(super) fn sensitive_signature(path: &str, bytes: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(bytes);
    let lower = text.trim_start().to_ascii_lowercase();
    if lower.starts_with("<!doctype html") || lower.starts_with("<html") {
        return None;
    }
    match path {
        ".git/HEAD"
            if text.trim().starts_with("ref: refs/")
                || (text.trim().len() == 40
                    && text.trim().bytes().all(|b| b.is_ascii_hexdigit())) =>
        {
            Some("Git HEAD structure")
        }
        ".git/config" if lower.contains("[core]") && lower.contains("repositoryformatversion") => {
            Some("Git configuration structure")
        }
        ".DS_Store" if bytes.starts_with(b"\0\0\0\x01Bud1") => Some("DS_Store magic"),
        "backup.zip" if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") => {
            Some("ZIP magic")
        }
        "config.php.bak"
            if lower.contains("<?php")
                && (lower.contains("password")
                    || lower.contains("db_")
                    || lower.contains("define(")) =>
        {
            Some("PHP configuration source")
        }
        ".env"
            if text.lines().any(|line| {
                let Some((key, _)) = line.trim().trim_start_matches("export ").split_once('=')
                else {
                    return false;
                };
                let key = key.trim();
                !key.is_empty()
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                    && [
                        "KEY", "SECRET", "TOKEN", "PASSWORD", "DATABASE", "DB_", "APP_",
                    ]
                    .iter()
                    .any(|s| key.contains(s))
            }) =>
        {
            Some("environment configuration assignment")
        }
        _ => None,
    }
}

pub(super) async fn check_sensitive_files(
    client: &ProbeClient<'_>,
    origin: &str,
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let baseline_url = format!("{origin}/{NONEXISTENT_PROBE_PATH}");
    let Some(baseline) = client.get(&baseline_url, true, None).await else {
        return findings;
    };
    for path in SENSITIVE_PATHS {
        if client.stopped() {
            break;
        }
        let url = format!("{origin}/{path}");
        let Some(response) = client.get(&url, true, None).await else {
            continue;
        };
        if !response.status.is_success() || response.bytes == baseline.bytes {
            continue;
        }
        let Some(signature) = sensitive_signature(path, &response.bytes) else {
            continue;
        };
        findings.push(attach(
            vuln_finding(session, &url, format!("exposed sensitive file: {path} ({signature})"), Confidence::High),
            "sensitive_file", None, EvidenceVerdict::Observed,
            vec![baseline.observation("nonexistent_path_control", ""), response.observation("file_probe", &response.text())],
            "File structure matches the requested resource; authentication was retained when configured. Impact depends on actual content.",
        ));
    }
    findings
}

pub(super) async fn check_origin(
    client: &ProbeClient<'_>,
    origin: &str,
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let root = format!("{origin}/");
    if let Some(response) = client.get(&root, true, None).await {
        let mut observations = check_cookie_flags(
            &response.headers,
            origin.starts_with("https://"),
            &root,
            session,
        );
        observations.extend(check_security_headers(
            &response.headers,
            origin.starts_with("https://"),
            &root,
            session,
        ));
        findings.extend(observations.into_iter().map(|f| attach(f, "headers_and_cookies", None, EvidenceVerdict::Observed,
            vec![response.observation("baseline", "")], "Header and cookie observations are advisory; application exploitability was not tested.")));
    }
    findings.extend(check_cors(client, &root, session).await);
    findings.extend(check_sensitive_files(client, origin, session).await);
    findings
}
