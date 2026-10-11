// crates/webrev-pipeline/src/active.rs
//! Lightweight active security checks run against endpoints already
//! discovered by static/dynamic recon (or, for a standalone run, the
//! mission seeds themselves).
//!
//! This is the only part of webrev that intentionally sends abnormal
//! traffic — injected characters, a spoofed `Origin`, a short list of
//! well-known sensitive paths — rather than passively observing. It stays
//! deliberately light: a handful of low-noise probes per target, hard
//! request budgets, and the same scope/jitter discipline as the rest of the
//! pipeline. It never issues a state-changing request (no POST/PUT/DELETE
//! probing) and never follows a redirect it injected itself.

use crate::stages::sleep_with_jitter;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use std::collections::BTreeSet;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use webrev_core::{
    Confidence, Endpoint, Finding, FindingKind, Method, OpsecConfig, Provenance, Result, Scope,
    SessionId, Source, WebrevError,
};

/// Hard per-request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Marker appended to fuzzed parameter values: unusual enough that any
/// occurrence in a response is effectively certain to be our own
/// reflection, not coincidental page content.
const FUZZ_MARKER: &str = "wrvFuzz9f3aQ<>";

/// Narrow, well-known error-based `SQLi` tells, checked after the fuzz probe.
/// Deliberately short to keep false positives low.
const SQL_ERROR_SIGNS: &[&str] = &[
    "sql syntax",
    "mysql_fetch",
    "ora-01756",
    "sqlite3::",
    "pg_query()",
    "unclosed quotation mark",
    "syntax error at or near",
    "odbc sql server driver",
    "sqlstate[",
    "pdoexception",
];

/// A handful of well-known sensitive paths, checked once per origin. This is
/// recon-grade confirmation, not a wordlist brute-forcer.
const SENSITIVE_PATHS: &[&str] = &[
    ".env",
    ".git/HEAD",
    ".git/config",
    ".DS_Store",
    "backup.zip",
    "config.php.bak",
];

/// A path that should never exist, used as a baseline so SPA catch-all
/// routes (which 200 on everything) don't make every sensitive path look
/// "found".
const NONEXISTENT_PROBE_PATH: &str = "__webrev_probe_9f3aqxnever__";

/// Query-parameter names that commonly carry a redirect target.
const REDIRECT_PARAM_NAMES: &[&str] = &[
    "redirect",
    "redirect_uri",
    "redirecturl",
    "return",
    "returnto",
    "return_to",
    "next",
    "url",
    "continue",
    "dest",
    "destination",
    "callback",
    "target",
];

/// Hard caps so active scanning stays light regardless of how many
/// endpoints recon discovered.
const MAX_FUZZ_TARGETS: usize = 15;
const MAX_IDOR_TARGETS: usize = 15;
const MAX_REDIRECT_TARGETS: usize = 15;

fn build_probe_client(opsec: &OpsecConfig) -> Result<reqwest::Client> {
    let ua = opsec
        .rotation
        .user_agent_for(0)
        .unwrap_or("webrev")
        .to_owned();
    let mut builder = reqwest::Client::builder()
        .user_agent(ua)
        .timeout(REQUEST_TIMEOUT)
        // Never follow a redirect ourselves: open-redirect detection reads
        // the raw `Location` header, and following one we injected would
        // send a request to an attacker-controlled-looking host.
        .redirect(Policy::none());
    if let Some(proxy) = &opsec.egress.proxy {
        let p = reqwest::Proxy::all(proxy)
            .map_err(|e| WebrevError::Config(format!("invalid proxy {proxy:?}: {e}")))?;
        builder = builder.proxy(p);
    }
    builder
        .build()
        .map_err(|e| WebrevError::Fetch(format!("building http client: {e}")))
}

fn apply_headers(
    mut req: reqwest::RequestBuilder,
    headers: &[(String, String)],
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            req = req.header(name, value);
        }
    }
    req
}

fn vuln_finding(
    session: SessionId,
    url: &str,
    value: impl Into<String>,
    confidence: Confidence,
) -> Finding {
    Finding::new(
        session,
        FindingKind::Vulnerability,
        Some(url.to_owned()),
        value,
        confidence,
        Provenance::new(Source::Active, None),
    )
}

fn idor_finding(session: SessionId, url: &str, value: impl Into<String>) -> Finding {
    Finding::new(
        session,
        FindingKind::Idor,
        Some(url.to_owned()),
        value,
        Confidence::Medium,
        Provenance::new(Source::Active, None),
    )
}

/// `scheme://host[:port]` prefix of a URL, or `None` if it has no scheme.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

/// Split a URL into its base (scheme+host+path) and decoded-enough query
/// pairs. Fragment is dropped, matching the rest of the crate's URL
/// handling (`fetch.rs::strip_fragment`).
fn split_query(url: &str) -> (&str, Vec<(&str, &str)>) {
    match url.split_once('?') {
        Some((base, rest)) => {
            let q = rest.split('#').next().unwrap_or(rest);
            let pairs = q
                .split('&')
                .filter(|s| !s.is_empty())
                .filter_map(|kv| {
                    let mut it = kv.splitn(2, '=');
                    let k = it.next()?;
                    Some((k, it.next().unwrap_or("")))
                })
                .collect();
            (base, pairs)
        }
        None => (url, Vec::new()),
    }
}

/// Minimal percent-encoding, sufficient for the ASCII probe characters this
/// module injects (quotes, angle brackets, braces).
fn urlencode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn rebuild_query(base: &str, pairs: &[(String, String)]) -> String {
    if pairs.is_empty() {
        return base.to_owned();
    }
    let q = pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{q}")
}

/// True when the path contains a segment that looks like a database id: an
/// all-digit segment, or a UUID.
fn has_identifier_segment(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path.split('/')
        .any(|seg| (!seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit())) || looks_like_uuid(seg))
}

fn looks_like_uuid(seg: &str) -> bool {
    let parts: Vec<&str> = seg.split('-').collect();
    parts.len() == 5
        && [8usize, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(&len, p)| p.len() == len && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Missing `Content-Security-Policy` / `X-Content-Type-Options` /
/// `X-Frame-Options` / (https-only) `Strict-Transport-Security`.
fn check_security_headers(
    headers: &reqwest::header::HeaderMap,
    is_https: bool,
    root: &str,
    session: SessionId,
) -> Option<Finding> {
    let mut missing = Vec::new();
    if !headers.contains_key("content-security-policy") {
        missing.push("Content-Security-Policy");
    }
    if !headers.contains_key("x-content-type-options") {
        missing.push("X-Content-Type-Options");
    }
    let csp_has_frame_ancestors = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("frame-ancestors"));
    if !headers.contains_key("x-frame-options") && !csp_has_frame_ancestors {
        missing.push("X-Frame-Options");
    }
    if is_https && !headers.contains_key("strict-transport-security") {
        missing.push("Strict-Transport-Security");
    }
    if missing.is_empty() {
        None
    } else {
        Some(vuln_finding(
            session,
            root,
            format!("missing security header(s): {}", missing.join(", ")),
            Confidence::High,
        ))
    }
}

/// `Set-Cookie` entries missing `Secure` (https-only) / `HttpOnly` / `SameSite`.
fn check_cookie_flags(
    headers: &reqwest::header::HeaderMap,
    is_https: bool,
    root: &str,
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for cookie in headers.get_all("set-cookie") {
        let Ok(c) = cookie.to_str() else { continue };
        let lc = c.to_ascii_lowercase();
        let name = c.split('=').next().unwrap_or(c).to_owned();
        let mut flags = Vec::new();
        if is_https && !lc.contains("secure") {
            flags.push("Secure");
        }
        if !lc.contains("httponly") {
            flags.push("HttpOnly");
        }
        if !lc.contains("samesite") {
            flags.push("SameSite");
        }
        if !flags.is_empty() {
            findings.push(vuln_finding(
                session,
                root,
                format!("cookie '{name}' missing {} flag(s)", flags.join("/")),
                Confidence::High,
            ));
        }
    }
    findings
}

/// Does the origin reflect an arbitrary `Origin` back in
/// `Access-Control-Allow-Origin`, with credentials allowed?
async fn check_cors(
    client: &reqwest::Client,
    auth_headers: &[(String, String)],
    root: &str,
    session: SessionId,
) -> Option<Finding> {
    const PROBE_ORIGIN: &str = "https://webrev-cors-probe.invalid";
    let cors_resp = apply_headers(client.get(root), auth_headers)
        .header("Origin", PROBE_ORIGIN)
        .send()
        .await
        .ok()?;
    let acao = cors_resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())?;
    if acao != PROBE_ORIGIN {
        return None;
    }
    let credentials_allowed = cors_resp
        .headers()
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let value = if credentials_allowed {
        "CORS misconfiguration: arbitrary Origin reflected with credentials allowed"
    } else {
        "CORS misconfiguration: arbitrary Origin reflected in Access-Control-Allow-Origin"
    };
    Some(vuln_finding(session, root, value, Confidence::High))
}

/// Sweep [`SENSITIVE_PATHS`], compared against a nonexistent-path baseline so
/// an SPA catch-all route (200s on everything) doesn't flag every path.
async fn check_sensitive_files(
    client: &reqwest::Client,
    auth_headers: &[(String, String)],
    origin: &str,
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let baseline_url = format!("{origin}/{NONEXISTENT_PROBE_PATH}");
    let baseline = apply_headers(client.get(&baseline_url), auth_headers)
        .send()
        .await
        .ok();
    let baseline_status = baseline.as_ref().map(|r| r.status().as_u16());
    let baseline_len = match baseline {
        Some(r) => r.text().await.unwrap_or_default().len(),
        None => 0,
    };
    for path in SENSITIVE_PATHS {
        let url = format!("{origin}/{path}");
        let Ok(resp) = apply_headers(client.get(&url), auth_headers).send().await else {
            continue;
        };
        let status = resp.status();
        let Ok(body) = resp.text().await else { continue };
        let looks_distinct =
            baseline_status != Some(status.as_u16()) || body.len().abs_diff(baseline_len) > 32;
        if status.is_success() && looks_distinct && !body.trim().is_empty() {
            findings.push(vuln_finding(
                session,
                &url,
                format!("exposed sensitive file: {path}"),
                Confidence::Medium,
            ));
        }
    }
    findings
}

/// Origin-level checks: missing security headers, cookie flags, CORS
/// reflection, and a short sensitive-file-exposure sweep. Run once per
/// unique origin, not per endpoint.
async fn check_origin(
    client: &reqwest::Client,
    auth_headers: &[(String, String)],
    origin: &str,
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let root = format!("{origin}/");
    let Ok(resp) = apply_headers(client.get(&root), auth_headers).send().await else {
        return findings;
    };
    let is_https = origin.starts_with("https://");
    let headers = resp.headers().clone();

    findings.extend(check_security_headers(&headers, is_https, &root, session));
    findings.extend(check_cookie_flags(&headers, is_https, &root, session));
    findings.extend(check_cors(client, auth_headers, &root, session).await);
    findings.extend(check_sensitive_files(client, auth_headers, origin, session).await);

    findings
}

/// Swap a redirect-shaped query parameter for a probe URL and check whether
/// the response redirects there without validation.
async fn check_open_redirect(
    client: &reqwest::Client,
    auth_headers: &[(String, String)],
    base: &str,
    params: &[(&str, &str)],
    session: SessionId,
) -> Option<Finding> {
    const PROBE_TARGET: &str = "https://webrev-redirect-probe.invalid/";
    let (redirect_key, _) = params
        .iter()
        .find(|(k, _)| REDIRECT_PARAM_NAMES.iter().any(|n| n.eq_ignore_ascii_case(k)))?;
    let mutated: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| {
            if k.eq_ignore_ascii_case(redirect_key) {
                ((*k).to_owned(), PROBE_TARGET.to_owned())
            } else {
                ((*k).to_owned(), (*v).to_owned())
            }
        })
        .collect();
    let url = rebuild_query(base, &mutated);
    let resp = apply_headers(client.get(&url), auth_headers).send().await.ok()?;
    if !resp.status().is_redirection() {
        return None;
    }
    let location = resp.headers().get("location")?.to_str().ok()?;
    if location.starts_with(PROBE_TARGET) {
        Some(vuln_finding(
            session,
            &url,
            format!("open redirect via '{redirect_key}' parameter (Location: {location})"),
            Confidence::High,
        ))
    } else {
        None
    }
}

/// Inject a single combined SQLi/reflection probe into every query
/// parameter at once and compare against an unmodified baseline response.
async fn check_param_fuzz(
    client: &reqwest::Client,
    auth_headers: &[(String, String)],
    original_url: &str,
    base: &str,
    params: &[(&str, &str)],
    session: SessionId,
) -> Option<Vec<Finding>> {
    let baseline_body = apply_headers(client.get(original_url), auth_headers)
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    let baseline_lower = baseline_body.to_ascii_lowercase();

    let fuzzed: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| ((*k).to_owned(), format!("{v}'><{FUZZ_MARKER}")))
        .collect();
    let url = rebuild_query(base, &fuzzed);
    let resp = apply_headers(client.get(&url), auth_headers).send().await.ok()?;
    let body = resp.text().await.ok()?;
    let lower = body.to_ascii_lowercase();

    let mut findings = Vec::new();
    let sql_error_signal = SQL_ERROR_SIGNS.iter().any(|sig| lower.contains(sig))
        && !SQL_ERROR_SIGNS.iter().any(|sig| baseline_lower.contains(sig));
    if sql_error_signal {
        findings.push(vuln_finding(
            session,
            &url,
            "possible SQL injection: database error signature returned after injecting a quote",
            Confidence::Medium,
        ));
    }
    if body.contains(FUZZ_MARKER) && !baseline_body.contains(FUZZ_MARKER) {
        findings.push(vuln_finding(
            session,
            &url,
            "reflected parameter: injected value echoed back unescaped (possible XSS, verify manually)",
            Confidence::Low,
        ));
    }
    if findings.is_empty() {
        None
    } else {
        Some(findings)
    }
}

/// IDOR-lite: does the same URL still return a successful, similarly-sized
/// response with no authentication material attached at all? This does not
/// require a second identity — just comparing "with the mission's auth" to
/// "with none".
async fn check_idor(
    client: &reqwest::Client,
    auth_headers: &[(String, String)],
    url: &str,
    session: SessionId,
) -> Option<Finding> {
    let authed = apply_headers(client.get(url), auth_headers).send().await.ok()?;
    if !authed.status().is_success() {
        return None;
    }
    let authed_len = authed.text().await.ok()?.len();

    let anon = client.get(url).send().await.ok()?;
    if !anon.status().is_success() {
        return None;
    }
    let anon_len = anon.text().await.ok()?.len();

    let close_enough = authed_len.abs_diff(anon_len) <= (authed_len / 10).max(16);
    if close_enough {
        Some(idor_finding(
            session,
            url,
            "resource returned a success response with no authentication/session material sent",
        ))
    } else {
        None
    }
}

/// Run the light active-scan battery against `endpoints`: origin-level
/// checks once per unique origin, then per-endpoint open-redirect, parameter
/// fuzzing, and IDOR-lite checks, all scope-checked and budget-capped.
///
/// Only ever issues safe (GET-shaped) requests — endpoints known to mutate
/// state (`POST`/`PUT`/`DELETE`/`PATCH`) are skipped entirely.
pub async fn run_active_scan(
    opsec: &OpsecConfig,
    scope: &Scope,
    session: SessionId,
    endpoints: &[Endpoint],
    cancel: CancellationToken,
) -> Result<Vec<Finding>> {
    // Fail-closed egress, matching the fetch stage and dynamic browser path.
    if opsec.egress.proxy.is_none() && !opsec.egress.allow_direct {
        return Err(WebrevError::Config(
            "egress policy forbids direct connections but no proxy is configured".into(),
        ));
    }

    let client = build_probe_client(opsec)?;
    let auth_headers = opsec.auth.effective_headers();
    let mut findings = Vec::new();

    let mut origins: BTreeSet<String> = BTreeSet::new();
    for ep in endpoints {
        if scope.allows(&ep.url) {
            if let Some(origin) = origin_of(&ep.url) {
                origins.insert(origin);
            }
        }
    }
    for origin in &origins {
        if cancel.is_cancelled() {
            return Ok(findings);
        }
        findings.extend(check_origin(&client, &auth_headers, origin, session).await);
        sleep_with_jitter(opsec, 0).await;
    }

    let mut fuzz_budget = MAX_FUZZ_TARGETS;
    let mut redirect_budget = MAX_REDIRECT_TARGETS;
    // IDOR-lite only makes sense when the mission is actually authenticated;
    // otherwise "no auth sent" vs "mission auth sent" is not a comparison.
    let mut idor_budget = if opsec.auth.is_empty() { 0 } else { MAX_IDOR_TARGETS };

    for ep in endpoints {
        if cancel.is_cancelled() {
            break;
        }
        if !scope.allows(&ep.url) {
            continue;
        }
        if matches!(
            ep.method,
            Method::Post | Method::Put | Method::Delete | Method::Patch
        ) {
            continue;
        }

        let (base, params) = split_query(&ep.url);

        if redirect_budget > 0 && !params.is_empty() {
            if let Some(f) = check_open_redirect(&client, &auth_headers, base, &params, session).await {
                findings.push(f);
                redirect_budget -= 1;
                sleep_with_jitter(opsec, 0).await;
            }
        }
        if fuzz_budget > 0 && !params.is_empty() {
            if let Some(fs) =
                check_param_fuzz(&client, &auth_headers, &ep.url, base, &params, session).await
            {
                findings.extend(fs);
                fuzz_budget -= 1;
                sleep_with_jitter(opsec, 0).await;
            }
        }
        if idor_budget > 0 && has_identifier_segment(&ep.url) {
            if let Some(f) = check_idor(&client, &auth_headers, &ep.url, session).await {
                findings.push(f);
                idor_budget -= 1;
                sleep_with_jitter(opsec, 0).await;
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
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
    fn split_query_parses_pairs() {
        let (base, pairs) = split_query("https://ex.com/a?x=1&y=two&z");
        assert_eq!(base, "https://ex.com/a");
        assert_eq!(pairs, vec![("x", "1"), ("y", "two"), ("z", "")]);
        let (base, pairs) = split_query("https://ex.com/a");
        assert_eq!(base, "https://ex.com/a");
        assert!(pairs.is_empty());
    }

    #[test]
    fn rebuild_query_encodes_injected_characters() {
        let url = rebuild_query(
            "https://ex.com/a",
            &[("x".to_owned(), "1'><wrv".to_owned())],
        );
        assert_eq!(url, "https://ex.com/a?x=1%27%3E%3Cwrv");
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
}
