//! Security header and cookie observations.
use super::client::vuln_finding;
use webrev_core::{Confidence, Finding, SessionId};

/// Missing `Content-Security-Policy` / `X-Content-Type-Options` /
/// `X-Frame-Options` / (https-only) `Strict-Transport-Security`.
pub(super) fn check_security_headers(
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
        .is_some_and(|v| {
            v.split(';').any(|directive| {
                directive
                    .split_whitespace()
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("frame-ancestors"))
            })
        });
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
pub(super) fn check_cookie_flags(
    headers: &reqwest::header::HeaderMap,
    is_https: bool,
    root: &str,
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for cookie in headers.get_all("set-cookie") {
        let Ok(c) = cookie.to_str() else { continue };
        let attributes: Vec<_> = c
            .split(';')
            .skip(1)
            .map(|a| {
                a.trim()
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
            })
            .collect();
        let name = c.split('=').next().unwrap_or(c).to_owned();
        let mut flags = Vec::new();
        if is_https && !attributes.iter().any(|a| a == "secure") {
            flags.push("Secure");
        }
        if !attributes.iter().any(|a| a == "httponly") {
            flags.push("HttpOnly");
        }
        if !attributes.iter().any(|a| a == "samesite") {
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
