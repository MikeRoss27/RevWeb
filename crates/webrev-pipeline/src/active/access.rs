//! Anonymous access comparison, with explicit limitations on IDOR evidence.
use super::{
    client::idor_finding, evidence::attach, transport::ProbeClient, urls::query_parameters,
};
use webrev_core::{EvidenceVerdict, Finding, SessionId};

pub(super) fn response_shape(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut last_was_digit = false;
    for c in body.chars() {
        if c.is_whitespace() {
            continue;
        }
        if c.is_ascii_digit() {
            if !last_was_digit {
                out.push('0');
            }
            last_was_digit = true;
        } else {
            out.push(c);
            last_was_digit = false;
        }
    }
    out
}

pub(super) fn has_query_credentials(url: &str) -> bool {
    query_parameters(url).iter().any(|(name, _)| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "token"
                | "access_token"
                | "api_key"
                | "apikey"
                | "key"
                | "auth"
                | "authorization"
                | "session"
                | "jwt"
                | "signature"
        )
    })
}

pub(super) async fn check_idor(
    client: &ProbeClient<'_>,
    url: &str,
    session: SessionId,
) -> Option<Finding> {
    // A token kept in the URL would authenticate both requests, so a header-only
    // comparison cannot meaningfully establish anonymous access in that case.
    if has_query_credentials(url) {
        return None;
    }
    let authed = client.get(url, true, None).await?;
    if !authed.status.is_success() || authed.bytes.is_empty() {
        client.inconclusive("anonymous_access");
        return None;
    }
    let authed_body = authed.text();
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&authed_body) {
        if json.get("error").is_some()
            || json.get("errors").is_some()
            || json.get("success") == Some(&serde_json::Value::Bool(false))
        {
            return None;
        }
    }
    let anon = client.get(url, false, None).await?;
    if !anon.status.is_success() || anon.content_type() != authed.content_type() {
        return None;
    }
    let len_close =
        authed.bytes.len().abs_diff(anon.bytes.len()) <= (authed.bytes.len() / 10).max(16);
    if !len_close || response_shape(&authed_body) != response_shape(&anon.text()) {
        return None;
    }
    Some(attach(
        idor_finding(session, url, "resource returned a success response with no authentication/session material sent"),
        "anonymous_access_comparison", None, EvidenceVerdict::Signal,
        vec![authed.observation("authenticated", &authed_body), anon.observation("anonymous", &anon.text())],
        "Public resources may legitimately match. No second identity or ownership check was performed; IDOR is not confirmed.",
    ))
}
