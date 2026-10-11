//! Shared request configuration and active finding constructors.
use reqwest::{
    header::{HeaderName, HeaderValue},
    redirect::Policy,
};
use std::time::Duration;
use webrev_core::{
    Confidence, Finding, FindingKind, OpsecConfig, Provenance, Result, SessionId, Source,
    WebrevError,
};

/// Hard per-request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) fn build_probe_client(opsec: &OpsecConfig) -> Result<reqwest::Client> {
    for (name, value) in opsec.auth.effective_headers() {
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| WebrevError::Config("invalid authentication header name".into()))?;
        HeaderValue::from_str(&value)
            .map_err(|_| WebrevError::Config("invalid authentication header value".into()))?;
    }
    let ua = opsec
        .rotation
        .user_agent_for(0)
        .unwrap_or("webrev")
        .to_owned();
    let mut builder = reqwest::Client::builder()
        .user_agent(ua)
        .timeout(REQUEST_TIMEOUT)
        .no_proxy()
        .retry(reqwest::retry::never())
        // Separate connections avoid stale-pool retries and connection-bound
        // authentication contaminating the anonymous control.
        .pool_max_idle_per_host(0)
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

pub(super) fn apply_headers(
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

pub(super) fn vuln_finding(
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

pub(super) fn idor_finding(session: SessionId, url: &str, value: impl Into<String>) -> Finding {
    Finding::new(
        session,
        FindingKind::Idor,
        Some(url.to_owned()),
        value,
        Confidence::Medium,
        Provenance::new(Source::Active, None),
    )
}
