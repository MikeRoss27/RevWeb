//! HTTP client setup, retries and Retry-After handling.
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE},
    redirect::Policy,
};
use std::time::Duration;
use webrev_core::{OpsecConfig, Result, Scope, WebrevError};

/// Hard per-request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Maximum attempts per URL before giving up.
const MAX_ATTEMPTS: u32 = 3;

pub(super) fn build_client(opsec: &OpsecConfig, scope: &Scope) -> Result<reqwest::Client> {
    let ua = opsec
        .rotation
        .user_agent_for(0)
        .unwrap_or("webrev")
        .to_owned();
    let redirect_scope = scope.clone();
    let mut builder = reqwest::Client::builder()
        .user_agent(ua)
        .timeout(REQUEST_TIMEOUT)
        .dns_resolver(crate::dns::pinned_resolver(
            scope.clone(),
            opsec.egress.proxy.as_deref(),
        ))
        .redirect(Policy::custom(move |attempt| {
            let destination = attempt.url();
            if attempt.previous().len() >= 5
                || !matches!(destination.scheme(), "http" | "https")
                || !destination.username().is_empty()
                || destination.password().is_some()
                || !redirect_scope.allows(destination.as_str())
            {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }));
    if let Some(proxy) = &opsec.egress.proxy {
        let p = reqwest::Proxy::all(proxy).map_err(|e| {
            WebrevError::Config(format!(
                "invalid proxy {:?}: {}",
                webrev_core::redact_url(proxy),
                e.without_url()
            ))
        })?;
        builder = builder.proxy(p);
    }
    // Authenticated context: attach cookies/headers/bearer to every request.
    let mut headers = HeaderMap::new();
    for (name, value) in opsec.auth.effective_headers() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(name, value);
        }
    }
    if !headers.is_empty() {
        builder = builder.default_headers(headers);
    }
    builder
        .build()
        .map_err(|e| WebrevError::Fetch(format!("building http client: {e}")))
}

/// Cap on how long a single `Retry-After` wait is allowed to block a wave.
pub(super) const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Parse a `Retry-After` header value. Only the delay-seconds form is
/// handled (the HTTP-date form is rare for API rate limiting and not worth
/// the parsing surface here); an unparseable or absent header falls back to
/// the caller's exponential backoff.
pub(super) fn parse_retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(HeaderName::from_static("retry-after"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|secs| Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

/// Whether a response must be treated as binary (never lossily decoded to
/// UTF-8 text): the URL ends in `.wasm`, or the response declares
/// `application/wasm`. Checked against both the URL and the content-type so a
/// `.wasm` served without the right header, or a wasm endpoint with no `.wasm`
/// extension, are both caught.
pub(super) fn is_wasm_response(url: &str, content_type: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path.to_ascii_lowercase().ends_with(".wasm")
        || content_type
            .to_ascii_lowercase()
            .contains("application/wasm")
}

/// Read a response body in chunks, stopping (without erroring) once
/// `max_body_bytes` is reached. Unlike `Response::bytes()`/`Response::text()`,
/// this never buffers an unbounded amount of attacker- or
/// misconfiguration-controlled data: a pathologically large or slow-drip
/// response is truncated to the cap rather than read to completion, the same
/// bounded-read discipline `active::transport::read_bounded_body` already
/// applies to active-probe responses (there, exceeding the cap drops the
/// response entirely; here, the leading bytes are kept, since a crawled page
/// is read for extraction rather than as an exact proof).
pub(super) async fn read_bounded(
    mut resp: reqwest::Response,
    max_body_bytes: usize,
) -> std::result::Result<(Vec<u8>, bool), reqwest::Error> {
    let mut bytes = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        let remaining = max_body_bytes.saturating_sub(bytes.len());
        if chunk.len() > remaining {
            bytes.extend_from_slice(&chunk[..remaining]);
            return Ok((bytes, true));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((bytes, false))
}

/// Returns `(content_type, response_headers, body, bytes, rate_limited)`.
/// `body` is always empty for a binary (wasm) response — the raw bytes live in
/// `bytes` instead, so a binary body is never lossily decoded to UTF-8.
/// `bytes` is `None` for ordinary text responses. `rate_limited` is set once
/// this URL ever drew a 429/503, even if a later attempt eventually
/// succeeded, so the caller can back off the whole crawl, not just retry this
/// one request. The body is bounded by `max_body_bytes`
/// (`OpsecConfig::max_body_bytes`); a text body past the cap is decoded from
/// only its first `max_body_bytes` bytes as UTF-8 with lossy replacement —
/// identical to `Response::text()`'s own fallback decoding whenever the
/// response declares no explicit non-UTF-8 charset, which is the common case
/// for the HTML/JS this scanner extracts from.
pub(super) async fn fetch_with_retry(
    client: &reqwest::Client,
    url: &str,
    max_body_bytes: usize,
) -> Result<(String, Vec<(String, String)>, String, Option<Vec<u8>>, bool)> {
    let mut attempt = 0;
    let mut rate_limited = false;
    loop {
        attempt += 1;
        let outcome = client.get(url).send().await;
        match outcome {
            Ok(resp) => {
                let status = resp.status();
                let is_rate_limited =
                    status.as_u16() == 429 || status == reqwest::StatusCode::SERVICE_UNAVAILABLE;
                rate_limited |= is_rate_limited;
                let retry_after = parse_retry_after(&resp);
                let content_type = resp
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|v| (name.as_str().to_owned(), v.to_owned()))
                    })
                    .collect();
                let is_wasm = is_wasm_response(url, &content_type);
                let read_outcome = read_bounded(resp, max_body_bytes).await;
                match read_outcome {
                    Ok((raw, truncated)) => {
                        if truncated {
                            tracing::debug!(
                                url = %webrev_core::redact_url(url),
                                max_body_bytes,
                                "response body truncated at the crawl body cap"
                            );
                        }
                        let (body, bytes) = if is_wasm {
                            (String::new(), Some(raw))
                        } else {
                            (String::from_utf8_lossy(&raw).into_owned(), None)
                        };
                        if (status.is_server_error() || is_rate_limited) && attempt < MAX_ATTEMPTS {
                            let wait = retry_after
                                .unwrap_or_else(|| Duration::from_millis(200 * u64::from(attempt)));
                            tokio::time::sleep(wait).await;
                            continue;
                        }
                        return Ok((content_type, headers, body, bytes, rate_limited));
                    }
                    Err(e) if attempt < MAX_ATTEMPTS => {
                        tokio::time::sleep(Duration::from_millis(200 * u64::from(attempt))).await;
                        let _ = e;
                    }
                    Err(e) => {
                        return Err(WebrevError::Fetch(format!(
                            "reading {}: {}",
                            webrev_core::redact_url(url),
                            e.without_url()
                        )))
                    }
                }
            }
            Err(e) if attempt < MAX_ATTEMPTS => {
                tokio::time::sleep(Duration::from_millis(200 * u64::from(attempt))).await;
                let _ = e;
            }
            Err(e) => {
                return Err(WebrevError::Fetch(format!(
                    "requesting {}: {}",
                    webrev_core::redact_url(url),
                    e.without_url()
                )))
            }
        }
    }
}
