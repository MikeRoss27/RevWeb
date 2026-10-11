//! HTTP client setup, retries and Retry-After handling.
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE},
    redirect::Policy,
};
use std::time::Duration;
use webrev_core::{OpsecConfig, Result, WebrevError};

/// Hard per-request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Maximum attempts per URL before giving up.
const MAX_ATTEMPTS: u32 = 3;

pub(super) fn build_client(opsec: &OpsecConfig) -> Result<reqwest::Client> {
    let ua = opsec
        .rotation
        .user_agent_for(0)
        .unwrap_or("webrev")
        .to_owned();
    let mut builder = reqwest::Client::builder()
        .user_agent(ua)
        .timeout(REQUEST_TIMEOUT)
        .redirect(Policy::limited(5));
    if let Some(proxy) = &opsec.egress.proxy {
        let p = reqwest::Proxy::all(proxy)
            .map_err(|e| WebrevError::Config(format!("invalid proxy {proxy:?}: {e}")))?;
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

/// Returns `(content_type, response_headers, body, bytes, rate_limited)`.
/// `body` is always empty for a binary (wasm) response — the raw bytes live in
/// `bytes` instead, so a binary body is never lossily decoded to UTF-8.
/// `bytes` is `None` for ordinary text responses. `rate_limited` is set once
/// this URL ever drew a 429/503, even if a later attempt eventually
/// succeeded, so the caller can back off the whole crawl, not just retry this
/// one request.
pub(super) async fn fetch_with_retry(
    client: &reqwest::Client,
    url: &str,
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
                let read_outcome = if is_wasm {
                    resp.bytes()
                        .await
                        .map(|b| (String::new(), Some(b.to_vec())))
                } else {
                    resp.text().await.map(|body| (body, None))
                };
                match read_outcome {
                    Ok((body, bytes)) => {
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
                    Err(e) => return Err(WebrevError::Fetch(format!("reading {url}: {e}"))),
                }
            }
            Err(e) if attempt < MAX_ATTEMPTS => {
                tokio::time::sleep(Duration::from_millis(200 * u64::from(attempt))).await;
                let _ = e;
            }
            Err(e) => return Err(WebrevError::Fetch(format!("requesting {url}: {e}"))),
        }
    }
}
