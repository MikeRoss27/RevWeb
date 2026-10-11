//! One scope gate, request budget, cancellation and body bound for every probe.
use super::client::{apply_headers, build_probe_client};
use crate::stages::sleep_with_jitter;
use std::sync::Mutex;
use tokio_util::sync::CancellationToken;
use webrev_core::{ActiveCoverage, OpsecConfig, ResponseObservation, Result, Scope};

pub(super) struct ProbeClient<'a> {
    client: reqwest::Client,
    opsec: &'a OpsecConfig,
    scope: &'a Scope,
    cancel: CancellationToken,
    coverage: Mutex<ActiveCoverage>,
}

pub(super) struct ProbeResponse {
    pub url: String,
    pub status: reqwest::StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub bytes: Vec<u8>,
    pub authenticated: bool,
}

impl ProbeResponse {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    pub fn content_type(&self) -> String {
        self.headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase()
    }

    pub fn observation(&self, role: &str, excerpt: &str) -> ResponseObservation {
        ResponseObservation {
            role: role.into(),
            url: self.url.clone(),
            status: self.status.as_u16(),
            authenticated: self.authenticated,
            content_type: self.content_type(),
            body_bytes: self.bytes.len(),
            excerpt: excerpt.chars().take(256).collect(),
        }
    }
}

impl<'a> ProbeClient<'a> {
    pub fn new(
        opsec: &'a OpsecConfig,
        scope: &'a Scope,
        cancel: CancellationToken,
    ) -> Result<Self> {
        Ok(Self {
            client: build_probe_client(opsec)?,
            opsec,
            scope,
            cancel,
            coverage: Mutex::new(ActiveCoverage {
                request_limit: opsec.active.max_requests,
                ..ActiveCoverage::default()
            }),
        })
    }

    pub fn update(&self, update: impl FnOnce(&mut ActiveCoverage)) {
        update(&mut self.coverage.lock().expect("coverage lock"));
    }

    pub fn coverage(&self) -> ActiveCoverage {
        let mut coverage = self.coverage.lock().expect("coverage lock").clone();
        coverage.cancelled = self.cancel.is_cancelled();
        coverage
    }

    pub fn stopped(&self) -> bool {
        self.cancel.is_cancelled() || self.coverage().budget_exhausted
    }

    pub fn record_check(&self, name: &str, findings: usize) {
        self.update(|c| {
            let check = c.checks.entry(name.into()).or_default();
            check.attempted += 1;
            check.findings += findings;
        });
    }

    pub fn inconclusive(&self, name: &str) {
        self.update(|c| c.checks.entry(name.into()).or_default().inconclusive += 1);
    }

    /// No redirects, retries, cookie jar or ambient credentials. `auth=false`
    /// omits every mission header; URL query material is still part of the URL.
    pub async fn get(&self, url: &str, auth: bool, origin: Option<&str>) -> Option<ProbeResponse> {
        let failures = self.coverage().transport_errors;
        let response = self.get_once(url, auth, origin).await;
        // One explicitly counted retry for a transport failure. This goes
        // through the same budget, delay and cancellation gates; hidden
        // HTTP-client retries remain disabled. Failures stay in coverage.
        if response.is_none() && self.coverage().transport_errors > failures && !self.stopped() {
            return self.get_once(url, auth, origin).await;
        }
        response
    }

    async fn get_once(&self, url: &str, auth: bool, origin: Option<&str>) -> Option<ProbeResponse> {
        let parsed = reqwest::Url::parse(url).ok()?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || !self.scope.allows(url)
        {
            self.update(|c| c.out_of_scope += 1);
            return None;
        }
        if self.stopped() {
            return None;
        }
        if self.coverage().requests >= self.opsec.active.max_requests {
            self.update(|c| c.budget_exhausted = true);
            return None;
        }
        tokio::select! {
            () = self.cancel.cancelled() => return None,
            () = sleep_with_jitter(self.opsec, 0) => {},
        }
        let index = self.coverage().requests;
        let mut request = self.client.get(url);
        if let Some(ua) = self
            .opsec
            .rotation
            .user_agent_for(u32::try_from(index).unwrap_or(u32::MAX))
        {
            request = request.header("User-Agent", ua);
        }
        if auth {
            request = apply_headers(request, &self.opsec.auth.effective_headers());
        }
        if let Some(origin) = origin {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::ORIGIN, origin.parse().ok()?);
            request = request.headers(headers);
        }
        self.update(|c| c.requests += 1);
        let response = tokio::select! {
            () = self.cancel.cancelled() => return None,
            result = request.send() => result,
        };
        let mut response = match response {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(%url, %error, "active probe request failed");
                self.update(|c| c.transport_errors += 1);
                return None;
            }
        };
        self.update(|c| {
            c.responses += 1;
            if matches!(response.status().as_u16(), 401 | 403 | 429) {
                c.refused_responses += 1;
            }
        });
        let status = response.status();
        let headers = response.headers().clone();
        let mut bytes = Vec::new();
        loop {
            let chunk = tokio::select! {
                () = self.cancel.cancelled() => return None,
                chunk = response.chunk() => chunk,
            };
            match chunk {
                Ok(Some(chunk)) => {
                    if bytes.len().saturating_add(chunk.len()) > self.opsec.active.max_body_bytes {
                        self.update(|c| c.oversized_responses += 1);
                        return None;
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => {
                    self.update(|c| c.transport_errors += 1);
                    return None;
                }
            }
        }
        Some(ProbeResponse {
            url: url.into(),
            status,
            headers,
            bytes,
            authenticated: auth && !self.opsec.auth.is_empty(),
        })
    }
}
