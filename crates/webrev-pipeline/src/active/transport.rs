//! One scope gate, request budget, cancellation and body bound for every probe.
use super::client::{apply_headers, build_probe_client};
use crate::stages::sleep_with_jitter;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tokio_util::sync::CancellationToken;
use webrev_core::{ActiveCoverage, AuthConfig, OpsecConfig, ResponseObservation, Result, Scope};

pub(super) struct ProbeClient<'a> {
    client: reqwest::Client,
    opsec: &'a OpsecConfig,
    scope: &'a Scope,
    cancel: CancellationToken,
    coverage: Mutex<ActiveCoverage>,
    last_recorded: Mutex<(usize, usize, usize, usize, usize, usize)>,
    reserved_requests: AtomicUsize,
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
            method: "GET".into(),
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
            client: build_probe_client(opsec, scope)?,
            opsec,
            scope,
            cancel,
            coverage: Mutex::new(ActiveCoverage {
                request_limit: opsec.active.max_requests,
                ..ActiveCoverage::default()
            }),
            last_recorded: Mutex::new((0, 0, 0, 0, 0, 0)),
            reserved_requests: AtomicUsize::new(0),
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
        let mut last = self.last_recorded.lock().expect("check counters lock");
        self.update(|c| {
            let now = (
                c.requests,
                c.responses,
                c.refused_responses,
                c.transport_errors,
                c.oversized_responses,
                c.out_of_scope,
            );
            let sent = now.0.saturating_sub(last.0);
            let responses = now.1.saturating_sub(last.1);
            let refused = now.2.saturating_sub(last.2);
            let errors = now.3.saturating_sub(last.3);
            let oversized = now.4.saturating_sub(last.4);
            let scope_refused = now.5.saturating_sub(last.5);
            let check = c.checks.entry(name.into()).or_default();
            check.attempted += 1;
            if sent == 0 {
                check.not_executed += 1;
            } else {
                check.executed += 1;
            }
            check.refused += usize::from(refused > 0);
            check.scope_refused += usize::from(scope_refused > 0);
            check.errors += usize::from(errors > 0 || oversized > 0);
            if findings == 0
                && responses > 0
                && refused == 0
                && scope_refused == 0
                && errors == 0
                && oversized == 0
                && check.inconclusive == 0
            {
                check.negative += 1;
            }
            check.findings += findings;
            *last = now;
        });
    }

    pub fn not_selected(&self, name: &str) {
        self.update(|c| c.checks.entry(name.into()).or_default().not_selected += 1);
    }

    /// A URL that looks state-changing was refused before any request. This is
    /// recorded as a refused, inconclusive `destructive_url_guard` check, so the
    /// coverage record can never read as complete or clean.
    pub fn refuse_destructive(&self) {
        self.update(|c| {
            let check = c.checks.entry("destructive_url_guard".into()).or_default();
            check.attempted += 1;
            check.not_executed += 1;
            check.refused += 1;
            check.inconclusive += 1;
        });
    }

    pub fn inconclusive(&self, name: &str) {
        self.update(|c| c.checks.entry(name.into()).or_default().inconclusive += 1);
    }

    /// No redirects, retries, cookie jar or ambient credentials. `auth=false`
    /// omits every mission header; URL query material is still part of the URL.
    pub async fn get(&self, url: &str, auth: bool, origin: Option<&str>) -> Option<ProbeResponse> {
        let headers = auth.then(|| self.opsec.auth.effective_headers());
        self.get_with_headers(url, headers.as_deref(), origin).await
    }

    /// Send a bounded GET under an explicitly supplied account. The same
    /// scope, DNS pinning, request budget and redirect policy apply.
    pub async fn get_as(&self, url: &str, account: &AuthConfig) -> Option<ProbeResponse> {
        let headers = account.effective_headers();
        self.get_with_headers(url, Some(&headers), None).await
    }

    async fn get_with_headers(
        &self,
        url: &str,
        headers: Option<&[(String, String)]>,
        origin: Option<&str>,
    ) -> Option<ProbeResponse> {
        let failures = self.coverage().transport_errors;
        let response = self.get_once(url, headers, origin).await;
        // One explicitly counted retry for a transport failure. This goes
        // through the same budget, delay and cancellation gates; hidden
        // HTTP-client retries remain disabled. Failures stay in coverage.
        if response.is_none() && self.coverage().transport_errors > failures && !self.stopped() {
            return self.get_once(url, headers, origin).await;
        }
        response
    }

    async fn get_once(
        &self,
        url: &str,
        headers: Option<&[(String, String)]>,
        origin: Option<&str>,
    ) -> Option<ProbeResponse> {
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
        // Reserve a slot before the delay await. Concurrent endpoint probes
        // must not all pass a check-then-increment budget gate together.
        let reservation =
            self.reserved_requests
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                    (reserved < self.opsec.active.max_requests).then_some(reserved + 1)
                });
        let Ok(reservation) = reservation else {
            self.update(|c| c.budget_exhausted = true);
            return None;
        };
        tokio::select! {
            () = self.cancel.cancelled() => return None,
            () = sleep_with_jitter(self.opsec, 0) => {},
        }
        let index = reservation;
        let mut request = self.client.get(url);
        if let Some(ua) = self
            .opsec
            .rotation
            .user_agent_for(u32::try_from(index).unwrap_or(u32::MAX))
        {
            request = request.header("User-Agent", ua);
        }
        if let Some(headers) = headers {
            request = apply_headers(request, headers);
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
                let out_of_scope = error.to_string().contains("outside the configured scope");
                // reqwest errors embed the full URL; log a redacted one.
                tracing::debug!(url = %webrev_core::redact_url(url), error = %error.without_url(), "active probe request failed");
                // The resolver deliberately returns PermissionDenied when all
                // DNS answers fall outside the configured IP/CIDR scope. Keep
                // that authorization refusal distinct from a network failure.
                if out_of_scope {
                    self.update(|c| c.out_of_scope += 1);
                } else {
                    self.update(|c| c.transport_errors += 1);
                }
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
        let response_headers = response.headers().clone();
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
            headers: response_headers,
            bytes,
            authenticated: headers.is_some_and(|headers| !headers.is_empty()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scope_refusal_is_recorded_without_counting_a_negative_test() {
        let opsec = OpsecConfig::default();
        let scope = Scope::new(vec!["allowed.example".into()], vec![]);
        let client = ProbeClient::new(&opsec, &scope, CancellationToken::new()).unwrap();

        assert!(client
            .get("http://outside.invalid/", true, None)
            .await
            .is_none());
        client.record_check("test_check", 0);

        let coverage = client.coverage();
        assert_eq!(coverage.out_of_scope, 1);
        let check = &coverage.checks["test_check"];
        assert_eq!(check.scope_refused, 1);
        assert_eq!(check.negative, 0);
        assert_eq!(check.not_executed, 1);
        assert_eq!(coverage.requests, 0);
    }
}
