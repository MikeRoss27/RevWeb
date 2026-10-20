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
            // Stored raw: the excerpt is the proof of the probe. Masking happens
            // on export (`--redact`), which scrubs the whole excerpt. The cut
            // point is chosen so it never splits a token-shaped run (see
            // `safe_char_cut`): `--redact`'s patterns match a secret by its
            // whole shape (a JWT's three dot-separated parts, a 16+ char
            // high-entropy run, ...) and a value sliced in half can fall
            // outside every pattern, letting a live credential fragment (or a
            // JWT's readable claims) through unmasked.
            excerpt: safe_char_prefix(excerpt, EXCERPT_LIMIT),
            body: String::new(),
            body_truncated: false,
        }
    }
}

/// Largest excerpt kept per observation, in characters.
const EXCERPT_LIMIT: usize = 256;

/// Characters that make up every secret shape `Sanitizer` recognises: the
/// base64url/hex alphabet plus the separators used by JWTs, vendor-prefixed
/// tokens and `key=value` assignments (`.`, `-`, `_`, `+`, `/`, `=`, `%`,
/// `~`). A run of these is treated as one token for truncation purposes.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '+' | '/' | '=' | '%')
}

/// Shortest run worth protecting. Below this, a value is too short to be
/// flagged as a secret by `Sanitizer` anyway (its shortest unnamed-token
/// heuristic requires 16 characters), so there is nothing a mid-run cut could
/// hide that redaction would otherwise have caught.
const MIN_PROTECTED_RUN: usize = 12;

/// Bound on how much a cut point may retreat to avoid splitting a run. Well
/// past the length of every token `Sanitizer` recognises by structure alone
/// (a JWT with a handful of claims runs well under this), so a real secret
/// is always dropped whole; past this bound the kept text is almost
/// certainly one long opaque blob (base64 image data, a minified file, ...)
/// rather than a secret, and retreating further would cost more of the
/// excerpt than it protects.
const MAX_RETREAT: usize = 200;

/// A prefix of at most `limit` characters that never ends partway through a
/// run of [`is_token_char`] characters long enough to be secret-shaped
/// ([`MIN_PROTECTED_RUN`] or more already included). When the naive cut at
/// `limit` would split such a run, the cut retreats to the run's start
/// instead, up to [`MAX_RETREAT`] characters back; past that bound the excerpt
/// would shrink too much to stay useful, so the naive cut is kept and the
/// (necessarily partial, and very likely harmless) remainder is left to
/// `Sanitizer`, as before.
fn safe_char_prefix(text: &str, limit: usize) -> String {
    let mut chars = text.char_indices();
    let Some((cut_byte, _)) = chars.by_ref().nth(limit) else {
        // Fewer than `limit` characters: nothing is cut.
        return text.to_owned();
    };
    let first_excluded = text[cut_byte..].chars().next();
    let kept = &text[..cut_byte];
    let last_included = kept.chars().next_back();
    let splitting_a_run = matches!((last_included, first_excluded), (Some(a), Some(b)) if is_token_char(a) && is_token_char(b));
    if !splitting_a_run {
        return kept.to_owned();
    }
    let run_start = kept
        .char_indices()
        .rev()
        .take_while(|&(_, c)| is_token_char(c))
        .last()
        .map_or(0, |(i, _)| i);
    let run_chars = kept[run_start..].chars().count();
    if !(MIN_PROTECTED_RUN..=MAX_RETREAT).contains(&run_chars) {
        return kept.to_owned();
    }
    kept[..run_start].to_owned()
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

    #[test]
    fn observation_keeps_url_and_excerpt_raw_but_truncated() {
        let response = ProbeResponse {
            url: "https://t.test/a?token=url-secret-value".into(),
            status: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::new(),
            bytes: Vec::new(),
            authenticated: false,
        };
        let body = r#"{"apiKey":"abcdef0123456789xyz","name":"visible"}"#;
        let observation = response.observation("probe", body);
        assert!(observation.excerpt.contains("abcdef0123456789xyz"));
        assert!(observation.excerpt.contains("visible"));
        assert!(observation.url.contains("url-secret-value"));

        let long = "x".repeat(1000);
        assert_eq!(response.observation("probe", &long).excerpt.len(), 256);
    }

    /// Regression for the gap tracked in `goal.md` (Étape 4, "secret coupé
    /// par la troncature à 256 caractères d'un extrait de sonde"): a
    /// credential-shaped value that straddles the excerpt limit used to be
    /// stored as a readable half-value, and `Sanitizer::scrub` (used by
    /// `--redact`) can need the whole shape of a token to recognise it (a
    /// JWT's three dot-separated parts, in this case), so the fragment slid
    /// through unmasked. The fix must drop such a run whole instead of
    /// slicing it, for every cut point that actually lands inside it.
    #[test]
    fn a_token_straddling_the_excerpt_limit_is_dropped_whole_not_split() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.c2lnbmF0dXJlYmxvYmJsb2JibG9iYmxvYmJsb2I";
        let sanitizer = webrev_core::Sanitizer::with_default_patterns();
        let response = ProbeResponse {
            url: "https://x.test/r".into(),
            status: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::new(),
            bytes: Vec::new(),
            authenticated: false,
        };
        let mut covered_a_straddling_cut = false;
        for pad_len in 100..220 {
            let pad = "a".repeat(pad_len);
            // "v" is not a name any of Sanitizer's key-name patterns
            // recognise, so only the JWT's own three-part structure could
            // have caught it -- exactly what a mid-token cut breaks.
            let body = format!(r#"{{"pad":"{pad}","link":"https://x.test/r?v={jwt}"}}"#);
            let naive: String = body.chars().take(EXCERPT_LIMIT).collect();
            let naive_ends_mid_jwt = (1..jwt.len()).any(|n| naive.ends_with(&jwt[..n]));
            if !naive_ends_mid_jwt {
                continue;
            }
            covered_a_straddling_cut = true;
            let observation = response.observation("probe", &body);
            let scrubbed = sanitizer.scrub(&observation.excerpt);
            let leaked = (MIN_PROTECTED_RUN..jwt.len()).find(|&n| scrubbed.contains(&jwt[..n]));
            assert!(
                leaked.is_none(),
                "pad_len={pad_len} leaked {:?} in {scrubbed:?}",
                leaked.map(|n| &jwt[..n])
            );
        }
        assert!(
            covered_a_straddling_cut,
            "no pad length landed the naive cut inside the JWT; test is not exercising the bug"
        );
    }

    /// An ordinary excerpt that happens to end exactly on a short,
    /// non-secret run of word characters is unaffected: nothing retreats
    /// just because the boundary falls inside a run of letters.
    #[test]
    fn a_short_ordinary_run_at_the_boundary_is_not_retreated() {
        let response = ProbeResponse {
            url: "https://t.test/a".into(),
            status: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::new(),
            bytes: Vec::new(),
            authenticated: false,
        };
        // 250 filler characters then a 10-character word straddling the
        // 256-character limit: too short to be secret-shaped, so the cut
        // stays at the naive boundary.
        let body = format!(r#"{}"readability""#, "x".repeat(250));
        let observation = response.observation("probe", &body);
        assert_eq!(observation.excerpt.chars().count(), 256);
    }

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
