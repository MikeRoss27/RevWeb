//! Read-only cross-account object access checks from two captured sessions.

use super::{
    access::has_query_credentials,
    client::idor_finding,
    evidence::attach,
    transport::{ProbeClient, ProbeResponse},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;
use webrev_core::{
    normalize_url_with_pattern, AuthConfig, Endpoint, EvidenceVerdict, Finding, Method,
    OpsecConfig, ResponseObservation, Result, Scope, SessionId, Source, WebrevError,
};

const MAX_PAIRS: usize = 15;

/// One path shape observed by both accounts with different object identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BolaCandidate {
    pub route: String,
    pub account_a_url: String,
    pub account_b_url: String,
}

/// Pair concrete GET requests seen in both browser sessions. Only one path
/// segment or one ID-shaped query value may differ; no ID is guessed.
#[must_use]
pub fn bola_candidates(a: &[Endpoint], b: &[Endpoint]) -> Vec<BolaCandidate> {
    let mut by_route: BTreeMap<String, Vec<&Endpoint>> = BTreeMap::new();
    for endpoint in b
        .iter()
        .filter(|e| e.method == Method::Get && e.source == Source::Browser)
    {
        let (route, _) = normalize_url_with_pattern(&endpoint.url);
        if safe_capture_url(&endpoint.url) {
            by_route.entry(route).or_default().push(endpoint);
        }
    }
    let mut candidates = BTreeMap::new();
    for endpoint in a
        .iter()
        .filter(|e| e.method == Method::Get && e.source == Source::Browser)
    {
        let (route, _) = normalize_url_with_pattern(&endpoint.url);
        if !safe_capture_url(&endpoint.url) {
            continue;
        }
        if let Some((peer, pair_route)) = by_route
            .get(&route)
            .into_iter()
            .flatten()
            .find_map(|peer| pair_route(&endpoint.url, &peer.url).map(|key| (peer, key)))
        {
            candidates
                .entry(pair_route)
                .or_insert_with(|| (endpoint.url.clone(), peer.url.clone()));
        }
    }
    let mut candidates: Vec<_> = candidates
        .into_iter()
        .map(|(route, (account_a_url, account_b_url))| BolaCandidate {
            route,
            account_a_url,
            account_b_url,
        })
        .collect();
    candidates.sort_by(|a, b| {
        priority(&b.route)
            .cmp(&priority(&a.route))
            .then(a.route.cmp(&b.route))
    });
    candidates
}

fn priority(route: &str) -> u8 {
    let lower = route.to_ascii_lowercase();
    let mut score = u8::from(lower.contains("/api/") || lower.contains("/rest/"));
    if [
        "/users/",
        "/accounts/",
        "/orders/",
        "/payments/",
        "/invoices/",
        "/documents/",
    ]
    .iter()
    .any(|part| lower.contains(part))
    {
        score += 2;
    }
    score
}

fn safe_capture_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|parsed| {
        matches!(parsed.scheme(), "http" | "https")
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && !has_query_credentials(url)
    })
}

fn pair_route(a: &str, b: &str) -> Option<String> {
    let (Ok(a), Ok(b)) = (reqwest::Url::parse(a), reqwest::Url::parse(b)) else {
        return None;
    };
    if a.origin() != b.origin() {
        return None;
    }
    let a_segments: Vec<_> = a.path_segments().into_iter().flatten().collect();
    let b_segments: Vec<_> = b.path_segments().into_iter().flatten().collect();
    if a_segments.len() != b_segments.len() {
        return None;
    }
    let path_differences = a_segments
        .iter()
        .zip(b_segments)
        .filter(|(x, y)| *x != y)
        .count();
    let (route, inferred) = normalize_url_with_pattern(a.as_str());
    if path_differences == 1 && inferred && a.query() == b.query() {
        return Some(route);
    }
    if path_differences != 0 {
        return None;
    }
    let a_query: Vec<_> = a.query_pairs().collect();
    let b_query: Vec<_> = b.query_pairs().collect();
    if a_query.len() != b_query.len() || a_query.is_empty() {
        return None;
    }
    let differences: Vec<_> = a_query
        .iter()
        .zip(&b_query)
        .filter(|((a_name, a_value), (b_name, b_value))| a_name != b_name || a_value != b_value)
        .collect();
    let [((a_name, a_value), (b_name, b_value))] = differences.as_slice() else {
        return None;
    };
    if a_name != b_name || !id_key(a_name) || !id_value(a_value) || !id_value(b_value) {
        return None;
    }
    Some(format!("{route}?{a_name}={{id}}"))
}

fn id_key(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "id" || lower.ends_with("_id") || lower.ends_with("id")
}

fn id_value(value: &str) -> bool {
    normalize_url_with_pattern(&format!("/{value}")).1
}

fn validate_account(account: &AuthConfig) -> Result<()> {
    if account.is_empty() {
        return Err(WebrevError::Config(
            "BOLA comparison requires two non-empty account profiles".into(),
        ));
    }
    for (name, value) in account.effective_headers() {
        reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| WebrevError::Config("invalid account header name".into()))?;
        reqwest::header::HeaderValue::from_str(&value)
            .map_err(|_| WebrevError::Config("invalid account header value".into()))?;
    }
    Ok(())
}

/// Compare A→A, B→B, B→A and A→B with GET only. Returns a signal, never a
/// confirmed ownership verdict: callers must supply accounts and objects they own.
pub async fn run_bola_scan(
    opsec: &OpsecConfig,
    scope: &Scope,
    session: SessionId,
    account_a: &AuthConfig,
    account_b: &AuthConfig,
    candidates: &[BolaCandidate],
    cancel: CancellationToken,
) -> Result<Vec<Finding>> {
    validate_account(account_a)?;
    validate_account(account_b)?;
    if account_a.effective_headers() == account_b.effective_headers() {
        return Err(WebrevError::Config(
            "BOLA comparison requires distinct account profiles".into(),
        ));
    }
    let client = ProbeClient::new(opsec, scope, cancel)?;
    let mut findings = Vec::new();
    let max_pairs = MAX_PAIRS.min(opsec.active.max_requests / 4);
    for candidate in candidates.iter().take(max_pairs) {
        if client.stopped() {
            break;
        }
        if !scope.allows(&candidate.account_a_url) || !scope.allows(&candidate.account_b_url) {
            client.update(|coverage| coverage.out_of_scope += 1);
            continue;
        }
        if super::destructive_keyword(&candidate.account_a_url).is_some()
            || super::destructive_keyword(&candidate.account_b_url).is_some()
        {
            client.refuse_destructive();
            continue;
        }
        let found = check_pair(&client, session, account_a, account_b, candidate).await;
        client.record_check("cross_account_bola", usize::from(found.is_some()));
        findings.extend(found);
    }
    if candidates.len() > max_pairs {
        client.update(|coverage| coverage.target_limit_reached = true);
    }
    if candidates.is_empty() {
        client.not_selected("cross_account_bola");
    }
    findings.push(super::coverage_finding(session, client.coverage()));
    Ok(findings)
}

async fn check_pair(
    client: &ProbeClient<'_>,
    session: SessionId,
    a: &AuthConfig,
    b: &AuthConfig,
    candidate: &BolaCandidate,
) -> Option<Finding> {
    let own_a = client.get_as(&candidate.account_a_url, a).await?;
    let own_b = client.get_as(&candidate.account_b_url, b).await?;
    if !valid_own_response(&own_a)
        || !valid_own_response(&own_b)
        || own_a.bytes == own_b.bytes
        || own_a.content_type() != own_b.content_type()
    {
        client.inconclusive("cross_account_bola");
        return None;
    }
    let cross_b_to_a = client.get_as(&candidate.account_a_url, b).await?;
    let cross_a_to_b = client.get_as(&candidate.account_b_url, a).await?;
    let b_reads_a = same_private_response(&own_a, &cross_b_to_a);
    let a_reads_b = same_private_response(&own_b, &cross_a_to_b);
    if !b_reads_a && !a_reads_b {
        return None;
    }
    let observations = [
        ("A own object", &own_a),
        ("B own object", &own_b),
        ("B reads A object", &cross_b_to_a),
        ("A reads B object", &cross_a_to_b),
    ]
    .into_iter()
    .map(|(role, response)| observation(role, response))
    .collect();
    let affected = if b_reads_a {
        &candidate.account_a_url
    } else {
        &candidate.account_b_url
    };
    Some(attach(
        idor_finding(session, affected, format!("cross-account object access signal on {}", candidate.route)),
        "cross_account_bola",
        None,
        EvidenceVerdict::Signal,
        observations,
        "Both own-object controls returned distinct JSON bodies; a cross-account response matched an owner's body. Confirm both objects are private and owned by the supplied test accounts. Public objects or shared caches can produce this signal.",
    ))
}

fn valid_own_response(response: &ProbeResponse) -> bool {
    response.status.is_success()
        && response.content_type().contains("json")
        && response.bytes.len() >= 8
        && serde_json::from_slice::<serde_json::Value>(&response.bytes).is_ok_and(|value| {
            !value.is_null() && value.get("error").is_none() && value.get("errors").is_none()
        })
}

fn same_private_response(own: &ProbeResponse, cross: &ProbeResponse) -> bool {
    cross.status.is_success()
        && cross.content_type() == own.content_type()
        && cross.bytes == own.bytes
}

fn observation(role: &str, response: &ProbeResponse) -> ResponseObservation {
    let digest = Sha256::digest(&response.bytes);
    let mut observation = response.observation(role, "");
    observation.excerpt = format!("sha256={}", hex::encode(digest));
    observation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_only_observed_single_identifier_changes() {
        let a = vec![Endpoint::new(
            "https://x.test/api/users/101",
            Method::Get,
            Source::Browser,
        )];
        let b = vec![
            Endpoint::new("https://x.test/api/users/202", Method::Get, Source::Browser),
            Endpoint::new(
                "https://x.test/api/users/303?token=secret",
                Method::Get,
                Source::Browser,
            ),
            Endpoint::new(
                "https://x.test/api/users/404",
                Method::Post,
                Source::Browser,
            ),
        ];
        let candidates = bola_candidates(&a, &b);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].account_b_url, "https://x.test/api/users/202");
    }

    #[test]
    fn pairs_query_object_ids_without_changing_other_parameters() {
        let a = vec![Endpoint::new(
            "https://x.test/api/user?userId=101&view=full",
            Method::Get,
            Source::Browser,
        )];
        let b = vec![
            Endpoint::new(
                "https://x.test/api/user?userId=202&view=full",
                Method::Get,
                Source::Browser,
            ),
            Endpoint::new(
                "https://x.test/api/user?userId=303&view=compact",
                Method::Get,
                Source::Browser,
            ),
        ];
        let candidates = bola_candidates(&a, &b);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].route, "https://x.test/api/user?userId={id}");
        assert_eq!(
            candidates[0].account_b_url,
            "https://x.test/api/user?userId=202&view=full"
        );
    }
}
