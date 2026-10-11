//! Scoped active assessment with shared request limits and explicit proof tiers.
mod access;
mod client;
mod evidence;
mod expression;
mod headers;
mod injection;
mod origin;
mod targets;
mod transport;
mod urls;
pub use targets::active_targets;
#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod tests;

use access::{check_idor, has_query_credentials};
use expression::check_expressions;
use injection::{check_open_redirect, check_param_fuzz, redirect_parameter};
use origin::{check_cors, check_origin};
use std::collections::{BTreeMap, BTreeSet};
use tokio_util::sync::CancellationToken;
use transport::ProbeClient;
use urls::{has_identifier_segment, looks_like_api_endpoint, origin_of, query_parameters};
use webrev_core::{
    Confidence, Endpoint, Finding, FindingKind, Method, OpsecConfig, Provenance, Result, Scope,
    SessionId, Source, WebrevError,
};

const MAX_TARGETS_PER_CHECK: usize = 15;

/// GET-shaped checks only; GET handlers themselves may have side effects.
/// Each run includes a `ScanCoverage` record, even if no weakness was observed.
pub async fn run_active_scan(
    opsec: &OpsecConfig,
    scope: &Scope,
    session: SessionId,
    endpoints: &[Endpoint],
    cancel: CancellationToken,
) -> Result<Vec<Finding>> {
    if opsec.egress.proxy.is_none() && !opsec.egress.allow_direct {
        return Err(WebrevError::Config(
            "egress policy forbids direct connections but no proxy is configured".into(),
        ));
    }
    let client = ProbeClient::new(opsec, scope, cancel)?;
    let mut findings = Vec::new();
    let mut origins = BTreeSet::new();
    let mut api_by_origin = BTreeMap::new();
    let eligible = scoped_endpoints(scope, &client, endpoints);
    for ep in &eligible {
        let Some(origin) = origin_of(&ep.url) else {
            continue;
        };
        if looks_like_api_endpoint(&ep.url) {
            api_by_origin
                .entry(origin.clone())
                .or_insert_with(|| ep.url.clone());
        }
        origins.insert(origin);
    }
    for origin in &origins {
        if client.stopped() {
            break;
        }
        let found = check_origin(&client, origin, session).await;
        client.record_check("origin", found.len());
        findings.extend(found);
        if let Some(url) = api_by_origin.get(origin) {
            let found = check_cors(&client, url, session).await;
            client.record_check("api_cors", usize::from(found.is_some()));
            findings.extend(found);
        }
    }
    let (mut fuzz, mut redirects, mut access, mut expressions) = (0, 0, 0, 0);
    for ep in eligible {
        if client.stopped() {
            break;
        }
        let all_params = query_parameters(&ep.url);
        let params = &all_params[..all_params.len().min(opsec.active.max_parameters)];
        if params.len() != all_params.len() {
            client.update(|c| c.parameter_limit_reached = true);
        }
        if let Some(index) = redirect_parameter(params) {
            if redirects < MAX_TARGETS_PER_CHECK {
                redirects += 1;
                let found =
                    check_open_redirect(&client, &ep.url, index, &params[index].0, session).await;
                client.record_check("open_redirect", usize::from(found.is_some()));
                findings.extend(found);
            } else {
                client.update(|c| c.target_limit_reached = true);
            }
        }
        if !params.is_empty() {
            if fuzz < MAX_TARGETS_PER_CHECK {
                fuzz += 1;
                let found = check_param_fuzz(&client, &ep.url, params, session).await;
                client.record_check("parameter_fuzz", found.len());
                findings.extend(found);
            } else {
                client.update(|c| c.target_limit_reached = true);
            }
            if expressions < MAX_TARGETS_PER_CHECK && !client.stopped() {
                expressions += 1;
                let found = check_expressions(&client, &ep.url, params, session).await;
                client.record_check("template_arithmetic", found.len());
                findings.extend(found);
            } else if expressions >= MAX_TARGETS_PER_CHECK {
                client.update(|c| c.target_limit_reached = true);
            }
        }
        if !opsec.auth.is_empty()
            && has_identifier_segment(&ep.url)
            && has_query_credentials(&ep.url)
        {
            client.update(|c| c.skipped_query_auth += 1);
        }
        if !opsec.auth.is_empty()
            && has_identifier_segment(&ep.url)
            && !has_query_credentials(&ep.url)
        {
            if access < MAX_TARGETS_PER_CHECK && !client.stopped() {
                access += 1;
                let found = check_idor(&client, &ep.url, session).await;
                client.record_check("anonymous_access", usize::from(found.is_some()));
                findings.extend(found);
            } else if access >= MAX_TARGETS_PER_CHECK {
                client.update(|c| c.target_limit_reached = true);
            }
        }
    }
    let record = coverage_finding(session, client.coverage());
    findings.push(record);
    Ok(findings)
}

fn scoped_endpoints<'a>(
    scope: &Scope,
    client: &ProbeClient<'_>,
    endpoints: &'a [Endpoint],
) -> Vec<&'a Endpoint> {
    let mut seen = BTreeSet::new();
    endpoints
        .iter()
        .filter(|ep| {
            let valid = reqwest::Url::parse(&ep.url).is_ok_and(|url| {
                matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none()
            });
            if !valid {
                client.update(|c| c.out_of_scope += 1);
                return false;
            }
            if !scope.allows(&ep.url) {
                client.update(|c| c.out_of_scope += 1);
                return false;
            }
            if !matches!(ep.method, Method::Get | Method::Unknown) {
                client.update(|c| c.skipped_methods += 1);
                return false;
            }
            seen.insert(ep.url.clone())
        })
        .collect()
}

fn coverage_finding(session: SessionId, coverage: webrev_core::ActiveCoverage) -> Finding {
    let state = if coverage.complete() {
        "completed selected checks"
    } else {
        "incomplete / no clean verdict"
    };
    let mut record = Finding::new(session, FindingKind::ScanCoverage, None,
        format!("active coverage: {state}; {} / {} requests, {} responses, {} transport errors, {} refused, {} oversized, {} method skips, {} query-auth skips; cancelled={}, budget_exhausted={}, target_limit={}, parameter_limit={}",
            coverage.requests, coverage.request_limit, coverage.responses, coverage.transport_errors,
            coverage.refused_responses, coverage.oversized_responses, coverage.skipped_methods, coverage.skipped_query_auth, coverage.cancelled,
            coverage.budget_exhausted, coverage.target_limit_reached, coverage.parameter_limit_reached),
        Confidence::High, Provenance::new(Source::Active, None));
    record.coverage = Some(Box::new(coverage));
    record
}
