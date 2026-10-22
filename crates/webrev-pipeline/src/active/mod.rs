//! Scoped active assessment with shared request limits and explicit proof tiers.
mod access;
mod bola;
mod bola_diff;
mod client;
mod crlf;
mod destructive;
mod evidence;
mod expression;
mod graphql;
mod headers;
mod injection;
mod origin;
mod pollution;
mod ssrf;
mod takeover;
mod targets;
mod timing;
mod transport;
mod traversal;
mod urls;
mod ws_replay;
pub use bola::{bola_candidates, run_bola_scan, BolaCandidate};
pub(crate) use destructive::destructive_keyword;
pub use targets::active_targets;
pub use ws_replay::{
    run_ws_replay_scan, ws_frame_candidates, WsDirection, WsFrameCandidate, WsMutation,
    MAX_WS_REPLAY_FRAMES,
};
#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod tests;

use access::{check_idor, has_query_credentials};
use crlf::check_crlf;
use expression::check_expressions;
use graphql::{check_graphql_introspection, is_graphql_endpoint};
use injection::{check_open_redirect, check_param_fuzz, redirect_parameter};
use origin::{check_cors, check_origin};
use pollution::check_prototype_pollution;
use ssrf::{check_ssrf, has_url_param};
use std::collections::{BTreeMap, BTreeSet};
use takeover::check_subdomain_takeover;
use timing::check_timing_injection;
use tokio_util::sync::CancellationToken;
use transport::ProbeClient;
use traversal::{check_path_traversal, has_file_param};
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
    let mut takeover = 0;
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
        if takeover < MAX_TARGETS_PER_CHECK && !client.stopped() {
            takeover += 1;
            let found = check_subdomain_takeover(&client, origin, session).await;
            client.record_check("subdomain_takeover", usize::from(found.is_some()));
            findings.extend(found);
        } else if takeover >= MAX_TARGETS_PER_CHECK {
            client.update(|c| c.target_limit_reached = true);
        }
    }
    let mut budget = Budget::default();
    for ep in eligible {
        if client.stopped() {
            break;
        }
        let all_params = query_parameters(&ep.url);
        let params = &all_params[..all_params.len().min(opsec.active.max_parameters)];
        if params.len() != all_params.len() {
            client.update(|c| c.parameter_limit_reached = true);
        }
        findings
            .extend(classic_checks(&client, opsec, &ep.url, params, &mut budget, session).await);
        findings.extend(recon_checks(&client, &ep.url, params, &mut budget, session).await);
    }
    for check in [
        "origin",
        "api_cors",
        "subdomain_takeover",
        "open_redirect",
        "parameter_fuzz",
        "template_arithmetic",
        "anonymous_access",
        "crlf_injection",
        "path_traversal",
        "ssrf_signal",
        "prototype_pollution",
        "graphql_introspection",
        "timing_injection",
    ] {
        if !client.coverage().checks.contains_key(check) {
            client.not_selected(check);
        }
    }
    let record = coverage_finding(session, client.coverage());
    findings.push(record);
    Ok(findings)
}

/// Per-endpoint target counters, so each check is independently capped at
/// `MAX_TARGETS_PER_CHECK` across the whole scan.
#[derive(Default)]
struct Budget {
    fuzz: usize,
    redirects: usize,
    access: usize,
    expressions: usize,
    traversal: usize,
    crlf: usize,
    ssrf: usize,
    pollution: usize,
    graphql: usize,
    timing: usize,
}

/// The original SQLi/XSS/open-redirect/SSTI/IDOR checks for one endpoint.
async fn classic_checks(
    client: &ProbeClient<'_>,
    opsec: &OpsecConfig,
    url: &str,
    params: &[(String, String)],
    budget: &mut Budget,
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(index) = redirect_parameter(params) {
        if budget.redirects < MAX_TARGETS_PER_CHECK {
            budget.redirects += 1;
            let found = check_open_redirect(client, url, index, &params[index].0, session).await;
            client.record_check("open_redirect", usize::from(found.is_some()));
            findings.extend(found);
        } else {
            client.update(|c| c.target_limit_reached = true);
        }
    }
    if !params.is_empty() {
        if budget.fuzz < MAX_TARGETS_PER_CHECK {
            budget.fuzz += 1;
            let found = check_param_fuzz(client, url, params, session).await;
            client.record_check("parameter_fuzz", found.len());
            findings.extend(found);
        } else {
            client.update(|c| c.target_limit_reached = true);
        }
        if budget.expressions < MAX_TARGETS_PER_CHECK && !client.stopped() {
            budget.expressions += 1;
            let found = check_expressions(client, url, params, session).await;
            client.record_check("template_arithmetic", found.len());
            findings.extend(found);
        } else if budget.expressions >= MAX_TARGETS_PER_CHECK {
            client.update(|c| c.target_limit_reached = true);
        }
        if opsec.active.allow_timing_probes {
            if budget.timing < MAX_TARGETS_PER_CHECK && !client.stopped() {
                budget.timing += 1;
                let found = check_timing_injection(client, url, params, session).await;
                client.record_check("timing_injection", found.len());
                findings.extend(found);
            } else if budget.timing >= MAX_TARGETS_PER_CHECK {
                client.update(|c| c.target_limit_reached = true);
            }
        }
    }
    if !opsec.auth.is_empty() && has_identifier_segment(url) && has_query_credentials(url) {
        client.update(|c| c.skipped_query_auth += 1);
    }
    if !opsec.auth.is_empty() && has_identifier_segment(url) && !has_query_credentials(url) {
        if budget.access < MAX_TARGETS_PER_CHECK && !client.stopped() {
            budget.access += 1;
            let found = check_idor(client, url, session).await;
            client.record_check("anonymous_access", usize::from(found.is_some()));
            findings.extend(found);
        } else if budget.access >= MAX_TARGETS_PER_CHECK {
            client.update(|c| c.target_limit_reached = true);
        }
    }
    findings
}

/// The recon-style checks (CRLF, traversal, SSRF signal, prototype pollution,
/// GraphQL introspection) for one endpoint, each capped independently.
async fn recon_checks(
    client: &ProbeClient<'_>,
    url: &str,
    params: &[(String, String)],
    budget: &mut Budget,
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !params.is_empty() {
        if budget.crlf < MAX_TARGETS_PER_CHECK && !client.stopped() {
            budget.crlf += 1;
            let found = check_crlf(client, url, params, session).await;
            client.record_check("crlf_injection", found.len());
            findings.extend(found);
        } else if budget.crlf >= MAX_TARGETS_PER_CHECK {
            client.update(|c| c.target_limit_reached = true);
        }
        if has_file_param(params) {
            if budget.traversal < MAX_TARGETS_PER_CHECK && !client.stopped() {
                budget.traversal += 1;
                let found = check_path_traversal(client, url, params, session).await;
                client.record_check("path_traversal", found.len());
                findings.extend(found);
            } else if budget.traversal >= MAX_TARGETS_PER_CHECK {
                client.update(|c| c.target_limit_reached = true);
            }
        }
        if has_url_param(params) {
            if budget.ssrf < MAX_TARGETS_PER_CHECK && !client.stopped() {
                budget.ssrf += 1;
                let found = check_ssrf(client, url, params, session).await;
                client.record_check("ssrf_signal", found.len());
                findings.extend(found);
            } else if budget.ssrf >= MAX_TARGETS_PER_CHECK {
                client.update(|c| c.target_limit_reached = true);
            }
        }
    }
    if budget.pollution < MAX_TARGETS_PER_CHECK && !client.stopped() {
        budget.pollution += 1;
        let found = check_prototype_pollution(client, url, session).await;
        client.record_check("prototype_pollution", usize::from(found.is_some()));
        findings.extend(found);
    } else if budget.pollution >= MAX_TARGETS_PER_CHECK {
        client.update(|c| c.target_limit_reached = true);
    }
    if is_graphql_endpoint(url) {
        if budget.graphql < MAX_TARGETS_PER_CHECK && !client.stopped() {
            budget.graphql += 1;
            let found = check_graphql_introspection(client, url, session).await;
            client.record_check("graphql_introspection", found.len());
            findings.extend(found);
        } else if budget.graphql >= MAX_TARGETS_PER_CHECK {
            client.update(|c| c.target_limit_reached = true);
        }
    }
    findings
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
            if destructive_keyword(&ep.url).is_some() {
                client.refuse_destructive();
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
        format!("active coverage: {state}; {} / {} requests, {} responses, {} transport errors, {} HTTP refused, {} scope refused, {} oversized, {} method skips, {} query-auth skips; cancelled={}, budget_exhausted={}, target_limit={}, parameter_limit={}",
            coverage.requests, coverage.request_limit, coverage.responses, coverage.transport_errors,
            coverage.refused_responses, coverage.out_of_scope, coverage.oversized_responses, coverage.skipped_methods, coverage.skipped_query_auth, coverage.cancelled,
            coverage.budget_exhausted, coverage.target_limit_reached, coverage.parameter_limit_reached),
        Confidence::High, Provenance::new(Source::Active, None));
    record.status = if coverage.complete() {
        webrev_core::FindingStatus::Observed
    } else {
        webrev_core::FindingStatus::Inconclusive
    };
    record.detectors.push("active_coverage".into());
    record.justification = state.into();
    record.coverage = Some(Box::new(coverage));
    record
}
