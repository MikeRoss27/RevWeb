//! Conservative, observational SSRF-sink detection.
//!
//! This check deliberately does NOT try to prove SSRF. It never asks the
//! target to fetch an internal, loopback, link-local or cloud-metadata
//! address (169.254.169.254 and friends) -- coercing a server into an
//! internal request is exactly the intrusive behaviour a budgeted GET-only
//! scanner must avoid. Instead it substitutes an obviously external, harmless,
//! attacker-free host under a `.invalid` TLD (RFC 6761: guaranteed never to
//! resolve) into URL-valued parameters and merely observes whether the
//! parameter behaves like a URL *sink* -- reflected back, or changing the
//! response shape. That is a LOW-confidence lead for manual, out-of-band
//! confirmation, nothing more.
use super::{
    client::vuln_finding, evidence::attach, transport::ProbeClient, urls::mutate_parameter,
};
use webrev_core::{Confidence, EvidenceVerdict, Finding, SessionId};

/// A value that looks like a URL the backend might dereference.
fn looks_like_url_or_host(value: &str) -> bool {
    let v = value.trim();
    v.starts_with("//") || v.contains("://")
}

/// True when any parameter value looks like a URL sink worth probing.
pub(super) fn has_url_param(params: &[(String, String)]) -> bool {
    params
        .iter()
        .any(|(_, value)| looks_like_url_or_host(value))
}

pub(super) async fn check_ssrf(
    client: &ProbeClient<'_>,
    original: &str,
    params: &[(String, String)],
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(baseline) = client.get(original, true, None).await else {
        return findings;
    };
    let baseline_body = baseline.text();
    for (index, (name, value)) in params.iter().enumerate() {
        if !looks_like_url_or_host(value) {
            continue;
        }
        if client.stopped() {
            break;
        }
        let nonce = rand::random::<u64>();
        // Externally shaped, unresolvable and attacker-free: the server cannot
        // be coerced into any internal fetch, so this stays observational.
        let marker = format!("webrev-ssrf-{nonce:016x}.invalid");
        let probe_value = format!("https://{marker}/");
        let Some(url) = mutate_parameter(original, index, &probe_value) else {
            continue;
        };
        let Some(response) = client.get(&url, true, None).await else {
            continue;
        };
        let body = response.text();
        let reflected = body.contains(&marker);
        let threshold = (baseline.bytes.len() / 4).max(64);
        let behaviour_changed = response.status != baseline.status
            || response.bytes.len().abs_diff(baseline.bytes.len()) > threshold;
        if !reflected && !behaviour_changed {
            continue;
        }
        let detail = if reflected {
            "URL value reflected in response"
        } else {
            "response behaviour changed for an external URL value"
        };
        findings.push(attach(
            vuln_finding(
                session,
                &url,
                format!("possible SSRF sink: parameter accepts a URL ('{name}', {detail})"),
                Confidence::Low,
            ),
            "ssrf_signal",
            Some(name),
            EvidenceVerdict::Signal,
            vec![
                baseline.observation("baseline", &baseline_body),
                response.observation("probe", &marker),
            ],
            "Observational only: no internal/metadata address was requested. Confirm server-side fetching out of band before treating this as SSRF.",
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_url_shaped_values_are_probed() {
        assert!(looks_like_url_or_host("https://example.com/x"));
        assert!(looks_like_url_or_host("//example.com"));
        assert!(looks_like_url_or_host("ftp://host/f"));
        assert!(!looks_like_url_or_host("hello"));
        assert!(!looks_like_url_or_host("42"));
        assert!(has_url_param(&[("next".into(), "https://a/".into())]));
        assert!(!has_url_param(&[("q".into(), "term".into())]));
    }
}
