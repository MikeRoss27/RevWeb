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

fn is_navigation_parameter(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "redirect_uri"
            | "redirect_url"
            | "redirect"
            | "return_url"
            | "return_to"
            | "next"
            | "continue"
            | "callback"
            | "callback_url"
    )
}

/// A reflected URL and a different status are application behaviour, not
/// evidence of an outbound server request. Require a network-resolution error
/// tied to the injected host before retaining even a manual-review lead.
fn has_outbound_error(body: &str, marker: &str) -> bool {
    if !body.contains(marker) {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    [
        "enotfound",
        "eai_again",
        "name or service not known",
        "could not resolve host",
        "dns lookup failed",
        "getaddrinfo",
    ]
    .iter()
    .any(|signal| lower.contains(signal))
}

/// A value that looks like a URL the backend might dereference.
fn looks_like_url_or_host(value: &str) -> bool {
    let v = value.trim();
    v.starts_with("//") || v.contains("://")
}

/// True when any parameter value looks like a URL sink worth probing.
pub(super) fn has_url_param(params: &[(String, String)]) -> bool {
    params
        .iter()
        .any(|(name, value)| !is_navigation_parameter(name) && looks_like_url_or_host(value))
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
    for (index, (name, value)) in params.iter().enumerate() {
        if is_navigation_parameter(name) || !looks_like_url_or_host(value) {
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
        if response.status.is_redirection() || !has_outbound_error(&body, &marker) {
            client.inconclusive("ssrf_signal");
            continue;
        }
        findings.push(attach(
            vuln_finding(
                session,
                &url,
                format!("possible outbound URL resolution: '{name}' produced a DNS error mentioning the probe host"),
                Confidence::Low,
            ),
            "ssrf_signal",
            Some(name),
            EvidenceVerdict::Signal,
            vec![
                baseline.observation("baseline", ""),
                response.observation("probe", &body),
            ],
            "DNS error is a lead, not SSRF confirmation. No internal/metadata address was requested; independently verify a server-originated fetch.",
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
        assert!(!has_url_param(&[("next".into(), "https://a/".into())]));
        assert!(!has_url_param(&[("q".into(), "term".into())]));
        assert!(!has_url_param(&[(
            "redirect_uri".into(),
            "https://a/".into()
        )]));
        assert!(has_url_param(&[("service".into(), "https://a/".into())]));
    }

    #[test]
    fn status_change_and_reflection_are_not_ssrf_evidence() {
        let marker = "probe.invalid";
        assert!(!has_outbound_error("HTTP 500", marker));
        assert!(!has_outbound_error("redirect to probe.invalid", marker));
        assert!(has_outbound_error(
            "getaddrinfo ENOTFOUND probe.invalid",
            marker
        ));
    }
}
