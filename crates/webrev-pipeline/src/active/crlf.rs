//! CRLF / HTTP response-header-injection probes.
//!
//! A CRLF sequence is injected into each reflectable parameter; a positive is
//! only recorded when the RESPONSE actually carries the header we injected
//! (`X-Webrev-Injected`), which reqwest surfaces only if the server split the
//! header line. We never assert injection from the body alone.
use super::{
    client::vuln_finding, evidence::attach, transport::ProbeClient, urls::mutate_parameter,
};
use webrev_core::{Confidence, EvidenceVerdict, Finding, SessionId};

/// Header the probe tries to smuggle into the response via CR LF.
const INJECTED_HEADER: &str = "x-webrev-injected";

pub(super) async fn check_crlf(
    client: &ProbeClient<'_>,
    original: &str,
    params: &[(String, String)],
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, (name, value)) in params.iter().enumerate() {
        // Variant 1 carries raw CR LF (single percent-encoded on the wire by
        // `mutate_parameter`); variant 2 is already encoded, so it arrives
        // double-encoded for backends that decode the query twice.
        for payload in [
            format!("{value}\r\nX-Webrev-Injected:1"),
            format!("{value}%0d%0aX-Webrev-Injected:1"),
        ] {
            if client.stopped() {
                return findings;
            }
            let Some(url) = mutate_parameter(original, index, &payload) else {
                continue;
            };
            let Some(response) = client.get(&url, true, None).await else {
                continue;
            };
            if !response.headers.contains_key(INJECTED_HEADER) {
                continue;
            }
            findings.push(attach(
                vuln_finding(
                    session,
                    &url,
                    format!(
                        "possible CRLF / header injection: injected response header observed via '{name}' parameter"
                    ),
                    Confidence::Medium,
                ),
                "crlf_injection",
                Some(name),
                EvidenceVerdict::Observed,
                vec![response.observation("probe", "X-Webrev-Injected: 1")],
                "A header we injected appeared in the response; confirm it is attacker-controllable and not a fixed server header before reporting.",
            ));
            // One confirmed variant per parameter is enough.
            break;
        }
    }
    findings
}
