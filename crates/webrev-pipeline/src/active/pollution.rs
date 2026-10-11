//! Conservative prototype-pollution signal.
//!
//! Appends `__proto__[...]` / `constructor[prototype][...]` query parameters
//! and looks for a server error or a reflected pollution marker relative to a
//! clean baseline. This is only ever a LOW-confidence lead: prototype
//! pollution is confirmed dynamically, by observing a polluted property change
//! later application behaviour, which a single GET probe cannot establish.
use super::{
    client::vuln_finding, evidence::attach, transport::ProbeClient, urls::append_query_pair,
};
use webrev_core::{Confidence, EvidenceVerdict, Finding, SessionId};

/// Marker key the probes try to set on the prototype.
const MARKER: &str = "webrevpp";
const PAYLOADS: &[&str] = &[
    "__proto__[webrevpp]=1",
    "constructor[prototype][webrevpp]=1",
];

pub(super) async fn check_prototype_pollution(
    client: &ProbeClient<'_>,
    original: &str,
    session: SessionId,
) -> Option<Finding> {
    let baseline = client.get(original, true, None).await?;
    let baseline_body = baseline.text();
    for payload in PAYLOADS {
        if client.stopped() {
            return None;
        }
        let Some(url) = append_query_pair(original, payload) else {
            continue;
        };
        let Some(response) = client.get(&url, true, None).await else {
            continue;
        };
        let server_error = response.status.is_server_error() && !baseline.status.is_server_error();
        let body = response.text();
        let reflected = body.contains(MARKER) && !baseline_body.contains(MARKER);
        if !server_error && !reflected {
            continue;
        }
        let detail = if server_error {
            "server error triggered"
        } else {
            "pollution key reflected"
        };
        return Some(attach(
            vuln_finding(
                session,
                &url,
                format!("possible prototype pollution: {detail} by '{payload}'"),
                Confidence::Low,
            ),
            "prototype_pollution",
            None,
            EvidenceVerdict::Signal,
            vec![
                baseline.observation("baseline", &baseline_body),
                response.observation("probe", &body),
            ],
            "A lead only: prototype pollution is confirmed dynamically by a polluted property affecting later behaviour, which a GET probe cannot show.",
        ));
    }
    None
}
