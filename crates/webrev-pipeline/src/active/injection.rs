//! Individual query probes, differenced against a successful baseline.
use super::{
    client::vuln_finding, evidence::attach, transport::ProbeClient, urls::mutate_parameter,
};
use webrev_core::{Confidence, EvidenceVerdict, Finding, SessionId};

const STRONG_SQL: &[&str] = &[
    "mysql_fetch",
    "ora-01756",
    "sqlite3::",
    "pg_query()",
    "odbc sql server driver",
    "sqlstate[",
    "pdoexception",
];
const GENERIC_SQL: &[&str] = &[
    "sql syntax",
    "unclosed quotation mark",
    "syntax error at or near",
];
const REDIRECT_NAMES: &[&str] = &[
    "redirect",
    "redirect_uri",
    "redirecturl",
    "return",
    "returnto",
    "return_to",
    "next",
    "url",
    "continue",
    "dest",
    "destination",
    "callback",
    "target",
];

pub(super) fn redirect_parameter(params: &[(String, String)]) -> Option<usize> {
    params
        .iter()
        .position(|(name, _)| REDIRECT_NAMES.iter().any(|n| n.eq_ignore_ascii_case(name)))
}

pub(super) async fn check_open_redirect(
    client: &ProbeClient<'_>,
    original: &str,
    index: usize,
    parameter: &str,
    session: SessionId,
) -> Option<Finding> {
    let nonce = rand::random::<u64>();
    let path = format!("/{nonce:016x}");
    let target_host = "webrev-redirect-probe.invalid";
    let target = format!("https://{target_host}{path}");
    let origin = reqwest::Url::parse(original).ok()?;
    let _origin_host = origin.host_str()?;
    let probes = [
        target.clone(),
        format!("//{target_host}{path}"),
        format!("@{target_host}{path}"),
        format!("\t//{target_host}{path}"),
        format!("\\/{target_host}{path}"),
    ];

    for probe in probes {
        if client.stopped() {
            return None;
        }
        let url = mutate_parameter(original, index, &probe)?;
        let Some(response) = client.get(&url, true, None).await else {
            continue;
        };
        if !response.status.is_redirection() {
            continue;
        }
        let Some(location) = response
            .headers
            .get("location")
            .and_then(|value| value.to_str().ok())
        else {
            continue;
        };
        // Resolve relative and protocol-relative Location values as a browser
        // would, but never follow them. Require our randomized host and path;
        // a status difference or a reflected substring is not sufficient.
        let Some(resolved) = origin.join(location).ok() else {
            continue;
        };
        if !matches!(resolved.scheme(), "http" | "https")
            || resolved.host_str() != Some(target_host)
            || resolved.path() != path
            || resolved.query().is_some()
        {
            continue;
        }
        let expected_scheme = if probe == target {
            "https"
        } else {
            origin.scheme()
        };
        if resolved.scheme() != expected_scheme {
            continue;
        }
        let technique = if probe.starts_with('@') {
            " (authority-prefix bypass)".to_owned()
        } else if probe.starts_with("//") {
            " (protocol-relative destination)".to_owned()
        } else if probe.starts_with('\t') {
            " (tab-prefixed protocol-relative destination)".to_owned()
        } else if probe.starts_with('\\') {
            " (backslash URL separator)".to_owned()
        } else {
            String::new()
        };
        return Some(attach(
            vuln_finding(
                session,
                &url,
                format!("open redirect via '{parameter}' parameter{technique} (Location: {location})"),
                Confidence::High,
            ),
            "open_redirect",
            Some(parameter),
            EvidenceVerdict::Observed,
            vec![response.observation("probe", location)],
            "The randomized external .invalid destination was present as the resolved Location; the scanner did not follow it.",
        ));
    }
    None
}

pub(super) async fn check_param_fuzz(
    client: &ProbeClient<'_>,
    original: &str,
    params: &[(String, String)],
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(baseline) = client.get(original, true, None).await else {
        return findings;
    };
    if !baseline.status.is_success() {
        client.inconclusive("parameter_fuzz");
        return findings;
    }
    let baseline_lower = baseline.text().to_ascii_lowercase();
    for (index, (parameter, value)) in params.iter().enumerate() {
        if client.stopped() {
            break;
        }
        let marker = format!("wrvFuzz{:016x}<>", rand::random::<u64>());
        let Some(url) = mutate_parameter(original, index, &format!("{value}'><{marker}")) else {
            continue;
        };
        let Some(response) = client.get(&url, true, None).await else {
            continue;
        };
        if matches!(response.status.as_u16(), 401 | 403 | 429) {
            continue;
        }
        let body = response.text();
        let lower = body.to_ascii_lowercase();
        let new_signature = STRONG_SQL
            .iter()
            .copied()
            .chain(
                GENERIC_SQL
                    .iter()
                    .copied()
                    .filter(|_| response.status.is_server_error()),
            )
            .find(|sig| lower.contains(sig) && !baseline_lower.contains(sig));
        let point = format!("{parameter} (query position {})", index + 1);
        if let Some(signature) = new_signature {
            findings.push(attach(
                vuln_finding(
                    session,
                    &url,
                    format!("possible SQL injection: new database error '{signature}' for {point}"),
                    Confidence::Medium,
                ),
                "sql_error_differential",
                Some(&point),
                EvidenceVerdict::Signal,
                vec![
                    baseline.observation("baseline", ""),
                    response.observation("probe", signature),
                ],
                "An error signature is not proof of query execution or database access.",
            ));
        }
        let html = response
            .content_type()
            .split(';')
            .next()
            .is_some_and(|mime| matches!(mime.trim(), "text/html" | "application/xhtml+xml"));
        if html && body.contains(&marker) && !baseline_lower.contains(&marker.to_ascii_lowercase())
        {
            let offset = body.find(&marker).unwrap_or(0);
            let excerpt: String = body[offset..].chars().take(160).collect();
            findings.push(attach(
                vuln_finding(session, &url, format!("reflected parameter: literal markup echoed in HTML for {point} (possible XSS, verify context manually)"), Confidence::Low),
                "html_reflection", Some(&point), EvidenceVerdict::Signal,
                vec![baseline.observation("baseline", ""), response.observation("probe", &excerpt)],
                "Reflection in HTML is not JavaScript execution. JSON and escaped markup are not classified as XSS.",
            ));
        }
    }
    findings
}
