//! Path-traversal / local-file-inclusion probes for file/path-style params.
//!
//! GET-shaped and content-verified: a traversal payload is only reported when
//! the response body actually matches the structure of a well-known system
//! file (`/etc/passwd` or `win.ini`). A status code or a reflected payload
//! alone is never treated as a positive, so these stay high-signal.
use super::{
    client::vuln_finding, evidence::attach, transport::ProbeClient, urls::mutate_parameter,
};
use std::sync::LazyLock;
use webrev_core::{Confidence, EvidenceVerdict, Finding, SessionId};

/// Parameter names that commonly carry a filename or path the backend opens.
const FILE_PARAM_HINTS: &[&str] = &["file", "path", "page", "template", "doc", "include", "load"];

/// Traversal payloads sent as a parameter value. `mutate_parameter`
/// percent-encodes each, so the first two arrive single-encoded and the third
/// (already percent-encoded) arrives double-encoded for backends that decode
/// twice. The Windows payload targets `win.ini`.
const PAYLOADS: &[&str] = &[
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
];

/// `root:...:0:0:` is the superuser line every `/etc/passwd` carries.
static PASSWD: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"root:.*:0:0:").expect("static passwd regex"));

fn is_file_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    FILE_PARAM_HINTS.iter().any(|hint| lower.contains(hint))
}

/// True when any parameter looks like a file/path sink worth probing.
pub(super) fn has_file_param(params: &[(String, String)]) -> bool {
    params.iter().any(|(name, _)| is_file_param(name))
}

/// Match the body against the two system files this check verifies against.
fn file_signature(body: &str) -> Option<&'static str> {
    if PASSWD.is_match(body) {
        return Some("/etc/passwd");
    }
    let lower = body.to_ascii_lowercase();
    if lower.contains("[extensions]") || lower.contains("[fonts]") {
        return Some("win.ini");
    }
    None
}

pub(super) async fn check_path_traversal(
    client: &ProbeClient<'_>,
    original: &str,
    params: &[(String, String)],
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, (name, _)) in params.iter().enumerate() {
        if !is_file_param(name) {
            continue;
        }
        for payload in PAYLOADS {
            if client.stopped() {
                return findings;
            }
            let Some(url) = mutate_parameter(original, index, payload) else {
                continue;
            };
            let Some(response) = client.get(&url, true, None).await else {
                continue;
            };
            if !response.status.is_success() {
                continue;
            }
            let body = response.text();
            let Some(signature) = file_signature(&body) else {
                continue;
            };
            findings.push(attach(
                vuln_finding(
                    session,
                    &url,
                    format!(
                        "possible path traversal / local file inclusion: {signature} contents returned for '{name}' parameter"
                    ),
                    Confidence::High,
                ),
                "path_traversal",
                Some(name),
                EvidenceVerdict::Observed,
                vec![response.observation("probe", &body)],
                "The body matches a known system-file structure; confirm the file is genuinely served rather than reflected sample text.",
            ));
            // One confirmed payload per parameter is enough; stop probing it.
            break;
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_params_are_detected_by_name_substring() {
        assert!(is_file_param("file"));
        assert!(is_file_param("templateName"));
        assert!(is_file_param("download_path"));
        assert!(!is_file_param("q"));
        assert!(has_file_param(&[
            ("q".into(), "1".into()),
            ("page".into(), "home".into())
        ]));
        assert!(!has_file_param(&[("q".into(), "1".into())]));
    }

    #[test]
    fn only_real_system_file_structures_match() {
        assert_eq!(
            file_signature("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"),
            Some("/etc/passwd")
        );
        assert_eq!(
            file_signature("; for 16-bit app support\n[fonts]\n[extensions]\n"),
            Some("win.ini")
        );
        assert_eq!(file_signature("rootkit guide: nothing to see"), None);
        assert_eq!(file_signature("<html>enter a path to a file</html>"), None);
    }
}
