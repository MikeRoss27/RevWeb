//! Shared triage labels. Reflections and anonymous access remain signals.
use super::finding::{Finding, FindingKind};

impl Finding {
    /// Category from the stable phrases emitted by existing active probes.
    #[must_use]
    pub fn category(&self) -> &str {
        match self.kind {
            FindingKind::Idor => "IDOR",
            FindingKind::Secret => "Secret",
            FindingKind::Technology => "Tech",
            FindingKind::Vulnerability => {
                let value = self.value.to_ascii_lowercase();
                if value.starts_with("reflected parameter:") {
                    "XSS"
                } else if value.starts_with("template expression evaluation:") {
                    "SSTI"
                } else if value.starts_with("possible sql injection:") {
                    "SQLi"
                } else if value.starts_with("command injection timing signal:") {
                    "RCE"
                } else if value.starts_with("cors misconfiguration:") {
                    "CORS"
                } else if value.starts_with("open redirect ") {
                    "Redirect"
                } else if value.starts_with("exposed sensitive file:") {
                    "Exposure"
                } else if value.starts_with("missing security header(s):") {
                    "Headers"
                } else if value.starts_with("cookie '") {
                    "Cookie"
                } else {
                    "Vuln"
                }
            }
            _ => self.kind.slug(),
        }
    }

    /// What the evidence establishes, independently of priority/confidence.
    #[must_use]
    pub fn assessment(&self) -> &'static str {
        if let Some(evidence) = &self.evidence {
            return evidence.verdict.label();
        }
        match self.category() {
            "IDOR" | "XSS" | "SQLi" | "RCE" | "Exposure" | "Vuln" => "signal / verify manually",
            "Secret" => "detected / validity unchecked",
            "Tech" => "signature detected",
            _ => "observed",
        }
    }

    #[must_use]
    pub fn is_vulnerability(&self) -> bool {
        matches!(self.kind, FindingKind::Vulnerability | FindingKind::Idor)
    }

    /// Credentials when present; other findings retain their evidence.
    #[must_use]
    pub fn display_value(&self) -> &str {
        self.plaintext.as_deref().unwrap_or(&self.value)
    }
}

/// Escape terminal controls without truncating untrusted evidence or secrets.
#[must_use]
pub fn terminal_text(value: &str) -> String {
    value.chars().fold(String::new(), |mut out, c| {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, Provenance, SessionId, Source};

    #[test]
    fn labels_do_not_claim_execution_or_exploitability() {
        let mk = |kind, value| {
            Finding::new(
                SessionId::new(),
                kind,
                None,
                value,
                Confidence::High,
                Provenance::new(Source::Active, None),
            )
        };
        for (kind, value, category) in [
            (FindingKind::Idor, "anonymous success", "IDOR"),
            (
                FindingKind::Vulnerability,
                "reflected parameter: possible XSS",
                "XSS",
            ),
            (
                FindingKind::Vulnerability,
                "possible SQL injection: error",
                "SQLi",
            ),
            (
                FindingKind::Vulnerability,
                "exposed sensitive file: .env",
                "Exposure",
            ),
        ] {
            let f = mk(kind, value);
            assert_eq!(f.category(), category);
            assert_eq!(f.assessment(), "signal / verify manually");
        }
        assert_eq!(
            mk(FindingKind::Endpoint, "GET /rce/xss").category(),
            "endpoint"
        );
        assert_eq!(
            mk(FindingKind::Vulnerability, "unknown RCE string").category(),
            "Vuln"
        );
    }

    #[test]
    fn terminal_controls_remain_visible() {
        assert_eq!(terminal_text("clé\n\u{1b}[2J"), "clé\\n\\u{1b}[2J");
    }
}
