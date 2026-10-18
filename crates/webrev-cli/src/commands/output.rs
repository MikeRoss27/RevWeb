//! Compact scan view; the exported text report retains every observation.
//!
//! This view lands in terminals, CI logs and screen shares, so URLs and
//! surface values go through [`redact_url`] (userinfo, token-like path
//! segments and credential parameters). Detected secrets are the point of the
//! finding and keep their plaintext. Exported reports are masked separately
//! (`SessionReport::redacted`) unless `--unredacted` is given.
use std::fmt::Write;
use std::io::IsTerminal;
use webrev_core::{
    model::triage::terminal_text, redact_url, Finding, FindingKind, FindingStatus, Severity,
};
use webrev_report::SessionReport;

const SURFACE_LIMIT: usize = 8;

pub(super) fn show(report: &SessionReport) -> anyhow::Result<()> {
    let body = render(report);
    if !std::io::stdout().is_terminal() || std::env::var_os("NO_COLOR").is_some() {
        return super::report::write_stdout(&body);
    }
    super::report::write_stdout(&colorize(&body))
}

// The scan summary reads in display order and is easier to audit as one flow.
#[allow(clippy::too_many_lines)]
fn render(report: &SessionReport) -> String {
    let findings = &report.findings;
    let leads = ranked(
        findings
            .iter()
            .filter(|f| f.is_vulnerability() || f.kind == FindingKind::Secret),
    );
    let technologies = ranked(
        findings
            .iter()
            .filter(|f| f.kind == FindingKind::Technology),
    );
    let surface = ranked(findings.iter().filter(|f| {
        !f.is_vulnerability()
            && !matches!(
                f.kind,
                FindingKind::Secret | FindingKind::Technology | FindingKind::ScanCoverage
            )
    }));
    let coverage: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == FindingKind::ScanCoverage)
        .collect();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\nSCAN COMPLETE  {}",
        terminal_text(&redact_url(&report.mission.name))
    );
    let _ = writeln!(
        out,
        "{} findings  ·  {} endpoints  ·  {} to review",
        findings.len(),
        report.endpoints.len(),
        leads.len()
    );
    let count = |severity| leads.iter().filter(|f| f.severity() == severity).count();
    let _ = writeln!(
        out,
        "Priority  CRIT {}  HIGH {}  MED {}  LOW {}",
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low)
    );
    out.push_str("Severity is impact priority; status and confidence describe the evidence.\n");

    let _ = writeln!(
        out,
        "\nVULNERABILITIES & SECRETS TO REVIEW ({})",
        leads.len()
    );
    if leads.is_empty() {
        out.push_str("  No vulnerability or secret findings recorded.\n");
    }
    for (index, finding) in leads.iter().enumerate() {
        write_finding(&mut out, index + 1, finding);
    }

    let _ = writeln!(out, "\nTECHNOLOGIES ({})", technologies.len());
    if technologies.is_empty() {
        out.push_str("  None recorded.\n");
    }
    for finding in technologies {
        let _ = writeln!(out, "  • {}", terminal_text(&finding.value));
    }

    let _ = writeln!(out, "\nATTACK SURFACE ({})", surface.len());
    if surface.is_empty() {
        out.push_str("  None recorded.\n");
    }
    for finding in surface.iter().take(SURFACE_LIMIT) {
        let _ = writeln!(
            out,
            "  [{}] {:<10} {}",
            finding.severity().tag().trim(),
            finding.kind.slug(),
            terminal_text(&redact_url(&finding.value))
        );
    }
    if surface.len() > SURFACE_LIMIT {
        let _ = writeln!(
            out,
            "  + {} more in the report",
            surface.len() - SURFACE_LIMIT
        );
    }

    if !coverage.is_empty() {
        let _ = writeln!(out, "\nCOVERAGE ({})", coverage.len());
        for finding in coverage {
            if let Some(data) = &finding.coverage {
                let _ = writeln!(
                    out,
                    "  {} requests  ·  {} checks  ·  {}",
                    data.requests,
                    data.checks.len(),
                    if data.complete() {
                        "complete"
                    } else {
                        "incomplete"
                    }
                );
            } else {
                let _ = writeln!(out, "  {}", terminal_text(&finding.value));
            }
        }
    }
    out.push_str(
        "\nSignals: RCE: not tested (no detector). Counts are findings, not test coverage.\n",
    );
    out
}

fn ranked<'a>(items: impl Iterator<Item = &'a Finding>) -> Vec<&'a Finding> {
    let mut rows: Vec<_> = items.collect();
    rows.sort_by(|a, b| {
        b.severity()
            .cmp(&a.severity())
            .then(status_rank(b.status).cmp(&status_rank(a.status)))
            .then(b.confidence.cmp(&a.confidence))
            .then(a.value.cmp(&b.value))
    });
    rows
}

fn status_rank(status: FindingStatus) -> u8 {
    match status {
        FindingStatus::Confirmed => 3,
        FindingStatus::Suspicious => 2,
        FindingStatus::Observed => 1,
        FindingStatus::Inconclusive => 0,
    }
}

fn write_finding(out: &mut String, index: usize, finding: &Finding) {
    let _ = writeln!(
        out,
        "  {:>2}. [{}] {}  ·  {}  ·  confidence={}  ·  {}",
        index,
        finding.severity().tag().trim(),
        finding.category(),
        finding.status.slug(),
        finding.confidence.slug(),
        finding.assessment()
    );
    let _ = writeln!(out, "      {}", terminal_text(finding.display_value()));
    if let Some(url) = &finding.url {
        let _ = writeln!(out, "      URL       {}", terminal_text(&redact_url(url)));
    }
    if let Some(evidence) = &finding.evidence {
        let _ = writeln!(out, "      Check     {}", terminal_text(&evidence.check));
        if let Some(observation) = evidence
            .observations
            .iter()
            .find(|observation| !observation.excerpt.is_empty())
        {
            let _ = writeln!(
                out,
                "      Evidence  {}",
                terminal_text(&observation.excerpt)
            );
        }
    }
    if !finding.justification.is_empty() {
        let _ = writeln!(
            out,
            "      Reason    {}",
            terminal_text(&finding.justification)
        );
    }
}

fn colorize(body: &str) -> String {
    let mut out = String::new();
    for line in body.lines() {
        let color = if line.contains("[CRIT]") || line.contains("[HIGH]") {
            "\x1b[1;38;2;229;101;63m"
        } else if line.contains("[MED]") {
            "\x1b[1;38;2;240;181;99m"
        } else if line.starts_with("SCAN COMPLETE") || line.starts_with("VULNERABILITIES") {
            "\x1b[1;38;2;250;244;232m"
        } else if line.starts_with("TECHNOLOGIES")
            || line.starts_with("ATTACK SURFACE")
            || line.starts_with("COVERAGE")
        {
            "\x1b[1;38;2;163;154;146m"
        } else {
            ""
        };
        out.push_str(color);
        out.push_str(line);
        if !color.is_empty() {
            out.push_str("\x1b[0m");
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{Confidence, Mission, Provenance, Scope, Source};

    #[test]
    fn leads_precede_surface_and_target_controls_are_escaped() {
        let mission = Mission::new("target\u{1b}[2J", Scope::default(), vec![]);
        let session_id = mission.id;
        let mk = |kind, value| {
            Finding::new(
                session_id,
                kind,
                None,
                value,
                Confidence::High,
                Provenance::new(Source::Active, None),
            )
        };
        let report = SessionReport::build(
            mission,
            vec![
                mk(FindingKind::Endpoint, "https://example.test/admin"),
                mk(FindingKind::Secret, "fingerprint").with_plaintext(Some("token123".into())),
                mk(
                    FindingKind::Vulnerability,
                    "reflected parameter: possible XSS",
                ),
            ],
            vec![],
        );
        let text = render(&report);
        assert!(text.contains("TO REVIEW (2)"));
        assert!(text.contains("token123"));
        assert!(text.contains("XSS"));
        assert!(text.contains("ATTACK SURFACE (1)"));
        assert!(!text.contains('\u{1b}'));
        assert!(text.find("TO REVIEW").unwrap() < text.find("ATTACK SURFACE").unwrap());
    }

    #[test]
    fn surface_urls_are_redacted_but_secret_plaintext_is_kept() {
        let mission = Mission::new(
            "https://u:pw@app.test/?token=seedtok",
            Scope::default(),
            vec![],
        );
        let session_id = mission.id;
        let mk = |kind, value| {
            Finding::new(
                session_id,
                kind,
                None,
                value,
                Confidence::High,
                Provenance::new(Source::JsAst, None),
            )
        };
        let report = SessionReport::build(
            mission,
            vec![
                mk(
                    FindingKind::Endpoint,
                    "https://app.test/reset/Zk3Jq9XvT2bLm8Rw4NpYs7Ad?access_token=abc&page=2",
                ),
                mk(FindingKind::Secret, "fingerprint").with_plaintext(Some("token123".into())),
            ],
            vec![],
        );
        let text = render(&report);
        for leaked in [
            "Zk3Jq9XvT2bLm8Rw4NpYs7Ad",
            "access_token=abc",
            "seedtok",
            "u:pw",
        ] {
            assert!(!text.contains(leaked), "{leaked} in:\n{text}");
        }
        assert!(text.contains("/reset/[REDACTED]?access_token=[REDACTED]&page=2"));
        assert!(text.contains("token123"));
    }
}
