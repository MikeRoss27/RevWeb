//! Complete human-readable triage, with full credentials and evidence.
use crate::{RenderOptions, SessionReport};
use std::fmt::Write;
use webrev_core::{model::triage::terminal_text, Finding, FindingKind};

impl SessionReport {
    /// Group results with priority, confidence, evidence and source.
    #[must_use]
    pub fn render_text(&self, opts: RenderOptions) -> String {
        let findings: Vec<_> = self.kept_findings(opts).collect();
        let count = |kind| findings.iter().filter(|f| f.kind == kind).count();
        let vulns = findings.iter().filter(|f| f.is_vulnerability()).count();
        let mut out = format!(
            "\nwebrev · {}\n{} findings | {} endpoints | {} secrets | {} vulnerabilities | {} technologies\n",
            terminal_text(&self.mission.name), findings.len(), count(FindingKind::Endpoint),
            count(FindingKind::Secret), vulns, count(FindingKind::Technology),
        );
        let by_category = |category| findings.iter().filter(|f| f.category() == category).count();
        let _ = writeln!(
            out,
            "Signals: IDOR {} | XSS {} | SQLi {} | SSTI {} | RCE: timing probe only (opt-in, never confirmed)",
            by_category("IDOR"),
            by_category("XSS"),
            by_category("SQLi"),
            by_category("SSTI")
        );
        out.push_str("Counts describe recorded findings, not test coverage. Active probes: --active / TUI a.\n");
        for group in [
            "VULNERABILITIES",
            "SECRETS",
            "TECHNOLOGIES",
            "COVERAGE",
            "ATTACK SURFACE",
        ] {
            let mut rows: Vec<_> = findings
                .iter()
                .copied()
                .filter(|f| group_for(f) == group)
                .collect();
            rows.sort_by(|a, b| {
                b.severity()
                    .cmp(&a.severity())
                    .then(b.confidence.cmp(&a.confidence))
            });
            let _ = writeln!(out, "\n{group} ({})", rows.len());
            if rows.is_empty() {
                out.push_str("  none recorded\n");
            }
            for finding in rows {
                let _ = writeln!(
                    out,
                    "  [{}] {:<9} status={} confidence={} evidence_score={} · {}\n    {}",
                    finding.severity().tag().trim(),
                    finding.category(),
                    finding.status.slug(),
                    finding.confidence.slug(),
                    finding.evidence_score(),
                    finding.assessment(),
                    terminal_text(finding.display_value())
                );
                if let Some(url) = &finding.url {
                    let _ = writeln!(out, "    url: {}", terminal_text(url));
                }
                if let Some(evidence) = &finding.evidence {
                    for line in evidence.details() {
                        let _ = writeln!(out, "    {}", terminal_text(&line));
                    }
                }
                for evidence in &finding.additional_evidence {
                    for line in evidence.details() {
                        let _ = writeln!(out, "    {}", terminal_text(&line));
                    }
                }
                if !finding.justification.is_empty() {
                    let _ = writeln!(out, "    reason: {}", terminal_text(&finding.justification));
                }
                if !finding.detectors.is_empty() {
                    let _ = writeln!(out, "    detectors: {}", finding.detectors.join(", "));
                }
                if let Some(coverage) = &finding.coverage {
                    for (check, count) in &coverage.checks {
                        let _ = writeln!(
                            out,
                            "    {check}: {} selected, {} executed, {} negative, {} not executed, {} not selected, {} HTTP refused, {} scope refused, {} errors, {} inconclusive, {} findings",
                            count.attempted, count.executed, count.negative, count.not_executed,
                            count.not_selected, count.refused, count.scope_refused, count.errors, count.inconclusive, count.findings
                        );
                    }
                }
                write_provenances(&mut out, finding);
            }
        }
        out
    }
}

fn group_for(f: &Finding) -> &'static str {
    if f.kind == FindingKind::ScanCoverage {
        "COVERAGE"
    } else if f.is_vulnerability() {
        "VULNERABILITIES"
    } else if f.kind == FindingKind::Secret {
        "SECRETS"
    } else if f.kind == FindingKind::Technology {
        "TECHNOLOGIES"
    } else {
        "ATTACK SURFACE"
    }
}

fn write_provenances(out: &mut String, finding: &Finding) {
    let location = |value: &Option<String>| {
        value
            .as_ref()
            .map_or_else(String::new, |s| format!(" · {}", terminal_text(s)))
    };
    let _ = writeln!(
        out,
        "    source: {}{}",
        finding.provenance.source,
        location(&finding.provenance.location)
    );
    for provenance in finding
        .provenances
        .iter()
        .filter(|p| *p != &finding.provenance)
    {
        let _ = writeln!(
            out,
            "    also from: {}{}",
            provenance.source,
            location(&provenance.location)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReportFormat;
    use webrev_core::{Confidence, Mission, Provenance, Scope, Severity, Source};

    #[test]
    fn triage_keeps_evidence_and_filters_without_inventing_rce() {
        let mission = Mission::new("fixture", Scope::default(), vec![]);
        let mk = |kind, value| {
            Finding::new(
                mission.id,
                kind,
                Some("https://x/api".into()),
                value,
                Confidence::High,
                Provenance::new(Source::Active, Some("app.js".into())),
            )
        };
        let report = SessionReport::build(
            mission.clone(),
            vec![
                mk(FindingKind::Technology, "React (frontend)"),
                mk(FindingKind::Secret, "fp:test").with_plaintext(Some("credential-raw".into())),
                mk(
                    FindingKind::Vulnerability,
                    "reflected parameter: possible XSS",
                ),
                mk(FindingKind::Idor, "anonymous success"),
            ],
            vec![],
        );
        let text = report
            .render(RenderOptions {
                format: ReportFormat::Text,
                ..RenderOptions::default()
            })
            .unwrap();
        for expected in [
            "IDOR 1 | XSS 1 | SQLi 0",
            "RCE: timing probe only",
            "credential-raw",
            "React (frontend)",
            "reflected parameter: possible XSS",
            "signal / verify manually",
            "app.js",
            "confidence=high",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        let filtered = report
            .render(RenderOptions {
                format: ReportFormat::Text,
                min_severity: Severity::High,
                ..RenderOptions::default()
            })
            .unwrap();
        assert!(!filtered.contains("React (frontend)"));
        assert!(filtered.contains("XSS 0"));
    }
}
