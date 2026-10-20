//! Compact scan view; the exported text report retains every observation.
//!
//! This view lands in terminals, CI logs and screen shares, so URLs and
//! surface values go through [`redact_url`] (userinfo, token-like path
//! segments and credential parameters). Detected secrets are the point of the
//! finding and keep their plaintext. Exported reports are masked separately
//! (`SessionReport::redacted`) only when `--redact` is given.
//!
//! Colors come from a [`Tone`] assigned while the view is built, never from
//! scanning the rendered text: a target-controlled string such as `[CRIT]`
//! cannot restyle a line.
use crate::term::{fit_end, fit_middle};
use std::io::IsTerminal;
use webrev_core::{
    model::triage::terminal_text, redact_url, Finding, FindingKind, FindingStatus, Severity,
};
use webrev_report::SessionReport;
use webrev_tui::color::{self, ColorMode};

/// How much of the view to show.
#[derive(Clone, Copy, Debug)]
pub(super) struct ShowOpts {
    /// Surface rows to list; `None` lists them all (`--all`).
    pub limit: Option<usize>,
    /// Terminal columns to fit target-controlled text into; `None` for pipes.
    pub width: Option<usize>,
}

impl ShowOpts {
    pub(super) fn from_args(args: &crate::cli::ScanArgs) -> Self {
        Self {
            limit: (!args.all).then_some(args.limit),
            width: if std::io::stdout().is_terminal() {
                crate::term::width_of(std::io::stdout())
            } else {
                None
            },
        }
    }
}

/// Visual role of a line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tone {
    Plain,
    /// Critical / high severity.
    Alert,
    /// Medium severity.
    Warn,
    /// Primary headings.
    Title,
    /// Secondary headings.
    Section,
}

impl Tone {
    fn of(severity: Severity) -> Self {
        match severity {
            Severity::Critical | Severity::High => Self::Alert,
            Severity::Medium => Self::Warn,
            _ => Self::Plain,
        }
    }
}

#[derive(Default)]
struct Doc(Vec<(Tone, String)>);

impl Doc {
    fn push(&mut self, tone: Tone, text: impl Into<String>) {
        self.0.push((tone, text.into()));
    }
    fn plain(&mut self, text: impl Into<String>) {
        self.push(Tone::Plain, text);
    }
    fn blank(&mut self) {
        self.plain("");
    }
}

pub(super) fn show(report: &SessionReport, opts: ShowOpts) -> anyhow::Result<()> {
    let doc = render_doc(report, opts);
    let mode = color::mode(std::io::stdout().is_terminal());
    super::report::write_stdout(&paint(&doc, mode))
}

/// Number of vulnerability / secret findings at or above `threshold`
/// (`--fail-on`).
pub(super) fn count_at_least(report: &SessionReport, threshold: Severity) -> usize {
    report
        .findings
        .iter()
        .filter(|f| f.is_vulnerability() || f.kind == FindingKind::Secret)
        .filter(|f| f.severity() >= threshold)
        .count()
}

/// `prefix` + `text` fitted to the terminal width, keeping the tail visible.
fn fitted(prefix: &str, text: &str, opts: ShowOpts, middle: bool) -> String {
    let Some(width) = opts.width else {
        return format!("{prefix}{text}");
    };
    let avail = width.saturating_sub(prefix.chars().count()).max(12);
    let body = if middle {
        fit_middle(text, avail)
    } else {
        fit_end(text, avail)
    };
    format!("{prefix}{body}")
}

// The scan summary reads in display order and is easier to audit as one flow.
#[allow(clippy::too_many_lines)]
fn render_doc(report: &SessionReport, opts: ShowOpts) -> Doc {
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
    let mut out = Doc::default();
    out.blank();
    out.push(
        Tone::Title,
        format!(
            "SCAN COMPLETE  {}",
            terminal_text(&redact_url(&report.mission.name))
        ),
    );
    out.plain(format!(
        "{} findings  \u{b7}  {} endpoints  \u{b7}  {} to review",
        findings.len(),
        report.endpoints.len(),
        leads.len()
    ));
    let tier = |slug: &str| {
        report
            .summary
            .endpoints_by_evidence_tier
            .get(slug)
            .copied()
            .unwrap_or(0)
    };
    out.plain(format!(
        "Endpoint evidence  observed {}  static {}  inferred {}",
        tier("observed"),
        tier("static"),
        tier("inferred")
    ));
    let count = |severity| leads.iter().filter(|f| f.severity() == severity).count();
    out.plain(format!(
        "Priority  CRIT {}  HIGH {}  MED {}  LOW {}",
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low)
    ));
    out.plain("Severity is impact priority; status and confidence describe the evidence.");

    out.blank();
    out.push(
        Tone::Title,
        format!("VULNERABILITIES & SECRETS TO REVIEW ({})", leads.len()),
    );
    if leads.is_empty() {
        out.plain("  No vulnerability or secret findings recorded.");
    }
    for (index, finding) in leads.iter().enumerate() {
        write_finding(&mut out, index + 1, finding, opts);
    }

    out.blank();
    out.push(
        Tone::Section,
        format!("TECHNOLOGIES ({})", technologies.len()),
    );
    if technologies.is_empty() {
        out.plain("  None recorded.");
    }
    for finding in technologies {
        out.plain(fitted(
            "  \u{2022} ",
            &terminal_text(&finding.value),
            opts,
            false,
        ));
    }

    out.blank();
    out.push(Tone::Section, format!("ATTACK SURFACE ({})", surface.len()));
    if surface.is_empty() {
        out.plain("  None recorded.");
    }
    let shown = opts.limit.map_or(surface.len(), |l| l.min(surface.len()));
    for finding in surface.iter().take(shown) {
        let severity = finding.severity();
        let prefix = format!("  [{}] {:<10} ", severity.tag().trim(), finding.kind.slug());
        out.push(
            Tone::of(severity),
            fitted(
                &prefix,
                &terminal_text(&redact_url(&finding.value)),
                opts,
                true,
            ),
        );
    }
    if surface.len() > shown {
        out.plain(format!(
            "  + {} more (use --all, or --limit N; the report has everything)",
            surface.len() - shown
        ));
    }

    if !coverage.is_empty() {
        out.blank();
        out.push(Tone::Section, format!("COVERAGE ({})", coverage.len()));
        for finding in coverage {
            if let Some(data) = &finding.coverage {
                out.plain(format!(
                    "  {} requests  \u{b7}  {} checks  \u{b7}  {}",
                    data.requests,
                    data.checks.len(),
                    if data.complete() {
                        "complete"
                    } else {
                        "incomplete"
                    }
                ));
            } else {
                out.plain(fitted("  ", &terminal_text(&finding.value), opts, false));
            }
        }
    }
    out.blank();
    out.plain("Signals: RCE: not tested (no detector). Counts are findings, not test coverage.");
    out
}

/// Plain text of the view (tests, and the uncolored path).
#[cfg(test)]
fn render(report: &SessionReport, opts: ShowOpts) -> String {
    paint(&render_doc(report, opts), ColorMode::None)
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

fn write_finding(out: &mut Doc, index: usize, finding: &Finding, opts: ShowOpts) {
    out.push(
        Tone::of(finding.severity()),
        format!(
            "  {:>2}. [{}] {}  \u{b7}  {}  \u{b7}  confidence={}  \u{b7}  {}",
            index,
            finding.severity().tag().trim(),
            finding.category(),
            finding.status.slug(),
            finding.confidence.slug(),
            finding.assessment()
        ),
    );
    out.plain(fitted(
        "      ",
        &terminal_text(finding.display_value()),
        opts,
        false,
    ));
    if let Some(url) = &finding.url {
        out.plain(fitted(
            "      URL       ",
            &terminal_text(&redact_url(url)),
            opts,
            true,
        ));
    }
    if let Some(evidence) = &finding.evidence {
        out.plain(fitted(
            "      Check     ",
            &terminal_text(&evidence.check),
            opts,
            false,
        ));
        if let Some(observation) = evidence
            .observations
            .iter()
            .find(|observation| !observation.excerpt.is_empty())
        {
            out.plain(fitted(
                "      Evidence  ",
                &terminal_text(&observation.excerpt),
                opts,
                false,
            ));
        }
    }
    if !finding.justification.is_empty() {
        out.plain(fitted(
            "      Reason    ",
            &terminal_text(&finding.justification),
            opts,
            false,
        ));
    }
}

/// SGR prefix: bold + foreground, truecolor or the nearest xterm-256 entry.
fn sgr(mode: ColorMode, rgb: (u8, u8, u8), xterm256: u8) -> String {
    if mode == ColorMode::Truecolor {
        format!("\x1b[1;38;2;{};{};{}m", rgb.0, rgb.1, rgb.2)
    } else {
        format!("\x1b[1;38;5;{xterm256}m")
    }
}

/// Join the lines, wrapping each in the escape for its [`Tone`] when `mode`
/// allows color.
fn paint(doc: &Doc, mode: ColorMode) -> String {
    let prefix = |tone: Tone| -> String {
        if !mode.enabled() {
            return String::new();
        }
        match tone {
            Tone::Alert => sgr(mode, (229, 101, 63), 202),
            Tone::Warn => sgr(mode, (240, 181, 99), 215),
            Tone::Title => sgr(mode, (250, 244, 232), 230),
            Tone::Section => sgr(mode, (163, 154, 146), 246),
            Tone::Plain => String::new(),
        }
    };
    let mut out = String::new();
    for (tone, text) in &doc.0 {
        let color = prefix(*tone);
        out.push_str(&color);
        out.push_str(text);
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
    const FULL: ShowOpts = ShowOpts {
        limit: None,
        width: None,
    };
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
        let text = render(&report, FULL);
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
        let text = render(&report, FULL);
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

    fn report_with(values: &[(FindingKind, &str)]) -> SessionReport {
        let mission = Mission::new("m", Scope::default(), vec![]);
        let session_id = mission.id;
        let findings = values
            .iter()
            .map(|(kind, value)| {
                Finding::new(
                    session_id,
                    *kind,
                    None,
                    *value,
                    Confidence::High,
                    Provenance::new(Source::JsAst, None),
                )
            })
            .collect();
        SessionReport::build(mission, findings, vec![])
    }

    #[test]
    fn target_text_cannot_spoof_severity_colors() {
        let report = report_with(&[(FindingKind::Technology, "[CRIT] [HIGH] fake")]);
        let colored = paint(&render_doc(&report, FULL), ColorMode::Truecolor);
        let line = colored.lines().find(|l| l.contains("fake")).unwrap();
        assert!(!line.contains('\x1b'), "{line:?}");
    }

    #[test]
    fn limit_and_all_control_surface_rows() {
        let report = report_with(&[
            (FindingKind::Endpoint, "https://a.test/1"),
            (FindingKind::Endpoint, "https://a.test/2"),
            (FindingKind::Endpoint, "https://a.test/3"),
        ]);
        let some = ShowOpts {
            limit: Some(1),
            width: None,
        };
        assert!(render(&report, some).contains("+ 2 more"));
        assert!(!render(&report, FULL).contains("more ("));
    }

    #[test]
    fn long_urls_are_cut_in_the_middle_to_the_terminal_width() {
        let url = "https://example.test/aaaa/bbbb/cccc/dddd/eeee/ffff/gggg/hhhh/final.js";
        let report = report_with(&[(FindingKind::Endpoint, url)]);
        let narrow = ShowOpts {
            limit: None,
            width: Some(50),
        };
        let text = render(&report, narrow);
        let row = text
            .lines()
            .find(|l| l.trim_start().starts_with('['))
            .unwrap();
        assert!(row.chars().count() <= 50, "{row}");
        assert!(
            row.contains('\u{2026}') && row.ends_with("final.js"),
            "{row}"
        );
    }
}
