//! Help and finding-detail overlays.
use super::theme::{ACCENT, PRIMARY};
use ratatui::{
    layout::{Constraint, Flex, Layout, Rect},
    style::{Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
    Frame,
};
use webrev_core::{Finding, FindingKind};

/// A centered popup listing every key binding, grouped by purpose.
pub(super) fn render_help(frame: &mut Frame, area: Rect) {
    let key = |k: &str, desc: &str| {
        Line::from(vec![
            Span::from(format!("  {k:<10}"))
                .fg(PRIMARY)
                .add_modifier(Modifier::BOLD),
            Span::from(desc.to_owned()),
        ])
    };
    let heading = |t: &str| {
        Line::from(
            Span::from(t.to_owned())
                .fg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )
    };
    let lines = vec![
        heading("Navigate"),
        key("Tab / →", "next tab"),
        key("S-Tab / ←", "previous tab"),
        key("↑ / k", "scroll up"),
        key("↓ / j", "scroll down"),
        key("g / Home", "jump to top"),
        key("G / End", "jump to bottom (resume follow)"),
        Line::from(""),
        heading("Inspect"),
        key("Enter", "open/close detail of the selected row"),
        key("/", "filter the active list (Enter apply · Esc clear)"),
        key("o", "toggle severity sort (Endpoints/Findings)"),
        Line::from(""),
        heading("Act"),
        key("s", "start a static scan"),
        key("d", "start a dynamic scan (headless Chromium)"),
        key("a", "active probes (authorized targets only)"),
        key("r", "export the JSON report"),
        key("? ", "toggle this help"),
        key("q / Esc", "close overlay, then quit"),
        Line::from(""),
        Line::from("Esc / ? to close").dim(),
    ];
    #[allow(clippy::cast_possible_truncation)]
    let height = (lines.len() as u16) + 2;
    let popup = centered_rect(area, 60, height);
    let block = Block::bordered()
        .border_style(Style::new().fg(PRIMARY))
        .title(
            Span::from(" <_ keys ")
                .fg(PRIMARY)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}

/// A centered popup showing the selected finding's full structured fields.
pub(super) fn render_detail(frame: &mut Frame, area: Rect, finding: &Finding, scroll: u16) -> u16 {
    let field = |label: &str, value: String| {
        Line::from(vec![
            Span::from(format!("{label:<12}")).bold(),
            Span::from(webrev_core::model::triage::terminal_text(&value)),
        ])
    };
    let mut lines = vec![
        field("kind", finding.kind.slug().to_owned()),
        field("category", finding.category().to_owned()),
        field("severity", finding.severity().slug().to_owned()),
        field("evidence", finding.assessment().to_owned()),
        field("confidence", finding.confidence.slug().to_owned()),
        field("source", finding.provenance.source.to_string()),
        field("url", finding.url.clone().unwrap_or_else(|| "—".to_owned())),
        field(
            if finding.kind == FindingKind::Secret {
                "fingerprint"
            } else {
                "value"
            },
            finding.value.clone(),
        ),
        field(
            "location",
            finding
                .provenance
                .location
                .clone()
                .unwrap_or_else(|| "—".to_owned()),
        ),
    ];
    if let Some(evidence) = &finding.evidence {
        lines.extend(
            evidence
                .details()
                .into_iter()
                .map(|detail| field("probe", detail)),
        );
    }
    if let Some(coverage) = &finding.coverage {
        for (check, count) in &coverage.checks {
            lines.push(field(
                "coverage",
                format!(
                    "{check}: {} selected targets, {} findings, {} inconclusive",
                    count.attempted, count.findings, count.inconclusive
                ),
            ));
        }
    }
    // Highlight the detected credential in the detail view.
    if let Some(plaintext) = &finding.plaintext {
        lines.push(Line::from(vec![
            Span::from(format!("{:<12}", "detected")).bold().red(),
            Span::from(webrev_core::model::triage::terminal_text(plaintext)).red(),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("↑↓ scroll · g top · Esc / Enter close").dim());
    // Grow the popup by the extra plaintext row so nothing is clipped.
    let height = area.height.saturating_sub(2);
    let popup = centered_rect(area, 72, height);
    let block = Block::bordered()
        .border_style(Style::new().fg(PRIMARY))
        .title(
            Span::from(" <_ detail ")
                .fg(PRIMARY)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(Clear, popup);
    let inner = block.inner(popup);
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    let maximum = paragraph
        .line_count(inner.width)
        .saturating_sub(usize::from(inner.height));
    let offset = scroll.min(u16::try_from(maximum).unwrap_or(u16::MAX));
    frame.render_widget(paragraph.block(block).scroll((offset, 0)), popup);
    offset
}

/// A rectangle of `width`×`height` centered inside `area` (clamped to it).
fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let [h] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center)
        .areas(area);
    let [v] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(h);
    v
}
