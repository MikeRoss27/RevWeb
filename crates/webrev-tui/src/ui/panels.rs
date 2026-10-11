//! Lists, empty-state rendering, severity colors and status panel.
use super::theme::{ACCENT, ERR, OK, PRIMARY, VOID, WARN};
use crate::{
    app::{App, Tab},
    brand,
};
use ratatui::{
    layout::{Alignment, Constraint, Flex, Layout, Rect},
    style::{Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, List, ListItem, Paragraph},
    Frame,
};

pub(super) fn render_body(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.tab == Tab::Status {
        frame.render_widget(status_panel(app), area);
        return;
    }

    let visible = app.visible_items();
    let sort = if app.sort_by_severity && app.tab != Tab::Logs {
        " ⇅sev"
    } else {
        ""
    };
    let title = if app.filter.is_empty() {
        format!(" {} ({}){sort} ", app.tab.title(), visible.len())
    } else {
        format!(
            " {} ({}/{}) /{}{sort} ",
            app.tab.title(),
            visible.len(),
            app.tab_count(app.tab),
            app.filter
        )
    };
    if visible.is_empty() && app.tab != Tab::Logs {
        let filtered = !app.filter.is_empty();
        render_empty(frame, area, title, app.scanning, filtered);
        return;
    }
    let items: Vec<ListItem> = visible
        .iter()
        .map(|line| styled_item(app.tab, line))
        .collect();
    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_symbol("▶ ")
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(list, area, &mut app.list_state);
}

/// Empty-state panel: the symbol in brand orange over a one-line status and a
/// hint, instead of a blank bordered list. The art is dropped when it won't fit.
fn render_empty(frame: &mut Frame, area: Rect, title: String, scanning: bool, filtered: bool) {
    let block = Block::bordered().title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let (headline, hint) = if filtered {
        ("no match for this filter", "Esc clears it")
    } else if scanning {
        ("scanning…", "results stream in as they are found")
    } else {
        (
            "nothing here yet",
            "press s to start a static scan · ? for keys",
        )
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    let art_rows = u16::try_from(brand::GLYPH.len()).unwrap_or(u16::MAX);
    if inner.height >= art_rows + 4 {
        lines.extend(
            brand::GLYPH
                .iter()
                .map(|row| Line::from(Span::from(*row).fg(PRIMARY))),
        );
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::from(headline).bold().fg(ACCENT)));
    lines.push(Line::from(Span::from(hint).dim()));

    let height = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .min(inner.height);
    let [row] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(inner);
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), row);
}

/// Colour log lines by log level, and record lines (Endpoints/Findings) by the
/// severity tag that leads each one.
fn styled_item(tab: Tab, line: &str) -> ListItem<'static> {
    let owned = line.to_owned();
    let span = match tab {
        Tab::Logs => {
            if line.contains("ERROR") {
                owned.fg(ERR)
            } else if line.starts_with("[secret]") {
                owned.fg(WARN)
            } else if line.contains("completed") {
                owned.fg(OK)
            } else {
                owned.dim()
            }
        }
        Tab::Endpoints
        | Tab::Findings
        | Tab::Vulnerabilities
        | Tab::Secrets
        | Tab::Technologies => severity_styled(owned),
        Tab::Status => Span::from(owned),
    };
    ListItem::new(Line::from(span))
}

/// Style a record line by its leading severity tag (`CRIT`/`HIGH`/…).
fn severity_styled(line: String) -> Span<'static> {
    match line.split(' ').next().unwrap_or("") {
        // Critical is the one reversed-out row: ink on orange, like the active tab.
        "CRIT" => line.fg(VOID).bg(PRIMARY).bold(),
        "HIGH" => line.fg(PRIMARY).bold(),
        "MED" => line.fg(WARN),
        "LOW" => line.fg(ACCENT),
        _ => line.dim(), // INFO
    }
}

fn status_panel(app: &App) -> Paragraph<'static> {
    let state = if app.scanning { "running" } else { "idle" };
    let mut lines = vec![
        Line::from(vec![
            Span::from("mission:   ").bold(),
            Span::from(app.mission_name.clone()),
        ]),
        Line::from(format!(
            "endpoints: {} ({} internal, {} external)",
            app.endpoints.len(),
            app.internal_endpoints,
            app.external_endpoints
        )),
        Line::from(format!("findings:  {}", app.findings.len())),
        Line::from(format!("secrets:   {}", app.tab_count(Tab::Secrets))),
        Line::from(format!(
            "vulns:     {}",
            app.tab_count(Tab::Vulnerabilities)
        )),
        Line::from(format!("tech:      {}", app.tab_count(Tab::Technologies))),
        Line::from(format!(
            "signals:   IDOR {} | XSS {} | SQLi {} | SSTI {}",
            app.category_count("IDOR"),
            app.category_count("XSS"),
            app.category_count("SQLi"),
            app.category_count("SSTI")
        )),
        Line::from("RCE:       not tested (no detector)"),
        Line::from("Active:    press a to probe; IDOR needs authentication"),
        Line::from("Signals require manual verification; counts are not coverage."),
        Line::from(format!("log lines: {}", app.logs.len())),
        Line::from(format!("state:     {state}")),
    ];
    if let Some(record) = app.latest_active_coverage() {
        lines.push(Line::from(webrev_core::model::triage::terminal_text(
            &record.value,
        )));
    }
    Paragraph::new(lines).block(Block::bordered().title(" Status "))
}
