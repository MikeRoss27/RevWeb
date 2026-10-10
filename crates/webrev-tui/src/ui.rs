// crates/webrev-tui/src/ui.rs
//! Rendering. Pure view over [`App`]: header tabs, a stateful body list (or the
//! status panel), and a footer with the live status line and key help.

use crate::app::{App, Tab};
use crate::brand::{self, Rgb};
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, Paragraph, Tabs, Wrap};
use ratatui::Frame;
use webrev_core::Finding;

/// Draw the whole UI. Takes `&mut App` because the body list carries scroll
/// state rendered via `render_stateful_widget`.
pub fn render(frame: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(4),
    ])
    .areas(frame.area());

    render_header(frame, header, app);
    render_body(frame, body, app);
    render_footer(frame, footer, app);

    // The detail overlay floats above the body when open.
    if app.show_detail {
        if let Some(finding) = app.selected_record() {
            render_detail(frame, body, finding);
        }
    }

    // The help overlay floats above everything; it takes precedence visually.
    if app.show_help {
        render_help(frame, body);
    }
}

/// A centered popup listing every key binding, grouped by purpose.
fn render_help(frame: &mut Frame, area: Rect) {
    let key = |k: &str, desc: &str| {
        Line::from(vec![
            Span::from(format!("  {k:<10}")).fg(PRIMARY).add_modifier(Modifier::BOLD),
            Span::from(desc.to_owned()),
        ])
    };
    let heading = |t: &str| Line::from(Span::from(t.to_owned()).fg(ACCENT).add_modifier(Modifier::BOLD));
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
        .title(Span::from(" <_ keys ").fg(PRIMARY).add_modifier(Modifier::BOLD));
    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), popup);
}

/// A centered popup showing the selected finding's full structured fields.
fn render_detail(frame: &mut Frame, area: Rect, finding: &Finding) {
    let field = |label: &str, value: String| {
        Line::from(vec![Span::from(format!("{label:<12}")).bold(), Span::from(value)])
    };
    let mut lines = vec![
        field("kind", finding.kind.slug().to_owned()),
        field("confidence", finding.confidence.slug().to_owned()),
        field("source", finding.provenance.source.to_string()),
        field("url", finding.url.clone().unwrap_or_else(|| "—".to_owned())),
        field("value", finding.value.clone()),
        field(
            "location",
            finding.provenance.location.clone().unwrap_or_else(|| "—".to_owned()),
        ),
    ];
    // Revealed plaintext (opt-in): flagged in warning red so it reads as
    // sensitive material, not just another field.
    if let Some(plaintext) = &finding.plaintext {
        lines.push(Line::from(vec![
            Span::from(format!("{:<12}", "plaintext")).bold().red(),
            Span::from(plaintext.clone()).red(),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Esc / Enter to close").dim());
    // Grow the popup by the extra plaintext row so nothing is clipped.
    let height = 11 + u16::from(finding.plaintext.is_some());
    let popup = centered_rect(area, 72, height);
    let block = Block::bordered()
        .border_style(Style::new().fg(PRIMARY))
        .title(Span::from(" <_ detail ").fg(PRIMARY).add_modifier(Modifier::BOLD));
    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), popup);
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

const fn rgb(c: Rgb) -> Color {
    Color::Rgb(c.0, c.1, c.2)
}

/// Brand palette, shared across the UI (values live in [`crate::brand`]).
/// Orange is the one signal color: the mark, the active tab, live state and
/// severity; the rest is cream on ink with sand/mint/clay for log levels.
const PRIMARY: Color = rgb(brand::ORANGE);
const ACCENT: Color = rgb(brand::CREAM);
const WARN: Color = rgb(brand::SAND);
const VOID: Color = rgb(brand::INK);
const OK: Color = rgb(brand::MINT);
const ERR: Color = rgb(brand::CLAY);

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    // Branded title: the `<_` badge + wordmark + mission, with the version
    // pinned to the right edge.
    let brand = Line::from(vec![
        Span::from(" "),
        Span::from(" <_ ").fg(VOID).bg(PRIMARY).add_modifier(Modifier::BOLD),
        Span::from(" webrev").fg(ACCENT).add_modifier(Modifier::BOLD),
        Span::from("  ·  ").dim(),
        Span::from(app.mission_name.clone()),
        Span::from(" "),
    ]);
    let version = Line::from(Span::from(format!(" v{} ", env!("CARGO_PKG_VERSION"))).dim())
        .right_aligned();
    let block = Block::bordered()
        .border_style(Style::new().add_modifier(Modifier::DIM))
        .title(brand)
        .title_top(version);
    let tabs = Tabs::new(Tab::ALL.map(Tab::title))
        .select(app.tab.index())
        .block(block)
        .divider(Span::from("·").dim())
        .highlight_style(
            Style::new()
                .fg(VOID)
                .bg(PRIMARY)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, area);
}

fn render_body(frame: &mut Frame, area: Rect, app: &mut App) {
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
            app.current_items().len(),
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
        ("nothing here yet", "press s to start a static scan · ? for keys")
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    let art_rows = u16::try_from(brand::GLYPH.len()).unwrap_or(u16::MAX);
    if inner.height >= art_rows + 4 {
        lines.extend(brand::GLYPH.iter().map(|row| Line::from(Span::from(*row).fg(PRIMARY))));
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::from(headline).bold().fg(ACCENT)));
    lines.push(Line::from(Span::from(hint).dim()));

    let height = u16::try_from(lines.len()).unwrap_or(u16::MAX).min(inner.height);
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
        Tab::Endpoints | Tab::Findings => severity_styled(owned),
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
    let lines = vec![
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
        Line::from(format!("secrets:   {}", app.secrets)),
        Line::from(format!("log lines: {}", app.logs.len())),
        Line::from(format!("state:     {state}")),
    ];
    Paragraph::new(lines).block(Block::bordered().title(" Status "))
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    // While filtering, the top line becomes the filter input prompt.
    let top = if app.filtering {
        Line::from(vec![
            Span::from(" filter: ").bold().fg(PRIMARY),
            Span::from(app.filter.clone()),
            Span::from("▏").fg(PRIMARY),
            Span::from("  (Enter apply · Esc clear)").dim(),
        ])
    } else {
        let indicator = if app.scanning {
            Span::from(" ● scanning ").fg(PRIMARY).add_modifier(Modifier::BOLD)
        } else {
            Span::from(" ○ ready ").fg(ACCENT).add_modifier(Modifier::BOLD)
        };
        Line::from(vec![indicator, Span::from(app.status.clone())])
    };
    let help = Line::from(
        "? keys · Tab tabs · ↑↓ scroll · / filter · o sort · Enter detail · s static · d dynamic · r report · q quit",
    )
    .dim();
    let footer = Paragraph::new(vec![top, help]).block(Block::bordered().title(" status "));
    frame.render_widget(footer, area);
}
