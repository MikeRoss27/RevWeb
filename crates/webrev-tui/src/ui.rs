// crates/webrev-tui/src/ui.rs
//! Rendering. Pure view over [`App`]: header tabs, a stateful body list (or the
//! status panel), and a footer with the live status line and key help.

use crate::app::{App, Tab};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
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

/// Brand palette, shared across the UI (see docs/assets). Acid is the one
/// signal color: keep it for the mark, the active tab, and live state.
const PRIMARY: Color = Color::Rgb(198, 255, 61); // acid  #C6FF3D
const ACCENT: Color = Color::Rgb(237, 237, 230); // bone  #EDEDE6
const ALERT: Color = Color::Rgb(255, 90, 54); // alert #FF5A36
const VOID: Color = Color::Rgb(10, 10, 10); // void  #0A0A0A

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

/// Colour log lines by log level, and record lines (Endpoints/Findings) by the
/// severity tag that leads each one.
fn styled_item(tab: Tab, line: &str) -> ListItem<'static> {
    let owned = line.to_owned();
    let span = match tab {
        Tab::Logs => {
            if line.contains("ERROR") {
                owned.red()
            } else if line.starts_with("[secret]") {
                owned.yellow()
            } else if line.contains("completed") {
                owned.green()
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
        "CRIT" => line.fg(ALERT).bold(),
        "HIGH" => line.fg(ALERT),
        "MED" => line.yellow(),
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
