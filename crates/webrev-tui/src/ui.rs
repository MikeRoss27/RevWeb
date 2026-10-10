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
}

/// A centered popup showing the selected finding's full structured fields.
fn render_detail(frame: &mut Frame, area: Rect, finding: &Finding) {
    let popup = centered_rect(area, 72, 11);
    let field = |label: &str, value: String| {
        Line::from(vec![Span::from(format!("{label:<12}")).bold(), Span::from(value)])
    };
    let lines = vec![
        field("kind", finding.kind.slug().to_owned()),
        field("confidence", finding.confidence.slug().to_owned()),
        field("source", finding.provenance.source.to_string()),
        field("url", finding.url.clone().unwrap_or_else(|| "—".to_owned())),
        field("value", finding.value.clone()),
        field(
            "location",
            finding.provenance.location.clone().unwrap_or_else(|| "—".to_owned()),
        ),
        Line::from(""),
        Line::from("Esc / Enter to close").dim(),
    ];
    let block = Block::bordered().title(" Detail ").title_style(Style::new().bold());
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

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let tabs = Tabs::new(Tab::ALL.map(Tab::title))
        .select(app.tab.index())
        .block(Block::bordered().title(Span::from(format!(" webrev — {} ", app.mission_name)).bold()))
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
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
    let title = if app.filter.is_empty() {
        format!(" {} ({}) ", app.tab.title(), visible.len())
    } else {
        format!(
            " {} ({}/{}) /{} ",
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

/// Colour log lines by severity, and dim external (third-party) endpoints so
/// the in-scope target surface stands out; other data tabs stay plain.
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
        Tab::Endpoints if line.starts_with("ext ") => owned.dim(),
        _ => Span::from(owned),
    };
    ListItem::new(Line::from(span))
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
            Span::from(" filter: ").bold().cyan(),
            Span::from(app.filter.clone()),
            Span::from("▏").cyan(),
            Span::from("  (Enter apply · Esc clear)").dim(),
        ])
    } else {
        let indicator = if app.scanning { "scanning" } else { "ready" };
        Line::from(vec![
            Span::from(format!(" [{indicator}] ")).bold(),
            Span::from(app.status.clone()),
        ])
    };
    let help = Line::from(
        "Tab/←→ tabs · ↑↓ jk scroll · / filter · Enter detail · s static · d dynamic · r report · q quit",
    )
    .dim();
    let footer = Paragraph::new(vec![top, help]).block(Block::bordered().title(" status "));
    frame.render_widget(footer, area);
}
