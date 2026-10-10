// crates/webrev-tui/src/ui.rs
//! Rendering. Pure view over [`App`]: header tabs, a stateful body list (or the
//! status panel), and a footer with the live status line and key help.

use crate::app::{App, Tab};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, Paragraph, Tabs};
use ratatui::Frame;

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

    let title = format!(" {} ({}) ", app.tab.title(), app.current_items().len());
    let items: Vec<ListItem> = app
        .current_items()
        .iter()
        .map(|line| styled_item(app.tab, line))
        .collect();
    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_symbol("▶ ")
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(list, area, &mut app.list_state);
}

/// Colour log lines by severity; leave data tabs plain for readability.
fn styled_item(tab: Tab, line: &str) -> ListItem<'static> {
    let owned = line.to_owned();
    let span = if tab == Tab::Logs {
        if line.contains("ERROR") {
            owned.red()
        } else if line.starts_with("[secret]") {
            owned.yellow()
        } else if line.contains("completed") {
            owned.green()
        } else {
            owned.dim()
        }
    } else {
        Span::from(owned)
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
        Line::from(format!("endpoints: {}", app.endpoints.len())),
        Line::from(format!("findings:  {}", app.findings.len())),
        Line::from(format!("secrets:   {}", app.secrets)),
        Line::from(format!("log lines: {}", app.logs.len())),
        Line::from(format!("state:     {state}")),
    ];
    Paragraph::new(lines).block(Block::bordered().title(" Status "))
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let indicator = if app.scanning { "scanning" } else { "ready" };
    let status = Line::from(vec![
        Span::from(format!(" [{indicator}] ")).bold(),
        Span::from(app.status.clone()),
    ]);
    let help = Line::from(
        "Tab/←→ tabs · ↑↓ jk scroll · g/G top/bottom · s static · d dynamic · r report · q quit",
    )
    .dim();
    let footer = Paragraph::new(vec![status, help]).block(Block::bordered().title(" status "));
    frame.render_widget(footer, area);
}
