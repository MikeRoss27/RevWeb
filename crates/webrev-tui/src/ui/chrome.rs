//! Header tabs and footer/status controls.
use super::theme::{ACCENT, PRIMARY, VOID};
use crate::app::{App, Tab};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Paragraph, Tabs},
    Frame,
};

pub(super) fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    // Branded title: the `<_` badge + wordmark + mission, with the version
    // pinned to the right edge.
    let brand = Line::from(vec![
        Span::from(" "),
        Span::from(" <_ ")
            .fg(VOID)
            .bg(PRIMARY)
            .add_modifier(Modifier::BOLD),
        Span::from(" webrev")
            .fg(ACCENT)
            .add_modifier(Modifier::BOLD),
        Span::from("  ·  ").dim(),
        Span::from(app.mission_name.clone()),
        Span::from(" "),
    ]);
    let version =
        Line::from(Span::from(format!(" v{} ", env!("CARGO_PKG_VERSION"))).dim()).right_aligned();
    let block = Block::bordered()
        .border_style(Style::new().add_modifier(Modifier::DIM))
        .title(brand)
        .title_top(version);
    let tabs = Tabs::new(Tab::ALL.map(|tab| {
        if tab.is_list() && area.width >= 110 {
            format!("{} {}", tab.title(), app.tab_count(tab))
        } else {
            tab.title().to_owned()
        }
    }))
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

pub(super) fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    // While filtering, the top line becomes the filter input prompt.
    let top = if app.filtering {
        Line::from(vec![
            Span::from(" filter: ").bold().fg(PRIMARY),
            Span::from(app.filter.clone()),
            Span::from("▏").fg(PRIMARY),
            Span::from("  (Enter apply · Esc clear)").dim(),
        ])
    } else {
        let status = webrev_core::model::triage::terminal_text(&app.status);
        if app.scanning {
            Line::from(vec![
                Span::from(format!(" {} ", app.spinner()))
                    .fg(PRIMARY)
                    .add_modifier(Modifier::BOLD),
                Span::from(app.progress_line()).fg(PRIMARY),
                Span::from("  "),
                Span::from(status).dim(),
            ])
        } else {
            Line::from(vec![
                Span::from(" ○ ready ")
                    .fg(ACCENT)
                    .add_modifier(Modifier::BOLD),
                Span::from(status),
            ])
        }
    };
    let help = Line::from(
        "? keys · Tab views · / filter · Enter detail · s/d/a scans · r report · Esc back · q quit",
    )
    .dim();
    let footer = Paragraph::new(vec![top, help]).block(Block::bordered().title(" status "));
    frame.render_widget(footer, area);
}
