//! Render the frame by composing chrome, panels and overlays.
mod chrome;
mod overlays;
mod panels;
#[cfg(test)]
mod tests;
mod theme;

use crate::app::App;
use chrome::{render_footer, render_header};
use overlays::{render_detail, render_help, render_quit_confirm, render_toast};
use panels::render_body;
use ratatui::{
    layout::{Constraint, Layout},
    Frame,
};

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
            app.detail_scroll = render_detail(frame, body, finding, app.detail_scroll);
        }
    }

    // The help overlay floats above everything; it takes precedence visually.
    if app.show_help {
        render_help(frame, body);
    }

    if let Some(toast) = &app.toast {
        render_toast(frame, body, &toast.text);
    }
    if app.confirm_quit {
        render_quit_confirm(frame, body, app);
    }
}
