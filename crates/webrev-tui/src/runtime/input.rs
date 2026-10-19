//! Dispatch terminal actions and filter-input keys.
use super::controller::Controller;
use crate::{
    app::{App, UiEvent},
    events::Action,
};
use tokio::sync::mpsc::UnboundedSender;

/// While the filter line is open, keys edit the filter string instead of
/// triggering actions. Enter confirms (keeps the filter), Esc cancels (clears).
pub(super) fn handle_filter_key(key: crossterm::event::KeyEvent, app: &mut App) {
    use crossterm::event::KeyCode;
    match key.code {
        KeyCode::Esc => app.filter_cancel(),
        KeyCode::Enter => app.filter_confirm(),
        KeyCode::Backspace => app.filter_backspace(),
        KeyCode::Char(c) => app.filter_push(c),
        _ => {}
    }
}

/// Apply a decoded key action to the app and controller.
pub(super) async fn handle_action(
    action: Action,
    app: &mut App,
    controller: &Controller,
    ui_tx: &UnboundedSender<UiEvent>,
) {
    if app.show_detail {
        match action {
            Action::ScrollUp => {
                app.detail_scroll = app.detail_scroll.saturating_sub(1);
                return;
            }
            Action::ScrollDown => {
                app.detail_scroll = app.detail_scroll.saturating_add(1);
                return;
            }
            Action::ScrollTop => {
                app.detail_scroll = 0;
                return;
            }
            Action::NextTab | Action::PrevTab => app.show_detail = false,
            _ => {}
        }
    }
    match action {
        Action::Quit => {
            // Esc/q first dismisses an open overlay (help, then detail), then quits.
            if app.show_help {
                app.show_help = false;
            } else if app.show_detail {
                app.show_detail = false;
            } else {
                controller.cancel.cancel();
                app.should_quit = true;
            }
        }
        Action::ToggleHelp => app.toggle_help(),
        Action::ToggleDetail => app.toggle_detail(),
        Action::ToggleSort => app.toggle_sort(),
        Action::NextTab => app.select_tab(app.tab.next()),
        Action::PrevTab => app.select_tab(app.tab.prev()),
        Action::ScrollUp => app.scroll_up(),
        Action::ScrollDown => app.scroll_down(),
        Action::ScrollTop => app.scroll_to_top(),
        Action::ScrollBottom => app.scroll_to_bottom(),
        Action::StartStatic if !app.scanning => {
            app.scanning = true;
            controller.start_static(ui_tx.clone());
            app.apply(UiEvent::Status("static scan started".to_owned()));
        }
        Action::StartDynamic if !app.scanning => {
            app.scanning = true;
            controller.start_dynamic(ui_tx.clone());
            app.apply(UiEvent::Status("dynamic scan started".to_owned()));
        }
        Action::StartActive if !app.scanning => {
            app.scanning = true;
            controller.start_active(ui_tx.clone());
            app.apply(UiEvent::Status(
                "active probes started (authorized targets only)".to_owned(),
            ));
        }
        Action::StartStatic | Action::StartDynamic | Action::StartActive => {
            app.apply(UiEvent::Status("a scan is already running".to_owned()));
        }
        Action::ExportReport => {
            let status = match controller.export_report().await {
                Ok(path) if controller.redact_report => {
                    format!("report written to {} (credentials masked)", path.display())
                }
                Ok(path) => format!(
                    "report written to {}: raw, holds captured credentials (--redact to mask)",
                    path.display()
                ),
                Err(e) => format!("report failed: {e}"),
            };
            app.apply(UiEvent::Status(status));
        }
        Action::Filter => app.begin_filter(),
        Action::None => {}
    }
}
