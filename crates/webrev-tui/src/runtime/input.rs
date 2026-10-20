//! Dispatch terminal actions and filter-input keys.
use super::controller::Controller;
use crate::{
    app::{App, UiEvent},
    events::Action,
};
use tokio::sync::mpsc::UnboundedSender;

/// While the filter line is open, keys edit the filter string instead of
/// triggering actions. Enter confirms (keeps the filter), Esc cancels (clears),
/// Ctrl-U clears the text, Ctrl-C asks to quit.
pub(super) fn handle_filter_key(key: crossterm::event::KeyEvent, app: &mut App) {
    use crossterm::event::{KeyCode, KeyModifiers};
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('c') => app.request_quit(),
            KeyCode::Char('u') => {
                app.filter.clear();
                app.after_filter_change();
            }
            _ => {}
        }
        return;
    }
    match key.code {
        KeyCode::Esc => app.filter_cancel(),
        KeyCode::Enter => app.filter_confirm(),
        KeyCode::Backspace => app.filter_backspace(),
        KeyCode::Char(c) => app.filter_push(c),
        _ => {}
    }
}

/// Keys while the quit dialog is open: `e` export then quit, `y` (or Ctrl-C
/// again) quit now, anything else cancels.
pub(super) fn handle_confirm_key(
    key: crossterm::event::KeyEvent,
    app: &mut App,
    controller: &Controller,
    ui_tx: &UnboundedSender<UiEvent>,
) {
    use crossterm::event::{KeyCode, KeyModifiers};
    let ctrl_c = key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c');
    match key.code {
        _ if ctrl_c => app.should_quit = true,
        KeyCode::Char('y' | 'Y') => app.should_quit = true,
        KeyCode::Char('e' | 'E') => {
            app.quit_after_export = true;
            controller.spawn_export(app.report_written, ui_tx.clone());
            app.show_toast("exporting report…");
        }
        _ => app.confirm_quit = false,
    }
}

/// Apply a decoded key action to the app and controller.
pub(super) fn handle_action(
    action: Action,
    app: &mut App,
    controller: &Controller,
    ui_tx: &UnboundedSender<UiEvent>,
) {
    // Only an immediate second `r` confirms overwriting an existing report.
    let overwrite_confirmed = std::mem::take(&mut app.overwrite_pending);
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
        Action::Quit => app.request_quit(),
        Action::Back => app.back(),
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
            app.begin_scan();
            controller.start_static(ui_tx.clone());
            app.apply(UiEvent::Status("static scan started".to_owned()));
        }
        Action::StartDynamic if !app.scanning => {
            app.begin_scan();
            controller.start_dynamic(ui_tx.clone());
            app.apply(UiEvent::Status("dynamic scan started".to_owned()));
        }
        Action::StartActive if !app.scanning => {
            app.begin_scan();
            controller.start_active(ui_tx.clone());
            app.apply(UiEvent::Status(
                "active probes started (authorized targets only)".to_owned(),
            ));
        }
        Action::StartStatic | Action::StartDynamic | Action::StartActive => {
            app.apply(UiEvent::Status("a scan is already running".to_owned()));
        }
        Action::ExportReport => {
            controller.spawn_export(overwrite_confirmed || app.report_written, ui_tx.clone());
            app.show_toast("exporting report…");
        }
        Action::Filter => app.begin_filter(),
        Action::None => {}
    }
}
