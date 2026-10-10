// crates/webrev-tui/src/events.rs
//! Key → action mapping. Terminal events are read asynchronously via
//! `crossterm::event::EventStream` in the event loop (`lib.rs`); this module
//! only decodes a key press into a high-level [`Action`].

use crossterm::event::{KeyCode, KeyEvent};

/// A user intent decoded from a key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    NextTab,
    PrevTab,
    ScrollUp,
    ScrollDown,
    ScrollTop,
    ScrollBottom,
    StartStatic,
    StartDynamic,
    ExportReport,
    /// Enter filter-input mode.
    Filter,
    /// Open/close the detail overlay for the selected item.
    ToggleDetail,
    /// Toggle severity ordering of the active list.
    ToggleSort,
}

/// Map a key event to an [`Action`].
#[must_use]
pub fn map_key(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        KeyCode::Tab | KeyCode::Right => Action::NextTab,
        KeyCode::BackTab | KeyCode::Left => Action::PrevTab,
        KeyCode::Up | KeyCode::Char('k') => Action::ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => Action::ScrollDown,
        KeyCode::Home | KeyCode::Char('g') => Action::ScrollTop,
        KeyCode::End | KeyCode::Char('G') => Action::ScrollBottom,
        KeyCode::Char('s') => Action::StartStatic,
        KeyCode::Char('d') => Action::StartDynamic,
        KeyCode::Char('r') => Action::ExportReport,
        KeyCode::Char('/') => Action::Filter,
        KeyCode::Char('o') => Action::ToggleSort,
        KeyCode::Enter => Action::ToggleDetail,
        _ => Action::None,
    }
}
