// crates/webrev-tui/src/events.rs
//! Key → action mapping. Terminal events are read asynchronously via
//! `crossterm::event::EventStream` in the event loop (`runtime/mod.rs`); this module
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
    StartActive,
    ExportReport,
    /// Enter filter-input mode.
    Filter,
    /// Open/close the detail overlay for the selected item.
    ToggleDetail,
    /// Toggle severity ordering of the active list.
    ToggleSort,
    /// Open/close the keyboard-help overlay.
    ToggleHelp,
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
        KeyCode::Char('a') => Action::StartActive,
        KeyCode::Char('r') => Action::ExportReport,
        KeyCode::Char('/') => Action::Filter,
        KeyCode::Char('o') => Action::ToggleSort,
        KeyCode::Char('?') => Action::ToggleHelp,
        KeyCode::Enter => Action::ToggleDetail,
        _ => Action::None,
    }
}

/// Events that drive the UI, merged from the pipeline and background tasks.
#[derive(Debug, Clone)]
pub enum UiEvent {
    /// Forwarded from the pipeline's broadcast channel.
    Pipeline(webrev_pipeline::PipelineEvent),
    /// A one-line status update (e.g. a scan starting or finishing).
    Status(String),
    /// A scan task finished, including forwarding all of its pipeline events.
    ScanFinished(String),
}
