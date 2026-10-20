// crates/webrev-tui/src/events.rs
//! Key → action mapping. Terminal events are read asynchronously via
//! `crossterm::event::EventStream` in the event loop (`runtime/mod.rs`); this module
//! only decodes a key press into a high-level [`Action`].

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// A user intent decoded from a key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    /// `q` / Ctrl-C: ask to leave (confirms when work would be lost).
    Quit,
    /// Esc: close filter, detail or help in turn, then ask to leave.
    Back,
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
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        // Ctrl-C quits; other Ctrl chords must not fall through to the plain
        // letter bindings (Ctrl-D is not "dynamic scan").
        return match key.code {
            KeyCode::Char('c') => Action::Quit,
            _ => Action::None,
        };
    }
    match key.code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Esc => Action::Back,
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
    /// The pipeline broadcast overflowed; this many events never reached the UI.
    Lagged(u64),
    /// An export task finished.
    Exported(crate::app::ExportOutcome),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventKind;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        let mut event = KeyEvent::new(code, modifiers);
        event.kind = KeyEventKind::Press;
        event
    }

    fn plain(code: KeyCode) -> Action {
        map_key(key(code, KeyModifiers::NONE))
    }

    #[test]
    fn letters_map_to_their_actions() {
        for (c, want) in [
            ('q', Action::Quit),
            ('j', Action::ScrollDown),
            ('k', Action::ScrollUp),
            ('g', Action::ScrollTop),
            ('G', Action::ScrollBottom),
            ('s', Action::StartStatic),
            ('d', Action::StartDynamic),
            ('a', Action::StartActive),
            ('r', Action::ExportReport),
            ('/', Action::Filter),
            ('o', Action::ToggleSort),
            ('?', Action::ToggleHelp),
            ('x', Action::None),
        ] {
            assert_eq!(plain(KeyCode::Char(c)), want, "char {c:?}");
        }
    }

    #[test]
    fn special_keys_map_to_navigation() {
        assert_eq!(plain(KeyCode::Esc), Action::Back);
        assert_eq!(plain(KeyCode::Enter), Action::ToggleDetail);
        assert_eq!(plain(KeyCode::Tab), Action::NextTab);
        assert_eq!(plain(KeyCode::Right), Action::NextTab);
        assert_eq!(plain(KeyCode::BackTab), Action::PrevTab);
        assert_eq!(plain(KeyCode::Left), Action::PrevTab);
        assert_eq!(plain(KeyCode::Up), Action::ScrollUp);
        assert_eq!(plain(KeyCode::Down), Action::ScrollDown);
        assert_eq!(plain(KeyCode::Home), Action::ScrollTop);
        assert_eq!(plain(KeyCode::End), Action::ScrollBottom);
    }

    #[test]
    fn ctrl_c_quits_and_other_ctrl_chords_are_inert() {
        let ctrl = |c| map_key(key(KeyCode::Char(c), KeyModifiers::CONTROL));
        assert_eq!(ctrl('c'), Action::Quit);
        assert_eq!(
            ctrl('d'),
            Action::None,
            "Ctrl-D must not start a dynamic scan"
        );
        assert_eq!(ctrl('s'), Action::None);
    }
}
