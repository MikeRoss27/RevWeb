//! Application state, separated from navigation and incoming-event updates.
mod navigation;
mod tab;
#[cfg(test)]
mod tests;
mod updates;

pub use crate::events::UiEvent;
use ratatui::widgets::ListState;
pub use tab::Tab;
use webrev_core::{Finding, Scope};
/// All mutable UI state.
// Justification: these flags model genuinely independent UI concerns (scan
// running, quit requested, filter input open, follow-tail) — collapsing them
// into an enum would obscure, not clarify.
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    pub mission_name: String,
    pub tab: Tab,
    pub endpoints: Vec<String>,
    pub findings: Vec<String>,
    pub logs: Vec<String>,
    pub status: String,
    pub secrets: usize,
    pub internal_endpoints: usize,
    pub external_endpoints: usize,
    pub scanning: bool,
    pub should_quit: bool,
    /// True while the detail overlay for the selected item is open.
    pub show_detail: bool,
    pub detail_scroll: u16,
    /// True while the keyboard-help overlay is open.
    pub show_help: bool,
    /// When true, the Endpoints/Findings lists are ordered by severity (desc).
    pub sort_by_severity: bool,
    /// Selection/scroll state for the active list tab.
    pub list_state: ListState,
    /// Case-insensitive substring filter applied to the active list.
    pub filter: String,
    /// True while the filter input line is capturing keystrokes.
    pub filtering: bool,
    /// Structured records behind the Findings list (parallel to `findings`).
    finding_data: Vec<Finding>,
    /// Structured records behind the Endpoints list (parallel to `endpoints`).
    endpoint_data: Vec<Finding>,
    /// Mission scope, used to tag endpoints internal vs external.
    scope: Scope,
    /// When true, the selection sticks to the newest item as entries arrive.
    follow: bool,
    /// Animation frame counter, advanced by [`App::tick`] while a scan runs.
    pub tick_count: u64,
}

impl App {
    #[must_use]
    pub fn new(mission_name: String, scope: Scope) -> Self {
        Self {
            mission_name,
            tab: Tab::Endpoints,
            endpoints: Vec::new(),
            findings: Vec::new(),
            logs: Vec::new(),
            status: "idle".to_owned(),
            secrets: 0,
            internal_endpoints: 0,
            external_endpoints: 0,
            scanning: false,
            should_quit: false,
            show_detail: false,
            detail_scroll: 0,
            show_help: false,
            sort_by_severity: false,
            list_state: ListState::default(),
            filter: String::new(),
            filtering: false,
            finding_data: Vec::new(),
            endpoint_data: Vec::new(),
            scope,
            follow: true,
            tick_count: 0,
        }
    }
}
