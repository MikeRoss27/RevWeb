// crates/webrev-tui/src/app.rs
//! The TUI application state and the events that mutate it.
//!
//! State-only: no rendering and no I/O live here, which keeps the update logic
//! unit-testable (see the tests at the bottom). Rendering reads this state in
//! `ui.rs`; the event loop in `lib.rs` feeds it [`UiEvent`]s and key actions.

use ratatui::widgets::ListState;
use webrev_core::{Finding, FindingKind};

/// Maximum number of log lines retained in memory.
const MAX_LOGS: usize = 1000;

/// The four tabs shown in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Endpoints,
    Findings,
    Logs,
    Status,
}

impl Tab {
    /// All tabs, in display order.
    pub const ALL: [Tab; 4] = [Tab::Endpoints, Tab::Findings, Tab::Logs, Tab::Status];

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Tab::Endpoints => "Endpoints",
            Tab::Findings => "Findings",
            Tab::Logs => "Logs",
            Tab::Status => "Status",
        }
    }

    #[must_use]
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    #[must_use]
    pub fn next(self) -> Tab {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    #[must_use]
    pub fn prev(self) -> Tab {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    /// Whether this tab shows a scrollable list.
    #[must_use]
    pub fn is_list(self) -> bool {
        !matches!(self, Tab::Status)
    }
}

/// Events that drive the UI, merged from the pipeline and background tasks.
#[derive(Debug, Clone)]
pub enum UiEvent {
    /// Forwarded from the pipeline's broadcast channel.
    Pipeline(webrev_pipeline::PipelineEvent),
    /// A one-line status update (e.g. a scan starting or finishing).
    Status(String),
}

/// All mutable UI state.
pub struct App {
    pub mission_name: String,
    pub tab: Tab,
    pub endpoints: Vec<String>,
    pub findings: Vec<String>,
    pub logs: Vec<String>,
    pub status: String,
    pub secrets: usize,
    pub scanning: bool,
    pub should_quit: bool,
    /// Selection/scroll state for the active list tab.
    pub list_state: ListState,
    /// When true, the selection sticks to the newest item as entries arrive.
    follow: bool,
}

impl App {
    #[must_use]
    pub fn new(mission_name: String) -> Self {
        Self {
            mission_name,
            tab: Tab::Endpoints,
            endpoints: Vec::new(),
            findings: Vec::new(),
            logs: Vec::new(),
            status: "idle".to_owned(),
            secrets: 0,
            scanning: false,
            should_quit: false,
            list_state: ListState::default(),
            follow: true,
        }
    }

    /// The items backing the active list tab (empty for the Status tab).
    #[must_use]
    pub fn current_items(&self) -> &[String] {
        match self.tab {
            Tab::Endpoints => &self.endpoints,
            Tab::Findings => &self.findings,
            Tab::Logs => &self.logs,
            Tab::Status => &[],
        }
    }

    fn current_len(&self) -> usize {
        self.current_items().len()
    }

    /// Switch tabs, resetting the view to follow the newest item.
    pub fn select_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.follow = true;
        self.refresh_follow();
    }

    /// Re-pin the selection to the last item when following.
    fn refresh_follow(&mut self) {
        if self.follow && self.tab.is_list() {
            self.list_state.select(self.current_len().checked_sub(1));
        }
    }

    /// Clamp the selection into range after the active list changes size.
    fn clamp_selection(&mut self) {
        let len = self.current_len();
        match self.list_state.selected() {
            _ if len == 0 => self.list_state.select(None),
            Some(i) if i >= len => self.list_state.select(Some(len - 1)),
            _ => {}
        }
    }

    pub fn scroll_down(&mut self) {
        if !self.tab.is_list() || self.current_len() == 0 {
            return;
        }
        self.follow = false;
        self.list_state.select_next();
        self.clamp_selection();
    }

    pub fn scroll_up(&mut self) {
        if !self.tab.is_list() {
            return;
        }
        self.follow = false;
        self.list_state.select_previous();
    }

    pub fn scroll_to_top(&mut self) {
        if !self.tab.is_list() {
            return;
        }
        self.follow = false;
        self.list_state.select_first();
        self.clamp_selection();
    }

    pub fn scroll_to_bottom(&mut self) {
        self.follow = true;
        self.refresh_follow();
    }

    fn push_log(&mut self, line: String) {
        self.logs.push(line);
        if self.logs.len() > MAX_LOGS {
            self.logs.remove(0);
        }
    }

    /// Apply a merged UI event, keeping the follow-tail invariant.
    pub fn apply(&mut self, event: UiEvent) {
        match event {
            UiEvent::Pipeline(pe) => self.apply_pipeline(pe),
            UiEvent::Status(s) => {
                self.push_log(format!("[status] {s}"));
                self.status = s;
            }
        }
        self.refresh_follow();
    }

    fn apply_pipeline(&mut self, event: webrev_pipeline::PipelineEvent) {
        use webrev_pipeline::PipelineEvent as Pe;
        match event {
            Pe::StageStarted { stage } => {
                self.scanning = true;
                self.push_log(format!("[{stage}] started"));
            }
            Pe::StageCompleted { stage, emitted } => {
                self.push_log(format!("[{stage}] completed ({emitted} emitted)"));
            }
            Pe::Progress { stage, processed } => {
                self.push_log(format!("[{stage}] progress: {processed}"));
            }
            Pe::Error { stage, message } => {
                self.push_log(format!("[{stage}] ERROR: {message}"));
            }
            Pe::SecretDetected { fingerprint } => {
                self.secrets += 1;
                self.push_log(format!("[secret] {fingerprint}"));
            }
            Pe::Finding(finding) => self.record_finding(&finding),
        }
    }

    fn record_finding(&mut self, finding: &Finding) {
        let locus = finding.url.as_deref().unwrap_or(&finding.value);
        let line = format!(
            "{:<9} {} [{}]",
            finding.kind.slug(),
            locus,
            finding.provenance.source
        );
        if finding.kind == FindingKind::Endpoint {
            self.endpoints.push(line.clone());
        }
        self.findings.push(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{Confidence, Provenance, SessionId, Source};
    use webrev_pipeline::PipelineEvent;

    fn endpoint_event() -> UiEvent {
        let f = Finding::new(
            SessionId::new(),
            FindingKind::Endpoint,
            Some("/api".into()),
            "GET /api",
            Confidence::High,
            Provenance::new(Source::JsAst, None),
        );
        UiEvent::Pipeline(PipelineEvent::Finding(Box::new(f)))
    }

    #[test]
    fn tab_cycles_both_ways() {
        assert_eq!(Tab::Endpoints.next(), Tab::Findings);
        assert_eq!(Tab::Endpoints.prev(), Tab::Status);
    }

    #[test]
    fn endpoint_finding_lands_in_both_lists() {
        let mut app = App::new("m".into());
        app.apply(endpoint_event());
        assert_eq!(app.endpoints.len(), 1);
        assert_eq!(app.findings.len(), 1);
    }

    #[test]
    fn follow_tail_tracks_newest_then_releases_on_scroll_up() {
        let mut app = App::new("m".into());
        app.apply(endpoint_event());
        app.apply(endpoint_event());
        // Following: selection pinned to the last item.
        assert_eq!(app.list_state.selected(), Some(1));

        app.scroll_up();
        assert_eq!(app.list_state.selected(), Some(0));
        // A new arrival no longer moves the selection while scrolled up.
        app.apply(endpoint_event());
        assert_eq!(app.list_state.selected(), Some(0));

        // Jumping back to the bottom re-enables follow.
        app.scroll_to_bottom();
        assert_eq!(app.list_state.selected(), Some(2));
    }
}
