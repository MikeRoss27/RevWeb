// crates/webrev-tui/src/app.rs
//! The TUI application state and the events that mutate it.
//!
//! State-only: no rendering and no I/O live here, which keeps the update logic
//! unit-testable (see the tests at the bottom). Rendering reads this state in
//! `ui.rs`; the event loop in `lib.rs` feeds it [`UiEvent`]s and key actions.

use ratatui::widgets::ListState;
use webrev_core::{EndpointScope, Finding, FindingKind, Scope};

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
            sort_by_severity: false,
            list_state: ListState::default(),
            filter: String::new(),
            filtering: false,
            finding_data: Vec::new(),
            endpoint_data: Vec::new(),
            scope,
            follow: true,
        }
    }

    /// The full items backing the active list tab (empty for the Status tab).
    #[must_use]
    pub fn current_items(&self) -> &[String] {
        match self.tab {
            Tab::Endpoints => &self.endpoints,
            Tab::Findings => &self.findings,
            Tab::Logs => &self.logs,
            Tab::Status => &[],
        }
    }

    /// Indices into `current_items` that pass the active filter, in order —
    /// then optionally re-ordered by severity (descending) for the record tabs.
    fn visible_source_indices(&self) -> Vec<usize> {
        let items = self.current_items();
        let mut indices: Vec<usize> = if self.filter.is_empty() {
            (0..items.len()).collect()
        } else {
            let needle = self.filter.to_lowercase();
            items
                .iter()
                .enumerate()
                .filter(|(_, line)| line.to_lowercase().contains(&needle))
                .map(|(i, _)| i)
                .collect()
        };
        if self.sort_by_severity {
            if let Some(data) = self.active_records() {
                // Stable sort by descending severity keeps discovery order
                // within a severity band.
                indices.sort_by(|&a, &b| data[b].severity().cmp(&data[a].severity()));
            }
        }
        indices
    }

    /// The structured records parallel to the active list, if it has any.
    fn active_records(&self) -> Option<&[Finding]> {
        match self.tab {
            Tab::Endpoints => Some(&self.endpoint_data),
            Tab::Findings => Some(&self.finding_data),
            Tab::Logs | Tab::Status => None,
        }
    }

    /// Toggle severity ordering of the active record list.
    pub fn toggle_sort(&mut self) {
        self.sort_by_severity = !self.sort_by_severity;
        self.follow = false;
        self.clamp_selection();
    }

    /// Items actually shown: `current_items` narrowed by the active filter.
    #[must_use]
    pub fn visible_items(&self) -> Vec<&String> {
        let items = self.current_items();
        self.visible_source_indices()
            .into_iter()
            .map(|i| &items[i])
            .collect()
    }

    /// The structured finding behind the selected row, if any (Endpoints and
    /// Findings tabs only). Maps the selection through the active filter.
    #[must_use]
    pub fn selected_record(&self) -> Option<&Finding> {
        let data = self.active_records()?;
        let pos = self.list_state.selected()?;
        let original = *self.visible_source_indices().get(pos)?;
        data.get(original)
    }

    /// Toggle the detail overlay (no-op on tabs without records).
    pub fn toggle_detail(&mut self) {
        if self.show_detail {
            self.show_detail = false;
        } else if self.selected_record().is_some() {
            self.show_detail = true;
        }
    }

    fn current_len(&self) -> usize {
        self.visible_source_indices().len()
    }

    // --- filtering --------------------------------------------------------

    /// Enter filter-input mode (keystrokes now edit the filter string).
    pub fn begin_filter(&mut self) {
        self.filtering = true;
    }

    /// Append a character to the filter and re-pin the selection.
    pub fn filter_push(&mut self, c: char) {
        self.filter.push(c);
        self.after_filter_change();
    }

    /// Delete the last filter character.
    pub fn filter_backspace(&mut self) {
        self.filter.pop();
        self.after_filter_change();
    }

    /// Confirm the filter, leaving input mode but keeping the filter active.
    pub fn filter_confirm(&mut self) {
        self.filtering = false;
    }

    /// Abandon input mode and clear the filter entirely.
    pub fn filter_cancel(&mut self) {
        self.filtering = false;
        self.filter.clear();
        self.after_filter_change();
    }

    fn after_filter_change(&mut self) {
        self.follow = true;
        self.refresh_follow();
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
        let sev = finding.severity().tag();
        let line = format!(
            "{sev} {:<9} {} [{}]",
            finding.kind.slug(),
            locus,
            finding.provenance.source
        );
        if finding.kind == FindingKind::Endpoint {
            // Tag with the in/out-of-scope classification so the Endpoints tab
            // separates the target surface from third-party references.
            let scope_tag = match self.scope.classify(locus) {
                EndpointScope::Internal => {
                    self.internal_endpoints += 1;
                    "int"
                }
                EndpointScope::External => {
                    self.external_endpoints += 1;
                    "ext"
                }
            };
            self.endpoints.push(format!(
                "{sev} {scope_tag} {} [{}]",
                finding.value, finding.provenance.source
            ));
            self.endpoint_data.push(finding.clone());
        }
        self.findings.push(line);
        self.finding_data.push(finding.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{Confidence, Provenance, SessionId, Source};
    use webrev_pipeline::PipelineEvent;

    fn app() -> App {
        App::new("m".into(), Scope::new(vec!["x.test".into()], vec![]))
    }

    fn endpoint_event() -> UiEvent {
        finding_event(FindingKind::Endpoint, Some("/api".into()), "GET /api")
    }

    fn finding_event(kind: FindingKind, url: Option<String>, value: &str) -> UiEvent {
        let f = Finding::new(
            SessionId::new(),
            kind,
            url,
            value,
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
        let mut app = app();
        app.apply(endpoint_event());
        assert_eq!(app.endpoints.len(), 1);
        assert_eq!(app.findings.len(), 1);
    }

    #[test]
    fn endpoints_are_tagged_internal_vs_external() {
        let mut app = app();
        app.apply(finding_event(FindingKind::Endpoint, Some("https://x.test/a".into()), "GET https://x.test/a"));
        app.apply(finding_event(FindingKind::Endpoint, Some("https://cdn.other/x".into()), "GET https://cdn.other/x"));
        assert_eq!(app.internal_endpoints, 1);
        assert_eq!(app.external_endpoints, 1);
        // Lines lead with a severity tag, then the scope tag.
        assert!(app.endpoints[0].contains(" int "));
        assert!(app.endpoints[1].contains(" ext "));
    }

    #[test]
    fn sort_by_severity_orders_high_first() {
        let mut app = app();
        // Info-level param, then a high-severity admin endpoint.
        app.apply(finding_event(FindingKind::Parameter, None, "q"));
        app.apply(finding_event(FindingKind::Endpoint, Some("https://x.test/admin".into()), "GET https://x.test/admin"));
        app.select_tab(Tab::Findings);
        // Natural order: param first.
        assert!(app.visible_items()[0].starts_with("INFO"));
        app.toggle_sort();
        // Severity order: the admin endpoint (HIGH) leads.
        assert!(app.visible_items()[0].starts_with("HIGH"));
    }

    #[test]
    fn selected_record_follows_filter_mapping() {
        let mut app = app();
        app.apply(finding_event(FindingKind::Endpoint, Some("https://x.test/login".into()), "GET https://x.test/login"));
        app.apply(finding_event(FindingKind::Endpoint, Some("https://x.test/health".into()), "GET https://x.test/health"));
        // Filter to the second item; the selection must resolve to its record.
        app.begin_filter();
        for c in "health".chars() {
            app.filter_push(c);
        }
        let record = app.selected_record().expect("a selected record");
        assert!(record.value.contains("/health"));
        // Detail opens only when something is selected.
        app.toggle_detail();
        assert!(app.show_detail);
    }

    #[test]
    fn filter_narrows_visible_items() {
        let mut app = app();
        app.apply(finding_event(FindingKind::Endpoint, Some("https://x.test/login".into()), "GET https://x.test/login"));
        app.apply(finding_event(FindingKind::Endpoint, Some("https://x.test/assets/app.js".into()), "GET https://x.test/assets/app.js"));
        assert_eq!(app.visible_items().len(), 2);

        app.begin_filter();
        for c in "login".chars() {
            app.filter_push(c);
        }
        assert_eq!(app.visible_items().len(), 1);
        assert!(app.visible_items()[0].contains("login"));

        app.filter_cancel();
        assert_eq!(app.visible_items().len(), 2);
    }

    #[test]
    fn follow_tail_tracks_newest_then_releases_on_scroll_up() {
        let mut app = app();
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
