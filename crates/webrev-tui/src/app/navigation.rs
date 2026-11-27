//! Filtering, selection, ordering and follow-tail behavior.

use super::{App, Tab};
use webrev_core::Finding;

impl App {
    pub(crate) fn latest_active_coverage(&self) -> Option<&webrev_core::Finding> {
        self.finding_data
            .iter()
            .rev()
            .find(|f| f.coverage.is_some())
    }
    /// The full items backing the active list tab (empty for the Status tab).
    #[must_use]
    pub fn current_items(&self) -> &[String] {
        match self.tab {
            Tab::Endpoints => &self.endpoints,
            Tab::Findings | Tab::Vulnerabilities | Tab::Secrets | Tab::Technologies => {
                &self.findings
            }
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
        if let Some(data) = self.active_records() {
            indices.retain(|&i| self.tab_accepts(&data[i]));
        }
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
            Tab::Findings | Tab::Vulnerabilities | Tab::Secrets | Tab::Technologies => {
                Some(&self.finding_data)
            }
            Tab::Logs | Tab::Status => None,
        }
    }

    fn tab_accepts(&self, finding: &Finding) -> bool {
        use webrev_core::FindingKind;
        match self.tab {
            Tab::Vulnerabilities => finding.is_vulnerability(),
            Tab::Secrets => finding.kind == FindingKind::Secret,
            Tab::Technologies => finding.kind == FindingKind::Technology,
            _ => true,
        }
    }

    /// Number of records belonging to this tab before the text filter.
    #[must_use]
    pub fn tab_count(&self, tab: Tab) -> usize {
        match tab {
            Tab::Endpoints => self.endpoints.len(),
            Tab::Findings => self.findings.len(),
            Tab::Vulnerabilities => self
                .finding_data
                .iter()
                .filter(|f| f.is_vulnerability())
                .count(),
            Tab::Secrets => self
                .finding_data
                .iter()
                .filter(|f| f.kind == webrev_core::FindingKind::Secret)
                .count(),
            Tab::Technologies => self
                .finding_data
                .iter()
                .filter(|f| f.kind == webrev_core::FindingKind::Technology)
                .count(),
            Tab::Logs => self.logs.len(),
            Tab::Status => 0,
        }
    }

    #[must_use]
    pub fn category_count(&self, category: &str) -> usize {
        self.finding_data
            .iter()
            .filter(|f| f.category() == category)
            .count()
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

    /// Toggle the keyboard-help overlay.
    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    /// Toggle the detail overlay (no-op on tabs without records).
    pub fn toggle_detail(&mut self) {
        if self.show_detail {
            self.show_detail = false;
        } else if self.selected_record().is_some() {
            self.detail_scroll = 0;
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

    pub(crate) fn after_filter_change(&mut self) {
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
    pub(super) fn refresh_follow(&mut self) {
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
}
