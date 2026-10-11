//! Tab identity and navigation order.

/// Focused views over the same structured findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Endpoints,
    Findings,
    Vulnerabilities,
    Secrets,
    Technologies,
    Logs,
    Status,
}

impl Tab {
    /// All tabs, in display order.
    pub const ALL: [Tab; 7] = [
        Tab::Endpoints,
        Tab::Findings,
        Tab::Vulnerabilities,
        Tab::Secrets,
        Tab::Technologies,
        Tab::Logs,
        Tab::Status,
    ];

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Tab::Endpoints => "Endpoints",
            Tab::Findings => "Findings",
            Tab::Vulnerabilities => "Vulns",
            Tab::Secrets => "Secrets",
            Tab::Technologies => "Tech",
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
