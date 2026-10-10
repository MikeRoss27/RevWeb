// crates/webrev-report/src/format.rs
//! Output formats for a [`SessionReport`].
//!
//! Recon output is only useful if it composes with the rest of a toolchain, so
//! the report renders to more than one shape:
//!
//! - [`ReportFormat::Json`]  — the full pretty document (default).
//! - [`ReportFormat::Jsonl`] — one finding per line (stream into `jq`, etc.).
//! - [`ReportFormat::Urls`]  — bare endpoint URLs, one per line, ready to pipe
//!   into `ffuf` / `httpx` / `nuclei`.
//! - [`ReportFormat::Csv`]   — findings as a spreadsheet-friendly table.
//!
//! Two filters narrow the output: a minimum [`Confidence`] (applied to
//! findings) and an [`EndpointScope`] selector (applied to the URL list).

use crate::json::SessionReport;
use std::collections::BTreeSet;
use std::fmt;
use webrev_core::{Confidence, EndpointScope, Finding, Result, Severity, WebrevError};

/// The serialization shape requested on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Jsonl,
    Urls,
    Csv,
}

/// Which endpoints the URL list should include.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeFilter {
    All,
    Internal,
    External,
}

impl ScopeFilter {
    fn matches(self, scope: EndpointScope) -> bool {
        match self {
            ScopeFilter::All => true,
            ScopeFilter::Internal => scope == EndpointScope::Internal,
            ScopeFilter::External => scope == EndpointScope::External,
        }
    }
}

/// How to render a report: format plus the two filters.
#[derive(Debug, Clone, Copy)]
pub struct RenderOptions {
    pub format: ReportFormat,
    pub scope: ScopeFilter,
    /// Findings below this confidence are dropped from finding-oriented output.
    pub min_confidence: Confidence,
    /// Findings below this severity are dropped from finding-oriented output.
    pub min_severity: Severity,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            format: ReportFormat::Json,
            scope: ScopeFilter::All,
            min_confidence: Confidence::Low,
            min_severity: Severity::Info,
        }
    }
}

impl SessionReport {
    /// Render the report in the requested format, applying the filters.
    pub fn render(&self, opts: RenderOptions) -> Result<String> {
        match opts.format {
            ReportFormat::Json => self.render_json(opts),
            ReportFormat::Jsonl => self.render_jsonl(opts),
            ReportFormat::Urls => Ok(self.render_urls(opts)),
            ReportFormat::Csv => Ok(self.render_csv(opts)),
        }
    }

    /// Findings passing both floors, in stored order.
    fn kept_findings(&self, opts: RenderOptions) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| {
            f.confidence >= opts.min_confidence && f.severity() >= opts.min_severity
        })
    }

    /// The kept findings, ranked by severity then confidence (both descending)
    /// so the most important rows lead the triage-oriented exports.
    fn ranked_findings(&self, opts: RenderOptions) -> Vec<&Finding> {
        let mut findings: Vec<&Finding> = self.kept_findings(opts).collect();
        findings.sort_by(|a, b| {
            b.severity()
                .cmp(&a.severity())
                .then(b.confidence.cmp(&a.confidence))
        });
        findings
    }

    fn render_json(&self, opts: RenderOptions) -> Result<String> {
        // When no filter is active, emit the document verbatim; otherwise emit a
        // filtered clone so counts and contents stay consistent.
        if opts.min_confidence == Confidence::Low
            && opts.min_severity == Severity::Info
            && opts.scope == ScopeFilter::All
        {
            return self.to_json();
        }
        let mut filtered = self.clone();
        filtered.findings = self.kept_findings(opts).cloned().collect();
        filtered.endpoints = self
            .endpoints
            .iter()
            .filter(|e| opts.scope.matches(e.scope))
            .cloned()
            .collect();
        filtered.summary = crate::Summary::from_findings(&filtered.findings);
        filtered.summary.set_endpoint_scopes(&filtered.endpoints);
        filtered.to_json()
    }

    fn render_jsonl(&self, opts: RenderOptions) -> Result<String> {
        let mut out = String::new();
        for finding in self.ranked_findings(opts) {
            let line = serde_json::to_string(finding)
                .map_err(|e| WebrevError::Config(format!("serializing finding: {e}")))?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }

    /// Unique endpoint URLs (scope-filtered), sorted — the pipe-into-ffuf view.
    fn render_urls(&self, opts: RenderOptions) -> String {
        let urls: BTreeSet<&str> = self
            .endpoints
            .iter()
            .filter(|e| opts.scope.matches(e.scope))
            .map(|e| e.url.as_str())
            .collect();
        let mut out: String = urls.into_iter().fold(String::new(), |mut acc, u| {
            acc.push_str(u);
            acc.push('\n');
            acc
        });
        if out.is_empty() {
            out
        } else {
            out.truncate(out.trim_end().len());
            out
        }
    }

    fn render_csv(&self, opts: RenderOptions) -> String {
        let mut out = String::from("severity,kind,confidence,url,value,source\n");
        for f in self.ranked_findings(opts) {
            let row = [
                f.severity().slug().to_owned(),
                f.kind.slug().to_owned(),
                f.confidence.slug().to_owned(),
                f.url.clone().unwrap_or_default(),
                f.value.clone(),
                f.provenance.source.to_string(),
            ];
            let line: Vec<String> = row.iter().map(|c| csv_field(c)).collect();
            out.push_str(&line.join(","));
            out.push('\n');
        }
        out
    }
}

/// Minimal RFC-4180 CSV quoting: wrap in quotes and double embedded quotes when
/// the field contains a comma, quote, or newline.
fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReportFormat::Json => "json",
            ReportFormat::Jsonl => "jsonl",
            ReportFormat::Urls => "urls",
            ReportFormat::Csv => "csv",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{
        Endpoint, Finding, FindingKind, Method, Mission, Provenance, Scope, Source,
    };

    fn report() -> SessionReport {
        let mission = Mission::new("t", Scope::new(vec!["x.test".into()], vec![]), vec![]);
        let sid = mission.id;
        let findings = vec![
            Finding::new(sid, FindingKind::Endpoint, Some("https://x.test/api/v1/users".into()), "GET https://x.test/api/v1/users", Confidence::High, Provenance::new(Source::JsAst, None)),
            Finding::new(sid, FindingKind::Parameter, None, "noisyParam", Confidence::Low, Provenance::new(Source::JsRegex, None)),
        ];
        let endpoints = vec![
            Endpoint::new("https://x.test/a", Method::Get, Source::JsAst),
            Endpoint::new("https://cdn.other/x.js", Method::Unknown, Source::JsRegex)
                .with_scope(EndpointScope::External),
        ];
        SessionReport::build(mission, findings, endpoints)
    }

    fn opts(format: ReportFormat, scope: ScopeFilter, min: Confidence) -> RenderOptions {
        RenderOptions { format, scope, min_confidence: min, min_severity: Severity::Info }
    }

    #[test]
    fn urls_are_scope_filtered_and_sorted() {
        let all = report().render(opts(ReportFormat::Urls, ScopeFilter::All, Confidence::Low)).unwrap();
        assert_eq!(all.lines().count(), 2);

        let internal = report().render(opts(ReportFormat::Urls, ScopeFilter::Internal, Confidence::Low)).unwrap();
        assert_eq!(internal, "https://x.test/a");

        let external = report().render(opts(ReportFormat::Urls, ScopeFilter::External, Confidence::Low)).unwrap();
        assert_eq!(external, "https://cdn.other/x.js");
    }

    #[test]
    fn min_confidence_drops_low_findings_from_jsonl() {
        let r = report();
        let all = r.render(opts(ReportFormat::Jsonl, ScopeFilter::All, Confidence::Low)).unwrap();
        assert_eq!(all.lines().count(), 2);
        let high = r.render(opts(ReportFormat::Jsonl, ScopeFilter::All, Confidence::High)).unwrap();
        assert_eq!(high.lines().count(), 1);
        assert!(high.contains("x.test/api/v1/users"));
    }

    #[test]
    fn csv_has_header_and_quotes_commas() {
        let r = report();
        let csv = r.render(opts(ReportFormat::Csv, ScopeFilter::All, Confidence::Low)).unwrap();
        assert!(csv.starts_with("severity,kind,confidence,url,value,source\n"));
        assert_eq!(csv.lines().count(), 3); // header + 2 findings
        // Ranked: the medium-severity endpoint precedes the info-level param.
        let first = csv.lines().nth(1).unwrap();
        assert!(first.starts_with("medium,endpoint"));
    }

    #[test]
    fn min_severity_drops_low_signal_findings() {
        let r = report();
        let opts = RenderOptions {
            format: ReportFormat::Jsonl,
            scope: ScopeFilter::All,
            min_confidence: Confidence::Low,
            min_severity: Severity::Medium,
        };
        let out = r.render(opts).unwrap();
        // Only the /api/v1 endpoint (medium) survives; the info-level param is cut.
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("x.test/api/v1/users"));
    }

    #[test]
    fn csv_field_quotes_when_needed() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn filtered_json_recounts_summary() {
        let r = report();
        let json = r.render(opts(ReportFormat::Json, ScopeFilter::Internal, Confidence::High)).unwrap();
        // Only the high-confidence endpoint finding survives.
        assert!(json.contains("\"total\": 1"));
        assert!(json.contains("\"internal\": 1"));
        assert!(!json.contains("noisyParam"));
    }
}
