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
//! - [`ReportFormat::UrlsExact`] — concrete URLs as discovered (real ids and
//!   query strings, relative references resolved), one per line, for replay
//!   and fuzzing; [`ReportFormat::Requests`] adds the HTTP method.
//! - [`ReportFormat::Csv`]   — findings as a spreadsheet-friendly table.
//!
//! Two filters narrow the output: a minimum [`Confidence`] (applied to
//! findings) and an [`EndpointScope`] selector (applied to the URL list).

use crate::json::SessionReport;
use std::collections::BTreeSet;
use std::fmt;
use webrev_core::{
    redact_url, Confidence, EndpointResolver, EndpointScope, Finding, FindingKind, Method, Result,
    Severity, WebrevError,
};

/// The serialization shape requested on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Text,
    Json,
    Jsonl,
    Urls,
    /// Concrete URLs as discovered, one per line. Unlike [`ReportFormat::Urls`],
    /// which lists the stored route templates (`/users/{id}`, no query string),
    /// this keeps real path ids and query strings.
    UrlsExact,
    /// `METHOD URL` per line, from the same concrete URLs as `UrlsExact`.
    Requests,
    Csv,
    /// Reconstructed `OpenAPI` 3.1 document (reverse the API from the consumer).
    OpenApi,
    /// Graphviz directed graph of observed endpoint, component and parameter links.
    Dot,
    /// `GraphML` directed graph, suitable for Gephi and other graph tooling.
    GraphMl,
}

/// Which endpoints the URL list should include.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeFilter {
    All,
    Internal,
    External,
}

impl ScopeFilter {
    pub(crate) fn matches(self, scope: EndpointScope) -> bool {
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
    /// Mask credentials in URLs, evidence and finding text. Off by default: an
    /// exported report is a bug-bounty deliverable and keeps what was captured.
    /// Detected secret plaintext is kept either way. Enable with `--redact`.
    pub redact: bool,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            format: ReportFormat::Json,
            scope: ScopeFilter::All,
            min_confidence: Confidence::Low,
            min_severity: Severity::Info,
            redact: false,
        }
    }
}

impl SessionReport {
    /// Render the report in the requested format, applying the filters.
    pub fn render(&self, opts: RenderOptions) -> Result<String> {
        // The concrete-URL formats resolve against the raw findings, then mask
        // each resolved URL, so they bypass the masked clone.
        if matches!(
            opts.format,
            ReportFormat::UrlsExact | ReportFormat::Requests
        ) {
            return Ok(self.render_exact(opts));
        }
        if opts.redact {
            return self.redacted().render_unmasked(opts);
        }
        self.render_unmasked(opts)
    }

    /// Format dispatch on the report as held; masking is `render`'s job.
    fn render_unmasked(&self, opts: RenderOptions) -> Result<String> {
        match opts.format {
            ReportFormat::Text => Ok(self.render_text(opts)),
            ReportFormat::Json => self.render_json(opts),
            ReportFormat::Jsonl => self.render_jsonl(opts),
            ReportFormat::Urls => Ok(self.render_urls(opts)),
            ReportFormat::UrlsExact | ReportFormat::Requests => Ok(self.render_exact(opts)),
            ReportFormat::Csv => Ok(self.render_csv(opts)),
            ReportFormat::OpenApi => self.render_openapi(opts),
            ReportFormat::Dot => Ok(self.render_dot(opts)),
            ReportFormat::GraphMl => Ok(self.render_graphml(opts)),
        }
    }

    /// Findings passing both floors, in stored order.
    pub(crate) fn kept_findings(&self, opts: RenderOptions) -> impl Iterator<Item = &Finding> {
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

    /// Concrete request targets, scope-filtered, de-duplicated and sorted by URL
    /// then method. The stored endpoint rows are route templates, so the exact
    /// URLs come from the `Endpoint` findings, resolved against their document
    /// the same way the store stage resolves them. Template placeholders
    /// (`{id}`) and fragments are not requestable and are skipped. With
    /// `opts.redact` each URL is masked before de-duplication.
    fn render_exact(&self, opts: RenderOptions) -> String {
        let mut resolver = EndpointResolver::new(&self.mission);
        let mut rows: BTreeSet<(String, Method)> = BTreeSet::new();
        for finding in self
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::Endpoint)
        {
            let Some(raw) = finding.url.as_deref() else {
                continue;
            };
            if raw.contains(['{', '}']) {
                continue;
            }
            let Some(mut url) = resolver.resolve(finding) else {
                continue;
            };
            url.set_fragment(None);
            let url = url.to_string();
            if !opts.scope.matches(self.mission.scope.classify(&url)) {
                continue;
            }
            let method = finding
                .value
                .split_whitespace()
                .next()
                .map_or(Method::Unknown, Method::parse);
            let url = if opts.redact { redact_url(&url) } else { url };
            rows.insert((url, method));
        }
        let lines: Vec<String> = if opts.format == ReportFormat::Requests {
            rows.into_iter()
                .map(|(url, method)| format!("{method} {url}"))
                .collect()
        } else {
            let urls: BTreeSet<String> = rows.into_iter().map(|(url, _)| url).collect();
            urls.into_iter().collect()
        };
        lines.join("\n")
    }

    fn render_csv(&self, opts: RenderOptions) -> String {
        let mut out = String::from("severity,kind,confidence,url,value,source,evidence,coverage\n");
        for f in self.ranked_findings(opts) {
            let row = [
                f.severity().slug().to_owned(),
                f.kind.slug().to_owned(),
                f.confidence.slug().to_owned(),
                f.url.clone().unwrap_or_default(),
                f.plaintext.as_ref().unwrap_or(&f.value).clone(),
                f.provenance.source.to_string(),
                f.evidence.as_ref().map_or_else(String::new, |e| {
                    serde_json::to_string(e).expect("serializable evidence")
                }),
                f.coverage.as_ref().map_or_else(String::new, |c| {
                    serde_json::to_string(c).expect("serializable coverage")
                }),
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
            ReportFormat::Text => "text",
            ReportFormat::Json => "json",
            ReportFormat::Jsonl => "jsonl",
            ReportFormat::Urls => "urls",
            ReportFormat::UrlsExact => "urls-exact",
            ReportFormat::Requests => "requests",
            ReportFormat::Csv => "csv",
            ReportFormat::OpenApi => "openapi",
            ReportFormat::Dot => "dot",
            ReportFormat::GraphMl => "graphml",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{Endpoint, Finding, FindingKind, Method, Mission, Provenance, Scope, Source};

    fn report() -> SessionReport {
        let mission = Mission::new("t", Scope::new(vec!["x.test".into()], vec![]), vec![]);
        let sid = mission.id;
        let findings = vec![
            Finding::new(
                sid,
                FindingKind::Endpoint,
                Some("https://x.test/api/v1/users".into()),
                "GET https://x.test/api/v1/users",
                Confidence::High,
                Provenance::new(Source::JsAst, None),
            ),
            Finding::new(
                sid,
                FindingKind::Parameter,
                None,
                "noisyParam",
                Confidence::Low,
                Provenance::new(Source::JsRegex, None),
            ),
        ];
        let endpoints = vec![
            Endpoint::new("https://x.test/a", Method::Get, Source::JsAst),
            Endpoint::new("https://cdn.other/x.js", Method::Unknown, Source::JsRegex)
                .with_scope(EndpointScope::External),
        ];
        SessionReport::build(mission, findings, endpoints)
    }

    fn opts(format: ReportFormat, scope: ScopeFilter, min: Confidence) -> RenderOptions {
        RenderOptions {
            format,
            scope,
            min_confidence: min,
            min_severity: Severity::Info,
            redact: false,
        }
    }

    #[test]
    fn urls_are_scope_filtered_and_sorted() {
        let all = report()
            .render(opts(ReportFormat::Urls, ScopeFilter::All, Confidence::Low))
            .unwrap();
        assert_eq!(all.lines().count(), 2);

        let internal = report()
            .render(opts(
                ReportFormat::Urls,
                ScopeFilter::Internal,
                Confidence::Low,
            ))
            .unwrap();
        assert_eq!(internal, "https://x.test/a");

        let external = report()
            .render(opts(
                ReportFormat::Urls,
                ScopeFilter::External,
                Confidence::Low,
            ))
            .unwrap();
        assert_eq!(external, "https://cdn.other/x.js");
    }

    #[test]
    fn min_confidence_drops_low_findings_from_jsonl() {
        let r = report();
        let all = r
            .render(opts(ReportFormat::Jsonl, ScopeFilter::All, Confidence::Low))
            .unwrap();
        assert_eq!(all.lines().count(), 2);
        let high = r
            .render(opts(
                ReportFormat::Jsonl,
                ScopeFilter::All,
                Confidence::High,
            ))
            .unwrap();
        assert_eq!(high.lines().count(), 1);
        assert!(high.contains("x.test/api/v1/users"));
    }

    #[test]
    fn csv_has_header_and_quotes_commas() {
        let r = report();
        let csv = r
            .render(opts(ReportFormat::Csv, ScopeFilter::All, Confidence::Low))
            .unwrap();
        assert!(csv.starts_with("severity,kind,confidence,url,value,source,evidence,coverage\n"));
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
            redact: false,
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
        let json = r
            .render(opts(
                ReportFormat::Json,
                ScopeFilter::Internal,
                Confidence::High,
            ))
            .unwrap();
        // Only the high-confidence endpoint finding survives.
        assert!(json.contains("\"total\": 1"));
        assert!(json.contains("\"internal\": 1"));
        assert!(!json.contains("noisyParam"));
    }

    fn exact_report() -> SessionReport {
        let mission = Mission::new(
            "t",
            Scope::new(vec!["x.test".into()], vec![]),
            vec!["https://x.test/app/".into()],
        );
        let sid = mission.id;
        let endpoint = |url: &str, value: &str, source: Source, location: Option<&str>| {
            Finding::new(
                sid,
                FindingKind::Endpoint,
                Some(url.into()),
                value,
                Confidence::High,
                Provenance::new(source, location.map(str::to_owned)),
            )
        };
        let findings = vec![
            endpoint(
                "https://x.test/api/users/12?tab=a&token=Zk3JqW9xLmN2pR5tVb8Y",
                "GET https://x.test/api/users/12?tab=a&token=Zk3JqW9xLmN2pR5tVb8Y",
                Source::Browser,
                None,
            ),
            endpoint(
                "https://x.test/api/users/12?tab=a&token=Zk3JqW9xLmN2pR5tVb8Y",
                "POST https://x.test/api/users/12?tab=a&token=Zk3JqW9xLmN2pR5tVb8Y",
                Source::JsAst,
                None,
            ),
            endpoint(
                "orders/7?x=1#top",
                "GET orders/7?x=1#top",
                Source::JsAst,
                Some("https://x.test/assets/app.js"),
            ),
            endpoint(
                "https://x.test/api/users/{id}",
                "GET https://x.test/api/users/{id}",
                Source::JsRegex,
                None,
            ),
            endpoint(
                "https://cdn.other/lib.js?v=3",
                "GET https://cdn.other/lib.js?v=3",
                Source::Html,
                None,
            ),
        ];
        SessionReport::build(mission, findings, Vec::new())
    }

    fn exact(format: ReportFormat, scope: ScopeFilter, redact: bool) -> String {
        let mut o = opts(format, scope, Confidence::Low);
        o.redact = redact;
        exact_report().render(o).unwrap()
    }

    #[test]
    fn urls_exact_keeps_ids_and_query_and_resolves_relative_references() {
        let out = exact(ReportFormat::UrlsExact, ScopeFilter::All, false);
        assert_eq!(
            out,
            "https://cdn.other/lib.js?v=3\n\
             https://x.test/api/users/12?tab=a&token=Zk3JqW9xLmN2pR5tVb8Y\n\
             https://x.test/app/orders/7?x=1"
        );
        // The template row and the fragment never reach the list.
        assert!(!out.contains('{'));
        assert!(!out.contains("#top"));
    }

    #[test]
    fn urls_exact_filters_by_scope_and_is_stable() {
        let internal = exact(ReportFormat::UrlsExact, ScopeFilter::Internal, false);
        assert_eq!(internal.lines().count(), 2);
        assert!(!internal.contains("cdn.other"));
        let external = exact(ReportFormat::UrlsExact, ScopeFilter::External, false);
        assert_eq!(external, "https://cdn.other/lib.js?v=3");
        assert_eq!(
            exact(ReportFormat::UrlsExact, ScopeFilter::All, false),
            exact(ReportFormat::UrlsExact, ScopeFilter::All, false)
        );
    }

    #[test]
    fn requests_lists_each_method_once_per_url() {
        let out = exact(ReportFormat::Requests, ScopeFilter::Internal, false);
        assert_eq!(
            out,
            "GET https://x.test/api/users/12?tab=a&token=Zk3JqW9xLmN2pR5tVb8Y\n\
             POST https://x.test/api/users/12?tab=a&token=Zk3JqW9xLmN2pR5tVb8Y\n\
             GET https://x.test/app/orders/7?x=1"
        );
    }

    #[test]
    fn exact_formats_mask_credentials_but_keep_object_ids_with_redact() {
        let urls = exact(ReportFormat::UrlsExact, ScopeFilter::Internal, true);
        assert!(!urls.contains("Zk3JqW9xLmN2pR5tVb8Y"), "{urls}");
        assert!(
            urls.contains("/api/users/12?tab=a&token=[REDACTED]"),
            "{urls}"
        );
        assert!(urls.contains("/app/orders/7?x=1"), "{urls}");
        let requests = exact(ReportFormat::Requests, ScopeFilter::Internal, true);
        assert!(!requests.contains("Zk3JqW9xLmN2pR5tVb8Y"), "{requests}");
    }
}
