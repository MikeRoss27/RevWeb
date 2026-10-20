//! Apply scan events and build the visible finding/log records.

use super::{App, UiEvent};
use std::time::Instant;
use webrev_core::{EndpointScope, Finding, FindingKind};

const MAX_LOGS: usize = 1000;

impl App {
    fn push_log(&mut self, line: &str) {
        self.logs
            .push(webrev_core::model::triage::terminal_text(line));
        if self.logs.len() > MAX_LOGS {
            self.logs.remove(0);
        }
    }

    /// Advance time-driven state. Returns `true` when the next frame differs
    /// from the last one (an animation moved), so the caller can skip idle redraws.
    pub fn tick(&mut self, _now: Instant) -> bool {
        if self.scanning {
            self.tick_count = self.tick_count.wrapping_add(1);
            true
        } else {
            false
        }
    }

    /// Apply a merged UI event, keeping the follow-tail invariant.
    pub fn apply(&mut self, event: UiEvent) {
        match event {
            UiEvent::Pipeline(pe) => self.apply_pipeline(pe),
            UiEvent::Status(s) => {
                self.push_log(&format!("[status] {s}"));
                self.status = s;
            }
            UiEvent::ScanFinished(s) => {
                self.scanning = false;
                self.push_log(&format!("[status] {s}"));
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
                self.push_log(&format!("[{stage}] started"));
            }
            Pe::StageCompleted { stage, emitted } => {
                self.push_log(&format!("[{stage}] completed ({emitted} emitted)"));
            }
            Pe::Progress { stage, processed } => {
                self.push_log(&format!("[{stage}] progress: {processed}"));
            }
            Pe::Error { stage, message } => {
                self.push_log(&format!("[{stage}] ERROR: {message}"));
            }
            Pe::SecretDetected {
                fingerprint,
                plaintext,
            } => {
                self.secrets += 1;
                match plaintext {
                    Some(p) => self.push_log(&format!("[secret] {fingerprint} = {p}")),
                    None => self.push_log(&format!("[secret] {fingerprint}")),
                }
            }
            Pe::Finding(finding) => self.record_finding(&finding),
        }
    }

    fn record_finding(&mut self, finding: &Finding) {
        let locus = finding.url.as_deref().unwrap_or(&finding.value);
        let sev = finding.severity().tag();
        let line = format!(
            "{sev} {:<9} {} | {} [{}; confidence={}; {}]",
            finding.category(),
            webrev_core::model::triage::terminal_text(finding.display_value()),
            webrev_core::model::triage::terminal_text(
                finding
                    .url
                    .as_deref()
                    .or(finding.provenance.location.as_deref())
                    .unwrap_or("—")
            ),
            finding.provenance.source,
            finding.confidence.slug(),
            finding.assessment()
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
            // The evidence tier for this one occurrence (live traffic > static
            // JS/HTML > inferred/normalized). The deduplicated per-route best
            // tier lives on the stored `Endpoint` (see
            // `webrev_core::EndpointConfidence` and the JSON/graph exports);
            // this live view shows the tier of the source that just fired.
            let tier = finding.provenance.source.endpoint_confidence();
            self.endpoints.push(format!(
                "{sev} {scope_tag} {} [{}; evidence={tier}]",
                webrev_core::model::triage::terminal_text(&finding.value),
                finding.provenance.source
            ));
            self.endpoint_data.push(finding.clone());
        }
        self.findings.push(line);
        self.finding_data.push(finding.clone());
    }
}
