//! Active probe evidence: observations, evaluation proof, and actual coverage.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVerdict {
    Signal,
    Observed,
    EvaluationConfirmed,
    /// Elapsed response time correlates with an injected delay at two
    /// distinct magnitudes, net of a length-matched, non-executing control.
    /// Only reachable via an opt-in probe (`--allow-timing-probes`) that
    /// actually executes a sleep on the target if vulnerable. A strong
    /// command/code-execution signal, but timing remains a side channel
    /// (network jitter, slow queries, rate limiting can mimic it), so it is
    /// never promoted to `FindingStatus::Confirmed`.
    TimingCorrelated,
}

impl EvidenceVerdict {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Signal => "signal / verify manually",
            Self::Observed => "observed",
            Self::EvaluationConfirmed => "expression evaluation confirmed / RCE not established",
            Self::TimingCorrelated => {
                "response delay correlates with injected sleep / execution likely, not certain (timing side channel)"
            }
        }
    }
}

/// A response supporting a finding. Excerpts are bounded; credentials extracted
/// elsewhere retain their complete plaintext. Auth material is never replayed
/// by a report: this boolean records whether mission headers were attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseObservation {
    pub role: String,
    #[serde(default = "default_probe_method")]
    pub method: String,
    pub url: String,
    pub status: u16,
    pub authenticated: bool,
    pub content_type: String,
    pub body_bytes: usize,
    pub excerpt: String,
    /// Bounded raw response body, kept by checks whose proof is the content
    /// itself (cross-account object reads). Empty for every other check, and
    /// absent from older reports. `--redact` scrubs it on export.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
    /// True when `body` is a prefix of a longer response (`body_bytes`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub body_truncated: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's `skip_serializing_if` signature
fn is_false(value: &bool) -> bool {
    !*value
}

fn default_probe_method() -> String {
    "GET".to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeEvidence {
    pub check: String,
    pub parameter: Option<String>,
    pub verdict: EvidenceVerdict,
    pub observations: Vec<ResponseObservation>,
    pub limitation: String,
    /// Human-readable comparison of the observed responses (for a
    /// cross-account read: which fields differ between the two owners'
    /// objects). Empty when a check has nothing to compare.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diff: Vec<String>,
}

impl ProbeEvidence {
    /// Shared details for CLI and TUI; terminal control escaping belongs to
    /// the renderer, so machine-readable values remain unchanged.
    #[must_use]
    pub fn details(&self) -> Vec<String> {
        let mut lines = vec![format!("check: {}", self.check)];
        if let Some(parameter) = &self.parameter {
            lines.push(format!("parameter: {parameter}"));
        }
        lines.push(format!("limit: {}", self.limitation));
        for response in &self.observations {
            lines.push(format!(
                "{}: {} {} → HTTP {} | auth={} | {} bytes | {}",
                response.role,
                response.method,
                response.url,
                response.status,
                response.authenticated,
                response.body_bytes,
                response.content_type
            ));
            if !response.excerpt.is_empty() {
                lines.push(format!("match: {}", response.excerpt));
            }
            if !response.body.is_empty() {
                let cut = if response.body_truncated {
                    " (truncated)"
                } else {
                    ""
                };
                lines.push(format!("body{cut}: {}", response.body));
            }
        }
        lines.extend(self.diff.iter().map(|line| format!("diff: {line}")));
        lines
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CheckCoverage {
    /// Targets selected for this check (legacy name retained in JSON).
    pub attempted: usize,
    pub executed: usize,
    pub not_executed: usize,
    pub not_selected: usize,
    pub negative: usize,
    pub refused: usize,
    /// Selected probe targets refused by the configured authorization scope.
    #[serde(default)]
    pub scope_refused: usize,
    pub errors: usize,
    pub findings: usize,
    pub inconclusive: usize,
}

/// Counts actual wire attempts, including unsuccessful probes. An incomplete
/// scan cannot establish absence of vulnerabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
// These independent stop conditions can occur together; they are not states.
#[allow(clippy::struct_excessive_bools)]
pub struct ActiveCoverage {
    pub request_limit: usize,
    pub requests: usize,
    pub responses: usize,
    pub transport_errors: usize,
    pub refused_responses: usize,
    pub oversized_responses: usize,
    pub out_of_scope: usize,
    pub skipped_methods: usize,
    pub skipped_query_auth: usize,
    pub cancelled: bool,
    pub budget_exhausted: bool,
    pub target_limit_reached: bool,
    pub parameter_limit_reached: bool,
    pub checks: BTreeMap<String, CheckCoverage>,
}

impl ActiveCoverage {
    #[must_use]
    pub fn complete(&self) -> bool {
        self.requests > 0
            && !self.cancelled
            && !self.budget_exhausted
            && !self.target_limit_reached
            && !self.parameter_limit_reached
            && self.transport_errors == 0
            && self.refused_responses == 0
            && self.oversized_responses == 0
            && self.skipped_methods == 0
            && self.skipped_query_auth == 0
            && self.checks.values().all(|check| check.inconclusive == 0)
            && self
                .checks
                .values()
                .all(|check| check.not_executed == 0 && check.errors == 0)
    }
}
