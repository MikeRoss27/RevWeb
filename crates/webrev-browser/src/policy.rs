//! Opt-in browser observation controls and request refusal evidence.

use serde::Serialize;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, SessionId, Source};

/// Browser-driven investigation remains the compatibility default.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub enum InteractionPolicy {
    /// Scroll and click buttons, allowing the application's scoped requests.
    #[default]
    Explore,
    /// Do not scroll/click, and refuse HTTP methods other than GET/HEAD/OPTIONS.
    /// This cannot guarantee no side effects: an application may mutate on GET.
    ObserveOnly,
}

/// Why a browser request was refused before network I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RefusalReason {
    OutOfScope,
    MethodRestricted,
}

/// A request intent refused by browser interception, not a successful request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RefusedRequest {
    pub url: String,
    pub method: String,
    pub reason: RefusalReason,
}

/// A UI control the driver declined to click because it looks destructive
/// (delete/logout/pay/...) or would submit a non-GET form.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RefusedInteraction {
    /// Short label of the control (at most 60 characters).
    pub label: String,
    /// The matched keyword, or `non_get_form`.
    pub reason: String,
}

/// Words whose presence in a control description marks it as state-changing.
/// Matched as whole tokens (camelCase and punctuation split), not substrings.
/// Keep in sync with the URL denylist in `webrev-pipeline/src/active/destructive.rs`.
const DESTRUCTIVE_TOKENS: &[&str] = &[
    "logout",
    "logoff",
    "signout",
    "delete",
    "remove",
    "destroy",
    "unsubscribe",
    "deactivate",
    "terminate",
    "purge",
    "wipe",
    "revoke",
    "checkout",
    "purchase",
    "pay",
    "buy",
    "transfer",
    "withdraw",
    "cancel",
    "reset",
    "erase",
    "drop",
    "close_account",
    "log_out",
    "sign_out",
    "log_off",
];

/// Return the destructive keyword found in `text`, if any. Splits camelCase and
/// non-alphanumerics, then also tests each adjacent pair joined by `_`.
#[must_use]
pub fn destructive_keyword(text: &str) -> Option<&'static str> {
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for ch in text.chars() {
        if !ch.is_alphanumeric() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            previous_lower = false;
            continue;
        }
        if ch.is_uppercase() && previous_lower && !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
        previous_lower = ch.is_lowercase();
        current.extend(ch.to_lowercase());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    for (index, token) in tokens.iter().enumerate() {
        let joined = tokens.get(index + 1).map(|next| format!("{token}_{next}"));
        for word in DESTRUCTIVE_TOKENS {
            if token == word || joined.as_deref() == Some(word) {
                return Some(word);
            }
        }
    }
    None
}

/// Decide whether a described control may be clicked in `Explore` mode.
/// `description` is the concatenated label/id/class/name/onclick/href text;
/// `non_get_form` is true for a submit control inside a non-GET form.
#[must_use]
pub(crate) fn interaction_refusal(description: &str, non_get_form: bool) -> Option<String> {
    if let Some(word) = destructive_keyword(description) {
        return Some(word.to_owned());
    }
    non_get_form.then(|| "non_get_form".to_owned())
}

/// Dynamic findings and bounded refusal evidence. Policy-refused request intents
/// are retained in refusal evidence and excluded from endpoint findings.
#[derive(Debug, Default)]
pub struct DynamicRunReport {
    pub findings: Vec<Finding>,
    /// Up to 1024 refused intents, at most 1 MiB of original URL/method bytes.
    pub refused_requests: Vec<RefusedRequest>,
    /// Includes refusals beyond the evidence cap.
    pub refused_request_count: usize,
    /// Controls the driver did not click (destructive-looking or non-GET form
    /// submit). At most 256 are retained; `refused_interaction_count` is the total.
    pub refused_interactions: Vec<RefusedInteraction>,
    pub refused_interaction_count: usize,
}

/// Keep original values for retained intents; omit whole records beyond either
/// bound and expose omissions through the report's total count.
#[derive(Clone, Debug, Default)]
pub(crate) struct RefusalLog {
    pub count: usize,
    pub requests: Vec<RefusedRequest>,
    evidence_bytes: usize,
}

impl RefusalLog {
    pub fn merge(&mut self, other: Self) {
        let omitted = other.count.saturating_sub(other.requests.len());
        for request in other.requests {
            self.record(&request.url, &request.method, request.reason);
        }
        self.count += omitted;
    }

    pub fn record(&mut self, url: &str, method: &str, reason: RefusalReason) {
        self.count += 1;
        let bytes = url.len().saturating_add(method.len());
        if self.requests.len() < 1024
            && bytes <= (1024 * 1024_usize).saturating_sub(self.evidence_bytes)
        {
            self.evidence_bytes += bytes;
            self.requests.push(RefusedRequest {
                url: url.to_owned(),
                method: method.to_owned(),
                reason,
            });
        }
    }
}

impl DynamicRunReport {
    /// Preserve refusal evidence in ordinary JSON/text reports without claiming
    /// that CDP request intents measure completed wire requests or full coverage.
    #[must_use]
    pub fn coverage_finding(
        &self,
        session: SessionId,
        url: &str,
        policy: InteractionPolicy,
    ) -> Finding {
        let evidence = serde_json::json!({
            "check": "browser_request_interception",
            "policy": policy,
            "refused_request_count": self.refused_request_count,
            "refused_requests": self.refused_requests,
            "refusal_evidence_truncated": self.refused_request_count > self.refused_requests.len(),
            "refused_interaction_count": self.refused_interaction_count,
            "refused_interactions": self.refused_interactions,
            "complete": false,
            "limitation": "Incomplete browser coverage; policy-refused intents are excluded from endpoint findings. Explore never clicks controls that look destructive (delete/logout/pay/...) or submit a non-GET form, and records them as refused interactions; the keyword list is a heuristic. ObserveOnly disables driven clicks/scroll and refuses methods other than GET/HEAD/OPTIONS. Page scripts still execute; GET, WebSocket messages and other browser mechanisms may mutate state. This is not a non-destructivity guarantee."
        });
        Finding::new(
            session,
            FindingKind::ScanCoverage,
            Some(url.to_owned()),
            evidence.to_string(),
            Confidence::High,
            Provenance::new(
                Source::Browser,
                Some("browser interception coverage".to_owned()),
            ),
        )
    }
}

pub(crate) fn request_refusal(
    in_scope: bool,
    policy: InteractionPolicy,
    method: &str,
) -> Option<RefusalReason> {
    if !in_scope {
        Some(RefusalReason::OutOfScope)
    } else if policy == InteractionPolicy::ObserveOnly
        && !matches!(method, "GET" | "HEAD" | "OPTIONS")
    {
        Some(RefusalReason::MethodRestricted)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_evidence_is_bounded_without_changing_retained_values() {
        let mut log = RefusalLog::default();
        let oversized = "x".repeat(1024 * 1024);
        log.record(&oversized, "POST", RefusalReason::MethodRestricted);
        assert!(log.requests.is_empty());
        for _ in 0..1025 {
            log.record(
                "https://fixture/?token=plaintext",
                "POST",
                RefusalReason::MethodRestricted,
            );
        }
        assert_eq!(log.count, 1026);
        assert_eq!(log.requests.len(), 1024);
        assert_eq!(log.requests[0].url, "https://fixture/?token=plaintext");
    }

    #[test]
    fn coverage_stays_inconclusive_and_preserves_refused_evidence() {
        let report = DynamicRunReport {
            findings: vec![],
            refused_request_count: 1025,
            refused_requests: vec![RefusedRequest {
                url: "https://example.test/?token=plaintext".to_owned(),
                method: "POST".to_owned(),
                reason: RefusalReason::MethodRestricted,
            }],
            ..DynamicRunReport::default()
        };
        let finding = report.coverage_finding(
            SessionId::new(),
            "https://example.test/",
            InteractionPolicy::ObserveOnly,
        );
        assert_eq!(finding.status, webrev_core::FindingStatus::Inconclusive);
        assert!(finding.coverage.is_none());
        let evidence: serde_json::Value =
            serde_json::from_str(&finding.value).expect("coverage evidence");
        assert_eq!(evidence["complete"], false);
        assert_eq!(evidence["refusal_evidence_truncated"], true);
        assert_eq!(evidence["refused_request_count"], 1025);
        assert_eq!(
            evidence["refused_requests"][0]["url"],
            "https://example.test/?token=plaintext"
        );
    }

    #[test]
    fn observation_methods_are_explicit_and_scope_always_wins() {
        for method in ["GET", "HEAD", "OPTIONS"] {
            assert_eq!(
                request_refusal(true, InteractionPolicy::ObserveOnly, method),
                None
            );
        }
        for method in ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "get"] {
            assert_eq!(
                request_refusal(true, InteractionPolicy::ObserveOnly, method),
                Some(RefusalReason::MethodRestricted)
            );
            assert_eq!(
                request_refusal(true, InteractionPolicy::Explore, method),
                None
            );
        }
        assert_eq!(
            request_refusal(false, InteractionPolicy::Explore, "GET"),
            Some(RefusalReason::OutOfScope)
        );
        assert_eq!(InteractionPolicy::default(), InteractionPolicy::Explore);
    }

    #[test]
    fn destructive_keywords_match_whole_tokens_only() {
        for text in [
            "Delete account",
            "deleteAccount",
            "btn-logout",
            "Sign out",
            "log_off",
            "/Pay now",
            "Unsubscribe",
            "Cancel subscription",
            "Close account",
            "confirmPurchase",
        ] {
            assert!(destructive_keyword(text).is_some(), "{text}");
        }
        for text in [
            "Load more",
            "Search",
            "payload",
            "Display",
            "Dropdown menu",
            "Save",
        ] {
            assert_eq!(destructive_keyword(text), None, "{text}");
        }
    }

    #[test]
    fn non_get_form_submit_is_refused_even_with_innocent_label() {
        assert_eq!(
            interaction_refusal("Save", true).as_deref(),
            Some("non_get_form")
        );
        assert_eq!(interaction_refusal("Save", false), None);
        assert_eq!(
            interaction_refusal("Delete", false).as_deref(),
            Some("delete")
        );
    }

    #[test]
    fn coverage_records_refused_interactions_and_is_never_complete() {
        let report = DynamicRunReport {
            refused_interactions: vec![RefusedInteraction {
                label: "Delete account".into(),
                reason: "delete".into(),
            }],
            refused_interaction_count: 1,
            ..DynamicRunReport::default()
        };
        let finding = report.coverage_finding(
            SessionId::new(),
            "https://x.test/",
            InteractionPolicy::Explore,
        );
        let evidence: serde_json::Value = serde_json::from_str(&finding.value).unwrap();
        assert_eq!(evidence["complete"], false);
        assert_eq!(evidence["refused_interaction_count"], 1);
        assert_eq!(evidence["refused_interactions"][0]["reason"], "delete");
    }
}
