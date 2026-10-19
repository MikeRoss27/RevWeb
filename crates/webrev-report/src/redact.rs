// crates/webrev-report/src/redact.rs
//! Credential masking applied when a report leaves the process.
//!
//! A scan records what the target sent, so URLs, response excerpts and the
//! free text of findings can carry live credentials (`?token=...`, a bearer in
//! a captured WebSocket frame, a JWT in a path). [`SessionReport::redacted`]
//! returns a copy with those masked; [`SessionReport::render`] and
//! [`SessionReport::export_json`] call it only when the caller asks for it
//! (`--redact`). An exported report is raw by default: it is the deliverable
//! of a bug-bounty run and the proof of a finding lives in those values.
//!
//! What is kept on purpose: `Finding::plaintext` of a secret finding (the
//! detected credential is the deliverable, see `docs/security.md`) and its
//! fingerprint `value`. Detection runs on the original findings; only this
//! output copy is altered.

use crate::json::SessionReport;
use webrev_core::{
    redact_url, Endpoint, Finding, FindingKind, Mission, ProbeEvidence, Provenance, Sanitizer,
};

/// Masks URLs and free text with the shared sanitizer.
struct Masker {
    sanitizer: Sanitizer,
}

impl Masker {
    fn new() -> Self {
        Self {
            sanitizer: Sanitizer::with_default_patterns(),
        }
    }

    /// A field that holds one URL or path.
    fn url(&self, raw: &str) -> String {
        self.sanitizer.scrub(&redact_url(raw))
    }

    /// Free text: every absolute URL goes through [`redact_url`], then the
    /// sanitizer masks key/value pairs and known token shapes. Text that is a
    /// JSON document is masked leaf by leaf so it stays parseable.
    fn text(&self, raw: &str) -> String {
        let trimmed = raw.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(mut doc) = serde_json::from_str::<serde_json::Value>(raw) {
                if self.json(&mut doc) {
                    // Only re-serialize when a leaf changed: key order and
                    // spacing of untouched documents stay as captured.
                    return serde_json::to_string(&doc).unwrap_or_else(|_| self.plain(raw));
                }
                return raw.to_owned();
            }
        }
        self.plain(raw)
    }

    /// Mask the string leaves of a JSON document; true when any changed.
    fn json(&self, value: &mut serde_json::Value) -> bool {
        use serde_json::Value;
        match value {
            Value::String(text) => {
                let masked = self.plain(text);
                let changed = masked != *text;
                *text = masked;
                changed
            }
            Value::Array(items) => items.iter_mut().fold(false, |acc, v| self.json(v) | acc),
            Value::Object(map) => {
                // A `"password": "hunter2"` pair is invisible to the text
                // patterns once split into key and leaf, so judge the pair.
                let mut changed = false;
                for (key, leaf) in map.iter_mut() {
                    if let Value::String(text) = leaf {
                        let pair = format!("{key}: {text}");
                        if self.plain(text) == *text && self.sanitizer.scrub(&pair) != pair {
                            "[REDACTED]".clone_into(text);
                            changed = true;
                            continue;
                        }
                    }
                    changed |= self.json(leaf);
                }
                changed
            }
            _ => false,
        }
    }

    fn plain(&self, raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(at) = rest.find("://") {
            let before = &rest[..at];
            let start = before
                .char_indices()
                .rev()
                .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
                .map_or(0, |(i, c)| i + c.len_utf8());
            let after = &rest[at + 3..];
            let end = after
                .find(|c: char| {
                    c.is_whitespace()
                        || matches!(c, '"' | '\'' | '<' | '>' | '`' | ')' | ']' | '}' | '\\')
                })
                .unwrap_or(after.len());
            out.push_str(&rest[..start]);
            out.push_str(&redact_url(&rest[start..at + 3 + end]));
            rest = &rest[at + 3 + end..];
        }
        out.push_str(rest);
        self.sanitizer.scrub(&out)
    }

    fn opt_url(&self, value: &mut Option<String>) {
        if let Some(v) = value {
            *v = self.url(v);
        }
    }

    fn provenance(&self, provenance: &mut Provenance) {
        self.opt_url(&mut provenance.location);
    }

    fn evidence(&self, evidence: &mut ProbeEvidence) {
        if let Some(parameter) = &mut evidence.parameter {
            *parameter = self.text(parameter);
        }
        evidence.limitation = self.text(&evidence.limitation);
        for observation in &mut evidence.observations {
            observation.url = self.url(&observation.url);
            observation.excerpt = self.text(&observation.excerpt);
        }
    }

    fn finding(&self, finding: &mut Finding) {
        self.opt_url(&mut finding.url);
        self.provenance(&mut finding.provenance);
        for provenance in &mut finding.provenances {
            self.provenance(provenance);
        }
        finding.justification = self.text(&finding.justification);
        if finding.kind == FindingKind::Secret {
            // `value` is the HMAC fingerprint and `plaintext` the detected
            // credential: both are the finding itself.
            return;
        }
        finding.value = self.text(&finding.value);
        if let Some(plaintext) = &mut finding.plaintext {
            *plaintext = self.text(plaintext);
        }
        if let Some(evidence) = &mut finding.evidence {
            self.evidence(evidence);
        }
        for evidence in &mut finding.additional_evidence {
            self.evidence(evidence);
        }
    }

    fn endpoint(&self, endpoint: &mut Endpoint) {
        endpoint.url = self.url(&endpoint.url);
    }

    fn mission(&self, mission: &mut Mission) {
        mission.name = self.text(&mission.name);
        for seed in &mut mission.seeds {
            *seed = self.url(seed);
        }
    }
}

impl SessionReport {
    /// A copy of the report with credentials masked in mission name and
    /// seeds, endpoint and finding URLs, finding text and probe evidence.
    ///
    /// Counts and the summary are unchanged; two endpoints that differed only
    /// by a masked segment stay two entries. Applying it twice gives the same
    /// result. Secret findings keep their detected plaintext and fingerprint.
    #[must_use]
    pub fn redacted(&self) -> Self {
        let masker = Masker::new();
        let mut out = self.clone();
        masker.mission(&mut out.mission);
        out.endpoints.iter_mut().for_each(|e| masker.endpoint(e));
        out.findings.iter_mut().for_each(|f| masker.finding(f));
        out.redacted = true;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{
        Confidence, EvidenceVerdict, Method, Mission, ResponseObservation, Scope, Source,
    };

    const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUlkxMjM0In0.c2lnbmF0dXJlQ0FOQVJZMTIz";
    const TOKEN: &str = "Zk3Jq9XvT2bLm8Rw4NpYs7Ad";
    const PLAINTEXT: &str = "AKIAQ7ZXC9VB2NM4LK8P";

    fn finding(mission: &Mission, kind: FindingKind, url: Option<&str>, value: &str) -> Finding {
        Finding::new(
            mission.id,
            kind,
            url.map(str::to_owned),
            value,
            Confidence::High,
            Provenance::new(Source::JsAst, url.map(str::to_owned)),
        )
    }

    fn report() -> SessionReport {
        let mission = Mission::new(
            format!("run https://ops:hunter2pass@t.test/?tok={TOKEN}"),
            Scope::new(vec!["t.test".into()], vec![]),
            vec![format!("https://t.test/app?access_token={JWT}")],
        );
        let mut secret = finding(
            &mission,
            FindingKind::Secret,
            Some(&format!("https://t.test/app.js?v={TOKEN}")),
            "fp:0123456789abcdef",
        );
        secret.plaintext = Some(PLAINTEXT.to_owned());
        let frame = finding(
            &mission,
            FindingKind::WebSocketFrame,
            Some("wss://t.test/socket"),
            &format!("{{\"auth\":\"Bearer {JWT}\"}}"),
        );
        let mut vuln = finding(
            &mission,
            FindingKind::Vulnerability,
            Some(&format!("https://t.test/reset/{JWT}")),
            "reflected parameter",
        );
        vuln.justification = format!("replayed https://t.test/cb?tok={TOKEN} and got 200");
        vuln.evidence = Some(Box::new(ProbeEvidence {
            check: "reflection".into(),
            parameter: Some("q".into()),
            verdict: EvidenceVerdict::Observed,
            observations: vec![ResponseObservation {
                role: "probe".into(),
                method: "GET".into(),
                url: format!("https://t.test/search?q=x&session={TOKEN}"),
                status: 200,
                authenticated: false,
                content_type: "text/html".into(),
                body_bytes: 40,
                excerpt: format!("{{\"api_key\":\"{TOKEN}\",\"name\":\"ok\"}}"),
            }],
            limitation: String::new(),
        }));
        let endpoints = vec![
            Endpoint::new(
                format!("https://t.test/api/users?id=7&token={TOKEN}"),
                Method::Get,
                Source::JsAst,
            ),
            Endpoint::new("https://t.test/api/health", Method::Get, Source::JsAst),
        ];
        SessionReport::build(mission, vec![secret, frame, vuln], endpoints)
    }

    #[test]
    fn masks_every_credential_outside_secret_plaintext() {
        let masked = serde_json::to_string(&report().redacted()).unwrap();
        for leaked in [JWT, TOKEN, "hunter2pass"] {
            assert!(!masked.contains(leaked), "{leaked} survived in {masked}");
        }
        assert!(masked.contains("[REDACTED]"));
        assert!(masked.contains("\"redacted\":true"));
    }

    #[test]
    fn keeps_secret_plaintext_and_fingerprint() {
        let masked = report().redacted();
        let secret = &masked.findings[0];
        assert_eq!(secret.plaintext.as_deref(), Some(PLAINTEXT));
        assert_eq!(secret.value, "fp:0123456789abcdef");
    }

    #[test]
    fn leaves_ordinary_data_intact() {
        let masked = report().redacted();
        assert_eq!(masked.endpoints[1].url, "https://t.test/api/health");
        assert!(masked.endpoints[0]
            .url
            .starts_with("https://t.test/api/users?id=7&token="));
        let vuln = &masked.findings[2];
        assert_eq!(vuln.value, "reflected parameter");
        let evidence = vuln.evidence.as_ref().unwrap();
        assert_eq!(evidence.check, "reflection");
        assert_eq!(evidence.parameter.as_deref(), Some("q"));
        let observation = &evidence.observations[0];
        assert!(observation
            .url
            .starts_with("https://t.test/search?q=x&session="));
        assert_eq!(observation.status, 200);
        assert!(observation.excerpt.contains("\"name\":\"ok\""));
        assert_eq!(masked.summary, report().summary);
    }

    #[test]
    fn object_identifiers_stay_readable_next_to_masked_credentials() {
        let id = "550e8400-e29b-41d4-a716-446655440001";
        let mission = Mission::new("demo", Scope::new(vec!["t.test".into()], vec![]), vec![]);
        let url = format!("https://t.test/api/orders/{id}?author_id={id}&token={TOKEN}");
        let mut idor = finding(
            &mission,
            FindingKind::Idor,
            Some(&url),
            &format!("cross-account object access signal on /api/orders/{id}"),
        );
        idor.evidence = Some(Box::new(ProbeEvidence {
            check: "cross_account_bola".into(),
            parameter: None,
            verdict: EvidenceVerdict::Signal,
            observations: vec![ResponseObservation {
                role: "B reads A object".into(),
                method: "GET".into(),
                url: url.clone(),
                status: 200,
                authenticated: true,
                content_type: "application/json".into(),
                body_bytes: 40,
                excerpt: "sha256=9f86d081884c7d659a2feaa0c55ad0159f86d081884c7d659a2feaa0c55ad015"
                    .into(),
            }],
            limitation: String::new(),
        }));
        let endpoint = Endpoint::new(url, Method::Get, Source::Browser);
        let masked = SessionReport::build(mission, vec![idor], vec![endpoint]).redacted();
        let body = serde_json::to_string(&masked).unwrap();
        assert!(!body.contains(TOKEN), "{body}");
        let idor = &masked.findings[0];
        let observation = &idor.evidence.as_ref().unwrap().observations[0];
        for readable in [
            idor.url.as_deref().unwrap(),
            observation.url.as_str(),
            masked.endpoints[0].url.as_str(),
        ] {
            assert!(
                readable.contains(&format!("/api/orders/{id}?author_id={id}&token=[REDACTED]")),
                "{readable}"
            );
        }
        assert!(idor.value.ends_with(id), "{}", idor.value);
        assert!(observation.excerpt.starts_with("sha256=9f86d081"));
    }

    #[test]
    fn plain_text_fields_are_not_altered() {
        let mission = Mission::new("demo", Scope::new(vec!["t.test".into()], vec![]), vec![]);
        let values = [
            "GET /api/v2/orders/12345",
            "React 18.2.0",
            "application/json",
            "src/components/Auth/Login.tsx",
            "getUserProfileData",
            "https://t.test/a@b?page=2&q=hi#top",
        ];
        let findings = values
            .iter()
            .map(|v| finding(&mission, FindingKind::Config, None, v))
            .collect();
        let masked = SessionReport::build(mission, findings, vec![]).redacted();
        for (finding, expected) in masked.findings.iter().zip(values) {
            assert_eq!(finding.value, expected);
        }
    }

    fn masked_value(kind: FindingKind, value: &str) -> String {
        let mission = Mission::new("demo", Scope::new(vec!["t.test".into()], vec![]), vec![]);
        let finding = finding(&mission, kind, None, value);
        let report = SessionReport::build(mission, vec![finding], vec![]);
        report.redacted().findings.remove(0).value
    }

    #[test]
    fn json_values_stay_parseable_and_lose_only_the_credential() {
        let coverage = format!(
            r#"{{"complete":false,"refused_requests":[{{"method":"POST","url":"https://t.test/x?token={TOKEN}","reason":"MethodRestricted"}}]}}"#
        );
        let masked = masked_value(FindingKind::ScanCoverage, &coverage);
        let doc: serde_json::Value = serde_json::from_str(&masked).expect("still JSON");
        assert!(!masked.contains(TOKEN));
        assert_eq!(doc["complete"], false);
        assert_eq!(doc["refused_requests"][0]["reason"], "MethodRestricted");
        assert_eq!(doc["refused_requests"][0]["method"], "POST");

        let frame = masked_value(
            FindingKind::WebSocketFrame,
            r#"{"password":"hunter2pass","user":"ada"}"#,
        );
        let doc: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(doc["password"], "[REDACTED]");
        assert_eq!(doc["user"], "ada");
    }

    #[test]
    fn untouched_json_is_kept_byte_for_byte() {
        let original = r#"{ "z": 1,  "a": ["x", "y"], "name": "ok" }"#;
        assert_eq!(masked_value(FindingKind::Config, original), original);
    }

    #[test]
    fn urls_inside_prose_are_masked_without_eating_the_sentence() {
        let masked = masked_value(
            FindingKind::Vulnerability,
            &format!("fetched (https://t.test/cb?code=xyz&tok={TOKEN}) then \"https://t.test/ok\" worked"),
        );
        assert!(!masked.contains(TOKEN));
        assert!(
            masked.ends_with(") then \"https://t.test/ok\" worked"),
            "{masked}"
        );
    }

    #[test]
    fn render_masks_every_format_unless_told_not_to() {
        use crate::{RenderOptions, ReportFormat};
        let formats = [
            ReportFormat::Text,
            ReportFormat::Json,
            ReportFormat::Jsonl,
            ReportFormat::Urls,
            ReportFormat::Csv,
            ReportFormat::OpenApi,
            ReportFormat::Dot,
            ReportFormat::GraphMl,
        ];
        let report = report();
        for format in formats {
            let opts = RenderOptions {
                format,
                ..RenderOptions::default()
            };
            assert!(!opts.redact, "the exported report is raw by default");
            let raw = report.render(opts).unwrap();
            assert!(
                [JWT, TOKEN].iter().any(|s| raw.contains(s)),
                "{format:?} should keep credentials by default"
            );
            let masked = report
                .render(RenderOptions {
                    redact: true,
                    ..opts
                })
                .unwrap();
            for leaked in [JWT, TOKEN, "hunter2pass"] {
                assert!(!masked.contains(leaked), "{format:?} leaked {leaked}");
            }
        }
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = report().redacted();
        let twice = once.redacted();
        assert_eq!(
            serde_json::to_string(&once).unwrap(),
            serde_json::to_string(&twice).unwrap()
        );
    }
}
