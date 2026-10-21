    use super::*;
    use crate::model::endpoint::Method;
    use crate::model::session::SessionId;

    #[test]
    fn severity_ranks_secrets_and_sensitive_endpoints() {
        let sid = SessionId::new();
        let secret = Finding::new(
            sid,
            FindingKind::Secret,
            None,
            "fp:x",
            Confidence::High,
            Provenance::new(Source::JsRegex, None),
        );
        assert_eq!(secret.severity(), Severity::High);

        let mk_ep = |url: &str| {
            Finding::new(
                sid,
                FindingKind::Endpoint,
                Some(url.into()),
                format!("GET {url}"),
                Confidence::Low,
                Provenance::new(Source::JsAst, None),
            )
        };
        assert_eq!(mk_ep("https://x/admin/users").severity(), Severity::High);
        assert_eq!(mk_ep("https://x/api/v1/me").severity(), Severity::Medium);
        assert_eq!(mk_ep("https://x/about").severity(), Severity::Low);

        let param = Finding::new(
            sid,
            FindingKind::Parameter,
            None,
            "q",
            Confidence::Low,
            Provenance::new(Source::JsRegex, None),
        );
        assert_eq!(param.severity(), Severity::Info);
        // Severity ordering is usable for sorting.
        assert!(Severity::Critical > Severity::Info);
    }

    #[test]
    fn vulnerability_and_idor_severity_ranked_by_weakness() {
        let sid = SessionId::new();
        let mk_vuln = |value: &str| {
            Finding::new(
                sid,
                FindingKind::Vulnerability,
                None,
                value,
                Confidence::High,
                Provenance::new(Source::Active, None),
            )
        };
        assert_eq!(
            mk_vuln("CORS misconfiguration: arbitrary Origin reflected with credentials allowed")
                .severity(),
            Severity::Critical
        );
        assert_eq!(
            mk_vuln("possible SQL injection: database error signature returned").severity(),
            Severity::High
        );
        assert_eq!(
            mk_vuln("open redirect via 'next' parameter").severity(),
            Severity::Medium
        );
        assert_eq!(
            mk_vuln("missing security header(s): X-Frame-Options").severity(),
            Severity::Low
        );
        // Active checks added later map through the same marker phrases.
        assert_eq!(
            mk_vuln(
                "possible path traversal / local file inclusion: /etc/passwd contents returned for 'file' parameter"
            )
            .severity(),
            Severity::High
        );
        assert_eq!(
            mk_vuln("possible subdomain takeover (GitHub Pages)").severity(),
            Severity::High
        );
        assert_eq!(
            mk_vuln(
                "possible CRLF / header injection: injected response header observed via 'q' parameter"
            )
            .severity(),
            Severity::Medium
        );
        assert_eq!(
            mk_vuln("graphql introspection enabled: __schema returned over GET").severity(),
            Severity::Medium
        );
        assert_eq!(
            mk_vuln("possible SSRF sink: parameter accepts a URL ('url', URL value reflected in response)")
                .severity(),
            Severity::Low
        );
        assert_eq!(
            mk_vuln(
                "possible prototype pollution: server error triggered by '__proto__[webrevpp]=1'"
            )
            .severity(),
            Severity::Low
        );

        let idor = Finding::new(
            sid,
            FindingKind::Idor,
            None,
            "no auth required",
            Confidence::Medium,
            Provenance::new(Source::Active, None),
        );
        assert_eq!(idor.severity(), Severity::High);
    }

    #[test]
    fn dedup_key_preserves_method_and_ignores_source() {
        let sid = SessionId::new();
        let a = Finding::from_endpoint(
            sid,
            &Endpoint::new("https://x/api/v1", Method::Get, Source::Html),
            Confidence::Medium,
        );
        let b = Finding::from_endpoint(
            sid,
            &Endpoint::new("https://x/api/v1", Method::Post, Source::JsAst),
            Confidence::High,
        );
        // GET and POST are different observed routes even on one URL.
        assert_ne!(a.dedup_key(), b.dedup_key());
    }

    #[test]
    fn dedup_key_falls_back_to_value() {
        let sid = SessionId::new();
        let f = Finding::new(
            sid,
            FindingKind::Secret,
            None,
            "fp:deadbeef",
            Confidence::High,
            Provenance::new(Source::JsRegex, None),
        );
        assert_eq!(f.dedup_key(), "secret|fp:deadbeef");
    }

    #[test]
    fn same_page_can_keep_multiple_technologies_and_proofs() {
        for kind in [
            FindingKind::Technology,
            FindingKind::Vulnerability,
            FindingKind::Parameter,
        ] {
            let mk = |value| {
                Finding::new(
                    SessionId::new(),
                    kind,
                    Some("https://x/page".into()),
                    value,
                    Confidence::High,
                    Provenance::new(Source::Html, None),
                )
            };
            assert_ne!(mk("one").dedup_key(), mk("two").dedup_key());
            assert_eq!(mk("one").dedup_key(), mk("one").dedup_key());
        }
    }

    #[test]
    fn merging_retains_sources_and_does_not_promote_signals_to_confirmed() {
        let session = SessionId::new();
        let mut first = Finding::new(
            session,
            FindingKind::Vulnerability,
            Some("https://x.test/a".into()),
            "possible SSRF",
            Confidence::Low,
            Provenance::new(Source::JsRegex, Some("a.js".into())),
        );
        let mut second = Finding::new(
            session,
            FindingKind::Vulnerability,
            Some("https://x.test/a".into()),
            "possible SSRF",
            Confidence::High,
            Provenance::new(Source::Active, Some("GET /a".into())),
        );
        second.detectors.push("ssrf_signal".into());
        first.merge_from(second);
        assert_eq!(first.provenances.len(), 2);
        assert_eq!(first.detectors, ["ssrf_signal"]);
        assert_eq!(first.confidence, Confidence::High);
        assert_eq!(first.status, FindingStatus::Suspicious);
        assert_eq!(first.evidence_score(), 60);
    }

    #[test]
    fn classification_is_independent_of_severity() {
        let f = Finding::new(
            SessionId::new(),
            FindingKind::Secret,
            None,
            "fp:abc",
            Confidence::High,
            Provenance::new(Source::JsAst, None),
        );
        assert_eq!(f.severity(), Severity::High);
        assert_eq!(f.status, FindingStatus::Suspicious);
    }

    #[test]
    fn repeated_merges_keep_each_independent_evidence_once() {
        use crate::model::evidence::{EvidenceVerdict, ProbeEvidence};

        let mut original = Finding::new(
            SessionId::new(),
            FindingKind::Vulnerability,
            Some("https://fixture.test/a".into()),
            "possible SSRF",
            Confidence::Medium,
            Provenance::new(Source::Active, None),
        );
        let proof = |check: &str| ProbeEvidence {
            check: check.into(),
            parameter: Some("url".into()),
            verdict: EvidenceVerdict::Signal,
            observations: Vec::new(),
            limitation: "Observation only; exploitation not established".into(),
            diff: Vec::new(),
        };
        let first = proof("response_difference");
        let second = proof("url_reflection");
        original.evidence = Some(Box::new(first.clone()));

        let mut repeated = original.clone();
        repeated.evidence = Some(Box::new(second.clone()));
        // Reports can carry the same observation in either evidence field.
        repeated.additional_evidence = vec![first.clone(), second.clone()];
        for _ in 0..32 {
            original.merge_from(repeated.clone());
        }
        assert_eq!(original.evidence.as_deref(), Some(&first));
        assert_eq!(original.additional_evidence, [second]);
        assert_eq!(original.status, FindingStatus::Suspicious);
        assert_eq!(original.provenances.len(), 1);
    }

    #[test]
    fn merge_from_caps_provenances_on_a_large_crawl() {
        let mut target = Finding::new(
            SessionId::new(),
            FindingKind::Endpoint,
            Some("https://x.test/api/common".into()),
            "GET /api/common",
            Confidence::High,
            Provenance::new(Source::JsAst, Some("page-0.html".into())),
        );
        for i in 1..(MAX_PROVENANCES_PER_FINDING + 50) {
            let other = Finding::new(
                SessionId::new(),
                FindingKind::Endpoint,
                Some("https://x.test/api/common".into()),
                "GET /api/common",
                Confidence::High,
                Provenance::new(Source::JsAst, Some(format!("page-{i}.html"))),
            );
            target.merge_from(other);
        }
        assert_eq!(target.provenances.len(), MAX_PROVENANCES_PER_FINDING);
    }
