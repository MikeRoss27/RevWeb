import unittest

from vulnerableapp_adapter import convert, open_redirect_proof


TARGET = "https://webrev-redirect-probe.invalid/0123456789abcdef"


def redirect_finding(finding_id="redirect-1", url="https://lab.test/app?next=x"):
    return {
        "id": finding_id,
        "kind": "Vulnerability",
        "status": "observed",
        "url": url,
        "value": f"open redirect via 'next' parameter (Location: {TARGET})",
        "evidence": {
            "check": "open_redirect",
            "verdict": "observed",
            "observations": [{
                "role": "probe",
                "method": "GET",
                "url": url,
                "status": 302,
                "excerpt": TARGET,
            }],
        },
    }


def report_with_coverage(*findings):
    return {
        "findings": [
            {
                "kind": "ScanCoverage",
                "coverage": {"checks": {"open_redirect": {
                    "attempted": 1,
                    "executed": 1,
                    "not_executed": 0,
                    "not_selected": 0,
                    "refused": 0,
                    "scope_refused": 0,
                    "errors": 0,
                    "inconclusive": 0,
                }}},
            },
            *findings,
        ]
    }


class VulnerableAppAdapterTests(unittest.TestCase):
    def test_maps_exact_open_redirect_proof_and_strips_query(self):
        payload, review = convert(report_with_coverage(redirect_finding()))
        self.assertEqual(payload["findings"], [{
            "url": "/app",
            "type": "OPEN_REDIRECT_3XX_STATUS_CODE",
            "method": "GET",
        }])
        self.assertEqual(review["submitted_count"], 1)
        self.assertEqual(review["skipped_count"], 0)

    def test_deduplicates_same_case_from_multiple_evidence_records(self):
        payload, review = convert(report_with_coverage(
            redirect_finding("redirect-1", "https://lab.test/app?next=one"),
            redirect_finding("redirect-2", "https://lab.test/app?next=two"),
        ))
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(review["submitted_count"], 1)

    def test_accepts_protocol_relative_location_after_resolution(self):
        finding = redirect_finding()
        location = "//webrev-redirect-probe.invalid/0123456789abcdef"
        finding["value"] = f"open redirect via 'next' parameter (Location: {location})"
        finding["evidence"]["observations"][0]["excerpt"] = location
        payload, review = convert(report_with_coverage(finding))
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(review["submitted_count"], 1)

    def test_accepts_domain_prefix_location_with_external_authority(self):
        finding = redirect_finding(url="http://lab.test/app?next=%40target")
        location = "http://lab.test@webrev-redirect-probe.invalid/0123456789abcdef"
        finding["value"] = f"open redirect via 'next' parameter (Location: {location})"
        finding["evidence"]["observations"][0]["excerpt"] = location
        payload, review = convert(report_with_coverage(finding))
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(review["submitted_count"], 1)

    def test_accepts_browser_backslash_url_separator(self):
        finding = redirect_finding()
        location = r"\/webrev-redirect-probe.invalid/0123456789abcdef"
        finding["value"] = f"open redirect via 'next' parameter (Location: {location})"
        finding["evidence"]["observations"][0]["excerpt"] = location
        payload, review = convert(report_with_coverage(finding))
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(review["submitted_count"], 1)

    def test_resolves_tab_prefixed_protocol_relative_location(self):
        finding = redirect_finding()
        location = "\t//webrev-redirect-probe.invalid/0123456789abcdef"
        finding["value"] = f"open redirect via 'next' parameter (Location: {location})"
        finding["evidence"]["observations"][0]["excerpt"] = location
        payload, review = convert(report_with_coverage(finding))
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(review["submitted_count"], 1)

    def test_rejects_reflected_marker_on_same_origin_location(self):
        finding = redirect_finding()
        location = "/continue?next=https://webrev-redirect-probe.invalid/0123456789abcdef"
        finding["value"] = f"open redirect via 'next' parameter (Location: {location})"
        finding["evidence"]["observations"][0]["excerpt"] = location
        payload, review = convert(report_with_coverage(finding))
        self.assertEqual(payload["findings"], [])
        self.assertIn("does not resolve", review["skipped"][0]["reason"])

    def test_rejects_status_difference_or_missing_exact_location_proof(self):
        finding = redirect_finding()
        finding["evidence"]["observations"][0]["excerpt"] = "302 Found"
        payload, review = convert(report_with_coverage(finding))
        self.assertEqual(payload["findings"], [])
        self.assertIn("no probe response proves", review["skipped"][0]["reason"])

    def test_never_maps_ssrf_or_other_unverified_finding_types(self):
        finding = redirect_finding()
        finding["evidence"]["check"] = "ssrf_signal"
        finding["value"] = "possible SSRF based on response"
        payload, review = convert(report_with_coverage(finding))
        self.assertEqual(payload["findings"], [])
        self.assertEqual(review["skipped_count"], 1)

    def test_rejects_non_http_observation_url(self):
        finding = redirect_finding(url="/relative")
        payload, review = convert(report_with_coverage(finding))
        self.assertEqual(payload["findings"], [])
        self.assertIn("not an absolute HTTP(S)", review["skipped"][0]["reason"])

    def test_refuses_unexecuted_probe_coverage(self):
        report = report_with_coverage()
        report["findings"][0]["coverage"]["checks"]["open_redirect"]["executed"] = 0
        with self.assertRaisesRegex(ValueError, "no usable open_redirect execution"):
            convert(report)

    def test_keeps_refused_coverage_visible_in_sidecar(self):
        report = report_with_coverage(redirect_finding())
        check = report["findings"][0]["coverage"]["checks"]["open_redirect"]
        check["refused"] = 1
        payload, review = convert(report)
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(review["open_redirect_coverage"]["refused"], 1)


if __name__ == "__main__":
    unittest.main()
