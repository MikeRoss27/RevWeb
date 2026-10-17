#!/usr/bin/env python3
"""Convert evidence-backed Webrev open-redirect findings for VulnerableApp.

This deliberately narrow adapter only submits the exact randomized redirect
proof produced by Webrev's ``open_redirect`` active check. All other findings
are retained in a review sidecar, so the comparator cannot silently grade
unmapped observations as vulnerabilities.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit


LOCATION_VALUE = re.compile(r"\(Location: ([^)]+)\)$")
PROBE_PATH = re.compile(r"/[0-9a-f]{16}$")


def open_redirect_proof(finding: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Check the proof fields required before scoring an open redirect."""
    if finding.get("kind") != "Vulnerability":
        return None, "not an active vulnerability finding"
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("check") != "open_redirect":
        return None, "no open_redirect check evidence"
    if evidence.get("verdict") != "observed":
        return None, "unexpected evidence verdict"
    match = LOCATION_VALUE.search(str(finding.get("value", "")))
    if not match:
        return None, "finding value lacks a Location value"
    location = match.group(1)
    source = urlsplit(str(finding.get("url", "")))
    if source.scheme not in ("http", "https") or not source.hostname:
        return None, "finding URL is not an absolute HTTP(S) URL"
    # WHATWG URL parsing for special HTTP(S) schemes removes ASCII tab/newline
    # bytes and treats backslashes as path separators. Python's urljoin follows
    # RFC 3986, so normalize these browser-defined cases before resolving.
    browser_location = location.translate({ord("\t"): None, ord("\r"): None, ord("\n"): None})
    browser_location = browser_location.replace("\\", "/")
    try:
        destination = urlsplit(urljoin(str(finding["url"]), browser_location))
    except (KeyError, ValueError):
        return None, "finding Location cannot be resolved against its probe URL"
    if (
        destination.scheme not in ("http", "https")
        or destination.hostname != "webrev-redirect-probe.invalid"
        or destination.hostname == source.hostname
        or not PROBE_PATH.fullmatch(destination.path)
        or destination.query
        or destination.fragment
    ):
        return None, "finding Location does not resolve to the randomized external .invalid target"
    observations = evidence.get("observations")
    if not isinstance(observations, list):
        return None, "missing response observations"
    for observation in observations:
        if not isinstance(observation, dict) or observation.get("role") != "probe":
            continue
        try:
            status = int(observation.get("status", 0))
        except (TypeError, ValueError):
            continue
        if (
            300 <= status < 400
            and observation.get("excerpt") == location
            and str(observation.get("method", "GET")).upper() == "GET"
        ):
            return observation, "exact randomized external .invalid target observed in resolved 3xx Location"
    return None, "no probe response proves the exact injected 3xx Location"


def route_only(url: str) -> str | None:
    """Return path only; query values and target host are not sent to the lab."""
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return parsed.path or "/"


def require_redirect_coverage(report: dict[str, Any]) -> dict[str, int]:
    """Do not turn an unrun check into an empty benchmark submission."""
    for finding in report.get("findings", []):
        if not isinstance(finding, dict) or finding.get("kind") != "ScanCoverage":
            continue
        coverage = finding.get("coverage")
        checks = coverage.get("checks") if isinstance(coverage, dict) else None
        check = checks.get("open_redirect") if isinstance(checks, dict) else None
        if not isinstance(check, dict):
            continue
        executed = (
            int(check.get("attempted", 0)) > 0
            and int(check.get("executed", 0)) > 0
            and int(check.get("not_executed", 0)) == 0
            and int(check.get("errors", 0)) == 0
            and int(check.get("inconclusive", 0)) == 0
        )
        if executed:
            return {
                key: int(check.get(key, 0))
                for key in (
                    "attempted", "executed", "not_executed", "not_selected",
                    "negative", "refused", "scope_refused", "errors",
                    "findings", "inconclusive",
                )
            }
    raise ValueError(
        "report has no usable open_redirect execution evidence; refusing to create a "
        "benchmark payload that could score untested cases as misses"
    )


def convert(report: dict[str, Any], tool_name: str = "Webrev") -> tuple[dict[str, Any], dict[str, Any]]:
    coverage = require_redirect_coverage(report)
    submitted: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for finding in report.get("findings", []):
        if not isinstance(finding, dict):
            continue
        if finding.get("kind") == "ScanCoverage":
            continue
        probe, reason = open_redirect_proof(finding)
        if probe is None:
            skipped.append({
                "finding_id": str(finding.get("id", "")),
                "kind": str(finding.get("kind", "")),
                "status": str(finding.get("status", "")),
                "reason": reason,
            })
            continue

        route = route_only(str(probe.get("url", "")))
        if route is None:
            skipped.append({
                "finding_id": str(finding.get("id", "")),
                "kind": str(finding.get("kind", "")),
                "status": str(finding.get("status", "")),
                "reason": "probe URL is not an absolute HTTP(S) URL",
            })
            continue
        item = {
            "url": route,
            "type": "OPEN_REDIRECT_3XX_STATUS_CODE",
            "method": "GET",
        }
        key = (item["url"], item["type"], item["method"])
        if key not in seen:
            submitted.append(item)
            seen.add(key)

    payload = {"tool": tool_name, "scanType": "DAST", "findings": submitted}
    review = {
        "adapter": "vulnerableapp_adapter.py",
        "mapping": "Webrev open_redirect exact randomized Location proof -> OPEN_REDIRECT_3XX_STATUS_CODE",
        "submitted_count": len(submitted),
        "skipped_count": len(skipped),
        "open_redirect_coverage": coverage,
        "coverage_note": "the comparator may count VulnerableApp cases outside the executed or selected target set as missed; use this result as an end-to-end run score, not detector-only recall",
        "skipped": skipped,
    }
    return payload, review


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Webrev JSON report")
    parser.add_argument("--output", type=Path, required=True, help="VulnerableApp benchmark input JSON")
    parser.add_argument("--review-output", type=Path, help="Sidecar for unmapped findings (default: OUTPUT.review.json)")
    parser.add_argument("--tool", default="Webrev", help="Tool label in the benchmark payload")
    args = parser.parse_args()

    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise ValueError("report must be an object containing a findings array")
        payload, review = convert(report, args.tool)
        review_path = args.review_output or args.output.with_suffix(args.output.suffix + ".review.json")
        args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        review_path.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"submitted {review['submitted_count']} unique finding(s); skipped {review['skipped_count']}; review: {review_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
