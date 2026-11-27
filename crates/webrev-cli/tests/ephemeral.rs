//! Exercise the real CLI against a loopback fixture, including its disk output.

mod common;

use common::{cli, files, scan_args, success, Fixture, SECRET};
use webrev_core::FindingKind;
use webrev_report::SessionReport;

#[test]
fn default_scans_export_plaintext_without_any_database() {
    let fixture = Fixture::new();
    for command in ["scan", "static"] {
        let dir = tempfile::tempdir().unwrap();
        let output = cli(dir.path(), &scan_args(command, &fixture));
        success(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains(SECRET));
        let report: SessionReport =
            serde_json::from_slice(&std::fs::read(dir.path().join("webrev-report.json")).unwrap())
                .unwrap();
        assert_eq!(report.mission.seeds, vec![fixture.url.clone()]);
        assert!(report.findings.iter().any(|finding| {
            finding.kind == FindingKind::Secret && finding.plaintext.as_deref() == Some(SECRET)
        }));
        assert!(!report.endpoints.is_empty());
        assert_eq!(files(dir.path()), vec!["webrev-report.json"]);
    }
}

#[test]
fn no_report_shows_secrets_and_leaves_no_files() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("scan", &fixture);
    args.push("--no-report");
    let output = cli(dir.path(), &args);
    success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(files(dir.path()).is_empty());
}

#[test]
fn report_conversion_preserves_metadata_and_plaintext() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("scan", &fixture);
    args.extend(["--report", "custom.json", "--name", "fixture mission"]);
    success(&cli(dir.path(), &args));
    let original = std::fs::read(dir.path().join("custom.json")).unwrap();

    for format in ["json", "jsonl", "csv", "urls"] {
        let output = cli(
            dir.path(),
            &["report", "--input", "custom.json", "--format", format],
        );
        success(&output);
        let rendered = String::from_utf8(output.stdout).unwrap();
        if format == "urls" {
            assert!(rendered.contains("/api/demo"));
        } else {
            assert!(rendered.contains(SECRET), "missing secret in {format}");
        }
        if format == "json" {
            let report: SessionReport = serde_json::from_str(&rendered).unwrap();
            assert_eq!(report.mission.name, "fixture mission");
            assert_eq!(report.mission.seeds, vec![fixture.url.clone()]);
        }
    }
    assert_eq!(
        std::fs::read(dir.path().join("custom.json")).unwrap(),
        original
    );
    assert_eq!(files(dir.path()), vec!["custom.json"]);
}

#[test]
fn scan_exports_plaintext_in_each_finding_format() {
    let fixture = Fixture::new();
    for format in ["json", "jsonl", "csv"] {
        let dir = tempfile::tempdir().unwrap();
        let mut args = scan_args("scan", &fixture);
        args.extend(["--format", format, "--report", "result.txt"]);
        success(&cli(dir.path(), &args));
        assert!(std::fs::read_to_string(dir.path().join("result.txt"))
            .unwrap()
            .contains(SECRET));
        assert_eq!(files(dir.path()), vec!["result.txt"]);
    }
}

#[test]
fn standalone_active_exports_without_database() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    success(&cli(dir.path(), &scan_args("active", &fixture)));
    let report: SessionReport =
        serde_json::from_slice(&std::fs::read(dir.path().join("webrev-report.json")).unwrap())
            .unwrap();
    assert!(!report.findings.is_empty());
    assert_eq!(files(dir.path()), vec!["webrev-report.json"]);
}

#[test]
#[ignore = "requires a local Chromium/Chrome installation"]
fn dynamic_scans_preserve_captured_tokens_without_database() {
    let fixture = Fixture::new();
    for command in ["dynamic", "scan"] {
        let dir = tempfile::tempdir().unwrap();
        let mut args = scan_args(command, &fixture);
        args.extend(["--duration-secs", "1"]);
        if command == "scan" {
            args.push("--dynamic");
        }
        let output = cli(dir.path(), &args);
        success(&output);
        let report: SessionReport =
            serde_json::from_slice(&std::fs::read(dir.path().join("webrev-report.json")).unwrap())
                .unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.provenance.source == webrev_core::Source::Browser
                && finding
                    .url
                    .as_deref()
                    .is_some_and(|url| url.contains(SECRET))
        }));
        assert_eq!(files(dir.path()), vec!["webrev-report.json"]);
    }
}

#[test]
fn removed_options_are_rejected_and_missing_report_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    for command in ["scan", "static", "dynamic", "active", "tui", "report"] {
        let output = cli(dir.path(), &[command, "--db", "unused.db"]);
        assert!(!output.status.success());
    }
    for option in ["--no-db", "--reveal-secrets", "--no-secret-reveal"] {
        let output = cli(dir.path(), &["scan", option]);
        assert!(!output.status.success());
    }
    assert!(!cli(dir.path(), &["report"]).status.success());
    assert!(files(dir.path()).is_empty());
}

#[test]
fn zero_active_budget_is_wired_to_json_coverage_without_disk_output() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let output = cli(
        dir.path(),
        &[
            "active",
            "--seed",
            &fixture.url,
            "--max-active-requests",
            "0",
            "--report",
            "-",
        ],
    );
    success(&output);
    let report: SessionReport = serde_json::from_slice(&output.stdout).unwrap();
    let coverage = report
        .findings
        .iter()
        .find_map(|f| f.coverage.as_ref())
        .unwrap();
    assert_eq!(coverage.requests, 0);
    assert!(coverage.budget_exhausted && !coverage.complete());
    assert!(files(dir.path()).is_empty());
}

#[test]
fn scan_stdout_exports_are_clean_and_create_no_files() {
    let fixture = Fixture::new();
    for format in ["json", "jsonl", "urls", "text"] {
        let dir = tempfile::tempdir().unwrap();
        let mut args = scan_args("scan", &fixture);
        args.extend(["--format", format, "--report", "-"]);
        let output = cli(dir.path(), &args);
        success(&output);
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(!text.contains("mission '"));
        assert!(!text.contains("report written"));
        assert!(!text.contains('\u{1b}'));
        match format {
            "json" => {
                serde_json::from_slice::<SessionReport>(&output.stdout).unwrap();
            }
            "jsonl" => {
                for line in text.lines() {
                    serde_json::from_str::<webrev_core::Finding>(line).unwrap();
                }
            }
            "urls" => {
                assert!(text.lines().all(|line| line.starts_with("http://")));
            }
            "text" => {
                assert!(text.contains("TECHNOLOGIES"));
                assert!(text.contains(SECRET));
            }
            _ => unreachable!(),
        }
        assert!(files(dir.path()).is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("static:"));
    }
    for command in ["static", "active"] {
        let dir = tempfile::tempdir().unwrap();
        let mut args = scan_args(command, &fixture);
        args.extend(["--report", "-"]);
        let output = cli(dir.path(), &args);
        success(&output);
        serde_json::from_slice::<SessionReport>(&output.stdout).unwrap();
        assert!(files(dir.path()).is_empty());
    }
}

#[test]
fn active_scan_triage_uses_real_queries_and_ids_and_shows_the_stack() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("scan", &fixture);
    args.extend(["--active", "--cookie", "session=fixture"]);
    let output = cli(dir.path(), &args);
    success(&output);
    let text = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "VULNERABILITIES",
        "SECRETS",
        "TECHNOLOGIES",
        "React (framework)",
        "Vue.js (framework)",
        SECRET,
        "XSS",
        "SQLi",
        "IDOR",
        "signal / verify manually",
        "RCE: timing probe only",
        "confidence=",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    let report: SessionReport =
        serde_json::from_slice(&std::fs::read(dir.path().join("webrev-report.json")).unwrap())
            .unwrap();
    for category in ["XSS", "SQLi", "IDOR"] {
        let findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category() == category)
            .collect();
        assert!(
            !findings.is_empty(),
            "missing {category}: {}",
            report.to_json().unwrap()
        );
        assert!(findings
            .iter()
            .any(|f| f.url.as_deref().unwrap().contains("/api/users/123")));
    }
    assert_eq!(files(dir.path()), vec!["webrev-report.json"]);
    let conversion = cli(dir.path(), &["report", "--format", "text"]);
    success(&conversion);
    let detailed = String::from_utf8_lossy(&conversion.stdout);
    assert!(detailed.contains("baseline:"));
    assert!(detailed.contains("ATTACK SURFACE"));
    assert!(text.contains("to review"));
    assert!(text.contains("COVERAGE"));
}

#[test]
#[ignore = "requires a local Chromium/Chrome installation"]
fn observation_only_exports_refusals_and_preserves_plaintext() {
    let fixture = Fixture::new();
    for command in ["dynamic", "scan"] {
        let dir = tempfile::tempdir().unwrap();
        let mut args = scan_args(command, &fixture);
        args.extend(["--duration-secs", "1", "--observation-only"]);
        if command == "scan" {
            args.push("--dynamic");
        }
        success(&cli(dir.path(), &args));
        let report: SessionReport =
            serde_json::from_slice(&std::fs::read(dir.path().join("webrev-report.json")).unwrap())
                .unwrap();
        let coverage = report
            .findings
            .iter()
            .find(|finding| {
                finding.kind == FindingKind::ScanCoverage
                    && finding.provenance.source == webrev_core::Source::Browser
            })
            .expect("browser coverage");
        let evidence: serde_json::Value = serde_json::from_str(&coverage.value).unwrap();
        assert_eq!(evidence["complete"], false);
        assert_eq!(evidence["policy"], "ObserveOnly");
        assert!(evidence["refused_requests"]
            .as_array()
            .unwrap()
            .iter()
            .any(|request| request["method"] == "POST" && request["reason"] == "MethodRestricted"));
        assert!(!report
            .endpoints
            .iter()
            .any(|endpoint| endpoint.source == webrev_core::Source::Browser
                && endpoint.url.ends_with("/api/mutate")));
        assert!(report.findings.iter().any(|finding| finding
            .url
            .as_deref()
            .is_some_and(|url| url.contains(SECRET))));
        let text = cli(
            dir.path(),
            &[
                "report",
                "--input",
                "webrev-report.json",
                "--format",
                "text",
            ],
        );
        success(&text);
        let text = String::from_utf8(text.stdout).unwrap();
        assert!(text.contains("COVERAGE") && text.contains("MethodRestricted"));
        assert!(text.contains(SECRET));
    }
}

#[test]
fn tui_rejects_unsupported_observation_policy_before_launch() {
    let dir = tempfile::tempdir().unwrap();
    let output = cli(dir.path(), &["tui", "--observation-only"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("TUI browser exploration does not support"));
}
