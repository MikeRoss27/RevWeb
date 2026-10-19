//! Exported reports are raw by default, because the captured values are the
//! proof a bug hunter files; `--redact` masks credentials in every format.
//! Logs, errors and the compact terminal summary are masked either way.

mod common;

use common::{cli, cli_env, scan_args, success, Fixture, SECRET};
use webrev_core::FindingKind;
use webrev_report::SessionReport;

const FORMATS: [&str; 8] = [
    "json", "jsonl", "csv", "urls", "text", "openapi", "dot", "graphml",
];

#[test]
fn exported_reports_keep_captured_values_by_default_in_every_format() {
    let fixture = Fixture::new();
    let raw_param = format!("token={SECRET}");
    for format in FORMATS {
        let dir = tempfile::tempdir().unwrap();
        let mut args = scan_args("scan", &fixture);
        args.extend(["--format", format, "--report", "-"]);
        let output = cli(dir.path(), &args);
        success(&output);
        let text = String::from_utf8_lossy(&output.stdout);
        match format {
            "json" => {
                let report: SessionReport = serde_json::from_slice(&output.stdout).unwrap();
                assert!(!report.redacted, "a raw report is not marked masked");
                assert!(report
                    .findings
                    .iter()
                    .any(|f| f.url.as_deref().is_some_and(|u| u.contains(&raw_param))));
                assert!(report.findings.iter().any(|f| {
                    f.kind == FindingKind::Secret && f.plaintext.as_deref() == Some(SECRET)
                }));
                assert!(report
                    .findings
                    .iter()
                    .any(|f| f.url.as_deref() == Some("/api/users/123?q=hello")));
            }
            "jsonl" | "csv" | "text" => {
                assert!(text.contains(&raw_param), "{format}: {text}");
            }
            // The endpoint listings (`urls`, OpenAPI, DOT, GraphML) normalise
            // paths and drop the query string by design; they still list it.
            _ => assert!(text.contains("/api/demo"), "{format}: {text}"),
        }
    }
}

#[test]
fn redact_masks_credentials_in_every_format() {
    let fixture = Fixture::new();
    let leaked_param = format!("token={SECRET}");
    for format in FORMATS {
        let dir = tempfile::tempdir().unwrap();
        let mut args = scan_args("scan", &fixture);
        args.extend(["--format", format, "--report", "-", "--redact"]);
        let output = cli(dir.path(), &args);
        success(&output);
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(!text.contains(&leaked_param), "{format}: {text}");
        match format {
            // The detected key is the deliverable of its secret finding and
            // nowhere else.
            "json" => {
                let report: SessionReport = serde_json::from_slice(&output.stdout).unwrap();
                assert!(report.redacted);
                for finding in report
                    .findings
                    .iter()
                    .filter(|f| f.kind != FindingKind::Secret)
                {
                    let body = serde_json::to_string(finding).unwrap();
                    assert!(!body.contains(SECRET), "{body}");
                }
                assert!(report.endpoints.iter().all(|e| !e.url.contains(SECRET)));
                assert!(report.findings.iter().any(|f| {
                    f.kind == FindingKind::Secret && f.plaintext.as_deref() == Some(SECRET)
                }));
                // Ordinary data survives, and the credential-bearing URL is
                // still listed with its parameter name.
                assert!(report
                    .findings
                    .iter()
                    .any(|f| f.url.as_deref() == Some("/api/users/123?q=hello")));
                assert!(report.findings.iter().any(|f| f
                    .url
                    .as_deref()
                    .is_some_and(|u| u.starts_with("/api/demo?token="))));
            }
            "jsonl" => {
                for line in text.lines() {
                    let finding: webrev_core::Finding = serde_json::from_str(line).unwrap();
                    if finding.kind != FindingKind::Secret {
                        assert!(!line.contains(SECRET), "{line}");
                    }
                }
            }
            "csv" => {
                for line in text.lines().filter(|l| l.contains(SECRET)) {
                    assert_eq!(line.split(',').nth(1), Some("secret"), "{line}");
                }
            }
            "text" => assert!(
                text.contains(SECRET),
                "plaintext stays in the SECRETS section"
            ),
            _ => assert!(!text.contains(SECRET), "{format}: {text}"),
        }
    }
}

#[test]
fn redact_flag_and_env_select_the_masked_report() {
    let fixture = Fixture::new();
    let raw_param = format!("token={SECRET}");
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("scan", &fixture);
    args.extend(["--format", "jsonl", "--report", "-"]);
    let raw = cli(dir.path(), &args);
    success(&raw);
    assert!(String::from_utf8_lossy(&raw.stdout).contains(&raw_param));

    let mut flagged = args.clone();
    flagged.push("--redact");
    let output = cli(dir.path(), &flagged);
    success(&output);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&raw_param));

    let output = cli_env(dir.path(), &args, "WEBREV_REPORT_REDACT", "1");
    success(&output);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&raw_param));
}

#[test]
fn the_unredacted_flag_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    for command in [
        "scan", "static", "dynamic", "active", "tui", "report", "bola",
    ] {
        let output = cli(dir.path(), &[command, "--unredacted"]);
        assert!(!output.status.success(), "{command} accepted --unredacted");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--unredacted"),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn report_conversion_follows_the_input_and_bola_accepts_either_capture() {
    let fixture = Fixture::new();
    let raw_param = format!("token={SECRET}");
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("scan", &fixture);
    args.extend(["--report", "raw.json"]);
    success(&cli(dir.path(), &args));
    let mut args = scan_args("scan", &fixture);
    args.extend(["--report", "masked.json", "--redact"]);
    success(&cli(dir.path(), &args));

    let raw_file = std::fs::read_to_string(dir.path().join("raw.json")).unwrap();
    assert!(raw_file.contains(&raw_param));
    assert!(!std::fs::read_to_string(dir.path().join("masked.json"))
        .unwrap()
        .contains(&raw_param));

    let convert = |extra: &[&str]| {
        let mut args = vec!["report", "--input", "raw.json", "--format", "jsonl"];
        args.extend_from_slice(extra);
        let output = cli(dir.path(), &args);
        success(&output);
        String::from_utf8(output.stdout).unwrap()
    };
    assert!(convert(&[]).contains(&raw_param));
    assert!(!convert(&["--redact"]).contains(&raw_param));

    std::fs::write(dir.path().join("a-auth.json"), r#"{"bearer":"account-a"}"#).unwrap();
    std::fs::write(dir.path().join("b-auth.json"), r#"{"bearer":"account-b"}"#).unwrap();
    for capture in ["raw.json", "masked.json"] {
        let output = cli(
            dir.path(),
            &[
                "bola",
                "--a-report",
                capture,
                "--b-report",
                capture,
                "--a-auth",
                "a-auth.json",
                "--b-auth",
                "b-auth.json",
            ],
        );
        // A masked report is still a valid input: only credentials were hidden.
        success(&output);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("0 captured object pair"), "{stderr}");
    }
}

#[test]
fn a_raw_report_file_comes_with_a_one_line_warning() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("scan", &fixture);
    args.extend(["--report", "raw.json"]);
    let output = cli(dir.path(), &args);
    success(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let warnings: Vec<_> = stderr.lines().filter(|l| l.contains("--redact")).collect();
    assert_eq!(warnings.len(), 1, "{stderr}");
    assert!(warnings[0].contains("credentials"), "{stderr}");

    let mut args = scan_args("scan", &fixture);
    args.extend(["--report", "masked.json", "--redact"]);
    let output = cli(dir.path(), &args);
    success(&output);
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("--redact"),
        "a masked report needs no warning"
    );
}

/// What scrolls past in a terminal, a CI log or a screen share stays masked
/// whatever the report mode: the compact summary, the logs and the errors.
#[test]
fn terminal_output_logs_and_errors_stay_masked_in_both_modes() {
    let fixture = Fixture::new();
    let seed_token = "Zk3Jq9XvT2bLm8Rw4NpYs7Ad";
    let seed = format!("{}?session_token={seed_token}", fixture.url);
    let dir = tempfile::tempdir().unwrap();
    for extra in [&[][..], &["--redact"][..]] {
        let mut args = vec![
            "scan",
            "--seed",
            &seed,
            "--delay-min-ms",
            "0",
            "--delay-max-ms",
            "0",
            "--max-pages",
            "1",
            "--max-depth",
            "0",
            "--report",
            "out.json",
        ];
        args.extend_from_slice(extra);
        let output = cli_env(dir.path(), &args, "RUST_LOG", "debug");
        success(&output);
        let terminal = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!terminal.contains(seed_token), "{extra:?}: {terminal}");
        // The token did reach the report (raw) or was masked there (--redact):
        // the terminal check above is not passing for lack of data.
        let report = std::fs::read_to_string(dir.path().join("out.json")).unwrap();
        assert_eq!(report.contains(seed_token), extra.is_empty(), "{extra:?}");
        assert!(
            !terminal.contains(&format!("token={SECRET}")),
            "{extra:?}: {terminal}"
        );
    }

    // An error that quotes a URL masks its credentials.
    std::fs::write(dir.path().join("a-auth.json"), r#"{"bearer":"account-a"}"#).unwrap();
    std::fs::write(dir.path().join("b-auth.json"), r#"{"bearer":"account-b"}"#).unwrap();
    let bad_seed = format!("http://[bad?token={SECRET}");
    for extra in [&[][..], &["--redact"][..]] {
        let mut args = vec![
            "bola",
            "--seed",
            &bad_seed,
            "--a-auth",
            "a-auth.json",
            "--b-auth",
            "b-auth.json",
        ];
        args.extend_from_slice(extra);
        let output = cli(dir.path(), &args);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("invalid BOLA seed URL"), "{stderr}");
        assert!(!stderr.contains(SECRET), "{extra:?}: {stderr}");
    }
}
