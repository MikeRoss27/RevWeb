//! Exported reports mask credentials in every format; `--unredacted` keeps them.

mod common;

use common::{cli, cli_env, scan_args, success, Fixture, SECRET};
use webrev_core::FindingKind;
use webrev_report::SessionReport;

#[test]
fn exported_reports_mask_credentials_in_every_format() {
    let fixture = Fixture::new();
    let leaked_param = format!("token={SECRET}");
    for format in [
        "json", "jsonl", "csv", "urls", "text", "openapi", "dot", "graphml",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut args = scan_args("scan", &fixture);
        args.extend(["--format", format, "--report", "-"]);
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
fn unredacted_flag_and_env_keep_the_raw_report() {
    let fixture = Fixture::new();
    let raw_param = format!("token={SECRET}");
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("scan", &fixture);
    args.extend(["--format", "jsonl", "--report", "-"]);
    let masked = cli(dir.path(), &args);
    success(&masked);
    assert!(!String::from_utf8_lossy(&masked.stdout).contains(&raw_param));

    let mut flagged = args.clone();
    flagged.push("--unredacted");
    let output = cli(dir.path(), &flagged);
    success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains(&raw_param));

    let output = cli_env(dir.path(), &args, "WEBREV_REPORT_UNREDACTED", "1");
    success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains(&raw_param));
}

#[test]
fn report_conversion_masks_a_raw_file_and_bola_accepts_a_masked_one() {
    let fixture = Fixture::new();
    let raw_param = format!("token={SECRET}");
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("scan", &fixture);
    args.extend(["--report", "raw.json", "--unredacted"]);
    success(&cli(dir.path(), &args));
    let mut args = scan_args("scan", &fixture);
    args.extend(["--report", "masked.json"]);
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
    assert!(!convert(&[]).contains(&raw_param));
    assert!(convert(&["--unredacted"]).contains(&raw_param));

    std::fs::write(dir.path().join("a-auth.json"), r#"{"bearer":"account-a"}"#).unwrap();
    std::fs::write(dir.path().join("b-auth.json"), r#"{"bearer":"account-b"}"#).unwrap();
    let output = cli(
        dir.path(),
        &[
            "bola",
            "--a-report",
            "masked.json",
            "--b-report",
            "masked.json",
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
