//! Progress stream, exit codes and `--help` of the real binary.

mod common;

use common::{cli, scan_args, success, Fixture, SECRET};

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn plain_progress_goes_to_stderr_and_stdout_stays_data() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("static", &fixture);
    args.extend(["--progress", "plain", "--no-banner"]);
    let output = cli(dir.path(), &args);
    success(&output);
    let err = stderr(&output);
    assert!(err.contains("static:") && err.contains("started"), "{err}");
    assert!(!err.contains('\r') && !err.contains('\x1b'), "{err:?}");
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains(SECRET));
    assert!(!out.contains("started"), "progress leaked to stdout");
}

#[test]
fn json_progress_is_one_object_per_line() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("static", &fixture);
    args.extend(["--progress", "json"]);
    let output = cli(dir.path(), &args);
    success(&output);
    let events: Vec<serde_json::Value> = stderr(&output)
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("valid json line"))
        .collect();
    assert!(events.iter().any(|e| e["event"] == "stage_started"));
    assert!(events.iter().any(|e| e["event"] == "finished"));
}

#[test]
fn quiet_and_none_silence_status_and_progress() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("static", &fixture);
    args.push("--quiet");
    let output = cli(dir.path(), &args);
    success(&output);
    let err = stderr(&output);
    assert!(
        !err.contains("mission '") && !err.contains("static:"),
        "{err}"
    );
    let mut args = scan_args("static", &fixture);
    args.extend(["--progress", "none"]);
    let output = cli(dir.path(), &args);
    success(&output);
    assert!(!stderr(&output).contains("static: "), "{}", stderr(&output));
}

#[test]
fn missing_seeds_is_a_usage_error_with_a_hint() {
    let dir = tempfile::tempdir().unwrap();
    let output = cli(dir.path(), &["static"]);
    assert_eq!(output.status.code(), Some(2));
    let err = stderr(&output);
    assert!(
        err.contains("error: no seeds") && err.contains("hint:"),
        "{err}"
    );
}

#[test]
fn clap_usage_errors_exit_2_and_runtime_errors_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(cli(dir.path(), &["bogus"]).status.code(), Some(2));
    let output = cli(dir.path(), &["report", "--input", "missing.json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("hint:"));
}

#[test]
fn fail_on_gates_on_severity_but_still_writes_the_report() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("static", &fixture);
    args.extend(["--fail-on", "high"]);
    let output = cli(dir.path(), &args);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(dir.path().join("webrev-report.json").exists());
    let mut args = scan_args("static", &fixture);
    args.extend(["--fail-on", "critical"]);
    success(&cli(dir.path(), &args));
}

#[test]
fn help_is_grouped_short_vs_long_and_has_examples() {
    let dir = tempfile::tempdir().unwrap();
    let long = String::from_utf8(cli(dir.path(), &["scan", "--help"]).stdout).unwrap();
    for heading in [
        "Target & scope:",
        "Network & auth:",
        "Budgets & pacing:",
        "Output:",
    ] {
        assert!(long.contains(heading), "{heading} missing:\n{long}");
    }
    assert!(long.contains("EXAMPLES:") && long.contains("EXIT STATUS:"));
    let short = String::from_utf8(cli(dir.path(), &["scan", "-h"]).stdout).unwrap();
    assert!(!short.contains("EXIT STATUS:"));
    assert!(short.contains("--seed <URL>"));
}

#[test]
fn completions_are_generated_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let output = cli(dir.path(), &["completions", "bash"]);
    success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("_webrev"));
}
