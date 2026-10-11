//! Exercise the real CLI against a loopback fixture, including its disk output.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use webrev_core::FindingKind;
use webrev_report::SessionReport;

const SECRET: &str = "AKIAZ4XB7NMPQR2STUVW";

struct Fixture {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let body = format!(
                "<html data-reactroot data-v-app><script>const apiKey = '{SECRET}'; fetch('/api/demo?token={SECRET}'); fetch('/api/users/123?q=hello');</script></html>"
            );
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let mut request_bytes = Vec::new();
                        let mut chunk = [0; 4096];
                        while request_bytes.len() < 16384
                            && !request_bytes.windows(4).any(|w| w == b"\r\n\r\n")
                        {
                            let len = stream.read(&mut chunk).unwrap_or(0);
                            if len == 0 {
                                break;
                            }
                            request_bytes.extend_from_slice(&chunk[..len]);
                        }
                        let request = String::from_utf8_lossy(&request_bytes);
                        let path = request.split_whitespace().nth(1).unwrap_or("/");
                        let body = if path.contains("wrvFuzz") {
                            format!(
                                "sqlstate[fixture] {}",
                                reqwest::Url::parse(&format!("http://fixture.test{path}"))
                                    .unwrap()
                                    .query_pairs()
                                    .map(|(_, value)| value.into_owned())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            )
                        } else if path.starts_with("/api/users/123") {
                            r#"{"id":123,"name":"fixture"}"#.to_owned()
                        } else {
                            body.clone()
                        };
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("fixture listener: {e}"),
                }
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn cli(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_webrev"))
        .current_dir(dir)
        .env_remove("WEBREV_PROXY")
        .env_remove("WEBREV_BEARER")
        .env_remove("WEBREV_NAME")
        // Legacy settings must neither restore persistence nor hide secrets.
        .env("WEBREV_DB", dir.join("legacy.db"))
        .env("WEBREV_REVEAL_SECRETS", "false")
        .env("NO_PROXY", "*")
        .args(args)
        .output()
        .unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn scan_args<'a>(command: &'a str, fixture: &'a Fixture) -> Vec<&'a str> {
    vec![
        command,
        "--seed",
        &fixture.url,
        "--delay-min-ms",
        "0",
        "--delay-max-ms",
        "0",
        "--max-pages",
        "1",
        "--max-depth",
        "0",
    ]
}

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
        "RCE: not tested",
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
    assert_eq!(String::from_utf8_lossy(&conversion.stdout), text);
}
