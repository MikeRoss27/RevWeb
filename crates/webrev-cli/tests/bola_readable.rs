//! A BOLA/IDOR result is raw by default and must stay usable under `--redact`
//! too: the reader has to see which object leaked, and the account
//! credentials that drove the comparison are never written to the result.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use webrev_core::{Confidence, Finding, FindingKind, Mission, Provenance, Scope, Source};
use webrev_report::SessionReport;

const ID_A: &str = "550e8400-e29b-41d4-a716-446655440001";
const ID_B: &str = "550e8400-e29b-41d4-a716-446655440002";
const BEARER_A: &str = "Zk3Jq9XvT2bLm8Rw4NpYs7Ad";
const BEARER_B: &str = "Qw8Er5TyUi2OpAs6DfGh3Jk9";
/// Credentials stored inside the two objects themselves: the proof body keeps
/// them raw, `--redact` must not.
const KEY_A: &str = "Xk9fQ2mT7vLp4RwZ8nBc";
const KEY_B: &str = "Hd3Ws6YuN1eCq5JtV9aG";

/// Two private objects behind bearer tokens. When `vulnerable`, the server
/// ignores the token and serves any object to anyone.
struct Api {
    origin: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Api {
    fn new(vulnerable: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut chunk = [0; 4096];
                        while request.len() < 16384 && !request.windows(4).any(|w| w == b"\r\n\r\n")
                        {
                            let len = stream.read(&mut chunk).unwrap_or(0);
                            if len == 0 {
                                break;
                            }
                            request.extend_from_slice(&chunk[..len]);
                        }
                        let request = String::from_utf8_lossy(&request);
                        let path = request.split_whitespace().nth(1).unwrap_or("/");
                        let caller_a = request.contains(BEARER_A);
                        let caller_b = request.contains(BEARER_B);
                        let (status, body) = if path.ends_with(ID_A) {
                            if vulnerable || caller_a {
                                (
                                    "200 OK",
                                    format!(
                                        r#"{{"id":"{ID_A}","owner":"a","note":"alpha","api_key":"{KEY_A}"}}"#
                                    ),
                                )
                            } else {
                                ("403 Forbidden", r#"{"error":"forbidden"}"#.to_owned())
                            }
                        } else if path.ends_with(ID_B) {
                            if vulnerable || caller_b {
                                (
                                    "200 OK",
                                    format!(
                                        r#"{{"id":"{ID_B}","owner":"b","note":"bravo","api_key":"{KEY_B}"}}"#
                                    ),
                                )
                            } else {
                                ("403 Forbidden", r#"{"error":"forbidden"}"#.to_owned())
                            }
                        } else {
                            ("404 Not Found", r#"{"error":"missing"}"#.to_owned())
                        };
                        let _ = write!(
                            stream,
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
            origin,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

/// A capture of one account, exported the way a scan exports it by default.
fn capture(api: &Api, id: &str) -> String {
    let mission = Mission::new(
        "capture",
        Scope::new(vec!["127.0.0.1".into()], vec![]),
        vec![format!("{}/", api.origin)],
    );
    let url = format!("{}/api/orders/{id}", api.origin);
    let endpoint = Finding::new(
        mission.id,
        FindingKind::Endpoint,
        Some(url.clone()),
        "GET",
        Confidence::High,
        Provenance::new(Source::Browser, Some(url)),
    );
    SessionReport::build(mission, vec![endpoint], vec![])
        .export_json(false)
        .unwrap()
}

fn run_bola(dir: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_webrev"))
        .current_dir(dir)
        .env_remove("WEBREV_PROXY")
        .env_remove("WEBREV_BEARER")
        .env_remove("WEBREV_REPORT_REDACT")
        .env("NO_PROXY", "*")
        .args([
            "bola",
            "--a-report",
            "a.json",
            "--b-report",
            "b.json",
            "--a-auth",
            "a-auth.json",
            "--b-auth",
            "b-auth.json",
            "--output",
            "-",
            "--max-requests",
            "8",
        ])
        .args(extra)
        .output()
        .unwrap()
}

fn scenario(vulnerable: bool, extra: &[&str]) -> (SessionReport, String, String) {
    let api = Api::new(vulnerable);
    let dir = tempfile::tempdir().unwrap();
    let a = capture(&api, ID_A);
    let b = capture(&api, ID_B);
    std::fs::write(dir.path().join("a.json"), &a).unwrap();
    std::fs::write(dir.path().join("b.json"), &b).unwrap();
    std::fs::write(
        dir.path().join("a-auth.json"),
        format!(r#"{{"bearer":"{BEARER_A}"}}"#),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b-auth.json"),
        format!(r#"{{"bearer":"{BEARER_B}"}}"#),
    )
    .unwrap();
    assert!(a.contains(ID_A) && b.contains(ID_B), "{a}\n{b}");
    let output = run_bola(dir.path(), extra);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let report: SessionReport = serde_json::from_str(&stdout).unwrap();
    (report, stdout, stderr)
}

/// The result names the affected object and says which accounts could read it.
fn assert_idor_is_readable(report: &SessionReport, stdout: &str) {
    let idor = report
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::Idor)
        .unwrap_or_else(|| panic!("no Idor finding in {stdout}"));
    let url = idor.url.as_deref().unwrap();
    assert!(
        url.ends_with(ID_A) || url.ends_with(ID_B),
        "the affected object must be readable: {url}"
    );
    let evidence = idor.evidence.as_ref().expect("evidence");
    assert_eq!(evidence.observations.len(), 4, "{stdout}");
    let seen: Vec<_> = evidence
        .observations
        .iter()
        .map(|o| (o.role.as_str(), o.status))
        .collect();
    assert!(
        seen.contains(&("B reads A object", 200)) || seen.contains(&("A reads B object", 200)),
        "{seen:?}"
    );
    for (role, observation) in evidence
        .observations
        .iter()
        .map(|o| (o.role.as_str(), o))
        .filter(|(role, _)| role.contains("object"))
    {
        assert!(
            observation.url.ends_with(ID_A) || observation.url.ends_with(ID_B),
            "{role}: {}",
            observation.url
        );
        // The fingerprint identifies the response; the same fingerprint on
        // both accounts is what proves the object was shared.
        assert!(
            observation.excerpt.starts_with("sha256="),
            "{role}: {}",
            observation.excerpt
        );
        // The proof is the content itself: which object the other account read.
        assert!(
            observation.body.contains(r#""owner""#) && observation.body.contains(r#""note""#),
            "{role}: {}",
            observation.body
        );
        assert!(!observation.body_truncated, "{role}");
    }
    let leaked: Vec<_> = evidence
        .observations
        .iter()
        .filter(|o| o.status == 200 && o.role.contains("reads"))
        .collect();
    assert!(!leaked.is_empty(), "{seen:?}");
    for observation in leaked {
        let object = if observation.role.starts_with("B reads A") {
            (ID_A, "alpha")
        } else {
            (ID_B, "bravo")
        };
        assert!(
            observation.body.contains(object.0) && observation.body.contains(object.1),
            "{}: {}",
            observation.role,
            observation.body
        );
    }
    // The comparison states the direction and the fields that tell the two
    // owners' objects apart.
    let diff = evidence.diff.join("\n");
    assert!(
        diff.contains("B reads A's object") || diff.contains("A reads B's object"),
        "{diff}"
    );
    assert!(diff.contains(r#"note: "alpha" ≠ "bravo""#), "{diff}");
    assert!(diff.contains(r#"owner: "a" ≠ "b""#), "{diff}");
}

/// Raw keeps the credentials stored inside the leaked objects; `--redact`
/// hides them from the body and the comparison but keeps the object readable.
fn assert_object_credentials(stdout: &str, redacted: bool) {
    for key in [KEY_A, KEY_B] {
        assert_eq!(stdout.contains(key), !redacted, "{key} in {stdout}");
    }
}

fn assert_no_account_credential(stdout: &str) {
    for credential in [BEARER_A, BEARER_B] {
        assert!(
            !stdout.contains(credential),
            "{credential} leaked: {stdout}"
        );
    }
}

#[test]
fn an_idor_result_is_raw_and_readable_by_default() {
    let (report, stdout, stderr) = scenario(true, &[]);
    assert!(stderr.contains("1 captured object pair"), "{stderr}");
    assert!(!report.redacted, "the result is raw by default");
    assert_idor_is_readable(&report, &stdout);
    assert_object_credentials(&stdout, false);
    assert_no_account_credential(&stdout);
}

#[test]
fn an_idor_result_stays_readable_under_redact() {
    let (report, stdout, stderr) = scenario(true, &["--redact"]);
    assert!(stderr.contains("1 captured object pair"), "{stderr}");
    assert!(report.redacted, "--redact marks the result");
    assert_idor_is_readable(&report, &stdout);
    assert_object_credentials(&stdout, true);
    assert_no_account_credential(&stdout);
}

#[test]
fn protected_objects_give_no_signal_and_no_credential() {
    for extra in [&[][..], &["--redact"][..]] {
        let (report, stdout, stderr) = scenario(false, extra);
        assert!(stderr.contains("1 captured object pair"), "{stderr}");
        assert!(
            !report.findings.iter().any(|f| f.kind == FindingKind::Idor),
            "{stdout}"
        );
        assert_no_account_credential(&stdout);
    }
}
