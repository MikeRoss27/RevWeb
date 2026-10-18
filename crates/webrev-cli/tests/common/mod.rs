// crates/webrev-cli/tests/common/mod.rs
//! Loopback fixture and CLI helpers shared by the integration tests.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const SECRET: &str = "AKIAZ4XB7NMPQR2STUVW";

pub struct Fixture {
    pub url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    pub fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let body = format!(
                "<html data-reactroot data-v-app><script>const apiKey = '{SECRET}'; fetch('/api/demo?token={SECRET}'); fetch('/api/users/123?q=hello'); fetch('/api/mutate', {{method:'POST'}}).catch(() => {{}});</script></html>"
            );
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Accepted sockets inherit the listener's non-blocking mode on Windows and BSD.
                        stream.set_nonblocking(false).unwrap();
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

pub fn cli(dir: &Path, args: &[&str]) -> Output {
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

pub fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

pub fn scan_args<'a>(command: &'a str, fixture: &'a Fixture) -> Vec<&'a str> {
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

pub fn cli_env(dir: &Path, args: &[&str], key: &str, value: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_webrev"))
        .current_dir(dir)
        .env_remove("WEBREV_PROXY")
        .env_remove("WEBREV_BEARER")
        .env_remove("WEBREV_NAME")
        .env("NO_PROXY", "*")
        .env(key, value)
        .args(args)
        .output()
        .unwrap()
}
