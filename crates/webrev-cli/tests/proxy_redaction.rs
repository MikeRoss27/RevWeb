//! `--proxy` carries the upstream proxy's credentials in its userinfo
//! (`http://user:pass@host:port`), and reqwest turns that into a
//! `Proxy-Authorization` header on every proxied request. Per
//! `docs/security.md`, logs/errors/the compact summary stay masked
//! regardless of `--redact`; this was never actually exercised with a
//! `--proxy` configured (only direct egress was measured on 2026-10-18), so
//! this test drives a real proxied scan under `RUST_LOG=trace` and checks the
//! proxy credential never reaches stdout/stderr or the written report.

mod common;

use common::cli_env;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const PROXY_USER: &str = "proxyuser";
const PROXY_PASS: &str = "proxyS3cretPass123";

/// A minimal HTTP forward proxy: it does not inspect the absolute-URI target,
/// it just answers every proxied request with a fixed body, the same way the
/// real destination would. Good enough to exercise the client's proxy
/// handshake (and its `Proxy-Authorization` header) without a real upstream.
struct ProxyFixture {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ProxyFixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{PROXY_USER}:{PROXY_PASS}@{addr}");
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let body = "<html><script>fetch('/api/demo');</script></html>";
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
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
                        // Answer unconditionally; the client used the proxy
                        // handshake regardless of what we do with the target.
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("proxy listener: {e}"),
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

impl Drop for ProxyFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn proxy_credentials_never_reach_stdout_stderr_or_the_report_under_trace_logging() {
    let proxy = ProxyFixture::new();
    let dir = tempfile::tempdir().unwrap();
    for level in ["debug", "trace"] {
        let args = [
            "scan",
            "--seed",
            "http://proxy-redaction-fixture.test/",
            "--proxy",
            &proxy.url,
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
        let output = cli_env(dir.path(), &args, "RUST_LOG", level);
        let terminal = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !terminal.contains(PROXY_PASS),
            "{level}: proxy password leaked: {terminal}"
        );
        // The Basic auth header is base64(user:pass); check the encoded form
        // too, in case the raw password string itself is never printed but
        // the header value is.
        let encoded = base64_encode(format!("{PROXY_USER}:{PROXY_PASS}").as_bytes());
        assert!(
            !terminal.contains(&encoded),
            "{level}: proxy Basic auth header leaked: {terminal}"
        );
        let report_path = dir.path().join("out.json");
        if report_path.exists() {
            let report = std::fs::read_to_string(&report_path).unwrap();
            assert!(
                !report.contains(PROXY_PASS),
                "{level}: proxy password leaked into the report: {report}"
            );
            assert!(
                !report.contains(&encoded),
                "{level}: proxy Basic auth header leaked into the report: {report}"
            );
            let _ = std::fs::remove_file(&report_path);
        }
    }
}

/// Tiny dependency-free base64 encoder (standard alphabet, padded), just for
/// building the same `Proxy-Authorization` value reqwest would send.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}
