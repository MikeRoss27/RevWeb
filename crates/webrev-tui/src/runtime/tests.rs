//! Exercise scan launching and event delivery without an interactive terminal.
use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use webrev_core::{AuthConfig, Mission, OpsecConfig, Scope};

struct Fixture {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
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
                            "<html data-reactroot data-v-app><script>fetch('/api/users/123?q=hello')</script></html>".to_owned()
                        };
                        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
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

async fn drain_scan(app: &mut App, rx: &mut mpsc::UnboundedReceiver<UiEvent>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = rx.recv().await.unwrap();
            let finished = matches!(&event, UiEvent::ScanFinished(_));
            app.apply(event);
            if finished {
                break;
            }
        }
    })
    .await
    .expect("scan must finish and release the UI");
}

#[tokio::test]
async fn tui_active_key_surfaces_real_probe_results_after_static_recon() {
    let fixture = Fixture::new();
    let mission = Mission::new(
        "tui fixture",
        Scope::new(vec!["127.0.0.1".into()], vec![]),
        vec![fixture.url.clone()],
    );
    let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
    storage.create_session(&mission).await.unwrap();
    let controller = Controller {
        mission: Arc::new(mission.clone()),
        opsec: Arc::new(OpsecConfig {
            delay_min_ms: 0,
            delay_max_ms: 0,
            max_pages: 1,
            max_depth: 0,
            auth: AuthConfig {
                cookies: vec![("session".into(), "fixture".into())],
                ..AuthConfig::default()
            },
            ..OpsecConfig::default()
        }),
        registry: Arc::new(ExtractorRegistry::with_defaults()),
        storage,
        cancel: CancellationToken::new(),
        report_path: PathBuf::new(),
        redact_report: true,
    };
    let mut app = App::new(mission.name, mission.scope);
    let (tx, mut rx) = mpsc::unbounded_channel();
    handle_action(
        crate::events::Action::StartStatic,
        &mut app,
        &controller,
        &tx,
    );
    assert!(app.scanning);
    drain_scan(&mut app, &mut rx).await;
    assert!(!app.scanning);
    assert!(app.tab_count(crate::app::Tab::Technologies) >= 2);
    let active = map_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('a'),
        crossterm::event::KeyModifiers::NONE,
    ));
    handle_action(active, &mut app, &controller, &tx);
    drain_scan(&mut app, &mut rx).await;
    assert!(!app.scanning);
    for category in ["IDOR", "XSS", "SQLi"] {
        assert!(
            app.category_count(category) > 0,
            "missing {category}: {:?}",
            app.findings
        );
    }
    assert!(app.status.starts_with("active scan done"));
}
