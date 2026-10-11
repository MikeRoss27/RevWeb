use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub(super) struct Reply {
    pub status: u16,
    pub mime: &'static str,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub delay_ms: u64,
}

impl Reply {
    pub fn html(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            mime: "text/html",
            body: body.into().into_bytes(),
            headers: vec![],
            delay_ms: 0,
        }
    }

    pub fn json(body: impl Into<String>) -> Self {
        Self {
            mime: "application/json",
            ..Self::html(body)
        }
    }
}

pub(super) struct Fixture {
    pub origin: String,
    pub requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Fixture {
    pub fn new(handler: impl Fn(&str) -> Reply + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(vec![]));
        let stopping = stop.clone();
        let captured = requests.clone();
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                let (mut socket, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("accept: {e}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut bytes = vec![];
                let mut chunk = [0; 4096];
                while bytes.len() < 16384 && !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    let Ok(n) = socket.read(&mut chunk) else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                }
                if bytes.is_empty() {
                    continue;
                }
                let request = String::from_utf8_lossy(&bytes).into_owned();
                captured.lock().unwrap().push(request.clone());
                let reply = handler(&request);
                if reply.status == 0 {
                    // Deliberate pre-response disconnect for transport-budget tests.
                    continue;
                }
                thread::sleep(Duration::from_millis(reply.delay_ms));
                let mut response = format!("HTTP/1.1 {} Fixture\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Security-Policy: frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\n", reply.status, reply.mime, reply.body.len());
                for (key, value) in reply.headers {
                    response.push_str(&key);
                    response.push_str(": ");
                    response.push_str(&value);
                    response.push_str("\r\n");
                }
                response.push_str("\r\n");
                let mut output = response.into_bytes();
                output.extend_from_slice(&reply.body);
                let _ = socket.write_all(&output);
                let _ = socket.shutdown(std::net::Shutdown::Write);
                // Drain peer shutdown before closing the Windows socket, so
                // fixture teardown cannot reset a completed response.
                let _ = socket.read(&mut chunk);
            }
        });
        Self {
            origin,
            requests,
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

pub(super) fn path(request: &str) -> &str {
    request.split_whitespace().nth(1).unwrap_or("/")
}

pub(super) fn query(request: &str) -> Vec<(String, String)> {
    reqwest::Url::parse(&format!("http://fixture.invalid{}", path(request)))
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

pub(super) fn evaluate_arithmetic(value: &str) -> String {
    let re = regex::Regex::new(r"\{\{(\d+)\*(\d+)\}\}|\$\{(\d+)\*(\d+)\}").unwrap();
    re.replace_all(value, |c: &regex::Captures<'_>| {
        let left = c
            .get(1)
            .or_else(|| c.get(3))
            .unwrap()
            .as_str()
            .parse::<u64>()
            .unwrap();
        let right = c
            .get(2)
            .or_else(|| c.get(4))
            .unwrap()
            .as_str()
            .parse::<u64>()
            .unwrap();
        (left * right).to_string()
    })
    .into_owned()
}
