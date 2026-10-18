//! Browser egress boundary: validate URL and DNS before opening any destination.
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use url::Url;
use webrev_core::{Result, Scope, WebrevError};

use crate::policy::{RefusalLog, RefusalReason};

const HEADER_LIMIT: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);

pub(crate) struct ScopedEgressProxy {
    address: SocketAddr,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    refused: Arc<Mutex<RefusalLog>>,
}

impl ScopedEgressProxy {
    pub async fn start(scope: Scope, upstream: Option<&str>) -> Result<Self> {
        let upstream = upstream.map(parse_upstream).transpose()?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let refused = Arc::new(Mutex::new(RefusalLog::default()));
        let task = tokio::spawn(listen(
            listener,
            scope,
            upstream,
            cancel.clone(),
            Arc::clone(&refused),
        ));
        Ok(Self {
            address,
            cancel,
            task,
            refused,
        })
    }

    #[cfg(test)]
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.address)
    }
    pub fn take_refusals(&self) -> RefusalLog {
        self.refused
            .lock()
            .map(|mut log| std::mem::take(&mut *log))
            .unwrap_or_default()
    }
}

impl Drop for ScopedEgressProxy {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid proxy request")
}

fn parse_upstream(text: &str) -> Result<Url> {
    let url = Url::parse(text).map_err(|_| {
        WebrevError::Config("browser upstream proxy must be an HTTP URL without credentials".into())
    })?;
    if url.scheme() != "http"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(WebrevError::Config(
            "browser upstream proxy must be an HTTP URL without credentials".into(),
        ));
    }
    Ok(url)
}

async fn listen(
    listener: TcpListener,
    scope: Scope,
    upstream: Option<Url>,
    cancel: CancellationToken,
    refused: Arc<Mutex<RefusalLog>>,
) {
    let limit = Arc::new(Semaphore::new(64));
    let scope = Arc::new(scope);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((client, _)) = accepted else { break };
                let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else { continue };
                let scope = Arc::clone(&scope);
                let refused = Arc::clone(&refused);
                let upstream = upstream.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let _ = timeout(CONNECTION_TIMEOUT, serve(client, &scope, upstream.as_ref(), &refused)).await;
                });
            }
        }
    }
    // Dropping JoinSet aborts children, closing all destination/client sockets.
}

struct Request {
    method: String,
    url: Url,
    headers: Vec<(String, String)>,
    extra: Vec<u8>,
    tunnel: bool,
    body_len: u64,
}

async fn read_head(client: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut bytes = Vec::new();
    loop {
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            if end + 4 > HEADER_LIMIT {
                return Err(invalid());
            }
            let extra = bytes.split_off(end + 4);
            return Ok((bytes, extra));
        }
        if bytes.len() >= HEADER_LIMIT {
            return Err(invalid());
        }
        let mut chunk = [0u8; 4096];
        let count = client.read(&mut chunk).await?;
        if count == 0 {
            return Err(invalid());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn parse_request(head: &[u8], extra: Vec<u8>) -> io::Result<Request> {
    let text = std::str::from_utf8(head).map_err(|_| invalid())?;
    let mut lines = text
        .strip_suffix("\r\n\r\n")
        .ok_or_else(invalid)?
        .split("\r\n");
    let mut parts = lines.next().ok_or_else(invalid)?.split(' ');
    let method = parts.next().ok_or_else(invalid)?;
    let target = parts.next().ok_or_else(invalid)?;
    let version = parts.next().ok_or_else(invalid)?;
    if !token(method)
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || parts.next().is_some()
        || target.bytes().any(|b| b <= b' ' || b == 127 || b == b'\\')
    {
        return Err(invalid());
    }
    let connect = method == "CONNECT";
    if connect
        && (target.contains(['/', '?', '#', '@'])
            || !target
                .rsplit_once(':')
                .is_some_and(|(_, port)| port.parse::<u16>().is_ok_and(|p| p != 0)))
    {
        return Err(invalid());
    }
    let mut url = Url::parse(&if connect {
        format!("https://{target}/")
    } else {
        target.to_owned()
    })
    .map_err(|_| invalid())?;
    normalize_host(&mut url)?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (!connect && !matches!(url.scheme(), "http" | "ws"))
    {
        return Err(invalid());
    }
    let mut headers = Vec::new();
    let mut host = None;
    let mut body_len = None;
    let mut upgrade = false;
    let mut upgrade_connection = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        if !token(name) || value.bytes().any(|b| (b < 32 && b != b'\t') || b == 127) {
            return Err(invalid());
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim().to_owned();
        match name.as_str() {
            "host" => {
                if host.replace(value.clone()).is_some() {
                    return Err(invalid());
                }
            }
            "transfer-encoding" => return Err(invalid()),
            "content-length" => {
                if body_len.is_some() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                body_len = Some(value.parse::<u64>().map_err(|_| invalid())?);
            }
            "upgrade" => {
                if value != "websocket" || upgrade {
                    return Err(invalid());
                }
                upgrade = true;
            }
            "connection" => {
                upgrade_connection |= value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"));
            }
            _ => {}
        }
        headers.push((name, value));
    }
    let host = host.ok_or_else(invalid)?;
    if host.contains(['/', '?', '#', '@', '\\']) {
        return Err(invalid());
    }
    let mut host_url = Url::parse(&format!("{}://{host}/", url.scheme())).map_err(|_| invalid())?;
    normalize_host(&mut host_url)?;
    if host_url.host_str() != url.host_str()
        || host_url.port_or_known_default() != url.port_or_known_default()
    {
        return Err(invalid());
    }
    if upgrade != upgrade_connection || ((connect || upgrade) && body_len.unwrap_or(0) != 0) {
        return Err(invalid());
    }
    if !connect
        && !upgrade
        && u64::try_from(extra.len()).unwrap_or(u64::MAX) > body_len.unwrap_or(0)
    {
        return Err(invalid());
    }
    Ok(Request {
        method: method.to_owned(),
        url,
        headers,
        extra,
        tunnel: connect || upgrade,
        body_len: body_len.unwrap_or(0),
    })
}

/// Canonical host form so scope rules see one spelling per destination:
/// a trailing dot (`example.test.`) is dropped, and an IPv4-mapped IPv6
/// literal (`[::ffff:127.0.0.1]`, which Linux connects to IPv4 loopback) is
/// rewritten to its IPv4 form. Without this, hostname/CIDR exclusions written
/// for `example.test` or `127.0.0.0/8` would not match those spellings.
fn normalize_host(url: &mut Url) -> io::Result<()> {
    match url.host() {
        Some(url::Host::Domain(name)) => {
            let trimmed = name.trim_end_matches('.');
            if trimmed.is_empty() {
                return Err(invalid());
            }
            if trimmed.len() != name.len() {
                let trimmed = trimmed.to_owned();
                url.set_host(Some(&trimmed)).map_err(|_| invalid())?;
            }
        }
        Some(url::Host::Ipv6(address)) => {
            let canonical = address.to_canonical();
            if canonical != std::net::IpAddr::V6(address) {
                url.set_ip_host(canonical).map_err(|()| invalid())?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn host(url: &Url) -> io::Result<&str> {
    Ok(url.host_str().ok_or_else(invalid)?.trim_matches(['[', ']']))
}

fn is_invalid_name(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    name.eq_ignore_ascii_case("invalid")
        || name
            .len()
            .checked_sub(".invalid".len())
            .and_then(|start| name.get(start..))
            .is_some_and(|tail| tail.eq_ignore_ascii_case(".invalid"))
}

async fn destination(scope: &Scope, url: &Url) -> io::Result<SocketAddr> {
    let name = host(url)?;
    let port = url.port_or_known_default().ok_or_else(invalid)?;
    // RFC 6761: `.invalid` never resolves. Answer locally instead of asking the
    // system resolver, whose latency is outside our control (a slow resolver
    // can outlast the client's patience) and which would leak the name.
    if is_invalid_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "reserved .invalid name",
        ));
    }
    let addresses = lookup_host((name, port)).await?;
    addresses
        .into_iter()
        .map(|address| SocketAddr::new(address.ip().to_canonical(), address.port()))
        .find(|address| scope.allows_resolved_ip(name, address.ip()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "destination refused"))
}

async fn connect_upstream(upstream: &Url) -> io::Result<TcpStream> {
    TcpStream::connect((
        host(upstream)?,
        upstream.port_or_known_default().ok_or_else(invalid)?,
    ))
    .await
}

fn request_head(request: &Request) -> String {
    let mut target = request.url.path().to_owned();
    if let Some(query) = request.url.query() {
        target.push('?');
        target.push_str(query);
    }
    let mut head = format!("{} {target} HTTP/1.1\r\n", request.method);
    for (name, value) in &request.headers {
        if !matches!(
            name.as_str(),
            "connection" | "proxy-connection" | "proxy-authorization"
        ) {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
    }
    head.push_str(if request.tunnel {
        "connection: Upgrade\r\n\r\n"
    } else {
        "connection: close\r\n\r\n"
    });
    head
}

async fn establish(
    client: &mut TcpStream,
    request: &Request,
    scope: &Scope,
    upstream: Option<&Url>,
) -> io::Result<TcpStream> {
    let pinned = destination(scope, &request.url).await?;
    let mut remote = if let Some(proxy) = upstream {
        connect_upstream(proxy).await?
    } else {
        TcpStream::connect(pinned).await?
    };
    let mut early_remote = Vec::new();
    if upstream.is_some() {
        // Always tunnel to the locally validated IP. Forward-proxy absolute URI
        // rewriting could replace the original Host and break virtual hosting.
        remote
            .write_all(format!("CONNECT {pinned} HTTP/1.1\r\nhost: {pinned}\r\n\r\n").as_bytes())
            .await?;
        let (response, extra) = read_head(&mut remote).await?;
        let status = std::str::from_utf8(&response)
            .map_err(|_| invalid())?
            .split_whitespace()
            .nth(1);
        if status != Some("200") {
            return Err(io::Error::other("upstream CONNECT refused"));
        }
        early_remote = extra;
    }
    if request.method == "CONNECT" {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.write_all(&early_remote).await?;
    } else {
        if !early_remote.is_empty() {
            return Err(invalid());
        }
        remote.write_all(request_head(request).as_bytes()).await?;
    }
    remote.write_all(&request.extra).await?;
    Ok(remote)
}

async fn serve(
    mut client: TcpStream,
    scope: &Scope,
    upstream: Option<&Url>,
    refused: &Mutex<RefusalLog>,
) -> io::Result<()> {
    let request = match timeout(HANDSHAKE_TIMEOUT, read_head(&mut client)).await {
        Ok(Ok((head, extra))) => parse_request(&head, extra),
        _ => Err(invalid()),
    };
    let Ok(request) = request else {
        client
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        return Ok(());
    };
    if !scope.allows(request.url.as_str()) {
        if let Ok(mut log) = refused.lock() {
            log.record(
                request.url.as_str(),
                &request.method,
                RefusalReason::OutOfScope,
            );
        }
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    let remote = timeout(
        HANDSHAKE_TIMEOUT,
        establish(&mut client, &request, scope, upstream),
    )
    .await;
    let mut remote = match remote {
        Ok(Ok(remote)) => remote,
        other => {
            let denied =
                matches!(&other, Ok(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied);
            if denied {
                if let Ok(mut log) = refused.lock() {
                    log.record(
                        request.url.as_str(),
                        &request.method,
                        RefusalReason::OutOfScope,
                    );
                }
            }
            let response: &[u8] = if denied {
                b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            } else {
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            };
            client.write_all(response).await?;
            return Ok(());
        }
    };
    if request.tunnel {
        tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    } else {
        let remaining =
            request.body_len - u64::try_from(request.extra.len()).map_err(|_| invalid())?;
        let (client_read, mut client_write) = client.split();
        let (mut remote_read, mut remote_write) = remote.split();
        let upload = async {
            tokio::io::copy(&mut client_read.take(remaining), &mut remote_write).await?;
            remote_write.shutdown().await
        };
        let download = tokio::io::copy(&mut remote_read, &mut client_write);
        tokio::try_join!(upload, download)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "egress_proxy_tests.rs"]
mod tests;
