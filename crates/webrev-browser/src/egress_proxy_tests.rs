use super::{parse_request, parse_upstream, read_head, ScopedEgressProxy};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use webrev_core::Scope;

/// Linux routes all of 127.0.0.0/8 to loopback; macOS and others only 127.0.0.1.
fn loopback_alias_available() -> bool {
    std::net::TcpListener::bind(("127.0.0.2", 0)).is_ok()
}

macro_rules! require_loopback_alias {
    () => {
        if !loopback_alias_available() {
            eprintln!("skipped: 127.0.0.2 is not bindable on this platform");
            return;
        }
    };
}

async fn listener(host: &str) -> TcpListener {
    TcpListener::bind((host, 0)).await.unwrap()
}
fn scope() -> Scope {
    Scope::new(vec!["127.0.0.1".into()], vec![])
}
async fn exchange(proxy: SocketAddr, request: &str) -> Vec<u8> {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    // Generous on purpose: this bounds a loopback round-trip, not a network
    // call, but under heavy concurrent CPU load (e.g. a `cargo build` running
    // in parallel) the test's own tokio runtime can be starved for longer
    // than a tight bound would tolerate, failing the test with no real bug.
    timeout(Duration::from_secs(10), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

#[test]
fn upstream_proxy_url_rejects_embedded_credentials() {
    // A proxy URL configured as `http://user:pass@host:port/` would leak the
    // credential into logs, process args and config files wherever the
    // upstream string is handled; `parse_upstream` must refuse it outright
    // rather than silently stripping or forwarding it.
    for url in [
        "http://user:pass@proxy.example:8080/",
        "http://user@proxy.example:8080/",
        "http://:pass@proxy.example:8080/",
    ] {
        assert!(parse_upstream(url).is_err(), "{url} must be rejected");
    }
}

#[test]
fn upstream_proxy_url_accepts_a_plain_http_host() {
    assert!(parse_upstream("http://proxy.example:8080/").is_ok());
}

#[tokio::test]
async fn authorized_http_preserves_body_auth_and_host() {
    let target = listener("127.0.0.1").await;
    let address = target.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        let text = String::from_utf8(received).unwrap();
        assert!(text.starts_with("POST /upload?q=1 HTTP/1.1\r\n"));
        assert!(text.contains(&format!("host: {address}\r\n")));
        assert!(text.contains("authorization: Bearer synthetic-test\r\n"));
        assert!(text.contains("connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\npayload"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let proxy = ScopedEgressProxy::start(scope(), None).await.unwrap();
    let response = exchange(proxy.address(), &format!("POST http://{address}/upload?q=1 HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer synthetic-test\r\nContent-Length: 7\r\n\r\npayload")).await;
    assert!(response.ends_with(b"ok"));
    server.await.unwrap();
}

#[tokio::test]
async fn refused_http_upgrade_and_connect_never_reach_destination() {
    require_loopback_alias!();
    let target = listener("127.0.0.2").await;
    let address = target.local_addr().unwrap();
    let proxy = ScopedEgressProxy::start(scope(), None).await.unwrap();
    for request in [
        format!("GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\n\r\n"),
        format!("GET ws://{address}/ HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
        format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n"),
    ] {
        assert!(exchange(proxy.address(), &request).await.starts_with(b"HTTP/1.1 403"));
    }
    assert!(timeout(Duration::from_millis(150), target.accept())
        .await
        .is_err());
    let log = proxy.take_refusals();
    assert_eq!(log.count, 3);
    assert_eq!(log.requests.len(), 3);
    assert_eq!(proxy.take_refusals().count, 0);
}

#[tokio::test]
async fn authorized_upgrade_and_connect_relay_early_bytes_and_later_bytes() {
    for connect in [false, true] {
        let target = listener("127.0.0.1").await;
        let address = target.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut bytes = [0u8; 4];
            if connect {
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"ping");
            } else {
                let (head, extra) = read_head(&mut stream).await.unwrap();
                assert!(head.starts_with(b"GET /socket HTTP/1.1\r\n"));
                assert_eq!(extra, b"ping");
                stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").await.unwrap();
            }
            stream.write_all(b"pong").await.unwrap();
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"more");
            stream.write_all(b"done").await.unwrap();
        });
        let proxy = ScopedEgressProxy::start(scope(), None).await.unwrap();
        let mut client = TcpStream::connect(proxy.address()).await.unwrap();
        let request = if connect {
            format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\nping")
        } else {
            format!("GET ws://{address}/socket HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nping")
        };
        client.write_all(request.as_bytes()).await.unwrap();
        let (head, mut extra) = read_head(&mut client).await.unwrap();
        assert!(head.starts_with(if connect {
            b"HTTP/1.1 200"
        } else {
            b"HTTP/1.1 101"
        }));
        while extra.len() < 4 {
            extra.push(client.read_u8().await.unwrap());
        }
        assert_eq!(&extra, b"pong");
        client.write_all(b"more").await.unwrap();
        let mut bytes = [0u8; 4];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"done");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn dns_exclusion_refuses_before_destination_connect() {
    let target = listener("127.0.0.1").await;
    let port = target.local_addr().unwrap().port();
    let proxy = ScopedEgressProxy::start(
        Scope::new(
            vec!["localhost".into()],
            vec!["127.0.0.0/8".into(), "::1/128".into()],
        ),
        None,
    )
    .await
    .unwrap();
    assert!(exchange(
        proxy.address(),
        &format!("GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
    )
    .await
    .starts_with(b"HTTP/1.1 403"));
    assert!(timeout(Duration::from_millis(150), target.accept())
        .await
        .is_err());
    assert_eq!(proxy.take_refusals().count, 1);
}

#[tokio::test]
async fn unsupported_upstream_is_configuration_error() {
    for upstream in [
        "socks5://127.0.0.1:1",
        "http://user:pass@127.0.0.1:1",
        "https://127.0.0.1:1",
        "http://127.0.0.1/a",
    ] {
        assert!(ScopedEgressProxy::start(scope(), Some(upstream))
            .await
            .is_err());
    }
}

#[test]
fn ambiguous_host_framing_and_connect_authority_are_rejected() {
    for request in [
        "GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.2\r\n\r\n",
        "GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: 127.0.0.1\r\n\r\n",
        "GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        "CONNECT user@127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n",
        "CONNECT 127.0.0.1:443/path HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n",
        "GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n folded: bad\r\n\r\n",
    ] { assert!(parse_request(request.as_bytes(), vec![]).is_err(), "{request}"); }
}

#[tokio::test]
async fn upstream_tunnels_to_pinned_ip_and_preserves_virtual_host() {
    let upstream = listener("127.0.0.1").await;
    let upstream_address = upstream.local_addr().unwrap();
    let relay = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let (connect, extra) = read_head(&mut stream).await.unwrap();
        assert!(String::from_utf8(connect)
            .unwrap()
            .starts_with("CONNECT 127.0.0.1:12345 HTTP/1.1\r\n"));
        assert!(extra.is_empty());
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        let request = String::from_utf8(received).unwrap();
        assert!(request.starts_with("GET /vhost HTTP/1.1\r\n"));
        assert!(request.contains("host: 127.0.0.1:12345\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let proxy = ScopedEgressProxy::start(scope(), Some(&format!("http://{upstream_address}")))
        .await
        .unwrap();
    assert!(exchange(
        proxy.address(),
        "GET http://127.0.0.1:12345/vhost HTTP/1.1\r\nHost: 127.0.0.1:12345\r\n\r\n"
    )
    .await
    .ends_with(b"ok"));
    relay.await.unwrap();
}

#[tokio::test]
async fn dropping_proxy_closes_active_tunnel() {
    let target = listener("127.0.0.1").await;
    let address = target.local_addr().unwrap();
    let proxy = ScopedEgressProxy::start(scope(), None).await.unwrap();
    let mut client = TcpStream::connect(proxy.address()).await.unwrap();
    client
        .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let (mut destination, _) = target.accept().await.unwrap();
    read_head(&mut client).await.unwrap();
    drop(proxy);
    assert_eq!(
        timeout(Duration::from_secs(1), destination.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

fn get(authority: &str) -> String {
    format!("GET http://{authority}/ HTTP/1.1\r\nHost: {authority}\r\n\r\n")
}
async fn silent(target: &TcpListener) -> bool {
    timeout(Duration::from_millis(150), target.accept())
        .await
        .is_err()
}

#[tokio::test]
async fn ip_spellings_cannot_bypass_address_exclusion() {
    require_loopback_alias!();
    // Decimal, hex, octal, short and IPv4-mapped forms of an excluded loopback IP.
    let target = listener("127.0.0.2").await;
    let port = target.local_addr().unwrap().port();
    let scope = Scope::new(vec!["127.0.0.0/8".into()], vec!["127.0.0.2".into()]);
    let proxy = ScopedEgressProxy::start(scope, None).await.unwrap();
    for host in [
        "127.0.0.2",
        "2130706434",
        "0x7f000002",
        "0177.0.0.2",
        "127.2",
        "[::ffff:127.0.0.2]",
        "[::ffff:7f00:2]",
    ] {
        let response = exchange(proxy.address(), &get(&format!("{host}:{port}"))).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403") || response.starts_with(b"HTTP/1.1 400"),
            "{host}: {}",
            String::from_utf8_lossy(&response)
        );
    }
    assert!(silent(&target).await);
}

#[tokio::test]
async fn trailing_dot_and_case_cannot_bypass_hostname_exclusion() {
    let target = listener("127.0.0.1").await;
    let port = target.local_addr().unwrap().port();
    // CIDR include lets hostnames reach DNS validation; the hostname exclusion
    // must still match every spelling of the name.
    let scope = Scope::new(vec!["127.0.0.0/8".into()], vec!["localhost".into()]);
    let proxy = ScopedEgressProxy::start(scope, None).await.unwrap();
    for host in [
        "localhost",
        "LOCALHOST",
        "localhost.",
        "LocalHost.",
        "localhost..",
    ] {
        let response = exchange(proxy.address(), &get(&format!("{host}:{port}"))).await;
        assert!(
            !response.is_empty() && !response.starts_with(b"HTTP/1.1 200"),
            "{host}"
        );
        assert!(
            response.starts_with(b"HTTP/1.1 403") || response.starts_with(b"HTTP/1.1 400"),
            "{host}: {}",
            String::from_utf8_lossy(&response)
        );
    }
    assert!(silent(&target).await);
}

#[tokio::test]
async fn userinfo_and_authority_tricks_are_rejected() {
    require_loopback_alias!();
    let target = listener("127.0.0.2").await;
    let port = target.local_addr().unwrap().port();
    let proxy = ScopedEgressProxy::start(scope(), None).await.unwrap();
    for request in [
        format!(
            "GET http://127.0.0.1@127.0.0.2:{port}/ HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n"
        ),
        format!(
            "GET http://127.0.0.1:80@127.0.0.2:{port}/ HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n"
        ),
        format!("GET http://127.0.0.1%40@127.0.0.2:{port}/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        format!("GET http://127.0.0.1\\@127.0.0.2:{port}/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        // Host header disagreeing with the absolute URI (scope sees the URI).
        format!("GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n"),
        format!("GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1@127.0.0.2:{port}\r\n\r\n"),
        format!("CONNECT 127.0.0.1:80@127.0.0.2:{port} HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n"),
    ] {
        let response = exchange(proxy.address(), &request).await;
        assert!(response.starts_with(b"HTTP/1.1 400"), "{request}");
    }
    assert!(silent(&target).await);
}

#[test]
fn host_spellings_normalize_to_one_canonical_form() {
    for (authority, expected) in [
        ("EXAMPLE.test.:80", "example.test"),
        ("example.test..:80", "example.test"),
        ("2130706433:80", "127.0.0.1"),
        ("0x7f.1:80", "127.0.0.1"),
        ("[::ffff:127.0.0.1]:80", "127.0.0.1"),
        ("[::1]:80", "[::1]"),
    ] {
        let request = format!("GET http://{authority}/ HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        let parsed = parse_request(request.as_bytes(), vec![]).unwrap();
        assert_eq!(parsed.url.host_str(), Some(expected), "{authority}");
    }
    assert!(parse_request(b"CONNECT .:443 HTTP/1.1\r\nHost: .:443\r\n\r\n", vec![]).is_err());
}

#[tokio::test]
async fn ipv6_literal_connect_is_scoped_and_relayed() {
    let Ok(target) = TcpListener::bind(("::1", 0)).await else {
        return; // host without IPv6 loopback
    };
    let port = target.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        stream.write_all(b"v6").await.unwrap();
    });
    let proxy = ScopedEgressProxy::start(Scope::new(vec!["::1".into()], vec![]), None)
        .await
        .unwrap();
    let mut client = TcpStream::connect(proxy.address()).await.unwrap();
    client
        .write_all(
            format!("CONNECT [::1]:{port} HTTP/1.1\r\nHost: [::1]:{port}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let (head, mut extra) = read_head(&mut client).await.unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"));
    while extra.len() < 2 {
        extra.push(client.read_u8().await.unwrap());
    }
    assert_eq!(&extra, b"v6");
    server.await.unwrap();
}

#[tokio::test]
async fn redirects_are_not_followed_and_next_hop_is_rechecked() {
    require_loopback_alias!();
    let allowed = listener("127.0.0.1").await;
    let forbidden = listener("127.0.0.2").await;
    let port = allowed.local_addr().unwrap().port();
    let location = format!("http://{}/secret", forbidden.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = allowed.accept().await.unwrap();
        let _ = read_head(&mut stream).await.unwrap();
        stream
            .write_all(
                format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        location
    });
    let proxy = ScopedEgressProxy::start(scope(), None).await.unwrap();
    let first = exchange(proxy.address(), &get(&format!("127.0.0.1:{port}"))).await;
    assert!(first.starts_with(b"HTTP/1.1 302"));
    let location = server.await.unwrap();
    let authority = location
        .trim_start_matches("http://")
        .trim_end_matches("/secret");
    // The browser re-issues the redirect through the proxy: scope applies again.
    assert!(exchange(proxy.address(), &get(authority))
        .await
        .starts_with(b"HTTP/1.1 403"));
    assert!(silent(&forbidden).await);
}

#[tokio::test]
async fn upstream_is_never_contacted_for_refused_or_unresolvable_destinations() {
    let upstream = listener("127.0.0.1").await;
    let upstream_url = format!("http://{}", upstream.local_addr().unwrap());
    // Name-only scope: the proxy resolves locally first, so a name only the
    // upstream could resolve (reserved .invalid TLD) fails closed with 502
    // instead of being delegated to the upstream.
    let proxy = ScopedEgressProxy::start(
        Scope::new(
            vec!["hidden.invalid".into(), "127.0.0.0/8".into()],
            vec!["127.0.0.9".into()],
        ),
        Some(&upstream_url),
    )
    .await
    .unwrap();
    // `.invalid` is answered locally (RFC 6761), so this never waits on the
    // host resolver and stays well inside `exchange`'s read timeout.
    let started = std::time::Instant::now();
    let unresolved = exchange(proxy.address(), &get("hidden.invalid:80")).await;
    assert!(unresolved.starts_with(b"HTTP/1.1 502"));
    assert!(started.elapsed() < Duration::from_secs(1));
    for request in [
        get("127.0.0.9:80"),
        get("203.0.113.5:80"),
        "CONNECT 127.0.0.9:443 HTTP/1.1\r\nHost: 127.0.0.9:443\r\n\r\n".to_owned(),
        "CONNECT hidden.invalid:443 HTTP/1.1\r\nHost: hidden.invalid:443\r\n\r\n".to_owned(),
    ] {
        let response = exchange(proxy.address(), &request).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403") || response.starts_with(b"HTTP/1.1 502"),
            "{request}"
        );
    }
    assert!(silent(&upstream).await);
}

#[test]
fn invalid_names_are_recognised_only_as_a_whole_label() {
    use super::is_invalid_name;
    for name in [
        "invalid",
        "hidden.invalid",
        "A.B.INVALID",
        "hidden.invalid.",
    ] {
        assert!(is_invalid_name(name), "{name}");
    }
    for name in [
        "notinvalid",
        "invalid.example",
        "hidden.invalid.example",
        "127.0.0.1",
        "",
    ] {
        assert!(!is_invalid_name(name), "{name}");
    }
}

#[tokio::test]
async fn upstream_connect_receives_ip_never_the_hostname() {
    let upstream = listener("127.0.0.1").await;
    let upstream_url = format!("http://{}", upstream.local_addr().unwrap());
    let relay = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let (connect, _) = read_head(&mut stream).await.unwrap();
        let connect = String::from_utf8(connect).unwrap();
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await
            .unwrap();
        connect
    });
    let proxy = ScopedEgressProxy::start(
        Scope::new(vec!["localhost".into()], vec!["::1".into()]),
        Some(&upstream_url),
    )
    .await
    .unwrap();
    // Upstream refusal is surfaced as 502 and the tunnel is not established.
    let response = exchange(
        proxy.address(),
        "CONNECT localhost:8443 HTTP/1.1\r\nHost: localhost:8443\r\n\r\n",
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 502"));
    let connect = relay.await.unwrap();
    assert!(
        connect.starts_with("CONNECT 127.0.0.1:8443 HTTP/1.1\r\n"),
        "{connect}"
    );
    assert!(!connect.contains("localhost"));
}
