use motosan_sandbox_proxy::{ProxyConfig, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Minimal upstream that accepts a connection and echoes "ok".
async fn upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        if let Ok((mut s, _)) = l.accept().await {
            let _ = s.write_all(b"ok").await;
        }
    });
    (addr, h)
}

/// Send a CONNECT for `target` to the proxy; return the proxy's status line.
async fn connect_via(proxy: std::net::SocketAddr, target: &str) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn allowed_host_connects() {
    let (up, _h) = upstream().await;
    // Allow the loopback upstream by exact host (port stripped) = "127.0.0.1".
    let proxy = ProxyServer::start(ProxyConfig {
        allowlist: vec!["127.0.0.1".into()],
    })
    .await
    .unwrap();
    let status = connect_via(proxy.addr, &format!("127.0.0.1:{}", up.port())).await;
    assert!(status.contains("200"), "got: {status}");
}

#[tokio::test]
async fn denied_host_refused() {
    let (up, _h) = upstream().await;
    let proxy = ProxyServer::start(ProxyConfig {
        allowlist: vec!["example.com".into()],
    })
    .await
    .unwrap();
    let status = connect_via(proxy.addr, &format!("127.0.0.1:{}", up.port())).await;
    assert!(status.contains("403"), "got: {status}");
}

#[tokio::test]
async fn non_connect_method_405() {
    let proxy = ProxyServer::start(ProxyConfig {
        allowlist: vec!["*".into()],
    })
    .await
    .unwrap();
    let mut s = TcpStream::connect(proxy.addr).await.unwrap();
    s.write_all(b"GET http://example.com/ HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("405"));
}
