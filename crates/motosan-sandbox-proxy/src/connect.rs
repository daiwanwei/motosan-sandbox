//! CONNECT-only HTTP proxy connection handling. Plain-HTTP (forward) is NOT
//! proxied in Phase 2 — non-CONNECT methods get 405.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::matcher::Allowlist;

pub async fn handle_conn(mut client: TcpStream, allow: &Allowlist) -> std::io::Result<()> {
    // Read the request line + headers (until CRLFCRLF). Cap to avoid abuse.
    // `header_end` = index just past the blank line; bytes after it are payload
    // the client pipelined (e.g. an early TLS ClientHello) and must be forwarded.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Ok(()); // client closed
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 16 * 1024 {
            break buf.len();
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]);
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or(""); // "host:port" for CONNECT

    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = client
            .write_all(
                b"HTTP/1.1 405 Method Not Allowed\r\n\r\nplain HTTP not proxied in this phase\r\n",
            )
            .await;
        return Ok(());
    }

    // `allows` normalizes (strips the port) internally, so pass the full target.
    if !allow.allows(target) {
        tracing::info!(%target, "proxy DENY");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        return Ok(());
    }
    tracing::info!(%target, "proxy ALLOW");

    // Connect upstream (the proxy — in the unsandboxed parent — resolves DNS).
    let mut upstream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Err(e);
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    // Forward any bytes the client pipelined after the CONNECT headers (rare —
    // most clients wait for the 200 — but correct).
    if header_end < buf.len() {
        upstream.write_all(&buf[header_end..]).await?;
    }
    // Blind-tunnel both directions (no MITM). TLS bytes flow opaquely.
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}
