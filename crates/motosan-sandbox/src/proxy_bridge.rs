//! Host side of the netns proxy bridge (spec §7: runs in the unsandboxed tokio
//! parent, before unshare). For each proxy env var we want the in-netns target
//! to honor, we create one UDS in a temp dir and spawn a tokio accept loop:
//! `UnixListener(uds) → TcpStream::connect(proxy)`. The `ProxyRouteSpec` we
//! hand back is the IPC payload that travels in `MOTOSAN_SANDBOX_POLICY` to
//! the inner stage, which binds a per-route loopback TCP listener and forwards
//! each accepted client through `UnixStream::connect(uds_path)` — the only
//! exit from the empty netns.
//!
//! Synchronization model: tokio (parent only). The forked in-netns bridge is
//! sync std (`linux_bridge.rs`) — fork + tokio is unsafe.
//!
//! Lifecycle: `HostBridgeGuard` is RAII — its `Drop` aborts every accept loop
//! and removes the UDS temp dir, on every exit path (success, `?`, panic).

#![cfg(feature = "proxy")]
#![allow(dead_code)] // wired by Task 7 (run() Linux Proxied integration)

use std::net::SocketAddr;

use crate::reexec::{ProxyRouteEntry, ProxyRouteSpec};

/// Default proxy env vars we route through the bridge. Mirrors the macOS
/// `inject_proxy_env` set so cooperative tools see the same wiring on both
/// platforms (`NO_PROXY` is NOT routed — it's just a hint to the client).
pub(crate) const ROUTED_PROXY_ENV_KEYS: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"];

/// For each proxy env var, create a UDS and a tokio accept loop forwarding
/// UDS↔proxy. Returns the `ProxyRouteSpec` (carried in the helper IPC) plus
/// the RAII guard that tears the bridges + temp dir down on drop.
pub(crate) async fn prepare_host_bridge(
    proxy_addr: SocketAddr,
    env_keys: &[&str],
) -> std::io::Result<(ProxyRouteSpec, HostBridgeGuard)> {
    let dir = tempfile::tempdir()?;
    let mut routes = Vec::with_capacity(env_keys.len());
    let mut tasks = Vec::with_capacity(env_keys.len());
    for (i, key) in env_keys.iter().enumerate() {
        let uds_path = dir.path().join(format!("route-{i}.sock"));
        let listener = tokio::net::UnixListener::bind(&uds_path)?;
        let task = tokio::spawn(async move {
            // Accept loop: one TCP connection per accepted UDS connection.
            // `copy_bidirectional` returns when either half closes; the
            // per-accept task ends and the loop continues.
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    match tokio::net::TcpStream::connect(proxy_addr).await {
                        Ok(mut up) => {
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
                        }
                        Err(_) => {
                            // Proxy unreachable (e.g. it crashed). Drop the
                            // client; the in-netns target gets a closed conn.
                        }
                    }
                });
            }
        });
        tasks.push(task);
        routes.push(ProxyRouteEntry {
            env_key: (*key).to_string(),
            uds_path,
        });
    }
    Ok((ProxyRouteSpec { routes }, HostBridgeGuard { _dir: dir, tasks }))
}

/// RAII guard: aborts every accept loop and removes the UDS temp dir on Drop.
/// Held by `Sandbox::run()` for the full lifetime of the run, so cancellation
/// / `?` / panic all tear the bridge down (just like `ProxyGuard`).
pub(crate) struct HostBridgeGuard {
    // `tempfile::TempDir` removes the dir + the UDS files inside on Drop.
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for HostBridgeGuard {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UnixStream};

    /// End-to-end byte test: a fake "proxy" listens on 127.0.0.1, the host
    /// bridge accepts UDS clients and forwards to it. Asserts the bytes the
    /// UDS client writes show up at the fake proxy, and vice versa.
    #[tokio::test]
    async fn host_bridge_forwards_uds_to_tcp() {
        // 1. fake proxy: echo every byte once.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut conn, _)) = proxy.accept().await {
                let mut buf = [0u8; 32];
                if let Ok(n) = conn.read(&mut buf).await {
                    let _ = conn.write_all(&buf[..n]).await;
                }
            }
        });

        // 2. host bridge for one env key.
        let (spec, _guard) = prepare_host_bridge(proxy_addr, &["HTTP_PROXY"])
            .await
            .expect("prepare_host_bridge");
        assert_eq!(spec.routes.len(), 1);
        assert_eq!(spec.routes[0].env_key, "HTTP_PROXY");

        // 3. connect to the UDS as if we were the in-netns bridge.
        let mut client = UnixStream::connect(&spec.routes[0].uds_path)
            .await
            .expect("uds connect");
        client.write_all(b"PING").await.unwrap();
        let mut got = [0u8; 4];
        // small timeout so a regression doesn't hang the suite.
        let n = tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut got))
            .await
            .expect("read timed out")
            .expect("read");
        assert_eq!(n, 4);
        assert_eq!(&got, b"PING");
    }

    /// `Drop` aborts the accept tasks: after the guard is dropped, a fresh
    /// UDS connect attempt should fail (the listener is gone with the dir).
    #[tokio::test]
    async fn guard_drop_aborts_accept_loops_and_removes_dir() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let (spec, guard) = prepare_host_bridge(proxy_addr, &["HTTP_PROXY"])
            .await
            .unwrap();
        let uds_path = spec.routes[0].uds_path.clone();
        assert!(uds_path.exists(), "UDS should exist while guard is alive");

        drop(guard);

        // tempdir is removed synchronously on Drop; the UDS file goes with it.
        // (Give the runtime a tick in case anything was racing.)
        tokio::task::yield_now().await;
        assert!(
            !uds_path.exists(),
            "UDS path should be removed when guard drops"
        );
    }

    #[tokio::test]
    async fn prepare_host_bridge_routes_match_env_keys_in_order() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let keys = ROUTED_PROXY_ENV_KEYS;
        let (spec, _guard) = prepare_host_bridge(proxy_addr, keys).await.unwrap();
        let got: Vec<&str> = spec.routes.iter().map(|r| r.env_key.as_str()).collect();
        assert_eq!(got, keys.to_vec());
        // Each route has a unique UDS path.
        let mut paths: Vec<_> = spec.routes.iter().map(|r| r.uds_path.clone()).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), keys.len());
    }
}
