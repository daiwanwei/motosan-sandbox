//! Local allowlist HTTP CONNECT proxy. Leaf crate — no dependency on
//! `motosan-sandbox` (avoids a circular dep with core's `proxy` feature). Takes
//! the allowlist as pattern strings and matches them internally.

mod connect;
mod matcher;

use std::net::SocketAddr;

/// Configuration for [`ProxyServer::start`].
pub struct ProxyConfig {
    /// Pattern strings: `"example.com"`, `"*.x.com"`, `"**.x.com"`, `"*"`.
    pub allowlist: Vec<String>,
}

/// RAII handle for a running proxy. `Drop` aborts the serving task (the cleanup
/// guarantee for every exit path); [`ProxyServerHandle::shutdown`] is the
/// graceful path.
pub struct ProxyServerHandle {
    pub addr: SocketAddr,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyServerHandle {
    /// Graceful shutdown — abort the serving task and await its termination.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for ProxyServerHandle {
    fn drop(&mut self) {
        // Cleanup guarantee on every exit path (including `?` early returns
        // in callers): synchronously abort the serving task.
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

/// The proxy itself. Use [`ProxyServer::start`] to bind a loopback listener
/// and begin serving.
pub struct ProxyServer;

impl ProxyServer {
    /// Bind a loopback listener and start serving. Returns once bound.
    pub async fn start(config: ProxyConfig) -> std::io::Result<ProxyServerHandle> {
        let allow = std::sync::Arc::new(matcher::Allowlist::parse(&config.allowlist));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let allow = allow.clone();
                        tokio::spawn(async move {
                            if let Err(e) = connect::handle_conn(stream, &allow).await {
                                tracing::debug!("proxy conn ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("accept failed: {e}");
                        break;
                    }
                }
            }
        });
        Ok(ProxyServerHandle {
            addr,
            task: Some(task),
        })
    }
}
