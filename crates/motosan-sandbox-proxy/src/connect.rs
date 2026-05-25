//! CONNECT parsing + tunneling (stub — real implementation lands in Task 5).

pub async fn handle_conn(
    _stream: tokio::net::TcpStream,
    _allow: &crate::matcher::Allowlist,
) -> std::io::Result<()> {
    Ok(())
}
