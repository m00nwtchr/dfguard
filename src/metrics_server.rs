use anyhow::{Context, Result};
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

pub async fn start_metrics_server(
    metrics_listen: &str,
    readiness: std::sync::Arc<AtomicBool>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(metrics_listen)
        .await
        .with_context(|| format!("bind metrics listen address {metrics_listen}"))?;
    info!("probe endpoint listening on {metrics_listen}");

    loop {
        let (mut socket, _) = listener.accept().await?;
        let readiness = readiness.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_metrics_connection(&mut socket, readiness).await {
                debug!("metrics connection error: {err:#}");
            }
        });
    }
}

async fn handle_metrics_connection(
    socket: &mut TcpStream,
    readiness: std::sync::Arc<AtomicBool>,
) -> Result<()> {
    let mut buf = [0u8; 2048];
    let n = socket.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    match path {
        "/healthz" => write_http_response(socket, 200, "text/plain", "ok").await,
        "/livez" => write_http_response(socket, 200, "text/plain", "alive").await,
        "/readyz" => {
            if readiness.load(std::sync::atomic::Ordering::Relaxed) {
                write_http_response(socket, 200, "text/plain", "ready").await
            } else {
                write_http_response(socket, 503, "text/plain", "not ready").await
            }
        }
        _ => write_http_response(socket, 404, "text/plain", "not found").await,
    }
}

async fn write_http_response(
    socket: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<()> {
    write_http_response_bytes(socket, status, content_type, body.as_bytes()).await
}

async fn write_http_response_bytes(
    socket: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let status_text = match status {
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "OK",
    };
    let mut response = Vec::with_capacity(body.len() + 128);
    response.extend_from_slice(
        format!(
            "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    response.extend_from_slice(body);
    socket.write_all(&response).await?;
    Ok(())
}
