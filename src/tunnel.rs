use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, error, info};

use crate::cli::TunnelConfig;
use crate::telemetry::Telemetry;

pub async fn handle_tunnel_connection(
    downstream: TcpStream,
    upstream_addr: std::net::SocketAddr,
    server_name: rustls::pki_types::ServerName<'static>,
    client_config: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    tcp_nodelay: bool,
    telemetry: &Telemetry,
) -> Result<()> {
    info!(
        "handle_tunnel_connection CALLED: upstream_addr={:?}, server_name={:?}",
        upstream_addr, server_name
    );
    let tcp_started = tokio::time::Instant::now();
    let upstream_socket = tokio::time::timeout(connect_timeout, TcpStream::connect(upstream_addr))
        .instrument(tracing::info_span!("tunnel_upstream_tcp_connect"))
        .await;
    info!("tunnel TCP connect result: {:?}", upstream_socket);
    let upstream_socket = match upstream_socket {
        Ok(Ok(socket)) => socket,
        Ok(Err(e)) => {
            error!("tunnel TCP connect FAILED (direct): {}", e);
            telemetry.observe_upstream_tcp_connect_ms(tcp_started.elapsed(), "error");
            return Err(anyhow::Error::from(e)).context("tunnel upstream TCP connect failed");
        }
        Err(e) => {
            error!("tunnel TCP connect FAILED (timeout): {}", e);
            telemetry.observe_upstream_tcp_connect_ms(tcp_started.elapsed(), "timeout");
            return Err(anyhow::Error::from(e)).context("upstream TCP connect timeout");
        }
    };

    if tcp_nodelay && let Err(err) = upstream_socket.set_nodelay(true) {
        debug!("failed to enable upstream TCP_NODELAY: {err}");
    }
    telemetry.observe_upstream_tcp_connect_ms(tcp_started.elapsed(), "success");

    let connector = tokio_rustls::TlsConnector::from(client_config.clone());
    let tls_started = tokio::time::Instant::now();
    info!(
        "tunnel about to do TLS connect to {:?} with server_name {:?}",
        upstream_addr, server_name
    );
    debug!(
        "tunnel attempting TLS handshake to {:?} with SNI {:?}",
        upstream_addr, server_name
    );
    let upstream_tls = tokio::time::timeout(
        connect_timeout,
        connector.connect(server_name, upstream_socket),
    )
    .instrument(tracing::info_span!("tunnel_upstream_tls_handshake"))
    .await
    .context("upstream TLS handshake timeout")?
    .inspect_err(|e| {
        error!("tunnel TLS handshake failed: {:#}", e);
        telemetry.observe_upstream_tls_handshake_ms(tls_started.elapsed(), "error");
        telemetry.connection_error("tls_handshake", "upstream");
    })
    .context("tunnel TLS handshake failed")?;
    debug!("tunnel TLS handshake succeeded");
    telemetry.observe_upstream_tls_handshake_ms(tls_started.elapsed(), "success");

    let mut upstream_tls = upstream_tls;
    let mut downstream = downstream;

    info!("tunnel: copy_bidirectional starting");
    match tokio::io::copy_bidirectional(&mut downstream, &mut upstream_tls).await {
        Ok((d, u)) => {
            info!(
                "tunnel: copy_bidirectional completed normally: downstream->upstream={} bytes, upstream->downstream={} bytes",
                d, u
            );
        }
        Err(e) => {
            error!("tunnel: copy_bidirectional error: {:#}", e);
        }
    }
    info!("tunnel: handle_tunnel_connection returning Ok");
    Ok(())
}

pub async fn run_tunnel(config: TunnelConfig) -> Result<()> {
    let mut telemetry = crate::telemetry::Telemetry::new();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _otel_runtime = crate::telemetry::init_telemetry_tunnel(&config, filter, &mut telemetry);
    let telemetry = Arc::new(telemetry);

    let client_config = Arc::new(crate::tls::build_tunnel_client_config(&config)?);
    let connect_timeout = Duration::from_secs(config.connect_timeout_secs);
    let shutdown_timeout = Duration::from_secs(config.shutdown_timeout_secs);
    let tcp_nodelay = config.tcp_nodelay;

    let (upstream_host, upstream_port) = crate::utils::parse_host_port(&config.upstream)?;
    let upstream_addr = crate::utils::resolve_addr(&config.upstream)?;
    info!(
        "tunnel upstream {}:{} resolved to {:?}",
        upstream_host, upstream_port, upstream_addr
    );
    let server_name = crate::utils::parse_server_name(&upstream_host)?;
    info!("tunnel server name for TLS: {:?}", server_name);

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("shutdown signal received");
        shutdown_flag_clone.store(true, Ordering::Relaxed);
    });

    if let Some(metrics_listen) = &config.metrics_listen {
        let readiness = Arc::new(AtomicBool::new(false));
        let readiness_for_server = readiness.clone();
        let metrics_listen = metrics_listen.clone();
        tokio::spawn(async move {
            if let Err(err) =
                crate::metrics_server::start_metrics_server(&metrics_listen, readiness_for_server)
                    .await
            {
                tracing::error!("metrics server error: {err:#}");
            }
        });
        readiness.store(true, Ordering::Relaxed);
    }

    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind listen address {}", config.listen))?;

    info!("tunnel listening on {}", config.listen);
    info!("tunnel upstream {}:{}", upstream_host, upstream_port);

    let mut connections: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            info!("stopping accept loop due to shutdown signal");
            break;
        }

        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((socket, peer_addr)) => {
                        if tcp_nodelay && let Err(err) = socket.set_nodelay(true) {
                            debug!("failed to enable downstream TCP_NODELAY: {err}");
                        }
                        telemetry.connection_accepted();

                        let client_config = client_config.clone();
                        let server_name = server_name.clone();
                        let telemetry = telemetry.clone();
                        let _shutdown_flag = shutdown_flag.clone();

                        let handle = tokio::spawn(async move {
                            info!("tunnel spawn PRE: socket={}, upstream_addr={:?}, server_name={:?}", peer_addr, upstream_addr, server_name);
                            let span = tracing::info_span!("tunnel_connection", peer = %peer_addr);
                            let result = handle_tunnel_connection(
                                socket,
                                upstream_addr,
                                server_name,
                                client_config,
                                connect_timeout,
                                tcp_nodelay,
                                &telemetry,
                            )
                            .instrument(span)
                            .await;
                            match result {
                                Ok(()) => {
                                    info!("tunnel connection completed OK");
                                }
                                Err(e) => {
                                    tracing::error!("tunnel connection error: {e:#}");
                                    telemetry.connection_error("tunnel_connection", "downstream");
                                }
                            }
                            telemetry.connection_closed();
                        });
                        connections.push(handle);
                    }
                    Err(err) => {
                        if shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        tracing::error!("accept error: {err:#}");
                    }
                }
            }
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    info!(
        "waiting for {} tunnel connections to finish",
        connections.len()
    );
    let shutdown_deadline = tokio::time::Instant::now() + shutdown_timeout;
    for handle in connections {
        let remaining = shutdown_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, handle).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!("tunnel task panicked: {e:#}"),
            Err(_) => debug!("tunnel task timed out during shutdown"),
        }
    }

    info!("tunnel shutdown complete");
    Ok(())
}
