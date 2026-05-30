use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::BytesMut;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Instant, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::Instrument;
use tracing::{debug, error, info, info_span};

use crate::auth::extract_dns_user;
use crate::auth::send_auth;
use crate::cli::ProxyConfig;
use crate::protocol::{
    apply_command_state_after_response, apply_command_state_before_send, classify_command,
    close_reason_from_io_error, idle_timeout_from_secs, parse_command_frame, parse_resp_frame_len,
    should_reauth_after_reset,
};
use crate::telemetry::Telemetry;
use crate::tls::build_client_config;
use crate::tls::build_server_config;

use crate::types::{
    AclEntry, ClientConfigs, CommandClass, FrameInfo, PinnedAt, PinnedConn, PoolDropReason,
    PoolKey, RouteState, SessionState, UpstreamConn, UpstreamPool,
};
use crate::utils::{
    is_tls_handshake_eof, parse_server_name, resolve_addr, should_retry_without_resumption,
};

pub async fn run_proxy(config: ProxyConfig) -> Result<()> {
    let mut telemetry = Telemetry::new();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _otel_runtime = crate::telemetry::init_telemetry_proxy(&config, filter, &mut telemetry);
    let telemetry = Arc::new(telemetry);

    let acl = crate::watcher::load_acl(&config.acl)?;
    telemetry.set_acl_entries(acl.len());
    let (acl_tx, acl_rx) = watch::channel(Arc::new(acl));

    let server_config = Arc::new(build_server_config(&config)?);
    let client_configs = Arc::new(ClientConfigs {
        with_resumption: Arc::new(build_client_config(&config, false)?),
        no_resumption: Arc::new(build_client_config(&config, true)?),
    });
    let (server_tx, server_rx) = watch::channel(server_config);
    let (client_tx, client_rx) = watch::channel(client_configs);
    let resumption_enabled = Arc::new(AtomicBool::new(true));
    telemetry.set_tls_resumption_enabled(true);
    let handshake_timeout = Duration::from_secs(config.handshake_timeout_secs);

    let (upstream_host, _upstream_port) = crate::utils::parse_host_port(&config.upstream)?;
    let upstream_addr = resolve_addr(&config.upstream)?;
    let server_name = parse_server_name(&upstream_host)?;
    let upstream_pool = Arc::new(UpstreamPool {
        idle: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        upstream_addr,
        server_name,
        handshake_timeout,
        max_idle_per_user: config.pool_max_idle_per_user,
        client_rx: client_rx.clone(),
        resumption_enabled: resumption_enabled.clone(),
        telemetry: telemetry.clone(),
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
                error!("metrics server error: {err:#}");
            }
        });
        readiness.store(true, Ordering::Relaxed);
    }

    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind listen address {}", config.listen))?;

    info!("listening on {}", config.listen);

    let config = Arc::new(config);
    let _acl_watcher =
        crate::watcher::start_acl_watcher(config.acl.clone(), acl_tx, telemetry.clone())?;
    let _tls_watcher =
        crate::watcher::start_tls_watcher(config.clone(), server_tx, client_tx, telemetry.clone())?;

    loop {
        let (socket, _) = listener.accept().await?;
        if let Err(err) = socket.set_nodelay(true) {
            debug!("failed to enable downstream TCP_NODELAY: {err}");
        }
        telemetry.connection_accepted();
        let server_rx = server_rx.clone();
        let acl_rx = acl_rx.clone();
        let upstream_pool = upstream_pool.clone();
        let config = config.clone();
        let telemetry = telemetry.clone();
        tokio::spawn(async move {
            let span = info_span!("connection", peer = %socket.peer_addr().map_or_else(|_| "unknown".to_string(), |addr| addr.to_string()));
            if let Err(err) = handle_connection(socket, server_rx, acl_rx, config, upstream_pool)
                .instrument(span)
                .await
            {
                error!("connection error: {err:#}");
                telemetry.connection_error("connection_task", "downstream");
                telemetry.connection_closed_reason("error");
            }
            telemetry.connection_closed();
        });
    }
}

#[allow(clippy::too_many_lines)]
pub async fn handle_connection(
    socket: TcpStream,
    server_rx: watch::Receiver<Arc<rustls::ServerConfig>>,
    acl_rx: watch::Receiver<Arc<std::collections::HashMap<String, AclEntry>>>,
    config: Arc<ProxyConfig>,
    upstream_pool: Arc<UpstreamPool>,
) -> Result<()> {
    let server_config = server_rx.borrow().clone();
    let acceptor = TlsAcceptor::from(server_config);
    let handshake_timeout = Duration::from_secs(config.handshake_timeout_secs);
    let idle_timeout = idle_timeout_from_secs(config.idle_timeout_secs);
    let handshake_started = Instant::now();
    let tls_stream = match timeout(handshake_timeout, acceptor.accept(socket))
        .instrument(info_span!("downstream_tls_handshake"))
        .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            upstream_pool
                .telemetry
                .observe_downstream_handshake_ms(handshake_started.elapsed(), "error");
            if is_tls_handshake_eof(&err) {
                upstream_pool
                    .telemetry
                    .connection_closed_reason("downstream_tls_eof");
                debug!("downstream TLS handshake eof");
                return Ok(());
            }
            upstream_pool
                .telemetry
                .connection_error("tls_handshake", "downstream");
            return Err(anyhow!(err)).context("downstream TLS handshake failed");
        }
        Err(_) => {
            upstream_pool
                .telemetry
                .observe_downstream_handshake_ms(handshake_started.elapsed(), "timeout");
            upstream_pool
                .telemetry
                .connection_error("tls_handshake", "downstream");
            upstream_pool
                .telemetry
                .connection_closed_reason("handshake_timeout");
            return Err(anyhow!("downstream TLS handshake timeout"));
        }
    };
    upstream_pool
        .telemetry
        .observe_downstream_handshake_ms(handshake_started.elapsed(), "success");

    let user = extract_dns_user(&tls_stream)?;
    let acl = acl_rx.borrow().clone();
    let entry = acl
        .get(&user)
        .ok_or_else(|| anyhow!("user not found in ACL: {user}"))?
        .clone();

    let key = PoolKey { user };
    let password = entry.password;
    let mut downstream = tls_stream;
    let mut downstream_buf = BytesMut::with_capacity(8192);
    let mut route_state = RouteState::Stateless;
    let max_frame_size = config.max_frame_size;

    loop {
        let frame_result = read_next_command_frame(
            &mut downstream,
            &mut downstream_buf,
            idle_timeout,
            max_frame_size,
        )
        .await;

        let frame = match frame_result {
            Ok(frame) => frame,
            Err(err) => {
                let close_reason = close_reason_from_io_error(&err);
                upstream_pool
                    .telemetry
                    .connection_closed_reason(close_reason);
                upstream_pool
                    .telemetry
                    .connection_error("read", "downstream");
                return Err(err);
            }
        };

        let Some((frame, data)) = frame else {
            let should_release = match &route_state {
                RouteState::Pinned(pinned_conn) => pinned_conn.state.can_unpin(),
                RouteState::Stateless => false,
            };
            if should_release {
                let RouteState::Pinned(pinned_conn) =
                    std::mem::replace(&mut route_state, RouteState::Stateless)
                else {
                    unreachable!("release checked pinned state");
                };
                upstream_pool.telemetry.observe_pinned_duration_ms(
                    pinned_conn.pinned_at.started.elapsed(),
                    "client_eof",
                );
                upstream_pool.telemetry.session_unpin("client_eof");
                upstream_pool
                    .telemetry
                    .pin_transition("pinned", "stateless", "client_eof");
                upstream_pool.release(&key, pinned_conn.conn);
            }
            upstream_pool
                .telemetry
                .connection_closed_reason("client_eof");
            return Ok(());
        };

        if frame.is_auth {
            upstream_pool.telemetry.auth_blocked();
            downstream
                .write_all(b"-ERR AUTH disabled by proxy\r\n")
                .await?;
            continue;
        }

        let class = classify_command(&frame);
        upstream_pool
            .telemetry
            .command_classified(&frame.command, class);
        upstream_pool
            .telemetry
            .observe_command_size(data.len(), class);
        if matches!(route_state, RouteState::Stateless)
            && matches!(
                class,
                CommandClass::PinTemporary
                    | CommandClass::PinForever
                    | CommandClass::PinWhileBlocking
            )
        {
            let conn = upstream_pool
                .checkout(&key, password.as_deref())
                .instrument(info_span!(
                    "upstream_checkout",
                    route_class = class.as_str(),
                    mode = "pin"
                ))
                .await?;
            route_state = RouteState::Pinned(Box::new(PinnedConn {
                conn,
                state: SessionState::default(),
                pinned_at: PinnedAt {
                    started: Instant::now(),
                },
            }));
            upstream_pool
                .telemetry
                .pin_transition("stateless", "pinned", "stateful_command");
            debug!(route_class = class.as_str(), "route transitioned to pinned");
        }

        if let RouteState::Pinned(pinned_conn) = &mut route_state {
            apply_command_state_before_send(&mut pinned_conn.state, &frame, class);
            pinned_conn.conn.tls.write_all(&data).await?;
            let started = Instant::now();
            let response =
                read_upstream_response(&mut pinned_conn.conn, idle_timeout, max_frame_size)
                    .instrument(info_span!("upstream_response", route_mode = "pinned"))
                    .await?;
            upstream_pool
                .telemetry
                .observe_upstream_roundtrip_ms(&frame.command, started.elapsed());
            upstream_pool
                .telemetry
                .observe_response_size(response.len(), class);
            downstream.write_all(&response).await?;
            apply_command_state_after_response(&mut pinned_conn.state, &frame, class, &response);

            if should_reauth_after_reset(&frame, &response) {
                upstream_pool.telemetry.reauth_after_reset_attempt();
                let reauth_started = Instant::now();
                match send_auth(&mut pinned_conn.conn.tls, &key.user, password.as_deref())
                    .instrument(info_span!("upstream_auth", trigger = "reset"))
                    .await
                {
                    Ok(()) => upstream_pool
                        .telemetry
                        .observe_upstream_auth_ms(reauth_started.elapsed(), "success"),
                    Err(err) => {
                        let RouteState::Pinned(dropped_conn) =
                            std::mem::replace(&mut route_state, RouteState::Stateless)
                        else {
                            unreachable!("state just matched pinned");
                        };
                        upstream_pool.telemetry.observe_pinned_duration_ms(
                            dropped_conn.pinned_at.started.elapsed(),
                            "reauth_failed",
                        );
                        upstream_pool.telemetry.session_unpin("reauth_failed");
                        upstream_pool.telemetry.pin_transition(
                            "pinned",
                            "stateless",
                            "reauth_failed",
                        );
                        upstream_pool.telemetry.reauth_after_reset_failure();
                        upstream_pool.telemetry.upstream_auth_failure();
                        upstream_pool
                            .telemetry
                            .observe_upstream_auth_ms(reauth_started.elapsed(), "error");
                        upstream_pool.telemetry.connection_error("auth", "upstream");
                        error!("upstream re-authentication after RESET failed: {err:#}");
                        downstream
                            .write_all(
                                b"-ERR proxy failed to reauthenticate upstream after RESET\r\n",
                            )
                            .await?;
                        continue;
                    }
                }
            }

            if pinned_conn.state.can_unpin() {
                let RouteState::Pinned(pinned_conn) =
                    std::mem::replace(&mut route_state, RouteState::Stateless)
                else {
                    unreachable!("state just matched pinned");
                };
                upstream_pool.telemetry.observe_pinned_duration_ms(
                    pinned_conn.pinned_at.started.elapsed(),
                    "state_cleared",
                );
                upstream_pool.telemetry.session_unpin("state_cleared");
                upstream_pool
                    .telemetry
                    .pin_transition("pinned", "stateless", "state_cleared");
                upstream_pool.release(&key, pinned_conn.conn);
            }
            continue;
        }

        let mut conn = upstream_pool
            .checkout(&key, password.as_deref())
            .instrument(info_span!(
                "upstream_checkout",
                route_class = class.as_str(),
                mode = "stateless"
            ))
            .await?;
        conn.tls.write_all(&data).await?;
        let started = Instant::now();
        let response = read_upstream_response(&mut conn, idle_timeout, max_frame_size).await?;
        upstream_pool
            .telemetry
            .observe_upstream_roundtrip_ms(&frame.command, started.elapsed());
        upstream_pool
            .telemetry
            .observe_response_size(response.len(), class);
        downstream.write_all(&response).await?;
        upstream_pool.release(&key, conn);
    }
}

impl UpstreamPool {
    pub async fn checkout(&self, key: &PoolKey, password: Option<&str>) -> Result<UpstreamConn> {
        if let Some(conn) = {
            let mut idle = self.idle.lock();
            idle.get_mut(key).and_then(Vec::pop)
        } {
            self.telemetry.pool_checkout_hit();
            self.telemetry.pool_idle_delta(-1);
            return Ok(conn);
        }
        self.telemetry.pool_checkout_miss();
        self.connect_new(key, password).await
    }

    pub fn release(&self, key: &PoolKey, conn: UpstreamConn) {
        if !conn.read_buf.is_empty() {
            self.telemetry
                .pool_release_dropped(PoolDropReason::ReadBufNotEmpty.as_str());
            return;
        }

        let mut idle = self.idle.lock();
        let entry = idle.entry(key.clone()).or_default();
        if entry.len() < self.max_idle_per_user {
            entry.push(conn);
            self.telemetry.pool_idle_delta(1);
        } else {
            self.telemetry
                .pool_release_dropped(PoolDropReason::PoolFull.as_str());
        }
    }

    async fn connect_new(&self, key: &PoolKey, password: Option<&str>) -> Result<UpstreamConn> {
        self.telemetry.pool_connect_new();
        let client_configs = self.client_rx.borrow().clone();
        let connector = TlsConnector::from(client_configs.with_resumption.clone());
        let connector_no_resumption = TlsConnector::from(client_configs.no_resumption.clone());

        let mut upstream_tls = if self.resumption_enabled.load(Ordering::Relaxed) {
            match connect_upstream(
                &connector,
                self.upstream_addr,
                self.server_name.clone(),
                self.handshake_timeout,
                self.telemetry.as_ref(),
            )
            .await
            {
                Ok(stream) => stream,
                Err(err) => {
                    if should_retry_without_resumption(&err) {
                        info!("upstream TLS resumption failed, retrying without resumption");
                        let stream = connect_upstream(
                            &connector_no_resumption,
                            self.upstream_addr,
                            self.server_name.clone(),
                            self.handshake_timeout,
                            self.telemetry.as_ref(),
                        )
                        .await?;
                        self.resumption_enabled.store(false, Ordering::Relaxed);
                        self.telemetry.set_tls_resumption_enabled(false);
                        info!("upstream TLS resumption disabled for future connections");
                        stream
                    } else {
                        return Err(err);
                    }
                }
            }
        } else {
            connect_upstream(
                &connector_no_resumption,
                self.upstream_addr,
                self.server_name.clone(),
                self.handshake_timeout,
                self.telemetry.as_ref(),
            )
            .await?
        };

        let auth_started = Instant::now();
        send_auth(&mut upstream_tls, &key.user, password)
            .instrument(info_span!("upstream_auth", trigger = "connect_new"))
            .await
            .inspect_err(|_| {
                self.telemetry.upstream_auth_failure();
                self.telemetry.connection_error("auth", "upstream");
                self.telemetry
                    .observe_upstream_auth_ms(auth_started.elapsed(), "error");
            })?;
        self.telemetry
            .observe_upstream_auth_ms(auth_started.elapsed(), "success");

        Ok(UpstreamConn {
            tls: upstream_tls,
            read_buf: BytesMut::with_capacity(1024),
        })
    }
}

async fn connect_upstream(
    connector: &TlsConnector,
    addr: std::net::SocketAddr,
    server_name: ServerName<'static>,
    timeout_duration: Duration,
    telemetry: &Telemetry,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp_started = Instant::now();
    let upstream_socket = timeout(timeout_duration, TcpStream::connect(addr))
        .instrument(info_span!("upstream_tcp_connect"))
        .await
        .inspect_err(|_| {
            telemetry.observe_upstream_tcp_connect_ms(tcp_started.elapsed(), "timeout");
            telemetry.connection_error("tcp_connect", "upstream");
        })
        .context("upstream TCP connect timeout")?
        .inspect_err(|_| {
            telemetry.observe_upstream_tcp_connect_ms(tcp_started.elapsed(), "error");
            telemetry.connection_error("tcp_connect", "upstream");
        })?;
    if let Err(err) = upstream_socket.set_nodelay(true) {
        debug!("failed to enable upstream TCP_NODELAY: {err}");
    }
    telemetry.observe_upstream_tcp_connect_ms(tcp_started.elapsed(), "success");

    let tls_started = Instant::now();
    let upstream_tls = timeout(
        timeout_duration,
        connector.connect(server_name, upstream_socket),
    )
    .instrument(info_span!("upstream_tls_handshake"))
    .await
    .inspect_err(|_| {
        telemetry.observe_upstream_tls_handshake_ms(tls_started.elapsed(), "timeout");
        telemetry.connection_error("tls_handshake", "upstream");
    })
    .context("upstream TLS handshake timeout")?
    .inspect_err(|_| {
        telemetry.observe_upstream_tls_handshake_ms(tls_started.elapsed(), "error");
        telemetry.connection_error("tls_handshake", "upstream");
    })?;
    telemetry.observe_upstream_tls_handshake_ms(tls_started.elapsed(), "success");

    Ok(upstream_tls)
}

async fn read_next_command_frame(
    downstream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    buffer: &mut BytesMut,
    idle_timeout: Option<Duration>,
    max_frame_size: usize,
) -> Result<Option<(FrameInfo, BytesMut)>> {
    let mut read_buf = [0u8; 8192];
    loop {
        if let Some(frame) = parse_command_frame(buffer)? {
            if frame.len > max_frame_size {
                bail!("frame exceeds max size");
            }
            let data = buffer.split_to(frame.len);
            return Ok(Some((frame, data)));
        }

        let n = match idle_timeout {
            Some(idle_timeout) => match timeout(idle_timeout, downstream.read(&mut read_buf)).await
            {
                Ok(Ok(n)) => n,
                Ok(Err(err)) => return Err(anyhow!(err)),
                Err(_) => return Err(anyhow!("downstream idle timeout")),
            },
            None => downstream
                .read(&mut read_buf)
                .await
                .map_err(anyhow::Error::from)?,
        };

        if n == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            bail!("downstream closed with partial frame");
        }

        buffer.extend_from_slice(&read_buf[..n]);
        if buffer.len() > max_frame_size {
            bail!("frame buffer exceeds max size");
        }
    }
}

async fn read_upstream_response(
    upstream: &mut UpstreamConn,
    idle_timeout: Option<Duration>,
    max_frame_size: usize,
) -> Result<BytesMut> {
    let mut read_buf = [0u8; 8192];
    loop {
        if let Some(len) = parse_resp_frame_len(&upstream.read_buf)? {
            if len > max_frame_size {
                bail!("response frame exceeds max size");
            }
            return Ok(upstream.read_buf.split_to(len));
        }

        let n = match idle_timeout {
            Some(idle_timeout) => {
                match timeout(idle_timeout, upstream.tls.read(&mut read_buf)).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(err)) => return Err(anyhow!(err)),
                    Err(_) => return Err(anyhow!("upstream idle timeout")),
                }
            }
            None => upstream
                .tls
                .read(&mut read_buf)
                .await
                .map_err(anyhow::Error::from)?,
        };

        if n == 0 {
            bail!("upstream closed connection");
        }

        upstream.read_buf.extend_from_slice(&read_buf[..n]);
        if upstream.read_buf.len() > max_frame_size {
            bail!("response buffer exceeds max size");
        }
    }
}
