#![warn(clippy::pedantic)]
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::BytesMut;
use clap::Parser;
use notify::{RecursiveMode, Watcher};
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName,
};
use rustls::{AlertDescription, ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{Instrument, debug, error, info, info_span};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Parser, Debug, Clone)]
#[command(name = "dfguard", version, about = "mTLS auth proxy for DragonflyDB")]
struct Config {
    #[arg(long, env = "DFGUARD_LISTEN", default_value = "[::]:6379")]
    listen: String,
    #[arg(long, env = "DFGUARD_UPSTREAM")]
    upstream: String,
    #[arg(long, value_name = "FILE", env = "DFGUARD_ACL")]
    acl: PathBuf,

    #[arg(long, value_name = "FILE", env = "DFGUARD_SERVER_CERT")]
    server_cert: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_SERVER_KEY")]
    server_key: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_SERVER_CA")]
    server_ca: PathBuf,

    #[arg(long, value_name = "FILE", env = "DFGUARD_UPSTREAM_CERT")]
    upstream_cert: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_UPSTREAM_KEY")]
    upstream_key: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_UPSTREAM_CA")]
    upstream_ca: PathBuf,

    #[arg(long, env = "DFGUARD_HANDSHAKE_TIMEOUT_SECS", default_value = "10")]
    handshake_timeout_secs: u64,
    #[arg(long, env = "DFGUARD_IDLE_TIMEOUT_SECS", default_value = "0")]
    idle_timeout_secs: u64,
    #[arg(long, env = "DFGUARD_MAX_FRAME_SIZE", default_value = "16777216")]
    max_frame_size: usize,

    #[arg(long, env = "DFGUARD_POOL_MAX_IDLE_PER_USER", default_value = "64")]
    pool_max_idle_per_user: usize,

    #[arg(long, env = "DFGUARD_INSECURE_UPSTREAM", default_value_t = false)]
    insecure_upstream: bool,

    #[arg(long, env = "DFGUARD_METRICS_LISTEN")]
    metrics_listen: Option<String>,
}

#[derive(Clone)]
struct Telemetry {
    otel_metrics: Option<Arc<OTelMetrics>>,
    tls_resumption_enabled: Arc<std::sync::atomic::AtomicI64>,
    acl_entries: Arc<std::sync::atomic::AtomicI64>,
}

struct OTelRuntime {
    _tracer: Option<SdkTracerProvider>,
    _meter: Option<SdkMeterProvider>,
    _logger: Option<SdkLoggerProvider>,
}

struct OTelMetrics {
    conn_accepted: Counter<u64>,
    errors: Counter<u64>,
    conn_closed: Counter<u64>,
    auth_blocked: Counter<u64>,
    commands_total: Counter<u64>,
    commands_rejected: Counter<u64>,
    pin_transitions: Counter<u64>,
    session_unpin: Counter<u64>,
    session_reauth_after_reset: Counter<u64>,
    session_reauth_after_reset_failures: Counter<u64>,
    upstream_auth_failures: Counter<u64>,
    pool_checkout_hit: Counter<u64>,
    pool_checkout_miss: Counter<u64>,
    pool_connect_new: Counter<u64>,
    pool_release_dropped: Counter<u64>,
    reload_events: Counter<u64>,
    active_connections: UpDownCounter<i64>,
    pool_idle_connections: UpDownCounter<i64>,
    acl_entries: UpDownCounter<i64>,
    tls_resumption_enabled: UpDownCounter<i64>,
    downstream_tls_handshake_ms: Histogram<f64>,
    upstream_tcp_connect_ms: Histogram<f64>,
    upstream_tls_handshake_ms: Histogram<f64>,
    upstream_auth_ms: Histogram<f64>,
    upstream_roundtrip_ms: Histogram<f64>,
    session_pinned_ms: Histogram<f64>,
    downstream_command_size_bytes: Histogram<u64>,
    upstream_response_size_bytes: Histogram<u64>,
}

impl Telemetry {
    fn new() -> Self {
        Self {
            otel_metrics: None,
            tls_resumption_enabled: Arc::new(std::sync::atomic::AtomicI64::new(1)),
            acl_entries: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        }
    }

    fn set_otel(&mut self, metrics: Arc<OTelMetrics>) {
        let acl_entries = self.acl_entries.load(Ordering::Relaxed);
        let tls_resumption_enabled = self.tls_resumption_enabled.load(Ordering::Relaxed);
        if acl_entries != 0 {
            metrics.acl_entries.add(acl_entries, &[]);
        }
        metrics
            .tls_resumption_enabled
            .add(tls_resumption_enabled, &[]);
        self.otel_metrics = Some(metrics);
    }

    fn set_acl_entries(&self, size: usize) {
        let Ok(size) = i64::try_from(size) else {
            return;
        };
        let prev = self.acl_entries.swap(size, Ordering::Relaxed);
        if let Some(metrics) = &self.otel_metrics {
            metrics.acl_entries.add(size - prev, &[]);
        }
    }

    fn set_tls_resumption_enabled(&self, enabled: bool) {
        let value = i64::from(enabled);
        let prev = self.tls_resumption_enabled.swap(value, Ordering::Relaxed);
        if let Some(metrics) = &self.otel_metrics {
            metrics.tls_resumption_enabled.add(value - prev, &[]);
        }
    }

    fn connection_accepted(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.conn_accepted.add(1, &[]);
            metrics.active_connections.add(1, &[]);
        }
    }

    fn connection_closed(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.active_connections.add(-1, &[]);
        }
    }

    fn connection_error(&self, stage: &'static str, direction: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.errors.add(
                1,
                &[
                    KeyValue::new("error.stage", stage),
                    KeyValue::new("error.direction", direction),
                ],
            );
        }
    }

    fn connection_closed_reason(&self, reason: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics
                .conn_closed
                .add(1, &[KeyValue::new("close.reason", reason)]);
        }
    }

    fn auth_blocked(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.auth_blocked.add(1, &[]);
            metrics
                .commands_rejected
                .add(1, &[KeyValue::new("reason", "auth_disabled")]);
        }
    }

    fn command_classified(&self, command: &str, class: CommandClass) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.commands_total.add(
                1,
                &[
                    KeyValue::new("redis.command", command.to_string()),
                    KeyValue::new("route.class", class.as_str()),
                ],
            );
        }
    }

    fn pin_transition(&self, from: &'static str, to: &'static str, reason: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.pin_transitions.add(
                1,
                &[
                    KeyValue::new("pin.from", from),
                    KeyValue::new("pin.to", to),
                    KeyValue::new("pin.reason", reason),
                ],
            );
        }
    }

    fn session_unpin(&self, reason: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics
                .session_unpin
                .add(1, &[KeyValue::new("reason", reason)]);
        }
    }

    fn reload_event(&self, kind: &'static str, status: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.reload_events.add(
                1,
                &[
                    KeyValue::new("reload.kind", kind),
                    KeyValue::new("reload.status", status),
                ],
            );
        }
    }

    fn observe_upstream_roundtrip_ms(&self, command: &str, elapsed: Duration) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.upstream_roundtrip_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("redis.command", command.to_string())],
            );
        }
    }

    fn observe_downstream_handshake_ms(&self, elapsed: Duration, status: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.downstream_tls_handshake_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("status", status)],
            );
        }
    }

    fn observe_upstream_tcp_connect_ms(&self, elapsed: Duration, status: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.upstream_tcp_connect_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("status", status)],
            );
        }
    }

    fn observe_upstream_tls_handshake_ms(&self, elapsed: Duration, status: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.upstream_tls_handshake_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("status", status)],
            );
        }
    }

    fn observe_upstream_auth_ms(&self, elapsed: Duration, status: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.upstream_auth_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("status", status)],
            );
        }
    }

    fn upstream_auth_failure(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.upstream_auth_failures.add(1, &[]);
        }
    }

    fn observe_pinned_duration_ms(&self, elapsed: Duration, reason: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.session_pinned_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("reason", reason)],
            );
        }
    }

    fn observe_command_size(&self, size: usize, class: CommandClass) {
        if let Some(metrics) = &self.otel_metrics
            && let Ok(size) = u64::try_from(size)
        {
            metrics
                .downstream_command_size_bytes
                .record(size, &[KeyValue::new("route.class", class.as_str())]);
        }
    }

    fn observe_response_size(&self, size: usize, class: CommandClass) {
        if let Some(metrics) = &self.otel_metrics
            && let Ok(size) = u64::try_from(size)
        {
            metrics
                .upstream_response_size_bytes
                .record(size, &[KeyValue::new("route.class", class.as_str())]);
        }
    }

    fn pool_checkout_hit(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.pool_checkout_hit.add(1, &[]);
        }
    }

    fn pool_checkout_miss(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.pool_checkout_miss.add(1, &[]);
        }
    }

    fn pool_connect_new(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.pool_connect_new.add(1, &[]);
        }
    }

    fn pool_idle_delta(&self, delta: i64) {
        if delta == 0 {
            return;
        }
        if let Some(metrics) = &self.otel_metrics {
            metrics.pool_idle_connections.add(delta, &[]);
        }
    }

    fn pool_release_dropped(&self, reason: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics
                .pool_release_dropped
                .add(1, &[KeyValue::new("reason", reason)]);
        }
    }

    fn reauth_after_reset_attempt(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.session_reauth_after_reset.add(1, &[]);
        }
    }

    fn reauth_after_reset_failure(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.session_reauth_after_reset_failures.add(1, &[]);
        }
    }
}

#[derive(Clone)]
struct ClientConfigs {
    with_resumption: Arc<ClientConfig>,
    no_resumption: Arc<ClientConfig>,
}

#[derive(Clone, Debug)]
struct AclEntry {
    password: Option<String>,
}

#[derive(Clone)]
struct UpstreamPool {
    idle: Arc<Mutex<HashMap<PoolKey, Vec<UpstreamConn>>>>,
    upstream_addr: SocketAddr,
    server_name: ServerName<'static>,
    handshake_timeout: Duration,
    max_idle_per_user: usize,
    client_rx: watch::Receiver<Arc<ClientConfigs>>,
    resumption_enabled: Arc<AtomicBool>,
    telemetry: Arc<Telemetry>,
}

#[derive(Clone, Eq, PartialEq, Hash)]
struct PoolKey {
    user: String,
}

struct UpstreamConn {
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    read_buf: BytesMut,
}

#[derive(Default)]
struct SessionState {
    txn: TxnState,
    watch: WatchState,
    tracking: TrackingState,
    blocking: BlockingState,
    sticky: StickyState,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum TxnState {
    #[default]
    None,
    InMulti,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum WatchState {
    #[default]
    Off,
    On,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum TrackingState {
    #[default]
    Off,
    On,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum BlockingState {
    #[default]
    Idle,
    Waiting,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum StickyState {
    #[default]
    Off,
    On,
}

impl SessionState {
    fn can_unpin(&self) -> bool {
        self.txn == TxnState::None
            && self.watch == WatchState::Off
            && self.tracking == TrackingState::Off
            && self.sticky == StickyState::Off
            && self.blocking == BlockingState::Idle
    }
}

struct PinnedConn {
    conn: UpstreamConn,
    state: SessionState,
    pinned_at: PinnedAt,
}

enum RouteState {
    Stateless,
    Pinned(Box<PinnedConn>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandClass {
    Stateless,
    PinTemporary,
    PinForever,
    PinWhileBlocking,
}

impl CommandClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stateless => "stateless",
            Self::PinTemporary => "pin_temporary",
            Self::PinForever => "pin_forever",
            Self::PinWhileBlocking => "pin_while_blocking",
        }
    }
}

#[derive(Clone, Copy)]
enum PoolDropReason {
    ReadBufNotEmpty,
    PoolFull,
}

impl PoolDropReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReadBufNotEmpty => "read_buf_not_empty",
            Self::PoolFull => "pool_full",
        }
    }
}

struct PinnedAt {
    started: tokio::time::Instant,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();
    let mut telemetry = Telemetry::new();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _otel_runtime = init_telemetry(&config, filter, &mut telemetry);
    let telemetry = Arc::new(telemetry);

    let acl = load_acl(&config.acl)?;
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

    let (upstream_host, _upstream_port) = parse_host_port(&config.upstream)?;
    let upstream_addr = resolve_addr(&config.upstream)?;
    let server_name = parse_server_name(&upstream_host)?;
    let upstream_pool = Arc::new(UpstreamPool {
        idle: Arc::new(Mutex::new(HashMap::new())),
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
            if let Err(err) = start_metrics_server(&metrics_listen, readiness_for_server).await {
                error!("metrics server error: {err:#}");
            }
        });
        readiness.store(true, Ordering::Relaxed);
    }

    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind listen address {}", config.listen))?;

    info!("listening on {}", config.listen);

    let config = Arc::new(config);
    let _acl_watcher = start_acl_watcher(config.acl.clone(), acl_tx, telemetry.clone())?;
    let _tls_watcher = start_tls_watcher(config.clone(), server_tx, client_tx, telemetry.clone())?;

    loop {
        let (socket, _) = listener.accept().await?;
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

fn init_telemetry(config: &Config, filter: EnvFilter, telemetry: &mut Telemetry) -> OTelRuntime {
    let resource = Resource::builder()
        .with_service_name(
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "dfguard".to_string()),
        )
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .with_attribute(KeyValue::new("dfguard.listen", config.listen.clone()))
        .build();

    let mut tracer_provider = None;
    let mut meter_provider = None;
    let mut logger_provider = None;

    let sdk_disabled = std::env::var("OTEL_SDK_DISABLED")
        .map(|v| v == "true")
        .unwrap_or(false);
    let otlp_configured = has_otel_otlp_endpoint_env();

    if sdk_disabled || !otlp_configured {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_target(false))
            .init();
        return OTelRuntime {
            _tracer: None,
            _meter: None,
            _logger: None,
        };
    }

    match opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .map(|exporter| {
            opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(resource.clone())
                .build()
        }) {
        Ok(provider) => {
            global::set_tracer_provider(provider.clone());
            tracer_provider = Some(provider);
        }
        Err(err) => {
            eprintln!("failed to initialize OTLP trace exporter: {err}");
        }
    }

    match opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .build()
        .map(|exporter| {
            let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter).build();
            opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                .with_reader(reader)
                .with_resource(resource.clone())
                .build()
        }) {
        Ok(provider) => {
            global::set_meter_provider(provider.clone());
            let meter = provider.meter("dfguard");
            telemetry.set_otel(Arc::new(build_otel_metrics(&meter)));
            meter_provider = Some(provider);
        }
        Err(err) => {
            eprintln!("failed to initialize OTLP metrics exporter: {err}");
        }
    }

    match opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .build()
        .map(|exporter| {
            opentelemetry_sdk::logs::SdkLoggerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(resource)
                .build()
        }) {
        Ok(provider) => {
            logger_provider = Some(provider);
        }
        Err(err) => {
            eprintln!("failed to initialize OTLP logs exporter: {err}");
        }
    }

    let tracer_layer = tracer_provider
        .as_ref()
        .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("dfguard")));
    let log_layer = logger_provider
        .as_ref()
        .map(OpenTelemetryTracingBridge::new);

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(tracer_layer)
        .with(log_layer)
        .init();

    OTelRuntime {
        _tracer: tracer_provider,
        _meter: meter_provider,
        _logger: logger_provider,
    }
}

fn has_otel_otlp_endpoint_env() -> bool {
    [
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    ]
    .iter()
    .any(|name| {
        std::env::var(name)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    })
}

fn build_otel_metrics(meter: &Meter) -> OTelMetrics {
    OTelMetrics {
        conn_accepted: meter.u64_counter("dfguard.connections.accepted").build(),
        errors: meter.u64_counter("dfguard.errors.total").build(),
        conn_closed: meter.u64_counter("dfguard.connections.closed").build(),
        auth_blocked: meter.u64_counter("dfguard.auth.blocked").build(),
        commands_total: meter.u64_counter("dfguard.commands.total").build(),
        commands_rejected: meter.u64_counter("dfguard.commands.rejected").build(),
        pin_transitions: meter.u64_counter("dfguard.pin.transitions").build(),
        session_unpin: meter.u64_counter("dfguard.session.unpin").build(),
        session_reauth_after_reset: meter
            .u64_counter("dfguard.session.reauth_after_reset")
            .build(),
        session_reauth_after_reset_failures: meter
            .u64_counter("dfguard.session.reauth_after_reset.failures")
            .build(),
        upstream_auth_failures: meter.u64_counter("dfguard.upstream.auth.failures").build(),
        pool_checkout_hit: meter.u64_counter("dfguard.pool.checkout.hit").build(),
        pool_checkout_miss: meter.u64_counter("dfguard.pool.checkout.miss").build(),
        pool_connect_new: meter.u64_counter("dfguard.pool.connect_new").build(),
        pool_release_dropped: meter.u64_counter("dfguard.pool.release.dropped").build(),
        reload_events: meter.u64_counter("dfguard.reload.events").build(),
        active_connections: meter
            .i64_up_down_counter("dfguard.connections.active")
            .build(),
        pool_idle_connections: meter
            .i64_up_down_counter("dfguard.pool.idle.connections")
            .build(),
        acl_entries: meter.i64_up_down_counter("dfguard.acl.entries").build(),
        tls_resumption_enabled: meter
            .i64_up_down_counter("dfguard.tls.resumption.enabled")
            .build(),
        downstream_tls_handshake_ms: meter
            .f64_histogram("dfguard.downstream.tls.handshake.ms")
            .build(),
        upstream_tcp_connect_ms: meter
            .f64_histogram("dfguard.upstream.tcp.connect.ms")
            .build(),
        upstream_tls_handshake_ms: meter
            .f64_histogram("dfguard.upstream.tls.handshake.ms")
            .build(),
        upstream_auth_ms: meter.f64_histogram("dfguard.upstream.auth.ms").build(),
        upstream_roundtrip_ms: meter.f64_histogram("dfguard.upstream.roundtrip.ms").build(),
        session_pinned_ms: meter.f64_histogram("dfguard.session.pinned.ms").build(),
        downstream_command_size_bytes: meter
            .u64_histogram("dfguard.downstream.command.size_bytes")
            .build(),
        upstream_response_size_bytes: meter
            .u64_histogram("dfguard.upstream.response.size_bytes")
            .build(),
    }
}

async fn start_metrics_server(metrics_listen: &str, readiness: Arc<AtomicBool>) -> Result<()> {
    let listener = TcpListener::bind(metrics_listen)
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
    readiness: Arc<AtomicBool>,
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
            if readiness.load(Ordering::Relaxed) {
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

#[allow(clippy::too_many_lines)]
async fn handle_connection(
    socket: TcpStream,
    server_rx: watch::Receiver<Arc<ServerConfig>>,
    acl_rx: watch::Receiver<Arc<HashMap<String, AclEntry>>>,
    config: Arc<Config>,
    upstream_pool: Arc<UpstreamPool>,
) -> Result<()> {
    let server_config = server_rx.borrow().clone();
    let acceptor = TlsAcceptor::from(server_config);
    let handshake_timeout = Duration::from_secs(config.handshake_timeout_secs);
    let idle_timeout = idle_timeout_from_secs(config.idle_timeout_secs);
    let handshake_started = tokio::time::Instant::now();
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
                upstream_pool.release(&key, pinned_conn.conn).await;
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
                    started: tokio::time::Instant::now(),
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
            let started = tokio::time::Instant::now();
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
                let reauth_started = tokio::time::Instant::now();
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
                upstream_pool.release(&key, pinned_conn.conn).await;
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
        let started = tokio::time::Instant::now();
        let response = read_upstream_response(&mut conn, idle_timeout, max_frame_size).await?;
        upstream_pool
            .telemetry
            .observe_upstream_roundtrip_ms(&frame.command, started.elapsed());
        upstream_pool
            .telemetry
            .observe_response_size(response.len(), class);
        downstream.write_all(&response).await?;
        upstream_pool.release(&key, conn).await;
    }
}

impl UpstreamPool {
    async fn checkout(&self, key: &PoolKey, password: Option<&str>) -> Result<UpstreamConn> {
        if let Some(conn) = {
            let mut idle = self.idle.lock().await;
            idle.get_mut(key).and_then(Vec::pop)
        } {
            self.telemetry.pool_checkout_hit();
            self.telemetry.pool_idle_delta(-1);
            return Ok(conn);
        }
        self.telemetry.pool_checkout_miss();
        self.connect_new(key, password).await
    }

    async fn release(&self, key: &PoolKey, conn: UpstreamConn) {
        if !conn.read_buf.is_empty() {
            self.telemetry
                .pool_release_dropped(PoolDropReason::ReadBufNotEmpty.as_str());
            return;
        }

        let mut idle = self.idle.lock().await;
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

        let auth_started = tokio::time::Instant::now();
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

fn parse_host_port(input: &str) -> Result<(String, u16)> {
    if let Some(rest) = input.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow!("invalid IPv6 upstream address"))?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("missing port in upstream address"))?;
        let port = port.parse::<u16>().context("invalid port")?;
        return Ok((host.to_string(), port));
    }

    let (host, port) = input
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("upstream must be host:port"))?;
    let port = port.parse::<u16>().context("invalid port")?;
    Ok((host.to_string(), port))
}

fn resolve_addr(addr: &str) -> Result<SocketAddr> {
    addr.to_socket_addrs()
        .context("resolve upstream address")?
        .next()
        .ok_or_else(|| anyhow!("no upstream address resolved"))
}

fn extract_dns_user(tls: &tokio_rustls::server::TlsStream<TcpStream>) -> Result<String> {
    let (_, session) = tls.get_ref();
    let certs = session
        .peer_certificates()
        .ok_or_else(|| anyhow!("no client certificate"))?;
    let cert = certs
        .first()
        .ok_or_else(|| anyhow!("no client certificate"))?;
    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).context("parse client cert")?;
    let san = parsed
        .subject_alternative_name()
        .context("read client SAN")?
        .ok_or_else(|| anyhow!("client certificate missing SAN"))?;

    let mut dns_names = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();

    if dns_names.is_empty() {
        bail!("client certificate missing dNSName SAN");
    }
    if dns_names.len() != 1 {
        bail!("client certificate has multiple dNSName SAN entries");
    }
    Ok(dns_names.remove(0))
}

fn load_acl(path: &Path) -> Result<HashMap<String, AclEntry>> {
    let file = File::open(path).with_context(|| format!("open ACL file {}", path.display()))?;
    let reader = BufReader::new(file);
    parse_acl_lines(reader.lines())
}

fn start_acl_watcher(
    path: PathBuf,
    acl_tx: watch::Sender<Arc<HashMap<String, AclEntry>>>,
    telemetry: Arc<Telemetry>,
) -> Result<notify::RecommendedWatcher> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            let _ = event_tx.send(());
        }
    })
    .context("create ACL watcher")?;

    watcher
        .watch(&path, RecursiveMode::NonRecursive)
        .with_context(|| format!("watch ACL file {}", path.display()))?;

    tokio::spawn(async move {
        while event_rx.recv().await.is_some() {
            debug!("ACL change detected, reloading");
            tokio::time::sleep(Duration::from_millis(200)).await;
            match async { load_acl(&path) }
                .instrument(info_span!("acl_reload", path = %path.display()))
                .await
            {
                Ok(map) => {
                    telemetry.set_acl_entries(map.len());
                    let _ = acl_tx.send(Arc::new(map));
                    telemetry.reload_event("acl", "success");
                    info!("ACL reloaded");
                }
                Err(err) => {
                    telemetry.connection_error("reload", "downstream");
                    telemetry.reload_event("acl", "error");
                    error!("ACL reload failed: {err:#}");
                }
            }
        }
    });

    Ok(watcher)
}

fn start_tls_watcher(
    config: Arc<Config>,
    server_tx: watch::Sender<Arc<ServerConfig>>,
    client_tx: watch::Sender<Arc<ClientConfigs>>,
    telemetry: Arc<Telemetry>,
) -> Result<notify::RecommendedWatcher> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            let _ = event_tx.send(());
        }
    })
    .context("create TLS watcher")?;

    let paths = vec![
        config.server_cert.clone(),
        config.server_key.clone(),
        config.server_ca.clone(),
        config.upstream_cert.clone(),
        config.upstream_key.clone(),
        config.upstream_ca.clone(),
    ];
    for path in &paths {
        watcher
            .watch(path, RecursiveMode::NonRecursive)
            .with_context(|| format!("watch TLS file {}", path.display()))?;
    }

    tokio::spawn(async move {
        while event_rx.recv().await.is_some() {
            debug!("TLS change detected, reloading");
            tokio::time::sleep(Duration::from_millis(200)).await;
            match async { build_server_config(config.as_ref()) }
                .instrument(info_span!("tls_reload_server"))
                .await
            {
                Ok(server_config) => {
                    let _ = server_tx.send(Arc::new(server_config));
                    telemetry.reload_event("tls_server", "success");
                    info!("server TLS config reloaded");
                }
                Err(err) => {
                    telemetry.connection_error("reload", "downstream");
                    telemetry.reload_event("tls_server", "error");
                    error!("server TLS reload failed: {err:#}");
                }
            }

            match async {
                (
                    build_client_config(config.as_ref(), false),
                    build_client_config(config.as_ref(), true),
                )
            }
            .instrument(info_span!("tls_reload_upstream"))
            .await
            {
                (Ok(with_resumption), Ok(no_resumption)) => {
                    let configs = ClientConfigs {
                        with_resumption: Arc::new(with_resumption),
                        no_resumption: Arc::new(no_resumption),
                    };
                    let _ = client_tx.send(Arc::new(configs));
                    telemetry.set_tls_resumption_enabled(true);
                    telemetry.reload_event("tls_upstream", "success");
                    info!("upstream TLS config reloaded");
                }
                (Err(err), _) | (_, Err(err)) => {
                    telemetry.connection_error("reload", "upstream");
                    telemetry.reload_event("tls_upstream", "error");
                    error!("upstream TLS reload failed: {err:#}");
                }
            }
        }
    });

    Ok(watcher)
}

fn parse_acl_lines<I>(lines: I) -> Result<HashMap<String, AclEntry>>
where
    I: Iterator<Item = std::io::Result<String>>,
{
    let mut map = HashMap::new();

    for (line_num, line) in lines.enumerate() {
        let line = line.with_context(|| format!("read ACL line {}", line_num + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let line = match trimmed.split_once('#') {
            Some((left, _)) => left.trim(),
            None => trimmed,
        };
        if line.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            bail!("invalid ACL line {}: expected 'USER <name>'", line_num + 1);
        }
        if !tokens[0].eq_ignore_ascii_case("USER") {
            bail!(
                "invalid ACL line {}: only USER entries are supported",
                line_num + 1
            );
        }
        let user = tokens[1].to_string();
        let mut password: Option<String> = None;
        let mut saw_nopass = false;
        for token in tokens.iter().skip(2) {
            if let Some(rest) = token.strip_prefix('>')
                && !rest.is_empty()
            {
                password = Some(rest.to_string());
            }
            if token.eq_ignore_ascii_case("nopass") {
                saw_nopass = true;
            }
        }
        if !saw_nopass && password.is_none() {
            bail!("invalid ACL line {}: missing password", line_num + 1);
        }

        if map.contains_key(&user) {
            bail!("duplicate ACL entry for user {user}");
        }
        map.insert(user, AclEntry { password });
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::{
        CommandClass, FrameInfo, SessionState, apply_command_state_after_response,
        apply_command_state_before_send, classify_command, idle_timeout_from_secs, parse_acl_lines,
        parse_resp_frame_len, should_reauth_after_reset,
    };

    fn frame(command: &str, args: &[&str]) -> FrameInfo {
        FrameInfo {
            len: 0,
            is_auth: false,
            command: command.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
        }
    }

    #[test]
    fn acl_last_password_wins() {
        let input = vec![
            Ok("USER svc ON >first >second +@all ~*".to_string()),
            Ok("# comment".to_string()),
        ];
        let map = parse_acl_lines(input.into_iter()).expect("parse ACL");
        assert_eq!(
            map.get("svc").and_then(|entry| entry.password.as_deref()),
            Some("second")
        );
    }

    #[test]
    fn acl_duplicate_user_errors() {
        let input = vec![
            Ok("USER svc ON >one +@all ~*".to_string()),
            Ok("USER svc ON >two +@all ~*".to_string()),
        ];
        let err = parse_acl_lines(input.into_iter()).expect_err("duplicate user should error");
        assert!(err.to_string().contains("duplicate ACL entry"));
    }

    #[test]
    fn acl_namespace_token_supported() {
        let input = vec![Ok(
            "USER user1 NAMESPACE:namespace1 ON >user_pass +@all ~*".to_string()
        )];
        let map = parse_acl_lines(input.into_iter()).expect("parse ACL");
        assert_eq!(
            map.get("user1").and_then(|entry| entry.password.as_deref()),
            Some("user_pass")
        );
    }

    #[test]
    fn acl_rejects_setuser_format() {
        let input = vec![Ok("ACL SETUSER user1 ON >user_pass +@all ~*".to_string())];
        let err = parse_acl_lines(input.into_iter()).expect_err("invalid ACL format should error");
        assert!(err.to_string().contains("only USER entries are supported"));
    }

    #[test]
    fn classify_tracking_on_pins_temporarily() {
        let frame = frame("CLIENT", &["TRACKING", "ON"]);
        assert_eq!(classify_command(&frame), CommandClass::PinTemporary);
    }

    #[test]
    fn classify_xread_block_pins_while_blocking() {
        let frame = frame("XREAD", &["BLOCK", "5000"]);
        assert_eq!(classify_command(&frame), CommandClass::PinWhileBlocking);
    }

    #[test]
    fn unpin_after_exec_clears_transaction_state() {
        let mut state = SessionState::default();
        let multi = frame("MULTI", &[]);
        let exec = frame("EXEC", &[]);

        apply_command_state_before_send(&mut state, &multi, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &multi,
            CommandClass::PinTemporary,
            b"+OK\r\n",
        );
        assert!(!state.can_unpin());

        apply_command_state_before_send(&mut state, &exec, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &exec,
            CommandClass::PinTemporary,
            b"*0\r\n",
        );
        assert!(state.can_unpin());
    }

    #[test]
    fn watch_then_unwatch_unpins() {
        let mut state = SessionState::default();
        let watch = frame("WATCH", &["key"]);
        let unwatch = frame("UNWATCH", &[]);

        apply_command_state_before_send(&mut state, &watch, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &watch,
            CommandClass::PinTemporary,
            b"+OK\r\n",
        );
        assert!(!state.can_unpin());

        apply_command_state_before_send(&mut state, &unwatch, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &unwatch,
            CommandClass::PinTemporary,
            b"+OK\r\n",
        );
        assert!(state.can_unpin());
    }

    #[test]
    fn tracking_on_error_does_not_taint_state() {
        let mut state = SessionState::default();
        let tracking_on = frame("CLIENT", &["TRACKING", "ON"]);

        apply_command_state_before_send(&mut state, &tracking_on, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &tracking_on,
            CommandClass::PinTemporary,
            b"-ERR syntax error\r\n",
        );

        assert!(state.can_unpin());
    }

    #[test]
    fn blocking_state_clears_after_reply() {
        let mut state = SessionState::default();
        let blpop = frame("BLPOP", &["q", "10"]);

        apply_command_state_before_send(&mut state, &blpop, CommandClass::PinWhileBlocking);
        assert!(!state.can_unpin());

        apply_command_state_after_response(
            &mut state,
            &blpop,
            CommandClass::PinWhileBlocking,
            b"-ERR timeout\r\n",
        );
        assert!(state.can_unpin());
    }

    #[test]
    fn reset_clears_all_session_state() {
        let mut state = SessionState::default();
        let multi = frame("MULTI", &[]);
        let watch = frame("WATCH", &["k"]);
        let subscribe = frame("SUBSCRIBE", &["events"]);
        let blocking = frame("BLPOP", &["q", "10"]);
        let reset = frame("RESET", &[]);

        apply_command_state_before_send(&mut state, &multi, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &multi,
            CommandClass::PinTemporary,
            b"+OK\r\n",
        );
        apply_command_state_before_send(&mut state, &watch, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &watch,
            CommandClass::PinTemporary,
            b"+OK\r\n",
        );
        apply_command_state_before_send(&mut state, &subscribe, CommandClass::PinForever);
        apply_command_state_after_response(
            &mut state,
            &subscribe,
            CommandClass::PinForever,
            b"*3\r\n$9\r\nsubscribe\r\n$6\r\nevents\r\n:1\r\n",
        );
        apply_command_state_before_send(&mut state, &blocking, CommandClass::PinWhileBlocking);
        apply_command_state_after_response(
            &mut state,
            &blocking,
            CommandClass::PinWhileBlocking,
            b"$-1\r\n",
        );
        assert!(!state.can_unpin());

        apply_command_state_before_send(&mut state, &reset, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &reset,
            CommandClass::PinTemporary,
            b"+RESET\r\n",
        );

        assert!(state.can_unpin());
    }

    #[test]
    fn resp3_push_len_parses() {
        let frame = b">3\r\n+message\r\n$7\r\nchannel\r\n$5\r\nhello\r\n";
        let len = parse_resp_frame_len(frame)
            .expect("parse")
            .expect("complete frame");
        assert_eq!(len, frame.len());
    }

    #[test]
    fn resp3_map_len_parses() {
        let frame = b"%2\r\n+key1\r\n:1\r\n+key2\r\n$3\r\nval\r\n";
        let len = parse_resp_frame_len(frame)
            .expect("parse")
            .expect("complete frame");
        assert_eq!(len, frame.len());
    }

    #[test]
    fn reset_success_requires_reauth() {
        let reset = frame("RESET", &[]);
        assert!(should_reauth_after_reset(&reset, b"+RESET\r\n"));
    }

    #[test]
    fn reset_error_does_not_require_reauth() {
        let reset = frame("RESET", &[]);
        assert!(!should_reauth_after_reset(
            &reset,
            b"-ERR unknown command\r\n"
        ));
    }

    #[test]
    fn idle_timeout_zero_disables_timeout() {
        assert_eq!(idle_timeout_from_secs(0), None);
    }

    #[test]
    fn idle_timeout_positive_enables_timeout() {
        assert_eq!(
            idle_timeout_from_secs(300),
            Some(std::time::Duration::from_secs(300))
        );
    }
}

fn build_server_config(config: &Config) -> Result<ServerConfig> {
    let certs = load_certs(&config.server_cert)?;
    let key = load_private_key(&config.server_key)?;
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&config.server_ca)? {
        roots.add(cert).context("add server CA")?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
        .build()
        .context("build client cert verifier")?;
    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("build server TLS config")?;
    Ok(server_config)
}

fn build_client_config(config: &Config, disable_resumption: bool) -> Result<ClientConfig> {
    let certs = load_certs(&config.upstream_cert)?;
    let key = load_private_key(&config.upstream_key)?;
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&config.upstream_ca)? {
        roots.add(cert).context("add upstream CA")?;
    }
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("build upstream TLS config")?;

    if config.insecure_upstream {
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(InsecureVerifier));
    }
    if disable_resumption {
        client_config.resumption = rustls::client::Resumption::disabled();
    }
    Ok(client_config)
}

#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem_data =
        std::fs::read(path).with_context(|| format!("read cert file {}", path.display()))?;
    let blocks = pem::parse_many(pem_data).context("parse cert PEM")?;
    let mut certs = Vec::new();
    for block in blocks {
        if block.tag() == "CERTIFICATE" {
            certs.push(CertificateDer::from(block.contents().to_vec()));
        }
    }
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let pem_data =
        std::fs::read(path).with_context(|| format!("read key file {}", path.display()))?;
    let blocks = pem::parse_many(pem_data).context("parse key PEM")?;
    for block in blocks {
        let key = match block.tag() {
            "PRIVATE KEY" => {
                let key = PrivatePkcs8KeyDer::from(block.contents().to_vec());
                PrivateKeyDer::from(key)
            }
            "RSA PRIVATE KEY" => {
                let key = PrivatePkcs1KeyDer::from(block.contents().to_vec());
                PrivateKeyDer::from(key)
            }
            "EC PRIVATE KEY" => {
                let key = PrivateSec1KeyDer::from(block.contents().to_vec());
                PrivateKeyDer::from(key)
            }
            _ => continue,
        };
        return Ok(key);
    }
    bail!("no private key found in {}", path.display())
}

async fn send_auth(
    upstream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    user: &str,
    password: Option<&str>,
) -> Result<()> {
    let payload = build_auth_command(user, password);
    upstream.write_all(&payload).await?;

    let mut buffer = Vec::with_capacity(128);
    let mut temp = [0u8; 64];
    loop {
        let n = upstream.read(&mut temp).await?;
        if n == 0 {
            bail!("upstream closed connection during AUTH");
        }
        buffer.extend_from_slice(&temp[..n]);
        if let Some(pos) = find_crlf(&buffer) {
            let line = &buffer[..pos];
            if line.starts_with(b"-") {
                let msg = String::from_utf8_lossy(line);
                bail!("upstream AUTH error: {msg}");
            }
            return Ok(());
        }
        if buffer.len() > 1024 {
            bail!("unexpected AUTH response size");
        }
    }
}

fn build_auth_command(user: &str, password: Option<&str>) -> Vec<u8> {
    if let Some(password) = password {
        let mut out = Vec::with_capacity(64 + user.len() + password.len());
        out.extend_from_slice(b"*3\r\n");
        push_bulk(&mut out, b"AUTH");
        push_bulk(&mut out, user.as_bytes());
        push_bulk(&mut out, password.as_bytes());
        out
    } else {
        let mut out = Vec::with_capacity(48 + user.len());
        out.extend_from_slice(b"*2\r\n");
        push_bulk(&mut out, b"AUTH");
        push_bulk(&mut out, user.as_bytes());
        out
    }
}

fn push_bulk(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(b"$");
    out.extend_from_slice(data.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

fn parse_command_frame(buf: &BytesMut) -> Result<Option<FrameInfo>> {
    if buf.is_empty() {
        return Ok(None);
    }
    match buf[0] {
        b'*' => parse_array_frame(buf),
        b'+' | b'-' | b':' | b'$' => bail!("unsupported frame type from client"),
        _ => parse_inline_frame(buf),
    }
}

fn parse_inline_frame(buf: &BytesMut) -> Result<Option<FrameInfo>> {
    let Some(line_end) = find_crlf(buf) else {
        return Ok(None);
    };
    let line = &buf[..line_end];
    let mut iter = line
        .split(u8::is_ascii_whitespace)
        .filter(|s| !s.is_empty());
    let cmd = iter.next().ok_or_else(|| anyhow!("empty inline command"))?;
    let is_auth = cmd.eq_ignore_ascii_case(b"AUTH");
    let command = to_upper_ascii_string(cmd);
    let args = iter.take(8).map(to_upper_ascii_string).collect();
    Ok(Some(FrameInfo {
        len: line_end + 2,
        is_auth,
        command,
        args,
    }))
}

fn parse_array_frame(buf: &BytesMut) -> Result<Option<FrameInfo>> {
    let mut idx = 1;
    let Some(line_end) = find_crlf_from(buf, idx) else {
        return Ok(None);
    };
    let count = parse_number(&buf[idx..line_end])?;
    if count <= 0 {
        bail!("invalid array length");
    }
    idx = line_end + 2;

    let mut is_auth = false;
    let mut command = String::new();
    let mut args = Vec::new();
    for i in 0..count {
        if idx >= buf.len() {
            return Ok(None);
        }
        if buf[idx] != b'$' {
            bail!("unsupported array element type");
        }
        idx += 1;
        let Some(bulk_len_end) = find_crlf_from(buf, idx) else {
            return Ok(None);
        };
        let bulk_len = parse_number(&buf[idx..bulk_len_end])?;
        if bulk_len < 0 {
            bail!("null bulk not supported for command");
        }
        let bulk_len = usize::try_from(bulk_len).context("bulk length too large")?;
        idx = bulk_len_end + 2;
        if idx + bulk_len + 2 > buf.len() {
            return Ok(None);
        }
        if i == 0 {
            let cmd = &buf[idx..idx + bulk_len];
            is_auth = cmd.eq_ignore_ascii_case(b"AUTH");
            command = to_upper_ascii_string(cmd);
        } else if args.len() < 8 {
            args.push(to_upper_ascii_string(&buf[idx..idx + bulk_len]));
        }
        idx += bulk_len + 2;
    }

    Ok(Some(FrameInfo {
        len: idx,
        is_auth,
        command,
        args,
    }))
}

fn to_upper_ascii_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_ascii_uppercase()
}

async fn read_next_command_frame(
    downstream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    buffer: &mut BytesMut,
    idle_timeout: Option<Duration>,
    max_frame_size: usize,
) -> Result<Option<(FrameInfo, Vec<u8>)>> {
    let mut read_buf = [0u8; 8192];
    loop {
        if let Some(frame) = parse_command_frame(buffer)? {
            if frame.len > max_frame_size {
                bail!("frame exceeds max size");
            }
            let data = buffer.split_to(frame.len).to_vec();
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
) -> Result<Vec<u8>> {
    let mut read_buf = [0u8; 8192];
    loop {
        if let Some(len) = parse_resp_frame_len(&upstream.read_buf)? {
            if len > max_frame_size {
                bail!("response frame exceeds max size");
            }
            return Ok(upstream.read_buf.split_to(len).to_vec());
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

fn parse_resp_frame_len(buf: &[u8]) -> Result<Option<usize>> {
    parse_resp_frame_len_from(buf, 0)
}

fn parse_resp_frame_len_from(buf: &[u8], start: usize) -> Result<Option<usize>> {
    if start >= buf.len() {
        return Ok(None);
    }

    match buf[start] {
        b'+' | b'-' | b':' | b',' | b'(' | b'#' => Ok(parse_resp_line_len(buf, start)),
        b'_' => {
            if start + 3 > buf.len() {
                return Ok(None);
            }
            if &buf[start + 1..start + 3] == b"\r\n" {
                Ok(Some(3))
            } else {
                bail!("invalid RESP null frame")
            }
        }
        b'$' => parse_resp_sized_payload_len(buf, start, -1, "invalid bulk length"),
        b'=' | b'!' => parse_resp_sized_payload_len(buf, start, 0, "invalid payload length"),
        b'*' | b'~' | b'>' | b'|' => parse_resp_aggregate_len(buf, start, 1),
        b'%' => parse_resp_aggregate_len(buf, start, 2),
        _ => bail!("unsupported RESP response type"),
    }
}

fn parse_resp_line_len(buf: &[u8], start: usize) -> Option<usize> {
    let line_end = find_crlf_from(buf, start + 1)?;
    Some(line_end + 2 - start)
}

fn parse_resp_sized_payload_len(
    buf: &[u8],
    start: usize,
    min_allowed: i64,
    invalid_msg: &str,
) -> Result<Option<usize>> {
    let Some(line_end) = find_crlf_from(buf, start + 1) else {
        return Ok(None);
    };
    let payload_len = parse_number(&buf[start + 1..line_end])?;
    if min_allowed == -1 && payload_len == -1 {
        return Ok(Some(line_end + 2 - start));
    }
    if payload_len < min_allowed {
        bail!("{invalid_msg}");
    }
    let payload_len = usize::try_from(payload_len).context("payload length too large")?;
    let total = line_end + 2 + payload_len + 2;
    if total > buf.len() {
        return Ok(None);
    }
    Ok(Some(total - start))
}

fn parse_resp_aggregate_len(
    buf: &[u8],
    start: usize,
    child_multiplier: usize,
) -> Result<Option<usize>> {
    let Some(line_end) = find_crlf_from(buf, start + 1) else {
        return Ok(None);
    };

    let count = parse_number(&buf[start + 1..line_end])?;
    if count == -1 {
        return Ok(Some(line_end + 2 - start));
    }
    if count < -1 {
        bail!("invalid aggregate length");
    }

    let count = usize::try_from(count).context("aggregate length too large")?;
    let children = count
        .checked_mul(child_multiplier)
        .ok_or_else(|| anyhow!("aggregate length too large"))?;

    let mut idx = line_end + 2;
    for _ in 0..children {
        let Some(next_len) = parse_resp_frame_len_from(buf, idx)? else {
            return Ok(None);
        };
        idx += next_len;
    }
    Ok(Some(idx - start))
}

fn classify_command(frame: &FrameInfo) -> CommandClass {
    let cmd = frame.command.as_str();
    match cmd {
        "MULTI" | "WATCH" | "UNWATCH" | "EXEC" | "DISCARD" | "RESET" => CommandClass::PinTemporary,
        "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE" | "MONITOR" | "SELECT" => {
            CommandClass::PinForever
        }
        "BLPOP" | "BRPOP" | "BRPOPLPUSH" | "BZPOPMIN" | "BZPOPMAX" => {
            CommandClass::PinWhileBlocking
        }
        "CLIENT" if frame.args.first().is_some_and(|arg| arg == "TRACKING") => {
            CommandClass::PinTemporary
        }
        "XREAD" | "XREADGROUP" if frame.args.iter().any(|arg| arg == "BLOCK") => {
            CommandClass::PinWhileBlocking
        }
        _ => CommandClass::Stateless,
    }
}

fn apply_command_state_before_send(
    state: &mut SessionState,
    _frame: &FrameInfo,
    class: CommandClass,
) {
    match class {
        CommandClass::PinWhileBlocking => state.blocking = BlockingState::Waiting,
        CommandClass::Stateless | CommandClass::PinTemporary | CommandClass::PinForever => {}
    }
}

fn apply_command_state_after_response(
    state: &mut SessionState,
    frame: &FrameInfo,
    class: CommandClass,
    response: &[u8],
) {
    if matches!(class, CommandClass::PinWhileBlocking) && !response.is_empty() {
        state.blocking = BlockingState::Idle;
    }

    if is_error_response(response) {
        return;
    }

    let cmd = frame.command.as_str();
    match class {
        CommandClass::PinForever => state.sticky = StickyState::On,
        CommandClass::PinWhileBlocking | CommandClass::PinTemporary | CommandClass::Stateless => {}
    }

    match cmd {
        "MULTI" => state.txn = TxnState::InMulti,
        "WATCH" => state.watch = WatchState::On,
        "UNWATCH" => state.watch = WatchState::Off,
        "EXEC" | "DISCARD" => {
            state.txn = TxnState::None;
            state.watch = WatchState::Off;
        }
        "CLIENT"
            if frame.args.first().is_some_and(|arg| arg == "TRACKING")
                && frame.args.get(1).is_some_and(|arg| arg == "ON") =>
        {
            state.tracking = TrackingState::On;
        }
        "CLIENT"
            if frame.args.first().is_some_and(|arg| arg == "TRACKING")
                && frame.args.get(1).is_some_and(|arg| arg == "OFF") =>
        {
            state.tracking = TrackingState::Off;
        }
        "RESET" => {
            *state = SessionState::default();
        }
        _ => {}
    }
}

fn is_error_response(response: &[u8]) -> bool {
    response.first().copied() == Some(b'-') || response.first().copied() == Some(b'!')
}

fn should_reauth_after_reset(frame: &FrameInfo, response: &[u8]) -> bool {
    frame.command == "RESET" && !is_error_response(response)
}

fn close_reason_from_io_error(err: &anyhow::Error) -> &'static str {
    let msg = err.to_string();
    if msg.contains("idle timeout") {
        "idle_timeout"
    } else if msg.contains("partial frame") {
        "partial_frame"
    } else if msg.contains("upstream closed") {
        "upstream_closed"
    } else {
        "error"
    }
}

fn parse_number(slice: &[u8]) -> Result<i64> {
    let s = std::str::from_utf8(slice).context("invalid number")?;
    let n = s.parse::<i64>().context("invalid number")?;
    Ok(n)
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    find_crlf_from(buf, 0)
}

fn find_crlf_from(buf: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

struct FrameInfo {
    len: usize,
    is_auth: bool,
    command: String,
    args: Vec<String>,
}

async fn connect_upstream(
    connector: &TlsConnector,
    addr: SocketAddr,
    server_name: ServerName<'static>,
    timeout_duration: Duration,
    telemetry: &Telemetry,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp_started = tokio::time::Instant::now();
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
    telemetry.observe_upstream_tcp_connect_ms(tcp_started.elapsed(), "success");

    let tls_started = tokio::time::Instant::now();
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

fn parse_server_name(host: &str) -> Result<ServerName<'static>> {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Ok(ServerName::IpAddress(ip.into())),
        Err(_) => {
            ServerName::try_from(host.to_string()).context("invalid upstream hostname for TLS")
        }
    }
}

fn should_retry_without_resumption(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(rustls::Error::AlertReceived(desc)) = cause.downcast_ref::<rustls::Error>()
            && *desc == AlertDescription::InternalError
        {
            return true;
        }
    }
    err.to_string().contains("InternalError")
}

fn idle_timeout_from_secs(secs: u64) -> Option<Duration> {
    if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    }
}

fn is_tls_handshake_eof(err: &dyn std::error::Error) -> bool {
    let mut current: Option<&dyn std::error::Error> = Some(err);
    while let Some(cause) = current {
        if cause.to_string().contains("tls handshake eof") {
            return true;
        }
        current = cause.source();
    }
    false
}
