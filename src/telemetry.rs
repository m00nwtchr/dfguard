use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider, UpDownCounter};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tonic::transport::{Certificate, ClientTlsConfig, Identity};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::cli::ProxyConfig;
use crate::cli::TunnelConfig;

#[derive(Clone)]
pub struct Telemetry {
    pub otel_metrics: Option<Arc<OTelMetrics>>,
    pub tls_resumption_enabled: Arc<std::sync::atomic::AtomicI64>,
    pub acl_entries: Arc<std::sync::atomic::AtomicI64>,
}

pub struct OTelRuntime {
    pub _tracer: Option<SdkTracerProvider>,
    pub _meter: Option<SdkMeterProvider>,
    pub _logger: Option<SdkLoggerProvider>,
}

pub struct OTelMetrics {
    pub conn_accepted: Counter<u64>,
    pub errors: Counter<u64>,
    pub conn_closed: Counter<u64>,
    pub auth_blocked: Counter<u64>,
    pub commands_total: Counter<u64>,
    pub commands_rejected: Counter<u64>,
    pub pin_transitions: Counter<u64>,
    pub session_unpin: Counter<u64>,
    pub session_reauth_after_reset: Counter<u64>,
    pub session_reauth_after_reset_failures: Counter<u64>,
    pub upstream_auth_failures: Counter<u64>,
    pub pool_checkout_hit: Counter<u64>,
    pub pool_checkout_miss: Counter<u64>,
    pub pool_connect_new: Counter<u64>,
    pub pool_release_dropped: Counter<u64>,
    pub reload_events: Counter<u64>,
    pub active_connections: UpDownCounter<i64>,
    pub pool_idle_connections: UpDownCounter<i64>,
    pub acl_entries: UpDownCounter<i64>,
    pub tls_resumption_enabled: UpDownCounter<i64>,
    pub downstream_tls_handshake_ms: Histogram<f64>,
    pub upstream_tcp_connect_ms: Histogram<f64>,
    pub upstream_tls_handshake_ms: Histogram<f64>,
    pub upstream_auth_ms: Histogram<f64>,
    pub upstream_roundtrip_ms: Histogram<f64>,
    pub session_pinned_ms: Histogram<f64>,
    pub downstream_command_size_bytes: Histogram<u64>,
    pub upstream_response_size_bytes: Histogram<u64>,
}

impl Telemetry {
    pub fn new() -> Self {
        Self {
            otel_metrics: None,
            tls_resumption_enabled: Arc::new(std::sync::atomic::AtomicI64::new(1)),
            acl_entries: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        }
    }

    pub fn set_otel(&mut self, metrics: Arc<OTelMetrics>) {
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

    pub fn set_acl_entries(&self, size: usize) {
        let Ok(size) = i64::try_from(size) else {
            return;
        };
        let prev = self.acl_entries.swap(size, Ordering::Relaxed);
        if let Some(metrics) = &self.otel_metrics {
            metrics.acl_entries.add(size - prev, &[]);
        }
    }

    pub fn set_tls_resumption_enabled(&self, enabled: bool) {
        let value = i64::from(enabled);
        let prev = self.tls_resumption_enabled.swap(value, Ordering::Relaxed);
        if let Some(metrics) = &self.otel_metrics {
            metrics.tls_resumption_enabled.add(value - prev, &[]);
        }
    }

    pub fn connection_accepted(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.conn_accepted.add(1, &[]);
            metrics.active_connections.add(1, &[]);
        }
    }

    pub fn connection_closed(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.active_connections.add(-1, &[]);
        }
    }

    pub fn connection_error(&self, stage: &'static str, direction: &'static str) {
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

    pub fn connection_closed_reason(&self, reason: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics
                .conn_closed
                .add(1, &[KeyValue::new("close.reason", reason)]);
        }
    }

    pub fn auth_blocked(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.auth_blocked.add(1, &[]);
            metrics
                .commands_rejected
                .add(1, &[KeyValue::new("reason", "auth_disabled")]);
        }
    }

    pub fn command_classified(&self, command: &str, class: crate::types::CommandClass) {
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

    pub fn pin_transition(&self, from: &'static str, to: &'static str, reason: &'static str) {
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

    pub fn session_unpin(&self, reason: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics
                .session_unpin
                .add(1, &[KeyValue::new("reason", reason)]);
        }
    }

    pub fn reload_event(&self, kind: &'static str, status: &'static str) {
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

    pub fn observe_upstream_roundtrip_ms(&self, command: &str, elapsed: Duration) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.upstream_roundtrip_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("redis.command", command.to_string())],
            );
        }
    }

    pub fn observe_downstream_handshake_ms(&self, elapsed: Duration, status: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.downstream_tls_handshake_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("status", status)],
            );
        }
    }

    pub fn observe_upstream_tcp_connect_ms(&self, elapsed: Duration, status: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.upstream_tcp_connect_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("status", status)],
            );
        }
    }

    pub fn observe_upstream_tls_handshake_ms(&self, elapsed: Duration, status: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.upstream_tls_handshake_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("status", status)],
            );
        }
    }

    pub fn observe_upstream_auth_ms(&self, elapsed: Duration, status: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.upstream_auth_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("status", status)],
            );
        }
    }

    pub fn upstream_auth_failure(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.upstream_auth_failures.add(1, &[]);
        }
    }

    pub fn observe_pinned_duration_ms(&self, elapsed: Duration, reason: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.session_pinned_ms.record(
                elapsed.as_secs_f64() * 1000.0,
                &[KeyValue::new("reason", reason)],
            );
        }
    }

    pub fn observe_command_size(&self, size: usize, class: crate::types::CommandClass) {
        if let Some(metrics) = &self.otel_metrics
            && let Ok(size) = u64::try_from(size)
        {
            metrics
                .downstream_command_size_bytes
                .record(size, &[KeyValue::new("route.class", class.as_str())]);
        }
    }

    pub fn observe_response_size(&self, size: usize, class: crate::types::CommandClass) {
        if let Some(metrics) = &self.otel_metrics
            && let Ok(size) = u64::try_from(size)
        {
            metrics
                .upstream_response_size_bytes
                .record(size, &[KeyValue::new("route.class", class.as_str())]);
        }
    }

    pub fn pool_checkout_hit(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.pool_checkout_hit.add(1, &[]);
        }
    }

    pub fn pool_checkout_miss(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.pool_checkout_miss.add(1, &[]);
        }
    }

    pub fn pool_connect_new(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.pool_connect_new.add(1, &[]);
        }
    }

    pub fn pool_idle_delta(&self, delta: i64) {
        if delta == 0 {
            return;
        }
        if let Some(metrics) = &self.otel_metrics {
            metrics.pool_idle_connections.add(delta, &[]);
        }
    }

    pub fn pool_release_dropped(&self, reason: &'static str) {
        if let Some(metrics) = &self.otel_metrics {
            metrics
                .pool_release_dropped
                .add(1, &[KeyValue::new("reason", reason)]);
        }
    }

    pub fn reauth_after_reset_attempt(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.session_reauth_after_reset.add(1, &[]);
        }
    }

    pub fn reauth_after_reset_failure(&self) {
        if let Some(metrics) = &self.otel_metrics {
            metrics.session_reauth_after_reset_failures.add(1, &[]);
        }
    }
}

pub fn build_otel_metrics(meter: &Meter) -> OTelMetrics {
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

pub fn init_telemetry_proxy(
    config: &ProxyConfig,
    filter: EnvFilter,
    telemetry: &mut Telemetry,
) -> OTelRuntime {
    let resource = Resource::builder()
        .with_service_name(
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "dfguard".to_string()),
        )
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .with_attribute(KeyValue::new("dfguard.listen", config.listen.to_string()))
        .build();

    init_telemetry(resource, filter, telemetry)
}

pub fn init_telemetry_tunnel(
    config: &TunnelConfig,
    filter: EnvFilter,
    telemetry: &mut Telemetry,
) -> OTelRuntime {
    let resource = Resource::builder()
        .with_service_name(
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "dfguard".to_string()),
        )
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .with_attribute(KeyValue::new("dfguard.mode", "tunnel"))
        .with_attribute(KeyValue::new("dfguard.listen", config.listen.to_string()))
        .with_attribute(KeyValue::new("dfguard.upstream", config.upstream.clone()))
        .build();

    init_telemetry(resource, filter, telemetry)
}

fn init_telemetry(resource: Resource, filter: EnvFilter, telemetry: &mut Telemetry) -> OTelRuntime {
    let sdk_disabled = std::env::var("OTEL_SDK_DISABLED").is_ok_and(|value| value == "true");
    if sdk_disabled
        || !["TRACES", "METRICS", "LOGS"]
            .iter()
            .any(|signal| otlp_setting_with(signal, "ENDPOINT", &env_otlp_setting).is_some())
    {
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

    let tracer = build_tracer(&resource);
    let meter = build_meter(&resource, telemetry);
    let logger = build_logger(resource);

    let tracer_layer = tracer.as_ref().ok().map(|(provider, _)| {
        tracing_opentelemetry::layer().with_tracer(provider.tracer("dfguard"))
    });
    let log_layer = logger.as_ref().ok().map(|(provider, _)| {
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(provider)
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(tracer_layer)
        .with(log_layer)
        .init();

    let results: [(&str, Result<&OtlpSettings, &anyhow::Error>); 3] = [
        ("traces", tracer.as_ref().map(|(_, settings)| settings)),
        ("metrics", meter.as_ref().map(|(_, settings)| settings)),
        ("logs", logger.as_ref().map(|(_, settings)| settings)),
    ];
    for (signal, result) in results {
        report_signal_result(signal, result);
    }

    OTelRuntime {
        _tracer: tracer.ok().map(|(provider, _)| provider),
        _meter: meter.ok().map(|(provider, _)| provider),
        _logger: logger.ok().map(|(provider, _)| provider),
    }
}

fn report_signal_result(signal: &str, result: Result<&OtlpSettings, &anyhow::Error>) {
    match result {
        Ok(settings) => tracing::info!(
            signal,
            endpoint = %settings.endpoint,
            tls = settings.tls,
            "OTLP exporter configured"
        ),
        Err(error) => tracing::warn!(
            signal,
            error = %format_args!("{error:#}"),
            "failed to initialise OTLP exporter"
        ),
    }
}

fn build_tracer(resource: &Resource) -> Result<(SdkTracerProvider, OtlpSettings)> {
    configure_otlp(
        opentelemetry_otlp::SpanExporter::builder().with_tonic(),
        "TRACES",
    )
    .and_then(|(builder, settings)| {
        builder
            .build()
            .map(|exporter| {
                let provider = SdkTracerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(resource.clone())
                    .build();
                (provider, settings)
            })
            .map_err(Into::into)
    })
    .inspect(|(provider, _)| opentelemetry::global::set_tracer_provider(provider.clone()))
}

fn build_meter(
    resource: &Resource,
    telemetry: &mut Telemetry,
) -> Result<(SdkMeterProvider, OtlpSettings)> {
    configure_otlp(
        opentelemetry_otlp::MetricExporter::builder().with_tonic(),
        "METRICS",
    )
    .and_then(|(builder, settings)| {
        builder
            .build()
            .map(|exporter| {
                let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter).build();
                let provider = SdkMeterProvider::builder()
                    .with_reader(reader)
                    .with_resource(resource.clone())
                    .build();
                opentelemetry::global::set_meter_provider(provider.clone());
                let meter = provider.meter("dfguard");
                telemetry.set_otel(Arc::new(build_otel_metrics(&meter)));
                (provider, settings)
            })
            .map_err(Into::into)
    })
}

fn build_logger(resource: Resource) -> Result<(SdkLoggerProvider, OtlpSettings)> {
    configure_otlp(
        opentelemetry_otlp::LogExporter::builder().with_tonic(),
        "LOGS",
    )
    .and_then(|(builder, settings)| {
        builder
            .build()
            .map(|exporter| {
                let provider = SdkLoggerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(resource)
                    .build();
                (provider, settings)
            })
            .map_err(Into::into)
    })
}

fn configure_otlp<B: WithExportConfig + WithTonicConfig>(
    builder: B,
    signal: &str,
) -> Result<(B, OtlpSettings)> {
    let settings = resolve_otlp(signal, &env_otlp_setting)?;

    let builder = builder.with_endpoint(settings.endpoint.clone());
    if !settings.tls {
        return Ok((builder, settings));
    }

    // Tonic needs explicit TLS configuration here and an unbracketed IPv6 address.
    let mut tls = ClientTlsConfig::new().domain_name(&settings.host);
    tls = match &settings.ca_path {
        Some(path) => tls.ca_certificate(Certificate::from_pem(read_otlp_pem(path)?)),
        None => tls.with_webpki_roots(),
    };

    if let (Some(cert_path), Some(key_path)) =
        (&settings.client_cert_path, &settings.client_key_path)
    {
        tls = tls.identity(Identity::from_pem(
            read_otlp_pem(cert_path)?,
            read_otlp_pem(key_path)?,
        ));
    }

    Ok((builder.with_tls_config(tls), settings))
}

/// Endpoint and TLS configuration resolved from the `OTEL_EXPORTER_OTLP_*`
/// environment for a single signal.
#[derive(Debug, PartialEq, Eq)]
struct OtlpSettings {
    endpoint: String,
    /// Host for the TLS handshake (SNI), with IPv6 brackets stripped.
    host: String,
    /// Whether the exporter uses TLS (an `https://` scheme or a bare endpoint).
    tls: bool,
    ca_path: Option<String>,
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
}

fn env_otlp_setting(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn resolve_otlp(signal: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<OtlpSettings> {
    let endpoint = otlp_setting_with(signal, "ENDPOINT", env)
        .unwrap_or_else(|| "http://localhost:4317".to_owned());
    let (scheme, target) = match endpoint.split_once("://") {
        Some((scheme, target)) if scheme.eq_ignore_ascii_case("http") => ("http", target),
        Some((scheme, target)) if scheme.eq_ignore_ascii_case("https") => ("https", target),
        Some(_) => bail!("OTLP endpoint for {signal} must use http or https, got {endpoint:?}"),
        None => {
            let insecure = otlp_setting_with(signal, "INSECURE", env)
                .is_some_and(|value| value.eq_ignore_ascii_case("true"));
            (if insecure { "http" } else { "https" }, endpoint.as_str())
        }
    };

    let endpoint = format!("{scheme}://{target}");
    let uri: http::Uri = endpoint
        .parse()
        .with_context(|| format!("invalid OTLP endpoint URL for {signal}: {endpoint}"))?;
    let host = uri
        .host()
        .with_context(|| format!("OTLP endpoint URL for {signal} has no host: {endpoint}"))?;

    let ca_path = otlp_setting_with(signal, "CERTIFICATE", env);
    let client_cert_path = otlp_setting_with(signal, "CLIENT_CERTIFICATE", env);
    let client_key_path = otlp_setting_with(signal, "CLIENT_KEY", env);
    if client_cert_path.is_some() != client_key_path.is_some() {
        bail!("OTLP mTLS for {signal} requires both CLIENT_CERTIFICATE and CLIENT_KEY");
    }

    Ok(OtlpSettings {
        endpoint,
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        tls: scheme == "https",
        ca_path,
        client_cert_path,
        client_key_path,
    })
}

fn otlp_setting_with(
    signal: &str,
    setting: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    // Blank values are treated as unset, matching the SDK's env handling.
    let read = |name: &str| env(name).filter(|value| !value.trim().is_empty());
    read(&format!("OTEL_EXPORTER_OTLP_{signal}_{setting}"))
        .or_else(|| read(&format!("OTEL_EXPORTER_OTLP_{setting}")))
}

fn read_otlp_pem(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("failed to read OTLP TLS file {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_string())
        }
    }

    #[test]
    fn http_endpoint_stays_plaintext() {
        let settings = resolve_otlp(
            "TRACES",
            &env_from(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")]),
        )
        .unwrap();
        assert_eq!(settings.endpoint, "http://collector:4317");
        assert!(!settings.tls);
        assert_eq!(settings.host, "collector");
    }

    #[test]
    fn https_endpoint_enables_tls() {
        let settings = resolve_otlp(
            "TRACES",
            &env_from(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4317")]),
        )
        .unwrap();
        assert!(settings.tls);
        assert_eq!(settings.host, "collector");
    }

    #[test]
    fn bare_endpoint_defaults_to_tls() {
        let settings = resolve_otlp(
            "TRACES",
            &env_from(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4317")]),
        )
        .unwrap();
        assert_eq!(settings.endpoint, "https://collector:4317");
        assert!(settings.tls);
    }

    #[test]
    fn bare_endpoint_with_insecure_uses_plaintext() {
        let settings = resolve_otlp(
            "TRACES",
            &env_from(&[
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4317"),
                ("OTEL_EXPORTER_OTLP_INSECURE", "TRUE"),
            ]),
        )
        .unwrap();
        assert_eq!(settings.endpoint, "http://collector:4317");
        assert!(!settings.tls);
    }

    #[test]
    fn https_scheme_wins_over_insecure() {
        let settings = resolve_otlp(
            "TRACES",
            &env_from(&[
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4317"),
                ("OTEL_EXPORTER_OTLP_INSECURE", "true"),
            ]),
        )
        .unwrap();
        assert!(settings.tls);
    }

    #[test]
    fn unknown_scheme_is_rejected() {
        let error = resolve_otlp(
            "TRACES",
            &env_from(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "grpc://collector:4317")]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("grpc://collector:4317"));
    }

    #[test]
    fn signal_specific_endpoint_overrides_shared() {
        let env = env_from(&[
            ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://traces:4317"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://shared:4317"),
        ]);
        let traces = resolve_otlp("TRACES", &env).unwrap();
        assert_eq!(traces.endpoint, "https://traces:4317");
        let metrics = resolve_otlp("METRICS", &env).unwrap();
        assert_eq!(metrics.endpoint, "http://shared:4317");
    }

    #[test]
    fn missing_signal_endpoint_falls_back_to_default() {
        let settings = resolve_otlp(
            "TRACES",
            &env_from(&[(
                "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
                "https://metrics:4317",
            )]),
        )
        .unwrap();
        assert_eq!(settings.endpoint, "http://localhost:4317");
        assert!(!settings.tls);
    }

    #[test]
    fn empty_values_are_treated_as_unset() {
        let settings = resolve_otlp(
            "TRACES",
            &env_from(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "  ")]),
        )
        .unwrap();
        assert_eq!(settings.endpoint, "http://localhost:4317");
    }

    #[test]
    fn ipv6_host_is_unbracketed() {
        let settings = resolve_otlp(
            "TRACES",
            &env_from(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "https://[::1]:4317")]),
        )
        .unwrap();
        assert_eq!(settings.host, "::1");
        assert!(settings.tls);
    }

    #[test]
    fn endpoint_without_host_is_rejected() {
        assert!(
            resolve_otlp(
                "TRACES",
                &env_from(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "https://")]),
            )
            .is_err()
        );
    }

    #[test]
    fn half_configured_mtls_is_rejected_even_for_plaintext() {
        let error = resolve_otlp(
            "TRACES",
            &env_from(&[
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317"),
                ("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "/tmp/client.pem"),
            ]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("CLIENT_CERTIFICATE"));
    }

    #[test]
    fn mtls_pair_is_accepted() {
        let settings = resolve_otlp(
            "TRACES",
            &env_from(&[
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4317"),
                ("OTEL_EXPORTER_OTLP_CERTIFICATE", "/tmp/ca.pem"),
                ("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "/tmp/client.pem"),
                ("OTEL_EXPORTER_OTLP_CLIENT_KEY", "/tmp/client.key"),
            ]),
        )
        .unwrap();
        assert_eq!(settings.ca_path.as_deref(), Some("/tmp/ca.pem"));
        assert_eq!(
            settings.client_cert_path.as_deref(),
            Some("/tmp/client.pem")
        );
        assert_eq!(settings.client_key_path.as_deref(), Some("/tmp/client.key"));
    }
}
