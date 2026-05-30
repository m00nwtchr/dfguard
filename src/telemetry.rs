use std::sync::Arc;
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider, UpDownCounter};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::sync::atomic::Ordering;
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

    let _opentelemetry_otlp = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .map(|exporter| {
            opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(resource.clone())
                .build()
        })
        .and_then(|provider| {
            opentelemetry::global::set_tracer_provider(provider.clone());
            tracer_provider = Some(provider.clone());
            Ok(provider)
        })
        .ok();

    let _opentelemetry_otlp = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .build()
        .map(|exporter| {
            let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter).build();
            opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                .with_reader(reader)
                .with_resource(resource.clone())
                .build()
        })
        .and_then(|provider| {
            opentelemetry::global::set_meter_provider(provider.clone());
            let meter = provider.meter("dfguard");
            telemetry.set_otel(Arc::new(build_otel_metrics(&meter)));
            meter_provider = Some(provider.clone());
            Ok(provider)
        })
        .ok();

    let _opentelemetry_otlp = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .build()
        .map(|exporter| {
            opentelemetry_sdk::logs::SdkLoggerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(resource)
                .build()
        })
        .and_then(|provider| {
            logger_provider = Some(provider.clone());
            Ok(provider)
        })
        .ok();

    let tracer_layer = tracer_provider
        .as_ref()
        .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("dfguard")));
    let log_layer = logger_provider
        .as_ref()
        .map(opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new);

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

    let _opentelemetry_otlp = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .map(|exporter| {
            opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(resource.clone())
                .build()
        })
        .and_then(|provider| {
            opentelemetry::global::set_tracer_provider(provider.clone());
            tracer_provider = Some(provider.clone());
            Ok(provider)
        })
        .ok();

    let _opentelemetry_otlp = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .build()
        .map(|exporter| {
            let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter).build();
            opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                .with_reader(reader)
                .with_resource(resource.clone())
                .build()
        })
        .and_then(|provider| {
            opentelemetry::global::set_meter_provider(provider.clone());
            let meter = provider.meter("dfguard");
            telemetry.set_otel(Arc::new(build_otel_metrics(&meter)));
            meter_provider = Some(provider.clone());
            Ok(provider)
        })
        .ok();

    let _opentelemetry_otlp = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .build()
        .map(|exporter| {
            opentelemetry_sdk::logs::SdkLoggerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(resource)
                .build()
        })
        .and_then(|provider| {
            logger_provider = Some(provider.clone());
            Ok(provider)
        })
        .ok();

    let tracer_layer = tracer_provider
        .as_ref()
        .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("dfguard")));
    let log_layer = logger_provider
        .as_ref()
        .map(opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new);

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
