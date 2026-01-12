use std::sync::Arc;
use std::time::Duration;

use miette::Result;
use opentelemetry::{
    global,
    trace::{SamplingDecision, SamplingResult, TraceContextExt, TracerProvider},
};
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    logs::SdkLoggerProvider,
    metrics::{Aggregation, Instrument, PeriodicReader, SdkMeterProvider, Stream, Temporality},
    trace::{Sampler, SdkTracerProvider},
};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;

/// Smart sampler that ensures all error and slow spans are captured
/// while applying ratio-based sampling to regular spans
#[derive(Debug, Clone)]
pub struct SmartSampler {
    base_sampler: Sampler,
}

impl SmartSampler {
    #[must_use]
    pub fn new(base_ratio: f64) -> Self {
        Self {
            base_sampler: Sampler::TraceIdRatioBased(base_ratio),
        }
    }
}

impl opentelemetry_sdk::trace::ShouldSample for SmartSampler {
    fn should_sample(
        &self,
        parent_context: Option<&opentelemetry::Context>,
        trace_id: opentelemetry::trace::TraceId,
        name: &str,
        span_kind: &opentelemetry::trace::SpanKind,
        attributes: &[opentelemetry::KeyValue],
        links: &[opentelemetry::trace::Link],
    ) -> SamplingResult {
        for attr in attributes {
            let key = attr.key.as_str();
            if key == "error" || key == "slow" {
                // always sample spans with `error` or `slow` attributes
                return SamplingResult {
                    decision: SamplingDecision::RecordAndSample,
                    attributes: Vec::new(),
                    trace_state: parent_context
                        .map(|ctx| ctx.span().span_context().trace_state().clone())
                        .unwrap_or_default(),
                };
            }
        }

        self.base_sampler.should_sample(
            parent_context,
            trace_id,
            name,
            span_kind,
            attributes,
            links,
        )
    }
}

/// Discover the OTLP endpoint by looking for an external peer with "o11y" in the name
async fn discover_o11y_endpoint(db_path: &std::path::Path) -> Option<Arc<str>> {
    if !db_path.exists() {
        return None;
    }

    let db_url = format!("sqlite:{}?mode=ro", db_path.display());
    let pool = sqlx::SqlitePool::connect(&db_url).await.ok()?;

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT wg_address FROM peers WHERE is_external = 1 AND (name LIKE 'o11y%' OR name LIKE '%o11y') LIMIT 1"
    )
    .fetch_optional(&pool)
    .await
    .ok()?;

    row.map(|(wg_address,)| Arc::from(format!("http://{wg_address}:4317")))
}

/// Initialise observability
///
/// # Errors
/// Returns an error if initialisation fails
pub async fn init(config: &Config) -> Result<()> {
    let o11y = &config.o11y;
    let node = &config.node;

    // Resolve endpoint: explicit config > auto-discovery > None (no OTLP export)
    let endpoint = if let Some(ep) = &o11y.otlp_endpoint {
        Some(ep.clone())
    } else {
        let db_path = config.corrosion.db.path.as_std_path();
        discover_o11y_endpoint(db_path).await
    };

    let resource = Resource::builder()
        .with_service_name(format!("makiatto.{}", node.name))
        .build();

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("makiatto=info,corro_agent=info"));

    let fmt_layer = tracing_subscriber::fmt::layer();

    // If we have an endpoint and any export is enabled, set up OTLP
    let (tracer_provider, logger_provider, metrics_enabled) = if let Some(ref ep) = endpoint {
        let metrics = if o11y.metrics_enabled {
            init_metrics(ep, resource.clone())?;
            true
        } else {
            false
        };

        let logger = if o11y.logging_enabled {
            Some(init_logging(ep, resource.clone())?)
        } else {
            None
        };

        let tracer = if o11y.tracing_enabled {
            Some(init_tracer(ep, o11y.sampling_ratio, resource)?)
        } else {
            None
        };

        (tracer, logger, metrics)
    } else {
        (None, None, false)
    };

    let has_tracing = tracer_provider.is_some();
    let has_logging = logger_provider.is_some();

    match (tracer_provider, logger_provider) {
        (Some(tracer), Some(logger)) => {
            let trace_layer = tracing_opentelemetry::layer().with_tracer(tracer.tracer("makiatto"));
            let log_layer =
                opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&logger);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(trace_layer)
                .with(log_layer)
                .init();
        }
        (Some(tracer), None) => {
            let trace_layer = tracing_opentelemetry::layer().with_tracer(tracer.tracer("makiatto"));
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(trace_layer)
                .init();
        }
        (None, Some(logger)) => {
            let log_layer =
                opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&logger);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(log_layer)
                .init();
        }
        (None, None) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
    }

    // Log after tracing is set up
    if let Some(ref ep) = endpoint
        && (has_tracing || has_logging || metrics_enabled)
    {
        info!(
            endpoint = %ep,
            tracing = has_tracing,
            logging = has_logging,
            metrics = metrics_enabled,
            "OpenTelemetry export enabled"
        );
    }

    Ok(())
}

/// Initialise OpenTelemetry tracer
fn init_tracer(
    endpoint: &str,
    sampling_ratio: f64,
    resource: Resource,
) -> Result<SdkTracerProvider> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| miette::miette!("Failed to create OTLP span exporter: {e}"))?;

    let tracer_provider = SdkTracerProvider::builder()
        .with_sampler(SmartSampler::new(sampling_ratio))
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    Ok(tracer_provider)
}

/// Initialise OpenTelemetry logging
fn init_logging(endpoint: &str, resource: Resource) -> Result<SdkLoggerProvider> {
    let exporter = LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| miette::miette!("Failed to create OTLP log exporter: {e}"))?;

    let logger_provider = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    Ok(logger_provider)
}

/// Initialise OpenTelemetry metrics
fn init_metrics(endpoint: &str, resource: Resource) -> Result<()> {
    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_temporality(Temporality::Cumulative)
        .build()
        .map_err(|e| miette::miette!("Failed to create OTLP metrics exporter: {e}"))?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(30))
        .build();

    // Custom histogram buckets for duration metrics (in seconds)
    // Standard OTel semantic convention boundaries
    let duration_histogram_buckets = vec![
        0.0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
    ];

    let duration_view = move |instrument: &Instrument| {
        if instrument.name().ends_with(".duration") {
            Stream::builder()
                .with_name(instrument.name().to_string())
                .with_aggregation(Aggregation::ExplicitBucketHistogram {
                    boundaries: duration_histogram_buckets.clone(),
                    record_min_max: true,
                })
                .build()
                .ok()
        } else {
            None
        }
    };

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .with_view(duration_view)
        .build();

    global::set_meter_provider(provider);

    Ok(())
}
