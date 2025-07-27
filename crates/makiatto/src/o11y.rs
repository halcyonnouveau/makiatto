use std::time::Duration;

use miette::Result;
use opentelemetry::{
    global,
    trace::{SamplingDecision, SamplingResult, TraceContextExt, TracerProvider},
};
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider, Temporality},
    trace::{Sampler, SdkTracerProvider},
};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{Config, ObservabilityConfig};

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
        // Check attributes for error or slow indicators
        for attr in attributes {
            let key = attr.key.as_str();
            if key == "error" || key == "slow" {
                // Always sample spans with error or slow attributes
                return SamplingResult {
                    decision: SamplingDecision::RecordAndSample,
                    attributes: Vec::new(),
                    trace_state: parent_context
                        .map(|ctx| ctx.span().span_context().trace_state().clone())
                        .unwrap_or_default(),
                };
            }
        }

        // For everything else, use base sampler
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

/// Initialise observability
///
/// # Errors
/// Returns an error if initialisation fails
pub fn init(Config { o11y, node, .. }: &Config) -> Result<()> {
    let resource = Resource::builder()
        .with_service_name(format!("makaitto.{}", node.name))
        .build();

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("makiatto=info,corro_agent=info"));

    let fmt_layer = tracing_subscriber::fmt::layer();

    if o11y.tracing_enabled || o11y.metrics_enabled {
        info!("Initialising OpenTelemetry to {}", o11y.otlp_endpoint);
    }

    let tracer_provider = if o11y.tracing_enabled {
        Some(init_tracer(o11y, resource.clone())?)
    } else {
        None
    };

    if o11y.metrics_enabled {
        init_metrics(o11y, resource)?;
    }

    if let Some(provider) = tracer_provider {
        let otel_layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("makiatto"));

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    }

    Ok(())
}

/// Initialise OpenTelemetry tracer
fn init_tracer(config: &ObservabilityConfig, resource: Resource) -> Result<SdkTracerProvider> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(config.otlp_endpoint.to_string())
        .build()
        .map_err(|e| miette::miette!("Failed to create OTLP span exporter: {e}"))?;

    let tracer_provider = SdkTracerProvider::builder()
        .with_sampler(SmartSampler::new(config.sampling_ratio))
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    Ok(tracer_provider)
}

/// Initialise OpenTelemetry metrics
fn init_metrics(config: &ObservabilityConfig, resource: Resource) -> Result<()> {
    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(config.otlp_endpoint.to_string())
        .with_temporality(Temporality::Cumulative)
        .build()
        .map_err(|e| miette::miette!("Failed to create OTLP metrics exporter: {e}"))?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(30))
        .build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    global::set_meter_provider(provider);

    Ok(())
}
