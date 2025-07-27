use std::time::Duration;

use miette::Result;
use opentelemetry::{global, trace::TracerProvider};
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider, Temporality},
    trace::{Sampler, SdkTracerProvider},
};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::ObservabilityConfig;

/// Initialise observability
///
/// # Errors
/// Returns an error if initialisation fails
pub fn init(config: &ObservabilityConfig) -> Result<()> {
    let resource = Resource::builder()
        .with_service_name(config.service_name.to_string())
        .build();

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("makiatto=info,corro_agent=info"));

    let fmt_layer = tracing_subscriber::fmt::layer();

    if config.tracing_enabled || config.metrics_enabled {
        info!("Initialising OpenTelemetry to {}", config.otlp_endpoint);
    }

    let tracer_provider = if config.tracing_enabled {
        Some(init_tracer(config, resource.clone())?)
    } else {
        None
    };

    if config.metrics_enabled {
        init_metrics(config, resource)?;
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
        .with_sampler(Sampler::TraceIdRatioBased(config.sampling_ratio))
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
