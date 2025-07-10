use miette::Result;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod corrosion;
mod dns;
mod utils;
mod wireguard;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "makiatto=info,corro_agent=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting makiatto...");

    let config = config::load()?;
    info!("Loaded config for node '{}'", config.node.name);

    wireguard::setup_interface(&config)?;

    let (tripwire, tripwire_worker) = tripwire::Tripwire::new_signals();
    let mut handles = vec![];

    info!("Starting Corrosion agent...");
    let cfg_corrosion = config.clone();
    let tw_corrosion = tripwire.clone();
    let corrosion_handle = tokio::spawn(async move {
        match corrosion::run(cfg_corrosion, tw_corrosion).await {
            Ok(()) => Ok("corrosion"),
            Err(e) => Err(format!("Corrosion agent failed: {e}")),
        }
    });
    handles.push(corrosion_handle);

    if config.node.is_nameserver {
        info!("Starting DNS server (nameserver enabled)...");
        let cfg_dns = config.clone();
        let tw_dns = tripwire.clone();
        let dns_handle = tokio::spawn(async move {
            match dns::run_dns(cfg_dns, tw_dns).await {
                Ok(()) => Ok("dns"),
                Err(e) => Err(format!("DNS server failed: {e}")),
            }
        });
        handles.push(dns_handle);
    } else {
        info!("DNS server disabled (not a nameserver)");
    }

    // TODO: Spawn other services (web, file sync)

    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| miette::miette!("Failed to setup SIGTERM handler: {}", e))?;

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            match result {
                Ok(()) => {
                    info!("Received SIGINT, shutting down...");
                    drop(tripwire_worker);
                }
                Err(e) => return Err(miette::miette!("Failed to listen for ctrl+c: {}", e)),
            }
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down...");
            drop(tripwire_worker);
        }
        result = futures::future::join_all(handles) => {
            for (i, res) in result.into_iter().enumerate() {
                match res {
                    Ok(Ok(service)) => info!("Service '{}' stopped cleanly", service),
                    Ok(Err(e)) => {
                        tracing::error!("Service failed: {}", e);
                        return Err(miette::miette!("{}", e));
                    }
                    Err(e) => {
                        tracing::error!("Service task panicked: {}", e);
                        return Err(miette::miette!("Service task {} panicked: {}", i, e));
                    }
                }
            }
            info!("All services stopped");
        }
    }

    wireguard::cleanup_interface(&config)?;

    Ok(())
}
