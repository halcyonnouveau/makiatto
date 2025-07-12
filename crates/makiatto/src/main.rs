use makiatto::{config, corrosion, dns, wireguard};
use miette::Result;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

    // peers excluding ourself
    let peers = corrosion::get_peers(&config).ok().as_ref().map(|p| {
        p.iter()
            .filter(|peer| peer.name != config.node.name)
            .cloned()
            .collect::<Vec<_>>()
            .into()
    });

    let (_wg_manager, wg_handle) = wireguard::setup_wireguard(&config, peers)?;

    let (tripwire, tripwire_worker) = tripwire::Tripwire::new_signals();
    let mut handles = vec![];

    let wg_task = tokio::spawn(async move {
        match wg_handle.await {
            Ok(Ok(())) => Ok("wireguard"),
            Ok(Err(e)) => Err(format!("WireGuard failed: {e}")),
            Err(e) => Err(format!("WireGuard task panicked: {e}")),
        }
    });
    handles.push(wg_task);

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

    let (_dns_manager, dns_handle) = if config.node.is_nameserver {
        info!("Starting DNS server...");
        let (dns_manager, dns_task) = dns::setup_dns(config.clone(), tripwire.clone())?;
        (
            Some(dns_manager),
            Some(tokio::spawn(async move {
                match dns_task.await {
                    Ok(Ok(())) => Ok("dns"),
                    Ok(Err(e)) => Err(format!("DNS server failed: {e}")),
                    Err(e) => Err(format!("DNS task panicked: {e}")),
                }
            })),
        )
    } else {
        (None, None)
    };

    if let Some(handle) = dns_handle {
        handles.push(handle);
    }

    // TODO: Spawn other services (web, file sync)

    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| miette::miette!("Failed to setup SIGTERM handler: {e}"))?;

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            match result {
                Ok(()) => {
                    info!("Received SIGINT, shutting down...");
                    drop(tripwire_worker);
                }
                Err(e) => return Err(miette::miette!("Failed to listen for ctrl+c: {e}")),
            }
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down...");
            drop(tripwire_worker);
        }
        result = futures::future::join_all(handles) => {
            for (i, res) in result.into_iter().enumerate() {
                match res {
                    Ok(Ok(service)) => info!("Service '{service}' stopped cleanly"),
                    Ok(Err(e)) => {
                        tracing::error!("Service failed: {e}");
                        return Err(miette::miette!(e));
                    }
                    Err(e) => {
                        tracing::error!("Service task panicked: {e}");
                        return Err(miette::miette!("Service task {i} panicked: {e}"));
                    }
                }
            }
            info!("All services stopped");
        }
    }

    Ok(())
}
