use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use makiatto::{
    cache::CacheStore,
    config,
    corrosion::{self, subscriptions::SubscriptionWatcher},
    dns, wireguard,
};
use miette::Result;
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::mpsc,
};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[allow(clippy::too_many_lines)]
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

    let (tripwire, tripwire_worker) = tripwire::Tripwire::new_signals();
    let (dns_restart_tx, mut dns_restart_rx) = mpsc::channel(100);

    let cache_store = CacheStore::new(&config.node.data_dir)?;
    let mut handles = vec![];

    // peers excluding ourself
    let peers = corrosion::get_peers(&config).ok().as_ref().map(|p| {
        p.iter()
            .filter(|peer| peer.name != config.node.name)
            .cloned()
            .collect::<Vec<_>>()
            .into()
    });

    let (wg_manager, wg_handle) = wireguard::setup_wireguard(&config, peers)?;

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

    info!("Starting subscription watcher...");
    let subscription_watcher = SubscriptionWatcher::new(
        Arc::new(config.clone()),
        cache_store,
        dns_restart_tx,
        wg_manager,
    );

    let sub_tripwire = tripwire.clone();
    let subscription_handle = tokio::spawn(async move {
        subscription_watcher.run(sub_tripwire).await;
        Ok("subscriptions")
    });
    handles.push(subscription_handle);

    let (dns_manager, dns_handle) = if config.node.is_nameserver {
        info!("Starting DNS server...");
        let (dns_mgr, dns_task) = dns::setup_dns(config.clone(), tripwire.clone())?;
        (
            Some(dns_mgr),
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

    // handle dns restart signals with debouncing
    if let Some(dns_mgr) = dns_manager.clone() {
        let dns_restart_handle = tokio::spawn(async move {
            let restart_pending = Arc::new(AtomicBool::new(false));

            while let Some(()) = dns_restart_rx.recv().await {
                if !restart_pending.swap(true, Ordering::SeqCst) {
                    let dns_mgr_clone = dns_mgr.clone();
                    let restart_pending_clone = restart_pending.clone();

                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                        if let Err(e) = dns_mgr_clone.restart().await {
                            tracing::error!("Failed to restart DNS server: {e}");
                        } else {
                            info!("DNS server restarted");
                        }

                        restart_pending_clone.store(false, Ordering::SeqCst);
                    });
                }
            }
            Ok("dns_restart_handler")
        });
        handles.push(dns_restart_handle);
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
