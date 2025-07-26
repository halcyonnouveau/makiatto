use std::sync::Arc;

use argh::FromArgs;
use makiatto::{
    cache::CacheStore,
    config,
    corrosion::{self, subscriptions::SubscriptionWatcher},
    dns,
    service::{handle_service_restarts, setup_service},
    web, wireguard,
};
use miette::Result;
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::mpsc,
};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(FromArgs)]
#[allow(clippy::struct_excessive_bools)]
/// Makiatto network daemon
struct Args {
    /// disable `WireGuard` interface setup
    #[argh(switch)]
    no_wireguard: bool,

    /// disable DNS server
    #[argh(switch)]
    no_dns: bool,

    /// disable web server
    #[argh(switch)]
    no_web: bool,

    /// disable Corrosion database
    #[argh(switch)]
    no_corrosion: bool,

    /// only run specific services (comma-separated: wireguard,dns,web,corrosion)
    #[argh(option)]
    only: Option<String>,
}

#[allow(clippy::struct_excessive_bools)]
struct ServiceFlags {
    wireguard: bool,
    dns: bool,
    web: bool,
    corrosion: bool,
}

impl ServiceFlags {
    fn from_args(args: &Args) -> Self {
        if let Some(only_services) = &args.only {
            let services: std::collections::HashSet<&str> = only_services.split(',').collect();
            Self {
                wireguard: services.contains("wireguard"),
                dns: services.contains("dns"),
                web: services.contains("web"),
                corrosion: services.contains("corrosion"),
            }
        } else {
            Self {
                wireguard: !args.no_wireguard,
                dns: !args.no_dns,
                web: !args.no_web,
                corrosion: !args.no_corrosion,
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = argh::from_env();
    let services = ServiceFlags::from_args(&args);

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "makiatto=info,corro_agent=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting makiatto...");

    let config = config::load()?;
    info!("Loaded config for node '{}'", config.node.name);
    info!(
        "Services enabled: wireguard={}, dns={}, web={}, corrosion={}",
        services.wireguard, services.dns, services.web, services.corrosion
    );

    let (tripwire, tripwire_worker) = tripwire::Tripwire::new_signals();
    let (dns_restart_tx, dns_restart_rx) = mpsc::channel(100);
    let (_web_restart_tx, web_restart_rx) = mpsc::channel(100);

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

    let wg_manager = if services.wireguard {
        let (wg_mgr, wg_handle) = wireguard::setup_wireguard(&config, peers)?;
        let wg_task = tokio::spawn(async move {
            match wg_handle.await {
                Ok(Ok(())) => Ok("wireguard"),
                Ok(Err(e)) => Err(format!("WireGuard failed: {e}")),
                Err(e) => Err(format!("WireGuard task panicked: {e}")),
            }
        });
        handles.push(wg_task);
        Some(wg_mgr)
    } else {
        None
    };

    if services.corrosion {
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
    }

    if let Some(wg_mgr) = wg_manager {
        info!("Starting subscription watcher...");
        let subscription_watcher = SubscriptionWatcher::new(
            Arc::new(config.clone()),
            cache_store,
            dns_restart_tx,
            wg_mgr,
        );

        let sub_tripwire = tripwire.clone();
        let subscription_handle = tokio::spawn(async move {
            subscription_watcher.run(sub_tripwire).await;
            Ok("subscriptions")
        });
        handles.push(subscription_handle);
    }

    let (dns_manager, dns_handle) = if services.dns && config.node.is_nameserver {
        info!("Starting dns server...");
        let (dns_mgr, dns_task) = setup_service(
            "dns",
            Arc::new(config.clone()),
            tripwire.clone(),
            |config, tripwire| async move { dns::start_dns_server(config, tripwire).await },
        )?;
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
    if let Some(dns_mgr) = dns_manager {
        let dns_restart_handle =
            tokio::spawn(handle_service_restarts("dns", dns_restart_rx, dns_mgr));
        handles.push(dns_restart_handle);
    }

    let (web_manager, web_handle) = if services.web {
        info!("Starting web server...");
        let (web_manager, web_handle) = setup_service(
            "web",
            Arc::new(config.clone()),
            tripwire.clone(),
            |config, tripwire| async move { web::start_web_server(config, tripwire).await },
        )?;
        (
            Some(web_manager),
            Some(tokio::spawn(async move {
                match web_handle.await {
                    Ok(Ok(())) => Ok("web"),
                    Ok(Err(e)) => Err(format!("Web server failed: {e}")),
                    Err(e) => Err(format!("Web server task panicked: {e}")),
                }
            })),
        )
    } else {
        (None, None)
    };

    if let Some(handle) = web_handle {
        handles.push(handle);
    }

    // handle web restart signals with debouncing
    if let Some(web_mgr) = web_manager {
        let web_restart_handle =
            tokio::spawn(handle_service_restarts("web", web_restart_rx, web_mgr));
        handles.push(web_restart_handle);
    }

    // TODO: Spawn other services (file sync)

    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| miette::miette!("Failed to setup SIGTERM handler: {e}"))?;

    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down...");
            drop(tripwire_worker);
        }
        result = tokio::signal::ctrl_c() => {
            match result {
                Ok(()) => {
                    info!("Received SIGINT, shutting down...");
                    drop(tripwire_worker);
                }
                Err(e) => return Err(miette::miette!("Failed to listen for ctrl+c: {e}")),
            }
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
