use std::sync::Arc;

use argh::FromArgs;
use makiatto::{
    cache::CacheStore,
    config,
    corrosion::{self, consensus::DirectorElection, subscriptions::SubscriptionWatcher},
    fs, service, web,
    web::certificate::{CertificateManager, CertificateStore},
    wireguard,
};
use miette::Result;
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::mpsc,
};
use tracing::{error, info};

#[derive(FromArgs)]
#[allow(clippy::struct_excessive_bools)]
/// Makiatto network daemon
struct Args {
    /// disable wireguard interface setup
    #[argh(switch)]
    no_wireguard: bool,

    /// disable dns server
    #[argh(switch)]
    no_dns: bool,

    /// disable axum server
    #[argh(switch)]
    no_axum: bool,

    /// disable corrosion database
    #[argh(switch)]
    no_corrosion: bool,

    /// disable file sync services
    #[argh(switch)]
    no_fs: bool,

    /// only run specific services (comma-separated: wireguard,dns,axum,corrosion,fs)
    #[argh(option)]
    only: Option<String>,
}

#[allow(clippy::struct_excessive_bools)]
struct ServiceFlags {
    wireguard: bool,
    dns: bool,
    axum: bool,
    corrosion: bool,
    fs: bool,
}

impl ServiceFlags {
    fn from_args(args: &Args) -> Self {
        if let Some(only_services) = &args.only {
            let services: std::collections::HashSet<&str> = only_services.split(',').collect();
            Self {
                wireguard: services.contains("wireguard"),
                dns: services.contains("dns"),
                axum: services.contains("axum"),
                corrosion: services.contains("corrosion"),
                fs: services.contains("fs"),
            }
        } else {
            Self {
                wireguard: !args.no_wireguard,
                dns: !args.no_dns,
                axum: !args.no_axum,
                corrosion: !args.no_corrosion,
                fs: !args.no_fs,
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = argh::from_env();
    let services = ServiceFlags::from_args(&args);

    let config = Arc::new(config::load()?);
    makiatto::o11y::init(&config)?;

    info!("Starting makiatto...");

    let (tripwire, tripwire_worker) = tripwire::Tripwire::new_signals();
    info!("Loaded config for node '{}'", config.node.name);
    info!(
        "Services enabled: wireguard={}, dns={}, web={}, corrosion={}, fs={}",
        services.wireguard, services.dns, services.axum, services.corrosion, services.fs
    );

    let (dns_restart_tx, dns_restart_rx) = mpsc::channel(100);
    let (axum_restart_tx, axum_restart_rx) = mpsc::channel(100);

    let cache_store = CacheStore::new(&config.node.data_dir)?;
    let mut handles = vec![];

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

    let wg_manager = if services.wireguard {
        let (wg_mgr, wg_handle) = wireguard::setup(&config).await?;
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

    if services.corrosion && config.consensus.enabled {
        info!("Starting director election...");
        let director_election = Arc::new(DirectorElection::new(config.clone()));

        let consensus_tripwire = tripwire.clone();
        let director_clone = director_election.clone();
        let consensus_handle = tokio::spawn(async move {
            director_clone.run(consensus_tripwire).await;
            Ok("consensus")
        });
        handles.push(consensus_handle);

        info!("Starting subscription watcher...");
        let subscription_watcher = SubscriptionWatcher::new(
            config.clone(),
            cache_store.clone(),
            director_election.clone(),
            wg_manager,
            dns_restart_tx,
            axum_restart_tx,
        );

        let sub_tripwire = tripwire.clone();
        let subscription_handle = tokio::spawn(async move {
            subscription_watcher.run(sub_tripwire).await;
            Ok("subscriptions")
        });
        handles.push(subscription_handle);

        // Start certificate manager for ACME renewal
        info!("Starting certificate manager...");
        let cert_store = Arc::new(CertificateStore::new());
        let cert_manager = CertificateManager::new(config.clone(), director_election, cert_store)?;

        let cert_tripwire = tripwire.clone();
        let cert_handle = tokio::spawn(async move {
            cert_manager.run(cert_tripwire).await;
            Ok("certificate_manager")
        });
        handles.push(cert_handle);
    }

    let (dns_manager, dns_handle) = if services.dns && config.node.is_nameserver {
        info!("Starting dns server...");
        let (dns_mgr, dns_task) = service::setup(
            "dns",
            config.clone(),
            tripwire.clone(),
            |config, tripwire| async move { web::dns::start(config, tripwire).await },
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
            tokio::spawn(service::handle_restarts("dns", dns_restart_rx, dns_mgr));
        handles.push(dns_restart_handle);
    }

    let (axum_manager, axum_handle) = if services.axum {
        info!("Starting axum server...");

        let (axum_manager, axum_handle) =
            service::setup("axum", config.clone(), tripwire.clone(), {
                move |config, tripwire| async move { web::axum::start(config, tripwire).await }
            })?;
        (
            Some(axum_manager),
            Some(tokio::spawn(async move {
                match axum_handle.await {
                    Ok(Ok(())) => Ok("axum"),
                    Ok(Err(e)) => Err(format!("axum server failed: {e}")),
                    Err(e) => Err(format!("axum server task panicked: {e}")),
                }
            })),
        )
    } else {
        (None, None)
    };

    if let Some(handle) = axum_handle {
        handles.push(handle);
    }

    // handle axum restart signals with debouncing
    if let Some(axum_mgr) = axum_manager {
        let axum_restart_handle =
            tokio::spawn(service::handle_restarts("axum", axum_restart_rx, axum_mgr));
        handles.push(axum_restart_handle);
    }

    // start file sync services
    if services.fs && config.fs.enabled {
        info!("Starting file sync services...");

        // Run startup reconciliation to ensure filesystem matches database
        info!("Running startup filesystem reconciliation...");
        if let Err(e) = fs::reconcile::run_once(config.clone()).await {
            error!("Startup reconciliation failed: {e}");
            return Err(e);
        }

        let file_sync_config = config.clone();
        let (fs_shutdown_tx, fs_shutdown_rx) = mpsc::channel(1);
        let file_sync_handle = tokio::spawn(async move {
            match fs::start(file_sync_config, fs_shutdown_rx).await {
                Ok(()) => Ok("fs_http"),
                Err(e) => Err(format!("File sync HTTP server failed: {e}")),
            }
        });
        handles.push(file_sync_handle);

        let file_watcher_config = config.clone();
        let (fw_shutdown_tx, fw_shutdown_rx) = mpsc::channel(1);
        let file_watcher_handle = tokio::spawn(async move {
            match fs::watcher::start(file_watcher_config, fw_shutdown_rx).await {
                Ok(()) => Ok("fs_watcher"),
                Err(e) => Err(format!("File watcher failed: {e}")),
            }
        });
        handles.push(file_watcher_handle);

        let reconcile_config = config.clone();
        let (reconcile_shutdown_tx, reconcile_shutdown_rx) = mpsc::channel(1);
        let reconcile_handle = tokio::spawn(async move {
            match fs::reconcile::start(reconcile_config, reconcile_shutdown_rx).await {
                Ok(()) => Ok("fs_reconcile"),
                Err(e) => Err(format!("Filesystem reconciliation failed: {e}")),
            }
        });
        handles.push(reconcile_handle);

        let file_sync_shutdowns = vec![fs_shutdown_tx, fw_shutdown_tx, reconcile_shutdown_tx];
        let shutdown_handle = tripwire.clone();
        tokio::spawn(async move {
            shutdown_handle.await;
            for tx in file_sync_shutdowns {
                let _ = tx.send(()).await;
            }
        });
    }

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
