use std::{future::Future, pin::Pin, sync::Arc};

use corro_types::api::QueryEvent;
use corro_types::pubsub::ChangeType;
use futures_util::StreamExt;
use miette::Result;
use tokio::time::{Duration, sleep};
use tracing::{error, info, warn};

use crate::cache::{CacheStore, SubscriptionState};
use crate::config::Config;
use crate::constants::{CORROSION_API_PORT, WIREGUARD_PORT};
use crate::wireguard::WireguardManager;

pub struct SubscriptionWatcher {
    config: Arc<Config>,
    cache_store: CacheStore,
    wireguard_manager: WireguardManager,
    dns_restart_tx: tokio::sync::mpsc::Sender<()>,
}

impl SubscriptionWatcher {
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        cache_store: CacheStore,
        dns_restart_tx: tokio::sync::mpsc::Sender<()>,
        wireguard_manager: WireguardManager,
    ) -> Self {
        Self {
            config,
            cache_store,
            wireguard_manager,
            dns_restart_tx,
        }
    }

    /// Start watching subscriptions
    pub async fn run(&self, mut tripwire: tripwire::Tripwire) {
        let peers_handle = tokio::spawn(Arc::new(self.clone()).watch_peers(tripwire.clone()));
        let dns_handle = tokio::spawn(Arc::new(self.clone()).watch_dns_records(tripwire.clone()));

        tokio::select! {
            () = &mut tripwire => {
                info!("Subscription watcher shutting down");
            }
            res = peers_handle => {
                if let Err(e) = res {
                    error!("Peers watcher task failed: {e}");
                }
            }
            res = dns_handle => {
                if let Err(e) = res {
                    error!("DNS records watcher task failed: {e}");
                }
            }
        }
    }

    /// Watch `peers` table for changes
    async fn watch_peers(self: Arc<Self>, mut tripwire: tripwire::Tripwire) {
        let query = "SELECT name, ipv4, wg_public_key, wg_address FROM peers";
        let state_key = "subscription_peers";

        loop {
            tokio::select! {
                () = &mut tripwire => {
                    info!("Peers watcher shutting down");
                    break;
                }
                result = self.subscribe_and_watch(query, state_key, |event| {
                    let watcher = self.clone();
                    Box::pin(async move { watcher.handle_peers_change(event).await })
                }) => {
                    if let Err(e) = result {
                        warn!("Peers subscription failed: {e}, retrying in 5 seconds");
                    } else {
                        warn!("Peers subscription ended, retrying in 5 seconds");
                    }
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Watch `dns_records` table for changes
    async fn watch_dns_records(self: Arc<Self>, mut tripwire: tripwire::Tripwire) {
        let query = "SELECT domain, name, record_type, base_value FROM dns_records";
        let state_key = "subscription_dns_records";

        loop {
            tokio::select! {
                () = &mut tripwire => {
                    info!("DNS records watcher shutting down");
                    break;
                }
                result = self.subscribe_and_watch(query, state_key, |event| {
                    let watcher = self.clone();
                    Box::pin(async move {
                        watcher.handle_dns_change(event);
                        Ok(())
                    })
                }) => {
                    if let Err(e) = result {
                        warn!("DNS subscription failed: {e}, retrying in 1 seconds");
                    } else {
                        warn!("DNS subscription ended, retrying in 1 seconds");
                    }
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Subscribe to a query and process events
    async fn subscribe_and_watch<F>(&self, query: &str, state_key: &str, handler: F) -> Result<()>
    where
        F: Fn(&QueryEvent) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>,
    {
        let api_base = format!("http://127.0.0.1:{CORROSION_API_PORT}/v1/subscriptions");
        let client = reqwest::Client::new();

        let mut state = self
            .cache_store
            .get_subscription(state_key)
            .await
            .unwrap_or(SubscriptionState {
                query_id: None,
                last_change_id: 0,
            });

        let (url, is_new) = if let Some(query_id) = &state.query_id {
            let from = if state.last_change_id > 0 {
                format!("?from={}", state.last_change_id)
            } else {
                String::new()
            };
            (format!("{api_base}/{query_id}{from}"), false)
        } else {
            (api_base, true)
        };

        info!(
            "Subscribing to query: {state_key} (new: {is_new}, from: {})",
            state.last_change_id
        );

        let response = if is_new {
            client
                .post(&url)
                .header("content-type", "application/json")
                .body(format!("\"{query}\""))
                .send()
                .await
                .map_err(|e| miette::miette!("Failed to create subscription: {e}"))?
        } else {
            client
                .get(&url)
                .send()
                .await
                .map_err(|e| miette::miette!("Failed to reconnect to subscription: {e}"))?
        };

        if is_new
            && let Some(query_id_str) = response.headers().get("corro-query-id")
            && let Ok(query_id_str) = query_id_str.to_str()
        {
            state.query_id = Some(query_id_str.to_string());
            info!("New subscription created with ID: {query_id_str}");

            self.cache_store
                .set_subscription(state_key, state.clone())
                .await?;
        }

        let mut stream = response.bytes_stream();
        let mut buffer = Vec::new();
        let mut last_persist = std::time::Instant::now();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|e| miette::miette!("Failed to read subscription response chunk: {e}"))?;

            buffer.extend_from_slice(&chunk);

            while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                let line = buffer.drain(..=pos).collect::<Vec<_>>();
                let line_str = String::from_utf8_lossy(&line);
                let line_str = line_str.trim();

                if line_str.is_empty() {
                    continue;
                }

                match serde_json::from_str::<QueryEvent>(line_str) {
                    Ok(event) => {
                        if let QueryEvent::Change(_, _, _, change_id) = &event {
                            state.last_change_id = change_id.0;

                            // persist state periodically (every 10 seconds)
                            if last_persist.elapsed() > Duration::from_secs(10) {
                                self.cache_store
                                    .set_subscription(state_key, state.clone())
                                    .await?;
                                last_persist = std::time::Instant::now();
                            }
                        }

                        handler(&event).await?;
                    }
                    Err(e) => {
                        error!("Failed to parse subscription event: {e}");
                        error!("Raw line: {line_str}");
                    }
                }
            }
        }

        self.cache_store.set_subscription(state_key, state).await?;

        Ok(())
    }

    /// Handle changes to peers table
    async fn handle_peers_change(&self, event: &QueryEvent) -> Result<()> {
        if let QueryEvent::Change(change_type, row_id, values, _) = event {
            info!("Peers change: {change_type:?} row {row_id}");

            if let Err(e) = self.dns_restart_tx.try_send(()) {
                error!("Failed to signal DNS restart: {e}");
            }

            if values.len() >= 4 {
                let name = values[0].as_text().unwrap_or("");
                let ipv4 = values[1].as_text().unwrap_or("");
                let public_key = values[2].as_text().unwrap_or("");
                let wg_address = values[3].as_text().unwrap_or("");

                match change_type {
                    ChangeType::Insert => {
                        info!("New peer added: {name}");
                        let endpoint = format!("{ipv4}:{WIREGUARD_PORT}");
                        let address = format!("{wg_address}/32");
                        if let Err(e) = self
                            .wireguard_manager
                            .add_peer(&endpoint, &address, public_key)
                            .await
                        {
                            error!("Failed to add WireGuard peer {name}: {e}");
                        } else {
                            info!("Added WireGuard peer: {name} ({endpoint} -> {address})");
                        }
                    }
                    ChangeType::Delete => {
                        info!("Peer removed: {name}");
                        if let Err(e) = self.wireguard_manager.remove_peer(public_key).await {
                            error!("Failed to remove WireGuard peer: {e}");
                        } else {
                            info!("Removed WireGuard peer: {name}");
                        }
                    }
                    ChangeType::Update => {
                        info!("Peer updated: {name}");
                        let endpoint = format!("{ipv4}:{WIREGUARD_PORT}");
                        let address = format!("{wg_address}/32");

                        // Update peer in WireGuard (remove and re-add)
                        if let Err(e) = self.wireguard_manager.remove_peer(public_key).await {
                            error!("Failed to remove WireGuard peer for update: {e}");
                        }

                        if let Err(e) = self
                            .wireguard_manager
                            .add_peer(&endpoint, &address, public_key)
                            .await
                        {
                            error!("Failed to re-add WireGuard peer {name}: {e}");
                        } else {
                            info!("Updated WireGuard peer: {name} ({endpoint} -> {address})");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle changes to `dns_records` table
    fn handle_dns_change(&self, event: &QueryEvent) {
        if let QueryEvent::Change(change_type, row_id, _, _) = event {
            info!("DNS records change: {change_type:?} row {row_id}");

            if let Err(e) = self.dns_restart_tx.try_send(()) {
                error!("Failed to signal DNS restart: {e}");
            }
        }
    }
}

impl Clone for SubscriptionWatcher {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cache_store: self.cache_store.clone(),
            wireguard_manager: self.wireguard_manager.clone(),
            dns_restart_tx: self.dns_restart_tx.clone(),
        }
    }
}
