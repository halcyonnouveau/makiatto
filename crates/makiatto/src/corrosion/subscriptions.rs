use std::{future::Future, pin::Pin, sync::Arc};

use futures_util::StreamExt;
use klukai_types::{api::QueryEvent, pubsub::ChangeType, tripwire::Tripwire};
use miette::Result;
use tokio::time::{Duration, sleep};
use tokio_util::{
    codec::{FramedRead, LinesCodec},
    io::StreamReader,
};
use tracing::{debug, error, info, warn};

use crate::{
    cache::{CacheStore, SubscriptionState},
    config::Config,
    r#const::{CORROSION_API_PORT, WIREGUARD_PORT},
    corrosion::consensus::DirectorElection,
    fs,
    wireguard::WireguardManager,
};

const MAX_BACKOFF_SECS: u64 = 86400; // 1 day

pub struct SubscriptionWatcher {
    config: Arc<Config>,
    cache_store: CacheStore,
    director_election: Arc<DirectorElection>,
    wireguard_manager: Option<WireguardManager>,
    dns_restart_tx: tokio::sync::mpsc::Sender<()>,
    axum_restart_tx: tokio::sync::mpsc::Sender<()>,
}

impl SubscriptionWatcher {
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        cache_store: CacheStore,
        director_election: Arc<DirectorElection>,
        wireguard_manager: Option<WireguardManager>,
        dns_restart_tx: tokio::sync::mpsc::Sender<()>,
        axum_restart_tx: tokio::sync::mpsc::Sender<()>,
    ) -> Self {
        Self {
            config,
            cache_store,
            director_election,
            wireguard_manager,
            dns_restart_tx,
            axum_restart_tx,
        }
    }

    /// Start watching subscriptions
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, mut tripwire: Tripwire) {
        let peers_handle = tokio::spawn({
            let watcher = self.clone();
            let tripwire = tripwire.clone();
            async move {
                watcher
                    .watch_table(
                        tripwire,
                        "Peers",
                        "SELECT name, ipv4, wg_public_key, wg_address FROM peers",
                        "subscription_peers",
                        |event| {
                            let watcher = watcher.clone();
                            Box::pin(async move {
                                watcher.handle_peers_change(event).await?;
                                Ok(())
                            })
                        },
                    )
                    .await;
            }
        });

        let dns_handle = tokio::spawn({
            let watcher = self.clone();
            let tripwire = tripwire.clone();
            async move {
                watcher
                    .watch_table(
                        tripwire,
                        "DNS",
                        "SELECT domain, name, record_type, value FROM dns_records",
                        "subscription_dns_records",
                        |event| {
                            let watcher = watcher.clone();
                            Box::pin(async move {
                                watcher.handle_dns_change(event);
                                Ok(())
                            })
                        },
                    )
                    .await;
            }
        });

        let certificates_handle = tokio::spawn({
            let watcher = self.clone();
            let tripwire = tripwire.clone();
            async move {
                watcher.watch_table(
                    tripwire,
                    "Certificates",
                    "SELECT domain, certificate_pem, private_key_pem, expires_at, issuer FROM certificates",
                    "subscription_certificates",
                    |event| {
                        let watcher = watcher.clone();
                        Box::pin(async move {
                            watcher.handle_certificates_change(event);
                            Ok(())
                        })
                    },
                ).await;
            }
        });

        let domains_handle = tokio::spawn({
            let watcher = self.clone();
            let tripwire = tripwire.clone();
            async move {
                watcher
                    .watch_table(
                        tripwire,
                        "Domains",
                        "SELECT name FROM domains",
                        "subscription_domains",
                        |event| {
                            let watcher = watcher.clone();
                            Box::pin(async move {
                                watcher.handle_domains_change(event);
                                Ok(())
                            })
                        },
                    )
                    .await;
            }
        });

        let domain_aliases_handle = tokio::spawn({
            let watcher = self.clone();
            let tripwire = tripwire.clone();
            async move {
                watcher
                    .watch_table(
                        tripwire,
                        "Domain aliases",
                        "SELECT alias, target FROM domain_aliases",
                        "subscription_domain_aliases",
                        |event| {
                            let watcher = watcher.clone();
                            Box::pin(async move {
                                watcher.handle_domain_aliases_change(event);
                                Ok(())
                            })
                        },
                    )
                    .await;
            }
        });

        let files_handle = tokio::spawn({
            let watcher = self.clone();
            let tripwire = tripwire.clone();
            async move {
                watcher
                    .watch_table(
                        tripwire,
                        "Files",
                        "SELECT domain, path, content_hash, size, modified_at FROM files",
                        "subscription_files",
                        |event| {
                            let watcher = watcher.clone();
                            Box::pin(async move {
                                watcher.handle_files_change(event).await;
                                Ok(())
                            })
                        },
                    )
                    .await;
            }
        });

        let cache_persist_handle = tokio::spawn({
            let cache_store = self.cache_store.clone();
            let mut tripwire = tripwire.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                interval.tick().await;

                loop {
                    tokio::select! {
                        () = &mut tripwire => {
                            info!("Cache persistence task shutting down");
                            // Final persist on shutdown
                            if let Err(e) = cache_store.persist().await {
                                error!("Failed to persist cache on shutdown: {e}");
                            }
                            break;
                        }
                        _ = interval.tick() => {
                            if let Err(e) = cache_store.persist().await {
                                error!("Failed to persist cache: {e}");
                            } else {
                                debug!("Cache persisted successfully");
                            }
                        }
                    }
                }
            }
        });

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
            res = certificates_handle => {
                if let Err(e) = res {
                    error!("Certificates watcher task failed: {e}");
                }
            }
            res = domains_handle => {
                if let Err(e) = res {
                    error!("Domains watcher task failed: {e}");
                }
            }
            res = domain_aliases_handle => {
                if let Err(e) = res {
                    error!("Domain aliases watcher task failed: {e}");
                }
            }
            res = files_handle => {
                if let Err(e) = res {
                    error!("Files watcher task failed: {e}");
                }
            }
            res = cache_persist_handle => {
                if let Err(e) = res {
                    error!("Cache persistence task failed: {e}");
                }
            }
        }
    }

    /// Generic watcher for table changes with backoff and retry logic
    async fn watch_table<F>(
        &self,
        mut tripwire: Tripwire,
        table_name: &str,
        query: &str,
        state_key: &str,
        handler: F,
    ) where
        F: Fn(&QueryEvent) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>,
    {
        let mut backoff_secs = 1u64;

        loop {
            tokio::select! {
                () = &mut tripwire => {
                    info!("{table_name} watcher shutting down");
                    break;
                }
                result = self.subscribe(query, state_key, &handler) => {
                    if let Err(e) = result {
                        warn!("{table_name} subscription failed: {e}, retrying in {backoff_secs} seconds");
                    } else {
                        backoff_secs = 1;
                        warn!("{table_name} subscription ended, retrying...");
                    }

                    sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                }
            }
        }
    }

    /// Subscribe to a query and process events
    #[allow(clippy::too_many_lines)]
    async fn subscribe<F>(&self, query: &str, state_key: &str, handler: F) -> Result<()>
    where
        F: Fn(&QueryEvent) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>,
    {
        let api_base = format!("http://127.0.0.1:{CORROSION_API_PORT}/v1/subscriptions");
        let client = reqwest::Client::builder()
            .tcp_keepalive(Duration::from_secs(60))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .build()
            .map_err(|e| miette::miette!("Failed to create HTTP client: {e}"))?;

        let mut state = self
            .cache_store
            .get_subscription(state_key)
            .await
            .unwrap_or(SubscriptionState {
                query_id: None,
                last_change_id: 0,
            });

        loop {
            let (url, is_new) = if let Some(query_id) = &state.query_id {
                let from = if state.last_change_id > 0 {
                    format!("?from={}", state.last_change_id)
                } else {
                    String::new()
                };
                (format!("{api_base}/{query_id}{from}"), false)
            } else {
                (api_base.clone(), true)
            };

            debug!(
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

            // handle new subscription ID
            if is_new
                && let Some(query_id_str) = response.headers().get("corro-query-id")
                && let Ok(query_id_str) = query_id_str.to_str()
            {
                state.query_id = Some(query_id_str.to_string());
                info!("New subscription created with ID: {query_id_str}");

                self.cache_store
                    .set_subscription(state_key, state.clone())
                    .await;
            }

            let reader = StreamReader::new(
                response
                    .bytes_stream()
                    .map(|result| result.map_err(std::io::Error::other)),
            );

            let codec = LinesCodec::new();
            let mut framed_stream = FramedRead::new(reader, codec);

            // track if we've observed End-of-Query - true if resuming from existing state
            let mut observed_eoq = state.last_change_id > 0;

            while let Some(line_result) = framed_stream.next().await {
                let line = line_result
                    .map_err(|e| miette::miette!("Failed to read subscription line: {e}"))?;

                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                match serde_json::from_str::<QueryEvent>(line) {
                    Ok(event) => {
                        match &event {
                            QueryEvent::EndOfQuery { change_id, .. } => {
                                observed_eoq = true;
                                if let Some(id) = change_id {
                                    state.last_change_id = id.0;
                                }
                                debug!(
                                    "End-of-query reached for {state_key}, now processing live updates"
                                );
                            }
                            QueryEvent::Change(_, _, _, change_id) => {
                                // only update state and handle changes after EOQ
                                if observed_eoq {
                                    // check for missed changes
                                    if state.last_change_id > 0
                                        && change_id.0 != state.last_change_id + 1
                                    {
                                        let expected = state.last_change_id + 1;
                                        error!(
                                            "Missed change detected for {state_key} - expected: {expected}, got: {}, forcing reconnection",
                                            change_id.0
                                        );
                                        return Err(miette::miette!(
                                            "Missed change (expected: {}, got: {}), inconsistent state",
                                            expected,
                                            change_id.0
                                        ));
                                    }

                                    state.last_change_id = change_id.0;
                                    if let Err(e) = handler(&event).await {
                                        error!("Handler error for subscription event: {e}");
                                    }
                                } else {
                                    debug!("Skipping initial query result - waiting for EOQ");
                                }
                            }
                            _ => {
                                // Handle other event types (if any)
                                if let Err(e) = handler(&event).await {
                                    error!("Handler error for subscription event: {e}");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse subscription event: {e}");
                        error!("Raw line: {line}");
                    }
                }
            }

            // stream ended cleanly, save state and reconnect
            self.cache_store
                .set_subscription(state_key, state.clone())
                .await;

            info!("Subscription stream ended, reconnecting to {state_key}...");
            sleep(Duration::from_secs(5)).await;
        }
    }

    /// Handle changes to peers table
    async fn handle_peers_change(&self, event: &QueryEvent) -> Result<()> {
        if let QueryEvent::Change(change_type, row_id, values, _) = event {
            info!("Peers change: {change_type:?} row {row_id}");

            if values.len() >= 4 {
                let name = values[0].as_text().unwrap_or("");
                let ipv4 = values[1].as_text().unwrap_or("");
                let public_key = values[2].as_text().unwrap_or("");
                let wg_address = values[3].as_text().unwrap_or("");

                match change_type {
                    ChangeType::Insert => {
                        info!("New peer added: {name}");
                        let endpoint = format!("{ipv4}:{WIREGUARD_PORT}");
                        if let Some(ref wg_mgr) = self.wireguard_manager {
                            wg_mgr.add_peer(&endpoint, wg_address, public_key).await?;
                        }
                    }
                    ChangeType::Delete => {
                        info!("Peer removed: {name}");
                        if let Some(ref wg_mgr) = self.wireguard_manager {
                            wg_mgr.remove_peer(wg_address, public_key).await?;
                        }
                    }
                    ChangeType::Update => {
                        info!("Peer updated: {name}");
                        let endpoint = format!("{ipv4}:{WIREGUARD_PORT}");

                        if let Some(ref wg_mgr) = self.wireguard_manager {
                            wg_mgr.remove_peer(wg_address, public_key).await?;
                            wg_mgr.add_peer(&endpoint, wg_address, public_key).await?;
                        }
                    }
                }

                if let Err(e) = self.dns_restart_tx.try_send(()) {
                    error!("Failed to signal DNS restart: {e}");
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

    /// Handle changes to `certificates` table
    fn handle_certificates_change(&self, event: &QueryEvent) {
        if let QueryEvent::Change(change_type, row_id, values, _) = event {
            let domain = if values.is_empty() {
                "unknown"
            } else {
                values[0].as_text().unwrap_or("unknown")
            };

            info!("Certificates change: {change_type:?} row {row_id} domain {domain}");

            if let Err(e) = self.dns_restart_tx.try_send(()) {
                error!("Failed to signal DNS restart: {e}");
            }

            if let Err(e) = self.axum_restart_tx.try_send(()) {
                error!("Failed to signal Axum restart: {e}");
            }
        }
    }

    /// Handle changes to `domains` table
    fn handle_domains_change(&self, event: &QueryEvent) {
        if let QueryEvent::Change(change_type, row_id, values, _) = event {
            let domain = if values.is_empty() {
                "unknown"
            } else {
                values[0].as_text().unwrap_or("unknown")
            };

            info!("Domains change: {change_type:?} row {row_id} domain {domain}");

            if let Err(e) = self.dns_restart_tx.try_send(()) {
                error!("Failed to signal DNS restart: {e}");
            }
        }
    }

    /// Handle changes to `domain_aliases` table
    fn handle_domain_aliases_change(&self, event: &QueryEvent) {
        if let QueryEvent::Change(change_type, row_id, values, _) = event {
            let (alias, target) = if values.len() >= 2 {
                (
                    values[0].as_text().unwrap_or("unknown"),
                    values[1].as_text().unwrap_or("unknown"),
                )
            } else {
                ("unknown", "unknown")
            };

            info!("Domain alias change: {change_type:?} row {row_id} alias {alias} -> {target}");

            if let Err(e) = self.axum_restart_tx.try_send(()) {
                error!("Failed to signal web server reload: {e}");
            }
        }
    }

    /// Handle changes to `files` table
    async fn handle_files_change(&self, event: &QueryEvent) {
        if let QueryEvent::Change(change_type, row_id, values, _) = event {
            let (domain, path, content_hash) = if values.len() >= 3 {
                (
                    values[0].as_text().unwrap_or("unknown"),
                    values[1].as_text().unwrap_or("unknown"),
                    values[2].as_text().unwrap_or("unknown"),
                )
            } else {
                ("unknown", "unknown", "unknown")
            };

            info!(
                "File change: {change_type:?} row {row_id} {domain}{path} (hash: {content_hash})"
            );

            let config = self.config.clone();
            let domain = domain.to_string();
            let path = path.to_string();
            let content_hash = content_hash.to_string();
            let change_type = *change_type;

            match change_type {
                ChangeType::Insert | ChangeType::Update => {
                    match fs::watcher::fetch_domain_file(&config, &content_hash, &domain, &path)
                        .await
                    {
                        Ok(()) => {
                            debug!("Successfully fetched file {content_hash} for {domain}{path}");
                        }
                        Err(e) => {
                            error!("Error fetching file {content_hash} for {domain}{path}: {e}");
                        }
                    }
                }
                ChangeType::Delete => {
                    match fs::watcher::delete_domain_file(&config, &domain, &path).await {
                        Ok(()) => {
                            debug!("File deleted from database: {domain}{path}");
                        }
                        Err(e) => {
                            error!("Failed to delete domain file {domain}{path}: {e}");
                        }
                    }
                }
            }
        }
    }
}

impl Clone for SubscriptionWatcher {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cache_store: self.cache_store.clone(),
            director_election: self.director_election.clone(),
            wireguard_manager: self.wireguard_manager.clone(),
            dns_restart_tx: self.dns_restart_tx.clone(),
            axum_restart_tx: self.axum_restart_tx.clone(),
        }
    }
}
