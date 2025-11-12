use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    name_server::TokioConnectionProvider,
    proto::rr::RecordType,
    proto::xfer::Protocol,
};
use miette::Result;
use tokio::time::{Duration, interval, timeout};
use tracing::{debug, error, info, warn};
use tripwire::Tripwire;

use crate::config::Config;
use crate::corrosion;

#[derive(Debug, Clone)]
struct NodeHealthState {
    consecutive_failures: u32,
    consecutive_successes: u32,
    is_marked_unhealthy: bool,
}

#[derive(Debug, Clone)]
pub struct HealthMonitor {
    config: Arc<Config>,
}

impl HealthMonitor {
    #[must_use]
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    pub async fn run(
        &self,
        election: Arc<crate::corrosion::consensus::DirectorElection>,
        mut tripwire: Tripwire,
    ) {
        let check_interval = self.config.health.check_interval;

        let mut interval = interval(Duration::from_secs(check_interval));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            "Starting health monitor with {}s check interval",
            check_interval
        );

        let mut node_states: HashMap<Arc<str>, NodeHealthState> = HashMap::new();

        loop {
            tokio::select! {
                () = &mut tripwire => {
                    info!("Health monitor shutting down");
                    break;
                }
                _ = interval.tick() => {
                    // Only run health checks if we're the leader
                    if !election.is_leader().await {
                        debug!("Not the leader, skipping health checks");
                        continue;
                    }

                    debug!("Running health checks as leader");
                    if let Err(e) = self.check_all_nodes(&mut node_states).await {
                        error!("Health check failed: {e}");
                    }
                }
            }
        }
    }

    /// Check health of all nodes
    async fn check_all_nodes(
        &self,
        node_states: &mut HashMap<Arc<str>, NodeHealthState>,
    ) -> Result<()> {
        let peers = corrosion::get_peers().await?;
        let unhealthy_nodes = corrosion::get_unhealthy_nodes().await?;

        for peer in peers.iter() {
            let node_name = peer.name.clone();

            // Get or create state for this node, checking if node is already marked unhealthy
            let state = node_states.entry(node_name.clone()).or_insert_with(|| {
                let is_marked_unhealthy = unhealthy_nodes.contains(node_name.as_ref());
                NodeHealthState {
                    consecutive_failures: 0,
                    consecutive_successes: 0,
                    is_marked_unhealthy,
                }
            });

            match self.check_node_health(peer).await {
                Ok(()) => {
                    state.consecutive_failures = 0;
                    state.consecutive_successes += 1;

                    // If node was marked unhealthy and now has enough successes, mark as healthy
                    if state.is_marked_unhealthy
                        && state.consecutive_successes >= self.config.health.success_threshold
                    {
                        info!(
                            "Node '{}' recovered after {} consecutive successes",
                            node_name, state.consecutive_successes
                        );
                        if let Err(e) = self.mark_node_healthy(&node_name).await {
                            error!("Failed to mark node '{}' as healthy: {}", node_name, e);
                        } else {
                            state.is_marked_unhealthy = false;
                            state.consecutive_successes = 0;
                        }
                    }
                }
                Err(failure_reason) => {
                    state.consecutive_successes = 0;
                    state.consecutive_failures += 1;

                    // If node is not yet marked unhealthy and has enough failures, mark as unhealthy
                    if !state.is_marked_unhealthy
                        && state.consecutive_failures >= self.config.health.failure_threshold
                    {
                        warn!(
                            "Node '{}' failed after {} consecutive failures: {}",
                            node_name, state.consecutive_failures, failure_reason
                        );
                        if let Err(e) = self.mark_node_unhealthy(&node_name, &failure_reason).await
                        {
                            error!("Failed to mark node '{}' as unhealthy: {}", node_name, e);
                        } else {
                            state.is_marked_unhealthy = true;
                            state.consecutive_failures = 0;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a single node is healthy
    async fn check_node_health(&self, peer: &corrosion::schema::Peer) -> Result<(), String> {
        let dns_result = self.check_dns_health(peer).await;
        let http_result = self.check_http_health(peer).await;

        match (dns_result, http_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(dns_err), Err(http_err)) => Err(format!(
                "DNS check failed: {dns_err}; HTTP check failed: {http_err}"
            )),
            (Err(dns_err), Ok(())) => Err(format!("DNS check failed: {dns_err}")),
            (Ok(()), Err(http_err)) => Err(format!("HTTP check failed: {http_err}")),
        }
    }

    async fn check_dns_health(&self, peer: &corrosion::schema::Peer) -> Result<(), String> {
        if !peer.is_nameserver {
            return Ok(());
        }

        let domains = match corrosion::get_domains().await {
            Ok(domains) if !domains.is_empty() => domains,
            _ => return Ok(()),
        };

        let domain = &domains[0];

        let wg_addr = peer.wg_address.as_ref();
        let dns_timeout = Duration::from_secs(self.config.health.dns_timeout);
        let ip_addr = wg_addr.split('/').next().unwrap_or(wg_addr);

        let ip: IpAddr = match ip_addr.parse() {
            Ok(ip) => ip,
            Err(e) => return Err(format!("invalid IP address: {e}")),
        };

        let sock_addr = SocketAddr::new(ip, 53);
        let nameserver = NameServerConfig::new(sock_addr, Protocol::Udp);
        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(nameserver);

        let resolver =
            TokioResolver::builder_with_config(resolver_config, TokioConnectionProvider::default())
                .build();

        match timeout(dns_timeout, resolver.lookup(domain, RecordType::A)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("DNS query failed: {e}")),
            Err(_) => Err("DNS query timeout".to_string()),
        }
    }

    async fn check_http_health(&self, peer: &corrosion::schema::Peer) -> Result<(), String> {
        let http_timeout = Duration::from_secs(self.config.health.http_timeout);

        let domains = match corrosion::get_domains().await {
            Ok(domains) if !domains.is_empty() => domains,
            _ => return Ok(()),
        };

        let domain = &domains[0];

        let Ok(pool) = corrosion::get_pool().await else {
            return Err("failed to get database pool".to_string());
        };

        let cert_exists = sqlx::query!(
            "SELECT domain FROM certificates WHERE domain = ?1 LIMIT 1",
            domain
        )
        .fetch_optional(pool)
        .await
        .unwrap_or(None)
        .is_some();

        let url = if cert_exists {
            format!("https://{}", peer.ipv4)
        } else {
            format!("http://{}", peer.ipv4)
        };

        match timeout(http_timeout, async {
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::HOST,
                reqwest::header::HeaderValue::from_str(domain).unwrap(),
            );
            client.get(&url).headers(headers).send().await
        })
        .await
        {
            Ok(Ok(response)) if response.status().is_success() => Ok(()),
            Ok(Ok(response)) => Err(format!("HTTP {}", response.status())),
            Ok(Err(e)) => Err(format!("HTTP request failed: {e}")),
            Err(_) => Err("HTTP request timeout".to_string()),
        }
    }

    /// Mark a node as unhealthy in the database
    async fn mark_node_unhealthy(&self, node_name: &str, failure_reason: &str) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| miette::miette!("Failed to get current time: {e}"))?
            .as_secs() as i64;

        let sql = format!(
            r"
            INSERT INTO unhealthy_nodes (node_name, marked_unhealthy_at, failure_reason)
            VALUES ('{}', {}, '{}')
            ON CONFLICT(node_name) DO UPDATE SET
                marked_unhealthy_at = {},
                failure_reason = '{}'
            ",
            node_name.replace('\'', "''"),
            current_time,
            failure_reason.replace('\'', "''"),
            current_time,
            failure_reason.replace('\'', "''"),
        );

        corrosion::execute_transactions(&[sql]).await?;

        info!(
            "Marked node '{}' as unhealthy: {}",
            node_name, failure_reason
        );

        Ok(())
    }

    /// Mark a node as healthy
    async fn mark_node_healthy(&self, node_name: &str) -> Result<()> {
        let sql = format!(
            r"
            DELETE FROM unhealthy_nodes
            WHERE node_name = '{}'
            ",
            node_name.replace('\'', "''"),
        );

        corrosion::execute_transactions(&[sql]).await?;

        info!("Marked node '{}' as healthy", node_name);

        Ok(())
    }
}
