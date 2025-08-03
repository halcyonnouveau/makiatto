pub mod acme;
pub mod store;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub use acme::AcmeClient;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_resolver::name_server::{GenericConnector, TokioConnectionProvider};
use hickory_resolver::{Resolver, TokioResolver};
use miette::Result;
pub use store::CertificateStore;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    corrosion::{self, consensus::DirectorElection},
    util,
};

/// Orchestrates certificate lifecycle management
#[derive(Debug, Clone)]
pub struct CertificateManager {
    config: Arc<Config>,
    director_election: Arc<DirectorElection>,
    store: Arc<CertificateStore>,
    acme_client: Arc<AcmeClient>,
    resolver: Arc<Resolver<GenericConnector<TokioRuntimeProvider>>>,
}

impl CertificateManager {
    /// Create a new certificate manager
    ///
    /// # Errors
    /// Returns an error if the DNS resolver cannot be created
    pub fn new(
        config: Arc<Config>,
        director_election: Arc<DirectorElection>,
        store: Arc<CertificateStore>,
    ) -> Result<Self> {
        let acme_client = Arc::new(AcmeClient::new(config.clone()));

        let resolver = Arc::new(
            TokioResolver::builder(TokioConnectionProvider::default())
                .map_err(|e| miette::miette!("Failed to create resolver: {e}"))?
                .build(),
        );

        Ok(Self {
            config,
            director_election,
            store,
            acme_client,
            resolver,
        })
    }

    /// Start the ACME renewal loop
    pub async fn run(&self, mut tripwire: tripwire::Tripwire) {
        if !self.config.acme.enabled {
            info!("ACME certificate renewal is disabled");
            return;
        }

        let mut check_interval = interval(Duration::from_secs(self.config.acme.check_interval));

        loop {
            tokio::select! {
                () = &mut tripwire => {
                    info!("Certificate manager shutting down");
                    break;
                }
                _ = check_interval.tick() => {
                    if !self.director_election.is_leader().await {
                        continue;
                    }

                    if let Err(e) = self.check_and_renew_certificates().await {
                        error!("Certificate renewal check failed: {e}");
                    }
                }
            }
        }
    }

    async fn check_and_renew_certificates(&self) -> Result<()> {
        let domains = self.get_candidate_domains().await?;

        let peer_ips = self.get_cluster_ips().await?;

        for domain in domains {
            if let Err(e) = self.process_domain(&domain, &peer_ips).await {
                error!("Failed to process domain {domain}: {e}");
            }
        }

        Ok(())
    }

    async fn process_domain(&self, domain: &str, peer_ips: &[IpAddr]) -> Result<()> {
        if domain.parse::<IpAddr>().is_ok() || domain == "localhost" {
            debug!("Skipping {domain}: not eligible for certificates");
            return Ok(());
        }

        if !self.validate_domain_ownership(domain, peer_ips).await? {
            warn!("Domain {domain} does not resolve to our cluster, skipping");
            return Ok(());
        }

        let needs_renewal = self
            .store
            .is_certificate_expiring(domain, self.config.acme.renewal_threshold.into())
            .await?;

        if !needs_renewal {
            debug!("Domain {domain} certificate is still valid");
            return Ok(());
        }

        info!("Domain {domain} needs certificate renewal");

        if let Some((status, retry_count, last_check)) = self.get_renewal_status(domain).await? {
            if status == "in_progress" {
                let now = util::get_current_timestamp()?;
                let ten_minutes_ago = now - 600; // 10 minutes in seconds

                if last_check > ten_minutes_ago {
                    warn!("Certificate renewal for {domain} is already in progress");
                    return Ok(());
                }

                info!(
                    "Certificate renewal for {domain} was in progress but last check was over 10 minutes ago, continuing"
                );
            }

            if retry_count >= self.config.acme.max_retry_attempts {
                // check if enough time has passed to reset the retry count
                let now = util::get_current_timestamp()?;
                #[allow(clippy::cast_lossless)]
                let reset_threshold = now - (self.config.acme.retry_reset_hours as i64 * 3600);

                if last_check < reset_threshold {
                    info!(
                        "Resetting retry count for {domain} after {} hours",
                        self.config.acme.retry_reset_hours
                    );
                    self.reset_retry_count(domain).await?;
                } else {
                    warn!("Maximum retry attempts reached for {domain}, skipping");
                    return Ok(());
                }
            }
        }

        self.update_renewal_status(domain, "in_progress").await?;

        match self.acme_client.order_certificate(domain).await {
            Ok(cert) => {
                info!("Successfully obtained certificate for {domain}");
                self.store.save_certificate(cert).await?;
                self.update_renewal_status(domain, "completed").await?;
            }
            Err(e) => {
                error!("Failed to obtain certificate for {domain}: {e}");
                self.update_renewal_status(domain, "failed").await?;
                self.increment_retry_count(domain).await?;
                return Err(e);
            }
        }

        Ok(())
    }

    async fn get_candidate_domains(&self) -> Result<Vec<String>> {
        let pool = corrosion::get_pool().await?;

        let rows = sqlx::query!(
            "SELECT DISTINCT domain FROM (
                SELECT CASE
                    WHEN name = '@' THEN domain
                    ELSE name || '.' || domain
                END AS domain
                FROM dns_records WHERE record_type IN ('A', 'AAAA', 'CNAME')
                UNION
                SELECT alias AS domain FROM domain_aliases
            ) ORDER BY domain"
        )
        .fetch_all(pool)
        .await
        .map_err(|e| miette::miette!("Failed to query domains: {e}"))?;

        let domains: Vec<String> = rows.into_iter().map(|row| row.domain).collect();
        Ok(domains)
    }

    async fn get_cluster_ips(&self) -> Result<Vec<IpAddr>> {
        let peers = corrosion::get_peers().await?;
        let mut peer_ips = Vec::new();

        for peer in peers.iter() {
            if let Ok(ip) = peer.ipv4.parse::<IpAddr>() {
                peer_ips.push(ip);
            }

            if let Some(ipv6) = &peer.ipv6
                && let Ok(ip) = ipv6.parse::<IpAddr>()
            {
                peer_ips.push(ip);
            }
        }

        Ok(peer_ips)
    }

    async fn validate_domain_ownership(&self, domain: &str, peer_ips: &[IpAddr]) -> Result<bool> {
        match self.resolver.lookup_ip(domain).await {
            Ok(response) => {
                let resolved_ips: Vec<IpAddr> = response.iter().collect();
                debug!("Domain {domain} resolves to: {:?}", resolved_ips);

                let valid = resolved_ips.iter().any(|ip| peer_ips.contains(ip));

                if !valid {
                    debug!("Domain {domain} does not resolve to cluster IPs");
                    debug!("Peer IPs: {:?}", peer_ips);
                }

                Ok(valid)
            }
            Err(e) => {
                warn!("Failed to resolve domain {domain}: {e}");
                Ok(false)
            }
        }
    }

    async fn get_renewal_status(&self, domain: &str) -> Result<Option<(String, u32, i64)>> {
        let pool = corrosion::get_pool().await?;

        let row = sqlx::query!(
            "SELECT renewal_status, retry_count, last_check FROM certificate_renewals WHERE domain = ?1",
            domain
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| miette::miette!("Failed to query renewal status: {e}"))?;

        match row {
            Some(row) => Ok(Some((
                row.renewal_status,
                row.retry_count.try_into().unwrap_or(0),
                row.last_check,
            ))),
            None => Ok(None),
        }
    }

    async fn update_renewal_status(&self, domain: &str, status: &str) -> Result<()> {
        let now = util::get_current_timestamp()?;

        #[allow(clippy::cast_possible_wrap)]
        let next_check = now + self.config.acme.check_interval as i64;

        let sql = format!(
            r"INSERT OR REPLACE INTO certificate_renewals
            (domain, last_check, renewal_status, next_check, retry_count, last_renewal)
            VALUES ('{domain}', {now}, '{status}', {next_check},
                COALESCE((SELECT retry_count FROM certificate_renewals WHERE domain = '{domain}'), 0),
                CASE WHEN '{status}' = 'completed' THEN {now} ELSE
                    (SELECT last_renewal FROM certificate_renewals WHERE domain = '{domain}')
                END
            )",
        );

        corrosion::execute_transactions(&[sql]).await
    }

    async fn increment_retry_count(&self, domain: &str) -> Result<()> {
        let sql = format!(
            r"UPDATE certificate_renewals
            SET retry_count = retry_count + 1
            WHERE domain = '{domain}'",
        );

        corrosion::execute_transactions(&[sql]).await
    }

    async fn reset_retry_count(&self, domain: &str) -> Result<()> {
        let sql = format!(
            r"UPDATE certificate_renewals
            SET retry_count = 0
            WHERE domain = '{domain}'",
        );

        corrosion::execute_transactions(&[sql]).await
    }
}
