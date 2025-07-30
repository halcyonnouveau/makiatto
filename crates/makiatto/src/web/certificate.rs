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
    corrosion::{self, consensus::DirectorElection, schema::Certificate},
    util,
};

/// Orchestrates certificate lifecycle management
#[derive(Debug)]
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

    /// Load certificates from database and generate nameserver records
    ///
    /// # Errors
    /// Returns an error if operations fail
    pub async fn load_certificates(&self) -> Result<()> {
        self.store.load_certificates().await?;

        // Generate nameserver DNS records automatically
        if let Err(e) = corrosion::generate_nameserver_records().await {
            error!("Failed to generate nameserver records: {e}");
        }

        Ok(())
    }

    /// Get a certificate by domain
    pub async fn get_certificate(&self, domain: &str) -> Option<Certificate> {
        self.store.get_certificate(domain).await
    }

    /// Save a certificate
    ///
    /// # Errors
    /// Returns an error if database operations fail
    pub async fn save_certificate(&self, cert: Certificate) -> Result<()> {
        self.store.save_certificate(cert).await
    }

    /// Build TLS configuration
    ///
    /// # Errors
    /// Returns an error if TLS config cannot be built
    pub async fn build_tls_config(&self) -> Result<rustls::ServerConfig> {
        self.store.build_tls_config().await
    }

    /// Get expiring certificates
    ///
    /// # Errors
    /// Returns an error if operations fail
    pub async fn get_expiring_certificates(&self, days_threshold: u64) -> Result<Vec<String>> {
        self.store.get_expiring_certificates(days_threshold).await
    }

    /// Check if certificate is expiring
    ///
    /// # Errors
    /// Returns an error if operations fail
    pub async fn is_certificate_expiring(&self, domain: &str, days_threshold: u64) -> Result<bool> {
        self.store
            .is_certificate_expiring(domain, days_threshold)
            .await
    }

    /// Get certificate expiration info
    pub async fn get_certificate_expiration_info(&self) -> Vec<(String, i64, bool)> {
        self.store.get_certificate_expiration_info().await
    }

    /// Start the ACME renewal loop
    pub async fn run(&self, mut tripwire: tripwire::Tripwire) {
        if !self.config.acme.enabled {
            info!("ACME certificate renewal is disabled");
            return;
        }

        let mut check_interval = interval(Duration::from_secs(self.config.acme.check_interval));
        check_interval.tick().await; // skip the first immediate tick

        loop {
            tokio::select! {
                () = &mut tripwire => {
                    info!("Certificate manager shutting down");
                    break;
                }
                _ = check_interval.tick() => {
                    if !self.director_election.is_leader().await {
                        debug!("Not the director, skipping certificate check");
                        continue;
                    }

                    info!("Running certificate check as director");
                    if let Err(e) = self.check_and_renew_certificates().await {
                        error!("Certificate renewal check failed: {e}");
                    }
                }
            }
        }
    }

    /// Check all domains and renew certificates as needed (business logic)
    async fn check_and_renew_certificates(&self) -> Result<()> {
        let domains = self.get_candidate_domains().await?;
        info!(
            "Found {} candidate domains for certificate management",
            domains.len()
        );

        let peer_ips = self.get_cluster_ips().await?;

        for domain in domains {
            if let Err(e) = self.process_domain(&domain, &peer_ips).await {
                error!("Failed to process domain {domain}: {e}");
            }
        }

        Ok(())
    }

    /// Process a single domain for certificate renewal (business logic)
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

        if let Some((status, retry_count)) = self.get_renewal_status(domain).await? {
            if status == "in_progress" {
                warn!("Certificate renewal for {domain} is already in progress");
                return Ok(());
            }

            if retry_count >= self.config.acme.max_retry_attempts {
                warn!("Maximum retry attempts reached for {domain}, skipping");
                return Ok(());
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

    /// Get all candidate domains from the database
    async fn get_candidate_domains(&self) -> Result<Vec<String>> {
        let pool = corrosion::get_pool().await?;

        let rows = sqlx::query!(
            "SELECT DISTINCT domain FROM (
                SELECT domain FROM dns_records WHERE record_type IN ('A', 'AAAA', 'CNAME')
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

    /// Get cluster IPs for domain validation
    async fn get_cluster_ips(&self) -> Result<Vec<IpAddr>> {
        let peers = corrosion::get_peers().await?;
        let mut peer_ips = Vec::new();

        // Add peer IPs
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

    /// Validate that a domain resolves to one of our IPs
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

    /// Get renewal status from database
    async fn get_renewal_status(&self, domain: &str) -> Result<Option<(String, u32)>> {
        let pool = corrosion::get_pool().await?;

        let row = sqlx::query!(
            "SELECT renewal_status, retry_count FROM certificate_renewals WHERE domain = ?1",
            domain
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| miette::miette!("Failed to query renewal status: {e}"))?;

        match row {
            Some(row) => Ok(Some((
                row.renewal_status,
                row.retry_count.try_into().unwrap_or(0),
            ))),
            None => Ok(None),
        }
    }

    /// Update renewal status in database
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

        corrosion::execute_transaction(&sql).await
    }

    /// Increment retry count for a domain
    async fn increment_retry_count(&self, domain: &str) -> Result<()> {
        let sql = format!(
            r"UPDATE certificate_renewals
            SET retry_count = retry_count + 1
            WHERE domain = '{domain}'",
        );

        corrosion::execute_transaction(&sql).await
    }
}
