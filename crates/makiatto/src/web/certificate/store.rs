use std::collections::HashMap;
use std::io::BufReader;
use std::sync::Arc;

use base64::prelude::*;
use miette::Result;
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::{ServerConfig, sign::CertifiedKey};
use rustls_pemfile::{certs, private_key};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::{
    corrosion::{self, schema::Certificate},
    util,
};

#[derive(Debug, Clone)]
pub struct CertificateStore {
    certificates: Arc<RwLock<HashMap<String, Certificate>>>,
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            certificates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load all certificates from the database
    ///
    /// # Errors
    /// Returns an error if the database connection fails or the query fails
    pub async fn load_certificates(&self) -> Result<()> {
        let pool = crate::corrosion::get_pool()
            .await
            .map_err(|e| miette::miette!("Failed to get connection pool: {e}"))?;

        let rows = sqlx::query!(
            "SELECT domain, certificate_pem, private_key_pem, expires_at, issuer FROM certificates"
        )
        .fetch_all(pool)
        .await
        .map_err(|e| miette::miette!("Failed to query certificates: {e}"))?;

        let mut certs = Vec::new();
        for row in rows {
            match (
                BASE64_STANDARD.decode(&row.certificate_pem),
                BASE64_STANDARD.decode(&row.private_key_pem),
            ) {
                (Ok(cert_bytes), Ok(key_bytes)) => {
                    match (String::from_utf8(cert_bytes), String::from_utf8(key_bytes)) {
                        (Ok(certificate_pem), Ok(private_key_pem)) => {
                            let cert = Certificate {
                                domain: Arc::from(row.domain.clone()),
                                certificate_pem: Arc::from(certificate_pem),
                                private_key_pem: Arc::from(private_key_pem),
                                expires_at: row.expires_at,
                                issuer: Arc::from(row.issuer),
                            };
                            info!("Loaded certificate for domain: {}", row.domain);
                            certs.push(cert);
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            error!("Failed to decode certificate PEM for {}: {e}", row.domain);
                        }
                    }
                }
                (Err(e), _) | (_, Err(e)) => {
                    error!(
                        "Failed to decode base64 certificate for {}: {e}",
                        row.domain
                    );
                }
            }
        }

        info!("Loaded {} certificates from database", certs.len());

        let mut certificates = self.certificates.write().await;
        certificates.clear();

        for cert in certs {
            certificates.insert(cert.domain.to_string(), cert);
        }

        Ok(())
    }

    /// Save a certificate to the database and update memory cache
    ///
    /// # Errors
    /// Returns an error if the database transaction fails
    pub async fn save_certificate(&self, cert: Certificate) -> Result<()> {
        let cert_pem_b64 = BASE64_STANDARD.encode(cert.certificate_pem.as_bytes());
        let key_pem_b64 = BASE64_STANDARD.encode(cert.private_key_pem.as_bytes());

        let sql = format!(
            "INSERT OR REPLACE INTO certificates (domain, certificate_pem, private_key_pem, expires_at, issuer) VALUES ('{}', '{}', '{}', {}, '{}')",
            cert.domain, cert_pem_b64, key_pem_b64, cert.expires_at, cert.issuer
        );

        // update memory cache
        self.certificates
            .write()
            .await
            .insert(cert.domain.to_string(), cert);

        corrosion::execute_transactions(&[sql]).await?;

        Ok(())
    }

    /// Check if a certificate exists and is expiring within the threshold
    ///
    /// # Errors
    /// Returns an error if system time cannot be retrieved
    pub async fn is_certificate_expiring(&self, domain: &str, days_threshold: u64) -> Result<bool> {
        let current_time = util::get_current_timestamp()?;

        #[allow(clippy::cast_possible_wrap)]
        let threshold_time = current_time + (days_threshold * 24 * 60 * 60) as i64;

        // query database directly to ensure we have the latest certificate info
        let pool = corrosion::get_pool().await?;
        let row = sqlx::query!(
            "SELECT expires_at FROM certificates WHERE domain = ?1",
            domain
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| miette::miette!("Failed to query certificate expiry: {e}"))?;

        if let Some(cert) = row {
            Ok(cert.expires_at <= threshold_time)
        } else {
            // no certificate exists, so it needs one
            Ok(true)
        }
    }

    /// Build TLS configuration from loaded certificates with SNI support
    ///
    /// # Errors
    /// Returns an error if no certificates are available or TLS config building fails
    pub async fn build_tls_config(&self) -> Result<ServerConfig> {
        let certificates = self.certificates.read().await;

        if certificates.is_empty() {
            return Err(miette::miette!("No certificates available"));
        }

        // Build certified keys for all domains
        let mut certified_keys = HashMap::new();
        let mut default_cert = None;

        for (domain, cert) in certificates.iter() {
            let cert_chain = load_certs_from_pem(&cert.certificate_pem)
                .map_err(|e| miette::miette!("Failed to parse PEM for {domain}: {e}"))?;

            let key = load_key_from_pem(&cert.private_key_pem)
                .map_err(|e| miette::miette!("Failed to create private key for {domain}: {e}"))?;

            let signing_key = any_supported_type(&key)
                .map_err(|e| miette::miette!("Failed to create signing key for {domain}: {e}"))?;

            let certified_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));

            if default_cert.is_none() {
                default_cert = Some(certified_key.clone());
            }

            certified_keys.insert(domain.clone(), certified_key);
            info!("Registered certificate for domain: {}", domain);
        }

        let cert_resolver = SniCertResolver {
            certs: certified_keys,
            default_cert,
        };

        // Install default crypto provider if none is set
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(cert_resolver));

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(config)
    }
}

fn load_certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem.as_bytes());
    certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| miette::miette!("Failed to parse certificate PEM: {e}"))
}

fn load_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());
    private_key(&mut reader)
        .map_err(|e| miette::miette!("Failed to parse private key PEM: {e}"))?
        .ok_or_else(|| miette::miette!("No private key found in PEM"))
}

/// SNI certificate resolver that selects the appropriate certificate based on the requested hostname
#[derive(Debug)]
struct SniCertResolver {
    certs: HashMap<String, Arc<CertifiedKey>>,
    default_cert: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name) = client_hello.server_name() {
            let name = match std::str::from_utf8(server_name.as_ref()) {
                Ok(name) => name,
                Err(e) => {
                    debug!("Invalid UTF-8 in SNI hostname: {e}");
                    return self.default_cert.clone();
                }
            };

            if let Some(cert) = self.certs.get(name) {
                return Some(cert.clone());
            }

            // Try wildcard match (e.g., *.example.com matches sub.example.com)
            if let Some(dot_pos) = name.find('.') {
                let wildcard = format!("*{}", &name[dot_pos..]);
                if let Some(cert) = self.certs.get(&wildcard) {
                    return Some(cert.clone());
                }
            }
        }

        self.default_cert.clone()
    }
}
