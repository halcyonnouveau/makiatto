use std::collections::HashMap;
use std::io::BufReader;
use std::sync::Arc;

use base64::prelude::*;
use corro_agent::rusqlite::{Connection, Error as SqliteError, types::Type as SqliteType};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::{ServerConfig, sign::CertifiedKey};
use rustls_pemfile::{certs, private_key};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::constants::CORROSION_API_PORT;
use crate::corrosion::schema::Certificate;

#[derive(Debug, Clone)]
pub struct CertificateManager {
    certificates: Arc<RwLock<HashMap<String, Certificate>>>,
    db_path: camino::Utf8PathBuf,
}

impl CertificateManager {
    #[must_use]
    pub fn new(db_path: camino::Utf8PathBuf) -> Self {
        Self {
            certificates: Arc::new(RwLock::new(HashMap::new())),
            db_path,
        }
    }

    /// Load all certificates from the database
    ///
    /// # Errors
    /// Returns an error if the database connection fails or the query fails
    pub async fn load_certificates(&self) -> miette::Result<()> {
        let db_path = self.db_path.clone();

        let certs = tokio::task::spawn_blocking(move || -> miette::Result<Vec<Certificate>> {
            if !db_path.exists() {
                info!("Database does not exist yet, skipping certificate loading");
                return Ok(Vec::new());
            }

            let conn = Connection::open(&db_path)
                .map_err(|e| miette::miette!("Failed to open database: {e}"))?;

            let mut stmt = conn
                .prepare("SELECT domain, certificate_pem, private_key_pem, expires_at, issuer FROM certificates")
                .map_err(|e| miette::miette!("Failed to prepare query: {e}"))?;

            let rows = stmt
                .query_map([], |row| {
                    let cert_b64: String = row.get(1)?;
                    let key_b64: String = row.get(2)?;

                    let certificate_pem = BASE64_STANDARD.decode(&cert_b64)
                        .map_err(|e| SqliteError::FromSqlConversionFailure(1, SqliteType::Text, Box::new(e)))
                        .and_then(|bytes| String::from_utf8(bytes)
                            .map_err(|e| SqliteError::FromSqlConversionFailure(1, SqliteType::Text, Box::new(e))))?;

                    let private_key_pem = BASE64_STANDARD.decode(&key_b64)
                        .map_err(|e| SqliteError::FromSqlConversionFailure(2, SqliteType::Text, Box::new(e)))
                        .and_then(|bytes| String::from_utf8(bytes)
                            .map_err(|e| SqliteError::FromSqlConversionFailure(2, SqliteType::Text, Box::new(e))))?;

                    Ok(Certificate {
                        domain: row.get(0)?,
                        certificate_pem,
                        private_key_pem,
                        expires_at: row.get(3)?,
                        issuer: row.get(4)?,
                    })
                })
                .map_err(|e| miette::miette!("Failed to query certificates: {e}"))?;

            let mut certs = Vec::new();
            for cert_result in rows {
                match cert_result {
                    Ok(cert) => {
                        info!("Loaded certificate for domain: {}", cert.domain);
                        certs.push(cert);
                    }
                    Err(e) => {
                        error!("Failed to load certificate: {e}");
                    }
                }
            }

            info!("Loaded {} certificates from database", certs.len());
            Ok(certs)
        }).await
        .map_err(|e| miette::miette!("Failed to spawn blocking task: {e}"))??;

        let mut certificates = self.certificates.write().await;
        certificates.clear();

        for cert in certs {
            certificates.insert(cert.domain.clone(), cert);
        }

        Ok(())
    }

    pub async fn get_certificate(&self, domain: &str) -> Option<Certificate> {
        self.certificates.read().await.get(domain).cloned()
    }

    /// Save a certificate to the database
    ///
    /// # Errors
    /// Returns an error if the database transaction fails
    pub async fn save_certificate(&self, cert: Certificate) -> miette::Result<()> {
        let cert_pem_b64 = BASE64_STANDARD.encode(cert.certificate_pem.as_bytes());
        let key_pem_b64 = BASE64_STANDARD.encode(cert.private_key_pem.as_bytes());

        let sql = format!(
            "INSERT OR REPLACE INTO certificates (domain, certificate_pem, private_key_pem, expires_at, issuer) VALUES ('{}', '{}', '{}', {}, '{}')",
            cert.domain.replace('\'', "''"),
            cert_pem_b64,
            key_pem_b64,
            cert.expires_at,
            cert.issuer.replace('\'', "''")
        );

        let json_payload = format!("[\"{}\"]", sql.replace('"', "\\\""));

        let client = reqwest::Client::new();
        let response = client
            .post(format!(
                "http://127.0.0.1:{CORROSION_API_PORT}/v1/transactions",
            ))
            .header("Content-Type", "application/json")
            .body(json_payload)
            .send()
            .await
            .map_err(|e| miette::miette!("Failed to send transaction to Corrosion: {e}"))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(miette::miette!("Corrosion API error: {error_text}"));
        }

        let response_text = response
            .text()
            .await
            .map_err(|e| miette::miette!("Failed to read response: {e}"))?;

        if !response_text.contains("\"rows_affected\"") || response_text.contains("\"error\"") {
            return Err(miette::miette!("Corrosion API error: {response_text}"));
        }

        self.certificates
            .write()
            .await
            .insert(cert.domain.clone(), cert);

        Ok(())
    }

    /// Build TLS configuration from loaded certificates with SNI support
    ///
    /// # Errors
    /// Returns an error if no certificates are available or TLS config building fails
    pub async fn build_tls_config(&self) -> miette::Result<ServerConfig> {
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
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(cert_resolver));

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(config)
    }
}

fn load_certs_from_pem(pem: &str) -> miette::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem.as_bytes());
    certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| miette::miette!("Failed to parse certificate PEM: {e}"))
}

fn load_key_from_pem(pem: &str) -> miette::Result<PrivateKeyDer<'static>> {
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
