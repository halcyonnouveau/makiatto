use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use miette::{IntoDiagnostic, Result};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::config::Config;
use crate::corrosion::{self, schema::Certificate};

/// How long to wait for a stored challenge to become readable before proceeding.
const CHALLENGE_VISIBILITY_TIMEOUT: Duration = Duration::from_secs(15);

pub struct AcmeClient {
    config: Arc<Config>,
    /// Cached ACME account, reused for the lifetime of the process to avoid
    /// registering a brand-new account on every certificate order.
    account: Mutex<Option<Account>>,
}

impl std::fmt::Debug for AcmeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeClient").finish_non_exhaustive()
    }
}

impl AcmeClient {
    #[must_use]
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            account: Mutex::new(None),
        }
    }

    /// Order a certificate from Let's Encrypt
    ///
    /// # Errors
    /// Returns an error if ACME protocol operations fail
    ///
    /// # Panics
    /// Panics if system time is before UNIX epoch
    pub async fn order_certificate(&self, domain: &str) -> Result<Certificate> {
        info!("Ordering certificate for domain: {domain}");

        let account = self.get_or_create_account().await?;

        let identifiers = vec![Identifier::Dns(domain.to_string())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .into_diagnostic()?;

        let mut challenge_tokens = Vec::new();

        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.into_diagnostic()?;

            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| miette::miette!("No HTTP-01 challenge found"))?;

            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization();
            let key_auth_string = key_auth.as_str();
            self.store_acme_challenge(&token, key_auth_string).await?;

            // wait until the challenge is actually readable before telling the CA
            // to validate, rather than a blind fixed sleep that races propagation
            self.wait_for_challenge_visible(&token).await;

            challenge.set_ready().await.into_diagnostic()?;
            challenge_tokens.push(token);
        }

        let retry_policy = RetryPolicy::new()
            .initial_delay(Duration::from_secs(5))
            .backoff(2.0)
            .timeout(Duration::from_mins(10));

        let status = order.poll_ready(&retry_policy).await.into_diagnostic()?;

        if status != OrderStatus::Ready {
            // best-effort cleanup of challenge tokens we created for this order
            self.cleanup_challenges(&challenge_tokens).await;
            return Err(miette::miette!("Order validation failed: {status:?}"));
        }

        let private_key_pem = order.finalize().await.into_diagnostic()?;
        let cert_pem = order
            .poll_certificate(&retry_policy)
            .await
            .into_diagnostic()?;

        // challenge has served its purpose; remove the tokens from the cluster
        self.cleanup_challenges(&challenge_tokens).await;

        // Calculate expiration (90 days for Let's Encrypt)
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + (90 * 86400);

        Ok(Certificate {
            domain: Arc::from(domain),
            certificate_pem: Arc::from(cert_pem),
            private_key_pem: Arc::from(private_key_pem),
            expires_at,
            issuer: Arc::from("lets_encrypt"),
        })
    }

    /// Store ACME challenge in database for HTTP-01 validation
    ///
    /// # Errors
    /// Returns an error if database operations fail
    ///
    /// # Panics
    /// Panics if system time is before UNIX epoch
    pub async fn store_acme_challenge(&self, token: &str, key_auth: &str) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let expires_at = now + 300; // 5 minutes

        let sql = corrosion::Statement::with_params(
            r"INSERT OR REPLACE INTO acme_challenges
            (token, key_authorisation, created_at, expires_at)
            VALUES (?, ?, ?, ?)",
            vec![
                serde_json::json!(token),
                serde_json::json!(key_auth),
                serde_json::json!(now),
                serde_json::json!(expires_at),
            ],
        );

        corrosion::execute_transactions(&[sql]).await
    }

    /// Delete ACME challenge from database
    ///
    /// # Errors
    /// Returns an error if database operations fail
    pub async fn delete_acme_challenge(&self, token: &str) -> Result<()> {
        let sql = corrosion::Statement::with_params(
            "DELETE FROM acme_challenges WHERE token = ?",
            vec![serde_json::json!(token)],
        );
        corrosion::execute_transactions(&[sql]).await
    }

    /// Poll the local database until a freshly stored challenge token is
    /// readable, so we only ask the CA to validate once the row has committed.
    ///
    /// This confirms our own write is queryable and gives gossip a brief window
    /// to replicate it to peers (the validator may be geo-routed to any node).
    /// Best-effort: returns after [`CHALLENGE_VISIBILITY_TIMEOUT`] regardless.
    async fn wait_for_challenge_visible(&self, token: &str) {
        let start = SystemTime::now();

        loop {
            match corrosion::get_pool().await {
                Ok(pool) => {
                    let row =
                        sqlx::query!("SELECT token FROM acme_challenges WHERE token = ?1", token)
                            .fetch_optional(pool)
                            .await;

                    if matches!(row, Ok(Some(_))) {
                        // give gossip a brief moment to fan the row out to peers
                        sleep(Duration::from_secs(2)).await;
                        return;
                    }
                }
                Err(e) => warn!("Waiting for challenge visibility, pool not ready: {e}"),
            }

            if start.elapsed().unwrap_or_default() > CHALLENGE_VISIBILITY_TIMEOUT {
                warn!("Timed out waiting for ACME challenge '{token}' to become visible");
                return;
            }

            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Best-effort deletion of challenge tokens once they are no longer needed.
    async fn cleanup_challenges(&self, tokens: &[String]) {
        for token in tokens {
            if let Err(e) = self.delete_acme_challenge(token).await {
                warn!("Failed to delete ACME challenge '{token}': {e}");
            }
        }
    }

    /// Get or create the ACME account, reusing a cached account for the lifetime
    /// of the process.
    ///
    /// Note: the account is not persisted across restarts yet, so a restart will
    /// register a fresh account on the next order.
    async fn get_or_create_account(&self) -> Result<Account> {
        let mut cached = self.account.lock().await;
        if let Some(account) = cached.as_ref() {
            return Ok(account.clone());
        }

        let directory = if self.config.acme.staging {
            LetsEncrypt::Staging
        } else {
            LetsEncrypt::Production
        };

        let contact = if self.config.acme.email.is_empty() {
            vec![]
        } else {
            vec![format!("mailto:{}", self.config.acme.email)]
        };

        let (account, _credentials) = Account::builder()
            .into_diagnostic()?
            .create(
                &NewAccount {
                    contact: &contact.iter().map(String::as_str).collect::<Vec<_>>(),
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory.url().to_string(),
                None,
            )
            .await
            .into_diagnostic()?;

        *cached = Some(account.clone());
        Ok(account)
    }
}
