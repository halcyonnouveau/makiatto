use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use miette::{IntoDiagnostic, Result};
use tokio::time::sleep;
use tracing::info;

use crate::config::Config;
use crate::corrosion::{self, schema::Certificate};

#[derive(Debug)]
pub struct AcmeClient {
    config: Arc<Config>,
}

impl AcmeClient {
    #[must_use]
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
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

            sleep(Duration::from_secs(2)).await;
            challenge.set_ready().await.into_diagnostic()?;
        }

        let retry_policy = RetryPolicy::new()
            .initial_delay(Duration::from_secs(5))
            .backoff(2.0)
            .timeout(Duration::from_secs(600)); // 10 minutes

        let status = order.poll_ready(&retry_policy).await.into_diagnostic()?;

        if status != OrderStatus::Ready {
            return Err(miette::miette!("Order validation failed: {status:?}"));
        }

        let private_key_pem = order.finalize().await.into_diagnostic()?;
        let cert_pem = order
            .poll_certificate(&retry_policy)
            .await
            .into_diagnostic()?;

        // Calculate expiration (90 days for Let's Encrypt)
        #[allow(clippy::cast_possible_wrap)]
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
        #[allow(clippy::cast_possible_wrap)]
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let expires_at = now + 300; // 5 minutes

        let sql = format!(
            r"INSERT OR REPLACE INTO acme_challenges
            (token, key_authorisation, created_at, expires_at)
            VALUES ('{token}', '{key_auth}', {now}, {expires_at})",
        );

        corrosion::execute_transactions(&[sql]).await
    }

    /// Delete ACME challenge from database
    ///
    /// # Errors
    /// Returns an error if database operations fail
    pub async fn delete_acme_challenge(&self, token: &str) -> Result<()> {
        let sql = format!("DELETE FROM acme_challenges WHERE token = '{token}'");
        corrosion::execute_transactions(&[sql]).await
    }

    /// Get or create ACME account
    async fn get_or_create_account(&self) -> Result<Account> {
        // for now, create a new account each time
        // TODO: store and reuse account credentials
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

        Ok(account)
    }
}
