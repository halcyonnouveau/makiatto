#![cfg(test)]
use std::sync::Arc;

use miette::{IntoDiagnostic, Result};
use testcontainers::{ContainerAsync, GenericImage};

use crate::container::{ContainerContext, TestContainer, util};

/// Helper function to remove an ACME challenge via Corrosion API
async fn remove_acme_challenge(
    daemon: &Arc<ContainerAsync<GenericImage>>,
    token: &str,
) -> Result<()> {
    let sql = format!("DELETE FROM acme_challenges WHERE token = '{token}'");
    util::execute_transaction(daemon, &sql).await
}

/// Insert an ACME challenge via Corrosion API
pub async fn insert_acme_challenge(
    daemon: &Arc<ContainerAsync<GenericImage>>,
    token: &str,
    key_authorisation: &str,
    expires_in_seconds: i64,
) -> Result<()> {
    let current_time = util::current_timestamp();
    let expires_at = current_time + expires_in_seconds;

    let sql = format!(
        "INSERT INTO acme_challenges (token, key_authorisation, created_at, expires_at) VALUES ('{token}', '{key_authorisation}', {current_time}, {expires_at})"
    );
    util::execute_transaction(daemon, &sql).await
}

#[tokio::test]
async fn test_valid() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let token = "test_token_123";
    let key_authorisation = "test_key_auth_456";

    insert_acme_challenge(&daemon, token, key_authorisation, 3600).await?;

    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/.well-known/acme-challenge/{}",
            ports.http, token
        ))
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);
    let body = response.text().await.into_diagnostic()?;
    assert_eq!(body, key_authorisation);

    Ok(())
}

#[tokio::test]
async fn test_not_found() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let _daemon = daemon_container.unwrap();

    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/.well-known/acme-challenge/nonexistent_token",
            ports.http
        ))
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 404);
    let body = response.text().await.into_diagnostic()?;
    assert_eq!(body, "Challenge not found");

    Ok(())
}

#[tokio::test]
async fn test_expired() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let token = "expired_token_123";
    let key_authorisation = "expired_key_auth_456";

    insert_acme_challenge(&daemon, token, key_authorisation, -3600).await?;

    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/.well-known/acme-challenge/{}",
            ports.http, token
        ))
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 404);
    let body = response.text().await.into_diagnostic()?;
    assert_eq!(body, "Challenge expired");

    Ok(())
}

#[tokio::test]
async fn test_removal() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let token = "removable_token_123";
    let key_authorisation = "removable_key_auth_456";

    insert_acme_challenge(&daemon, token, key_authorisation, 3600).await?;

    // Verify it's accessible
    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/.well-known/acme-challenge/{}",
            ports.http, token
        ))
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);
    let body = response.text().await.into_diagnostic()?;
    assert_eq!(body, key_authorisation);

    remove_acme_challenge(&daemon, token).await?;

    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/.well-known/acme-challenge/{}",
            ports.http, token
        ))
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 404);
    let body = response.text().await.into_diagnostic()?;
    assert_eq!(body, "Challenge not found");

    Ok(())
}

#[tokio::test]
async fn test_multiple_tokens() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let challenges = vec![
        ("token1", "key_auth1"),
        ("token2", "key_auth2"),
        ("token3", "key_auth3"),
    ];

    for (token, key_auth) in &challenges {
        insert_acme_challenge(&daemon, token, key_auth, 3600).await?;
    }

    // Verify all challenges are accessible
    for (token, expected_key_auth) in &challenges {
        let response = reqwest::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/.well-known/acme-challenge/{}",
                ports.http, token
            ))
            .send()
            .await
            .into_diagnostic()?;

        assert_eq!(response.status(), 200);
        let body = response.text().await.into_diagnostic()?;
        assert_eq!(body, *expected_key_auth);
    }

    Ok(())
}

#[tokio::test]
async fn test_special_characters() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    // Test with URL-safe base64 characters commonly used in ACME tokens
    let token = "AbC_123-XyZ.890";
    let key_authorisation = "key_auth.with-special_chars_123.domain.com";

    insert_acme_challenge(&daemon, token, key_authorisation, 3600).await?;

    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/.well-known/acme-challenge/{}",
            ports.http, token
        ))
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);
    let body = response.text().await.into_diagnostic()?;
    assert_eq!(body, key_authorisation);

    Ok(())
}

#[tokio::test]
async fn test_timing_edge_case() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let token = "timing_test_token";
    let key_authorisation = "timing_key_auth";

    // Insert a challenge that expires in 2 seconds
    insert_acme_challenge(&daemon, token, key_authorisation, 2).await?;

    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/.well-known/acme-challenge/{}",
            ports.http, token
        ))
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 200);
    let body = response.text().await.into_diagnostic()?;
    assert_eq!(body, key_authorisation);

    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    let response = reqwest::Client::new()
        .get(format!(
            "http://127.0.0.1:{}/.well-known/acme-challenge/{}",
            ports.http, token
        ))
        .send()
        .await
        .into_diagnostic()?;

    assert_eq!(response.status(), 404);
    let body = response.text().await.into_diagnostic()?;
    assert_eq!(body, "Challenge expired");

    Ok(())
}
