#![cfg(test)]
use std::time::Duration;

use miette::Result;

use crate::container::{ContainerContext, TestContainer, util};

#[tokio::test]
async fn test_certificate_storage_and_retrieval() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let domain = "example.com";
    util::insert_certificate_record(&daemon, domain, 30).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    let output = util::query_database(
        &daemon,
        "SELECT domain, expires_at, issuer FROM certificates WHERE domain = 'example.com';",
    )
    .await?;

    assert!(output.contains("example.com"));
    assert!(output.contains("test_ca"));

    Ok(())
}

#[tokio::test]
async fn test_certificate_expiration_detection() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    util::insert_certificate_record(&daemon, "soon-expire.com", 5).await?; // Expires in 5 days
    util::insert_certificate_record(&daemon, "far-expire.com", 60).await?; // Expires in 60 days
    util::insert_certificate_record(&daemon, "expired.com", -5).await?; // Already expired

    tokio::time::sleep(Duration::from_secs(1)).await;

    let threshold_time = util::current_timestamp() + (30 * 86400);
    let output = util::query_database(
        &daemon,
        &format!("SELECT domain FROM certificates WHERE expires_at <= {threshold_time};"),
    )
    .await?;

    // should find the soon-expiring and expired certificates
    assert!(output.contains("soon-expire.com"));
    assert!(output.contains("expired.com"));
    assert!(!output.contains("far-expire.com"));

    Ok(())
}

#[tokio::test]
async fn test_candidate_domain_discovery() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    util::insert_dns_record(&daemon, "example.com", "web", "A", "192.168.1.1").await?;
    util::insert_dns_record(&daemon, "example.com", "api", "A", "192.168.1.2").await?;
    util::insert_dns_record(&daemon, "example.com", "mail", "MX", "10 mail.example.com").await?;
    util::insert_dns_record(&daemon, "example.com", "cdn", "CNAME", "cdn.provider.com").await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    let output = util::query_database(&daemon, "SELECT DISTINCT name FROM dns_records WHERE record_type IN ('A', 'AAAA', 'CNAME') ORDER BY domain;").await?;

    assert!(output.contains("web"));
    assert!(output.contains("api"));
    assert!(output.contains("cdn"));
    assert!(!output.contains("mail"));

    Ok(())
}

#[tokio::test]
async fn test_domain_alias_support() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let sql =
        "INSERT INTO domain_aliases (alias, target) VALUES ('www.example.com', 'example.com')";
    util::execute_transactions(&daemon, &[sql.to_string()]).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    let output = util::query_database(&daemon, "SELECT DISTINCT domain FROM (SELECT domain FROM dns_records WHERE record_type IN ('A', 'AAAA', 'CNAME') UNION SELECT alias AS domain FROM domain_aliases) ORDER BY domain;").await?;

    assert!(output.contains("www.example.com"));

    Ok(())
}

#[tokio::test]
async fn test_certificate_retry_limit() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    util::insert_renewal_status(&daemon, "max-retry.com", "failed", 5).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    let output = util::query_database(
        &daemon,
        "SELECT domain, retry_count FROM certificate_renewals WHERE retry_count >= 3;",
    )
    .await?;

    assert!(output.contains("max-retry.com|5"));

    Ok(())
}

#[tokio::test]
async fn test_certificate_issuer_tracking() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    util::insert_certificate_record(&daemon, "letsencrypt.com", 30).await?;

    let expires_at = util::current_timestamp() + (30 * 86400);
    let sql = format!(
        "INSERT INTO certificates (domain, certificate_pem, private_key_pem, expires_at, issuer) VALUES ('internal.com', 'cert2', 'key2', {expires_at}, 'internal_ca')"
    );
    util::execute_transactions(&daemon, &[sql]).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    let output = util::query_database(
        &daemon,
        "SELECT domain, issuer FROM certificates ORDER BY domain;",
    )
    .await?;

    assert!(output.contains("internal.com|internal_ca"));
    assert!(output.contains("letsencrypt.com|test_ca"));

    Ok(())
}

#[tokio::test]
async fn test_certificate_replacement() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let domain = "example.com";

    util::insert_certificate_record(&daemon, domain, 5).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    // verify first certificate exists
    let output = util::query_database(
        &daemon,
        &format!("SELECT COUNT(*) FROM certificates WHERE domain = '{domain}';"),
    )
    .await?;
    assert!(output.trim() == "1");

    // replace with new certificate (longer expiry)
    let new_expires_at = util::current_timestamp() + (90 * 86400); // 90 days
    let update_sql = format!(
        "UPDATE certificates SET expires_at = {new_expires_at}, issuer = 'lets_encrypt' WHERE domain = '{domain}'"
    );
    util::execute_transactions(&daemon, &[update_sql]).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    // verify certificate was updated, not duplicated
    let count_output = util::query_database(
        &daemon,
        &format!("SELECT COUNT(*) FROM certificates WHERE domain = '{domain}';"),
    )
    .await?;
    assert!(
        count_output.trim() == "1",
        "Should have only one certificate for domain"
    );

    let issuer_output = util::query_database(
        &daemon,
        &format!("SELECT issuer FROM certificates WHERE domain = '{domain}';"),
    )
    .await?;
    assert!(issuer_output.contains("lets_encrypt"));

    Ok(())
}
