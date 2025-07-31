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

    // Should find the soon-expiring and expired certificates
    assert!(output.contains("soon-expire.com"));
    assert!(output.contains("expired.com"));
    assert!(!output.contains("far-expire.com"));

    Ok(())
}

#[tokio::test]
async fn test_renewal_status_tracking() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    util::insert_renewal_status(&daemon, "test1.com", "completed", 0).await?;
    util::insert_renewal_status(&daemon, "test2.com", "in_progress", 1).await?;
    util::insert_renewal_status(&daemon, "test3.com", "failed", 3).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Query renewal status
    let output = util::query_database(
        &daemon,
        "SELECT domain, renewal_status, retry_count FROM certificate_renewals ORDER BY domain;",
    )
    .await?;

    assert!(output.contains("test1.com|completed|0"));
    assert!(output.contains("test2.com|in_progress|1"));
    assert!(output.contains("test3.com|failed|3"));

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

    util::insert_dns_record(&daemon, "web.example.com", "A", "192.168.1.1").await?;
    util::insert_dns_record(&daemon, "api.example.com", "A", "192.168.1.2").await?;
    util::insert_dns_record(&daemon, "mail.example.com", "MX", "10 mail.example.com").await?;
    util::insert_dns_record(&daemon, "cdn.example.com", "CNAME", "cdn.provider.com").await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Query for candidate domains (A, AAAA, CNAME records)
    let output = util::query_database(&daemon, "SELECT DISTINCT domain FROM dns_records WHERE record_type IN ('A', 'AAAA', 'CNAME') ORDER BY domain;").await?;

    assert!(output.contains("web.example.com"));
    assert!(output.contains("api.example.com"));
    assert!(output.contains("cdn.example.com"));
    // MX records shouldn't be included as certificate candidates
    assert!(!output.contains("mail.example.com"));

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
    util::execute_transaction(&daemon, sql).await?;

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

    // Query for domains that have exceeded retry limit (assuming limit is 3)
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

    // Insert a second certificate with different issuer
    let expires_at = util::current_timestamp() + (30 * 86400);
    let sql = format!(
        "INSERT INTO certificates (domain, certificate_pem, private_key_pem, expires_at, issuer) VALUES ('internal.com', 'cert2', 'key2', {expires_at}, 'internal_ca')"
    );
    util::execute_transaction(&daemon, &sql).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Query certificates by issuer
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

    // Verify first certificate exists
    let output = util::query_database(
        &daemon,
        &format!("SELECT COUNT(*) FROM certificates WHERE domain = '{domain}';"),
    )
    .await?;
    assert!(output.trim() == "1");

    // Replace with new certificate (longer expiry)
    let new_expires_at = util::current_timestamp() + (90 * 86400); // 90 days
    let update_sql = format!(
        "UPDATE certificates SET expires_at = {new_expires_at}, issuer = 'lets_encrypt' WHERE domain = '{domain}'"
    );
    util::execute_transaction(&daemon, &update_sql).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify certificate was updated, not duplicated
    let count_output = util::query_database(
        &daemon,
        &format!("SELECT COUNT(*) FROM certificates WHERE domain = '{domain}';"),
    )
    .await?;
    assert!(
        count_output.trim() == "1",
        "Should have only one certificate for domain"
    );

    // Verify issuer was updated
    let issuer_output = util::query_database(
        &daemon,
        &format!("SELECT issuer FROM certificates WHERE domain = '{domain}';"),
    )
    .await?;
    assert!(issuer_output.contains("lets_encrypt"));

    Ok(())
}
