#![cfg(test)]
use miette::Result;

use crate::container::{ContainerContext, TestContainer, util};

#[tokio::test]
async fn test_corrosion() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon1_container,
        ..
    } = context.make_daemon().await?;

    let TestContainer {
        container: daemon2_container,
        ..
    } = context.make_daemon().await?;

    let d1 = daemon1_container.unwrap();
    let d2 = daemon2_container.unwrap();

    let insert_sql = r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6) VALUES ('test-peer', 'test-pubkey-123', '10.0.0.99/32', 12.345, 67.890, '192.168.1.99', NULL)";
    util::execute_transaction(&d2, insert_sql).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let stdout = util::query_database(
        &d1,
        "SELECT name, wg_public_key, ipv4 FROM peers WHERE name = 'test-peer';",
    )
    .await?;

    assert!(!stdout.is_empty(), "No data returned from d1 query");
    assert!(stdout.contains("test-peer"));
    assert!(stdout.contains("test-pubkey-123"));
    assert!(stdout.contains("192.168.1.99"));

    Ok(())
}
