#![cfg(test)]
use miette::{IntoDiagnostic, Result, miette};
use testcontainers::core::ExecCommand;

use crate::container::{ContainerContext, TestContainer};

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

    let insert_sql = "INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6) VALUES (\\\"test-peer\\\", \\\"test-pubkey-123\\\", \\\"10.0.0.99/32\\\", 12.345, 67.890, \\\"192.168.1.99\\\", NULL)";
    let json_payload = format!("[\"{insert_sql}\"]");

    // I DONT KNOW WHY BUT REMOVING THIS MAKES THE TEST FAIL
    // WHAT THE FUCK IS HAPPENING
    let mut warmup = d2
        .exec(ExecCommand::new(vec![
            "curl",
            "-s",
            "-f",
            "http://127.0.0.1:8181/",
            "-o",
            "/dev/null",
        ]))
        .await
        .map_err(|e| miette!("Failed to warm up network: {e}"))?;

    let _ = warmup.stdout_to_vec().await.into_diagnostic()?;

    let mut insert = d2
        .exec(ExecCommand::new(vec![
            "curl",
            "-s",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            &json_payload,
            "http://127.0.0.1:8181/v1/transactions",
        ]))
        .await
        .map_err(|e| miette!("Failed to insert peer in d2: {e}"))?;

    let _ = insert.stdout_to_vec().await.into_diagnostic()?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let mut query = d1
        .exec(ExecCommand::new(vec![
            "sqlite3",
            "/var/makiatto/cluster.db",
            "SELECT name, wg_public_key, ipv4 FROM peers WHERE name = 'test-peer';",
        ]))
        .await
        .map_err(|e| miette!("Failed to query d1: {e}"))?;

    let d1_stdout = query.stdout_to_vec().await.into_diagnostic()?;
    let stdout = String::from_utf8_lossy(&d1_stdout);

    assert!(!stdout.is_empty(), "No data returned from d1 query");
    assert!(stdout.contains("test-peer"));
    assert!(stdout.contains("test-pubkey-123"));
    assert!(stdout.contains("192.168.1.99"));

    Ok(())
}
