#![cfg(test)]
use std::time::Duration;

use miette::{IntoDiagnostic, Result};
use uuid::Uuid;

use crate::container::{ContainerContext, TestContainer, util};

#[tokio::test]
async fn test_unhealthy_node_excluded_from_dns() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports: daemon_ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let insert_peers_sql = vec![
        r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, is_nameserver, fs_port) VALUES ('peer-healthy', 'pubkey-1', '10.0.0.10', 40.7128, -74.0060, '192.168.1.10', NULL, 1, 8282)",
        r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, is_nameserver, fs_port) VALUES ('peer-unhealthy', 'pubkey-2', '10.0.0.20', 51.5074, -0.1278, '192.168.1.20', NULL, 1, 8282)",
    ];

    let insert_peers_sql_strings: Vec<String> = insert_peers_sql
        .into_iter()
        .map(ToString::to_string)
        .collect();

    util::execute_transactions(&daemon, &insert_peers_sql_strings).await?;

    let id = Uuid::now_v7().to_string();

    util::execute_transactions(
        &daemon,
        &[format!("INSERT INTO dns_records (id, domain, name, record_type, value, geo_enabled) VALUES ('{id}', 'example.com', 'geo', 'A', '192.168.1.100', 1)")]
    ).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let dig_before = std::process::Command::new("dig")
        .args([
            "@127.0.0.1",
            "-p",
            &daemon_ports.dns.to_string(),
            "geo.example.com",
            "A",
            "+short",
            "+tcp",
        ])
        .output()
        .into_diagnostic()?;

    let result_before = String::from_utf8_lossy(&dig_before.stdout)
        .trim()
        .to_string();

    assert!(
        result_before.contains("192.168.1.10") || result_before.contains("192.168.1.20"),
        "Should return one of the peer IPs before marking unhealthy, got: {result_before}"
    );

    let timestamp = jiff::Timestamp::now().as_second();
    util::execute_transactions(
        &daemon,
        &[format!(
            "INSERT INTO unhealthy_nodes (node_name, marked_unhealthy_at, failure_reason) VALUES ('peer-unhealthy', {timestamp}, 'integration test')"
        )]
    ).await?;

    tokio::time::sleep(Duration::from_secs(3)).await;

    for _ in 0..5 {
        let dig_after = std::process::Command::new("dig")
            .args([
                "@127.0.0.1",
                "-p",
                &daemon_ports.dns.to_string(),
                "geo.example.com",
                "A",
                "+short",
                "+tcp",
            ])
            .output()
            .into_diagnostic()?;

        let result_after = String::from_utf8_lossy(&dig_after.stdout)
            .trim()
            .to_string();

        assert!(
            !result_after.contains("192.168.1.20"),
            "Should NOT return unhealthy peer IP (192.168.1.20), got: {result_after}"
        );

        if result_after.contains("192.168.1.10") {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    panic!("DNS never returned healthy peer IP after marking peer-unhealthy");
}

#[tokio::test]
async fn test_node_recovery_restores_dns() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports: daemon_ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let insert_peers_sql = vec![
        r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, is_nameserver, fs_port) VALUES ('peer-1', 'pubkey-1', '10.0.0.10', 40.7128, -74.0060, '192.168.1.10', NULL, 1, 8282)",
        r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, is_nameserver, fs_port) VALUES ('peer-2', 'pubkey-2', '10.0.0.20', 51.5074, -0.1278, '192.168.1.20', NULL, 1, 8282)",
    ];

    let insert_peers_sql_strings: Vec<String> = insert_peers_sql
        .into_iter()
        .map(ToString::to_string)
        .collect();

    util::execute_transactions(&daemon, &insert_peers_sql_strings).await?;

    let id = Uuid::now_v7().to_string();

    util::execute_transactions(
        &daemon,
        &[format!("INSERT INTO dns_records (id, domain, name, record_type, value, geo_enabled) VALUES ('{id}', 'example.com', 'geo', 'A', '192.168.1.100', 1)")]
    ).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let timestamp = jiff::Timestamp::now().as_second();
    util::execute_transactions(
        &daemon,
        &[format!(
            "INSERT INTO unhealthy_nodes (node_name, marked_unhealthy_at, failure_reason) VALUES ('peer-1', {timestamp}, 'test failure')"
        )]
    ).await?;

    tokio::time::sleep(Duration::from_secs(3)).await;

    for _ in 0..5 {
        let dig_unhealthy = std::process::Command::new("dig")
            .args([
                "@127.0.0.1",
                "-p",
                &daemon_ports.dns.to_string(),
                "geo.example.com",
                "A",
                "+short",
                "+tcp",
            ])
            .output()
            .into_diagnostic()?;

        let result_unhealthy = String::from_utf8_lossy(&dig_unhealthy.stdout)
            .trim()
            .to_string();

        if !result_unhealthy.is_empty()
            && !result_unhealthy.contains("192.168.1.10")
            && result_unhealthy.contains("192.168.1.20")
        {
            break;
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    util::execute_transactions(
        &daemon,
        &["DELETE FROM unhealthy_nodes WHERE node_name = 'peer-1'".to_string()],
    )
    .await?;

    tokio::time::sleep(Duration::from_secs(3)).await;

    for _ in 0..5 {
        let dig_recovered = std::process::Command::new("dig")
            .args([
                "@127.0.0.1",
                "-p",
                &daemon_ports.dns.to_string(),
                "geo.example.com",
                "A",
                "+short",
                "+tcp",
            ])
            .output()
            .into_diagnostic()?;

        let result_recovered = String::from_utf8_lossy(&dig_recovered.stdout)
            .trim()
            .to_string();

        if result_recovered.contains("192.168.1.10") || result_recovered.contains("192.168.1.20") {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    panic!("DNS never returned recovered peer IP after marking healthy");
}

#[tokio::test]
async fn test_multiple_unhealthy_nodes_in_cluster() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports: daemon_ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let insert_peers_sql = vec![
        r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, is_nameserver, fs_port) VALUES ('peer-1', 'pubkey-1', '10.0.0.10', 40.7128, -74.0060, '192.168.1.10', NULL, 1, 8282)",
        r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, is_nameserver, fs_port) VALUES ('peer-2', 'pubkey-2', '10.0.0.20', 51.5074, -0.1278, '192.168.1.20', NULL, 1, 8282)",
        r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, is_nameserver, fs_port) VALUES ('peer-3', 'pubkey-3', '10.0.0.30', 35.6762, 139.6503, '192.168.1.30', NULL, 1, 8282)",
    ];

    let insert_peers_sql_strings: Vec<String> = insert_peers_sql
        .into_iter()
        .map(ToString::to_string)
        .collect();

    util::execute_transactions(&daemon, &insert_peers_sql_strings).await?;

    let id = Uuid::now_v7().to_string();

    util::execute_transactions(
        &daemon,
        &[format!("INSERT INTO dns_records (id, domain, name, record_type, value, geo_enabled) VALUES ('{id}', 'example.com', 'geo', 'A', '192.168.1.100', 1)")]
    ).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let timestamp = jiff::Timestamp::now().as_second();
    util::execute_transactions(
        &daemon,
        &[
            format!("INSERT INTO unhealthy_nodes (node_name, marked_unhealthy_at, failure_reason) VALUES ('peer-1', {timestamp}, 'test')"),
            format!("INSERT INTO unhealthy_nodes (node_name, marked_unhealthy_at, failure_reason) VALUES ('peer-2', {timestamp}, 'test')"),
        ]
    ).await?;

    tokio::time::sleep(Duration::from_secs(3)).await;

    for _ in 0..5 {
        let dig_output = std::process::Command::new("dig")
            .args([
                "@127.0.0.1",
                "-p",
                &daemon_ports.dns.to_string(),
                "geo.example.com",
                "A",
                "+short",
                "+tcp",
            ])
            .output()
            .into_diagnostic()?;

        let result = String::from_utf8_lossy(&dig_output.stdout)
            .trim()
            .to_string();

        assert!(
            !result.contains("192.168.1.10") && !result.contains("192.168.1.20"),
            "Should not return unhealthy peer IPs, got: {result}"
        );

        if result.contains("192.168.1.30") {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    panic!("DNS never returned only healthy peer IP (192.168.1.30)");
}
