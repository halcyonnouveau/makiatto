#![cfg(test)]
use miette::{IntoDiagnostic, Result};
use testcontainers::core::ExecCommand;

use crate::container::{ContainerContext, TestContainer, create_cert};

#[tokio::test]
async fn test_replication() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon1_container,
        ports: d1_ports,
        ..
    } = context.make_daemon().await?;

    let TestContainer {
        container: daemon2_container,
        ports: d2_ports,
        ..
    } = context.make_daemon().await?;

    let d1 = daemon1_container.unwrap();
    let d2 = daemon2_container.unwrap();

    let insert_sql = r#"INSERT INTO dns_records (domain, name, record_type, base_value, ttl, priority, geo_enabled) VALUES (\"example.com\", \"test\", \"A\", \"192.168.1.100\", 300, NULL, 0)"#;
    let json_payload = format!("[\"{insert_sql}\"]");

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
        .into_diagnostic()?;

    let _ = insert.stdout_to_vec().await.into_diagnostic()?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let mut query = d1
        .exec(ExecCommand::new(vec![
            "sqlite3",
            "/var/makiatto/cluster.db",
            "SELECT domain, name, record_type, base_value FROM dns_records WHERE domain = 'example.com';",
        ]))
        .await
        .into_diagnostic()?;

    let d1_stdout = query.stdout_to_vec().await.into_diagnostic()?;
    let stdout = String::from_utf8_lossy(&d1_stdout);

    assert!(!stdout.is_empty(), "No DNS record returned from d1 query");
    assert!(stdout.contains("example.com"));
    assert!(stdout.contains("test"));
    assert!(stdout.contains('A'));
    assert!(stdout.contains("192.168.1.100"));

    let dig_d1_output = std::process::Command::new("dig")
        .args([
            "@127.0.0.1",
            "-p",
            &d1_ports.dns.to_string(),
            "test.example.com",
            "A",
            "+short",
        ])
        .output()
        .into_diagnostic()?;

    let dig_d1_result = String::from_utf8_lossy(&dig_d1_output.stdout)
        .trim()
        .to_string();

    assert!(
        !dig_d1_result.is_empty(),
        "DNS resolution on d1 returned empty result"
    );
    assert!(
        dig_d1_result.contains("192.168.1.100"),
        "DNS resolution on d1 should return the correct IP"
    );

    let dig_d2_output = std::process::Command::new("dig")
        .args([
            "@127.0.0.1",
            "-p",
            &d2_ports.dns.to_string(),
            "test.example.com",
            "A",
            "+short",
        ])
        .output()
        .into_diagnostic()?;

    let dig_d2_result = String::from_utf8_lossy(&dig_d2_output.stdout)
        .trim()
        .to_string();

    assert!(
        !dig_d2_result.is_empty(),
        "DNS resolution on d2 returned empty result"
    );
    assert!(
        dig_d2_result.contains("192.168.1.100"),
        "DNS resolution on d2 should return the correct IP"
    );

    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_dns_geolocation() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports: daemon_ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    let insert_peers_sql = [
        r#"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6) VALUES (\"peer-nyc\", \"pubkey-nyc-123\", \"10.0.0.10/32\", 40.7128, -74.0060, \"192.168.1.10\", NULL)"#,
        r#"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6) VALUES (\"peer-london\", \"pubkey-london-456\", \"10.0.0.20/32\", 51.5074, -0.1278, \"192.168.1.20\", NULL)"#,
        r#"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6) VALUES (\"peer-tokyo\", \"pubkey-tokyo-789\", \"10.0.0.30/32\", 35.6762, 139.6503, \"192.168.1.30\", NULL)"#,
    ];

    let json_payload = format!(
        "[{}]",
        insert_peers_sql
            .iter()
            .map(|sql| format!("\"{sql}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut insert_peers = daemon
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
        .into_diagnostic()?;

    let _ = insert_peers.stdout_to_vec().await.into_diagnostic()?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let dns_record_sql = r#"INSERT INTO dns_records (domain, name, record_type, base_value, ttl, priority, geo_enabled) VALUES (\"example.com\", \"geo\", \"A\", \"192.168.1.100\", 300, NULL, 1)"#;
    let json_payload = format!("[\"{dns_record_sql}\"]");

    let mut insert_dns = daemon
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
        .into_diagnostic()?;

    let _ = insert_dns.stdout_to_vec().await.into_diagnostic()?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let mut query_peers = daemon
        .exec(ExecCommand::new(vec![
            "sqlite3",
            "/var/makiatto/cluster.db",
            "SELECT name, latitude, longitude, ipv4 FROM peers ORDER BY name;",
        ]))
        .await
        .into_diagnostic()?;

    let peers_stdout = query_peers.stdout_to_vec().await.into_diagnostic()?;
    let peers_output = String::from_utf8_lossy(&peers_stdout);

    assert!(peers_output.contains("peer-nyc|40.7128|-74.006|192.168.1.10"));
    assert!(peers_output.contains("peer-london|51.5074|-0.1278|192.168.1.20"));
    assert!(peers_output.contains("peer-tokyo|35.6762|139.6503|192.168.1.30"));

    let mut query_dns = daemon
        .exec(ExecCommand::new(vec![
            "sqlite3",
            "/var/makiatto/cluster.db",
            "SELECT domain, name, record_type, geo_enabled FROM dns_records WHERE domain = 'example.com';",
        ]))
        .await
        .into_diagnostic()?;

    let dns_stdout = query_dns.stdout_to_vec().await.into_diagnostic()?;
    let dns_output = String::from_utf8_lossy(&dns_stdout);

    assert!(dns_output.contains("example.com|geo|A|1"));

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

    let dig_result = String::from_utf8_lossy(&dig_output.stdout)
        .trim()
        .to_string();

    assert!(
        !dig_result.is_empty(),
        "DNS geolocation resolution returned empty result"
    );

    assert!(
        dig_result.contains("192.168.1.10")
            || dig_result.contains("192.168.1.20")
            || dig_result.contains("192.168.1.30"),
        "DNS geolocation should return one of the peer IPs, got: {dig_result}",
    );

    Ok(())
}

#[tokio::test]
async fn test_over_tls_with_certificates() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    create_cert(&daemon, "wawa.ns.example.com", "dns.crt", "dns.key").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let dns_record_sql = r#"INSERT INTO dns_records (domain, name, record_type, base_value, ttl, priority, geo_enabled) VALUES (\"example.com\", \"test\", \"A\", \"192.168.1.100\", 300, NULL, 0)"#;
    let json_payload = format!("[\"{dns_record_sql}\"]");

    let mut insert_dns = daemon
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
        .into_diagnostic()?;

    let _ = insert_dns.stdout_to_vec().await.into_diagnostic()?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let mut result = daemon
        .exec(ExecCommand::new(vec![
            "timeout",
            "5",
            "openssl",
            "s_client",
            "-connect",
            "127.0.0.1:853",
            "-servername",
            "wawa.ns.example.com",
            "-verify_return_error",
        ]))
        .await
        .into_diagnostic()?;

    let stdout = result.stdout_to_vec().await.unwrap_or_default();
    let stderr = result.stderr_to_vec().await.unwrap_or_default();
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );

    assert!(
        output.contains("CONNECTED")
            || output.contains("Verification: OK")
            || output.contains("SSL-Session"),
        "DoT TLS connection should work when certificates are configured. Output: {output}",
    );

    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_multi_domain_sni() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        ports,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    create_cert(&daemon, "ns1.example.com", "ns1.crt", "ns1.key").await?;
    create_cert(&daemon, "ns2.example.com", "ns2.crt", "ns2.key").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let dns_records_sql = [
        r#"INSERT INTO dns_records (domain, name, record_type, base_value, ttl, priority, geo_enabled) VALUES (\"example.com\", \"api\", \"A\", \"192.168.1.10\", 300, NULL, 0)"#,
        r#"INSERT INTO dns_records (domain, name, record_type, base_value, ttl, priority, geo_enabled) VALUES (\"test.com\", \"api\", \"A\", \"192.168.1.20\", 300, NULL, 0)"#,
    ];

    let json_payload = format!(
        "[{}]",
        dns_records_sql
            .iter()
            .map(|sql| format!("\"{sql}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut insert_dns = daemon
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
        .into_diagnostic()?;

    let _ = insert_dns.stdout_to_vec().await.into_diagnostic()?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let dig_example_output = std::process::Command::new("dig")
        .args([
            "@127.0.0.1",
            "-p",
            &ports.dns.to_string(),
            "api.example.com",
            "A",
            "+short",
        ])
        .output()
        .into_diagnostic()?;

    let example_result = String::from_utf8_lossy(&dig_example_output.stdout)
        .trim()
        .to_string();

    assert!(
        !example_result.is_empty(),
        "DNS resolution for example.com should work"
    );
    assert!(
        example_result.contains("192.168.1.10"),
        "DNS should return correct IP for example.com"
    );

    let dig_test_output = std::process::Command::new("dig")
        .args([
            "@127.0.0.1",
            "-p",
            &ports.dns.to_string(),
            "api.test.com",
            "A",
            "+short",
        ])
        .output()
        .into_diagnostic()?;

    let test_result = String::from_utf8_lossy(&dig_test_output.stdout)
        .trim()
        .to_string();

    assert!(
        !test_result.is_empty(),
        "DNS resolution for test.com should work"
    );
    assert!(
        test_result.contains("192.168.1.20"),
        "DNS should return correct IP for test.com"
    );

    let mut ss = daemon
        .exec(ExecCommand::new(vec!["ss", "-tulpn"]))
        .await
        .into_diagnostic()?;

    let ss_output = ss.stdout_to_vec().await.into_diagnostic()?;
    let ss_str = String::from_utf8_lossy(&ss_output);

    assert!(
        ss_str.contains(":853"),
        "Port 853 should be listening when certificates are configured"
    );

    // Test SNI with ns1.example.com certificate
    let mut ns1_result = daemon
        .exec(ExecCommand::new(vec![
            "timeout",
            "5",
            "openssl",
            "s_client",
            "-connect",
            "127.0.0.1:853",
            "-servername",
            "ns1.example.com",
            "-verify_return_error",
        ]))
        .await
        .into_diagnostic()?;

    let ns1_stdout = ns1_result.stdout_to_vec().await.unwrap_or_default();
    let ns1_stderr = ns1_result.stderr_to_vec().await.unwrap_or_default();
    let ns1_output = format!(
        "{}{}",
        String::from_utf8_lossy(&ns1_stdout),
        String::from_utf8_lossy(&ns1_stderr)
    );

    assert!(
        ns1_output.contains("CONNECTED")
            || ns1_output.contains("Verification: OK")
            || ns1_output.contains("SSL-Session"),
        "DoT TLS connection should work for ns1.example.com. Output: {ns1_output}",
    );

    assert!(
        ns1_output.contains("ns1.example.com"),
        "Certificate should be for ns1.example.com. Output: {ns1_output}",
    );

    // Test SNI with ns2.example.com certificate
    let mut ns2_result = daemon
        .exec(ExecCommand::new(vec![
            "timeout",
            "5",
            "openssl",
            "s_client",
            "-connect",
            "127.0.0.1:853",
            "-servername",
            "ns2.example.com",
            "-verify_return_error",
        ]))
        .await
        .into_diagnostic()?;

    let ns2_stdout = ns2_result.stdout_to_vec().await.unwrap_or_default();
    let ns2_stderr = ns2_result.stderr_to_vec().await.unwrap_or_default();
    let ns2_output = format!(
        "{}{}",
        String::from_utf8_lossy(&ns2_stdout),
        String::from_utf8_lossy(&ns2_stderr)
    );

    assert!(
        ns2_output.contains("CONNECTED")
            || ns2_output.contains("Verification: OK")
            || ns2_output.contains("SSL-Session"),
        "DoT TLS connection should work for ns2.example.com. Output: {ns2_output}",
    );

    assert!(
        ns2_output.contains("ns2.example.com"),
        "Certificate should be for ns2.example.com. Output: {ns2_output}",
    );

    Ok(())
}
