#![cfg(test)]
use miette::{IntoDiagnostic, Result};

use crate::container::{ContainerContext, TestContainer, util};

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

    util::insert_dns_record(&d2, "test.example.com", "A", "192.168.1.100").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let stdout = util::query_database(&d1, "SELECT domain, name, record_type, value FROM dns_records WHERE domain = 'test.example.com';").await?;

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
        r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, fs_port) VALUES ('peer-nyc', 'pubkey-nyc-123', '10.0.0.10', 40.7128, -74.0060, '192.168.1.10', NULL, 8282)",
        r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, fs_port) VALUES ('peer-london', 'pubkey-london-456', '10.0.0.20', 51.5074, -0.1278, '192.168.1.20', NULL, 8282)",
        r"INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, fs_port) VALUES ('peer-tokyo', 'pubkey-tokyo-789', '10.0.0.30', 35.6762, 139.6503, '192.168.1.30', NULL, 8282)",
    ];

    for sql in insert_peers_sql {
        util::execute_transaction(&daemon, sql).await?;
    }

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let sql = r"INSERT INTO dns_records (domain, name, record_type, value, source_domain, ttl, priority, geo_enabled) VALUES ('geo.example.com', 'geo', 'A', '192.168.1.100', 'example.com', 300, 0, 1)";
    util::execute_transaction(&daemon, sql).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let peers_output = util::query_database(
        &daemon,
        "SELECT name, latitude, longitude, ipv4 FROM peers ORDER BY name;",
    )
    .await?;

    assert!(peers_output.contains("peer-nyc|40.7128|-74.006|192.168.1.10"));
    assert!(peers_output.contains("peer-london|51.5074|-0.1278|192.168.1.20"));
    assert!(peers_output.contains("peer-tokyo|35.6762|139.6503|192.168.1.30"));

    let dns_output = util::query_database(&daemon, "SELECT domain, name, record_type, geo_enabled FROM dns_records WHERE domain = 'geo.example.com';").await?;

    assert!(dns_output.contains("geo.example.com|geo|A|1"));

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

    util::generate_tls_certificate(&daemon, "wawa.ns.example.com", "dns.crt", "dns.key").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let dns_record_sql = r"INSERT INTO dns_records (domain, name, record_type, value, source_domain, ttl, priority, geo_enabled) VALUES ('test.example.com', 'test', 'A', '192.168.1.100', 'example.com', 300, 0, 0)";
    util::execute_transaction(&daemon, dns_record_sql).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let (stdout, stderr) = util::execute_command(&daemon, "timeout 5 openssl s_client -connect 127.0.0.1:853 -servername wawa.ns.example.com -verify_return_error").await?;
    let output = format!("{stdout}{stderr}");

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

    util::generate_tls_certificate(&daemon, "ns1.example.com", "ns1.crt", "ns1.key").await?;
    util::generate_tls_certificate(&daemon, "ns2.example.com", "ns2.crt", "ns2.key").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let dns_records_sql = [
        r"INSERT INTO dns_records (domain, name, record_type, value, source_domain, ttl, priority, geo_enabled) VALUES ('api.example.com', 'api', 'A', '192.168.1.10', 'example.com', 300, 0, 0)",
        r"INSERT INTO dns_records (domain, name, record_type, value, source_domain, ttl, priority, geo_enabled) VALUES ('api.test.com', 'api', 'A', '192.168.1.20', 'test.com', 300, 0, 0)",
    ];

    for sql in dns_records_sql {
        util::execute_transaction(&daemon, sql).await?;
    }

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

    let (ss_output, _) = util::execute_command(&daemon, "ss -tulpn").await?;

    assert!(
        ss_output.contains(":853"),
        "Port 853 should be listening when certificates are configured"
    );

    // Test SNI with ns1.example.com certificate
    let (ns1_stdout, ns1_stderr) = util::execute_command(&daemon, "timeout 5 openssl s_client -connect 127.0.0.1:853 -servername ns1.example.com -verify_return_error").await?;
    let ns1_output = format!("{ns1_stdout}{ns1_stderr}");

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
    let (ns2_stdout, ns2_stderr) = util::execute_command(&daemon, "timeout 5 openssl s_client -connect 127.0.0.1:853 -servername ns2.example.com -verify_return_error").await?;
    let ns2_output = format!("{ns2_stdout}{ns2_stderr}");

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
