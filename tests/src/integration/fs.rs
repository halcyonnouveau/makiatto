#![cfg(test)]
use std::sync::Arc;

use blake3::Hasher;
use miette::Result;
use testcontainers::{ContainerAsync, GenericImage};

use crate::container::{ContainerContext, TestContainer, util};

/// Insert a peer with external file sync port via Corrosion API
pub async fn insert_peer_with_fs_port(
    daemon: &Arc<ContainerAsync<GenericImage>>,
    name: &str,
    wg_address: &str,
    ipv4: &str,
    fs_port: u16,
) -> Result<()> {
    let sql = format!(
        "INSERT INTO peers (name, wg_public_key, wg_address, latitude, longitude, ipv4, ipv6, fs_port) VALUES ('{name}', 'test-pubkey', '{wg_address}', 0.0, 0.0, '{ipv4}', NULL, {fs_port})",
    );
    util::execute_transaction(daemon, &sql).await
}

/// Create a test file in the container's static directory
pub async fn create_test_file(
    daemon: &Arc<ContainerAsync<GenericImage>>,
    domain: &str,
    path: &str,
    content: &str,
) -> Result<String> {
    let domain_dir = format!("/var/makiatto/sites/{domain}");
    util::execute_command(daemon, &format!("mkdir -p {domain_dir}")).await?;

    // Write file content
    let full_path = format!(
        "{}/{}",
        domain_dir.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let write_cmd = format!("echo '{content}' > '{full_path}'");
    util::execute_command(daemon, &write_cmd).await?;

    let mut hasher = Hasher::new();
    hasher.update(content.as_bytes());
    let content_hash = hasher.finalize().to_hex().to_string();

    Ok(content_hash)
}

/// Create a large test file using repeating pattern
pub async fn create_large_test_file(
    daemon: &Arc<ContainerAsync<GenericImage>>,
    domain: &str,
    path: &str,
    size_mb: u64,
) -> Result<()> {
    let domain_dir = format!("/var/makiatto/sites/{domain}");
    util::execute_command(daemon, &format!("mkdir -p {domain_dir}")).await?;

    let full_path = format!(
        "{}/{}",
        domain_dir.trim_end_matches('/'),
        path.trim_start_matches('/')
    );

    let create_cmd = format!(
        "yes 'This is a test pattern for large file sync in makiatto CDN!' | head -c {size_mb}M > '{full_path}' && sync",
    );
    util::execute_command(daemon, &create_cmd).await?;
    util::execute_command(daemon, "sudo chown -R makiatto:makiatto /var/makiatto").await?;

    // Wait longer and verify file creation completed
    let expected_size = size_mb * 1024 * 1024;
    let mut retries = 0;
    loop {
        let (size_output, _) = util::execute_command(
            daemon,
            &format!("stat -c%s '{full_path}' 2>/dev/null || echo 0"),
        )
        .await?;
        let actual_size = size_output.trim().parse::<u64>().unwrap_or(0);

        if actual_size == expected_size {
            break;
        }

        retries += 1;
        if retries > 20 {
            return Err(miette::miette!("File creation timed out after 10 seconds"));
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    Ok(())
}

/// Verify that a file exists with expected content
pub async fn verify_file_content(
    daemon: &Arc<ContainerAsync<GenericImage>>,
    domain: &str,
    path: &str,
    expected_content: &str,
) -> Result<bool> {
    let full_path = format!(
        "/var/makiatto/sites/{}/{}",
        domain,
        path.trim_start_matches('/')
    );
    let (stdout, _) = util::execute_command(daemon, &format!("cat '{full_path}'")).await?;
    Ok(stdout.trim() == expected_content)
}

/// Verify that a file sync between two daemons worked
pub async fn verify_file_sync(
    source_daemon: &Arc<ContainerAsync<GenericImage>>,
    target_daemon: &Arc<ContainerAsync<GenericImage>>,
    domain: &str,
    path: &str,
    expected_content: &str,
) -> Result<bool> {
    // Give a bit more time for sync to propagate
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let source_has_file =
        verify_file_content(source_daemon, domain, path, expected_content).await?;

    if !source_has_file {
        return Ok(false);
    }

    verify_file_content(target_daemon, domain, path, expected_content).await
}

#[tokio::test]
async fn test_file_sync_basic() -> Result<()> {
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

    // Add peers to each daemon's database with their file sync ports using gateway IP for wg_address
    insert_peer_with_fs_port(
        &d1,
        "daemon2",
        &context.gateway_ip,
        "127.0.0.1",
        d2_ports.fs,
    )
    .await?;
    insert_peer_with_fs_port(
        &d2,
        "daemon1",
        &context.gateway_ip,
        "127.0.0.1",
        d1_ports.fs,
    )
    .await?;

    let test_content = "Hello from daemon1";
    let _content_hash = create_test_file(&d1, "example.com", "/test.txt", test_content).await?;

    assert!(verify_file_sync(&d1, &d2, "example.com", "/test.txt", test_content).await?);

    Ok(())
}

#[tokio::test]
async fn test_file_deletion_sync() -> Result<()> {
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

    insert_peer_with_fs_port(
        &d1,
        "daemon2",
        &context.gateway_ip,
        "127.0.0.1",
        d2_ports.fs,
    )
    .await?;
    insert_peer_with_fs_port(
        &d2,
        "daemon1",
        &context.gateway_ip,
        "127.0.0.1",
        d1_ports.fs,
    )
    .await?;

    let test_content = "File to be deleted";
    let _content_hash =
        create_test_file(&d1, "example.com", "/delete-me.txt", test_content).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    assert!(verify_file_content(&d1, "example.com", "/delete-me.txt", test_content).await?);
    assert!(verify_file_content(&d2, "example.com", "/delete-me.txt", test_content).await?);

    util::execute_command(&d1, "rm /var/makiatto/sites/example.com/delete-me.txt").await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    assert!(
        !verify_file_content(&d2, "example.com", "/delete-me.txt", test_content).await?,
        "File should have been deleted from daemon2"
    );

    Ok(())
}

#[tokio::test]
async fn test_content_deduplication() -> Result<()> {
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

    // Setup peers
    insert_peer_with_fs_port(
        &d1,
        "daemon2",
        &context.gateway_ip,
        "127.0.0.1",
        d2_ports.fs,
    )
    .await?;
    insert_peer_with_fs_port(
        &d2,
        "daemon1",
        &context.gateway_ip,
        "127.0.0.1",
        d1_ports.fs,
    )
    .await?;

    // Create two files with identical content
    let duplicate_content = "Same content in both files";
    let hash1 = create_test_file(&d1, "example.com", "/file1.txt", duplicate_content).await?;

    // Add delay between file creations to avoid race conditions
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let hash2 = create_test_file(&d1, "example.com", "/file2.txt", duplicate_content).await?;

    assert_eq!(
        hash1, hash2,
        "Files with identical content should have the same hash"
    );

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let file1_synced =
        verify_file_sync(&d1, &d2, "example.com", "/file1.txt", duplicate_content).await?;
    let file2_synced =
        verify_file_sync(&d1, &d2, "example.com", "/file2.txt", duplicate_content).await?;

    assert!(file1_synced, "File1 should have synced to daemon2");
    assert!(file2_synced, "File2 should have synced to daemon2");

    Ok(())
}

#[tokio::test]
async fn test_file_edit_sync() -> Result<()> {
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

    // Setup peers
    insert_peer_with_fs_port(
        &d1,
        "daemon2",
        &context.gateway_ip,
        "127.0.0.1",
        d2_ports.fs,
    )
    .await?;
    insert_peer_with_fs_port(
        &d2,
        "daemon1",
        &context.gateway_ip,
        "127.0.0.1",
        d1_ports.fs,
    )
    .await?;

    // Create initial file
    let initial_content = "Initial file content";
    let _initial_hash =
        create_test_file(&d1, "example.com", "/edit-me.txt", initial_content).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verify initial sync worked
    assert!(
        verify_file_sync(&d1, &d2, "example.com", "/edit-me.txt", initial_content).await?,
        "Initial files should be synced"
    );

    // Edit the file with new content
    let updated_content = "Updated file content after edit";
    let _updated_hash =
        create_test_file(&d1, "example.com", "/edit-me.txt", updated_content).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    assert!(
        verify_file_sync(&d1, &d2, "example.com", "/edit-me.txt", updated_content).await?,
        "Updated files should be synced"
    );

    // Verify the old content is no longer present on either daemon
    assert!(!verify_file_content(&d1, "example.com", "/edit-me.txt", initial_content).await?);
    assert!(!verify_file_content(&d2, "example.com", "/edit-me.txt", initial_content).await?);

    Ok(())
}

#[tokio::test]
async fn test_large_file_sync() -> Result<()> {
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

    // Setup peers
    insert_peer_with_fs_port(
        &d1,
        "daemon2",
        &context.gateway_ip,
        "127.0.0.1",
        d2_ports.fs,
    )
    .await?;
    insert_peer_with_fs_port(
        &d2,
        "daemon1",
        &context.gateway_ip,
        "127.0.0.1",
        d1_ports.fs,
    )
    .await?;

    // Create a 150MB file (above streaming threshold of 100MB)
    create_large_test_file(&d1, "example.com", "/large-video.bin", 150).await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    let (size1, _) = util::execute_command(
        &d1,
        "stat -c%s /var/makiatto/sites/example.com/large-video.bin 2>/dev/null || echo 0",
    )
    .await?;

    let (size2, _) = util::execute_command(
        &d2,
        "stat -c%s /var/makiatto/sites/example.com/large-video.bin 2>/dev/null || echo 0",
    )
    .await?;

    let expected_size = 150 * 1024 * 1024; // 150MB in bytes
    let actual_size1 = size1.trim().parse::<u64>().unwrap_or(0);
    let actual_size2 = size2.trim().parse::<u64>().unwrap_or(0);

    assert!(
        actual_size1 == expected_size,
        "Large file should exist on daemon1 with correct size. Expected: {expected_size}, Actual: {actual_size1}, Raw output: '{size1}'"
    );

    assert!(
        actual_size2 == expected_size,
        "Large file should have synced to daemon2 with correct size. Expected: {expected_size}, Actual: {actual_size2}, Raw output: '{size2}'"
    );

    // Verify content matches by comparing first few bytes
    let (content1, _) = util::execute_command(
        &d1,
        "head -c 100 /var/makiatto/sites/example.com/large-video.bin",
    )
    .await?;

    let (content2, _) = util::execute_command(
        &d2,
        "head -c 100 /var/makiatto/sites/example.com/large-video.bin",
    )
    .await?;

    assert_eq!(
        content1.trim(),
        content2.trim(),
        "File content should match between daemons"
    );

    Ok(())
}
