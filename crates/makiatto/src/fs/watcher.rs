use std::os::unix::fs::MetadataExt;
use std::{path::PathBuf, sync::Arc};

use blake3::Hasher;
use futures_util::StreamExt;
use miette::Result;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rand::{Rng, seq::SliceRandom};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    corrosion::{self, schema::File},
    util,
};

// Use streaming for files larger than 100MB
const STREAMING_THRESHOLD: u64 = 100 * 1024 * 1024; // 100MB

/// File watcher service that monitors `static_dir` for changes
///
/// # Errors
/// Returns an error if the file watcher cannot be created or started
pub async fn start(config: Arc<Config>, mut shutdown_rx: mpsc::Receiver<()>) -> Result<()> {
    let static_dir = config.web.static_dir.as_std_path();
    let storage_dir = config.fs.storage_dir.as_std_path();

    info!("Starting file watcher for {}", static_dir.display());

    let (tx, mut rx) = mpsc::channel(100);

    // Create file watcher
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            if let Ok(event) = res
                && let Err(e) = tx.blocking_send(event)
            {
                error!("Failed to send file event: {e}");
            }
        },
        notify::Config::default(),
    )
    .map_err(|e| miette::miette!("Failed to create file watcher: {e}"))?;

    // Start watching the static directory
    watcher
        .watch(static_dir, RecursiveMode::Recursive)
        .map_err(|e| miette::miette!("Failed to watch directory {}: {e}", static_dir.display()))?;

    loop {
        tokio::select! {
            // Handle shutdown signal
            _ = shutdown_rx.recv() => {
                info!("File watcher received shutdown signal");
                break;
            }

            // Handle file system events
            Some(event) = rx.recv() => {
                if let Err(e) = handle_file_event(&event, static_dir, storage_dir, &config).await {
                    error!("Failed to handle file event: {e}");
                }
            }
        }
    }

    Ok(())
}

/// Handle individual file system events
async fn handle_file_event(
    event: &Event,
    static_dir: &std::path::Path,
    storage_dir: &std::path::Path,
    config: &Config,
) -> Result<()> {
    // Only handle file creation and modification events
    match event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {
            let file_records = process_file_changes(&event.paths, static_dir, storage_dir).await;

            if !file_records.is_empty()
                && let Err(e) = update_file_records(&file_records, config).await
            {
                error!("Failed to batch update file records: {e}");
            }
        }
        EventKind::Remove(_) => {
            let delete_records = collect_file_deletions(&event.paths, static_dir);

            if !delete_records.is_empty()
                && let Err(e) = delete_file_records(&delete_records).await
            {
                error!("Failed to batch delete file records: {e}");
            }
        }
        _ => {} // Ignore other event types
    }

    Ok(())
}

/// Process multiple file changes in batch
async fn process_file_changes(
    paths: &[std::path::PathBuf],
    static_dir: &std::path::Path,
    storage_dir: &std::path::Path,
) -> Vec<File> {
    let mut file_records = Vec::new();

    for path in paths {
        match process_file_change(path, static_dir, storage_dir).await {
            Ok(Some(record)) => file_records.push(record),
            Ok(None) => {} // File was skipped (not a file, etc.)
            Err(e) => warn!("Failed to process file change for {}: {e}", path.display()),
        }
    }

    file_records
}

/// Collect file deletions for batch processing
fn collect_file_deletions(
    paths: &[std::path::PathBuf],
    static_dir: &std::path::Path,
) -> Vec<(String, String)> {
    let mut delete_records = Vec::new();

    for path in paths {
        match parse_domain_and_path(path, static_dir) {
            Ok((domain, normalized_path)) => {
                info!(
                    "File removed: {} ({}{})",
                    path.display(),
                    domain,
                    normalized_path
                );
                delete_records.push((domain.to_string(), normalized_path));
            }
            Err(e) => warn!("Failed to process file removal for {}: {e}", path.display()),
        }
    }

    delete_records
}

/// Parse domain and path from a file path relative to static dir
///
/// # Errors
/// Returns an error if the file path is outside the static directory or has invalid encoding
pub fn parse_domain_and_path<'a>(
    file_path: &'a std::path::Path,
    static_dir: &std::path::Path,
) -> Result<(&'a str, String)> {
    let relative_path = file_path
        .strip_prefix(static_dir)
        .map_err(|e| miette::miette!("File outside static directory: {e}"))?;

    let mut components = relative_path.components();
    let domain = components
        .next()
        .and_then(|c| c.as_os_str().to_str())
        .ok_or_else(|| miette::miette!("Could not extract domain from path"))?;

    let file_relative_path = components
        .as_path()
        .to_str()
        .ok_or_else(|| miette::miette!("Invalid path encoding"))?;

    // Ensure path starts with /
    let normalised_path = if file_relative_path.starts_with('/') {
        file_relative_path.to_string()
    } else {
        format!("/{file_relative_path}")
    };

    Ok((domain, normalised_path))
}

/// Process a single file change for batching
async fn process_file_change(
    file_path: &std::path::Path,
    static_dir: &std::path::Path,
    storage_dir: &std::path::Path,
) -> Result<Option<File>> {
    if !file_path.is_file() {
        return Ok(None);
    }

    let (domain, normalised_path) = parse_domain_and_path(file_path, static_dir)?;

    // Handle race condition: check if file was modified during processing
    let metadata_before = tokio::fs::metadata(file_path)
        .await
        .map_err(|e| miette::miette!("Failed to get file metadata: {e}"))?;

    // Check if file was modified during read
    let metadata_after = tokio::fs::metadata(file_path)
        .await
        .map_err(|e| miette::miette!("Failed to get file metadata after read: {e}"))?;

    let modified_before = metadata_before
        .modified()
        .map_err(|e| miette::miette!("Failed to get modification time: {e}"))?;

    let modified_after = metadata_after
        .modified()
        .map_err(|e| miette::miette!("Failed to get modification time: {e}"))?;

    if modified_before != modified_after {
        warn!(
            "File {} was modified during processing, retrying",
            file_path.display()
        );
        return Box::pin(process_file_change(file_path, static_dir, storage_dir)).await;
    }

    let file_size = metadata_before.len();

    let hash = if file_size > STREAMING_THRESHOLD {
        debug!(
            "Using streaming for large file {} ({} MB)",
            file_path.display(),
            file_size / 1024 / 1024
        );
        store_content_streaming(file_path, storage_dir).await?
    } else {
        // Small file - use existing approach
        let content = fs::read(file_path)
            .await
            .map_err(|e| miette::miette!("Failed to read file {}: {e}", file_path.display()))?;

        // Store in content-addressed storage
        store_content(&storage_dir.to_path_buf(), &content).await?
    };

    // Check if we already have this exact record in database
    if file_record_exists(domain, &normalised_path, &hash).await? {
        debug!("File {domain}{normalised_path} already exists with hash {hash}, skipping");
        return Ok(None);
    }

    let current_time = util::get_current_timestamp()?;

    info!(
        "Processed file change: {} -> {} (hash: {}, size: {})",
        file_path.display(),
        normalised_path,
        hash,
        file_size
    );

    #[allow(clippy::cast_possible_wrap)]
    Ok(Some(File {
        domain: Arc::from(domain),
        path: Arc::from(normalised_path),
        content_hash: Arc::from(hash),
        size: file_size as i64,
        modified_at: current_time,
    }))
}

/// Batch update multiple file records in database
async fn update_file_records(records: &[File], config: &Config) -> Result<()> {
    for record in records {
        let pool = corrosion::get_pool().await?;
        let domain_str = record.domain.as_ref();
        let path_str = record.path.as_ref();
        let content_hash = record.content_hash.as_ref();

        let existing_hash: Option<String> = sqlx::query_scalar!(
            "SELECT content_hash FROM files WHERE domain = ? AND path = ?",
            domain_str,
            path_str
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| miette::miette!("Failed to check existing file record: {e}"))?;

        let sql = format!(
            "INSERT INTO files (domain, path, content_hash, size, modified_at)
            VALUES ('{}', '{}', '{}', {}, {})
            ON CONFLICT(domain, path) DO UPDATE SET content_hash='{}', size={}, modified_at={}",
            record.domain,
            record.path,
            record.content_hash,
            record.size,
            record.modified_at,
            record.content_hash,
            record.size,
            record.modified_at
        );

        corrosion::execute_transaction(&sql)
            .await
            .map_err(|e| miette::miette!("Failed to insert file record: {e}"))?;

        // If this was an update with a different content hash, we need to recreate hardlinks
        if let Some(old_hash) = existing_hash
            && old_hash != content_hash
        {
            info!(
                "File {} content changed from {} to {}, recreating hardlinks",
                record.path, old_hash, content_hash
            );

            // Ensure all files with the old content hash still have proper hardlinks
            if let Err(e) = recreate_hardlinks_for_content(config, &old_hash).await {
                warn!("Failed to recreate hardlinks for content {}: {e}", old_hash);
            }
        }
    }

    debug!("Batch updated {} file records", records.len());
    Ok(())
}

/// Batch delete multiple file records from database
async fn delete_file_records(records: &[(String, String)]) -> Result<()> {
    for (domain, path) in records {
        let sql = format!("DELETE FROM files WHERE domain = '{domain}' AND path = '{path}'",);

        corrosion::execute_transaction(&sql)
            .await
            .map_err(|e| miette::miette!("Failed to delete file record: {e}"))?;
    }

    debug!("Batch deleted {} file records", records.len());
    Ok(())
}

/// Check if a file record already exists in database with exact same domain, path, and content hash
async fn file_record_exists(domain: &str, path: &str, content_hash: &str) -> Result<bool> {
    let pool = corrosion::get_pool().await?;

    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM files WHERE domain = ? AND path = ? AND content_hash = ?",
        domain,
        path,
        content_hash
    )
    .fetch_one(pool)
    .await
    .map_err(|e| miette::miette!("Failed to check if file record exists: {e}"))?;

    Ok(count > 0)
}

/// Recreate hardlinks for all files sharing the same content hash
///
/// # Errors
/// Returns an error if database query or hardlink creation fails
async fn recreate_hardlinks_for_content(config: &Config, content_hash: &str) -> Result<()> {
    let pool = corrosion::get_pool().await?;

    // Find all files that should have this content hash
    let files: Vec<(String, String)> =
        sqlx::query_as("SELECT domain, path FROM files WHERE content_hash = ?")
            .bind(content_hash)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                miette::miette!(
                    "Failed to fetch files with content hash {}: {e}",
                    content_hash
                )
            })?;

    let content_path = config.fs.storage_dir.join(content_hash);
    if !content_path.exists() {
        debug!(
            "Content file {} doesn't exist, skipping hardlink recreation",
            content_hash
        );
        return Ok(());
    }

    for (domain, path) in files {
        let domain_dir = config.web.static_dir.as_std_path().join(&domain);
        let file_path = domain_dir.join(path.trim_start_matches('/'));

        // Check if file exists and is properly hardlinked
        if file_path.exists() {
            // Check if it's the same inode (proper hardlink)
            if let (Ok(content_metadata), Ok(file_metadata)) = (
                std::fs::metadata(&content_path),
                std::fs::metadata(&file_path),
            ) && content_metadata.ino() == file_metadata.ino()
            {
                continue;
            }

            // File exists but isn't properly hardlinked, recreate it
            debug!(
                "Recreating hardlink for {}{} -> {}",
                domain, path, content_hash
            );
        } else {
            // Ensure parent directory exists
            if let Some(parent) = file_path.parent()
                && let Err(e) = tokio::fs::create_dir_all(parent).await
            {
                warn!("Failed to create directory {}: {e}", parent.display());
                continue;
            }
        }

        // Create hardlink
        if let Err(e) = create_hardlink(content_path.as_std_path(), &file_path).await {
            warn!("Failed to recreate hardlink for {}{}: {e}", domain, path);
        } else {
            debug!(
                "Recreated hardlink: {} -> {}",
                file_path.display(),
                content_hash
            );
        }
    }

    Ok(())
}

/// Clean up content file if no other files reference this hash
///
/// # Errors
/// Returns an error if database query or file deletion fails
pub async fn cleanup_unreferenced_content(config: &Config, content_hash: &str) -> Result<()> {
    let pool = corrosion::get_pool().await?;

    // Check if any other files still reference this content hash
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM files WHERE content_hash = ?",
        content_hash
    )
    .fetch_one(pool)
    .await
    .map_err(|e| miette::miette!("Failed to check content references: {e}"))?;

    if count == 0 {
        // No other files reference this hash, safe to delete
        let content_path = config.fs.storage_dir.join(content_hash);
        if content_path.exists() {
            tokio::fs::remove_file(&content_path).await.map_err(|e| {
                miette::miette!("Failed to delete content file {content_path}: {e}")
            })?;
            debug!("Cleaned up unreferenced content file: {content_hash}");
        }
    } else {
        debug!("Content file {content_hash} still referenced by {count} other files",);
    }

    Ok(())
}

/// Fetch a missing file from other peers
///
/// # Errors
/// Returns an error if the file cannot be fetched or stored
pub async fn fetch_domain_file(
    config: &Config,
    content_hash: &str,
    domain: &str,
    path: &str,
) -> Result<()> {
    let storage_dir = config.fs.storage_dir.as_std_path().to_path_buf();

    // if content exists locally, recreate the domain file from it
    if storage_dir.join(content_hash).exists() {
        recreate_domain_file(config, domain, path, content_hash).await?;
        debug!("Recreated domain file {domain}{path} from existing content {content_hash}");
        return Ok(());
    }

    debug!("Fetching missing file {content_hash} for {domain}{path}");

    let peers = corrosion::get_peers().await?;
    // randomise peer order to distribute load across different nodes
    let mut peers: Vec<_> = peers.iter().collect();
    peers.shuffle(&mut rand::rng());

    for (i, peer) in peers.iter().enumerate() {
        if peer.name == config.node.name {
            continue;
        }

        let url = format!(
            "http://{}:{}/files/{content_hash}",
            peer.wg_address, peer.fs_port
        );

        match reqwest::get(&url).await {
            Ok(response) if response.status().is_success() => {
                // Check content length to decide on streaming
                let should_stream = response
                    .content_length()
                    .is_some_and(|len| len > STREAMING_THRESHOLD);

                if should_stream {
                    match stream_download_and_verify(response, &storage_dir, content_hash).await {
                        Ok(()) => {
                            recreate_domain_file(config, domain, path, content_hash).await?;
                            debug!(
                                "Successfully streamed large file {content_hash} from {}",
                                peer.name
                            );
                            return Ok(());
                        }
                        Err(e) => warn!("Failed to stream download from {}: {e}", peer.name),
                    }
                } else {
                    match response.bytes().await {
                        Ok(content) => {
                            let actual_hash = hash_content(&content);
                            if actual_hash == content_hash {
                                store_content(&storage_dir, &content).await?;
                                recreate_domain_file(config, domain, path, content_hash).await?;

                                debug!(
                                    "Successfully fetched file {content_hash} from {}",
                                    peer.name
                                );
                                return Ok(());
                            }
                            warn!(
                                "Hash mismatch for file from {}: expected {content_hash}, got {actual_hash}",
                                peer.name
                            );
                        }
                        Err(e) => warn!("Failed to read response body from {}: {e}", peer.name),
                    }
                }
            }
            Ok(response) => {
                warn!("Peer {} returned status {}", peer.name, response.status());
            }
            Err(e) => {
                warn!("Failed to fetch file from {}: {e}", peer.name);
            }
        }

        if i < peers.len() - 1 {
            let delay_ms = rand::rng().random_range(0..=2000);
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }
    }

    error!("Could not fetch file {content_hash} from any peer");
    Ok(())
}

/// Recreate file in domain directory structure using hardlink
///
/// # Errors
/// Returns an error if the file cannot be created or linked
pub async fn recreate_domain_file(
    config: &Config,
    domain: &str,
    path: &str,
    content_hash: &str,
) -> Result<()> {
    let domain_dir = config.web.static_dir.as_std_path().join(domain);
    let file_path = domain_dir.join(path.trim_start_matches('/'));
    let content_path = config.fs.storage_dir.join(content_hash);

    if let Some(parent) = file_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| miette::miette!("Failed to create directory {}: {e}", parent.display()))?;
    }

    create_hardlink(content_path.as_std_path(), &file_path).await?;

    debug!(
        "Recreated file: {} -> {}",
        file_path.display(),
        content_hash
    );
    Ok(())
}

/// Create hardlink with fallback to copy for cross-filesystem scenarios
async fn create_hardlink(source: &std::path::Path, target: &std::path::Path) -> Result<()> {
    // Check if target already exists and is the same hardlink
    if target.exists() {
        if let (Ok(source_meta), Ok(target_meta)) =
            (std::fs::metadata(source), std::fs::metadata(target))
            && source_meta.ino() == target_meta.ino()
        {
            debug!("File already hardlinked correctly: {}", target.display());
            return Ok(());
        }

        // file exists but isn't the right hardlink - use atomic rename
        let temp_filename = format!(".tmp.{}", uuid::Uuid::new_v4());

        let temp_path = source
            .parent()
            .unwrap_or(std::path::Path::new("/tmp"))
            .join(temp_filename);

        match std::fs::hard_link(source, &temp_path) {
            Ok(()) => match tokio::fs::rename(&temp_path, target).await {
                Ok(()) => {
                    debug!(
                        "Atomically replaced hardlink: {} -> {}",
                        target.display(),
                        source.display()
                    );
                    Ok(())
                }
                Err(e) => {
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    Err(miette::miette!("Failed to rename temp hardlink: {e}"))
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
                // Fallback to copy for cross-filesystem scenarios
                tokio::fs::copy(source, &temp_path).await.map_err(|e| {
                    miette::miette!("Failed to copy file for cross-filesystem fallback: {e}")
                })?;

                match tokio::fs::rename(&temp_path, target).await {
                    Ok(()) => {
                        warn!(
                            "Used copy fallback (cross-filesystem): {} -> {}",
                            target.display(),
                            source.display()
                        );
                        Ok(())
                    }
                    Err(e) => {
                        let _ = tokio::fs::remove_file(&temp_path).await;
                        Err(miette::miette!("Failed to rename temp file: {e}"))
                    }
                }
            }
            Err(e) => Err(miette::miette!(
                "Failed to create temp hardlink {}: {e}",
                temp_path.display()
            )),
        }
    } else {
        // Target doesn't exist, create directly
        match std::fs::hard_link(source, target) {
            Ok(()) => {
                debug!(
                    "Created hardlink: {} -> {}",
                    target.display(),
                    source.display()
                );
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
                // Fallback to copy for cross-filesystem scenarios
                tokio::fs::copy(source, target).await.map_err(|e| {
                    miette::miette!("Failed to copy file for cross-filesystem fallback: {e}")
                })?;
                warn!(
                    "Used copy fallback (cross-filesystem): {} -> {}",
                    target.display(),
                    source.display()
                );
                Ok(())
            }
            Err(e) => Err(miette::miette!(
                "Failed to create hardlink {}: {e}",
                target.display()
            )),
        }
    }
}

/// Delete file from domain directory structure
///
/// # Errors
/// Returns an error if the file cannot be deleted
pub async fn delete_domain_file(config: &Config, domain: &str, path: &str) -> Result<()> {
    let domain_dir = config.web.static_dir.as_std_path().join(domain);
    let file_path = domain_dir.join(path.trim_start_matches('/'));

    if file_path.exists() {
        tokio::fs::remove_file(&file_path)
            .await
            .map_err(|e| miette::miette!("Failed to delete file {}: {e}", file_path.display()))?;
        debug!("Deleted file: {}", file_path.display());
    }

    Ok(())
}

/// Store content in content-addressed storage
/// Returns the hash of the content
async fn store_content(storage_dir: &PathBuf, content: &[u8]) -> Result<String> {
    let hash = hash_content(content);
    let file_path = storage_dir.join(&hash);

    fs::create_dir_all(storage_dir)
        .await
        .map_err(|e| miette::miette!("Failed to create storage directory: {e}"))?;

    if !file_path.exists() {
        fs::write(&file_path, content)
            .await
            .map_err(|e| miette::miette!("Failed to write file {hash}: {e}"))?;
        debug!("Stored new file {hash} ({} bytes)", content.len());
    }

    Ok(hash)
}

/// Process large files with streaming to avoid memory issues
async fn store_content_streaming(
    file_path: &std::path::Path,
    storage_dir: &std::path::Path,
) -> Result<String> {
    let hash = hash_content_streaming(file_path).await?;
    let storage_path = storage_dir.join(&hash);

    // Only copy if it doesn't already exist
    if !tokio::fs::try_exists(&storage_path)
        .await
        .map_err(|e| miette::miette!("Failed to check if storage file exists: {e}"))?
    {
        // Second pass: copy file to storage
        tokio::fs::copy(file_path, &storage_path)
            .await
            .map_err(|e| miette::miette!("Failed to copy large file to storage: {e}"))?;

        debug!(
            "Stored large file {hash} ({} MB)",
            tokio::fs::metadata(file_path)
                .await
                .map_err(|e| miette::miette!("Failed to get file metadata: {e}"))?
                .len()
                / 1024
                / 1024
        );
    }

    Ok(hash)
}

/// Calculate BLAKE3 hash of file content
fn hash_content(content: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(content);
    format!("{}", hasher.finalize())
}

/// Hash large files with streaming
async fn hash_content_streaming(file_path: &std::path::Path) -> Result<String> {
    let mut file = tokio::fs::File::open(file_path)
        .await
        .map_err(|e| miette::miette!("Failed to open large file {}: {e}", file_path.display()))?;

    let mut hasher = Hasher::new();
    let mut buffer = vec![0; 65536]; // 64KB chunks on heap

    loop {
        let n = file
            .read(&mut buffer)
            .await
            .map_err(|e| miette::miette!("Failed to read from large file: {e}"))?;

        if n == 0 {
            break; // EOF
        }

        hasher.update(&buffer[..n]);
    }

    Ok(format!("{}", hasher.finalize()))
}

/// Stream download large files and verify hash
async fn stream_download_and_verify(
    response: reqwest::Response,
    storage_dir: &std::path::Path,
    expected_hash: &str,
) -> Result<()> {
    let storage_path = storage_dir.join(expected_hash);

    // don't re-download if already exists
    if tokio::fs::try_exists(&storage_path).await.unwrap_or(false) {
        return Ok(());
    }

    fs::create_dir_all(storage_dir)
        .await
        .map_err(|e| miette::miette!("Failed to create storage directory: {e}"))?;

    let mut stream = response.bytes_stream();
    let mut hasher = Hasher::new();
    let mut output_file = tokio::fs::File::create(&storage_path)
        .await
        .map_err(|e| miette::miette!("Failed to create storage file: {e}"))?;

    while let Some(chunk_result) = stream.next().await {
        let chunk =
            chunk_result.map_err(|e| miette::miette!("Failed to read download chunk: {e}"))?;

        hasher.update(&chunk);
        output_file
            .write_all(&chunk)
            .await
            .map_err(|e| miette::miette!("Failed to write download chunk: {e}"))?;
    }

    let actual_hash = format!("{}", hasher.finalize());

    if actual_hash != expected_hash {
        // clean up failed download
        let _ = tokio::fs::remove_file(&storage_path).await;
        return Err(miette::miette!(
            "Hash mismatch: expected {expected_hash}, got {actual_hash}"
        ));
    }

    debug!("Successfully streamed and verified file {expected_hash}");
    Ok(())
}
