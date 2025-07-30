use std::sync::Arc;

use miette::Result;
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    corrosion,
    fs::watcher::{fetch_domain_file, parse_domain_and_path},
};

/// Run filesystem reconciliation once (for startup)
///
/// # Errors
/// Returns an error if reconciliation fails
pub async fn run_once(config: Arc<Config>) -> Result<()> {
    info!("Running startup filesystem reconciliation");
    reconcile_filesystem_with_database(&config).await?;
    info!("Startup reconciliation completed");
    Ok(())
}

/// Start periodic filesystem reconciliation
///
/// # Errors
/// Returns an error if reconciliation fails
pub async fn start(config: Arc<Config>, mut shutdown_rx: mpsc::Receiver<()>) -> Result<()> {
    let interval_hours = config.fs.reconcile_interval;
    info!(
        "Starting filesystem reconciliation (every {} hours)",
        interval_hours
    );

    let mut interval =
        tokio::time::interval(tokio::time::Duration::from_secs(interval_hours * 3600));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Filesystem reconciliation received shutdown signal");
                break;
            }
            _ = interval.tick() => {
                info!("Starting filesystem reconciliation check");
                if let Err(e) = reconcile_filesystem_with_database(&config).await {
                    error!("Filesystem reconciliation failed: {e}");
                } else {
                    info!("Filesystem reconciliation completed successfully");
                }
            }
        }
    }

    Ok(())
}

/// Reconcile filesystem state with database
async fn reconcile_filesystem_with_database(config: &Config) -> Result<()> {
    let mut issues_found = 0;

    // 1. check all DB records have corresponding files
    issues_found += reconcile_missing_files(config).await?;

    // 2. check all domain files have DB records - remove those that don't
    issues_found += reconcile_orphaned_files(config).await?;

    // 3. clean up unreferenced content files
    issues_found += cleanup_orphaned_content(config).await?;

    if issues_found > 0 {
        warn!("Reconciliation found and fixed {issues_found} issues");
    } else {
        debug!("Reconciliation found no issues");
    }

    Ok(())
}

/// Check for missing files that exist in database but not on filesystem
async fn reconcile_missing_files(config: &Config) -> Result<usize> {
    let pool = corrosion::get_pool().await?;

    let records: Vec<(String, String, String)> =
        sqlx::query_as("SELECT domain, path, content_hash FROM files")
            .fetch_all(pool)
            .await
            .map_err(|e| miette::miette!("Failed to fetch file records: {e}"))?;

    let missing_files: Vec<_> = records
        .into_iter()
        .filter(|(domain, path, _)| {
            let domain_dir = config.web.static_dir.as_std_path().join(domain);
            let file_path = domain_dir.join(path.trim_start_matches('/'));
            !file_path.exists()
        })
        .collect();

    if missing_files.is_empty() {
        return Ok(0);
    }

    info!(
        "Found {} missing files, fetching in parallel...",
        missing_files.len()
    );

    let semaphore = Arc::new(Semaphore::new(10));

    let fetch_tasks: Vec<_> = missing_files
        .iter()
        .map(|(domain, path, content_hash)| {
            let config = config.clone();
            let semaphore = semaphore.clone();
            let domain = domain.clone();
            let path = path.clone();
            let content_hash = content_hash.clone();

            async move {
                let domain_dir = config.web.static_dir.as_std_path().join(&domain);
                let file_path = domain_dir.join(path.trim_start_matches('/'));

                warn!(
                    "Missing file {}, attempting to recreate",
                    file_path.display()
                );

                let _permit = semaphore.acquire().await.expect("Semaphore closed");

                match fetch_domain_file(&config, &content_hash, &domain, &path).await {
                    Ok(()) => {
                        info!(
                            "Successfully recreated missing file {}",
                            file_path.display()
                        );
                        1usize
                    }
                    Err(e) => {
                        error!("Error recreating missing file {}: {e}", file_path.display());
                        0usize
                    }
                }
            }
        })
        .collect();

    let results = futures::future::join_all(fetch_tasks).await;
    let fixed_count: usize = results.into_iter().sum();

    Ok(fixed_count)
}

/// Check for orphaned files that exist on filesystem but not in database
async fn reconcile_orphaned_files(config: &Config) -> Result<usize> {
    let static_dir = config.web.static_dir.as_std_path();
    let mut fixed_count = 0;

    if let Ok(entries) = tokio::fs::read_dir(static_dir).await {
        let mut entries = entries;
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                let domain = entry.file_name().to_string_lossy().to_string();
                fixed_count += scan_domain_for_orphans(&domain, static_dir).await?;
            }
        }
    }

    Ok(fixed_count)
}

/// Scan a specific domain for orphaned files
async fn scan_domain_for_orphans(domain: &str, static_dir: &std::path::Path) -> Result<usize> {
    let domain_dir = static_dir.join(domain);
    let mut fixed_count = 0;

    if let Ok(files) = scan_directory_recursive(&domain_dir).await {
        for file_path in files {
            if let Ok(Some((file_domain, normalised_path))) =
                extract_file_info(&file_path, static_dir)
            {
                // Check if this file has a database record
                if !has_file_record(file_domain, &normalised_path).await? {
                    warn!(
                        "Orphaned file found: {} (not in database, removing)",
                        file_path.display()
                    );

                    if let Err(e) = tokio::fs::remove_file(&file_path).await {
                        error!(
                            "Failed to remove orphaned file {}: {e}",
                            file_path.display()
                        );
                    } else {
                        info!("Removed orphaned file {}", file_path.display());
                        fixed_count += 1;
                    }
                }
            }
        }
    }

    Ok(fixed_count)
}

/// Recursively scan directory for files
async fn scan_directory_recursive(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();

    if let Ok(mut entries) = tokio::fs::read_dir(dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if entry
                .file_type()
                .await
                .map(|t| t.is_file())
                .unwrap_or(false)
            {
                files.push(path);
            } else if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false)
                && let Ok(mut subfiles) = Box::pin(scan_directory_recursive(&path)).await
            {
                files.append(&mut subfiles);
            }
        }
    }

    Ok(files)
}

/// Check if a file record exists in database (any content hash)
async fn has_file_record(domain: &str, path: &str) -> Result<bool> {
    let pool = corrosion::get_pool().await?;

    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM files WHERE domain = ? AND path = ?",
        domain,
        path
    )
    .fetch_one(pool)
    .await
    .map_err(|e| miette::miette!("Failed to check file record existence: {e}"))?;

    Ok(count > 0)
}

/// Clean up content files that are no longer referenced by any file records
async fn cleanup_orphaned_content(config: &Config) -> Result<usize> {
    let storage_dir = config.fs.storage_dir.as_std_path();
    let mut cleaned_count = 0;

    if let Ok(mut entries) = tokio::fs::read_dir(storage_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry
                .file_type()
                .await
                .map(|t| t.is_file())
                .unwrap_or(false)
            {
                let filename = entry.file_name().to_string_lossy().to_string();

                if !is_content_referenced(&filename).await? {
                    warn!("Orphaned content file: {filename}");
                    if let Err(e) = tokio::fs::remove_file(entry.path()).await {
                        error!("Failed to remove orphaned content {filename}: {e}");
                    } else {
                        info!("Cleaned up orphaned content: {filename}");
                        cleaned_count += 1;
                    }
                }
            }
        }
    }

    Ok(cleaned_count)
}

/// Check if content hash is referenced by any file record
async fn is_content_referenced(content_hash: &str) -> Result<bool> {
    let pool = corrosion::get_pool().await?;

    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM files WHERE content_hash = ?",
        content_hash
    )
    .fetch_one(pool)
    .await
    .map_err(|e| miette::miette!("Failed to check content references: {e}"))?;

    Ok(count > 0)
}

/// Extract domain and normalised path from a file path
fn extract_file_info<'a>(
    file_path: &'a std::path::Path,
    static_dir: &std::path::Path,
) -> Result<Option<(&'a str, String)>> {
    if !file_path.is_file() && !file_path.is_symlink() {
        return Ok(None);
    }

    let (domain, path) = parse_domain_and_path(file_path, static_dir)?;
    Ok(Some((domain, path)))
}
