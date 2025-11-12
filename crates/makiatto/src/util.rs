use std::time::SystemTime;

use miette::Result;

/// Get current timestamp as Unix seconds
///
/// # Errors
/// Returns an error if system time cannot be retrieved
pub fn get_current_timestamp() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| miette::miette!("Failed to get current time: {e}"))?
        .as_secs() as i64)
}
