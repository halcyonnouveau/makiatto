use std::path::{Component, Path, PathBuf};
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

/// Extract the host portion of a `Host`-header value, dropping any port and
/// IPv6 brackets. Never panics on malformed input.
#[must_use]
pub fn host_without_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        // bracketed IPv6: `[::1]` or `[::1]:443`
        return rest.split(']').next().unwrap_or(rest);
    }

    match host.rsplit_once(':') {
        // a single colon means host:port; a bare IPv6 has multiple colons and
        // is returned unchanged
        Some((h, _)) if !h.contains(':') => h,
        _ => host,
    }
}

/// Validate that `domain` is a single, safe path segment.
#[must_use]
pub fn is_safe_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain != "."
        && domain != ".."
        && !domain.contains('/')
        && !domain.contains('\\')
        && !domain.contains('\0')
}

/// Join a peer- or client-controlled `domain` and `path` under `base`, rejecting
/// any input that would escape the `base/domain` directory.
///
/// `path` is treated as relative (a leading `/` is stripped). Any `..`
/// component, absolute root, NUL byte, or unsafe `domain` segment is rejected so
/// the result is always contained within `base/domain`.
///
/// # Errors
/// Returns an error if the inputs would traverse outside `base/domain`.
pub fn contained_path(base: &Path, domain: &str, path: &str) -> Result<PathBuf> {
    if !is_safe_domain(domain) {
        return Err(miette::miette!("Invalid domain component: {domain:?}"));
    }

    if path.contains('\0') {
        return Err(miette::miette!("Path contains NUL byte"));
    }

    let domain_root = base.join(domain);
    let mut result = domain_root.clone();

    for component in Path::new(path.trim_start_matches('/')).components() {
        match component {
            Component::Normal(part) => result.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(miette::miette!("Path traversal rejected in {path:?}"));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(miette::miette!("Absolute path rejected in {path:?}"));
            }
        }
    }

    // belt-and-braces: the lexical result must remain under the domain root
    if !result.starts_with(&domain_root) {
        return Err(miette::miette!("Resolved path escapes domain root"));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contained_path_allows_normal_paths() {
        let base = Path::new("/srv/sites");
        let p = contained_path(base, "example.com", "/css/app.css").unwrap();
        assert_eq!(p, Path::new("/srv/sites/example.com/css/app.css"));
    }

    #[test]
    fn contained_path_rejects_traversal() {
        let base = Path::new("/srv/sites");
        assert!(contained_path(base, "example.com", "../../etc/passwd").is_err());
        assert!(contained_path(base, "../../etc", "passwd").is_err());
        assert!(contained_path(base, "example.com", "/a/../../b").is_err());
    }

    #[test]
    fn contained_path_rejects_bad_domain() {
        let base = Path::new("/srv/sites");
        assert!(contained_path(base, "..", "index.html").is_err());
        assert!(contained_path(base, "a/b", "index.html").is_err());
        assert!(contained_path(base, "", "index.html").is_err());
    }
}
