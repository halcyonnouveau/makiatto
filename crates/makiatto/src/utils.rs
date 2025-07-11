/// Check if running in a container environment
#[must_use]
pub fn is_container() -> bool {
    // Check common container indicators
    std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
}
