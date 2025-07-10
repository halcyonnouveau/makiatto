#![allow(dead_code)]
use console::{Term, style};
use dialoguer::Password;
#[cfg(not(feature = "integration-tests"))]
use indicatif::{ProgressBar, ProgressStyle};
use miette::{Result, miette};

/// Print a status update
pub fn status(msg: &str) {
    println!("{} {}", style("==>").green().bold(), msg);
}

/// Print an info message
pub fn info(msg: &str) {
    println!("{} {}", style("::").blue().bold(), style(msg).dim());
}

/// Print a key-value field
pub fn field(key: &str, value: &str) {
    println!("  {}: {}", style(key).dim(), value);
}

/// Print a header
pub fn header(title: &str) {
    println!("{} {}", style("::").blue().bold(), style(title).bold());
}

/// Print an action
pub fn action(msg: &str) {
    println!("  {} {}", style("->").blue(), msg);
}

/// Prompt user for password input
///
/// # Errors
/// Returns an error if input cannot be read
pub fn password(prompt: &str) -> Result<String> {
    Password::new()
        .with_prompt(prompt)
        .interact()
        .map_err(|e| miette!("Failed to read input: {}", e))
}

/// Print a separator line that fits terminal width
pub fn separator() {
    let term = Term::stdout();
    let width = term.size().1 as usize;
    let line = "─".repeat(width.min(80));
    println!("{}", style(line).dim());
}

/// Create a spinner progress indicator
///
/// # Panics
/// Panics if the progress bar template is invalid
#[cfg(not(feature = "integration-tests"))]
#[must_use]
pub fn spinner(msg: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    spinner.set_message(msg.to_string());
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));
    spinner
}

/// Create a progress bar
///
/// # Panics
/// Panics if the progress bar template is invalid
#[cfg(not(feature = "integration-tests"))]
#[must_use]
pub fn progress_bar(total_bytes: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} {msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(msg.to_string());
    pb
}

/// Create a spinner progress indicator
///
/// # Panics
/// Panics if the progress bar template is invalid
#[cfg(feature = "integration-tests")]
#[must_use]
pub fn spinner(msg: &str) -> MockProgressBar {
    println!("{msg}");
    MockProgressBar
}

/// Create a progress bar
///
/// # Panics
/// Panics if the progress bar template is invalid
#[cfg(feature = "integration-tests")]
#[must_use]
pub fn progress_bar(_total_bytes: u64, msg: &str) -> MockProgressBar {
    println!("{msg}");
    MockProgressBar
}

#[cfg(feature = "integration-tests")]
#[derive(Clone, Copy)]
pub struct MockProgressBar;

#[cfg(feature = "integration-tests")]
impl MockProgressBar {
    #[allow(clippy::needless_pass_by_value)]
    pub fn finish_with_message(&self, msg: String) {
        println!("{msg}");
    }
    pub fn finish(&self) {}
    pub fn set_message(&self, _msg: String) {}
    pub fn inc(&self, _delta: u64) {}
    pub fn set_position(&self, _pos: u64) {}
    pub fn enable_steady_tick(&self, _duration: std::time::Duration) {}
}
