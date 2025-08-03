use std::env;

use console::{Term, style};
use dialoguer::Password;
use indicatif::{ProgressBar, ProgressStyle};
use miette::{Result, miette};

/// Check if we should use simple output (for CI/tests or terminals without progress support)
fn ci_mode() -> bool {
    env::var("MAKIATTO_CI_MODE").is_ok() || env::var("CI").is_ok()
}

/// Print a status update
pub fn status(msg: &str) {
    println!("{} {}", style("==>").green().bold(), msg);
}

/// Print an info message
pub fn info(msg: &str) {
    println!("{} {}", style("::").blue().bold(), style(msg).dim());
}

/// Print a warning message
pub fn warn(msg: &str) {
    println!("{} {}", style("!!").yellow().bold(), style(msg).yellow());
}

/// Print plain text without any prefix
pub fn text(msg: &str) {
    println!("{msg}");
}

/// Print a command to run (dimmed)
pub fn command(cmd: &str) {
    println!("  {}", style(cmd).dim());
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

/// Progress bar wrapper that can be either real or mock
pub enum Progress {
    Real(ProgressBar),
    Mock,
}

impl Progress {
    pub fn finish_with_message(&self, msg: impl Into<String>) {
        match self {
            Self::Real(pb) => pb.finish_with_message(msg.into()),
            Self::Mock => println!("{}", msg.into()),
        }
    }

    pub fn finish(&self) {
        match self {
            Self::Real(pb) => pb.finish(),
            Self::Mock => {}
        }
    }

    pub fn set_message(&self, msg: impl Into<String>) {
        match self {
            Self::Real(pb) => pb.set_message(msg.into()),
            Self::Mock => {}
        }
    }

    pub fn inc(&self, delta: u64) {
        match self {
            Self::Real(pb) => pb.inc(delta),
            Self::Mock => {}
        }
    }

    pub fn set_position(&self, pos: u64) {
        match self {
            Self::Real(pb) => pb.set_position(pos),
            Self::Mock => {}
        }
    }

    pub fn enable_steady_tick(&self, duration: std::time::Duration) {
        match self {
            Self::Real(pb) => pb.enable_steady_tick(duration),
            Self::Mock => {}
        }
    }
}

/// Create a spinner progress indicator
///
/// Returns a mock spinner if `MAKIATTO_CI_MODE` or `CI` env var is set
///
/// # Panics
/// Panics if the progress spinner template is malformed
#[must_use]
pub fn spinner(msg: &str) -> Progress {
    if ci_mode() {
        println!("{msg}");
        Progress::Mock
    } else {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .expect("Spinner template is invalid"),
        );
        spinner.set_message(msg.to_string());
        spinner.enable_steady_tick(std::time::Duration::from_millis(100));
        Progress::Real(spinner)
    }
}

/// Create a progress bar
///
/// Returns a mock progress bar if `MAKIATTO_CI_MODE` or `CI` env var is set
///
/// # Panics
/// Panics if the progress bar template is malformed
#[must_use]
pub fn progress_bar(total_bytes: u64, msg: &str) -> Progress {
    if ci_mode() {
        println!("{msg}");
        Progress::Mock
    } else {
        let pb = ProgressBar::new(total_bytes);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} {msg} [{wide_bar:.cyan/blue}] {bytes}/{total_bytes}")
                .expect("Progress bar template is invalid")
                .progress_chars("#>-"),
        );
        pb.set_message(msg.to_string());
        Progress::Real(pb)
    }
}
