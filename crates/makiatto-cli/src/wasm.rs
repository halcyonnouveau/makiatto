use std::path::PathBuf;

use argh::FromArgs;
use miette::{Context, IntoDiagnostic, Result, miette};

use crate::ui;

/// manage WASM development
#[derive(FromArgs)]
#[argh(subcommand, name = "wasm")]
pub struct WasmCommand {
    #[argh(subcommand)]
    pub action: WasmAction,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum WasmAction {
    Fetch(FetchWit),
}

/// download WIT files for WASM development
#[derive(FromArgs)]
#[argh(subcommand, name = "fetch")]
pub struct FetchWit {
    /// output directory (default: ./wit)
    #[argh(option, short = 'o')]
    pub output: Option<PathBuf>,

    /// version/tag to download (default: current CLI version)
    #[argh(option, short = 'v')]
    pub version: Option<String>,
}

pub async fn fetch_wit(fetch: &FetchWit) -> Result<()> {
    ui::status("Fetching WIT interface files");

    let output = fetch
        .output
        .as_ref()
        .map_or_else(|| PathBuf::from("wit"), PathBuf::clone);

    if output.exists() {
        return Err(miette!(
            "Directory '{}' already exists. Please remove it or choose a different output directory.",
            output.display()
        ));
    }

    let version = fetch
        .version
        .as_deref()
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    ui::action(&format!("Fetching WIT files for version {version}"));

    let download_url = format!(
        "https://github.com/halcyonnouveau/makiatto/releases/download/v{version}/makiatto-wit.tar.gz"
    );

    ui::action("Downloading makiatto-wit.tar.gz");
    let response = reqwest::get(&download_url)
        .await
        .into_diagnostic()
        .context("Failed to download WIT files")?;

    if !response.status().is_success() {
        return Err(miette!("Failed to download: HTTP {}", response.status()));
    }

    let tarball_bytes = response
        .bytes()
        .await
        .into_diagnostic()
        .context("Failed to read response body")?;

    ui::action("Extracting WIT files");
    let tar = flate2::read::GzDecoder::new(&tarball_bytes[..]);
    let mut archive = tar::Archive::new(tar);

    if let Some(parent) = output.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .context("Failed to create parent directory")?;
    }

    let temp_dir = std::env::temp_dir().join(format!("makiatto-wit-{}", uuid::Uuid::new_v4()));
    archive
        .unpack(&temp_dir)
        .into_diagnostic()
        .context("Failed to extract tarball")?;

    let extracted_wit = temp_dir.join("makiatto-wit").join("wit");
    std::fs::rename(&extracted_wit, &output)
        .into_diagnostic()
        .with_context(|| format!("Failed to move WIT files to {}", output.display()))?;

    let _ = std::fs::remove_dir_all(temp_dir);

    ui::status(&format!("WIT files installed to {}", output.display()));
    ui::info("You can now build WASM components using these interface definitions");
    ui::info("Example structure:");
    ui::info("  wit/http/http-handler.wit    - For HTTP functions");
    ui::info("  wit/transform/transform.wit  - For file transforms");

    Ok(())
}
