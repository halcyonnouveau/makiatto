use std::{path::Path, sync::Arc, time::SystemTime};

use blake3::Hasher;
use imageflow_core::clients::stateless::{BuildInput, BuildRequest, LibClient};
use imageflow_types::{Constraint, ConstraintMode, EncoderPreset, Framewise, Node, ResampleHints};
use moka::future::Cache;
use serde::Deserialize;
use tracing::debug;

use crate::config::ImageConfig;

#[derive(Clone)]
pub struct ImageProcessor {
    config: Arc<ImageConfig>,
    cache: Cache<String, Arc<Vec<u8>>>,
}

#[derive(Debug, Deserialize)]
pub struct ImageParams {
    /// Width in pixels
    #[serde(rename = "w")]
    width: Option<u32>,

    /// Height in pixels
    #[serde(rename = "h")]
    height: Option<u32>,

    /// Fit mode: max, pad, crop, stretch
    #[serde(rename = "fit")]
    fit: Option<String>,

    /// Output format: webp, avif, jpg, jpeg, png
    #[serde(rename = "fmt")]
    format: Option<String>,

    /// Quality (1-100)
    #[serde(rename = "q")]
    quality: Option<u32>,
}

impl ImageProcessor {
    #[must_use]
    pub fn new(config: ImageConfig) -> Self {
        let cache_size_bytes = config.cache_size_mb * 1024 * 1024;

        let cache = Cache::builder()
            .max_capacity(cache_size_bytes as u64)
            .weigher(|_key: &String, value: &Arc<Vec<u8>>| -> u32 {
                value.len().try_into().unwrap_or(u32::MAX)
            })
            .build();

        Self {
            config: Arc::new(config),
            cache,
        }
    }

    /// Check if the request has image transformation parameters
    #[must_use]
    pub fn has_transform_params(query: &str) -> bool {
        query.contains("w=")
            || query.contains("h=")
            || query.contains("fmt=")
            || query.contains("q=")
            || query.contains("fit=")
    }

    /// Process an image with the given parameters
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Parameters are invalid (dimensions out of range, unsupported format, etc.)
    /// - File I/O fails
    /// - Image processing fails
    pub async fn process_image(
        &self,
        file_path: &Path,
        params: ImageParams,
    ) -> Result<(Vec<u8>, &'static str), ProcessError> {
        self.validate_params(&params)?;
        let cache_key = self.generate_cache_key(file_path, &params).await?;

        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Cache hit for image: {:?}", file_path);
            let content_type = Self::get_content_type(&params);
            return Ok(((*cached).clone(), content_type));
        }

        debug!("Cache miss for image: {:?}", file_path);

        let image_data = tokio::fs::read(file_path)
            .await
            .map_err(|e| ProcessError::IoError(e.to_string()))?;

        let processed = Self::transform_image(&image_data, &params)?;
        let content_type = Self::get_content_type(&params);

        self.cache
            .insert(cache_key, Arc::new(processed.clone()))
            .await;

        Ok((processed, content_type))
    }

    fn validate_params(&self, params: &ImageParams) -> Result<(), ProcessError> {
        if let Some(w) = params.width
            && (w == 0 || w > self.config.max_width)
        {
            return Err(ProcessError::InvalidParams(format!(
                "Width must be between 1 and {}",
                self.config.max_width
            )));
        }

        if let Some(h) = params.height
            && (h == 0 || h > self.config.max_height)
        {
            return Err(ProcessError::InvalidParams(format!(
                "Height must be between 1 and {}",
                self.config.max_height
            )));
        }

        if let Some(ref fmt) = params.format
            && !self.config.allowed_formats.contains(&fmt.to_lowercase())
        {
            return Err(ProcessError::InvalidParams(format!(
                "Format '{}' not allowed. Allowed formats: {:?}",
                fmt, self.config.allowed_formats
            )));
        }

        if let Some(q) = params.quality
            && (q == 0 || q > 100)
        {
            return Err(ProcessError::InvalidParams(
                "Quality must be between 1 and 100".to_string(),
            ));
        }

        Ok(())
    }

    async fn generate_cache_key(
        &self,
        file_path: &Path,
        params: &ImageParams,
    ) -> Result<String, ProcessError> {
        // Include file modification time in cache key for cache invalidation
        let metadata = tokio::fs::metadata(file_path)
            .await
            .map_err(|e| ProcessError::IoError(e.to_string()))?;

        let mtime = metadata
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut hasher = Hasher::new();
        hasher.update(file_path.to_string_lossy().as_bytes());
        hasher.update(&mtime.to_le_bytes());

        if let Some(w) = params.width {
            hasher.update(b"w:");
            hasher.update(&w.to_le_bytes());
        }
        if let Some(h) = params.height {
            hasher.update(b"h:");
            hasher.update(&h.to_le_bytes());
        }
        if let Some(ref fit) = params.fit {
            hasher.update(b"fit:");
            hasher.update(fit.as_bytes());
        }
        if let Some(ref fmt) = params.format {
            hasher.update(b"fmt:");
            hasher.update(fmt.as_bytes());
        }
        if let Some(q) = params.quality {
            hasher.update(b"q:");
            hasher.update(&q.to_le_bytes());
        }

        Ok(hasher.finalize().to_hex().to_string())
    }

    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    fn transform_image(image_data: &[u8], params: &ImageParams) -> Result<Vec<u8>, ProcessError> {
        let mut steps = Vec::new();

        steps.push(Node::Decode {
            io_id: 0,
            commands: None,
        });

        if params.width.is_some() || params.height.is_some() {
            let fit_mode = params.fit.as_deref().unwrap_or("max");

            let mode = match fit_mode {
                "max" => ConstraintMode::Within,
                "pad" => ConstraintMode::WithinPad,
                "crop" => ConstraintMode::FitCrop,
                "stretch" => ConstraintMode::Distort,
                _ => {
                    return Err(ProcessError::InvalidParams(format!(
                        "Invalid fit mode: {fit_mode}. Valid options: max, pad, crop, stretch"
                    )));
                }
            };

            let constraint = Constraint {
                mode,
                w: params.width,
                h: params.height,
                hints: Some(ResampleHints::default()),
                gravity: None,
                canvas_color: None,
            };

            steps.push(Node::Constrain(constraint));
        }

        let output_format = params.format.as_deref().unwrap_or("jpg");
        let quality = params.quality.unwrap_or(85);

        let preset = match output_format {
            "webp" => EncoderPreset::WebPLossy {
                quality: quality as f32,
            },
            "png" => EncoderPreset::Libpng {
                depth: None,
                matte: None,
                zlib_compression: None,
            },
            "jpg" | "jpeg" => EncoderPreset::Mozjpeg {
                quality: Some(quality as u8),
                progressive: None,
                matte: None,
            },
            _ => {
                return Err(ProcessError::InvalidParams(format!(
                    "Unsupported output format: {output_format}"
                )));
            }
        };

        steps.push(Node::Encode { io_id: 1, preset });

        let request = BuildRequest {
            inputs: vec![BuildInput {
                io_id: 0,
                bytes: image_data,
            }],
            framewise: Framewise::Steps(steps),
            export_graphs_to: None,
        };

        let mut client = LibClient::new();
        let result = client
            .build(request)
            .map_err(|e| ProcessError::ImageflowError(format!("Failed to process image: {e:?}")))?;

        if let Some(output) = result.outputs.first() {
            Ok(output.bytes.clone())
        } else {
            Err(ProcessError::ImageflowError(
                "No output in result".to_string(),
            ))
        }
    }

    fn get_content_type(params: &ImageParams) -> &'static str {
        match params.format.as_deref().unwrap_or("jpg") {
            "webp" => "image/webp",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            _ => "application/octet-stream",
        }
    }
}

#[derive(Debug)]
pub enum ProcessError {
    InvalidParams(String),
    IoError(String),
    ImageflowError(String),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParams(msg) => write!(f, "Invalid parameters: {msg}"),
            Self::IoError(msg) => write!(f, "IO error: {msg}"),
            Self::ImageflowError(msg) => write!(f, "Image processing error: {msg}"),
        }
    }
}

impl std::error::Error for ProcessError {}
