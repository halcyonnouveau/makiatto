mod functions;
mod transforms;

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use dashmap::DashMap;
pub(crate) use functions::wasm_function_middleware;
use miette::{Context, IntoDiagnostic, Result, miette};
pub(crate) use transforms::wasm_transform_middleware;
use wasmtime::component::{Component, ResourceTable};
use wasmtime::{Config, Engine};
use wasmtime_wasi::sockets::SocketAddrUse;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::config::WasmConfig;

pub mod http_bindings {
    wasmtime::component::bindgen!({
        world: "http",
        path: "wit/http.wit",
        imports: {
            default: async,
        },
        exports: {
            default: async,
        },
    });
}

pub mod transformer_bindings {
    wasmtime::component::bindgen!({
        world: "transform",
        path: "wit/transform.wit",
        imports: {
            default: async,
        },
        exports: {
            default: async,
        },
    });
}

/// Node context information
#[derive(Debug, Clone)]
pub struct NodeContext {
    pub name: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// Global WASM engine shared across all requests
pub struct WasmRuntime {
    engine: Engine,
    components: DashMap<String, Component>,
    config: WasmConfig,
    pub node_context: NodeContext,
}

impl WasmRuntime {
    /// Create a new WASM runtime with the given configuration and node context
    ///
    /// # Errors
    /// Returns an error if the WASM engine fails to initialize
    pub fn new(config: WasmConfig, node_context: NodeContext) -> Result<Self> {
        let mut engine_config = Config::new();
        engine_config.async_support(true);
        engine_config.wasm_component_model(true);
        engine_config.max_wasm_stack(1024 * 1024); // 1MB stack

        let engine = Engine::new(&engine_config)
            .map_err(|e| miette!("Failed to create WASM engine: {e}"))?;

        Ok(Self {
            engine,
            components: DashMap::new(),
            config,
            node_context,
        })
    }

    /// Get the effective memory limit for a function/transform
    /// Returns the requested limit, capped at the global max
    #[must_use]
    pub fn effective_memory_limit(&self, requested_mb: Option<u64>) -> u64 {
        let limit = requested_mb.unwrap_or(self.config.default_max_memory_mb);
        limit.min(self.config.max_memory_mb)
    }

    /// Get the effective timeout for a function/transform
    /// Returns the requested timeout, capped at the global max
    #[must_use]
    pub fn effective_timeout(&self, requested_ms: Option<u64>) -> u64 {
        let timeout = requested_ms.unwrap_or(self.config.default_timeout_ms);
        timeout.min(self.config.max_timeout_ms)
    }

    /// Load or get cached component
    ///
    /// # Errors
    /// Returns an error if the component file cannot be read or compiled
    pub async fn get_component(&self, path: &Path) -> Result<Component> {
        let path_str = path.to_string_lossy().to_string();

        if self.config.cache_modules
            && let Some(component) = self.components.get(&path_str)
        {
            return Ok(component.clone());
        }

        let component_bytes = tokio::fs::read(path)
            .await
            .into_diagnostic()
            .with_context(|| format!("Failed to read WASM component: {}", path.display()))?;

        let component = Component::new(&self.engine, &component_bytes)
            .map_err(|e| miette!("Failed to compile WASM component {}: {e}", path.display()))?;

        if self.config.cache_modules {
            self.components.insert(path_str, component.clone());
        }

        Ok(component)
    }
}

/// Store data for WASI p2 Component Model
pub struct StoreData {
    pub wasi: WasiCtx,
    pub table: ResourceTable,
    pub limits: wasmtime::StoreLimits,
}

impl WasiView for StoreData {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// Check if an IP address is private or reserved (for SSRF protection)
fn is_private_or_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_documentation()
                || ipv4.is_unspecified()
                // AWS/cloud metadata endpoints
                || ipv4.octets() == [169, 254, 169, 254]
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified() || ipv6.is_multicast(),
    }
}

/// Create store data with WASI context, resource table, and limits
pub(crate) fn create_store_data(
    env: std::collections::HashMap<String, String>,
    memory_bytes: usize,
    domain_dir: Option<&Path>,
) -> StoreData {
    let mut builder = WasiCtxBuilder::new();

    for (key, value) in env {
        builder.env(&key, &value);
    }

    // Configure network access with SSRF protection
    builder.socket_addr_check(|addr: SocketAddr, _use: SocketAddrUse| {
        Box::pin(async move {
            let allowed = !is_private_or_reserved_ip(addr.ip());
            if !allowed {
                tracing::warn!(
                    "WASM: Blocked connection attempt to private/reserved IP: {}",
                    addr.ip()
                );
            }
            allowed
        })
    });

    // Preopen domain directory for file system access (sandboxed to domain, read-only)
    if let Some(dir) = domain_dir {
        let dir_perms = wasmtime_wasi::DirPerms::READ;
        let file_perms = wasmtime_wasi::FilePerms::READ;
        let _ = builder.preopened_dir(dir, "/", dir_perms, file_perms);
    }

    let wasi = builder.build();
    let table = ResourceTable::new();
    let limits = wasmtime::StoreLimitsBuilder::new()
        .memory_size(memory_bytes)
        .build();

    StoreData {
        wasi,
        table,
        limits,
    }
}
