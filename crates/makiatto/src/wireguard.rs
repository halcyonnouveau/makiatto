use std::str::FromStr;

#[cfg(not(target_os = "macos"))]
use defguard_wireguard_rs::Kernel;
#[cfg(target_os = "macos")]
use defguard_wireguard_rs::Userspace;
use defguard_wireguard_rs::{
    InterfaceConfiguration, WGApi, WireguardInterfaceApi, net::IpAddrMask,
};
use miette::{Result, miette};
use tracing::info;

use crate::config::Config;

/// Set up the `WireGuard` interface
pub fn setup_interface(config: &Config) -> Result<()> {
    let ifname = &config.network.interface;

    info!("Setting up WireGuard interface '{}'", ifname);

    #[cfg(not(target_os = "macos"))]
    let wgapi = WGApi::<Kernel>::new(ifname.clone())
        .map_err(|e| miette!("Failed to create WireGuard API: {}", e))?;
    #[cfg(target_os = "macos")]
    let wgapi = WGApi::<Userspace>::new(ifname.clone())
        .map_err(|e| miette!("Failed to create WireGuard API: {}", e))?;

    if check_interface_exists(&wgapi) {
        wgapi
            .remove_interface()
            .map_err(|e| miette!("Failed to remove existing interface: {}", e))?;
    }

    wgapi
        .create_interface()
        .map_err(|e| miette!("Failed to create WireGuard interface: {}", e))?;

    info!("Created WireGuard interface '{}'", ifname);

    let address_mask = IpAddrMask::from_str(&config.network.address)
        .map_err(|e| miette!("Invalid WireGuard address format: {}", e))?;

    let interface_config = InterfaceConfiguration {
        name: ifname.clone(),
        prvkey: config.network.private_key.clone(),
        addresses: vec![address_mask],
        port: u32::from(config.network.port),
        peers: vec![],
        mtu: None,
    };

    info!(
        "Configuring interface with address {}",
        config.network.address
    );

    wgapi
        .configure_interface(&interface_config)
        .map_err(|e| miette!("Failed to configure WireGuard interface: {}", e))?;

    let output = std::process::Command::new("sudo")
        .args(["ip", "link", "set", ifname, "up"])
        .output()
        .map_err(|e| miette!("Failed to execute ip command: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette!("Failed to bring up interface: {}", stderr));
    }

    info!("WireGuard interface '{}' configured and started", ifname);

    Ok(())
}

/// Clean up the `WireGuard` interface on shutdown
pub fn cleanup_interface(config: &Config) -> Result<()> {
    let ifname = &config.network.interface;

    info!("Cleaning up WireGuard interface '{}'", ifname);

    #[cfg(not(target_os = "macos"))]
    let wgapi = WGApi::<Kernel>::new(ifname.clone())
        .map_err(|e| miette!("Failed to create WireGuard API: {}", e))?;
    #[cfg(target_os = "macos")]
    let wgapi = WGApi::<Userspace>::new(ifname.clone())
        .map_err(|e| miette!("Failed to create WireGuard API: {}", e))?;

    if check_interface_exists(&wgapi) {
        wgapi
            .remove_interface()
            .map_err(|e| miette!("Failed to remove WireGuard interface: {}", e))?;
        info!("Removed WireGuard interface '{}'", ifname);
    } else {
        info!("WireGuard interface '{}' already removed", ifname);
    }

    Ok(())
}

/// Check if the WireGuard interface already exists
#[cfg(not(target_os = "macos"))]
fn check_interface_exists(wgapi: &WGApi<Kernel>) -> bool {
    wgapi.read_interface_data().is_ok()
}

/// Check if the `WireGuard` interface already exists
#[cfg(target_os = "macos")]
fn check_interface_exists(wgapi: &WGApi<Userspace>) -> bool {
    wgapi.read_interface_data().is_ok()
}
