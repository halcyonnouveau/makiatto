use std::{collections::HashSet, path::PathBuf, time::SystemTime};

use argh::FromArgs;
use miette::{Result, miette};
use uuid::Uuid;

use crate::{
    config::{Config, DnsRecord, Domain, Machine, Profile},
    machine::corrosion,
    ssh::SshSession,
    ui,
};

/// sync the project to the cdn
#[derive(FromArgs)]
#[argh(subcommand, name = "sync")]
pub struct SyncCommand {
    /// path to SSH private key (optional)
    #[argh(option, long = "ssh-priv-key")]
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DnsRecordKey {
    pub name: String,
    pub record_type: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DnsRecordData {
    pub value: String,
    pub ttl: u32,
    pub priority: i32,
    pub geo_enabled: bool,
}

/// Sync project files and DNS configuration to the CDN
///
/// # Errors
/// Returns an error if sync operations fail
pub fn sync_project(command: &SyncCommand, profile: &Profile, config: &Config) -> Result<()> {
    if profile.machines.is_empty() {
        return Err(miette!(
            "No machines configured. Use `machine init` to add one first"
        ));
    }

    if config.domains.is_empty() {
        return Err(miette!("No domains configured in makiatto.toml"));
    }

    // validate all wasm file paths
    for domain in config.domains.iter() {
        for function in domain.functions.iter() {
            let path_str = function.path.display().to_string();
            if !std::path::Path::new(&path_str)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("wasm"))
            {
                return Err(miette::miette!(
                    "Domain '{}': Function path '{}' must end with .wasm extension",
                    domain.name,
                    path_str
                ));
            }
        }

        for transform in domain.transforms.iter() {
            let path_str = transform.path.display().to_string();
            if !std::path::Path::new(&path_str)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("wasm"))
            {
                return Err(miette::miette!(
                    "Domain '{}': Transform path '{}' must end with .wasm extension",
                    domain.name,
                    path_str
                ));
            }
        }
    }

    let sync_machine = profile
        .machines
        .iter()
        .find(|m| m.is_nameserver && m.sync_target)
        .unwrap_or(&profile.machines[0]);

    ui::header(&format!("Syncing to machine '{}'", sync_machine.name));
    ui::status(&format!("Connecting to {}", sync_machine.ssh_target));

    let ssh = SshSession::new(
        &sync_machine.ssh_target,
        sync_machine.port,
        command.key_path.as_ref(),
    )?;

    check_remote_version(&ssh);

    for domain in config.domains.iter() {
        ui::header(&format!("Processing domain: {}", domain.name));
        sync_domain_files(&ssh, domain, command.key_path.as_ref(), sync_machine)?;
        sync_domain_records(&ssh, domain, &profile.machines)?;
        sync_domain_functions(&ssh, domain)?;
        sync_domain_transforms(&ssh, domain)?;
    }

    ui::status("Sync completed successfully");
    Ok(())
}

fn check_remote_version(ssh: &SshSession) {
    let cli_version = env!("CARGO_PKG_VERSION");

    match ssh.exec("makiatto --version 2>/dev/null") {
        Ok(output) => {
            let remote_version = output.trim();
            if !remote_version.is_empty() && remote_version != cli_version {
                ui::warn(&format!(
                    "maki is v{cli_version} but makiatto daemon is v{remote_version}. Consider running 'maki machine upgrade' to update the daemon binary",
                ));
            }
        }
        Err(_) => {
            ui::warn("Could not determine remote makiatto version");
        }
    }
}

fn sync_domain_files(
    ssh: &SshSession,
    domain: &Domain,
    key_path: Option<&PathBuf>,
    machine: &Machine,
) -> Result<()> {
    ui::status("Syncing files...");

    let target_dir = format!("/var/makiatto/sites/{}", domain.name);
    ssh.exec(&format!("sudo mkdir -p {target_dir}"))?;

    if let Err(e) = ssh.exec(&format!(
        "curl -s -X POST http://{}:8282/watcher/pause",
        machine.wg_address
    )) {
        return Err(miette!(format!("Failed to pause file watcher: {e}")));
    }

    let spinner = ui::spinner("Running rsync...");

    let source = domain.path.to_string_lossy();
    let target = format!("{}@{}:{}/", ssh.user, ssh.host, target_dir);

    let ssh_args = if let Some(key_path) = key_path {
        format!(
            "ssh -i {} -p {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
            key_path.display(),
            ssh.port
        )
    } else {
        format!(
            "ssh -p {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
            ssh.port
        )
    };

    let rsync_path = if let Some(password) = &ssh.password {
        &format!("echo '{password}' | sudo -S rsync")
    } else {
        "sudo rsync"
    };

    let mut rsync_cmd = std::process::Command::new("rsync");
    rsync_cmd
        .arg("-avz")
        .arg("--delete-after")
        .arg("--progress")
        .arg("-e")
        .arg(&ssh_args)
        .arg("--rsync-path")
        .arg(rsync_path)
        .arg(format!("{}/", source.trim_end_matches('/')))
        .arg(&target);

    let output = rsync_cmd
        .output()
        .map_err(|e| miette!("Failed to execute rsync: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette!("rsync failed: {stderr}"));
    }

    spinner.finish_with_message("✓ rsync completed");

    // fix ownership (`rsync --chown` not available in older rsync on macOS)
    ssh.exec(&format!("sudo chown -R makiatto:makiatto {target_dir}"))?;

    // trigger a manual directory scan to catch any files missed by the watcher
    ui::status("Scanning synced files...");
    ssh.exec(&format!(
        "curl -s -X POST http://{}:8282/scan/{}",
        machine.wg_address, domain.name
    ))?;

    if let Err(e) = ssh.exec(&format!(
        "curl -s -X POST http://{}:8282/watcher/resume",
        machine.wg_address
    )) {
        return Err(miette!(format!("Failed to resume file watcher: {e}")));
    }

    Ok(())
}

fn sync_domain_records(ssh: &SshSession, domain: &Domain, machines: &[Machine]) -> Result<()> {
    ui::status("Updating DNS records...");

    let domain_sql = format!(
        "INSERT OR IGNORE INTO domains (name) VALUES ('{}')",
        domain.name
    );
    corrosion::execute_transactions(ssh, &[domain_sql])?;

    for alias in domain.aliases.iter() {
        let alias_sql = format!(
            "INSERT OR REPLACE INTO domain_aliases (alias, target) VALUES ('{}', '{}')",
            alias, domain.name
        );
        corrosion::execute_transactions(ssh, &[alias_sql])?;
    }

    let existing_records = get_existing_dns_records(ssh, &domain.name)?;

    let mut desired_records = Vec::new();
    generate_dns_records(
        &domain.name,
        machines,
        &domain.records,
        &mut desired_records,
    )?;

    apply_dns_diff(ssh, &domain.name, &existing_records, &desired_records)?;

    Ok(())
}

fn get_existing_dns_records(
    ssh: &SshSession,
    domain: &str,
) -> Result<Vec<(DnsRecordKey, DnsRecordData)>> {
    let sql = format!(
        "SELECT name, record_type, value, ttl, priority, geo_enabled FROM dns_records WHERE domain = '{domain}'"
    );
    let cmd = format!("sudo sqlite3 /var/makiatto/cluster.db -separator '|' \"{sql}\"");

    let output = ssh.exec(&cmd)?;
    let mut records = Vec::new();

    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() != 6 {
            continue;
        }

        let key = DnsRecordKey {
            name: parts[0].to_string(),
            record_type: parts[1].to_string(),
        };

        let data = DnsRecordData {
            value: parts[2].to_string(),
            ttl: parts[3].parse().unwrap_or(300),
            priority: parts[4].parse().unwrap_or(0),
            geo_enabled: parts[5] == "1",
        };

        records.push((key, data));
    }

    Ok(records)
}

/// Generate all DNS records for a domain including infrastructure and custom records
///
/// # Errors
/// Returns an error if no nameservers are configured
///
/// # Panics
/// May panic if a machine has `ipv6` set to `Some` but the value is accessed incorrectly
pub fn generate_dns_records(
    domain: &str,
    machines: &[Machine],
    custom_records: &[DnsRecord],
    records: &mut Vec<(DnsRecordKey, DnsRecordData)>,
) -> Result<()> {
    let mut nameservers: Vec<_> = machines.iter().filter(|m| m.is_nameserver).collect();
    nameservers.sort_by(|a, b| a.name.cmp(&b.name));

    if nameservers.is_empty() {
        return Err(miette!(
            "No nameservers configured. At least one machine must be a nameserver"
        ));
    }

    if let Some(machine) = machines.iter().find(|m| !m.ipv4.is_empty()) {
        records.push((
            DnsRecordKey {
                name: "@".to_string(),
                record_type: "A".to_string(),
            },
            DnsRecordData {
                value: machine.ipv4.to_string(),
                ttl: 300,
                priority: 0,
                geo_enabled: true,
            },
        ));
    }

    if let Some(machine) = machines
        .iter()
        .find(|m| m.ipv6.is_some() && !m.ipv6.as_ref().unwrap().is_empty())
    {
        records.push((
            DnsRecordKey {
                name: "@".to_string(),
                record_type: "AAAA".to_string(),
            },
            DnsRecordData {
                value: machine.ipv6.as_ref().unwrap().to_string(),
                ttl: 300,
                priority: 0,
                geo_enabled: true,
            },
        ));
    }

    // generate NS records for each nameserver
    for nameserver in &nameservers {
        let ns_name = format!("{}.ns", nameserver.name);

        records.push((
            DnsRecordKey {
                name: "@".to_string(),
                record_type: "NS".to_string(),
            },
            DnsRecordData {
                value: format!("{ns_name}.{domain}"),
                ttl: 300,
                priority: 0,
                geo_enabled: false,
            },
        ));

        records.push((
            DnsRecordKey {
                name: ns_name.clone(),
                record_type: "A".to_string(),
            },
            DnsRecordData {
                value: nameserver.ipv4.to_string(),
                ttl: 300,
                priority: 0,
                geo_enabled: false,
            },
        ));

        if let Some(ipv6) = &nameserver.ipv6
            && !ipv6.is_empty()
        {
            records.push((
                DnsRecordKey {
                    name: ns_name,
                    record_type: "AAAA".to_string(),
                },
                DnsRecordData {
                    value: ipv6.to_string(),
                    ttl: 300,
                    priority: 0,
                    geo_enabled: false,
                },
            ));
        }
    }

    if let Some(primary_ns) = nameservers.first() {
        let serial = {
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let date = now / 86400; // Days since epoch
            format!("{date}00")
        };

        let soa_value = format!(
            "{}.ns.{} admin.{} {} 86400 10800 3600000 3600",
            primary_ns.name, domain, domain, serial
        );

        records.push((
            DnsRecordKey {
                name: "@".to_string(),
                record_type: "SOA".to_string(),
            },
            DnsRecordData {
                value: soa_value,
                ttl: 300,
                priority: 0,
                geo_enabled: false,
            },
        ));
    }

    records.push((
        DnsRecordKey {
            name: "@".to_string(),
            record_type: "CAA".to_string(),
        },
        DnsRecordData {
            value: "0 issue letsencrypt.org".to_string(),
            ttl: 300,
            priority: 0,
            geo_enabled: false,
        },
    ));

    // Add custom records from config
    for record in custom_records {
        records.push((
            DnsRecordKey {
                name: record.name.to_string(),
                record_type: record.record_type.to_string(),
            },
            DnsRecordData {
                value: record.value.to_string(),
                ttl: record.ttl,
                priority: record.priority.unwrap_or(0),
                geo_enabled: false,
            },
        ));
    }

    Ok(())
}

fn apply_dns_diff(
    ssh: &SshSession,
    domain: &str,
    existing: &[(DnsRecordKey, DnsRecordData)],
    desired: &[(DnsRecordKey, DnsRecordData)],
) -> Result<()> {
    let existing_set: HashSet<_> = existing.iter().collect();
    let desired_set: HashSet<_> = desired.iter().collect();

    let to_delete: Vec<_> = existing
        .iter()
        .filter(|r| !desired_set.contains(r))
        .collect();

    let to_add: Vec<_> = desired
        .iter()
        .filter(|r| !existing_set.contains(r))
        .collect();

    if to_delete.is_empty() && to_add.is_empty() {
        return Ok(());
    }

    let mut sqls = Vec::new();

    for (key, data) in &to_delete {
        ui::action(&format!(
            "Removing DNS record: {} {} -> {}",
            key.name, key.record_type, data.value
        ));
        let sql = format!(
            "DELETE FROM dns_records WHERE domain = '{}' AND name = '{}' AND record_type = '{}'",
            domain, key.name, key.record_type
        );
        sqls.push(sql);
    }

    for (key, data) in &to_add {
        ui::action(&format!(
            "Adding DNS record: {} {} -> {}",
            key.name, key.record_type, data.value
        ));
        let id = Uuid::now_v7().to_string();
        let sql = format!(
            "INSERT INTO dns_records (id, domain, name, record_type, value, ttl, priority, geo_enabled) \
             VALUES ('{}', '{}', '{}', '{}', '{}', {}, {}, {})",
            id,
            domain,
            key.name,
            key.record_type,
            data.value,
            data.ttl,
            data.priority,
            i32::from(data.geo_enabled)
        );
        sqls.push(sql);
    }

    corrosion::execute_transactions(ssh, &sqls)?;

    let added_ns_records: Vec<_> = to_add
        .iter()
        .filter(|(key, _)| key.record_type == "NS")
        .collect();

    if !added_ns_records.is_empty() {
        ui::warn("⚠️ New nameserver records detected");
        ui::info(
            "Consider running `maki dns nameserver-setup` to get the complete nameserver configuration guide.",
        );
    }

    Ok(())
}

fn sync_domain_functions(ssh: &SshSession, domain: &Domain) -> Result<()> {
    if domain.functions.is_empty() {
        return Ok(());
    }

    ui::status("Syncing WASM functions...");

    let delete_sql = format!(
        "DELETE FROM domain_functions WHERE domain = '{}'",
        domain.name
    );
    corrosion::execute_transactions(ssh, &[delete_sql])?;

    let mut sqls = Vec::new();
    for function in domain.functions.iter() {
        let path_str = function.path.display().to_string();

        let route = path_str.strip_suffix(".wasm").unwrap();
        let route = if route.starts_with('/') {
            route.to_string()
        } else {
            format!("/{route}")
        };

        let id = format!("{}:{}", domain.name, route);

        let methods_json = if let Some(ref methods) = function.methods {
            serde_json::to_string(methods).unwrap_or_else(|_| "null".to_string())
        } else {
            "null".to_string()
        };

        let env_json = serde_json::to_string(&function.env).unwrap_or_else(|_| "{}".to_string());

        let timeout_ms = function
            .timeout_ms
            .map_or("NULL".to_string(), |t| t.to_string());
        let max_memory_mb = function
            .max_memory_mb
            .map_or("NULL".to_string(), |m| m.to_string());

        let updated_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let sql = format!(
            "INSERT INTO domain_functions (\
                id, domain, path, methods, env, \
                timeout_ms, max_memory_mb, updated_at\
            ) VALUES (\
                '{}', '{}', '{}', '{}', '{}', \
                {}, {}, {}\
            )",
            id,
            domain.name,
            path_str,
            methods_json,
            env_json,
            timeout_ms,
            max_memory_mb,
            updated_at
        );
        sqls.push(sql);

        ui::action(&format!("  Added function: {path_str}"));
    }

    corrosion::execute_transactions(ssh, &sqls)?;
    Ok(())
}

fn sync_domain_transforms(ssh: &SshSession, domain: &Domain) -> Result<()> {
    if domain.transforms.is_empty() {
        return Ok(());
    }

    ui::status("Syncing WASM transforms...");

    // Delete existing transforms for this domain
    let delete_sql = format!(
        "DELETE FROM domain_transforms WHERE domain = '{}'",
        domain.name
    );
    corrosion::execute_transactions(ssh, &[delete_sql])?;

    let mut sqls = Vec::new();
    for (idx, transform) in domain.transforms.iter().enumerate() {
        let path_str = transform.path.display().to_string();
        let id = format!("{}:{}:{}", domain.name, path_str, idx);

        let env_json = serde_json::to_string(&transform.env).unwrap_or_else(|_| "{}".to_string());

        let timeout_ms = transform
            .timeout_ms
            .map_or("NULL".to_string(), |t| t.to_string());
        let max_memory_mb = transform
            .max_memory_mb
            .map_or("NULL".to_string(), |m| m.to_string());
        let max_file_size_kb = transform
            .max_file_size_kb
            .map_or("NULL".to_string(), |s| s.to_string());

        let updated_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let sql = format!(
            "INSERT INTO domain_transforms (\
                id, domain, path, files_pattern, env, \
                timeout_ms, max_memory_mb, max_file_size_kb, \
                execution_order, updated_at\
            ) VALUES (\
                '{}', '{}', '{}', '{}', '{}', \
                {}, {}, {}, \
                {}, {}\
            )",
            id,
            domain.name,
            path_str,
            transform.files,
            env_json,
            timeout_ms,
            max_memory_mb,
            max_file_size_kb,
            idx,
            updated_at
        );
        sqls.push(sql);

        ui::action(&format!(
            "  Added transform: {} ({})",
            path_str, transform.files
        ));
    }

    corrosion::execute_transactions(ssh, &sqls)?;
    Ok(())
}
