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
struct DnsRecordKey {
    name: String,
    record_type: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct DnsRecordData {
    value: String,
    ttl: u32,
    priority: i32,
    geo_enabled: bool,
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

    let sync_machine = profile
        .machines
        .iter()
        .find(|m| m.is_nameserver && m.sync_target)
        .unwrap_or(&profile.machines[0]);

    ui::header(&format!("Syncing to machine '{}'", sync_machine.name));

    ui::status(&format!("Connecting to {}", sync_machine.ssh_target));
    let ssh = SshSession::new(&sync_machine.ssh_target, command.key_path.as_ref())?;

    for domain in config.domains.iter() {
        ui::header(&format!("Processing domain: {}", domain.name));
        sync_domain_files(&ssh, domain, command.key_path.as_ref(), sync_machine)?;
        sync_domain_records(&ssh, domain, &profile.machines)?;
    }

    ui::status("Sync completed successfully");
    Ok(())
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
        .arg("--chown=makiatto:makiatto")
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
    generate_dns_records(&domain.name, machines, &mut desired_records)?;
    collect_dns_records(&domain.records, &mut desired_records);

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

#[allow(clippy::too_many_lines)]
fn generate_dns_records(
    domain: &str,
    machines: &[Machine],
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

    Ok(())
}

fn collect_dns_records(
    config_records: &[DnsRecord],
    records: &mut Vec<(DnsRecordKey, DnsRecordData)>,
) {
    for record in config_records {
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
        ui::info("No DNS records changed");
        return Ok(());
    }

    let mut sqls = Vec::new();

    for (key, _) in &to_delete {
        ui::action(&format!(
            "Removing DNS record: {} {}",
            key.name, key.record_type
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

    ui::info(&format!(
        "DNS diff applied: {} added, {} removed",
        to_add.len(),
        to_delete.len()
    ));

    let added_ns_records: Vec<_> = to_add
        .iter()
        .filter(|(key, _)| key.record_type == "NS")
        .collect();

    if !added_ns_records.is_empty() {
        ui::warn("⚠️ New nameserver records detected");
        ui::info(
            "Consider running `makiatto-cli dns nameserver-setup` to get the complete nameserver configuration guide.",
        );
    }

    Ok(())
}
