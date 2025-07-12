use std::path::PathBuf;

use indoc::formatdoc;
use miette::Result;

use crate::{
    config::{GlobalConfig, MachineConfig},
    machine::corrosion,
    ssh::SshSession,
    ui,
};

pub fn install_makiatto(
    global_config: &GlobalConfig,
    machine_config: &MachineConfig,
    wg_private_key: &str,
    binary_path: Option<&PathBuf>,
    key_path: Option<&PathBuf>,
) -> Result<SshSession> {
    ui::status("Connecting to remote machine via SSH...");
    let ssh = SshSession::new(&machine_config.ssh_target, key_path)?;

    create_makiatto_user(&ssh)?;
    install_makiatto_binary(&ssh, binary_path)?;
    setup_system_permissions(&ssh)?;
    ensure_sqlite3_installed(&ssh)?;
    create_daemon_config(&ssh, global_config, machine_config, wg_private_key)?;
    setup_systemd_service(&ssh)?;

    if ssh.is_container() {
        ui::info("Container environment detected - starting makiatto as background process");
        start_makiatto_background(&ssh)?;
    } else {
        start_makiatto_service(&ssh)?;
    }

    add_self_as_peer(&ssh, machine_config)?;

    Ok(ssh)
}

fn create_makiatto_user(ssh: &SshSession) -> Result<()> {
    ui::status("Creating makiatto user...");

    if ssh.exec("id makiatto").is_ok() {
        ui::info("Makiatto user already exists");
        return Ok(());
    }

    ui::action("Creating system user");
    ssh.exec(
        "sudo useradd --system --home-dir /var/makiatto --create-home --shell /bin/false makiatto",
    )?;

    ui::action("Adding user to systemd-journal group");
    ssh.exec("sudo usermod -a -G systemd-journal makiatto")?;

    ui::action("Setting up passwordless sudo permissions");
    let sudoers_cmd = formatdoc! {r"
        sudo tee /etc/sudoers.d/makiatto > /dev/null << 'EOF'
        makiatto ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/sbin/setcap, /usr/bin/mkdir, /usr/bin/chown, /usr/bin/chmod, /usr/bin/ip, /usr/sbin/ip
        EOF
    "};
    ssh.exec(&sudoers_cmd)?;

    Ok(())
}

fn install_makiatto_binary(ssh: &SshSession, binary_path: Option<&PathBuf>) -> Result<()> {
    ui::status("Installing makiatto binary...");

    if let Some(path) = binary_path {
        ssh.upload_file(path, "/tmp/makiatto")?;

        let commands = vec![
            "sudo mkdir -p /usr/local/bin",
            "sudo mv /tmp/makiatto /usr/local/bin/makiatto",
            "sudo chmod +x /usr/local/bin/makiatto",
            "sudo chown makiatto:makiatto /usr/local/bin/makiatto",
        ];

        for cmd in commands {
            ssh.exec(cmd)?;
        }
    } else {
        return Err(miette::miette!(
            "TODO: download binary from github releases"
        ));
    }

    Ok(())
}

fn setup_system_permissions(ssh: &SshSession) -> Result<()> {
    ui::status("Setting up system permissions...");

    // Only set capabilities if not in a container (overlay fs doesn't support xattrs properly)
    if ssh.is_container() {
        ui::info("Container detected - skipping capability setup (overlay fs limitation)");
    } else {
        ui::action("Setting network admin capabilities");
        ssh.exec("sudo setcap cap_net_admin=+epi /usr/local/bin/makiatto")?;
    }

    ui::action("Configuring unprivileged port binding");
    ssh.exec(
        "echo 'net.ipv4.ip_unprivileged_port_start=0' | sudo tee /etc/sysctl.d/50-unprivileged-ports.conf"
    )?;

    ui::action("Reloading sysctl configuration");
    ssh.exec("sudo sysctl --system")?;

    Ok(())
}

fn ensure_sqlite3_installed(ssh: &SshSession) -> Result<()> {
    if ssh.exec("which sqlite3").is_ok() {
        return Ok(());
    }

    ui::status("Installing SQLite3...");

    // Try different package managers in order of preference
    let install_commands = [
        // Debian/Ubuntu (apt)
        "sudo apt update && sudo apt install -y sqlite3",
        // RHEL/CentOS/Fedora (yum/dnf)
        "sudo dnf install -y sqlite || sudo yum install -y sqlite",
        // Alpine Linux (apk)
        "sudo apk add sqlite",
        // Arch Linux (pacman)
        "sudo pacman -S --noconfirm sqlite",
        // openSUSE (zypper)
        "sudo zypper install -y sqlite3",
        // Gentoo (emerge)
        "sudo emerge dev-db/sqlite",
        // FreeBSD (pkg)
        "sudo pkg install -y sqlite3",
    ];

    for cmd in &install_commands {
        if ssh.exec(cmd).is_ok() && ssh.exec("which sqlite3").is_ok() {
            return Ok(());
        }
    }

    Err(miette::miette!(
        "Failed to install SQLite3. Please install it manually on the target system."
    ))
}

fn create_daemon_config(
    ssh: &SshSession,
    global_config: &GlobalConfig,
    machine_config: &MachineConfig,
    wg_private_key: &str,
) -> Result<()> {
    ui::status("Creating makiatto configuration...");

    // bootstrap with wireguard ip address + corrosion gossip port
    let corrosion_bootstrap: Vec<String> = global_config
        .machines
        .iter()
        .take(10)
        .filter(|m| m.name != machine_config.name)
        .map(|m| format!("{}:8787", m.wg_address))
        .collect();

    // collect wireguard bootstrap peers
    let wireguard_peers: Vec<String> = global_config
        .machines
        .iter()
        .map(|m| {
            formatdoc! {r#"
            [[wireguard.bootstrap]]
            public_key = "{}"
            endpoint = "{}:51880""#,
                m.wg_public_key,
                m.ipv4
            }
        })
        .collect();

    let wireguard_bootstrap = wireguard_peers.join("\n\n");

    let config_content = formatdoc! {
        r#"
        [node]
        name = "{name}"
        data_dir = "/var/makiatto"
        is_nameserver = {is_nameserver}

        [wireguard]
        interface = "wawa0"
        address = "{wg_address}"
        private_key = "{wg_private_key}"
        public_key = "{wg_public_key}"

        {wireguard_bootstrap}

        [dns]
        addr = "0.0.0.0:53"
        geolite_path = "/var/makiatto/GeoLite2-City.mmdb"

        [web]
        http_addr = "0.0.0.0:80"
        https_addr = "0.0.0.0:443"
        static_dir = "/var/makiatto/sites"

        [corrosion.admin]
        path = "/var/makiatto/admin.sock"

        [corrosion.db]
        path = "/var/makiatto/cluster.db"

        [corrosion.gossip]
        addr = "0.0.0.0:8787"
        external_addr = "{wg_address}:8787"
        bootstrap = {corrosion_bootstrap:?}
        plaintext = true

        [corrosion.api]
        addr = "127.0.0.1:8181"
        "#,
        name = machine_config.name,
        is_nameserver = machine_config.is_nameserver,
        wg_address = machine_config.wg_address,
        wg_private_key = wg_private_key,
        wg_public_key = machine_config.wg_public_key,
        wireguard_bootstrap = wireguard_bootstrap,
        corrosion_bootstrap = corrosion_bootstrap,
    };

    if ssh.exec("test -d /var/makiatto").is_ok() {
        ui::action("Cleaning up old data directory");
        ssh.exec("sudo rm -rf /var/makiatto")?;
    }

    ui::action("Creating data directories");
    ssh.exec("sudo mkdir -p /var/makiatto")?;
    ssh.exec("sudo mkdir -p /var/makiatto/sites")?;
    ssh.exec("sudo mkdir -p /etc/makiatto")?;

    ui::action("Setting directory ownership");
    ssh.exec("sudo chown -R makiatto:makiatto /var/makiatto")?;

    ui::action("Writing configuration file");
    let write_config_cmd = formatdoc! {r"
        sudo tee /etc/makiatto.toml > /dev/null << 'EOF'
        {config_content}
        EOF
        ",
        config_content = config_content
    };
    ssh.exec(&write_config_cmd)?;
    ssh.exec("sudo chown makiatto:makiatto /etc/makiatto.toml")?;

    Ok(())
}

fn setup_systemd_service(ssh: &SshSession) -> Result<()> {
    ui::status("Setting up systemd service...");

    let service_content = formatdoc! {r"
        [Unit]
        Description=Makiatto Service
        After=network.target
        Wants=network.target

        [Service]
        Type=simple
        ExecStart=/usr/local/bin/makiatto
        Restart=on-failure
        RestartSec=10
        StartLimitBurst=3
        StartLimitIntervalSec=60
        User=makiatto
        Group=makiatto
        Environment=RUST_LOG=makiatto=info
        WorkingDirectory=/var/makiatto

        [Install]
        WantedBy=multi-user.target
    "};

    ui::action("Writing systemd service file");
    let write_service_cmd = formatdoc! {r"
        sudo tee /etc/systemd/system/makiatto.service > /dev/null << 'EOF'
        {service_content}
        EOF
        ",
        service_content = service_content
    };
    ssh.exec(&write_service_cmd)?;

    Ok(())
}

fn start_makiatto_service(ssh: &SshSession) -> Result<()> {
    ui::action("Reloading systemd daemon");
    ssh.exec("sudo systemctl daemon-reload")?;

    ui::action("Enabling service on boot");
    ssh.exec("sudo systemctl enable makiatto")?;

    ui::status("Starting makiatto service...");

    ssh.exec("sudo systemctl restart makiatto")?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    match ssh.exec("sudo systemctl is-active makiatto") {
        Ok(status) => {
            if status.trim() != "active" {
                return Err(miette::miette!(
                    "Service status: {} - check 'sudo systemctl status makiatto' for details",
                    status.trim(),
                ));
            }
        }
        Err(_) => {
            return Err(miette::miette!(
                "Service failed to start - check logs with 'sudo journalctl -u makiatto'"
            ));
        }
    }

    Ok(())
}

fn add_self_as_peer(ssh: &SshSession, machine_config: &MachineConfig) -> Result<()> {
    ui::status("Inserting self into database...");
    let spinner = ui::spinner("Checking for waiting for database to be ready...");
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(10);

    loop {
        if start_time.elapsed() > timeout {
            spinner.finish_with_message("Timeout waiting for peers table");
            return Err(miette::miette!(
                "Timeout waiting for peers table to be created"
            ));
        }

        let result = ssh.exec("sudo -u makiatto sqlite3 /var/makiatto/cluster.db \".tables\"");

        if let Ok(output) = result
            && output.contains("peers")
        {
            spinner.finish_with_message("✓ Database ready");
            std::thread::sleep(std::time::Duration::from_secs(1));
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    ui::action("Writing to Corrosion API");
    corrosion::insert_peer(ssh, machine_config)?;

    Ok(())
}

fn start_makiatto_background(ssh: &SshSession) -> Result<()> {
    ui::status("Starting makiatto in background...");

    ui::action("Launching background process");
    ssh.exec("sudo -u makiatto nohup /usr/local/bin/makiatto > /var/makiatto/makiatto.log 2>&1 &")?;
    std::thread::sleep(std::time::Duration::from_secs(1));

    let result = ssh.exec("pgrep -f '/usr/local/bin/makiatto'");
    match result {
        Ok(pid) => {
            ui::info(&format!("Makiatto started with PID: {}", pid.trim()));
        }
        Err(_) => {
            return Err(miette::miette!(
                "Failed to start makiatto - check logs with 'tail /var/makiatto/makiatto.log'"
            ));
        }
    }

    Ok(())
}
