use std::path::PathBuf;

use indoc::formatdoc;
use miette::Result;

use crate::{
    config::{GlobalConfig, MachineConfig},
    ssh::SshSession,
    ui,
};

pub fn install_makiatto(
    global_config: &GlobalConfig,
    machine_config: &MachineConfig,
    wg_private_key: &str,
    binary_path: &Option<PathBuf>,
    key_path: &Option<PathBuf>,
) -> Result<SshSession> {
    ui::status("Connecting to remote machine via SSH...");
    let ssh = SshSession::new(&machine_config.ssh_target, key_path)?;

    create_makiatto_user(&ssh)?;
    install_makiatto_binary(&ssh, binary_path)?;
    setup_system_permissions(&ssh)?;

    create_daemon_config(&ssh, global_config, machine_config, wg_private_key)?;
    setup_systemd_service(&ssh)?;

    if ssh.is_remote_container()? {
        ui::info("Container environment detected - skipping systemd start");
    } else {
        start_makiatto_service(&ssh)?;
    }

    // TODO: insert self into peers table, return self

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

fn install_makiatto_binary(ssh: &SshSession, binary_path: &Option<PathBuf>) -> Result<()> {
    ui::status("Installing makiatto binary...");

    if let Some(path) = binary_path {
        ssh.upload_file(path, "/tmp/makiatto")?;

        let commands = vec![
            "sudo mkdir -p /usr/local/bin",
            "sudo mv /tmp/makiatto /usr/local/bin/makiatto",
            "sudo chmod +x /usr/local/bin/makiatto",
            "sudo chown root:root /usr/local/bin/makiatto",
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

    ui::action("Setting network admin capabilities");
    ssh.exec("sudo setcap cap_net_admin=+epi /usr/local/bin/makiatto")?;

    ui::action("Configuring unprivileged port binding");
    ssh.exec(
        "echo 'net.ipv4.ip_unprivileged_port_start=0' | sudo tee /etc/sysctl.d/50-unprivileged-ports.conf"
    )?;

    ui::action("Reloading sysctl configuration");
    ssh.exec("sudo sysctl --system")?;

    Ok(())
}

fn create_daemon_config(
    ssh: &SshSession,
    global_config: &GlobalConfig,
    machine_config: &MachineConfig,
    wg_private_key: &str,
) -> Result<()> {
    ui::status("Creating makiatto configuration...");

    // bootstrap with wireguard ip address + corrosion gossip port
    let bootstrap_machines: Vec<String> = global_config
        .machines
        .iter()
        .take(10)
        .filter(|m| m.name != machine_config.name)
        .map(|m| format!("{}:8787", m.wg_address))
        .collect();

    let config_content = formatdoc! {
        r#"
        [node]
        name = "{name}"
        data_dir = "/var/makiatto"
        is_nameserver = {is_nameserver}

        [network]
        interface = "wawa0"
        port = 51880
        address = "{wg_address}"
        private_key = "{wg_private_key}"
        public_key = "{wg_public_key}"

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
        bootstrap = {bootstrap_machines:?}
        plaintext = true

        [corrosion.api]
        addr = "127.0.0.1:8181"
        "#,
        name = machine_config.name,
        is_nameserver = machine_config.is_nameserver,
        wg_address = machine_config.wg_address,
        wg_private_key = wg_private_key,
        wg_public_key = machine_config.wg_public_key,
        bootstrap_machines = bootstrap_machines,
    };

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
