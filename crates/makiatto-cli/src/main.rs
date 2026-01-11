use std::path::PathBuf;

use argh::FromArgs;
use makiatto_cli::{
    config::{Config, Profile},
    dns,
    health::{self, HealthCommand},
    machine::{self, AddMachine, InitMachine, RemoveMachine, UpgradeMachine},
    peer::{self, AddExternalPeer, RemoveExternalPeer, WgConfig},
    sync::{self, SyncCommand},
    ui,
    wasm::{self, WasmCommand},
};
use miette::Result;

/// maki (makiatto-cli) - manage makiatto cdn nodes and deployments
#[derive(FromArgs)]
struct Cli {
    /// project config path (default: ./makiatto.toml)
    #[argh(option, long = "config")]
    config_path: Option<PathBuf>,

    /// profile path (default: ~/.config/makiatto/default.toml)
    #[argh(option, long = "profile")]
    profile_path: Option<PathBuf>,

    /// show version information
    #[argh(switch)]
    version: bool,

    #[argh(subcommand)]
    command: Option<Command>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Machine(MachineCommand),
    Peer(PeerCommand),
    Sync(SyncCommand),
    Health(HealthCommand),
    Dns(DnsCommand),
    Wasm(WasmCommand),
}

/// manage external peers
#[derive(FromArgs)]
#[argh(subcommand, name = "peer")]
struct PeerCommand {
    #[argh(subcommand)]
    action: PeerAction,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum PeerAction {
    Add(AddExternalPeer),
    WgConfig(WgConfig),
    Remove(RemoveExternalPeer),
}

/// manage makiatto machines
#[derive(FromArgs)]
#[argh(subcommand, name = "machine")]
struct MachineCommand {
    #[argh(subcommand)]
    action: MachineAction,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum MachineAction {
    Init(InitMachine),
    Add(AddMachine),
    List(ListMachines),
    Upgrade(UpgradeMachine),
    Remove(RemoveMachine),
}

/// list configured machines
#[derive(FromArgs)]
#[argh(subcommand, name = "list")]
struct ListMachines {}

/// manage DNS configuration
#[derive(FromArgs)]
#[argh(subcommand, name = "dns")]
struct DnsCommand {
    #[argh(subcommand)]
    action: DnsAction,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum DnsAction {
    NameserverSetup(NameserverSetupCommand),
}

/// show complete nameserver setup guide for domain registrars
#[derive(FromArgs)]
#[argh(subcommand, name = "nameserver-setup")]
struct NameserverSetupCommand {}

#[tokio::main]
async fn main() -> Result<()> {
    let cli: Cli = argh::from_env();

    if cli.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let Some(command) = cli.command else {
        eprintln!("No command specified. Use --help for usage information.");
        std::process::exit(1);
    };

    let mut profile = Profile::load(cli.profile_path.clone())?;

    match command {
        Command::Machine(machine) => match machine.action {
            MachineAction::Init(init) => {
                machine::init_machine(&init, &mut profile)?;
                profile.save(cli.profile_path)?;

                Ok(())
            }
            MachineAction::Add(add) => {
                machine::add_machine(&add, &mut profile)?;
                profile.save(cli.profile_path)?;

                Ok(())
            }
            MachineAction::List(_) => {
                if profile.machines.is_empty() {
                    ui::info("No machines configured yet. Use `machine init` to add one");
                } else {
                    ui::header("Configured machines:");
                    for (i, machine) in profile.machines.iter().enumerate() {
                        if i > 0 {
                            ui::separator();
                        }
                        ui::field("Name", &machine.name);
                        ui::field("SSH Target", &machine.ssh_target);
                        ui::field("Nameserver", &machine.is_nameserver.to_string());
                        ui::field("WireGuard Address", &machine.wg_address);
                    }
                }
                Ok(())
            }
            MachineAction::Upgrade(upgrade) => {
                machine::upgrade_machine(&upgrade, &profile)?;
                Ok(())
            }
            MachineAction::Remove(remove) => {
                machine::remove_machine(&remove, &mut profile)?;
                profile.save(cli.profile_path)?;
                Ok(())
            }
        },
        Command::Peer(peer_cmd) => match peer_cmd.action {
            PeerAction::Add(add) => {
                peer::add_external_peer(&add, &profile)?;
                Ok(())
            }
            PeerAction::WgConfig(wg_config) => {
                peer::show_wg_config(&wg_config, &profile)?;
                Ok(())
            }
            PeerAction::Remove(remove) => {
                peer::remove_external_peer(&remove, &profile)?;
                Ok(())
            }
        },
        Command::Sync(command) => {
            let config = Config::load(cli.config_path)?;
            sync::sync_project(&command, &profile, &config)?;
            Ok(())
        }
        Command::Health(command) => {
            let config = Config::load(cli.config_path)?;
            health::check_health(&command, &profile, &config).await
        }
        Command::Dns(dns) => match dns.action {
            DnsAction::NameserverSetup(_) => {
                let config = Config::load(cli.config_path)?;
                dns::show_nameserver_setup(&profile, &config)?;
                Ok(())
            }
        },
        Command::Wasm(wasm) => match wasm.action {
            wasm::WasmAction::Fetch(fetch) => wasm::fetch_wit(&fetch).await,
        },
    }
}
