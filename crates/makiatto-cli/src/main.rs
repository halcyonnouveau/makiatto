use std::path::PathBuf;

use argh::FromArgs;
use makiatto_cli::{
    config::{Config, Profile},
    machine::{self, AddMachine, InitMachine},
    sync::{self, SyncCommand},
    ui,
};
use miette::Result;

/// makiatto-cli - manage makiatto cdn nodes and deployments
#[derive(FromArgs)]
struct Cli {
    /// path to local project config (default: ./makiatto.toml)
    #[argh(option, long = "config")]
    config_path: Option<PathBuf>,

    /// path to machines profile (default: ~/.config/makiatto/default.toml)
    #[argh(option, long = "profile")]
    profile_path: Option<PathBuf>,

    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Machine(MachineCommand),
    Sync(SyncCommand),
    Status(StatusCommand),
}

// TODO: commands to add
// machine remove - remove a machine from the cluster
// update - update all machines with latest makiatto server
// domain list - list all domains in the corrosion db
// domain remove - remove a domain from the corrosion db

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
}

/// list configured machines
#[derive(FromArgs)]
#[argh(subcommand, name = "list")]
struct ListMachines {}

/// show cluster status
#[derive(FromArgs)]
#[argh(subcommand, name = "status")]
struct StatusCommand {}

#[tokio::main]
async fn main() -> Result<()> {
    let cli: Cli = argh::from_env();
    let mut profile = Profile::load(cli.profile_path.clone())?;

    match cli.command {
        Command::Machine(machine) => match machine.action {
            MachineAction::Init(init) => {
                machine::init_machine(&init, &mut profile).await?;
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
        },
        Command::Sync(command) => {
            let config = Config::load(cli.config_path)?;
            sync::sync_project(&command, &profile, &config)?;
            Ok(())
        }
        Command::Status(_) => {
            ui::header("Cluster status:");
            // TODO: Query machines for status
            Ok(())
        }
    }
}
