use std::path::PathBuf;

use argh::FromArgs;
use makiatto_cli::{
    config::{LocalConfig, MachineConfig},
    machine::{self, AddMachine, InitMachine},
    ui,
};
use miette::Result;

/// makiatto-cli - manage makiatto cdn nodes and deployments
#[derive(FromArgs)]
struct Cli {
    /// path to local project config (default: ./makiatto.toml)
    #[argh(option, long = "config")]
    config_path: Option<PathBuf>,

    /// path to machines config (default: ~/.config/makiatto/default.toml)
    #[argh(option, long = "machines-config")]
    machines_config_path: Option<PathBuf>,

    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Machine(MachineCommand),
    Deploy(DeployCommand),
    Status(StatusCommand),
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
}

/// list configured machines
#[derive(FromArgs)]
#[argh(subcommand, name = "list")]
struct ListMachines {}

/// deploy the project to the cdn
#[derive(FromArgs)]
#[argh(subcommand, name = "sync")]
struct DeployCommand {}

/// show cluster status
#[derive(FromArgs)]
#[argh(subcommand, name = "status")]
struct StatusCommand {}

#[tokio::main]
async fn main() -> Result<()> {
    let cli: Cli = argh::from_env();
    let mut machines_config = MachineConfig::load(cli.machines_config_path.clone())?;

    match cli.command {
        Command::Machine(machine) => match machine.action {
            MachineAction::Init(init) => {
                machine::init_machine(&init, &mut machines_config)?;
                machines_config.save(cli.machines_config_path)?;

                Ok(())
            }
            MachineAction::Add(add) => {
                machine::add_machine(&add, &mut machines_config)?;
                machines_config.save(cli.machines_config_path)?;

                Ok(())
            }
            MachineAction::List(_) => {
                if machines_config.machines.is_empty() {
                    ui::info("No machines configured yet. Use `machine init` to add one");
                } else {
                    ui::header("Configured machines:");
                    for (i, machine) in machines_config.machines.iter().enumerate() {
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
        Command::Deploy(_) => {
            let _ = LocalConfig::load(cli.config_path);
            /*
             * Update LocalConfig Structure
             *    - Add ttl field to DnsRecord struct (optional, defaults to 300)
             *    - Add priority field to DnsRecord struct (optional, for MX records)
             *
             * Implement Sync Command Logic
             *    - Load ./makiatto.toml using LocalConfig::load()
             *    - Load machines config to get machine list and find nameservers
             *    - Connect to first available machine's Corrosion API or database
             *    - Insert/update domain in domains table
             *    - Auto-generate required DNS records:
             *      * A records: Point to all active peer IPs (with geo_enabled=1)
             *      * SOA record: Primary nameserver with standard values
             *      * NS records: One for each nameserver machine
             *      * CAA records: Let's Encrypt authorization
             *    - Insert custom records from config records array
             *
             * Database Operations
             *    - Set appropriate geo_enabled flags (1 for A/AAAA records, 0 for others)
             *
             * Error Handling
             *    - Validate domain format
             *    - Handle database connection errors
             *    - Check if machines exist in peers table
             *    - Provide clear error messages for missing configs
             */
            Ok(())
        }
        Command::Status(_) => {
            ui::header("Cluster status:");
            // TODO: Query machines for status
            Ok(())
        }
    }
}
