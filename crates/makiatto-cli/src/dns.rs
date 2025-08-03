use miette::Result;

use crate::{
    config::{Config, Profile},
    ui,
};

/// Show complete nameserver setup guide for domain registrars
///
/// # Errors
/// Returns an error if no nameservers are configured
pub fn show_nameserver_setup(profile: &Profile, config: &Config) -> Result<()> {
    if profile.machines.is_empty() {
        ui::warn("No machines configured. Use `machine init` to add one first");
        return Ok(());
    }

    if config.domains.is_empty() {
        ui::warn("No domains configured in makiatto.toml");
        return Ok(());
    }

    let nameservers: Vec<_> = profile
        .machines
        .iter()
        .filter(|m| m.is_nameserver)
        .collect();

    if nameservers.is_empty() {
        ui::warn("No nameservers configured. At least one machine must be a nameserver");
        return Ok(());
    }

    ui::text("Follow these steps to configure your custom nameservers:\n");

    // Step 1: Glue Records
    ui::header("Step 1: Add glue records to your domain registrar\n");
    ui::text(
        "Glue records tell the internet where to find your nameservers when they're subdomains of your own domain.",
    );
    ui::text(
        "Without them, there's a circular dependency: DNS can't find your nameservers to resolve your domain.",
    );
    ui::text(
        "Add these as glue records (also called 'name server records' or 'host records') in your domain registrar's control panel.\n",
    );

    for domain in config.domains.iter() {
        ui::info(&format!("Glue records for {}:\n", domain.name));

        for nameserver in &nameservers {
            let ns_hostname = format!("{}.ns.{}", nameserver.name, domain.name);
            let mut ips = vec![nameserver.ipv4.clone()];

            if let Some(ipv6) = &nameserver.ipv6
                && !ipv6.is_empty()
            {
                ips.push(ipv6.clone());
            }

            let ip_list = ips.join(", ");
            ui::field(&ns_hostname, &ip_list);
        }

        println!();
    }

    // Step 2: Nameserver Configuration
    ui::header("Step 2: Set your domain to use your custom nameservers\n");
    ui::text(
        "After adding glue records, you must also tell your registrar to use your custom nameservers instead of their defaults.",
    );
    ui::text(
        "In your domain registrar's control panel, change the nameservers for your domain to:",
    );
    println!();

    for domain in config.domains.iter() {
        ui::info(&format!("Nameservers for {}:\n", domain.name));

        for nameserver in &nameservers {
            ui::text(&format!("  {}.ns.{}", nameserver.name, domain.name));
        }

        println!();
    }

    // Step 3: Testing and Notes
    ui::header("Step 3: Testing and verification");
    ui::text("After configuration, test your setup with:\n");
    for domain in config.domains.iter() {
        let first_ns = format!("{}.ns.{}", nameservers[0].name, domain.name);
        ui::command(&format!("dig @{} {}", first_ns, domain.name));
    }
    println!();
    ui::text("Note: DNS changes may take 24-48 hours to propagate globally.");
    ui::text("For registrar-specific guides:");
    ui::text(
        "  Porkbun: https://kb.porkbun.com/article/112-how-to-host-your-own-nameservers-with-glue-records",
    );
    ui::text(
        "  Namecheap: https://www.namecheap.com/support/knowledgebase/article.aspx/768/10/how-do-i-register-personal-nameservers-for-my-domain/",
    );

    Ok(())
}
