#![cfg(test)]
use std::sync::Arc;

use makiatto_cli::{
    config::{Config, DnsRecord, Domain, Profile},
    sync::{self, SyncCommand},
};
use miette::{IntoDiagnostic, Result};

use crate::container::{ContainerContext, util};

#[tokio::test]
#[allow(clippy::similar_names)]
async fn test_single_domain() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let daemon = context.make_daemon().await?;
    let machine = daemon.get_config();
    let container = daemon.container.unwrap();

    let test_domain = "test-sync.example.com";
    let domain_path = context.target.join("sites").join(test_domain);

    tokio::fs::create_dir_all(&domain_path)
        .await
        .into_diagnostic()?;

    tokio::fs::write(domain_path.join("index.html"), b"<h1>Test Site</h1>")
        .await
        .into_diagnostic()?;

    tokio::fs::write(domain_path.join("style.css"), b"body { color: red; }")
        .await
        .into_diagnostic()?;

    let nested_dir = domain_path.join("assets");

    tokio::fs::create_dir_all(&nested_dir)
        .await
        .into_diagnostic()?;

    tokio::fs::write(nested_dir.join("script.js"), b"console.log('test');")
        .await
        .into_diagnostic()?;

    let profile = Profile {
        machines: vec![machine.clone()],
    };

    let config = Config {
        domains: vec![Domain {
            name: Arc::from(test_domain),
            path: domain_path.clone(),
            aliases: vec![Arc::from("www.test-sync.example.com")].into(),
            records: vec![DnsRecord {
                name: Arc::from("mail"),
                record_type: Arc::from("A"),
                value: Arc::from("192.168.1.10"),
                ttl: 3600,
                priority: None,
            }]
            .into(),
        }]
        .into(),
    };

    let command = SyncCommand {
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    sync::sync_project(&command, &profile, &config)?;

    let ls_cmd = format!("ls -la /var/makiatto/sites/{test_domain}");
    let (output, _) = util::execute_command(&container, &ls_cmd).await?;
    assert!(output.contains("index.html"));
    assert!(output.contains("style.css"));
    assert!(output.contains("assets"));

    let cat_cmd = format!("cat /var/makiatto/sites/{test_domain}/index.html");
    let (content, _) = util::execute_command(&container, &cat_cmd).await?;
    assert_eq!(content.trim(), "<h1>Test Site</h1>");

    let stat_cmd = format!("stat -c '%U:%G' /var/makiatto/sites/{test_domain}/index.html");
    let (ownership, _) = util::execute_command(&container, &stat_cmd).await?;
    assert_eq!(ownership.trim(), "makiatto:makiatto");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let dns_query = format!(
        "SELECT name, record_type, value FROM dns_records WHERE domain = '{test_domain}' AND name LIKE '%mail%';"
    );
    let dns_result = util::query_database(&container, &dns_query).await?;
    assert!(dns_result.contains("mail|A|192.168.1.10"));

    let alias_query = format!("SELECT alias FROM domain_aliases WHERE target = '{test_domain}';");
    let alias_result = util::query_database(&container, &alias_query).await?;
    assert!(alias_result.contains("www.test-sync.example.com"));

    Ok(())
}

#[tokio::test]
async fn test_multiple_domains() -> Result<()> {
    let mut context = ContainerContext::new()?;
    let daemon = context.make_daemon().await?;
    let machine = daemon.get_config();
    let container = daemon.container.unwrap();

    let domain1 = "site1.example.com";
    let domain2 = "site2.example.com";

    let domain1_path = context.target.join("sites").join(domain1);
    let domain2_path = context.target.join("sites").join(domain2);

    tokio::fs::create_dir_all(&domain1_path)
        .await
        .into_diagnostic()?;
    tokio::fs::create_dir_all(&domain2_path)
        .await
        .into_diagnostic()?;

    tokio::fs::write(domain1_path.join("index.html"), b"<h1>Site 1</h1>")
        .await
        .into_diagnostic()?;
    tokio::fs::write(domain2_path.join("index.html"), b"<h1>Site 2</h1>")
        .await
        .into_diagnostic()?;

    let profile = Profile {
        machines: vec![machine.clone()],
    };

    let config = Config {
        domains: vec![
            Domain {
                name: Arc::from(domain1),
                path: domain1_path.clone(),
                aliases: vec![].into(),
                records: vec![].into(),
            },
            Domain {
                name: Arc::from(domain2),
                path: domain2_path.clone(),
                aliases: vec![].into(),
                records: vec![].into(),
            },
        ]
        .into(),
    };

    let command = SyncCommand {
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    sync::sync_project(&command, &profile, &config)?;

    let cat_cmd1 = format!("cat /var/makiatto/sites/{domain1}/index.html");
    let (content1, _) = util::execute_command(&container, &cat_cmd1).await?;
    assert_eq!(content1.trim(), "<h1>Site 1</h1>");

    let cat_cmd2 = format!("cat /var/makiatto/sites/{domain2}/index.html");
    let (content2, _) = util::execute_command(&container, &cat_cmd2).await?;
    assert_eq!(content2.trim(), "<h1>Site 2</h1>");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let dns_query = format!(
        "SELECT domain FROM dns_records WHERE domain IN ('{domain1}', '{domain2}') GROUP BY domain ORDER BY domain;"
    );
    let dns_result = util::query_database(&container, &dns_query).await?;
    assert!(dns_result.contains(domain1));
    assert!(dns_result.contains(domain2));

    Ok(())
}

#[tokio::test]
async fn test_nameserver_filtering() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let daemon1 = context.make_daemon().await?;
    let daemon2 = context.make_daemon().await?;

    let test_domain = "nameserver-test.example.com";
    let domain_path = context.target.join("sites").join(test_domain);

    tokio::fs::create_dir_all(&domain_path)
        .await
        .into_diagnostic()?;

    tokio::fs::write(domain_path.join("index.html"), b"<h1>NS Test</h1>")
        .await
        .into_diagnostic()?;

    let mut machine1 = daemon1.get_config();
    machine1.is_nameserver = true;

    let mut machine2 = daemon2.get_config();
    machine2.is_nameserver = false;

    let profile = Profile {
        machines: vec![machine1.clone(), machine2.clone()],
    };

    let config = Config {
        domains: vec![Domain {
            name: Arc::from(test_domain),
            path: domain_path.clone(),
            aliases: vec![].into(),
            records: vec![].into(),
        }]
        .into(),
    };

    let command = SyncCommand {
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    sync::sync_project(&command, &profile, &config)?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let ns_query = format!(
        "SELECT value FROM dns_records WHERE domain = '{test_domain}' AND record_type = 'NS';"
    );
    let container1 = daemon1.container.unwrap();
    let ns_result = util::query_database(&container1, &ns_query).await?;

    assert!(ns_result.contains(&format!("{}.ns.{}", machine1.name, test_domain)));
    assert!(!ns_result.contains(&format!("{}.ns.{}", machine2.name, test_domain)));

    Ok(())
}

#[tokio::test]
async fn test_update_changes() -> Result<()> {
    let mut context = ContainerContext::new()?;
    let daemon = context.make_daemon().await?;
    let machine = daemon.get_config();
    let container = daemon.container.unwrap();

    let test_domain = "update-sync.example.com";
    let domain_path = context.target.join("sites").join(test_domain);
    tokio::fs::create_dir_all(&domain_path)
        .await
        .into_diagnostic()?;

    tokio::fs::write(domain_path.join("index.html"), b"<h1>Original</h1>")
        .await
        .into_diagnostic()?;

    let profile = Profile {
        machines: vec![machine.clone()],
    };

    let config = Config {
        domains: vec![Domain {
            name: Arc::from(test_domain),
            path: domain_path.clone(),
            aliases: vec![].into(),
            records: vec![DnsRecord {
                name: Arc::from("old"),
                record_type: Arc::from("CNAME"),
                value: Arc::from("old.target.com"),
                ttl: 300,
                priority: None,
            }]
            .into(),
        }]
        .into(),
    };

    let command = SyncCommand {
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    sync::sync_project(&command, &profile, &config)?;

    let cat_cmd = format!("cat /var/makiatto/sites/{test_domain}/index.html");
    let (initial_content, _) = util::execute_command(&container, &cat_cmd).await?;
    assert_eq!(initial_content.trim(), "<h1>Original</h1>");

    tokio::fs::write(domain_path.join("index.html"), b"<h1>Updated</h1>")
        .await
        .into_diagnostic()?;

    let config = Config {
        domains: vec![Domain {
            name: Arc::from(test_domain),
            path: domain_path.clone(),
            aliases: vec![].into(),
            records: vec![DnsRecord {
                name: Arc::from("new"),
                record_type: Arc::from("CNAME"),
                value: Arc::from("new.target.com"),
                ttl: 300,
                priority: None,
            }]
            .into(),
        }]
        .into(),
    };

    let command = SyncCommand {
        key_path: Some(context.root.join("tests/fixtures/.ssh/id_ed25519")),
    };

    sync::sync_project(&command, &profile, &config)?;

    let (updated_content, _) = util::execute_command(&container, &cat_cmd).await?;
    assert_eq!(updated_content.trim(), "<h1>Updated</h1>");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let old_query = format!(
        "SELECT COUNT(*) FROM dns_records WHERE domain = '{test_domain}' AND name = 'old';"
    );
    let old_result = util::query_database(&container, &old_query).await?;
    assert_eq!(old_result.trim(), "0");

    let new_query = format!(
        "SELECT value FROM dns_records WHERE domain = '{test_domain}' AND name = 'new' AND record_type = 'CNAME';"
    );
    let new_result = util::query_database(&container, &new_query).await?;
    assert!(new_result.contains("new.target.com"));

    Ok(())
}
