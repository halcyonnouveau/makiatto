#![cfg(test)]
use std::{sync::Arc, time::Duration};

use miette::Result;
use testcontainers::{ContainerAsync, GenericImage};

use crate::container::{ContainerContext, TestContainer, util};

async fn get_cluster_leadership(
    daemon: &Arc<ContainerAsync<GenericImage>>,
) -> Result<Option<Vec<String>>> {
    let response = util::query_database(daemon, "SELECT role, node_name, term, last_heartbeat, expires_at FROM cluster_leadership WHERE role = 'director';").await?;

    if response.trim().is_empty() {
        return Ok(None);
    }

    let line = response.trim();
    if line.is_empty() {
        return Ok(None);
    }

    let fields: Vec<String> = line.split('|').map(String::from).collect();
    if fields.len() >= 5 {
        Ok(Some(fields))
    } else {
        Ok(None)
    }
}

async fn wait_for_leadership(
    daemon: &Arc<ContainerAsync<GenericImage>>,
    expected_node: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let start = std::time::Instant::now();

    while start.elapsed() < Duration::from_secs(timeout_secs) {
        if let Some(leadership) = get_cluster_leadership(daemon).await?
            && leadership.len() >= 2
            && leadership[1].contains(expected_node)
        {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(false)
}

#[tokio::test]
async fn test_single_node_becomes_leader() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        id,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    // Wait for daemon to start and claim leadership
    tokio::time::sleep(Duration::from_secs(3)).await;

    let became_leader = wait_for_leadership(&daemon, &id, 30).await?;
    assert!(became_leader, "Node should have become leader");

    let leadership = get_cluster_leadership(&daemon).await?;
    assert!(leadership.is_some(), "Leadership record should exist");

    let leadership = leadership.unwrap();
    assert_eq!(&leadership[0], "director");
    assert!(leadership[1].contains(&*id), "Leader should be our daemon");

    let term: i64 = leadership[2].parse().unwrap();
    assert!(term > 0, "Term should be positive");

    Ok(())
}

#[tokio::test]
async fn test_two_node_election() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon1_container,
        id: daemon1_id,
        ..
    } = context.make_daemon().await?;

    let daemon1 = daemon1_container.unwrap();

    // Wait for first daemon to claim leadership
    tokio::time::sleep(Duration::from_secs(3)).await;

    let became_leader1 = wait_for_leadership(&daemon1, &daemon1_id, 30).await?;
    assert!(became_leader1, "First node should have become leader");

    let TestContainer {
        container: daemon2_container,
        id: daemon2_id,
        ..
    } = context.make_daemon().await?;

    let daemon2 = daemon2_container.unwrap();

    // Wait for second daemon to join cluster
    tokio::time::sleep(Duration::from_secs(2)).await;

    let leadership1 = get_cluster_leadership(&daemon1).await?;
    let leadership2 = get_cluster_leadership(&daemon2).await?;

    assert!(
        leadership1.is_some() && leadership2.is_some(),
        "Both nodes should see leadership"
    );

    let leadership1_binding = leadership1.unwrap();
    let leader1_name = &leadership1_binding[1];
    let leadership2_binding = leadership2.unwrap();
    let leader2_name = &leadership2_binding[1];

    assert_eq!(
        leader1_name, leader2_name,
        "Both nodes should agree on leader"
    );

    assert!(
        leader1_name.contains(&*daemon1_id),
        "First daemon should be leader"
    );
    assert!(
        !leader1_name.contains(&*daemon2_id),
        "Second daemon should not be leader"
    );

    Ok(())
}

#[tokio::test]
async fn test_leader_heartbeat_updates() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon_container,
        id,
        ..
    } = context.make_daemon().await?;

    let daemon = daemon_container.unwrap();

    // Wait for daemon to start and claim leadership
    tokio::time::sleep(Duration::from_secs(3)).await;

    let became_leader = wait_for_leadership(&daemon, &id, 30).await?;
    assert!(became_leader, "Node should have become leader");

    let initial_leadership = get_cluster_leadership(&daemon).await?.unwrap();
    let initial_heartbeat: i64 = initial_leadership[3].parse().unwrap();

    // Wait for heartbeat interval to pass (2s heartbeat)
    tokio::time::sleep(Duration::from_secs(4)).await;

    let updated_leadership = get_cluster_leadership(&daemon).await?.unwrap();
    let updated_heartbeat: i64 = updated_leadership[3].parse().unwrap();

    assert!(
        updated_heartbeat > initial_heartbeat,
        "Heartbeat should have been updated"
    );

    Ok(())
}

#[tokio::test]
async fn test_leadership_expiration_and_takeover() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon1_container,
        id: daemon1_id,
        ..
    } = context.make_daemon().await?;

    let daemon1 = daemon1_container.unwrap();

    // Wait for first daemon to claim leadership
    tokio::time::sleep(Duration::from_secs(3)).await;

    let became_leader1 = wait_for_leadership(&daemon1, &daemon1_id, 30).await?;
    assert!(became_leader1, "First node should have become leader");

    let TestContainer {
        container: daemon2_container,
        id: daemon2_id,
        ..
    } = context.make_daemon().await?;

    let daemon2 = daemon2_container.unwrap();

    // Wait for second daemon to join cluster
    tokio::time::sleep(Duration::from_secs(2)).await;

    let leadership = get_cluster_leadership(&daemon2).await?.unwrap();
    let leader_name = &leadership[1];

    assert!(
        leader_name.contains(&*daemon1_id),
        "Daemon1 should still be leader"
    );

    let _ = daemon1.stop().await;

    // Give daemon1 time to stop + wait for lease expiration (6s) + detection time
    tokio::time::sleep(Duration::from_secs(8)).await;

    let became_leader2 = wait_for_leadership(&daemon2, &daemon2_id, 30).await?;
    assert!(
        became_leader2,
        "Second node should have taken over leadership after first failed"
    );

    Ok(())
}

#[tokio::test]
async fn test_term_numbers_increase() -> Result<()> {
    let mut context = ContainerContext::new()?;

    let TestContainer {
        container: daemon1_container,
        id: daemon1_id,
        ..
    } = context.make_daemon().await?;

    let daemon1 = daemon1_container.unwrap();

    // Wait for first daemon to claim leadership
    tokio::time::sleep(Duration::from_secs(3)).await;

    let became_leader1 = wait_for_leadership(&daemon1, &daemon1_id, 30).await?;
    assert!(became_leader1, "First node should have become leader");

    let initial_leadership = get_cluster_leadership(&daemon1).await?.unwrap();
    let initial_term: i64 = initial_leadership[2].parse().unwrap();

    let TestContainer {
        container: daemon2_container,
        id: daemon2_id,
        ..
    } = context.make_daemon().await?;

    let daemon2 = daemon2_container.unwrap();

    // Wait for second daemon to join cluster
    tokio::time::sleep(Duration::from_secs(2)).await;

    let _ = daemon1.stop().await;

    // Wait for lease expiration (6s) + detection time + failover
    tokio::time::sleep(Duration::from_secs(8)).await;

    let became_leader2 = wait_for_leadership(&daemon2, &daemon2_id, 30).await?;
    assert!(became_leader2, "Second node should have taken over");

    let new_leadership = get_cluster_leadership(&daemon2).await?.unwrap();
    let new_term: i64 = new_leadership[2].parse().unwrap();

    assert!(
        new_term > initial_term,
        "Term should have increased after takeover"
    );

    Ok(())
}
