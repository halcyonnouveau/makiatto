use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use miette::Result;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};
use tripwire::Tripwire;

use crate::config::Config;
use crate::corrosion::{self, schema::ClusterLeadership};

const DIRECTOR_ROLE: &str = "director";

#[derive(Debug, Clone)]
pub struct DirectorElection {
    config: Arc<Config>,
    node_name: Arc<str>,
    state: Arc<RwLock<LeadershipState>>,
}

#[derive(Debug, Clone)]
struct LeadershipState {
    is_leader: bool,
    current_leader: Option<Arc<str>>,
    current_term: i64,
}

impl DirectorElection {
    #[must_use]
    pub fn new(config: Arc<Config>) -> Self {
        let node_name = config.node.name.clone();

        Self {
            config,
            node_name,
            state: Arc::new(RwLock::new(LeadershipState {
                is_leader: false,
                current_leader: None,
                current_term: 0,
            })),
        }
    }

    /// Start the election loop
    pub async fn run(&self, mut tripwire: Tripwire) {
        let heartbeat_interval = self.config.consensus.heartbeat_interval;

        let mut interval = interval(Duration::from_secs(heartbeat_interval));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            "Starting director election for node '{}' with {heartbeat_interval}s heartbeat interval",
            self.node_name,
        );

        loop {
            tokio::select! {
                () = &mut tripwire => {
                    info!("Director election shutting down");
                    if self.is_leader().await
                        && let Err(e) = self.step_down().await {
                            error!("Failed to step down as leader: {e}");
                        }
                    break;
                }
                _ = interval.tick() => {
                    debug!("Running election tick for node '{}'", self.node_name);
                    if let Err(e) = self.election_tick().await {
                        error!("Election tick failed: {e}");
                    }
                }
            }
        }
    }

    /// Perform one election tick - check leadership and update heartbeat
    async fn election_tick(&self) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| miette::miette!("Failed to get current time: {e}"))?
            .as_secs() as i64;

        let lease_duration = self.config.consensus.lease_duration as i64;
        let leadership = self.get_current_leadership().await?;

        if let Some(leader) = leadership {
            if leader.node_name == self.node_name {
                if leader.term == self.state.read().await.current_term {
                    // we are the leader, update heartbeat
                    self.update_heartbeat(current_time, lease_duration).await?;
                } else {
                    // term mismatch - try to reclaim
                    match self
                        .try_claim_leadership(current_time, lease_duration, leader.term + 1)
                        .await
                    {
                        Ok(()) => info!("Successfully attempted leadership claim"),
                        Err(e) => error!("Failed to claim leadership: {e}"),
                    }
                }
            } else if leader.expires_at < current_time {
                // leader expired, try to claim leadership
                info!(
                    "Current leader '{}' expired (expires_at: {}, current_time: {}), attempting to claim leadership",
                    leader.node_name, leader.expires_at, current_time
                );
                match self
                    .try_claim_leadership(current_time, lease_duration, leader.term + 1)
                    .await
                {
                    Ok(()) => info!("Successfully attempted leadership claim"),
                    Err(e) => error!("Failed to claim leadership: {e}"),
                }
            } else {
                // someone else is leader
                let mut state = self.state.write().await;
                state.is_leader = false;
                state.current_leader = Some(leader.node_name.clone());
                state.current_term = leader.term;
                debug!(
                    "Current leader is '{}' (term {}), expires_at: {}, current_time: {}",
                    leader.node_name, leader.term, leader.expires_at, current_time
                );
            }
        } else {
            // no leader exists, try to claim
            info!("No current leader, attempting to claim leadership");
            match self
                .try_claim_leadership(current_time, lease_duration, 1)
                .await
            {
                Ok(()) => info!("Successfully attempted initial leadership claim"),
                Err(e) => error!("Failed to claim initial leadership: {e}"),
            }
        }

        Ok(())
    }

    /// Try to claim leadership
    async fn try_claim_leadership(
        &self,
        current_time: i64,
        lease_duration: i64,
        new_term: i64,
    ) -> Result<()> {
        let expires_at = current_time + lease_duration;

        let sql = format!(
            r"
            INSERT INTO cluster_leadership (role, node_name, term, last_heartbeat, expires_at)
            VALUES ('{}', '{}', {}, {}, {})
            ON CONFLICT(role) DO UPDATE SET
                node_name = '{}',
                term = {},
                last_heartbeat = {},
                expires_at = {}
            WHERE term < {} OR expires_at < {}
            ",
            DIRECTOR_ROLE,
            self.node_name,
            new_term,
            current_time,
            expires_at,
            self.node_name,
            new_term,
            current_time,
            expires_at,
            new_term,
            current_time,
        );

        corrosion::execute_transactions(&[sql]).await?;

        let leadership = self.get_current_leadership().await?;

        if let Some(leader) = leadership {
            if leader.node_name == self.node_name && leader.term == new_term {
                let mut state = self.state.write().await;
                state.is_leader = true;
                state.current_leader = Some(self.node_name.clone());
                state.current_term = new_term;
                info!("Successfully claimed leadership (term {new_term})");
            } else {
                let mut state = self.state.write().await;
                state.is_leader = false;
                state.current_leader = Some(leader.node_name.clone());
                state.current_term = leader.term;
                debug!(
                    "Failed to claim leadership, current leader is '{}' (term {})",
                    leader.node_name, leader.term
                );
            }
        }

        Ok(())
    }

    /// Update heartbeat for current leader
    async fn update_heartbeat(&self, current_time: i64, lease_duration: i64) -> Result<()> {
        let expires_at = current_time + lease_duration;
        let state = self.state.read().await;
        let current_term = state.current_term;
        drop(state);

        let sql = format!(
            r"
            UPDATE cluster_leadership
            SET last_heartbeat = {}, expires_at = {}
            WHERE role = '{}' AND node_name = '{}' AND term = {}
            ",
            current_time, expires_at, DIRECTOR_ROLE, self.node_name, current_term
        );

        match corrosion::execute_transactions(&[sql]).await {
            Ok(()) => {
                debug!("Updated leadership heartbeat");
            }
            Err(e) => {
                warn!("Failed to update heartbeat: {e}");
            }
        }

        // check if we're still leader
        let leadership = self.get_current_leadership().await?;

        if let Some(leader) = leadership
            && (leader.node_name != self.node_name || leader.term != current_term)
        {
            let mut state = self.state.write().await;
            state.is_leader = false;
            state.current_leader = Some(leader.node_name.clone());
            state.current_term = leader.term;
            warn!(
                "Lost leadership to '{}' (term {})",
                leader.node_name, leader.term
            );
        }

        Ok(())
    }

    /// Get current leadership from database
    async fn get_current_leadership(&self) -> Result<Option<ClusterLeadership>> {
        let pool = corrosion::get_pool().await?;

        let row = sqlx::query!(
            "SELECT role, node_name, term, last_heartbeat, expires_at FROM cluster_leadership WHERE role = ?1",
            DIRECTOR_ROLE
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| miette::miette!("Failed to query leadership: {e}"))?;

        match row {
            Some(row) => Ok(Some(ClusterLeadership {
                role: row.role.into(),
                node_name: row.node_name.into(),
                term: row.term,
                last_heartbeat: row.last_heartbeat,
                expires_at: row.expires_at,
            })),
            None => Ok(None),
        }
    }

    /// Step down from leadership
    async fn step_down(&self) -> Result<()> {
        let state = self.state.read().await;
        if !state.is_leader {
            return Ok(());
        }
        let current_term = state.current_term;
        drop(state);

        let sql = format!(
            r"
            DELETE FROM cluster_leadership
            WHERE role = '{}' AND node_name = '{}' AND term = {}
            ",
            DIRECTOR_ROLE, self.node_name, current_term
        );

        if corrosion::execute_transactions(&[sql]).await.is_ok() {
            let mut state = self.state.write().await;
            state.is_leader = false;
            info!("Stepped down from leadership");
        }

        Ok(())
    }

    /// Check if this node is currently the leader
    pub async fn is_leader(&self) -> bool {
        self.state.read().await.is_leader
    }

    /// Get the current leader node ID
    pub async fn get_current_leader(&self) -> Option<Arc<str>> {
        self.state.read().await.current_leader.clone()
    }
}
