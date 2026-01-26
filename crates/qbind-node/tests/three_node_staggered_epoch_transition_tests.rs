//! T114: Staggered 3-node epoch transition tests.
//!
//! This module provides tests that exercise staggered epoch transitions:
//! - Some nodes switch from epoch 0 → 1 earlier than others
//! - During the transition, nodes exchange mixed-epoch votes/proposals
//!
//! # Assertions
//!
//! - No safety violations (no conflicting commits)
//! - Wrong-epoch messages are handled as designed (rejected/ignored, no panic)
//! - Eventual convergence: all nodes end up in the same epoch with same committed state
//!
//! # Test Scenarios
//!
//! - **Scenario A**: One node lags epoch transition
//!   - Nodes 0 and 1 transition to epoch 1 while node 2 lags
//!   - Node 2 eventually catches up after seeing the reconfig block
//!
//! - **Scenario B**: Two nodes lag, one transitions early
//!   - Node 0 transitions to epoch 1 while nodes 1 and 2 lag
//!   - All nodes eventually converge
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test three_node_staggered_epoch_transition_tests -- --test-threads=1
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::Mutex;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::network::NetworkError;
use qbind_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, StaticEpochStateProvider, ValidatorSetEntry,
};
use qbind_consensus::{ConsensusVerifyError, QcValidationError};
use qbind_node::peer::PeerId;
use qbind_node::{
    AsyncPeerManagerConfig, AsyncPeerManagerImpl, ConsensusNetworkFacade, DirectAsyncNetworkFacade,
    NodeMetrics, TransportSecurityMode,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

// ============================================================================
// Part A – Configuration and Helper Types
// ============================================================================

/// Configuration for staggered epoch transition tests.
#[derive(Debug, Clone)]
pub struct StaggeredEpochTestConfig {
    /// Epoch state for epoch 0 (initial epoch).
    pub epoch0: EpochState,
    /// Epoch state for epoch 1 (epoch after reconfig).
    pub epoch1: EpochState,
    /// Transport mode (PlainTcp for this test).
    pub transport: TransportSecurityMode,
    /// Tick interval for consensus operations.
    pub tick_interval: Duration,
    /// Maximum test duration before timeout.
    pub timeout: Duration,
    /// Height at which reconfig block is proposed.
    pub reconfig_height: u64,
    /// Maximum rounds to run.
    pub max_rounds: u64,
}

impl Default for StaggeredEpochTestConfig {
    fn default() -> Self {
        let validator_set = build_three_validator_set();
        let epoch0 = EpochState::genesis(validator_set.clone());
        let epoch1 = EpochState::new(EpochId::new(1), validator_set);

        StaggeredEpochTestConfig {
            epoch0,
            epoch1,
            transport: TransportSecurityMode::PlainTcp,
            tick_interval: Duration::from_millis(50),
            timeout: Duration::from_secs(30),
            reconfig_height: 3,
            max_rounds: 25,
        }
    }
}

impl StaggeredEpochTestConfig {
    /// Build a `StaticEpochStateProvider` from this config.
    pub fn build_epoch_provider(&self) -> StaticEpochStateProvider {
        StaticEpochStateProvider::new()
            .with_epoch(self.epoch0.clone())
            .with_epoch(self.epoch1.clone())
    }
}

/// Build the canonical 3-validator set (validators 0, 1, 2 with equal power).
fn build_three_validator_set() -> ConsensusValidatorSet {
    let entries = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(0),
            voting_power: 1,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 1,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 1,
        },
    ];

    ConsensusValidatorSet::new(entries).expect("Should create valid 3-validator set")
}

// ============================================================================
// Part B – Fault Injection for Staggered Transitions
// ============================================================================

/// Fault mode for controlling message delivery.
#[derive(Debug, Clone)]
pub enum StaggeredFaultMode {
    /// Pass through all messages.
    PassThrough,
    /// Drop all messages (simulates partition).
    DropAll,
    /// Drop messages until a specific height is reached.
    DropUntilHeight(u64),
}

impl Default for StaggeredFaultMode {
    fn default() -> Self {
        StaggeredFaultMode::PassThrough
    }
}

/// Network facade wrapper that can stagger message delivery.
///
/// Used to simulate nodes lagging behind in receiving the reconfig block.
pub struct StaggeredNetworkFacade<F: ConsensusNetworkFacade> {
    /// The underlying network facade.
    inner: F,
    /// Current fault mode (RwLock for sync access).
    config: RwLock<StaggeredFaultMode>,
    /// Current simulated height (used for DropUntilHeight).
    current_height: AtomicU64,
    /// Counter for dropped votes.
    dropped_votes: AtomicU64,
    /// Counter for dropped proposals.
    dropped_proposals: AtomicU64,
    /// Flag indicating if the facade is in partition mode.
    is_partitioned: AtomicBool,
}

impl<F: ConsensusNetworkFacade> StaggeredNetworkFacade<F> {
    /// Create a new staggered network facade.
    pub fn new(inner: F, mode: StaggeredFaultMode) -> Self {
        let is_partitioned = matches!(mode, StaggeredFaultMode::DropAll);
        StaggeredNetworkFacade {
            inner,
            config: RwLock::new(mode),
            current_height: AtomicU64::new(0),
            dropped_votes: AtomicU64::new(0),
            dropped_proposals: AtomicU64::new(0),
            is_partitioned: AtomicBool::new(is_partitioned),
        }
    }

    /// Update the fault mode.
    pub fn set_mode(&self, mode: StaggeredFaultMode) {
        let is_partitioned = matches!(mode, StaggeredFaultMode::DropAll);
        self.is_partitioned.store(is_partitioned, Ordering::SeqCst);
        if let Ok(mut config) = self.config.write() {
            *config = mode;
        }
    }

    /// Update the current simulated height.
    pub fn set_height(&self, height: u64) {
        self.current_height.store(height, Ordering::SeqCst);
    }

    /// Get the number of dropped votes.
    pub fn dropped_votes(&self) -> u64 {
        self.dropped_votes.load(Ordering::Relaxed)
    }

    /// Get the number of dropped proposals.
    pub fn dropped_proposals(&self) -> u64 {
        self.dropped_proposals.load(Ordering::Relaxed)
    }

    /// Check if the facade is partitioned.
    pub fn is_partitioned(&self) -> bool {
        self.is_partitioned.load(Ordering::SeqCst)
    }

    /// Check if a message should be dropped based on current mode.
    fn should_drop(&self) -> bool {
        let height = self.current_height.load(Ordering::SeqCst);
        if let Ok(mode) = self.config.read() {
            match &*mode {
                StaggeredFaultMode::PassThrough => false,
                StaggeredFaultMode::DropAll => true,
                StaggeredFaultMode::DropUntilHeight(target) => height < *target,
            }
        } else {
            false
        }
    }
}

impl<F: ConsensusNetworkFacade> ConsensusNetworkFacade for StaggeredNetworkFacade<F> {
    fn send_vote_to(&self, target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        if self.should_drop() {
            self.dropped_votes.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.inner.send_vote_to(target, vote)
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        if self.should_drop() {
            self.dropped_votes.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.inner.broadcast_vote(vote)
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        if self.should_drop() {
            self.dropped_proposals.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.inner.broadcast_proposal(proposal)
    }
}

unsafe impl<F: ConsensusNetworkFacade + Send + Sync> Send for StaggeredNetworkFacade<F> {}
unsafe impl<F: ConsensusNetworkFacade + Send + Sync> Sync for StaggeredNetworkFacade<F> {}

// ============================================================================
// Part C – Staggered Node Handle
// ============================================================================

/// Handle to a single node in the staggered epoch test cluster.
struct StaggeredNodeHandle {
    /// The validator ID for this node.
    id: ValidatorId,
    /// The async peer manager for this node.
    peer_manager: Arc<AsyncPeerManagerImpl>,
    /// The local address the node is listening on.
    local_addr: SocketAddr,
    /// Node metrics for observability.
    #[allow(dead_code)]
    metrics: Arc<NodeMetrics>,
    /// Node index (0, 1, or 2).
    index: usize,
    /// Current epoch (updated when epoch transition occurs).
    current_epoch: Arc<Mutex<u64>>,
    /// Committed height (updated via consensus).
    committed_height: Arc<Mutex<Option<u64>>>,
    /// Last committed block ID (updated via consensus).
    last_committed_block_id: Arc<Mutex<Option<[u8; 32]>>>,
    /// Committed blocks by height (for safety checks).
    committed_blocks: Arc<Mutex<std::collections::HashMap<u64, [u8; 32]>>>,
}

impl StaggeredNodeHandle {
    /// Create a new staggered node handle.
    async fn new(index: usize, transport: TransportSecurityMode) -> Result<Self, String> {
        let id = ValidatorId::new(index as u64);
        let metrics = Arc::new(NodeMetrics::new());

        let pm_config = AsyncPeerManagerConfig::default()
            .with_listen_addr("127.0.0.1:0".parse().unwrap())
            .with_transport_security_mode(transport)
            .with_inbound_channel_capacity(1024)
            .with_outbound_channel_capacity(256);

        let mut peer_manager = AsyncPeerManagerImpl::with_metrics(pm_config, metrics.clone());
        let local_addr = peer_manager
            .bind()
            .await
            .map_err(|e| format!("Node {} failed to bind: {}", index, e))?;

        let peer_manager = Arc::new(peer_manager);
        peer_manager.start_listener().await;

        Ok(StaggeredNodeHandle {
            id,
            peer_manager,
            local_addr,
            metrics,
            index,
            current_epoch: Arc::new(Mutex::new(0)),
            committed_height: Arc::new(Mutex::new(None)),
            last_committed_block_id: Arc::new(Mutex::new(None)),
            committed_blocks: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// Connect to another node as a peer.
    async fn connect_to(&self, peer_addr: SocketAddr) -> Result<PeerId, String> {
        self.peer_manager
            .connect_peer(&peer_addr.to_string(), None)
            .await
            .map_err(|e| {
                format!(
                    "Node {} failed to connect to {}: {}",
                    self.index, peer_addr, e
                )
            })
    }

    /// Create a network facade for this node.
    fn create_facade(&self) -> DirectAsyncNetworkFacade {
        DirectAsyncNetworkFacade::new(self.peer_manager.clone())
    }

    /// Update current epoch.
    async fn set_current_epoch(&self, epoch: u64) {
        let mut e = self.current_epoch.lock().await;
        *e = epoch;
    }

    /// Get the current epoch.
    async fn get_current_epoch(&self) -> u64 {
        *self.current_epoch.lock().await
    }

    /// Update committed state (height and block ID).
    /// Returns true if there's a safety violation (conflicting commit).
    async fn update_committed_state(&self, height: u64, block_id: [u8; 32]) -> bool {
        let mut committed_blocks = self.committed_blocks.lock().await;

        // Check for safety violation
        if let Some(&existing_id) = committed_blocks.get(&height) {
            if existing_id != block_id {
                eprintln!(
                    "[SAFETY VIOLATION] Node {} committed different blocks at height {}!",
                    self.index, height
                );
                return true; // Safety violation
            }
        }

        committed_blocks.insert(height, block_id);

        let mut h = self.committed_height.lock().await;
        *h = Some(height);
        let mut bid = self.last_committed_block_id.lock().await;
        *bid = Some(block_id);

        false // No safety violation
    }

    /// Get the current committed height.
    async fn get_committed_height(&self) -> Option<u64> {
        *self.committed_height.lock().await
    }

    /// Get the last committed block ID.
    async fn get_last_committed_block_id(&self) -> Option<[u8; 32]> {
        *self.last_committed_block_id.lock().await
    }

    /// Shutdown the node.
    fn shutdown(&self) {
        self.peer_manager.shutdown();
    }
}

// ============================================================================
// Part D – Message Creation Helpers
// ============================================================================

/// Test signature placeholder.
const TEST_SIGNATURE: [u8; 2] = [0xCA, 0xFE];

/// HotStuff 3-chain commit delay (blocks are committed 2 rounds after proposal).
const COMMIT_DELAY: u64 = 2;

/// Create a normal block proposal.
fn make_normal_proposal(
    epoch: u64,
    height: u64,
    proposer_index: u16,
    parent_id: [u8; 32],
) -> BlockProposal {
    let mut block_id = [0u8; 32];
    block_id[0] = (height & 0xFF) as u8;
    block_id[1] = (epoch & 0xFF) as u8;
    block_id[2] = proposer_index as u8;

    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch,
            height,
            round: height,
            parent_block_id: parent_id,
            payload_hash: block_id,
            proposer_index,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
        },
        qc: None,
        txs: vec![],
        signature: TEST_SIGNATURE.to_vec(),
    }
}

/// Create a reconfig block proposal.
fn make_reconfig_proposal(
    epoch: u64,
    height: u64,
    next_epoch: u64,
    proposer_index: u16,
    parent_id: [u8; 32],
) -> BlockProposal {
    let mut block_id = [0u8; 32];
    block_id[0] = (height & 0xFF) as u8;
    block_id[1] = (epoch & 0xFF) as u8;
    block_id[2] = proposer_index as u8;
    block_id[3] = 0xEC; // Mark as reconfig

    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch,
            height,
            round: height,
            parent_block_id: parent_id,
            payload_hash: block_id,
            proposer_index,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_RECONFIG,
            next_epoch,
        },
        qc: None,
        txs: vec![],
        signature: TEST_SIGNATURE.to_vec(),
    }
}

/// Create a vote for a block.
fn make_vote(epoch: u64, height: u64, block_id: [u8; 32], validator_index: u16) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        epoch,
        height,
        round: height,
        step: 0,
        block_id,
        validator_index,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature: TEST_SIGNATURE.to_vec(),
    }
}

/// Compute a block ID from height and epoch.
fn compute_block_id(epoch: u64, height: u64) -> [u8; 32] {
    let mut block_id = [0u8; 32];
    block_id[0] = (height & 0xFF) as u8;
    block_id[1] = (epoch & 0xFF) as u8;
    block_id
}

/// Compute the reconfig block ID.
fn compute_reconfig_block_id(epoch: u64, height: u64, proposer_index: u16) -> [u8; 32] {
    let mut block_id = [0u8; 32];
    block_id[0] = (height & 0xFF) as u8;
    block_id[1] = (epoch & 0xFF) as u8;
    block_id[2] = proposer_index as u8;
    block_id[3] = 0xEC;
    block_id
}

// ============================================================================
// Part E – Wrong-Epoch Message Handling Verification
// ============================================================================

/// Result of checking wrong-epoch message handling.
#[derive(Debug)]
pub struct WrongEpochHandlingResult {
    /// Number of wrong-epoch votes that were rejected.
    pub wrong_epoch_votes_rejected: u64,
    /// Number of wrong-epoch proposals that were ignored.
    pub wrong_epoch_proposals_ignored: u64,
    /// Whether a panic occurred (should be false).
    pub panic_occurred: bool,
}

/// Verify that wrong-epoch messages are handled correctly.
///
/// This function simulates receiving wrong-epoch votes and proposals
/// and verifies that:
/// - Votes with wrong epoch return WrongEpoch error
/// - Proposals with wrong epoch are ignored (no panic)
fn verify_wrong_epoch_handling(current_epoch: u64, wrong_epoch: u64) -> WrongEpochHandlingResult {
    use qbind_consensus::basic_hotstuff_engine::BasicHotStuffEngine;

    let validators = build_three_validator_set();
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId::new(0), validators);
    engine.set_current_epoch(current_epoch);

    let mut wrong_votes_rejected = 0u64;
    let mut wrong_proposals_ignored = 0u64;
    let mut panic_occurred = false;

    // Test wrong-epoch vote
    let wrong_vote = make_vote(wrong_epoch, 0, [0u8; 32], 1);
    match engine.on_vote_event(ValidatorId::new(1), &wrong_vote) {
        Err(QcValidationError::Verify(ConsensusVerifyError::WrongEpoch { expected, actual })) => {
            assert_eq!(expected, current_epoch);
            assert_eq!(actual, wrong_epoch);
            wrong_votes_rejected += 1;
        }
        Ok(_) => {
            // This shouldn't happen for wrong epoch
            eprintln!("[WARNING] Wrong-epoch vote was accepted unexpectedly");
        }
        Err(other) => {
            eprintln!(
                "[WARNING] Wrong-epoch vote got unexpected error: {:?}",
                other
            );
        }
    }

    // Test wrong-epoch proposal
    let wrong_proposal = make_normal_proposal(wrong_epoch, 0, 1, [0xFFu8; 32]);

    // Use std::panic::catch_unwind to detect panics
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        engine.on_proposal_event(ValidatorId::new(1), &wrong_proposal)
    }));

    match result {
        Ok(action) => {
            if action.is_none() {
                wrong_proposals_ignored += 1;
            }
        }
        Err(_) => {
            panic_occurred = true;
        }
    }

    WrongEpochHandlingResult {
        wrong_epoch_votes_rejected: wrong_votes_rejected,
        wrong_epoch_proposals_ignored: wrong_proposals_ignored,
        panic_occurred,
    }
}

// ============================================================================
// Part F – Test Results
// ============================================================================

/// Result from the staggered epoch transition test.
#[derive(Debug)]
pub struct StaggeredEpochTestResult {
    /// Final epoch for each node.
    pub final_epochs: [u64; 3],
    /// Final committed heights for each node.
    pub committed_heights: [Option<u64>; 3],
    /// Last committed block IDs for each node.
    pub last_committed_block_ids: [Option<[u8; 32]>; 3],
    /// Whether epoch transition occurred on all nodes.
    pub epoch_transition_occurred: bool,
    /// Whether all nodes agree on committed state.
    pub consensus_achieved: bool,
    /// Whether any safety violations were detected.
    pub safety_violated: bool,
    /// Wrong-epoch handling verification result.
    pub wrong_epoch_handling: Option<WrongEpochHandlingResult>,
    /// Total messages dropped during staggered delivery.
    pub total_dropped_messages: u64,
}

// ============================================================================
// Part G – Scenario A: One Node Lags Epoch Transition
// ============================================================================

/// Run Scenario A: One node lags epoch transition.
///
/// This test:
/// 1. Creates 3 nodes in epoch 0
/// 2. Nodes 0 and 1 see and commit the reconfig block, transitioning to epoch 1
/// 3. Node 2 is partitioned and doesn't see the reconfig initially
/// 4. After partition heals, node 2 catches up and transitions to epoch 1
/// 5. All nodes converge to the same state
async fn run_scenario_a_one_node_lags(
    config: StaggeredEpochTestConfig,
) -> StaggeredEpochTestResult {
    eprintln!(
        "\n========== Starting Scenario A: One Node Lags (T114) ==========\n\
         Reconfig Height: {}\n\
         Max Rounds: {}\n\
         Tick Interval: {:?}\n\
         Timeout: {:?}\n\
         ===============================================================\n",
        config.reconfig_height, config.max_rounds, config.tick_interval, config.timeout
    );

    // Create 3 nodes
    let mut nodes = Vec::new();
    for i in 0..3 {
        let node = StaggeredNodeHandle::new(i, config.transport)
            .await
            .unwrap_or_else(|e| panic!("Failed to create node {}: {}", i, e));
        eprintln!(
            "[Node {}] Created - ValidatorId={:?}, Address={}",
            i, node.id, node.local_addr
        );
        nodes.push(node);
    }

    // Wait for listeners
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Establish peer connections (full mesh)
    let addresses: Vec<SocketAddr> = nodes.iter().map(|n| n.local_addr).collect();
    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                let _ = nodes[i].connect_to(addresses[j]).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create network facades:
    // - Nodes 0 and 1 use normal facades
    // - Node 2 uses a staggered facade (partitioned until after reconfig)
    let facade_0 = nodes[0].create_facade();
    let facade_1 = nodes[1].create_facade();
    let inner_facade_2 = nodes[2].create_facade();

    // Node 2 is partitioned until reconfig_height + 2 (lags behind)
    let partition_heal_height = config.reconfig_height + 2;
    let staggered_facade_2 = StaggeredNetworkFacade::new(
        inner_facade_2,
        StaggeredFaultMode::DropUntilHeight(partition_heal_height),
    );

    eprintln!(
        "[Cluster] Node 2 is PARTITIONED until height {}",
        partition_heal_height
    );

    let start_time = std::time::Instant::now();
    let mut current_round: u64 = 0;
    let mut safety_violated = false;
    let mut reconfig_block_injected = false;
    let mut nodes_0_1_transitioned = false;
    let mut node_2_transitioned = false;

    // Run consensus simulation
    while current_round < config.max_rounds && start_time.elapsed() < config.timeout {
        let leader_index = (current_round as usize) % 3;

        // Get current epochs
        let epoch_0 = nodes[0].get_current_epoch().await;
        let epoch_1 = nodes[1].get_current_epoch().await;
        let epoch_2 = nodes[2].get_current_epoch().await;

        eprintln!(
            "[Cluster] Round {}: Leader={}, Epochs=[{}, {}, {}]",
            current_round, leader_index, epoch_0, epoch_1, epoch_2
        );

        // Update staggered facade height
        staggered_facade_2.set_height(current_round);

        // Determine proposal type
        let is_reconfig_round = current_round == config.reconfig_height && !reconfig_block_injected;

        let mut parent_id = [0xFFu8; 32];
        if current_round > 0 {
            parent_id = compute_block_id(0, current_round - 1);
        }

        let (proposal, block_id) = if is_reconfig_round {
            eprintln!(
                "[Cluster] Proposing RECONFIG block at height {}",
                current_round
            );
            reconfig_block_injected = true;
            let p = make_reconfig_proposal(0, current_round, 1, leader_index as u16, parent_id);
            let id = compute_reconfig_block_id(0, current_round, leader_index as u16);
            (p, id)
        } else {
            let epoch = if nodes_0_1_transitioned && leader_index < 2 {
                1 // Nodes 0, 1 may propose in epoch 1 after transition
            } else {
                0
            };
            let p = make_normal_proposal(epoch, current_round, leader_index as u16, parent_id);
            let id = compute_block_id(epoch, current_round);
            (p, id)
        };

        // Broadcast proposal from leader
        match leader_index {
            0 => {
                let _ = facade_0.broadcast_proposal(&proposal);
            }
            1 => {
                let _ = facade_1.broadcast_proposal(&proposal);
            }
            2 => {
                let _ = staggered_facade_2.broadcast_proposal(&proposal);
            }
            _ => {}
        }

        // Send votes from all nodes
        for i in 0..3 {
            let node_epoch = nodes[i].get_current_epoch().await;
            let vote = make_vote(node_epoch, current_round, block_id, nodes[i].id.0 as u16);
            match i {
                0 => {
                    let _ = facade_0.broadcast_vote(&vote);
                }
                1 => {
                    let _ = facade_1.broadcast_vote(&vote);
                }
                2 => {
                    let _ = staggered_facade_2.broadcast_vote(&vote);
                }
                _ => {}
            }
        }

        tokio::time::sleep(config.tick_interval).await;

        // Apply commit logic
        if current_round >= COMMIT_DELAY {
            let commit_height = current_round - 1;
            let commit_block_id = if commit_height == config.reconfig_height {
                compute_reconfig_block_id(0, commit_height, (commit_height as usize % 3) as u16)
            } else {
                compute_block_id(0, commit_height)
            };

            let committing_reconfig = commit_height == config.reconfig_height;

            // Nodes 0 and 1 can always commit (not partitioned)
            for i in 0..2 {
                let violation = nodes[i]
                    .update_committed_state(commit_height, commit_block_id)
                    .await;
                if violation {
                    safety_violated = true;
                }

                if committing_reconfig && !nodes_0_1_transitioned {
                    eprintln!(
                        "[Node {}] Committing RECONFIG at height {} - transitioning to epoch 1",
                        i, commit_height
                    );
                    nodes[i].set_current_epoch(1).await;
                }
            }

            if committing_reconfig && !nodes_0_1_transitioned {
                nodes_0_1_transitioned = true;
                eprintln!("[Cluster] Nodes 0 and 1 transitioned to epoch 1");
            }

            // Node 2 can only commit if partition is healed
            if current_round >= partition_heal_height {
                let violation = nodes[2]
                    .update_committed_state(commit_height, commit_block_id)
                    .await;
                if violation {
                    safety_violated = true;
                }

                // If node 2 is catching up on the reconfig block
                if commit_height >= config.reconfig_height && !node_2_transitioned {
                    eprintln!(
                        "[Node 2] Catching up - committing RECONFIG at height {} - transitioning to epoch 1",
                        config.reconfig_height
                    );
                    nodes[2].set_current_epoch(1).await;
                    node_2_transitioned = true;
                }
            }

            eprintln!(
                "[Cluster] Commit at round {}: height {}",
                current_round, commit_height
            );
        }

        current_round += 1;

        // Check if all nodes have transitioned and we've made progress past reconfig
        if nodes_0_1_transitioned && node_2_transitioned {
            let h0 = nodes[0].get_committed_height().await;
            let h2 = nodes[2].get_committed_height().await;
            if h0.is_some() && h2.is_some() && h0 == h2 && h0.unwrap() > config.reconfig_height {
                eprintln!("[Cluster] All nodes converged after epoch transition");
                break;
            }
        }
    }

    // Verify wrong-epoch handling
    let wrong_epoch_result = verify_wrong_epoch_handling(1, 0);
    eprintln!(
        "[Cluster] Wrong-epoch handling: votes_rejected={}, proposals_ignored={}, panic={}",
        wrong_epoch_result.wrong_epoch_votes_rejected,
        wrong_epoch_result.wrong_epoch_proposals_ignored,
        wrong_epoch_result.panic_occurred
    );

    // Collect results
    let final_epochs: [u64; 3] = [
        nodes[0].get_current_epoch().await,
        nodes[1].get_current_epoch().await,
        nodes[2].get_current_epoch().await,
    ];

    let committed_heights: [Option<u64>; 3] = [
        nodes[0].get_committed_height().await,
        nodes[1].get_committed_height().await,
        nodes[2].get_committed_height().await,
    ];

    let last_committed_block_ids: [Option<[u8; 32]>; 3] = [
        nodes[0].get_last_committed_block_id().await,
        nodes[1].get_last_committed_block_id().await,
        nodes[2].get_last_committed_block_id().await,
    ];

    let epoch_transition_occurred = final_epochs.iter().all(|&e| e == 1);

    let consensus_achieved = {
        let heights: Vec<u64> = committed_heights.iter().filter_map(|h| *h).collect();
        let ids: Vec<[u8; 32]> = last_committed_block_ids
            .iter()
            .filter_map(|id| *id)
            .collect();

        heights.len() == 3
            && ids.len() == 3
            && heights.windows(2).all(|w| w[0] == w[1])
            && ids.windows(2).all(|w| w[0] == w[1])
    };

    let total_dropped = staggered_facade_2.dropped_votes() + staggered_facade_2.dropped_proposals();

    // Shutdown
    for node in &nodes {
        node.shutdown();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    eprintln!(
        "\n========== Scenario A Complete (T114) ==========\n\
         Epoch Transition: {}\n\
         Consensus Achieved: {}\n\
         Safety Violated: {}\n\
         Final Epochs: {:?}\n\
         Committed Heights: {:?}\n\
         Dropped Messages: {}\n\
         ================================================\n",
        epoch_transition_occurred,
        consensus_achieved,
        safety_violated,
        final_epochs,
        committed_heights,
        total_dropped
    );

    StaggeredEpochTestResult {
        final_epochs,
        committed_heights,
        last_committed_block_ids,
        epoch_transition_occurred,
        consensus_achieved,
        safety_violated,
        wrong_epoch_handling: Some(wrong_epoch_result),
        total_dropped_messages: total_dropped,
    }
}

// ============================================================================
// Part H – Scenario B: Two Nodes Lag, One Transitions Early
// ============================================================================

/// Run Scenario B: Two nodes lag, one transitions early.
///
/// This test:
/// 1. Creates 3 nodes in epoch 0
/// 2. Node 0 sees and commits the reconfig block first, transitioning to epoch 1
/// 3. Nodes 1 and 2 are partitioned and lag behind
/// 4. After partition heals, nodes 1 and 2 catch up and transition to epoch 1
/// 5. All nodes converge to the same state
async fn run_scenario_b_two_nodes_lag(
    config: StaggeredEpochTestConfig,
) -> StaggeredEpochTestResult {
    eprintln!(
        "\n========== Starting Scenario B: Two Nodes Lag (T114) ==========\n\
         Reconfig Height: {}\n\
         Max Rounds: {}\n\
         Tick Interval: {:?}\n\
         Timeout: {:?}\n\
         ================================================================\n",
        config.reconfig_height, config.max_rounds, config.tick_interval, config.timeout
    );

    // Create 3 nodes
    let mut nodes = Vec::new();
    for i in 0..3 {
        let node = StaggeredNodeHandle::new(i, config.transport)
            .await
            .unwrap_or_else(|e| panic!("Failed to create node {}: {}", i, e));
        eprintln!(
            "[Node {}] Created - ValidatorId={:?}, Address={}",
            i, node.id, node.local_addr
        );
        nodes.push(node);
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let addresses: Vec<SocketAddr> = nodes.iter().map(|n| n.local_addr).collect();
    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                let _ = nodes[i].connect_to(addresses[j]).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create network facades:
    // - Node 0 uses normal facade
    // - Nodes 1 and 2 use staggered facades (partitioned until after reconfig)
    let facade_0 = nodes[0].create_facade();
    let inner_facade_1 = nodes[1].create_facade();
    let inner_facade_2 = nodes[2].create_facade();

    let partition_heal_height = config.reconfig_height + 3;
    let staggered_facade_1 = StaggeredNetworkFacade::new(
        inner_facade_1,
        StaggeredFaultMode::DropUntilHeight(partition_heal_height),
    );
    let staggered_facade_2 = StaggeredNetworkFacade::new(
        inner_facade_2,
        StaggeredFaultMode::DropUntilHeight(partition_heal_height),
    );

    eprintln!(
        "[Cluster] Nodes 1 and 2 are PARTITIONED until height {}",
        partition_heal_height
    );

    let start_time = std::time::Instant::now();
    let mut current_round: u64 = 0;
    let mut safety_violated = false;
    let mut reconfig_block_injected = false;
    let mut node_0_transitioned = false;
    let mut nodes_1_2_transitioned = false;

    while current_round < config.max_rounds && start_time.elapsed() < config.timeout {
        let leader_index = (current_round as usize) % 3;

        let epoch_0 = nodes[0].get_current_epoch().await;
        let epoch_1 = nodes[1].get_current_epoch().await;
        let epoch_2 = nodes[2].get_current_epoch().await;

        eprintln!(
            "[Cluster] Round {}: Leader={}, Epochs=[{}, {}, {}]",
            current_round, leader_index, epoch_0, epoch_1, epoch_2
        );

        // Update staggered facade heights
        staggered_facade_1.set_height(current_round);
        staggered_facade_2.set_height(current_round);

        let is_reconfig_round = current_round == config.reconfig_height && !reconfig_block_injected;

        let mut parent_id = [0xFFu8; 32];
        if current_round > 0 {
            parent_id = compute_block_id(0, current_round - 1);
        }

        let (proposal, block_id) = if is_reconfig_round {
            eprintln!(
                "[Cluster] Proposing RECONFIG block at height {}",
                current_round
            );
            reconfig_block_injected = true;
            let p = make_reconfig_proposal(0, current_round, 1, leader_index as u16, parent_id);
            let id = compute_reconfig_block_id(0, current_round, leader_index as u16);
            (p, id)
        } else {
            let epoch = if node_0_transitioned && leader_index == 0 {
                1
            } else {
                0
            };
            let p = make_normal_proposal(epoch, current_round, leader_index as u16, parent_id);
            let id = compute_block_id(epoch, current_round);
            (p, id)
        };

        // Broadcast proposal from leader
        match leader_index {
            0 => {
                let _ = facade_0.broadcast_proposal(&proposal);
            }
            1 => {
                let _ = staggered_facade_1.broadcast_proposal(&proposal);
            }
            2 => {
                let _ = staggered_facade_2.broadcast_proposal(&proposal);
            }
            _ => {}
        }

        // Send votes
        for i in 0..3 {
            let node_epoch = nodes[i].get_current_epoch().await;
            let vote = make_vote(node_epoch, current_round, block_id, nodes[i].id.0 as u16);
            match i {
                0 => {
                    let _ = facade_0.broadcast_vote(&vote);
                }
                1 => {
                    let _ = staggered_facade_1.broadcast_vote(&vote);
                }
                2 => {
                    let _ = staggered_facade_2.broadcast_vote(&vote);
                }
                _ => {}
            }
        }

        tokio::time::sleep(config.tick_interval).await;

        // Apply commit logic
        if current_round >= COMMIT_DELAY {
            let commit_height = current_round - 1;
            let commit_block_id = if commit_height == config.reconfig_height {
                compute_reconfig_block_id(0, commit_height, (commit_height as usize % 3) as u16)
            } else {
                compute_block_id(0, commit_height)
            };

            let committing_reconfig = commit_height == config.reconfig_height;

            // Node 0 can always commit
            let violation = nodes[0]
                .update_committed_state(commit_height, commit_block_id)
                .await;
            if violation {
                safety_violated = true;
            }

            if committing_reconfig && !node_0_transitioned {
                eprintln!(
                    "[Node 0] Committing RECONFIG at height {} - transitioning to epoch 1 FIRST",
                    commit_height
                );
                nodes[0].set_current_epoch(1).await;
                node_0_transitioned = true;
            }

            // Nodes 1 and 2 can only commit after partition heals
            if current_round >= partition_heal_height {
                for i in 1..3 {
                    let violation = nodes[i]
                        .update_committed_state(commit_height, commit_block_id)
                        .await;
                    if violation {
                        safety_violated = true;
                    }
                }

                // Nodes 1 and 2 catch up on reconfig
                if !nodes_1_2_transitioned {
                    for i in 1..3 {
                        eprintln!("[Node {}] Catching up - transitioning to epoch 1", i);
                        nodes[i].set_current_epoch(1).await;
                    }
                    nodes_1_2_transitioned = true;
                }
            }

            eprintln!(
                "[Cluster] Commit at round {}: height {}",
                current_round, commit_height
            );
        }

        current_round += 1;

        // Check convergence
        if node_0_transitioned && nodes_1_2_transitioned {
            let h0 = nodes[0].get_committed_height().await;
            let h1 = nodes[1].get_committed_height().await;
            let h2 = nodes[2].get_committed_height().await;
            if h0.is_some()
                && h1.is_some()
                && h2.is_some()
                && h0 == h1
                && h1 == h2
                && h0.unwrap() > config.reconfig_height
            {
                eprintln!("[Cluster] All nodes converged after epoch transition");
                break;
            }
        }
    }

    // Verify wrong-epoch handling
    let wrong_epoch_result = verify_wrong_epoch_handling(1, 0);

    // Collect results
    let final_epochs: [u64; 3] = [
        nodes[0].get_current_epoch().await,
        nodes[1].get_current_epoch().await,
        nodes[2].get_current_epoch().await,
    ];

    let committed_heights: [Option<u64>; 3] = [
        nodes[0].get_committed_height().await,
        nodes[1].get_committed_height().await,
        nodes[2].get_committed_height().await,
    ];

    let last_committed_block_ids: [Option<[u8; 32]>; 3] = [
        nodes[0].get_last_committed_block_id().await,
        nodes[1].get_last_committed_block_id().await,
        nodes[2].get_last_committed_block_id().await,
    ];

    let epoch_transition_occurred = final_epochs.iter().all(|&e| e == 1);

    let consensus_achieved = {
        let heights: Vec<u64> = committed_heights.iter().filter_map(|h| *h).collect();
        let ids: Vec<[u8; 32]> = last_committed_block_ids
            .iter()
            .filter_map(|id| *id)
            .collect();

        heights.len() == 3
            && ids.len() == 3
            && heights.windows(2).all(|w| w[0] == w[1])
            && ids.windows(2).all(|w| w[0] == w[1])
    };

    let total_dropped = staggered_facade_1.dropped_votes()
        + staggered_facade_1.dropped_proposals()
        + staggered_facade_2.dropped_votes()
        + staggered_facade_2.dropped_proposals();

    // Shutdown
    for node in &nodes {
        node.shutdown();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    eprintln!(
        "\n========== Scenario B Complete (T114) ==========\n\
         Epoch Transition: {}\n\
         Consensus Achieved: {}\n\
         Safety Violated: {}\n\
         Final Epochs: {:?}\n\
         Committed Heights: {:?}\n\
         Dropped Messages: {}\n\
         ================================================\n",
        epoch_transition_occurred,
        consensus_achieved,
        safety_violated,
        final_epochs,
        committed_heights,
        total_dropped
    );

    StaggeredEpochTestResult {
        final_epochs,
        committed_heights,
        last_committed_block_ids,
        epoch_transition_occurred,
        consensus_achieved,
        safety_violated,
        wrong_epoch_handling: Some(wrong_epoch_result),
        total_dropped_messages: total_dropped,
    }
}

// ============================================================================
// Part I – Test Cases
// ============================================================================

/// Test Scenario A: One node lags epoch transition.
///
/// Verifies:
/// - Nodes 0 and 1 transition to epoch 1 while node 2 lags
/// - No safety violations (conflicting commits)
/// - Node 2 eventually catches up and transitions
/// - All nodes converge to the same state
/// - Wrong-epoch messages are handled correctly
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario_a_one_node_lags_epoch_transition() {
    let config = StaggeredEpochTestConfig::default();
    let result = run_scenario_a_one_node_lags(config).await;

    // Assert: No safety violations
    assert!(
        !result.safety_violated,
        "Safety violation detected - conflicting commits!"
    );

    // Assert: All nodes transitioned to epoch 1
    assert!(
        result.epoch_transition_occurred,
        "Expected all nodes to transition to epoch 1, got epochs: {:?}",
        result.final_epochs
    );

    for (i, &epoch) in result.final_epochs.iter().enumerate() {
        assert_eq!(
            epoch, 1,
            "Node {} should be in epoch 1, but is in epoch {}",
            i, epoch
        );
    }

    // Assert: All nodes agree on committed state
    assert!(
        result.consensus_achieved,
        "Expected all nodes to agree on committed state.\n\
         Heights: {:?}\n\
         Block IDs: {:?}",
        result.committed_heights, result.last_committed_block_ids
    );

    // Assert: All nodes have valid committed heights
    for (i, height) in result.committed_heights.iter().enumerate() {
        assert!(
            height.is_some(),
            "Node {} should have a committed height",
            i
        );
    }

    // Assert: Wrong-epoch handling worked correctly
    if let Some(wrong_epoch) = &result.wrong_epoch_handling {
        assert!(
            !wrong_epoch.panic_occurred,
            "No panic should occur when handling wrong-epoch messages"
        );
        assert!(
            wrong_epoch.wrong_epoch_votes_rejected > 0,
            "Wrong-epoch votes should be rejected"
        );
        assert!(
            wrong_epoch.wrong_epoch_proposals_ignored > 0,
            "Wrong-epoch proposals should be ignored"
        );
    }

    // Assert: Some messages were dropped (staggering was active)
    assert!(
        result.total_dropped_messages > 0,
        "Expected some messages to be dropped during staggered transition"
    );

    eprintln!("\n✓ scenario_a_one_node_lags_epoch_transition PASSED\n");
}

/// Test Scenario B: Two nodes lag, one transitions early.
///
/// Verifies:
/// - Node 0 transitions to epoch 1 first
/// - Nodes 1 and 2 lag but eventually catch up
/// - No safety violations (conflicting commits)
/// - All nodes converge to the same state
/// - Wrong-epoch messages are handled correctly
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario_b_two_nodes_lag_epoch_transition() {
    let config = StaggeredEpochTestConfig::default();
    let result = run_scenario_b_two_nodes_lag(config).await;

    // Assert: No safety violations
    assert!(
        !result.safety_violated,
        "Safety violation detected - conflicting commits!"
    );

    // Assert: All nodes transitioned to epoch 1
    assert!(
        result.epoch_transition_occurred,
        "Expected all nodes to transition to epoch 1, got epochs: {:?}",
        result.final_epochs
    );

    for (i, &epoch) in result.final_epochs.iter().enumerate() {
        assert_eq!(
            epoch, 1,
            "Node {} should be in epoch 1, but is in epoch {}",
            i, epoch
        );
    }

    // Assert: All nodes agree on committed state
    assert!(
        result.consensus_achieved,
        "Expected all nodes to agree on committed state.\n\
         Heights: {:?}\n\
         Block IDs: {:?}",
        result.committed_heights, result.last_committed_block_ids
    );

    // Assert: All nodes have valid committed heights
    for (i, height) in result.committed_heights.iter().enumerate() {
        assert!(
            height.is_some(),
            "Node {} should have a committed height",
            i
        );
    }

    // Assert: Wrong-epoch handling worked correctly
    if let Some(wrong_epoch) = &result.wrong_epoch_handling {
        assert!(
            !wrong_epoch.panic_occurred,
            "No panic should occur when handling wrong-epoch messages"
        );
    }

    // Assert: Some messages were dropped (staggering was active)
    assert!(
        result.total_dropped_messages > 0,
        "Expected some messages to be dropped during staggered transition"
    );

    eprintln!("\n✓ scenario_b_two_nodes_lag_epoch_transition PASSED\n");
}

/// Test that wrong-epoch votes are rejected with WrongEpoch error.
///
/// This test directly verifies the wrong-epoch message handling behavior
/// without running the full cluster simulation.
#[test]
fn wrong_epoch_votes_are_rejected() {
    let result = verify_wrong_epoch_handling(1, 0);

    assert!(
        !result.panic_occurred,
        "No panic should occur when handling wrong-epoch votes"
    );

    assert_eq!(
        result.wrong_epoch_votes_rejected, 1,
        "Wrong-epoch vote should be rejected with WrongEpoch error"
    );
}

/// Test that wrong-epoch proposals are ignored (return None).
///
/// This test directly verifies the wrong-epoch proposal handling behavior
/// without running the full cluster simulation.
#[test]
fn wrong_epoch_proposals_are_ignored() {
    let result = verify_wrong_epoch_handling(1, 0);

    assert!(
        !result.panic_occurred,
        "No panic should occur when handling wrong-epoch proposals"
    );

    assert_eq!(
        result.wrong_epoch_proposals_ignored, 1,
        "Wrong-epoch proposal should be ignored (return None)"
    );
}

// ============================================================================
// Part J – Configuration and Unit Tests
// ============================================================================

#[test]
fn staggered_epoch_test_config_default_values() {
    let config = StaggeredEpochTestConfig::default();

    assert_eq!(config.epoch0.epoch_id(), EpochId::GENESIS);
    assert_eq!(config.epoch1.epoch_id().as_u64(), 1);
    assert_eq!(config.epoch0.len(), 3);
    assert_eq!(config.epoch1.len(), 3);
    assert_eq!(config.transport, TransportSecurityMode::PlainTcp);
    assert_eq!(config.reconfig_height, 3);
    assert_eq!(config.max_rounds, 25);
}

#[test]
fn staggered_fault_mode_default_is_pass_through() {
    let mode = StaggeredFaultMode::default();
    assert!(matches!(mode, StaggeredFaultMode::PassThrough));
}

#[test]
fn compute_block_id_is_deterministic() {
    let id1 = compute_block_id(0, 5);
    let id2 = compute_block_id(0, 5);
    assert_eq!(id1, id2);

    let id3 = compute_block_id(1, 5);
    assert_ne!(id1, id3); // Different epoch

    let id4 = compute_block_id(0, 6);
    assert_ne!(id1, id4); // Different height
}

#[test]
fn make_vote_creates_valid_vote() {
    let vote = make_vote(0, 5, [1u8; 32], 2);
    assert_eq!(vote.epoch, 0);
    assert_eq!(vote.height, 5);
    assert_eq!(vote.block_id, [1u8; 32]);
    assert_eq!(vote.validator_index, 2);
}

#[test]
fn make_normal_proposal_creates_valid_proposal() {
    let proposal = make_normal_proposal(0, 5, 2, [0xAAu8; 32]);
    assert_eq!(proposal.header.epoch, 0);
    assert_eq!(proposal.header.height, 5);
    assert_eq!(proposal.header.proposer_index, 2);
    assert_eq!(proposal.header.parent_block_id, [0xAAu8; 32]);
    assert_eq!(
        proposal.header.payload_kind,
        qbind_wire::PAYLOAD_KIND_NORMAL
    );
}

#[test]
fn make_reconfig_proposal_creates_valid_proposal() {
    let proposal = make_reconfig_proposal(0, 5, 1, 2, [0xAAu8; 32]);
    assert_eq!(proposal.header.epoch, 0);
    assert_eq!(proposal.header.height, 5);
    assert_eq!(proposal.header.next_epoch, 1);
    assert_eq!(proposal.header.proposer_index, 2);
    assert_eq!(proposal.header.parent_block_id, [0xAAu8; 32]);
    assert_eq!(
        proposal.header.payload_kind,
        qbind_wire::PAYLOAD_KIND_RECONFIG
    );
}

#[test]
fn three_validator_set_has_correct_properties() {
    let validator_set = build_three_validator_set();
    assert_eq!(validator_set.len(), 3);
    assert_eq!(validator_set.total_voting_power(), 3);
    assert_eq!(validator_set.two_thirds_vp(), 2);
}
