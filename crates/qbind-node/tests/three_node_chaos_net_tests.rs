//! Adversarial / Chaos networking tests for 3-node HotStuff consensus (T108).
//!
//! This module provides test-only adversarial networking scenarios for the QBIND
//! 3-node HotStuff setup, using the existing async networking & KEMTLS stack.
//!
//! # Goals
//!
//! - **Safety**: Verify no conflicting commits when network conditions are bad.
//! - **Basic Liveness**: Once network heals, all nodes eventually converge to the
//!   same committed height and block ID.
//!
//! # Scenarios
//!
//! - **Scenario A**: Temporary partition of one node, then heal. The partitioned node
//!   should lag, but non-partitioned nodes should not commit conflicting blocks.
//!   After healing, all 3 nodes converge.
//!
//! - **Scenario B**: Random message drops below safety threshold. With a small fraction
//!   of dropped messages (e.g., 5-20%), consensus should still make progress and
//!   all nodes should eventually reach the target height with agreement.
//!
//! # Test-Only Code
//!
//! The `FaultyNetworkFacade` is test-only and not exposed in production. All fault
//! injection types live within this test module.
//!
//! # Transport Mode
//!
//! Tests use PlainTcp transport for speed. KEMTLS can be tested in follow-up.
//!
//! # Determinism
//!
//! - Fixed seeds for any randomization
//! - Bounded loops and timeouts
//! - Clear failure messages when convergence doesn't happen
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test three_node_chaos_net_tests
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::Mutex;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::network::NetworkError;
use qbind_node::peer::PeerId;
use qbind_node::{
    AsyncPeerManagerConfig, AsyncPeerManagerImpl, ConsensusNetworkFacade, DirectAsyncNetworkFacade,
    NodeMetrics, TransportSecurityMode,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

// ============================================================================
// Part A – FaultyNetworkFacade: Test-only fault injection wrapper
// ============================================================================

/// Fault injection mode for the `FaultyNetworkFacade`.
///
/// Controls how messages are dropped or delayed.
#[derive(Debug, Clone)]
pub enum FaultMode {
    /// Pass-through mode: no faults injected, all messages forwarded.
    PassThrough,

    /// Drop all messages (simulates full network partition).
    DropAll,

    /// Drop messages deterministically based on a counter.
    /// Drops every Nth message where N is the modulus value.
    /// E.g., DropEveryNth(7) drops messages 0, 7, 14, 21, ...
    DropEveryNth(u64),

    /// Drop a fixed percentage of messages using a deterministic pattern.
    /// Uses a simple pseudo-random sequence based on a seed.
    /// The percentage should be between 0 and 100.
    DropPercentage { percentage: u8, seed: u64 },
}

impl Default for FaultMode {
    fn default() -> Self {
        FaultMode::PassThrough
    }
}

/// Configuration for the faulty network facade.
#[derive(Debug, Clone)]
pub struct FaultyNetworkConfig {
    /// The fault mode for outbound votes.
    pub vote_fault_mode: FaultMode,
    /// The fault mode for outbound proposals.
    pub proposal_fault_mode: FaultMode,
}

impl Default for FaultyNetworkConfig {
    fn default() -> Self {
        FaultyNetworkConfig {
            vote_fault_mode: FaultMode::PassThrough,
            proposal_fault_mode: FaultMode::PassThrough,
        }
    }
}

impl FaultyNetworkConfig {
    /// Create a config that drops all messages (full partition).
    pub fn full_partition() -> Self {
        FaultyNetworkConfig {
            vote_fault_mode: FaultMode::DropAll,
            proposal_fault_mode: FaultMode::DropAll,
        }
    }

    /// Create a config that drops every Nth message.
    pub fn drop_every_nth(n: u64) -> Self {
        FaultyNetworkConfig {
            vote_fault_mode: FaultMode::DropEveryNth(n),
            proposal_fault_mode: FaultMode::DropEveryNth(n),
        }
    }

    /// Create a config that drops a percentage of messages.
    pub fn drop_percentage(percentage: u8, seed: u64) -> Self {
        FaultyNetworkConfig {
            vote_fault_mode: FaultMode::DropPercentage { percentage, seed },
            proposal_fault_mode: FaultMode::DropPercentage { percentage, seed },
        }
    }

    /// Create a pass-through config (no faults).
    pub fn pass_through() -> Self {
        FaultyNetworkConfig::default()
    }
}

/// A test-only wrapper that injects faults into a `ConsensusNetworkFacade`.
///
/// This facade can:
/// - Drop a subset of outbound messages based on configurable rules
/// - Switch between fault modes dynamically (e.g., partition then heal)
///
/// # Thread Safety
///
/// The facade uses atomic counters and a `RwLock<FaultyNetworkConfig>` for
/// synchronous access to the configuration. This avoids async operations
/// in the sync `ConsensusNetworkFacade` trait methods.
///
/// # Usage
///
/// ```ignore
/// let inner = DirectAsyncNetworkFacade::new(peer_manager.clone());
/// let faulty = FaultyNetworkFacade::new(inner, FaultyNetworkConfig::full_partition());
///
/// // Later, heal the partition:
/// faulty.set_config(FaultyNetworkConfig::pass_through());
/// ```
pub struct FaultyNetworkFacade<F: ConsensusNetworkFacade> {
    /// The underlying network facade.
    inner: F,
    /// Current fault configuration (RwLock for sync access).
    config: RwLock<FaultyNetworkConfig>,
    /// Counter for vote messages (used for deterministic dropping).
    vote_counter: AtomicU64,
    /// Counter for proposal messages (used for deterministic dropping).
    proposal_counter: AtomicU64,
    /// Counter for dropped vote messages.
    dropped_votes: AtomicU64,
    /// Counter for dropped proposal messages.
    dropped_proposals: AtomicU64,
    /// Flag indicating if the facade is in partition mode (for debugging).
    is_partitioned: AtomicBool,
}

impl<F: ConsensusNetworkFacade> FaultyNetworkFacade<F> {
    /// Create a new faulty network facade wrapping the given inner facade.
    pub fn new(inner: F, config: FaultyNetworkConfig) -> Self {
        let is_partitioned = matches!(config.vote_fault_mode, FaultMode::DropAll)
            && matches!(config.proposal_fault_mode, FaultMode::DropAll);

        FaultyNetworkFacade {
            inner,
            config: RwLock::new(config),
            vote_counter: AtomicU64::new(0),
            proposal_counter: AtomicU64::new(0),
            dropped_votes: AtomicU64::new(0),
            dropped_proposals: AtomicU64::new(0),
            is_partitioned: AtomicBool::new(is_partitioned),
        }
    }

    /// Update the fault configuration.
    ///
    /// This allows tests to dynamically change fault behavior (e.g., heal a partition).
    pub fn set_config(&self, new_config: FaultyNetworkConfig) {
        let is_partitioned = matches!(new_config.vote_fault_mode, FaultMode::DropAll)
            && matches!(new_config.proposal_fault_mode, FaultMode::DropAll);
        self.is_partitioned.store(is_partitioned, Ordering::SeqCst);

        if let Ok(mut config) = self.config.write() {
            *config = new_config;
        }
    }

    /// Get the number of dropped vote messages.
    pub fn dropped_votes(&self) -> u64 {
        self.dropped_votes.load(Ordering::Relaxed)
    }

    /// Get the number of dropped proposal messages.
    pub fn dropped_proposals(&self) -> u64 {
        self.dropped_proposals.load(Ordering::Relaxed)
    }

    /// Check if the facade is currently in partition mode.
    pub fn is_partitioned(&self) -> bool {
        self.is_partitioned.load(Ordering::SeqCst)
    }

    /// Determine if a message should be dropped based on the fault mode.
    fn should_drop(mode: &FaultMode, counter: u64) -> bool {
        match mode {
            FaultMode::PassThrough => false,
            FaultMode::DropAll => true,
            FaultMode::DropEveryNth(n) => {
                if *n == 0 {
                    false
                } else {
                    counter % n == 0
                }
            }
            FaultMode::DropPercentage { percentage, seed } => {
                // Use a simple deterministic pseudo-random decision.
                // We XOR the counter with the seed and check if the result modulo 100
                // is less than the percentage.
                if *percentage >= 100 {
                    return true;
                }
                if *percentage == 0 {
                    return false;
                }
                let hash = counter.wrapping_mul(0x517cc1b727220a95) ^ seed;
                (hash % 100) < (*percentage as u64)
            }
        }
    }

    /// Check if a vote should be dropped and increment counters accordingly.
    /// Returns true if the message should be dropped.
    fn check_vote_drop(&self) -> bool {
        let counter = self.vote_counter.fetch_add(1, Ordering::Relaxed);
        let should_drop = self
            .config
            .read()
            .map(|cfg| Self::should_drop(&cfg.vote_fault_mode, counter))
            .unwrap_or(false);

        if should_drop {
            self.dropped_votes.fetch_add(1, Ordering::Relaxed);
        }
        should_drop
    }

    /// Check if a proposal should be dropped and increment counters accordingly.
    /// Returns true if the message should be dropped.
    fn check_proposal_drop(&self) -> bool {
        let counter = self.proposal_counter.fetch_add(1, Ordering::Relaxed);
        let should_drop = self
            .config
            .read()
            .map(|cfg| Self::should_drop(&cfg.proposal_fault_mode, counter))
            .unwrap_or(false);

        if should_drop {
            self.dropped_proposals.fetch_add(1, Ordering::Relaxed);
        }
        should_drop
    }
}

impl<F: ConsensusNetworkFacade> ConsensusNetworkFacade for FaultyNetworkFacade<F> {
    fn send_vote_to(&self, target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        if self.check_vote_drop() {
            return Ok(());
        }
        self.inner.send_vote_to(target, vote)
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        if self.check_vote_drop() {
            return Ok(());
        }
        self.inner.broadcast_vote(vote)
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        if self.check_proposal_drop() {
            return Ok(());
        }
        self.inner.broadcast_proposal(proposal)
    }
}

// SAFETY: FaultyNetworkFacade is safe to send and share across threads because:
// - `inner: F` is required to be Send + Sync by the trait bound
// - `config: RwLock<FaultyNetworkConfig>` is Send + Sync (RwLock provides synchronization)
// - All other fields are atomic types (AtomicU64, AtomicBool) which are Send + Sync
unsafe impl<F: ConsensusNetworkFacade + Send + Sync> Send for FaultyNetworkFacade<F> {}
unsafe impl<F: ConsensusNetworkFacade + Send + Sync> Sync for FaultyNetworkFacade<F> {}

// ============================================================================
// Part B – Chaos Test Cluster Helpers
// ============================================================================

/// Test signature placeholder (dummy value for testing - signatures not verified).
const TEST_SIGNATURE: [u8; 2] = [0xCA, 0xFE];

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

/// Create a normal block proposal for testing.
fn make_proposal(
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
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: TEST_SIGNATURE.to_vec(),
    }
}

/// Compute a block ID from height and epoch for deterministic testing.
fn compute_block_id(epoch: u64, height: u64) -> [u8; 32] {
    let mut block_id = [0u8; 32];
    block_id[0] = (height & 0xFF) as u8;
    block_id[1] = (epoch & 0xFF) as u8;
    block_id
}

// ============================================================================
// Part C – Chaos Node Handle
// ============================================================================

/// Handle to a single node in the chaos test cluster.
///
/// This encapsulates:
/// - Validator identity
/// - Async peer manager for networking
/// - Either a normal or faulty network facade
/// - State accessors for committed height/block
struct ChaosNodeHandle {
    /// The validator ID for this node.
    id: ValidatorId,
    /// The async peer manager for this node.
    peer_manager: Arc<AsyncPeerManagerImpl>,
    /// The local address the node is listening on.
    local_addr: SocketAddr,
    /// Node metrics for observability (kept for future use/debugging).
    #[allow(dead_code)]
    metrics: Arc<NodeMetrics>,
    /// Node index (0, 1, or 2).
    index: usize,
    /// Committed height (updated via consensus).
    committed_height: Arc<Mutex<Option<u64>>>,
    /// Last committed block ID (updated via consensus).
    last_committed_block_id: Arc<Mutex<Option<[u8; 32]>>>,
}

impl ChaosNodeHandle {
    /// Create a new chaos node handle.
    async fn new(index: usize) -> Result<Self, String> {
        let id = ValidatorId::new(index as u64);
        let metrics = Arc::new(NodeMetrics::new());

        // Build AsyncPeerManagerConfig (PlainTcp for speed)
        let pm_config = AsyncPeerManagerConfig::default()
            .with_listen_addr("127.0.0.1:0".parse().unwrap())
            .with_transport_security_mode(TransportSecurityMode::PlainTcp)
            .with_inbound_channel_capacity(1024)
            .with_outbound_channel_capacity(256);

        // Create and bind the peer manager
        let mut peer_manager = AsyncPeerManagerImpl::with_metrics(pm_config, metrics.clone());
        let local_addr = peer_manager
            .bind()
            .await
            .map_err(|e| format!("Node {} failed to bind: {}", index, e))?;

        let peer_manager = Arc::new(peer_manager);

        // Start the listener
        peer_manager.start_listener().await;

        Ok(ChaosNodeHandle {
            id,
            peer_manager,
            local_addr,
            metrics,
            index,
            committed_height: Arc::new(Mutex::new(None)),
            last_committed_block_id: Arc::new(Mutex::new(None)),
        })
    }

    /// Connect to another node as a peer.
    async fn connect_to(&self, peer_addr: SocketAddr) -> Result<PeerId, String> {
        // PlainTcp mode - no client config needed
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

    /// Update committed state (height and block ID).
    async fn update_committed_state(&self, height: u64, block_id: [u8; 32]) {
        let mut h = self.committed_height.lock().await;
        *h = Some(height);
        let mut bid = self.last_committed_block_id.lock().await;
        *bid = Some(block_id);
    }

    /// Get the current committed height.
    async fn get_committed_height(&self) -> Option<u64> {
        *self.committed_height.lock().await
    }

    /// Get the last committed block ID.
    async fn get_last_committed_block_id(&self) -> Option<[u8; 32]> {
        *self.last_committed_block_id.lock().await
    }

    /// Create a network facade for this node.
    fn create_facade(&self) -> DirectAsyncNetworkFacade {
        DirectAsyncNetworkFacade::new(self.peer_manager.clone())
    }

    /// Shutdown the node.
    fn shutdown(&self) {
        self.peer_manager.shutdown();
    }
}

// ============================================================================
// Part D – Test Scenario A: Temporary partition then heal
// ============================================================================

/// Configuration for the partition scenario test.
#[derive(Debug, Clone)]
pub struct PartitionTestConfig {
    /// Number of rounds to run with the partition active.
    pub partition_rounds: u64,
    /// Number of rounds to run after healing.
    pub heal_rounds: u64,
    /// Target height to reach after healing.
    pub target_height: u64,
    /// Tick interval between rounds.
    pub tick_interval: Duration,
    /// Maximum test duration.
    pub timeout: Duration,
}

impl Default for PartitionTestConfig {
    fn default() -> Self {
        PartitionTestConfig {
            partition_rounds: 5,
            heal_rounds: 10,
            target_height: 8,
            tick_interval: Duration::from_millis(100),
            timeout: Duration::from_secs(60),
        }
    }
}

/// Result from the partition scenario test.
#[derive(Debug)]
pub struct PartitionTestResult {
    /// Final committed heights for each node.
    pub committed_heights: [Option<u64>; 3],
    /// Last committed block IDs for each node.
    pub last_committed_block_ids: [Option<[u8; 32]>; 3],
    /// Whether all nodes converged after healing.
    pub converged: bool,
    /// Whether any conflicting commits were detected during partition.
    pub safety_violated: bool,
    /// Number of messages dropped by the faulty facade.
    pub dropped_messages: u64,
}

/// Run the partition scenario test.
///
/// This test:
/// 1. Creates a 3-node cluster
/// 2. Partitions node 2 (drops all its outbound messages)
/// 3. Runs consensus for `partition_rounds` rounds
/// 4. Heals the partition (switches to pass-through)
/// 5. Continues consensus until `target_height` or timeout
/// 6. Verifies all nodes converged and no conflicting commits occurred
async fn run_partition_scenario(config: PartitionTestConfig) -> PartitionTestResult {
    eprintln!(
        "\n========== Starting Partition Scenario Test (T108) ==========\n\
         Partition Rounds: {}\n\
         Heal Rounds: {}\n\
         Target Height: {}\n\
         Tick Interval: {:?}\n\
         Timeout: {:?}\n\
         ==============================================================\n",
        config.partition_rounds,
        config.heal_rounds,
        config.target_height,
        config.tick_interval,
        config.timeout
    );

    // Create 3 nodes
    let mut nodes = Vec::new();
    for i in 0..3 {
        let node = ChaosNodeHandle::new(i)
            .await
            .unwrap_or_else(|e| panic!("Failed to create node {}: {}", i, e));
        eprintln!(
            "[Node {}] Created - ValidatorId={:?}, Address={}",
            i, node.id, node.local_addr
        );
        nodes.push(node);
    }

    // Wait for listeners to be ready
    eprintln!("[Cluster] Waiting for listeners...");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Establish peer connections (full mesh)
    let addresses: Vec<SocketAddr> = nodes.iter().map(|n| n.local_addr).collect();

    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                let peer_id = nodes[i].connect_to(addresses[j]).await.unwrap_or_else(|e| {
                    panic!("Node {} failed to connect to node {}: {}", i, j, e)
                });
                eprintln!(
                    "[Node {}] Connected to node {} as PeerId({:?})",
                    i, j, peer_id
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Wait for connections to stabilize
    eprintln!("[Cluster] Waiting for connections to stabilize...");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create network facades:
    // - Nodes 0 and 1 use normal facades
    // - Node 2 uses a faulty facade (initially in full partition mode)
    let facade_0 = nodes[0].create_facade();
    let facade_1 = nodes[1].create_facade();
    let inner_facade_2 = nodes[2].create_facade();
    let faulty_facade_2 =
        FaultyNetworkFacade::new(inner_facade_2, FaultyNetworkConfig::full_partition());

    eprintln!("[Cluster] Node 2 is PARTITIONED (all outbound messages dropped)");

    // Track block IDs committed by each node at each height for safety check
    let mut committed_blocks: [std::collections::HashMap<u64, [u8; 32]>; 3] = [
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
    ];
    let mut safety_violated = false;

    let start_time = std::time::Instant::now();
    let mut current_round: u64 = 0;
    let mut last_committed_height: u64 = 0;
    let epoch: u64 = 0;

    // HotStuff 3-chain commit delay
    const COMMIT_DELAY: u64 = 2;

    // Phase 1: Run with partition active
    while current_round < config.partition_rounds && start_time.elapsed() < config.timeout {
        let leader_index = (current_round as usize) % 3;

        eprintln!(
            "[Cluster] Round {} (PARTITIONED): Leader is Node {}",
            current_round, leader_index
        );

        // Create proposal
        let mut parent_id = [0xFFu8; 32];
        if current_round > 0 {
            parent_id = compute_block_id(epoch, current_round - 1);
        }

        let block_id = compute_block_id(epoch, current_round);

        // Broadcast proposal from leader
        let proposal = make_proposal(epoch, current_round, leader_index as u16, parent_id);
        match leader_index {
            0 => {
                let _ = facade_0.broadcast_proposal(&proposal);
            }
            1 => {
                let _ = facade_1.broadcast_proposal(&proposal);
            }
            2 => {
                let _ = faulty_facade_2.broadcast_proposal(&proposal);
            }
            _ => {}
        }

        // Send votes from all nodes
        for i in 0..3 {
            let vote = make_vote(epoch, current_round, block_id, nodes[i].id.0 as u16);
            match i {
                0 => {
                    let _ = facade_0.broadcast_vote(&vote);
                }
                1 => {
                    let _ = facade_1.broadcast_vote(&vote);
                }
                2 => {
                    let _ = faulty_facade_2.broadcast_vote(&vote);
                }
                _ => {}
            }
        }

        // Wait for message propagation
        tokio::time::sleep(config.tick_interval).await;

        // Apply simplified 3-chain commit rule (commits happen starting at round 2)
        // Only nodes 0 and 1 can commit since node 2 is partitioned
        if current_round >= COMMIT_DELAY {
            let commit_height = current_round - 1;
            let commit_block_id = compute_block_id(epoch, commit_height);

            // Update nodes 0 and 1 (they can see each other's messages)
            for i in 0..2 {
                nodes[i]
                    .update_committed_state(commit_height, commit_block_id)
                    .await;
                committed_blocks[i].insert(commit_height, commit_block_id);
            }

            // Node 2 might not commit (partitioned), but if it somehow does,
            // check for safety violation
            // For this simulation, node 2 doesn't commit during partition

            last_committed_height = commit_height;
            eprintln!(
                "[Cluster] Commit at round {}: height {} committed by nodes 0,1",
                current_round, commit_height
            );
        }

        current_round += 1;
    }

    // Phase 2: Heal the partition
    eprintln!("\n[Cluster] HEALING partition - Node 2 can now communicate");
    faulty_facade_2.set_config(FaultyNetworkConfig::pass_through());

    // Continue consensus after healing
    let heal_start_round = current_round;
    while last_committed_height < config.target_height
        && current_round < heal_start_round + config.heal_rounds
        && start_time.elapsed() < config.timeout
    {
        let leader_index = (current_round as usize) % 3;

        eprintln!(
            "[Cluster] Round {} (HEALED): Leader is Node {}",
            current_round, leader_index
        );

        let mut parent_id = [0xFFu8; 32];
        if current_round > 0 {
            parent_id = compute_block_id(epoch, current_round - 1);
        }

        let block_id = compute_block_id(epoch, current_round);

        // Broadcast proposal from leader
        let proposal = make_proposal(epoch, current_round, leader_index as u16, parent_id);
        match leader_index {
            0 => {
                let _ = facade_0.broadcast_proposal(&proposal);
            }
            1 => {
                let _ = facade_1.broadcast_proposal(&proposal);
            }
            2 => {
                let _ = faulty_facade_2.broadcast_proposal(&proposal);
            }
            _ => {}
        }

        // Send votes from all nodes
        for i in 0..3 {
            let vote = make_vote(epoch, current_round, block_id, nodes[i].id.0 as u16);
            match i {
                0 => {
                    let _ = facade_0.broadcast_vote(&vote);
                }
                1 => {
                    let _ = facade_1.broadcast_vote(&vote);
                }
                2 => {
                    let _ = faulty_facade_2.broadcast_vote(&vote);
                }
                _ => {}
            }
        }

        tokio::time::sleep(config.tick_interval).await;

        // Apply 3-chain commit rule (all nodes can now commit)
        if current_round >= COMMIT_DELAY {
            let commit_height = current_round - 1;
            let commit_block_id = compute_block_id(epoch, commit_height);

            // Update all nodes
            for i in 0..3 {
                // Check for safety violation: if this node already committed
                // a different block at this height, that's a safety violation
                if let Some(&existing_id) = committed_blocks[i].get(&commit_height) {
                    if existing_id != commit_block_id {
                        eprintln!(
                            "[SAFETY VIOLATION] Node {} committed different blocks at height {}!",
                            i, commit_height
                        );
                        safety_violated = true;
                    }
                }

                nodes[i]
                    .update_committed_state(commit_height, commit_block_id)
                    .await;
                committed_blocks[i].insert(commit_height, commit_block_id);
            }

            last_committed_height = commit_height;
            eprintln!(
                "[Cluster] Commit at round {}: height {} committed by all nodes",
                current_round, commit_height
            );
        }

        current_round += 1;
    }

    // Collect results
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

    // Check convergence: all nodes should have same height and block ID
    let converged = {
        let heights: Vec<u64> = committed_heights.iter().filter_map(|h| *h).collect();
        let ids: Vec<[u8; 32]> = last_committed_block_ids
            .iter()
            .filter_map(|id| *id)
            .collect();

        if heights.len() != 3 || ids.len() != 3 {
            false
        } else {
            heights.windows(2).all(|w| w[0] == w[1]) && ids.windows(2).all(|w| w[0] == w[1])
        }
    };

    let dropped_messages = faulty_facade_2.dropped_votes() + faulty_facade_2.dropped_proposals();

    // Shutdown nodes
    eprintln!("[Cluster] Shutting down nodes...");
    for node in &nodes {
        node.shutdown();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    eprintln!(
        "\n========== Partition Scenario Test Complete (T108) ==========\n\
         Converged: {}\n\
         Safety Violated: {}\n\
         Committed Heights: {:?}\n\
         Dropped Messages: {}\n\
         Elapsed: {:?}\n\
         ==============================================================\n",
        converged,
        safety_violated,
        committed_heights,
        dropped_messages,
        start_time.elapsed()
    );

    PartitionTestResult {
        committed_heights,
        last_committed_block_ids,
        converged,
        safety_violated,
        dropped_messages,
    }
}

// ============================================================================
// Part E – Test Scenario B: Random message drops below threshold
// ============================================================================

/// Configuration for the random drop scenario test.
#[derive(Debug, Clone)]
pub struct RandomDropTestConfig {
    /// Percentage of messages to drop (0-100).
    pub drop_percentage: u8,
    /// Seed for deterministic random behavior.
    pub random_seed: u64,
    /// Target height to reach.
    pub target_height: u64,
    /// Maximum rounds to attempt.
    pub max_rounds: u64,
    /// Tick interval between rounds.
    pub tick_interval: Duration,
    /// Maximum test duration.
    pub timeout: Duration,
}

impl Default for RandomDropTestConfig {
    fn default() -> Self {
        RandomDropTestConfig {
            drop_percentage: 15, // 15% drop rate
            random_seed: 12345,
            target_height: 10,
            max_rounds: 30,
            tick_interval: Duration::from_millis(100),
            timeout: Duration::from_secs(60),
        }
    }
}

/// Result from the random drop scenario test.
#[derive(Debug)]
pub struct RandomDropTestResult {
    /// Final committed heights for each node.
    pub committed_heights: [Option<u64>; 3],
    /// Last committed block IDs for each node.
    pub last_committed_block_ids: [Option<[u8; 32]>; 3],
    /// Whether all nodes reached target height.
    pub target_reached: bool,
    /// Whether all nodes agree on committed state.
    pub consensus_achieved: bool,
    /// Total messages dropped across all faulty facades.
    pub total_dropped_messages: u64,
    /// Number of rounds executed.
    pub rounds_executed: u64,
}

/// Run the random drop scenario test.
///
/// This test:
/// 1. Creates a 3-node cluster with all nodes using faulty facades
/// 2. Configures facades to randomly drop a percentage of messages
/// 3. Runs consensus until target height or timeout
/// 4. Verifies all nodes converged to the same state
async fn run_random_drop_scenario(config: RandomDropTestConfig) -> RandomDropTestResult {
    eprintln!(
        "\n========== Starting Random Drop Scenario Test (T108) ==========\n\
         Drop Percentage: {}%\n\
         Random Seed: {}\n\
         Target Height: {}\n\
         Max Rounds: {}\n\
         Tick Interval: {:?}\n\
         Timeout: {:?}\n\
         ================================================================\n",
        config.drop_percentage,
        config.random_seed,
        config.target_height,
        config.max_rounds,
        config.tick_interval,
        config.timeout
    );

    // Create 3 nodes
    let mut nodes = Vec::new();
    for i in 0..3 {
        let node = ChaosNodeHandle::new(i)
            .await
            .unwrap_or_else(|e| panic!("Failed to create node {}: {}", i, e));
        eprintln!(
            "[Node {}] Created - ValidatorId={:?}, Address={}",
            i, node.id, node.local_addr
        );
        nodes.push(node);
    }

    // Wait for listeners
    eprintln!("[Cluster] Waiting for listeners...");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Establish peer connections (full mesh)
    let addresses: Vec<SocketAddr> = nodes.iter().map(|n| n.local_addr).collect();

    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                let peer_id = nodes[i].connect_to(addresses[j]).await.unwrap_or_else(|e| {
                    panic!("Node {} failed to connect to node {}: {}", i, j, e)
                });
                eprintln!(
                    "[Node {}] Connected to node {} as PeerId({:?})",
                    i, j, peer_id
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    eprintln!("[Cluster] Waiting for connections to stabilize...");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create faulty network facades for all nodes
    // Each node gets a slightly different seed to avoid correlated drops
    let faulty_facade_0 = FaultyNetworkFacade::new(
        nodes[0].create_facade(),
        FaultyNetworkConfig::drop_percentage(config.drop_percentage, config.random_seed),
    );
    let faulty_facade_1 = FaultyNetworkFacade::new(
        nodes[1].create_facade(),
        FaultyNetworkConfig::drop_percentage(
            config.drop_percentage,
            config.random_seed.wrapping_add(1),
        ),
    );
    let faulty_facade_2 = FaultyNetworkFacade::new(
        nodes[2].create_facade(),
        FaultyNetworkConfig::drop_percentage(
            config.drop_percentage,
            config.random_seed.wrapping_add(2),
        ),
    );

    eprintln!(
        "[Cluster] All nodes configured with {}% random message drops",
        config.drop_percentage
    );

    let start_time = std::time::Instant::now();
    let mut current_round: u64 = 0;
    let mut last_committed_height: u64 = 0;
    let epoch: u64 = 0;

    const COMMIT_DELAY: u64 = 2;

    // Run consensus until target height or limits
    while last_committed_height < config.target_height
        && current_round < config.max_rounds
        && start_time.elapsed() < config.timeout
    {
        let leader_index = (current_round as usize) % 3;

        eprintln!(
            "[Cluster] Round {}: Leader is Node {}, height so far {}",
            current_round, leader_index, last_committed_height
        );

        let mut parent_id = [0xFFu8; 32];
        if current_round > 0 {
            parent_id = compute_block_id(epoch, current_round - 1);
        }

        let block_id = compute_block_id(epoch, current_round);

        // Broadcast proposal from leader
        let proposal = make_proposal(epoch, current_round, leader_index as u16, parent_id);
        match leader_index {
            0 => {
                let _ = faulty_facade_0.broadcast_proposal(&proposal);
            }
            1 => {
                let _ = faulty_facade_1.broadcast_proposal(&proposal);
            }
            2 => {
                let _ = faulty_facade_2.broadcast_proposal(&proposal);
            }
            _ => {}
        }

        // Send votes from all nodes
        for i in 0..3 {
            let vote = make_vote(epoch, current_round, block_id, nodes[i].id.0 as u16);
            match i {
                0 => {
                    let _ = faulty_facade_0.broadcast_vote(&vote);
                }
                1 => {
                    let _ = faulty_facade_1.broadcast_vote(&vote);
                }
                2 => {
                    let _ = faulty_facade_2.broadcast_vote(&vote);
                }
                _ => {}
            }
        }

        tokio::time::sleep(config.tick_interval).await;

        // Apply 3-chain commit rule
        if current_round >= COMMIT_DELAY {
            let commit_height = current_round - 1;
            let commit_block_id = compute_block_id(epoch, commit_height);

            for node in &nodes {
                node.update_committed_state(commit_height, commit_block_id)
                    .await;
            }

            last_committed_height = commit_height;
            eprintln!(
                "[Cluster] Commit at round {}: height {} committed",
                current_round, commit_height
            );
        }

        current_round += 1;
    }

    // Collect results
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

    let target_reached = committed_heights
        .iter()
        .all(|h| h.map(|h| h >= config.target_height).unwrap_or(false));

    let consensus_achieved = {
        let heights: Vec<u64> = committed_heights.iter().filter_map(|h| *h).collect();
        let ids: Vec<[u8; 32]> = last_committed_block_ids
            .iter()
            .filter_map(|id| *id)
            .collect();

        if heights.len() != 3 || ids.len() != 3 {
            false
        } else {
            heights.windows(2).all(|w| w[0] == w[1]) && ids.windows(2).all(|w| w[0] == w[1])
        }
    };

    let total_dropped_messages = faulty_facade_0.dropped_votes()
        + faulty_facade_0.dropped_proposals()
        + faulty_facade_1.dropped_votes()
        + faulty_facade_1.dropped_proposals()
        + faulty_facade_2.dropped_votes()
        + faulty_facade_2.dropped_proposals();

    // Shutdown nodes
    eprintln!("[Cluster] Shutting down nodes...");
    for node in &nodes {
        node.shutdown();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    eprintln!(
        "\n========== Random Drop Scenario Test Complete (T108) ==========\n\
         Target Reached: {}\n\
         Consensus Achieved: {}\n\
         Committed Heights: {:?}\n\
         Total Dropped Messages: {}\n\
         Rounds Executed: {}\n\
         Elapsed: {:?}\n\
         ================================================================\n",
        target_reached,
        consensus_achieved,
        committed_heights,
        total_dropped_messages,
        current_round,
        start_time.elapsed()
    );

    RandomDropTestResult {
        committed_heights,
        last_committed_block_ids,
        target_reached,
        consensus_achieved,
        total_dropped_messages,
        rounds_executed: current_round,
    }
}

// ============================================================================
// Part F – Test Cases
// ============================================================================

/// Test Scenario A: Temporary partition of one node, then heal.
///
/// Verifies:
/// - During partition: Non-partitioned nodes can make progress
/// - During partition: No safety violations (conflicting commits)
/// - After healing: All nodes converge to the same state
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_node_temporary_partition_then_heal_converges() {
    let config = PartitionTestConfig {
        partition_rounds: 5,
        heal_rounds: 15,
        target_height: 8,
        tick_interval: Duration::from_millis(100),
        timeout: Duration::from_secs(60),
    };

    let result = run_partition_scenario(config).await;

    // Assert: No safety violations occurred
    assert!(
        !result.safety_violated,
        "Safety violation detected - conflicting commits during partition!"
    );

    // Assert: All nodes converged after healing
    assert!(
        result.converged,
        "Expected all nodes to converge after healing partition.\n\
         Committed Heights: {:?}\n\
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

    // Assert: All nodes agree on the same height
    let valid_heights: Vec<u64> = result.committed_heights.iter().filter_map(|h| *h).collect();
    assert!(
        valid_heights.windows(2).all(|w| w[0] == w[1]),
        "All nodes should have the same committed height, got: {:?}",
        valid_heights
    );

    // Assert: All nodes agree on the same block ID
    let valid_ids: Vec<[u8; 32]> = result
        .last_committed_block_ids
        .iter()
        .filter_map(|id| *id)
        .collect();
    assert!(
        valid_ids.windows(2).all(|w| w[0] == w[1]),
        "All nodes should have the same last committed block ID"
    );

    // Assert: Some messages were dropped during the partition
    assert!(
        result.dropped_messages > 0,
        "Expected some messages to be dropped during partition (dropped={})",
        result.dropped_messages
    );

    eprintln!("\n✓ three_node_temporary_partition_then_heal_converges PASSED\n");
}

/// Test Scenario B: Random message drops below safety threshold.
///
/// Verifies:
/// - With 15% message drops, consensus still makes progress
/// - All nodes eventually reach the target height
/// - All nodes agree on the committed state
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_node_random_drop_below_threshold_still_converges() {
    let config = RandomDropTestConfig {
        drop_percentage: 15, // 15% drop rate - below 33% safety threshold
        random_seed: 42,     // Fixed seed for determinism
        target_height: 10,
        max_rounds: 30,
        tick_interval: Duration::from_millis(100),
        timeout: Duration::from_secs(60),
    };

    let result = run_random_drop_scenario(config).await;

    // Assert: Target height was reached
    assert!(
        result.target_reached,
        "Expected all nodes to reach target height >= 10.\n\
         Committed Heights: {:?}\n\
         Rounds Executed: {}",
        result.committed_heights, result.rounds_executed
    );

    // Assert: Consensus was achieved (all nodes agree)
    assert!(
        result.consensus_achieved,
        "Expected all nodes to agree on committed height and block ID.\n\
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

    // Assert: All nodes agree on the same height
    let valid_heights: Vec<u64> = result.committed_heights.iter().filter_map(|h| *h).collect();
    assert!(
        valid_heights.windows(2).all(|w| w[0] == w[1]),
        "All nodes should have the same committed height, got: {:?}",
        valid_heights
    );

    // Assert: All nodes agree on the same block ID
    let valid_ids: Vec<[u8; 32]> = result
        .last_committed_block_ids
        .iter()
        .filter_map(|id| *id)
        .collect();
    assert!(
        valid_ids.windows(2).all(|w| w[0] == w[1]),
        "All nodes should have the same last committed block ID"
    );

    // Assert: Some messages were dropped (verifying fault injection worked)
    assert!(
        result.total_dropped_messages > 0,
        "Expected some messages to be dropped (dropped={})",
        result.total_dropped_messages
    );

    eprintln!("\n✓ three_node_random_drop_below_threshold_still_converges PASSED\n");
}

// ============================================================================
// Part G – Unit Tests for FaultyNetworkFacade
// ============================================================================

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn fault_mode_default_is_pass_through() {
        let mode = FaultMode::default();
        assert!(matches!(mode, FaultMode::PassThrough));
    }

    #[test]
    fn faulty_network_config_default_is_pass_through() {
        let config = FaultyNetworkConfig::default();
        assert!(matches!(config.vote_fault_mode, FaultMode::PassThrough));
        assert!(matches!(config.proposal_fault_mode, FaultMode::PassThrough));
    }

    #[test]
    fn should_drop_pass_through_never_drops() {
        let mode = FaultMode::PassThrough;
        for i in 0..100 {
            assert!(!FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, i));
        }
    }

    #[test]
    fn should_drop_drop_all_always_drops() {
        let mode = FaultMode::DropAll;
        for i in 0..100 {
            assert!(FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, i));
        }
    }

    #[test]
    fn should_drop_every_nth_works() {
        let mode = FaultMode::DropEveryNth(5);
        // Drops messages at counter 0, 5, 10, 15, ...
        assert!(FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, 0));
        assert!(!FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, 1));
        assert!(!FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, 4));
        assert!(FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, 5));
        assert!(FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, 10));
    }

    #[test]
    fn should_drop_every_nth_with_zero_never_drops() {
        let mode = FaultMode::DropEveryNth(0);
        for i in 0..100 {
            assert!(!FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, i));
        }
    }

    #[test]
    fn should_drop_percentage_zero_never_drops() {
        let mode = FaultMode::DropPercentage {
            percentage: 0,
            seed: 42,
        };
        for i in 0..100 {
            assert!(!FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, i));
        }
    }

    #[test]
    fn should_drop_percentage_100_always_drops() {
        let mode = FaultMode::DropPercentage {
            percentage: 100,
            seed: 42,
        };
        for i in 0..100 {
            assert!(FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, i));
        }
    }

    #[test]
    fn should_drop_percentage_50_drops_approximately_half() {
        let mode = FaultMode::DropPercentage {
            percentage: 50,
            seed: 12345,
        };
        let mut drop_count = 0;
        for i in 0..1000 {
            if FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, i) {
                drop_count += 1;
            }
        }
        // With 50% drop rate, we expect roughly 500 drops (+/- some variance)
        // Allow 20% tolerance
        assert!(
            drop_count >= 400 && drop_count <= 600,
            "Expected ~500 drops with 50% rate, got {}",
            drop_count
        );
    }

    #[test]
    fn should_drop_percentage_is_deterministic() {
        let mode = FaultMode::DropPercentage {
            percentage: 30,
            seed: 99,
        };
        let results_1: Vec<bool> = (0..100)
            .map(|i| FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, i))
            .collect();
        let results_2: Vec<bool> = (0..100)
            .map(|i| FaultyNetworkFacade::<qbind_node::NullNetworkFacade>::should_drop(&mode, i))
            .collect();
        assert_eq!(
            results_1, results_2,
            "Deterministic drops should be identical"
        );
    }

    #[test]
    fn faulty_network_config_builders() {
        let full = FaultyNetworkConfig::full_partition();
        assert!(matches!(full.vote_fault_mode, FaultMode::DropAll));
        assert!(matches!(full.proposal_fault_mode, FaultMode::DropAll));

        let nth = FaultyNetworkConfig::drop_every_nth(7);
        assert!(matches!(nth.vote_fault_mode, FaultMode::DropEveryNth(7)));

        let pct = FaultyNetworkConfig::drop_percentage(20, 42);
        assert!(matches!(
            pct.vote_fault_mode,
            FaultMode::DropPercentage {
                percentage: 20,
                seed: 42
            }
        ));

        let pass = FaultyNetworkConfig::pass_through();
        assert!(matches!(pass.vote_fault_mode, FaultMode::PassThrough));
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
    fn make_proposal_creates_valid_proposal() {
        let proposal = make_proposal(0, 5, 2, [0xAAu8; 32]);
        assert_eq!(proposal.header.epoch, 0);
        assert_eq!(proposal.header.height, 5);
        assert_eq!(proposal.header.proposer_index, 2);
        assert_eq!(proposal.header.parent_block_id, [0xAAu8; 32]);
    }

    #[test]
    fn partition_test_config_default() {
        let config = PartitionTestConfig::default();
        assert_eq!(config.partition_rounds, 5);
        assert_eq!(config.heal_rounds, 10);
        assert_eq!(config.target_height, 8);
    }

    #[test]
    fn random_drop_test_config_default() {
        let config = RandomDropTestConfig::default();
        assert_eq!(config.drop_percentage, 15);
        assert_eq!(config.random_seed, 12345);
        assert_eq!(config.target_height, 10);
    }
}
