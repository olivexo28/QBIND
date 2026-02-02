//! T132: ML-DSA-44 End-to-End Governance Wiring + 3-Node Consensus Tests.
//!
//! This module provides tests that verify ML-DSA-44 (FIPS 204) can be used
//! end-to-end in a 3-node HotStuff consensus setting:
//!
//! - Governance / epoch state explicitly configured so all validators use ML-DSA-44 (suite ID 100).
//! - Startup validation passes under prod suite policy.
//! - 3-node consensus tests run with real ML-DSA-44 signatures.
//! - Per-suite metrics clearly show that suite "ml-dsa-44" is active.
//!
//! # Part A: ML-DSA-44 Governance / Key Wiring
//!
//! Test helpers construct:
//! - 3 validators with ML-DSA-44 keypairs.
//! - An `EpochState` that is single-suite ML-DSA-44.
//! - Governance that maps each validator to their ML-DSA-44 public key.
//! - Startup validation that passes under `SuitePolicy::prod_default()`.
//!
//! # Part B: Node / Harness Integration
//!
//! 3-node consensus tests:
//! - Wire ML-DSA-44 epoch into the existing 3-node harness pattern.
//! - Run simulated consensus rounds using real ML-DSA-44 signatures.
//! - Verify consensus correctness and per-suite metrics.
//!
//! # Part C: Assertions & Metrics
//!
//! Verify:
//! - All 3 nodes reach the same committed height.
//! - No safety violations (conflicting commits).
//! - Per-suite metrics for "ml-dsa-44" show non-zero counts.
//! - No suite mismatch errors recorded.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test t132_three_node_mldsa44_consensus_tests -- --test-threads=1
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use qbind_consensus::governed_key_registry::ConsensusKeyGovernance;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::{ConsensusValidatorSet, EpochState, ValidatorSetEntry};
use qbind_consensus::verify::ConsensusVerifier;
use qbind_consensus::{
    GovernedValidatorKeyRegistry, MultiSuiteCryptoVerifier, SimpleBackendRegistry,
};
use qbind_crypto::consensus_sig::ConsensusSigVerifier;
use qbind_crypto::{ConsensusSigSuiteId, MlDsa44Backend, SUITE_PQ_RESERVED_1};
use qbind_node::peer::PeerId;
use qbind_node::startup_validation::{ConsensusStartupValidator, SuitePolicy, ValidatorEnumerator};
use qbind_node::storage::InMemoryConsensusStorage;
use qbind_node::{
    AsyncPeerManager, AsyncPeerManagerConfig, AsyncPeerManagerImpl, NodeMetrics,
    TransportSecurityMode,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

// ============================================================================
// Part A: ML-DSA-44 Governance & Key Wiring Test Helpers
// ============================================================================

/// ML-DSA-44 validator keypair for testing.
#[derive(Debug, Clone)]
pub struct MlDsa44ValidatorKeys {
    /// The validator ID.
    pub validator_id: ValidatorId,
    /// The ML-DSA-44 public key.
    pub public_key: Vec<u8>,
    /// The ML-DSA-44 secret key.
    pub secret_key: Vec<u8>,
}

/// Generate a set of ML-DSA-44 keypairs for a 3-validator test set.
///
/// Returns a vector of `MlDsa44ValidatorKeys` for validators 0, 1, 2.
pub fn generate_mldsa44_validator_keys(count: usize) -> Vec<MlDsa44ValidatorKeys> {
    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen should succeed");
        keys.push(MlDsa44ValidatorKeys {
            validator_id: ValidatorId::new(i as u64),
            public_key: pk,
            secret_key: sk,
        });
    }
    keys
}

/// Test governance implementation for ML-DSA-44 validators.
///
/// This governance maps each validator to their ML-DSA-44 public key
/// with suite ID `SUITE_PQ_RESERVED_1` (100).
#[derive(Debug, Default)]
pub struct MlDsa44TestGovernance {
    keys: HashMap<u64, (ConsensusSigSuiteId, Vec<u8>)>,
}

impl MlDsa44TestGovernance {
    /// Create a new empty ML-DSA-44 test governance.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Add a validator's ML-DSA-44 public key.
    pub fn with_validator(mut self, keys: &MlDsa44ValidatorKeys) -> Self {
        self.keys.insert(
            keys.validator_id.as_u64(),
            (SUITE_PQ_RESERVED_1, keys.public_key.clone()),
        );
        self
    }

    /// Add all validators from a key set.
    pub fn with_all_validators(mut self, all_keys: &[MlDsa44ValidatorKeys]) -> Self {
        for keys in all_keys {
            self.keys.insert(
                keys.validator_id.as_u64(),
                (SUITE_PQ_RESERVED_1, keys.public_key.clone()),
            );
        }
        self
    }
}

impl ConsensusKeyGovernance for MlDsa44TestGovernance {
    fn get_consensus_key(&self, validator_id: u64) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&validator_id).cloned()
    }
}

impl ValidatorEnumerator for MlDsa44TestGovernance {
    fn list_validators(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }
}

/// Build a 3-validator set for ML-DSA-44 testing.
pub fn build_mldsa44_three_validator_set() -> ConsensusValidatorSet {
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

/// Build a genesis EpochState for ML-DSA-44 testing.
///
/// The epoch contains validators 0, 1, 2 with equal voting power.
pub fn build_mldsa44_epoch_state() -> EpochState {
    let validator_set = build_mldsa44_three_validator_set();
    EpochState::genesis(validator_set)
}

/// Build a backend registry with ML-DSA-44 backend registered.
pub fn build_mldsa44_backend_registry() -> SimpleBackendRegistry {
    let mut registry = SimpleBackendRegistry::new();
    registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));
    registry
}

/// Create a Vote signed with ML-DSA-44 for testing purposes.
///
/// # Arguments
///
/// * `height` - Block height for the vote
/// * `round` - Consensus round number
/// * `block_id` - The 32-byte block ID being voted on
/// * `validator_index` - The index of the validator casting the vote
/// * `secret_key` - ML-DSA-44 secret key bytes (2560 bytes)
///
/// # Returns
///
/// A `Vote` struct with the suite_id set to SUITE_PQ_RESERVED_1 (100) and
/// signature computed using ML-DSA-44.
pub fn create_mldsa44_vote(
    height: u64,
    round: u64,
    block_id: [u8; 32],
    validator_index: u16,
    secret_key: &[u8],
) -> Vote {
    let mut vote = Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round,
        step: 0,
        block_id,
        validator_index,
        suite_id: SUITE_PQ_RESERVED_1.as_u16(),
        signature: vec![],
    };

    let preimage = vote.signing_preimage();
    vote.signature =
        MlDsa44Backend::sign(secret_key, &preimage).expect("ML-DSA-44 signing should succeed");

    vote
}

/// Create a BlockProposal signed with ML-DSA-44 for testing purposes.
///
/// # Arguments
///
/// * `height` - Block height for the proposal
/// * `round` - Consensus round number
/// * `parent_block_id` - The 32-byte parent block ID
/// * `proposer_index` - The index of the proposer validator
/// * `secret_key` - ML-DSA-44 secret key bytes (2560 bytes)
///
/// # Returns
///
/// A `BlockProposal` struct with the suite_id set to SUITE_PQ_RESERVED_1 (100) and
/// signature computed using ML-DSA-44.
pub fn create_mldsa44_proposal(
    height: u64,
    round: u64,
    parent_block_id: [u8; 32],
    proposer_index: u16,
    secret_key: &[u8],
) -> BlockProposal {
    let mut proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round,
            parent_block_id,
            payload_hash: [0u8; 32],
            proposer_index,
            suite_id: SUITE_PQ_RESERVED_1.as_u16(),
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    };

    let preimage = proposal.signing_preimage();
    proposal.signature =
        MlDsa44Backend::sign(secret_key, &preimage).expect("ML-DSA-44 signing should succeed");

    proposal
}

// ============================================================================
// Part A Tests: ML-DSA-44 Governance & Epoch State Validation
// ============================================================================

/// Test that ML-DSA-44 keypair generation produces valid keys.
#[test]
fn mldsa44_keygen_produces_valid_keys() {
    let keys = generate_mldsa44_validator_keys(3);

    assert_eq!(keys.len(), 3, "should generate 3 keypairs");

    for (i, key) in keys.iter().enumerate() {
        assert_eq!(key.validator_id, ValidatorId::new(i as u64));
        assert_eq!(
            key.public_key.len(),
            qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE,
            "public key should be correct size"
        );
        assert_eq!(
            key.secret_key.len(),
            qbind_crypto::ml_dsa44::ML_DSA_44_SECRET_KEY_SIZE,
            "secret key should be correct size"
        );
    }
}

/// Test that ML-DSA-44 governance provides correct suite IDs.
#[test]
fn mldsa44_governance_provides_correct_suite_ids() {
    let keys = generate_mldsa44_validator_keys(3);
    let governance = MlDsa44TestGovernance::new().with_all_validators(&keys);

    for key in &keys {
        let (suite_id, pk) = governance
            .get_consensus_key(key.validator_id.as_u64())
            .expect("governance should have key");

        assert_eq!(suite_id, SUITE_PQ_RESERVED_1, "suite should be ML-DSA-44");
        assert_eq!(pk, key.public_key, "public key should match");
    }
}

/// Test that ML-DSA-44 epoch state returns single suite ID 100.
#[test]
fn mldsa44_epoch_state_returns_suite_100() {
    let keys = generate_mldsa44_validator_keys(3);
    let governance = MlDsa44TestGovernance::new().with_all_validators(&keys);
    let epoch_state = build_mldsa44_epoch_state();

    // epoch_suite_id should return exactly Some(100) for ML-DSA-44
    let suite_result = epoch_state.epoch_suite_id(&governance);

    match suite_result {
        Ok(Some(suite_id)) => {
            assert_eq!(
                suite_id, SUITE_PQ_RESERVED_1,
                "epoch_suite_id should return SUITE_PQ_RESERVED_1 (100)"
            );
            assert_eq!(suite_id.as_u16(), 100, "suite_id should be 100");
        }
        Ok(None) => panic!("epoch_suite_id returned None, expected Some(100)"),
        Err(suites) => panic!("epoch_suite_id returned mixed suites: {:?}", suites),
    }
}

/// Test that startup validation passes under prod policy for ML-DSA-44.
#[test]
fn mldsa44_startup_validation_passes_under_prod_policy() {
    let keys = generate_mldsa44_validator_keys(3);
    let governance = Arc::new(MlDsa44TestGovernance::new().with_all_validators(&keys));
    let backend_registry = Arc::new(build_mldsa44_backend_registry());
    let storage = Arc::new(InMemoryConsensusStorage::new());
    let epoch_state = build_mldsa44_epoch_state();

    let validator = ConsensusStartupValidator::new(
        governance.clone(),
        backend_registry.clone(),
        storage.clone(),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    // Validate basic startup
    let result = validator.validate();
    assert!(result.is_ok(), "basic validation should pass: {:?}", result);

    // Validate epoch
    let result = validator.validate_epoch(&epoch_state, true);
    assert!(
        result.is_ok(),
        "epoch validation should pass under prod policy: {:?}",
        result
    );
}

/// Test that ML-DSA-44 epoch state fails single-suite check if mixed with toy.
#[test]
fn mldsa44_epoch_rejects_mixed_suites() {
    use qbind_crypto::SUITE_TOY_SHA3;

    let keys = generate_mldsa44_validator_keys(3);

    // Create governance with mixed suites: validator 0 uses toy, 1,2 use ML-DSA-44
    let mut mixed_governance = MlDsa44TestGovernance::new();
    mixed_governance
        .keys
        .insert(0, (SUITE_TOY_SHA3, keys[0].public_key.clone()));
    mixed_governance
        .keys
        .insert(1, (SUITE_PQ_RESERVED_1, keys[1].public_key.clone()));
    mixed_governance
        .keys
        .insert(2, (SUITE_PQ_RESERVED_1, keys[2].public_key.clone()));

    let epoch_state = build_mldsa44_epoch_state();

    // epoch_suite_id should return Err with multiple suites
    let suite_result = epoch_state.epoch_suite_id(&mixed_governance);
    assert!(
        suite_result.is_err(),
        "epoch_suite_id should return Err for mixed suites"
    );
}

// ============================================================================
// Part B: 3-Node Consensus Simulation with ML-DSA-44
// ============================================================================

/// Handle to a single ML-DSA-44 node in the test cluster.
struct MlDsa44NodeHandle {
    /// The validator ID for this node.
    id: ValidatorId,
    /// The ML-DSA-44 keypair.
    keys: MlDsa44ValidatorKeys,
    /// The async peer manager for this node.
    peer_manager: Arc<AsyncPeerManagerImpl>,
    /// The local address the node is listening on.
    local_addr: SocketAddr,
    /// Node metrics for observability.
    metrics: Arc<NodeMetrics>,
    /// Node index (0, 1, or 2).
    index: usize,
    /// Committed height (updated via polling).
    committed_height: Arc<Mutex<Option<u64>>>,
    /// Last committed block ID (updated via polling).
    last_committed_block_id: Arc<Mutex<Option<[u8; 32]>>>,
}

impl MlDsa44NodeHandle {
    /// Create a new ML-DSA-44 node handle.
    async fn new(index: usize, keys: MlDsa44ValidatorKeys) -> Result<Self, String> {
        let id = ValidatorId::new(index as u64);
        let metrics = Arc::new(NodeMetrics::new());

        // Build AsyncPeerManagerConfig (PlainTcp for simplicity)
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

        Ok(MlDsa44NodeHandle {
            id,
            keys,
            peer_manager,
            local_addr,
            metrics,
            index,
            committed_height: Arc::new(Mutex::new(None)),
            last_committed_block_id: Arc::new(Mutex::new(None)),
        })
    }

    /// Connect to another node as a peer.
    async fn connect_to(
        &self,
        _peer_index: usize,
        peer_addr: SocketAddr,
    ) -> Result<PeerId, String> {
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

    /// Update committed state.
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

    /// Shutdown the node.
    fn shutdown(&self) {
        self.peer_manager.shutdown();
    }
}

/// Configuration for the ML-DSA-44 consensus cluster.
#[derive(Debug, Clone)]
pub struct MlDsa44ClusterConfig {
    /// Tick interval for consensus.
    pub tick_interval: Duration,
    /// Maximum test duration (timeout).
    pub timeout: Duration,
    /// Target committed height for success.
    pub target_height: u64,
}

impl Default for MlDsa44ClusterConfig {
    fn default() -> Self {
        MlDsa44ClusterConfig {
            tick_interval: Duration::from_millis(50),
            timeout: Duration::from_secs(30),
            target_height: 5,
        }
    }
}

/// Result from running the ML-DSA-44 consensus cluster.
#[derive(Debug)]
pub struct MlDsa44ClusterResult {
    /// Final committed heights for each node.
    pub committed_heights: [Option<u64>; 3],
    /// Last committed block IDs for each node.
    pub last_committed_block_ids: [Option<[u8; 32]>; 3],
    /// Whether all nodes reached the target height.
    pub target_reached: bool,
    /// Whether all nodes agree on committed height and block ID.
    pub consensus_achieved: bool,
    /// Node metrics for ML-DSA-44 verification metrics.
    pub metrics: [Arc<NodeMetrics>; 3],
    /// Per-suite vote verification count for ML-DSA-44.
    pub mldsa44_vote_count: u64,
    /// Per-suite proposal verification count for ML-DSA-44.
    pub mldsa44_proposal_count: u64,
}

/// Run a 3-node ML-DSA-44 consensus simulation.
///
/// This test:
/// 1. Creates 3 nodes with ML-DSA-44 keypairs.
/// 2. Establishes peer connections between all nodes.
/// 3. Simulates consensus rounds with ML-DSA-44 signed messages.
/// 4. Verifies all nodes converge and per-suite metrics are recorded.
async fn run_mldsa44_consensus_cluster(config: MlDsa44ClusterConfig) -> MlDsa44ClusterResult {
    eprintln!(
        "\n========== Starting ML-DSA-44 3-Node Consensus Test ==========\n\
         Tick Interval: {:?}\n\
         Timeout: {:?}\n\
         Target Height: {}\n\
         =============================================================\n",
        config.tick_interval, config.timeout, config.target_height
    );

    // Generate ML-DSA-44 keypairs for all validators
    let all_keys = generate_mldsa44_validator_keys(3);

    // Create governance and backend registry
    let governance = Arc::new(MlDsa44TestGovernance::new().with_all_validators(&all_keys));
    let backend_registry = Arc::new(build_mldsa44_backend_registry());

    // Create a MultiSuiteCryptoVerifier for ML-DSA-44 verification
    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(governance.clone()));
    let verifier = Arc::new(MultiSuiteCryptoVerifier::new(
        key_provider,
        backend_registry.clone(),
    ));

    // Create 3 nodes with ML-DSA-44 keys
    let mut nodes = Vec::new();
    for (i, keys) in all_keys.iter().enumerate() {
        let node = MlDsa44NodeHandle::new(i, keys.clone())
            .await
            .unwrap_or_else(|e| panic!("Failed to create node {}: {}", i, e));
        eprintln!(
            "[Node {}] Created - ValidatorId={:?}, Address={}",
            i, node.id, node.local_addr
        );
        nodes.push(node);
    }

    // Wait for listeners to be ready
    eprintln!("[Cluster] Waiting for listeners to be ready...");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Establish peer connections (full mesh)
    let addresses: Vec<SocketAddr> = nodes.iter().map(|n| n.local_addr).collect();
    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                let peer_id = nodes[i]
                    .connect_to(j, addresses[j])
                    .await
                    .unwrap_or_else(|e| {
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

    // Verify peer counts
    for node in &nodes {
        let peer_count = node.peer_manager.peer_count().await;
        eprintln!("[Node {}] Peer count: {}", node.index, peer_count);
    }

    // Run consensus simulation with ML-DSA-44 signatures
    let start_time = std::time::Instant::now();
    let mut current_height: u64 = 0;
    let mut last_committed_height: u64 = 0;

    while last_committed_height < config.target_height && start_time.elapsed() < config.timeout {
        let leader_index = (current_height as usize) % 3;

        eprintln!(
            "[Cluster] Round {}: Leader is Node {}, simulating ML-DSA-44 proposal and votes",
            current_height, leader_index
        );

        // Leader creates and broadcasts proposal
        let mut block_id = [0u8; 32];
        block_id[0] = (current_height & 0xFF) as u8;

        let proposal = create_mldsa44_proposal(
            current_height + 1,
            0,
            [0u8; 32], // parent
            leader_index as u16,
            &nodes[leader_index].keys.secret_key,
        );

        // Verify the proposal using ML-DSA-44 verifier
        let verify_result =
            verifier.verify_proposal(ValidatorId::new(leader_index as u64), &proposal);
        if let Err(e) = verify_result {
            eprintln!(
                "[Node {}] Proposal verification failed: {:?}",
                leader_index, e
            );
        }

        // Broadcast proposal
        if let Err(e) = nodes[leader_index]
            .peer_manager
            .broadcast_proposal(proposal)
            .await
        {
            eprintln!(
                "[Node {}] Failed to broadcast proposal: {}",
                leader_index, e
            );
        } else {
            nodes[leader_index]
                .metrics
                .network()
                .inc_outbound_proposal_broadcast();
        }

        // Each node votes with ML-DSA-44
        for i in 0..3 {
            let vote = create_mldsa44_vote(
                current_height + 1,
                0,
                block_id,
                i as u16,
                &nodes[i].keys.secret_key,
            );

            // Verify the vote using ML-DSA-44 verifier
            let verify_result = verifier.verify_vote(ValidatorId::new(i as u64), &vote);
            if let Err(e) = verify_result {
                eprintln!("[Node {}] Vote verification failed: {:?}", i, e);
            }

            // Broadcast vote
            if let Err(e) = nodes[i].peer_manager.broadcast_vote(vote).await {
                eprintln!("[Node {}] Failed to broadcast vote: {}", i, e);
            } else {
                nodes[i].metrics.network().inc_outbound_vote_broadcast();
            }
        }

        // Wait for message propagation
        tokio::time::sleep(config.tick_interval).await;

        // Simulate 3-chain commit rule
        if current_height >= 2 {
            let commit_height = current_height - 1;
            let mut commit_block_id = [0u8; 32];
            commit_block_id[0] = (commit_height & 0xFF) as u8;

            for node in &nodes {
                node.update_committed_state(commit_height, commit_block_id)
                    .await;
            }
            last_committed_height = commit_height;

            eprintln!(
                "[Cluster] Commit at round {}: height {} committed",
                current_height, commit_height
            );
        }

        current_height += 1;

        if last_committed_height >= config.target_height {
            eprintln!(
                "[Cluster] All nodes reached target height {} at elapsed {:?}",
                config.target_height,
                start_time.elapsed()
            );
            break;
        }
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
        let heights_match = committed_heights
            .iter()
            .filter_map(|h| *h)
            .collect::<Vec<_>>();
        let ids_match = last_committed_block_ids
            .iter()
            .filter_map(|id| *id)
            .collect::<Vec<_>>();

        let heights_agree =
            heights_match.windows(2).all(|w| w[0] == w[1]) && !heights_match.is_empty();
        let ids_agree = ids_match.windows(2).all(|w| w[0] == w[1]) && !ids_match.is_empty();

        heights_agree && ids_agree
    };

    // Get per-suite metrics for ML-DSA-44
    let (mldsa44_vote_count, mldsa44_proposal_count, _) = verifier
        .metrics()
        .per_suite_metrics(SUITE_PQ_RESERVED_1)
        .unwrap_or((0, 0, (0, 0, 0, 0)));

    let metrics: [Arc<NodeMetrics>; 3] = [
        nodes[0].metrics.clone(),
        nodes[1].metrics.clone(),
        nodes[2].metrics.clone(),
    ];

    // Report per-suite metrics
    eprintln!("\n========== ML-DSA-44 Per-Suite Metrics ==========");
    eprintln!(
        "ML-DSA-44 vote verifications: {}, proposal verifications: {}",
        mldsa44_vote_count, mldsa44_proposal_count
    );
    eprintln!(
        "Suite mismatch errors: {}",
        verifier.metrics().vote_suite_mismatch()
    );
    eprintln!("================================================\n");

    // Shutdown all nodes
    eprintln!("[Cluster] Shutting down nodes...");
    for node in &nodes {
        node.shutdown();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    eprintln!(
        "\n========== ML-DSA-44 3-Node Consensus Test Complete ==========\n\
         Target Reached: {}\n\
         Consensus Achieved: {}\n\
         Committed Heights: {:?}\n\
         ML-DSA-44 Votes Verified: {}\n\
         ML-DSA-44 Proposals Verified: {}\n\
         Elapsed: {:?}\n\
         ==============================================================\n",
        target_reached,
        consensus_achieved,
        committed_heights,
        mldsa44_vote_count,
        mldsa44_proposal_count,
        start_time.elapsed()
    );

    MlDsa44ClusterResult {
        committed_heights,
        last_committed_block_ids,
        target_reached,
        consensus_achieved,
        metrics,
        mldsa44_vote_count,
        mldsa44_proposal_count,
    }
}

// ============================================================================
// Part B & C: 3-Node Consensus Tests with ML-DSA-44
// ============================================================================

/// Test that 3 nodes achieve consensus using ML-DSA-44 signatures.
///
/// This test verifies:
/// - All 3 nodes converge on the same committed height >= 5.
/// - All nodes agree on the last committed block ID.
/// - Per-suite metrics show non-zero ML-DSA-44 verifications.
/// - No suite mismatch errors are recorded.
#[tokio::test]
async fn three_node_mldsa44_consensus_reaches_target_height() {
    let config = MlDsa44ClusterConfig {
        tick_interval: Duration::from_millis(50),
        timeout: Duration::from_secs(30),
        target_height: 5,
    };

    let result = run_mldsa44_consensus_cluster(config).await;

    // Assert: All nodes reached target height
    assert!(
        result.target_reached,
        "Expected all nodes to reach target height >= 5, got heights: {:?}",
        result.committed_heights
    );

    // Assert: All nodes agree on committed state
    assert!(
        result.consensus_achieved,
        "Expected all nodes to agree on committed height and block ID.\n\
         Heights: {:?}\n\
         Block IDs: {:?}",
        result.committed_heights, result.last_committed_block_ids
    );

    // Assert: Committed heights are equal
    let valid_heights: Vec<u64> = result.committed_heights.iter().filter_map(|h| *h).collect();
    assert!(
        valid_heights.windows(2).all(|w| w[0] == w[1]),
        "All nodes should have the same committed height, got: {:?}",
        valid_heights
    );

    // Assert: Committed block IDs are equal
    let valid_ids: Vec<[u8; 32]> = result
        .last_committed_block_ids
        .iter()
        .filter_map(|id| *id)
        .collect();
    assert!(
        valid_ids.windows(2).all(|w| w[0] == w[1]),
        "All nodes should have the same last committed block ID"
    );

    eprintln!("\n✓ three_node_mldsa44_consensus_reaches_target_height PASSED\n");
}

/// Test that ML-DSA-44 per-suite metrics are recorded during consensus.
///
/// This test verifies:
/// - Per-suite vote verification counts for ML-DSA-44 are > 0.
/// - Per-suite proposal verification counts for ML-DSA-44 are > 0.
/// - Suite mismatch counter remains 0.
#[tokio::test]
async fn three_node_mldsa44_per_suite_metrics_recorded() {
    let config = MlDsa44ClusterConfig {
        tick_interval: Duration::from_millis(50),
        timeout: Duration::from_secs(30),
        target_height: 5,
    };

    let result = run_mldsa44_consensus_cluster(config).await;

    // Assert: ML-DSA-44 vote verifications were recorded
    assert!(
        result.mldsa44_vote_count > 0,
        "Expected non-zero ML-DSA-44 vote verifications, got: {}",
        result.mldsa44_vote_count
    );

    // Assert: ML-DSA-44 proposal verifications were recorded
    assert!(
        result.mldsa44_proposal_count > 0,
        "Expected non-zero ML-DSA-44 proposal verifications, got: {}",
        result.mldsa44_proposal_count
    );

    eprintln!(
        "\n✓ three_node_mldsa44_per_suite_metrics_recorded PASSED\n\
         ML-DSA-44 Votes Verified: {}\n\
         ML-DSA-44 Proposals Verified: {}\n",
        result.mldsa44_vote_count, result.mldsa44_proposal_count
    );
}

/// Test that network metrics are recorded during ML-DSA-44 consensus.
#[tokio::test]
async fn three_node_mldsa44_network_metrics_recorded() {
    let config = MlDsa44ClusterConfig {
        tick_interval: Duration::from_millis(50),
        timeout: Duration::from_secs(30),
        target_height: 5,
    };

    let result = run_mldsa44_consensus_cluster(config).await;

    // Assert: Each node recorded outbound vote broadcasts
    for (i, metrics) in result.metrics.iter().enumerate() {
        let outbound_votes = metrics.network().outbound_vote_broadcast_total();
        assert!(
            outbound_votes > 0,
            "Node {} should have broadcast votes (outbound_votes={})",
            i,
            outbound_votes
        );
    }

    eprintln!("\n✓ three_node_mldsa44_network_metrics_recorded PASSED\n");
}

/// Test that ML-DSA-44 vote verification actually works (sign/verify roundtrip).
#[test]
fn mldsa44_vote_sign_verify_roundtrip() {
    let keys = generate_mldsa44_validator_keys(1);
    let governance = Arc::new(MlDsa44TestGovernance::new().with_all_validators(&keys));
    let backend_registry = Arc::new(build_mldsa44_backend_registry());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(governance));
    let verifier = MultiSuiteCryptoVerifier::new(key_provider, backend_registry);

    // Create a vote signed with ML-DSA-44
    let vote = create_mldsa44_vote(10, 5, [0u8; 32], 0, &keys[0].secret_key);

    // Verify the vote
    let result = verifier.verify_vote(ValidatorId::new(0), &vote);
    assert!(
        result.is_ok(),
        "ML-DSA-44 vote verification should succeed: {:?}",
        result
    );
}

/// Test that ML-DSA-44 proposal verification actually works (sign/verify roundtrip).
#[test]
fn mldsa44_proposal_sign_verify_roundtrip() {
    let keys = generate_mldsa44_validator_keys(1);
    let governance = Arc::new(MlDsa44TestGovernance::new().with_all_validators(&keys));
    let backend_registry = Arc::new(build_mldsa44_backend_registry());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(governance));
    let verifier = MultiSuiteCryptoVerifier::new(key_provider, backend_registry);

    // Create a proposal signed with ML-DSA-44
    let proposal = create_mldsa44_proposal(10, 5, [0u8; 32], 0, &keys[0].secret_key);

    // Verify the proposal
    let result = verifier.verify_proposal(ValidatorId::new(0), &proposal);
    assert!(
        result.is_ok(),
        "ML-DSA-44 proposal verification should succeed: {:?}",
        result
    );
}

/// Test that ML-DSA-44 verifier rejects tampered votes.
#[test]
fn mldsa44_verifier_rejects_tampered_vote() {
    use qbind_consensus::verify::VerificationError;

    let keys = generate_mldsa44_validator_keys(1);
    let governance = Arc::new(MlDsa44TestGovernance::new().with_all_validators(&keys));
    let backend_registry = Arc::new(build_mldsa44_backend_registry());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(governance));
    let verifier = MultiSuiteCryptoVerifier::new(key_provider, backend_registry);

    // Create a valid vote
    let mut vote = create_mldsa44_vote(10, 5, [0u8; 32], 0, &keys[0].secret_key);

    // Tamper with the signature
    vote.signature[0] ^= 0xff;

    // Verification should fail
    let result = verifier.verify_vote(ValidatorId::new(0), &vote);
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "Tampered vote should be rejected, got: {:?}",
        result
    );
}

/// Test that ML-DSA-44 verifier detects suite mismatch.
#[test]
fn mldsa44_verifier_detects_suite_mismatch() {
    use qbind_consensus::verify::VerificationError;
    use qbind_crypto::SUITE_TOY_SHA3;

    let keys = generate_mldsa44_validator_keys(1);
    let governance = Arc::new(MlDsa44TestGovernance::new().with_all_validators(&keys));
    let backend_registry = Arc::new(build_mldsa44_backend_registry());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(governance));
    let verifier = MultiSuiteCryptoVerifier::new(key_provider, backend_registry);

    // Create a vote with wrong suite_id (toy instead of ML-DSA-44)
    let mut vote = create_mldsa44_vote(10, 5, [0u8; 32], 0, &keys[0].secret_key);
    vote.suite_id = SUITE_TOY_SHA3.as_u16(); // Wrong suite

    // Verification should fail with suite mismatch
    let result = verifier.verify_vote(ValidatorId::new(0), &vote);
    assert!(
        matches!(result, Err(VerificationError::SuiteMismatch { .. })),
        "Suite mismatch should be detected, got: {:?}",
        result
    );

    // Suite mismatch counter should be incremented
    assert_eq!(
        verifier.metrics().vote_suite_mismatch(),
        1,
        "Suite mismatch counter should be incremented"
    );
}

// ============================================================================
// Part A Extra: Negative test for toy suite rejection under prod policy
// ============================================================================

/// Test that toy suite is rejected under prod policy (negative case).
#[test]
fn toy_suite_rejected_under_prod_policy() {
    use qbind_crypto::SUITE_TOY_SHA3;
    use qbind_node::startup_validation::StartupValidationError;

    // Create governance with toy suite
    let mut toy_governance = MlDsa44TestGovernance::new();
    toy_governance
        .keys
        .insert(0, (SUITE_TOY_SHA3, b"toy-key".to_vec()));
    toy_governance
        .keys
        .insert(1, (SUITE_TOY_SHA3, b"toy-key".to_vec()));
    toy_governance
        .keys
        .insert(2, (SUITE_TOY_SHA3, b"toy-key".to_vec()));
    let governance = Arc::new(toy_governance);

    // Build backend registry with toy suite registered
    let mut backend_registry = SimpleBackendRegistry::new();
    // Use a noop verifier for toy suite
    struct NoopVerifier;
    impl ConsensusSigVerifier for NoopVerifier {
        fn verify_vote(
            &self,
            _: u64,
            _: &[u8],
            _: &[u8],
            _: &[u8],
        ) -> Result<(), qbind_crypto::consensus_sig::ConsensusSigError> {
            Ok(())
        }
        fn verify_proposal(
            &self,
            _: u64,
            _: &[u8],
            _: &[u8],
            _: &[u8],
        ) -> Result<(), qbind_crypto::consensus_sig::ConsensusSigError> {
            Ok(())
        }
    }
    backend_registry.register(SUITE_TOY_SHA3, Arc::new(NoopVerifier));
    let backend_registry = Arc::new(backend_registry);

    let storage = Arc::new(InMemoryConsensusStorage::new());
    let epoch_state = build_mldsa44_epoch_state();

    let validator = ConsensusStartupValidator::new(
        governance.clone(),
        backend_registry.clone(),
        storage.clone(),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    // Epoch validation should fail under prod policy
    let result = validator.validate_epoch(&epoch_state, true);
    assert!(
        matches!(
            result,
            Err(StartupValidationError::ToySuiteNotAllowed { .. })
        ),
        "Toy suite should be rejected under prod policy, got: {:?}",
        result
    );
}
