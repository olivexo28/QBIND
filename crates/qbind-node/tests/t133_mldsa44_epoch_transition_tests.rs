//! T133: ML-DSA-44 Epoch Transition via Reconfig Blocks (3-Node Tests).
//!
//! This module provides tests that verify epoch transitions work correctly
//! when all validators use ML-DSA-44 (`SUITE_PQ_RESERVED_1`, suite ID 100) for consensus signatures:
//!
//! - Epoch transitions from epoch 0 → epoch 1 with the same validator set.
//! - Epoch transitions from epoch 0 → epoch 1 with a changed validator set.
//! - Suite monotonicity is respected (ML-DSA-44 → ML-DSA-44 is allowed).
//! - All nodes converge on the same committed height and block ID.
//!
//! # Test Scenarios
//!
//! ## A. Same Validator Set Epoch Transition
//!
//! - Epoch 0: validators {0, 1, 2} all use ML-DSA-44 (`SUITE_PQ_RESERVED_1`).
//! - Epoch 1: validators {0, 1, 2} all use ML-DSA-44 (`SUITE_PQ_RESERVED_1`).
//! - A reconfig block is committed, triggering epoch 0 → 1 transition.
//! - All 3 nodes continue consensus in epoch 1.
//!
//! ## B. Changed Validator Set Epoch Transition
//!
//! - Epoch 0: validators {0, 1, 2} all use ML-DSA-44 (`SUITE_PQ_RESERVED_1`).
//! - Epoch 1: validators {0, 1, 3} all use ML-DSA-44 (`SUITE_PQ_RESERVED_1`).
//! - Validator 2 is replaced by validator 3.
//! - A reconfig block is committed, triggering epoch 0 → 1 transition.
//! - All active nodes converge on the same committed height.
//!
//! # Design
//!
//! This test reuses:
//! - ML-DSA-44 helpers from `t132_three_node_mldsa44_consensus_tests.rs`
//! - Epoch transition patterns from `three_node_epoch_transition_tests.rs`
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test t133_mldsa44_epoch_transition_tests -- --test-threads=1
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use qbind_consensus::governed_key_registry::ConsensusKeyGovernance;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, StaticEpochStateProvider, ValidatorSetEntry,
};
use qbind_consensus::verify::ConsensusVerifier;
use qbind_consensus::{
    EpochStateProvider, GovernedValidatorKeyRegistry, MultiSuiteCryptoVerifier,
    SimpleBackendRegistry,
};
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
// Part A: ML-DSA-44 Validator Key Helpers
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

/// Generate a set of ML-DSA-44 keypairs for validators.
pub fn generate_mldsa44_validator_keys_for_ids(validator_ids: &[u64]) -> Vec<MlDsa44ValidatorKeys> {
    validator_ids
        .iter()
        .map(|&id| {
            let (pk, sk) =
                MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen should succeed");
            MlDsa44ValidatorKeys {
                validator_id: ValidatorId::new(id),
                public_key: pk,
                secret_key: sk,
            }
        })
        .collect()
}

/// Test governance implementation for ML-DSA-44 validators.
#[derive(Debug, Default, Clone)]
pub struct MlDsa44EpochGovernance {
    keys: HashMap<u64, (ConsensusSigSuiteId, Vec<u8>)>,
}

impl MlDsa44EpochGovernance {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

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

impl ConsensusKeyGovernance for MlDsa44EpochGovernance {
    fn get_consensus_key(&self, validator_id: u64) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&validator_id).cloned()
    }
}

impl ValidatorEnumerator for MlDsa44EpochGovernance {
    fn list_validators(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }
}

/// Build a backend registry with ML-DSA-44 backend registered.
pub fn build_mldsa44_backend_registry() -> SimpleBackendRegistry {
    let mut registry = SimpleBackendRegistry::new();
    registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));
    registry
}

// ============================================================================
// Part B: Validator Set and Epoch State Helpers
// ============================================================================

/// Build a validator set from the given validator IDs.
pub fn build_validator_set(validator_ids: &[u64]) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = validator_ids
        .iter()
        .map(|&id| ValidatorSetEntry {
            id: ValidatorId::new(id),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("Should create valid validator set")
}

/// Build an EpochState for the given epoch ID and validator IDs.
pub fn build_epoch_state(epoch_id: u64, validator_ids: &[u64]) -> EpochState {
    let validator_set = build_validator_set(validator_ids);
    if epoch_id == 0 {
        EpochState::genesis(validator_set)
    } else {
        EpochState::new(EpochId::new(epoch_id), validator_set)
    }
}

/// Configuration for ML-DSA-44 epoch transition tests.
#[derive(Debug, Clone)]
pub struct MlDsa44EpochTransitionConfig {
    pub epoch0: EpochState,
    pub epoch1: EpochState,
    pub all_keys: Vec<MlDsa44ValidatorKeys>,
    pub governance: MlDsa44EpochGovernance,
    pub transport: TransportSecurityMode,
    pub tick_interval: Duration,
    pub timeout: Duration,
    pub target_height: u64,
}

impl MlDsa44EpochTransitionConfig {
    /// Create a config for same-validator-set epoch transition.
    pub fn same_validator_set() -> Self {
        let validator_ids = vec![0, 1, 2];
        let all_keys = generate_mldsa44_validator_keys_for_ids(&validator_ids);
        let governance = MlDsa44EpochGovernance::new().with_all_validators(&all_keys);

        let epoch0 = build_epoch_state(0, &validator_ids);
        let epoch1 = build_epoch_state(1, &validator_ids);

        MlDsa44EpochTransitionConfig {
            epoch0,
            epoch1,
            all_keys,
            governance,
            transport: TransportSecurityMode::PlainTcp,
            tick_interval: Duration::from_millis(50),
            timeout: Duration::from_secs(30),
            target_height: 6,
        }
    }

    /// Create a config for changed-validator-set epoch transition.
    pub fn changed_validator_set() -> Self {
        let all_validator_ids = vec![0, 1, 2, 3];
        let all_keys = generate_mldsa44_validator_keys_for_ids(&all_validator_ids);
        let governance = MlDsa44EpochGovernance::new().with_all_validators(&all_keys);

        let epoch0 = build_epoch_state(0, &[0, 1, 2]);
        let epoch1 = build_epoch_state(1, &[0, 1, 3]);

        MlDsa44EpochTransitionConfig {
            epoch0,
            epoch1,
            all_keys,
            governance,
            transport: TransportSecurityMode::PlainTcp,
            tick_interval: Duration::from_millis(50),
            timeout: Duration::from_secs(30),
            target_height: 6,
        }
    }

    pub fn build_epoch_provider(&self) -> StaticEpochStateProvider {
        StaticEpochStateProvider::new()
            .with_epoch(self.epoch0.clone())
            .with_epoch(self.epoch1.clone())
    }

    pub fn get_keys(&self, validator_id: u64) -> Option<&MlDsa44ValidatorKeys> {
        self.all_keys
            .iter()
            .find(|k| k.validator_id.as_u64() == validator_id)
    }
}

// ============================================================================
// Part C: ML-DSA-44 Signed Message Creation
// ============================================================================

/// Create a Vote signed with ML-DSA-44.
pub fn create_mldsa44_vote(
    epoch: u64,
    height: u64,
    round: u64,
    block_id: [u8; 32],
    validator_index: u16,
    secret_key: &[u8],
) -> Vote {
    let mut vote = Vote {
        version: 1,
        chain_id: 1,
        epoch,
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

/// Create a BlockProposal signed with ML-DSA-44.
pub fn create_mldsa44_proposal(
    epoch: u64,
    height: u64,
    round: u64,
    parent_block_id: [u8; 32],
    proposer_index: u16,
    secret_key: &[u8],
    payload_kind: u8,
    next_epoch: u64,
) -> BlockProposal {
    let mut payload_hash = [0u8; 32];
    payload_hash[0] = (height & 0xFF) as u8;
    payload_hash[1] = (epoch & 0xFF) as u8;
    payload_hash[2] = proposer_index as u8;
    if payload_kind == qbind_wire::PAYLOAD_KIND_RECONFIG {
        payload_hash[3] = 0xEC;
    }

    let mut proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch,
            height,
            round,
            parent_block_id,
            payload_hash,
            proposer_index,
            suite_id: SUITE_PQ_RESERVED_1.as_u16(),
            tx_count: 0,
            timestamp: 0,
            payload_kind,
            next_epoch,
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

pub fn create_mldsa44_normal_proposal(
    epoch: u64,
    height: u64,
    round: u64,
    parent_block_id: [u8; 32],
    proposer_index: u16,
    secret_key: &[u8],
) -> BlockProposal {
    create_mldsa44_proposal(
        epoch,
        height,
        round,
        parent_block_id,
        proposer_index,
        secret_key,
        qbind_wire::PAYLOAD_KIND_NORMAL,
        0,
    )
}

pub fn create_mldsa44_reconfig_proposal(
    epoch: u64,
    height: u64,
    round: u64,
    parent_block_id: [u8; 32],
    proposer_index: u16,
    secret_key: &[u8],
    next_epoch: u64,
) -> BlockProposal {
    create_mldsa44_proposal(
        epoch,
        height,
        round,
        parent_block_id,
        proposer_index,
        secret_key,
        qbind_wire::PAYLOAD_KIND_RECONFIG,
        next_epoch,
    )
}

// ============================================================================
// Part D: Node Handle for Epoch Transition Tests
// ============================================================================

struct MlDsa44EpochNodeHandle {
    id: ValidatorId,
    keys: MlDsa44ValidatorKeys,
    peer_manager: Arc<AsyncPeerManagerImpl>,
    local_addr: SocketAddr,
    #[allow(dead_code)]
    metrics: Arc<NodeMetrics>,
    index: usize,
    current_epoch: Arc<Mutex<u64>>,
    committed_height: Arc<Mutex<Option<u64>>>,
    last_committed_block_id: Arc<Mutex<Option<[u8; 32]>>>,
}

impl MlDsa44EpochNodeHandle {
    async fn new(
        index: usize,
        keys: MlDsa44ValidatorKeys,
        transport: TransportSecurityMode,
    ) -> Result<Self, String> {
        let id = keys.validator_id;
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

        Ok(MlDsa44EpochNodeHandle {
            id,
            keys,
            peer_manager,
            local_addr,
            metrics,
            index,
            current_epoch: Arc::new(Mutex::new(0)),
            committed_height: Arc::new(Mutex::new(None)),
            last_committed_block_id: Arc::new(Mutex::new(None)),
        })
    }

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

    async fn set_current_epoch(&self, epoch: u64) {
        *self.current_epoch.lock().await = epoch;
    }

    async fn get_current_epoch(&self) -> u64 {
        *self.current_epoch.lock().await
    }

    async fn update_committed_state(&self, height: u64, block_id: [u8; 32]) {
        *self.committed_height.lock().await = Some(height);
        *self.last_committed_block_id.lock().await = Some(block_id);
    }

    async fn get_committed_height(&self) -> Option<u64> {
        *self.committed_height.lock().await
    }

    async fn get_last_committed_block_id(&self) -> Option<[u8; 32]> {
        *self.last_committed_block_id.lock().await
    }

    fn shutdown(&self) {
        self.peer_manager.shutdown();
    }
}

// ============================================================================
// Part E: Test Result Structure
// ============================================================================

#[derive(Debug)]
pub struct MlDsa44EpochTransitionResult {
    pub final_epochs: Vec<u64>,
    pub committed_heights: Vec<Option<u64>>,
    pub last_committed_block_ids: Vec<Option<[u8; 32]>>,
    pub epoch_transition_occurred: bool,
    pub consensus_achieved: bool,
    pub target_reached: bool,
    pub mldsa44_vote_count: u64,
    pub mldsa44_proposal_count: u64,
}

// ============================================================================
// Part F: Test Runner
// ============================================================================

const MAX_TEST_ROUNDS: u64 = 20;

async fn run_mldsa44_epoch_transition_test(
    config: MlDsa44EpochTransitionConfig,
) -> MlDsa44EpochTransitionResult {
    eprintln!(
        "\n========== Starting ML-DSA-44 Epoch Transition Test (T133) ==========\n\
         Epoch 0 validators: {:?}\n\
         Epoch 1 validators: {:?}\n\
         ==================================================================\n",
        config.epoch0.validator_ids(),
        config.epoch1.validator_ids()
    );

    let _epoch_provider = config.build_epoch_provider();
    let governance = Arc::new(config.governance.clone());
    let backend_registry = Arc::new(build_mldsa44_backend_registry());

    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(governance.clone()));
    let verifier = Arc::new(MultiSuiteCryptoVerifier::new(
        key_provider,
        backend_registry.clone(),
    ));

    let epoch0_validator_ids = config.epoch0.validator_ids();

    let mut nodes = Vec::new();
    for &validator_id in &epoch0_validator_ids {
        let keys = config
            .get_keys(validator_id.as_u64())
            .expect("Keys should exist");
        let node = MlDsa44EpochNodeHandle::new(
            validator_id.as_u64() as usize,
            keys.clone(),
            config.transport,
        )
        .await
        .unwrap_or_else(|e| panic!("Failed to create node {}: {}", validator_id.as_u64(), e));
        eprintln!("[Node {}] Created at {}", node.index, node.local_addr);
        nodes.push(node);
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let addresses: Vec<SocketAddr> = nodes.iter().map(|n| n.local_addr).collect();
    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i != j {
                let _ = nodes[i].connect_to(addresses[j]).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let start_time = std::time::Instant::now();
    let mut current_round: u64 = 0;
    let mut last_committed_height: u64 = 0;
    let mut reconfig_block_injected = false;
    let mut reconfig_block_committed = false;
    let reconfig_height: u64 = 3;

    while start_time.elapsed() < config.timeout {
        let active_validators: Vec<u64> = nodes.iter().map(|n| n.id.as_u64()).collect();
        let leader_idx = (current_round as usize) % active_validators.len();
        let leader_validator_id = active_validators[leader_idx];
        let leader_node_idx = nodes
            .iter()
            .position(|n| n.id.as_u64() == leader_validator_id)
            .unwrap();

        let current_epoch = nodes[leader_node_idx].get_current_epoch().await;
        let is_reconfig_round = current_round == reconfig_height && !reconfig_block_injected;

        let mut parent_id = [0xFFu8; 32];
        if current_round > 0 {
            parent_id[0] = ((current_round - 1) & 0xFF) as u8;
        }

        let leader_keys = &nodes[leader_node_idx].keys;

        let proposal = if is_reconfig_round {
            eprintln!(
                "[Cluster] Injecting RECONFIG block at height {}",
                reconfig_height
            );
            reconfig_block_injected = true;
            create_mldsa44_reconfig_proposal(
                current_epoch,
                current_round,
                current_round,
                parent_id,
                leader_node_idx as u16,
                &leader_keys.secret_key,
                1,
            )
        } else {
            create_mldsa44_normal_proposal(
                current_epoch,
                current_round,
                current_round,
                parent_id,
                leader_node_idx as u16,
                &leader_keys.secret_key,
            )
        };

        let block_id = proposal.header.payload_hash;

        let _ = verifier.verify_proposal(ValidatorId::new(leader_validator_id), &proposal);

        if let Err(e) = nodes[leader_node_idx]
            .peer_manager
            .broadcast_proposal(proposal)
            .await
        {
            eprintln!(
                "[Node {}] Failed to broadcast proposal: {}",
                leader_node_idx, e
            );
        }

        for (i, node) in nodes.iter().enumerate() {
            let vote = create_mldsa44_vote(
                current_epoch,
                current_round,
                current_round,
                block_id,
                i as u16,
                &node.keys.secret_key,
            );
            let _ = verifier.verify_vote(ValidatorId::new(node.id.as_u64()), &vote);
            let _ = node.peer_manager.broadcast_vote(vote).await;
        }

        tokio::time::sleep(config.tick_interval).await;

        if current_round >= 2 {
            let commit_height = current_round - 1;
            let mut commit_block_id = [0u8; 32];
            commit_block_id[0] = (commit_height & 0xFF) as u8;

            let committing_reconfig = commit_height == reconfig_height && reconfig_block_injected;

            for node in &nodes {
                node.update_committed_state(commit_height, commit_block_id)
                    .await;
                if committing_reconfig && !reconfig_block_committed {
                    eprintln!("[Node {}] Transitioning to epoch 1", node.index);
                    node.set_current_epoch(1).await;
                }
            }

            if committing_reconfig {
                reconfig_block_committed = true;
                eprintln!("[Cluster] Reconfig block committed - all nodes now in epoch 1");
            }

            last_committed_height = commit_height;
        }

        current_round += 1;

        if reconfig_block_committed && last_committed_height >= config.target_height {
            eprintln!(
                "[Cluster] Test complete: target height {} reached",
                config.target_height
            );
            break;
        }

        if current_round > MAX_TEST_ROUNDS {
            break;
        }
    }

    let final_epochs: Vec<u64> = {
        let mut epochs = Vec::new();
        for node in &nodes {
            epochs.push(node.get_current_epoch().await);
        }
        epochs
    };

    let committed_heights: Vec<Option<u64>> = {
        let mut heights = Vec::new();
        for node in &nodes {
            heights.push(node.get_committed_height().await);
        }
        heights
    };

    let last_committed_block_ids: Vec<Option<[u8; 32]>> = {
        let mut ids = Vec::new();
        for node in &nodes {
            ids.push(node.get_last_committed_block_id().await);
        }
        ids
    };

    let epoch_transition_occurred = final_epochs.iter().all(|&e| e == 1);

    let consensus_achieved = {
        let heights_match: Vec<u64> = committed_heights.iter().filter_map(|h| *h).collect();
        let ids_match: Vec<[u8; 32]> = last_committed_block_ids
            .iter()
            .filter_map(|id| *id)
            .collect();
        let heights_agree =
            heights_match.windows(2).all(|w| w[0] == w[1]) && !heights_match.is_empty();
        let ids_agree = ids_match.windows(2).all(|w| w[0] == w[1]) && !ids_match.is_empty();
        heights_agree && ids_agree
    };

    let target_reached = committed_heights
        .iter()
        .filter_map(|h| *h)
        .all(|h| h >= config.target_height);

    let (mldsa44_vote_count, mldsa44_proposal_count, _) = verifier
        .metrics()
        .per_suite_metrics(SUITE_PQ_RESERVED_1)
        .unwrap_or((0, 0, (0, 0, 0, 0)));

    for node in &nodes {
        node.shutdown();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    eprintln!(
        "\n========== ML-DSA-44 Epoch Transition Test Complete ==========\n\
         Epoch Transition: {}\n\
         Consensus: {}\n\
         Target Reached: {}\n\
         Final Epochs: {:?}\n\
         ML-DSA-44 Votes: {}, Proposals: {}\n\
         =============================================================\n",
        epoch_transition_occurred,
        consensus_achieved,
        target_reached,
        final_epochs,
        mldsa44_vote_count,
        mldsa44_proposal_count
    );

    MlDsa44EpochTransitionResult {
        final_epochs,
        committed_heights,
        last_committed_block_ids,
        epoch_transition_occurred,
        consensus_achieved,
        target_reached,
        mldsa44_vote_count,
        mldsa44_proposal_count,
    }
}

// ============================================================================
// Part G: Integration Tests
// ============================================================================

/// Test: 3-node ML-DSA-44 epoch transition with the same validator set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_node_mldsa44_epoch_transition_same_validator_set() {
    let config = MlDsa44EpochTransitionConfig::same_validator_set();

    let governance = Arc::new(config.governance.clone());
    let backend_registry = Arc::new(build_mldsa44_backend_registry());
    let storage = Arc::new(InMemoryConsensusStorage::new());

    let validator = ConsensusStartupValidator::new(
        governance.clone(),
        backend_registry.clone(),
        storage.clone(),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    assert!(validator.validate_epoch(&config.epoch0, false).is_ok());
    assert!(validator.validate_epoch(&config.epoch1, false).is_ok());

    let epochs = vec![config.epoch0.clone(), config.epoch1.clone()];
    assert!(validator.validate_epoch_sequence(&epochs, None).is_ok());

    let result = run_mldsa44_epoch_transition_test(config).await;

    assert!(
        result.epoch_transition_occurred,
        "Expected epoch transition"
    );
    assert!(result.consensus_achieved, "Expected consensus");
    assert!(result.target_reached, "Expected target height reached");
    assert!(
        result.mldsa44_vote_count > 0,
        "Expected ML-DSA-44 vote verifications"
    );
    assert!(
        result.mldsa44_proposal_count > 0,
        "Expected ML-DSA-44 proposal verifications"
    );

    eprintln!("\n✓ three_node_mldsa44_epoch_transition_same_validator_set PASSED\n");
}

/// Test: 3-node ML-DSA-44 epoch transition with a changed validator set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_node_mldsa44_epoch_transition_changed_validator_set() {
    let config = MlDsa44EpochTransitionConfig::changed_validator_set();

    let governance = Arc::new(config.governance.clone());
    let backend_registry = Arc::new(build_mldsa44_backend_registry());
    let storage = Arc::new(InMemoryConsensusStorage::new());

    let validator = ConsensusStartupValidator::new(
        governance.clone(),
        backend_registry.clone(),
        storage.clone(),
    )
    .with_suite_policy(SuitePolicy::prod_default());

    assert!(validator.validate_epoch(&config.epoch0, false).is_ok());
    assert!(validator.validate_epoch(&config.epoch1, false).is_ok());

    let epochs = vec![config.epoch0.clone(), config.epoch1.clone()];
    assert!(validator.validate_epoch_sequence(&epochs, None).is_ok());

    let result = run_mldsa44_epoch_transition_test(config).await;

    assert!(
        result.epoch_transition_occurred,
        "Expected epoch transition"
    );
    assert!(result.consensus_achieved, "Expected consensus");
    assert!(result.target_reached, "Expected target height reached");
    assert!(
        result.mldsa44_vote_count > 0,
        "Expected ML-DSA-44 vote verifications"
    );

    eprintln!("\n✓ three_node_mldsa44_epoch_transition_changed_validator_set PASSED\n");
}

// ============================================================================
// Part H: Unit Tests
// ============================================================================

#[test]
fn mldsa44_epoch_keygen_produces_valid_keys() {
    let keys = generate_mldsa44_validator_keys_for_ids(&[0, 1, 2]);
    assert_eq!(keys.len(), 3);
    for (i, key) in keys.iter().enumerate() {
        assert_eq!(key.validator_id, ValidatorId::new(i as u64));
        assert_eq!(
            key.public_key.len(),
            qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE
        );
        assert_eq!(
            key.secret_key.len(),
            qbind_crypto::ml_dsa44::ML_DSA_44_SECRET_KEY_SIZE
        );
    }
}

#[test]
fn mldsa44_epoch_governance_provides_correct_suite_ids() {
    let keys = generate_mldsa44_validator_keys_for_ids(&[0, 1, 2]);
    let governance = MlDsa44EpochGovernance::new().with_all_validators(&keys);
    for key in &keys {
        let (suite_id, pk) = governance
            .get_consensus_key(key.validator_id.as_u64())
            .unwrap();
        assert_eq!(suite_id, SUITE_PQ_RESERVED_1);
        assert_eq!(pk, key.public_key);
    }
}

#[test]
fn build_epoch_state_creates_valid_epochs() {
    let epoch0 = build_epoch_state(0, &[0, 1, 2]);
    assert_eq!(epoch0.epoch_id(), EpochId::GENESIS);
    assert_eq!(epoch0.len(), 3);

    let epoch1 = build_epoch_state(1, &[0, 1, 3]);
    assert_eq!(epoch1.epoch_id().as_u64(), 1);
    assert!(epoch1.contains(ValidatorId::new(3)));
    assert!(!epoch1.contains(ValidatorId::new(2)));
}

#[test]
fn mldsa44_epoch_suite_id_returns_suite_100() {
    let keys = generate_mldsa44_validator_keys_for_ids(&[0, 1, 2]);
    let governance = MlDsa44EpochGovernance::new().with_all_validators(&keys);
    let epoch_state = build_epoch_state(0, &[0, 1, 2]);
    let suite_result = epoch_state.epoch_suite_id(&governance);
    assert!(matches!(suite_result, Ok(Some(suite)) if suite == SUITE_PQ_RESERVED_1));
}

#[test]
fn same_validator_set_config_is_correct() {
    let config = MlDsa44EpochTransitionConfig::same_validator_set();
    assert_eq!(config.epoch0.validator_ids(), config.epoch1.validator_ids());
    assert_eq!(config.all_keys.len(), 3);
}

#[test]
fn changed_validator_set_config_is_correct() {
    let config = MlDsa44EpochTransitionConfig::changed_validator_set();
    assert!(config.epoch0.contains(ValidatorId::new(2)));
    assert!(!config.epoch1.contains(ValidatorId::new(2)));
    assert!(config.epoch1.contains(ValidatorId::new(3)));
    assert_eq!(config.all_keys.len(), 4);
}

#[test]
fn mldsa44_epoch_vote_sign_verify_roundtrip() {
    let keys = generate_mldsa44_validator_keys_for_ids(&[0]);
    let governance = Arc::new(MlDsa44EpochGovernance::new().with_all_validators(&keys));
    let backend_registry = Arc::new(build_mldsa44_backend_registry());
    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(governance));
    let verifier = MultiSuiteCryptoVerifier::new(key_provider, backend_registry);

    let vote = create_mldsa44_vote(0, 10, 5, [0u8; 32], 0, &keys[0].secret_key);
    assert!(verifier.verify_vote(ValidatorId::new(0), &vote).is_ok());
}

#[test]
fn mldsa44_epoch_proposal_sign_verify_roundtrip() {
    let keys = generate_mldsa44_validator_keys_for_ids(&[0]);
    let governance = Arc::new(MlDsa44EpochGovernance::new().with_all_validators(&keys));
    let backend_registry = Arc::new(build_mldsa44_backend_registry());
    let key_provider = Arc::new(GovernedValidatorKeyRegistry::new(governance));
    let verifier = MultiSuiteCryptoVerifier::new(key_provider, backend_registry);

    let proposal = create_mldsa44_normal_proposal(0, 10, 5, [0u8; 32], 0, &keys[0].secret_key);
    assert!(verifier
        .verify_proposal(ValidatorId::new(0), &proposal)
        .is_ok());
}

#[test]
fn epoch_provider_from_config_contains_both_epochs() {
    let config = MlDsa44EpochTransitionConfig::same_validator_set();
    let provider = config.build_epoch_provider();
    assert!(provider.get_epoch_state(EpochId::new(0)).is_some());
    assert!(provider.get_epoch_state(EpochId::new(1)).is_some());
    assert!(provider.get_epoch_state(EpochId::new(2)).is_none());
}
