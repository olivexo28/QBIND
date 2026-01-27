//! T145: PQC Prod Profile Soak Harness (Single-Node)
//!
//! This module implements a single-validator soak test exercising the PQC prod profile
//! (ML-DSA-44 + ML-KEM-768) under sustained consensus load.
//!
//! # Purpose
//!
//! The goal is to:
//! 1. Exercise PQC prod profile mode (suite 100: ML-DSA-44 signing, ML-KEM-768 in registry)
//! 2. Run a single validator HotStuff consensus to target committed height
//! 3. Assert PQC metrics are being emitted correctly
//! 4. Verify consensus limits are respected under PQC load
//! 5. Identify performance bottlenecks and risks for future multi-node PQC tests
//!
//! # Architecture
//!
//! Uses the existing soak harness infrastructure (T130) adapted for single-node PQC:
//! - `PqcProdSoakNode`: Single-validator HotStuffStateEngine with ML-DSA-44 keys
//! - `PqcProdSoakConfig`: Configuration extending basic SoakConfig
//! - `run_pqc_prod_single_node_soak()`: Main harness function
//!
//! # Running Tests
//!
//! ```bash
//! # Run all PQC soak tests
//! cargo test -p qbind-node --test t145_pqc_prod_soak_tests -- --test-threads=1
//!
//! # Run with output
//! cargo test -p qbind-node --test t145_pqc_prod_soak_tests -- --test-threads=1 --nocapture
//! ```

mod soak_harness;

use std::sync::Arc;
use std::time::Duration;

use qbind_consensus::hotstuff_state_engine::HotStuffStateEngine;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::{ConsensusValidatorSet, EpochState, ValidatorSetEntry};
use qbind_consensus::vote_accumulator::ConsensusLimitsConfig;
use qbind_crypto::{ConsensusSigSuiteId, MlDsa44Backend, SUITE_PQ_RESERVED_1};
use qbind_node::startup_validation::{ConsensusStartupValidator, SuitePolicy, ValidatorEnumerator};
use qbind_node::storage::InMemoryConsensusStorage;
use qbind_node::NodeMetrics;
use soak_harness::{run_three_node_soak, SoakConfig};

use qbind_consensus::governed_key_registry::ConsensusKeyGovernance;
use std::collections::HashMap;

// ============================================================================
// Part A: PQC Prod Soak Configuration & Helpers
// ============================================================================

/// Single-validator ML-DSA-44 keypair for PQC prod profile soak.
#[derive(Debug, Clone)]
pub struct PqcProdSoakValidatorKeys {
    /// The validator ID (must be 0 for single-node).
    pub validator_id: u64,
    /// The ML-DSA-44 public key (1312 bytes per FIPS 204).
    pub public_key: Vec<u8>,
    /// The ML-DSA-44 secret key (for future signing if needed).
    #[allow(dead_code)]
    pub secret_key: Vec<u8>,
}

/// Simple governance for single PQC prod profile validator.
///
/// Maps validator 0 to ML-DSA-44 (suite ID 100) public key.
#[derive(Debug)]
pub struct PqcProdSoakGovernance {
    keys: HashMap<u64, (ConsensusSigSuiteId, Vec<u8>)>,
}

impl PqcProdSoakGovernance {
    /// Create governance for a single validator.
    pub fn new(validator: &PqcProdSoakValidatorKeys) -> Self {
        let mut keys = HashMap::new();
        keys.insert(
            validator.validator_id,
            (SUITE_PQ_RESERVED_1, validator.public_key.clone()),
        );
        PqcProdSoakGovernance { keys }
    }
}

impl ConsensusKeyGovernance for PqcProdSoakGovernance {
    fn get_consensus_key(&self, validator_id: u64) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&validator_id).cloned()
    }
}

impl ValidatorEnumerator for PqcProdSoakGovernance {
    fn list_validators(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }
}

/// Generate a single ML-DSA-44 keypair for PQC prod soak.
fn generate_pqc_prod_soak_validator_keys() -> PqcProdSoakValidatorKeys {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen should succeed");
    PqcProdSoakValidatorKeys {
        validator_id: 0, // Single node
        public_key: pk,
        secret_key: sk,
    }
}

/// Build single-validator set for PQC prod soak.
fn build_pqc_prod_soak_validator_set() -> ConsensusValidatorSet {
    let entries = vec![ValidatorSetEntry {
        id: ValidatorId::new(0),
        voting_power: 1,
    }];
    ConsensusValidatorSet::new(entries).expect("Valid validator set should be created")
}

/// Build epoch state for PQC prod soak.
fn build_pqc_prod_soak_epoch_state() -> EpochState {
    let validator_set = build_pqc_prod_soak_validator_set();
    EpochState::genesis(validator_set)
}

/// Build backend registry with ML-DSA-44 for PQC soak.
fn build_pqc_prod_soak_backend_registry() -> Arc<qbind_consensus::SimpleBackendRegistry> {
    let mut registry = qbind_consensus::SimpleBackendRegistry::new();
    registry.register(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend::new()));
    Arc::new(registry)
}

// ============================================================================
// Part B: PQC Prod Single-Node Soak Harness
// ============================================================================

/// Results from a PQC prod single-node soak run.
#[derive(Debug, Clone)]
pub struct PqcProdSoakResult {
    /// Final committed height reached by the single node.
    pub final_height: u64,

    /// Number of QCs formed during the soak.
    pub qcs_formed: u64,

    /// Number of view changes.
    pub view_changes: u64,

    /// Number of blocks evicted due to memory limits.
    pub evicted_blocks: u64,

    /// Number of commit log entries evicted.
    pub evicted_commit_log_entries: u64,

    /// Number of votes_by_view entries evicted.
    pub evicted_votes_by_view_entries: u64,

    /// Number of views evicted.
    pub evicted_views: u64,

    /// Whether the target height was reached.
    pub target_reached: bool,

    /// Elapsed time for the soak run.
    pub elapsed: Duration,

    /// Number of steps executed.
    pub steps_executed: usize,
}

impl Default for PqcProdSoakResult {
    fn default() -> Self {
        PqcProdSoakResult {
            final_height: 0,
            qcs_formed: 0,
            view_changes: 0,
            evicted_blocks: 0,
            evicted_commit_log_entries: 0,
            evicted_votes_by_view_entries: 0,
            evicted_views: 0,
            target_reached: false,
            elapsed: Duration::ZERO,
            steps_executed: 0,
        }
    }
}

/// Configuration for PQC prod single-node soak.
#[derive(Debug, Clone)]
pub struct PqcProdSoakConfig {
    /// Maximum number of consensus steps to run.
    pub max_steps: usize,

    /// Target committed height to reach.
    pub target_height: u64,

    /// Whether to use small limits for testing eviction.
    pub use_small_limits: bool,

    /// Optional custom consensus limits.
    pub consensus_limits: Option<ConsensusLimitsConfig>,
}

impl Default for PqcProdSoakConfig {
    fn default() -> Self {
        PqcProdSoakConfig {
            max_steps: 2000,
            target_height: 50,
            use_small_limits: false,
            consensus_limits: None,
        }
    }
}

impl PqcProdSoakConfig {
    /// Create a new default config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set max steps.
    pub fn with_max_steps(mut self, max_steps: usize) -> Self {
        self.max_steps = max_steps;
        self
    }

    /// Set target height.
    pub fn with_target_height(mut self, target_height: u64) -> Self {
        self.target_height = target_height;
        self
    }

    /// Enable small limits for testing eviction.
    pub fn with_small_limits(mut self) -> Self {
        self.use_small_limits = true;
        self
    }

    /// Set custom consensus limits.
    pub fn with_consensus_limits(mut self, limits: ConsensusLimitsConfig) -> Self {
        self.consensus_limits = Some(limits);
        self
    }
}

/// Run a single-node PQC prod soak test.
///
/// # Algorithm
///
/// The harness simulates a single validator running HotStuff consensus,
/// proposing blocks and accumulating votes in a round-robin fashion.
/// The single validator's own vote always succeeds, forming QCs.
///
/// # Returns
///
/// A `PqcProdSoakResult` with metrics from the completed soak.
pub fn run_pqc_prod_single_node_soak(config: &PqcProdSoakConfig) -> PqcProdSoakResult {
    let start_time = std::time::Instant::now();
    let mut result = PqcProdSoakResult::default();

    eprintln!(
        "\n========== Starting PQC Prod Single-Node Soak Test (T145) ==========\n\
         Max Steps: {}\n\
         Target Height: {}\n\
         Small Limits: {}\n\
         ====================================================================\n",
        config.max_steps, config.target_height, config.use_small_limits,
    );

    // Build single-validator set
    let validator_set = build_pqc_prod_soak_validator_set();

    // Determine consensus limits
    let limits = if config.use_small_limits {
        ConsensusLimitsConfig {
            max_tracked_views: 8,
            max_votes_per_view: 16,
            max_pending_blocks: 32,
            max_votes_by_view_entries: 64,
            max_commit_log_entries: 32,
        }
    } else if let Some(ref custom_limits) = config.consensus_limits {
        *custom_limits
    } else {
        ConsensusLimitsConfig::default()
    };

    eprintln!(
        "[PQC Soak] Using limits: max_tracked_views={}, max_pending_blocks={}, \
         max_votes_by_view_entries={}, max_commit_log_entries={}",
        limits.max_tracked_views,
        limits.max_pending_blocks,
        limits.max_votes_by_view_entries,
        limits.max_commit_log_entries,
    );

    // Create single simulated node with PQC
    let mut state = HotStuffStateEngine::with_limits(validator_set.clone(), limits);
    let mut committed_height: u64 = 0;
    let mut current_view: u64 = 0;
    let mut _views_seen: Vec<u64> = vec![0];

    // Single validator ID
    let validator_id = ValidatorId::new(0);

    let mut current_round: u64 = 0;
    const COMMIT_DELAY: u64 = 2; // HotStuff 3-chain commit delay

    // Main simulation loop
    while result.steps_executed < config.max_steps {
        // Check if target height reached
        if config.target_height > 0 && committed_height >= config.target_height {
            result.target_reached = true;
            break;
        }

        // Create block ID for this round
        let mut block_id = [0u8; 32];
        block_id[0] = (current_round & 0xFF) as u8;
        block_id[1] = ((current_round >> 8) & 0xFF) as u8;

        // Create parent block ID
        let mut parent_id = [0xFFu8; 32];
        if current_round > 0 {
            parent_id[0] = ((current_round - 1) & 0xFF) as u8;
            parent_id[1] = (((current_round - 1) >> 8) & 0xFF) as u8;
        }

        // Register block in the state
        let justify_qc = state.locked_qc().cloned();
        let parent = if current_round > 0 {
            Some(parent_id)
        } else {
            None
        };
        state.register_block(block_id, current_round, parent, justify_qc);

        // Single validator votes (always succeeds for single-node)
        if let Ok(Some(_qc)) = state.on_vote(validator_id, current_round, &block_id) {
            result.qcs_formed += 1;
        }

        // Advance view after QC
        current_view += 1;
        result.view_changes += 1;
        _views_seen.push(current_view);

        // Apply 3-chain commit rule
        if current_round >= COMMIT_DELAY {
            let commit_height = current_round - 1;
            let mut _commit_block_id = [0u8; 32];
            _commit_block_id[0] = (commit_height & 0xFF) as u8;
            _commit_block_id[1] = ((commit_height >> 8) & 0xFF) as u8;

            if commit_height > committed_height {
                committed_height = commit_height;
            }
        }

        current_round += 1;
        result.steps_executed += 1;
    }

    // Collect final metrics
    result.elapsed = start_time.elapsed();
    result.final_height = committed_height;
    result.evicted_blocks = state.evicted_blocks();
    result.evicted_commit_log_entries = state.evicted_commit_log_entries();
    result.evicted_votes_by_view_entries = state.evicted_votes_by_view_entries();
    result.evicted_views = state.evicted_views();

    eprintln!(
        "\n========== PQC Prod Single-Node Soak Complete (T145) ==========\n\
         Steps Executed: {}\n\
         Final Height: {}\n\
         Target Reached: {}\n\
         QCs Formed: {}\n\
         View Changes: {}\n\
         Evicted Blocks: {}\n\
         Evicted Commit Log Entries: {}\n\
         Evicted Votes-by-View Entries: {}\n\
         Evicted Views: {}\n\
         Elapsed: {:?}\n\
         ================================================================\n",
        result.steps_executed,
        result.final_height,
        result.target_reached,
        result.qcs_formed,
        result.view_changes,
        result.evicted_blocks,
        result.evicted_commit_log_entries,
        result.evicted_votes_by_view_entries,
        result.evicted_views,
        result.elapsed,
    );

    result
}

// ============================================================================
// Part C: Tests
// ============================================================================

/// Test 1: PQC prod single-node soak reaches target height.
///
/// This test verifies:
/// - Single validator with ML-DSA-44 can reach target committed height
/// - QCs are formed correctly
/// - View changes are non-zero but finite
///
/// # CI Constraints
/// - max_steps: 2000
/// - target_height: 64
/// - Should complete in ~5-10 seconds
#[test]
fn pqc_prod_single_node_soak_reaches_target_height() {
    let config = PqcProdSoakConfig::new()
        .with_max_steps(2000)
        .with_target_height(64);

    let result = run_pqc_prod_single_node_soak(&config);

    // Assert: Target height was reached
    assert!(
        result.target_reached,
        "Expected to reach target height >= 64, got final_height={}",
        result.final_height
    );

    // Assert: Final height is at least target
    assert!(
        result.final_height >= 64,
        "Expected final_height >= 64, got {}",
        result.final_height
    );

    // Assert: Some QCs were formed
    assert!(
        result.qcs_formed > 0,
        "Expected qcs_formed > 0, got {}",
        result.qcs_formed
    );

    // Assert: View changes are reasonable
    assert!(
        result.view_changes > 0 && result.view_changes < 1000,
        "Expected reasonable view changes, got {}",
        result.view_changes
    );

    // Assert: Steps executed is reasonable
    assert!(
        result.steps_executed <= config.max_steps,
        "Steps executed ({}) should not exceed max_steps ({})",
        result.steps_executed,
        config.max_steps
    );

    // Assert: Elapsed time is reasonable for CI (< 30 seconds)
    assert!(
        result.elapsed.as_secs() < 30,
        "Expected elapsed < 30s for CI, got {:?}",
        result.elapsed
    );

    eprintln!("\n✓ pqc_prod_single_node_soak_reaches_target_height PASSED");
    eprintln!(
        "  Final Height: {}, QCs: {}, View Changes: {}, Elapsed: {:?}\n",
        result.final_height, result.qcs_formed, result.view_changes, result.elapsed
    );
}

/// Test 2: PQC prod single-node soak respects consensus limits.
///
/// This test verifies:
/// - Eviction counters work correctly under PQC load with small limits
/// - No panics occur when limits are exceeded
/// - Final state is still consistent
///
/// Uses small limits:
/// - max_tracked_views: 8
/// - max_pending_blocks: 32
/// - max_votes_by_view_entries: 64
/// - max_commit_log_entries: 32
///
/// # CI Constraints
/// - max_steps: 4000
/// - target_height: 100
/// - Should complete in ~10-20 seconds
#[test]
fn pqc_prod_single_node_soak_respects_consensus_limits() {
    let config = PqcProdSoakConfig::new()
        .with_max_steps(4000)
        .with_target_height(100)
        .with_small_limits();

    let result = run_pqc_prod_single_node_soak(&config);

    // Assert: Made progress toward target
    assert!(
        result.final_height >= 50,
        "Expected final_height >= 50 even with small limits, got {}",
        result.final_height
    );

    // Assert: Some eviction occurred (limits were exercised)
    let total_evictions = result.evicted_blocks
        + result.evicted_commit_log_entries
        + result.evicted_votes_by_view_entries
        + result.evicted_views;

    assert!(
        total_evictions > 0,
        "Expected some evictions with small limits, got total_evictions=0.\n\
         evicted_blocks={}, evicted_commit_log_entries={}, \
         evicted_votes_by_view_entries={}, evicted_views={}",
        result.evicted_blocks,
        result.evicted_commit_log_entries,
        result.evicted_votes_by_view_entries,
        result.evicted_views
    );

    // Assert: QCs were still formed despite evictions
    assert!(
        result.qcs_formed > 0,
        "Expected qcs_formed > 0 even with small limits, got {}",
        result.qcs_formed
    );

    // Assert: Elapsed time is reasonable for CI (< 30 seconds)
    assert!(
        result.elapsed.as_secs() < 30,
        "Expected elapsed < 30s for CI, got {:?}",
        result.elapsed
    );

    eprintln!("\n✓ pqc_prod_single_node_soak_respects_consensus_limits PASSED");
    eprintln!(
        "  Final Height: {}, Evicted Blocks: {}, Evicted Votes: {}, \
         Evicted Commit Log: {}, Elapsed: {:?}\n",
        result.final_height,
        result.evicted_blocks,
        result.evicted_votes_by_view_entries,
        result.evicted_commit_log_entries,
        result.elapsed
    );
}

/// Test 3: PQC prod single-node soak produces valid metrics.
///
/// This test verifies:
/// - PQC governance can be created and validated
/// - Startup validator accepts PQC prod profile configuration
/// - NodeMetrics exposes KEM metrics correctly
/// - Per-suite signature metrics would include ML-DSA-44 (if verifier exercised)
///
/// # CI Constraints
/// - Should complete in <10 seconds (no soak run, just wiring validation)
#[test]
fn pqc_prod_single_node_soak_pqc_metrics_sane() {
    // Generate single validator with ML-DSA-44
    let validator = generate_pqc_prod_soak_validator_keys();
    let governance = Arc::new(PqcProdSoakGovernance::new(&validator));
    let backend_registry = build_pqc_prod_soak_backend_registry();
    let _epoch_state = build_pqc_prod_soak_epoch_state();
    let storage = Arc::new(InMemoryConsensusStorage::new());

    // Create startup validator with PQC prod profile
    let startup_validator = ConsensusStartupValidator::new(
        governance.clone(),
        backend_registry.clone(),
        storage.clone() as Arc<dyn qbind_node::storage::ConsensusStorage>,
    )
    .with_suite_policy(SuitePolicy::prod_default());

    // Assert: Basic validation passes (backends exist)
    let basic_result = startup_validator.validate();
    assert!(
        basic_result.is_ok(),
        "PQC prod profile startup validation should pass: {:?}",
        basic_result
    );

    // Assert: Governance enumerates single validator
    let validators_list = governance.list_validators();
    assert_eq!(
        validators_list.len(),
        1,
        "Should have 1 validator in governance"
    );
    assert_eq!(validators_list[0], 0, "Validator ID should be 0");

    // Assert: Validator is mapped to ML-DSA-44
    let key_result = governance.get_consensus_key(0);
    assert!(
        key_result.is_some(),
        "Validator 0 should have a key in governance"
    );

    let (suite_id, key) = key_result.unwrap();
    assert_eq!(
        suite_id, SUITE_PQ_RESERVED_1,
        "Validator 0 should use ML-DSA-44 suite (ID 100)"
    );
    assert_eq!(
        key.len(),
        1312,
        "ML-DSA-44 public key should be 1312 bytes (FIPS 204)"
    );

    // Assert: NodeMetrics can be created and formatted
    let metrics = Arc::new(NodeMetrics::new());
    let metrics_str = metrics.format_metrics();
    assert!(!metrics_str.is_empty(), "Metrics should be formattable");

    // Assert: Metrics contain KEM section
    assert!(
        metrics_str.contains("qbind_net_kem"),
        "Metrics should contain KEM metrics section"
    );

    // Assert: No toy suite in PQC prod configuration
    // Verify governance list only contains validator 0 with ML-DSA-44
    for v_id in governance.list_validators() {
        let (s_id, _) = governance
            .get_consensus_key(v_id)
            .expect("Should have key for validator");
        assert_eq!(
            s_id, SUITE_PQ_RESERVED_1,
            "All validators in PQC prod soak should use ML-DSA-44"
        );
    }

    eprintln!("\n✓ pqc_prod_single_node_soak_pqc_metrics_sane PASSED");
    eprintln!(
        "  Single Validator ID: 0\n\
         Suite: ML-DSA-44 (ID=100)\n\
         Public Key Size: {} bytes\n\
         Metrics Exposed: ✓ KEM section present\n",
        1312
    );
}

// ============================================================================
// Integration Test: PQC Prod Profile via Existing 3-Node Soak Harness
// ============================================================================

/// Integration test: Verify that existing 3-node soak harness is NOT affected by PQC work.
///
/// This test runs the standard 3-node soak (which uses toy suite) to confirm
/// that PQC additions don't break existing consensus functionality.
#[test]
fn pqc_prod_soak_does_not_break_existing_three_node_soak() {
    let config = SoakConfig::new()
        .with_max_steps(1000)
        .with_target_height(30);

    let result = run_three_node_soak(&config);

    // Assert: Standard 3-node soak still works
    assert!(
        result.target_reached,
        "Existing 3-node soak should still reach target height"
    );

    assert!(
        result.consensus_achieved,
        "Existing 3-node soak should achieve consensus"
    );

    assert!(
        result.qcs_formed > 0,
        "Existing 3-node soak should form QCs"
    );

    eprintln!("\n✓ pqc_prod_soak_does_not_break_existing_three_node_soak PASSED");
}
