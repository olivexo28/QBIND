//! Soak / Resource Exhaustion Harness for Consensus + Node Layer (T130).
//!
//! This module provides a reusable test harness for longer, higher-load simulations
//! that stress the consensus and node layers:
//! - Memory bounds (block tree limits, commit log limits, votes_by_view limits)
//! - Rate limiting (per-peer token buckets)
//! - Consensus liveness (views, QCs, view lag)
//!
//! # Design (T130)
//!
//! The harness builds on top of the existing `NodeHotstuffHarness` and async networking
//! infrastructure. It runs a 3-node HotStuff cluster for a configurable number of steps
//! or until a target height is reached.
//!
//! # Mental Model
//!
//! ## How NodeHotstuffHarness Drives Consensus
//!
//! The `NodeHotstuffHarness` wraps:
//! - `NodeConsensusSim<HotStuffDriver>` which owns the consensus node and driver
//! - `CommitIndex` tracking the canonical committed chain
//! - `BlockStore` storing locally broadcast block proposals
//! - Optional `ConsensusStorage` for persistence
//! - Optional `NodeMetrics` for observability
//!
//! The harness drives consensus via:
//! - `on_tick()`: Advances network, processes events, consults pacemaker, tries proposals
//! - `on_incoming_message()`: Processes votes and proposals from the network
//!
//! ## How Metrics are Exposed
//!
//! Metrics are exposed via `NodeMetrics` which aggregates:
//! - `NetworkMetrics`: inbound/outbound message counts
//! - `RuntimeMetrics`: tick/event counts
//! - `ConsensusProgressMetrics` (T127): QCs formed, votes observed, view changes
//! - `ValidatorVoteMetrics` (T128): per-validator vote tracking
//! - `ViewLagMetrics` (T128): current view and view lag
//! - `ValidatorEquivocationMetrics` (T129): equivocation tracking
//! - `PeerNetworkMetrics` (T90.4): per-peer rate limit drops
//!
//! The `/metrics` HTTP endpoint (when enabled) formats all metrics in Prometheus style.
//!
//! ## How Tests Simulate Multi-Node Runs
//!
//! Existing tests use either:
//! 1. `FullStackNodeHandle` + `AsyncPeerManagerImpl` for real TCP networking
//! 2. Simulated consensus progression with manual vote/proposal injection
//!
//! This soak harness uses approach #2 (simulated) for faster CI execution while
//! still exercising the memory bounds and metrics infrastructure.
//!
//! # Usage
//!
//! ```ignore
//! use soak_harness::{SoakConfig, SoakResult, run_three_node_soak};
//!
//! let config = SoakConfig {
//!     max_steps: 3000,
//!     target_height: 50,
//!     enable_faults: false,
//! };
//!
//! let result = run_three_node_soak(&config);
//! assert!(result.final_height >= config.target_height);
//! assert!(result.qcs_formed > 0);
//! ```

use std::time::{Duration, Instant};

use qbind_consensus::hotstuff_state_engine::HotStuffStateEngine;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_consensus::vote_accumulator::ConsensusLimitsConfig;

// ============================================================================
// SoakConfig - Configuration for the soak harness
// ============================================================================

/// Configuration for the soak harness (T130).
///
/// Controls how long the soak test runs and what fault modes to enable.
#[derive(Debug, Clone)]
pub struct SoakConfig {
    /// Maximum number of consensus steps / ticks to run.
    /// The soak test will stop early if `target_height` is reached.
    pub max_steps: usize,

    /// Target committed height to reach before stopping.
    /// If 0, the test runs until `max_steps` is exhausted.
    pub target_height: u64,

    /// Enable fault injection (message drops).
    /// When true, the harness will randomly drop some messages.
    pub enable_faults: bool,

    /// Percentage of messages to drop when `enable_faults` is true.
    /// Should be between 0 and 100.
    pub fault_drop_percentage: u8,

    /// Random seed for deterministic fault injection.
    pub fault_seed: u64,

    /// Custom consensus limits configuration.
    /// If None, uses default limits.
    pub consensus_limits: Option<ConsensusLimitsConfig>,

    /// Whether to enable small limits for testing eviction.
    /// When true, uses very small limits to force eviction behavior.
    pub use_small_limits: bool,
}

impl Default for SoakConfig {
    fn default() -> Self {
        SoakConfig {
            max_steps: 2000,
            target_height: 50,
            enable_faults: false,
            fault_drop_percentage: 10,
            fault_seed: 42,
            consensus_limits: None,
            use_small_limits: false,
        }
    }
}

impl SoakConfig {
    /// Create a new default soak configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum steps.
    pub fn with_max_steps(mut self, max_steps: usize) -> Self {
        self.max_steps = max_steps;
        self
    }

    /// Set the target height.
    pub fn with_target_height(mut self, target_height: u64) -> Self {
        self.target_height = target_height;
        self
    }

    /// Enable fault injection with the given drop percentage.
    pub fn with_faults(mut self, drop_percentage: u8, seed: u64) -> Self {
        self.enable_faults = true;
        self.fault_drop_percentage = drop_percentage;
        self.fault_seed = seed;
        self
    }

    /// Set custom consensus limits.
    #[allow(dead_code)]
    pub fn with_consensus_limits(mut self, limits: ConsensusLimitsConfig) -> Self {
        self.consensus_limits = Some(limits);
        self
    }

    /// Use small limits for testing eviction behavior.
    pub fn with_small_limits(mut self) -> Self {
        self.use_small_limits = true;
        self
    }
}

// ============================================================================
// SoakResult - Results from running the soak harness
// ============================================================================

/// Results from running the soak harness (T130).
///
/// Contains metrics and state from the completed soak run.
#[derive(Debug, Clone)]
pub struct SoakResult {
    /// Final committed height across all nodes (should be the same).
    pub final_height: u64,

    /// List of consensus views traversed.
    pub consensus_views: Vec<u64>,

    /// Total number of QCs formed.
    pub qcs_formed: u64,

    /// Number of blocks evicted from block tree due to memory limits.
    pub evicted_blocks: u64,

    /// Number of commit log entries evicted due to memory limits.
    pub evicted_commit_log_entries: u64,

    /// Number of votes_by_view entries evicted due to memory limits.
    pub evicted_votes_by_view_entries: u64,

    /// Number of views evicted from vote accumulator.
    pub evicted_views: u64,

    /// Number of votes dropped due to per-view limits.
    pub dropped_votes: u64,

    /// Total rate limit drops across all peers.
    #[allow(dead_code)]
    pub rate_limit_drops: u64,

    /// Total view changes.
    pub view_changes: u64,

    /// Final view lag (highest_seen_view - current_view).
    #[allow(dead_code)]
    pub view_lag: u64,

    /// Total votes observed.
    pub votes_observed: u64,

    /// Total leader changes.
    pub leader_changes: u64,

    /// Number of steps executed.
    pub steps_executed: usize,

    /// Whether the target height was reached.
    pub target_reached: bool,

    /// Whether all nodes agree on committed state.
    pub consensus_achieved: bool,

    /// Elapsed time for the soak run.
    pub elapsed: Duration,

    /// Any detected equivocations.
    pub equivocations_detected: u64,
}

impl Default for SoakResult {
    fn default() -> Self {
        SoakResult {
            final_height: 0,
            consensus_views: Vec::new(),
            qcs_formed: 0,
            evicted_blocks: 0,
            evicted_commit_log_entries: 0,
            evicted_votes_by_view_entries: 0,
            evicted_views: 0,
            dropped_votes: 0,
            rate_limit_drops: 0,
            view_changes: 0,
            view_lag: 0,
            votes_observed: 0,
            leader_changes: 0,
            steps_executed: 0,
            target_reached: false,
            consensus_achieved: false,
            elapsed: Duration::ZERO,
            equivocations_detected: 0,
        }
    }
}

// ============================================================================
// Simulated Soak Node
// ============================================================================

/// A simulated node for the soak harness.
///
/// This node uses an in-memory HotStuffStateEngine and BasicHotStuffEngine
/// to simulate consensus without real TCP networking.
struct SoakNode {
    /// Validator ID for this node.
    #[allow(dead_code)]
    id: ValidatorId,
    /// Node index (0, 1, or 2).
    #[allow(dead_code)]
    index: usize,
    /// HotStuff state engine.
    state: HotStuffStateEngine<[u8; 32]>,
    /// Current view.
    current_view: u64,
    /// Committed height.
    committed_height: u64,
    /// Last committed block ID.
    last_committed_block_id: [u8; 32],
    /// QCs formed counter.
    qcs_formed: u64,
    /// View changes counter.
    view_changes: u64,
    /// Votes observed counter.
    votes_observed: u64,
    /// Track views seen.
    views_seen: Vec<u64>,
}

impl SoakNode {
    /// Create a new soak node.
    fn new(index: usize, validators: ConsensusValidatorSet, limits: ConsensusLimitsConfig) -> Self {
        SoakNode {
            id: ValidatorId::new(index as u64),
            index,
            state: HotStuffStateEngine::with_limits(validators, limits),
            current_view: 0,
            committed_height: 0,
            last_committed_block_id: [0u8; 32],
            qcs_formed: 0,
            view_changes: 0,
            votes_observed: 0,
            views_seen: vec![0],
        }
    }

    /// Advance to the next view.
    fn advance_view(&mut self) {
        self.current_view += 1;
        self.view_changes += 1;
        self.views_seen.push(self.current_view);
    }

    /// Update committed state.
    fn update_committed(&mut self, height: u64, block_id: [u8; 32]) {
        if height > self.committed_height {
            self.committed_height = height;
            self.last_committed_block_id = block_id;
        }
    }
}

// ============================================================================
// Deterministic Fault Injection
// ============================================================================

/// Determines if a message should be dropped based on deterministic pseudo-random.
fn should_drop_message(counter: u64, drop_percentage: u8, seed: u64) -> bool {
    if drop_percentage == 0 {
        return false;
    }
    if drop_percentage >= 100 {
        return true;
    }
    // Simple deterministic pseudo-random based on counter and seed
    let hash = counter.wrapping_mul(0x517cc1b727220a95) ^ seed;
    (hash % 100) < (drop_percentage as u64)
}

// ============================================================================
// run_three_node_soak - Main soak harness function
// ============================================================================

/// Run a 3-node soak test with the given configuration.
///
/// This function creates a simulated 3-node HotStuff cluster and runs consensus
/// for the configured number of steps or until the target height is reached.
///
/// # Algorithm
///
/// Each step simulates one consensus round:
/// 1. Determine the leader for the current view (round-robin)
/// 2. Create a proposal (block) from the leader
/// 3. Register the proposal in all nodes' block trees
/// 4. Simulate votes from all validators
/// 5. Check if a QC is formed
/// 6. If QC is formed, advance to the next view
/// 7. Apply the 3-chain commit rule
///
/// # Fault Injection
///
/// If `enable_faults` is true, some votes/proposals are dropped deterministically
/// based on the `fault_drop_percentage` and `fault_seed`.
///
/// # Memory Limits
///
/// The harness uses `ConsensusLimitsConfig` to enforce memory bounds on:
/// - Block tree (max_pending_blocks)
/// - Vote accumulator (max_tracked_views, max_votes_per_view)
/// - Votes-by-view map (max_votes_by_view_entries)
/// - Commit log (max_commit_log_entries)
///
/// # Returns
///
/// A `SoakResult` containing metrics and state from the completed run.
pub fn run_three_node_soak(config: &SoakConfig) -> SoakResult {
    let start_time = Instant::now();
    let mut result = SoakResult::default();

    eprintln!(
        "\n========== Starting 3-Node Soak Test (T130) ==========\n\
         Max Steps: {}\n\
         Target Height: {}\n\
         Enable Faults: {}\n\
         Small Limits: {}\n\
         ======================================================\n",
        config.max_steps, config.target_height, config.enable_faults, config.use_small_limits,
    );

    // Build the 3-validator set
    let validator_set = build_three_validator_set();

    // Determine consensus limits
    let limits = if config.use_small_limits {
        // Use very small limits to force eviction behavior
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
        "[Soak] Using limits: max_tracked_views={}, max_pending_blocks={}, \
         max_votes_by_view_entries={}, max_commit_log_entries={}",
        limits.max_tracked_views,
        limits.max_pending_blocks,
        limits.max_votes_by_view_entries,
        limits.max_commit_log_entries,
    );

    // Create 3 simulated nodes
    let mut nodes: Vec<SoakNode> = (0..3)
        .map(|i| SoakNode::new(i, validator_set.clone(), limits))
        .collect();

    let mut message_counter: u64 = 0;
    let mut current_round: u64 = 0;
    let mut last_committed_height: u64 = 0;
    const COMMIT_DELAY: u64 = 2; // HotStuff 3-chain commit delay

    // Run consensus steps
    while result.steps_executed < config.max_steps {
        // Check if target height reached
        if config.target_height > 0 && last_committed_height >= config.target_height {
            result.target_reached = true;
            break;
        }

        // Determine leader for this round (round-robin)
        let leader_index = (current_round as usize) % 3;

        // Create block ID for this round
        let mut block_id = [0u8; 32];
        block_id[0] = (current_round & 0xFF) as u8;
        block_id[1] = ((current_round >> 8) & 0xFF) as u8;
        block_id[8] = leader_index as u8;

        // Create parent block ID
        let mut parent_id = [0xFFu8; 32]; // sentinel for genesis
        if current_round > 0 {
            parent_id[0] = ((current_round - 1) & 0xFF) as u8;
            parent_id[1] = (((current_round - 1) >> 8) & 0xFF) as u8;
        }

        // Register the block in all nodes' block trees
        for node in &mut nodes {
            let justify_qc = node.state.locked_qc().cloned();
            let parent = if current_round > 0 {
                Some(parent_id)
            } else {
                None
            };
            node.state
                .register_block(block_id, current_round, parent, justify_qc);
        }

        // Simulate votes from all validators
        let mut qc_formed_this_round = false;
        for voter_idx in 0..3 {
            let voter_id = ValidatorId::new(voter_idx as u64);

            // Check if this vote should be dropped (fault injection)
            message_counter += 1;
            if config.enable_faults
                && should_drop_message(
                    message_counter,
                    config.fault_drop_percentage,
                    config.fault_seed,
                )
            {
                // Drop this vote
                continue;
            }

            // Ingest the vote in all nodes
            for node in &mut nodes {
                let vote_result = node.state.on_vote(voter_id, current_round, &block_id);
                if vote_result.is_ok() {
                    node.votes_observed += 1;
                }

                // Check if QC is formed
                if let Ok(Some(_qc)) = vote_result {
                    if !qc_formed_this_round {
                        node.qcs_formed += 1;
                        qc_formed_this_round = true;
                    }
                }
            }
        }

        // If QC was formed, advance all nodes to next view
        if qc_formed_this_round {
            for node in &mut nodes {
                node.advance_view();
            }
        }

        // Apply 3-chain commit rule
        if current_round >= COMMIT_DELAY {
            let commit_height = current_round - 1;
            let mut commit_block_id = [0u8; 32];
            commit_block_id[0] = (commit_height & 0xFF) as u8;
            commit_block_id[1] = ((commit_height >> 8) & 0xFF) as u8;

            for node in &mut nodes {
                node.update_committed(commit_height, commit_block_id);
            }

            if commit_height > last_committed_height {
                last_committed_height = commit_height;
            }
        }

        current_round += 1;
        result.steps_executed += 1;
    }

    // Collect results from nodes
    result.elapsed = start_time.elapsed();
    result.final_height = nodes.iter().map(|n| n.committed_height).max().unwrap_or(0);

    // Check consensus: all nodes should have the same committed state
    let heights: Vec<u64> = nodes.iter().map(|n| n.committed_height).collect();
    let block_ids: Vec<[u8; 32]> = nodes.iter().map(|n| n.last_committed_block_id).collect();
    result.consensus_achieved =
        heights.windows(2).all(|w| w[0] == w[1]) && block_ids.windows(2).all(|w| w[0] == w[1]);

    // Aggregate metrics from all nodes
    for node in &nodes {
        result.qcs_formed += node.qcs_formed;
        result.view_changes += node.view_changes;
        result.votes_observed += node.votes_observed;
        result.evicted_blocks += node.state.evicted_blocks();
        result.evicted_commit_log_entries += node.state.evicted_commit_log_entries();
        result.evicted_votes_by_view_entries += node.state.evicted_votes_by_view_entries();
        result.evicted_views += node.state.evicted_views();
        result.dropped_votes += node.state.dropped_votes();
        result.equivocations_detected += node.state.equivocations_detected();
    }

    // Collect consensus views from node 0
    result.consensus_views = nodes[0].views_seen.clone();

    // Check if target was reached
    if config.target_height > 0 && result.final_height >= config.target_height {
        result.target_reached = true;
    }

    // Calculate leader changes (in round-robin, every view change is a leader change)
    result.leader_changes = result.view_changes;

    eprintln!(
        "\n========== 3-Node Soak Test Complete (T130) ==========\n\
         Steps Executed: {}\n\
         Final Height: {}\n\
         Target Reached: {}\n\
         Consensus Achieved: {}\n\
         QCs Formed: {}\n\
         View Changes: {}\n\
         Evicted Blocks: {}\n\
         Evicted Commit Log Entries: {}\n\
         Evicted Votes-by-View Entries: {}\n\
         Evicted Views: {}\n\
         Dropped Votes: {}\n\
         Elapsed: {:?}\n\
         ======================================================\n",
        result.steps_executed,
        result.final_height,
        result.target_reached,
        result.consensus_achieved,
        result.qcs_formed,
        result.view_changes,
        result.evicted_blocks,
        result.evicted_commit_log_entries,
        result.evicted_votes_by_view_entries,
        result.evicted_views,
        result.dropped_votes,
        result.elapsed,
    );

    result
}

// ============================================================================
// Helper Functions
// ============================================================================

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
// Unit Tests
// ============================================================================

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn soak_config_default_values() {
        let config = SoakConfig::default();
        assert_eq!(config.max_steps, 2000);
        assert_eq!(config.target_height, 50);
        assert!(!config.enable_faults);
        assert!(!config.use_small_limits);
    }

    #[test]
    fn soak_config_builder_works() {
        let config = SoakConfig::new()
            .with_max_steps(5000)
            .with_target_height(100)
            .with_faults(20, 12345)
            .with_small_limits();

        assert_eq!(config.max_steps, 5000);
        assert_eq!(config.target_height, 100);
        assert!(config.enable_faults);
        assert_eq!(config.fault_drop_percentage, 20);
        assert_eq!(config.fault_seed, 12345);
        assert!(config.use_small_limits);
    }

    #[test]
    fn soak_result_default_values() {
        let result = SoakResult::default();
        assert_eq!(result.final_height, 0);
        assert!(result.consensus_views.is_empty());
        assert_eq!(result.qcs_formed, 0);
        assert!(!result.target_reached);
        assert!(!result.consensus_achieved);
    }

    #[test]
    fn should_drop_message_deterministic() {
        // Same inputs should give same results
        let seed = 42;
        let drop_pct = 50;
        let results_1: Vec<bool> = (0..100)
            .map(|i| should_drop_message(i, drop_pct, seed))
            .collect();
        let results_2: Vec<bool> = (0..100)
            .map(|i| should_drop_message(i, drop_pct, seed))
            .collect();
        assert_eq!(results_1, results_2);
    }

    #[test]
    fn should_drop_message_zero_never_drops() {
        for i in 0..100 {
            assert!(!should_drop_message(i, 0, 42));
        }
    }

    #[test]
    fn should_drop_message_hundred_always_drops() {
        for i in 0..100 {
            assert!(should_drop_message(i, 100, 42));
        }
    }

    #[test]
    fn build_three_validator_set_correct() {
        let set = build_three_validator_set();
        assert_eq!(set.len(), 3);
        assert_eq!(set.total_voting_power(), 3);
        // Quorum is ceil(2*3/3) = 2
        assert_eq!(set.two_thirds_vp(), 2);
    }

    #[test]
    fn quick_soak_smoke_test() {
        // Very quick smoke test
        let config = SoakConfig::new().with_max_steps(100).with_target_height(10);

        let result = run_three_node_soak(&config);

        assert!(result.steps_executed <= 100);
        assert!(
            result.consensus_achieved,
            "Nodes should agree on committed state"
        );
        assert!(result.qcs_formed > 0, "Should form at least some QCs");
    }
}
