//! 3-Node Soak Tests for Consensus + Node Layer (T130).
//!
//! This module contains CI-friendly soak tests that exercise the consensus layer
//! under higher-load conditions while remaining fast enough for CI execution.
//!
//! # Tests
//!
//! 1. `three_node_basic_soak_reaches_target_height`: Basic soak test that verifies
//!    all nodes can reach a target committed height with no divergence.
//!
//! 2. `three_node_soak_respects_consensus_limits`: Soak test that uses small
//!    memory limits to verify that eviction logic works correctly under realistic,
//!    longer runs.
//!
//! # CI Constraints
//!
//! All tests in this file should complete within 30-60 seconds to be CI-friendly.
//! Longer-running soak tests are marked with `#[ignore]` and can be run manually.
//!
//! # Running Tests
//!
//! ```bash
//! # Run all soak tests
//! cargo test -p qbind-node --test three_node_soak_tests
//!
//! # Run ignored (long) soak tests
//! cargo test -p qbind-node --test three_node_soak_tests -- --ignored
//! ```

mod soak_harness;

use soak_harness::{run_three_node_soak, SoakConfig, SoakResult};

// ============================================================================
// Part B – CI-Friendly Soak Tests
// ============================================================================

/// Test 1: Basic soak test that reaches target height.
///
/// This test verifies:
/// - All nodes reach the same committed height >= target_height
/// - No divergence: same block ID at each height
/// - QCs formed > 0
/// - View changes are non-zero but finite
///
/// # CI Constraints
/// - max_steps: 3000 (tuned for CI speed)
/// - target_height: 50
/// - Should complete in ~5-15 seconds
#[test]
fn three_node_basic_soak_reaches_target_height() {
    let config = SoakConfig::new()
        .with_max_steps(3000)
        .with_target_height(50);

    let result = run_three_node_soak(&config);

    // Assert: Target height was reached
    assert!(
        result.target_reached,
        "Expected to reach target height >= 50, got final_height={}",
        result.final_height
    );

    // Assert: Final height is at least target
    assert!(
        result.final_height >= 50,
        "Expected final_height >= 50, got {}",
        result.final_height
    );

    // Assert: All nodes agree on committed state
    assert!(
        result.consensus_achieved,
        "Expected all nodes to agree on committed state (consensus_achieved=false)"
    );

    // Assert: Some QCs were formed
    assert!(
        result.qcs_formed > 0,
        "Expected qcs_formed > 0, got {}",
        result.qcs_formed
    );

    // Assert: Some view changes occurred
    assert!(
        result.view_changes > 0,
        "Expected view_changes > 0, got {}",
        result.view_changes
    );

    // Assert: View changes are finite (not exploding)
    // With target_height=50, we expect at most ~150 view changes (3 per commit)
    assert!(
        result.view_changes < 300,
        "Expected view_changes < 300 (not exploding), got {}",
        result.view_changes
    );

    // Assert: Steps executed is reasonable
    assert!(
        result.steps_executed <= config.max_steps,
        "Steps executed ({}) should not exceed max_steps ({})",
        result.steps_executed,
        config.max_steps
    );

    // Assert: Elapsed time is reasonable for CI (should be < 30 seconds)
    assert!(
        result.elapsed.as_secs() < 30,
        "Expected elapsed < 30s for CI, got {:?}",
        result.elapsed
    );

    // Assert: No equivocations (in normal operation)
    assert_eq!(
        result.equivocations_detected, 0,
        "Expected no equivocations in basic soak, got {}",
        result.equivocations_detected
    );

    eprintln!("\n✓ three_node_basic_soak_reaches_target_height PASSED");
    eprintln!(
        "  Final Height: {}, QCs: {}, View Changes: {}, Elapsed: {:?}\n",
        result.final_height, result.qcs_formed, result.view_changes, result.elapsed
    );
}

/// Test 2: Soak test that respects consensus limits.
///
/// This test verifies:
/// - Memory bounding logic (T118/T122/T123) operates under realistic, longer runs
/// - evicted_blocks, evicted_votes_by_view_entries, or evicted_views counters are non-zero
/// - No panics, and final state is still consistent
///
/// Uses small limits to force eviction behavior:
/// - max_tracked_views: 8
/// - max_pending_blocks: 32
/// - max_votes_by_view_entries: 64
/// - max_commit_log_entries: 32
///
/// # Note
///
/// The commit log eviction (`evicted_commit_log_entries`) may be zero in this test
/// because the simulated harness doesn't fully exercise the 3-chain commit rule
/// which populates the commit log. Block tree and votes_by_view evictions are
/// the primary metrics verified here.
///
/// # CI Constraints
/// - max_steps: 5000 (pushes harder than basic soak)
/// - target_height: 100
/// - Should complete in ~10-30 seconds
#[test]
fn three_node_soak_respects_consensus_limits() {
    let config = SoakConfig::new()
        .with_max_steps(5000)
        .with_target_height(100)
        .with_small_limits();

    let result = run_three_node_soak(&config);

    // Assert: Target height was reached (or close)
    // With small limits, we might not reach target if eviction affects progress
    assert!(
        result.final_height >= 50,
        "Expected final_height >= 50 even with small limits, got {}",
        result.final_height
    );

    // Assert: All nodes agree on committed state (safety preserved)
    assert!(
        result.consensus_achieved,
        "Expected consensus_achieved=true even with small limits (safety must be preserved)"
    );

    // Assert: Some eviction occurred (limits were exercised)
    // With small limits (max_commit_log_entries=32) and target_height=100, we should evict
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

    // Assert: Elapsed time is reasonable for CI (should be < 60 seconds)
    assert!(
        result.elapsed.as_secs() < 60,
        "Expected elapsed < 60s for CI, got {:?}",
        result.elapsed
    );

    // Assert: No panics (implicit - if we got here, no panics occurred)

    eprintln!("\n✓ three_node_soak_respects_consensus_limits PASSED");
    eprintln!(
        "  Final Height: {}, Evicted Blocks: {}, Evicted Commit Log: {}, \
         Evicted Views: {}, Elapsed: {:?}\n",
        result.final_height,
        result.evicted_blocks,
        result.evicted_commit_log_entries,
        result.evicted_views,
        result.elapsed
    );
}

/// Test 3: Soak test with fault injection (message drops).
///
/// This test verifies:
/// - Consensus can make progress even with some message drops
/// - Safety is preserved (no conflicting commits)
/// - The system eventually reaches consensus
///
/// # CI Constraints
/// - max_steps: 3000
/// - target_height: 30 (lower than basic due to drops)
/// - drop_percentage: 15%
/// - Should complete in ~10-20 seconds
#[test]
fn three_node_soak_with_faults_still_converges() {
    let config = SoakConfig::new()
        .with_max_steps(3000)
        .with_target_height(30)
        .with_faults(15, 42); // 15% drop rate, seed 42

    let result = run_three_node_soak(&config);

    // Assert: Made some progress (may not reach target with drops)
    assert!(
        result.final_height >= 10,
        "Expected final_height >= 10 even with 15% drops, got {}",
        result.final_height
    );

    // Assert: All nodes agree on committed state (safety preserved)
    assert!(
        result.consensus_achieved,
        "Expected consensus_achieved=true even with faults (safety must be preserved)"
    );

    // Assert: Some QCs were formed
    assert!(
        result.qcs_formed > 0,
        "Expected qcs_formed > 0, got {}",
        result.qcs_formed
    );

    // Assert: Elapsed time is reasonable for CI
    assert!(
        result.elapsed.as_secs() < 30,
        "Expected elapsed < 30s for CI, got {:?}",
        result.elapsed
    );

    eprintln!("\n✓ three_node_soak_with_faults_still_converges PASSED");
    eprintln!(
        "  Final Height: {}, QCs: {}, Target Reached: {}, Elapsed: {:?}\n",
        result.final_height, result.qcs_formed, result.target_reached, result.elapsed
    );
}

// ============================================================================
// Part B – Longer Soak Tests (Ignored by default)
// ============================================================================

/// Extended soak test with higher target height.
///
/// This test runs for longer to stress the system more thoroughly.
/// It is ignored by default to keep CI fast.
///
/// Run with: `cargo test -p qbind-node --test three_node_soak_tests -- --ignored`
#[test]
#[ignore]
fn three_node_extended_soak_high_target() {
    let config = SoakConfig::new()
        .with_max_steps(10000)
        .with_target_height(500);

    let result = run_three_node_soak(&config);

    assert!(
        result.target_reached,
        "Expected to reach target height >= 500, got final_height={}",
        result.final_height
    );

    assert!(
        result.consensus_achieved,
        "Expected all nodes to agree on committed state"
    );

    eprintln!("\n✓ three_node_extended_soak_high_target PASSED");
    eprintln!(
        "  Final Height: {}, QCs: {}, Steps: {}, Elapsed: {:?}\n",
        result.final_height, result.qcs_formed, result.steps_executed, result.elapsed
    );
}

/// Extended soak test with small limits and high target.
///
/// This test runs for longer with small memory limits to stress eviction.
/// It is ignored by default to keep CI fast.
///
/// Run with: `cargo test -p qbind-node --test three_node_soak_tests -- --ignored`
#[test]
#[ignore]
fn three_node_extended_soak_small_limits_high_target() {
    let config = SoakConfig::new()
        .with_max_steps(15000)
        .with_target_height(500)
        .with_small_limits();

    let result = run_three_node_soak(&config);

    // With small limits, we should see significant eviction
    let total_evictions = result.evicted_blocks
        + result.evicted_commit_log_entries
        + result.evicted_votes_by_view_entries
        + result.evicted_views;

    assert!(
        total_evictions > 100,
        "Expected significant evictions with small limits and high target, got {}",
        total_evictions
    );

    assert!(
        result.consensus_achieved,
        "Expected all nodes to agree on committed state even with high eviction"
    );

    eprintln!("\n✓ three_node_extended_soak_small_limits_high_target PASSED");
    eprintln!(
        "  Final Height: {}, Total Evictions: {}, Steps: {}, Elapsed: {:?}\n",
        result.final_height, total_evictions, result.steps_executed, result.elapsed
    );
}

// ============================================================================
// Unit Tests for Test Configuration
// ============================================================================

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn soak_config_defaults_are_ci_friendly() {
        let config = SoakConfig::default();
        // Default settings should be CI-friendly
        assert!(
            config.max_steps <= 5000,
            "Default max_steps should be <= 5000 for CI"
        );
        assert!(
            config.target_height <= 100,
            "Default target_height should be <= 100 for CI"
        );
        assert!(
            !config.enable_faults,
            "Faults should be disabled by default"
        );
    }

    #[test]
    fn soak_result_has_all_expected_fields() {
        let result = SoakResult::default();
        // Verify all fields exist and have expected defaults
        assert_eq!(result.final_height, 0);
        assert!(result.consensus_views.is_empty());
        assert_eq!(result.qcs_formed, 0);
        assert_eq!(result.evicted_blocks, 0);
        assert_eq!(result.evicted_commit_log_entries, 0);
        assert_eq!(result.evicted_votes_by_view_entries, 0);
        assert_eq!(result.evicted_views, 0);
        assert_eq!(result.dropped_votes, 0);
        assert_eq!(result.rate_limit_drops, 0);
        assert_eq!(result.view_changes, 0);
        assert_eq!(result.view_lag, 0);
        assert_eq!(result.votes_observed, 0);
        assert_eq!(result.leader_changes, 0);
        assert_eq!(result.steps_executed, 0);
        assert!(!result.target_reached);
        assert!(!result.consensus_achieved);
        assert_eq!(result.elapsed, std::time::Duration::ZERO);
        assert_eq!(result.equivocations_detected, 0);
    }
}
