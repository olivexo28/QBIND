//! Tests for commit log memory limits (T123).
//!
//! These tests verify that HotStuffStateEngine properly enforces memory limits
//! for the commit log, ensuring bounded memory usage while preserving safety
//! and observability.

use cano_consensus::{
    ConsensusLimitsConfig, ConsensusValidatorSet, HotStuffStateEngine, ValidatorId,
    ValidatorSetEntry,
};

/// Create a simple validator set with the given number of validators.
/// Each validator has voting power 1, so quorum = ceil(2*n/3).
fn make_validator_set(num_validators: u64) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = (0..num_validators)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

/// Create a block ID from a seed value.
fn make_block_id(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// Helper to form a QC by voting from validators 0, 1, 2.
/// Returns the formed QC.
fn form_qc_for_block(engine: &mut HotStuffStateEngine<[u8; 32]>, view: u64, block_id: &[u8; 32]) {
    // Need 3 votes out of 4 (total=4, threshold=3)
    for i in 0..3 {
        let _ = engine.on_vote(ValidatorId(i), view, block_id);
    }
}

/// Test that commit log is bounded by max_commit_log_entries limit.
#[test]
fn commit_log_is_bounded_by_limit() {
    // Configure with a small limit (5 entries)
    let limits = ConsensusLimitsConfig {
        max_tracked_views: 128,
        max_votes_per_view: 256,
        max_pending_blocks: 4096,
        max_votes_by_view_entries: 16384,
        max_commit_log_entries: 5,
    };
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators, limits);

    // Create a long chain and commit many blocks
    // We'll create blocks A → B → C → D → ... and form QCs to commit them
    let mut prev_block = None;
    for i in 0..20u64 {
        let block_id = make_block_id((i % 256) as u8);
        engine.register_block(block_id, i, prev_block, None);
        prev_block = Some(block_id);
    }

    // Now form QCs to commit blocks
    // Each 3-chain commits the grandparent
    for i in 0..18u64 {
        // Form QC for block i, i+1, i+2 to commit block i
        let block_id_i = make_block_id((i % 256) as u8);
        let block_id_i1 = make_block_id(((i + 1) % 256) as u8);
        let block_id_i2 = make_block_id(((i + 2) % 256) as u8);

        form_qc_for_block(&mut engine, i, &block_id_i);
        form_qc_for_block(&mut engine, i + 1, &block_id_i1);
        form_qc_for_block(&mut engine, i + 2, &block_id_i2);
    }

    // The commit log should be bounded by the limit (5 entries)
    assert!(engine.commit_log().len() <= 5);
    // Some evictions should have occurred
    assert!(engine.evicted_commit_log_entries() > 0);
}

/// Test basic bounding with a small max_commit_log_entries.
#[test]
fn commit_log_basic_bounding() {
    // Configure with a very small limit (3 entries)
    let limits = ConsensusLimitsConfig {
        max_tracked_views: 128,
        max_votes_per_view: 256,
        max_pending_blocks: 4096,
        max_votes_by_view_entries: 16384,
        max_commit_log_entries: 3,
    };
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators, limits);

    // Create blocks A → B → C → D → E → F
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let block_c = make_block_id(0xCC);
    let block_d = make_block_id(0xDD);
    let block_e = make_block_id(0xEE);
    let block_f = make_block_id(0xFF);

    engine.register_block(block_a, 1, None, None);
    engine.register_block(block_b, 2, Some(block_a), None);
    engine.register_block(block_c, 3, Some(block_b), None);
    engine.register_block(block_d, 4, Some(block_c), None);
    engine.register_block(block_e, 5, Some(block_d), None);
    engine.register_block(block_f, 6, Some(block_e), None);

    // Form QCs to commit blocks
    // 3-chain (A,B,C) → commit A
    form_qc_for_block(&mut engine, 1, &block_a);
    form_qc_for_block(&mut engine, 2, &block_b);
    form_qc_for_block(&mut engine, 3, &block_c);

    assert_eq!(engine.commit_log().len(), 1);
    assert_eq!(engine.evicted_commit_log_entries(), 0);

    // 3-chain (B,C,D) → commit B
    form_qc_for_block(&mut engine, 4, &block_d);
    assert_eq!(engine.commit_log().len(), 2);
    assert_eq!(engine.evicted_commit_log_entries(), 0);

    // 3-chain (C,D,E) → commit C
    form_qc_for_block(&mut engine, 5, &block_e);
    assert_eq!(engine.commit_log().len(), 3); // At limit
    assert_eq!(engine.evicted_commit_log_entries(), 0);

    // 3-chain (D,E,F) → commit D
    form_qc_for_block(&mut engine, 6, &block_f);
    // Should still have 3 entries (evicted oldest A)
    assert_eq!(engine.commit_log().len(), 3);
    assert_eq!(engine.evicted_commit_log_entries(), 1);

    // Verify the retained entries are the most recent (B, C, D)
    let log = engine.commit_log();
    assert_eq!(log.len(), 3);
    assert_eq!(log[0].block_id, block_b); // B
    assert_eq!(log[1].block_id, block_c); // C
    assert_eq!(log[2].block_id, block_d); // D

    // Verify A is not in the log
    assert!(!log.iter().any(|entry| entry.block_id == block_a));
}

/// Test that commit log bounding does not affect safety.
#[test]
fn commit_log_bounding_does_not_affect_safety() {
    // Configure with a small limit
    let limits = ConsensusLimitsConfig {
        max_tracked_views: 128,
        max_votes_per_view: 256,
        max_pending_blocks: 4096,
        max_votes_by_view_entries: 16384,
        max_commit_log_entries: 2,
    };
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators, limits);

    // Create and commit blocks
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let block_c = make_block_id(0xCC);
    let block_d = make_block_id(0xDD);

    engine.register_block(block_a, 1, None, None);
    engine.register_block(block_b, 2, Some(block_a), None);
    engine.register_block(block_c, 3, Some(block_b), None);
    engine.register_block(block_d, 4, Some(block_c), None);

    // Commit A, B, C, D
    form_qc_for_block(&mut engine, 1, &block_a);
    form_qc_for_block(&mut engine, 2, &block_b);
    form_qc_for_block(&mut engine, 3, &block_c); // Commits A
    form_qc_for_block(&mut engine, 4, &block_d); // Commits B

    // Commit log should have at most 2 entries (C and D won't be committed yet)
    // Actually, let's trace:
    // - QC for C commits A
    // - QC for D commits B
    // So commit log should have A and B, but limit is 2, so both fit

    // Verify safety properties are maintained
    assert_eq!(engine.committed_block(), Some(&block_b));
    assert_eq!(engine.committed_height(), Some(1)); // B's height

    // Even if commit log entries are evicted, committed block and height remain correct
    // Add more commits to force eviction
    let block_e = make_block_id(0xEE);
    let block_f = make_block_id(0xFF);
    engine.register_block(block_e, 5, Some(block_d), None);
    engine.register_block(block_f, 6, Some(block_e), None);

    form_qc_for_block(&mut engine, 5, &block_e); // Commits C
    form_qc_for_block(&mut engine, 6, &block_f); // Commits D

    // Now commit log should have C and D (evicted A and B)
    assert_eq!(engine.commit_log().len(), 2);
    assert!(engine.evicted_commit_log_entries() >= 2);

    // But safety is preserved: committed block should be D (height 3)
    assert_eq!(engine.committed_block(), Some(&block_d));
    assert_eq!(engine.committed_height(), Some(3));
}

/// Test zero limit edge case.
#[test]
fn commit_log_zero_limit() {
    // Configure with zero limit
    let limits = ConsensusLimitsConfig {
        max_tracked_views: 128,
        max_votes_per_view: 256,
        max_pending_blocks: 4096,
        max_votes_by_view_entries: 16384,
        max_commit_log_entries: 0,
    };
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators, limits);

    // Create and commit a block
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let block_c = make_block_id(0xCC);

    engine.register_block(block_a, 1, None, None);
    engine.register_block(block_b, 2, Some(block_a), None);
    engine.register_block(block_c, 3, Some(block_b), None);

    form_qc_for_block(&mut engine, 1, &block_a);
    form_qc_for_block(&mut engine, 2, &block_b);
    form_qc_for_block(&mut engine, 3, &block_c); // Commits A

    // Commit log should be empty (or immediately evicted)
    assert_eq!(engine.commit_log().len(), 0);
    // Eviction counter should reflect the eviction
    assert_eq!(engine.evicted_commit_log_entries(), 1);

    // Safety should still be preserved
    assert_eq!(engine.committed_block(), Some(&block_a));
    assert_eq!(engine.committed_height(), Some(0));
}

/// Test large limit edge case (no eviction).
#[test]
fn commit_log_large_limit_no_eviction() {
    // Configure with a large limit
    let limits = ConsensusLimitsConfig {
        max_tracked_views: 128,
        max_votes_per_view: 256,
        max_pending_blocks: 4096,
        max_votes_by_view_entries: 16384,
        max_commit_log_entries: 10_000,
    };
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators, limits);

    // Create and commit a few blocks
    let mut prev_block = None;
    for i in 0..10u64 {
        let block_id = make_block_id((i % 256) as u8);
        engine.register_block(block_id, i, prev_block, None);
        prev_block = Some(block_id);
    }

    // Form QCs to commit blocks
    for i in 0..8u64 {
        let block_id_i = make_block_id((i % 256) as u8);
        let block_id_i1 = make_block_id(((i + 1) % 256) as u8);
        let block_id_i2 = make_block_id(((i + 2) % 256) as u8);

        form_qc_for_block(&mut engine, i, &block_id_i);
        form_qc_for_block(&mut engine, i + 1, &block_id_i1);
        form_qc_for_block(&mut engine, i + 2, &block_id_i2);
    }

    // Should have 8 commits (blocks 0-7)
    assert_eq!(engine.commit_log().len(), 8);
    // No evictions should have occurred
    assert_eq!(engine.evicted_commit_log_entries(), 0);
}

/// Test that driver commit notification still works with bounded commit log.
/// This test is disabled because HotStuffStateEngine doesn't implement HasCommitLog.
/// We'll keep the test but mark it as ignored for now.
#[test]
#[ignore]
fn driver_commit_notification_with_bounded_log() {
    // This test would require HotStuffStateEngine to implement HasCommitLog.
    // Since that's not required for T123, we skip it.
}

/// Test that update_validators preserves commit log limits.
#[test]
fn update_validators_preserves_commit_log_limits() {
    let limits = ConsensusLimitsConfig {
        max_tracked_views: 128,
        max_votes_per_view: 256,
        max_pending_blocks: 4096,
        max_votes_by_view_entries: 16384,
        max_commit_log_entries: 100,
    };
    let validators1 = make_validator_set(4);
    let validators2 = make_validator_set(6);

    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators1, limits);

    // Update validators
    engine.update_validators(validators2);

    // Limits should be preserved
    assert_eq!(engine.limits().max_commit_log_entries, 100);
}
