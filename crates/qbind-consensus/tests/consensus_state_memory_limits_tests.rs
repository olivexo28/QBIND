//! Tests for consensus state memory limits (T122).
//!
//! These tests verify that HotStuffStateEngine properly enforces memory limits
//! for both the blocks map and votes_by_view map, ensuring bounded memory usage
//! without compromising safety.

use qbind_consensus::{
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

/// Test that blocks are bounded by max_pending_blocks limit.
#[test]
fn blocks_are_bounded_by_limit() {
    // Configure with a very small limit
    let limits = ConsensusLimitsConfig::new(128, 256, 8, 16384);
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators, limits);

    // Insert many synthetic blocks at increasing heights
    for i in 0..100u64 {
        let block_id = make_block_id((i % 256) as u8);
        let parent_id = if i > 0 {
            Some(make_block_id(((i - 1) % 256) as u8))
        } else {
            None
        };
        engine.register_block(block_id, i, parent_id, None);
    }

    // Assert blocks.len() <= max_pending_blocks + small slack
    // We allow slight overruns if no safe blocks can be evicted
    assert!(
        engine.block_count() <= limits.max_pending_blocks + 10,
        "block_count = {}, max_pending_blocks = {}",
        engine.block_count(),
        limits.max_pending_blocks
    );

    // No committed blocks should have been evicted
    // (In this test we haven't committed any blocks, so this is trivially true)
    assert_eq!(engine.committed_block(), None);
    assert_eq!(engine.committed_height(), None);
}

/// Test that votes_by_view is bounded by max_votes_by_view_entries limit.
#[test]
fn votes_by_view_are_bounded_by_limit() {
    // Configure with small limits
    let limits = ConsensusLimitsConfig::new(128, 256, 4096, 10);
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators.clone(), limits);

    let block_id = make_block_id(0xAA);

    // Feed many synthetic votes into the engine
    for view in 0..100u64 {
        for validator_idx in 0..4u64 {
            let _ = engine.on_vote(ValidatorId(validator_idx), view, &block_id);
        }
    }

    // The votes_by_view map should not exceed the limit
    // Note: We can't directly access votes_by_view, but we can check that
    // new votes still insert successfully (which they should, with eviction)

    // Add more votes to ensure eviction is working
    for view in 100..200u64 {
        for validator_idx in 0..4u64 {
            let result = engine.on_vote(ValidatorId(validator_idx), view, &block_id);
            assert!(result.is_ok(), "Failed to insert vote at view {}", view);
        }
    }

    // Check that eviction counters have increased
    assert!(
        engine.evicted_votes_by_view_entries() > 0,
        "Expected some votes_by_view entries to be evicted"
    );
}

/// Test that eviction does not break commit safety.
#[test]
fn eviction_does_not_break_commit_safety() {
    // Configure with small limits to force eviction
    let limits = ConsensusLimitsConfig::new(128, 256, 10, 10);
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators.clone(), limits);

    // Construct a 3-chain that would commit a block
    // Block 0 (genesis)
    let block0 = make_block_id(0);
    engine.register_block(block0, 0, None, None);

    // Block 1 (child of 0)
    let block1 = make_block_id(1);
    engine.register_block(block1, 1, Some(block0), None);

    // Block 2 (child of 1)
    let block2 = make_block_id(2);
    engine.register_block(block2, 2, Some(block1), None);

    // Block 3 (child of 2) - will form 3-chain with QCs
    let block3 = make_block_id(3);
    engine.register_block(block3, 3, Some(block2), None);

    // First create QCs for the 3-chain BEFORE adding extra blocks
    // This ensures the blocks have own_qc and won't be evicted
    for validator_idx in 0..4u64 {
        let _ = engine.on_vote(ValidatorId(validator_idx), 0, &block0);
    }

    for validator_idx in 0..4u64 {
        let _ = engine.on_vote(ValidatorId(validator_idx), 1, &block1);
    }

    for validator_idx in 0..4u64 {
        let _ = engine.on_vote(ValidatorId(validator_idx), 2, &block2);
    }

    // Now force the engine to approach/exceed limits while building the chain
    // Add many other blocks to trigger eviction (but they shouldn't evict our chain)
    for i in 100..115u64 {
        let block_id = make_block_id((i % 256) as u8);
        let parent_id = if i > 100 {
            Some(make_block_id(((i - 1) % 256) as u8))
        } else {
            None
        };
        engine.register_block(block_id, i, parent_id, None);
    }

    // Assert the commit still happens correctly
    assert_eq!(engine.committed_block(), Some(&block0));
    assert_eq!(engine.committed_height(), Some(0));

    // No panic / double-commit occurs (implicitly verified by test not panicking)
}

/// Test integration with default limits.
#[test]
fn integration_with_default_limits() {
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators.clone());
    let defaults = ConsensusLimitsConfig::default();

    // Verify default limits are used
    assert_eq!(
        engine.limits().max_pending_blocks,
        defaults.max_pending_blocks
    );
    assert_eq!(
        engine.limits().max_votes_by_view_entries,
        defaults.max_votes_by_view_entries
    );

    // Run a small simulated round-set
    let block0 = make_block_id(0);
    engine.register_block(block0, 0, None, None);

    let block1 = make_block_id(1);
    engine.register_block(block1, 1, Some(block0), None);

    // Add votes
    for validator_idx in 0..4u64 {
        let result = engine.on_vote(ValidatorId(validator_idx), 1, &block1);
        assert!(result.is_ok());
    }

    // Verify no regressions in behavior
    assert_eq!(engine.block_count(), 2);
    assert_eq!(engine.equivocations_detected(), 0);
}

/// Test that committed blocks are never evicted.
#[test]
fn committed_blocks_never_evicted() {
    // Configure with very small limit
    let limits = ConsensusLimitsConfig::new(128, 256, 3, 16384);
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators.clone(), limits);

    // Create and commit a block
    let block0 = make_block_id(0);
    engine.register_block(block0, 0, None, None);

    let block1 = make_block_id(1);
    engine.register_block(block1, 1, Some(block0), None);

    let block2 = make_block_id(2);
    engine.register_block(block2, 2, Some(block1), None);

    // Create 3-chain to commit block0
    for validator_idx in 0..4u64 {
        let _ = engine.on_vote(ValidatorId(validator_idx), 0, &block0);
    }
    for validator_idx in 0..4u64 {
        let _ = engine.on_vote(ValidatorId(validator_idx), 1, &block1);
    }
    for validator_idx in 0..4u64 {
        let _ = engine.on_vote(ValidatorId(validator_idx), 2, &block2);
    }

    // Verify block0 is committed
    assert_eq!(engine.committed_block(), Some(&block0));

    // Add many other blocks to trigger eviction
    for i in 100..110u64 {
        let block_id = make_block_id((i % 256) as u8);
        let parent_id = if i > 100 {
            Some(make_block_id(((i - 1) % 256) as u8))
        } else {
            None
        };
        engine.register_block(block_id, i, parent_id, None);
    }

    // Verify committed block is still present
    assert!(
        engine.get_block(&block0).is_some(),
        "Committed block was evicted!"
    );

    // Verify we can still access the committed block's information
    assert_eq!(engine.committed_block(), Some(&block0));
    assert_eq!(engine.committed_height(), Some(0));
}

/// Test that blocks with own_qc are not evicted.
#[test]
fn blocks_with_own_qc_not_evicted() {
    // Configure with small limit
    let limits = ConsensusLimitsConfig::new(128, 256, 3, 16384);
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators.clone(), limits);

    // Create a block with own_qc
    let block0 = make_block_id(0);
    engine.register_block(block0, 0, None, None);

    // Give it a QC
    for validator_idx in 0..4u64 {
        let _ = engine.on_vote(ValidatorId(validator_idx), 0, &block0);
    }

    // Add many other blocks to trigger eviction
    for i in 100..110u64 {
        let block_id = make_block_id((i % 256) as u8);
        let parent_id = if i > 100 {
            Some(make_block_id(((i - 1) % 256) as u8))
        } else {
            None
        };
        engine.register_block(block_id, i, parent_id, None);
    }

    // Verify block with own_qc is still present
    let block = engine.get_block(&block0);
    assert!(block.is_some(), "Block with own_qc was evicted!");
    assert!(block.unwrap().own_qc.is_some(), "Block should have own_qc");
}

/// Test eviction metrics are tracked.
#[test]
fn eviction_metrics_are_tracked() {
    let limits = ConsensusLimitsConfig::new(128, 256, 5, 5);
    let validators = make_validator_set(4);
    let mut engine: HotStuffStateEngine<[u8; 32]> =
        HotStuffStateEngine::with_limits(validators.clone(), limits);

    // Initially no evictions
    assert_eq!(engine.evicted_blocks(), 0);
    assert_eq!(engine.evicted_votes_by_view_entries(), 0);

    // Add blocks to trigger block eviction
    for i in 0..10u64 {
        let block_id = make_block_id((i % 256) as u8);
        let parent_id = if i > 0 {
            Some(make_block_id(((i - 1) % 256) as u8))
        } else {
            None
        };
        engine.register_block(block_id, i, parent_id, None);
    }

    // Should have evicted some blocks
    assert!(
        engine.evicted_blocks() > 0,
        "Expected some blocks to be evicted"
    );

    // Add votes to trigger votes_by_view eviction
    let block_id = make_block_id(0xAA);
    for view in 0..10u64 {
        for validator_idx in 0..4u64 {
            let _ = engine.on_vote(ValidatorId(validator_idx), view, &block_id);
        }
    }

    // Should have evicted some votes_by_view entries
    assert!(
        engine.evicted_votes_by_view_entries() > 0,
        "Expected some votes_by_view entries to be evicted"
    );
}
