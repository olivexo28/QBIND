//! Tests for the `validator_set` module.
//!
//! These tests verify that:
//! - `ConsensusValidatorSet::new` rejects empty input
//! - `ConsensusValidatorSet::new` rejects duplicate `ValidatorId`s
//! - Index lookup and `contains` work correctly
//! - Total voting power sums correctly

use qbind_consensus::{ConsensusValidatorSet, ValidatorId, ValidatorSetEntry};

/// Test that an empty validator set is rejected.
#[test]
fn validator_set_rejects_empty() {
    let validators: Vec<ValidatorSetEntry> = vec![];
    let result = ConsensusValidatorSet::new(validators);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("must not be empty"),
        "Expected 'must not be empty' error, got: {}",
        err
    );
}

/// Test that duplicate ValidatorIds are rejected.
#[test]
fn validator_set_rejects_duplicate_ids() {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 10,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 20,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(1), // Duplicate
            voting_power: 30,
        },
    ];

    let result = ConsensusValidatorSet::new(validators);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("duplicate ValidatorId"),
        "Expected 'duplicate ValidatorId' error, got: {}",
        err
    );
}

/// Test that index_of and contains work correctly.
#[test]
fn validator_set_index_and_contains_work() {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(10),
            voting_power: 100,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(20),
            voting_power: 200,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(30),
            voting_power: 300,
        },
    ];

    let set = ConsensusValidatorSet::new(validators).expect("should succeed");

    // Test index_of
    assert_eq!(set.index_of(ValidatorId::new(10)), Some(0));
    assert_eq!(set.index_of(ValidatorId::new(20)), Some(1));
    assert_eq!(set.index_of(ValidatorId::new(30)), Some(2));
    assert_eq!(set.index_of(ValidatorId::new(99)), None);

    // Test contains
    assert!(set.contains(ValidatorId::new(10)));
    assert!(set.contains(ValidatorId::new(20)));
    assert!(set.contains(ValidatorId::new(30)));
    assert!(!set.contains(ValidatorId::new(99)));

    // Test get
    let v0 = set.get(0).expect("index 0 should exist");
    assert_eq!(v0.id, ValidatorId::new(10));

    let v2 = set.get(2).expect("index 2 should exist");
    assert_eq!(v2.id, ValidatorId::new(30));

    assert!(set.get(3).is_none());
}

/// Test that total voting power sums correctly.
#[test]
fn validator_set_total_voting_power_sums_correctly() {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 100,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 200,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(3),
            voting_power: 300,
        },
    ];

    let set = ConsensusValidatorSet::new(validators).expect("should succeed");

    assert_eq!(set.total_voting_power(), 600);
    assert_eq!(set.len(), 3);
}

/// Test that voting power saturates instead of overflowing.
#[test]
fn validator_set_total_voting_power_saturates_on_overflow() {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: u64::MAX,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 1,
        },
    ];

    let set = ConsensusValidatorSet::new(validators).expect("should succeed");

    // Should saturate to u64::MAX instead of panicking or overflowing
    assert_eq!(set.total_voting_power(), u64::MAX);
}

/// Test iteration over validators.
#[test]
fn validator_set_iter_works() {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 10,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 20,
        },
    ];

    let set = ConsensusValidatorSet::new(validators).expect("should succeed");

    let collected: Vec<&ValidatorSetEntry> = set.iter().collect();
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].id, ValidatorId::new(1));
    assert_eq!(collected[1].id, ValidatorId::new(2));
}

// ============================================================================
// M2.1: Stake filtering tests for epoch boundary
// ============================================================================

use qbind_consensus::{build_validator_set_with_stake_filter, ValidatorCandidate};

/// Test that validators below minimum stake are excluded from ValidatorSet at epoch transition.
#[test]
fn m2_1_validator_below_min_stake_excluded() {
    // Define minimum stake: 1,000,000 microQBIND (1 QBIND)
    let min_stake: u64 = 1_000_000;

    let candidates = vec![
        ValidatorCandidate::new(ValidatorId::new(1), 500_000, 1),    // Below threshold
        ValidatorCandidate::new(ValidatorId::new(2), 1_000_000, 1),  // At threshold
        ValidatorCandidate::new(ValidatorId::new(3), 2_000_000, 1),  // Above threshold
    ];

    let result = build_validator_set_with_stake_filter(candidates, min_stake)
        .expect("should succeed with at least one eligible validator");

    // Validator 1 should be excluded (500k < 1M)
    assert!(!result.validator_set.contains(ValidatorId::new(1)));
    
    // Validators 2 and 3 should be included
    assert!(result.validator_set.contains(ValidatorId::new(2)));
    assert!(result.validator_set.contains(ValidatorId::new(3)));
    
    // Check counts
    assert_eq!(result.validator_set.len(), 2);
    assert_eq!(result.excluded.len(), 1);
    assert_eq!(result.excluded[0].validator_id, ValidatorId::new(1));
    assert_eq!(result.excluded[0].stake, 500_000);
}

/// Test that validators at or above minimum stake are included in ValidatorSet.
#[test]
fn m2_1_validator_at_or_above_min_stake_included() {
    let min_stake: u64 = 1_000_000;

    let candidates = vec![
        ValidatorCandidate::new(ValidatorId::new(1), 1_000_000, 1),   // Exactly at threshold
        ValidatorCandidate::new(ValidatorId::new(2), 1_000_001, 1),   // One above threshold
        ValidatorCandidate::new(ValidatorId::new(3), 10_000_000, 1),  // Well above threshold
    ];

    let result = build_validator_set_with_stake_filter(candidates, min_stake)
        .expect("should succeed");

    // All validators should be included
    assert_eq!(result.validator_set.len(), 3);
    assert_eq!(result.excluded.len(), 0);
    
    assert!(result.validator_set.contains(ValidatorId::new(1)));
    assert!(result.validator_set.contains(ValidatorId::new(2)));
    assert!(result.validator_set.contains(ValidatorId::new(3)));
}

/// Test determinism: same inputs produce same ValidatorSet ordering regardless of input order.
#[test]
fn m2_1_stake_filter_deterministic_ordering() {
    let min_stake: u64 = 1_000_000;

    // First ordering: 1, 2, 3
    let candidates_order1 = vec![
        ValidatorCandidate::new(ValidatorId::new(1), 2_000_000, 1),
        ValidatorCandidate::new(ValidatorId::new(2), 3_000_000, 1),
        ValidatorCandidate::new(ValidatorId::new(3), 1_500_000, 1),
    ];

    // Second ordering: 3, 1, 2 (different input order)
    let candidates_order2 = vec![
        ValidatorCandidate::new(ValidatorId::new(3), 1_500_000, 1),
        ValidatorCandidate::new(ValidatorId::new(1), 2_000_000, 1),
        ValidatorCandidate::new(ValidatorId::new(2), 3_000_000, 1),
    ];

    // Third ordering: 2, 3, 1 (yet another input order)
    let candidates_order3 = vec![
        ValidatorCandidate::new(ValidatorId::new(2), 3_000_000, 1),
        ValidatorCandidate::new(ValidatorId::new(3), 1_500_000, 1),
        ValidatorCandidate::new(ValidatorId::new(1), 2_000_000, 1),
    ];

    let result1 = build_validator_set_with_stake_filter(candidates_order1, min_stake)
        .expect("should succeed");
    let result2 = build_validator_set_with_stake_filter(candidates_order2, min_stake)
        .expect("should succeed");
    let result3 = build_validator_set_with_stake_filter(candidates_order3, min_stake)
        .expect("should succeed");

    // All results should have the same validator IDs in the same order
    assert_eq!(result1.validator_set.len(), result2.validator_set.len());
    assert_eq!(result1.validator_set.len(), result3.validator_set.len());
    
    // Check ordering by iterating - should be sorted by validator_id (1, 2, 3)
    let ids1: Vec<_> = result1.validator_set.iter().map(|v| v.id).collect();
    let ids2: Vec<_> = result2.validator_set.iter().map(|v| v.id).collect();
    let ids3: Vec<_> = result3.validator_set.iter().map(|v| v.id).collect();

    assert_eq!(ids1, ids2);
    assert_eq!(ids2, ids3);
    
    // Verify the expected deterministic ordering (sorted by validator_id)
    assert_eq!(ids1[0], ValidatorId::new(1));
    assert_eq!(ids1[1], ValidatorId::new(2));
    assert_eq!(ids1[2], ValidatorId::new(3));
}

/// Test that filtering with all validators below threshold fails.
#[test]
fn m2_1_stake_filter_fails_if_no_eligible_validators() {
    let min_stake: u64 = 1_000_000;

    let candidates = vec![
        ValidatorCandidate::new(ValidatorId::new(1), 500_000, 1),
        ValidatorCandidate::new(ValidatorId::new(2), 999_999, 1),
    ];

    let result = build_validator_set_with_stake_filter(candidates, min_stake);

    // Should fail because no validators meet the threshold
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("must not be empty"),
        "Expected empty validator set error, got: {}",
        err
    );
}

/// Test that filtering with zero min_stake includes all validators.
#[test]
fn m2_1_stake_filter_zero_min_stake_includes_all() {
    let min_stake: u64 = 0;

    let candidates = vec![
        ValidatorCandidate::new(ValidatorId::new(1), 0, 1),       // Zero stake
        ValidatorCandidate::new(ValidatorId::new(2), 1, 1),       // Minimal stake
        ValidatorCandidate::new(ValidatorId::new(3), 1_000_000, 1),
    ];

    let result = build_validator_set_with_stake_filter(candidates, min_stake)
        .expect("should succeed");

    // All validators should be included with min_stake = 0
    assert_eq!(result.validator_set.len(), 3);
    assert_eq!(result.excluded.len(), 0);
}

/// Test excluded validators are sorted by validator_id.
#[test]
fn m2_1_excluded_validators_sorted_by_id() {
    let min_stake: u64 = 1_000_000;

    // Input order: 3, 1, 2
    let candidates = vec![
        ValidatorCandidate::new(ValidatorId::new(3), 500_000, 1),  // Below threshold
        ValidatorCandidate::new(ValidatorId::new(1), 400_000, 1),  // Below threshold
        ValidatorCandidate::new(ValidatorId::new(2), 300_000, 1),  // Below threshold
        ValidatorCandidate::new(ValidatorId::new(4), 2_000_000, 1), // Above threshold
    ];

    let result = build_validator_set_with_stake_filter(candidates, min_stake)
        .expect("should succeed with at least one eligible validator");

    // Excluded should be sorted by validator_id (1, 2, 3)
    assert_eq!(result.excluded.len(), 3);
    assert_eq!(result.excluded[0].validator_id, ValidatorId::new(1));
    assert_eq!(result.excluded[1].validator_id, ValidatorId::new(2));
    assert_eq!(result.excluded[2].validator_id, ValidatorId::new(3));
}

/// Test voting power is preserved correctly in filtered set.
#[test]
fn m2_1_voting_power_preserved_in_filtered_set() {
    let min_stake: u64 = 1_000_000;

    let candidates = vec![
        ValidatorCandidate::new(ValidatorId::new(1), 2_000_000, 10),
        ValidatorCandidate::new(ValidatorId::new(2), 3_000_000, 20),
        ValidatorCandidate::new(ValidatorId::new(3), 500_000, 5),  // Excluded
    ];

    let result = build_validator_set_with_stake_filter(candidates, min_stake)
        .expect("should succeed");

    // Check that voting power is preserved
    assert_eq!(result.validator_set.len(), 2);
    
    let v1 = result.validator_set.get(0).expect("should have validator at index 0");
    let v2 = result.validator_set.get(1).expect("should have validator at index 1");
    
    assert_eq!(v1.id, ValidatorId::new(1));
    assert_eq!(v1.voting_power, 10);
    assert_eq!(v2.id, ValidatorId::new(2));
    assert_eq!(v2.voting_power, 20);
    
    // Total voting power should be sum of included validators
    assert_eq!(result.validator_set.total_voting_power(), 30);
}
