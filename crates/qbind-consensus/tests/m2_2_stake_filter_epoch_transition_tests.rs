//! M2.2: Stake filtering epoch transition integration tests.
//!
//! These tests verify that:
//! - `StakeFilteringEpochStateProvider` correctly filters validators below minimum stake
//! - Epoch transitions exclude low-stake validators from leader schedule
//! - Quorum thresholds reflect only included validators
//! - Fail-closed behavior when all validators are excluded
//! - Determinism of filtering results

use qbind_consensus::basic_hotstuff_engine::BasicHotStuffEngine;
use qbind_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, StakeFilteringEpochStateProvider,
    StaticEpochStateProvider, ValidatorSetEntry,
};
use qbind_consensus::{EpochStateProvider, ValidatorId};

/// Create a validator set with specified validator IDs and voting powers.
/// For this test, voting_power serves as a proxy for stake (as documented in
/// StakeFilteringEpochStateProvider).
fn make_validator_set_with_stakes(id_stakes: &[(u64, u64)]) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = id_stakes
        .iter()
        .map(|&(id, stake)| ValidatorSetEntry {
            id: ValidatorId(id),
            voting_power: stake, // voting_power used as stake proxy
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

fn make_simple_validator_set(ids: &[u64]) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = ids
        .iter()
        .map(|&i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

// ============================================================================
// StakeFilteringEpochStateProvider Basic Tests
// ============================================================================

#[test]
fn m2_2_stake_filtering_provider_excludes_low_stake_validators() {
    // Setup: 3 validators with different stakes
    // Validator 1: 500,000 microQBIND (below 1M threshold)
    // Validator 2: 1,000,000 microQBIND (at threshold)
    // Validator 3: 2,000,000 microQBIND (above threshold)
    let validators = make_validator_set_with_stakes(&[
        (1, 500_000),   // Below threshold
        (2, 1_000_000), // At threshold
        (3, 2_000_000), // Above threshold
    ]);

    let epoch_state = EpochState::genesis(validators);
    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch_state);

    // Create stake-filtering provider with 1 QBIND minimum stake
    let min_stake = 1_000_000;
    let provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    // Get filtered epoch state
    let filtered_state = provider.get_epoch_state(EpochId::GENESIS);
    assert!(filtered_state.is_some(), "should return filtered epoch state");

    let state = filtered_state.unwrap();

    // Validator 1 should be excluded (stake < min_stake)
    assert!(
        !state.contains(ValidatorId(1)),
        "validator 1 should be excluded (500k < 1M)"
    );

    // Validators 2 and 3 should be included
    assert!(
        state.contains(ValidatorId(2)),
        "validator 2 should be included (1M >= 1M)"
    );
    assert!(
        state.contains(ValidatorId(3)),
        "validator 3 should be included (2M >= 1M)"
    );

    // Check total count
    assert_eq!(state.len(), 2, "filtered set should have 2 validators");
}

#[test]
fn m2_2_stake_filtering_provider_includes_all_when_above_threshold() {
    // All validators above threshold
    let validators = make_validator_set_with_stakes(&[
        (1, 2_000_000),
        (2, 3_000_000),
        (3, 5_000_000),
    ]);

    let epoch_state = EpochState::genesis(validators);
    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch_state);

    let min_stake = 1_000_000;
    let provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    let filtered_state = provider.get_epoch_state(EpochId::GENESIS);
    assert!(filtered_state.is_some());

    let state = filtered_state.unwrap();
    assert_eq!(state.len(), 3, "all validators should be included");
    assert!(state.contains(ValidatorId(1)));
    assert!(state.contains(ValidatorId(2)));
    assert!(state.contains(ValidatorId(3)));
}

#[test]
fn m2_2_stake_filtering_provider_zero_min_stake_passes_through() {
    // With min_stake = 0, all validators should pass through
    let validators = make_validator_set_with_stakes(&[
        (1, 0),     // Zero stake
        (2, 1),     // Minimal stake
        (3, 1_000), // Small stake
    ]);

    let epoch_state = EpochState::genesis(validators);
    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch_state);

    let min_stake = 0;
    let provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    let filtered_state = provider.get_epoch_state(EpochId::GENESIS);
    assert!(filtered_state.is_some());

    let state = filtered_state.unwrap();
    assert_eq!(state.len(), 3, "all validators should pass through with min_stake=0");
}

// ============================================================================
// Fail-Closed Behavior Tests
// ============================================================================

#[test]
fn m2_2_stake_filtering_fails_closed_when_all_excluded() {
    // All validators below threshold
    let validators = make_validator_set_with_stakes(&[
        (1, 500_000),
        (2, 600_000),
        (3, 700_000),
    ]);

    let epoch_state = EpochState::genesis(validators);
    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch_state);

    let min_stake = 1_000_000;
    let provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    // Should return None (fail closed)
    let filtered_state = provider.get_epoch_state(EpochId::GENESIS);
    assert!(
        filtered_state.is_none(),
        "should fail closed when all validators excluded"
    );

    // Check error details
    let error = provider.last_filter_error();
    assert!(error.is_some(), "should have recorded filter error");

    let err = error.unwrap();
    assert_eq!(err.epoch, EpochId::GENESIS);
    assert_eq!(err.total_candidates, 3);
    assert_eq!(err.min_stake, min_stake);
}

#[test]
fn m2_2_stake_filtering_clears_error_on_success() {
    // Setup provider with multiple epochs
    let validators_low = make_validator_set_with_stakes(&[(1, 100), (2, 200)]);
    let validators_high = make_validator_set_with_stakes(&[(3, 2_000_000), (4, 3_000_000)]);

    let inner_provider = StaticEpochStateProvider::new()
        .with_epoch(EpochState::genesis(validators_low))
        .with_epoch(EpochState::new(EpochId::new(1), validators_high));

    let min_stake = 1_000_000;
    let provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    // First, fail on epoch 0
    let result0 = provider.get_epoch_state(EpochId::GENESIS);
    assert!(result0.is_none());
    assert!(provider.last_filter_error().is_some());

    // Then succeed on epoch 1
    let result1 = provider.get_epoch_state(EpochId::new(1));
    assert!(result1.is_some());

    // Error should be cleared
    assert!(
        provider.last_filter_error().is_none(),
        "error should be cleared after successful filtering"
    );
}

// ============================================================================
// Leader Schedule Tests (Filtered validators excluded from leadership)
// ============================================================================

#[test]
fn m2_2_leader_schedule_excludes_filtered_validators() {
    // Setup: 4 validators, 1 below threshold
    let validators = make_validator_set_with_stakes(&[
        (1, 500_000),   // Below threshold - will be excluded
        (2, 1_000_000), // At threshold
        (3, 1_500_000), // Above threshold
        (4, 2_000_000), // Above threshold
    ]);

    let epoch_state = EpochState::new(EpochId::new(1), validators.clone());
    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch_state);

    let min_stake = 1_000_000;
    let provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    let filtered_state = provider.get_epoch_state(EpochId::new(1));
    assert!(filtered_state.is_some());

    let state = filtered_state.unwrap();

    // Create engine with unfiltered set first
    let unfiltered_set = validators;
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(2), unfiltered_set);

    // Verify initial leader includes validator 1
    let leaders_before: Vec<ValidatorId> = (0..4).map(|v| engine.leader_for_view(v)).collect();
    assert!(
        leaders_before.contains(&ValidatorId(1)),
        "before filtering, validator 1 should be in leader rotation"
    );

    // Transition to epoch with filtered validator set
    let result = engine.transition_to_epoch(EpochId::new(1), state.validator_set.clone());
    assert!(result.is_ok());

    // Check leader schedule after transition - validator 1 should NOT appear
    // The filtered set has 3 validators: 2, 3, 4
    let leaders_after: Vec<ValidatorId> = (0..10).map(|v| engine.leader_for_view(v)).collect();

    // Validator 1 should NEVER appear as leader after filtering
    assert!(
        !leaders_after.contains(&ValidatorId(1)),
        "after filtering, validator 1 should NOT be in leader rotation"
    );

    // Verify only filtered validators appear
    for leader in &leaders_after {
        assert!(
            *leader == ValidatorId(2) || *leader == ValidatorId(3) || *leader == ValidatorId(4),
            "leader {:?} should be one of the filtered validators (2, 3, 4)",
            leader
        );
    }
}

// ============================================================================
// Quorum Threshold Tests (Filtered set affects quorum calculation)
// ============================================================================

#[test]
fn m2_2_quorum_threshold_reflects_filtered_set() {
    // Setup: 4 validators, 1 excluded
    let validators = make_validator_set_with_stakes(&[
        (1, 500_000),   // Below threshold - excluded
        (2, 1_000_000), // Included, voting power = 1
        (3, 1_000_000), // Included, voting power = 1
        (4, 1_000_000), // Included, voting power = 1
    ]);

    let epoch_state = EpochState::genesis(validators.clone());
    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch_state);

    let min_stake = 1_000_000;
    let provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    let filtered_state = provider.get_epoch_state(EpochId::GENESIS).unwrap();

    // Original set: 4 validators, total VP = 4, quorum = ceil(2*4/3) = 3
    // Filtered set: 3 validators, total VP = 3, quorum = ceil(2*3/3) = 2
    let unfiltered_quorum = validators.two_thirds_vp();
    let filtered_quorum = filtered_state.validator_set.two_thirds_vp();

    // Note: In this test, voting_power equals stake value, so:
    // Original: total = 500k + 1M + 1M + 1M = 3.5M, quorum = ceil(7M/3) = 2,333,334
    // But that's not how ConsensusValidatorSet works - VP values are counted directly
    // So we use the stake values as VP values in this test
    assert!(
        filtered_quorum <= unfiltered_quorum,
        "filtered quorum ({}) should be <= unfiltered ({})",
        filtered_quorum,
        unfiltered_quorum
    );

    // More specifically, test has_quorum behavior
    let filtered_set = &filtered_state.validator_set;

    // With 3 validators (VP=1M each), total VP = 3M, quorum = 2M
    // Quorum needs 2 of 3 validators
    assert!(
        filtered_set.has_quorum([ValidatorId(2), ValidatorId(3)]),
        "2 of 3 validators should be quorum"
    );

    // Single validator should NOT be quorum
    assert!(
        !filtered_set.has_quorum([ValidatorId(2)]),
        "1 of 3 validators should NOT be quorum"
    );

    // Excluded validator should not count towards quorum
    // Even if validator 1 votes, it doesn't add to quorum since it's excluded
    assert!(
        !filtered_set.has_quorum([ValidatorId(1), ValidatorId(2)]),
        "excluded validator should not contribute to quorum"
    );
}

// ============================================================================
// Determinism Tests
// ============================================================================

#[test]
fn m2_2_stake_filtering_is_deterministic() {
    // Create same validators in different input orders
    let validators_order1 = make_validator_set_with_stakes(&[
        (1, 500_000),
        (2, 1_000_000),
        (3, 2_000_000),
    ]);

    // Note: ConsensusValidatorSet sorts internally, so we test
    // that the provider produces same results regardless of which
    // epoch state it's given

    let inner1 = StaticEpochStateProvider::new()
        .with_epoch(EpochState::genesis(validators_order1.clone()));
    let inner2 = StaticEpochStateProvider::new()
        .with_epoch(EpochState::genesis(validators_order1.clone()));

    let min_stake = 1_000_000;
    let provider1 = StakeFilteringEpochStateProvider::new(inner1, min_stake);
    let provider2 = StakeFilteringEpochStateProvider::new(inner2, min_stake);

    let state1 = provider1.get_epoch_state(EpochId::GENESIS).unwrap();
    let state2 = provider2.get_epoch_state(EpochId::GENESIS).unwrap();

    // Same validators in same order
    let ids1: Vec<_> = state1.validator_set.iter().map(|v| v.id).collect();
    let ids2: Vec<_> = state2.validator_set.iter().map(|v| v.id).collect();

    assert_eq!(ids1, ids2, "filtered sets should be identical");

    // Same total voting power
    assert_eq!(
        state1.validator_set.total_voting_power(),
        state2.validator_set.total_voting_power()
    );
}

// ============================================================================
// Multiple Epoch Transition Tests
// ============================================================================

#[test]
fn m2_2_stake_filtering_works_across_multiple_epochs() {
    // Epoch 0: validators 1,2,3 - validator 1 low stake
    let validators0 = make_validator_set_with_stakes(&[
        (1, 500_000),
        (2, 1_000_000),
        (3, 2_000_000),
    ]);

    // Epoch 1: validators 2,3,4 - all above threshold
    let validators1 = make_validator_set_with_stakes(&[
        (2, 1_500_000),
        (3, 2_500_000),
        (4, 3_000_000),
    ]);

    // Epoch 2: validators 3,4,5 - validator 5 low stake
    let validators2 = make_validator_set_with_stakes(&[
        (3, 2_000_000),
        (4, 2_500_000),
        (5, 800_000),
    ]);

    let inner = StaticEpochStateProvider::new()
        .with_epoch(EpochState::genesis(validators0))
        .with_epoch(EpochState::new(EpochId::new(1), validators1))
        .with_epoch(EpochState::new(EpochId::new(2), validators2));

    let min_stake = 1_000_000;
    let provider = StakeFilteringEpochStateProvider::new(inner, min_stake);

    // Epoch 0: validator 1 excluded
    let state0 = provider.get_epoch_state(EpochId::GENESIS).unwrap();
    assert!(!state0.contains(ValidatorId(1)));
    assert!(state0.contains(ValidatorId(2)));
    assert!(state0.contains(ValidatorId(3)));
    assert_eq!(state0.len(), 2);

    // Epoch 1: all included
    let state1 = provider.get_epoch_state(EpochId::new(1)).unwrap();
    assert!(state1.contains(ValidatorId(2)));
    assert!(state1.contains(ValidatorId(3)));
    assert!(state1.contains(ValidatorId(4)));
    assert_eq!(state1.len(), 3);

    // Epoch 2: validator 5 excluded
    let state2 = provider.get_epoch_state(EpochId::new(2)).unwrap();
    assert!(state2.contains(ValidatorId(3)));
    assert!(state2.contains(ValidatorId(4)));
    assert!(!state2.contains(ValidatorId(5)));
    assert_eq!(state2.len(), 2);
}

// ============================================================================
// Provider Diagnostics Tests
// ============================================================================

#[test]
fn m2_2_provider_reports_min_stake_threshold() {
    let validators = make_simple_validator_set(&[1, 2, 3]);
    let inner = StaticEpochStateProvider::new()
        .with_epoch(EpochState::genesis(validators));

    let min_stake = 5_000_000;
    let provider = StakeFilteringEpochStateProvider::new(inner, min_stake);

    assert_eq!(provider.min_validator_stake(), min_stake);
}

#[test]
fn m2_2_provider_returns_none_for_unknown_epoch() {
    let validators = make_simple_validator_set(&[1, 2, 3]);
    let inner = StaticEpochStateProvider::new()
        .with_epoch(EpochState::genesis(validators));

    let min_stake = 0; // No filtering to isolate inner provider behavior
    let provider = StakeFilteringEpochStateProvider::new(inner, min_stake);

    // Epoch 0 exists
    assert!(provider.get_epoch_state(EpochId::GENESIS).is_some());

    // Epoch 99 does not exist
    assert!(provider.get_epoch_state(EpochId::new(99)).is_none());

    // Unknown epoch should not set filter error (it's not a filter failure)
    assert!(provider.last_filter_error().is_none());
}

// ============================================================================
// Engine Integration Tests (Full epoch transition with filtering)
// ============================================================================

#[test]
fn m2_2_engine_epoch_transition_with_filtered_provider() {
    // Setup genesis with 4 validators, 1 will be excluded in epoch 1
    let genesis_validators = make_validator_set_with_stakes(&[
        (1, 2_000_000),
        (2, 2_000_000),
        (3, 2_000_000),
        (4, 2_000_000),
    ]);

    // Epoch 1: validator 1 drops below threshold
    let epoch1_validators = make_validator_set_with_stakes(&[
        (1, 500_000),   // Below threshold - will be excluded
        (2, 2_000_000), // Included
        (3, 2_000_000), // Included
        (4, 2_000_000), // Included
    ]);

    let inner = StaticEpochStateProvider::new()
        .with_epoch(EpochState::genesis(genesis_validators.clone()))
        .with_epoch(EpochState::new(EpochId::new(1), epoch1_validators));

    let min_stake = 1_000_000;
    let provider = StakeFilteringEpochStateProvider::new(inner, min_stake);

    // Create engine at genesis
    let genesis_state = provider.get_epoch_state(EpochId::GENESIS).unwrap();
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(2), genesis_state.validator_set.clone());

    assert_eq!(engine.current_epoch(), 0);

    // At genesis, all 4 validators are included (all have 2M stake)
    assert_eq!(genesis_state.len(), 4);
    assert!(genesis_state.contains(ValidatorId(1)));

    // Transition to epoch 1
    let epoch1_state = provider.get_epoch_state(EpochId::new(1)).unwrap();

    // Epoch 1 should have only 3 validators (1 excluded)
    assert_eq!(epoch1_state.len(), 3);
    assert!(!epoch1_state.contains(ValidatorId(1)));

    let result = engine.transition_to_epoch(EpochId::new(1), epoch1_state.validator_set.clone());
    assert!(result.is_ok());

    assert_eq!(engine.current_epoch(), 1);

    // Verify leader schedule excludes validator 1
    for view in 0..10 {
        let leader = engine.leader_for_view(view);
        assert_ne!(
            leader,
            ValidatorId(1),
            "validator 1 should not be leader in epoch 1"
        );
    }
}

#[test]
fn m2_2_error_display_is_informative() {
    let err = qbind_consensus::StakeFilterEmptySetError {
        epoch: EpochId::new(5),
        total_candidates: 10,
        min_stake: 1_000_000,
    };

    let msg = format!("{}", err);
    assert!(msg.contains("EpochId(5)") || msg.contains("epoch"));
    assert!(msg.contains("10 validators") || msg.contains("10"));
    assert!(msg.contains("1000000"));
    assert!(msg.contains("fail-closed") || msg.contains("Fail") || msg.contains("guard"));
}
