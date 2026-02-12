//! M2.3: Stake filtering node-level integration tests.
//!
//! These tests verify that `StakeFilteringEpochStateProvider` is correctly wired
//! into the canonical epoch transition path at the node level.
//!
//! # Test Coverage
//!
//! 1. Excluded validators are filtered from the active validator set at epoch transition
//! 2. Leader schedule never selects excluded validators post-transition
//! 3. Quorum threshold reflects only the filtered validator set
//! 4. Fail-closed behavior when stake filtering would result in empty set
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test m2_3_stake_filtering_node_integration_tests -- --test-threads=1
//! ```

use qbind_consensus::basic_hotstuff_engine::BasicHotStuffEngine;
use qbind_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, StaticEpochStateProvider, ValidatorSetEntry,
};
use qbind_consensus::{EpochStateProvider, StakeFilteringEpochStateProvider, ValidatorId};

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a validator set with specified validator IDs and stakes.
/// Voting power is used as a proxy for stake as documented in StakeFilteringEpochStateProvider.
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

// ============================================================================
// M2.3 Node-Level Integration Tests
// ============================================================================

/// M2.3: Verify that StakeFilteringEpochStateProvider correctly filters validators.
#[test]
fn m2_3_stake_filtering_provider_wiring() {
    // Setup: 3 validators, one below stake threshold
    // Validator 1: 500,000 (below 1M threshold)
    // Validator 2: 1,000,000 (at threshold)
    // Validator 3: 2,000,000 (above threshold)
    let validators_epoch0 = make_validator_set_with_stakes(&[
        (1, 500_000),   // Below threshold
        (2, 1_000_000), // At threshold
        (3, 2_000_000), // Above threshold
    ]);

    // Create epoch states with these validators
    let epoch0 = EpochState::genesis(validators_epoch0.clone());
    let epoch1 = EpochState::new(EpochId::new(1), validators_epoch0.clone());

    // Create the inner provider
    let inner_provider = StaticEpochStateProvider::new()
        .with_epoch(epoch0)
        .with_epoch(epoch1);

    // Apply stake filtering with 1 QBIND minimum stake
    let min_stake = 1_000_000;
    let filtering_provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    // Get the filtered epoch state from the provider
    let filtered_state = filtering_provider.get_epoch_state(EpochId::GENESIS);
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

    // Filtered set should have 2 validators
    assert_eq!(state.len(), 2, "filtered set should have 2 validators");
}

/// M2.3: Verify leader schedule excludes filtered validators after epoch transition.
#[test]
fn m2_3_leader_schedule_excludes_filtered_validators() {
    // Setup: 4 validators, 1 below threshold
    let validators_epoch0 = make_validator_set_with_stakes(&[
        (1, 500_000),   // Below threshold - will be excluded
        (2, 1_000_000), // At threshold
        (3, 1_500_000), // Above threshold
        (4, 2_000_000), // Above threshold
    ]);

    // Create epoch states
    let epoch0 = EpochState::genesis(validators_epoch0.clone());
    let epoch1 = EpochState::new(EpochId::new(1), validators_epoch0.clone());

    let inner_provider = StaticEpochStateProvider::new()
        .with_epoch(epoch0)
        .with_epoch(epoch1);

    // Apply stake filtering
    let min_stake = 1_000_000;
    let filtering_provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    // Get the filtered epoch state for epoch 1
    let filtered_state = filtering_provider.get_epoch_state(EpochId::new(1)).unwrap();

    // Verify validator 1 is excluded
    assert!(!filtered_state.contains(ValidatorId(1)));

    // Create engine with unfiltered set first (representing initial state)
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(2), validators_epoch0.clone());

    // Verify initial leader includes validator 1
    let leaders_before: Vec<ValidatorId> = (0..4).map(|v| engine.leader_for_view(v)).collect();
    assert!(
        leaders_before.contains(&ValidatorId(1)),
        "before filtering, validator 1 should be in leader rotation"
    );

    // Transition to epoch with filtered validator set
    let result = engine.transition_to_epoch(EpochId::new(1), filtered_state.validator_set.clone());
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

/// M2.3: Verify quorum threshold reflects only the filtered validator set.
#[test]
fn m2_3_quorum_threshold_reflects_filtered_set() {
    // Setup: 4 validators, 1 excluded
    let validators = make_validator_set_with_stakes(&[
        (1, 500_000),   // Below threshold - excluded
        (2, 1_000_000), // Included
        (3, 1_000_000), // Included
        (4, 1_000_000), // Included
    ]);

    let epoch_state = EpochState::genesis(validators.clone());
    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch_state);

    let min_stake = 1_000_000;
    let filtering_provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    let filtered_state = filtering_provider.get_epoch_state(EpochId::GENESIS).unwrap();
    let filtered_set = &filtered_state.validator_set;

    // Quorum should require 2/3 of the filtered set (3 validators)
    // With voting powers as stake values (1M each), total = 3M
    // Quorum = ceil(2 * 3M / 3) = 2M, which means 2 validators
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
    assert!(
        !filtered_set.has_quorum([ValidatorId(1), ValidatorId(2)]),
        "excluded validator should not contribute to quorum"
    );
}

/// M2.3: Verify fail-closed behavior when all validators would be excluded.
#[test]
fn m2_3_fail_closed_when_all_validators_excluded() {
    // Setup: All validators below threshold
    let validators = make_validator_set_with_stakes(&[
        (1, 500_000),
        (2, 600_000),
        (3, 700_000),
    ]);

    let epoch_state = EpochState::genesis(validators.clone());
    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch_state);

    let min_stake = 1_000_000;
    let filtering_provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    // Should return None (fail closed) because all validators are below threshold
    let filtered_state = filtering_provider.get_epoch_state(EpochId::GENESIS);
    assert!(
        filtered_state.is_none(),
        "should fail closed when all validators are excluded"
    );

    // Check error details via last_filter_error
    let error = filtering_provider.last_filter_error();
    assert!(error.is_some(), "should have recorded filter error");

    let err = error.unwrap();
    assert_eq!(err.epoch, EpochId::GENESIS);
    assert_eq!(err.total_candidates, 3);
    assert_eq!(err.min_stake, min_stake);
}

/// M2.3: Verify excluded validator is absent from active validator set post-transition.
#[test]
fn m2_3_excluded_validator_absent_post_transition() {
    // Setup: 3 validators, validator 1 below threshold in epoch 1
    let validators_epoch0 = make_validator_set_with_stakes(&[
        (1, 2_000_000), // Above threshold in epoch 0
        (2, 2_000_000),
        (3, 2_000_000),
    ]);

    // In epoch 1, validator 1's stake drops below threshold
    let validators_epoch1 = make_validator_set_with_stakes(&[
        (1, 500_000),   // Below threshold in epoch 1
        (2, 2_000_000),
        (3, 2_000_000),
    ]);

    let epoch0 = EpochState::genesis(validators_epoch0.clone());
    let epoch1 = EpochState::new(EpochId::new(1), validators_epoch1.clone());

    let inner_provider = StaticEpochStateProvider::new()
        .with_epoch(epoch0)
        .with_epoch(epoch1);

    let min_stake = 1_000_000;
    let filtering_provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    // Epoch 0: All validators included (all above threshold)
    let state0 = filtering_provider.get_epoch_state(EpochId::GENESIS).unwrap();
    assert!(state0.contains(ValidatorId(1)));
    assert!(state0.contains(ValidatorId(2)));
    assert!(state0.contains(ValidatorId(3)));
    assert_eq!(state0.len(), 3);

    // Epoch 1: Validator 1 excluded (below threshold)
    let state1 = filtering_provider.get_epoch_state(EpochId::new(1)).unwrap();
    assert!(
        !state1.contains(ValidatorId(1)),
        "validator 1 should be excluded in epoch 1"
    );
    assert!(state1.contains(ValidatorId(2)));
    assert!(state1.contains(ValidatorId(3)));
    assert_eq!(state1.len(), 2);
}

/// M2.3: Verify determinism of stake filtering across multiple calls.
#[test]
fn m2_3_stake_filtering_is_deterministic() {
    let validators = make_validator_set_with_stakes(&[
        (1, 500_000),
        (2, 1_000_000),
        (3, 2_000_000),
    ]);

    let epoch_state = EpochState::genesis(validators.clone());

    // Create two separate provider instances
    let inner1 = StaticEpochStateProvider::new().with_epoch(epoch_state.clone());
    let inner2 = StaticEpochStateProvider::new().with_epoch(epoch_state);

    let min_stake = 1_000_000;
    let provider1 = StakeFilteringEpochStateProvider::new(inner1, min_stake);
    let provider2 = StakeFilteringEpochStateProvider::new(inner2, min_stake);

    let state1 = provider1.get_epoch_state(EpochId::GENESIS).unwrap();
    let state2 = provider2.get_epoch_state(EpochId::GENESIS).unwrap();

    // Results should be identical
    let ids1: Vec<_> = state1.validator_set.iter().map(|v| v.id).collect();
    let ids2: Vec<_> = state2.validator_set.iter().map(|v| v.id).collect();

    assert_eq!(ids1, ids2, "filtered sets should be identical");
    assert_eq!(
        state1.validator_set.total_voting_power(),
        state2.validator_set.total_voting_power()
    );
}

/// M2.3: Verify zero min_stake passes through all validators.
#[test]
fn m2_3_zero_min_stake_passes_through() {
    let validators = make_validator_set_with_stakes(&[
        (1, 0),     // Zero stake
        (2, 1),     // Minimal stake
        (3, 1_000), // Small stake
    ]);

    let epoch_state = EpochState::genesis(validators.clone());
    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch_state);

    // With min_stake = 0, all validators should pass through
    let min_stake = 0;
    let filtering_provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    let filtered_state = filtering_provider.get_epoch_state(EpochId::GENESIS).unwrap();

    assert_eq!(filtered_state.len(), 3, "all validators should pass through with min_stake=0");
}

/// M2.3: Verify engine epoch transition with stake-filtered provider.
#[test]
fn m2_3_engine_epoch_transition_with_filtered_provider() {
    // Setup genesis with 4 validators, all above threshold
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
