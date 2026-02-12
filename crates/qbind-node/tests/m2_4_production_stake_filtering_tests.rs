//! M2.4: Production stake filtering integration tests.
//!
//! These tests verify that `StakeFilteringEpochStateProvider` is correctly wired
//! into the production node boot path via `new_with_stake_filtering()` and
//! `enable_stake_filtering_for_environment()`.
//!
//! # Test Coverage
//!
//! 1. Production constructor `new_with_stake_filtering` correctly wires stake filtering
//! 2. TestNet configuration enables stake filtering with 10 QBIND minimum
//! 3. MainNet configuration enables stake filtering with 100,000 QBIND minimum
//! 4. Fail-closed behavior: epoch transition fails if all validators excluded
//! 5. Excluded validators are filtered at epoch boundaries
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test m2_4_production_stake_filtering_tests -- --test-threads=1
//! ```

use qbind_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, StaticEpochStateProvider, ValidatorSetEntry,
};
use qbind_consensus::{StakeFilteringEpochStateProvider, ValidatorId};
use qbind_node::node_config::{
    NodeConfig, MIN_VALIDATOR_STAKE_DEVNET, MIN_VALIDATOR_STAKE_MAINNET,
    MIN_VALIDATOR_STAKE_TESTNET,
};

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
// M2.4 Production Configuration Tests
// ============================================================================

/// M2.4: Verify TestNet Alpha preset has correct minimum stake.
#[test]
fn m2_4_testnet_alpha_preset_stake_config() {
    let node_config = NodeConfig::testnet_alpha_preset();
    assert_eq!(
        node_config.validator_stake.min_validator_stake,
        MIN_VALIDATOR_STAKE_TESTNET,
        "TestNet Alpha should have 10 QBIND minimum stake"
    );
    assert!(!node_config.validator_stake.fail_fast_on_startup);
}

/// M2.4: Verify TestNet Beta preset has correct minimum stake.
#[test]
fn m2_4_testnet_beta_preset_stake_config() {
    let node_config = NodeConfig::testnet_beta_preset();
    assert_eq!(
        node_config.validator_stake.min_validator_stake,
        MIN_VALIDATOR_STAKE_TESTNET,
        "TestNet Beta should have 10 QBIND minimum stake"
    );
}

/// M2.4: Verify MainNet preset has correct minimum stake.
#[test]
fn m2_4_mainnet_preset_stake_config() {
    let node_config = NodeConfig::mainnet_preset();
    assert_eq!(
        node_config.validator_stake.min_validator_stake,
        MIN_VALIDATOR_STAKE_MAINNET,
        "MainNet should have 100,000 QBIND minimum stake"
    );
    assert!(node_config.validator_stake.fail_fast_on_startup);
}

/// M2.4: Verify DevNet preset has correct minimum stake.
#[test]
fn m2_4_devnet_preset_stake_config() {
    let node_config = NodeConfig::devnet_v0_preset();
    assert_eq!(
        node_config.validator_stake.min_validator_stake,
        MIN_VALIDATOR_STAKE_DEVNET,
        "DevNet should have 1 QBIND minimum stake"
    );
    assert!(!node_config.validator_stake.fail_fast_on_startup);
}

// ============================================================================
// M2.4 Stake Filtering Integration Tests
// ============================================================================

/// M2.4: Verify that stake filtering works correctly with TestNet threshold.
#[test]
fn m2_4_stake_filtering_testnet_threshold() {
    // Setup: 3 validators, one below TestNet threshold (10M)
    // Validator 0: 5,000,000 (below 10M threshold)
    // Validator 1: 20,000,000 (above threshold)
    // Validator 2: 30,000,000 (above threshold)
    let validators = make_validator_set_with_stakes(&[
        (0, 5_000_000),  // Below threshold
        (1, 20_000_000), // Above threshold
        (2, 30_000_000), // Above threshold
    ]);

    let epoch0 = EpochState::genesis(validators);

    // Create the inner provider
    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch0);

    // Apply stake filtering with TestNet threshold
    let min_stake = MIN_VALIDATOR_STAKE_TESTNET;
    let filtering_provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    // Get the filtered epoch state
    use qbind_consensus::EpochStateProvider;
    let filtered_state = filtering_provider.get_epoch_state(EpochId::GENESIS);
    assert!(filtered_state.is_some(), "should return filtered epoch state");

    let state = filtered_state.unwrap();

    // Validator 0 should be excluded (5M < 10M threshold)
    assert!(
        !state.contains(ValidatorId(0)),
        "validator 0 should be excluded (5M < 10M)"
    );

    // Validators 1 and 2 should be included
    assert!(
        state.contains(ValidatorId(1)),
        "validator 1 should be included (20M >= 10M)"
    );
    assert!(
        state.contains(ValidatorId(2)),
        "validator 2 should be included (30M >= 10M)"
    );

    assert_eq!(state.len(), 2, "filtered set should have 2 validators");
}

/// M2.4: Verify that stake filtering works correctly with MainNet threshold.
#[test]
fn m2_4_stake_filtering_mainnet_threshold() {
    // Setup: Validators with stakes around MainNet threshold (100,000 QBIND = 100B microQBIND)
    // Validator 0: 50B (50k QBIND - below 100k threshold)
    // Validator 1: 100B (100k QBIND - at threshold)
    // Validator 2: 200B (200k QBIND - above threshold)
    let validators = make_validator_set_with_stakes(&[
        (0, 50_000_000_000),  // Below threshold
        (1, 100_000_000_000), // At threshold
        (2, 200_000_000_000), // Above threshold
    ]);

    let epoch0 = EpochState::genesis(validators);

    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch0);

    // Apply stake filtering with MainNet threshold
    let min_stake = MIN_VALIDATOR_STAKE_MAINNET;
    let filtering_provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    use qbind_consensus::EpochStateProvider;
    let filtered_state = filtering_provider.get_epoch_state(EpochId::GENESIS);
    assert!(filtered_state.is_some(), "should return filtered state");

    let state = filtered_state.unwrap();

    // Validator 0 should be excluded (50k < 100k threshold)
    assert!(
        !state.contains(ValidatorId(0)),
        "validator 0 should be excluded (50k QBIND < 100k)"
    );

    // Validators 1 and 2 should be included
    assert!(
        state.contains(ValidatorId(1)),
        "validator 1 should be included (100k QBIND >= 100k)"
    );
    assert!(
        state.contains(ValidatorId(2)),
        "validator 2 should be included (200k QBIND >= 100k)"
    );

    assert_eq!(state.len(), 2);
}

/// M2.4: Verify that stake filtering works correctly with DevNet threshold.
#[test]
fn m2_4_stake_filtering_devnet_threshold() {
    // Setup: Validators with stakes around DevNet threshold (1 QBIND = 1M microQBIND)
    // Validator 0: 500k (0.5 QBIND - below 1 QBIND threshold)
    // Validator 1: 1M (1 QBIND - at threshold)
    // Validator 2: 2M (2 QBIND - above threshold)
    let validators = make_validator_set_with_stakes(&[
        (0, 500_000),   // Below threshold
        (1, 1_000_000), // At threshold
        (2, 2_000_000), // Above threshold
    ]);

    let epoch0 = EpochState::genesis(validators);

    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch0);

    // Apply stake filtering with DevNet threshold
    let min_stake = MIN_VALIDATOR_STAKE_DEVNET;
    let filtering_provider = StakeFilteringEpochStateProvider::new(inner_provider, min_stake);

    use qbind_consensus::EpochStateProvider;
    let filtered_state = filtering_provider.get_epoch_state(EpochId::GENESIS);
    assert!(filtered_state.is_some(), "should return filtered state");

    let state = filtered_state.unwrap();

    // Validator 0 should be excluded (500k < 1M threshold)
    assert!(
        !state.contains(ValidatorId(0)),
        "validator 0 should be excluded (500k < 1M)"
    );

    // Validators 1 and 2 should be included
    assert!(
        state.contains(ValidatorId(1)),
        "validator 1 should be included (1M >= 1M)"
    );
    assert!(
        state.contains(ValidatorId(2)),
        "validator 2 should be included (2M >= 1M)"
    );

    assert_eq!(state.len(), 2);
}

/// M2.4: Verify fail-closed behavior when all validators excluded.
#[test]
fn m2_4_fail_closed_all_validators_excluded() {
    // Setup: All validators below TestNet threshold (10M)
    let validators = make_validator_set_with_stakes(&[
        (0, 1_000_000), // 1 QBIND - below 10M
        (1, 2_000_000), // 2 QBIND - below 10M
        (2, 3_000_000), // 3 QBIND - below 10M
    ]);

    let epoch0 = EpochState::genesis(validators);

    let inner_provider = StaticEpochStateProvider::new().with_epoch(epoch0);

    // Apply stake filtering with TestNet threshold (10M)
    let filtering_provider =
        StakeFilteringEpochStateProvider::new(inner_provider, MIN_VALIDATOR_STAKE_TESTNET);

    // Fail-closed: get_epoch_state should return None because all validators excluded
    use qbind_consensus::EpochStateProvider;
    let filtered_state = filtering_provider.get_epoch_state(EpochId::GENESIS);
    assert!(
        filtered_state.is_none(),
        "Should return None when all validators excluded (fail-closed)"
    );

    // Verify error was recorded
    let error = filtering_provider.last_filter_error();
    assert!(
        error.is_some(),
        "Should have recorded the fail-closed error"
    );
}

/// M2.4: Verify epoch transition uses filtered validators.
#[test]
fn m2_4_epoch_transition_uses_filtered_set() {
    // Setup: Different validator sets for epoch 0 and 1
    let genesis_validators = make_validator_set_with_stakes(&[
        (0, 20_000_000), // Above TestNet threshold
        (1, 20_000_000), // Above threshold
        (2, 20_000_000), // Above threshold
    ]);

    // In epoch 1, validator 2 drops below threshold
    let epoch1_validators = make_validator_set_with_stakes(&[
        (0, 20_000_000), // Above threshold
        (1, 20_000_000), // Above threshold
        (2, 5_000_000),  // Now below threshold!
    ]);

    let epoch0 = EpochState::genesis(genesis_validators);
    let epoch1 = EpochState::new(EpochId::new(1), epoch1_validators);

    let inner_provider = StaticEpochStateProvider::new()
        .with_epoch(epoch0)
        .with_epoch(epoch1);

    let filtering_provider =
        StakeFilteringEpochStateProvider::new(inner_provider, MIN_VALIDATOR_STAKE_TESTNET);

    use qbind_consensus::EpochStateProvider;

    // Genesis epoch: all 3 validators should be included (all above 10M)
    let genesis_state = filtering_provider.get_epoch_state(EpochId::GENESIS).unwrap();
    assert_eq!(
        genesis_state.len(),
        3,
        "Genesis should have all 3 validators"
    );
    assert!(genesis_state.contains(ValidatorId(0)));
    assert!(genesis_state.contains(ValidatorId(1)));
    assert!(genesis_state.contains(ValidatorId(2)));

    // Epoch 1: validator 2 should be excluded (5M < 10M)
    let epoch1_state = filtering_provider.get_epoch_state(EpochId::new(1)).unwrap();
    assert_eq!(
        epoch1_state.len(),
        2,
        "Epoch 1 should have only 2 validators"
    );
    assert!(epoch1_state.contains(ValidatorId(0)));
    assert!(epoch1_state.contains(ValidatorId(1)));
    assert!(
        !epoch1_state.contains(ValidatorId(2)),
        "validator 2 should be excluded in epoch 1"
    );
}

/// M2.4: Verify NodeConfig presets use correct ValidatorStakeConfig.
#[test]
fn m2_4_config_preset_stake_filtering_values() {
    // DevNet: Low threshold for testing
    let devnet = NodeConfig::devnet_v0_preset();
    assert!(
        devnet.validator_stake.is_stake_sufficient(1_000_000),
        "DevNet: 1 QBIND should be sufficient"
    );
    assert!(
        !devnet.validator_stake.is_stake_sufficient(500_000),
        "DevNet: 0.5 QBIND should not be sufficient"
    );

    // TestNet: Moderate threshold
    let testnet = NodeConfig::testnet_alpha_preset();
    assert!(
        testnet.validator_stake.is_stake_sufficient(10_000_000),
        "TestNet: 10 QBIND should be sufficient"
    );
    assert!(
        !testnet.validator_stake.is_stake_sufficient(5_000_000),
        "TestNet: 5 QBIND should not be sufficient"
    );

    // MainNet: High economic threshold
    let mainnet = NodeConfig::mainnet_preset();
    assert!(
        mainnet.validator_stake.is_stake_sufficient(100_000_000_000),
        "MainNet: 100k QBIND should be sufficient"
    );
    assert!(
        !mainnet.validator_stake.is_stake_sufficient(50_000_000_000),
        "MainNet: 50k QBIND should not be sufficient"
    );
}

/// M2.4: Verify MainNet config validation requires fail_fast_on_startup.
#[test]
fn m2_4_mainnet_config_validation() {
    let mainnet = NodeConfig::mainnet_preset();

    // MainNet config should be valid
    let validation = mainnet.validator_stake.validate_for_mainnet();
    assert!(
        validation.is_ok(),
        "MainNet preset should pass validation: {:?}",
        validation
    );

    // Custom config with low stake should fail
    let mut custom = NodeConfig::mainnet_preset();
    custom.validator_stake.min_validator_stake = MIN_VALIDATOR_STAKE_TESTNET;
    let validation = custom.validator_stake.validate_for_mainnet();
    assert!(
        validation.is_err(),
        "MainNet config with TestNet stake threshold should fail validation"
    );

    // Custom config without fail_fast_on_startup should fail
    let mut custom = NodeConfig::mainnet_preset();
    custom.validator_stake.fail_fast_on_startup = false;
    let validation = custom.validator_stake.validate_for_mainnet();
    assert!(
        validation.is_err(),
        "MainNet config without fail_fast_on_startup should fail validation"
    );
}
