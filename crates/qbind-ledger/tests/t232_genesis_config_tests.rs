//! T232: Genesis Configuration Tests
//!
//! Tests for the genesis state model and validation logic in qbind-ledger.
//!
//! # Test Coverage
//!
//! - **Basic Validation**: Valid configs pass, invalid configs rejected
//! - **Allocation Invariants**: Zero amounts, duplicate addresses
//! - **Validator Invariants**: Empty set, duplicate addresses, missing PQC keys
//! - **Council Invariants**: Threshold bounds, duplicate members
//! - **Monetary Config**: Roundtrip conversion to/from MonetaryEngineConfig

use qbind_ledger::{
    GenesisAllocation, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig,
    GenesisValidationError, GenesisValidator, MonetaryEngineConfig, PhaseParameters,
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Returns a default monetary config for testing.
fn test_monetary_config() -> GenesisMonetaryConfig {
    GenesisMonetaryConfig::mainnet_default()
}

/// Returns a valid genesis config for testing.
fn valid_genesis_config() -> GenesisConfig {
    GenesisConfig::new(
        "qbind-testnet-v0",
        1738000000000,
        vec![
            GenesisAllocation::new("0x1111111111111111111111111111111111111111", 1_000_000),
            GenesisAllocation::new("0x2222222222222222222222222222222222222222", 2_000_000),
        ],
        vec![
            GenesisValidator::new(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "pqc_key_validator_1",
                100_000,
            ),
            GenesisValidator::new(
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "pqc_key_validator_2",
                200_000,
            ),
        ],
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        test_monetary_config(),
    )
}

// ============================================================================
// Test 1: Basic Validation (as specified in T232)
// ============================================================================

/// Test: Valid genesis config with 2 allocations, 2 validators, 3 council members, threshold=2.
///
/// This test verifies:
/// 1. A well-formed genesis config passes validation
/// 2. Total supply is computed correctly
/// 3. Validator and council counts are correct
#[test]
fn test_genesis_valid_basic() {
    let config = valid_genesis_config();
    assert!(config.validate().is_ok());

    // Check computed values
    assert_eq!(config.total_supply(), 3_000_000);
    assert_eq!(config.validator_count(), 2);
    assert_eq!(config.council_member_count(), 3);
    assert_eq!(config.council.threshold, 2);
}

// ============================================================================
// Test 2: Allocation with amount=0 is rejected (T232 requirement)
// ============================================================================

/// Test: Allocation with amount=0 → error.
///
/// This test verifies:
/// 1. Zero allocation amounts are detected
/// 2. Correct error type is returned
#[test]
fn test_genesis_rejects_zero_allocation() {
    let mut config = valid_genesis_config();
    config.allocations[0].amount = 0;

    let result = config.validate();
    assert!(result.is_err());

    match result {
        Err(GenesisValidationError::ZeroAllocationAmount { address }) => {
            assert_eq!(address, config.allocations[0].address);
        }
        other => panic!("Expected ZeroAllocationAmount, got {:?}", other),
    }
}

// ============================================================================
// Test 3: Duplicate address in allocations is rejected (T232 requirement)
// ============================================================================

/// Test: Same address appears twice in allocations → error.
///
/// This test verifies:
/// 1. Duplicate allocation addresses are detected
/// 2. Correct error type is returned
#[test]
fn test_genesis_rejects_duplicate_address() {
    let mut config = valid_genesis_config();
    config.allocations[1].address = config.allocations[0].address.clone();

    let result = config.validate();
    assert!(result.is_err());

    match result {
        Err(GenesisValidationError::DuplicateAllocationAddress { address }) => {
            assert_eq!(address, config.allocations[0].address);
        }
        other => panic!("Expected DuplicateAllocationAddress, got {:?}", other),
    }
}

// ============================================================================
// Test 4: Invalid council threshold is rejected (T232 requirement)
// ============================================================================

/// Test: Council threshold > member count → error.
///
/// This test verifies:
/// 1. Threshold exceeding member count is detected
/// 2. Threshold of 0 is detected
/// 3. Correct error types are returned
#[test]
fn test_genesis_rejects_invalid_council_threshold() {
    // Test threshold > members
    let mut config = valid_genesis_config();
    config.council.threshold = 10; // Only 3 members

    let result = config.validate();
    assert!(result.is_err());

    match result {
        Err(GenesisValidationError::CouncilThresholdTooHigh {
            threshold,
            member_count,
        }) => {
            assert_eq!(threshold, 10);
            assert_eq!(member_count, 3);
        }
        other => panic!("Expected CouncilThresholdTooHigh, got {:?}", other),
    }

    // Test threshold = 0
    let mut config2 = valid_genesis_config();
    config2.council.threshold = 0;

    let result2 = config2.validate();
    assert!(result2.is_err());

    assert!(matches!(
        result2,
        Err(GenesisValidationError::CouncilThresholdZero)
    ));
}

// ============================================================================
// Test 5: Monetary config roundtrip (T232 requirement)
// ============================================================================

/// Test: GenesisMonetaryConfig built from existing MonetaryEngineConfig validates.
///
/// This test verifies:
/// 1. Conversion from MonetaryEngineConfig to GenesisMonetaryConfig works
/// 2. Conversion back to MonetaryEngineConfig preserves key values
#[test]
fn test_genesis_monetary_config_roundtrips() {
    // Create an engine config
    let engine_config = MonetaryEngineConfig {
        pqc_premium_compute: 0.30,
        pqc_premium_bandwidth: 0.15,
        pqc_premium_storage: 0.10,
        bootstrap: PhaseParameters {
            r_target_annual: 0.05,
            inflation_floor_annual: 0.0,
            fee_smoothing_half_life_days: 30.0,
            max_annual_inflation_cap: 0.12,
            ema_lambda_bps: 700,
            max_delta_r_inf_per_epoch_bps: 25,
        },
        transition: PhaseParameters {
            r_target_annual: 0.04,
            inflation_floor_annual: 0.0,
            fee_smoothing_half_life_days: 60.0,
            max_annual_inflation_cap: 0.10,
            ema_lambda_bps: 300,
            max_delta_r_inf_per_epoch_bps: 10,
        },
        mature: PhaseParameters {
            r_target_annual: 0.03,
            inflation_floor_annual: 0.01,
            fee_smoothing_half_life_days: 90.0,
            max_annual_inflation_cap: 0.08,
            ema_lambda_bps: 150,
            max_delta_r_inf_per_epoch_bps: 5,
        },
        alpha_fee_offset: 1.0,
    };

    // Convert to genesis config
    let genesis_monetary = GenesisMonetaryConfig::from_engine_config(&engine_config);

    // Convert back
    let roundtrip = genesis_monetary.to_engine_config();

    // Check key fields match
    assert_eq!(
        roundtrip.pqc_premium_compute,
        engine_config.pqc_premium_compute
    );
    assert_eq!(
        roundtrip.pqc_premium_bandwidth,
        engine_config.pqc_premium_bandwidth
    );
    assert_eq!(
        roundtrip.pqc_premium_storage,
        engine_config.pqc_premium_storage
    );
    assert_eq!(
        roundtrip.bootstrap.r_target_annual,
        engine_config.bootstrap.r_target_annual
    );
    assert_eq!(
        roundtrip.bootstrap.max_annual_inflation_cap,
        engine_config.bootstrap.max_annual_inflation_cap
    );
    assert_eq!(
        roundtrip.bootstrap.ema_lambda_bps,
        engine_config.bootstrap.ema_lambda_bps
    );
    assert_eq!(
        roundtrip.transition.r_target_annual,
        engine_config.transition.r_target_annual
    );
    assert_eq!(
        roundtrip.mature.r_target_annual,
        engine_config.mature.r_target_annual
    );
    assert_eq!(
        roundtrip.mature.inflation_floor_annual,
        engine_config.mature.inflation_floor_annual
    );
    assert_eq!(roundtrip.alpha_fee_offset, engine_config.alpha_fee_offset);
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

/// Test: Empty chain ID is rejected.
#[test]
fn test_genesis_rejects_empty_chain_id() {
    let mut config = valid_genesis_config();
    config.chain_id = "".to_string();

    assert!(matches!(
        config.validate(),
        Err(GenesisValidationError::EmptyChainId)
    ));
}

/// Test: No allocations is rejected.
#[test]
fn test_genesis_rejects_no_allocations() {
    let mut config = valid_genesis_config();
    config.allocations.clear();

    assert!(matches!(
        config.validate(),
        Err(GenesisValidationError::NoAllocations)
    ));
}

/// Test: No validators is rejected.
#[test]
fn test_genesis_rejects_no_validators() {
    let mut config = valid_genesis_config();
    config.validators.clear();

    assert!(matches!(
        config.validate(),
        Err(GenesisValidationError::NoValidators)
    ));
}

/// Test: Duplicate validator address is rejected.
#[test]
fn test_genesis_rejects_duplicate_validator() {
    let mut config = valid_genesis_config();
    config.validators[1].address = config.validators[0].address.clone();

    assert!(matches!(
        config.validate(),
        Err(GenesisValidationError::DuplicateValidatorAddress { .. })
    ));
}

/// Test: Duplicate council member is rejected.
#[test]
fn test_genesis_rejects_duplicate_council_member() {
    let mut config = valid_genesis_config();
    config.council.members[1] = config.council.members[0].clone();

    assert!(matches!(
        config.validate(),
        Err(GenesisValidationError::DuplicateCouncilMember { .. })
    ));
}

/// Test: Empty validator PQC key is rejected.
#[test]
fn test_genesis_rejects_empty_validator_pqc_key() {
    let mut config = valid_genesis_config();
    config.validators[0].pqc_public_key = "".to_string();

    assert!(matches!(
        config.validate(),
        Err(GenesisValidationError::EmptyValidatorPqcKey { .. })
    ));
}

/// Test: Allocation with lockup.
#[test]
fn test_genesis_allocation_with_lockup() {
    let mut config = valid_genesis_config();
    config.allocations[0] = GenesisAllocation::with_lockup(
        "0x1111111111111111111111111111111111111111",
        1_000_000,
        1900000000000, // Lockup until 2030
    );

    assert!(config.validate().is_ok());
    assert_eq!(
        config.allocations[0].lockup_until_unix_ms,
        Some(1900000000000)
    );
}

/// Test: Allocation with memo.
#[test]
fn test_genesis_allocation_with_memo() {
    let mut config = valid_genesis_config();
    config.allocations[0] = GenesisAllocation::with_memo(
        "0x1111111111111111111111111111111111111111",
        1_000_000,
        "Foundation allocation",
    );

    assert!(config.validate().is_ok());
    assert_eq!(
        config.allocations[0].memo,
        Some("Foundation allocation".to_string())
    );
}

/// Test: Validator with name and metadata.
#[test]
fn test_genesis_validator_with_name() {
    let mut config = valid_genesis_config();
    config.validators[0] = GenesisValidator::with_name(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "pqc_key_validator_1",
        100_000,
        "Validator One",
    );
    config.validators[0].metadata = Some("https://validator-one.example.com".to_string());

    assert!(config.validate().is_ok());
    assert_eq!(
        config.validators[0].name,
        Some("Validator One".to_string())
    );
    assert_eq!(
        config.validators[0].metadata,
        Some("https://validator-one.example.com".to_string())
    );
}

/// Test: MainNet default monetary config.
#[test]
fn test_genesis_mainnet_monetary_defaults() {
    let monetary = GenesisMonetaryConfig::mainnet_default();

    // Verify MainNet defaults from design doc
    assert!((monetary.pqc_premium_compute - 0.30).abs() < 0.001);
    assert!((monetary.pqc_premium_bandwidth - 0.15).abs() < 0.001);
    assert!((monetary.pqc_premium_storage - 0.10).abs() < 0.001);
    assert!((monetary.bootstrap_r_target_annual - 0.05).abs() < 0.001);
    assert!((monetary.transition_r_target_annual - 0.04).abs() < 0.001);
    assert!((monetary.mature_r_target_annual - 0.03).abs() < 0.001);
    assert!((monetary.mature_inflation_floor_annual - 0.01).abs() < 0.001);
}

/// Test: JSON serialization roundtrip.
#[test]
fn test_genesis_json_roundtrip() {
    let config = valid_genesis_config();

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&config).expect("Failed to serialize");

    // Deserialize back
    let parsed: GenesisConfig = serde_json::from_str(&json).expect("Failed to deserialize");

    // Check key fields
    assert_eq!(parsed.chain_id, config.chain_id);
    assert_eq!(parsed.genesis_time_unix_ms, config.genesis_time_unix_ms);
    assert_eq!(parsed.allocations.len(), config.allocations.len());
    assert_eq!(parsed.validators.len(), config.validators.len());
    assert_eq!(parsed.council.threshold, config.council.threshold);

    // Validate the parsed config
    assert!(parsed.validate().is_ok());
}