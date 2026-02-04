//! T197: Monetary Seigniorage Tests
//!
//! Tests for the seigniorage split computation and distribution logic.
//!
//! # Test Coverage
//!
//! - **Conservation**: Total issuance equals sum of all bucket amounts
//! - **Determinism**: Same inputs always produce same outputs
//! - **Rounding**: Remainder is assigned to treasury, no over-mint
//! - **Mode semantics**: Shadow vs Active mode behavior

use qbind_ledger::monetary_engine::{
    compute_seigniorage_split, parse_monetary_mode, MonetaryAccounts, MonetaryMode,
    SeigniorageSplit, SEIGNIORAGE_SPLIT_MAINNET_DEFAULT, VALID_MONETARY_MODES,
};

// ============================================================================
// Conservation Tests
// ============================================================================

/// Test that seigniorage split conserves total issuance.
///
/// Requirements:
/// - For any total_issuance and valid SeigniorageSplit:
///   - Sum of all bucket amounts equals total_issuance
///   - All bucket amounts are >= 0
#[test]
fn test_seigniorage_split_conservation() {
    let split = SEIGNIORAGE_SPLIT_MAINNET_DEFAULT;

    // Test various issuance amounts
    let test_amounts: &[u128] = &[
        0,
        1,
        10,
        100,
        1_000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
        u128::MAX / 2,
    ];

    for &total in test_amounts {
        let accounting = compute_seigniorage_split(total, &split);

        // Conservation check
        let sum = accounting
            .to_validators
            .saturating_add(accounting.to_treasury)
            .saturating_add(accounting.to_insurance)
            .saturating_add(accounting.to_community);

        assert_eq!(
            sum, total,
            "Conservation failed: sum {} != total {} for issuance {}",
            sum, total, total
        );

        assert!(accounting.is_balanced(), "is_balanced() should return true");

        // All amounts should be non-negative (they're u128, so this is always true)
        // but we verify explicitly
        assert!(accounting.to_validators <= total);
        assert!(accounting.to_treasury <= total);
        assert!(accounting.to_insurance <= total);
        assert!(accounting.to_community <= total);
    }
}

/// Test conservation with the default MainNet split (50/30/10/10).
#[test]
fn test_mainnet_default_split_conservation() {
    let split = SEIGNIORAGE_SPLIT_MAINNET_DEFAULT;

    // Verify the default split is valid
    assert!(split.is_valid(), "MainNet default split should be valid");
    assert_eq!(
        split.sum(),
        10_000,
        "MainNet default split should sum to 10,000 bps"
    );

    // Test with a round number (should have no rounding issues)
    let accounting = compute_seigniorage_split(1_000_000, &split);

    assert_eq!(accounting.to_validators, 500_000, "50% of 1M = 500K");
    assert_eq!(accounting.to_treasury, 300_000, "30% of 1M = 300K");
    assert_eq!(accounting.to_insurance, 100_000, "10% of 1M = 100K");
    assert_eq!(accounting.to_community, 100_000, "10% of 1M = 100K");
    assert!(accounting.is_balanced());
}

// ============================================================================
// Determinism Tests
// ============================================================================

/// Test that seigniorage split is deterministic.
///
/// Requirements:
/// - Same inputs always produce identical outputs
/// - No random or time-dependent behavior
#[test]
fn test_seigniorage_split_rounding_deterministic() {
    let split = SEIGNIORAGE_SPLIT_MAINNET_DEFAULT;

    // Test values that cause rounding
    let test_amounts: &[u128] = &[1, 2, 3, 10, 11, 17, 33, 99, 101, 999, 1001, 9999];

    for &total in test_amounts {
        // Compute twice and compare
        let result1 = compute_seigniorage_split(total, &split);
        let result2 = compute_seigniorage_split(total, &split);

        assert_eq!(
            result1.to_validators, result2.to_validators,
            "Validators should be deterministic for total {}",
            total
        );
        assert_eq!(
            result1.to_treasury, result2.to_treasury,
            "Treasury should be deterministic for total {}",
            total
        );
        assert_eq!(
            result1.to_insurance, result2.to_insurance,
            "Insurance should be deterministic for total {}",
            total
        );
        assert_eq!(
            result1.to_community, result2.to_community,
            "Community should be deterministic for total {}",
            total
        );

        // Verify no over-mint (conservation)
        assert!(
            result1.is_balanced(),
            "Result should be balanced for total {}",
            total
        );
    }
}

/// Test that rounding remainder goes to treasury.
#[test]
fn test_rounding_remainder_goes_to_treasury() {
    // Use a split that will cause rounding with small amounts
    let split = SEIGNIORAGE_SPLIT_MAINNET_DEFAULT;

    // With total = 3:
    // validators = floor(3 * 5000 / 10000) = floor(1.5) = 1
    // insurance = floor(3 * 1000 / 10000) = floor(0.3) = 0
    // community = floor(3 * 1000 / 10000) = floor(0.3) = 0
    // treasury = 3 - 1 - 0 - 0 = 2 (gets the remainder)
    let accounting = compute_seigniorage_split(3, &split);

    assert_eq!(accounting.to_validators, 1);
    assert_eq!(accounting.to_insurance, 0);
    assert_eq!(accounting.to_community, 0);
    assert_eq!(accounting.to_treasury, 2); // Gets remainder
    assert_eq!(accounting.total_issuance, 3);
    assert!(accounting.is_balanced());
}

// ============================================================================
// Split Validation Tests
// ============================================================================

/// Test that split validation works correctly.
#[test]
fn test_split_validation() {
    // Valid split
    let valid_split = SeigniorageSplit::new(5_000, 3_000, 1_000, 1_000);
    assert!(valid_split.is_valid());
    assert!(valid_split.validate().is_ok());

    // Invalid splits (cannot use new() as it panics)
    let invalid_splits = [
        SeigniorageSplit {
            validators_bps: 5_000,
            treasury_bps: 3_000,
            insurance_bps: 1_000,
            community_bps: 999, // Sum = 9999
        },
        SeigniorageSplit {
            validators_bps: 5_000,
            treasury_bps: 3_000,
            insurance_bps: 1_000,
            community_bps: 1_001, // Sum = 10001
        },
        SeigniorageSplit {
            validators_bps: 0,
            treasury_bps: 0,
            insurance_bps: 0,
            community_bps: 0, // Sum = 0
        },
    ];

    for split in &invalid_splits {
        assert!(!split.is_valid(), "Split {:?} should be invalid", split);
        assert!(
            split.validate().is_err(),
            "Split {:?} should fail validation",
            split
        );
    }
}

/// Test that new() panics with invalid split.
#[test]
#[should_panic(expected = "SeigniorageSplit sum must equal 10,000")]
fn test_new_split_panics_on_invalid_sum() {
    let _ = SeigniorageSplit::new(5_000, 3_000, 1_000, 999);
}

// ============================================================================
// MonetaryMode Tests
// ============================================================================

/// Test monetary mode parsing.
#[test]
fn test_parse_monetary_mode() {
    // Valid values (case-insensitive)
    assert_eq!(parse_monetary_mode("off"), Some(MonetaryMode::Off));
    assert_eq!(parse_monetary_mode("OFF"), Some(MonetaryMode::Off));
    assert_eq!(parse_monetary_mode("Off"), Some(MonetaryMode::Off));
    assert_eq!(parse_monetary_mode("shadow"), Some(MonetaryMode::Shadow));
    assert_eq!(parse_monetary_mode("SHADOW"), Some(MonetaryMode::Shadow));
    assert_eq!(parse_monetary_mode("Shadow"), Some(MonetaryMode::Shadow));
    assert_eq!(parse_monetary_mode("active"), Some(MonetaryMode::Active));
    assert_eq!(parse_monetary_mode("ACTIVE"), Some(MonetaryMode::Active));
    assert_eq!(parse_monetary_mode("Active"), Some(MonetaryMode::Active));

    // Invalid values
    assert_eq!(parse_monetary_mode(""), None);
    assert_eq!(parse_monetary_mode("invalid"), None);
    assert_eq!(parse_monetary_mode("on"), None);
    assert_eq!(parse_monetary_mode("enabled"), None);
}

/// Test monetary mode display.
#[test]
fn test_monetary_mode_display() {
    assert_eq!(format!("{}", MonetaryMode::Off), "off");
    assert_eq!(format!("{}", MonetaryMode::Shadow), "shadow");
    assert_eq!(format!("{}", MonetaryMode::Active), "active");
}

/// Test VALID_MONETARY_MODES constant.
#[test]
fn test_valid_monetary_modes_constant() {
    assert_eq!(VALID_MONETARY_MODES.len(), 3);
    assert!(VALID_MONETARY_MODES.contains(&"off"));
    assert!(VALID_MONETARY_MODES.contains(&"shadow"));
    assert!(VALID_MONETARY_MODES.contains(&"active"));
}

/// Test MonetaryMode default.
#[test]
fn test_monetary_mode_default() {
    let mode: MonetaryMode = Default::default();
    assert_eq!(mode, MonetaryMode::Off);
}

// ============================================================================
// MonetaryAccounts Tests
// ============================================================================

/// Test that test accounts are created correctly.
#[test]
fn test_monetary_accounts_test_accounts() {
    let accounts = MonetaryAccounts::test_accounts();

    // All accounts should be distinct
    assert!(
        accounts.all_distinct(),
        "Test accounts should all be distinct"
    );

    // Verify accounts are non-zero
    assert_ne!(accounts.validator_pool, [0u8; 32]);
    assert_ne!(accounts.treasury, [0u8; 32]);
    assert_ne!(accounts.insurance, [0u8; 32]);
    assert_ne!(accounts.community, [0u8; 32]);
}

/// Test that all_distinct works correctly.
#[test]
fn test_monetary_accounts_all_distinct() {
    // Distinct accounts
    let distinct = MonetaryAccounts::new([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
    assert!(distinct.all_distinct());

    // Duplicate accounts
    let duplicate_1_2 = MonetaryAccounts::new([1u8; 32], [1u8; 32], [3u8; 32], [4u8; 32]);
    assert!(!duplicate_1_2.all_distinct());

    let duplicate_1_3 = MonetaryAccounts::new([1u8; 32], [2u8; 32], [1u8; 32], [4u8; 32]);
    assert!(!duplicate_1_3.all_distinct());

    let duplicate_1_4 = MonetaryAccounts::new([1u8; 32], [2u8; 32], [3u8; 32], [1u8; 32]);
    assert!(!duplicate_1_4.all_distinct());

    let duplicate_2_3 = MonetaryAccounts::new([1u8; 32], [2u8; 32], [2u8; 32], [4u8; 32]);
    assert!(!duplicate_2_3.all_distinct());

    let duplicate_2_4 = MonetaryAccounts::new([1u8; 32], [2u8; 32], [3u8; 32], [2u8; 32]);
    assert!(!duplicate_2_4.all_distinct());

    let duplicate_3_4 = MonetaryAccounts::new([1u8; 32], [2u8; 32], [3u8; 32], [3u8; 32]);
    assert!(!duplicate_3_4.all_distinct());
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Test zero issuance.
#[test]
fn test_zero_issuance() {
    let split = SEIGNIORAGE_SPLIT_MAINNET_DEFAULT;
    let accounting = compute_seigniorage_split(0, &split);

    assert_eq!(accounting.total_issuance, 0);
    assert_eq!(accounting.to_validators, 0);
    assert_eq!(accounting.to_treasury, 0);
    assert_eq!(accounting.to_insurance, 0);
    assert_eq!(accounting.to_community, 0);
    assert!(accounting.is_balanced());
}

/// Test single unit issuance.
#[test]
fn test_single_unit_issuance() {
    let split = SEIGNIORAGE_SPLIT_MAINNET_DEFAULT;
    let accounting = compute_seigniorage_split(1, &split);

    // With 50/30/10/10 split and total=1:
    // validators = floor(1 * 5000 / 10000) = 0
    // insurance = floor(1 * 1000 / 10000) = 0
    // community = floor(1 * 1000 / 10000) = 0
    // treasury = 1 - 0 - 0 - 0 = 1
    assert_eq!(accounting.total_issuance, 1);
    assert_eq!(accounting.to_validators, 0);
    assert_eq!(accounting.to_treasury, 1); // Gets the single unit
    assert_eq!(accounting.to_insurance, 0);
    assert_eq!(accounting.to_community, 0);
    assert!(accounting.is_balanced());
}

/// Test large issuance (near u128::MAX).
#[test]
fn test_large_issuance() {
    let split = SEIGNIORAGE_SPLIT_MAINNET_DEFAULT;
    let large_value = u128::MAX / 10_000; // Avoid overflow in multiplication
    let accounting = compute_seigniorage_split(large_value, &split);

    assert!(accounting.is_balanced());
    assert_eq!(accounting.total_issuance, large_value);
}

/// Test custom split configurations.
#[test]
fn test_custom_splits() {
    // All to validators
    let all_validators = SeigniorageSplit::new(10_000, 0, 0, 0);
    let accounting = compute_seigniorage_split(1_000_000, &all_validators);
    assert_eq!(accounting.to_validators, 1_000_000);
    assert_eq!(accounting.to_treasury, 0);
    assert_eq!(accounting.to_insurance, 0);
    assert_eq!(accounting.to_community, 0);
    assert!(accounting.is_balanced());

    // All to treasury
    let all_treasury = SeigniorageSplit::new(0, 10_000, 0, 0);
    let accounting = compute_seigniorage_split(1_000_000, &all_treasury);
    assert_eq!(accounting.to_validators, 0);
    assert_eq!(accounting.to_treasury, 1_000_000);
    assert_eq!(accounting.to_insurance, 0);
    assert_eq!(accounting.to_community, 0);
    assert!(accounting.is_balanced());

    // Equal split (25% each)
    let equal_split = SeigniorageSplit::new(2_500, 2_500, 2_500, 2_500);
    let accounting = compute_seigniorage_split(1_000_000, &equal_split);
    assert_eq!(accounting.to_validators, 250_000);
    assert_eq!(accounting.to_insurance, 250_000);
    assert_eq!(accounting.to_community, 250_000);
    // Treasury gets remainder (250_000)
    assert!(accounting.is_balanced());
}
