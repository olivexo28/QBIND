//! T152 Gas Model Tests
//!
//! Tests for the QBIND gas model implementation including:
//! - Basic gas charge computation
//! - EIP-1559 effective gas price calculation
//! - Error cases (max_fee < base_fee, overflow)
//! - Gas limit validation

use qbind_runtime::{
    compute_gas_charges, default_gas_config, validate_tx_gas_price, Address, GasError,
    GasModelConfig, QbindTx, U256,
};

// ============================================================================
// Helper functions
// ============================================================================

fn make_test_addr(byte: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = byte;
    Address::from_bytes(bytes)
}

fn make_test_tx(gas_limit: u64, max_fee: u128, max_priority_fee: u128) -> QbindTx {
    QbindTx::transfer(make_test_addr(1), make_test_addr(2), U256::from_u64(100), 0).with_gas(
        gas_limit,
        max_fee,
        max_priority_fee,
    )
}

// ============================================================================
// Test: Basic gas charge computation
// ============================================================================

#[test]
fn test_compute_gas_charges_basic() {
    let cfg = default_gas_config();
    // base_fee = 1, max_fee = 10, max_priority = 2, gas_used = 1000
    let tx = make_test_tx(21000, 10, 2);
    let gas_used = 1000;

    let charges = compute_gas_charges(&cfg, &tx, gas_used).expect("should succeed");

    // effective_gas_price = base(1) + min(priority(2), max_fee(10) - base(1))
    //                     = 1 + min(2, 9) = 1 + 2 = 3
    assert_eq!(charges.effective_gas_price, 3);
    assert_eq!(charges.gas_used, 1000);
    // total_fee = 1000 * 3 = 3000
    assert_eq!(charges.total_fee, 3000);
    // No burning, all to proposer
    assert_eq!(charges.burned_fee, 0);
    assert_eq!(charges.proposer_fee, 3000);
}

#[test]
fn test_compute_gas_charges_tip_capped_by_headroom() {
    let cfg = default_gas_config();
    // max_fee = 5, max_priority = 100 (very high)
    // headroom = 5 - 1 = 4, so tip_cap = min(100, 4) = 4
    let tx = make_test_tx(21000, 5, 100);
    let gas_used = 1000;

    let charges = compute_gas_charges(&cfg, &tx, gas_used).expect("should succeed");

    // effective_gas_price = 1 + 4 = 5
    assert_eq!(charges.effective_gas_price, 5);
    assert_eq!(charges.total_fee, 1000 * 5);
    assert_eq!(charges.proposer_fee, 5000);
}

#[test]
fn test_compute_gas_charges_standard_transfer() {
    let cfg = default_gas_config();
    // Standard 21k gas transfer at 1 Gwei
    let tx = make_test_tx(21000, 1_000_000_000, 1_000_000_000);
    let gas_used = 21000;

    let charges = compute_gas_charges(&cfg, &tx, gas_used).expect("should succeed");

    // With base_fee = 1, effective = 1 + 1 = 2 (capped by base_fee=1)
    // Actually: base=1, max_priority=1B, max_fee=1B, headroom = 1B-1 = ~1B
    // tip = min(1B, ~1B) = 1B-1? No wait...
    // max_fee = 1_000_000_000, base = 1, headroom = 999_999_999
    // tip = min(1_000_000_000, 999_999_999) = 999_999_999
    // effective = 1 + 999_999_999 = 1_000_000_000
    assert_eq!(charges.effective_gas_price, 1_000_000_000);
    assert_eq!(charges.gas_used, 21000);
    // total_fee = 21000 * 1_000_000_000 = 21_000_000_000_000
    assert_eq!(charges.total_fee, 21_000_000_000_000);
}

// ============================================================================
// Test: max_fee < base_fee rejection
// ============================================================================

#[test]
fn test_max_fee_below_base_fee_rejected() {
    let cfg = GasModelConfig {
        base_fee_per_gas: 100,
        tip_cap_floor: 0,
        burn_fraction_numerator: 0,
        burn_fraction_denominator: 1,
    };
    let tx = make_test_tx(21000, 50, 10); // max_fee = 50 < base_fee = 100

    let result = compute_gas_charges(&cfg, &tx, 21000);

    match result {
        Err(GasError::MaxFeeBelowBaseFee { max_fee, base_fee }) => {
            assert_eq!(max_fee, 50);
            assert_eq!(base_fee, 100);
        }
        other => panic!("expected MaxFeeBelowBaseFee, got {:?}", other),
    }
}

#[test]
fn test_validate_tx_gas_price_rejection() {
    let cfg = GasModelConfig {
        base_fee_per_gas: 100,
        tip_cap_floor: 0,
        burn_fraction_numerator: 0,
        burn_fraction_denominator: 1,
    };
    let tx = make_test_tx(21000, 50, 10);

    let result = validate_tx_gas_price(&cfg, &tx);
    assert!(result.is_err());

    match result {
        Err(GasError::MaxFeeBelowBaseFee { max_fee, base_fee }) => {
            assert_eq!(max_fee, 50);
            assert_eq!(base_fee, 100);
        }
        other => panic!("expected MaxFeeBelowBaseFee, got {:?}", other),
    }
}

// ============================================================================
// Test: gas_used exceeds gas_limit
// ============================================================================

#[test]
fn test_gas_exceeds_limit_rejected() {
    let cfg = default_gas_config();
    let tx = make_test_tx(21000, 10, 2);
    let gas_used = 30000; // Exceeds limit of 21000

    let result = compute_gas_charges(&cfg, &tx, gas_used);

    match result {
        Err(GasError::GasExceedsLimit {
            gas_used: gu,
            gas_limit: gl,
        }) => {
            assert_eq!(gu, 30000);
            assert_eq!(gl, 21000);
        }
        other => panic!("expected GasExceedsLimit, got {:?}", other),
    }
}

// ============================================================================
// Test: overflow detection
// ============================================================================

#[test]
fn test_overflow_detected_large_values() {
    let cfg = GasModelConfig {
        base_fee_per_gas: u128::MAX / 2,
        tip_cap_floor: 0,
        burn_fraction_numerator: 0,
        burn_fraction_denominator: 1,
    };
    // max_fee >= base_fee to pass the first check
    let tx = make_test_tx(u64::MAX, u128::MAX, u128::MAX / 2);
    let gas_used = u64::MAX;

    let result = compute_gas_charges(&cfg, &tx, gas_used);

    // Should detect overflow during multiplication
    match result {
        Err(GasError::GasOverflow) => {} // Expected
        Err(GasError::GasExceedsLimit { .. }) => {
            // Also acceptable - gas_used == gas_limit so this passes
            panic!("unexpected GasExceedsLimit when gas_used == gas_limit");
        }
        Ok(_) => panic!("expected overflow error, got success"),
        other => panic!("expected GasOverflow, got {:?}", other),
    }
}

// ============================================================================
// Test: zero gas used
// ============================================================================

#[test]
fn test_zero_gas_used() {
    let cfg = default_gas_config();
    let tx = make_test_tx(21000, 10, 2);
    let gas_used = 0;

    let charges = compute_gas_charges(&cfg, &tx, gas_used).expect("should succeed");

    assert_eq!(charges.gas_used, 0);
    assert_eq!(charges.total_fee, 0);
    assert_eq!(charges.proposer_fee, 0);
    assert_eq!(charges.burned_fee, 0);
}

// ============================================================================
// Test: burning enabled
// ============================================================================

#[test]
fn test_burning_enabled_half() {
    let cfg = GasModelConfig {
        base_fee_per_gas: 10,
        tip_cap_floor: 0,
        burn_fraction_numerator: 1,
        burn_fraction_denominator: 2, // 50% of base fee portion burned
    };
    let tx = make_test_tx(10000, 15, 5);
    let gas_used = 1000;

    let charges = compute_gas_charges(&cfg, &tx, gas_used).expect("should succeed");

    // effective_gas_price = 10 + min(5, 15-10) = 15
    assert_eq!(charges.effective_gas_price, 15);
    // total_fee = 1000 * 15 = 15000
    assert_eq!(charges.total_fee, 15000);
    // burned = (1000 * 10 * 1) / 2 = 5000
    assert_eq!(charges.burned_fee, 5000);
    // proposer = 15000 - 5000 = 10000
    assert_eq!(charges.proposer_fee, 10000);
}

#[test]
fn test_burning_full() {
    let cfg = GasModelConfig {
        base_fee_per_gas: 10,
        tip_cap_floor: 0,
        burn_fraction_numerator: 1,
        burn_fraction_denominator: 1, // 100% of base fee portion burned
    };
    let tx = make_test_tx(10000, 15, 5);
    let gas_used = 1000;

    let charges = compute_gas_charges(&cfg, &tx, gas_used).expect("should succeed");

    // burned = (1000 * 10 * 1) / 1 = 10000
    assert_eq!(charges.burned_fee, 10000);
    // proposer = 15000 - 10000 = 5000 (just the tip portion)
    assert_eq!(charges.proposer_fee, 5000);
}

// ============================================================================
// Test: validate_tx_gas_price OK
// ============================================================================

#[test]
fn test_validate_tx_gas_price_ok() {
    let cfg = default_gas_config();
    let tx = make_test_tx(21000, 10, 2);

    assert!(validate_tx_gas_price(&cfg, &tx).is_ok());
}

#[test]
fn test_validate_tx_gas_price_exact_base_fee() {
    let cfg = GasModelConfig {
        base_fee_per_gas: 100,
        tip_cap_floor: 0,
        burn_fraction_numerator: 0,
        burn_fraction_denominator: 1,
    };
    // max_fee exactly equals base_fee - should be OK
    let tx = make_test_tx(21000, 100, 0);

    assert!(validate_tx_gas_price(&cfg, &tx).is_ok());

    let charges = compute_gas_charges(&cfg, &tx, 21000).expect("should succeed");
    // effective = 100 + min(0, 0) = 100
    assert_eq!(charges.effective_gas_price, 100);
}

// ============================================================================
// Test: default config values
// ============================================================================

#[test]
fn test_default_gas_config_values() {
    let cfg = default_gas_config();

    assert_eq!(cfg.base_fee_per_gas, 1);
    assert_eq!(cfg.tip_cap_floor, 0);
    assert_eq!(cfg.burn_fraction_numerator, 0);
    assert_eq!(cfg.burn_fraction_denominator, 1);
}
