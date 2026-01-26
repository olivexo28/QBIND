//! Gas model and fee computation for QBIND transactions.
//!
//! This module defines the QBIND gas/fee model introduced in T152.
//! It provides EIP-1559 compatible semantics with a simplified v0 implementation:
//!
//! - Fixed base fee per gas (configurable, default = 1)
//! - Priority fee (tip) capped by `max_priority_fee_per_gas` and `max_fee_per_gas - base_fee`
//! - All fees go to the block proposer (no burning in v0)
//!
//! ## Gas Price Calculation (EIP-1559 compatible)
//!
//! ```text
//! effective_gas_price = base_fee + min(max_priority_fee, max_fee - base_fee)
//! total_fee = gas_used * effective_gas_price
//! ```
//!
//! ## Fee Distribution (v0)
//!
//! Currently all fees go to the block proposer (coinbase). Future versions
//! may implement fee burning (EIP-1559 style) by setting `burn_fraction > 0`.

use crate::qbind_tx::QbindTx;
use std::fmt;

/// Configuration for the QBIND gas model.
///
/// This struct holds all parameters needed to compute gas charges for transactions.
/// For T152, we use a simplified configuration with fixed base fee and no burning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasModelConfig {
    /// Base fee per gas unit (in wei-like units).
    ///
    /// This is the minimum gas price that transactions must pay.
    /// For T152, this is a fixed constant. Future versions may implement
    /// dynamic base fee updates (EIP-1559 style).
    pub base_fee_per_gas: u128,

    /// Minimum tip/priority fee floor (in wei-like units).
    ///
    /// Set to 0 for T152. Future versions may use this for minimum tip enforcement.
    pub tip_cap_floor: u128,

    /// Numerator for burn fraction (0..=denominator).
    ///
    /// Set to 0 for T152 (no burning, all fees to proposer).
    pub burn_fraction_numerator: u64,

    /// Denominator for burn fraction.
    ///
    /// E.g., numerator=1, denominator=2 means 50% burned.
    pub burn_fraction_denominator: u64,
}

impl Default for GasModelConfig {
    fn default() -> Self {
        default_gas_config()
    }
}

/// Returns the default gas model configuration for T152.
///
/// - `base_fee_per_gas = 1` (minimal, non-zero base fee)
/// - `tip_cap_floor = 0` (no minimum tip)
/// - `burn_fraction = 0/1` (no burning, all fees to proposer)
pub fn default_gas_config() -> GasModelConfig {
    GasModelConfig {
        base_fee_per_gas: 1,
        tip_cap_floor: 0,
        burn_fraction_numerator: 0,
        burn_fraction_denominator: 1,
    }
}

/// Computed gas charges for a transaction.
///
/// This struct contains the breakdown of gas costs and fee distribution
/// after transaction execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasCharges {
    /// Effective gas price paid per unit of gas.
    ///
    /// Computed as: `base_fee + min(max_priority_fee, max_fee - base_fee)`
    pub effective_gas_price: u128,

    /// Actual gas consumed by the transaction.
    pub gas_used: u64,

    /// Total fee paid by sender: `gas_used * effective_gas_price`.
    pub total_fee: u128,

    /// Amount burned (subtracted from total supply).
    ///
    /// For T152, this is always 0.
    pub burned_fee: u128,

    /// Amount credited to the block proposer.
    ///
    /// For T152, this equals `total_fee` (all fees to proposer).
    pub proposer_fee: u128,
}

/// Errors that can occur during gas computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GasError {
    /// Transaction's max_fee_per_gas is below the current base fee.
    ///
    /// The transaction cannot afford the minimum gas price.
    MaxFeeBelowBaseFee { max_fee: u128, base_fee: u128 },

    /// Arithmetic overflow during fee calculation.
    ///
    /// This occurs when `gas_used * effective_gas_price` exceeds u128::MAX.
    GasOverflow,

    /// Gas used exceeds the transaction's gas limit.
    ///
    /// This should not happen if the execution engine is correct,
    /// but we check as a sanity invariant.
    GasExceedsLimit { gas_used: u64, gas_limit: u64 },
}

impl fmt::Display for GasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GasError::MaxFeeBelowBaseFee { max_fee, base_fee } => {
                write!(
                    f,
                    "max_fee_per_gas ({}) is below base_fee_per_gas ({})",
                    max_fee, base_fee
                )
            }
            GasError::GasOverflow => {
                write!(f, "gas fee calculation overflowed")
            }
            GasError::GasExceedsLimit {
                gas_used,
                gas_limit,
            } => {
                write!(
                    f,
                    "gas_used ({}) exceeds gas_limit ({})",
                    gas_used, gas_limit
                )
            }
        }
    }
}

impl std::error::Error for GasError {}

/// Compute gas charges for a transaction.
///
/// This function calculates the effective gas price, total fee, and fee distribution
/// based on the gas model configuration and transaction parameters.
///
/// ## Arguments
///
/// - `cfg`: Gas model configuration (base fee, burn fraction, etc.)
/// - `tx`: The transaction that was executed
/// - `gas_used`: Actual gas consumed during execution
///
/// ## Returns
///
/// On success, returns `GasCharges` with the computed fee breakdown.
///
/// ## Errors
///
/// - `GasError::MaxFeeBelowBaseFee` if `tx.max_fee_per_gas < cfg.base_fee_per_gas`
/// - `GasError::GasExceedsLimit` if `gas_used > tx.gas_limit`
/// - `GasError::GasOverflow` if fee calculation overflows
///
/// ## Example
///
/// ```ignore
/// let cfg = default_gas_config();
/// let tx = QbindTx::transfer(...).with_gas(21000, 10, 2);
/// let gas_used = 21000;
///
/// let charges = compute_gas_charges(&cfg, &tx, gas_used)?;
/// // charges.effective_gas_price = 1 + min(2, 10-1) = 3
/// // charges.total_fee = 21000 * 3 = 63000
/// // charges.proposer_fee = 63000 (no burning)
/// ```
pub fn compute_gas_charges(
    cfg: &GasModelConfig,
    tx: &QbindTx,
    gas_used: u64,
) -> Result<GasCharges, GasError> {
    let base_fee = cfg.base_fee_per_gas;
    let max_fee = tx.max_fee_per_gas;
    let max_priority_fee = tx.max_priority_fee_per_gas;

    // Check: max_fee must be >= base_fee
    if max_fee < base_fee {
        return Err(GasError::MaxFeeBelowBaseFee { max_fee, base_fee });
    }

    // Check: gas_used must not exceed gas_limit
    if gas_used > tx.gas_limit {
        return Err(GasError::GasExceedsLimit {
            gas_used,
            gas_limit: tx.gas_limit,
        });
    }

    // Compute tip cap = min(max_priority_fee, max_fee - base_fee)
    let fee_headroom = max_fee.saturating_sub(base_fee);
    let tip_cap = max_priority_fee.min(fee_headroom);

    // Effective gas price = base_fee + tip_cap
    let effective_gas_price = base_fee.saturating_add(tip_cap);

    // Total fee = gas_used * effective_gas_price
    let total_fee = (gas_used as u128)
        .checked_mul(effective_gas_price)
        .ok_or(GasError::GasOverflow)?;

    // Compute burn and proposer portions
    let (burned_fee, proposer_fee) =
        if cfg.burn_fraction_numerator == 0 || cfg.burn_fraction_denominator == 0 {
            // No burning: all fees to proposer
            (0, total_fee)
        } else {
            // Burn fraction of base fee portion
            // burned = (gas_used * base_fee * burn_numerator) / burn_denominator
            let base_portion = (gas_used as u128)
                .checked_mul(base_fee)
                .ok_or(GasError::GasOverflow)?;

            let burned = base_portion
                .checked_mul(cfg.burn_fraction_numerator as u128)
                .ok_or(GasError::GasOverflow)?
                .checked_div(cfg.burn_fraction_denominator as u128)
                .unwrap_or(0);

            let proposer = total_fee.saturating_sub(burned);
            (burned, proposer)
        };

    Ok(GasCharges {
        effective_gas_price,
        gas_used,
        total_fee,
        burned_fee,
        proposer_fee,
    })
}

/// Validate that a transaction can afford the base fee before execution.
///
/// This is a pre-execution check that can be used to reject transactions
/// early before spending resources on EVM execution.
///
/// ## Returns
///
/// `Ok(())` if the transaction's max_fee_per_gas >= base_fee_per_gas.
/// `Err(GasError::MaxFeeBelowBaseFee)` otherwise.
pub fn validate_tx_gas_price(cfg: &GasModelConfig, tx: &QbindTx) -> Result<(), GasError> {
    if tx.max_fee_per_gas < cfg.base_fee_per_gas {
        return Err(GasError::MaxFeeBelowBaseFee {
            max_fee: tx.max_fee_per_gas,
            base_fee: cfg.base_fee_per_gas,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm_types::{Address, U256};

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

    #[test]
    fn test_default_gas_config() {
        let cfg = default_gas_config();
        assert_eq!(cfg.base_fee_per_gas, 1);
        assert_eq!(cfg.tip_cap_floor, 0);
        assert_eq!(cfg.burn_fraction_numerator, 0);
        assert_eq!(cfg.burn_fraction_denominator, 1);
    }

    #[test]
    fn test_compute_gas_charges_basic() {
        let cfg = default_gas_config();
        let tx = make_test_tx(21000, 10, 2);
        let gas_used = 21000;

        let charges = compute_gas_charges(&cfg, &tx, gas_used).unwrap();

        // effective_gas_price = base(1) + min(priority(2), max_fee(10) - base(1)) = 1 + 2 = 3
        assert_eq!(charges.effective_gas_price, 3);
        assert_eq!(charges.gas_used, 21000);
        // total_fee = 21000 * 3 = 63000
        assert_eq!(charges.total_fee, 63000);
        // No burning, all to proposer
        assert_eq!(charges.burned_fee, 0);
        assert_eq!(charges.proposer_fee, 63000);
    }

    #[test]
    fn test_compute_gas_charges_tip_capped_by_headroom() {
        let cfg = default_gas_config();
        // max_fee = 5, max_priority = 100 (very high)
        // headroom = 5 - 1 = 4, so tip_cap = min(100, 4) = 4
        let tx = make_test_tx(21000, 5, 100);
        let gas_used = 21000;

        let charges = compute_gas_charges(&cfg, &tx, gas_used).unwrap();

        // effective_gas_price = 1 + 4 = 5
        assert_eq!(charges.effective_gas_price, 5);
        assert_eq!(charges.total_fee, 21000 * 5);
    }

    #[test]
    fn test_max_fee_below_base_fee_rejected() {
        let cfg = GasModelConfig {
            base_fee_per_gas: 100,
            tip_cap_floor: 0,
            burn_fraction_numerator: 0,
            burn_fraction_denominator: 1,
        };
        let tx = make_test_tx(21000, 50, 10); // max_fee = 50 < base_fee = 100
        let gas_used = 21000;

        let result = compute_gas_charges(&cfg, &tx, gas_used);

        match result {
            Err(GasError::MaxFeeBelowBaseFee { max_fee, base_fee }) => {
                assert_eq!(max_fee, 50);
                assert_eq!(base_fee, 100);
            }
            other => panic!("expected MaxFeeBelowBaseFee, got {:?}", other),
        }
    }

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

    #[test]
    fn test_overflow_detected() {
        let cfg = default_gas_config();
        // Use very large values to trigger overflow
        let tx = make_test_tx(u64::MAX, u128::MAX, u128::MAX);
        let gas_used = u64::MAX;

        let result = compute_gas_charges(&cfg, &tx, gas_used);

        // Should detect overflow during multiplication
        match result {
            Err(GasError::GasOverflow) => {} // Expected
            Err(GasError::GasExceedsLimit { .. }) => {
                // Also acceptable since gas_used equals gas_limit
            }
            other => panic!("expected GasOverflow or GasExceedsLimit, got {:?}", other),
        }
    }

    #[test]
    fn test_zero_gas_used() {
        let cfg = default_gas_config();
        let tx = make_test_tx(21000, 10, 2);
        let gas_used = 0;

        let charges = compute_gas_charges(&cfg, &tx, gas_used).unwrap();

        assert_eq!(charges.gas_used, 0);
        assert_eq!(charges.total_fee, 0);
        assert_eq!(charges.proposer_fee, 0);
    }

    #[test]
    fn test_burning_enabled() {
        let cfg = GasModelConfig {
            base_fee_per_gas: 10,
            tip_cap_floor: 0,
            burn_fraction_numerator: 1,
            burn_fraction_denominator: 2, // 50% of base fee portion burned
        };
        let tx = make_test_tx(1000, 15, 5);
        let gas_used = 1000;

        let charges = compute_gas_charges(&cfg, &tx, gas_used).unwrap();

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
    fn test_validate_tx_gas_price_ok() {
        let cfg = default_gas_config();
        let tx = make_test_tx(21000, 10, 2);

        assert!(validate_tx_gas_price(&cfg, &tx).is_ok());
    }

    #[test]
    fn test_validate_tx_gas_price_rejected() {
        let cfg = GasModelConfig {
            base_fee_per_gas: 100,
            ..default_gas_config()
        };
        let tx = make_test_tx(21000, 50, 10);

        assert!(validate_tx_gas_price(&cfg, &tx).is_err());
    }
}
