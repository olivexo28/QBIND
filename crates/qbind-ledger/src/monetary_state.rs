//! T199: Monetary Epoch State v1 (Consensus-Side Inflation Calculator)
//!
//! This module provides consensus-tracked "monetary epoch state" that, for each epoch,
//! deterministically computes and records:
//! - The inflation rate r_inf chosen by the monetary engine for that epoch (annual bps)
//! - The target rate and intermediate fields (for debugging/auditing)
//! - The phase and phase transition recommendation (from T195)
//! - The fee coverage signal being fed into the engine
//!
//! **Important**: T199 is calculation + state only:
//! - No actual minting / account balance changes
//! - No reward distribution adjusted yet
//! - No governance / parameter changes
//!
//! Those are intentionally left for:
//! - T200 – seigniorage distribution to validators (staking reward pipeline)
//! - T201 – routing to treasury / insurance / community accounts
//!
//! This keeps T199 "read-only" w.r.t. balances while still making the monetary
//! engine consensus-visible and testable.
//!
//! See: `docs/econ/QBIND_MONETARY_POLICY_DESIGN.md` (T194) §7.4 for detailed design.

use crate::monetary_engine::{
    compute_monetary_decision, MonetaryDecision, MonetaryEngineConfig, MonetaryInputs,
    MonetaryPhase, PhaseParameters,
};

// ============================================================================
// Constants
// ============================================================================

/// Default number of blocks per epoch (can be overridden in configuration).
/// For a 6-second block time, ~8640 blocks per day. 3 days ≈ 25920 blocks.
/// For testing, this can be much smaller (e.g., 5 blocks).
pub const DEFAULT_BLOCKS_PER_EPOCH: u64 = 25920;

/// Number of epochs per year (assuming DEFAULT_BLOCKS_PER_EPOCH with 6s blocks).
/// 365 days / 3 days per epoch ≈ 122 epochs per year.
pub const DEFAULT_EPOCHS_PER_YEAR: u64 = 122;

// ============================================================================
// MonetaryEpochInputs
// ============================================================================

/// Input parameters for computing the monetary epoch state.
///
/// These are the observed values at the end of an epoch, used to compute
/// the monetary decision for that epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct MonetaryEpochInputs {
    /// The epoch index (0-based, incrementing each epoch).
    pub epoch_index: u64,

    /// Raw fees collected during this epoch, in base token units.
    pub raw_epoch_fees: u128,

    /// Previous epoch's smoothed annual fee revenue (for EMA continuation).
    /// Set to 0 for the first epoch.
    pub previous_smoothed_annual_fee_revenue: u128,

    /// Total staked supply at the time of the epoch boundary.
    pub staked_supply: u128,

    /// Current monetary phase.
    pub phase: MonetaryPhase,

    /// Bonded ratio (fraction of total supply staked, e.g., 0.6 for 60%).
    /// Used for phase transition readiness checks.
    pub bonded_ratio: f64,

    /// Days since network launch.
    /// Used for time-based phase transition guards.
    pub days_since_launch: u64,

    /// Fee volatility metric (dimensionless, annualized σ / mean).
    /// Used for phase transition readiness checks.
    pub fee_volatility: f64,

    /// Number of epochs per year (for annualization).
    pub epochs_per_year: u64,
}

impl Default for MonetaryEpochInputs {
    fn default() -> Self {
        Self {
            epoch_index: 0,
            raw_epoch_fees: 0,
            previous_smoothed_annual_fee_revenue: 0,
            staked_supply: 0,
            phase: MonetaryPhase::Bootstrap,
            bonded_ratio: 0.0,
            days_since_launch: 0,
            fee_volatility: 0.0,
            epochs_per_year: DEFAULT_EPOCHS_PER_YEAR,
        }
    }
}

// ============================================================================
// MonetaryEpochState
// ============================================================================

/// Consensus-tracked monetary state for a single epoch.
///
/// This struct records the monetary engine's decision for an epoch, including
/// all inputs and outputs for auditability. It is persisted in consensus state.
#[derive(Debug, Clone, PartialEq)]
pub struct MonetaryEpochState {
    /// The epoch index this state corresponds to.
    pub epoch_index: u64,

    /// The monetary phase at the time of this decision.
    pub phase: MonetaryPhase,

    /// Annualized, smoothed fee revenue used for this epoch's decision.
    /// Stored as u128 to match token precision.
    pub smoothed_annual_fee_revenue: u128,

    /// Snapshot of total staked supply at the time of decision.
    pub staked_supply: u128,

    /// The engine decision for this epoch.
    pub decision: MonetaryDecision,

    /// Fee coverage ratio: smoothed_annual_fee_revenue / (staked_supply * r_target).
    /// Dimensionless, used for metrics and phase transition checks.
    pub fee_coverage_ratio: f64,
}

impl Default for MonetaryEpochState {
    fn default() -> Self {
        Self {
            epoch_index: 0,
            phase: MonetaryPhase::Bootstrap,
            smoothed_annual_fee_revenue: 0,
            staked_supply: 0,
            decision: MonetaryDecision {
                effective_r_target_annual: 0.0,
                recommended_r_inf_annual: 0.0,
                inflation_floor_applied: false,
                inflation_cap_applied: false,
                phase_recommendation:
                    crate::monetary_engine::PhaseTransitionRecommendation::Stay,
            },
            fee_coverage_ratio: 0.0,
        }
    }
}

impl MonetaryEpochState {
    /// Get the recommended annual inflation rate in basis points (1 bps = 0.01%).
    ///
    /// This converts the f64 rate (e.g., 0.0775 for 7.75%) to integer bps (775).
    pub fn r_inf_annual_bps(&self) -> u64 {
        (self.decision.recommended_r_inf_annual * 10_000.0).round() as u64
    }

    /// Get the effective target annual rate in basis points.
    pub fn r_target_annual_bps(&self) -> u64 {
        (self.decision.effective_r_target_annual * 10_000.0).round() as u64
    }
}

// ============================================================================
// Fee Smoothing Logic
// ============================================================================

/// Compute the smoothed annual fee revenue for this epoch.
///
/// This implements "Option A" (no real smoothing) from the T199 spec:
/// `smoothed_annual_fee_revenue = fees_this_epoch * epochs_per_year`
///
/// Later tasks (T202–T205) will refine this to use proper EMA smoothing
/// with phase-dependent λ values.
///
/// # Arguments
///
/// * `raw_epoch_fees` - Fees collected during this epoch
/// * `previous_smoothed` - Previous epoch's smoothed annual fee revenue
/// * `epochs_per_year` - Number of epochs per year (for annualization)
/// * `_phase_params` - Phase parameters (unused in Option A, reserved for Option B EMA)
///
/// # Returns
///
/// The smoothed annual fee revenue for this epoch.
pub fn compute_smoothed_annual_fee_revenue(
    raw_epoch_fees: u128,
    _previous_smoothed: u128,
    epochs_per_year: u64,
    _phase_params: &PhaseParameters,
) -> u128 {
    // Option A: Simple annualization without smoothing
    // smoothed_annual_fee_revenue = fees_this_epoch * epochs_per_year
    //
    // Note: The `_previous_smoothed` and `_phase_params` parameters are included
    // for forward compatibility with Option B EMA smoothing (T202–T205).
    // When EMA is implemented, this function will use phase_params.fee_smoothing_half_life_days
    // to compute λ and apply: new_smoothed = λ * annualized_fees + (1 - λ) * previous_smoothed
    raw_epoch_fees.saturating_mul(epochs_per_year as u128)
}

// ============================================================================
// Core Computation Function
// ============================================================================

/// Compute the monetary epoch state for a given set of inputs.
///
/// This is the core function that bridges epoch inputs to the T195 monetary engine.
///
/// # Algorithm
///
/// 1. Update smoothed_annual_fee_revenue (Option A: simple annualization)
/// 2. Build MonetaryInputs for T195
/// 3. Call compute_monetary_decision()
/// 4. Package into MonetaryEpochState
///
/// # Arguments
///
/// * `config` - The monetary engine configuration
/// * `params` - Phase-specific parameters (derived from config and inputs.phase)
/// * `inputs` - The epoch inputs (fees, stake, phase, etc.)
///
/// # Returns
///
/// A new `MonetaryEpochState` containing the computed decision.
pub fn compute_epoch_state(
    config: &MonetaryEngineConfig,
    inputs: &MonetaryEpochInputs,
) -> MonetaryEpochState {
    let params = config.params_for_phase(inputs.phase);

    // Step 1: Compute smoothed annual fee revenue
    let smoothed_annual_fee_revenue = compute_smoothed_annual_fee_revenue(
        inputs.raw_epoch_fees,
        inputs.previous_smoothed_annual_fee_revenue,
        inputs.epochs_per_year,
        params,
    );

    // Step 2: Compute fee coverage ratio
    // fee_coverage = smoothed_annual_fee_revenue / (staked_supply * r_target)
    // Use a business-logic-based minimum (0.0001 = 0.01%) rather than f64::EPSILON
    // since r_target_annual represents meaningful inflation rates (typically 1-12%).
    const MIN_R_TARGET_FOR_COVERAGE: f64 = 0.0001;
    let fee_coverage_ratio =
        if inputs.staked_supply > 0 && params.r_target_annual > MIN_R_TARGET_FOR_COVERAGE {
            let security_budget = (inputs.staked_supply as f64) * params.r_target_annual;
            (smoothed_annual_fee_revenue as f64) / security_budget
        } else {
            0.0
        };

    // Step 3: Build MonetaryInputs for T195 engine
    let monetary_inputs = MonetaryInputs {
        phase: inputs.phase,
        total_staked_tokens: inputs.staked_supply as f64,
        smoothed_annual_fee_revenue: smoothed_annual_fee_revenue as f64,
        bonded_ratio: inputs.bonded_ratio,
        fee_coverage_ratio,
        fee_volatility: inputs.fee_volatility,
        days_since_launch: inputs.days_since_launch,
    };

    // Step 4: Call the T195 monetary engine
    let decision = compute_monetary_decision(config, &monetary_inputs);

    // Step 5: Package into MonetaryEpochState
    MonetaryEpochState {
        epoch_index: inputs.epoch_index,
        phase: inputs.phase,
        smoothed_annual_fee_revenue,
        staked_supply: inputs.staked_supply,
        decision,
        fee_coverage_ratio,
    }
}

// ============================================================================
// Epoch Boundary Detection
// ============================================================================

/// Determine the epoch index for a given block height.
///
/// This is a simple helper that divides height by blocks_per_epoch.
/// It uses integer division, so epoch 0 spans heights [0, blocks_per_epoch).
///
/// # Arguments
///
/// * `height` - The block height
/// * `blocks_per_epoch` - Number of blocks per epoch
///
/// # Returns
///
/// The epoch index (0-based).
///
/// # Example
///
/// ```
/// use qbind_ledger::monetary_state::epoch_for_height;
///
/// assert_eq!(epoch_for_height(0, 100), 0);
/// assert_eq!(epoch_for_height(99, 100), 0);
/// assert_eq!(epoch_for_height(100, 100), 1);
/// assert_eq!(epoch_for_height(250, 100), 2);
/// ```
pub fn epoch_for_height(height: u64, blocks_per_epoch: u64) -> u64 {
    if blocks_per_epoch == 0 {
        return 0;
    }
    height / blocks_per_epoch
}

/// Check if a new epoch has begun at the given height.
///
/// # Arguments
///
/// * `height` - The current block height
/// * `last_epoch` - The last known epoch index
/// * `blocks_per_epoch` - Number of blocks per epoch
///
/// # Returns
///
/// `true` if `epoch_for_height(height, blocks_per_epoch) != last_epoch`.
pub fn is_epoch_boundary(height: u64, last_epoch: u64, blocks_per_epoch: u64) -> bool {
    epoch_for_height(height, blocks_per_epoch) != last_epoch
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monetary_engine::PhaseTransitionRecommendation;

    fn test_config() -> MonetaryEngineConfig {
        MonetaryEngineConfig {
            pqc_premium_compute: 0.30,
            pqc_premium_bandwidth: 0.15,
            pqc_premium_storage: 0.10,
            bootstrap: PhaseParameters {
                r_target_annual: 0.05,
                inflation_floor_annual: 0.0,
                fee_smoothing_half_life_days: 30.0,
                max_annual_inflation_cap: 0.12,
            },
            transition: PhaseParameters {
                r_target_annual: 0.04,
                inflation_floor_annual: 0.0,
                fee_smoothing_half_life_days: 60.0,
                max_annual_inflation_cap: 0.10,
            },
            mature: PhaseParameters {
                r_target_annual: 0.03,
                inflation_floor_annual: 0.01,
                fee_smoothing_half_life_days: 90.0,
                max_annual_inflation_cap: 0.08,
            },
            alpha_fee_offset: 1.0,
        }
    }

    #[test]
    fn test_epoch_for_height() {
        assert_eq!(epoch_for_height(0, 100), 0);
        assert_eq!(epoch_for_height(99, 100), 0);
        assert_eq!(epoch_for_height(100, 100), 1);
        assert_eq!(epoch_for_height(199, 100), 1);
        assert_eq!(epoch_for_height(200, 100), 2);
        assert_eq!(epoch_for_height(1000, 100), 10);

        // Edge case: blocks_per_epoch = 0 should return 0
        assert_eq!(epoch_for_height(100, 0), 0);
    }

    #[test]
    fn test_is_epoch_boundary() {
        // Not a boundary - same epoch
        assert!(!is_epoch_boundary(50, 0, 100));
        assert!(!is_epoch_boundary(99, 0, 100));

        // Is a boundary - new epoch
        assert!(is_epoch_boundary(100, 0, 100));
        assert!(is_epoch_boundary(200, 1, 100));

        // Not a boundary - already in that epoch
        assert!(!is_epoch_boundary(150, 1, 100));
    }

    #[test]
    fn test_compute_smoothed_annual_fee_revenue_option_a() {
        let params = PhaseParameters {
            r_target_annual: 0.05,
            inflation_floor_annual: 0.0,
            fee_smoothing_half_life_days: 30.0,
            max_annual_inflation_cap: 0.12,
        };

        // 1000 fees per epoch, 100 epochs per year = 100,000 annualized
        let result = compute_smoothed_annual_fee_revenue(1000, 0, 100, &params);
        assert_eq!(result, 100_000);

        // Previous smoothed is ignored in Option A
        let result2 = compute_smoothed_annual_fee_revenue(1000, 50_000, 100, &params);
        assert_eq!(result2, 100_000);
    }

    #[test]
    fn test_compute_epoch_state_basic() {
        let config = test_config();
        let inputs = MonetaryEpochInputs {
            epoch_index: 1,
            raw_epoch_fees: 0,
            previous_smoothed_annual_fee_revenue: 0,
            staked_supply: 10_000_000,
            phase: MonetaryPhase::Bootstrap,
            bonded_ratio: 0.5,
            days_since_launch: 100,
            fee_volatility: 1.0,
            epochs_per_year: 100,
        };

        let state = compute_epoch_state(&config, &inputs);

        assert_eq!(state.epoch_index, 1);
        assert_eq!(state.phase, MonetaryPhase::Bootstrap);
        assert_eq!(state.staked_supply, 10_000_000);
        assert_eq!(state.smoothed_annual_fee_revenue, 0);

        // With zero fees, r_inf should be the effective target
        // PQC multiplier = 1.55, base = 0.05, effective = 0.0775
        assert!(
            (state.decision.recommended_r_inf_annual - 0.0775).abs() < 1e-6,
            "Expected r_inf ≈ 0.0775, got {}",
            state.decision.recommended_r_inf_annual
        );

        // Fee coverage should be 0 with zero fees
        assert_eq!(state.fee_coverage_ratio, 0.0);
    }

    #[test]
    fn test_compute_epoch_state_with_fees() {
        let config = test_config();
        let inputs = MonetaryEpochInputs {
            epoch_index: 5,
            raw_epoch_fees: 10_000, // 10k fees this epoch
            previous_smoothed_annual_fee_revenue: 0,
            staked_supply: 10_000_000,
            phase: MonetaryPhase::Bootstrap,
            bonded_ratio: 0.5,
            days_since_launch: 100,
            fee_volatility: 1.0,
            epochs_per_year: 100,
        };

        let state = compute_epoch_state(&config, &inputs);

        // Smoothed = 10_000 * 100 = 1_000_000
        assert_eq!(state.smoothed_annual_fee_revenue, 1_000_000);

        // Fee coverage = 1_000_000 / (10_000_000 * 0.05) = 1_000_000 / 500_000 = 2.0
        assert!(
            (state.fee_coverage_ratio - 2.0).abs() < 1e-6,
            "Expected fee_coverage ≈ 2.0, got {}",
            state.fee_coverage_ratio
        );

        // With high fees, inflation should be reduced
        // fee_offset = 1.0 * (1_000_000 / 10_000_000) = 0.1
        // r_raw = 0.0775 - 0.1 = -0.0225 → clamped to 0
        assert!(
            state.decision.recommended_r_inf_annual < 0.001,
            "Expected r_inf near 0, got {}",
            state.decision.recommended_r_inf_annual
        );
    }

    #[test]
    fn test_compute_epoch_state_zero_stake() {
        let config = test_config();
        let inputs = MonetaryEpochInputs {
            epoch_index: 0,
            raw_epoch_fees: 1000,
            previous_smoothed_annual_fee_revenue: 0,
            staked_supply: 0, // Edge case: zero stake
            phase: MonetaryPhase::Bootstrap,
            bonded_ratio: 0.0,
            days_since_launch: 0,
            fee_volatility: 0.0,
            epochs_per_year: 100,
        };

        let state = compute_epoch_state(&config, &inputs);

        // Should not panic; fee coverage should be 0
        assert_eq!(state.fee_coverage_ratio, 0.0);

        // With zero stake, fee offset = 0, so r_inf = effective_r_target
        assert!(
            (state.decision.recommended_r_inf_annual - 0.0775).abs() < 1e-6,
            "Expected r_inf ≈ 0.0775, got {}",
            state.decision.recommended_r_inf_annual
        );
    }

    #[test]
    fn test_r_inf_and_r_target_bps() {
        let config = test_config();
        let inputs = MonetaryEpochInputs {
            epoch_index: 0,
            raw_epoch_fees: 0,
            previous_smoothed_annual_fee_revenue: 0,
            staked_supply: 1_000_000,
            phase: MonetaryPhase::Bootstrap,
            bonded_ratio: 0.5,
            days_since_launch: 100,
            fee_volatility: 1.0,
            epochs_per_year: 100,
        };

        let state = compute_epoch_state(&config, &inputs);

        // Effective target = 0.0775 → 775 bps
        assert_eq!(state.r_target_annual_bps(), 775);

        // r_inf with zero fees = effective target = 775 bps
        assert_eq!(state.r_inf_annual_bps(), 775);
    }

    #[test]
    fn test_phase_recommendation_in_epoch_state() {
        let config = test_config();
        let inputs = MonetaryEpochInputs {
            epoch_index: 0,
            raw_epoch_fees: 0,
            previous_smoothed_annual_fee_revenue: 0,
            staked_supply: 1_000_000,
            phase: MonetaryPhase::Bootstrap,
            bonded_ratio: 0.5,
            days_since_launch: 100, // Too early for transition
            fee_volatility: 1.0,
            epochs_per_year: 100,
        };

        let state = compute_epoch_state(&config, &inputs);

        // Should stay in Bootstrap (time gate not met)
        assert_eq!(
            state.decision.phase_recommendation,
            PhaseTransitionRecommendation::Stay
        );
    }

    #[test]
    fn test_monetary_epoch_state_default() {
        let state = MonetaryEpochState::default();
        assert_eq!(state.epoch_index, 0);
        assert_eq!(state.phase, MonetaryPhase::Bootstrap);
        assert_eq!(state.smoothed_annual_fee_revenue, 0);
        assert_eq!(state.staked_supply, 0);
        assert_eq!(state.fee_coverage_ratio, 0.0);
    }
}