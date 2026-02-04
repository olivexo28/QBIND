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

    /// Previous epoch's smoothed annual fee revenue (for backward compatibility).
    /// Set to 0 for the first epoch.
    pub previous_smoothed_annual_fee_revenue: u128,

    /// Previous epoch's EMA fees per epoch (for T202 EMA continuation).
    /// Set to 0 for the first epoch.
    pub previous_ema_fees_per_epoch: u128,

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
            previous_ema_fees_per_epoch: 0,
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

    /// EMA-smoothed fees per epoch (T202).
    ///
    /// Computed using: `EMA_fees_t = λ × fees_t + (1 - λ) × EMA_fees_{t-1}`
    /// where λ is phase-dependent (ema_lambda_bps / 10_000).
    ///
    /// For epoch 0 with no previous state, this equals raw_epoch_fees.
    pub ema_fees_per_epoch: u128,

    /// Annualized, EMA-smoothed fee revenue used for this epoch's decision.
    /// Computed as: `ema_fees_per_epoch * epochs_per_year`
    ///
    /// **T202 semantic change**: Previously computed from raw epoch fees.
    /// Now uses EMA-smoothed fees for stability.
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
            ema_fees_per_epoch: 0,
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
// Fee Smoothing Logic (T202)
// ============================================================================

/// Compute a single EMA (Exponential Moving Average) step for fee smoothing.
///
/// Implements the formula from design doc §3.3.2:
/// ```text
/// EMA_fees_t = λ × fees_t + (1 - λ) × EMA_fees_{t-1}
/// ```
///
/// # Arguments
///
/// * `prev_ema` - Previous epoch's EMA value (EMA_fees_{t-1})
/// * `fees_t` - Current epoch's raw fees (fees_t)
/// * `lambda_bps` - Smoothing factor λ in basis points (0–10,000), where 10,000 = 100%
///
/// # Returns
///
/// The new EMA value for this epoch.
///
/// # Arithmetic
///
/// - Uses u128 with saturating arithmetic to prevent overflow
/// - Floor division (no rounding up)
/// - Computation: `(λ * fees_t + (10000 - λ) * prev_ema) / 10000`
///
/// # Example
///
/// ```
/// use qbind_ledger::ema_step;
///
/// // λ = 50% (5000 bps): new EMA is average of fees_t and prev_ema
/// let ema = ema_step(100, 200, 5000);
/// assert_eq!(ema, 150);
///
/// // λ = 10% (1000 bps): new EMA weights heavily toward prev_ema
/// let ema = ema_step(100, 200, 1000);
/// assert_eq!(ema, 110);  // 0.1 * 200 + 0.9 * 100 = 110
/// ```
pub fn ema_step(prev_ema: u128, fees_t: u128, lambda_bps: u16) -> u128 {
    // Ensure lambda_bps is within valid range for the formula to work correctly
    // (caller should validate config, but we guard here defensively)
    let lambda = lambda_bps.min(10_000) as u128;
    let one_minus_lambda = 10_000_u128.saturating_sub(lambda);

    // Compute: λ * fees_t + (1 - λ) * prev_ema
    // Using saturating arithmetic to prevent overflow
    let weighted_fees = fees_t.saturating_mul(lambda);
    let weighted_prev = prev_ema.saturating_mul(one_minus_lambda);
    let num = weighted_fees.saturating_add(weighted_prev);

    // Floor division by 10_000
    num / 10_000
}

/// Compute the smoothed annual fee revenue for this epoch.
///
/// **T202 Update**: This function now uses EMA-based smoothing with phase-dependent λ.
///
/// # Arguments
///
/// * `raw_epoch_fees` - Fees collected during this epoch
/// * `previous_ema_fees` - Previous epoch's EMA fees per epoch
/// * `epochs_per_year` - Number of epochs per year (for annualization)
/// * `phase_params` - Phase parameters (contains ema_lambda_bps)
/// * `epoch_index` - Current epoch index (for initialization handling)
///
/// # Returns
///
/// A tuple of (ema_fees_per_epoch, smoothed_annual_fee_revenue).
pub fn compute_ema_fee_revenue(
    raw_epoch_fees: u128,
    previous_ema_fees: u128,
    epochs_per_year: u64,
    phase_params: &PhaseParameters,
    epoch_index: u64,
) -> (u128, u128) {
    // Handle epoch 0 initialization: use raw fees directly
    let ema_fees_per_epoch = if epoch_index == 0 && previous_ema_fees == 0 {
        raw_epoch_fees
    } else {
        ema_step(previous_ema_fees, raw_epoch_fees, phase_params.ema_lambda_bps)
    };

    // Annualize the EMA fees
    let smoothed_annual_fee_revenue =
        ema_fees_per_epoch.saturating_mul(epochs_per_year as u128);

    (ema_fees_per_epoch, smoothed_annual_fee_revenue)
}

/// Legacy function for backward compatibility.
///
/// **Deprecated**: Use `compute_ema_fee_revenue` for T202+ behavior.
///
/// This implements "Option A" (simple annualization without EMA smoothing):
/// `smoothed_annual_fee_revenue = fees_this_epoch * epochs_per_year`
///
/// # Arguments
///
/// * `raw_epoch_fees` - Fees collected during this epoch
/// * `_previous_smoothed` - Previous epoch's smoothed annual fee revenue (ignored)
/// * `epochs_per_year` - Number of epochs per year (for annualization)
/// * `_phase_params` - Phase parameters (unused in Option A)
///
/// # Returns
///
/// The smoothed annual fee revenue for this epoch.
#[deprecated(since = "0.1.0", note = "Use compute_ema_fee_revenue for T202 EMA behavior")]
pub fn compute_smoothed_annual_fee_revenue(
    raw_epoch_fees: u128,
    _previous_smoothed: u128,
    epochs_per_year: u64,
    _phase_params: &PhaseParameters,
) -> u128 {
    // Option A: Simple annualization without smoothing
    raw_epoch_fees.saturating_mul(epochs_per_year as u128)
}

// ============================================================================
// Core Computation Function
// ============================================================================

/// Compute the monetary epoch state for a given set of inputs.
///
/// This is the core function that bridges epoch inputs to the T195 monetary engine.
///
/// # Algorithm (T202 Updated)
///
/// 1. Compute EMA-smoothed fees per epoch using phase-dependent λ
/// 2. Annualize the EMA fees to get smoothed_annual_fee_revenue
/// 3. Compute fee coverage ratio
/// 4. Build MonetaryInputs for T195 engine
/// 5. Call compute_monetary_decision()
/// 6. Package into MonetaryEpochState
///
/// # Arguments
///
/// * `config` - The monetary engine configuration
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

    // Step 1: Compute EMA-smoothed fees per epoch (T202)
    let (ema_fees_per_epoch, smoothed_annual_fee_revenue) = compute_ema_fee_revenue(
        inputs.raw_epoch_fees,
        inputs.previous_ema_fees_per_epoch,
        inputs.epochs_per_year,
        params,
        inputs.epoch_index,
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
        ema_fees_per_epoch,
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
// T200: Epoch Issuance Computation
// ============================================================================

/// Number of epochs per year for MainNet (assuming 10-minute epochs).
/// 365 days × 24 hours × 6 epochs/hour = 52,560 epochs/year.
/// This is the constant from the design doc: QBIND_MONETARY_POLICY_DESIGN.md §4.2.
pub const MAINNET_EPOCHS_PER_YEAR: u64 = 52_560;

/// Compute the total issuance for a single epoch.
///
/// This implements the epoch issuance formula from QBIND_MONETARY_POLICY_DESIGN.md §4.2:
/// ```text
/// issuance_epoch = r_inf × S_t / epochs_per_year
/// ```
///
/// # Arguments
///
/// * `epoch_state` - The computed monetary epoch state (from T199)
/// * `epochs_per_year` - Number of epochs per year (use `MAINNET_EPOCHS_PER_YEAR` for production)
///
/// # Returns
///
/// The total issuance for this epoch in base token units.
///
/// # Algorithm
///
/// Uses integer arithmetic with basis points (bps) for determinism:
/// 1. Get r_inf_annual_bps (e.g., 775 bps = 7.75%)
/// 2. Compute: issuance = (staked_supply × r_inf_bps) / (epochs_per_year × 10,000)
///
/// The division by 10,000 converts from basis points to a fraction.
///
/// # Overflow Safety
///
/// Uses `saturating_mul` and `checked_div` to prevent overflow.
/// For realistic MainNet values (staked_supply ≤ 10^18, r_inf_bps ≤ 12,000),
/// the intermediate product fits comfortably in u128.
///
/// # Example
///
/// ```
/// use qbind_ledger::monetary_state::{compute_epoch_issuance, MonetaryEpochState, MAINNET_EPOCHS_PER_YEAR};
///
/// let mut state = MonetaryEpochState::default();
/// state.staked_supply = 1_000_000_000_000; // 1 trillion tokens
/// state.decision.recommended_r_inf_annual = 0.0775; // 7.75%
///
/// let issuance = compute_epoch_issuance(&state, MAINNET_EPOCHS_PER_YEAR);
/// // issuance ≈ 1e12 × 0.0775 / 52560 ≈ 1,474,924 tokens per epoch
/// assert!(issuance > 1_000_000); // Approximately 1.47M per epoch
/// ```
pub fn compute_epoch_issuance(epoch_state: &MonetaryEpochState, epochs_per_year: u64) -> u128 {
    if epochs_per_year == 0 {
        return 0;
    }

    let staked_supply = epoch_state.staked_supply;
    let r_inf_bps = epoch_state.r_inf_annual_bps() as u128;

    // issuance = (staked_supply × r_inf_bps) / (epochs_per_year × 10,000)
    // We use saturating_mul for safety, though overflow is unlikely for realistic values.
    let numerator = staked_supply.saturating_mul(r_inf_bps);
    let denominator = (epochs_per_year as u128).saturating_mul(10_000);

    // Note: denominator cannot be zero here since epochs_per_year > 0 (checked above)
    // and 10_000 is a constant. Using standard division.
    numerator / denominator
}

// ============================================================================
// T200: Validator Reward Distribution
// ============================================================================

/// Represents a single validator's stake for reward distribution.
///
/// This is a lightweight struct used as input to `compute_validator_rewards`.
/// The `validator_id` is a u64 matching the consensus layer's `ValidatorId` type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorStake {
    /// The validator's unique identifier.
    pub validator_id: u64,
    /// The validator's staked amount in base token units.
    pub stake: u128,
}

/// Represents a computed reward for a single validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorReward {
    /// The validator's unique identifier.
    pub validator_id: u64,
    /// The reward amount in base token units.
    pub reward: u128,
}

/// Result of computing validator rewards for an epoch.
///
/// This struct contains:
/// - The per-validator reward amounts
/// - Accounting totals for audit/verification
///
/// # Invariant
///
/// The sum of all `rewards[i].reward` must equal `total_distributed`.
/// Call `is_balanced()` to verify this invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRewardDistribution {
    /// Per-validator reward amounts (same order as input stakes).
    pub rewards: Vec<ValidatorReward>,
    /// Total amount distributed (should equal sum of all rewards).
    pub total_distributed: u128,
    /// Input total validators issuance (for reference).
    pub total_validators_issuance: u128,
    /// Input expected staked supply (for reference).
    pub expected_staked_supply: u128,
    /// Actual sum of stakes from input (for invariant checking).
    pub actual_staked_supply: u128,
}

impl ValidatorRewardDistribution {
    /// Check if the distribution is balanced (all rewards sum to total_distributed).
    pub fn is_balanced(&self) -> bool {
        let sum: u128 = self.rewards.iter().map(|r| r.reward).sum();
        sum == self.total_distributed
    }

    /// Check if the stake invariant holds (actual stake matches expected).
    pub fn stake_invariant_ok(&self) -> bool {
        self.actual_staked_supply == self.expected_staked_supply
    }
}

/// Compute per-validator rewards from the total validators' issuance.
///
/// This function distributes `total_validators_issuance` tokens among validators
/// proportionally to their stake.
///
/// # Algorithm
///
/// Uses integer arithmetic only for determinism:
/// 1. Validate that sum of stakes equals `expected_staked_supply`
/// 2. For each validator i: reward_i = floor(total_issuance × stake_i / total_stake)
/// 3. Assign any remainder to the last validator (deterministic ordering)
///
/// This guarantees:
/// - All reward amounts are ≥ 0
/// - Sum of rewards equals exactly `total_validators_issuance`
/// - Results are deterministic for the same inputs
///
/// # Arguments
///
/// * `total_validators_issuance` - Total tokens to distribute to validators
/// * `stakes` - Slice of validator stakes. **Note**: For consensus determinism, the caller
///   must ensure this slice has a consistent ordering across all validators (e.g., sorted
///   by `validator_id`). This function does not enforce ordering.
/// * `expected_staked_supply` - Expected sum of all stakes (for invariant checking)
///
/// # Returns
///
/// * `Some(ValidatorRewardDistribution)` if the stake invariant holds
/// * `None` if `sum(stakes)` does not equal `expected_staked_supply`
///
/// # Example
///
/// ```
/// use qbind_ledger::monetary_state::{compute_validator_rewards, ValidatorStake};
///
/// let stakes = vec![
///     ValidatorStake { validator_id: 1, stake: 100 },
///     ValidatorStake { validator_id: 2, stake: 200 },
///     ValidatorStake { validator_id: 3, stake: 300 },
/// ];
///
/// let distribution = compute_validator_rewards(600, &stakes, 600).unwrap();
///
/// assert_eq!(distribution.rewards[0].reward, 100); // 1/6 of 600
/// assert_eq!(distribution.rewards[1].reward, 200); // 2/6 of 600
/// assert_eq!(distribution.rewards[2].reward, 300); // 3/6 of 600
/// assert!(distribution.is_balanced());
/// ```
pub fn compute_validator_rewards(
    total_validators_issuance: u128,
    stakes: &[ValidatorStake],
    expected_staked_supply: u128,
) -> Option<ValidatorRewardDistribution> {
    // Calculate actual staked supply
    let actual_staked_supply: u128 = stakes.iter().map(|s| s.stake).sum();

    // Check stake invariant
    if actual_staked_supply != expected_staked_supply {
        return None;
    }

    // Handle edge cases
    if stakes.is_empty() || actual_staked_supply == 0 || total_validators_issuance == 0 {
        let rewards: Vec<ValidatorReward> = stakes
            .iter()
            .map(|s| ValidatorReward {
                validator_id: s.validator_id,
                reward: 0,
            })
            .collect();

        return Some(ValidatorRewardDistribution {
            rewards,
            total_distributed: 0,
            total_validators_issuance,
            expected_staked_supply,
            actual_staked_supply,
        });
    }

    // Compute per-validator rewards using floor division
    let mut rewards = Vec::with_capacity(stakes.len());
    let mut allocated: u128 = 0;

    for stake in stakes.iter() {
        // reward_i = floor(total_issuance × stake_i / total_stake)
        let reward = total_validators_issuance
            .saturating_mul(stake.stake)
            .saturating_div(actual_staked_supply);

        rewards.push(ValidatorReward {
            validator_id: stake.validator_id,
            reward,
        });

        allocated = allocated.saturating_add(reward);
    }

    // Assign remainder to the last validator for exact conservation
    let remainder = total_validators_issuance.saturating_sub(allocated);
    if remainder > 0 && !rewards.is_empty() {
        let last_idx = rewards.len() - 1;
        rewards[last_idx].reward = rewards[last_idx].reward.saturating_add(remainder);
    }

    Some(ValidatorRewardDistribution {
        rewards,
        total_distributed: total_validators_issuance,
        total_validators_issuance,
        expected_staked_supply,
        actual_staked_supply,
    })
}

// ============================================================================
// T201: Seigniorage Application & Routing
// ============================================================================

use crate::monetary_engine::{
    compute_seigniorage_split, MonetaryAccounts, MonetaryMode, SeigniorageAccounting,
    SeigniorageSplit,
};

/// MainNet default seigniorage split: 82% validators, 12% treasury, 4% insurance, 2% community.
///
/// This follows the QBIND_MAINNET_V0_SPEC §4.1 parameters.
pub const SEIGNIORAGE_SPLIT_MAINNET_T201: SeigniorageSplit = SeigniorageSplit {
    validators_bps: 8_200, // 82%
    treasury_bps: 1_200,   // 12%
    insurance_bps: 400,    // 4%
    community_bps: 200,    // 2%
};

/// Result of applying seigniorage at an epoch boundary.
///
/// This struct captures all computed values and the actions taken, allowing
/// the caller to verify conservation invariants and update metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeigniorageApplicationResult {
    /// The epoch index this result applies to.
    pub epoch_index: u64,

    /// Total issuance computed for this epoch.
    pub total_issuance: u128,

    /// Seigniorage accounting breakdown (validators/treasury/insurance/community).
    pub accounting: SeigniorageAccounting,

    /// Per-validator reward distribution (if computed).
    /// This is `None` if the stake invariant check failed.
    pub validator_distribution: Option<ValidatorRewardDistribution>,

    /// Whether balance changes were actually applied.
    /// `true` only when mode is Active and all computations succeeded.
    pub balances_updated: bool,

    /// The monetary mode under which this result was computed.
    pub mode: MonetaryMode,
}

impl SeigniorageApplicationResult {
    /// Create a result for Off mode (nothing computed or applied).
    pub fn off_mode(epoch_index: u64) -> Self {
        Self {
            epoch_index,
            total_issuance: 0,
            accounting: SeigniorageAccounting::default(),
            validator_distribution: None,
            balances_updated: false,
            mode: MonetaryMode::Off,
        }
    }

    /// Create a result for a computed seigniorage (Shadow or Active mode).
    pub fn computed(
        epoch_index: u64,
        total_issuance: u128,
        accounting: SeigniorageAccounting,
        validator_distribution: Option<ValidatorRewardDistribution>,
        balances_updated: bool,
        mode: MonetaryMode,
    ) -> Self {
        Self {
            epoch_index,
            total_issuance,
            accounting,
            validator_distribution,
            balances_updated,
            mode,
        }
    }

    /// Check if the issuance conservation invariant holds.
    ///
    /// Returns `true` if the sum of all seigniorage buckets equals total_issuance.
    pub fn is_conserved(&self) -> bool {
        self.accounting.is_balanced()
    }

    /// Check if validator rewards conservation invariant holds.
    ///
    /// Returns `true` if:
    /// - There is no validator distribution (empty validators or zero issuance), OR
    /// - The sum of all validator rewards equals the validators bucket.
    pub fn validator_rewards_conserved(&self) -> bool {
        match &self.validator_distribution {
            None => true, // No distribution means nothing to verify
            Some(dist) => dist.total_distributed == self.accounting.to_validators,
        }
    }
}

/// Compute epoch seigniorage without applying balance changes.
///
/// This function performs all the T200/T201 calculations:
/// 1. Compute epoch issuance from MonetaryEpochState
/// 2. Split issuance among validators/treasury/insurance/community
/// 3. Distribute validator slice to individual validators
///
/// It does NOT modify any account balances - that is the caller's responsibility
/// when `mode == MonetaryMode::Active`.
///
/// # Arguments
///
/// * `epoch_state` - The computed monetary epoch state (from T199)
/// * `epochs_per_year` - Number of epochs per year (for issuance calculation)
/// * `split` - The seigniorage split configuration
/// * `validator_stakes` - Slice of validator stakes (must be in deterministic order)
/// * `mode` - The monetary mode (Off/Shadow/Active)
///
/// # Returns
///
/// A `SeigniorageApplicationResult` with all computed values.
/// If mode is Off, returns an empty result with no computations.
///
/// # Example
///
/// ```
/// use qbind_ledger::monetary_state::{
///     compute_epoch_seigniorage, MonetaryEpochState, ValidatorStake,
///     SEIGNIORAGE_SPLIT_MAINNET_T201,
/// };
/// use qbind_ledger::MonetaryMode;
///
/// let mut state = MonetaryEpochState::default();
/// state.epoch_index = 100;
/// state.staked_supply = 10_000_000;
/// state.decision.recommended_r_inf_annual = 0.0775;
///
/// let stakes = vec![
///     ValidatorStake { validator_id: 1, stake: 5_000_000 },
///     ValidatorStake { validator_id: 2, stake: 5_000_000 },
/// ];
///
/// let result = compute_epoch_seigniorage(
///     &state,
///     100, // epochs per year
///     &SEIGNIORAGE_SPLIT_MAINNET_T201,
///     &stakes,
///     MonetaryMode::Shadow,
/// );
///
/// assert!(result.is_conserved());
/// assert!(result.validator_rewards_conserved());
/// ```
pub fn compute_epoch_seigniorage(
    epoch_state: &MonetaryEpochState,
    epochs_per_year: u64,
    split: &SeigniorageSplit,
    validator_stakes: &[ValidatorStake],
    mode: MonetaryMode,
) -> SeigniorageApplicationResult {
    // Off mode: do nothing
    if mode == MonetaryMode::Off {
        return SeigniorageApplicationResult::off_mode(epoch_state.epoch_index);
    }

    // Step 1: Compute epoch issuance
    let total_issuance = compute_epoch_issuance(epoch_state, epochs_per_year);

    // Step 2: Split issuance
    let accounting = compute_seigniorage_split(total_issuance, split);

    // Step 3: Compute validator rewards distribution
    let validator_distribution = if accounting.to_validators > 0 && !validator_stakes.is_empty() {
        let expected_stake = epoch_state.staked_supply;
        compute_validator_rewards(accounting.to_validators, validator_stakes, expected_stake)
    } else {
        // Zero validators issuance or no validators - create empty distribution
        if validator_stakes.is_empty() {
            Some(ValidatorRewardDistribution {
                rewards: vec![],
                total_distributed: 0,
                total_validators_issuance: accounting.to_validators,
                expected_staked_supply: epoch_state.staked_supply,
                actual_staked_supply: 0,
            })
        } else {
            // Compute with zero issuance to get proper structure
            compute_validator_rewards(0, validator_stakes, epoch_state.staked_supply)
        }
    };

    // Balances are only updated in Active mode (by the caller after this returns)
    let balances_updated = false;

    SeigniorageApplicationResult::computed(
        epoch_state.epoch_index,
        total_issuance,
        accounting,
        validator_distribution,
        balances_updated,
        mode,
    )
}

/// Trait for applying seigniorage balance changes to accounts.
///
/// This trait abstracts over the actual state mutation, allowing the
/// seigniorage application logic to work with different state backends.
pub trait SeigniorageStateMutator {
    /// Credit an amount to an account, creating it if it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `account` - The 32-byte account identifier
    /// * `amount` - The amount to credit
    ///
    /// # Returns
    ///
    /// `true` if the credit succeeded, `false` otherwise.
    fn credit_account(&mut self, account: &[u8; 32], amount: u128) -> bool;
}

/// Apply seigniorage balance changes in Active mode.
///
/// This function takes a computed `SeigniorageApplicationResult` and applies
/// the balance changes to the accounts via the provided state mutator.
///
/// # Arguments
///
/// * `result` - The computed seigniorage result (must have mode == Active)
/// * `accounts` - The monetary accounts configuration (destination addresses)
/// * `validator_accounts` - Function to look up validator staking account by ID
/// * `state` - The state mutator for applying balance changes
///
/// # Returns
///
/// A new `SeigniorageApplicationResult` with `balances_updated = true` if successful,
/// or the original result if mode is not Active or if any credit fails.
///
/// # Safety
///
/// This function MUST only be called when:
/// - The result was computed with `mode == MonetaryMode::Active`
/// - All monetary accounts are properly configured
/// - The validator_accounts function returns valid addresses for all validators
pub fn apply_seigniorage_balances<F>(
    mut result: SeigniorageApplicationResult,
    accounts: &MonetaryAccounts,
    validator_accounts: F,
    state: &mut impl SeigniorageStateMutator,
) -> SeigniorageApplicationResult
where
    F: Fn(u64) -> [u8; 32],
{
    // Only apply balances in Active mode
    if result.mode != MonetaryMode::Active {
        return result;
    }

    // Skip if no issuance
    if result.total_issuance == 0 {
        result.balances_updated = true;
        return result;
    }

    // Credit treasury
    if result.accounting.to_treasury > 0 {
        if !state.credit_account(&accounts.treasury, result.accounting.to_treasury) {
            // TODO(T201): Add stricter error handling in production
            eprintln!(
                "[T201] Warning: Failed to credit treasury account, epoch={}",
                result.epoch_index
            );
            return result;
        }
    }

    // Credit insurance
    if result.accounting.to_insurance > 0 {
        if !state.credit_account(&accounts.insurance, result.accounting.to_insurance) {
            eprintln!(
                "[T201] Warning: Failed to credit insurance account, epoch={}",
                result.epoch_index
            );
            return result;
        }
    }

    // Credit community
    if result.accounting.to_community > 0 {
        if !state.credit_account(&accounts.community, result.accounting.to_community) {
            eprintln!(
                "[T201] Warning: Failed to credit community account, epoch={}",
                result.epoch_index
            );
            return result;
        }
    }

    // Credit individual validator rewards
    if let Some(ref distribution) = result.validator_distribution {
        for reward in &distribution.rewards {
            if reward.reward > 0 {
                let validator_account = validator_accounts(reward.validator_id);
                if !state.credit_account(&validator_account, reward.reward) {
                    eprintln!(
                        "[T201] Warning: Failed to credit validator {} account, epoch={}",
                        reward.validator_id, result.epoch_index
                    );
                    return result;
                }
            }
        }
    }

    result.balances_updated = true;
    result
}

/// Process epoch boundary seigniorage based on monetary mode.
///
/// This is the top-level function that handles the complete T201 workflow:
///
/// - **Off mode**: Returns immediately with no computation
/// - **Shadow mode**: Computes seigniorage and returns result (no balance changes)
/// - **Active mode**: Computes seigniorage and applies balance changes
///
/// # Arguments
///
/// * `epoch_state` - The computed monetary epoch state (from T199)
/// * `epochs_per_year` - Number of epochs per year
/// * `split` - The seigniorage split configuration
/// * `validator_stakes` - Slice of validator stakes
/// * `mode` - The monetary mode
/// * `accounts` - Optional monetary accounts (required for Active mode)
/// * `validator_accounts` - Function to look up validator account by ID
/// * `state` - Optional state mutator (required for Active mode)
///
/// # Returns
///
/// A `SeigniorageApplicationResult` describing what was computed and applied.
///
/// # Panics
///
/// Does not panic. If Active mode is used without accounts or state, balance
/// changes are simply not applied (logged as warnings).
pub fn process_epoch_seigniorage<F, S>(
    epoch_state: &MonetaryEpochState,
    epochs_per_year: u64,
    split: &SeigniorageSplit,
    validator_stakes: &[ValidatorStake],
    mode: MonetaryMode,
    accounts: Option<&MonetaryAccounts>,
    validator_accounts: F,
    state: Option<&mut S>,
) -> SeigniorageApplicationResult
where
    F: Fn(u64) -> [u8; 32],
    S: SeigniorageStateMutator,
{
    // Compute seigniorage (Off mode returns early)
    let result = compute_epoch_seigniorage(epoch_state, epochs_per_year, split, validator_stakes, mode);

    // For Shadow mode or Off mode, return the result as-is
    if mode != MonetaryMode::Active {
        return result;
    }

    // Active mode: apply balance changes if we have accounts and state
    match (accounts, state) {
        (Some(accts), Some(s)) => apply_seigniorage_balances(result, accts, validator_accounts, s),
        _ => {
            eprintln!(
                "[T201] Warning: Active mode but missing accounts or state, epoch={}",
                result.epoch_index
            );
            result
        }
    }
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
                ema_lambda_bps: 700, // T202: 7% EMA factor
            },
            transition: PhaseParameters {
                r_target_annual: 0.04,
                inflation_floor_annual: 0.0,
                fee_smoothing_half_life_days: 60.0,
                max_annual_inflation_cap: 0.10,
                ema_lambda_bps: 300, // T202: 3% EMA factor
            },
            mature: PhaseParameters {
                r_target_annual: 0.03,
                inflation_floor_annual: 0.01,
                fee_smoothing_half_life_days: 90.0,
                max_annual_inflation_cap: 0.08,
                ema_lambda_bps: 150, // T202: 1.5% EMA factor
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
    #[allow(deprecated)]
    fn test_compute_smoothed_annual_fee_revenue_option_a() {
        let params = PhaseParameters {
            r_target_annual: 0.05,
            inflation_floor_annual: 0.0,
            fee_smoothing_half_life_days: 30.0,
            max_annual_inflation_cap: 0.12,
            ema_lambda_bps: 700,
        };

        // 1000 fees per epoch, 100 epochs per year = 100,000 annualized
        let result = compute_smoothed_annual_fee_revenue(1000, 0, 100, &params);
        assert_eq!(result, 100_000);

        // Previous smoothed is ignored in Option A (legacy behavior)
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
            previous_ema_fees_per_epoch: 0,
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
        assert_eq!(state.ema_fees_per_epoch, 0);

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
        // Epoch 0: EMA initializes to raw fees
        let inputs = MonetaryEpochInputs {
            epoch_index: 0,
            raw_epoch_fees: 10_000, // 10k fees this epoch
            previous_smoothed_annual_fee_revenue: 0,
            previous_ema_fees_per_epoch: 0, // First epoch, no previous EMA
            staked_supply: 10_000_000,
            phase: MonetaryPhase::Bootstrap,
            bonded_ratio: 0.5,
            days_since_launch: 100,
            fee_volatility: 1.0,
            epochs_per_year: 100,
        };

        let state = compute_epoch_state(&config, &inputs);

        // Epoch 0 with no previous EMA: ema_fees = raw_fees = 10,000
        assert_eq!(state.ema_fees_per_epoch, 10_000);
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
            previous_ema_fees_per_epoch: 0,
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
            previous_ema_fees_per_epoch: 0,
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
            previous_ema_fees_per_epoch: 0,
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
        assert_eq!(state.ema_fees_per_epoch, 0);
        assert_eq!(state.smoothed_annual_fee_revenue, 0);
        assert_eq!(state.staked_supply, 0);
        assert_eq!(state.fee_coverage_ratio, 0.0);
    }

    // ========================================================================
    // T200: Epoch Issuance Tests
    // ========================================================================

    #[test]
    fn test_compute_epoch_issuance_basic() {
        let mut state = MonetaryEpochState::default();
        state.staked_supply = 1_000_000_000; // 1 billion tokens
        state.decision.recommended_r_inf_annual = 0.0775; // 7.75%

        // Using 100 epochs/year for simple math
        // issuance = (1e9 * 775) / (100 * 10000) = 775e9 / 1e6 = 775_000
        let issuance = compute_epoch_issuance(&state, 100);
        assert_eq!(issuance, 775_000);
    }

    #[test]
    fn test_compute_epoch_issuance_mainnet_values() {
        let mut state = MonetaryEpochState::default();
        state.staked_supply = 1_000_000_000_000; // 1 trillion tokens
        state.decision.recommended_r_inf_annual = 0.0775; // 7.75% = 775 bps

        // With MAINNET_EPOCHS_PER_YEAR = 52,560:
        // r_inf_bps = round(0.0775 * 10000) = 775
        // issuance = (1e12 * 775) / (52560 * 10000)
        // = 775_000_000_000_000 / 525_600_000 = 1_474_505 (floor division)
        let issuance = compute_epoch_issuance(&state, MAINNET_EPOCHS_PER_YEAR);

        assert_eq!(issuance, 1_474_505);
    }

    #[test]
    fn test_compute_epoch_issuance_zero_stake() {
        let mut state = MonetaryEpochState::default();
        state.staked_supply = 0;
        state.decision.recommended_r_inf_annual = 0.0775;

        let issuance = compute_epoch_issuance(&state, 100);
        assert_eq!(issuance, 0);
    }

    #[test]
    fn test_compute_epoch_issuance_zero_inflation() {
        let mut state = MonetaryEpochState::default();
        state.staked_supply = 1_000_000_000;
        state.decision.recommended_r_inf_annual = 0.0;

        let issuance = compute_epoch_issuance(&state, 100);
        assert_eq!(issuance, 0);
    }

    #[test]
    fn test_compute_epoch_issuance_zero_epochs_per_year() {
        let mut state = MonetaryEpochState::default();
        state.staked_supply = 1_000_000_000;
        state.decision.recommended_r_inf_annual = 0.0775;

        // Edge case: should return 0, not panic
        let issuance = compute_epoch_issuance(&state, 0);
        assert_eq!(issuance, 0);
    }

    #[test]
    fn test_compute_epoch_issuance_large_values() {
        let mut state = MonetaryEpochState::default();
        // Large but realistic value (100 trillion tokens)
        state.staked_supply = 100_000_000_000_000;
        state.decision.recommended_r_inf_annual = 0.12; // 12% = max cap

        let issuance = compute_epoch_issuance(&state, MAINNET_EPOCHS_PER_YEAR);

        // Should not overflow and produce reasonable value
        // issuance = 100e12 * 1200 / (52560 * 10000) = 1.2e17 / 5.256e8 ≈ 228,310,502
        assert!(issuance > 0);
        assert!(issuance < state.staked_supply);
    }

    // ========================================================================
    // T200: Validator Reward Distribution Tests
    // ========================================================================

    #[test]
    fn test_compute_validator_rewards_basic() {
        let stakes = vec![
            ValidatorStake { validator_id: 1, stake: 100 },
            ValidatorStake { validator_id: 2, stake: 200 },
            ValidatorStake { validator_id: 3, stake: 300 },
        ];

        let distribution = compute_validator_rewards(600, &stakes, 600).unwrap();

        assert_eq!(distribution.rewards.len(), 3);
        assert_eq!(distribution.rewards[0].validator_id, 1);
        assert_eq!(distribution.rewards[0].reward, 100); // 100/600 * 600 = 100
        assert_eq!(distribution.rewards[1].validator_id, 2);
        assert_eq!(distribution.rewards[1].reward, 200); // 200/600 * 600 = 200
        assert_eq!(distribution.rewards[2].validator_id, 3);
        assert_eq!(distribution.rewards[2].reward, 300); // 300/600 * 600 = 300

        assert!(distribution.is_balanced());
        assert!(distribution.stake_invariant_ok());
        assert_eq!(distribution.total_distributed, 600);
    }

    #[test]
    fn test_compute_validator_rewards_with_rounding() {
        let stakes = vec![
            ValidatorStake { validator_id: 1, stake: 100 },
            ValidatorStake { validator_id: 2, stake: 100 },
            ValidatorStake { validator_id: 3, stake: 100 },
        ];

        // 1000 tokens split 3 ways = 333 each, remainder 1 to last
        let distribution = compute_validator_rewards(1000, &stakes, 300).unwrap();

        assert_eq!(distribution.rewards[0].reward, 333);
        assert_eq!(distribution.rewards[1].reward, 333);
        assert_eq!(distribution.rewards[2].reward, 334); // Gets remainder

        assert!(distribution.is_balanced());
        assert_eq!(distribution.total_distributed, 1000);
    }

    #[test]
    fn test_compute_validator_rewards_stake_mismatch() {
        let stakes = vec![
            ValidatorStake { validator_id: 1, stake: 100 },
            ValidatorStake { validator_id: 2, stake: 200 },
        ];

        // Expected stake doesn't match actual (300 != 500)
        let result = compute_validator_rewards(600, &stakes, 500);
        assert!(result.is_none());
    }

    #[test]
    fn test_compute_validator_rewards_empty_stakes() {
        let stakes: Vec<ValidatorStake> = vec![];

        let distribution = compute_validator_rewards(1000, &stakes, 0).unwrap();

        assert!(distribution.rewards.is_empty());
        assert_eq!(distribution.total_distributed, 0);
        assert!(distribution.is_balanced());
    }

    #[test]
    fn test_compute_validator_rewards_zero_issuance() {
        let stakes = vec![
            ValidatorStake { validator_id: 1, stake: 100 },
            ValidatorStake { validator_id: 2, stake: 200 },
        ];

        let distribution = compute_validator_rewards(0, &stakes, 300).unwrap();

        assert_eq!(distribution.rewards[0].reward, 0);
        assert_eq!(distribution.rewards[1].reward, 0);
        assert_eq!(distribution.total_distributed, 0);
        assert!(distribution.is_balanced());
    }

    #[test]
    fn test_compute_validator_rewards_single_validator() {
        let stakes = vec![ValidatorStake { validator_id: 42, stake: 1000 }];

        let distribution = compute_validator_rewards(5000, &stakes, 1000).unwrap();

        assert_eq!(distribution.rewards.len(), 1);
        assert_eq!(distribution.rewards[0].validator_id, 42);
        assert_eq!(distribution.rewards[0].reward, 5000);
        assert!(distribution.is_balanced());
    }

    #[test]
    fn test_compute_validator_rewards_conservation() {
        // Test with various issuance amounts to ensure conservation
        let stakes = vec![
            ValidatorStake { validator_id: 1, stake: 17 },
            ValidatorStake { validator_id: 2, stake: 23 },
            ValidatorStake { validator_id: 3, stake: 41 },
            ValidatorStake { validator_id: 4, stake: 19 },
        ];
        let total_stake: u128 = stakes.iter().map(|s| s.stake).sum();

        for issuance in [0, 1, 7, 100, 999, 1000, 10007, 1_000_000] {
            let distribution = compute_validator_rewards(issuance, &stakes, total_stake).unwrap();

            let sum_rewards: u128 = distribution.rewards.iter().map(|r| r.reward).sum();
            assert_eq!(
                sum_rewards, issuance,
                "Conservation failed for issuance {}",
                issuance
            );
            assert!(distribution.is_balanced());
        }
    }

    #[test]
    fn test_compute_validator_rewards_deterministic() {
        let stakes = vec![
            ValidatorStake { validator_id: 1, stake: 123 },
            ValidatorStake { validator_id: 2, stake: 456 },
            ValidatorStake { validator_id: 3, stake: 789 },
        ];
        let total_stake: u128 = stakes.iter().map(|s| s.stake).sum();

        let dist1 = compute_validator_rewards(10000, &stakes, total_stake).unwrap();
        let dist2 = compute_validator_rewards(10000, &stakes, total_stake).unwrap();

        assert_eq!(dist1, dist2, "Results should be deterministic");
    }

    #[test]
    fn test_compute_validator_rewards_large_values() {
        let stakes = vec![
            ValidatorStake { validator_id: 1, stake: 10_000_000_000_000 },
            ValidatorStake { validator_id: 2, stake: 20_000_000_000_000 },
            ValidatorStake { validator_id: 3, stake: 30_000_000_000_000 },
        ];
        let total_stake: u128 = stakes.iter().map(|s| s.stake).sum(); // 60 trillion

        // Distribute 1 trillion tokens
        let distribution = compute_validator_rewards(1_000_000_000_000, &stakes, total_stake).unwrap();

        // 1/6 of 1 trillion = ~166.67 billion
        assert!(distribution.rewards[0].reward > 166_000_000_000);
        assert!(distribution.rewards[0].reward < 167_000_000_000);

        assert!(distribution.is_balanced());
        assert_eq!(distribution.total_distributed, 1_000_000_000_000);
    }

    #[test]
    fn test_compute_validator_rewards_unequal_stakes() {
        // One validator has vastly more stake than others
        let stakes = vec![
            ValidatorStake { validator_id: 1, stake: 1 },
            ValidatorStake { validator_id: 2, stake: 1 },
            ValidatorStake { validator_id: 3, stake: 999_998 },
        ];

        let distribution = compute_validator_rewards(1_000_000, &stakes, 1_000_000).unwrap();

        // Validator 3 should get almost all the rewards
        assert_eq!(distribution.rewards[0].reward, 1);
        assert_eq!(distribution.rewards[1].reward, 1);
        assert_eq!(distribution.rewards[2].reward, 999_998);
        assert!(distribution.is_balanced());
    }
}