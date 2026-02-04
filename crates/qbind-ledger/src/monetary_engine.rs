//! T195: Monetary Engine v1 - Pure, side-effect-free inflation rate calculator.
//!
//! This module implements the "brain" of the QBIND monetary system, computing:
//! - A recommended annual inflation rate based on security budget targets and fee offsets
//! - A phase transition recommendation (Bootstrap → Transition → Mature)
//!
//! The engine is pure logic with no IO, no static state, and no runtime wiring.
//! It takes configuration and observed inputs and returns deterministic outputs.
//!
//! See: `docs/econ/QBIND_MONETARY_POLICY_DESIGN.md` (T194) for detailed design rationale.

// ============================================================================
// Phase Model
// ============================================================================

/// The three phases of QBIND's monetary policy lifecycle.
///
/// Each phase has distinct inflation targets, fee sensitivity, and stability characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonetaryPhase {
    /// Phase 1: Network establishment (roughly years 0–3).
    /// Higher inflation target, limited fee offset, no inflation floor.
    Bootstrap,

    /// Phase 2: Growth and stabilization (roughly years 3–7).
    /// Moderate inflation target, full fee offset sensitivity, no inflation floor.
    Transition,

    /// Phase 3: Long-term operation (year 7+).
    /// Lower inflation target, full fee offset, active inflation floor for stability.
    Mature,
}

// ============================================================================
// Configuration Types
// ============================================================================

/// Phase-specific parameters for the monetary engine.
///
/// All rates are dimensionless annual rates (e.g., 0.12 for 12%).
#[derive(Debug, Clone)]
pub struct PhaseParameters {
    /// Target gross annual security rate (PQC-adjusted base rate for this phase).
    /// This is the inflation rate before fee offsets are applied.
    pub r_target_annual: f64,

    /// Minimum annual inflation for this phase (may be 0.0 in Bootstrap/Transition, >0 in Mature).
    /// The floor only applies when r_raw >= 0; see `compute_monetary_decision` for details.
    pub inflation_floor_annual: f64,

    /// EMA half-life for fee smoothing in this phase (in days).
    /// Not used in T195 computations, but stored for reference and future use.
    pub fee_smoothing_half_life_days: f64,

    /// Phase-specific maximum annual inflation cap (safety guardrail).
    pub max_annual_inflation_cap: f64,
}

/// Configuration for the monetary engine.
///
/// Contains PQC premium factors and phase-specific parameters.
#[derive(Debug, Clone)]
pub struct MonetaryEngineConfig {
    /// PQC compute premium (β_compute): higher CPU cost for ML-DSA-44 verification.
    /// Typical range: 0.20–0.35.
    pub pqc_premium_compute: f64,

    /// PQC bandwidth premium (β_bandwidth): larger signature sizes.
    /// Typical range: 0.10–0.20.
    pub pqc_premium_bandwidth: f64,

    /// PQC storage premium (β_storage): larger keys and state.
    /// Typical range: 0.05–0.10.
    pub pqc_premium_storage: f64,

    /// Parameters for the Bootstrap phase.
    pub bootstrap: PhaseParameters,

    /// Parameters for the Transition phase.
    pub transition: PhaseParameters,

    /// Parameters for the Mature phase.
    pub mature: PhaseParameters,

    /// Fee offset coefficient (α in the design doc).
    /// Fraction of fees that offset the security budget.
    /// Typical range: 0.3–1.5, phase-dependent sensitivity.
    pub alpha_fee_offset: f64,
}

impl MonetaryEngineConfig {
    /// Returns the `PhaseParameters` for the given phase.
    pub fn params_for_phase(&self, phase: MonetaryPhase) -> &PhaseParameters {
        match phase {
            MonetaryPhase::Bootstrap => &self.bootstrap,
            MonetaryPhase::Transition => &self.transition,
            MonetaryPhase::Mature => &self.mature,
        }
    }
}

// ============================================================================
// Input Types
// ============================================================================

/// Observed economic inputs for a single monetary engine evaluation.
///
/// These values are "observed" from the ledger/chain state at a given point in time.
#[derive(Debug, Clone)]
pub struct MonetaryInputs {
    /// The current monetary phase.
    pub phase: MonetaryPhase,

    /// Total staked tokens (S), in base units or abstract "tokens".
    /// Used as denominator for fee-offset rate calculation.
    pub total_staked_tokens: f64,

    /// Smoothed annual fee revenue (already EMA-smoothed by caller).
    /// Denominated in same units as tokens per year.
    pub smoothed_annual_fee_revenue: f64,

    /// Fraction of total supply staked (e.g., 0.6 for 60%).
    /// Used for phase transition readiness checks.
    pub bonded_ratio: f64,

    /// Ratio of smoothed fees to target security budget (dimensionless).
    /// Used for phase transition readiness checks.
    pub fee_coverage_ratio: f64,

    /// Dimensionless fee volatility metric (e.g., annualized σ / mean).
    /// Used for phase transition readiness checks.
    pub fee_volatility: f64,

    /// Days since network launch.
    /// Used for time-based phase transition guards.
    pub days_since_launch: u64,
}

// ============================================================================
// Output Types
// ============================================================================

/// Recommendation for phase transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseTransitionRecommendation {
    /// Stay in current phase (time conditions not met).
    Stay,

    /// Advance to the next phase (all conditions satisfied).
    /// Bootstrap → Transition, or Transition → Mature.
    Advance,

    /// Economic metrics say "not ready" even though time suggests we could advance.
    HoldBack,
}

/// The computed monetary decision output.
#[derive(Debug, Clone)]
pub struct MonetaryDecision {
    /// The effective PQC-adjusted target rate (R_target * pqc_mult).
    pub effective_r_target_annual: f64,

    /// The recommended annual inflation rate (after floor/cap/clamp).
    pub recommended_r_inf_annual: f64,

    /// True if the inflation floor was applied (r_raw < floor and r_raw >= 0).
    pub inflation_floor_applied: bool,

    /// True if the inflation cap was applied (r_raw > cap).
    pub inflation_cap_applied: bool,

    /// Recommendation for phase transition based on current inputs.
    pub phase_recommendation: PhaseTransitionRecommendation,
}

// ============================================================================
// Phase Transition Constants (T195 v1 simple heuristics)
// ============================================================================

/// Minimum days before Bootstrap → Transition can be considered (~3 years).
const BOOTSTRAP_MIN_DAYS: u64 = 3 * 365;

/// Minimum days before Transition → Mature can be considered (~7 years from genesis).
const TRANSITION_MIN_DAYS: u64 = 7 * 365;

/// Minimum bonded ratio for Bootstrap → Transition.
const BOOTSTRAP_TO_TRANSITION_MIN_BONDED_RATIO: f64 = 0.5;

/// Minimum fee coverage ratio for Bootstrap → Transition.
const BOOTSTRAP_TO_TRANSITION_MIN_FEE_COVERAGE: f64 = 0.3;

/// Maximum fee volatility for Bootstrap → Transition.
const BOOTSTRAP_TO_TRANSITION_MAX_VOLATILITY: f64 = 2.0;

/// Minimum bonded ratio for Transition → Mature.
const TRANSITION_TO_MATURE_MIN_BONDED_RATIO: f64 = 0.5;

/// Minimum fee coverage ratio for Transition → Mature.
const TRANSITION_TO_MATURE_MIN_FEE_COVERAGE: f64 = 0.6;

/// Maximum fee volatility for Transition → Mature (tighter than Bootstrap→Transition).
const TRANSITION_TO_MATURE_MAX_VOLATILITY: f64 = 1.5;

// ============================================================================
// Core Engine Function
// ============================================================================

/// Computes the monetary decision based on configuration and observed inputs.
///
/// This is a pure function with no side effects, no IO, and no static state.
///
/// # Algorithm
///
/// 1. **PQC-adjusted target**: Compute `effective_r_target = r_target_base * pqc_mult`
///    where `pqc_mult = 1 + β_compute + β_bandwidth + β_storage`.
///
/// 2. **Fee offset**: Compute `r_fee_offset = α * (smoothed_annual_fee_revenue / total_staked_tokens)`.
///    If `total_staked_tokens ≈ 0`, treat `r_fee_offset = 0`.
///
/// 3. **Unclamped inflation**: `r_raw = effective_r_target - r_fee_offset`.
///
/// 4. **Apply floor and cap**:
///    - If `r_raw < 0`, clamp to 0 (floor_applied = false, since floor only applies when r_raw >= 0).
///    - Else if `r_raw < inflation_floor`, set to floor (floor_applied = true).
///    - If result > cap, set to cap (cap_applied = true).
///
/// 5. **Phase transition recommendation**: Simple heuristic based on time and economic metrics.
///
/// # Arguments
///
/// * `cfg` - The monetary engine configuration.
/// * `inputs` - The observed economic inputs.
///
/// # Returns
///
/// A `MonetaryDecision` containing the recommended inflation rate and phase transition advice.
pub fn compute_monetary_decision(
    cfg: &MonetaryEngineConfig,
    inputs: &MonetaryInputs,
) -> MonetaryDecision {
    let params = cfg.params_for_phase(inputs.phase);

    // Step 1: PQC-adjusted target rate
    let pqc_mult =
        1.0 + cfg.pqc_premium_compute + cfg.pqc_premium_bandwidth + cfg.pqc_premium_storage;
    let effective_r_target = params.r_target_annual * pqc_mult;

    // Step 2: Fee offset (security-budget-driven)
    // If total_staked_tokens is ~0, treat r_fee_offset as 0 to avoid division issues.
    let r_fee_offset = if inputs.total_staked_tokens > f64::EPSILON {
        cfg.alpha_fee_offset * (inputs.smoothed_annual_fee_revenue / inputs.total_staked_tokens)
    } else {
        0.0
    };

    // Step 3: Unclamped inflation
    let r_raw = effective_r_target - r_fee_offset;

    // Step 4: Apply floor, cap, and non-negativity clamp
    let mut r_inf = r_raw;
    let mut floor_applied = false;
    let mut cap_applied = false;

    // Rule: floor is interpreted as "minimum non-zero inflation only when target is positive".
    // If r_raw < 0, we clamp to 0, floor_applied = false.
    if r_raw < 0.0 {
        r_inf = 0.0;
        // floor_applied remains false since floor only applies when r_raw >= 0
    } else if r_raw < params.inflation_floor_annual {
        r_inf = params.inflation_floor_annual;
        floor_applied = true;
    }

    // Apply cap (regardless of whether floor was applied)
    if r_inf > params.max_annual_inflation_cap {
        r_inf = params.max_annual_inflation_cap;
        cap_applied = true;
    }

    // Step 5: Phase transition recommendation
    let phase_recommendation = compute_phase_recommendation(inputs);

    MonetaryDecision {
        effective_r_target_annual: effective_r_target,
        recommended_r_inf_annual: r_inf,
        inflation_floor_applied: floor_applied,
        inflation_cap_applied: cap_applied,
        phase_recommendation,
    }
}

/// Computes the phase transition recommendation based on time and economic metrics.
///
/// # Heuristics (T195 v1, simple)
///
/// - **Bootstrap → Transition**: Requires days_since_launch >= BOOTSTRAP_MIN_DAYS,
///   bonded_ratio >= 0.5, fee_coverage_ratio >= 0.3, fee_volatility <= 2.0.
///
/// - **Transition → Mature**: Requires days_since_launch >= TRANSITION_MIN_DAYS,
///   bonded_ratio >= 0.5, fee_coverage_ratio >= 0.6, fee_volatility <= 1.5.
///
/// - **Mature**: Already at top phase, always returns `Stay`.
fn compute_phase_recommendation(inputs: &MonetaryInputs) -> PhaseTransitionRecommendation {
    match inputs.phase {
        MonetaryPhase::Bootstrap => {
            // Check time gate for Bootstrap → Transition
            if inputs.days_since_launch < BOOTSTRAP_MIN_DAYS {
                return PhaseTransitionRecommendation::Stay;
            }

            // Time condition met; check economic gates
            let bonded_ok = inputs.bonded_ratio >= BOOTSTRAP_TO_TRANSITION_MIN_BONDED_RATIO;
            let fee_coverage_ok =
                inputs.fee_coverage_ratio >= BOOTSTRAP_TO_TRANSITION_MIN_FEE_COVERAGE;
            let volatility_ok = inputs.fee_volatility <= BOOTSTRAP_TO_TRANSITION_MAX_VOLATILITY;

            if bonded_ok && fee_coverage_ok && volatility_ok {
                PhaseTransitionRecommendation::Advance
            } else {
                PhaseTransitionRecommendation::HoldBack
            }
        }

        MonetaryPhase::Transition => {
            // Check time gate for Transition → Mature
            if inputs.days_since_launch < TRANSITION_MIN_DAYS {
                return PhaseTransitionRecommendation::Stay;
            }

            // Time condition met; check economic gates
            let bonded_ok = inputs.bonded_ratio >= TRANSITION_TO_MATURE_MIN_BONDED_RATIO;
            let fee_coverage_ok =
                inputs.fee_coverage_ratio >= TRANSITION_TO_MATURE_MIN_FEE_COVERAGE;
            let volatility_ok = inputs.fee_volatility <= TRANSITION_TO_MATURE_MAX_VOLATILITY;

            if bonded_ok && fee_coverage_ok && volatility_ok {
                PhaseTransitionRecommendation::Advance
            } else {
                PhaseTransitionRecommendation::HoldBack
            }
        }

        MonetaryPhase::Mature => {
            // Already at top phase; cannot advance further.
            PhaseTransitionRecommendation::Stay
        }
    }
}

// ============================================================================
// T197: Monetary Mode & Seigniorage Types
// ============================================================================

/// Mode controlling the monetary engine's behavior.
///
/// This determines whether the engine:
/// - Computes and applies decisions (Active)
/// - Computes decisions for metrics only (Shadow)
/// - Does nothing (Off)
///
/// # Phased Rollout
///
/// - **DevNet v0**: `Off` – no issuance, no decisions
/// - **TestNet Alpha**: `Shadow` – decisions + metrics only
/// - **TestNet Beta**: `Shadow` – decisions + metrics only
/// - **MainNet v0**: `Shadow` – governance can flip to `Active` later
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MonetaryMode {
    /// Off: No decisions, no metrics, no issuance.
    ///
    /// The monetary engine is completely disabled.
    /// Use for DevNet or when monetary policy is not yet needed.
    #[default]
    Off,

    /// Shadow: Decisions + metrics, no state changes.
    ///
    /// The engine computes monetary decisions and exposes them via
    /// metrics and logs, but does not mint tokens or modify balances.
    /// Use for testing and observability before enabling issuance.
    Shadow,

    /// Active: Decisions + metrics + minting + seigniorage split.
    ///
    /// The engine computes decisions and actually mints tokens,
    /// distributing them to the configured seigniorage accounts.
    Active,
}

impl std::fmt::Display for MonetaryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MonetaryMode::Off => write!(f, "off"),
            MonetaryMode::Shadow => write!(f, "shadow"),
            MonetaryMode::Active => write!(f, "active"),
        }
    }
}

/// Parse a monetary mode from a string (case-insensitive).
///
/// # Arguments
///
/// * `s` - The string to parse ("off", "shadow", or "active")
///
/// # Returns
///
/// `Some(MonetaryMode)` if valid, `None` for unrecognized values.
///
/// # Example
///
/// ```
/// use qbind_ledger::monetary_engine::parse_monetary_mode;
///
/// assert_eq!(parse_monetary_mode("off"), Some(qbind_ledger::MonetaryMode::Off));
/// assert_eq!(parse_monetary_mode("SHADOW"), Some(qbind_ledger::MonetaryMode::Shadow));
/// assert_eq!(parse_monetary_mode("Active"), Some(qbind_ledger::MonetaryMode::Active));
/// assert_eq!(parse_monetary_mode("invalid"), None);
/// ```
pub fn parse_monetary_mode(s: &str) -> Option<MonetaryMode> {
    match s.to_lowercase().as_str() {
        "off" => Some(MonetaryMode::Off),
        "shadow" => Some(MonetaryMode::Shadow),
        "active" => Some(MonetaryMode::Active),
        _ => None,
    }
}

/// Valid monetary mode values for CLI help text.
pub const VALID_MONETARY_MODES: &[&str] = &["off", "shadow", "active"];

// ============================================================================
// T197: Seigniorage Split Configuration
// ============================================================================

/// Seigniorage split configuration in basis points (bps).
///
/// Determines how newly minted tokens are distributed among:
/// - Validators (reward pool)
/// - Treasury (protocol development)
/// - Insurance (slashing/security fund)
/// - Community (grants, ecosystem growth)
///
/// All values are in basis points where 10,000 bps = 100%.
/// The sum of all fields must equal 10,000.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeigniorageSplit {
    /// Basis points allocated to validators (staking rewards pool).
    pub validators_bps: u16,
    /// Basis points allocated to the protocol treasury.
    pub treasury_bps: u16,
    /// Basis points allocated to the insurance fund.
    pub insurance_bps: u16,
    /// Basis points allocated to community programs.
    pub community_bps: u16,
}

impl SeigniorageSplit {
    /// Total basis points that the split must sum to (100%).
    pub const BPS_TOTAL: u32 = 10_000;

    /// Create a new seigniorage split.
    ///
    /// # Arguments
    ///
    /// * `validators_bps` - Basis points for validators
    /// * `treasury_bps` - Basis points for treasury
    /// * `insurance_bps` - Basis points for insurance
    /// * `community_bps` - Basis points for community
    ///
    /// # Panics
    ///
    /// Panics if the sum does not equal 10,000.
    pub fn new(
        validators_bps: u16,
        treasury_bps: u16,
        insurance_bps: u16,
        community_bps: u16,
    ) -> Self {
        let split = Self {
            validators_bps,
            treasury_bps,
            insurance_bps,
            community_bps,
        };
        assert!(
            split.is_valid(),
            "SeigniorageSplit sum must equal 10,000, got {}",
            split.sum()
        );
        split
    }

    /// Check if this split is valid (sums to 10,000 bps).
    pub fn is_valid(&self) -> bool {
        self.sum() == Self::BPS_TOTAL
    }

    /// Calculate the sum of all split components.
    pub fn sum(&self) -> u32 {
        self.validators_bps as u32
            + self.treasury_bps as u32
            + self.insurance_bps as u32
            + self.community_bps as u32
    }

    /// Validate this split and return an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        let sum = self.sum();
        if sum == Self::BPS_TOTAL {
            Ok(())
        } else {
            Err(format!(
                "SeigniorageSplit must sum to {} bps, got {} bps",
                Self::BPS_TOTAL,
                sum
            ))
        }
    }
}

/// Default seigniorage split for MainNet:
/// - 50% validators
/// - 30% treasury
/// - 10% insurance
/// - 10% community
pub const SEIGNIORAGE_SPLIT_MAINNET_DEFAULT: SeigniorageSplit = SeigniorageSplit {
    validators_bps: 5_000, // 50%
    treasury_bps: 3_000,   // 30%
    insurance_bps: 1_000,  // 10%
    community_bps: 1_000,  // 10%
};

impl Default for SeigniorageSplit {
    fn default() -> Self {
        SEIGNIORAGE_SPLIT_MAINNET_DEFAULT
    }
}

// ============================================================================
// T197: Seigniorage Accounting
// ============================================================================

/// Result of computing seigniorage split for a given issuance amount.
///
/// This struct records how the total issuance is distributed among
/// the four buckets. The sum of all bucket amounts must equal `total_issuance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeigniorageAccounting {
    /// Total tokens issued in this period.
    pub total_issuance: u128,
    /// Tokens allocated to the validator reward pool.
    pub to_validators: u128,
    /// Tokens allocated to the protocol treasury.
    pub to_treasury: u128,
    /// Tokens allocated to the insurance fund.
    pub to_insurance: u128,
    /// Tokens allocated to community programs.
    pub to_community: u128,
}

impl SeigniorageAccounting {
    /// Check if the accounting is balanced (all parts sum to total).
    pub fn is_balanced(&self) -> bool {
        self.to_validators
            .saturating_add(self.to_treasury)
            .saturating_add(self.to_insurance)
            .saturating_add(self.to_community)
            == self.total_issuance
    }
}

/// Compute the seigniorage split for a given total issuance amount.
///
/// This function distributes `total_issuance` tokens among four buckets
/// according to the provided `split` configuration.
///
/// # Algorithm
///
/// Uses integer arithmetic only:
/// 1. Compute validators, insurance, and community amounts via floor division
/// 2. Assign any remainder to treasury to ensure exact conservation
///
/// This guarantees:
/// - All bucket amounts are ≥ 0
/// - The sum equals exactly `total_issuance`
/// - Results are deterministic for the same inputs
///
/// # Arguments
///
/// * `total_issuance` - Total tokens to distribute
/// * `split` - The basis-point split configuration
///
/// # Returns
///
/// A `SeigniorageAccounting` struct with the distributed amounts.
///
/// # Example
///
/// ```
/// use qbind_ledger::monetary_engine::{compute_seigniorage_split, SeigniorageSplit};
///
/// let split = SeigniorageSplit::new(5_000, 3_000, 1_000, 1_000);
/// let accounting = compute_seigniorage_split(1_000_000, &split);
///
/// assert_eq!(accounting.to_validators, 500_000);
/// assert_eq!(accounting.to_treasury, 300_000);
/// assert_eq!(accounting.to_insurance, 100_000);
/// assert_eq!(accounting.to_community, 100_000);
/// assert!(accounting.is_balanced());
/// ```
pub fn compute_seigniorage_split(
    total_issuance: u128,
    split: &SeigniorageSplit,
) -> SeigniorageAccounting {
    if total_issuance == 0 {
        return SeigniorageAccounting::default();
    }

    let bps_total = SeigniorageSplit::BPS_TOTAL as u128;

    // Compute three buckets via floor division
    let to_validators = total_issuance
        .saturating_mul(split.validators_bps as u128)
        .saturating_div(bps_total);
    let to_insurance = total_issuance
        .saturating_mul(split.insurance_bps as u128)
        .saturating_div(bps_total);
    let to_community = total_issuance
        .saturating_mul(split.community_bps as u128)
        .saturating_div(bps_total);

    // Assign remainder to treasury to ensure exact conservation
    let allocated = to_validators
        .saturating_add(to_insurance)
        .saturating_add(to_community);
    let to_treasury = total_issuance.saturating_sub(allocated);

    SeigniorageAccounting {
        total_issuance,
        to_validators,
        to_treasury,
        to_insurance,
        to_community,
    }
}

// ============================================================================
// T197: Monetary Accounts Configuration
// ============================================================================

/// Account identifiers for seigniorage distribution.
///
/// These are the destination accounts where newly minted tokens are credited.
/// In Active mode, the monetary engine transfers seigniorage to these accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonetaryAccounts {
    /// Account ID for the validator reward pool.
    /// Individual validator rewards are distributed from this pool later.
    pub validator_pool: [u8; 32],
    /// Account ID for the protocol treasury.
    pub treasury: [u8; 32],
    /// Account ID for the insurance/security fund.
    pub insurance: [u8; 32],
    /// Account ID for community programs.
    pub community: [u8; 32],
}

impl MonetaryAccounts {
    /// Create monetary accounts from raw byte arrays.
    pub fn new(
        validator_pool: [u8; 32],
        treasury: [u8; 32],
        insurance: [u8; 32],
        community: [u8; 32],
    ) -> Self {
        Self {
            validator_pool,
            treasury,
            insurance,
            community,
        }
    }

    /// Create test/dummy monetary accounts for DevNet/TestNet.
    ///
    /// These accounts use predictable values derived from their names.
    /// NOT for production use.
    pub fn test_accounts() -> Self {
        Self {
            validator_pool: Self::derive_test_account(b"validator_pool"),
            treasury: Self::derive_test_account(b"treasury"),
            insurance: Self::derive_test_account(b"insurance"),
            community: Self::derive_test_account(b"community"),
        }
    }

    /// Derive a test account ID from a seed.
    fn derive_test_account(seed: &[u8]) -> [u8; 32] {
        let mut result = [0u8; 32];
        // Simple derivation: fill with seed bytes, padded/truncated
        for (i, byte) in seed.iter().cycle().take(32).enumerate() {
            result[i] = *byte;
        }
        result
    }

    /// Check if all accounts are distinct (no duplicate account IDs).
    pub fn all_distinct(&self) -> bool {
        self.validator_pool != self.treasury
            && self.validator_pool != self.insurance
            && self.validator_pool != self.community
            && self.treasury != self.insurance
            && self.treasury != self.community
            && self.insurance != self.community
    }
}

// ============================================================================
// Unit Tests (basic sanity checks; comprehensive tests in t195_monetary_engine_tests.rs)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> MonetaryEngineConfig {
        MonetaryEngineConfig {
            pqc_premium_compute: 0.30,
            pqc_premium_bandwidth: 0.15,
            pqc_premium_storage: 0.10,
            bootstrap: PhaseParameters {
                r_target_annual: 0.05,       // 5% base
                inflation_floor_annual: 0.0, // no floor
                fee_smoothing_half_life_days: 30.0,
                max_annual_inflation_cap: 0.12, // 12% cap
            },
            transition: PhaseParameters {
                r_target_annual: 0.04,       // 4% base
                inflation_floor_annual: 0.0, // no floor
                fee_smoothing_half_life_days: 60.0,
                max_annual_inflation_cap: 0.10, // 10% cap
            },
            mature: PhaseParameters {
                r_target_annual: 0.03,        // 3% base
                inflation_floor_annual: 0.01, // 1% floor
                fee_smoothing_half_life_days: 90.0,
                max_annual_inflation_cap: 0.08, // 8% cap
            },
            alpha_fee_offset: 1.0,
        }
    }

    fn default_inputs() -> MonetaryInputs {
        MonetaryInputs {
            phase: MonetaryPhase::Bootstrap,
            total_staked_tokens: 1_000_000.0,
            smoothed_annual_fee_revenue: 0.0,
            bonded_ratio: 0.5,
            fee_coverage_ratio: 0.3,
            fee_volatility: 1.0,
            days_since_launch: 100,
        }
    }

    #[test]
    fn test_pqc_multiplier_calculation() {
        let cfg = default_config();
        let inputs = default_inputs();
        let decision = compute_monetary_decision(&cfg, &inputs);

        // PQC multiplier = 1 + 0.30 + 0.15 + 0.10 = 1.55
        // Effective target = 0.05 * 1.55 = 0.0775
        assert!(
            (decision.effective_r_target_annual - 0.0775).abs() < 1e-9,
            "Expected effective_r_target_annual ≈ 0.0775, got {}",
            decision.effective_r_target_annual
        );
    }

    #[test]
    fn test_zero_fees_returns_effective_target() {
        let cfg = default_config();
        let inputs = default_inputs(); // fees = 0
        let decision = compute_monetary_decision(&cfg, &inputs);

        // With zero fees, r_inf should equal effective_r_target (capped if needed)
        // Bootstrap cap is 0.12, effective target is 0.0775, so no cap applied
        assert!(
            (decision.recommended_r_inf_annual - 0.0775).abs() < 1e-9,
            "Expected r_inf ≈ 0.0775, got {}",
            decision.recommended_r_inf_annual
        );
        assert!(!decision.inflation_floor_applied);
        assert!(!decision.inflation_cap_applied);
    }

    #[test]
    fn test_mature_phase_has_floor() {
        let cfg = default_config();
        let mut inputs = default_inputs();
        inputs.phase = MonetaryPhase::Mature;
        // Set very high fees to drive r_raw below floor
        inputs.total_staked_tokens = 1_000_000.0;
        inputs.smoothed_annual_fee_revenue = 50_000.0; // 5% fee rate, exceeds target

        let decision = compute_monetary_decision(&cfg, &inputs);

        // Effective target = 0.03 * 1.55 = 0.0465
        // Fee offset = 1.0 * (50000 / 1000000) = 0.05
        // r_raw = 0.0465 - 0.05 = -0.0035 (negative!)
        // Since r_raw < 0, clamp to 0 (floor not applied because r_raw < 0)
        assert_eq!(decision.recommended_r_inf_annual, 0.0);
        assert!(!decision.inflation_floor_applied);
    }
}