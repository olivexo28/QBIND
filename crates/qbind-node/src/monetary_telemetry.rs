//! T196: Monetary Engine Telemetry & Shadow Mode
//!
//! This module provides node-level telemetry for the monetary engine (T195).
//! It watches real blocks as they are committed, derives smoothed fee revenue
//! and other inputs, and calls `compute_monetary_decision(...)` to produce
//! a `MonetaryDecision` per block.
//!
//! **Shadow Mode**: The results are exposed via metrics and logs only.
//! No changes to balances, no minting, no seigniorage wiring. This lets
//! operators see what the monetary engine would do under current workloads.
//!
//! # Usage
//!
//! ```rust,ignore
//! use qbind_node::monetary_telemetry::{
//!     MonetaryTelemetry, MonetaryTelemetryConfig, default_monetary_engine_config_for_testnet,
//! };
//! use qbind_ledger::MonetaryPhase;
//!
//! let cfg = MonetaryTelemetryConfig {
//!     enabled: true,
//!     blocks_per_second: 1.0 / 6.0,
//!     phase: MonetaryPhase::Bootstrap,
//!     engine_config: default_monetary_engine_config_for_testnet(),
//! };
//!
//! let mut telemetry = MonetaryTelemetry::new(cfg);
//!
//! // On each block commit:
//! let decision = telemetry.on_block_committed(
//!     height,
//!     block_fees_total,
//!     total_staked_tokens,
//!     bonded_ratio,
//!     None,  // fee_coverage_ratio_hint
//!     None,  // fee_volatility_hint
//!     days_since_launch,
//! );
//! ```
//!
//! # Design
//!
//! - Pure deterministic math + state updates in `on_block_committed`
//! - No logging or metrics inside this module; those are handled at the node level
//! - EMA-based fee smoothing with configurable half-life per phase

use qbind_ledger::monetary_engine::{
    compute_monetary_decision, MonetaryDecision, MonetaryEngineConfig, MonetaryInputs,
    MonetaryPhase, PhaseParameters,
};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the monetary telemetry service.
///
/// This is a small, focused config that doesn't couple directly to NodeConfig.
/// Later phases may wire this into the node configuration system.
#[derive(Debug, Clone)]
pub struct MonetaryTelemetryConfig {
    /// Whether telemetry is enabled. If false, `on_block_committed` is a no-op.
    pub enabled: bool,

    /// Blocks per second estimate (for annualization).
    ///
    /// For a 6-second block time, use `1.0 / 6.0 ≈ 0.1667`.
    pub blocks_per_second: f64,

    /// Current phase for this network (Bootstrap / Transition / Mature).
    ///
    /// For now, this is supplied in config. Later we can infer from height/time.
    pub phase: MonetaryPhase,

    /// Engine configuration (from T195, possibly with network-specific defaults).
    pub engine_config: MonetaryEngineConfig,
}

impl Default for MonetaryTelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            blocks_per_second: 1.0 / 6.0, // 6-second blocks
            phase: MonetaryPhase::Bootstrap,
            engine_config: default_monetary_engine_config_for_testnet(),
        }
    }
}

// ============================================================================
// Runtime State
// ============================================================================

/// Runtime state for the monetary telemetry service.
///
/// Carries the smoothed fee signal and last decision.
#[derive(Debug, Clone)]
pub struct MonetaryTelemetryState {
    /// Last processed block height.
    pub last_height: u64,

    /// EMA-smoothed annual fee revenue (fed into MonetaryInputs).
    pub smoothed_annual_fee_revenue: f64,

    /// Last computed monetary decision.
    pub last_decision: Option<MonetaryDecision>,
}

impl Default for MonetaryTelemetryState {
    fn default() -> Self {
        Self {
            last_height: 0,
            smoothed_annual_fee_revenue: 0.0,
            last_decision: None,
        }
    }
}

// ============================================================================
// MonetaryTelemetry Service
// ============================================================================

/// Monetary telemetry service for shadow-mode observability.
///
/// This service:
/// 1. Receives block commit notifications with fee totals
/// 2. Maintains an EMA-smoothed annual fee revenue estimate
/// 3. Calls the monetary engine to compute decisions
/// 4. Exposes state for metrics/logging at the node level
///
/// No side effects beyond state updates; logging and metrics are external.
#[derive(Debug, Clone)]
pub struct MonetaryTelemetry {
    cfg: MonetaryTelemetryConfig,
    state: MonetaryTelemetryState,
}

impl MonetaryTelemetry {
    /// Create a new monetary telemetry service with the given configuration.
    pub fn new(cfg: MonetaryTelemetryConfig) -> Self {
        Self {
            cfg,
            state: MonetaryTelemetryState::default(),
        }
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &MonetaryTelemetryConfig {
        &self.cfg
    }

    /// Returns the current telemetry state.
    pub fn state(&self) -> &MonetaryTelemetryState {
        &self.state
    }

    /// Called whenever a block is committed and VmV0 stats are available.
    ///
    /// # Arguments
    ///
    /// * `height` - Block height
    /// * `block_fees_total` - Total fees in this block, in base token units
    /// * `total_staked_tokens` - Total staked tokens (S)
    /// * `bonded_ratio` - Fraction of total supply staked (e.g., 0.6 for 60%)
    /// * `fee_coverage_ratio_hint` - Optional precomputed fee coverage ratio
    /// * `fee_volatility_hint` - Optional precomputed fee volatility metric
    /// * `days_since_launch` - Days since network launch
    ///
    /// # Returns
    ///
    /// The new `MonetaryDecision` if telemetry is enabled, otherwise `None`.
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_committed(
        &mut self,
        height: u64,
        block_fees_total: f64,
        total_staked_tokens: f64,
        bonded_ratio: f64,
        fee_coverage_ratio_hint: Option<f64>,
        fee_volatility_hint: Option<f64>,
        days_since_launch: u64,
    ) -> Option<MonetaryDecision> {
        // Early return if disabled
        if !self.cfg.enabled {
            return None;
        }

        // Get phase parameters for EMA calculation
        let phase_params = self.cfg.engine_config.params_for_phase(self.cfg.phase);

        // Calculate blocks per year
        let blocks_per_year = self.cfg.blocks_per_second * 60.0 * 60.0 * 24.0 * 365.0;

        // Compute EMA decay factor (lambda) from half-life
        let lambda = compute_ema_lambda(
            phase_params.fee_smoothing_half_life_days,
            self.cfg.blocks_per_second,
        );

        // Update EMA of fees per block, then scale to annual
        let ema_prev_per_block = if blocks_per_year > f64::EPSILON {
            self.state.smoothed_annual_fee_revenue / blocks_per_year
        } else {
            0.0
        };

        let ema_new_per_block =
            ema_prev_per_block + lambda * (block_fees_total - ema_prev_per_block);

        let smoothed_annual_fee_revenue = ema_new_per_block * blocks_per_year;

        // Update state
        self.state.last_height = height;
        self.state.smoothed_annual_fee_revenue = smoothed_annual_fee_revenue;

        // Build inputs for monetary engine
        let fee_coverage_ratio = fee_coverage_ratio_hint.unwrap_or(0.0);
        let fee_volatility = fee_volatility_hint.unwrap_or(0.0);

        let inputs = MonetaryInputs {
            phase: self.cfg.phase,
            total_staked_tokens,
            smoothed_annual_fee_revenue,
            bonded_ratio,
            fee_coverage_ratio,
            fee_volatility,
            days_since_launch,
        };

        // Compute monetary decision
        let decision = compute_monetary_decision(&self.cfg.engine_config, &inputs);

        // Store and return
        self.state.last_decision = Some(decision.clone());
        Some(decision)
    }

    /// Reset the telemetry state (useful for testing).
    pub fn reset(&mut self) {
        self.state = MonetaryTelemetryState::default();
    }
}

// ============================================================================
// EMA Helper Functions
// ============================================================================

/// Compute the EMA decay factor (lambda) from a half-life in days.
///
/// The formula converts a half-life H (in days) to a per-block decay factor:
///
/// ```text
/// half_life_seconds = H * 24 * 3600
/// half_life_blocks = blocks_per_second * half_life_seconds
/// lambda = ln(2) / half_life_blocks
/// ```
///
/// Lambda is clamped to [0, 1] for numerical stability.
fn compute_ema_lambda(half_life_days: f64, blocks_per_second: f64) -> f64 {
    // Convert half-life from days to seconds
    let half_life_seconds = half_life_days * 24.0 * 3600.0;

    // Convert to blocks
    let half_life_blocks = blocks_per_second * half_life_seconds;

    // Avoid division by zero; if half_life_blocks is tiny, use no smoothing
    if half_life_blocks <= f64::EPSILON {
        return 1.0;
    }

    // Standard EMA: alpha = ln(2) / H_blocks
    (std::f64::consts::LN_2 / half_life_blocks).clamp(0.0, 1.0)
}

// ============================================================================
// Default Configuration Helpers
// ============================================================================

/// Create a default `MonetaryEngineConfig` suitable for TestNet.
///
/// This provides reasonable defaults consistent with T194 design:
/// - PQC premiums reflecting ML-DSA-44 overhead
/// - Phase-specific parameters for Bootstrap, Transition, Mature
/// - Conservative fee offset coefficient
pub fn default_monetary_engine_config_for_testnet() -> MonetaryEngineConfig {
    MonetaryEngineConfig {
        // PQC premium factors (T194 estimates)
        pqc_premium_compute: 0.30,   // ~30% compute overhead
        pqc_premium_bandwidth: 0.15, // ~15% bandwidth overhead
        pqc_premium_storage: 0.10,   // ~10% storage overhead

        // Bootstrap phase (years 0-3)
        bootstrap: PhaseParameters {
            r_target_annual: 0.05,              // 5% base (7.75% PQC-adjusted)
            inflation_floor_annual: 0.0,        // No floor
            fee_smoothing_half_life_days: 30.0, // Fast response
            max_annual_inflation_cap: 0.12,     // 12% cap
            ema_lambda_bps: 700,                // λ = 0.07 — faster response for fee baseline
            max_delta_r_inf_per_epoch_bps: 25,  // T203: 0.25% max change per epoch
        },

        // Transition phase (years 3-7)
        transition: PhaseParameters {
            r_target_annual: 0.04,              // 4% base (6.2% PQC-adjusted)
            inflation_floor_annual: 0.0,        // No floor
            fee_smoothing_half_life_days: 60.0, // Medium smoothing
            max_annual_inflation_cap: 0.10,     // 10% cap
            ema_lambda_bps: 300,                // λ = 0.03 — balanced response during growth
            max_delta_r_inf_per_epoch_bps: 10,  // T203: 0.10% max change per epoch
        },

        // Mature phase (year 7+)
        mature: PhaseParameters {
            r_target_annual: 0.03,              // 3% base (4.65% PQC-adjusted)
            inflation_floor_annual: 0.01,       // 1% floor
            fee_smoothing_half_life_days: 90.0, // Long smoothing
            max_annual_inflation_cap: 0.08,     // 8% cap
            ema_lambda_bps: 150,                // λ = 0.015 — maximum smoothing for stability
            max_delta_r_inf_per_epoch_bps: 5,   // T203: 0.05% max change per epoch
        },

        // Fee offset coefficient (α)
        alpha_fee_offset: 1.0,
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MonetaryTelemetryConfig {
        MonetaryTelemetryConfig {
            enabled: true,
            blocks_per_second: 1.0 / 6.0, // 6-second blocks
            phase: MonetaryPhase::Bootstrap,
            engine_config: default_monetary_engine_config_for_testnet(),
        }
    }

    #[test]
    fn test_default_config() {
        let cfg = MonetaryTelemetryConfig::default();
        assert!(!cfg.enabled);
        assert!((cfg.blocks_per_second - 1.0 / 6.0).abs() < 1e-9);
        assert_eq!(cfg.phase, MonetaryPhase::Bootstrap);
    }

    #[test]
    fn test_default_state() {
        let state = MonetaryTelemetryState::default();
        assert_eq!(state.last_height, 0);
        assert_eq!(state.smoothed_annual_fee_revenue, 0.0);
        assert!(state.last_decision.is_none());
    }

    #[test]
    fn test_ema_lambda_computation() {
        let blocks_per_second = 1.0 / 6.0;

        // 30-day half-life
        let lambda_30d = compute_ema_lambda(30.0, blocks_per_second);
        // Expected: ln(2) / (0.1667 * 30 * 24 * 3600) ≈ 1.61e-6
        assert!(lambda_30d > 0.0 && lambda_30d < 0.001);

        // Very short half-life should give high lambda (capped at 1.0)
        let lambda_tiny = compute_ema_lambda(0.0, blocks_per_second);
        assert_eq!(lambda_tiny, 1.0);

        // Very long half-life should give tiny lambda
        let lambda_long = compute_ema_lambda(365.0, blocks_per_second);
        assert!(lambda_long > 0.0 && lambda_long < lambda_30d);
    }

    #[test]
    fn test_new_telemetry() {
        let cfg = test_config();
        let telemetry = MonetaryTelemetry::new(cfg.clone());

        assert!(telemetry.config().enabled);
        assert_eq!(telemetry.state().last_height, 0);
        assert_eq!(telemetry.state().smoothed_annual_fee_revenue, 0.0);
    }

    #[test]
    fn test_on_block_committed_updates_state() {
        let cfg = test_config();
        let mut telemetry = MonetaryTelemetry::new(cfg);

        let decision = telemetry.on_block_committed(
            1,      // height
            100.0,  // block_fees_total
            1000.0, // total_staked_tokens
            0.5,    // bonded_ratio
            None,   // fee_coverage_ratio_hint
            None,   // fee_volatility_hint
            100,    // days_since_launch
        );

        assert!(decision.is_some());
        assert_eq!(telemetry.state().last_height, 1);
        assert!(telemetry.state().smoothed_annual_fee_revenue > 0.0);
        assert!(telemetry.state().last_decision.is_some());
    }

    #[test]
    fn test_reset() {
        let cfg = test_config();
        let mut telemetry = MonetaryTelemetry::new(cfg);

        // Process some blocks
        telemetry.on_block_committed(1, 100.0, 1000.0, 0.5, None, None, 100);
        assert!(telemetry.state().last_decision.is_some());

        // Reset
        telemetry.reset();
        assert_eq!(telemetry.state().last_height, 0);
        assert_eq!(telemetry.state().smoothed_annual_fee_revenue, 0.0);
        assert!(telemetry.state().last_decision.is_none());
    }
}