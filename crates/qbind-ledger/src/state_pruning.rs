//! T208: State pruning and state growth monitoring.
//!
//! This module provides a state pruning trait and statistics for managing
//! blockchain state growth. The pruning mechanism is purely local node
//! behavior and does not affect consensus rules.
//!
//! # Design
//!
//! State pruning removes historical state data below a certain block height,
//! keeping only recent state needed for:
//! - Current state queries
//! - Block verification within the retention window
//! - Re-execution during chain reorganizations
//!
//! # Thread Safety
//!
//! Implementations should be thread-safe. Pruning operations may run in a
//! background task while reads/writes continue on the main execution path.
//!
//! # Metrics
//!
//! `PruneStats` provides telemetry data for monitoring:
//! - `keys_scanned`: Number of keys examined during pruning
//! - `keys_pruned`: Number of keys actually removed
//! - `duration_ms`: Time taken for the pruning operation

use std::time::Duration;

// ============================================================================
// Pruning Statistics
// ============================================================================

/// Statistics from a state pruning operation.
///
/// This struct captures telemetry data from a pruning run, useful for
/// monitoring state growth and pruning efficiency.
///
/// # Example
///
/// ```rust
/// use qbind_ledger::PruneStats;
///
/// let stats = PruneStats {
///     keys_scanned: 10000,
///     keys_pruned: 500,
///     duration_ms: 42,
/// };
///
/// println!(
///     "Pruned {}/{} keys in {}ms",
///     stats.keys_pruned, stats.keys_scanned, stats.duration_ms
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PruneStats {
    /// Number of keys scanned during the pruning operation.
    ///
    /// This includes keys that were examined but not pruned because
    /// they are above the retention height.
    pub keys_scanned: u64,

    /// Number of keys that were actually pruned (deleted).
    pub keys_pruned: u64,

    /// Duration of the pruning operation in milliseconds.
    pub duration_ms: u64,
}

impl PruneStats {
    /// Create a new PruneStats instance.
    pub fn new(keys_scanned: u64, keys_pruned: u64, duration_ms: u64) -> Self {
        Self {
            keys_scanned,
            keys_pruned,
            duration_ms,
        }
    }

    /// Create PruneStats from a duration.
    pub fn from_duration(keys_scanned: u64, keys_pruned: u64, duration: Duration) -> Self {
        Self {
            keys_scanned,
            keys_pruned,
            duration_ms: duration.as_millis() as u64,
        }
    }

    /// Check if any keys were pruned.
    pub fn has_pruned(&self) -> bool {
        self.keys_pruned > 0
    }

    /// Calculate the prune ratio (keys_pruned / keys_scanned).
    ///
    /// Returns 0.0 if no keys were scanned.
    pub fn prune_ratio(&self) -> f64 {
        if self.keys_scanned == 0 {
            0.0
        } else {
            self.keys_pruned as f64 / self.keys_scanned as f64
        }
    }
}

// ============================================================================
// State Pruner Trait
// ============================================================================

/// Trait for state backends that support pruning historical data.
///
/// Implementations prune state data that is no longer needed, based on
/// the specified height threshold. This is purely local node behavior
/// and does not affect consensus.
///
/// # Height-Based Pruning
///
/// For v1, pruning is height-based: all state entries associated with
/// block heights below `prune_below_height` may be removed. The exact
/// semantics depend on the storage layout:
///
/// - **Account state**: Current account state is always retained; only
///   historical snapshots below the threshold are pruned.
/// - **Block data**: Block headers/bodies below the threshold may be pruned.
/// - **Transaction receipts**: Receipts below the threshold may be pruned.
///
/// # Thread Safety
///
/// Implementations should be safe to call from a background task while
/// the main execution path continues to read/write the state.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_ledger::{RocksDbAccountState, StatePruner};
/// use std::path::Path;
///
/// let mut storage = RocksDbAccountState::open(Path::new("/data/state"))?;
///
/// // Prune all state below height 100_000
/// let stats = storage.prune_below(100_000)?;
/// println!("Pruned {} keys in {}ms", stats.keys_pruned, stats.duration_ms);
/// ```
pub trait StatePruner {
    /// Error type returned by pruning operations.
    type Error;

    /// Prune state data below the specified block height.
    ///
    /// Removes historical state entries associated with block heights
    /// strictly below `prune_below_height`. Returns statistics about
    /// the pruning operation.
    ///
    /// # Arguments
    ///
    /// * `prune_below_height` - Block height threshold. State entries
    ///   associated with heights < this value may be pruned.
    ///
    /// # Returns
    ///
    /// `Ok(PruneStats)` with statistics about the pruning operation.
    /// `Err(Self::Error)` if pruning fails.
    ///
    /// # Notes
    ///
    /// - Current account state is never pruned (only historical snapshots).
    /// - Pruning is best-effort: some storage backends may not support
    ///   fine-grained height-based pruning.
    fn prune_below(&mut self, prune_below_height: u64) -> Result<PruneStats, Self::Error>;

    /// Get the estimated state size in bytes.
    ///
    /// Returns an approximate size of the state storage, useful for
    /// monitoring state growth over time.
    ///
    /// # Returns
    ///
    /// `Ok(u64)` with the estimated size in bytes.
    /// `Err(Self::Error)` if the size cannot be determined.
    fn estimated_size_bytes(&self) -> Result<u64, Self::Error>;
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prune_stats_new() {
        let stats = PruneStats::new(100, 25, 42);
        assert_eq!(stats.keys_scanned, 100);
        assert_eq!(stats.keys_pruned, 25);
        assert_eq!(stats.duration_ms, 42);
    }

    #[test]
    fn test_prune_stats_from_duration() {
        let duration = Duration::from_millis(123);
        let stats = PruneStats::from_duration(50, 10, duration);
        assert_eq!(stats.keys_scanned, 50);
        assert_eq!(stats.keys_pruned, 10);
        assert_eq!(stats.duration_ms, 123);
    }

    #[test]
    fn test_prune_stats_has_pruned() {
        let stats_with = PruneStats::new(100, 1, 10);
        assert!(stats_with.has_pruned());

        let stats_without = PruneStats::new(100, 0, 10);
        assert!(!stats_without.has_pruned());
    }

    #[test]
    fn test_prune_stats_prune_ratio() {
        let stats = PruneStats::new(100, 25, 10);
        assert!((stats.prune_ratio() - 0.25).abs() < 0.001);

        // Edge case: no keys scanned
        let stats_empty = PruneStats::new(0, 0, 10);
        assert!((stats_empty.prune_ratio() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_prune_stats_default() {
        let stats = PruneStats::default();
        assert_eq!(stats.keys_scanned, 0);
        assert_eq!(stats.keys_pruned, 0);
        assert_eq!(stats.duration_ms, 0);
    }
}
