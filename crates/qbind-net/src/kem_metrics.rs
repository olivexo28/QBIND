//! KEM operation metrics for KEMTLS handshake observability.
//!
//! This module provides low-level metrics for tracking KEM (Key Encapsulation Mechanism)
//! operations during KEMTLS handshakes. Metrics track operation counts and latency
//! distributions using simple bucket histograms.
//!
//! # Design
//!
//! - Thread-safe, lock-free (atomics only)
//! - Very small, no dynamic allocation per op
//! - Simple hard-coded bucket scheme
//! - Best-effort recording (never affects handshake behavior)
//!
//! # Latency Buckets
//!
//! For KEM operations (expected ~35-40μs for ML-KEM-768):
//! - `< 0.1ms` (100μs): Very fast operations
//! - `< 1ms`: Normal operations
//! - `< 10ms`: Slow operations
//! - `+Inf`: All operations (cumulative)
//!
//! # Thread Safety
//!
//! All counters use `AtomicU64` with `Ordering::Relaxed` for performance.
//! This is acceptable for observability where exact ordering is not required.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Metrics for KEM operations (encapsulation and decapsulation).
///
/// Tracks total counts and latency distributions for both operation types.
/// This is a global metrics instance that can be shared across multiple
/// handshake instances (assuming a single KEM suite per process).
#[derive(Debug, Default)]
pub struct KemOpMetrics {
    // Total operation counts
    encaps_total: AtomicU64,
    decaps_total: AtomicU64,

    // Encapsulation latency buckets
    encaps_latency_under_0_1ms: AtomicU64,
    encaps_latency_under_1ms: AtomicU64,
    encaps_latency_under_10ms: AtomicU64,
    encaps_latency_inf: AtomicU64,

    // Decapsulation latency buckets
    decaps_latency_under_0_1ms: AtomicU64,
    decaps_latency_under_1ms: AtomicU64,
    decaps_latency_under_10ms: AtomicU64,
    decaps_latency_inf: AtomicU64,
}

impl KemOpMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an encapsulation operation with its duration.
    ///
    /// This method is best-effort and will never panic or affect handshake behavior.
    /// If metrics recording fails (shouldn't happen with atomics), the operation
    /// is silently ignored.
    pub fn record_encaps(&self, duration: Duration) {
        // Convert duration to milliseconds (capping at u64::MAX to prevent overflow)
        let millis = duration.as_millis().min(u64::MAX as u128) as u64;
        let micros = duration.as_micros().min(u64::MAX as u128) as u64;

        // Increment total count
        self.encaps_total.fetch_add(1, Ordering::Relaxed);

        // Update latency buckets (cumulative histogram)
        // +Inf bucket: all operations
        self.encaps_latency_inf.fetch_add(1, Ordering::Relaxed);

        // < 10ms bucket: all operations < 10ms
        if millis < 10 {
            self.encaps_latency_under_10ms
                .fetch_add(1, Ordering::Relaxed);
        }

        // < 1ms bucket: all operations < 1ms
        if millis < 1 {
            self.encaps_latency_under_1ms
                .fetch_add(1, Ordering::Relaxed);
        }

        // < 0.1ms bucket: all operations < 0.1ms (100 microseconds)
        if micros < 100 {
            self.encaps_latency_under_0_1ms
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a decapsulation operation with its duration.
    ///
    /// This method is best-effort and will never panic or affect handshake behavior.
    /// If metrics recording fails (shouldn't happen with atomics), the operation
    /// is silently ignored.
    pub fn record_decaps(&self, duration: Duration) {
        // Convert duration to milliseconds (capping at u64::MAX to prevent overflow)
        let millis = duration.as_millis().min(u64::MAX as u128) as u64;
        let micros = duration.as_micros().min(u64::MAX as u128) as u64;

        // Increment total count
        self.decaps_total.fetch_add(1, Ordering::Relaxed);

        // Update latency buckets (cumulative histogram)
        // +Inf bucket: all operations
        self.decaps_latency_inf.fetch_add(1, Ordering::Relaxed);

        // < 10ms bucket: all operations < 10ms
        if millis < 10 {
            self.decaps_latency_under_10ms
                .fetch_add(1, Ordering::Relaxed);
        }

        // < 1ms bucket: all operations < 1ms
        if millis < 1 {
            self.decaps_latency_under_1ms
                .fetch_add(1, Ordering::Relaxed);
        }

        // < 0.1ms bucket: all operations < 0.1ms (100 microseconds)
        if micros < 100 {
            self.decaps_latency_under_0_1ms
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get total encapsulation count.
    pub fn encaps_total(&self) -> u64 {
        self.encaps_total.load(Ordering::Relaxed)
    }

    /// Get total decapsulation count.
    pub fn decaps_total(&self) -> u64 {
        self.decaps_total.load(Ordering::Relaxed)
    }

    /// Get encapsulation latency buckets.
    ///
    /// Returns (under_0.1ms, under_1ms, under_10ms, inf).
    pub fn encaps_latency_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.encaps_latency_under_0_1ms.load(Ordering::Relaxed),
            self.encaps_latency_under_1ms.load(Ordering::Relaxed),
            self.encaps_latency_under_10ms.load(Ordering::Relaxed),
            self.encaps_latency_inf.load(Ordering::Relaxed),
        )
    }

    /// Get decapsulation latency buckets.
    ///
    /// Returns (under_0.1ms, under_1ms, under_10ms, inf).
    pub fn decaps_latency_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.decaps_latency_under_0_1ms.load(Ordering::Relaxed),
            self.decaps_latency_under_1ms.load(Ordering::Relaxed),
            self.decaps_latency_under_10ms.load(Ordering::Relaxed),
            self.decaps_latency_inf.load(Ordering::Relaxed),
        )
    }

    /// Format metrics for test assertions.
    ///
    /// This produces a simple text format suitable for test assertions.
    /// It does not need to be Prometheus-perfect (Prometheus wiring can be a later task).
    pub fn format_for_tests(&self) -> String {
        let encaps_total = self.encaps_total();
        let decaps_total = self.decaps_total();
        let (encaps_0_1, encaps_1, encaps_10, encaps_inf) = self.encaps_latency_buckets();
        let (decaps_0_1, decaps_1, decaps_10, decaps_inf) = self.decaps_latency_buckets();

        format!(
            "KEM Metrics:\n\
             encaps_total: {}\n\
             decaps_total: {}\n\
             encaps_latency_buckets: <0.1ms={}, <1ms={}, <10ms={}, +Inf={}\n\
             decaps_latency_buckets: <0.1ms={}, <1ms={}, <10ms={}, +Inf={}",
            encaps_total,
            decaps_total,
            encaps_0_1,
            encaps_1,
            encaps_10,
            encaps_inf,
            decaps_0_1,
            decaps_1,
            decaps_10,
            decaps_inf
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_metrics_are_zero() {
        let metrics = KemOpMetrics::new();
        assert_eq!(metrics.encaps_total(), 0);
        assert_eq!(metrics.decaps_total(), 0);
        assert_eq!(metrics.encaps_latency_buckets(), (0, 0, 0, 0));
        assert_eq!(metrics.decaps_latency_buckets(), (0, 0, 0, 0));
    }

    #[test]
    fn test_record_encaps() {
        let metrics = KemOpMetrics::new();
        metrics.record_encaps(Duration::from_micros(50));
        assert_eq!(metrics.encaps_total(), 1);
        let (b0_1, b1, b10, inf) = metrics.encaps_latency_buckets();
        assert_eq!(inf, 1);
        assert_eq!(b10, 1);
        assert_eq!(b1, 1);
        assert_eq!(b0_1, 1); // 50μs < 100μs
    }

    #[test]
    fn test_record_decaps() {
        let metrics = KemOpMetrics::new();
        metrics.record_decaps(Duration::from_millis(5));
        assert_eq!(metrics.decaps_total(), 1);
        let (b0_1, b1, b10, inf) = metrics.decaps_latency_buckets();
        assert_eq!(inf, 1);
        assert_eq!(b10, 1);
        assert_eq!(b1, 0); // 5ms >= 1ms
        assert_eq!(b0_1, 0); // 5ms >= 0.1ms
    }

    #[test]
    fn test_latency_buckets() {
        let metrics = KemOpMetrics::new();

        // Record operations in different buckets
        metrics.record_encaps(Duration::from_micros(50)); // < 0.1ms
        metrics.record_encaps(Duration::from_micros(500)); // < 1ms, >= 0.1ms
        metrics.record_encaps(Duration::from_millis(5)); // < 10ms, >= 1ms
        metrics.record_encaps(Duration::from_millis(50)); // >= 10ms

        assert_eq!(metrics.encaps_total(), 4);
        let (b0_1, b1, b10, inf) = metrics.encaps_latency_buckets();
        assert_eq!(inf, 4); // All operations
        assert_eq!(b10, 3); // 50μs, 500μs, 5ms (all < 10ms)
        assert_eq!(b1, 2); // 50μs, 500μs (all < 1ms)
        assert_eq!(b0_1, 1); // 50μs (all < 0.1ms)
    }

    #[test]
    fn test_format_for_tests() {
        let metrics = KemOpMetrics::new();
        metrics.record_encaps(Duration::from_micros(50));
        metrics.record_decaps(Duration::from_millis(1));
        let formatted = metrics.format_for_tests();
        assert!(formatted.contains("encaps_total: 1"));
        assert!(formatted.contains("decaps_total: 1"));
    }
}
