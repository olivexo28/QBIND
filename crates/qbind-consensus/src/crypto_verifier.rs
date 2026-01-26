//! Crypto-backed consensus verification.
//!
//! This module provides `CryptoConsensusVerifier`, a `ConsensusVerifier` implementation
//! that uses a `ValidatorKeyProvider` to look up public keys and a `ConsensusSigVerifier`
//! backend to verify signatures.
//!
//! # Design
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │                    CryptoConsensusVerifier                    │
//! │  ┌──────────────────────┐   ┌────────────────────────────────┐│
//! │  │ ValidatorKeyProvider │   │ Arc<dyn ConsensusSigVerifier>  ││
//! │  │   (ValidatorId →     │   │   (Verify signatures)          ││
//! │  │    raw key bytes)    │   └────────────────────────────────┘│
//! │  └──────────────────────┘                                     │
//! └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Multi-Suite Support
//!
//! For cryptographic agility, the module also provides:
//! - `ConsensusSigBackendRegistry`: trait for mapping suite IDs to verifier backends
//! - `SimpleBackendRegistry`: simple HashMap-based registry implementation
//! - `MultiSuiteCryptoVerifier`: verifier with per-suite backend dispatch
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                      MultiSuiteCryptoVerifier                           │
//! │  ┌────────────────────────────────┐  ┌────────────────────────────────┐│
//! │  │ SuiteAwareValidatorKeyProvider │  │ ConsensusSigBackendRegistry    ││
//! │  │   (ValidatorId →               │  │   (suite_id → backend)         ││
//! │  │    (suite_id, pk_bytes))       │  └────────────────────────────────┘│
//! │  └────────────────────────────────┘                                    │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Observability
//!
//! The verifier tracks metrics for signature verification outcomes:
//! - `consensus_sig_verification_total{kind="vote|proposal", result="ok|missing_key|invalid_signature|other"}`
//!
//! These metrics are exposed via the `ConsensusSigMetrics` struct and can be
//! accessed through the `metrics()` method on `CryptoConsensusVerifier`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::ConsensusSigSuiteId;
use qbind_wire::consensus::{BlockProposal, Vote};

use crate::ids::ValidatorId;
use crate::key_registry::{
    SuiteAwareValidatorKeyProvider, ValidatorKeyProvider, ValidatorKeyRegistry,
};
use crate::verify::{ConsensusVerifier, VerificationError};

// ============================================================================
// Backend Registry
// ============================================================================

/// Trait for mapping signature suite IDs to their verifier backends.
///
/// This trait enables per-suite verifier dispatch, allowing the system to support
/// multiple signature algorithms simultaneously.
///
/// # Design Notes
///
/// - Implementations should be thread-safe (`Send + Sync`).
/// - Returns `None` if no backend is registered for the given suite ID.
/// - The returned backend is wrapped in `Arc` for shared ownership.
pub trait ConsensusSigBackendRegistry: Send + Sync {
    /// Get the verifier backend for a given signature suite.
    ///
    /// Returns `Some(backend)` if a verifier is registered for this suite,
    /// or `None` if the suite is not supported.
    fn get_backend(&self, suite: ConsensusSigSuiteId) -> Option<Arc<dyn ConsensusSigVerifier>>;
}

/// A simple HashMap-based backend registry.
///
/// This implementation stores a mapping from suite IDs to their corresponding
/// verifier backends. It is suitable for static configurations where the set
/// of supported suites is known at initialization time.
#[derive(Clone)]
pub struct SimpleBackendRegistry {
    backends: HashMap<ConsensusSigSuiteId, Arc<dyn ConsensusSigVerifier>>,
}

impl SimpleBackendRegistry {
    /// Create a new empty backend registry.
    pub fn new() -> Self {
        SimpleBackendRegistry {
            backends: HashMap::new(),
        }
    }

    /// Register a verifier backend for a signature suite.
    ///
    /// If a backend was already registered for this suite, the old backend
    /// is replaced and returned.
    pub fn register(
        &mut self,
        suite: ConsensusSigSuiteId,
        backend: Arc<dyn ConsensusSigVerifier>,
    ) -> Option<Arc<dyn ConsensusSigVerifier>> {
        self.backends.insert(suite, backend)
    }

    /// Create a registry with a single backend.
    ///
    /// This is a convenience method for simple configurations.
    pub fn with_backend(
        suite: ConsensusSigSuiteId,
        backend: Arc<dyn ConsensusSigVerifier>,
    ) -> Self {
        let mut registry = Self::new();
        registry.register(suite, backend);
        registry
    }
}

impl Default for SimpleBackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SimpleBackendRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleBackendRegistry")
            .field("suites", &self.backends.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ConsensusSigBackendRegistry for SimpleBackendRegistry {
    fn get_backend(&self, suite: ConsensusSigSuiteId) -> Option<Arc<dyn ConsensusSigVerifier>> {
        self.backends.get(&suite).cloned()
    }
}

// ============================================================================
// Metrics
// ============================================================================

// ============================================================================
// Per-Suite Metrics (T120)
// ============================================================================

/// Maximum number of suites tracked individually in per-suite metrics.
///
/// This bounds the memory usage of per-suite metrics. Suites beyond this limit
/// are not individually tracked (but aggregate metrics still work).
pub const MAX_PER_SUITE_SLOTS: usize = 8;

/// Sentinel value indicating an uninitialized per-suite slot.
/// We use u64::MAX because valid suite IDs are u16 (0..65535).
const SUITE_SLOT_UNINITIALIZED: u64 = u64::MAX;

/// Per-suite metrics counters for a single suite ID.
///
/// Tracks vote/proposal verification counts and latency buckets per suite.
/// Uses atomic counters for lock-free concurrent access.
#[derive(Debug)]
pub struct PerSuiteMetrics {
    /// The suite ID this slot tracks (SUITE_SLOT_UNINITIALIZED means uninitialized).
    suite_id: AtomicU64,
    /// Vote verification count for this suite.
    vote_count: AtomicU64,
    /// Proposal verification count for this suite.
    proposal_count: AtomicU64,
    /// Latency bucket: < 1ms.
    latency_under_1ms: AtomicU64,
    /// Latency bucket: 1ms - 10ms.
    latency_1ms_to_10ms: AtomicU64,
    /// Latency bucket: 10ms - 100ms.
    latency_10ms_to_100ms: AtomicU64,
    /// Latency bucket: > 100ms.
    latency_over_100ms: AtomicU64,
}

impl Default for PerSuiteMetrics {
    fn default() -> Self {
        PerSuiteMetrics {
            suite_id: AtomicU64::new(SUITE_SLOT_UNINITIALIZED),
            vote_count: AtomicU64::new(0),
            proposal_count: AtomicU64::new(0),
            latency_under_1ms: AtomicU64::new(0),
            latency_1ms_to_10ms: AtomicU64::new(0),
            latency_10ms_to_100ms: AtomicU64::new(0),
            latency_over_100ms: AtomicU64::new(0),
        }
    }
}

impl PerSuiteMetrics {
    /// Create a new per-suite metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the suite ID for this slot, or None if uninitialized.
    pub fn suite_id(&self) -> Option<u16> {
        let val = self.suite_id.load(Ordering::Relaxed);
        if val == SUITE_SLOT_UNINITIALIZED {
            None
        } else {
            Some(val as u16)
        }
    }

    /// Check if this slot is initialized.
    pub fn is_initialized(&self) -> bool {
        self.suite_id.load(Ordering::Relaxed) != SUITE_SLOT_UNINITIALIZED
    }

    /// Get the vote verification count.
    pub fn vote_count(&self) -> u64 {
        self.vote_count.load(Ordering::Relaxed)
    }

    /// Get the proposal verification count.
    pub fn proposal_count(&self) -> u64 {
        self.proposal_count.load(Ordering::Relaxed)
    }

    /// Get latency bucket counts as (under_1ms, 1ms_to_10ms, 10ms_to_100ms, over_100ms).
    pub fn latency_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.latency_under_1ms.load(Ordering::Relaxed),
            self.latency_1ms_to_10ms.load(Ordering::Relaxed),
            self.latency_10ms_to_100ms.load(Ordering::Relaxed),
            self.latency_over_100ms.load(Ordering::Relaxed),
        )
    }
}

/// Metrics for consensus signature verification.
///
/// This struct tracks counters for signature verification outcomes, split by
/// message kind (vote vs proposal) and result (ok, missing_key, invalid_signature, suite_mismatch, other).
///
/// # Per-Suite Metrics (T120)
///
/// In addition to aggregate counters, this struct tracks per-suite metrics:
/// - `qbind_consensus_sig_verifications_total{kind="vote",suite="<name>"}`
/// - `qbind_consensus_sig_verifications_total{kind="proposal",suite="<name>"}`
/// - `qbind_consensus_sig_verify_duration_ms_bucket{suite="<name>",le="<threshold>"}`
///
/// Per-suite metrics use a fixed-size array of slots to bound memory usage.
/// The first `MAX_PER_SUITE_SLOTS` suites encountered are tracked individually.
///
/// All counters use relaxed ordering for performance in hot paths.
#[derive(Debug)]
pub struct ConsensusSigMetrics {
    // Vote verification counters
    vote_ok: AtomicU64,
    vote_missing_key: AtomicU64,
    vote_invalid_signature: AtomicU64,
    vote_suite_mismatch: AtomicU64,
    vote_other: AtomicU64,

    // Proposal verification counters
    proposal_ok: AtomicU64,
    proposal_missing_key: AtomicU64,
    proposal_invalid_signature: AtomicU64,
    proposal_suite_mismatch: AtomicU64,
    proposal_other: AtomicU64,

    // Per-suite metrics (T120)
    // Using a fixed-size array to avoid unbounded HashMap growth.
    // Slots are claimed lazily via compare_exchange on suite_id.
    per_suite_slots: [PerSuiteMetrics; MAX_PER_SUITE_SLOTS],
    /// Number of slots currently in use.
    per_suite_slot_count: AtomicU64,
}

// Manual `Default` implementation is required because `PerSuiteMetrics` uses a
// non-zero sentinel value (SUITE_SLOT_UNINITIALIZED = u64::MAX) to indicate
// empty slots. The derive macro would initialize slots with 0, which would
// conflict with suite ID 0 (SUITE_TOY_SHA3).
impl Default for ConsensusSigMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusSigMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        ConsensusSigMetrics {
            vote_ok: AtomicU64::new(0),
            vote_missing_key: AtomicU64::new(0),
            vote_invalid_signature: AtomicU64::new(0),
            vote_suite_mismatch: AtomicU64::new(0),
            vote_other: AtomicU64::new(0),
            proposal_ok: AtomicU64::new(0),
            proposal_missing_key: AtomicU64::new(0),
            proposal_invalid_signature: AtomicU64::new(0),
            proposal_suite_mismatch: AtomicU64::new(0),
            proposal_other: AtomicU64::new(0),
            per_suite_slots: Default::default(),
            per_suite_slot_count: AtomicU64::new(0),
        }
    }

    /// Get the count of successful vote verifications.
    pub fn vote_ok(&self) -> u64 {
        self.vote_ok.load(Ordering::Relaxed)
    }

    /// Get the count of vote verifications that failed due to missing key.
    pub fn vote_missing_key(&self) -> u64 {
        self.vote_missing_key.load(Ordering::Relaxed)
    }

    /// Get the count of vote verifications that failed due to invalid signature.
    pub fn vote_invalid_signature(&self) -> u64 {
        self.vote_invalid_signature.load(Ordering::Relaxed)
    }

    /// Get the count of vote verifications that failed due to suite mismatch.
    pub fn vote_suite_mismatch(&self) -> u64 {
        self.vote_suite_mismatch.load(Ordering::Relaxed)
    }

    /// Get the count of vote verifications that failed due to other errors.
    pub fn vote_other(&self) -> u64 {
        self.vote_other.load(Ordering::Relaxed)
    }

    /// Get the count of successful proposal verifications.
    pub fn proposal_ok(&self) -> u64 {
        self.proposal_ok.load(Ordering::Relaxed)
    }

    /// Get the count of proposal verifications that failed due to missing key.
    pub fn proposal_missing_key(&self) -> u64 {
        self.proposal_missing_key.load(Ordering::Relaxed)
    }

    /// Get the count of proposal verifications that failed due to invalid signature.
    pub fn proposal_invalid_signature(&self) -> u64 {
        self.proposal_invalid_signature.load(Ordering::Relaxed)
    }

    /// Get the count of proposal verifications that failed due to suite mismatch.
    pub fn proposal_suite_mismatch(&self) -> u64 {
        self.proposal_suite_mismatch.load(Ordering::Relaxed)
    }

    /// Get the count of proposal verifications that failed due to other errors.
    pub fn proposal_other(&self) -> u64 {
        self.proposal_other.load(Ordering::Relaxed)
    }

    // ========================================================================
    // Per-Suite Metrics (T120)
    // ========================================================================

    /// Find or allocate a per-suite slot for the given suite ID.
    ///
    /// Returns `Some(index)` if a slot is found or allocated, `None` if all
    /// slots are full and the suite is not already tracked.
    fn find_or_allocate_suite_slot(&self, suite_id: ConsensusSigSuiteId) -> Option<usize> {
        let suite_id_u64 = suite_id.as_u16() as u64;

        // First, look for an existing slot
        for i in 0..MAX_PER_SUITE_SLOTS {
            let slot_suite = self.per_suite_slots[i].suite_id.load(Ordering::Relaxed);
            if slot_suite == suite_id_u64 {
                return Some(i);
            }
        }

        // Try to allocate a new slot
        let current_count = self.per_suite_slot_count.load(Ordering::Relaxed) as usize;
        if current_count >= MAX_PER_SUITE_SLOTS {
            return None;
        }

        // Try to claim a slot via compare_exchange
        for i in 0..MAX_PER_SUITE_SLOTS {
            let result = self.per_suite_slots[i].suite_id.compare_exchange(
                SUITE_SLOT_UNINITIALIZED,
                suite_id_u64,
                Ordering::SeqCst,
                Ordering::Relaxed,
            );

            match result {
                Ok(_) => {
                    // Successfully claimed this slot
                    self.per_suite_slot_count.fetch_add(1, Ordering::Relaxed);
                    return Some(i);
                }
                Err(current) if current == suite_id_u64 => {
                    // Another thread already claimed this slot for the same suite
                    return Some(i);
                }
                Err(_) => {
                    // Slot was claimed by a different suite; continue searching
                }
            }
            // Slot was claimed by a different suite; continue searching
        }

        None
    }

    /// Record a per-suite vote verification.
    ///
    /// This increments the vote count for the specified suite.
    pub fn record_per_suite_vote(&self, suite_id: ConsensusSigSuiteId) {
        if let Some(idx) = self.find_or_allocate_suite_slot(suite_id) {
            self.per_suite_slots[idx]
                .vote_count
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a per-suite proposal verification.
    ///
    /// This increments the proposal count for the specified suite.
    pub fn record_per_suite_proposal(&self, suite_id: ConsensusSigSuiteId) {
        if let Some(idx) = self.find_or_allocate_suite_slot(suite_id) {
            self.per_suite_slots[idx]
                .proposal_count
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a per-suite verification latency.
    ///
    /// This increments the appropriate latency bucket for the specified suite.
    pub fn record_per_suite_latency(
        &self,
        suite_id: ConsensusSigSuiteId,
        duration: std::time::Duration,
    ) {
        if let Some(idx) = self.find_or_allocate_suite_slot(suite_id) {
            let millis = duration.as_millis();
            let slot = &self.per_suite_slots[idx];
            if millis < 1 {
                slot.latency_under_1ms.fetch_add(1, Ordering::Relaxed);
            } else if millis < 10 {
                slot.latency_1ms_to_10ms.fetch_add(1, Ordering::Relaxed);
            } else if millis < 100 {
                slot.latency_10ms_to_100ms.fetch_add(1, Ordering::Relaxed);
            } else {
                slot.latency_over_100ms.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get per-suite metrics for a specific suite ID.
    ///
    /// Returns `Some((vote_count, proposal_count, latency_buckets))` if the suite
    /// is tracked, `None` otherwise.
    #[allow(clippy::type_complexity)]
    pub fn per_suite_metrics(
        &self,
        suite_id: ConsensusSigSuiteId,
    ) -> Option<(u64, u64, (u64, u64, u64, u64))> {
        let suite_id_u64 = suite_id.as_u16() as u64;

        for i in 0..MAX_PER_SUITE_SLOTS {
            let slot_suite = self.per_suite_slots[i].suite_id.load(Ordering::Relaxed);
            if slot_suite == suite_id_u64 {
                return Some((
                    self.per_suite_slots[i].vote_count.load(Ordering::Relaxed),
                    self.per_suite_slots[i]
                        .proposal_count
                        .load(Ordering::Relaxed),
                    self.per_suite_slots[i].latency_buckets(),
                ));
            }
        }

        None
    }

    /// Get all tracked per-suite metrics.
    ///
    /// Returns a vector of (suite_id, vote_count, proposal_count, latency_buckets).
    #[allow(clippy::type_complexity)]
    pub fn all_per_suite_metrics(
        &self,
    ) -> Vec<(ConsensusSigSuiteId, u64, u64, (u64, u64, u64, u64))> {
        let mut result = Vec::new();

        for i in 0..MAX_PER_SUITE_SLOTS {
            let slot_suite = self.per_suite_slots[i].suite_id.load(Ordering::Relaxed);
            if slot_suite != SUITE_SLOT_UNINITIALIZED {
                result.push((
                    ConsensusSigSuiteId::new(slot_suite as u16),
                    self.per_suite_slots[i].vote_count.load(Ordering::Relaxed),
                    self.per_suite_slots[i]
                        .proposal_count
                        .load(Ordering::Relaxed),
                    self.per_suite_slots[i].latency_buckets(),
                ));
            }
        }

        result
    }

    /// Format per-suite metrics as Prometheus-style output.
    ///
    /// This is intended for integration with NodeMetrics::format_metrics().
    pub fn format_per_suite_metrics(&self) -> String {
        let mut output = String::new();

        for (suite_id, vote_count, proposal_count, (under_1ms, to_10ms, to_100ms, over_100ms)) in
            self.all_per_suite_metrics()
        {
            // Get suite name from catalog if available
            let suite_name = qbind_crypto::suite_name(suite_id);

            // Vote/proposal counts
            output.push_str(&format!(
                "qbind_consensus_sig_verifications_total{{kind=\"vote\",suite=\"{}\"}} {}\n",
                suite_name, vote_count
            ));
            output.push_str(&format!(
                "qbind_consensus_sig_verifications_total{{kind=\"proposal\",suite=\"{}\"}} {}\n",
                suite_name, proposal_count
            ));

            // Latency histogram buckets (cumulative)
            let total_latency_count = under_1ms + to_10ms + to_100ms + over_100ms;
            if total_latency_count > 0 {
                output.push_str(&format!(
                    "qbind_consensus_sig_verify_duration_ms_bucket{{suite=\"{}\",le=\"1\"}} {}\n",
                    suite_name, under_1ms
                ));
                output.push_str(&format!(
                    "qbind_consensus_sig_verify_duration_ms_bucket{{suite=\"{}\",le=\"10\"}} {}\n",
                    suite_name,
                    under_1ms + to_10ms
                ));
                output.push_str(&format!(
                    "qbind_consensus_sig_verify_duration_ms_bucket{{suite=\"{}\",le=\"100\"}} {}\n",
                    suite_name,
                    under_1ms + to_10ms + to_100ms
                ));
                output.push_str(&format!(
                    "qbind_consensus_sig_verify_duration_ms_bucket{{suite=\"{}\",le=\"+Inf\"}} {}\n",
                    suite_name, total_latency_count
                ));
                output.push_str(&format!(
                    "qbind_consensus_sig_verify_duration_ms_count{{suite=\"{}\"}} {}\n",
                    suite_name, total_latency_count
                ));
            }
        }

        output
    }

    // Internal increment methods

    fn inc_vote_ok(&self) {
        self.vote_ok.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_vote_missing_key(&self) {
        self.vote_missing_key.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_vote_invalid_signature(&self) {
        self.vote_invalid_signature.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_vote_suite_mismatch(&self) {
        self.vote_suite_mismatch.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_vote_other(&self) {
        self.vote_other.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_proposal_ok(&self) {
        self.proposal_ok.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_proposal_missing_key(&self) {
        self.proposal_missing_key.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_proposal_invalid_signature(&self) {
        self.proposal_invalid_signature
            .fetch_add(1, Ordering::Relaxed);
    }

    fn inc_proposal_suite_mismatch(&self) {
        self.proposal_suite_mismatch.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_proposal_other(&self) {
        self.proposal_other.fetch_add(1, Ordering::Relaxed);
    }
}

/// Verification result category for metrics tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationResult {
    Ok,
    MissingKey,
    InvalidSignature,
    SuiteMismatch,
    Other,
}

impl From<&VerificationError> for VerificationResult {
    fn from(err: &VerificationError) -> Self {
        match err {
            VerificationError::MissingKey(_) => VerificationResult::MissingKey,
            VerificationError::InvalidSignature => VerificationResult::InvalidSignature,
            VerificationError::SuiteMismatch { .. } => VerificationResult::SuiteMismatch,
            VerificationError::QcSuiteMismatch { .. } => VerificationResult::SuiteMismatch,
            VerificationError::Other(_) => VerificationResult::Other,
        }
    }
}

/// Message kind for metrics tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    Vote,
    Proposal,
}

// ============================================================================
// SingleSuiteKeyProviderAdapter
// ============================================================================

/// An adapter that wraps a `ValidatorKeyProvider` to implement `SuiteAwareValidatorKeyProvider`.
///
/// This adapter always returns `SUITE_TOY_SHA3` as the suite ID, making it suitable
/// for backwards compatibility when using `CryptoConsensusVerifier` with single-backend
/// configurations.
///
/// # Design
///
/// ```text
/// ValidatorKeyProvider → SingleSuiteKeyProviderAdapter → SuiteAwareValidatorKeyProvider
///       (pk_bytes)            (adds SUITE_TOY_SHA3)        (suite_id, pk_bytes)
/// ```
pub struct SingleSuiteKeyProviderAdapter {
    inner: Arc<dyn ValidatorKeyProvider>,
    suite_id: ConsensusSigSuiteId,
}

impl SingleSuiteKeyProviderAdapter {
    /// Create a new adapter wrapping the given key provider.
    ///
    /// The adapter will return the specified `suite_id` for all validators.
    pub fn new(inner: Arc<dyn ValidatorKeyProvider>, suite_id: ConsensusSigSuiteId) -> Self {
        SingleSuiteKeyProviderAdapter { inner, suite_id }
    }

    /// Create a new adapter using `SUITE_TOY_SHA3` as the suite ID.
    ///
    /// This is the most common configuration for backwards compatibility.
    pub fn with_toy_sha3(inner: Arc<dyn ValidatorKeyProvider>) -> Self {
        Self::new(inner, qbind_crypto::SUITE_TOY_SHA3)
    }
}

impl std::fmt::Debug for SingleSuiteKeyProviderAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleSuiteKeyProviderAdapter")
            .field("inner", &self.inner)
            .field("suite_id", &self.suite_id)
            .finish()
    }
}

impl SuiteAwareValidatorKeyProvider for SingleSuiteKeyProviderAdapter {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.inner.get_key(id).map(|pk| (self.suite_id, pk))
    }
}

// ============================================================================
// CryptoConsensusVerifier (single-backend, backwards-compatible)
// ============================================================================

/// A `ConsensusVerifier` that uses a `ValidatorKeyProvider` plus a
/// `ConsensusSigVerifier` implementation from `qbind-crypto`.
///
/// This struct bridges the typed world of `qbind-consensus` (with `ValidatorId`,
/// key providers) with the algorithm-agnostic `ConsensusSigVerifier` trait
/// in `qbind-crypto`.
///
/// The key provider can be:
/// - A simple `ValidatorKeyRegistry` (in-memory HashMap)
/// - A `GovernedValidatorKeyRegistry` (governance-backed)
/// - Any other `ValidatorKeyProvider` implementation
///
/// # Observability
///
/// The verifier tracks metrics for all verification attempts via `ConsensusSigMetrics`.
/// Access metrics via the `metrics()` method.
///
/// # Implementation
///
/// Internally, `CryptoConsensusVerifier` delegates to `MultiSuiteCryptoVerifier`
/// with a single-suite configuration. This ensures that the multi-suite verification
/// path is always used, providing a consistent code path for all verification.
///
/// For explicit multi-suite support with per-suite backend dispatch, use
/// `MultiSuiteCryptoVerifier` directly.
pub struct CryptoConsensusVerifier {
    /// The inner multi-suite verifier that does the actual work.
    inner: MultiSuiteCryptoVerifier,
}

impl std::fmt::Debug for CryptoConsensusVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoConsensusVerifier")
            .field("inner", &self.inner)
            .finish()
    }
}

impl CryptoConsensusVerifier {
    /// Create a new `CryptoConsensusVerifier` with a concrete `ValidatorKeyRegistry`.
    ///
    /// This is a convenience method for backwards compatibility.
    ///
    /// # Arguments
    ///
    /// * `registry` - The validator key registry for looking up public keys.
    /// * `backend` - The signature verification backend.
    ///
    /// # Implementation Note
    ///
    /// This method wraps the registry in a `SingleSuiteKeyProviderAdapter` with
    /// `SUITE_TOY_SHA3` as the suite ID, and creates a `SimpleBackendRegistry`
    /// with the provided backend registered under `SUITE_TOY_SHA3`.
    pub fn new(registry: ValidatorKeyRegistry, backend: Arc<dyn ConsensusSigVerifier>) -> Self {
        Self::with_key_provider(Arc::new(registry), backend)
    }

    /// Create a new `CryptoConsensusVerifier` with any `ValidatorKeyProvider`.
    ///
    /// This method allows using governance-backed registries or other custom
    /// key providers.
    ///
    /// # Arguments
    ///
    /// * `registry` - The key provider for looking up public keys.
    /// * `backend` - The signature verification backend.
    ///
    /// # Implementation Note
    ///
    /// This method wraps the registry in a `SingleSuiteKeyProviderAdapter` with
    /// `SUITE_TOY_SHA3` as the suite ID, and creates a `SimpleBackendRegistry`
    /// with the provided backend registered under `SUITE_TOY_SHA3`.
    pub fn with_key_provider(
        registry: Arc<dyn ValidatorKeyProvider>,
        backend: Arc<dyn ConsensusSigVerifier>,
    ) -> Self {
        // Wrap the key provider in a SingleSuiteKeyProviderAdapter
        let suite_aware_provider: Arc<dyn SuiteAwareValidatorKeyProvider> =
            Arc::new(SingleSuiteKeyProviderAdapter::with_toy_sha3(registry));

        // Create a backend registry with the single backend
        let backend_registry =
            SimpleBackendRegistry::with_backend(qbind_crypto::SUITE_TOY_SHA3, backend);

        // Create the inner MultiSuiteCryptoVerifier
        let inner = MultiSuiteCryptoVerifier::new(suite_aware_provider, Arc::new(backend_registry));

        CryptoConsensusVerifier { inner }
    }

    /// Get a reference to the metrics for this verifier.
    ///
    /// This allows external code to inspect verification statistics.
    pub fn metrics(&self) -> &ConsensusSigMetrics {
        self.inner.metrics()
    }
}

/// Map a `ConsensusSigError` to a `VerificationError`.
fn map_sig_error(err: ConsensusSigError) -> VerificationError {
    match err {
        ConsensusSigError::MissingKey(id) => VerificationError::MissingKey(ValidatorId::new(id)),
        ConsensusSigError::MalformedSignature | ConsensusSigError::InvalidSignature => {
            VerificationError::InvalidSignature
        }
        ConsensusSigError::Other(msg) => VerificationError::Other(msg),
    }
}

/// Record a verification result in metrics and optionally log failures.
///
/// This function:
/// - Increments the appropriate metric counter
/// - Logs failures at debug level with structured fields (validator_id, kind, result, suite_id)
/// - Does NOT log sensitive data (keys, signatures, preimages)
fn record_verification_result(
    metrics: &ConsensusSigMetrics,
    validator_id: ValidatorId,
    kind: MessageKind,
    result: VerificationResult,
    suite_id: Option<ConsensusSigSuiteId>,
) {
    // Increment appropriate metric counter
    match (kind, result) {
        (MessageKind::Vote, VerificationResult::Ok) => metrics.inc_vote_ok(),
        (MessageKind::Vote, VerificationResult::MissingKey) => metrics.inc_vote_missing_key(),
        (MessageKind::Vote, VerificationResult::InvalidSignature) => {
            metrics.inc_vote_invalid_signature()
        }
        (MessageKind::Vote, VerificationResult::SuiteMismatch) => metrics.inc_vote_suite_mismatch(),
        (MessageKind::Vote, VerificationResult::Other) => metrics.inc_vote_other(),
        (MessageKind::Proposal, VerificationResult::Ok) => metrics.inc_proposal_ok(),
        (MessageKind::Proposal, VerificationResult::MissingKey) => {
            metrics.inc_proposal_missing_key()
        }
        (MessageKind::Proposal, VerificationResult::InvalidSignature) => {
            metrics.inc_proposal_invalid_signature()
        }
        (MessageKind::Proposal, VerificationResult::SuiteMismatch) => {
            metrics.inc_proposal_suite_mismatch()
        }
        (MessageKind::Proposal, VerificationResult::Other) => metrics.inc_proposal_other(),
    }

    // Log failures at debug level (only on failure to keep hot path lightweight).
    // Note: We intentionally do NOT log keys, signatures, or preimages.
    //
    // Design note: This codebase does not have an established tracing/logging framework.
    // We use eprintln! only in debug builds to aid development and testing.
    // When a proper logging framework is adopted (e.g., `tracing`), this should be
    // replaced with `tracing::debug!` or similar.
    #[cfg(debug_assertions)]
    if result != VerificationResult::Ok {
        let kind_str = match kind {
            MessageKind::Vote => "vote",
            MessageKind::Proposal => "proposal",
        };
        let result_str = match result {
            VerificationResult::Ok => "ok",
            VerificationResult::MissingKey => "missing_key",
            VerificationResult::InvalidSignature => "invalid_signature",
            VerificationResult::SuiteMismatch => "suite_mismatch",
            VerificationResult::Other => "other",
        };
        if let Some(suite) = suite_id {
            eprintln!(
                "[consensus_sig] verification failed: validator_id={}, kind={}, result={}, suite_id={}",
                validator_id.as_u64(),
                kind_str,
                result_str,
                suite
            );
        } else {
            eprintln!(
                "[consensus_sig] verification failed: validator_id={}, kind={}, result={}",
                validator_id.as_u64(),
                kind_str,
                result_str
            );
        }
    }
    // Suppress unused variable warnings in release builds
    #[cfg(not(debug_assertions))]
    {
        let _ = validator_id;
        let _ = suite_id;
    }
}

impl ConsensusVerifier for CryptoConsensusVerifier {
    fn verify_vote(&self, from: ValidatorId, vote: &Vote) -> Result<(), VerificationError> {
        // Delegate to the inner MultiSuiteCryptoVerifier
        self.inner.verify_vote(from, vote)
    }

    fn verify_proposal(
        &self,
        from: ValidatorId,
        proposal: &BlockProposal,
    ) -> Result<(), VerificationError> {
        // Delegate to the inner MultiSuiteCryptoVerifier
        self.inner.verify_proposal(from, proposal)
    }
}

// ============================================================================
// MultiSuiteCryptoVerifier (multi-backend, suite-aware)
// ============================================================================

/// A `ConsensusVerifier` with per-suite backend dispatch.
///
/// This verifier uses a `SuiteAwareValidatorKeyProvider` to obtain both the
/// signature suite ID and public key for each validator, then dispatches
/// verification to the appropriate backend from a `ConsensusSigBackendRegistry`.
///
/// # Design
///
/// 1. Look up `(suite_id, pk_bytes)` for the validator
/// 2. Look up the verifier backend for `suite_id`
/// 3. Call the backend's verify method
///
/// # Error Handling
///
/// - No key configured → `VerificationError::MissingKey`
/// - No backend for suite → `VerificationError::Other("unsupported consensus signature suite")`
/// - Verification failed → `VerificationError::InvalidSignature`
pub struct MultiSuiteCryptoVerifier {
    key_provider: Arc<dyn SuiteAwareValidatorKeyProvider>,
    backend_registry: Arc<dyn ConsensusSigBackendRegistry>,
    metrics: Arc<ConsensusSigMetrics>,
}

impl MultiSuiteCryptoVerifier {
    /// Create a new multi-suite crypto verifier.
    ///
    /// # Arguments
    ///
    /// * `key_provider` - Provider for looking up (suite_id, pk_bytes) per validator.
    /// * `backend_registry` - Registry mapping suite IDs to verifier backends.
    pub fn new(
        key_provider: Arc<dyn SuiteAwareValidatorKeyProvider>,
        backend_registry: Arc<dyn ConsensusSigBackendRegistry>,
    ) -> Self {
        MultiSuiteCryptoVerifier {
            key_provider,
            backend_registry,
            metrics: Arc::new(ConsensusSigMetrics::new()),
        }
    }

    /// Get a reference to the metrics for this verifier.
    pub fn metrics(&self) -> &ConsensusSigMetrics {
        &self.metrics
    }

    /// Look up the suite ID and public key for a validator.
    fn suite_and_key_for(
        &self,
        validator: ValidatorId,
    ) -> Result<(ConsensusSigSuiteId, Vec<u8>), VerificationError> {
        self.key_provider
            .get_suite_and_key(validator)
            .ok_or(VerificationError::MissingKey(validator))
    }

    /// Get the verifier backend for a suite ID.
    fn backend_for(
        &self,
        suite_id: ConsensusSigSuiteId,
    ) -> Result<Arc<dyn ConsensusSigVerifier>, VerificationError> {
        self.backend_registry.get_backend(suite_id).ok_or_else(|| {
            VerificationError::Other(format!(
                "unsupported consensus signature suite: {}",
                suite_id
            ))
        })
    }

    /// Record a verification result in metrics.
    fn record_result(
        &self,
        validator_id: ValidatorId,
        kind: MessageKind,
        result: VerificationResult,
        suite_id: Option<ConsensusSigSuiteId>,
    ) {
        record_verification_result(&self.metrics, validator_id, kind, result, suite_id);
    }
}

impl std::fmt::Debug for MultiSuiteCryptoVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiSuiteCryptoVerifier")
            .field("key_provider", &self.key_provider)
            .field("backend_registry", &"<ConsensusSigBackendRegistry>")
            .field("metrics", &"<ConsensusSigMetrics>")
            .finish()
    }
}

impl ConsensusVerifier for MultiSuiteCryptoVerifier {
    fn verify_vote(&self, from: ValidatorId, vote: &Vote) -> Result<(), VerificationError> {
        // Step 1: Look up (governance_suite_id, pk_bytes) from key provider
        let (governance_suite_id, pk) = match self.suite_and_key_for(from) {
            Ok(result) => result,
            Err(err) => {
                self.record_result(from, MessageKind::Vote, (&err).into(), None);
                return Err(err);
            }
        };

        // Step 2: Extract wire suite_id from the Vote and compare with governance suite
        let wire_suite_id = ConsensusSigSuiteId::new(vote.suite_id);
        if wire_suite_id != governance_suite_id {
            // Suite mismatch detected: the wire format carries a different suite
            // than what governance says this validator should be using.
            let err = VerificationError::SuiteMismatch {
                validator_id: from,
                wire_suite: wire_suite_id,
                governance_suite: governance_suite_id,
            };
            self.record_result(
                from,
                MessageKind::Vote,
                VerificationResult::SuiteMismatch,
                Some(governance_suite_id),
            );

            // Log the mismatch with full context (debug builds only)
            #[cfg(debug_assertions)]
            eprintln!(
                "[consensus_sig] SUITE MISMATCH: validator_id={}, kind=vote, wire_suite={}, governance_suite={}",
                from.as_u64(),
                wire_suite_id,
                governance_suite_id
            );

            return Err(err);
        }

        // Step 3: Get the backend for this suite (using governance suite, which now equals wire suite)
        let backend = match self.backend_for(governance_suite_id) {
            Ok(b) => b,
            Err(err) => {
                self.record_result(
                    from,
                    MessageKind::Vote,
                    (&err).into(),
                    Some(governance_suite_id),
                );
                return Err(err);
            }
        };

        // Step 4: Verify the signature with timing (T120 per-suite latency)
        let start = std::time::Instant::now();
        let preimage = vote.signing_preimage();
        let result = backend
            .verify_vote(from.as_u64(), &pk, &preimage, &vote.signature)
            .map_err(map_sig_error);
        let duration = start.elapsed();

        // Record metric and log if failed
        match &result {
            Ok(()) => {
                self.record_result(
                    from,
                    MessageKind::Vote,
                    VerificationResult::Ok,
                    Some(governance_suite_id),
                );
                // T120: Record per-suite vote verification and latency
                self.metrics.record_per_suite_vote(governance_suite_id);
                self.metrics
                    .record_per_suite_latency(governance_suite_id, duration);
            }
            Err(err) => {
                self.record_result(
                    from,
                    MessageKind::Vote,
                    err.into(),
                    Some(governance_suite_id),
                );
            }
        }

        result
    }

    fn verify_proposal(
        &self,
        from: ValidatorId,
        proposal: &BlockProposal,
    ) -> Result<(), VerificationError> {
        // Step 1: Look up (governance_suite_id, pk_bytes) from key provider
        let (governance_suite_id, pk) = match self.suite_and_key_for(from) {
            Ok(result) => result,
            Err(err) => {
                self.record_result(from, MessageKind::Proposal, (&err).into(), None);
                return Err(err);
            }
        };

        // Step 2: Extract wire suite_id from the BlockProposal header and compare with governance suite
        let wire_suite_id = ConsensusSigSuiteId::new(proposal.header.suite_id);
        if wire_suite_id != governance_suite_id {
            // Suite mismatch detected: the wire format carries a different suite
            // than what governance says this validator should be using.
            let err = VerificationError::SuiteMismatch {
                validator_id: from,
                wire_suite: wire_suite_id,
                governance_suite: governance_suite_id,
            };
            self.record_result(
                from,
                MessageKind::Proposal,
                VerificationResult::SuiteMismatch,
                Some(governance_suite_id),
            );

            // Log the mismatch with full context (debug builds only)
            #[cfg(debug_assertions)]
            eprintln!(
                "[consensus_sig] SUITE MISMATCH: validator_id={}, kind=proposal, wire_suite={}, governance_suite={}",
                from.as_u64(),
                wire_suite_id,
                governance_suite_id
            );

            return Err(err);
        }

        // Step 3: Get the backend for this suite (using governance suite, which now equals wire suite)
        let backend = match self.backend_for(governance_suite_id) {
            Ok(b) => b,
            Err(err) => {
                self.record_result(
                    from,
                    MessageKind::Proposal,
                    (&err).into(),
                    Some(governance_suite_id),
                );
                return Err(err);
            }
        };

        // Step 4: Verify the signature with timing (T120 per-suite latency)
        let start = std::time::Instant::now();
        let preimage = proposal.signing_preimage();
        let result = backend
            .verify_proposal(from.as_u64(), &pk, &preimage, &proposal.signature)
            .map_err(map_sig_error);
        let duration = start.elapsed();

        // Record metric and log if failed
        match &result {
            Ok(()) => {
                self.record_result(
                    from,
                    MessageKind::Proposal,
                    VerificationResult::Ok,
                    Some(governance_suite_id),
                );
                // T120: Record per-suite proposal verification and latency
                self.metrics.record_per_suite_proposal(governance_suite_id);
                self.metrics
                    .record_per_suite_latency(governance_suite_id, duration);
            }
            Err(err) => {
                self.record_result(
                    from,
                    MessageKind::Proposal,
                    err.into(),
                    Some(governance_suite_id),
                );
            }
        }

        result
    }
}
