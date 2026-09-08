//! Run 072 (C4 piece: PQC trust-anchor lifecycle — production
//! session-eviction hook): smallest safe, production-honest internal
//! API for closing all currently authenticated P2P sessions on
//! demand, so a future Run 073+ live trust-bundle reload-apply
//! pipeline can satisfy Run 070's strict `validate → swap →
//! evict_sessions → commit_sequence` ordering without redesigning
//! the transport.
//!
//! # Strict scope (what Run 072 is and is NOT)
//!
//! Run 072 is **only** the session-eviction blocker called out in
//! `docs/whitepaper/contradiction.md` C4 §"Run 071 evidence update".
//! It is intentionally minimal:
//!
//! - This module defines the [`P2pSessionEvictor`] trait, the
//!   public [`EvictionReason`] / [`EvictionReport`] /
//!   [`EvictionError`] types, and a deterministic [`MockP2pSessionEvictor`]
//!   used by tests and by the Run 070 contract-style tests.
//! - The concrete implementation on the live transport lives in
//!   [`crate::p2p_tcp::TcpKemTlsP2pService::evict_all_sessions`].
//! - Run 072 does **not** enable Run 070's production live-apply
//!   path: `apply_validated_candidate` on the running `qbind-node`
//!   binary continues to surface
//!   [`crate::pqc_trust_reload::ReloadApplyError::UnsupportedRuntimeContext`]
//!   because the `LiveTrustApplyContext` adapter that wires
//!   `LivePqcTrustState::swap_snapshot` + this evictor +
//!   `pqc_trust_sequence::commit_sequence` is explicitly deferred to
//!   Run 073.
//! - Run 072 does **not** accept peer-supplied or gossiped bundles.
//! - Run 072 does **not** mutate the trust bundle, the active
//!   roots / revocation sets, or the persisted sequence record.
//! - Run 072 does **not** rotate the bundle-signing key, integrate
//!   with KMS/HSM, or implement `activation_epoch` runtime sourcing.
//! - Run 072 does **not** redesign KEMTLS, consensus, or the
//!   listener / dialer loops.
//! - Run 072 does **not** weaken Run 069 reload-check, Run 070's
//!   apply contract, or Run 071's `LivePqcTrustState` semantics.
//!
//! # Session-eviction policy (v0, conservative)
//!
//! Calling [`P2pSessionEvictor::evict_all_sessions`] on the live
//! transport MUST:
//!
//! 1. Atomically drain the per-peer `PeerConnection` registry.
//! 2. Drop the per-peer outbound `tx` channels (this closes each
//!    write loop, releasing the AEAD key material held in the
//!    matching `AeadSession`).
//! 3. Abort the per-peer read-loop `JoinHandle`s so neither
//!    direction's old session continues to read encrypted bytes.
//! 4. Decrement `connections_current` to zero (no peer is active
//!    after a successful drain — the listener/dialer continue
//!    running and may accept new sessions).
//! 5. Return a truthful [`EvictionReport`] with `attempted` =
//!    `evicted + failed`.
//!
//! It MUST NOT:
//!
//! * Stop the TCP listener or any dialer/retry tasks (operator
//!   intent: terminate **existing** sessions; new sessions under
//!   the current trust state are still allowed).
//! * Selectively retain some peers — Run 072 is "evict all" only.
//! * Touch the live PQC trust state (`LivePqcTrustState`).
//! * Touch the persisted bundle sequence record.
//! * Touch any `/metrics` family other than the four counters
//!   declared on `P2pMetrics` for Run 072.
//!
//! # Reconnect behaviour
//!
//! Reconnect after eviction is governed by the existing
//! `TcpKemTlsP2pService` dialer / accept loops; Run 072 does not
//! add any reconnect logic of its own. The dialer's bounded
//! initial-dial-with-retry tasks (B8) complete during `start()`,
//! so an evicted outbound peer typically does NOT reconnect
//! automatically until the operator triggers a new dial. Inbound
//! reconnects can still arrive at the listener. This is the
//! honest boundary recorded in
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_072.md`.
//!
//! # Trait shape vs. Run 070's `LiveTrustApplyContext`
//!
//! [`P2pSessionEvictor::evict_all_sessions`] is intentionally
//! **synchronous** (`&self -> Result<EvictionReport, EvictionError>`)
//! so that a thin adapter can satisfy
//! [`crate::pqc_trust_reload::LiveTrustApplyContext::evict_sessions`]
//! (also sync) in a future Run 073 wiring, without forcing Run 070's
//! sequencing contract to learn about Tokio. The concrete
//! implementation on `TcpKemTlsP2pService` is internally race-safe
//! because session ownership lives behind a `parking_lot::RwLock`
//! and the per-peer task handles are `tokio::task::JoinHandle`,
//! which can be aborted from a sync context.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Operator/component-supplied reason for an eviction call. Logged
/// and surfaced in [`EvictionReport`]; carries no private material.
///
/// The variant set is intentionally closed in Run 072 — adding a new
/// reason in a future run is a deliberate evidence event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvictionReason {
    /// The eviction was triggered as part of a future Run 073+ live
    /// trust-bundle reload-apply pipeline. Run 072 does **not** wire
    /// this from production yet; this variant exists so the
    /// `LiveTrustApplyContext` adapter that lands in Run 073 has a
    /// stable reason to pass through.
    TrustBundleReloadApply,
    /// The eviction was triggered by an operator/test harness
    /// invocation against the internal Run 072 hook. Used by every
    /// Run 072 integration test and by the matching
    /// release-binary evidence smoke.
    OperatorTest,
}

impl EvictionReason {
    /// Stable lowercase identifier used in logs and reports.
    /// Returns `"trust_bundle_reload_apply"` or `"operator_test"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            EvictionReason::TrustBundleReloadApply => "trust_bundle_reload_apply",
            EvictionReason::OperatorTest => "operator_test",
        }
    }
}

impl std::fmt::Display for EvictionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Truthful report of a single eviction call.
///
/// Invariant: `attempted == evicted + failed`. This invariant is
/// enforced by [`EvictionReport::new`] and re-asserted at the call
/// site by every concrete implementation in Run 072.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictionReport {
    /// Reason supplied by the caller.
    pub reason: EvictionReason,
    /// Total number of sessions the implementation tried to evict.
    /// Equals the registry size observed at the start of the call.
    pub attempted: usize,
    /// Number of sessions the implementation believes were closed
    /// (peer entry removed, outbound channel dropped, read-loop
    /// handle aborted).
    pub evicted: usize,
    /// Number of sessions the implementation could not close
    /// safely. A non-zero value means the report is a partial
    /// failure; callers MUST treat the eviction as not fully
    /// successful.
    pub failed: usize,
}

impl EvictionReport {
    /// Construct an [`EvictionReport`] and enforce the
    /// `attempted == evicted + failed` invariant. Panicking here is
    /// safe because all in-tree call sites compute the counts from
    /// the registry size they just drained — a violation would
    /// indicate a programming error in the eviction loop, not an
    /// operator-driven condition.
    pub fn new(
        reason: EvictionReason,
        attempted: usize,
        evicted: usize,
        failed: usize,
    ) -> Self {
        assert_eq!(
            attempted,
            evicted + failed,
            "Run 072: EvictionReport invariant violated — attempted={} != evicted={} + failed={}",
            attempted,
            evicted,
            failed
        );
        Self {
            reason,
            attempted,
            evicted,
            failed,
        }
    }

    /// `true` iff every attempted session was successfully evicted.
    pub fn is_full_success(&self) -> bool {
        self.failed == 0
    }

    /// Operator-log line summarising the eviction call. Single
    /// source of truth so binary logs and tests agree.
    ///
    /// Output shape (single line, no secrets):
    /// `"[binary] Run 072: p2p session eviction (reason=<R> attempted=<A> evicted=<E> failed=<F> verdict=<V>)"`
    pub fn log_line(&self) -> String {
        let verdict = if self.is_full_success() {
            "full-success"
        } else if self.evicted == 0 {
            "failed"
        } else {
            "partial-success"
        };
        format!(
            "[binary] Run 072: p2p session eviction (reason={} attempted={} evicted={} failed={} verdict={})",
            self.reason, self.attempted, self.evicted, self.failed, verdict
        )
    }
}

/// Error returned by a [`P2pSessionEvictor`] implementation when
/// eviction could not be attempted at all.
///
/// A *partial* failure (some sessions closed, some not) is reported
/// inside [`EvictionReport`] via `failed > 0`, not via this enum.
/// This enum is reserved for the case where the runtime cannot
/// safely attempt eviction in the first place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvictionError {
    /// The current runtime context cannot expose the session
    /// registry to the evictor (e.g. a stub `NullP2pService` or a
    /// transport that never registered a session manager). Behaves
    /// analogously to
    /// [`crate::pqc_trust_reload::ReloadApplyError::UnsupportedRuntimeContext`]
    /// on the Run 070 surface: live trust state, peer sessions, and
    /// the persisted sequence record are all untouched.
    UnsupportedSessionEviction(String),
}

impl std::fmt::Display for EvictionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvictionError::UnsupportedSessionEviction(msg) => write!(
                f,
                "Run 072 p2p session eviction unsupported on this runtime — \
                 live trust state unchanged; sequence not committed; no sessions \
                 mutated: {}",
                msg
            ),
        }
    }
}

impl std::error::Error for EvictionError {}

/// Production-honest internal session-eviction handle.
///
/// Implementations:
///
/// * [`crate::p2p_tcp::TcpKemTlsP2pService`] — drains the live
///   per-peer `PeerConnection` registry, drops the outbound `tx`
///   channels, and aborts the per-peer read-loop handles.
/// * [`MockP2pSessionEvictor`] — deterministic in-memory evictor
///   used by Run 072 unit tests and by Run 070 contract-style
///   tests that need to satisfy
///   [`crate::pqc_trust_reload::LiveTrustApplyContext::evict_sessions`]
///   without spinning up real TCP sockets.
///
/// All methods are synchronous so the future Run 073 adapter can
/// wrap an evictor handle and present it to Run 070's sync
/// `LiveTrustApplyContext::evict_sessions` without forcing Tokio
/// into the apply-sequencing contract.
pub trait P2pSessionEvictor: Send + Sync {
    /// Number of sessions currently authenticated under live trust
    /// state. Reported by [`EvictionReport::attempted`]. Cheap —
    /// implementations MUST NOT perform I/O.
    fn connected_session_count(&self) -> usize;

    /// Close all currently authenticated sessions; return a
    /// truthful [`EvictionReport`]. See the module-level docs for
    /// the precise mutation contract.
    ///
    /// MUST NOT mutate the trust bundle, the active roots /
    /// revocation sets, or the persisted sequence record.
    fn evict_all_sessions(
        &self,
        reason: EvictionReason,
    ) -> Result<EvictionReport, EvictionError>;
}

/// Deterministic in-memory [`P2pSessionEvictor`] for tests.
///
/// `MockP2pSessionEvictor` is intentionally tiny: it owns a counter
/// of "live sessions" and a configurable per-session failure count.
/// Tests use it to drive every branch (empty / one / many / partial
/// failure / repeated-call idempotency) without depending on a real
/// listener.
#[derive(Debug, Default)]
pub struct MockP2pSessionEvictor {
    /// Current live session count. Decremented to zero on a
    /// successful `evict_all_sessions` call. May be reset via
    /// [`Self::seed_sessions`].
    live: AtomicUsize,
    /// Number of sessions the next call should report as failed.
    /// Tests use this to drive the partial-failure branch.
    failure_seed: AtomicUsize,
    /// Recorded calls. Tests assert on the sequence of reasons /
    /// counts.
    log: Mutex<Vec<EvictionReport>>,
    /// Number of total attempts observed. Useful when tests want to
    /// confirm idempotency from a single read.
    attempt_counter: AtomicU64,
}

impl MockP2pSessionEvictor {
    /// Build a mock evictor with `live` sessions already authenticated.
    pub fn new(live: usize) -> Self {
        Self {
            live: AtomicUsize::new(live),
            failure_seed: AtomicUsize::new(0),
            log: Mutex::new(Vec::new()),
            attempt_counter: AtomicU64::new(0),
        }
    }

    /// Reset the live session count (test helper).
    pub fn seed_sessions(&self, n: usize) {
        self.live.store(n, Ordering::Relaxed);
    }

    /// Arrange that the next `evict_all_sessions` call reports
    /// `failed = n` sessions (capped at the current live count).
    /// `n=0` (the default) means "every live session is evicted
    /// cleanly".
    pub fn arrange_failure(&self, n: usize) {
        self.failure_seed.store(n, Ordering::Relaxed);
    }

    /// Total number of recorded calls.
    pub fn attempt_count(&self) -> u64 {
        self.attempt_counter.load(Ordering::Relaxed)
    }

    /// Snapshot of every recorded report, in call order.
    pub fn recorded_reports(&self) -> Vec<EvictionReport> {
        self.log.lock().unwrap().clone()
    }
}

impl P2pSessionEvictor for MockP2pSessionEvictor {
    fn connected_session_count(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    fn evict_all_sessions(
        &self,
        reason: EvictionReason,
    ) -> Result<EvictionReport, EvictionError> {
        self.attempt_counter.fetch_add(1, Ordering::Relaxed);
        let attempted = self.live.swap(0, Ordering::Relaxed);
        let failed = self.failure_seed.swap(0, Ordering::Relaxed).min(attempted);
        let evicted = attempted - failed;
        // Sessions that "failed to evict" remain alive on the mock,
        // mirroring the truthful behaviour expected of the real
        // implementation: a report MUST NOT claim a session evicted
        // when the underlying handle could not be closed.
        if failed > 0 {
            self.live.store(failed, Ordering::Relaxed);
        }
        let report = EvictionReport::new(reason, attempted, evicted, failed);
        self.log.lock().unwrap().push(report.clone());
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // EvictionReason value/serialisation surface.
    // ====================================================================

    #[test]
    fn eviction_reason_as_str_is_stable_lowercase_snake_case() {
        assert_eq!(
            EvictionReason::TrustBundleReloadApply.as_str(),
            "trust_bundle_reload_apply"
        );
        assert_eq!(EvictionReason::OperatorTest.as_str(), "operator_test");
        // Display agrees with as_str (single source of truth).
        assert_eq!(
            format!("{}", EvictionReason::TrustBundleReloadApply),
            "trust_bundle_reload_apply"
        );
        assert_eq!(format!("{}", EvictionReason::OperatorTest), "operator_test");
    }

    #[test]
    fn eviction_reason_variants_are_distinct() {
        assert_ne!(
            EvictionReason::TrustBundleReloadApply,
            EvictionReason::OperatorTest
        );
    }

    // ====================================================================
    // EvictionReport invariants and log line.
    // ====================================================================

    #[test]
    fn report_invariant_holds_for_full_success() {
        let r = EvictionReport::new(EvictionReason::OperatorTest, 3, 3, 0);
        assert_eq!(r.attempted, 3);
        assert_eq!(r.evicted, 3);
        assert_eq!(r.failed, 0);
        assert!(r.is_full_success());
    }

    #[test]
    fn report_invariant_holds_for_partial_failure() {
        let r = EvictionReport::new(EvictionReason::OperatorTest, 3, 2, 1);
        assert!(!r.is_full_success());
        assert_eq!(r.attempted, r.evicted + r.failed);
    }

    #[test]
    #[should_panic(expected = "EvictionReport invariant violated")]
    fn report_invariant_panics_when_attempted_mismatches_sum() {
        // Pinned: programming errors in the eviction loop fail loudly.
        let _ = EvictionReport::new(EvictionReason::OperatorTest, 5, 2, 1);
    }

    #[test]
    fn report_log_line_marks_full_success_truthfully() {
        let r = EvictionReport::new(EvictionReason::TrustBundleReloadApply, 4, 4, 0);
        let line = r.log_line();
        assert!(line.contains("Run 072"), "{}", line);
        assert!(line.contains("p2p session eviction"), "{}", line);
        assert!(line.contains("reason=trust_bundle_reload_apply"), "{}", line);
        assert!(line.contains("attempted=4"), "{}", line);
        assert!(line.contains("evicted=4"), "{}", line);
        assert!(line.contains("failed=0"), "{}", line);
        assert!(line.contains("verdict=full-success"), "{}", line);
    }

    #[test]
    fn report_log_line_marks_partial_success_truthfully() {
        let r = EvictionReport::new(EvictionReason::OperatorTest, 4, 3, 1);
        let line = r.log_line();
        assert!(line.contains("verdict=partial-success"), "{}", line);
        assert!(line.contains("evicted=3"), "{}", line);
        assert!(line.contains("failed=1"), "{}", line);
    }

    #[test]
    fn report_log_line_marks_total_failure_truthfully() {
        let r = EvictionReport::new(EvictionReason::OperatorTest, 2, 0, 2);
        let line = r.log_line();
        assert!(line.contains("verdict=failed"), "{}", line);
        assert!(line.contains("attempted=2"), "{}", line);
        assert!(line.contains("evicted=0"), "{}", line);
        assert!(line.contains("failed=2"), "{}", line);
    }

    #[test]
    fn report_log_line_does_not_leak_keying_material_keywords() {
        // Defence-in-depth: the log line must never carry words a
        // future code reviewer would interpret as private material.
        let r = EvictionReport::new(EvictionReason::OperatorTest, 1, 1, 0);
        let line = r.log_line();
        let lower = line.to_lowercase();
        for forbidden in ["secret", "private", "key=", "aead", "kem"] {
            assert!(
                !lower.contains(forbidden),
                "Run 072 log line must not contain {:?}: {}",
                forbidden,
                line
            );
        }
    }

    // ====================================================================
    // EvictionError display surface.
    // ====================================================================

    #[test]
    fn unsupported_session_eviction_display_is_operator_actionable() {
        let e = EvictionError::UnsupportedSessionEviction(
            "no session registry on this transport".into(),
        );
        let s = format!("{}", e);
        assert!(s.contains("Run 072"), "{}", s);
        assert!(s.contains("unsupported"), "{}", s);
        assert!(s.contains("live trust state unchanged"), "{}", s);
        assert!(s.contains("sequence not committed"), "{}", s);
        assert!(s.contains("no sessions mutated"), "{}", s);
    }

    // ====================================================================
    // MockP2pSessionEvictor behaviour.
    // ====================================================================

    #[test]
    fn mock_empty_returns_zero_attempted_and_zero_evicted() {
        let m = MockP2pSessionEvictor::new(0);
        let r = m
            .evict_all_sessions(EvictionReason::OperatorTest)
            .expect("eviction supported on mock");
        assert_eq!(r.attempted, 0);
        assert_eq!(r.evicted, 0);
        assert_eq!(r.failed, 0);
        assert!(r.is_full_success());
        assert_eq!(m.connected_session_count(), 0);
    }

    #[test]
    fn mock_one_session_evicted_returns_attempted_one() {
        let m = MockP2pSessionEvictor::new(1);
        assert_eq!(m.connected_session_count(), 1);
        let r = m
            .evict_all_sessions(EvictionReason::OperatorTest)
            .expect("evict ok");
        assert_eq!(r.attempted, 1);
        assert_eq!(r.evicted, 1);
        assert_eq!(r.failed, 0);
        assert_eq!(m.connected_session_count(), 0);
    }

    #[test]
    fn mock_many_sessions_evicted_in_single_call() {
        let m = MockP2pSessionEvictor::new(7);
        let r = m
            .evict_all_sessions(EvictionReason::TrustBundleReloadApply)
            .expect("ok");
        assert_eq!(r.attempted, 7);
        assert_eq!(r.evicted, 7);
        assert_eq!(r.failed, 0);
        assert_eq!(m.connected_session_count(), 0);
    }

    #[test]
    fn mock_partial_failure_reports_failed_truthfully_and_leaves_alive_sessions() {
        let m = MockP2pSessionEvictor::new(5);
        m.arrange_failure(2);
        let r = m
            .evict_all_sessions(EvictionReason::OperatorTest)
            .expect("ok");
        assert_eq!(r.attempted, 5);
        assert_eq!(r.evicted, 3);
        assert_eq!(r.failed, 2);
        assert!(!r.is_full_success());
        // The two sessions that "failed" remain authenticated —
        // a partial-failure report MUST NOT claim them evicted.
        assert_eq!(m.connected_session_count(), 2);
    }

    #[test]
    fn mock_repeated_eviction_is_idempotent_after_first_full_success() {
        let m = MockP2pSessionEvictor::new(3);
        let r1 = m
            .evict_all_sessions(EvictionReason::OperatorTest)
            .expect("ok");
        assert_eq!(r1.evicted, 3);
        let r2 = m
            .evict_all_sessions(EvictionReason::OperatorTest)
            .expect("ok");
        // Second call attempts/evicts nothing — sessions already
        // gone; idempotency invariant preserved.
        assert_eq!(r2.attempted, 0);
        assert_eq!(r2.evicted, 0);
        assert_eq!(r2.failed, 0);
        assert_eq!(m.attempt_count(), 2);
    }

    #[test]
    fn mock_records_each_report_in_call_order() {
        let m = MockP2pSessionEvictor::new(2);
        let _ = m.evict_all_sessions(EvictionReason::OperatorTest);
        m.seed_sessions(4);
        let _ = m.evict_all_sessions(EvictionReason::TrustBundleReloadApply);
        let history = m.recorded_reports();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].reason, EvictionReason::OperatorTest);
        assert_eq!(history[0].evicted, 2);
        assert_eq!(history[1].reason, EvictionReason::TrustBundleReloadApply);
        assert_eq!(history[1].evicted, 4);
    }

    #[test]
    fn mock_implements_p2p_session_evictor_dyn() {
        // Sanity: dynamic dispatch through `dyn P2pSessionEvictor`
        // works for the mock so a future Run 073 `LiveTrustApplyContext`
        // adapter can accept a `&dyn P2pSessionEvictor`.
        let m: Box<dyn P2pSessionEvictor> = Box::new(MockP2pSessionEvictor::new(2));
        assert_eq!(m.connected_session_count(), 2);
        let r = m.evict_all_sessions(EvictionReason::OperatorTest).unwrap();
        assert_eq!(r.attempted, 2);
        assert_eq!(r.evicted, 2);
    }
}