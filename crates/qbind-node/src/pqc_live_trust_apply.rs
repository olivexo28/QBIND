//! Run 073 (C4 piece: PQC trust-bundle reload-apply runtime adapter):
//! a small, production-honest adapter that composes Run 069
//! validation + Run 070 apply contract + Run 071
//! [`crate::pqc_live_trust::LivePqcTrustState`] + Run 072
//! [`crate::p2p_session_eviction::P2pSessionEvictor`] +
//! [`crate::pqc_trust_sequence::check_and_update_sequence`] into a
//! single concrete [`crate::pqc_trust_reload::LiveTrustApplyContext`]
//! implementation.
//!
//! # Strict scope (what Run 073 is and is NOT)
//!
//! Run 073 is **only** the smallest possible adapter that lets the
//! Run 070 apply pipeline run end-to-end against the production
//! `LivePqcTrustState` + `P2pSessionEvictor` + sequence-persistence
//! layers, exposed for **operator-triggered local file** reload-apply
//! invocations. It is intentionally minimal:
//!
//! - The adapter takes an [`Arc<LivePqcTrustState>`] (Run 071) and an
//!   [`Arc<dyn P2pSessionEvictor>`] (Run 072) and a sequence
//!   persistence path (`crate::pqc_trust_sequence`) and exposes them
//!   to the Run 070 apply pipeline via the
//!   [`crate::pqc_trust_reload::LiveTrustApplyContext`] trait.
//! - The adapter performs **no validation** of its own — it relies on
//!   the Run 069/070 entry points to validate the candidate *before*
//!   any callback is invoked. Validation parity with startup is
//!   preserved by construction.
//! - The adapter performs **no mutation** before the Run 070
//!   pipeline calls `swap_trust_state`. Snapshot capture is read-only.
//! - The adapter performs **no sequence write** before the Run 070
//!   pipeline calls `commit_sequence` (which only happens after a
//!   successful swap and a successful eviction).
//! - Rollback is exact: the captured `Arc<LivePqcTrustSnapshot>` is
//!   re-installed under a single short write lock. The previously-
//!   persisted sequence record is **not** rolled back here because
//!   `commit_sequence` only writes on success — see the rollback
//!   notes on [`ProductionLiveTrustApplyContext::commit_sequence`].
//! - The adapter is the *only* in-tree concrete
//!   [`crate::pqc_trust_reload::LiveTrustApplyContext`] implementation
//!   used by the production binary. Tests continue to use the
//!   in-memory `FakeLiveTrustApplyContext` from
//!   `tests/run_070_pqc_trust_bundle_reload_apply_tests.rs` for the
//!   pure sequencing-contract proofs.
//!
//! Run 073 is **NOT**:
//!
//! - peer-supplied / gossiped bundle acceptance (local file only);
//! - automatic filesystem-watcher hot reload (operator-triggered
//!   only);
//! - a long-running-node SIGHUP / admin-API trigger — the production
//!   binary `qbind-node` invokes this adapter at process-start time
//!   under the existing `--p2p-trust-bundle-reload-apply-path` hook
//!   (the node does not start in that mode; the operator workflow is
//!   "stop → reload-apply → restart"). A future run that lands a
//!   long-running signal handler can call the same adapter on a
//!   running node without changing this surface;
//! - KMS / HSM custody;
//! - bundle-signing-key ratification;
//! - `activation_epoch` runtime sourcing;
//! - selective session retention — the v0 policy is "evict all"
//!   (Run 072).
//!
//! # Composition (validate → swap → evict → commit)
//!
//! `ProductionLiveTrustApplyContext` slots into Run 070's apply
//! pipeline as follows (the pipeline lives in
//! [`crate::pqc_trust_reload::apply_validated_candidate`]):
//!
//! 1. **Validate.** Run 070 calls Run 069's
//!    `validate_candidate_bundle_full`. The adapter is **not** called
//!    here.
//! 2. **Snapshot.** Run 070 calls
//!    [`crate::pqc_trust_reload::LiveTrustApplyContext::snapshot_active`].
//!    The adapter takes a short read lock on `LivePqcTrustState` and
//!    captures an `Arc<LivePqcTrustSnapshot>` clone (Arc bump only —
//!    no deep copy). The captured Arc is returned boxed for the
//!    Run 070 rollback path.
//! 3. **Swap.** Run 070 calls
//!    [`crate::pqc_trust_reload::LiveTrustApplyContext::swap_trust_state`].
//!    The adapter constructs a fresh
//!    [`crate::pqc_live_trust::LivePqcTrustSnapshot`] from the
//!    Run 069-validated [`crate::pqc_trust_bundle::LoadedTrustBundle`]
//!    and installs it via
//!    [`crate::pqc_live_trust::LivePqcTrustState::swap_snapshot`]
//!    under a single short write lock. Readers see either the
//!    entire old snapshot or the entire new snapshot — never a
//!    half-applied state.
//! 4. **Evict.** Run 070 calls
//!    [`crate::pqc_trust_reload::LiveTrustApplyContext::evict_sessions`].
//!    The adapter forwards to
//!    [`crate::p2p_session_eviction::P2pSessionEvictor::evict_all_sessions`]
//!    with [`crate::p2p_session_eviction::EvictionReason::TrustBundleReloadApply`].
//!    The Run 072 truthful invariant (`attempted == evicted + failed`)
//!    is preserved.
//! 5. **Commit.** Run 070 calls
//!    [`crate::pqc_trust_reload::LiveTrustApplyContext::commit_sequence`].
//!    The adapter calls
//!    [`crate::pqc_trust_sequence::check_and_update_sequence`] with the
//!    candidate's `(sequence, fingerprint)`. This is the SAME writer
//!    function the startup binary uses, so any future hardening of
//!    the anti-rollback contract applies automatically.
//! 6. **Rollback (failure paths only).** On post-swap failure
//!    (eviction or sequence commit) Run 070 calls
//!    [`crate::pqc_trust_reload::LiveTrustApplyContext::rollback_trust_state`].
//!    The adapter re-installs the captured snapshot Arc via
//!    `swap_snapshot`. Rollback only restores the in-memory live
//!    trust handle — the on-disk sequence record is not touched
//!    here because `check_and_update_sequence` is atomic and only
//!    writes on a successful upgrade; a commit failure either
//!    happened before the atomic write (no on-disk change) or
//!    surfaced as a write error (the atomic-write helper rewinds
//!    on its own).
//!
//! # No /metrics fabrication
//!
//! Run 073 deliberately reuses Run 072's existing session-eviction
//! counters (`qbind_p2p_session_eviction_*`) as the only metric
//! surface for the reload-apply session-eviction stage. The validate
//! and commit stages already have no metric in Run 069/070 (the
//! validation-only / staging boundary explicitly avoided
//! `/metrics` fabrication; see
//! `crates/qbind-node/src/pqc_trust_reload.rs` module-level
//! comment). Operator-visible verdicts go through `eprintln!`
//! log lines from the binary surface — single source of truth via
//! [`crate::pqc_trust_reload::AppliedCandidate::applied_log_line`].
//!
//! # No fallback
//!
//! The adapter NEVER falls back to `--p2p-trusted-root`, NEVER falls
//! back to `DummySig` / `DummyKem` / `DummyAead`, and NEVER silently
//! accepts an invalid candidate.

use std::path::PathBuf;
use std::sync::Arc;

use qbind_types::{ChainId, NetworkEnvironment};

use crate::p2p_session_eviction::{EvictionError, EvictionReason, P2pSessionEvictor};
use crate::pqc_live_trust::{LivePqcTrustSnapshot, LivePqcTrustState};
use crate::pqc_trust_bundle::LoadedTrustBundle;
use crate::pqc_trust_reload::LiveTrustApplyContext;
use crate::pqc_trust_sequence::{
    check_and_update_sequence, SequenceCheckOutcome, TrustBundleSequenceError,
};

/// Production-honest adapter implementing
/// [`LiveTrustApplyContext`] by composing Run 071's
/// [`LivePqcTrustState`], Run 072's
/// [`P2pSessionEvictor`], and Run 055's
/// [`check_and_update_sequence`] persistence writer.
///
/// Construction is cheap: every dependency is supplied as a clonable
/// handle (`Arc<LivePqcTrustState>` is a clone of the same handle
/// the production binary builds at startup; `Arc<dyn P2pSessionEvictor>`
/// wraps either the live `TcpKemTlsP2pService` or the
/// [`NoActiveSessionsEvictor`] for at-startup-time invocations).
///
/// The adapter holds **no** mutable state of its own between
/// callback invocations — every call reads through the supplied
/// handles. The captured snapshot for rollback is held in the
/// boxed `dyn Any` value Run 070 owns between
/// `snapshot_active` → `rollback_trust_state`; the adapter does not
/// hold it.
pub struct ProductionLiveTrustApplyContext {
    /// Shared live trust-state handle (Run 071). Read-locked during
    /// `snapshot_active`; write-locked during `swap_trust_state` and
    /// `rollback_trust_state`.
    live: Arc<LivePqcTrustState>,
    /// Shared session-evictor handle (Run 072). The adapter never
    /// touches sessions directly — every eviction goes through this
    /// handle's `evict_all_sessions` method.
    evictor: Arc<dyn P2pSessionEvictor>,
    /// Runtime environment used by `check_and_update_sequence` for
    /// domain validation against the on-disk record. MUST match the
    /// environment the candidate was validated under (the Run 069
    /// pipeline enforces this on the candidate; the adapter
    /// preserves it on the persistence layer).
    environment: NetworkEnvironment,
    /// Runtime chain id used by `check_and_update_sequence` for
    /// domain validation against the on-disk record. Same parity
    /// rule as `environment`.
    chain_id: ChainId,
    /// Path of the on-disk sequence persistence file (typically
    /// `<data_dir>/pqc_trust_bundle_sequence.json`). `Option` so
    /// DevNet without `--data-dir` can be supported by surfacing a
    /// clean fail-closed `CommitSequence` error from
    /// [`Self::commit_sequence`] rather than silently skipping the
    /// commit.
    sequence_path: Option<PathBuf>,
    /// Wall-clock seconds passed through to
    /// `check_and_update_sequence` for the `accepted_at` record
    /// field. Captured once at adapter construction so the apply
    /// run uses a consistent timestamp.
    now_unix_secs: u64,
}

impl ProductionLiveTrustApplyContext {
    /// Construct an adapter. All handles are stored as-is — no
    /// validation is performed at construction. Validation parity
    /// with startup is preserved by the Run 070 entry point's
    /// validation stage, which is guaranteed to run before any
    /// callback on this adapter fires.
    pub fn new(
        live: Arc<LivePqcTrustState>,
        evictor: Arc<dyn P2pSessionEvictor>,
        environment: NetworkEnvironment,
        chain_id: ChainId,
        sequence_path: Option<PathBuf>,
        now_unix_secs: u64,
    ) -> Self {
        Self {
            live,
            evictor,
            environment,
            chain_id,
            sequence_path,
            now_unix_secs,
        }
    }

    /// Capture metadata about the currently-active live trust state
    /// — the previous fingerprint prefix (8 hex chars) and the
    /// previous bundle sequence — so the apply success path can
    /// produce an operator-log line that includes BOTH the old and
    /// the new fingerprint without exposing private material.
    ///
    /// Returned values are derived from a single short read lock on
    /// `LivePqcTrustState`. Returns `("", None)` if the lock is
    /// poisoned (caller fails closed in that scenario via the apply
    /// pipeline's `StateSwapFailed` boundary).
    pub fn snapshot_previous_metadata(&self) -> (String, Option<u64>) {
        match self.live.snapshot() {
            Ok(snap) => {
                let mut prev_fp_prefix = String::with_capacity(8);
                for b in &snap.fingerprint()[..4] {
                    use std::fmt::Write;
                    let _ = write!(prev_fp_prefix, "{:02x}", b);
                }
                (prev_fp_prefix, Some(snap.sequence()))
            }
            Err(_) => (String::new(), None),
        }
    }
}

impl LiveTrustApplyContext for ProductionLiveTrustApplyContext {
    /// Capture an `Arc<LivePqcTrustSnapshot>` clone of the active
    /// live trust state. Read-only — the inner Arc is cloned under
    /// a short read lock and the lock is dropped before this method
    /// returns. The boxed `Arc` is what Run 070 hands back to
    /// [`Self::rollback_trust_state`] if any post-swap step fails.
    fn snapshot_active(&mut self) -> Result<Box<dyn std::any::Any + Send + Sync>, String> {
        match self.live.snapshot() {
            Ok(prev) => Ok(Box::new(prev)),
            Err(e) => Err(format!(
                "Run 073: failed to snapshot live PQC trust state for rollback: {}",
                e
            )),
        }
    }

    /// Build a fresh [`LivePqcTrustSnapshot`] from the validated
    /// candidate bundle and install it via `swap_snapshot` under a
    /// single short write lock. Swap is all-or-nothing: a poisoned
    /// lock fails closed without touching the inner Arc.
    fn swap_trust_state(&mut self, candidate: &LoadedTrustBundle) -> Result<(), String> {
        let new_snap = LivePqcTrustSnapshot::from_loaded(candidate);
        match self.live.swap_snapshot(new_snap) {
            Ok(_previous_arc) => Ok(()),
            Err(e) => Err(format!(
                "Run 073: failed to swap live PQC trust state: {}",
                e
            )),
        }
    }

    /// Forward to
    /// [`P2pSessionEvictor::evict_all_sessions`] with
    /// [`EvictionReason::TrustBundleReloadApply`]. The Run 072
    /// invariant (`attempted == evicted + failed`) is preserved.
    /// Partial failures are surfaced as `Err` so the Run 070
    /// pipeline can roll back the swap.
    fn evict_sessions(&mut self) -> Result<usize, String> {
        match self
            .evictor
            .evict_all_sessions(EvictionReason::TrustBundleReloadApply)
        {
            Ok(report) => {
                if report.is_full_success() {
                    Ok(report.evicted)
                } else {
                    Err(format!(
                        "Run 073: p2p session eviction reported partial failure \
                         (attempted={} evicted={} failed={}); rolling back live trust state",
                        report.attempted, report.evicted, report.failed
                    ))
                }
            }
            Err(EvictionError::UnsupportedSessionEviction(msg)) => Err(format!(
                "Run 073: p2p session eviction unsupported on this runtime: {}",
                msg
            )),
        }
    }

    /// Persist the candidate's `(sequence, fingerprint)` via
    /// [`check_and_update_sequence`] — the SAME writer the startup
    /// binary uses. On success the on-disk record reflects the
    /// candidate's sequence; on failure (corrupt persistence,
    /// wrong-env/wrong-chain on-disk record, sequence rollback, I/O
    /// error, equal-sequence fingerprint mismatch) the writer
    /// surfaces a typed error which the adapter wraps into a
    /// `String` for the Run 070 surface.
    ///
    /// Rollback semantics: `check_and_update_sequence` performs the
    /// atomic write only after every validation passes. If this
    /// method returns `Err`, no partial on-disk state exists, so
    /// rolling back the in-memory live trust state in
    /// [`Self::rollback_trust_state`] restores full consistency.
    fn commit_sequence(&mut self, candidate: &LoadedTrustBundle) -> Result<(), String> {
        let path = match self.sequence_path.as_ref() {
            Some(p) => p,
            None => {
                return Err(
                    "Run 073: --data-dir not configured, sequence persistence path is \
                     unavailable; refusing to commit sequence (fail-closed, will trigger \
                     rollback). Re-run with --data-dir <DIR> so the candidate's sequence \
                     can be persisted alongside startup-time sequence records."
                        .to_string(),
                );
            }
        };
        match check_and_update_sequence(
            path,
            self.environment,
            self.chain_id,
            candidate.bundle.sequence,
            &candidate.fingerprint,
            self.now_unix_secs,
        ) {
            Ok(SequenceCheckOutcome::FirstLoad { .. })
            | Ok(SequenceCheckOutcome::Upgraded { .. })
            | Ok(SequenceCheckOutcome::EqualSequenceSameFingerprint { .. }) => Ok(()),
            Err(e) => Err(format_commit_sequence_error(&e)),
        }
    }

    /// Restore the captured live trust snapshot via
    /// `swap_snapshot`. Caller-supplied `snapshot` is downcast back
    /// to `Arc<LivePqcTrustSnapshot>`. A type-mismatched value (which
    /// would only happen on a programming error inside Run 070)
    /// surfaces as a clean fail-closed error rather than panicking.
    fn rollback_trust_state(
        &mut self,
        snapshot: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<(), String> {
        let prev_arc: Arc<LivePqcTrustSnapshot> =
            match snapshot.downcast::<Arc<LivePqcTrustSnapshot>>() {
                Ok(boxed) => *boxed,
                Err(_) => {
                    return Err(
                        "Run 073: rollback snapshot was not an Arc<LivePqcTrustSnapshot>; this \
                     is a programming error in the Run 070 apply pipeline. Live trust \
                     state may be ahead of the on-disk sequence record — fail-closed."
                            .to_string(),
                    );
                }
            };
        // Clone the inner snapshot data into a fresh
        // `LivePqcTrustSnapshot` so we can hand it to `swap_snapshot`
        // (which takes ownership of a value). The Arc bump from
        // `snapshot_active` cost nothing; the deep clone here happens
        // only on the failure-rollback path and only ever once per
        // failed apply.
        let snap_clone: LivePqcTrustSnapshot = (*prev_arc).clone();
        match self.live.swap_snapshot(snap_clone) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!(
                "Run 073: rollback failed to restore live PQC trust state via \
                 swap_snapshot: {}. Live trust state may now be ahead of the on-disk \
                 sequence record — operator MUST stop the node and recover offline.",
                e
            )),
        }
    }
}

/// Map a [`TrustBundleSequenceError`] into a human-readable string
/// for the Run 070 `ReloadApplyError::SequenceCommitFailed[
/// RollbackAlsoFailed]` surface.
///
/// Single source of truth so binary logs and tests agree on the
/// commit-stage error message shape. No private material is included.
fn format_commit_sequence_error(e: &TrustBundleSequenceError) -> String {
    format!(
        "Run 073: sequence persistence commit refused: {} (live trust state will be \
         rolled back to previous snapshot; on-disk sequence record unchanged)",
        e
    )
}

// ============================================================================
// NoActiveSessionsEvictor — truthful zero-session adapter for at-startup-time
// reload-apply invocations.
// ============================================================================

/// A truthful [`P2pSessionEvictor`] that reports zero connected
/// sessions and a zero-eviction success report.
///
/// # Why this exists
///
/// The production `qbind-node` binary's
/// `--p2p-trust-bundle-reload-apply-path` hook runs at process-start
/// time (immediately after CLI parsing, BEFORE network bring-up):
/// the node has not connected to any peer yet, so the registry of
/// authenticated KEMTLS sessions is empty. Using a
/// `TcpKemTlsP2pService` in that scope is unnecessary (no sessions
/// to evict) AND impossible (no listener has been created yet).
/// [`NoActiveSessionsEvictor`] is the smallest safe
/// production-honest evictor for that scope: it reports zero
/// sessions, performs zero work, and the Run 072 invariant holds
/// trivially (`attempted == evicted + failed == 0`).
///
/// # Strict scope (what this evictor is NOT)
///
/// - This is **not** a stub that hides failed evictions. The
///   "attempted=0" report is truthful because there are genuinely
///   zero authenticated sessions at the point this evictor is
///   constructed (binary-startup operator-triggered reload-apply).
/// - This is **not** suitable for a long-running-node scenario.
///   A future run that adds SIGHUP / admin-API triggered live apply
///   on a running node MUST wire the live `TcpKemTlsP2pService`
///   (or another fallible production evictor) instead, so existing
///   authenticated sessions are actually closed.
/// - This evictor MUST NOT be used as a silent fallback when a
///   live evictor was expected. The production binary path passes
///   this evictor *only* on the at-startup-time hook where it is
///   the honest choice.
///
/// See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md` for the
/// boundary statement.
#[derive(Debug, Default)]
pub struct NoActiveSessionsEvictor;

impl NoActiveSessionsEvictor {
    /// Construct a fresh zero-session evictor.
    pub fn new() -> Self {
        Self
    }
}

impl P2pSessionEvictor for NoActiveSessionsEvictor {
    fn connected_session_count(&self) -> usize {
        0
    }

    fn evict_all_sessions(
        &self,
        reason: EvictionReason,
    ) -> Result<crate::p2p_session_eviction::EvictionReport, EvictionError> {
        // Truthful zero-report: no sessions attempted, zero
        // evicted, zero failed. Run 072 invariant trivially holds.
        Ok(crate::p2p_session_eviction::EvictionReport::new(
            reason, 0, 0, 0,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p_session_eviction::MockP2pSessionEvictor;
    use crate::pqc_devnet_helper::mint_devnet_root;
    use crate::pqc_trust_bundle::{build_helper_bundle, HelperBundleMode, TrustBundle};
    use crate::pqc_trust_sequence::{load_record, sequence_file_path};

    fn hex_lower(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", x);
        }
        s
    }

    fn fresh_loaded_devnet_bundle(sequence: u64) -> LoadedTrustBundle {
        let root = mint_devnet_root().expect("mint devnet root");
        let id_hex = hex_lower(&root.root_key_id);
        let pk_hex = hex_lower(&root.root_pk);
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 200);
        // `build_helper_bundle` hard-codes sequence=1; override so
        // tests can distinguish swap / rollback by sequence value.
        bundle.sequence = sequence;
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 200).expect("loads")
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "qbind-run073-unit-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&p).expect("create_dir_all");
        p
    }

    #[test]
    fn no_active_sessions_evictor_reports_zero_truthfully() {
        let e = NoActiveSessionsEvictor::new();
        assert_eq!(e.connected_session_count(), 0);
        let r = e
            .evict_all_sessions(EvictionReason::TrustBundleReloadApply)
            .expect("zero-session evictor must always succeed");
        assert_eq!(r.attempted, 0);
        assert_eq!(r.evicted, 0);
        assert_eq!(r.failed, 0);
        assert!(r.is_full_success());
        assert_eq!(r.reason, EvictionReason::TrustBundleReloadApply);
    }

    #[test]
    fn no_active_sessions_evictor_is_p2p_session_evictor_dyn() {
        let e: Box<dyn P2pSessionEvictor> = Box::new(NoActiveSessionsEvictor::new());
        assert_eq!(e.connected_session_count(), 0);
        let r = e
            .evict_all_sessions(EvictionReason::OperatorTest)
            .expect("ok");
        assert_eq!(r.attempted, 0);
        assert_eq!(r.evicted, 0);
        assert_eq!(r.failed, 0);
    }

    #[test]
    fn snapshot_active_captures_arc_snapshot_for_rollback() {
        let loaded = fresh_loaded_devnet_bundle(5);
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(&loaded));
        let evictor: Arc<dyn P2pSessionEvictor> = Arc::new(MockP2pSessionEvictor::new(0));
        let mut ctx = ProductionLiveTrustApplyContext::new(
            live.clone(),
            evictor,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            None,
            42,
        );
        let snap_any = ctx.snapshot_active().expect("snapshot ok");
        let arc_snap = *snap_any
            .downcast::<Arc<LivePqcTrustSnapshot>>()
            .expect("downcast to Arc<LivePqcTrustSnapshot>");
        // The captured Arc points at the same heap allocation as a
        // fresh `live.snapshot()` because Run 073 hasn't swapped yet.
        let current = live.snapshot().expect("current snapshot ok");
        assert!(Arc::ptr_eq(&arc_snap, &current));
        assert_eq!(arc_snap.sequence(), 5);
    }

    #[test]
    fn swap_trust_state_replaces_inner_snapshot_with_candidate() {
        let loaded_a = fresh_loaded_devnet_bundle(1);
        let loaded_b = fresh_loaded_devnet_bundle(2);
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(&loaded_a));
        let evictor: Arc<dyn P2pSessionEvictor> = Arc::new(MockP2pSessionEvictor::new(0));
        let mut ctx = ProductionLiveTrustApplyContext::new(
            live.clone(),
            evictor,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            None,
            0,
        );
        let before = live.snapshot().expect("before");
        assert_eq!(before.sequence(), 1);
        ctx.swap_trust_state(&loaded_b).expect("swap ok");
        let after = live.snapshot().expect("after");
        assert_eq!(after.sequence(), 2);
        assert_eq!(after.fingerprint(), &loaded_b.fingerprint);
        assert!(!Arc::ptr_eq(&before, &after));
    }

    #[test]
    fn rollback_trust_state_restores_inner_snapshot() {
        let loaded_a = fresh_loaded_devnet_bundle(1);
        let loaded_b = fresh_loaded_devnet_bundle(2);
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(&loaded_a));
        let evictor: Arc<dyn P2pSessionEvictor> = Arc::new(MockP2pSessionEvictor::new(0));
        let mut ctx = ProductionLiveTrustApplyContext::new(
            live.clone(),
            evictor,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            None,
            0,
        );
        // 1. Capture initial snapshot (Arc<Snapshot> with sequence=1).
        let snap_for_rollback = ctx.snapshot_active().expect("snapshot ok");
        // 2. Swap to candidate sequence=2.
        ctx.swap_trust_state(&loaded_b).expect("swap ok");
        assert_eq!(live.snapshot().expect("post-swap").sequence(), 2);
        // 3. Rollback restores sequence=1.
        ctx.rollback_trust_state(snap_for_rollback)
            .expect("rollback ok");
        assert_eq!(live.snapshot().expect("post-rollback").sequence(), 1);
    }

    #[test]
    fn rollback_trust_state_rejects_wrong_type() {
        // Programming-error guard: if Run 070 ever hands a non-Arc
        // value back, the adapter surfaces a clean fail-closed
        // error rather than panicking on downcast.
        let loaded = fresh_loaded_devnet_bundle(1);
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(&loaded));
        let evictor: Arc<dyn P2pSessionEvictor> = Arc::new(MockP2pSessionEvictor::new(0));
        let mut ctx = ProductionLiveTrustApplyContext::new(
            live,
            evictor,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            None,
            0,
        );
        let wrong: Box<dyn std::any::Any + Send + Sync> = Box::new("not an Arc".to_string());
        match ctx.rollback_trust_state(wrong) {
            Err(s) => {
                assert!(s.contains("Run 073"), "{}", s);
                assert!(s.contains("programming error"), "{}", s);
                assert!(s.contains("fail-closed"), "{}", s);
            }
            Ok(()) => panic!("rollback must reject wrong type"),
        }
    }

    #[test]
    fn evict_sessions_forwards_to_evictor_with_reload_apply_reason() {
        let loaded = fresh_loaded_devnet_bundle(1);
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(&loaded));
        let mock = Arc::new(MockP2pSessionEvictor::new(3));
        let evictor: Arc<dyn P2pSessionEvictor> = mock.clone();
        let mut ctx = ProductionLiveTrustApplyContext::new(
            live,
            evictor,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            None,
            0,
        );
        let n = ctx.evict_sessions().expect("evict ok");
        assert_eq!(n, 3);
        let reports = mock.recorded_reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].reason, EvictionReason::TrustBundleReloadApply);
        assert_eq!(reports[0].attempted, 3);
        assert_eq!(reports[0].evicted, 3);
        assert_eq!(reports[0].failed, 0);
    }

    #[test]
    fn evict_sessions_partial_failure_surfaces_error_with_invariant_counts() {
        let loaded = fresh_loaded_devnet_bundle(1);
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(&loaded));
        let mock = Arc::new(MockP2pSessionEvictor::new(5));
        mock.arrange_failure(2);
        let evictor: Arc<dyn P2pSessionEvictor> = mock.clone();
        let mut ctx = ProductionLiveTrustApplyContext::new(
            live,
            evictor,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            None,
            0,
        );
        match ctx.evict_sessions() {
            Err(msg) => {
                assert!(msg.contains("Run 073"), "{}", msg);
                assert!(msg.contains("partial failure"), "{}", msg);
                assert!(msg.contains("attempted=5"), "{}", msg);
                assert!(msg.contains("evicted=3"), "{}", msg);
                assert!(msg.contains("failed=2"), "{}", msg);
                assert!(msg.contains("rolling back"), "{}", msg);
            }
            Ok(_) => panic!("partial failure must surface as Err for rollback"),
        }
    }

    #[test]
    fn commit_sequence_first_load_writes_persistence_record() {
        let loaded = fresh_loaded_devnet_bundle(7);
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(&loaded));
        let evictor: Arc<dyn P2pSessionEvictor> = Arc::new(NoActiveSessionsEvictor::new());
        let dir = tmpdir("commit-first-load");
        let path = sequence_file_path(&dir);
        let mut ctx = ProductionLiveTrustApplyContext::new(
            live,
            evictor,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            Some(path.clone()),
            123,
        );
        assert!(!path.exists());
        ctx.commit_sequence(&loaded).expect("commit ok");
        let rec = load_record(&path)
            .expect("load")
            .expect("record was written");
        assert_eq!(rec.highest_sequence, 7);
    }

    #[test]
    fn commit_sequence_without_data_dir_surfaces_clean_error() {
        let loaded = fresh_loaded_devnet_bundle(1);
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(&loaded));
        let evictor: Arc<dyn P2pSessionEvictor> = Arc::new(NoActiveSessionsEvictor::new());
        let mut ctx = ProductionLiveTrustApplyContext::new(
            live,
            evictor,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            None,
            0,
        );
        match ctx.commit_sequence(&loaded) {
            Err(msg) => {
                assert!(msg.contains("--data-dir"), "{}", msg);
                assert!(msg.contains("Run 073"), "{}", msg);
                assert!(msg.contains("fail-closed"), "{}", msg);
            }
            Ok(()) => panic!("missing data-dir must fail closed"),
        }
    }
}
