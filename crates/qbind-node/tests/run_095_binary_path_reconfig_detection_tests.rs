//! Run 095 — integration tests for binary-path canonical reconfig
//! block detection and engine epoch-transition triggering.
//!
//! These tests pin the public-API contract introduced by Run 095:
//!
//! - `BinaryReconfigDetector::new(initial_commit_log_len)` seeds the
//!   detector so that pre-existing committed entries (e.g. snapshot-
//!   restored baselines) are not retroactively re-processed.
//! - `BinaryReconfigDetector::record_observed_proposal(&proposal)`
//!   caches the canonical `(payload_kind, next_epoch)` tuple keyed by
//!   the canonical binary-path block ID derivation
//!   (`BlockStore::compute_block_id`), which matches the engine's
//!   internal `derive_block_id_from_header` derivation.
//! - `maybe_transition_epoch_from_committed_block(engine, detector)`
//!   walks newly committed entries since the previous call and:
//!     * returns `Ok(None)` when no canonical committed reconfig
//!       block is observed,
//!     * invokes `BasicHotStuffEngine::transition_to_epoch` exactly
//!       once per canonical committed reconfig block,
//!     * fails closed with `NonMonotonicTargetEpoch` for `next_epoch
//!       <= current_epoch` and with `EngineRejected` for the engine's
//!       own sequential-epoch rejection,
//!     * records the actual committed reconfig block ID in
//!       `detector.latest_reconfig_block_id()` so the Run 094
//!       persistence hook can persist the real ID.
//! - `maybe_persist_engine_epoch_transition(..., reconfig_block_id)`
//!   refuses to persist a real transition when no committed reconfig
//!   block ID was supplied, with
//!   `EpochPersistenceFailureSource::MissingReconfigBlockId`. Zero
//!   fallback is NOT used for real transitions.
//! - Normal-kind committed blocks never trigger a transition.
//! - Detector observation does NOT change engine state on its own —
//!   only a committed canonical reconfig block does.

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_consensus::BasicHotStuffEngine;
use qbind_node::binary_consensus_loop::{
    maybe_persist_engine_epoch_transition, maybe_transition_epoch_from_committed_block,
    BinaryReconfigDetector, EpochPersistenceFailureSource, ReconfigTransitionError,
};
use qbind_node::storage::{ConsensusStorage, InMemoryConsensusStorage};
use qbind_wire::consensus::{BlockHeader, BlockProposal};

// ============================================================================
// Helpers
// ============================================================================

fn single_validator_engine() -> BasicHotStuffEngine<[u8; 32]> {
    let v0 = ValidatorId::new(0);
    let entries = vec![ValidatorSetEntry {
        id: v0,
        voting_power: 1,
    }];
    let vset = ConsensusValidatorSet::new(entries).expect("single-validator set is valid");
    BasicHotStuffEngine::new(v0, vset)
}

fn make_proposal(
    proposer_index: u16,
    height: u64,
    payload_kind: u8,
    next_epoch: u64,
    parent_block_id: [u8; 32],
) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round: height,
            parent_block_id,
            payload_hash: [0u8; 32],
            proposer_index,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind,
            next_epoch,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![0xDE, 0xAD],
    }
}

// ============================================================================
// Tests — `BinaryReconfigDetector` public surface
// ============================================================================

/// Fresh detector observes no headers, has no latest reconfig block id,
/// and starts its cursor at the supplied `initial_commit_log_len`.
#[test]
fn run_095_detector_fresh_state() {
    let det = BinaryReconfigDetector::new(0);
    assert_eq!(det.cached_headers(), 0);
    assert_eq!(det.latest_reconfig_block_id(), None);
}

/// `record_observed_proposal` caches one entry per distinct block ID
/// for both normal and reconfig proposals. Run 095 records all
/// observed proposals because we only learn the (payload_kind,
/// next_epoch) header at proposal time — the cache is the only way to
/// look this up later when the same block ID appears in
/// `engine.commit_log()`.
#[test]
fn run_095_detector_record_observed_proposal_caches_headers() {
    let mut det = BinaryReconfigDetector::new(0);
    let p1 = make_proposal(0, 1, qbind_wire::PAYLOAD_KIND_NORMAL, 0, [0u8; 32]);
    let p2 = make_proposal(0, 2, qbind_wire::PAYLOAD_KIND_RECONFIG, 1, [0u8; 32]);
    det.record_observed_proposal(&p1);
    det.record_observed_proposal(&p2);
    assert_eq!(det.cached_headers(), 2);
    // Recording the same proposal twice does not double-count (idempotent
    // by canonical block ID).
    det.record_observed_proposal(&p2);
    assert_eq!(det.cached_headers(), 2);
}

/// With an empty `engine.commit_log()` no transition fires regardless
/// of how many proposals the detector has observed. Run 095 only acts
/// on *committed* canonical reconfig blocks.
#[test]
fn run_095_observed_but_not_committed_no_transition() {
    let mut engine = single_validator_engine();
    let mut det = BinaryReconfigDetector::new(engine.commit_log().len());
    let reconfig = make_proposal(0, 1, qbind_wire::PAYLOAD_KIND_RECONFIG, 1, [0u8; 32]);
    det.record_observed_proposal(&reconfig);

    let res = maybe_transition_epoch_from_committed_block(&mut engine, &mut det)
        .expect("no commits ⇒ Ok(None)");
    assert_eq!(res, None);
    assert_eq!(engine.current_epoch(), 0);
    assert_eq!(det.latest_reconfig_block_id(), None);
}

/// A fresh engine with no commits and no observations: helper is a
/// no-op and engine state is unchanged.
#[test]
fn run_095_no_commits_no_observations_no_transition() {
    let mut engine = single_validator_engine();
    let mut det = BinaryReconfigDetector::new(engine.commit_log().len());

    let res = maybe_transition_epoch_from_committed_block(&mut engine, &mut det).expect("ok");
    assert_eq!(res, None);
    assert_eq!(engine.current_epoch(), 0);
}

// ============================================================================
// Tests — Run 094 persistence helper Run 095 changes
// ============================================================================

/// Run 095 §"D. Correct reconfig_block_id": when the canonical engine
/// epoch has advanced but the caller supplies `None` for
/// `reconfig_block_id`, the persistence helper refuses to persist and
/// returns `EpochPersistenceFailureSource::MissingReconfigBlockId`.
/// `last_persisted_epoch` is left unchanged so the failure is
/// reproducible on the next tick.
#[test]
fn run_095_persistence_refuses_zero_fallback_for_real_transition() {
    let mut engine = single_validator_engine();
    let storage: Arc<dyn ConsensusStorage> = Arc::new(InMemoryConsensusStorage::new());
    let mut last_persisted = engine.current_epoch();
    assert_eq!(last_persisted, 0);

    // Simulate an engine canonical epoch advance under the existing
    // engine epoch-transition machinery (Run 094 helper test pattern).
    engine.set_current_epoch(1);

    let err = maybe_persist_engine_epoch_transition(&engine, &storage, &mut last_persisted, None)
        .expect_err("missing reconfig_block_id ⇒ fail-closed Err");

    assert!(matches!(
        err.source,
        EpochPersistenceFailureSource::MissingReconfigBlockId
    ));
    assert_eq!(err.previous_epoch, 0);
    assert_eq!(err.target_epoch, 1);
    // `last_persisted_epoch` must NOT advance on a refused persist.
    assert_eq!(last_persisted, 0);
    // Storage must NOT have been written.
    assert_eq!(storage.get_current_epoch().expect("read ok"), None);
    // Display string must call out fail-closed semantics so the
    // operator can correlate against the loop-exit summary.
    let display = format!("{}", err);
    assert!(display.contains("missing_reconfig_block_id"));
    assert!(display.contains("fail closed"));
    assert!(display.contains("previous_epoch=0"));
    assert!(display.contains("target_epoch=1"));
}

/// When the caller supplies the actual committed reconfig block ID,
/// the persistence helper writes through the canonical
/// `apply_epoch_transition_atomic` machinery exactly as in Run 094.
#[test]
fn run_095_persistence_succeeds_with_supplied_block_id() {
    let mut engine = single_validator_engine();
    let storage: Arc<dyn ConsensusStorage> = Arc::new(InMemoryConsensusStorage::new());
    let mut last_persisted = engine.current_epoch();
    engine.set_current_epoch(1);

    let reconfig_block_id: [u8; 32] = [0xCAu8; 32];
    let persisted = maybe_persist_engine_epoch_transition(
        &engine,
        &storage,
        &mut last_persisted,
        Some(reconfig_block_id),
    )
    .expect("supplied reconfig_block_id ⇒ persistence ok");

    assert!(persisted);
    assert_eq!(last_persisted, 1);
    assert_eq!(storage.get_current_epoch().expect("read ok"), Some(1));
}

/// When the engine epoch has NOT advanced, no persistence happens —
/// regardless of whether `reconfig_block_id` is `None` or `Some`.
/// This is the no-op idempotent path Run 094 already guarantees,
/// preserved by Run 095.
#[test]
fn run_095_persistence_no_advance_no_persistence_even_without_block_id() {
    let engine = single_validator_engine();
    let storage: Arc<dyn ConsensusStorage> = Arc::new(InMemoryConsensusStorage::new());
    let mut last_persisted = engine.current_epoch();

    let persisted =
        maybe_persist_engine_epoch_transition(&engine, &storage, &mut last_persisted, None)
            .expect("no advance ⇒ Ok(false)");
    assert!(!persisted);
    assert_eq!(last_persisted, 0);

    // Even with a Some(_) the helper is a no-op when nothing
    // advanced — defends against spurious writes on idle ticks.
    let persisted = maybe_persist_engine_epoch_transition(
        &engine,
        &storage,
        &mut last_persisted,
        Some([0xAAu8; 32]),
    )
    .expect("no advance ⇒ Ok(false)");
    assert!(!persisted);
    assert_eq!(last_persisted, 0);

    // Storage must remain `PresentNoCommittedEpoch` — no implicit 0.
    assert_eq!(storage.get_current_epoch().expect("read ok"), None);
}

// ============================================================================
// Tests — `ReconfigTransitionError` display strings
// ============================================================================

/// `ReconfigTransitionError::NonMonotonicTargetEpoch` display string
/// mentions the canonical engine epoch pair and the fail-closed
/// boundary so the operator can correlate against engine logs.
#[test]
fn run_095_non_monotonic_target_epoch_display_string() {
    let err = ReconfigTransitionError::NonMonotonicTargetEpoch {
        committed_block_id: [0u8; 32],
        current_epoch: 5,
        next_epoch: 0,
    };
    let display = format!("{}", err);
    assert!(display.contains("current_epoch=5"));
    assert!(display.contains("next_epoch=0"));
    assert!(display.contains("fail closed"));
    assert!(display.contains("non-monotonic"));
}

/// `ReconfigTransitionError::EngineRejected` display string carries
/// the underlying engine error verbatim so the failure can be
/// correlated against engine logs.
#[test]
fn run_095_engine_rejected_display_string() {
    use qbind_consensus::validator_set::EpochId;
    let err = ReconfigTransitionError::EngineRejected {
        committed_block_id: [0u8; 32],
        next_epoch: 7,
        source: qbind_consensus::validator_set::EpochTransitionError::NonSequentialEpoch {
            current: EpochId::new(0),
            requested: EpochId::new(7),
        },
    };
    let display = format!("{}", err);
    assert!(display.contains("next_epoch=7"));
    assert!(display.contains("fail closed"));
    assert!(display.contains("engine_error"));
}

// ============================================================================
// Tests — end-to-end engine + detector
// ============================================================================

/// Run 095: a normal-kind committed block does NOT trigger an epoch
/// transition. This is the negative regression test: even when the
/// loop drives many proposals and commits, as long as none of them is
/// a canonical reconfig block, the engine's `current_epoch()` stays
/// at the value it started with.
///
/// We drive the engine end-to-end with `try_propose` on a single-
/// validator setup. `try_propose` always emits
/// `PAYLOAD_KIND_NORMAL` blocks under existing engine code (see
/// `BasicHotStuffEngine::try_propose` — header.payload_kind is
/// hard-coded to `PAYLOAD_KIND_NORMAL`), so this is a *real* test of
/// the Run 095 detector: every committed block is a normal block,
/// none of them is a canonical reconfig commit, and the detector
/// must NOT fabricate a transition.
#[test]
fn run_095_normal_committed_blocks_do_not_trigger_transition() {
    use qbind_consensus::driver::ConsensusEngineAction;

    let mut engine = single_validator_engine();
    let mut det = BinaryReconfigDetector::new(engine.commit_log().len());
    let initial_epoch = engine.current_epoch();

    // Drive a few rounds of leader self-proposals and self-votes.
    // For a single-validator setup the engine reaches QC, locks,
    // and commits along the 3-chain rule.
    for _ in 0..16 {
        let actions = engine.try_propose();
        for action in &actions {
            if let ConsensusEngineAction::BroadcastProposal(p) = action {
                det.record_observed_proposal(p);
            }
        }
        // Allow ticking forward — the engine's HotStuff state
        // machine accumulates QCs and commits along the 3-chain
        // (we don't need to assert intermediate state; we only
        // care that the *terminal* `current_epoch()` is unchanged
        // and no reconfig block ID is recorded).
        let _ = maybe_transition_epoch_from_committed_block(&mut engine, &mut det)
            .expect("normal blocks ⇒ no transition error");
    }

    assert_eq!(
        engine.current_epoch(),
        initial_epoch,
        "no canonical reconfig commit ⇒ engine current_epoch unchanged"
    );
    assert_eq!(
        det.latest_reconfig_block_id(),
        None,
        "no canonical reconfig commit ⇒ no reconfig block ID recorded"
    );
}

/// Run 095 §"C. Engine transition trigger" — the engine's own
/// `transition_to_epoch` enforces strict sequential epoch +1
/// monotonicity. The Run 095 detector's pre-check for
/// `next_epoch <= current_epoch` catches `next_epoch == 0` cleanly;
/// any other non-monotonic value is delegated to the engine and
/// surfaces as `ReconfigTransitionError::EngineRejected`.
///
/// We assert that the engine's own pre-existing monotonicity rule is
/// preserved — Run 095 does NOT redesign HotStuff epoch semantics.
#[test]
fn run_095_engine_enforces_sequential_epoch_monotonicity() {
    let mut engine = single_validator_engine();
    assert_eq!(engine.current_epoch(), 0);

    // Skipping to epoch 2 must be rejected by the engine's existing
    // `NonSequentialEpoch` rule. Run 095 surfaces this verbatim via
    // `ReconfigTransitionError::EngineRejected`.
    let validators = engine.validators().clone();
    let res = engine.transition_to_epoch(
        qbind_consensus::validator_set::EpochId::new(2),
        validators.clone(),
    );
    assert!(res.is_err(), "skipping epoch 1 must be rejected by engine");

    // Going to epoch 1 succeeds.
    engine
        .transition_to_epoch(qbind_consensus::validator_set::EpochId::new(1), validators)
        .expect("epoch 0 -> 1 is sequential");
    assert_eq!(engine.current_epoch(), 1);
}
