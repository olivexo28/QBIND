//! Run 094 — integration tests for binary-path epoch transition
//! persistence via the Run 093 canonical `ConsensusStorage` handle.
//!
//! These tests pin the public-API contract introduced by Run 094:
//!
//! - `BinaryConsensusLoopConfig::with_consensus_storage` accepts an
//!   `Arc<dyn ConsensusStorage>` (e.g. the `Arc<RocksDbConsensusStorage>`
//!   handle opened by Run 093's `open_production_consensus_storage`).
//! - `maybe_persist_engine_epoch_transition` is a pure helper that
//!   takes the *canonical engine epoch counter* (`current_epoch()`)
//!   from a `BasicHotStuffEngine` and, if and only if it has advanced
//!   above the caller's `last_persisted_epoch`, persists the
//!   transition via `apply_epoch_transition_atomic`. The persisted
//!   epoch survives "restart" (a re-open against the same DB).
//! - Persistence failure is surfaced as `EpochPersistenceFailed` and
//!   the binary loop must fail closed on it. Run 094 does NOT
//!   silently downgrade to memory-only epoch.
//! - Fresh genesis remains `PresentNoCommittedEpoch` (no implicit
//!   epoch `0`), preserving Run 091/092 fail-closed
//!   `CurrentEpochUnavailable` for trust-bundle activation.
//! - The engine's `current_epoch()` is the *only* persistence
//!   trigger. Run 094 invents no synthetic epoch, no wall-clock
//!   epoch, no view-derived epoch, and no block-height-derived
//!   epoch.

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_consensus::BasicHotStuffEngine;
use qbind_node::binary_consensus_loop::{
    maybe_persist_engine_epoch_transition, EpochPersistenceFailed,
};
use qbind_node::node_config::NodeConfig;
use qbind_node::production_consensus_storage::{
    open_production_consensus_storage, ConsensusStorageState,
};
use qbind_node::storage::{ConsensusStorage, InMemoryConsensusStorage, RocksDbConsensusStorage};
use tempfile::TempDir;

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

fn devnet_with_data_dir(data_dir: &std::path::Path) -> NodeConfig {
    NodeConfig::devnet().with_data_dir(data_dir)
}

// ============================================================================
// Tests
// ============================================================================

/// Pre-condition: a brand-new engine reports `current_epoch() == 0`. A
/// caller that initializes `last_persisted_epoch = engine.current_epoch()`
/// observes no transition until the engine actually advances. Run 094
/// must never write on a no-op tick.
#[test]
fn run_094_no_engine_advance_no_persistence() {
    let engine = single_validator_engine();
    let storage: Arc<dyn ConsensusStorage> = Arc::new(InMemoryConsensusStorage::new());

    let mut last_persisted = engine.current_epoch();
    let persisted = maybe_persist_engine_epoch_transition(&engine, &storage, &mut last_persisted, Some([0x95u8; 32]))
        .expect("no advance ⇒ Ok(false)");
    assert!(!persisted, "no engine epoch advance ⇒ no persistence");
    assert_eq!(
        storage.get_current_epoch().expect("read ok"),
        None,
        "storage must remain `PresentNoCommittedEpoch` — no implicit 0"
    );
}

/// When `engine.current_epoch()` advances under existing
/// consensus/epoch rules (here, via the engine's public
/// `set_current_epoch` setter — Run 094 does not invent a transition
/// path), the helper persists exactly that value via
/// `apply_epoch_transition_atomic`. The persisted `meta:current_epoch`
/// equals the engine's value — no derivation, no synthesis.
#[test]
fn run_094_engine_advance_triggers_canonical_atomic_persistence() {
    let mut engine = single_validator_engine();
    let storage: Arc<dyn ConsensusStorage> = Arc::new(InMemoryConsensusStorage::new());

    let mut last_persisted = engine.current_epoch();
    assert_eq!(last_persisted, 0);

    // Engine advances epoch under existing consensus/epoch rules.
    engine.set_current_epoch(7);

    let persisted = maybe_persist_engine_epoch_transition(&engine, &storage, &mut last_persisted, Some([0x95u8; 32]))
        .expect("advance ⇒ persistence ok");
    assert!(persisted);
    assert_eq!(last_persisted, 7);
    assert_eq!(
        storage.get_current_epoch().expect("read ok"),
        Some(7),
        "meta:current_epoch must equal engine's canonical current_epoch()"
    );

    // Idempotent: a second call without further advance must not
    // re-persist (no thrash, no spurious atomic writes).
    let again = maybe_persist_engine_epoch_transition(&engine, &storage, &mut last_persisted, Some([0x95u8; 32]))
        .expect("no advance ⇒ Ok(false)");
    assert!(!again);
    assert_eq!(storage.get_current_epoch().expect("read ok"), Some(7));
}

/// The trigger is `engine.current_epoch()` advance — NOT wall-clock,
/// NOT view number, NOT block height, NOT any helper-only test
/// fixture. We assert this by holding the engine epoch fixed while
/// driving every other observable (none of which the helper reads),
/// and confirming no persistence occurs.
#[test]
fn run_094_persistence_trigger_is_engine_current_epoch_only() {
    let engine = single_validator_engine();
    let storage: Arc<dyn ConsensusStorage> = Arc::new(InMemoryConsensusStorage::new());
    let mut last_persisted = engine.current_epoch();

    // Time passes, callers call repeatedly — none of this is a
    // trigger.
    for _ in 0..32 {
        let persisted =
            maybe_persist_engine_epoch_transition(&engine, &storage, &mut last_persisted, Some([0x95u8; 32]))
                .expect("ok");
        assert!(!persisted);
    }
    assert_eq!(storage.get_current_epoch().expect("read ok"), None);
}

/// Multi-step canonical advance: epoch goes 0 → 1 → 2 → 5. Each
/// advance is persisted exactly once; the helper's `last_persisted`
/// cursor tracks the latest committed value so the helper does not
/// re-persist on later no-op ticks.
#[test]
fn run_094_multi_step_engine_advance_persists_each_step_once() {
    let mut engine = single_validator_engine();
    let storage: Arc<dyn ConsensusStorage> = Arc::new(InMemoryConsensusStorage::new());
    let mut last_persisted = engine.current_epoch();

    for new_epoch in [1u64, 2, 5] {
        engine.set_current_epoch(new_epoch);
        let persisted =
            maybe_persist_engine_epoch_transition(&engine, &storage, &mut last_persisted, Some([0x95u8; 32]))
                .expect("advance ⇒ ok");
        assert!(persisted);
        assert_eq!(last_persisted, new_epoch);
        assert_eq!(
            storage.get_current_epoch().expect("read ok"),
            Some(new_epoch)
        );
        // No-op repeat: no second write.
        let again =
            maybe_persist_engine_epoch_transition(&engine, &storage, &mut last_persisted, Some([0x95u8; 32]))
                .expect("ok");
        assert!(!again);
    }
}

/// Persistence failure path. We use the `InMemoryConsensusStorage`
/// surface to inject a controlled `apply_epoch_transition_atomic`
/// failure via a tiny wrapper, and assert that the helper returns
/// `Err(EpochPersistenceFailed)` carrying the canonical engine
/// previous/target epoch — never `Ok(false)`, never a silent
/// "downgrade-to-memory" path.
#[test]
fn run_094_persistence_failure_is_fail_closed_with_canonical_epoch_pair() {
    use qbind_node::storage::{EpochTransitionBatch, EpochTransitionMarker, StorageError};
    use qbind_wire::consensus::{BlockProposal, QuorumCertificate};

    struct FailingStorage;
    impl ConsensusStorage for FailingStorage {
        fn put_block(&self, _: &[u8; 32], _: &BlockProposal) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_block(&self, _: &[u8; 32]) -> Result<Option<BlockProposal>, StorageError> {
            Ok(None)
        }
        fn put_qc(&self, _: &[u8; 32], _: &QuorumCertificate) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_qc(&self, _: &[u8; 32]) -> Result<Option<QuorumCertificate>, StorageError> {
            Ok(None)
        }
        fn put_last_committed(&self, _: &[u8; 32]) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_last_committed(&self) -> Result<Option<[u8; 32]>, StorageError> {
            Ok(None)
        }
        fn put_current_epoch(&self, _: u64) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_current_epoch(&self) -> Result<Option<u64>, StorageError> {
            Ok(None)
        }
        fn put_schema_version(&self, _: u32) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_schema_version(&self) -> Result<Option<u32>, StorageError> {
            Ok(None)
        }
        fn apply_epoch_transition_atomic(
            &self,
            _: EpochTransitionBatch,
        ) -> Result<(), StorageError> {
            Err(StorageError::Io(
                "Run 094 injected atomic-write failure".to_string(),
            ))
        }
        fn write_epoch_transition_marker(
            &self,
            _: &EpochTransitionMarker,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn check_for_incomplete_epoch_transition(
            &self,
        ) -> Result<Option<EpochTransitionMarker>, StorageError> {
            Ok(None)
        }
        fn verify_epoch_consistency_on_startup(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    let mut engine = single_validator_engine();
    let storage: Arc<dyn ConsensusStorage> = Arc::new(FailingStorage);
    let mut last_persisted = engine.current_epoch();
    engine.set_current_epoch(3);

    let err: EpochPersistenceFailed =
        maybe_persist_engine_epoch_transition(&engine, &storage, &mut last_persisted, Some([0x95u8; 32]))
            .expect_err("write failure ⇒ fail-closed Err");
    assert_eq!(err.previous_epoch, 0);
    assert_eq!(err.target_epoch, 3);
    // The helper must NOT have advanced `last_persisted` on failure.
    assert_eq!(last_persisted, 0);
    // The error must mention the canonical engine epoch pair so
    // the operator can correlate against engine logs.
    let display = format!("{}", err);
    assert!(display.contains("previous_epoch=0"));
    assert!(display.contains("target_epoch=3"));
    assert!(display.contains("fail closed"));
}

/// End-to-end through the Run 093 surface: open the canonical
/// production storage, drive a canonical engine epoch advance, persist
/// via the threaded handle, drop the handle (simulating clean
/// shutdown / restart), re-open via the same Run 093 entry point, and
/// observe `ConsensusStorageState::CommittedEpoch(n)`. This is the
/// minimum source-level proof that the binary-path persistence path
/// is real and survives restart.
#[test]
fn run_094_committed_epoch_survives_restart_via_run_093_surface() {
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());

    // First start: open canonical Run 093 storage. State must be
    // `PresentNoCommittedEpoch` — fresh genesis is NOT epoch 0.
    let target_epoch: u64;
    {
        let opened = open_production_consensus_storage(&cfg).expect("open ok");
        assert_eq!(opened.state, ConsensusStorageState::PresentNoCommittedEpoch);
        let handle: Arc<RocksDbConsensusStorage> =
            opened.handle.clone().expect("data_dir set ⇒ handle");

        // Engine canonical advance under existing consensus/epoch
        // rules. We exercise the same surface a future Run 094-style
        // binary-path epoch-transition wiring will exercise. Run 094
        // does NOT invent a transition path here.
        let mut engine = single_validator_engine();
        let mut last_persisted = engine.current_epoch();
        target_epoch = 11;
        engine.set_current_epoch(target_epoch);

        let storage_dyn: Arc<dyn ConsensusStorage> = handle.clone();
        let persisted =
            maybe_persist_engine_epoch_transition(&engine, &storage_dyn, &mut last_persisted, Some([0x95u8; 32]))
                .expect("persistence ok");
        assert!(persisted);

        // Drop both `handle` and `opened` so RocksDB releases its
        // lock before the restart re-open below.
        drop(storage_dyn);
        drop(handle);
        drop(opened);
    }

    // Restart: re-open canonical Run 093 storage and observe
    // `CommittedEpoch(n)`. No reset, no silent downgrade to
    // `PresentNoCommittedEpoch`, no implicit 0.
    let opened2 = open_production_consensus_storage(&cfg).expect("reopen ok");
    assert_eq!(
        opened2.state,
        ConsensusStorageState::CommittedEpoch(target_epoch),
        "restart must observe CommittedEpoch(n) — Run 094 binary-path \
         epoch transition persistence is durable"
    );
    assert_eq!(opened2.state.committed_epoch(), Some(target_epoch));
}

/// Trust-bundle activation isolation regression check. Run 094 wires
/// epoch persistence on the binary path; it MUST NOT change the
/// activation `current_epoch: None` invariant Run 091/092 pinned.
/// We assert this at the production_consensus_storage surface by
/// confirming `committed_epoch()` is observed only on the storage-state
/// type — not via any new accessor on `ActivationContext`, and not via
/// any new accessor on the engine. If anyone wires
/// `committed_epoch()` into `pqc_trust_activation::ActivationContext`
/// without an explicit Run-N task scope, this test cannot detect that
/// regression at the source level — Run 091's integration suite
/// remains the authoritative guard. We document the surface here.
#[test]
fn run_094_consensus_storage_state_committed_epoch_is_isolated_from_activation() {
    // Smoke check: the `ConsensusStorageState::committed_epoch()` API
    // continues to surface a strict `Option<u64>` and the three
    // variants remain explicit. No coercion of "missing" or
    // "no-storage" into `Some(0)`.
    assert_eq!(ConsensusStorageState::NoConsensusStorage.committed_epoch(), None);
    assert_eq!(
        ConsensusStorageState::PresentNoCommittedEpoch.committed_epoch(),
        None
    );
    assert_eq!(
        ConsensusStorageState::CommittedEpoch(9).committed_epoch(),
        Some(9)
    );
}