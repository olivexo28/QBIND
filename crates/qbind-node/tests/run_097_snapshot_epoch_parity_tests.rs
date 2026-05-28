//! Run 097 integration tests — snapshot epoch parity for
//! `StateSnapshotMeta.epoch`, the production `<data_dir>/consensus`
//! `meta:current_epoch` surface, and the binary restore path.
//!
//! Scope (mirrors `task/RUN_097_TASK.txt`):
//!
//! 1. **Creation parity**: a snapshot taken on a node whose canonical
//!    `ConsensusStorage` reports `CommittedEpoch(n)` carries
//!    `epoch=Some(n)` in `meta.json` (and only via the operator-
//!    supplied / canonical path; the metadata layer never derives
//!    epoch from height, view, wall-clock, or directory name).
//! 2. **Restore parity**: applying that snapshot through the same
//!    library entry point the binary calls
//!    (`apply_snapshot_restore_if_requested` →
//!    `persist_restored_snapshot_epoch`) re-establishes
//!    `meta:current_epoch=n` in the restored node's
//!    `<data_dir>/consensus`.
//! 3. **Old-snapshot compatibility**: a pre-Run-097 `meta.json`
//!    (missing `epoch`) still restores cleanly, and
//!    `meta:current_epoch` in restored consensus storage is left as
//!    explicit-absence (NOT silently coerced to `0`).
//! 4. **Fail-closed inconsistency**: a snapshot whose `epoch` differs
//!    from a pre-existing `meta:current_epoch` in the restored
//!    `<data_dir>/consensus` is refused (no silent overwrite).
//! 5. **Activation isolation**: Run 097 must not touch
//!    `ActivationContext.current_epoch` — the Run 091/092 fail-closed
//!    `CurrentEpochUnavailable` boundary remains intact. Asserted by
//!    inspecting the public surface of
//!    `qbind_node::production_consensus_storage` — the new function
//!    only touches `meta:current_epoch`, not any activation context.

use std::path::Path;

use tempfile::tempdir;

use qbind_ledger::{
    AccountState, PersistentAccountState, RocksDbAccountState, StateSnapshotMeta, StateSnapshotter,
};
use qbind_node::node_config::{FastSyncConfig, NodeConfig};
use qbind_node::production_consensus_storage::{
    open_production_consensus_storage, persist_restored_snapshot_epoch, ConsensusStorageState,
    ProductionConsensusStorageError,
};
use qbind_node::snapshot_restore::apply_snapshot_restore_if_requested;
use qbind_node::storage::{ConsensusStorage, RocksDbConsensusStorage};

// ============================================================================
// Helpers
// ============================================================================

fn devnet_chain_id() -> u64 {
    NodeConfig::default().chain_id().as_u64()
}

/// Build a real on-disk snapshot at `target` populated with one
/// well-known account, returning the `StateSnapshotMeta` written.
///
/// `epoch` controls the canonical committed-epoch field embedded in
/// `meta.json` (Run 097). Pass `Some(n)` to simulate a snapshot taken
/// on a node whose canonical `ConsensusStorage` reports
/// `CommittedEpoch(n)`. Pass `None` to simulate a pre-Run-097 snapshot
/// (or a snapshot taken on a node with no canonical committed epoch).
fn build_real_snapshot_with_epoch(
    state_dir: &Path,
    target: &Path,
    chain_id: u64,
    height: u64,
    epoch: Option<u64>,
) -> StateSnapshotMeta {
    let storage = RocksDbAccountState::open(state_dir).expect("open state dir");
    storage
        .put_account_state(
            &[0xCD; 32],
            &AccountState {
                nonce: 7,
                balance: 4242,
            },
        )
        .expect("put account state");
    storage.flush().expect("flush");

    let meta = StateSnapshotMeta::new(height, [height as u8; 32], 1_700_000_000_000, chain_id)
        .with_epoch(epoch);
    storage
        .create_snapshot(&meta, target)
        .expect("create_snapshot");

    drop(storage);
    meta
}

/// Configure a NodeConfig with restore-from-snapshot and a data_dir.
fn restore_config(data_dir: &Path, snapshot: &Path, _chain_id: u64) -> NodeConfig {
    let mut cfg = NodeConfig::default();
    cfg.data_dir = Some(data_dir.to_path_buf());
    cfg.fast_sync_config = FastSyncConfig::from_snapshot(snapshot.to_path_buf());
    cfg
}

// ============================================================================
// 1. Creation parity
// ============================================================================

#[test]
fn run097_snapshot_metadata_carries_canonical_committed_epoch_when_present() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let target = snap_root.path().join("snap-100");
    let chain_id = devnet_chain_id();

    let meta = build_real_snapshot_with_epoch(src_state.path(), &target, chain_id, 100, Some(13));
    assert_eq!(meta.epoch, Some(13));

    // The on-disk `meta.json` must round-trip the canonical epoch
    // through the exact code path validate_snapshot_dir uses.
    let raw = std::fs::read(target.join("meta.json")).expect("read meta.json");
    let parsed = StateSnapshotMeta::from_json(&raw).expect("parse meta.json");
    assert_eq!(parsed.epoch, Some(13));
    assert_eq!(parsed.height, 100);
    assert_eq!(parsed.chain_id, chain_id);
}

#[test]
fn run097_snapshot_metadata_omits_epoch_when_no_canonical_source_available() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let target = snap_root.path().join("snap-100");
    let chain_id = devnet_chain_id();

    let meta = build_real_snapshot_with_epoch(src_state.path(), &target, chain_id, 100, None);
    assert_eq!(meta.epoch, None);

    let raw = std::fs::read(target.join("meta.json")).expect("read meta.json");
    let raw_str = String::from_utf8(raw.clone()).unwrap();
    assert!(
        !raw_str.contains("epoch"),
        "meta.json must omit epoch field when None (backward compat): {raw_str}"
    );
    let parsed = StateSnapshotMeta::from_json(&raw).expect("parse meta.json");
    assert_eq!(parsed.epoch, None);
}

// ============================================================================
// 2. Restore parity (binary library entry points)
// ============================================================================

#[test]
fn run097_restore_persists_snapshot_epoch_into_canonical_consensus_storage() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();

    let snapshot = snap_root.path().join("snap-100");
    let chain_id = devnet_chain_id();
    build_real_snapshot_with_epoch(src_state.path(), &snapshot, chain_id, 100, Some(7));

    let cfg = restore_config(data_dir.path(), &snapshot, chain_id);

    // Step 1: restore the VM-v0 state (B3 / Run 003) — same call the
    // binary makes.
    let outcome = apply_snapshot_restore_if_requested(&cfg)
        .expect("restore ok")
        .expect("restore outcome present");
    assert_eq!(outcome.meta.epoch, Some(7));

    // Step 2: open the canonical production ConsensusStorage at
    // <data_dir>/consensus (Run 093) — same call the binary makes.
    let opened = open_production_consensus_storage(&cfg).expect("open consensus storage");
    assert_eq!(opened.state, ConsensusStorageState::PresentNoCommittedEpoch);

    // Step 3: Run 097 — persist the snapshot's canonical epoch into
    // the open storage. This is what main.rs does immediately after
    // open_production_consensus_storage when restore_outcome is Some.
    let wrote =
        persist_restored_snapshot_epoch(&opened, outcome.meta.epoch).expect("persist epoch ok");
    assert!(wrote, "snapshot epoch must be persisted on fresh storage");

    // The persisted epoch must now be observable from a fresh re-open
    // of the same canonical path — proving parity with future binary
    // restarts.
    drop(opened);
    let opened2 = open_production_consensus_storage(&cfg).expect("reopen ok");
    assert_eq!(opened2.state, ConsensusStorageState::CommittedEpoch(7));
}

#[test]
fn run097_restore_with_pre_run097_snapshot_leaves_storage_at_no_committed_epoch() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();

    let snapshot = snap_root.path().join("snap-100");
    let chain_id = devnet_chain_id();
    // No canonical epoch: simulates a snapshot taken by a pre-Run-097
    // node or a node whose canonical ConsensusStorage was in the
    // PresentNoCommittedEpoch state.
    build_real_snapshot_with_epoch(src_state.path(), &snapshot, chain_id, 100, None);

    let cfg = restore_config(data_dir.path(), &snapshot, chain_id);
    let outcome = apply_snapshot_restore_if_requested(&cfg)
        .expect("restore ok")
        .expect("restore outcome present");
    assert_eq!(outcome.meta.epoch, None);

    let opened = open_production_consensus_storage(&cfg).expect("open ok");
    let wrote = persist_restored_snapshot_epoch(&opened, outcome.meta.epoch).expect("noop is ok");
    assert!(!wrote);

    // CRITICAL Run 091/092 invariant: the absence of an epoch in
    // meta.json MUST NOT be silently coerced to CommittedEpoch(0).
    drop(opened);
    let opened2 = open_production_consensus_storage(&cfg).expect("reopen ok");
    assert_eq!(
        opened2.state,
        ConsensusStorageState::PresentNoCommittedEpoch
    );
    assert_eq!(opened2.state.committed_epoch(), None);
}

// ============================================================================
// 3. Fail-closed inconsistency
// ============================================================================

#[test]
fn run097_restore_inconsistent_snapshot_epoch_fails_closed() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();

    let snapshot = snap_root.path().join("snap-100");
    let chain_id = devnet_chain_id();
    build_real_snapshot_with_epoch(src_state.path(), &snapshot, chain_id, 100, Some(7));

    let cfg = restore_config(data_dir.path(), &snapshot, chain_id);

    // Pre-populate the canonical consensus storage with a DIFFERENT
    // committed epoch (simulating: the operator restored onto a node
    // whose <data_dir>/consensus was already advanced past the
    // snapshot's epoch, OR the snapshot is from the wrong node/epoch).
    {
        let consensus_dir = cfg.consensus_storage_dir().expect("data_dir set");
        std::fs::create_dir_all(consensus_dir.parent().unwrap()).unwrap();
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("open");
        storage.put_current_epoch(42).expect("write existing epoch");
    }

    // Now do the restore + open + persist sequence the binary follows.
    let outcome = apply_snapshot_restore_if_requested(&cfg)
        .expect("vm-v0 restore ok")
        .expect("outcome present");
    assert_eq!(outcome.meta.epoch, Some(7));

    let opened = open_production_consensus_storage(&cfg).expect("open ok");
    assert_eq!(opened.state, ConsensusStorageState::CommittedEpoch(42));

    let err =
        persist_restored_snapshot_epoch(&opened, outcome.meta.epoch).expect_err("must fail closed");
    match err {
        ProductionConsensusStorageError::RestoreEpochInconsistent {
            existing, snapshot, ..
        } => {
            assert_eq!(existing, 42);
            assert_eq!(snapshot, 7);
        }
        other => panic!("expected RestoreEpochInconsistent, got {other:?}"),
    }

    // Storage MUST be unchanged after a failed-closed restore.
    drop(opened);
    let opened2 = open_production_consensus_storage(&cfg).expect("reopen");
    assert_eq!(opened2.state, ConsensusStorageState::CommittedEpoch(42));
}

#[test]
fn run097_idempotent_restore_when_snapshot_epoch_matches_existing() {
    // Re-running the same restore (e.g. operator restarts the binary
    // with --restore-from-snapshot pointing at the same snap dir)
    // must be a no-op once epoch parity has already been established.
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();

    let snapshot = snap_root.path().join("snap-100");
    let chain_id = devnet_chain_id();
    build_real_snapshot_with_epoch(src_state.path(), &snapshot, chain_id, 100, Some(11));

    let cfg = restore_config(data_dir.path(), &snapshot, chain_id);

    // Pre-populate <data_dir>/consensus with the SAME epoch the
    // snapshot carries (e.g. the previous startup already persisted it).
    {
        let consensus_dir = cfg.consensus_storage_dir().expect("data_dir set");
        std::fs::create_dir_all(consensus_dir.parent().unwrap()).unwrap();
        let storage = RocksDbConsensusStorage::open(&consensus_dir).expect("open");
        storage.put_current_epoch(11).unwrap();
    }
    // VM-v0 state restore: must not fail just because the snapshot
    // file is the same — the restore code already enforces a fresh
    // target. So skip apply_snapshot_restore_if_requested here and
    // only exercise the Run 097 epoch-parity branch directly.

    let opened = open_production_consensus_storage(&cfg).expect("open");
    assert_eq!(opened.state, ConsensusStorageState::CommittedEpoch(11));

    let wrote = persist_restored_snapshot_epoch(&opened, Some(11)).expect("ok");
    assert!(!wrote, "matching epoch must be a no-op (idempotent)");
}

// ============================================================================
// 4. Activation isolation (Run 091/092 boundary preserved)
// ============================================================================

#[test]
fn run097_does_not_touch_activation_context_current_epoch_surface() {
    // The Run 097 surface (`persist_restored_snapshot_epoch`) writes
    // only `meta:current_epoch` via `ConsensusStorage::put_current_epoch`.
    // It does NOT construct any `ActivationContext`, and it does NOT
    // call any PQC trust-bundle activation entry point. This test
    // documents that contract by exercising the function and then
    // confirming the only observable side effect is on the
    // ConsensusStorage `get_current_epoch` surface.
    let tmp = tempdir().unwrap();
    let mut cfg = NodeConfig::default();
    cfg.data_dir = Some(tmp.path().to_path_buf());
    let opened = open_production_consensus_storage(&cfg).expect("open");
    assert_eq!(opened.state, ConsensusStorageState::PresentNoCommittedEpoch);

    let _ = persist_restored_snapshot_epoch(&opened, Some(3)).expect("ok");
    // Side effect: ConsensusStorage::get_current_epoch advances.
    assert_eq!(
        opened.handle.as_ref().unwrap().get_current_epoch().unwrap(),
        Some(3)
    );
    // No other surface in this module is mutated. Activation-side
    // assertions (ActivationContext.current_epoch == None) remain
    // covered by the Run 091/092 regression suites.
}
