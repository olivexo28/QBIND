//! B3 integration tests: restore-from-snapshot startup path.
//!
//! These tests cover the smallest honest restore-from-snapshot path landed
//! by B3 — see `crates/qbind-node/src/snapshot_restore.rs`,
//! `docs/whitepaper/contradiction.md` C4 (B3), and
//! `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`.
//!
//! The tests drive the same library entry points the binary calls
//! (`apply_snapshot_restore_if_requested` / `restore_from_snapshot`); they
//! do not spawn a child `qbind-node` process. This mirrors the style of
//! `binary_path_b1_b2_b4_tests.rs`.
//!
//! Coverage:
//!
//! - **A. valid restore path accepted**: a snapshot produced by the canonical
//!   `StateSnapshotter` impl is validated and materialized into the
//!   configured `data_dir`.
//! - **B. invalid restore paths rejected** (missing path, wrong chain id,
//!   layout missing `state/` and missing `meta.json`).
//! - **C. no-flag normal startup unchanged**: when `FastSyncConfig` is
//!   disabled, `apply_snapshot_restore_if_requested` is a no-op that
//!   returns `Ok(None)`.
//! - **D. restore-then-observe**: after restore, the materialized state
//!   directory is reopened as a `RocksDbAccountState` and the account
//!   state written before the snapshot is observable. This is the proof
//!   that restore is real, not just syntactic parsing.
//! - **E. audit marker**: a `RESTORED_FROM_SNAPSHOT.json` line is written
//!   under `data_dir`, capturing snapshot metadata.

use std::path::Path;

use tempfile::tempdir;

use qbind_ledger::{
    AccountState, PersistentAccountState, RocksDbAccountState, StateSnapshotMeta, StateSnapshotter,
};
use qbind_node::node_config::{FastSyncConfig, NodeConfig};
use qbind_node::snapshot_restore::{
    apply_snapshot_restore_if_requested, restore_from_snapshot, RestoreError,
    RESTORE_MARKER_FILENAME, VM_V0_STATE_SUBDIR,
};

// ============================================================================
// Helpers
// ============================================================================

/// Build a real snapshot directory at `target` populated by writing a
/// well-known account state into a fresh `RocksDbAccountState` and then
/// invoking `create_snapshot`. Returns `(account_id, expected_state, meta)`.
fn build_real_snapshot(
    state_dir: &Path,
    target: &Path,
    chain_id: u64,
    height: u64,
) -> ([u8; 32], AccountState, StateSnapshotMeta) {
    let storage = RocksDbAccountState::open(state_dir).expect("open state dir");
    let account: [u8; 32] = [0xCD; 32];
    let state = AccountState::new(7, 4242);
    storage
        .put_account_state(&account, &state)
        .expect("put account state");
    storage.flush().expect("flush state");

    let meta = StateSnapshotMeta::new(height, [height as u8; 32], 1_700_000_000_000, chain_id);
    storage
        .create_snapshot(&meta, target)
        .expect("create_snapshot");

    drop(storage);
    (account, state, meta)
}

/// Devnet chain id matches `NodeConfig::default()` (DevNet env).
fn devnet_chain_id() -> u64 {
    NodeConfig::default().chain_id().as_u64()
}

// ============================================================================
// A. valid restore path accepted
// ============================================================================

#[test]
fn b3_valid_snapshot_is_accepted_and_materialized() {
    let snap_root = tempdir().expect("tempdir");
    let src_state = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");

    let snapshot_dir = snap_root.path().join("snap-100");
    let chain_id = devnet_chain_id();
    let (_account, _state, meta) =
        build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 100);

    // Drive the lower-level entry point used by `main.rs`.
    let outcome = restore_from_snapshot(&snapshot_dir, data_dir.path(), chain_id)
        .expect("valid snapshot must restore");

    assert_eq!(outcome.meta.height, 100, "height round-trips");
    assert_eq!(outcome.meta.chain_id, chain_id, "chain_id round-trips");
    assert_eq!(outcome.meta, meta);
    assert_eq!(
        outcome.target_state_dir,
        data_dir.path().join(VM_V0_STATE_SUBDIR)
    );
    assert!(
        outcome.target_state_dir.exists(),
        "target state dir was created"
    );
    assert!(outcome.bytes_copied > 0, "non-empty checkpoint was copied");

    // The audit marker exists and is non-empty.
    let marker = data_dir.path().join(RESTORE_MARKER_FILENAME);
    assert!(marker.exists(), "marker exists");
    let body = std::fs::read_to_string(&marker).expect("read marker");
    assert!(body.contains("\"snapshot_height\":100"));
    assert!(body.contains(&format!("\"snapshot_chain_id\":{}", chain_id)));
}

// ============================================================================
// B. invalid restore paths rejected
// ============================================================================

#[test]
fn b3_missing_snapshot_path_is_rejected() {
    let data_dir = tempdir().expect("tempdir");
    let bogus = data_dir.path().join("does-not-exist");
    let err = restore_from_snapshot(&bogus, data_dir.path(), devnet_chain_id())
        .expect_err("missing path must fail");
    assert!(
        matches!(err, RestoreError::SnapshotPathMissing(_)),
        "wanted SnapshotPathMissing, got {:?}",
        err
    );
}

#[test]
fn b3_wrong_chain_id_is_rejected() {
    let snap_root = tempdir().expect("tempdir");
    let src_state = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");

    let snapshot_dir = snap_root.path().join("snap-100");
    // Build snapshot with a chain id we'll claim is wrong.
    let snap_chain_id: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    let _ = build_real_snapshot(src_state.path(), &snapshot_dir, snap_chain_id, 100);

    let expected_chain_id: u64 = 0x0000_0000_0000_0001;
    let err = restore_from_snapshot(&snapshot_dir, data_dir.path(), expected_chain_id)
        .expect_err("chain mismatch must fail");
    match err {
        RestoreError::SnapshotInvalid(qbind_ledger::SnapshotValidationResult::ChainIdMismatch {
            expected,
            actual,
        }) => {
            assert_eq!(expected, expected_chain_id);
            assert_eq!(actual, snap_chain_id);
        }
        other => panic!("expected ChainIdMismatch, got {:?}", other),
    }
}

#[test]
fn b3_missing_meta_json_is_rejected() {
    // Simulate an incomplete snapshot directory: only state/ exists.
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("incomplete");
    std::fs::create_dir_all(snapshot_dir.join("state").join("dummy_subdir")).unwrap();
    std::fs::write(snapshot_dir.join("state").join("dummy_subdir").join("a"), b"x").unwrap();

    let err = restore_from_snapshot(&snapshot_dir, data_dir.path(), devnet_chain_id())
        .expect_err("missing meta must fail");
    match err {
        RestoreError::SnapshotInvalid(qbind_ledger::SnapshotValidationResult::MissingMetadata(
            _,
        )) => {}
        other => panic!("expected MissingMetadata, got {:?}", other),
    }
}

#[test]
fn b3_missing_state_dir_is_rejected() {
    // Build a directory that has meta.json but no state/.
    let snap_root = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("nostate");
    std::fs::create_dir_all(&snapshot_dir).unwrap();
    let meta = StateSnapshotMeta::new(50, [0u8; 32], 1_700_000_000_000, devnet_chain_id());
    std::fs::write(snapshot_dir.join("meta.json"), meta.to_json()).unwrap();

    let err = restore_from_snapshot(&snapshot_dir, data_dir.path(), devnet_chain_id())
        .expect_err("missing state must fail");
    match err {
        RestoreError::SnapshotInvalid(qbind_ledger::SnapshotValidationResult::MissingStateDir(
            _,
        )) => {}
        other => panic!("expected MissingStateDir, got {:?}", other),
    }
}

#[test]
fn b3_target_state_dir_already_populated_is_rejected() {
    // Operator-honesty: do not silently overwrite existing local state.
    let snap_root = tempdir().expect("tempdir");
    let src_state = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");

    let snapshot_dir = snap_root.path().join("snap-100");
    let chain_id = devnet_chain_id();
    let _ = build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 100);

    // Pre-populate the target VM-v0 state dir with a stray file.
    let target = data_dir.path().join(VM_V0_STATE_SUBDIR);
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("PRE_EXISTING"), b"do not destroy").unwrap();

    let err = restore_from_snapshot(&snapshot_dir, data_dir.path(), chain_id)
        .expect_err("populated target must fail");
    assert!(matches!(err, RestoreError::TargetStateNotEmpty(_)));

    // The pre-existing file is still there — we did not touch it.
    assert!(target.join("PRE_EXISTING").exists());
}

#[test]
fn b3_apply_with_no_data_dir_is_rejected() {
    // FastSyncConfig is enabled but data_dir is unset on the NodeConfig.
    let snap_root = tempdir().expect("tempdir");
    let src_state = tempdir().expect("tempdir");
    let snapshot_dir = snap_root.path().join("snap-100");
    let _ = build_real_snapshot(src_state.path(), &snapshot_dir, devnet_chain_id(), 100);

    let mut config = NodeConfig::default();
    config.fast_sync_config = FastSyncConfig::from_snapshot(snapshot_dir);
    // intentionally: config.data_dir = None

    let err = apply_snapshot_restore_if_requested(&config)
        .expect_err("no data_dir must fail");
    assert!(matches!(err, RestoreError::MissingDataDir));
}

// ============================================================================
// C. no-flag normal startup unchanged
// ============================================================================

#[test]
fn b3_no_restore_flag_is_a_noop() {
    // Default config has FastSyncConfig::disabled().
    let config = NodeConfig::default();
    assert!(!config.fast_sync_config.is_enabled());
    let result =
        apply_snapshot_restore_if_requested(&config).expect("disabled fast-sync is Ok(None)");
    assert!(result.is_none(), "no restore was requested");
}

// ============================================================================
// D. restore-then-observe (the proof that restore is real, not syntactic)
// ============================================================================

#[test]
fn b3_restored_state_is_observable_after_reopen() {
    let snap_root = tempdir().expect("tempdir");
    let src_state = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");

    // 1. Write a known account into the source state, snapshot it.
    let snapshot_dir = snap_root.path().join("snap-200");
    let chain_id = devnet_chain_id();
    let (account, expected_state, _meta) =
        build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 200);

    // 2. Restore the snapshot into a fresh data_dir.
    let outcome = restore_from_snapshot(&snapshot_dir, data_dir.path(), chain_id)
        .expect("restore must succeed");

    // 3. Reopen the materialized RocksDB checkpoint as a normal account
    //    state store and confirm we can observe the pre-snapshot account.
    let restored = RocksDbAccountState::open(&outcome.target_state_dir)
        .expect("restored RocksDB must reopen as a normal account state store");
    let read_back = restored.get_account_state(&account);
    assert_eq!(
        read_back, expected_state,
        "account state present pre-snapshot must be readable post-restore"
    );
}

// ============================================================================
// E. NodeConfig-driven entry point honors fast_sync_config
// ============================================================================

#[test]
fn b3_apply_via_node_config_round_trip() {
    let snap_root = tempdir().expect("tempdir");
    let src_state = tempdir().expect("tempdir");
    let data_dir = tempdir().expect("tempdir");

    let snapshot_dir = snap_root.path().join("snap-300");
    let chain_id = devnet_chain_id();
    let (account, expected_state, _meta) =
        build_real_snapshot(src_state.path(), &snapshot_dir, chain_id, 300);

    let mut config = NodeConfig::default();
    config.data_dir = Some(data_dir.path().to_path_buf());
    config.fast_sync_config = FastSyncConfig::from_snapshot(snapshot_dir.clone());

    let outcome = apply_snapshot_restore_if_requested(&config)
        .expect("apply Ok")
        .expect("restore was requested");
    assert_eq!(outcome.meta.height, 300);
    assert_eq!(outcome.snapshot_dir, snapshot_dir);

    // Reopen and observe.
    let restored =
        RocksDbAccountState::open(&outcome.target_state_dir).expect("reopen restored state");
    assert_eq!(restored.get_account_state(&account), expected_state);
}