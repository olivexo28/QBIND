//! Run 124 — Snapshot/restore authority anti-rollback marker enforcement.
//!
//! These integration tests exercise
//! [`qbind_node::snapshot_restore::restore_from_snapshot_with_authority_marker_check`]
//! against real snapshot directories produced by the canonical
//! `StateSnapshotter::create_snapshot` API plus the additive
//! [`qbind_ledger::AuthorityStateSnapshotMeta`] block introduced in
//! Run 117. They prove that the restore surface:
//!
//! 1. Accepts a legacy pre-Run-117 snapshot (no `authority_state` block) into
//!    a fresh `data_dir` (no local marker) — preserves pre-Run-124 ergonomics
//!    for first-time restores.
//! 2. Refuses to silently shadow a local marker with a legacy snapshot
//!    (snapshot meta absent + local marker present → `RejectMissingSnapshotMarker`).
//! 3. Accepts a snapshot whose authority block matches the persisted local
//!    marker bit-for-bit, and does NOT rewrite the local marker bytes.
//! 4. Refuses a snapshot whose authority block conflicts with the persisted
//!    local marker (rollback / same-sequence equivocation / wrong-domain),
//!    BEFORE any state copy or audit-marker write, and preserves the local
//!    marker bytes verbatim.
//! 5. Refuses a corrupt local marker fail-closed; the on-disk bytes are
//!    preserved verbatim.
//!
//! The Run 070 `commit_sequence` / Run 117 atomic-persist invariants are
//! preserved bit-for-bit on the accept paths because the restore surface
//! NEVER writes, rewrites, or deletes the local authority marker file —
//! the only on-disk writes are the existing B3 state-checkpoint copy
//! and the B3 `RESTORED_FROM_SNAPSHOT.json` audit marker.

use std::path::Path;

use tempfile::tempdir;

use qbind_ledger::{
    AccountState, AuthorityStateSnapshotMeta, PersistentAccountState, RocksDbAccountState,
    StateSnapshotMeta, StateSnapshotter,
};
use qbind_node::node_config::NodeConfig;
use qbind_node::pqc_authority_state::SnapshotRestoreAuthorityCheckOutcome;
use qbind_node::pqc_authority_state::{
    authority_state_file_path, persist_authority_state_atomic, AuthorityStateUpdateSource,
    PersistentAuthorityStateRecord,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::snapshot_restore::{
    restore_from_snapshot_with_authority_marker_check, RestoreAuthorityContext, RestoreError,
};

use qbind_types::{ChainId, NetworkEnvironment};

// ----------------------------------------------------------------------
// Trust-domain constants shared across all tests in this file.
// ----------------------------------------------------------------------

const RUNTIME_GENESIS_HEX: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn runtime_chain_id() -> ChainId {
    NodeConfig::default().chain_id()
}

fn runtime_chain_id_u64() -> u64 {
    runtime_chain_id().as_u64()
}

fn runtime_chain_id_hex_lower() -> String {
    format!("{:016x}", runtime_chain_id_u64())
}

fn authority_ctx<'a>() -> RestoreAuthorityContext<'a> {
    RestoreAuthorityContext {
        runtime_env: NetworkEnvironment::Devnet,
        runtime_chain_id: runtime_chain_id(),
        runtime_genesis_hash_hex: RUNTIME_GENESIS_HEX,
    }
}

/// Build a real snapshot directory with B3-compatible layout plus the
/// optional Run-117 `authority_state` block.
fn build_snapshot_with_optional_authority_meta(
    state_dir: &Path,
    target: &Path,
    height: u64,
    auth: Option<AuthorityStateSnapshotMeta>,
) -> StateSnapshotMeta {
    let storage = RocksDbAccountState::open(state_dir).expect("open state");
    let account: [u8; 32] = [0xAB; 32];
    let state = AccountState::new(11, 9999);
    storage.put_account_state(&account, &state).expect("put");
    storage.flush().expect("flush");
    let meta = StateSnapshotMeta::new(
        height,
        [height as u8; 32],
        1_700_000_000_000,
        runtime_chain_id_u64(),
    )
    .with_authority_state(auth);
    storage.create_snapshot(&meta, target).expect("snapshot");
    drop(storage);
    meta
}

fn matching_snapshot_auth_meta() -> AuthorityStateSnapshotMeta {
    AuthorityStateSnapshotMeta {
        chain_id_hex: runtime_chain_id_hex_lower(),
        environment: "devnet".to_string(),
        genesis_hash_hex: RUNTIME_GENESIS_HEX.to_string(),
        authority_policy_version: 1,
        authority_sequence: 5,
        authority_epoch: Some(2),
        authority_root_fingerprint: "b".repeat(40),
        ratified_bundle_signing_key_fingerprint: "c".repeat(40),
        ratification_object_hash: "d".repeat(64),
    }
}

fn matching_local_marker() -> PersistentAuthorityStateRecord {
    PersistentAuthorityStateRecord::new(
        runtime_chain_id_hex_lower(),
        TrustBundleEnvironment::Devnet,
        RUNTIME_GENESIS_HEX.to_string(),
        1,
        5,
        Some(2),
        "b".repeat(40),
        "c".repeat(40),
        "d".repeat(64),
        AuthorityStateUpdateSource::StartupLoad,
        1_700_000_000,
    )
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

#[test]
fn run124_legacy_snapshot_into_fresh_data_dir_is_accepted() {
    // Pre-Run-117 snapshot (no authority block) + no local marker →
    // restore proceeds and the restore surface does NOT synthesise a
    // local marker.
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-77");
    build_snapshot_with_optional_authority_meta(src_state.path(), &snapshot_dir, 77, None);

    let outcome = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect("legacy snapshot + no local marker must accept");
    assert_eq!(outcome.meta.height, 77);
    assert!(outcome.target_state_dir.exists());
    assert!(!authority_state_file_path(data_dir.path()).exists());
}

#[test]
fn run124_legacy_snapshot_into_data_dir_with_local_marker_is_rejected() {
    // Snapshot has no authority block, but the data dir has a persisted
    // marker → accepting the restore would silently erase / shadow the
    // local marker. Fail-closed before any state mutation.
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-78");
    build_snapshot_with_optional_authority_meta(src_state.path(), &snapshot_dir, 78, None);

    let marker_path = authority_state_file_path(data_dir.path());
    persist_authority_state_atomic(&marker_path, &matching_local_marker()).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("legacy snapshot + local marker present must reject");
    match err {
        RestoreError::AuthorityMarkerConflict(
            SnapshotRestoreAuthorityCheckOutcome::RejectMissingSnapshotMarker,
        ) => {}
        other => panic!(
            "expected RejectMissingSnapshotMarker, got {:?} ({})",
            other, other
        ),
    }
    // Local marker bytes preserved; no state materialization audit marker.
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
    assert!(!data_dir
        .path()
        .join(qbind_node::snapshot_restore::RESTORE_MARKER_FILENAME)
        .exists());
    assert!(
        !data_dir
            .path()
            .join(qbind_node::snapshot_restore::VM_V0_STATE_SUBDIR)
            .exists()
            || std::fs::read_dir(
                data_dir
                    .path()
                    .join(qbind_node::snapshot_restore::VM_V0_STATE_SUBDIR)
            )
            .map(|mut e| e.next().is_none())
            .unwrap_or(true),
        "no state should have been materialized on reject"
    );
}

#[test]
fn run124_matching_snapshot_and_local_marker_accepts_and_preserves_local() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-50");
    build_snapshot_with_optional_authority_meta(
        src_state.path(),
        &snapshot_dir,
        50,
        Some(matching_snapshot_auth_meta()),
    );

    let marker_path = authority_state_file_path(data_dir.path());
    persist_authority_state_atomic(&marker_path, &matching_local_marker()).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let outcome = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect("matching snapshot must accept");
    assert_eq!(outcome.meta.height, 50);
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
}

#[test]
fn run124_rollback_snapshot_against_higher_local_is_rejected() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-22");
    build_snapshot_with_optional_authority_meta(
        src_state.path(),
        &snapshot_dir,
        22,
        Some(matching_snapshot_auth_meta()), // authority_sequence = 5
    );

    let marker_path = authority_state_file_path(data_dir.path());
    let mut local = matching_local_marker();
    local.authority_sequence = 9;
    persist_authority_state_atomic(&marker_path, &local).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("rollback snapshot must reject");
    assert!(matches!(err, RestoreError::AuthorityMarkerConflict(_)));
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
}

#[test]
fn run124_same_sequence_conflicting_hash_is_rejected() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-33");
    let mut snap_auth = matching_snapshot_auth_meta();
    snap_auth.ratification_object_hash = "e".repeat(64);
    build_snapshot_with_optional_authority_meta(
        src_state.path(),
        &snapshot_dir,
        33,
        Some(snap_auth),
    );

    let marker_path = authority_state_file_path(data_dir.path());
    persist_authority_state_atomic(&marker_path, &matching_local_marker()).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("conflicting same-sequence snapshot must reject");
    assert!(matches!(err, RestoreError::AuthorityMarkerConflict(_)));
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
}

#[test]
fn run124_corrupt_local_marker_fails_closed_and_preserves_bytes() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-44");
    build_snapshot_with_optional_authority_meta(
        src_state.path(),
        &snapshot_dir,
        44,
        Some(matching_snapshot_auth_meta()),
    );

    let marker_path = authority_state_file_path(data_dir.path());
    std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
    std::fs::write(&marker_path, b"not valid json").unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("corrupt local marker must fail closed");
    match err {
        RestoreError::AuthorityMarkerConflict(
            SnapshotRestoreAuthorityCheckOutcome::RejectLocalMarkerCorrupt(_),
        ) => {}
        other => panic!("expected RejectLocalMarkerCorrupt, got {}", other),
    }
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
}

#[test]
fn run124_snapshot_with_wrong_domain_is_rejected_even_without_local_marker() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-55");
    let mut snap_auth = matching_snapshot_auth_meta();
    snap_auth.genesis_hash_hex = "f".repeat(64);
    build_snapshot_with_optional_authority_meta(
        src_state.path(),
        &snapshot_dir,
        55,
        Some(snap_auth),
    );

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("wrong-domain snapshot must reject");
    assert!(matches!(err, RestoreError::AuthorityMarkerConflict(_)));
}
