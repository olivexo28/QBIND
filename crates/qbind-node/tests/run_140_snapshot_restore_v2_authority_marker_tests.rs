//! Run 140 — Snapshot/restore parity for v2 authority anti-rollback markers.
//!
//! These integration tests exercise the v2 dispatch path of
//! [`qbind_node::snapshot_restore::restore_from_snapshot_with_authority_marker_check`]
//! against real snapshot directories produced by
//! `StateSnapshotter::create_snapshot` plus the additive Run 140
//! [`qbind_ledger::AuthorityStateSnapshotMetaV2`] block. They prove the
//! restore surface routes v2-bearing snapshots through
//! [`qbind_node::pqc_authority_state::verify_snapshot_authority_state_for_restore_v2`]
//! and ultimately through the existing Run 130
//! [`qbind_node::pqc_authority_state::compare_authority_marker_v2`]
//! primitive, fail-closed.
//!
//! Test matrix:
//!
//! * A1 — no local marker + v2 snapshot block → `AcceptSnapshotV2MarkerNoLocal`.
//! * A2 — local v2 marker matches snapshot v2 marker bit-for-bit
//!        → `AcceptMatchingV2Marker`; local marker bytes preserved.
//! * A3 — local v2 marker present + snapshot v2 block carries strictly
//!        higher sequence with matching trust domain + root
//!        → `AcceptHigherV2Sequence`; local marker bytes preserved.
//! * A4 — local v1 marker present + snapshot v2 block matching v1 trust
//!        domain + root → `AcceptV2AfterV1Migration`; local marker bytes
//!        preserved (no v1→v2 swap on the restore surface).
//!
//! * R1 — local v2 marker present + snapshot has neither v1 nor v2 block
//!        → routed via v1 path because `authority_state_v2.is_none()`, and
//!        the v1 path produces `RejectMissingSnapshotMarker`. (Sanity
//!        check that the v1 dispatch is preserved verbatim for v2-only
//!        operators.)
//! * R2 — local v2 marker present + snapshot v2 block carries strictly
//!        lower sequence → `RejectV2Comparison(LowerSequenceRejected)`.
//! * R3 — same v2 sequence but different ratification digest
//!        → `RejectV2Comparison(SameSequenceDifferentDigestRejected)`.
//! * R4 — snapshot v2 block with wrong genesis_hash
//!        → `RejectSnapshotMarkerWrongDomain`.
//! * R5 — snapshot v2 block with wrong environment
//!        → `RejectSnapshotMarkerWrongDomain`.
//! * R6 — local marker structurally corrupt → `RejectLocalMarkerCorrupt`;
//!        marker bytes preserved verbatim.
//! * R7 — snapshot meta carries both v1 (`authority_state`) and v2
//!        (`authority_state_v2`) blocks → `RejectAmbiguousSnapshotMarkers`;
//!        no state materialization.
//! * R8 — local v2 marker present + snapshot v2 block advertises a
//!        different authority_root_fingerprint
//!        → `RejectV2Comparison(WrongAuthorityRootRejected)`.
//! * R9 — local v1 marker present + snapshot v2 block in a different
//!        trust domain from the v1 local
//!        → `RejectLocalMarkerWrongDomain` or
//!        `RejectSnapshotMarkerWrongDomain` (precedence: local-domain
//!        check runs first).
//!
//! All accept paths assert that the local marker file's bytes are
//! preserved verbatim (the Run 140 strict non-goal: the restore surface
//! NEVER synthesises, rewrites, or deletes the local v2 marker).
//! All reject paths assert that no state materialization, no audit
//! marker, and no marker mutation occurred.

use std::path::Path;

use tempfile::tempdir;

use qbind_ledger::{
    AccountState, AuthorityStateSnapshotMeta, AuthorityStateSnapshotMetaV2,
    BundleSigningRatificationV2Action, PersistentAccountState, RocksDbAccountState,
    StateSnapshotMeta, StateSnapshotter,
};
use qbind_node::node_config::NodeConfig;
use qbind_node::pqc_authority_state::{
    authority_state_file_path, persist_authority_state_atomic,
    persist_authority_state_v2_atomic, AuthorityMarkerV2ComparisonOutcome,
    AuthorityStateUpdateSource, PersistentAuthorityStateRecord,
    PersistentAuthorityStateRecordV2, SnapshotRestoreAuthorityCheckV2Outcome,
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

// ----------------------------------------------------------------------
// Snapshot + marker fixtures.
// ----------------------------------------------------------------------

fn build_snapshot_with_optional_v2_auth(
    state_dir: &Path,
    target: &Path,
    height: u64,
    auth_v1: Option<AuthorityStateSnapshotMeta>,
    auth_v2: Option<AuthorityStateSnapshotMetaV2>,
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
    .with_authority_state(auth_v1)
    .with_authority_state_v2(auth_v2);
    storage.create_snapshot(&meta, target).expect("snapshot");
    drop(storage);
    meta
}

fn matching_snapshot_v2_auth_meta() -> AuthorityStateSnapshotMetaV2 {
    AuthorityStateSnapshotMetaV2 {
        chain_id_hex: runtime_chain_id_hex_lower(),
        environment: "devnet".to_string(),
        genesis_hash_hex: RUNTIME_GENESIS_HEX.to_string(),
        authority_root_fingerprint: "b".repeat(40),
        authority_root_suite_id: 1,
        active_bundle_signing_key_fingerprint: "c".repeat(40),
        active_bundle_signing_key_suite_id: 1,
        latest_authority_domain_sequence: 5,
        latest_lifecycle_action_byte: 0, // Ratify
        previous_bundle_signing_key_fingerprint: None,
        latest_ratification_v2_digest: "d".repeat(64),
        revoked_key_metadata: None,
    }
}

fn matching_local_v2_marker() -> PersistentAuthorityStateRecordV2 {
    PersistentAuthorityStateRecordV2::new(
        runtime_chain_id_hex_lower(),
        TrustBundleEnvironment::Devnet,
        RUNTIME_GENESIS_HEX.to_string(),
        "b".repeat(40),
        1,
        "c".repeat(40),
        1,
        5,
        BundleSigningRatificationV2Action::Ratify,
        None,
        "d".repeat(64),
        None,
        AuthorityStateUpdateSource::StartupLoad,
        1_700_000_000,
    )
}

fn matching_local_v1_marker() -> PersistentAuthorityStateRecord {
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

fn assert_no_materialization(data_dir: &Path) {
    assert!(
        !data_dir
            .join(qbind_node::snapshot_restore::RESTORE_MARKER_FILENAME)
            .exists(),
        "audit marker must not be written on reject"
    );
    let vm_dir = data_dir.join(qbind_node::snapshot_restore::VM_V0_STATE_SUBDIR);
    assert!(
        !vm_dir.exists()
            || std::fs::read_dir(&vm_dir)
                .map(|mut e| e.next().is_none())
                .unwrap_or(true),
        "no state should have been materialized on reject"
    );
}

// ----------------------------------------------------------------------
// A — accept paths
// ----------------------------------------------------------------------

#[test]
fn run140_a1_no_local_marker_v2_snapshot_block_is_accepted() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-a1");
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        101,
        None,
        Some(matching_snapshot_v2_auth_meta()),
    );

    let outcome = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect("A1 must accept");
    assert_eq!(outcome.meta.height, 101);
    assert!(outcome.target_state_dir.exists());
    // Restore surface must not synthesise a local marker.
    assert!(!authority_state_file_path(data_dir.path()).exists());
}

#[test]
fn run140_a2_matching_local_v2_marker_accepts_and_preserves_local() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-a2");
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        102,
        None,
        Some(matching_snapshot_v2_auth_meta()),
    );

    let marker_path = authority_state_file_path(data_dir.path());
    persist_authority_state_v2_atomic(&marker_path, &matching_local_v2_marker()).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let outcome = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect("A2 must accept");
    assert_eq!(outcome.meta.height, 102);
    // Local v2 marker bytes preserved verbatim.
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
}

#[test]
fn run140_a3_higher_v2_sequence_accepts_and_preserves_local() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-a3");
    let mut snap_auth = matching_snapshot_v2_auth_meta();
    snap_auth.latest_authority_domain_sequence = 10;
    snap_auth.latest_ratification_v2_digest = "e".repeat(64);
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        103,
        None,
        Some(snap_auth),
    );

    let marker_path = authority_state_file_path(data_dir.path());
    persist_authority_state_v2_atomic(&marker_path, &matching_local_v2_marker()).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let outcome = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect("A3 must accept");
    assert_eq!(outcome.meta.height, 103);
    // Local v2 marker bytes preserved verbatim — restore surface does
    // not persist the new sequence (release-binary reload-apply does).
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
}

#[test]
fn run140_a4_local_v1_marker_with_v2_snapshot_matching_root_is_accepted() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-a4");
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        104,
        None,
        Some(matching_snapshot_v2_auth_meta()),
    );

    let marker_path = authority_state_file_path(data_dir.path());
    persist_authority_state_atomic(&marker_path, &matching_local_v1_marker()).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let outcome = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect("A4 must accept (explicit v1→v2 migration semantics)");
    assert_eq!(outcome.meta.height, 104);
    // Local v1 marker bytes preserved verbatim — v1→v2 swap is a
    // separate release-binary step (deferred to Run 141).
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
}

// ----------------------------------------------------------------------
// R — reject paths
// ----------------------------------------------------------------------

#[test]
fn run140_r1_local_v2_marker_present_legacy_snapshot_rejects_via_v1_path() {
    // Snapshot carries neither v1 nor v2 block (legacy). The dispatcher
    // routes to the v1 path because authority_state_v2 is None; the v1
    // path then returns RejectMissingSnapshotMarker because a local
    // marker (here a v2 marker, which load_authority_state will read as
    // an unsupported version) exists.
    //
    // We don't pin the exact v1 outcome variant here — Run 124 already
    // tests it — but we assert that the restore is refused, no state
    // materialization happens, and the local marker bytes are preserved.
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-r1");
    build_snapshot_with_optional_v2_auth(src_state.path(), &snapshot_dir, 201, None, None);

    let marker_path = authority_state_file_path(data_dir.path());
    persist_authority_state_v2_atomic(&marker_path, &matching_local_v2_marker()).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("R1 must reject (legacy snapshot + local marker)");
    assert!(matches!(err, RestoreError::AuthorityMarkerConflict(_)));
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
    assert_no_materialization(data_dir.path());
}

#[test]
fn run140_r2_lower_v2_sequence_is_rejected() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-r2");
    let mut snap_auth = matching_snapshot_v2_auth_meta();
    snap_auth.latest_authority_domain_sequence = 2;
    snap_auth.latest_ratification_v2_digest = "f".repeat(64);
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        202,
        None,
        Some(snap_auth),
    );

    let marker_path = authority_state_file_path(data_dir.path());
    persist_authority_state_v2_atomic(&marker_path, &matching_local_v2_marker()).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("R2 must reject");
    match err {
        RestoreError::AuthorityMarkerConflictV2(
            SnapshotRestoreAuthorityCheckV2Outcome::RejectV2Comparison(
                AuthorityMarkerV2ComparisonOutcome::LowerSequenceRejected {
                    persisted_sequence,
                    candidate_sequence,
                },
            ),
        ) => {
            assert_eq!(persisted_sequence, 5);
            assert_eq!(candidate_sequence, 2);
        }
        other => panic!("expected LowerSequenceRejected, got {:?}", other),
    }
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
    assert_no_materialization(data_dir.path());
}

#[test]
fn run140_r3_same_sequence_different_digest_is_rejected() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-r3");
    let mut snap_auth = matching_snapshot_v2_auth_meta();
    snap_auth.latest_ratification_v2_digest = "9".repeat(64);
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        203,
        None,
        Some(snap_auth),
    );

    let marker_path = authority_state_file_path(data_dir.path());
    persist_authority_state_v2_atomic(&marker_path, &matching_local_v2_marker()).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("R3 must reject");
    match err {
        RestoreError::AuthorityMarkerConflictV2(
            SnapshotRestoreAuthorityCheckV2Outcome::RejectV2Comparison(
                AuthorityMarkerV2ComparisonOutcome::SameSequenceDifferentDigestRejected {
                    sequence,
                    ..
                },
            ),
        ) => assert_eq!(sequence, 5),
        other => panic!("expected SameSequenceDifferentDigestRejected, got {:?}", other),
    }
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
    assert_no_materialization(data_dir.path());
}

#[test]
fn run140_r4_snapshot_v2_wrong_genesis_hash_is_rejected() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-r4");
    let mut snap_auth = matching_snapshot_v2_auth_meta();
    snap_auth.genesis_hash_hex = "0".repeat(64);
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        204,
        None,
        Some(snap_auth),
    );

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("R4 must reject");
    match err {
        RestoreError::AuthorityMarkerConflictV2(
            SnapshotRestoreAuthorityCheckV2Outcome::RejectSnapshotMarkerWrongDomain { .. },
        ) => {}
        other => panic!("expected RejectSnapshotMarkerWrongDomain, got {:?}", other),
    }
    assert_no_materialization(data_dir.path());
}

#[test]
fn run140_r5_snapshot_v2_wrong_environment_is_rejected() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-r5");
    let mut snap_auth = matching_snapshot_v2_auth_meta();
    snap_auth.environment = "mainnet".to_string();
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        205,
        None,
        Some(snap_auth),
    );

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("R5 must reject");
    match err {
        RestoreError::AuthorityMarkerConflictV2(
            SnapshotRestoreAuthorityCheckV2Outcome::RejectSnapshotMarkerWrongDomain { .. },
        ) => {}
        other => panic!("expected RejectSnapshotMarkerWrongDomain, got {:?}", other),
    }
    assert_no_materialization(data_dir.path());
}

#[test]
fn run140_r6_corrupt_local_marker_fails_closed_and_preserves_bytes() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-r6");
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        206,
        None,
        Some(matching_snapshot_v2_auth_meta()),
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
    .expect_err("R6 must reject");
    match err {
        RestoreError::AuthorityMarkerConflictV2(
            SnapshotRestoreAuthorityCheckV2Outcome::RejectLocalMarkerCorrupt(_),
        ) => {}
        other => panic!("expected RejectLocalMarkerCorrupt, got {:?}", other),
    }
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
    assert_no_materialization(data_dir.path());
}

#[test]
fn run140_r7_ambiguous_snapshot_with_both_v1_and_v2_blocks_is_rejected() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-r7");

    let v1 = AuthorityStateSnapshotMeta {
        chain_id_hex: runtime_chain_id_hex_lower(),
        environment: "devnet".to_string(),
        genesis_hash_hex: RUNTIME_GENESIS_HEX.to_string(),
        authority_policy_version: 1,
        authority_sequence: 5,
        authority_epoch: Some(2),
        authority_root_fingerprint: "b".repeat(40),
        ratified_bundle_signing_key_fingerprint: "c".repeat(40),
        ratification_object_hash: "d".repeat(64),
    };
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        207,
        Some(v1),
        Some(matching_snapshot_v2_auth_meta()),
    );

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("R7 must reject");
    match err {
        RestoreError::AuthorityMarkerConflictV2(
            SnapshotRestoreAuthorityCheckV2Outcome::RejectAmbiguousSnapshotMarkers,
        ) => {}
        other => panic!("expected RejectAmbiguousSnapshotMarkers, got {:?}", other),
    }
    assert_no_materialization(data_dir.path());
}

#[test]
fn run140_r8_v2_snapshot_with_different_authority_root_is_rejected() {
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-r8");
    let mut snap_auth = matching_snapshot_v2_auth_meta();
    snap_auth.authority_root_fingerprint = "1".repeat(40);
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        208,
        None,
        Some(snap_auth),
    );

    let marker_path = authority_state_file_path(data_dir.path());
    persist_authority_state_v2_atomic(&marker_path, &matching_local_v2_marker()).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("R8 must reject");
    match err {
        RestoreError::AuthorityMarkerConflictV2(
            SnapshotRestoreAuthorityCheckV2Outcome::RejectV2Comparison(
                AuthorityMarkerV2ComparisonOutcome::WrongAuthorityRootRejected { .. },
            ),
        ) => {}
        other => panic!("expected WrongAuthorityRootRejected, got {:?}", other),
    }
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
    assert_no_materialization(data_dir.path());
}

#[test]
fn run140_r9_local_v1_marker_wrong_domain_against_v2_snapshot_is_rejected() {
    // Local v1 marker exists in the wrong trust domain (different
    // genesis hash from the runtime). The local-domain check runs BEFORE
    // any snapshot inspection, so the surface returns
    // RejectLocalMarkerWrongDomain.
    let snap_root = tempdir().unwrap();
    let src_state = tempdir().unwrap();
    let data_dir = tempdir().unwrap();
    let snapshot_dir = snap_root.path().join("snap-r9");
    build_snapshot_with_optional_v2_auth(
        src_state.path(),
        &snapshot_dir,
        209,
        None,
        Some(matching_snapshot_v2_auth_meta()),
    );

    let marker_path = authority_state_file_path(data_dir.path());
    let mut local = matching_local_v1_marker();
    local.genesis_hash = "9".repeat(64);
    persist_authority_state_atomic(&marker_path, &local).unwrap();
    let bytes_before = std::fs::read(&marker_path).unwrap();

    let err = restore_from_snapshot_with_authority_marker_check(
        &snapshot_dir,
        data_dir.path(),
        runtime_chain_id_u64(),
        &authority_ctx(),
    )
    .expect_err("R9 must reject");
    match err {
        RestoreError::AuthorityMarkerConflictV2(
            SnapshotRestoreAuthorityCheckV2Outcome::RejectLocalMarkerWrongDomain { .. },
        ) => {}
        other => panic!("expected RejectLocalMarkerWrongDomain, got {:?}", other),
    }
    assert_eq!(std::fs::read(&marker_path).unwrap(), bytes_before);
    assert_no_materialization(data_dir.path());
}