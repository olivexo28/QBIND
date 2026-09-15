//! Run 422 D7-C2 — behavioral tests for the bounded, **non-authorizing**
//! genesis / authority-record correspondence checker
//! (`qbind_node::genesis_authority_record_correspondence`).
//!
//! These tests use the **real** genesis loader/validator with temporary genesis
//! files and valid ML-DSA-44 consensus public keys from the existing crypto
//! implementation, and exercise the D7-C1 storage observation against **real
//! temporary RocksDB databases** wherever a database observation is claimed.
//!
//! The authority records in these tests are **supplied fixtures**, hand-built
//! in-memory values — they are **NOT** records read from RocksDB. No production
//! reader, storage key, schema, file format, or CLI surface is exercised or
//! introduced. A successful correspondence never becomes an authorization
//! capability: there is deliberately no API on the result that converts it into
//! an owner, snapshot, ticket, established state, or signing capability.
//!
//! Coverage (task §6):
//!   A. Matching pinned genesis + coherent record + explicit epoch zero.
//!   B. Wrong genesis pin / replacement genesis contents reject at construction.
//!   C. Wrong chain label / genesis hash / authority commitment reject.
//!   D. Same count but changed validator identity/key/suite/weight reject
//!      (claimed commitment left unchanged).
//!   E. Missing / duplicate / extra / noncanonical membership entries reject.
//!   F. Missing record; absent handle; db without epoch; record/storage epoch
//!      mismatch; non-founding epoch — distinct outcomes; missing epoch never 0.
//!   G. C1 malformed metadata / incomplete-transition / read-failure stay errors.
//!   H. A record derived from unrelated genesis B cannot redefine expectations
//!      pinned to A (expected A frozen).
//!   I. A separate/reopened db reporting the same epoch supplies no provenance
//!      by itself; the result retains co-origin-not-established and current-
//!      authorization-unavailable.

use std::path::{Path, PathBuf};

use tempfile::TempDir;

use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::ConsensusSigSuiteId;
use qbind_ledger::{
    compute_canonical_genesis_hash, GenesisAllocation, GenesisConfig, GenesisCouncilConfig,
    GenesisHash, GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
};
use qbind_node::consensus_storage_observation::{
    observe_consensus_storage, ConsensusStorageObservation, ConsensusStorageObservationError,
};
use qbind_node::genesis_authority_record_correspondence::{
    check_genesis_record_correspondence, ClaimedAuthorityRecord, ClaimedValidatorRecord,
    ExpectedGenesisIdentity, ExpectedGenesisIdentityError, RecordCorrespondenceError,
};
use qbind_node::storage::{
    ConsensusStorage, EpochTransitionMarker, RocksDbConsensusStorage, StorageError,
};
use qbind_node::timeout_verification_bridge::SUPPORTED_TIMEOUT_SUITE_ID;

const ENV: NetworkEnvironmentPolicy = NetworkEnvironmentPolicy::Devnet;

// ============================================================================
// Fixtures — real genesis + valid ML-DSA-44 keys
// ============================================================================

/// Fresh ML-DSA-44 keypair: `(public_key_hex, public_key_bytes)`.
fn fresh_key() -> (String, Vec<u8>) {
    let (pk, _sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    let hex = pk.iter().map(|b| format!("{:02x}", b)).collect();
    (hex, pk)
}

fn validator(addr_seed: u8, pk_hex: String) -> GenesisValidator {
    GenesisValidator::new(format!("{:02x}", addr_seed).repeat(32), pk_hex, 100_000u128)
}

/// A three-validator genesis plus the ordered public-key bytes of its
/// validators (index order), so a coherent fixture record can be built.
fn genesis3() -> (GenesisConfig, Vec<Vec<u8>>) {
    let (h0, b0) = fresh_key();
    let (h1, b1) = fresh_key();
    let (h2, b2) = fresh_key();
    let g = genesis_with(vec![
        validator(1, h0),
        validator(2, h1),
        validator(3, h2),
    ]);
    (g, vec![b0, b1, b2])
}

fn genesis_with(validators: Vec<GenesisValidator>) -> GenesisConfig {
    GenesisConfig::new(
        "0000000051424e44",
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            "0x1111111111111111111111111111111111111111",
            1_000_000u128,
        )],
        validators,
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    )
}

fn write_genesis(g: &GenesisConfig) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("genesis.json");
    std::fs::write(&path, serde_json::to_vec_pretty(g).expect("serialize")).expect("write");
    (dir, path)
}

/// The independent pin for a genesis under the DevNet policy.
fn pin(g: &GenesisConfig) -> GenesisHash {
    compute_canonical_genesis_hash(g, ENV)
}

/// Build a coherent fixture record that matches the pinned expected identity at
/// the founding epoch. This is a **supplied in-memory fixture**, not a record
/// read from RocksDB.
fn coherent_record(
    expected: &ExpectedGenesisIdentity,
    pks: &[Vec<u8>],
    claimed_epoch: u64,
) -> ClaimedAuthorityRecord {
    ClaimedAuthorityRecord {
        chain_id: expected.chain_id().to_string(),
        genesis_hash: *expected.genesis_hash(),
        authority_commitment: *expected.authority_commitment(),
        claimed_epoch,
        validators: pks
            .iter()
            .enumerate()
            .map(|(i, pk)| ClaimedValidatorRecord {
                index: i as u64,
                voting_power: 1,
                suite: SUPPORTED_TIMEOUT_SUITE_ID,
                public_key: pk.clone(),
            })
            .collect(),
    }
}

// ============================================================================
// Real temporary RocksDB helpers
// ============================================================================

fn open_rocks(tmp: &TempDir, name: &str) -> RocksDbConsensusStorage {
    RocksDbConsensusStorage::open(tmp.path().join(name)).expect("open rocksdb")
}

/// Open a fresh real RocksDB, persist an explicit committed epoch, and return an
/// observation over it. The handle is kept alive by the caller's `TempDir`.
fn observe_epoch(
    tmp: &TempDir,
    name: &str,
    epoch: u64,
) -> (
    RocksDbConsensusStorage,
    Result<ConsensusStorageObservation, ConsensusStorageObservationError>,
) {
    let storage = open_rocks(tmp, name);
    storage.put_current_epoch(epoch).expect("persist epoch");
    let obs = observe_consensus_storage(Some(&storage));
    (storage, obs)
}

fn build_expected(path: &Path, the_pin: &GenesisHash) -> ExpectedGenesisIdentity {
    ExpectedGenesisIdentity::load_pinned(path, ENV, the_pin).expect("pinned expected identity")
}

// ============================================================================
// A. Matching pinned genesis + coherent record + explicit epoch zero
// ============================================================================

#[test]
fn d7c2_a_matching_record_explicit_epoch_zero_corresponds_without_authorization() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let the_pin = pin(&g);

    let expected = build_expected(&path, &the_pin);
    let record = coherent_record(&expected, &pks, 0);

    // Real temporary RocksDB with an explicitly persisted committed epoch 0.
    let tmp = TempDir::new().unwrap();
    let (storage, obs) = observe_epoch(&tmp, "db-a", 0);
    assert_eq!(
        obs.as_ref().unwrap(),
        &ConsensusStorageObservation::CommittedEpoch(0)
    );

    let correspondence =
        check_genesis_record_correspondence(&expected, Some(&record), obs).expect("corresponds");

    // Correspondence-only: it establishes NO authorization capability.
    assert_eq!(correspondence.corresponded_epoch(), 0);
    assert_eq!(correspondence.validator_count(), 3);
    assert_eq!(correspondence.chain_id(), "0000000051424e44");
    assert!(!correspondence.storage_record_coorigin_established());
    assert!(!correspondence.activation_authorization_established());
    assert!(!correspondence.current_authorization_available());

    // The checker performed no writes: the storage still reports epoch 0 and no
    // additional state was created.
    assert_eq!(storage.get_current_epoch().unwrap(), Some(0));
    assert!(storage
        .check_for_incomplete_epoch_transition()
        .unwrap()
        .is_none());
}

// ============================================================================
// B. Wrong genesis pin / replacement genesis contents reject at construction
// ============================================================================

#[test]
fn d7c2_b_wrong_pin_rejects_expected_construction() {
    let (g, _pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let wrong_pin = [0x11u8; 32];

    match ExpectedGenesisIdentity::load_pinned(&path, ENV, &wrong_pin) {
        Err(ExpectedGenesisIdentityError::GenesisRevalidationFailed { .. }) => {}
        other => panic!("expected GenesisRevalidationFailed, got {other:?}"),
    }
}

#[test]
fn d7c2_b_replacement_genesis_contents_reject_against_frozen_pin() {
    // Pin is established from an original fixture A, then held fixed while the
    // file's contents are replaced with a different genesis B.
    let (g_a, _pks_a) = genesis3();
    let (dir, path) = write_genesis(&g_a);
    let pin_a = pin(&g_a);
    // Sanity: A loads against its own pin.
    build_expected(&path, &pin_a);

    // Replace the file at the same path with a different genesis B.
    let (g_b, _pks_b) = genesis3();
    std::fs::write(
        dir.path().join("genesis.json"),
        serde_json::to_vec_pretty(&g_b).expect("serialize B"),
    )
    .expect("overwrite");

    // The frozen pin A no longer matches the replaced contents.
    match ExpectedGenesisIdentity::load_pinned(&path, ENV, &pin_a) {
        Err(ExpectedGenesisIdentityError::GenesisRevalidationFailed { .. }) => {}
        other => panic!("expected GenesisRevalidationFailed, got {other:?}"),
    }
}

// ============================================================================
// C. Wrong chain label / genesis hash / authority commitment reject
// ============================================================================

#[test]
fn d7c2_c_wrong_chain_label_rejects() {
    // Ordinary SAME-LENGTH mismatch: the claimed label has exactly the same
    // byte length as the expected label ("0000000051424e44", 16 bytes) but
    // different bytes. It must still reject, with bounded metadata reporting the
    // equal byte lengths and no copy of the claimed label.
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    record.chain_id = "deadbeefdeadbeef".to_string();
    assert_eq!(record.chain_id.len(), expected.chain_id().len());

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-c1", 0);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::ChainIdMismatch {
            expected_len,
            claimed_len,
        }) => {
            assert_eq!(expected_len, expected.chain_id().len());
            assert_eq!(claimed_len, "deadbeefdeadbeef".len());
            assert_eq!(expected_len, claimed_len);
        }
        other => panic!("expected ChainIdMismatch, got {other:?}"),
    }
}

#[test]
fn d7c2_c_oversized_claimed_label_rejects_with_bounded_diagnostics() {
    // An oversized untrusted label (1 MiB) is constructed BEFORE invoking the
    // checker (the fixture's own allocation is separate from checker behavior).
    // The checker must reject it with bounded metadata (byte lengths only) and
    // must NOT reproduce the label in either Display or derived Debug output.
    // The length-incompatible label is rejected before any per-byte comparison
    // or full-input fingerprint of the claimed label.
    const OVERSIZED_LEN: usize = 1024 * 1024; // 1 MiB
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    record.chain_id = "A".repeat(OVERSIZED_LEN);
    assert_eq!(record.chain_id.len(), OVERSIZED_LEN);
    assert_ne!(record.chain_id.len(), expected.chain_id().len());

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-c-oversized", 0);
    let err = match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(e) => e,
        Ok(_) => panic!("oversized claimed label must reject"),
    };

    // Bounded metadata: byte lengths only.
    match &err {
        RecordCorrespondenceError::ChainIdMismatch {
            expected_len,
            claimed_len,
        } => {
            assert_eq!(*expected_len, expected.chain_id().len());
            assert_eq!(*claimed_len, OVERSIZED_LEN);
        }
        other => panic!("expected ChainIdMismatch, got {other:?}"),
    }

    // Bounded Display and Debug: both stay tiny and never reproduce the 1 MiB
    // untrusted label. Explicit byte limits are asserted; a full copy of the
    // label would blow past these bounds.
    const MAX_DISPLAY_BYTES: usize = 256;
    const MAX_DEBUG_BYTES: usize = 256;
    let display = err.to_string();
    let debug = format!("{err:?}");
    assert!(
        display.len() <= MAX_DISPLAY_BYTES,
        "Display must be bounded, got {} bytes",
        display.len()
    );
    assert!(
        debug.len() <= MAX_DEBUG_BYTES,
        "Debug must be bounded, got {} bytes",
        debug.len()
    );
    // Neither rendering may contain the oversized label run.
    assert!(!display.contains(&"A".repeat(64)));
    assert!(!debug.contains(&"A".repeat(64)));
    // The bounded lengths are still surfaced in Display for diagnostics.
    assert!(display.contains(&OVERSIZED_LEN.to_string()));
}

#[test]
fn d7c2_c_wrong_genesis_hash_rejects() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    record.genesis_hash = [0x22u8; 32];

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-c2", 0);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::GenesisHashMismatch { .. }) => {}
        other => panic!("expected GenesisHashMismatch, got {other:?}"),
    }
}

#[test]
fn d7c2_c_wrong_authority_commitment_rejects() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    record.authority_commitment[0] ^= 0xFF;

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-c3", 0);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::AuthorityCommitmentMismatch { .. }) => {}
        other => panic!("expected AuthorityCommitmentMismatch, got {other:?}"),
    }
}

// ============================================================================
// D. Same count but changed validator identity/key/suite/weight reject
//    (claimed commitment deliberately left unchanged)
// ============================================================================

#[test]
fn d7c2_d_changed_validator_key_rejects_despite_unchanged_commitment() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    // Alter validator 1's key bytes but LEAVE the claimed commitment unchanged.
    let (_h, other_key) = fresh_key();
    record.validators[1].public_key = other_key;
    // commitment intentionally still equals the expected commitment.
    assert_eq!(&record.authority_commitment, expected.authority_commitment());

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-d1", 0);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::ValidatorKeyMismatch { position: 1, .. }) => {}
        other => panic!("expected ValidatorKeyMismatch@1, got {other:?}"),
    }
}

#[test]
fn d7c2_d_changed_validator_suite_rejects() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    record.validators[2].suite = ConsensusSigSuiteId::new(999);

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-d2", 0);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::UnsupportedSuite { position: 2, .. }) => {}
        other => panic!("expected UnsupportedSuite@2, got {other:?}"),
    }
}

#[test]
fn d7c2_d_changed_validator_weight_rejects() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    // A stake/balance is never silently reinterpreted as voting weight.
    record.validators[0].voting_power = 100_000;

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-d3", 0);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::ValidatorVotingPowerMismatch { position: 0, .. }) => {}
        other => panic!("expected ValidatorVotingPowerMismatch@0, got {other:?}"),
    }
}

// ============================================================================
// E. Missing / duplicate / extra / noncanonical membership entries reject
// ============================================================================

#[test]
fn d7c2_e_missing_entry_rejects_as_count_mismatch() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    record.validators.pop(); // drop validator 2

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-e1", 0);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::MembershipCountMismatch {
            expected: 3,
            claimed: 2,
        }) => {}
        other => panic!("expected MembershipCountMismatch, got {other:?}"),
    }
}

#[test]
fn d7c2_e_extra_entry_rejects_as_count_mismatch() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    let (_h, extra) = fresh_key();
    record.validators.push(ClaimedValidatorRecord {
        index: 3,
        voting_power: 1,
        suite: SUPPORTED_TIMEOUT_SUITE_ID,
        public_key: extra,
    });

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-e2", 0);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::MembershipCountMismatch {
            expected: 3,
            claimed: 4,
        }) => {}
        other => panic!("expected MembershipCountMismatch, got {other:?}"),
    }
}

#[test]
fn d7c2_e_duplicate_key_rejects_without_repair() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    // Same count, canonical indices, but validator 1 duplicates validator 0's key.
    record.validators[1].public_key = record.validators[0].public_key.clone();

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-e3", 0);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::DuplicateClaimedKey {
            first_position: 0,
            duplicate_position: 1,
            ..
        }) => {}
        other => panic!("expected DuplicateClaimedKey, got {other:?}"),
    }
}

#[test]
fn d7c2_e_noncanonical_index_rejects_without_repair() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let mut record = coherent_record(&expected, &pks, 0);
    record.validators[1].index = 5; // declared index != canonical position

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-e4", 0);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::NonCanonicalMembership {
            position: 1,
            declared_index: 5,
        }) => {}
        other => panic!("expected NonCanonicalMembership, got {other:?}"),
    }
}

// ============================================================================
// F. Missing record; absent handle; db without epoch; record/storage epoch
//    mismatch; non-founding epoch — distinct outcomes; missing epoch never 0
// ============================================================================

#[test]
fn d7c2_f_missing_record_is_explicit() {
    let (g, _pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-f1", 0);
    match check_genesis_record_correspondence(&expected, None, obs) {
        Err(RecordCorrespondenceError::MissingRecord) => {}
        other => panic!("expected MissingRecord, got {other:?}"),
    }
}

#[test]
fn d7c2_f_absent_storage_handle_is_explicit() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let record = coherent_record(&expected, &pks, 0);

    // No storage handle at all.
    let obs = observe_consensus_storage::<RocksDbConsensusStorage>(None);
    assert_eq!(obs.as_ref().unwrap(), &ConsensusStorageObservation::NoStorageHandle);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::StorageHandleAbsent) => {}
        other => panic!("expected StorageHandleAbsent, got {other:?}"),
    }
}

#[test]
fn d7c2_f_database_without_committed_epoch_never_becomes_zero() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let record = coherent_record(&expected, &pks, 0);

    // Real database opened but no epoch committed.
    let tmp = TempDir::new().unwrap();
    let storage = open_rocks(&tmp, "db-f3");
    let obs = observe_consensus_storage(Some(&storage));
    assert_eq!(
        obs.as_ref().unwrap(),
        &ConsensusStorageObservation::PresentNoCommittedEpoch
    );
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::StorageCommittedEpochAbsent) => {}
        other => panic!("expected StorageCommittedEpochAbsent, got {other:?}"),
    }
}

#[test]
fn d7c2_f_record_storage_epoch_mismatch_rejects() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    // Record claims founding epoch 0, but the database committed epoch 1.
    let record = coherent_record(&expected, &pks, 0);

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-f4", 1);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::RecordStorageEpochMismatch {
            claimed_epoch: 0,
            storage_epoch: 1,
        }) => {}
        other => panic!("expected RecordStorageEpochMismatch, got {other:?}"),
    }
}

#[test]
fn d7c2_f_non_founding_claimed_epoch_rejects() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    // Record claims a non-founding epoch.
    let record = coherent_record(&expected, &pks, 7);

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-f5", 7);
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::ClaimedEpochNotFounding {
            claimed_epoch: 7,
            founding_epoch: 0,
        }) => {}
        other => panic!("expected ClaimedEpochNotFounding, got {other:?}"),
    }
}

// ============================================================================
// G. C1 malformed metadata / incomplete-transition / read-failure stay errors
// ============================================================================

#[test]
fn d7c2_g_injected_malformed_metadata_stays_error() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let record = coherent_record(&expected, &pks, 0);

    // Injected (clearly labelled) C1 malformed-metadata error.
    let injected = Err(ConsensusStorageObservationError::MalformedMetadata {
        surface: "current epoch",
        source: StorageError::Corruption("injected corruption".into()),
    });
    match check_genesis_record_correspondence(&expected, Some(&record), injected) {
        Err(RecordCorrespondenceError::StorageObservationError(
            ConsensusStorageObservationError::MalformedMetadata { surface, .. },
        )) => assert_eq!(surface, "current epoch"),
        other => panic!("expected StorageObservationError(MalformedMetadata), got {other:?}"),
    }
}

#[test]
fn d7c2_g_injected_read_failure_stays_error() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let record = coherent_record(&expected, &pks, 0);

    // Injected (clearly labelled) C1 read-failure error.
    let injected = Err(ConsensusStorageObservationError::ReadFailed {
        surface: "current epoch",
        source: StorageError::Io("injected io".into()),
    });
    match check_genesis_record_correspondence(&expected, Some(&record), injected) {
        Err(RecordCorrespondenceError::StorageObservationError(
            ConsensusStorageObservationError::ReadFailed { .. },
        )) => {}
        other => panic!("expected StorageObservationError(ReadFailed), got {other:?}"),
    }
}

#[test]
fn d7c2_g_real_incomplete_transition_marker_stays_error() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let record = coherent_record(&expected, &pks, 0);

    // Real RocksDB carrying a genuine incomplete-epoch-transition marker.
    let tmp = TempDir::new().unwrap();
    let storage = open_rocks(&tmp, "db-g3");
    storage.put_current_epoch(0).unwrap();
    storage
        .write_epoch_transition_marker(&EpochTransitionMarker {
            target_epoch: 1,
            previous_epoch: 0,
            started_at_ms: 1,
            reconfig_block_id: [7u8; 32],
        })
        .unwrap();
    let obs = observe_consensus_storage(Some(&storage));
    match check_genesis_record_correspondence(&expected, Some(&record), obs) {
        Err(RecordCorrespondenceError::StorageObservationError(
            ConsensusStorageObservationError::IncompleteEpochTransition {
                target_epoch: 1,
                previous_epoch: 0,
            },
        )) => {}
        other => panic!("expected StorageObservationError(IncompleteEpochTransition), got {other:?}"),
    }
    // The checker did not clear the marker or change the epoch.
    assert!(storage
        .check_for_incomplete_epoch_transition()
        .unwrap()
        .is_some());
    assert_eq!(storage.get_current_epoch().unwrap(), Some(0));
}

// ============================================================================
// H. A record derived from unrelated genesis B cannot redefine expectations
//    pinned to A (expected A frozen)
// ============================================================================

#[test]
fn d7c2_h_unrelated_genesis_b_cannot_redefine_pinned_a() {
    // Freeze expected A + pin A.
    let (g_a, pks_a) = genesis3();
    let (_dir_a, path_a) = write_genesis(&g_a);
    let pin_a = pin(&g_a);
    let expected_a = build_expected(&path_a, &pin_a);

    // A record derived entirely from an unrelated genesis B (different keys →
    // different genesis hash + commitment, same chain label).
    let (g_b, pks_b) = genesis3();
    let (_dir_b, path_b) = write_genesis(&g_b);
    let expected_b = build_expected(&path_b, &pin(&g_b));
    let record_b = coherent_record(&expected_b, &pks_b, 0);

    let tmp = TempDir::new().unwrap();
    let (_s, obs) = observe_epoch(&tmp, "db-h", 0);
    // B's claims are checked against the frozen expected A; B cannot redefine A.
    match check_genesis_record_correspondence(&expected_a, Some(&record_b), obs) {
        Err(RecordCorrespondenceError::GenesisHashMismatch { .. }) => {}
        other => panic!("expected GenesisHashMismatch, got {other:?}"),
    }

    // Expected A was NOT rebuilt from B: its identity is unchanged, and A's own
    // coherent record still corresponds.
    assert_eq!(expected_a.genesis_hash(), &pin_a);
    let record_a = coherent_record(&expected_a, &pks_a, 0);
    let (_s2, obs2) = observe_epoch(&tmp, "db-h2", 0);
    assert!(check_genesis_record_correspondence(&expected_a, Some(&record_a), obs2).is_ok());
}

// ============================================================================
// I. A separate/reopened database reporting the same epoch supplies no
//    provenance by itself
// ============================================================================

#[test]
fn d7c2_i_separate_database_same_epoch_supplies_no_provenance() {
    let (g, pks) = genesis3();
    let (_dir, path) = write_genesis(&g);
    let expected = build_expected(&path, &pin(&g));
    let record = coherent_record(&expected, &pks, 0);

    let tmp = TempDir::new().unwrap();

    // Database #1 with epoch 0 → correspondence.
    let (_db1, obs1) = observe_epoch(&tmp, "db-i1", 0);
    let c1 = check_genesis_record_correspondence(&expected, Some(&record), obs1).expect("db1 ok");

    // A completely separate database #2 (no chain/genesis provenance) also
    // reports epoch 0 → correspondence again, but this proves NOTHING about
    // co-origin or current authorization.
    let (db2, obs2) = observe_epoch(&tmp, "db-i2", 0);
    let c2 = check_genesis_record_correspondence(&expected, Some(&record), obs2).expect("db2 ok");

    for c in [&c1, &c2] {
        assert!(!c.storage_record_coorigin_established());
        assert!(!c.activation_authorization_established());
        assert!(!c.current_authorization_available());
    }

    // A successful reopen of db2 reporting the same epoch is not authentication
    // or anti-rollback evidence: the state is unchanged (checker wrote nothing).
    drop(db2);
    let db2_reopened = open_rocks(&tmp, "db-i2");
    assert_eq!(db2_reopened.get_current_epoch().unwrap(), Some(0));
    let obs2b = observe_consensus_storage(Some(&db2_reopened));
    let c2b = check_genesis_record_correspondence(&expected, Some(&record), obs2b).expect("reopen");
    assert!(!c2b.storage_record_coorigin_established());
    assert!(!c2b.current_authorization_available());
}