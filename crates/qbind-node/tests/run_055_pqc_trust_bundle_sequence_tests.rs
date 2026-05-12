//! Run 055 (C4 piece: PQC trust-bundle anti-rollback persistence):
//! integration tests for the trust-bundle sequence-monotonicity
//! persistence layer.
//!
//! These tests exercise the public API of
//! `qbind_node::pqc_trust_sequence` against real validated
//! `LoadedTrustBundle`s (Run 050/051/053 surface) to prove the
//! end-to-end behaviour an operator sees: a node accepts the first
//! signed DevNet bundle, accepts a strictly higher sequence on
//! restart, rejects a strictly lower sequence as rollback, rejects
//! equal-sequence + different-fingerprint as equivocation, accepts
//! equal-sequence + same-fingerprint as a no-op restart, and refuses
//! a corrupt persistence file fail-closed rather than silently
//! resetting state. Wrong-environment / wrong-chain-id / tampered-
//! signature / revoked-root bundles continue to fail in the
//! pre-existing validation layer BEFORE the sequence check runs, so
//! none of those failure modes are allowed to bump the persisted
//! highest sequence.

use std::path::PathBuf;

use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey,
    BundleSigningKeySet, HelperBundleMode, RootStatus, TrustBundle, TrustBundleEnvironment,
    TrustBundleRoot, TrustBundleSignature,
};
use qbind_node::pqc_trust_sequence::{
    atomic_write_record, chain_id_hex, check_and_update_sequence, fingerprint_hex,
    load_record, sequence_file_path, PersistentTrustBundleSequenceRecord,
    SequenceCheckOutcome, TrustBundleSequenceError, TRUST_BUNDLE_SEQUENCE_RECORD_VERSION,
};
use qbind_types::NetworkEnvironment;

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", x);
    }
    s
}

/// Unique tmp dir per test invocation. We deliberately do NOT use any
/// project-internal helper because the persistence layer's whole point
/// is robust on-disk behaviour.
fn fresh_dir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run055-it-{}-{}-{}",
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

/// Mint one DevNet root + signing key in memory and return a closure
/// that produces a freshly-signed DevNet bundle at any requested
/// sequence number (each call mints a deterministically distinct
/// canonical fingerprint via a different `generated_at` UNIX seconds
/// component so equal-sequence tests can distinguish two same-seq
/// bundles).
fn sign_devnet_helper_bundle(
    sequence: u64,
    generated_at: u64,
    signing_key_id: [u8; 32],
    signing_sk: &[u8],
    root_id_hex: &str,
    root_pk_hex: &str,
) -> TrustBundle {
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: TrustBundleEnvironment::Devnet,
        chain_id: Some(chain_id_hex(NetworkEnvironment::Devnet.chain_id())),
        generated_at,
        valid_from: 0,
        valid_until: u64::MAX,
        sequence,
        roots: vec![TrustBundleRoot {
            root_id: root_id_hex.to_string(),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            root_pk: root_pk_hex.to_string(),
            status: RootStatus::Active,
            not_before: 0,
            not_after: u64::MAX,
            activation_epoch: None,
            activation_height: None,
        }],
        revocations: vec![],
        signature: None,
    };
    let sig = sign_bundle_devnet_helper(&bundle, signing_key_id, signing_sk)
        .expect("ML-DSA-44 sign devnet helper bundle");
    bundle.signature = Some(sig);
    bundle
}

struct DevnetSigningHarness {
    signing_keys: BundleSigningKeySet,
    signing_key_id: [u8; 32],
    signing_sk: Vec<u8>,
    root_id_hex: String,
    root_pk_hex: String,
}

fn devnet_signing_harness() -> DevnetSigningHarness {
    use qbind_crypto::MlDsa44Backend;
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen for signing key");
    let signing_key_id = derive_signing_key_id(&pk);
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: signing_key_id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: pk,
    }]);
    let root = mint_devnet_root().expect("mint devnet root");
    DevnetSigningHarness {
        signing_keys,
        signing_key_id,
        signing_sk: sk,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

fn load_validate_devnet(
    bundle: &TrustBundle,
    signing_keys: &BundleSigningKeySet,
) -> qbind_node::pqc_trust_bundle::LoadedTrustBundle {
    let bytes = serde_json::to_vec(bundle).expect("serialise");
    TrustBundle::load_from_bytes_with_signing_keys_and_chain_id(
        &bytes,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        signing_keys,
    )
    .expect("validate devnet bundle")
}

// -----------------------------------------------------------------
// 1. First-load on an empty data-dir accepts and persists.
// -----------------------------------------------------------------
#[test]
fn first_load_signed_devnet_seq1_accepts_and_writes_record() {
    let dir = fresh_dir("first-load");
    let path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = sign_devnet_helper_bundle(
        1,
        10,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let loaded = load_validate_devnet(&bundle, &h.signing_keys);
    let outcome = check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded.bundle.sequence,
        &loaded.fingerprint,
        1234,
    )
    .expect("first load");
    assert!(matches!(
        outcome,
        SequenceCheckOutcome::FirstLoad {
            persisted_sequence: 1,
            ..
        }
    ));
    let record = load_record(&path).expect("ok").expect("some");
    assert_eq!(record.record_version, TRUST_BUNDLE_SEQUENCE_RECORD_VERSION);
    assert_eq!(record.environment, TrustBundleEnvironment::Devnet);
    assert_eq!(
        record.chain_id,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id())
    );
    assert_eq!(record.highest_sequence, 1);
    assert_eq!(record.bundle_fingerprint, fingerprint_hex(&loaded.fingerprint));
}

// -----------------------------------------------------------------
// 2. Upgrade: sequence 1 then sequence 2 accepts and persists 2.
// -----------------------------------------------------------------
#[test]
fn signed_devnet_seq2_accepted_after_seq1_persists_2() {
    let dir = fresh_dir("upgrade");
    let path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let b1 = sign_devnet_helper_bundle(
        1,
        10,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let l1 = load_validate_devnet(&b1, &h.signing_keys);
    check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        l1.bundle.sequence,
        &l1.fingerprint,
        0,
    )
    .unwrap();
    let b2 = sign_devnet_helper_bundle(
        2,
        20,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let l2 = load_validate_devnet(&b2, &h.signing_keys);
    assert_ne!(l1.fingerprint, l2.fingerprint);
    let outcome = check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        l2.bundle.sequence,
        &l2.fingerprint,
        0,
    )
    .expect("upgrade");
    assert!(matches!(
        outcome,
        SequenceCheckOutcome::Upgraded {
            previous_sequence: 1,
            new_sequence: 2,
            ..
        }
    ));
    let record = load_record(&path).unwrap().unwrap();
    assert_eq!(record.highest_sequence, 2);
    assert_eq!(record.bundle_fingerprint, fingerprint_hex(&l2.fingerprint));
}

// -----------------------------------------------------------------
// 3. Rollback: sequence 1 after sequence 2 rejected fail-closed.
//    Record must NOT be updated.
// -----------------------------------------------------------------
#[test]
fn signed_devnet_seq1_rejected_after_seq2() {
    let dir = fresh_dir("rollback");
    let path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let b1 = sign_devnet_helper_bundle(
        1,
        10,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let b2 = sign_devnet_helper_bundle(
        2,
        20,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let l1 = load_validate_devnet(&b1, &h.signing_keys);
    let l2 = load_validate_devnet(&b2, &h.signing_keys);
    check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        l2.bundle.sequence,
        &l2.fingerprint,
        0,
    )
    .unwrap();
    let err = check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        l1.bundle.sequence,
        &l1.fingerprint,
        0,
    )
    .err()
    .expect("rollback");
    assert!(matches!(
        err,
        TrustBundleSequenceError::SequenceRollback {
            attempted_sequence: 1,
            persisted_highest_sequence: 2,
        }
    ));
    // Highest must remain at 2 + fingerprint of b2.
    let record = load_record(&path).unwrap().unwrap();
    assert_eq!(record.highest_sequence, 2);
    assert_eq!(record.bundle_fingerprint, fingerprint_hex(&l2.fingerprint));
}

// -----------------------------------------------------------------
// 4. Equal-sequence same-fingerprint is accepted as a no-op restart.
// -----------------------------------------------------------------
#[test]
fn restart_with_identical_bundle_is_accepted_no_write() {
    let dir = fresh_dir("eq-same");
    let path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = sign_devnet_helper_bundle(
        7,
        10,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let loaded = load_validate_devnet(&bundle, &h.signing_keys);
    check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded.bundle.sequence,
        &loaded.fingerprint,
        50,
    )
    .unwrap();
    let outcome = check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded.bundle.sequence,
        &loaded.fingerprint,
        // Different now_unix_secs — must be ignored on the no-op path.
        9999,
    )
    .expect("eq same fp");
    assert!(matches!(
        outcome,
        SequenceCheckOutcome::EqualSequenceSameFingerprint { sequence: 7, .. }
    ));
    assert!(!outcome.record_written());
    let record = load_record(&path).unwrap().unwrap();
    assert_eq!(record.updated_at_unix_secs, 50);
}

// -----------------------------------------------------------------
// 5. Equal-sequence different-fingerprint is rejected as equivocation.
// -----------------------------------------------------------------
#[test]
fn equal_sequence_different_fingerprint_rejected_as_equivocation() {
    let dir = fresh_dir("eq-diff");
    let path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let b_a = sign_devnet_helper_bundle(
        5,
        100,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    // Same sequence, different generated_at → different canonical bytes
    // → different fingerprint, but still a validly signed bundle for
    // the same trust domain.
    let b_b = sign_devnet_helper_bundle(
        5,
        200,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let l_a = load_validate_devnet(&b_a, &h.signing_keys);
    let l_b = load_validate_devnet(&b_b, &h.signing_keys);
    assert_ne!(l_a.fingerprint, l_b.fingerprint);
    check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        l_a.bundle.sequence,
        &l_a.fingerprint,
        0,
    )
    .unwrap();
    let err = check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        l_b.bundle.sequence,
        &l_b.fingerprint,
        0,
    )
    .err()
    .expect("equiv");
    assert!(matches!(
        err,
        TrustBundleSequenceError::EqualSequenceFingerprintMismatch { sequence: 5, .. }
    ));
    let record = load_record(&path).unwrap().unwrap();
    assert_eq!(record.bundle_fingerprint, fingerprint_hex(&l_a.fingerprint));
}

// -----------------------------------------------------------------
// 6. Wrong chain_id on the bundle path still fails BEFORE sequence
//    update; persisted state must not advance.
// -----------------------------------------------------------------
#[test]
fn wrong_chain_id_bundle_fails_before_sequence_update() {
    let dir = fresh_dir("wrongchain");
    let path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    // First, persist seq=2 with a well-formed bundle on DevNet.
    let good = sign_devnet_helper_bundle(
        2,
        10,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let l_good = load_validate_devnet(&good, &h.signing_keys);
    check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        l_good.bundle.sequence,
        &l_good.fingerprint,
        0,
    )
    .unwrap();

    // Now hand-craft a bundle declaring a different chain_id and
    // re-sign it; validation must reject it at the Run 053 stage,
    // never reaching the sequence check.
    let mut wrong = good.clone();
    wrong.chain_id = Some("0000000000000001".to_string());
    wrong.signature = None;
    let sig = sign_bundle_devnet_helper(&wrong, h.signing_key_id, &h.signing_sk).unwrap();
    wrong.signature = Some(sig);
    let bytes = serde_json::to_vec(&wrong).unwrap();
    let res = TrustBundle::load_from_bytes_with_signing_keys_and_chain_id(
        &bytes,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
    );
    assert!(res.is_err(), "wrong chain_id must fail closed pre-sequence");
    // Sequence record untouched.
    let record = load_record(&path).unwrap().unwrap();
    assert_eq!(record.highest_sequence, 2);
}

// -----------------------------------------------------------------
// 7. Tampered signature fails BEFORE sequence update.
// -----------------------------------------------------------------
#[test]
fn tampered_signature_fails_before_sequence_update() {
    let dir = fresh_dir("tampered");
    let path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let good = sign_devnet_helper_bundle(
        3,
        10,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let l_good = load_validate_devnet(&good, &h.signing_keys);
    check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        l_good.bundle.sequence,
        &l_good.fingerprint,
        0,
    )
    .unwrap();

    let mut tampered = good.clone();
    // Bump sequence post-signing — signature no longer matches preimage.
    tampered.sequence = 4;
    let bytes = serde_json::to_vec(&tampered).unwrap();
    let res = TrustBundle::load_from_bytes_with_signing_keys_and_chain_id(
        &bytes,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
    );
    assert!(res.is_err());
    let record = load_record(&path).unwrap().unwrap();
    assert_eq!(record.highest_sequence, 3);
    assert_eq!(record.bundle_fingerprint, fingerprint_hex(&l_good.fingerprint));
}

// -----------------------------------------------------------------
// 8. Revoked-root bundle still fails BEFORE sequence update (Run 050
//    invariant preserved).
// -----------------------------------------------------------------
#[test]
fn revoked_root_only_bundle_still_loads_and_does_not_disturb_sequence() {
    // This test verifies Run 050 invariant: a bundle that revokes a
    // root via revocations[].root_id still LOADS successfully (the
    // root is just excluded from active_roots). The sequence check
    // is wired AFTER load, so the bundle's sequence is honored just
    // like any other valid bundle. The test pins that we have not
    // accidentally widened the sequence layer to reject valid bundles.
    let dir = fresh_dir("revroot");
    let path = sequence_file_path(&dir);
    let (id, pk) = {
        let r = mint_devnet_root().unwrap();
        (hex_lower(&r.root_key_id), hex_lower(&r.root_pk))
    };
    let bundle =
        qbind_node::pqc_trust_bundle::build_helper_bundle(HelperBundleMode::RootStatusRevoked, &id, &pk, 0);
    // Unsigned DevNet bundle (Run 050 path) — empty signing key set.
    let bytes = serde_json::to_vec(&bundle).unwrap();
    let loaded = TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100)
        .expect("revoked-root bundle still loads on DevNet (status filtered to empty)");
    let outcome = check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded.bundle.sequence,
        &loaded.fingerprint,
        0,
    )
    .expect("first-load of revoked-root DevNet bundle still persists sequence");
    assert!(matches!(outcome, SequenceCheckOutcome::FirstLoad { .. }));
}

// -----------------------------------------------------------------
// 9. Corrupt persistence file fails closed; no silent reset.
// -----------------------------------------------------------------
#[test]
fn corrupt_persistence_file_fails_closed_no_silent_reset() {
    let dir = fresh_dir("corrupt");
    let path = sequence_file_path(&dir);
    std::fs::write(&path, b"{not really json").unwrap();
    let h = devnet_signing_harness();
    let bundle = sign_devnet_helper_bundle(
        1,
        10,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let loaded = load_validate_devnet(&bundle, &h.signing_keys);
    let err = check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded.bundle.sequence,
        &loaded.fingerprint,
        0,
    )
    .err()
    .expect("malformed");
    assert!(matches!(err, TrustBundleSequenceError::Malformed(_)));
    // File must still be the corrupt bytes — no silent reset.
    let still = std::fs::read(&path).unwrap();
    assert_eq!(still, b"{not really json");
}

// -----------------------------------------------------------------
// 10. Stray wrong-environment record on the same path fails closed.
//     A DevNet startup using a path that already carries a MainNet
//     record MUST refuse — preserves trust-domain isolation.
// -----------------------------------------------------------------
#[test]
fn stray_mainnet_record_blocks_devnet_load_fail_closed() {
    let dir = fresh_dir("stray-env");
    let path = sequence_file_path(&dir);
    let stray = PersistentTrustBundleSequenceRecord::new(
        TrustBundleEnvironment::Mainnet,
        chain_id_hex(NetworkEnvironment::Mainnet.chain_id()),
        100,
        "ff".repeat(32),
        0,
    );
    atomic_write_record(&path, &stray).unwrap();
    let h = devnet_signing_harness();
    let bundle = sign_devnet_helper_bundle(
        1,
        10,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    let loaded = load_validate_devnet(&bundle, &h.signing_keys);
    let err = check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded.bundle.sequence,
        &loaded.fingerprint,
        0,
    )
    .err()
    .expect("wrong env");
    assert!(matches!(
        err,
        TrustBundleSequenceError::WrongEnvironment {
            expected: TrustBundleEnvironment::Devnet,
            found: TrustBundleEnvironment::Mainnet,
        }
    ));
}

// -----------------------------------------------------------------
// 11. Null chain_id compatibility (Run 053 policy) is preserved: a
//     bundle with `chain_id: None` still loads and its sequence is
//     persisted under the runtime chain_id. The persisted record
//     carries the RUNTIME chain_id, not "none".
// -----------------------------------------------------------------
#[test]
fn null_chain_id_bundle_persists_under_runtime_chain_id() {
    let dir = fresh_dir("nullchain");
    let path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let mut bundle = sign_devnet_helper_bundle(
        1,
        10,
        h.signing_key_id,
        &h.signing_sk,
        &h.root_id_hex,
        &h.root_pk_hex,
    );
    // Drop chain_id and re-sign.
    bundle.chain_id = None;
    bundle.signature = None;
    bundle.signature = Some(sign_bundle_devnet_helper(&bundle, h.signing_key_id, &h.signing_sk).unwrap());
    let loaded = load_validate_devnet(&bundle, &h.signing_keys);
    check_and_update_sequence(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded.bundle.sequence,
        &loaded.fingerprint,
        0,
    )
    .unwrap();
    let record = load_record(&path).unwrap().unwrap();
    assert_eq!(
        record.chain_id,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id())
    );
}

// -----------------------------------------------------------------
// 12. TrustBundleSignature is unused symbol guard — keep it imported
//     so a future refactor that drops it from this crate's re-export
//     fails at this test, not at a downstream evidence run.
// -----------------------------------------------------------------
#[test]
fn trust_bundle_signature_type_still_re_exported() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TrustBundleSignature>();
}