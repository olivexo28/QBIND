//! Run 069 (C4 piece: PQC trust-bundle hot-reload —
//! disabled-by-default validation/staging boundary): integration tests
//! for `qbind_node::pqc_trust_reload::validate_candidate_bundle`.
//!
//! These tests prove the **non-mutating** contract of the Run 069
//! reload-check: a valid candidate validates without applying, every
//! rejection class fails closed, and on **every** path
//! (positive AND negative) the on-disk anti-rollback sequence record
//! is left bit-for-bit unchanged. They do NOT spawn the `qbind-node`
//! binary; they exercise the public library entry point. The
//! matching release-binary smokes are recorded in
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md`.
//!
//! Coverage matrix (per RUN_069_TASK.txt §"Required tests"):
//!
//! 1. valid higher-sequence candidate validates;
//! 2. lower-sequence candidate rejected as rollback;
//! 3. equal-sequence different-fingerprint candidate rejected;
//! 4. wrong-chain candidate rejected;
//! 5. tampered-signature candidate rejected;
//! 6. too-soon activation candidate rejected (Run 057 future-height);
//! 7. local revoked-leaf candidate rejected (Run 061 reuse);
//! 8. local issuer-root revoked candidate rejected (Run 063 reuse);
//! 9. startup path (`check_and_update_sequence`) still updates the
//!    persistence record after a reload-check ran first;
//! 10. startup path still merges active roots into the trust set
//!     (proven by re-loading the bundle through the live loader and
//!     asserting `loaded.active_roots` is non-empty after the
//!     reload-check returned).
//! 11. no-prior-record peek reports `NoPriorRecord` without writing
//!     the persistence file.

use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::{ActivationContext, TrustBundleActivationError};
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleError, TrustBundleRevocation,
    TrustBundleRoot,
};
use qbind_node::pqc_trust_reload::{
    validate_candidate_bundle, validate_candidate_bundle_full, ReloadCheckError,
    ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::{
    chain_id_hex, check_and_update_sequence, fingerprint_hex, load_record, peek_sequence,
    sequence_file_path, SequenceCheckOutcome, SequencePeekOutcome, TrustBundleSequenceError,
};
use qbind_types::NetworkEnvironment;
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

// ---------------------------------------------------------------------
// Helpers (mirror the shape used by Run 055/061/063 tests).
// ---------------------------------------------------------------------

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", x);
    }
    s
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run069-{}-{}-{}",
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

struct DevnetSigningHarness {
    signing_keys: BundleSigningKeySet,
    signing_key_id: [u8; 32],
    signing_sk: Vec<u8>,
    root_id: [u8; 32],
    root_id_hex: String,
    root_pk_hex: String,
}

fn devnet_signing_harness() -> DevnetSigningHarness {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key");
    let id = derive_signing_key_id(&pk);
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: pk,
    }]);
    let root = mint_devnet_root().expect("mint devnet root");
    DevnetSigningHarness {
        signing_keys,
        signing_key_id: id,
        signing_sk: sk,
        root_id: root.root_key_id,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

/// Build + sign a DevNet trust bundle at the given sequence,
/// optionally including a single revocation entry and an optional
/// `activation_height`. `generated_at` lets equal-sequence tests mint
/// two bundles with distinct canonical fingerprints.
fn build_signed_devnet_bundle(
    h: &DevnetSigningHarness,
    sequence: u64,
    generated_at: u64,
    activation_height: Option<u64>,
    revocations: Vec<TrustBundleRevocation>,
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
            root_id: h.root_id_hex.clone(),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            root_pk: h.root_pk_hex.clone(),
            status: RootStatus::Active,
            not_before: 0,
            not_after: u64::MAX,
            activation_epoch: None,
            activation_height: None,
        }],
        revocations,
        signature: None,
        activation_epoch: None,
        activation_height,
    };
    let sig = sign_bundle_devnet_helper(&bundle, h.signing_key_id, &h.signing_sk).expect("sign");
    bundle.signature = Some(sig);
    bundle
}

fn write_bundle_to_disk(dir: &Path, name: &str, bundle: &TrustBundle) -> PathBuf {
    let path = dir.join(name);
    let bytes = serde_json::to_vec(bundle).expect("serialise bundle");
    std::fs::write(&path, &bytes).expect("write bundle");
    path
}

fn fixture_cert_with_root(validator_byte: u8, root_id: [u8; 32]) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id: [validator_byte; 32],
        root_key_id: root_id,
        leaf_kem_suite_id: 1,
        leaf_kem_pk: vec![0x22; 32],
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: vec![],
        sig_suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        sig_bytes: vec![0x33; 64],
    }
}

fn encode_cert_bytes(cert: &NetworkDelegationCert) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    cert.encode(&mut out);
    out
}

/// Snapshot the persistence file (bytes + mtime) so a test can assert
/// the reload-check is byte-for-byte non-mutating.
fn snapshot_seq_file(path: &Path) -> Option<(Vec<u8>, std::time::SystemTime)> {
    if !path.exists() {
        return None;
    }
    let bytes = std::fs::read(path).expect("read seq file");
    let mtime = std::fs::metadata(path)
        .expect("metadata")
        .modified()
        .expect("mtime");
    Some((bytes, mtime))
}

fn assert_seq_file_unchanged(
    path: &Path,
    snapshot: Option<(Vec<u8>, std::time::SystemTime)>,
) {
    match (snapshot, path.exists()) {
        (None, false) => { /* both absent — ok */ }
        (None, true) => panic!(
            "reload-check must not create persistence file at {}",
            path.display()
        ),
        (Some(_), false) => panic!(
            "reload-check must not delete persistence file at {}",
            path.display()
        ),
        (Some((bytes_before, mtime_before)), true) => {
            let bytes_after = std::fs::read(path).expect("read seq file");
            assert_eq!(
                bytes_before, bytes_after,
                "reload-check must not rewrite persistence file"
            );
            let mtime_after = std::fs::metadata(path)
                .expect("metadata")
                .modified()
                .expect("mtime");
            assert_eq!(
                mtime_before, mtime_after,
                "reload-check must not touch persistence file mtime"
            );
        }
    }
}

fn devnet_inputs<'a>(
    candidate_path: &'a Path,
    signing_keys: &'a BundleSigningKeySet,
    seq_path: Option<&'a Path>,
    activation_current_height: u64,
    leaf_bytes: Option<&'a [u8]>,
) -> ReloadCheckInputs<'a> {
    ReloadCheckInputs {
        candidate_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys,
        activation_ctx: ActivationContext::height_only(activation_current_height),
        sequence_persistence_path: seq_path,
        local_leaf_cert_bytes: leaf_bytes,
    }
}

// ============================================================================
// 1. Positive: valid higher-sequence candidate validates without write.
// ============================================================================

#[test]
fn run069_valid_higher_sequence_candidate_validates_and_does_not_write_sequence() {
    let dir = tmpdir("valid-higher");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Pre-seed sequence=1 baseline.
    let b1 = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    let b1_path = write_bundle_to_disk(&dir, "b1.json", &b1);
    let (loaded1, _) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &b1_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ActivationContext::height_only(0),
    )
    .expect("seed bundle loads");
    check_and_update_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded1.bundle.sequence,
        &loaded1.fingerprint,
        0,
    )
    .expect("seed sequence write");
    let seq_snapshot = snapshot_seq_file(&seq_path);

    // Candidate at sequence=2.
    let b2 = build_signed_devnet_bundle(&h, 2, 20, None, vec![]);
    let b2_path = write_bundle_to_disk(&dir, "b2.json", &b2);

    let inputs = devnet_inputs(&b2_path, &h.signing_keys, Some(&seq_path), 0, None);
    let candidate = validate_candidate_bundle(inputs).expect("valid candidate");
    assert_eq!(candidate.sequence, 2);
    assert_eq!(candidate.environment, TrustBundleEnvironment::Devnet);
    assert!(candidate.signature_verified);
    assert_eq!(candidate.active_root_count, 1);
    assert!(matches!(
        candidate.sequence_peek,
        SequencePeekOutcome::WouldUpgrade {
            previous_sequence: 1,
            candidate_sequence: 2,
            ..
        }
    ));
    let log_line = candidate.staged_metadata_log_line();
    assert!(log_line.contains("Run 069"));
    assert!(log_line.contains("not applied"));
    assert!(log_line.contains("sequence not persisted"));
    assert!(log_line.contains("live trust state unchanged"));

    // Persistence MUST NOT have been touched by the reload-check.
    assert_seq_file_unchanged(&seq_path, seq_snapshot);
    let record_after = load_record(&seq_path).unwrap().unwrap();
    assert_eq!(record_after.highest_sequence, 1);
    assert_eq!(record_after.bundle_fingerprint, fingerprint_hex(&loaded1.fingerprint));
}

// ============================================================================
// 2. Negative: lower-sequence candidate rejected as rollback.
// ============================================================================

#[test]
fn run069_lower_sequence_candidate_rejected_as_rollback_without_mutation() {
    let dir = tmpdir("rollback");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Baseline sequence=5.
    let b5 = build_signed_devnet_bundle(&h, 5, 10, None, vec![]);
    let b5_path = write_bundle_to_disk(&dir, "b5.json", &b5);
    let (loaded5, _) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &b5_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ActivationContext::height_only(0),
    )
    .expect("seed bundle loads");
    check_and_update_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded5.bundle.sequence,
        &loaded5.fingerprint,
        0,
    )
    .expect("seed seq=5");
    let snap = snapshot_seq_file(&seq_path);

    // Candidate at sequence=3 (rollback).
    let b3 = build_signed_devnet_bundle(&h, 3, 20, None, vec![]);
    let b3_path = write_bundle_to_disk(&dir, "b3.json", &b3);
    let inputs = devnet_inputs(&b3_path, &h.signing_keys, Some(&seq_path), 0, None);

    let err = validate_candidate_bundle(inputs).expect_err("rollback rejected");
    match err {
        ReloadCheckError::Sequence(TrustBundleSequenceError::SequenceRollback {
            attempted_sequence: 3,
            persisted_highest_sequence: 5,
        }) => {}
        other => panic!("expected SequenceRollback, got {:?}", other),
    }
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 3. Negative: equal-sequence different-fingerprint rejected as equivocation.
// ============================================================================

#[test]
fn run069_equal_sequence_different_fingerprint_rejected_without_mutation() {
    let dir = tmpdir("equivocation");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let baseline = build_signed_devnet_bundle(&h, 2, 10, None, vec![]);
    let baseline_path = write_bundle_to_disk(&dir, "baseline.json", &baseline);
    let (loaded_base, _) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &baseline_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ActivationContext::height_only(0),
    )
    .expect("baseline loads");
    check_and_update_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded_base.bundle.sequence,
        &loaded_base.fingerprint,
        0,
    )
    .expect("seed seq=2");
    let snap = snapshot_seq_file(&seq_path);

    // Candidate at same sequence=2 but distinct fingerprint (different
    // generated_at).
    let candidate = build_signed_devnet_bundle(&h, 2, 99, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "equivocator.json", &candidate);
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);

    let err = validate_candidate_bundle(inputs).expect_err("equivocation rejected");
    assert!(matches!(
        err,
        ReloadCheckError::Sequence(
            TrustBundleSequenceError::EqualSequenceFingerprintMismatch { sequence: 2, .. }
        )
    ));
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 4. Negative: wrong-chain candidate rejected.
// ============================================================================

#[test]
fn run069_wrong_chain_id_candidate_rejected_without_mutation() {
    let dir = tmpdir("wrong-chain");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Build a bundle declaring TESTNET chain id while we feed DevNet
    // runtime — the env enforcement triggers WrongEnvironment.
    // For pure chain-id mismatch (env matches but chain_id doesn't),
    // we set a manual mismatching chain_id while keeping the env
    // DevNet, then re-sign.
    let mut bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    bundle.signature = None;
    bundle.chain_id = Some("0000000000000001".to_string()); // not DevNet's id
    let sig = sign_bundle_devnet_helper(&bundle, h.signing_key_id, &h.signing_sk).expect("re-sign");
    bundle.signature = Some(sig);
    let candidate_path = write_bundle_to_disk(&dir, "wrong-chain.json", &bundle);

    let snap = snapshot_seq_file(&seq_path);
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let err = validate_candidate_bundle(inputs).expect_err("wrong chain rejected");
    match err {
        ReloadCheckError::Bundle(TrustBundleError::WrongChainId { .. }) => {}
        other => panic!("expected WrongChainId, got {:?}", other),
    }
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 5. Negative: tampered-signature candidate rejected.
// ============================================================================

#[test]
fn run069_tampered_signature_candidate_rejected_without_mutation() {
    let dir = tmpdir("tampered");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let mut bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    // Flip one byte of the signature.
    if let Some(sig) = bundle.signature.as_mut() {
        let mut bytes: Vec<u8> = (0..sig.sig_bytes.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig.sig_bytes[i..i + 2], 16).expect("hex"))
            .collect();
        bytes[0] ^= 0xFF;
        sig.sig_bytes = hex_lower(&bytes);
    }
    let candidate_path = write_bundle_to_disk(&dir, "tampered.json", &bundle);

    let snap = snapshot_seq_file(&seq_path);
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let err = validate_candidate_bundle(inputs).expect_err("tampered rejected");
    match err {
        ReloadCheckError::Bundle(TrustBundleError::BadSignature { .. }) => {}
        ReloadCheckError::Bundle(TrustBundleError::MalformedSignatureBytes { .. }) => {}
        other => panic!("expected BadSignature/MalformedSignatureBytes, got {:?}", other),
    }
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 6. Negative: too-soon activation candidate rejected (Run 057 future-height).
// ============================================================================

#[test]
fn run069_too_soon_activation_candidate_rejected_without_mutation() {
    let dir = tmpdir("too-soon");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Bundle declares activation_height=100, but the runtime
    // current_height=0 — Run 057 future-height rejection.
    // (DevNet min-activation-margin = 0, so the bundle reaches the
    // Run 057 gate rather than the Run 065 minimum-margin gate.)
    let bundle = build_signed_devnet_bundle(&h, 1, 10, Some(100), vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "too-soon.json", &bundle);

    let snap = snapshot_seq_file(&seq_path);
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let err = validate_candidate_bundle(inputs).expect_err("future activation rejected");
    match err {
        ReloadCheckError::Bundle(TrustBundleError::Activation(
            TrustBundleActivationError::ActivationHeightNotYetReached { .. },
        )) => {}
        other => panic!(
            "expected Activation(ActivationHeightNotYetReached), got {:?}",
            other
        ),
    }
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 7. Negative: local revoked-leaf candidate rejected (Run 061 reuse).
// ============================================================================

#[test]
fn run069_local_revoked_leaf_candidate_rejected_without_mutation() {
    let dir = tmpdir("local-leaf-revoked");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Build a leaf cert issued by the bundle's root, compute its
    // canonical Run 052 fingerprint, and add a leaf-revocation entry
    // for that fingerprint to the candidate bundle.
    let cert = fixture_cert_with_root(0xA1, h.root_id);
    let cert_bytes = encode_cert_bytes(&cert);
    let leaf_fp =
        qbind_node::pqc_trust_bundle::cert_leaf_fingerprint(&cert);
    let leaf_fp_hex = hex_lower(&leaf_fp);

    let revocation = TrustBundleRevocation {
        root_id: h.root_id_hex.clone(),
        leaf_cert_fingerprint: Some(leaf_fp_hex),
        reason: "leaf-compromise".to_string(),
        effective_from: 0,
        activation_height: None,
    };
    let bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![revocation]);
    let candidate_path = write_bundle_to_disk(&dir, "leaf-revoke.json", &bundle);

    let snap = snapshot_seq_file(&seq_path);
    let inputs = devnet_inputs(
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        0,
        Some(&cert_bytes),
    );
    let err = validate_candidate_bundle(inputs).expect_err("local leaf revoked rejected");
    match err {
        ReloadCheckError::LocalLeafRevoked(_) => {}
        other => panic!("expected LocalLeafRevoked, got {:?}", other),
    }
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 8. Negative: local issuer-root revoked candidate rejected (Run 063 reuse).
// ============================================================================

#[test]
fn run069_local_issuer_root_revoked_candidate_rejected_without_mutation() {
    let dir = tmpdir("local-issuer-root-revoked");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let cert = fixture_cert_with_root(0xA2, h.root_id);
    let cert_bytes = encode_cert_bytes(&cert);

    // Active root-scope revocation against the same root that issues
    // the local leaf cert.
    let revocation = TrustBundleRevocation {
        root_id: h.root_id_hex.clone(),
        leaf_cert_fingerprint: None,
        reason: "root-compromise".to_string(),
        effective_from: 0,
        activation_height: None,
    };
    let bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![revocation]);
    let candidate_path = write_bundle_to_disk(&dir, "root-revoke.json", &bundle);

    let snap = snapshot_seq_file(&seq_path);
    let inputs = devnet_inputs(
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        0,
        Some(&cert_bytes),
    );
    let err = validate_candidate_bundle(inputs)
        .expect_err("local issuer-root revoked rejected");
    match err {
        ReloadCheckError::LocalIssuerRootRevoked(_) => {}
        other => panic!("expected LocalIssuerRootRevoked, got {:?}", other),
    }
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 9. Positive: startup path still updates the persistence record AFTER a
//    reload-check ran first.
// ============================================================================

#[test]
fn run069_startup_path_still_persists_after_reload_check_runs_first() {
    let dir = tmpdir("startup-still-persists");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Baseline seq=1.
    let b1 = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    let b1_path = write_bundle_to_disk(&dir, "b1.json", &b1);
    let (loaded1, _) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &b1_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ActivationContext::height_only(0),
    )
    .expect("baseline loads");
    check_and_update_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded1.bundle.sequence,
        &loaded1.fingerprint,
        0,
    )
    .expect("seed seq=1");

    // Run reload-check for a future seq=2 candidate first.
    let b2 = build_signed_devnet_bundle(&h, 2, 20, None, vec![]);
    let b2_path = write_bundle_to_disk(&dir, "b2.json", &b2);
    let reload_snap = snapshot_seq_file(&seq_path);
    let inputs = devnet_inputs(&b2_path, &h.signing_keys, Some(&seq_path), 0, None);
    validate_candidate_bundle(inputs).expect("candidate valid");
    assert_seq_file_unchanged(&seq_path, reload_snap);
    // Persisted record MUST still be 1, untouched.
    let mid_record = load_record(&seq_path).unwrap().unwrap();
    assert_eq!(mid_record.highest_sequence, 1);

    // Now run the live startup-style update with the same candidate.
    let (loaded2, _) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &b2_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ActivationContext::height_only(0),
    )
    .expect("candidate loads via live loader");
    let outcome = check_and_update_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded2.bundle.sequence,
        &loaded2.fingerprint,
        0,
    )
    .expect("live path upgrade");
    assert!(matches!(
        outcome,
        SequenceCheckOutcome::Upgraded {
            previous_sequence: 1,
            new_sequence: 2,
            ..
        }
    ));
    let final_record = load_record(&seq_path).unwrap().unwrap();
    assert_eq!(final_record.highest_sequence, 2);
    assert_eq!(
        final_record.bundle_fingerprint,
        fingerprint_hex(&loaded2.fingerprint)
    );
}

// ============================================================================
// 10. Positive: startup path still produces active_roots; reload-check matches.
// ============================================================================

#[test]
fn run069_reload_check_and_live_loader_agree_on_active_roots() {
    let dir = tmpdir("agree-active-roots");
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 7, 10, None, vec![]);
    let bundle_path = write_bundle_to_disk(&dir, "b.json", &bundle);

    // Reload-check (validation-only).
    let inputs = ReloadCheckInputs {
        candidate_path: &bundle_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
    };
    let (loaded_reload, _, candidate) =
        validate_candidate_bundle_full(inputs).expect("reload validate");
    assert_eq!(loaded_reload.active_root_count(), 1);
    assert_eq!(candidate.active_root_count, 1);
    assert!(candidate.signature_verified);

    // Live loader path on the same file.
    let (loaded_live, _) =
        TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
            &bundle_path,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            100,
            &h.signing_keys,
            ActivationContext::height_only(0),
        )
        .expect("live loader");
    assert_eq!(loaded_live.active_root_count(), loaded_reload.active_root_count());
    assert_eq!(loaded_live.fingerprint, loaded_reload.fingerprint);
}

// ============================================================================
// 11. Positive: no-prior-record peek reports NoPriorRecord, no file written.
// ============================================================================

#[test]
fn run069_no_prior_record_peek_does_not_create_persistence_file() {
    let dir = tmpdir("no-prior");
    let seq_path = sequence_file_path(&dir);
    assert!(!seq_path.exists(), "precondition: file must be absent");
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    let bundle_path = write_bundle_to_disk(&dir, "b.json", &bundle);

    let inputs = devnet_inputs(&bundle_path, &h.signing_keys, Some(&seq_path), 0, None);
    let candidate = validate_candidate_bundle(inputs).expect("no-prior valid");
    assert!(matches!(
        candidate.sequence_peek,
        SequencePeekOutcome::NoPriorRecord {
            candidate_sequence: 1,
            ..
        }
    ));
    assert!(
        !seq_path.exists(),
        "reload-check must NOT create persistence file under DevNet validation-only path"
    );
}

// ============================================================================
// 12. Read-only-ness: even on success, peek_sequence directly observes the
//     persisted record unchanged.
// ============================================================================

#[test]
fn run069_peek_sequence_observes_unchanged_record_after_reload_check_success() {
    let dir = tmpdir("peek-after");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Baseline seq=2.
    let b2 = build_signed_devnet_bundle(&h, 2, 10, None, vec![]);
    let b2_path = write_bundle_to_disk(&dir, "b2.json", &b2);
    let (loaded2, _) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &b2_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ActivationContext::height_only(0),
    )
    .expect("baseline loads");
    check_and_update_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded2.bundle.sequence,
        &loaded2.fingerprint,
        0,
    )
    .expect("seed seq=2");
    let baseline_fp = loaded2.fingerprint;

    // Run reload-check for seq=5.
    let b5 = build_signed_devnet_bundle(&h, 5, 50, None, vec![]);
    let b5_path = write_bundle_to_disk(&dir, "b5.json", &b5);
    let inputs = devnet_inputs(&b5_path, &h.signing_keys, Some(&seq_path), 0, None);
    let _ = validate_candidate_bundle(inputs).expect("seq=5 candidate valid");

    // Direct peek confirms the persistence baseline is still seq=2.
    let peek_again = peek_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        2,
        &baseline_fp,
    )
    .expect("direct peek still ok");
    assert!(matches!(
        peek_again,
        SequencePeekOutcome::EqualSequenceSameFingerprint { sequence: 2, .. }
    ));
}