//! Run 076 (C4 piece: peer/gossiped trust-bundle candidate validation
//! boundary — disabled-by-default, validation-only): integration
//! tests for `qbind_node::pqc_trust_peer_candidate::PeerCandidateValidator`.
//!
//! These tests prove the **non-mutating** contract of the Run 076
//! peer-supplied candidate validator: when explicitly enabled, a
//! valid candidate validates without applying; every rejection class
//! fails closed; on **every** path the on-disk anti-rollback sequence
//! record is left bit-for-bit unchanged AND the validator never
//! mutates any live PQC trust state (no apply API even exists on the
//! Run 076 surface). They do NOT spawn the `qbind-node` binary; they
//! exercise the public library entry point.
//!
//! Coverage matrix (per `task/RUN_076_TASK.txt` §"Required tests"):
//!
//! 1. Disabled-by-default validator never touches payload (no temp
//!    file written, no sequence-file write).
//! 2. Valid higher-sequence candidate validates and is **not**
//!    applied — sequence file unchanged.
//! 3. Tampered-signature candidate rejected at loader stage, file
//!    unchanged.
//! 4. Wrong-environment candidate rejected at the envelope layer
//!    BEFORE any crypto runs.
//! 5. Wrong-chain-id candidate rejected at the envelope layer
//!    BEFORE any crypto runs.
//! 6. Lower-sequence candidate rejected as rollback by Run 055 peek
//!    (read-only), file unchanged.
//! 7. Equal-sequence different-fingerprint candidate rejected as
//!    equivocation by Run 055 peek, file unchanged.
//! 8. Local revoked-leaf candidate rejected by Run 061 self-check,
//!    file unchanged.
//! 9. Local issuer-root revoked candidate rejected by Run 063
//!    self-check, file unchanged.
//! 10. Oversize candidate dropped BEFORE any crypto and BEFORE any
//!     temp file is written.
//! 11. Declared-length-vs-payload mismatch rejected at envelope.
//! 12. Declared-fingerprint-prefix mismatch (envelope vs parsed
//!     bundle) rejected AFTER loader.
//! 13. Declared-sequence mismatch (envelope vs parsed bundle)
//!     rejected AFTER loader.
//! 14. Duplicate-fingerprint suppression: a second call with the
//!     same prefix short-circuits without doing crypto again.
//! 15. Rate-limit kicks in after `max_in_window` admissions.
//! 16. Run 069 reload-check entry point unaffected by Run 076 —
//!     both paths can run side by side without mutating each other.

use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleError, TrustBundleRevocation,
    TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::{
    PeerCandidateConfig, PeerCandidateEnvelope, PeerCandidateEnvelopeError, PeerCandidateOutcome,
    PeerCandidateRejection, PeerCandidateRuntimeContext, PeerCandidateValidator,
    MAX_PEER_CANDIDATE_BUNDLE_BYTES,
};
use qbind_node::pqc_trust_reload::{
    validate_candidate_bundle, ReloadCheckError, ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::{
    chain_id_hex, check_and_update_sequence, sequence_file_path, SequencePeekOutcome,
    TrustBundleSequenceError,
};
use qbind_types::NetworkEnvironment;
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

// ---------------------------------------------------------------------
// Helpers (mirror Run 069 shape).
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
        "qbind-run076-{}-{}-{}",
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
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
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

fn bundle_to_bytes(b: &TrustBundle) -> Vec<u8> {
    serde_json::to_vec(b).expect("serialise bundle")
}

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

fn assert_seq_file_unchanged(path: &Path, snapshot: Option<(Vec<u8>, std::time::SystemTime)>) {
    match (snapshot, path.exists()) {
        (None, false) => {}
        (None, true) => panic!(
            "Run 076 must not create persistence file at {}",
            path.display()
        ),
        (Some(_), false) => panic!(
            "Run 076 must not delete persistence file at {}",
            path.display()
        ),
        (Some((bytes_before, mtime_before)), true) => {
            let bytes_after = std::fs::read(path).expect("read seq file");
            assert_eq!(
                bytes_before, bytes_after,
                "Run 076 must not rewrite persistence file"
            );
            let mtime_after = std::fs::metadata(path)
                .expect("metadata")
                .modified()
                .expect("mtime");
            assert_eq!(
                mtime_before, mtime_after,
                "Run 076 must not touch persistence file mtime"
            );
        }
    }
}

fn count_scratch_files(scratch: &Path) -> usize {
    std::fs::read_dir(scratch)
        .map(|it| {
            it.filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("qbind-run076-peer-candidate-")
                })
                .count()
        })
        .unwrap_or(0)
}

fn compute_bundle_fp_prefix(_bytes: &[u8]) -> String {
    // Placeholder 8-hex prefix used in tests where the loader is
    // expected to fail BEFORE the validator can reach the declared-
    // prefix cross-check (so the value here doesn't need to match
    // anything authoritative).
    "deadbeef".to_string()
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

/// Authoritative declared-fingerprint-prefix: parse the candidate via
/// the same loader, read its fingerprint_hex, take the first 8 chars.
fn loader_fingerprint_prefix(bundle_bytes: &[u8], keys: &BundleSigningKeySet) -> String {
    let dir = tmpdir("fpprobe");
    let path = dir.join("probe.json");
    std::fs::write(&path, bundle_bytes).expect("write probe");
    let inputs = ReloadCheckInputs {
        candidate_path: &path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys: keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
    };
    let v = validate_candidate_bundle(inputs).expect("probe validates");
    v.fingerprint_prefix
}

fn enabled_config() -> PeerCandidateConfig {
    PeerCandidateConfig {
        enabled: true,
        ..PeerCandidateConfig::default()
    }
}

fn envelope_with(
    bundle_bytes: Vec<u8>,
    declared_sequence: u64,
    declared_fingerprint_prefix: String,
) -> PeerCandidateEnvelope {
    let len = bundle_bytes.len();
    PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some("peer-test".to_string()),
        environment: TrustBundleEnvironment::Devnet,
        chain_id_hex: chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
        declared_sequence,
        declared_fingerprint_prefix,
        declared_length: len,
        bundle_bytes,
    }
}

fn ctx<'a>(
    scratch: &'a Path,
    keys: &'a BundleSigningKeySet,
    seq_path: Option<&'a Path>,
    leaf_bytes: Option<&'a [u8]>,
) -> PeerCandidateRuntimeContext<'a> {
    PeerCandidateRuntimeContext {
        expected_environment: NetworkEnvironment::Devnet,
        expected_chain_id: NetworkEnvironment::Devnet.chain_id(),
        scratch_dir: scratch,
        validation_time_secs: 100,
        signing_keys: keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: seq_path,
        local_leaf_cert_bytes: leaf_bytes,
        now_ms: 1_000,
    }
}

// ============================================================================
// 1. Disabled-by-default: NO mutation, NO crypto, NO scratch file written.
// ============================================================================

#[test]
fn run076_disabled_by_default_is_noop() {
    let dir = tmpdir("disabled");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 3, 10, None, vec![]);
    let bytes = bundle_to_bytes(&bundle);
    let env = envelope_with(bytes, 3, "deadbeef".to_string());

    let mut v = PeerCandidateValidator::disabled();
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, Some(&seq_path), None));
    assert!(matches!(out, PeerCandidateOutcome::Disabled));
    // No scratch files left behind.
    assert_eq!(count_scratch_files(&scratch), 0);
    // Persistence not created.
    assert!(!seq_path.exists());
}

// ============================================================================
// 2. Positive: valid higher-sequence candidate validates and is NOT applied.
// ============================================================================

#[test]
fn run076_valid_higher_sequence_candidate_validates_but_not_applied() {
    let dir = tmpdir("valid-higher");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Pre-seed sequence=1 baseline.
    let b1 = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    let b1_bytes = bundle_to_bytes(&b1);
    let b1_path = dir.join("b1.json");
    std::fs::write(&b1_path, &b1_bytes).unwrap();
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
    let b2_bytes = bundle_to_bytes(&b2);
    let prefix = loader_fingerprint_prefix(&b2_bytes, &h.signing_keys);
    let env = envelope_with(b2_bytes, 2, prefix.clone());

    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, Some(&seq_path), None));
    match out {
        PeerCandidateOutcome::Validated(vc) => {
            assert_eq!(vc.validated.sequence, 2);
            assert_eq!(vc.validated.fingerprint_prefix, prefix);
            assert!(vc.validated.signature_verified);
            assert!(matches!(
                vc.validated.sequence_peek,
                SequencePeekOutcome::WouldUpgrade {
                    previous_sequence: 1,
                    candidate_sequence: 2,
                    ..
                }
            ));
            let log_line = vc.observed_log_line();
            assert!(log_line.contains("Run 076"));
            assert!(log_line.contains("NOT applied"));
            assert!(log_line.contains("sequence not persisted"));
            assert!(log_line.contains("live trust state unchanged"));
            assert!(log_line.contains("sessions untouched"));
            assert!(log_line.contains("not propagated"));
        }
        other => panic!("expected Validated, got {:?}", other),
    }
    // Sequence file untouched even on the success path — Run 076 is
    // strictly validation-only.
    assert_seq_file_unchanged(&seq_path, seq_snapshot);
    // Scratch file removed.
    assert_eq!(count_scratch_files(&scratch), 0);
}

// ============================================================================
// 3. Tampered-signature candidate rejected at loader; file unchanged.
// ============================================================================

#[test]
fn run076_tampered_signature_candidate_rejected_at_loader() {
    let dir = tmpdir("tampered");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let mut bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    if let Some(sig) = bundle.signature.as_mut() {
        let mut bytes: Vec<u8> = (0..sig.sig_bytes.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig.sig_bytes[i..i + 2], 16).expect("hex"))
            .collect();
        bytes[0] ^= 0xFF;
        sig.sig_bytes = hex_lower(&bytes);
    }
    let bytes = bundle_to_bytes(&bundle);
    let pfx = compute_bundle_fp_prefix(&bytes); // Anything 8-hex; loader will reject before we cross-check.
    let env = envelope_with(bytes, 1, pfx);

    let snap = snapshot_seq_file(&seq_path);
    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, Some(&seq_path), None));
    match out {
        PeerCandidateOutcome::Rejected(PeerCandidateRejection::ValidationFailed(
            ReloadCheckError::Bundle(TrustBundleError::BadSignature { .. })
            | ReloadCheckError::Bundle(TrustBundleError::MalformedSignatureBytes { .. }),
        )) => {}
        other => panic!("expected loader BadSignature, got {:?}", other),
    }
    assert_seq_file_unchanged(&seq_path, snap);
    assert_eq!(count_scratch_files(&scratch), 0);
}

// ============================================================================
// 4. Wrong-environment envelope rejected BEFORE any crypto runs.
// ============================================================================

#[test]
fn run076_wrong_environment_envelope_rejected_pre_crypto() {
    let dir = tmpdir("wrong-env");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    let mut env = envelope_with(bundle_to_bytes(&bundle), 1, "deadbeef".to_string());
    env.environment = TrustBundleEnvironment::Mainnet; // operator runtime is DevNet
    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, Some(&seq_path), None));
    assert!(matches!(
        out,
        PeerCandidateOutcome::Rejected(PeerCandidateRejection::Envelope(
            PeerCandidateEnvelopeError::EnvironmentMismatch { .. }
        ))
    ));
    // No scratch file should have been written (envelope pre-check
    // failed BEFORE we paid the temp-file cost).
    assert_eq!(count_scratch_files(&scratch), 0);
    assert!(!seq_path.exists());
}

// ============================================================================
// 5. Wrong-chain-id envelope rejected BEFORE any crypto runs.
// ============================================================================

#[test]
fn run076_wrong_chain_id_envelope_rejected_pre_crypto() {
    let dir = tmpdir("wrong-chain");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    let mut env = envelope_with(bundle_to_bytes(&bundle), 1, "deadbeef".to_string());
    env.chain_id_hex = "0000000000000001".to_string();
    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, None, None));
    assert!(matches!(
        out,
        PeerCandidateOutcome::Rejected(PeerCandidateRejection::Envelope(
            PeerCandidateEnvelopeError::ChainIdMismatch { .. }
        ))
    ));
    assert_eq!(count_scratch_files(&scratch), 0);
}

// ============================================================================
// 6. Rollback (lower-sequence) candidate rejected by Run 055 peek; file unchanged.
// ============================================================================

#[test]
fn run076_rollback_candidate_rejected_by_read_only_peek() {
    let dir = tmpdir("rollback");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Baseline seq=5.
    let b5 = build_signed_devnet_bundle(&h, 5, 10, None, vec![]);
    let b5_bytes = bundle_to_bytes(&b5);
    let b5_path = dir.join("b5.json");
    std::fs::write(&b5_path, &b5_bytes).unwrap();
    let (loaded5, _) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &b5_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ActivationContext::height_only(0),
    )
    .expect("seed");
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

    let b3 = build_signed_devnet_bundle(&h, 3, 20, None, vec![]);
    let b3_bytes = bundle_to_bytes(&b3);
    let prefix = loader_fingerprint_prefix(&b3_bytes, &h.signing_keys);
    let env = envelope_with(b3_bytes, 3, prefix);

    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, Some(&seq_path), None));
    match out {
        PeerCandidateOutcome::Rejected(PeerCandidateRejection::ValidationFailed(
            ReloadCheckError::Sequence(TrustBundleSequenceError::SequenceRollback {
                attempted_sequence: 3,
                persisted_highest_sequence: 5,
            }),
        )) => {}
        other => panic!("expected SequenceRollback, got {:?}", other),
    }
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 7. Equal-sequence different-fingerprint candidate rejected.
// ============================================================================

#[test]
fn run076_equal_sequence_different_fingerprint_rejected() {
    let dir = tmpdir("equivocation");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let baseline = build_signed_devnet_bundle(&h, 2, 10, None, vec![]);
    let baseline_path = dir.join("baseline.json");
    std::fs::write(&baseline_path, bundle_to_bytes(&baseline)).unwrap();
    let (loaded, _) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
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
        loaded.bundle.sequence,
        &loaded.fingerprint,
        0,
    )
    .expect("seed seq=2");
    let snap = snapshot_seq_file(&seq_path);

    let other = build_signed_devnet_bundle(&h, 2, 99, None, vec![]);
    let bytes = bundle_to_bytes(&other);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let env = envelope_with(bytes, 2, prefix);

    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, Some(&seq_path), None));
    assert!(matches!(
        out,
        PeerCandidateOutcome::Rejected(PeerCandidateRejection::ValidationFailed(
            ReloadCheckError::Sequence(
                TrustBundleSequenceError::EqualSequenceFingerprintMismatch { sequence: 2, .. }
            )
        ))
    ));
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 8. Local revoked-leaf candidate rejected (Run 061 reuse).
// ============================================================================

#[test]
fn run076_local_revoked_leaf_candidate_rejected() {
    let dir = tmpdir("local-leaf-revoked");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let cert = fixture_cert_with_root(0xA1, h.root_id);
    let cert_bytes = encode_cert_bytes(&cert);
    let leaf_fp = qbind_node::pqc_trust_bundle::cert_leaf_fingerprint(&cert);
    let leaf_fp_hex = hex_lower(&leaf_fp);

    let revocation = TrustBundleRevocation {
        root_id: h.root_id_hex.clone(),
        leaf_cert_fingerprint: Some(leaf_fp_hex),
        reason: "leaf-compromise".to_string(),
        effective_from: 0,
        activation_height: None,
    };
    let bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![revocation]);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let env = envelope_with(bytes, 1, prefix);

    let snap = snapshot_seq_file(&seq_path);
    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(
        env,
        &ctx(
            &scratch,
            &h.signing_keys,
            Some(&seq_path),
            Some(&cert_bytes),
        ),
    );
    assert!(matches!(
        out,
        PeerCandidateOutcome::Rejected(PeerCandidateRejection::ValidationFailed(
            ReloadCheckError::LocalLeafRevoked(_)
        ))
    ));
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 9. Local issuer-root revoked candidate rejected (Run 063 reuse).
// ============================================================================

#[test]
fn run076_local_issuer_root_revoked_candidate_rejected() {
    let dir = tmpdir("local-issuer-root-revoked");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let cert = fixture_cert_with_root(0xA2, h.root_id);
    let cert_bytes = encode_cert_bytes(&cert);

    let revocation = TrustBundleRevocation {
        root_id: h.root_id_hex.clone(),
        leaf_cert_fingerprint: None,
        reason: "root-compromise".to_string(),
        effective_from: 0,
        activation_height: None,
    };
    let bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![revocation]);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let env = envelope_with(bytes, 1, prefix);

    let snap = snapshot_seq_file(&seq_path);
    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(
        env,
        &ctx(
            &scratch,
            &h.signing_keys,
            Some(&seq_path),
            Some(&cert_bytes),
        ),
    );
    assert!(matches!(
        out,
        PeerCandidateOutcome::Rejected(PeerCandidateRejection::ValidationFailed(
            ReloadCheckError::LocalIssuerRootRevoked(_)
        ))
    ));
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 10. Oversize candidate dropped BEFORE any crypto, no scratch file.
// ============================================================================

#[test]
fn run076_oversize_candidate_dropped_pre_crypto_no_scratch() {
    let dir = tmpdir("oversize");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let huge = vec![0u8; MAX_PEER_CANDIDATE_BUNDLE_BYTES + 1];
    let env = envelope_with(huge, 1, "deadbeef".to_string());

    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, Some(&seq_path), None));
    match out {
        PeerCandidateOutcome::Oversize { cap, observed_len } => {
            assert_eq!(cap, MAX_PEER_CANDIDATE_BUNDLE_BYTES);
            assert!(observed_len > cap);
        }
        other => panic!("expected Oversize, got {:?}", other),
    }
    assert_eq!(count_scratch_files(&scratch), 0);
    assert!(!seq_path.exists());
}

// ============================================================================
// 11. Declared length-vs-payload mismatch rejected at envelope layer.
// ============================================================================

#[test]
fn run076_declared_length_payload_mismatch_rejected() {
    let dir = tmpdir("declared-len");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    let mut env = envelope_with(bundle_to_bytes(&bundle), 1, "deadbeef".to_string());
    env.declared_length = env.bundle_bytes.len() + 7;

    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, None, None));
    assert!(matches!(
        out,
        PeerCandidateOutcome::Rejected(PeerCandidateRejection::Envelope(
            PeerCandidateEnvelopeError::DeclaredLengthMismatch { .. }
        ))
    ));
    assert_eq!(count_scratch_files(&scratch), 0);
}

// ============================================================================
// 12. Declared-fingerprint-prefix mismatch (envelope vs parsed bundle).
// ============================================================================

#[test]
fn run076_declared_fingerprint_prefix_mismatch_after_loader() {
    let dir = tmpdir("fp-mismatch");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    let bytes = bundle_to_bytes(&bundle);
    // 8-hex but deliberately not matching loader's fingerprint prefix.
    let env = envelope_with(bytes, 1, "00000000".to_string());

    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, None, None));
    match out {
        PeerCandidateOutcome::Rejected(PeerCandidateRejection::DeclaredMetadataMismatch(m)) => {
            assert!(m.contains("declared_fingerprint_prefix"), "{}", m);
        }
        other => panic!("expected DeclaredMetadataMismatch (fp), got {:?}", other),
    }
}

// ============================================================================
// 13. Declared-sequence mismatch (envelope vs parsed bundle).
// ============================================================================

#[test]
fn run076_declared_sequence_mismatch_after_loader() {
    let dir = tmpdir("seq-mismatch");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 7, 10, None, vec![]);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    // Declared sequence != bundle.sequence.
    let env = envelope_with(bytes, 99, prefix);

    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, None, None));
    match out {
        PeerCandidateOutcome::Rejected(PeerCandidateRejection::DeclaredMetadataMismatch(m)) => {
            assert!(m.contains("declared_sequence"), "{}", m);
        }
        other => panic!("expected DeclaredMetadataMismatch (seq), got {:?}", other),
    }
}

// ============================================================================
// 14. Duplicate-fingerprint suppression: second call short-circuits.
// ============================================================================

#[test]
fn run076_duplicate_suppression_skips_second_crypto() {
    let dir = tmpdir("dup");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 1, 10, None, vec![]);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);

    let mut v = PeerCandidateValidator::new(enabled_config());
    // First call validates.
    let env1 = envelope_with(bytes.clone(), 1, prefix.clone());
    let out1 = v.try_accept(env1, &ctx(&scratch, &h.signing_keys, None, None));
    assert!(matches!(out1, PeerCandidateOutcome::Validated(_)));
    // Second call with identical prefix is suppressed.
    let env2 = envelope_with(bytes, 1, prefix.clone());
    let out2 = v.try_accept(env2, &ctx(&scratch, &h.signing_keys, None, None));
    match out2 {
        PeerCandidateOutcome::DuplicateSuppressed {
            fingerprint_prefix: fp,
        } => assert_eq!(fp, prefix),
        other => panic!("expected DuplicateSuppressed, got {:?}", other),
    }
}

// ============================================================================
// 15. Rate-limit kicks in after max_in_window admissions.
// ============================================================================

#[test]
fn run076_rate_limit_blocks_after_cap() {
    let dir = tmpdir("rate-limit");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();

    let mut cfg = enabled_config();
    cfg.max_in_window = 2;
    cfg.rate_limit_window_ms = 10_000;
    cfg.duplicate_suppression = false; // isolate the limiter from dup cache
    let mut v = PeerCandidateValidator::new(cfg);

    // Three different (distinct-fingerprint) candidates so dup cache
    // never short-circuits.
    let mk = |seq: u64, gen_at: u64| {
        let b = build_signed_devnet_bundle(&h, seq, gen_at, None, vec![]);
        let bytes = bundle_to_bytes(&b);
        let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
        envelope_with(bytes, seq, prefix)
    };

    let mut c = ctx(&scratch, &h.signing_keys, None, None);
    c.now_ms = 100;
    let o1 = v.try_accept(mk(10, 10), &c);
    assert!(matches!(o1, PeerCandidateOutcome::Validated(_)));
    c.now_ms = 200;
    let o2 = v.try_accept(mk(11, 11), &c);
    assert!(matches!(o2, PeerCandidateOutcome::Validated(_)));
    // Third call within the same window is blocked.
    c.now_ms = 300;
    let o3 = v.try_accept(mk(12, 12), &c);
    match o3 {
        PeerCandidateOutcome::RateLimited { cap, .. } => assert_eq!(cap, 2),
        other => panic!("expected RateLimited, got {:?}", other),
    }
}

// ============================================================================
// 16. Run 069 reload-check unaffected by Run 076 — both can run side
//     by side, neither mutates the other's state.
// ============================================================================

#[test]
fn run076_does_not_affect_run069_reload_check_path() {
    let dir = tmpdir("run069-parity");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Run 076 sees a candidate first.
    let bundle = build_signed_devnet_bundle(&h, 3, 10, None, vec![]);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let env = envelope_with(bytes.clone(), 3, prefix);
    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(env, &ctx(&scratch, &h.signing_keys, Some(&seq_path), None));
    assert!(matches!(out, PeerCandidateOutcome::Validated(_)));
    // No scratch file leftover, no seq file created by Run 076.
    assert_eq!(count_scratch_files(&scratch), 0);
    assert!(!seq_path.exists());

    // Now the local reload-check (Run 069) on the SAME bundle file
    // must still validate cleanly without seeing Run 076's
    // (non-)mutation.
    let cand_path = dir.join("cand.json");
    std::fs::write(&cand_path, &bytes).unwrap();
    let inputs = ReloadCheckInputs {
        candidate_path: &cand_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: Some(&seq_path),
        local_leaf_cert_bytes: None,
    };
    let v069 = validate_candidate_bundle(inputs).expect("Run 069 still validates");
    assert_eq!(v069.sequence, 3);
    assert!(!seq_path.exists());
}
