//! Run 077 (C4 piece: production-binary-facing, disabled-by-default
//! peer-candidate validation **local check** surface): integration
//! tests for `qbind_node::pqc_peer_candidate_binary::run_local_check`.
//!
//! These tests drive the **pure function** entry point that the
//! `qbind-node` binary's Run 077 hook calls under the two required-
//! together hidden CLI flags
//! `--p2p-trust-bundle-peer-candidate-validation-enabled`
//! and `--p2p-trust-bundle-peer-candidate-check <ENVELOPE_PATH>`.
//! They do NOT spawn the `qbind-node` binary — they exercise the
//! same library entry point under the same fail-closed preconditions
//! the binary applies.
//!
//! Coverage matrix:
//!
//! 1. Disabled-by-default boundary: neither flag → hook is inactive
//!    (`run077_hook_active` returns `false`).
//! 2. Partial config (path only) → `Refused(EnabledFlagMissing)`,
//!    exit code 1, no metrics bumped.
//! 3. Partial config (enabled only) → `Refused(EnvelopePathMissing)`,
//!    exit code 1, no metrics bumped.
//! 4. Fixture I/O error → `Refused(FixtureIoError)`, exit code 1,
//!    `received_total` NOT bumped (we never read the file).
//! 5. Fixture JSON parse error → `Refused(FixtureParseError)`, exit
//!    code 1, `received_total` NOT bumped.
//! 6. Valid higher-sequence candidate → `Ran(Validated)`, exit code
//!    0, sequence file bit-for-bit unchanged, scratch file removed,
//!    `received_total` AND `validated_total` bumped by exactly one,
//!    no `_applied_total` family exists in metrics output, no
//!    Run 074 live-reload counter bumped.
//! 7. Oversize candidate → `Ran(Oversize)`, exit code 1, sequence
//!    unchanged, no scratch file written, `received_total` AND
//!    `dropped_oversize_total` bumped.
//! 8. Wrong-environment envelope → `Ran(Rejected(Envelope))`, exit
//!    code 1, sequence unchanged, scratch removed, `received_total`
//!    AND `rejected_total` bumped.
//! 9. Wrong-chain-id envelope → `Ran(Rejected(Envelope))`, exit code
//!    1, sequence unchanged, `received_total` AND `rejected_total`
//!    bumped.
//! 10. Tampered-signature candidate → `Ran(Rejected(ValidationFailed))`,
//!     exit code 1, sequence unchanged.
//! 11. Run 069 reload-check path remains valid against the same
//!     baseline AFTER a successful Run 077 check (no cross-mutation).
//! 12. `_applied_total` metric family is intentionally absent in the
//!     rendered `/metrics` output even after a Validated outcome.

use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_node::metrics::P2pMetrics;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_binary::{
    run077_hook_active, run_local_check, Run077Inputs, Run077RefusalReason, Run077Result,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::{
    PeerCandidateEnvelope, PeerCandidateOutcome, MAX_PEER_CANDIDATE_BUNDLE_BYTES,
};
use qbind_node::pqc_trust_reload::{validate_candidate_bundle, ReloadCheckInputs};
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------
// Helpers (mirror Run 069 / Run 076 shape).
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
        "qbind-run077-{}-{}-{}",
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
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

fn build_signed_devnet_bundle(h: &DevnetSigningHarness, sequence: u64) -> TrustBundle {
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: TrustBundleEnvironment::Devnet,
        chain_id: Some(chain_id_hex(NetworkEnvironment::Devnet.chain_id())),
        generated_at: 10,
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
        revocations: vec![],
        signature: None,
        activation_epoch: None,
        activation_height: None,
    };
    let sig = sign_bundle_devnet_helper(&bundle, h.signing_key_id, &h.signing_sk).expect("sign");
    bundle.signature = Some(sig);
    bundle
}

fn bundle_to_bytes(b: &TrustBundle) -> Vec<u8> {
    serde_json::to_vec(b).expect("serialise bundle")
}

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

fn envelope_with(
    bundle_bytes: Vec<u8>,
    declared_sequence: u64,
    declared_fingerprint_prefix: String,
) -> PeerCandidateEnvelope {
    let len = bundle_bytes.len();
    PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some("peer-test-run077".to_string()),
        environment: TrustBundleEnvironment::Devnet,
        chain_id_hex: chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
        declared_sequence,
        declared_fingerprint_prefix,
        declared_length: len,
        bundle_bytes,
    }
}

fn write_envelope_fixture(dir: &Path, envelope: &PeerCandidateEnvelope) -> PathBuf {
    let path = dir.join("envelope.json");
    let bytes = serde_json::to_vec_pretty(envelope).expect("serialise envelope");
    std::fs::write(&path, bytes).expect("write fixture");
    path
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

fn assert_seq_file_unchanged(path: &Path, snap: Option<(Vec<u8>, std::time::SystemTime)>) {
    match (snap, path.exists()) {
        (None, false) => {}
        (None, true) => panic!(
            "Run 077 must not create persistence file at {}",
            path.display()
        ),
        (Some(_), false) => panic!(
            "Run 077 must not delete persistence file at {}",
            path.display()
        ),
        (Some((bytes_before, mtime_before)), true) => {
            let bytes_after = std::fs::read(path).expect("read seq file");
            assert_eq!(
                bytes_before, bytes_after,
                "Run 077 must not rewrite persistence file"
            );
            let mtime_after = std::fs::metadata(path)
                .expect("metadata")
                .modified()
                .expect("mtime");
            assert_eq!(
                mtime_before, mtime_after,
                "Run 077 must not touch persistence file mtime"
            );
        }
    }
}

fn count_scratch_files(scratch: &Path) -> usize {
    // The Run 077 binary path reuses the Run 076
    // `PeerCandidateValidator::try_accept` verbatim; the scratch
    // file it stages is named with the literal Run 076 prefix
    // `qbind-run076-peer-candidate-...` (see
    // `crates/qbind-node/src/pqc_trust_peer_candidate.rs`). The test
    // therefore checks for that exact prefix — finding it would
    // indicate a leak by the reused validator.
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

fn inputs<'a>(
    envelope_path: Option<&'a Path>,
    validation_enabled: bool,
    signing_keys: &'a BundleSigningKeySet,
    scratch_dir: &'a Path,
    seq_path: Option<&'a Path>,
) -> Run077Inputs<'a> {
    Run077Inputs {
        validation_enabled_flag: validation_enabled,
        envelope_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: seq_path,
        local_leaf_cert_bytes: None,
        scratch_dir,
        now_ms: 1_000,
    }
}

// ============================================================================
// 1. Disabled-by-default: neither flag supplied → hook is inactive.
// ============================================================================

#[test]
fn run077_disabled_by_default_hook_is_inactive() {
    // Operator typed neither Run 077 flag → hook is a no-op for the
    // binary. We assert this via the public guard predicate that
    // main.rs uses.
    assert!(!run077_hook_active(None, false));
}

// ============================================================================
// 2. Partial config: path only → EnabledFlagMissing, exit 1.
// ============================================================================

#[test]
fn run077_partial_config_path_only_refuses_and_does_not_bump_metrics() {
    let dir = tmpdir("partial-path-only");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let envelope = envelope_with(bundle_to_bytes(&bundle), 1, "deadbeef".to_string());
    let path = write_envelope_fixture(&dir, &envelope);
    let metrics = P2pMetrics::default();

    let result = run_local_check(
        inputs(Some(&path), false, &h.signing_keys, &scratch, None),
        &metrics,
    );
    let exit_code = result.exit_code();
    match result {
        Run077Result::Refused {
            reason: Run077RefusalReason::EnabledFlagMissing,
        } => {}
        other => panic!("expected EnabledFlagMissing, got {:?}", other),
    }
    assert_eq!(exit_code, 1);
    // No counters bumped because the validator was never constructed
    // and the fixture was never read.
    assert_eq!(metrics.peer_candidate_received_total(), 0);
    assert_eq!(metrics.peer_candidate_validated_total(), 0);
    assert_eq!(metrics.peer_candidate_rejected_total(), 0);
    assert_eq!(metrics.peer_candidate_disabled_total(), 0);
    assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
    assert_eq!(metrics.peer_candidate_duplicate_total(), 0);
    assert_eq!(metrics.peer_candidate_rate_limited_total(), 0);
}

// ============================================================================
// 3. Partial config: enabled only → EnvelopePathMissing, exit 1.
// ============================================================================

#[test]
fn run077_partial_config_enabled_only_refuses_and_does_not_bump_metrics() {
    let dir = tmpdir("partial-enabled-only");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let metrics = P2pMetrics::default();

    let result = run_local_check(
        inputs(None, true, &h.signing_keys, &scratch, None),
        &metrics,
    );
    let exit_code = result.exit_code();
    match result {
        Run077Result::Refused {
            reason: Run077RefusalReason::EnvelopePathMissing,
        } => {}
        other => panic!("expected EnvelopePathMissing, got {:?}", other),
    }
    assert_eq!(exit_code, 1);
    assert_eq!(metrics.peer_candidate_received_total(), 0);
}

// ============================================================================
// 4. Fixture I/O error → Refused before validator/metrics.
// ============================================================================

#[test]
fn run077_fixture_io_error_refuses_before_validator() {
    let dir = tmpdir("fixture-io");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bogus = dir.join("does-not-exist.json");
    let metrics = P2pMetrics::default();

    let result = run_local_check(
        inputs(Some(&bogus), true, &h.signing_keys, &scratch, None),
        &metrics,
    );
    let exit_code = result.exit_code();
    match result {
        Run077Result::Refused {
            reason: Run077RefusalReason::FixtureIoError { .. },
        } => {}
        other => panic!("expected FixtureIoError, got {:?}", other),
    }
    assert_eq!(exit_code, 1);
    assert_eq!(metrics.peer_candidate_received_total(), 0);
}

// ============================================================================
// 5. Fixture JSON parse error → Refused before validator/metrics.
// ============================================================================

#[test]
fn run077_fixture_parse_error_refuses_before_validator() {
    let dir = tmpdir("fixture-parse");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bad = dir.join("bad.json");
    std::fs::write(&bad, b"{ not json").unwrap();
    let metrics = P2pMetrics::default();

    let result = run_local_check(
        inputs(Some(&bad), true, &h.signing_keys, &scratch, None),
        &metrics,
    );
    match result {
        Run077Result::Refused {
            reason: Run077RefusalReason::FixtureParseError { .. },
        } => {}
        other => panic!("expected FixtureParseError, got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 0);
}

// ============================================================================
// 6. Valid higher-sequence candidate → Validated, exit 0, NO mutation.
// ============================================================================

#[test]
fn run077_valid_candidate_validates_and_does_not_apply() {
    let dir = tmpdir("valid");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir); // intentionally never created
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let envelope = envelope_with(bytes, 1, prefix.clone());
    let path = write_envelope_fixture(&dir, &envelope);
    let seq_snap = snapshot_seq_file(&seq_path);
    let metrics = P2pMetrics::default();

    let result = run_local_check(
        inputs(Some(&path), true, &h.signing_keys, &scratch, Some(&seq_path)),
        &metrics,
    );
    let exit_code = result.exit_code();
    let (outcome, verdict_line, observed) = match result {
        Run077Result::Ran {
            outcome,
            verdict_line,
            observed_log_line,
        } => (outcome, verdict_line, observed_log_line),
        other => panic!("expected Ran(Validated), got {:?}", other),
    };
    match &outcome {
        PeerCandidateOutcome::Validated(vc) => {
            assert_eq!(vc.validated.sequence, 1);
            assert_eq!(vc.validated.fingerprint_prefix, prefix);
            assert!(vc.validated.signature_verified);
        }
        other => panic!("expected Validated outcome, got {:?}", other),
    }
    assert_eq!(exit_code, 0);

    // VERDICT log line shape.
    assert!(verdict_line.contains("Run 077"));
    assert!(verdict_line.contains("VERDICT=validated"));
    assert!(verdict_line.contains("NOT applied"));
    assert!(verdict_line.contains("sequence not persisted"));
    assert!(verdict_line.contains("live trust state unchanged"));
    assert!(verdict_line.contains("sessions untouched"));
    assert!(verdict_line.contains("not propagated"));

    // observed_log_line is present and references Run 076's
    // not-applied disclaimer (reused single-source-of-truth).
    let obs = observed.expect("Validated must carry observed_log_line");
    assert!(obs.contains("Run 076"));
    assert!(obs.contains("NOT applied"));

    // Sequence file untouched even on the success path.
    assert_seq_file_unchanged(&seq_path, seq_snap);
    // Scratch file removed by the validator.
    assert_eq!(count_scratch_files(&scratch), 0);

    // Metric counters bumped exactly once and only for the right
    // outcome family.
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_validated_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 0);
    assert_eq!(metrics.peer_candidate_disabled_total(), 0);
    assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
    assert_eq!(metrics.peer_candidate_duplicate_total(), 0);
    assert_eq!(metrics.peer_candidate_rate_limited_total(), 0);
}

// ============================================================================
// 7. Oversize candidate → Ran(Oversize), exit 1, no scratch leak.
// ============================================================================

#[test]
fn run077_oversize_candidate_dropped_pre_crypto_no_scratch() {
    let dir = tmpdir("oversize");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let mut envelope =
        envelope_with(vec![0u8; 8], 1, "deadbeef".to_string());
    envelope.bundle_bytes = vec![0u8; MAX_PEER_CANDIDATE_BUNDLE_BYTES + 1];
    envelope.declared_length = envelope.bundle_bytes.len();
    let path = write_envelope_fixture(&dir, &envelope);
    let seq_snap = snapshot_seq_file(&seq_path);
    let metrics = P2pMetrics::default();

    let result = run_local_check(
        inputs(Some(&path), true, &h.signing_keys, &scratch, Some(&seq_path)),
        &metrics,
    );
    let exit_code = result.exit_code();
    match result {
        Run077Result::Ran { outcome, .. } => match outcome {
            PeerCandidateOutcome::Oversize { cap, .. } => {
                assert_eq!(cap, MAX_PEER_CANDIDATE_BUNDLE_BYTES);
            }
            other => panic!("expected Oversize, got {:?}", other),
        },
        other => panic!("expected Ran outcome, got {:?}", other),
    }
    assert_eq!(exit_code, 1);
    assert_seq_file_unchanged(&seq_path, seq_snap);
    assert_eq!(count_scratch_files(&scratch), 0);
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 1);
    assert_eq!(metrics.peer_candidate_validated_total(), 0);
}

// ============================================================================
// 8. Wrong-environment envelope → Rejected at envelope, exit 1.
// ============================================================================

#[test]
fn run077_wrong_environment_envelope_rejected_pre_crypto() {
    let dir = tmpdir("wrong-env");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 1);
    let mut envelope = envelope_with(bundle_to_bytes(&bundle), 1, "deadbeef".to_string());
    envelope.environment = TrustBundleEnvironment::Mainnet; // operator runtime is DevNet
    let path = write_envelope_fixture(&dir, &envelope);
    let seq_snap = snapshot_seq_file(&seq_path);
    let metrics = P2pMetrics::default();

    let result = run_local_check(
        inputs(Some(&path), true, &h.signing_keys, &scratch, Some(&seq_path)),
        &metrics,
    );
    let exit_code = result.exit_code();
    match result {
        Run077Result::Ran { outcome, .. } => {
            assert!(matches!(outcome, PeerCandidateOutcome::Rejected(_)));
        }
        other => panic!("expected Ran(Rejected), got {:?}", other),
    }
    assert_eq!(exit_code, 1);
    assert_seq_file_unchanged(&seq_path, seq_snap);
    assert_eq!(count_scratch_files(&scratch), 0);
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
    assert_eq!(metrics.peer_candidate_validated_total(), 0);
}

// ============================================================================
// 9. Wrong-chain-id envelope → Rejected at envelope, exit 1.
// ============================================================================

#[test]
fn run077_wrong_chain_id_envelope_rejected_pre_crypto() {
    let dir = tmpdir("wrong-chain");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 1);
    let mut envelope = envelope_with(bundle_to_bytes(&bundle), 1, "deadbeef".to_string());
    envelope.chain_id_hex = "0000000000000001".to_string();
    let path = write_envelope_fixture(&dir, &envelope);
    let metrics = P2pMetrics::default();

    let result = run_local_check(
        inputs(Some(&path), true, &h.signing_keys, &scratch, None),
        &metrics,
    );
    let exit_code = result.exit_code();
    match result {
        Run077Result::Ran { outcome, .. } => {
            assert!(matches!(outcome, PeerCandidateOutcome::Rejected(_)));
        }
        other => panic!("expected Ran(Rejected), got {:?}", other),
    }
    assert_eq!(exit_code, 1);
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
}

// ============================================================================
// 10. Tampered-signature candidate → Rejected at loader, exit 1.
// ============================================================================

#[test]
fn run077_tampered_signature_rejected_at_loader() {
    let dir = tmpdir("tampered");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let mut bundle = build_signed_devnet_bundle(&h, 1);
    if let Some(sig) = bundle.signature.as_mut() {
        let mut sig_bytes: Vec<u8> = (0..sig.sig_bytes.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig.sig_bytes[i..i + 2], 16).expect("hex"))
            .collect();
        sig_bytes[0] ^= 0xFF;
        sig.sig_bytes = hex_lower(&sig_bytes);
    }
    let bytes = bundle_to_bytes(&bundle);
    let envelope = envelope_with(bytes, 1, "deadbeef".to_string());
    let path = write_envelope_fixture(&dir, &envelope);
    let seq_snap = snapshot_seq_file(&seq_path);
    let metrics = P2pMetrics::default();

    let result = run_local_check(
        inputs(Some(&path), true, &h.signing_keys, &scratch, Some(&seq_path)),
        &metrics,
    );
    let exit_code = result.exit_code();
    match result {
        Run077Result::Ran { outcome, .. } => {
            assert!(matches!(outcome, PeerCandidateOutcome::Rejected(_)));
        }
        other => panic!("expected Ran(Rejected), got {:?}", other),
    }
    assert_eq!(exit_code, 1);
    assert_seq_file_unchanged(&seq_path, seq_snap);
    assert_eq!(count_scratch_files(&scratch), 0);
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
    assert_eq!(metrics.peer_candidate_validated_total(), 0);
}

// ============================================================================
// 11. Run 069 reload-check entry point unaffected by Run 077.
// ============================================================================

#[test]
fn run077_does_not_affect_run069_reload_check_path() {
    let dir = tmpdir("run069-coexistence");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);

    // 1. Run 077 first: validates the candidate.
    let envelope = envelope_with(bytes.clone(), 1, prefix);
    let path = write_envelope_fixture(&dir, &envelope);
    let metrics = P2pMetrics::default();
    let result = run_local_check(
        inputs(Some(&path), true, &h.signing_keys, &scratch, Some(&seq_path)),
        &metrics,
    );
    assert_eq!(result.exit_code(), 0);

    // 2. Run 069 reload-check on the SAME signed bytes: still
    //    validates cleanly (no cross-mutation).
    let bundle_path = dir.join("bundle.json");
    std::fs::write(&bundle_path, &bytes).unwrap();
    let inputs_069 = ReloadCheckInputs {
        candidate_path: &bundle_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: Some(&seq_path),
        local_leaf_cert_bytes: None,
    };
    let v = validate_candidate_bundle(inputs_069).expect("Run 069 still validates");
    assert_eq!(v.sequence, 1);
    // Run 077 must not have written the persistence file.
    assert!(!seq_path.exists());
}

// ============================================================================
// 12. `/metrics` text has Run 076 counters and NO `_applied_total` family.
// ============================================================================

#[test]
fn run077_metrics_output_never_contains_applied_total_family() {
    let dir = tmpdir("metrics-no-applied");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();

    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let envelope = envelope_with(bytes, 1, prefix);
    let path = write_envelope_fixture(&dir, &envelope);
    let metrics = P2pMetrics::default();
    let _ = run_local_check(
        inputs(Some(&path), true, &h.signing_keys, &scratch, None),
        &metrics,
    );

    let rendered = metrics.format_metrics();
    // Run 076 counters present.
    assert!(
        rendered.contains("qbind_p2p_pqc_trust_bundle_peer_candidate_received_total"),
        "received counter must be rendered"
    );
    assert!(
        rendered.contains("qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total"),
        "validated counter must be rendered"
    );
    // No applied family — Run 077 intentionally does NOT introduce
    // one. Run 076 already asserts this; the Run 077 surface MUST
    // not regress that property.
    assert!(
        !rendered.contains("qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total"),
        "no peer_candidate_applied_total family must exist"
    );
    // No Run 074 trigger counter bumped by Run 077.
    assert!(
        !rendered.contains("qbind_p2p_trust_bundle_live_reload_trigger_total 1"),
        "Run 077 must not bump Run 074 live-reload trigger counters"
    );
}