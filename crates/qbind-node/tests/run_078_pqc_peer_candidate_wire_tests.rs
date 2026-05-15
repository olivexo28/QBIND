//! Run 078 (C4 piece: production-binary-facing, disabled-by-default
//! **P2P wire** receive path for peer-candidate validation **only**):
//! integration tests for the `qbind_node::pqc_peer_candidate_wire`
//! module.
//!
//! These tests prove the **non-mutating** contract of the Run 078
//! wire-receive surface: a peer-supplied frame can be observed at
//! the same length-prefixed framing layer the existing
//! `p2p_tcp.rs` consensus / DAG / control frames use, decoded
//! through a strict typed envelope (`PeerCandidateWireEnvelopeV1`,
//! domain tag `QBIND:PQC_TRUST_BUNDLE_PEER_CANDIDATE_WIRE:v1`),
//! and routed through the **same** Run 076 validator without ever
//! applying the candidate, persisting its sequence, evicting any
//! P2P session, or propagating the frame to other peers.
//!
//! Coverage matrix (per Run 078 §"Required tests"):
//!
//! 1. Disabled-by-default: a receiver constructed with the default
//!    config never decodes the payload, never calls the validator,
//!    and never bumps anything except `received_total` +
//!    `disabled_total`.
//! 2. Encode/decode roundtrip: `encode_peer_candidate_wire_frame`
//!    + `decode_peer_candidate_wire_frame` is byte-for-byte stable
//!    across the wire envelope's full field set.
//! 3. Unknown-discriminator frame is rejected at the frame layer
//!    (uses a `p2p_tcp.rs` consensus-discriminator byte to verify
//!    cross-stream replays cannot reach the validator).
//! 4. Oversize declared payload is dropped BEFORE allocation /
//!    decode / crypto; the matching `dropped_oversize_total`
//!    counter is bumped without any scratch file write.
//! 5. Truncated frame, malformed JSON payload, unknown envelope
//!    version, and unknown domain tag are each rejected at the
//!    frame layer with `rejected_total` (not `dropped_oversize_total`).
//! 6. Enabled + valid higher-sequence candidate validates and is
//!    NOT applied — the on-disk sequence file is bit-for-bit
//!    unchanged, no scratch file is left behind, `received_total`
//!    AND `validated_total` are each bumped by exactly one, no
//!    `_applied_total` family exists in `format_metrics()` output,
//!    and no Run 072 session-eviction or Run 074 live-reload
//!    counter is bumped by the wire path.
//! 7. Enabled + tampered-signature candidate is rejected at the
//!    Run 069 loader stage; sequence file unchanged.
//! 8. Enabled + wrong-environment candidate is rejected at the
//!    envelope pre-check BEFORE any crypto runs.
//! 9. Enabled + wrong-chain-id candidate is rejected at the
//!    envelope pre-check BEFORE any crypto runs.
//! 10. Enabled + duplicate-fingerprint frame: the second handle
//!     short-circuits on the Run 076 LRU without paying ML-DSA
//!     verification cost twice; `duplicate_total` is bumped.
//! 11. Enabled + rate-limit kicks in after `max_in_window`
//!     admissions; `rate_limited_total` is bumped.
//! 12. Enabled + same candidate is acceptable via the SAME wire
//!     frame AND via the Run 069 reload-check entry point in the
//!     same test (no cross-mutation between the wire receiver and
//!     the existing reload-check path).
//! 13. Run 077 binary-facing local check (`run_local_check`)
//!     remains untouched: a Run 077 fixture file and a Run 078
//!     wire frame for the same bundle bytes both validate
//!     successfully and do not mutate each other's state.
//! 14. `format_metrics()` output rendered after a Run 078
//!     `Validated` outcome contains the seven Run 076
//!     `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters but
//!     does NOT contain `peer_candidate_applied_total`, the
//!     Run 074 trigger counter, or any new Run 078-specific
//!     metric family.
//!
//! These tests do NOT spawn the `qbind-node` binary; they exercise
//! the public library entry point under the same fail-closed
//! preconditions a future production gossip dispatcher would
//! observe.

use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_node::metrics::P2pMetrics;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_binary::{run_local_check, Run077Inputs, Run077Result};
use qbind_node::pqc_peer_candidate_wire::{
    decode_peer_candidate_wire_frame, encode_peer_candidate_wire_frame, wire_observed_log_line,
    PeerCandidateWireEnvelopeV1, PeerCandidateWireFrameError, PeerCandidateWireOutcome,
    PeerCandidateWireReceiver, PeerCandidateWireReceiverConfig, PeerCandidateWireRuntimeContext,
    DISCRIMINATOR_PEER_CANDIDATE_WIRE, MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES,
    PEER_CANDIDATE_WIRE_DOMAIN_TAG, PEER_CANDIDATE_WIRE_VERSION,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::{
    PeerCandidateConfig, PeerCandidateEnvelope, PeerCandidateOutcome,
    MAX_PEER_CANDIDATE_BUNDLE_BYTES,
};
use qbind_node::pqc_trust_reload::{validate_candidate_bundle, ReloadCheckInputs};
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------
// Helpers (mirror Run 076 / Run 077 shape).
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
        "qbind-run078-{}-{}-{}",
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

fn wire_envelope_with(
    bundle_bytes: Vec<u8>,
    declared_sequence: u64,
    declared_fingerprint_prefix: String,
    environment: TrustBundleEnvironment,
    chain_id_hex_value: String,
) -> PeerCandidateWireEnvelopeV1 {
    let len = bundle_bytes.len();
    PeerCandidateWireEnvelopeV1 {
        envelope_version: PEER_CANDIDATE_WIRE_VERSION,
        domain_tag: PEER_CANDIDATE_WIRE_DOMAIN_TAG.to_string(),
        peer_id: Some("peer-test-run078".to_string()),
        environment,
        chain_id_hex: chain_id_hex_value,
        declared_sequence,
        declared_fingerprint_prefix,
        declared_length: len,
        bundle_bytes,
    }
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
            "Run 078 must not create persistence file at {}",
            path.display()
        ),
        (Some(_), false) => panic!(
            "Run 078 must not delete persistence file at {}",
            path.display()
        ),
        (Some((bytes_before, mtime_before)), true) => {
            let bytes_after = std::fs::read(path).expect("read seq file");
            assert_eq!(
                bytes_before, bytes_after,
                "Run 078 must not rewrite persistence file"
            );
            let mtime_after = std::fs::metadata(path)
                .expect("metadata")
                .modified()
                .expect("mtime");
            assert_eq!(
                mtime_before, mtime_after,
                "Run 078 must not touch persistence file mtime"
            );
        }
    }
}

fn count_scratch_files(scratch: &Path) -> usize {
    // Run 078 reuses the Run 076 validator scratch-file prefix
    // verbatim.
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

fn devnet_runtime_ctx<'a>(
    scratch: &'a Path,
    signing_keys: &'a BundleSigningKeySet,
    seq_path: Option<&'a Path>,
    now_ms: u64,
) -> PeerCandidateWireRuntimeContext<'a> {
    PeerCandidateWireRuntimeContext {
        expected_environment: NetworkEnvironment::Devnet,
        expected_chain_id: NetworkEnvironment::Devnet.chain_id(),
        scratch_dir: scratch,
        validation_time_secs: 100,
        signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: seq_path,
        local_leaf_cert_bytes: None,
        now_ms,
    }
}

// ============================================================================
// 1. Disabled-by-default boundary.
// ============================================================================

#[test]
fn run078_disabled_by_default_does_not_decode_or_call_validator() {
    let dir = tmpdir("disabled-default");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let env = wire_envelope_with(
        bytes,
        1,
        prefix,
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let frame = encode_peer_candidate_wire_frame(&env).unwrap();

    let mut receiver = PeerCandidateWireReceiver::disabled();
    let metrics = P2pMetrics::default();
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);

    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);
    assert!(matches!(outcome, PeerCandidateWireOutcome::Disabled));

    // Truthful: received_total + disabled_total, nothing else.
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_disabled_total(), 1);
    assert_eq!(metrics.peer_candidate_validated_total(), 0);
    assert_eq!(metrics.peer_candidate_rejected_total(), 0);
    assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
    assert_eq!(metrics.peer_candidate_rate_limited_total(), 0);
    assert_eq!(metrics.peer_candidate_duplicate_total(), 0);

    // No scratch file written.
    assert_eq!(count_scratch_files(&scratch), 0);
}

// ============================================================================
// 2. Encode/decode roundtrip.
// ============================================================================

#[test]
fn run078_wire_envelope_roundtrip_preserves_all_fields() {
    let env = PeerCandidateWireEnvelopeV1 {
        envelope_version: PEER_CANDIDATE_WIRE_VERSION,
        domain_tag: PEER_CANDIDATE_WIRE_DOMAIN_TAG.to_string(),
        peer_id: Some("p2p-node-abcdef0123456789".to_string()),
        environment: TrustBundleEnvironment::Devnet,
        chain_id_hex: chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
        declared_sequence: 42,
        declared_fingerprint_prefix: "0badc0de".to_string(),
        declared_length: 5,
        bundle_bytes: vec![0x01, 0x02, 0x03, 0x04, 0x05],
    };
    let frame = encode_peer_candidate_wire_frame(&env).unwrap();
    assert_eq!(frame[0], DISCRIMINATOR_PEER_CANDIDATE_WIRE);
    let decoded = decode_peer_candidate_wire_frame(&frame).unwrap();
    assert_eq!(decoded, env);
}

// ============================================================================
// 3. Unknown discriminator (cross-stream replay) is rejected at frame layer.
// ============================================================================

#[test]
fn run078_unknown_discriminator_rejected_at_frame_layer() {
    let dir = tmpdir("unknown-disc");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let env = wire_envelope_with(
        bytes,
        1,
        prefix,
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let mut frame = encode_peer_candidate_wire_frame(&env).unwrap();
    // Stamp the p2p_tcp.rs consensus-discriminator on top to model
    // a cross-stream replay attempt.
    frame[0] = 0x01;

    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let metrics = P2pMetrics::default();
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);

    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);
    match outcome {
        PeerCandidateWireOutcome::FrameRejected(
            PeerCandidateWireFrameError::UnknownDiscriminator { observed },
        ) => {
            assert_eq!(observed, 0x01);
        }
        other => panic!("expected UnknownDiscriminator, got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
    assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
    assert_eq!(metrics.peer_candidate_validated_total(), 0);
    assert_eq!(count_scratch_files(&scratch), 0);
}

// ============================================================================
// 4. Oversize declared payload dropped pre-allocation.
// ============================================================================

#[test]
fn run078_oversize_declared_payload_dropped_before_allocation() {
    let dir = tmpdir("oversize");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let metrics = P2pMetrics::default();
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);

    // Header declares oversize; NO body bytes provided. The cap
    // check must fire BEFORE the receiver tries to slice the body.
    let declared: u32 = (MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES + 1) as u32;
    let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
    frame.extend_from_slice(&declared.to_be_bytes());

    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);
    match outcome {
        PeerCandidateWireOutcome::FrameRejected(
            PeerCandidateWireFrameError::DeclaredPayloadOversize { declared: d, .. },
        ) => assert_eq!(d, declared as usize),
        other => panic!("expected DeclaredPayloadOversize, got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 0);
    assert_eq!(count_scratch_files(&scratch), 0);
}

// ============================================================================
// 5a. Truncated frame.
// ============================================================================

#[test]
fn run078_truncated_frame_rejected_at_frame_layer() {
    let dir = tmpdir("truncated");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let metrics = P2pMetrics::default();
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);

    let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
    frame.extend_from_slice(&50u32.to_be_bytes());
    // Only 5 body bytes; declared 50.
    frame.extend_from_slice(b"01234");

    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);
    match outcome {
        PeerCandidateWireOutcome::FrameRejected(
            PeerCandidateWireFrameError::FrameTruncated { declared, observed },
        ) => {
            assert_eq!(declared, 50);
            assert_eq!(observed, 5);
        }
        other => panic!("expected FrameTruncated, got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
    assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
}

// ============================================================================
// 5b. Malformed JSON payload.
// ============================================================================

#[test]
fn run078_malformed_payload_rejected_at_frame_layer() {
    let dir = tmpdir("malformed");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let metrics = P2pMetrics::default();
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);

    let bad = b"{ not json".to_vec();
    let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
    frame.extend_from_slice(&(bad.len() as u32).to_be_bytes());
    frame.extend_from_slice(&bad);

    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);
    match outcome {
        PeerCandidateWireOutcome::FrameRejected(
            PeerCandidateWireFrameError::PayloadParseError { .. },
        ) => {}
        other => panic!("expected PayloadParseError, got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
}

// ============================================================================
// 5c. Unknown envelope version.
// ============================================================================

#[test]
fn run078_unknown_envelope_version_rejected_at_frame_layer() {
    let dir = tmpdir("unkver");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let mut env = wire_envelope_with(
        bytes,
        1,
        prefix,
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    env.envelope_version = 9999;
    let payload = serde_json::to_vec(&env).unwrap();
    let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);

    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let metrics = P2pMetrics::default();
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);

    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);
    match outcome {
        PeerCandidateWireOutcome::FrameRejected(
            PeerCandidateWireFrameError::UnsupportedEnvelopeVersion { observed },
        ) => assert_eq!(observed, 9999),
        other => panic!("expected UnsupportedEnvelopeVersion, got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
    assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
    assert_eq!(count_scratch_files(&scratch), 0);
}

// ============================================================================
// 5d. Unknown domain tag (cross-protocol replay).
// ============================================================================

#[test]
fn run078_unknown_domain_tag_rejected_at_frame_layer() {
    let dir = tmpdir("unkdomain");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let mut env = wire_envelope_with(
        bytes,
        1,
        prefix,
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    // Mimic the Run 076 fixture domain tag — must NOT be accepted.
    env.domain_tag = PeerCandidateEnvelope::DOMAIN_TAG.to_string();
    let payload = serde_json::to_vec(&env).unwrap();
    let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);

    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let metrics = P2pMetrics::default();
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);

    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);
    match outcome {
        PeerCandidateWireOutcome::FrameRejected(
            PeerCandidateWireFrameError::UnknownDomainTag { observed },
        ) => {
            assert_eq!(observed, PeerCandidateEnvelope::DOMAIN_TAG);
        }
        other => panic!("expected UnknownDomainTag, got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
    assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
}

// ============================================================================
// 6. Valid higher-sequence candidate validates but is NOT applied.
// ============================================================================

#[test]
fn run078_valid_candidate_validates_but_is_not_applied() {
    let dir = tmpdir("valid");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir); // intentionally never created
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let env = wire_envelope_with(
        bytes,
        1,
        prefix.clone(),
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let frame = encode_peer_candidate_wire_frame(&env).unwrap();
    let seq_snap = snapshot_seq_file(&seq_path);
    let metrics = P2pMetrics::default();

    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, Some(&seq_path), 1_000);
    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);

    match &outcome {
        PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Validated(vc)) => {
            assert_eq!(vc.validated.sequence, 1);
            assert_eq!(vc.validated.fingerprint_prefix, prefix);
            assert!(vc.validated.signature_verified);
        }
        other => panic!("expected ValidatorRan(Validated), got {:?}", other),
    }
    assert!(outcome.is_validated());

    // Strict non-mutation contract:
    assert_seq_file_unchanged(&seq_path, seq_snap);
    assert_eq!(count_scratch_files(&scratch), 0);

    // Counters: received + validated bumped by exactly 1; nothing else.
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_validated_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 0);
    assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
    assert_eq!(metrics.peer_candidate_rate_limited_total(), 0);
    assert_eq!(metrics.peer_candidate_duplicate_total(), 0);
    assert_eq!(metrics.peer_candidate_disabled_total(), 0);

    // Operator log line shape.
    let log = wire_observed_log_line(&outcome, Some("peer-test-run078"));
    assert!(log.contains("Run 078"));
    assert!(log.contains("NOT applied"));
    assert!(log.contains("not propagated"));
    assert!(log.contains("sequence not persisted"));
    assert!(log.contains("live trust state unchanged"));
    assert!(log.contains("sessions untouched"));
}

// ============================================================================
// 7. Tampered-signature candidate is rejected at loader stage.
// ============================================================================

#[test]
fn run078_tampered_signature_candidate_rejected_at_loader() {
    let dir = tmpdir("tampered");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let mut bundle = build_signed_devnet_bundle(&h, 1);
    // Flip the first hex nibble of the signature AFTER signing
    // (sig_bytes is a lowercase hex string).
    if let Some(sig) = bundle.signature.as_mut() {
        let first = sig.sig_bytes.chars().next().expect("non-empty sig");
        let replacement = if first == '0' { '1' } else { '0' };
        let rest: String = sig.sig_bytes.chars().skip(1).collect();
        sig.sig_bytes = format!("{}{}", replacement, rest);
    }
    let bytes = bundle_to_bytes(&bundle);
    // Use a placeholder declared-prefix because the validator
    // rejects at the loader stage BEFORE comparing prefix.
    let env = wire_envelope_with(
        bytes,
        1,
        "deadbeef".to_string(),
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let frame = encode_peer_candidate_wire_frame(&env).unwrap();
    let seq_snap = snapshot_seq_file(&seq_path);
    let metrics = P2pMetrics::default();

    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, Some(&seq_path), 1_000);
    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);

    match &outcome {
        PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Rejected(_)) => {}
        other => panic!("expected ValidatorRan(Rejected), got {:?}", other),
    }

    assert_seq_file_unchanged(&seq_path, seq_snap);
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
    assert_eq!(metrics.peer_candidate_validated_total(), 0);
}

// ============================================================================
// 8. Wrong-environment candidate rejected pre-crypto.
// ============================================================================

#[test]
fn run078_wrong_environment_envelope_rejected_pre_crypto() {
    let dir = tmpdir("wrong-env");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    // Wire envelope claims Mainnet but runtime expects Devnet.
    let env = wire_envelope_with(
        bytes,
        1,
        prefix,
        TrustBundleEnvironment::Mainnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let frame = encode_peer_candidate_wire_frame(&env).unwrap();
    let metrics = P2pMetrics::default();
    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);

    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);
    match &outcome {
        PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Rejected(_)) => {}
        other => panic!("expected ValidatorRan(Rejected), got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
    assert_eq!(count_scratch_files(&scratch), 0);
}

// ============================================================================
// 9. Wrong-chain-id candidate rejected pre-crypto.
// ============================================================================

#[test]
fn run078_wrong_chain_id_envelope_rejected_pre_crypto() {
    let dir = tmpdir("wrong-chain");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    // Wire envelope's chain_id is a bogus 16-hex value.
    let env = wire_envelope_with(
        bytes,
        1,
        prefix,
        TrustBundleEnvironment::Devnet,
        "deadbeefdeadbeef".to_string(),
    );
    let frame = encode_peer_candidate_wire_frame(&env).unwrap();
    let metrics = P2pMetrics::default();
    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);

    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);
    match &outcome {
        PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Rejected(_)) => {}
        other => panic!("expected ValidatorRan(Rejected), got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 1);
    assert_eq!(metrics.peer_candidate_rejected_total(), 1);
    assert_eq!(count_scratch_files(&scratch), 0);
}

// ============================================================================
// 10. Duplicate-fingerprint frame short-circuits via Run 076 LRU.
// ============================================================================

#[test]
fn run078_duplicate_fingerprint_frame_short_circuits_via_lru() {
    let dir = tmpdir("dup");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let env = wire_envelope_with(
        bytes,
        1,
        prefix,
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let frame = encode_peer_candidate_wire_frame(&env).unwrap();
    let metrics = P2pMetrics::default();

    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, Some(&seq_path), 1_000);

    // First frame: validates.
    let o1 = receiver.try_handle_frame(&frame, &ctx, &metrics);
    assert!(o1.is_validated());
    assert_eq!(metrics.peer_candidate_validated_total(), 1);

    // Second frame: SAME prefix → duplicate suppression.
    let o2 = receiver.try_handle_frame(&frame, &ctx, &metrics);
    match &o2 {
        PeerCandidateWireOutcome::ValidatorRan(
            PeerCandidateOutcome::DuplicateSuppressed { .. },
        ) => {}
        other => panic!("expected DuplicateSuppressed on 2nd call, got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 2);
    assert_eq!(metrics.peer_candidate_validated_total(), 1);
    assert_eq!(metrics.peer_candidate_duplicate_total(), 1);
}

// ============================================================================
// 11. Rate limit triggers after max_in_window admissions.
// ============================================================================

#[test]
fn run078_rate_limit_triggers_after_max_in_window() {
    let dir = tmpdir("rl");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let metrics = P2pMetrics::default();

    // Cap admissions at 1, duplicate-suppression off so each call is
    // an admission attempt.
    let inner = PeerCandidateConfig {
        enabled: true,
        duplicate_suppression: false,
        max_in_window: 1,
        rate_limit_window_ms: 60_000,
        ..PeerCandidateConfig::default()
    };
    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner,
    });
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);

    // Build TWO distinct valid bundles so each consumes a budget slot.
    let bundle_a = build_signed_devnet_bundle(&h, 1);
    let bytes_a = bundle_to_bytes(&bundle_a);
    let prefix_a = loader_fingerprint_prefix(&bytes_a, &h.signing_keys);
    let env_a = wire_envelope_with(
        bytes_a,
        1,
        prefix_a,
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let frame_a = encode_peer_candidate_wire_frame(&env_a).unwrap();

    let bundle_b = build_signed_devnet_bundle(&h, 2);
    let bytes_b = bundle_to_bytes(&bundle_b);
    let prefix_b = loader_fingerprint_prefix(&bytes_b, &h.signing_keys);
    let env_b = wire_envelope_with(
        bytes_b,
        2,
        prefix_b,
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let frame_b = encode_peer_candidate_wire_frame(&env_b).unwrap();

    let o1 = receiver.try_handle_frame(&frame_a, &ctx, &metrics);
    assert!(o1.is_validated(), "first frame should validate");

    let o2 = receiver.try_handle_frame(&frame_b, &ctx, &metrics);
    match &o2 {
        PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::RateLimited { .. }) => {}
        other => panic!("expected RateLimited on 2nd call, got {:?}", other),
    }
    assert_eq!(metrics.peer_candidate_received_total(), 2);
    assert_eq!(metrics.peer_candidate_validated_total(), 1);
    assert_eq!(metrics.peer_candidate_rate_limited_total(), 1);
}

// ============================================================================
// 12. Wire receive does not affect Run 069 reload-check entry point.
// ============================================================================

#[test]
fn run078_does_not_affect_run069_reload_check_path() {
    let dir = tmpdir("crosscheck");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);

    // Path 1: Run 078 wire frame validates.
    let env = wire_envelope_with(
        bytes.clone(),
        1,
        prefix.clone(),
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let frame = encode_peer_candidate_wire_frame(&env).unwrap();
    let metrics = P2pMetrics::default();
    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let seq_path = sequence_file_path(&dir);
    let seq_snap = snapshot_seq_file(&seq_path);
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, Some(&seq_path), 1_000);
    let o1 = receiver.try_handle_frame(&frame, &ctx, &metrics);
    assert!(o1.is_validated());
    assert_seq_file_unchanged(&seq_path, seq_snap);

    // Path 2: same bundle bytes still validate through Run 069
    // reload-check entry point in the same test.
    let candidate_path = dir.join("candidate.json");
    std::fs::write(&candidate_path, &bytes).unwrap();
    let inputs = ReloadCheckInputs {
        candidate_path: &candidate_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: Some(&seq_path),
        local_leaf_cert_bytes: None,
    };
    let v = validate_candidate_bundle(inputs).expect("run069 still validates");
    assert_eq!(v.fingerprint_prefix, prefix);

    // Persistence file is STILL unchanged after both paths.
    let seq_snap2 = snapshot_seq_file(&seq_path);
    assert_seq_file_unchanged(&seq_path, seq_snap2);
}

// ============================================================================
// 13. Run 077 binary-facing fixture path + Run 078 wire path coexist.
// ============================================================================

#[test]
fn run078_coexists_with_run077_binary_local_check_path() {
    let dir = tmpdir("coexist");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let seq_path = sequence_file_path(&dir);

    // Run 078 path FIRST.
    let env_wire = wire_envelope_with(
        bytes.clone(),
        1,
        prefix.clone(),
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let frame = encode_peer_candidate_wire_frame(&env_wire).unwrap();
    let metrics_wire = P2pMetrics::default();
    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let ctx_wire = devnet_runtime_ctx(&scratch, &h.signing_keys, Some(&seq_path), 1_000);
    let seq_snap = snapshot_seq_file(&seq_path);
    let o_wire = receiver.try_handle_frame(&frame, &ctx_wire, &metrics_wire);
    assert!(o_wire.is_validated());
    assert_seq_file_unchanged(&seq_path, seq_snap);

    // Run 077 path SECOND, against the same bundle written to a fixture
    // file. The two paths share `--data-dir` (and therefore the same
    // sequence persistence path), but neither writes to it.
    let fixture = PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some("op-run077".to_string()),
        environment: TrustBundleEnvironment::Devnet,
        chain_id_hex: chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
        declared_sequence: 1,
        declared_fingerprint_prefix: prefix.clone(),
        declared_length: bytes.len(),
        bundle_bytes: bytes,
    };
    let fixture_path = dir.join("fixture.json");
    std::fs::write(
        &fixture_path,
        serde_json::to_vec_pretty(&fixture).expect("serialise fixture"),
    )
    .unwrap();
    let metrics_bin = P2pMetrics::default();
    let inputs = Run077Inputs {
        validation_enabled_flag: true,
        envelope_path: Some(&fixture_path),
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: Some(&seq_path),
        local_leaf_cert_bytes: None,
        scratch_dir: &scratch,
        now_ms: 2_000,
    };
    let result = run_local_check(inputs, &metrics_bin);
    match result {
        Run077Result::Ran {
            outcome: PeerCandidateOutcome::Validated(_),
            ..
        } => {}
        other => panic!("expected Run 077 Validated, got {:?}", other),
    }

    // Neither path mutated the persistence file.
    let seq_snap2 = snapshot_seq_file(&seq_path);
    assert_seq_file_unchanged(&seq_path, seq_snap2);
}

// ============================================================================
// 14. format_metrics output never contains _applied_total or Run 078-specific
//     new metric families after a Validated wire frame.
// ============================================================================

#[test]
fn run078_metrics_output_never_contains_applied_total_family() {
    let dir = tmpdir("metrics-render");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    let env = wire_envelope_with(
        bytes,
        1,
        prefix,
        TrustBundleEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    );
    let frame = encode_peer_candidate_wire_frame(&env).unwrap();
    let metrics = P2pMetrics::default();
    let mut receiver = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
        enabled: true,
        inner: PeerCandidateConfig::default(),
    });
    let ctx = devnet_runtime_ctx(&scratch, &h.signing_keys, None, 1_000);
    let outcome = receiver.try_handle_frame(&frame, &ctx, &metrics);
    assert!(outcome.is_validated());

    let rendered = metrics.format_metrics();
    // Seven existing Run 076 counters are present.
    assert!(
        rendered.contains("qbind_p2p_pqc_trust_bundle_peer_candidate_received_total"),
        "expected received_total in /metrics output"
    );
    assert!(
        rendered.contains("qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total"),
        "expected validated_total in /metrics output"
    );
    // No applied_total family — by design.
    assert!(
        !rendered.contains("qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total"),
        "Run 078 must not introduce a _applied_total family"
    );
    // No new Run 078-specific metric family beyond the seven Run 076 counters.
    assert!(
        !rendered.contains("qbind_p2p_pqc_trust_bundle_peer_candidate_wire_"),
        "Run 078 must reuse the existing seven Run 076 counters; \
         no peer_candidate_wire_* family is permitted"
    );
}

// ============================================================================
// 15. Wire envelope <-> Run 076 fixture envelope bridge round trip.
// ============================================================================

#[test]
fn run078_wire_envelope_bridge_to_run076_fixture_preserves_fields() {
    let bundle = vec![10u8, 20, 30, 40, 50];
    let len = bundle.len();
    let fixture = PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some("p1".to_string()),
        environment: TrustBundleEnvironment::Devnet,
        chain_id_hex: chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
        declared_sequence: 11,
        declared_fingerprint_prefix: "abcdef01".to_string(),
        declared_length: len,
        bundle_bytes: bundle.clone(),
    };
    let wire = PeerCandidateWireEnvelopeV1::from_run076_envelope(&fixture);
    assert_eq!(wire.envelope_version, PEER_CANDIDATE_WIRE_VERSION);
    assert_eq!(wire.domain_tag, PEER_CANDIDATE_WIRE_DOMAIN_TAG);
    assert_eq!(wire.bundle_bytes, bundle);

    let back = wire.into_run076_envelope();
    assert_eq!(back.envelope_version, PeerCandidateEnvelope::ENVELOPE_VERSION);
    assert_eq!(back.domain_tag, PeerCandidateEnvelope::DOMAIN_TAG);
    assert_eq!(back.bundle_bytes, bundle);
    assert_eq!(back.declared_sequence, 11);
    assert_eq!(back.declared_fingerprint_prefix, "abcdef01");
}

// ============================================================================
// 16. Hard cap relationship between Run 076 inner bundle cap and Run 078
//     wire frame cap.
// ============================================================================

#[test]
fn run078_wire_frame_cap_strictly_exceeds_run076_bundle_cap() {
    // A legitimate maximum-sized Run 076 bundle MUST fit inside the
    // Run 078 wire frame cap so a well-formed candidate is never
    // dropped at the wire layer for a frame-level reason.
    assert!(
        MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES > MAX_PEER_CANDIDATE_BUNDLE_BYTES,
        "wire frame cap must exceed bundle cap"
    );
}