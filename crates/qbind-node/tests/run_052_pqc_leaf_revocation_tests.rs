//! Run 052 (C4 piece: PQC trust-anchor lifecycle — leaf-level
//! certificate revocation enforcement): integration tests that
//! exercise the full leaf-revocation surface end-to-end on the
//! `qbind-node` side.
//!
//! These tests do NOT spawn the `qbind-node` binary; they exercise
//! the public `qbind_node::pqc_trust_bundle` API and the
//! `qbind_net::CertVerifyMetricsSink` adapter implemented for
//! `P2pMetrics`. The matching qbind-net handshake-boundary tests
//! live in `crates/qbind-net/tests/run_052_leaf_revocation_handshake_tests.rs`.
//! The matching live-binary smoke is recorded in
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_052.md`.
//!
//! Coverage:
//!
//! 1. The trust bundle's `revocations[].leaf_cert_fingerprint` field
//!    parses correctly into a 32-byte canonical form, malformed hex
//!    fails closed, and future-dated entries are recorded but not
//!    yet active.
//! 2. The qbind-node `cert_leaf_fingerprint` helper produces the
//!    same 32-byte digest as the qbind-net `leaf_cert_fingerprint`
//!    helper for the same `NetworkDelegationCert` (no protocol
//!    drift across the crate boundary).
//! 3. The Run 044 cert-verify metrics adapter forwards
//!    `inc_rejected_revoked` onto
//!    `inc_pqc_cert_verify_rejected_revoked`, which bumps the new
//!    `qbind_p2p_pqc_cert_verify_rejected_revoked_total` counter
//!    AND the aggregate `qbind_p2p_pqc_cert_verify_rejected_total`
//!    (Run 037 contract preserved).
//! 4. The new metric is rendered on both `format_metrics` and the
//!    crypto-wrapper formatter.
//! 5. A non-revoked signed bundle still loads and exposes a usable
//!    `PqcStaticRootConfig` (Run 051 path preserved).
//! 6. A revoked-leaf signed bundle still loads (the bundle itself
//!    is structurally valid; the revocation surface lives on the
//!    `LoadedTrustBundle`, not the `PqcStaticRootConfig`).
//! 7. Negative: an entry whose `leaf_cert_fingerprint` does not
//!    match the project's strict 64-lowercase-hex shape fails the
//!    bundle load with `MalformedLeafFingerprint`.

use std::sync::Arc;

use qbind_crypto::MlDsa44Backend;
use qbind_net::{
    leaf_cert_fingerprint as net_leaf_cert_fingerprint, CertVerifyMetricsSink,
    LEAF_CERT_FINGERPRINT_DOMAIN_SEPARATOR as NET_LEAF_FP_DOMAIN_SEP,
};
use qbind_node::metrics::{NodeMetrics, P2pMetrics};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::{PqcRootMode, PqcStaticRootConfig, PQC_TRANSPORT_SUITE_ML_DSA_44};
use qbind_node::pqc_trust_bundle::{
    build_helper_bundle, cert_leaf_fingerprint, cert_leaf_fingerprint_hex, derive_signing_key_id,
    sign_bundle_devnet_helper, BundleSignatureStatus, BundleSigningKeySet,
    HelperBundleMode, TrustBundle, TrustBundleEnvironment, TrustBundleError, TrustBundleRevocation,
    TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR,
};
use qbind_types::NetworkEnvironment;
use qbind_wire::net::NetworkDelegationCert;

// ============================================================================
// Helpers
// ============================================================================

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", x);
    }
    s
}

fn fresh_root_pair() -> (String, String) {
    let root = mint_devnet_root().expect("mint root");
    (hex_lower(&root.root_key_id), hex_lower(&root.root_pk))
}

fn fresh_signing_keypair() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
    let id = derive_signing_key_id(&pk);
    (pk, sk, id)
}

fn signing_set_with(id: [u8; 32], pk: &[u8]) -> BundleSigningKeySet {
    let spec = format!(
        "{}:{}:{}",
        hex_lower(&id),
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        hex_lower(pk)
    );
    BundleSigningKeySet::parse_specs(&[spec]).expect("parse signing-key set")
}

fn fixture_cert(validator_byte: u8) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id: [validator_byte; 32],
        root_key_id: [0x11; 32],
        leaf_kem_suite_id: 1,
        leaf_kem_pk: vec![0x22; 32],
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: vec![],
        sig_suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        sig_bytes: vec![0x33; 64],
    }
}

// ============================================================================
// 1. Trust-bundle leaf-revocation surface (parse + active-set)
// ============================================================================

#[test]
fn signed_bundle_with_revoked_leaf_surfaces_revoked_leaf_fingerprint() {
    let cert = fixture_cert(0xCC);
    let fp = cert_leaf_fingerprint(&cert);
    let fp_hex = cert_leaf_fingerprint_hex(&fp);

    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Devnet;
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: Some(fp_hex.clone()),
        reason: "leaf-compromise".to_string(),
        effective_from: 0,
        activation_height: None,
    });
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let set = signing_set_with(signing_id, &signing_pk);

    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Devnet,
        100,
        &set,
    )
    .expect("loads + verifies");
    assert!(matches!(
        loaded.signature_status,
        BundleSignatureStatus::Verified { .. }
    ));
    // Run 052: leaf revocation surfaced.
    assert_eq!(loaded.revoked_leaf_fingerprint_count(), 1);
    assert!(loaded.is_leaf_revoked(&fp));
    // The root remains active — leaf-only revocation does NOT
    // exclude the root.
    assert_eq!(loaded.active_root_count(), 1);
    assert_eq!(loaded.revoked_root_count(), 0);
}

#[test]
fn signed_bundle_with_no_revocations_continues_to_work() {
    // Regression guard for Run 051: the absence of any
    // leaf-revocation entries must not regress the existing signed-
    // bundle path. The bundle still loads, verifies, and exposes a
    // healthy `PqcStaticRootConfig` with no leaf revocations.
    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Devnet;
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let set = signing_set_with(signing_id, &signing_pk);

    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Devnet,
        100,
        &set,
    )
    .expect("loads + verifies");
    assert!(matches!(
        loaded.signature_status,
        BundleSignatureStatus::Verified { .. }
    ));
    assert_eq!(loaded.revoked_leaf_fingerprint_count(), 0);
    assert_eq!(loaded.active_root_count(), 1);

    // The PqcStaticRootConfig remains constructible from the loaded
    // active roots. (No leaf revocations on this path; matches Run 051.)
    let cfg = PqcStaticRootConfig {
        mode: PqcRootMode::PqcStaticRoot,
        trusted_roots: loaded.active_roots.clone(),
        leaf_credentials: None,
        peer_leaf_certs: vec![],
    };
    assert_eq!(cfg.trusted_roots.len(), 1);
    assert!(matches!(cfg.mode, PqcRootMode::PqcStaticRoot));
}

#[test]
fn future_dated_leaf_revocation_is_not_yet_active_in_signed_bundle() {
    let cert = fixture_cert(0xEE);
    let fp = cert_leaf_fingerprint(&cert);
    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Devnet;
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: Some(cert_leaf_fingerprint_hex(&fp)),
        reason: "scheduled-leaf-rotation".to_string(),
        effective_from: 1_000_000,
        activation_height: None,
    });
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let set = signing_set_with(signing_id, &signing_pk);

    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Devnet,
        100,
        &set,
    )
    .expect("loads + verifies");
    // Future-dated: not yet active.
    assert_eq!(loaded.revoked_leaf_fingerprint_count(), 0);
    assert!(!loaded.is_leaf_revoked(&fp));

    // Replay the same bundle bytes after the effective-from time
    // has passed: now the leaf IS revoked.
    let loaded_later = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Devnet,
        2_000_000,
        &set,
    )
    .expect("loads + verifies");
    assert_eq!(loaded_later.revoked_leaf_fingerprint_count(), 1);
    assert!(loaded_later.is_leaf_revoked(&fp));
}

#[test]
fn malformed_leaf_fingerprint_in_signed_bundle_fails_closed() {
    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Devnet;
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        // Wrong length AND not a valid hex shape.
        leaf_cert_fingerprint: Some("not-a-valid-fingerprint".to_string()),
        reason: "leaf-compromise".to_string(),
        effective_from: 0,
        activation_height: None,
    });
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let set = signing_set_with(signing_id, &signing_pk);

    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Devnet,
        100,
        &set,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TrustBundleError::MalformedLeafFingerprint { .. }
    ));
}

// ============================================================================
// 2. Cross-crate fingerprint determinism
// ============================================================================

#[test]
fn qbind_node_and_qbind_net_leaf_fingerprints_agree() {
    // Anti-drift guard: the `cert_leaf_fingerprint` helper exposed
    // on the qbind-node trust-bundle module MUST produce the same
    // 32-byte digest as the qbind-net `leaf_cert_fingerprint` helper
    // used by the live handshake engine. If this regresses, an
    // operator's revocation entry would silently fail to match a
    // live cert and a revoked leaf would be silently accepted.
    let cert_a = fixture_cert(0xAA);
    let cert_b = fixture_cert(0xBB);
    assert_eq!(
        cert_leaf_fingerprint(&cert_a),
        net_leaf_cert_fingerprint(&cert_a),
        "qbind-node and qbind-net cert fingerprints must agree (cert A)"
    );
    assert_eq!(
        cert_leaf_fingerprint(&cert_b),
        net_leaf_cert_fingerprint(&cert_b),
        "qbind-node and qbind-net cert fingerprints must agree (cert B)"
    );
    assert_ne!(
        cert_leaf_fingerprint(&cert_a),
        cert_leaf_fingerprint(&cert_b),
        "distinct certs must have distinct fingerprints"
    );
}

#[test]
fn qbind_node_and_qbind_net_leaf_fingerprint_domain_separators_agree() {
    // The two crates MUST use the same domain separator string;
    // this is what makes the cross-crate fingerprint helpers above
    // produce identical bytes for the same cert.
    assert_eq!(
        TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR,
        NET_LEAF_FP_DOMAIN_SEP
    );
}

// ============================================================================
// 3. P2pMetrics adapter mapping for `inc_rejected_revoked`
// ============================================================================

#[test]
fn adapter_inc_rejected_revoked_bumps_revoked_and_aggregate() {
    let m = Arc::new(P2pMetrics::new());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = m.clone();
    dyn_sink.inc_rejected_revoked();

    // Run 052: dedicated sub-counter MUST move by exactly 1.
    assert_eq!(m.pqc_cert_verify_rejected_revoked_total(), 1);
    // Run 037 contract preserved: aggregate also moves by 1.
    assert_eq!(m.pqc_cert_verify_rejected_total(), 1);
    // Other per-reason counters MUST NOT move.
    assert_eq!(m.pqc_cert_verify_accepted_total(), 0);
    assert_eq!(m.pqc_cert_rejected_unknown_root_total(), 0);
    assert_eq!(m.pqc_cert_rejected_wrong_suite_total(), 0);
    assert_eq!(m.pqc_cert_rejected_bad_signature_total(), 0);
    assert_eq!(m.pqc_cert_rejected_validator_mismatch_total(), 0);
    assert_eq!(m.pqc_cert_rejected_malformed_total(), 0);
    assert_eq!(m.pqc_cert_rejected_expired_total(), 0);
}

#[test]
fn adapter_inc_rejected_revoked_is_independent_of_other_per_reason_counters() {
    // Bumping the new counter several times must not bleed into any
    // pre-Run-052 sub-counter.
    let m = Arc::new(P2pMetrics::new());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = m.clone();
    for _ in 0..7 {
        dyn_sink.inc_rejected_revoked();
    }
    assert_eq!(m.pqc_cert_verify_rejected_revoked_total(), 7);
    assert_eq!(m.pqc_cert_verify_rejected_total(), 7);
    assert_eq!(m.pqc_cert_rejected_unknown_root_total(), 0);
    assert_eq!(m.pqc_cert_rejected_expired_total(), 0);
}

// ============================================================================
// 4. /metrics rendering — the new family is visible on both formatters
// ============================================================================

#[test]
fn revoked_total_metric_is_rendered_zero_by_default() {
    let metrics = NodeMetrics::new();
    let output = metrics.format_metrics();
    assert!(output.contains("qbind_p2p_pqc_cert_verify_rejected_revoked_total 0"));
    let output_with_crypto = metrics.format_metrics_with_crypto(None, None);
    assert!(output_with_crypto.contains("qbind_p2p_pqc_cert_verify_rejected_revoked_total 0"));
}

#[test]
fn revoked_total_metric_propagates_through_node_formatter() {
    let metrics = NodeMetrics::new();
    metrics.p2p().inc_pqc_cert_verify_rejected_revoked();
    metrics.p2p().inc_pqc_cert_verify_rejected_revoked();
    metrics.p2p().inc_pqc_cert_verify_rejected_revoked();
    let output = metrics.format_metrics();
    assert!(output.contains("qbind_p2p_pqc_cert_verify_rejected_revoked_total 3"));
    // Aggregate moved with each per-reason bump.
    assert!(output.contains("qbind_p2p_pqc_cert_verify_rejected_total 3"));
}

#[test]
fn revoked_total_metric_emitted_exactly_once() {
    let metrics = NodeMetrics::new();
    let output = metrics.format_metrics();
    let count = output
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("qbind_p2p_pqc_cert_verify_rejected_revoked_total ")
        })
        .count();
    assert_eq!(
        count, 1,
        "qbind_p2p_pqc_cert_verify_rejected_revoked_total must be rendered exactly once"
    );

    let output2 = metrics.format_metrics_with_crypto(None, None);
    let count2 = output2
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("qbind_p2p_pqc_cert_verify_rejected_revoked_total ")
        })
        .count();
    assert_eq!(count2, 1);
}

// ============================================================================
// 5. No-fallback assertion: the leaf revocation surface has no escape hatch
//    onto DummySig / DummyKem / DummyAead / --p2p-trusted-root.
// ============================================================================

#[test]
fn no_fallback_to_test_grade_dummy_primitives_for_pqc_path() {
    // Production-honest contract: the `PqcStaticRootConfig` built
    // from a loaded trust bundle's `active_roots` only carries
    // ML-DSA-44 (`PQC_TRANSPORT_SUITE_ML_DSA_44`) roots. There is
    // no DummySig / DummyKem / DummyAead suite ID surfaced on this
    // path, and `PqcRootMode::PqcStaticRoot` is the only mode used.
    // If a future change introduced a silent fallback, the asserts
    // below would catch it (sig_suite_id is the discriminator).
    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Devnet;
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: Some(cert_leaf_fingerprint_hex(&cert_leaf_fingerprint(
            &fixture_cert(0xAB),
        ))),
        reason: "leaf-compromise".to_string(),
        effective_from: 0,
        activation_height: None,
    });
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let set = signing_set_with(signing_id, &signing_pk);

    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Devnet,
        100,
        &set,
    )
    .expect("loads");

    let cfg = PqcStaticRootConfig {
        mode: PqcRootMode::PqcStaticRoot,
        trusted_roots: loaded.active_roots.clone(),
        leaf_credentials: None,
        peer_leaf_certs: vec![],
    };
    assert!(matches!(cfg.mode, PqcRootMode::PqcStaticRoot));
    for root in &cfg.trusted_roots {
        assert_eq!(
            root.suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44,
            "trusted root MUST be ML-DSA-44; no DummySig fallback allowed on the PQC path"
        );
    }
    // Even though a leaf was revoked, the bundle still loaded and
    // surfaced a usable PQC config — proving the revocation surface
    // is additive (no silent disablement of the PQC path).
    assert_eq!(loaded.revoked_leaf_fingerprint_count(), 1);
}
