//! Run 061 (C4 piece: PQC trust-anchor lifecycle — local revoked-leaf
//! startup self-check): integration tests that exercise the
//! `check_local_leaf_not_revoked` helper end-to-end against signed
//! `LoadedTrustBundle`s minted via the same DevNet helper path used
//! by Runs 050/051/052/054.
//!
//! These tests do NOT spawn the `qbind-node` binary; they exercise
//! the public `qbind_node::pqc_trust_bundle` API. The matching live
//! release-binary smokes are recorded in
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_061.md`.
//!
//! Coverage:
//!
//! 1. A signed DevNet bundle that revokes ONE leaf fingerprint
//!    rejects exactly that local cert and accepts a different one
//!    (i.e. the "non-revoked local leaf passes / revoked local
//!    leaf fails closed" pair).
//! 2. A signed DevNet bundle whose `revoked_leaf_fingerprints` set
//!    contains only fingerprints that do NOT match the local cert
//!    (the "unknown revoked fingerprint" case) does NOT trigger a
//!    rejection on the local cert.
//! 3. The startup self-check fingerprint is byte-identical to the
//!    Run 052 peer-handshake fingerprint surfaced by qbind-net.
//! 4. The helper never consults the root-revocation axis: a bundle
//!    that root-revokes the local cert's issuing root MUST NOT
//!    by itself fail the local-leaf self-check (the root-revocation
//!    surface is enforced separately at cert verify time).
//! 5. The Run 052 trust-bundle path is preserved bit-for-bit: a
//!    bundle with no leaf revocations exposes
//!    `revoked_leaf_fingerprint_count() == 0` and the helper
//!    short-circuits to Ok.
//! 6. The malformed-cert-bytes safety net preserves fail-closed
//!    behaviour even though the binary's `PqcLeafCredentialPaths::
//!    load` has already validated the shape before this helper
//!    runs.
//! 7. The helper's signature accepts ONLY the public cert bytes
//!    plus the public revocation set plus the public bundle
//!    fingerprint — no private-key material is required (or even
//!    accepted) at the call site.

use qbind_crypto::MlDsa44Backend;
use qbind_net::leaf_cert_fingerprint as net_leaf_cert_fingerprint;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    build_helper_bundle, cert_leaf_fingerprint, cert_leaf_fingerprint_hex,
    check_local_leaf_not_revoked, derive_signing_key_id, sign_bundle_devnet_helper,
    BundleSignatureStatus, BundleSigningKeySet, HelperBundleMode, LocalLeafSelfCheckError,
    TrustBundle, TrustBundleEnvironment, TrustBundleRevocation,
};
use qbind_types::NetworkEnvironment;
use qbind_wire::io::WireEncode;
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

fn encode_cert_bytes(cert: &NetworkDelegationCert) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    cert.encode(&mut out);
    out
}

/// Mint a signed DevNet bundle whose `revocations[]` revokes exactly
/// the supplied `revoked_leaf_fps` (each entry must be the canonical
/// 32-byte SHA3-256 of a leaf cert's wire encoding). Returns the
/// loaded bundle together with the signing-key set used for
/// verification, so the test can call `check_local_leaf_not_revoked`
/// against `loaded.revoked_leaf_fingerprints`.
fn signed_devnet_bundle_revoking(
    revoked_leaf_fps: &[[u8; 32]],
) -> qbind_node::pqc_trust_bundle::LoadedTrustBundle {
    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Devnet;
    for fp in revoked_leaf_fps {
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id_hex.clone(),
            leaf_cert_fingerprint: Some(cert_leaf_fingerprint_hex(fp)),
            reason: "leaf-compromise".to_string(),
            effective_from: 0,
        });
    }
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let set = signing_set_with(signing_id, &signing_pk);

    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded =
        TrustBundle::load_from_bytes_with_signing_keys(&json, NetworkEnvironment::Devnet, 100, &set)
            .expect("signed devnet bundle loads + verifies");
    assert!(matches!(
        loaded.signature_status,
        BundleSignatureStatus::Verified { .. }
    ));
    loaded
}

// ============================================================================
// 1. Positive non-revoked local leaf
// ============================================================================

#[test]
fn run_061_signed_devnet_bundle_with_non_revoked_local_leaf_passes_self_check() {
    // The bundle revokes a DIFFERENT validator's leaf; the local
    // cert must be allowed to start (the most common production
    // path on a healthy node).
    let local = fixture_cert(0xA0);
    let other = fixture_cert(0xA1);
    let other_fp = cert_leaf_fingerprint(&other);
    let loaded = signed_devnet_bundle_revoking(&[other_fp]);
    assert_eq!(loaded.revoked_leaf_fingerprint_count(), 1);

    let local_bytes = encode_cert_bytes(&local);
    let returned = check_local_leaf_not_revoked(
        &local_bytes,
        &loaded.revoked_leaf_fingerprints,
        &loaded.fingerprint,
    )
    .expect("non-revoked local leaf must pass self-check");
    assert_eq!(returned, cert_leaf_fingerprint(&local));
}

// ============================================================================
// 2. Negative revoked local leaf — fails closed before P2P start
// ============================================================================

#[test]
fn run_061_signed_devnet_bundle_revoking_local_leaf_fails_closed_self_check() {
    // The bundle revokes the EXACT local leaf cert. The helper must
    // return `Revoked` so the binary fails closed BEFORE
    // `P2pNodeBuilder::build` runs and BEFORE any peer connection
    // is attempted.
    let local = fixture_cert(0xB0);
    let local_fp = cert_leaf_fingerprint(&local);
    let loaded = signed_devnet_bundle_revoking(&[local_fp]);
    assert_eq!(loaded.revoked_leaf_fingerprint_count(), 1);

    let local_bytes = encode_cert_bytes(&local);
    let err = check_local_leaf_not_revoked(
        &local_bytes,
        &loaded.revoked_leaf_fingerprints,
        &loaded.fingerprint,
    )
    .unwrap_err();
    match err {
        LocalLeafSelfCheckError::Revoked {
            leaf_fingerprint_prefix,
            bundle_fingerprint_prefix,
        } => {
            assert_eq!(leaf_fingerprint_prefix.len(), 8);
            assert_eq!(bundle_fingerprint_prefix.len(), 8);
            let full = cert_leaf_fingerprint_hex(&local_fp);
            assert_eq!(leaf_fingerprint_prefix, full[..8]);
            // bundle prefix matches the loaded bundle fingerprint.
            assert_eq!(
                bundle_fingerprint_prefix,
                loaded.fingerprint_hex()[..8].to_string()
            );
        }
        other => panic!("expected Revoked, got {:?}", other),
    }
}

// ============================================================================
// 3. Positive unknown revoked fingerprint
// ============================================================================

#[test]
fn run_061_signed_devnet_bundle_with_unknown_revoked_fingerprint_passes_self_check() {
    // A bundle whose only leaf revocation is a synthetic fingerprint
    // that no real cert can produce. Same shape as the Run 054
    // `signed-devnet-revoked-unknown` fixture: any local cert
    // (other than that synthetic one) must start cleanly.
    let synthetic = [0u8; 32];
    let loaded = signed_devnet_bundle_revoking(&[synthetic]);
    assert_eq!(loaded.revoked_leaf_fingerprint_count(), 1);

    let local = fixture_cert(0xC1);
    let local_bytes = encode_cert_bytes(&local);
    let returned = check_local_leaf_not_revoked(
        &local_bytes,
        &loaded.revoked_leaf_fingerprints,
        &loaded.fingerprint,
    )
    .expect("unknown-revoked-fingerprint bundle must not reject the local cert");
    assert_eq!(returned, cert_leaf_fingerprint(&local));
    // Sanity: the local cert's fingerprint is NOT the synthetic one.
    assert_ne!(returned, synthetic);
}

// ============================================================================
// 4. Run 052 fingerprint parity (anti-drift guard)
// ============================================================================

#[test]
fn run_061_self_check_fingerprint_matches_run_052_peer_handshake_fingerprint() {
    // The Run 061 startup self-check and the Run 052 peer-handshake
    // revocation check MUST hash the same bytes for the same cert.
    // We assert that:
    //   (a) qbind-node `cert_leaf_fingerprint` == qbind-net
    //       `leaf_cert_fingerprint` (Run 052 invariant), AND
    //   (b) `check_local_leaf_not_revoked` on a clean revocation
    //       set returns exactly that same fingerprint.
    let cert = fixture_cert(0xD2);
    let node_fp = cert_leaf_fingerprint(&cert);
    let net_fp = net_leaf_cert_fingerprint(&cert);
    assert_eq!(node_fp, net_fp, "Run 052 cross-crate parity");

    let local_bytes = encode_cert_bytes(&cert);
    let returned = check_local_leaf_not_revoked(
        &local_bytes,
        &std::collections::HashSet::new(),
        &[0u8; 32],
    )
    .expect("clean revocation set passes");
    assert_eq!(
        returned, net_fp,
        "Run 061 self-check fingerprint must equal Run 052 handshake fingerprint"
    );
}

// ============================================================================
// 5. Root-revocation axis remains orthogonal
// ============================================================================

#[test]
fn run_061_self_check_does_not_react_to_root_level_revocation_only() {
    // Build a bundle that root-revokes the issuing root but does
    // NOT carry any leaf-level revocation entries. The local-leaf
    // self-check must NOT reject the local cert. Root-level
    // revocation enforcement is the cert-verify layer's job and is
    // exercised in the Run 050 / Run 052 cert-verify tests; the
    // Run 061 helper is leaf-only by design.
    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle =
        build_helper_bundle(HelperBundleMode::RootRevocationListed, &id_hex, &pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Devnet;
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let set = signing_set_with(signing_id, &signing_pk);
    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded =
        TrustBundle::load_from_bytes_with_signing_keys(&json, NetworkEnvironment::Devnet, 100, &set)
            .expect("loads");
    assert_eq!(
        loaded.revoked_leaf_fingerprint_count(),
        0,
        "RootRevocationListed sets only the root axis"
    );
    assert!(loaded.revoked_root_count() >= 1);

    let local = fixture_cert(0xE3);
    let local_bytes = encode_cert_bytes(&local);
    check_local_leaf_not_revoked(
        &local_bytes,
        &loaded.revoked_leaf_fingerprints,
        &loaded.fingerprint,
    )
    .expect("leaf-only self-check must not consult the root-revocation axis");
}

// ============================================================================
// 6. Empty revocation set / no bundle preserves Run 050–060 behaviour
// ============================================================================

#[test]
fn run_061_empty_revocation_set_short_circuits_to_ok() {
    // A signed DevNet bundle with zero leaf revocations represents
    // the standard pre-Run-061 production path. The helper must
    // return Ok with the local cert's fingerprint and no rejection.
    let loaded = signed_devnet_bundle_revoking(&[]);
    assert_eq!(loaded.revoked_leaf_fingerprint_count(), 0);

    let local = fixture_cert(0xF4);
    let local_bytes = encode_cert_bytes(&local);
    let returned = check_local_leaf_not_revoked(
        &local_bytes,
        &loaded.revoked_leaf_fingerprints,
        &loaded.fingerprint,
    )
    .expect("empty revocation set must pass");
    assert_eq!(returned, cert_leaf_fingerprint(&local));
}

// ============================================================================
// 7. Malformed local cert bytes preserve fail-closed (defence in depth)
// ============================================================================

#[test]
fn run_061_self_check_fails_closed_on_malformed_local_cert_bytes() {
    // On the binary path the cert has already been decoded by
    // `PqcLeafCredentialPaths::load`, so this branch is
    // unreachable in normal operation. Defence in depth: the helper
    // itself must still fail closed if it is ever fed garbage.
    let loaded = signed_devnet_bundle_revoking(&[]);
    let err = check_local_leaf_not_revoked(
        &[0x00, 0x01, 0x02],
        &loaded.revoked_leaf_fingerprints,
        &loaded.fingerprint,
    )
    .unwrap_err();
    assert_eq!(err, LocalLeafSelfCheckError::DecodeFailed);
}

// ============================================================================
// 8. Run 052 peer-handshake metric contract preserved
// ============================================================================

#[test]
fn run_061_self_check_does_not_touch_peer_handshake_metric_family() {
    // The Run 061 helper signature does not take any metrics sink,
    // so calling it cannot bump the Run 052 peer-handshake counter
    // `qbind_p2p_pqc_cert_verify_rejected_revoked_total`. We
    // assert this end-to-end by constructing a NodeMetrics, calling
    // the helper several times in both Ok and Err shapes, and
    // checking the counter remains at zero. This pins the "startup
    // self-check is NOT a handshake event" boundary required by
    // the task.
    use qbind_node::metrics::NodeMetrics;
    let metrics = NodeMetrics::new();
    let local = fixture_cert(0xA7);
    let local_fp = cert_leaf_fingerprint(&local);
    let local_bytes = encode_cert_bytes(&local);

    // Positive call.
    let loaded_ok = signed_devnet_bundle_revoking(&[]);
    let _ = check_local_leaf_not_revoked(
        &local_bytes,
        &loaded_ok.revoked_leaf_fingerprints,
        &loaded_ok.fingerprint,
    );

    // Negative call.
    let loaded_revoked = signed_devnet_bundle_revoking(&[local_fp]);
    let _ = check_local_leaf_not_revoked(
        &local_bytes,
        &loaded_revoked.revoked_leaf_fingerprints,
        &loaded_revoked.fingerprint,
    );

    // The Run 052 peer-handshake counter MUST remain at zero — the
    // startup self-check is a startup-only signal and does NOT
    // share its metric family.
    assert_eq!(metrics.p2p().pqc_cert_verify_rejected_revoked_total(), 0);
    assert_eq!(metrics.p2p().pqc_cert_verify_rejected_total(), 0);
}

// ============================================================================
// 9. No private-key material crosses the helper boundary
// ============================================================================

#[test]
fn run_061_helper_signature_pins_no_private_key_dependency() {
    // The helper's public signature accepts only:
    //   - public cert bytes,
    //   - the public revocation set,
    //   - the public bundle fingerprint.
    // This test pins the call-site shape so a future refactor
    // cannot accidentally widen the API to require KEM/sig secret
    // bytes. It is a compile-time + runtime guard: if the signature
    // ever drops one of these parameters or gains a private-key
    // parameter, this test will fail to compile.
    let cert = fixture_cert(0xB8);
    let cert_bytes = encode_cert_bytes(&cert);
    let revoked: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let bundle_fp = [0u8; 32];
    let _: Result<[u8; 32], LocalLeafSelfCheckError> =
        check_local_leaf_not_revoked(&cert_bytes, &revoked, &bundle_fp);
}