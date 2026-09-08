//! Run 063 (C4 piece: PQC trust-anchor lifecycle — local revoked
//! ISSUER-ROOT startup self-check): integration tests that exercise
//! the `check_local_leaf_issuer_root_not_revoked` helper end-to-end
//! against signed `LoadedTrustBundle`s minted via the same DevNet
//! helper path used by Runs 050/051/052/054/061/062.
//!
//! These tests do NOT spawn the `qbind-node` binary; they exercise
//! the public `qbind_node::pqc_trust_bundle` API. The matching live
//! release-binary smokes are recorded in
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_063.md`.
//!
//! Coverage:
//!
//! 1. A signed DevNet bundle that does NOT root-revoke the issuing
//!    root accepts the local cert.
//! 2. A signed DevNet bundle whose active `revoked_root_ids` set
//!    contains the local cert's issuing root fails closed.
//! 3. A signed DevNet bundle whose root-revocation entry is PENDING
//!    (Run 062 `activation_height` not yet satisfied) does NOT
//!    reject the local cert — the helper consults the active set
//!    only, and `loaded.revoked_root_ids` excludes pending entries
//!    by construction.
//! 4. A signed DevNet bundle that root-revokes an UNRELATED root
//!    does NOT reject the local cert if the local issuing root is
//!    still valid.
//! 5. The Run 063 self-check uses byte-identical issuer-root
//!    identity to the cert-verify path (decoded
//!    `NetworkDelegationCert.root_key_id`).
//! 6. Run 061 local leaf-fingerprint self-check behaviour is
//!    preserved: a leaf-revocation-only bundle still triggers the
//!    Run 061 helper while leaving Run 063 happy.
//! 7. The helper's signature pins no private-key dependency.

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::{decode_network_delegation_cert, PQC_TRANSPORT_SUITE_ML_DSA_44};
use qbind_node::pqc_trust_bundle::{
    build_helper_bundle, cert_leaf_fingerprint, cert_leaf_fingerprint_hex,
    check_local_leaf_issuer_root_not_revoked, check_local_leaf_not_revoked, derive_signing_key_id,
    sign_bundle_devnet_helper, BundleSignatureStatus, BundleSigningKeySet, HelperBundleMode,
    LocalLeafIssuerRootSelfCheckError, LocalLeafSelfCheckError, TrustBundle,
    TrustBundleEnvironment, TrustBundleRevocation,
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

fn fresh_root_pair() -> ([u8; 32], String, String) {
    let root = mint_devnet_root().expect("mint root");
    (
        root.root_key_id,
        hex_lower(&root.root_key_id),
        hex_lower(&root.root_pk),
    )
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

/// Mint a signed DevNet bundle whose root is `id_hex`/`pk_hex`, and
/// optionally append a single root-scope revocation entry against
/// that same root with the given `activation_height`. Returns the
/// loaded bundle.
fn signed_devnet_bundle_with_root_revocation(
    id_hex: &str,
    pk_hex: &str,
    revoke_root: bool,
    activation_height: Option<u64>,
) -> qbind_node::pqc_trust_bundle::LoadedTrustBundle {
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, id_hex, pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Devnet;
    if revoke_root {
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id_hex.to_string(),
            leaf_cert_fingerprint: None,
            reason: "root-compromise".to_string(),
            effective_from: 0,
            activation_height,
        });
    }
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
    .expect("signed devnet bundle loads + verifies");
    assert!(matches!(
        loaded.signature_status,
        BundleSignatureStatus::Verified { .. }
    ));
    loaded
}

// ============================================================================
// 1. Positive — non-revoked local issuer root passes startup self-check.
// ============================================================================

#[test]
fn run063_signed_devnet_bundle_with_non_revoked_local_issuer_root_passes_self_check() {
    let (root_id, id_hex, pk_hex) = fresh_root_pair();
    let loaded = signed_devnet_bundle_with_root_revocation(&id_hex, &pk_hex, false, None);
    assert_eq!(loaded.revoked_root_count(), 0);

    let cert = fixture_cert_with_root(0xA0, root_id);
    let cert_bytes = encode_cert_bytes(&cert);
    let returned = check_local_leaf_issuer_root_not_revoked(
        &cert_bytes,
        &loaded.revoked_root_ids,
        &loaded.fingerprint,
    )
    .expect("non-revoked local issuer root must pass self-check");
    assert_eq!(returned, root_id);
}

// ============================================================================
// 2. Negative — active-revoked local issuer root fails closed.
// ============================================================================

#[test]
fn run063_signed_devnet_bundle_with_active_revoked_local_issuer_root_fails_closed() {
    let (root_id, id_hex, pk_hex) = fresh_root_pair();
    let loaded = signed_devnet_bundle_with_root_revocation(&id_hex, &pk_hex, true, None);
    assert_eq!(loaded.revoked_root_count(), 1);
    assert!(loaded.revoked_root_ids.contains(&root_id));

    let cert = fixture_cert_with_root(0xB0, root_id);
    let cert_bytes = encode_cert_bytes(&cert);
    let err = check_local_leaf_issuer_root_not_revoked(
        &cert_bytes,
        &loaded.revoked_root_ids,
        &loaded.fingerprint,
    )
    .unwrap_err();
    match err {
        LocalLeafIssuerRootSelfCheckError::IssuerRootRevoked {
            root_id_prefix,
            leaf_fingerprint_prefix,
            bundle_fingerprint_prefix,
        } => {
            assert_eq!(root_id_prefix.len(), 8);
            assert_eq!(leaf_fingerprint_prefix.len(), 8);
            assert_eq!(bundle_fingerprint_prefix.len(), 8);
            let full_root = hex_lower(&root_id);
            assert_eq!(root_id_prefix, full_root[..8]);
            let leaf_fp = cert_leaf_fingerprint(&cert);
            let full_leaf = cert_leaf_fingerprint_hex(&leaf_fp);
            assert_eq!(leaf_fingerprint_prefix, full_leaf[..8]);
            assert_eq!(
                bundle_fingerprint_prefix,
                loaded.fingerprint_hex()[..8].to_string()
            );
        }
        other => panic!("expected IssuerRootRevoked, got {:?}", other),
    }
}

// ============================================================================
// 3. Positive — pending-revoked local issuer root must NOT reject.
// ============================================================================

#[test]
fn run063_signed_devnet_bundle_with_pending_revoked_local_issuer_root_passes_self_check() {
    // Run 062: an entry with `activation_height = u64::MAX` and
    // `current_height = 100` resolves to PENDING. The bundle parser
    // places the root_id into `pending_revoked_root_ids` (NOT into
    // `revoked_root_ids`). The Run 063 self-check consults the
    // ACTIVE set only, so the local cert must start cleanly.
    let (root_id, id_hex, pk_hex) = fresh_root_pair();
    let loaded = signed_devnet_bundle_with_root_revocation(&id_hex, &pk_hex, true, Some(u64::MAX));
    // The bundle has a configured revocation, but it is pending.
    assert_eq!(loaded.configured_revocations_total(), 1);
    assert_eq!(loaded.revoked_root_count(), 0, "pending must not be active");
    assert_eq!(loaded.pending_revoked_root_count(), 1);
    assert!(loaded.pending_revoked_root_ids.contains(&root_id));
    assert!(!loaded.revoked_root_ids.contains(&root_id));

    let cert = fixture_cert_with_root(0xC0, root_id);
    let cert_bytes = encode_cert_bytes(&cert);
    let returned = check_local_leaf_issuer_root_not_revoked(
        &cert_bytes,
        &loaded.revoked_root_ids,
        &loaded.fingerprint,
    )
    .expect("pending-revoked local issuer root MUST NOT fail closed early");
    assert_eq!(returned, root_id);
}

// ============================================================================
// 4. Positive — unrelated active-revoked root does not reject local leaf.
// ============================================================================

#[test]
fn run063_signed_devnet_bundle_with_unrelated_active_revoked_root_passes_self_check() {
    // Build a bundle whose active root revocation targets a
    // completely different root. The local cert's issuer root is
    // not the one revoked, so the helper must pass.
    let (local_root_id, local_id_hex, local_pk_hex) = fresh_root_pair();
    // Mint a separate "other" root and root-revoke that one in the
    // signed bundle. We do this by listing the local root as
    // `roots[0]` (so the bundle is valid for chain trust) and adding
    // a revocation entry whose `root_id` points at the OTHER root
    // id. However, the bundle parser refuses revocations that
    // reference an unknown root id (see `TrustBundleError::
    // UnknownRevocationRootId`). To express "an unrelated active
    // root revocation" we therefore use a *two-root* bundle: roots
    // = [local, other], and revoke `other` only.
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &local_id_hex, &local_pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Devnet;
    let (_other_root_id, other_id_hex, other_pk_hex) = fresh_root_pair();
    // Append the other root as a second entry so the bundle parser
    // accepts the revocation reference.
    bundle
        .roots
        .push(qbind_node::pqc_trust_bundle::TrustBundleRoot {
            root_id: other_id_hex.clone(),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            root_pk: other_pk_hex,
            not_before: 0,
            not_after: u64::MAX,
            status: qbind_node::pqc_trust_bundle::RootStatus::Active,
            activation_epoch: None,
            activation_height: None,
        });
    bundle.revocations.push(TrustBundleRevocation {
        root_id: other_id_hex.clone(),
        leaf_cert_fingerprint: None,
        reason: "unrelated-root-compromise".to_string(),
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
    assert_eq!(loaded.revoked_root_count(), 1);
    // Local root is still in active_roots.
    assert!(loaded
        .active_roots
        .iter()
        .any(|r| r.root_key_id == local_root_id));
    assert!(!loaded.revoked_root_ids.contains(&local_root_id));

    let cert = fixture_cert_with_root(0xD0, local_root_id);
    let cert_bytes = encode_cert_bytes(&cert);
    let returned = check_local_leaf_issuer_root_not_revoked(
        &cert_bytes,
        &loaded.revoked_root_ids,
        &loaded.fingerprint,
    )
    .expect("unrelated active-revoked root must not reject local cert");
    assert_eq!(returned, local_root_id);
}

// ============================================================================
// 5. Identity parity — issuer root_id equals cert.root_key_id.
// ============================================================================

#[test]
fn run063_self_check_uses_same_root_id_as_cert_verify_path() {
    // The cert-verify path looks up the trusted root pk by
    // `cert.root_key_id`. The Run 063 self-check MUST use the same
    // identity; otherwise a node could either fail to start with a
    // cert that the cert-verify path would actually accept, or
    // start with a cert that the cert-verify path would actually
    // reject. We assert that the helper returns exactly that field.
    let (root_id, id_hex, pk_hex) = fresh_root_pair();
    let loaded = signed_devnet_bundle_with_root_revocation(&id_hex, &pk_hex, false, None);
    let cert = fixture_cert_with_root(0xE5, root_id);
    let cert_bytes = encode_cert_bytes(&cert);
    let helper_root_id = check_local_leaf_issuer_root_not_revoked(
        &cert_bytes,
        &loaded.revoked_root_ids,
        &loaded.fingerprint,
    )
    .expect("not revoked");
    let decoded = decode_network_delegation_cert(&cert_bytes).expect("decode");
    assert_eq!(
        helper_root_id, decoded.root_key_id,
        "Run 063 issuer-root identity must equal cert.root_key_id"
    );
    assert_eq!(helper_root_id, root_id, "and equal to the minted root_id");
}

// ============================================================================
// 6. Run 061 leaf-axis preservation — both axes coexist independently.
// ============================================================================

#[test]
fn run063_does_not_weaken_run_061_local_leaf_fingerprint_self_check() {
    // Build a bundle with NO root revocation but WITH an active
    // leaf-fingerprint revocation targeting the local cert. The
    // Run 063 issuer-root self-check passes (no root revoked); the
    // Run 061 leaf-fingerprint self-check still fails closed
    // exactly as before. This pins the orthogonality of the two
    // axes at the binary call site.
    let (root_id, id_hex, pk_hex) = fresh_root_pair();
    let local = fixture_cert_with_root(0xF6, root_id);
    let local_fp = cert_leaf_fingerprint(&local);

    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Devnet;
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: Some(cert_leaf_fingerprint_hex(&local_fp)),
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
    assert_eq!(loaded.revoked_root_count(), 0);
    assert_eq!(loaded.revoked_leaf_fingerprint_count(), 1);

    let cert_bytes = encode_cert_bytes(&local);
    // Run 063: passes (no root revoked).
    check_local_leaf_issuer_root_not_revoked(
        &cert_bytes,
        &loaded.revoked_root_ids,
        &loaded.fingerprint,
    )
    .expect("issuer root is not revoked");
    // Run 061: still fails closed (leaf fingerprint is revoked).
    let err = check_local_leaf_not_revoked(
        &cert_bytes,
        &loaded.revoked_leaf_fingerprints,
        &loaded.fingerprint,
    )
    .unwrap_err();
    assert!(matches!(err, LocalLeafSelfCheckError::Revoked { .. }));
}

// ============================================================================
// 7. No private-key material crosses the helper boundary (API pin).
// ============================================================================

#[test]
fn run063_helper_signature_pins_no_private_key_dependency() {
    // The helper's public signature accepts only:
    //   - public cert bytes,
    //   - the public active revoked-root set,
    //   - the public bundle fingerprint.
    // This test pins the call-site shape so a future refactor
    // cannot accidentally widen the API to require KEM / signing
    // secret bytes.
    let cert = fixture_cert_with_root(0xB8, [0u8; 32]);
    let cert_bytes = encode_cert_bytes(&cert);
    let revoked: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let bundle_fp = [0u8; 32];
    let _: Result<[u8; 32], LocalLeafIssuerRootSelfCheckError> =
        check_local_leaf_issuer_root_not_revoked(&cert_bytes, &revoked, &bundle_fp);
}

// ============================================================================
// 8. Pending root revocation: explicit `pending` accessor never bleeds
//    into the active set the binary feeds to the helper.
// ============================================================================

#[test]
fn run063_pending_revoked_root_never_bleeds_into_active_set_used_by_helper() {
    // Pin the invariant that the active set used by the binary
    // (`loaded.revoked_root_ids`) is disjoint from the pending set
    // (`loaded.pending_revoked_root_ids`). The Run 062 parser is
    // already proven to enforce this for the bundle as a whole; this
    // test pins the boundary specifically at the call site of the
    // Run 063 helper.
    let (root_id, id_hex, pk_hex) = fresh_root_pair();
    let loaded = signed_devnet_bundle_with_root_revocation(&id_hex, &pk_hex, true, Some(u64::MAX));
    for id in loaded.revoked_root_ids.iter() {
        assert!(
            !loaded.pending_revoked_root_ids.contains(id),
            "active and pending must be disjoint"
        );
    }
    assert!(loaded.pending_revoked_root_ids.contains(&root_id));
    assert!(!loaded.revoked_root_ids.contains(&root_id));
    // Helper sees the empty active set; passes.
    let cert = fixture_cert_with_root(0x7A, root_id);
    let cert_bytes = encode_cert_bytes(&cert);
    check_local_leaf_issuer_root_not_revoked(
        &cert_bytes,
        &loaded.revoked_root_ids,
        &loaded.fingerprint,
    )
    .expect("pending-only revocation must not be enforced");
}
