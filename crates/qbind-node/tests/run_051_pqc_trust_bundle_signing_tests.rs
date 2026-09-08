//! Run 051 (C4 piece: PQC trust-bundle ML-DSA-44 signed-bundle
//! verification): integration tests for the signed-bundle load
//! surface as it appears to operators on the
//! `--p2p-trust-bundle` + `--p2p-trust-bundle-signing-key` path.
//!
//! These tests do NOT spawn the `qbind-node` binary; they exercise
//! the public `qbind_node::pqc_trust_bundle` API end-to-end with
//! real ML-DSA-44 signatures. The matching live-binary smokes are
//! recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_051.md`.

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::{PqcRootMode, PqcStaticRootConfig, PQC_TRANSPORT_SUITE_ML_DSA_44};
use qbind_node::pqc_trust_bundle::{
    build_helper_bundle, derive_signing_key_id, sign_bundle_devnet_helper, BundleSignatureStatus,
    BundleSigningKey, BundleSigningKeySet, HelperBundleMode, TrustBundle, TrustBundleEnvironment,
    TrustBundleError,
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

fn build_signed_bundle(env: TrustBundleEnvironment) -> (TrustBundle, BundleSigningKeySet) {
    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    bundle.environment = env;
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let set = signing_set_with(signing_id, &signing_pk);
    (bundle, set)
}

#[test]
fn signed_devnet_bundle_loads_with_signing_key_and_merges_active_roots() {
    let (bundle, set) = build_signed_bundle(TrustBundleEnvironment::Devnet);
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
    let config = PqcStaticRootConfig {
        mode: PqcRootMode::PqcStaticRoot,
        trusted_roots: loaded.active_roots.clone(),
        leaf_credentials: None,
        peer_leaf_certs: Vec::new(),
    };
    assert_eq!(config.trusted_roots.len(), 1);
    let id_bytes = config.trusted_roots[0].root_key_id;
    let resolved = config
        .lookup_root_pk(&id_bytes)
        .expect("verified root must be resolvable through PqcStaticRootConfig");
    assert_eq!(resolved.suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44);
}

#[test]
fn unsigned_devnet_bundle_still_loads_when_signing_keys_are_supplied() {
    let (id_hex, pk_hex) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    let (signing_pk, _signing_sk, signing_id) = fresh_signing_keypair();
    let set = signing_set_with(signing_id, &signing_pk);
    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Devnet,
        100,
        &set,
    )
    .expect("unsigned DevNet bundle still loads");
    assert_eq!(loaded.signature_status, BundleSignatureStatus::Unsigned);
}

#[test]
fn signed_testnet_bundle_loads_with_signing_key() {
    let (bundle, set) = build_signed_bundle(TrustBundleEnvironment::Testnet);
    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Testnet,
        100,
        &set,
    )
    .expect("signed TestNet bundle verifies");
    assert!(loaded.signature_status.is_verified());
    assert_eq!(loaded.environment(), TrustBundleEnvironment::Testnet);
}

#[test]
fn unsigned_testnet_bundle_fails_closed_even_with_signing_keys_supplied() {
    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Testnet;
    let (signing_pk, _signing_sk, signing_id) = fresh_signing_keypair();
    let set = signing_set_with(signing_id, &signing_pk);
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Testnet,
        100,
        &set,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TrustBundleError::UnsignedBundleNotAllowed(TrustBundleEnvironment::Testnet)
    ));
}

#[test]
fn signed_mainnet_bundle_loads_with_signing_key() {
    let (bundle, set) = build_signed_bundle(TrustBundleEnvironment::Mainnet);
    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Mainnet,
        100,
        &set,
    )
    .expect("signed MainNet bundle verifies");
    assert!(loaded.signature_status.is_verified());
}

#[test]
fn unsigned_mainnet_bundle_fails_closed_even_with_signing_keys_supplied() {
    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    bundle.environment = TrustBundleEnvironment::Mainnet;
    let (signing_pk, _signing_sk, signing_id) = fresh_signing_keypair();
    let set = signing_set_with(signing_id, &signing_pk);
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Mainnet,
        100,
        &set,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TrustBundleError::UnsignedBundleNotAllowed(TrustBundleEnvironment::Mainnet)
    ));
}

#[test]
fn tampered_signed_bundle_fails_closed_with_bad_signature() {
    let (mut bundle, set) = build_signed_bundle(TrustBundleEnvironment::Devnet);
    // Mutate `not_after` post-signing — preimage changes, signature
    // (which signed the original preimage) no longer verifies.
    bundle.roots[0].not_after = bundle.roots[0].not_after.wrapping_sub(1);
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Devnet,
        100,
        &set,
    )
    .unwrap_err();
    assert!(matches!(err, TrustBundleError::BadSignature { .. }));
}

#[test]
fn wrong_signing_key_fails_closed() {
    let (bundle, _set) = build_signed_bundle(TrustBundleEnvironment::Devnet);
    // Build a *different* signing set keyed to the same id but a
    // fresh (unrelated) pk — simulates an operator who configured
    // the wrong public key for the right id.
    let signing_id_hex = bundle.signature.as_ref().unwrap().signing_key_id.clone();
    let signing_id_bytes = hex_to_32(&signing_id_hex);
    let (other_pk, _other_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let mut wrong_set = BundleSigningKeySet::empty();
    wrong_set.push_key_unchecked(BundleSigningKey {
        key_id_bytes: signing_id_bytes,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: other_pk,
    });
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Devnet,
        100,
        &wrong_set,
    )
    .unwrap_err();
    assert!(matches!(err, TrustBundleError::BadSignature { .. }));
}

#[test]
fn signed_bundle_with_unsupported_suite_fails_closed() {
    let (mut bundle, set) = build_signed_bundle(TrustBundleEnvironment::Devnet);
    bundle.signature.as_mut().unwrap().suite_id = 99;
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
        TrustBundleError::UnsupportedSignatureSuite { suite_id: 99, .. }
    ));
}

#[test]
fn signed_bundle_with_missing_signing_key_fails_closed() {
    let (bundle, _set) = build_signed_bundle(TrustBundleEnvironment::Devnet);
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes_with_signing_keys(
        &json,
        NetworkEnvironment::Devnet,
        100,
        &BundleSigningKeySet::empty(),
    )
    .unwrap_err();
    assert!(matches!(err, TrustBundleError::MissingSigningKey { .. }));
}

#[test]
fn signing_key_colliding_with_bundle_root_id_fails_closed() {
    // Construct a bundle where signature.signing_key_id == roots[0].root_id
    // exactly. Even with a matching signing-key configured (operator
    // typo), the validator must refuse to load the bundle — bundle-
    // signing authority MUST be trust-separated from transport roots.
    let (id_hex, pk_hex) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    let id_bytes = hex_to_32(&id_hex);
    let (signing_pk, signing_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let mut sig = sign_bundle_devnet_helper(&bundle, id_bytes, &signing_sk).expect("sign");
    sig.signing_key_id = id_hex.clone();
    bundle.signature = Some(sig);
    let mut set = BundleSigningKeySet::empty();
    set.push_key_unchecked(BundleSigningKey {
        key_id_bytes: id_bytes,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: signing_pk,
    });
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
        TrustBundleError::SigningKeyCollidesWithRootId(_)
    ));
}

#[test]
fn signature_metadata_change_does_not_affect_signing_preimage() {
    // A previously-unsigned bundle's fingerprint equals the same
    // bundle's fingerprint when re-signed: signature is stripped
    // from both the fingerprint and the signing preimage. This
    // proves that re-signing the same bundle does not change what
    // was signed.
    let (id_hex, pk_hex) = fresh_root_pair();
    let bundle_unsigned = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    let json_u = serde_json::to_vec(&bundle_unsigned).unwrap();
    let loaded_unsigned =
        TrustBundle::load_from_bytes(&json_u, NetworkEnvironment::Devnet, 100).expect("unsigned");

    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let mut bundle_signed = bundle_unsigned.clone();
    let sig = sign_bundle_devnet_helper(&bundle_signed, signing_id, &signing_sk).expect("sign");
    bundle_signed.signature = Some(sig);
    let set = signing_set_with(signing_id, &signing_pk);
    let json_s = serde_json::to_vec(&bundle_signed).unwrap();
    let loaded_signed = TrustBundle::load_from_bytes_with_signing_keys(
        &json_s,
        NetworkEnvironment::Devnet,
        100,
        &set,
    )
    .expect("signed");

    assert_eq!(loaded_unsigned.fingerprint, loaded_signed.fingerprint);
}

#[test]
fn back_compat_3_arg_load_still_works_for_unsigned_devnet() {
    // Run 050 callers (e.g. the run_050_pqc_trust_bundle_tests
    // integration tests) use the 3-arg `load_from_bytes` shim;
    // confirm it still routes through the new verify path with an
    // empty signing-key set and accepts unsigned DevNet bundles.
    let (id_hex, pk_hex) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded =
        TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 100).expect("loads");
    assert_eq!(loaded.signature_status, BundleSignatureStatus::Unsigned);
}

fn hex_to_32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = nibble(chunk[0]);
        let lo = nibble(chunk[1]);
        out[i] = (hi << 4) | lo;
    }
    out
}

fn nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + b - b'a',
        _ => panic!("bad hex"),
    }
}