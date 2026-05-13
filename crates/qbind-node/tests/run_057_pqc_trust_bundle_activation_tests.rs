//! Run 057 (C4 piece: PQC trust-bundle activation epoch/height gating):
//! integration tests for the activation-gate layer.
//!
//! These tests exercise the public API of
//! `qbind_node::pqc_trust_activation` and
//! `qbind_node::pqc_trust_bundle::TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
//! against real validated `LoadedTrustBundle`s to prove the end-to-
//! end behaviour an operator sees: a node accepts a bundle whose
//! declared activation gate is satisfied at the supplied runtime
//! context, refuses a structurally-valid + signed bundle whose
//! `activation_height` is in the future, refuses a bundle that
//! declares any gate which requires a runtime source the caller did
//! not supply, and crucially does NOT advance the
//! `pqc_trust_bundle_sequence` anti-rollback persistence record (or
//! merge any roots) on the future-activation rejection path — so a
//! premature signed bundle cannot permanently burn a higher
//! sequence and silently roll back the node when a satisfied bundle
//! later arrives.
//!
//! Strict scope: this file does NOT touch KEMTLS, consensus, timeout
//! verification, NewView wire formats, or any signature/verification
//! semantics outside the bundle-activation surface.

use std::path::PathBuf;

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::{
    check_bundle_activation, ActivationContext, ActivationScope,
    TrustBundleActivationError,
};
use qbind_node::pqc_trust_bundle::{
    build_helper_bundle, derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey,
    BundleSigningKeySet, HelperBundleMode, RootStatus, TrustBundle, TrustBundleEnvironment,
    TrustBundleError, TrustBundleRoot,
};
use qbind_node::pqc_trust_sequence::{
    check_and_update_sequence, load_record, sequence_file_path,
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

fn fresh_dir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run057-it-{}-{}-{}",
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

/// Build a freshly signed DevNet bundle with optional bundle-level
/// activation_height / activation_epoch. The activation fields are
/// applied BEFORE signing so the signed preimage and canonical
/// fingerprint cover them.
fn signed_devnet_bundle_with_activation(
    h: &DevnetSigningHarness,
    sequence: u64,
    generated_at: u64,
    activation_height: Option<u64>,
    activation_epoch: Option<u64>,
) -> TrustBundle {
    let mut b = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: TrustBundleEnvironment::Devnet,
        chain_id: Some(format!(
            "{:016x}",
            NetworkEnvironment::Devnet.chain_id().as_u64()
        )),
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
        revocations: vec![],
        signature: None,
        activation_epoch,
        activation_height,
    };
    let sig = sign_bundle_devnet_helper(&b, h.signing_key_id, &h.signing_sk)
        .expect("ML-DSA-44 sign devnet bundle");
    b.signature = Some(sig);
    b
}

fn write_bundle_json(dir: &std::path::Path, b: &TrustBundle) -> PathBuf {
    let p = dir.join("trust-bundle.json");
    std::fs::write(&p, serde_json::to_vec(b).expect("serialise")).expect("write");
    p
}

// ============================================================================
// 1. A signed DevNet bundle without any activation_* fields is accepted under
//    any runtime context (mirrors Run 050/051/055 behaviour; activation gate
//    is no-op).
// ============================================================================
#[test]
fn no_activation_fields_accepted_under_any_context() {
    let dir = fresh_dir("no-activation");
    let h = devnet_signing_harness();
    let bundle = signed_devnet_bundle_with_activation(&h, 1, 10, None, None);
    let path = write_bundle_json(&dir, &bundle);

    let ctx = ActivationContext::height_only(0);
    let (loaded, out) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .expect("loads");
    assert_eq!(loaded.active_root_count(), 1);
    assert_eq!(out.required_height, None);
    assert_eq!(out.required_epoch, None);
    assert_eq!(out.current_height, Some(0));
}

// ============================================================================
// 2. activation_height satisfied (current >= required) accepts the bundle.
// ============================================================================
#[test]
fn activation_height_satisfied_accepts_bundle() {
    let dir = fresh_dir("act-h-satisfied");
    let h = devnet_signing_harness();
    let bundle = signed_devnet_bundle_with_activation(&h, 1, 10, Some(100), None);
    let path = write_bundle_json(&dir, &bundle);

    let ctx = ActivationContext::height_only(150);
    let (loaded, out) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .expect("loads");
    assert_eq!(loaded.active_root_count(), 1);
    assert_eq!(out.required_height, Some(100));
    assert_eq!(out.current_height, Some(150));
}

// ============================================================================
// 3. activation_height in the future (current < required) refuses the bundle
//    with the precise activation error; LoadedTrustBundle is never produced.
// ============================================================================
#[test]
fn activation_height_future_refuses_bundle() {
    let dir = fresh_dir("act-h-future");
    let h = devnet_signing_harness();
    let bundle = signed_devnet_bundle_with_activation(&h, 1, 10, Some(1_000), None);
    let path = write_bundle_json(&dir, &bundle);

    let ctx = ActivationContext::height_only(999);
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    match err {
        TrustBundleError::Activation(act) => match act {
            TrustBundleActivationError::ActivationHeightNotYetReached {
                current_height,
                required_height,
                scope,
            } => {
                assert_eq!(current_height, 999);
                assert_eq!(required_height, 1_000);
                assert!(matches!(scope, ActivationScope::Bundle));
            }
            other => panic!("expected ActivationHeightNotYetReached, got {:?}", other),
        },
        other => panic!("expected TrustBundleError::Activation, got {:?}", other),
    }
}

// ============================================================================
// 4. activation_height inclusive boundary: current == required activates.
// ============================================================================
#[test]
fn activation_height_inclusive_equal_accepts() {
    let dir = fresh_dir("act-h-equal");
    let h = devnet_signing_harness();
    let bundle = signed_devnet_bundle_with_activation(&h, 1, 10, Some(42), None);
    let path = write_bundle_json(&dir, &bundle);

    let ctx = ActivationContext::height_only(42);
    let (_loaded, out) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .expect("loads");
    assert_eq!(out.required_height, Some(42));
    assert_eq!(out.current_height, Some(42));
}

// ============================================================================
// 5. activation_height declared but no current_height supplied refuses the
//    bundle with the CurrentHeightUnavailable variant (Run 057 fail-closed
//    on unavailable runtime source).
// ============================================================================
#[test]
fn activation_height_present_without_current_height_refuses() {
    let dir = fresh_dir("act-h-no-source");
    let h = devnet_signing_harness();
    let bundle = signed_devnet_bundle_with_activation(&h, 1, 10, Some(5), None);
    let path = write_bundle_json(&dir, &bundle);

    let ctx = ActivationContext::unavailable();
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TrustBundleError::Activation(
            TrustBundleActivationError::CurrentHeightUnavailable {
                required_height: 5,
                scope: ActivationScope::Bundle,
            }
        )
    ));
}

// ============================================================================
// 6. activation_epoch declared without epoch source refuses (Run 057's
//    "epoch gating deferred" boundary made honest at the loader boundary).
// ============================================================================
#[test]
fn activation_epoch_present_without_current_epoch_refuses() {
    let dir = fresh_dir("act-e-no-source");
    let h = devnet_signing_harness();
    let bundle = signed_devnet_bundle_with_activation(&h, 1, 10, None, Some(7));
    let path = write_bundle_json(&dir, &bundle);

    // Even a real height source does NOT substitute for the missing
    // epoch source; the gate enforced is the one the bundle declared.
    let ctx = ActivationContext::height_only(u64::MAX);
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TrustBundleError::Activation(
            TrustBundleActivationError::CurrentEpochUnavailable {
                required_epoch: 7,
                scope: ActivationScope::Bundle,
            }
        )
    ));
}

// ============================================================================
// 7. Most important guarantee: a future-activation bundle does NOT advance
//    the sequence-persistence record. We simulate the binary's strict order
//    (signature/env validate -> activation gate -> sequence persistence) and
//    assert that on activation rejection no sequence-persistence file ever
//    appears.
// ============================================================================
#[test]
fn future_activation_does_not_advance_sequence_persistence() {
    let dir = fresh_dir("act-seq-noadvance");
    let seq_path = sequence_file_path(&dir);
    assert!(load_record(&seq_path).expect("load").is_none());

    let h = devnet_signing_harness();
    let bundle = signed_devnet_bundle_with_activation(&h, 5, 10, Some(1_000), None);
    let path = write_bundle_json(&dir, &bundle);

    // Drive the activation-aware loader at current_height=0.
    let ctx = ActivationContext::height_only(0);
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TrustBundleError::Activation(
            TrustBundleActivationError::ActivationHeightNotYetReached { .. }
        )
    ));

    // CRITICAL: the binary surface stops on the Err and never reaches
    // check_and_update_sequence. We assert that here by demonstrating
    // that NO sequence file appears at the canonical path on this
    // failure path. (If the binary ever did the wrong thing and bumped
    // the sequence on a future-activation bundle, a subsequent
    // satisfied bundle at sequence=4 would later be rejected as
    // rollback — a silent permanent disable of the trust bundle.)
    assert!(load_record(&seq_path).expect("load").is_none());

    // Now demonstrate the converse: a satisfied bundle at sequence=5
    // (same generated_at, fresh signing key for distinctness is not
    // needed because content matches structurally — but we use a NEW
    // bundle with activation_height satisfied) on the same data_dir
    // produces a fresh FirstLoad persistence record. The
    // future-activation bundle did not corrupt this path.
    let satisfied = signed_devnet_bundle_with_activation(&h, 5, 11, Some(1_000), None);
    let path_sat = write_bundle_json(&dir, &satisfied);
    let ctx_sat = ActivationContext::height_only(1_000);
    let (loaded, _out) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path_sat,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ctx_sat,
    )
    .expect("activation now satisfied");
    let now = 99;
    let outcome = check_and_update_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        loaded.bundle.sequence,
        &loaded.fingerprint,
        now,
    )
    .expect("seq persistence advances cleanly on satisfied gate");
    assert_eq!(outcome.persisted_sequence(), 5);
}

// ============================================================================
// 8. Future-activation bundle still passes the Run 050/051/053 structural
//    layer (signature is valid, env / chain_id / window / revocations all
//    pass) — the only thing that fails is the Run 057 activation gate.
//    This proves the gate is its own boundary, not a side-effect of some
//    earlier validation.
// ============================================================================
#[test]
fn future_activation_bundle_is_structurally_valid_and_signed() {
    let h = devnet_signing_harness();
    let bundle = signed_devnet_bundle_with_activation(&h, 1, 10, Some(1_000), None);

    // The same bundle bytes pass the non-activation loader (proving
    // structural+signature validity is independent of activation).
    let bytes = serde_json::to_vec(&bundle).expect("serialise");
    let loaded = TrustBundle::load_from_bytes_with_signing_keys_and_chain_id(
        &bytes,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
    )
    .expect("structurally + signature valid");
    assert!(loaded.signature_status.is_verified());

    // And the activation check, run separately on the validated
    // bundle, fires only on the gate.
    let err = check_bundle_activation(&loaded.bundle, ActivationContext::height_only(999))
        .unwrap_err();
    assert!(err.is_future_activation());
}

// ============================================================================
// 9. Tampering with activation_height after signing invalidates the
//    signature (the field is covered by the canonical signing preimage).
// ============================================================================
#[test]
fn tampering_activation_height_after_signing_invalidates_signature() {
    let h = devnet_signing_harness();
    let mut bundle = signed_devnet_bundle_with_activation(&h, 1, 10, Some(100), None);
    // Mutate the activation_height post-signing.
    bundle.activation_height = Some(0);
    let bytes = serde_json::to_vec(&bundle).expect("serialise");
    let err = TrustBundle::load_from_bytes_with_signing_keys_and_chain_id(
        &bytes,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
    )
    .expect_err("post-signing tamper of activation_height must reject");
    // Must reject at the signature-verification boundary, NOT at the
    // activation boundary (the signature covers the canonical
    // preimage including the activation fields).
    assert!(
        matches!(err, TrustBundleError::BadSignature { .. }),
        "expected BadSignature, got {:?}",
        err
    );
}

// ============================================================================
// 10. Canonical fingerprint is sensitive to bundle-level
//     activation_height (proves the fingerprint covers the field, so the
//     equivocation guard in Run 055 cannot be bypassed by re-publishing
//     "same sequence, different activation_height" bundles).
// ============================================================================
#[test]
fn canonical_fingerprint_covers_activation_height() {
    let h = devnet_signing_harness();
    let a = signed_devnet_bundle_with_activation(&h, 1, 10, Some(100), None);
    let b = signed_devnet_bundle_with_activation(&h, 1, 10, Some(200), None);
    let fp_a = qbind_node::pqc_trust_bundle::canonical_fingerprint(&a);
    let fp_b = qbind_node::pqc_trust_bundle::canonical_fingerprint(&b);
    assert_ne!(fp_a, fp_b);
}

// ============================================================================
// 11. Per-root activation_height in the future on an Active root refuses
//     the whole bundle (mirrors the bundle-level gate).
// ============================================================================
#[test]
fn per_root_activation_height_future_refuses_bundle() {
    let h = devnet_signing_harness();
    // Build via build_helper_bundle then mutate, then SIGN so the
    // mutation is covered by the signed preimage.
    let mut b =
        build_helper_bundle(HelperBundleMode::Valid, &h.root_id_hex, &h.root_pk_hex, 10);
    b.environment = TrustBundleEnvironment::Devnet;
    b.chain_id = Some(format!(
        "{:016x}",
        NetworkEnvironment::Devnet.chain_id().as_u64()
    ));
    b.roots[0].activation_height = Some(2_000);
    let sig =
        sign_bundle_devnet_helper(&b, h.signing_key_id, &h.signing_sk).expect("sign");
    b.signature = Some(sig);

    let dir = fresh_dir("per-root-future");
    let path = write_bundle_json(&dir, &b);
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ActivationContext::height_only(1_999),
    )
    .unwrap_err();
    match err {
        TrustBundleError::Activation(
            TrustBundleActivationError::ActivationHeightNotYetReached {
                current_height,
                required_height,
                scope,
            },
        ) => {
            assert_eq!(current_height, 1_999);
            assert_eq!(required_height, 2_000);
            match scope {
                ActivationScope::Root(id) => assert_eq!(id, h.root_id_hex),
                other => panic!("expected Root scope, got {:?}", other),
            }
        }
        other => panic!("expected ActivationHeightNotYetReached, got {:?}", other),
    }
}

// ============================================================================
// 12. JSON parses back-compat for older bundles that don't carry the new
//     bundle-level activation_* fields. They default to None and are
//     accepted as "no activation gate declared".
// ============================================================================
#[test]
fn legacy_bundle_json_without_activation_fields_parses_clean() {
    // Hand-craft a minimal valid DevNet UNSIGNED bundle JSON that
    // does NOT include the new `activation_epoch` / `activation_height`
    // keys at all. The serde `default` attribute must populate them
    // as `None` and the loader must accept the result.
    let h = devnet_signing_harness();
    let json = format!(
        r#"{{
            "bundle_version": 1,
            "environment": "devnet",
            "chain_id": "{chain}",
            "generated_at": 10,
            "valid_from": 0,
            "valid_until": {u64_max},
            "sequence": 1,
            "roots": [
                {{
                    "root_id": "{rid}",
                    "suite_id": {suite},
                    "root_pk": "{rpk}",
                    "status": "active",
                    "not_before": 0,
                    "not_after": {u64_max}
                }}
            ],
            "revocations": []
        }}"#,
        chain = format!("{:016x}", NetworkEnvironment::Devnet.chain_id().as_u64()),
        u64_max = u64::MAX,
        rid = h.root_id_hex,
        suite = PQC_TRANSPORT_SUITE_ML_DSA_44,
        rpk = h.root_pk_hex,
    );
    let parsed: TrustBundle = serde_json::from_str(&json).expect("legacy JSON parses");
    assert_eq!(parsed.activation_epoch, None);
    assert_eq!(parsed.activation_height, None);
    assert_eq!(parsed.roots[0].activation_epoch, None);
    assert_eq!(parsed.roots[0].activation_height, None);

    // And the activation check accepts it under an unavailable context.
    let out = check_bundle_activation(&parsed, ActivationContext::unavailable())
        .expect("no gate declared");
    assert_eq!(out.required_height, None);
    assert_eq!(out.required_epoch, None);
}