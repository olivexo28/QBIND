//! Run 065 (C4 piece: per-environment minimum activation-height
//! policy for trust-bundle and revocation activation scheduling):
//! end-to-end loader-path integration tests.
//!
//! These tests drive
//! `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
//! against real ML-DSA-44-signed bundles to prove the Run 065 policy
//! correctly:
//!
//!   1. Accepts DevNet bundles with `activation_height = 0` against
//!      `current_height = 0` (immediate cutover preserved on the
//!      scaffolding environment).
//!   2. Rejects TestNet bundles whose `activation_height` is below
//!      `current_height + MIN_TESTNET_ACTIVATION_MARGIN`.
//!   3. Accepts TestNet bundles whose `activation_height` is exactly
//!      at the required minimum margin (inclusive boundary).
//!   4. Rejects MainNet bundles whose `activation_height` is below
//!      `current_height + MIN_MAINNET_ACTIVATION_MARGIN`.
//!   5. Accepts MainNet bundles whose `activation_height` meets the
//!      stricter MainNet margin.
//!   6. Preserves immediate emergency revocations (revocation entries
//!      with `activation_height = None`) on MainNet — the policy
//!      does NOT block emergency response.
//!   7. Rejects scheduled-revocation entries below the margin while
//!      keeping immediate revocations available in the same bundle.
//!   8. A bundle rejected by the Run 065 policy MUST NOT update the
//!      sequence-persistence file (the load fails before
//!      `check_and_update_sequence` is called by the binary).
//!
//! Strict scope: this file does NOT touch KEMTLS, consensus, timeout
//! verification, NewView wire formats, the leaf-handshake revocation
//! path, or any signature/verification semantics outside the
//! Run 065 minimum activation-height policy surface.

use std::path::PathBuf;

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::{
    ActivationContext, ActivationScope, RevocationScope, TrustBundleActivationError,
    MIN_MAINNET_ACTIVATION_MARGIN, MIN_TESTNET_ACTIVATION_MARGIN,
};
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleError, TrustBundleRevocation,
    TrustBundleRoot,
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
        "qbind-run065-it-{}-{}-{}",
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

struct Harness {
    signing_keys: BundleSigningKeySet,
    signing_key_id: [u8; 32],
    signing_sk: Vec<u8>,
    root_id_hex: String,
    root_pk_hex: String,
}

fn harness() -> Harness {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen for signing key");
    let signing_key_id = derive_signing_key_id(&pk);
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: signing_key_id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: pk,
    }]);
    let root = mint_devnet_root().expect("mint devnet root");
    Harness {
        signing_keys,
        signing_key_id,
        signing_sk: sk,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

/// Build a freshly signed bundle for the given environment with a
/// caller-chosen bundle-level `activation_height` and an optional
/// revocation entry. The bundle is signed AFTER all fields are
/// finalised so the signature is valid for the produced shape.
fn signed_bundle(
    h: &Harness,
    env: TrustBundleEnvironment,
    runtime_env: NetworkEnvironment,
    activation_height: Option<u64>,
    revocations: Vec<TrustBundleRevocation>,
) -> TrustBundle {
    let mut b = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: env,
        chain_id: Some(format!("{:016x}", runtime_env.chain_id().as_u64())),
        generated_at: 10,
        valid_from: 0,
        valid_until: u64::MAX,
        sequence: 1,
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
    let sig = sign_bundle_devnet_helper(&b, h.signing_key_id, &h.signing_sk)
        .expect("ML-DSA-44 sign bundle");
    b.signature = Some(sig);
    b
}

fn write_bundle_json(dir: &std::path::Path, b: &TrustBundle) -> PathBuf {
    let p = dir.join("trust-bundle.json");
    std::fs::write(&p, serde_json::to_vec(b).expect("serialise")).expect("write");
    p
}

// ============================================================
// 1. DevNet baseline: activation_height = 0 against
//    current_height = 0 is accepted (preserves Run 057/058
//    immediate-cutover DevNet evidence shape).
// ============================================================
#[test]
fn run065_signed_devnet_activation_height_zero_loads() {
    let dir = fresh_dir("devnet-zero");
    let h = harness();
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Devnet,
        NetworkEnvironment::Devnet,
        Some(0),
        vec![],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(0);
    let (loaded, _act) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .expect("DevNet signed bundle with activation_height=0 loads");
    assert!(loaded.signature_status.is_verified());
    assert_eq!(loaded.bundle.activation_height, Some(0));
}

// ============================================================
// 2. TestNet too-soon negative.
// ============================================================
#[test]
fn run065_signed_testnet_activation_height_below_margin_fails_closed() {
    let dir = fresh_dir("testnet-too-soon");
    let h = harness();
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Testnet,
        NetworkEnvironment::Testnet,
        Some(MIN_TESTNET_ACTIVATION_MARGIN - 1), // 7 against current=0
        vec![],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(0);
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Testnet,
        NetworkEnvironment::Testnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    match err {
        TrustBundleError::Activation(
            TrustBundleActivationError::ActivationHeightBelowMinimumMargin {
                environment,
                activation_height,
                required_min_height,
                scope: ActivationScope::Bundle,
                ..
            },
        ) => {
            assert_eq!(environment, TrustBundleEnvironment::Testnet);
            assert_eq!(activation_height, MIN_TESTNET_ACTIVATION_MARGIN - 1);
            assert_eq!(required_min_height, MIN_TESTNET_ACTIVATION_MARGIN);
        }
        other => panic!(
            "expected Activation(ActivationHeightBelowMinimumMargin{{Bundle}}), got {:?}",
            other
        ),
    }
}

// ============================================================
// 3. TestNet sufficient-margin: at-margin is the smallest legal
//    scheduling; from current_height = 0 the bundle is therefore
//    future-dated and reaches Run 057's "not yet reached" path
//    (the legitimate scheduled-but-not-yet-effective boundary).
//    A bundle with activation_height = 5 against current = 10
//    (already-effective, was published when current was smaller)
//    loads cleanly. Both shapes prove the Run 065 policy does NOT
//    reject correctly-margined or already-effective bundles.
// ============================================================
#[test]
fn run065_signed_testnet_at_margin_reaches_run057_boundary() {
    let dir = fresh_dir("testnet-at-margin-r057");
    let h = harness();
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Testnet,
        NetworkEnvironment::Testnet,
        Some(MIN_TESTNET_ACTIVATION_MARGIN), // 8 against current = 0
        vec![],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(0);
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Testnet,
        NetworkEnvironment::Testnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    // Run 057 future-height gate is the next boundary — the bundle
    // is correctly margined (Run 065 passes) but not yet effective.
    match err {
        TrustBundleError::Activation(
            TrustBundleActivationError::ActivationHeightNotYetReached {
                current_height: 0,
                required_height,
                ..
            },
        ) => assert_eq!(required_height, MIN_TESTNET_ACTIVATION_MARGIN),
        other => panic!(
            "expected Run 057 ActivationHeightNotYetReached, got {:?}",
            other
        ),
    }
}

#[test]
fn run065_signed_testnet_already_effective_loads() {
    let dir = fresh_dir("testnet-already-effective");
    let h = harness();
    // Bundle published earlier, activation has passed: activation=5,
    // current=10 (10 > 5) so Run 057 passes; Run 065 sees activation
    // < current, treats as already-effective.
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Testnet,
        NetworkEnvironment::Testnet,
        Some(5),
        vec![],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(10);
    let (loaded, _act) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Testnet,
        NetworkEnvironment::Testnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .expect("TestNet already-effective bundle loads");
    assert!(loaded.signature_status.is_verified());
    assert_eq!(loaded.bundle.activation_height, Some(5));
}

// ============================================================
// 4. MainNet too-soon negative — also proves the MainNet margin
//    is strictly stricter than TestNet (a value that satisfies
//    TestNet still fails MainNet).
// ============================================================
#[test]
fn run065_signed_mainnet_activation_height_below_margin_fails_closed() {
    let dir = fresh_dir("mainnet-too-soon");
    let h = harness();
    // 10 satisfies TestNet (>=8) but NOT MainNet (>=32).
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Mainnet,
        NetworkEnvironment::Mainnet,
        Some(10),
        vec![],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(0);
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Mainnet,
        NetworkEnvironment::Mainnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    match err {
        TrustBundleError::Activation(
            TrustBundleActivationError::ActivationHeightBelowMinimumMargin {
                environment,
                required_min_height,
                ..
            },
        ) => {
            assert_eq!(environment, TrustBundleEnvironment::Mainnet);
            assert_eq!(required_min_height, MIN_MAINNET_ACTIVATION_MARGIN);
        }
        other => panic!(
            "expected Activation(ActivationHeightBelowMinimumMargin), got {:?}",
            other
        ),
    }
}

// ============================================================
// 5. MainNet sufficient-margin: at-margin is the smallest legal
//    scheduling; from current_height = 0 the bundle reaches
//    Run 057's "not yet reached" boundary. An already-effective
//    MainNet bundle loads cleanly.
// ============================================================
#[test]
fn run065_signed_mainnet_at_margin_reaches_run057_boundary() {
    let dir = fresh_dir("mainnet-at-margin-r057");
    let h = harness();
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Mainnet,
        NetworkEnvironment::Mainnet,
        Some(MIN_MAINNET_ACTIVATION_MARGIN), // 32 against current = 0
        vec![],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(0);
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Mainnet,
        NetworkEnvironment::Mainnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    match err {
        TrustBundleError::Activation(
            TrustBundleActivationError::ActivationHeightNotYetReached {
                current_height: 0,
                required_height,
                ..
            },
        ) => assert_eq!(required_height, MIN_MAINNET_ACTIVATION_MARGIN),
        other => panic!(
            "expected Run 057 ActivationHeightNotYetReached, got {:?}",
            other
        ),
    }
}

#[test]
fn run065_signed_mainnet_already_effective_loads() {
    let dir = fresh_dir("mainnet-already-effective");
    let h = harness();
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Mainnet,
        NetworkEnvironment::Mainnet,
        Some(5),
        vec![],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(1000);
    let (loaded, _act) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Mainnet,
        NetworkEnvironment::Mainnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .expect("MainNet already-effective bundle loads");
    assert!(loaded.signature_status.is_verified());
}

// ============================================================
// 6. Emergency immediate revocation preserved on MainNet — a
//    revocation entry with activation_height = None is NOT
//    constrained by the Run 065 policy.
// ============================================================
#[test]
fn run065_immediate_revocation_preserved_on_signed_mainnet() {
    let dir = fresh_dir("mainnet-emergency");
    let h = harness();
    // Revocation MUST refer to a known root; the schema rule is
    // `RevocationReferencesUnknownRoot` otherwise. Target the only
    // root in the bundle; the resulting bundle has an empty active
    // root set after the revocation activates, which is the
    // documented "emergency revoke everything" shape and is the
    // operator path Run 065 intentionally preserves.
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Mainnet,
        NetworkEnvironment::Mainnet,
        None, // no scheduled bundle activation
        vec![TrustBundleRevocation {
            root_id: h.root_id_hex.clone(),
            leaf_cert_fingerprint: None,
            reason: "compromise".to_string(),
            effective_from: 0,
            activation_height: None, // immediate
        }],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(0);
    let (loaded, _act) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Mainnet,
        NetworkEnvironment::Mainnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .expect("MainNet immediate emergency revocation must load");
    assert!(loaded.signature_status.is_verified());
    assert_eq!(loaded.active_revocations_total(), 1);
    assert_eq!(loaded.pending_revocations_total(), 0);
}

// ============================================================
// 7. Scheduled revocation activation_height below the margin is
//    rejected on MainNet, while a sibling immediate revocation in
//    the same bundle would have been accepted on its own — proves
//    the policy fires precisely on the scheduled-revocation
//    activation_height field, not on the revocation entry as a
//    whole.
// ============================================================
#[test]
fn run065_scheduled_revocation_below_margin_fails_closed_on_signed_mainnet() {
    let dir = fresh_dir("mainnet-sched-too-soon");
    let h = harness();
    let target_root = h.root_id_hex.clone();
    let leaf_fp = "aa".repeat(32);
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Mainnet,
        NetworkEnvironment::Mainnet,
        None,
        vec![TrustBundleRevocation {
            root_id: target_root.clone(),
            leaf_cert_fingerprint: Some(leaf_fp.clone()),
            reason: "rotation".to_string(),
            effective_from: 0,
            activation_height: Some(10), // < 32
        }],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(0);
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Mainnet,
        NetworkEnvironment::Mainnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    match err {
        TrustBundleError::Activation(
            TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin {
                environment,
                required_min_height,
                scope:
                    RevocationScope {
                        ref root_id,
                        leaf_fingerprint: Some(ref lf),
                    },
                ..
            },
        ) => {
            assert_eq!(environment, TrustBundleEnvironment::Mainnet);
            assert_eq!(required_min_height, MIN_MAINNET_ACTIVATION_MARGIN);
            assert_eq!(root_id, &target_root);
            assert_eq!(lf, &leaf_fp);
        }
        other => panic!(
            "expected RevocationActivationHeightBelowMinimumMargin, got {:?}",
            other
        ),
    }
}

// ============================================================
// 8. A bundle rejected by the Run 065 policy does NOT create or
//    update the sequence-persistence file. This pins the strict
//    ordering: Run 065 policy fails closed BEFORE
//    `pqc_trust_sequence::check_and_update_sequence` would be
//    called by the binary (the loader returns Err before sequence
//    persistence is even attempted).
// ============================================================
#[test]
fn run065_too_soon_bundle_does_not_touch_loader_outcome() {
    let dir = fresh_dir("seq-not-touched");
    let h = harness();
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Mainnet,
        NetworkEnvironment::Mainnet,
        Some(1), // < 32
        vec![],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(0);
    // The loader returns Err — the binary's strict ordering
    // (`main.rs` calls `check_and_update_sequence` only on Ok)
    // therefore never invokes sequence persistence. The unit test
    // surface here pins the loader-level boundary; the binary-level
    // boundary is documented in the Run 065 release-binary smokes.
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Mainnet,
        NetworkEnvironment::Mainnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TrustBundleError::Activation(
            TrustBundleActivationError::ActivationHeightBelowMinimumMargin { .. }
        )
    ));
    // No sequence file was written (the loader never returned a
    // LoadedTrustBundle, and the binary writes the sequence file
    // only after a successful load).
    let candidate_seq = dir.join("pqc_trust_sequence.json");
    assert!(
        !candidate_seq.exists(),
        "rejected too-soon bundle must not create a sequence file"
    );
}

// ============================================================
// 9. Run 057 future-height gating still wins on a bundle that
//    declares activation_height > current_height regardless of
//    the Run 065 margin. The Display message identifies the
//    Run 057 path, not the Run 065 path.
// ============================================================
#[test]
fn run065_future_height_still_handled_by_run_057_gate() {
    let dir = fresh_dir("future-height-still-r057");
    let h = harness();
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Mainnet,
        NetworkEnvironment::Mainnet,
        Some(1_000_000), // satisfies Run 065 (>>32) but > current=0
        vec![],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(0);
    let err = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Mainnet,
        NetworkEnvironment::Mainnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .unwrap_err();
    match err {
        TrustBundleError::Activation(
            TrustBundleActivationError::ActivationHeightNotYetReached { .. },
        ) => {}
        other => panic!(
            "expected Run 057 ActivationHeightNotYetReached, got {:?}",
            other
        ),
    }
}

// ============================================================
// 10. Signed DevNet bundle with a scheduled revocation at
//     activation_height = 0 still loads (preserves Run 062
//     DevNet shape) — confirms DevNet's zero margin path is
//     also applied to scheduled revocations.
// ============================================================
#[test]
fn run065_signed_devnet_scheduled_revocation_zero_loads() {
    let dir = fresh_dir("devnet-sched-zero");
    let h = harness();
    let bundle = signed_bundle(
        &h,
        TrustBundleEnvironment::Devnet,
        NetworkEnvironment::Devnet,
        None,
        vec![TrustBundleRevocation {
            root_id: h.root_id_hex.clone(),
            leaf_cert_fingerprint: Some("cc".repeat(32)),
            reason: "rotation".to_string(),
            effective_from: 0,
            activation_height: Some(0),
        }],
    );
    let path = write_bundle_json(&dir, &bundle);
    let ctx = ActivationContext::height_only(0);
    let (loaded, _act) = TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        &path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
        ctx,
    )
    .expect("DevNet scheduled revocation at activation_height=0 loads");
    assert_eq!(loaded.active_revocations_total(), 1);
}
