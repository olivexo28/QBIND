//! Run 091 (C4 piece: PQC trust-bundle `activation_epoch` runtime
//! source boundary):
//!
//! These integration tests pin the **partial-positive** boundary
//! established by Run 091: there is no canonical pre-consensus
//! runtime epoch source wired into the trust-bundle activation gate
//! today, so every production path (startup load, validation-only
//! reload-check, SIGHUP live reload, peer-candidate validation /
//! propagation) MUST fail closed when a bundle declares any
//! `activation_epoch` — never silently treat it as satisfied,
//! never advance the anti-rollback sequence, never mutate live
//! trust state, never evict sessions. The same fail-closed
//! semantics MUST apply on DevNet, TestNet, and MainNet (the
//! `activation_epoch` axis is environment-agnostic; per-environment
//! Run 065 minimum-margin policy applies only to the `activation_height`
//! axis).
//!
//! Run 091 explicitly does **not**:
//! - introduce a canonical runtime epoch source (no `meta:current_epoch`
//!   read at startup, no consensus-epoch peek before the trust-bundle
//!   gate; that would couple the trust-bundle load to the storage layer
//!   or consensus state and is out of scope);
//! - extend `TrustBundleRevocation` with an `activation_epoch` field
//!   (the wire format on `TrustBundleRevocation` carries only
//!   `activation_height`; per-entry revocation `activation_epoch` is
//!   intentionally unsupported at the schema level today);
//! - change the wire envelope, the bundle signing scheme, or any of
//!   the Run 050–090 invariants.
//!
//! Coverage matrix (per RUN_091_TASK.txt §"Required tests"):
//!
//! 1.  activation_epoch omitted: existing behavior unchanged
//!     (DevNet/TestNet/MainNet).
//! 2.  activation_epoch satisfied: candidate accepted when all
//!     other checks pass.
//! 3.  activation_epoch future: rejected before sequence write.
//! 4.  activation_height satisfied but activation_epoch future:
//!     rejected.
//! 5.  activation_epoch satisfied but activation_height future:
//!     rejected.
//! 6.  root activation_epoch future: bundle rejected.
//! 7.  root activation_epoch satisfied: bundle accepted.
//! 8.  unsupported epoch source with activation_epoch present on
//!     DevNet / TestNet / MainNet: fail-closed, not ignored.
//! 9.  reload-check with future activation_epoch: no sequence
//!     mutation.
//! 10. reload-check with activation_epoch declared under unavailable
//!     epoch source: no sequence mutation.
//! 11. revocation entries have no `activation_epoch` field at the
//!     schema level (pins the intentional unsupported-revocation-
//!     epoch boundary).

use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::{
    check_bundle_activation, ActivationContext, ActivationScope, TrustBundleActivationError,
};
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleError, TrustBundleRevocation,
    TrustBundleRoot,
};
use qbind_node::pqc_trust_reload::{
    validate_candidate_bundle, ReloadCheckError, ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::{
    chain_id_hex, load_record, sequence_file_path,
};
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------
// Test helpers (mirror Run 057 / Run 069 shape).
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
        "qbind-run091-{}-{}-{}",
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

/// Build a freshly signed DevNet bundle carrying optional bundle-level
/// AND optional per-active-root `activation_height` / `activation_epoch`.
/// The activation fields are applied BEFORE signing so the signed
/// preimage and canonical fingerprint cover them.
#[allow(clippy::too_many_arguments)]
fn build_signed_devnet_bundle(
    h: &DevnetSigningHarness,
    sequence: u64,
    generated_at: u64,
    bundle_act_h: Option<u64>,
    bundle_act_e: Option<u64>,
    root_act_h: Option<u64>,
    root_act_e: Option<u64>,
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
            activation_epoch: root_act_e,
            activation_height: root_act_h,
        }],
        revocations: vec![],
        signature: None,
        activation_epoch: bundle_act_e,
        activation_height: bundle_act_h,
    };
    let sig =
        sign_bundle_devnet_helper(&bundle, h.signing_key_id, &h.signing_sk).expect("sign");
    bundle.signature = Some(sig);
    bundle
}

fn write_bundle(dir: &Path, name: &str, b: &TrustBundle) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec(b).expect("serialise")).expect("write");
    path
}

fn devnet_reload_inputs<'a>(
    candidate_path: &'a Path,
    signing_keys: &'a BundleSigningKeySet,
    seq_path: Option<&'a Path>,
    ctx: ActivationContext,
) -> ReloadCheckInputs<'a> {
    ReloadCheckInputs {
        candidate_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys,
        activation_ctx: ctx,
        sequence_persistence_path: seq_path,
        local_leaf_cert_bytes: None,
    }
}

fn snapshot_file(path: &Path) -> Option<(Vec<u8>, std::time::SystemTime)> {
    if !path.exists() {
        return None;
    }
    let bytes = std::fs::read(path).expect("read");
    let mtime = std::fs::metadata(path)
        .expect("metadata")
        .modified()
        .expect("mtime");
    Some((bytes, mtime))
}

fn assert_seq_unchanged(path: &Path, snap: Option<(Vec<u8>, std::time::SystemTime)>) {
    match (snap, path.exists()) {
        (None, false) => {}
        (None, true) => panic!(
            "Run 091: rejection path must not create persistence file at {}",
            path.display()
        ),
        (Some(_), false) => panic!(
            "Run 091: rejection path must not delete persistence file at {}",
            path.display()
        ),
        (Some((b1, m1)), true) => {
            let b2 = std::fs::read(path).expect("read");
            assert_eq!(b1, b2, "Run 091: persistence bytes mutated on rejection");
            let m2 = std::fs::metadata(path)
                .expect("metadata")
                .modified()
                .expect("mtime");
            assert_eq!(m1, m2, "Run 091: persistence mtime mutated on rejection");
        }
    }
}

// =====================================================================
// 1. Unit-level: activation_epoch omitted preserves Run 050–090
//    behaviour under every runtime context (DevNet / TestNet / MainNet).
// =====================================================================

#[test]
fn run091_activation_epoch_omitted_devnet_no_op() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, 10, None, None, None, None);
    let out = check_bundle_activation(&b, ActivationContext::unavailable()).expect("ok");
    assert_eq!(out.required_epoch, None);
    assert_eq!(out.current_epoch, None);
}

#[test]
fn run091_activation_epoch_omitted_under_height_only_no_op() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, 10, Some(0), None, None, None);
    let out = check_bundle_activation(&b, ActivationContext::height_only(100)).expect("ok");
    assert_eq!(out.required_epoch, None);
    assert_eq!(out.current_epoch, None);
}

// =====================================================================
// 2. activation_epoch satisfied: candidate accepted when both gates pass.
// =====================================================================

#[test]
fn run091_bundle_activation_epoch_satisfied_accepted() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, 10, None, Some(3), None, None);
    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: Some(3),
    };
    let out = check_bundle_activation(&b, ctx).expect("epoch satisfied");
    assert_eq!(out.required_epoch, Some(3));
    assert_eq!(out.current_epoch, Some(3));
}

// =====================================================================
// 3. activation_epoch future: rejected.
// =====================================================================

#[test]
fn run091_bundle_activation_epoch_future_rejected() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, 10, None, Some(9), None, None);
    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: Some(2),
    };
    let err = check_bundle_activation(&b, ctx).expect_err("future epoch rejected");
    assert!(
        matches!(
            err,
            TrustBundleActivationError::ActivationEpochNotYetReached {
                current_epoch: 2,
                required_epoch: 9,
                scope: ActivationScope::Bundle,
            }
        ),
        "got {:?}",
        err
    );
    assert!(err.is_future_activation());
}

// =====================================================================
// 4. activation_height satisfied but activation_epoch future: rejected.
//    (Already covered by `both_gates_one_future_rejected` in the module
//    tests; we restate it here at the integration level so Run 091's
//    coverage matrix is independently verifiable.)
// =====================================================================

#[test]
fn run091_height_satisfied_epoch_future_rejected() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, 10, Some(50), Some(10), None, None);
    let ctx = ActivationContext {
        current_height: Some(60), // height satisfied
        current_epoch: Some(5),   // epoch NOT yet satisfied
    };
    let err = check_bundle_activation(&b, ctx).expect_err("epoch future rejects");
    assert!(matches!(
        err,
        TrustBundleActivationError::ActivationEpochNotYetReached { .. }
    ));
}

// =====================================================================
// 5. activation_epoch satisfied but activation_height future: rejected.
//    The converse: both gates evaluated independently; either future
//    fails closed.
// =====================================================================

#[test]
fn run091_epoch_satisfied_height_future_rejected() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, 10, Some(1_000), Some(2), None, None);
    let ctx = ActivationContext {
        current_height: Some(10), // height NOT yet satisfied
        current_epoch: Some(5),   // epoch satisfied
    };
    let err = check_bundle_activation(&b, ctx).expect_err("height future rejects");
    assert!(matches!(
        err,
        TrustBundleActivationError::ActivationHeightNotYetReached {
            current_height: 10,
            required_height: 1_000,
            scope: ActivationScope::Bundle,
        }
    ));
}

// =====================================================================
// 6. Root-level activation_epoch future: bundle rejected with Root scope.
// =====================================================================

#[test]
fn run091_root_activation_epoch_future_rejected() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, 10, None, None, None, Some(20));
    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: Some(19),
    };
    let err = check_bundle_activation(&b, ctx).expect_err("root epoch future rejects");
    match err {
        TrustBundleActivationError::ActivationEpochNotYetReached {
            current_epoch: 19,
            required_epoch: 20,
            scope: ActivationScope::Root(ref id),
        } => {
            assert_eq!(id, &h.root_id_hex);
        }
        other => panic!("expected Root-scope ActivationEpochNotYetReached, got {:?}", other),
    }
}

// =====================================================================
// 7. Root-level activation_epoch satisfied: bundle accepted; the
//    aggregate `required_epoch` carries the root's value.
// =====================================================================

#[test]
fn run091_root_activation_epoch_satisfied_accepted() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, 10, None, None, None, Some(4));
    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: Some(4),
    };
    let out = check_bundle_activation(&b, ctx).expect("root epoch satisfied");
    assert_eq!(out.required_epoch, Some(4));
}

// =====================================================================
// 8. Unsupported epoch source with activation_epoch present is
//    fail-closed on every environment. Run 091 partial-positive
//    invariant: the absence of a runtime epoch source MUST NOT
//    silently weaken the gate on TestNet or MainNet.
//    (TrustBundleEnvironment is checked via field flip on a structurally
//    signed bundle; the activation gate is environment-agnostic, so
//    the signature surface is the DevNet helper here. We flip the
//    `environment` field on the in-memory struct only for the
//    activation-layer assertion. The Run 050/051/053 signature/env
//    binding is separately verified by Run 057 integration tests.)
// =====================================================================

#[test]
fn run091_devnet_unsupported_epoch_source_fails_closed() {
    let h = devnet_signing_harness();
    let mut b = build_signed_devnet_bundle(&h, 1, 10, None, Some(1), None, None);
    b.environment = TrustBundleEnvironment::Devnet;
    let err = check_bundle_activation(&b, ActivationContext::unavailable())
        .expect_err("devnet fail-closed");
    assert!(matches!(
        err,
        TrustBundleActivationError::CurrentEpochUnavailable {
            required_epoch: 1,
            scope: ActivationScope::Bundle,
        }
    ));
}

#[test]
fn run091_testnet_unsupported_epoch_source_fails_closed() {
    let h = devnet_signing_harness();
    let mut b = build_signed_devnet_bundle(&h, 1, 10, None, Some(1), None, None);
    b.environment = TrustBundleEnvironment::Testnet;
    let err = check_bundle_activation(&b, ActivationContext::unavailable())
        .expect_err("testnet fail-closed");
    assert!(matches!(
        err,
        TrustBundleActivationError::CurrentEpochUnavailable {
            required_epoch: 1,
            scope: ActivationScope::Bundle,
        }
    ));

    // Height-only is the exact context the binary uses today. Even
    // with current_height supplied, a TestNet bundle declaring
    // activation_epoch MUST NOT be silently treated as satisfied.
    let err2 = check_bundle_activation(&b, ActivationContext::height_only(u64::MAX))
        .expect_err("testnet height-only fail-closed");
    assert!(matches!(
        err2,
        TrustBundleActivationError::CurrentEpochUnavailable { required_epoch: 1, .. }
    ));
}

#[test]
fn run091_mainnet_unsupported_epoch_source_fails_closed() {
    let h = devnet_signing_harness();
    let mut b = build_signed_devnet_bundle(&h, 1, 10, None, Some(1), None, None);
    b.environment = TrustBundleEnvironment::Mainnet;
    let err = check_bundle_activation(&b, ActivationContext::unavailable())
        .expect_err("mainnet fail-closed");
    assert!(matches!(
        err,
        TrustBundleActivationError::CurrentEpochUnavailable {
            required_epoch: 1,
            scope: ActivationScope::Bundle,
        }
    ));

    let err2 = check_bundle_activation(&b, ActivationContext::height_only(u64::MAX))
        .expect_err("mainnet height-only fail-closed");
    assert!(matches!(
        err2,
        TrustBundleActivationError::CurrentEpochUnavailable { required_epoch: 1, .. }
    ));
}

// =====================================================================
// 9. Reload-check (Run 069 surface) with a bundle declaring
//    activation_epoch on the unavailable-epoch context the binary
//    uses today: MUST reject with CurrentEpochUnavailable and MUST
//    NOT create / mutate the sequence persistence file. This is the
//    Run 091 partial-positive proof for the validation-only reload
//    path that operators run via `--p2p-trust-bundle-reload-check`.
// =====================================================================

#[test]
fn run091_reload_check_bundle_activation_epoch_unsupported_fails_closed_no_sequence_mutation() {
    let dir = tmpdir("reload-eu");
    let seq_path = sequence_file_path(&dir);
    assert!(load_record(&seq_path).expect("load").is_none());

    let h = devnet_signing_harness();
    // Bundle declares activation_epoch but the reload context (today)
    // has no epoch source. Height context = Some(u64::MAX) deliberately
    // so the only failing axis is the epoch source.
    let b = build_signed_devnet_bundle(&h, 1, 10, None, Some(7), None, None);
    let candidate = write_bundle(&dir, "reload-eu.json", &b);

    let snap = snapshot_file(&seq_path);
    let inputs = devnet_reload_inputs(
        &candidate,
        &h.signing_keys,
        Some(&seq_path),
        ActivationContext::height_only(u64::MAX),
    );
    let err = validate_candidate_bundle(inputs).expect_err("unsupported epoch source rejects");
    match err {
        ReloadCheckError::Bundle(TrustBundleError::Activation(
            TrustBundleActivationError::CurrentEpochUnavailable {
                required_epoch: 7,
                scope: ActivationScope::Bundle,
            },
        )) => {}
        other => panic!(
            "Run 091: expected Bundle(Activation(CurrentEpochUnavailable)), got {:?}",
            other
        ),
    }
    assert_seq_unchanged(&seq_path, snap);
    // Persistence remains absent — no sequence was burned.
    assert!(load_record(&seq_path).expect("load").is_none());
}

// =====================================================================
// 10. Reload-check with a bundle declaring activation_epoch in the
//     future under a SUPPLIED epoch source: rejected with
//     ActivationEpochNotYetReached; sequence persistence unchanged.
//     This proves the "future epoch" reject path under the hypothetical
//     future where the binary DOES supply a `current_epoch`. The
//     same call site MUST refuse to advance the sequence file on
//     that future-epoch path.
// =====================================================================

#[test]
fn run091_reload_check_bundle_activation_epoch_future_does_not_advance_sequence() {
    let dir = tmpdir("reload-ef");
    let seq_path = sequence_file_path(&dir);
    assert!(load_record(&seq_path).expect("load").is_none());

    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, 10, None, Some(9), None, None);
    let candidate = write_bundle(&dir, "reload-ef.json", &b);

    // Hypothetical supplied epoch source < required: future-epoch
    // reject path. Run 091 does not wire this surface in production
    // today, but the loader honours it correctly.
    let ctx = ActivationContext {
        current_height: Some(u64::MAX),
        current_epoch: Some(2),
    };
    let snap = snapshot_file(&seq_path);
    let inputs = devnet_reload_inputs(&candidate, &h.signing_keys, Some(&seq_path), ctx);
    let err = validate_candidate_bundle(inputs).expect_err("future epoch rejects");
    match err {
        ReloadCheckError::Bundle(TrustBundleError::Activation(
            TrustBundleActivationError::ActivationEpochNotYetReached {
                current_epoch: 2,
                required_epoch: 9,
                scope: ActivationScope::Bundle,
            },
        )) => {}
        other => panic!(
            "Run 091: expected Bundle(Activation(ActivationEpochNotYetReached)), got {:?}",
            other
        ),
    }
    assert_seq_unchanged(&seq_path, snap);
    assert!(load_record(&seq_path).expect("load").is_none());
}

// =====================================================================
// 11. Per-entry revocation `activation_epoch` is intentionally NOT
//     supported at the schema level today. The `TrustBundleRevocation`
//     struct carries only `activation_height` (Run 062 boundary). This
//     test pins that the schema field set has not grown an
//     `activation_epoch` axis under Run 091 — a fail-closed boundary
//     surfaces if a future run attempts to add the field without an
//     accompanying epoch-source design. The check is a compile-time
//     pattern match on every public field of `TrustBundleRevocation`.
// =====================================================================

#[test]
fn run091_revocation_schema_has_no_activation_epoch_field() {
    let rev = TrustBundleRevocation {
        root_id: "00".repeat(32),
        leaf_cert_fingerprint: None,
        reason: "rotation".to_string(),
        effective_from: 0,
        activation_height: None,
    };
    // Exhaustive destructure: if `activation_epoch` is ever added,
    // this test will fail to compile, which is precisely the gate
    // Run 091 is pinning. The body of this assertion is intentionally
    // minimal — its value is the destructure pattern itself.
    let TrustBundleRevocation {
        root_id,
        leaf_cert_fingerprint,
        reason,
        effective_from,
        activation_height,
    } = rev;
    let _ = (
        root_id,
        leaf_cert_fingerprint,
        reason,
        effective_from,
        activation_height,
    );
}

// =====================================================================
// 12. Display of the CurrentEpochUnavailable error must surface the
//     fail-closed boundary marker so operator logs can grep for it.
//     This pins the metadata-safety invariant: no private material,
//     no internal state, only the public scope + required epoch.
// =====================================================================

#[test]
fn run091_current_epoch_unavailable_display_is_safe_and_explicit() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, 10, None, Some(42), None, None);
    let err = check_bundle_activation(&b, ActivationContext::unavailable()).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("activation epoch gating requires current_epoch"),
        "fail-closed phrase missing: {}",
        msg
    );
    assert!(
        msg.contains("required_epoch=42"),
        "required_epoch missing: {}",
        msg
    );
    assert!(
        msg.contains("scope=bundle"),
        "scope missing: {}",
        msg
    );
    // No DummySig / DummyKem / DummyAead / no fallback to
    // --p2p-trusted-root leakage in error text.
    assert!(!msg.to_ascii_lowercase().contains("dummy"));
}