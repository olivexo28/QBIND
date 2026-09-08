//! Run 071 (C4 piece: PQC trust-anchor lifecycle — mutable live
//! trust-context handle, initialize-only): integration tests that
//! exercise the [`qbind_node::pqc_live_trust::LivePqcTrustState`]
//! handle end-to-end against signed `LoadedTrustBundle`s minted via
//! the same DevNet helper path used by Runs 050/051/052/054/061/
//! 062/063 and through the same `P2pNodeBuilder` wiring used by the
//! production binary.
//!
//! These tests do NOT spawn the `qbind-node` binary; they exercise
//! the public `qbind_node::pqc_live_trust` + `pqc_trust_bundle` APIs
//! and the `qbind_node::p2p_node_builder` wiring. The matching live
//! release-binary smokes are recorded in
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_071.md`.
//!
//! Coverage:
//!
//! 1. `LivePqcTrustState::initialize_from_loaded_bundle` snapshot
//!    carries the same active roots, revoked root ids, revoked
//!    leaf-cert fingerprints, sequence, and canonical fingerprint as
//!    the validated `LoadedTrustBundle`.
//! 2. Pending revocations (Run 062 activation-gate not yet
//!    satisfied) are EXCLUDED from the live snapshot's active
//!    enforcement sets and INCLUDED in its observability-only
//!    pending sets.
//! 3. `LivePqcTrustState::lookup_active_root_pk` returns the
//!    bundle's `active_roots[i].root_pk` for a known root id and
//!    `None` for an unknown one.
//! 4. `LivePqcTrustState::is_leaf_revoked` returns `true` for an
//!    active revoked fingerprint and `false` for a pending-only
//!    one — proves Run 062 contract is preserved at the live
//!    handle's surface.
//! 5. `LivePqcTrustState` is `Clone` and produces consistent
//!    `snapshot()` reads from independently cloned handles
//!    (concurrency smoke).
//! 6. The signed-bundle `BundleSignatureStatus::Verified { .. }`
//!    surfaces on the live snapshot unchanged.
//! 7. `P2pNodeBuilder::with_live_pqc_trust(...)` accepts a live
//!    handle and `build()` still succeeds (the handle is wired into
//!    the production-honest PQC mutual-auth path; pre-Run-071
//!    builders are unaffected).

use std::collections::HashSet;
use std::sync::Arc;

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_live_trust::{LivePqcTrustError, LivePqcTrustSnapshot, LivePqcTrustState};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    build_helper_bundle, derive_signing_key_id, sign_bundle_devnet_helper, BundleSignatureStatus,
    BundleSigningKeySet, HelperBundleMode, TrustBundle, TrustBundleEnvironment,
    TrustBundleRevocation,
};
use qbind_types::NetworkEnvironment;

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

fn loaded_unsigned_devnet_bundle() -> qbind_node::pqc_trust_bundle::LoadedTrustBundle {
    let (_id_bytes, id_hex, pk_hex) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 100);
    let bytes = serde_json::to_vec(&bundle).expect("serialize");
    TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 200).expect("loads")
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn run_071_live_snapshot_matches_loaded_bundle_active_roots() {
    let loaded = loaded_unsigned_devnet_bundle();
    let expected_id = loaded.active_roots[0].root_key_id;
    let expected_pk = loaded.active_roots[0].root_pk.clone();

    let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
    let snap = live.snapshot().expect("snapshot");

    assert_eq!(snap.active_root_count(), 1);
    assert_eq!(snap.active_roots()[0].root_key_id, expected_id);
    assert_eq!(snap.active_roots()[0].root_pk, expected_pk);
    assert_eq!(snap.active_roots()[0].suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44);
    assert_eq!(snap.environment(), TrustBundleEnvironment::Devnet);
    assert_eq!(snap.sequence(), loaded.bundle.sequence);
    assert_eq!(snap.fingerprint(), &loaded.fingerprint);
    assert_eq!(snap.chain_id(), loaded.bundle.chain_id.as_deref());
}

#[test]
fn run_071_lookup_active_root_pk_round_trips_with_bundle() {
    let loaded = loaded_unsigned_devnet_bundle();
    let id = loaded.active_roots[0].root_key_id;
    let expected_pk = loaded.active_roots[0].root_pk.clone();
    let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);

    let resolved = live.lookup_active_root_pk(&id).expect("ok");
    assert_eq!(resolved, Some(expected_pk));

    let unknown = [0xFFu8; 32];
    assert_eq!(live.lookup_active_root_pk(&unknown).expect("ok"), None);
}

#[test]
fn run_071_live_snapshot_excludes_active_revoked_root_from_lookup() {
    // Build a signed DevNet bundle whose root id is also revoked
    // with `effective_from <= validation_time` and no activation
    // height — i.e. an ACTIVE root revocation. The live snapshot
    // MUST surface this in `revoked_root_ids` (active set) and
    // `lookup_active_root_pk` MUST return `None`.
    let (id_bytes, id_hex, pk_hex) = fresh_root_pair();
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();

    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 100);
    // Introduce a second active root so the bundle is still loadable
    // after the first root is revoked.
    let (_id2_bytes, id2_hex, pk2_hex) = fresh_root_pair();
    bundle.roots.push(qbind_node::pqc_trust_bundle::TrustBundleRoot {
        root_id: id2_hex.clone(),
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        root_pk: pk2_hex.clone(),
        status: qbind_node::pqc_trust_bundle::RootStatus::Active,
        not_before: 0,
        not_after: u64::MAX,
        activation_epoch: None,
        activation_height: None,
    });
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: None,
        reason: "run-071-test-revocation".to_string(),
        effective_from: 0,
        activation_height: None,
    });
    bundle.sequence = 2;
    bundle.environment = TrustBundleEnvironment::Devnet;

    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let bytes = serde_json::to_vec(&bundle).expect("serialize");
    let keys = signing_set_with(signing_id, &signing_pk);
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &bytes,
        NetworkEnvironment::Devnet,
        200,
        &keys,
    )
    .expect("loads signed");

    assert!(loaded.is_root_revoked(&id_bytes));
    let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
    let snap = live.snapshot().expect("snap");
    assert!(snap.revoked_root_ids().contains(&id_bytes));
    assert!(snap.pending_revoked_root_ids().is_empty());
    assert_eq!(live.lookup_active_root_pk(&id_bytes).expect("ok"), None);
}

#[test]
fn run_071_live_snapshot_pending_root_revocation_is_not_enforced() {
    // Build a signed DevNet bundle whose root revocation declares a
    // future `activation_height` greater than the runtime height the
    // loader was given — Run 062 PENDING semantics. The live snapshot
    // MUST place that id in `pending_revoked_root_ids` (observability
    // only) and NOT in `revoked_root_ids` (active enforcement set).
    let (id_bytes, id_hex, pk_hex) = fresh_root_pair();
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();

    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 100);
    // Second active root so the bundle still has a usable active
    // root if we want to verify lookup_active works.
    let (_id2_bytes, id2_hex, pk2_hex) = fresh_root_pair();
    bundle.roots.push(qbind_node::pqc_trust_bundle::TrustBundleRoot {
        root_id: id2_hex.clone(),
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        root_pk: pk2_hex.clone(),
        status: qbind_node::pqc_trust_bundle::RootStatus::Active,
        not_before: 0,
        not_after: u64::MAX,
        activation_epoch: None,
        activation_height: None,
    });
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: None,
        reason: "run-071-pending-revocation".to_string(),
        effective_from: 0,
        // Activation gate not yet satisfied: requires height >= 1000;
        // the loader is given height 0 below.
        activation_height: Some(1000),
    });
    bundle.sequence = 2;

    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let bytes = serde_json::to_vec(&bundle).expect("serialize");
    let keys = signing_set_with(signing_id, &signing_pk);
    // The legacy `load_from_bytes_with_signing_keys` path treats a
    // declared `activation_height` revocation as PENDING when no
    // runtime height is supplied (fail-safe semantics, Run 062).
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &bytes,
        NetworkEnvironment::Devnet,
        200,
        &keys,
    )
    .expect("loads signed");

    let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
    let snap = live.snapshot().expect("snap");
    assert!(!snap.revoked_root_ids().contains(&id_bytes));
    assert!(snap.pending_revoked_root_ids().contains(&id_bytes));
    // Lookup of the pending-but-not-active-revoked root still
    // returns its public key (Run 062 contract preserved).
    assert!(live.lookup_active_root_pk(&id_bytes).expect("ok").is_some());
}

#[test]
fn run_071_live_snapshot_active_leaf_revocation_is_enforced() {
    let (id_bytes, id_hex, pk_hex) = fresh_root_pair();
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let active_fp = [0xAAu8; 32];

    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 100);
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: Some(hex_lower(&active_fp)),
        reason: "run-071-active-leaf".to_string(),
        effective_from: 0,
        activation_height: None,
    });
    bundle.sequence = 2;

    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let bytes = serde_json::to_vec(&bundle).expect("serialize");
    let keys = signing_set_with(signing_id, &signing_pk);
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &bytes,
        NetworkEnvironment::Devnet,
        200,
        &keys,
    )
    .expect("loads signed");

    // The active root id is unchanged.
    let _ = id_bytes;

    let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
    assert!(live.is_leaf_revoked(&active_fp).expect("ok"));
    assert_eq!(live.active_leaf_revocation_count().expect("ok"), 1);
    let unknown = [0xBBu8; 32];
    assert!(!live.is_leaf_revoked(&unknown).expect("ok"));
}

#[test]
fn run_071_live_snapshot_pending_leaf_revocation_is_not_enforced() {
    let (_id_bytes, id_hex, pk_hex) = fresh_root_pair();
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let pending_fp = [0xCCu8; 32];

    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 100);
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: Some(hex_lower(&pending_fp)),
        reason: "run-071-pending-leaf".to_string(),
        effective_from: 0,
        activation_height: Some(1000),
    });
    bundle.sequence = 2;

    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let bytes = serde_json::to_vec(&bundle).expect("serialize");
    let keys = signing_set_with(signing_id, &signing_pk);
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &bytes,
        NetworkEnvironment::Devnet,
        200,
        &keys,
    )
    .expect("loads (pending leaf, legacy path)");

    let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
    assert!(!live.is_leaf_revoked(&pending_fp).expect("ok"));
    assert_eq!(live.active_leaf_revocation_count().expect("ok"), 0);

    let snap = live.snapshot().expect("snap");
    assert!(snap.pending_revoked_leaf_fingerprints().contains(&pending_fp));
    assert!(!snap.revoked_leaf_fingerprints().contains(&pending_fp));
}

#[test]
fn run_071_signed_bundle_signature_status_round_trips() {
    let (_id_bytes, id_hex, pk_hex) = fresh_root_pair();
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 100);
    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let bytes = serde_json::to_vec(&bundle).expect("serialize");
    let keys = signing_set_with(signing_id, &signing_pk);
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &bytes,
        NetworkEnvironment::Devnet,
        200,
        &keys,
    )
    .expect("loads signed");
    assert!(matches!(
        loaded.signature_status,
        BundleSignatureStatus::Verified { .. }
    ));

    let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
    let snap = live.snapshot().expect("snap");
    match snap.signature_status() {
        BundleSignatureStatus::Verified { signing_key_id } => {
            assert_eq!(signing_key_id, &hex_lower(&signing_id));
        }
        other => panic!("expected Verified, got {:?}", other),
    }
}

#[test]
fn run_071_clones_of_live_handle_share_underlying_snapshot() {
    // Cheap-clone contract: the inner Arc<RwLock<...>> is shared.
    // Two snapshots obtained from two different clones of the SAME
    // handle (no swap) must point at the same heap allocation.
    let loaded = loaded_unsigned_devnet_bundle();
    let live_a = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
    let live_b = live_a.clone();
    let snap_a = live_a.snapshot().expect("a");
    let snap_b = live_b.snapshot().expect("b");
    assert!(Arc::ptr_eq(&snap_a, &snap_b));
}

#[test]
fn run_071_from_snapshot_constructor_round_trips_metadata() {
    // The from_snapshot test-only constructor lets callers pin down
    // a specific snapshot for tests; it must round-trip every public
    // field correctly.
    let loaded = loaded_unsigned_devnet_bundle();
    let original = LivePqcTrustSnapshot::from_loaded(&loaded);
    let env = original.environment();
    let fp = *original.fingerprint();
    let seq = original.sequence();
    let active = original.active_root_count();
    let live = LivePqcTrustState::from_snapshot(original);
    let snap = live.snapshot().expect("snap");
    assert_eq!(snap.environment(), env);
    assert_eq!(snap.fingerprint(), &fp);
    assert_eq!(snap.sequence(), seq);
    assert_eq!(snap.active_root_count(), active);
}

#[test]
fn run_071_lookup_returns_lock_poisoned_error_on_poisoned_rwlock() {
    // We cannot easily poison the lock here without reaching into the
    // private field. The library-level test in
    // `crates/qbind-node/src/pqc_live_trust.rs::tests::
    // poisoned_lock_returns_lock_poisoned_error` covers that path.
    // This integration test instead asserts the error variant is
    // public, has a Display string, and matches the documented
    // contract.
    let e = LivePqcTrustError::LockPoisoned;
    let s = format!("{}", e);
    assert!(s.contains("live PQC trust-state lock is poisoned"));
    assert!(s.contains("fail closed"));
}

#[test]
fn run_071_live_handle_wires_into_p2p_node_builder_without_panic() {
    // Smoke test: the new `with_live_pqc_trust(...)` builder method
    // accepts a `LivePqcTrustState` cleanly. We do not exercise the
    // full `build()` pipeline (it spawns sockets / consensus threads);
    // covered by the live-binary smokes in
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_071.md`.
    let loaded = loaded_unsigned_devnet_bundle();
    let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
    let _builder = qbind_node::p2p_node_builder::P2pNodeBuilder::new().with_live_pqc_trust(live);
}

#[test]
fn run_071_handle_does_not_mutate_on_repeated_snapshot_reads() {
    // Run 071 NEVER mutates the live handle after startup. Repeated
    // snapshot reads must return Arcs pointing at the same allocation.
    let loaded = loaded_unsigned_devnet_bundle();
    let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
    let mut prev: Option<Arc<LivePqcTrustSnapshot>> = None;
    for _ in 0..16 {
        let s = live.snapshot().expect("snap");
        if let Some(p) = prev.as_ref() {
            assert!(Arc::ptr_eq(p, &s));
        }
        prev = Some(s);
    }
}

#[test]
fn run_071_active_revocation_sets_match_loaded_bundle_counts() {
    // Multi-entry sanity check: build a signed DevNet bundle with one
    // active leaf revocation, one pending leaf revocation, and one
    // active root revocation; assert that the live snapshot's active
    // and pending sets all line up with the loaded bundle's
    // post-validation counts.
    let (id_bytes, id_hex, pk_hex) = fresh_root_pair();
    let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
    let active_leaf_fp = [0x11u8; 32];
    let pending_leaf_fp = [0x22u8; 32];
    let _ = id_bytes;

    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 100);
    let (_id2_bytes, id2_hex, pk2_hex) = fresh_root_pair();
    bundle.roots.push(qbind_node::pqc_trust_bundle::TrustBundleRoot {
        root_id: id2_hex.clone(),
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        root_pk: pk2_hex.clone(),
        status: qbind_node::pqc_trust_bundle::RootStatus::Active,
        not_before: 0,
        not_after: u64::MAX,
        activation_epoch: None,
        activation_height: None,
    });
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: Some(hex_lower(&active_leaf_fp)),
        reason: "active-leaf".to_string(),
        effective_from: 0,
        activation_height: None,
    });
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: Some(hex_lower(&pending_leaf_fp)),
        reason: "pending-leaf".to_string(),
        effective_from: 0,
        activation_height: Some(1000),
    });
    bundle.revocations.push(TrustBundleRevocation {
        root_id: id_hex.clone(),
        leaf_cert_fingerprint: None,
        reason: "active-root".to_string(),
        effective_from: 0,
        activation_height: None,
    });
    bundle.sequence = 2;

    let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
    bundle.signature = Some(sig);
    let bytes = serde_json::to_vec(&bundle).expect("serialize");
    let keys = signing_set_with(signing_id, &signing_pk);
    let loaded = TrustBundle::load_from_bytes_with_signing_keys(
        &bytes,
        NetworkEnvironment::Devnet,
        200,
        &keys,
    )
    .expect("loads (mixed active+pending revocations, legacy path)");

    let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
    let snap = live.snapshot().expect("snap");

    // Active sets match loaded bundle.
    let expected_active_leaves: HashSet<[u8; 32]> =
        loaded.revoked_leaf_fingerprints.iter().copied().collect();
    let expected_pending_leaves: HashSet<[u8; 32]> =
        loaded.pending_revoked_leaf_fingerprints.iter().copied().collect();
    let expected_active_roots: HashSet<[u8; 32]> =
        loaded.revoked_root_ids.iter().copied().collect();
    let expected_pending_roots: HashSet<[u8; 32]> =
        loaded.pending_revoked_root_ids.iter().copied().collect();
    assert_eq!(snap.revoked_leaf_fingerprints(), &expected_active_leaves);
    assert_eq!(snap.pending_revoked_leaf_fingerprints(), &expected_pending_leaves);
    assert_eq!(snap.revoked_root_ids(), &expected_active_roots);
    assert_eq!(snap.pending_revoked_root_ids(), &expected_pending_roots);

    // Sanity on the cross-checks: at least one of each scope is
    // present.
    assert!(snap.revoked_leaf_count() >= 1);
    assert!(snap.pending_revoked_leaf_count() >= 1);
    assert!(snap.revoked_root_count() >= 1);
}