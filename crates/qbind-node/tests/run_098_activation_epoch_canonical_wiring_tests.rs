//! Run 098 — canonical `meta:current_epoch` wiring into
//! `ActivationContext.current_epoch` for production trust-bundle
//! activation.
//!
//! These tests pin the contract Run 098 lands:
//!
//! - the new [`activation_epoch_source_from_storage`] helper reads
//!   `meta:current_epoch` ONLY from the canonical Run 093 production
//!   `ConsensusStorage` surface;
//! - missing `meta:current_epoch` is NEVER coerced into `Some(0)` —
//!   it returns [`ActivationEpochSource::UnavailableNoCommittedEpoch`],
//!   which maps to `current_epoch = None`, which in turn triggers
//!   `TrustBundleActivationError::CurrentEpochUnavailable` at the
//!   activation gate for any bundle that declares `activation_epoch`;
//! - a committed `meta:current_epoch = n` satisfies the epoch axis
//!   for bundles with `activation_epoch <= n`;
//! - a committed `meta:current_epoch = n` rejects bundles with
//!   `activation_epoch > n` via
//!   [`TrustBundleActivationError::ActivationEpochNotYetReached`];
//! - bundles WITHOUT `activation_epoch` are unaffected (the epoch
//!   axis remains silent — backwards compatible with Run 050–097).
//!
//! Run 098 explicitly does NOT:
//! - derive epoch from block height, view, wall-clock, snapshot
//!   height, or any other non-canonical source;
//! - treat missing epoch as `0`;
//! - change the trust-bundle wire format;
//! - claim full C4 / C5 closure.
//!
//! See `task/RUN_098_TASK.txt` and
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::{
    check_bundle_activation, ActivationContext, ActivationScope, TrustBundleActivationError,
};
use qbind_node::pqc_trust_activation_epoch::{
    activation_epoch_source_from_lifecycle, activation_epoch_source_from_storage,
    ActivationEpochSource,
};
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_node::production_consensus_storage::OpenedProductionConsensusStorage;
use qbind_node::storage::{ConsensusStorage, RocksDbConsensusStorage};
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------
// Test helpers (mirror Run 091).
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
        "qbind-run098-{}-{}-{}",
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

#[allow(dead_code)]
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

fn build_signed_devnet_bundle(
    h: &DevnetSigningHarness,
    sequence: u64,
    bundle_act_e: Option<u64>,
) -> TrustBundle {
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
        activation_epoch: bundle_act_e,
        activation_height: None,
    };
    let sig =
        sign_bundle_devnet_helper(&bundle, h.signing_key_id, &h.signing_sk).expect("sign");
    bundle.signature = Some(sig);
    bundle
}

fn open_test_storage(dir: &Path) -> Arc<RocksDbConsensusStorage> {
    let path = dir.join("consensus");
    Arc::new(RocksDbConsensusStorage::open(&path).expect("open RocksDB consensus storage"))
}

// =====================================================================
// A. Canonical epoch helper tests
// =====================================================================

#[test]
fn run098_canonical_helper_returns_committed_when_storage_has_epoch() {
    let dir = tmpdir("committed");
    let storage = open_test_storage(&dir);
    storage.put_current_epoch(5).expect("put_current_epoch");
    let src = activation_epoch_source_from_storage(Some(&storage)).expect("read ok");
    assert!(matches!(src, ActivationEpochSource::Committed(5)));
    assert_eq!(src.as_option(), Some(5));
}

#[test]
fn run098_canonical_helper_returns_unavailable_when_no_committed_epoch() {
    let dir = tmpdir("nocommit");
    let storage = open_test_storage(&dir);
    // No put_current_epoch call.
    let src = activation_epoch_source_from_storage(Some(&storage)).expect("read ok");
    assert!(matches!(
        src,
        ActivationEpochSource::UnavailableNoCommittedEpoch
    ));
    assert_eq!(
        src.as_option(),
        None,
        "missing epoch MUST be None, never Some(0)"
    );
}

#[test]
fn run098_canonical_helper_returns_unavailable_when_no_storage_handle() {
    let src = activation_epoch_source_from_storage(None).expect("None ok");
    assert!(matches!(
        src,
        ActivationEpochSource::UnavailableNoCommittedEpoch
    ));
    assert_eq!(src.as_option(), None);
}

#[test]
fn run098_canonical_helper_lifecycle_no_storage_state_maps_to_unavailable() {
    let opened = OpenedProductionConsensusStorage::no_storage();
    let src = activation_epoch_source_from_lifecycle(&opened);
    assert!(matches!(
        src,
        ActivationEpochSource::UnavailableNoCommittedEpoch
    ));
    assert_eq!(src.as_option(), None);
}

// =====================================================================
// B. Bundle activation tests — committed epoch satisfies the gate.
// =====================================================================

#[test]
fn run098_bundle_with_activation_epoch_passes_when_committed_epoch_satisfies() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, Some(3));
    let dir = tmpdir("satisfies");
    let storage = open_test_storage(&dir);
    storage.put_current_epoch(5).expect("put 5");
    let epoch_opt = activation_epoch_source_from_storage(Some(&storage))
        .expect("ok")
        .as_option();
    assert_eq!(epoch_opt, Some(5));

    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: epoch_opt,
    };
    let out = check_bundle_activation(&b, ctx).expect("epoch axis satisfied");
    assert_eq!(out.required_epoch, Some(3));
    assert_eq!(out.current_epoch, Some(5));
}

#[test]
fn run098_bundle_with_activation_epoch_passes_when_committed_equals_required() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, Some(7));
    let dir = tmpdir("equal");
    let storage = open_test_storage(&dir);
    storage.put_current_epoch(7).expect("put 7");
    let epoch_opt = activation_epoch_source_from_storage(Some(&storage))
        .expect("ok")
        .as_option();
    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: epoch_opt,
    };
    let out = check_bundle_activation(&b, ctx).expect("epoch axis satisfied");
    assert_eq!(out.required_epoch, Some(7));
    assert_eq!(out.current_epoch, Some(7));
}

// =====================================================================
// C. Bundle activation tests — future epoch rejects fail-closed.
// =====================================================================

#[test]
fn run098_bundle_with_activation_epoch_rejects_future_epoch_via_canonical_source() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, Some(10));
    let dir = tmpdir("future");
    let storage = open_test_storage(&dir);
    storage.put_current_epoch(5).expect("put 5");
    let epoch_opt = activation_epoch_source_from_storage(Some(&storage))
        .expect("ok")
        .as_option();
    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: epoch_opt,
    };
    let err = check_bundle_activation(&b, ctx).expect_err("future epoch rejected");
    assert!(
        matches!(
            err,
            TrustBundleActivationError::ActivationEpochNotYetReached {
                current_epoch: 5,
                required_epoch: 10,
                scope: ActivationScope::Bundle,
            }
        ),
        "got {:?}",
        err
    );
}

// =====================================================================
// D. Bundle activation tests — unavailable epoch fail-closed.
// =====================================================================

#[test]
fn run098_bundle_with_activation_epoch_rejects_when_canonical_unavailable() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, Some(3));
    // Open storage with NO committed epoch — fresh genesis case.
    let dir = tmpdir("genesis");
    let storage = open_test_storage(&dir);
    let epoch_opt = activation_epoch_source_from_storage(Some(&storage))
        .expect("ok")
        .as_option();
    assert_eq!(
        epoch_opt, None,
        "fresh genesis storage MUST yield None, never Some(0)"
    );
    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: epoch_opt,
    };
    let err = check_bundle_activation(&b, ctx).expect_err("unavailable epoch rejected");
    assert!(
        matches!(
            err,
            TrustBundleActivationError::CurrentEpochUnavailable {
                required_epoch: 3,
                scope: ActivationScope::Bundle,
            }
        ),
        "got {:?}",
        err
    );
}

#[test]
fn run098_bundle_with_activation_epoch_rejects_when_no_storage_handle_at_all() {
    // Simulate DevNet ad-hoc without --data-dir: no storage handle.
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, Some(3));
    let epoch_opt = activation_epoch_source_from_storage(None)
        .expect("ok")
        .as_option();
    assert_eq!(epoch_opt, None);
    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: epoch_opt,
    };
    let err = check_bundle_activation(&b, ctx).expect_err("unavailable epoch rejected");
    assert!(matches!(
        err,
        TrustBundleActivationError::CurrentEpochUnavailable { required_epoch: 3, .. }
    ));
}

// =====================================================================
// E. Backwards compatibility — bundle without activation_epoch is silent.
// =====================================================================

#[test]
fn run098_bundle_without_activation_epoch_unchanged_by_canonical_wiring() {
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, None);
    // With None canonical:
    let ctx_none = ActivationContext {
        current_height: Some(0),
        current_epoch: None,
    };
    let out_none = check_bundle_activation(&b, ctx_none).expect("epoch silent");
    assert_eq!(out_none.required_epoch, None);
    assert_eq!(out_none.current_epoch, None);

    // With committed canonical:
    let ctx_some = ActivationContext {
        current_height: Some(0),
        current_epoch: Some(42),
    };
    let out_some = check_bundle_activation(&b, ctx_some).expect("epoch silent");
    assert_eq!(out_some.required_epoch, None);
    assert_eq!(
        out_some.current_epoch,
        Some(42),
        "current_epoch is still echoed even when bundle declares no gate"
    );
}

// =====================================================================
// F. Old snapshot without epoch still rejects (Run 097 parity).
// =====================================================================

#[test]
fn run098_old_snapshot_without_epoch_still_rejects_activation_epoch() {
    // Simulate a Run 097 restore from an OLD snapshot that has no
    // canonical epoch: persist_restored_snapshot_epoch returns
    // Ok(false) without writing anything. The post-restore storage
    // therefore has no committed epoch.
    let dir = tmpdir("oldsnap");
    let storage = open_test_storage(&dir);
    // (No put_current_epoch — old snapshot did not carry epoch.)
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, Some(3));
    let epoch_opt = activation_epoch_source_from_storage(Some(&storage))
        .expect("ok")
        .as_option();
    assert_eq!(epoch_opt, None);
    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: epoch_opt,
    };
    let err = check_bundle_activation(&b, ctx).expect_err("unavailable epoch rejected");
    assert!(matches!(
        err,
        TrustBundleActivationError::CurrentEpochUnavailable { required_epoch: 3, .. }
    ));
}

// =====================================================================
// G. Restored snapshot WITH epoch satisfies (Run 097 parity).
// =====================================================================

#[test]
fn run098_restored_snapshot_with_epoch_satisfies_activation_epoch() {
    // Simulate a Run 097 restore from a snapshot carrying canonical
    // epoch = 4: the restore path persisted meta:current_epoch=4.
    let dir = tmpdir("restored");
    let storage = open_test_storage(&dir);
    storage.put_current_epoch(4).expect("restore epoch");
    let h = devnet_signing_harness();
    let b = build_signed_devnet_bundle(&h, 1, Some(3));
    let epoch_opt = activation_epoch_source_from_storage(Some(&storage))
        .expect("ok")
        .as_option();
    assert_eq!(epoch_opt, Some(4));
    let ctx = ActivationContext {
        current_height: Some(0),
        current_epoch: epoch_opt,
    };
    let out = check_bundle_activation(&b, ctx).expect("epoch axis satisfied via restored epoch");
    assert_eq!(out.required_epoch, Some(3));
    assert_eq!(out.current_epoch, Some(4));
}