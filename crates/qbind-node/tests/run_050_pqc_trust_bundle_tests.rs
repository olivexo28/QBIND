//! Run 050 (C4 piece: PQC transport trust-anchor lifecycle —
//! foundation layer): integration tests for the trust bundle
//! load + validate + merge surface as it appears to operators.
//!
//! These tests do NOT spawn the `qbind-node` binary; they exercise
//! the public `qbind_node::pqc_trust_bundle` API end-to-end (parse
//! from JSON bytes, validate, produce active-root list, surface
//! revoked-root set, and confirm the resulting `PqcTrustedRoot`s
//! satisfy `PqcStaticRootConfig::lookup_root_pk` so the live
//! transport stack picks them up unchanged).
//!
//! Real-binary smoke evidence (positive two-node trust-bundle
//! handshake; negative wrong-env / revoked / expired-bundle smokes)
//! is recorded in
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_050.md`.

use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::{
    PqcRootMode, PqcStaticRootConfig, PQC_TRANSPORT_SUITE_ML_DSA_44,
};
use qbind_node::pqc_trust_bundle::{
    build_helper_bundle, HelperBundleMode, TrustBundle, TrustBundleEnvironment, TrustBundleError,
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

/// Build a PqcStaticRootConfig by merging the bundle's active roots
/// into an (initially empty) trust set, mirroring the main.rs wiring.
fn config_from_loaded_bundle(
    loaded: &qbind_node::pqc_trust_bundle::LoadedTrustBundle,
) -> PqcStaticRootConfig {
    PqcStaticRootConfig {
        mode: PqcRootMode::PqcStaticRoot,
        trusted_roots: loaded.active_roots.clone(),
        leaf_credentials: None,
        peer_leaf_certs: Vec::new(),
    }
}

#[test]
fn devnet_valid_unsigned_bundle_round_trips_into_pqc_static_root_config() {
    let (id, pk) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 100);
    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded =
        TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 200).expect("loads");
    assert_eq!(loaded.active_root_count(), 1);
    assert_eq!(loaded.revoked_root_count(), 0);
    assert_eq!(loaded.environment(), TrustBundleEnvironment::Devnet);

    let config = config_from_loaded_bundle(&loaded);
    // The exact same id bytes used by the on-wire NetworkDelegationCert
    // resolver lookup should now resolve to a configured trusted root.
    assert_eq!(config.trusted_roots.len(), 1);
    let id_bytes = config.trusted_roots[0].root_key_id;
    let resolved = config
        .lookup_root_pk(&id_bytes)
        .expect("trusted root must be resolvable from bundle-derived config");
    assert_eq!(resolved.suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44);
    assert_eq!(
        resolved.root_pk.len(),
        qbind_crypto::ML_DSA_44_PUBLIC_KEY_SIZE
    );
}

#[test]
fn wrong_environment_bundle_is_rejected_fail_closed() {
    let (id, pk) = fresh_root_pair();
    // Helper produces a testnet bundle when given WrongEnvironment;
    // loader is told the runtime is DevNet -> mismatch.
    let bundle = build_helper_bundle(HelperBundleMode::WrongEnvironment, &id, &pk, 0);
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 100).unwrap_err();
    match err {
        TrustBundleError::WrongEnvironment { expected, found } => {
            assert_eq!(expected, TrustBundleEnvironment::Devnet);
            assert_eq!(found, TrustBundleEnvironment::Testnet);
        }
        other => panic!("expected WrongEnvironment, got {:?}", other),
    }
}

#[test]
fn chain_id_mismatch_bundle_is_rejected_fail_closed() {
    let (id, pk) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
    bundle.chain_id = Some("chain_51424e4454535400".to_string());
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 100).unwrap_err();
    match err {
        TrustBundleError::WrongChainId { expected, found } => {
            assert_eq!(expected, qbind_types::QBIND_DEVNET_CHAIN_ID);
            assert_eq!(found, qbind_types::QBIND_TESTNET_CHAIN_ID);
        }
        other => panic!("expected WrongChainId, got {:?}", other),
    }
}

#[test]
fn revoked_root_is_excluded_from_resolved_trust_set() {
    let (id, pk) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::RootRevocationListed, &id, &pk, 0);
    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded =
        TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 100).expect("loads");
    assert_eq!(loaded.active_root_count(), 0);
    assert_eq!(loaded.revoked_root_count(), 1);

    let config = config_from_loaded_bundle(&loaded);
    // The revoked root MUST NOT be resolvable through the same
    // `lookup_root_pk` path the live transport uses.
    let mut id_bytes = [0u8; 32];
    for (i, chunk) in id.as_bytes().chunks(2).enumerate() {
        let hi = match chunk[0] {
            b'0'..=b'9' => chunk[0] - b'0',
            b'a'..=b'f' => 10 + chunk[0] - b'a',
            _ => panic!("bad hex"),
        };
        let lo = match chunk[1] {
            b'0'..=b'9' => chunk[1] - b'0',
            b'a'..=b'f' => 10 + chunk[1] - b'a',
            _ => panic!("bad hex"),
        };
        id_bytes[i] = (hi << 4) | lo;
    }
    assert!(
        config.lookup_root_pk(&id_bytes).is_none(),
        "revoked root MUST NOT be resolvable through PqcStaticRootConfig::lookup_root_pk"
    );
    assert!(loaded.is_root_revoked(&id_bytes));
}

#[test]
fn revoked_status_root_is_excluded_even_without_revocation_list() {
    let (id, pk) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::RootStatusRevoked, &id, &pk, 0);
    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded =
        TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 100).expect("loads");
    assert_eq!(loaded.active_root_count(), 0);
    // Status-revoked does NOT populate the explicit revocation list;
    // the defense-in-depth pathway is the explicit `revocations`
    // section. Documented in evidence.
    assert_eq!(loaded.revoked_root_count(), 0);
    let config = config_from_loaded_bundle(&loaded);
    assert!(config.trusted_roots.is_empty());
}

#[test]
fn expired_bundle_is_rejected_fail_closed() {
    let (id, pk) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::ExpiredBundle, &id, &pk, 0);
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 100).unwrap_err();
    assert!(matches!(err, TrustBundleError::BundleExpired));
}

#[test]
fn expired_root_is_rejected_fail_closed() {
    let (id, pk) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::ExpiredRoot, &id, &pk, 0);
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 100).unwrap_err();
    assert!(matches!(err, TrustBundleError::RootExpired(_)));
}

#[test]
fn duplicate_root_id_is_rejected_fail_closed() {
    let (id, pk) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::DuplicateRoot, &id, &pk, 0);
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 100).unwrap_err();
    assert!(matches!(err, TrustBundleError::DuplicateRootId(_)));
}

#[test]
fn unsupported_suite_is_rejected_fail_closed() {
    let (id, pk) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::UnsupportedSuite, &id, &pk, 0);
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 100).unwrap_err();
    match err {
        TrustBundleError::UnsupportedSuite { suite_id, .. } => assert_eq!(suite_id, 99),
        other => panic!("expected UnsupportedSuite, got {:?}", other),
    }
}

#[test]
fn malformed_bundle_bytes_is_rejected_fail_closed() {
    let err =
        TrustBundle::load_from_bytes(b"{garbage}", NetworkEnvironment::Devnet, 100).unwrap_err();
    assert!(matches!(err, TrustBundleError::Malformed(_)));
}

#[test]
fn testnet_runtime_refuses_unsigned_bundle_fail_closed() {
    let (id, pk) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
    bundle.environment = TrustBundleEnvironment::Testnet;
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes(&json, NetworkEnvironment::Testnet, 100).unwrap_err();
    match err {
        TrustBundleError::UnsignedBundleNotAllowed(env) => {
            assert_eq!(env, TrustBundleEnvironment::Testnet)
        }
        other => panic!(
            "expected UnsignedBundleNotAllowed(Testnet), got {:?}",
            other
        ),
    }
}

#[test]
fn mainnet_runtime_refuses_unsigned_bundle_fail_closed() {
    let (id, pk) = fresh_root_pair();
    let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
    bundle.environment = TrustBundleEnvironment::Mainnet;
    let json = serde_json::to_vec(&bundle).unwrap();
    let err = TrustBundle::load_from_bytes(&json, NetworkEnvironment::Mainnet, 100).unwrap_err();
    match err {
        TrustBundleError::UnsignedBundleNotAllowed(env) => {
            assert_eq!(env, TrustBundleEnvironment::Mainnet)
        }
        other => panic!(
            "expected UnsignedBundleNotAllowed(Mainnet), got {:?}",
            other
        ),
    }
}

#[test]
fn canonical_fingerprint_is_deterministic_across_load_cycles() {
    let (id, pk) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 42);
    let json = serde_json::to_vec(&bundle).unwrap();
    let loaded_a =
        TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 100).expect("loads a");
    let loaded_b =
        TrustBundle::load_from_bytes(&json, NetworkEnvironment::Devnet, 200).expect("loads b");
    assert_eq!(loaded_a.fingerprint, loaded_b.fingerprint);
    assert_eq!(loaded_a.fingerprint_hex(), loaded_b.fingerprint_hex());
    assert_eq!(loaded_a.fingerprint_short().len(), 8);
}

#[test]
fn bundle_path_loader_round_trips_through_disk() {
    let (id, pk) = fresh_root_pair();
    let bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("trust-bundle.json");
    let json = serde_json::to_vec_pretty(&bundle).unwrap();
    std::fs::write(&path, &json).expect("write bundle");
    let loaded = TrustBundle::load_from_path(&path, NetworkEnvironment::Devnet, 100)
        .expect("load from disk");
    assert_eq!(loaded.active_root_count(), 1);
}
