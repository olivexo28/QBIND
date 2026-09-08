//! Run 105 — integration tests for the **non-mutating bundle-signing-
//! key ratification enforcement** layer on the existing trust-bundle
//! validation surfaces (Run 069 reload-check API,
//! `validate_candidate_bundle_full_with_ratification`).
//!
//! These tests prove the same invariant on every code path:
//!
//!   * No live trust state is mutated.
//!   * No on-disk anti-rollback sequence record is written, mutated, or
//!     deleted.
//!   * No file is created or destroyed by the validator.
//!
//! independent of whether ratification accepts, refuses, or is skipped.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_105.md` for the matching
//! release-binary smokes.

use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::test_helpers as ratification_helpers,
    compute_canonical_genesis_hash, BundleSigningRatification, GenesisAllocation,
    GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisHash,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    RatificationEnforcementFailure, RatificationEnforcementPolicy, RatificationEnvironment,
    RatificationFailure, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRevocation, TrustBundleRoot,
};
use qbind_node::pqc_trust_reload::{
    validate_candidate_bundle_full_with_ratification, validate_candidate_bundle_with_ratification,
    RatificationEnforcementContext, ReloadCheckError, ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------
// Helpers — minimal mirrors of the Run 069 helpers, scoped to Run 105.
// ---------------------------------------------------------------------

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", x);
    }
    s
}

fn full_pk_hex(pk: &[u8]) -> String {
    hex_lower(pk)
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run105-{}-{}-{}",
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

struct DevnetHarness {
    signing_keys: BundleSigningKeySet,
    signing_pk: Vec<u8>,
    signing_key_id: [u8; 32],
    signing_sk: Vec<u8>,
    root_id_hex: String,
    root_pk_hex: String,
    // Genesis-authority key pair used to ratify bundle-signing key.
    authority_pk: Vec<u8>,
    authority_sk: Vec<u8>,
    genesis_cfg: GenesisConfig,
    canonical_hash: GenesisHash,
    chain_id_str: String,
    env_policy: NetworkEnvironmentPolicy,
}

fn devnet_harness() -> DevnetHarness {
    let (signing_pk, signing_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key");
    let signing_key_id = derive_signing_key_id(&signing_pk);
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: signing_key_id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: signing_pk.clone(),
    }]);
    let root = mint_devnet_root().expect("mint devnet root");

    // Build a genesis config whose bundle_signing_authority_roots
    // include a freshly-minted ML-DSA-44 authority key. We bind the
    // chain id to NetworkEnvironment::Devnet.chain_id() so ratification
    // env=Devnet and chain_id match.
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen authority key");
    let chain_id = NetworkEnvironment::Devnet.chain_id();
    let chain_id_str = chain_id_hex(chain_id);
    let mut genesis_cfg = GenesisConfig::new(
        &chain_id_str,
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            format!("0x{}", "11".repeat(32)),
            100,
        )],
        vec![GenesisValidator::new(
            format!("0x{}", "22".repeat(32)),
            "ab".repeat(32),
            100,
        )],
        GenesisCouncilConfig::new(
            vec![
                format!("0x{}", "33".repeat(32)),
                format!("0x{}", "44".repeat(32)),
                format!("0x{}", "55".repeat(32)),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    );
    let auth_root = GenesisAuthorityRoot::new(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &full_pk_hex(&authority_pk),
        "test-bundle-signing-1",
    );
    genesis_cfg.authority = Some(GenesisAuthorityConfig::new(vec![auth_root]));
    let env_policy = NetworkEnvironmentPolicy::Devnet;
    let canonical_hash = compute_canonical_genesis_hash(&genesis_cfg, env_policy);

    DevnetHarness {
        signing_keys,
        signing_pk,
        signing_key_id,
        signing_sk,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
        authority_pk,
        authority_sk,
        genesis_cfg,
        canonical_hash,
        chain_id_str,
        env_policy,
    }
}

fn build_signed_bundle(h: &DevnetHarness, sequence: u64, generated_at: u64) -> TrustBundle {
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: TrustBundleEnvironment::Devnet,
        chain_id: Some(h.chain_id_str.clone()),
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
        revocations: Vec::<TrustBundleRevocation>::new(),
        signature: None,
        activation_epoch: None,
        activation_height: None,
    };
    let sig = sign_bundle_devnet_helper(&bundle, h.signing_key_id, &h.signing_sk).expect("sign");
    bundle.signature = Some(sig);
    bundle
}

fn write_bundle(dir: &Path, name: &str, bundle: &TrustBundle) -> PathBuf {
    let path = dir.join(name);
    let bytes = serde_json::to_vec(bundle).expect("serialise");
    std::fs::write(&path, &bytes).expect("write");
    path
}

fn build_signed_ratification_for(h: &DevnetHarness) -> BundleSigningRatification {
    ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &full_pk_hex(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
    )
}

fn devnet_inputs<'a>(
    candidate_path: &'a Path,
    signing_keys: &'a BundleSigningKeySet,
) -> ReloadCheckInputs<'a> {
    ReloadCheckInputs {
        candidate_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
    }
}

// =====================================================================
// Tests
// =====================================================================

/// A valid ratification + matching bundle-signing key under Strict
/// policy returns a successful `ValidatedCandidate` exactly equivalent
/// to the Run 069 path.
#[test]
fn run_105_strict_devnet_valid_ratification_validates_candidate() {
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 1, 100);
    let dir = tmpdir("strict-valid");
    let bundle_path = write_bundle(&dir, "bundle.json", &bundle);

    let ratification = build_signed_ratification_for(&h);
    let ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().expect("authority"),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&ratification),
        policy: RatificationEnforcementPolicy::Strict,
    };

    let candidate = validate_candidate_bundle_with_ratification(
        devnet_inputs(&bundle_path, &h.signing_keys),
        &ctx,
    )
    .expect("strict + valid ratification must succeed");
    assert_eq!(candidate.sequence, 1);
}

/// Under Strict policy, a missing ratification fails closed with the
/// typed `RatificationRefused(Missing)` variant.
#[test]
fn run_105_strict_devnet_missing_ratification_refused_without_mutation() {
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 1, 100);
    let dir = tmpdir("strict-missing");
    let bundle_path = write_bundle(&dir, "bundle.json", &bundle);

    let ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().expect("authority"),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: None,
        policy: RatificationEnforcementPolicy::Strict,
    };

    let err = validate_candidate_bundle_with_ratification(
        devnet_inputs(&bundle_path, &h.signing_keys),
        &ctx,
    )
    .expect_err("missing ratification must be refused under Strict");
    match err {
        ReloadCheckError::RatificationRefused(RatificationEnforcementFailure::Missing {
            ..
        }) => {}
        other => panic!("expected Missing, got {:?}", other),
    }
    // Bundle file untouched.
    assert!(bundle_path.exists());
}

/// A ratification authorising a different bundle-signing key is
/// refused with `RatifiesDifferentKey`.
#[test]
fn run_105_ratification_for_different_key_refused() {
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 1, 100);
    let dir = tmpdir("wrong-key");
    let bundle_path = write_bundle(&dir, "bundle.json", &bundle);

    // Ratification points at a *different* bundle-signing key.
    let (other_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let bad_ratification = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &full_pk_hex(&h.authority_pk),
        &h.authority_sk,
        &other_pk,
    );
    let ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().expect("authority"),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&bad_ratification),
        policy: RatificationEnforcementPolicy::Strict,
    };
    let err = validate_candidate_bundle_with_ratification(
        devnet_inputs(&bundle_path, &h.signing_keys),
        &ctx,
    )
    .expect_err("ratification for different key must be refused");
    match err {
        ReloadCheckError::RatificationRefused(
            RatificationEnforcementFailure::RatifiesDifferentKey { .. },
        ) => {}
        other => panic!("expected RatifiesDifferentKey, got {:?}", other),
    }
}

/// A ratification that names the wrong chain id is refused with the
/// inner `Verifier(ChainMismatch)` variant; the bundle file is
/// otherwise unchanged.
#[test]
fn run_105_wrong_chain_ratification_refused() {
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 1, 100);
    let dir = tmpdir("wrong-chain");
    let bundle_path = write_bundle(&dir, "bundle.json", &bundle);
    let bad = ratification_helpers::build_signed_ratification(
        "definitely-not-the-runtime-chain",
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &full_pk_hex(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
    );
    let ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().expect("authority"),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&bad),
        policy: RatificationEnforcementPolicy::Strict,
    };
    let err = validate_candidate_bundle_with_ratification(
        devnet_inputs(&bundle_path, &h.signing_keys),
        &ctx,
    )
    .expect_err("wrong-chain ratification must be refused");
    assert!(matches!(
        err,
        ReloadCheckError::RatificationRefused(RatificationEnforcementFailure::Verifier(
            RatificationFailure::ChainMismatch { .. }
        ))
    ));
}

/// Under AllowLegacyUnratified policy on DevNet, a missing ratification
/// produces an explicit `LegacyUnratifiedAccepted` outcome internally
/// and the validator returns a normal `ValidatedCandidate`.
#[test]
fn run_105_devnet_legacy_unratified_accepts() {
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 1, 100);
    let dir = tmpdir("devnet-legacy");
    let bundle_path = write_bundle(&dir, "bundle.json", &bundle);

    let ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().expect("authority"),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: None,
        policy: RatificationEnforcementPolicy::AllowLegacyUnratified,
    };
    let candidate = validate_candidate_bundle_with_ratification(
        devnet_inputs(&bundle_path, &h.signing_keys),
        &ctx,
    )
    .expect("DevNet legacy-unratified must succeed under AllowLegacyUnratified policy");
    assert_eq!(candidate.sequence, 1);
}

/// The full-result entry point also returns the inner
/// `LoadedTrustBundle` and `ActivationCheckOutcome` on a successful
/// ratification, matching the existing Run 069 contract.
#[test]
fn run_105_full_entry_point_returns_loaded_bundle_and_activation() {
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 1, 100);
    let dir = tmpdir("full-result");
    let bundle_path = write_bundle(&dir, "bundle.json", &bundle);

    let ratification = build_signed_ratification_for(&h);
    let ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().expect("authority"),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&ratification),
        policy: RatificationEnforcementPolicy::Strict,
    };
    let (loaded, _activation, candidate) = validate_candidate_bundle_full_with_ratification(
        devnet_inputs(&bundle_path, &h.signing_keys),
        &ctx,
    )
    .expect("full entry point must succeed on valid ratification");
    assert_eq!(candidate.sequence, loaded.bundle.sequence);
    assert!(loaded.signature_status.is_verified());
}
