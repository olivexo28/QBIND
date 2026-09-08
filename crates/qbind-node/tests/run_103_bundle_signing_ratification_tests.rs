//! Run 103 — Minimal Bundle-Signing-Key Ratification Verifier
//! integration tests (release-binary-facing).
//!
//! These tests import the public `qbind-ledger` surface that the
//! production `qbind-node` binary links against. They exercise the
//! verifier through the *same* `verify_bundle_signing_key_ratification`
//! API that Run 104 will wire into trust-bundle acceptance paths.
//!
//! Scope mirrors `task/RUN_103_TASK.txt` "Required tests" sections A–D
//! and the Run 103 boundary cases:
//!
//!   * A. Schema / preimage determinism and field sensitivity.
//!   * B. Authority-root lookup, transport-root separation.
//!   * C. PQC (ML-DSA-44) signature verification.
//!   * D. Bundle-signing-key identity binding.
//!   * E. Authority-key material boundary (genesis carries only a 64-hex
//!        fingerprint → fail closed with the documented partial reason).

use qbind_ledger::bundle_signing_ratification::test_helpers::build_signed_ratification;
use qbind_ledger::{
    canonical_ratification_digest, canonical_ratification_preimage, classify_authority_root_kind,
    compute_canonical_genesis_hash, pqc_public_key_fingerprint,
    verify_bundle_signing_key_ratification, BundleSigningRatification, GenesisAllocation,
    GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisAuthorityRootKind, GenesisConfig,
    GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    RatificationEnvironment, RatificationFailure, RatificationVerifierInputs,
    BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1, BUNDLE_SIGNING_RATIFICATION_VERSION_V1,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};

use qbind_crypto::MlDsa44Backend;

// ---------- helpers ----------

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

fn make_mainnet_genesis(chain_id: &str, authority_pk_hex: &str) -> GenesisConfig {
    let mut cfg = GenesisConfig::new(
        chain_id,
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
    cfg.authority = Some(GenesisAuthorityConfig::new(vec![
        GenesisAuthorityRoot::new(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            authority_pk_hex,
            "foundation-bundle-signing-1",
        ),
    ]));
    cfg
}

fn run<'a>(
    r: &'a BundleSigningRatification,
    auth: &'a GenesisAuthorityConfig,
    chain: &'a str,
    env: NetworkEnvironmentPolicy,
    gh: &'a [u8; 32],
) -> Result<qbind_ledger::RatifiedBundleSigningKey, RatificationFailure> {
    verify_bundle_signing_key_ratification(RatificationVerifierInputs {
        ratification: r,
        authority: auth,
        expected_chain_id: chain,
        expected_environment: env,
        expected_genesis_hash: gh,
    })
}

// ---------- Scenario 1 — valid ratification accepted ----------

#[test]
fn run_103_scenario_1_valid_ratification_accepted() {
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let auth_pk_hex = hex_of(&auth_pk);
    let cfg = make_mainnet_genesis("qbind-mainnet-v0", &auth_pk_hex);
    let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let r = build_signed_ratification(
        "qbind-mainnet-v0",
        RatificationEnvironment::Mainnet,
        gh,
        &auth_pk_hex,
        &auth_sk,
        &bsk_pk,
    );

    // Preimage must start with the domain separator.
    let preimage = canonical_ratification_preimage(&r);
    assert!(preimage.starts_with(BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1));
    // Digest is deterministic.
    assert_eq!(
        canonical_ratification_digest(&r),
        canonical_ratification_digest(&r)
    );
    // Version is v1.
    assert_eq!(r.version, BUNDLE_SIGNING_RATIFICATION_VERSION_V1);

    let auth = cfg.authority.as_ref().unwrap();
    let ratified = run(
        &r,
        auth,
        "qbind-mainnet-v0",
        NetworkEnvironmentPolicy::Mainnet,
        &gh,
    )
    .expect("Run 103 Scenario 1: valid ratification must be accepted");
    assert_eq!(ratified.public_key, bsk_pk.to_vec());
    assert_eq!(ratified.fingerprint, pqc_public_key_fingerprint(&bsk_pk));
    assert_eq!(
        ratified.signature_suite_id,
        GENESIS_AUTHORITY_SUITE_ML_DSA_44
    );
    assert_eq!(ratified.authority_root_fingerprint, auth_pk_hex);
}

// ---------- Scenario 2 — wrong chain rejected ----------

#[test]
fn run_103_scenario_2_wrong_chain_rejected() {
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let auth_pk_hex = hex_of(&auth_pk);
    let cfg = make_mainnet_genesis("qbind-mainnet-v0", &auth_pk_hex);
    let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    // Object signed for a *different* chain.
    let r = build_signed_ratification(
        "qbind-testnet-beta",
        RatificationEnvironment::Mainnet,
        gh,
        &auth_pk_hex,
        &auth_sk,
        &bsk_pk,
    );
    let auth = cfg.authority.as_ref().unwrap();
    let err = run(
        &r,
        auth,
        "qbind-mainnet-v0",
        NetworkEnvironmentPolicy::Mainnet,
        &gh,
    )
    .unwrap_err();
    assert!(matches!(err, RatificationFailure::ChainMismatch { .. }));
}

// ---------- Scenario 3 — wrong environment rejected ----------

#[test]
fn run_103_scenario_3_wrong_environment_rejected() {
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let auth_pk_hex = hex_of(&auth_pk);
    let cfg = make_mainnet_genesis("qbind-mainnet-v0", &auth_pk_hex);
    let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let r = build_signed_ratification(
        "qbind-mainnet-v0",
        RatificationEnvironment::Testnet,
        gh,
        &auth_pk_hex,
        &auth_sk,
        &bsk_pk,
    );
    let auth = cfg.authority.as_ref().unwrap();
    let err = run(
        &r,
        auth,
        "qbind-mainnet-v0",
        NetworkEnvironmentPolicy::Mainnet,
        &gh,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        RatificationFailure::EnvironmentMismatch { .. }
    ));
}

// ---------- Scenario 4 — unknown authority root rejected ----------

#[test]
fn run_103_scenario_4_unknown_authority_root_rejected() {
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (other_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    // Genesis carries `other_pk`, ratification claims `auth_pk`.
    let cfg = make_mainnet_genesis("qbind-mainnet-v0", &hex_of(&other_pk));
    let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let r = build_signed_ratification(
        "qbind-mainnet-v0",
        RatificationEnvironment::Mainnet,
        gh,
        &hex_of(&auth_pk),
        &auth_sk,
        &bsk_pk,
    );
    let auth = cfg.authority.as_ref().unwrap();
    let err = run(
        &r,
        auth,
        "qbind-mainnet-v0",
        NetworkEnvironmentPolicy::Mainnet,
        &gh,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        RatificationFailure::UnknownAuthorityRoot { .. }
    ));
}

// ---------- Scenario 5 — transport root rejected ----------

#[test]
fn run_103_scenario_5_transport_root_rejected() {
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (other_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    // Bundle-signing set: only `other_pk`. Transport set: `auth_pk`.
    let mut cfg = make_mainnet_genesis("qbind-mainnet-v0", &hex_of(&other_pk));
    cfg.authority.as_mut().unwrap().pqc_transport_roots = vec![GenesisAuthorityRoot::new(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        hex_of(&auth_pk),
        "foundation-transport-1",
    )];
    let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let r = build_signed_ratification(
        "qbind-mainnet-v0",
        RatificationEnvironment::Mainnet,
        gh,
        &hex_of(&auth_pk),
        &auth_sk,
        &bsk_pk,
    );

    let auth = cfg.authority.as_ref().unwrap();

    // Sanity: classifier correctly distinguishes the two sets.
    assert_eq!(
        classify_authority_root_kind(auth, &hex_of(&auth_pk), GENESIS_AUTHORITY_SUITE_ML_DSA_44),
        Some(GenesisAuthorityRootKind::Transport)
    );
    assert_eq!(
        classify_authority_root_kind(auth, &hex_of(&other_pk), GENESIS_AUTHORITY_SUITE_ML_DSA_44),
        Some(GenesisAuthorityRootKind::BundleSigning)
    );

    let err = run(
        &r,
        auth,
        "qbind-mainnet-v0",
        NetworkEnvironmentPolicy::Mainnet,
        &gh,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        RatificationFailure::TransportRootNotAllowed { .. }
    ));
}

// ---------- Scenario 6 — bad signature rejected ----------

#[test]
fn run_103_scenario_6_bad_signature_rejected() {
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let auth_pk_hex = hex_of(&auth_pk);
    let cfg = make_mainnet_genesis("qbind-mainnet-v0", &auth_pk_hex);
    let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let mut r = build_signed_ratification(
        "qbind-mainnet-v0",
        RatificationEnvironment::Mainnet,
        gh,
        &auth_pk_hex,
        &auth_sk,
        &bsk_pk,
    );
    // Flip a byte deep inside the signature.
    let last = r.signature.len() - 1;
    r.signature[last] ^= 0xAA;
    let auth = cfg.authority.as_ref().unwrap();
    let err = run(
        &r,
        auth,
        "qbind-mainnet-v0",
        NetworkEnvironmentPolicy::Mainnet,
        &gh,
    )
    .unwrap_err();
    assert!(matches!(err, RatificationFailure::BadSignature));
}

// ---------- Scenario 7 — authority key material unavailable (partial boundary) ----------

#[test]
fn run_103_scenario_7_authority_key_material_unavailable() {
    // Genesis stores ONLY a 64-hex SHA3 fingerprint of the authority key,
    // not the full ML-DSA-44 PK bytes. The Run 103 verifier must fail
    // closed with the documented `AuthorityKeyMaterialUnavailable`
    // boundary — it must NOT silently accept the ratification, and must
    // NOT fake signature verification.
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let short_fp = pqc_public_key_fingerprint(&auth_pk);
    assert_eq!(short_fp.len(), 64);
    let cfg = make_mainnet_genesis("qbind-mainnet-v0", &short_fp);
    let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let r = build_signed_ratification(
        "qbind-mainnet-v0",
        RatificationEnvironment::Mainnet,
        gh,
        &short_fp,
        &auth_sk,
        &bsk_pk,
    );
    let auth = cfg.authority.as_ref().unwrap();
    let err = run(
        &r,
        auth,
        "qbind-mainnet-v0",
        NetworkEnvironmentPolicy::Mainnet,
        &gh,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        RatificationFailure::AuthorityKeyMaterialUnavailable { .. }
    ));
}

// ---------- Scenario 8 — wrong genesis hash rejected (Run 101/102 binding) ----------

#[test]
fn run_103_scenario_8_wrong_genesis_hash_rejected() {
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let auth_pk_hex = hex_of(&auth_pk);
    let cfg = make_mainnet_genesis("qbind-mainnet-v0", &auth_pk_hex);
    let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let r = build_signed_ratification(
        "qbind-mainnet-v0",
        RatificationEnvironment::Mainnet,
        gh,
        &auth_pk_hex,
        &auth_sk,
        &bsk_pk,
    );
    // Verifier is told the runtime believes the canonical hash is
    // something else (e.g. operator forgot to update --expected hash
    // after a genesis amendment). The ratification was signed for `gh`
    // → mismatch → fail closed.
    let mut wrong = gh;
    wrong[31] ^= 0xFF;
    let auth = cfg.authority.as_ref().unwrap();
    let err = run(
        &r,
        auth,
        "qbind-mainnet-v0",
        NetworkEnvironmentPolicy::Mainnet,
        &wrong,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        RatificationFailure::GenesisHashMismatch { .. }
    ));
}
