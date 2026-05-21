//! Run 104 — Genesis-Bound Authority Key Material Registry integration
//! tests (release-binary-facing).
//!
//! These tests exercise the public `qbind-ledger` surface that the
//! production `qbind-node` binary links against. They prove the
//! Run 104 contract:
//!
//!   * A genesis-bound bundle-signing authority root carries validated
//!     full ML-DSA-44 `public_key_hex`, hash-bound into the canonical
//!     genesis hash.
//!   * MainNet refuses fingerprint-only bundle-signing roots
//!     (`MissingPublicKeyMaterial`).
//!   * MainNet refuses malformed `public_key_hex` (wrong length, non-hex,
//!     or fingerprint mismatch with the declared `key_fingerprint`).
//!   * Two roots may not share the same `(suite_id, public_key_hex)`.
//!   * The Run 103 verifier accepts a ratification signed by the
//!     genesis-bound authority key when the root carries
//!     `public_key_hex` — no overloading of `key_fingerprint`.
//!   * Tampering with `public_key_hex` after genesis publication causes
//!     the Run 103 verifier to fail closed with
//!     `AuthorityKeyMaterialMalformed` (or a hash mismatch upstream).
//!
//! Scope mirrors `task/RUN_104_TASK.txt` "Required tests" sections A–F.

use qbind_ledger::bundle_signing_ratification::test_helpers::build_signed_ratification;
use qbind_ledger::{
    authority_public_key_fingerprint, compute_canonical_genesis_hash,
    verify_bundle_signing_key_ratification, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisAuthorityValidationError, GenesisConfig, GenesisCouncilConfig,
    GenesisMonetaryConfig, GenesisValidationError, GenesisValidator, NetworkEnvironmentPolicy,
    RatificationEnvironment, RatificationFailure, RatificationVerifierInputs,
    GENESIS_AUTHORITY_KEY_FINGERPRINT_HEX_LEN, GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES,
    GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_HEX_LEN, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
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

fn synthetic_ml_dsa_44_pk(seed: u8) -> Vec<u8> {
    vec![seed; GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES]
}

/// Build a Run 104 MainNet genesis whose bundle-signing authority root
/// carries the full ML-DSA-44 public key (and matching SHA3-256
/// fingerprint) for `auth_pk`.
fn mainnet_genesis_with_clean_root(chain_id: &str, auth_pk: &[u8]) -> GenesisConfig {
    let mut cfg = GenesisConfig::new(
        chain_id,
        1_738_000_000_000,
        vec![GenesisAllocation::new(format!("0x{}", "11".repeat(20)), 100)],
        vec![GenesisValidator::new(
            format!("0x{}", "22".repeat(20)),
            "ab".repeat(32),
            100,
        )],
        GenesisCouncilConfig::new(
            vec![
                format!("0x{}", "33".repeat(20)),
                format!("0x{}", "44".repeat(20)),
                format!("0x{}", "55".repeat(20)),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    );
    cfg.authority = Some(GenesisAuthorityConfig::new(vec![
        GenesisAuthorityRoot::with_public_key_bytes(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            auth_pk,
            "foundation-bundle-signer-1",
        ),
    ]));
    cfg
}

// ===========================================================================
// §A — Schema: `public_key_hex` round-trips, sha3 fingerprint derivation
// ===========================================================================

#[test]
fn run_104_a_public_key_hex_is_hash_bound() {
    let (auth_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let cfg_with = mainnet_genesis_with_clean_root("qbind-mainnet-v0", &auth_pk);
    // A second config with a different PK (and therefore different
    // fingerprint and different public_key_hex) hashes differently.
    let (auth_pk2, _) = MlDsa44Backend::generate_keypair().unwrap();
    let cfg_alt = mainnet_genesis_with_clean_root("qbind-mainnet-v0", &auth_pk2);
    let h1 = compute_canonical_genesis_hash(&cfg_with, NetworkEnvironmentPolicy::Mainnet);
    let h2 = compute_canonical_genesis_hash(&cfg_alt, NetworkEnvironmentPolicy::Mainnet);
    assert_ne!(h1, h2);
}

#[test]
fn run_104_a_authority_public_key_fingerprint_helper_is_canonical() {
    let pk = synthetic_ml_dsa_44_pk(0x11);
    let fp = authority_public_key_fingerprint(&pk);
    assert_eq!(fp.len(), GENESIS_AUTHORITY_KEY_FINGERPRINT_HEX_LEN);
    let root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &pk,
        "foundation-bundle-signer-1",
    );
    assert_eq!(root.key_fingerprint, fp);
    assert_eq!(
        root.public_key_hex.unwrap().len(),
        GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_HEX_LEN
    );
}

// ===========================================================================
// §B — MainNet refuses bundle-signing roots without full key material
// ===========================================================================

#[test]
fn run_104_b_mainnet_rejects_bundle_signing_root_missing_public_key_hex() {
    let mut cfg = mainnet_genesis_with_clean_root(
        "qbind-mainnet-v0",
        &synthetic_ml_dsa_44_pk(0xab),
    );
    cfg.authority
        .as_mut()
        .unwrap()
        .bundle_signing_authority_roots[0]
        .public_key_hex = None;
    let err = cfg
        .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
        .unwrap_err();
    assert!(
        matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::MissingPublicKeyMaterial { .. }
            )
        ),
        "got {:?}",
        err
    );
}

#[test]
fn run_104_b_mainnet_rejects_malformed_public_key_length() {
    let mut cfg = mainnet_genesis_with_clean_root(
        "qbind-mainnet-v0",
        &synthetic_ml_dsa_44_pk(0xab),
    );
    let pk = cfg
        .authority
        .as_mut()
        .unwrap()
        .bundle_signing_authority_roots[0]
        .public_key_hex
        .as_mut()
        .unwrap();
    pk.truncate(pk.len() - 2);
    let err = cfg
        .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
        .unwrap_err();
    assert!(
        matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::MalformedPublicKey { .. }
            )
        ),
        "got {:?}",
        err
    );
}

#[test]
fn run_104_b_mainnet_rejects_public_key_fingerprint_mismatch() {
    let mut cfg = mainnet_genesis_with_clean_root(
        "qbind-mainnet-v0",
        &synthetic_ml_dsa_44_pk(0xab),
    );
    // Replace public_key_hex with an unrelated PK while keeping the
    // declared `key_fingerprint`.
    let unrelated = hex_of(&synthetic_ml_dsa_44_pk(0xcd));
    cfg.authority
        .as_mut()
        .unwrap()
        .bundle_signing_authority_roots[0]
        .public_key_hex = Some(unrelated);
    let err = cfg
        .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
        .unwrap_err();
    assert!(
        matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::PublicKeyFingerprintMismatch { .. }
            )
        ),
        "got {:?}",
        err
    );
}

// ===========================================================================
// §C — Duplicate detection across roots
// ===========================================================================

#[test]
fn run_104_c_rejects_duplicate_root_pair() {
    let mut cfg = mainnet_genesis_with_clean_root(
        "qbind-mainnet-v0",
        &synthetic_ml_dsa_44_pk(0xab),
    );
    let dup = cfg
        .authority
        .as_ref()
        .unwrap()
        .bundle_signing_authority_roots[0]
        .clone();
    cfg.authority
        .as_mut()
        .unwrap()
        .bundle_signing_authority_roots
        .push(dup);
    let err = cfg
        .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
        .unwrap_err();
    assert!(
        matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::DuplicateAuthorityRoot { .. }
            )
        ),
        "got {:?}",
        err
    );
}

// ===========================================================================
// §D — Run 103 verifier accepts ratification signed by the genesis-bound key
// ===========================================================================

#[test]
fn run_104_d_verifier_accepts_signed_by_genesis_bound_key() {
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let cfg = mainnet_genesis_with_clean_root("qbind-mainnet-v0", &auth_pk);
    cfg.validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
        .expect("Run 104 clean-shape MainNet genesis must validate");
    let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let fp = authority_public_key_fingerprint(&auth_pk);
    let r = build_signed_ratification(
        "qbind-mainnet-v0",
        RatificationEnvironment::Mainnet,
        gh,
        &fp,
        &auth_sk,
        &bsk_pk,
    );
    let auth = cfg.authority.as_ref().unwrap();
    let ok = verify_bundle_signing_key_ratification(RatificationVerifierInputs {
        ratification: &r,
        authority: auth,
        expected_chain_id: "qbind-mainnet-v0",
        expected_environment: NetworkEnvironmentPolicy::Mainnet,
        expected_genesis_hash: &gh,
    })
    .expect("Run 104 ratification signed by genesis-bound authority key must verify");
    assert_eq!(ok.public_key, bsk_pk);
}

// ===========================================================================
// §E — Tamper detection: post-genesis mutation fails closed
// ===========================================================================

#[test]
fn run_104_e_tampered_public_key_hex_fails_closed_in_verifier() {
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (other_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let mut cfg = mainnet_genesis_with_clean_root("qbind-mainnet-v0", &auth_pk);
    let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let fp = authority_public_key_fingerprint(&auth_pk);
    let r = build_signed_ratification(
        "qbind-mainnet-v0",
        RatificationEnvironment::Mainnet,
        gh,
        &fp,
        &auth_sk,
        &bsk_pk,
    );
    // Post-publication tampering: substitute a different PK while
    // leaving the declared 64-hex fingerprint pointing at the original.
    cfg.authority
        .as_mut()
        .unwrap()
        .bundle_signing_authority_roots[0]
        .public_key_hex = Some(hex_of(&other_pk));
    let auth = cfg.authority.as_ref().unwrap();
    let err = verify_bundle_signing_key_ratification(RatificationVerifierInputs {
        ratification: &r,
        authority: auth,
        expected_chain_id: "qbind-mainnet-v0",
        expected_environment: NetworkEnvironmentPolicy::Mainnet,
        expected_genesis_hash: &gh,
    })
    .unwrap_err();
    assert!(
        matches!(err, RatificationFailure::AuthorityKeyMaterialMalformed { .. }),
        "tampered public_key_hex must fail closed, got {:?}",
        err
    );
}

// ===========================================================================
// §F — DevNet/TestNet preservation
// ===========================================================================

#[test]
fn run_104_f_devnet_remains_permissive_for_legacy_short_fingerprint_roots() {
    let mut cfg = GenesisConfig::new(
        "qbind-devnet-v0",
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            format!("0x{}", "11".repeat(20)),
            100,
        )],
        vec![GenesisValidator::new(
            format!("0x{}", "22".repeat(20)),
            "ab".repeat(32),
            100,
        )],
        GenesisCouncilConfig::new(
            vec![
                format!("0x{}", "33".repeat(20)),
                format!("0x{}", "44".repeat(20)),
                format!("0x{}", "55".repeat(20)),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    );
    // DevNet legacy: only short fingerprint, no public_key_hex.
    let short_fp = format!("{:02x}", 0xab_u8).repeat(32);
    cfg.authority = Some(GenesisAuthorityConfig::new(vec![GenesisAuthorityRoot::new(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        short_fp,
        "devnet-bundle-signer-1",
    )]));
    cfg.validate_for_environment(NetworkEnvironmentPolicy::Devnet)
        .expect("DevNet legacy fingerprint-only authority must remain valid");
}