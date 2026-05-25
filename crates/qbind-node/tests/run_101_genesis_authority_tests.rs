//! Run 101 — Genesis Authority Fields and Boot-Time Genesis Hash Binding
//! integration tests (release-binary-facing).
//!
//! Scope mirrors `task/RUN_101_TASK.txt` §"Required tests" sections A–D:
//!
//!   * A. Canonical genesis-hash sensitivity (chain_id, env, authority,
//!        validator set) — covered both in `qbind-ledger` unit tests and
//!        the harness reuse here.
//!   * B. Expected-hash verification per environment.
//!   * C. Authority validation (MainNet missing/empty/malformed/duplicate
//!        rejection; DevNet permissive).
//!   * D. Startup integration: MainNet boot-time refusal happens *before*
//!        any trust-bundle / network startup work, by running the boot
//!        verification helper directly (the helper is invoked from
//!        startup; refusing here proves the refusal point).
//!
//! These tests deliberately exercise the *types and helpers re-exported by
//! `qbind-ledger`* through the same path that `qbind-node` startup uses
//! (no parallel loader). They are release-binary-facing in the sense that
//! they import the public surface that the production `qbind-node` binary
//! links against.

use qbind_ledger::{
    compute_canonical_genesis_hash, verify_boot_time_genesis, BootGenesisVerificationError,
    GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot,
    GenesisAuthorityValidationError, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig,
    GenesisValidationError, GenesisValidator, NetworkEnvironmentPolicy,
    GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES, GENESIS_AUTHORITY_POLICY_VERSION_RUN_101,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};

/// Run 104: synthetic 1312-byte ML-DSA-44 public key filled with `seed`.
fn synthetic_ml_dsa_44_pk(seed: u8) -> Vec<u8> {
    vec![seed; GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES]
}

fn root(seed: u8, label: &str) -> GenesisAuthorityRoot {
    // Run 104: produce a fully-populated authority root with full
    // public-key material so MainNet test fixtures satisfy the new
    // key-material policy.
    GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &synthetic_ml_dsa_44_pk(seed),
        label,
    )
}

fn monetary() -> GenesisMonetaryConfig {
    GenesisMonetaryConfig::mainnet_default()
}

fn mainnet_genesis() -> GenesisConfig {
    let mut cfg = GenesisConfig::new(
        "qbind-mainnet-v0",
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            "0x1111111111111111111111111111111111111111",
            1_000_000u128,
        )],
        vec![GenesisValidator::new(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "pqc_key_validator_1",
            100_000u128,
        )],
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        monetary(),
    );
    let mut auth = GenesisAuthorityConfig::new(vec![root(0xab, "foundation-bundle-signer-1")]);
    auth.pqc_transport_roots = vec![root(0xcd, "foundation-transport-1")];
    cfg.authority = Some(auth);
    cfg
}

// ---------------------------------------------------------------------------
// Scenario 1 — DevNet legacy genesis (no authority, no expected hash) passes.
// ---------------------------------------------------------------------------

#[test]
fn run_101_scenario_1_devnet_legacy_path_remains_usable() {
    let mut cfg = mainnet_genesis();
    cfg.chain_id = "qbind-devnet-v0".to_string();
    cfg.authority = None;

    let v = verify_boot_time_genesis(NetworkEnvironmentPolicy::Devnet, &cfg, None)
        .expect("DevNet legacy path must remain explicitly allowed");
    assert_eq!(
        v.canonical_hash,
        compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Devnet)
    );
}

// ---------------------------------------------------------------------------
// Scenario 2 — MainNet missing expected hash rejects.
// ---------------------------------------------------------------------------

#[test]
fn run_101_scenario_2_mainnet_missing_expected_hash_rejects() {
    let cfg = mainnet_genesis();
    let err = verify_boot_time_genesis(NetworkEnvironmentPolicy::Mainnet, &cfg, None)
        .expect_err("MainNet without expected canonical genesis hash must fail closed");
    match err {
        BootGenesisVerificationError::ExpectedCanonicalHashMissing {
            env: NetworkEnvironmentPolicy::Mainnet,
        } => {}
        other => panic!("expected ExpectedCanonicalHashMissing, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Scenario 3 — MainNet hash mismatch rejects.
// ---------------------------------------------------------------------------

#[test]
fn run_101_scenario_3_mainnet_hash_mismatch_rejects() {
    let cfg = mainnet_genesis();
    let bogus = [0u8; 32];
    let err = verify_boot_time_genesis(NetworkEnvironmentPolicy::Mainnet, &cfg, Some(&bogus))
        .expect_err("MainNet expected-hash mismatch must fail closed");
    match err {
        BootGenesisVerificationError::CanonicalHashMismatch {
            env: NetworkEnvironmentPolicy::Mainnet,
            expected,
            actual,
        } => {
            assert_eq!(expected, bogus);
            assert_ne!(actual, bogus);
        }
        other => panic!("expected CanonicalHashMismatch, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Scenario 4 — MainNet correct hash but missing authority rejects (with a
// precise authority error, before any other downstream startup).
// ---------------------------------------------------------------------------

#[test]
fn run_101_scenario_4_mainnet_missing_authority_rejects() {
    let mut cfg = mainnet_genesis();
    cfg.authority = None;
    let h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let err = verify_boot_time_genesis(NetworkEnvironmentPolicy::Mainnet, &cfg, Some(&h))
        .expect_err("MainNet missing authority must fail closed even with a matching hash");
    match err {
        BootGenesisVerificationError::AuthorityValidationFailed(
            GenesisAuthorityValidationError::Missing {
                env: NetworkEnvironmentPolicy::Mainnet,
            },
        ) => {}
        other => panic!("expected AuthorityValidationFailed(Missing), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Scenario 5 — MainNet valid genesis + authority + matching hash passes.
// ---------------------------------------------------------------------------

#[test]
fn run_101_scenario_5_mainnet_valid_genesis_passes() {
    let cfg = mainnet_genesis();
    let h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let v = verify_boot_time_genesis(NetworkEnvironmentPolicy::Mainnet, &cfg, Some(&h))
        .expect("MainNet valid genesis + authority + matching hash must pass");
    assert_eq!(v.canonical_hash, h);
}

// ---------------------------------------------------------------------------
// Additional refusal coverage required by §Required tests / §C.
// ---------------------------------------------------------------------------

#[test]
fn run_101_mainnet_rejects_empty_authority_roots() {
    let mut cfg = mainnet_genesis();
    cfg.authority.as_mut().unwrap().bundle_signing_authority_roots = vec![];
    let err = cfg
        .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
        .unwrap_err();
    assert!(matches!(
        err,
        GenesisValidationError::AuthorityValidationFailed(
            GenesisAuthorityValidationError::EmptyBundleSigningRoots
        )
    ));
}

#[test]
fn run_101_mainnet_rejects_wrong_environment_chain_id() {
    let mut cfg = mainnet_genesis();
    cfg.chain_id = "qbind-devnet-v0".to_string();
    let h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
    let err = verify_boot_time_genesis(NetworkEnvironmentPolicy::Mainnet, &cfg, Some(&h))
        .expect_err("MainNet with non-mainnet chain_id must fail closed");
    assert!(matches!(
        err,
        BootGenesisVerificationError::ChainEnvironmentMismatch { .. }
    ));
}

#[test]
fn run_101_mainnet_rejects_duplicate_roots() {
    let mut cfg = mainnet_genesis();
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
    assert!(matches!(
        err,
        GenesisValidationError::AuthorityValidationFailed(
            GenesisAuthorityValidationError::DuplicateAuthorityRoot { .. }
        )
    ));
}

#[test]
fn run_101_mainnet_rejects_malformed_root() {
    let mut cfg = mainnet_genesis();
    cfg.authority.as_mut().unwrap().bundle_signing_authority_roots[0].key_fingerprint =
        "not-hex".into();
    let err = cfg
        .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
        .unwrap_err();
    assert!(matches!(
        err,
        GenesisValidationError::AuthorityValidationFailed(
            GenesisAuthorityValidationError::MalformedFingerprint { .. }
        )
    ));
}

#[test]
fn run_101_authority_policy_version_is_run_101() {
    let cfg = mainnet_genesis();
    assert_eq!(
        cfg.authority.unwrap().authority_policy_version,
        GENESIS_AUTHORITY_POLICY_VERSION_RUN_101
    );
}

// ---------------------------------------------------------------------------
// Canonical-hash sanity: equal inputs => equal hashes; same canonical genesis
// produces same hash even after a round-trip through serde_json.
// ---------------------------------------------------------------------------

#[test]
fn run_101_canonical_hash_stable_across_serde_json_roundtrip() {
    let cfg = mainnet_genesis();
    let h1 = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);

    let json = serde_json::to_string(&cfg).unwrap();
    let cfg_rt: GenesisConfig = serde_json::from_str(&json).unwrap();
    let h2 = compute_canonical_genesis_hash(&cfg_rt, NetworkEnvironmentPolicy::Mainnet);
    assert_eq!(h1, h2);
}