//! Run 422 D7-C3B — dormant, **non-authorizing** correspondence between a
//! pin-validated genesis identity and the standard network mapping.
//!
//! These tests use the **real** genesis loader/validator (single owned read via
//! `ExpectedGenesisIdentity::load_pinned`), canonical hashing, valid ML-DSA-44
//! consensus-key fixtures, and the existing C3A resolver
//! (`resolve_network_wire_alias`, reached only through
//! `ExpectedGenesisIdentity::check_network_correspondence`). No authorization,
//! signing, storage, or engine state is constructed.
//!
//! Behavioural matrix (task §5):
//!   A. Matching controls (DevNet/TestNet/MainNet) → exact C3A alias, attached
//!      to the original validated genesis hash + authority commitment.
//!   B. Environment provenance mismatch — full 3×3 matrix, all six mismatched
//!      pairs reject even with a correct runtime ID for the newly selected env.
//!   C. Full-width runtime validation — other standard IDs and invalid values
//!      (incl. a different high word with the correct low 32 bits) reject via
//!      C3A, without truncation/fallback.
//!   D. Pin and snapshot preservation.
//!   E. Canonical-hash pin isolation. One fixture that validates under **both**
//!      DevNet and TestNet (required TestNet label + authority config): its
//!      DevNet and TestNet canonical pins differ; each pin loads only under its
//!      own environment; and supplying the frozen DevNet pin under TestNet fails
//!      through the typed `CanonicalHashMismatch` (not a label-policy rejection),
//!      both via `verify_boot_time_genesis` directly and via `load_pinned`.
//!   F. No invented label registry (ordinary label; two distinct genesis files
//!      each correspond under the same env when separately pinned).
//!   G. Bounded diagnostics for both typed mismatch errors.

use std::path::{Path, PathBuf};

use tempfile::TempDir;

use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::{
    compute_canonical_genesis_hash, verify_boot_time_genesis, BootGenesisVerificationError,
    GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig,
    GenesisCouncilConfig, GenesisHash, GenesisMonetaryConfig, GenesisValidator,
    NetworkEnvironmentPolicy, GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::genesis_authority_record_correspondence::{
    ExpectedGenesisIdentity, ExpectedGenesisIdentityError, GenesisNetworkCorrespondenceError,
};
use qbind_types::{
    ChainId, NetworkEnvironment, QBIND_DEVNET_CHAIN_ID, QBIND_DEVNET_WIRE_ALIAS,
    QBIND_MAINNET_CHAIN_ID, QBIND_MAINNET_WIRE_ALIAS, QBIND_TESTNET_CHAIN_ID,
    QBIND_TESTNET_WIRE_ALIAS,
};

// ============================================================================
// Fixtures — real genesis + valid ML-DSA-44 keys, per standard environment
// ============================================================================

/// Fresh ML-DSA-44 public-key hex for a genesis validator entry.
fn fresh_key_hex() -> String {
    let (pk, _sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    pk.iter().map(|b| format!("{:02x}", b)).collect()
}

fn validator(addr_seed: u8) -> GenesisValidator {
    GenesisValidator::new(
        format!("{:02x}", addr_seed).repeat(32),
        fresh_key_hex(),
        100_000u128,
    )
}

/// A fully-populated authority root so TestNet/MainNet fixtures satisfy the
/// Run 104 key-material policy.
fn root(seed: u8, label: &str) -> GenesisAuthorityRoot {
    GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &vec![seed; GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES],
        label,
    )
}

/// The runtime environment mapped from a policy (for `check_network_correspondence`).
fn env_of(policy: NetworkEnvironmentPolicy) -> NetworkEnvironment {
    match policy {
        NetworkEnvironmentPolicy::Devnet => NetworkEnvironment::Devnet,
        NetworkEnvironmentPolicy::Testnet => NetworkEnvironment::Testnet,
        NetworkEnvironmentPolicy::Mainnet => NetworkEnvironment::Mainnet,
    }
}

/// An ordinary, human-readable genesis `chain_id` label per environment. This is
/// deliberately NOT the synthetic runtime-identity fixture string: the numeric
/// runtime ChainId is never parsed out of it (task §5.F). For MainNet/TestNet it
/// carries the required lowercase environment token.
fn chain_label(policy: NetworkEnvironmentPolicy, tag: &str) -> String {
    match policy {
        NetworkEnvironmentPolicy::Devnet => format!("qbind-devnet-{tag}"),
        NetworkEnvironmentPolicy::Testnet => format!("qbind-testnet-{tag}"),
        NetworkEnvironmentPolicy::Mainnet => format!("qbind-mainnet-{tag}"),
    }
}

/// Build a valid three-validator genesis for `policy` (with an authority block
/// for TestNet/MainNet), plus its canonical pin under that policy. `tag`
/// distinguishes otherwise-equivalent-shape fixtures (case F).
fn genesis_for(policy: NetworkEnvironmentPolicy, tag: &str) -> (GenesisConfig, GenesisHash) {
    let mut cfg = GenesisConfig::new(
        chain_label(policy, tag),
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            "0x1111111111111111111111111111111111111111",
            1_000_000u128,
        )],
        vec![validator(1), validator(2), validator(3)],
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    );
    if matches!(
        policy,
        NetworkEnvironmentPolicy::Testnet | NetworkEnvironmentPolicy::Mainnet
    ) {
        let mut auth = GenesisAuthorityConfig::new(vec![root(0xab, "foundation-bundle-signer-1")]);
        auth.pqc_transport_roots = vec![root(0xcd, "foundation-transport-1")];
        cfg.authority = Some(auth);
    }
    let pin = compute_canonical_genesis_hash(&cfg, policy);
    (cfg, pin)
}

fn write_genesis(g: &GenesisConfig) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("genesis.json");
    std::fs::write(&path, serde_json::to_vec_pretty(g).expect("serialize")).expect("write");
    (dir, path)
}

fn load(path: &Path, policy: NetworkEnvironmentPolicy, pin: &GenesisHash) -> ExpectedGenesisIdentity {
    ExpectedGenesisIdentity::load_pinned(path, policy, pin).expect("pinned identity")
}

const POLICIES: [NetworkEnvironmentPolicy; 3] = [
    NetworkEnvironmentPolicy::Devnet,
    NetworkEnvironmentPolicy::Testnet,
    NetworkEnvironmentPolicy::Mainnet,
];

// ============================================================================
// A. Matching controls (DevNet, TestNet, MainNet)
// ============================================================================

#[test]
fn d7c3b_a_matching_controls_resolve_exact_alias_attached_to_identity() {
    for policy in POLICIES {
        let (g, pin) = genesis_for(policy, "a");
        let (_dir, path) = write_genesis(&g);
        let identity = load(&path, policy, &pin);

        let env = env_of(policy);
        let runtime = env.chain_id();
        let corr = identity
            .check_network_correspondence(env, runtime)
            .expect("matching correspondence");

        // Exact C3A alias.
        let expected_alias = match policy {
            NetworkEnvironmentPolicy::Devnet => QBIND_DEVNET_WIRE_ALIAS,
            NetworkEnvironmentPolicy::Testnet => QBIND_TESTNET_WIRE_ALIAS,
            NetworkEnvironmentPolicy::Mainnet => QBIND_MAINNET_WIRE_ALIAS,
        };
        assert_eq!(corr.wire_alias(), expected_alias);
        assert_eq!(corr.environment(), env);
        assert_eq!(corr.runtime_chain_id(), runtime);
        assert_eq!(corr.validation_policy(), policy);

        // Refers to the original validated genesis hash + authority commitment.
        assert_eq!(corr.genesis_hash(), identity.genesis_hash());
        assert_eq!(corr.genesis_hash().as_slice(), pin.as_slice());
        assert_eq!(corr.authority_commitment(), identity.authority_commitment());
        assert_eq!(corr.validator_count(), identity.validator_count());
        assert_eq!(corr.founding_epoch(), identity.founding_epoch());
        assert_eq!(corr.chain_id(), identity.chain_id());
        // Borrow points at the same identity.
        assert_eq!(
            corr.identity().genesis_hash().as_slice(),
            identity.genesis_hash().as_slice()
        );
    }
}

// ============================================================================
// B. Environment provenance mismatch — full 3×3 matrix
// ============================================================================

#[test]
fn d7c3b_b_env_provenance_mismatch_rejects_all_six_pairs() {
    let mut mismatched = 0usize;
    for validated in POLICIES {
        let (g, pin) = genesis_for(validated, "b");
        let (_dir, path) = write_genesis(&g);
        let identity = load(&path, validated, &pin);

        for selected in POLICIES {
            let sel_env = env_of(selected);
            // Supply the correct runtime ID for the *newly selected* environment,
            // proving the environment/runtime pair cannot relabel the identity.
            let runtime = sel_env.chain_id();
            let result = identity.check_network_correspondence(sel_env, runtime);

            if selected == validated {
                assert!(result.is_ok(), "matching pair must succeed");
            } else {
                mismatched += 1;
                match result {
                    Err(GenesisNetworkCorrespondenceError::ValidationPolicyMismatch {
                        validated_policy,
                        selected_environment,
                        selected_policy,
                    }) => {
                        assert_eq!(validated_policy, validated);
                        assert_eq!(selected_environment, sel_env);
                        assert_eq!(selected_policy, selected);
                    }
                    other => panic!("expected ValidationPolicyMismatch, got {other:?}"),
                }
            }
        }
    }
    assert_eq!(mismatched, 6, "all six off-diagonal pairs must be exercised");
}

// ============================================================================
// C. Full-width runtime validation (via C3A, no truncation)
// ============================================================================

#[test]
fn d7c3b_c_full_width_runtime_mismatch_rejects_via_c3a() {
    // Validate under DevNet; keep policy/environment matched so only the runtime
    // ID varies.
    let (g, pin) = genesis_for(NetworkEnvironmentPolicy::Devnet, "c");
    let (_dir, path) = write_genesis(&g);
    let identity = load(&path, NetworkEnvironmentPolicy::Devnet, &pin);
    let env = NetworkEnvironment::Devnet;
    let expected = QBIND_DEVNET_CHAIN_ID;

    // Other standard runtime IDs (wrong network) reject.
    for wrong in [QBIND_TESTNET_CHAIN_ID, QBIND_MAINNET_CHAIN_ID] {
        assert_runtime_mismatch(&identity, env, wrong, expected);
    }

    // Different high word but identical low 32 bits — must NOT be truncated to a
    // match. DevNet low word is 0x44455600.
    let low = expected.as_u64() & 0x0000_0000_FFFF_FFFF;
    let different_high = ChainId::new(0xDEAD_BEEF_0000_0000 | low);
    assert_ne!(different_high, expected);
    assert_eq!(different_high.as_u64() as u32, expected.as_u64() as u32);
    assert_runtime_mismatch(&identity, env, different_high, expected);

    // Representative invalid extremes.
    for wrong in [ChainId::new(0), ChainId::new(u64::MAX)] {
        assert_runtime_mismatch(&identity, env, wrong, expected);
    }
}

fn assert_runtime_mismatch(
    identity: &ExpectedGenesisIdentity,
    env: NetworkEnvironment,
    supplied: ChainId,
    expected: ChainId,
) {
    match identity.check_network_correspondence(env, supplied) {
        Err(GenesisNetworkCorrespondenceError::RuntimeMismatch(m)) => {
            assert_eq!(m.environment, env);
            assert_eq!(m.expected_runtime, expected);
            assert_eq!(m.supplied_runtime, supplied);
        }
        other => panic!("expected RuntimeMismatch, got {other:?}"),
    }
}

// ============================================================================
// D. Pin and snapshot preservation
// ============================================================================

#[test]
fn d7c3b_d_wrong_pin_rejects_construction() {
    let (g, _pin) = genesis_for(NetworkEnvironmentPolicy::Devnet, "d1");
    let (_dir, path) = write_genesis(&g);
    let wrong = [0x11u8; 32];
    match ExpectedGenesisIdentity::load_pinned(&path, NetworkEnvironmentPolicy::Devnet, &wrong) {
        Err(ExpectedGenesisIdentityError::GenesisRevalidationFailed { .. }) => {}
        other => panic!("expected pin revalidation failure, got {other:?}"),
    }
}

#[test]
fn d7c3b_d_replacement_genesis_rejects_against_frozen_pin() {
    let (g_a, pin_a) = genesis_for(NetworkEnvironmentPolicy::Devnet, "d2a");
    let (dir, path) = write_genesis(&g_a);
    // A loads against its own pin.
    load(&path, NetworkEnvironmentPolicy::Devnet, &pin_a);
    // Replace file contents with a different genesis B, keep frozen pin A.
    let (g_b, _pin_b) = genesis_for(NetworkEnvironmentPolicy::Devnet, "d2b");
    std::fs::write(
        dir.path().join("genesis.json"),
        serde_json::to_vec_pretty(&g_b).unwrap(),
    )
    .unwrap();
    match ExpectedGenesisIdentity::load_pinned(&path, NetworkEnvironmentPolicy::Devnet, &pin_a) {
        Err(ExpectedGenesisIdentityError::GenesisRevalidationFailed { .. }) => {}
        other => panic!("expected frozen-pin rejection of replacement, got {other:?}"),
    }
}

#[test]
fn d7c3b_d_loaded_identity_survives_source_removal_and_correspondence_needs_no_reread() {
    let (g, pin) = genesis_for(NetworkEnvironmentPolicy::Mainnet, "d3");
    let (dir, path) = write_genesis(&g);
    let identity = load(&path, NetworkEnvironmentPolicy::Mainnet, &pin);
    let hash_before = *identity.genesis_hash();

    // Remove the source file entirely.
    std::fs::remove_file(&path).unwrap();
    drop(dir);

    // Identity is unchanged and correspondence still succeeds without any reread.
    assert_eq!(identity.genesis_hash().as_slice(), hash_before.as_slice());
    let corr = identity
        .check_network_correspondence(NetworkEnvironment::Mainnet, QBIND_MAINNET_CHAIN_ID)
        .expect("correspondence from retained identity");
    assert_eq!(corr.wire_alias(), QBIND_MAINNET_WIRE_ALIAS);
    assert_eq!(corr.genesis_hash().as_slice(), hash_before.as_slice());
}

// ============================================================================
// E. Canonical-hash pin isolation
// ============================================================================

#[test]
fn d7c3b_e_canonical_hash_pin_is_environment_isolated() {
    // ONE fixture that satisfies the existing validation rules under BOTH DevNet
    // and TestNet: it carries the required lowercase "testnet" chain-id token and
    // a full authority block (TestNet requires an authority; DevNet accepts it).
    // The production validators are used unchanged for every check below.
    let mut cfg = GenesisConfig::new(
        "qbind-testnet-e",
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            "0x1111111111111111111111111111111111111111",
            1_000_000u128,
        )],
        vec![validator(1), validator(2), validator(3)],
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    );
    let mut auth = GenesisAuthorityConfig::new(vec![root(0xab, "signer-e")]);
    auth.pqc_transport_roots = vec![root(0xcd, "transport-e")];
    cfg.authority = Some(auth);

    let (_dir, path) = write_genesis(&cfg);

    // Freeze the DevNet and TestNet canonical pins of this single unchanged
    // fixture. They differ only because the canonical hash binds the environment
    // scope ("DEV" vs "TST"); the fixture bytes are identical.
    let devnet_pin = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Devnet);
    let testnet_pin = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Testnet);
    assert_ne!(
        devnet_pin.as_slice(),
        testnet_pin.as_slice(),
        "DevNet and TestNet canonical pins of the same fixture must differ"
    );

    // Each pin loads successfully only under its own environment.
    let dev_identity = load(&path, NetworkEnvironmentPolicy::Devnet, &devnet_pin);
    assert_eq!(dev_identity.genesis_hash().as_slice(), devnet_pin.as_slice());
    let test_identity = load(&path, NetworkEnvironmentPolicy::Testnet, &testnet_pin);
    assert_eq!(
        test_identity.genesis_hash().as_slice(),
        testnet_pin.as_slice()
    );

    // The frozen DevNet pin under TestNet is rejected by the canonical-hash
    // comparison itself — the fixture passes TestNet's structural + label checks,
    // so this is NOT a label-policy rejection. Assert the typed mismatch with its
    // environment and the exact expected/actual hashes.
    match verify_boot_time_genesis(
        NetworkEnvironmentPolicy::Testnet,
        &cfg,
        Some(&devnet_pin),
    ) {
        Err(BootGenesisVerificationError::CanonicalHashMismatch {
            env,
            expected,
            actual,
        }) => {
            assert_eq!(env, NetworkEnvironmentPolicy::Testnet);
            assert_eq!(expected.as_slice(), devnet_pin.as_slice());
            assert_eq!(actual.as_slice(), testnet_pin.as_slice());
        }
        other => panic!("expected CanonicalHashMismatch under TestNet, got {other:?}"),
    }

    // The same mismatched pin is also rejected through `load_pinned`'s existing
    // error interface (which wraps `verify_boot_time_genesis`).
    match ExpectedGenesisIdentity::load_pinned(
        &path,
        NetworkEnvironmentPolicy::Testnet,
        &devnet_pin,
    ) {
        Err(ExpectedGenesisIdentityError::GenesisRevalidationFailed { detail }) => {
            assert!(
                detail.contains("canonical genesis hash mismatch"),
                "load_pinned must reject via the canonical-hash mismatch, got: {detail}"
            );
        }
        other => panic!("cross-env pin must fail closed via load_pinned, got {other:?}"),
    }
}

// ============================================================================
// F. No invented label registry
// ============================================================================

#[test]
fn d7c3b_f_two_distinct_genesis_files_each_correspond_under_same_env() {
    // Two structurally distinct DevNet genesis files (different validator keys,
    // different ordinary labels), each accepted under its own independent pin.
    // Both correspond under DevNet — the helper does not choose an official
    // genesis or assert uniqueness across forks. Correspondence depends on
    // retained provenance + C3A, never on parsing the chain_id string.
    let (g_a, pin_a) = genesis_for(NetworkEnvironmentPolicy::Devnet, "f-alpha");
    let (g_b, pin_b) = genesis_for(NetworkEnvironmentPolicy::Devnet, "f-beta");
    assert_ne!(pin_a.as_slice(), pin_b.as_slice());

    let (_da, pa) = write_genesis(&g_a);
    let (_db, pb) = write_genesis(&g_b);
    let id_a = load(&pa, NetworkEnvironmentPolicy::Devnet, &pin_a);
    let id_b = load(&pb, NetworkEnvironmentPolicy::Devnet, &pin_b);

    let corr_a = id_a
        .check_network_correspondence(NetworkEnvironment::Devnet, QBIND_DEVNET_CHAIN_ID)
        .expect("A corresponds");
    let corr_b = id_b
        .check_network_correspondence(NetworkEnvironment::Devnet, QBIND_DEVNET_CHAIN_ID)
        .expect("B corresponds");

    // Same standard environment / alias, but distinct underlying genesis hashes.
    assert_eq!(corr_a.wire_alias(), QBIND_DEVNET_WIRE_ALIAS);
    assert_eq!(corr_b.wire_alias(), QBIND_DEVNET_WIRE_ALIAS);
    assert_ne!(
        corr_a.genesis_hash().as_slice(),
        corr_b.genesis_hash().as_slice()
    );
}

// ============================================================================
// G. Bounded diagnostics for the new typed mismatch errors
// ============================================================================

#[test]
fn d7c3b_g_bounded_diagnostics_for_both_mismatch_variants() {
    const BOUND: usize = 256;

    // Validation-policy mismatch: validated DevNet, selected MainNet.
    let (g, pin) = genesis_for(NetworkEnvironmentPolicy::Devnet, "g");
    let (_dir, path) = write_genesis(&g);
    let identity = load(&path, NetworkEnvironmentPolicy::Devnet, &pin);
    let policy_err = identity
        .check_network_correspondence(NetworkEnvironment::Mainnet, QBIND_MAINNET_CHAIN_ID)
        .unwrap_err();
    let d = format!("{policy_err}");
    let dbg = format!("{policy_err:?}");
    assert!(d.len() <= BOUND, "Display too long: {}", d.len());
    assert!(dbg.len() <= BOUND, "Debug too long: {}", dbg.len());
    // Bounded metadata present; no genesis label / path leaked.
    assert!(dbg.contains("ValidationPolicyMismatch"));
    assert!(!d.contains(identity.chain_id()));
    assert!(!dbg.contains(identity.chain_id()));

    // Runtime-id mismatch with an extreme supplied ID (u64::MAX).
    let rt_err = identity
        .check_network_correspondence(NetworkEnvironment::Devnet, ChainId::new(u64::MAX))
        .unwrap_err();
    let d2 = format!("{rt_err}");
    let dbg2 = format!("{rt_err:?}");
    assert!(d2.len() <= BOUND, "Display too long: {}", d2.len());
    assert!(dbg2.len() <= BOUND, "Debug too long: {}", dbg2.len());
    assert!(dbg2.contains("RuntimeMismatch"));
}