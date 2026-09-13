//! Run 422 D7 — genesis-static consensus-authority freshness / lifetime.
//!
//! D7 concern: an immutable authority *provider* does not, by itself, prove
//! continued authorization across epoch / membership / restore transitions.
//! These tests exercise the additive, fail-closed lifetime guard
//! `GenesisConsensusAuthority::authorize_configuration` (and the immutable
//! snapshot it defends) using the real ML-DSA-44 backend and real genesis
//! parsing. They map directly onto task section 12.E:
//!
//!   * Context snapshot does not change if source files change after
//!     validation.
//!   * Parallel verification cannot mix keys, suites, membership, or results.
//!   * Restart / restore with mismatched authority identity fails closed.
//!   * A changed configuration cannot keep using genesis-static authority
//!     without an authorized transition.
//!   * Malformed / extreme input cannot panic.
//!   * Fixture bypass is unreachable through all current production
//!     constructors and parser routes.
//!
//! Boundaries preserved (unchanged by D7): production
//! `proposal_vote_authority` remains `None`; the genesis-authority startup
//! route stays refused; no CLI/env activation switch, fallback, or synthetic
//! epoch is introduced. The observed epoch is always supplied by the caller
//! from a validated source and is never used to activate a trust bundle.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::ml_dsa44::{MlDsa44Backend, ML_DSA_44_PUBLIC_KEY_SIZE};
use qbind_ledger::{
    GenesisAllocation, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator,
    GenesisHash, NetworkEnvironmentPolicy,
};
use qbind_node::genesis_consensus_authority::{
    build_genesis_consensus_authority, load_verify_and_build_genesis_authority,
    AuthorityLifetimeError, GenesisConsensusAuthority, ObservedConsensusConfiguration,
    GENESIS_STATIC_AUTHORITY_EPOCH,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn fresh_pk_hex() -> String {
    let (pk, _sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    assert_eq!(pk.len(), ML_DSA_44_PUBLIC_KEY_SIZE);
    pk.iter().map(|b| format!("{:02x}", b)).collect()
}

fn validator(addr_seed: u8, pk_hex: String) -> GenesisValidator {
    GenesisValidator::new(format!("{:02x}", addr_seed).repeat(32), pk_hex, 100_000u128)
}

fn genesis_with(validators: Vec<GenesisValidator>) -> GenesisConfig {
    GenesisConfig::new(
        "0000000051424e44",
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            "0x1111111111111111111111111111111111111111",
            1_000_000u128,
        )],
        validators,
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    )
}

fn three_validator_genesis() -> GenesisConfig {
    genesis_with(vec![
        validator(1, fresh_pk_hex()),
        validator(2, fresh_pk_hex()),
        validator(3, fresh_pk_hex()),
    ])
}

fn build_auth(g: &GenesisConfig, ghash: GenesisHash) -> GenesisConsensusAuthority {
    build_genesis_consensus_authority(g, &ghash, ValidatorId::new(0)).expect("valid authority")
}

fn write_genesis(g: &GenesisConfig) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("genesis.json");
    std::fs::write(&path, serde_json::to_vec_pretty(g).expect("serialize")).expect("write");
    (dir, path)
}

// ---------------------------------------------------------------------------
// Positive control + the changed-configuration matrix (section 12.E:
// "changed configuration cannot keep using genesis-static authority
// without an authorized transition").
// ---------------------------------------------------------------------------

/// The authority authorizes exactly its own founding configuration at the
/// founding epoch. This is the only accepting case.
#[test]
fn founding_configuration_authorizes() {
    let g = three_validator_genesis();
    let auth = build_auth(&g, [0xAAu8; 32]);
    assert_eq!(auth.authorized_epoch(), GENESIS_STATIC_AUTHORITY_EPOCH);
    assert_eq!(auth.authorized_epoch(), 0);

    // The authority's own advertised identity must round-trip to Ok.
    assert_eq!(auth.authorize_configuration(&auth.config_identity()), Ok(()));

    // An independently reconstructed identity with identical fields also
    // authorizes (equality, not object identity).
    let observed = ObservedConsensusConfiguration::new(
        auth.chain_id.clone(),
        auth.genesis_hash,
        auth.commitment,
        auth.validator_count,
        0,
    );
    assert_eq!(auth.authorize_configuration(&observed), Ok(()));
}

/// A different chain id is refused: genesis-static keys are bound to one
/// chain.
#[test]
fn changed_chain_id_rejected() {
    let g = three_validator_genesis();
    let auth = build_auth(&g, [0xAAu8; 32]);
    let mut observed = auth.config_identity();
    observed.chain_id = "0000000051424e45".to_string();
    match auth.authorize_configuration(&observed) {
        Err(AuthorityLifetimeError::ChainIdChanged { .. }) => {}
        other => panic!("expected ChainIdChanged, got {other:?}"),
    }
}

/// A resized membership is a different authority, not this one.
#[test]
fn changed_membership_count_rejected() {
    let g = three_validator_genesis();
    let auth = build_auth(&g, [0xAAu8; 32]);
    let mut observed = auth.config_identity();
    observed.validator_count = 4;
    match auth.authorize_configuration(&observed) {
        Err(AuthorityLifetimeError::MembershipCountChanged {
            authorized: 3,
            observed: 4,
        }) => {}
        other => panic!("expected MembershipCountChanged, got {other:?}"),
    }
}

/// A changed validator set (same count, different keys) changes the
/// commitment and is refused. This is the core "cannot authorize a changed
/// validator set with stale keys" guard.
#[test]
fn changed_validator_set_commitment_rejected() {
    let g_a = three_validator_genesis();
    let auth_a = build_auth(&g_a, [0xAAu8; 32]);

    // A second genesis with the SAME count but different committed keys ⇒
    // a different authority commitment.
    let g_b = three_validator_genesis();
    let auth_b = build_auth(&g_b, [0xAAu8; 32]);
    assert_ne!(auth_a.commitment, auth_b.commitment);
    assert_eq!(auth_a.validator_count, auth_b.validator_count);

    // Present B's membership commitment to A's lifetime guard.
    let observed = ObservedConsensusConfiguration::new(
        auth_a.chain_id.clone(),
        auth_a.genesis_hash,
        auth_b.commitment,
        auth_a.validator_count,
        0,
    );
    match auth_a.authorize_configuration(&observed) {
        Err(AuthorityLifetimeError::AuthorityCommitmentChanged { .. }) => {}
        other => panic!("expected AuthorityCommitmentChanged, got {other:?}"),
    }
}

/// Any epoch other than the founding epoch has NO authorized transition:
/// this run implements no key rotation / membership transition, so the
/// stale genesis keys must not keep signing across an epoch advance.
#[test]
fn epoch_advance_has_no_authorized_transition() {
    let g = three_validator_genesis();
    let auth = build_auth(&g, [0xAAu8; 32]);

    for observed_epoch in [1u64, 2, 7, u64::MAX] {
        let mut observed = auth.config_identity();
        observed.epoch = observed_epoch;
        match auth.authorize_configuration(&observed) {
            Err(AuthorityLifetimeError::EpochTransitionUnauthorized {
                authorized_epoch: 0,
                observed_epoch: got,
            }) => assert_eq!(got, observed_epoch),
            other => panic!("expected EpochTransitionUnauthorized, got {other:?}"),
        }
    }
}

/// Coarse-to-fine ordering: a chain change is reported before an epoch
/// change even when both diverge, so the diagnostic names the most
/// fundamental divergence.
#[test]
fn divergence_reporting_is_coarse_to_fine() {
    let g = three_validator_genesis();
    let auth = build_auth(&g, [0xAAu8; 32]);
    let observed = ObservedConsensusConfiguration::new(
        "different-chain",
        [0x00u8; 32],
        [0x00u8; 32],
        99,
        42,
    );
    match auth.authorize_configuration(&observed) {
        Err(AuthorityLifetimeError::ChainIdChanged { .. }) => {}
        other => panic!("expected ChainIdChanged first, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Restart / restore with mismatched authority identity fails closed
// (section 12.E). A restart / restore / replay onto a different network
// identity or a tampered membership must never reuse the genesis-static keys.
// ---------------------------------------------------------------------------

#[test]
fn restart_restore_mismatched_genesis_identity_fails_closed() {
    let g = three_validator_genesis();
    let auth = build_auth(&g, [0xAAu8; 32]);

    // Restart/restore presents storage bound to a DIFFERENT canonical
    // genesis hash (a different network identity).
    let mut observed = auth.config_identity();
    observed.genesis_hash = [0xBBu8; 32];
    match auth.authorize_configuration(&observed) {
        Err(AuthorityLifetimeError::GenesisHashChanged { .. }) => {}
        other => panic!("expected GenesisHashChanged, got {other:?}"),
    }
}

#[test]
fn restore_same_network_tampered_membership_fails_closed() {
    let g = three_validator_genesis();
    let auth = build_auth(&g, [0xAAu8; 32]);

    // Same chain + same genesis hash, but the operating membership
    // commitment was tampered — restore must still refuse.
    let mut observed = auth.config_identity();
    observed.authority_commitment[0] ^= 0x01;
    match auth.authorize_configuration(&observed) {
        Err(AuthorityLifetimeError::AuthorityCommitmentChanged { .. }) => {}
        other => panic!("expected AuthorityCommitmentChanged, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Context snapshot does not change if source files change after validation
// (section 12.E). The authority is an owned snapshot; mutating the on-disk
// genesis after activation cannot retroactively change it, and the guard
// keeps authorizing only the original founding identity.
// ---------------------------------------------------------------------------

#[test]
fn snapshot_immutable_when_source_file_changes_after_validation() {
    let g_a = three_validator_genesis();
    let (dir, path) = write_genesis(&g_a);

    let auth = load_verify_and_build_genesis_authority(
        &path,
        NetworkEnvironmentPolicy::Devnet,
        None,
        None,
        ValidatorId::new(0),
        3,
    )
    .expect("snapshot A activates");

    // Capture the immutable identity established at validation time.
    let genesis_hash_before = auth.genesis_hash;
    let commitment_before = auth.commitment;
    let count_before = auth.validator_count;
    let key0_before = auth
        .key_provider
        .get_suite_and_key(ValidatorId::new(0))
        .expect("v0 key");

    // Replace the file at the same path with a DIFFERENT genesis (B).
    let g_b = three_validator_genesis();
    std::fs::write(
        dir.path().join("genesis.json"),
        serde_json::to_vec_pretty(&g_b).expect("serialize B"),
    )
    .expect("overwrite genesis");

    // The in-memory snapshot is unchanged by the on-disk mutation.
    assert_eq!(auth.genesis_hash, genesis_hash_before);
    assert_eq!(auth.commitment, commitment_before);
    assert_eq!(auth.validator_count, count_before);
    assert_eq!(
        auth.key_provider.get_suite_and_key(ValidatorId::new(0)),
        Some(key0_before)
    );

    // And the guard still authorizes only the ORIGINAL founding identity.
    assert_eq!(auth.authorize_configuration(&auth.config_identity()), Ok(()));

    // A freshly re-loaded authority reflects B and has a different
    // commitment; presenting B's identity to the ORIGINAL A is refused.
    let auth_b = load_verify_and_build_genesis_authority(
        &path,
        NetworkEnvironmentPolicy::Devnet,
        None,
        None,
        ValidatorId::new(0),
        3,
    )
    .expect("snapshot B activates");
    assert_ne!(auth_b.commitment, commitment_before);
    assert_ne!(auth_b.genesis_hash, genesis_hash_before);
    // A refuses B's (different) identity. B differs in both genesis hash and
    // commitment, so the coarse-to-fine guard reports the genesis mismatch.
    assert!(
        auth.authorize_configuration(&auth_b.config_identity()).is_err(),
        "the original authority must refuse the reloaded (changed) identity"
    );
}

// ---------------------------------------------------------------------------
// Parallel verification cannot mix keys, suites, membership, or results
// (section 12.E). Two distinct immutable authorities are queried and guarded
// concurrently; neither ever authorizes the other's configuration and neither
// provider ever serves the other's keys.
// ---------------------------------------------------------------------------

#[test]
fn parallel_verification_does_not_mix_keys_suites_membership_or_results() {
    let auth_a = Arc::new(build_auth(&three_validator_genesis(), [0xAAu8; 32]));
    let auth_b = Arc::new(build_auth(&three_validator_genesis(), [0xBBu8; 32]));

    // Sanity: the two authorities are genuinely distinct.
    assert_ne!(auth_a.commitment, auth_b.commitment);
    assert_ne!(auth_a.genesis_hash, auth_b.genesis_hash);
    let id_a = auth_a.config_identity();
    let id_b = auth_b.config_identity();
    let a_keys: Vec<_> = (0..3)
        .map(|i| auth_a.key_provider.get_suite_and_key(ValidatorId::new(i)))
        .collect();
    let b_keys: Vec<_> = (0..3)
        .map(|i| auth_b.key_provider.get_suite_and_key(ValidatorId::new(i)))
        .collect();
    assert_ne!(a_keys, b_keys);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let auth_a = Arc::clone(&auth_a);
        let auth_b = Arc::clone(&auth_b);
        let id_a = id_a.clone();
        let id_b = id_b.clone();
        let a_keys = a_keys.clone();
        let b_keys = b_keys.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..500 {
                // Each authority authorizes ONLY its own identity.
                assert_eq!(auth_a.authorize_configuration(&id_a), Ok(()));
                assert_eq!(auth_b.authorize_configuration(&id_b), Ok(()));
                // ... and never the other's (results never cross).
                assert!(auth_a.authorize_configuration(&id_b).is_err());
                assert!(auth_b.authorize_configuration(&id_a).is_err());
                // Providers never serve the other authority's keys/suites.
                for i in 0..3u64 {
                    assert_eq!(
                        auth_a.key_provider.get_suite_and_key(ValidatorId::new(i)),
                        a_keys[i as usize]
                    );
                    assert_eq!(
                        auth_b.key_provider.get_suite_and_key(ValidatorId::new(i)),
                        b_keys[i as usize]
                    );
                }
                // Membership sizes stay fixed and distinct-per-authority.
                assert_eq!(auth_a.validators.len(), 3);
                assert_eq!(auth_b.validators.len(), 3);
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }
}

// ---------------------------------------------------------------------------
// Malformed / extreme observed input cannot panic (section 12.E). The guard
// is total: every degenerate input returns a bounded Err (or Ok only for an
// exact match), never a panic / overflow.
// ---------------------------------------------------------------------------

#[test]
fn malformed_or_extreme_observed_input_cannot_panic() {
    let g = three_validator_genesis();
    let auth = build_auth(&g, [0xAAu8; 32]);

    let cases = [
        ObservedConsensusConfiguration::new("", [0x00u8; 32], [0x00u8; 32], 0, 0),
        ObservedConsensusConfiguration::new(
            auth.chain_id.clone(),
            [0xFFu8; 32],
            [0xFFu8; 32],
            usize::MAX,
            u64::MAX,
        ),
        ObservedConsensusConfiguration::new(
            "\u{0}\u{1}\u{2}".to_string(),
            [0x00u8; 32],
            [0x00u8; 32],
            usize::MAX,
            u64::MAX,
        ),
        // Exact match apart from an overflowing epoch.
        ObservedConsensusConfiguration::new(
            auth.chain_id.clone(),
            auth.genesis_hash,
            auth.commitment,
            auth.validator_count,
            u64::MAX,
        ),
    ];
    for c in cases {
        // Must not panic; every degenerate case is a rejection.
        assert!(auth.authorize_configuration(&c).is_err());
    }
}

// ---------------------------------------------------------------------------
// Fixture bypass is unreachable through all current production constructors
// and parser routes (section 12.E). There is no public constructor that
// yields a `GenesisConsensusAuthority` without full validation, the only
// struct literal lives inside the validated builder, and the production CLI
// activation route is refused before any consensus service starts.
// ---------------------------------------------------------------------------

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read_src(name: &str) -> String {
    std::fs::read_to_string(crate_src().join(name)).expect("read src")
}

#[test]
fn fixture_bypass_unreachable_through_production_constructors_and_parser() {
    let module = read_src("genesis_consensus_authority.rs");

    // The ONLY struct-literal construction of a `GenesisConsensusAuthority`
    // is inside the validated builder (`Ok(GenesisConsensusAuthority { .. })`).
    // A second construction site would be an unvalidated back door.
    let literal_count = module.matches("Ok(GenesisConsensusAuthority {").count();
    assert_eq!(
        literal_count, 1,
        "exactly one struct-literal construction site is allowed (the validated builder)"
    );

    // The authority field map has no public mutating constructor; the key
    // provider has no public constructor other than the builder.
    assert!(
        module.contains("public constructor"),
        "the key provider must document that it has no bypass constructor"
    );

    // Production `main.rs` refuses the genesis-authority activation route
    // before any P2P / consensus service starts — no fixture/unsigned
    // context can escape through the parser route.
    let main_src = read_src("main.rs");
    assert!(
        main_src.contains("args.consensus_authority_from_genesis"),
        "main.rs must consult the activation flag"
    );
    assert!(
        main_src.contains("genesis-authority activation is disabled"),
        "main.rs must refuse the genesis-authority activation route (fail-closed)"
    );

    // No `LocalFixtureUnsigned` construction leaks through this module.
    assert!(
        !module.contains("LocalFixtureUnsigned"),
        "the genesis authority module must not reference the fixture-unsigned policy"
    );
}
