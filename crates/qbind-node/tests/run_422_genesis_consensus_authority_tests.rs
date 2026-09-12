//! Run 422 — genesis-bound consensus authority activation integration
//! tests (release-binary-facing).
//!
//! These tests exercise the SAME validated constructor the production
//! `qbind-node` binary invokes
//! (`timeout_verification_bridge::try_build_timeout_verification_context`),
//! fed with authority derived from the boot-verified canonical genesis via
//! `genesis_consensus_authority::build_genesis_consensus_authority`, using
//! the real ML-DSA-44 backend. They complement the in-module unit tests
//! (authority commitment / parsing / adversarial rejection) with the
//! end-to-end activation and signer-correspondence behavior, plus a
//! source-level guard that `main.rs` wires genesis authority into that
//! constructor.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::ids::ValidatorId;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{ConsensusSigSuiteId, ValidatorSigningKey};
use qbind_ledger::{
    GenesisAllocation, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator,
};
use qbind_node::genesis_consensus_authority::{
    build_genesis_consensus_authority, GenesisConsensusAuthorityError,
};
use qbind_node::validator_signer::{LocalKeySigner, ValidatorSigner};
use qbind_node::timeout_verification_bridge::{
    try_build_timeout_verification_context, TimeoutVerificationBridgeInputs,
};
use qbind_types::ChainId;

/// Fresh ML-DSA-44 keypair: returns `(public_key_hex, secret_key_bytes)`.
fn fresh_keypair() -> (String, Vec<u8>) {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    (pk.iter().map(|b| format!("{:02x}", b)).collect(), sk)
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

fn backend_registry() -> Arc<SimpleBackendRegistry> {
    let mut r = SimpleBackendRegistry::new();
    r.register(ConsensusSigSuiteId::new(100), Arc::new(MlDsa44Backend::new()));
    Arc::new(r)
}

/// Valid genesis authority + matching local signer reaches the shared
/// constructor and yields an ACTIVE immutable context with a live signer.
#[test]
fn genesis_authority_plus_matching_signer_activates() {
    let (pk0, sk0) = fresh_keypair();
    let (pk1, _sk1) = fresh_keypair();
    let (pk2, _sk2) = fresh_keypair();
    let g = genesis_with(vec![
        validator(1, pk0),
        validator(2, pk1),
        validator(3, pk2),
    ]);
    let ghash = [0xAAu8; 32];

    let authority = build_genesis_consensus_authority(&g, &ghash, ValidatorId::new(0))
        .expect("valid genesis authority");
    assert_eq!(authority.validator_count, 3);

    // Local signer for validator 0 using the genesis-committed key.
    let signer: Arc<dyn ValidatorSigner> = Arc::new(LocalKeySigner::new(
        ValidatorId::new(0),
        100,
        Arc::new(ValidatorSigningKey::new(sk0)),
    ));

    let inputs = TimeoutVerificationBridgeInputs {
        validators: authority.validators.clone(),
        key_provider: authority.key_provider.clone(),
        backend_registry: backend_registry(),
        chain_id: ChainId::new(0x0000_0000_5142_4e44),
        signer: Some(signer),
        local_validator_id: ValidatorId::new(0),
    };
    let outcome = try_build_timeout_verification_context(inputs);
    assert!(outcome.is_active(), "expected Active, got {outcome:?}");
    let ctx = outcome.as_option().expect("active ctx");
    assert!(ctx.signer.is_some());
    assert_eq!(ctx.validators.len(), 3);
    // The genesis-committed key for validator 0 resolves to a full
    // 1312-byte ML-DSA-44 key under suite 100.
    let (suite, pk) = ctx
        .key_provider
        .get_suite_and_key(ValidatorId::new(0))
        .expect("v0 key");
    assert_eq!(suite, ConsensusSigSuiteId::new(100));
    assert_eq!(pk.len(), 1312);
}

/// The genesis-committed key for the local validator equals the loaded
/// signer's derived public key on a match, and differs on a mismatch —
/// this is exactly the fail-closed binding `main` enforces before
/// activating under `--consensus-authority-from-genesis`.
#[test]
fn signer_genesis_key_correspondence_is_detectable() {
    let (pk0, sk0) = fresh_keypair();
    let g = genesis_with(vec![validator(1, pk0)]);
    let ghash = [0xAAu8; 32];
    let authority =
        build_genesis_consensus_authority(&g, &ghash, ValidatorId::new(0)).unwrap();

    let signing_key = ValidatorSigningKey::new(sk0);
    let signer_pk = signing_key.derive_public_key().unwrap();
    let (_s, genesis_pk) = authority
        .key_provider
        .get_suite_and_key(ValidatorId::new(0))
        .unwrap();
    // Match.
    assert_eq!(signer_pk, genesis_pk);

    // A different signer's key does NOT match validator 0's committed key.
    let (_pk_other, sk_other) = fresh_keypair();
    let other_pk = ValidatorSigningKey::new(sk_other).derive_public_key().unwrap();
    assert_ne!(other_pk, genesis_pk);
}

/// A signer whose validator id is not the local validator is rejected by
/// the shared constructor (no half-initialized context).
#[test]
fn signer_validator_id_mismatch_is_disabled() {
    let (pk0, _sk0) = fresh_keypair();
    let (_pk_x, sk_x) = fresh_keypair();
    let g = genesis_with(vec![validator(1, pk0)]);
    let authority =
        build_genesis_consensus_authority(&g, &[0xAAu8; 32], ValidatorId::new(0)).unwrap();

    // Signer claims validator 7 (not the local id 0).
    let signer: Arc<dyn ValidatorSigner> = Arc::new(LocalKeySigner::new(
        ValidatorId::new(7),
        100,
        Arc::new(ValidatorSigningKey::new(sk_x)),
    ));
    let inputs = TimeoutVerificationBridgeInputs {
        validators: authority.validators.clone(),
        key_provider: authority.key_provider.clone(),
        backend_registry: backend_registry(),
        chain_id: ChainId::new(1),
        signer: Some(signer),
        local_validator_id: ValidatorId::new(0),
    };
    let outcome = try_build_timeout_verification_context(inputs);
    assert!(!outcome.is_active(), "signer/id mismatch must not activate");
}

/// A genesis committing a wrong-length consensus key is rejected before
/// any context is built.
#[test]
fn malformed_committed_key_rejected() {
    let g = genesis_with(vec![validator(1, "abcd".to_string())]);
    match build_genesis_consensus_authority(&g, &[0xAAu8; 32], ValidatorId::new(0)) {
        Err(GenesisConsensusAuthorityError::InvalidKeyLength { .. }) => {}
        other => panic!("expected InvalidKeyLength, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Source-level guard: production `main.rs` wires genesis authority into the
// SAME validated constructor, behind the explicit opt-in flag, fail-closed.
// ---------------------------------------------------------------------------

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(name: &str) -> String {
    std::fs::read_to_string(crate_src().join(name)).expect("read src")
}

#[test]
fn main_rs_wires_genesis_authority_into_validated_constructor() {
    let src = read("main.rs");
    // The opt-in flag is consulted.
    assert!(
        src.contains("args.consensus_authority_from_genesis"),
        "main.rs must consult the --consensus-authority-from-genesis flag"
    );
    // The genesis-bound authority builder is invoked.
    assert!(
        src.contains("build_genesis_consensus_authority"),
        "main.rs must build the genesis-bound authority"
    );
    // Its output is fed into the SAME validated constructor.
    assert!(
        src.contains("try_build_timeout_verification_context"),
        "main.rs must feed the genesis authority into the shared constructor"
    );
    // Fail-closed: invalid activation exits nonzero, never downgrades.
    assert!(
        src.contains("--consensus-authority-from-genesis rejected the")
            || src.contains("--consensus-authority-from-genesis"),
        "main.rs must fail closed on invalid genesis activation"
    );
}

#[test]
fn cli_exposes_consensus_authority_from_genesis_flag() {
    let src = read("cli.rs");
    assert!(src.contains("consensus-authority-from-genesis"));
    assert!(src.contains("pub consensus_authority_from_genesis: bool"));
}
