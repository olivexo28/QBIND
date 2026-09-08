//! Run 113 evidence-only fixture helper for the release-binary
//! process-start reload-apply ratification scenarios.
//!
//! This helper mints ephemeral ML-DSA-44 genesis-authority and
//! bundle-signing material, then writes:
//!
//!   * per-environment `genesis.json` with the Run 101
//!     `genesis_authority` block bound to the minted authority key;
//!   * per-environment `expected-genesis-hash.txt` for Run 102
//!     `--expect-genesis-hash` enforcement;
//!   * per-environment ratified + unratified signing-key specs in
//!     the `KEYID:SUITE:PK_HEX` form consumed by the binary's
//!     `--p2p-trust-bundle-signing-key` flag;
//!   * per-environment signed baseline trust bundle (sequence 1,
//!     signed by the ratified signing key) used by
//!     `--p2p-trust-bundle <BASELINE>`;
//!   * per-environment signed candidate trust bundle (sequence 2,
//!     signed by the ratified signing key) used by
//!     `--p2p-trust-bundle-reload-apply-path <CANDIDATE>`;
//!   * Run 103 ratification sidecars: valid, bad-signature,
//!     wrong-chain, wrong-environment, and unknown-authority-root
//!     variants for the reload-apply path.
//!
//! Run 113 is evidence-only. This helper does NOT modify production
//! runtime code, does NOT create fallback authorities, static
//! production source-code anchors, peer-driven live apply, or
//! wire-format changes. It is an `examples/` target only.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::bundle_signing_ratification::test_helpers as ratification_helpers;
use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig,
    GenesisValidator, NetworkEnvironmentPolicy, RatificationEnvironment,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

fn env_policy(env: NetworkEnvironment) -> NetworkEnvironmentPolicy {
    match env {
        NetworkEnvironment::Mainnet => NetworkEnvironmentPolicy::Mainnet,
        NetworkEnvironment::Testnet => NetworkEnvironmentPolicy::Testnet,
        NetworkEnvironment::Devnet => NetworkEnvironmentPolicy::Devnet,
    }
}

fn rat_env(env: NetworkEnvironment) -> RatificationEnvironment {
    match env {
        NetworkEnvironment::Mainnet => RatificationEnvironment::Mainnet,
        NetworkEnvironment::Testnet => RatificationEnvironment::Testnet,
        NetworkEnvironment::Devnet => RatificationEnvironment::Devnet,
    }
}

fn other_rat_env(env: NetworkEnvironment) -> RatificationEnvironment {
    match env {
        NetworkEnvironment::Mainnet => RatificationEnvironment::Devnet,
        NetworkEnvironment::Testnet => RatificationEnvironment::Devnet,
        NetworkEnvironment::Devnet => RatificationEnvironment::Mainnet,
    }
}

fn bundle_env(env: NetworkEnvironment) -> TrustBundleEnvironment {
    match env {
        NetworkEnvironment::Mainnet => TrustBundleEnvironment::Mainnet,
        NetworkEnvironment::Testnet => TrustBundleEnvironment::Testnet,
        NetworkEnvironment::Devnet => TrustBundleEnvironment::Devnet,
    }
}

fn genesis_chain_id(env: NetworkEnvironment) -> &'static str {
    match env {
        NetworkEnvironment::Mainnet => "qbind-mainnet-v0",
        NetworkEnvironment::Testnet => "qbind-testnet-v0",
        NetworkEnvironment::Devnet => "qbind-devnet-v0",
    }
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize json"),
    )
    .expect("write json");
}

struct SigningMaterial {
    pk: Vec<u8>,
    sk: Vec<u8>,
    key_id: [u8; 32],
    spec: String,
}

fn signing_material() -> SigningMaterial {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 signing keygen");
    let key_id = derive_signing_key_id(&pk);
    let spec = format!(
        "{}:{}:{}",
        hex_lower(&key_id),
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        hex_lower(&pk)
    );
    SigningMaterial {
        pk,
        sk,
        key_id,
        spec,
    }
}

struct Harness {
    env: NetworkEnvironment,
    chain_id_str: String,
    genesis: GenesisConfig,
    canonical_hash: qbind_ledger::GenesisHash,
    authority_sk: Vec<u8>,
    authority_fp: String,
    // unrelated authority key NOT bound in the genesis authority set
    rogue_authority_sk: Vec<u8>,
    rogue_authority_fp: String,
    root_id_hex: String,
    root_pk_hex: String,
}

fn harness(env: NetworkEnvironment) -> Harness {
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run113-bundle-signing-authority",
    );
    let authority_fp = authority_root.key_fingerprint.clone();

    let (rogue_authority_pk, rogue_authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 rogue authority keygen");
    let rogue_authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &rogue_authority_pk,
        "run113-rogue-authority",
    );
    let rogue_authority_fp = rogue_authority_root.key_fingerprint.clone();

    let root = mint_devnet_root().expect("mint transport root");
    let chain_id_str = chain_id_hex(env.chain_id());
    let mut genesis = GenesisConfig::new(
        genesis_chain_id(env),
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
    // Only the legitimate authority root is bound into the genesis;
    // the rogue authority is intentionally omitted so that a
    // ratification signed by it surfaces as `UnknownAuthorityRoot`.
    genesis.authority = Some(GenesisAuthorityConfig::new(vec![authority_root]));
    let canonical_hash = compute_canonical_genesis_hash(&genesis, env_policy(env));
    Harness {
        env,
        chain_id_str,
        genesis,
        canonical_hash,
        authority_sk,
        authority_fp,
        rogue_authority_sk,
        rogue_authority_fp,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

fn signed_bundle(h: &Harness, signing: &SigningMaterial, sequence: u64) -> TrustBundle {
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: signing.key_id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: signing.pk.clone(),
    }]);
    assert!(
        !signing_keys.is_empty(),
        "fixture signing key set must not be empty"
    );

    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: bundle_env(h.env),
        chain_id: Some(h.chain_id_str.clone()),
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
        activation_epoch: None,
        activation_height: None,
    };
    let sig = sign_bundle_devnet_helper(&bundle, signing.key_id, &signing.sk).expect("sign bundle");
    bundle.signature = Some(sig);
    bundle
}

fn write_env_fixtures(base: &Path, env: NetworkEnvironment) {
    let h = harness(env);
    let ratified = signing_material();
    let unratified = signing_material();

    fs::create_dir_all(base).expect("mkdir env outdir");
    write_json(&base.join("genesis.json"), &h.genesis);
    fs::write(
        base.join("expected-genesis-hash.txt"),
        format!("{}\n", format_genesis_hash(&h.canonical_hash)),
    )
    .expect("write expected hash");
    fs::write(
        base.join("signing-key.ratified.spec"),
        format!("{}\n", ratified.spec),
    )
    .expect("write ratified signing spec");
    fs::write(
        base.join("signing-key.unratified.spec"),
        format!("{}\n", unratified.spec),
    )
    .expect("write unratified signing spec");

    // Baseline bundle (sequence 1) signed by the ratified key.
    // This is the bundle the Run 073 adapter seeds the live trust
    // handle from via `--p2p-trust-bundle`.
    let baseline = signed_bundle(&h, &ratified, 1);
    write_json(&base.join("baseline-bundle.json"), &baseline);

    // Candidate bundle (sequence 2) signed by the ratified key.
    // This is the bundle the reload-apply path attempts to apply.
    let candidate = signed_bundle(&h, &ratified, 2);
    write_json(&base.join("candidate-bundle.ratified.json"), &candidate);

    // Candidate bundle (sequence 2) signed by an UNRATIFIED key —
    // present so that even a release-binary "no ratification gate"
    // legacy run can exercise the path that bypasses the gate but
    // is still signed by a known signing key. This bundle is signed
    // by `unratified`; the binary must be invoked with the
    // `unratified` signing-key spec for that legacy DevNet scenario.
    let candidate_unrat = signed_bundle(&h, &unratified, 2);
    write_json(
        &base.join("candidate-bundle.unratified.json"),
        &candidate_unrat,
    );

    let valid_ratification = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        rat_env(env),
        h.canonical_hash,
        &h.authority_fp,
        &h.authority_sk,
        &ratified.pk,
    );

    let mut bad_ratification = valid_ratification.clone();
    bad_ratification.signature[0] ^= 0xff;

    // Wrong-chain ratification: rebuild against a bogus chain_id
    // string so the verifier surfaces `ChainMismatch`. Signed
    // honestly by the genesis-bound authority so this is purely a
    // canonical-field mismatch, not a signature corruption.
    let wrong_chain_ratification = ratification_helpers::build_signed_ratification(
        "qbind-wrong-chain-v0",
        rat_env(env),
        h.canonical_hash,
        &h.authority_fp,
        &h.authority_sk,
        &ratified.pk,
    );

    // Wrong-environment ratification: bind to the OTHER environment
    // policy than this fixture group is for.
    let wrong_env_ratification = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        other_rat_env(env),
        h.canonical_hash,
        &h.authority_fp,
        &h.authority_sk,
        &ratified.pk,
    );

    // Unknown-authority-root ratification: signed by the rogue
    // authority secret key, whose public key is NOT in
    // `genesis.authority.bundle_signing_authority_roots`.
    let unknown_authority_ratification = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        rat_env(env),
        h.canonical_hash,
        &h.rogue_authority_fp,
        &h.rogue_authority_sk,
        &ratified.pk,
    );

    write_json(&base.join("ratification.valid.json"), &valid_ratification);
    write_json(
        &base.join("ratification.bad-signature.json"),
        &bad_ratification,
    );
    write_json(
        &base.join("ratification.wrong-chain.json"),
        &wrong_chain_ratification,
    );
    write_json(
        &base.join("ratification.wrong-environment.json"),
        &wrong_env_ratification,
    );
    write_json(
        &base.join("ratification.unknown-authority.json"),
        &unknown_authority_ratification,
    );
}

fn main() {
    let outdir = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: run_113_reload_apply_ratification_fixture_helper <outdir>");
    fs::create_dir_all(&outdir).expect("mkdir outdir");
    write_env_fixtures(&outdir.join("mainnet"), NetworkEnvironment::Mainnet);
    write_env_fixtures(&outdir.join("devnet"), NetworkEnvironment::Devnet);
    eprintln!(
        "[run113-fixture-helper] wrote ephemeral release-binary reload-apply fixtures under {}",
        outdir.display()
    );
}
