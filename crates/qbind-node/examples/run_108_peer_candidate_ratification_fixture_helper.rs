//! Run 108 evidence-only fixture helper for release-binary
//! peer-candidate-check ratification smoke scenarios.
//!
//! This helper mints ephemeral ML-DSA-44 authority and bundle-signing
//! material, writes genesis-bound ratification sidecars, and writes local
//! peer-candidate envelope JSON fixtures. It is an example target only;
//! it is not used by production runtime code and does not create fallback
//! authorities, static production anchors, live propagation, or apply paths.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::bundle_signing_ratification::test_helpers as ratification_helpers;
use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash, GenesisAllocation,
    GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy, RatificationEnvironment,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    canonical_fingerprint, derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey,
    BundleSigningKeySet, RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::PeerCandidateEnvelope;
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
    fs::write(path, serde_json::to_vec_pretty(value).expect("serialize json")).expect("write json");
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
    SigningMaterial { pk, sk, key_id, spec }
}

struct Harness {
    env: NetworkEnvironment,
    chain_id_str: String,
    genesis: GenesisConfig,
    canonical_hash: qbind_ledger::GenesisHash,
    authority_sk: Vec<u8>,
    authority_fp: String,
    root_id_hex: String,
    root_pk_hex: String,
}

fn harness(env: NetworkEnvironment) -> Harness {
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run108-bundle-signing-authority",
    );
    let authority_fp = authority_root.key_fingerprint.clone();
    let root = mint_devnet_root().expect("mint transport root");
    let chain_id_str = chain_id_hex(env.chain_id());
    let mut genesis = GenesisConfig::new(
        genesis_chain_id(env),
        1_738_000_000_000,
        vec![GenesisAllocation::new(format!("0x{}", "11".repeat(32)), 100)],
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
    genesis.authority = Some(GenesisAuthorityConfig::new(vec![authority_root]));
    let canonical_hash = compute_canonical_genesis_hash(&genesis, env_policy(env));
    Harness {
        env,
        chain_id_str,
        genesis,
        canonical_hash,
        authority_sk,
        authority_fp,
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
    assert!(!signing_keys.is_empty(), "fixture signing key set must not be empty");

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

fn envelope_for(h: &Harness, signing: &SigningMaterial, peer_id: &str, sequence: u64) -> PeerCandidateEnvelope {
    let bundle = signed_bundle(h, signing, sequence);
    let fp = hex_lower(&canonical_fingerprint(&bundle));
    let bytes = serde_json::to_vec_pretty(&bundle).expect("serialize bundle");
    PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some(peer_id.to_string()),
        environment: bundle_env(h.env),
        chain_id_hex: h.chain_id_str.clone(),
        declared_sequence: sequence,
        declared_fingerprint_prefix: fp[..8].to_string(),
        declared_length: bytes.len(),
        bundle_bytes: bytes,
    }
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
    fs::write(base.join("signing-key.ratified.spec"), format!("{}\n", ratified.spec))
        .expect("write ratified signing spec");
    fs::write(
        base.join("signing-key.unratified.spec"),
        format!("{}\n", unratified.spec),
    )
    .expect("write unratified signing spec");

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

    write_json(&base.join("ratification.valid.json"), &valid_ratification);
    write_json(&base.join("ratification.bad-signature.json"), &bad_ratification);
    write_json(
        &base.join("peer-candidate.ratified.json"),
        &envelope_for(&h, &ratified, "run108-ratified", 1),
    );
    write_json(
        &base.join("peer-candidate.unratified.json"),
        &envelope_for(&h, &unratified, "run108-unratified", 1),
    );
}

fn main() {
    let outdir = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: run_108_peer_candidate_ratification_fixture_helper <outdir>");
    fs::create_dir_all(&outdir).expect("mkdir outdir");
    write_env_fixtures(&outdir.join("mainnet"), NetworkEnvironment::Mainnet);
    write_env_fixtures(&outdir.join("devnet"), NetworkEnvironment::Devnet);
    eprintln!(
        "[run108-fixture-helper] wrote ephemeral release-binary fixtures under {}",
        outdir.display()
    );
}
