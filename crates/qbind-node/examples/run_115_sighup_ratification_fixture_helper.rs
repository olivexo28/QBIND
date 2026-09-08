//! Run 115 evidence-only fixture helper for the release-binary
//! **SIGHUP** live trust-bundle reload-apply ratification scenarios.
//!
//! This helper is an extension of the Run 113 helper. Run 113's
//! process-start reload-apply path runs in `LocalMesh` mode (no
//! KEMTLS / leaf cert / P2P listener required) because the apply
//! pipeline executes during startup and the binary then exits.
//! Run 115's SIGHUP path requires the node to actually enter the
//! `run_p2p_node` async loop (only that loop installs the Run 074
//! SIGHUP handler that the Run 114 ratification gate plugs into),
//! which means the node must come up as a single-validator P2P
//! node with a leaf cert + KEM SK + signed trust bundle, and
//! everything must hang together against the SAME minted transport
//! root.
//!
//! This helper mints, per environment (`mainnet/` + `devnet/`):
//!
//!   * an ephemeral ML-DSA-44 PQC **transport root** (the trust
//!     bundle's `roots[0]` entry);
//!   * a fresh ML-KEM-768 **leaf KEM keypair** for validator `v0`
//!     (the only validator the SIGHUP harness ever runs), and a
//!     real ML-DSA-44-signed `NetworkDelegationCert` binding the
//!     leaf KEM pub key under the transport root (the cert the
//!     binary's `--p2p-leaf-cert` flag consumes; the SK the
//!     `--p2p-leaf-cert-key` flag consumes);
//!   * an ephemeral ML-DSA-44 **genesis-authority** keypair, bound
//!     into the Run 101 `genesis.authority.bundle_signing_authority_roots`
//!     block of the per-environment `genesis.json`;
//!   * an ephemeral ML-DSA-44 **rogue authority** keypair, NOT
//!     bound into the genesis authority block (used to mint the
//!     `unknown-authority` ratification sidecar variant so the
//!     Run 103 verifier surfaces `UnknownAuthorityRoot`);
//!   * a Run 102 `expected-genesis-hash.txt` for `--expect-genesis-hash`
//!     enforcement;
//!   * ephemeral ML-DSA-44 **ratified** and **unratified**
//!     bundle-signing key specs in the `KEYID:SUITE:PK_HEX` form
//!     that the binary's `--p2p-trust-bundle-signing-key` flag
//!     consumes;
//!   * a **baseline trust bundle** at `sequence=1` signed by the
//!     ratified signing key (the `--p2p-trust-bundle <BASELINE>`
//!     bundle the node loads at startup);
//!   * a **candidate trust bundle** at `sequence=2` signed by the
//!     ratified signing key (the bundle the SIGHUP path attempts
//!     to apply via `--p2p-trust-bundle-live-reload-path`);
//!   * a **candidate trust bundle (unratified-signed)** at
//!     `sequence=2` signed by the unratified signing key (the
//!     legacy DevNet "no-opt-in" candidate);
//!   * five Run 103 ratification sidecars covering the candidate
//!     bundle's ratified signing key:
//!       * `ratification.valid.json` — signed by the legitimate
//!         genesis-authority secret key;
//!       * `ratification.bad-signature.json` — same payload as
//!         `valid`, signature byte 0 flipped;
//!       * `ratification.wrong-chain.json` — rebuilt against a
//!         bogus `chain_id` so the verifier surfaces `ChainMismatch`;
//!       * `ratification.wrong-environment.json` — rebuilt against
//!         the OTHER environment policy so the verifier surfaces
//!         `EnvironmentMismatch`;
//!       * `ratification.unknown-authority.json` — signed by the
//!         rogue authority (NOT in the genesis authority block) so
//!         the verifier surfaces `UnknownAuthorityRoot`.
//!
//! Run 115 is **evidence-only**. This helper does NOT modify
//! production runtime code, does NOT create fallback authorities,
//! does NOT introduce static production source-code anchors, does
//! NOT introduce peer-driven live apply, and does NOT change any
//! wire format. It is an `examples/` target only. All fixture
//! material is per-run ephemeral and is regenerated from scratch
//! on every harness invocation.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use qbind_crypto::{MlDsa44Backend, MlKem768Backend};
use qbind_ledger::bundle_signing_ratification::test_helpers as ratification_helpers;
use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig,
    GenesisValidator, NetworkEnvironmentPolicy, RatificationEnvironment,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_devnet_helper::{
    encode_cert, issue_leaf_delegation_cert, mint_devnet_root, LeafCertSpec,
};
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

fn vid_bytes(vid: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    let s = format!("qbind-val-{}", vid);
    let n = s.len().min(32);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b
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
    rogue_authority_sk: Vec<u8>,
    rogue_authority_fp: String,
    transport_root: qbind_node::pqc_devnet_helper::DevNetRoot,
    root_id_hex: String,
    root_pk_hex: String,
}

fn harness(env: NetworkEnvironment) -> Harness {
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run115-bundle-signing-authority",
    );
    let authority_fp = authority_root.key_fingerprint.clone();

    let (rogue_authority_pk, rogue_authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 rogue authority keygen");
    let rogue_authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &rogue_authority_pk,
        "run115-rogue-authority",
    );
    let rogue_authority_fp = rogue_authority_root.key_fingerprint.clone();

    let transport_root = mint_devnet_root().expect("mint transport root");
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
    let root_id_hex = hex_lower(&transport_root.root_key_id);
    let root_pk_hex = hex_lower(&transport_root.root_pk);
    Harness {
        env,
        chain_id_str,
        genesis,
        canonical_hash,
        authority_sk,
        authority_fp,
        rogue_authority_sk,
        rogue_authority_fp,
        transport_root,
        root_id_hex,
        root_pk_hex,
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

    // The trusted-root identifier the binary's `--p2p-trust-bundle`
    // resolver advertises via the bundle's `roots[]` block. We
    // record the raw hex so the harness can include it in evidence
    // even though the binary discovers it from the bundle.
    fs::write(base.join("root.id.hex"), &h.root_id_hex).expect("write root id");
    fs::write(base.join("root.pk.hex"), &h.root_pk_hex).expect("write root pk");

    // Mint validator v0's KEM keypair + leaf cert against the same
    // transport root that the trust bundle advertises. This is the
    // ONLY validator the SIGHUP harness ever runs.
    let (kem_pk, kem_sk) = MlKem768Backend::generate_keypair().expect("ML-KEM-768 keygen");
    let cert_spec =
        LeafCertSpec::currently_valid(vid_bytes(0), h.transport_root.root_key_id, kem_pk);
    let cert = issue_leaf_delegation_cert(&cert_spec, &h.transport_root.root_sk)
        .expect("issue v0 leaf cert");
    fs::write(base.join("v0.cert.bin"), encode_cert(&cert)).expect("write v0.cert.bin");
    let kem_sk_path = base.join("v0.kem.sk.bin");
    fs::write(&kem_sk_path, &kem_sk).expect("write v0.kem.sk.bin");
    fs::set_permissions(&kem_sk_path, fs::Permissions::from_mode(0o600))
        .expect("chmod v0.kem.sk.bin 0600");

    // Baseline bundle (sequence 1) signed by the ratified key.
    let baseline = signed_bundle(&h, &ratified, 1);
    write_json(&base.join("baseline-bundle.json"), &baseline);

    // Candidate bundle (sequence 2) signed by the ratified key.
    let candidate = signed_bundle(&h, &ratified, 2);
    write_json(&base.join("candidate-bundle.ratified.json"), &candidate);

    // Candidate bundle (sequence 2) signed by the UNRATIFIED key —
    // used only for the DevNet legacy "no opt-in" scenario where
    // the Run 114 SIGHUP gate must SKIP and the apply proceeds via
    // the pre-Run-114 path.
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

    let wrong_chain_ratification = ratification_helpers::build_signed_ratification(
        "qbind-wrong-chain-v0",
        rat_env(env),
        h.canonical_hash,
        &h.authority_fp,
        &h.authority_sk,
        &ratified.pk,
    );

    let wrong_env_ratification = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        other_rat_env(env),
        h.canonical_hash,
        &h.authority_fp,
        &h.authority_sk,
        &ratified.pk,
    );

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
        .expect("usage: run_115_sighup_ratification_fixture_helper <outdir>");
    fs::create_dir_all(&outdir).expect("mkdir outdir");
    write_env_fixtures(&outdir.join("mainnet"), NetworkEnvironment::Mainnet);
    write_env_fixtures(&outdir.join("devnet"), NetworkEnvironment::Devnet);
    eprintln!(
        "[run115-fixture-helper] wrote ephemeral release-binary SIGHUP fixtures under {}",
        outdir.display()
    );
}
