//! Run 133 evidence-only fixture helper for the release-binary
//! v2 validation-only acceptance/rejection matrix.
//!
//! Mints ephemeral ML-DSA-44 authority + bundle-signing material
//! (active + previous), writes:
//!   * per-environment `genesis.json` with Run 101 `genesis_authority`
//!     block bound to the minted authority key;
//!   * per-environment `expected-genesis-hash.txt`;
//!   * per-environment ratified signing-key spec
//!     (`KEYID:SUITE:PK_HEX`) for `--p2p-trust-bundle-signing-key`;
//!   * per-environment baseline trust bundle signed by the ratified
//!     signing key (used by `--p2p-trust-bundle <BASELINE>`);
//!   * per-environment candidate trust bundle (sequence 2) used by
//!     `--p2p-trust-bundle-reload-check <CANDIDATE>`;
//!   * per-environment peer-candidate envelope JSON for the local
//!     `--p2p-trust-bundle-peer-candidate-check <ENVELOPE>` path;
//!   * v1 ratification sidecar (regression for the Run 132 fall-
//!     through v1 path);
//!   * v2 ratification sidecars covering the Run 132 acceptance /
//!     rejection matrix (ratify@seq=1, ratify@seq=2 upgrade,
//!     rotate@seq=2 upgrade, revoke@seq=2 upgrade, ratify@seq=1
//!     same-digest, ratify@seq=1 different-digest, lower-sequence,
//!     tampered signature, wrong chain, wrong environment, wrong
//!     genesis hash, sequence-zero);
//!   * seeded v1 marker file (`pqc_authority_state.json` at v1
//!     sequence=1) and seeded v2 marker file (`pqc_authority_state.json`
//!     at v2 sequence=1) so the harness can pick which scenario gets
//!     which prior marker state by copying the seed into the per-
//!     scenario data dir.
//!
//! Run 133 is evidence-only. This helper does NOT modify production
//! runtime code and does NOT touch any wire format.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::bundle_signing_ratification::{
    test_helpers as v1_helpers, v2_test_helpers,
};
use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash,
    BundleSigningRatificationV2Action, GenesisAllocation,
    GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    RatificationEnvironment, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecord,
    PersistentAuthorityStateRecordV2,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    canonical_fingerprint, derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey,
    BundleSigningKeySet, RootStatus, TrustBundle, TrustBundleEnvironment,
    TrustBundleRoot,
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

fn v2_digest_hex(v: &qbind_ledger::BundleSigningRatificationV2) -> String {
    hex_lower(&qbind_ledger::canonical_ratification_v2_digest(v))
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) {
    fs::write(path, serde_json::to_vec_pretty(value).expect("serialize json"))
        .expect("write json");
}

struct Signing {
    pk: Vec<u8>,
    sk: Vec<u8>,
    key_id: [u8; 32],
    spec: String,
}

fn mint_signing() -> Signing {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 signing keygen");
    let key_id = derive_signing_key_id(&pk);
    let spec = format!(
        "{}:{}:{}",
        hex_lower(&key_id),
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        hex_lower(&pk)
    );
    Signing { pk, sk, key_id, spec }
}

struct Harness {
    env: NetworkEnvironment,
    chain_id_hex: String,
    genesis: GenesisConfig,
    canonical_hash: qbind_ledger::GenesisHash,
    canonical_hash_hex: String,
    canonical_hash_marker_hex: String,
    authority_pk_hex: String,
    authority_sk: Vec<u8>,
    root_id_hex: String,
    root_pk_hex: String,
}

fn harness(env: NetworkEnvironment) -> Harness {
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let authority_pk_hex = hex_lower(&authority_pk);
    let authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run133-bundle-signing-authority",
    );
    let root = mint_devnet_root().expect("mint transport root");
    let chain_id_hex_str = chain_id_hex(env.chain_id());
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
    let canonical_hash_hex = format_genesis_hash(&canonical_hash);
    let canonical_hash_marker_hex = hex_lower(&canonical_hash);
    Harness {
        env,
        chain_id_hex: chain_id_hex_str,
        genesis,
        canonical_hash,
        canonical_hash_hex,
        canonical_hash_marker_hex,
        authority_pk_hex,
        authority_sk,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

fn signed_bundle(h: &Harness, signing: &Signing, sequence: u64) -> TrustBundle {
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: signing.key_id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: signing.pk.clone(),
    }]);
    assert!(!signing_keys.is_empty(), "fixture signing key set must not be empty");

    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: bundle_env(h.env),
        chain_id: Some(h.chain_id_hex.clone()),
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
    let sig =
        sign_bundle_devnet_helper(&bundle, signing.key_id, &signing.sk).expect("sign bundle");
    bundle.signature = Some(sig);
    bundle
}

fn envelope_for(
    h: &Harness,
    signing: &Signing,
    peer_id: &str,
    sequence: u64,
) -> PeerCandidateEnvelope {
    let bundle = signed_bundle(h, signing, sequence);
    let fp = hex_lower(&canonical_fingerprint(&bundle));
    let bytes = serde_json::to_vec_pretty(&bundle).expect("serialize bundle");
    PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some(peer_id.to_string()),
        environment: bundle_env(h.env),
        chain_id_hex: h.chain_id_hex.clone(),
        declared_sequence: sequence,
        declared_fingerprint_prefix: fp[..8].to_string(),
        declared_length: bytes.len(),
        bundle_bytes: bytes,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_v2(
    h: &Harness,
    target: &Signing,
    sequence: u64,
    action: BundleSigningRatificationV2Action,
    previous_key_fingerprint: Option<String>,
    previous_ratification_digest: Option<String>,
    revocation_reason: Option<String>,
    capabilities_scope: Option<String>,
) -> qbind_ledger::BundleSigningRatificationV2 {
    v2_test_helpers::build_signed_ratification_v2(
        &h.chain_id_hex,
        rat_env(h.env),
        h.canonical_hash,
        1,
        &h.authority_pk_hex,
        &h.authority_sk,
        &target.pk,
        sequence,
        action,
        previous_key_fingerprint,
        previous_ratification_digest,
        None,
        None,
        revocation_reason,
        capabilities_scope,
    )
}

fn write_env_fixtures(base: &Path, env: NetworkEnvironment) {
    fs::create_dir_all(base).expect("mkdir env outdir");
    let h = harness(env);
    let active = mint_signing();
    let rotated = mint_signing();

    // ----------------- baseline genesis / hash / signing spec --------------
    write_json(&base.join("genesis.json"), &h.genesis);
    fs::write(
        base.join("expected-genesis-hash.txt"),
        format!("{}\n", &h.canonical_hash_hex),
    )
    .expect("write expected hash");
    fs::write(
        base.join("signing-key.ratified.spec"),
        format!("{}\n", active.spec),
    )
    .expect("write ratified spec");

    // ----------------- baseline / candidate trust bundles ------------------
    let baseline_bundle = signed_bundle(&h, &active, 1);
    let candidate_bundle = signed_bundle(&h, &active, 2);
    write_json(&base.join("baseline-bundle.json"), &baseline_bundle);
    write_json(&base.join("candidate-bundle.json"), &candidate_bundle);

    // peer-candidate envelopes
    write_json(
        &base.join("peer-candidate.json"),
        &envelope_for(&h, &active, "run133-active", 2),
    );

    // ----------------- v1 ratification sidecar (regression) ----------------
    let v1_valid = v1_helpers::build_signed_ratification(
        &h.chain_id_hex,
        rat_env(env),
        h.canonical_hash,
        &h.authority_pk_hex,
        &h.authority_sk,
        &active.pk,
    );
    write_json(&base.join("ratification.v1.valid.json"), &v1_valid);

    // ----------------- v2 ratification sidecars: matrix --------------------
    let v2_ratify_seq1 = build_v2(
        &h,
        &active,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
        None,
        None,
    );
    let v2_ratify_seq1_digest_hex = v2_digest_hex(&v2_ratify_seq1);
    write_json(&base.join("ratification.v2.ratify.seq1.json"), &v2_ratify_seq1);

    // upgrade: seq=2 ratify (same active key as seq=1)
    let v2_ratify_seq2 = build_v2(
        &h,
        &active,
        2,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
        None,
        None,
    );
    write_json(&base.join("ratification.v2.ratify.seq2.json"), &v2_ratify_seq2);

    // upgrade: seq=2 rotate (active -> rotated)
    let v2_rotate_seq2 = build_v2(
        &h,
        &rotated,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(qbind_ledger::pqc_public_key_fingerprint(&active.pk)),
        Some(v2_ratify_seq1_digest_hex.clone()),
        None,
        None,
    );
    write_json(&base.join("ratification.v2.rotate.seq2.json"), &v2_rotate_seq2);

    // upgrade: seq=2 revoke (revoke active key)
    let v2_revoke_seq2 = build_v2(
        &h,
        &active,
        2,
        BundleSigningRatificationV2Action::Revoke,
        None,
        None,
        Some("run133-evidence-only".to_string()),
        None,
    );
    write_json(&base.join("ratification.v2.revoke.seq2.json"), &v2_revoke_seq2);

    // idempotent: same-sequence same-digest as seq1
    write_json(
        &base.join("ratification.v2.same.seq1.json"),
        &v2_ratify_seq1,
    );

    // equivocation: same-sequence different-digest (different target key but same seq=1)
    let v2_diff_digest_seq1 = build_v2(
        &h,
        &rotated, // different target key -> different digest
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
        None,
        None,
    );
    write_json(
        &base.join("ratification.v2.equivocation.seq1.json"),
        &v2_diff_digest_seq1,
    );

    // lower-sequence: a fresh ratify@seq=1 to be replayed against a seq=2 marker
    write_json(
        &base.join("ratification.v2.lower.seq1.json"),
        &v2_ratify_seq1,
    );

    // tampered signature
    let mut v2_bad_sig = v2_ratify_seq1.clone();
    if !v2_bad_sig.signature.is_empty() {
        v2_bad_sig.signature[0] ^= 0xff;
    }
    write_json(&base.join("ratification.v2.bad-signature.json"), &v2_bad_sig);

    // wrong chain id
    let mut v2_wchain = v2_ratify_seq1.clone();
    v2_wchain.chain_id = "ffffffffffffffff".to_string();
    write_json(&base.join("ratification.v2.wrong-chain.json"), &v2_wchain);

    // wrong environment
    let mut v2_wenv = v2_ratify_seq1.clone();
    v2_wenv.environment = match env {
        NetworkEnvironment::Devnet => RatificationEnvironment::Testnet,
        _ => RatificationEnvironment::Devnet,
    };
    write_json(&base.join("ratification.v2.wrong-environment.json"), &v2_wenv);

    // wrong genesis hash
    let mut v2_wgenesis = v2_ratify_seq1.clone();
    let mut bad = h.canonical_hash;
    bad[0] ^= 0xff;
    v2_wgenesis.genesis_hash = bad;
    write_json(&base.join("ratification.v2.wrong-genesis.json"), &v2_wgenesis);

    // sequence zero
    let v2_seq0 = build_v2(
        &h,
        &active,
        0,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
        None,
        None,
    );
    write_json(&base.join("ratification.v2.sequence-zero.json"), &v2_seq0);

    // ----------------- seed v1 marker (for v1-after-v2 / migration) --------
    let now_secs = 1_738_000_000;
    let v1_marker = PersistentAuthorityStateRecord::new(
        h.chain_id_hex.clone(),
        bundle_env(env),
        h.canonical_hash_marker_hex.clone(),
        1,
        0,
        None,
        h.authority_pk_hex.clone(),
        qbind_ledger::pqc_public_key_fingerprint(&active.pk),
        hex_lower(&qbind_ledger::canonical_ratification_digest(&v1_valid)),
        AuthorityStateUpdateSource::TestOrFixture,
        now_secs,
    );
    write_json(&base.join("seed-marker.v1.json"), &v1_marker);

    // ----------------- seed v2 marker at seq=1 -----------------------------
    let v2_marker_seq1 = PersistentAuthorityStateRecordV2::new(
        h.chain_id_hex.clone(),
        bundle_env(env),
        h.canonical_hash_marker_hex.clone(),
        h.authority_pk_hex.clone(),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        qbind_ledger::pqc_public_key_fingerprint(&active.pk),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        v2_ratify_seq1_digest_hex.clone(),
        None,
        AuthorityStateUpdateSource::TestOrFixture,
        now_secs,
    );
    write_json(&base.join("seed-marker.v2.seq1.json"), &v2_marker_seq1);

    // ----------------- seed v2 marker at seq=2 -----------------------------
    let v2_ratify_seq2_digest_hex = v2_digest_hex(&v2_ratify_seq2);
    let v2_marker_seq2 = PersistentAuthorityStateRecordV2::new(
        h.chain_id_hex.clone(),
        bundle_env(env),
        h.canonical_hash_marker_hex.clone(),
        h.authority_pk_hex.clone(),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        qbind_ledger::pqc_public_key_fingerprint(&active.pk),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        2,
        BundleSigningRatificationV2Action::Ratify,
        None,
        v2_ratify_seq2_digest_hex,
        None,
        AuthorityStateUpdateSource::TestOrFixture,
        now_secs,
    );
    write_json(&base.join("seed-marker.v2.seq2.json"), &v2_marker_seq2);

    // ----------------- defensive: drop authority secret key ---------------
    drop(h.authority_sk);
    drop(active.sk);
    drop(rotated.sk);
}

fn main() {
    let outdir = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: run_133_v2_validation_only_fixture_helper <OUTDIR>");

    let _ = fs::remove_dir_all(&outdir);
    fs::create_dir_all(&outdir).expect("mkdir outdir");

    for env in [NetworkEnvironment::Devnet, NetworkEnvironment::Mainnet] {
        let sub = outdir.join(match env {
            NetworkEnvironment::Devnet => "devnet",
            NetworkEnvironment::Mainnet => "mainnet",
            NetworkEnvironment::Testnet => "testnet",
        });
        write_env_fixtures(&sub, env);
    }

    eprintln!(
        "[run-133] v2 validation-only fixtures written under {}",
        outdir.display()
    );
}
