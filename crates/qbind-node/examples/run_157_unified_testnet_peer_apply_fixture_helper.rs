//! Run 157 unified TestNet fixture universe helper.
//!
//! Source/test fixture tooling only. This helper mints one coherent
//! TestNet universe for a future Run 158 release-binary positive
//! peer-driven apply harness. It does not change production wire/schema/CLI
//! semantics and does not claim release-binary positive apply evidence.

use std::env;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use qbind_crypto::{MlDsa44Backend, MlKem768Backend};
use qbind_ledger::bundle_signing_ratification::v2_test_helpers;
use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash, BundleSigningRatificationV2Action,
    GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig,
    GenesisCouncilConfig, GenesisHash, GenesisMonetaryConfig, GenesisValidator,
    NetworkEnvironmentPolicy, RatificationEnvironment, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
};
use qbind_node::pqc_devnet_helper::{
    encode_cert, issue_leaf_delegation_cert, mint_devnet_root, DevNetRoot, LeafCertSpec,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    canonical_fingerprint, derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey,
    BundleSigningKeySet, RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::PeerCandidateEnvelope;
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;
use serde::Serialize;

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

fn vid_bytes(vid: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&vid.to_be_bytes());
    out
}

fn write_json<T: Serialize>(path: &Path, value: &T) {
    fs::write(path, serde_json::to_vec_pretty(value).expect("serialize json"))
        .expect("write json");
}

#[derive(Clone)]
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
    canonical_hash: GenesisHash,
    canonical_hash_hex: String,
    canonical_hash_marker_hex: String,
    authority_pk_hex: String,
    authority_sk: Vec<u8>,
    authority_root_fingerprint: String,
    transport_root: DevNetRoot,
    candidate_extra_root: DevNetRoot,
    signing: Signing,
}

fn harness() -> Harness {
    let env = NetworkEnvironment::Testnet;
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let authority_pk_hex = hex_lower(&authority_pk);
    let authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run157-unified-testnet-bundle-signing-authority",
    );
    let authority_root_fingerprint = authority_root.key_fingerprint.clone();
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
        chain_id_hex: chain_id_hex(env.chain_id()),
        genesis,
        canonical_hash,
        canonical_hash_hex,
        canonical_hash_marker_hex,
        authority_pk_hex,
        authority_sk,
        authority_root_fingerprint,
        transport_root: mint_devnet_root().expect("mint transport root"),
        candidate_extra_root: mint_devnet_root().expect("mint candidate extra root"),
        signing: mint_signing(),
    }
}

fn signing_keys(signing: &Signing) -> BundleSigningKeySet {
    BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: signing.key_id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: signing.pk.clone(),
    }])
}

fn root_entry(root: &DevNetRoot) -> TrustBundleRoot {
    TrustBundleRoot {
        root_id: hex_lower(&root.root_key_id),
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        root_pk: hex_lower(&root.root_pk),
        status: RootStatus::Active,
        not_before: 0,
        not_after: u64::MAX,
        activation_epoch: None,
        activation_height: None,
    }
}

fn signed_bundle(h: &Harness, sequence: u64) -> TrustBundle {
    let roots = if sequence == 1 {
        vec![root_entry(&h.transport_root)]
    } else {
        vec![root_entry(&h.transport_root), root_entry(&h.candidate_extra_root)]
    };
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: bundle_env(h.env),
        chain_id: Some(h.chain_id_hex.clone()),
        generated_at: 10 + sequence,
        valid_from: 0,
        valid_until: u64::MAX,
        sequence,
        roots,
        revocations: vec![],
        signature: None,
        activation_epoch: None,
        activation_height: None,
    };
    let sig = sign_bundle_devnet_helper(&bundle, h.signing.key_id, &h.signing.sk)
        .expect("sign bundle");
    bundle.signature = Some(sig);
    bundle
}

fn signed_bundle_with_generated_at(h: &Harness, sequence: u64, generated_at: u64) -> TrustBundle {
    let mut bundle = signed_bundle(h, sequence);
    bundle.signature = None;
    bundle.generated_at = generated_at;
    let sig = sign_bundle_devnet_helper(&bundle, h.signing.key_id, &h.signing.sk)
        .expect("sign bundle");
    bundle.signature = Some(sig);
    bundle
}

fn envelope_from_bundle(h: &Harness, bundle: &TrustBundle, peer_id: &str, sequence: u64) -> PeerCandidateEnvelope {
    let fp = hex_lower(&canonical_fingerprint(bundle));
    let bytes = serde_json::to_vec_pretty(bundle).expect("serialize bundle");
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

fn build_v2(h: &Harness, sequence: u64) -> qbind_ledger::BundleSigningRatificationV2 {
    v2_test_helpers::build_signed_ratification_v2(
        &h.chain_id_hex,
        rat_env(h.env),
        h.canonical_hash,
        1,
        &h.authority_pk_hex,
        &h.authority_sk,
        &h.signing.pk,
        sequence,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

fn v2_digest_hex(v: &qbind_ledger::BundleSigningRatificationV2) -> String {
    hex_lower(&qbind_ledger::canonical_ratification_v2_digest(v))
}

fn write_leaf_material(base: &Path, h: &Harness, validator_id: u64) -> NodeMaterialManifest {
    let (kem_pk, kem_sk) = MlKem768Backend::generate_keypair().expect("ML-KEM-768 keygen");
    let spec = LeafCertSpec::currently_valid(vid_bytes(validator_id), h.transport_root.root_key_id, kem_pk);
    let cert = issue_leaf_delegation_cert(&spec, &h.transport_root.root_sk).expect("issue leaf cert");
    let cert_path = base.join(format!("v{}.cert.bin", validator_id));
    let kem_sk_path = base.join(format!("v{}.kem.sk.bin", validator_id));
    fs::write(&cert_path, encode_cert(&cert)).expect("write cert");
    fs::write(&kem_sk_path, kem_sk).expect("write kem sk");
    #[cfg(unix)]
    fs::set_permissions(&kem_sk_path, fs::Permissions::from_mode(0o600)).expect("chmod kem sk");
    NodeMaterialManifest {
        leaf_cert: cert_path,
        kem_secret_key: kem_sk_path,
    }
}

#[derive(Serialize)]
struct NodeMaterialManifest {
    leaf_cert: PathBuf,
    kem_secret_key: PathBuf,
}

#[derive(Serialize)]
struct NegativePeerCandidateManifest {
    lower_sequence: PathBuf,
    same_sequence_different_digest: PathBuf,
    bad_signature: PathBuf,
    wrong_environment: PathBuf,
    wrong_chain: PathBuf,
    wrong_genesis_ratification: PathBuf,
    ambiguous_v1_v2: PathBuf,
    duplicate_candidate: PathBuf,
}

#[derive(Serialize)]
struct UnifiedManifest {
    environment: &'static str,
    chain_id: &'static str,
    chain_id_hex: String,
    genesis: PathBuf,
    expected_genesis_hash: PathBuf,
    expected_genesis_hash_hex: String,
    baseline_trust_bundle: PathBuf,
    candidate_trust_bundle: PathBuf,
    v2_ratification_sidecar: PathBuf,
    baseline_v2_ratification_sidecar: PathBuf,
    bundle_signing_key_specs: PathBuf,
    transport_root_id: PathBuf,
    transport_root_public_key: PathBuf,
    candidate_extra_root_public_key: PathBuf,
    v0: NodeMaterialManifest,
    v1: NodeMaterialManifest,
    v2: NodeMaterialManifest,
    seeded_authority_marker: PathBuf,
    valid_peer_candidate_envelope: PathBuf,
    negative_peer_candidate_envelopes: NegativePeerCandidateManifest,
    expected_authority_domain_sequence: u64,
    baseline_fingerprint: String,
    expected_candidate_fingerprint: String,
    expected_candidate_digest: String,
    authority_root_fingerprint: String,
    mainnet_fixture: Option<PathBuf>,
}

fn write_negative_peer_candidates(base: &Path, h: &Harness, candidate: &TrustBundle, v2_seq2: &qbind_ledger::BundleSigningRatificationV2) -> NegativePeerCandidateManifest {
    let lower_sequence = base.join("peer-candidate.lower-sequence.json");
    write_json(&lower_sequence, &envelope_from_bundle(h, &signed_bundle(h, 1), "run157-lower", 1));

    let same_sequence_different_digest = base.join("peer-candidate.same-sequence-different-digest.json");
    let diff_digest = signed_bundle_with_generated_at(h, 2, 99);
    write_json(&same_sequence_different_digest, &envelope_from_bundle(h, &diff_digest, "run157-diff-digest", 2));

    let bad_signature = base.join("peer-candidate.bad-signature.json");
    let mut bad_sig = candidate.clone();
    if let Some(sig) = bad_sig.signature.as_mut() {
        let mut bytes: Vec<u8> = (0..sig.sig_bytes.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig.sig_bytes[i..i + 2], 16).expect("hex"))
            .collect();
        if !bytes.is_empty() {
            bytes[0] ^= 0xff;
        }
        sig.sig_bytes = hex_lower(&bytes);
    }
    write_json(&bad_signature, &envelope_from_bundle(h, &bad_sig, "run157-bad-sig", 2));

    let wrong_environment = base.join("peer-candidate.wrong-environment.json");
    let mut wrong_env = envelope_from_bundle(h, candidate, "run157-wrong-env", 2);
    wrong_env.environment = TrustBundleEnvironment::Devnet;
    write_json(&wrong_environment, &wrong_env);

    let wrong_chain = base.join("peer-candidate.wrong-chain.json");
    let mut wrong_chain_env = envelope_from_bundle(h, candidate, "run157-wrong-chain", 2);
    wrong_chain_env.chain_id_hex = "ffffffffffffffff".to_string();
    write_json(&wrong_chain, &wrong_chain_env);

    let wrong_genesis_ratification = base.join("ratification.v2.wrong-genesis.json");
    let mut wrong_genesis = v2_seq2.clone();
    wrong_genesis.genesis_hash[0] ^= 0xff;
    write_json(&wrong_genesis_ratification, &wrong_genesis);

    let ambiguous_v1_v2 = base.join("peer-candidate.ambiguous-v1-v2.json");
    let mut ambiguous = envelope_from_bundle(h, candidate, "run157-ambiguous", 2);
    ambiguous.domain_tag = "qbind-peer-trust-bundle-candidate-v1+v2-ambiguous".to_string();
    write_json(&ambiguous_v1_v2, &ambiguous);

    let duplicate_candidate = base.join("peer-candidate.duplicate.json");
    write_json(&duplicate_candidate, &envelope_from_bundle(h, candidate, "run157-valid", 2));

    NegativePeerCandidateManifest {
        lower_sequence,
        same_sequence_different_digest,
        bad_signature,
        wrong_environment,
        wrong_chain,
        wrong_genesis_ratification,
        ambiguous_v1_v2,
        duplicate_candidate,
    }
}

fn write_unified_testnet(base: &Path) -> UnifiedManifest {
    fs::create_dir_all(base).expect("mkdir outdir");
    let h = harness();
    let baseline = signed_bundle(&h, 1);
    let candidate = signed_bundle(&h, 2);
    let v2_seq1 = build_v2(&h, 1);
    let v2_seq2 = build_v2(&h, 2);
    let baseline_fp = hex_lower(&canonical_fingerprint(&baseline));
    let candidate_fp = hex_lower(&canonical_fingerprint(&candidate));
    let candidate_digest = candidate_fp.clone();

    let genesis = base.join("genesis.json");
    let expected_genesis_hash = base.join("expected-genesis-hash.txt");
    let baseline_trust_bundle = base.join("baseline-bundle.seq1.json");
    let candidate_trust_bundle = base.join("candidate-bundle.seq2.json");
    let baseline_v2_ratification_sidecar = base.join("ratification.v2.ratify.seq1.json");
    let v2_ratification_sidecar = base.join("ratification.v2.ratify.seq2.json");
    let bundle_signing_key_specs = base.join("signing-key.ratified.spec");
    let transport_root_id = base.join("transport-root.id.hex");
    let transport_root_public_key = base.join("transport-root.pk.hex");
    let candidate_extra_root_public_key = base.join("candidate-extra-root.pk.hex");

    write_json(&genesis, &h.genesis);
    fs::write(&expected_genesis_hash, format!("{}\n", h.canonical_hash_hex)).expect("write genesis hash");
    write_json(&baseline_trust_bundle, &baseline);
    write_json(&candidate_trust_bundle, &candidate);
    write_json(&baseline_v2_ratification_sidecar, &v2_seq1);
    write_json(&v2_ratification_sidecar, &v2_seq2);
    fs::write(&bundle_signing_key_specs, format!("{}\n", h.signing.spec)).expect("write signing spec");
    fs::write(&transport_root_id, format!("{}\n", hex_lower(&h.transport_root.root_key_id))).expect("write root id");
    fs::write(&transport_root_public_key, format!("{}\n", hex_lower(&h.transport_root.root_pk))).expect("write root pk");
    fs::write(&candidate_extra_root_public_key, format!("{}\n", hex_lower(&h.candidate_extra_root.root_pk))).expect("write extra root pk");

    let v0 = write_leaf_material(base, &h, 0);
    let v1 = write_leaf_material(base, &h, 1);
    let v2 = write_leaf_material(base, &h, 2);

    let now_secs = 1_738_000_000;
    let marker = PersistentAuthorityStateRecordV2::new(
        h.chain_id_hex.clone(),
        bundle_env(h.env),
        h.canonical_hash_marker_hex.clone(),
        h.authority_pk_hex.clone(),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        qbind_ledger::pqc_public_key_fingerprint(&h.signing.pk),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        v2_digest_hex(&v2_seq1),
        None,
        AuthorityStateUpdateSource::TestOrFixture,
        now_secs,
    );
    let seeded_authority_marker = base.join("seed-marker.v2.seq1.json");
    write_json(&seeded_authority_marker, &marker);

    let valid_peer_candidate_envelope = base.join("peer-candidate.valid.json");
    write_json(&valid_peer_candidate_envelope, &envelope_from_bundle(&h, &candidate, "run157-valid", 2));
    let negative_peer_candidate_envelopes = write_negative_peer_candidates(base, &h, &candidate, &v2_seq2);

    UnifiedManifest {
        environment: "testnet",
        chain_id: "qbind-testnet-v0",
        chain_id_hex: h.chain_id_hex.clone(),
        genesis,
        expected_genesis_hash,
        expected_genesis_hash_hex: h.canonical_hash_hex.clone(),
        baseline_trust_bundle,
        candidate_trust_bundle,
        v2_ratification_sidecar,
        baseline_v2_ratification_sidecar,
        bundle_signing_key_specs,
        transport_root_id,
        transport_root_public_key,
        candidate_extra_root_public_key,
        v0,
        v1,
        v2,
        seeded_authority_marker,
        valid_peer_candidate_envelope,
        negative_peer_candidate_envelopes,
        expected_authority_domain_sequence: 2,
        baseline_fingerprint: baseline_fp,
        expected_candidate_fingerprint: candidate_fp,
        expected_candidate_digest: candidate_digest,
        authority_root_fingerprint: h.authority_root_fingerprint,
        mainnet_fixture: None,
    }
}

fn main() {
    let outdir = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: run_157_unified_testnet_peer_apply_fixture_helper <OUTDIR>");
    let _ = fs::remove_dir_all(&outdir);
    fs::create_dir_all(&outdir).expect("mkdir outdir");
    let manifest = write_unified_testnet(&outdir);
    write_json(&outdir.join("unified_testnet_manifest.json"), &manifest);
    eprintln!(
        "[run-157] unified TestNet source/test fixtures written under {}",
        outdir.display()
    );
}
