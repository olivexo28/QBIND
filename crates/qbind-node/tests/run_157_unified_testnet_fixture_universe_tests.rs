//! Run 157 — unified TestNet fixture universe for positive peer-driven apply.
//!
//! These tests are source/test fixture tooling only. They prove that one
//! helper invocation mints live N=3 transport material and a baseline(seq=1)
//! -> candidate(seq=2) peer-driven apply pair inside the same TestNet
//! authority/root/genesis/domain universe. Release-binary positive apply
//! evidence remains deferred to Run 158.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};

use qbind_crypto::{MlDsa44SignatureSuite, StaticCryptoProvider};
use qbind_ledger::{
    compute_canonical_genesis_hash, BundleSigningRatificationV2, GenesisConfig,
    NetworkEnvironmentPolicy, RatificationV2VerifierInputs,
};
use qbind_node::pqc_authority_marker_acceptance::{
    verify_marker_for_validation_only_v2, ValidationOnlyMarkerV2AcceptReason,
    ValidationOnlyMarkerV2Inputs,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    canonical_fingerprint, BundleSigningKeySet, TrustBundle, TrustBundleEnvironment,
};
use qbind_node::pqc_trust_peer_candidate::{
    PeerCandidateConfig, PeerCandidateEnvelope, PeerCandidateOutcome, PeerCandidateRuntimeContext,
    PeerCandidateValidator,
};
use qbind_node::pqc_trust_reload::{validate_candidate_bundle, ReloadCheckInputs};
use qbind_node::pqc_trust_sequence::{
    chain_id_hex, peek_sequence, PersistentTrustBundleSequenceRecord, SequencePeekOutcome,
};
use qbind_types::NetworkEnvironment;
use qbind_wire::io::WireDecode;
use qbind_wire::net::NetworkDelegationCert;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NodeMaterialManifest {
    leaf_cert: PathBuf,
    kem_secret_key: PathBuf,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
struct UnifiedManifest {
    environment: String,
    chain_id: String,
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run157-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&p).expect("create temp dir");
    p
}

fn helper_exe_path() -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target"));
    let exe = if cfg!(windows) {
        "run_157_unified_testnet_peer_apply_fixture_helper.exe"
    } else {
        "run_157_unified_testnet_peer_apply_fixture_helper"
    };
    target.join("debug").join("examples").join(exe)
}

fn run_helper(out: &Path) {
    let exe = helper_exe_path();
    let status = if exe.exists() {
        Command::new(&exe).arg(out).status().expect("run helper exe")
    } else {
        Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(workspace_root())
            .args([
                "run",
                "--quiet",
                "-p",
                "qbind-node",
                "--example",
                "run_157_unified_testnet_peer_apply_fixture_helper",
                "--",
            ])
            .arg(out)
            .status()
            .expect("cargo run helper")
    };
    assert!(status.success(), "Run 157 helper failed: {:?}", status);
}

fn manifest() -> &'static UnifiedManifest {
    static MANIFEST: OnceLock<UnifiedManifest> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        let out = tmpdir("manifest");
        run_helper(&out);
        let manifest_path = out.join("unified_testnet_manifest.json");
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest")
    })
}

fn load_bundle(path: &Path) -> TrustBundle {
    serde_json::from_slice(&std::fs::read(path).expect("read bundle")).expect("parse bundle")
}

fn load_ratification(path: &Path) -> BundleSigningRatificationV2 {
    serde_json::from_slice(&std::fs::read(path).expect("read ratification"))
        .expect("parse ratification")
}

fn load_envelope(path: &Path) -> PeerCandidateEnvelope {
    serde_json::from_slice(&std::fs::read(path).expect("read envelope")).expect("parse envelope")
}

fn signing_keys(m: &UnifiedManifest) -> BundleSigningKeySet {
    let spec = std::fs::read_to_string(&m.bundle_signing_key_specs).expect("read signing spec");
    BundleSigningKeySet::parse_specs(&[spec.trim().to_string()]).expect("parse signing spec")
}

fn genesis(m: &UnifiedManifest) -> GenesisConfig {
    serde_json::from_slice(&std::fs::read(&m.genesis).expect("read genesis")).expect("parse genesis")
}

fn expected_genesis_hash(m: &UnifiedManifest) -> qbind_ledger::GenesisHash {
    let cfg = genesis(m);
    compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Testnet)
}

fn validate_path(path: &Path, keys: &BundleSigningKeySet) -> qbind_node::pqc_trust_reload::ValidatedCandidate {
    validate_candidate_bundle(ReloadCheckInputs {
        candidate_path: path,
        environment: NetworkEnvironment::Testnet,
        chain_id: NetworkEnvironment::Testnet.chain_id(),
        validation_time_secs: 100,
        signing_keys: keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
    })
    .expect("candidate validates")
}

fn enabled_config() -> PeerCandidateConfig {
    PeerCandidateConfig {
        enabled: true,
        ..PeerCandidateConfig::default()
    }
}

fn peer_ctx<'a>(scratch: &'a Path, keys: &'a BundleSigningKeySet) -> PeerCandidateRuntimeContext<'a> {
    PeerCandidateRuntimeContext {
        expected_environment: NetworkEnvironment::Testnet,
        expected_chain_id: NetworkEnvironment::Testnet.chain_id(),
        scratch_dir: scratch,
        validation_time_secs: 100,
        signing_keys: keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
        now_ms: 1_000,
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex byte"))
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

#[test]
fn a1_unified_helper_produces_manifest_and_required_files() {
    let m = manifest();
    assert_eq!(m.environment, "testnet");
    assert_eq!(m.chain_id, "qbind-testnet-v0");
    assert_eq!(m.chain_id_hex, "51424e4454535400");
    assert_eq!(m.expected_authority_domain_sequence, 2);
    assert!(m.mainnet_fixture.is_none(), "Run 157 must not mint MainNet production material");

    let mut paths = vec![
        &m.genesis,
        &m.expected_genesis_hash,
        &m.baseline_trust_bundle,
        &m.candidate_trust_bundle,
        &m.v2_ratification_sidecar,
        &m.baseline_v2_ratification_sidecar,
        &m.bundle_signing_key_specs,
        &m.transport_root_id,
        &m.transport_root_public_key,
        &m.candidate_extra_root_public_key,
        &m.v0.leaf_cert,
        &m.v0.kem_secret_key,
        &m.v1.leaf_cert,
        &m.v1.kem_secret_key,
        &m.v2.leaf_cert,
        &m.v2.kem_secret_key,
        &m.seeded_authority_marker,
        &m.valid_peer_candidate_envelope,
        &m.negative_peer_candidate_envelopes.lower_sequence,
        &m.negative_peer_candidate_envelopes.same_sequence_different_digest,
        &m.negative_peer_candidate_envelopes.bad_signature,
        &m.negative_peer_candidate_envelopes.wrong_environment,
        &m.negative_peer_candidate_envelopes.wrong_chain,
        &m.negative_peer_candidate_envelopes.wrong_genesis_ratification,
        &m.negative_peer_candidate_envelopes.ambiguous_v1_v2,
        &m.negative_peer_candidate_envelopes.duplicate_candidate,
    ];
    paths.sort();
    paths.dedup();
    for path in paths {
        assert!(path.exists(), "manifest-listed file must exist: {}", path.display());
    }
}

#[test]
fn a2_baseline_testnet_bundle_validates_under_testnet_domain() {
    let m = manifest();
    let keys = signing_keys(m);
    let baseline = load_bundle(&m.baseline_trust_bundle);
    assert_eq!(baseline.environment, TrustBundleEnvironment::Testnet);
    assert_eq!(baseline.chain_id.as_deref(), Some(m.chain_id_hex.as_str()));
    assert_eq!(baseline.sequence, 1);
    let validated = validate_path(&m.baseline_trust_bundle, &keys);
    assert_eq!(validated.sequence, 1);
    assert_eq!(validated.fingerprint_hex, m.baseline_fingerprint);
    assert_eq!(hex_lower(&expected_genesis_hash(m)), m.expected_genesis_hash_hex.trim_start_matches("0x"));
}

#[test]
fn a3_candidate_is_valid_successor_of_baseline_in_same_universe() {
    let m = manifest();
    let keys = signing_keys(m);
    let baseline = load_bundle(&m.baseline_trust_bundle);
    let candidate = load_bundle(&m.candidate_trust_bundle);
    assert_eq!(baseline.sequence, 1);
    assert_eq!(candidate.sequence, 2);
    assert_eq!(baseline.environment, candidate.environment);
    assert_eq!(baseline.chain_id, candidate.chain_id);
    assert_eq!(baseline.roots[0].root_id, candidate.roots[0].root_id);
    assert_eq!(baseline.roots[0].root_pk, candidate.roots[0].root_pk);
    assert!(candidate.roots.len() > baseline.roots.len(), "candidate adds material while retaining live transport root");

    let seq_path = tmpdir("seq").join("pqc_trust_bundle_sequence.json");
    let record = PersistentTrustBundleSequenceRecord::new(
        TrustBundleEnvironment::Testnet,
        m.chain_id_hex.clone(),
        1,
        m.baseline_fingerprint.clone(),
        1_000,
    );
    std::fs::write(&seq_path, serde_json::to_vec_pretty(&record).unwrap()).expect("write seq");
    let candidate_fp = canonical_fingerprint(&candidate);
    let peek = peek_sequence(
        &seq_path,
        NetworkEnvironment::Testnet,
        NetworkEnvironment::Testnet.chain_id(),
        candidate.sequence,
        &candidate_fp,
    )
    .expect("peek accepts higher sequence");
    assert!(matches!(peek, SequencePeekOutcome::WouldUpgrade { previous_sequence: 1, candidate_sequence: 2, .. }));

    let validated = validate_path(&m.candidate_trust_bundle, &keys);
    assert_eq!(validated.sequence, 2);
    assert_eq!(validated.active_root_count, 2);
    assert_eq!(validated.fingerprint_hex, m.expected_candidate_fingerprint);
}

#[test]
fn a4_candidate_v2_ratification_verifies_under_testnet_domain() {
    let m = manifest();
    let rat = load_ratification(&m.v2_ratification_sidecar);
    let cfg = genesis(m);
    let hash = expected_genesis_hash(m);
    let verified = qbind_ledger::verify_bundle_signing_key_ratification_v2(
        RatificationV2VerifierInputs {
            ratification: &rat,
            authority: cfg.authority.as_ref().expect("authority"),
            expected_chain_id: &m.chain_id_hex,
            expected_environment: NetworkEnvironmentPolicy::Testnet,
            expected_genesis_hash: &hash,
        },
    )
    .expect("v2 ratification verifies");
    assert_eq!(rat.authority_domain_sequence, 2);
    assert_eq!(verified.authority_domain_sequence, 2);
    let candidate = load_bundle(&m.candidate_trust_bundle);
    assert_eq!(hex_lower(&canonical_fingerprint(&candidate)), m.expected_candidate_digest);
}

#[test]
fn a5_seeded_v2_marker_accepts_candidate_as_higher_sequence() {
    let m = manifest();
    let rat = load_ratification(&m.v2_ratification_sidecar);
    let cfg = genesis(m);
    let hash = expected_genesis_hash(m);
    let ratified = qbind_ledger::verify_bundle_signing_key_ratification_v2(
        RatificationV2VerifierInputs {
            ratification: &rat,
            authority: cfg.authority.as_ref().expect("authority"),
            expected_chain_id: &m.chain_id_hex,
            expected_environment: NetworkEnvironmentPolicy::Testnet,
            expected_genesis_hash: &hash,
        },
    )
    .expect("v2 ratification verifies");
    let hash_hex = hex_lower(&hash);
    let decision = verify_marker_for_validation_only_v2(ValidationOnlyMarkerV2Inputs {
        marker_path: &m.seeded_authority_marker,
        runtime_env: NetworkEnvironment::Testnet,
        runtime_chain_id: NetworkEnvironment::Testnet.chain_id(),
        runtime_genesis_hash_hex: &hash_hex,
        ratification: &rat,
        ratified: &ratified,
    })
    .expect("marker accepts higher sequence");
    assert_eq!(
        decision,
        ValidationOnlyMarkerV2AcceptReason::UpgradeCompatible {
            previous_sequence: 1,
            new_sequence: 2,
        }
    );
}

#[test]
fn a6_valid_peer_candidate_envelope_validates_without_mutation() {
    let m = manifest();
    let keys = signing_keys(m);
    let scratch = tmpdir("peer-scratch");
    let before_marker = std::fs::read(&m.seeded_authority_marker).expect("read marker");
    let mut validator = PeerCandidateValidator::new(enabled_config());
    let out = validator.try_accept(load_envelope(&m.valid_peer_candidate_envelope), &peer_ctx(&scratch, &keys));
    match out {
        PeerCandidateOutcome::Validated(vc) => {
            assert_eq!(vc.validated.sequence, 2);
            assert!(vc.validated.signature_verified);
        }
        other => panic!("expected validation-only acceptance, got {:?}", other),
    }
    assert_eq!(std::fs::read(&m.seeded_authority_marker).expect("read marker"), before_marker);
}

#[test]
fn a7_live_p2p_transport_material_is_internally_coherent() {
    let m = manifest();
    let root_pk_hex = std::fs::read_to_string(&m.transport_root_public_key).expect("root pk");
    let root_pk = hex_decode(root_pk_hex.trim());
    let baseline = load_bundle(&m.baseline_trust_bundle);
    assert_eq!(baseline.roots[0].root_pk, root_pk_hex.trim());

    let suite = MlDsa44SignatureSuite::new(PQC_TRANSPORT_SUITE_ML_DSA_44);
    let crypto: Arc<StaticCryptoProvider> =
        Arc::new(StaticCryptoProvider::new().with_signature_suite(Arc::new(suite)));
    for cert_path in [&m.v0.leaf_cert, &m.v1.leaf_cert, &m.v2.leaf_cert] {
        let bytes = std::fs::read(cert_path).expect("read cert");
        let cert = NetworkDelegationCert::decode(&mut bytes.as_slice()).expect("decode cert");
        assert_eq!(hex_lower(&cert.root_key_id), baseline.roots[0].root_id);
        qbind_net::verify_delegation_cert(crypto.as_ref(), &cert, &root_pk)
            .expect("leaf cert verifies under unified transport root");
    }
}

#[test]
fn a8_dry_run_command_builder_references_existing_fixture_paths() {
    let m = manifest();
    let nodes = [&m.v0, &m.v1, &m.v2];
    for (idx, node) in nodes.iter().enumerate() {
        let args = vec![
            "qbind-node".to_string(),
            "--env".to_string(),
            "testnet".to_string(),
            "--network-mode".to_string(),
            "p2p".to_string(),
            "--enable-p2p".to_string(),
            "--genesis-path".to_string(),
            m.genesis.display().to_string(),
            "--expect-genesis-hash".to_string(),
            m.expected_genesis_hash_hex.clone(),
            "--p2p-trust-bundle".to_string(),
            m.baseline_trust_bundle.display().to_string(),
            "--p2p-trust-bundle-signing-key".to_string(),
            std::fs::read_to_string(&m.bundle_signing_key_specs).unwrap().trim().to_string(),
            "--p2p-trusted-root".to_string(),
            format!(
                "{}:{}:{}",
                std::fs::read_to_string(&m.transport_root_id).unwrap().trim(),
                PQC_TRANSPORT_SUITE_ML_DSA_44,
                std::fs::read_to_string(&m.transport_root_public_key).unwrap().trim()
            ),
            "--p2p-leaf-cert".to_string(),
            node.leaf_cert.display().to_string(),
            "--p2p-leaf-cert-key".to_string(),
            node.kem_secret_key.display().to_string(),
        ];
        assert!(args.iter().any(|a| a == "testnet"), "node {idx} uses TestNet args");
        for p in [&m.genesis, &m.baseline_trust_bundle, &node.leaf_cert, &node.kem_secret_key] {
            assert!(p.exists(), "node {idx} command path exists: {}", p.display());
        }
    }
}

#[test]
fn r1_old_disjoint_universe_shape_is_rejected_before_staging() {
    let a = manifest();
    let b_dir = tmpdir("disjoint");
    run_helper(&b_dir);
    let b: UnifiedManifest = serde_json::from_slice(
        &std::fs::read(b_dir.join("unified_testnet_manifest.json")).expect("read manifest b"),
    )
    .expect("parse manifest b");
    let a_baseline = load_bundle(&a.baseline_trust_bundle);
    let b_candidate = load_bundle(&b.candidate_trust_bundle);
    assert_ne!(a_baseline.roots[0].root_id, b_candidate.roots[0].root_id);
    let a_keys = signing_keys(a);
    assert!(
        validate_candidate_bundle(ReloadCheckInputs {
            candidate_path: &b.candidate_trust_bundle,
            environment: NetworkEnvironment::Testnet,
            chain_id: NetworkEnvironment::Testnet.chain_id(),
            validation_time_secs: 100,
            signing_keys: &a_keys,
            activation_ctx: ActivationContext::height_only(0),
            sequence_persistence_path: None,
            local_leaf_cert_bytes: None,
        })
        .is_err(),
        "candidate from a disjoint universe must fail before staging under V1's configured authority"
    );
}

#[test]
fn r2_r3_wrong_environment_and_wrong_chain_peer_candidates_rejected() {
    let m = manifest();
    let keys = signing_keys(m);
    for path in [
        &m.negative_peer_candidate_envelopes.wrong_environment,
        &m.negative_peer_candidate_envelopes.wrong_chain,
    ] {
        let scratch = tmpdir("wrong-domain");
        let out = PeerCandidateValidator::new(enabled_config()).try_accept(load_envelope(path), &peer_ctx(&scratch, &keys));
        assert!(matches!(out, PeerCandidateOutcome::Rejected(_)), "{:?}", out);
    }
}

#[test]
fn r4_wrong_genesis_ratification_rejected() {
    let m = manifest();
    let rat = load_ratification(&m.negative_peer_candidate_envelopes.wrong_genesis_ratification);
    let cfg = genesis(m);
    let hash = expected_genesis_hash(m);
    assert!(
        qbind_ledger::verify_bundle_signing_key_ratification_v2(RatificationV2VerifierInputs {
            ratification: &rat,
            authority: cfg.authority.as_ref().expect("authority"),
            expected_chain_id: &m.chain_id_hex,
            expected_environment: NetworkEnvironmentPolicy::Testnet,
            expected_genesis_hash: &hash,
        })
        .is_err()
    );
}

#[test]
fn r5_bad_signature_peer_candidate_rejected() {
    let m = manifest();
    let keys = signing_keys(m);
    let scratch = tmpdir("bad-sig");
    let out = PeerCandidateValidator::new(enabled_config()).try_accept(
        load_envelope(&m.negative_peer_candidate_envelopes.bad_signature),
        &peer_ctx(&scratch, &keys),
    );
    assert!(matches!(out, PeerCandidateOutcome::Rejected(_)), "{:?}", out);
}

#[test]
fn r6_lower_sequence_candidate_rejected_by_sequence_guard() {
    let m = manifest();
    let env = load_envelope(&m.negative_peer_candidate_envelopes.lower_sequence);
    let bundle: TrustBundle = serde_json::from_slice(&env.bundle_bytes).expect("parse bundle");
    let seq_path = tmpdir("lower-seq").join("pqc_trust_bundle_sequence.json");
    let record = PersistentTrustBundleSequenceRecord::new(
        TrustBundleEnvironment::Testnet,
        m.chain_id_hex.clone(),
        2,
        m.expected_candidate_fingerprint.clone(),
        1_000,
    );
    std::fs::write(&seq_path, serde_json::to_vec_pretty(&record).unwrap()).expect("write seq");
    assert!(peek_sequence(
        &seq_path,
        NetworkEnvironment::Testnet,
        NetworkEnvironment::Testnet.chain_id(),
        bundle.sequence,
        &canonical_fingerprint(&bundle),
    )
    .is_err());
}

#[test]
fn r7_same_sequence_different_digest_rejected_by_sequence_guard() {
    let m = manifest();
    let env = load_envelope(&m.negative_peer_candidate_envelopes.same_sequence_different_digest);
    let bundle: TrustBundle = serde_json::from_slice(&env.bundle_bytes).expect("parse bundle");
    let seq_path = tmpdir("same-seq-diff").join("pqc_trust_bundle_sequence.json");
    let record = PersistentTrustBundleSequenceRecord::new(
        TrustBundleEnvironment::Testnet,
        m.chain_id_hex.clone(),
        2,
        m.expected_candidate_fingerprint.clone(),
        1_000,
    );
    std::fs::write(&seq_path, serde_json::to_vec_pretty(&record).unwrap()).expect("write seq");
    assert!(peek_sequence(
        &seq_path,
        NetworkEnvironment::Testnet,
        NetworkEnvironment::Testnet.chain_id(),
        bundle.sequence,
        &canonical_fingerprint(&bundle),
    )
    .is_err());
}

#[test]
fn r8_ambiguous_v1_v2_material_rejected() {
    let m = manifest();
    let keys = signing_keys(m);
    let scratch = tmpdir("ambiguous");
    let out = PeerCandidateValidator::new(enabled_config()).try_accept(
        load_envelope(&m.negative_peer_candidate_envelopes.ambiguous_v1_v2),
        &peer_ctx(&scratch, &keys),
    );
    assert!(matches!(out, PeerCandidateOutcome::Rejected(_)), "{:?}", out);
}

#[test]
fn r9_mainnet_fixture_use_remains_refused_or_fixture_only() {
    let m = manifest();
    assert!(m.mainnet_fixture.is_none());
    assert_eq!(m.environment, "testnet");
    assert_ne!(chain_id_hex(NetworkEnvironment::Mainnet.chain_id()), m.chain_id_hex);
    assert!(!m.authority_root_fingerprint.is_empty());
}
