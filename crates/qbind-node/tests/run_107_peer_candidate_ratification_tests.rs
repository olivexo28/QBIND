//! Run 107 — ratification enforcement on the local
//! `--p2p-trust-bundle-peer-candidate-check` path.
//!
//! These tests exercise the pure Run 077 local-check entry point with
//! the Run 105 ratification wrapper added by Run 107. They do not touch
//! live wire validation, propagation, reload-apply, or SIGHUP paths.

use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::test_helpers as ratification_helpers,
    compute_canonical_genesis_hash, BundleSigningRatification, GenesisAllocation,
    GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisHash,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    RatificationEnforcementFailure, RatificationEnforcementPolicy, RatificationEnvironment,
    RatificationFailure, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::metrics::P2pMetrics;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_binary::{
    run_local_check, run_local_check_with_ratification, Run077Inputs, Run077Result,
};
use qbind_node::pqc_ratification_policy::{
    ratification_gate_decision, GateInvokeReason, GateSkipReason, RatificationGateDecision,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::{
    PeerCandidateEnvelope, PeerCandidateOutcome, PeerCandidateRejection,
};
use qbind_node::pqc_trust_reload::{
    RatificationEnforcementContext, ReloadCheckError, ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", x);
    }
    s
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run107-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&p).expect("create_dir_all");
    p
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

struct Harness {
    env: NetworkEnvironment,
    signing_keys: BundleSigningKeySet,
    signing_pk: Vec<u8>,
    signing_key_id: [u8; 32],
    signing_sk: Vec<u8>,
    authority_sk: Vec<u8>,
    genesis_cfg: GenesisConfig,
    canonical_hash: GenesisHash,
    chain_id_str: String,
    root_id_hex: String,
    root_pk_hex: String,
}

fn harness(env: NetworkEnvironment) -> Harness {
    let (signing_pk, signing_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key");
    let signing_key_id = derive_signing_key_id(&signing_pk);
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: signing_key_id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: signing_pk.clone(),
    }]);
    let root = mint_devnet_root().expect("mint root");
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let chain_id_str = chain_id_hex(env.chain_id());
    let mut genesis_cfg = GenesisConfig::new(
        &chain_id_str,
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
    let auth_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run107-bundle-signing-authority",
    );
    genesis_cfg.authority = Some(GenesisAuthorityConfig::new(vec![auth_root]));
    let canonical_hash = compute_canonical_genesis_hash(&genesis_cfg, env_policy(env));
    Harness {
        env,
        signing_keys,
        signing_pk,
        signing_key_id,
        signing_sk,
        authority_sk,
        genesis_cfg,
        canonical_hash,
        chain_id_str,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

fn build_signed_bundle(h: &Harness, sequence: u64) -> TrustBundle {
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
    let sig = sign_bundle_devnet_helper(&bundle, h.signing_key_id, &h.signing_sk).expect("sign");
    bundle.signature = Some(sig);
    bundle
}

fn bundle_to_bytes(b: &TrustBundle) -> Vec<u8> {
    serde_json::to_vec(b).expect("serialise bundle")
}

fn loader_fingerprint_prefix(bytes: &[u8], h: &Harness) -> String {
    let dir = tmpdir("fpprobe");
    let path = dir.join("probe.json");
    std::fs::write(&path, bytes).expect("write probe");
    let v = qbind_node::pqc_trust_reload::validate_candidate_bundle(ReloadCheckInputs {
        candidate_path: &path,
        environment: h.env,
        chain_id: h.env.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
    })
    .expect("probe validates");
    v.fingerprint_prefix
}

fn envelope_for(
    h: &Harness,
    bytes: Vec<u8>,
    sequence: u64,
    prefix: String,
) -> PeerCandidateEnvelope {
    let len = bytes.len();
    PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some("peer-test-run107".to_string()),
        environment: bundle_env(h.env),
        chain_id_hex: h.chain_id_str.clone(),
        declared_sequence: sequence,
        declared_fingerprint_prefix: prefix,
        declared_length: len,
        bundle_bytes: bytes,
    }
}

fn write_envelope_fixture(dir: &Path, envelope: &PeerCandidateEnvelope) -> PathBuf {
    let path = dir.join("envelope.json");
    std::fs::write(&path, serde_json::to_vec_pretty(envelope).unwrap()).unwrap();
    path
}

fn inputs<'a>(
    h: &'a Harness,
    envelope_path: &'a Path,
    scratch: &'a Path,
    seq_path: Option<&'a Path>,
) -> Run077Inputs<'a> {
    Run077Inputs {
        validation_enabled_flag: true,
        envelope_path: Some(envelope_path),
        environment: h.env,
        chain_id: h.env.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: seq_path,
        local_leaf_cert_bytes: None,
        scratch_dir: scratch,
        now_ms: 1_000,
    }
}

fn ratification_for(h: &Harness) -> BundleSigningRatification {
    let authority_fp = &h
        .genesis_cfg
        .authority
        .as_ref()
        .expect("authority")
        .bundle_signing_authority_roots[0]
        .key_fingerprint;
    ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        rat_env(h.env),
        h.canonical_hash,
        authority_fp,
        &h.authority_sk,
        &h.signing_pk,
    )
}

fn ctx<'a>(
    h: &'a Harness,
    ratification: Option<&'a BundleSigningRatification>,
) -> RatificationEnforcementContext<'a> {
    RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().expect("authority"),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: env_policy(h.env),
        expected_chain_id_str: &h.chain_id_str,
        ratification,
        policy: RatificationEnforcementPolicy::Strict,
    }
}

fn assert_seq_file_unchanged(path: &Path, existed_before: bool) {
    assert_eq!(
        path.exists(),
        existed_before,
        "Run 107 peer-candidate check must not create/delete sequence state"
    );
}

fn run_with_ratification(
    tag: &str,
    h: &Harness,
    ratification: Option<&BundleSigningRatification>,
) -> (Run077Result, PathBuf) {
    let dir = tmpdir(tag);
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let seq_path = sequence_file_path(&dir);
    let bundle = build_signed_bundle(h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, h);
    let envelope = envelope_for(h, bytes, 1, prefix);
    let path = write_envelope_fixture(&dir, &envelope);
    let result = run_local_check_with_ratification(
        inputs(h, &path, &scratch, Some(&seq_path)),
        &P2pMetrics::default(),
        &ctx(h, ratification),
    );
    (result, seq_path)
}

fn ratification_failure(result: Run077Result) -> RatificationEnforcementFailure {
    match result {
        Run077Result::Ran {
            outcome:
                PeerCandidateOutcome::Rejected(PeerCandidateRejection::ValidationFailed(
                    ReloadCheckError::RatificationRefused(e),
                )),
            ..
        } => e,
        other => panic!("expected ratification refusal, got {:?}", other),
    }
}

#[test]
fn run107_peer_candidate_policy_matches_run106() {
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Mainnet, false),
        RatificationGateDecision::Invoke(GateInvokeReason::MainnetDefaultStrict)
    );
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Testnet, false),
        RatificationGateDecision::Invoke(GateInvokeReason::TestnetDefaultStrict)
    );
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Devnet, false),
        RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn)
    );
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Devnet, true),
        RatificationGateDecision::Invoke(GateInvokeReason::DevnetOperatorOptIn)
    );
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Mainnet, true),
        RatificationGateDecision::Invoke(GateInvokeReason::MainnetDefaultStrict)
    );
}

#[test]
fn run107_valid_mainnet_ratification_passes_and_does_not_write_sequence() {
    let h = harness(NetworkEnvironment::Mainnet);
    let ratification = ratification_for(&h);
    let (result, seq_path) = run_with_ratification("valid-mainnet", &h, Some(&ratification));
    assert_eq!(result.exit_code(), 0);
    match result {
        Run077Result::Ran {
            outcome: PeerCandidateOutcome::Validated(v),
            ..
        } => assert!(v.validated.signature_verified),
        other => panic!("expected valid peer candidate, got {:?}", other),
    }
    assert_seq_file_unchanged(&seq_path, false);
}

#[test]
fn run107_missing_ratification_rejects_mainnet_without_sequence_write() {
    let h = harness(NetworkEnvironment::Mainnet);
    let (result, seq_path) = run_with_ratification("missing-mainnet", &h, None);
    let err = ratification_failure(result);
    assert!(matches!(
        err,
        RatificationEnforcementFailure::Missing { .. }
    ));
    assert_seq_file_unchanged(&seq_path, false);
}

#[test]
fn run107_devnet_without_opt_in_preserves_legacy_unratified_local_check() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("devnet-no-opt-in");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let bundle = build_signed_bundle(&h, 1);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h);
    let envelope = envelope_for(&h, bytes, 1, prefix);
    let path = write_envelope_fixture(&dir, &envelope);
    let result = run_local_check(inputs(&h, &path, &scratch, None), &P2pMetrics::default());
    assert_eq!(result.exit_code(), 0);
}

#[test]
fn run107_bad_signature_wrong_chain_wrong_env_and_unsupported_suite_reject_precisely() {
    let h = harness(NetworkEnvironment::Mainnet);

    let mut bad_sig = ratification_for(&h);
    bad_sig.signature[0] ^= 0xFF;
    assert!(matches!(
        ratification_failure(run_with_ratification("bad-sig", &h, Some(&bad_sig)).0),
        RatificationEnforcementFailure::Verifier(RatificationFailure::BadSignature)
    ));

    let mut wrong_chain = ratification_for(&h);
    wrong_chain.chain_id = "0000000000000000".to_string();
    assert!(matches!(
        ratification_failure(run_with_ratification("wrong-chain", &h, Some(&wrong_chain)).0),
        RatificationEnforcementFailure::Verifier(RatificationFailure::ChainMismatch { .. })
    ));

    let mut wrong_env = ratification_for(&h);
    wrong_env.environment = RatificationEnvironment::Devnet;
    assert!(matches!(
        ratification_failure(run_with_ratification("wrong-env", &h, Some(&wrong_env)).0),
        RatificationEnforcementFailure::Verifier(RatificationFailure::EnvironmentMismatch { .. })
    ));

    let mut unsupported_suite = ratification_for(&h);
    unsupported_suite.signature_suite_id = 99;
    assert!(matches!(
        ratification_failure(
            run_with_ratification("unsupported-suite", &h, Some(&unsupported_suite)).0
        ),
        RatificationEnforcementFailure::Verifier(RatificationFailure::UnsupportedSuite { .. })
    ));
}

#[test]
fn run107_unknown_transport_missing_and_malformed_authority_reject_precisely() {
    let h = harness(NetworkEnvironment::Mainnet);

    let mut unknown = ratification_for(&h);
    unknown.authority_root_fingerprint = "aa".repeat(32);
    assert!(matches!(
        ratification_failure(run_with_ratification("unknown-root", &h, Some(&unknown)).0),
        RatificationEnforcementFailure::Verifier(RatificationFailure::UnknownAuthorityRoot { .. })
    ));

    let mut no_key_material = harness(NetworkEnvironment::Mainnet);
    no_key_material
        .genesis_cfg
        .authority
        .as_mut()
        .unwrap()
        .bundle_signing_authority_roots[0]
        .public_key_hex = None;
    no_key_material.canonical_hash = compute_canonical_genesis_hash(
        &no_key_material.genesis_cfg,
        env_policy(no_key_material.env),
    );
    let no_key_rat = ratification_for(&no_key_material);
    let missing_key_err = ratification_failure(
        run_with_ratification("missing-key-material", &no_key_material, Some(&no_key_rat)).0,
    );
    assert!(
        matches!(
            missing_key_err,
            RatificationEnforcementFailure::Verifier(
                RatificationFailure::AuthorityKeyMaterialUnavailable { .. }
            )
        ),
        "expected AuthorityKeyMaterialUnavailable, got {:?}",
        missing_key_err
    );

    let mut malformed = harness(NetworkEnvironment::Mainnet);
    malformed
        .genesis_cfg
        .authority
        .as_mut()
        .unwrap()
        .bundle_signing_authority_roots[0]
        .public_key_hex = Some("00".to_string());
    malformed.canonical_hash =
        compute_canonical_genesis_hash(&malformed.genesis_cfg, env_policy(malformed.env));
    let malformed_rat = ratification_for(&malformed);
    assert!(matches!(
        ratification_failure(
            run_with_ratification("malformed-key-material", &malformed, Some(&malformed_rat)).0
        ),
        RatificationEnforcementFailure::Verifier(
            RatificationFailure::AuthorityKeyMaterialMalformed { .. }
        )
    ));

    let mut transport = harness(NetworkEnvironment::Mainnet);
    let transport_root = transport
        .genesis_cfg
        .authority
        .as_ref()
        .unwrap()
        .bundle_signing_authority_roots[0]
        .clone();
    let transport_fp = transport_root.key_fingerprint.clone();
    let (other_pk, _other_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let unrelated_bundle_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &other_pk,
        "unrelated-bundle-authority",
    );
    {
        let authority = transport.genesis_cfg.authority.as_mut().unwrap();
        authority.pqc_transport_roots = vec![transport_root];
        authority.bundle_signing_authority_roots = vec![unrelated_bundle_root];
    }
    transport.canonical_hash =
        compute_canonical_genesis_hash(&transport.genesis_cfg, env_policy(transport.env));
    let transport_rat = ratification_helpers::build_signed_ratification(
        &transport.chain_id_str,
        rat_env(transport.env),
        transport.canonical_hash,
        &transport_fp,
        &transport.authority_sk,
        &transport.signing_pk,
    );
    let transport_err = ratification_failure(
        run_with_ratification("transport-root", &transport, Some(&transport_rat)).0,
    );
    assert!(
        matches!(
            transport_err,
            RatificationEnforcementFailure::Verifier(
                RatificationFailure::TransportRootNotAllowed { .. }
            )
        ),
        "expected TransportRootNotAllowed, got {:?}",
        transport_err
    );
}