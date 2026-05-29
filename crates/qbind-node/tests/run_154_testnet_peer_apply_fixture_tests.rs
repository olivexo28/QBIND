//! Run 154 — source/test TestNet fixture tooling for a future Run 155
//! release-binary TestNet peer-driven apply evidence harness.
//!
//! Run 154 is **source/test fixture tooling only**. It closes the
//! fixture-tooling blocker that caused the Run 153 A2 TestNet evidence to
//! be deferred. Release-binary TestNet end-to-end peer-driven apply
//! evidence remains deferred to Run 155. MainNet remains refused.
//! Governance, KMS/HSM, signing-key rotation/revocation lifecycle, and
//! validator-set rotation all remain open. No full C4 or C5 closure is
//! claimed.
//!
//! These tests mint TestNet material with the same public library APIs
//! that the (now TestNet-aware) Run 133 v2 fixture helper
//! (`crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`)
//! uses, and prove the verify/reject matrix demanded by
//! `task/RUN_154_TASK.txt`:
//!
//!   * a valid TestNet trust bundle verifies under a TestNet context;
//!   * a valid TestNet v2 ratification sidecar verifies under a TestNet
//!     context;
//!   * a valid TestNet peer-candidate `0x05` envelope validates under a
//!     TestNet context;
//!   * the same artifacts FAIL under a DevNet context;
//!   * the same artifacts FAIL under a MainNet context (MainNet refused);
//!   * wrong-chain / wrong-genesis variants fail;
//!   * the bad-signature variant fails;
//!   * lower-sequence and same-sequence different-digest variants fail
//!     through the v2 authority-marker comparison;
//!   * every TestNet artifact is domain-bound (environment = TestNet,
//!     TestNet chain_id, TestNet genesis hash, the minted authority-root
//!     fingerprint, and the v2 authority-domain sequence);
//!   * DevNet fixture behaviour is unchanged (DevNet material is bound to
//!     the DevNet domain and is distinct from TestNet material);
//!   * helper output is deterministic in its domain fields and the
//!     non-deterministic fields (ephemeral keys / signatures / genesis
//!     hash derived from the minted authority key) are recorded
//!     explicitly;
//!   * no production source-code anchor is introduced (the authority-root
//!     fingerprint is derived from freshly minted ephemeral key
//!     material);
//!   * no fallback root or fallback signing key is introduced (ephemeral
//!     material differs run-to-run).
//!
//! No mutation of any live trust state, sequence file, or marker file is
//! performed by any test below; the only on-disk writes are explicit
//! fixture / pre-seed files inside per-test temp directories.

use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::v2_test_helpers as ratification_v2_helpers,
    compute_canonical_genesis_hash, BundleSigningRatificationV2,
    BundleSigningRatificationV2Action, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisHash,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    RatificationEnvironment, RatificationV2VerifierInputs, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_marker_acceptance::{
    verify_marker_for_validation_only_v2, ValidationOnlyMarkerV2AcceptReason,
    ValidationOnlyMarkerV2Error, ValidationOnlyMarkerV2Inputs,
};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, derive_authority_state_v2_from_ratification,
    persist_authority_state_v2_atomic, AuthorityStateDerivationV2Inputs,
    AuthorityStateUpdateSource,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    canonical_fingerprint, derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey,
    BundleSigningKeySet, RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::{
    PeerCandidateConfig, PeerCandidateEnvelope, PeerCandidateOutcome,
    PeerCandidateRuntimeContext, PeerCandidateValidator,
};
use qbind_node::pqc_trust_reload::{validate_candidate_bundle, ReloadCheckInputs};
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;

// =====================================================================
// Helpers (mirror the Run 133 helper / Run 142 test shape).
// =====================================================================

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
        "qbind-run154-{}-{}-{}",
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

fn genesis_chain_id(env: NetworkEnvironment) -> &'static str {
    match env {
        NetworkEnvironment::Mainnet => "qbind-mainnet-v0",
        NetworkEnvironment::Testnet => "qbind-testnet-v0",
        NetworkEnvironment::Devnet => "qbind-devnet-v0",
    }
}

/// A TestNet (or other-environment) fixture harness mirroring the Run 133
/// helper: ephemeral ML-DSA-44 authority + bundle-signing material, an
/// ephemeral transport root, a genesis bound to the minted authority key,
/// and the canonical genesis hash for the environment.
struct Harness {
    env: NetworkEnvironment,
    signing_keys: BundleSigningKeySet,
    signing_pk: Vec<u8>,
    signing_key_id: [u8; 32],
    signing_sk: Vec<u8>,
    authority_pk: Vec<u8>,
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
    let root = mint_devnet_root().expect("mint transport root");
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let chain_id_str = chain_id_hex(env.chain_id());
    let mut genesis_cfg = GenesisConfig::new(
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
    let auth_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run154-bundle-signing-authority",
    );
    genesis_cfg.authority = Some(GenesisAuthorityConfig::new(vec![auth_root]));
    let canonical_hash = compute_canonical_genesis_hash(&genesis_cfg, env_policy(env));
    Harness {
        env,
        signing_keys,
        signing_pk,
        signing_key_id,
        signing_sk,
        authority_pk,
        authority_sk,
        genesis_cfg,
        canonical_hash,
        chain_id_str,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

fn build_signed_bundle(h: &Harness, sequence: u64, generated_at: u64) -> TrustBundle {
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: bundle_env(h.env),
        chain_id: Some(h.chain_id_str.clone()),
        generated_at,
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

/// Authoritative declared-fingerprint-prefix: parse the candidate via the
/// same loader under a TestNet context and take the first 8 hex chars.
fn loader_fingerprint_prefix(bundle_bytes: &[u8], h: &Harness) -> String {
    let dir = tmpdir("fpprobe");
    let path = dir.join("probe.json");
    std::fs::write(&path, bundle_bytes).expect("write probe");
    let inputs = ReloadCheckInputs {
        candidate_path: &path,
        environment: h.env,
        chain_id: h.env.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
    };
    validate_candidate_bundle(inputs)
        .expect("probe validates")
        .fingerprint_prefix
}

fn envelope_from_bundle(
    h: &Harness,
    bundle: &TrustBundle,
    peer_id: &str,
    declared_sequence: u64,
) -> PeerCandidateEnvelope {
    let fp = hex_lower(&canonical_fingerprint(bundle));
    let bytes = serde_json::to_vec_pretty(bundle).expect("serialise bundle");
    let len = bytes.len();
    PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some(peer_id.to_string()),
        environment: bundle_env(h.env),
        chain_id_hex: h.chain_id_str.clone(),
        declared_sequence,
        declared_fingerprint_prefix: fp[..8].to_string(),
        declared_length: len,
        bundle_bytes: bytes,
    }
}

/// Build a v2 ratification sidecar bound to `h`'s domain, ratifying a
/// specific target signing key at `sequence`.
fn v2_ratification_for_target(
    h: &Harness,
    target_pk: &[u8],
    sequence: u64,
) -> BundleSigningRatificationV2 {
    let authority = h.genesis_cfg.authority.as_ref().expect("authority");
    ratification_v2_helpers::build_signed_ratification_v2(
        &h.chain_id_str,
        rat_env(h.env),
        h.canonical_hash,
        authority.authority_policy_version,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        target_pk,
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

fn v2_ratification_for(h: &Harness, sequence: u64) -> BundleSigningRatificationV2 {
    v2_ratification_for_target(h, &h.signing_pk, sequence)
}

fn verifier_inputs<'a>(
    h: &'a Harness,
    env: NetworkEnvironment,
    ratification: &'a BundleSigningRatificationV2,
) -> RatificationV2VerifierInputs<'a> {
    RatificationV2VerifierInputs {
        ratification,
        authority: h.genesis_cfg.authority.as_ref().expect("authority"),
        expected_chain_id: &h.chain_id_str,
        expected_environment: env_policy(env),
        expected_genesis_hash: &h.canonical_hash,
    }
}

fn genesis_hash_hex(h: &Harness) -> String {
    hex_lower(&h.canonical_hash)
}

/// Pre-seed a persisted v2 marker on disk from a verified v2 ratification
/// (mirrors the Run 142 pre-seed primitive).
fn preseed_v2_marker(h: &Harness, marker_path: &Path, ratification: &BundleSigningRatificationV2) {
    let ratified = qbind_ledger::verify_bundle_signing_key_ratification_v2(verifier_inputs(
        h,
        h.env,
        ratification,
    ))
    .expect("pre-seed: v2 verifier must succeed");
    let record = derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
        runtime_env: h.env,
        runtime_chain_id: h.env.chain_id(),
        runtime_genesis_hash_hex: &genesis_hash_hex(h),
        ratification,
        ratified: &ratified,
        update_source: AuthorityStateUpdateSource::TestOrFixture,
        updated_at_unix_secs: 1_000,
    })
    .expect("pre-seed: derive v2 marker");
    persist_authority_state_v2_atomic(marker_path, &record).expect("pre-seed: persist v2 marker");
}

/// Run the validation-only v2 marker comparison for `ratification` against
/// the on-disk marker at `marker_path`, under `h`'s TestNet domain.
fn marker_check(
    h: &Harness,
    marker_path: &Path,
    ratification: &BundleSigningRatificationV2,
) -> Result<ValidationOnlyMarkerV2AcceptReason, ValidationOnlyMarkerV2Error> {
    let ratified = qbind_ledger::verify_bundle_signing_key_ratification_v2(verifier_inputs(
        h,
        h.env,
        ratification,
    ))
    .expect("candidate v2 verifier must succeed before marker comparison");
    let hash_hex = genesis_hash_hex(h);
    verify_marker_for_validation_only_v2(ValidationOnlyMarkerV2Inputs {
        marker_path,
        runtime_env: h.env,
        runtime_chain_id: h.env.chain_id(),
        runtime_genesis_hash_hex: &hash_hex,
        ratification,
        ratified: &ratified,
    })
}

fn enabled_config() -> PeerCandidateConfig {
    PeerCandidateConfig {
        enabled: true,
        ..PeerCandidateConfig::default()
    }
}

fn peer_candidate_ctx<'a>(
    env: NetworkEnvironment,
    scratch: &'a Path,
    keys: &'a BundleSigningKeySet,
) -> PeerCandidateRuntimeContext<'a> {
    PeerCandidateRuntimeContext {
        expected_environment: env,
        expected_chain_id: env.chain_id(),
        scratch_dir: scratch,
        validation_time_secs: 100,
        signing_keys: keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
        now_ms: 1_000,
    }
}

// =====================================================================
// 1. Valid TestNet bundle verifies under TestNet context.
// =====================================================================

#[test]
fn run154_testnet_valid_bundle_verifies_under_testnet_context() {
    let h = harness(NetworkEnvironment::Testnet);
    let bundle = build_signed_bundle(&h, 1, 10);
    let bytes = bundle_to_bytes(&bundle);
    let path = tmpdir("valid-bundle").join("bundle.json");
    std::fs::write(&path, &bytes).expect("write bundle");

    let inputs = ReloadCheckInputs {
        candidate_path: &path,
        environment: NetworkEnvironment::Testnet,
        chain_id: NetworkEnvironment::Testnet.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
    };
    assert!(
        validate_candidate_bundle(inputs).is_ok(),
        "TestNet bundle must verify under a TestNet context"
    );
}

// =====================================================================
// 2. Same TestNet bundle FAILS under DevNet / MainNet contexts.
// =====================================================================

fn assert_bundle_fails_under(h: &Harness, ctx_env: NetworkEnvironment) {
    let bundle = build_signed_bundle(h, 1, 10);
    let bytes = bundle_to_bytes(&bundle);
    let path = tmpdir("xdomain-bundle").join("bundle.json");
    std::fs::write(&path, &bytes).expect("write bundle");

    let inputs = ReloadCheckInputs {
        candidate_path: &path,
        environment: ctx_env,
        chain_id: ctx_env.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
    };
    assert!(
        validate_candidate_bundle(inputs).is_err(),
        "TestNet bundle must FAIL under a {:?} context",
        ctx_env
    );
}

#[test]
fn run154_testnet_bundle_fails_under_devnet_context() {
    let h = harness(NetworkEnvironment::Testnet);
    assert_bundle_fails_under(&h, NetworkEnvironment::Devnet);
}

#[test]
fn run154_testnet_bundle_fails_under_mainnet_context() {
    let h = harness(NetworkEnvironment::Testnet);
    assert_bundle_fails_under(&h, NetworkEnvironment::Mainnet);
}

// =====================================================================
// 3. Valid TestNet v2 ratification verifies under TestNet context and
//    FAILS under DevNet / MainNet contexts (MainNet refused).
// =====================================================================

#[test]
fn run154_testnet_v2_ratification_verifies_under_testnet_context() {
    let h = harness(NetworkEnvironment::Testnet);
    let rat = v2_ratification_for(&h, 1);
    assert!(
        qbind_ledger::verify_bundle_signing_key_ratification_v2(verifier_inputs(
            &h,
            NetworkEnvironment::Testnet,
            &rat
        ))
        .is_ok(),
        "TestNet v2 ratification must verify under a TestNet context"
    );
}

#[test]
fn run154_testnet_v2_ratification_fails_under_devnet_context() {
    let h = harness(NetworkEnvironment::Testnet);
    let rat = v2_ratification_for(&h, 1);
    assert!(
        qbind_ledger::verify_bundle_signing_key_ratification_v2(verifier_inputs(
            &h,
            NetworkEnvironment::Devnet,
            &rat
        ))
        .is_err(),
        "TestNet v2 ratification must FAIL under a DevNet context"
    );
}

#[test]
fn run154_testnet_v2_ratification_fails_under_mainnet_context() {
    let h = harness(NetworkEnvironment::Testnet);
    let rat = v2_ratification_for(&h, 1);
    assert!(
        qbind_ledger::verify_bundle_signing_key_ratification_v2(verifier_inputs(
            &h,
            NetworkEnvironment::Mainnet,
            &rat
        ))
        .is_err(),
        "MainNet remains refused: TestNet v2 ratification must FAIL under a MainNet context"
    );
}

// =====================================================================
// 4. TestNet peer-candidate validates under TestNet context and FAILS
//    under DevNet / MainNet contexts.
// =====================================================================

#[test]
fn run154_testnet_peer_candidate_validates_under_testnet_context() {
    let h = harness(NetworkEnvironment::Testnet);
    let dir = tmpdir("pc-valid");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).expect("scratch");

    let bundle = build_signed_bundle(&h, 2, 20);
    let bytes = bundle_to_bytes(&bundle);
    let prefix = loader_fingerprint_prefix(&bytes, &h);
    let mut env = envelope_from_bundle(&h, &bundle, "run154-testnet-active", 2);
    env.declared_fingerprint_prefix = prefix;

    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(
        env,
        &peer_candidate_ctx(NetworkEnvironment::Testnet, &scratch, &h.signing_keys),
    );
    match out {
        PeerCandidateOutcome::Validated(vc) => {
            assert_eq!(vc.validated.sequence, 2);
            assert!(vc.validated.signature_verified);
        }
        other => panic!("expected TestNet Validated, got {:?}", other),
    }
}

#[test]
fn run154_testnet_peer_candidate_fails_under_devnet_context() {
    let h = harness(NetworkEnvironment::Testnet);
    let dir = tmpdir("pc-xdomain");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).expect("scratch");

    let bundle = build_signed_bundle(&h, 2, 20);
    let env = envelope_from_bundle(&h, &bundle, "run154-testnet-active", 2);

    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(
        env,
        &peer_candidate_ctx(NetworkEnvironment::Devnet, &scratch, &h.signing_keys),
    );
    assert!(
        matches!(out, PeerCandidateOutcome::Rejected(_)),
        "TestNet peer-candidate must be rejected under a DevNet context, got {:?}",
        out
    );
}

#[test]
fn run154_testnet_peer_candidate_fails_under_mainnet_context() {
    let h = harness(NetworkEnvironment::Testnet);
    let dir = tmpdir("pc-mainnet");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).expect("scratch");

    let bundle = build_signed_bundle(&h, 2, 20);
    let env = envelope_from_bundle(&h, &bundle, "run154-testnet-active", 2);

    let mut v = PeerCandidateValidator::new(enabled_config());
    let out = v.try_accept(
        env,
        &peer_candidate_ctx(NetworkEnvironment::Mainnet, &scratch, &h.signing_keys),
    );
    assert!(
        matches!(out, PeerCandidateOutcome::Rejected(_)),
        "TestNet peer-candidate must be rejected under a MainNet context, got {:?}",
        out
    );
}

// =====================================================================
// 5. Wrong-chain / wrong-genesis / bad-signature variants fail.
// =====================================================================

#[test]
fn run154_testnet_wrong_chain_v2_ratification_fails() {
    let h = harness(NetworkEnvironment::Testnet);
    let mut rat = v2_ratification_for(&h, 1);
    rat.chain_id = "ffffffffffffffff".to_string();
    assert!(
        qbind_ledger::verify_bundle_signing_key_ratification_v2(verifier_inputs(
            &h,
            NetworkEnvironment::Testnet,
            &rat
        ))
        .is_err(),
        "wrong-chain v2 ratification must fail"
    );
}

#[test]
fn run154_testnet_wrong_genesis_v2_ratification_fails() {
    let h = harness(NetworkEnvironment::Testnet);
    let mut rat = v2_ratification_for(&h, 1);
    let mut bad = h.canonical_hash;
    bad[0] ^= 0xff;
    rat.genesis_hash = bad;
    assert!(
        qbind_ledger::verify_bundle_signing_key_ratification_v2(verifier_inputs(
            &h,
            NetworkEnvironment::Testnet,
            &rat
        ))
        .is_err(),
        "wrong-genesis v2 ratification must fail"
    );
}

#[test]
fn run154_testnet_bad_signature_v2_ratification_fails() {
    let h = harness(NetworkEnvironment::Testnet);
    let mut rat = v2_ratification_for(&h, 1);
    if !rat.signature.is_empty() {
        rat.signature[0] ^= 0xff;
    }
    assert!(
        qbind_ledger::verify_bundle_signing_key_ratification_v2(verifier_inputs(
            &h,
            NetworkEnvironment::Testnet,
            &rat
        ))
        .is_err(),
        "bad-signature v2 ratification must fail"
    );
}

#[test]
fn run154_testnet_bad_signature_bundle_fails() {
    let h = harness(NetworkEnvironment::Testnet);
    let mut bundle = build_signed_bundle(&h, 1, 10);
    if let Some(sig) = bundle.signature.as_mut() {
        let mut bytes: Vec<u8> = (0..sig.sig_bytes.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig.sig_bytes[i..i + 2], 16).expect("hex"))
            .collect();
        bytes[0] ^= 0xff;
        sig.sig_bytes = hex_lower(&bytes);
    }
    let bytes = bundle_to_bytes(&bundle);
    let path = tmpdir("bad-sig-bundle").join("bundle.json");
    std::fs::write(&path, &bytes).expect("write bundle");

    let inputs = ReloadCheckInputs {
        candidate_path: &path,
        environment: NetworkEnvironment::Testnet,
        chain_id: NetworkEnvironment::Testnet.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
    };
    assert!(
        validate_candidate_bundle(inputs).is_err(),
        "bad-signature TestNet bundle must fail"
    );
}

// =====================================================================
// 6. Lower-sequence and same-sequence different-digest fail through the
//    v2 authority-marker comparison.
// =====================================================================

#[test]
fn run154_testnet_lower_sequence_fails_through_v2_marker() {
    let h = harness(NetworkEnvironment::Testnet);
    let dir = tmpdir("lower-seq");
    let marker_path = authority_state_file_path(&dir);

    // Persisted marker at seq=5.
    preseed_v2_marker(&h, &marker_path, &v2_ratification_for(&h, 5));
    let marker_before = std::fs::read(&marker_path).expect("marker exists");

    // Candidate at seq=2 (lower).
    let candidate = v2_ratification_for(&h, 2);
    match marker_check(&h, &marker_path, &candidate) {
        Err(ValidationOnlyMarkerV2Error::LowerV2SequenceRefused {
            persisted_sequence,
            candidate_sequence,
        }) => {
            assert_eq!(persisted_sequence, 5);
            assert_eq!(candidate_sequence, 2);
        }
        other => panic!("expected LowerV2SequenceRefused, got {:?}", other),
    }
    // Validation-only: marker is never rewritten.
    assert_eq!(
        std::fs::read(&marker_path).expect("marker still exists"),
        marker_before,
        "validation-only marker comparison must not rewrite the marker"
    );
}

#[test]
fn run154_testnet_same_sequence_different_digest_fails_through_v2_marker() {
    let h = harness(NetworkEnvironment::Testnet);
    let dir = tmpdir("same-seq-diff");
    let marker_path = authority_state_file_path(&dir);

    // Persisted marker at seq=3 ratifying the active signing key.
    preseed_v2_marker(&h, &marker_path, &v2_ratification_for(&h, 3));
    let marker_before = std::fs::read(&marker_path).expect("marker exists");

    // Candidate at the SAME seq=3 ratifying a DIFFERENT target key -> a
    // different digest at the same sequence (equivocation).
    let (other_pk, _other_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 conflicting target key");
    let candidate = v2_ratification_for_target(&h, &other_pk, 3);
    match marker_check(&h, &marker_path, &candidate) {
        Err(ValidationOnlyMarkerV2Error::SameSequenceDifferentDigestRefused { sequence, .. }) => {
            assert_eq!(sequence, 3);
        }
        other => panic!("expected SameSequenceDifferentDigestRefused, got {:?}", other),
    }
    assert_eq!(
        std::fs::read(&marker_path).expect("marker still exists"),
        marker_before,
        "validation-only marker comparison must not rewrite the marker"
    );
}

#[test]
fn run154_testnet_higher_sequence_accepted_through_v2_marker() {
    let h = harness(NetworkEnvironment::Testnet);
    let dir = tmpdir("higher-seq");
    let marker_path = authority_state_file_path(&dir);

    preseed_v2_marker(&h, &marker_path, &v2_ratification_for(&h, 3));
    let candidate = v2_ratification_for(&h, 4);
    match marker_check(&h, &marker_path, &candidate) {
        Ok(ValidationOnlyMarkerV2AcceptReason::UpgradeCompatible {
            previous_sequence,
            new_sequence,
        }) => {
            assert_eq!(previous_sequence, 3);
            assert_eq!(new_sequence, 4);
        }
        other => panic!("expected UpgradeCompatible accept, got {:?}", other),
    }
}

// =====================================================================
// 7. Every generated TestNet artifact is domain-bound.
// =====================================================================

#[test]
fn run154_testnet_artifacts_are_domain_bound() {
    let h = harness(NetworkEnvironment::Testnet);

    // Bundle: environment = TestNet, TestNet chain_id.
    let bundle = build_signed_bundle(&h, 1, 10);
    assert_eq!(bundle.environment, TrustBundleEnvironment::Testnet);
    assert_eq!(
        bundle.chain_id.as_deref(),
        Some(chain_id_hex(NetworkEnvironment::Testnet.chain_id()).as_str())
    );

    // Peer-candidate envelope: environment = TestNet, TestNet chain_id.
    let env = envelope_from_bundle(&h, &bundle, "run154-testnet-active", 1);
    assert_eq!(env.environment, TrustBundleEnvironment::Testnet);
    assert_eq!(
        env.chain_id_hex,
        chain_id_hex(NetworkEnvironment::Testnet.chain_id())
    );

    // v2 ratification: TestNet environment, TestNet chain_id, TestNet
    // genesis hash, the minted authority-root fingerprint, and the v2
    // authority-domain sequence.
    let rat = v2_ratification_for(&h, 1);
    assert_eq!(rat.environment, RatificationEnvironment::Testnet);
    assert_eq!(rat.chain_id, h.chain_id_str);
    assert_eq!(rat.genesis_hash, h.canonical_hash);
    assert_eq!(rat.authority_domain_sequence, 1);
    assert_eq!(
        rat.authority_root_fingerprint,
        hex_lower(&h.authority_pk),
        "v2 ratification must bind to the minted authority-root key material"
    );
    // The genesis authority-root carries the canonical fingerprint of the
    // same minted key.
    let authority = h.genesis_cfg.authority.as_ref().expect("authority");
    assert_eq!(
        authority.bundle_signing_authority_roots[0].key_fingerprint,
        qbind_ledger::pqc_public_key_fingerprint(&h.authority_pk),
        "genesis authority-root fingerprint must be derived from the minted key"
    );
}

// =====================================================================
// 8. DevNet fixture behaviour remains unchanged: DevNet material is bound
//    to the DevNet domain and is distinct from TestNet material.
// =====================================================================

#[test]
fn run154_devnet_fixture_behavior_unchanged() {
    let devnet = harness(NetworkEnvironment::Devnet);
    let testnet = harness(NetworkEnvironment::Testnet);

    let devnet_bundle = build_signed_bundle(&devnet, 1, 10);
    assert_eq!(devnet_bundle.environment, TrustBundleEnvironment::Devnet);
    assert_eq!(
        devnet_bundle.chain_id.as_deref(),
        Some(chain_id_hex(NetworkEnvironment::Devnet.chain_id()).as_str())
    );

    // DevNet and TestNet domains are distinct.
    assert_ne!(devnet.chain_id_str, testnet.chain_id_str);

    // A DevNet v2 ratification verifies under DevNet and not under TestNet.
    let devnet_rat = v2_ratification_for(&devnet, 1);
    assert!(qbind_ledger::verify_bundle_signing_key_ratification_v2(verifier_inputs(
        &devnet,
        NetworkEnvironment::Devnet,
        &devnet_rat
    ))
    .is_ok());
    assert!(qbind_ledger::verify_bundle_signing_key_ratification_v2(verifier_inputs(
        &devnet,
        NetworkEnvironment::Testnet,
        &devnet_rat
    ))
    .is_err());
}

// =====================================================================
// 9. Determinism: domain fields are deterministic; ephemeral key /
//    signature / genesis-hash fields are recorded as non-deterministic.
// =====================================================================

#[test]
fn run154_domain_fields_deterministic_keys_are_not() {
    let a = harness(NetworkEnvironment::Testnet);
    let b = harness(NetworkEnvironment::Testnet);

    // Deterministic domain fields.
    assert_eq!(a.chain_id_str, b.chain_id_str);
    assert_eq!(
        a.chain_id_str,
        chain_id_hex(NetworkEnvironment::Testnet.chain_id())
    );

    // Non-deterministic fields (recorded explicitly): ephemeral authority /
    // signing / transport-root material and the genesis hash derived from
    // the minted authority key all differ run-to-run.
    assert_ne!(a.authority_pk, b.authority_pk);
    assert_ne!(a.signing_pk, b.signing_pk);
    assert_ne!(a.root_pk_hex, b.root_pk_hex);
    assert_ne!(a.canonical_hash, b.canonical_hash);
}

// =====================================================================
// 10. No production anchor / no fallback root or signing key: the
//     authority-root fingerprint is derived from freshly minted ephemeral
//     material, and every minted root / signing key is non-empty and
//     differs run-to-run.
// =====================================================================

#[test]
fn run154_no_production_anchor_or_fallback_material() {
    let a = harness(NetworkEnvironment::Testnet);
    let b = harness(NetworkEnvironment::Testnet);

    // Authority-root fingerprint is bound to the minted authority key, not
    // a static production anchor.
    let authority = a.genesis_cfg.authority.as_ref().expect("authority");
    assert_eq!(
        authority.bundle_signing_authority_roots[0].key_fingerprint,
        qbind_ledger::pqc_public_key_fingerprint(&a.authority_pk),
        "authority-root fingerprint must be derived from the minted key"
    );

    // No fallback (shared/static) root or signing key: ephemeral material
    // is non-empty and differs between independent harnesses.
    assert!(!a.root_pk_hex.is_empty());
    assert!(!a.signing_pk.is_empty());
    assert_ne!(a.root_pk_hex, b.root_pk_hex, "transport root must be ephemeral");
    assert_ne!(a.signing_pk, b.signing_pk, "signing key must be ephemeral");
    assert_ne!(
        a.authority_pk, b.authority_pk,
        "authority key must be ephemeral"
    );
}

// =====================================================================
// 11. The Run 133 fixture helper now mints TestNet material (the source
//     fixture tooling that closes the Run 153 A2 blocker exists).
// =====================================================================

#[test]
fn run154_fixture_helper_source_mints_testnet() {
    let helper = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/run_133_v2_validation_only_fixture_helper.rs"
    );
    let src = std::fs::read_to_string(helper).expect("read fixture helper source");
    assert!(
        src.contains("NetworkEnvironment::Testnet"),
        "Run 133 helper must mint TestNet material for the Run 153 A2 gap"
    );
}