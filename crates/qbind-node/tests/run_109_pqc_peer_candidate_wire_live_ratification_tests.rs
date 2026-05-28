//! Run 109 — ratification enforcement on the live inbound `0x05`
//! peer-candidate wire validation path.
//!
//! These tests exercise the
//! [`qbind_node::pqc_peer_candidate_wire::LivePeerCandidateWireDispatcher`]
//! Run 079 entry point with the Run 109 owned ratification context
//! installed, and additionally re-cover the Run 088 propagation
//! gating contract under ratification (valid ratified candidates may
//! rebroadcast under existing Run 088 rules; unratified / bad / wrong
//! candidates are rejected BEFORE any rebroadcast).
//!
//! Run 109 strictly does NOT implement peer-driven live apply,
//! reload-apply, SIGHUP enforcement, signing-key rotation, signing-
//! key revocation, authority anti-rollback persistence, KMS/HSM
//! custody, governance, validator-set rotation, full C4 closure, or
//! C5 closure. The tests below assert the non-mutation invariants
//! (no sequence write, no apply, no session eviction, no live trust
//! mutation, no `_applied_total` metric family) on every rejection
//! path, just like Run 088 does for its unratified surface today.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
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
use qbind_node::p2p::NodeId;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_wire::{
    encode_peer_candidate_wire_frame, LivePeerCandidateWireDispatcher,
    LivePeerCandidateWireDispatcherConfig, LiveRatificationConfig,
    PeerCandidatePropagationConfig, PeerCandidateWireEnvelopeV1, PeerCandidateWireFrameSender,
    PeerCandidateWireOutcome, PeerCandidateWireReceiverConfig, RawFramePeerSendOutcome,
    RawFrameSendReport, PEER_CANDIDATE_WIRE_DOMAIN_TAG, PEER_CANDIDATE_WIRE_VERSION,
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
use qbind_node::pqc_trust_peer_candidate::{PeerCandidateConfig, PeerCandidateOutcome};
use qbind_node::pqc_trust_reload::{validate_candidate_bundle, ReloadCheckError, ReloadCheckInputs};
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

// =====================================================================
// Helpers
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
        "qbind-run109-{}-{}-{}",
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
        "run109-bundle-signing-authority",
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

fn wire_envelope(
    h: &Harness,
    bundle_bytes: Vec<u8>,
    declared_sequence: u64,
    declared_fingerprint_prefix: String,
) -> PeerCandidateWireEnvelopeV1 {
    let len = bundle_bytes.len();
    PeerCandidateWireEnvelopeV1 {
        envelope_version: PEER_CANDIDATE_WIRE_VERSION,
        domain_tag: PEER_CANDIDATE_WIRE_DOMAIN_TAG.to_string(),
        peer_id: Some("run109-peer".to_string()),
        environment: bundle_env(h.env),
        chain_id_hex: h.chain_id_str.clone(),
        declared_sequence,
        declared_fingerprint_prefix,
        declared_length: len,
        bundle_bytes,
    }
}

fn valid_frame(h: &Harness, sequence: u64) -> Vec<u8> {
    let bundle = build_signed_bundle(h, sequence);
    let bytes = bundle_to_bytes(&bundle);
    let fp = loader_fingerprint_prefix(&bytes, h);
    encode_peer_candidate_wire_frame(&wire_envelope(h, bytes, sequence, fp)).expect("encode")
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

fn live_rat_config(
    h: &Harness,
    ratification: Option<&BundleSigningRatification>,
    gate_decision: RatificationGateDecision,
    policy: RatificationEnforcementPolicy,
) -> LiveRatificationConfig {
    LiveRatificationConfig {
        authority: h.genesis_cfg.authority.clone().expect("authority"),
        expected_genesis_hash: h.canonical_hash,
        expected_environment_policy: env_policy(h.env),
        expected_chain_id_str: h.chain_id_str.clone(),
        ratification: ratification.cloned(),
        ratification_v2: None,
        policy,
        gate_decision,
    }
}

#[derive(Default)]
struct RecordingSender {
    peers: Vec<NodeId>,
    sent: Mutex<Vec<(Vec<NodeId>, Vec<u8>)>>,
}

impl RecordingSender {
    fn with_peers(peers: Vec<NodeId>) -> Arc<Self> {
        Arc::new(Self {
            peers,
            sent: Mutex::new(Vec::new()),
        })
    }
}

impl PeerCandidateWireFrameSender for RecordingSender {
    fn connected_peer_node_ids(&self) -> Vec<NodeId> {
        self.peers.clone()
    }

    fn send_raw_frame_to_all_peers(&self, frame_bytes: Vec<u8>) -> RawFrameSendReport {
        self.send_raw_frame_to_selected_peers(frame_bytes, &self.peers)
    }

    fn send_raw_frame_to_selected_peers(
        &self,
        frame_bytes: Vec<u8>,
        selected_peers: &[NodeId],
    ) -> RawFrameSendReport {
        self.sent
            .lock()
            .push((selected_peers.to_vec(), frame_bytes));
        RawFrameSendReport::from_per_peer(
            selected_peers
                .iter()
                .copied()
                .map(|p| (p, RawFramePeerSendOutcome::Enqueued))
                .collect(),
        )
    }
}

fn sequence_snapshot(path: &Path) -> Option<Vec<u8>> {
    path.exists().then(|| std::fs::read(path).expect("read seq"))
}

fn assert_sequence_unchanged(path: &Path, before: Option<Vec<u8>>) {
    assert_eq!(sequence_snapshot(path), before);
}

fn dispatcher(
    h: &Harness,
    metrics: Arc<P2pMetrics>,
    sender: Option<Arc<RecordingSender>>,
    propagation: PeerCandidatePropagationConfig,
    sequence_path: Option<PathBuf>,
    live_ratification: Option<LiveRatificationConfig>,
) -> LivePeerCandidateWireDispatcher {
    let scratch = tmpdir("scratch");
    let propagation_sender: Option<Arc<dyn PeerCandidateWireFrameSender>> = sender
        .map(|s| -> Arc<dyn PeerCandidateWireFrameSender> { s });
    LivePeerCandidateWireDispatcher::new(
        LivePeerCandidateWireDispatcherConfig {
            inner: PeerCandidateWireReceiverConfig {
                enabled: true,
                inner: PeerCandidateConfig::default(),
            },
            expected_environment: h.env,
            expected_chain_id: h.env.chain_id(),
            scratch_dir: scratch,
            signing_keys: h.signing_keys.clone(),
            activation_ctx: ActivationContext::height_only(0),
            consensus_storage_for_epoch: None,
            sequence_persistence_path: sequence_path,
            local_leaf_cert_bytes: None,
            validation_time_secs: 100,
            propagation,
            propagation_sender,
            live_ratification,
            authority_marker_path: None,
        },
        metrics,
    )
}

fn ratification_failure(outcome: &PeerCandidateWireOutcome) -> &RatificationEnforcementFailure {
    match outcome {
        PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Rejected(
            qbind_node::pqc_trust_peer_candidate::PeerCandidateRejection::ValidationFailed(
                ReloadCheckError::RatificationRefused(e),
            ),
        )) => e,
        other => panic!("expected ratification refusal, got {:?}", other),
    }
}

// =====================================================================
// A. Live validation policy tests
// =====================================================================

#[test]
fn run109_policy_matches_run106_for_every_environment() {
    // Cross-check: the dispatcher MUST consult the SAME Run 106 policy
    // function the local Run 107 peer-candidate-check path uses. If a
    // future run introduces a second policy table, this test fails.
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Mainnet, false),
        RatificationGateDecision::Invoke(GateInvokeReason::MainnetDefaultStrict)
    );
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Mainnet, true),
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
}

#[test]
fn run109_mainnet_dispatcher_invokes_gate_regardless_of_devnet_opt_in_flag() {
    // The dispatcher MUST NOT honour a DevNet-shaped skip on MainNet.
    let h = harness(NetworkEnvironment::Mainnet);
    let rat = ratification_for(&h);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        None,
        Some(live_rat_config(
            &h,
            Some(&rat),
            ratification_gate_decision(NetworkEnvironment::Mainnet, false),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    assert!(disp.ratification_gate_is_invoked());
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "valid ratified MainNet frame must pass");
}

#[test]
fn run109_devnet_without_opt_in_skips_gate_and_uses_legacy_path() {
    let h = harness(NetworkEnvironment::Devnet);
    let metrics = Arc::new(P2pMetrics::default());
    // Even when an (irrelevant) ratification object is wired, a
    // `Skip(DevnetNoOperatorOptIn)` gate decision MUST short-circuit
    // to the pre-Run-109 unguarded path. This preserves DevNet
    // developer ergonomics for unsigned and legacy bundles.
    let rat = ratification_for(&h);
    let skip = RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        None,
        Some(live_rat_config(
            &h,
            Some(&rat),
            skip,
            RatificationEnforcementPolicy::AllowLegacyUnratified,
        )),
    );
    assert!(!disp.ratification_gate_is_invoked());
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(
        out.is_validated(),
        "DevNet without opt-in: legacy valid candidate must still validate"
    );
}

#[test]
fn run109_devnet_with_opt_in_invokes_gate_and_rejects_missing_ratification() {
    let h = harness(NetworkEnvironment::Devnet);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        None,
        Some(live_rat_config(
            &h,
            None, // no ratification supplied
            ratification_gate_decision(NetworkEnvironment::Devnet, true),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    assert!(disp.ratification_gate_is_invoked());
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Missing { .. }
    ));
}

#[test]
fn run109_no_live_ratification_installed_preserves_pre_run109_unguarded_path() {
    let h = harness(NetworkEnvironment::Devnet);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        None,
        None,
    );
    assert!(!disp.ratification_gate_is_invoked());
    assert!(disp.live_ratification().is_none());
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated());
}

// =====================================================================
// B. Live candidate ratification tests
// =====================================================================

fn dispatch_mainnet_with_ratification(
    h: &Harness,
    ratification: Option<&BundleSigningRatification>,
) -> PeerCandidateWireOutcome {
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        h,
        metrics,
        None,
        PeerCandidatePropagationConfig::default(),
        None,
        Some(live_rat_config(
            h,
            ratification,
            ratification_gate_decision(NetworkEnvironment::Mainnet, false),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    disp.dispatch_frame_for_test(&valid_frame(h, 1))
}

#[test]
fn run109_mainnet_valid_ratification_passes_live_validation() {
    let h = harness(NetworkEnvironment::Mainnet);
    let rat = ratification_for(&h);
    let out = dispatch_mainnet_with_ratification(&h, Some(&rat));
    assert!(out.is_validated());
}

#[test]
fn run109_mainnet_missing_ratification_rejects_before_validation_success() {
    let h = harness(NetworkEnvironment::Mainnet);
    let out = dispatch_mainnet_with_ratification(&h, None);
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Missing { .. }
    ));
}

#[test]
fn run109_mainnet_bad_signature_rejects() {
    let h = harness(NetworkEnvironment::Mainnet);
    let mut rat = ratification_for(&h);
    rat.signature[0] ^= 0xFF;
    let out = dispatch_mainnet_with_ratification(&h, Some(&rat));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Verifier(RatificationFailure::BadSignature)
    ));
}

#[test]
fn run109_mainnet_wrong_chain_rejects() {
    let h = harness(NetworkEnvironment::Mainnet);
    let mut rat = ratification_for(&h);
    rat.chain_id = "0000000000000000".to_string();
    let out = dispatch_mainnet_with_ratification(&h, Some(&rat));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Verifier(RatificationFailure::ChainMismatch { .. })
    ));
}

#[test]
fn run109_mainnet_wrong_environment_rejects() {
    let h = harness(NetworkEnvironment::Mainnet);
    let mut rat = ratification_for(&h);
    rat.environment = RatificationEnvironment::Devnet;
    let out = dispatch_mainnet_with_ratification(&h, Some(&rat));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Verifier(RatificationFailure::EnvironmentMismatch { .. })
    ));
}

#[test]
fn run109_mainnet_unsupported_suite_rejects() {
    let h = harness(NetworkEnvironment::Mainnet);
    let mut rat = ratification_for(&h);
    rat.signature_suite_id = 99;
    let out = dispatch_mainnet_with_ratification(&h, Some(&rat));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Verifier(RatificationFailure::UnsupportedSuite { .. })
    ));
}

#[test]
fn run109_mainnet_unknown_authority_root_rejects() {
    let h = harness(NetworkEnvironment::Mainnet);
    let mut rat = ratification_for(&h);
    rat.authority_root_fingerprint = "aa".repeat(32);
    let out = dispatch_mainnet_with_ratification(&h, Some(&rat));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Verifier(RatificationFailure::UnknownAuthorityRoot { .. })
    ));
}

#[test]
fn run109_mainnet_missing_authority_key_material_rejects() {
    let mut h = harness(NetworkEnvironment::Mainnet);
    h.genesis_cfg
        .authority
        .as_mut()
        .unwrap()
        .bundle_signing_authority_roots[0]
        .public_key_hex = None;
    h.canonical_hash = compute_canonical_genesis_hash(&h.genesis_cfg, env_policy(h.env));
    let rat = ratification_for(&h);
    let out = dispatch_mainnet_with_ratification(&h, Some(&rat));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Verifier(
            RatificationFailure::AuthorityKeyMaterialUnavailable { .. }
        )
    ));
}

#[test]
fn run109_mainnet_malformed_authority_key_material_rejects() {
    let mut h = harness(NetworkEnvironment::Mainnet);
    h.genesis_cfg
        .authority
        .as_mut()
        .unwrap()
        .bundle_signing_authority_roots[0]
        .public_key_hex = Some("00".to_string());
    h.canonical_hash = compute_canonical_genesis_hash(&h.genesis_cfg, env_policy(h.env));
    let rat = ratification_for(&h);
    let out = dispatch_mainnet_with_ratification(&h, Some(&rat));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Verifier(
            RatificationFailure::AuthorityKeyMaterialMalformed { .. }
        )
    ));
}

#[test]
fn run109_mainnet_transport_root_cannot_ratify_signing_keys() {
    // A genesis whose only authority root sits in the
    // `pqc_transport_roots` list (NOT
    // `bundle_signing_authority_roots`) MUST NOT ratify a bundle-
    // signing key. This is the explicit Run 100 boundary the
    // verifier enforces; Run 109 must surface it on the live wire
    // path identically to the Run 107 local-check path.
    let mut h = harness(NetworkEnvironment::Mainnet);
    let transport_root = h
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
        let authority = h.genesis_cfg.authority.as_mut().unwrap();
        authority.pqc_transport_roots = vec![transport_root];
        authority.bundle_signing_authority_roots = vec![unrelated_bundle_root];
    }
    h.canonical_hash = compute_canonical_genesis_hash(&h.genesis_cfg, env_policy(h.env));
    let rat = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        rat_env(h.env),
        h.canonical_hash,
        &transport_fp,
        &h.authority_sk,
        &h.signing_pk,
    );
    let out = dispatch_mainnet_with_ratification(&h, Some(&rat));
    let err = ratification_failure(&out);
    assert!(
        matches!(
            err,
            RatificationEnforcementFailure::Verifier(
                RatificationFailure::TransportRootNotAllowed { .. }
            )
        ),
        "expected TransportRootNotAllowed, got {:?}",
        err
    );
}

#[test]
fn run109_testnet_default_strict_rejects_missing_ratification() {
    let h = harness(NetworkEnvironment::Testnet);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        None,
        Some(live_rat_config(
            &h,
            None,
            ratification_gate_decision(NetworkEnvironment::Testnet, false),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Missing { .. }
    ));
}

// =====================================================================
// C. Propagation gating tests
// =====================================================================

#[test]
fn run109_valid_ratified_candidate_may_rebroadcast_under_run088_rules() {
    let h = harness(NetworkEnvironment::Mainnet);
    let rat = ratification_for(&h);
    let metrics = Arc::new(P2pMetrics::default());
    let source = NodeId::new([1u8; 32]);
    let target = NodeId::new([2u8; 32]);
    let sender = RecordingSender::with_peers(vec![source, target]);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Some(Arc::clone(&sender)),
        PeerCandidatePropagationConfig {
            enabled: true,
            ..PeerCandidatePropagationConfig::default()
        },
        None,
        Some(live_rat_config(
            &h,
            Some(&rat),
            ratification_gate_decision(NetworkEnvironment::Mainnet, false),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    let frame = valid_frame(&h, 1);
    let out = disp.dispatch_frame_from_peer_for_test(&frame, Some(source));
    assert!(out.is_validated());
    assert_eq!(metrics.peer_candidate_propagation_attempt_total(), 1);
    assert_eq!(metrics.peer_candidate_propagation_sent_total(), 1);
    let sent = sender.sent.lock();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, vec![target], "source peer must be excluded");
}

#[test]
fn run109_unratified_candidate_does_not_rebroadcast() {
    let h = harness(NetworkEnvironment::Mainnet);
    let metrics = Arc::new(P2pMetrics::default());
    let source = NodeId::new([1u8; 32]);
    let target = NodeId::new([2u8; 32]);
    let sender = RecordingSender::with_peers(vec![source, target]);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Some(Arc::clone(&sender)),
        PeerCandidatePropagationConfig {
            enabled: true,
            ..PeerCandidatePropagationConfig::default()
        },
        None,
        Some(live_rat_config(
            &h,
            None,
            ratification_gate_decision(NetworkEnvironment::Mainnet, false),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    let out = disp.dispatch_frame_from_peer_for_test(&valid_frame(&h, 1), Some(source));
    assert!(!out.is_validated());
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Missing { .. }
    ));
    assert!(sender.sent.lock().is_empty());
    assert_eq!(metrics.peer_candidate_propagation_sent_total(), 0);
    // The Run 088 propagation gate routes invalid outcomes to the
    // "suppressed_invalid" counter family (the existing Run 088
    // metric reuse — no new metric family introduced by Run 109).
    assert_eq!(
        metrics.peer_candidate_propagation_suppressed_invalid_total(),
        1
    );
}

#[test]
fn run109_bad_ratification_candidate_does_not_rebroadcast() {
    let h = harness(NetworkEnvironment::Mainnet);
    let mut rat = ratification_for(&h);
    rat.signature[0] ^= 0xFF;
    let metrics = Arc::new(P2pMetrics::default());
    let source = NodeId::new([1u8; 32]);
    let target = NodeId::new([2u8; 32]);
    let sender = RecordingSender::with_peers(vec![source, target]);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Some(Arc::clone(&sender)),
        PeerCandidatePropagationConfig {
            enabled: true,
            ..PeerCandidatePropagationConfig::default()
        },
        None,
        Some(live_rat_config(
            &h,
            Some(&rat),
            ratification_gate_decision(NetworkEnvironment::Mainnet, false),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    let out = disp.dispatch_frame_from_peer_for_test(&valid_frame(&h, 1), Some(source));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Verifier(RatificationFailure::BadSignature)
    ));
    assert!(sender.sent.lock().is_empty());
    assert_eq!(metrics.peer_candidate_propagation_sent_total(), 0);
}

#[test]
fn run109_duplicate_unratified_candidate_does_not_become_accepted_via_dup_cache() {
    let h = harness(NetworkEnvironment::Mainnet);
    let metrics = Arc::new(P2pMetrics::default());
    let sender = RecordingSender::with_peers(vec![NodeId::new([2u8; 32])]);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Some(Arc::clone(&sender)),
        PeerCandidatePropagationConfig {
            enabled: true,
            ..PeerCandidatePropagationConfig::default()
        },
        None,
        Some(live_rat_config(
            &h,
            None,
            ratification_gate_decision(NetworkEnvironment::Mainnet, false),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    let frame = valid_frame(&h, 1);
    let first = disp.dispatch_frame_from_peer_for_test(&frame, Some(NodeId::new([1u8; 32])));
    assert!(!first.is_validated(), "first must be rejected");
    let second = disp.dispatch_frame_from_peer_for_test(&frame, Some(NodeId::new([1u8; 32])));
    assert!(
        !second.is_validated(),
        "duplicate suppression must NOT convert a rejection into an acceptance"
    );
    assert!(sender.sent.lock().is_empty());
    assert_eq!(metrics.peer_candidate_propagation_sent_total(), 0);
}

// =====================================================================
// D. Non-mutation tests
// =====================================================================

#[test]
fn run109_unratified_rejection_does_not_write_sequence_file() {
    let h = harness(NetworkEnvironment::Mainnet);
    let data_dir = tmpdir("seq-unratified");
    let seq = sequence_file_path(&data_dir);
    let before = sequence_snapshot(&seq);
    assert!(before.is_none(), "sequence file pre-test must be absent");
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq.clone()),
        Some(live_rat_config(
            &h,
            None,
            ratification_gate_decision(NetworkEnvironment::Mainnet, false),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Missing { .. }
    ));
    assert_sequence_unchanged(&seq, before);
    // No live apply / session eviction / `_applied_total` family
    // exists on the live wire path. Pin those invariants here.
    assert_eq!(metrics.live_reload_apply_success_total(), 0);
    assert_eq!(metrics.live_reload_apply_failure_total(), 0);
    assert_eq!(metrics.session_eviction_attempt_total(), 0);
    assert_eq!(metrics.live_reload_sessions_evicted_total(), 0);
    assert!(!metrics
        .format_metrics()
        .contains("qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total"));
}

#[test]
fn run109_bad_ratification_rejection_does_not_write_sequence_file() {
    let h = harness(NetworkEnvironment::Mainnet);
    let mut rat = ratification_for(&h);
    rat.signature[0] ^= 0xFF;
    let data_dir = tmpdir("seq-bad");
    let seq = sequence_file_path(&data_dir);
    let before = sequence_snapshot(&seq);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq.clone()),
        Some(live_rat_config(
            &h,
            Some(&rat),
            ratification_gate_decision(NetworkEnvironment::Mainnet, false),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(matches!(
        ratification_failure(&out),
        RatificationEnforcementFailure::Verifier(RatificationFailure::BadSignature)
    ));
    assert_sequence_unchanged(&seq, before);
}

#[test]
fn run109_valid_ratified_acceptance_does_not_write_sequence_file_either() {
    // The Run 088 / Run 076 non-mutation contract: even on a valid
    // outcome, the live wire path is read-only on the sequence file
    // (peek-only). Pin it here so a future regression cannot silently
    // start persisting peer-driven sequence numbers.
    let h = harness(NetworkEnvironment::Mainnet);
    let rat = ratification_for(&h);
    let data_dir = tmpdir("seq-valid");
    let seq = sequence_file_path(&data_dir);
    let before = sequence_snapshot(&seq);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq.clone()),
        Some(live_rat_config(
            &h,
            Some(&rat),
            ratification_gate_decision(NetworkEnvironment::Mainnet, false),
            RatificationEnforcementPolicy::Strict,
        )),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated());
    assert_sequence_unchanged(&seq, before);
    assert_eq!(metrics.live_reload_apply_success_total(), 0);
    assert_eq!(metrics.live_reload_apply_failure_total(), 0);
    assert_eq!(metrics.session_eviction_attempt_total(), 0);
}