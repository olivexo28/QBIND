//! Run 142 — integration tests for **v2 ratification + v2
//! authority-marker** wiring on the **live inbound `0x05`
//! peer-candidate validation-only** receive path.
//!
//! These tests exercise the
//! [`qbind_node::pqc_peer_candidate_wire::LivePeerCandidateWireDispatcher`]
//! Run 079 entry point with the Run 142 owned **v2** ratification
//! context installed (`LiveRatificationConfig::ratification_v2`) and
//! assert that the dispatcher routes Validated outcomes through the
//! Run 130 v2 verifier and the Run 132
//! [`qbind_node::pqc_authority_marker_acceptance::verify_marker_for_validation_only_v2`]
//! helper, mirroring the local Run 132 peer-candidate-check binary
//! path bit-for-bit. **No mutation** of any kind occurs on this surface
//! under Run 142 — no live trust swap, no sequence write, no marker
//! write, no session eviction, no reload-apply, no SIGHUP.
//!
//! Acceptance scenarios (A1–A4) and rejection scenarios (R1–R11) per
//! `task/RUN_142_TASK.txt`:
//!
//!   * **A1** valid v2 candidate accepted validation-only
//!   * **A2** idempotent v2 marker accepted, no rewrite
//!   * **A3** higher-sequence v2 accepted, no persistence
//!   * **A4** v2-after-v1 migration accepted, v1 marker preserved
//!   * **R1** lower-sequence v2 rejected
//!   * **R2** same-sequence different-digest v2 rejected
//!   * **R3** bad-signature v2 rejected (Run 130 verifier failure)
//!   * **R4** wrong-environment v2 rejected
//!   * **R5** wrong-chain v2 rejected
//!   * **R6** wrong-genesis v2 rejected
//!   * **R7** ambiguous v1+v2 fail-closed
//!   * **R8** corrupted local marker fail-closed
//!   * **R9** v1 live inbound `0x05` regression
//!   * **R10** no-sidecar / legacy live inbound `0x05` regression
//!   * **R11** propagation-only v2 interaction
//!
//! Strict scope (matches `task/RUN_142_TASK.txt`):
//!
//!   * Source/test wiring only. Release-binary live inbound `0x05` v2
//!     evidence is deferred to Run 143.
//!   * Validation-only receive path. No live apply.
//!   * No peer-driven trust-state mutation.
//!   * No sequence write. No authority-marker write. No session
//!     eviction.
//!   * No CLI / wire / schema / metric drift.
//!   * Does not weaken v1 live inbound `0x05` behaviour.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::test_helpers as ratification_helpers,
    bundle_signing_ratification::v2_test_helpers as ratification_v2_helpers,
    compute_canonical_genesis_hash, BundleSigningRatification, BundleSigningRatificationV2,
    BundleSigningRatificationV2Action, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisHash,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy, RatificationEnforcementPolicy,
    RatificationEnvironment, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::metrics::P2pMetrics;
use qbind_node::p2p::NodeId;
use qbind_node::pqc_authority_marker_acceptance::{
    verify_marker_for_validation_only_v2, ValidationOnlyMarkerV2Inputs,
};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, persist_authority_state_atomic,
    persist_authority_state_v2_atomic, AuthorityStateUpdateSource, PersistentAuthorityStateRecord,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_wire::{
    encode_peer_candidate_wire_frame, LivePeerCandidateWireDispatcher,
    LivePeerCandidateWireDispatcherConfig, LiveRatificationConfig,
    PeerCandidatePropagationConfig, PeerCandidateWireEnvelopeV1, PeerCandidateWireFrameSender,
    PeerCandidateWireOutcome, PeerCandidateWireReceiverConfig, RawFramePeerSendOutcome,
    RawFrameSendReport, PEER_CANDIDATE_WIRE_DOMAIN_TAG, PEER_CANDIDATE_WIRE_VERSION,
};
use qbind_node::pqc_ratification_policy::ratification_gate_decision;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::{
    PeerCandidateConfig, PeerCandidateOutcome, PeerCandidateRejection,
};
use qbind_node::pqc_trust_reload::{
    validate_candidate_bundle, ReloadCheckError, ReloadCheckInputs,
};
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
        "qbind-run142-{}-{}-{}",
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
    let root = mint_devnet_root().expect("mint root");
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let chain_id_str = chain_id_hex(env.chain_id());
    let mut genesis_cfg = GenesisConfig::new(
        &chain_id_str,
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
        "run142-bundle-signing-authority",
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
        peer_id: Some("run142-peer".to_string()),
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

fn v1_ratification_for(h: &Harness) -> BundleSigningRatification {
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

fn v2_ratification_for(h: &Harness, sequence: u64) -> BundleSigningRatificationV2 {
    let authority = h.genesis_cfg.authority.as_ref().expect("authority");
    ratification_v2_helpers::build_signed_ratification_v2(
        &h.chain_id_str,
        rat_env(h.env),
        h.canonical_hash,
        authority.authority_policy_version,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
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

/// Build a [`LiveRatificationConfig`] carrying a v2 sidecar. `ratification`
/// (v1) is left `None`; gate decision/policy default to MainNet strict.
fn live_v2_rat_config(
    h: &Harness,
    ratification_v2: Option<BundleSigningRatificationV2>,
) -> LiveRatificationConfig {
    LiveRatificationConfig {
        authority: h.genesis_cfg.authority.clone().expect("authority"),
        expected_genesis_hash: h.canonical_hash,
        expected_environment_policy: env_policy(h.env),
        expected_chain_id_str: h.chain_id_str.clone(),
        ratification: None,
        ratification_v2,
        policy: RatificationEnforcementPolicy::Strict,
        gate_decision: ratification_gate_decision(h.env, false),
    }
}

/// Build a [`LiveRatificationConfig`] carrying a v1 sidecar (regression).
fn live_v1_rat_config(
    h: &Harness,
    ratification: Option<&BundleSigningRatification>,
) -> LiveRatificationConfig {
    LiveRatificationConfig {
        authority: h.genesis_cfg.authority.clone().expect("authority"),
        expected_genesis_hash: h.canonical_hash,
        expected_environment_policy: env_policy(h.env),
        expected_chain_id_str: h.chain_id_str.clone(),
        ratification: ratification.cloned(),
        ratification_v2: None,
        policy: RatificationEnforcementPolicy::Strict,
        gate_decision: ratification_gate_decision(h.env, false),
    }
}

/// Build a [`LiveRatificationConfig`] carrying BOTH v1 AND v2 — used to
/// exercise the Run 142 fail-closed ambiguity rejection (R7).
fn live_v1_plus_v2_rat_config(
    h: &Harness,
    ratification: BundleSigningRatification,
    ratification_v2: BundleSigningRatificationV2,
) -> LiveRatificationConfig {
    LiveRatificationConfig {
        authority: h.genesis_cfg.authority.clone().expect("authority"),
        expected_genesis_hash: h.canonical_hash,
        expected_environment_policy: env_policy(h.env),
        expected_chain_id_str: h.chain_id_str.clone(),
        ratification: Some(ratification),
        ratification_v2: Some(ratification_v2),
        policy: RatificationEnforcementPolicy::Strict,
        gate_decision: ratification_gate_decision(h.env, false),
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
    fn sent_count(&self) -> usize {
        self.sent.lock().len()
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

fn marker_snapshot(path: &Path) -> Option<Vec<u8>> {
    path.exists().then(|| std::fs::read(path).expect("read marker"))
}

fn assert_no_mutation(
    seq_path: &Path,
    seq_before: Option<Vec<u8>>,
    marker_path: &Path,
    marker_before: Option<Vec<u8>>,
) {
    assert_eq!(
        sequence_snapshot(seq_path),
        seq_before,
        "Run 142 invariant: pqc_trust_bundle_sequence.json must be byte-identical pre/post"
    );
    assert_eq!(
        marker_snapshot(marker_path),
        marker_before,
        "Run 142 invariant: pqc_authority_state.json must be byte-identical pre/post"
    );
}

#[allow(clippy::too_many_arguments)]
fn dispatcher(
    h: &Harness,
    metrics: Arc<P2pMetrics>,
    sender: Option<Arc<RecordingSender>>,
    propagation: PeerCandidatePropagationConfig,
    sequence_path: Option<PathBuf>,
    marker_path: Option<PathBuf>,
    live_ratification: Option<LiveRatificationConfig>,
) -> LivePeerCandidateWireDispatcher {
    let scratch = tmpdir("scratch");
    let propagation_sender: Option<Arc<dyn PeerCandidateWireFrameSender>> =
        sender.map(|s| -> Arc<dyn PeerCandidateWireFrameSender> { s });
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
            authority_marker_path: marker_path,
        },
        metrics,
    )
}

/// Pre-seed a persisted v2 marker on disk by re-running the production
/// derivation primitive against a verified v2 ratification.
fn preseed_v2_marker(h: &Harness, marker_path: &Path, ratification: &BundleSigningRatificationV2) {
    use qbind_node::pqc_authority_state::{
        derive_authority_state_v2_from_ratification, AuthorityStateDerivationV2Inputs,
    };
    let ratified = qbind_ledger::verify_bundle_signing_key_ratification_v2(
        qbind_ledger::RatificationV2VerifierInputs {
            ratification,
            authority: h.genesis_cfg.authority.as_ref().expect("authority"),
            expected_chain_id: &h.chain_id_str,
            expected_environment: env_policy(h.env),
            expected_genesis_hash: &h.canonical_hash,
        },
    )
    .expect("preseed: v2 verifier must succeed");
    let mut hash_hex = String::with_capacity(64);
    for b in h.canonical_hash {
        use std::fmt::Write;
        let _ = write!(hash_hex, "{:02x}", b);
    }
    let record = derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
        runtime_env: h.env,
        runtime_chain_id: h.env.chain_id(),
        runtime_genesis_hash_hex: &hash_hex,
        ratification,
        ratified: &ratified,
        update_source: AuthorityStateUpdateSource::TestOrFixture,
        updated_at_unix_secs: 1_000,
    })
    .expect("preseed: derive v2 marker");
    persist_authority_state_v2_atomic(marker_path, &record).expect("preseed: persist v2 marker");
}

/// Pre-seed a persisted v1 marker (for R8 corrupt + A4 v2-after-v1 setup).
fn preseed_v1_marker(h: &Harness, marker_path: &Path, sequence: u64) {
    let authority = h.genesis_cfg.authority.as_ref().expect("authority");
    let record = PersistentAuthorityStateRecord::new(
        h.chain_id_str.clone(),
        bundle_env(h.env),
        hex_lower(&h.canonical_hash),
        authority.authority_policy_version,
        sequence,
        None,
        hex_lower(&h.authority_pk),
        hex_lower(&h.signing_pk)[..64].to_string(),
        "aa".repeat(32),
        AuthorityStateUpdateSource::ReloadApply,
        1000,
    );
    persist_authority_state_atomic(marker_path, &record).expect("preseed: persist v1 marker");
}

fn marker_conflict_message(outcome: &PeerCandidateWireOutcome) -> &str {
    match outcome {
        PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Rejected(
            PeerCandidateRejection::ValidationFailed(ReloadCheckError::MarkerConflict(s)),
        )) => s.as_str(),
        other => panic!("expected MarkerConflict rejection, got {:?}", other),
    }
}

// =====================================================================
// Acceptance scenarios (A1–A4)
// =====================================================================

#[test]
fn run142_a1_valid_v2_candidate_accepted_validation_only() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("a1");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
    );
    assert!(disp.ratification_gate_is_invoked());
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(
        out.is_validated(),
        "A1: valid v2 candidate must validate (validation-only), got {:?}",
        out
    );
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run142_a2_idempotent_v2_marker_accepted_no_rewrite() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("a2");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    let rat_v2 = v2_ratification_for(&h, 3);
    preseed_v2_marker(&h, &marker_path, &rat_v2);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);
    assert!(marker_before.is_some(), "preseed must write marker");

    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "A2: idempotent v2 marker must accept");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run142_a3_higher_sequence_v2_accepted_no_persist() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("a3");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    // Persisted v2 marker at seq=3; candidate carries seq=4.
    let rat_v2_persisted = v2_ratification_for(&h, 3);
    preseed_v2_marker(&h, &marker_path, &rat_v2_persisted);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2_candidate = v2_ratification_for(&h, 4);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2_candidate))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "A3: higher-sequence v2 must accept");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run142_a4_v2_after_v1_migration_candidate_accepted() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("a4");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    // Pre-existing v1 marker (legacy).
    preseed_v1_marker(&h, &marker_path, 1);
    let seq_before = sequence_snapshot(&seq_path);
    let v1_marker_before = marker_snapshot(&marker_path);
    assert!(v1_marker_before.is_some());

    // Candidate is v2 with a higher sequence.
    let rat_v2 = v2_ratification_for(&h, 2);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "A4: v2-after-v1 migration must accept");
    // CRITICAL: the v1 marker bytes are preserved untouched.
    assert_no_mutation(&seq_path, seq_before, &marker_path, v1_marker_before);
}

// =====================================================================
// Rejection scenarios (R1–R11)
// =====================================================================

#[test]
fn run142_r1_lower_sequence_v2_rejected() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r1");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    let rat_v2_persisted = v2_ratification_for(&h, 5);
    preseed_v2_marker(&h, &marker_path, &rat_v2_persisted);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2_candidate = v2_ratification_for(&h, 2); // lower
    let metrics = Arc::new(P2pMetrics::default());
    let sender = RecordingSender::with_peers(vec![NodeId::from([7u8; 32])]);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Some(Arc::clone(&sender)),
        PeerCandidatePropagationConfig {
            enabled: true,
            ..PeerCandidatePropagationConfig::default()
        },
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2_candidate))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    let msg = marker_conflict_message(&out);
    assert!(
        msg.contains("lower sequence") || msg.contains("Run 132"),
        "R1: expected v2 lower-sequence refusal, got: {}",
        msg
    );
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
    assert_eq!(sender.sent_count(), 0, "R1: must not propagate");
}

#[test]
fn run142_r2_same_sequence_different_digest_v2_rejected() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r2");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    // Persist a v2 marker at seq=3.
    let rat_v2_persisted = v2_ratification_for(&h, 3);
    preseed_v2_marker(&h, &marker_path, &rat_v2_persisted);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    // Candidate at the SAME seq=3 but with a different target signing key
    // → different digest (different `target_bundle_signing_public_key`).
    let (other_pk, _other_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 conflicting signing key");
    let authority = h.genesis_cfg.authority.as_ref().expect("authority");
    let rat_v2_conflict = ratification_v2_helpers::build_signed_ratification_v2(
        &h.chain_id_str,
        rat_env(h.env),
        h.canonical_hash,
        authority.authority_policy_version,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &other_pk,
        3,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let metrics = Arc::new(P2pMetrics::default());
    let sender = RecordingSender::with_peers(vec![NodeId::from([8u8; 32])]);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Some(Arc::clone(&sender)),
        PeerCandidatePropagationConfig {
            enabled: true,
            ..PeerCandidatePropagationConfig::default()
        },
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2_conflict))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    // Could be rejected at inner sig check (different signing key) or at
    // v2 marker compare. Either way, no mutation, no propagation.
    assert!(!out.is_validated(), "R2: equivocation must reject");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
    assert_eq!(sender.sent_count(), 0, "R2: must not propagate");
}

#[test]
fn run142_r3_bad_signature_v2_rejected() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r3");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut rat_v2 = v2_ratification_for(&h, 1);
    rat_v2.signature[0] ^= 0xFF;

    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    let msg = marker_conflict_message(&out);
    assert!(
        msg.contains("v2 ratification verifier failure")
            || msg.contains("Run 132"),
        "R3: expected Run 130 v2 verifier failure, got: {}",
        msg
    );
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run142_r4_wrong_environment_v2_rejected() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r4");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut rat_v2 = v2_ratification_for(&h, 1);
    rat_v2.environment = RatificationEnvironment::Devnet;

    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(!out.is_validated(), "R4: wrong-environment must reject");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run142_r5_wrong_chain_v2_rejected() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r5");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut rat_v2 = v2_ratification_for(&h, 1);
    rat_v2.chain_id = "0000000000000000".to_string();

    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(!out.is_validated(), "R5: wrong-chain must reject");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run142_r6_wrong_genesis_v2_rejected() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r6");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut rat_v2 = v2_ratification_for(&h, 1);
    rat_v2.genesis_hash = [0xAAu8; 32];

    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(!out.is_validated(), "R6: wrong-genesis must reject");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run142_r7_ambiguous_v1_plus_v2_fail_closed() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r7");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v1 = v1_ratification_for(&h);
    let rat_v2 = v2_ratification_for(&h, 1);

    let metrics = Arc::new(P2pMetrics::default());
    let sender = RecordingSender::with_peers(vec![NodeId::from([9u8; 32])]);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Some(Arc::clone(&sender)),
        PeerCandidatePropagationConfig {
            enabled: true,
            ..PeerCandidatePropagationConfig::default()
        },
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v1_plus_v2_rat_config(&h, rat_v1, rat_v2)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    let msg = marker_conflict_message(&out);
    assert!(
        msg.contains("ambiguous v1+v2"),
        "R7: expected ambiguous v1+v2 fail-closed, got: {}",
        msg
    );
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
    assert_eq!(sender.sent_count(), 0, "R7: must not propagate");
}

#[test]
fn run142_r8_corrupted_local_marker_fail_closed() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r8");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    // Write corrupt JSON bytes that the loader cannot parse.
    std::fs::write(&marker_path, b"not-valid-json{").expect("write corrupt");
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);
    assert!(marker_before.is_some());

    let rat_v2 = v2_ratification_for(&h, 1);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(!out.is_validated(), "R8: corrupt marker must fail-closed");
    // Corrupt bytes preserved verbatim.
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run142_r9_v1_live_inbound_regression_unchanged() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r9");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    // v1 sidecar, no v2. Should take the existing Run 109 v1 path and
    // pass validation exactly as before Run 142.
    let rat_v1 = v1_ratification_for(&h);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v1_rat_config(&h, Some(&rat_v1))),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(
        out.is_validated(),
        "R9: v1 live inbound regression must remain unchanged, got {:?}",
        out
    );
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run142_r10_no_sidecar_legacy_live_inbound_regression_unchanged() {
    // DevNet without operator opt-in → ratification gate is SKIP →
    // pre-Run-109 legacy unguarded path. Run 142 must not fabricate a
    // v2 marker, must not invoke v2 helpers, and must not mutate.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r10");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        None, // no live ratification context at all
    );
    assert!(!disp.ratification_gate_is_invoked());
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(
        out.is_validated(),
        "R10: legacy unguarded path must remain unchanged"
    );
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run142_r11_propagation_only_v2_interaction() {
    let h = harness(NetworkEnvironment::Mainnet);

    // Sub-case 11a: propagation disabled, valid v2 candidate → no rebroadcast.
    {
        let dir = tmpdir("r11a");
        let marker_path = authority_state_file_path(&dir);
        let seq_path = sequence_file_path(&dir);
        let seq_before = sequence_snapshot(&seq_path);
        let marker_before = marker_snapshot(&marker_path);
        let rat_v2 = v2_ratification_for(&h, 1);
        let metrics = Arc::new(P2pMetrics::default());
        let sender = RecordingSender::with_peers(vec![NodeId::from([10u8; 32])]);
        let disp = dispatcher(
            &h,
            Arc::clone(&metrics),
            Some(Arc::clone(&sender)),
            PeerCandidatePropagationConfig {
                enabled: false,
                ..PeerCandidatePropagationConfig::default()
            },
            Some(seq_path.clone()),
            Some(marker_path.clone()),
            Some(live_v2_rat_config(&h, Some(rat_v2))),
        );
        let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
        assert!(out.is_validated(), "R11a: valid v2 must validate");
        assert_eq!(sender.sent_count(), 0, "R11a: propagation disabled");
        assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
    }

    // Sub-case 11b: propagation enabled, valid v2 candidate → rebroadcasts
    // ONLY after validation passes. No apply, no marker write, no
    // sequence write either way.
    {
        let dir = tmpdir("r11b");
        let marker_path = authority_state_file_path(&dir);
        let seq_path = sequence_file_path(&dir);
        let seq_before = sequence_snapshot(&seq_path);
        let marker_before = marker_snapshot(&marker_path);
        let rat_v2 = v2_ratification_for(&h, 1);
        let metrics = Arc::new(P2pMetrics::default());
        let sender = RecordingSender::with_peers(vec![NodeId::from([11u8; 32])]);
        let disp = dispatcher(
            &h,
            Arc::clone(&metrics),
            Some(Arc::clone(&sender)),
            PeerCandidatePropagationConfig {
                enabled: true,
                ..PeerCandidatePropagationConfig::default()
            },
            Some(seq_path.clone()),
            Some(marker_path.clone()),
            Some(live_v2_rat_config(&h, Some(rat_v2))),
        );
        let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
        assert!(out.is_validated(), "R11b: valid v2 must validate");
        assert_eq!(
            sender.sent_count(),
            1,
            "R11b: valid v2 rebroadcasts exactly once"
        );
        assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
    }

    // Sub-case 11c: propagation enabled, INVALID v2 candidate (bad sig) →
    // never rebroadcasts. No apply, no mutation.
    {
        let dir = tmpdir("r11c");
        let marker_path = authority_state_file_path(&dir);
        let seq_path = sequence_file_path(&dir);
        let seq_before = sequence_snapshot(&seq_path);
        let marker_before = marker_snapshot(&marker_path);
        let mut rat_v2 = v2_ratification_for(&h, 1);
        rat_v2.signature[0] ^= 0xFF;
        let metrics = Arc::new(P2pMetrics::default());
        let sender = RecordingSender::with_peers(vec![NodeId::from([12u8; 32])]);
        let disp = dispatcher(
            &h,
            Arc::clone(&metrics),
            Some(Arc::clone(&sender)),
            PeerCandidatePropagationConfig {
                enabled: true,
                ..PeerCandidatePropagationConfig::default()
            },
            Some(seq_path.clone()),
            Some(marker_path.clone()),
            Some(live_v2_rat_config(&h, Some(rat_v2))),
        );
        let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
        assert!(!out.is_validated(), "R11c: invalid v2 must reject");
        assert_eq!(
            sender.sent_count(),
            0,
            "R11c: invalid v2 must NEVER rebroadcast"
        );
        assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
    }
}

// =====================================================================
// Local peer-candidate-check parity — Run 142 §4
// =====================================================================
//
// The live inbound `0x05` v2 validation outcome must match the local
// peer-candidate-check v2 decision (the
// `verify_marker_for_validation_only_v2` helper) for the same candidate.
// This test asserts both surfaces agree on accept and reject for the
// same fixture.

#[test]
fn run142_local_peer_candidate_check_parity_accepts_and_rejects_match() {
    let h = harness(NetworkEnvironment::Mainnet);

    // Accept case parity.
    {
        let dir = tmpdir("parity-accept");
        let marker_path = authority_state_file_path(&dir);
        let rat_v2 = v2_ratification_for(&h, 1);
        let ratified = qbind_ledger::verify_bundle_signing_key_ratification_v2(
            qbind_ledger::RatificationV2VerifierInputs {
                ratification: &rat_v2,
                authority: h.genesis_cfg.authority.as_ref().expect("authority"),
                expected_chain_id: &h.chain_id_str,
                expected_environment: env_policy(h.env),
                expected_genesis_hash: &h.canonical_hash,
            },
        )
        .expect("local v2 verifier must accept");

        let mut hash_hex = String::with_capacity(64);
        for b in h.canonical_hash {
            use std::fmt::Write;
            let _ = write!(hash_hex, "{:02x}", b);
        }
        let local = verify_marker_for_validation_only_v2(ValidationOnlyMarkerV2Inputs {
            marker_path: &marker_path,
            runtime_env: h.env,
            runtime_chain_id: h.env.chain_id(),
            runtime_genesis_hash_hex: &hash_hex,
            ratification: &rat_v2,
            ratified: &ratified,
        });
        assert!(local.is_ok(), "local Run 132 surface accepts");

        let metrics = Arc::new(P2pMetrics::default());
        let disp = dispatcher(
            &h,
            metrics,
            None,
            PeerCandidatePropagationConfig::default(),
            None,
            Some(marker_path),
            Some(live_v2_rat_config(&h, Some(rat_v2))),
        );
        let wire_out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
        assert!(
            wire_out.is_validated(),
            "live `0x05` v2 surface accepts same candidate"
        );
    }

    // Reject case parity: lower-sequence v2 candidate.
    {
        let dir = tmpdir("parity-reject");
        let marker_path = authority_state_file_path(&dir);
        preseed_v2_marker(&h, &marker_path, &v2_ratification_for(&h, 5));

        let rat_v2_low = v2_ratification_for(&h, 2);
        let ratified = qbind_ledger::verify_bundle_signing_key_ratification_v2(
            qbind_ledger::RatificationV2VerifierInputs {
                ratification: &rat_v2_low,
                authority: h.genesis_cfg.authority.as_ref().expect("authority"),
                expected_chain_id: &h.chain_id_str,
                expected_environment: env_policy(h.env),
                expected_genesis_hash: &h.canonical_hash,
            },
        )
        .expect("verifier accepts (it's the marker compare that rejects)");
        let mut hash_hex = String::with_capacity(64);
        for b in h.canonical_hash {
            use std::fmt::Write;
            let _ = write!(hash_hex, "{:02x}", b);
        }
        let local = verify_marker_for_validation_only_v2(ValidationOnlyMarkerV2Inputs {
            marker_path: &marker_path,
            runtime_env: h.env,
            runtime_chain_id: h.env.chain_id(),
            runtime_genesis_hash_hex: &hash_hex,
            ratification: &rat_v2_low,
            ratified: &ratified,
        });
        assert!(local.is_err(), "local Run 132 surface rejects");

        let metrics = Arc::new(P2pMetrics::default());
        let disp = dispatcher(
            &h,
            metrics,
            None,
            PeerCandidatePropagationConfig::default(),
            None,
            Some(marker_path),
            Some(live_v2_rat_config(&h, Some(rat_v2_low))),
        );
        let wire_out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
        assert!(
            !wire_out.is_validated(),
            "live `0x05` v2 surface rejects same candidate"
        );
    }
}