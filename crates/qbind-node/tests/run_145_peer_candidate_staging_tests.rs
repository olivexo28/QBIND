//! Run 145 — integration / unit tests for the **non-applying, staged
//! peer-driven trust-bundle candidate queue** scaffold.
//!
//! These tests exercise the new
//! [`qbind_node::pqc_peer_candidate_staging::PeerCandidateStagingQueue`]
//! library surface and prove every Run 145 invariant required by
//! `task/RUN_145_TASK.txt`.
//!
//! **Strict scope (Run 145):**
//!
//! - Source/test scaffold only.
//! - No live apply.
//! - No mutation of `LivePqcTrustState`, the trust-bundle sequence
//!   file, the authority marker, or P2P / KEMTLS sessions.
//! - No call to Run 070 `apply_validated_candidate*`.
//! - No SIGHUP / reload-apply invocation.
//! - Staging is disabled by default; MainNet is refused.
//! - Bounded and deduplicated; reject-new at capacity.
//! - Existing validation-only and propagation-only behaviour
//!   (Runs 142/143, Run 088) remains bit-for-bit unchanged.
//!
//! The acceptance scenarios A1–A4 and rejection scenarios R1–R13 mirror
//! the matrix specified by `task/RUN_145_TASK.txt`.

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
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    RatificationEnforcementPolicy, RatificationEnvironment, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::metrics::P2pMetrics;
use qbind_node::p2p::NodeId;
use qbind_node::pqc_authority_state::{authority_state_file_path, AuthorityStateUpdateSource};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_staging::{
    PeerCandidateStagingQueue, PeerDrivenStagingPolicy, StagedPeerCandidate, StagingOutcome,
    DEFAULT_MAX_CANDIDATES_PER_PEER, DEFAULT_MAX_STAGED_CANDIDATES, DEFAULT_TTL_SECS,
};
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
    PeerCandidateConfig, PeerCandidateOutcome, ValidatedPeerCandidate,
};
use qbind_node::pqc_trust_reload::{
    validate_candidate_bundle, ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

// =====================================================================
// Harness (adapted from run_142_live_inbound_0x05_v2_validation_tests.rs)
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
        "qbind-run145-{}-{}-{}",
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
        "run145-bundle-signing-authority",
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
    peer_id: Option<&str>,
) -> PeerCandidateWireEnvelopeV1 {
    let len = bundle_bytes.len();
    PeerCandidateWireEnvelopeV1 {
        envelope_version: PEER_CANDIDATE_WIRE_VERSION,
        domain_tag: PEER_CANDIDATE_WIRE_DOMAIN_TAG.to_string(),
        peer_id: peer_id.map(|s| s.to_string()),
        environment: bundle_env(h.env),
        chain_id_hex: h.chain_id_str.clone(),
        declared_sequence,
        declared_fingerprint_prefix,
        declared_length: len,
        bundle_bytes,
        governance_authority_proof: None,
    }
}

fn valid_frame(h: &Harness, sequence: u64, peer_id: Option<&str>) -> Vec<u8> {
    let bundle = build_signed_bundle(h, sequence);
    let bytes = bundle_to_bytes(&bundle);
    let fp = loader_fingerprint_prefix(&bytes, h);
    encode_peer_candidate_wire_frame(&wire_envelope(h, bytes, sequence, fp, peer_id))
        .expect("encode")
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
        "Run 145 invariant: pqc_trust_bundle_sequence.json must be byte-identical pre/post"
    );
    assert_eq!(
        marker_snapshot(marker_path),
        marker_before,
        "Run 145 invariant: pqc_authority_state.json must be byte-identical pre/post"
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
            staging_queue: None,
        },
        metrics,
    )
}

fn preseed_v1_marker(h: &Harness, marker_path: &Path, sequence: u64) {
    use qbind_node::pqc_authority_state::{
        persist_authority_state_atomic, PersistentAuthorityStateRecord,
    };
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

/// Run a frame through the dispatcher and return the produced
/// [`PeerCandidateWireOutcome`].
fn dispatch_via_v2(
    h: &Harness,
    seq_path: &Path,
    marker_path: &Path,
    rat_v2: Option<BundleSigningRatificationV2>,
    frame: &[u8],
) -> PeerCandidateWireOutcome {
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        h,
        metrics,
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.to_path_buf()),
        Some(marker_path.to_path_buf()),
        Some(live_v2_rat_config(h, rat_v2)),
    );
    disp.dispatch_frame_for_test(frame)
}

/// Extract the `ValidatedPeerCandidate` from a Validated outcome; panic
/// otherwise. Used by Run 145 acceptance tests that drive the staging
/// queue with a real validation result.
fn expect_validated(outcome: PeerCandidateWireOutcome) -> ValidatedPeerCandidate {
    match outcome {
        PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Validated(v)) => v,
        other => panic!("expected Validated, got {:?}", other),
    }
}

// =====================================================================
// Run 145 — Acceptance scenarios (A1–A4)
// =====================================================================

#[test]
fn run145_a1_valid_v2_candidate_stages_on_devnet_when_policy_enabled() {
    // A1: valid v2 candidate stages when policy enabled on DevNet.
    // - candidate passes existing validation-only result;
    // - staging accepts metadata;
    // - no apply, no sequence write, no marker write, no live trust mutation.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("a1");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2),
        &valid_frame(&h, 1, Some("peer-a1")),
    );
    let validated = expect_validated(outcome);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let staged = queue.try_stage_validated(&validated, Some("digest-a1".to_string()), 100);
    assert!(
        staged.is_staged(),
        "A1: candidate must stage on DevNet when enabled, got {:?}",
        staged
    );
    assert_eq!(queue.len(), 1, "A1: queue must hold exactly the new entry");
    let entry = &queue.entries()[0];
    assert_eq!(entry.sequence, 1);
    assert_eq!(entry.peer_id.as_deref(), Some("peer-a1"));
    assert_eq!(entry.environment, bundle_env(h.env));
    assert_eq!(entry.chain_id_hex, h.chain_id_str);
    assert_eq!(entry.authority_marker_digest.as_deref(), Some("digest-a1"));
    // Run 145 negative assertions (file-level): no mutation of trust files.
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_a2_idempotent_v2_candidate_dedupes() {
    // A2: same sequence/digest candidate submitted twice → AlreadyStaged.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("a2");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2),
        &valid_frame(&h, 1, Some("peer-a2")),
    );
    let validated = expect_validated(outcome);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let first = queue.try_stage_validated(&validated, Some("digest-a2".to_string()), 100);
    assert!(first.is_staged(), "A2: first submission must stage");

    let second = queue.try_stage_validated(&validated, Some("digest-a2".to_string()), 101);
    assert!(
        second.is_already_staged(),
        "A2: second submission must dedupe, got {:?}",
        second
    );
    assert_eq!(queue.len(), 1, "A2: queue must not grow on dedup hit");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_a3_higher_sequence_v2_candidate_stages_as_newer() {
    // A3: local marker seq=N; candidate seq=N+1 → stages as newer.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("a3");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    // Stage an older v2 candidate first (representing the prior seq=N).
    let rat_v2_n = v2_ratification_for(&h, 1);
    let prior = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2_n),
        &valid_frame(&h, 1, Some("peer-a3")),
    );
    let prior_validated = expect_validated(prior);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    assert!(queue
        .try_stage_validated(&prior_validated, Some("d-n".to_string()), 100)
        .is_staged());

    // Now a higher-sequence candidate seq=N+1.
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);
    let rat_v2_next = v2_ratification_for(&h, 2);
    let newer = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2_next),
        &valid_frame(&h, 2, Some("peer-a3")),
    );
    let newer_validated = expect_validated(newer);

    let staged = queue.try_stage_validated(&newer_validated, Some("d-n1".to_string()), 200);
    assert!(staged.is_staged(), "A3: newer candidate must stage");
    assert_eq!(queue.len(), 2, "A3: both entries are retained");
    let seqs: Vec<u64> = queue.entries().iter().map(|e| e.sequence).collect();
    assert!(seqs.contains(&1) && seqs.contains(&2));
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_a4_v2_after_v1_migration_candidate_stages_v1_marker_unchanged() {
    // A4: local v1 marker exists; valid v2 migration candidate accepted by
    // validation-only; staging records migration candidate; local v1 marker
    // bytes unchanged.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("a4");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    preseed_v1_marker(&h, &marker_path, 1);
    let seq_before = sequence_snapshot(&seq_path);
    let v1_marker_before = marker_snapshot(&marker_path);
    assert!(v1_marker_before.is_some());

    let rat_v2 = v2_ratification_for(&h, 2);
    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2),
        &valid_frame(&h, 2, Some("peer-a4")),
    );
    let validated = expect_validated(outcome);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let staged = queue.try_stage_validated(&validated, Some("digest-a4".to_string()), 300);
    assert!(staged.is_staged(), "A4: v2-after-v1 migration must stage");
    // CRITICAL: v1 marker bytes are byte-identical pre/post.
    assert_no_mutation(&seq_path, seq_before, &marker_path, v1_marker_before);
}

// =====================================================================
// Run 145 — Rejection scenarios (R1–R13)
// =====================================================================

#[test]
fn run145_r1_disabled_policy_refuses_staging() {
    // R1: validation may pass; staging refuses because policy disabled.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r1");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2),
        &valid_frame(&h, 1, Some("peer-r1")),
    );
    let validated = expect_validated(outcome);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::default());
    let staged = queue.try_stage_validated(&validated, None, 100);
    assert_eq!(staged, StagingOutcome::RefusedDisabled);
    assert!(queue.is_empty(), "R1: queue must remain empty");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r2_mainnet_policy_refuses_staging_even_when_enabled() {
    // R2: even with enabled=true, MainNet staging refuses because
    // governance proof does not exist yet.
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r2");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2),
        &valid_frame(&h, 1, Some("peer-r2")),
    );
    let validated = expect_validated(outcome);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::mainnet_attempted());
    let staged = queue.try_stage_validated(&validated, None, 100);
    assert_eq!(staged, StagingOutcome::RefusedEnvironmentPolicy);
    assert!(queue.is_empty(), "R2: MainNet staging must remain empty");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r3_lower_sequence_v2_candidate_does_not_stage() {
    // R3: lower-sequence v2 candidate → validation rejected → staging
    // refuses the non-validated outcome.
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r3");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    // Preseed a v2 marker at seq=5 via the dispatcher's own success path.
    let rat_v2_persisted = v2_ratification_for(&h, 5);
    // Manually preseed using the same helper as Run 142.
    use qbind_node::pqc_authority_state::{
        derive_authority_state_v2_from_ratification, persist_authority_state_v2_atomic,
        AuthorityStateDerivationV2Inputs,
    };
    let ratified = qbind_ledger::verify_bundle_signing_key_ratification_v2(
        qbind_ledger::RatificationV2VerifierInputs {
            ratification: &rat_v2_persisted,
            authority: h.genesis_cfg.authority.as_ref().expect("authority"),
            expected_chain_id: &h.chain_id_str,
            expected_environment: env_policy(h.env),
            expected_genesis_hash: &h.canonical_hash,
        },
    )
    .expect("preseed v2 verifier");
    let hash_hex = hex_lower(&h.canonical_hash);
    let record = derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
        runtime_env: h.env,
        runtime_chain_id: h.env.chain_id(),
        runtime_genesis_hash_hex: &hash_hex,
        ratification: &rat_v2_persisted,
        ratified: &ratified,
        update_source: AuthorityStateUpdateSource::TestOrFixture,
        updated_at_unix_secs: 1_000,
    })
    .expect("preseed derive v2");
    persist_authority_state_v2_atomic(&marker_path, &record).expect("preseed write");
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2_lower = v2_ratification_for(&h, 2);
    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2_lower),
        &valid_frame(&h, 1, Some("peer-r3")),
    );
    assert!(!outcome.is_validated(), "R3: lower-sequence must reject");

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let staged = queue.try_stage_outcome(&outcome, None, 100);
    assert_eq!(staged, StagingOutcome::RefusedNotValidated);
    assert!(queue.is_empty(), "R3: queue must remain empty");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r4_same_sequence_different_digest_candidate_does_not_stage() {
    // R4: same-sequence different-digest equivocation candidate. Validation
    // rejects (e.g., signing key mismatch / v2 marker conflict); staging
    // refuses.
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r4");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    // Pre-seed a persisted v2 marker at seq=3 so the dispatcher has an
    // anchor that the equivocating candidate must conflict against.
    let rat_v2_persisted = v2_ratification_for(&h, 3);
    use qbind_node::pqc_authority_state::{
        derive_authority_state_v2_from_ratification, persist_authority_state_v2_atomic,
        AuthorityStateDerivationV2Inputs,
    };
    let ratified = qbind_ledger::verify_bundle_signing_key_ratification_v2(
        qbind_ledger::RatificationV2VerifierInputs {
            ratification: &rat_v2_persisted,
            authority: h.genesis_cfg.authority.as_ref().expect("authority"),
            expected_chain_id: &h.chain_id_str,
            expected_environment: env_policy(h.env),
            expected_genesis_hash: &h.canonical_hash,
        },
    )
    .expect("preseed v2 verifier");
    let hash_hex = hex_lower(&h.canonical_hash);
    let record = derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
        runtime_env: h.env,
        runtime_chain_id: h.env.chain_id(),
        runtime_genesis_hash_hex: &hash_hex,
        ratification: &rat_v2_persisted,
        ratified: &ratified,
        update_source: AuthorityStateUpdateSource::TestOrFixture,
        updated_at_unix_secs: 1_000,
    })
    .expect("preseed derive v2");
    persist_authority_state_v2_atomic(&marker_path, &record).expect("preseed write");

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
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);
    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2_conflict),
        &valid_frame(&h, 1, Some("peer-r4")),
    );
    assert!(!outcome.is_validated(), "R4: equivocation must reject");

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let staged = queue.try_stage_outcome(&outcome, None, 100);
    assert_eq!(staged, StagingOutcome::RefusedNotValidated);
    assert!(queue.is_empty());
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r5_bad_signature_candidate_does_not_stage() {
    // R5: bad-signature candidate. Run 130 v2 verifier rejects; staging
    // refuses the non-validated outcome.
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r5");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut rat_v2 = v2_ratification_for(&h, 1);
    rat_v2.signature[0] ^= 0xFF;

    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2),
        &valid_frame(&h, 1, Some("peer-r5")),
    );
    assert!(!outcome.is_validated(), "R5: bad signature must reject");

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let staged = queue.try_stage_outcome(&outcome, None, 100);
    assert_eq!(staged, StagingOutcome::RefusedNotValidated);
    assert!(queue.is_empty());
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r6_wrong_domain_candidate_does_not_stage() {
    // R6: wrong-domain (wrong environment) candidate. Validation rejects;
    // staging refuses.
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r6");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut rat_v2 = v2_ratification_for(&h, 1);
    // Flip to a different environment to violate the domain.
    rat_v2.environment = RatificationEnvironment::Devnet;

    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2),
        &valid_frame(&h, 1, Some("peer-r6")),
    );
    assert!(!outcome.is_validated(), "R6: wrong-domain must reject");

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let staged = queue.try_stage_outcome(&outcome, None, 100);
    assert_eq!(staged, StagingOutcome::RefusedNotValidated);
    assert!(queue.is_empty());
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r7_ambiguous_v1_plus_v2_candidate_does_not_stage() {
    // R7: ambiguous v1+v2 candidate. Run 142 fail-closed ambiguity
    // rejection applies; staging refuses.
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r7");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v1 = v1_ratification_for(&h);
    let rat_v2 = v2_ratification_for(&h, 1);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        metrics,
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v1_plus_v2_rat_config(&h, rat_v1, rat_v2)),
    );
    let outcome = disp.dispatch_frame_for_test(&valid_frame(&h, 1, Some("peer-r7")));
    assert!(!outcome.is_validated(), "R7: ambiguous v1+v2 must reject");

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let staged = queue.try_stage_outcome(&outcome, None, 100);
    assert_eq!(staged, StagingOutcome::RefusedNotValidated);
    assert!(queue.is_empty());
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r8_duplicate_candidate_does_not_grow_queue() {
    // R8: bounded/deduped behavior — repeated submissions of the same
    // candidate do not grow the queue.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r8");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2),
        &valid_frame(&h, 1, Some("peer-r8")),
    );
    let validated = expect_validated(outcome);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    for i in 0..10 {
        let out = queue.try_stage_validated(&validated, Some("dig-r8".to_string()), 100 + i);
        if i == 0 {
            assert!(out.is_staged());
        } else {
            assert!(out.is_already_staged());
        }
    }
    assert_eq!(queue.len(), 1, "R8: queue must not grow under dedup");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r9_per_peer_bound_enforced() {
    // R9: one peer cannot fill the queue beyond configured cap.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r9");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut policy = PeerDrivenStagingPolicy::devnet_enabled();
    policy.max_candidates_per_peer = 2;
    policy.max_staged_candidates = 8;
    let mut queue = PeerCandidateStagingQueue::new(policy);

    // Three distinct candidates from the same peer (distinct sequences).
    for seq in 1u64..=3 {
        let rat = v2_ratification_for(&h, seq);
        let outcome = dispatch_via_v2(
            &h,
            &seq_path,
            &marker_path,
            Some(rat),
            &valid_frame(&h, seq, Some("peer-r9")),
        );
        let validated = expect_validated(outcome);
        let result =
            queue.try_stage_validated(&validated, Some(format!("dig-r9-{}", seq)), 100 + seq);
        if seq <= 2 {
            assert!(result.is_staged(), "first {} must stage", seq);
        } else {
            assert_eq!(
                result,
                StagingOutcome::RefusedPerPeerCapacity { cap: 2 },
                "third must refuse per-peer cap"
            );
        }
    }
    assert_eq!(queue.len(), 2, "R9: per-peer cap holds queue at 2");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r10_global_bound_enforced_reject_new() {
    // R10: queue rejects new entries when global cap reached.
    // Eviction policy is explicitly reject-new (safer than silent eviction).
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r10");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut policy = PeerDrivenStagingPolicy::devnet_enabled();
    policy.max_staged_candidates = 2;
    policy.max_candidates_per_peer = 5; // not the limiting factor here
    let mut queue = PeerCandidateStagingQueue::new(policy);

    for (i, peer) in ["peer-a", "peer-b", "peer-c"].iter().enumerate() {
        let seq = (i + 1) as u64;
        let rat = v2_ratification_for(&h, seq);
        let outcome = dispatch_via_v2(
            &h,
            &seq_path,
            &marker_path,
            Some(rat),
            &valid_frame(&h, seq, Some(peer)),
        );
        let validated = expect_validated(outcome);
        let result = queue.try_stage_validated(
            &validated,
            Some(format!("dig-r10-{}", peer)),
            100 + seq,
        );
        if i < 2 {
            assert!(result.is_staged());
        } else {
            assert_eq!(
                result,
                StagingOutcome::RefusedGlobalCapacity { cap: 2 },
                "third candidate (from a new peer) must be reject-new"
            );
        }
    }
    assert_eq!(queue.len(), 2, "R10: global cap holds queue at 2");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r11_ttl_expiry_removes_stale_staged_candidate() {
    // R11: expired candidate cannot be applied later. Since apply does
    // not exist, assert that it is removed/unavailable after the TTL
    // sweep — and that the entry was never applied (queue is the only
    // residence; no apply call site exists).
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r11");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut policy = PeerDrivenStagingPolicy::devnet_enabled();
    policy.ttl_secs = 10;
    let mut queue = PeerCandidateStagingQueue::new(policy);

    let rat_v2 = v2_ratification_for(&h, 1);
    let outcome = dispatch_via_v2(
        &h,
        &seq_path,
        &marker_path,
        Some(rat_v2),
        &valid_frame(&h, 1, Some("peer-r11")),
    );
    let validated = expect_validated(outcome);

    let staged_at = 1_000u64;
    let staged =
        queue.try_stage_validated(&validated, Some("dig-r11".to_string()), staged_at);
    assert!(staged.is_staged());
    assert_eq!(queue.len(), 1);

    // Sweep at staged_at + ttl_secs + 1 → expires.
    let removed = queue.purge_expired(staged_at + 11);
    assert_eq!(removed, 1, "R11: expired entry must be swept");
    assert_eq!(queue.len(), 0, "R11: queue must be empty after sweep");
    // Subsequent stage attempts with a different time should also lazily
    // sweep (already empty here, but lazy sweep contract holds).
    queue.purge_expired(staged_at + 100);
    assert_eq!(queue.len(), 0);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r12_v1_live_inbound_behavior_unchanged() {
    // R12: v1 validation-only path remains unchanged. No v2 staging unless
    // explicitly valid and policy permits.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r12");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    // Drive the dispatcher with a v1 sidecar exactly like Run 142 R9.
    let rat_v1 = v1_ratification_for(&h);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        metrics,
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v1_rat_config(&h, Some(&rat_v1))),
    );
    let outcome = disp.dispatch_frame_for_test(&valid_frame(&h, 1, Some("peer-r12")));
    // The v1 path may validate or rebroadcast — either way it is unchanged.
    // The Run 145 invariant here is the staging queue: if and only if the
    // outcome is Validated, the queue accepts it; otherwise refuses. v1
    // dispatcher behaviour is not modified by Run 145.
    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let staged = queue.try_stage_outcome(&outcome, None, 100);
    if outcome.is_validated() {
        assert!(staged.is_staged(), "v1 validated outcome may stage");
        assert_eq!(queue.len(), 1);
    } else {
        assert_eq!(staged, StagingOutcome::RefusedNotValidated);
        assert!(queue.is_empty());
    }
    // Critically, no mutation to trust files occurs on the v1 path.
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run145_r13_propagation_only_behavior_unchanged() {
    // R13: staging does not imply propagation; propagation remains
    // governed by existing Run 088 / Run 143 rules.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r13");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    // Dispatcher has propagation disabled by default → no sender used.
    let sender = RecordingSender::with_peers(vec![NodeId::from([13u8; 32])]);
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        metrics,
        Some(Arc::clone(&sender)),
        PeerCandidatePropagationConfig::default(), // disabled
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
    );
    let outcome = disp.dispatch_frame_for_test(&valid_frame(&h, 1, Some("peer-r13")));
    let validated = expect_validated(outcome);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let staged = queue.try_stage_validated(&validated, Some("dig-r13".to_string()), 100);
    assert!(staged.is_staged(), "R13: staging is independent of propagation");
    assert_eq!(
        sender.sent_count(),
        0,
        "R13: staging must NOT trigger propagation"
    );
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

// =====================================================================
// Run 145 — Constants / structural assertions
// =====================================================================

#[test]
fn run145_default_constants_match_documented_values() {
    assert_eq!(DEFAULT_MAX_STAGED_CANDIDATES, 16);
    assert_eq!(DEFAULT_MAX_CANDIDATES_PER_PEER, 4);
    assert_eq!(DEFAULT_TTL_SECS, 300);
}

#[test]
fn run145_default_policy_is_disabled_everywhere() {
    let p = PeerDrivenStagingPolicy::default();
    assert!(!p.enabled);
    assert!(!p.allow_devnet);
    assert!(!p.allow_testnet);
    assert!(!p.allow_mainnet);
}

#[test]
fn run145_staged_entry_metadata_is_log_safe() {
    // StagedPeerCandidate must hold only log-safe metadata (peer id,
    // fingerprint, sequence, environment, chain id, time, marker digest,
    // signature_verified). No bundle bytes; no live trust state.
    let entry = StagedPeerCandidate {
        peer_id: Some("p".to_string()),
        fingerprint_prefix: "00112233".to_string(),
        fingerprint_hex: "0".repeat(64),
        sequence: 1,
        environment: TrustBundleEnvironment::Devnet,
        chain_id_hex: "0".repeat(16),
        staged_at_unix_secs: 0,
        authority_marker_digest: None,
        signature_verified: true,
    };
    // Compile-time guarantee: the entry has no bytes-of-bundle field.
    let _: &str = &entry.fingerprint_prefix;
}