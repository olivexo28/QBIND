//! Run 146 — integration tests for the **non-applying peer-candidate
//! staging hook** wired into the **live inbound `0x05`** validation-only
//! path.
//!
//! These tests exercise the [`LivePeerCandidateWireDispatcher`] with a
//! [`PeerCandidateStagingQueue`] installed via
//! [`LivePeerCandidateWireDispatcherConfig::staging_queue`] and assert
//! the full Run 146 acceptance / rejection matrix from
//! `task/RUN_146_TASK.txt`:
//!
//! * **A1** accepted v2 candidate stages when policy enabled
//! * **A2** accepted idempotent v2 candidate dedupes in runtime hook
//! * **A3** higher-sequence v2 candidate stages
//! * **A4** v2-after-v1 migration candidate stages, v1 marker untouched
//! * **R1** staging disabled preserves Run 143 behavior
//! * **R2** MainNet refuses staging
//! * **R3** lower-sequence v2 candidate does not stage
//! * **R4** same-sequence different-digest candidate does not stage
//! * **R5** bad-signature candidate does not stage
//! * **R6** wrong-domain (wrong-chain) candidate does not stage
//! * **R7** ambiguous v1+v2 candidate does not stage
//! * **R8** propagation disabled + staging enabled
//! * **R9** propagation enabled + staging disabled
//! * **R10** propagation enabled + staging enabled
//! * **R11** queue bounds enforced through live hook
//! * **R12** TTL expiry through live hook
//! * **R13** v1 live inbound regression
//! * **R14** legacy/no-sidecar regression
//!
//! # Strict scope (Run 146)
//!
//! * Source/test wiring only. Release-binary staging evidence is
//!   deferred to Run 147.
//! * Validation-only receive path. **No live apply.**
//! * No peer-driven trust-state mutation. No sequence write. No
//!   authority-marker write. No session eviction. No SIGHUP /
//!   reload-apply. No Run 070 apply invocation. No new wire format.
//! * MainNet refuses staging unconditionally.
//!
//! Each test, in addition to the per-scenario assertions, performs the
//! Run 146 negative invariants:
//!
//! * `pqc_trust_bundle_sequence.json` is byte-identical pre/post.
//! * `pqc_authority_state.json` is byte-identical pre/post.
//! * If a `RecordingSender` is supplied, its sent count is asserted
//!   appropriately for the propagation flag under test.

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
use qbind_node::pqc_authority_state::authority_state_file_path;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_staging::{
    PeerCandidateStagingQueue, PeerDrivenStagingPolicy,
};
use qbind_node::pqc_peer_candidate_wire::{
    encode_peer_candidate_wire_frame, LivePeerCandidateWireDispatcher,
    LivePeerCandidateWireDispatcherConfig, LiveRatificationConfig,
    PeerCandidatePropagationConfig, PeerCandidateWireEnvelopeV1, PeerCandidateWireFrameSender,
    PeerCandidateWireReceiverConfig, RawFramePeerSendOutcome, RawFrameSendReport,
    PEER_CANDIDATE_WIRE_DOMAIN_TAG, PEER_CANDIDATE_WIRE_VERSION,
};
use qbind_node::pqc_ratification_policy::ratification_gate_decision;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::PeerCandidateConfig;
use qbind_node::pqc_trust_reload::{validate_candidate_bundle, ReloadCheckInputs};
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

// =====================================================================
// Harness (adapted from run_142 / run_145 tests)
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
        "qbind-run146-{}-{}-{}",
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
        "run146-bundle-signing-authority",
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
        peer_id: Some("run146-peer".to_string()),
        environment: bundle_env(h.env),
        chain_id_hex: h.chain_id_str.clone(),
        declared_sequence,
        declared_fingerprint_prefix,
        declared_length: len,
        bundle_bytes,
        governance_authority_proof: None,
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
        gate_decision: ratification_gate_decision(h.env, true),
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
        gate_decision: ratification_gate_decision(h.env, true),
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
        gate_decision: ratification_gate_decision(h.env, true),
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

/// Run 146 negative invariants: trust-state-related files must be
/// byte-identical pre/post regardless of whether staging happened.
fn assert_no_mutation(
    seq_path: &Path,
    seq_before: Option<Vec<u8>>,
    marker_path: &Path,
    marker_before: Option<Vec<u8>>,
) {
    assert_eq!(
        sequence_snapshot(seq_path),
        seq_before,
        "Run 146 invariant: pqc_trust_bundle_sequence.json must be byte-identical pre/post"
    );
    assert_eq!(
        marker_snapshot(marker_path),
        marker_before,
        "Run 146 invariant: pqc_authority_state.json must be byte-identical pre/post"
    );
}

/// Pre-seed a persisted v2 marker on disk.
fn preseed_v2_marker(h: &Harness, marker_path: &Path, ratification: &BundleSigningRatificationV2) {
    use qbind_node::pqc_authority_state::{
        derive_authority_state_v2_from_ratification, persist_authority_state_v2_atomic,
        AuthorityStateDerivationV2Inputs, AuthorityStateUpdateSource,
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
    .expect("preseed v2 verify");
    let record = derive_authority_state_v2_from_ratification(AuthorityStateDerivationV2Inputs {
        runtime_env: h.env,
        runtime_chain_id: h.env.chain_id(),
        runtime_genesis_hash_hex: &hex_lower(&h.canonical_hash),
        ratification,
        ratified: &ratified,
        update_source: AuthorityStateUpdateSource::TestOrFixture,
        updated_at_unix_secs: 1_000,
    })
    .expect("derive v2 marker");
    persist_authority_state_v2_atomic(marker_path, &record).expect("persist v2 marker");
}

fn preseed_v1_marker(h: &Harness, marker_path: &Path, sequence: u64) {
    use qbind_node::pqc_authority_state::{
        persist_authority_state_atomic, AuthorityStateUpdateSource, PersistentAuthorityStateRecord,
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
        1_000,
    );
    persist_authority_state_atomic(marker_path, &record).expect("persist v1 marker");
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
    staging_queue: Option<Arc<Mutex<PeerCandidateStagingQueue>>>,
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
            staging_queue,
        },
        metrics,
    )
}

fn new_queue(policy: PeerDrivenStagingPolicy) -> Arc<Mutex<PeerCandidateStagingQueue>> {
    Arc::new(Mutex::new(PeerCandidateStagingQueue::new(policy)))
}

// =====================================================================
// Acceptance scenarios (A1–A4)
// =====================================================================

#[test]
fn run146_a1_accepted_v2_candidate_stages_when_policy_enabled() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("a1");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
        Some(Arc::clone(&queue)),
    );
    assert!(disp.staging_hook_is_armed(), "A1: hook must be armed");

    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "A1: validation must accept, got {:?}", out);

    let q = queue.lock();
    assert_eq!(q.len(), 1, "A1: queue must contain exactly one entry");
    let entries = q.entries();
    assert_eq!(entries[0].sequence, 1);
    assert_eq!(entries[0].environment, bundle_env(h.env));
    assert_eq!(entries[0].chain_id_hex, h.chain_id_str);
    assert!(entries[0].signature_verified);
    assert!(entries[0].authority_marker_digest.is_some());
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_a2_idempotent_v2_candidate_dedupes_in_runtime_hook() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("a2");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
        Some(Arc::clone(&queue)),
    );

    let frame = valid_frame(&h, 1);
    // First dispatch stages.
    let o1 = disp.dispatch_frame_for_test(&frame);
    assert!(o1.is_validated(), "A2: first frame must validate");
    // Second dispatch: same frame. The Run 088 dedup will short-circuit
    // to DuplicateSuppressed, so try_stage_outcome returns
    // RefusedNotValidated and the queue does NOT grow.
    let _o2 = disp.dispatch_frame_for_test(&frame);

    let q = queue.lock();
    assert_eq!(
        q.len(),
        1,
        "A2: queue must not grow on byte-identical resubmission"
    );
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_a3_higher_sequence_v2_candidate_stages() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("a3");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    // Persisted v2 marker at seq=3; candidate carries seq=4.
    let rat_v2_persisted = v2_ratification_for(&h, 3);
    preseed_v2_marker(&h, &marker_path, &rat_v2_persisted);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2_candidate = v2_ratification_for(&h, 4);
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2_candidate))),
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 4));
    assert!(out.is_validated(), "A3: higher-seq must accept, got {:?}", out);

    let q = queue.lock();
    assert_eq!(q.len(), 1, "A3: queue must contain the newer candidate");
    assert_eq!(q.entries()[0].sequence, 4);
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_a4_v2_after_v1_migration_candidate_stages_v1_marker_unchanged() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("a4");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    // Pre-existing v1 marker.
    preseed_v1_marker(&h, &marker_path, 1);
    let seq_before = sequence_snapshot(&seq_path);
    let v1_marker_before = marker_snapshot(&marker_path);
    assert!(v1_marker_before.is_some());

    let rat_v2 = v2_ratification_for(&h, 2);
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "A4: v2-after-v1 must accept");
    let q = queue.lock();
    assert_eq!(q.len(), 1, "A4: candidate must stage");
    drop(q);
    // CRITICAL: v1 marker bytes preserved.
    assert_no_mutation(&seq_path, seq_before, &marker_path, v1_marker_before);
}

// =====================================================================
// Rejection scenarios (R1–R14)
// =====================================================================

#[test]
fn run146_r1_staging_disabled_preserves_run143_behavior() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r1");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    // Disabled-by-default policy on DevNet.
    let queue = new_queue(PeerDrivenStagingPolicy::default());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
        Some(Arc::clone(&queue)),
    );
    assert!(
        !disp.staging_hook_is_armed(),
        "R1: hook must NOT be armed under default disabled policy"
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "R1: validation-only outcome unchanged");

    let q = queue.lock();
    assert!(q.is_empty(), "R1: disabled policy must not stage");
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r2_mainnet_refuses_staging() {
    let h = harness(NetworkEnvironment::Mainnet);
    let dir = tmpdir("r2");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    // Policy explicitly attempts to enable MainNet; the queue refuses
    // unconditionally.
    let queue = new_queue(PeerDrivenStagingPolicy::mainnet_attempted());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
        Some(Arc::clone(&queue)),
    );
    assert!(
        !disp.staging_hook_is_armed(),
        "R2: MainNet must never arm the hook"
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "R2: validation must remain unaffected");

    let q = queue.lock();
    assert!(q.is_empty(), "R2: MainNet staging must remain empty");
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r3_lower_sequence_v2_candidate_does_not_stage() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r3");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    let rat_v2_persisted = v2_ratification_for(&h, 5);
    preseed_v2_marker(&h, &marker_path, &rat_v2_persisted);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2_candidate = v2_ratification_for(&h, 2);
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2_candidate))),
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 2));
    assert!(!out.is_validated(), "R3: lower-seq must reject");

    let q = queue.lock();
    assert!(q.is_empty(), "R3: rejected candidate must NOT stage");
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r4_same_sequence_different_digest_candidate_does_not_stage() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r4");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);

    let rat_v2_persisted = v2_ratification_for(&h, 3);
    preseed_v2_marker(&h, &marker_path, &rat_v2_persisted);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

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
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2_conflict))),
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 3));
    assert!(!out.is_validated(), "R4: equivocation must reject");

    let q = queue.lock();
    assert!(q.is_empty(), "R4: rejected candidate must NOT stage");
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r5_bad_signature_candidate_does_not_stage() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r5");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut rat_v2 = v2_ratification_for(&h, 1);
    rat_v2.signature[0] ^= 0xFF;
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(!out.is_validated(), "R5: bad signature must reject");

    let q = queue.lock();
    assert!(q.is_empty(), "R5: bad-signature candidate must NOT stage");
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r6_wrong_chain_candidate_does_not_stage() {
    // Run 146 §R6 — "wrong-domain" maps to the broader Run 142 family
    // of wrong-env/wrong-chain/wrong-genesis ratification rejections.
    // The validator rejects under the v2 verifier before staging is
    // ever consulted.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r6");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut rat_v2 = v2_ratification_for(&h, 1);
    rat_v2.chain_id = "0000000000000000".to_string();
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(!out.is_validated(), "R6: wrong-chain must reject");

    let q = queue.lock();
    assert!(q.is_empty(), "R6: rejected candidate must NOT stage");
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r7_ambiguous_v1_plus_v2_candidate_does_not_stage() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r7");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v1 = v1_ratification_for(&h);
    let rat_v2 = v2_ratification_for(&h, 1);
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v1_plus_v2_rat_config(&h, rat_v1, rat_v2)),
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(!out.is_validated(), "R7: ambiguous v1+v2 must reject");

    let q = queue.lock();
    assert!(q.is_empty(), "R7: ambiguous candidate must NOT stage");
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r8_propagation_disabled_and_staging_enabled() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r8");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let sender = RecordingSender::with_peers(vec![NodeId::from([42u8; 32])]);
    let metrics = Arc::new(P2pMetrics::default());
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
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "R8: validation must accept");

    let q = queue.lock();
    assert_eq!(q.len(), 1, "R8: candidate must stage");
    drop(q);
    assert_eq!(sender.sent_count(), 0, "R8: must NOT propagate");
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r9_propagation_enabled_and_staging_disabled() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r9");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    // Disabled queue: validation passes & propagation occurs; queue
    // remains empty.
    let queue = new_queue(PeerDrivenStagingPolicy::default());
    let sender = RecordingSender::with_peers(vec![NodeId::from([55u8; 32])]);
    let metrics = Arc::new(P2pMetrics::default());
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
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "R9: validation must accept");

    let q = queue.lock();
    assert!(q.is_empty(), "R9: disabled queue must NOT stage");
    drop(q);
    assert_eq!(
        sender.sent_count(),
        1,
        "R9: propagation must proceed independent of staging"
    );
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r10_propagation_enabled_and_staging_enabled() {
    let h = harness(NetworkEnvironment::Devnet);

    // Sub-case 10a — valid candidate: both stage and propagate.
    {
        let dir = tmpdir("r10a");
        let marker_path = authority_state_file_path(&dir);
        let seq_path = sequence_file_path(&dir);
        let seq_before = sequence_snapshot(&seq_path);
        let marker_before = marker_snapshot(&marker_path);

        let rat_v2 = v2_ratification_for(&h, 1);
        let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
        let sender = RecordingSender::with_peers(vec![NodeId::from([77u8; 32])]);
        let metrics = Arc::new(P2pMetrics::default());
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
            Some(Arc::clone(&queue)),
        );
        let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
        assert!(out.is_validated(), "R10a: validation must accept");
        let q = queue.lock();
        assert_eq!(q.len(), 1, "R10a: candidate must stage");
        drop(q);
        assert_eq!(sender.sent_count(), 1, "R10a: must propagate");
        assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
    }

    // Sub-case 10b — invalid candidate (bad sig): neither stages nor
    // propagates.
    {
        let dir = tmpdir("r10b");
        let marker_path = authority_state_file_path(&dir);
        let seq_path = sequence_file_path(&dir);
        let seq_before = sequence_snapshot(&seq_path);
        let marker_before = marker_snapshot(&marker_path);

        let mut rat_v2 = v2_ratification_for(&h, 1);
        rat_v2.signature[0] ^= 0xFF;
        let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
        let sender = RecordingSender::with_peers(vec![NodeId::from([88u8; 32])]);
        let metrics = Arc::new(P2pMetrics::default());
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
            Some(Arc::clone(&queue)),
        );
        let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
        assert!(!out.is_validated(), "R10b: invalid candidate must reject");
        let q = queue.lock();
        assert!(q.is_empty(), "R10b: invalid candidate must NOT stage");
        drop(q);
        assert_eq!(sender.sent_count(), 0, "R10b: must NOT propagate");
        assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
    }
}

#[test]
fn run146_r11_queue_bounds_enforced_through_live_hook() {
    // Tight global cap. Verifies the hook enforces capacity end-to-end.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r11");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut policy = PeerDrivenStagingPolicy::devnet_enabled();
    policy.max_staged_candidates = 2;
    policy.max_candidates_per_peer = 2;
    let queue = new_queue(policy);

    // Dispatch three distinct candidates (sequences 1, 2, 3). Each
    // requires its own ratification + a fresh dispatcher build because
    // the live ratification context is per-dispatcher.
    let mut staged_count = 0usize;
    for seq in [1u64, 2, 3] {
        let rat_v2 = v2_ratification_for(&h, seq);
        let metrics = Arc::new(P2pMetrics::default());
        let disp = dispatcher(
            &h,
            Arc::clone(&metrics),
            None,
            PeerCandidatePropagationConfig::default(),
            Some(seq_path.clone()),
            Some(marker_path.clone()),
            Some(live_v2_rat_config(&h, Some(rat_v2))),
            Some(Arc::clone(&queue)),
        );
        let out = disp.dispatch_frame_for_test(&valid_frame(&h, seq));
        if out.is_validated() {
            staged_count += 1;
        }
    }
    assert!(staged_count >= 2, "R11: at least 2 frames must validate");

    let q = queue.lock();
    assert!(
        q.len() <= 2,
        "R11: queue length must respect cap=2, got {}",
        q.len()
    );
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r12_ttl_expiry_through_live_hook() {
    // Stage one candidate, advance "now" past TTL via purge_expired,
    // confirm the staged entry is unavailable.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r12");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let mut policy = PeerDrivenStagingPolicy::devnet_enabled();
    policy.ttl_secs = 60;
    let queue = new_queue(policy);

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
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "R12: must validate before TTL");
    {
        let q = queue.lock();
        assert_eq!(q.len(), 1, "R12: candidate is staged");
    }

    // Advance well past TTL and sweep.
    let mut q = queue.lock();
    let staged_at = q.entries()[0].staged_at_unix_secs;
    let purged = q.purge_expired(staged_at + 10_000);
    assert_eq!(purged, 1, "R12: expired entry must be swept");
    assert!(q.is_empty(), "R12: queue empty after TTL sweep");
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r13_v1_live_inbound_regression_unchanged() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r13");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    // v1 sidecar, no v2. The Run 109 v1 path validates; the dispatcher's
    // marker-conflict derivation runs the v1 enforcer. We confirm that
    // when staging is disabled (default policy), v1 behavior is exactly
    // unchanged.
    let rat_v1 = v1_ratification_for(&h);
    let queue = new_queue(PeerDrivenStagingPolicy::default());
    let metrics = Arc::new(P2pMetrics::default());
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v1_rat_config(&h, Some(&rat_v1))),
        Some(Arc::clone(&queue)),
    );
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(
        out.is_validated(),
        "R13: v1 live inbound regression must remain unchanged, got {:?}",
        out
    );
    let q = queue.lock();
    assert!(q.is_empty(), "R13: disabled policy does not stage v1");
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

#[test]
fn run146_r14_legacy_no_sidecar_regression_unchanged() {
    // No ratification context, no staging queue → exactly the
    // pre-Run-146 legacy unguarded path.
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("r14");
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
        None, // no ratification context
        None, // no staging queue
    );
    assert!(!disp.ratification_gate_is_invoked());
    assert!(!disp.staging_hook_is_armed());
    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(
        out.is_validated(),
        "R14: legacy unguarded path must remain unchanged"
    );
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}

// =====================================================================
// Late-install via set_staging_queue — the Run 147 production wiring
// path will install the queue after dispatcher construction (e.g. once
// CLI flags are resolved). Verify this path is observable and behaves
// identically to constructor-installation.
// =====================================================================

#[test]
fn run146_late_install_set_staging_queue_arms_hook() {
    let h = harness(NetworkEnvironment::Devnet);
    let dir = tmpdir("late");
    let marker_path = authority_state_file_path(&dir);
    let seq_path = sequence_file_path(&dir);
    let seq_before = sequence_snapshot(&seq_path);
    let marker_before = marker_snapshot(&marker_path);

    let rat_v2 = v2_ratification_for(&h, 1);
    let metrics = Arc::new(P2pMetrics::default());
    let mut disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        None,
        PeerCandidatePropagationConfig::default(),
        Some(seq_path.clone()),
        Some(marker_path.clone()),
        Some(live_v2_rat_config(&h, Some(rat_v2))),
        None, // no queue at construction time
    );
    assert!(!disp.staging_hook_is_armed(), "no queue installed yet");

    // Late install — the Run 147 production wiring path.
    let queue = new_queue(PeerDrivenStagingPolicy::devnet_enabled());
    disp.set_staging_queue(Arc::clone(&queue));
    assert!(
        disp.staging_hook_is_armed(),
        "late install must arm the hook"
    );

    let out = disp.dispatch_frame_for_test(&valid_frame(&h, 1));
    assert!(out.is_validated(), "late install: validation must accept");
    let q = queue.lock();
    assert_eq!(q.len(), 1, "late install: candidate must stage");
    drop(q);
    assert_no_mutation(&seq_path, seq_before, &marker_path, marker_before);
}