use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use qbind_crypto::MlDsa44Backend;
use qbind_node::metrics::P2pMetrics;
use qbind_node::p2p::NodeId;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_wire::{
    encode_peer_candidate_wire_frame, LivePeerCandidateWireDispatcher,
    LivePeerCandidateWireDispatcherConfig, PeerCandidatePropagationConfig,
    PeerCandidateWireEnvelopeV1, PeerCandidateWireFrameSender, PeerCandidateWireOutcome,
    PeerCandidateWireReceiverConfig, RawFramePeerSendOutcome, RawFrameSendReport,
    MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES, PEER_CANDIDATE_WIRE_DOMAIN_TAG,
    PEER_CANDIDATE_WIRE_VERSION, DISCRIMINATOR_PEER_CANDIDATE_WIRE,
};
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
        "qbind-run088-{}-{}-{}",
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

struct DevnetSigningHarness {
    signing_keys: BundleSigningKeySet,
    signing_key_id: [u8; 32],
    signing_sk: Vec<u8>,
    root_id_hex: String,
    root_pk_hex: String,
}

fn devnet_signing_harness() -> DevnetSigningHarness {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
    let id = derive_signing_key_id(&pk);
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: pk,
    }]);
    let root = mint_devnet_root().expect("mint devnet root");
    DevnetSigningHarness {
        signing_keys,
        signing_key_id: id,
        signing_sk: sk,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

fn build_signed_devnet_bundle(h: &DevnetSigningHarness, sequence: u64) -> TrustBundle {
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: TrustBundleEnvironment::Devnet,
        chain_id: Some(chain_id_hex(NetworkEnvironment::Devnet.chain_id())),
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

fn loader_fingerprint_prefix(bundle_bytes: &[u8], keys: &BundleSigningKeySet) -> String {
    let dir = tmpdir("fpprobe");
    let path = dir.join("probe.json");
    std::fs::write(&path, bundle_bytes).expect("write probe");
    let inputs = ReloadCheckInputs {
        candidate_path: &path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys: keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: None,
        local_leaf_cert_bytes: None,
    };
    validate_candidate_bundle(inputs)
        .expect("probe validates")
        .fingerprint_prefix
}

fn wire_envelope(
    bundle_bytes: Vec<u8>,
    declared_sequence: u64,
    declared_fingerprint_prefix: String,
) -> PeerCandidateWireEnvelopeV1 {
    let len = bundle_bytes.len();
    PeerCandidateWireEnvelopeV1 {
        envelope_version: PEER_CANDIDATE_WIRE_VERSION,
        domain_tag: PEER_CANDIDATE_WIRE_DOMAIN_TAG.to_string(),
        peer_id: Some("run088-peer".to_string()),
        environment: TrustBundleEnvironment::Devnet,
        chain_id_hex: chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
        declared_sequence,
        declared_fingerprint_prefix,
        declared_length: len,
        bundle_bytes,
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
    h: &DevnetSigningHarness,
    metrics: Arc<P2pMetrics>,
    sender: Arc<RecordingSender>,
    propagation: PeerCandidatePropagationConfig,
    sequence_path: Option<PathBuf>,
) -> LivePeerCandidateWireDispatcher {
    let scratch = tmpdir("scratch");
    let sender_trait: Arc<dyn PeerCandidateWireFrameSender> = sender;
    LivePeerCandidateWireDispatcher::new(
        LivePeerCandidateWireDispatcherConfig {
            inner: PeerCandidateWireReceiverConfig {
                enabled: true,
                inner: PeerCandidateConfig::default(),
            },
            expected_environment: NetworkEnvironment::Devnet,
            expected_chain_id: NetworkEnvironment::Devnet.chain_id(),
            scratch_dir: scratch,
            signing_keys: h.signing_keys.clone(),
            activation_ctx: ActivationContext::height_only(0),
            consensus_storage_for_epoch: None,
            sequence_persistence_path: sequence_path,
            local_leaf_cert_bytes: None,
            validation_time_secs: 100,
            propagation,
            propagation_sender: Some(sender_trait),
            live_ratification: None,
            authority_marker_path: None,
            staging_queue: None,
        },
        metrics,
    )
}

fn valid_frame(h: &DevnetSigningHarness, sequence: u64) -> Vec<u8> {
    let bundle = build_signed_devnet_bundle(h, sequence);
    let bytes = bundle_to_bytes(&bundle);
    let fp = loader_fingerprint_prefix(&bytes, &h.signing_keys);
    encode_peer_candidate_wire_frame(&wire_envelope(bytes, sequence, fp)).expect("encode")
}

#[test]
fn run088_disabled_by_default_valid_candidate_does_not_rebroadcast() {
    let h = devnet_signing_harness();
    let metrics = Arc::new(P2pMetrics::default());
    let source = NodeId::new([1u8; 32]);
    let target = NodeId::new([2u8; 32]);
    let sender = RecordingSender::with_peers(vec![source, target]);
    let data = tmpdir("seq-disabled");
    let seq = sequence_file_path(&data);
    let before = sequence_snapshot(&seq);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Arc::clone(&sender),
        PeerCandidatePropagationConfig::default(),
        Some(seq.clone()),
    );
    let out = disp.dispatch_frame_from_peer_for_test(&valid_frame(&h, 10), Some(source));
    assert!(matches!(out, PeerCandidateWireOutcome::ValidatorRan(_)));
    assert_eq!(metrics.peer_candidate_validated_total(), 1);
    assert_eq!(metrics.peer_candidate_propagation_attempt_total(), 0);
    assert_eq!(metrics.peer_candidate_propagation_sent_total(), 0);
    assert!(sender.sent.lock().is_empty());
    assert_sequence_unchanged(&seq, before);
}

#[test]
fn run088_enabled_valid_candidate_rebroadcasts_once_to_non_source_only() {
    let h = devnet_signing_harness();
    let metrics = Arc::new(P2pMetrics::default());
    let source = NodeId::new([1u8; 32]);
    let target = NodeId::new([2u8; 32]);
    let sender = RecordingSender::with_peers(vec![source, target]);
    let data = tmpdir("seq-valid");
    let seq = sequence_file_path(&data);
    let before = sequence_snapshot(&seq);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Arc::clone(&sender),
        PeerCandidatePropagationConfig {
            enabled: true,
            ..PeerCandidatePropagationConfig::default()
        },
        Some(seq.clone()),
    );
    let frame = valid_frame(&h, 11);
    let out = disp.dispatch_frame_from_peer_for_test(&frame, Some(source));
    assert!(out.is_validated());
    assert_eq!(metrics.peer_candidate_propagation_attempt_total(), 1);
    assert_eq!(metrics.peer_candidate_propagation_sent_total(), 1);
    let sent = sender.sent.lock();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, vec![target]);
    assert_eq!(sent[0].1, frame);
    assert_sequence_unchanged(&seq, before);
    assert_eq!(metrics.live_reload_apply_success_total(), 0);
    assert_eq!(metrics.live_reload_apply_failure_total(), 0);
    assert_eq!(metrics.session_eviction_attempt_total(), 0);
    assert_eq!(metrics.live_reload_sessions_evicted_total(), 0);
    assert!(!metrics
        .format_metrics()
        .contains("qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total"));
}

#[test]
fn run088_invalid_and_oversize_candidates_do_not_rebroadcast() {
    let h = devnet_signing_harness();
    let metrics = Arc::new(P2pMetrics::default());
    let sender = RecordingSender::with_peers(vec![NodeId::new([2u8; 32])]);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Arc::clone(&sender),
        PeerCandidatePropagationConfig {
            enabled: true,
            ..PeerCandidatePropagationConfig::default()
        },
        None,
    );
    let mut bad = valid_frame(&h, 12);
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    let out = disp.dispatch_frame_from_peer_for_test(&bad, Some(NodeId::new([1u8; 32])));
    assert!(!out.is_validated());

    let mut oversize = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
    oversize.extend_from_slice(&((MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES + 1) as u32).to_be_bytes());
    let out = disp.dispatch_frame_from_peer_for_test(&oversize, Some(NodeId::new([1u8; 32])));
    assert!(!out.is_validated());

    assert!(sender.sent.lock().is_empty());
    assert_eq!(
        metrics.peer_candidate_propagation_suppressed_invalid_total(),
        2
    );
    assert_eq!(metrics.peer_candidate_propagation_sent_total(), 0);
}

#[test]
fn run088_duplicate_candidate_is_suppressed_after_first_rebroadcast() {
    let h = devnet_signing_harness();
    let metrics = Arc::new(P2pMetrics::default());
    let sender = RecordingSender::with_peers(vec![NodeId::new([2u8; 32])]);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Arc::clone(&sender),
        PeerCandidatePropagationConfig {
            enabled: true,
            ..PeerCandidatePropagationConfig::default()
        },
        None,
    );
    let frame = valid_frame(&h, 13);
    assert!(disp
        .dispatch_frame_from_peer_for_test(&frame, Some(NodeId::new([1u8; 32])))
        .is_validated());
    let second = disp.dispatch_frame_from_peer_for_test(&frame, Some(NodeId::new([1u8; 32])));
    assert!(!second.is_validated());
    assert_eq!(sender.sent.lock().len(), 1);
    assert_eq!(
        metrics.peer_candidate_propagation_suppressed_duplicate_total(),
        1
    );
}

#[test]
fn run088_propagation_rate_limit_blocks_rebroadcast_after_validation() {
    let h = devnet_signing_harness();
    let metrics = Arc::new(P2pMetrics::default());
    let sender = RecordingSender::with_peers(vec![NodeId::new([2u8; 32])]);
    let disp = dispatcher(
        &h,
        Arc::clone(&metrics),
        Arc::clone(&sender),
        PeerCandidatePropagationConfig {
            enabled: true,
            max_in_window: 0,
            ..PeerCandidatePropagationConfig::default()
        },
        None,
    );
    let out = disp.dispatch_frame_from_peer_for_test(&valid_frame(&h, 14), None);
    assert!(out.is_validated());
    assert!(sender.sent.lock().is_empty());
    assert_eq!(metrics.peer_candidate_propagation_attempt_total(), 1);
    assert_eq!(metrics.peer_candidate_propagation_rate_limited_total(), 1);
    assert_eq!(metrics.peer_candidate_propagation_sent_total(), 0);
}