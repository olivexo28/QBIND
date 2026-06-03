use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use qbind_node::metrics::P2pMetrics;
use qbind_node::p2p::NodeId;
use qbind_node::pqc_peer_candidate_wire::{
    wire_publish_log_line, LivePeerCandidateWirePublisher, PeerCandidateWireFrameSender,
    PeerCandidateWirePublishConfig, PeerCandidateWirePublishError, RawFramePeerSendOutcome,
    RawFrameSendReport,
};
use qbind_node::pqc_trust_peer_candidate::PeerCandidateEnvelope;
use qbind_types::NetworkEnvironment;

struct FakeSender {
    peers: Vec<NodeId>,
    outcome: RawFramePeerSendOutcome,
    sent: Mutex<Vec<Vec<u8>>>,
}

impl FakeSender {
    fn new(peers: Vec<NodeId>, outcome: RawFramePeerSendOutcome) -> Arc<Self> {
        Arc::new(Self {
            peers,
            outcome,
            sent: Mutex::new(Vec::new()),
        })
    }
}

impl PeerCandidateWireFrameSender for FakeSender {
    fn connected_peer_node_ids(&self) -> Vec<NodeId> {
        self.peers.clone()
    }

    fn send_raw_frame_to_all_peers(&self, frame_bytes: Vec<u8>) -> RawFrameSendReport {
        self.sent.lock().push(frame_bytes);
        RawFrameSendReport::from_per_peer(
            self.peers
                .iter()
                .copied()
                .map(|p| (p, self.outcome))
                .collect(),
        )
    }
}

fn mk_env() -> PeerCandidateEnvelope {
    let bundle_bytes = vec![1, 2, 3, 4, 5];
    PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some("run080-int".into()),
        environment: qbind_node::pqc_trust_bundle::TrustBundleEnvironment::Devnet,
        chain_id_hex: qbind_node::pqc_trust_sequence::chain_id_hex(
            NetworkEnvironment::Devnet.chain_id(),
        ),
        declared_sequence: 19,
        declared_fingerprint_prefix: "deadbeef".into(),
        declared_length: bundle_bytes.len(),
        bundle_bytes,
    }
}

fn write_env(env: &PeerCandidateEnvelope) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "qbind-run080-int-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("candidate.json");
    std::fs::write(&path, serde_json::to_vec(env).unwrap()).unwrap();
    path
}

#[tokio::test]
async fn run080_publish_once_success_reports_sent_and_not_applied_boundary() {
    let sender = FakeSender::new(
        vec![NodeId::new([1u8; 32]), NodeId::new([2u8; 32])],
        RawFramePeerSendOutcome::Enqueued,
    );
    let sender_trait: Arc<dyn PeerCandidateWireFrameSender> = sender.clone();
    let metrics = Arc::new(P2pMetrics::default());
    let pubr = LivePeerCandidateWirePublisher::new(sender_trait, Arc::clone(&metrics));
    let cfg = PeerCandidateWirePublishConfig {
        enabled: true,
        envelope_path: Some(write_env(&mk_env())),
        publish_once: true,
        wait_for_peer_timeout: Duration::from_secs(1),
        wait_poll_interval: Duration::from_millis(10),
        governance_proof_path: None,
    };
    let report = pubr.publish_once_from_config(&cfg).await.unwrap();
    assert_eq!(report.sent(), 2);
    assert_eq!(report.failed(), 0);
    assert_eq!(metrics.peer_candidate_sent_total(), 2);
    assert_eq!(sender.sent.lock().len(), 1);
    let line = wire_publish_log_line(&report, 2);
    assert!(line.contains("validation-only/not-applied"));
}

#[tokio::test]
async fn run080_publish_once_no_peer_fails_closed() {
    let sender = FakeSender::new(vec![], RawFramePeerSendOutcome::Enqueued);
    let sender_trait: Arc<dyn PeerCandidateWireFrameSender> = sender;
    let metrics = Arc::new(P2pMetrics::default());
    let pubr = LivePeerCandidateWirePublisher::new(sender_trait, Arc::clone(&metrics));
    let cfg = PeerCandidateWirePublishConfig {
        enabled: true,
        envelope_path: Some(write_env(&mk_env())),
        publish_once: true,
        wait_for_peer_timeout: Duration::from_millis(20),
        wait_poll_interval: Duration::from_millis(5),
        governance_proof_path: None,
    };
    let err = pubr.publish_once_from_config(&cfg).await.unwrap_err();
    assert!(matches!(
        err,
        PeerCandidateWirePublishError::NoPeerWithinTimeout { .. }
    ));
    assert_eq!(metrics.peer_candidate_send_no_peer_total(), 1);
}

#[tokio::test]
async fn run080_publish_once_queue_full_counts_failures() {
    let sender = FakeSender::new(
        vec![NodeId::new([7u8; 32]), NodeId::new([8u8; 32])],
        RawFramePeerSendOutcome::QueueFull,
    );
    let sender_trait: Arc<dyn PeerCandidateWireFrameSender> = sender;
    let metrics = Arc::new(P2pMetrics::default());
    let pubr = LivePeerCandidateWirePublisher::new(sender_trait, Arc::clone(&metrics));
    let cfg = PeerCandidateWirePublishConfig {
        enabled: true,
        envelope_path: Some(write_env(&mk_env())),
        publish_once: true,
        wait_for_peer_timeout: Duration::from_secs(1),
        wait_poll_interval: Duration::from_millis(10),
        governance_proof_path: None,
    };
    let report = pubr.publish_once_from_config(&cfg).await.unwrap();
    assert_eq!(report.sent(), 0);
    assert_eq!(report.failed(), 2);
    assert_eq!(metrics.peer_candidate_send_failure_total(), 2);
}