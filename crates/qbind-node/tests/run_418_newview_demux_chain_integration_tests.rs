//! Run 418 corrective pass — `NewView` authenticated transport-origin
//! admission exercised through the REAL inbound demux → handler → envelope →
//! consensus-loop → binding-gate chain.
//!
//! Scope / honesty guard: this test drives the production
//! `P2pInboundDemuxer` → `ChannelConsensusHandler` →
//! `InboundConsensusEnvelope` → `BinaryConsensusLoopIo { binding_gate: Some }`
//! → `PeerConsensusBindingGate` chain with the SAME types production P2P
//! traffic traverses after decode. It does **not** open a real socket, run a
//! KEMTLS handshake, or drive `TcpKemTlsP2pService`, so it is NOT and is not
//! described as end-to-end transport evidence. It proves the demux/handler
//! layer faithfully carries (or omits) the authenticated origin into the
//! `NewView` origin-admission gate, and that an unauthenticated
//! (Optional/Disabled) session is rejected fail-closed. The `NewView`
//! admission is transport-origin admission only; F5 (`TimeoutCertificate`
//! signer verification) remains independently unresolved.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use parking_lot::Mutex as PlMutex;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::network::NetworkError;
use qbind_consensus::timeout::TimeoutCertificate;
use qbind_node::binary_consensus_loop::{
    ConsensusVerificationPolicy,
    run_binary_consensus_loop_with_io, BinaryConsensusLoopConfig, BinaryConsensusLoopIo,
    BinaryConsensusLoopProgress,
};
use qbind_node::consensus_network_facade::ConsensusNetworkFacade;
use qbind_node::metrics::NodeMetrics;
use qbind_node::p2p::{ConsensusNetMsg, NodeId, P2pMessage};
use qbind_node::p2p_inbound::{
    ChannelConsensusHandler, ConsensusInboundHandler, InboundP2pEnvelope, NullDagHandler,
    P2pInboundDemuxer,
};
use qbind_node::peer::PeerId;
use qbind_node::peer_consensus_binding::{
    AuthenticatedConsensusOrigin, ConsensusBindingReject, PeerConsensusBindingGate,
    PeerConsensusBindingMap,
};
use qbind_wire::consensus::{BlockProposal, Vote};

fn nid(first: u8, tag: u8) -> NodeId {
    let mut b = [0u8; 32];
    b[0] = first;
    b[31] = tag;
    NodeId::new(b)
}
fn node_a() -> NodeId {
    nid(0xA0, 0x01)
}
fn node_b() -> NodeId {
    nid(0xB0, 0x02)
}

fn two_validator_gate() -> Arc<PeerConsensusBindingGate> {
    let map = PeerConsensusBindingMap::build([
        (node_a(), ValidatorId::new(0)),
        (node_b(), ValidatorId::new(1)),
    ])
    .expect("valid one-to-one map");
    Arc::new(PeerConsensusBindingGate::new(map))
}

fn make_new_view(timeout_view: u64, signers: Vec<ValidatorId>) -> Vec<u8> {
    let tc: TimeoutCertificate<[u8; 32]> = TimeoutCertificate::new(timeout_view, None, signers);
    bincode::serialize(&tc).expect("serialize TC")
}

/// A `ConsensusNetworkFacade` that records every outbound action.
#[derive(Default)]
struct RecordingFacade {
    inner: Mutex<usize>,
}
impl RecordingFacade {
    fn total_actions(&self) -> usize {
        *self.inner.lock().unwrap()
    }
}
impl ConsensusNetworkFacade for RecordingFacade {
    fn send_vote_to(&self, _t: ValidatorId, _v: &Vote) -> Result<(), NetworkError> {
        *self.inner.lock().unwrap() += 1;
        Ok(())
    }
    fn broadcast_vote(&self, _v: &Vote) -> Result<(), NetworkError> {
        *self.inner.lock().unwrap() += 1;
        Ok(())
    }
    fn broadcast_proposal(&self, _p: &BlockProposal) -> Result<(), NetworkError> {
        *self.inner.lock().unwrap() += 1;
        Ok(())
    }
    fn send_timeout_msg(&self, _t: PeerId, _b: Vec<u8>) -> Result<(), NetworkError> {
        *self.inner.lock().unwrap() += 1;
        Ok(())
    }
}

struct DemuxOutcome {
    progress: BinaryConsensusLoopProgress,
    outbound: Arc<RecordingFacade>,
}

/// Drive a single inbound P2P envelope through the REAL demux → handler →
/// envelope → consensus loop → binding gate chain.
async fn drive_through_demux(
    local: ValidatorId,
    n: u64,
    gate: Arc<PeerConsensusBindingGate>,
    origin: Option<AuthenticatedConsensusOrigin>,
    net_msg: ConsensusNetMsg,
) -> DemuxOutcome {
    // Real production consensus handler + the channel the binary loop consumes.
    let (handler, inbound_rx) = ChannelConsensusHandler::new(16);
    let consensus_handler: Arc<dyn ConsensusInboundHandler> = Arc::new(handler);

    // Real production demuxer. We feed it directly via `handle_envelope`, the
    // same method its `run()` loop calls per received transport envelope.
    let (_p2p_tx, p2p_rx) = mpsc::channel::<InboundP2pEnvelope>(16);
    let demuxer = P2pInboundDemuxer::new(p2p_rx, consensus_handler, Arc::new(NullDagHandler), None);

    // Route the transport envelope through the demux → handler. This is exactly
    // what `handle_envelope` does for a decoded `P2pMessage::Consensus` frame:
    // it carries the authenticated origin (or `None`) into the consensus
    // handler, which forwards an `InboundConsensusEnvelope` onto `inbound_rx`.
    demuxer.handle_envelope(InboundP2pEnvelope::new(
        origin,
        P2pMessage::Consensus(net_msg),
    ));
    // Drop the demuxer (and thus the handler/sender) so the loop's inbound
    // channel closes once the queued envelope is drained.
    drop(demuxer);

    let cfg = BinaryConsensusLoopConfig::new(local, n)
        .with_tick_interval(Duration::from_millis(50))
        .with_max_ticks(10);
    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let progress = Arc::new(PlMutex::new(BinaryConsensusLoopProgress::default()));
    let outbound = Arc::new(RecordingFacade::default());
    let outbound_dyn: Arc<dyn ConsensusNetworkFacade> = outbound.clone();

    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound: outbound_dyn,
        peer_connectivity: None,
        verification_ctx: None,
        binding_gate: Some(gate),
        verification_policy: ConsensusVerificationPolicy::LocalFixtureUnsigned,
    };

    let handle = tokio::spawn(async move {
        run_binary_consensus_loop_with_io(cfg, shutdown_rx, progress, metrics, Some(io)).await
    });
    let final_progress = timeout(Duration::from_secs(3), handle)
        .await
        .expect("loop finished within 3s")
        .expect("loop task did not panic");

    DemuxOutcome {
        progress: final_progress,
        outbound,
    }
}

// A missing-origin NewView arriving via the real demux chain (an
// unauthenticated Optional/Disabled session) is rejected fail-closed BEFORE
// the delivered counter and with no engine/view/outbound side effect.
#[tokio::test]
async fn run418_demux_newview_missing_origin_rejected() {
    let gate = two_validator_gate();
    let bytes = make_new_view(0, vec![ValidatorId::new(0), ValidatorId::new(1)]);
    let out = drive_through_demux(
        ValidatorId::new(1),
        2,
        gate.clone(),
        None,
        ConsensusNetMsg::NewView(bytes),
    )
    .await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total,
        1
    );
    assert_eq!(out.progress.inbound.inbound_new_views_delivered, 0);
    assert_eq!(out.progress.inbound.view_timeout_advances, 0);
    assert_eq!(out.progress.current_view, 0);
    assert_eq!(out.outbound.total_actions(), 0);
    assert_eq!(gate.metrics().accepted(), 0);
    assert_eq!(
        gate.metrics()
            .reject_count(ConsensusBindingReject::MissingOrigin),
        1
    );
}

// An authenticated, correctly mapped origin flows through the demux chain,
// passes NewView transport-origin admission, and reaches the delivered counter
// (remaining subject to the existing F5/engine rules).
#[tokio::test]
async fn run418_demux_newview_authenticated_origin_admitted() {
    let gate = two_validator_gate();
    let origin = AuthenticatedConsensusOrigin::new(node_b(), ValidatorId::new(1));
    let bytes = make_new_view(0, vec![ValidatorId::new(0), ValidatorId::new(1)]);
    let out = drive_through_demux(
        ValidatorId::new(0),
        2,
        gate.clone(),
        Some(origin),
        ConsensusNetMsg::NewView(bytes),
    )
    .await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total,
        0
    );
    assert_eq!(out.progress.inbound.inbound_new_views_delivered, 1);
    assert_eq!(gate.metrics().accepted(), 1);
}

// Cross-check that an unauthenticated Proposal is ALSO rejected through the
// same demux chain — so Optional/Disabled unauthenticated ingress rejection is
// demonstrated for BOTH Proposal and NewView, not inferred from one kind.
#[tokio::test]
async fn run418_demux_proposal_missing_origin_rejected() {
    let gate = two_validator_gate();
    // A minimal genesis proposal claiming validator 0.
    let proposal = qbind_wire::consensus::BlockProposal {
        header: qbind_wire::consensus::BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 0,
            round: 0,
            parent_block_id: [0xFF; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    };
    let mut bytes = Vec::new();
    qbind_wire::io::WireEncode::encode(&proposal, &mut bytes);
    let out = drive_through_demux(
        ValidatorId::new(1),
        2,
        gate.clone(),
        None,
        ConsensusNetMsg::Proposal(bytes),
    )
    .await;

    assert_eq!(
        out.progress.inbound.inbound_sender_binding_rejected_total,
        1
    );
    assert_eq!(out.progress.inbound.inbound_proposals_delivered, 0);
    assert_eq!(out.outbound.total_actions(), 0);
    assert_eq!(gate.metrics().accepted(), 0);
    assert_eq!(
        gate.metrics()
            .reject_count(ConsensusBindingReject::MissingOrigin),
        1
    );
}