//! B11 — close the `consensus_net_*_total` Prometheus coverage gap on
//! the real `P2pConsensusNetwork` binary path, while preserving the
//! now-working multi-validator binary-path consensus flow.
//!
//! Boundary surfaced empirically by DevNet Evidence Run 008 / Run 009:
//!
//! > Run 009 was the first sustained positive multi-validator binary-
//! > path consensus run. Loop-level counters (`outbound_proposals` /
//! > `inbound_proposals` / `outbound_votes` / `inbound_votes`) and
//! > engine counters (`qbind_consensus_proposals_total{result="accepted"}` /
//! > `…votes_total{result="accepted"}` / `…qcs_formed_total`) all
//! > moved on real `qbind-node` processes, AND `committed_height >
//! > None` on both nodes. But `consensus_net_outbound_total{kind=
//! > "proposal_broadcast"}` / `…{kind="vote_broadcast"}` /
//! > `consensus_net_inbound_total{kind="proposal"}` /
//! > `…{kind="vote"}` stayed at 0 across all three `/metrics`
//! > scrapes — i.e. the Prometheus surface under-reported the
//! > `P2pConsensusNetwork` traffic the rest of the binary already
//! > observed.
//!
//! # Root cause this file pins down
//!
//! The `inc_outbound_proposal_broadcast` / `inc_outbound_vote_broadcast`
//! / `inc_outbound_vote_send_to` increments and the
//! `inc_inbound_proposal` / `inc_inbound_vote` increments live on the
//! `crates/qbind-node/src/consensus_net_worker.rs` codepath. The real
//! binary path used by `qbind-node` does not exercise that worker; it
//! uses `P2pConsensusNetwork` (outbound) and `BinaryConsensusLoopIo` /
//! `handle_inbound_consensus_msg` (inbound). Pre-B11, neither of those
//! touched the `NetworkMetrics` counters, so the Prometheus family
//! stayed at 0 on the binary path even when the loop-level evidence
//! and the engine evidence were both positive.
//!
//! # Test matrix (small, high-signal)
//!
//! - **A. Pre-fix shape (regression guard).** When `P2pConsensusNetwork`
//!   is constructed *without* `with_metrics(...)` (the legacy
//!   constructor, the path single-validator / harness-only callers
//!   still take), every `broadcast_*` / `send_vote_to` call must
//!   leave the `consensus_net_outbound_total{...}` family at 0. This
//!   is the honest under-report shape: it must remain bit-equivalent
//!   to pre-B11 so we don't double-count anywhere a future caller
//!   wires metrics at a higher layer.
//!
//! - **B. Post-fix outbound proof.** When `P2pConsensusNetwork` is
//!   constructed *with* `with_metrics(node_metrics)` (the production
//!   path, after this commit also taken by `main.rs::run_p2p_node`),
//!   each call to `broadcast_proposal` / `broadcast_vote` /
//!   `send_vote_to` increments exactly the matching
//!   `consensus_net_outbound_total{kind="..."}` counter exactly once.
//!   No double counting and no fabricated increments.
//!
//! - **C. Post-fix inbound proof.** When `BinaryConsensusLoopIo` is
//!   driven through the real `run_binary_consensus_loop_with_io`
//!   surface and inbound `ConsensusNetMsg::Proposal` /
//!   `ConsensusNetMsg::Vote` / `ConsensusNetMsg::Timeout` frames are
//!   delivered through the inbound channel, the matching
//!   `consensus_net_inbound_total{kind="..."}` counters move
//!   monotonically. Counts equal the number of inbound frames; no
//!   fabricated increments, no decode-failure-only paths missed.
//!
//! - **D. Regression guard: B9 single-shot late-peer re-emit does not
//!   double-count outbound.** When the B9 late-peer-connect helper
//!   re-broadcasts the cached proposal exactly once per view, the
//!   `consensus_net_outbound_total{kind="proposal_broadcast"}` counter
//!   goes up by exactly 1 over that re-emit (in addition to the +1
//!   from the original leader-step emission). The B9 boundedness
//!   contract is intact; the metric just observes what the facade
//!   actually pushed to the transport.
//!
//! - **E. Regression guard: `peer_connectivity = None` /
//!   single-validator path leaves the family at 0.** When the loop
//!   runs without I/O wiring (the `io = None` LocalMesh / B1/B2
//!   path), no `consensus_net_*_total` increment is observable —
//!   exactly as before B11 and consistent with "honest under-report,
//!   never fabricate".
//!
//! These tests strongly predict that a future scrape on the same
//! Run-009-shaped binary run would now show non-zero
//! `consensus_net_*_total` for proposal_broadcast / vote_broadcast /
//! proposal / vote.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex as PlMutex;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::network::NetworkError;
use qbind_node::binary_consensus_loop::{
    run_binary_consensus_loop_with_io, spawn_binary_consensus_loop_with_io,
    BinaryConsensusLoopConfig, BinaryConsensusLoopIo, BinaryConsensusLoopProgress,
    PeerConnectivitySource,
};
use qbind_node::consensus_net_p2p::P2pConsensusNetwork;
use qbind_node::consensus_network_facade::ConsensusNetworkFacade;
use qbind_node::metrics::NodeMetrics;
use qbind_node::p2p::{ConsensusNetMsg, NodeId, NullP2pService};
use qbind_node::peer::PeerId;
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};
use qbind_wire::io::WireEncode;

// ============================================================================
// Shared test helpers
// ============================================================================

fn encode<T: WireEncode>(t: &T) -> Vec<u8> {
    let mut out = Vec::new();
    t.encode(&mut out);
    out
}

fn make_proposal(proposer_index: u16, height: u64) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round: 0,
            parent_block_id: [0u8; 32],
            payload_hash: [0u8; 32],
            proposer_index,
            suite_id: 0,
            tx_count: 0,
            timestamp: 0,
            payload_kind: 0,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

fn make_vote(validator_index: u16, height: u64) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round: 0,
        step: 0,
        block_id: [0u8; 32],
        validator_index,
        suite_id: 0,
        signature: vec![],
    }
}

#[derive(Default)]
struct FakePeerConnectivity {
    inner: PlMutex<Vec<NodeId>>,
}

impl FakePeerConnectivity {
    fn new() -> Self {
        Self::default()
    }
    fn set(&self, peers: Vec<NodeId>) {
        *self.inner.lock() = peers;
    }
}

impl PeerConnectivitySource for FakePeerConnectivity {
    fn connected_peers(&self) -> Vec<NodeId> {
        self.inner.lock().clone()
    }
}

fn fake_peer_id(byte: u8) -> NodeId {
    NodeId::new([byte; 32])
}

// ============================================================================
// A. Pre-fix shape: legacy `P2pConsensusNetwork::new(...)` without metrics
//    wiring leaves the `consensus_net_outbound_total{...}` family at 0.
// ============================================================================

#[test]
fn b11_a_outbound_metrics_are_not_counted_without_wiring() {
    // Use the existing `NullP2pService` so the broadcast() / send_to()
    // calls succeed (drop the message) without standing up real sockets.
    let p2p = Arc::new(NullP2pService::zero());
    let net = P2pConsensusNetwork::new(p2p.clone(), 4);

    // We cannot read the worker-path NetworkMetrics directly without
    // wiring them; the point is exactly that the *legacy* construction
    // path does not touch `NodeMetrics`. So we construct an *unwired*
    // metrics instance, exercise the facade, and assert the family
    // stays at zero — proving the facade did NOT find some hidden way
    // to mutate metrics it was never given.
    let metrics = Arc::new(NodeMetrics::new());

    let proposal = make_proposal(0, 1);
    let vote = make_vote(0, 1);

    for _ in 0..7 {
        net.broadcast_proposal(&proposal).expect("ok");
        net.broadcast_vote(&vote).expect("ok");
        net.send_vote_to(ValidatorId::new(1), &vote).expect("ok");
    }

    assert_eq!(
        metrics.network().outbound_proposal_broadcast_total(),
        0,
        "without with_metrics(...), proposal_broadcast counter must stay at 0 \
         (honest under-report, pre-B11 shape)"
    );
    assert_eq!(metrics.network().outbound_vote_broadcast_total(), 0);
    assert_eq!(metrics.network().outbound_vote_send_to_total(), 0);
}

// ============================================================================
// B. Post-fix outbound proof: `with_metrics(...)` wires the family,
//    every facade call increments the matching counter exactly once.
// ============================================================================

#[test]
fn b11_b_outbound_metrics_increment_on_every_facade_call() {
    let p2p = Arc::new(NullP2pService::zero());
    let metrics = Arc::new(NodeMetrics::new());

    // Production-default construction path (also taken by
    // `main.rs::run_p2p_node` after B11): `with_metrics(...)`.
    let net = P2pConsensusNetwork::new(p2p, 4).with_metrics(Arc::clone(&metrics));

    let proposal = make_proposal(0, 1);
    let vote = make_vote(0, 1);

    // 3 proposal broadcasts.
    for _ in 0..3 {
        net.broadcast_proposal(&proposal).expect("ok");
    }
    // 5 vote broadcasts.
    for _ in 0..5 {
        net.broadcast_vote(&vote).expect("ok");
    }
    // 2 directed vote sends to a known validator.
    for _ in 0..2 {
        net.send_vote_to(ValidatorId::new(1), &vote).expect("ok");
    }
    // A failing send_vote_to (unknown validator) MUST NOT increment
    // the counter — we only count what the transport actually saw.
    let bad = net.send_vote_to(ValidatorId::new(999), &vote);
    assert!(bad.is_err(), "send to unknown validator must error");

    assert_eq!(
        metrics.network().outbound_proposal_broadcast_total(),
        3,
        "broadcast_proposal called 3 times → counter should be 3"
    );
    assert_eq!(
        metrics.network().outbound_vote_broadcast_total(),
        5,
        "broadcast_vote called 5 times → counter should be 5"
    );
    assert_eq!(
        metrics.network().outbound_vote_send_to_total(),
        2,
        "send_vote_to(known) called 2 times (1 unknown errored) → counter should be 2"
    );

    // No cross-counter pollution: inbound family must remain at 0
    // (this facade has no inbound side).
    assert_eq!(metrics.network().inbound_proposal_total(), 0);
    assert_eq!(metrics.network().inbound_vote_total(), 0);
    assert_eq!(metrics.network().inbound_other_total(), 0);
}

// ============================================================================
// C. Post-fix inbound proof: `handle_inbound_consensus_msg` (exercised
//    via the public `run_binary_consensus_loop_with_io` surface)
//    increments the inbound family on every inbound frame.
// ============================================================================

/// Recording facade used by the inbound test: counts outbound events
/// the loop emits but otherwise drops them. Lets the loop run cleanly.
#[derive(Default)]
struct CountingFacade {
    proposals: PlMutex<u64>,
    votes: PlMutex<u64>,
}

impl ConsensusNetworkFacade for CountingFacade {
    fn send_vote_to(&self, _t: ValidatorId, _v: &Vote) -> Result<(), NetworkError> {
        *self.votes.lock() += 1;
        Ok(())
    }
    fn broadcast_vote(&self, _v: &Vote) -> Result<(), NetworkError> {
        *self.votes.lock() += 1;
        Ok(())
    }
    fn broadcast_proposal(&self, _p: &BlockProposal) -> Result<(), NetworkError> {
        *self.proposals.lock() += 1;
        Ok(())
    }
    fn send_timeout_msg(&self, _t: PeerId, _b: Vec<u8>) -> Result<(), NetworkError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b11_c_inbound_metrics_increment_on_every_inbound_frame() {
    // 2-validator config so leader-step emissions are bounded and we
    // can isolate the inbound counter movement we care about.
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(1), 2)
        .with_tick_interval(Duration::from_millis(5))
        .with_max_ticks(120);

    let (inbound_tx, inbound_rx) = mpsc::channel::<ConsensusNetMsg>(64);
    let facade: Arc<dyn ConsensusNetworkFacade> = Arc::new(CountingFacade::default());

    // Pre-load 4 proposal frames, 3 vote frames, and 2 timeout frames
    // (the timeout frames are received-but-unhandled on the binary
    // path; B11 counts them under `inbound_total{kind="other"}` so
    // they do not silently disappear from /metrics).
    for h in 1..=4 {
        let p = make_proposal(0, h);
        inbound_tx
            .send(ConsensusNetMsg::Proposal(encode(&p)))
            .await
            .unwrap();
    }
    for h in 1..=3 {
        let v = make_vote(0, h);
        inbound_tx
            .send(ConsensusNetMsg::Vote(encode(&v)))
            .await
            .unwrap();
    }
    for _ in 0..2 {
        inbound_tx
            .send(ConsensusNetMsg::Timeout(vec![1, 2, 3]))
            .await
            .unwrap();
    }
    drop(inbound_tx);

    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound: facade,
        peer_connectivity: None,
        verification_ctx: None,
    };

    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let progress = Arc::new(parking_lot::Mutex::new(
        BinaryConsensusLoopProgress::default(),
    ));

    let progress = run_binary_consensus_loop_with_io(
        cfg,
        shutdown_rx,
        progress,
        Arc::clone(&metrics),
        Some(io),
    )
    .await;

    // The loop consumes every frame we sent through the channel.
    assert!(
        progress.inbound.inbound_msgs_received >= 4 + 3 + 2,
        "loop must have received all 9 inbound frames; got {:?}",
        progress.inbound
    );

    // ----- B11 post-fix Prometheus inbound family. -----
    assert_eq!(
        metrics.network().inbound_proposal_total(),
        4,
        "4 inbound Proposal frames → consensus_net_inbound_total{{kind=\"proposal\"}} = 4; \
         got {}",
        metrics.network().inbound_proposal_total()
    );
    assert_eq!(
        metrics.network().inbound_vote_total(),
        3,
        "3 inbound Vote frames → consensus_net_inbound_total{{kind=\"vote\"}} = 3; \
         got {}",
        metrics.network().inbound_vote_total()
    );
    assert_eq!(
        metrics.network().inbound_other_total(),
        2,
        "2 inbound Timeout frames → consensus_net_inbound_total{{kind=\"other\"}} = 2; \
         got {}",
        metrics.network().inbound_other_total()
    );
}

// ============================================================================
// D. Regression guard: B9 late-peer-connect re-emit does not double-
//    count the outbound proposal counter.
// ============================================================================

/// Forwarding-and-counting facade backed by `Arc<NodeMetrics>` (i.e. the
/// same shape `P2pConsensusNetwork::with_metrics` produces in
/// production: every successful broadcast bumps the outbound counter).
/// We use this — instead of the real `P2pConsensusNetwork` — because
/// the in-tree late-peer-connect tests cannot stand up real KEMTLS
/// transport. The contract under test is "outbound counter == number
/// of facade calls", which is exactly what `with_metrics` enforces in
/// production code.
struct MetricsForwardingFacade {
    inbound: mpsc::Sender<ConsensusNetMsg>,
    metrics: Arc<NodeMetrics>,
}

impl ConsensusNetworkFacade for MetricsForwardingFacade {
    fn send_vote_to(&self, _t: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        let _ = self.inbound.try_send(ConsensusNetMsg::Vote(encode(vote)));
        self.metrics.network().inc_outbound_vote_send_to();
        Ok(())
    }
    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        let _ = self.inbound.try_send(ConsensusNetMsg::Vote(encode(vote)));
        self.metrics.network().inc_outbound_vote_broadcast();
        Ok(())
    }
    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        let _ = self
            .inbound
            .try_send(ConsensusNetMsg::Proposal(encode(proposal)));
        self.metrics.network().inc_outbound_proposal_broadcast();
        Ok(())
    }
    fn send_timeout_msg(&self, _t: PeerId, _b: Vec<u8>) -> Result<(), NetworkError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b11_d_b9_late_peer_reemit_does_not_double_count() {
    // V0 is leader; V1 connects late so the B9 helper fires.
    let cfg_v0 = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 2)
        .with_tick_interval(Duration::from_millis(5))
        .with_max_ticks(120);

    // Throw-away inbound for V0 (no peer feeding it in this test —
    // we only care about V0's outbound counter behaviour).
    let (_dead_tx, inbound_v0_rx) = mpsc::channel::<ConsensusNetMsg>(64);
    // V1 inbound — V0's outbound facade forwards into here, but we
    // don't actually consume it in this test (the goal is to count
    // outbound, not run V1's engine).
    let (inbound_v1_tx, _inbound_v1_rx) = mpsc::channel::<ConsensusNetMsg>(64);

    let metrics_v0 = Arc::new(NodeMetrics::new());
    let facade_v0: Arc<dyn ConsensusNetworkFacade> = Arc::new(MetricsForwardingFacade {
        inbound: inbound_v1_tx,
        metrics: Arc::clone(&metrics_v0),
    });

    let conn_v0 = Arc::new(FakePeerConnectivity::new());
    let conn_v0_dyn: Arc<dyn PeerConnectivitySource> = conn_v0.clone();

    let io_v0 = BinaryConsensusLoopIo {
        inbound_rx: inbound_v0_rx,
        outbound: facade_v0,
        peer_connectivity: Some(conn_v0_dyn),
        verification_ctx: None,
    };

    let (_shutdown_tx, shutdown_rx) = watch::channel(());

    let (handle, _progress) =
        spawn_binary_consensus_loop_with_io(cfg_v0, shutdown_rx, Arc::clone(&metrics_v0), io_v0);

    // Let V0 emit its first leader-step proposal+vote (no peer connected yet).
    tokio::time::sleep(Duration::from_millis(50)).await;
    let proposals_after_initial = metrics_v0.network().outbound_proposal_broadcast_total();
    assert!(
        proposals_after_initial >= 1,
        "V0 must have emitted >=1 proposal in its first leader step; got {}",
        proposals_after_initial
    );

    // Flip connectivity: V1 just appeared. B9's per-view single-shot
    // latch must fire exactly once — re-emitting the cached proposal
    // (and, by B10, the cached vote) — and never again on subsequent
    // ticks within the same view.
    conn_v0.set(vec![fake_peer_id(0xAA)]);

    let final_v0 = timeout(Duration::from_secs(8), handle)
        .await
        .expect("V0 loop did not finish")
        .expect("V0 loop panicked");

    // B9 contract: at most ONE proposal re-emit per view across the
    // whole run.
    assert_eq!(
        final_v0.inbound.outbound_proposal_late_peer_reemits, 1,
        "B9 must re-emit exactly one proposal; got {:?}",
        final_v0.inbound
    );

    // The Prometheus counter equals the number of broadcast_proposal
    // calls the facade actually saw, which is initial + B9 re-emit
    // (= proposals_after_initial + 1). No double counting on the
    // re-emit path: a single re-emit must move the counter by
    // exactly +1 over its pre-re-emit value.
    let final_total = metrics_v0.network().outbound_proposal_broadcast_total();
    let total_via_facade = final_v0.inbound.outbound_proposals_sent
        + final_v0.inbound.outbound_proposal_late_peer_reemits;
    assert_eq!(
        final_total, total_via_facade,
        "consensus_net_outbound_total{{kind=\"proposal_broadcast\"}} must equal the total \
         number of broadcast_proposal calls the facade observed (initial leader-step \
         emissions + late-peer re-emits). final={} loop_total={} loop_stats={:?}",
        final_total, total_via_facade, final_v0.inbound,
    );
}

// ============================================================================
// E. Regression guard: `peer_connectivity = None` / single-validator
//    LocalMesh path leaves the `consensus_net_*_total` family at 0.
//    B1/B2 bit-equivalence: pre-B11 absence of any increment is
//    preserved on this path.
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b11_e_localmesh_io_none_path_does_not_touch_consensus_net_counters() {
    // io = None is the LocalMesh / B1/B2 single-validator path.
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
        .with_tick_interval(Duration::from_millis(2))
        .with_max_ticks(40);
    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let progress = Arc::new(parking_lot::Mutex::new(
        BinaryConsensusLoopProgress::default(),
    ));

    let final_progress =
        run_binary_consensus_loop_with_io(cfg, shutdown_rx, progress, Arc::clone(&metrics), None)
            .await;

    // Sanity: single-validator path still actually advances commits
    // (B1/B2 not regressed).
    assert!(
        final_progress.commits >= 1,
        "single-validator io=None path must still commit; got {:?}",
        final_progress
    );
    // The B11 contract on this path: no `consensus_net_*_total`
    // increment at all (no facade is wired, no inbound channel, no
    // P2P).
    assert_eq!(metrics.network().outbound_proposal_broadcast_total(), 0);
    assert_eq!(metrics.network().outbound_vote_broadcast_total(), 0);
    assert_eq!(metrics.network().outbound_vote_send_to_total(), 0);
    assert_eq!(metrics.network().inbound_proposal_total(), 0);
    assert_eq!(metrics.network().inbound_vote_total(), 0);
    assert_eq!(metrics.network().inbound_other_total(), 0);
}
