//! B10 — engine-side acceptance / QC-formation closure on the
//! multi-validator binary path under the post-B9 re-emitted leader
//! proposal.
//!
//! These tests close the boundary surfaced by DevNet Evidence Run 008:
//!
//! > Run 008 reached the binary-path "proposal crosses, vote crosses
//! > back" shape end-to-end on real `qbind-node` processes, but
//! > engine-side acceptance counters stayed at 0, `qcs_formed_total`
//! > stayed at 0, and `committed_height` stayed `None`. The remaining
//! > boundary sat above the network/transport/identity stack and below
//! > final consensus progression.
//!
//! Run 008 evidence (canonical, in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_008.md`):
//!
//! - V0 (leader): `outbound_proposals=1 outbound_votes=1
//!   outbound_proposal_late_peer_reemits=1 inbound_votes=1 view=1`
//! - V1 (peer):   `outbound_proposals=0 outbound_votes=1
//!   outbound_proposal_late_peer_reemits=0 inbound_proposals=1
//!   inbound_votes=0 view=0`
//!
//! The reproduction below does not depend on any harness-only glue: it
//! exercises the real `run_binary_consensus_loop_with_io` surface with
//! the production `B9` `PeerConnectivitySource` path, plus a tiny
//! "selective drop" facade that models the Run-008 timing — V1 has not
//! yet completed its inbound dial when V0 emits its first
//! leader-step actions, so V0's view-0 `BroadcastVote` is dropped
//! before being delivered to V1.
//!
//! # Root cause this file pins down
//!
//! Pre-B10, the binary loop's late-peer-connect re-emit (B9) replays
//! only the leader's cached `BroadcastProposal`, never the leader's
//! same-view `BroadcastVote`. With 2 validators and a 2/3 threshold,
//! the late-connecting peer (V1) needs **both** votes for view 0 to
//! reach quorum: its own self-vote (produced when it accepts the
//! re-emitted proposal) and the leader's view-0 vote. The leader vote
//! emitted at first leader-step is gone (V1 wasn't connected yet) and
//! is never replayed, so V1 stays at view 0 forever even though the
//! leader's engine forms a QC, advances to view 1, and then stalls
//! waiting on V1 (which is leader of view 1 in the round-robin
//! 2-validator setup).
//!
//! # Test matrix
//!
//! - **A. Pre-fix Run-008 shape (regression guard).** With the B10 vote
//!   re-emit *disabled* (we model this by using a facade that drops
//!   the leader's first-tick vote outbound but lets every other
//!   message through, equivalent to V1 not yet being connected when
//!   V0 first emits), the proposal still crosses (via B9 re-emit),
//!   V1 still emits its vote and V0 ingests it, but V1 stays at view
//!   0 and `committed_height` is `None` everywhere. This test
//!   reproduces the exact Run-008 shape in-tree.
//!
//! - **B. Post-fix engine-acceptance / QC closure.** With the same
//!   selective-drop topology but the **B10 leader-vote re-emit
//!   enabled** (this is the production-default path now), V1 receives
//!   the leader's view-0 vote on the same tick the proposal is
//!   re-emitted, V1's engine reaches 2/3 for view 0, V1 forms its
//!   own QC, V1 advances past view 0, and both nodes' engine-acceptance
//!   counters move on `/metrics`.
//!
//! - **C. Regression: B6 cross-wired path still passes.** Same in
//!   spirit as `b6_two_engine_cross_wired_binary_path_progression`,
//!   re-asserted here because the B10 changes touched both
//!   `do_leader_tick` and `maybe_reemit_on_late_peer_connect`.
//!
//! - **D. Regression: B9 latch still bounded.** Even after the B10
//!   addition, the late-peer-connect re-emit still fires at most once
//!   per view across the proposal+vote pair — never twice on
//!   reconnect churn.
//!
//! - **E. Regression: `io=None` single-validator path still commits.**
//!   The B10 changes must not regress B1/B2/B3/B5 (the LocalMesh /
//!   single-validator path). With `io=None`, the loop continues to
//!   commit per tick exactly as before.

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
use qbind_node::consensus_network_facade::ConsensusNetworkFacade;
use qbind_node::metrics::NodeMetrics;
use qbind_node::p2p::{ConsensusNetMsg, NodeId};
use qbind_node::peer::PeerId;
use qbind_wire::consensus::{BlockProposal, Vote};
use qbind_wire::io::WireEncode;

// ============================================================================
// Test helpers
// ============================================================================

fn encode<T: WireEncode>(t: &T) -> Vec<u8> {
    let mut out = Vec::new();
    t.encode(&mut out);
    out
}

fn fake_peer_id(byte: u8) -> NodeId {
    NodeId::new([byte; 32])
}

/// `PeerConnectivitySource` whose connected set can be flipped from the
/// test thread. Identical in shape to the helper used in the B9 test
/// suite; duplicated here intentionally so this file stands on its own
/// and the regression guards remain readable.
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

/// Statistics recorded by `LateConnectFacade` for assertions. The
/// `_dropped_*` counters capture how many outbound actions the facade
/// dropped because the simulated peer wasn't "connected" yet — i.e.
/// the exact failure mode Run 008 surfaced on the real wire when V1
/// hadn't completed its inbound dial in time for V0's first leader
/// step.
#[derive(Default, Clone, Copy, Debug)]
struct LateConnectFacadeStats {
    proposals_attempted: u64,
    votes_attempted: u64,
    proposals_forwarded: u64,
    votes_forwarded: u64,
    proposals_dropped: u64,
    votes_dropped: u64,
}

/// A `ConsensusNetworkFacade` that simulates "peer not yet connected".
///
/// While `connected.load() == false`, every outbound action is counted
/// but **dropped** — exactly modelling the real-wire behaviour of
/// `P2pConsensusNetwork::broadcast_*` against a `P2pService` whose
/// connected-peer set is empty (the production path returns `Ok(())`
/// in that case but no peer ever sees the bytes). Once `connected`
/// flips to `true`, every subsequent outbound action is forwarded
/// into `peer_inbound`. This lets the test isolate the exact
/// timing-of-late-connect window that Run 008 hit, without standing
/// up real KEMTLS / network sockets.
struct LateConnectFacade {
    peer_inbound: mpsc::Sender<ConsensusNetMsg>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    stats: Arc<PlMutex<LateConnectFacadeStats>>,
}

impl LateConnectFacade {
    fn new(
        peer_inbound: mpsc::Sender<ConsensusNetMsg>,
        connected: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            peer_inbound,
            connected,
            stats: Arc::new(PlMutex::new(LateConnectFacadeStats::default())),
        }
    }

    #[allow(dead_code)]
    fn snapshot(&self) -> LateConnectFacadeStats {
        *self.stats.lock()
    }
}

impl ConsensusNetworkFacade for LateConnectFacade {
    fn send_vote_to(&self, _target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        // Direct send: route through the same connected gate so the
        // Run-008 shape applies to both broadcast and direct sends.
        let mut s = self.stats.lock();
        s.votes_attempted = s.votes_attempted.saturating_add(1);
        if self.connected.load(std::sync::atomic::Ordering::Relaxed) {
            let msg = ConsensusNetMsg::Vote(encode(vote));
            let _ = self.peer_inbound.try_send(msg);
            s.votes_forwarded = s.votes_forwarded.saturating_add(1);
        } else {
            s.votes_dropped = s.votes_dropped.saturating_add(1);
        }
        Ok(())
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        let mut s = self.stats.lock();
        s.votes_attempted = s.votes_attempted.saturating_add(1);
        if self.connected.load(std::sync::atomic::Ordering::Relaxed) {
            let msg = ConsensusNetMsg::Vote(encode(vote));
            let _ = self.peer_inbound.try_send(msg);
            s.votes_forwarded = s.votes_forwarded.saturating_add(1);
        } else {
            s.votes_dropped = s.votes_dropped.saturating_add(1);
        }
        Ok(())
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        let mut s = self.stats.lock();
        s.proposals_attempted = s.proposals_attempted.saturating_add(1);
        if self.connected.load(std::sync::atomic::Ordering::Relaxed) {
            let msg = ConsensusNetMsg::Proposal(encode(proposal));
            let _ = self.peer_inbound.try_send(msg);
            s.proposals_forwarded = s.proposals_forwarded.saturating_add(1);
        } else {
            s.proposals_dropped = s.proposals_dropped.saturating_add(1);
        }
        Ok(())
    }

    fn send_timeout_msg(&self, _target: PeerId, _msg_bytes: Vec<u8>) -> Result<(), NetworkError> {
        Ok(())
    }
}

/// A "always forward" facade for the peer side. Used so the peer's
/// outbound vote always reaches the leader; only the leader's
/// outbound is gated by `LateConnectFacade`.
struct AlwaysForwardFacade {
    peer_inbound: mpsc::Sender<ConsensusNetMsg>,
    votes_forwarded: Arc<PlMutex<u64>>,
}

impl AlwaysForwardFacade {
    fn new(peer_inbound: mpsc::Sender<ConsensusNetMsg>) -> Self {
        Self {
            peer_inbound,
            votes_forwarded: Arc::new(PlMutex::new(0)),
        }
    }
}

impl ConsensusNetworkFacade for AlwaysForwardFacade {
    fn send_vote_to(&self, _target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        *self.votes_forwarded.lock() += 1;
        let msg = ConsensusNetMsg::Vote(encode(vote));
        let _ = self.peer_inbound.try_send(msg);
        Ok(())
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        *self.votes_forwarded.lock() += 1;
        let msg = ConsensusNetMsg::Vote(encode(vote));
        let _ = self.peer_inbound.try_send(msg);
        Ok(())
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        let msg = ConsensusNetMsg::Proposal(encode(proposal));
        let _ = self.peer_inbound.try_send(msg);
        Ok(())
    }

    fn send_timeout_msg(&self, _target: PeerId, _msg_bytes: Vec<u8>) -> Result<(), NetworkError> {
        Ok(())
    }
}

// ============================================================================
// A. Pre-fix Run-008 shape: leader vote dropped, peer stuck at view 0
// ============================================================================

/// **B10 / pre-fix reproduction.**
///
/// This test reproduces the exact Run-008 partial-positive boundary
/// shape on the real binary-path surface, **without** the B10 leader
/// vote re-emit. We disable the B10 fix at the topology level (not in
/// production code): the leader's facade is a `LateConnectFacade`
/// initialised with `connected=false`, so V0's first leader-step
/// `BroadcastProposal` and `BroadcastVote` are both dropped on the
/// way to V1. We then flip `connected=true` to model V1 finishing its
/// inbound dial, **and we only re-enable forwarding for the proposal**
/// by the time the B9 late-peer-connect path fires. The B9 mechanism
/// re-broadcasts the cached proposal; the cached vote on the leader
/// side is still re-emitted (B10 is on by default in production), but
/// in this test we deliberately use a facade variant that drops
/// votes only — to prove the **boundary that would exist if B10
/// were absent** is correctly captured by this test surface.
///
/// In other words: we use a facade that always drops votes (even
/// after `connected=true`) but always forwards proposals. This
/// isolates the "missing leader vote on the late-connecting peer
/// side" failure mode that Run 008 hit, independent of the B10 fix
/// landed in production code.
///
/// Expected pre-fix shape:
///
/// 1. V0 emits 1 proposal (initial) + 1 vote (initial). Both go into
///    the gate — proposal counted as attempted, dropped or forwarded
///    depending on connectivity.
/// 2. After V1 connects, B9 re-emits the proposal. The proposal
///    actually reaches V1.
/// 3. V1 receives proposal, accepts it (engine `on_proposal_event`
///    returns a vote action), and broadcasts its vote back through
///    its own facade (which always forwards).
/// 4. V0 ingests V1's vote (via `on_vote_event`) — V0 now has [V0,
///    V1] votes for view 0 and forms its own QC, advances to view 1.
/// 5. V1 still has only its own vote for view 0 — it cannot form a
///    QC, cannot advance. V1's `current_view == 0`. No commit.
///
/// This is exactly Run 008's qualitative shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b10_a_pre_fix_run_008_shape_reproduces_in_tree() {
    /// A facade that gates proposals and votes on independent connect
    /// flags. Initially both `false` to mirror the Run-008 timing
    /// (V1 not yet connected when V0 emits its first leader-step
    /// actions, so both proposal and vote are dropped). The test
    /// then flips `proposals_connected = true` to model V1's
    /// inbound dial completing — but leaves `votes_connected =
    /// false` to model "B10 leader-vote re-emit absent from V1's
    /// perspective". B9's proposal re-emit then succeeds (V1
    /// receives the proposal), but V1 still never sees the
    /// leader's view-0 vote.
    struct SelectiveConnectFacade {
        peer_inbound: mpsc::Sender<ConsensusNetMsg>,
        proposals_connected: Arc<std::sync::atomic::AtomicBool>,
        votes_connected: Arc<std::sync::atomic::AtomicBool>,
    }
    impl ConsensusNetworkFacade for SelectiveConnectFacade {
        fn send_vote_to(&self, _t: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
            if self.votes_connected.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = self
                    .peer_inbound
                    .try_send(ConsensusNetMsg::Vote(encode(vote)));
            }
            Ok(())
        }
        fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
            if self.votes_connected.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = self
                    .peer_inbound
                    .try_send(ConsensusNetMsg::Vote(encode(vote)));
            }
            Ok(())
        }
        fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
            if self.proposals_connected.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = self
                    .peer_inbound
                    .try_send(ConsensusNetMsg::Proposal(encode(proposal)));
            }
            Ok(())
        }
        fn send_timeout_msg(
            &self,
            _t: PeerId,
            _b: Vec<u8>,
        ) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    // V0 (leader) and V1 (peer). num_validators=2, so leader of view 0
    // is V0 and leader of view 1 is V1.
    let cfg_v0 = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 2)
        .with_tick_interval(Duration::from_millis(5))
        .with_max_ticks(160);
    let cfg_v1 = BinaryConsensusLoopConfig::new(ValidatorId::new(1), 2)
        .with_tick_interval(Duration::from_millis(5))
        .with_max_ticks(160);

    let (inbound_v0_tx, inbound_v0_rx) = mpsc::channel::<ConsensusNetMsg>(64);
    let (inbound_v1_tx, inbound_v1_rx) = mpsc::channel::<ConsensusNetMsg>(64);

    let proposals_connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let votes_connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let facade_v0: Arc<dyn ConsensusNetworkFacade> = Arc::new(SelectiveConnectFacade {
        peer_inbound: inbound_v1_tx,
        proposals_connected: Arc::clone(&proposals_connected),
        votes_connected: Arc::clone(&votes_connected),
    });
    let facade_v1: Arc<dyn ConsensusNetworkFacade> =
        Arc::new(AlwaysForwardFacade::new(inbound_v0_tx));

    let conn_v0 = Arc::new(FakePeerConnectivity::new());
    let conn_v0_dyn: Arc<dyn PeerConnectivitySource> = conn_v0.clone();
    let conn_v1 = Arc::new(FakePeerConnectivity::new());
    let conn_v1_dyn: Arc<dyn PeerConnectivitySource> = conn_v1.clone();

    let io_v0 = BinaryConsensusLoopIo {
        inbound_rx: inbound_v0_rx,
        outbound: facade_v0,
        peer_connectivity: Some(conn_v0_dyn),
        verification_ctx: None,
    };
    let io_v1 = BinaryConsensusLoopIo {
        inbound_rx: inbound_v1_rx,
        outbound: facade_v1,
        peer_connectivity: Some(conn_v1_dyn),
        verification_ctx: None,
    };

    let (_shutdown_tx_v0, shutdown_rx_v0) = watch::channel(());
    let (_shutdown_tx_v1, shutdown_rx_v1) = watch::channel(());

    let metrics_v0 = Arc::new(NodeMetrics::new());
    let metrics_v1 = Arc::new(NodeMetrics::new());

    let (handle_v0, _progress_v0) = spawn_binary_consensus_loop_with_io(
        cfg_v0,
        shutdown_rx_v0,
        Arc::clone(&metrics_v0),
        io_v0,
    );
    let (handle_v1, _progress_v1) = spawn_binary_consensus_loop_with_io(
        cfg_v1,
        shutdown_rx_v1,
        Arc::clone(&metrics_v1),
        io_v1,
    );

    // Let V0 emit its first leader-step proposal+vote. Both are
    // dropped (Run-008 timing).
    tokio::time::sleep(Duration::from_millis(40)).await;

    // Now flip proposals to "connected" (V1's inbound is up) and
    // tell V0's connectivity source about V1. B9 will fire on V0's
    // next tick and re-broadcast the cached proposal. The B10 vote
    // re-emit will also fire, but votes_connected stays false —
    // exactly modelling "B10 absent" from V1's perspective.
    proposals_connected.store(true, std::sync::atomic::Ordering::Relaxed);
    conn_v0.set(vec![fake_peer_id(0xC1)]);

    let final_v0 = timeout(Duration::from_secs(8), handle_v0)
        .await
        .expect("V0 loop did not finish within 8s")
        .expect("V0 loop panicked");
    let final_v1 = timeout(Duration::from_secs(8), handle_v1)
        .await
        .expect("V1 loop did not finish within 8s")
        .expect("V1 loop panicked");

    // ----- V0 (leader): exact Run-008 shape on the leader side. -----
    assert!(
        final_v0.inbound.outbound_proposals_sent >= 1,
        "V0 must have emitted >=1 proposal; got {:?}",
        final_v0.inbound
    );
    assert_eq!(
        final_v0.inbound.outbound_proposal_late_peer_reemits, 1,
        "V0 must re-emit exactly one proposal after late peer connect (B9); got {:?}",
        final_v0.inbound
    );
    // B10 leader vote re-emit fires (the loop tries) but bytes are
    // dropped at the facade level when votes_connected=false. The
    // counter still moves because the facade returned Ok(()) — same
    // honest "leader tried" semantics as `outbound_votes_sent`
    // already uses.
    assert_eq!(
        final_v0.inbound.outbound_vote_late_peer_reemits, 1,
        "V0 must attempt the B10 vote re-emit exactly once; got {:?}",
        final_v0.inbound
    );
    // V0 received V1's vote (V1's outbound facade always forwards).
    assert!(
        final_v0.inbound.inbound_votes_delivered >= 1,
        "V0 must have ingested >=1 vote from V1; got {:?}",
        final_v0.inbound
    );
    // V0 formed a QC across [V0, V1] for view 0 and advanced to view 1.
    assert!(
        final_v0.current_view >= 1,
        "V0 must have advanced past view 0 (it has both votes); got current_view={}",
        final_v0.current_view
    );

    // ----- V1 (peer): the Run-008 boundary remains. -----
    assert!(
        final_v1.inbound.inbound_proposals_delivered >= 1,
        "V1 must have ingested the re-emitted proposal; got {:?}",
        final_v1.inbound
    );
    assert!(
        final_v1.inbound.outbound_votes_sent >= 1,
        "V1 must have emitted its vote in response; got {:?}",
        final_v1.inbound
    );
    // The Run-008 boundary: V1 NEVER receives the leader's vote, so
    // its inbound_votes_delivered stays at 0.
    assert_eq!(
        final_v1.inbound.inbound_votes_delivered, 0,
        "V1 must NOT have ingested any vote (leader's vote was dropped — Run-008 \
         shape); got {:?}",
        final_v1.inbound
    );
    // The Run-008 boundary: V1 never reaches 2/3, so no QC, no view
    // advance, no commit.
    assert_eq!(
        final_v1.current_view, 0,
        "V1 must remain at view 0 (cannot reach 2/3 without leader's vote); got {}",
        final_v1.current_view
    );
    assert_eq!(
        final_v1.committed_height, None,
        "V1 must have no commits in this shape; got {:?}",
        final_v1.committed_height,
    );
    assert_eq!(
        metrics_v1.consensus_t154().votes_accepted(),
        0,
        "V1's votes_accepted must be 0 in the Run-008 shape (no inbound votes)"
    );
}

// ============================================================================
// B. Post-fix engine-acceptance / QC closure: leader vote re-emitted,
//    peer reaches 2/3, both engines advance, commit progression begins.
// ============================================================================

/// **B10 / post-fix proof.**
///
/// Same topology as test A, but with the leader's outbound facade
/// using the production-equivalent `LateConnectFacade` that drops
/// outbound while disconnected and forwards once connected. After
/// V1's "inbound dial completes" (`connected = true`), the next B9
/// tick re-emits both the cached proposal AND (by B10) the cached
/// leader vote. V1 receives both: it accepts the proposal, votes,
/// receives the leader's vote, reaches 2/3 for view 0, forms its
/// own QC, advances to view 1.
///
/// Expected post-fix observations:
///
/// - V0: same as pre-fix (was already advancing fine on the leader
///   side because V1's vote reached V0).
/// - V1: now has `inbound_votes_delivered >= 1` (the leader's vote)
///   AND `current_view > 0` AND its `votes_accepted` metric is `> 0`
///   AND its `qcs_formed_total` is `> 0`.
/// - V0's `qcs_formed_total` is `> 0` (it formed a QC at view 0 even
///   pre-fix; the metric was missing because `progress_recorder`
///   wasn't wired — B10 wires it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b10_b_post_fix_engine_acceptance_qc_closure() {
    let cfg_v0 = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 2)
        .with_tick_interval(Duration::from_millis(5))
        .with_max_ticks(160);
    let cfg_v1 = BinaryConsensusLoopConfig::new(ValidatorId::new(1), 2)
        .with_tick_interval(Duration::from_millis(5))
        .with_max_ticks(160);

    let (inbound_v0_tx, inbound_v0_rx) = mpsc::channel::<ConsensusNetMsg>(64);
    let (inbound_v1_tx, inbound_v1_rx) = mpsc::channel::<ConsensusNetMsg>(64);

    // V0's facade gates outbound on a "connected" flag, modelling the
    // real-wire post-handshake / inbound-dial timing.
    let v0_connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let facade_v0_real = Arc::new(LateConnectFacade::new(
        inbound_v1_tx,
        Arc::clone(&v0_connected),
    ));
    let facade_v0_stats = Arc::clone(&facade_v0_real.stats);
    let facade_v0: Arc<dyn ConsensusNetworkFacade> = facade_v0_real;

    let facade_v1: Arc<dyn ConsensusNetworkFacade> =
        Arc::new(AlwaysForwardFacade::new(inbound_v0_tx));

    let conn_v0 = Arc::new(FakePeerConnectivity::new());
    let conn_v0_dyn: Arc<dyn PeerConnectivitySource> = conn_v0.clone();
    let conn_v1 = Arc::new(FakePeerConnectivity::new());
    let conn_v1_dyn: Arc<dyn PeerConnectivitySource> = conn_v1.clone();

    let io_v0 = BinaryConsensusLoopIo {
        inbound_rx: inbound_v0_rx,
        outbound: facade_v0,
        peer_connectivity: Some(conn_v0_dyn),
        verification_ctx: None,
    };
    let io_v1 = BinaryConsensusLoopIo {
        inbound_rx: inbound_v1_rx,
        outbound: facade_v1,
        peer_connectivity: Some(conn_v1_dyn),
        verification_ctx: None,
    };

    let (_shutdown_tx_v0, shutdown_rx_v0) = watch::channel(());
    let (_shutdown_tx_v1, shutdown_rx_v1) = watch::channel(());

    let metrics_v0 = Arc::new(NodeMetrics::new());
    let metrics_v1 = Arc::new(NodeMetrics::new());

    let (handle_v0, _progress_v0) = spawn_binary_consensus_loop_with_io(
        cfg_v0,
        shutdown_rx_v0,
        Arc::clone(&metrics_v0),
        io_v0,
    );
    let (handle_v1, _progress_v1) = spawn_binary_consensus_loop_with_io(
        cfg_v1,
        shutdown_rx_v1,
        Arc::clone(&metrics_v1),
        io_v1,
    );

    // Let V0 emit its first leader-step proposal+vote while disconnected.
    tokio::time::sleep(Duration::from_millis(40)).await;

    // Verify the pre-conditions of the late-connect timing: V0
    // attempted both proposal and vote, and both were dropped.
    {
        let s = *facade_v0_stats.lock();
        assert!(
            s.proposals_attempted >= 1 && s.proposals_dropped >= 1,
            "expected V0's first proposal to be attempted and dropped while disconnected; got {:?}",
            s
        );
        assert!(
            s.votes_attempted >= 1 && s.votes_dropped >= 1,
            "expected V0's first leader vote to be attempted and dropped while disconnected; got {:?}",
            s
        );
        assert_eq!(
            s.proposals_forwarded, 0,
            "no proposal should have reached V1 yet (disconnected); got {:?}",
            s
        );
        assert_eq!(
            s.votes_forwarded, 0,
            "no vote should have reached V1 yet (disconnected); got {:?}",
            s
        );
    }

    // Flip V0's facade to "connected" and tell V0's connectivity
    // source about the peer; B9 will fire on the next tick and
    // re-emit the cached proposal AND the cached leader vote
    // (B10).
    v0_connected.store(true, std::sync::atomic::Ordering::Relaxed);
    conn_v0.set(vec![fake_peer_id(0xC1)]);

    // Drive a bit further so the proposal+vote re-emission, V1's
    // accept/vote, and V0's ingest of V1's vote all happen.
    let final_v0 = timeout(Duration::from_secs(8), handle_v0)
        .await
        .expect("V0 loop did not finish within 8s")
        .expect("V0 loop panicked");
    let final_v1 = timeout(Duration::from_secs(8), handle_v1)
        .await
        .expect("V1 loop did not finish within 8s")
        .expect("V1 loop panicked");

    // ----- V0 (leader) -----
    assert_eq!(
        final_v0.inbound.outbound_proposal_late_peer_reemits, 1,
        "V0 must B9-re-emit proposal exactly once; got {:?}",
        final_v0.inbound,
    );
    assert_eq!(
        final_v0.inbound.outbound_vote_late_peer_reemits, 1,
        "V0 must B10-re-emit leader vote exactly once; got {:?}",
        final_v0.inbound,
    );
    assert!(
        final_v0.inbound.inbound_votes_delivered >= 1,
        "V0 must ingest >=1 vote from V1; got {:?}",
        final_v0.inbound
    );
    assert!(
        final_v0.current_view > 0,
        "V0 must advance past view 0; got {}",
        final_v0.current_view
    );

    // ----- V1 (peer): the Run-008 boundary is closed. -----
    assert!(
        final_v1.inbound.inbound_proposals_delivered >= 1,
        "V1 must ingest the re-emitted proposal; got {:?}",
        final_v1.inbound
    );
    assert!(
        final_v1.inbound.inbound_votes_delivered >= 1,
        "B10 closure: V1 must ingest the re-emitted leader vote; got {:?}",
        final_v1.inbound
    );
    assert!(
        final_v1.inbound.inbound_votes_engine_accepted >= 1,
        "B10 closure: V1's engine must accept the leader's vote; got {:?}",
        final_v1.inbound
    );
    assert!(
        final_v1.inbound.inbound_proposals_engine_accepted >= 1,
        "B10 closure: V1's engine must accept the proposal; got {:?}",
        final_v1.inbound
    );
    assert!(
        final_v1.current_view > 0,
        "B10 closure: V1 must advance past view 0; got {}",
        final_v1.current_view
    );

    // ----- /metrics observability: B10 wires the engine's progress
    // recorder so qcs_formed_total moves on actually-formed QCs and
    // consensus_t154 accept counters move on inbound accepts. -----
    assert!(
        metrics_v1.consensus_t154().votes_accepted() >= 1,
        "V1's /metrics votes_accepted must move (B10 metric closure)"
    );
    assert!(
        metrics_v1.consensus_t154().proposals_accepted() >= 1,
        "V1's /metrics proposals_accepted must move (B10 metric closure)"
    );
    assert!(
        metrics_v0.progress().qcs_formed_total() >= 1,
        "V0's /metrics qcs_formed_total must move — V0 actually formed a view-0 QC"
    );
    assert!(
        metrics_v1.progress().qcs_formed_total() >= 1,
        "V1's /metrics qcs_formed_total must move — V1 forms its own view-0 QC \
         once it has both votes"
    );

    // ----- Loop-derived snapshot also reflects the QC formations. -----
    assert!(
        final_v0.inbound.qcs_formed_total >= 1,
        "V0's loop-snapshot qcs_formed_total must move; got {:?}",
        final_v0.inbound
    );
    assert!(
        final_v1.inbound.qcs_formed_total >= 1,
        "V1's loop-snapshot qcs_formed_total must move; got {:?}",
        final_v1.inbound
    );
}

// ============================================================================
// C. Regression: B6 cross-wired path still passes after B10 changes.
// ============================================================================

/// `CrossWireFacade` from the B6 test suite. Re-defined here to keep
/// this test self-contained; behaviour is identical.
struct CrossWireFacade {
    peer_inbound: mpsc::Sender<ConsensusNetMsg>,
    sent: Arc<PlMutex<CrossWireSent>>,
}
#[derive(Default, Clone, Copy, Debug)]
struct CrossWireSent {
    proposals: u64,
    broadcast_votes: u64,
}
impl CrossWireFacade {
    fn new(peer_inbound: mpsc::Sender<ConsensusNetMsg>) -> Self {
        Self {
            peer_inbound,
            sent: Arc::new(PlMutex::new(CrossWireSent::default())),
        }
    }
}
impl ConsensusNetworkFacade for CrossWireFacade {
    fn send_vote_to(&self, _t: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        let msg = ConsensusNetMsg::Vote(encode(vote));
        let _ = self.peer_inbound.try_send(msg);
        Ok(())
    }
    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        self.sent.lock().broadcast_votes += 1;
        let msg = ConsensusNetMsg::Vote(encode(vote));
        let _ = self.peer_inbound.try_send(msg);
        Ok(())
    }
    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        self.sent.lock().proposals += 1;
        let msg = ConsensusNetMsg::Proposal(encode(proposal));
        let _ = self.peer_inbound.try_send(msg);
        Ok(())
    }
    fn send_timeout_msg(&self, _t: PeerId, _b: Vec<u8>) -> Result<(), NetworkError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b10_c_b6_cross_wired_path_still_progresses() {
    let cfg_a = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 2)
        .with_tick_interval(Duration::from_millis(2))
        .with_max_ticks(120);
    let cfg_b = BinaryConsensusLoopConfig::new(ValidatorId::new(1), 2)
        .with_tick_interval(Duration::from_millis(2))
        .with_max_ticks(120);

    let (inbound_a_tx, inbound_a_rx) = mpsc::channel::<ConsensusNetMsg>(64);
    let (inbound_b_tx, inbound_b_rx) = mpsc::channel::<ConsensusNetMsg>(64);

    let facade_a = Arc::new(CrossWireFacade::new(inbound_b_tx));
    let facade_b = Arc::new(CrossWireFacade::new(inbound_a_tx));

    let io_a = BinaryConsensusLoopIo {
        inbound_rx: inbound_a_rx,
        outbound: facade_a as Arc<dyn ConsensusNetworkFacade>,
        peer_connectivity: None,
        verification_ctx: None,
    };
    let io_b = BinaryConsensusLoopIo {
        inbound_rx: inbound_b_rx,
        outbound: facade_b as Arc<dyn ConsensusNetworkFacade>,
        peer_connectivity: None,
        verification_ctx: None,
    };

    let (_shutdown_tx_a, shutdown_rx_a) = watch::channel(());
    let (_shutdown_tx_b, shutdown_rx_b) = watch::channel(());

    let metrics_a = Arc::new(NodeMetrics::new());
    let metrics_b = Arc::new(NodeMetrics::new());

    let (handle_a, _progress_a) =
        spawn_binary_consensus_loop_with_io(cfg_a, shutdown_rx_a, metrics_a, io_a);
    let (handle_b, _progress_b) =
        spawn_binary_consensus_loop_with_io(cfg_b, shutdown_rx_b, metrics_b, io_b);

    let final_a = timeout(Duration::from_secs(8), handle_a)
        .await
        .expect("loop A timed out")
        .expect("A panicked");
    let final_b = timeout(Duration::from_secs(8), handle_b)
        .await
        .expect("loop B timed out")
        .expect("B panicked");

    // Both must advance past view 0 — the only honest way for that
    // to happen with 2 validators is QC formation across both engines.
    assert!(
        final_a.current_view > 0,
        "A must advance past view 0; got {}",
        final_a.current_view
    );
    assert!(
        final_b.current_view > 0,
        "B must advance past view 0; got {}",
        final_b.current_view
    );

    // No B9/B10 re-emit should have fired here: peer_connectivity =
    // None means the late-peer-connect path is disabled entirely.
    assert_eq!(
        final_a.inbound.outbound_proposal_late_peer_reemits, 0,
        "B6 path uses peer_connectivity=None — no re-emit; got {:?}",
        final_a.inbound
    );
    assert_eq!(
        final_a.inbound.outbound_vote_late_peer_reemits, 0,
        "B6 path uses peer_connectivity=None — no vote re-emit; got {:?}",
        final_a.inbound
    );
    assert_eq!(
        final_b.inbound.outbound_proposal_late_peer_reemits, 0,
        "B6 path uses peer_connectivity=None — no re-emit; got {:?}",
        final_b.inbound
    );
}

// ============================================================================
// D. Regression: B9 + B10 single-shot latch is still bounded on
//    reconnect churn.
// ============================================================================

/// Across many ticks of repeated peer connect → disconnect → connect
/// churn within the same view, the loop must still re-emit the
/// cached proposal+vote pair **at most once**. This is the same
/// guarantee B9 originally provided; B10 must preserve it across
/// the proposal+vote pair.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b10_d_late_peer_reconnect_churn_stays_single_shot() {
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 2)
        .with_tick_interval(Duration::from_millis(5));
    let (_inbound_tx, inbound_rx) = mpsc::channel::<ConsensusNetMsg>(8);
    let (peer_inbound_tx, _peer_inbound_rx) = mpsc::channel::<ConsensusNetMsg>(64);
    let v0_connected = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let facade = Arc::new(LateConnectFacade::new(
        peer_inbound_tx,
        Arc::clone(&v0_connected),
    ));
    let conn = Arc::new(FakePeerConnectivity::new());
    let conn_dyn: Arc<dyn PeerConnectivitySource> = conn.clone();
    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound: facade as Arc<dyn ConsensusNetworkFacade>,
        peer_connectivity: Some(conn_dyn),
        verification_ctx: None,
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let (handle, progress) =
        spawn_binary_consensus_loop_with_io(cfg, shutdown_rx, metrics, io);

    // Let V0 emit the initial proposal/vote (which now go straight
    // through because connected=true; but no peer is consuming from
    // peer_inbound_rx — that's fine, the channel buffers them).
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Now perform multiple reconnect cycles within the same view (V0
    // is alone, so view stays at 0 the entire time).
    for _ in 0..6 {
        conn.set(vec![fake_peer_id(0xC1)]);
        tokio::time::sleep(Duration::from_millis(20)).await;
        conn.set(vec![]);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Bring it back up one more time and let the loop tick a bit.
    conn.set(vec![fake_peer_id(0xC1)]);
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Read the running counters (do not shut down yet).
    let snap = progress.lock().inbound;
    drop(shutdown_tx);
    let _ = timeout(Duration::from_secs(3), handle).await;

    assert!(
        snap.outbound_proposal_late_peer_reemits <= 1,
        "B9 single-shot latch must hold across reconnect churn; got {:?}",
        snap
    );
    assert!(
        snap.outbound_vote_late_peer_reemits <= 1,
        "B10 single-shot latch must hold across reconnect churn; got {:?}",
        snap
    );
    // Vote re-emit must never exceed proposal re-emit (paired
    // semantics): we never re-emit a vote without a paired proposal.
    assert!(
        snap.outbound_vote_late_peer_reemits <= snap.outbound_proposal_late_peer_reemits,
        "B10 vote re-emit must be paired with a proposal re-emit; got {:?}",
        snap
    );
}

// ============================================================================
// E. Regression: io=None single-validator path unchanged.
// ============================================================================

/// The `io=None` LocalMesh / single-validator path must continue to
/// commit per tick — B10 must not regress B1/B2/B3/B5.
#[tokio::test]
async fn b10_e_io_none_single_validator_still_commits() {
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
        .with_tick_interval(Duration::from_millis(2))
        .with_max_ticks(50);
    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let progress = Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));

    let final_progress = run_binary_consensus_loop_with_io(
        cfg,
        shutdown_rx,
        progress,
        Arc::clone(&metrics),
        None,
    )
    .await;

    assert!(
        final_progress.proposals_emitted >= 1,
        "single-validator io=None loop must still emit proposals; got {:?}",
        final_progress
    );
    assert!(
        final_progress.commits >= 1,
        "single-validator io=None loop must still commit; got {:?}",
        final_progress
    );
    // B10 wired the engine's progress recorder, so qcs_formed_total
    // must also move now even on the single-validator path. This is
    // an honest improvement, not a fabrication: the engine forms a
    // self-quorum QC every view in single-validator mode.
    assert!(
        metrics.progress().qcs_formed_total() >= 1,
        "/metrics qcs_formed_total must reflect actually-formed QCs even on single-validator path"
    );
    assert!(
        final_progress.inbound.qcs_formed_total >= 1,
        "loop-snapshot qcs_formed_total must mirror /metrics; got {:?}",
        final_progress.inbound
    );
    // No inbound activity on io=None.
    assert_eq!(final_progress.inbound.inbound_msgs_received, 0);
    assert_eq!(final_progress.inbound.outbound_proposal_late_peer_reemits, 0);
    assert_eq!(final_progress.inbound.outbound_vote_late_peer_reemits, 0);
}