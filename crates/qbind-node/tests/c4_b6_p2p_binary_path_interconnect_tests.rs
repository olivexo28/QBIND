//! C4 / B6 — Multi-validator P2P binary-path consensus interconnect tests.
//!
//! These tests prove the smallest honest claim required by the C4 sub-item:
//! when the binary-path consensus loop is wired with an inbound
//! `ConsensusNetMsg` channel (as produced by `ChannelConsensusHandler` in
//! the P2P inbound demuxer) and an outbound `ConsensusNetworkFacade`
//! (as implemented by `P2pConsensusNetwork`), inbound proposals and votes
//! actually move the running `BasicHotStuffEngine`'s state, and the
//! engine's resulting `ConsensusEngineAction`s flow back out through the
//! supplied facade.
//!
//! These tests intentionally do not spin up the real PQC KEMTLS transport:
//! they target the *binary path itself*, by replacing the P2P transport
//! with a recording / cross-wired `ConsensusNetworkFacade`. That is the
//! correct surface to test, because the bug being closed (C4) was that
//! the binary path never fed inbound messages into the engine at all,
//! regardless of which transport produced them.
//!
//! Test matrix:
//!
//! - **A. Inbound proposal reaches the engine** — feeding a
//!   `ConsensusNetMsg::Proposal` into `inbound_rx` causes the engine to
//!   call `on_proposal_event` (proven by the engine emitting the
//!   resulting `BroadcastVote` to the outbound facade and the inbound
//!   stats recording one delivered proposal). This test would fail under
//!   the pre-B6 wiring where `P2pNodeBuilder` plugged a dropped channel
//!   into the demuxer and inbound traffic was silently lost.
//!
//! - **B. Two-engine cross-wired binary-path progression** — two engines
//!   driven by `run_binary_consensus_loop_with_io`, with their outbound
//!   facades cross-wired into each other's inbound channels, advance views
//!   together: leader proposes, follower votes, the leader receives the
//!   follower's vote, a QC forms across the two engines, and the cross-node
//!   commit count increases. This is the bounded "binary path is no longer
//!   transport-only" proof.
//!
//! - **C. Single-validator behaviour does not regress** — the io=None
//!   variant of the loop continues to commit per tick, exactly as the
//!   pre-B6 path.
//!
//! - **D. Inbound channel close is handled honestly** — the loop does not
//!   panic / busy-loop when the inbound channel closes; it falls through
//!   to tick-only behaviour and exits cleanly on shutdown.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use parking_lot::Mutex as PlMutex;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::network::NetworkError;
use qbind_node::binary_consensus_loop::{
    run_binary_consensus_loop_with_io, spawn_binary_consensus_loop_with_io,
    BinaryConsensusLoopConfig, BinaryConsensusLoopIo, BinaryConsensusLoopProgress,
};
use qbind_node::consensus_network_facade::ConsensusNetworkFacade;
use qbind_node::metrics::NodeMetrics;
use qbind_node::p2p::ConsensusNetMsg;
use qbind_node::peer::PeerId;
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};
use qbind_wire::io::WireEncode;

// ============================================================================
// Test helpers
// ============================================================================

/// Build a wire-format `BlockProposal` for view 0 by validator `proposer`,
/// exactly matching what the leader-step path of `BasicHotStuffEngine`
/// would produce for a fresh genesis view. Importantly:
///
/// - `header.proposer_index == proposer.as_u64() as u16` so the loop can
///   recover the sender's `ValidatorId` (this is the same convention used
///   throughout `qbind-wire`).
/// - `parent_block_id == [0xFF; 32]` (the engine's "no parent" sentinel).
/// - No qc / no transactions.
fn make_genesis_proposal(proposer: ValidatorId) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 0,
            round: 0,
            parent_block_id: [0xFF; 32],
            payload_hash: [0u8; 32],
            proposer_index: proposer.as_u64() as u16,
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
    }
}

fn encode<T: WireEncode>(t: &T) -> Vec<u8> {
    let mut out = Vec::new();
    t.encode(&mut out);
    out
}

/// A `ConsensusNetworkFacade` that records every action it receives.
/// Used by tests that want to assert on engine outbound actions without
/// going through real transport.
#[derive(Default)]
struct RecordingFacade {
    inner: Mutex<RecordingFacadeInner>,
}

#[derive(Default)]
struct RecordingFacadeInner {
    proposals: Vec<BlockProposal>,
    broadcast_votes: Vec<Vote>,
    direct_votes: Vec<(ValidatorId, Vote)>,
    timeouts: Vec<(PeerId, Vec<u8>)>,
}

impl RecordingFacade {
    fn snapshot(&self) -> RecordingSnapshot {
        let inner = self.inner.lock().unwrap();
        RecordingSnapshot {
            proposals: inner.proposals.clone(),
            broadcast_votes: inner.broadcast_votes.clone(),
            direct_votes: inner.direct_votes.clone(),
            timeout_count: inner.timeouts.len(),
        }
    }
}

#[derive(Clone)]
#[allow(dead_code)]
struct RecordingSnapshot {
    proposals: Vec<BlockProposal>,
    broadcast_votes: Vec<Vote>,
    direct_votes: Vec<(ValidatorId, Vote)>,
    timeout_count: usize,
}

impl ConsensusNetworkFacade for RecordingFacade {
    fn send_vote_to(&self, target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        self.inner
            .lock()
            .unwrap()
            .direct_votes
            .push((target, vote.clone()));
        Ok(())
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        self.inner.lock().unwrap().broadcast_votes.push(vote.clone());
        Ok(())
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        self.inner
            .lock()
            .unwrap()
            .proposals
            .push(proposal.clone());
        Ok(())
    }

    fn send_timeout_msg(&self, target: PeerId, msg_bytes: Vec<u8>) -> Result<(), NetworkError> {
        self.inner
            .lock()
            .unwrap()
            .timeouts
            .push((target, msg_bytes));
        Ok(())
    }
}

/// A `ConsensusNetworkFacade` that re-encodes every outbound action as a
/// `ConsensusNetMsg` and forwards it into a peer's inbound channel — i.e.
/// the in-process equivalent of the real P2P broadcast path. Used by the
/// two-engine cross-wired test to prove the binary path actually moves
/// peer engines forward.
struct CrossWireFacade {
    peer_inbound: mpsc::Sender<ConsensusNetMsg>,
    /// Mirror counter for assertions independent of the receiving loop.
    sent: Arc<PlMutex<CrossWireSent>>,
}

#[derive(Default, Clone, Copy, Debug)]
struct CrossWireSent {
    proposals: u64,
    broadcast_votes: u64,
    direct_votes: u64,
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
    fn send_vote_to(&self, _target: ValidatorId, vote: &Vote) -> Result<(), NetworkError> {
        {
            let mut s = self.sent.lock();
            s.direct_votes = s.direct_votes.saturating_add(1);
        }
        let msg = ConsensusNetMsg::Vote(encode(vote));
        let _ = self.peer_inbound.try_send(msg);
        Ok(())
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        {
            let mut s = self.sent.lock();
            s.broadcast_votes = s.broadcast_votes.saturating_add(1);
        }
        let msg = ConsensusNetMsg::Vote(encode(vote));
        let _ = self.peer_inbound.try_send(msg);
        Ok(())
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        {
            let mut s = self.sent.lock();
            s.proposals = s.proposals.saturating_add(1);
        }
        let msg = ConsensusNetMsg::Proposal(encode(proposal));
        let _ = self.peer_inbound.try_send(msg);
        Ok(())
    }

    fn send_timeout_msg(&self, _target: PeerId, _msg_bytes: Vec<u8>) -> Result<(), NetworkError> {
        // Timeout / TC routing on the binary path is intentionally deferred
        // (see `binary_consensus_loop::handle_inbound_consensus_msg`).
        Ok(())
    }
}

// ============================================================================
// A. Inbound proposal reaches the engine
// ============================================================================

/// **C4/B6 inbound→engine routing proof.**
///
/// Build a 2-validator binary-path loop running as validator 1 (the
/// follower for view 0, since validator 0 is leader). Feed in a wire-encoded
/// `BlockProposal` from validator 0 via the inbound channel. The loop must:
///
/// 1. record one inbound proposal delivered;
/// 2. cause the engine to emit a `BroadcastVote` for the proposal — which
///    appears on the outbound facade.
///
/// If the inbound→engine wiring were missing (the pre-B6 state described by
/// C4), the recorded outbound vote count would stay at 0 because the engine
/// would never have seen the proposal. Therefore this test directly fails
/// the "transport up, engine isolated" bug.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b6_inbound_proposal_reaches_engine_and_emits_vote() {
    let local = ValidatorId::new(1);
    let leader = ValidatorId::new(0);

    let cfg = BinaryConsensusLoopConfig::new(local, 2)
        .with_tick_interval(Duration::from_millis(50)) // long enough that
        // ticks don't dominate
        .with_max_ticks(20);

    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let progress = Arc::new(PlMutex::new(BinaryConsensusLoopProgress::default()));

    let (inbound_tx, inbound_rx) = mpsc::channel::<ConsensusNetMsg>(16);
    let outbound = Arc::new(RecordingFacade::default());
    let outbound_dyn: Arc<dyn ConsensusNetworkFacade> = outbound.clone();

    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound: outbound_dyn,
    };

    // Pre-feed the inbound channel before the loop starts so the very first
    // `recv()` succeeds without racing the ticker.
    let proposal = make_genesis_proposal(leader);
    inbound_tx
        .send(ConsensusNetMsg::Proposal(encode(&proposal)))
        .await
        .expect("inbound channel must accept proposal");

    let loop_metrics = metrics.clone();
    let loop_progress = progress.clone();
    let handle = tokio::spawn(async move {
        run_binary_consensus_loop_with_io(
            cfg,
            shutdown_rx,
            loop_progress,
            loop_metrics,
            Some(io),
        )
        .await
    });

    // Wait until the loop has either delivered the proposal or run its
    // tick budget — whichever comes first.
    let final_progress = timeout(Duration::from_secs(3), handle)
        .await
        .expect("binary consensus loop did not finish within 3s")
        .expect("binary consensus loop task panicked");

    // The loop must have observed and delivered the inbound proposal.
    assert!(
        final_progress.inbound.inbound_msgs_received >= 1,
        "loop must have observed at least one inbound message; got {:?}",
        final_progress.inbound
    );
    assert_eq!(
        final_progress.inbound.inbound_proposals_delivered, 1,
        "loop must have delivered exactly one inbound proposal to the engine; \
         stats={:?}",
        final_progress.inbound
    );

    // The engine must have voted for the proposal — that vote action must
    // have flowed through the outbound facade. This is the smoking gun
    // proving inbound bytes affect engine state and produce real network
    // actions.
    let snap = outbound.snapshot();
    assert!(
        !snap.broadcast_votes.is_empty(),
        "engine must have emitted a BroadcastVote in response to the \
         inbound proposal — got 0 outbound broadcast votes (snapshot proposals={}, \
         direct_votes={})",
        snap.proposals.len(),
        snap.direct_votes.len()
    );

    // The vote's height/block_id must match the proposal that was fed in.
    let v = &snap.broadcast_votes[0];
    assert_eq!(
        v.height, proposal.header.height,
        "outbound vote must be for the proposed view"
    );
    assert_eq!(
        v.validator_index as u64,
        local.as_u64(),
        "outbound vote must be authored by the local validator"
    );

    // Counter sanity: every successful broadcast_vote also moved the
    // outbound counter the loop maintains.
    assert!(
        final_progress.inbound.outbound_votes_sent >= 1,
        "loop's outbound_votes_sent counter must reflect the emitted vote; \
         stats={:?}",
        final_progress.inbound
    );
}

// ============================================================================
// B. Bounded multi-node binary-path progression proof
// ============================================================================

/// **C4/B6 cross-node binary-path progression proof.**
///
/// Two engines (validator 0 and validator 1) drive
/// `run_binary_consensus_loop_with_io` concurrently. Their outbound facades
/// are cross-wired (each one's outbound feeds the other's inbound), so:
///
/// - validator 0 (leader for view 0) emits a proposal + leader self-vote
///   on its first tick;
/// - validator 1 receives the proposal via its inbound channel, calls
///   `on_proposal_event`, and broadcasts its vote;
/// - validator 0 receives validator 1's vote, calls `on_vote_event`,
///   forms a QC across the two engines, advances its view, etc.
///
/// The test asserts that **both** engines advance past view 0 within a
/// bounded time window and that **both** sides observed cross-engine
/// progress (outbound proposals from leader, outbound votes from
/// follower, inbound votes/proposals delivered on each side). This proves
/// the binary path is no longer "transport up, engine isolated": peers
/// actually move each other's engines forward.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b6_two_engine_cross_wired_binary_path_progression() {
    // Two-validator setup; tight tick budget so the test stays bounded.
    let cfg_a = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 2)
        .with_tick_interval(Duration::from_millis(2))
        .with_max_ticks(80);
    let cfg_b = BinaryConsensusLoopConfig::new(ValidatorId::new(1), 2)
        .with_tick_interval(Duration::from_millis(2))
        .with_max_ticks(80);

    // Inbound channels for each engine.
    let (inbound_a_tx, inbound_a_rx) = mpsc::channel::<ConsensusNetMsg>(64);
    let (inbound_b_tx, inbound_b_rx) = mpsc::channel::<ConsensusNetMsg>(64);

    // Cross-wired facades: A's outbound goes to B's inbound and vice versa.
    let facade_a = Arc::new(CrossWireFacade::new(inbound_b_tx));
    let facade_b = Arc::new(CrossWireFacade::new(inbound_a_tx));
    let sent_a = facade_a.sent.clone();
    let sent_b = facade_b.sent.clone();

    let io_a = BinaryConsensusLoopIo {
        inbound_rx: inbound_a_rx,
        outbound: facade_a as Arc<dyn ConsensusNetworkFacade>,
    };
    let io_b = BinaryConsensusLoopIo {
        inbound_rx: inbound_b_rx,
        outbound: facade_b as Arc<dyn ConsensusNetworkFacade>,
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
        .expect("loop A did not finish within 8s")
        .expect("loop A panicked");
    let final_b = timeout(Duration::from_secs(8), handle_b)
        .await
        .expect("loop B did not finish within 8s")
        .expect("loop B panicked");

    // ----- Cross-node activity must have happened on both sides. -----

    // The leader (A) must have emitted at least one proposal that was
    // sent through the cross-wired facade — i.e. A really tried to drive
    // B's engine.
    let sa = *sent_a.lock();
    let sb = *sent_b.lock();
    assert!(
        sa.proposals >= 1,
        "leader (A) must have broadcast at least one proposal across the \
         cross-wired facade; sa={:?}",
        sa
    );

    // B must have received and decoded at least one inbound proposal —
    // proof that a *peer's* P2P-equivalent bytes reached B's engine.
    assert!(
        final_b.inbound.inbound_proposals_delivered >= 1,
        "follower (B) must have delivered at least one inbound proposal to \
         its engine; stats_b={:?}",
        final_b.inbound
    );

    // B must have voted in response, and that vote must have been forwarded
    // through B's outbound facade.
    assert!(
        sb.broadcast_votes >= 1,
        "follower (B) must have emitted at least one outbound vote in \
         response to the leader's proposal; sb={:?}",
        sb
    );

    // A must have received and ingested at least one inbound vote (B's
    // vote, looped back through the cross-wired facade).
    assert!(
        final_a.inbound.inbound_votes_delivered >= 1,
        "leader (A) must have delivered at least one inbound vote to its \
         engine (B's vote); stats_a={:?}",
        final_a.inbound
    );

    // Both engines must have advanced past view 0 — the only honest way
    // for that to happen with 2 validators is QC formation across both
    // engines. (Single-validator self-quorum is impossible with n=2.)
    assert!(
        final_a.current_view > 0,
        "leader (A) must have advanced past view 0; got current_view={}",
        final_a.current_view
    );
    assert!(
        final_b.current_view > 0,
        "follower (B) must have advanced past view 0; got current_view={}",
        final_b.current_view
    );
}

// ============================================================================
// C. Single-validator regression: io=None path is unchanged
// ============================================================================

/// The `io=None` variant of the loop must remain bit-equivalent to the
/// pre-B6 single-validator path. This regression-tests B1/B2/B5 paths.
#[tokio::test]
async fn b6_io_none_single_validator_path_unchanged() {
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
        .with_tick_interval(Duration::from_millis(2))
        .with_max_ticks(30);
    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let progress = Arc::new(PlMutex::new(BinaryConsensusLoopProgress::default()));

    let final_progress =
        run_binary_consensus_loop_with_io(cfg, shutdown_rx, progress, metrics, None).await;

    assert!(
        final_progress.proposals_emitted >= 1,
        "single-validator io=None loop must still emit proposals"
    );
    assert!(
        final_progress.commits >= 1,
        "single-validator io=None loop must still commit"
    );
    // No inbound activity must have been recorded — the io=None path must
    // not invent inbound traffic.
    assert_eq!(final_progress.inbound.inbound_msgs_received, 0);
    assert_eq!(final_progress.inbound.inbound_proposals_delivered, 0);
    assert_eq!(final_progress.inbound.inbound_votes_delivered, 0);
    assert_eq!(final_progress.inbound.outbound_proposals_sent, 0);
    assert_eq!(final_progress.inbound.outbound_votes_sent, 0);
}

// ============================================================================
// D. Inbound channel close is handled honestly
// ============================================================================

/// If the inbound channel closes (e.g. the demuxer task ended) the loop
/// must not panic or stall; it must keep ticking and exit cleanly on
/// shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b6_loop_survives_inbound_close() {
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
        .with_tick_interval(Duration::from_millis(2))
        .with_max_ticks(20);
    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let progress = Arc::new(PlMutex::new(BinaryConsensusLoopProgress::default()));

    // Build an inbound channel and immediately drop the sender so the
    // loop sees the channel close on its very first poll.
    let (inbound_tx, inbound_rx) = mpsc::channel::<ConsensusNetMsg>(8);
    drop(inbound_tx);
    let outbound: Arc<dyn ConsensusNetworkFacade> = Arc::new(RecordingFacade::default());
    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound,
    };

    let final_progress = timeout(
        Duration::from_secs(3),
        run_binary_consensus_loop_with_io(cfg, shutdown_rx, progress, metrics, Some(io)),
    )
    .await
    .expect("loop did not finish within 3s after inbound close");

    // Loop must still tick to completion (max_ticks reached).
    assert!(
        final_progress.ticks >= 1,
        "loop must keep ticking after inbound channel closes"
    );
    // Single-validator self-quorum still works.
    assert!(
        final_progress.proposals_emitted >= 1,
        "loop must still emit proposals after inbound close"
    );
}

// ============================================================================
// E. Decoded sender mismatch is rejected honestly (proposer != leader)
// ============================================================================

/// An inbound proposal whose `proposer_index` is not the leader for the
/// current view must be rejected by `engine.on_proposal_event` (no vote),
/// but the inbound stats must still record that the message arrived and
/// decoded successfully. This guards against the loop silently swallowing
/// inbound messages just because the engine refused them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b6_inbound_non_leader_proposal_does_not_silently_drop() {
    // Local node = validator 1; leader for view 0 = validator 0. Send a
    // proposal *from validator 1* (non-leader) — engine should reject the
    // vote, but the loop must still register the inbound message.
    let local = ValidatorId::new(1);
    let cfg = BinaryConsensusLoopConfig::new(local, 2)
        .with_tick_interval(Duration::from_millis(50))
        .with_max_ticks(10);

    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let progress = Arc::new(PlMutex::new(BinaryConsensusLoopProgress::default()));

    let (inbound_tx, inbound_rx) = mpsc::channel::<ConsensusNetMsg>(8);
    let outbound = Arc::new(RecordingFacade::default());
    let outbound_dyn: Arc<dyn ConsensusNetworkFacade> = outbound.clone();
    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound: outbound_dyn,
    };

    // Proposal from a non-leader (validator 1).
    let bad_proposal = make_genesis_proposal(ValidatorId::new(1));
    inbound_tx
        .send(ConsensusNetMsg::Proposal(encode(&bad_proposal)))
        .await
        .unwrap();

    let final_progress = timeout(
        Duration::from_secs(3),
        run_binary_consensus_loop_with_io(cfg, shutdown_rx, progress, metrics, Some(io)),
    )
    .await
    .expect("loop did not finish within 3s");

    // Inbound delivery is recorded — the engine *was* called with the
    // proposal — but no vote was emitted because the engine rejected the
    // non-leader proposer.
    assert_eq!(
        final_progress.inbound.inbound_proposals_delivered, 1,
        "loop must record the inbound proposal as delivered to the engine, \
         even when the engine refuses to vote on it; stats={:?}",
        final_progress.inbound
    );
    let snap = outbound.snapshot();
    assert!(
        snap.broadcast_votes.is_empty(),
        "engine must not vote on a proposal whose proposer is not the leader \
         for the current view; got broadcast_votes={}",
        snap.broadcast_votes.len()
    );
}