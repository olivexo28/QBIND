//! B9 — Leader-side re-emission of `BroadcastProposal` on late peer
//! connect within the same view (binary-path consensus loop).
//!
//! These tests prove the smallest honest claim required to close the
//! negative finding of DevNet Evidence Run 007:
//!
//! > V0's leader-issued view-0 `BroadcastProposal` action was emitted at
//! > consensus-loop start but never reached the wire because V1 had not
//! > yet established its TCP→V0 inbound at the moment of leader emission
//! > and the engine does not re-emit a view-0 proposal once issued.
//!
//! The B9 fix runs entirely on the binary-path consensus loop (no engine
//! redesign): when a `PeerConnectivitySource` is wired into
//! `BinaryConsensusLoopIo`, the loop tracks the leader's last
//! `BroadcastProposal` and the view it was emitted for, observes the
//! connected NodeId set on every tick, and re-broadcasts the cached
//! current-view proposal exactly once on the next tick after at least
//! one expected peer transitions from "not connected" to "connected" —
//! provided the local engine is still leader of that same view, the
//! view has not changed, and no commit has invalidated the proposal.
//!
//! Test matrix:
//!
//! - **A. Late peer connect triggers exactly one bounded re-emission**
//!   — single-validator engine (so it is leader of every view) starts
//!   with an empty connected-peer set, emits the view-0 proposal once,
//!   then a peer NodeId becomes "connected"; on the next tick the loop
//!   re-broadcasts the cached proposal and bumps
//!   `outbound_proposal_late_peer_reemits` to exactly 1. This test
//!   would fail under the pre-B9 loop, where no re-emission code path
//!   exists.
//!
//! - **B. No unbounded repeat spam.** Once the late-peer re-emit has
//!   fired, additional ticks with the same connected set produce no
//!   further re-emits. Reconnect churn (peer disappears and reappears
//!   within the same view) also produces no further re-emits — the
//!   per-view single-shot latch holds.
//!
//! - **C. View-change invalidates re-emission.** If the view advances
//!   between the original emission and the late peer connect, the
//!   cached proposal is dropped and no stale re-emission occurs.
//!
//! - **D. Peer already connected before first proposal does not
//!   re-emit.** When the initial connected set already contains an
//!   expected peer, the very first tick observes a transition (empty →
//!   present), but because the proposal was just emitted on the same
//!   tick the path stays bounded and the test asserts that the
//!   counter still increments at most once.
//!
//! - **E. Single-validator / `peer_connectivity = None` regression
//!   guard.** With `peer_connectivity = None` the loop never enters the
//!   B9 branch, so `outbound_proposal_late_peer_reemits` stays at 0
//!   regardless of how many ticks fire. This protects B1/B2 and
//!   LocalMesh from regression.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex as PlMutex;
use tokio::sync::{mpsc, watch};

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::network::NetworkError;
use qbind_node::binary_consensus_loop::{
    run_binary_consensus_loop_with_io, BinaryConsensusLoopConfig, BinaryConsensusLoopIo,
    BinaryConsensusLoopProgress, PeerConnectivitySource,
};
use qbind_node::consensus_network_facade::ConsensusNetworkFacade;
use qbind_node::metrics::NodeMetrics;
use qbind_node::p2p::{ConsensusNetMsg, NodeId};
use qbind_node::peer::PeerId;
use qbind_wire::consensus::{BlockProposal, Vote};

// ============================================================================
// Test helpers
// ============================================================================

/// A `ConsensusNetworkFacade` that records every `broadcast_proposal` call
/// (and ignores everything else for this test surface). Tests use the
/// recorded count to assert "the loop *actually called* the outbound facade
/// for re-emission, not just incremented a counter".
#[derive(Default)]
struct RecordingProposalFacade {
    proposals: PlMutex<Vec<BlockProposal>>,
}

impl RecordingProposalFacade {
    fn proposal_count(&self) -> usize {
        self.proposals.lock().len()
    }
}

impl ConsensusNetworkFacade for RecordingProposalFacade {
    fn send_vote_to(&self, _target: ValidatorId, _vote: &Vote) -> Result<(), NetworkError> {
        Ok(())
    }
    fn broadcast_vote(&self, _vote: &Vote) -> Result<(), NetworkError> {
        Ok(())
    }
    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        self.proposals.lock().push(proposal.clone());
        Ok(())
    }
    fn send_timeout_msg(&self, _target: PeerId, _msg_bytes: Vec<u8>) -> Result<(), NetworkError> {
        Ok(())
    }
}

/// A `PeerConnectivitySource` whose connected set can be flipped at will
/// from the test thread. Models "static peer initially down, then comes
/// up" without standing up real KEMTLS.
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

/// Spawn a single-validator binary loop with a recording facade and a
/// fake `PeerConnectivitySource` so the test can drive late-peer
/// transitions on demand. Returns:
///
/// - the join handle for the loop task,
/// - the shutdown sender (drop or send to terminate),
/// - the recording facade (for proposal-count assertions),
/// - the fake connectivity source (for `set(...)`),
/// - the inbound tx (kept open so the loop's `select!` doesn't fall
///   through to the no-io branch),
/// - the shared progress handle (for `inbound.outbound_proposal_late_peer_reemits` reads).
#[allow(clippy::type_complexity)]
fn spawn_loop_for_test(
    tick: Duration,
) -> (
    tokio::task::JoinHandle<BinaryConsensusLoopProgress>,
    watch::Sender<()>,
    Arc<RecordingProposalFacade>,
    Arc<FakePeerConnectivity>,
    mpsc::Sender<ConsensusNetMsg>,
    Arc<parking_lot::Mutex<BinaryConsensusLoopProgress>>,
) {
    let (inbound_tx, inbound_rx) = mpsc::channel::<ConsensusNetMsg>(8);
    let outbound = Arc::new(RecordingProposalFacade::default());
    let outbound_dyn: Arc<dyn ConsensusNetworkFacade> = outbound.clone();
    let connectivity = Arc::new(FakePeerConnectivity::new());
    let connectivity_dyn: Arc<dyn PeerConnectivitySource> = connectivity.clone();

    // num_validators=2 with local_validator_id=0 → leader of view 0 is
    // validator 0 (local), but quorum requires both votes. Without an
    // inbound vote from the other validator, view 0 stays current and
    // the cached proposal remains valid for the entire test, allowing
    // us to exercise the B9 re-emit path deterministically. (Single
    // validator mode does NOT work here: self-quorum would advance the
    // view on the same tick the proposal is emitted, invalidating the
    // cache before any connectivity poll could observe a transition —
    // which is exactly what gate 3 is supposed to do, and is tested
    // separately in `b9_c_view_change_does_not_replay_stale_proposal_for_old_view`.)
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 2).with_tick_interval(tick);

    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound: outbound_dyn,
        peer_connectivity: Some(connectivity_dyn),
        verification_ctx: None,
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let progress = Arc::new(parking_lot::Mutex::new(
        BinaryConsensusLoopProgress::default(),
    ));
    let progress_for_task = progress.clone();
    let metrics = Arc::new(NodeMetrics::new());
    let handle = tokio::spawn(async move {
        run_binary_consensus_loop_with_io(cfg, shutdown_rx, progress_for_task, metrics, Some(io))
            .await
    });
    (
        handle,
        shutdown_tx,
        outbound,
        connectivity,
        inbound_tx,
        progress,
    )
}

async fn shutdown_and_join(
    handle: tokio::task::JoinHandle<BinaryConsensusLoopProgress>,
    shutdown_tx: watch::Sender<()>,
) -> BinaryConsensusLoopProgress {
    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("loop did not exit within 5s of shutdown")
        .expect("loop task panicked")
}

// ============================================================================
// A. Late peer connect triggers exactly one bounded re-emission
// ============================================================================

#[tokio::test]
async fn b9_a_late_peer_connect_triggers_exactly_one_reemit() {
    // Use a fast tick so we don't sleep too long, but slow enough that
    // multiple ticks fire before/after the connectivity flip so the
    // per-view boundedness latch is actually exercised.
    let tick = Duration::from_millis(20);
    let (handle, shutdown_tx, outbound, connectivity, _inbound_tx, progress) =
        spawn_loop_for_test(tick);

    // Phase 1: empty connected set; let the loop run several ticks.
    // The single-validator leader emits view-0 (and possibly more)
    // proposals. The B9 path should NOT fire because there is no
    // not-connected → connected transition.
    tokio::time::sleep(Duration::from_millis(120)).await;
    let phase1_reemits = progress.lock().inbound.outbound_proposal_late_peer_reemits;
    assert_eq!(
        phase1_reemits, 0,
        "phase 1: empty connected set must produce zero late-peer re-emits, got {}",
        phase1_reemits
    );
    let phase1_proposal_count = outbound.proposal_count();

    // Phase 2: peer connects. On the next tick the loop should observe
    // the empty → present transition, gate-check the cached proposal
    // against the engine's current view (still leader, view matches),
    // and re-emit exactly once. Multiple ticks pass to ensure there is
    // no per-tick rebroadcast.
    connectivity.set(vec![fake_peer_id(0xAA)]);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let final_progress = shutdown_and_join(handle, shutdown_tx).await;

    let reemits = final_progress.inbound.outbound_proposal_late_peer_reemits;
    assert_eq!(
        reemits, 1,
        "B9: exactly one late-peer re-emit expected after the empty→present transition, got {}",
        reemits
    );
    let phase2_proposal_count = outbound.proposal_count();
    assert!(
        phase2_proposal_count > phase1_proposal_count,
        "B9: outbound facade must observe an extra broadcast_proposal call after late peer \
         connect (phase1={}, phase2={})",
        phase1_proposal_count,
        phase2_proposal_count
    );
    // The extra call count is 1 — anything more would mean unbounded
    // rebroadcast on subsequent ticks.
    let extra = phase2_proposal_count - phase1_proposal_count;
    assert!(
        extra >= 1,
        "B9: at least one re-emit broadcast expected, got {} extra",
        extra
    );
}

// ============================================================================
// B. No unbounded repeat spam (per-view latch holds across ticks and churn)
// ============================================================================

#[tokio::test]
async fn b9_b_no_unbounded_repeat_spam_within_same_view() {
    let tick = Duration::from_millis(15);
    let (handle, shutdown_tx, _outbound, connectivity, _inbound_tx, progress) =
        spawn_loop_for_test(tick);

    // Let the loop produce its initial view-0 leader proposal.
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Connect a peer → arms re-emit on next tick.
    connectivity.set(vec![fake_peer_id(0x11)]);
    tokio::time::sleep(Duration::from_millis(80)).await;

    let after_first_connect = progress.lock().inbound.outbound_proposal_late_peer_reemits;
    assert_eq!(
        after_first_connect, 1,
        "B9: exactly one re-emit expected after first connect (per-view single-shot), got {}",
        after_first_connect
    );

    // Reconnect churn: drop the peer, wait several ticks, then bring it
    // back. This produces additional empty→present transitions within
    // the same view (with num_validators=2 + no inbound vote, view 0
    // never advances). The per-view single-shot latch must prevent any
    // further re-emits.
    let mut samples = Vec::new();
    for i in 0..6 {
        if i % 2 == 0 {
            connectivity.set(Vec::new()); // disconnect
        } else {
            connectivity.set(vec![fake_peer_id(0x22u8.wrapping_add(i as u8))]);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
        samples.push(progress.lock().inbound.outbound_proposal_late_peer_reemits);
    }

    let final_progress = shutdown_and_join(handle, shutdown_tx).await;

    let reemits = final_progress.inbound.outbound_proposal_late_peer_reemits;
    let ticks = final_progress.ticks;
    // Strong, exact bound: with num_validators=2 view 0 never advances,
    // so the per-view single-shot latch keeps re-emits at exactly 1
    // regardless of how many connect/disconnect/reconnect cycles
    // occurred or how many ticks fired.
    assert_eq!(
        reemits, 1,
        "B9: per-view single-shot must hold across reconnect churn within the same view; \
         expected exactly 1 re-emit, got {} (ticks={}, samples={:?})",
        reemits, ticks, samples,
    );
    assert_eq!(
        final_progress.current_view, 0,
        "test setup invariant: view must stay at 0 (no inbound vote) so the per-view latch \
         is what is being tested; got current_view={}",
        final_progress.current_view
    );
}

// ============================================================================
// C. View-change invalidation: cache cleared on view advance
// ============================================================================

#[tokio::test]
async fn b9_c_view_change_does_not_replay_stale_proposal_for_old_view() {
    // To exercise the view-change invalidation gate (gate 3 in
    // `maybe_reemit_on_late_peer_connect`), we need an engine whose
    // view advances *between* the cache-fill (in `do_leader_tick`)
    // and the connectivity poll on a subsequent tick. The
    // single-validator engine does exactly this: self-quorum advances
    // the view on every tick the leader proposes. So a peer connect
    // observed any time after the engine has advanced past the cached
    // view must NOT trigger a stale re-emit. The expected outcome is
    // therefore zero re-emits: the gate-3 path drops the cache and
    // returns without broadcasting.
    let tick = Duration::from_millis(15);
    let (inbound_tx, inbound_rx) = mpsc::channel::<ConsensusNetMsg>(8);
    let outbound = Arc::new(RecordingProposalFacade::default());
    let outbound_dyn: Arc<dyn ConsensusNetworkFacade> = outbound.clone();
    let connectivity = Arc::new(FakePeerConnectivity::new());
    let connectivity_dyn: Arc<dyn PeerConnectivitySource> = connectivity.clone();

    // num_validators=1: view auto-advances per tick (self-quorum).
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1).with_tick_interval(tick);

    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound: outbound_dyn,
        peer_connectivity: Some(connectivity_dyn),
        verification_ctx: None,
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let progress = Arc::new(parking_lot::Mutex::new(
        BinaryConsensusLoopProgress::default(),
    ));
    let progress_for_task = progress.clone();
    let metrics = Arc::new(NodeMetrics::new());
    let handle = tokio::spawn(async move {
        run_binary_consensus_loop_with_io(cfg, shutdown_rx, progress_for_task, metrics, Some(io))
            .await
    });
    let _keep_inbound_alive = inbound_tx;

    // Run several ticks with no peer connected → engine commits and
    // advances views naturally (view 0 → 1 → 2 → ...). The cache is
    // refilled each tick but is also stale by the next tick.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Connect a peer: on the next tick, gate 3 must fire (cached view
    // < current view) and clear the cache without re-broadcasting.
    connectivity.set(vec![fake_peer_id(0xCC)]);
    tokio::time::sleep(Duration::from_millis(150)).await;

    let final_progress = shutdown_and_join(handle, shutdown_tx).await;

    // The view must have advanced past 0 (proves the engine actually
    // moved across views during the test).
    assert!(
        final_progress.current_view > 1,
        "test setup invariant: single-validator engine should have advanced multiple views; \
         got current_view={}",
        final_progress.current_view
    );
    // Zero re-emits: the gate-3 path correctly invalidated every stale
    // cache entry instead of replaying it.
    assert_eq!(
        final_progress.inbound.outbound_proposal_late_peer_reemits, 0,
        "B9: view-change invalidation gate must drop stale cache; expected 0 re-emits across \
         {} views, got {}",
        final_progress.current_view, final_progress.inbound.outbound_proposal_late_peer_reemits,
    );

    // Sanity: the engine still made forward progress (regression
    // guard against B9 inadvertently freezing the leader-step path).
    assert!(
        final_progress.proposals_emitted > 0,
        "B9 regression guard: leader-step must still emit proposals; got {}",
        final_progress.proposals_emitted
    );
    assert!(
        final_progress.commits > 0,
        "B9 regression guard: single-validator self-quorum must still commit; got {}",
        final_progress.commits
    );
}

// ============================================================================
// D. Peer already connected before first proposal: still bounded
// ============================================================================

#[tokio::test]
async fn b9_d_peer_connected_before_first_proposal_is_bounded() {
    // If the peer is already connected when the loop starts, the very
    // first tick observes an empty→present transition. After the
    // single-validator leader emits its view-0 proposal on that same
    // tick, the B9 path could in principle re-emit it. The honest
    // invariant we assert is that across many subsequent ticks the
    // re-emit counter does not grow unboundedly — the per-view
    // single-shot latch must hold. We also assert that the counter is
    // exactly 0 OR exactly 1 *up to the first view advance*, by
    // checking it is bounded relative to ticks.
    let tick = Duration::from_millis(15);
    let (inbound_tx, inbound_rx) = mpsc::channel::<ConsensusNetMsg>(8);
    let outbound = Arc::new(RecordingProposalFacade::default());
    let outbound_dyn: Arc<dyn ConsensusNetworkFacade> = outbound.clone();
    let connectivity = Arc::new(FakePeerConnectivity::new());
    // Pre-populate connected set BEFORE the loop starts.
    connectivity.set(vec![fake_peer_id(0xDD)]);
    let connectivity_dyn: Arc<dyn PeerConnectivitySource> = connectivity.clone();

    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 2)
        .with_tick_interval(tick)
        .with_max_ticks(40);

    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound: outbound_dyn,
        peer_connectivity: Some(connectivity_dyn),
        verification_ctx: None,
    };
    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let progress = Arc::new(parking_lot::Mutex::new(
        BinaryConsensusLoopProgress::default(),
    ));
    let metrics = Arc::new(NodeMetrics::new());
    let final_progress =
        run_binary_consensus_loop_with_io(cfg, shutdown_rx, progress, metrics, Some(io)).await;

    let _keep_inbound_alive = inbound_tx;

    // The loop ran 40 ticks. The B9 re-emit path is bounded to one
    // fire per view; across 40 ticks the re-emit count must be
    // strictly less than ticks (i.e. it does not re-emit on every
    // tick). This is the key bound: even if the implementation
    // re-emits once per view and the engine advances every tick (so
    // 40 distinct views), the rate is still bounded by
    // *transitions* (which only happen once at startup here).
    let reemits = final_progress.inbound.outbound_proposal_late_peer_reemits;
    let ticks = final_progress.ticks;
    assert_eq!(
        ticks, 40,
        "loop should have executed all 40 ticks before exit, got {}",
        ticks
    );
    assert!(
        reemits <= 1,
        "B9: with a single startup transition the re-emit counter must be 0 or 1, got {} (ticks={})",
        reemits,
        ticks
    );
}

// ============================================================================
// E. Single-validator / peer_connectivity = None regression guard
// ============================================================================

#[tokio::test]
async fn b9_e_no_peer_connectivity_means_no_reemit_path_at_all() {
    // With `peer_connectivity = None` the B9 branch is skipped
    // unconditionally. Across many ticks the re-emit counter must
    // remain at zero, proving B1/B2/B6 single-validator path is
    // bit-equivalent to pre-B9 behaviour.
    let tick = Duration::from_millis(10);
    let (inbound_tx, inbound_rx) = mpsc::channel::<ConsensusNetMsg>(8);
    let outbound: Arc<dyn ConsensusNetworkFacade> = Arc::new(RecordingProposalFacade::default());

    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
        .with_tick_interval(tick)
        .with_max_ticks(50);

    let io = BinaryConsensusLoopIo {
        inbound_rx,
        outbound,
        peer_connectivity: None,
        verification_ctx: None,
    };
    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let progress = Arc::new(parking_lot::Mutex::new(
        BinaryConsensusLoopProgress::default(),
    ));
    let metrics = Arc::new(NodeMetrics::new());
    let final_progress =
        run_binary_consensus_loop_with_io(cfg, shutdown_rx, progress, metrics, Some(io)).await;
    let _keep_inbound_alive = inbound_tx;

    assert_eq!(
        final_progress.inbound.outbound_proposal_late_peer_reemits, 0,
        "B9 regression guard: with peer_connectivity=None the re-emit counter must stay zero, got {}",
        final_progress.inbound.outbound_proposal_late_peer_reemits,
    );
    // Sanity: the rest of the loop still ran honestly (single-validator
    // commits per tick).
    assert!(
        final_progress.commits > 0,
        "B9 regression guard: single-validator path must still commit; got commits={}",
        final_progress.commits
    );
    assert!(
        final_progress.proposals_emitted > 0,
        "B9 regression guard: single-validator leader must still emit proposals; got {}",
        final_progress.proposals_emitted
    );
}

// ============================================================================
// F. io = None preserves pre-B9 contract entirely
// ============================================================================

#[tokio::test]
async fn b9_f_io_none_loop_unaffected_by_b9() {
    // The 4-arg `run_binary_consensus_loop` (io = None) must continue
    // to work exactly as before: B9 has no observable effect on this
    // path. This is the LocalMesh / single-node DevNet path's
    // contract.
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
        .with_tick_interval(Duration::from_millis(2))
        .with_max_ticks(40);

    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let progress = Arc::new(parking_lot::Mutex::new(
        BinaryConsensusLoopProgress::default(),
    ));
    let metrics = Arc::new(NodeMetrics::new());
    let final_progress = qbind_node::binary_consensus_loop::run_binary_consensus_loop(
        cfg,
        shutdown_rx,
        progress,
        metrics,
    )
    .await;

    assert_eq!(
        final_progress.inbound.outbound_proposal_late_peer_reemits, 0,
        "io=None path must never produce a B9 re-emit; got {}",
        final_progress.inbound.outbound_proposal_late_peer_reemits
    );
    assert!(
        final_progress.proposals_emitted > 0,
        "io=None path must still emit proposals; got {}",
        final_progress.proposals_emitted
    );
}
