//! Minimal binary-path consensus loop (B1).
//!
//! Wires the existing `BasicHotStuffEngine` from `qbind-consensus` into the
//! `qbind-node` binary path so that running `qbind-node` no longer terminates
//! at "transport built, idle"; instead the binary actually drives consensus
//! and advances views/commits blocks.
//!
//! # Scope
//!
//! This module is deliberately minimal. It is the smallest honest integration
//! that turns the binary into a node that:
//!
//! - Initializes a real consensus engine (`BasicHotStuffEngine`) with a
//!   validator set that includes the local validator id.
//! - Drives the engine on a tokio interval (the leader step proposes,
//!   self-votes, and — in the single-validator case — forms a QC and
//!   advances the view, committing blocks).
//! - Exits cleanly on shutdown.
//!
//! It does **not** introduce a parallel consensus architecture: it reuses the
//! same `BasicHotStuffEngine::on_leader_step` / `on_proposal_event` /
//! `on_vote_event` entry points that the test harnesses
//! (`NodeHotstuffHarness`, `t132`/`t138`/`localmesh_integration_tests`, …)
//! already exercise.
//!
//! # Single-validator behaviour
//!
//! In single-validator mode (`num_validators = 1`, the DevNet default when
//! `--validator-id` is supplied without static peers) the local validator is
//! always leader. `on_leader_step` proposes a block, self-votes, and the
//! single self-vote is a 1/1 = 100% quorum. The engine advances views and
//! commits blocks every tick interval. This is the same behaviour exercised
//! by the existing single-node consensus tests in
//! `crates/qbind-node/tests/localmesh_integration_tests.rs`.
//!
//! # Multi-validator behaviour
//!
//! For multi-validator setups the local validator only proposes when it is
//! leader for the current view; it cannot self-form a QC alone. Producing
//! commits in that case requires real inter-node message flow; that wiring
//! (P2P → consensus engine event ingestion) is tracked in the audit and is
//! intentionally out of scope for this module. We still drive the engine
//! tick (proposing when leader, advancing views via timeouts) so the binary
//! path is honest about *what it can do* without silently pretending to make
//! commits it cannot make.

//! # Live `/metrics` integration (DevNet Run 002 enabler)
//!
//! The loop also accepts a shared [`Arc<NodeMetrics>`] and updates the
//! existing consensus-related metric families in lock-step with real engine
//! events. No new metric families are introduced; we deliberately reuse:
//!
//! - `runtime().inc_events_tick()` — incremented once per executed tick.
//! - `consensus_t154().inc_proposal_accepted()` — incremented per
//!   `ConsensusEngineAction::BroadcastProposal` emitted on a tick. In
//!   single-validator mode the local engine is also the acceptor of its own
//!   proposal (it self-votes and the proposal is consumed by the QC path),
//!   so "accepted" is honest here. We do not invent a separate
//!   "proposals_emitted" counter.
//! - `commit().record_commit(tick_elapsed)` — once per *new* committed entry
//!   observed in `commit_log()` after a tick. `tick_elapsed` is the wall
//!   time spent driving the engine in that tick (best available proxy for a
//!   single-validator commit's "duration"; not a network round-trip).
//! - `consensus_t154().set_view_number(view)`,
//!   `view_lag().set_current_view(view)`,
//!   `view_lag().update_highest_seen_view(view)` — current view gauges.
//! - `progress().inc_view_changes()` — once per actual view advance.
//!
//! Counters are only updated from observed engine state mutations on real
//! ticks. When the loop is not running, no metric is touched. This keeps
//! `/metrics` honest: zeros mean "the binary path is not running"; non-zero
//! means "the binary path is actually progressing".
//!
//! Note: this is an observability integration only. It does **not** wire
//! P2P inbound consensus messages (which would justify
//! `consensus_t154.inc_vote_accepted()` etc.) and it does **not** speak to
//! restore-from-snapshot (B3). Both remain out of scope.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use qbind_consensus::basic_hotstuff_engine::{
    BasicHotStuffEngine, RestoreCatchupBlock as EngineRestoreCatchupBlock,
};
use qbind_consensus::driver::ConsensusEngineAction;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_wire::consensus::{BlockProposal, Vote};

use crate::consensus_network_facade::ConsensusNetworkFacade;
use crate::metrics::NodeMetrics;
use crate::p2p::{
    ConsensusNetMsg, NodeId, P2pService, RestoreCatchupBlock, RestoreCatchupRequest,
    RestoreCatchupResponse,
};

/// Adapter that exposes `Arc<NodeMetrics>` as a
/// `qbind_consensus::ConsensusProgressRecorder`.
///
/// `NodeMetrics::progress()` returns a borrowed `&ConsensusProgressMetrics`
/// (which already implements `ConsensusProgressRecorder`), but the engine
/// requires `Arc<dyn ConsensusProgressRecorder>` ownership — `&` cannot
/// be stored. Rather than restructure `NodeMetrics`, we hand the engine
/// a tiny adapter that holds an `Arc<NodeMetrics>` and forwards each
/// recorder method to the inner `ConsensusProgressMetrics` impl. This
/// keeps the change strictly additive (no public-API changes to
/// `NodeMetrics`) and ensures every recorder callback the engine fires
/// is observed by the same `/metrics`-backing counters the rest of the
/// binary already exposes.
#[derive(Debug)]
struct NodeMetricsProgressRecorder {
    metrics: Arc<NodeMetrics>,
}

impl NodeMetricsProgressRecorder {
    fn new(metrics: Arc<NodeMetrics>) -> Self {
        Self { metrics }
    }
}

impl qbind_consensus::ConsensusProgressRecorder for NodeMetricsProgressRecorder {
    fn record_qc_formed(&self) {
        self.metrics.progress().record_qc_formed();
    }

    fn record_qc_formed_with_latency(&self, latency: Duration) {
        self.metrics.progress().record_qc_formed_with_latency(latency);
    }

    fn record_vote_observed(&self, is_for_current_view: bool) {
        self.metrics.progress().record_vote_observed(is_for_current_view);
    }

    fn record_view_change(&self, from_view: u64, to_view: u64) {
        self.metrics.progress().record_view_change(from_view, to_view);
    }

    fn record_leader_change(&self) {
        self.metrics.progress().record_leader_change();
    }

    fn reset_current_view_votes(&self) {
        self.metrics.progress().reset_current_view_votes();
    }
}

/// Read-only view of "which deterministic peer NodeIds are currently
/// connected" — the smallest visibility surface the binary-path consensus
/// loop needs to detect a *late peer connect* transition (B9).
///
/// In the real `qbind-node` binary this is implemented by
/// [`P2pServicePeerConnectivity`], which simply forwards to the same
/// `Arc<dyn P2pService>` that backs the outbound `P2pConsensusNetwork`
/// (so connectivity, outbound, and inbound are all observed from the same
/// transport instance — no parallel networking architecture). Tests can
/// substitute a tiny in-memory implementation that flips the connected
/// set on demand without standing up real KEMTLS.
///
/// # Why a separate trait?
///
/// `P2pService` is a much larger surface (broadcast / send_to / inbound
/// subscribe / shutdown). The consensus loop only needs `connected_peers()`
/// to detect late connect transitions; widening the trait would make
/// regression tests harder to write and would couple the loop to send
/// semantics it does not need. Keeping a tiny dedicated trait is the
/// smallest honest abstraction.
pub trait PeerConnectivitySource: Send + Sync {
    /// Snapshot of currently connected peer NodeIds.
    ///
    /// Implementations must be cheap to call on a tick; the binary loop
    /// polls this once per tick (default 100 ms).
    fn connected_peers(&self) -> Vec<NodeId>;
}

/// `PeerConnectivitySource` adapter over an `Arc<dyn P2pService>`.
///
/// This is the production-path implementation used by `run_p2p_node` in
/// `main.rs`. It forwards `connected_peers()` to the underlying
/// `P2pService` so that the consensus loop observes connectivity from
/// exactly the same transport instance the inbound demuxer and outbound
/// `P2pConsensusNetwork` use.
pub struct P2pServicePeerConnectivity {
    inner: Arc<dyn P2pService>,
}

impl P2pServicePeerConnectivity {
    pub fn new(inner: Arc<dyn P2pService>) -> Self {
        Self { inner }
    }
}

impl PeerConnectivitySource for P2pServicePeerConnectivity {
    fn connected_peers(&self) -> Vec<NodeId> {
        self.inner.connected_peers()
    }
}


///
/// Matches `AsyncNodeRunner` defaults (100 ms). Long enough to keep CPU low
/// for an idle node; short enough that single-validator commits visibly
/// advance during smoke tests.
pub const DEFAULT_BINARY_CONSENSUS_TICK_INTERVAL: Duration = Duration::from_millis(100);

const RESTORE_CATCHUP_REQUEST_EVERY_TICKS: u64 = 10;
const RESTORE_CATCHUP_MAX_BLOCKS_PER_RESPONSE: usize = 128;

/// Configuration for the binary consensus loop.
#[derive(Debug, Clone)]
pub struct BinaryConsensusLoopConfig {
    /// Local validator id.
    pub local_validator_id: ValidatorId,
    /// Total number of validators in the set (≥ 1). Validators are
    /// enumerated 0..num_validators with equal voting power.
    pub num_validators: u64,
    /// Tick interval for `on_leader_step` calls.
    pub tick_interval: Duration,
    /// Optional cap on number of ticks (primarily for tests). `None` runs
    /// until shutdown.
    pub max_ticks: Option<u64>,
    /// Optional restore-aware consensus baseline (B5).
    ///
    /// When `Some`, the engine is initialized from this snapshot baseline
    /// before the first tick fires: `committed_height` is seeded to the
    /// snapshot height, the snapshot anchor block is inserted into the
    /// block tree, and `current_view = snapshot_height + 1`. Subsequent
    /// commits then advance above the restored height rather than
    /// effectively from zero.
    ///
    /// When `None`, startup behavior is unchanged (engine begins at
    /// view 0 with no committed prefix).
    pub restore_baseline: Option<RestoreBaseline>,
}

/// Restore-aware consensus baseline derived from a successful snapshot
/// restore (B5).
///
/// Built by `qbind-node`'s binary `main.rs` from the
/// `snapshot_restore::RestoreOutcome` returned by
/// `apply_snapshot_restore_if_requested`. Carries only metadata that the
/// existing `StateSnapshotMeta` actually exposes — we do not invent
/// unsupported snapshot semantics here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreBaseline {
    /// Height of the restored snapshot (from `StateSnapshotMeta::height`).
    pub snapshot_height: u64,
    /// Snapshot anchor block id (from `StateSnapshotMeta::block_hash`).
    /// Used as an opaque parent identifier when seeding the block tree;
    /// no claim is made that this matches any pre-snapshot consensus
    /// block id.
    pub snapshot_block_id: [u8; 32],
}

impl BinaryConsensusLoopConfig {
    /// Build a config with sensible defaults from a validator id and validator count.
    pub fn new(local_validator_id: ValidatorId, num_validators: u64) -> Self {
        Self {
            local_validator_id,
            num_validators: num_validators.max(1),
            tick_interval: DEFAULT_BINARY_CONSENSUS_TICK_INTERVAL,
            max_ticks: None,
            restore_baseline: None,
        }
    }

    /// Override the tick interval.
    pub fn with_tick_interval(mut self, d: Duration) -> Self {
        self.tick_interval = d;
        self
    }

    /// Cap the number of ticks (testing).
    pub fn with_max_ticks(mut self, n: u64) -> Self {
        self.max_ticks = Some(n);
        self
    }

    /// Apply a restore-aware consensus baseline (B5).
    ///
    /// See [`RestoreBaseline`] and the loop body in
    /// [`run_binary_consensus_loop`] for the semantics.
    pub fn with_restore_baseline(mut self, baseline: RestoreBaseline) -> Self {
        self.restore_baseline = Some(baseline);
        self
    }
}

/// Snapshot of consensus loop progress, used by tests and operators to
/// confirm the binary path is actually moving.
#[derive(Debug, Clone, Default)]
pub struct BinaryConsensusLoopProgress {
    /// Number of ticks executed.
    pub ticks: u64,
    /// Number of proposals emitted by the local validator.
    pub proposals_emitted: u64,
    /// Number of self-vote QC commits observed (single-validator mode).
    pub commits: u64,
    /// Highest committed height observed (if any).
    pub committed_height: Option<u64>,
    /// Current view.
    pub current_view: u64,
    /// Inbound P2P → engine routing stats (C4/B6). Always present; zero
    /// when the loop runs without I/O wiring (single-validator / LocalMesh).
    pub inbound: BinaryConsensusLoopInboundStats,
}

/// Build a `ConsensusValidatorSet` containing `num_validators` validators
/// with equal voting power. Validator ids are 0..num_validators.
fn build_uniform_validator_set(num_validators: u64) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = (0..num_validators)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId::new(i),
            voting_power: 1,
        })
        .collect();
    ConsensusValidatorSet::new(entries)
        .expect("uniform validator set with unique ids is always valid")
}

/// I/O surface for the multi-validator binary-path consensus loop (C4/B6).
///
/// When supplied, the loop:
///
/// - consumes inbound `ConsensusNetMsg` events (decoded P2P consensus
///   frames, as forwarded by [`crate::p2p_inbound::ChannelConsensusHandler`])
///   and feeds them into the running [`BasicHotStuffEngine`] via the same
///   `on_proposal_event` / `on_vote_event` / `on_timeout_msg` entry points
///   that the existing test harnesses already exercise;
/// - publishes the engine's resulting [`ConsensusEngineAction`]s back out
///   through an existing [`ConsensusNetworkFacade`] (typically the real
///   `P2pConsensusNetwork`) — never via a parallel networking layer.
///
/// When `None` (the default), the loop runs single-validator-only behaviour
/// exactly as before. This keeps the LocalMesh / single-node DevNet path
/// unchanged.
pub struct BinaryConsensusLoopIo {
    /// Inbound consensus messages received from the P2P transport.
    ///
    /// The node binary builds this end via
    /// [`crate::p2p_inbound::ChannelConsensusHandler`], which is registered
    /// with `P2pNodeBuilder.with_consensus_handler(...)`. The demuxer
    /// forwards every `P2pMessage::Consensus(_)` frame into this channel.
    pub inbound_rx: mpsc::Receiver<ConsensusNetMsg>,

    /// Outbound consensus network surface used to send the engine's
    /// `ConsensusEngineAction`s back over the wire.
    ///
    /// In the binary this is the real `P2pConsensusNetwork` (which wraps
    /// the same `TcpKemTlsP2pService` the inbound side reads from). Tests
    /// can substitute any `ConsensusNetworkFacade` implementation
    /// (including a recording facade) without rewiring transport.
    pub outbound: Arc<dyn ConsensusNetworkFacade>,

    /// Optional connected-peers visibility source (B9).
    ///
    /// When `Some`, the loop observes connected-peer transitions on every
    /// tick and, if the local node is still leader of the same view that
    /// already emitted a `BroadcastProposal`, re-emits that proposal
    /// **exactly once** through `outbound` so a peer that was not yet
    /// connected at the time of the original emission can still receive
    /// it. This closes the negative finding of DevNet Evidence Run 007.
    ///
    /// When `None`, the loop's behaviour is bit-equivalent to the pre-B9
    /// path: there is no late-peer-connect re-emission. The single
    /// validator / LocalMesh path supplies `None` here.
    ///
    /// Boundedness rules (enforced inside the loop):
    /// - re-emission triggers only on a *transition* from "not in
    ///   connected set" to "in connected set" for at least one peer;
    /// - re-emission requires the engine to still be leader of the
    ///   same view that produced the cached proposal;
    /// - re-emission requires no commit / view change to have invalidated
    ///   the cached proposal (the cache is cleared on view advance);
    /// - re-emission fires at most **once per view** regardless of how
    ///   many peers connect or how many ticks pass.
    pub peer_connectivity: Option<Arc<dyn PeerConnectivitySource>>,
}

impl std::fmt::Debug for BinaryConsensusLoopIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryConsensusLoopIo")
            .field("inbound_rx", &"<mpsc::Receiver<ConsensusNetMsg>>")
            .field("outbound", &"<Arc<dyn ConsensusNetworkFacade>>")
            .field(
                "peer_connectivity",
                &if self.peer_connectivity.is_some() {
                    "<Arc<dyn PeerConnectivitySource>>"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

/// Counters describing what the C4/B6 inbound→engine path actually did,
/// independent of single-validator self-quorum activity. Useful for tests
/// that need to prove "inbound P2P bytes really did affect engine state".
#[derive(Debug, Clone, Copy, Default)]
pub struct BinaryConsensusLoopInboundStats {
    /// `ConsensusNetMsg` frames received from the inbound channel.
    pub inbound_msgs_received: u64,
    /// Inbound `Proposal` frames that decoded successfully and were
    /// delivered to `engine.on_proposal_event`.
    pub inbound_proposals_delivered: u64,
    /// Inbound `Vote` frames that decoded successfully and were delivered
    /// to `engine.on_vote_event`.
    pub inbound_votes_delivered: u64,
    /// Inbound frames whose wire decode failed.
    pub inbound_decode_failures: u64,
    /// Inbound votes the engine rejected (e.g. wrong epoch, no block).
    pub inbound_vote_engine_rejects: u64,
    /// Outbound `BroadcastProposal` actions emitted to the facade.
    pub outbound_proposals_sent: u64,
    /// Outbound `BroadcastVote` actions emitted to the facade.
    pub outbound_votes_sent: u64,
    /// Outbound `SendVoteTo` actions emitted to the facade.
    pub outbound_send_vote_to: u64,
    /// Outbound `BroadcastProposal` actions re-emitted by the binary
    /// consensus loop in response to a *late peer connect* transition
    /// for the current view (B9).
    ///
    /// Bounded: incremented at most once per view (see
    /// [`BinaryConsensusLoopIo::peer_connectivity`] for the exact
    /// boundedness rules). Tests assert this counter is `0` when no late
    /// connect occurs and exactly `1` after a single late connect, even
    /// across many subsequent ticks / reconnect churn within the same
    /// view.
    pub outbound_proposal_late_peer_reemits: u64,
    /// Outbound `BroadcastVote` actions re-emitted by the binary
    /// consensus loop alongside a B9 proposal re-emission, so that a
    /// peer that connected after the leader's first emission of the
    /// current view can also receive the leader's same-view vote and
    /// reach the 2/3 quorum threshold (B10).
    ///
    /// Shares the exact same per-view single-shot latch as
    /// [`Self::outbound_proposal_late_peer_reemits`]: incremented at
    /// most once per view, only when the cached leader vote exists and
    /// matches the current view. With no cached vote (e.g., view 0 is
    /// only the proposal-no-leader-vote shape) this counter stays at 0.
    pub outbound_vote_late_peer_reemits: u64,
    /// Inbound `Proposal` frames the engine actually accepted (i.e.,
    /// produced a vote action in response). Strictly `<=
    /// inbound_proposals_delivered`. (B10 observability.)
    pub inbound_proposals_engine_accepted: u64,
    /// Inbound `Vote` frames the engine actually accepted (i.e.,
    /// `on_vote_event` returned `Ok(_)`). Strictly `<=
    /// inbound_votes_delivered`. (B10 observability.)
    pub inbound_votes_engine_accepted: u64,
    /// Quorum certificates the binary loop observed forming inside the
    /// engine since startup. Mirrors `qbind_consensus_qcs_formed_total`
    /// and is derived from the same `ConsensusProgressRecorder` callback
    /// the engine already drives. (B10 observability.)
    pub qcs_formed_total: u64,
    /// Restore-catchup requests broadcast by a restored binary-path node.
    pub restore_catchup_requests_sent: u64,
    /// Restore-catchup requests received from peers.
    pub restore_catchup_requests_received: u64,
    /// Restore-catchup responses sent to peers.
    pub restore_catchup_responses_sent: u64,
    /// Restore-catchup responses received from peers.
    pub restore_catchup_responses_received: u64,
    /// Peer-learned catchup blocks accepted and applied.
    pub restore_catchup_blocks_applied: u64,
    /// Malformed or inconsistent catchup responses rejected fail-closed.
    pub restore_catchup_responses_rejected: u64,
    /// Future proposals deferred while a restored node is behind its peers.
    pub restore_catchup_proposals_deferred: u64,
    /// Whether the restored node is still in bounded restore-catchup mode
    /// (`1`) or has transitioned out into normal participation (`0`).
    ///
    /// For nodes that did **not** start with a `RestoreBaseline`, this is
    /// always `0` — they were never in restore-catchup mode at all.
    ///
    /// For restored nodes, this starts at `1` (bounded restore-catchup
    /// mode is active: the loop is allowed to broadcast
    /// `RestoreCatchupRequest` frames every
    /// `RESTORE_CATCHUP_REQUEST_EVERY_TICKS` ticks and to defer inbound
    /// proposals more than one height above the local committed anchor)
    /// and flips to `0` exactly once when the explicit transition
    /// condition in `RestoreCatchupModeState::maybe_exit_after_response`
    /// is met. After that flip, request broadcasts and proposal deferral
    /// stop and the node participates as a normal binary-path validator.
    pub restore_catchup_mode_active: u64,
    /// The local `committed_height` at the moment the restored node
    /// transitioned out of bounded restore-catchup mode, or `0` if no
    /// transition has occurred yet (either because the node was never
    /// restoring or because it has not yet caught up to the safe-exit
    /// condition). This is observability only — set exactly once on the
    /// transition tick — and never decreases.
    pub restore_catchup_mode_exited_at_height: u64,
}

/// Transition state for the bounded "restore-catchup mode → normal
/// participation" boundary on the binary path.
///
/// # Why this exists
///
/// Before this struct, the binary loop keyed restore-catchup behaviour
/// (request broadcasts and inbound-proposal deferral) permanently off
/// `cfg.restore_baseline.is_some()`. That value is immutable for the
/// lifetime of the loop, so a node that successfully completed catchup
/// remained "permanently restoring" — it kept emitting
/// `RestoreCatchupRequest` frames every 10 ticks and kept deferring any
/// inbound proposal whose height was more than one above its committed
/// anchor. DevNet Evidence Run 012 documented the resulting plateau
/// (V1B reaches `committed_height=339` then never resumes participation;
/// see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_012.md`).
///
/// # Transition condition (explicit and bounded)
///
/// Mode flips from `active=true` to `active=false` exactly once, on the
/// first inbound `RestoreCatchupResponse` tick where ALL of the
/// following hold:
///
/// 1. The response was either applied successfully (added ≥ 0 blocks)
///    or rejected with no state change. We never flip on a malformed /
///    inconsistent response — fail-closed (the engine state is already
///    unchanged in that case).
/// 2. `engine.committed_height() >= max_observed_responder_committed`
///    — the local node has caught up to (or above) the highest
///    committed height any peer has ever reported in a response.
/// 3. `engine.committed_height() > snapshot_baseline_height` — at
///    least one block above the restored snapshot prefix has actually
///    committed (so we never declare "caught up" while we have made no
///    progress at all above the snapshot).
///
/// The transition is single-shot. Once `active=false`, this struct is
/// never re-armed for the lifetime of the loop. The catchup machinery
/// is not torn down — the inbound handler continues to validate any
/// stragglers fail-closed — but the node stops emitting fresh requests
/// and stops deferring proposals. New post-exit progression is then
/// driven by the same `BasicHotStuffEngine::on_proposal_event` /
/// `on_vote_event` paths the non-restore binary path already uses.
#[derive(Debug, Clone, Copy)]
struct RestoreCatchupModeState {
    /// `true` while the node is in bounded restore-catchup mode.
    active: bool,
    /// The snapshot baseline height the loop was started above, used to
    /// require strict progress above the restored prefix before we
    /// declare catchup complete. `None` when no baseline was applied
    /// (in which case `active` is also `false` from the start).
    snapshot_baseline_height: Option<u64>,
    /// The maximum `responder_committed_height` ever observed in an
    /// inbound `RestoreCatchupResponse`. Updated on every received
    /// response (including responses that carry zero blocks). Used as
    /// the catch-up target.
    peer_max_observed_committed_height: Option<u64>,
    /// The local `committed_height` at the moment of the active→false
    /// flip, or `None` if no flip has occurred. Observability only.
    exited_at_height: Option<u64>,
}

impl RestoreCatchupModeState {
    /// Initialize from the loop config. Mode is active iff a snapshot
    /// baseline was applied.
    fn from_config(restore_baseline: Option<RestoreBaseline>) -> Self {
        Self {
            active: restore_baseline.is_some(),
            snapshot_baseline_height: restore_baseline.map(|b| b.snapshot_height),
            peer_max_observed_committed_height: None,
            exited_at_height: None,
        }
    }

    /// Whether the loop should still be broadcasting catchup requests
    /// and deferring far-future inbound proposals.
    fn is_active(&self) -> bool {
        self.active
    }

    /// Update peer-anchor tracking on receipt of an inbound response and
    /// evaluate the transition condition. Returns `Some(new_height)` if
    /// the mode flipped from active to inactive on this call, otherwise
    /// `None`. Idempotent once `active=false`.
    fn maybe_exit_after_response(
        &mut self,
        responder_committed_height: Option<u64>,
        local_committed_height: Option<u64>,
    ) -> Option<u64> {
        if !self.active {
            return None;
        }
        if let Some(h) = responder_committed_height {
            self.peer_max_observed_committed_height = Some(
                self.peer_max_observed_committed_height
                    .map(|prev| prev.max(h))
                    .unwrap_or(h),
            );
        }
        // Transition gates:
        let local_height = match local_committed_height {
            Some(h) => h,
            None => return None,
        };
        let target = match self.peer_max_observed_committed_height {
            Some(h) => h,
            None => return None,
        };
        if local_height < target {
            return None;
        }
        // Require strict progress above the snapshot baseline. This
        // prevents flipping "caught up" purely on the restored prefix
        // when no peer-learned material has actually been applied.
        if let Some(base) = self.snapshot_baseline_height {
            if local_height <= base {
                return None;
            }
        }
        self.active = false;
        self.exited_at_height = Some(local_height);
        Some(local_height)
    }
}


///
/// Used directly by tests; the binary's `tokio::main` calls
/// `spawn_binary_consensus_loop` which delegates here.
///
/// The loop:
/// 1. Builds a `BasicHotStuffEngine` with a uniform validator set.
/// 2. On each tick, calls `try_propose()`. When the local validator is
///    leader and the validator set has size 1, this advances a view and
///    produces a commit per tick (single-validator devnet smoke).
/// 3. Records progress in `progress`.
///
/// Returns the final `BinaryConsensusLoopProgress`.
pub async fn run_binary_consensus_loop(
    cfg: BinaryConsensusLoopConfig,
    shutdown_rx: watch::Receiver<()>,
    progress: Arc<parking_lot::Mutex<BinaryConsensusLoopProgress>>,
    metrics: Arc<NodeMetrics>,
) -> BinaryConsensusLoopProgress {
    // Single-validator / LocalMesh path: no inbound P2P → engine wiring,
    // no outbound facade. Equivalent to the pre-C4/B6 behaviour.
    run_binary_consensus_loop_with_io(cfg, shutdown_rx, progress, metrics, None).await
}

/// Run the binary-path consensus loop with an optional inbound→engine /
/// engine→outbound I/O surface (C4/B6).
///
/// When `io` is `Some`, every inbound `ConsensusNetMsg` received on
/// `io.inbound_rx` is decoded and routed into the running engine via the
/// real `on_proposal_event` / `on_vote_event` / `on_timeout_msg` entry
/// points; engine-emitted `ConsensusEngineAction`s (from both inbound
/// processing and the leader-step tick) are forwarded out through
/// `io.outbound`. This is the smallest honest binary-path interconnect
/// that lets multi-node `qbind-node` processes feed real consensus
/// messages into each other's engines without `NodeHotstuffHarness`
/// scaffolding.
///
/// When `io` is `None`, behaviour is identical to the pre-C4/B6 loop:
/// the engine is driven only by leader-step ticks. This is the path
/// the LocalMesh and single-validator DevNet runs continue to use.
pub async fn run_binary_consensus_loop_with_io(
    cfg: BinaryConsensusLoopConfig,
    mut shutdown_rx: watch::Receiver<()>,
    progress: Arc<parking_lot::Mutex<BinaryConsensusLoopProgress>>,
    metrics: Arc<NodeMetrics>,
    io: Option<BinaryConsensusLoopIo>,
) -> BinaryConsensusLoopProgress {
    let validators = build_uniform_validator_set(cfg.num_validators);
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(cfg.local_validator_id, validators);

    // ----------------------------------------------------------------------
    // B10: wire the existing `ConsensusProgressRecorder` adapter into the
    // engine.
    //
    // `NodeMetrics::progress()` already implements
    // `qbind_consensus::ConsensusProgressRecorder` (see
    // `metrics::ConsensusProgressMetrics`). Before B10 the binary-path
    // loop never installed any progress recorder on its engine, so even
    // when the engine genuinely formed a QC and advanced its view (as
    // V0 actually did in Run 008), the `qbind_consensus_qcs_formed_total`
    // counter on `/metrics` stayed at 0. That is a metric-coverage gap,
    // not a fabrication: the engine's existing `record_qc_formed` /
    // `record_qc_formed_with_latency` callbacks fire only on actually
    // formed QCs. Wiring them here makes `/metrics` honestly reflect
    // engine progress without changing any consensus logic.
    let progress_recorder: Arc<dyn qbind_consensus::ConsensusProgressRecorder> =
        Arc::new(NodeMetricsProgressRecorder::new(Arc::clone(&metrics)));
    engine.set_progress_recorder(progress_recorder);

    // ----------------------------------------------------------------------
    // B5: restore-aware consensus start.
    // ----------------------------------------------------------------------
    if let Some(baseline) = cfg.restore_baseline {
        engine.initialize_from_snapshot_baseline(
            baseline.snapshot_block_id,
            baseline.snapshot_height,
        );
        eprintln!(
            "[binary-consensus] B5: applied restore baseline: snapshot_height={} \
             starting_view={} (engine committed_height={:?})",
            baseline.snapshot_height,
            engine.current_view(),
            engine.committed_height(),
        );
    }

    let (mut inbound_rx, outbound_facade, peer_connectivity): (
        Option<mpsc::Receiver<ConsensusNetMsg>>,
        Option<Arc<dyn ConsensusNetworkFacade>>,
        Option<Arc<dyn PeerConnectivitySource>>,
    ) = match io {
        Some(io) => (Some(io.inbound_rx), Some(io.outbound), io.peer_connectivity),
        None => (None, None, None),
    };

    eprintln!(
        "[binary-consensus] Starting consensus loop: local_id={:?} num_validators={} tick={}ms \
         restore_baseline={} interconnect={} late_peer_reemit={}",
        cfg.local_validator_id,
        cfg.num_validators,
        cfg.tick_interval.as_millis(),
        cfg.restore_baseline.is_some(),
        if outbound_facade.is_some() { "p2p" } else { "none" },
        if peer_connectivity.is_some() { "on" } else { "off" },
    );

    let mut ticker = tokio::time::interval(cfg.tick_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut ticks: u64 = 0;
    let mut proposals_emitted: u64 = 0;
    let mut last_commits: u64 = 0;
    let mut last_view: u64 = engine.current_view();
    let mut inbound_stats = BinaryConsensusLoopInboundStats::default();

    // ----------------------------------------------------------------------
    // B9 + B10: late-peer-connect proposal/vote re-emission state.
    //
    // - `last_leader_proposal`: the most recent `BroadcastProposal` the
    //   local engine emitted on a leader-step tick, paired with the view
    //   it was emitted for. Refilled by `do_leader_tick` whenever a new
    //   leader-step proposal is produced. Used as the source of bytes for
    //   a possible re-emission.
    // - `last_leader_vote` (B10): the leader's *own* `BroadcastVote`
    //   produced by the same leader-step tick that produced the cached
    //   proposal. The engine's `on_leader_step` always emits a
    //   `BroadcastProposal` immediately followed by a `BroadcastVote`
    //   for the leader's self-vote on its own proposal (see
    //   `BasicHotStuffEngine::on_leader_step`). Without this cache,
    //   B9's late-peer re-emit would replay only the proposal — the
    //   late-connecting peer would still be missing the leader's vote
    //   for that view and would never reach the 2/3 quorum. This
    //   matches Run 008's observed boundary exactly: the proposal
    //   crossed, the peer voted, the leader formed a QC, but the peer
    //   stayed at view 0 because it never saw the leader's vote.
    // - `reemitted_for_view`: the (single) view we have already
    //   re-emitted for, if any. Acts as the per-view "fired" latch that
    //   prevents unbounded rebroadcast loops on reconnect churn. The
    //   latch covers BOTH the proposal and the vote re-emit; we never
    //   re-emit just one of them on a separate tick.
    // - `last_known_peers`: snapshot of the connected NodeId set on the
    //   previous tick. Used to detect a *transition* from not-connected
    //   to connected for at least one peer; only such a transition can
    //   arm re-emission. This means simply observing a steady connected
    //   set tick after tick produces no re-emits.
    //
    // All four are local to this loop and are not visible elsewhere; the
    // only externally observable effects are
    // `outbound_proposal_late_peer_reemits` and
    // `outbound_vote_late_peer_reemits` in `BinaryConsensusLoopInboundStats`.
    // ----------------------------------------------------------------------
    let mut last_leader_proposal: Option<(u64, BlockProposal)> = None;
    let mut last_leader_vote: Option<(u64, Vote)> = None;
    let mut reemitted_for_view: Option<u64> = None;
    let mut last_known_peers: HashSet<NodeId> = HashSet::new();

    // Bounded restore-catchup mode state. Active iff a snapshot baseline
    // was applied; flips to inactive exactly once per loop lifetime when
    // the explicit safe-exit condition is met (see
    // `RestoreCatchupModeState`).
    let mut restore_mode = RestoreCatchupModeState::from_config(cfg.restore_baseline);
    // Reflect the initial active state on /metrics so operators see
    // `qbind_restore_catchup_mode_active=1` from startup of a restored
    // node, not only after the first response is processed.
    inbound_stats.restore_catchup_mode_active = if restore_mode.is_active() { 1 } else { 0 };
    update_restore_catchup_metrics(&metrics, &inbound_stats);

    loop {
        // We always select on shutdown + ticker. When inbound I/O is wired
        // we additionally select on inbound_rx so an inbound proposal/vote
        // can wake the loop and drive engine state immediately, instead of
        // waiting for the next tick. This is what makes the binary path
        // reactive to peers rather than "transport up, engine isolated".
        if let Some(rx) = inbound_rx.as_mut() {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    eprintln!(
                        "[binary-consensus] Shutdown signal received after {} ticks.",
                        ticks
                    );
                    break;
                }
                maybe_msg = rx.recv() => {
                    match maybe_msg {
                        Some(msg) => {
                            handle_inbound_consensus_msg(
                                &mut engine,
                                msg,
                                &mut inbound_stats,
                                outbound_facade.as_deref(),
                                &metrics,
                                cfg.local_validator_id,
                                &mut restore_mode,
                            );
                            // Reflect engine state changes (view / commits)
                            // immediately so /metrics never stalls behind
                            // inbound progress.
                            update_state_metrics(
                                &engine,
                                &metrics,
                                &mut last_commits,
                                &mut last_view,
                                Duration::ZERO,
                            );
                            update_restore_catchup_metrics(&metrics, &inbound_stats);
                            // Refresh progress snapshot.
                            {
                                inbound_stats.qcs_formed_total =
                                    metrics.progress().qcs_formed_total();
                                let mut p = progress.lock();
                                p.commits = engine.commit_log().len() as u64;
                                p.committed_height = engine.committed_height();
                                p.current_view = engine.current_view();
                                p.inbound = inbound_stats;
                            }
                        }
                        None => {
                            // Inbound channel closed: stop reacting to
                            // inbound events but keep ticking so the loop
                            // can still shut down cleanly. We drop the
                            // receiver to fall through to the no-io branch
                            // on subsequent iterations.
                            inbound_rx = None;
                        }
                    }
                }
                _ = ticker.tick() => {
                    ticks = ticks.saturating_add(1);
                    let tick_started = Instant::now();
                    do_leader_tick(
                        &mut engine,
                        &mut proposals_emitted,
                        &metrics,
                        &mut inbound_stats,
                        outbound_facade.as_deref(),
                        &mut last_leader_proposal,
                        &mut last_leader_vote,
                    );
                    // B9 + B10: poll for a late-peer-connect transition
                    // and, if armed, re-emit the cached current-view
                    // proposal AND the cached current-view leader vote
                    // exactly once. Only runs when peer_connectivity is
                    // wired (multi-validator P2P binary path); single
                    // validator / LocalMesh paths skip this entirely.
                    if let Some(pc) = peer_connectivity.as_deref() {
                        maybe_reemit_on_late_peer_connect(
                            &engine,
                            &mut last_leader_proposal,
                            &mut last_leader_vote,
                            &mut reemitted_for_view,
                            &mut last_known_peers,
                            pc,
                            outbound_facade.as_deref(),
                            &mut inbound_stats,
                        );
                    }
                    maybe_broadcast_restore_catchup_request(
                        &engine,
                        ticks,
                        cfg.local_validator_id,
                        restore_mode.is_active(),
                        outbound_facade.as_deref(),
                        &mut inbound_stats,
                    );
                    update_state_metrics(
                        &engine,
                        &metrics,
                        &mut last_commits,
                        &mut last_view,
                        tick_started.elapsed(),
                    );
                    update_restore_catchup_metrics(&metrics, &inbound_stats);
                    {
                        inbound_stats.qcs_formed_total =
                            metrics.progress().qcs_formed_total();
                        let mut p = progress.lock();
                        p.ticks = ticks;
                        p.proposals_emitted = proposals_emitted;
                        p.commits = engine.commit_log().len() as u64;
                        p.committed_height = engine.committed_height();
                        p.current_view = engine.current_view();
                        p.inbound = inbound_stats;
                    }
                    if let Some(cap) = cfg.max_ticks {
                        if ticks >= cap {
                            eprintln!(
                                "[binary-consensus] Reached max_ticks={}, stopping.",
                                cap
                            );
                            break;
                        }
                    }
                }
            }
        } else {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    eprintln!(
                        "[binary-consensus] Shutdown signal received after {} ticks.",
                        ticks
                    );
                    break;
                }
                _ = ticker.tick() => {
                    ticks = ticks.saturating_add(1);
                    let tick_started = Instant::now();
                    do_leader_tick(
                        &mut engine,
                        &mut proposals_emitted,
                        &metrics,
                        &mut inbound_stats,
                        outbound_facade.as_deref(),
                        &mut last_leader_proposal,
                        &mut last_leader_vote,
                    );
                    if let Some(pc) = peer_connectivity.as_deref() {
                        maybe_reemit_on_late_peer_connect(
                            &engine,
                            &mut last_leader_proposal,
                            &mut last_leader_vote,
                            &mut reemitted_for_view,
                            &mut last_known_peers,
                            pc,
                            outbound_facade.as_deref(),
                            &mut inbound_stats,
                        );
                    }
                    maybe_broadcast_restore_catchup_request(
                        &engine,
                        ticks,
                        cfg.local_validator_id,
                        restore_mode.is_active(),
                        outbound_facade.as_deref(),
                        &mut inbound_stats,
                    );
                    update_state_metrics(
                        &engine,
                        &metrics,
                        &mut last_commits,
                        &mut last_view,
                        tick_started.elapsed(),
                    );
                    update_restore_catchup_metrics(&metrics, &inbound_stats);
                    {
                        inbound_stats.qcs_formed_total =
                            metrics.progress().qcs_formed_total();
                        let mut p = progress.lock();
                        p.ticks = ticks;
                        p.proposals_emitted = proposals_emitted;
                        p.commits = engine.commit_log().len() as u64;
                        p.committed_height = engine.committed_height();
                        p.current_view = engine.current_view();
                        p.inbound = inbound_stats;
                    }
                    if let Some(cap) = cfg.max_ticks {
                        if ticks >= cap {
                            eprintln!(
                                "[binary-consensus] Reached max_ticks={}, stopping.",
                                cap
                            );
                            break;
                        }
                    }
                }
            }
        }
    }

    let final_progress = progress.lock().clone();
    eprintln!(
        "[binary-consensus] Loop exit: ticks={} proposals={} commits={} committed_height={:?} \
         view={} inbound_msgs={} inbound_proposals={} inbound_votes={} \
         outbound_proposals={} outbound_votes={} outbound_proposal_late_peer_reemits={}",
        final_progress.ticks,
        final_progress.proposals_emitted,
        final_progress.commits,
        final_progress.committed_height,
        final_progress.current_view,
        final_progress.inbound.inbound_msgs_received,
        final_progress.inbound.inbound_proposals_delivered,
        final_progress.inbound.inbound_votes_delivered,
        final_progress.inbound.outbound_proposals_sent,
        final_progress.inbound.outbound_votes_sent,
        final_progress.inbound.outbound_proposal_late_peer_reemits,
    );
    final_progress
}

/// Drive a single leader-step tick of the engine and forward any resulting
/// network actions through the (optional) outbound facade.
///
/// **B9 cache update**: when a `BroadcastProposal` is emitted, the
/// `(view, BlockProposal)` pair is recorded in `last_leader_proposal`
/// before forwarding. This is the only writer of that cache. The view
/// captured is the engine's `current_view()` at the moment of emission,
/// which is also the view the proposal carries (the engine sets
/// `proposed_in_view` and produces the action atomically).
///
/// **B10 cache update**: when the same leader-step tick also emits the
/// leader's own `BroadcastVote` (which `BasicHotStuffEngine::on_leader_step`
/// always does immediately after the proposal — that is the leader's
/// self-vote on its own proposal), the `(view, Vote)` pair is recorded in
/// `last_leader_vote`. The view captured is the same `view_at_step` used
/// for the proposal, which by construction matches `vote.height` because
/// the engine builds the vote with `height = current_view`. Without this
/// cache, the B9 late-peer-connect re-emit would replay only the proposal
/// — the late-connecting peer would still be missing the leader's vote
/// for that view and would never reach the 2/3 quorum threshold.
fn do_leader_tick(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    proposals_emitted: &mut u64,
    metrics: &Arc<NodeMetrics>,
    inbound_stats: &mut BinaryConsensusLoopInboundStats,
    outbound: Option<&dyn ConsensusNetworkFacade>,
    last_leader_proposal: &mut Option<(u64, BlockProposal)>,
    last_leader_vote: &mut Option<(u64, Vote)>,
) {
    let view_at_step = engine.current_view();
    let actions = engine.try_propose();
    let mut tick_proposals: u64 = 0;
    let mut emitted_proposal_in_this_tick = false;
    for action in &actions {
        match action {
            ConsensusEngineAction::BroadcastProposal(p) => {
                *proposals_emitted = proposals_emitted.saturating_add(1);
                tick_proposals = tick_proposals.saturating_add(1);
                // B9: cache the proposal + its view so a later late-peer
                // connect can re-emit it once. We always overwrite — the
                // engine only ever produces one proposal per view, and view
                // change naturally invalidates the previous cache entry via
                // the `cur_view != proposal_view` gate in the re-emit check.
                *last_leader_proposal = Some((view_at_step, (**p).clone()));
                emitted_proposal_in_this_tick = true;
                // B9 + B10: a fresh leader-step proposal supersedes any
                // previous cache. Drop the prior cached vote so we never
                // pair a stale view's vote with a new proposal.
                *last_leader_vote = None;
            }
            ConsensusEngineAction::BroadcastVote(v) => {
                // B10: only cache the leader's self-vote produced *as
                // part of the same leader-step tick that just emitted a
                // proposal*. `BasicHotStuffEngine::on_leader_step`
                // always emits these as a paired pair, in this order:
                // proposal first, then leader vote. We rely on that
                // ordering here — the `emitted_proposal_in_this_tick`
                // flag is `true` if and only if a `BroadcastProposal`
                // appeared earlier in the same `actions` vector. If
                // the engine's leader-step ever changes to emit the
                // vote before (or without) the proposal, this branch
                // simply does not cache, the B10 vote re-emit
                // counter stays at 0, and the `outbound_vote_late_peer_reemits
                // <= outbound_proposal_late_peer_reemits` invariant
                // (asserted in `b10_d_late_peer_reconnect_churn_stays_single_shot`)
                // continues to hold — i.e. this is fail-safe under
                // any future ordering change. We also defensively
                // require `v.height == view_at_step` so a vote with
                // a height that doesn't match the current view (which
                // would not be valid for late-peer re-emission
                // anyway) is never cached.
                if emitted_proposal_in_this_tick && v.height == view_at_step {
                    *last_leader_vote = Some((view_at_step, v.clone()));
                }
            }
            ConsensusEngineAction::SendVoteTo { .. } | ConsensusEngineAction::Noop => {}
        }
    }
    metrics.runtime().inc_events_tick();
    for _ in 0..tick_proposals {
        metrics.consensus_t154().inc_proposal_accepted();
    }
    if let Some(facade) = outbound {
        forward_actions_to_facade(actions, facade, inbound_stats);
    }
}

/// B9 + B10: late-peer-connect proposal/vote re-emission.
///
/// Called once per tick when the binary loop has been wired with both an
/// outbound `ConsensusNetworkFacade` *and* a `PeerConnectivitySource`.
/// All gating below is intentional and bounded:
///
/// 1. **Transition required.** Re-emission only fires when the connected
///    peer set on this tick contains at least one NodeId that was not in
///    the set on the previous tick. A steady-state set tick after tick
///    produces no re-emits.
/// 2. **Cached proposal required.** The local engine must have actually
///    emitted a `BroadcastProposal` for some view (refilled in
///    `do_leader_tick`); otherwise there is nothing to re-emit and we
///    return without touching the facade.
/// 3. **View match.** The cached proposal's view must equal the engine's
///    current view. A view change since the original emission
///    invalidates the cached proposal — the loop drops the stale entry
///    and waits for the new view's leader-step to refill it.
/// 4. **Leader of current view.** Only the leader of the current view
///    re-emits its own proposal. A node that is not leader never
///    re-broadcasts another node's proposal here.
/// 5. **Commit not invalidated.** If the engine has committed at or
///    beyond the cached proposal's view, the proposal is logically
///    obsolete and is not re-emitted.
/// 6. **Per-view single-shot.** The `reemitted_for_view` latch ensures
///    that, even if peers connect and disconnect repeatedly within the
///    same view, the loop re-emits at most once for that view. This is
///    the single bound that prevents reconnect-churn rebroadcast spam.
///    The latch covers BOTH the proposal and the leader vote re-emit;
///    we never re-emit just one of them on a separate tick.
///
/// **B10 vote re-emit (paired):** If the cache also contains a
/// `last_leader_vote` for the same view as the cached proposal, the
/// loop re-broadcasts that leader vote on the same tick the proposal is
/// re-emitted. This is the smallest honest fix for the Run-008 boundary:
/// without it, a late-connecting peer can receive the proposal, vote on
/// it, and have its vote reach the leader (so the leader forms a QC and
/// advances), but the peer itself can never reach 2/3 because it never
/// saw the leader's own same-view vote — leaving the peer stuck at the
/// proposal's view and stalling the round-robin once the leader advances
/// past it. Vote re-emission is gated on the same view-match /
/// commit-invalidated / per-view single-shot rules as the proposal; if
/// no cached vote exists (e.g., a future engine variant that emits the
/// proposal without a leader self-vote), only the proposal is re-emitted
/// and the vote-reemit counter stays at 0.
///
/// On a successful re-emit, the loop increments
/// `inbound_stats.outbound_proposal_late_peer_reemits` (and, if a vote
/// was re-emitted too, `inbound_stats.outbound_vote_late_peer_reemits`)
/// and logs the event. On any failure (facade error, gates not met) the
/// loop is silent in the failure case but logs the facade error for ops
/// visibility.
fn maybe_reemit_on_late_peer_connect(
    engine: &BasicHotStuffEngine<[u8; 32]>,
    last_leader_proposal: &mut Option<(u64, BlockProposal)>,
    last_leader_vote: &mut Option<(u64, Vote)>,
    reemitted_for_view: &mut Option<u64>,
    last_known_peers: &mut HashSet<NodeId>,
    peer_connectivity: &dyn PeerConnectivitySource,
    facade: Option<&dyn ConsensusNetworkFacade>,
    stats: &mut BinaryConsensusLoopInboundStats,
) {
    // Always refresh the connected snapshot so reconnect churn within
    // the same view does not reset our notion of "newly connected" on
    // subsequent ticks.
    let current: HashSet<NodeId> = peer_connectivity.connected_peers().into_iter().collect();
    let newly_connected_count =
        current.iter().filter(|n| !last_known_peers.contains(*n)).count();
    *last_known_peers = current;

    // Gate 1: transition required.
    if newly_connected_count == 0 {
        return;
    }

    // Gate 2: cached proposal required.
    let cached_view = match last_leader_proposal {
        Some((v, _)) => *v,
        None => return,
    };

    let cur_view = engine.current_view();

    // Gate 3: view match — view advanced ⇒ cache invalid, drop it.
    if cur_view != cached_view {
        *last_leader_proposal = None;
        *last_leader_vote = None;
        return;
    }

    // Gate 4: leader of current view.
    if !engine.is_leader_for_current_view() {
        return;
    }

    // Gate 5: commit not invalidated.
    if let Some(h) = engine.committed_height() {
        if h >= cached_view {
            return;
        }
    }

    // Gate 6: per-view single-shot.
    if *reemitted_for_view == Some(cached_view) {
        return;
    }

    // Gate 7: outbound facade required to actually send anything.
    let facade = match facade {
        Some(f) => f,
        None => return,
    };

    // Re-borrow the cached proposal for sending. Safe by gate 2.
    let proposal = match last_leader_proposal {
        Some((_, p)) => p,
        None => return,
    };

    if let Err(e) = facade.broadcast_proposal(proposal) {
        eprintln!(
            "[binary-consensus] B9: late-peer reemit broadcast_proposal failed (view={}): {:?}",
            cached_view, e,
        );
        return;
    }

    *reemitted_for_view = Some(cached_view);
    stats.outbound_proposal_late_peer_reemits =
        stats.outbound_proposal_late_peer_reemits.saturating_add(1);

    // B10: paired vote re-emit. Only re-emit the leader vote if its
    // cached view matches the cached proposal's view. If no cached vote
    // exists, leave the vote-reemit counter alone — this is the
    // strictest "no fabricated metrics" semantics.
    let mut vote_reemitted = false;
    if let Some((vote_view, vote)) = last_leader_vote.as_ref() {
        if *vote_view == cached_view {
            if let Err(e) = facade.broadcast_vote(vote) {
                eprintln!(
                    "[binary-consensus] B10: late-peer reemit broadcast_vote failed (view={}): {:?}",
                    cached_view, e,
                );
            } else {
                stats.outbound_vote_late_peer_reemits =
                    stats.outbound_vote_late_peer_reemits.saturating_add(1);
                vote_reemitted = true;
            }
        }
    }

    eprintln!(
        "[binary-consensus] B9+B10: re-emitted view {} BroadcastProposal{} after late peer connect \
         (newly_connected_peers={}, proposal_reemits_total={}, vote_reemits_total={})",
        cached_view,
        if vote_reemitted { " + BroadcastVote" } else { "" },
        newly_connected_count,
        stats.outbound_proposal_late_peer_reemits,
        stats.outbound_vote_late_peer_reemits,
    );
}

/// Forward a list of `ConsensusEngineAction`s through a
/// [`ConsensusNetworkFacade`]. Errors are logged but do not stop the loop;
/// per-action delivery is best-effort and the engine itself remains the
/// source of truth for protocol progress.
fn forward_actions_to_facade(
    actions: Vec<ConsensusEngineAction<ValidatorId>>,
    facade: &dyn ConsensusNetworkFacade,
    inbound_stats: &mut BinaryConsensusLoopInboundStats,
) {
    for action in actions {
        match action {
            ConsensusEngineAction::BroadcastProposal(proposal) => {
                if let Err(e) = facade.broadcast_proposal(&proposal) {
                    eprintln!(
                        "[binary-consensus] outbound broadcast_proposal failed: {:?}",
                        e
                    );
                } else {
                    inbound_stats.outbound_proposals_sent =
                        inbound_stats.outbound_proposals_sent.saturating_add(1);
                }
            }
            ConsensusEngineAction::BroadcastVote(vote) => {
                if let Err(e) = facade.broadcast_vote(&vote) {
                    eprintln!(
                        "[binary-consensus] outbound broadcast_vote failed: {:?}",
                        e
                    );
                } else {
                    inbound_stats.outbound_votes_sent =
                        inbound_stats.outbound_votes_sent.saturating_add(1);
                }
            }
            ConsensusEngineAction::SendVoteTo { to, vote } => {
                if let Err(e) = facade.send_vote_to(to, &vote) {
                    eprintln!(
                        "[binary-consensus] outbound send_vote_to({:?}) failed: {:?}",
                        to, e
                    );
                } else {
                    inbound_stats.outbound_send_vote_to =
                        inbound_stats.outbound_send_vote_to.saturating_add(1);
                }
            }
            ConsensusEngineAction::Noop => {}
        }
    }
}

/// Decode an inbound `ConsensusNetMsg` and feed it into the engine through
/// the same `on_proposal_event` / `on_vote_event` entry points the existing
/// HotStuff harnesses already exercise. Resulting engine actions are
/// forwarded through `outbound` so the upstream node sees the response.
///
/// The wire-encoded `BlockProposal::header.proposer_index` and
/// `Vote::validator_index` carry the sender's `ValidatorId`. We do not
/// invent any peer-identity layer here: it is the same convention the
/// `qbind-wire` consensus types expose to the rest of the codebase.
///
/// Decode failures and engine-level rejections (e.g. wrong epoch) are
/// counted in `stats` but never panic — they are exactly the kinds of
/// peer-induced failures the binary path must tolerate.
fn handle_inbound_consensus_msg(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    msg: ConsensusNetMsg,
    stats: &mut BinaryConsensusLoopInboundStats,
    outbound: Option<&dyn ConsensusNetworkFacade>,
    metrics: &Arc<NodeMetrics>,
    local_validator_id: ValidatorId,
    restore_mode: &mut RestoreCatchupModeState,
) {
    use qbind_wire::consensus::{BlockProposal, Vote};
    use qbind_wire::io::WireDecode;

    stats.inbound_msgs_received = stats.inbound_msgs_received.saturating_add(1);

    // B11: count every inbound `ConsensusNetMsg` that arrives at the
    // binary path before any decode/accept gating, so the
    // `consensus_net_inbound_total{kind="..."}` Prometheus family
    // honestly reflects the same traffic the loop-level
    // `inbound_msgs_received` / `inbound_proposals_delivered` /
    // `inbound_votes_delivered` counters already observe. We count one
    // per inbound frame and never fabricate increments:
    //   - `Proposal(...)` → `inbound_total{kind="proposal"}`
    //   - `Vote(...)`     → `inbound_total{kind="vote"}`
    //   - `Timeout(...)` / `NewView(...)` → `inbound_total{kind="other"}`
    //     (these frames are received-but-unhandled on the binary path,
    //     see the match arms below; counting them under "other" is
    //     honest and avoids silently hiding the fact that real bytes
    //     arrived).
    // The matching outbound counters are incremented by the
    // `P2pConsensusNetwork` facade itself (see
    // `crates/qbind-node/src/consensus_net_p2p.rs`); the engine ↔
    // facade boundary in `forward_actions_to_facade` deliberately does
    // not count there to avoid double counting.
    match &msg {
        ConsensusNetMsg::Proposal(_) => metrics.network().inc_inbound_proposal(),
        ConsensusNetMsg::Vote(_) => metrics.network().inc_inbound_vote(),
        ConsensusNetMsg::Timeout(_)
        | ConsensusNetMsg::NewView(_)
        | ConsensusNetMsg::RestoreCatchupRequest(_)
        | ConsensusNetMsg::RestoreCatchupResponse(_) => {
            metrics.network().inc_inbound_other()
        }
    }

    match msg {
        ConsensusNetMsg::Proposal(bytes) => {
            let mut slice: &[u8] = &bytes;
            match BlockProposal::decode(&mut slice) {
                Ok(proposal) => {
                    if restore_mode.is_active()
                        && should_defer_restore_proposal_for_catchup(engine, &proposal)
                    {
                        stats.restore_catchup_proposals_deferred =
                            stats.restore_catchup_proposals_deferred.saturating_add(1);
                        eprintln!(
                            "[restore-catchup] deferred proposal at height={} while local committed_height={:?}",
                            proposal.header.height,
                            engine.committed_height(),
                        );
                        return;
                    }
                    let from = ValidatorId::new(proposal.header.proposer_index as u64);
                    stats.inbound_proposals_delivered =
                        stats.inbound_proposals_delivered.saturating_add(1);
                    if let Some(action) = engine.on_proposal_event(from, &proposal) {
                        // B10: an action returned from `on_proposal_event`
                        // means the engine performed the full accept path
                        // (epoch ok, view ok, leader ok, safe-to-vote ok)
                        // and produced a vote. Reflect that in both the
                        // loop's structured stats and the public
                        // `consensus_t154.proposals_accepted` counter on
                        // `/metrics`. Without this, the counter could
                        // never increment for inbound traffic on the
                        // multi-validator binary path.
                        stats.inbound_proposals_engine_accepted =
                            stats.inbound_proposals_engine_accepted.saturating_add(1);
                        metrics.consensus_t154().inc_proposal_accepted();
                        if let Some(facade) = outbound {
                            forward_actions_to_facade(vec![action], facade, stats);
                        }
                    }
                }
                Err(e) => {
                    stats.inbound_decode_failures =
                        stats.inbound_decode_failures.saturating_add(1);
                    eprintln!(
                        "[binary-consensus] inbound proposal decode failed: {:?}",
                        e
                    );
                }
            }
        }
        ConsensusNetMsg::Vote(bytes) => {
            let mut slice: &[u8] = &bytes;
            match Vote::decode(&mut slice) {
                Ok(vote) => {
                    let from = ValidatorId::new(vote.validator_index as u64);
                    match engine.on_vote_event(from, &vote) {
                        Ok(_) => {
                            stats.inbound_votes_delivered =
                                stats.inbound_votes_delivered.saturating_add(1);
                            // B10: same observability rationale as for
                            // proposals — `Ok(_)` from `on_vote_event`
                            // is the canonical "engine accepted this
                            // vote" signal (the `Ok(Some(qc))` branch
                            // additionally formed a QC, which the
                            // engine's progress recorder reports
                            // separately via `record_qc_formed`).
                            stats.inbound_votes_engine_accepted =
                                stats.inbound_votes_engine_accepted.saturating_add(1);
                            metrics.consensus_t154().inc_vote_accepted();
                        }
                        Err(e) => {
                            stats.inbound_vote_engine_rejects =
                                stats.inbound_vote_engine_rejects.saturating_add(1);
                            eprintln!(
                                "[binary-consensus] inbound vote rejected by engine: {:?}",
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    stats.inbound_decode_failures =
                        stats.inbound_decode_failures.saturating_add(1);
                    eprintln!("[binary-consensus] inbound vote decode failed: {:?}", e);
                }
            }
        }
        ConsensusNetMsg::Timeout(_bytes) => {
            // Timeout / view-change ingestion on the binary path is
            // intentionally deferred: the existing
            // `BasicHotStuffEngine::on_timeout_msg` API takes a typed
            // `TimeoutMsg`, but `ConsensusNetMsg::Timeout` carries opaque
            // bytes whose canonical decoder is not yet exposed by
            // `qbind-wire` for general-purpose deserialization. Counting it
            // as "received but unhandled" keeps the binary path honest:
            // we don't silently drop it as if it were a NoOp.
            stats.inbound_decode_failures =
                stats.inbound_decode_failures.saturating_add(1);
        }
        ConsensusNetMsg::NewView(_bytes) => {
            // NewView is reserved for a future view-change protocol
            // extension (see `ConsensusNetMsg::NewView` doc). The current
            // engine does not consume it; we record it as
            // received-but-not-routable rather than fake a Noop.
            stats.inbound_decode_failures =
                stats.inbound_decode_failures.saturating_add(1);
        }
        ConsensusNetMsg::RestoreCatchupRequest(req) => {
            stats.restore_catchup_requests_received =
                stats.restore_catchup_requests_received.saturating_add(1);
            handle_restore_catchup_request(engine, req, stats, outbound, local_validator_id);
        }
        ConsensusNetMsg::RestoreCatchupResponse(resp) => {
            stats.restore_catchup_responses_received =
                stats.restore_catchup_responses_received.saturating_add(1);
            handle_restore_catchup_response(engine, resp, stats, local_validator_id, restore_mode);
        }
    }
}

fn maybe_broadcast_restore_catchup_request(
    engine: &BasicHotStuffEngine<[u8; 32]>,
    ticks: u64,
    local_validator_id: ValidatorId,
    restore_catchup_enabled: bool,
    outbound: Option<&dyn ConsensusNetworkFacade>,
    stats: &mut BinaryConsensusLoopInboundStats,
) {
    if !restore_catchup_enabled || ticks % RESTORE_CATCHUP_REQUEST_EVERY_TICKS != 1 {
        return;
    }
    let (Some(from_height), Some(from_block_id), Some(facade)) = (
        engine.committed_height(),
        engine.committed_block().copied(),
        outbound,
    ) else {
        return;
    };
    let req = RestoreCatchupRequest {
        requester_validator_index: local_validator_id.0 as u16,
        from_height,
        from_block_id,
    };
    if let Err(e) = facade.broadcast_consensus_msg(&ConsensusNetMsg::RestoreCatchupRequest(req)) {
        eprintln!("[restore-catchup] request broadcast failed: {:?}", e);
        return;
    }
    stats.restore_catchup_requests_sent = stats.restore_catchup_requests_sent.saturating_add(1);
}

fn should_defer_restore_proposal_for_catchup(
    engine: &BasicHotStuffEngine<[u8; 32]>,
    proposal: &BlockProposal,
) -> bool {
    let Some(committed_height) = engine.committed_height() else {
        return false;
    };
    if proposal.header.height > committed_height.saturating_add(1) {
        return true;
    }
    if proposal.header.height == committed_height.saturating_add(1) {
        if let Some(committed_block) = engine.committed_block() {
            return proposal.header.parent_block_id != *committed_block;
        }
    }
    false
}

fn handle_restore_catchup_request(
    engine: &BasicHotStuffEngine<[u8; 32]>,
    req: RestoreCatchupRequest,
    stats: &mut BinaryConsensusLoopInboundStats,
    outbound: Option<&dyn ConsensusNetworkFacade>,
    local_validator_id: ValidatorId,
) {
    if req.requester_validator_index as u64 == local_validator_id.0 {
        return;
    }
    let Some(facade) = outbound else {
        return;
    };
    let blocks = engine.export_restore_catchup_blocks(
        req.from_height,
        req.from_block_id,
        RESTORE_CATCHUP_MAX_BLOCKS_PER_RESPONSE,
    );
    if blocks.is_empty() {
        return;
    }
    let resp = RestoreCatchupResponse {
        responder_validator_index: local_validator_id.0 as u16,
        request_from_height: req.from_height,
        request_from_block_id: req.from_block_id,
        responder_committed_height: engine.committed_height(),
        blocks: blocks
            .into_iter()
            .map(|b| RestoreCatchupBlock {
                height: b.height,
                view: b.view,
                parent_block_id: b.parent_block_id,
                block_id: b.block_id,
                proposer_index: b.proposer.0 as u16,
                qc_signer_indices: b.qc_signers.into_iter().map(|v| v.0 as u16).collect(),
            })
            .collect(),
    };
    if let Err(e) = facade.broadcast_consensus_msg(&ConsensusNetMsg::RestoreCatchupResponse(resp)) {
        eprintln!("[restore-catchup] response broadcast failed: {:?}", e);
        return;
    }
    stats.restore_catchup_responses_sent = stats.restore_catchup_responses_sent.saturating_add(1);
}

fn handle_restore_catchup_response(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    resp: RestoreCatchupResponse,
    stats: &mut BinaryConsensusLoopInboundStats,
    local_validator_id: ValidatorId,
    restore_mode: &mut RestoreCatchupModeState,
) {
    if resp.responder_validator_index as u64 == local_validator_id.0 {
        return;
    }
    // Capture the responder's reported committed-anchor height before any
    // early return so the transition tracker observes peer progress even
    // when this particular response carries no useful blocks (e.g. the
    // peer is at-or-below us). This is the key signal that lets the
    // restored node detect "I'm caught up" and exit restore-catchup mode.
    let responder_committed_height = resp.responder_committed_height;
    if resp.blocks.is_empty() {
        // Even on an empty response, evaluate the transition condition:
        // if the peer reports being at or below our committed height we
        // have nothing more to catch up to from this peer.
        evaluate_restore_mode_transition(
            engine,
            stats,
            restore_mode,
            responder_committed_height,
        );
        return;
    }
    if engine.committed_height() != Some(resp.request_from_height)
        || engine.committed_block().copied() != Some(resp.request_from_block_id)
    {
        stats.restore_catchup_responses_rejected =
            stats.restore_catchup_responses_rejected.saturating_add(1);
        eprintln!(
            "[restore-catchup] rejected stale/mismatched response anchor: response_height={} local_height={:?}",
            resp.request_from_height,
            engine.committed_height()
        );
        // Stale-anchor rejection does not mutate engine state; do not
        // count this as progress towards transition. Re-evaluate the
        // transition condition only against the responder's reported
        // anchor (peer-progress observation), not against our local
        // unchanged height.
        evaluate_restore_mode_transition(
            engine,
            stats,
            restore_mode,
            responder_committed_height,
        );
        return;
    }

    let blocks: Vec<EngineRestoreCatchupBlock<[u8; 32]>> = resp
        .blocks
        .into_iter()
        .map(|b| EngineRestoreCatchupBlock {
            height: b.height,
            view: b.view,
            parent_block_id: b.parent_block_id,
            block_id: b.block_id,
            proposer: ValidatorId::new(b.proposer_index as u64),
            qc_signers: b
                .qc_signer_indices
                .into_iter()
                .map(|v| ValidatorId::new(v as u64))
                .collect(),
        })
        .collect();

    match engine.apply_restore_catchup_blocks(&blocks) {
        Ok(applied) => {
            stats.restore_catchup_blocks_applied = stats
                .restore_catchup_blocks_applied
                .saturating_add(applied as u64);
            eprintln!(
                "[restore-catchup] applied {} peer-learned certified blocks; committed_height={:?} view={}",
                applied,
                engine.committed_height(),
                engine.current_view()
            );
            // Successful application is the primary point at which the
            // local committed_height advances; evaluate the transition
            // condition now to flip mode at the earliest safe moment.
            evaluate_restore_mode_transition(
                engine,
                stats,
                restore_mode,
                responder_committed_height,
            );
        }
        Err(e) => {
            stats.restore_catchup_responses_rejected =
                stats.restore_catchup_responses_rejected.saturating_add(1);
            eprintln!("[restore-catchup] rejected response: {:?}", e);
            // Fail-closed: a rejected response did NOT mutate engine
            // state, so we treat it as if the response had not
            // happened. Specifically, we do NOT update the
            // peer-anchor tracker from a malformed payload (the
            // `responder_committed_height` field came from an
            // untrusted/inconsistent message and must not influence the
            // transition decision). Mode stays active.
        }
    }
}

/// Update peer-anchor tracking and, if the safe-exit condition is met,
/// flip restore-catchup mode from active to inactive exactly once. This
/// is a thin wrapper over [`RestoreCatchupModeState::maybe_exit_after_response`]
/// that also publishes the resulting state into `stats` so `/metrics`
/// observes the transition.
fn evaluate_restore_mode_transition(
    engine: &BasicHotStuffEngine<[u8; 32]>,
    stats: &mut BinaryConsensusLoopInboundStats,
    restore_mode: &mut RestoreCatchupModeState,
    responder_committed_height: Option<u64>,
) {
    let was_active = restore_mode.is_active();
    let exited_at = restore_mode
        .maybe_exit_after_response(responder_committed_height, engine.committed_height());
    // Always reflect the (possibly unchanged) active flag on the stats
    // surface so /metrics can publish a faithful gauge each tick.
    stats.restore_catchup_mode_active = if restore_mode.is_active() { 1 } else { 0 };
    if let Some(h) = exited_at {
        stats.restore_catchup_mode_exited_at_height = h;
        eprintln!(
            "[restore-catchup] exit: caught up to peer anchor — local committed_height={} peer_max_observed={:?}; \
             stopping further RestoreCatchupRequest broadcasts and proposal-deferral gating",
            h,
            restore_mode.peer_max_observed_committed_height,
        );
    } else if was_active && !restore_mode.is_active() {
        // Defensive: only `maybe_exit_after_response` flips the flag,
        // and it returns `Some` whenever it does. Reaching this branch
        // would mean an internal invariant was violated. Fail loudly in
        // debug/test builds so regressions are caught; in release the
        // node continues so production observability is not interrupted.
        debug_assert!(
            false,
            "[restore-catchup] mode flipped without exit height — internal invariant violation"
        );
        eprintln!(
            "[restore-catchup] WARN: mode flipped without exit height — internal invariant warning"
        );
    }
}

/// Refresh `/metrics` and progress-tracking variables based on the current
/// engine state. Called from both leader-step ticks and inbound-message
/// branches so /metrics reflects live progress regardless of which
/// codepath last advanced the engine.
fn update_state_metrics(
    engine: &BasicHotStuffEngine<[u8; 32]>,
    metrics: &Arc<NodeMetrics>,
    last_commits: &mut u64,
    last_view: &mut u64,
    tick_elapsed: Duration,
) {
    let new_commits_total = engine.commit_log().len() as u64;
    let new_view = engine.current_view();
    let commits_delta = new_commits_total.saturating_sub(*last_commits);
    for _ in 0..commits_delta {
        metrics.commit().record_commit(tick_elapsed);
    }
    let view_delta = new_view.saturating_sub(*last_view);
    for _ in 0..view_delta {
        metrics.progress().inc_view_changes();
    }
    metrics.consensus_t154().set_view_number(new_view);
    metrics.view_lag().set_current_view(new_view);
    metrics.view_lag().update_highest_seen_view(new_view);
    if let (Some(height), Some(block_id)) = (engine.committed_height(), engine.committed_block()) {
        metrics.committed_anchor().set_anchor(height, *block_id);
        if commits_delta > 0 {
            eprintln!(
                "[binary-consensus] committed_anchor height={} block_id={}",
                height,
                hex::encode(block_id)
            );
        }
    }
    *last_commits = new_commits_total;
    *last_view = new_view;
}

fn update_restore_catchup_metrics(
    metrics: &Arc<NodeMetrics>,
    stats: &BinaryConsensusLoopInboundStats,
) {
    metrics.restore_catchup().set(
        stats.restore_catchup_requests_sent,
        stats.restore_catchup_requests_received,
        stats.restore_catchup_responses_sent,
        stats.restore_catchup_responses_received,
        stats.restore_catchup_blocks_applied,
        stats.restore_catchup_responses_rejected,
        stats.restore_catchup_proposals_deferred,
        stats.restore_catchup_mode_active,
        stats.restore_catchup_mode_exited_at_height,
    );
}

/// Spawn `run_binary_consensus_loop` on the current tokio runtime. Returns a
/// `JoinHandle` and a shared `BinaryConsensusLoopProgress` the caller can
/// observe while the loop is running.
pub fn spawn_binary_consensus_loop(
    cfg: BinaryConsensusLoopConfig,
    shutdown_rx: watch::Receiver<()>,
    metrics: Arc<NodeMetrics>,
) -> (
    JoinHandle<BinaryConsensusLoopProgress>,
    Arc<parking_lot::Mutex<BinaryConsensusLoopProgress>>,
) {
    let progress = Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));
    let progress_for_task = progress.clone();
    let handle = tokio::spawn(async move {
        run_binary_consensus_loop(cfg, shutdown_rx, progress_for_task, metrics).await
    });
    (handle, progress)
}

/// Spawn the binary-path consensus loop with C4/B6 inbound→engine
/// interconnect wiring (multi-validator P2P).
///
/// This is the variant `qbind-node`'s P2P main path uses: it threads a
/// `ChannelConsensusHandler`-backed `mpsc::Receiver<ConsensusNetMsg>` plus
/// a `P2pConsensusNetwork` outbound facade into the loop, so inbound
/// proposals/votes from peers are decoded and fed into
/// `BasicHotStuffEngine::on_proposal_event` / `on_vote_event`, and the
/// engine's resulting actions are sent back out the existing P2P path.
pub fn spawn_binary_consensus_loop_with_io(
    cfg: BinaryConsensusLoopConfig,
    shutdown_rx: watch::Receiver<()>,
    metrics: Arc<NodeMetrics>,
    io: BinaryConsensusLoopIo,
) -> (
    JoinHandle<BinaryConsensusLoopProgress>,
    Arc<parking_lot::Mutex<BinaryConsensusLoopProgress>>,
) {
    let progress = Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));
    let progress_for_task = progress.clone();
    let handle = tokio::spawn(async move {
        run_binary_consensus_loop_with_io(
            cfg,
            shutdown_rx,
            progress_for_task,
            metrics,
            Some(io),
        )
        .await
    });
    (handle, progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn single_validator_loop_advances_views_and_commits() {
        let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
            .with_tick_interval(Duration::from_millis(2))
            .with_max_ticks(50);

        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let progress =
            Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));
        let metrics = Arc::new(NodeMetrics::new());
        let final_progress =
            run_binary_consensus_loop(cfg, shutdown_rx, progress.clone(), metrics).await;

        assert_eq!(final_progress.ticks, 50, "loop should run 50 ticks");
        assert!(
            final_progress.proposals_emitted > 0,
            "single-validator leader should emit at least one proposal, got {}",
            final_progress.proposals_emitted
        );
        assert!(
            final_progress.current_view > 0,
            "single-validator engine should advance past view 0, got view {}",
            final_progress.current_view
        );
    }

    #[tokio::test]
    async fn loop_stops_on_shutdown() {
        let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
            .with_tick_interval(Duration::from_millis(10));
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let progress =
            Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));
        let metrics = Arc::new(NodeMetrics::new());

        let handle = tokio::spawn({
            let progress = progress.clone();
            async move { run_binary_consensus_loop(cfg, shutdown_rx, progress, metrics).await }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        // Trigger shutdown.
        drop(shutdown_tx);

        // Should exit promptly.
        let final_progress = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("loop did not exit within 2s of shutdown")
            .expect("task panicked");

        assert!(final_progress.ticks > 0, "loop should have ticked at least once");
    }

    #[test]
    fn build_validator_set_works_for_n() {
        let vs = build_uniform_validator_set(4);
        assert_eq!(vs.len(), 4);
    }

    /// DevNet Run 002 enabler: prove `/metrics`-backing counters move when the
    /// binary-path consensus loop runs live, using only existing
    /// `NodeMetrics` families.
    #[tokio::test]
    async fn binary_path_metrics_move_during_live_loop() {
        let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
            .with_tick_interval(Duration::from_millis(2))
            .with_max_ticks(50);

        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let progress =
            Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));
        let metrics = Arc::new(NodeMetrics::new());

        // Sanity: pre-run all consensus-relevant counters/gauges are zero.
        assert_eq!(metrics.runtime().events_tick_total(), 0);
        assert_eq!(metrics.consensus_t154().proposals_accepted(), 0);
        assert_eq!(metrics.consensus_t154().view_number(), 0);
        assert_eq!(metrics.commit().commit_count(), 0);
        assert_eq!(metrics.view_lag().current_view(), 0);
        assert_eq!(metrics.view_lag().highest_seen_view(), 0);
        assert_eq!(metrics.progress().view_changes_total(), 0);

        let final_progress = run_binary_consensus_loop(
            cfg,
            shutdown_rx,
            progress.clone(),
            Arc::clone(&metrics),
        )
        .await;

        // Ticks must be reflected.
        assert_eq!(
            metrics.runtime().events_tick_total(),
            final_progress.ticks,
            "every executed tick must increment runtime events_tick_total"
        );

        // Proposals must be reflected (single-validator leader emits proposals).
        assert!(
            metrics.consensus_t154().proposals_accepted() > 0,
            "consensus_t154.proposals_accepted should track proposals emitted; got 0"
        );
        assert_eq!(
            metrics.consensus_t154().proposals_accepted(),
            final_progress.proposals_emitted,
            "proposals_accepted must equal proposals_emitted observed by the loop"
        );

        // Current view gauges must reflect engine view.
        assert_eq!(
            metrics.consensus_t154().view_number(),
            final_progress.current_view
        );
        assert_eq!(
            metrics.view_lag().current_view(),
            final_progress.current_view
        );
        assert!(
            metrics.view_lag().highest_seen_view() >= final_progress.current_view,
            "highest_seen_view must be monotonic and at least the current view"
        );

        // View advanced from 0 → there must be at least one view change.
        assert!(
            metrics.progress().view_changes_total() > 0,
            "progress.view_changes_total must be > 0 when current_view advanced"
        );

        // Single-validator self-quorum must produce commits, and commit
        // metrics must reflect them.
        assert!(
            final_progress.commits > 0,
            "single-validator self-quorum should commit at least once"
        );
        assert_eq!(
            metrics.commit().commit_count(),
            final_progress.commits,
            "commit().commit_count must equal commit_log length"
        );
    }

    /// No counters move when the loop is constructed but never executes.
    /// Guards against accidental "fake" updates on construction or shutdown.
    #[tokio::test]
    async fn binary_path_metrics_stay_zero_when_loop_never_ticks() {
        // Tick interval longer than the test wait so no tick fires before
        // shutdown.
        let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
            .with_tick_interval(Duration::from_secs(60));

        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let progress =
            Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));
        let metrics = Arc::new(NodeMetrics::new());

        let handle = {
            let metrics = Arc::clone(&metrics);
            tokio::spawn(async move {
                run_binary_consensus_loop(cfg, shutdown_rx, progress, metrics).await
            })
        };

        // The first `tokio::time::interval` tick fires immediately. To
        // guarantee "loop never executed a tick body", shut down before
        // yielding to the spawned task. `drop(shutdown_tx)` schedules the
        // shutdown branch, which must be selected before the next ticker
        // tick (which is 60s away).
        drop(shutdown_tx);
        let final_progress = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("loop did not exit on shutdown")
            .expect("task panicked");

        // If the immediate first tick raced ahead of shutdown, we have at
        // most that one tick; everything beyond it must still be zero. We
        // assert that no commits / view-changes / proposals were fabricated
        // on shutdown.
        assert!(
            final_progress.ticks <= 1,
            "expected at most the immediate first tick, got {}",
            final_progress.ticks
        );
        assert_eq!(
            metrics.runtime().events_tick_total(),
            final_progress.ticks,
            "tick metric must match observed ticks exactly (no fabrication)"
        );
        // After at most one tick at view 0, the engine has not advanced
        // views. No view-change increments should have occurred.
        if final_progress.current_view == 0 {
            assert_eq!(
                metrics.progress().view_changes_total(),
                0,
                "no view changes should be recorded when view did not advance"
            );
            assert_eq!(metrics.view_lag().current_view(), 0);
            assert_eq!(metrics.consensus_t154().view_number(), 0);
        }
    }

    // ========================================================================
    // B5: restore-aware consensus start (binary loop integration)
    // ========================================================================

    /// B5: With a `RestoreBaseline` configured, the binary consensus loop
    /// must start the engine from `view = snapshot_height + 1` and advance
    /// committed height *above* the snapshot height — not from zero. This
    /// is the loop-level proof for DevNet Evidence Run 004.
    #[tokio::test]
    async fn b5_restore_baseline_makes_committed_height_advance_above_snapshot() {
        const SNAPSHOT_HEIGHT: u64 = 250;
        let baseline = RestoreBaseline {
            snapshot_height: SNAPSHOT_HEIGHT,
            snapshot_block_id: [0xA5; 32],
        };

        let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
            .with_tick_interval(Duration::from_millis(1))
            .with_max_ticks(80)
            .with_restore_baseline(baseline);

        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let progress =
            Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));
        let metrics = Arc::new(NodeMetrics::new());
        let final_progress =
            run_binary_consensus_loop(cfg, shutdown_rx, progress.clone(), metrics).await;

        // The loop must have observed a committed height strictly above the
        // restored snapshot height — this is the post-restore progression
        // signal Run 004 will assert against.
        let committed_height = final_progress
            .committed_height
            .expect("expected at least one commit after baseline + 80 ticks");
        assert!(
            committed_height > SNAPSHOT_HEIGHT,
            "post-restore committed_height ({}) must advance above \
             snapshot_height ({}) — got the same height-floor we started from, \
             which would mean B5 did not actually seed the engine",
            committed_height,
            SNAPSHOT_HEIGHT
        );

        // Current view must also be above snapshot_height + 1 (i.e. the
        // engine has progressed at least one view past the seeded view).
        assert!(
            final_progress.current_view > SNAPSHOT_HEIGHT,
            "post-restore current_view ({}) must be above snapshot_height ({})",
            final_progress.current_view,
            SNAPSHOT_HEIGHT
        );
    }

    /// B5: Without a baseline, the loop continues to start from view 0 and
    /// the first commit's height is small (single-digit), proving the
    /// no-restore path is unchanged.
    #[tokio::test]
    async fn b5_no_baseline_loop_starts_from_zero() {
        let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
            .with_tick_interval(Duration::from_millis(1))
            .with_max_ticks(20);
        // Sanity: no baseline configured.
        assert!(cfg.restore_baseline.is_none());

        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let progress =
            Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));
        let metrics = Arc::new(NodeMetrics::new());
        let final_progress =
            run_binary_consensus_loop(cfg, shutdown_rx, progress, metrics).await;

        // 20 ticks at view 0 must keep the committed height firmly below
        // any plausible snapshot height. We use 100 as an order-of-magnitude
        // sentinel: the no-restore loop must not reach into "restored"
        // territory.
        if let Some(h) = final_progress.committed_height {
            assert!(
                h < 100,
                "no-restore loop committed_height ({}) climbed unexpectedly high — \
                 the no-restore startup path may have been regressed by B5",
                h
            );
        }
        // current_view must be at most max_ticks (each tick advances at most
        // once in single-validator self-quorum mode).
        assert!(final_progress.current_view <= 20);
    }

    /// B5: Pure builder behavior. `with_restore_baseline` is the only way to
    /// opt in; `BinaryConsensusLoopConfig::new` defaults to `None` so prior
    /// callers are not silently affected.
    #[test]
    fn b5_config_default_has_no_restore_baseline() {
        let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1);
        assert!(cfg.restore_baseline.is_none());

        let baseline = RestoreBaseline {
            snapshot_height: 7,
            snapshot_block_id: [1u8; 32],
        };
        let cfg2 = cfg.with_restore_baseline(baseline);
        assert_eq!(cfg2.restore_baseline, Some(baseline));
    }

    // ========================================================================
    // Post-catchup restore-mode transition (Run-012 boundary fix)
    //
    // The tests below exercise `RestoreCatchupModeState` and the
    // `evaluate_restore_mode_transition` / `handle_restore_catchup_response`
    // surfaces directly, without spinning up the full tokio loop. They
    // are deliberately small and high-signal: each one asserts a single
    // bounded property of the new transition state machine.
    // ========================================================================

    /// `RestoreCatchupModeState` is inactive when no baseline was applied.
    /// Non-restore binary path is unaffected.
    #[test]
    fn restore_mode_inactive_without_baseline() {
        let mut s = RestoreCatchupModeState::from_config(None);
        assert!(!s.is_active(), "no baseline ⇒ never in restore-catchup mode");
        // Even if a peer reports a higher anchor, with no baseline we are
        // not in catchup mode and never flip.
        let exited = s.maybe_exit_after_response(Some(10), Some(10));
        assert!(exited.is_none());
        assert!(!s.is_active());
    }

    /// `RestoreCatchupModeState` is active at startup when a baseline was
    /// applied; only the explicit safe-exit condition flips it.
    #[test]
    fn restore_mode_active_with_baseline_until_caught_up() {
        let baseline = RestoreBaseline {
            snapshot_height: 5,
            snapshot_block_id: [0xAA; 32],
        };
        let mut s = RestoreCatchupModeState::from_config(Some(baseline));
        assert!(s.is_active());

        // Peer at height 100 but local still at snapshot baseline ⇒ no exit.
        assert_eq!(s.maybe_exit_after_response(Some(100), Some(5)), None);
        assert!(s.is_active());

        // Local advances but still below peer ⇒ no exit.
        assert_eq!(s.maybe_exit_after_response(Some(100), Some(50)), None);
        assert!(s.is_active());

        // Local catches up to peer ⇒ exit, returns the catchup height.
        assert_eq!(s.maybe_exit_after_response(Some(100), Some(100)), Some(100));
        assert!(!s.is_active());

        // Subsequent responses are no-ops; the flip is single-shot.
        assert_eq!(s.maybe_exit_after_response(Some(200), Some(150)), None);
        assert!(!s.is_active());
    }

    /// Strict-progress gate: the mode must NOT exit if the local node has
    /// not advanced strictly above the snapshot baseline, even if the peer
    /// reports being at-or-below the baseline. This prevents a degenerate
    /// "I'm caught up" claim while no peer-learned suffix has actually
    /// committed.
    #[test]
    fn restore_mode_requires_progress_above_baseline() {
        let baseline = RestoreBaseline {
            snapshot_height: 5,
            snapshot_block_id: [0xAA; 32],
        };
        let mut s = RestoreCatchupModeState::from_config(Some(baseline));
        // Peer at 5, local at 5 — both equal to the baseline. We have
        // not made any strict progress above the baseline.
        assert_eq!(s.maybe_exit_after_response(Some(5), Some(5)), None);
        assert!(s.is_active(), "must not exit at exactly the baseline height");

        // Now we advance one block above the baseline AND peer is at-or-below.
        assert_eq!(s.maybe_exit_after_response(Some(5), Some(6)), Some(6));
        assert!(!s.is_active());
    }

    /// `peer_max_observed_committed_height` is the running maximum across
    /// all responses, so a temporarily slow/lagging peer does not lower the
    /// catchup target on a later response.
    #[test]
    fn restore_mode_tracks_peer_max_observed_height() {
        let baseline = RestoreBaseline {
            snapshot_height: 0,
            snapshot_block_id: [0xBB; 32],
        };
        let mut s = RestoreCatchupModeState::from_config(Some(baseline));
        // Peer A at 100.
        assert_eq!(s.maybe_exit_after_response(Some(100), Some(50)), None);
        // Peer B at 80 (lagging) — must not lower the max-observed target.
        assert_eq!(s.maybe_exit_after_response(Some(80), Some(80)), None);
        assert_eq!(s.peer_max_observed_committed_height, Some(100));
        // Local now at 100, matches the running max ⇒ exit.
        assert_eq!(s.maybe_exit_after_response(Some(80), Some(100)), Some(100));
        assert!(!s.is_active());
    }

    /// End-to-end (single function): `handle_restore_catchup_response`
    /// must NOT update peer-max from a malformed/rejected payload, so
    /// mode stays active (fail-closed). Also asserts the rejected counter
    /// increments and engine state is unchanged.
    #[test]
    fn restore_mode_stays_active_on_malformed_response() {
        use qbind_consensus::ValidatorId;

        let validators = build_uniform_validator_set(2);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId::new(1), validators);
        engine.initialize_from_snapshot_baseline([0x01; 32], 5);

        let baseline = RestoreBaseline {
            snapshot_height: 5,
            snapshot_block_id: [0x01; 32],
        };
        let mut mode = RestoreCatchupModeState::from_config(Some(baseline));
        let mut stats = BinaryConsensusLoopInboundStats::default();

        // Build a response whose blocks claim a wrong parent: applying it
        // must fail-closed, leaving engine state unchanged.
        let bad = RestoreCatchupBlock {
            height: 6,
            view: 6,
            parent_block_id: [0xFF; 32], // wrong: real parent is the snapshot anchor
            block_id: [0x06; 32],
            proposer_index: 0,
            qc_signer_indices: vec![0, 1],
        };
        let resp = RestoreCatchupResponse {
            responder_validator_index: 0,
            request_from_height: 5,
            request_from_block_id: [0x01; 32],
            responder_committed_height: Some(999),
            blocks: vec![bad],
        };

        handle_restore_catchup_response(
            &mut engine,
            resp,
            &mut stats,
            ValidatorId::new(1),
            &mut mode,
        );

        // Engine did not advance.
        assert_eq!(engine.committed_height(), Some(5));
        // Rejected counter incremented.
        assert_eq!(stats.restore_catchup_responses_rejected, 1);
        // Mode still active — we MUST NOT have ingested
        // `responder_committed_height=999` from a malformed payload as
        // the catchup target.
        assert!(mode.is_active(), "malformed response must not flip mode");
        assert!(
            mode.peer_max_observed_committed_height.is_none(),
            "peer-max must not be updated from a malformed payload"
        );
    }

    /// End-to-end: an empty response from a peer at-or-below us correctly
    /// drives the transition out of restore-catchup mode (we have no more
    /// to catch up to from this peer, and we're above the baseline).
    #[test]
    fn restore_mode_exits_on_empty_response_from_caught_up_peer() {
        use qbind_consensus::ValidatorId;

        let validators = build_uniform_validator_set(2);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId::new(1), validators);
        engine.initialize_from_snapshot_baseline([0x01; 32], 5);

        // Simulate: the engine has already been brought up above the
        // snapshot baseline by a prior catchup batch. We model that here
        // with `register_block` + `on_vote` via the public restart API.
        // For the purpose of this transition test we only need
        // `engine.committed_height()` > snapshot_baseline_height. We
        // achieve that by replaying a correctly-formed catchup block
        // through the same path the real loop uses, anchored at the
        // snapshot. The transition logic itself is independent of how
        // the engine got to that height — it only reads
        // `committed_height()` — so we exercise the response handler
        // directly with an empty response that reflects the peer being
        // at-or-below us.

        // Force local committed_height to advance: we don't have a
        // public "set committed_height" API, so we instead make a
        // direct minimal claim by replaying one valid certified block
        // via `apply_restore_catchup_blocks`. Build it the same way
        // `BasicHotStuffEngine::derive_block_id_from_header` does so the
        // engine accepts it.
        let leader = engine.leader_for_view(6);
        // Reproduce the engine's block-id derivation to keep the test
        // self-contained; if this drifts, the test will fail loudly.
        let parent = [0x01u8; 32];
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&leader.0.to_le_bytes());
        id[8..16].copy_from_slice(&6u64.to_le_bytes());
        id[16..32].copy_from_slice(&parent[..16]);

        let block = EngineRestoreCatchupBlock::<[u8; 32]> {
            height: 6,
            view: 6,
            parent_block_id: parent,
            block_id: id,
            proposer: leader,
            qc_signers: vec![ValidatorId::new(0), ValidatorId::new(1)],
        };
        engine
            .apply_restore_catchup_blocks(&[block])
            .expect("certified suffix application should succeed");
        // Note: the 3-chain rule means a single block above the snapshot
        // baseline does not commit on its own. For this test we only
        // need the transition condition to compare local committed to
        // peer-max; if local committed is still 5, we deliberately
        // observe that the transition does NOT fire.
        let local_committed = engine.committed_height();

        let baseline = RestoreBaseline {
            snapshot_height: 5,
            snapshot_block_id: [0x01; 32],
        };
        let mut mode = RestoreCatchupModeState::from_config(Some(baseline));
        let mut stats = BinaryConsensusLoopInboundStats::default();

        // Empty response, peer reports the same committed_height as the
        // local node (whatever that is after the partial application).
        let resp = RestoreCatchupResponse {
            responder_validator_index: 0,
            request_from_height: local_committed.unwrap_or(5),
            request_from_block_id: parent,
            responder_committed_height: local_committed,
            blocks: vec![],
        };

        handle_restore_catchup_response(
            &mut engine,
            resp,
            &mut stats,
            ValidatorId::new(1),
            &mut mode,
        );

        // The transition flips iff local committed > snapshot baseline
        // AND local >= peer-max. With a single applied suffix block, the
        // 3-chain rule may or may not have committed yet; assert the
        // exact correspondence between the two.
        let h = local_committed.unwrap_or(5);
        if h > 5 {
            assert!(
                !mode.is_active(),
                "with strict progress above baseline + peer at-or-below, mode must exit"
            );
            assert_eq!(stats.restore_catchup_mode_active, 0);
            assert_eq!(stats.restore_catchup_mode_exited_at_height, h);
        } else {
            assert!(
                mode.is_active(),
                "without strict progress above baseline, mode must stay active"
            );
            assert_eq!(stats.restore_catchup_mode_active, 1);
            assert_eq!(stats.restore_catchup_mode_exited_at_height, 0);
        }
    }

    /// Once mode flips to inactive, `maybe_broadcast_restore_catchup_request`
    /// must stop broadcasting new requests on subsequent ticks. We assert
    /// this by calling the function directly with a recording facade and
    /// verifying the counter does not increment.
    #[test]
    fn restore_mode_inactive_stops_request_broadcasts() {
        use crate::consensus_network_facade::ConsensusNetworkFacade;
        use qbind_consensus::network::NetworkError;
        use qbind_consensus::ValidatorId;
        use qbind_wire::consensus::{BlockProposal, Vote};
        use std::sync::Mutex;

        // Tiny recording facade: counts broadcast_consensus_msg calls.
        #[derive(Default)]
        struct RecordingFacade {
            broadcasts: Mutex<u64>,
        }
        impl ConsensusNetworkFacade for RecordingFacade {
            fn broadcast_proposal(&self, _p: &BlockProposal) -> Result<(), NetworkError> {
                Ok(())
            }
            fn broadcast_vote(&self, _v: &Vote) -> Result<(), NetworkError> {
                Ok(())
            }
            fn send_vote_to(
                &self,
                _to: ValidatorId,
                _v: &Vote,
            ) -> Result<(), NetworkError> {
                Ok(())
            }
            fn broadcast_consensus_msg(
                &self,
                _m: &ConsensusNetMsg,
            ) -> Result<(), NetworkError> {
                *self.broadcasts.lock().unwrap() += 1;
                Ok(())
            }
        }

        let validators = build_uniform_validator_set(2);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId::new(1), validators);
        engine.initialize_from_snapshot_baseline([0x01; 32], 5);

        let facade = RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();

        // Active mode: tick number that matches RESTORE_CATCHUP_REQUEST_EVERY_TICKS
        // schedule (ticks % 10 == 1) ⇒ broadcasts.
        maybe_broadcast_restore_catchup_request(
            &engine,
            1, // (1 % 10) == 1 — schedule slot
            ValidatorId::new(1),
            true,
            Some(&facade),
            &mut stats,
        );
        assert_eq!(*facade.broadcasts.lock().unwrap(), 1);
        assert_eq!(stats.restore_catchup_requests_sent, 1);

        // Inactive mode: same schedule slot, but mode flag is false ⇒
        // broadcast must NOT fire.
        maybe_broadcast_restore_catchup_request(
            &engine,
            11, // (11 % 10) == 1 — also a schedule slot
            ValidatorId::new(1),
            false,
            Some(&facade),
            &mut stats,
        );
        assert_eq!(
            *facade.broadcasts.lock().unwrap(),
            1,
            "inactive mode must suppress new RestoreCatchupRequest broadcasts"
        );
        assert_eq!(stats.restore_catchup_requests_sent, 1);
    }
}