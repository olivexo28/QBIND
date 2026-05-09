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
use qbind_consensus::timeout::{TimeoutCertificate, TimeoutMsg};
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_wire::consensus::{BlockProposal, Vote};

use crate::consensus_network_facade::ConsensusNetworkFacade;
use crate::metrics::NodeMetrics;
use crate::node_config::SnapshotConfig;
use crate::p2p::{
    ConsensusNetMsg, NodeId, P2pService, RestoreCatchupBlock, RestoreCatchupRequest,
    RestoreCatchupResponse,
};
use crate::vm_v0_runtime::{SnapshotAnchor, VmV0RuntimeError, VmV0RuntimeState};

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

/// B14: default number of ticks of zero forward view-progress that elapse
/// before the binary-path view-timeout primitive emits a `TimeoutMsg`.
///
/// At the default `DEFAULT_BINARY_CONSENSUS_TICK_INTERVAL` of 100ms this
/// is ~5s — comfortably above normal proposal/vote/QC round-trip times
/// in the existing N=4 binary-path topology, so an honest live leader
/// is never timed out by accident, while still bounded enough to recover
/// from an absent leader within seconds.
///
/// "Forward view-progress" here means `engine.current_view()` strictly
/// increasing OR a new commit landing — both observed at the loop level
/// from engine state. This deliberately does not depend on wall-clock
/// time so single-validator and bounded-tick test paths stay
/// deterministic.
pub const DEFAULT_BINARY_CONSENSUS_VIEW_TIMEOUT_TICKS: u64 = 50;

/// B14: maximum accepted byte length for an inbound bincode-encoded
/// `TimeoutMsg` / `TimeoutCertificate` payload before we even attempt
/// deserialization.
///
/// A `TimeoutMsg<[u8; 32]>` is a 32-byte block-id (optional) plus a
/// `u64` view, a `u64` validator id, and a small QC structure
/// (`view + block_id + Vec<ValidatorId>`); a `TimeoutCertificate` is
/// the same plus a `Vec<ValidatorId>` of signers. With validator-set
/// sizes today bounded at small N, a few-hundred-byte payload is the
/// real upper bound; 64 KiB is several orders of magnitude above that
/// and is *only* a defense-in-depth ceiling against a hostile peer
/// trying to drive memory exhaustion via an oversized length prefix
/// in a bincode frame. We fail closed (decode-failure counters
/// increment, no engine state mutation) on any payload above this
/// limit.
const MAX_INBOUND_TIMEOUT_FRAME_BYTES: usize = 64 * 1024;

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
    /// B14: number of ticks of zero forward view-progress before the
    /// binary path emits a `TimeoutMsg` for the current view.
    ///
    /// `None` disables the view-timeout primitive entirely (preserves
    /// pre-B14 behaviour: a parked view never auto-advances). The
    /// default constructor [`BinaryConsensusLoopConfig::new`] sets this
    /// to `Some(DEFAULT_BINARY_CONSENSUS_VIEW_TIMEOUT_TICKS)`.
    ///
    /// View-timeout emission is suppressed while bounded restore-catchup
    /// mode is active (`RestoreCatchupModeState::active=true`) so a
    /// restored node never times out a live view it is still catching
    /// up to.
    pub view_timeout_ticks: Option<u64>,
    /// Optional committed-height periodic VM-v0 snapshot trigger.
    pub periodic_snapshot: Option<BinaryPeriodicSnapshotConfig>,
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

#[derive(Debug, Clone)]
pub struct BinaryPeriodicSnapshotConfig {
    pub snapshot_config: SnapshotConfig,
    pub runtime: Option<Arc<VmV0RuntimeState>>,
    pub chain_id: u64,
}

impl BinaryPeriodicSnapshotConfig {
    pub fn new(
        snapshot_config: SnapshotConfig,
        runtime: Option<Arc<VmV0RuntimeState>>,
        chain_id: u64,
    ) -> Self {
        Self {
            snapshot_config,
            runtime,
            chain_id,
        }
    }
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
            view_timeout_ticks: Some(DEFAULT_BINARY_CONSENSUS_VIEW_TIMEOUT_TICKS),
            periodic_snapshot: None,
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

    /// B14: override the view-timeout tick threshold.
    ///
    /// Pass `None` to disable the binary-path view-timeout primitive
    /// entirely (the pre-B14 behaviour: a parked view never
    /// auto-advances). Tests use small values to deterministically
    /// trigger timeouts within a bounded `max_ticks` window.
    pub fn with_view_timeout_ticks(mut self, n: Option<u64>) -> Self {
        self.view_timeout_ticks = n;
        self
    }

    pub fn with_periodic_snapshot(mut self, periodic: BinaryPeriodicSnapshotConfig) -> Self {
        self.periodic_snapshot = Some(periodic);
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

    // ----------------------------------------------------------------------
    // B14: binary-path view-timeout / view-change observability.
    //
    // All four counters are strict accounts of what the timeout primitive
    // actually did on real ticks/inbound frames. They never increment
    // speculatively. With `view_timeout_ticks = None` (the primitive
    // disabled) all four stay at zero for the life of the loop.
    // ----------------------------------------------------------------------
    /// `TimeoutMsg` frames emitted by this validator after the
    /// configured `view_timeout_ticks` window of zero forward
    /// view-progress elapsed in the current view. Bounded: incremented
    /// at most once per view by `engine.timeout_emitted_in_view()`
    /// gating; cleared on every successful view advance.
    pub view_timeouts_emitted: u64,
    /// Inbound `Timeout(bytes)` frames that decoded as a typed
    /// `TimeoutMsg` and were delivered to `engine.on_timeout_msg`.
    pub inbound_timeouts_delivered: u64,
    /// Inbound `Timeout(bytes)` frames the engine accepted (i.e.
    /// `on_timeout_msg` returned `Ok(_)` — either a fresh ingestion or
    /// a duplicate accepted). Strictly `<= inbound_timeouts_delivered`.
    pub inbound_timeouts_engine_accepted: u64,
    /// `TimeoutCertificate`s actually formed at this validator, either
    /// by ingesting our own emitted timeout or after a peer's inbound
    /// timeout pushed the accumulator past the 2/3 threshold.
    pub timeout_certificates_formed: u64,
    /// `NewView(bytes)` frames broadcast by this validator after a TC
    /// was formed locally. Strictly `<= timeout_certificates_formed`.
    pub outbound_new_views_sent: u64,
    /// Inbound `NewView(bytes)` frames that decoded as a typed
    /// `TimeoutCertificate` and were delivered to
    /// `engine.on_timeout_certificate`.
    pub inbound_new_views_delivered: u64,
    /// Inbound `NewView` frames the engine accepted to advance the
    /// view (i.e. `on_timeout_certificate` returned `Ok(view)` with
    /// `view > previous_view`). Strictly `<= inbound_new_views_delivered`.
    pub inbound_new_views_engine_accepted: u64,
    /// Total view advances driven by a `TimeoutCertificate` (locally
    /// formed OR received via `NewView`). This is a subset of
    /// `progress.view_changes_total` — the rest are normal QC-driven
    /// advances. Bounded: at most one per TC application.
    pub view_timeout_advances: u64,
    /// Inbound `Timeout(bytes)` / `NewView(bytes)` frames whose typed
    /// decode failed (malformed bincode payload). Counted under the
    /// existing `inbound_decode_failures` family for consistency with
    /// proposal/vote decode failures, and additionally surfaced here
    /// for B14-specific test assertions. Fail-closed: no engine state
    /// change occurs on such frames.
    pub view_timeout_decode_failures: u64,
    /// Inbound `Timeout` / `NewView` frames the engine rejected after
    /// successful decode (e.g. `TimeoutValidationError::NonMemberSigner`,
    /// `InsufficientQuorum`, `ViewMismatch`). Fail-closed: engine state
    /// is unchanged.
    pub view_timeout_engine_rejects: u64,
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

/// B14: per-loop view-timeout state for the binary path.
///
/// Tracks the tick of the last observed forward view-progress
/// (`engine.current_view()` strictly increasing OR a new commit). The
/// loop emits a `TimeoutMsg` for the current view exactly when:
///
/// 1. `view_timeout_ticks` is configured (`Some(n)`), AND
/// 2. `restore_mode.is_active() == false` (we never time out a view
///    we are still catching up to from a snapshot), AND
/// 3. `engine.timeout_emitted_in_view() == false` (single-shot per
///    view; cleared by the engine on every successful view advance), AND
/// 4. an outbound `ConsensusNetworkFacade` is wired (single-validator
///    / LocalMesh paths cannot broadcast and stay zero), AND
/// 5. `ticks_since_last_view_progress >= n`.
///
/// All five gates are explicit. There is no implicit retry, no silent
/// heuristic, no "absent-leader detection" beyond the standard
/// HotStuff "no progress for N ticks". This naturally handles the
/// Run-015 N=4 absent-leader plateau (leader for `view_v` is
/// permanently absent ⇒ no QC ⇒ view does not advance ⇒ after `n`
/// ticks the present validators emit a timeout for `view_v` and a
/// `TimeoutCertificate` advances them to `view_v + 1`, which has a
/// different leader under round-robin).
#[derive(Debug, Clone, Copy)]
struct ViewTimeoutState {
    /// The view number observed on the most recent tick where forward
    /// progress was detected. Used to decide whether the view has
    /// changed since the last tick.
    last_observed_view: u64,
    /// The total commit count observed on the most recent tick where
    /// forward progress was detected. A new commit also counts as
    /// progress (pipelined HotStuff can commit at view `v-2` while
    /// view advances to `v+1`); both reset the timeout window.
    last_observed_commits: u64,
    /// The tick number on which forward progress was last observed.
    /// The timeout fires when `current_tick - last_progress_tick >=
    /// view_timeout_ticks`.
    last_progress_tick: u64,
}

impl ViewTimeoutState {
    fn new(initial_view: u64, initial_commits: u64) -> Self {
        Self {
            last_observed_view: initial_view,
            last_observed_commits: initial_commits,
            last_progress_tick: 0,
        }
    }

    /// Update progress tracking from current engine state. Returns
    /// `true` if forward progress was observed on this call (view
    /// strictly increased OR commits strictly increased), in which
    /// case `last_progress_tick` is updated.
    fn observe(&mut self, current_view: u64, current_commits: u64, current_tick: u64) -> bool {
        let progressed =
            current_view > self.last_observed_view || current_commits > self.last_observed_commits;
        if progressed {
            self.last_observed_view = current_view;
            self.last_observed_commits = current_commits;
            self.last_progress_tick = current_tick;
        }
        progressed
    }

    /// Whether the timeout window has elapsed for the current tick.
    /// Pure function of `current_tick`, `last_progress_tick`, and
    /// `view_timeout_ticks`. Returns `false` when the primitive is
    /// disabled (`view_timeout_ticks = None`).
    fn timeout_window_elapsed(
        &self,
        current_tick: u64,
        view_timeout_ticks: Option<u64>,
    ) -> bool {
        match view_timeout_ticks {
            None => false,
            Some(n) => current_tick.saturating_sub(self.last_progress_tick) >= n,
        }
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
    update_binary_view_timeout_metrics(&metrics, &inbound_stats);

    // B14: per-loop view-timeout state. Seeded with the engine's
    // current view (which already reflects any restore baseline) and
    // commit count so the very first tick after restore does not
    // trip the timeout window.
    let mut view_timeout_state = ViewTimeoutState::new(
        engine.current_view(),
        engine.commit_log().len() as u64,
    );
    let mut last_periodic_snapshot_height: Option<u64> = None;
    log_periodic_snapshot_config(cfg.periodic_snapshot.as_ref());

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
                            let committed_anchor = update_state_metrics(
                                &engine,
                                &metrics,
                                &mut last_commits,
                                &mut last_view,
                                Duration::ZERO,
                            );
                            maybe_trigger_periodic_snapshot(
                                cfg.periodic_snapshot.as_ref(),
                                committed_anchor,
                                &mut last_periodic_snapshot_height,
                                Arc::clone(&metrics),
                            );
                            update_restore_catchup_metrics(&metrics, &inbound_stats);
                            update_binary_view_timeout_metrics(&metrics, &inbound_stats);
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
                    // B14: emit a `TimeoutMsg` if the current view has
                    // been parked for more than `view_timeout_ticks`
                    // ticks without forward progress, then locally
                    // ingest it, broadcast it, and apply any resulting
                    // `TimeoutCertificate` so a present quorum can
                    // leave an absent-leader view.
                    maybe_emit_view_timeout(
                        &mut engine,
                        &mut view_timeout_state,
                        ticks,
                        cfg.view_timeout_ticks,
                        restore_mode.is_active(),
                        outbound_facade.as_deref(),
                        &mut inbound_stats,
                    );
                    let committed_anchor = update_state_metrics(
                        &engine,
                        &metrics,
                        &mut last_commits,
                        &mut last_view,
                        tick_started.elapsed(),
                    );
                    maybe_trigger_periodic_snapshot(
                        cfg.periodic_snapshot.as_ref(),
                        committed_anchor,
                        &mut last_periodic_snapshot_height,
                        Arc::clone(&metrics),
                    );
                    update_restore_catchup_metrics(&metrics, &inbound_stats);
                    update_binary_view_timeout_metrics(&metrics, &inbound_stats);
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
                    // B14: see other branch — same view-timeout
                    // emission gating applies on the no-inbound-IO
                    // path so a single-validator loop with an
                    // outbound facade can still record timeout
                    // emissions for testing.
                    maybe_emit_view_timeout(
                        &mut engine,
                        &mut view_timeout_state,
                        ticks,
                        cfg.view_timeout_ticks,
                        restore_mode.is_active(),
                        outbound_facade.as_deref(),
                        &mut inbound_stats,
                    );
                    let committed_anchor = update_state_metrics(
                        &engine,
                        &metrics,
                        &mut last_commits,
                        &mut last_view,
                        tick_started.elapsed(),
                    );
                    maybe_trigger_periodic_snapshot(
                        cfg.periodic_snapshot.as_ref(),
                        committed_anchor,
                        &mut last_periodic_snapshot_height,
                        Arc::clone(&metrics),
                    );
                    update_restore_catchup_metrics(&metrics, &inbound_stats);
                    update_binary_view_timeout_metrics(&metrics, &inbound_stats);
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
        ConsensusNetMsg::Timeout(bytes) => {
            // B14: typed binary-path ingestion of `TimeoutMsg`.
            //
            // We deserialize the bincode payload, route it through
            // `engine.on_timeout_msg`, and — if a `TimeoutCertificate`
            // is formed as a result — broadcast it as a `NewView` and
            // locally apply it via `engine.on_timeout_certificate` so
            // the engine actually advances out of the parked view.
            //
            // Fail-closed:
            //   - bincode decode failure  → `inbound_decode_failures`
            //     and `view_timeout_decode_failures` incremented; no
            //     engine state change.
            //   - engine validation error → `view_timeout_engine_rejects`
            //     incremented; no engine state change.
            //
            // We do NOT verify the timeout's signature here. This is
            // consistent with the existing binary-path inbound handlers
            // for `Proposal` and `Vote`, which today also flow through
            // `engine.on_proposal_event` / `engine.on_vote_event`
            // without independent signature verification at the loop
            // level (see `BasicHotStuffEngine::on_vote_event`, which
            // does no per-vote crypto). Production crypto verification
            // for timeout messages is a separate hardening step that
            // the engine surface (`on_timeout_msg` doc) explicitly
            // defers to its caller.
            // Defense-in-depth: bound bincode's allocation budget via
            // `bincode::config().limit(N)` and additionally short-circuit
            // any frame whose byte length already exceeds the cap, so a
            // hostile peer cannot drive memory exhaustion via an
            // oversized length prefix or oversized payload. The cap is
            // several orders of magnitude above the true upper bound
            // for these messages; see `MAX_INBOUND_TIMEOUT_FRAME_BYTES`.
            if bytes.len() > MAX_INBOUND_TIMEOUT_FRAME_BYTES {
                stats.inbound_decode_failures =
                    stats.inbound_decode_failures.saturating_add(1);
                stats.view_timeout_decode_failures =
                    stats.view_timeout_decode_failures.saturating_add(1);
                eprintln!(
                    "[binary-consensus] B14: inbound timeout exceeds {} byte cap (got {}); dropping",
                    MAX_INBOUND_TIMEOUT_FRAME_BYTES,
                    bytes.len()
                );
                update_binary_view_timeout_metrics(metrics, stats);
                return;
            }
            match bincode::config()
                .limit(MAX_INBOUND_TIMEOUT_FRAME_BYTES as u64)
                .deserialize::<TimeoutMsg<[u8; 32]>>(&bytes)
            {
                Ok(timeout) => {
                    stats.inbound_timeouts_delivered =
                        stats.inbound_timeouts_delivered.saturating_add(1);
                    let from = timeout.validator_id;
                    match engine.on_timeout_msg(from, timeout) {
                        Ok(maybe_tc) => {
                            stats.inbound_timeouts_engine_accepted =
                                stats.inbound_timeouts_engine_accepted.saturating_add(1);
                            if let Some(tc) = maybe_tc {
                                apply_local_tc_and_broadcast_new_view(
                                    engine,
                                    &tc,
                                    stats,
                                    outbound,
                                );
                            }
                        }
                        Err(e) => {
                            stats.view_timeout_engine_rejects =
                                stats.view_timeout_engine_rejects.saturating_add(1);
                            eprintln!(
                                "[binary-consensus] B14: inbound timeout rejected by engine: {:?}",
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    stats.inbound_decode_failures =
                        stats.inbound_decode_failures.saturating_add(1);
                    stats.view_timeout_decode_failures =
                        stats.view_timeout_decode_failures.saturating_add(1);
                    eprintln!(
                        "[binary-consensus] B14: inbound timeout decode failed: {:?}",
                        e
                    );
                }
            }
            update_binary_view_timeout_metrics(metrics, stats);
        }
        ConsensusNetMsg::NewView(bytes) => {
            // B14: typed binary-path ingestion of `TimeoutCertificate`.
            //
            // The wire payload is a bincode-encoded
            // `TimeoutCertificate<[u8; 32]>`. After decode we route it
            // through `engine.on_timeout_certificate`, which (a)
            // validates that the signers are validator-set members
            // with sufficient combined voting power (≥ 2/3),
            // (b) updates `locked_qc` if the TC carries a higher
            // high_qc than ours, and (c) advances `current_view` to
            // `tc.view`. Engine validation failure is the fail-closed
            // path.
            // Defense-in-depth size cap (see Timeout arm above). Same
            // ceiling for `TimeoutCertificate` payloads.
            if bytes.len() > MAX_INBOUND_TIMEOUT_FRAME_BYTES {
                stats.inbound_decode_failures =
                    stats.inbound_decode_failures.saturating_add(1);
                stats.view_timeout_decode_failures =
                    stats.view_timeout_decode_failures.saturating_add(1);
                eprintln!(
                    "[binary-consensus] B14: inbound NewView exceeds {} byte cap (got {}); dropping",
                    MAX_INBOUND_TIMEOUT_FRAME_BYTES,
                    bytes.len()
                );
                update_binary_view_timeout_metrics(metrics, stats);
                return;
            }
            match bincode::config()
                .limit(MAX_INBOUND_TIMEOUT_FRAME_BYTES as u64)
                .deserialize::<TimeoutCertificate<[u8; 32]>>(&bytes)
            {
                Ok(tc) => {
                    stats.inbound_new_views_delivered =
                        stats.inbound_new_views_delivered.saturating_add(1);
                    let from_view = engine.current_view();
                    match engine.on_timeout_certificate(&tc) {
                        Ok(to_view) => {
                            if to_view > from_view {
                                stats.inbound_new_views_engine_accepted = stats
                                    .inbound_new_views_engine_accepted
                                    .saturating_add(1);
                                stats.view_timeout_advances =
                                    stats.view_timeout_advances.saturating_add(1);
                                eprintln!(
                                    "[binary-consensus] B14: NewView advanced view {} -> {}",
                                    from_view, to_view
                                );
                            }
                        }
                        Err(e) => {
                            stats.view_timeout_engine_rejects =
                                stats.view_timeout_engine_rejects.saturating_add(1);
                            eprintln!(
                                "[binary-consensus] B14: NewView rejected by engine: {:?}",
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    stats.inbound_decode_failures =
                        stats.inbound_decode_failures.saturating_add(1);
                    stats.view_timeout_decode_failures =
                        stats.view_timeout_decode_failures.saturating_add(1);
                    eprintln!(
                        "[binary-consensus] B14: inbound NewView decode failed: {:?}",
                        e
                    );
                }
            }
            update_binary_view_timeout_metrics(metrics, stats);
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

/// B14: per-tick view-timeout emission on the binary path.
///
/// Called from the loop's tick handler after the leader-step
/// (`do_leader_tick`) and after `restore_mode` evaluation, but before
/// `update_state_metrics`. Emits at most one `TimeoutMsg` per view per
/// validator per loop instance:
///
/// 1. Snapshots the current `(view, commits)` state and asks
///    `view_state.observe(...)` whether forward progress occurred since
///    the last tick. Forward progress resets the timeout window — this
///    is the same liveness criterion as HotStuff's pacemaker
///    (proposal/QC/commit). When the leader is genuinely live the
///    window keeps resetting and no timeout ever fires.
///
/// 2. If `view_timeout_ticks` is `None` (primitive disabled), or
///    restore-catchup mode is still active (we never time out a view
///    we are still catching up to), or no outbound facade is wired
///    (single-validator / LocalMesh), or the engine has already
///    emitted a timeout for the current view, the function returns
///    without side-effects.
///
/// 3. Otherwise, when the configured tick window has elapsed, the
///    function builds a `TimeoutMsg` via `engine.create_timeout_msg()`,
///    marks the engine as "timeout emitted in this view" so the same
///    view never fires twice, locally ingests the timeout (so a single
///    validator that is itself one of the 2/3 quorum is not
///    permanently waiting for its own bytes to round-trip back), and
///    broadcasts the bincode-encoded payload as
///    `ConsensusNetMsg::Timeout(bytes)`.
///
/// 4. If local ingestion already crosses the 2/3 threshold (e.g. in a
///    bounded test where this validator drives the timeout-accumulator
///    past quorum on its own ingestion), the resulting
///    `TimeoutCertificate` is also broadcast as
///    `ConsensusNetMsg::NewView(bytes)` and applied to the engine via
///    `engine.on_timeout_certificate`, advancing the view immediately.
///
/// All counter updates are strict accounts of what the function
/// actually did. Encode failures (which should never happen for these
/// plain-data structs) are logged and bounce out without engine
/// effect.
fn maybe_emit_view_timeout(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    view_state: &mut ViewTimeoutState,
    ticks: u64,
    view_timeout_ticks: Option<u64>,
    restore_mode_active: bool,
    outbound: Option<&dyn ConsensusNetworkFacade>,
    stats: &mut BinaryConsensusLoopInboundStats,
) {
    // Always observe progress, even if the primitive is disabled — so
    // re-enabling later starts from a current baseline.
    let progressed = view_state.observe(
        engine.current_view(),
        engine.commit_log().len() as u64,
        ticks,
    );
    if progressed {
        // Forward progress resets the engine's per-view timeout-emitted
        // flag indirectly via `try_advance_to_view` / `advance_view` /
        // `on_timeout_certificate` — those are the only paths that
        // mutate `current_view`. There is nothing to do here besides
        // observe.
        return;
    }
    // Gate 1: primitive enabled?
    let Some(_) = view_timeout_ticks else {
        return;
    };
    // Gate 2: restore-catchup mode must not be active.
    if restore_mode_active {
        return;
    }
    // Gate 3: outbound facade required for broadcast.
    let Some(facade) = outbound else {
        return;
    };
    // Gate 4: engine must not have already emitted a timeout for this view.
    if engine.timeout_emitted_in_view() {
        return;
    }
    // Gate 5: the configured tick window must have elapsed.
    if !view_state.timeout_window_elapsed(ticks, view_timeout_ticks) {
        return;
    }

    let timed_out_view = engine.current_view();
    let timeout_msg = engine.create_timeout_msg();
    let local_id = timeout_msg.validator_id;

    // Encode first so a serialization error fails closed before we
    // mutate engine state.
    let bytes = match bincode::serialize(&timeout_msg) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "[binary-consensus] B14: timeout encode failed (view={}): {:?} — skipping emit",
                timed_out_view, e
            );
            return;
        }
    };

    // Mark before locally ingesting so a self-fire that produces a TC
    // does not re-enter this branch.
    engine.mark_timeout_emitted();
    stats.view_timeouts_emitted = stats.view_timeouts_emitted.saturating_add(1);

    // Locally ingest. In a 2/3 quorum where this validator is the
    // first to time out, no TC forms yet; in a small (e.g. f=0,
    // n=1) topology this single timeout already crosses 2/3 and the
    // engine returns a TC immediately. In both cases we then
    // broadcast.
    let mut formed_tc: Option<TimeoutCertificate<[u8; 32]>> = None;
    match engine.on_timeout_msg(local_id, timeout_msg) {
        Ok(maybe_tc) => {
            // Note: the local self-ingest does NOT increment
            // `inbound_timeouts_engine_accepted` — that counter is
            // strictly the "from the wire" view (see the `Timeout`
            // arm of `handle_inbound_consensus_msg`). Any TC formed
            // here is captured below via `timeout_certificates_formed`
            // in `apply_local_tc_and_broadcast_new_view`.
            formed_tc = maybe_tc;
        }
        Err(e) => {
            stats.view_timeout_engine_rejects =
                stats.view_timeout_engine_rejects.saturating_add(1);
            eprintln!(
                "[binary-consensus] B14: local timeout ingest rejected by engine: {:?}",
                e
            );
        }
    }

    if let Err(e) = facade.broadcast_consensus_msg(&ConsensusNetMsg::Timeout(bytes)) {
        eprintln!(
            "[binary-consensus] B14: timeout broadcast failed (view={}): {:?}",
            timed_out_view, e
        );
    } else {
        eprintln!(
            "[binary-consensus] B14: emitted TimeoutMsg for view={} after {} ticks of no progress",
            timed_out_view,
            ticks.saturating_sub(view_state.last_progress_tick),
        );
    }

    if let Some(tc) = formed_tc {
        apply_local_tc_and_broadcast_new_view(engine, &tc, stats, outbound);
    }
}

/// B14: apply a locally-formed or just-received `TimeoutCertificate`
/// to the engine and broadcast it to peers as a `NewView(bytes)`.
///
/// This is shared between (a) the path where a local
/// `engine.on_timeout_msg` ingestion crossed the 2/3 quorum and
/// produced a TC, and (b) the path where an inbound peer's
/// `Timeout(bytes)` was the one that crossed the threshold. In both
/// cases we want to publish the TC so the rest of the cluster can
/// jump views without each peer having to independently re-derive it.
///
/// Engine apply is the source of truth: if
/// `engine.on_timeout_certificate` rejects (insufficient quorum,
/// non-member signers, view mismatch, …), no view advance is
/// recorded and no broadcast occurs.
fn apply_local_tc_and_broadcast_new_view(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    tc: &TimeoutCertificate<[u8; 32]>,
    stats: &mut BinaryConsensusLoopInboundStats,
    outbound: Option<&dyn ConsensusNetworkFacade>,
) {
    stats.timeout_certificates_formed =
        stats.timeout_certificates_formed.saturating_add(1);
    let from_view = engine.current_view();
    match engine.on_timeout_certificate(tc) {
        Ok(to_view) => {
            if to_view > from_view {
                stats.view_timeout_advances =
                    stats.view_timeout_advances.saturating_add(1);
                eprintln!(
                    "[binary-consensus] B14: TimeoutCertificate advanced view {} -> {}",
                    from_view, to_view
                );
            }
        }
        Err(e) => {
            stats.view_timeout_engine_rejects =
                stats.view_timeout_engine_rejects.saturating_add(1);
            eprintln!(
                "[binary-consensus] B14: local TC apply rejected by engine: {:?}",
                e
            );
            return;
        }
    }
    let Some(facade) = outbound else {
        return;
    };
    match bincode::serialize(tc) {
        Ok(bytes) => {
            if let Err(e) =
                facade.broadcast_consensus_msg(&ConsensusNetMsg::NewView(bytes))
            {
                eprintln!("[binary-consensus] B14: NewView broadcast failed: {:?}", e);
            } else {
                stats.outbound_new_views_sent =
                    stats.outbound_new_views_sent.saturating_add(1);
            }
        }
        Err(e) => {
            eprintln!("[binary-consensus] B14: TC encode failed: {:?}", e);
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
) -> Option<SnapshotAnchor> {
    let new_commits_total = engine.commit_log().len() as u64;
    let new_view = engine.current_view();
    let commits_delta = new_commits_total.saturating_sub(*last_commits);
    let mut new_committed_anchor = None;
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
            new_committed_anchor = Some(SnapshotAnchor {
                height,
                block_hash: *block_id,
            });
        }
    }
    *last_commits = new_commits_total;
    *last_view = new_view;
    new_committed_anchor
}

fn log_periodic_snapshot_config(periodic: Option<&BinaryPeriodicSnapshotConfig>) {
    let Some(periodic) = periodic else {
        eprintln!("[snapshot] periodic snapshot trigger disabled: no snapshot config wired");
        return;
    };
    if !periodic.snapshot_config.enabled {
        eprintln!("[snapshot] periodic snapshot trigger disabled: snapshot config disabled");
    } else if periodic.snapshot_config.snapshot_dir.is_none() {
        eprintln!("[snapshot] periodic snapshot trigger disabled: --snapshot-dir not configured");
    } else if periodic.snapshot_config.snapshot_interval_blocks == 0 {
        eprintln!(
            "[snapshot] periodic snapshot trigger disabled: --snapshot-interval-blocks is zero"
        );
    } else if periodic.runtime.is_none() {
        eprintln!("[snapshot] periodic snapshot trigger disabled: VM-v0 runtime not active");
    } else {
        eprintln!(
            "[snapshot] periodic snapshot trigger enabled: interval_blocks={} snapshot_dir={}",
            periodic.snapshot_config.snapshot_interval_blocks,
            periodic
                .snapshot_config
                .snapshot_dir
                .as_ref()
                .expect("checked")
                .display()
        );
    }
}

fn maybe_trigger_periodic_snapshot(
    periodic: Option<&BinaryPeriodicSnapshotConfig>,
    committed_anchor: Option<SnapshotAnchor>,
    last_periodic_snapshot_height: &mut Option<u64>,
    metrics: Arc<NodeMetrics>,
) {
    let Some(anchor) = committed_anchor else {
        return;
    };
    if anchor.height == 0 {
        eprintln!("[snapshot] periodic snapshot skipped: committed height is zero");
        return;
    }
    let Some(periodic) = periodic else {
        return;
    };
    if !periodic
        .snapshot_config
        .should_snapshot_at_height(anchor.height)
    {
        return;
    }
    eprintln!(
        "[snapshot] periodic condition detected: height={} interval_blocks={}",
        anchor.height, periodic.snapshot_config.snapshot_interval_blocks
    );
    if *last_periodic_snapshot_height == Some(anchor.height) {
        eprintln!(
            "[snapshot] periodic snapshot skipped: already created for height={}",
            anchor.height
        );
        return;
    }
    let Some(runtime) = periodic.runtime.as_ref().cloned() else {
        eprintln!(
            "[snapshot] periodic snapshot skipped: VM-v0 runtime unavailable at height={}",
            anchor.height
        );
        return;
    };
    let chain_id = periodic.chain_id;
    *last_periodic_snapshot_height = Some(anchor.height);
    // Fire-and-forget is deliberate here: periodic snapshots must not block the
    // consensus tick path. The inner spawn_blocking result is logged and metrics
    // are updated; shutdown may abandon an in-flight periodic request rather
    // than extending node termination.
    tokio::spawn(async move {
        let snapshot_height = anchor.height;
        let metrics_for_task = Arc::clone(&metrics);
        let result = tokio::task::spawn_blocking(move || {
            runtime.create_snapshot(anchor, chain_id, &metrics_for_task)
        })
        .await;
        match result {
            Ok(Ok(stats)) => {
                eprintln!(
                    "[snapshot] periodic success: height={} size_bytes={} duration_ms={}",
                    stats.height, stats.size_bytes, stats.duration_ms
                );
            }
            Ok(Err(VmV0RuntimeError::SnapshotAlreadyInProgress)) => {
                eprintln!(
                    "[snapshot] periodic snapshot skipped: another snapshot is already in progress at height={}",
                    snapshot_height
                );
            }
            Ok(Err(e)) => {
                eprintln!(
                    "[snapshot] periodic ERROR: height={} error={}",
                    snapshot_height, e
                );
            }
            Err(e) => {
                eprintln!(
                    "[snapshot] periodic ERROR: snapshot task join failed at height={}: {}",
                    snapshot_height, e
                );
                metrics.snapshot().record_failure();
            }
        }
    });
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

fn update_binary_view_timeout_metrics(
    metrics: &Arc<NodeMetrics>,
    stats: &BinaryConsensusLoopInboundStats,
) {
    metrics.binary_view_timeout().set(
        stats.view_timeouts_emitted,
        stats.inbound_timeouts_delivered,
        stats.inbound_timeouts_engine_accepted,
        stats.timeout_certificates_formed,
        stats.outbound_new_views_sent,
        stats.inbound_new_views_delivered,
        stats.inbound_new_views_engine_accepted,
        stats.view_timeout_advances,
        stats.view_timeout_decode_failures,
        stats.view_timeout_engine_rejects,
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
    use crate::node_config::{ExecutionProfile, NodeConfig};
    use crate::vm_v0_runtime::VmV0RuntimeState;
    use tempfile::TempDir;

    fn vm_v0_periodic_runtime(
        data_dir: &std::path::Path,
        snapshot_dir: Option<&std::path::Path>,
        interval_blocks: u64,
        max_snapshots: u32,
    ) -> (SnapshotConfig, Arc<VmV0RuntimeState>, u64) {
        let mut config = NodeConfig::devnet_v0_preset();
        config.execution_profile = ExecutionProfile::VmV0;
        config.data_dir = Some(data_dir.to_path_buf());
        config.snapshot_config = SnapshotConfig {
            enabled: snapshot_dir.is_some(),
            snapshot_dir: snapshot_dir.map(std::path::Path::to_path_buf),
            snapshot_interval_blocks: interval_blocks,
            max_snapshots,
        };
        let chain_id = config.chain_id().as_u64();
        let runtime = VmV0RuntimeState::open_from_config(&config)
            .unwrap()
            .unwrap();
        (config.snapshot_config, runtime, chain_id)
    }

    async fn wait_for_snapshot_success(metrics: &NodeMetrics, expected: u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            if metrics.snapshot().success_total() >= expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "timed out waiting for snapshot success_total >= {}, got {}",
            expected,
            metrics.snapshot().success_total()
        );
    }

    async fn short_settle() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn periodic_snapshot_trigger_does_not_fire_without_snapshot_dir() {
        let data = TempDir::new().unwrap();
        let (snapshot_config, runtime, chain_id) =
            vm_v0_periodic_runtime(data.path(), None, 4, 3);
        let periodic = BinaryPeriodicSnapshotConfig::new(snapshot_config, Some(runtime), chain_id);
        let metrics = Arc::new(NodeMetrics::new());
        let mut last_height = None;

        maybe_trigger_periodic_snapshot(
            Some(&periodic),
            Some(SnapshotAnchor {
                height: 4,
                block_hash: [4; 32],
            }),
            &mut last_height,
            Arc::clone(&metrics),
        );
        short_settle().await;

        assert_eq!(metrics.snapshot().success_total(), 0);
        assert_eq!(metrics.snapshot().failure_total(), 0);
        assert_eq!(last_height, None);
    }

    #[tokio::test]
    async fn periodic_snapshot_trigger_does_not_fire_without_interval() {
        let data = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let (snapshot_config, runtime, chain_id) =
            vm_v0_periodic_runtime(data.path(), Some(snapshots.path()), 0, 3);
        let periodic = BinaryPeriodicSnapshotConfig::new(snapshot_config, Some(runtime), chain_id);
        let metrics = Arc::new(NodeMetrics::new());
        let mut last_height = None;

        maybe_trigger_periodic_snapshot(
            Some(&periodic),
            Some(SnapshotAnchor {
                height: 4,
                block_hash: [4; 32],
            }),
            &mut last_height,
            Arc::clone(&metrics),
        );
        short_settle().await;

        assert_eq!(metrics.snapshot().success_total(), 0);
        assert_eq!(metrics.snapshot().failure_total(), 0);
        assert!(!snapshots.path().join("4").exists());
        assert_eq!(last_height, None);
    }

    #[tokio::test]
    async fn periodic_snapshot_trigger_does_not_fire_at_height_zero() {
        let data = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let (snapshot_config, runtime, chain_id) =
            vm_v0_periodic_runtime(data.path(), Some(snapshots.path()), 4, 3);
        let periodic = BinaryPeriodicSnapshotConfig::new(snapshot_config, Some(runtime), chain_id);
        let metrics = Arc::new(NodeMetrics::new());
        let mut last_height = None;

        maybe_trigger_periodic_snapshot(
            Some(&periodic),
            Some(SnapshotAnchor {
                height: 0,
                block_hash: [0; 32],
            }),
            &mut last_height,
            Arc::clone(&metrics),
        );
        short_settle().await;

        assert_eq!(metrics.snapshot().success_total(), 0);
        assert_eq!(metrics.snapshot().failure_total(), 0);
        assert!(!snapshots.path().join("0").exists());
        assert_eq!(last_height, None);
    }

    #[tokio::test]
    async fn periodic_snapshot_trigger_fires_once_for_same_committed_height() {
        let data = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let (snapshot_config, runtime, chain_id) =
            vm_v0_periodic_runtime(data.path(), Some(snapshots.path()), 4, 3);
        let periodic = BinaryPeriodicSnapshotConfig::new(snapshot_config, Some(runtime), chain_id);
        let metrics = Arc::new(NodeMetrics::new());
        let mut last_height = None;
        let anchor = SnapshotAnchor {
            height: 4,
            block_hash: [4; 32],
        };

        maybe_trigger_periodic_snapshot(
            Some(&periodic),
            Some(anchor),
            &mut last_height,
            Arc::clone(&metrics),
        );
        wait_for_snapshot_success(&metrics, 1).await;
        maybe_trigger_periodic_snapshot(
            Some(&periodic),
            Some(anchor),
            &mut last_height,
            Arc::clone(&metrics),
        );
        short_settle().await;

        assert_eq!(metrics.snapshot().success_total(), 1);
        assert_eq!(metrics.snapshot().failure_total(), 0);
        assert_eq!(metrics.snapshot().last_height(), 4);
        assert!(snapshots.path().join("4/meta.json").is_file());
    }

    #[tokio::test]
    async fn periodic_snapshot_trigger_uses_runtime_snapshot_path_and_prunes_numeric_dirs() {
        let data = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let (snapshot_config, runtime, chain_id) =
            vm_v0_periodic_runtime(data.path(), Some(snapshots.path()), 4, 2);
        let periodic = BinaryPeriodicSnapshotConfig::new(snapshot_config, Some(runtime), chain_id);
        let metrics = Arc::new(NodeMetrics::new());
        let mut last_height = None;
        std::fs::create_dir_all(snapshots.path().join("operator-notes")).unwrap();

        for height in [4_u64, 8, 12] {
            maybe_trigger_periodic_snapshot(
                Some(&periodic),
                Some(SnapshotAnchor {
                    height,
                    block_hash: [height as u8; 32],
                }),
                &mut last_height,
                Arc::clone(&metrics),
            );
            wait_for_snapshot_success(&metrics, height / 4).await;
        }

        assert_eq!(metrics.snapshot().success_total(), 3);
        assert_eq!(metrics.snapshot().failure_total(), 0);
        assert_eq!(metrics.snapshot().last_height(), 12);
        assert!(!snapshots.path().join("4").exists());
        assert!(snapshots.path().join("8/meta.json").is_file());
        assert!(snapshots.path().join("12/meta.json").is_file());
        assert!(snapshots.path().join("operator-notes").is_dir());
    }

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

    // ========================================================================
    // B14: binary-path view-timeout / view-change primitive tests.
    //
    // These tests exercise `maybe_emit_view_timeout` and the inbound
    // `ConsensusNetMsg::Timeout` / `NewView` handlers in
    // `handle_inbound_consensus_msg` directly. They prove:
    //
    //   A. After `view_timeout_ticks` ticks of no forward progress, a
    //      `TimeoutMsg` is emitted and broadcast.
    //   B. Restore-catchup mode suppresses emission (B13 invariant).
    //   C. Disabling the primitive (`view_timeout_ticks = None`)
    //      preserves pre-B14 behaviour: no emission ever.
    //   D. Forward progress (commit OR view advance) resets the window.
    //   E. The 2/3-quorum threshold actually advances the view: in a
    //      bounded N=1 topology the local timeout itself crosses the
    //      threshold, forms a TC, and `current_view` advances by 1.
    //   F. Inbound malformed `Timeout` / `NewView` bytes are
    //      fail-closed: counters increment, engine state unchanged.
    //   G. Inbound `NewView` carrying a structurally valid TC advances
    //      the view at the receiver.
    //   H. Run-015 absent-leader N=4 shape: local + two peer timeouts
    //      cross 2/3 quorum, the engine forms a TC, the loop applies
    //      it, and the parked view advances to one whose leader is
    //      different.
    // ========================================================================

    /// Tiny recording facade reused by B14 tests. Counts every
    /// `broadcast_consensus_msg` invocation by `ConsensusNetMsg` variant
    /// so tests can assert exact send shapes (Timeout vs NewView).
    #[derive(Default)]
    struct B14RecordingFacade {
        timeouts_sent: std::sync::Mutex<u64>,
        new_views_sent: std::sync::Mutex<u64>,
        last_timeout_bytes: std::sync::Mutex<Option<Vec<u8>>>,
        last_new_view_bytes: std::sync::Mutex<Option<Vec<u8>>>,
    }

    impl crate::consensus_network_facade::ConsensusNetworkFacade for B14RecordingFacade {
        fn broadcast_proposal(
            &self,
            _p: &qbind_wire::consensus::BlockProposal,
        ) -> Result<(), qbind_consensus::network::NetworkError> {
            Ok(())
        }
        fn broadcast_vote(
            &self,
            _v: &qbind_wire::consensus::Vote,
        ) -> Result<(), qbind_consensus::network::NetworkError> {
            Ok(())
        }
        fn send_vote_to(
            &self,
            _to: ValidatorId,
            _v: &qbind_wire::consensus::Vote,
        ) -> Result<(), qbind_consensus::network::NetworkError> {
            Ok(())
        }
        fn broadcast_consensus_msg(
            &self,
            m: &ConsensusNetMsg,
        ) -> Result<(), qbind_consensus::network::NetworkError> {
            match m {
                ConsensusNetMsg::Timeout(b) => {
                    *self.timeouts_sent.lock().unwrap() += 1;
                    *self.last_timeout_bytes.lock().unwrap() = Some(b.clone());
                }
                ConsensusNetMsg::NewView(b) => {
                    *self.new_views_sent.lock().unwrap() += 1;
                    *self.last_new_view_bytes.lock().unwrap() = Some(b.clone());
                }
                _ => {}
            }
            Ok(())
        }
    }

    fn b14_make_engine(n: u64, local_id: u64) -> BasicHotStuffEngine<[u8; 32]> {
        let validators = build_uniform_validator_set(n);
        BasicHotStuffEngine::new(ValidatorId::new(local_id), validators)
    }

    /// Test A (boundary the Run-015 plateau hit): with the primitive
    /// enabled and a wired outbound facade, after `view_timeout_ticks`
    /// ticks of zero forward progress, exactly one `TimeoutMsg` is
    /// emitted and broadcast for the parked view.
    #[test]
    fn b14_view_timeout_emits_after_window_elapses_no_progress() {
        // N=4, local is V0, current_view=15 ⇒ leader = view % n = 15 %
        // 4 = 3, which is "absent" in the Run-015 shape.
        let mut engine = b14_make_engine(4, 0);
        assert!(engine.try_advance_to_view(15));
        assert_eq!(engine.current_view(), 15);
        assert_eq!(engine.leader_for_view(15), ValidatorId::new(3));
        assert!(!engine.is_leader_for_current_view());

        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut view_state =
            ViewTimeoutState::new(engine.current_view(), engine.commit_log().len() as u64);

        // Ticks below threshold ⇒ no emission.
        for tick in 1..=4 {
            maybe_emit_view_timeout(
                &mut engine,
                &mut view_state,
                tick,
                Some(5), // small window for test determinism
                /* restore_mode_active */ false,
                Some(&facade),
                &mut stats,
            );
            assert_eq!(*facade.timeouts_sent.lock().unwrap(), 0);
            assert_eq!(stats.view_timeouts_emitted, 0);
        }

        // First tick at which window has elapsed ⇒ emit exactly once.
        maybe_emit_view_timeout(
            &mut engine,
            &mut view_state,
            5,
            Some(5),
            false,
            Some(&facade),
            &mut stats,
        );
        assert_eq!(*facade.timeouts_sent.lock().unwrap(), 1);
        assert_eq!(stats.view_timeouts_emitted, 1);
        assert!(engine.timeout_emitted_in_view());

        // Subsequent ticks must NOT re-emit (engine flag prevents
        // duplicate emission for the same view).
        for tick in 6..=20 {
            maybe_emit_view_timeout(
                &mut engine,
                &mut view_state,
                tick,
                Some(5),
                false,
                Some(&facade),
                &mut stats,
            );
        }
        assert_eq!(
            *facade.timeouts_sent.lock().unwrap(),
            1,
            "TimeoutMsg must be emitted at most once per view"
        );
        assert_eq!(stats.view_timeouts_emitted, 1);

        // The bytes broadcast must round-trip back to a valid
        // TimeoutMsg for the parked view (proves no fake/garbage
        // payload was sent).
        let bytes = facade.last_timeout_bytes.lock().unwrap().clone().unwrap();
        let decoded: TimeoutMsg<[u8; 32]> = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.view, 15);
        assert_eq!(decoded.validator_id, ValidatorId::new(0));
    }

    /// Test B: a restored node still in bounded restore-catchup mode
    /// must NOT time out a live view it is still catching up to.
    /// This preserves B13's safe restore-exit invariant.
    #[test]
    fn b14_view_timeout_suppressed_in_restore_catchup_mode() {
        let mut engine = b14_make_engine(4, 0);
        assert!(engine.try_advance_to_view(15));
        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut view_state =
            ViewTimeoutState::new(engine.current_view(), engine.commit_log().len() as u64);

        for tick in 1..=200 {
            maybe_emit_view_timeout(
                &mut engine,
                &mut view_state,
                tick,
                Some(5),
                /* restore_mode_active */ true,
                Some(&facade),
                &mut stats,
            );
        }
        assert_eq!(*facade.timeouts_sent.lock().unwrap(), 0);
        assert_eq!(stats.view_timeouts_emitted, 0);
        assert!(!engine.timeout_emitted_in_view());
    }

    /// Test C: `view_timeout_ticks = None` disables the primitive
    /// entirely (preserves pre-B14 behaviour). No emission ever.
    #[test]
    fn b14_view_timeout_disabled_via_none_emits_nothing() {
        let mut engine = b14_make_engine(4, 0);
        assert!(engine.try_advance_to_view(15));
        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut view_state =
            ViewTimeoutState::new(engine.current_view(), engine.commit_log().len() as u64);

        for tick in 1..=1000 {
            maybe_emit_view_timeout(
                &mut engine,
                &mut view_state,
                tick,
                /* view_timeout_ticks */ None,
                false,
                Some(&facade),
                &mut stats,
            );
        }
        assert_eq!(*facade.timeouts_sent.lock().unwrap(), 0);
        assert_eq!(stats.view_timeouts_emitted, 0);
    }

    /// Test D: forward view-progress resets the timeout window. We
    /// simulate this by having the engine's current_view advance in
    /// the middle of the tick stream, and assert no emission fires
    /// because the window keeps resetting.
    #[test]
    fn b14_view_timeout_progress_resets_window() {
        let mut engine = b14_make_engine(4, 0);
        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut view_state =
            ViewTimeoutState::new(engine.current_view(), engine.commit_log().len() as u64);

        // Advance the view between ticks so observe() always sees
        // forward progress and resets the window. Window threshold = 3.
        for tick in 1..=20 {
            assert!(engine.try_advance_to_view(engine.current_view() + 1));
            maybe_emit_view_timeout(
                &mut engine,
                &mut view_state,
                tick,
                Some(3),
                false,
                Some(&facade),
                &mut stats,
            );
        }
        assert_eq!(*facade.timeouts_sent.lock().unwrap(), 0);
        assert_eq!(stats.view_timeouts_emitted, 0);
    }

    /// Test E: in a bounded N=1 topology the local timeout itself is
    /// the entire 2/3 quorum, so emission immediately forms a TC, the
    /// loop applies it locally, and `current_view` advances. This is
    /// the smallest end-to-end exercise of the full primitive.
    #[test]
    fn b14_n1_self_quorum_forms_tc_advances_view_and_broadcasts_new_view() {
        let mut engine = b14_make_engine(1, 0);
        assert!(engine.try_advance_to_view(7));
        let from_view = engine.current_view();
        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut view_state =
            ViewTimeoutState::new(engine.current_view(), engine.commit_log().len() as u64);

        // Below window: no emission.
        maybe_emit_view_timeout(
            &mut engine, &mut view_state, 1, Some(2), false, Some(&facade), &mut stats,
        );
        assert_eq!(stats.view_timeouts_emitted, 0);

        // At window: emit, self-ingest, TC forms (1 ≥ 2/3 of 1 = 1),
        // engine advances view, NewView broadcast.
        maybe_emit_view_timeout(
            &mut engine, &mut view_state, 2, Some(2), false, Some(&facade), &mut stats,
        );
        assert_eq!(stats.view_timeouts_emitted, 1);
        assert_eq!(*facade.timeouts_sent.lock().unwrap(), 1);
        assert_eq!(stats.timeout_certificates_formed, 1);
        assert_eq!(stats.view_timeout_advances, 1);
        assert_eq!(stats.outbound_new_views_sent, 1);
        assert_eq!(*facade.new_views_sent.lock().unwrap(), 1);
        assert!(
            engine.current_view() > from_view,
            "TC application must advance current_view (was {}, now {})",
            from_view,
            engine.current_view()
        );

        // The NewView bytes round-trip to a valid TC for the timed-out view.
        let bytes = facade.last_new_view_bytes.lock().unwrap().clone().unwrap();
        let decoded: TimeoutCertificate<[u8; 32]> = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.timeout_view, from_view);
        assert_eq!(decoded.view, from_view + 1);
    }

    /// Export check for the same real B14 activity as Test E: the
    /// `/metrics` family mirrors the already-maintained in-process stats.
    #[test]
    fn b14_metrics_export_matches_self_quorum_activity_stats() {
        let mut engine = b14_make_engine(1, 0);
        assert!(engine.try_advance_to_view(7));
        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut view_state =
            ViewTimeoutState::new(engine.current_view(), engine.commit_log().len() as u64);
        let metrics = Arc::new(NodeMetrics::new());

        maybe_emit_view_timeout(
            &mut engine, &mut view_state, 2, Some(2), false, Some(&facade), &mut stats,
        );
        update_binary_view_timeout_metrics(&metrics, &stats);

        assert_eq!(stats.view_timeouts_emitted, 1);
        assert_eq!(stats.timeout_certificates_formed, 1);
        assert_eq!(stats.outbound_new_views_sent, 1);
        assert_eq!(stats.view_timeout_advances, 1);
        let output = metrics.format_metrics();
        assert!(output.contains("qbind_consensus_view_timeouts_emitted_total 1"));
        assert!(output.contains("qbind_consensus_timeout_certificates_formed_total 1"));
        assert!(output.contains("qbind_consensus_outbound_new_views_sent_total 1"));
        assert!(output.contains("qbind_consensus_view_timeout_advances_total 1"));
        assert!(output.contains("qbind_consensus_inbound_timeouts_delivered_total 0"));
        assert!(output.contains("consensus_net_inbound_total{kind=\"vote\"} 0"));
    }

    /// Test F (fail-closed): malformed `Timeout(bytes)` bytes ingested
    /// via the inbound handler do NOT mutate engine state; the
    /// `view_timeout_decode_failures` counter increments.
    #[test]
    fn b14_inbound_malformed_timeout_fails_closed() {
        let mut engine = b14_make_engine(4, 0);
        assert!(engine.try_advance_to_view(15));
        let view_before = engine.current_view();
        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut restore_mode = RestoreCatchupModeState::from_config(None);
        let metrics = Arc::new(NodeMetrics::new());

        handle_inbound_consensus_msg(
            &mut engine,
            ConsensusNetMsg::Timeout(vec![0xff, 0xfe, 0xfd]),
            &mut stats,
            Some(&facade),
            &metrics,
            ValidatorId::new(0),
            &mut restore_mode,
        );
        assert_eq!(engine.current_view(), view_before);
        assert_eq!(stats.inbound_timeouts_delivered, 0);
        assert_eq!(stats.inbound_timeouts_engine_accepted, 0);
        assert_eq!(stats.view_timeout_decode_failures, 1);
        assert_eq!(stats.inbound_decode_failures, 1);
        assert_eq!(*facade.new_views_sent.lock().unwrap(), 0);
        let output = metrics.format_metrics();
        assert!(output.contains("qbind_consensus_view_timeout_decode_failures_total 1"));
        assert!(output.contains("qbind_consensus_inbound_timeouts_delivered_total 0"));
        assert!(output.contains("qbind_consensus_view_timeout_engine_rejects_total 0"));

        // Malformed NewView same shape.
        handle_inbound_consensus_msg(
            &mut engine,
            ConsensusNetMsg::NewView(vec![0xaa, 0xbb]),
            &mut stats,
            Some(&facade),
            &metrics,
            ValidatorId::new(0),
            &mut restore_mode,
        );
        assert_eq!(engine.current_view(), view_before);
        assert_eq!(stats.inbound_new_views_delivered, 0);
        assert_eq!(stats.view_timeout_decode_failures, 2);
        assert_eq!(stats.inbound_decode_failures, 2);
        let output = metrics.format_metrics();
        assert!(output.contains("qbind_consensus_view_timeout_decode_failures_total 2"));
        assert!(output.contains("qbind_consensus_inbound_new_views_delivered_total 0"));
    }

    /// Test G: inbound `NewView(bytes)` carrying a structurally valid
    /// TC advances the receiver's view. We construct the TC by having
    /// 3 of 4 validators sign locally (≥ 2/3 quorum for N=4) — this
    /// is what Test H also relies on, but here we synthesize the TC
    /// directly to isolate the NewView ingestion path.
    #[test]
    fn b14_inbound_new_view_with_valid_tc_advances_view() {
        let mut engine = b14_make_engine(4, 0);
        assert!(engine.try_advance_to_view(15));
        let view_before = engine.current_view();

        // Hand-built TC: timed_out_view=15, signers={V1,V2,V3}.
        let tc: TimeoutCertificate<[u8; 32]> = TimeoutCertificate::new(
            15,
            None,
            vec![ValidatorId::new(1), ValidatorId::new(2), ValidatorId::new(3)],
        );
        let bytes = bincode::serialize(&tc).unwrap();

        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut restore_mode = RestoreCatchupModeState::from_config(None);
        let metrics = Arc::new(NodeMetrics::new());

        handle_inbound_consensus_msg(
            &mut engine,
            ConsensusNetMsg::NewView(bytes),
            &mut stats,
            Some(&facade),
            &metrics,
            ValidatorId::new(0),
            &mut restore_mode,
        );
        assert_eq!(stats.inbound_new_views_delivered, 1);
        assert_eq!(stats.inbound_new_views_engine_accepted, 1);
        assert_eq!(stats.view_timeout_advances, 1);
        assert!(
            engine.current_view() > view_before,
            "valid NewView TC must advance view (was {}, now {})",
            view_before,
            engine.current_view()
        );
        // The new view should equal `tc.view` = 16.
        assert_eq!(engine.current_view(), 16);
    }

    /// Test G2 (fail-closed quorum): a structurally decodable TC with
    /// fewer than 2/3 signers must be rejected by the engine; the
    /// view stays put.
    #[test]
    fn b14_inbound_new_view_insufficient_quorum_fails_closed() {
        let mut engine = b14_make_engine(4, 0);
        assert!(engine.try_advance_to_view(15));
        let view_before = engine.current_view();
        // Only 1 signer in N=4 — well below 2/3.
        let tc: TimeoutCertificate<[u8; 32]> =
            TimeoutCertificate::new(15, None, vec![ValidatorId::new(1)]);
        let bytes = bincode::serialize(&tc).unwrap();

        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut restore_mode = RestoreCatchupModeState::from_config(None);
        let metrics = Arc::new(NodeMetrics::new());

        handle_inbound_consensus_msg(
            &mut engine,
            ConsensusNetMsg::NewView(bytes),
            &mut stats,
            Some(&facade),
            &metrics,
            ValidatorId::new(0),
            &mut restore_mode,
        );
        assert_eq!(stats.inbound_new_views_delivered, 1);
        assert_eq!(stats.inbound_new_views_engine_accepted, 0);
        assert_eq!(stats.view_timeout_engine_rejects, 1);
        assert_eq!(engine.current_view(), view_before);
        let output = metrics.format_metrics();
        assert!(output.contains("qbind_consensus_inbound_new_views_delivered_total 1"));
        assert!(output.contains("qbind_consensus_inbound_new_views_engine_accepted_total 0"));
        assert!(output.contains("qbind_consensus_view_timeout_engine_rejects_total 1"));
    }

    /// Test H (Run-015 absent-leader N=4 shape, end-to-end): local V0
    /// emits its own TimeoutMsg via the loop's primitive, then two
    /// peer Timeouts arrive over the inbound channel. After the third
    /// (≥ 2f+1 = 3 out of 4), the engine forms a TC, the loop applies
    /// it, broadcasts NewView, and the parked view 15 advances to 16.
    /// Round-robin leader for view 16 = 16 % 4 = 0 — i.e. V0 itself,
    /// which is present. The cluster has left the absent-leader view.
    #[test]
    fn b14_run_015_n4_absent_leader_shape_advances_via_tc() {
        let mut engine = b14_make_engine(4, 0);
        assert!(engine.try_advance_to_view(15));
        assert_eq!(engine.leader_for_view(15), ValidatorId::new(3));

        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut restore_mode = RestoreCatchupModeState::from_config(None);
        let mut view_state =
            ViewTimeoutState::new(engine.current_view(), engine.commit_log().len() as u64);
        let metrics = Arc::new(NodeMetrics::new());

        // 1) Local V0 times out (window=2, tick=2 ⇒ emit).
        maybe_emit_view_timeout(
            &mut engine,
            &mut view_state,
            1,
            Some(2),
            false,
            Some(&facade),
            &mut stats,
        );
        maybe_emit_view_timeout(
            &mut engine,
            &mut view_state,
            2,
            Some(2),
            false,
            Some(&facade),
            &mut stats,
        );
        assert_eq!(stats.view_timeouts_emitted, 1);
        assert_eq!(*facade.timeouts_sent.lock().unwrap(), 1);
        // Only 1/4 timeouts so far (own) ⇒ no TC, no advance.
        assert_eq!(stats.timeout_certificates_formed, 0);
        assert_eq!(engine.current_view(), 15);

        // 2) Inbound timeout from V1.
        let v1_timeout: qbind_consensus::timeout::TimeoutMsg<[u8; 32]> =
            qbind_consensus::timeout::TimeoutMsg::new(15, None, ValidatorId::new(1));
        let v1_bytes = bincode::serialize(&v1_timeout).unwrap();
        handle_inbound_consensus_msg(
            &mut engine,
            ConsensusNetMsg::Timeout(v1_bytes),
            &mut stats,
            Some(&facade),
            &metrics,
            ValidatorId::new(0),
            &mut restore_mode,
        );
        // 2/4 timeouts ⇒ still no TC, view still 15.
        assert_eq!(stats.inbound_timeouts_delivered, 1);
        assert_eq!(stats.inbound_timeouts_engine_accepted, 1);
        assert_eq!(stats.timeout_certificates_formed, 0);
        assert_eq!(engine.current_view(), 15);

        // 3) Inbound timeout from V2 — third timeout = 2f+1 = 3
        // crosses threshold, TC forms inside the engine, the
        // inbound handler applies it locally and broadcasts NewView.
        let v2_timeout: qbind_consensus::timeout::TimeoutMsg<[u8; 32]> =
            qbind_consensus::timeout::TimeoutMsg::new(15, None, ValidatorId::new(2));
        let v2_bytes = bincode::serialize(&v2_timeout).unwrap();
        handle_inbound_consensus_msg(
            &mut engine,
            ConsensusNetMsg::Timeout(v2_bytes),
            &mut stats,
            Some(&facade),
            &metrics,
            ValidatorId::new(0),
            &mut restore_mode,
        );
        assert_eq!(stats.inbound_timeouts_delivered, 2);
        assert_eq!(stats.inbound_timeouts_engine_accepted, 2);
        assert_eq!(stats.timeout_certificates_formed, 1);
        assert_eq!(stats.view_timeout_advances, 1);
        assert_eq!(stats.outbound_new_views_sent, 1);
        assert_eq!(*facade.new_views_sent.lock().unwrap(), 1);
        assert_eq!(engine.current_view(), 16);
        // Run-015 boundary cleared: the new view's leader is no
        // longer the absent V3.
        assert_ne!(engine.leader_for_view(16), ValidatorId::new(3));
        assert_eq!(engine.leader_for_view(16), ValidatorId::new(0));
    }

    /// Test F2 (defense-in-depth): an oversized `Timeout(bytes)` payload
    /// (above `MAX_INBOUND_TIMEOUT_FRAME_BYTES`) is rejected without
    /// invoking bincode at all and counts under the same fail-closed
    /// counters. This protects against a hostile peer driving memory
    /// exhaustion via an oversized length prefix.
    #[test]
    fn b14_inbound_oversized_timeout_fails_closed() {
        let mut engine = b14_make_engine(4, 0);
        assert!(engine.try_advance_to_view(15));
        let view_before = engine.current_view();
        let facade = B14RecordingFacade::default();
        let mut stats = BinaryConsensusLoopInboundStats::default();
        let mut restore_mode = RestoreCatchupModeState::from_config(None);
        let metrics = Arc::new(NodeMetrics::new());

        // Build a payload one byte over the cap.
        let oversized = vec![0u8; MAX_INBOUND_TIMEOUT_FRAME_BYTES + 1];
        handle_inbound_consensus_msg(
            &mut engine,
            ConsensusNetMsg::Timeout(oversized),
            &mut stats,
            Some(&facade),
            &metrics,
            ValidatorId::new(0),
            &mut restore_mode,
        );
        assert_eq!(engine.current_view(), view_before);
        assert_eq!(stats.inbound_timeouts_delivered, 0);
        assert_eq!(stats.view_timeout_decode_failures, 1);
        assert_eq!(stats.inbound_decode_failures, 1);

        // Same shape for NewView.
        let oversized2 = vec![0u8; MAX_INBOUND_TIMEOUT_FRAME_BYTES + 1];
        handle_inbound_consensus_msg(
            &mut engine,
            ConsensusNetMsg::NewView(oversized2),
            &mut stats,
            Some(&facade),
            &metrics,
            ValidatorId::new(0),
            &mut restore_mode,
        );
        assert_eq!(engine.current_view(), view_before);
        assert_eq!(stats.inbound_new_views_delivered, 0);
        assert_eq!(stats.view_timeout_decode_failures, 2);
        assert_eq!(stats.inbound_decode_failures, 2);
    }

    /// Test I: B14 must not regress the non-restore single-validator
    /// binary path. This is identical in shape to the long-standing
    /// `single_validator_loop_advances_views_and_commits` test, but
    /// runs with the default config (which now has
    /// `view_timeout_ticks = Some(50)` enabled). The single-validator
    /// loop drives QC-based view advances on every tick, so the
    /// timeout window never elapses and no `TimeoutMsg` is ever
    /// emitted. The point of this test is to assert exactly that.
    #[tokio::test]
    async fn b14_single_validator_loop_does_not_emit_timeouts() {
        let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
            .with_tick_interval(Duration::from_millis(2))
            .with_max_ticks(60); // > default view_timeout_ticks (50)
        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let progress =
            Arc::new(parking_lot::Mutex::new(BinaryConsensusLoopProgress::default()));
        let metrics = Arc::new(NodeMetrics::new());
        let final_progress = run_binary_consensus_loop(
            cfg,
            shutdown_rx,
            progress.clone(),
            Arc::clone(&metrics),
        )
        .await;
        // QC-driven progression must have occurred.
        assert!(final_progress.proposals_emitted > 0);
        assert!(final_progress.current_view > 0);
        // No timeout fired (every tick had forward progress).
        assert_eq!(
            final_progress.inbound.view_timeouts_emitted, 0,
            "single-validator loop has constant forward progress; no timeout should ever fire"
        );
        assert_eq!(final_progress.inbound.timeout_certificates_formed, 0);
        assert_eq!(final_progress.inbound.view_timeout_advances, 0);
        let output = metrics.format_metrics();
        assert!(output.contains("qbind_consensus_view_timeouts_emitted_total 0"));
        assert!(output.contains("qbind_consensus_timeout_certificates_formed_total 0"));
        assert!(output.contains("qbind_consensus_view_timeout_advances_total 0"));
        assert!(output.contains("qbind_consensus_view_timeout_decode_failures_total 0"));
    }
}