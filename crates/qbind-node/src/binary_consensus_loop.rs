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

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use qbind_consensus::basic_hotstuff_engine::BasicHotStuffEngine;
use qbind_consensus::driver::ConsensusEngineAction;
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};

use crate::consensus_network_facade::ConsensusNetworkFacade;
use crate::metrics::NodeMetrics;
use crate::p2p::ConsensusNetMsg;

/// Default tick interval for the binary consensus loop.
///
/// Matches `AsyncNodeRunner` defaults (100 ms). Long enough to keep CPU low
/// for an idle node; short enough that single-validator commits visibly
/// advance during smoke tests.
pub const DEFAULT_BINARY_CONSENSUS_TICK_INTERVAL: Duration = Duration::from_millis(100);

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
}

impl std::fmt::Debug for BinaryConsensusLoopIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryConsensusLoopIo")
            .field("inbound_rx", &"<mpsc::Receiver<ConsensusNetMsg>>")
            .field("outbound", &"<Arc<dyn ConsensusNetworkFacade>>")
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

    let (mut inbound_rx, outbound_facade): (
        Option<mpsc::Receiver<ConsensusNetMsg>>,
        Option<Arc<dyn ConsensusNetworkFacade>>,
    ) = match io {
        Some(io) => (Some(io.inbound_rx), Some(io.outbound)),
        None => (None, None),
    };

    eprintln!(
        "[binary-consensus] Starting consensus loop: local_id={:?} num_validators={} tick={}ms \
         restore_baseline={} interconnect={}",
        cfg.local_validator_id,
        cfg.num_validators,
        cfg.tick_interval.as_millis(),
        cfg.restore_baseline.is_some(),
        if outbound_facade.is_some() { "p2p" } else { "none" },
    );

    let mut ticker = tokio::time::interval(cfg.tick_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut ticks: u64 = 0;
    let mut proposals_emitted: u64 = 0;
    let mut last_commits: u64 = 0;
    let mut last_view: u64 = engine.current_view();
    let mut inbound_stats = BinaryConsensusLoopInboundStats::default();

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
                            // Refresh progress snapshot.
                            {
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
                    );
                    update_state_metrics(
                        &engine,
                        &metrics,
                        &mut last_commits,
                        &mut last_view,
                        tick_started.elapsed(),
                    );
                    {
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
                    );
                    update_state_metrics(
                        &engine,
                        &metrics,
                        &mut last_commits,
                        &mut last_view,
                        tick_started.elapsed(),
                    );
                    {
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
         outbound_proposals={} outbound_votes={}",
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
    );
    final_progress
}

/// Drive a single leader-step tick of the engine and forward any resulting
/// network actions through the (optional) outbound facade.
fn do_leader_tick(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    proposals_emitted: &mut u64,
    metrics: &Arc<NodeMetrics>,
    inbound_stats: &mut BinaryConsensusLoopInboundStats,
    outbound: Option<&dyn ConsensusNetworkFacade>,
) {
    let actions = engine.try_propose();
    let mut tick_proposals: u64 = 0;
    for action in &actions {
        if matches!(action, ConsensusEngineAction::BroadcastProposal(_)) {
            *proposals_emitted = proposals_emitted.saturating_add(1);
            tick_proposals = tick_proposals.saturating_add(1);
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
) {
    use qbind_wire::consensus::{BlockProposal, Vote};
    use qbind_wire::io::WireDecode;

    stats.inbound_msgs_received = stats.inbound_msgs_received.saturating_add(1);

    match msg {
        ConsensusNetMsg::Proposal(bytes) => {
            let mut slice: &[u8] = &bytes;
            match BlockProposal::decode(&mut slice) {
                Ok(proposal) => {
                    let from = ValidatorId::new(proposal.header.proposer_index as u64);
                    stats.inbound_proposals_delivered =
                        stats.inbound_proposals_delivered.saturating_add(1);
                    if let Some(action) = engine.on_proposal_event(from, &proposal) {
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
    *last_commits = new_commits_total;
    *last_view = new_view;
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
}