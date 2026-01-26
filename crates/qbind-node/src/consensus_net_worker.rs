//! Async consensus network worker for qbind post-quantum blockchain.
//!
//! This module provides `ConsensusNetWorker`, an async worker that bridges the
//! existing network stack to the `AsyncNodeRunner` via the `ConsensusEventSender`
//! channel.
//!
//! # Design (T87)
//!
//! The consensus network worker establishes a clear separation:
//! - **Network worker(s)**: Async tasks that manage sockets, KEMTLS sessions,
//!   encoding/decoding, and produce `ConsensusNetworkEvent<PeerId>` objects.
//! - **Runtime**: `AsyncNodeRunner` consuming `ConsensusEvent` and driving the harness.
//! - **Consensus core**: `NodeHotstuffHarness` + HotStuff engines, synchronous.
//!
//! # Data Flow
//!
//! ```text
//! Network → ConsensusNetWorker → ConsensusEventSender → AsyncNodeRunner → NodeHotstuffHarness
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use qbind_node::consensus_net_worker::{ConsensusNetWorker, ConsensusNetService};
//! use qbind_node::async_runner::{AsyncNodeRunner, ConsensusEventSender};
//!
//! // Create the network service
//! let net_service = MyNetService::new(/* ... */);
//!
//! // Create the runner and get the event sender
//! let (runner, events_tx) = AsyncNodeRunner::new(harness, tick_interval);
//!
//! // Create the network worker
//! let net_worker = ConsensusNetWorker::new(net_service, events_tx);
//!
//! // Run both concurrently
//! tokio::select! {
//!     res = runner.run() => { /* handle consensus loop result */ }
//!     res = net_worker.run() => { /* handle network worker result */ }
//! }
#![allow(clippy::type_complexity)]
//! ```

use crate::async_runner::{ConsensusEvent, ConsensusEventSender};
use crate::channel_config::ChannelCapacityConfig;
use crate::peer::PeerId;
use qbind_consensus::network::{ConsensusNetworkEvent, NetworkError};
use qbind_wire::consensus::{BlockProposal, Vote};

// ============================================================================
// ConsensusNetService trait
// ============================================================================

/// Trait for the underlying async network service.
///
/// This trait abstracts the consensus layer's view of the network for async
/// operations. Implementors provide:
/// - Async receive of incoming consensus events
/// - Async send of outbound consensus messages
///
/// # Design Notes
///
/// - This is intentionally a simple trait that can wrap the existing
///   `ConsensusNetwork` trait or any other network implementation.
/// - The trait uses `&mut self` for `recv()` to allow stateful network
///   implementations (e.g., those tracking connection state).
/// - The `send_*` methods are provided for outbound messages but are not
///   used by the inbound worker loop.
///
/// # ID Type
///
/// The trait uses `PeerId` as the peer identifier type, matching the
/// existing `ConsensusNetAdapter` implementation in the node.
pub trait ConsensusNetService: Send {
    /// Asynchronously receive the next consensus network event.
    ///
    /// This method should:
    /// - Return `Some(event)` when a consensus message is available
    /// - Return `None` when the network is closed or shutting down
    ///
    /// The implementation may block internally (via async) waiting for
    /// the next event from the network.
    ///
    /// # Implementation Notes
    ///
    /// For implementations wrapping synchronous network code, consider using
    /// `tokio::task::spawn_blocking` or a separate thread to avoid blocking
    /// the async runtime.
    fn recv(
        &mut self,
    ) -> impl std::future::Future<Output = Option<ConsensusNetworkEvent<PeerId>>> + Send;

    /// Asynchronously send a vote to a specific peer.
    ///
    /// # Arguments
    ///
    /// - `to`: The peer ID to send the vote to
    /// - `vote`: The vote message to send
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(NetworkError)` on failure.
    fn send_vote_to(
        &mut self,
        to: PeerId,
        vote: &Vote,
    ) -> impl std::future::Future<Output = Result<(), NetworkError>> + Send;

    /// Asynchronously broadcast a vote to all peers.
    ///
    /// # Arguments
    ///
    /// - `vote`: The vote message to broadcast
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(NetworkError)` on failure.
    fn broadcast_vote(
        &mut self,
        vote: &Vote,
    ) -> impl std::future::Future<Output = Result<(), NetworkError>> + Send;

    /// Asynchronously broadcast a block proposal to all peers.
    ///
    /// # Arguments
    ///
    /// - `proposal`: The block proposal to broadcast
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(NetworkError)` on failure.
    fn broadcast_proposal(
        &mut self,
        proposal: &BlockProposal,
    ) -> impl std::future::Future<Output = Result<(), NetworkError>> + Send;
}

// ============================================================================
// ConsensusNetSender trait
// ============================================================================

/// Trait for sending outbound consensus messages.
///
/// This trait provides a minimal interface for the consensus layer to send
/// outbound messages (votes, proposals) without depending on the full
/// network implementation.
///
/// # Design Notes
///
/// - This trait is synchronous by design, as the consensus core is synchronous.
/// - Implementations may buffer messages and send them asynchronously.
/// - The trait is `Send + Sync` to allow sharing across threads.
pub trait ConsensusNetSender: Send + Sync {
    /// Send a vote to a specific peer.
    fn send_vote_to(&self, to: PeerId, vote: &Vote) -> Result<(), NetworkError>;

    /// Broadcast a vote to all peers.
    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError>;

    /// Broadcast a block proposal to all peers.
    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError>;
}

// ============================================================================
// ConsensusNetWorkerError
// ============================================================================

/// Error type for `ConsensusNetWorker` operations.
#[derive(Debug)]
pub enum ConsensusNetWorkerError {
    /// The event channel was closed (receiver dropped).
    ChannelClosed,
    /// Network error during operation.
    Network(NetworkError),
    /// The network returned None (graceful shutdown).
    NetworkClosed,
}

impl std::fmt::Display for ConsensusNetWorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusNetWorkerError::ChannelClosed => {
                write!(f, "consensus event channel closed")
            }
            ConsensusNetWorkerError::Network(e) => {
                write!(f, "network error: {}", e)
            }
            ConsensusNetWorkerError::NetworkClosed => {
                write!(f, "network closed")
            }
        }
    }
}

impl std::error::Error for ConsensusNetWorkerError {}

impl From<NetworkError> for ConsensusNetWorkerError {
    fn from(e: NetworkError) -> Self {
        ConsensusNetWorkerError::Network(e)
    }
}

// ============================================================================
// ConsensusNetWorker
// ============================================================================

/// Async consensus network worker that bridges the network to the event channel.
///
/// This worker:
/// 1. Listens for incoming consensus network events using the network service
/// 2. Forwards each event to the `ConsensusEventSender` as
///    `ConsensusEvent::IncomingMessage(Box<ConsensusNetworkEvent<PeerId>>)`
/// 3. Handles graceful shutdown when the network closes or the channel is dropped
///
/// # Observability (T89)
///
/// When configured with `NodeMetrics`, the worker tracks:
/// - Inbound message counts by type (vote, proposal, other)
/// - Channel closure events
///
/// # Type Parameter
///
/// - `N`: The network service type implementing `ConsensusNetService`
///
/// # Lifecycle
///
/// The worker exits when:
/// - `recv()` returns `None` (network closed)
/// - The event channel is closed (all receivers dropped)
///
/// # Example
///
/// ```ignore
/// let net_worker = ConsensusNetWorker::new(net_service, events_tx);
///
/// // Run as a separate task
/// let net_handle = tokio::spawn(net_worker.run());
///
/// // Or run concurrently with the main loop
/// tokio::select! {
///     res = runner.run() => { /* ... */ }
///     res = net_worker.run() => { /* ... */ }
/// }
/// ```
pub struct ConsensusNetWorker<N> {
    /// The underlying network service.
    net: N,
    /// Sender for consensus events.
    events_tx: ConsensusEventSender,
    /// Optional metrics for observability (T89).
    metrics: Option<std::sync::Arc<crate::metrics::NodeMetrics>>,
}

impl<N> std::fmt::Debug for ConsensusNetWorker<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsensusNetWorker")
            .field("net", &"<ConsensusNetService>")
            .field("events_tx", &"<ConsensusEventSender>")
            .field("metrics", &self.metrics.is_some())
            .finish()
    }
}

impl<N: ConsensusNetService> ConsensusNetWorker<N> {
    /// Create a new `ConsensusNetWorker` with the given network service and event sender.
    ///
    /// # Arguments
    ///
    /// - `net`: The network service implementing `ConsensusNetService`
    /// - `events_tx`: The sender half of the consensus event channel
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (runner, events_tx) = AsyncNodeRunner::new(harness, tick_interval);
    /// let net_worker = ConsensusNetWorker::new(net_service, events_tx);
    /// ```
    pub fn new(net: N, events_tx: ConsensusEventSender) -> Self {
        ConsensusNetWorker {
            net,
            events_tx,
            metrics: None,
        }
    }

    /// Create a new `ConsensusNetWorker` with metrics enabled.
    ///
    /// # Arguments
    ///
    /// - `net`: The network service implementing `ConsensusNetService`
    /// - `events_tx`: The sender half of the consensus event channel
    /// - `metrics`: Shared metrics instance for observability
    pub fn with_metrics(
        net: N,
        events_tx: ConsensusEventSender,
        metrics: std::sync::Arc<crate::metrics::NodeMetrics>,
    ) -> Self {
        ConsensusNetWorker {
            net,
            events_tx,
            metrics: Some(metrics),
        }
    }

    /// Access the underlying network service.
    pub fn net(&self) -> &N {
        &self.net
    }

    /// Mutably access the underlying network service.
    pub fn net_mut(&mut self) -> &mut N {
        &mut self.net
    }

    /// Run the network worker loop.
    ///
    /// This method:
    /// 1. Loops on `net.recv().await`
    /// 2. For each `ConsensusNetworkEvent<PeerId>`:
    ///    - Wraps it in `ConsensusEvent::IncomingMessage(Box::new(event))`
    ///    - Sends it to `events_tx`
    ///    - Increments inbound metrics (if configured)
    /// 3. Handles send errors (channel closed) by logging and returning
    /// 4. Exits when `recv()` returns `None` (network closed)
    ///
    /// # Returns
    ///
    /// - `Ok(())` on graceful shutdown (network closed or channel dropped)
    /// - `Err(ConsensusNetWorkerError)` on fatal errors
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Run as a spawned task
    /// let handle = tokio::spawn(async move {
    ///     if let Err(e) = net_worker.run().await {
    ///         eprintln!("Network worker error: {}", e);
    ///     }
    /// });
    /// ```
    pub async fn run(mut self) -> Result<(), ConsensusNetWorkerError> {
        eprintln!("[ConsensusNetWorker] Starting network worker loop");

        loop {
            // Receive the next consensus network event
            let maybe_event = self.net.recv().await;

            match maybe_event {
                Some(event) => {
                    // Record inbound metrics by event type (T89)
                    if let Some(ref metrics) = self.metrics {
                        match &event {
                            ConsensusNetworkEvent::IncomingVote { .. } => {
                                metrics.network().inc_inbound_vote();
                            }
                            ConsensusNetworkEvent::IncomingProposal { .. } => {
                                metrics.network().inc_inbound_proposal();
                            }
                        }
                    }

                    // Wrap the event in ConsensusEvent::IncomingMessage
                    let consensus_event = ConsensusEvent::IncomingMessage(Box::new(event));

                    // Try to send to the event channel
                    if let Err(e) = self.events_tx.send(consensus_event).await {
                        // Channel closed - receiver dropped
                        if let Some(ref metrics) = self.metrics {
                            metrics.network().inc_inbound_channel_closed();
                        }
                        eprintln!(
                            "[ConsensusNetWorker] Event channel closed, exiting: {:?}",
                            e
                        );
                        return Ok(());
                    }
                }
                None => {
                    // Network closed - graceful shutdown
                    eprintln!("[ConsensusNetWorker] Network closed, exiting");
                    return Ok(());
                }
            }
        }
    }
}

// ============================================================================
// Priority-based message sending (T90.3)
// ============================================================================

/// Priority levels for outbound consensus messages.
///
/// This enum determines how messages are routed through the outbound channels:
/// - `Critical`: Never dropped; routed through a retry/backpressure worker.
/// - `Normal`: May be dropped under load; uses bounded channel with try_send.
/// - `Low`: May be dropped under load; lowest priority for non-essential messages.
///
/// # Priority Policy (T90.3)
///
/// **Critical** priority is for:
/// - Proposals for the current view/round
/// - Votes for the current view/current Pacemaker round
/// - Any messages required for safety/liveness of the active round
///
/// **Normal** priority is for:
/// - Standard votes/proposals not obviously critical
/// - Slightly delayed messages
///
/// **Low** priority is for:
/// - Optional gossip
/// - Non-essential rebroadcasts
/// - (Reserved for future use; treat as Normal if unused)
///
/// # Current Implementation
///
/// Currently, all votes and proposals are treated as `Critical` to ensure
/// consensus liveness. Future work will refine classification based on
/// whether the message is for the "current round" vs older rounds.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ConsensusMsgPriority {
    /// Critical messages are never dropped. They are routed through a
    /// dedicated retry worker that uses async `send().await` for backpressure.
    Critical,
    /// Normal messages may be dropped if the channel is full.
    /// Uses `try_send` with metrics on drops.
    Normal,
    /// Low priority messages may be dropped under load.
    /// Reserved for non-essential gossip/rebroadcasts.
    Low,
}

impl Default for ConsensusMsgPriority {
    /// Default priority is `Normal` for backwards compatibility.
    fn default() -> Self {
        ConsensusMsgPriority::Normal
    }
}

// ============================================================================
// AsyncConsensusNetAdapter - Production async adapter (T88)
// ============================================================================

/// Async command variants for outbound network operations.
///
/// These commands are sent via an mpsc channel to the async network loop,
/// which processes them and sends the actual messages over the network.
///
/// # Priority (T90.3)
///
/// Each command carries a `priority` field that determines how the message
/// is routed:
/// - `Critical`: Sent via an unbounded retry channel, never dropped.
/// - `Normal`/`Low`: Sent via bounded channel with `try_send`, may be dropped.
#[derive(Debug, Clone)]
pub enum OutboundCommand {
    /// Send a vote to a specific peer.
    SendVoteTo {
        to: PeerId,
        vote: Vote,
        priority: ConsensusMsgPriority,
    },
    /// Broadcast a vote to all peers.
    BroadcastVote {
        vote: Vote,
        priority: ConsensusMsgPriority,
    },
    /// Broadcast a proposal to all peers.
    BroadcastProposal {
        proposal: BlockProposal,
        priority: ConsensusMsgPriority,
    },
}

impl OutboundCommand {
    /// Get the priority of this command.
    pub fn priority(&self) -> ConsensusMsgPriority {
        match self {
            OutboundCommand::SendVoteTo { priority, .. } => *priority,
            OutboundCommand::BroadcastVote { priority, .. } => *priority,
            OutboundCommand::BroadcastProposal { priority, .. } => *priority,
        }
    }

    /// Returns true if this command is critical priority.
    pub fn is_critical(&self) -> bool {
        self.priority() == ConsensusMsgPriority::Critical
    }
}

/// A real async consensus network adapter implementing `ConsensusNetService`.
///
/// This adapter wraps the existing blocking `PeerManager` / `NetService` and
/// provides an async interface by:
/// - Using an internal mpsc channel for inbound events (filled by a blocking task)
/// - Using `tokio::task::spawn_blocking` for outbound sends
///
/// # Design (T88)
///
/// This is an **interim** implementation that bridges the blocking network code
/// to the async Tokio runtime. The blocking operations are contained within
/// `spawn_blocking` calls to avoid blocking the Tokio runtime.
///
/// A future task will replace the underlying `PeerManager` with a truly async
/// implementation using `tokio::net::TcpStream` and `tokio::net::TcpListener`.
///
/// # Thread Safety
///
/// The adapter uses `Arc<Mutex<...>>` for shared state between the async
/// runtime and the blocking tasks. This is acceptable for correctness but
/// may introduce contention under high load.
///
/// # Usage
///
/// ```ignore
/// use qbind_node::consensus_net_worker::{AsyncConsensusNetAdapter, ConsensusNetService};
///
/// // Create the adapter
/// let (adapter, inbound_tx) = AsyncConsensusNetAdapter::new();
///
/// // Spawn a background task to feed inbound events
/// tokio::spawn(async move {
///     // ... poll blocking network and send to inbound_tx ...
/// });
///
/// // Use the adapter with ConsensusNetWorker
/// let worker = ConsensusNetWorker::new(adapter, events_tx);
/// ```
pub struct AsyncConsensusNetAdapter {
    /// Receiver for inbound consensus events.
    /// Events are pushed here by a separate task that polls the blocking network.
    inbound_rx: tokio::sync::mpsc::Receiver<ConsensusNetworkEvent<PeerId>>,

    /// Sender for outbound commands.
    /// Commands are processed by a separate task that sends to the blocking network.
    outbound_tx: tokio::sync::mpsc::Sender<OutboundCommand>,

    /// Flag indicating whether the adapter is shutting down.
    shutdown: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for AsyncConsensusNetAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncConsensusNetAdapter")
            .field("inbound_rx", &"<mpsc::Receiver>")
            .field("outbound_tx", &"<mpsc::Sender>")
            .field("shutdown", &self.shutdown)
            .finish()
    }
}

/// Sender half for inbound events to the `AsyncConsensusNetAdapter`.
///
/// This type is returned from `AsyncConsensusNetAdapter::new()` and should be
/// used by a background task to feed inbound events into the adapter.
pub type InboundEventSender = tokio::sync::mpsc::Sender<ConsensusNetworkEvent<PeerId>>;

/// Receiver half for outbound commands from the `AsyncConsensusNetAdapter`.
///
/// This type is returned from `AsyncConsensusNetAdapter::new()` and should be
/// used by a background task to process outbound commands.
pub type OutboundCommandReceiver = tokio::sync::mpsc::Receiver<OutboundCommand>;

impl AsyncConsensusNetAdapter {
    /// Default capacity for the inbound event channel.
    pub const DEFAULT_INBOUND_CAPACITY: usize = 1024;

    /// Default capacity for the outbound command channel.
    pub const DEFAULT_OUTBOUND_CAPACITY: usize = 1024;

    /// Create a new `AsyncConsensusNetAdapter` with default channel capacities.
    ///
    /// Returns a tuple of:
    /// - The adapter itself (for use with `ConsensusNetWorker`)
    /// - The inbound event sender (for a background task to push events)
    /// - The outbound command receiver (for a background task to process commands)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (adapter, inbound_tx, outbound_rx) = AsyncConsensusNetAdapter::new();
    ///
    /// // Spawn inbound task
    /// tokio::spawn(async move {
    ///     loop {
    ///         // Poll blocking network...
    ///         let event = poll_network_blocking();
    ///         if inbound_tx.send(event).await.is_err() {
    ///             break; // Adapter dropped
    ///         }
    ///     }
    /// });
    ///
    /// // Spawn outbound task
    /// tokio::spawn(async move {
    ///     while let Some(cmd) = outbound_rx.recv().await {
    ///         // Process command with blocking network...
    ///     }
    /// });
    /// ```
    pub fn new() -> (Self, InboundEventSender, OutboundCommandReceiver) {
        Self::with_capacity(
            Self::DEFAULT_INBOUND_CAPACITY,
            Self::DEFAULT_OUTBOUND_CAPACITY,
        )
    }

    /// Create a new `AsyncConsensusNetAdapter` with custom channel capacities.
    ///
    /// # Arguments
    ///
    /// - `inbound_capacity`: Buffer size for the inbound event channel
    /// - `outbound_capacity`: Buffer size for the outbound command channel
    pub fn with_capacity(
        inbound_capacity: usize,
        outbound_capacity: usize,
    ) -> (Self, InboundEventSender, OutboundCommandReceiver) {
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(inbound_capacity);
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(outbound_capacity);

        let adapter = AsyncConsensusNetAdapter {
            inbound_rx,
            outbound_tx,
            shutdown: std::sync::atomic::AtomicBool::new(false),
        };

        (adapter, inbound_tx, outbound_rx)
    }

    /// Create a new `AsyncConsensusNetAdapter` with channel capacities from config.
    ///
    /// This constructor uses the `outbound_command_capacity` field from the
    /// provided `ChannelCapacityConfig` for both inbound and outbound channels.
    ///
    /// Note: The inbound capacity uses the same value as outbound since both
    /// represent network message flow. Use `with_capacity()` for fine-grained control.
    ///
    /// # Arguments
    ///
    /// - `config`: Channel capacity configuration
    pub fn with_config(
        config: &ChannelCapacityConfig,
    ) -> (Self, InboundEventSender, OutboundCommandReceiver) {
        // Use outbound_command_capacity for both as they represent the same message flow
        Self::with_capacity(
            config.outbound_command_capacity,
            config.outbound_command_capacity,
        )
    }

    /// Signal shutdown to the adapter.
    ///
    /// This sets the shutdown flag, causing `recv()` to return `None` on the
    /// next call. It also signals the outbound command channel to close.
    pub fn shutdown(&self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Check if the adapter is shutting down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl ConsensusNetService for AsyncConsensusNetAdapter {
    async fn recv(&mut self) -> Option<ConsensusNetworkEvent<PeerId>> {
        // Check shutdown flag first
        if self.is_shutdown() {
            return None;
        }

        // Wait for the next inbound event
        self.inbound_rx.recv().await
    }

    async fn send_vote_to(&mut self, to: PeerId, vote: &Vote) -> Result<(), NetworkError> {
        // ConsensusNetService uses Critical priority by default since it's used
        // for consensus-critical paths (T90.3)
        let cmd = OutboundCommand::SendVoteTo {
            to,
            vote: vote.clone(),
            priority: ConsensusMsgPriority::Critical,
        };

        self.outbound_tx
            .send(cmd)
            .await
            .map_err(|_| NetworkError::Other("outbound channel closed".to_string()))
    }

    async fn broadcast_vote(&mut self, vote: &Vote) -> Result<(), NetworkError> {
        // ConsensusNetService uses Critical priority by default (T90.3)
        let cmd = OutboundCommand::BroadcastVote {
            vote: vote.clone(),
            priority: ConsensusMsgPriority::Critical,
        };

        self.outbound_tx
            .send(cmd)
            .await
            .map_err(|_| NetworkError::Other("outbound channel closed".to_string()))
    }

    async fn broadcast_proposal(&mut self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        // ConsensusNetService uses Critical priority by default (T90.3)
        let cmd = OutboundCommand::BroadcastProposal {
            proposal: proposal.clone(),
            priority: ConsensusMsgPriority::Critical,
        };

        self.outbound_tx
            .send(cmd)
            .await
            .map_err(|_| NetworkError::Other("outbound channel closed".to_string()))
    }
}

// ============================================================================
// AsyncNetSender - Synchronous sender wrapping async adapter (T88)
// ============================================================================

/// A synchronous `ConsensusNetSender` implementation that wraps an async channel.
///
/// This sender is designed to be used by the synchronous consensus core
/// (`NodeHotstuffHarness`) to send outbound messages without blocking on
/// async operations.
///
/// # Design (T88)
///
/// The sender uses an mpsc channel to queue outbound commands. The actual
/// network sends are performed by a separate async task that consumes from
/// this channel.
///
/// This design:
/// - Keeps the consensus core synchronous and deterministic
/// - Allows outbound sends to be batched and processed asynchronously
/// - Provides backpressure via the bounded channel
///
/// # Observability (T89)
///
/// When configured with `NodeMetrics`, the sender tracks:
/// - Outbound message counts by type (vote_send_to, vote_broadcast, proposal_broadcast)
/// - Dropped messages due to channel full/closed
/// - Approximate queue depth
///
/// # Thread Safety
///
/// The sender is `Send + Sync` and can be shared across threads. Multiple
/// callers can send concurrently; messages are processed in order by the
/// outbound task.
///
/// # Usage
///
/// ```ignore
/// use qbind_node::consensus_net_worker::{
///     AsyncNetSender, ConsensusNetSender, spawn_critical_outbound_worker,
/// };
///
/// // Create sender with bounded channel and unbounded critical channel
/// let (sender, outbound_rx, critical_rx) = AsyncNetSender::with_channel(1024);
///
/// // Spawn the critical worker to forward critical messages
/// let critical_worker = spawn_critical_outbound_worker(critical_rx, sender.outbound_tx());
///
/// // Use in synchronous consensus code - defaults to Critical priority
/// sender.broadcast_vote(&vote)?;
///
/// // Or explicitly choose priority
/// sender.broadcast_vote_critical(&vote)?;  // Never dropped
/// sender.broadcast_vote_normal(&vote)?;    // May be dropped if full
/// ```
///
/// # Priority-Based Sending (T90.3)
///
/// The sender routes messages based on their priority:
///
/// - **Critical messages** are sent to an unbounded (or large-bounded) critical
///   channel. A dedicated async worker drains this channel and forwards messages
///   to the main outbound channel using `send().await`, providing backpressure
///   without blocking the consensus core.
///
/// - **Normal/Low messages** use the existing `try_send` path and may be dropped
///   if the channel is full, with metrics recorded.
///
/// This ensures that consensus-critical messages (proposals, current-round votes)
/// are never silently dropped due to channel saturation.
#[derive(Clone)]
pub struct AsyncNetSender {
    /// Sender for outbound commands (bounded channel for normal/low priority).
    outbound_tx: tokio::sync::mpsc::Sender<OutboundCommand>,
    /// Sender for critical messages (unbounded channel, never drops).
    /// Critical messages are forwarded to outbound_tx by a dedicated worker.
    critical_tx: tokio::sync::mpsc::UnboundedSender<OutboundCommand>,
    /// Optional metrics for observability (T89).
    metrics: Option<std::sync::Arc<crate::metrics::NodeMetrics>>,
    /// Rate limiter state for backpressure logging (T89).
    /// Tracks the last time we logged a backpressure warning.
    last_backpressure_log: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for AsyncNetSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncNetSender")
            .field("outbound_tx", &"<mpsc::Sender>")
            .field("critical_tx", &"<mpsc::UnboundedSender>")
            .field("metrics", &self.metrics.is_some())
            .finish()
    }
}

/// Receiver for critical outbound commands.
///
/// Used by `spawn_critical_outbound_worker` to drain critical messages and
/// forward them to the main outbound channel.
pub type CriticalCommandReceiver = tokio::sync::mpsc::UnboundedReceiver<OutboundCommand>;

/// Minimum interval between backpressure log messages (in milliseconds).
///
/// Set to 1 second to avoid log spam while still providing timely warnings.
/// This balances observability with log volume - under sustained backpressure,
/// we log at most once per second rather than every dropped message.
const BACKPRESSURE_LOG_INTERVAL_MS: u64 = 1000;

impl AsyncNetSender {
    /// Create a new `AsyncNetSender` from an outbound command sender.
    ///
    /// This constructor creates an internal critical channel and returns
    /// the receiver that must be consumed by `spawn_critical_outbound_worker`.
    ///
    /// # Arguments
    ///
    /// - `outbound_tx`: The main outbound command sender (bounded)
    ///
    /// # Returns
    ///
    /// A tuple of (sender, critical_rx) where critical_rx should be passed to
    /// `spawn_critical_outbound_worker`.
    pub fn new(
        outbound_tx: tokio::sync::mpsc::Sender<OutboundCommand>,
    ) -> (Self, CriticalCommandReceiver) {
        let (critical_tx, critical_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            AsyncNetSender {
                outbound_tx,
                critical_tx,
                metrics: None,
                last_backpressure_log: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            },
            critical_rx,
        )
    }

    /// Create a new `AsyncNetSender` with metrics enabled.
    ///
    /// # Arguments
    ///
    /// - `outbound_tx`: The outbound command sender
    /// - `metrics`: Shared metrics instance for observability
    ///
    /// # Returns
    ///
    /// A tuple of (sender, critical_rx) where critical_rx should be passed to
    /// `spawn_critical_outbound_worker`.
    pub fn with_metrics(
        outbound_tx: tokio::sync::mpsc::Sender<OutboundCommand>,
        metrics: std::sync::Arc<crate::metrics::NodeMetrics>,
    ) -> (Self, CriticalCommandReceiver) {
        let (critical_tx, critical_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            AsyncNetSender {
                outbound_tx,
                critical_tx,
                metrics: Some(metrics),
                last_backpressure_log: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            },
            critical_rx,
        )
    }

    /// Create a new `AsyncNetSender` with a new channel.
    ///
    /// Returns the sender, the receiver for the outbound commands, and the
    /// receiver for critical commands.
    ///
    /// The outbound receiver should be consumed by a background task (e.g.,
    /// `spawn_outbound_processor`). The critical receiver should be consumed
    /// by `spawn_critical_outbound_worker`.
    pub fn with_channel(
        capacity: usize,
    ) -> (Self, OutboundCommandReceiver, CriticalCommandReceiver) {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        let (critical_tx, critical_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            AsyncNetSender {
                outbound_tx: tx,
                critical_tx,
                metrics: None,
                last_backpressure_log: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            },
            rx,
            critical_rx,
        )
    }

    /// Create a new `AsyncNetSender` with a new channel and metrics.
    ///
    /// Returns the sender, the receiver for outbound commands, and the
    /// receiver for critical commands.
    pub fn with_channel_and_metrics(
        capacity: usize,
        metrics: std::sync::Arc<crate::metrics::NodeMetrics>,
    ) -> (Self, OutboundCommandReceiver, CriticalCommandReceiver) {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        let (critical_tx, critical_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            AsyncNetSender {
                outbound_tx: tx,
                critical_tx,
                metrics: Some(metrics),
                last_backpressure_log: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            },
            rx,
            critical_rx,
        )
    }

    /// Create a new `AsyncNetSender` with capacity from config.
    ///
    /// Returns the sender, the receiver for outbound commands, and the
    /// receiver for critical commands.
    ///
    /// # Arguments
    ///
    /// - `config`: Channel capacity configuration
    pub fn with_channel_config(
        config: &ChannelCapacityConfig,
    ) -> (Self, OutboundCommandReceiver, CriticalCommandReceiver) {
        Self::with_channel(config.outbound_command_capacity)
    }

    /// Create a new `AsyncNetSender` with capacity from config and metrics.
    ///
    /// Returns the sender, the receiver for outbound commands, and the
    /// receiver for critical commands.
    ///
    /// # Arguments
    ///
    /// - `config`: Channel capacity configuration
    /// - `metrics`: Shared metrics instance for observability
    pub fn with_channel_config_and_metrics(
        config: &ChannelCapacityConfig,
        metrics: std::sync::Arc<crate::metrics::NodeMetrics>,
    ) -> (Self, OutboundCommandReceiver, CriticalCommandReceiver) {
        Self::with_channel_and_metrics(config.outbound_command_capacity, metrics)
    }

    /// Get a clone of the outbound channel sender.
    ///
    /// This is useful for setting up the critical worker which needs
    /// its own sender to forward messages to the outbound channel.
    ///
    /// # Returns
    ///
    /// A clone of the bounded outbound channel sender.
    pub fn outbound_tx(&self) -> tokio::sync::mpsc::Sender<OutboundCommand> {
        self.outbound_tx.clone()
    }

    /// Send a critical message via the unbounded critical channel.
    ///
    /// This method never fails due to channel capacity (unbounded).
    /// It only fails if the critical worker has been dropped.
    ///
    /// # Arguments
    ///
    /// - `cmd`: The outbound command to send
    fn send_critical(&self, cmd: OutboundCommand) -> Result<(), NetworkError> {
        // Record metric for critical send attempt
        if let Some(ref metrics) = self.metrics {
            metrics.network().inc_outbound_critical_total();
        }

        self.critical_tx.send(cmd).map_err(|_| {
            // Critical channel closed - this is a fatal error
            eprintln!("[AsyncNetSender] FATAL: critical channel closed");
            NetworkError::Other("critical channel closed".to_string())
        })
    }

    /// Try to send a normal/low priority command without blocking.
    ///
    /// This method uses `try_send` which will fail immediately if the channel
    /// is full, rather than blocking.
    ///
    /// # Arguments
    ///
    /// - `cmd`: The outbound command to send
    /// - `priority`: The priority of the message (for metrics)
    fn try_send_normal(
        &self,
        cmd: OutboundCommand,
        priority: ConsensusMsgPriority,
    ) -> Result<(), NetworkError> {
        // Update queue depth metric before send attempt (T89)
        if let Some(ref metrics) = self.metrics {
            // Queue depth = max_capacity - remaining_capacity
            // capacity() returns remaining capacity (number of additional items that can be sent)
            // max_capacity() returns total channel capacity
            // Note: This is approximate due to concurrent access
            let max_capacity = self.outbound_tx.max_capacity();
            let remaining_capacity = self.outbound_tx.capacity();
            let queue_depth = max_capacity - remaining_capacity;
            metrics
                .network()
                .set_outbound_queue_depth(queue_depth as u64);
        }

        self.outbound_tx.try_send(cmd).map_err(|e| {
            match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    // Record drop metric with priority (T90.3)
                    if let Some(ref metrics) = self.metrics {
                        metrics.network().inc_outbound_dropped_by_priority(priority);
                    }

                    // Rate-limited backpressure logging (Part B)
                    self.log_backpressure_if_needed(priority);

                    NetworkError::Other("outbound channel full".to_string())
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    // Record drop metric with priority (T90.3)
                    if let Some(ref metrics) = self.metrics {
                        metrics.network().inc_outbound_dropped_by_priority(priority);
                    }
                    NetworkError::Other("outbound channel closed".to_string())
                }
            }
        })
    }

    /// Route a command based on its priority.
    ///
    /// - Critical: Goes through the unbounded critical channel
    /// - Normal/Low: Uses try_send on the bounded channel
    fn route_by_priority(&self, cmd: OutboundCommand) -> Result<(), NetworkError> {
        let priority = cmd.priority();
        match priority {
            ConsensusMsgPriority::Critical => self.send_critical(cmd),
            ConsensusMsgPriority::Normal | ConsensusMsgPriority::Low => {
                self.try_send_normal(cmd, priority)
            }
        }
    }

    /// Log a backpressure warning, rate-limited to avoid log spam.
    fn log_backpressure_if_needed(&self, priority: ConsensusMsgPriority) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let last = self
            .last_backpressure_log
            .load(std::sync::atomic::Ordering::Relaxed);

        if now_ms.saturating_sub(last) >= BACKPRESSURE_LOG_INTERVAL_MS {
            // Try to update the timestamp (best effort, no strict synchronization needed)
            let _ = self.last_backpressure_log.compare_exchange(
                last,
                now_ms,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            );

            // Log backpressure event
            let capacity = self.outbound_tx.max_capacity();
            eprintln!(
                "[AsyncNetSender] BACKPRESSURE: outbound channel full (capacity={}, priority={:?})",
                capacity, priority
            );
        }
    }

    // ========================================================================
    // Priority-specific send methods (T90.3)
    // ========================================================================

    /// Send a vote to a specific peer with Critical priority.
    ///
    /// Critical messages are never dropped; they are queued in an unbounded
    /// channel and forwarded by a dedicated worker with backpressure.
    pub fn send_vote_to_critical(&self, to: PeerId, vote: &Vote) -> Result<(), NetworkError> {
        let cmd = OutboundCommand::SendVoteTo {
            to,
            vote: vote.clone(),
            priority: ConsensusMsgPriority::Critical,
        };
        self.send_critical(cmd)?;

        if let Some(ref metrics) = self.metrics {
            metrics
                .network()
                .inc_outbound_vote_send_to_by_priority(ConsensusMsgPriority::Critical);
        }
        Ok(())
    }

    /// Send a vote to a specific peer with Normal priority.
    ///
    /// Normal messages may be dropped if the channel is full.
    pub fn send_vote_to_normal(&self, to: PeerId, vote: &Vote) -> Result<(), NetworkError> {
        let cmd = OutboundCommand::SendVoteTo {
            to,
            vote: vote.clone(),
            priority: ConsensusMsgPriority::Normal,
        };
        self.try_send_normal(cmd, ConsensusMsgPriority::Normal)?;

        if let Some(ref metrics) = self.metrics {
            metrics
                .network()
                .inc_outbound_vote_send_to_by_priority(ConsensusMsgPriority::Normal);
        }
        Ok(())
    }

    /// Broadcast a vote to all peers with Critical priority.
    pub fn broadcast_vote_critical(&self, vote: &Vote) -> Result<(), NetworkError> {
        let cmd = OutboundCommand::BroadcastVote {
            vote: vote.clone(),
            priority: ConsensusMsgPriority::Critical,
        };
        self.send_critical(cmd)?;

        if let Some(ref metrics) = self.metrics {
            metrics
                .network()
                .inc_outbound_vote_broadcast_by_priority(ConsensusMsgPriority::Critical);
        }
        Ok(())
    }

    /// Broadcast a vote to all peers with Normal priority.
    pub fn broadcast_vote_normal(&self, vote: &Vote) -> Result<(), NetworkError> {
        let cmd = OutboundCommand::BroadcastVote {
            vote: vote.clone(),
            priority: ConsensusMsgPriority::Normal,
        };
        self.try_send_normal(cmd, ConsensusMsgPriority::Normal)?;

        if let Some(ref metrics) = self.metrics {
            metrics
                .network()
                .inc_outbound_vote_broadcast_by_priority(ConsensusMsgPriority::Normal);
        }
        Ok(())
    }

    /// Broadcast a proposal with Critical priority.
    pub fn broadcast_proposal_critical(
        &self,
        proposal: &BlockProposal,
    ) -> Result<(), NetworkError> {
        let cmd = OutboundCommand::BroadcastProposal {
            proposal: proposal.clone(),
            priority: ConsensusMsgPriority::Critical,
        };
        self.send_critical(cmd)?;

        if let Some(ref metrics) = self.metrics {
            metrics
                .network()
                .inc_outbound_proposal_broadcast_by_priority(ConsensusMsgPriority::Critical);
        }
        Ok(())
    }

    /// Broadcast a proposal with Normal priority.
    pub fn broadcast_proposal_normal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        let cmd = OutboundCommand::BroadcastProposal {
            proposal: proposal.clone(),
            priority: ConsensusMsgPriority::Normal,
        };
        self.try_send_normal(cmd, ConsensusMsgPriority::Normal)?;

        if let Some(ref metrics) = self.metrics {
            metrics
                .network()
                .inc_outbound_proposal_broadcast_by_priority(ConsensusMsgPriority::Normal);
        }
        Ok(())
    }
}

impl ConsensusNetSender for AsyncNetSender {
    fn send_vote_to(&self, to: PeerId, vote: &Vote) -> Result<(), NetworkError> {
        // ConsensusNetSender trait uses Critical priority by default (T90.3)
        // All votes/proposals are treated as critical until we can classify
        // "current round" vs "old round" messages.
        let cmd = OutboundCommand::SendVoteTo {
            to,
            vote: vote.clone(),
            priority: ConsensusMsgPriority::Critical,
        };
        self.route_by_priority(cmd)?;

        // Record outbound metric on success (T89)
        if let Some(ref metrics) = self.metrics {
            metrics.network().inc_outbound_vote_send_to();
        }

        Ok(())
    }

    fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
        // ConsensusNetSender trait uses Critical priority by default (T90.3)
        let cmd = OutboundCommand::BroadcastVote {
            vote: vote.clone(),
            priority: ConsensusMsgPriority::Critical,
        };
        self.route_by_priority(cmd)?;

        // Record outbound metric on success (T89)
        if let Some(ref metrics) = self.metrics {
            metrics.network().inc_outbound_vote_broadcast();
        }

        Ok(())
    }

    fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        // ConsensusNetSender trait uses Critical priority by default (T90.3)
        let cmd = OutboundCommand::BroadcastProposal {
            proposal: proposal.clone(),
            priority: ConsensusMsgPriority::Critical,
        };
        self.route_by_priority(cmd)?;

        // Record outbound metric on success (T89)
        if let Some(ref metrics) = self.metrics {
            metrics.network().inc_outbound_proposal_broadcast();
        }

        Ok(())
    }
}

// ============================================================================
// Helper functions for bridging blocking network to async (T88)
// ============================================================================

use crate::consensus_net::ConsensusNetAdapter;
use crate::peer_manager::PeerManager;
use qbind_consensus::ConsensusNetwork;
use std::sync::{Arc, Mutex};

/// Process outbound commands using a blocking `PeerManager`.
///
/// This function processes commands from the outbound channel and sends them
/// using the blocking `PeerManager` API. It should be called from within a
/// `tokio::task::spawn_blocking` context or a dedicated thread.
///
/// # Arguments
///
/// - `peers`: Arc-wrapped PeerManager for thread-safe access
/// - `cmd`: The outbound command to process
///
/// # Note
///
/// This is an **interim** bridge function. It wraps blocking I/O operations
/// and should be called from within `spawn_blocking` to avoid blocking the
/// Tokio runtime.
///
/// In a future task, the `PeerManager` will be replaced with an async
/// implementation that doesn't require this bridging.
pub fn process_outbound_command_blocking(
    peers: &Arc<Mutex<PeerManager>>,
    cmd: OutboundCommand,
) -> Result<(), NetworkError> {
    let mut peers_guard = peers
        .lock()
        .map_err(|_| NetworkError::Other("peer manager lock poisoned".to_string()))?;

    let mut adapter = ConsensusNetAdapter::new(&mut peers_guard);

    // The priority field is used for routing decisions upstream;
    // here we just process the command regardless of priority.
    match cmd {
        OutboundCommand::SendVoteTo {
            to,
            vote,
            priority: _,
        } => ConsensusNetwork::send_vote_to(&mut adapter, to, &vote),
        OutboundCommand::BroadcastVote { vote, priority: _ } => {
            ConsensusNetwork::broadcast_vote(&mut adapter, &vote)
        }
        OutboundCommand::BroadcastProposal {
            proposal,
            priority: _,
        } => ConsensusNetwork::broadcast_proposal(&mut adapter, &proposal),
    }
}

/// Spawn an async task that processes outbound commands using blocking I/O.
///
/// This function creates a background task that:
/// 1. Receives outbound commands from the channel
/// 2. Uses `spawn_blocking` to process each command with the blocking `PeerManager`
///
/// # Arguments
///
/// - `peers`: Arc-wrapped PeerManager for thread-safe access
/// - `outbound_rx`: Receiver for outbound commands
///
/// # Returns
///
/// A `JoinHandle` for the spawned task. The task runs until the outbound
/// channel is closed (all senders dropped).
///
/// # Note
///
/// This is an **interim** implementation. Each outbound command spawns a
/// blocking task, which may be inefficient under high load. A future task
/// will replace this with a truly async network implementation.
pub fn spawn_outbound_processor(
    peers: Arc<Mutex<PeerManager>>,
    outbound_rx: OutboundCommandReceiver,
) -> tokio::task::JoinHandle<()> {
    spawn_outbound_processor_with_metrics(peers, outbound_rx, None)
}

/// Spawn an async task that processes outbound commands using blocking I/O,
/// with optional metrics tracking.
///
/// # Observability (T89)
///
/// When `metrics` is provided, this function tracks:
/// - `consensus_net_spawn_blocking_total`: Count of spawn_blocking calls
/// - Latency bucket distribution for blocking operations
///
/// # Arguments
///
/// - `peers`: Arc-wrapped PeerManager for thread-safe access
/// - `outbound_rx`: Receiver for outbound commands
/// - `metrics`: Optional shared metrics instance
pub fn spawn_outbound_processor_with_metrics(
    peers: Arc<Mutex<PeerManager>>,
    mut outbound_rx: OutboundCommandReceiver,
    metrics: Option<Arc<crate::metrics::NodeMetrics>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        eprintln!("[T88] Outbound processor started");

        while let Some(cmd) = outbound_rx.recv().await {
            let peers_clone = peers.clone();
            let metrics_clone = metrics.clone();

            // Record start time for latency measurement (T89)
            let start = std::time::Instant::now();

            // Process the command in a blocking task to avoid blocking the runtime
            let result = tokio::task::spawn_blocking(move || {
                process_outbound_command_blocking(&peers_clone, cmd)
            })
            .await;

            // Record spawn_blocking metrics (T89)
            if let Some(ref m) = metrics_clone {
                let duration = start.elapsed();
                m.spawn_blocking().record_blocking_duration(duration);
            }

            match result {
                Ok(Ok(())) => {
                    // Command processed successfully
                }
                Ok(Err(e)) => {
                    eprintln!("[T88] Outbound command error: {}", e);
                }
                Err(e) => {
                    // Log spawn_blocking failure (Part B)
                    eprintln!(
                        "[T88] FATAL: spawn_blocking task panicked in outbound processor: {:?}",
                        e
                    );
                }
            }
        }

        eprintln!("[T88] Outbound processor stopped");
    })
}

// ============================================================================
// Critical outbound worker (T90.3)
// ============================================================================

/// Spawn an async worker that forwards critical messages to the main outbound channel.
///
/// This worker:
/// 1. Receives critical commands from the unbounded critical channel
/// 2. Forwards them to the main outbound channel using `send().await`
/// 3. Provides backpressure when the outbound channel is full (without blocking consensus)
///
/// # Design (T90.3)
///
/// Critical messages are never dropped by the sender. Instead, they are queued
/// in an unbounded channel and processed by this worker. The worker uses the
/// async `send().await` method which will wait for capacity in the bounded
/// outbound channel, providing natural backpressure.
///
/// This keeps the consensus core synchronous and non-blocking, while ensuring
/// critical messages are never lost due to channel saturation.
///
/// # Arguments
///
/// - `critical_rx`: Receiver for critical outbound commands
/// - `outbound_tx`: Sender for the main outbound channel (bounded)
///
/// # Returns
///
/// A `JoinHandle` for the spawned task. The task runs until the critical
/// channel is closed (all senders dropped).
pub fn spawn_critical_outbound_worker(
    critical_rx: CriticalCommandReceiver,
    outbound_tx: tokio::sync::mpsc::Sender<OutboundCommand>,
) -> tokio::task::JoinHandle<()> {
    spawn_critical_outbound_worker_with_metrics(critical_rx, outbound_tx, None)
}

/// Spawn an async worker that forwards critical messages with metrics tracking.
///
/// # Observability (T90.3)
///
/// When `metrics` is provided, this function tracks:
/// - `consensus_net_outbound_critical_worker_total`: Count of successfully delivered commands
/// - Time spent waiting on backpressure (tracked via latency buckets)
///
/// # Arguments
///
/// - `critical_rx`: Receiver for critical outbound commands
/// - `outbound_tx`: Sender for the main outbound channel (bounded)
/// - `metrics`: Optional shared metrics instance
pub fn spawn_critical_outbound_worker_with_metrics(
    mut critical_rx: CriticalCommandReceiver,
    outbound_tx: tokio::sync::mpsc::Sender<OutboundCommand>,
    metrics: Option<Arc<crate::metrics::NodeMetrics>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        eprintln!("[T90.3] Critical outbound worker started");

        while let Some(cmd) = critical_rx.recv().await {
            // Record start time to measure backpressure wait time
            let start = std::time::Instant::now();

            // Use send().await which will wait for capacity (backpressure)
            match outbound_tx.send(cmd).await {
                Ok(()) => {
                    // Record metrics for successful delivery
                    if let Some(ref m) = metrics {
                        let duration = start.elapsed();
                        m.network().inc_outbound_critical_worker_total();
                        m.network().record_critical_backpressure_wait(duration);
                    }
                }
                Err(e) => {
                    // Outbound channel closed - this is a fatal error
                    // Log at error level since critical messages should never be lost
                    eprintln!(
                        "[T90.3] FATAL: outbound channel closed while sending critical message: {:?}",
                        e
                    );
                    // Break out of the loop - the channel is gone
                    break;
                }
            }
        }

        eprintln!("[T90.3] Critical outbound worker stopped");
    })
}

/// Spawn an async task that polls the blocking network and feeds inbound events.
///
/// This function creates a background task that:
/// 1. Periodically polls the blocking `PeerManager` for incoming messages
/// 2. Converts messages to `ConsensusNetworkEvent` and sends them to the channel
///
/// # Arguments
///
/// - `peers`: Arc-wrapped PeerManager for thread-safe access
/// - `inbound_tx`: Sender for inbound events
/// - `poll_interval`: How often to poll the network (e.g., 10ms)
///
/// # Returns
///
/// A `JoinHandle` for the spawned task. The task runs until the inbound
/// channel is closed (all receivers dropped).
///
/// # Note
///
/// This is an **interim** implementation that uses polling. A future task
/// will replace this with event-driven async I/O using `tokio::net`.
pub fn spawn_inbound_processor(
    peers: Arc<Mutex<PeerManager>>,
    inbound_tx: InboundEventSender,
    poll_interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    spawn_inbound_processor_with_metrics(peers, inbound_tx, poll_interval, None)
}

/// Spawn an async task that polls the blocking network and feeds inbound events,
/// with optional metrics tracking.
///
/// # Observability (T89)
///
/// When `metrics` is provided, this function tracks:
/// - `consensus_net_spawn_blocking_total`: Count of spawn_blocking calls
/// - Latency bucket distribution for blocking poll operations
///
/// # Arguments
///
/// - `peers`: Arc-wrapped PeerManager for thread-safe access
/// - `inbound_tx`: Sender for inbound events
/// - `poll_interval`: How often to poll the network (e.g., 10ms)
/// - `metrics`: Optional shared metrics instance
pub fn spawn_inbound_processor_with_metrics(
    peers: Arc<Mutex<PeerManager>>,
    inbound_tx: InboundEventSender,
    poll_interval: std::time::Duration,
    metrics: Option<Arc<crate::metrics::NodeMetrics>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        eprintln!(
            "[T88] Inbound processor started with poll_interval={:?}",
            poll_interval
        );

        let mut interval = tokio::time::interval(poll_interval);

        loop {
            interval.tick().await;

            // Check if the channel is closed
            if inbound_tx.is_closed() {
                eprintln!("[T88] Inbound channel closed, stopping processor");
                break;
            }

            let peers_clone = peers.clone();
            let metrics_clone = metrics.clone();

            // Record start time for latency measurement (T89)
            let start = std::time::Instant::now();

            // Poll the network in a blocking task
            let result = tokio::task::spawn_blocking(move || {
                let mut peers_guard = match peers_clone.lock() {
                    Ok(g) => g,
                    Err(_) => return Err(NetworkError::Other("lock poisoned".to_string())),
                };

                let mut adapter = ConsensusNetAdapter::new(&mut peers_guard);

                // Use try_recv_one to avoid blocking
                ConsensusNetwork::try_recv_one(&mut adapter)
            })
            .await;

            // Record spawn_blocking metrics (T89)
            if let Some(ref m) = metrics_clone {
                let duration = start.elapsed();
                m.spawn_blocking().record_blocking_duration(duration);
            }

            match result {
                Ok(Ok(Some(event))) => {
                    // Got an event, send it to the channel
                    if inbound_tx.send(event).await.is_err() {
                        // Channel closed
                        eprintln!("[T88] Inbound channel closed while sending");
                        break;
                    }
                }
                Ok(Ok(None)) => {
                    // No event available, continue polling
                }
                Ok(Err(e)) => {
                    // Network error - log and continue
                    eprintln!("[T88] Inbound poll error: {}", e);
                }
                Err(e) => {
                    // Log spawn_blocking failure (Part B)
                    eprintln!(
                        "[T88] FATAL: spawn_blocking task panicked in inbound processor: {:?}",
                        e
                    );
                }
            }
        }

        eprintln!("[T88] Inbound processor stopped");
    })
}

// ============================================================================
// Mock implementations for testing
// ============================================================================

#[cfg(test)]
pub mod testing {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// A mock implementation of `ConsensusNetService` for testing.
    ///
    /// This mock:
    /// - Yields a configurable sequence of events from `recv()`
    /// - Records outbound calls to `send_vote_to()`, `broadcast_vote()`, and
    ///   `broadcast_proposal()`
    ///
    /// # Thread Safety
    ///
    /// The mock uses `Arc<Mutex<...>>` internally to allow inspection of
    /// recorded outbound calls from other tasks/threads.
    #[derive(Clone)]
    pub struct MockConsensusNetService {
        /// Queue of events to return from `recv()`.
        inbound: Arc<Mutex<VecDeque<ConsensusNetworkEvent<PeerId>>>>,
        /// Recorded outbound votes: (destination, vote). `None` means broadcast.
        outbound_votes: Arc<Mutex<Vec<(Option<PeerId>, Vote)>>>,
        /// Recorded outbound proposals.
        outbound_proposals: Arc<Mutex<Vec<BlockProposal>>>,
    }

    impl MockConsensusNetService {
        /// Create a new empty mock network service.
        pub fn new() -> Self {
            MockConsensusNetService {
                inbound: Arc::new(Mutex::new(VecDeque::new())),
                outbound_votes: Arc::new(Mutex::new(Vec::new())),
                outbound_proposals: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Create a new mock with pre-populated inbound events.
        pub fn with_events(events: Vec<ConsensusNetworkEvent<PeerId>>) -> Self {
            let mock = Self::new();
            {
                let mut inbound = mock.inbound.lock().unwrap();
                for event in events {
                    inbound.push_back(event);
                }
            }
            mock
        }

        /// Enqueue an event to be returned by the next `recv()` call.
        pub fn enqueue_event(&self, event: ConsensusNetworkEvent<PeerId>) {
            let mut inbound = self.inbound.lock().unwrap();
            inbound.push_back(event);
        }

        /// Get the recorded outbound votes.
        pub fn outbound_votes(&self) -> Vec<(Option<PeerId>, Vote)> {
            self.outbound_votes.lock().unwrap().clone()
        }

        /// Get the recorded outbound proposals.
        pub fn outbound_proposals(&self) -> Vec<BlockProposal> {
            self.outbound_proposals.lock().unwrap().clone()
        }
    }

    impl Default for MockConsensusNetService {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ConsensusNetService for MockConsensusNetService {
        async fn recv(&mut self) -> Option<ConsensusNetworkEvent<PeerId>> {
            // Pop the next event from the queue
            let mut inbound = self.inbound.lock().unwrap();
            inbound.pop_front()
        }

        async fn send_vote_to(&mut self, to: PeerId, vote: &Vote) -> Result<(), NetworkError> {
            let mut outbound = self.outbound_votes.lock().unwrap();
            outbound.push((Some(to), vote.clone()));
            Ok(())
        }

        async fn broadcast_vote(&mut self, vote: &Vote) -> Result<(), NetworkError> {
            let mut outbound = self.outbound_votes.lock().unwrap();
            outbound.push((None, vote.clone()));
            Ok(())
        }

        async fn broadcast_proposal(
            &mut self,
            proposal: &BlockProposal,
        ) -> Result<(), NetworkError> {
            let mut outbound = self.outbound_proposals.lock().unwrap();
            outbound.push(proposal.clone());
            Ok(())
        }
    }

    /// A mock implementation of `ConsensusNetSender` for testing.
    ///
    /// Records all outbound calls for later inspection.
    #[derive(Clone)]
    pub struct MockConsensusNetSender {
        /// Recorded outbound votes: (destination, vote). `None` means broadcast.
        outbound_votes: Arc<Mutex<Vec<(Option<PeerId>, Vote)>>>,
        /// Recorded outbound proposals.
        outbound_proposals: Arc<Mutex<Vec<BlockProposal>>>,
    }

    impl MockConsensusNetSender {
        /// Create a new empty mock sender.
        pub fn new() -> Self {
            MockConsensusNetSender {
                outbound_votes: Arc::new(Mutex::new(Vec::new())),
                outbound_proposals: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Get the recorded outbound votes.
        pub fn outbound_votes(&self) -> Vec<(Option<PeerId>, Vote)> {
            self.outbound_votes.lock().unwrap().clone()
        }

        /// Get the recorded outbound proposals.
        pub fn outbound_proposals(&self) -> Vec<BlockProposal> {
            self.outbound_proposals.lock().unwrap().clone()
        }
    }

    impl Default for MockConsensusNetSender {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ConsensusNetSender for MockConsensusNetSender {
        fn send_vote_to(&self, to: PeerId, vote: &Vote) -> Result<(), NetworkError> {
            let mut outbound = self.outbound_votes.lock().unwrap();
            outbound.push((Some(to), vote.clone()));
            Ok(())
        }

        fn broadcast_vote(&self, vote: &Vote) -> Result<(), NetworkError> {
            let mut outbound = self.outbound_votes.lock().unwrap();
            outbound.push((None, vote.clone()));
            Ok(())
        }

        fn broadcast_proposal(&self, proposal: &BlockProposal) -> Result<(), NetworkError> {
            let mut outbound = self.outbound_proposals.lock().unwrap();
            outbound.push(proposal.clone());
            Ok(())
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use qbind_wire::consensus::{BlockHeader, Vote};
    use tokio::sync::mpsc;

    /// Create a dummy Vote for testing.
    fn make_dummy_vote(height: u64, round: u64) -> Vote {
        Vote {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round,
            step: 0,
            block_id: [0u8; 32],
            validator_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signature: vec![],
        }
    }

    /// Create a dummy BlockProposal for testing.
    fn make_dummy_proposal(height: u64, round: u64) -> BlockProposal {
        BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                epoch: 0,
                height,
                round,
                parent_block_id: [0u8; 32],
                payload_hash: [0u8; 32],
                proposer_index: 0,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 0,
                payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
            },
            qc: None,
            txs: vec![],
            signature: vec![],
        }
    }

    #[test]
    fn consensus_net_worker_error_display() {
        let err = ConsensusNetWorkerError::ChannelClosed;
        assert_eq!(err.to_string(), "consensus event channel closed");

        let err = ConsensusNetWorkerError::NetworkClosed;
        assert_eq!(err.to_string(), "network closed");

        let err = ConsensusNetWorkerError::Network(NetworkError::Other("test".to_string()));
        assert!(err.to_string().contains("network error"));
    }

    #[test]
    fn mock_consensus_net_service_records_outbound_votes() {
        let mock = MockConsensusNetService::new();
        let vote = make_dummy_vote(1, 0);

        // Clone for use after async block
        let mock_clone = mock.clone();

        // Use a runtime to test async methods
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut mock = mock;
            mock.send_vote_to(PeerId(1), &vote).await.unwrap();
            mock.broadcast_vote(&vote).await.unwrap();
        });

        let outbound = mock_clone.outbound_votes();
        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].0, Some(PeerId(1)));
        assert_eq!(outbound[1].0, None);
    }

    #[test]
    fn mock_consensus_net_service_records_outbound_proposals() {
        let mock = MockConsensusNetService::new();
        let proposal = make_dummy_proposal(1, 0);

        // Clone for use after async block
        let mock_clone = mock.clone();

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut mock = mock;
            mock.broadcast_proposal(&proposal).await.unwrap();
        });

        let outbound = mock_clone.outbound_proposals();
        assert_eq!(outbound.len(), 1);
    }

    #[test]
    fn mock_consensus_net_service_returns_queued_events() {
        let vote = make_dummy_vote(1, 0);
        let proposal = make_dummy_proposal(2, 1);

        let events = vec![
            ConsensusNetworkEvent::IncomingVote {
                from: PeerId(100),
                vote: vote.clone(),
            },
            ConsensusNetworkEvent::IncomingProposal {
                from: PeerId(200),
                proposal: proposal.clone(),
            },
        ];

        let mock = MockConsensusNetService::with_events(events);

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut mock = mock;

            let event1 = mock.recv().await;
            assert!(matches!(
                event1,
                Some(ConsensusNetworkEvent::IncomingVote { .. })
            ));

            let event2 = mock.recv().await;
            assert!(matches!(
                event2,
                Some(ConsensusNetworkEvent::IncomingProposal { .. })
            ));

            let event3 = mock.recv().await;
            assert!(event3.is_none());
        });
    }

    #[test]
    fn mock_consensus_net_sender_records_calls() {
        let sender = MockConsensusNetSender::new();
        let vote = make_dummy_vote(1, 0);
        let proposal = make_dummy_proposal(1, 0);

        sender.send_vote_to(PeerId(1), &vote).unwrap();
        sender.broadcast_vote(&vote).unwrap();
        sender.broadcast_proposal(&proposal).unwrap();

        let votes = sender.outbound_votes();
        assert_eq!(votes.len(), 2);
        assert_eq!(votes[0].0, Some(PeerId(1)));
        assert_eq!(votes[1].0, None);

        let proposals = sender.outbound_proposals();
        assert_eq!(proposals.len(), 1);
    }

    #[tokio::test]
    async fn consensus_net_worker_forwards_events_to_channel() {
        let vote = make_dummy_vote(1, 0);
        let proposal = make_dummy_proposal(2, 1);

        let events = vec![
            ConsensusNetworkEvent::IncomingVote {
                from: PeerId(100),
                vote: vote.clone(),
            },
            ConsensusNetworkEvent::IncomingProposal {
                from: PeerId(200),
                proposal: proposal.clone(),
            },
        ];

        let mock = MockConsensusNetService::with_events(events);
        let (tx, mut rx) = mpsc::channel(10);

        let worker = ConsensusNetWorker::new(mock, tx);

        // Run the worker - it should exit when the mock returns None
        let result = worker.run().await;
        assert!(result.is_ok());

        // Check that events were forwarded
        let event1 = rx.recv().await;
        assert!(event1.is_some());
        match event1.unwrap() {
            ConsensusEvent::IncomingMessage(boxed) => {
                assert!(matches!(*boxed, ConsensusNetworkEvent::IncomingVote { .. }));
            }
            _ => panic!("expected IncomingMessage"),
        }

        let event2 = rx.recv().await;
        assert!(event2.is_some());
        match event2.unwrap() {
            ConsensusEvent::IncomingMessage(boxed) => {
                assert!(matches!(
                    *boxed,
                    ConsensusNetworkEvent::IncomingProposal { .. }
                ));
            }
            _ => panic!("expected IncomingMessage"),
        }

        // No more events
        let event3 = rx.try_recv();
        assert!(event3.is_err());
    }

    #[tokio::test]
    async fn consensus_net_worker_exits_when_channel_closed() {
        // Create a mock that will yield events forever (in practice, we'll close the channel)
        let mock = MockConsensusNetService::new();

        // Add one event
        mock.enqueue_event(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(1),
            vote: make_dummy_vote(1, 0),
        });

        let (tx, rx) = mpsc::channel(10);

        // Drop the receiver immediately
        drop(rx);

        let worker = ConsensusNetWorker::new(mock, tx);

        // Worker should exit gracefully when it can't send
        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn consensus_net_worker_exits_when_network_closes() {
        // Create a mock with no events - recv() will return None immediately
        let mock = MockConsensusNetService::new();
        let (tx, _rx) = mpsc::channel(10);

        let worker = ConsensusNetWorker::new(mock, tx);

        // Worker should exit gracefully when network returns None
        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[test]
    fn consensus_net_worker_debug_impl() {
        let mock = MockConsensusNetService::new();
        let (tx, _rx) = mpsc::channel::<ConsensusEvent>(10);
        let worker = ConsensusNetWorker::new(mock, tx);

        let debug_str = format!("{:?}", worker);
        assert!(debug_str.contains("ConsensusNetWorker"));
    }

    // ========================================================================
    // AsyncConsensusNetAdapter tests (T88)
    // ========================================================================

    #[tokio::test]
    async fn async_adapter_receives_events_from_inbound_channel() {
        let (mut adapter, inbound_tx, _outbound_rx) = AsyncConsensusNetAdapter::new();

        // Send some events to the inbound channel
        let vote = make_dummy_vote(1, 0);
        let proposal = make_dummy_proposal(2, 1);

        inbound_tx
            .send(ConsensusNetworkEvent::IncomingVote {
                from: PeerId(100),
                vote: vote.clone(),
            })
            .await
            .unwrap();

        inbound_tx
            .send(ConsensusNetworkEvent::IncomingProposal {
                from: PeerId(200),
                proposal: proposal.clone(),
            })
            .await
            .unwrap();

        // Drop the sender to close the channel
        drop(inbound_tx);

        // Receive events from the adapter
        let event1 = adapter.recv().await;
        assert!(matches!(
            event1,
            Some(ConsensusNetworkEvent::IncomingVote { .. })
        ));

        let event2 = adapter.recv().await;
        assert!(matches!(
            event2,
            Some(ConsensusNetworkEvent::IncomingProposal { .. })
        ));

        // Channel is closed, should return None
        let event3 = adapter.recv().await;
        assert!(event3.is_none());
    }

    #[tokio::test]
    async fn async_adapter_sends_commands_to_outbound_channel() {
        let (mut adapter, _inbound_tx, mut outbound_rx) = AsyncConsensusNetAdapter::new();

        let vote = make_dummy_vote(1, 0);
        let proposal = make_dummy_proposal(2, 1);

        // Send via the adapter
        adapter.send_vote_to(PeerId(1), &vote).await.unwrap();
        adapter.broadcast_vote(&vote).await.unwrap();
        adapter.broadcast_proposal(&proposal).await.unwrap();

        // Receive commands from the outbound channel
        let cmd1 = outbound_rx.recv().await.unwrap();
        assert!(matches!(
            cmd1,
            OutboundCommand::SendVoteTo { to: PeerId(1), .. }
        ));

        let cmd2 = outbound_rx.recv().await.unwrap();
        assert!(matches!(cmd2, OutboundCommand::BroadcastVote { .. }));

        let cmd3 = outbound_rx.recv().await.unwrap();
        assert!(matches!(cmd3, OutboundCommand::BroadcastProposal { .. }));
    }

    #[tokio::test]
    async fn async_adapter_respects_shutdown_flag() {
        let (mut adapter, inbound_tx, _outbound_rx) = AsyncConsensusNetAdapter::new();

        // Send an event
        inbound_tx
            .send(ConsensusNetworkEvent::IncomingVote {
                from: PeerId(1),
                vote: make_dummy_vote(1, 0),
            })
            .await
            .unwrap();

        // Signal shutdown
        adapter.shutdown();
        assert!(adapter.is_shutdown());

        // recv() should return None immediately when shutdown
        let event = adapter.recv().await;
        assert!(event.is_none());
    }

    #[test]
    fn async_adapter_debug_impl() {
        let (adapter, _inbound_tx, _outbound_rx) = AsyncConsensusNetAdapter::new();
        let debug_str = format!("{:?}", adapter);
        assert!(debug_str.contains("AsyncConsensusNetAdapter"));
    }

    // ========================================================================
    // AsyncNetSender tests (T88)
    // ========================================================================

    #[tokio::test]
    async fn async_net_sender_sends_commands_to_channel() {
        let (sender, mut outbound_rx, _critical_rx) = AsyncNetSender::with_channel(10);

        let vote = make_dummy_vote(1, 0);
        let proposal = make_dummy_proposal(2, 1);

        // Send via the sender (synchronous API)
        // Note: The ConsensusNetSender trait uses Critical priority by default,
        // which means messages go through the critical channel, not outbound_rx.
        // We need to use the explicit normal priority methods for this test.
        sender.send_vote_to_normal(PeerId(1), &vote).unwrap();
        sender.broadcast_vote_normal(&vote).unwrap();
        sender.broadcast_proposal_normal(&proposal).unwrap();

        // Receive commands from the channel
        let cmd1 = outbound_rx.recv().await.unwrap();
        assert!(matches!(
            cmd1,
            OutboundCommand::SendVoteTo { to: PeerId(1), .. }
        ));

        let cmd2 = outbound_rx.recv().await.unwrap();
        assert!(matches!(cmd2, OutboundCommand::BroadcastVote { .. }));

        let cmd3 = outbound_rx.recv().await.unwrap();
        assert!(matches!(cmd3, OutboundCommand::BroadcastProposal { .. }));
    }

    #[test]
    fn async_net_sender_fails_when_channel_full() {
        // Create a sender with capacity 1
        let (sender, _outbound_rx, _critical_rx) = AsyncNetSender::with_channel(1);

        let vote = make_dummy_vote(1, 0);

        // First send should succeed (using normal priority)
        sender.broadcast_vote_normal(&vote).unwrap();

        // Second send should fail (channel full)
        let result = sender.broadcast_vote_normal(&vote);
        assert!(result.is_err());
        match result {
            Err(NetworkError::Other(msg)) => {
                assert!(msg.contains("full"));
            }
            _ => panic!("expected Other error with 'full' message"),
        }
    }

    #[test]
    fn async_net_sender_fails_when_channel_closed() {
        let (sender, outbound_rx, _critical_rx) = AsyncNetSender::with_channel(10);

        // Drop the receiver to close the channel
        drop(outbound_rx);

        let vote = make_dummy_vote(1, 0);

        // Send with normal priority should fail (channel closed)
        let result = sender.broadcast_vote_normal(&vote);
        assert!(result.is_err());
        match result {
            Err(NetworkError::Other(msg)) => {
                assert!(msg.contains("closed"));
            }
            _ => panic!("expected Other error with 'closed' message"),
        }
    }

    #[test]
    fn async_net_sender_is_clone() {
        let (sender, _outbound_rx, _critical_rx) = AsyncNetSender::with_channel(10);
        let _sender2 = sender.clone();
    }

    #[test]
    fn async_net_sender_debug_impl() {
        let (sender, _outbound_rx, _critical_rx) = AsyncNetSender::with_channel(10);
        let debug_str = format!("{:?}", sender);
        assert!(debug_str.contains("AsyncNetSender"));
    }

    // ========================================================================
    // Priority-based sending tests (T90.3)
    // ========================================================================

    #[tokio::test]
    async fn async_net_sender_critical_messages_go_to_critical_channel() {
        let (sender, _outbound_rx, mut critical_rx) = AsyncNetSender::with_channel(10);

        let vote = make_dummy_vote(1, 0);
        let proposal = make_dummy_proposal(2, 1);

        // Send with critical priority
        sender.send_vote_to_critical(PeerId(1), &vote).unwrap();
        sender.broadcast_vote_critical(&vote).unwrap();
        sender.broadcast_proposal_critical(&proposal).unwrap();

        // Receive commands from the critical channel
        let cmd1 = critical_rx.recv().await.unwrap();
        assert!(matches!(
            cmd1,
            OutboundCommand::SendVoteTo {
                priority: ConsensusMsgPriority::Critical,
                ..
            }
        ));

        let cmd2 = critical_rx.recv().await.unwrap();
        assert!(matches!(
            cmd2,
            OutboundCommand::BroadcastVote {
                priority: ConsensusMsgPriority::Critical,
                ..
            }
        ));

        let cmd3 = critical_rx.recv().await.unwrap();
        assert!(matches!(
            cmd3,
            OutboundCommand::BroadcastProposal {
                priority: ConsensusMsgPriority::Critical,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn async_net_sender_normal_messages_go_to_outbound_channel() {
        let (sender, mut outbound_rx, _critical_rx) = AsyncNetSender::with_channel(10);

        let vote = make_dummy_vote(1, 0);

        // Send with normal priority
        sender.broadcast_vote_normal(&vote).unwrap();

        // Receive from outbound channel (not critical)
        let cmd = outbound_rx.recv().await.unwrap();
        assert!(matches!(
            cmd,
            OutboundCommand::BroadcastVote {
                priority: ConsensusMsgPriority::Normal,
                ..
            }
        ));
    }

    #[test]
    fn async_net_sender_critical_never_fails_on_full_outbound() {
        // Create a sender with capacity 1
        let (sender, _outbound_rx, _critical_rx) = AsyncNetSender::with_channel(1);

        let vote = make_dummy_vote(1, 0);

        // Fill the outbound channel with normal messages
        sender.broadcast_vote_normal(&vote).unwrap();

        // Normal should fail now (channel full)
        let result_normal = sender.broadcast_vote_normal(&vote);
        assert!(result_normal.is_err());

        // But critical should succeed (goes to unbounded critical channel)
        let result_critical = sender.broadcast_vote_critical(&vote);
        assert!(result_critical.is_ok());
    }

    #[test]
    fn outbound_command_priority_accessor() {
        let vote = make_dummy_vote(1, 0);

        let cmd_critical = OutboundCommand::BroadcastVote {
            vote: vote.clone(),
            priority: ConsensusMsgPriority::Critical,
        };
        assert_eq!(cmd_critical.priority(), ConsensusMsgPriority::Critical);
        assert!(cmd_critical.is_critical());

        let cmd_normal = OutboundCommand::BroadcastVote {
            vote: vote.clone(),
            priority: ConsensusMsgPriority::Normal,
        };
        assert_eq!(cmd_normal.priority(), ConsensusMsgPriority::Normal);
        assert!(!cmd_normal.is_critical());
    }

    #[test]
    fn consensus_msg_priority_default_is_normal() {
        assert_eq!(
            ConsensusMsgPriority::default(),
            ConsensusMsgPriority::Normal
        );
    }

    // ========================================================================
    // Worker + AsyncConsensusNetAdapter integration tests (T88)
    // ========================================================================

    #[tokio::test]
    async fn worker_with_async_adapter_forwards_events() {
        let (adapter, inbound_tx, _outbound_rx) = AsyncConsensusNetAdapter::new();
        let (tx, mut rx) = mpsc::channel(10);

        let vote = make_dummy_vote(1, 0);

        // Send event to the adapter
        inbound_tx
            .send(ConsensusNetworkEvent::IncomingVote {
                from: PeerId(100),
                vote: vote.clone(),
            })
            .await
            .unwrap();

        // Close the inbound channel
        drop(inbound_tx);

        // Create worker with the adapter
        let worker = ConsensusNetWorker::new(adapter, tx);

        // Run the worker
        let result = worker.run().await;
        assert!(result.is_ok());

        // Check that the event was forwarded
        let event = rx.recv().await.unwrap();
        match event {
            ConsensusEvent::IncomingMessage(boxed) => {
                assert!(matches!(*boxed, ConsensusNetworkEvent::IncomingVote { .. }));
            }
            _ => panic!("expected IncomingMessage"),
        }
    }
}
