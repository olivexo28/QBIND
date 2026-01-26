//! Tokio-driven async node runner for qbind post-quantum blockchain.
//!
//! This module provides `AsyncNodeRunner`, an async wrapper around the synchronous
//! `NodeHotstuffHarness` consensus driver. It serves as the transition layer between:
//!
//! - **Synchronous consensus core**: HotStuff state, voting, QC formation remain
//!   deterministic and synchronous.
//! - **Async runtime**: Tokio handles scheduling ticks, and will orchestrate
//!   network I/O and storage in future tasks.
//!
//! # Design (T85)
//!
//! This is a **skeleton layer** - it does not fully "Tokio-ify" the node. Rather:
//!
//! 1. The node's "heart" becomes an async event loop (`run()`) instead of a manual
//!    polling `while` loop.
//! 2. Consensus ticks are driven by `tokio::time::interval` rather than busy-looping.
//! 3. Network sockets and storage may still block internally (to be async-ified in
//!    future tasks).
//!
//! # Design (T86 - Event-driven consensus)
//!
//! This module introduces an event-driven interface between the async runtime and
//! the synchronous HotStuff harness via Tokio channels:
//!
//! 1. `ConsensusEvent` enum defines the events the runtime can receive:
//!    - `Tick`: Advance the consensus state machine
//!    - `IncomingMessage`: Process a consensus message from the network
//!    - `Shutdown`: Gracefully terminate the event loop
//!
//! 2. `AsyncNodeRunner` uses `tokio::select!` to multiplex:
//!    - Timer-based ticks
//!    - Incoming events from the channel
//!    - Shutdown signals
//!
//! 3. External tasks (e.g., network handlers) can send events via `ConsensusEventSender`
//!
//! # Usage
//!
//! ```ignore
//! use qbind_node::async_runner::{AsyncNodeRunner, ConsensusEvent, ConsensusEventSender};
//! use qbind_node::NodeHotstuffHarness;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Build harness from config...
//!     let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)?;
//!
//!     // Wrap in async runner - returns runner and event sender
//!     let (runner, event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(100));
//!
//!     // Spawn network task that sends events
//!     tokio::spawn(async move {
//!         // ... network logic that sends events via event_tx
//!     });
//!
//!     // Run the node (this will loop until shutdown or error)
//!     runner.run().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Future Extensions
//!
//! - Async network tasks that forward messages into the event channel
//! - Async storage operations

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{interval, Interval};

use crate::channel_config::ChannelCapacityConfig;
use crate::hotstuff_node_sim::{NodeHotstuffHarness, NodeHotstuffHarnessError};
use crate::peer::PeerId;
use crate::startup_validation::ValidatorEnumerator;
use qbind_consensus::crypto_verifier::ConsensusSigBackendRegistry;
use qbind_consensus::network::ConsensusNetworkEvent;

// ============================================================================
// ConsensusEvent - Event types for the async runtime
// ============================================================================

/// Default capacity for the consensus event channel.
///
/// This value (1024) is chosen to provide a reasonable buffer for bursty
/// network traffic while avoiding excessive memory usage. The channel is
/// bounded to provide backpressure if the consensus loop falls behind.
///
/// # Tuning Notes
///
/// - Higher values allow more buffering but use more memory
/// - Lower values may cause senders to block under heavy load
/// - For high-TPS scenarios, this may need to be increased
pub const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Events that can be received by the async consensus runtime.
///
/// This enum defines the event boundary between the async Tokio runtime and
/// the synchronous HotStuff consensus core. External async tasks (e.g., network
/// handlers) send these events through a Tokio mpsc channel, and the
/// `AsyncNodeRunner` processes them in its event loop.
///
/// # Event Ordering
///
/// Events are processed in FIFO order as they arrive on the channel. Timer
/// ticks and channel events are multiplexed via `tokio::select!`, so the
/// relative ordering between timer ticks and channel events depends on
/// timing and select fairness.
///
/// # Future Extensions
///
/// Additional event types (e.g., `ViewChange`, `LeaderElection`) can be added
/// as the consensus protocol evolves.
#[derive(Debug, Clone)]
pub enum ConsensusEvent {
    /// Advance the consensus state machine by one tick.
    ///
    /// This event can be sent externally to trigger a consensus step
    /// independently of the timer. The timer-based ticks in `AsyncNodeRunner`
    /// call the harness `on_tick()` method directly without going through
    /// the channel.
    Tick,

    /// Process an incoming consensus message from the network.
    ///
    /// The message is wrapped in `ConsensusNetworkEvent<PeerId>` which
    /// can be either:
    /// - `IncomingVote { from, vote }` - A vote from another validator
    /// - `IncomingProposal { from, proposal }` - A block proposal from a leader
    ///
    /// This reuses the existing `ConsensusNetworkEvent` type from
    /// `qbind-consensus::network` to avoid creating redundant message types.
    ///
    /// The event is boxed to reduce the size of the `ConsensusEvent` enum,
    /// as `ConsensusNetworkEvent` is significantly larger than the other variants.
    IncomingMessage(Box<ConsensusNetworkEvent<PeerId>>),

    /// Gracefully shut down the consensus event loop.
    ///
    /// When this event is received, the runner will exit its event loop
    /// and return `Ok(())`. This provides a clean shutdown mechanism
    /// alternative to dropping all senders (which also causes shutdown).
    Shutdown,
}

/// Sender half of the consensus event channel.
///
/// This type alias provides a convenient name for external tasks that need
/// to send events to the consensus runtime. Multiple senders can be cloned
/// from a single sender and used concurrently from different tasks.
///
/// # Usage
///
/// ```ignore
/// let sender: ConsensusEventSender = /* from AsyncNodeRunner::new() */;
///
/// // Send a shutdown signal
/// sender.send(ConsensusEvent::Shutdown).await?;
///
/// // Forward a network message
/// sender.send(ConsensusEvent::IncomingMessage(network_event)).await?;
/// ```
pub type ConsensusEventSender = mpsc::Sender<ConsensusEvent>;

/// Receiver half of the consensus event channel.
///
/// This type alias is used internally by `AsyncNodeRunner` to receive
/// events from external tasks. The receiver is stored inside the runner
/// and polled in the event loop.
pub type ConsensusEventReceiver = mpsc::Receiver<ConsensusEvent>;

// ============================================================================
// AsyncNodeError
// ============================================================================

/// Error type for async node runner operations.
///
/// This wraps the underlying `NodeHotstuffHarnessError` and adds async-specific
/// error variants for future use.
#[derive(Debug)]
pub enum AsyncNodeError {
    /// Error from the underlying harness (consensus, network, storage).
    Harness(NodeHotstuffHarnessError),
    /// Startup validation failed.
    StartupValidation(crate::startup_validation::StartupValidationError),
    /// The runner was cancelled or shut down.
    Cancelled,
}

impl From<NodeHotstuffHarnessError> for AsyncNodeError {
    fn from(e: NodeHotstuffHarnessError) -> Self {
        AsyncNodeError::Harness(e)
    }
}

impl From<crate::startup_validation::StartupValidationError> for AsyncNodeError {
    fn from(e: crate::startup_validation::StartupValidationError) -> Self {
        AsyncNodeError::StartupValidation(e)
    }
}

impl std::fmt::Display for AsyncNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsyncNodeError::Harness(e) => write!(f, "harness error: {}", e),
            AsyncNodeError::StartupValidation(e) => write!(f, "startup validation: {}", e),
            AsyncNodeError::Cancelled => write!(f, "runner cancelled"),
        }
    }
}

impl std::error::Error for AsyncNodeError {}

// ============================================================================
// AsyncNodeRunner
// ============================================================================

/// Async node runner that wraps `NodeHotstuffHarness` in a Tokio-driven event loop.
///
/// # Architecture Notes (T86 - Event-driven)
///
/// - **Consensus core remains synchronous**: `on_tick()` and `on_incoming_message()`
///   are called synchronously. HotStuff state, voting, and QC formation are deterministic.
///
/// - **Event-driven interface**: The runner receives events via a Tokio mpsc channel:
///   - `ConsensusEvent::Tick` - Advance the consensus state
///   - `ConsensusEvent::IncomingMessage` - Process network messages
///   - `ConsensusEvent::Shutdown` - Gracefully exit the loop
///
/// - **Tokio is used for**:
///   - Scheduling ticks via `interval`
///   - Receiving events via mpsc channel
///   - Multiplexing with `tokio::select!`
///
/// # Observability (T89)
///
/// When configured with `NodeMetrics`, the runner tracks:
/// - Event counts by type (tick, incoming_message, shutdown)
/// - Ticks per second rate (updated periodically)
///
/// # Event Processing
///
/// The event loop uses `tokio::select!` to multiplex between:
/// 1. Timer ticks - calls `harness.on_tick()` directly
/// 2. Channel events - dispatches to appropriate harness methods
///
/// # Shutdown
///
/// The runner exits cleanly when:
/// - `ConsensusEvent::Shutdown` is received
/// - All senders are dropped (channel returns `None`)
/// - `max_ticks` limit is reached (for testing)
///
/// # Creating a Runner
///
/// Use `AsyncNodeRunner::new()` which returns both the runner and a sender:
///
/// ```ignore
/// let (runner, event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(100));
///
/// // event_tx can be cloned and used by multiple tasks
/// let tx2 = event_tx.clone();
/// tokio::spawn(async move {
///     tx2.send(ConsensusEvent::IncomingMessage(msg)).await.unwrap();
/// });
///
/// runner.run().await?;
/// ```
pub struct AsyncNodeRunner {
    /// The underlying synchronous harness.
    harness: NodeHotstuffHarness,
    /// Tick interval for consensus steps.
    tick_interval: Duration,
    /// Optional maximum number of ticks (for testing).
    /// If `None`, runs indefinitely.
    max_ticks: Option<u64>,
    /// Receiver for consensus events from external tasks.
    events_rx: ConsensusEventReceiver,
    /// Optional metrics for observability (T89).
    metrics: Option<Arc<crate::metrics::NodeMetrics>>,
}

impl std::fmt::Debug for AsyncNodeRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncNodeRunner")
            .field("harness", &self.harness)
            .field("tick_interval", &self.tick_interval)
            .field("max_ticks", &self.max_ticks)
            .field("events_rx", &"<ConsensusEventReceiver>")
            .field("metrics", &self.metrics.is_some())
            .finish()
    }
}

impl AsyncNodeRunner {
    /// Create a new `AsyncNodeRunner` with the given harness and tick interval.
    ///
    /// Returns both the runner and a `ConsensusEventSender` that can be used by
    /// external tasks to send events to the consensus loop.
    ///
    /// # Arguments
    ///
    /// - `harness`: The underlying `NodeHotstuffHarness` (already configured with
    ///   network, validators, and optional storage).
    /// - `tick_interval`: How often to call `on_tick()`. Reasonable default: 100ms.
    ///
    /// # Returns
    ///
    /// A tuple of `(AsyncNodeRunner, ConsensusEventSender)`. The sender can be
    /// cloned and shared with multiple tasks.
    ///
    /// # Channel Capacity
    ///
    /// The event channel is created with `DEFAULT_EVENT_CHANNEL_CAPACITY` (1024).
    /// Use `new_with_capacity()` for custom capacity.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (runner, event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(100));
    ///
    /// // Spawn a task that sends events
    /// let tx = event_tx.clone();
    /// tokio::spawn(async move {
    ///     tx.send(ConsensusEvent::IncomingMessage(msg)).await.unwrap();
    /// });
    ///
    /// // Run the consensus loop
    /// runner.run().await?;
    /// ```
    pub fn new(
        harness: NodeHotstuffHarness,
        tick_interval: Duration,
    ) -> (Self, ConsensusEventSender) {
        Self::new_with_capacity(harness, tick_interval, DEFAULT_EVENT_CHANNEL_CAPACITY)
    }

    /// Create a new `AsyncNodeRunner` with custom channel capacity.
    ///
    /// # Arguments
    ///
    /// - `harness`: The underlying `NodeHotstuffHarness`
    /// - `tick_interval`: How often to call `on_tick()`
    /// - `capacity`: Buffer size for the event channel
    ///
    /// # Example
    ///
    /// ```ignore
    /// // High-throughput node with larger buffer
    /// let (runner, event_tx) = AsyncNodeRunner::new_with_capacity(
    ///     harness,
    ///     Duration::from_millis(50),
    ///     4096,
    /// );
    /// ```
    pub fn new_with_capacity(
        harness: NodeHotstuffHarness,
        tick_interval: Duration,
        capacity: usize,
    ) -> (Self, ConsensusEventSender) {
        let (tx, rx) = mpsc::channel(capacity);
        let runner = AsyncNodeRunner {
            harness,
            tick_interval,
            max_ticks: None,
            events_rx: rx,
            metrics: None,
        };
        (runner, tx)
    }

    /// Create a new `AsyncNodeRunner` with channel capacity from config.
    ///
    /// This constructor uses the `consensus_event_capacity` field from the
    /// provided `ChannelCapacityConfig`.
    ///
    /// # Arguments
    ///
    /// - `harness`: The underlying `NodeHotstuffHarness`
    /// - `tick_interval`: How often to call `on_tick()`
    /// - `config`: Channel capacity configuration
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = ChannelCapacityConfig::from_env();
    /// let (runner, event_tx) = AsyncNodeRunner::new_with_config(
    ///     harness,
    ///     Duration::from_millis(50),
    ///     &config,
    /// );
    /// ```
    pub fn new_with_config(
        harness: NodeHotstuffHarness,
        tick_interval: Duration,
        config: &ChannelCapacityConfig,
    ) -> (Self, ConsensusEventSender) {
        Self::new_with_capacity(harness, tick_interval, config.consensus_event_capacity)
    }

    /// Set a maximum number of ticks for this runner (primarily for testing).
    ///
    /// When `max_ticks` is set, `run()` will return `Ok(())` after that many
    /// ticks instead of running indefinitely.
    ///
    /// # Arguments
    ///
    /// - `max`: Maximum number of ticks before returning.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let runner = AsyncNodeRunner::new(harness, Duration::from_millis(10))
    ///     .with_max_ticks(100);  // Run for 100 ticks then exit
    /// ```
    pub fn with_max_ticks(mut self, max: u64) -> Self {
        self.max_ticks = Some(max);
        self
    }

    /// Configure metrics for the runner (T89).
    ///
    /// When metrics are configured, the runner tracks:
    /// - Event counts by type (tick, incoming_message, shutdown)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let metrics = Arc::new(NodeMetrics::new());
    /// let (runner, event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(100));
    /// let runner = runner.with_metrics(metrics);
    /// ```
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::NodeMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Access the underlying harness (immutable).
    pub fn harness(&self) -> &NodeHotstuffHarness {
        &self.harness
    }

    /// Access the underlying harness (mutable).
    ///
    /// Use this to inspect consensus state, drain commits, etc.
    pub fn harness_mut(&mut self) -> &mut NodeHotstuffHarness {
        &mut self.harness
    }

    /// Access the metrics (if configured).
    pub fn metrics(&self) -> Option<&Arc<crate::metrics::NodeMetrics>> {
        self.metrics.as_ref()
    }

    /// Get the configured tick interval.
    pub fn tick_interval(&self) -> Duration {
        self.tick_interval
    }

    /// Run startup validation using the provided governance and backend registry.
    ///
    /// This should be called before `run()` to ensure configuration consistency.
    ///
    /// # Type Parameters
    ///
    /// * `CG` - The governance type implementing `ValidatorEnumerator`.
    /// * `BR` - The backend registry type implementing `ConsensusSigBackendRegistry`.
    ///
    /// # Arguments
    ///
    /// * `governance` - Governance implementation for looking up validator keys.
    /// * `backend_registry` - Registry mapping suite IDs to verifier backends.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if validation passes.
    /// * `Err(AsyncNodeError::StartupValidation(_))` if validation fails.
    pub fn validate_startup_with<CG, BR>(
        &self,
        governance: Arc<CG>,
        backend_registry: Arc<BR>,
    ) -> Result<(), AsyncNodeError>
    where
        CG: ValidatorEnumerator + Send + Sync,
        BR: ConsensusSigBackendRegistry + Send + Sync,
    {
        self.harness
            .validate_startup_with(governance, backend_registry)?;
        Ok(())
    }

    /// Load persisted state from storage on startup.
    ///
    /// This restores the consensus engine to the last committed state. If no
    /// storage is attached or no state exists, this is a no-op and the node
    /// starts fresh from genesis.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(block_id))` if persisted state was loaded.
    /// * `Ok(None)` if no persisted state (fresh node).
    /// * `Err(AsyncNodeError::Harness(_))` if loading fails.
    pub fn load_persisted_state(&mut self) -> Result<Option<[u8; 32]>, AsyncNodeError> {
        Ok(self.harness.load_persisted_state()?)
    }

    /// Run the async consensus loop.
    ///
    /// This method uses `tokio::select!` to multiplex between:
    /// 1. Timer ticks - calls `harness.on_tick()` directly
    /// 2. Channel events - dispatches based on event type
    ///
    /// # Lifecycle
    ///
    /// The runner exits cleanly when:
    /// - `ConsensusEvent::Shutdown` is received
    /// - All senders are dropped (channel returns `None`)
    /// - `max_ticks` limit is reached (for testing)
    ///
    /// Errors from harness methods are treated as fatal and returned.
    ///
    /// # Event Ordering
    ///
    /// Timer ticks and channel events are handled by `tokio::select!`. When
    /// both are ready simultaneously, either may be processed first. This is
    /// acceptable because consensus safety does not depend on strict ordering
    /// between ticks and messages - only on the content of the messages.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[tokio::main]
    /// async fn main() -> Result<(), AsyncNodeError> {
    ///     let (mut runner, event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(100));
    ///     
    ///     // Optional: validate startup and load persisted state
    ///     runner.validate_startup_with(governance, backend_registry)?;
    ///     runner.load_persisted_state()?;
    ///
    ///     // Run the consensus loop
    ///     runner.run().await
    /// }
    /// ```
    pub async fn run(mut self) -> Result<(), AsyncNodeError> {
        self.run_loop_internal().await
    }

    /// Run the async consensus loop with a mutable reference.
    ///
    /// This variant keeps ownership of the runner, allowing inspection after
    /// the run completes. Useful for testing where you want to check state
    /// after running for a bounded number of ticks.
    ///
    /// # Arguments
    ///
    /// - Returns `Ok(())` when `max_ticks` is reached or on clean shutdown.
    /// - Returns `Err(AsyncNodeError)` on errors.
    pub async fn run_mut(&mut self) -> Result<(), AsyncNodeError> {
        self.run_loop_internal().await
    }

    /// Internal implementation of the event-driven consensus loop.
    ///
    /// Uses `tokio::select!` to multiplex:
    /// - Timer ticks: Advance the consensus state via `harness.on_tick()`
    /// - Channel events: Process incoming messages and shutdown signals
    ///
    /// # Event Processing
    ///
    /// - `ConsensusEvent::Tick`: Calls `harness.on_tick()` (same as timer tick)
    /// - `ConsensusEvent::IncomingMessage`: Calls `harness.on_incoming_message()`
    /// - `ConsensusEvent::Shutdown` or channel close: Exits the loop cleanly
    async fn run_loop_internal(&mut self) -> Result<(), AsyncNodeError> {
        let mut ticker: Interval = interval(self.tick_interval);
        let mut tick_count: u64 = 0;

        eprintln!(
            "[AsyncNodeRunner] Starting event-driven consensus loop with tick_interval={:?}",
            self.tick_interval
        );

        loop {
            tokio::select! {
                // Arm 1: Timer tick
                _ = ticker.tick() => {
                    tick_count += 1;

                    // Record tick metric (T89)
                    if let Some(ref metrics) = self.metrics {
                        metrics.runtime().inc_events_tick();
                    }

                    // Check if we've reached max_ticks (for testing)
                    if let Some(max) = self.max_ticks {
                        if tick_count > max {
                            eprintln!(
                                "[AsyncNodeRunner] Reached max_ticks={}, exiting normally",
                                max
                            );
                            return Ok(());
                        }
                    }

                    // Call the synchronous on_tick handler
                    // NOTE: This may block on network I/O and storage for now.
                    // Future tasks will make these operations async.
                    if let Err(err) = self.harness.on_tick() {
                        eprintln!(
                            "[AsyncNodeRunner] on_tick error at tick {}: {}",
                            tick_count, err
                        );
                        return Err(AsyncNodeError::Harness(err));
                    }

                    // Periodic progress logging (every 100 ticks in debug builds)
                    #[cfg(debug_assertions)]
                    if tick_count.is_multiple_of(100) {
                        let view = self.harness.current_view();
                        let height = self.harness.committed_height();
                        eprintln!(
                            "[AsyncNodeRunner] tick={}, view={}, committed_height={:?}",
                            tick_count, view, height
                        );
                    }
                }

                // Arm 2: Event from the channel
                maybe_event = self.events_rx.recv() => {
                    match maybe_event {
                        Some(ConsensusEvent::Tick) => {
                            // External tick event - same as timer tick
                            tick_count += 1;

                            // Record tick metric (T89)
                            if let Some(ref metrics) = self.metrics {
                                metrics.runtime().inc_events_tick();
                            }

                            if let Err(err) = self.harness.on_tick() {
                                eprintln!(
                                    "[AsyncNodeRunner] on_tick error from event at tick {}: {}",
                                    tick_count, err
                                );
                                return Err(AsyncNodeError::Harness(err));
                            }
                        }
                        Some(ConsensusEvent::IncomingMessage(msg)) => {
                            // Record incoming message metric (T89)
                            if let Some(ref metrics) = self.metrics {
                                metrics.runtime().inc_events_incoming_message();
                            }

                            // Process incoming consensus message (unbox the event)
                            if let Err(err) = self.harness.on_incoming_message(*msg) {
                                eprintln!(
                                    "[AsyncNodeRunner] on_incoming_message error: {}",
                                    err
                                );
                                return Err(AsyncNodeError::Harness(err));
                            }
                        }
                        Some(ConsensusEvent::Shutdown) => {
                            // Record shutdown metric (T89)
                            if let Some(ref metrics) = self.metrics {
                                metrics.runtime().inc_events_shutdown();
                            }

                            // Graceful shutdown requested
                            eprintln!("[AsyncNodeRunner] Shutdown event received, exiting normally");
                            return Ok(());
                        }
                        None => {
                            // All senders dropped - graceful shutdown
                            eprintln!("[AsyncNodeRunner] Event channel closed, exiting normally");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_node_error_display() {
        let err = AsyncNodeError::Cancelled;
        assert_eq!(err.to_string(), "runner cancelled");

        let harness_err = NodeHotstuffHarnessError::Config("test config error".to_string());
        let err2 = AsyncNodeError::Harness(harness_err);
        assert!(err2.to_string().contains("test config error"));
    }
}
