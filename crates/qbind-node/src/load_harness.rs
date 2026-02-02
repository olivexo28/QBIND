//! Single-node load harness for testing the async consensus node (T89).
//!
//! This module provides a self-contained load harness designed for:
//! - Stress testing the async node runtime and network stack
//! - Measuring metrics under synthetic load
//! - Enabling Devin or scripts to drive load testing
//!
//! # Design
//!
//! The load harness:
//! - Runs a single node with `AsyncNodeRunner` and loopback network
//! - Injects configurable streams of synthetic consensus messages
//! - Exposes metrics via the `NodeMetrics` API
//! - Supports configuration via environment variables or config structs
//!
//! # Usage
//!
//! ## As a test
//!
//! ```ignore
//! use qbind_node::load_harness::{LoadHarnessConfig, LoadGenerator, run_load_harness};
//!
//! #[tokio::test]
//! async fn stress_test() {
//!     let config = LoadHarnessConfig::default()
//!         .with_message_count(1000)
//!         .with_rate_per_second(100);
//!
//!     let result = run_load_harness(config).await;
//!     assert!(result.is_ok());
//!
//!     // Inspect metrics
//!     let metrics = result.unwrap();
//!     assert!(metrics.network().inbound_vote_total() > 0);
//! }
//! ```
//!
//! ## From command line (future)
//!
//! ```bash
//! LOAD_HARNESS_MESSAGES=1000 LOAD_HARNESS_RATE=100 cargo test -p qbind-node load_harness
//! ```
//!
//! # Metrics Exposure
//!
//! After a load run, metrics can be accessed via:
//! - `NodeMetrics::format_metrics()` - Prometheus-compatible string output
//! - Individual metric getters for programmatic access
//! - Printed to stderr during the run for live monitoring

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::async_runner::ConsensusEvent;
use crate::consensus_net_worker::ConsensusNetWorker;
use crate::metrics::NodeMetrics;
use crate::peer::PeerId;
use qbind_consensus::network::ConsensusNetworkEvent;
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

// ============================================================================
// LoadHarnessConfig
// ============================================================================

/// Configuration for the load harness.
///
/// # Defaults
///
/// - `message_count`: 100 messages
/// - `rate_per_second`: 50 messages/sec
/// - `vote_ratio`: 0.8 (80% votes, 20% proposals)
/// - `tick_interval`: 100ms
/// - `max_duration`: 30 seconds
#[derive(Debug, Clone)]
pub struct LoadHarnessConfig {
    /// Total number of synthetic messages to inject.
    pub message_count: u64,

    /// Target rate of message injection (messages per second).
    pub rate_per_second: u64,

    /// Ratio of votes to proposals (0.0 - 1.0).
    /// 1.0 = all votes, 0.0 = all proposals.
    pub vote_ratio: f64,

    /// Tick interval for the async runner.
    pub tick_interval: Duration,

    /// Maximum duration before forced shutdown.
    pub max_duration: Duration,

    /// Whether to print progress during the run.
    pub verbose: bool,
}

impl Default for LoadHarnessConfig {
    fn default() -> Self {
        LoadHarnessConfig {
            message_count: 100,
            rate_per_second: 50,
            vote_ratio: 0.8,
            tick_interval: Duration::from_millis(100),
            max_duration: Duration::from_secs(30),
            verbose: true,
        }
    }
}

impl LoadHarnessConfig {
    /// Create a new config with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the total number of messages to inject.
    pub fn with_message_count(mut self, count: u64) -> Self {
        self.message_count = count;
        self
    }

    /// Set the target message rate (messages per second).
    pub fn with_rate_per_second(mut self, rate: u64) -> Self {
        self.rate_per_second = rate;
        self
    }

    /// Set the ratio of votes to proposals.
    pub fn with_vote_ratio(mut self, ratio: f64) -> Self {
        self.vote_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Set the tick interval for the runner.
    pub fn with_tick_interval(mut self, interval: Duration) -> Self {
        self.tick_interval = interval;
        self
    }

    /// Set the maximum duration before forced shutdown.
    pub fn with_max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = duration;
        self
    }

    /// Enable or disable verbose output.
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Load configuration from environment variables.
    ///
    /// Supported variables:
    /// - `LOAD_HARNESS_MESSAGES`: Total message count
    /// - `LOAD_HARNESS_RATE`: Messages per second
    /// - `LOAD_HARNESS_VOTE_RATIO`: Ratio of votes (0.0-1.0)
    /// - `LOAD_HARNESS_TICK_MS`: Tick interval in milliseconds
    /// - `LOAD_HARNESS_MAX_SECS`: Maximum duration in seconds
    /// - `LOAD_HARNESS_VERBOSE`: "true" or "false"
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("LOAD_HARNESS_MESSAGES") {
            if let Ok(count) = val.parse() {
                config.message_count = count;
            }
        }

        if let Ok(val) = std::env::var("LOAD_HARNESS_RATE") {
            if let Ok(rate) = val.parse() {
                config.rate_per_second = rate;
            }
        }

        if let Ok(val) = std::env::var("LOAD_HARNESS_VOTE_RATIO") {
            if let Ok(ratio) = val.parse() {
                config.vote_ratio = ratio;
            }
        }

        if let Ok(val) = std::env::var("LOAD_HARNESS_TICK_MS") {
            if let Ok(ms) = val.parse::<u64>() {
                config.tick_interval = Duration::from_millis(ms);
            }
        }

        if let Ok(val) = std::env::var("LOAD_HARNESS_MAX_SECS") {
            if let Ok(secs) = val.parse::<u64>() {
                config.max_duration = Duration::from_secs(secs);
            }
        }

        if let Ok(val) = std::env::var("LOAD_HARNESS_VERBOSE") {
            config.verbose = val.to_lowercase() == "true";
        }

        config
    }
}

// ============================================================================
// LoadGenerator - Synthetic message generation
// ============================================================================

/// Generates synthetic consensus messages for load testing.
///
/// This generator creates fake votes and proposals that are structurally
/// valid but will not pass signature verification (since they use empty
/// signatures). This is appropriate for load testing the network and
/// runtime layers without exercising the full consensus verification path.
pub struct LoadGenerator {
    config: LoadHarnessConfig,
    messages_sent: u64,
    start_time: std::time::Instant,
}

impl LoadGenerator {
    /// Create a new load generator with the given configuration.
    pub fn new(config: LoadHarnessConfig) -> Self {
        LoadGenerator {
            config,
            messages_sent: 0,
            start_time: std::time::Instant::now(),
        }
    }

    /// Get the number of messages sent so far.
    pub fn messages_sent(&self) -> u64 {
        self.messages_sent
    }

    /// Check if the generator has sent all configured messages.
    pub fn is_complete(&self) -> bool {
        self.messages_sent >= self.config.message_count
    }

    /// Generate the next synthetic message.
    ///
    /// Returns `None` if all messages have been sent.
    pub fn next_message(&mut self) -> Option<ConsensusNetworkEvent<PeerId>> {
        if self.is_complete() {
            return None;
        }

        self.messages_sent += 1;

        // Deterministic vote vs proposal selection based on ratio
        // Use modulo 100 for precision to two decimal places
        let threshold = (self.config.vote_ratio * 100.0) as u64;
        let is_vote = (self.messages_sent % 100) < threshold;

        if is_vote {
            Some(ConsensusNetworkEvent::IncomingVote {
                from: PeerId(self.messages_sent % 100),
                vote: self.make_synthetic_vote(),
            })
        } else {
            Some(ConsensusNetworkEvent::IncomingProposal {
                from: PeerId(self.messages_sent % 100),
                proposal: self.make_synthetic_proposal(),
            })
        }
    }

    /// Calculate the delay needed to maintain the target rate.
    pub fn delay_for_rate(&self) -> Duration {
        if self.config.rate_per_second == 0 {
            return Duration::ZERO;
        }

        let elapsed = self.start_time.elapsed();
        // Use floating point to avoid overflow with large message counts
        let expected_secs = self.messages_sent as f64 / self.config.rate_per_second as f64;
        let expected_elapsed = Duration::from_secs_f64(expected_secs);

        if elapsed < expected_elapsed {
            expected_elapsed - elapsed
        } else {
            Duration::ZERO
        }
    }

    /// Create a synthetic vote for load testing.
    fn make_synthetic_vote(&self) -> Vote {
        Vote {
            version: 1,
            chain_id: 1,
            epoch: 0, // Static epoch for load testing (T101)
            height: self.messages_sent,
            round: 0,
            step: 0,
            block_id: [0u8; 32],
            validator_index: (self.messages_sent % 10) as u16,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signature: vec![], // Empty signature - will fail verification
        }
    }

    /// Create a synthetic proposal for load testing.
    fn make_synthetic_proposal(&self) -> BlockProposal {
        BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                epoch: 0, // Static epoch for load testing (T101)
                height: self.messages_sent,
                round: 0,
                parent_block_id: [0u8; 32],
                payload_hash: [0u8; 32],
                proposer_index: (self.messages_sent % 10) as u16,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 0,
                payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
                batch_commitment: [0u8; 32],
            },
            qc: None,
            txs: vec![],
            signature: vec![], // Empty signature - will fail verification
        }
    }
}

// ============================================================================
// LoopbackNetService - Self-contained network for single-node testing
// ============================================================================

use crate::consensus_net_worker::ConsensusNetService;
use qbind_consensus::network::NetworkError;

/// A loopback network service for single-node load testing.
///
/// This service:
/// - Receives messages from an internal queue (fed by the load generator)
/// - Discards outbound messages (single-node, no peers)
///
/// This allows testing the full async path without real network I/O.
pub struct LoopbackNetService {
    /// Receiver for injected messages.
    inbound_rx: mpsc::Receiver<ConsensusNetworkEvent<PeerId>>,
    /// Flag for shutdown.
    shutdown: bool,
}

impl LoopbackNetService {
    /// Create a new loopback service and return the sender for injecting messages.
    pub fn new(capacity: usize) -> (Self, mpsc::Sender<ConsensusNetworkEvent<PeerId>>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            LoopbackNetService {
                inbound_rx: rx,
                shutdown: false,
            },
            tx,
        )
    }

    /// Signal shutdown.
    pub fn shutdown(&mut self) {
        self.shutdown = true;
    }
}

impl ConsensusNetService for LoopbackNetService {
    async fn recv(&mut self) -> Option<ConsensusNetworkEvent<PeerId>> {
        if self.shutdown {
            return None;
        }
        self.inbound_rx.recv().await
    }

    async fn send_vote_to(&mut self, _to: PeerId, _vote: &Vote) -> Result<(), NetworkError> {
        // Loopback - discard outbound votes
        Ok(())
    }

    async fn broadcast_vote(&mut self, _vote: &Vote) -> Result<(), NetworkError> {
        // Loopback - discard outbound votes
        Ok(())
    }

    async fn broadcast_proposal(&mut self, _proposal: &BlockProposal) -> Result<(), NetworkError> {
        // Loopback - discard outbound proposals
        Ok(())
    }
}

// ============================================================================
// Load Harness Result
// ============================================================================

/// Result of a load harness run.
#[derive(Debug)]
pub struct LoadHarnessResult {
    /// The metrics collected during the run.
    pub metrics: Arc<NodeMetrics>,
    /// Total messages injected.
    pub messages_injected: u64,
    /// Duration of the run.
    pub duration: Duration,
    /// Whether the run completed successfully.
    pub completed: bool,
}

impl LoadHarnessResult {
    /// Print a summary of the load harness run.
    pub fn print_summary(&self) {
        eprintln!("\n========== Load Harness Results ==========");
        eprintln!("Completed: {}", self.completed);
        eprintln!("Duration: {:?}", self.duration);
        eprintln!("Messages injected: {}", self.messages_injected);
        eprintln!(
            "Effective rate: {:.2} msg/sec",
            self.messages_injected as f64 / self.duration.as_secs_f64()
        );
        eprintln!("\n--- Metrics ---");
        eprintln!("{}", self.metrics.format_metrics());
        eprintln!("=============================================\n");
    }
}

// ============================================================================
// run_load_harness - Main entry point
// ============================================================================

/// Error type for load harness operations.
#[derive(Debug)]
pub enum LoadHarnessError {
    /// Channel send failed.
    ChannelSend(String),
    /// Harness creation failed.
    HarnessCreation(String),
    /// Timeout exceeded.
    Timeout,
}

impl std::fmt::Display for LoadHarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadHarnessError::ChannelSend(msg) => write!(f, "channel send failed: {}", msg),
            LoadHarnessError::HarnessCreation(msg) => {
                write!(f, "harness creation failed: {}", msg)
            }
            LoadHarnessError::Timeout => write!(f, "load harness timeout exceeded"),
        }
    }
}

impl std::error::Error for LoadHarnessError {}

/// Run the load harness with the given configuration.
///
/// This function:
/// 1. Creates a single-node harness with loopback network
/// 2. Spawns a load generator that injects synthetic messages
/// 3. Runs until all messages are processed or timeout is reached
/// 4. Returns the collected metrics
///
/// # Example
///
/// ```ignore
/// use qbind_node::load_harness::{LoadHarnessConfig, run_load_harness};
///
/// #[tokio::test]
/// async fn load_test() {
///     let config = LoadHarnessConfig::default()
///         .with_message_count(500)
///         .with_rate_per_second(100);
///
///     let result = run_load_harness(config).await;
///     assert!(result.is_ok());
///     result.unwrap().print_summary();
/// }
/// ```
pub async fn run_load_harness(
    config: LoadHarnessConfig,
) -> Result<LoadHarnessResult, LoadHarnessError> {
    let start_time = std::time::Instant::now();
    let metrics = Arc::new(NodeMetrics::new());

    if config.verbose {
        eprintln!("[LoadHarness] Starting with config: {:?}", config);
    }

    // Create loopback network
    let (loopback_net, message_tx) = LoopbackNetService::new(1024);

    // Create event channel for the runner
    let (events_tx, events_rx) = mpsc::channel(1024);

    // Create a minimal harness-free setup:
    // Instead of a full NodeHotstuffHarness (which requires network configs),
    // we'll use a simplified approach that just exercises the network worker.
    // This tests the ConsensusNetWorker -> ConsensusEvent path.

    // Create network worker with metrics
    let net_worker =
        ConsensusNetWorker::with_metrics(loopback_net, events_tx.clone(), metrics.clone());

    // Create load generator
    let mut generator = LoadGenerator::new(config.clone());

    // Spawn the network worker
    let worker_handle = tokio::spawn(net_worker.run());

    // Spawn the load injector
    let inject_handle = tokio::spawn(async move {
        while let Some(event) = generator.next_message() {
            // Inject the message
            if let Err(e) = message_tx.send(event).await {
                eprintln!("[LoadHarness] Failed to inject message: {:?}", e);
                break;
            }

            // Delay to maintain target rate
            let delay = generator.delay_for_rate();
            if delay > Duration::ZERO {
                tokio::time::sleep(delay).await;
            }
        }

        // Close the channel to signal completion
        drop(message_tx);

        generator.messages_sent()
    });

    // Spawn event consumer (simulates runner processing)
    let consumer_metrics = metrics.clone();
    let consumer_handle = tokio::spawn(async move {
        let mut events_rx = events_rx;
        let mut count = 0u64;

        while let Some(event) = events_rx.recv().await {
            match event {
                ConsensusEvent::IncomingMessage(_) => {
                    consumer_metrics.runtime().inc_events_incoming_message();
                    count += 1;
                }
                ConsensusEvent::Tick => {
                    consumer_metrics.runtime().inc_events_tick();
                }
                ConsensusEvent::Shutdown => {
                    consumer_metrics.runtime().inc_events_shutdown();
                    break;
                }
            }
        }

        count
    });

    // Wait for completion or timeout
    let result = tokio::time::timeout(config.max_duration, async {
        // Wait for injector to complete
        let messages_injected = inject_handle.await.unwrap_or(0);

        // Send shutdown
        let _ = events_tx.send(ConsensusEvent::Shutdown).await;

        // Wait for worker and consumer
        let _ = worker_handle.await;
        let _ = consumer_handle.await;

        messages_injected
    })
    .await;

    let duration = start_time.elapsed();

    match result {
        Ok(messages_injected) => {
            let harness_result = LoadHarnessResult {
                metrics,
                messages_injected,
                duration,
                completed: true,
            };

            if config.verbose {
                harness_result.print_summary();
            }

            Ok(harness_result)
        }
        Err(_) => {
            // Timeout
            let harness_result = LoadHarnessResult {
                metrics,
                messages_injected: 0,
                duration,
                completed: false,
            };

            if config.verbose {
                eprintln!("[LoadHarness] Timeout exceeded!");
                harness_result.print_summary();
            }

            Err(LoadHarnessError::Timeout)
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
    fn load_harness_config_default() {
        let config = LoadHarnessConfig::default();
        assert_eq!(config.message_count, 100);
        assert_eq!(config.rate_per_second, 50);
        assert!((config.vote_ratio - 0.8).abs() < 0.001);
    }

    #[test]
    fn load_harness_config_builder() {
        let config = LoadHarnessConfig::new()
            .with_message_count(500)
            .with_rate_per_second(100)
            .with_vote_ratio(0.5);

        assert_eq!(config.message_count, 500);
        assert_eq!(config.rate_per_second, 100);
        assert!((config.vote_ratio - 0.5).abs() < 0.001);
    }

    #[test]
    fn load_generator_creates_expected_messages() {
        let config = LoadHarnessConfig::default()
            .with_message_count(10)
            .with_vote_ratio(1.0); // All votes

        let mut generator = LoadGenerator::new(config);

        let mut vote_count = 0;
        let mut proposal_count = 0;

        while let Some(event) = generator.next_message() {
            match event {
                ConsensusNetworkEvent::IncomingVote { .. } => vote_count += 1,
                ConsensusNetworkEvent::IncomingProposal { .. } => proposal_count += 1,
            }
        }

        assert_eq!(vote_count + proposal_count, 10);
        assert!(generator.is_complete());
    }

    #[test]
    fn load_generator_respects_vote_ratio() {
        let config = LoadHarnessConfig::default()
            .with_message_count(100)
            .with_vote_ratio(0.7);

        let mut generator = LoadGenerator::new(config);

        let mut vote_count = 0;
        let mut _proposal_count = 0;

        while let Some(event) = generator.next_message() {
            match event {
                ConsensusNetworkEvent::IncomingVote { .. } => vote_count += 1,
                ConsensusNetworkEvent::IncomingProposal { .. } => _proposal_count += 1,
            }
        }

        // Should be approximately 70% votes
        let vote_ratio = vote_count as f64 / 100.0;
        assert!((0.6..=0.8).contains(&vote_ratio));
    }

    #[tokio::test]
    async fn loopback_net_service_receives_messages() {
        let (mut service, tx) = LoopbackNetService::new(10);

        let vote = Vote {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 1,
            round: 0,
            step: 0,
            block_id: [0u8; 32],
            validator_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signature: vec![],
        };

        tx.send(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(1),
            vote: vote.clone(),
        })
        .await
        .unwrap();

        drop(tx);

        let event = service.recv().await;
        assert!(event.is_some());
        assert!(matches!(
            event.unwrap(),
            ConsensusNetworkEvent::IncomingVote { .. }
        ));

        let event2 = service.recv().await;
        assert!(event2.is_none());
    }

    #[tokio::test]
    async fn run_load_harness_completes_small_load() {
        let config = LoadHarnessConfig::default()
            .with_message_count(50)
            .with_rate_per_second(1000) // Fast rate for testing
            .with_verbose(false);

        let result = run_load_harness(config).await;
        assert!(result.is_ok());

        let harness_result = result.unwrap();
        assert!(harness_result.completed);
        assert_eq!(harness_result.messages_injected, 50);

        // Check that metrics were recorded
        let network_metrics = harness_result.metrics.network();
        let total_inbound =
            network_metrics.inbound_vote_total() + network_metrics.inbound_proposal_total();
        assert!(total_inbound > 0);
    }
}