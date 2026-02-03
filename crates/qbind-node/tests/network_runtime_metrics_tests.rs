//! Integration tests for network and runtime observability metrics (T89).
//!
//! These tests verify that the metrics added in T89 are correctly
//! incremented during network and runtime operations.
//!
//! # Test Categories
//!
//! - **Metrics increment tests**: Verify counters increment correctly
//! - **Load harness tests**: Verify the harness runs without panicking
//! - **Integration tests**: Verify metrics flow through the full stack
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test network_runtime_metrics_tests -- --nocapture
//! ```

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use qbind_consensus::network::ConsensusNetworkEvent;
use qbind_node::consensus_net_worker::{
    AsyncNetSender, ConsensusNetSender, ConsensusNetService, ConsensusNetWorker,
};
use qbind_node::load_harness::{run_load_harness, LoadHarnessConfig};
use qbind_node::metrics::NodeMetrics;
use qbind_node::peer::PeerId;
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

// ============================================================================
// Test Helpers
// ============================================================================

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
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

/// A mock implementation of `ConsensusNetService` for testing metrics.
#[derive(Clone)]
struct MetricsMockNetService {
    /// Queue of events to return from `recv()`.
    inbound: Arc<std::sync::Mutex<std::collections::VecDeque<ConsensusNetworkEvent<PeerId>>>>,
}

impl MetricsMockNetService {
    fn new() -> Self {
        MetricsMockNetService {
            inbound: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        }
    }

    fn with_events(events: Vec<ConsensusNetworkEvent<PeerId>>) -> Self {
        let mock = Self::new();
        {
            let mut inbound = mock.inbound.lock().unwrap();
            for event in events {
                inbound.push_back(event);
            }
        }
        mock
    }
}

impl ConsensusNetService for MetricsMockNetService {
    async fn recv(&mut self) -> Option<ConsensusNetworkEvent<PeerId>> {
        let mut inbound = self.inbound.lock().unwrap();
        inbound.pop_front()
    }

    async fn send_vote_to(
        &mut self,
        _to: PeerId,
        _vote: &Vote,
    ) -> Result<(), qbind_consensus::network::NetworkError> {
        Ok(())
    }

    async fn broadcast_vote(
        &mut self,
        _vote: &Vote,
    ) -> Result<(), qbind_consensus::network::NetworkError> {
        Ok(())
    }

    async fn broadcast_proposal(
        &mut self,
        _proposal: &BlockProposal,
    ) -> Result<(), qbind_consensus::network::NetworkError> {
        Ok(())
    }
}

// ============================================================================
// Part A: Network metrics tests
// ============================================================================

/// Test that inbound vote metrics increment when processing votes via ConsensusNetWorker.
#[tokio::test]
async fn network_worker_metrics_inbound_vote_increment() {
    let metrics = Arc::new(NodeMetrics::new());

    // Create mock with 3 vote events
    let events = vec![
        ConsensusNetworkEvent::IncomingVote {
            from: PeerId(1),
            vote: make_dummy_vote(1, 0),
        },
        ConsensusNetworkEvent::IncomingVote {
            from: PeerId(2),
            vote: make_dummy_vote(2, 0),
        },
        ConsensusNetworkEvent::IncomingVote {
            from: PeerId(3),
            vote: make_dummy_vote(3, 0),
        },
    ];

    let mock = MetricsMockNetService::with_events(events);
    let (tx, mut rx) = mpsc::channel(10);

    let worker = ConsensusNetWorker::with_metrics(mock, tx, metrics.clone());

    // Run worker
    let _ = worker.run().await;

    // Drain the channel
    while rx.try_recv().is_ok() {}

    // Check metrics
    assert_eq!(metrics.network().inbound_vote_total(), 3);
    assert_eq!(metrics.network().inbound_proposal_total(), 0);
}

/// Test that inbound proposal metrics increment when processing proposals.
#[tokio::test]
async fn network_worker_metrics_inbound_proposal_increment() {
    let metrics = Arc::new(NodeMetrics::new());

    // Create mock with 2 proposal events
    let events = vec![
        ConsensusNetworkEvent::IncomingProposal {
            from: PeerId(1),
            proposal: make_dummy_proposal(1, 0),
        },
        ConsensusNetworkEvent::IncomingProposal {
            from: PeerId(2),
            proposal: make_dummy_proposal(2, 0),
        },
    ];

    let mock = MetricsMockNetService::with_events(events);
    let (tx, mut rx) = mpsc::channel(10);

    let worker = ConsensusNetWorker::with_metrics(mock, tx, metrics.clone());

    // Run worker
    let _ = worker.run().await;

    // Drain the channel
    while rx.try_recv().is_ok() {}

    // Check metrics
    assert_eq!(metrics.network().inbound_vote_total(), 0);
    assert_eq!(metrics.network().inbound_proposal_total(), 2);
}

/// Test that mixed inbound events increment the correct counters.
#[tokio::test]
async fn network_worker_metrics_mixed_events() {
    let metrics = Arc::new(NodeMetrics::new());

    // Create mock with mixed events
    let events = vec![
        ConsensusNetworkEvent::IncomingVote {
            from: PeerId(1),
            vote: make_dummy_vote(1, 0),
        },
        ConsensusNetworkEvent::IncomingProposal {
            from: PeerId(2),
            proposal: make_dummy_proposal(2, 0),
        },
        ConsensusNetworkEvent::IncomingVote {
            from: PeerId(3),
            vote: make_dummy_vote(3, 0),
        },
        ConsensusNetworkEvent::IncomingProposal {
            from: PeerId(4),
            proposal: make_dummy_proposal(4, 0),
        },
        ConsensusNetworkEvent::IncomingVote {
            from: PeerId(5),
            vote: make_dummy_vote(5, 0),
        },
    ];

    let mock = MetricsMockNetService::with_events(events);
    let (tx, mut rx) = mpsc::channel(10);

    let worker = ConsensusNetWorker::with_metrics(mock, tx, metrics.clone());

    // Run worker
    let _ = worker.run().await;

    // Drain the channel
    while rx.try_recv().is_ok() {}

    // Check metrics
    assert_eq!(metrics.network().inbound_vote_total(), 3);
    assert_eq!(metrics.network().inbound_proposal_total(), 2);
}

// ============================================================================
// Part B: AsyncNetSender metrics tests
// ============================================================================

/// Test that outbound metrics increment when sending votes.
#[tokio::test]
async fn async_net_sender_metrics_outbound_vote() {
    let metrics = Arc::new(NodeMetrics::new());
    let (sender, mut rx, mut critical_rx) =
        AsyncNetSender::with_channel_and_metrics(10, metrics.clone());

    // Send votes using the ConsensusNetSender trait (which uses Critical by default)
    let vote1 = make_dummy_vote(1, 0);
    let vote2 = make_dummy_vote(2, 0);

    sender.send_vote_to(PeerId(1), &vote1).unwrap();
    sender.broadcast_vote(&vote2).unwrap();

    // Critical messages go to critical channel, drain it
    while critical_rx.try_recv().is_ok() {}
    while rx.try_recv().is_ok() {}

    // Check metrics - using critical priority by default
    assert_eq!(metrics.network().outbound_vote_send_to_total(), 1);
    assert_eq!(metrics.network().outbound_vote_broadcast_total(), 1);
    assert_eq!(metrics.network().outbound_proposal_broadcast_total(), 0);
}

/// Test that outbound proposal metrics increment when broadcasting proposals.
#[tokio::test]
async fn async_net_sender_metrics_outbound_proposal() {
    let metrics = Arc::new(NodeMetrics::new());
    let (sender, mut rx, mut critical_rx) =
        AsyncNetSender::with_channel_and_metrics(10, metrics.clone());

    // Send proposals using the ConsensusNetSender trait
    let proposal1 = make_dummy_proposal(1, 0);
    let proposal2 = make_dummy_proposal(2, 0);

    sender.broadcast_proposal(&proposal1).unwrap();
    sender.broadcast_proposal(&proposal2).unwrap();

    // Critical messages go to critical channel, drain it
    while critical_rx.try_recv().is_ok() {}
    while rx.try_recv().is_ok() {}

    // Check metrics
    assert_eq!(metrics.network().outbound_vote_send_to_total(), 0);
    assert_eq!(metrics.network().outbound_vote_broadcast_total(), 0);
    assert_eq!(metrics.network().outbound_proposal_broadcast_total(), 2);
}

/// Test that dropped message metrics increment when channel is full.
#[tokio::test]
async fn async_net_sender_metrics_dropped_on_full_channel() {
    let metrics = Arc::new(NodeMetrics::new());
    // Create a channel with capacity 2
    let (sender, _rx, _critical_rx) = AsyncNetSender::with_channel_and_metrics(2, metrics.clone());

    // Fill the channel with normal-priority messages (which use try_send)
    let vote = make_dummy_vote(1, 0);
    sender.broadcast_vote_normal(&vote).unwrap();
    sender.broadcast_vote_normal(&vote).unwrap();

    // This should fail and increment the dropped counter
    let result = sender.broadcast_vote_normal(&vote);
    assert!(result.is_err());

    // Check metrics
    assert_eq!(metrics.network().outbound_dropped_total(), 1);
}

// ============================================================================
// Part C: Load harness tests
// ============================================================================

/// Test that load harness completes a small synthetic workload.
#[tokio::test]
async fn load_harness_completes_synthetic_workload() {
    let config = LoadHarnessConfig::new()
        .with_message_count(100)
        .with_rate_per_second(1000)
        .with_verbose(false);

    let result = run_load_harness(config).await;
    assert!(result.is_ok(), "load harness should complete");

    let harness_result = result.unwrap();
    assert!(
        harness_result.completed,
        "harness should complete successfully"
    );
    assert_eq!(harness_result.messages_injected, 100);

    // Verify metrics were recorded
    let network = harness_result.metrics.network();
    let total_inbound = network.inbound_vote_total() + network.inbound_proposal_total();
    assert!(total_inbound > 0, "should have recorded inbound messages");
}

/// Test that load harness runs with default configuration.
#[tokio::test]
async fn load_harness_runs_with_default_config() {
    let config = LoadHarnessConfig::default().with_verbose(false);

    let result = run_load_harness(config).await;
    assert!(result.is_ok(), "load harness should run with defaults");
}

/// Test that load harness metrics are non-zero after run.
#[tokio::test]
async fn load_harness_metrics_populated() {
    let config = LoadHarnessConfig::new()
        .with_message_count(50)
        .with_rate_per_second(500)
        .with_vote_ratio(0.6) // 60% votes, 40% proposals
        .with_verbose(false);

    let result = run_load_harness(config).await.expect("should complete");

    // Metrics should be populated
    let network = result.metrics.network();
    let runtime = result.metrics.runtime();

    assert!(
        network.inbound_vote_total() > 0 || network.inbound_proposal_total() > 0,
        "should have recorded some inbound events"
    );

    // Runtime should have processed incoming messages
    assert!(
        runtime.events_incoming_message_total() > 0,
        "runtime should have processed incoming messages"
    );

    // Shutdown should be recorded
    assert_eq!(
        runtime.events_shutdown_total(),
        1,
        "should have recorded shutdown event"
    );
}

// ============================================================================
// Part D: spawn_blocking metrics tests
// ============================================================================

/// Test that spawn_blocking metrics are recorded.
#[test]
fn spawn_blocking_metrics_record_correctly() {
    use std::time::Duration;

    let metrics = NodeMetrics::new();

    // Record various durations
    metrics
        .spawn_blocking()
        .record_blocking_duration(Duration::from_micros(500));
    metrics
        .spawn_blocking()
        .record_blocking_duration(Duration::from_millis(5));
    metrics
        .spawn_blocking()
        .record_blocking_duration(Duration::from_millis(50));
    metrics
        .spawn_blocking()
        .record_blocking_duration(Duration::from_millis(150));

    // Check totals
    assert_eq!(metrics.spawn_blocking().spawn_blocking_total(), 4);

    // Check buckets
    assert_eq!(metrics.spawn_blocking().latency_under_1ms(), 1);
    assert_eq!(metrics.spawn_blocking().latency_1ms_to_10ms(), 1);
    assert_eq!(metrics.spawn_blocking().latency_10ms_to_100ms(), 1);
    assert_eq!(metrics.spawn_blocking().latency_over_100ms(), 1);
}

// ============================================================================
// Part E: Metrics format output test
// ============================================================================

/// Test that metrics format produces valid Prometheus-compatible output.
#[test]
fn metrics_format_produces_prometheus_output() {
    let metrics = NodeMetrics::new();

    // Populate some metrics
    metrics.network().inc_inbound_vote();
    metrics.network().inc_inbound_vote();
    metrics.network().inc_inbound_proposal();
    metrics.network().inc_outbound_vote_broadcast();
    metrics.runtime().inc_events_tick();
    metrics.runtime().inc_events_tick();
    metrics.runtime().inc_events_tick();
    metrics
        .spawn_blocking()
        .record_blocking_duration(Duration::from_micros(500));

    let output = metrics.format_metrics();

    // Verify key metrics appear in output
    assert!(output.contains("consensus_net_inbound_total{kind=\"vote\"} 2"));
    assert!(output.contains("consensus_net_inbound_total{kind=\"proposal\"} 1"));
    assert!(output.contains("consensus_net_outbound_total{kind=\"vote_broadcast\"} 1"));
    assert!(output.contains("consensus_events_total{kind=\"tick\"} 3"));
    assert!(output.contains("consensus_net_spawn_blocking_total 1"));
}
