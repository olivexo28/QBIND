//! Tests for priority-based sending and backpressure (T90.3).
//!
//! These tests validate the new behavior introduced in T90.3:
//! - Critical messages are never dropped when the channel is full
//! - Normal messages can be dropped under load with metrics
//! - Priority metrics are correctly tracked
//! - Backwards compatibility is maintained
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test priority_based_sending_tests -- --nocapture
//! ```

use std::sync::Arc;
use std::time::Duration;

use qbind_node::consensus_net_worker::{
    spawn_critical_outbound_worker_with_metrics, AsyncNetSender, ConsensusMsgPriority,
    ConsensusNetSender, OutboundCommand,
};
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

// ============================================================================
// Part D Test 1: Critical messages are not dropped
// ============================================================================

/// Test that critical messages are never dropped, even when the bounded
/// outbound channel is full.
///
/// This test:
/// 1. Creates an AsyncNetSender with a very small bounded channel (capacity 1)
/// 2. Floods it with a large number of Critical commands via the sync API
/// 3. Uses a slow consumer to drain the bounded channel
/// 4. Asserts that no "dropped" counters for priority=critical
/// 5. Asserts that all critical commands eventually reach the consumer
#[tokio::test]
async fn critical_messages_are_not_dropped() {
    let metrics = Arc::new(NodeMetrics::new());

    // Create sender with very small bounded channel (capacity 1)
    let (sender, mut outbound_rx, critical_rx) =
        AsyncNetSender::with_channel_and_metrics(1, metrics.clone());

    // Spawn the critical worker that forwards critical messages
    let critical_worker = spawn_critical_outbound_worker_with_metrics(
        critical_rx,
        sender.outbound_tx(),
        Some(metrics.clone()),
    );

    // Number of critical messages to send
    const NUM_CRITICAL_MESSAGES: usize = 100;

    // Send many critical messages (these go to unbounded critical channel)
    for i in 0..NUM_CRITICAL_MESSAGES {
        sender
            .broadcast_vote_critical(&make_dummy_vote(i as u64, 0))
            .unwrap();
    }

    // Drain the outbound channel slowly (simulating slow consumer)
    let mut received_count = 0;
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();

    while received_count < NUM_CRITICAL_MESSAGES && start.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(100), outbound_rx.recv()).await {
            Ok(Some(_cmd)) => {
                received_count += 1;
            }
            Ok(None) => break,  // Channel closed
            Err(_) => continue, // Timeout, try again
        }
    }

    // Drop sender to close channels and allow worker to finish
    drop(sender);

    // Wait for critical worker to finish
    let _ = tokio::time::timeout(Duration::from_secs(1), critical_worker).await;

    // Assert: no drops for critical priority
    assert_eq!(
        metrics
            .network()
            .outbound_dropped_by_priority(ConsensusMsgPriority::Critical),
        0,
        "Critical messages should never be dropped"
    );

    // Assert: all critical messages were received
    assert_eq!(
        received_count, NUM_CRITICAL_MESSAGES,
        "All {} critical messages should be received, got {}",
        NUM_CRITICAL_MESSAGES, received_count
    );

    // Assert: critical worker delivered all messages
    assert!(
        metrics.network().outbound_critical_worker_total() > 0,
        "Critical worker should have delivered some messages"
    );
}

// ============================================================================
// Part D Test 2: Normal messages can be dropped
// ============================================================================

/// Test that normal messages can be dropped when the channel is full.
///
/// This test:
/// 1. Creates an AsyncNetSender with a small capacity
/// 2. Fills the outbound channel with a few Normal commands
/// 3. Attempts additional Normal sends
/// 4. Asserts that the send returns an error (NetError::ChannelFull)
/// 5. Asserts that drop metrics increment for priority=normal
/// 6. Asserts that critical metrics remain unaffected
#[tokio::test]
async fn normal_messages_can_be_dropped() {
    let metrics = Arc::new(NodeMetrics::new());

    // Create sender with small bounded channel (capacity 2)
    let (sender, _outbound_rx, _critical_rx) =
        AsyncNetSender::with_channel_and_metrics(2, metrics.clone());

    let vote = make_dummy_vote(1, 0);

    // Fill the channel with normal messages
    sender.broadcast_vote_normal(&vote).unwrap();
    sender.broadcast_vote_normal(&vote).unwrap();

    // This should fail (channel full)
    let result = sender.broadcast_vote_normal(&vote);
    assert!(result.is_err(), "Third normal send should fail");

    // Assert: drop counter incremented for normal
    assert_eq!(
        metrics
            .network()
            .outbound_dropped_by_priority(ConsensusMsgPriority::Normal),
        1,
        "One normal message should be dropped"
    );

    // Assert: aggregate drop counter also incremented
    assert_eq!(
        metrics.network().outbound_dropped_total(),
        1,
        "Aggregate drop counter should be 1"
    );

    // Assert: critical drop counter unaffected
    assert_eq!(
        metrics
            .network()
            .outbound_dropped_by_priority(ConsensusMsgPriority::Critical),
        0,
        "Critical drop counter should remain 0"
    );
}

// ============================================================================
// Part D Test 3: Priority metrics and logs
// ============================================================================

/// Test that priority metrics are correctly tracked for a mix of messages.
#[tokio::test]
async fn priority_metrics_tracked_correctly() {
    let metrics = Arc::new(NodeMetrics::new());

    let (sender, _outbound_rx, _critical_rx) =
        AsyncNetSender::with_channel_and_metrics(100, metrics.clone());

    let vote = make_dummy_vote(1, 0);
    let proposal = make_dummy_proposal(1, 0);

    // Send a mix of critical and normal messages
    sender.send_vote_to_critical(PeerId(1), &vote).unwrap();
    sender.send_vote_to_critical(PeerId(2), &vote).unwrap();
    sender.send_vote_to_normal(PeerId(3), &vote).unwrap();

    sender.broadcast_vote_critical(&vote).unwrap();
    sender.broadcast_vote_normal(&vote).unwrap();
    sender.broadcast_vote_normal(&vote).unwrap();

    sender.broadcast_proposal_critical(&proposal).unwrap();
    sender.broadcast_proposal_normal(&proposal).unwrap();

    // Check per-priority counters
    assert_eq!(
        metrics
            .network()
            .outbound_vote_send_to_by_priority(ConsensusMsgPriority::Critical),
        2,
        "Should have 2 critical vote_send_to"
    );
    assert_eq!(
        metrics
            .network()
            .outbound_vote_send_to_by_priority(ConsensusMsgPriority::Normal),
        1,
        "Should have 1 normal vote_send_to"
    );

    assert_eq!(
        metrics
            .network()
            .outbound_vote_broadcast_by_priority(ConsensusMsgPriority::Critical),
        1,
        "Should have 1 critical vote_broadcast"
    );
    assert_eq!(
        metrics
            .network()
            .outbound_vote_broadcast_by_priority(ConsensusMsgPriority::Normal),
        2,
        "Should have 2 normal vote_broadcast"
    );

    assert_eq!(
        metrics
            .network()
            .outbound_proposal_broadcast_by_priority(ConsensusMsgPriority::Critical),
        1,
        "Should have 1 critical proposal_broadcast"
    );
    assert_eq!(
        metrics
            .network()
            .outbound_proposal_broadcast_by_priority(ConsensusMsgPriority::Normal),
        1,
        "Should have 1 normal proposal_broadcast"
    );

    // Check critical channel counter
    assert_eq!(
        metrics.network().outbound_critical_total(),
        4,
        "Should have 4 critical messages sent to critical channel (2+1+1)"
    );
}

// ============================================================================
// Part D Test 4: Backwards compatibility
// ============================================================================

/// Test that existing tests that didn't care about priorities still pass.
/// The ConsensusNetSender trait methods default to Critical priority.
#[tokio::test]
async fn backwards_compatibility_consensus_net_sender_trait() {
    let metrics = Arc::new(NodeMetrics::new());

    let (sender, _outbound_rx, mut critical_rx) =
        AsyncNetSender::with_channel_and_metrics(100, metrics.clone());

    let vote = make_dummy_vote(1, 0);
    let proposal = make_dummy_proposal(1, 0);

    // Use the ConsensusNetSender trait (as existing code would)
    ConsensusNetSender::send_vote_to(&sender, PeerId(1), &vote).unwrap();
    ConsensusNetSender::broadcast_vote(&sender, &vote).unwrap();
    ConsensusNetSender::broadcast_proposal(&sender, &proposal).unwrap();

    // All should go to critical channel (default behavior)
    assert!(critical_rx.recv().await.is_some(), "First message");
    assert!(critical_rx.recv().await.is_some(), "Second message");
    assert!(critical_rx.recv().await.is_some(), "Third message");

    // Check that aggregate counters work as before
    assert_eq!(metrics.network().outbound_vote_send_to_total(), 1);
    assert_eq!(metrics.network().outbound_vote_broadcast_total(), 1);
    assert_eq!(metrics.network().outbound_proposal_broadcast_total(), 1);
}

/// Test that the default priority is Normal for backwards compatibility.
#[test]
fn default_priority_is_normal() {
    assert_eq!(
        ConsensusMsgPriority::default(),
        ConsensusMsgPriority::Normal,
        "Default priority should be Normal for backwards compatibility"
    );
}

// ============================================================================
// Part D Test 5: OutboundCommand priority accessor
// ============================================================================

#[test]
fn outbound_command_priority_accessor_works() {
    let vote = make_dummy_vote(1, 0);
    let proposal = make_dummy_proposal(1, 0);

    let cmd_critical = OutboundCommand::BroadcastVote {
        vote: vote.clone(),
        priority: ConsensusMsgPriority::Critical,
    };
    assert_eq!(cmd_critical.priority(), ConsensusMsgPriority::Critical);
    assert!(cmd_critical.is_critical());

    let cmd_normal = OutboundCommand::SendVoteTo {
        to: PeerId(1),
        vote: vote.clone(),
        priority: ConsensusMsgPriority::Normal,
    };
    assert_eq!(cmd_normal.priority(), ConsensusMsgPriority::Normal);
    assert!(!cmd_normal.is_critical());

    let cmd_low = OutboundCommand::BroadcastProposal {
        proposal: proposal.clone(),
        priority: ConsensusMsgPriority::Low,
    };
    assert_eq!(cmd_low.priority(), ConsensusMsgPriority::Low);
    assert!(!cmd_low.is_critical());
}

// ============================================================================
// Part D Test 6: Critical worker backpressure tracking
// ============================================================================

/// Test that the critical worker tracks backpressure wait times.
#[tokio::test]
async fn critical_worker_tracks_backpressure() {
    let metrics = Arc::new(NodeMetrics::new());

    // Create sender with very small bounded channel
    let (sender, mut outbound_rx, critical_rx) =
        AsyncNetSender::with_channel_and_metrics(1, metrics.clone());

    // Clone outbound_tx for the worker
    let outbound_tx = sender.outbound_tx();

    // Spawn the critical worker
    let _critical_worker = spawn_critical_outbound_worker_with_metrics(
        critical_rx,
        outbound_tx,
        Some(metrics.clone()),
    );

    // Send a few critical messages
    sender
        .broadcast_vote_critical(&make_dummy_vote(1, 0))
        .unwrap();
    sender
        .broadcast_vote_critical(&make_dummy_vote(2, 0))
        .unwrap();

    // Give the worker time to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drain one message (allows next one to be processed)
    let _ = outbound_rx.recv().await;

    // Give more time
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drain remaining
    while outbound_rx.try_recv().is_ok() {}

    // Check that critical worker metrics were recorded
    let (under_1ms, _1ms_to_10ms, _10ms_to_100ms, _over_100ms) =
        metrics.network().critical_wait_buckets();

    // At least some operations should have completed quickly
    assert!(
        under_1ms > 0 || metrics.network().outbound_critical_worker_total() > 0,
        "Critical worker should have processed messages or recorded wait times"
    );
}

// ============================================================================
// Part D Test 7: Mixed priority flood test
// ============================================================================

/// Test behavior when flooding with both critical and normal messages.
#[tokio::test]
async fn mixed_priority_flood() {
    let metrics = Arc::new(NodeMetrics::new());

    // Create sender with small bounded channel
    let (sender, mut outbound_rx, critical_rx) =
        AsyncNetSender::with_channel_and_metrics(5, metrics.clone());

    let outbound_tx = sender.outbound_tx();

    // Spawn critical worker
    let critical_worker = spawn_critical_outbound_worker_with_metrics(
        critical_rx,
        outbound_tx,
        Some(metrics.clone()),
    );

    // Send interleaved critical and normal messages
    for i in 0..20 {
        if i % 2 == 0 {
            sender
                .broadcast_vote_critical(&make_dummy_vote(i as u64, 0))
                .unwrap();
        } else {
            // Normal messages may fail if channel is full
            let _ = sender.broadcast_vote_normal(&make_dummy_vote(i as u64, 0));
        }
    }

    // Drain all messages
    let timeout = Duration::from_secs(2);
    let start = std::time::Instant::now();
    let mut received_count = 0;

    while start.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(50), outbound_rx.recv()).await {
            Ok(Some(_)) => received_count += 1,
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(1), critical_worker).await;

    // All critical messages (10 total) should have been received
    // Some normal messages may have been dropped
    assert!(
        received_count >= 10,
        "At least 10 critical messages should be received, got {}",
        received_count
    );

    // Critical drops should be 0
    assert_eq!(
        metrics
            .network()
            .outbound_dropped_by_priority(ConsensusMsgPriority::Critical),
        0,
        "No critical messages should be dropped"
    );
}