//! Integration tests for the async consensus network adapter (T88).
//!
//! These tests verify the `AsyncConsensusNetAdapter` integration:
//! - Events flow from the async adapter to harness via the event channel
//! - Outbound messages are correctly routed through the async sender
//! - The adapter integrates with the full worker + runner path
//!
//! # Test Organization
//!
//! - **Adapter isolation tests**: Test the adapter with mock components
//! - **Full integration tests**: Test the complete path from adapter to harness
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test async_consensus_net_adapter_tests
//! ```

use std::time::Duration;

use qbind_consensus::network::ConsensusNetworkEvent;
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

use qbind_node::async_runner::ConsensusEvent;
use qbind_node::consensus_net_worker::{
    AsyncConsensusNetAdapter, AsyncNetSender, ConsensusNetSender, ConsensusNetService,
    ConsensusNetWorker, OutboundCommand,
};
use qbind_node::peer::PeerId;

use tokio::sync::mpsc;

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
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

// ============================================================================
// Part A: AsyncConsensusNetAdapter isolation tests
// ============================================================================

/// Test that the async adapter correctly receives events from the inbound channel.
#[tokio::test]
async fn async_adapter_receives_multiple_events() {
    let (mut adapter, inbound_tx, _outbound_rx) = AsyncConsensusNetAdapter::new();

    let vote1 = make_dummy_vote(1, 0);
    let vote2 = make_dummy_vote(2, 1);
    let proposal = make_dummy_proposal(3, 2);

    // Send multiple events
    inbound_tx
        .send(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(100),
            vote: vote1.clone(),
        })
        .await
        .unwrap();

    inbound_tx
        .send(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(200),
            vote: vote2.clone(),
        })
        .await
        .unwrap();

    inbound_tx
        .send(ConsensusNetworkEvent::IncomingProposal {
            from: PeerId(300),
            proposal: proposal.clone(),
        })
        .await
        .unwrap();

    // Close the channel
    drop(inbound_tx);

    // Receive all events in order
    let event1 = adapter.recv().await;
    assert!(matches!(
        event1,
        Some(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(100),
            ..
        })
    ));

    let event2 = adapter.recv().await;
    assert!(matches!(
        event2,
        Some(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(200),
            ..
        })
    ));

    let event3 = adapter.recv().await;
    assert!(matches!(
        event3,
        Some(ConsensusNetworkEvent::IncomingProposal {
            from: PeerId(300),
            ..
        })
    ));

    // Channel closed, should return None
    let event4 = adapter.recv().await;
    assert!(event4.is_none());
}

/// Test that the async adapter correctly sends outbound commands.
#[tokio::test]
async fn async_adapter_sends_all_command_types() {
    let (mut adapter, _inbound_tx, mut outbound_rx) = AsyncConsensusNetAdapter::new();

    let vote = make_dummy_vote(1, 0);
    let proposal = make_dummy_proposal(2, 1);

    // Send all types of commands
    adapter.send_vote_to(PeerId(1), &vote).await.unwrap();
    adapter.broadcast_vote(&vote).await.unwrap();
    adapter.broadcast_proposal(&proposal).await.unwrap();

    // Verify commands are received in order
    let cmd1 = outbound_rx.recv().await.unwrap();
    match cmd1 {
        OutboundCommand::SendVoteTo { to, vote: v, .. } => {
            assert_eq!(to, PeerId(1));
            assert_eq!(v.height, 1);
        }
        _ => panic!("expected SendVoteTo"),
    }

    let cmd2 = outbound_rx.recv().await.unwrap();
    match cmd2 {
        OutboundCommand::BroadcastVote { vote: v, .. } => {
            assert_eq!(v.height, 1);
        }
        _ => panic!("expected BroadcastVote"),
    }

    let cmd3 = outbound_rx.recv().await.unwrap();
    match cmd3 {
        OutboundCommand::BroadcastProposal { proposal: p, .. } => {
            assert_eq!(p.header.height, 2);
        }
        _ => panic!("expected BroadcastProposal"),
    }
}

/// Test that shutdown prevents further recv operations.
#[tokio::test]
async fn async_adapter_shutdown_stops_recv() {
    let (mut adapter, inbound_tx, _outbound_rx) = AsyncConsensusNetAdapter::new();

    // Queue up some events
    inbound_tx
        .send(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(1),
            vote: make_dummy_vote(1, 0),
        })
        .await
        .unwrap();

    // Verify not shutdown initially
    assert!(!adapter.is_shutdown());

    // Signal shutdown
    adapter.shutdown();
    assert!(adapter.is_shutdown());

    // recv should return None even though there are events queued
    let event = adapter.recv().await;
    assert!(event.is_none());
}

// ============================================================================
// Part B: AsyncNetSender tests
// ============================================================================

/// Test that AsyncNetSender implements ConsensusNetSender correctly.
#[tokio::test]
async fn async_net_sender_implements_trait() {
    let (sender, _outbound_rx, mut critical_rx) = AsyncNetSender::with_channel(10);

    let vote = make_dummy_vote(1, 0);
    let proposal = make_dummy_proposal(2, 1);

    // Use the trait methods (which default to Critical priority)
    ConsensusNetSender::send_vote_to(&sender, PeerId(1), &vote).unwrap();
    ConsensusNetSender::broadcast_vote(&sender, &vote).unwrap();
    ConsensusNetSender::broadcast_proposal(&sender, &proposal).unwrap();

    // Critical messages go to critical channel
    assert!(critical_rx.recv().await.is_some());
    assert!(critical_rx.recv().await.is_some());
    assert!(critical_rx.recv().await.is_some());
}

/// Test that AsyncNetSender can be used from multiple threads.
#[tokio::test]
async fn async_net_sender_is_send_sync() {
    let (sender, _outbound_rx, mut critical_rx) = AsyncNetSender::with_channel(100);

    let sender1 = sender.clone();
    let sender2 = sender.clone();
    let sender3 = sender.clone();

    // Spawn multiple tasks that send concurrently
    // Use broadcast_vote which defaults to Critical priority
    let handle1 = tokio::spawn(async move {
        for i in 0..10 {
            sender1.broadcast_vote(&make_dummy_vote(i, 0)).unwrap();
        }
    });

    let handle2 = tokio::spawn(async move {
        for i in 10..20 {
            sender2.broadcast_vote(&make_dummy_vote(i, 0)).unwrap();
        }
    });

    let handle3 = tokio::spawn(async move {
        for i in 20..30 {
            sender3.broadcast_vote(&make_dummy_vote(i, 0)).unwrap();
        }
    });

    // Wait for all tasks
    handle1.await.unwrap();
    handle2.await.unwrap();
    handle3.await.unwrap();

    // Drop the original sender
    drop(sender);

    // Count received commands from critical channel
    let mut count = 0;
    while critical_rx.recv().await.is_some() {
        count += 1;
    }
    assert_eq!(count, 30);
}

// ============================================================================
// Part C: Worker + AsyncConsensusNetAdapter integration tests
// ============================================================================

/// Test that ConsensusNetWorker correctly forwards events from AsyncConsensusNetAdapter.
#[tokio::test]
async fn worker_with_async_adapter_full_path() {
    let (adapter, inbound_tx, _outbound_rx) = AsyncConsensusNetAdapter::new();
    let (events_tx, mut events_rx) = mpsc::channel(10);

    // Create worker with the adapter
    let worker = ConsensusNetWorker::new(adapter, events_tx);

    // Send events
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

    // Close the inbound channel to trigger worker shutdown
    drop(inbound_tx);

    // Run the worker
    let result = worker.run().await;
    assert!(result.is_ok(), "worker should exit cleanly");

    // Verify events were forwarded
    let event1 = events_rx.recv().await.unwrap();
    match event1 {
        ConsensusEvent::IncomingMessage(boxed) => match *boxed {
            ConsensusNetworkEvent::IncomingVote { from, vote: v } => {
                assert_eq!(from, PeerId(100));
                assert_eq!(v.height, 1);
            }
            _ => panic!("expected IncomingVote"),
        },
        _ => panic!("expected IncomingMessage"),
    }

    let event2 = events_rx.recv().await.unwrap();
    match event2 {
        ConsensusEvent::IncomingMessage(boxed) => match *boxed {
            ConsensusNetworkEvent::IncomingProposal { from, proposal: p } => {
                assert_eq!(from, PeerId(200));
                assert_eq!(p.header.height, 2);
            }
            _ => panic!("expected IncomingProposal"),
        },
        _ => panic!("expected IncomingMessage"),
    }
}

/// Test that multiple workers can share the same event channel.
#[tokio::test]
async fn multiple_workers_share_event_channel() {
    let (adapter1, inbound_tx1, _outbound_rx1) = AsyncConsensusNetAdapter::new();
    let (adapter2, inbound_tx2, _outbound_rx2) = AsyncConsensusNetAdapter::new();

    let (events_tx, mut events_rx) = mpsc::channel(10);
    let events_tx2 = events_tx.clone();

    let worker1 = ConsensusNetWorker::new(adapter1, events_tx);
    let worker2 = ConsensusNetWorker::new(adapter2, events_tx2);

    // Send events to both adapters
    inbound_tx1
        .send(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(1),
            vote: make_dummy_vote(1, 0),
        })
        .await
        .unwrap();

    inbound_tx2
        .send(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(2),
            vote: make_dummy_vote(2, 0),
        })
        .await
        .unwrap();

    // Close both channels
    drop(inbound_tx1);
    drop(inbound_tx2);

    // Run both workers concurrently
    let (res1, res2) = tokio::join!(worker1.run(), worker2.run());
    assert!(res1.is_ok());
    assert!(res2.is_ok());

    // Should have received 2 events total
    let event1 = events_rx.recv().await.unwrap();
    let event2 = events_rx.recv().await.unwrap();

    assert!(matches!(event1, ConsensusEvent::IncomingMessage(_)));
    assert!(matches!(event2, ConsensusEvent::IncomingMessage(_)));
}

// ============================================================================
// Part D: Edge cases and error handling
// ============================================================================

/// Test adapter behavior when outbound channel is closed.
#[tokio::test]
async fn async_adapter_handles_closed_outbound_channel() {
    let (mut adapter, _inbound_tx, outbound_rx) = AsyncConsensusNetAdapter::new();

    // Drop the receiver to close the channel
    drop(outbound_rx);

    let vote = make_dummy_vote(1, 0);

    // Send should fail
    let result = adapter.send_vote_to(PeerId(1), &vote).await;
    assert!(result.is_err());
}

/// Test adapter behavior with empty inbound channel.
#[tokio::test]
async fn async_adapter_handles_empty_channel_then_data() {
    let (mut adapter, inbound_tx, _outbound_rx) = AsyncConsensusNetAdapter::new();

    // Spawn a task that waits then sends an event
    let tx = inbound_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(1),
            vote: make_dummy_vote(1, 0),
        })
        .await
        .unwrap();
    });

    // recv should wait for the event
    let event = tokio::time::timeout(Duration::from_secs(1), adapter.recv())
        .await
        .expect("should not timeout");

    assert!(matches!(
        event,
        Some(ConsensusNetworkEvent::IncomingVote { .. })
    ));
}

/// Test that OutboundCommand can be cloned and serialized correctly.
#[test]
fn outbound_command_is_clone() {
    use qbind_node::ConsensusMsgPriority;
    let cmd = OutboundCommand::BroadcastVote {
        vote: make_dummy_vote(1, 0),
        priority: ConsensusMsgPriority::Critical,
    };
    let _cmd2 = cmd.clone();
}

/// Test that OutboundCommand debug output is useful.
#[test]
fn outbound_command_debug_impl() {
    use qbind_node::ConsensusMsgPriority;
    let cmd = OutboundCommand::SendVoteTo {
        to: PeerId(42),
        vote: make_dummy_vote(1, 0),
        priority: ConsensusMsgPriority::Normal,
    };
    let debug_str = format!("{:?}", cmd);
    assert!(debug_str.contains("SendVoteTo"));
    assert!(debug_str.contains("PeerId(42)"));
}
