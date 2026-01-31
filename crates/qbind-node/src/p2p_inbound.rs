//! T174: P2P Inbound Processing – Receive path and message demultiplexing.
//!
//! This module provides the inbound message handling for P2P networking,
//! demultiplexing incoming `P2pMessage` instances into consensus and DAG handlers.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    P2P Inbound Processing                       │
//! │                                                                 │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │              TcpKemTlsP2pService                          │   │
//! │  │                     │                                     │   │
//! │  │                     ▼                                     │   │
//! │  │     subscribe() → Receiver<P2pMessage>                    │   │
//! │  └─────────────────────┬───────────────────────────────────┘   │
//! │                        │                                        │
//! │                        ▼                                        │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │               P2pInboundDemuxer                           │   │
//! │  │                                                           │   │
//! │  │     while let Some(msg) = rx.recv().await {               │   │
//! │  │         match msg {                                       │   │
//! │  │             Consensus(net_msg) => consensus.handle(...)   │   │
//! │  │             Dag(dag_msg)       => dag.handle(...)         │   │
//! │  │             Control(ctrl)      => control.handle(...)     │   │
//! │  │         }                                                 │   │
//! │  │     }                                                     │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! │                        │                                        │
//! │                        ▼                                        │
//! │  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────┐   │
//! │  │ConsensusHandler  │  │   DagHandler     │  │ControlHandler│   │
//! │  └──────────────────┘  └──────────────────┘  └─────────────┘   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use qbind_node::p2p_inbound::{P2pInboundDemuxer, ConsensusInboundHandler, DagInboundHandler};
//!
//! let p2p_service: TcpKemTlsP2pService = /* ... */;
//! let consensus_handler: Arc<dyn ConsensusInboundHandler> = /* ... */;
//! let dag_handler: Arc<dyn DagInboundHandler> = /* ... */;
//!
//! let receiver = p2p_service.subscribe().await;
//! let demuxer = P2pInboundDemuxer::new(receiver, consensus_handler, dag_handler, None);
//!
//! // Spawn the demux loop as a Tokio task
//! tokio::spawn(async move {
//!     demuxer.run().await;
//! });
//! ```

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::metrics::P2pMetrics;
use crate::p2p::{ConsensusNetMsg, ControlMsg, DagNetMsg, P2pMessage};

// ============================================================================
// Handler Traits
// ============================================================================

/// Handler trait for inbound consensus messages over P2P (T174).
///
/// Implementations receive deserialized consensus messages and route them
/// to the appropriate consensus processing logic.
pub trait ConsensusInboundHandler: Send + Sync {
    /// Handle an inbound consensus message.
    ///
    /// # Arguments
    ///
    /// * `msg` - The consensus network message (Proposal, Vote, Timeout, NewView)
    ///
    /// # Note
    ///
    /// This method should be non-blocking. Heavy processing should be
    /// dispatched to a background task or channel.
    fn handle_consensus_msg(&self, msg: ConsensusNetMsg);
}

/// Handler trait for inbound DAG mempool messages over P2P (T174).
///
/// Implementations receive deserialized DAG messages and route them
/// to the DAG mempool for processing.
pub trait DagInboundHandler: Send + Sync {
    /// Handle an inbound DAG message.
    ///
    /// # Arguments
    ///
    /// * `msg` - The DAG network message (Batch, BatchAck, BatchCertificate)
    ///
    /// # Note
    ///
    /// This method should be non-blocking. Heavy processing should be
    /// dispatched to a background task or channel.
    fn handle_dag_msg(&self, msg: DagNetMsg);
}

/// Handler trait for inbound control messages over P2P (T174).
///
/// Implementations receive control messages for network-level operations.
pub trait ControlInboundHandler: Send + Sync {
    /// Handle an inbound control message.
    ///
    /// # Arguments
    ///
    /// * `msg` - The control message (Heartbeat, PeerExchange, etc.)
    fn handle_control_msg(&self, msg: ControlMsg);
}

// ============================================================================
// Null Handlers (for testing / disabled functionality)
// ============================================================================

/// A no-op consensus handler that discards all messages (T174).
///
/// Useful for testing the demuxer without actual consensus processing,
/// or when consensus messages over P2P are not yet wired.
#[derive(Debug, Default)]
pub struct NullConsensusHandler;

impl ConsensusInboundHandler for NullConsensusHandler {
    fn handle_consensus_msg(&self, msg: ConsensusNetMsg) {
        // Debug logging for null handler - discards message
        let _ = msg_type(&msg);
    }
}

/// A no-op DAG handler that discards all messages (T174).
///
/// Useful for testing or when DAG networking is disabled.
#[derive(Debug, Default)]
pub struct NullDagHandler;

impl DagInboundHandler for NullDagHandler {
    fn handle_dag_msg(&self, msg: DagNetMsg) {
        // Debug logging for null handler - discards message
        let _ = dag_msg_type(&msg);
    }
}

/// A no-op control handler that discards all messages (T174).
#[derive(Debug, Default)]
pub struct NullControlHandler;

impl ControlInboundHandler for NullControlHandler {
    fn handle_control_msg(&self, msg: ControlMsg) {
        // Debug logging for null handler - discards message
        let _ = control_msg_type(&msg);
    }
}

// ============================================================================
// P2pInboundDemuxer
// ============================================================================

/// P2P inbound message demultiplexer (T174).
///
/// This component receives `P2pMessage` instances from the P2P transport layer
/// and routes them to the appropriate handlers:
///
/// - `P2pMessage::Consensus` → `ConsensusInboundHandler`
/// - `P2pMessage::Dag` → `DagInboundHandler`
/// - `P2pMessage::Control` → `ControlInboundHandler`
///
/// # Design Principles
///
/// - **Non-blocking**: Handlers should not block the demux loop.
/// - **Backpressure**: Uses bounded channel from P2P transport.
/// - **Testable**: Handlers can be mocked for unit testing.
/// - **Observable**: Increments P2P metrics for each message type.
pub struct P2pInboundDemuxer {
    /// Receiver for inbound P2P messages.
    receiver: mpsc::Receiver<P2pMessage>,
    /// Handler for consensus messages.
    consensus_handler: Arc<dyn ConsensusInboundHandler>,
    /// Handler for DAG messages.
    dag_handler: Arc<dyn DagInboundHandler>,
    /// Handler for control messages (optional).
    control_handler: Arc<dyn ControlInboundHandler>,
    /// P2P metrics (optional).
    metrics: Option<Arc<P2pMetrics>>,
}

impl P2pInboundDemuxer {
    /// Create a new P2P inbound demuxer.
    ///
    /// # Arguments
    ///
    /// * `receiver` - Channel receiver for inbound P2P messages
    /// * `consensus_handler` - Handler for consensus messages
    /// * `dag_handler` - Handler for DAG messages
    /// * `control_handler` - Handler for control messages (optional, uses NullControlHandler if None)
    pub fn new(
        receiver: mpsc::Receiver<P2pMessage>,
        consensus_handler: Arc<dyn ConsensusInboundHandler>,
        dag_handler: Arc<dyn DagInboundHandler>,
        control_handler: Option<Arc<dyn ControlInboundHandler>>,
    ) -> Self {
        Self {
            receiver,
            consensus_handler,
            dag_handler,
            control_handler: control_handler
                .unwrap_or_else(|| Arc::new(NullControlHandler)),
            metrics: None,
        }
    }

    /// Create a demuxer with all null handlers (for testing).
    pub fn with_null_handlers(receiver: mpsc::Receiver<P2pMessage>) -> Self {
        Self {
            receiver,
            consensus_handler: Arc::new(NullConsensusHandler),
            dag_handler: Arc::new(NullDagHandler),
            control_handler: Arc::new(NullControlHandler),
            metrics: None,
        }
    }

    /// Set the P2P metrics instance.
    pub fn with_metrics(mut self, metrics: Arc<P2pMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Run the demux loop.
    ///
    /// This method consumes the demuxer and runs the message processing loop
    /// until the receiver channel is closed (indicating P2P service shutdown).
    ///
    /// # Usage
    ///
    /// Typically spawned as a Tokio task:
    ///
    /// ```rust,ignore
    /// tokio::spawn(async move {
    ///     demuxer.run().await;
    /// });
    /// ```
    pub async fn run(mut self) {
        // Note: Using minimal logging to avoid noise during normal operation
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg);
        }
    }

    /// Handle a single P2P message.
    ///
    /// This method is also useful for testing: you can directly inject
    /// messages without going through the channel.
    pub fn handle_message(&self, msg: P2pMessage) {
        match msg {
            P2pMessage::Consensus(net_msg) => {
                // Record the message type for debug purposes
                let _ = msg_type(&net_msg);

                if let Some(ref m) = self.metrics {
                    m.inc_message_received("consensus");
                }

                self.consensus_handler.handle_consensus_msg(net_msg);
            }
            P2pMessage::Dag(dag_msg) => {
                // Record the message type for debug purposes
                let _ = dag_msg_type(&dag_msg);

                if let Some(ref m) = self.metrics {
                    m.inc_message_received("dag");
                }

                self.dag_handler.handle_dag_msg(dag_msg);
            }
            P2pMessage::Control(ctrl_msg) => {
                // Record the message type for debug purposes
                let _ = control_msg_type(&ctrl_msg);

                if let Some(ref m) = self.metrics {
                    m.inc_message_received("control");
                }

                self.control_handler.handle_control_msg(ctrl_msg);
            }
        }
    }
}

// ============================================================================
// Helper Functions for Logging
// ============================================================================

/// Get a human-readable type name for a consensus message.
fn msg_type(msg: &ConsensusNetMsg) -> &'static str {
    match msg {
        ConsensusNetMsg::Proposal(_) => "Proposal",
        ConsensusNetMsg::Vote(_) => "Vote",
        ConsensusNetMsg::Timeout(_) => "Timeout",
        ConsensusNetMsg::NewView(_) => "NewView",
    }
}

/// Get a human-readable type name for a DAG message.
fn dag_msg_type(msg: &DagNetMsg) -> &'static str {
    match msg {
        DagNetMsg::Batch { .. } => "Batch",
        DagNetMsg::BatchAck { .. } => "BatchAck",
        DagNetMsg::BatchCertificate { .. } => "BatchCertificate",
    }
}

/// Get a human-readable type name for a control message.
fn control_msg_type(msg: &ControlMsg) -> &'static str {
    match msg {
        ControlMsg::Heartbeat { .. } => "Heartbeat",
        ControlMsg::PeerExchangeRequest { .. } => "PeerExchangeRequest",
        ControlMsg::PeerExchangeResponse { .. } => "PeerExchangeResponse",
    }
}

// ============================================================================
// Channel-Based Handlers (for integration with existing code paths)
// ============================================================================

/// A consensus handler that forwards messages to an async channel (T174).
///
/// This handler provides integration with existing async consensus processing
/// by forwarding messages to a channel that can be consumed by the consensus
/// event loop.
#[derive(Clone)]
pub struct ChannelConsensusHandler {
    sender: mpsc::Sender<ConsensusNetMsg>,
}

impl ChannelConsensusHandler {
    /// Create a new channel-based consensus handler.
    ///
    /// Returns the handler and a receiver for the forwarded messages.
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<ConsensusNetMsg>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (Self { sender }, receiver)
    }

    /// Create from an existing sender.
    pub fn from_sender(sender: mpsc::Sender<ConsensusNetMsg>) -> Self {
        Self { sender }
    }
}

impl ConsensusInboundHandler for ChannelConsensusHandler {
    fn handle_consensus_msg(&self, msg: ConsensusNetMsg) {
        if let Err(e) = self.sender.try_send(msg) {
            eprintln!(
                "[P2P Inbound] Failed to forward consensus message (channel full or closed): {}",
                e
            );
        }
    }
}

/// A DAG handler that forwards messages to an async channel (T174).
///
/// This handler provides integration with existing DAG mempool processing
/// by forwarding messages to a channel.
#[derive(Clone)]
pub struct ChannelDagHandler {
    sender: mpsc::Sender<DagNetMsg>,
}

impl ChannelDagHandler {
    /// Create a new channel-based DAG handler.
    ///
    /// Returns the handler and a receiver for the forwarded messages.
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<DagNetMsg>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (Self { sender }, receiver)
    }

    /// Create from an existing sender.
    pub fn from_sender(sender: mpsc::Sender<DagNetMsg>) -> Self {
        Self { sender }
    }
}

impl DagInboundHandler for ChannelDagHandler {
    fn handle_dag_msg(&self, msg: DagNetMsg) {
        if let Err(e) = self.sender.try_send(msg) {
            eprintln!(
                "[P2P Inbound] Failed to forward DAG message (channel full or closed): {}",
                e
            );
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A test consensus handler that counts messages.
    struct CountingConsensusHandler {
        count: AtomicU64,
    }

    impl CountingConsensusHandler {
        fn new() -> Self {
            Self {
                count: AtomicU64::new(0),
            }
        }

        fn count(&self) -> u64 {
            self.count.load(Ordering::Relaxed)
        }
    }

    impl ConsensusInboundHandler for CountingConsensusHandler {
        fn handle_consensus_msg(&self, _msg: ConsensusNetMsg) {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A test DAG handler that counts messages.
    struct CountingDagHandler {
        count: AtomicU64,
    }

    impl CountingDagHandler {
        fn new() -> Self {
            Self {
                count: AtomicU64::new(0),
            }
        }

        fn count(&self) -> u64 {
            self.count.load(Ordering::Relaxed)
        }
    }

    impl DagInboundHandler for CountingDagHandler {
        fn handle_dag_msg(&self, _msg: DagNetMsg) {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_demuxer_routes_consensus_messages() {
        let (tx, rx) = mpsc::channel(16);
        let consensus_handler = Arc::new(CountingConsensusHandler::new());
        let dag_handler = Arc::new(CountingDagHandler::new());

        let demuxer =
            P2pInboundDemuxer::new(rx, consensus_handler.clone(), dag_handler.clone(), None);

        // Directly handle messages (without running the loop)
        let msg = P2pMessage::Consensus(ConsensusNetMsg::Vote(vec![1, 2, 3]));
        demuxer.handle_message(msg);

        assert_eq!(consensus_handler.count(), 1);
        assert_eq!(dag_handler.count(), 0);

        // Handle another consensus message
        let msg2 = P2pMessage::Consensus(ConsensusNetMsg::Proposal(vec![4, 5, 6]));
        demuxer.handle_message(msg2);

        assert_eq!(consensus_handler.count(), 2);
        assert_eq!(dag_handler.count(), 0);

        drop(tx); // Close the channel
    }

    #[test]
    fn test_demuxer_routes_dag_messages() {
        let (tx, rx) = mpsc::channel(16);
        let consensus_handler = Arc::new(CountingConsensusHandler::new());
        let dag_handler = Arc::new(CountingDagHandler::new());

        let demuxer =
            P2pInboundDemuxer::new(rx, consensus_handler.clone(), dag_handler.clone(), None);

        // Handle DAG messages
        let batch_msg = P2pMessage::Dag(DagNetMsg::Batch {
            data: vec![1, 2, 3],
        });
        demuxer.handle_message(batch_msg);

        let ack_msg = P2pMessage::Dag(DagNetMsg::BatchAck {
            data: vec![4, 5, 6],
        });
        demuxer.handle_message(ack_msg);

        let cert_msg = P2pMessage::Dag(DagNetMsg::BatchCertificate {
            data: vec![7, 8, 9],
        });
        demuxer.handle_message(cert_msg);

        assert_eq!(consensus_handler.count(), 0);
        assert_eq!(dag_handler.count(), 3);

        drop(tx);
    }

    #[test]
    fn test_demuxer_routes_mixed_messages() {
        let (tx, rx) = mpsc::channel(16);
        let consensus_handler = Arc::new(CountingConsensusHandler::new());
        let dag_handler = Arc::new(CountingDagHandler::new());

        let demuxer =
            P2pInboundDemuxer::new(rx, consensus_handler.clone(), dag_handler.clone(), None);

        // Mix of messages
        demuxer.handle_message(P2pMessage::Consensus(ConsensusNetMsg::Vote(vec![])));
        demuxer.handle_message(P2pMessage::Dag(DagNetMsg::Batch { data: vec![] }));
        demuxer.handle_message(P2pMessage::Consensus(ConsensusNetMsg::Proposal(vec![])));
        demuxer.handle_message(P2pMessage::Control(ControlMsg::Heartbeat {
            view: 1,
            timestamp_ms: 1000,
        }));
        demuxer.handle_message(P2pMessage::Dag(DagNetMsg::BatchAck { data: vec![] }));

        assert_eq!(consensus_handler.count(), 2);
        assert_eq!(dag_handler.count(), 2);

        drop(tx);
    }

    #[test]
    fn test_null_handlers_dont_panic() {
        let (tx, rx) = mpsc::channel(16);
        let demuxer = P2pInboundDemuxer::with_null_handlers(rx);

        // These should not panic
        demuxer.handle_message(P2pMessage::Consensus(ConsensusNetMsg::Vote(vec![])));
        demuxer.handle_message(P2pMessage::Dag(DagNetMsg::Batch { data: vec![] }));
        demuxer.handle_message(P2pMessage::Control(ControlMsg::Heartbeat {
            view: 0,
            timestamp_ms: 0,
        }));

        drop(tx);
    }

    #[tokio::test]
    async fn test_channel_consensus_handler() {
        let (handler, mut rx) = ChannelConsensusHandler::new(16);

        handler.handle_consensus_msg(ConsensusNetMsg::Vote(vec![1, 2, 3]));
        handler.handle_consensus_msg(ConsensusNetMsg::Proposal(vec![4, 5, 6]));

        let msg1 = rx.recv().await.expect("should receive first message");
        let msg2 = rx.recv().await.expect("should receive second message");

        assert!(matches!(msg1, ConsensusNetMsg::Vote(_)));
        assert!(matches!(msg2, ConsensusNetMsg::Proposal(_)));
    }

    #[tokio::test]
    async fn test_channel_dag_handler() {
        let (handler, mut rx) = ChannelDagHandler::new(16);

        handler.handle_dag_msg(DagNetMsg::Batch {
            data: vec![1, 2, 3],
        });
        handler.handle_dag_msg(DagNetMsg::BatchAck {
            data: vec![4, 5, 6],
        });

        let msg1 = rx.recv().await.expect("should receive first message");
        let msg2 = rx.recv().await.expect("should receive second message");

        assert!(matches!(msg1, DagNetMsg::Batch { .. }));
        assert!(matches!(msg2, DagNetMsg::BatchAck { .. }));
    }

    #[tokio::test]
    async fn test_demuxer_run_loop() {
        let (tx, rx) = mpsc::channel(16);
        let consensus_handler = Arc::new(CountingConsensusHandler::new());
        let dag_handler = Arc::new(CountingDagHandler::new());

        let demuxer =
            P2pInboundDemuxer::new(rx, consensus_handler.clone(), dag_handler.clone(), None);

        // Spawn the demux loop
        let handle = tokio::spawn(async move {
            demuxer.run().await;
        });

        // Send some messages
        tx.send(P2pMessage::Consensus(ConsensusNetMsg::Vote(vec![])))
            .await
            .unwrap();
        tx.send(P2pMessage::Dag(DagNetMsg::Batch { data: vec![] }))
            .await
            .unwrap();

        // Give time for processing
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Close the channel
        drop(tx);

        // Wait for the demux loop to terminate
        handle.await.unwrap();

        // Verify counts
        assert_eq!(consensus_handler.count(), 1);
        assert_eq!(dag_handler.count(), 1);
    }
}