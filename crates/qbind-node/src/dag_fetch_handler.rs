//! T183: DAG fetch-on-miss inbound handler.
//!
//! This module provides `DagFetchHandler`, an implementation of `DagInboundHandler`
//! that handles `BatchRequest` and `BatchResponse` messages for the fetch-on-miss
//! protocol.
//!
//! # Architecture
//!
//! The `DagFetchHandler` sits between the P2P inbound demuxer and the DAG mempool:
//!
//! ```text
//! P2P Transport
//!      │
//!      ▼
//! P2pInboundDemuxer
//!      │
//!      ▼ DagNetMsg
//! DagFetchHandler
//!      │
//!      ├──► BatchRequest  → get_batch() → respond_with_batch()
//!      ├──► BatchResponse → handle_batch_response()
//!      └──► Other msgs    → (delegate to existing handler)
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use qbind_node::dag_fetch_handler::DagFetchHandler;
//!
//! let handler = DagFetchHandler::new(
//!     mempool.clone(),
//!     p2p_client.clone(),
//!     Some(metrics.clone()),
//! );
//!
//! // Use with P2pInboundDemuxer
//! let demuxer = P2pInboundDemuxer::new(
//!     receiver,
//!     consensus_handler,
//!     Arc::new(handler),
//!     None,
//! );
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::dag_mempool::{decode_batch, decode_batch_ref, InMemoryDagMempool};
use crate::dag_net_p2p::DagP2pClient;
use crate::p2p::{DagNetMsg, NodeId};
use crate::p2p_inbound::DagInboundHandler;

// ============================================================================
// DagFetchMetrics
// ============================================================================

/// Metrics for DAG fetch operations (T183).
///
/// Tracks request/response counts and failures for fetch-on-miss protocol.
#[derive(Debug, Default)]
pub struct DagFetchMetrics {
    /// Total number of batch requests sent.
    pub fetch_requests_sent: AtomicU64,
    /// Total number of batch requests received.
    pub fetch_requests_received: AtomicU64,
    /// Total number of batch responses sent.
    pub fetch_responses_sent: AtomicU64,
    /// Total number of batch responses received.
    pub fetch_responses_received: AtomicU64,
    /// Total number of fetch failures (decode errors, validation errors).
    pub fetch_failures: AtomicU64,
    /// Total number of requests where we didn't have the batch.
    pub fetch_request_misses: AtomicU64,
}

impl DagFetchMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment fetch requests sent counter.
    pub fn inc_fetch_requests_sent(&self) {
        self.fetch_requests_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment fetch requests received counter.
    pub fn inc_fetch_requests_received(&self) {
        self.fetch_requests_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment fetch responses sent counter.
    pub fn inc_fetch_responses_sent(&self) {
        self.fetch_responses_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment fetch responses received counter.
    pub fn inc_fetch_responses_received(&self) {
        self.fetch_responses_received
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment fetch failures counter.
    pub fn inc_fetch_failures(&self) {
        self.fetch_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment fetch request misses counter.
    pub fn inc_fetch_request_misses(&self) {
        self.fetch_request_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Get fetch requests sent count.
    pub fn fetch_requests_sent(&self) -> u64 {
        self.fetch_requests_sent.load(Ordering::Relaxed)
    }

    /// Get fetch requests received count.
    pub fn fetch_requests_received(&self) -> u64 {
        self.fetch_requests_received.load(Ordering::Relaxed)
    }

    /// Get fetch responses sent count.
    pub fn fetch_responses_sent(&self) -> u64 {
        self.fetch_responses_sent.load(Ordering::Relaxed)
    }

    /// Get fetch responses received count.
    pub fn fetch_responses_received(&self) -> u64 {
        self.fetch_responses_received.load(Ordering::Relaxed)
    }

    /// Get fetch failures count.
    pub fn fetch_failures(&self) -> u64 {
        self.fetch_failures.load(Ordering::Relaxed)
    }

    /// Get fetch request misses count.
    pub fn fetch_request_misses(&self) -> u64 {
        self.fetch_request_misses.load(Ordering::Relaxed)
    }
}

// ============================================================================
// DagFetchHandler
// ============================================================================

/// DAG inbound handler with fetch-on-miss support (T183).
///
/// This handler processes `BatchRequest` and `BatchResponse` messages,
/// implementing the fetch-on-miss protocol for DAG batch availability.
///
/// # Message Handling
///
/// - `BatchRequest`: Look up the requested batch and respond if we have it
/// - `BatchResponse`: Decode and insert the batch into the mempool
/// - Other messages: Delegate to the optional inner handler
///
/// # Thread Safety
///
/// This handler is `Send + Sync` and can be used with `P2pInboundDemuxer`.
pub struct DagFetchHandler {
    /// The DAG mempool for looking up and inserting batches.
    mempool: Arc<InMemoryDagMempool>,
    /// The P2P client for sending responses.
    p2p_client: Arc<DagP2pClient>,
    /// Optional metrics for observability.
    metrics: Option<Arc<DagFetchMetrics>>,
    /// Optional inner handler for non-fetch messages.
    inner_handler: Option<Arc<dyn DagInboundHandler>>,
}

impl DagFetchHandler {
    /// Create a new DAG fetch handler.
    ///
    /// # Arguments
    ///
    /// * `mempool` - The DAG mempool for batch operations
    /// * `p2p_client` - The P2P client for sending responses
    /// * `metrics` - Optional metrics instance
    pub fn new(
        mempool: Arc<InMemoryDagMempool>,
        p2p_client: Arc<DagP2pClient>,
        metrics: Option<Arc<DagFetchMetrics>>,
    ) -> Self {
        Self {
            mempool,
            p2p_client,
            metrics,
            inner_handler: None,
        }
    }

    /// Set an inner handler for non-fetch messages.
    ///
    /// Messages that are not `BatchRequest` or `BatchResponse` will be
    /// delegated to this inner handler.
    pub fn with_inner_handler(mut self, handler: Arc<dyn DagInboundHandler>) -> Self {
        self.inner_handler = Some(handler);
        self
    }

    /// Handle an inbound batch request.
    ///
    /// If we have the requested batch, send it back to the requester.
    fn handle_batch_request(&self, data: &[u8], sender: Option<NodeId>) {
        if let Some(ref m) = self.metrics {
            m.inc_fetch_requests_received();
        }

        match decode_batch_ref(data) {
            Ok(batch_ref) => {
                if let Some(batch) = self.mempool.get_batch(&batch_ref.batch_id) {
                    // We have the batch - respond if we know the sender
                    if let Some(peer) = sender {
                        self.p2p_client.respond_with_batch(peer, &batch);
                        if let Some(ref m) = self.metrics {
                            m.inc_fetch_responses_sent();
                        }
                    }
                } else {
                    // We don't have the batch
                    if let Some(ref m) = self.metrics {
                        m.inc_fetch_request_misses();
                    }
                }
            }
            Err(e) => {
                eprintln!("[T183] BatchRequest decode error: {}", e);
                if let Some(ref m) = self.metrics {
                    m.inc_fetch_failures();
                }
            }
        }
    }

    /// Handle an inbound batch response.
    ///
    /// Decode and insert the batch into the mempool.
    fn handle_batch_response(&self, data: &[u8]) {
        if let Some(ref m) = self.metrics {
            m.inc_fetch_responses_received();
        }

        match decode_batch(data) {
            Ok(batch) => {
                if let Err(e) = self.mempool.handle_batch_response(batch) {
                    eprintln!("[T183] Batch insert error: {}", e);
                    if let Some(ref m) = self.metrics {
                        m.inc_fetch_failures();
                    }
                }
            }
            Err(e) => {
                eprintln!("[T183] BatchResponse decode error: {}", e);
                if let Some(ref m) = self.metrics {
                    m.inc_fetch_failures();
                }
            }
        }
    }
}

impl DagInboundHandler for DagFetchHandler {
    fn handle_dag_msg(&self, msg: DagNetMsg) {
        match msg {
            DagNetMsg::BatchRequest { ref data } => {
                // No sender context in basic trait - use None
                self.handle_batch_request(data, None);
            }
            DagNetMsg::BatchResponse { ref data } => {
                self.handle_batch_response(data);
            }
            // Delegate other messages to inner handler
            other => {
                if let Some(ref inner) = self.inner_handler {
                    inner.handle_dag_msg(other);
                }
            }
        }
    }

    fn handle_dag_msg_from(&self, msg: DagNetMsg, sender: NodeId) {
        match msg {
            DagNetMsg::BatchRequest { ref data } => {
                // We have sender context - can respond directly
                self.handle_batch_request(data, Some(sender));
            }
            DagNetMsg::BatchResponse { ref data } => {
                self.handle_batch_response(data);
            }
            // Delegate other messages to inner handler
            other => {
                if let Some(ref inner) = self.inner_handler {
                    inner.handle_dag_msg_from(other, sender);
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_mempool::BatchRef;
    use crate::p2p::NullP2pService;
    use qbind_consensus::ids::ValidatorId;

    fn create_test_handler() -> DagFetchHandler {
        let mempool = Arc::new(InMemoryDagMempool::new(ValidatorId::new(1)));
        let p2p_service = Arc::new(NullP2pService::zero());
        let p2p_client = Arc::new(DagP2pClient::new(
            p2p_service as Arc<dyn crate::p2p::P2pService>,
            crate::p2p::NodeId::zero(),
        ));
        let metrics = Arc::new(DagFetchMetrics::new());

        DagFetchHandler::new(mempool, p2p_client, Some(metrics))
    }

    #[test]
    fn test_dag_fetch_handler_creation() {
        let handler = create_test_handler();
        assert!(handler.inner_handler.is_none());
    }

    #[test]
    fn test_dag_fetch_metrics() {
        let metrics = DagFetchMetrics::new();

        assert_eq!(metrics.fetch_requests_sent(), 0);
        assert_eq!(metrics.fetch_requests_received(), 0);
        assert_eq!(metrics.fetch_responses_sent(), 0);
        assert_eq!(metrics.fetch_responses_received(), 0);
        assert_eq!(metrics.fetch_failures(), 0);

        metrics.inc_fetch_requests_sent();
        metrics.inc_fetch_requests_received();
        metrics.inc_fetch_responses_sent();
        metrics.inc_fetch_responses_received();
        metrics.inc_fetch_failures();

        assert_eq!(metrics.fetch_requests_sent(), 1);
        assert_eq!(metrics.fetch_requests_received(), 1);
        assert_eq!(metrics.fetch_responses_sent(), 1);
        assert_eq!(metrics.fetch_responses_received(), 1);
        assert_eq!(metrics.fetch_failures(), 1);
    }

    #[test]
    fn test_handle_invalid_batch_request() {
        let handler = create_test_handler();

        // Invalid data should not panic
        let invalid_data = vec![0xFF, 0xFF, 0xFF];
        handler.handle_dag_msg(DagNetMsg::BatchRequest { data: invalid_data });

        // Metrics should show failure
        if let Some(ref m) = handler.metrics {
            assert_eq!(m.fetch_failures(), 1);
        }
    }

    #[test]
    fn test_handle_invalid_batch_response() {
        let handler = create_test_handler();

        // Invalid data should not panic
        let invalid_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        handler.handle_dag_msg(DagNetMsg::BatchResponse { data: invalid_data });

        // Metrics should show failure
        if let Some(ref m) = handler.metrics {
            assert_eq!(m.fetch_failures(), 1);
        }
    }

    #[test]
    fn test_handle_batch_request_miss() {
        let handler = create_test_handler();
        let metrics = handler.metrics.clone();

        // Request for a batch we don't have
        let batch_ref = BatchRef::new(ValidatorId::new(99), [0xAB; 32]);
        let encoded = crate::dag_mempool::encode_batch_ref(&batch_ref);

        handler.handle_dag_msg(DagNetMsg::BatchRequest { data: encoded });

        // Should record a miss
        if let Some(ref m) = metrics {
            assert_eq!(m.fetch_request_misses(), 1);
            assert_eq!(m.fetch_requests_received(), 1);
        }
    }
}
