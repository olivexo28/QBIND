//! T183: DAG P2P client for batch fetch-on-miss.
//!
//! This module provides `DagP2pClient`, a helper for sending DAG batch fetch
//! requests and responses over the P2P network. It implements the fetch-on-miss
//! protocol where nodes can request missing batches from peers.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       DAG Fetch-on-Miss                         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  Node A (missing batch)        Node B (has batch)               │
//! │  ┌─────────────────┐           ┌─────────────────┐              │
//! │  │  DAG Mempool    │           │  DAG Mempool    │              │
//! │  │  - sees BatchAck│           │  - has batch    │              │
//! │  │  - batch absent │           │                 │              │
//! │  └────────┬────────┘           └────────▲────────┘              │
//! │           │                             │                       │
//! │           │ drain_missing_batches()     │ get_batch()           │
//! │           │                             │                       │
//! │  ┌────────▼────────┐           ┌────────┴────────┐              │
//! │  │  DagP2pClient   │           │  DagFetchHandler│              │
//! │  │  broadcast_     │──────────►│  handle_        │              │
//! │  │  batch_request()│BatchReq   │  batch_request()│              │
//! │  │                 │◄──────────│  respond_with_  │              │
//! │  │  (receives)     │BatchResp  │  batch()        │              │
//! │  └─────────────────┘           └─────────────────┘              │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use qbind_node::dag_net_p2p::DagP2pClient;
//! use qbind_node::p2p::{P2pService, NodeId};
//!
//! let p2p_service: Arc<dyn P2pService> = ...;
//! let local_node_id = NodeId::from_bytes([0u8; 32]);
//! let client = DagP2pClient::new(p2p_service, local_node_id);
//!
//! // Request a missing batch from peers
//! let batch_ref = BatchRef::new(ValidatorId::new(1), [0xAB; 32]);
//! client.broadcast_batch_request(&batch_ref);
//!
//! // Respond to a batch request
//! let peer = NodeId::from_bytes([0xCD; 32]);
//! let batch = mempool.get_batch(&batch_id).unwrap();
//! client.respond_with_batch(peer, &batch);
//! ```

use std::sync::Arc;

use crate::dag_mempool::{encode_batch, encode_batch_ref, BatchRef, QbindBatch};
use crate::p2p::{DagNetMsg, NodeId, P2pMessage, P2pService};

// ============================================================================
// DagP2pClient
// ============================================================================

/// DAG P2P client for batch fetch operations (T183).
///
/// This client wraps a `P2pService` and provides high-level methods for
/// sending batch requests and responses. It handles the encoding/framing
/// of messages into `DagNetMsg::BatchRequest` and `DagNetMsg::BatchResponse`.
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and can be shared across threads.
pub struct DagP2pClient {
    /// The underlying P2P service for sending messages.
    p2p_service: Arc<dyn P2pService>,
    /// The local node's ID (for debugging/logging).
    #[allow(dead_code)]
    local_node_id: NodeId,
}

impl DagP2pClient {
    /// Create a new DAG P2P client.
    ///
    /// # Arguments
    ///
    /// * `p2p_service` - The P2P service for sending messages
    /// * `local_node_id` - The local node's ID (for debugging)
    pub fn new(p2p_service: Arc<dyn P2pService>, local_node_id: NodeId) -> Self {
        Self {
            p2p_service,
            local_node_id,
        }
    }

    /// Broadcast a batch request to all connected peers (T183).
    ///
    /// This sends a `DagNetMsg::BatchRequest` to all peers, asking them to
    /// send the specified batch if they have it.
    ///
    /// # Arguments
    ///
    /// * `batch_ref` - Reference to the batch being requested
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let batch_ref = BatchRef::new(ValidatorId::new(1), [0xAB; 32]);
    /// client.broadcast_batch_request(&batch_ref);
    /// ```
    pub fn broadcast_batch_request(&self, batch_ref: &BatchRef) {
        let msg = P2pMessage::Dag(DagNetMsg::BatchRequest {
            data: encode_batch_ref(batch_ref),
        });
        self.p2p_service.broadcast(msg);
    }

    /// Send a batch response to a specific peer (T183).
    ///
    /// This sends a `DagNetMsg::BatchResponse` directly to the peer who
    /// requested the batch.
    ///
    /// # Arguments
    ///
    /// * `peer` - The peer to send the response to
    /// * `batch` - The batch to send
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let batch = mempool.get_batch(&batch_id).unwrap();
    /// client.respond_with_batch(requester_peer, &batch);
    /// ```
    pub fn respond_with_batch(&self, peer: NodeId, batch: &QbindBatch) {
        let msg = P2pMessage::Dag(DagNetMsg::BatchResponse {
            data: encode_batch(batch),
        });
        self.p2p_service.send_to(peer, msg);
    }

    /// Get a reference to the underlying P2P service.
    pub fn p2p_service(&self) -> &Arc<dyn P2pService> {
        &self.p2p_service
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_mempool::{BatchSignature, QbindBatch};
    use crate::p2p::NullP2pService;
    use qbind_consensus::ids::ValidatorId;

    #[test]
    fn test_dag_p2p_client_creation() {
        let p2p_service: Arc<dyn P2pService> = Arc::new(NullP2pService::zero());
        let local_node_id = NodeId::zero();
        let client = DagP2pClient::new(p2p_service.clone(), local_node_id);

        assert!(Arc::ptr_eq(client.p2p_service(), &p2p_service));
    }

    #[test]
    fn test_broadcast_batch_request_does_not_panic() {
        let p2p_service = Arc::new(NullP2pService::zero());
        let client = DagP2pClient::new(p2p_service, NodeId::zero());

        let batch_ref = BatchRef::new(ValidatorId::new(1), [0xAB; 32]);
        // Should not panic even with NullP2pService
        client.broadcast_batch_request(&batch_ref);
    }

    #[test]
    fn test_respond_with_batch_does_not_panic() {
        let p2p_service = Arc::new(NullP2pService::zero());
        let client = DagP2pClient::new(p2p_service, NodeId::zero());

        let batch = QbindBatch {
            batch_id: [0xCC; 32],
            creator: ValidatorId::new(1),
            view_hint: 100,
            parents: vec![],
            txs: vec![],
            signature: BatchSignature::empty(),
        };

        let peer = NodeId::zero();
        // Should not panic even with NullP2pService
        client.respond_with_batch(peer, &batch);
    }
}
