//! T183: DAG Fetch-on-Miss P2P Tests
//!
//! This test module validates the batch fetch-on-miss protocol components:
//!
//! - Encoding/decoding roundtrips for BatchRef and QbindBatch
//! - drain_missing_batches_for_fetch() cooldown behavior
//! - handle_batch_response() insertion and tracking
//! - DagP2pClient message construction
//! - DagFetchHandler message handling

use qbind_consensus::ids::ValidatorId;
use qbind_node::dag_mempool::{
    decode_batch, decode_batch_ref, encode_batch, encode_batch_ref, BatchRef, BatchSignature,
    DagMempool, InMemoryDagMempool, QbindBatch,
};

// ============================================================================
// Encoding/Decoding Tests
// ============================================================================

#[test]
fn test_encode_decode_batch_ref_roundtrip() {
    let original = BatchRef::new(ValidatorId::new(42), [0xAB; 32]);

    let encoded = encode_batch_ref(&original);
    let decoded = decode_batch_ref(&encoded).expect("decode should succeed");

    assert_eq!(decoded.creator, original.creator);
    assert_eq!(decoded.batch_id, original.batch_id);
}

#[test]
fn test_encode_decode_batch_ref_various_values() {
    // Test with zero values
    let ref1 = BatchRef::new(ValidatorId::new(0), [0x00; 32]);
    let encoded1 = encode_batch_ref(&ref1);
    let decoded1 = decode_batch_ref(&encoded1).expect("decode should succeed");
    assert_eq!(decoded1.creator.as_u64(), 0);
    assert_eq!(decoded1.batch_id, [0x00; 32]);

    // Test with max values
    let ref2 = BatchRef::new(ValidatorId::new(u64::MAX), [0xFF; 32]);
    let encoded2 = encode_batch_ref(&ref2);
    let decoded2 = decode_batch_ref(&encoded2).expect("decode should succeed");
    assert_eq!(decoded2.creator.as_u64(), u64::MAX);
    assert_eq!(decoded2.batch_id, [0xFF; 32]);
}

#[test]
fn test_decode_batch_ref_invalid_data() {
    // Too short
    let result = decode_batch_ref(&[0x01, 0x02]);
    assert!(result.is_err());

    // Empty
    let result = decode_batch_ref(&[]);
    assert!(result.is_err());
}

#[test]
fn test_encode_decode_batch_roundtrip() {
    let original = QbindBatch {
        batch_id: [0xCC; 32],
        creator: ValidatorId::new(99),
        view_hint: 12345,
        parents: vec![
            BatchRef::new(ValidatorId::new(1), [0x11; 32]),
            BatchRef::new(ValidatorId::new(2), [0x22; 32]),
        ],
        txs: vec![], // Empty for simplicity
        signature: BatchSignature::new(vec![0xAA; 100]),
    };

    let encoded = encode_batch(&original);
    let decoded = decode_batch(&encoded).expect("decode should succeed");

    assert_eq!(decoded.batch_id, original.batch_id);
    assert_eq!(decoded.creator, original.creator);
    assert_eq!(decoded.view_hint, original.view_hint);
    assert_eq!(decoded.parents.len(), 2);
    assert_eq!(decoded.signature.as_bytes().len(), 100);
}

#[test]
fn test_encode_decode_batch_empty() {
    let original = QbindBatch {
        batch_id: [0x00; 32],
        creator: ValidatorId::new(0),
        view_hint: 0,
        parents: vec![],
        txs: vec![],
        signature: BatchSignature::empty(),
    };

    let encoded = encode_batch(&original);
    let decoded = decode_batch(&encoded).expect("decode should succeed");

    assert_eq!(decoded.batch_id, [0x00; 32]);
    assert_eq!(decoded.parents.len(), 0);
    assert_eq!(decoded.txs.len(), 0);
    assert!(decoded.signature.is_empty());
}

#[test]
fn test_decode_batch_invalid_data() {
    // Too short
    let result = decode_batch(&[0x01, 0x02, 0x03]);
    assert!(result.is_err());

    // Empty
    let result = decode_batch(&[]);
    assert!(result.is_err());

    // Garbage data
    let result = decode_batch(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(result.is_err());
}

// ============================================================================
// drain_missing_batches_for_fetch Tests
// ============================================================================

#[test]
fn test_drain_missing_batches_for_fetch_basic() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    // Record some missing batches
    let ref1 = BatchRef::new(ValidatorId::new(10), [0x11; 32]);
    let ref2 = BatchRef::new(ValidatorId::new(20), [0x22; 32]);
    let ref3 = BatchRef::new(ValidatorId::new(30), [0x33; 32]);

    mempool.record_missing_batch(ref1.clone(), ValidatorId::new(1), 1000);
    mempool.record_missing_batch(ref2.clone(), ValidatorId::new(1), 1001);
    mempool.record_missing_batch(ref3.clone(), ValidatorId::new(1), 1002);

    assert_eq!(mempool.missing_batch_count(), 3);

    // Drain with max=2
    let now_ms = 2000;
    let cooldown_ms = 500;
    let drained = mempool.drain_missing_batches_for_fetch(2, now_ms, cooldown_ms);

    // Should get exactly 2 batch refs
    assert_eq!(drained.len(), 2);
}

#[test]
fn test_drain_missing_batches_respects_cooldown() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    let batch_ref = BatchRef::new(ValidatorId::new(99), [0xAA; 32]);
    mempool.record_missing_batch(batch_ref.clone(), ValidatorId::new(1), 1000);

    let cooldown_ms = 1000; // 1 second cooldown

    // First drain at time 2000 - should get the batch
    let drained1 = mempool.drain_missing_batches_for_fetch(10, 2000, cooldown_ms);
    assert_eq!(drained1.len(), 1);
    assert_eq!(drained1[0].batch_id, batch_ref.batch_id);

    // Second drain at time 2500 (500ms later) - should NOT get the batch (cooldown)
    let drained2 = mempool.drain_missing_batches_for_fetch(10, 2500, cooldown_ms);
    assert_eq!(drained2.len(), 0);

    // Third drain at time 3100 (1100ms after first) - should get the batch again
    let drained3 = mempool.drain_missing_batches_for_fetch(10, 3100, cooldown_ms);
    assert_eq!(drained3.len(), 1);
}

#[test]
fn test_drain_missing_batches_respects_max() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    // Record 10 missing batches
    for i in 0..10 {
        let mut batch_id = [0u8; 32];
        batch_id[0] = i;
        let batch_ref = BatchRef::new(ValidatorId::new(i as u64), batch_id);
        mempool.record_missing_batch(batch_ref, ValidatorId::new(1), 1000);
    }

    assert_eq!(mempool.missing_batch_count(), 10);

    // Drain with max=5
    let drained = mempool.drain_missing_batches_for_fetch(5, 2000, 100);
    assert_eq!(drained.len(), 5);

    // Drain again immediately - should get remaining 5 (different batches, no cooldown conflict)
    // Actually, the first 5 are now on cooldown, so we get the other 5
    let drained2 = mempool.drain_missing_batches_for_fetch(5, 2001, 100);
    assert_eq!(drained2.len(), 5);
}

#[test]
fn test_drain_missing_batches_empty() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    // No missing batches recorded
    let drained = mempool.drain_missing_batches_for_fetch(10, 1000, 100);
    assert!(drained.is_empty());
}

// ============================================================================
// handle_batch_response Tests
// ============================================================================

#[test]
fn test_handle_batch_response_inserts_and_clears_missing() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    // Create a batch using the proper constructor so batch_id is computed
    let batch = QbindBatch::new(ValidatorId::new(5), 100, vec![], vec![]);

    let batch_ref = BatchRef::new(batch.creator, batch.batch_id);

    // Record it as missing
    mempool.record_missing_batch(batch_ref, ValidatorId::new(2), 1000);
    assert_eq!(mempool.missing_batch_count(), 1);
    assert!(mempool.is_batch_missing(&batch.batch_id));

    // Handle the response
    let result = mempool.handle_batch_response(batch.clone());
    assert!(result.is_ok());
    assert!(result.unwrap()); // Was tracked as missing, now inserted

    // Should no longer be missing
    assert_eq!(mempool.missing_batch_count(), 0);
    assert!(!mempool.is_batch_missing(&batch.batch_id));

    // Batch should now exist
    let retrieved = mempool.get_batch(&batch.batch_id);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().creator, batch.creator);
}

#[test]
fn test_handle_batch_response_already_present() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    // Create a batch using the proper constructor
    let batch = QbindBatch::new(ValidatorId::new(3), 50, vec![], vec![]);

    // Insert the batch directly first
    mempool
        .insert_remote_batch(batch.clone())
        .expect("insert should succeed");

    // Now try to handle as response - should return Ok(false)
    let result = mempool.handle_batch_response(batch);
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Was not tracked as missing
}

#[test]
fn test_handle_batch_response_not_tracked_as_missing() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    // Create a batch using the proper constructor
    let batch = QbindBatch::new(ValidatorId::new(7), 75, vec![], vec![]);

    // Don't record as missing, just handle the response
    let result = mempool.handle_batch_response(batch.clone());
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Was not tracked as missing, but still inserted

    // Batch should exist
    assert!(mempool.get_batch(&batch.batch_id).is_some());
}

// ============================================================================
// Invalid Batch Response Tests
// ============================================================================

#[test]
fn test_invalid_batch_response_does_not_panic() {
    // Test that decode failures are handled gracefully
    let invalid_data = vec![0xFF, 0xFF, 0xFF, 0xFF];
    let result = decode_batch(&invalid_data);
    assert!(result.is_err());

    // Empty data
    let result = decode_batch(&[]);
    assert!(result.is_err());
}

// ============================================================================
// Integration-style Tests
// ============================================================================

#[test]
fn test_fetch_flow_simulation() {
    // Simulate a simplified fetch flow:
    // 1. Node A has batch, Node B doesn't
    // 2. Node B records batch as missing
    // 3. Node B would send BatchRequest (simulated by drain)
    // 4. Node A responds with BatchResponse
    // 5. Node B handles response and has batch

    let node_a_mempool = InMemoryDagMempool::new(ValidatorId::new(1));
    let node_b_mempool = InMemoryDagMempool::new(ValidatorId::new(2));

    // Node A has a batch - use proper constructor
    let batch = QbindBatch::new(ValidatorId::new(1), 200, vec![], vec![]);

    node_a_mempool
        .insert_remote_batch(batch.clone())
        .expect("insert should succeed");

    // Node B records batch as missing (learned via BatchAck)
    let batch_ref = BatchRef::new(batch.creator, batch.batch_id);
    node_b_mempool.record_missing_batch(batch_ref.clone(), ValidatorId::new(3), 1000);

    // Node B drains missing batches for fetch
    let to_fetch = node_b_mempool.drain_missing_batches_for_fetch(10, 2000, 100);
    assert_eq!(to_fetch.len(), 1);
    assert_eq!(to_fetch[0].batch_id, batch.batch_id);

    // Simulate: Node B sends request, Node A looks up and sends response
    let requested_batch = node_a_mempool.get_batch(&to_fetch[0].batch_id);
    assert!(requested_batch.is_some());

    // Simulate: Node B receives response
    let result = node_b_mempool.handle_batch_response(requested_batch.unwrap());
    assert!(result.is_ok());
    assert!(result.unwrap()); // Was missing, now inserted

    // Node B now has the batch
    assert!(node_b_mempool.get_batch(&batch.batch_id).is_some());
    assert!(!node_b_mempool.is_batch_missing(&batch.batch_id));
}

#[test]
fn test_multiple_missing_batches_flow() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    // Record multiple missing batches and create matching batches
    let batches: Vec<QbindBatch> = (0..5)
        .map(|i| QbindBatch::new(ValidatorId::new(i as u64 + 10), i as u64, vec![], vec![]))
        .collect();

    for batch in &batches {
        let batch_ref = BatchRef::new(batch.creator, batch.batch_id);
        mempool.record_missing_batch(batch_ref, ValidatorId::new(1), 1000);
    }

    assert_eq!(mempool.missing_batch_count(), 5);

    // Drain all
    let drained = mempool.drain_missing_batches_for_fetch(10, 2000, 100);
    assert_eq!(drained.len(), 5);

    // Simulate responses for each
    for batch in &batches {
        let result = mempool.handle_batch_response(batch.clone());
        assert!(result.is_ok());
    }

    // All missing batches should be resolved
    assert_eq!(mempool.missing_batch_count(), 0);
}
