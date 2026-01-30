//! T165 Unit Tests: DAG Availability Certificates v1
//!
//! These tests verify the DAG availability certificate functionality:
//! - BatchAck creation and signing preimage
//! - BatchCertificate formation when quorum is reached
//! - BatchAckTracker accumulation and certificate formation
//! - Duplicate ack rejection
//! - Unknown batch rejection
//! - Cross-chain rejection (chain-id domain separation)

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_ledger::QbindTransaction;
use qbind_node::{
    BatchAck, BatchAckResult, BatchAckTracker, BatchCertificate, BatchId, BatchRef,
    DagAvailabilityConfig, DagMempool, DagMempoolConfig, DagMempoolMetrics, InMemoryDagMempool,
    QbindBatch,
};
use qbind_types::{QBIND_DEVNET_CHAIN_ID, QBIND_TESTNET_CHAIN_ID};

// ============================================================================
// Test Helpers
// ============================================================================

fn test_account_id(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

fn make_test_tx(sender_byte: u8, nonce: u64, payload_byte: u8) -> QbindTransaction {
    QbindTransaction::new(test_account_id(sender_byte), nonce, vec![payload_byte; 32])
}

fn make_test_batch(creator: ValidatorId, view_hint: u64) -> QbindBatch {
    QbindBatch::new(
        creator,
        view_hint,
        vec![],
        vec![make_test_tx(creator.as_u64() as u8, 0, 0x11)],
    )
}

#[allow(dead_code)]
fn make_test_batch_ref(creator: ValidatorId, batch: &QbindBatch) -> BatchRef {
    BatchRef::new(creator, batch.batch_id)
}

fn make_test_ack(batch_ref: BatchRef, validator_id: ValidatorId, view_hint: u64) -> BatchAck {
    BatchAck::new_unsigned(batch_ref, validator_id, view_hint, 100)
}

// ============================================================================
// Part 1: BatchAck Tests
// ============================================================================

/// Test that BatchAck signing preimage includes domain tag.
#[test]
fn test_batch_ack_signing_preimage_starts_with_domain_tag() {
    let batch_ref = BatchRef::new(ValidatorId::new(1), [0xAA; 32]);
    let validator_id = ValidatorId::new(2);
    let view_hint = 10;

    // DevNet preimage
    let preimage_dev = BatchAck::signing_preimage_with_chain_id(
        QBIND_DEVNET_CHAIN_ID,
        &batch_ref,
        validator_id,
        view_hint,
    );
    assert!(
        preimage_dev.starts_with(b"QBIND:DEV:BATCH_ACK:v1"),
        "DevNet preimage should start with QBIND:DEV:BATCH_ACK:v1"
    );

    // TestNet preimage
    let preimage_test = BatchAck::signing_preimage_with_chain_id(
        QBIND_TESTNET_CHAIN_ID,
        &batch_ref,
        validator_id,
        view_hint,
    );
    assert!(
        preimage_test.starts_with(b"QBIND:TST:BATCH_ACK:v1"),
        "TestNet preimage should start with QBIND:TST:BATCH_ACK:v1"
    );
}

/// Test that different chain IDs produce different preimages.
#[test]
fn test_batch_ack_cross_chain_preimages_differ() {
    let batch_ref = BatchRef::new(ValidatorId::new(1), [0xBB; 32]);
    let validator_id = ValidatorId::new(2);
    let view_hint = 5;

    let preimage_dev = BatchAck::signing_preimage_with_chain_id(
        QBIND_DEVNET_CHAIN_ID,
        &batch_ref,
        validator_id,
        view_hint,
    );
    let preimage_test = BatchAck::signing_preimage_with_chain_id(
        QBIND_TESTNET_CHAIN_ID,
        &batch_ref,
        validator_id,
        view_hint,
    );

    assert_ne!(
        preimage_dev, preimage_test,
        "Different chain IDs must produce different preimages"
    );
}

/// Test BatchAck::new_signed creates a valid signed ack.
#[test]
fn test_batch_ack_new_signed() {
    let batch_ref = BatchRef::new(ValidatorId::new(1), [0xCC; 32]);
    let validator_id = ValidatorId::new(3);
    let view_hint = 15;
    let suite_id = 100u16;

    // Simple signing function for testing
    let sign_fn = |preimage: &[u8]| -> Result<Vec<u8>, String> {
        // Just use preimage hash as "signature" for testing
        Ok(qbind_hash::sha3_256(preimage).to_vec())
    };

    let ack = BatchAck::new_signed(
        batch_ref.clone(),
        validator_id,
        view_hint,
        QBIND_DEVNET_CHAIN_ID,
        suite_id,
        sign_fn,
    )
    .expect("signing should succeed");

    assert_eq!(ack.batch_ref, batch_ref);
    assert_eq!(ack.validator_id, validator_id);
    assert_eq!(ack.view_hint, view_hint);
    assert_eq!(ack.suite_id, suite_id);
    assert!(!ack.is_unsigned(), "ack should be signed");
    assert!(!ack.signature.is_empty(), "signature should not be empty");
}

/// Test BatchAck::new_unsigned creates an unsigned ack.
#[test]
fn test_batch_ack_new_unsigned() {
    let batch_ref = BatchRef::new(ValidatorId::new(1), [0xDD; 32]);
    let ack = BatchAck::new_unsigned(batch_ref.clone(), ValidatorId::new(2), 10, 100);

    assert_eq!(ack.batch_ref, batch_ref);
    assert!(ack.is_unsigned(), "ack should be unsigned");
    assert!(ack.signature.is_empty(), "signature should be empty");
}

// ============================================================================
// Part 2: BatchCertificate Tests
// ============================================================================

/// Test BatchCertificate creation and properties.
#[test]
fn test_batch_certificate_creation() {
    let batch_ref = BatchRef::new(ValidatorId::new(1), [0xEE; 32]);
    let signers = vec![
        ValidatorId::new(1),
        ValidatorId::new(2),
        ValidatorId::new(3),
    ];

    let cert = BatchCertificate::new(batch_ref.clone(), 100, signers.clone());

    assert_eq!(*cert.batch_id(), batch_ref.batch_id);
    assert_eq!(cert.view, 100);
    assert_eq!(cert.num_signers(), 3);
    assert!(cert.has_quorum(3), "should have quorum for 3 signers");
    assert!(cert.has_quorum(2), "should have quorum for 2 signers");
    assert!(!cert.has_quorum(4), "should not have quorum for 4 signers");
    assert!(cert.has_signer(ValidatorId::new(1)));
    assert!(cert.has_signer(ValidatorId::new(2)));
    assert!(!cert.has_signer(ValidatorId::new(99)));
}

// ============================================================================
// Part 3: BatchAckTracker Tests
// ============================================================================

/// Test that acks accumulate and form a certificate when quorum is reached.
#[test]
fn test_acks_accumulate_to_quorum_form_cert() {
    // Set up a tracker with quorum = 3 (like f=1, N=4)
    let mut tracker = BatchAckTracker::new(3);
    tracker.set_current_view(10);

    let batch_id: BatchId = [0xAA; 32];
    let batch_ref = BatchRef::new(ValidatorId::new(1), batch_id);

    // Mark batch as known
    tracker.mark_batch_known(batch_id);

    // Insert first ack - should be accepted
    let ack1 = make_test_ack(batch_ref.clone(), ValidatorId::new(1), 10);
    let result1 = tracker.insert_ack(ack1, true);
    assert_eq!(result1, BatchAckResult::Accepted);
    assert_eq!(tracker.ack_count(&batch_id), 1);
    assert!(!tracker.has_certificate(&batch_id));

    // Insert second ack - should be accepted
    let ack2 = make_test_ack(batch_ref.clone(), ValidatorId::new(2), 10);
    let result2 = tracker.insert_ack(ack2, true);
    assert_eq!(result2, BatchAckResult::Accepted);
    assert_eq!(tracker.ack_count(&batch_id), 2);
    assert!(!tracker.has_certificate(&batch_id));

    // Insert third ack - should form certificate
    let ack3 = make_test_ack(batch_ref.clone(), ValidatorId::new(3), 10);
    let result3 = tracker.insert_ack(ack3, true);

    match result3 {
        BatchAckResult::CertificateFormed(cert) => {
            assert_eq!(cert.num_signers(), 3);
            assert_eq!(cert.view, 10);
            assert!(cert.has_signer(ValidatorId::new(1)));
            assert!(cert.has_signer(ValidatorId::new(2)));
            assert!(cert.has_signer(ValidatorId::new(3)));
        }
        _ => panic!("expected CertificateFormed, got {:?}", result3),
    }

    assert!(tracker.has_certificate(&batch_id));
    assert_eq!(tracker.cert_count(), 1);

    // Verify certificate is retrievable
    let cert = tracker
        .certificate(&batch_id)
        .expect("certificate should exist");
    assert_eq!(*cert.batch_id(), batch_id);
}

/// Test that duplicate acks from the same validator are ignored.
#[test]
fn test_duplicate_acks_ignored() {
    let mut tracker = BatchAckTracker::new(2);
    let batch_id: BatchId = [0xBB; 32];
    let batch_ref = BatchRef::new(ValidatorId::new(1), batch_id);

    // Insert first ack
    let ack1 = make_test_ack(batch_ref.clone(), ValidatorId::new(5), 10);
    let result1 = tracker.insert_ack(ack1, true);
    assert_eq!(result1, BatchAckResult::Accepted);
    assert_eq!(tracker.ack_count(&batch_id), 1);

    // Insert duplicate ack from same validator
    let ack2 = make_test_ack(batch_ref.clone(), ValidatorId::new(5), 11); // different view
    let result2 = tracker.insert_ack(ack2, true);
    assert_eq!(result2, BatchAckResult::DuplicateAck);
    assert_eq!(tracker.ack_count(&batch_id), 1); // Should still be 1

    // Third ack from different validator should work
    let ack3 = make_test_ack(batch_ref.clone(), ValidatorId::new(6), 10);
    let result3 = tracker.insert_ack(ack3, true);

    // Should form certificate since we have quorum of 2
    match result3 {
        BatchAckResult::CertificateFormed(_) => {}
        _ => panic!("expected CertificateFormed, got {:?}", result3),
    }

    // Certificate should have exactly 2 unique signers
    let cert = tracker.certificate(&batch_id).unwrap();
    assert_eq!(cert.num_signers(), 2);
}

/// Test that acks for unknown batches are rejected.
#[test]
fn test_unknown_batch_rejected() {
    let mut tracker = BatchAckTracker::new(3);
    let batch_id: BatchId = [0xCC; 32];
    let batch_ref = BatchRef::new(ValidatorId::new(1), batch_id);

    // Insert ack for unknown batch (batch_exists = false)
    let ack = make_test_ack(batch_ref.clone(), ValidatorId::new(2), 10);
    let result = tracker.insert_ack(ack, false);
    assert_eq!(result, BatchAckResult::UnknownBatch);
    assert_eq!(tracker.ack_count(&batch_id), 0);
}

/// Test pending batch count tracking.
#[test]
fn test_pending_batch_count() {
    let mut tracker = BatchAckTracker::new(3);

    // Add acks for two different batches
    let batch1_id: BatchId = [0x11; 32];
    let batch2_id: BatchId = [0x22; 32];
    let batch1_ref = BatchRef::new(ValidatorId::new(1), batch1_id);
    let batch2_ref = BatchRef::new(ValidatorId::new(2), batch2_id);

    // Batch 1: 2 acks (not enough for cert)
    tracker.insert_ack(
        make_test_ack(batch1_ref.clone(), ValidatorId::new(1), 0),
        true,
    );
    tracker.insert_ack(
        make_test_ack(batch1_ref.clone(), ValidatorId::new(2), 0),
        true,
    );

    // Batch 2: 3 acks (forms cert)
    tracker.insert_ack(
        make_test_ack(batch2_ref.clone(), ValidatorId::new(1), 0),
        true,
    );
    tracker.insert_ack(
        make_test_ack(batch2_ref.clone(), ValidatorId::new(2), 0),
        true,
    );
    tracker.insert_ack(
        make_test_ack(batch2_ref.clone(), ValidatorId::new(3), 0),
        true,
    );

    // Check counts
    assert_eq!(tracker.cert_count(), 1, "should have 1 cert");
    assert_eq!(tracker.pending_count(), 1, "should have 1 pending batch");
}

// ============================================================================
// Part 4: InMemoryDagMempool Availability Tests
// ============================================================================

/// Test that availability is disabled by default.
#[test]
fn test_dag_mempool_availability_disabled_by_default() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    assert!(!mempool.is_availability_enabled());
    assert!(!mempool.has_certificate(&[0; 32]));
    assert!(mempool.batch_certificate(&[0; 32]).is_none());
    assert_eq!(mempool.ack_count(&[0; 32]), 0);
}

/// Test that availability can be enabled with quorum.
#[test]
fn test_dag_mempool_with_availability() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 10,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_availability(config, 3);

    assert!(mempool.is_availability_enabled());
}

/// Test that acks are processed when availability is enabled.
#[test]
fn test_dag_mempool_handle_batch_ack() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 10,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_availability(config, 3);
    mempool.set_current_view(10);

    // Create and insert a batch
    let batch = make_test_batch(ValidatorId::new(1), 5);
    let batch_id = batch.batch_id;
    let batch_ref = BatchRef::new(ValidatorId::new(1), batch_id);

    mempool
        .insert_remote_batch(batch)
        .expect("insert should succeed");

    // Insert acks
    let ack1 = make_test_ack(batch_ref.clone(), ValidatorId::new(1), 10);
    let result1 = mempool.handle_batch_ack(ack1);
    assert_eq!(result1, BatchAckResult::Accepted);
    assert_eq!(mempool.ack_count(&batch_id), 1);

    let ack2 = make_test_ack(batch_ref.clone(), ValidatorId::new(2), 10);
    let result2 = mempool.handle_batch_ack(ack2);
    assert_eq!(result2, BatchAckResult::Accepted);
    assert_eq!(mempool.ack_count(&batch_id), 2);

    let ack3 = make_test_ack(batch_ref.clone(), ValidatorId::new(3), 10);
    let result3 = mempool.handle_batch_ack(ack3);

    match result3 {
        BatchAckResult::CertificateFormed(cert) => {
            assert_eq!(cert.num_signers(), 3);
        }
        _ => panic!("expected CertificateFormed, got {:?}", result3),
    }

    assert!(mempool.has_certificate(&batch_id));
    let cert = mempool
        .batch_certificate(&batch_id)
        .expect("cert should exist");
    assert_eq!(cert.num_signers(), 3);
}

/// Test that acks are rejected when availability is disabled.
#[test]
fn test_dag_mempool_ack_rejected_when_disabled() {
    let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

    let batch_ref = BatchRef::new(ValidatorId::new(1), [0xAA; 32]);
    let ack = make_test_ack(batch_ref, ValidatorId::new(2), 10);
    let result = mempool.handle_batch_ack(ack);

    match result {
        BatchAckResult::Rejected(reason) => {
            assert!(reason.contains("not enabled"));
        }
        _ => panic!("expected Rejected, got {:?}", result),
    }
}

/// Test that duplicate acks are rejected via mempool.
#[test]
fn test_dag_mempool_duplicate_ack_rejected() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 10,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_availability(config, 3);

    // Create and insert a batch
    let batch = make_test_batch(ValidatorId::new(1), 5);
    let batch_ref = BatchRef::new(ValidatorId::new(1), batch.batch_id);
    mempool
        .insert_remote_batch(batch)
        .expect("insert should succeed");

    // Insert first ack
    let ack1 = make_test_ack(batch_ref.clone(), ValidatorId::new(2), 10);
    let result1 = mempool.handle_batch_ack(ack1);
    assert_eq!(result1, BatchAckResult::Accepted);

    // Insert duplicate ack
    let ack2 = make_test_ack(batch_ref.clone(), ValidatorId::new(2), 11);
    let result2 = mempool.handle_batch_ack(ack2);
    assert_eq!(result2, BatchAckResult::DuplicateAck);
}

/// Test that acks for unknown batches are rejected via mempool.
#[test]
fn test_dag_mempool_unknown_batch_ack_rejected() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 10,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_availability(config, 3);

    // Create ack for a batch that doesn't exist in mempool
    let batch_ref = BatchRef::new(ValidatorId::new(99), [0xFF; 32]);
    let ack = make_test_ack(batch_ref, ValidatorId::new(2), 10);
    let result = mempool.handle_batch_ack(ack);
    assert_eq!(result, BatchAckResult::UnknownBatch);
}

// ============================================================================
// Part 5: DagAvailabilityConfig Tests
// ============================================================================

/// Test quorum size calculation.
#[test]
fn test_dag_availability_config_quorum_size() {
    let config = DagAvailabilityConfig::enabled();

    // Standard BFT quorum: ceil(n * 2/3)
    assert_eq!(config.compute_quorum_size(4), 3); // f=1
    assert_eq!(config.compute_quorum_size(7), 5); // f=2
    assert_eq!(config.compute_quorum_size(10), 7); // f=3
    assert_eq!(config.compute_quorum_size(1), 1); // edge case
    assert_eq!(config.compute_quorum_size(0), 1); // edge case
}

// ============================================================================
// Part 6: Cross-Chain Rejection Test
// ============================================================================

/// Critical security test: Acks signed with DevNet chain-id must not be valid on TestNet.
///
/// This test verifies that domain separation prevents cross-chain replay attacks.
#[test]
fn test_cross_chain_ack_preimage_rejection() {
    let batch_ref = BatchRef::new(ValidatorId::new(1), [0xAA; 32]);
    let validator_id = ValidatorId::new(2);
    let view_hint = 10;

    // Generate preimages for different chains
    let devnet_preimage = BatchAck::signing_preimage_with_chain_id(
        QBIND_DEVNET_CHAIN_ID,
        &batch_ref,
        validator_id,
        view_hint,
    );
    let testnet_preimage = BatchAck::signing_preimage_with_chain_id(
        QBIND_TESTNET_CHAIN_ID,
        &batch_ref,
        validator_id,
        view_hint,
    );

    // Verify domain tags are present and different
    assert!(devnet_preimage.starts_with(b"QBIND:DEV:BATCH_ACK:v1"));
    assert!(testnet_preimage.starts_with(b"QBIND:TST:BATCH_ACK:v1"));

    // If a signature is created for devnet_preimage, it will NOT verify against testnet_preimage
    // because the preimages are different. This is the core domain separation guarantee.
    assert_ne!(
        devnet_preimage, testnet_preimage,
        "Cross-chain preimages MUST differ for security"
    );

    // The chain scope is embedded in the preimage, so a DevNet signature cannot be
    // replayed on TestNet - verification will fail because the preimage won't match.
}

// ============================================================================
// Part 7: Metrics Tests
// ============================================================================

/// Test that metrics are updated when processing acks.
#[test]
fn test_dag_mempool_metrics_ack_tracking() {
    let metrics = Arc::new(DagMempoolMetrics::new());
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 10,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
    };
    let mempool = InMemoryDagMempool::with_availability(config, 2).with_metrics(metrics.clone());

    // Create and insert a batch
    let batch = make_test_batch(ValidatorId::new(1), 5);
    let batch_id = batch.batch_id;
    let batch_ref = BatchRef::new(ValidatorId::new(1), batch_id);
    mempool
        .insert_remote_batch(batch)
        .expect("insert should succeed");

    // Process acks
    let ack1 = make_test_ack(batch_ref.clone(), ValidatorId::new(1), 10);
    mempool.handle_batch_ack(ack1);

    let ack2 = make_test_ack(batch_ref.clone(), ValidatorId::new(2), 10);
    mempool.handle_batch_ack(ack2);

    // Duplicate ack
    let ack3 = make_test_ack(batch_ref.clone(), ValidatorId::new(1), 11);
    mempool.handle_batch_ack(ack3);

    // Unknown batch ack
    let unknown_ref = BatchRef::new(ValidatorId::new(99), [0xFF; 32]);
    let ack4 = make_test_ack(unknown_ref, ValidatorId::new(3), 10);
    mempool.handle_batch_ack(ack4);

    // Check metrics
    assert_eq!(metrics.batch_acks_accepted(), 2); // ack1 + ack2
    assert_eq!(metrics.batch_acks_rejected_duplicate(), 1); // ack3
    assert_eq!(metrics.batch_acks_rejected_unknown(), 1); // ack4
    assert_eq!(metrics.batch_certs_total(), 1); // cert formed after ack2
}

/// Test metrics format output includes T165 metrics.
#[test]
fn test_dag_mempool_metrics_format_includes_t165() {
    let metrics = DagMempoolMetrics::new();

    // Simulate some activity
    metrics.inc_batch_acks_accepted();
    metrics.inc_batch_acks_accepted();
    metrics.inc_batch_acks_rejected_duplicate();
    metrics.inc_batch_certs_total();

    let output = metrics.format_metrics();

    assert!(output.contains("qbind_dag_batch_acks_total{result=\"accepted\"} 2"));
    assert!(output.contains("qbind_dag_batch_acks_invalid_total{reason=\"duplicate\"} 1"));
    assert!(output.contains("qbind_dag_batch_certs_total 1"));
}
