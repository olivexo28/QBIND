//! T165 Integration Tests: DAG Availability Certificates v1
//!
//! These integration tests verify the DAG availability certificate functionality
//! in more realistic scenarios:
//! - Single node with local acks reaching certificate state
//! - Multi-validator simulation with ack exchange
//! - Metrics integration with certificate formation
//!
//! These tests focus on safety and correctness, not high throughput.

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_ledger::QbindTransaction;
use qbind_node::{
    BatchAck, BatchAckResult, BatchId, BatchRef, DagAvailabilityConfig, DagMempool,
    DagMempoolConfig, DagMempoolMetrics, EvictionRateMode, InMemoryDagMempool, QbindBatch,
};
use qbind_types::QBIND_TESTNET_CHAIN_ID;

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

fn make_test_batch(creator: ValidatorId, view_hint: u64, tx_count: usize) -> QbindBatch {
    let txs: Vec<_> = (0..tx_count)
        .map(|i| make_test_tx(creator.as_u64() as u8, i as u64, (i + 1) as u8))
        .collect();
    QbindBatch::new(creator, view_hint, vec![], txs)
}

fn make_signed_ack(batch_ref: BatchRef, validator_id: ValidatorId, view_hint: u64) -> BatchAck {
    // Create a signed ack using a simple signing function
    BatchAck::new_signed(
        batch_ref,
        validator_id,
        view_hint,
        QBIND_TESTNET_CHAIN_ID,
        100,
        |preimage| Ok::<Vec<u8>, String>(qbind_hash::sha3_256(preimage).to_vec()),
    )
    .expect("signing should succeed")
}

/// Create a mempool configured for TestNet Alpha DAG mode.
fn create_testnet_dag_mempool(
    validator_id: ValidatorId,
    num_validators: usize,
) -> InMemoryDagMempool {
    let config = DagMempoolConfig {
        local_validator_id: validator_id,
        batch_size: 10,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
        max_pending_per_sender: 10_000,
        max_pending_bytes_per_sender: 64 * 1024 * 1024,
        max_txs_per_batch: 10_000,
        max_batch_bytes: 4 * 1024 * 1024,
        eviction_mode: EvictionRateMode::Off,
        max_evictions_per_interval: 10_000,
        eviction_interval_secs: 10,
    };

    let dag_config = DagAvailabilityConfig::enabled();
    let quorum_size = dag_config.compute_quorum_size(num_validators);

    InMemoryDagMempool::with_availability(config, quorum_size)
}

// ============================================================================
// Part 1: Single Node Local Acks Certificate Test
// ============================================================================

/// Test that a single node with DAG availability enabled can form certificates.
///
/// This simulates a node receiving acks from itself and other validators,
/// reaching the quorum threshold and forming a certificate.
#[test]
fn test_single_node_local_acks_cert() {
    // Setup: Single node in a 4-validator network (f=1, quorum=3)
    let node_id = ValidatorId::new(1);
    let mempool = create_testnet_dag_mempool(node_id, 4);
    let metrics = Arc::new(DagMempoolMetrics::new());
    let mempool = mempool.with_metrics(metrics.clone());
    mempool.set_current_view(10);

    // Create a local batch
    let batch = make_test_batch(node_id, 5, 3);
    let batch_id = batch.batch_id;
    let batch_ref = BatchRef::new(node_id, batch_id);

    // Insert the batch into the mempool
    mempool
        .insert_remote_batch(batch)
        .expect("insert should succeed");
    assert!(mempool.has_batch(&batch_id), "batch should exist");

    // Simulate receiving acks from 3 validators (including self)
    let ack1 = make_signed_ack(batch_ref.clone(), ValidatorId::new(1), 10);
    let result1 = mempool.handle_batch_ack(ack1);
    assert_eq!(result1, BatchAckResult::Accepted);
    assert!(!mempool.has_certificate(&batch_id), "no cert yet (1/3)");

    let ack2 = make_signed_ack(batch_ref.clone(), ValidatorId::new(2), 10);
    let result2 = mempool.handle_batch_ack(ack2);
    assert_eq!(result2, BatchAckResult::Accepted);
    assert!(!mempool.has_certificate(&batch_id), "no cert yet (2/3)");

    let ack3 = make_signed_ack(batch_ref.clone(), ValidatorId::new(3), 10);
    let result3 = mempool.handle_batch_ack(ack3);

    // Third ack should form certificate
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

    // Verify certificate is accessible
    assert!(mempool.has_certificate(&batch_id));
    let cert = mempool
        .batch_certificate(&batch_id)
        .expect("cert should exist");
    assert_eq!(cert.num_signers(), 3);

    // Verify metrics
    assert_eq!(metrics.batch_acks_accepted(), 3);
    assert_eq!(metrics.batch_certs_total(), 1);
}

// ============================================================================
// Part 2: Multi-Validator Cluster Simulation
// ============================================================================

/// Simulated validator node for multi-node testing.
struct SimulatedValidator {
    id: ValidatorId,
    mempool: InMemoryDagMempool,
}

impl SimulatedValidator {
    fn new(id: u64, num_validators: usize) -> Self {
        let validator_id = ValidatorId::new(id);
        let mempool = create_testnet_dag_mempool(validator_id, num_validators);
        SimulatedValidator {
            id: validator_id,
            mempool,
        }
    }

    fn insert_batch(&self, batch: QbindBatch) -> Result<(), String> {
        self.mempool
            .insert_remote_batch(batch)
            .map_err(|e| e.to_string())
    }

    fn handle_ack(&self, ack: BatchAck) -> BatchAckResult {
        self.mempool.handle_batch_ack(ack)
    }

    fn has_certificate(&self, batch_id: &BatchId) -> bool {
        self.mempool.has_certificate(batch_id)
    }
}

/// Multi-node cluster smoke test.
///
/// This test simulates a 4-validator cluster where:
/// 1. One validator creates a batch
/// 2. All validators receive the batch
/// 3. All validators exchange acks
/// 4. All validators form certificates
///
/// This is marked #[ignore] since it's a heavier test.
#[test]
#[ignore]
fn test_multi_node_cluster_smoke() {
    const NUM_VALIDATORS: usize = 4;

    // Create validators
    let validators: Vec<_> = (1..=NUM_VALIDATORS as u64)
        .map(|id| SimulatedValidator::new(id, NUM_VALIDATORS))
        .collect();

    // Validator 1 creates a batch
    let batch_creator = ValidatorId::new(1);
    let batch = make_test_batch(batch_creator, 1, 5);
    let batch_id = batch.batch_id;
    let batch_ref = BatchRef::new(batch_creator, batch_id);

    // All validators receive the batch (simulating network broadcast)
    for validator in &validators {
        validator
            .insert_batch(batch.clone())
            .expect("batch insert should succeed");
    }

    // Each validator creates and broadcasts an ack
    let acks: Vec<_> = validators
        .iter()
        .map(|v| make_signed_ack(batch_ref.clone(), v.id, 1))
        .collect();

    // All validators receive all acks
    for validator in &validators {
        for ack in &acks {
            let _ = validator.handle_ack(ack.clone());
        }
    }

    // All validators should have a certificate
    for validator in &validators {
        assert!(
            validator.has_certificate(&batch_id),
            "validator {} should have certificate",
            validator.id.as_u64()
        );
    }

    println!(
        "Multi-node cluster smoke test passed: all {} validators have certificate",
        NUM_VALIDATORS
    );
}

/// Multi-node test with partial ack delivery (some acks lost).
///
/// This test verifies that validators can still form certificates
/// even if some acks are lost, as long as quorum is reached.
#[test]
fn test_multi_node_partial_ack_delivery() {
    const NUM_VALIDATORS: usize = 4;
    const QUORUM: usize = 3;

    // Create validators
    let validators: Vec<_> = (1..=NUM_VALIDATORS as u64)
        .map(|id| SimulatedValidator::new(id, NUM_VALIDATORS))
        .collect();

    // Validator 1 creates a batch
    let batch_creator = ValidatorId::new(1);
    let batch = make_test_batch(batch_creator, 1, 3);
    let batch_id = batch.batch_id;
    let batch_ref = BatchRef::new(batch_creator, batch_id);

    // All validators receive the batch
    for validator in &validators {
        validator
            .insert_batch(batch.clone())
            .expect("should succeed");
    }

    // Create acks from only 3 validators (enough for quorum)
    let acks: Vec<_> = (1..=QUORUM as u64)
        .map(|id| make_signed_ack(batch_ref.clone(), ValidatorId::new(id), 1))
        .collect();

    // Validator 1 receives all 3 acks -> should form cert
    for ack in &acks {
        validators[0].handle_ack(ack.clone());
    }
    assert!(
        validators[0].has_certificate(&batch_id),
        "validator 1 should have certificate with 3 acks"
    );

    // Validator 4 only receives 2 acks (not enough)
    validators[3].handle_ack(acks[0].clone());
    validators[3].handle_ack(acks[1].clone());
    assert!(
        !validators[3].has_certificate(&batch_id),
        "validator 4 should NOT have certificate with only 2 acks"
    );

    // Validator 4 receives the third ack -> now has cert
    validators[3].handle_ack(acks[2].clone());
    assert!(
        validators[3].has_certificate(&batch_id),
        "validator 4 should have certificate after third ack"
    );
}

// ============================================================================
// Part 3: DAG Availability Config Integration
// ============================================================================

/// Test DagAvailabilityConfig integration with mempool.
#[test]
fn test_dag_availability_config_integration() {
    // Test disabled config (DevNet default)
    let disabled_config = DagAvailabilityConfig::disabled();
    assert!(!disabled_config.enabled);

    // Test enabled config (TestNet Alpha)
    let enabled_config = DagAvailabilityConfig::enabled();
    assert!(enabled_config.enabled);

    // Test quorum computation for different validator counts
    assert_eq!(enabled_config.compute_quorum_size(4), 3); // f=1, 2f+1=3
    assert_eq!(enabled_config.compute_quorum_size(7), 5); // f=2, 2f+1=5
    assert_eq!(enabled_config.compute_quorum_size(10), 7); // f=3, 2f+1=7

    // Create mempool with computed quorum
    let validator_id = ValidatorId::new(1);
    let num_validators = 4;
    let quorum = enabled_config.compute_quorum_size(num_validators);

    let config = DagMempoolConfig {
        local_validator_id: validator_id,
        batch_size: 10,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
        max_pending_per_sender: 10_000,
        max_pending_bytes_per_sender: 64 * 1024 * 1024,
        max_txs_per_batch: 10_000,
        max_batch_bytes: 4 * 1024 * 1024,
        eviction_mode: EvictionRateMode::Off,
        max_evictions_per_interval: 10_000,
        eviction_interval_secs: 10,
    };

    let mempool = InMemoryDagMempool::with_availability(config, quorum);
    assert!(mempool.is_availability_enabled());

    // Insert batch and verify it needs 3 acks for cert
    let batch = make_test_batch(validator_id, 1, 2);
    let batch_id = batch.batch_id;
    let batch_ref = BatchRef::new(validator_id, batch_id);
    mempool.insert_remote_batch(batch).expect("should succeed");

    // 2 acks -> no cert
    mempool.handle_batch_ack(make_signed_ack(batch_ref.clone(), ValidatorId::new(1), 1));
    mempool.handle_batch_ack(make_signed_ack(batch_ref.clone(), ValidatorId::new(2), 1));
    assert!(
        !mempool.has_certificate(&batch_id),
        "2 acks should not form cert"
    );

    // 3rd ack -> cert
    mempool.handle_batch_ack(make_signed_ack(batch_ref.clone(), ValidatorId::new(3), 1));
    assert!(
        mempool.has_certificate(&batch_id),
        "3 acks should form cert"
    );
}

// ============================================================================
// Part 4: Error Handling and Edge Cases
// ============================================================================

/// Test graceful handling of acks before batch arrives.
#[test]
fn test_ack_before_batch_ignored() {
    let mempool = create_testnet_dag_mempool(ValidatorId::new(1), 4);

    // Create ack for non-existent batch
    let unknown_batch_id: BatchId = [0xFF; 32];
    let batch_ref = BatchRef::new(ValidatorId::new(99), unknown_batch_id);
    let ack = make_signed_ack(batch_ref, ValidatorId::new(1), 10);

    // Ack should be rejected as unknown batch
    let result = mempool.handle_batch_ack(ack);
    assert_eq!(result, BatchAckResult::UnknownBatch);

    // No metrics impact for unknown batch (except rejected counter)
    let stats = mempool.stats();
    assert_eq!(stats.num_batches, 0);
}

/// Test that availability can be enabled after construction.
#[test]
fn test_enable_availability_after_construction() {
    let config = DagMempoolConfig {
        local_validator_id: ValidatorId::new(1),
        batch_size: 10,
        max_batches: 100,
        max_pending_txs: 1000,
        enable_fee_priority: false,
        max_pending_per_sender: 10_000,
        max_pending_bytes_per_sender: 64 * 1024 * 1024,
        max_txs_per_batch: 10_000,
        max_batch_bytes: 4 * 1024 * 1024,
        eviction_mode: EvictionRateMode::Off,
        max_evictions_per_interval: 10_000,
        eviction_interval_secs: 10,
    };

    // Start with availability disabled
    let mut mempool = InMemoryDagMempool::with_config(config);
    assert!(!mempool.is_availability_enabled());

    // Enable availability
    mempool.enable_availability(3);
    assert!(mempool.is_availability_enabled());

    // Now acks should be processed
    let batch = make_test_batch(ValidatorId::new(1), 1, 2);
    let batch_ref = BatchRef::new(ValidatorId::new(1), batch.batch_id);
    mempool.insert_remote_batch(batch).expect("should succeed");

    let ack = make_signed_ack(batch_ref, ValidatorId::new(2), 1);
    let result = mempool.handle_batch_ack(ack);
    assert_eq!(result, BatchAckResult::Accepted);
}

// ============================================================================
// Part 5: Metrics Integration Tests
// ============================================================================

/// Test that all T165 metrics are properly tracked.
#[test]
fn test_t165_metrics_integration() {
    let metrics = Arc::new(DagMempoolMetrics::new());
    let mempool = create_testnet_dag_mempool(ValidatorId::new(1), 4).with_metrics(metrics.clone());
    mempool.set_current_view(1);

    // Create and insert batch
    let batch = make_test_batch(ValidatorId::new(1), 1, 2);
    let batch_id = batch.batch_id;
    let batch_ref = BatchRef::new(ValidatorId::new(1), batch_id);
    mempool.insert_remote_batch(batch).expect("should succeed");

    // Track various ack scenarios
    // Accepted acks
    mempool.handle_batch_ack(make_signed_ack(batch_ref.clone(), ValidatorId::new(1), 1));
    mempool.handle_batch_ack(make_signed_ack(batch_ref.clone(), ValidatorId::new(2), 1));
    mempool.handle_batch_ack(make_signed_ack(batch_ref.clone(), ValidatorId::new(3), 1)); // forms cert

    // Duplicate ack
    mempool.handle_batch_ack(make_signed_ack(batch_ref.clone(), ValidatorId::new(1), 2));

    // Unknown batch ack
    let unknown_ref = BatchRef::new(ValidatorId::new(99), [0xFF; 32]);
    mempool.handle_batch_ack(make_signed_ack(unknown_ref, ValidatorId::new(4), 1));

    // Verify metrics
    assert_eq!(
        metrics.batch_acks_accepted(),
        3,
        "should have 3 accepted acks"
    );
    assert_eq!(
        metrics.batch_acks_rejected_duplicate(),
        1,
        "should have 1 duplicate rejection"
    );
    assert_eq!(
        metrics.batch_acks_rejected_unknown(),
        1,
        "should have 1 unknown rejection"
    );
    assert_eq!(metrics.batch_certs_total(), 1, "should have 1 certificate");

    // Verify format includes T165 metrics
    let output = metrics.format_metrics();
    assert!(output.contains("qbind_dag_batch_acks_total"));
    assert!(output.contains("qbind_dag_batch_certs_total"));
}
