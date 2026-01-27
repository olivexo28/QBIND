//! T155 Async Execution Pipeline Integration Tests
//!
//! Tests for the async execution service integration with the consensus harness.
//!
//! These tests verify:
//! 1. SingleThreadExecutionService processes blocks in order
//! 2. Async execution works correctly with QbindBlocks
//! 3. Metrics are properly updated
//! 4. Queue backpressure works as expected
//! 5. Shutdown behavior is correct

use std::sync::Arc;
use std::time::{Duration, Instant};

use qbind_ledger::{NonceExecutionEngine, QbindTransaction};
use qbind_node::execution_adapter::{
    AsyncExecError, AsyncExecutionService, QbindBlock, SingleThreadExecutionService,
    SingleThreadExecutionServiceConfig,
};
use qbind_node::metrics::ExecutionMetrics;
use qbind_wire::consensus::{BlockHeader, BlockProposal};

// ============================================================================
// Helper functions
// ============================================================================

fn test_account_id(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

fn make_test_proposal(height: u64) -> Arc<BlockProposal> {
    Arc::new(BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1337,
            epoch: 0,
            height,
            round: 0,
            parent_block_id: [0u8; 32],
            payload_hash: [height as u8; 32],
            proposer_index: 0,
            suite_id: 0,
            tx_count: 0,
            timestamp: 1704067200 + height,
            payload_kind: 0,
            next_epoch: 0,
        },
        qc: None,
        txs: Vec::new(),
        signature: Vec::new(),
    })
}

// ============================================================================
// Basic Integration Tests
// ============================================================================

#[test]
fn test_async_service_processes_blocks_in_order() {
    let engine = NonceExecutionEngine::new();
    let service = SingleThreadExecutionService::new(engine);

    let sender = test_account_id(0xAA);

    // Submit blocks in sequence
    for i in 0u64..10 {
        let txs = vec![QbindTransaction::new(
            sender,
            i,
            format!("block{}", i).into_bytes(),
        )];
        let proposal = make_test_proposal(i + 1);
        let block = QbindBlock::new(proposal, txs);

        let result = service.submit_block(block);
        assert!(result.is_ok(), "Block {} submission failed", i + 1);
    }

    // Wait for all processing
    std::thread::sleep(Duration::from_millis(500));

    // Verify queue is drained
    assert_eq!(
        service.queue_len(),
        0,
        "Queue should be empty after processing"
    );
}

#[test]
fn test_async_service_with_metrics() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default();
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    let sender = test_account_id(0xBB);

    // Submit a block with transactions
    let txs = vec![
        QbindTransaction::new(sender, 0, b"tx0".to_vec()),
        QbindTransaction::new(sender, 1, b"tx1".to_vec()),
        QbindTransaction::new(sender, 2, b"tx2".to_vec()),
    ];
    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    service.submit_block(block).expect("submit should succeed");

    // Wait for processing
    std::thread::sleep(Duration::from_millis(200));

    // Verify metrics were updated
    assert_eq!(metrics.txs_applied_total(), 3, "Should have applied 3 txs");
    assert_eq!(
        metrics.blocks_applied_total(),
        1,
        "Should have applied 1 block"
    );
}

#[test]
fn test_async_service_queue_backpressure() {
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::default().with_queue_capacity(2);
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    // Rapidly submit many blocks to trigger backpressure
    let mut queue_full_count = 0;
    for i in 0..100 {
        let proposal = make_test_proposal(i);
        let block = QbindBlock::empty(proposal);

        match service.submit_block(block) {
            Ok(()) => {}
            Err(AsyncExecError::QueueFull) => {
                queue_full_count += 1;
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // Should have seen some queue full errors
    assert!(
        queue_full_count > 0 || service.queue_full_count() > 0,
        "Should have experienced queue backpressure"
    );
}

#[test]
fn test_async_service_shutdown_behavior() {
    let engine = NonceExecutionEngine::new();
    let service = SingleThreadExecutionService::new(engine);

    // Submit one block first
    let proposal = make_test_proposal(1);
    let block = QbindBlock::empty(proposal);
    service
        .submit_block(block)
        .expect("first submit should succeed");

    // Signal shutdown
    service.shutdown();
    assert!(service.is_shutting_down());

    // Subsequent submits should return ShuttingDown
    let proposal2 = make_test_proposal(2);
    let block2 = QbindBlock::empty(proposal2);
    let result = service.submit_block(block2);

    assert!(matches!(result, Err(AsyncExecError::ShuttingDown)));
}

#[test]
fn test_async_service_empty_blocks() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default();
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    // Submit empty blocks
    for i in 0..5 {
        let proposal = make_test_proposal(i + 1);
        let block = QbindBlock::empty(proposal);
        service.submit_block(block).expect("submit should succeed");
    }

    // Wait for processing
    std::thread::sleep(Duration::from_millis(200));

    // Empty blocks should still be "applied" but with 0 txs
    assert_eq!(
        metrics.txs_applied_total(),
        0,
        "No txs should be applied for empty blocks"
    );
}

#[test]
fn test_async_service_multiple_senders() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default();
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    let sender_a = test_account_id(0xA1);
    let sender_b = test_account_id(0xB2);

    // Block with multiple senders
    let txs = vec![
        QbindTransaction::new(sender_a, 0, b"a0".to_vec()),
        QbindTransaction::new(sender_b, 0, b"b0".to_vec()),
        QbindTransaction::new(sender_a, 1, b"a1".to_vec()),
        QbindTransaction::new(sender_b, 1, b"b1".to_vec()),
    ];

    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);
    service.submit_block(block).expect("submit should succeed");

    // Wait for processing
    std::thread::sleep(Duration::from_millis(200));

    assert_eq!(
        metrics.txs_applied_total(),
        4,
        "Should have applied all 4 txs"
    );
}

#[test]
fn test_async_service_execution_latency_reasonable() {
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::default();
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    let sender = test_account_id(0xCC);

    // Submit a moderate-sized block
    let txs: Vec<_> = (0..100)
        .map(|i| QbindTransaction::new(sender, i, vec![0xAB; 128]))
        .collect();
    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    let start = Instant::now();
    service.submit_block(block).expect("submit should succeed");
    let submit_latency = start.elapsed();

    // Submit should be near-instant (non-blocking)
    assert!(
        submit_latency < Duration::from_millis(10),
        "Submit should be non-blocking, took {:?}",
        submit_latency
    );

    // Wait for processing to complete
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(service.queue_len(), 0, "Queue should be drained");
}

#[test]
fn test_async_service_nonce_mismatch_error_handling() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default();
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    let sender = test_account_id(0xDD);

    // Block with invalid nonce (should be 0, but starts at 5)
    let txs = vec![QbindTransaction::new(sender, 5, b"wrong_nonce".to_vec())];
    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    service.submit_block(block).expect("submit should succeed");

    // Wait for processing
    std::thread::sleep(Duration::from_millis(200));

    // Should have recorded an error
    assert!(
        metrics.errors_total() > 0,
        "Should have recorded an execution error"
    );
}

// ============================================================================
// T155 DevNet TPS Harness Compatibility Test
// ============================================================================

/// Verify that the async execution service can be used with TPS-style workloads
#[test]
fn test_async_service_tps_compatibility() {
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_ledger::UserPublicKey;

    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default().with_queue_capacity(1024);
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    // Generate a test keypair
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let public_key = UserPublicKey::ml_dsa_44(pk_bytes);

    // Derive account ID
    let pk_slice = public_key.as_bytes();
    let mut account_id = [0u8; 32];
    for (i, chunk) in pk_slice.chunks(32).enumerate() {
        for (j, &byte) in chunk.iter().enumerate() {
            if j < 32 {
                account_id[j] ^= byte.wrapping_add(i as u8);
            }
        }
    }

    // Create signed transactions and submit them in blocks
    let num_blocks = 10;
    let txs_per_block = 100;
    let total_txs = num_blocks * txs_per_block;

    let start = Instant::now();
    let mut nonce = 0u64;

    for block_num in 0..num_blocks {
        let mut block_txs = Vec::with_capacity(txs_per_block);
        for _ in 0..txs_per_block {
            let mut tx = QbindTransaction::new(account_id, nonce, vec![0xAB; 64]);
            tx.sign(&sk).expect("signing should succeed");
            block_txs.push(tx);
            nonce += 1;
        }

        let proposal = make_test_proposal(block_num as u64 + 1);
        let block = QbindBlock::new(proposal, block_txs);

        match service.submit_block(block) {
            Ok(()) => {}
            Err(AsyncExecError::QueueFull) => {
                // If queue is full, wait a bit and retry
                std::thread::sleep(Duration::from_millis(50));
                // In a real scenario, we'd retry the submission
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // Wait for all processing
    let timeout = Duration::from_secs(30);
    let start_wait = Instant::now();
    while service.queue_len() > 0 && start_wait.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(100));
    }

    let duration = start.elapsed();
    let applied = metrics.txs_applied_total();

    eprintln!(
        "[T155 TPS Test] Submitted {} txs in {} blocks",
        total_txs, num_blocks
    );
    eprintln!("[T155 TPS Test] Applied {} txs in {:?}", applied, duration);
    eprintln!("[T155 TPS Test] Queue len at end: {}", service.queue_len());
    eprintln!(
        "[T155 TPS Test] Queue full count: {}",
        service.queue_full_count()
    );

    // Verify most transactions were applied (allowing for some dropped due to queue full)
    assert!(
        applied >= total_txs as u64 / 2,
        "Should have applied at least half the transactions"
    );
}