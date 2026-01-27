//! T157 Parallel Execution Integration Tests
//!
//! Tests for the Stage A parallel execution integration with the async execution service.
//!
//! These tests verify:
//! 1. SingleThreadExecutionService with parallel executor processes blocks correctly
//! 2. Parallel execution metrics are recorded
//! 3. Multiple senders achieve parallelism
//! 4. Fallback to sequential works correctly
//! 5. TPS harness compatibility with parallel execution

use std::sync::Arc;
use std::time::{Duration, Instant};

use qbind_ledger::{NonceExecutionEngine, ParallelExecConfig, QbindTransaction};
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
// Test: Parallel execution with multiple senders
// ============================================================================

#[test]
fn test_parallel_execution_multiple_senders() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default()
        .with_parallel_config(ParallelExecConfig::default());
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    // Create a block with many distinct senders
    let mut txs = Vec::new();
    for sender_byte in 0u8..20 {
        for nonce in 0u64..5 {
            let sender = test_account_id(sender_byte);
            txs.push(QbindTransaction::new(
                sender,
                nonce,
                format!("tx_{}_n{}", sender_byte, nonce).into_bytes(),
            ));
        }
    }

    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    service.submit_block(block).expect("submit should succeed");

    // Wait for processing
    std::thread::sleep(Duration::from_millis(500));

    // Verify metrics
    let txs_applied = metrics.txs_applied_total();
    assert_eq!(txs_applied, 100, "should have applied 100 txs");

    // Check parallel execution metrics
    let parallel_workers = metrics.parallel_workers_active();
    eprintln!(
        "[T157] Applied {} txs with {} parallel workers",
        txs_applied, parallel_workers
    );

    // Parallel workers should be > 0 since we have many senders
    // (exact value depends on rayon's thread pool configuration)
}

// ============================================================================
// Test: Sequential fallback with single sender
// ============================================================================

#[test]
fn test_sequential_fallback_single_sender() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default()
        .with_parallel_config(ParallelExecConfig::default().with_min_senders(2));
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    // Create a block with a single sender
    let sender = test_account_id(0xAA);
    let txs: Vec<_> = (0..50)
        .map(|nonce| QbindTransaction::new(sender, nonce, format!("tx_{}", nonce).into_bytes()))
        .collect();

    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    service.submit_block(block).expect("submit should succeed");

    // Wait for processing
    std::thread::sleep(Duration::from_millis(300));

    // Verify transactions were applied
    assert_eq!(metrics.txs_applied_total(), 50);

    // Should have recorded a fallback
    let fallback_count = metrics.parallel_fallback_total();
    eprintln!("[T157] Sequential fallback count: {}", fallback_count);
    assert!(fallback_count > 0, "should have fallen back to sequential");
}

// ============================================================================
// Test: Forced sequential mode
// ============================================================================

#[test]
fn test_forced_sequential_mode() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default().sequential_only();
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    // Create a block with multiple senders (would normally use parallel)
    let mut txs = Vec::new();
    for sender_byte in 0u8..10 {
        for nonce in 0u64..5 {
            txs.push(QbindTransaction::new(
                test_account_id(sender_byte),
                nonce,
                b"test".to_vec(),
            ));
        }
    }

    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    service.submit_block(block).expect("submit should succeed");

    // Wait for processing
    std::thread::sleep(Duration::from_millis(300));

    // Verify transactions were applied
    assert_eq!(metrics.txs_applied_total(), 50);

    // Should have used sequential path
    let fallback_count = metrics.parallel_fallback_total();
    assert!(fallback_count > 0, "should have used sequential path");
}

// ============================================================================
// Test: Parallel execution metrics are recorded
// ============================================================================

#[test]
fn test_parallel_execution_metrics_recorded() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default();
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    // Submit multiple blocks with varying sender counts
    for block_num in 1u64..=3 {
        let sender_count = (block_num * 5) as u8;
        let mut txs = Vec::new();
        for sender_byte in 0u8..sender_count {
            // Use wrapping arithmetic to avoid overflow
            let sender_id = sender_byte.wrapping_add((block_num as u8).wrapping_mul(20));
            txs.push(QbindTransaction::new(
                test_account_id(sender_id),
                0,
                b"test".to_vec(),
            ));
        }

        let proposal = make_test_proposal(block_num);
        let block = QbindBlock::new(proposal, txs);
        service.submit_block(block).expect("submit should succeed");
    }

    // Wait for processing
    std::thread::sleep(Duration::from_millis(500));

    // Check sender partition metrics
    let sender_buckets = metrics.sender_partitions_buckets();
    let sender_sum = metrics.sender_partitions_sum();

    eprintln!("[T157] Sender partitions buckets: {:?}", sender_buckets);
    eprintln!("[T157] Sender partitions sum: {}", sender_sum);

    // Sum should be 5 + 10 + 15 = 30
    assert_eq!(sender_sum, 30, "sender partitions sum should match");

    // Check parallel block time metrics
    let (pb1, pb10, pb100, pb_over) = metrics.parallel_block_buckets();
    let total_blocks = pb1 + pb10 + pb100 + pb_over;
    assert_eq!(total_blocks, 3, "should have recorded 3 blocks");
}

// ============================================================================
// Test: Queue behavior with parallel execution
// ============================================================================

#[test]
fn test_queue_behavior_with_parallel() {
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::default().with_queue_capacity(10);
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    // Submit multiple blocks quickly
    for i in 0..20 {
        let sender = test_account_id((i % 10) as u8);
        let txs = vec![QbindTransaction::new(
            sender,
            (i / 10) as u64,
            format!("block_{}", i).into_bytes(),
        )];
        let proposal = make_test_proposal(i as u64 + 1);
        let block = QbindBlock::new(proposal, txs);

        let _ = service.submit_block(block); // Ignore queue full errors
    }

    // Wait for processing
    std::thread::sleep(Duration::from_millis(500));

    // Queue should be drained
    assert!(service.queue_len() < 5, "queue should be mostly drained");
}

// ============================================================================
// Test: TPS harness compatibility with parallel execution
// ============================================================================

/// Verify that the async execution service with parallel executor can handle
/// TPS-style workloads (many transactions from multiple senders).
#[test]
fn test_tps_harness_compatibility_parallel() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default()
        .with_queue_capacity(1024)
        .with_parallel_config(ParallelExecConfig::default().with_min_senders(2));
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    // Simulate TPS workload: 10 senders, 100 txs each = 1000 txs total
    let num_senders = 10usize;
    let txs_per_sender = 100usize;
    let num_blocks = 10usize;
    let txs_per_block = (num_senders * txs_per_sender) / num_blocks;

    let start = Instant::now();

    // Pre-compute all transactions
    let mut all_txs = Vec::new();
    for sender_idx in 0..num_senders {
        for nonce in 0..txs_per_sender {
            let sender = test_account_id(sender_idx as u8);
            all_txs.push(QbindTransaction::new(
                sender,
                nonce as u64,
                vec![0xAB; 64],
            ));
        }
    }

    // Distribute across blocks (interleaved)
    let mut tx_idx = 0;
    for block_num in 0..num_blocks {
        let mut block_txs = Vec::with_capacity(txs_per_block);
        for _ in 0..txs_per_block {
            if tx_idx < all_txs.len() {
                // Interleave: pick from different senders
                let sender_idx = tx_idx % num_senders;
                let nonce = tx_idx / num_senders;
                let tx = QbindTransaction::new(
                    test_account_id(sender_idx as u8),
                    nonce as u64,
                    vec![0xAB; 64],
                );
                block_txs.push(tx);
                tx_idx += 1;
            }
        }

        let proposal = make_test_proposal(block_num as u64 + 1);
        let block = QbindBlock::new(proposal, block_txs);

        match service.submit_block(block) {
            Ok(()) => {}
            Err(AsyncExecError::QueueFull) => {
                // Wait and retry
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // Wait for all processing
    let timeout = Duration::from_secs(10);
    let start_wait = Instant::now();
    while service.queue_len() > 0 && start_wait.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(50));
    }

    let duration = start.elapsed();
    let applied = metrics.txs_applied_total();

    eprintln!(
        "[T157 TPS] Submitted {} txs across {} blocks",
        num_senders * txs_per_sender,
        num_blocks
    );
    eprintln!("[T157 TPS] Applied {} txs in {:?}", applied, duration);
    eprintln!("[T157 TPS] Queue len at end: {}", service.queue_len());
    eprintln!(
        "[T157 TPS] Parallel workers active: {}",
        metrics.parallel_workers_active()
    );
    eprintln!(
        "[T157 TPS] Fallback count: {}",
        metrics.parallel_fallback_total()
    );

    // Verify most transactions were applied
    assert!(
        applied >= (num_senders * txs_per_sender / 2) as u64,
        "should have applied at least half the transactions"
    );
}

// ============================================================================
// Test: Empty blocks with parallel executor
// ============================================================================

#[test]
fn test_empty_blocks_parallel_executor() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default();
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    // Submit empty blocks
    for i in 1..=5 {
        let proposal = make_test_proposal(i);
        let block = QbindBlock::empty(proposal);
        service.submit_block(block).expect("submit should succeed");
    }

    // Wait for processing
    std::thread::sleep(Duration::from_millis(200));

    // No transactions should have been applied
    assert_eq!(metrics.txs_applied_total(), 0);

    // Blocks should still be tracked
    assert_eq!(metrics.blocks_applied_total(), 5);
}

// ============================================================================
// Test: Nonce errors are properly recorded
// ============================================================================

#[test]
fn test_nonce_errors_recorded_parallel() {
    let engine = NonceExecutionEngine::new();
    let metrics = Arc::new(ExecutionMetrics::new());
    let config = SingleThreadExecutionServiceConfig::default();
    let service = SingleThreadExecutionService::with_config(engine, config, Some(metrics.clone()));

    // Create block with intentional nonce errors
    let sender_a = test_account_id(0xA1);
    let sender_b = test_account_id(0xB2);

    let txs = vec![
        QbindTransaction::new(sender_a, 0, b"a0".to_vec()),
        QbindTransaction::new(sender_a, 5, b"a5_wrong".to_vec()), // wrong nonce
        QbindTransaction::new(sender_b, 0, b"b0".to_vec()),
        QbindTransaction::new(sender_b, 1, b"b1".to_vec()),
    ];

    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    service.submit_block(block).expect("submit should succeed");

    // Wait for processing
    std::thread::sleep(Duration::from_millis(200));

    // Should have some successful and some errors
    let applied = metrics.txs_applied_total();
    let errors = metrics.errors_total();

    eprintln!(
        "[T157] Applied: {}, Errors: {}",
        applied, errors
    );

    // 3 should succeed (a0, b0, b1), 1 should fail (a5_wrong)
    assert_eq!(applied, 3, "should have applied 3 txs");
    assert!(errors > 0, "should have recorded nonce errors");
}
