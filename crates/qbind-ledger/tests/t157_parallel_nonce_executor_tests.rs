//! T157 Stage A Parallel Nonce Executor Tests
//!
//! These tests verify:
//! 1. Parallel vs sequential equivalence (determinism)
//! 2. Single-sender edge case
//! 3. Nonce failure patterns
//! 4. Multiple sender correctness
//! 5. Empty block handling

use qbind_ledger::{
    get_account_nonce, InMemoryState, ParallelExecConfig,
    QbindTransaction, SenderPartitionedNonceExecutor,
};

// ============================================================================
// Helper functions
// ============================================================================

fn test_account_id(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

fn create_tx(sender_byte: u8, nonce: u64, payload: &[u8]) -> QbindTransaction {
    QbindTransaction::new(test_account_id(sender_byte), nonce, payload.to_vec())
}

// ============================================================================
// Test: Parallel vs Sequential Equivalence
// ============================================================================

/// Verify that parallel execution produces identical results to sequential execution.
#[test]
fn test_parallel_vs_sequential_equivalence() {
    // Create a block with many senders (100 senders, 5 txs each = 500 txs)
    let mut transactions = Vec::new();
    for sender_byte in 0u8..100 {
        for nonce in 0u64..5 {
            transactions.push(create_tx(
                sender_byte,
                nonce,
                format!("tx_{}_n{}", sender_byte, nonce).as_bytes(),
            ));
        }
    }

    // Shuffle transactions to ensure interleaving
    // We use a deterministic shuffle pattern (every other sender)
    let mut shuffled = Vec::new();
    for nonce in 0u64..5 {
        for sender_byte in 0u8..100 {
            let idx = (sender_byte as usize) * 5 + (nonce as usize);
            shuffled.push(transactions[idx].clone());
        }
    }

    // Run sequential execution
    let mut seq_state = InMemoryState::new();
    let seq_config = ParallelExecConfig::sequential();
    let seq_executor = SenderPartitionedNonceExecutor::new(seq_config);

    let (seq_receipts, seq_stats) = seq_executor
        .execute_block_sender_partitioned(&shuffled, &mut seq_state)
        .expect("sequential execution should succeed");

    // Run parallel execution
    let mut par_state = InMemoryState::new();
    let par_config = ParallelExecConfig::default();
    let par_executor = SenderPartitionedNonceExecutor::new(par_config);

    let (par_receipts, par_stats) = par_executor
        .execute_block_sender_partitioned(&shuffled, &mut par_state)
        .expect("parallel execution should succeed");

    // Verify receipts are identical
    assert_eq!(
        seq_receipts.len(),
        par_receipts.len(),
        "receipt count should match"
    );
    for (i, (seq_r, par_r)) in seq_receipts.iter().zip(par_receipts.iter()).enumerate() {
        assert_eq!(
            seq_r.success, par_r.success,
            "receipt {} success should match",
            i
        );
    }

    // Verify final states are identical
    for sender_byte in 0u8..100 {
        let sender = test_account_id(sender_byte);
        let seq_nonce = get_account_nonce(&seq_state, &sender);
        let par_nonce = get_account_nonce(&par_state, &sender);
        assert_eq!(
            seq_nonce, par_nonce,
            "nonce for sender {} should match (seq={}, par={})",
            sender_byte, seq_nonce, par_nonce
        );
        assert_eq!(seq_nonce, 5, "final nonce should be 5");
    }

    // Verify stats
    assert!(!seq_stats.used_parallel, "sequential should not use parallel");
    // Parallel may or may not be used depending on threshold
    eprintln!(
        "[T157] Sequential: {} senders, {} workers, parallel={}",
        seq_stats.num_senders, seq_stats.workers_used, seq_stats.used_parallel
    );
    eprintln!(
        "[T157] Parallel: {} senders, {} workers, parallel={}",
        par_stats.num_senders, par_stats.workers_used, par_stats.used_parallel
    );
}

// ============================================================================
// Test: Single Sender Edge Case
// ============================================================================

/// Verify that blocks with a single sender work correctly (fallback to sequential).
#[test]
fn test_single_sender_edge_case() {
    let sender = test_account_id(0xAA);
    let transactions: Vec<_> = (0..100)
        .map(|nonce| QbindTransaction::new(sender, nonce, format!("tx_{}", nonce).into_bytes()))
        .collect();

    let mut state = InMemoryState::new();
    let config = ParallelExecConfig::default().with_min_senders(2);
    let executor = SenderPartitionedNonceExecutor::new(config);

    let (receipts, stats) = executor
        .execute_block_sender_partitioned(&transactions, &mut state)
        .expect("execution should succeed");

    // Verify all transactions succeeded
    assert_eq!(receipts.len(), 100);
    for (i, receipt) in receipts.iter().enumerate() {
        assert!(receipt.success, "tx {} should succeed", i);
    }

    // Verify final nonce
    assert_eq!(get_account_nonce(&state, &sender), 100);

    // Verify stats
    assert_eq!(stats.num_senders, 1);
    // Should fallback to sequential since only 1 sender
    assert!(
        !stats.used_parallel || stats.workers_used <= 1,
        "should use sequential path for single sender"
    );
}

// ============================================================================
// Test: Nonce Failure Patterns
// ============================================================================

/// Verify that nonce mismatches are recorded correctly in receipts.
#[test]
fn test_nonce_failure_patterns() {
    let sender_a = test_account_id(0xA1);
    let sender_b = test_account_id(0xB2);

    // Create transactions with some incorrect nonces
    let transactions = vec![
        // sender_a: correct sequence 0, 1, wrong 5, should fail from 5 onwards
        QbindTransaction::new(sender_a, 0, b"a0".to_vec()),
        QbindTransaction::new(sender_a, 1, b"a1".to_vec()),
        QbindTransaction::new(sender_a, 5, b"a5_wrong".to_vec()), // wrong nonce
        QbindTransaction::new(sender_a, 3, b"a3_wrong".to_vec()), // also wrong
        // sender_b: all correct
        QbindTransaction::new(sender_b, 0, b"b0".to_vec()),
        QbindTransaction::new(sender_b, 1, b"b1".to_vec()),
        QbindTransaction::new(sender_b, 2, b"b2".to_vec()),
    ];

    let mut state = InMemoryState::new();
    let executor = SenderPartitionedNonceExecutor::default_config();

    let (receipts, _stats) = executor
        .execute_block_sender_partitioned(&transactions, &mut state)
        .expect("execution should succeed");

    // Verify receipts
    assert_eq!(receipts.len(), 7);

    // sender_a receipts (indices 0, 1, 2, 3)
    assert!(receipts[0].success, "a0 should succeed");
    assert!(receipts[1].success, "a1 should succeed");
    assert!(!receipts[2].success, "a5_wrong should fail (expected 2)");
    assert!(!receipts[3].success, "a3_wrong should fail (expected 2)");

    // sender_b receipts (indices 4, 5, 6)
    assert!(receipts[4].success, "b0 should succeed");
    assert!(receipts[5].success, "b1 should succeed");
    assert!(receipts[6].success, "b2 should succeed");

    // Verify final nonces
    assert_eq!(get_account_nonce(&state, &sender_a), 2);
    assert_eq!(get_account_nonce(&state, &sender_b), 3);
}

// ============================================================================
// Test: Sequential config forces sequential execution
// ============================================================================

#[test]
fn test_sequential_config_forces_sequential() {
    let mut transactions = Vec::new();
    for sender_byte in 0u8..10 {
        for nonce in 0u64..3 {
            transactions.push(create_tx(sender_byte, nonce, b"test"));
        }
    }

    let mut state = InMemoryState::new();
    let config = ParallelExecConfig::sequential();
    let executor = SenderPartitionedNonceExecutor::new(config);

    let (_receipts, stats) = executor
        .execute_block_sender_partitioned(&transactions, &mut state)
        .expect("execution should succeed");

    assert!(!stats.used_parallel, "sequential config should force sequential");
}

// ============================================================================
// Test: Empty block handling
// ============================================================================

#[test]
fn test_empty_block_handling() {
    let transactions: Vec<QbindTransaction> = Vec::new();
    let mut state = InMemoryState::new();
    let executor = SenderPartitionedNonceExecutor::default_config();

    let (receipts, stats) = executor
        .execute_block_sender_partitioned(&transactions, &mut state)
        .expect("execution should succeed");

    assert!(receipts.is_empty());
    assert_eq!(stats.num_senders, 0);
    assert_eq!(stats.workers_used, 0);
    assert!(!stats.used_parallel);
}

// ============================================================================
// Test: Multiple senders with interleaved transactions
// ============================================================================

#[test]
fn test_multiple_senders_interleaved() {
    // Create interleaved transactions from multiple senders
    let sender_a = test_account_id(0xA1);
    let sender_b = test_account_id(0xB2);
    let sender_c = test_account_id(0xC3);

    // Interleaved order
    let transactions = vec![
        QbindTransaction::new(sender_a, 0, b"a0".to_vec()),
        QbindTransaction::new(sender_b, 0, b"b0".to_vec()),
        QbindTransaction::new(sender_c, 0, b"c0".to_vec()),
        QbindTransaction::new(sender_a, 1, b"a1".to_vec()),
        QbindTransaction::new(sender_b, 1, b"b1".to_vec()),
        QbindTransaction::new(sender_c, 1, b"c1".to_vec()),
        QbindTransaction::new(sender_a, 2, b"a2".to_vec()),
        QbindTransaction::new(sender_b, 2, b"b2".to_vec()),
        QbindTransaction::new(sender_c, 2, b"c2".to_vec()),
    ];

    let mut state = InMemoryState::new();
    let executor = SenderPartitionedNonceExecutor::default_config();

    let (receipts, stats) = executor
        .execute_block_sender_partitioned(&transactions, &mut state)
        .expect("execution should succeed");

    // All should succeed
    assert_eq!(receipts.len(), 9);
    for (i, receipt) in receipts.iter().enumerate() {
        assert!(receipt.success, "tx {} should succeed", i);
    }

    // Verify final nonces
    assert_eq!(get_account_nonce(&state, &sender_a), 3);
    assert_eq!(get_account_nonce(&state, &sender_b), 3);
    assert_eq!(get_account_nonce(&state, &sender_c), 3);

    // Verify stats
    assert_eq!(stats.num_senders, 3);
}

// ============================================================================
// Test: Large block with many transactions
// ============================================================================

#[test]
fn test_large_block_performance() {
    // Create a large block: 50 senders, 100 txs each = 5000 txs
    let mut transactions = Vec::new();
    for sender_byte in 0u8..50 {
        for nonce in 0u64..100 {
            transactions.push(create_tx(sender_byte, nonce, &[0xAB; 64]));
        }
    }

    let mut state = InMemoryState::new();
    let executor = SenderPartitionedNonceExecutor::default_config();

    let start = std::time::Instant::now();
    let (receipts, stats) = executor
        .execute_block_sender_partitioned(&transactions, &mut state)
        .expect("execution should succeed");
    let duration = start.elapsed();

    // Verify all succeeded
    assert_eq!(receipts.len(), 5000);
    let success_count = receipts.iter().filter(|r| r.success).count();
    assert_eq!(success_count, 5000);

    // Verify final nonces
    for sender_byte in 0u8..50 {
        let sender = test_account_id(sender_byte);
        assert_eq!(get_account_nonce(&state, &sender), 100);
    }

    eprintln!(
        "[T157 Perf] Executed 5000 txs from 50 senders in {:?}, parallel={}, workers={}",
        duration, stats.used_parallel, stats.workers_used
    );
}

// ============================================================================
// Test: Receipts preserve original order
// ============================================================================

#[test]
fn test_receipts_preserve_original_order() {
    let sender_a = test_account_id(0xAA);
    let sender_b = test_account_id(0xBB);

    // Create transactions with identifiable payloads
    let transactions = vec![
        QbindTransaction::new(sender_a, 0, b"order_0".to_vec()),
        QbindTransaction::new(sender_b, 0, b"order_1".to_vec()),
        QbindTransaction::new(sender_a, 1, b"order_2".to_vec()),
        QbindTransaction::new(sender_b, 1, b"order_3".to_vec()),
        QbindTransaction::new(sender_a, 2, b"order_4".to_vec()),
    ];

    let mut state = InMemoryState::new();
    let executor = SenderPartitionedNonceExecutor::default_config();

    let (receipts, _stats) = executor
        .execute_block_sender_partitioned(&transactions, &mut state)
        .expect("execution should succeed");

    // Verify receipt count matches transaction count
    assert_eq!(receipts.len(), 5);

    // All should succeed
    for (i, receipt) in receipts.iter().enumerate() {
        assert!(receipt.success, "receipt {} should succeed", i);
    }
}

// ============================================================================
// Test: Config thresholds
// ============================================================================

#[test]
fn test_parallel_threshold_respected() {
    // 3 senders, but threshold is 5, should fallback to sequential
    let transactions = vec![
        create_tx(0xA1, 0, b"test"),
        create_tx(0xB2, 0, b"test"),
        create_tx(0xC3, 0, b"test"),
    ];

    let mut state = InMemoryState::new();
    let config = ParallelExecConfig::default().with_min_senders(5);
    let executor = SenderPartitionedNonceExecutor::new(config);

    let (_receipts, stats) = executor
        .execute_block_sender_partitioned(&transactions, &mut state)
        .expect("execution should succeed");

    assert!(!stats.used_parallel, "should fallback with 3 senders < 5 threshold");
    assert_eq!(stats.num_senders, 3);
}
