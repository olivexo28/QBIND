//! T171 Stage B Parallel Execution: Integration Tests
//!
//! These tests verify that parallel execution produces the same results
//! as sequential execution, ensuring correctness of the Stage B scheduler.
//!
//! Tests include:
//! 1. Parallel execution matches sequential for simple blocks
//! 2. Parallel execution matches sequential with failures
//! 3. Schedule determinism across multiple runs
//! 4. Sequential block with all conflicts produces linear schedule

use qbind_ledger::{
    build_conflict_graph, build_parallel_schedule, AccountStateView, InMemoryAccountState,
    QbindTransaction, TransferPayload, TxIndex, VmV0ExecutionEngine, VmV0TxResult,
};

// ============================================================================
// Helper functions
// ============================================================================

fn test_account_id(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

fn make_transfer_tx(
    sender_byte: u8,
    recipient_byte: u8,
    nonce: u64,
    amount: u128,
) -> QbindTransaction {
    let sender = test_account_id(sender_byte);
    let recipient = test_account_id(recipient_byte);
    let payload = TransferPayload::new(recipient, amount).encode();
    QbindTransaction::new(sender, nonce, payload)
}

/// Execute a block sequentially and return results + final state.
fn execute_sequential(
    transactions: &[QbindTransaction],
    initial_state: &InMemoryAccountState,
) -> (Vec<VmV0TxResult>, InMemoryAccountState) {
    let mut state = initial_state.clone();
    let engine = VmV0ExecutionEngine::new();
    let results = engine.execute_block(&mut state, transactions);
    (results, state)
}

/// Execute a block using the Stage B parallel schedule.
/// Uses sequential execution but follows the schedule ordering to verify correctness.
fn execute_with_schedule(
    transactions: &[QbindTransaction],
    initial_state: &InMemoryAccountState,
) -> (Vec<VmV0TxResult>, InMemoryAccountState) {
    let mut state = initial_state.clone();
    let engine = VmV0ExecutionEngine::new();

    // Build schedule
    let graph = build_conflict_graph(transactions);
    let schedule = build_parallel_schedule(&graph);

    // Execute according to schedule (level by level)
    let mut results = vec![None; transactions.len()];

    for level in &schedule.levels {
        // Within a level, execute in any order (they're independent)
        // We execute in sorted order for determinism
        for &tx_idx in level {
            let tx = &transactions[tx_idx.0];
            let result = engine.execute_tx(&mut state, tx);
            results[tx_idx.0] = Some(result);
        }
    }

    // Convert to final results
    let results: Vec<VmV0TxResult> = results
        .into_iter()
        .map(|opt| opt.expect("all txs should be executed"))
        .collect();

    (results, state)
}

/// Compare two states for equality.
fn states_equal(a: &InMemoryAccountState, b: &InMemoryAccountState) -> bool {
    // Get all accounts from both
    let accounts_a: std::collections::HashSet<_> = a.iter().map(|(acc, _)| *acc).collect();
    let accounts_b: std::collections::HashSet<_> = b.iter().map(|(acc, _)| *acc).collect();

    if accounts_a != accounts_b {
        return false;
    }

    for acc in accounts_a {
        if a.get_account_state(&acc) != b.get_account_state(&acc) {
            return false;
        }
    }

    true
}

/// Compare two result vectors for equality (success/failure only).
fn results_equal(a: &[VmV0TxResult], b: &[VmV0TxResult]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (ra, rb) in a.iter().zip(b.iter()) {
        if ra.success != rb.success {
            return false;
        }
    }
    true
}

// ============================================================================
// Test: Parallel execution matches sequential for simple block
// ============================================================================

/// Small block with a mix of independent and conflicting txs.
/// Construct an initial state with balances.
/// Execute sequential vs parallel (via schedule) and assert final state equality.
#[test]
fn parallel_execution_matches_sequential_for_simple_block() {
    // Initial state: A, B, C each have 1000 tokens
    let mut initial_state = InMemoryAccountState::new();
    initial_state.init_account(&test_account_id(0xAA), 1000);
    initial_state.init_account(&test_account_id(0xBB), 1000);
    initial_state.init_account(&test_account_id(0xCC), 1000);

    // Block with mixed dependencies:
    // tx0: A -> D (100)
    // tx1: B -> E (200)
    // tx2: C -> F (300)
    // tx3: A -> G (100) -- depends on tx0
    // tx4: B -> H (200) -- depends on tx1
    let transactions = vec![
        make_transfer_tx(0xAA, 0xDD, 0, 100),
        make_transfer_tx(0xBB, 0xEE, 0, 200),
        make_transfer_tx(0xCC, 0xFF, 0, 300),
        make_transfer_tx(0xAA, 0x11, 1, 100),
        make_transfer_tx(0xBB, 0x22, 1, 200),
    ];

    // Execute sequentially
    let (seq_results, seq_state) = execute_sequential(&transactions, &initial_state);

    // Execute using schedule
    let (sched_results, sched_state) = execute_with_schedule(&transactions, &initial_state);

    // Verify all transactions succeeded
    for (i, result) in seq_results.iter().enumerate() {
        assert!(result.success, "sequential tx {} should succeed", i);
    }
    for (i, result) in sched_results.iter().enumerate() {
        assert!(result.success, "scheduled tx {} should succeed", i);
    }

    // Verify results match
    assert!(
        results_equal(&seq_results, &sched_results),
        "results should match"
    );

    // Verify final states match
    assert!(
        states_equal(&seq_state, &sched_state),
        "final states should match"
    );

    // Verify expected final balances
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xAA)).balance,
        800
    ); // 1000 - 100 - 100
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xBB)).balance,
        600
    ); // 1000 - 200 - 200
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xCC)).balance,
        700
    ); // 1000 - 300
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xDD)).balance,
        100
    );
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xEE)).balance,
        200
    );
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xFF)).balance,
        300
    );
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0x11)).balance,
        100
    );
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0x22)).balance,
        200
    );
}

// ============================================================================
// Test: Parallel execution matches sequential with failures
// ============================================================================

/// Include txs that fail due to insufficient balance or nonce mismatch.
/// Ensure both execution modes fail the same txs and keep state identical.
#[test]
fn parallel_execution_matches_sequential_with_failures() {
    // Initial state: A has 100, B has 500
    let mut initial_state = InMemoryAccountState::new();
    initial_state.init_account(&test_account_id(0xAA), 100);
    initial_state.init_account(&test_account_id(0xBB), 500);

    // Block with some failing txs:
    // tx0: A -> C (50) -- should succeed
    // tx1: A -> D (100) -- should FAIL (insufficient balance: 50 < 100)
    // tx2: B -> E (200) -- should succeed
    // tx3: B -> F (200) -- should succeed
    // tx4: B -> G (200) -- should FAIL (insufficient balance after tx2+tx3: 100 < 200)
    // tx5: A -> H (10) -- nonce 2, should FAIL (expected nonce 1)
    let transactions = vec![
        make_transfer_tx(0xAA, 0xCC, 0, 50),  // tx0
        make_transfer_tx(0xAA, 0xDD, 1, 100), // tx1 - insufficient balance
        make_transfer_tx(0xBB, 0xEE, 0, 200), // tx2
        make_transfer_tx(0xBB, 0xFF, 1, 200), // tx3
        make_transfer_tx(0xBB, 0x11, 2, 200), // tx4 - insufficient balance
        make_transfer_tx(0xAA, 0x22, 2, 10),  // tx5 - nonce mismatch (expected 1, got 2)
    ];

    // Execute sequentially
    let (seq_results, seq_state) = execute_sequential(&transactions, &initial_state);

    // Execute using schedule
    let (sched_results, sched_state) = execute_with_schedule(&transactions, &initial_state);

    // Expected results:
    // tx0: success
    // tx1: fail (insufficient balance)
    // tx2: success
    // tx3: success
    // tx4: fail (insufficient balance)
    // tx5: fail (nonce mismatch - expected 1 after tx0, got 2)
    let expected_success = [true, false, true, true, false, false];

    for (i, expected) in expected_success.iter().enumerate() {
        assert_eq!(
            seq_results[i].success, *expected,
            "sequential tx {} success should be {}",
            i, expected
        );
        assert_eq!(
            sched_results[i].success, *expected,
            "scheduled tx {} success should be {}",
            i, expected
        );
    }

    // Verify results match
    assert!(
        results_equal(&seq_results, &sched_results),
        "results should match"
    );

    // Verify final states match
    assert!(
        states_equal(&seq_state, &sched_state),
        "final states should match"
    );

    // Verify expected final balances
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xAA)).balance,
        50
    ); // 100 - 50
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xBB)).balance,
        100
    ); // 500 - 200 - 200
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xCC)).balance,
        50
    );
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xEE)).balance,
        200
    );
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xFF)).balance,
        200
    );

    // Verify nonces
    assert_eq!(seq_state.get_account_state(&test_account_id(0xAA)).nonce, 1); // Only tx0 succeeded
    assert_eq!(seq_state.get_account_state(&test_account_id(0xBB)).nonce, 2); // tx2 and tx3 succeeded
}

// ============================================================================
// Test: Schedule is deterministic
// ============================================================================

/// Run schedule construction multiple times on the same block.
/// Ensure same ParallelSchedule every time.
#[test]
fn schedule_is_deterministic() {
    let transactions = vec![
        make_transfer_tx(0x01, 0x02, 0, 10),
        make_transfer_tx(0x03, 0x04, 0, 10),
        make_transfer_tx(0x01, 0x05, 1, 10),
        make_transfer_tx(0x03, 0x06, 1, 10),
        make_transfer_tx(0x07, 0x08, 0, 10),
        make_transfer_tx(0x09, 0x0A, 0, 10),
        make_transfer_tx(0x01, 0x0B, 2, 10),
        make_transfer_tx(0x0C, 0x0D, 0, 10),
    ];

    // Run multiple times
    let mut schedules = Vec::new();
    for _ in 0..20 {
        let graph = build_conflict_graph(&transactions);
        let schedule = build_parallel_schedule(&graph);
        schedules.push(schedule);
    }

    // All schedules should be identical
    let first = &schedules[0];
    for (i, schedule) in schedules.iter().enumerate().skip(1) {
        assert_eq!(
            first.levels.len(),
            schedule.levels.len(),
            "schedule {} has different level count",
            i
        );
        for (level_idx, (l1, l2)) in first.levels.iter().zip(schedule.levels.iter()).enumerate() {
            assert_eq!(l1, l2, "schedule {} level {} differs", i, level_idx);
        }
    }
}

// ============================================================================
// Test: Sequential block with all conflicts
// ============================================================================

/// Block where every tx touches a common hot account.
/// Ensure each tx ends up in its own level.
#[test]
fn sequential_block_with_all_conflicts_produces_linear_schedule() {
    // All transactions touch the "hot" account 0xFF
    let transactions = vec![
        make_transfer_tx(0xFF, 0x01, 0, 10), // tx0
        make_transfer_tx(0xFF, 0x02, 1, 10), // tx1 (depends on tx0)
        make_transfer_tx(0xFF, 0x03, 2, 10), // tx2 (depends on tx0, tx1)
        make_transfer_tx(0xFF, 0x04, 3, 10), // tx3 (depends on tx0, tx1, tx2)
        make_transfer_tx(0xFF, 0x05, 4, 10), // tx4 (depends on all)
    ];

    let graph = build_conflict_graph(&transactions);
    let schedule = build_parallel_schedule(&graph);

    // Should be fully sequential
    assert_eq!(schedule.level_count(), 5, "should have 5 levels");

    for (level_idx, level) in schedule.levels.iter().enumerate() {
        assert_eq!(
            level.len(),
            1,
            "level {} should have exactly 1 tx",
            level_idx
        );
        assert_eq!(
            level[0],
            TxIndex(level_idx),
            "level {} should contain tx{}",
            level_idx,
            level_idx
        );
    }
}

// ============================================================================
// Test: Large block with many independent transactions
// ============================================================================

/// Test with a large number of independent transactions to verify scalability.
#[test]
fn large_block_with_independent_transactions() {
    // Create 100 independent transactions (unique sender/recipient pairs)
    let mut initial_state = InMemoryAccountState::new();
    let mut transactions = Vec::new();

    for i in 0u8..100 {
        let sender_byte = i * 2;
        let recipient_byte = i * 2 + 1;
        initial_state.init_account(&test_account_id(sender_byte), 1000);
        transactions.push(make_transfer_tx(sender_byte, recipient_byte, 0, 100));
    }

    // Build schedule
    let graph = build_conflict_graph(&transactions);
    let schedule = build_parallel_schedule(&graph);

    // All 100 txs should be in a single level (fully parallel)
    assert_eq!(schedule.level_count(), 1);
    assert_eq!(schedule.levels[0].len(), 100);

    // Execute both ways
    let (seq_results, seq_state) = execute_sequential(&transactions, &initial_state);
    let (sched_results, sched_state) = execute_with_schedule(&transactions, &initial_state);

    // All should succeed
    for (i, result) in seq_results.iter().enumerate() {
        assert!(result.success, "tx {} should succeed", i);
    }

    // Results and states should match
    assert!(results_equal(&seq_results, &sched_results));
    assert!(states_equal(&seq_state, &sched_state));
}

// ============================================================================
// Test: Multiple chains with interleaved transactions
// ============================================================================

/// Test with multiple sender chains interleaved in the block.
#[test]
fn multiple_sender_chains_interleaved() {
    // Create 3 senders, each with 4 sequential transactions, interleaved
    let mut initial_state = InMemoryAccountState::new();
    initial_state.init_account(&test_account_id(0xAA), 1000);
    initial_state.init_account(&test_account_id(0xBB), 1000);
    initial_state.init_account(&test_account_id(0xCC), 1000);

    // Interleaved order
    let transactions = vec![
        make_transfer_tx(0xAA, 0x01, 0, 10), // tx0: A[0]
        make_transfer_tx(0xBB, 0x02, 0, 10), // tx1: B[0]
        make_transfer_tx(0xCC, 0x03, 0, 10), // tx2: C[0]
        make_transfer_tx(0xAA, 0x04, 1, 10), // tx3: A[1]
        make_transfer_tx(0xBB, 0x05, 1, 10), // tx4: B[1]
        make_transfer_tx(0xCC, 0x06, 1, 10), // tx5: C[1]
        make_transfer_tx(0xAA, 0x07, 2, 10), // tx6: A[2]
        make_transfer_tx(0xBB, 0x08, 2, 10), // tx7: B[2]
        make_transfer_tx(0xCC, 0x09, 2, 10), // tx8: C[2]
        make_transfer_tx(0xAA, 0x0A, 3, 10), // tx9: A[3]
        make_transfer_tx(0xBB, 0x0B, 3, 10), // tx10: B[3]
        make_transfer_tx(0xCC, 0x0C, 3, 10), // tx11: C[3]
    ];

    let graph = build_conflict_graph(&transactions);
    let schedule = build_parallel_schedule(&graph);

    // Expected: 4 levels, 3 txs each (one from each sender per level)
    assert_eq!(schedule.level_count(), 4);
    for (level_idx, level) in schedule.levels.iter().enumerate() {
        assert_eq!(level.len(), 3, "level {} should have 3 txs", level_idx);
    }

    // Execute both ways
    let (seq_results, seq_state) = execute_sequential(&transactions, &initial_state);
    let (sched_results, sched_state) = execute_with_schedule(&transactions, &initial_state);

    // All should succeed
    for (i, result) in seq_results.iter().enumerate() {
        assert!(result.success, "tx {} should succeed", i);
    }

    // Results and states should match
    assert!(results_equal(&seq_results, &sched_results));
    assert!(states_equal(&seq_state, &sched_state));

    // Verify final balances
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xAA)).balance,
        960
    ); // 1000 - 4*10
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xBB)).balance,
        960
    );
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xCC)).balance,
        960
    );
}

// ============================================================================
// Test: Shared recipient creates dependency
// ============================================================================

/// Test that transactions to a shared recipient create proper dependencies.
#[test]
fn shared_recipient_creates_dependency() {
    let mut initial_state = InMemoryAccountState::new();
    initial_state.init_account(&test_account_id(0xAA), 1000);
    initial_state.init_account(&test_account_id(0xBB), 1000);

    // Two different senders sending to the same recipient
    let transactions = vec![
        make_transfer_tx(0xAA, 0xFF, 0, 100), // tx0: A -> X
        make_transfer_tx(0xBB, 0xFF, 0, 200), // tx1: B -> X (depends on tx0 via recipient X)
    ];

    let graph = build_conflict_graph(&transactions);

    // tx1 should depend on tx0 (shared recipient)
    assert!(graph.has_dependency(TxIndex(0), TxIndex(1)));

    let schedule = build_parallel_schedule(&graph);

    // Should be sequential (2 levels)
    assert_eq!(schedule.level_count(), 2);

    // Execute both ways
    let (seq_results, seq_state) = execute_sequential(&transactions, &initial_state);
    let (sched_results, sched_state) = execute_with_schedule(&transactions, &initial_state);

    assert!(results_equal(&seq_results, &sched_results));
    assert!(states_equal(&seq_state, &sched_state));

    // Recipient should have 300
    assert_eq!(
        seq_state.get_account_state(&test_account_id(0xFF)).balance,
        300
    );
}

// ============================================================================
// Test: Malformed transactions don't break scheduler
// ============================================================================

/// Test that malformed transactions are handled gracefully.
#[test]
fn malformed_transactions_handled() {
    let mut initial_state = InMemoryAccountState::new();
    initial_state.init_account(&test_account_id(0xAA), 1000);
    initial_state.init_account(&test_account_id(0xBB), 1000);

    // Mix of valid and malformed transactions
    let transactions = vec![
        make_transfer_tx(0xAA, 0xCC, 0, 100), // tx0: valid
        QbindTransaction::new(test_account_id(0xBB), 0, vec![0xDE, 0xAD]), // tx1: malformed
        make_transfer_tx(0xAA, 0xDD, 1, 100), // tx2: valid (depends on tx0)
    ];

    // Build schedule (should not panic)
    let graph = build_conflict_graph(&transactions);
    let _schedule = build_parallel_schedule(&graph);

    // tx2 depends on tx0
    assert!(graph.has_dependency(TxIndex(0), TxIndex(2)));

    // Execute both ways
    let (seq_results, seq_state) = execute_sequential(&transactions, &initial_state);
    let (sched_results, sched_state) = execute_with_schedule(&transactions, &initial_state);

    // tx0 succeeds, tx1 fails (malformed), tx2 succeeds
    assert!(seq_results[0].success);
    assert!(!seq_results[1].success);
    assert!(seq_results[2].success);

    assert!(results_equal(&seq_results, &sched_results));
    assert!(states_equal(&seq_state, &sched_state));
}
