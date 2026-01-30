//! T171 Stage B Parallel Execution: Conflict Graph Unit Tests
//!
//! These tests verify:
//! 1. Conflict graph construction with no conflicts (disjoint accounts)
//! 2. Conflict graph with sequential sender nonce chain
//! 3. Conflict graph with mixed dependencies
//! 4. Schedule determinism

use qbind_ledger::{
    build_conflict_graph, build_parallel_schedule, extract_read_write_set, QbindTransaction,
    TransferPayload, TxIndex,
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

// ============================================================================
// Test: No conflicts produces single-level schedule (all parallel)
// ============================================================================

/// Block of txs touching disjoint sender/recipient pairs.
/// Graph should have no dependencies.
/// Schedule: all txs can be in a single level.
#[test]
fn conflict_graph_no_conflicts_produces_single_dependency_chain() {
    // Create 5 transactions with completely disjoint accounts
    // Each tx has unique sender and recipient
    let transactions = vec![
        make_transfer_tx(0x01, 0x11, 0, 10), // tx0: 0x01 -> 0x11
        make_transfer_tx(0x02, 0x12, 0, 10), // tx1: 0x02 -> 0x12
        make_transfer_tx(0x03, 0x13, 0, 10), // tx2: 0x03 -> 0x13
        make_transfer_tx(0x04, 0x14, 0, 10), // tx3: 0x04 -> 0x14
        make_transfer_tx(0x05, 0x15, 0, 10), // tx4: 0x05 -> 0x15
    ];

    // Build conflict graph
    let graph = build_conflict_graph(&transactions);

    // Verify no dependencies
    assert_eq!(graph.tx_count, 5);
    for i in 0..5 {
        assert_eq!(
            graph.dependency_count(TxIndex(i)),
            0,
            "tx {} should have no dependencies",
            i
        );
    }

    // Build schedule
    let schedule = build_parallel_schedule(&graph);

    // All txs should be in a single level (fully parallel)
    assert_eq!(schedule.level_count(), 1, "should have single level");
    assert_eq!(schedule.tx_count(), 5, "should have 5 txs");
    assert!(schedule.is_fully_parallel(), "should be fully parallel");

    // Verify all tx indices are present and sorted
    let level = &schedule.levels[0];
    assert_eq!(level.len(), 5);
    for (i, tx) in level.iter().enumerate() {
        assert_eq!(tx.0, i, "tx indices should be sorted");
    }
}

// ============================================================================
// Test: Sequential sender nonce chain produces linear schedule
// ============================================================================

/// Series of txs A→B, A→C, A→D, ... (same sender).
/// Each tx should depend on all earlier ones (or at least the last writer to A).
/// Schedule: linear (levels of size 1).
#[test]
fn conflict_graph_sequential_sender_nonce_chain() {
    // Create 5 transactions from the same sender to different recipients
    // All touch sender account A
    let transactions = vec![
        make_transfer_tx(0xAA, 0x01, 0, 10), // tx0: A -> 0x01
        make_transfer_tx(0xAA, 0x02, 1, 10), // tx1: A -> 0x02
        make_transfer_tx(0xAA, 0x03, 2, 10), // tx2: A -> 0x03
        make_transfer_tx(0xAA, 0x04, 3, 10), // tx3: A -> 0x04
        make_transfer_tx(0xAA, 0x05, 4, 10), // tx4: A -> 0x05
    ];

    // Build conflict graph
    let graph = build_conflict_graph(&transactions);

    // Verify dependency chain: each tx depends on all earlier txs (shared sender)
    assert_eq!(graph.tx_count, 5);

    // tx0 has no dependencies
    assert_eq!(graph.dependency_count(TxIndex(0)), 0);

    // tx1 depends on tx0
    assert!(graph.has_dependency(TxIndex(0), TxIndex(1)));
    assert_eq!(graph.dependency_count(TxIndex(1)), 1);

    // tx2 depends on tx0 and tx1
    assert!(graph.has_dependency(TxIndex(0), TxIndex(2)));
    assert!(graph.has_dependency(TxIndex(1), TxIndex(2)));
    assert_eq!(graph.dependency_count(TxIndex(2)), 2);

    // tx3 depends on tx0, tx1, tx2
    assert!(graph.has_dependency(TxIndex(0), TxIndex(3)));
    assert!(graph.has_dependency(TxIndex(1), TxIndex(3)));
    assert!(graph.has_dependency(TxIndex(2), TxIndex(3)));
    assert_eq!(graph.dependency_count(TxIndex(3)), 3);

    // tx4 depends on tx0, tx1, tx2, tx3
    for i in 0..4 {
        assert!(
            graph.has_dependency(TxIndex(i), TxIndex(4)),
            "tx4 should depend on tx{}",
            i
        );
    }
    assert_eq!(graph.dependency_count(TxIndex(4)), 4);

    // Build schedule
    let schedule = build_parallel_schedule(&graph);

    // Should be fully sequential (5 levels, 1 tx each)
    assert_eq!(schedule.level_count(), 5, "should have 5 levels");
    assert!(schedule.is_sequential(), "should be fully sequential");

    // Each level should have exactly one tx in order
    for (level_idx, level) in schedule.levels.iter().enumerate() {
        assert_eq!(level.len(), 1, "level {} should have 1 tx", level_idx);
        assert_eq!(
            level[0].0, level_idx,
            "level {} should contain tx{}",
            level_idx, level_idx
        );
    }
}

// ============================================================================
// Test: Mixed dependencies with partial parallelism
// ============================================================================

/// Construct a block where some txs share sender, some share recipient, some are independent.
/// Confirm dependencies and schedule levels match expectations.
#[test]
fn conflict_graph_mixed_dependencies() {
    // Transaction layout:
    // tx0: A -> B (sender=A, recipient=B)
    // tx1: C -> D (independent of tx0)
    // tx2: A -> E (depends on tx0 via sender A)
    // tx3: F -> B (depends on tx0 via recipient B)
    // tx4: C -> G (depends on tx1 via sender C)
    // tx5: H -> I (independent of all)
    let transactions = vec![
        make_transfer_tx(0xAA, 0xBB, 0, 10), // tx0: A -> B
        make_transfer_tx(0xCC, 0xDD, 0, 10), // tx1: C -> D
        make_transfer_tx(0xAA, 0xEE, 1, 10), // tx2: A -> E (depends on tx0)
        make_transfer_tx(0xFF, 0xBB, 0, 10), // tx3: F -> B (depends on tx0)
        make_transfer_tx(0xCC, 0x11, 1, 10), // tx4: C -> G (depends on tx1)
        make_transfer_tx(0x22, 0x33, 0, 10), // tx5: H -> I (independent)
    ];

    // Build conflict graph
    let graph = build_conflict_graph(&transactions);

    assert_eq!(graph.tx_count, 6);

    // tx0: no dependencies
    assert_eq!(graph.dependency_count(TxIndex(0)), 0);

    // tx1: no dependencies (independent of tx0)
    assert_eq!(graph.dependency_count(TxIndex(1)), 0);

    // tx2: depends on tx0 (shared sender A)
    assert!(graph.has_dependency(TxIndex(0), TxIndex(2)));
    assert_eq!(graph.dependency_count(TxIndex(2)), 1);

    // tx3: depends on tx0 (shared recipient B)
    assert!(graph.has_dependency(TxIndex(0), TxIndex(3)));
    assert_eq!(graph.dependency_count(TxIndex(3)), 1);

    // tx4: depends on tx1 (shared sender C)
    assert!(graph.has_dependency(TxIndex(1), TxIndex(4)));
    assert_eq!(graph.dependency_count(TxIndex(4)), 1);

    // tx5: no dependencies
    assert_eq!(graph.dependency_count(TxIndex(5)), 0);

    // Build schedule
    let schedule = build_parallel_schedule(&graph);

    // Expected schedule:
    // Level 0: tx0, tx1, tx5 (all have no dependencies)
    // Level 1: tx2, tx3, tx4 (each depends only on level 0 txs)
    assert_eq!(schedule.level_count(), 2, "should have 2 levels");

    // Level 0 should contain tx0, tx1, tx5 (sorted)
    let level0 = &schedule.levels[0];
    assert_eq!(level0.len(), 3, "level 0 should have 3 txs");
    assert!(level0.contains(&TxIndex(0)));
    assert!(level0.contains(&TxIndex(1)));
    assert!(level0.contains(&TxIndex(5)));
    // Should be sorted
    assert!(level0[0].0 < level0[1].0 && level0[1].0 < level0[2].0);

    // Level 1 should contain tx2, tx3, tx4 (sorted)
    let level1 = &schedule.levels[1];
    assert_eq!(level1.len(), 3, "level 1 should have 3 txs");
    assert!(level1.contains(&TxIndex(2)));
    assert!(level1.contains(&TxIndex(3)));
    assert!(level1.contains(&TxIndex(4)));
    // Should be sorted
    assert!(level1[0].0 < level1[1].0 && level1[1].0 < level1[2].0);
}

// ============================================================================
// Test: Schedule determinism
// ============================================================================

/// Run schedule construction multiple times on the same block.
/// Ensure same ParallelSchedule every time (by comparing levels).
#[test]
fn schedule_is_deterministic() {
    // Create a block with mixed dependencies
    let transactions = vec![
        make_transfer_tx(0x01, 0x02, 0, 10),
        make_transfer_tx(0x03, 0x04, 0, 10),
        make_transfer_tx(0x01, 0x05, 1, 10),
        make_transfer_tx(0x03, 0x06, 1, 10),
        make_transfer_tx(0x07, 0x08, 0, 10),
        make_transfer_tx(0x09, 0x0A, 0, 10),
        make_transfer_tx(0x01, 0x0B, 2, 10),
    ];

    // Run multiple times
    let mut schedules = Vec::new();
    for _ in 0..10 {
        let graph = build_conflict_graph(&transactions);
        let schedule = build_parallel_schedule(&graph);
        schedules.push(schedule);
    }

    // All schedules should be identical
    let first = &schedules[0];
    for (i, schedule) in schedules.iter().enumerate().skip(1) {
        assert_eq!(first, schedule, "schedule {} differs from schedule 0", i);
    }
}

// ============================================================================
// Test: Self-transfer conflict detection
// ============================================================================

/// Test that self-transfers are handled correctly (sender == recipient).
#[test]
fn conflict_graph_self_transfer() {
    let transactions = vec![
        make_transfer_tx(0xAA, 0xAA, 0, 10), // tx0: A -> A (self-transfer)
        make_transfer_tx(0xAA, 0xBB, 1, 10), // tx1: A -> B (depends on tx0)
        make_transfer_tx(0xBB, 0xCC, 0, 10), // tx2: B -> C (depends on tx1)
    ];

    let graph = build_conflict_graph(&transactions);

    // tx0: no dependencies
    assert_eq!(graph.dependency_count(TxIndex(0)), 0);

    // tx1: depends on tx0 (shared account A)
    assert!(graph.has_dependency(TxIndex(0), TxIndex(1)));

    // tx2: depends on tx1 (shared account B)
    assert!(graph.has_dependency(TxIndex(1), TxIndex(2)));
    // tx2 also depends on tx0 indirectly, but only direct deps are tracked
    // Actually, tx2 doesn't directly touch A, so no dependency on tx0
    assert!(!graph.has_dependency(TxIndex(0), TxIndex(2)));

    let schedule = build_parallel_schedule(&graph);
    assert_eq!(schedule.level_count(), 3);
}

// ============================================================================
// Test: Read/write set extraction
// ============================================================================

#[test]
fn test_read_write_set_extraction() {
    let tx = make_transfer_tx(0xAA, 0xBB, 0, 100);
    let rw = extract_read_write_set(&tx).expect("should decode");

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Both reads and writes should contain sender and recipient
    assert_eq!(rw.reads.len(), 2);
    assert_eq!(rw.writes.len(), 2);
    assert!(rw.reads.contains(&sender));
    assert!(rw.reads.contains(&recipient));
    assert!(rw.writes.contains(&sender));
    assert!(rw.writes.contains(&recipient));
}

#[test]
fn test_read_write_set_malformed_payload() {
    let sender = test_account_id(0xAA);
    let tx = QbindTransaction::new(sender, 0, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let rw = extract_read_write_set(&tx);
    assert!(rw.is_none(), "malformed payload should return None");
}

// ============================================================================
// Test: Complex dependency chain
// ============================================================================

/// Test a diamond dependency pattern:
/// tx0: A -> B
/// tx1: C -> D
/// tx2: A -> D (depends on tx0 and tx1)
/// tx3: E -> F
#[test]
fn conflict_graph_diamond_dependency() {
    let transactions = vec![
        make_transfer_tx(0xAA, 0xBB, 0, 10), // tx0: A -> B
        make_transfer_tx(0xCC, 0xDD, 0, 10), // tx1: C -> D
        make_transfer_tx(0xAA, 0xDD, 1, 10), // tx2: A -> D (depends on tx0 via A, tx1 via D)
        make_transfer_tx(0xEE, 0xFF, 0, 10), // tx3: E -> F (independent)
    ];

    let graph = build_conflict_graph(&transactions);

    // tx2 should depend on both tx0 (sender A) and tx1 (recipient D)
    assert!(graph.has_dependency(TxIndex(0), TxIndex(2)));
    assert!(graph.has_dependency(TxIndex(1), TxIndex(2)));
    assert_eq!(graph.dependency_count(TxIndex(2)), 2);

    let schedule = build_parallel_schedule(&graph);

    // Level 0: tx0, tx1, tx3 (no dependencies)
    // Level 1: tx2 (depends on tx0 and tx1)
    assert_eq!(schedule.level_count(), 2);
    assert_eq!(schedule.levels[0].len(), 3);
    assert_eq!(schedule.levels[1].len(), 1);
    assert_eq!(schedule.levels[1][0], TxIndex(2));
}

// ============================================================================
// Test: Empty block handling
// ============================================================================

#[test]
fn conflict_graph_empty_block() {
    let transactions: Vec<QbindTransaction> = Vec::new();

    let graph = build_conflict_graph(&transactions);
    assert_eq!(graph.tx_count, 0);

    let schedule = build_parallel_schedule(&graph);
    assert!(schedule.levels.is_empty());
    assert_eq!(schedule.tx_count(), 0);
}

// ============================================================================
// Test: Single transaction
// ============================================================================

#[test]
fn conflict_graph_single_transaction() {
    let transactions = vec![make_transfer_tx(0xAA, 0xBB, 0, 10)];

    let graph = build_conflict_graph(&transactions);
    assert_eq!(graph.tx_count, 1);
    assert_eq!(graph.dependency_count(TxIndex(0)), 0);

    let schedule = build_parallel_schedule(&graph);
    assert_eq!(schedule.level_count(), 1);
    assert_eq!(schedule.levels[0].len(), 1);
    assert_eq!(schedule.levels[0][0], TxIndex(0));
}

// ============================================================================
// Test: Long chain with one hot account
// ============================================================================

#[test]
fn sequential_block_with_all_conflicts_produces_linear_schedule() {
    // All transactions touch a common "hot" account (0xFF)
    let transactions = vec![
        make_transfer_tx(0xFF, 0x01, 0, 10), // tx0: Hot -> 0x01
        make_transfer_tx(0xFF, 0x02, 1, 10), // tx1: Hot -> 0x02
        make_transfer_tx(0xFF, 0x03, 2, 10), // tx2: Hot -> 0x03
        make_transfer_tx(0xFF, 0x04, 3, 10), // tx3: Hot -> 0x04
        make_transfer_tx(0x05, 0xFF, 0, 10), // tx4: 0x05 -> Hot (depends on tx0-tx3)
    ];

    let graph = build_conflict_graph(&transactions);

    // tx4 depends on all previous txs (all touch Hot account)
    for i in 0..4 {
        assert!(
            graph.has_dependency(TxIndex(i), TxIndex(4)),
            "tx4 should depend on tx{}",
            i
        );
    }

    let schedule = build_parallel_schedule(&graph);

    // Should be fully sequential (5 levels)
    assert_eq!(schedule.level_count(), 5);
    assert!(schedule.is_sequential());

    // Each level has exactly one tx
    for (level_idx, level) in schedule.levels.iter().enumerate() {
        assert_eq!(level.len(), 1);
        assert_eq!(level[0].0, level_idx);
    }
}