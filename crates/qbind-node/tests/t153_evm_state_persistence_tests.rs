//! T153 EVM State Persistence Tests
//!
//! Node-level tests for persistent EVM state:
//! - Single-block restart test
//! - Multi-block + pruning test
//! - Empty / no-snapshot startup test
//! - Deterministic state root verification after snapshot round-trip

use std::collections::HashMap;
use std::sync::Arc;

use tempfile::tempdir;

use qbind_node::evm_commit::{init_evm_account, EvmExecutionBridge};
use qbind_node::evm_state_store::FileEvmStateStorage;
use qbind_node::NodeCommittedBlock;
use qbind_runtime::{Address, EvmLedger, EvmStateStorage, EvmStateStorageConfig, QbindTx, U256};
use qbind_wire::consensus::{BlockHeader, BlockProposal};

// ============================================================================
// Helper functions
// ============================================================================

fn make_address(byte: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = byte;
    Address::from_bytes(bytes)
}

fn make_test_proposal(height: u64, round: u64) -> std::sync::Arc<BlockProposal> {
    std::sync::Arc::new(BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1337,
            epoch: 0,
            height,
            round,
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

fn make_committed_block(height: u64) -> NodeCommittedBlock<[u8; 32]> {
    NodeCommittedBlock {
        height,
        view: 1,
        block_id: [height as u8; 32],
        proposal: make_test_proposal(height, 1),
    }
}

// ============================================================================
// Test: Single-block restart test (Part 4.1)
// ============================================================================

#[test]
fn test_single_block_restart() {
    let dir = tempdir().unwrap();
    let storage_config = EvmStateStorageConfig {
        root_dir: dir.path().to_path_buf(),
        retention: 256,
    };

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    // Variables to store state from instance 1
    let state_root_1: qbind_runtime::H256;
    let balance_a_1: u64;
    let balance_b_1: u64;
    let nonce_a_1: u64;

    // Node instance 1: create and commit a block
    {
        let storage = Arc::new(
            FileEvmStateStorage::new(storage_config.clone())
                .expect("storage creation should succeed"),
        );

        let mut bridge =
            EvmExecutionBridge::with_storage(1337, storage, 256).expect("bridge should start");

        // Initialize genesis accounts
        init_evm_account(
            bridge.ledger_mut(),
            addr_a,
            U256::from_u128(10_000_000_000_000_000_000),
            0,
        );

        // Commit a transfer block
        let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(500_000), 0).with_gas(
            21000,
            1_000_000_000,
            1_000_000_000,
        );

        let block = make_committed_block(1);
        let result = bridge
            .apply_committed_block(&block, vec![tx])
            .expect("commit should succeed");

        // Store values for later assertion
        state_root_1 = result.state_root;
        balance_a_1 = bridge
            .ledger()
            .get_account(&addr_a)
            .unwrap()
            .balance
            .to_u64()
            .unwrap();
        balance_b_1 = bridge
            .ledger()
            .get_account(&addr_b)
            .unwrap()
            .balance
            .to_u64()
            .unwrap();
        nonce_a_1 = bridge.ledger().get_account(&addr_a).unwrap().nonce;

        // Bridge is dropped here, simulating node shutdown
    }

    // Node instance 2: restart and verify state
    {
        let storage = Arc::new(
            FileEvmStateStorage::new(storage_config).expect("storage creation should succeed"),
        );

        let bridge =
            EvmExecutionBridge::with_storage(1337, storage, 256).expect("bridge should start");

        // Verify current height was restored
        assert_eq!(bridge.current_height(), 1);

        // Verify state root matches
        let state_root_2 = bridge.compute_state_root();
        assert_eq!(state_root_1, state_root_2);

        // Verify account balances
        let balance_a_2 = bridge
            .ledger()
            .get_account(&addr_a)
            .expect("addr_a should exist")
            .balance
            .to_u64()
            .unwrap();
        assert_eq!(balance_a_1, balance_a_2);

        let balance_b_2 = bridge
            .ledger()
            .get_account(&addr_b)
            .expect("addr_b should exist")
            .balance
            .to_u64()
            .unwrap();
        assert_eq!(balance_b_1, balance_b_2);

        // Verify nonce
        let nonce_a_2 = bridge.ledger().get_account(&addr_a).unwrap().nonce;
        assert_eq!(nonce_a_1, nonce_a_2);
    }
}

// ============================================================================
// Test: Multi-block + pruning test (Part 4.2)
// ============================================================================

#[test]
fn test_multi_block_pruning() {
    let dir = tempdir().unwrap();
    let retention: u64 = 3; // Keep only 3 snapshots

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    // Track state roots for verification
    let mut state_roots: Vec<qbind_runtime::H256> = Vec::new();

    // Instance 1: commit 4 blocks
    {
        let storage = Arc::new(
            FileEvmStateStorage::with_dir_and_retention(dir.path(), retention)
                .expect("storage should be created"),
        );

        let mut bridge = EvmExecutionBridge::with_storage(1337, storage.clone(), retention)
            .expect("bridge should start");

        // Initialize genesis
        init_evm_account(
            bridge.ledger_mut(),
            addr_a,
            U256::from_u128(100_000_000_000_000_000_000),
            0,
        );

        // Commit 4 blocks
        for height in 1..=4 {
            let tx =
                QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), (height - 1) as u64)
                    .with_gas(21000, 1_000_000_000, 1_000_000_000);

            let block = make_committed_block(height);
            let result = bridge
                .apply_committed_block(&block, vec![tx])
                .expect("commit should succeed");

            state_roots.push(result.state_root);
        }

        // With retention=3:
        // - Height 3: prune_below = (3-3)+1 = 1, so heights < 1 are pruned (nothing)
        // - Height 4: prune_below = (4-3)+1 = 2, so height 1 is pruned
        assert!(
            storage.load_by_height(1).unwrap().is_none(),
            "height 1 should be pruned after height 4"
        );
        assert!(storage.load_by_height(2).unwrap().is_some());
        assert!(storage.load_by_height(3).unwrap().is_some());
        assert!(storage.load_by_height(4).unwrap().is_some());
    }

    // Instance 2: commit more blocks to trigger more pruning
    {
        let storage = Arc::new(
            FileEvmStateStorage::with_dir_and_retention(dir.path(), retention)
                .expect("storage should be created"),
        );

        let mut bridge = EvmExecutionBridge::with_storage(1337, storage.clone(), retention)
            .expect("bridge should start from snapshot");

        // Verify we loaded from height 4
        assert_eq!(bridge.current_height(), 4);

        // Commit blocks 5 and 6
        for height in 5..=6 {
            let tx =
                QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), (height - 1) as u64)
                    .with_gas(21000, 1_000_000_000, 1_000_000_000);

            let block = make_committed_block(height);
            let result = bridge
                .apply_committed_block(&block, vec![tx])
                .expect("commit should succeed");

            state_roots.push(result.state_root);
        }

        // After height 6 with retention 3:
        // - Height 5: prune_below = (5-3)+1 = 3, so heights 1, 2 pruned
        // - Height 6: prune_below = (6-3)+1 = 4, so heights 1, 2, 3 pruned
        assert!(
            storage.load_by_height(1).unwrap().is_none(),
            "height 1 should be pruned"
        );
        assert!(
            storage.load_by_height(2).unwrap().is_none(),
            "height 2 should be pruned"
        );
        assert!(
            storage.load_by_height(3).unwrap().is_none(),
            "height 3 should be pruned"
        );

        // Heights 4, 5, 6 should exist (the last 3)
        assert!(storage.load_by_height(4).unwrap().is_some());
        assert!(storage.load_by_height(5).unwrap().is_some());
        assert!(storage.load_by_height(6).unwrap().is_some());
    }

    // Instance 3: restart and verify state from latest snapshot
    {
        let storage = Arc::new(
            FileEvmStateStorage::with_dir_and_retention(dir.path(), retention)
                .expect("storage should be created"),
        );

        let bridge = EvmExecutionBridge::with_storage(1337, storage, retention)
            .expect("bridge should start");

        // Should load height 6
        assert_eq!(bridge.current_height(), 6);

        // State root should match
        let current_root = bridge.compute_state_root();
        assert_eq!(current_root, state_roots[5]); // state_roots[5] = block 6

        // Verify final balance: 6 transfers of 100_000 each
        let balance_b = bridge
            .ledger()
            .get_account(&addr_b)
            .expect("addr_b should exist")
            .balance
            .to_u64()
            .unwrap();
        assert_eq!(balance_b, 600_000);
    }
}

// ============================================================================
// Test: Empty / no-snapshot startup (Part 4.3)
// ============================================================================

#[test]
fn test_empty_storage_startup() {
    let dir = tempdir().unwrap();

    let storage = Arc::new(
        FileEvmStateStorage::with_dir_and_retention(dir.path(), 256).expect("should work"),
    );

    // Verify load_latest returns None
    assert!(storage.load_latest().unwrap().is_none());

    // Create bridge with empty storage
    let bridge = EvmExecutionBridge::with_storage(1337, storage, 256).expect("bridge should start");

    // Should start at height 0 with empty ledger
    assert_eq!(bridge.current_height(), 0);
    assert_eq!(bridge.ledger().account_count(), 0);
}

// ============================================================================
// Test: State root consistency after snapshot round-trip (Part 5)
// ============================================================================

#[test]
fn test_snapshot_roundtrip_state_root_consistency() {
    let dir = tempdir().unwrap();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);
    let addr_c = make_address(0xC3);

    // Create complex state with multiple accounts and storage
    let state_root_before: qbind_runtime::H256;

    {
        let storage = Arc::new(
            FileEvmStateStorage::with_dir_and_retention(dir.path(), 256).expect("should work"),
        );

        let mut bridge =
            EvmExecutionBridge::with_storage(1337, storage, 256).expect("bridge should start");

        // Initialize accounts
        init_evm_account(
            bridge.ledger_mut(),
            addr_a,
            U256::from_u128(50_000_000_000_000_000_000),
            0,
        );
        init_evm_account(
            bridge.ledger_mut(),
            addr_b,
            U256::from_u128(30_000_000_000_000_000_000),
            0,
        );
        init_evm_account(bridge.ledger_mut(), addr_c, U256::from_u64(1_000_000), 5);

        // Execute multiple transfers in one block
        let tx1 = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
            21000,
            1_000_000_000,
            1_000_000_000,
        );
        let tx2 = QbindTx::transfer(addr_b, addr_c, U256::from_u64(50_000), 0).with_gas(
            21000,
            1_000_000_000,
            1_000_000_000,
        );

        let block = make_committed_block(1);
        let result = bridge
            .apply_committed_block(&block, vec![tx1, tx2])
            .expect("commit should succeed");

        state_root_before = result.state_root;
    }

    // Restore and verify
    {
        let storage = Arc::new(
            FileEvmStateStorage::with_dir_and_retention(dir.path(), 256).expect("should work"),
        );

        let bridge =
            EvmExecutionBridge::with_storage(1337, storage, 256).expect("bridge should start");

        // Recompute state root
        let state_root_after = bridge.compute_state_root();

        // Must match exactly
        assert_eq!(state_root_before, state_root_after);
    }
}

// ============================================================================
// Test: Multiple independent snapshots preserve consistency
// ============================================================================

#[test]
fn test_multiple_snapshots_consistency() {
    let dir = tempdir().unwrap();

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    // Commit multiple blocks, record each state root
    let mut recorded_roots: HashMap<u64, qbind_runtime::H256> = HashMap::new();

    {
        let storage = Arc::new(
            FileEvmStateStorage::with_dir_and_retention(dir.path(), 256).expect("should work"),
        );

        let mut bridge = EvmExecutionBridge::with_storage(1337, storage.clone(), 256)
            .expect("bridge should start");

        // Initialize genesis
        init_evm_account(
            bridge.ledger_mut(),
            addr_a,
            U256::from_u128(100_000_000_000_000_000_000),
            0,
        );

        // Commit 5 blocks
        for height in 1..=5 {
            let tx = QbindTx::transfer(
                addr_a,
                addr_b,
                U256::from_u64(10_000 * height),
                (height - 1) as u64,
            )
            .with_gas(21000, 1_000_000_000, 1_000_000_000);

            let block = make_committed_block(height);
            let result = bridge
                .apply_committed_block(&block, vec![tx])
                .expect("commit should succeed");

            recorded_roots.insert(height, result.state_root);
        }

        // Verify each snapshot produces the correct state root
        for height in 1..=5 {
            let snapshot = storage
                .load_by_height(height)
                .expect("load should succeed")
                .expect("snapshot should exist");

            let ledger = EvmLedger::from_snapshot(&snapshot);
            let computed_root = ledger.compute_state_root();

            assert_eq!(
                computed_root, snapshot.state_root,
                "snapshot state_root should match computed root for height {}",
                height
            );
            assert_eq!(
                computed_root, recorded_roots[&height],
                "computed root should match recorded root for height {}",
                height
            );
        }
    }
}

// ============================================================================
// Test: Storage errors don't corrupt state
// ============================================================================

#[test]
fn test_bridge_without_storage_still_works() {
    // Verify that a bridge without storage works correctly (backwards compatibility)
    let mut bridge = EvmExecutionBridge::new(1337);

    let addr_a = make_address(0xA1);
    let addr_b = make_address(0xB2);

    init_evm_account(
        bridge.ledger_mut(),
        addr_a,
        U256::from_u128(10_000_000_000_000_000_000),
        0,
    );

    let tx = QbindTx::transfer(addr_a, addr_b, U256::from_u64(100_000), 0).with_gas(
        21000,
        1_000_000_000,
        1_000_000_000,
    );

    let block = make_committed_block(1);
    let result = bridge
        .apply_committed_block(&block, vec![tx])
        .expect("commit should succeed");

    assert_eq!(result.height, 1);
    assert!(!bridge.has_storage());
}

// ============================================================================
// Test: Retention configuration
// ============================================================================

#[test]
fn test_retention_configuration() {
    let dir = tempdir().unwrap();

    let storage = Arc::new(
        FileEvmStateStorage::with_dir_and_retention(dir.path(), 100).expect("should work"),
    );

    let bridge = EvmExecutionBridge::with_storage(1337, storage, 50).expect("bridge should start");

    // Bridge uses its own retention, not storage's
    assert_eq!(bridge.retention(), 50);
}
