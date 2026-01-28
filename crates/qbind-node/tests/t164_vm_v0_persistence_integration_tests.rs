//! T164: VM v0 Persistence Integration Tests
//!
//! This module tests the VM v0 persistence integration with the execution service:
//!
//! - Single-node restart with persistent state
//! - State directory configuration
//! - Execution service with persistent backend

use qbind_ledger::{
    AccountState, AccountStateUpdater, AccountStateView, CachedPersistentAccountState,
    PersistentAccountState, QbindTransaction, RocksDbAccountState, TransferPayload,
    VmV0ExecutionEngine,
};
use qbind_node::execution_adapter::SingleThreadExecutionServiceConfig;
use qbind_node::node_config::{ExecutionProfile, NodeConfig};
use qbind_types::{AccountId, NetworkEnvironment};
use std::path::PathBuf;
use tempfile::tempdir;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test account ID with the given byte value.
fn test_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

/// Create a simple transfer transaction.
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
// Part 4.2: NodeConfig VM v0 State Directory Tests
// ============================================================================

/// Test that NodeConfig correctly computes VM v0 state directory.
#[test]
fn test_node_config_vm_v0_state_dir() {
    // Without data_dir, should return None
    let config = NodeConfig::testnet_vm_v0();
    assert!(config.vm_v0_state_dir().is_none());

    // With data_dir, should return the correct path
    let config_with_dir = NodeConfig::testnet_vm_v0().with_data_dir("/data/qbind");
    let state_dir = config_with_dir.vm_v0_state_dir();
    assert!(state_dir.is_some());
    assert_eq!(state_dir.unwrap(), PathBuf::from("/data/qbind/state_vm_v0"));
}

/// Test that NodeConfig builder methods work correctly.
#[test]
fn test_node_config_builder() {
    let config = NodeConfig::new(NetworkEnvironment::Testnet).with_data_dir("/tmp/test");

    assert_eq!(config.environment, NetworkEnvironment::Testnet);
    assert_eq!(config.execution_profile, ExecutionProfile::NonceOnly);
    assert_eq!(config.data_dir, Some(PathBuf::from("/tmp/test")));
}

// ============================================================================
// Part 4.2: SingleThreadExecutionServiceConfig Tests
// ============================================================================

/// Test VM v0 config with state directory.
#[test]
fn test_execution_service_config_vm_v0_persistent() {
    let config = SingleThreadExecutionServiceConfig::vm_v0_persistent("/data/vm_state");

    assert_eq!(config.execution_profile, ExecutionProfile::VmV0);
    assert_eq!(config.state_dir, Some(PathBuf::from("/data/vm_state")));
}

/// Test builder method for state directory.
#[test]
fn test_execution_service_config_with_state_dir() {
    let config = SingleThreadExecutionServiceConfig::vm_v0().with_state_dir("/custom/path");

    assert_eq!(config.execution_profile, ExecutionProfile::VmV0);
    assert_eq!(config.state_dir, Some(PathBuf::from("/custom/path")));
}

// ============================================================================
// Part 4.2: Direct Execution Engine with Persistent State Tests
// ============================================================================

/// Test VmV0ExecutionEngine with CachedPersistentAccountState directly.
#[test]
fn test_vm_v0_engine_with_persistent_state() {
    let dir = tempdir().expect("Failed to create temp dir");
    let persistent =
        RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");
    let mut cached = CachedPersistentAccountState::new(persistent);

    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Initialize sender balance directly in the cached state
    cached.set_account_state(&sender, AccountState::new(0, 1000));

    // Create a transfer transaction
    let tx = make_transfer_tx(0xAA, 0xBB, 0, 100);

    // Execute the transaction
    let result = engine.execute_tx(&mut cached, &tx);
    assert!(result.success, "Transfer should succeed");

    // Verify state changes
    let sender_state = cached.get_account_state(&sender);
    assert_eq!(sender_state.nonce, 1);
    assert_eq!(sender_state.balance, 900);

    let recipient_state = cached.get_account_state(&recipient);
    assert_eq!(recipient_state.balance, 100);

    // Flush to persist
    cached.flush().expect("Failed to flush");
}

/// Test that state survives across simulated restart.
#[test]
fn test_vm_v0_state_survives_restart() {
    let dir = tempdir().expect("Failed to create temp dir");
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // First session: execute transactions and flush
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");
        let mut cached = CachedPersistentAccountState::new(persistent);
        let engine = VmV0ExecutionEngine::new();

        // Initialize sender
        cached.set_account_state(&sender, AccountState::new(0, 1000));

        // Execute two transfers
        let tx1 = make_transfer_tx(0xAA, 0xBB, 0, 100);
        let result1 = engine.execute_tx(&mut cached, &tx1);
        assert!(result1.success);

        let tx2 = make_transfer_tx(0xAA, 0xBB, 1, 200);
        let result2 = engine.execute_tx(&mut cached, &tx2);
        assert!(result2.success);

        cached.flush().expect("Failed to flush");
    }

    // Second session: verify state persisted (simulating restart)
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to reopen RocksDbAccountState");
        let cached = CachedPersistentAccountState::new(persistent);

        let sender_state = cached.get_account_state(&sender);
        assert_eq!(sender_state.nonce, 2, "sender nonce should persist");
        assert_eq!(sender_state.balance, 700, "sender balance should persist");

        let recipient_state = cached.get_account_state(&recipient);
        assert_eq!(
            recipient_state.balance, 300,
            "recipient balance should persist"
        );
    }
}

/// Test execute_block with persistent state.
#[test]
fn test_vm_v0_execute_block_persistent() {
    let dir = tempdir().expect("Failed to create temp dir");

    let sender = test_account_id(0xAA);
    let recipient1 = test_account_id(0xBB);
    let recipient2 = test_account_id(0xCC);

    // Execute a block
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");
        let mut cached = CachedPersistentAccountState::new(persistent);
        let engine = VmV0ExecutionEngine::new();

        // Initialize sender
        cached.set_account_state(&sender, AccountState::new(0, 1000));

        // Create transactions for the block
        let txs = vec![
            make_transfer_tx(0xAA, 0xBB, 0, 100),
            make_transfer_tx(0xAA, 0xCC, 1, 150),
        ];

        let results = engine.execute_block(&mut cached, &txs);
        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(results[1].success);

        cached.flush().expect("Failed to flush");
    }

    // Verify persisted state
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to reopen RocksDbAccountState");

        assert_eq!(persistent.get_account_state(&sender).nonce, 2);
        assert_eq!(persistent.get_account_state(&sender).balance, 750);
        assert_eq!(persistent.get_account_state(&recipient1).balance, 100);
        assert_eq!(persistent.get_account_state(&recipient2).balance, 150);
    }
}

// ============================================================================
// Part 4.2: Multiple Block Execution Tests
// ============================================================================

/// Test executing multiple blocks with persistent state.
#[test]
fn test_vm_v0_multiple_blocks_persistent() {
    let dir = tempdir().expect("Failed to create temp dir");
    let sender = test_account_id(0xAA);

    // First session: execute two blocks
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");
        let mut cached = CachedPersistentAccountState::new(persistent);
        let engine = VmV0ExecutionEngine::new();

        // Initialize sender
        cached.set_account_state(&sender, AccountState::new(0, 1000));

        // Block 1
        let block1_txs = vec![make_transfer_tx(0xAA, 0xBB, 0, 50)];
        engine.execute_block(&mut cached, &block1_txs);
        cached.flush().expect("Failed to flush block 1");

        // Block 2
        let block2_txs = vec![
            make_transfer_tx(0xAA, 0xCC, 1, 75),
            make_transfer_tx(0xAA, 0xDD, 2, 25),
        ];
        engine.execute_block(&mut cached, &block2_txs);
        cached.flush().expect("Failed to flush block 2");
    }

    // Verify final state
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to reopen RocksDbAccountState");

        let sender_state = persistent.get_account_state(&sender);
        assert_eq!(sender_state.nonce, 3);
        assert_eq!(sender_state.balance, 850); // 1000 - 50 - 75 - 25

        assert_eq!(
            persistent.get_account_state(&test_account_id(0xBB)).balance,
            50
        );
        assert_eq!(
            persistent.get_account_state(&test_account_id(0xCC)).balance,
            75
        );
        assert_eq!(
            persistent.get_account_state(&test_account_id(0xDD)).balance,
            25
        );
    }
}

// ============================================================================
// Error Case Tests
// ============================================================================

/// Test that failed transactions don't corrupt persistent state.
#[test]
fn test_vm_v0_failed_tx_no_state_corruption() {
    let dir = tempdir().expect("Failed to create temp dir");
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Execute a failing transaction
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");
        let mut cached = CachedPersistentAccountState::new(persistent);
        let engine = VmV0ExecutionEngine::new();

        // Initialize sender with low balance
        cached.set_account_state(&sender, AccountState::new(0, 50));

        // Try to transfer more than balance
        let tx = make_transfer_tx(0xAA, 0xBB, 0, 100);
        let result = engine.execute_tx(&mut cached, &tx);
        assert!(
            !result.success,
            "Transfer should fail (insufficient balance)"
        );

        cached.flush().expect("Failed to flush");
    }

    // Verify state unchanged after restart
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to reopen RocksDbAccountState");

        // Sender state should be unchanged (nonce and balance)
        let sender_state = persistent.get_account_state(&sender);
        assert_eq!(sender_state.nonce, 0, "nonce should be unchanged");
        assert_eq!(sender_state.balance, 50, "balance should be unchanged");

        // Recipient should have no balance
        assert_eq!(
            persistent.get_account_state(&recipient).balance,
            0,
            "recipient should have no balance"
        );
    }
}
