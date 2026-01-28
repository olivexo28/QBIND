//! T163 VM v0 Integration Tests
//!
//! These tests verify the VM v0 integration with the execution service:
//! 1. SingleThreadExecutionService with VmV0 profile
//! 2. Single-node VM v0 transfer flow
//! 3. DevNet regression (NonceOnly profile still works)

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use qbind_ledger::{
    AccountStateView, InMemoryAccountState, NonceExecutionEngine, QbindTransaction,
    TransferPayload, VmV0ExecutionEngine,
};
use qbind_node::{
    AsyncExecutionService, ExecutionProfile, NodeConfig, QbindBlock, SingleThreadExecutionService,
    SingleThreadExecutionServiceConfig,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal};

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

fn make_nonce_only_tx(sender_byte: u8, nonce: u64) -> QbindTransaction {
    let sender = test_account_id(sender_byte);
    // For nonce-only execution, payload is ignored
    QbindTransaction::new(sender, nonce, vec![0xAA; 32])
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
// Part 1: ExecutionProfile Tests
// ============================================================================

/// Test that ExecutionProfile defaults to NonceOnly.
#[test]
fn test_execution_profile_default() {
    let profile = ExecutionProfile::default();
    assert_eq!(profile, ExecutionProfile::NonceOnly);
}

/// Test ExecutionProfile display.
#[test]
fn test_execution_profile_display() {
    assert_eq!(format!("{}", ExecutionProfile::NonceOnly), "nonce-only");
    assert_eq!(format!("{}", ExecutionProfile::VmV0), "vm-v0");
}

// ============================================================================
// Part 2: NodeConfig Execution Profile Tests
// ============================================================================

/// Test that NodeConfig::default() uses NonceOnly profile.
#[test]
fn test_node_config_default_profile() {
    let config = NodeConfig::default();
    assert_eq!(config.execution_profile, ExecutionProfile::NonceOnly);
}

/// Test NodeConfig::testnet_vm_v0() creates correct configuration.
#[test]
fn test_node_config_testnet_vm_v0() {
    let config = NodeConfig::testnet_vm_v0();
    assert_eq!(config.execution_profile, ExecutionProfile::VmV0);
    assert_eq!(config.environment, qbind_types::NetworkEnvironment::Testnet);
}

/// Test NodeConfig::with_profile() creates correct configuration.
#[test]
fn test_node_config_with_profile() {
    let config = NodeConfig::with_profile(
        qbind_types::NetworkEnvironment::Devnet,
        ExecutionProfile::VmV0,
    );
    assert_eq!(config.environment, qbind_types::NetworkEnvironment::Devnet);
    assert_eq!(config.execution_profile, ExecutionProfile::VmV0);
}

// ============================================================================
// Part 3: SingleThreadExecutionServiceConfig Tests
// ============================================================================

/// Test that config defaults to NonceOnly.
#[test]
fn test_service_config_default_profile() {
    let config = SingleThreadExecutionServiceConfig::default();
    assert_eq!(config.execution_profile, ExecutionProfile::NonceOnly);
}

/// Test config with VM v0 profile.
#[test]
fn test_service_config_vm_v0() {
    let config = SingleThreadExecutionServiceConfig::vm_v0();
    assert_eq!(config.execution_profile, ExecutionProfile::VmV0);
}

/// Test config builder.
#[test]
fn test_service_config_builder() {
    let config = SingleThreadExecutionServiceConfig::default()
        .with_execution_profile(ExecutionProfile::VmV0)
        .with_queue_capacity(512);

    assert_eq!(config.execution_profile, ExecutionProfile::VmV0);
    assert_eq!(config.queue_capacity, 512);
}

// ============================================================================
// Part 4: SingleThreadExecutionService with NonceOnly (DevNet Regression)
// ============================================================================

/// Test that NonceOnly profile works correctly (DevNet regression).
#[test]
fn test_service_nonce_only_profile() {
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::default();
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    // Create a block with some transactions
    let txs = vec![
        make_nonce_only_tx(0xAA, 0),
        make_nonce_only_tx(0xBB, 0),
        make_nonce_only_tx(0xAA, 1),
    ];
    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    // Submit block
    let result = service.submit_block(block);
    assert!(result.is_ok(), "submit_block should succeed");

    // Wait for processing
    thread::sleep(Duration::from_millis(100));

    // Service should be running
    assert!(!service.is_shutting_down());

    // Shutdown
    service.shutdown();
}

// ============================================================================
// Part 5: SingleThreadExecutionService with VmV0
// ============================================================================

/// Test that VmV0 profile works with the execution service.
#[test]
fn test_service_vm_v0_profile() {
    // Note: The engine parameter is unused internally when VmV0 profile is selected.
    // The service creates its own VmV0ExecutionEngine internally.
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::vm_v0();
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    // Note: The service processes blocks internally, but we can't directly
    // check the VM state from outside. We just verify the service runs.

    // Create an empty block (no transfers, but service should handle it)
    let proposal = make_test_proposal(1);
    let block = QbindBlock::empty(proposal);

    // Submit block
    let result = service.submit_block(block);
    assert!(result.is_ok(), "submit_block should succeed");

    // Wait for processing
    thread::sleep(Duration::from_millis(100));

    // Service should be running
    assert!(!service.is_shutting_down());

    // Shutdown
    service.shutdown();
}

/// Test VmV0 profile with multiple blocks.
#[test]
fn test_service_vm_v0_multiple_blocks() {
    // Note: The engine parameter is unused internally when VmV0 profile is selected.
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::vm_v0();
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    // Submit multiple empty blocks
    for height in 1..=5 {
        let proposal = make_test_proposal(height);
        let block = QbindBlock::empty(proposal);
        let result = service.submit_block(block);
        assert!(result.is_ok(), "submit_block {} should succeed", height);
    }

    // Wait for processing
    thread::sleep(Duration::from_millis(200));

    // Service should be running
    assert!(!service.is_shutting_down());

    // Shutdown
    service.shutdown();
}

// ============================================================================
// Part 6: Startup Info String Tests
// ============================================================================

/// Test that startup info includes execution profile.
#[test]
fn test_startup_info_includes_profile() {
    let config = NodeConfig::testnet_vm_v0();
    let info = config.startup_info_string(Some("V1"));

    assert!(
        info.contains("profile=vm-v0"),
        "should include VM v0 profile"
    );
    assert!(
        info.contains("environment=TestNet"),
        "should include TestNet"
    );
}

/// Test startup info for DevNet default.
#[test]
fn test_startup_info_devnet_default() {
    let config = NodeConfig::default();
    let info = config.startup_info_string(None);

    assert!(
        info.contains("profile=nonce-only"),
        "should include nonce-only profile"
    );
    assert!(info.contains("environment=DevNet"), "should include DevNet");
}

// ============================================================================
// Part 7: Direct VmV0ExecutionEngine Tests (Sanity)
// ============================================================================

/// Sanity test for VmV0ExecutionEngine in service context.
#[test]
fn test_vm_v0_engine_direct() {
    let mut state = InMemoryAccountState::new();
    let engine = VmV0ExecutionEngine::new();

    // Initialize sender
    let sender = test_account_id(0xAA);
    state.init_account(&sender, 1000);

    // Execute transfers
    let txs = vec![
        make_transfer_tx(0xAA, 0xBB, 0, 100),
        make_transfer_tx(0xAA, 0xCC, 1, 200),
        make_transfer_tx(0xAA, 0xDD, 2, 300),
    ];

    let results = engine.execute_block(&mut state, &txs);

    assert_eq!(results.len(), 3);
    for result in &results {
        assert!(result.success, "all transfers should succeed");
    }

    // Verify final state
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.nonce, 3);
    assert_eq!(sender_state.balance, 400); // 1000 - 100 - 200 - 300

    let bb_state = state.get_account_state(&test_account_id(0xBB));
    assert_eq!(bb_state.balance, 100);

    let cc_state = state.get_account_state(&test_account_id(0xCC));
    assert_eq!(cc_state.balance, 200);

    let dd_state = state.get_account_state(&test_account_id(0xDD));
    assert_eq!(dd_state.balance, 300);
}
