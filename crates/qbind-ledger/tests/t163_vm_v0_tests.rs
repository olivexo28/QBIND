//! T163 VM v0 Unit Tests
//!
//! These tests verify the VM v0 execution semantics:
//! 1. Happy path simple transfer
//! 2. Nonce mismatch rejection
//! 3. Insufficient balance rejection
//! 4. Recipient creation
//! 5. Malformed payload error

use qbind_ledger::{
    AccountState, AccountStateUpdater, AccountStateView, InMemoryAccountState, QbindTransaction,
    TransferPayload, VmV0Error, VmV0ExecutionEngine, TRANSFER_PAYLOAD_SIZE,
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
// Test: TransferPayload encoding/decoding
// ============================================================================

#[test]
fn test_transfer_payload_roundtrip() {
    let recipient = test_account_id(0xBB);
    let amount = 12345678901234567890u128;

    let payload = TransferPayload::new(recipient, amount);
    let encoded = payload.encode();

    assert_eq!(encoded.len(), TRANSFER_PAYLOAD_SIZE);

    let decoded = TransferPayload::decode(&encoded).expect("decode should succeed");
    assert_eq!(decoded.recipient, recipient);
    assert_eq!(decoded.amount, amount);
}

#[test]
fn test_transfer_payload_decode_wrong_size() {
    // Too short
    let short = vec![0u8; 47];
    assert!(TransferPayload::decode(&short).is_none());

    // Too long
    let long = vec![0u8; 49];
    assert!(TransferPayload::decode(&long).is_none());

    // Empty
    let empty: Vec<u8> = vec![];
    assert!(TransferPayload::decode(&empty).is_none());
}

// ============================================================================
// Test: AccountState
// ============================================================================

#[test]
fn test_account_state_default() {
    let state = AccountState::default();
    assert_eq!(state.nonce, 0);
    assert_eq!(state.balance, 0);
}

#[test]
fn test_account_state_with_balance() {
    let state = AccountState::with_balance(100);
    assert_eq!(state.nonce, 0);
    assert_eq!(state.balance, 100);
}

#[test]
fn test_account_state_new() {
    let state = AccountState::new(5, 1000);
    assert_eq!(state.nonce, 5);
    assert_eq!(state.balance, 1000);
}

// ============================================================================
// Test: InMemoryAccountState
// ============================================================================

#[test]
fn test_in_memory_account_state_default() {
    let state = InMemoryAccountState::new();
    let account = test_account_id(0xAA);

    // Non-existent accounts should return default state
    let account_state = state.get_account_state(&account);
    assert_eq!(account_state.nonce, 0);
    assert_eq!(account_state.balance, 0);
}

#[test]
fn test_in_memory_account_state_init_account() {
    let mut state = InMemoryAccountState::new();
    let account = test_account_id(0xAA);

    state.init_account(&account, 100);

    let account_state = state.get_account_state(&account);
    assert_eq!(account_state.nonce, 0);
    assert_eq!(account_state.balance, 100);
}

#[test]
fn test_in_memory_account_state_set_and_get() {
    let mut state = InMemoryAccountState::new();
    let account = test_account_id(0xBB);

    state.set_account_state(&account, AccountState::new(3, 500));

    let account_state = state.get_account_state(&account);
    assert_eq!(account_state.nonce, 3);
    assert_eq!(account_state.balance, 500);
}

// ============================================================================
// Test: VM v0 happy path simple transfer
// ============================================================================

/// Test that a valid transfer succeeds and updates state correctly.
#[test]
fn test_happy_path_simple_transfer() {
    let mut state = InMemoryAccountState::new();
    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Initialize sender with balance 100, nonce 0
    state.init_account(&sender, 100);

    // Transfer 30 to recipient
    let tx = make_transfer_tx(0xAA, 0xBB, 0, 30);
    let result = engine.execute_tx(&mut state, &tx);

    // Should succeed
    assert!(result.success, "transfer should succeed");
    assert!(result.error.is_none());

    // Check sender state: nonce 1, balance 70
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.nonce, 1, "sender nonce should be incremented");
    assert_eq!(
        sender_state.balance, 70,
        "sender balance should be decremented"
    );

    // Check recipient state: nonce 0, balance 30
    let recipient_state = state.get_account_state(&recipient);
    assert_eq!(recipient_state.nonce, 0, "recipient nonce should remain 0");
    assert_eq!(
        recipient_state.balance, 30,
        "recipient balance should be 30"
    );
}

// ============================================================================
// Test: Nonce mismatch rejected
// ============================================================================

/// Test that a transaction with wrong nonce is rejected.
#[test]
fn test_nonce_mismatch_rejected() {
    let mut state = InMemoryAccountState::new();
    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);

    // Initialize sender with nonce 1 (via explicit state)
    state.set_account_state(&sender, AccountState::new(1, 100));

    // Try to send with nonce 0 (wrong)
    let tx = make_transfer_tx(0xAA, 0xBB, 0, 30);
    let result = engine.execute_tx(&mut state, &tx);

    // Should fail with NonceMismatch
    assert!(!result.success, "transfer should fail");
    assert!(result.error.is_some());

    match result.error.unwrap() {
        VmV0Error::NonceMismatch { expected, got } => {
            assert_eq!(expected, 1);
            assert_eq!(got, 0);
        }
        e => panic!("expected NonceMismatch, got {:?}", e),
    }

    // State should be unchanged
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.nonce, 1, "sender nonce should be unchanged");
    assert_eq!(
        sender_state.balance, 100,
        "sender balance should be unchanged"
    );
}

// ============================================================================
// Test: Insufficient balance rejected
// ============================================================================

/// Test that a transfer with insufficient balance is rejected.
#[test]
fn test_insufficient_balance_rejected() {
    let mut state = InMemoryAccountState::new();
    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);

    // Initialize sender with balance 10
    state.init_account(&sender, 10);

    // Try to send 50 (insufficient)
    let tx = make_transfer_tx(0xAA, 0xBB, 0, 50);
    let result = engine.execute_tx(&mut state, &tx);

    // Should fail with InsufficientBalance
    assert!(!result.success, "transfer should fail");
    assert!(result.error.is_some());

    match result.error.unwrap() {
        VmV0Error::InsufficientBalance { balance, needed } => {
            assert_eq!(balance, 10);
            assert_eq!(needed, 50);
        }
        e => panic!("expected InsufficientBalance, got {:?}", e),
    }

    // State should be unchanged
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.nonce, 0, "sender nonce should be unchanged");
    assert_eq!(
        sender_state.balance, 10,
        "sender balance should be unchanged"
    );
}

// ============================================================================
// Test: Recipient creation
// ============================================================================

/// Test that an absent recipient is created with the correct balance.
#[test]
fn test_recipient_creation() {
    let mut state = InMemoryAccountState::new();
    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Initialize sender with balance 100
    state.init_account(&sender, 100);

    // Recipient does not exist
    assert_eq!(state.get_account_state(&recipient), AccountState::default());

    // Transfer 40 to non-existent recipient
    let tx = make_transfer_tx(0xAA, 0xBB, 0, 40);
    let result = engine.execute_tx(&mut state, &tx);

    // Should succeed
    assert!(result.success, "transfer should succeed");

    // Recipient should be created with nonce 0 and balance 40
    let recipient_state = state.get_account_state(&recipient);
    assert_eq!(recipient_state.nonce, 0, "recipient nonce should be 0");
    assert_eq!(
        recipient_state.balance, 40,
        "recipient balance should be 40"
    );
}

// ============================================================================
// Test: Malformed payload error
// ============================================================================

/// Test that a malformed payload is rejected.
#[test]
fn test_malformed_payload_error() {
    let mut state = InMemoryAccountState::new();
    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);

    // Initialize sender with balance 100
    state.init_account(&sender, 100);

    // Create transaction with random/invalid payload
    let tx = QbindTransaction::new(sender, 0, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let result = engine.execute_tx(&mut state, &tx);

    // Should fail with MalformedPayload
    assert!(!result.success, "transfer should fail");
    assert!(result.error.is_some());

    match result.error.unwrap() {
        VmV0Error::MalformedPayload => {}
        e => panic!("expected MalformedPayload, got {:?}", e),
    }

    // State should be unchanged
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.nonce, 0, "sender nonce should be unchanged");
    assert_eq!(
        sender_state.balance, 100,
        "sender balance should be unchanged"
    );
}

// ============================================================================
// Test: Multiple sequential transactions
// ============================================================================

/// Test that multiple transactions from the same sender work correctly.
#[test]
fn test_multiple_sequential_transactions() {
    let mut state = InMemoryAccountState::new();
    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);

    // Initialize sender with balance 100
    state.init_account(&sender, 100);

    // Send 3 transactions
    for i in 0..3 {
        let tx = make_transfer_tx(0xAA, 0xBB, i, 20);
        let result = engine.execute_tx(&mut state, &tx);
        assert!(result.success, "transfer {} should succeed", i);
    }

    // Final state: sender has nonce=3, balance=40; recipient has nonce=0, balance=60
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.nonce, 3);
    assert_eq!(sender_state.balance, 40);

    let recipient_state = state.get_account_state(&test_account_id(0xBB));
    assert_eq!(recipient_state.nonce, 0);
    assert_eq!(recipient_state.balance, 60);
}

// ============================================================================
// Test: execute_block
// ============================================================================

/// Test execute_block processes all transactions in order.
#[test]
fn test_execute_block() {
    let mut state = InMemoryAccountState::new();
    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);

    // Initialize sender with balance 100
    state.init_account(&sender, 100);

    // Create a block with 5 transactions
    let transactions: Vec<_> = (0..5)
        .map(|i| make_transfer_tx(0xAA, 0xBB, i, 10))
        .collect();

    let results = engine.execute_block(&mut state, &transactions);

    // All should succeed
    assert_eq!(results.len(), 5);
    for (i, result) in results.iter().enumerate() {
        assert!(result.success, "tx {} should succeed", i);
    }

    // Final state check
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.nonce, 5);
    assert_eq!(sender_state.balance, 50);
}

// ============================================================================
// Test: Zero amount transfer
// ============================================================================

/// Test that a zero-amount transfer is valid.
#[test]
fn test_zero_amount_transfer() {
    let mut state = InMemoryAccountState::new();
    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);

    // Initialize sender with balance 100
    state.init_account(&sender, 100);

    // Transfer 0
    let tx = make_transfer_tx(0xAA, 0xBB, 0, 0);
    let result = engine.execute_tx(&mut state, &tx);

    // Should succeed (zero transfer is valid)
    assert!(result.success, "zero transfer should succeed");

    // Nonce should still be incremented
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.nonce, 1);
    assert_eq!(sender_state.balance, 100);

    // Recipient should have 0 balance
    let recipient_state = state.get_account_state(&test_account_id(0xBB));
    assert_eq!(recipient_state.balance, 0);
}

// ============================================================================
// Test: Self-transfer
// ============================================================================

/// Test that a self-transfer is valid.
#[test]
fn test_self_transfer() {
    let mut state = InMemoryAccountState::new();
    let engine = VmV0ExecutionEngine::new();

    let sender = test_account_id(0xAA);

    // Initialize sender with balance 100
    state.init_account(&sender, 100);

    // Transfer to self
    let tx = make_transfer_tx(0xAA, 0xAA, 0, 30);
    let result = engine.execute_tx(&mut state, &tx);

    // Should succeed
    assert!(result.success, "self-transfer should succeed");

    // Balance should remain the same (30 subtracted, then 30 added)
    let sender_state = state.get_account_state(&sender);
    assert_eq!(sender_state.nonce, 1);
    assert_eq!(sender_state.balance, 100);
}