//! T150 Execution Integration Tests
//!
//! Integration tests for the execution layer skeleton verifying:
//! 1. QbindTransaction with canonical signing preimage + verification
//! 2. ExecutionEngine trait with NonceExecutionEngine reference implementation
//! 3. QbindBlock carrying Vec<QbindTransaction>
//! 4. ExecutionAdapter commit hook with deterministic state evolution
//!
//! These tests demonstrate the T150 execution layer working end-to-end.

use std::sync::Arc;

use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::{
    get_account_nonce, ExecutionEngine, ExecutionEngineError, InMemoryState, NonceExecutionEngine,
    QbindTransaction, StateUpdater, UserPublicKey, USER_ML_DSA_44_SUITE_ID,
};
use qbind_node::{ExecutionAdapter, InMemoryExecutionAdapter, QbindBlock};
use qbind_wire::consensus::{BlockHeader, BlockProposal};

// ============================================================================
// Test Helpers
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
            parent_block_id: if height > 0 {
                [(height - 1) as u8; 32]
            } else {
                [0u8; 32]
            },
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
// Part 2: Transaction Signing & Verification Tests
// ============================================================================

#[test]
fn test_transaction_signing_preimage_stability() {
    // Verify that signing_preimage() produces deterministic output
    let sender = test_account_id(0xAA);
    let tx = QbindTransaction::new(sender, 42, b"payload data".to_vec());

    let preimage1 = tx.signing_preimage();
    let preimage2 = tx.signing_preimage();

    assert_eq!(preimage1, preimage2, "preimage should be deterministic");

    // Verify preimage contains expected components
    assert!(
        preimage1.starts_with(b"QBIND:TX:v1"),
        "should contain domain tag"
    );
    assert!(preimage1.len() > 11 + 32 + 8, "should have minimum length");
}

#[test]
fn test_transaction_sign_and_verify_roundtrip() {
    // Generate ML-DSA-44 keypair
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = UserPublicKey::ml_dsa_44(pk_bytes);

    // Create and sign transaction
    let sender = test_account_id(0xBB);
    let mut tx = QbindTransaction::new(sender, 0, b"test payload".to_vec());

    tx.sign(&sk).expect("signing should succeed");

    // Verify transaction has signature
    assert!(!tx.signature.bytes.is_empty(), "signature should be set");
    assert_eq!(tx.suite_id, USER_ML_DSA_44_SUITE_ID);

    // Verify signature
    let verify_result = tx.verify_signature(&pk);
    assert!(verify_result.is_ok(), "verification should succeed");
}

#[test]
fn test_transaction_verification_fails_with_wrong_key() {
    // Generate two keypairs
    let (pk_bytes1, sk1) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let (pk_bytes2, _sk2) = MlDsa44Backend::generate_keypair().expect("keygen failed");

    let correct_pk = UserPublicKey::ml_dsa_44(pk_bytes1);
    let wrong_pk = UserPublicKey::ml_dsa_44(pk_bytes2);

    // Sign with first key
    let sender = test_account_id(0xCC);
    let mut tx = QbindTransaction::new(sender, 0, b"test".to_vec());
    tx.sign(&sk1).expect("signing should succeed");

    // Verify with correct key succeeds
    assert!(tx.verify_signature(&correct_pk).is_ok());

    // Verify with wrong key fails
    assert!(tx.verify_signature(&wrong_pk).is_err());
}

#[test]
fn test_transaction_verification_fails_on_tampered_payload() {
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = UserPublicKey::ml_dsa_44(pk_bytes);

    let sender = test_account_id(0xDD);
    let mut tx = QbindTransaction::new(sender, 0, b"original".to_vec());
    tx.sign(&sk).expect("signing should succeed");

    // Tamper with payload
    tx.payload = b"tampered".to_vec();

    // Verification should fail
    assert!(tx.verify_signature(&pk).is_err());
}

// ============================================================================
// Part 3: ExecutionEngine Tests
// ============================================================================

#[test]
fn test_execution_engine_nonce_tracking() {
    let mut state = InMemoryState::new();
    let engine = NonceExecutionEngine::new();

    let sender = test_account_id(0xEE);

    // Execute tx with nonce 0 -> state nonce becomes 1
    let tx0 = QbindTransaction::new(sender, 0, b"tx0".to_vec());
    let result0 = engine.execute_tx(&mut state as &mut dyn StateUpdater, &tx0);
    assert!(result0.is_ok());
    assert_eq!(get_account_nonce(&state, &sender), 1);

    // Execute tx with nonce 1 -> state nonce becomes 2
    let tx1 = QbindTransaction::new(sender, 1, b"tx1".to_vec());
    let result1 = engine.execute_tx(&mut state as &mut dyn StateUpdater, &tx1);
    assert!(result1.is_ok());
    assert_eq!(get_account_nonce(&state, &sender), 2);

    // Execute tx with nonce 2 -> state nonce becomes 3
    let tx2 = QbindTransaction::new(sender, 2, b"tx2".to_vec());
    let result2 = engine.execute_tx(&mut state as &mut dyn StateUpdater, &tx2);
    assert!(result2.is_ok());
    assert_eq!(get_account_nonce(&state, &sender), 3);
}

#[test]
fn test_execution_engine_nonce_mismatch_error() {
    let mut state = InMemoryState::new();
    let engine = NonceExecutionEngine::new();

    let sender = test_account_id(0xFF);

    // Try executing with wrong nonce (1 instead of 0)
    let tx = QbindTransaction::new(sender, 1, b"wrong nonce".to_vec());
    let result = engine.execute_tx(&mut state as &mut dyn StateUpdater, &tx);

    assert!(matches!(
        result,
        Err(ExecutionEngineError::NonceMismatch {
            expected: 0,
            actual: 1
        })
    ));

    // State should remain unchanged
    assert_eq!(get_account_nonce(&state, &sender), 0);
}

#[test]
fn test_execution_engine_with_signature_verification() {
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = UserPublicKey::ml_dsa_44(pk_bytes);

    let sender = test_account_id(0x11);
    let mut tx = QbindTransaction::new(sender, 0, b"signed".to_vec());
    tx.sign(&sk).expect("signing should succeed");

    // Create engine with signature verification
    let pk_clone = pk.clone();
    let engine =
        NonceExecutionEngine::new().with_signature_verification(move |_| Some(pk_clone.clone()));

    let mut state = InMemoryState::new();
    let result = engine.execute_tx(&mut state as &mut dyn StateUpdater, &tx);

    assert!(result.is_ok());
    assert_eq!(get_account_nonce(&state, &sender), 1);
}

// ============================================================================
// Part 4: Single-Block Execution Tests
// ============================================================================

#[test]
fn test_single_block_execution() {
    let engine = NonceExecutionEngine::new();
    let mut adapter = InMemoryExecutionAdapter::new(engine);

    let sender_a = test_account_id(0xA1);
    let sender_b = test_account_id(0xB2);

    // Create block with multiple transactions
    let txs = vec![
        QbindTransaction::new(sender_a, 0, b"a0".to_vec()),
        QbindTransaction::new(sender_b, 0, b"b0".to_vec()),
        QbindTransaction::new(sender_a, 1, b"a1".to_vec()),
    ];

    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    // Apply block
    let result = adapter.apply_block(&block);
    assert!(result.is_ok(), "block execution should succeed");

    // Verify state
    assert_eq!(adapter.current_height(), 1);
    assert_eq!(get_account_nonce(adapter.state(), &sender_a), 2);
    assert_eq!(get_account_nonce(adapter.state(), &sender_b), 1);
}

// ============================================================================
// Part 5: Multi-Block Chain Tests
// ============================================================================

#[test]
fn test_multi_block_chain_execution() {
    let engine = NonceExecutionEngine::new();
    let mut adapter = InMemoryExecutionAdapter::new(engine);

    let sender = test_account_id(0xCC);

    // Block 1: nonce 0 -> 1
    let block1 = QbindBlock::new(
        make_test_proposal(1),
        vec![QbindTransaction::new(sender, 0, b"block1".to_vec())],
    );
    adapter.apply_block(&block1).unwrap();
    assert_eq!(adapter.current_height(), 1);
    assert_eq!(get_account_nonce(adapter.state(), &sender), 1);

    // Block 2: nonce 1 -> 2
    let block2 = QbindBlock::new(
        make_test_proposal(2),
        vec![QbindTransaction::new(sender, 1, b"block2".to_vec())],
    );
    adapter.apply_block(&block2).unwrap();
    assert_eq!(adapter.current_height(), 2);
    assert_eq!(get_account_nonce(adapter.state(), &sender), 2);

    // Block 3: multiple txs, nonce 2 -> 4
    let block3 = QbindBlock::new(
        make_test_proposal(3),
        vec![
            QbindTransaction::new(sender, 2, b"block3a".to_vec()),
            QbindTransaction::new(sender, 3, b"block3b".to_vec()),
        ],
    );
    adapter.apply_block(&block3).unwrap();
    assert_eq!(adapter.current_height(), 3);
    assert_eq!(get_account_nonce(adapter.state(), &sender), 4);
}

#[test]
fn test_multi_block_multiple_senders() {
    let engine = NonceExecutionEngine::new();
    let mut adapter = InMemoryExecutionAdapter::new(engine);

    let alice = test_account_id(0xAA);
    let bob = test_account_id(0xBB);
    let charlie = test_account_id(0xCC);

    // Block 1: alice and bob start
    let block1 = QbindBlock::new(
        make_test_proposal(1),
        vec![
            QbindTransaction::new(alice, 0, b"alice_0".to_vec()),
            QbindTransaction::new(bob, 0, b"bob_0".to_vec()),
        ],
    );
    adapter.apply_block(&block1).unwrap();

    // Block 2: charlie starts, alice continues
    let block2 = QbindBlock::new(
        make_test_proposal(2),
        vec![
            QbindTransaction::new(charlie, 0, b"charlie_0".to_vec()),
            QbindTransaction::new(alice, 1, b"alice_1".to_vec()),
        ],
    );
    adapter.apply_block(&block2).unwrap();

    // Block 3: all three transact
    let block3 = QbindBlock::new(
        make_test_proposal(3),
        vec![
            QbindTransaction::new(alice, 2, b"alice_2".to_vec()),
            QbindTransaction::new(bob, 1, b"bob_1".to_vec()),
            QbindTransaction::new(charlie, 1, b"charlie_1".to_vec()),
        ],
    );
    adapter.apply_block(&block3).unwrap();

    // Verify final nonces
    assert_eq!(get_account_nonce(adapter.state(), &alice), 3);
    assert_eq!(get_account_nonce(adapter.state(), &bob), 2);
    assert_eq!(get_account_nonce(adapter.state(), &charlie), 2);
}

// ============================================================================
// Part 6: Failure Path Tests
// ============================================================================

#[test]
fn test_block_with_invalid_tx_returns_error() {
    let engine = NonceExecutionEngine::new();
    let mut adapter = InMemoryExecutionAdapter::new(engine);

    let sender = test_account_id(0xDD);

    // Create block with invalid tx (wrong nonce)
    let block = QbindBlock::new(
        make_test_proposal(1),
        vec![
            QbindTransaction::new(sender, 5, b"wrong_nonce".to_vec()), // Expected 0
        ],
    );

    let result = adapter.apply_block(&block);
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert_eq!(err.height, 1);
    assert_eq!(err.tx_index, Some(0));
}

#[test]
fn test_partial_execution_on_error() {
    let engine = NonceExecutionEngine::new();
    let mut adapter = InMemoryExecutionAdapter::new(engine);

    let sender = test_account_id(0xEE);

    // Block with: valid tx, invalid tx, valid tx (never reached)
    let block = QbindBlock::new(
        make_test_proposal(1),
        vec![
            QbindTransaction::new(sender, 0, b"ok".to_vec()),
            QbindTransaction::new(sender, 5, b"bad".to_vec()), // Wrong nonce
            QbindTransaction::new(sender, 1, b"never".to_vec()),
        ],
    );

    let result = adapter.apply_block(&block);
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert_eq!(err.tx_index, Some(1)); // Error at second tx

    // First tx executed (nonce = 1), but block not marked as applied
    // (current_height should NOT be updated on error)
    assert_eq!(get_account_nonce(adapter.state(), &sender), 1);
    // Note: In T150, height is NOT updated on error
    assert_eq!(adapter.current_height(), 0);
}

// ============================================================================
// Part 7: Deterministic State Evolution Tests
// ============================================================================

#[test]
fn test_deterministic_state_evolution() {
    // Create two independent adapters with identical initial state
    let engine1 = NonceExecutionEngine::new();
    let engine2 = NonceExecutionEngine::new();
    let mut adapter1 = InMemoryExecutionAdapter::new(engine1);
    let mut adapter2 = InMemoryExecutionAdapter::new(engine2);

    let alice = test_account_id(0xAA);
    let bob = test_account_id(0xBB);

    // Apply same sequence of blocks to both
    let blocks = vec![
        QbindBlock::new(
            make_test_proposal(1),
            vec![
                QbindTransaction::new(alice, 0, b"a0".to_vec()),
                QbindTransaction::new(bob, 0, b"b0".to_vec()),
            ],
        ),
        QbindBlock::new(
            make_test_proposal(2),
            vec![
                QbindTransaction::new(bob, 1, b"b1".to_vec()),
                QbindTransaction::new(alice, 1, b"a1".to_vec()),
            ],
        ),
        QbindBlock::new(
            make_test_proposal(3),
            vec![QbindTransaction::new(alice, 2, b"a2".to_vec())],
        ),
    ];

    for block in &blocks {
        adapter1.apply_block(block).unwrap();
        adapter2.apply_block(block).unwrap();
    }

    // Verify identical final state
    assert_eq!(adapter1.current_height(), adapter2.current_height());
    assert_eq!(
        get_account_nonce(adapter1.state(), &alice),
        get_account_nonce(adapter2.state(), &alice)
    );
    assert_eq!(
        get_account_nonce(adapter1.state(), &bob),
        get_account_nonce(adapter2.state(), &bob)
    );

    // Verify expected values
    assert_eq!(get_account_nonce(adapter1.state(), &alice), 3);
    assert_eq!(get_account_nonce(adapter1.state(), &bob), 2);
}

// ============================================================================
// Part 8: Empty Block Tests
// ============================================================================

#[test]
fn test_empty_block_execution() {
    let engine = NonceExecutionEngine::new();
    let mut adapter = InMemoryExecutionAdapter::new(engine);

    // Apply several empty blocks
    for height in 1..=5 {
        let block = QbindBlock::empty(make_test_proposal(height));
        adapter.apply_block(&block).unwrap();
        assert_eq!(adapter.current_height(), height);
    }

    // State should remain empty (no accounts)
    assert!(adapter.state().is_empty());
}

#[test]
fn test_mixed_empty_and_tx_blocks() {
    let engine = NonceExecutionEngine::new();
    let mut adapter = InMemoryExecutionAdapter::new(engine);

    let sender = test_account_id(0xFF);

    // Block 1: empty
    adapter
        .apply_block(&QbindBlock::empty(make_test_proposal(1)))
        .unwrap();
    assert_eq!(adapter.current_height(), 1);
    assert_eq!(get_account_nonce(adapter.state(), &sender), 0);

    // Block 2: has tx
    adapter
        .apply_block(&QbindBlock::new(
            make_test_proposal(2),
            vec![QbindTransaction::new(sender, 0, b"tx".to_vec())],
        ))
        .unwrap();
    assert_eq!(get_account_nonce(adapter.state(), &sender), 1);

    // Block 3: empty
    adapter
        .apply_block(&QbindBlock::empty(make_test_proposal(3)))
        .unwrap();
    assert_eq!(get_account_nonce(adapter.state(), &sender), 1); // Unchanged
}
