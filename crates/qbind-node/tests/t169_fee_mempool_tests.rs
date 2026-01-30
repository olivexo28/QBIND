//! T169: Fee-aware mempool priority and eviction tests.

use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::{
    compute_gas_for_vm_v0_tx, ExecutionGasConfig, QbindTransaction, TransferPayloadV1,
    UserPublicKey,
};
use qbind_node::mempool::{
    compute_tx_mempool_cost, InMemoryBalanceProvider, InMemoryKeyProvider, InMemoryMempool,
    Mempool, MempoolConfig, MempoolError, TxPriorityScore,
};
use qbind_types::AccountId;
use std::sync::Arc;

fn test_account_id(byte: u8) -> AccountId {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

fn make_signed_tx_v1(
    sender: AccountId,
    nonce: u64,
    amount: u128,
    gas_limit: u64,
    max_fee_per_gas: u128,
    sk: &[u8],
) -> QbindTransaction {
    let recipient = test_account_id(0xFF);
    let payload = TransferPayloadV1::new(recipient, amount, gas_limit, max_fee_per_gas);
    let mut tx = QbindTransaction::new(sender, nonce, payload.encode());
    tx.sign(sk).expect("signing should succeed");
    tx
}

#[test]
fn test_priority_score_ordering() {
    // Higher fee_per_gas comes first
    let score1 = TxPriorityScore {
        fee_per_gas: 100,
        effective_fee: 5000,
        arrival_id: 0,
    };
    let score2 = TxPriorityScore {
        fee_per_gas: 200,
        effective_fee: 4000,
        arrival_id: 1,
    };
    assert!(score2 > score1, "Higher fee_per_gas should be greater");

    // Same fee_per_gas, higher effective_fee comes first
    let score3 = TxPriorityScore {
        fee_per_gas: 100,
        effective_fee: 6000,
        arrival_id: 2,
    };
    assert!(
        score3 > score1,
        "Same fee_per_gas, higher effective_fee should be greater"
    );

    // Same fee and effective_fee, lower arrival_id comes first
    let score4 = TxPriorityScore {
        fee_per_gas: 100,
        effective_fee: 5000,
        arrival_id: 3,
    };
    assert!(
        score1 > score4,
        "Same fee/effective_fee, earlier arrival should be greater"
    );
}

#[test]
fn test_fifo_priority_orders_by_fee_descending() {
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = UserPublicKey::ml_dsa_44(pk_bytes);
    let sender = test_account_id(0xAA);

    let mut key_provider = InMemoryKeyProvider::new();
    key_provider.register(sender, pk);

    let balance_provider = Arc::new(InMemoryBalanceProvider::new());
    balance_provider.set_balance(sender, 10_000_000); // Enough for fee

    let config = MempoolConfig {
        max_txs: 10,
        max_nonce_gap: 1000,
        gas_config: Some(ExecutionGasConfig::enabled()),
        enable_fee_priority: true,
    };

    let mempool = InMemoryMempool::with_providers(config, Arc::new(key_provider), balance_provider);

    // Insert transactions with different fees
    let tx1 = make_signed_tx_v1(sender, 0, 100, 50_000, 10, &sk); // Low fee
    let tx2 = make_signed_tx_v1(sender, 1, 100, 50_000, 100, &sk); // High fee
    let tx3 = make_signed_tx_v1(sender, 2, 100, 50_000, 50, &sk); // Mid fee

    mempool.insert(tx1).unwrap();
    mempool.insert(tx2.clone()).unwrap();
    mempool.insert(tx3.clone()).unwrap();

    // Get candidates - should be ordered by fee (descending)
    let candidates = mempool.get_block_candidates(10);
    assert_eq!(candidates.len(), 3);
    // Highest fee first
    assert_eq!(candidates[0].nonce, tx2.nonce);
    assert_eq!(candidates[1].nonce, tx3.nonce);
    assert_eq!(candidates[2].nonce, 0); // Lowest fee last
}

#[test]
fn test_fifo_priority_eviction_drops_lowest_fee() {
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = UserPublicKey::ml_dsa_44(pk_bytes);
    let sender = test_account_id(0xBB);

    let mut key_provider = InMemoryKeyProvider::new();
    key_provider.register(sender, pk);

    let balance_provider = Arc::new(InMemoryBalanceProvider::new());
    balance_provider.set_balance(sender, 10_000_000); // Enough for fee

    let config = MempoolConfig {
        max_txs: 2, // Only room for 2 txs
        max_nonce_gap: 1000,
        gas_config: Some(ExecutionGasConfig::enabled()),
        enable_fee_priority: true,
    };

    let mempool = InMemoryMempool::with_providers(config, Arc::new(key_provider), balance_provider);

    // Insert two low-fee txs
    let tx1 = make_signed_tx_v1(sender, 0, 100, 50_000, 10, &sk);
    let tx2 = make_signed_tx_v1(sender, 1, 100, 50_000, 20, &sk);
    mempool.insert(tx1).unwrap();
    mempool.insert(tx2).unwrap();
    assert_eq!(mempool.size(), 2);

    // Insert a high-fee tx - should evict lowest
    let tx3 = make_signed_tx_v1(sender, 2, 100, 50_000, 100, &sk);
    mempool.insert(tx3.clone()).unwrap();

    // Should still be size 2 (evicted one)
    assert_eq!(mempool.size(), 2);

    // Check that lowest fee (nonce 0) was evicted
    let candidates = mempool.get_block_candidates(10);
    assert_eq!(candidates.len(), 2);
    // Only tx2 and tx3 should remain
    let nonces: Vec<u64> = candidates.iter().map(|tx| tx.nonce).collect();
    assert!(nonces.contains(&1));
    assert!(nonces.contains(&2));
    assert!(!nonces.contains(&0));
}

#[test]
fn test_fifo_priority_rejects_low_priority_tx() {
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = UserPublicKey::ml_dsa_44(pk_bytes);
    let sender = test_account_id(0xCC);

    let mut key_provider = InMemoryKeyProvider::new();
    key_provider.register(sender, pk);

    let balance_provider = Arc::new(InMemoryBalanceProvider::new());
    balance_provider.set_balance(sender, 10_000_000); // Enough for fee

    let config = MempoolConfig {
        max_txs: 2,
        max_nonce_gap: 1000,
        gas_config: Some(ExecutionGasConfig::enabled()),
        enable_fee_priority: true,
    };

    let mempool = InMemoryMempool::with_providers(config, Arc::new(key_provider), balance_provider);

    // Fill with high-fee txs
    let tx1 = make_signed_tx_v1(sender, 0, 100, 50_000, 100, &sk);
    let tx2 = make_signed_tx_v1(sender, 1, 100, 50_000, 90, &sk);
    mempool.insert(tx1).unwrap();
    mempool.insert(tx2).unwrap();

    // Try to insert a low-fee tx - should be rejected
    let tx3 = make_signed_tx_v1(sender, 2, 100, 50_000, 10, &sk);
    let result = mempool.insert(tx3);
    assert!(
        matches!(result, Err(MempoolError::LowPriorityDropped)),
        "Low priority tx should be dropped"
    );
    assert_eq!(mempool.size(), 2);
}

#[test]
fn test_fifo_priority_respects_disabled_flag() {
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = UserPublicKey::ml_dsa_44(pk_bytes);
    let sender = test_account_id(0xDD);

    let mut key_provider = InMemoryKeyProvider::new();
    key_provider.register(sender, pk);

    let balance_provider = Arc::new(InMemoryBalanceProvider::new());
    balance_provider.set_balance(sender, 10_000_000); // Enough for fee

    let config = MempoolConfig {
        max_txs: 10,
        max_nonce_gap: 1000,
        gas_config: Some(ExecutionGasConfig::enabled()),
        enable_fee_priority: false, // Disabled
    };

    let mempool = InMemoryMempool::with_providers(config, Arc::new(key_provider), balance_provider);

    // Insert transactions with different fees
    let tx1 = make_signed_tx_v1(sender, 0, 100, 50_000, 10, &sk); // Low fee
    let tx2 = make_signed_tx_v1(sender, 1, 100, 50_000, 100, &sk); // High fee
    let tx3 = make_signed_tx_v1(sender, 2, 100, 50_000, 50, &sk); // Mid fee

    mempool.insert(tx1.clone()).unwrap();
    mempool.insert(tx2).unwrap();
    mempool.insert(tx3).unwrap();

    // Get candidates - should be ordered by insertion (FIFO), not fee
    let candidates = mempool.get_block_candidates(10);
    assert_eq!(candidates.len(), 3);
    // FIFO order
    assert_eq!(candidates[0].nonce, tx1.nonce);
    assert_eq!(candidates[1].nonce, 1);
    assert_eq!(candidates[2].nonce, 2);
}

#[test]
fn test_gas_disabled_forces_priority_off() {
    let config = MempoolConfig {
        max_txs: 10,
        max_nonce_gap: 1000,
        gas_config: None, // Gas disabled
        enable_fee_priority: true,
    };

    let enforced = config.enforce_constraints();
    assert!(
        !enforced.enable_fee_priority,
        "Fee priority should be disabled when gas is disabled"
    );
}

#[test]
fn test_compute_tx_mempool_cost() {
    let sender = test_account_id(0xEE);
    let (_pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");

    let tx = make_signed_tx_v1(sender, 0, 1000, 50_000, 100, &sk);

    let cost = compute_tx_mempool_cost(&tx).expect("should compute cost");
    assert_eq!(cost.gas_limit, 50_000);
    assert_eq!(cost.max_fee_per_gas, 100);
    assert_eq!(cost.fee_per_gas, 100);
    assert_eq!(cost.effective_fee, 50_000 * 100);

    // Verify gas cost is reasonable
    let gas_result = compute_gas_for_vm_v0_tx(&tx).expect("should compute gas");
    assert_eq!(cost.gas_cost, gas_result.gas_cost);
}
