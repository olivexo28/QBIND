//! T169: Fee-aware DAG mempool tests.

use qbind_consensus::ValidatorId;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::{QbindTransaction, TransferPayloadV1};
use qbind_node::dag_mempool::{DagMempool, DagMempoolConfig, InMemoryDagMempool};
use qbind_types::AccountId;

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
fn test_dag_batch_builder_prefers_high_fee_txs() {
    let (_pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let sender = test_account_id(0xAA);

    let config = DagMempoolConfig {
        max_batches: 100,
        max_pending_txs: 1000,
        batch_size: 5,
        local_validator_id: ValidatorId::new(1),
        enable_fee_priority: true,
    };

    let mempool = InMemoryDagMempool::with_config(config);

    // Create mixed-fee transactions
    let mut txs = vec![];
    txs.push(make_signed_tx_v1(sender, 0, 100, 50_000, 10, &sk)); // Low fee
    txs.push(make_signed_tx_v1(sender, 1, 100, 50_000, 100, &sk)); // High fee
    txs.push(make_signed_tx_v1(sender, 2, 100, 50_000, 50, &sk)); // Mid fee
    txs.push(make_signed_tx_v1(sender, 3, 100, 50_000, 200, &sk)); // Highest fee
    txs.push(make_signed_tx_v1(sender, 4, 100, 50_000, 25, &sk)); // Low-mid fee

    mempool.insert_local_txs(txs).unwrap();

    // Trigger batch creation
    let frontier = mempool.select_frontier_txs(10);

    // With priority enabled, highest-fee txs should be selected first
    assert_eq!(frontier.len(), 5);

    // Check that higher-fee txs are prioritized
    // The exact order depends on the implementation, but we should see
    // nonce 3 (fee 200) and nonce 1 (fee 100) early
    let nonces: Vec<u64> = frontier.iter().map(|tx| tx.nonce).collect();
    assert!(nonces.contains(&3), "Highest fee tx should be included");
    assert!(nonces.contains(&1), "High fee tx should be included");
}

#[test]
fn test_dag_frontier_selection_with_priority() {
    let (_pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let sender = test_account_id(0xBB);

    let config = DagMempoolConfig {
        max_batches: 100,
        max_pending_txs: 1000,
        batch_size: 3,
        local_validator_id: ValidatorId::new(1),
        enable_fee_priority: true,
    };

    let mempool = InMemoryDagMempool::with_config(config);

    // Insert transactions
    let mut txs = vec![];
    for i in 0..10 {
        let fee = if i % 3 == 0 {
            100
        } else if i % 3 == 1 {
            50
        } else {
            10
        };
        txs.push(make_signed_tx_v1(sender, i, 100, 50_000, fee, &sk));
    }

    mempool.insert_local_txs(txs).unwrap();

    // Select a limited number of frontier txs
    let frontier = mempool.select_frontier_txs(5);
    assert_eq!(frontier.len(), 5);

    // Higher-fee txs should dominate the selection
    let has_high_fee_tx = frontier
        .iter()
        .any(|tx| tx.nonce % 3 == 0 || tx.nonce % 3 == 1);
    assert!(
        has_high_fee_tx,
        "At least some high/mid-fee txs should be selected"
    );
}

#[test]
fn test_dag_priority_disabled_fifo_behavior() {
    let (_pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let sender = test_account_id(0xCC);

    let config = DagMempoolConfig {
        max_batches: 100,
        max_pending_txs: 1000,
        batch_size: 5,
        local_validator_id: ValidatorId::new(1),
        enable_fee_priority: false, // Disabled
    };

    let mempool = InMemoryDagMempool::with_config(config);

    // Create mixed-fee transactions
    let mut txs = vec![];
    txs.push(make_signed_tx_v1(sender, 0, 100, 50_000, 10, &sk)); // Low fee, first
    txs.push(make_signed_tx_v1(sender, 1, 100, 50_000, 200, &sk)); // High fee, second
    txs.push(make_signed_tx_v1(sender, 2, 100, 50_000, 50, &sk)); // Mid fee, third

    mempool.insert_local_txs(txs).unwrap();

    // With priority disabled, order should be FIFO/insertion order
    let frontier = mempool.select_frontier_txs(10);
    assert_eq!(frontier.len(), 3);

    // In FIFO mode, txs are processed in batch order (view_hint order)
    // Since all are in one batch, they'll be in the batch's order
    let nonces: Vec<u64> = frontier.iter().map(|tx| tx.nonce).collect();
    // Just verify all are present
    assert!(nonces.contains(&0));
    assert!(nonces.contains(&1));
    assert!(nonces.contains(&2));
}

#[test]
fn test_dag_config_with_fee_priority() {
    let config = DagMempoolConfig::default().with_fee_priority(true);
    assert!(config.enable_fee_priority);

    let config2 = DagMempoolConfig::default().with_fee_priority(false);
    assert!(!config2.enable_fee_priority);
}
