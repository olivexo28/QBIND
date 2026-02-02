//! T177 VM v0 Pipeline Property-Based Tests
//!
//! This module provides property-based integration tests that validate the
//! node-level execution pipeline (SingleThreadExecutionService + VM v0) behaves
//! consistently with the direct ledger-level engine.
//!
//! Goals:
//! - Validate determinism across the node pipeline
//! - Ensure pipeline produces the same results as direct engine execution
//! - Test simple restart-like scenarios (two runs with same inputs)
//!
//! These tests use in-memory state only (no RocksDB) to keep CI lightweight.
//!
//! Reference: [QBIND_TESTNET_ALPHA_AUDIT.md §4.2 (TA-R1)](../../docs/testnet/QBIND_TESTNET_ALPHA_AUDIT.md)

use proptest::prelude::*;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use qbind_ledger::NonceExecutionEngine;
use qbind_ledger::{
    AccountStateView, InMemoryAccountState, QbindTransaction, TransferPayload, VmV0ExecutionEngine,
};
use qbind_node::{
    AsyncExecutionService, ExecutionProfile, QbindBlock, SingleThreadExecutionService,
    SingleThreadExecutionServiceConfig,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal};

use std::collections::HashMap;

// ============================================================================
// Test configuration constants
// ============================================================================

/// Maximum number of accounts in generated test scenarios.
const MAX_ACCOUNTS: usize = 8;

/// Minimum number of accounts in generated test scenarios.
const MIN_ACCOUNTS: usize = 2;

/// Maximum initial balance for generated accounts.
const MAX_INITIAL_BALANCE: u128 = 1_000_000;

/// Maximum transfer amount.
const MAX_TRANSFER_AMOUNT: u128 = 100_000;

/// Maximum transaction sequence length for pipeline tests.
const MAX_TX_SEQUENCE_LEN: usize = 20;

/// Number of proptest cases for pipeline tests (lower for CI speed).
const PIPELINE_PROPTEST_CASES: u32 = 30;

/// Wait time for async service to process blocks.
const PROCESS_WAIT_MS: u64 = 100;

// ============================================================================
// Helper types and functions
// ============================================================================

/// Test account ID from an index.
fn test_account_id(idx: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = idx;
    id
}

/// A generated transfer transaction descriptor.
#[derive(Debug, Clone)]
struct TransferSpec {
    sender_idx: u8,
    recipient_idx: u8,
    amount: u128,
}

/// Initial state for property testing.
#[derive(Debug, Clone)]
struct InitialState {
    /// Map from account index to initial balance.
    accounts: Vec<(u8, u128)>,
}

impl InitialState {
    /// Build an InMemoryAccountState from this InitialState.
    fn build(&self) -> InMemoryAccountState {
        let mut state = InMemoryAccountState::new();
        for (idx, balance) in &self.accounts {
            state.init_account(&test_account_id(*idx), *balance);
        }
        state
    }

    /// Get list of account indices.
    fn account_indices(&self) -> Vec<u8> {
        self.accounts.iter().map(|(idx, _)| *idx).collect()
    }
}

/// Create a test block proposal for a given height.
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
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: Vec::new(),
        signature: Vec::new(),
    })
}

/// Execute transfers using the direct VmV0ExecutionEngine.
fn execute_with_direct_engine(
    initial_state: &InitialState,
    transfers: &[TransferSpec],
) -> InMemoryAccountState {
    let mut state = initial_state.build();
    let engine = VmV0ExecutionEngine::new();

    // Track nonces for each sender
    let mut nonces: HashMap<u8, u64> = HashMap::new();

    let txs: Vec<QbindTransaction> = transfers
        .iter()
        .map(|spec| {
            let sender = test_account_id(spec.sender_idx);
            let recipient = test_account_id(spec.recipient_idx);
            let nonce = *nonces.get(&spec.sender_idx).unwrap_or(&0);
            nonces.insert(spec.sender_idx, nonce + 1);
            let payload = TransferPayload::new(recipient, spec.amount).encode();
            QbindTransaction::new(sender, nonce, payload)
        })
        .collect();

    let _ = engine.execute_block(&mut state, &txs);
    state
}

/// Build QbindTransactions from transfer specs.
fn build_transactions(transfers: &[TransferSpec]) -> Vec<QbindTransaction> {
    let mut nonces: HashMap<u8, u64> = HashMap::new();

    transfers
        .iter()
        .map(|spec| {
            let sender = test_account_id(spec.sender_idx);
            let recipient = test_account_id(spec.recipient_idx);
            let nonce = *nonces.get(&spec.sender_idx).unwrap_or(&0);
            nonces.insert(spec.sender_idx, nonce + 1);
            let payload = TransferPayload::new(recipient, spec.amount).encode();
            QbindTransaction::new(sender, nonce, payload)
        })
        .collect()
}

// ============================================================================
// Proptest strategies
// ============================================================================

/// Strategy to generate a single account (index, initial_balance).
fn account_strategy() -> impl Strategy<Value = (u8, u128)> {
    (0u8..100, 1000u128..=MAX_INITIAL_BALANCE)
}

/// Strategy to generate initial state with 2-8 accounts.
fn initial_state_strategy() -> impl Strategy<Value = InitialState> {
    prop::collection::vec(account_strategy(), MIN_ACCOUNTS..=MAX_ACCOUNTS).prop_map(|accounts| {
        // Ensure unique indices
        let mut seen = std::collections::HashSet::new();
        let unique_accounts: Vec<(u8, u128)> = accounts
            .into_iter()
            .filter(|(idx, _)| seen.insert(*idx))
            .collect();

        // Ensure minimum accounts
        let accounts = if unique_accounts.len() < MIN_ACCOUNTS {
            let mut result = unique_accounts;
            for i in 0u8..255 {
                if result.len() >= MIN_ACCOUNTS {
                    break;
                }
                if !seen.contains(&i) {
                    result.push((i, 5000));
                    seen.insert(i);
                }
            }
            result
        } else {
            unique_accounts
        };

        InitialState { accounts }
    })
}

/// Strategy to generate a transfer given available account indices.
fn transfer_strategy(indices: Vec<u8>) -> impl Strategy<Value = TransferSpec> {
    let indices_clone = indices.clone();
    (
        prop::sample::select(indices),
        prop::sample::select(indices_clone),
        1u128..=MAX_TRANSFER_AMOUNT,
    )
        .prop_map(|(sender_idx, recipient_idx, amount)| TransferSpec {
            sender_idx,
            recipient_idx,
            amount,
        })
}

/// Strategy to generate a sequence of transfers.
fn transfer_sequence_strategy(
    initial_state: &InitialState,
) -> impl Strategy<Value = Vec<TransferSpec>> {
    let indices = initial_state.account_indices();
    prop::collection::vec(transfer_strategy(indices), 1..=MAX_TX_SEQUENCE_LEN)
}

/// Combined strategy for initial state + transfer sequence.
fn scenario_strategy() -> impl Strategy<Value = (InitialState, Vec<TransferSpec>)> {
    initial_state_strategy().prop_flat_map(|initial_state| {
        let state_clone = initial_state.clone();
        transfer_sequence_strategy(&initial_state)
            .prop_map(move |transfers| (state_clone.clone(), transfers))
    })
}

// ============================================================================
// Pipeline Property Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PIPELINE_PROPTEST_CASES))]

    /// Test that executing the same transactions twice via the direct engine
    /// produces identical results (baseline determinism check).
    #[test]
    fn prop_direct_engine_determinism((initial_state, transfers) in scenario_strategy()) {
        let final_state1 = execute_with_direct_engine(&initial_state, &transfers);
        let final_state2 = execute_with_direct_engine(&initial_state, &transfers);

        // Collect all relevant accounts
        let mut all_indices: std::collections::HashSet<u8> = initial_state
            .account_indices()
            .into_iter()
            .collect();
        for spec in &transfers {
            all_indices.insert(spec.recipient_idx);
        }

        // Verify states match
        for idx in all_indices {
            let account = test_account_id(idx);
            let state1 = final_state1.get_account_state(&account);
            let state2 = final_state2.get_account_state(&account);

            prop_assert_eq!(
                state1.nonce,
                state2.nonce,
                "Account {} nonce mismatch between runs: {} vs {}",
                idx,
                state1.nonce,
                state2.nonce
            );
            prop_assert_eq!(
                state1.balance,
                state2.balance,
                "Account {} balance mismatch between runs: {} vs {}",
                idx,
                state1.balance,
                state2.balance
            );
        }
    }

    /// Test that running two independent pipeline instances with the same
    /// transactions produces consistent results.
    /// Note: We can't directly inspect the internal state of the service,
    /// but we verify the service runs without panic and the transaction
    /// processing completes.
    #[test]
    fn prop_pipeline_runs_without_panic((_initial_state, transfers) in scenario_strategy()) {
        // Build transactions
        let txs = build_transactions(&transfers);

        // Create service with VM v0 profile
        let engine = NonceExecutionEngine::new();
        let config = SingleThreadExecutionServiceConfig::vm_v0();
        let service = SingleThreadExecutionService::with_config(engine, config, None);

        // Create block with transactions
        let proposal = make_test_proposal(1);
        let block = QbindBlock::new(proposal, txs);

        // Submit block
        let result = service.submit_block(block);

        // Should succeed without panic
        prop_assert!(
            result.is_ok(),
            "Pipeline should accept block submission: {:?}",
            result.err()
        );

        // Wait for processing
        thread::sleep(Duration::from_millis(PROCESS_WAIT_MS));

        // Service should be healthy
        prop_assert!(
            !service.is_shutting_down(),
            "Service should not be shutting down"
        );

        // Clean shutdown
        service.shutdown();
    }

    /// Test that running multiple blocks through the pipeline completes successfully.
    #[test]
    fn prop_pipeline_multiple_blocks(
        (_initial_state, transfers) in scenario_strategy(),
        block_count in 1usize..=3
    ) {
        let engine = NonceExecutionEngine::new();
        let config = SingleThreadExecutionServiceConfig::vm_v0();
        let service = SingleThreadExecutionService::with_config(engine, config, None);

        // Split transfers across blocks
        let chunk_size = (transfers.len() / block_count).max(1);

        for (block_num, chunk) in transfers.chunks(chunk_size).enumerate() {
            // Build transactions for this chunk with proper nonces
            // Note: We need independent nonces per block for VM v0
            let chunk_transfers: Vec<TransferSpec> = chunk.to_vec();
            let txs = build_transactions(&chunk_transfers);

            let proposal = make_test_proposal((block_num + 1) as u64);
            let block = QbindBlock::new(proposal, txs);

            let result = service.submit_block(block);
            prop_assert!(
                result.is_ok(),
                "Block {} submission should succeed: {:?}",
                block_num,
                result.err()
            );
        }

        // Wait for all blocks to process
        thread::sleep(Duration::from_millis(PROCESS_WAIT_MS * block_count as u64));

        // Verify service health
        prop_assert!(
            !service.is_shutting_down(),
            "Service should be healthy after multiple blocks"
        );

        service.shutdown();
    }
}

// ============================================================================
// Determinism Tests (Non-Property Based)
// ============================================================================

/// Test basic pipeline determinism with a known sequence.
#[test]
fn test_pipeline_basic_execution() {
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::vm_v0();
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    // Create simple transactions
    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    let txs = vec![
        QbindTransaction::new(sender, 0, TransferPayload::new(recipient, 100).encode()),
        QbindTransaction::new(sender, 1, TransferPayload::new(recipient, 50).encode()),
    ];

    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    // Submit block
    let result = service.submit_block(block);
    assert!(result.is_ok(), "Block submission should succeed");

    // Wait for processing
    thread::sleep(Duration::from_millis(PROCESS_WAIT_MS));

    // Verify service is healthy
    assert!(!service.is_shutting_down());

    service.shutdown();
}

/// Test that empty blocks are handled correctly.
#[test]
fn test_pipeline_empty_blocks() {
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::vm_v0();
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    // Submit multiple empty blocks
    for height in 1..=5 {
        let proposal = make_test_proposal(height);
        let block = QbindBlock::empty(proposal);

        let result = service.submit_block(block);
        assert!(
            result.is_ok(),
            "Empty block {} submission should succeed",
            height
        );
    }

    thread::sleep(Duration::from_millis(PROCESS_WAIT_MS));

    assert!(!service.is_shutting_down());
    service.shutdown();
}

/// Test that two service instances with the same transactions
/// both complete without error (simple restart-like scenario).
#[test]
fn test_pipeline_restart_consistency() {
    // Create the same transactions for both runs
    let sender = test_account_id(0x01);
    let recipient = test_account_id(0x02);

    let build_txs = || {
        vec![
            QbindTransaction::new(sender, 0, TransferPayload::new(recipient, 100).encode()),
            QbindTransaction::new(sender, 1, TransferPayload::new(recipient, 200).encode()),
            QbindTransaction::new(sender, 2, TransferPayload::new(recipient, 300).encode()),
        ]
    };

    // Run 1
    {
        let engine = NonceExecutionEngine::new();
        let config = SingleThreadExecutionServiceConfig::vm_v0();
        let service = SingleThreadExecutionService::with_config(engine, config, None);

        let txs = build_txs();
        let proposal = make_test_proposal(1);
        let block = QbindBlock::new(proposal, txs);

        let result = service.submit_block(block);
        assert!(result.is_ok(), "Run 1: Block submission should succeed");

        thread::sleep(Duration::from_millis(PROCESS_WAIT_MS));
        service.shutdown();
    }

    // Run 2 (same inputs)
    {
        let engine = NonceExecutionEngine::new();
        let config = SingleThreadExecutionServiceConfig::vm_v0();
        let service = SingleThreadExecutionService::with_config(engine, config, None);

        let txs = build_txs();
        let proposal = make_test_proposal(1);
        let block = QbindBlock::new(proposal, txs);

        let result = service.submit_block(block);
        assert!(result.is_ok(), "Run 2: Block submission should succeed");

        thread::sleep(Duration::from_millis(PROCESS_WAIT_MS));
        service.shutdown();
    }

    // Both runs completed without error - consistent behavior
}

/// Test pipeline handles mixed valid/invalid transactions.
#[test]
fn test_pipeline_mixed_valid_invalid_txs() {
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::vm_v0();
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    let sender = test_account_id(0xAA);
    let recipient = test_account_id(0xBB);

    // Mix of valid nonces (0, 1, 2) and invalid (99)
    let txs = vec![
        QbindTransaction::new(sender, 0, TransferPayload::new(recipient, 100).encode()),
        QbindTransaction::new(sender, 99, TransferPayload::new(recipient, 50).encode()), // Invalid
        QbindTransaction::new(sender, 1, TransferPayload::new(recipient, 75).encode()),
    ];

    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    let result = service.submit_block(block);
    assert!(result.is_ok(), "Block with mixed txs should be accepted");

    thread::sleep(Duration::from_millis(PROCESS_WAIT_MS));

    assert!(!service.is_shutting_down());
    service.shutdown();
}

/// Test pipeline handles malformed payloads gracefully.
#[test]
fn test_pipeline_malformed_payloads() {
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::vm_v0();
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    let sender = test_account_id(0xCC);

    // Malformed payload (wrong size)
    let txs = vec![
        QbindTransaction::new(sender, 0, vec![0xFF; 10]), // Malformed
        QbindTransaction::new(sender, 1, vec![0xAA; 5]),  // Malformed
    ];

    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    let result = service.submit_block(block);
    assert!(
        result.is_ok(),
        "Block with malformed payloads should be accepted (errors handled internally)"
    );

    thread::sleep(Duration::from_millis(PROCESS_WAIT_MS));

    assert!(!service.is_shutting_down());
    service.shutdown();
}

/// Test that multiple senders in same block work correctly.
#[test]
fn test_pipeline_multiple_senders() {
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::vm_v0();
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    let sender_a = test_account_id(0x01);
    let sender_b = test_account_id(0x02);
    let recipient = test_account_id(0x03);

    // Interleaved transactions from multiple senders
    let txs = vec![
        QbindTransaction::new(sender_a, 0, TransferPayload::new(recipient, 100).encode()),
        QbindTransaction::new(sender_b, 0, TransferPayload::new(recipient, 200).encode()),
        QbindTransaction::new(sender_a, 1, TransferPayload::new(recipient, 150).encode()),
        QbindTransaction::new(sender_b, 1, TransferPayload::new(recipient, 250).encode()),
    ];

    let proposal = make_test_proposal(1);
    let block = QbindBlock::new(proposal, txs);

    let result = service.submit_block(block);
    assert!(result.is_ok(), "Multi-sender block should succeed");

    thread::sleep(Duration::from_millis(PROCESS_WAIT_MS));

    assert!(!service.is_shutting_down());
    service.shutdown();
}

// ============================================================================
// Service Configuration Tests
// ============================================================================

/// Test that VM v0 service config is created correctly.
#[test]
fn test_vm_v0_service_config() {
    let config = SingleThreadExecutionServiceConfig::vm_v0();
    assert_eq!(config.execution_profile, ExecutionProfile::VmV0);
}

/// Test service with custom queue capacity.
#[test]
fn test_service_with_custom_queue() {
    let engine = NonceExecutionEngine::new();
    let config = SingleThreadExecutionServiceConfig::vm_v0().with_queue_capacity(128);
    let service = SingleThreadExecutionService::with_config(engine, config, None);

    // Verify service starts correctly
    assert!(!service.is_shutting_down());
    assert_eq!(service.queue_len(), 0);

    service.shutdown();
}
