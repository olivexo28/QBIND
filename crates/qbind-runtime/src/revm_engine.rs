//! Revm-based EVM execution engine for QBIND.
//!
//! This module provides the [`RevmExecutionEngine`] implementation that uses
//! the Revm crate as the underlying EVM implementation.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    QBIND Consensus                      │
//! │    (validates signatures, orders transactions)          │
//! └─────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              RevmExecutionEngine                        │
//! │    (implements ExecutionEngine trait)                   │
//! ├─────────────────────────────────────────────────────────┤
//! │  QbindTx → Revm TxEnv                                   │
//! │  QbindBlockEnv → Revm BlockEnv + CfgEnv                 │
//! │  StateView ← StateViewDb → Revm Database                │
//! └─────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                      Revm EVM                           │
//! │    (executes bytecode, applies state changes)           │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Determinism
//!
//! This implementation ensures deterministic execution by:
//! - Using only block timestamp from `QbindBlockEnv`, never wall clock time.
//! - Using `prev_randao` from block env for PREVRANDAO opcode.
//! - No external randomness sources.
//! - Consistent gas metering via Revm's built-in gas schedule.

use std::convert::Infallible;

use revm::bytecode::Bytecode;
use revm::context::{BlockEnv, Context, TxEnv};
use revm::context_interface::result::{ExecutionResult, HaltReason, Output};
use revm::database_interface::Database;
use revm::handler::{ExecuteCommitEvm, MainBuilder};
use revm::primitives::{Address as RevmAddress, Bytes, Log, TxKind, B256, U256 as RevmU256};
use revm::state::AccountInfo;

use crate::evm_types::{Address, EvmAccountState, LogEntry, U256};
use crate::execution_engine::{EvmExecutionError, ExecutionEngine, StateView, TxReceipt};
use crate::qbind_tx::{EvmBlockExecutionResult, QbindBlockEnv, QbindTx};

use std::collections::HashMap;

/// Configuration for the Revm execution engine.
#[derive(Clone, Debug)]
pub struct RevmConfig {
    /// Chain ID for EIP-155 replay protection.
    pub chain_id: u64,
}

impl Default for RevmConfig {
    fn default() -> Self {
        RevmConfig { chain_id: 1337 }
    }
}

impl RevmConfig {
    /// Create a new config with the specified chain ID.
    pub fn new(chain_id: u64) -> Self {
        RevmConfig { chain_id }
    }
}

/// Revm-based execution engine for QBIND.
///
/// This struct wraps Revm and implements the [`ExecutionEngine`] trait.
/// It provides deterministic EVM execution for QBIND blocks.
pub struct RevmExecutionEngine {
    config: RevmConfig,
}

impl RevmExecutionEngine {
    /// Create a new Revm execution engine with the given configuration.
    pub fn new(config: RevmConfig) -> Self {
        RevmExecutionEngine { config }
    }

    /// Create a new engine with default configuration.
    pub fn default_config() -> Self {
        RevmExecutionEngine::new(RevmConfig::default())
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }
}

impl ExecutionEngine for RevmExecutionEngine {
    type Tx = QbindTx;
    type BlockEnv = QbindBlockEnv;
    type Receipt = TxReceipt;
    type ExecutionError = EvmExecutionError;

    fn execute_block(
        &self,
        block_env: &Self::BlockEnv,
        state: &mut dyn StateView,
        txs: &[Self::Tx],
    ) -> Result<Vec<Self::Receipt>, Self::ExecutionError> {
        let mut receipts = Vec::with_capacity(txs.len());
        let mut cumulative_gas_used: u64 = 0;

        // Create a mutable wrapper around the state view
        let mut state_db = StateViewDb::new(state);

        for tx in txs {
            let receipt = execute_single_tx(
                &self.config,
                block_env,
                &mut state_db,
                tx,
                cumulative_gas_used,
            )?;

            cumulative_gas_used = receipt.cumulative_gas_used;
            receipts.push(receipt);
        }

        // Apply all accumulated changes back to the state view
        state_db.apply_changes();

        Ok(receipts)
    }
}

/// Execute a single transaction using Revm.
fn execute_single_tx(
    _config: &RevmConfig,
    block_env: &QbindBlockEnv,
    db: &mut StateViewDb<'_>,
    tx: &QbindTx,
    cumulative_gas_before: u64,
) -> Result<TxReceipt, EvmExecutionError> {
    // Validate transaction basics
    validate_tx(db, tx)?;

    // Compute effective gas price per EIP-1559:
    // effective_gas_price = basefee + min(max_priority_fee, max_fee - basefee)
    let effective_gas_price = tx.effective_gas_price(block_env.basefee);

    // Build Revm environment
    let revm_block_env = build_revm_block_env(block_env);
    let revm_tx_env = build_revm_tx_env(tx, block_env.chain_id);

    // Use CANCUN spec (latest stable)
    use revm::context::Journal;
    use revm::primitives::hardfork::SpecId;
    let spec = SpecId::CANCUN;

    // Create the context with spec directly, specifying the Journal type
    let mut ctx: Context<
        BlockEnv,
        TxEnv,
        _,
        &mut StateViewDb<'_>,
        Journal<&mut StateViewDb<'_>>,
        (),
        _,
    > = Context::new(db, spec);
    ctx.block = revm_block_env;
    ctx.tx = revm_tx_env.clone();
    ctx.cfg.chain_id = block_env.chain_id;

    // Build and run the EVM
    let mut evm = ctx.build_mainnet();

    // Execute the transaction with commit
    let result = evm.transact_commit(revm_tx_env);

    match result {
        Ok(exec_result) => {
            process_execution_result(exec_result, tx, cumulative_gas_before, effective_gas_price)
        }
        Err(e) => Err(EvmExecutionError::InternalError(format!(
            "Revm error: {:?}",
            e
        ))),
    }
}

/// Validate basic transaction properties before execution.
fn validate_tx(db: &StateViewDb<'_>, tx: &QbindTx) -> Result<(), EvmExecutionError> {
    // Check sender account
    let sender_state = db.state_view.get_account(&tx.from);
    let sender_nonce = sender_state.as_ref().map(|a| a.nonce).unwrap_or(0);
    let sender_balance = sender_state
        .as_ref()
        .map(|a| a.balance)
        .unwrap_or(U256::zero());

    // Check nonce
    if tx.nonce != sender_nonce {
        return Err(EvmExecutionError::InvalidTransaction(format!(
            "invalid nonce: expected {}, got {}",
            sender_nonce, tx.nonce
        )));
    }

    // Check balance for max possible cost
    if let Some(max_cost) = tx.max_cost() {
        if sender_balance.checked_sub(&max_cost).is_none() {
            return Err(EvmExecutionError::InvalidTransaction(
                "insufficient balance for gas + value".to_string(),
            ));
        }
    } else {
        return Err(EvmExecutionError::InvalidTransaction(
            "transaction cost overflow".to_string(),
        ));
    }

    Ok(())
}

/// Build Revm block environment from QBIND block environment.
fn build_revm_block_env(block_env: &QbindBlockEnv) -> BlockEnv {
    use revm::context_interface::block::BlobExcessGasAndPrice;

    BlockEnv {
        number: RevmU256::from(block_env.number),
        timestamp: RevmU256::from(block_env.timestamp),
        beneficiary: qbind_addr_to_revm(&block_env.coinbase),
        gas_limit: block_env.gas_limit,
        basefee: block_env.basefee as u64,
        difficulty: RevmU256::ZERO,
        prevrandao: Some(B256::from(
            qbind_u256_to_revm(&block_env.prev_randao).to_be_bytes(),
        )),
        // Set blob excess gas for Cancun+ compatibility (no blobs, so excess = 0)
        blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new(0, 3338477)),
    }
}

/// Build Revm transaction environment from QBIND transaction.
fn build_revm_tx_env(tx: &QbindTx, chain_id: u64) -> TxEnv {
    let kind = match tx.to {
        Some(addr) => TxKind::Call(qbind_addr_to_revm(&addr)),
        None => TxKind::Create,
    };

    TxEnv {
        tx_type: 2, // EIP-1559 transaction
        caller: qbind_addr_to_revm(&tx.from),
        gas_limit: tx.gas_limit,
        gas_price: tx.max_fee_per_gas,
        kind,
        value: qbind_u256_to_revm(&tx.value),
        data: Bytes::from(tx.data.clone()),
        nonce: tx.nonce,
        chain_id: Some(chain_id),
        access_list: Default::default(),
        gas_priority_fee: Some(tx.max_priority_fee_per_gas),
        blob_hashes: Vec::new(),
        max_fee_per_blob_gas: 0,
        authorization_list: Vec::new(),
    }
}

/// Process Revm execution result into a QBIND transaction receipt.
fn process_execution_result(
    result: ExecutionResult,
    tx: &QbindTx,
    cumulative_gas_before: u64,
    effective_gas_price: u128,
) -> Result<TxReceipt, EvmExecutionError> {
    match result {
        ExecutionResult::Success {
            gas_used,
            output,
            logs,
            ..
        } => {
            let output_data = match &output {
                Output::Call(data) => data.to_vec(),
                Output::Create(data, _) => data.to_vec(),
            };

            let cumulative_gas_used = cumulative_gas_before.saturating_add(gas_used);
            let converted_logs: Vec<LogEntry> = logs.into_iter().map(revm_log_to_qbind).collect();

            let mut receipt = TxReceipt::success(
                gas_used,
                cumulative_gas_used,
                effective_gas_price,
                converted_logs,
                output_data,
            );

            // If this was a contract creation, get the contract address
            if tx.is_contract_creation() {
                if let Output::Create(_, Some(addr)) = output {
                    receipt = receipt.with_contract_address(revm_addr_to_qbind(&addr));
                }
            }

            Ok(receipt)
        }
        ExecutionResult::Revert { gas_used, output } => {
            let cumulative_gas_used = cumulative_gas_before.saturating_add(gas_used);
            let mut receipt = TxReceipt::failure(
                gas_used,
                cumulative_gas_used,
                effective_gas_price,
                EvmExecutionError::Revert {
                    output: output.to_vec(),
                },
            );
            receipt.output = output.to_vec();
            Ok(receipt)
        }
        ExecutionResult::Halt { gas_used, reason } => {
            let cumulative_gas_used = cumulative_gas_before.saturating_add(gas_used);
            let error = halt_reason_to_error(reason, tx.gas_limit, gas_used);
            Ok(TxReceipt::failure(
                gas_used,
                cumulative_gas_used,
                effective_gas_price,
                error,
            ))
        }
    }
}

/// Convert Revm halt reason to QBIND execution error.
fn halt_reason_to_error(reason: HaltReason, gas_limit: u64, gas_used: u64) -> EvmExecutionError {
    match reason {
        HaltReason::OutOfGas(_) => EvmExecutionError::OutOfGas {
            gas_limit,
            gas_used,
        },
        HaltReason::OpcodeNotFound => EvmExecutionError::InvalidOpcode(0),
        HaltReason::InvalidFEOpcode => EvmExecutionError::InvalidOpcode(0xFE),
        HaltReason::InvalidJump => EvmExecutionError::InvalidJump,
        HaltReason::StackUnderflow => EvmExecutionError::StackUnderflow,
        HaltReason::StackOverflow => EvmExecutionError::StackOverflow,
        HaltReason::CallTooDeep => EvmExecutionError::CallDepthExceeded,
        HaltReason::StateChangeDuringStaticCall => EvmExecutionError::StaticCallViolation,
        HaltReason::CreateContractSizeLimit => {
            EvmExecutionError::ContractCreationFailed("contract size limit exceeded".to_string())
        }
        HaltReason::CreateContractStartingWithEF => {
            EvmExecutionError::ContractCreationFailed("contract starts with 0xEF".to_string())
        }
        HaltReason::CreateInitCodeSizeLimit => {
            EvmExecutionError::ContractCreationFailed("init code size limit exceeded".to_string())
        }
        _ => EvmExecutionError::InternalError(format!("halt: {:?}", reason)),
    }
}

/// Convert Revm log to QBIND log entry.
fn revm_log_to_qbind(log: Log) -> LogEntry {
    LogEntry {
        address: revm_addr_to_qbind(&log.address),
        topics: log
            .data
            .topics()
            .iter()
            .map(|t| U256::from_bytes(t.0))
            .collect(),
        data: log.data.data.to_vec(),
    }
}

// ============================================================================
// Type conversions between QBIND and Revm types
// ============================================================================

fn qbind_addr_to_revm(addr: &Address) -> RevmAddress {
    RevmAddress::from_slice(addr.as_bytes())
}

fn revm_addr_to_qbind(addr: &RevmAddress) -> Address {
    Address::from_slice(addr.as_slice())
}

fn qbind_u256_to_revm(value: &U256) -> RevmU256 {
    RevmU256::from_be_bytes(*value.as_bytes())
}

fn revm_u256_to_qbind(value: RevmU256) -> U256 {
    U256::from_bytes(value.to_be_bytes())
}

// ============================================================================
// StateViewDb: Adapter implementing Revm's Database trait
// ============================================================================

/// Adapter that implements Revm's Database trait using QBIND's StateView.
struct StateViewDb<'a> {
    state_view: &'a mut dyn StateView,
    /// Pending state changes to apply after execution
    pending_changes: HashMap<Address, EvmAccountState>,
    /// Pending storage changes
    pending_storage: HashMap<(Address, U256), U256>,
}

impl<'a> StateViewDb<'a> {
    fn new(state_view: &'a mut dyn StateView) -> Self {
        StateViewDb {
            state_view,
            pending_changes: HashMap::new(),
            pending_storage: HashMap::new(),
        }
    }

    /// Apply all pending changes to the underlying state view.
    fn apply_changes(&mut self) {
        // Apply account changes
        for (addr, account) in self.pending_changes.drain() {
            self.state_view.put_account(&addr, account);
        }

        // Apply storage changes
        for ((addr, key), value) in self.pending_storage.drain() {
            self.state_view.set_storage(&addr, key, value);
        }
    }

    /// Get account from pending changes or underlying state.
    fn get_account_internal(&self, addr: &Address) -> Option<EvmAccountState> {
        self.pending_changes
            .get(addr)
            .cloned()
            .or_else(|| self.state_view.get_account(addr))
    }
}

impl Database for StateViewDb<'_> {
    type Error = Infallible;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let qbind_addr = revm_addr_to_qbind(&address);
        let account_opt = self.get_account_internal(&qbind_addr);

        Ok(account_opt.map(|acc| AccountInfo {
            balance: qbind_u256_to_revm(&acc.balance),
            nonce: acc.nonce,
            code_hash: if acc.code.is_empty() {
                revm::primitives::KECCAK_EMPTY
            } else {
                B256::from_slice(&qbind_hash::sha3_256(&acc.code))
            },
            account_id: None,
            code: if acc.code.is_empty() {
                None
            } else {
                Some(Bytecode::new_legacy(Bytes::from(acc.code.clone())))
            },
        }))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // We include code in AccountInfo, so this shouldn't be called often
        Ok(Bytecode::default())
    }

    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256, Self::Error> {
        let qbind_addr = revm_addr_to_qbind(&address);
        let qbind_key = revm_u256_to_qbind(index);

        // Check pending storage first
        if let Some(value) = self.pending_storage.get(&(qbind_addr, qbind_key)) {
            return Ok(qbind_u256_to_revm(value));
        }

        // Then check underlying state
        let value = self.state_view.get_storage(&qbind_addr, &qbind_key);
        Ok(qbind_u256_to_revm(&value))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        // For simplicity, return a deterministic hash based on block number
        // In production, this should query historical block hashes
        let mut hash = [0u8; 32];
        hash[24..32].copy_from_slice(&number.to_be_bytes());
        Ok(B256::from(hash))
    }
}

impl revm::database_interface::DatabaseCommit for StateViewDb<'_> {
    fn commit(
        &mut self,
        changes: revm::primitives::map::HashMap<RevmAddress, revm::state::Account>,
    ) {
        for (addr, account) in changes {
            let qbind_addr = revm_addr_to_qbind(&addr);

            // Convert account info
            // Note: We must check if the code is actually empty (not just default Bytecode)
            // because default Bytecode contains a STOP opcode which would make is_empty() false
            let code = match &account.info.code {
                Some(bytecode) if !bytecode.is_empty() => bytecode.bytes().to_vec(),
                _ => Vec::new(),
            };

            let mut qbind_account = EvmAccountState {
                balance: revm_u256_to_qbind(account.info.balance),
                nonce: account.info.nonce,
                code,
                storage: HashMap::new(),
            };

            // Apply storage changes
            for (key, slot) in account.storage {
                let qbind_key = revm_u256_to_qbind(key);
                let qbind_value = revm_u256_to_qbind(slot.present_value);

                if qbind_value.is_zero() {
                    qbind_account.storage.remove(&qbind_key);
                } else {
                    qbind_account.storage.insert(qbind_key, qbind_value);
                }

                // Also track in pending_storage for subsequent reads
                self.pending_storage
                    .insert((qbind_addr, qbind_key), qbind_value);
            }

            self.pending_changes.insert(qbind_addr, qbind_account);
        }
    }
}

// ============================================================================
// Top-level block execution API
// ============================================================================

/// Execute a QBIND block of transactions.
///
/// This is the main entry point for block execution. It creates a
/// `RevmExecutionEngine` internally and executes all transactions.
///
/// # Arguments
///
/// * `engine` - The execution engine to use.
/// * `block_env` - Block-level context.
/// * `state` - Mutable state view.
/// * `txs` - Transactions to execute.
///
/// # Returns
///
/// A `EvmBlockExecutionResult` containing receipts and aggregate data.
pub fn execute_qbind_block<E>(
    engine: &E,
    block_env: &E::BlockEnv,
    state: &mut dyn StateView,
    txs: &[E::Tx],
) -> Result<EvmBlockExecutionResult, E::ExecutionError>
where
    E: ExecutionEngine<Tx = QbindTx, BlockEnv = QbindBlockEnv, Receipt = TxReceipt>,
{
    let receipts = engine.execute_block(block_env, state, txs)?;
    Ok(EvmBlockExecutionResult::new(receipts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revm_config_default() {
        let config = RevmConfig::default();
        assert_eq!(config.chain_id, 1337);
    }

    #[test]
    fn test_revm_engine_creation() {
        let engine = RevmExecutionEngine::new(RevmConfig::new(42));
        assert_eq!(engine.chain_id(), 42);
    }

    #[test]
    fn test_type_conversions() {
        let addr = Address::from_bytes([1u8; 20]);
        let revm_addr = qbind_addr_to_revm(&addr);
        let back = revm_addr_to_qbind(&revm_addr);
        assert_eq!(addr, back);

        let value = U256::from_u64(12345);
        let revm_value = qbind_u256_to_revm(&value);
        let back = revm_u256_to_qbind(revm_value);
        assert_eq!(value, back);
    }
}
