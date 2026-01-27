//! Execution engine traits for QBIND.
//!
//! This module defines the core abstractions for executing EVM transactions
//! within the QBIND blockchain. The design separates the execution engine
//! interface from the underlying VM implementation (e.g., Revm).
//!
//! ## Design Goals
//!
//! - **Abstraction**: `ExecutionEngine` is generic over transaction type and block environment.
//! - **Determinism**: Execution must be deterministic across validators (no time, randomness).
//! - **Isolation**: The EVM is isolated behind `StateView`, allowing different state backends.
//!
//! ## Key Traits
//!
//! - [`ExecutionEngine`]: Core trait for block-level execution.
//! - [`StateView`]: Abstraction for account/storage state access.

use crate::evm_types::{Address, EvmAccountState, U256};
use std::fmt;

/// Trait for accessing and modifying EVM state.
///
/// `StateView` provides the abstraction layer between the execution engine
/// and the underlying state storage (in-memory, persistent, etc.).
///
/// Implementors must ensure that all operations are deterministic and
/// maintain consistency between `get_account` and `put_account` calls.
pub trait StateView {
    /// Retrieve the account state for an address.
    ///
    /// Returns `None` if the account does not exist (equivalent to an
    /// empty account with zero balance, zero nonce, no code).
    fn get_account(&self, addr: &Address) -> Option<EvmAccountState>;

    /// Store or update an account's state.
    ///
    /// If the account state is empty (zero balance, zero nonce, no code),
    /// the implementation may choose to delete the account.
    fn put_account(&mut self, addr: &Address, account: EvmAccountState);

    /// Get a storage slot value for a contract.
    ///
    /// Default implementation delegates to `get_account` and reads from
    /// the account's storage map. Returns zero if account or slot doesn't exist.
    fn get_storage(&self, addr: &Address, key: &U256) -> U256 {
        self.get_account(addr)
            .map(|acc| acc.get_storage(key))
            .unwrap_or(U256::zero())
    }

    /// Set a storage slot value for a contract.
    ///
    /// Default implementation retrieves the account, modifies storage,
    /// and writes back. Creates account if it doesn't exist.
    fn set_storage(&mut self, addr: &Address, key: U256, value: U256) {
        let mut account = self.get_account(addr).unwrap_or_default();
        account.set_storage(key, value);
        self.put_account(addr, account);
    }

    /// Get the code for a contract address.
    ///
    /// Default implementation retrieves from account state.
    fn get_code(&self, addr: &Address) -> Vec<u8> {
        self.get_account(addr)
            .map(|acc| acc.code.clone())
            .unwrap_or_default()
    }

    /// Check if an account exists (is non-empty).
    fn account_exists(&self, addr: &Address) -> bool {
        self.get_account(addr)
            .map(|acc| !acc.is_empty())
            .unwrap_or(false)
    }
}

/// Errors that can occur during EVM execution.
#[derive(Debug, Clone)]
pub enum EvmExecutionError {
    /// Transaction ran out of gas.
    OutOfGas { gas_limit: u64, gas_used: u64 },

    /// Transaction reverted (REVERT opcode).
    Revert { output: Vec<u8> },

    /// Invalid transaction (bad nonce, insufficient balance, etc.).
    InvalidTransaction(String),

    /// Contract creation failed.
    ContractCreationFailed(String),

    /// Invalid opcode encountered.
    InvalidOpcode(u8),

    /// Stack underflow during execution.
    StackUnderflow,

    /// Stack overflow during execution.
    StackOverflow,

    /// Invalid jump destination.
    InvalidJump,

    /// State modification in static context.
    StaticCallViolation,

    /// Call depth exceeded.
    CallDepthExceeded,

    /// Internal error in the execution engine.
    InternalError(String),
}

impl fmt::Display for EvmExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvmExecutionError::OutOfGas {
                gas_limit,
                gas_used,
            } => {
                write!(f, "out of gas: limit={}, used={}", gas_limit, gas_used)
            }
            EvmExecutionError::Revert { output } => {
                write!(f, "transaction reverted: {} bytes output", output.len())
            }
            EvmExecutionError::InvalidTransaction(msg) => {
                write!(f, "invalid transaction: {}", msg)
            }
            EvmExecutionError::ContractCreationFailed(msg) => {
                write!(f, "contract creation failed: {}", msg)
            }
            EvmExecutionError::InvalidOpcode(op) => {
                write!(f, "invalid opcode: 0x{:02x}", op)
            }
            EvmExecutionError::StackUnderflow => write!(f, "stack underflow"),
            EvmExecutionError::StackOverflow => write!(f, "stack overflow"),
            EvmExecutionError::InvalidJump => write!(f, "invalid jump destination"),
            EvmExecutionError::StaticCallViolation => {
                write!(f, "state modification in static call")
            }
            EvmExecutionError::CallDepthExceeded => write!(f, "call depth exceeded"),
            EvmExecutionError::InternalError(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for EvmExecutionError {}

/// Receipt for a single EVM transaction execution.
#[derive(Debug, Clone)]
pub struct TxReceipt {
    /// Whether the transaction succeeded.
    pub success: bool,

    /// Gas used by this transaction.
    pub gas_used: u64,

    /// Cumulative gas used in the block up to and including this tx.
    pub cumulative_gas_used: u64,

    /// Effective gas price paid per unit of gas (T152).
    ///
    /// Computed as: `base_fee + min(max_priority_fee, max_fee - base_fee)`
    pub effective_gas_price: u128,

    /// Logs emitted during execution.
    pub logs: Vec<crate::evm_types::LogEntry>,

    /// Contract address created, if this was a contract creation tx.
    pub contract_address: Option<Address>,

    /// Output data (return value or revert reason).
    pub output: Vec<u8>,

    /// Execution error, if the transaction failed.
    pub error: Option<EvmExecutionError>,
}

impl TxReceipt {
    /// Create a successful receipt.
    pub fn success(
        gas_used: u64,
        cumulative_gas_used: u64,
        effective_gas_price: u128,
        logs: Vec<crate::evm_types::LogEntry>,
        output: Vec<u8>,
    ) -> Self {
        TxReceipt {
            success: true,
            gas_used,
            cumulative_gas_used,
            effective_gas_price,
            logs,
            contract_address: None,
            output,
            error: None,
        }
    }

    /// Create a failed receipt.
    pub fn failure(
        gas_used: u64,
        cumulative_gas_used: u64,
        effective_gas_price: u128,
        error: EvmExecutionError,
    ) -> Self {
        TxReceipt {
            success: false,
            gas_used,
            cumulative_gas_used,
            effective_gas_price,
            logs: Vec::new(),
            contract_address: None,
            output: Vec::new(),
            error: Some(error),
        }
    }

    /// Set the contract address (for contract creation txs).
    pub fn with_contract_address(mut self, addr: Address) -> Self {
        self.contract_address = Some(addr);
        self
    }

    /// Set the effective gas price.
    pub fn with_effective_gas_price(mut self, price: u128) -> Self {
        self.effective_gas_price = price;
        self
    }
}

/// Core trait for EVM execution engines.
///
/// This trait defines the interface for executing blocks of transactions.
/// Implementations should be deterministic: given the same initial state,
/// block environment, and transactions, the result must be identical.
///
/// ## Type Parameters
///
/// - `Tx`: The transaction type to execute.
/// - `BlockEnv`: Block-level context (height, timestamp, basefee, etc.).
/// - `Receipt`: Per-transaction execution receipt.
/// - `ExecutionError`: Error type for execution failures.
///
/// ## Determinism Requirements
///
/// Implementations MUST ensure:
/// - No use of wall clock time (use `BlockEnv` timestamp).
/// - No randomness (or deterministic pseudo-random from block data).
/// - Consistent gas metering across all validators.
/// - Identical state transitions for identical inputs.
pub trait ExecutionEngine {
    /// Transaction type.
    type Tx;

    /// Block environment type.
    type BlockEnv;

    /// Transaction receipt type.
    type Receipt;

    /// Execution error type.
    type ExecutionError: std::error::Error;

    /// Execute a block of transactions.
    ///
    /// Transactions are executed sequentially in the given order.
    /// State changes are applied to `state` as execution proceeds.
    ///
    /// # Arguments
    ///
    /// - `block_env`: Block-level context (height, timestamp, etc.).
    /// - `state`: Mutable reference to the state view.
    /// - `txs`: Slice of transactions to execute.
    ///
    /// # Returns
    ///
    /// A vector of receipts, one per transaction, in the same order.
    ///
    /// # Errors
    ///
    /// Returns an error only for catastrophic failures (e.g., corrupted state).
    /// Individual transaction failures are recorded in the receipts.
    fn execute_block(
        &self,
        block_env: &Self::BlockEnv,
        state: &mut dyn StateView,
        txs: &[Self::Tx],
    ) -> Result<Vec<Self::Receipt>, Self::ExecutionError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_execution_error_display() {
        let err = EvmExecutionError::OutOfGas {
            gas_limit: 21000,
            gas_used: 21001,
        };
        assert!(err.to_string().contains("out of gas"));

        let err = EvmExecutionError::Revert {
            output: vec![1, 2, 3],
        };
        assert!(err.to_string().contains("reverted"));

        let err = EvmExecutionError::InvalidTransaction("bad nonce".to_string());
        assert!(err.to_string().contains("bad nonce"));
    }

    #[test]
    fn test_tx_receipt_creation() {
        let receipt = TxReceipt::success(21000, 21000, 1_000_000_000, vec![], vec![]);
        assert!(receipt.success);
        assert_eq!(receipt.gas_used, 21000);
        assert_eq!(receipt.effective_gas_price, 1_000_000_000);
        assert!(receipt.error.is_none());

        let receipt = TxReceipt::failure(
            21000,
            21000,
            1_000_000_000,
            EvmExecutionError::OutOfGas {
                gas_limit: 21000,
                gas_used: 30000,
            },
        );
        assert!(!receipt.success);
        assert!(receipt.error.is_some());
    }
}
