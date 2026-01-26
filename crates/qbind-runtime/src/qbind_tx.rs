//! QBIND transaction types for EVM execution.
//!
//! This module defines the canonical transaction format for EVM execution
//! within the QBIND blockchain. These types are used by the execution layer
//! and are assumed to have been validated by consensus before execution.
//!
//! ## Design Notes
//!
//! - Transactions follow EIP-1559 structure (max_fee_per_gas, max_priority_fee_per_gas).
//! - Signature verification is handled by the consensus layer, not execution.
//! - The execution layer assumes all transactions are syntactically valid.

use crate::evm_types::{Address, U256};

/// A QBIND transaction for EVM execution.
///
/// This structure represents a transaction that has been validated by the
/// consensus layer and is ready for execution. The execution engine does
/// not verify signatures; it assumes the transaction is authentic.
///
/// ## Fields
///
/// The transaction format is EIP-1559 compatible with the following fields:
///
/// - `from`: The sender address (derived from signature verification in consensus).
/// - `to`: The recipient address, or `None` for contract creation.
/// - `nonce`: The sender's transaction count.
/// - `gas_limit`: Maximum gas units this transaction can consume.
/// - `max_fee_per_gas`: Maximum total fee per gas unit (in wei-equivalent).
/// - `max_priority_fee_per_gas`: Maximum priority fee (tip) per gas unit.
/// - `value`: Amount to transfer (in wei-equivalent).
/// - `data`: Call data (input for contract calls, init code for creation).
///
/// ## Note on Gas Fees
///
/// The actual gas price paid is:
/// `min(max_fee_per_gas, basefee + max_priority_fee_per_gas)`
///
/// For T150, gas accounting is simplified. Full EIP-1559 semantics
/// (including basefee updates and priority fee distribution) will be
/// implemented in T156+.
#[derive(Clone, Debug)]
pub struct QbindTx {
    /// Sender address (authenticated by consensus layer).
    pub from: Address,

    /// Recipient address. `None` for contract creation.
    pub to: Option<Address>,

    /// Transaction nonce (sender's tx count).
    pub nonce: u64,

    /// Maximum gas units this transaction can use.
    pub gas_limit: u64,

    /// Maximum total fee per gas unit (wei-equivalent).
    ///
    /// This is the absolute maximum the sender is willing to pay per gas.
    pub max_fee_per_gas: u128,

    /// Maximum priority fee per gas unit (wei-equivalent).
    ///
    /// This is the "tip" to the block producer. The actual priority fee
    /// is `min(max_priority_fee_per_gas, max_fee_per_gas - basefee)`.
    pub max_priority_fee_per_gas: u128,

    /// Value to transfer in wei-equivalent.
    pub value: U256,

    /// Transaction data.
    ///
    /// - For contract calls: the function selector and encoded arguments.
    /// - For contract creation: the init code (constructor + runtime code).
    /// - For simple transfers: typically empty.
    pub data: Vec<u8>,
}

impl QbindTx {
    /// Create a simple value transfer transaction.
    pub fn transfer(from: Address, to: Address, value: U256, nonce: u64) -> Self {
        QbindTx {
            from,
            to: Some(to),
            nonce,
            gas_limit: 21000,               // Standard ETH transfer gas
            max_fee_per_gas: 1_000_000_000, // 1 Gwei default
            max_priority_fee_per_gas: 1_000_000_000,
            value,
            data: Vec::new(),
        }
    }

    /// Create a contract creation transaction.
    pub fn create(
        from: Address,
        init_code: Vec<u8>,
        value: U256,
        nonce: u64,
        gas_limit: u64,
    ) -> Self {
        QbindTx {
            from,
            to: None,
            nonce,
            gas_limit,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            value,
            data: init_code,
        }
    }

    /// Create a contract call transaction.
    pub fn call(
        from: Address,
        to: Address,
        data: Vec<u8>,
        value: U256,
        nonce: u64,
        gas_limit: u64,
    ) -> Self {
        QbindTx {
            from,
            to: Some(to),
            nonce,
            gas_limit,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            value,
            data,
        }
    }

    /// Check if this is a contract creation transaction.
    pub fn is_contract_creation(&self) -> bool {
        self.to.is_none()
    }

    /// Calculate the effective gas price given the current basefee.
    ///
    /// Returns `min(max_fee_per_gas, basefee + max_priority_fee_per_gas)`.
    pub fn effective_gas_price(&self, basefee: u128) -> u128 {
        let priority_price = basefee.saturating_add(self.max_priority_fee_per_gas);
        self.max_fee_per_gas.min(priority_price)
    }

    /// Calculate the maximum cost of this transaction.
    ///
    /// Returns `gas_limit * max_fee_per_gas + value`.
    /// Used for balance checks before execution.
    pub fn max_cost(&self) -> Option<U256> {
        let gas_cost = (self.gas_limit as u128).checked_mul(self.max_fee_per_gas)?;
        let gas_cost_u256 = U256::from_u128(gas_cost);
        gas_cost_u256.checked_add(&self.value)
    }

    /// Set gas parameters.
    pub fn with_gas(
        mut self,
        gas_limit: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> Self {
        self.gas_limit = gas_limit;
        self.max_fee_per_gas = max_fee_per_gas;
        self.max_priority_fee_per_gas = max_priority_fee_per_gas;
        self
    }
}

/// Block environment for EVM execution.
///
/// Contains all block-level context needed for deterministic execution.
/// Values are provided by consensus and must be identical across all validators.
#[derive(Clone, Debug)]
pub struct QbindBlockEnv {
    /// Block number (height).
    pub number: u64,

    /// Block timestamp (seconds since Unix epoch).
    ///
    /// Provided by consensus, NOT derived from wall clock.
    pub timestamp: u64,

    /// Current base fee per gas (EIP-1559).
    ///
    /// For T150, this is set to a fixed value. Dynamic basefee
    /// updates will be implemented in T156+.
    pub basefee: u128,

    /// Gas limit for the entire block.
    pub gas_limit: u64,

    /// Coinbase address (block producer / fee recipient).
    pub coinbase: Address,

    /// Chain ID for EIP-155 replay protection.
    pub chain_id: u64,

    /// Previous block hash (BLOCKHASH opcode).
    pub prev_randao: U256,
}

impl QbindBlockEnv {
    /// Create a new block environment with the given parameters.
    pub fn new(
        number: u64,
        timestamp: u64,
        basefee: u128,
        gas_limit: u64,
        coinbase: Address,
        chain_id: u64,
    ) -> Self {
        QbindBlockEnv {
            number,
            timestamp,
            basefee,
            gas_limit,
            coinbase,
            chain_id,
            prev_randao: U256::zero(),
        }
    }

    /// Create a minimal test environment.
    pub fn test_env() -> Self {
        QbindBlockEnv {
            number: 1,
            timestamp: 1704067200,  // 2024-01-01 00:00:00 UTC
            basefee: 1_000_000_000, // 1 Gwei
            gas_limit: 30_000_000,  // 30M gas limit
            coinbase: Address::zero(),
            chain_id: 1337, // Common testnet chain ID
            prev_randao: U256::zero(),
        }
    }

    /// Set the prev_randao value.
    pub fn with_prev_randao(mut self, prev_randao: U256) -> Self {
        self.prev_randao = prev_randao;
        self
    }
}

/// Result of executing a QBIND block.
#[derive(Debug, Clone)]
pub struct EvmBlockExecutionResult {
    /// Receipts for each transaction, in order.
    pub receipts: Vec<crate::execution_engine::TxReceipt>,

    /// Total gas used by all transactions in the block.
    pub total_gas_used: u64,

    /// All logs emitted during block execution.
    pub logs: Vec<crate::evm_types::LogEntry>,
}

impl EvmBlockExecutionResult {
    /// Create a new block execution result.
    pub fn new(receipts: Vec<crate::execution_engine::TxReceipt>) -> Self {
        let total_gas_used = receipts.last().map(|r| r.cumulative_gas_used).unwrap_or(0);
        let logs = receipts.iter().flat_map(|r| r.logs.clone()).collect();

        EvmBlockExecutionResult {
            receipts,
            total_gas_used,
            logs,
        }
    }

    /// Check if all transactions succeeded.
    pub fn all_succeeded(&self) -> bool {
        self.receipts.iter().all(|r| r.success)
    }

    /// Get the number of successful transactions.
    pub fn successful_count(&self) -> usize {
        self.receipts.iter().filter(|r| r.success).count()
    }

    /// Get the number of failed transactions.
    pub fn failed_count(&self) -> usize {
        self.receipts.iter().filter(|r| !r.success).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qbind_tx_transfer() {
        let from = Address::from_bytes([1u8; 20]);
        let to = Address::from_bytes([2u8; 20]);
        let value = U256::from_u64(1_000_000);

        let tx = QbindTx::transfer(from, to, value, 0);

        assert_eq!(tx.from, from);
        assert_eq!(tx.to, Some(to));
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.gas_limit, 21000);
        assert!(!tx.is_contract_creation());
    }

    #[test]
    fn test_qbind_tx_create() {
        let from = Address::from_bytes([1u8; 20]);
        let init_code = vec![0x60, 0x00, 0x60, 0x00]; // PUSH1 0 PUSH1 0

        let tx = QbindTx::create(from, init_code.clone(), U256::zero(), 0, 100000);

        assert!(tx.is_contract_creation());
        assert_eq!(tx.to, None);
        assert_eq!(tx.data, init_code);
    }

    #[test]
    fn test_effective_gas_price() {
        let tx = QbindTx::transfer(
            Address::zero(),
            Address::from_bytes([1u8; 20]),
            U256::zero(),
            0,
        )
        .with_gas(21000, 100, 20);

        // basefee = 50, priority = 20, so effective = min(100, 50+20) = 70
        assert_eq!(tx.effective_gas_price(50), 70);

        // basefee = 90, priority = 20, so effective = min(100, 90+20) = 100
        assert_eq!(tx.effective_gas_price(90), 100);
    }

    #[test]
    fn test_max_cost() {
        let tx = QbindTx::transfer(
            Address::zero(),
            Address::from_bytes([1u8; 20]),
            U256::from_u64(1000),
            0,
        )
        .with_gas(21000, 10, 1);

        // max_cost = 21000 * 10 + 1000 = 211000
        let cost = tx.max_cost().unwrap();
        assert_eq!(cost.to_u64(), Some(211000));
    }

    #[test]
    fn test_qbind_block_env() {
        let env = QbindBlockEnv::test_env();

        assert_eq!(env.number, 1);
        assert_eq!(env.chain_id, 1337);
        assert!(env.basefee > 0);
    }

    #[test]
    fn test_block_execution_result() {
        let receipts = vec![
            crate::execution_engine::TxReceipt::success(21000, 21000, vec![], vec![]),
            crate::execution_engine::TxReceipt::failure(
                21000,
                42000,
                crate::execution_engine::EvmExecutionError::OutOfGas {
                    gas_limit: 21000,
                    gas_used: 30000,
                },
            ),
        ];

        let result = EvmBlockExecutionResult::new(receipts);

        assert_eq!(result.total_gas_used, 42000);
        assert_eq!(result.successful_count(), 1);
        assert_eq!(result.failed_count(), 1);
        assert!(!result.all_succeeded());
    }
}