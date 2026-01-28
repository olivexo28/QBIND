//! T168: Gas cost calculation for VM v0.
//!
//! This module provides gas cost computation for VM v0 transfer transactions,
//! implementing the gas model specified in QBIND_GAS_AND_FEES_DESIGN.md (T167).
//!
//! # Gas Model
//!
//! The gas cost formula for VM v0 transfers is:
//!
//! ```text
//! gas(tx) = GAS_BASE_TX
//!         + GAS_PER_ACCOUNT_READ  × num_reads
//!         + GAS_PER_ACCOUNT_WRITE × num_writes
//!         + GAS_PER_BYTE_PAYLOAD  × payload_len
//! ```
//!
//! # Example
//!
//! For a typical transfer (sender ≠ recipient):
//! - reads = 2 (sender + recipient)
//! - writes = 2 (sender + recipient)
//! - payload_len = 48 (TransferPayload size)
//!
//! ```text
//! gas = 21,000 + 2,600×2 + 5,000×2 + 16×48
//!     = 21,000 + 5,200 + 10,000 + 768
//!     = 36,968 gas
//! ```
//!
//! # Configuration
//!
//! Gas enforcement is config-gated:
//! - DevNet: `ExecutionGasConfig.enabled = false` (no gas enforcement)
//! - TestNet Alpha: `ExecutionGasConfig.enabled = false` by default, can be enabled
//! - TestNet Beta / MainNet: `ExecutionGasConfig.enabled = true`

use crate::execution::{QbindTransaction, TransferPayload, TRANSFER_PAYLOAD_SIZE};
use qbind_types::AccountId;

// ============================================================================
// Gas Cost Constants (from QBIND_GAS_AND_FEES_DESIGN.md)
// ============================================================================

/// Fixed cost for transaction inclusion: signature verification (ML-DSA-44),
/// nonce check, transaction parsing.
///
/// This value is higher than Ethereum's 21,000 because ML-DSA-44 signature
/// verification is computationally more expensive than ECDSA.
pub const GAS_BASE_TX: u64 = 21_000;

/// Cost to read one account state from storage.
///
/// Accounts are read to fetch sender/recipient state.
pub const GAS_PER_ACCOUNT_READ: u64 = 2_600;

/// Cost to write one account state to storage.
///
/// Accounts are written to update balances and nonces.
pub const GAS_PER_ACCOUNT_WRITE: u64 = 5_000;

/// Cost per byte of transaction payload.
///
/// Provides linear cost scaling with payload size.
pub const GAS_PER_BYTE_PAYLOAD: u64 = 16;

/// Default per-block gas limit.
///
/// 30 million gas allows approximately 800-1000 transfer transactions per block.
pub const BLOCK_GAS_LIMIT_DEFAULT: u64 = 30_000_000;

/// Minimum gas limit for a transaction.
///
/// Equal to GAS_BASE_TX to prevent trivially small gas limits.
pub const MINIMUM_GAS_LIMIT: u64 = GAS_BASE_TX;

/// Default gas limit for v0 payloads (which don't carry explicit gas_limit).
///
/// Set to 50,000 to provide headroom above the ~37k typical transfer cost.
pub const DEFAULT_V0_GAS_LIMIT: u64 = 50_000;

// ============================================================================
// Gas Computation Functions
// ============================================================================

/// Compute the gas cost for a VM v0 transfer transaction.
///
/// Uses saturating arithmetic to prevent overflow.
///
/// # Arguments
///
/// * `payload_len` - Length of the transaction payload in bytes
/// * `num_reads` - Number of account reads (typically 1 or 2)
/// * `num_writes` - Number of account writes (typically 1 or 2)
///
/// # Returns
///
/// The total gas cost for the transaction.
///
/// # Example
///
/// ```rust
/// use qbind_ledger::execution_gas::gas_for_transfer_v0;
///
/// // Typical transfer (sender ≠ recipient)
/// let gas = gas_for_transfer_v0(48, 2, 2);
/// assert_eq!(gas, 36_968);
///
/// // Self-transfer (sender == recipient)
/// let gas_self = gas_for_transfer_v0(48, 1, 1);
/// assert_eq!(gas_self, 29_368);
/// ```
pub fn gas_for_transfer_v0(payload_len: usize, num_reads: u32, num_writes: u32) -> u64 {
    // Use saturating arithmetic to prevent overflow
    GAS_BASE_TX
        .saturating_add(GAS_PER_ACCOUNT_READ.saturating_mul(num_reads as u64))
        .saturating_add(GAS_PER_ACCOUNT_WRITE.saturating_mul(num_writes as u64))
        .saturating_add(GAS_PER_BYTE_PAYLOAD.saturating_mul(payload_len as u64))
}

/// Compute the gas cost for a standard VM v0 transfer.
///
/// This function determines the read/write counts based on whether
/// the sender and recipient are the same account.
///
/// # Arguments
///
/// * `sender` - The sender account ID
/// * `recipient` - The recipient account ID
/// * `payload_len` - Length of the transaction payload
///
/// # Returns
///
/// The total gas cost for the transfer.
pub fn gas_for_standard_transfer(
    sender: &AccountId,
    recipient: &AccountId,
    payload_len: usize,
) -> u64 {
    if sender == recipient {
        // Self-transfer: 1 read, 1 write
        gas_for_transfer_v0(payload_len, 1, 1)
    } else {
        // Normal transfer: 2 reads, 2 writes
        gas_for_transfer_v0(payload_len, 2, 2)
    }
}

// ============================================================================
// VM Gas Error Types
// ============================================================================

/// Error type for gas-related operations in VM v0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmGasError {
    /// Transaction payload is malformed and cannot be decoded.
    MalformedPayload,

    /// Gas cost exceeds the specified gas limit.
    GasLimitExceeded {
        /// The required gas for the transaction.
        required: u64,
        /// The gas limit specified in the transaction.
        limit: u64,
    },

    /// Sender has insufficient balance to cover the fee.
    InsufficientBalanceForFee {
        /// The sender's current balance.
        balance: u128,
        /// The total amount needed (transfer amount + fee).
        needed: u128,
    },
}

impl std::fmt::Display for VmGasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmGasError::MalformedPayload => write!(f, "malformed payload"),
            VmGasError::GasLimitExceeded { required, limit } => {
                write!(
                    f,
                    "gas limit exceeded: required {}, limit {}",
                    required, limit
                )
            }
            VmGasError::InsufficientBalanceForFee { balance, needed } => {
                write!(
                    f,
                    "insufficient balance for fee: have {}, need {}",
                    balance, needed
                )
            }
        }
    }
}

impl std::error::Error for VmGasError {}

// ============================================================================
// Gas Computation for QbindTransaction
// ============================================================================

/// Result of computing gas for a VM v0 transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasComputeResult {
    /// The computed gas cost.
    pub gas_cost: u64,
    /// The effective gas limit (from v1 payload or default for v0).
    pub gas_limit: u64,
    /// The effective max fee per gas (from v1 payload or 0 for v0).
    pub max_fee_per_gas: u128,
    /// Whether the payload is v1 format.
    pub is_v1: bool,
}

/// Compute gas-related parameters for a VM v0 transaction.
///
/// This function:
/// 1. Decodes the payload to determine if it's v0 or v1 format
/// 2. Computes the gas cost based on the transaction
/// 3. Derives gas_limit and max_fee_per_gas (explicit for v1, defaults for v0)
///
/// # Arguments
///
/// * `tx` - The transaction to compute gas for
///
/// # Returns
///
/// `Ok(GasComputeResult)` with gas parameters, or `Err(VmGasError)` on error.
pub fn compute_gas_for_vm_v0_tx(tx: &QbindTransaction) -> Result<GasComputeResult, VmGasError> {
    match decode_transfer_payload(&tx.payload) {
        Ok(TransferPayloadDecoded::V0(v0)) => {
            let gas_cost = gas_for_standard_transfer(&tx.sender, &v0.recipient, tx.payload.len());
            Ok(GasComputeResult {
                gas_cost,
                // v0 payloads get a default gas_limit that's just enough for the tx
                gas_limit: gas_cost.max(DEFAULT_V0_GAS_LIMIT),
                max_fee_per_gas: 0, // v0 payloads are fee-free
                is_v1: false,
            })
        }
        Ok(TransferPayloadDecoded::V1(v1)) => {
            let gas_cost = gas_for_standard_transfer(&tx.sender, &v1.recipient, tx.payload.len());
            Ok(GasComputeResult {
                gas_cost,
                gas_limit: v1.gas_limit,
                max_fee_per_gas: v1.max_fee_per_gas,
                is_v1: true,
            })
        }
        Err(_) => Err(VmGasError::MalformedPayload),
    }
}

// ============================================================================
// Transfer Payload V1 (with gas fields)
// ============================================================================

/// Size of a v1 transfer payload in bytes.
///
/// v1 adds gas_limit (8 bytes) and max_fee_per_gas (16 bytes) to the v0 format.
pub const TRANSFER_PAYLOAD_V1_SIZE: usize = 32 + 16 + 8 + 16; // recipient + amount + gas_limit + max_fee_per_gas = 72

/// Transfer payload v1 with explicit gas fields.
///
/// This is the future transaction format that includes gas parameters:
/// - `recipient`: 32-byte account ID
/// - `amount`: u128 transfer amount
/// - `gas_limit`: u64 maximum gas the sender will pay
/// - `max_fee_per_gas`: u128 maximum fee per gas unit
///
/// # Wire Format
///
/// ```text
/// recipient:        [u8; 32]  (bytes 0..32)
/// amount:           u128 BE   (bytes 32..48)
/// gas_limit:        u64 BE    (bytes 48..56)
/// max_fee_per_gas:  u128 BE   (bytes 56..72)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPayloadV1 {
    /// The recipient account ID.
    pub recipient: AccountId,
    /// The amount to transfer.
    pub amount: u128,
    /// Maximum gas the sender will pay.
    pub gas_limit: u64,
    /// Maximum fee per gas unit (in native token).
    pub max_fee_per_gas: u128,
}

impl TransferPayloadV1 {
    /// Create a new transfer payload v1.
    pub fn new(recipient: AccountId, amount: u128, gas_limit: u64, max_fee_per_gas: u128) -> Self {
        Self {
            recipient,
            amount,
            gas_limit,
            max_fee_per_gas,
        }
    }

    /// Encode the transfer payload to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TRANSFER_PAYLOAD_V1_SIZE);
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.gas_limit.to_be_bytes());
        out.extend_from_slice(&self.max_fee_per_gas.to_be_bytes());
        out
    }

    /// Decode a transfer payload v1 from bytes.
    ///
    /// Returns `None` if the payload is malformed or wrong size.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != TRANSFER_PAYLOAD_V1_SIZE {
            return None;
        }

        let recipient: AccountId = bytes[0..32].try_into().ok()?;
        let amount = u128::from_be_bytes(bytes[32..48].try_into().ok()?);
        let gas_limit = u64::from_be_bytes(bytes[48..56].try_into().ok()?);
        let max_fee_per_gas = u128::from_be_bytes(bytes[56..72].try_into().ok()?);

        Some(Self {
            recipient,
            amount,
            gas_limit,
            max_fee_per_gas,
        })
    }
}

// ============================================================================
// Payload Discrimination (v0 vs v1)
// ============================================================================

/// Decoded transfer payload (v0 or v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferPayloadDecoded {
    /// v0 format (48 bytes): recipient + amount only
    V0(TransferPayload),
    /// v1 format (72 bytes): recipient + amount + gas_limit + max_fee_per_gas
    V1(TransferPayloadV1),
}

/// Decode a transfer payload, determining version by length.
///
/// - 48 bytes → `TransferPayload` (v0)
/// - 72 bytes → `TransferPayloadV1` (v1)
/// - Other lengths → Error
///
/// # Arguments
///
/// * `bytes` - The raw payload bytes
///
/// # Returns
///
/// `Ok(TransferPayloadDecoded)` with the decoded payload, or `Err(VmGasError)` on error.
pub fn decode_transfer_payload(bytes: &[u8]) -> Result<TransferPayloadDecoded, VmGasError> {
    match bytes.len() {
        TRANSFER_PAYLOAD_SIZE => {
            // v0 format
            TransferPayload::decode(bytes)
                .map(TransferPayloadDecoded::V0)
                .ok_or(VmGasError::MalformedPayload)
        }
        TRANSFER_PAYLOAD_V1_SIZE => {
            // v1 format
            TransferPayloadV1::decode(bytes)
                .map(TransferPayloadDecoded::V1)
                .ok_or(VmGasError::MalformedPayload)
        }
        _ => Err(VmGasError::MalformedPayload),
    }
}

// ============================================================================
// Execution Gas Configuration
// ============================================================================

/// Configuration for gas enforcement in VM v0 execution.
///
/// This struct controls whether gas accounting is enabled and the
/// per-block gas limit.
///
/// # Environments
///
/// - **DevNet**: `enabled = false` (no gas enforcement, DevNet is frozen)
/// - **TestNet Alpha**: `enabled = false` by default (preserves current behavior)
/// - **TestNet Beta**: `enabled = true` (full gas enforcement)
/// - **MainNet**: `enabled = true` (full gas enforcement)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionGasConfig {
    /// Whether gas enforcement is enabled.
    ///
    /// When `false`, VM v0 behaves exactly as before T168:
    /// - No gas limit checks
    /// - No fee deduction
    /// - No block gas limit enforcement
    ///
    /// When `true`:
    /// - Per-transaction gas limits are enforced
    /// - Fees are deducted (burned in TestNet)
    /// - Per-block gas limit is enforced
    pub enabled: bool,

    /// Per-block gas limit.
    ///
    /// Default: `BLOCK_GAS_LIMIT_DEFAULT` (30,000,000)
    pub block_gas_limit: u64,
}

impl Default for ExecutionGasConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for backward compatibility
            block_gas_limit: BLOCK_GAS_LIMIT_DEFAULT,
        }
    }
}

impl ExecutionGasConfig {
    /// Create a disabled gas configuration (DevNet default).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Create an enabled gas configuration for TestNet/MainNet.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            block_gas_limit: BLOCK_GAS_LIMIT_DEFAULT,
        }
    }

    /// Create an enabled configuration with a custom block gas limit.
    pub fn enabled_with_limit(block_gas_limit: u64) -> Self {
        Self {
            enabled: true,
            block_gas_limit,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_account_id(byte: u8) -> AccountId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[test]
    fn test_gas_constants() {
        assert_eq!(GAS_BASE_TX, 21_000);
        assert_eq!(GAS_PER_ACCOUNT_READ, 2_600);
        assert_eq!(GAS_PER_ACCOUNT_WRITE, 5_000);
        assert_eq!(GAS_PER_BYTE_PAYLOAD, 16);
        assert_eq!(BLOCK_GAS_LIMIT_DEFAULT, 30_000_000);
    }

    #[test]
    fn test_gas_for_transfer_v0_typical() {
        // Typical transfer (sender ≠ recipient): 2 reads, 2 writes, 48 bytes
        let gas = gas_for_transfer_v0(48, 2, 2);

        // 21,000 + 2,600×2 + 5,000×2 + 16×48
        // = 21,000 + 5,200 + 10,000 + 768
        // = 36,968
        assert_eq!(gas, 36_968);
    }

    #[test]
    fn test_gas_for_transfer_v0_self_transfer() {
        // Self-transfer (sender == recipient): 1 read, 1 write, 48 bytes
        let gas = gas_for_transfer_v0(48, 1, 1);

        // 21,000 + 2,600×1 + 5,000×1 + 16×48
        // = 21,000 + 2,600 + 5,000 + 768
        // = 29,368
        assert_eq!(gas, 29_368);
    }

    #[test]
    fn test_gas_for_standard_transfer() {
        let sender = test_account_id(0xAA);
        let recipient = test_account_id(0xBB);
        let same = test_account_id(0xCC);

        // Normal transfer
        let gas_normal = gas_for_standard_transfer(&sender, &recipient, TRANSFER_PAYLOAD_SIZE);
        assert_eq!(gas_normal, 36_968);

        // Self-transfer
        let gas_self = gas_for_standard_transfer(&same, &same, TRANSFER_PAYLOAD_SIZE);
        assert_eq!(gas_self, 29_368);
    }

    #[test]
    fn test_transfer_payload_v1_encode_decode() {
        let recipient = test_account_id(0xBB);
        let payload = TransferPayloadV1::new(recipient, 1000, 50_000, 100);

        let encoded = payload.encode();
        assert_eq!(encoded.len(), TRANSFER_PAYLOAD_V1_SIZE);

        let decoded = TransferPayloadV1::decode(&encoded).unwrap();
        assert_eq!(decoded.recipient, recipient);
        assert_eq!(decoded.amount, 1000);
        assert_eq!(decoded.gas_limit, 50_000);
        assert_eq!(decoded.max_fee_per_gas, 100);
    }

    #[test]
    fn test_decode_transfer_payload_v0() {
        let recipient = test_account_id(0xBB);
        let v0_payload = TransferPayload::new(recipient, 1000);
        let encoded = v0_payload.encode();

        let decoded = decode_transfer_payload(&encoded).unwrap();
        match decoded {
            TransferPayloadDecoded::V0(p) => {
                assert_eq!(p.recipient, recipient);
                assert_eq!(p.amount, 1000);
            }
            _ => panic!("expected v0 payload"),
        }
    }

    #[test]
    fn test_decode_transfer_payload_v1() {
        let recipient = test_account_id(0xBB);
        let v1_payload = TransferPayloadV1::new(recipient, 1000, 50_000, 100);
        let encoded = v1_payload.encode();

        let decoded = decode_transfer_payload(&encoded).unwrap();
        match decoded {
            TransferPayloadDecoded::V1(p) => {
                assert_eq!(p.recipient, recipient);
                assert_eq!(p.amount, 1000);
                assert_eq!(p.gas_limit, 50_000);
                assert_eq!(p.max_fee_per_gas, 100);
            }
            _ => panic!("expected v1 payload"),
        }
    }

    #[test]
    fn test_decode_transfer_payload_invalid_length() {
        let result = decode_transfer_payload(&[0u8; 50]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VmGasError::MalformedPayload));
    }

    #[test]
    fn test_execution_gas_config_default() {
        let config = ExecutionGasConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.block_gas_limit, BLOCK_GAS_LIMIT_DEFAULT);
    }

    #[test]
    fn test_execution_gas_config_enabled() {
        let config = ExecutionGasConfig::enabled();
        assert!(config.enabled);
        assert_eq!(config.block_gas_limit, BLOCK_GAS_LIMIT_DEFAULT);
    }

    #[test]
    fn test_execution_gas_config_with_limit() {
        let config = ExecutionGasConfig::enabled_with_limit(1_000_000);
        assert!(config.enabled);
        assert_eq!(config.block_gas_limit, 1_000_000);
    }

    #[test]
    fn test_vm_gas_error_display() {
        let err1 = VmGasError::MalformedPayload;
        assert_eq!(format!("{}", err1), "malformed payload");

        let err2 = VmGasError::GasLimitExceeded {
            required: 50_000,
            limit: 30_000,
        };
        assert_eq!(
            format!("{}", err2),
            "gas limit exceeded: required 50000, limit 30000"
        );

        let err3 = VmGasError::InsufficientBalanceForFee {
            balance: 100,
            needed: 200,
        };
        assert_eq!(
            format!("{}", err3),
            "insufficient balance for fee: have 100, need 200"
        );
    }
}