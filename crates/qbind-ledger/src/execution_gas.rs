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
// T193: Fee Distribution Policy
// ============================================================================

/// Fee distribution policy for hybrid burn + proposer reward (T193).
///
/// This struct defines how transaction fees are distributed between:
/// - Burning (deflationary pressure)
/// - Proposer reward (incentive to include transactions)
///
/// Values are specified in basis points (bps), where 10,000 bps = 100%.
/// The `burn_bps` and `proposer_bps` must sum to exactly 10,000.
///
/// # Environments
///
/// - **DevNet**: `BURN_ONLY` (10,000 / 0) - all fees burned
/// - **TestNet Alpha**: `BURN_ONLY` (10,000 / 0) - all fees burned
/// - **TestNet Beta**: `BURN_ONLY` (10,000 / 0) - all fees burned
/// - **MainNet v0**: `MAINNET_V0_DEFAULT` (5,000 / 5,000) - 50% burned, 50% to proposer
///
/// # Example
///
/// ```rust
/// use qbind_ledger::FeeDistributionPolicy;
///
/// // Use burn-only policy (TestNet default)
/// let policy = FeeDistributionPolicy::burn_only();
/// assert_eq!(policy.burn_bps, 10_000);
/// assert_eq!(policy.proposer_bps, 0);
///
/// // Use MainNet default (50/50 split)
/// let mainnet_policy = FeeDistributionPolicy::mainnet_default();
/// assert_eq!(mainnet_policy.burn_bps, 5_000);
/// assert_eq!(mainnet_policy.proposer_bps, 5_000);
///
/// // Compute distribution for a fee
/// let (burn, proposer) = mainnet_policy.distribute_fee(1000);
/// assert_eq!(burn, 500);
/// assert_eq!(proposer, 500);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeDistributionPolicy {
    /// Basis points (0-10,000) of fees to burn.
    ///
    /// 10,000 = 100% burned (burn-only policy).
    /// 5,000 = 50% burned (MainNet default).
    pub burn_bps: u16,

    /// Basis points (0-10,000) of fees to reward to block proposer.
    ///
    /// 0 = 0% to proposer (burn-only policy).
    /// 5,000 = 50% to proposer (MainNet default).
    pub proposer_bps: u16,
}

/// Total basis points representing 100%.
pub const BPS_100_PERCENT: u16 = 10_000;

impl FeeDistributionPolicy {
    /// Create a new fee distribution policy.
    ///
    /// # Arguments
    ///
    /// * `burn_bps` - Basis points to burn (0-10,000)
    /// * `proposer_bps` - Basis points to reward proposer (0-10,000)
    ///
    /// # Panics
    ///
    /// Panics if `burn_bps + proposer_bps != 10,000`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_ledger::FeeDistributionPolicy;
    ///
    /// // 70% burn, 30% proposer
    /// let policy = FeeDistributionPolicy::new(7_000, 3_000);
    /// ```
    pub fn new(burn_bps: u16, proposer_bps: u16) -> Self {
        assert_eq!(
            burn_bps.saturating_add(proposer_bps),
            BPS_100_PERCENT,
            "burn_bps ({}) + proposer_bps ({}) must equal {}",
            burn_bps,
            proposer_bps,
            BPS_100_PERCENT
        );
        Self {
            burn_bps,
            proposer_bps,
        }
    }

    /// Create a new fee distribution policy, returning an error if invalid.
    ///
    /// # Arguments
    ///
    /// * `burn_bps` - Basis points to burn (0-10,000)
    /// * `proposer_bps` - Basis points to reward proposer (0-10,000)
    ///
    /// # Returns
    ///
    /// `Ok(FeeDistributionPolicy)` if valid, `Err` if bps don't sum to 10,000.
    pub fn try_new(burn_bps: u16, proposer_bps: u16) -> Result<Self, &'static str> {
        if burn_bps.saturating_add(proposer_bps) != BPS_100_PERCENT {
            return Err("burn_bps + proposer_bps must equal 10,000");
        }
        Ok(Self {
            burn_bps,
            proposer_bps,
        })
    }

    /// Create a burn-only policy (DevNet / TestNet default).
    ///
    /// All fees are burned, nothing goes to the proposer.
    pub const fn burn_only() -> Self {
        Self {
            burn_bps: BPS_100_PERCENT,
            proposer_bps: 0,
        }
    }

    /// Create the MainNet v0 default policy (50% burn, 50% proposer).
    ///
    /// This is the canonical fee distribution for MainNet v0:
    /// - 50% of fees are burned (deflationary pressure)
    /// - 50% of fees go to the block proposer (incentive)
    pub const fn mainnet_default() -> Self {
        Self {
            burn_bps: 5_000,
            proposer_bps: 5_000,
        }
    }

    /// Check if this is a burn-only policy (no proposer rewards).
    pub fn is_burn_only(&self) -> bool {
        self.proposer_bps == 0
    }

    /// Distribute a fee according to this policy.
    ///
    /// # Arguments
    ///
    /// * `total_fee` - The total fee to distribute
    ///
    /// # Returns
    ///
    /// A tuple of `(burn_amount, proposer_reward)` where:
    /// - `burn_amount + proposer_reward == total_fee`
    /// - `burn_amount` is the portion to burn (remove from circulation)
    /// - `proposer_reward` is the portion to credit to the block proposer
    ///
    /// # Rounding
    ///
    /// The proposer reward is computed first with integer division (rounding down).
    /// The burn amount is `total_fee - proposer_reward` to ensure exact conservation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_ledger::FeeDistributionPolicy;
    ///
    /// let policy = FeeDistributionPolicy::mainnet_default();
    /// let (burn, proposer) = policy.distribute_fee(1000);
    /// assert_eq!(burn + proposer, 1000); // Conservation guaranteed
    /// ```
    pub fn distribute_fee(&self, total_fee: u128) -> (u128, u128) {
        if self.proposer_bps == 0 {
            // Burn-only: fast path
            return (total_fee, 0);
        }

        if self.burn_bps == 0 {
            // Proposer-only: fast path
            return (0, total_fee);
        }

        // Compute proposer reward first (rounds down)
        let proposer_reward =
            total_fee.saturating_mul(self.proposer_bps as u128) / (BPS_100_PERCENT as u128);

        // Burn amount is the remainder (ensures exact conservation)
        let burn_amount = total_fee.saturating_sub(proposer_reward);

        (burn_amount, proposer_reward)
    }
}

impl Default for FeeDistributionPolicy {
    /// Default is burn-only for backward compatibility.
    fn default() -> Self {
        Self::burn_only()
    }
}

impl std::fmt::Display for FeeDistributionPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let burn_pct = self.burn_bps as f64 / 100.0;
        let proposer_pct = self.proposer_bps as f64 / 100.0;
        write!(f, "burn={:.1}% proposer={:.1}%", burn_pct, proposer_pct)
    }
}

// ============================================================================
// Execution Gas Configuration
// ============================================================================

/// Configuration for gas enforcement in VM v0 execution.
///
/// This struct controls whether gas accounting is enabled, the
/// per-block gas limit, and the fee distribution policy.
///
/// # Environments
///
/// - **DevNet**: `enabled = false` (no gas enforcement, DevNet is frozen)
/// - **TestNet Alpha**: `enabled = false` by default (preserves current behavior)
/// - **TestNet Beta**: `enabled = true` (full gas enforcement, burn-only fees)
/// - **MainNet**: `enabled = true` (full gas enforcement, hybrid fee distribution)
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
    /// - Fees are deducted and distributed per `fee_distribution_policy`
    /// - Per-block gas limit is enforced
    pub enabled: bool,

    /// Per-block gas limit.
    ///
    /// Default: `BLOCK_GAS_LIMIT_DEFAULT` (30,000,000)
    pub block_gas_limit: u64,

    /// Fee distribution policy (T193).
    ///
    /// Determines how fees are split between burning and proposer rewards.
    ///
    /// Default: `FeeDistributionPolicy::burn_only()` for backward compatibility.
    pub fee_distribution_policy: FeeDistributionPolicy,
}

impl Default for ExecutionGasConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for backward compatibility
            block_gas_limit: BLOCK_GAS_LIMIT_DEFAULT,
            fee_distribution_policy: FeeDistributionPolicy::burn_only(),
        }
    }
}

impl ExecutionGasConfig {
    /// Create a disabled gas configuration (DevNet default).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Create an enabled gas configuration for TestNet (burn-only).
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            block_gas_limit: BLOCK_GAS_LIMIT_DEFAULT,
            fee_distribution_policy: FeeDistributionPolicy::burn_only(),
        }
    }

    /// Create an enabled configuration with a custom block gas limit.
    pub fn enabled_with_limit(block_gas_limit: u64) -> Self {
        Self {
            enabled: true,
            block_gas_limit,
            fee_distribution_policy: FeeDistributionPolicy::burn_only(),
        }
    }

    /// Create an enabled configuration for MainNet v0 (T193).
    ///
    /// Uses the MainNet default fee distribution policy (50% burn, 50% proposer).
    pub fn mainnet() -> Self {
        Self {
            enabled: true,
            block_gas_limit: BLOCK_GAS_LIMIT_DEFAULT,
            fee_distribution_policy: FeeDistributionPolicy::mainnet_default(),
        }
    }

    /// Create an enabled configuration with a custom fee distribution policy.
    pub fn enabled_with_policy(policy: FeeDistributionPolicy) -> Self {
        Self {
            enabled: true,
            block_gas_limit: BLOCK_GAS_LIMIT_DEFAULT,
            fee_distribution_policy: policy,
        }
    }

    /// Set the fee distribution policy.
    pub fn with_fee_policy(mut self, policy: FeeDistributionPolicy) -> Self {
        self.fee_distribution_policy = policy;
        self
    }

    /// Set the block gas limit.
    pub fn with_block_gas_limit(mut self, limit: u64) -> Self {
        self.block_gas_limit = limit;
        self
    }

    /// Check if this configuration uses hybrid (non-burn-only) fee distribution.
    pub fn has_proposer_rewards(&self) -> bool {
        !self.fee_distribution_policy.is_burn_only()
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

    // ========================================================================
    // T193: FeeDistributionPolicy Tests
    // ========================================================================

    #[test]
    fn test_fee_distribution_policy_burn_only() {
        let policy = FeeDistributionPolicy::burn_only();
        assert_eq!(policy.burn_bps, 10_000);
        assert_eq!(policy.proposer_bps, 0);
        assert!(policy.is_burn_only());
    }

    #[test]
    fn test_fee_distribution_policy_mainnet_default() {
        let policy = FeeDistributionPolicy::mainnet_default();
        assert_eq!(policy.burn_bps, 5_000);
        assert_eq!(policy.proposer_bps, 5_000);
        assert!(!policy.is_burn_only());
    }

    #[test]
    fn test_fee_distribution_policy_new() {
        let policy = FeeDistributionPolicy::new(7_000, 3_000);
        assert_eq!(policy.burn_bps, 7_000);
        assert_eq!(policy.proposer_bps, 3_000);
    }

    #[test]
    fn test_fee_distribution_policy_try_new_valid() {
        let policy = FeeDistributionPolicy::try_new(8_000, 2_000).unwrap();
        assert_eq!(policy.burn_bps, 8_000);
        assert_eq!(policy.proposer_bps, 2_000);
    }

    #[test]
    fn test_fee_distribution_policy_try_new_invalid() {
        // Sum != 10,000
        assert!(FeeDistributionPolicy::try_new(5_000, 4_000).is_err());
        assert!(FeeDistributionPolicy::try_new(11_000, 0).is_err());
    }

    #[test]
    #[should_panic(expected = "must equal")]
    fn test_fee_distribution_policy_new_panics_invalid() {
        FeeDistributionPolicy::new(5_000, 4_000);
    }

    #[test]
    fn test_fee_distribution_burn_only() {
        let policy = FeeDistributionPolicy::burn_only();

        // 100% burn
        let (burn, proposer) = policy.distribute_fee(1000);
        assert_eq!(burn, 1000);
        assert_eq!(proposer, 0);
        assert_eq!(burn + proposer, 1000);

        // Zero fee
        let (burn, proposer) = policy.distribute_fee(0);
        assert_eq!(burn, 0);
        assert_eq!(proposer, 0);

        // Large fee
        let (burn, proposer) = policy.distribute_fee(u128::MAX);
        assert_eq!(burn, u128::MAX);
        assert_eq!(proposer, 0);
    }

    #[test]
    fn test_fee_distribution_mainnet_default() {
        let policy = FeeDistributionPolicy::mainnet_default();

        // 50/50 split
        let (burn, proposer) = policy.distribute_fee(1000);
        assert_eq!(burn, 500);
        assert_eq!(proposer, 500);
        assert_eq!(burn + proposer, 1000);

        // Odd number (rounding)
        let (burn, proposer) = policy.distribute_fee(1001);
        // 1001 * 5000 / 10000 = 500 (proposer)
        // 1001 - 500 = 501 (burn)
        assert_eq!(proposer, 500);
        assert_eq!(burn, 501);
        assert_eq!(burn + proposer, 1001);

        // Zero fee
        let (burn, proposer) = policy.distribute_fee(0);
        assert_eq!(burn, 0);
        assert_eq!(proposer, 0);
    }

    #[test]
    fn test_fee_distribution_custom_70_30() {
        let policy = FeeDistributionPolicy::new(7_000, 3_000);

        let (burn, proposer) = policy.distribute_fee(1000);
        // 1000 * 3000 / 10000 = 300 (proposer)
        // 1000 - 300 = 700 (burn)
        assert_eq!(proposer, 300);
        assert_eq!(burn, 700);
        assert_eq!(burn + proposer, 1000);
    }

    #[test]
    fn test_fee_distribution_proposer_only() {
        let policy = FeeDistributionPolicy::new(0, 10_000);

        let (burn, proposer) = policy.distribute_fee(1000);
        assert_eq!(burn, 0);
        assert_eq!(proposer, 1000);
        assert_eq!(burn + proposer, 1000);
    }

    #[test]
    fn test_fee_distribution_conservation_property() {
        // Property: For any fee and any valid policy, burn + proposer == total_fee
        let policies = [
            FeeDistributionPolicy::burn_only(),
            FeeDistributionPolicy::mainnet_default(),
            FeeDistributionPolicy::new(0, 10_000),
            FeeDistributionPolicy::new(3_333, 6_667),
            FeeDistributionPolicy::new(9_999, 1),
        ];

        let fees: Vec<u128> = vec![0, 1, 100, 999, 1000, 10000, 100001, u128::MAX / 2];

        for policy in &policies {
            for &fee in &fees {
                let (burn, proposer) = policy.distribute_fee(fee);
                assert_eq!(
                    burn + proposer,
                    fee,
                    "Conservation failed for fee={} with policy {:?}",
                    fee,
                    policy
                );
            }
        }
    }

    #[test]
    fn test_fee_distribution_policy_display() {
        let policy = FeeDistributionPolicy::mainnet_default();
        let s = format!("{}", policy);
        assert!(s.contains("burn=50.0%"));
        assert!(s.contains("proposer=50.0%"));
    }

    #[test]
    fn test_execution_gas_config_mainnet() {
        let config = ExecutionGasConfig::mainnet();
        assert!(config.enabled);
        assert_eq!(config.block_gas_limit, BLOCK_GAS_LIMIT_DEFAULT);
        assert_eq!(
            config.fee_distribution_policy,
            FeeDistributionPolicy::mainnet_default()
        );
        assert!(config.has_proposer_rewards());
    }

    #[test]
    fn test_execution_gas_config_default_is_burn_only() {
        let config = ExecutionGasConfig::default();
        assert!(config.fee_distribution_policy.is_burn_only());
        assert!(!config.has_proposer_rewards());
    }

    #[test]
    fn test_execution_gas_config_with_fee_policy() {
        let policy = FeeDistributionPolicy::new(6_000, 4_000);
        let config = ExecutionGasConfig::enabled().with_fee_policy(policy);
        assert_eq!(config.fee_distribution_policy.burn_bps, 6_000);
        assert_eq!(config.fee_distribution_policy.proposer_bps, 4_000);
    }

    #[test]
    fn test_execution_gas_config_enabled_with_policy() {
        let policy = FeeDistributionPolicy::mainnet_default();
        let config = ExecutionGasConfig::enabled_with_policy(policy);
        assert!(config.enabled);
        assert!(!config.fee_distribution_policy.is_burn_only());
    }
}