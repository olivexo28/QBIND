//! T232: Genesis & Launch State Specification v0
//!
//! This module defines the genesis state model for QBIND, including:
//! - Genesis configuration schema (JSON/TOML compatible)
//! - Rust types for genesis state validation
//! - Invariant checking for initial token supply, allocations, validators, council
//!
//! # Design Goals
//!
//! 1. **Auditable**: Clear schema with documented constraints
//! 2. **Replayable**: Deterministic genesis state from config
//! 3. **Validated**: Strong invariants checked at parse time
//!
//! # Schema Overview
//!
//! ```json
//! {
//!   "chain_id": "qbind-mainnet-v0",
//!   "genesis_time_unix_ms": 1738000000000,
//!   "allocations": [...],
//!   "validators": [...],
//!   "council": { "members": [...], "threshold": 2 },
//!   "monetary": { ... },
//!   "extra": {}
//! }
//! ```
//!
//! # Validation Rules
//!
//! - All allocation amounts must be > 0
//! - No duplicate addresses in allocations
//! - Validator count must be >= 1
//! - Council threshold must be <= member count and > 0
//! - Total supply (sum of allocations) must be > 0
//!
//! See: `docs/consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md` for detailed design.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::MonetaryEngineConfig;

// ============================================================================
// Genesis Allocation
// ============================================================================

/// An initial token allocation in the genesis state.
///
/// Represents tokens assigned to an address at genesis, optionally with
/// lockup restrictions.
///
/// # Fields
///
/// - `address`: The recipient address (32-byte hex string)
/// - `amount`: Token amount in base units (must be > 0)
/// - `memo`: Optional human-readable description (e.g., "Foundation allocation")
/// - `lockup_until_unix_ms`: Optional lockup expiry timestamp (tokens frozen until this time)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Recipient address (32-byte hex string, e.g., "0x123...abc").
    pub address: String,

    /// Token amount in base units (smallest denomination).
    /// Must be > 0.
    pub amount: u128,

    /// Optional human-readable memo for this allocation.
    /// Used for audit trails and documentation (e.g., "Early contributor", "Treasury").
    #[serde(default)]
    pub memo: Option<String>,

    /// Optional lockup expiry timestamp (Unix milliseconds).
    /// If set, tokens cannot be transferred until this time.
    /// If None, tokens are immediately liquid.
    #[serde(default)]
    pub lockup_until_unix_ms: Option<u64>,
}

impl GenesisAllocation {
    /// Create a new unlocked allocation.
    pub fn new(address: impl Into<String>, amount: u128) -> Self {
        Self {
            address: address.into(),
            amount,
            memo: None,
            lockup_until_unix_ms: None,
        }
    }

    /// Create a new allocation with lockup.
    pub fn with_lockup(
        address: impl Into<String>,
        amount: u128,
        lockup_until_unix_ms: u64,
    ) -> Self {
        Self {
            address: address.into(),
            amount,
            memo: None,
            lockup_until_unix_ms: Some(lockup_until_unix_ms),
        }
    }

    /// Create a new allocation with memo.
    pub fn with_memo(address: impl Into<String>, amount: u128, memo: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            amount,
            memo: Some(memo.into()),
            lockup_until_unix_ms: None,
        }
    }
}

// ============================================================================
// Genesis Validator
// ============================================================================

/// An initial validator in the genesis state.
///
/// Represents a validator in the initial validator set, including their
/// PQC public key material and initial stake.
///
/// # PQC Key Material
///
/// The `pqc_public_key` field contains the ML-DSA-44 public key encoded
/// as a hex string. This key is used for consensus signing and verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Validator address (32-byte hex string).
    pub address: String,

    /// PQC public key (ML-DSA-44) as hex string.
    /// This is the validator's signing key for consensus operations.
    pub pqc_public_key: String,

    /// Initial stake amount in base units.
    /// Must be > 0 for active validators.
    pub stake: u128,

    /// Optional human-readable name or identifier.
    #[serde(default)]
    pub name: Option<String>,

    /// Optional validator metadata (e.g., website, contact info).
    #[serde(default)]
    pub metadata: Option<String>,
}

impl GenesisValidator {
    /// Create a new genesis validator.
    pub fn new(address: impl Into<String>, pqc_public_key: impl Into<String>, stake: u128) -> Self {
        Self {
            address: address.into(),
            pqc_public_key: pqc_public_key.into(),
            stake,
            name: None,
            metadata: None,
        }
    }

    /// Create a genesis validator with name.
    pub fn with_name(
        address: impl Into<String>,
        pqc_public_key: impl Into<String>,
        stake: u128,
        name: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            pqc_public_key: pqc_public_key.into(),
            stake,
            name: Some(name.into()),
            metadata: None,
        }
    }
}

// ============================================================================
// Genesis Council Configuration
// ============================================================================

/// Configuration for the initial governance council.
///
/// The council is a multisig body that can authorize protocol upgrades
/// and emergency actions. The threshold specifies the minimum number
/// of council member signatures required for authorization.
///
/// # Invariants
///
/// - `threshold` must be > 0
/// - `threshold` must be <= members.len()
/// - All member addresses must be distinct
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisCouncilConfig {
    /// Council member addresses (32-byte hex strings).
    /// Each member can sign council proposals.
    pub members: Vec<String>,

    /// Minimum signatures required for council authorization.
    /// Must be > 0 and <= members.len().
    pub threshold: u32,
}

impl GenesisCouncilConfig {
    /// Create a new council configuration.
    pub fn new(members: Vec<String>, threshold: u32) -> Self {
        Self { members, threshold }
    }

    /// Validate the council configuration.
    ///
    /// Returns `Err` if:
    /// - threshold is 0
    /// - threshold > members.len()
    /// - members contains duplicates
    pub fn validate(&self) -> Result<(), GenesisValidationError> {
        // Check threshold bounds
        if self.threshold == 0 {
            return Err(GenesisValidationError::CouncilThresholdZero);
        }
        if self.threshold as usize > self.members.len() {
            return Err(GenesisValidationError::CouncilThresholdTooHigh {
                threshold: self.threshold,
                member_count: self.members.len(),
            });
        }

        // Check for duplicate members
        let mut seen = HashSet::new();
        for member in &self.members {
            if !seen.insert(member.clone()) {
                return Err(GenesisValidationError::DuplicateCouncilMember {
                    address: member.clone(),
                });
            }
        }

        Ok(())
    }
}

// ============================================================================
// Genesis Monetary Configuration
// ============================================================================

/// Monetary engine configuration for genesis.
///
/// This wraps the `MonetaryEngineConfig` from the monetary engine module
/// and adds genesis-specific validation.
///
/// # Initial Parameters
///
/// The genesis monetary config establishes the initial monetary policy:
/// - PQC premiums for compute, bandwidth, and storage
/// - Phase-specific parameters (Bootstrap, Transition, Mature)
/// - Alpha fee offset factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisMonetaryConfig {
    /// PQC compute premium (β_compute): higher CPU cost for ML-DSA-44 verification.
    /// Typical range: 0.20–0.35.
    pub pqc_premium_compute: f64,

    /// PQC bandwidth premium (β_bandwidth): larger signature sizes.
    /// Typical range: 0.10–0.20.
    pub pqc_premium_bandwidth: f64,

    /// PQC storage premium (β_storage): larger state footprint.
    /// Typical range: 0.05–0.15.
    pub pqc_premium_storage: f64,

    /// Bootstrap phase: target annual inflation rate.
    pub bootstrap_r_target_annual: f64,

    /// Bootstrap phase: inflation floor (typically 0.0).
    pub bootstrap_inflation_floor_annual: f64,

    /// Bootstrap phase: maximum annual inflation cap.
    pub bootstrap_max_annual_inflation_cap: f64,

    /// Bootstrap phase: EMA lambda in basis points.
    pub bootstrap_ema_lambda_bps: u16,

    /// Bootstrap phase: max Δr per epoch in basis points.
    pub bootstrap_max_delta_r_per_epoch_bps: u32,

    /// Transition phase: target annual inflation rate.
    pub transition_r_target_annual: f64,

    /// Transition phase: inflation floor (typically 0.0).
    pub transition_inflation_floor_annual: f64,

    /// Transition phase: maximum annual inflation cap.
    pub transition_max_annual_inflation_cap: f64,

    /// Transition phase: EMA lambda in basis points.
    pub transition_ema_lambda_bps: u16,

    /// Transition phase: max Δr per epoch in basis points.
    pub transition_max_delta_r_per_epoch_bps: u32,

    /// Mature phase: target annual inflation rate.
    pub mature_r_target_annual: f64,

    /// Mature phase: inflation floor (typically > 0).
    pub mature_inflation_floor_annual: f64,

    /// Mature phase: maximum annual inflation cap.
    pub mature_max_annual_inflation_cap: f64,

    /// Mature phase: EMA lambda in basis points.
    pub mature_ema_lambda_bps: u16,

    /// Mature phase: max Δr per epoch in basis points.
    pub mature_max_delta_r_per_epoch_bps: u32,

    /// Alpha fee offset factor (typically 1.0).
    pub alpha_fee_offset: f64,
}

impl GenesisMonetaryConfig {
    /// Create a genesis monetary config from a MonetaryEngineConfig.
    pub fn from_engine_config(config: &MonetaryEngineConfig) -> Self {
        Self {
            pqc_premium_compute: config.pqc_premium_compute,
            pqc_premium_bandwidth: config.pqc_premium_bandwidth,
            pqc_premium_storage: config.pqc_premium_storage,
            bootstrap_r_target_annual: config.bootstrap.r_target_annual,
            bootstrap_inflation_floor_annual: config.bootstrap.inflation_floor_annual,
            bootstrap_max_annual_inflation_cap: config.bootstrap.max_annual_inflation_cap,
            bootstrap_ema_lambda_bps: config.bootstrap.ema_lambda_bps,
            bootstrap_max_delta_r_per_epoch_bps: config.bootstrap.max_delta_r_inf_per_epoch_bps,
            transition_r_target_annual: config.transition.r_target_annual,
            transition_inflation_floor_annual: config.transition.inflation_floor_annual,
            transition_max_annual_inflation_cap: config.transition.max_annual_inflation_cap,
            transition_ema_lambda_bps: config.transition.ema_lambda_bps,
            transition_max_delta_r_per_epoch_bps: config.transition.max_delta_r_inf_per_epoch_bps,
            mature_r_target_annual: config.mature.r_target_annual,
            mature_inflation_floor_annual: config.mature.inflation_floor_annual,
            mature_max_annual_inflation_cap: config.mature.max_annual_inflation_cap,
            mature_ema_lambda_bps: config.mature.ema_lambda_bps,
            mature_max_delta_r_per_epoch_bps: config.mature.max_delta_r_inf_per_epoch_bps,
            alpha_fee_offset: config.alpha_fee_offset,
        }
    }

    /// Convert to a MonetaryEngineConfig.
    pub fn to_engine_config(&self) -> MonetaryEngineConfig {
        use crate::PhaseParameters;

        MonetaryEngineConfig {
            pqc_premium_compute: self.pqc_premium_compute,
            pqc_premium_bandwidth: self.pqc_premium_bandwidth,
            pqc_premium_storage: self.pqc_premium_storage,
            bootstrap: PhaseParameters {
                r_target_annual: self.bootstrap_r_target_annual,
                inflation_floor_annual: self.bootstrap_inflation_floor_annual,
                fee_smoothing_half_life_days: 30.0, // Default value
                max_annual_inflation_cap: self.bootstrap_max_annual_inflation_cap,
                ema_lambda_bps: self.bootstrap_ema_lambda_bps,
                max_delta_r_inf_per_epoch_bps: self.bootstrap_max_delta_r_per_epoch_bps,
            },
            transition: PhaseParameters {
                r_target_annual: self.transition_r_target_annual,
                inflation_floor_annual: self.transition_inflation_floor_annual,
                fee_smoothing_half_life_days: 60.0, // Default value
                max_annual_inflation_cap: self.transition_max_annual_inflation_cap,
                ema_lambda_bps: self.transition_ema_lambda_bps,
                max_delta_r_inf_per_epoch_bps: self.transition_max_delta_r_per_epoch_bps,
            },
            mature: PhaseParameters {
                r_target_annual: self.mature_r_target_annual,
                inflation_floor_annual: self.mature_inflation_floor_annual,
                fee_smoothing_half_life_days: 90.0, // Default value
                max_annual_inflation_cap: self.mature_max_annual_inflation_cap,
                ema_lambda_bps: self.mature_ema_lambda_bps,
                max_delta_r_inf_per_epoch_bps: self.mature_max_delta_r_per_epoch_bps,
            },
            alpha_fee_offset: self.alpha_fee_offset,
        }
    }

    /// Create a default MainNet monetary configuration.
    pub fn mainnet_default() -> Self {
        Self {
            pqc_premium_compute: 0.30,
            pqc_premium_bandwidth: 0.15,
            pqc_premium_storage: 0.10,
            bootstrap_r_target_annual: 0.05,
            bootstrap_inflation_floor_annual: 0.0,
            bootstrap_max_annual_inflation_cap: 0.12,
            bootstrap_ema_lambda_bps: 700,
            bootstrap_max_delta_r_per_epoch_bps: 25,
            transition_r_target_annual: 0.04,
            transition_inflation_floor_annual: 0.0,
            transition_max_annual_inflation_cap: 0.10,
            transition_ema_lambda_bps: 300,
            transition_max_delta_r_per_epoch_bps: 10,
            mature_r_target_annual: 0.03,
            mature_inflation_floor_annual: 0.01,
            mature_max_annual_inflation_cap: 0.08,
            mature_ema_lambda_bps: 150,
            mature_max_delta_r_per_epoch_bps: 5,
            alpha_fee_offset: 1.0,
        }
    }
}

// ============================================================================
// Top-Level Genesis Configuration
// ============================================================================

/// Top-level genesis configuration for QBIND.
///
/// This is the canonical schema for `genesis.json`. It defines:
/// - Chain identity (chain_id, genesis_time)
/// - Initial token allocations
/// - Initial validator set
/// - Initial governance council
/// - Initial monetary parameters
///
/// # Validation
///
/// Call `validate()` after parsing to check all invariants:
/// - All allocations have amount > 0
/// - No duplicate addresses in allocations
/// - At least one validator
/// - Council threshold is valid
/// - Total supply > 0
///
/// # Example (JSON)
///
/// ```json
/// {
///   "chain_id": "qbind-mainnet-v0",
///   "genesis_time_unix_ms": 1738000000000,
///   "allocations": [
///     { "address": "0x123...", "amount": 1000000000, "memo": "Foundation" }
///   ],
///   "validators": [
///     { "address": "0xabc...", "pqc_public_key": "...", "stake": 100000 }
///   ],
///   "council": { "members": ["0x111...", "0x222...", "0x333..."], "threshold": 2 },
///   "monetary": { ... }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Chain identifier (e.g., "qbind-mainnet-v0", "qbind-testnet-beta").
    ///
    /// This value MUST match the chain_id used by all nodes on the network.
    /// It is embedded in all domain-separated signatures to prevent cross-chain replay.
    pub chain_id: String,

    /// Genesis timestamp (Unix milliseconds).
    ///
    /// The canonical start time of the blockchain. All nodes MUST agree on this value.
    /// Used for time-based lockup validation and historical reference.
    pub genesis_time_unix_ms: u64,

    /// Initial token allocations.
    ///
    /// Defines the initial token distribution at genesis. The sum of all amounts
    /// is the total initial supply.
    pub allocations: Vec<GenesisAllocation>,

    /// Initial validator set.
    ///
    /// Defines the validators that can participate in consensus from genesis.
    /// Must contain at least one validator.
    pub validators: Vec<GenesisValidator>,

    /// Initial governance council configuration.
    ///
    /// Defines the multisig council for protocol upgrades and emergency actions.
    pub council: GenesisCouncilConfig,

    /// Initial monetary engine parameters.
    ///
    /// Defines the starting monetary policy parameters (inflation targets, premiums, etc.).
    pub monetary: GenesisMonetaryConfig,

    /// Reserved for future extensions.
    ///
    /// Additional fields can be stored here without breaking schema compatibility.
    /// This allows adding new genesis features without changing the core schema.
    #[serde(default)]
    pub extra: serde_json::Value,
}

impl GenesisConfig {
    /// Create a new genesis configuration.
    pub fn new(
        chain_id: impl Into<String>,
        genesis_time_unix_ms: u64,
        allocations: Vec<GenesisAllocation>,
        validators: Vec<GenesisValidator>,
        council: GenesisCouncilConfig,
        monetary: GenesisMonetaryConfig,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            genesis_time_unix_ms,
            allocations,
            validators,
            council,
            monetary,
            extra: serde_json::Value::Null,
        }
    }

    /// Validate the genesis configuration.
    ///
    /// Checks all invariants:
    /// - All allocations have amount > 0
    /// - No duplicate addresses in allocations
    /// - At least one validator
    /// - Council threshold is valid
    /// - Total supply > 0
    /// - Chain ID is non-empty
    ///
    /// Returns `Err(GenesisValidationError)` if any invariant is violated.
    pub fn validate(&self) -> Result<(), GenesisValidationError> {
        // Check chain_id is non-empty
        if self.chain_id.is_empty() {
            return Err(GenesisValidationError::EmptyChainId);
        }

        // Check allocations
        if self.allocations.is_empty() {
            return Err(GenesisValidationError::NoAllocations);
        }

        let mut seen_addresses = HashSet::new();
        let mut total_supply: u128 = 0;

        for alloc in &self.allocations {
            // Check amount > 0
            if alloc.amount == 0 {
                return Err(GenesisValidationError::ZeroAllocationAmount {
                    address: alloc.address.clone(),
                });
            }

            // Check for empty address
            if alloc.address.is_empty() {
                return Err(GenesisValidationError::EmptyAddress);
            }

            // Check for duplicate addresses
            if !seen_addresses.insert(alloc.address.clone()) {
                return Err(GenesisValidationError::DuplicateAllocationAddress {
                    address: alloc.address.clone(),
                });
            }

            // Accumulate total supply (check for overflow)
            total_supply = total_supply
                .checked_add(alloc.amount)
                .ok_or(GenesisValidationError::TotalSupplyOverflow)?;
        }

        // Check total supply > 0 (implied by non-empty allocations with amount > 0)
        if total_supply == 0 {
            return Err(GenesisValidationError::ZeroTotalSupply);
        }

        // Check validators
        if self.validators.is_empty() {
            return Err(GenesisValidationError::NoValidators);
        }

        // Check validator addresses are distinct and non-empty
        let mut validator_addresses = HashSet::new();
        for validator in &self.validators {
            if validator.address.is_empty() {
                return Err(GenesisValidationError::EmptyAddress);
            }
            if validator.pqc_public_key.is_empty() {
                return Err(GenesisValidationError::EmptyValidatorPqcKey {
                    address: validator.address.clone(),
                });
            }
            if !validator_addresses.insert(validator.address.clone()) {
                return Err(GenesisValidationError::DuplicateValidatorAddress {
                    address: validator.address.clone(),
                });
            }
        }

        // Validate council configuration
        self.council.validate()?;

        Ok(())
    }

    /// Compute the total initial supply from allocations.
    pub fn total_supply(&self) -> u128 {
        self.allocations.iter().map(|a| a.amount).sum()
    }

    /// Get the number of initial validators.
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Get the number of council members.
    pub fn council_member_count(&self) -> usize {
        self.council.members.len()
    }
}

// ============================================================================
// Genesis Validation Errors
// ============================================================================

/// Error type for genesis configuration validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisValidationError {
    /// Chain ID is empty.
    EmptyChainId,

    /// No allocations defined in genesis.
    NoAllocations,

    /// An allocation has zero amount.
    ZeroAllocationAmount { address: String },

    /// An address is empty.
    EmptyAddress,

    /// Duplicate address in allocations.
    DuplicateAllocationAddress { address: String },

    /// Total supply would overflow u128.
    TotalSupplyOverflow,

    /// Total supply is zero.
    ZeroTotalSupply,

    /// No validators defined in genesis.
    NoValidators,

    /// Duplicate validator address.
    DuplicateValidatorAddress { address: String },

    /// Validator has empty PQC public key.
    EmptyValidatorPqcKey { address: String },

    /// Council threshold is zero.
    CouncilThresholdZero,

    /// Council threshold exceeds member count.
    CouncilThresholdTooHigh { threshold: u32, member_count: usize },

    /// Duplicate council member address.
    DuplicateCouncilMember { address: String },
}

impl std::fmt::Display for GenesisValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenesisValidationError::EmptyChainId => {
                write!(f, "chain_id must be non-empty")
            }
            GenesisValidationError::NoAllocations => {
                write!(f, "genesis must have at least one allocation")
            }
            GenesisValidationError::ZeroAllocationAmount { address } => {
                write!(f, "allocation for {} has zero amount", address)
            }
            GenesisValidationError::EmptyAddress => {
                write!(f, "address must be non-empty")
            }
            GenesisValidationError::DuplicateAllocationAddress { address } => {
                write!(f, "duplicate allocation address: {}", address)
            }
            GenesisValidationError::TotalSupplyOverflow => {
                write!(f, "total supply would overflow u128")
            }
            GenesisValidationError::ZeroTotalSupply => {
                write!(f, "total supply must be > 0")
            }
            GenesisValidationError::NoValidators => {
                write!(f, "genesis must have at least one validator")
            }
            GenesisValidationError::DuplicateValidatorAddress { address } => {
                write!(f, "duplicate validator address: {}", address)
            }
            GenesisValidationError::EmptyValidatorPqcKey { address } => {
                write!(f, "validator {} has empty PQC public key", address)
            }
            GenesisValidationError::CouncilThresholdZero => {
                write!(f, "council threshold must be > 0")
            }
            GenesisValidationError::CouncilThresholdTooHigh {
                threshold,
                member_count,
            } => {
                write!(
                    f,
                    "council threshold {} exceeds member count {}",
                    threshold, member_count
                )
            }
            GenesisValidationError::DuplicateCouncilMember { address } => {
                write!(f, "duplicate council member: {}", address)
            }
        }
    }
}

impl std::error::Error for GenesisValidationError {}

// ============================================================================
// T233: Genesis Hash Commitment Types
// ============================================================================

/// Type alias for a genesis hash (SHA3-256, 32 bytes).
///
/// This hash is computed over the exact bytes of the genesis JSON file,
/// with NO normalization, whitespace stripping, or key reordering.
///
/// # Canonical Definition
///
/// ```text
/// genesis_hash = SHA3-256(genesis_json_bytes)
/// ```
///
/// Where `genesis_json_bytes` is the exact file content as distributed.
pub type GenesisHash = [u8; 32];

/// Compute the canonical SHA3-256 genesis hash over raw bytes.
///
/// This function computes the SHA3-256 hash of the given bytes deterministically.
/// The bytes should be the exact content of the genesis JSON file.
///
/// # Important
///
/// - NO JSON normalization is applied
/// - NO whitespace stripping or key reordering
/// - The hash is computed over the exact file bytes as distributed
///
/// # Example
///
/// ```rust
/// use qbind_ledger::compute_genesis_hash_bytes;
///
/// let genesis_json = br#"{"chain_id": "qbind-mainnet-v0"}"#;
/// let hash = compute_genesis_hash_bytes(genesis_json);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn compute_genesis_hash_bytes(bytes: &[u8]) -> GenesisHash {
    qbind_hash::sha3_256(bytes)
}

/// Format a genesis hash as a hex string with 0x prefix.
///
/// # Example
///
/// ```rust
/// use qbind_ledger::{compute_genesis_hash_bytes, format_genesis_hash};
///
/// let hash = compute_genesis_hash_bytes(b"test");
/// let hex = format_genesis_hash(&hash);
/// assert!(hex.starts_with("0x"));
/// assert_eq!(hex.len(), 66); // 0x + 64 hex chars
/// ```
pub fn format_genesis_hash(hash: &GenesisHash) -> String {
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    format!("0x{}", hex)
}

/// Parse a genesis hash from a hex string (with or without 0x prefix).
///
/// # Arguments
///
/// * `hex_str` - A 64-character hex string, optionally prefixed with "0x"
///
/// # Returns
///
/// * `Ok(GenesisHash)` - The parsed 32-byte hash
/// * `Err(String)` - Error message if parsing fails
///
/// # Example
///
/// ```rust
/// use qbind_ledger::parse_genesis_hash;
///
/// // With 0x prefix
/// let hash1 = parse_genesis_hash(&format!("0x{}", "ab".repeat(32)));
/// assert!(hash1.is_ok());
///
/// // Without prefix
/// let hash2 = parse_genesis_hash(&"cd".repeat(32));
/// assert!(hash2.is_ok());
///
/// // Invalid length
/// let hash3 = parse_genesis_hash("0x1234");
/// assert!(hash3.is_err());
/// ```
pub fn parse_genesis_hash(hex_str: &str) -> Result<GenesisHash, String> {
    // Strip optional 0x prefix
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    // Check length (must be 64 hex chars for 32 bytes)
    if hex.len() != 64 {
        return Err(format!(
            "invalid genesis hash length: expected 64 hex characters, got {}",
            hex.len()
        ));
    }

    // Parse hex string to bytes
    let mut hash = [0u8; 32];
    for i in 0..32 {
        let byte_str = &hex[i * 2..i * 2 + 2];
        hash[i] = u8::from_str_radix(byte_str, 16).map_err(|e| {
            format!(
                "invalid hex character at position {}: {}",
                i * 2,
                e
            )
        })?;
    }

    Ok(hash)
}

// ============================================================================
// T233: Chain Metadata Types
// ============================================================================

/// Chain metadata stored during genesis application.
///
/// This structure captures the essential identity of a chain and is persisted
/// at height 0 when the genesis state is applied. It serves as a commitment
/// that can be verified by operators and auditors.
///
/// # Fields
///
/// - `chain_id`: The human-readable chain identifier (e.g., "qbind-mainnet-v0")
/// - `genesis_hash`: The SHA3-256 hash of the genesis JSON file bytes
///
/// # Usage
///
/// The `ChainMeta` is computed and stored during genesis application:
/// 1. Load genesis JSON file as raw bytes
/// 2. Compute `genesis_hash = SHA3-256(bytes)`
/// 3. Parse genesis config to extract `chain_id`
/// 4. Persist `ChainMeta { chain_id, genesis_hash }` as part of height 0 state
///
/// # Verification
///
/// Operators verify chain identity by:
/// 1. Computing the hash of their local genesis file
/// 2. Comparing against the stored `ChainMeta.genesis_hash`
/// 3. Using `--expect-genesis-hash` flag to fail fast on mismatch
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainMeta {
    /// Chain identifier from the genesis configuration.
    pub chain_id: String,

    /// SHA3-256 hash of the exact genesis JSON file bytes.
    pub genesis_hash: GenesisHash,
}

impl ChainMeta {
    /// Create a new ChainMeta.
    pub fn new(chain_id: impl Into<String>, genesis_hash: GenesisHash) -> Self {
        Self {
            chain_id: chain_id.into(),
            genesis_hash,
        }
    }

    /// Get the genesis hash as a hex string with 0x prefix.
    pub fn genesis_hash_hex(&self) -> String {
        format_genesis_hash(&self.genesis_hash)
    }
}

/// Errors that can occur when storing or loading chain metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainMetaError {
    /// Chain metadata already exists (attempted duplicate store).
    AlreadyExists,

    /// Chain metadata not found.
    NotFound,

    /// Serialization/deserialization error.
    SerializationError(String),

    /// Storage backend error.
    StorageError(String),
}

impl std::fmt::Display for ChainMetaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainMetaError::AlreadyExists => {
                write!(f, "chain metadata already exists (cannot re-apply genesis)")
            }
            ChainMetaError::NotFound => {
                write!(f, "chain metadata not found")
            }
            ChainMetaError::SerializationError(msg) => {
                write!(f, "chain metadata serialization error: {}", msg)
            }
            ChainMetaError::StorageError(msg) => {
                write!(f, "chain metadata storage error: {}", msg)
            }
        }
    }
}

impl std::error::Error for ChainMetaError {}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_monetary_config() -> GenesisMonetaryConfig {
        GenesisMonetaryConfig::mainnet_default()
    }

    fn valid_genesis_config() -> GenesisConfig {
        GenesisConfig::new(
            "qbind-testnet-v0",
            1738000000000,
            vec![
                GenesisAllocation::new("0x1111111111111111111111111111111111111111", 1_000_000),
                GenesisAllocation::new("0x2222222222222222222222222222222222222222", 2_000_000),
            ],
            vec![
                GenesisValidator::new(
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "pqc_key_validator_1",
                    100_000,
                ),
                GenesisValidator::new(
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "pqc_key_validator_2",
                    200_000,
                ),
            ],
            GenesisCouncilConfig::new(
                vec![
                    "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                    "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
                ],
                2,
            ),
            test_monetary_config(),
        )
    }

    #[test]
    fn test_genesis_valid_basic() {
        let config = valid_genesis_config();
        assert!(config.validate().is_ok());
        assert_eq!(config.total_supply(), 3_000_000);
        assert_eq!(config.validator_count(), 2);
        assert_eq!(config.council_member_count(), 3);
    }

    #[test]
    fn test_genesis_rejects_empty_chain_id() {
        let mut config = valid_genesis_config();
        config.chain_id = "".to_string();
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::EmptyChainId)
        ));
    }

    #[test]
    fn test_genesis_rejects_zero_allocation() {
        let mut config = valid_genesis_config();
        config.allocations[0].amount = 0;
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::ZeroAllocationAmount { .. })
        ));
    }

    #[test]
    fn test_genesis_rejects_duplicate_allocation_address() {
        let mut config = valid_genesis_config();
        config.allocations[1].address = config.allocations[0].address.clone();
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::DuplicateAllocationAddress { .. })
        ));
    }

    #[test]
    fn test_genesis_rejects_no_validators() {
        let mut config = valid_genesis_config();
        config.validators.clear();
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::NoValidators)
        ));
    }

    #[test]
    fn test_genesis_rejects_duplicate_validator_address() {
        let mut config = valid_genesis_config();
        config.validators[1].address = config.validators[0].address.clone();
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::DuplicateValidatorAddress { .. })
        ));
    }

    #[test]
    fn test_genesis_rejects_council_threshold_zero() {
        let mut config = valid_genesis_config();
        config.council.threshold = 0;
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::CouncilThresholdZero)
        ));
    }

    #[test]
    fn test_genesis_rejects_council_threshold_too_high() {
        let mut config = valid_genesis_config();
        config.council.threshold = 10; // Only 3 members
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::CouncilThresholdTooHigh { .. })
        ));
    }

    #[test]
    fn test_genesis_monetary_config_roundtrip() {
        use crate::MonetaryEngineConfig;

        // Create an engine config
        let engine_config = MonetaryEngineConfig {
            pqc_premium_compute: 0.30,
            pqc_premium_bandwidth: 0.15,
            pqc_premium_storage: 0.10,
            bootstrap: crate::PhaseParameters {
                r_target_annual: 0.05,
                inflation_floor_annual: 0.0,
                fee_smoothing_half_life_days: 30.0,
                max_annual_inflation_cap: 0.12,
                ema_lambda_bps: 700,
                max_delta_r_inf_per_epoch_bps: 25,
            },
            transition: crate::PhaseParameters {
                r_target_annual: 0.04,
                inflation_floor_annual: 0.0,
                fee_smoothing_half_life_days: 60.0,
                max_annual_inflation_cap: 0.10,
                ema_lambda_bps: 300,
                max_delta_r_inf_per_epoch_bps: 10,
            },
            mature: crate::PhaseParameters {
                r_target_annual: 0.03,
                inflation_floor_annual: 0.01,
                fee_smoothing_half_life_days: 90.0,
                max_annual_inflation_cap: 0.08,
                ema_lambda_bps: 150,
                max_delta_r_inf_per_epoch_bps: 5,
            },
            alpha_fee_offset: 1.0,
        };

        // Convert to genesis config
        let genesis_monetary = GenesisMonetaryConfig::from_engine_config(&engine_config);

        // Convert back
        let roundtrip = genesis_monetary.to_engine_config();

        // Check key fields match
        assert_eq!(
            roundtrip.pqc_premium_compute,
            engine_config.pqc_premium_compute
        );
        assert_eq!(
            roundtrip.bootstrap.r_target_annual,
            engine_config.bootstrap.r_target_annual
        );
        assert_eq!(
            roundtrip.mature.inflation_floor_annual,
            engine_config.mature.inflation_floor_annual
        );
    }

    #[test]
    fn test_allocation_constructors() {
        let alloc1 = GenesisAllocation::new("0x1234", 1000);
        assert_eq!(alloc1.amount, 1000);
        assert!(alloc1.lockup_until_unix_ms.is_none());
        assert!(alloc1.memo.is_none());

        let alloc2 = GenesisAllocation::with_lockup("0x1234", 1000, 1800000000000);
        assert_eq!(alloc2.lockup_until_unix_ms, Some(1800000000000));

        let alloc3 = GenesisAllocation::with_memo("0x1234", 1000, "Foundation");
        assert_eq!(alloc3.memo, Some("Foundation".to_string()));
    }

    #[test]
    fn test_validator_constructors() {
        let v1 = GenesisValidator::new("0xabc", "pqc_key_1", 10000);
        assert!(v1.name.is_none());

        let v2 = GenesisValidator::with_name("0xabc", "pqc_key_1", 10000, "Validator One");
        assert_eq!(v2.name, Some("Validator One".to_string()));
    }
}