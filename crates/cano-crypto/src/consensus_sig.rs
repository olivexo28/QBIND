//! Consensus signature verification interface.
//!
//! This module defines an algorithm-agnostic interface for verifying consensus
//! signatures. It is designed to be PQC-friendly and does not assume any specific
//! signature algorithm.
//!
//! # Design Notes
//!
//! - This module is verification-only; signing is handled separately.
//! - Uses primitive types (`u64`, `&[u8]`) to avoid circular dependencies with
//!   `cano-consensus` where `ValidatorId` and `ValidatorPublicKey` are defined.
//! - The actual integration with typed IDs happens in `cano-consensus`'s
//!   `CryptoConsensusVerifier`.
//! - The `ConsensusSigSuiteId` type provides cryptographic agility for multi-suite
//!   support without committing to specific algorithms.

use std::fmt;

/// Opaque identifier for a consensus signature suite.
///
/// This type enables cryptographic agility by allowing the system to support
/// multiple signature algorithms (e.g., classical, post-quantum) without
/// hard-coding specific choices. The numeric value is intentionally opaque
/// and should be treated as an identifier, not a meaningful quantity.
///
/// # Design Notes
///
/// - The `u16` size provides ample room for future suite IDs while remaining
///   compact for storage and transmission.
/// - Constants like `SUITE_TOY_SHA3` are defined for testing; real PQ suites
///   will be added in future tasks.
/// - This type is `Copy` for convenient use in function signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ConsensusSigSuiteId(pub u16);

impl ConsensusSigSuiteId {
    /// Create a new suite ID from a raw `u16` value.
    pub const fn new(id: u16) -> Self {
        ConsensusSigSuiteId(id)
    }

    /// Get the raw `u16` value.
    pub const fn as_u16(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for ConsensusSigSuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "suite_{}", self.0)
    }
}

/// Test-only SHA3-based signature suite identifier.
///
/// This suite is used for testing the verification pipeline and is
/// **NOT FOR PRODUCTION USE**. Real post-quantum suites will be added
/// in future tasks.
pub const SUITE_TOY_SHA3: ConsensusSigSuiteId = ConsensusSigSuiteId(0);

/// Error type for consensus signature verification.
#[derive(Debug)]
pub enum ConsensusSigError {
    /// Key for this validator is missing in the registry / config.
    MissingKey(u64),
    /// Signature bytes are malformed (length, encoding, etc.).
    MalformedSignature,
    /// Signature verification failed.
    InvalidSignature,
    /// Any other backend-specific error.
    Other(String),
}

impl fmt::Display for ConsensusSigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusSigError::MissingKey(id) => {
                write!(f, "missing consensus key for validator {}", id)
            }
            ConsensusSigError::MalformedSignature => write!(f, "malformed consensus signature"),
            ConsensusSigError::InvalidSignature => write!(f, "invalid consensus signature"),
            ConsensusSigError::Other(msg) => write!(f, "consensus signature error: {}", msg),
        }
    }
}

impl std::error::Error for ConsensusSigError {}

/// Trait for consensus signature verification.
///
/// This intentionally does **not** assume any specific algorithm.
/// Implementations may be PQC, classical, or purely test-only.
///
/// # Type Notes
///
/// - `validator_id` is a `u64` (the raw value from `ValidatorId`).
/// - `pk` is a byte slice representing the validator's consensus public key.
/// - `preimage` is produced by `Vote::signing_preimage()` or `BlockProposal::signing_preimage()`.
/// - `signature` is the raw signature bytes carried on the wire.
pub trait ConsensusSigVerifier: Send + Sync {
    /// Verify a vote signature for this validator.
    ///
    /// `validator_id` is the validator's raw ID (from `ValidatorId::as_u64()`).
    /// `pk` is the validator's consensus public key bytes.
    /// `preimage` is produced by `Vote::signing_preimage()`.
    /// `signature` is the raw signature bytes carried on the wire.
    fn verify_vote(
        &self,
        validator_id: u64,
        pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError>;

    /// Verify a block proposal signature for this validator.
    ///
    /// `preimage` is produced by `BlockProposal::signing_preimage()`.
    fn verify_proposal(
        &self,
        validator_id: u64,
        pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError>;
}
