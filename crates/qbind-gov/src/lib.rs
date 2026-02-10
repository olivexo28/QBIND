//! QBIND Governance Library (T225).
//!
//! This crate provides the upgrade envelope toolchain for QBIND MainNet:
//!
//! - **Parsing**: Load upgrade envelopes and council keysets from JSON
//! - **Hashing**: Deterministic envelope hashing for signature verification
//! - **Verification**: Multi-signature verification against council keyset
//!
//! # Overview
//!
//! An **Upgrade Envelope** is a signed document that represents Protocol Council
//! approval for a specific protocol version. The envelope contains:
//!
//! - Protocol version and network environment (mainnet, testnet, etc.)
//! - Upgrade class (A: non-consensus, B: compatible, C: hard-fork)
//! - Activation height (for Class C upgrades)
//! - Binary hashes for each platform (SHA3-256)
//! - Council member signatures (ML-DSA-44)
//!
//! # Example
//!
//! ```ignore
//! use qbind_gov::{UpgradeEnvelope, CouncilKeySet, verify_envelope};
//!
//! // Load envelope and keyset
//! let envelope = UpgradeEnvelope::from_file("upgrade-envelope-v0.1.0.json")?;
//! let keyset = CouncilKeySet::from_file("council-pubkeys.json")?;
//!
//! // Verify signatures
//! let result = verify_envelope(&envelope, &keyset)?;
//! if result.is_valid() {
//!     println!("Envelope verified with {}/{} signatures",
//!              result.valid_count, result.threshold);
//! } else {
//!     println!("Verification failed: need {} signatures, have {}",
//!              result.threshold, result.valid_count);
//! }
//! ```
//!
//! # CLI Tool
//!
//! This crate includes the `qbind-envelope` CLI tool:
//!
//! ```bash
//! # Inspect an envelope (human-readable summary)
//! qbind-envelope inspect envelope.json
//!
//! # Verify an envelope (signatures, binary hash, threshold)
//! qbind-envelope verify \
//!     --envelope envelope.json \
//!     --council-keys council-pubkeys.json \
//!     --binary /usr/local/bin/qbind-node \
//!     --platform linux-x86_64
//! ```
//!
//! # Security Notes
//!
//! - Envelope digests use domain-separated SHA3-256 hashing
//! - Signatures use ML-DSA-44 (FIPS 204) post-quantum signatures
//! - The council threshold (e.g., 5-of-7) must be met for validity
//! - Binary hashes should be verified before deployment

pub mod council;
pub mod envelope;
pub mod hash;
pub mod verify;

// Re-export main types
pub use council::{CouncilKey, CouncilKeySet};
pub use envelope::{BinaryHashHex, CouncilSignature, EnvelopeError, UpgradeClass, UpgradeEnvelope};
pub use hash::{
    envelope_digest, envelope_digest_hex, sha3_256_bytes, sha3_256_file, sha3_256_file_hex,
};
pub use verify::{
    sign_envelope, verify_envelope, verify_envelope_threshold, SignatureVerification,
    VerificationResult,
};
