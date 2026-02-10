//! Upgrade envelope data structures (T225).
//!
//! This module defines the data model for upgrade envelopes as specified
//! in the QBIND Governance & Upgrades Design (T224).
//!
//! # Example
//!
//! ```ignore
//! use qbind_gov::envelope::{UpgradeEnvelope, UpgradeClass};
//!
//! let json = r#"{
//!     "envelope_version": "1.0",
//!     "envelope_id": "T225-2026-02-08-001",
//!     "protocol_version": "0.1.0",
//!     "network_environment": "mainnet",
//!     "class": "c_hard_fork",
//!     "version": "0.1.0",
//!     "activation_height": 1000000,
//!     "binary_hashes": {
//!         "linux-x86_64": "abc123..."
//!     },
//!     "notes": "MainNet v0.1.0",
//!     "council_approvals": []
//! }"#;
//!
//! let envelope: UpgradeEnvelope = serde_json::from_str(json)?;
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Upgrade class as per T224 governance design.
///
/// Upgrade classes determine the coordination level required:
/// - Class A: Non-consensus changes (CLI, docs) — no coordination
/// - Class B: Consensus-compatible — rolling deployment
/// - Class C: Hard-fork / protocol changes — coordinated activation
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeClass {
    /// Class A: Non-consensus changes (CLI tooling, documentation, tests).
    /// No coordination required; operators upgrade at convenience.
    ANonConsensus,
    /// Class B: Consensus-compatible upgrades (performance, internal refactoring).
    /// Rolling deployment; operators upgrade within a window.
    BConsensusCompatible,
    /// Class C: Hard-fork / protocol changes (consensus rules, block format).
    /// Coordinated activation; must upgrade before activation height.
    CHardFork,
}

impl std::fmt::Display for UpgradeClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpgradeClass::ANonConsensus => write!(f, "A (Non-Consensus)"),
            UpgradeClass::BConsensusCompatible => write!(f, "B (Consensus-Compatible)"),
            UpgradeClass::CHardFork => write!(f, "C (Hard-Fork)"),
        }
    }
}

/// Platform identifier for binary hashes (e.g., "linux-x86_64", "darwin-aarch64").
pub type PlatformId = String;

/// SHA3-256 hash stored as hex string.
///
/// Binary hashes in the envelope are stored as lowercase hex-encoded SHA3-256 digests.
/// This allows easy verification against local binaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryHashHex(pub String);

impl BinaryHashHex {
    /// Create a new BinaryHashHex from a hex string.
    pub fn new(hex: impl Into<String>) -> Self {
        BinaryHashHex(hex.into())
    }

    /// Return the hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate that the hex string is a valid 64-character hex string (SHA3-256).
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.0.len() != 64 {
            return Err(EnvelopeError::InvalidBinaryHash(format!(
                "expected 64 hex characters, got {}",
                self.0.len()
            )));
        }
        if !self.0.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(EnvelopeError::InvalidBinaryHash(
                "hash contains non-hex characters".to_string(),
            ));
        }
        Ok(())
    }

    /// Decode the hex string to bytes.
    pub fn to_bytes(&self) -> Result<[u8; 32], EnvelopeError> {
        let bytes = hex::decode(&self.0)
            .map_err(|e| EnvelopeError::InvalidBinaryHash(format!("hex decode: {}", e)))?;
        if bytes.len() != 32 {
            return Err(EnvelopeError::InvalidBinaryHash(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// A council member's signature on an upgrade envelope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CouncilSignature {
    /// Unique identifier for the council member (e.g., "council-1").
    pub member_id: String,

    /// ML-DSA-44 public key bytes as hex-encoded string.
    pub public_key: String,

    /// ML-DSA-44 signature bytes as hex-encoded string.
    pub signature: String,

    /// ISO 8601 timestamp when the signature was created.
    pub timestamp: String,
}

impl CouncilSignature {
    /// Decode the public key from hex to bytes.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        hex::decode(&self.public_key)
            .map_err(|e| EnvelopeError::InvalidSignature(format!("public key hex: {}", e)))
    }

    /// Decode the signature from hex to bytes.
    pub fn signature_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        hex::decode(&self.signature)
            .map_err(|e| EnvelopeError::InvalidSignature(format!("signature hex: {}", e)))
    }
}

/// Upgrade envelope: a signed document authorizing a protocol upgrade.
///
/// The envelope is the authoritative record for upgrade decisions and contains:
/// - Protocol version and network environment
/// - Upgrade class (A/B/C)
/// - Activation parameters (height for Class C)
/// - Binary hashes for each platform
/// - Council member signatures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpgradeEnvelope {
    /// Envelope format version (e.g., "1.0").
    #[serde(default = "default_envelope_version")]
    pub envelope_version: String,

    /// Unique envelope identifier (e.g., "T225-2026-02-08-001").
    #[serde(default)]
    pub envelope_id: String,

    /// Target protocol version string (e.g., "0.1.0").
    pub protocol_version: String,

    /// Network environment: "mainnet", "testnet", "devnet", etc.
    pub network_environment: String,

    /// Upgrade class (A/B/C).
    pub class: UpgradeClass,

    /// Semantic version string for the upgrade (may match protocol_version).
    #[serde(default)]
    pub version: String,

    /// Activation height for Class C upgrades.
    /// For Class A/B, this may be 0 or omitted.
    #[serde(default)]
    pub activation_height: u64,

    /// Map from platform ID (e.g., "linux-x86_64") to SHA3-256 binary hash.
    #[serde(default)]
    pub binary_hashes: BTreeMap<PlatformId, BinaryHashHex>,

    /// Human-readable notes about this upgrade.
    #[serde(default)]
    pub notes: String,

    /// Council member signatures approving this envelope.
    #[serde(default)]
    pub council_approvals: Vec<CouncilSignature>,
}

fn default_envelope_version() -> String {
    "1.0".to_string()
}

impl UpgradeEnvelope {
    /// Parse an upgrade envelope from JSON.
    pub fn from_json(json: &str) -> Result<Self, EnvelopeError> {
        serde_json::from_str(json).map_err(|e| EnvelopeError::ParseError(e.to_string()))
    }

    /// Parse an upgrade envelope from a JSON file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, EnvelopeError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| EnvelopeError::IoError(format!("read {}: {}", path.display(), e)))?;
        Self::from_json(&content)
    }

    /// Serialize the envelope to JSON (pretty-printed).
    pub fn to_json_pretty(&self) -> Result<String, EnvelopeError> {
        serde_json::to_string_pretty(self).map_err(|e| EnvelopeError::SerializeError(e.to_string()))
    }

    /// Validate the envelope structure.
    ///
    /// Checks:
    /// - Envelope version is supported
    /// - Protocol version is non-empty
    /// - Network environment is non-empty
    /// - Activation height is set for Class C upgrades
    /// - Binary hashes are valid hex
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        // Check envelope version
        if self.envelope_version != "1.0" {
            return Err(EnvelopeError::UnsupportedVersion(
                self.envelope_version.clone(),
            ));
        }

        // Check required fields
        if self.protocol_version.is_empty() {
            return Err(EnvelopeError::MissingField("protocol_version".to_string()));
        }
        if self.network_environment.is_empty() {
            return Err(EnvelopeError::MissingField(
                "network_environment".to_string(),
            ));
        }

        // Class C requires activation height
        if self.class == UpgradeClass::CHardFork && self.activation_height == 0 {
            return Err(EnvelopeError::MissingField(
                "activation_height (required for Class C)".to_string(),
            ));
        }

        // Validate binary hashes
        for (platform, hash) in &self.binary_hashes {
            hash.validate()
                .map_err(|e| EnvelopeError::InvalidBinaryHash(format!("{} ({})", e, platform)))?;
        }

        Ok(())
    }

    /// Get the binary hash for a specific platform.
    pub fn binary_hash(&self, platform: &str) -> Option<&BinaryHashHex> {
        self.binary_hashes.get(platform)
    }

    /// Number of council approvals.
    pub fn approval_count(&self) -> usize {
        self.council_approvals.len()
    }

    /// Check if the envelope has at least the required number of approvals.
    pub fn has_threshold(&self, threshold: usize) -> bool {
        self.council_approvals.len() >= threshold
    }
}

/// Errors that can occur when working with upgrade envelopes.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("parse error: {0}")]
    ParseError(String),

    #[error("serialize error: {0}")]
    SerializeError(String),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(String),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid binary hash: {0}")]
    InvalidBinaryHash(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("threshold not met: need {required} signatures, have {actual}")]
    ThresholdNotMet { required: usize, actual: usize },

    #[error("unknown council member: {0}")]
    UnknownCouncilMember(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upgrade_class_display() {
        assert_eq!(
            format!("{}", UpgradeClass::ANonConsensus),
            "A (Non-Consensus)"
        );
        assert_eq!(
            format!("{}", UpgradeClass::BConsensusCompatible),
            "B (Consensus-Compatible)"
        );
        assert_eq!(format!("{}", UpgradeClass::CHardFork), "C (Hard-Fork)");
    }

    #[test]
    fn test_upgrade_class_serde() {
        let a = serde_json::to_string(&UpgradeClass::ANonConsensus).unwrap();
        assert_eq!(a, "\"a_non_consensus\"");
        let b = serde_json::to_string(&UpgradeClass::BConsensusCompatible).unwrap();
        assert_eq!(b, "\"b_consensus_compatible\"");
        let c = serde_json::to_string(&UpgradeClass::CHardFork).unwrap();
        assert_eq!(c, "\"c_hard_fork\"");

        let decoded: UpgradeClass = serde_json::from_str("\"c_hard_fork\"").unwrap();
        assert_eq!(decoded, UpgradeClass::CHardFork);
    }

    #[test]
    fn test_binary_hash_hex_validate() {
        // Valid 64-char hex
        let valid = BinaryHashHex::new("a".repeat(64));
        assert!(valid.validate().is_ok());

        // Too short
        let short = BinaryHashHex::new("abc");
        assert!(short.validate().is_err());

        // Non-hex characters
        let invalid = BinaryHashHex::new("g".repeat(64));
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_binary_hash_hex_to_bytes() {
        let hash = BinaryHashHex::new("00".repeat(32));
        let bytes = hash.to_bytes().unwrap();
        assert_eq!(bytes, [0u8; 32]);

        let hash2 = BinaryHashHex::new("ff".repeat(32));
        let bytes2 = hash2.to_bytes().unwrap();
        assert_eq!(bytes2, [0xff; 32]);
    }

    #[test]
    fn test_envelope_parse() {
        let json = r#"{
            "envelope_version": "1.0",
            "envelope_id": "T225-001",
            "protocol_version": "0.1.0",
            "network_environment": "mainnet",
            "class": "c_hard_fork",
            "version": "0.1.0",
            "activation_height": 1000000,
            "binary_hashes": {
                "linux-x86_64": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "notes": "Test upgrade",
            "council_approvals": []
        }"#;

        let envelope = UpgradeEnvelope::from_json(json).unwrap();
        assert_eq!(envelope.envelope_id, "T225-001");
        assert_eq!(envelope.protocol_version, "0.1.0");
        assert_eq!(envelope.network_environment, "mainnet");
        assert_eq!(envelope.class, UpgradeClass::CHardFork);
        assert_eq!(envelope.activation_height, 1000000);
        assert_eq!(envelope.binary_hashes.len(), 1);
    }

    #[test]
    fn test_envelope_validate_missing_activation_height() {
        let json = r#"{
            "protocol_version": "0.1.0",
            "network_environment": "mainnet",
            "class": "c_hard_fork",
            "activation_height": 0
        }"#;

        let envelope = UpgradeEnvelope::from_json(json).unwrap();
        let result = envelope.validate();
        assert!(matches!(result, Err(EnvelopeError::MissingField(_))));
    }

    #[test]
    fn test_envelope_validate_class_b_no_activation() {
        let json = r#"{
            "protocol_version": "0.1.0",
            "network_environment": "mainnet",
            "class": "b_consensus_compatible"
        }"#;

        let envelope = UpgradeEnvelope::from_json(json).unwrap();
        // Class B does not require activation height
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn test_envelope_approval_count() {
        let json = r#"{
            "protocol_version": "0.1.0",
            "network_environment": "mainnet",
            "class": "a_non_consensus",
            "council_approvals": [
                {"member_id": "c1", "public_key": "aa", "signature": "bb", "timestamp": "2026-01-01T00:00:00Z"},
                {"member_id": "c2", "public_key": "cc", "signature": "dd", "timestamp": "2026-01-01T00:00:00Z"}
            ]
        }"#;

        let envelope = UpgradeEnvelope::from_json(json).unwrap();
        assert_eq!(envelope.approval_count(), 2);
        assert!(envelope.has_threshold(2));
        assert!(!envelope.has_threshold(3));
    }
}
