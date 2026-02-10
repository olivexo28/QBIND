//! Deterministic envelope hashing (T225).
//!
//! This module provides the canonical hashing logic for upgrade envelopes.
//! The hash is computed over a deterministic JSON representation to ensure
//! all council members sign the same digest.
//!
//! # Algorithm
//!
//! 1. Serialize the envelope to canonical JSON (sorted keys, no whitespace)
//! 2. Exclude the `council_approvals` field from the hash
//! 3. Compute SHA3-256 over the canonical bytes
//!
//! # Example
//!
//! ```ignore
//! use qbind_gov::hash::envelope_digest;
//! use qbind_gov::envelope::UpgradeEnvelope;
//!
//! let envelope = UpgradeEnvelope::from_file("envelope.json")?;
//! let digest = envelope_digest(&envelope)?;
//! println!("Envelope digest: {}", hex::encode(digest));
//! ```

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

use crate::envelope::{EnvelopeError, UpgradeEnvelope};

/// Domain separation tag for envelope hashing.
///
/// This tag is prepended to the canonical JSON before hashing to prevent
/// cross-protocol signature confusion.
pub const ENVELOPE_HASH_DOMAIN: &str = "QBIND-ENVELOPE-v1:";

/// Compute the canonical digest of an upgrade envelope.
///
/// The digest is used as the message for council signature verification.
/// It excludes the `council_approvals` field so that signatures can be
/// added incrementally without changing the digest.
///
/// # Algorithm
///
/// 1. Extract hashable fields (excluding council_approvals)
/// 2. Serialize to canonical JSON (sorted keys via BTreeMap, no pretty-print)
/// 3. Prepend domain separation tag
/// 4. Compute SHA3-256
pub fn envelope_digest(envelope: &UpgradeEnvelope) -> Result<[u8; 32], EnvelopeError> {
    // Create a canonical representation excluding signatures
    let canonical = CanonicalEnvelope::from(envelope);
    let json = serde_json::to_string(&canonical)
        .map_err(|e| EnvelopeError::SerializeError(e.to_string()))?;

    // Domain-separated hash
    let mut hasher = Sha3_256::new();
    hasher.update(ENVELOPE_HASH_DOMAIN.as_bytes());
    hasher.update(json.as_bytes());
    let result = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Compute envelope digest and return as hex string.
pub fn envelope_digest_hex(envelope: &UpgradeEnvelope) -> Result<String, EnvelopeError> {
    let digest = envelope_digest(envelope)?;
    Ok(hex::encode(digest))
}

/// Canonical envelope representation for hashing.
///
/// This struct uses BTreeMap for sorted keys and excludes council_approvals.
/// The serialization order is deterministic across Rust versions.
#[derive(Serialize, Deserialize)]
struct CanonicalEnvelope {
    /// Fields stored in a BTreeMap for deterministic ordering.
    #[serde(flatten)]
    fields: BTreeMap<String, serde_json::Value>,
}

impl From<&UpgradeEnvelope> for CanonicalEnvelope {
    fn from(envelope: &UpgradeEnvelope) -> Self {
        let mut fields = BTreeMap::new();

        // Add all hashable fields in a deterministic order
        fields.insert(
            "activation_height".to_string(),
            serde_json::Value::Number(envelope.activation_height.into()),
        );

        // Binary hashes as sorted map (serialization cannot fail for BTreeMap<String, String>)
        let binary_hashes: BTreeMap<String, String> = envelope
            .binary_hashes
            .iter()
            .map(|(k, v)| (k.clone(), v.0.clone()))
            .collect();
        fields.insert(
            "binary_hashes".to_string(),
            serde_json::to_value(binary_hashes)
                .expect("BTreeMap<String, String> serialization cannot fail"),
        );

        // UpgradeClass is a simple enum, serialization cannot fail
        fields.insert(
            "class".to_string(),
            serde_json::to_value(&envelope.class).expect("UpgradeClass serialization cannot fail"),
        );

        fields.insert(
            "envelope_id".to_string(),
            serde_json::Value::String(envelope.envelope_id.clone()),
        );

        fields.insert(
            "envelope_version".to_string(),
            serde_json::Value::String(envelope.envelope_version.clone()),
        );

        fields.insert(
            "network_environment".to_string(),
            serde_json::Value::String(envelope.network_environment.clone()),
        );

        if !envelope.notes.is_empty() {
            fields.insert(
                "notes".to_string(),
                serde_json::Value::String(envelope.notes.clone()),
            );
        }

        fields.insert(
            "protocol_version".to_string(),
            serde_json::Value::String(envelope.protocol_version.clone()),
        );

        if !envelope.version.is_empty() {
            fields.insert(
                "version".to_string(),
                serde_json::Value::String(envelope.version.clone()),
            );
        }

        // Note: council_approvals is NOT included

        CanonicalEnvelope { fields }
    }
}

/// Compute SHA3-256 hash of a file.
///
/// Used for verifying binary hashes against local files.
pub fn sha3_256_file(path: &std::path::Path) -> Result<[u8; 32], EnvelopeError> {
    let data = std::fs::read(path)
        .map_err(|e| EnvelopeError::IoError(format!("read {}: {}", path.display(), e)))?;

    let mut hasher = Sha3_256::new();
    hasher.update(&data);
    let result = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Compute SHA3-256 hash of a file and return as hex string.
pub fn sha3_256_file_hex(path: &std::path::Path) -> Result<String, EnvelopeError> {
    let hash = sha3_256_file(path)?;
    Ok(hex::encode(hash))
}

/// Compute SHA3-256 hash of bytes.
pub fn sha3_256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{BinaryHashHex, UpgradeClass};

    fn test_envelope() -> UpgradeEnvelope {
        let mut binary_hashes = BTreeMap::new();
        binary_hashes.insert(
            "linux-x86_64".to_string(),
            BinaryHashHex::new("a".repeat(64)),
        );

        UpgradeEnvelope {
            envelope_version: "1.0".to_string(),
            envelope_id: "T225-001".to_string(),
            protocol_version: "0.1.0".to_string(),
            network_environment: "mainnet".to_string(),
            class: UpgradeClass::CHardFork,
            version: "0.1.0".to_string(),
            activation_height: 1000000,
            binary_hashes,
            notes: "Test upgrade".to_string(),
            council_approvals: vec![],
        }
    }

    #[test]
    fn test_envelope_digest_deterministic() {
        let envelope = test_envelope();

        let digest1 = envelope_digest(&envelope).unwrap();
        let digest2 = envelope_digest(&envelope).unwrap();

        assert_eq!(digest1, digest2, "digest should be deterministic");
    }

    #[test]
    fn test_envelope_digest_ignores_approvals() {
        let envelope1 = test_envelope();
        let mut envelope2 = test_envelope();

        // Add approvals to envelope2
        envelope2
            .council_approvals
            .push(crate::envelope::CouncilSignature {
                member_id: "c1".to_string(),
                public_key: "aa".to_string(),
                signature: "bb".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            });

        let digest1 = envelope_digest(&envelope1).unwrap();
        let digest2 = envelope_digest(&envelope2).unwrap();

        assert_eq!(digest1, digest2, "approvals should not affect digest");
    }

    #[test]
    fn test_envelope_digest_changes_with_content() {
        let envelope1 = test_envelope();
        let mut envelope2 = test_envelope();
        envelope2.activation_height = 2000000;

        let digest1 = envelope_digest(&envelope1).unwrap();
        let digest2 = envelope_digest(&envelope2).unwrap();

        assert_ne!(
            digest1, digest2,
            "different content should produce different digest"
        );
    }

    #[test]
    fn test_envelope_digest_hex() {
        let envelope = test_envelope();
        let hex = envelope_digest_hex(&envelope).unwrap();

        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sha3_256_bytes() {
        let data = b"test data";
        let hash = sha3_256_bytes(data);
        assert_eq!(hash.len(), 32);

        // Same input should produce same output
        let hash2 = sha3_256_bytes(data);
        assert_eq!(hash, hash2);

        // Different input should produce different output
        let hash3 = sha3_256_bytes(b"different");
        assert_ne!(hash, hash3);
    }
}
