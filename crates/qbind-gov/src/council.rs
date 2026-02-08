//! Council keyset data structures and management (T225).
//!
//! This module provides data structures for representing the Protocol Council's
//! public keys and threshold configuration. Council keysets are used to verify
//! that upgrade envelopes have the required number of valid signatures.
//!
//! # Example
//!
//! ```ignore
//! use qbind_gov::council::{CouncilKeySet, CouncilKey};
//!
//! let keyset = CouncilKeySet::from_file("council-keys.json")?;
//! assert!(keyset.threshold() <= keyset.total_members());
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::envelope::EnvelopeError;

/// A single council member's public key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CouncilKey {
    /// Unique identifier for this council member (e.g., "council-1").
    pub member_id: String,

    /// Human-readable name or organization (optional).
    #[serde(default)]
    pub name: String,

    /// ML-DSA-44 public key as hex-encoded bytes.
    pub public_key: String,

    /// Signature algorithm identifier (e.g., "ML-DSA-44").
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_algorithm() -> String {
    "ML-DSA-44".to_string()
}

impl CouncilKey {
    /// Create a new council key.
    pub fn new(member_id: impl Into<String>, public_key: impl Into<String>) -> Self {
        CouncilKey {
            member_id: member_id.into(),
            name: String::new(),
            public_key: public_key.into(),
            algorithm: default_algorithm(),
        }
    }

    /// Decode the public key from hex to bytes.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        hex::decode(&self.public_key)
            .map_err(|e| EnvelopeError::InvalidSignature(format!("council key hex: {}", e)))
    }

    /// Validate the council key.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.member_id.is_empty() {
            return Err(EnvelopeError::MissingField("member_id".to_string()));
        }
        if self.public_key.is_empty() {
            return Err(EnvelopeError::MissingField("public_key".to_string()));
        }
        // Validate hex and expected size for ML-DSA-44 (1312 bytes = 2624 hex chars)
        let bytes = self.public_key_bytes()?;
        if self.algorithm == "ML-DSA-44" && bytes.len() != 1312 {
            return Err(EnvelopeError::InvalidSignature(format!(
                "ML-DSA-44 public key should be 1312 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(())
    }
}

/// Council keyset: the set of all council member public keys and threshold.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CouncilKeySet {
    /// Keyset format version (e.g., "1.0").
    #[serde(default = "default_keyset_version")]
    pub keyset_version: String,

    /// Network environment this keyset applies to.
    #[serde(default)]
    pub network_environment: String,

    /// Required number of signatures for approval (M in M-of-N).
    pub threshold: usize,

    /// Emergency threshold (lower, for time-critical security fixes).
    #[serde(default)]
    pub emergency_threshold: usize,

    /// List of council member keys.
    pub keys: Vec<CouncilKey>,
}

fn default_keyset_version() -> String {
    "1.0".to_string()
}

impl CouncilKeySet {
    /// Create a new council keyset.
    pub fn new(threshold: usize, keys: Vec<CouncilKey>) -> Self {
        CouncilKeySet {
            keyset_version: default_keyset_version(),
            network_environment: String::new(),
            threshold,
            emergency_threshold: threshold.saturating_sub(1),
            keys,
        }
    }

    /// Parse a council keyset from JSON.
    pub fn from_json(json: &str) -> Result<Self, EnvelopeError> {
        serde_json::from_str(json).map_err(|e| EnvelopeError::ParseError(e.to_string()))
    }

    /// Parse a council keyset from a JSON file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, EnvelopeError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| EnvelopeError::IoError(format!("read {}: {}", path.display(), e)))?;
        Self::from_json(&content)
    }

    /// Serialize the keyset to JSON (pretty-printed).
    pub fn to_json_pretty(&self) -> Result<String, EnvelopeError> {
        serde_json::to_string_pretty(self).map_err(|e| EnvelopeError::SerializeError(e.to_string()))
    }

    /// Total number of council members.
    pub fn total_members(&self) -> usize {
        self.keys.len()
    }

    /// Get the approval threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Get the emergency threshold.
    pub fn emergency_threshold(&self) -> usize {
        self.emergency_threshold
    }

    /// Find a council key by member ID.
    pub fn find_key(&self, member_id: &str) -> Option<&CouncilKey> {
        self.keys.iter().find(|k| k.member_id == member_id)
    }

    /// Build a lookup map from member ID to public key bytes.
    pub fn key_map(&self) -> Result<HashMap<String, Vec<u8>>, EnvelopeError> {
        let mut map = HashMap::new();
        for key in &self.keys {
            let pk_bytes = key.public_key_bytes()?;
            map.insert(key.member_id.clone(), pk_bytes);
        }
        Ok(map)
    }

    /// Validate the keyset structure.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        // Check version
        if self.keyset_version != "1.0" {
            return Err(EnvelopeError::UnsupportedVersion(
                self.keyset_version.clone(),
            ));
        }

        // Check threshold sanity
        if self.threshold == 0 {
            return Err(EnvelopeError::MissingField("threshold must be > 0".to_string()));
        }
        if self.threshold > self.keys.len() {
            return Err(EnvelopeError::VerificationFailed(format!(
                "threshold ({}) exceeds number of keys ({})",
                self.threshold,
                self.keys.len()
            )));
        }

        // Check for duplicate member IDs
        let mut seen = std::collections::HashSet::new();
        for key in &self.keys {
            if !seen.insert(&key.member_id) {
                return Err(EnvelopeError::VerificationFailed(format!(
                    "duplicate member_id: {}",
                    key.member_id
                )));
            }
        }

        // Validate each key
        for key in &self.keys {
            key.validate()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a dummy ML-DSA-44 public key (1312 bytes) as hex.
    fn dummy_pk_hex() -> String {
        "aa".repeat(1312)
    }

    #[test]
    fn test_council_key_new() {
        let key = CouncilKey::new("council-1", dummy_pk_hex());
        assert_eq!(key.member_id, "council-1");
        assert_eq!(key.algorithm, "ML-DSA-44");
    }

    #[test]
    fn test_council_key_validate() {
        let key = CouncilKey::new("council-1", dummy_pk_hex());
        assert!(key.validate().is_ok());

        let bad_key = CouncilKey::new("council-2", "tooshort");
        assert!(bad_key.validate().is_err());
    }

    #[test]
    fn test_council_keyset_parse() {
        let json = format!(
            r#"{{
            "keyset_version": "1.0",
            "network_environment": "mainnet",
            "threshold": 5,
            "emergency_threshold": 4,
            "keys": [
                {{"member_id": "c1", "public_key": "{pk}"}},
                {{"member_id": "c2", "public_key": "{pk}"}},
                {{"member_id": "c3", "public_key": "{pk}"}},
                {{"member_id": "c4", "public_key": "{pk}"}},
                {{"member_id": "c5", "public_key": "{pk}"}},
                {{"member_id": "c6", "public_key": "{pk}"}},
                {{"member_id": "c7", "public_key": "{pk}"}}
            ]
        }}"#,
            pk = dummy_pk_hex()
        );

        let keyset = CouncilKeySet::from_json(&json).unwrap();
        assert_eq!(keyset.threshold(), 5);
        assert_eq!(keyset.emergency_threshold(), 4);
        assert_eq!(keyset.total_members(), 7);
    }

    #[test]
    fn test_council_keyset_validate() {
        let keys: Vec<CouncilKey> = (1..=7)
            .map(|i| CouncilKey::new(format!("c{}", i), dummy_pk_hex()))
            .collect();

        let keyset = CouncilKeySet::new(5, keys);
        assert!(keyset.validate().is_ok());
    }

    #[test]
    fn test_council_keyset_threshold_exceeds_keys() {
        let keys = vec![
            CouncilKey::new("c1", dummy_pk_hex()),
            CouncilKey::new("c2", dummy_pk_hex()),
        ];
        let keyset = CouncilKeySet::new(5, keys); // threshold 5, but only 2 keys
        assert!(keyset.validate().is_err());
    }

    #[test]
    fn test_council_keyset_duplicate_member_id() {
        let keys = vec![
            CouncilKey::new("c1", dummy_pk_hex()),
            CouncilKey::new("c1", dummy_pk_hex()), // duplicate
        ];
        let keyset = CouncilKeySet::new(1, keys);
        assert!(keyset.validate().is_err());
    }

    #[test]
    fn test_council_keyset_find_key() {
        let keys = vec![
            CouncilKey::new("c1", dummy_pk_hex()),
            CouncilKey::new("c2", dummy_pk_hex()),
        ];
        let keyset = CouncilKeySet::new(1, keys);

        assert!(keyset.find_key("c1").is_some());
        assert!(keyset.find_key("c2").is_some());
        assert!(keyset.find_key("c3").is_none());
    }

    #[test]
    fn test_council_keyset_key_map() {
        let keys = vec![
            CouncilKey::new("c1", dummy_pk_hex()),
            CouncilKey::new("c2", dummy_pk_hex()),
        ];
        let keyset = CouncilKeySet::new(1, keys);

        let map = keyset.key_map().unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("c1"));
        assert!(map.contains_key("c2"));
    }
}