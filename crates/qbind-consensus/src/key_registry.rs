//! Validator key registry for mapping validator IDs to public keys.
//!
//! This module provides:
//! - `ValidatorKeyProvider`: A trait for looking up validator public keys.
//! - `SuiteAwareValidatorKeyProvider`: A trait for looking up both suite ID and public keys.
//! - `ValidatorKeyRegistry`: A registry that maps `ValidatorId` to `ValidatorPublicKey`.
//!
//! It is used to look up public keys for signature verification during consensus.
//!
//! # Multi-Suite Support
//!
//! For cryptographic agility, the `SuiteAwareValidatorKeyProvider` trait allows
//! callers to obtain both the signature suite ID and the public key bytes.
//! The simpler `ValidatorKeyProvider` trait is kept for backwards compatibility.

use std::collections::HashMap;

use qbind_crypto::ConsensusSigSuiteId;

use crate::ids::{ValidatorId, ValidatorPublicKey};

/// Trait for looking up validator public keys.
///
/// This trait provides an algorithm-agnostic interface for key lookup.
/// Implementations may be backed by:
/// - A simple in-memory HashMap (`ValidatorKeyRegistry`)
/// - A governance-backed registry (`GovernedValidatorKeyRegistry`)
/// - Any other key source
///
/// The returned bytes represent the raw consensus public key in the appropriate
/// encoding for the configured suite. The consensus layer does not need to know
/// which suite is in use.
///
/// # Note
///
/// For multi-suite support, prefer using `SuiteAwareValidatorKeyProvider` which
/// also returns the suite ID. This trait is maintained for backwards compatibility.
pub trait ValidatorKeyProvider: Send + Sync + std::fmt::Debug {
    /// Look up the consensus public key for a validator.
    ///
    /// Returns `Some(pk_bytes)` if a key is configured for this validator,
    /// or `None` if no key exists.
    fn get_key(&self, id: ValidatorId) -> Option<Vec<u8>>;
}

/// Trait for looking up both suite ID and public key for a validator.
///
/// This trait extends the key lookup capability to include the signature suite
/// identifier, enabling per-suite verifier dispatch for cryptographic agility.
///
/// # Design Notes
///
/// - This trait is used by `CryptoConsensusVerifier` when multi-suite dispatch
///   is needed.
/// - Implementations should return `None` if the validator is not registered or
///   has no valid key configured.
pub trait SuiteAwareValidatorKeyProvider: Send + Sync + std::fmt::Debug {
    /// Look up the signature suite ID and consensus public key for a validator.
    ///
    /// Returns `Some((suite_id, pk_bytes))` if a key is configured for this
    /// validator, or `None` if no key exists.
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)>;
}

/// A registry mapping validator IDs to their public keys.
///
/// This struct provides a simple key-value store for looking up validator
/// public keys by their consensus identity. It is used during signature
/// verification to obtain the appropriate public key.
#[derive(Debug, Default, Clone)]
pub struct ValidatorKeyRegistry {
    inner: HashMap<ValidatorId, ValidatorPublicKey>,
}

impl ValidatorKeyRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        ValidatorKeyRegistry {
            inner: HashMap::new(),
        }
    }

    /// Insert a validator's public key into the registry.
    ///
    /// Returns the previous public key if one was already present for this validator.
    pub fn insert(
        &mut self,
        id: ValidatorId,
        pk: ValidatorPublicKey,
    ) -> Option<ValidatorPublicKey> {
        self.inner.insert(id, pk)
    }

    /// Get a reference to a validator's public key.
    pub fn get(&self, id: &ValidatorId) -> Option<&ValidatorPublicKey> {
        self.inner.get(id)
    }

    /// Check if the registry contains a key for the given validator.
    pub fn contains(&self, id: &ValidatorId) -> bool {
        self.inner.contains_key(id)
    }

    /// Returns the number of validators in the registry.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns an iterator over all (ValidatorId, ValidatorPublicKey) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&ValidatorId, &ValidatorPublicKey)> {
        self.inner.iter()
    }
}

impl ValidatorKeyProvider for ValidatorKeyRegistry {
    fn get_key(&self, id: ValidatorId) -> Option<Vec<u8>> {
        self.inner.get(&id).map(|pk| pk.0.clone())
    }
}
