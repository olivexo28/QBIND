//! Governance-backed validator key registry.
//!
//! This module provides `GovernedValidatorKeyRegistry`, a `ValidatorKeyProvider`
//! implementation that uses a governance model to look up consensus public keys.
//!
//! # Design
//!
//! The registry is parameterized over a governance type `G` that provides the
//! actual key lookup. This allows the consensus layer to remain agnostic to
//! the specific governance implementation (e.g., SuiteRegistry, KeyRolePolicy).
//!
//! The consensus layer sees only `ValidatorId` and raw public key bytes; it does
//! not need to know which cryptographic suite is in use.
//!
//! # Multi-Suite Support
//!
//! For cryptographic agility, this module supports multiple signature suites:
//! - `ConsensusKeyGovernance::get_consensus_key` returns `(suite_id, pk_bytes)`
//! - `SuiteAwareValidatorKeyProvider` exposes both suite ID and public key
//! - `ValidatorKeyProvider` is maintained for backwards compatibility

use std::sync::Arc;

use cano_crypto::ConsensusSigSuiteId;

use crate::ids::ValidatorId;
use crate::key_registry::{SuiteAwareValidatorKeyProvider, ValidatorKeyProvider};

/// Trait for governance systems that can provide consensus public keys.
///
/// This trait defines the interface that governance systems must implement
/// to provide consensus-signing public keys for validators.
///
/// # Multi-Suite Support
///
/// The returned tuple contains:
/// - `ConsensusSigSuiteId`: identifies which signature suite the key is for
/// - `Vec<u8>`: the public key bytes in the correct encoding for that suite
pub trait ConsensusKeyGovernance: Send + Sync {
    /// Look up the active consensus-signing public key for a validator.
    ///
    /// Returns `Some((suite_id, pk_bytes))` if a valid consensus key is configured
    /// for this validator, or `None` if:
    /// - The validator is not registered
    /// - The validator has no consensus key configured
    /// - The key configuration is invalid or inconsistent
    fn get_consensus_key(&self, validator_id: u64) -> Option<(ConsensusSigSuiteId, Vec<u8>)>;
}

/// A `ValidatorKeyProvider` backed by a governance model.
///
/// This struct bridges the consensus layer's need for validator public keys
/// with the governance system that manages key registration and activation.
///
/// # Type Parameters
///
/// * `G` - The governance type that implements `ConsensusKeyGovernance`.
///
/// # Multi-Suite Support
///
/// This registry implements both:
/// - `SuiteAwareValidatorKeyProvider`: exposes both suite ID and pk bytes
/// - `ValidatorKeyProvider`: returns only pk bytes (for backwards compatibility)
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use cano_consensus::governed_key_registry::{GovernedValidatorKeyRegistry, ConsensusKeyGovernance};
/// use cano_crypto::ConsensusSigSuiteId;
///
/// struct MyGovernance { /* ... */ }
///
/// impl ConsensusKeyGovernance for MyGovernance {
///     fn get_consensus_key(&self, validator_id: u64) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
///         // Look up key from on-chain state, registry, etc.
///         None
///     }
/// }
///
/// let governance = Arc::new(MyGovernance { /* ... */ });
/// let registry = GovernedValidatorKeyRegistry::new(governance);
/// ```
pub struct GovernedValidatorKeyRegistry<G> {
    governance: Arc<G>,
}

impl<G> GovernedValidatorKeyRegistry<G> {
    /// Create a new governance-backed key registry.
    ///
    /// # Arguments
    ///
    /// * `governance` - The governance system to query for consensus keys.
    pub fn new(governance: Arc<G>) -> Self {
        GovernedValidatorKeyRegistry { governance }
    }
}

impl<G: std::fmt::Debug> std::fmt::Debug for GovernedValidatorKeyRegistry<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GovernedValidatorKeyRegistry")
            .field("governance", &self.governance)
            .finish()
    }
}

impl<G> SuiteAwareValidatorKeyProvider for GovernedValidatorKeyRegistry<G>
where
    G: ConsensusKeyGovernance + Send + Sync + std::fmt::Debug,
{
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.governance.get_consensus_key(id.as_u64())
    }
}

impl<G> ValidatorKeyProvider for GovernedValidatorKeyRegistry<G>
where
    G: ConsensusKeyGovernance + Send + Sync + std::fmt::Debug,
{
    fn get_key(&self, id: ValidatorId) -> Option<Vec<u8>> {
        // For backwards compatibility: discard suite_id and return only pk bytes
        self.governance
            .get_consensus_key(id.as_u64())
            .map(|(_, pk)| pk)
    }
}
