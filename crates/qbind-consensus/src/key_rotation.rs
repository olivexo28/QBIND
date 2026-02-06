//! T213: Key Rotation Hooks v0.
//!
//! This module provides consensus-safe primitives for validator key rotation:
//! - `KeyRotationEvent`: represents a key rotation request
//! - `KeyRotationKind`: scheduled vs emergency rotation
//! - `ValidatorKeyState`: tracks current key and optional pending rotation
//! - `PendingKey`: holds the new key and grace period information
//!
//! # Design
//!
//! Key rotation follows a grace period model where both old and new keys
//! are valid during the transition:
//!
//! ```text
//! ────────────────────────────────────────────────────────────────►
//! │ Rotation Event │   Grace Period   │ New Key │
//! │   Applied      │  (both valid)    │ Only    │
//!                  ├──────────────────┤
//!                  grace_start        grace_end
//! ```
//!
//! # Non-Goals (T213)
//!
//! - No on-chain governance integration
//! - No automatic rotation scheduling
//! - No slashing interaction
//! - No HSM redundancy/failover

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ============================================================================
// Key Role
// ============================================================================

/// Identifies the role/purpose of a key within the validator's key set.
///
/// This enum distinguishes between different keys a validator may hold,
/// each with different security and rotation requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyRole {
    /// Consensus signing key (proposals, votes, timeouts).
    Consensus = 0,
    /// P2P identity key (KEMTLS handshakes).
    P2pIdentity = 1,
    /// DAG batch signing key.
    BatchSigning = 2,
}

impl std::fmt::Display for KeyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyRole::Consensus => write!(f, "Consensus"),
            KeyRole::P2pIdentity => write!(f, "P2pIdentity"),
            KeyRole::BatchSigning => write!(f, "BatchSigning"),
        }
    }
}

// ============================================================================
// Key Rotation Event
// ============================================================================

/// Distinguishes between scheduled (planned) and emergency rotations.
///
/// Both use the same mechanics, but the distinction is important for:
/// - Logging and audit trails
/// - Metrics and alerting
/// - Future governance integration (emergency may have different approval flow)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyRotationKind {
    /// Planned rotation per operational schedule.
    Scheduled,
    /// Emergency rotation due to suspected compromise.
    Emergency,
}

impl std::fmt::Display for KeyRotationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyRotationKind::Scheduled => write!(f, "Scheduled"),
            KeyRotationKind::Emergency => write!(f, "Emergency"),
        }
    }
}

/// Represents a request to rotate a validator's key.
///
/// A `KeyRotationEvent` is injected into the validator set (via governance
/// or manual operation) to initiate a key rotation with a grace period.
///
/// # Fields
///
/// - `validator_id`: The validator whose key is being rotated
/// - `key_role`: Which key is being rotated (Consensus, P2pIdentity, etc.)
/// - `new_public_key`: The new public key bytes (ML-DSA-44 for consensus)
/// - `effective_epoch`: When the grace period starts
/// - `grace_epochs`: How many epochs the grace period lasts
/// - `kind`: Scheduled vs Emergency rotation
///
/// # Example
///
/// ```ignore
/// use qbind_consensus::key_rotation::{KeyRotationEvent, KeyRotationKind, KeyRole};
///
/// let event = KeyRotationEvent {
///     validator_id: 42,
///     key_role: KeyRole::Consensus,
///     new_public_key: new_pk_bytes,
///     effective_epoch: 100,
///     grace_epochs: 2,
///     kind: KeyRotationKind::Scheduled,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationEvent {
    /// The validator whose key is being rotated.
    pub validator_id: u64,
    /// Which key role is being rotated.
    pub key_role: KeyRole,
    /// The new public key bytes (e.g., ML-DSA-44 public key).
    pub new_public_key: Vec<u8>,
    /// The epoch when the grace period starts.
    pub effective_epoch: u64,
    /// Number of epochs the grace period lasts.
    /// During grace period, both old and new keys are valid.
    pub grace_epochs: u64,
    /// Whether this is a scheduled or emergency rotation.
    pub kind: KeyRotationKind,
}

impl KeyRotationEvent {
    /// Create a new scheduled key rotation event.
    ///
    /// Scheduled rotations are planned key updates that follow the normal
    /// operational schedule. Use this for routine key rotation per policy.
    ///
    /// The rotation will take effect at `effective_epoch` with a grace period
    /// of `grace_epochs` where both old and new keys are valid.
    pub fn scheduled(
        validator_id: u64,
        key_role: KeyRole,
        new_public_key: Vec<u8>,
        effective_epoch: u64,
        grace_epochs: u64,
    ) -> Self {
        KeyRotationEvent {
            validator_id,
            key_role,
            new_public_key,
            effective_epoch,
            grace_epochs,
            kind: KeyRotationKind::Scheduled,
        }
    }

    /// Create a new emergency key rotation event.
    ///
    /// Emergency rotations are used when key compromise is suspected or
    /// confirmed. The rotation mechanics are identical to scheduled rotation,
    /// but the `kind` field is set to `Emergency` for logging, metrics, and
    /// future governance integration.
    ///
    /// Use this when:
    /// - Unauthorized signatures are detected
    /// - The validator host is compromised
    /// - HSM tamper detection triggers
    pub fn emergency(
        validator_id: u64,
        key_role: KeyRole,
        new_public_key: Vec<u8>,
        effective_epoch: u64,
        grace_epochs: u64,
    ) -> Self {
        KeyRotationEvent {
            validator_id,
            key_role,
            new_public_key,
            effective_epoch,
            grace_epochs,
            kind: KeyRotationKind::Emergency,
        }
    }

    /// Compute the grace period end epoch (inclusive).
    ///
    /// Uses saturating arithmetic to avoid overflow.
    pub fn grace_end_epoch(&self) -> u64 {
        self.effective_epoch.saturating_add(self.grace_epochs)
    }
}

// ============================================================================
// Validator Key State
// ============================================================================

/// Holds public key bytes.
pub type PublicKeyBytes = Vec<u8>;

/// Represents a pending key rotation during the grace period.
///
/// During the grace period, both the current key and the pending key
/// are valid for signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingKey {
    /// The new public key bytes.
    pub key: PublicKeyBytes,
    /// The epoch when the grace period started.
    pub grace_start_epoch: u64,
    /// The epoch when the grace period ends (inclusive).
    pub grace_end_epoch: u64,
    /// The kind of rotation (for logging/metrics).
    pub kind: KeyRotationKind,
}

impl PendingKey {
    /// Check if the given epoch is within the grace period.
    pub fn is_in_grace_period(&self, epoch: u64) -> bool {
        epoch >= self.grace_start_epoch && epoch <= self.grace_end_epoch
    }

    /// Check if the grace period has ended.
    pub fn grace_period_ended(&self, epoch: u64) -> bool {
        epoch > self.grace_end_epoch
    }
}

/// Tracks the key state for a single validator and key role.
///
/// A validator can be in one of two states:
/// - **Normal**: Single active key (no rotation in progress)
/// - **In-rotation**: Current key + pending new key with grace period
///
/// During the grace period, signatures from either key are valid.
/// After the grace period ends, the pending key becomes the current key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorKeyState {
    /// The currently active public key.
    pub current_key: PublicKeyBytes,
    /// Optional pending key during rotation.
    pub next_key: Option<PendingKey>,
}

impl ValidatorKeyState {
    /// Create a new key state with only a current key (no rotation).
    pub fn new(current_key: PublicKeyBytes) -> Self {
        ValidatorKeyState {
            current_key,
            next_key: None,
        }
    }

    /// Check if a rotation is currently in progress.
    pub fn is_rotating(&self) -> bool {
        self.next_key.is_some()
    }

    /// Check if a given public key is valid for the given epoch.
    ///
    /// A key is valid if:
    /// - It matches the current key, OR
    /// - It matches the pending key AND the epoch is within the grace period
    pub fn is_key_valid(&self, public_key: &[u8], epoch: u64) -> bool {
        // Current key is always valid
        if self.current_key == public_key {
            return true;
        }

        // Check pending key during grace period
        if let Some(ref pending) = self.next_key {
            if pending.key == public_key && pending.is_in_grace_period(epoch) {
                return true;
            }
        }

        false
    }

    /// Commit the rotation if the grace period has ended.
    ///
    /// If the grace period for the pending key has ended at the given epoch,
    /// this method:
    /// 1. Sets `current_key` to the pending key
    /// 2. Clears `next_key`
    ///
    /// Returns `true` if a rotation was committed.
    pub fn maybe_commit_rotation(&mut self, epoch: u64) -> bool {
        if let Some(ref pending) = self.next_key {
            if pending.grace_period_ended(epoch) {
                self.current_key = pending.key.clone();
                self.next_key = None;
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Key Rotation Errors
// ============================================================================

/// Errors that can occur when applying a key rotation event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRotationError {
    /// The validator is not in the validator set.
    ValidatorNotFound(u64),
    /// A rotation is already in progress for this validator and key role.
    RotationAlreadyInProgress {
        validator_id: u64,
        key_role: KeyRole,
        existing_grace_end: u64,
    },
    /// The effective epoch is in the past.
    EffectiveEpochInPast {
        effective_epoch: u64,
        current_epoch: u64,
    },
    /// The new public key is empty or invalid.
    InvalidPublicKey,
    /// The key role is not found for this validator.
    KeyRoleNotFound {
        validator_id: u64,
        key_role: KeyRole,
    },
}

impl std::fmt::Display for KeyRotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyRotationError::ValidatorNotFound(id) => {
                write!(f, "validator {} not found in validator set", id)
            }
            KeyRotationError::RotationAlreadyInProgress {
                validator_id,
                key_role,
                existing_grace_end,
            } => {
                write!(
                    f,
                    "rotation already in progress for validator {} role {}, grace ends at epoch {}",
                    validator_id, key_role, existing_grace_end
                )
            }
            KeyRotationError::EffectiveEpochInPast {
                effective_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "effective epoch {} is in the past (current epoch: {})",
                    effective_epoch, current_epoch
                )
            }
            KeyRotationError::InvalidPublicKey => {
                write!(f, "new public key is empty or invalid")
            }
            KeyRotationError::KeyRoleNotFound {
                validator_id,
                key_role,
            } => {
                write!(
                    f,
                    "key role {} not found for validator {}",
                    key_role, validator_id
                )
            }
        }
    }
}

impl std::error::Error for KeyRotationError {}

// ============================================================================
// Validator Key Registry (with rotation support)
// ============================================================================

/// A key identifier combining validator ID and key role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValidatorKeyId {
    pub validator_id: u64,
    pub key_role: KeyRole,
}

impl ValidatorKeyId {
    pub fn new(validator_id: u64, key_role: KeyRole) -> Self {
        ValidatorKeyId {
            validator_id,
            key_role,
        }
    }
}

/// A registry of validator keys with rotation support.
///
/// This struct maintains the key state for all validators across all key roles,
/// supporting dual-key validation during grace periods.
///
/// # Usage
///
/// ```ignore
/// use qbind_consensus::key_rotation::{KeyRotationRegistry, KeyRole, KeyRotationEvent};
///
/// let mut registry = KeyRotationRegistry::new();
/// registry.register_key(1, KeyRole::Consensus, initial_pk.clone());
///
/// // Apply a rotation event
/// let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, new_pk, 100, 2);
/// registry.apply_rotation_event(&event, 99)?;
///
/// // Advance epochs to commit rotations
/// let committed = registry.advance_epoch(103);
/// ```
#[derive(Debug, Clone, Default)]
pub struct KeyRotationRegistry {
    /// Map from (validator_id, key_role) to key state.
    keys: HashMap<ValidatorKeyId, ValidatorKeyState>,
}

impl KeyRotationRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        KeyRotationRegistry {
            keys: HashMap::new(),
        }
    }

    /// Register an initial key for a validator and role.
    ///
    /// This is used to populate the registry with genesis/initial keys.
    pub fn register_key(
        &mut self,
        validator_id: u64,
        key_role: KeyRole,
        public_key: PublicKeyBytes,
    ) {
        let key_id = ValidatorKeyId::new(validator_id, key_role);
        self.keys.insert(key_id, ValidatorKeyState::new(public_key));
    }

    /// Get the key state for a validator and role.
    ///
    /// Returns `None` if no key has been registered for the given
    /// (validator_id, key_role) combination via `register_key()`.
    pub fn get_key_state(&self, validator_id: u64, key_role: KeyRole) -> Option<&ValidatorKeyState> {
        let key_id = ValidatorKeyId::new(validator_id, key_role);
        self.keys.get(&key_id)
    }

    /// Get the key state for a validator and role (mutable).
    ///
    /// Returns `None` if no key has been registered for the given
    /// (validator_id, key_role) combination via `register_key()`.
    pub fn get_key_state_mut(
        &mut self,
        validator_id: u64,
        key_role: KeyRole,
    ) -> Option<&mut ValidatorKeyState> {
        let key_id = ValidatorKeyId::new(validator_id, key_role);
        self.keys.get_mut(&key_id)
    }

    /// Check if a validator has a registered key for the given role.
    pub fn has_key(&self, validator_id: u64, key_role: KeyRole) -> bool {
        let key_id = ValidatorKeyId::new(validator_id, key_role);
        self.keys.contains_key(&key_id)
    }

    /// Apply a key rotation event to the registry.
    ///
    /// # Arguments
    ///
    /// * `event` - The rotation event to apply
    /// * `current_epoch` - The current epoch (for validation)
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the rotation was applied successfully
    /// * `Err(KeyRotationError)` if the rotation could not be applied
    ///
    /// # Behavior
    ///
    /// - If the validator/role doesn't exist, returns `ValidatorNotFound` or `KeyRoleNotFound`
    /// - If a rotation is already in progress (next_key is Some), returns `RotationAlreadyInProgress`
    /// - If effective_epoch < current_epoch, returns `EffectiveEpochInPast`
    /// - Sets the pending key with computed grace period
    pub fn apply_rotation_event(
        &mut self,
        event: &KeyRotationEvent,
        current_epoch: u64,
    ) -> Result<(), KeyRotationError> {
        // Validate public key
        if event.new_public_key.is_empty() {
            return Err(KeyRotationError::InvalidPublicKey);
        }

        // Validate effective epoch (allow current_epoch == effective_epoch)
        if event.effective_epoch < current_epoch {
            return Err(KeyRotationError::EffectiveEpochInPast {
                effective_epoch: event.effective_epoch,
                current_epoch,
            });
        }

        // Get the key state
        let key_id = ValidatorKeyId::new(event.validator_id, event.key_role);
        let key_state = self
            .keys
            .get_mut(&key_id)
            .ok_or(KeyRotationError::KeyRoleNotFound {
                validator_id: event.validator_id,
                key_role: event.key_role,
            })?;

        // Check for existing rotation
        if let Some(ref existing) = key_state.next_key {
            return Err(KeyRotationError::RotationAlreadyInProgress {
                validator_id: event.validator_id,
                key_role: event.key_role,
                existing_grace_end: existing.grace_end_epoch,
            });
        }

        // Apply the rotation
        let pending = PendingKey {
            key: event.new_public_key.clone(),
            grace_start_epoch: event.effective_epoch,
            grace_end_epoch: event.grace_end_epoch(),
            kind: event.kind,
        };
        key_state.next_key = Some(pending);

        Ok(())
    }

    /// Check if a public key is valid for a validator and role at the given epoch.
    ///
    /// This is the main verification function for dual-key support.
    pub fn is_key_valid(
        &self,
        validator_id: u64,
        key_role: KeyRole,
        public_key: &[u8],
        epoch: u64,
    ) -> bool {
        if let Some(state) = self.get_key_state(validator_id, key_role) {
            state.is_key_valid(public_key, epoch)
        } else {
            false
        }
    }

    /// Advance to a new epoch, committing any rotations whose grace period has ended.
    ///
    /// Returns a list of (validator_id, key_role) pairs for rotations that were committed.
    pub fn advance_epoch(&mut self, new_epoch: u64) -> Vec<(u64, KeyRole)> {
        let mut committed = Vec::new();

        for (key_id, state) in self.keys.iter_mut() {
            if state.maybe_commit_rotation(new_epoch) {
                committed.push((key_id.validator_id, key_id.key_role));
            }
        }

        committed
    }

    /// Get all validators with active rotations (pending keys).
    pub fn validators_with_pending_rotations(&self) -> Vec<(u64, KeyRole)> {
        self.keys
            .iter()
            .filter(|(_, state)| state.is_rotating())
            .map(|(key_id, _)| (key_id.validator_id, key_id.key_role))
            .collect()
    }

    /// Get the number of registered key entries.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ============================================================================
// Integration with ConsensusValidatorSet (helper functions)
// ============================================================================

/// Apply a key rotation event to the registry with validation against a validator set.
///
/// This is a convenience function that validates the event against the validator set
/// before applying it to the registry.
///
/// # Arguments
///
/// * `registry` - The key rotation registry to update
/// * `validator_ids` - Iterator of valid validator IDs in the current set
/// * `event` - The rotation event to apply
/// * `current_epoch` - The current epoch
///
/// # Returns
///
/// * `Ok(())` if the rotation was applied successfully
/// * `Err(KeyRotationError::ValidatorNotFound)` if the validator is not in the set
/// * Other `KeyRotationError` variants for other failures
pub fn apply_key_rotation_event<I>(
    registry: &mut KeyRotationRegistry,
    validator_ids: I,
    event: &KeyRotationEvent,
    current_epoch: u64,
) -> Result<(), KeyRotationError>
where
    I: IntoIterator<Item = u64>,
{
    // Check if validator exists in the set
    let validator_exists = validator_ids
        .into_iter()
        .any(|id| id == event.validator_id);

    if !validator_exists {
        return Err(KeyRotationError::ValidatorNotFound(event.validator_id));
    }

    // Delegate to registry
    registry.apply_rotation_event(event, current_epoch)
}

/// Advance epoch for all validators in a registry, committing completed rotations.
///
/// This is a thin wrapper around `KeyRotationRegistry::advance_epoch` that
/// provides consistent semantics with the design spec.
pub fn advance_epoch_for_rotation(registry: &mut KeyRotationRegistry, new_epoch: u64) -> Vec<(u64, KeyRole)> {
    registry.advance_epoch(new_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pk(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    #[test]
    fn test_key_rotation_event_creation() {
        let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(1), 100, 2);
        assert_eq!(event.validator_id, 1);
        assert_eq!(event.key_role, KeyRole::Consensus);
        assert_eq!(event.effective_epoch, 100);
        assert_eq!(event.grace_epochs, 2);
        assert_eq!(event.grace_end_epoch(), 102);
        assert_eq!(event.kind, KeyRotationKind::Scheduled);

        let emergency = KeyRotationEvent::emergency(2, KeyRole::Consensus, test_pk(2), 50, 1);
        assert_eq!(emergency.kind, KeyRotationKind::Emergency);
        assert_eq!(emergency.grace_end_epoch(), 51);
    }

    #[test]
    fn test_grace_end_epoch_saturating() {
        let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(1), u64::MAX - 1, 10);
        // Should saturate to u64::MAX instead of overflowing
        assert_eq!(event.grace_end_epoch(), u64::MAX);
    }

    #[test]
    fn test_pending_key_grace_period() {
        let pending = PendingKey {
            key: test_pk(1),
            grace_start_epoch: 100,
            grace_end_epoch: 102,
            kind: KeyRotationKind::Scheduled,
        };

        // Before grace period
        assert!(!pending.is_in_grace_period(99));
        assert!(!pending.grace_period_ended(99));

        // During grace period
        assert!(pending.is_in_grace_period(100));
        assert!(pending.is_in_grace_period(101));
        assert!(pending.is_in_grace_period(102));
        assert!(!pending.grace_period_ended(100));
        assert!(!pending.grace_period_ended(102));

        // After grace period
        assert!(!pending.is_in_grace_period(103));
        assert!(pending.grace_period_ended(103));
    }

    #[test]
    fn test_validator_key_state_is_key_valid() {
        let mut state = ValidatorKeyState::new(test_pk(1));

        // Current key is always valid
        assert!(state.is_key_valid(&test_pk(1), 100));
        assert!(state.is_key_valid(&test_pk(1), 200));

        // Unknown key is not valid
        assert!(!state.is_key_valid(&test_pk(2), 100));

        // Add pending key
        state.next_key = Some(PendingKey {
            key: test_pk(2),
            grace_start_epoch: 100,
            grace_end_epoch: 102,
            kind: KeyRotationKind::Scheduled,
        });

        // Current key still valid
        assert!(state.is_key_valid(&test_pk(1), 100));

        // Pending key valid during grace period
        assert!(!state.is_key_valid(&test_pk(2), 99));  // Before grace
        assert!(state.is_key_valid(&test_pk(2), 100));  // At start
        assert!(state.is_key_valid(&test_pk(2), 101));  // During
        assert!(state.is_key_valid(&test_pk(2), 102));  // At end
        assert!(!state.is_key_valid(&test_pk(2), 103)); // After grace
    }

    #[test]
    fn test_validator_key_state_commit_rotation() {
        let mut state = ValidatorKeyState::new(test_pk(1));
        state.next_key = Some(PendingKey {
            key: test_pk(2),
            grace_start_epoch: 100,
            grace_end_epoch: 102,
            kind: KeyRotationKind::Scheduled,
        });

        // Not committed before grace end
        assert!(!state.maybe_commit_rotation(102));
        assert!(state.next_key.is_some());
        assert_eq!(state.current_key, test_pk(1));

        // Committed after grace end
        assert!(state.maybe_commit_rotation(103));
        assert!(state.next_key.is_none());
        assert_eq!(state.current_key, test_pk(2));

        // No-op if no pending key
        assert!(!state.maybe_commit_rotation(200));
    }

    #[test]
    fn test_registry_basic_operations() {
        let mut registry = KeyRotationRegistry::new();

        assert!(registry.is_empty());
        registry.register_key(1, KeyRole::Consensus, test_pk(1));
        registry.register_key(2, KeyRole::Consensus, test_pk(2));
        registry.register_key(1, KeyRole::BatchSigning, test_pk(3));

        assert_eq!(registry.len(), 3);
        assert!(!registry.is_empty());

        assert!(registry.has_key(1, KeyRole::Consensus));
        assert!(registry.has_key(2, KeyRole::Consensus));
        assert!(registry.has_key(1, KeyRole::BatchSigning));
        assert!(!registry.has_key(1, KeyRole::P2pIdentity));
        assert!(!registry.has_key(99, KeyRole::Consensus));
    }

    #[test]
    fn test_registry_apply_rotation_event() {
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));

        let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(2), 100, 2);

        // Apply rotation
        assert!(registry.apply_rotation_event(&event, 99).is_ok());

        // Verify state
        let state = registry.get_key_state(1, KeyRole::Consensus).unwrap();
        assert!(state.is_rotating());
        assert!(state.next_key.is_some());
        let pending = state.next_key.as_ref().unwrap();
        assert_eq!(pending.key, test_pk(2));
        assert_eq!(pending.grace_start_epoch, 100);
        assert_eq!(pending.grace_end_epoch, 102);
    }

    #[test]
    fn test_registry_reject_overlapping_rotation() {
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));

        let event1 = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(2), 100, 2);
        let event2 = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(3), 101, 2);

        // First rotation succeeds
        assert!(registry.apply_rotation_event(&event1, 99).is_ok());

        // Second rotation fails
        let result = registry.apply_rotation_event(&event2, 99);
        assert!(matches!(
            result,
            Err(KeyRotationError::RotationAlreadyInProgress { .. })
        ));
    }

    #[test]
    fn test_registry_reject_past_effective_epoch() {
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));

        let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(2), 50, 2);

        let result = registry.apply_rotation_event(&event, 100);
        assert!(matches!(
            result,
            Err(KeyRotationError::EffectiveEpochInPast { .. })
        ));
    }

    #[test]
    fn test_registry_reject_missing_validator() {
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));

        // Validator 99 doesn't exist
        let event = KeyRotationEvent::scheduled(99, KeyRole::Consensus, test_pk(2), 100, 2);
        let result = registry.apply_rotation_event(&event, 99);
        assert!(matches!(
            result,
            Err(KeyRotationError::KeyRoleNotFound { .. })
        ));
    }

    #[test]
    fn test_registry_reject_empty_public_key() {
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));

        let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, vec![], 100, 2);
        let result = registry.apply_rotation_event(&event, 99);
        assert!(matches!(result, Err(KeyRotationError::InvalidPublicKey)));
    }

    #[test]
    fn test_registry_is_key_valid() {
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));

        let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(2), 100, 2);
        registry.apply_rotation_event(&event, 99).unwrap();

        // Old key always valid
        assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(1), 99));
        assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(1), 100));
        assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(1), 103));

        // New key valid only during grace period
        assert!(!registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 99));
        assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 100));
        assert!(registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 102));
        assert!(!registry.is_key_valid(1, KeyRole::Consensus, &test_pk(2), 103));
    }

    #[test]
    fn test_registry_advance_epoch() {
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));
        registry.register_key(2, KeyRole::Consensus, test_pk(10));

        let event1 = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(2), 100, 2);
        let event2 = KeyRotationEvent::scheduled(2, KeyRole::Consensus, test_pk(11), 100, 3);
        registry.apply_rotation_event(&event1, 99).unwrap();
        registry.apply_rotation_event(&event2, 99).unwrap();

        // Epoch 102: still in grace for both
        let committed = registry.advance_epoch(102);
        assert!(committed.is_empty());

        // Epoch 103: validator 1's rotation completes (grace_end=102)
        let committed = registry.advance_epoch(103);
        assert_eq!(committed.len(), 1);
        assert!(committed.contains(&(1, KeyRole::Consensus)));

        // Verify validator 1's key changed
        let state1 = registry.get_key_state(1, KeyRole::Consensus).unwrap();
        assert!(!state1.is_rotating());
        assert_eq!(state1.current_key, test_pk(2));

        // Validator 2 still rotating
        let state2 = registry.get_key_state(2, KeyRole::Consensus).unwrap();
        assert!(state2.is_rotating());

        // Epoch 104: validator 2's rotation completes (grace_end=103)
        let committed = registry.advance_epoch(104);
        assert_eq!(committed.len(), 1);
        assert!(committed.contains(&(2, KeyRole::Consensus)));
    }

    #[test]
    fn test_registry_validators_with_pending_rotations() {
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));
        registry.register_key(2, KeyRole::Consensus, test_pk(2));
        registry.register_key(3, KeyRole::Consensus, test_pk(3));

        // No pending rotations initially
        assert!(registry.validators_with_pending_rotations().is_empty());

        // Add rotations for validators 1 and 2
        let event1 = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(11), 100, 2);
        let event2 = KeyRotationEvent::scheduled(2, KeyRole::Consensus, test_pk(12), 100, 2);
        registry.apply_rotation_event(&event1, 99).unwrap();
        registry.apply_rotation_event(&event2, 99).unwrap();

        let pending = registry.validators_with_pending_rotations();
        assert_eq!(pending.len(), 2);
        assert!(pending.contains(&(1, KeyRole::Consensus)));
        assert!(pending.contains(&(2, KeyRole::Consensus)));
        assert!(!pending.contains(&(3, KeyRole::Consensus)));
    }

    #[test]
    fn test_grace_epochs_zero_immediate_switch() {
        // grace_epochs = 0 means immediate switch at effective_epoch
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));

        let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(2), 100, 0);
        registry.apply_rotation_event(&event, 100).unwrap();

        // Grace period is [100, 100] (effective + 0 = 100)
        let state = registry.get_key_state(1, KeyRole::Consensus).unwrap();
        assert!(state.is_key_valid(&test_pk(2), 100));  // At effective epoch
        assert!(!state.is_key_valid(&test_pk(2), 101)); // After effective epoch

        // Commit at epoch 101
        let committed = registry.advance_epoch(101);
        assert_eq!(committed.len(), 1);

        // New key is now current
        let state = registry.get_key_state(1, KeyRole::Consensus).unwrap();
        assert_eq!(state.current_key, test_pk(2));
    }

    #[test]
    fn test_emergency_rotation_same_mechanics() {
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));

        let event = KeyRotationEvent::emergency(1, KeyRole::Consensus, test_pk(2), 100, 2);
        registry.apply_rotation_event(&event, 99).unwrap();

        // Same grace period behavior
        let state = registry.get_key_state(1, KeyRole::Consensus).unwrap();
        let pending = state.next_key.as_ref().unwrap();
        assert_eq!(pending.kind, KeyRotationKind::Emergency);
        assert!(pending.is_in_grace_period(101));

        // Commits the same way
        registry.advance_epoch(103);
        let state = registry.get_key_state(1, KeyRole::Consensus).unwrap();
        assert_eq!(state.current_key, test_pk(2));
    }

    #[test]
    fn test_apply_key_rotation_event_helper() {
        let mut registry = KeyRotationRegistry::new();
        registry.register_key(1, KeyRole::Consensus, test_pk(1));
        registry.register_key(2, KeyRole::Consensus, test_pk(2));

        let validator_ids = vec![1u64, 2u64, 3u64];

        // Validator exists in set
        let event = KeyRotationEvent::scheduled(1, KeyRole::Consensus, test_pk(11), 100, 2);
        assert!(apply_key_rotation_event(&mut registry, validator_ids.iter().copied(), &event, 99).is_ok());

        // Validator not in set
        let event2 = KeyRotationEvent::scheduled(99, KeyRole::Consensus, test_pk(99), 100, 2);
        let result = apply_key_rotation_event(&mut registry, validator_ids.iter().copied(), &event2, 99);
        assert!(matches!(result, Err(KeyRotationError::ValidatorNotFound(99))));
    }
}