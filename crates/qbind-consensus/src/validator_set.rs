//! Validator set abstraction for consensus.
//!
//! This module provides `ValidatorSetEntry` and `ConsensusValidatorSet` types for
//! representing the validator committee in the consensus layer.
//!
//! # Design Note
//!
//! This is a simplified validator set abstraction for T50. It provides:
//! - A canonical representation of the validator committee
//! - Simple helpers for index lookup, iteration, and total weight
//!
//! These types are distinct from the existing `ValidatorInfo` and `ValidatorSet`
//! types in `lib.rs`, which are specifically designed for verification with
//! cryptographic fields (consensus_pk, suite_id). The types in this module use
//! the canonical `ValidatorId` type and are intended for structural wiring.
//!
//! We are NOT yet:
//! - Parsing TOML/JSON from disk
//! - Verifying signatures
//! - Changing the actual consensus algorithm
//!
//! This is purely structural wiring.

use std::collections::HashMap;

use crate::ids::ValidatorId;

/// Information about a single validator in the consensus committee.
///
/// This is a minimal structure containing the validator's identity and voting power.
/// Future extensions may include cryptographic keys, suite IDs, etc.
///
/// Note: This type is distinct from the `ValidatorInfo` in `lib.rs`, which includes
/// cryptographic fields for verification purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSetEntry {
    /// The canonical validator identity.
    pub id: ValidatorId,
    /// Simple voting power for now; can be generalized later.
    pub voting_power: u64,
}

// ============================================================================
// M2.1: Validator Candidate for Stake Filtering
// ============================================================================

/// A candidate validator with stake information for epoch boundary filtering.
///
/// This struct represents a validator candidate before stake filtering is applied.
/// At epoch boundaries, candidates with `stake < min_validator_stake` are excluded
/// from the final `ConsensusValidatorSet`.
///
/// # Design Note (M2.1 + M13)
///
/// The `stake` field is the canonical on-chain stake from `ValidatorRecord.stake`.
/// This ensures that stake filtering uses the same value as other protocol components
/// (e.g., slashing, rewards). The stake is NOT an in-memory mirror but should be
/// read directly from the ledger state.
///
/// # M13: Canonical Economic State Unification
///
/// Per M13, `ValidatorRecord` is the single source of truth for:
/// - `stake`: Canonical stake amount (reduced by slashing)
/// - `jailed_until_epoch`: Canonical jail expiration
///
/// When constructing candidates, read these values directly from `ValidatorRecord`.
/// Do NOT use `ValidatorSlashingState.stake` for eligibility decisions.
///
/// # Determinism
///
/// For deterministic validator set derivation across nodes:
/// - Candidates are sorted by `validator_id` (ascending) before filtering
/// - Filtering is applied uniformly using the same `min_validator_stake` threshold
/// - The resulting set has consistent ordering regardless of input order
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorCandidate {
    /// The validator's canonical identity.
    pub validator_id: ValidatorId,
    /// The validator's current stake from on-chain `ValidatorRecord.stake` (in microQBIND).
    ///
    /// # M13 Note
    ///
    /// This MUST be sourced from `ValidatorRecord.stake` (canonical source).
    pub stake: u64,
    /// The voting power to assign if this validator passes stake filtering.
    /// For uniform voting power, this is typically 1.
    pub voting_power: u64,
}

impl ValidatorCandidate {
    /// Create a new validator candidate.
    pub fn new(validator_id: ValidatorId, stake: u64, voting_power: u64) -> Self {
        Self {
            validator_id,
            stake,
            voting_power,
        }
    }
}

/// Result of building a validator set with stake filtering.
///
/// This struct provides visibility into which validators were included
/// and which were excluded due to insufficient stake.
#[derive(Debug, Clone)]
pub struct ValidatorSetBuildResult {
    /// The resulting validator set (validators with stake >= min_validator_stake).
    pub validator_set: ConsensusValidatorSet,
    /// Validators that were excluded due to stake < min_validator_stake.
    /// Sorted by validator_id for deterministic ordering.
    pub excluded: Vec<ValidatorCandidate>,
}

/// Build a `ConsensusValidatorSet` from validator candidates with stake filtering.
///
/// This function applies the M2.1 minimum stake requirement at epoch boundaries:
/// - Only validators with `stake >= min_validator_stake` are included
/// - Validators are sorted by `validator_id` for deterministic ordering
/// - The resulting set has consistent ordering regardless of input candidate order
///
/// # Arguments
///
/// * `candidates` - Iterator of validator candidates with stake information
/// * `min_validator_stake` - Minimum stake required for inclusion (in microQBIND)
///
/// # Returns
///
/// * `Ok(ValidatorSetBuildResult)` - The filtered validator set and excluded candidates
/// * `Err(String)` - If no validators meet the minimum stake requirement
///
/// # Determinism Guarantees
///
/// This function ensures deterministic output:
/// 1. Candidates are sorted by `validator_id` (ascending)
/// 2. Filtering uses `>=` comparison (inclusive of threshold)
/// 3. The same inputs always produce the same outputs
///
/// # Example
///
/// ```ignore
/// use qbind_consensus::validator_set::{ValidatorCandidate, build_validator_set_with_stake_filter};
/// use qbind_consensus::ids::ValidatorId;
///
/// let candidates = vec![
///     ValidatorCandidate::new(ValidatorId::new(1), 500_000, 1),  // Below threshold
///     ValidatorCandidate::new(ValidatorId::new(2), 1_000_000, 1), // At threshold
///     ValidatorCandidate::new(ValidatorId::new(3), 2_000_000, 1), // Above threshold
/// ];
///
/// // With min_stake = 1_000_000 (1 QBIND in microQBIND)
/// let result = build_validator_set_with_stake_filter(candidates, 1_000_000)?;
///
/// // Validator 1 excluded (500k < 1M)
/// // Validators 2 and 3 included (1M >= 1M, 2M >= 1M)
/// assert_eq!(result.validator_set.len(), 2);
/// assert_eq!(result.excluded.len(), 1);
/// assert_eq!(result.excluded[0].validator_id, ValidatorId::new(1));
/// ```
pub fn build_validator_set_with_stake_filter<I>(
    candidates: I,
    min_validator_stake: u64,
) -> Result<ValidatorSetBuildResult, String>
where
    I: IntoIterator<Item = ValidatorCandidate>,
{
    // Collect and sort candidates by validator_id for deterministic ordering
    let mut all_candidates: Vec<ValidatorCandidate> = candidates.into_iter().collect();
    all_candidates.sort_by_key(|c| c.validator_id);

    // Partition into included and excluded based on stake threshold
    let mut included = Vec::new();
    let mut excluded = Vec::new();

    for candidate in all_candidates {
        if candidate.stake >= min_validator_stake {
            included.push(ValidatorSetEntry {
                id: candidate.validator_id,
                voting_power: candidate.voting_power,
            });
        } else {
            excluded.push(candidate);
        }
    }

    // Create the validator set (will fail if empty)
    let validator_set = ConsensusValidatorSet::new(included)?;

    Ok(ValidatorSetBuildResult {
        validator_set,
        excluded,
    })
}

// ============================================================================
// M9: Jail-Aware Validator Set Filtering
// ============================================================================

/// Extended validator candidate with jail information for epoch boundary filtering (M9, M13).
///
/// This struct extends `ValidatorCandidate` with jail status information to enable
/// filtering out jailed validators from the active set during epoch transitions.
///
/// # M13: Canonical Economic State
///
/// The `jailed_until_epoch` field MUST be sourced from `ValidatorRecord.jailed_until_epoch`
/// (the canonical source). Do NOT use `ValidatorSlashingState.jailed_until_epoch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorCandidateWithJailStatus {
    /// The base validator candidate information.
    pub candidate: ValidatorCandidate,
    /// Epoch until which the validator is jailed (None = not jailed).
    ///
    /// # M13 Note
    ///
    /// This MUST be sourced from `ValidatorRecord.jailed_until_epoch` (canonical source).
    pub jailed_until_epoch: Option<u64>,
}

impl ValidatorCandidateWithJailStatus {
    /// Create a new validator candidate with jail status.
    pub fn new(
        validator_id: ValidatorId,
        stake: u64,
        voting_power: u64,
        jailed_until_epoch: Option<u64>,
    ) -> Self {
        Self {
            candidate: ValidatorCandidate::new(validator_id, stake, voting_power),
            jailed_until_epoch,
        }
    }

    /// Check if the validator is jailed at the given epoch.
    pub fn is_jailed_at_epoch(&self, current_epoch: u64) -> bool {
        self.jailed_until_epoch
            .map(|until| current_epoch < until)
            .unwrap_or(false)
    }
}

/// Result of building a validator set with stake and jail filtering (M9).
#[derive(Debug, Clone)]
pub struct ValidatorSetBuildResultWithJail {
    /// The resulting validator set (validators with stake >= min_validator_stake AND not jailed).
    pub validator_set: ConsensusValidatorSet,
    /// Validators that were excluded due to stake < min_validator_stake.
    pub excluded_low_stake: Vec<ValidatorCandidate>,
    /// Validators that were excluded due to being jailed.
    pub excluded_jailed: Vec<ValidatorCandidate>,
}

/// Build a `ConsensusValidatorSet` from validator candidates with stake AND jail filtering (M9).
///
/// This function applies both:
/// - M2.1: Minimum stake requirement (stake >= min_validator_stake)
/// - M9: Jail exclusion (jailed_until_epoch > current_epoch means excluded)
///
/// # Arguments
///
/// * `candidates` - Iterator of validator candidates with stake and jail information
/// * `min_validator_stake` - Minimum stake required for inclusion (in microQBIND)
/// * `current_epoch` - Current epoch number for jail status checking
///
/// # Returns
///
/// * `Ok(ValidatorSetBuildResultWithJail)` - The filtered validator set and excluded validators
/// * `Err(String)` - If no validators meet the requirements (fail-closed)
///
/// # Determinism Guarantees
///
/// This function ensures deterministic output:
/// 1. Candidates are sorted by `validator_id` (ascending)
/// 2. Filtering is applied uniformly using the same thresholds
/// 3. The same inputs always produce the same outputs
///
/// # Example
///
/// ```ignore
/// use qbind_consensus::validator_set::{ValidatorCandidateWithJailStatus, build_validator_set_with_stake_and_jail_filter};
///
/// let candidates = vec![
///     ValidatorCandidateWithJailStatus::new(ValidatorId::new(1), 1_000_000, 1, None),       // Eligible
///     ValidatorCandidateWithJailStatus::new(ValidatorId::new(2), 1_000_000, 1, Some(15)),   // Jailed until epoch 15
///     ValidatorCandidateWithJailStatus::new(ValidatorId::new(3), 500_000, 1, None),         // Low stake
/// ];
///
/// // At epoch 10, with min_stake = 1_000_000
/// let result = build_validator_set_with_stake_and_jail_filter(candidates, 1_000_000, 10)?;
///
/// // Only validator 1 is included (stake ok, not jailed)
/// // Validator 2 excluded (jailed until 15 > 10)
/// // Validator 3 excluded (stake too low)
/// assert_eq!(result.validator_set.len(), 1);
/// assert_eq!(result.excluded_jailed.len(), 1);
/// assert_eq!(result.excluded_low_stake.len(), 1);
/// ```
pub fn build_validator_set_with_stake_and_jail_filter<I>(
    candidates: I,
    min_validator_stake: u64,
    current_epoch: u64,
) -> Result<ValidatorSetBuildResultWithJail, String>
where
    I: IntoIterator<Item = ValidatorCandidateWithJailStatus>,
{
    // Collect and sort candidates by validator_id for deterministic ordering
    let mut all_candidates: Vec<ValidatorCandidateWithJailStatus> =
        candidates.into_iter().collect();
    all_candidates.sort_by_key(|c| c.candidate.validator_id);

    // Partition into included and excluded based on stake AND jail status
    let mut included = Vec::new();
    let mut excluded_low_stake = Vec::new();
    let mut excluded_jailed = Vec::new();

    for candidate_with_jail in all_candidates {
        let jailed_until = candidate_with_jail.jailed_until_epoch;
        let is_jailed = candidate_with_jail.is_jailed_at_epoch(current_epoch);
        let candidate = candidate_with_jail.candidate;

        // Check stake first
        if candidate.stake < min_validator_stake {
            excluded_low_stake.push(candidate);
            continue;
        }

        // Check jail status
        if is_jailed {
            eprintln!(
                "[M9] Validator {} excluded: jailed until epoch {} (current={})",
                candidate.validator_id.as_u64(),
                jailed_until.unwrap_or(0),
                current_epoch
            );
            excluded_jailed.push(candidate);
            continue;
        }

        // Validator passes all checks - include in set
        included.push(ValidatorSetEntry {
            id: candidate.validator_id,
            voting_power: candidate.voting_power,
        });
    }

    // Log filtering results
    if !excluded_jailed.is_empty() || !excluded_low_stake.is_empty() {
        eprintln!(
            "[M9] Validator set filtering at epoch {}: {} included, {} jailed, {} low stake",
            current_epoch,
            included.len(),
            excluded_jailed.len(),
            excluded_low_stake.len()
        );
    }

    // Create the validator set (will fail if empty - fail closed)
    let validator_set = ConsensusValidatorSet::new(included)?;

    Ok(ValidatorSetBuildResultWithJail {
        validator_set,
        excluded_low_stake,
        excluded_jailed,
    })
}

/// A set of validators that form the consensus committee.
///
/// `ConsensusValidatorSet` provides:
/// - Fast lookup by `ValidatorId`
/// - Iteration over all validators
/// - Total voting power calculation
///
/// # Invariants
///
/// - The validator set is non-empty.
/// - All `ValidatorId`s are unique.
/// - Total voting power is the sum of all individual voting powers (with saturation).
///
/// Note: This type is distinct from the `ValidatorSet` in `lib.rs`, which is
/// specifically designed for consensus verification with cryptographic fields.
#[derive(Debug, Clone)]
pub struct ConsensusValidatorSet {
    validators: Vec<ValidatorSetEntry>,
    index_by_id: HashMap<ValidatorId, usize>,
    total_voting_power: u64,
}

impl ConsensusValidatorSet {
    /// Create a new `ConsensusValidatorSet` from an iterator of `ValidatorSetEntry`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The iterator is empty (validator set must not be empty)
    /// - There are duplicate `ValidatorId`s
    pub fn new<I>(validators: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = ValidatorSetEntry>,
    {
        let mut vec = Vec::new();
        let mut index_by_id = HashMap::new();
        let mut total_vp = 0u64;

        for info in validators {
            if index_by_id.contains_key(&info.id) {
                return Err(format!("duplicate ValidatorId: {:?}", info.id));
            }
            let idx = vec.len();
            total_vp = total_vp.saturating_add(info.voting_power);
            index_by_id.insert(info.id, idx);
            vec.push(info);
        }

        if vec.is_empty() {
            return Err("validator set must not be empty".to_string());
        }

        Ok(ConsensusValidatorSet {
            validators: vec,
            index_by_id,
            total_voting_power: total_vp,
        })
    }

    /// Returns the number of validators in the set.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Returns `true` if the validator set is empty.
    ///
    /// Note: This should always return `false` since the constructor
    /// enforces that the set is non-empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Returns the total voting power of all validators.
    pub fn total_voting_power(&self) -> u64 {
        self.total_voting_power
    }

    /// Get a validator by index.
    ///
    /// Returns `None` if the index is out of bounds.
    pub fn get(&self, idx: usize) -> Option<&ValidatorSetEntry> {
        self.validators.get(idx)
    }

    /// Get the index of a validator by its `ValidatorId`.
    ///
    /// Returns `None` if the validator is not in the set.
    pub fn index_of(&self, id: ValidatorId) -> Option<usize> {
        self.index_by_id.get(&id).copied()
    }

    /// Check if a validator with the given `ValidatorId` is in the set.
    pub fn contains(&self, id: ValidatorId) -> bool {
        self.index_by_id.contains_key(&id)
    }

    /// Iterate over all validators in the set.
    pub fn iter(&self) -> impl Iterator<Item = &ValidatorSetEntry> {
        self.validators.iter()
    }

    /// Returns the classical `f` assuming `n = 3f + 1` type reasoning.
    ///
    /// This is a helper for tests and thresholds; we do not enforce that
    /// the set exactly satisfies 3f+1 for now.
    ///
    /// For n validators, returns floor((n - 1) / 3).
    pub fn f(&self) -> usize {
        let n = self.len();
        if n == 0 {
            return 0;
        }
        // integer floor of (n - 1)/3
        (n.saturating_sub(1)) / 3
    }

    /// Convenience: minimum number of validators for a "classic" quorum: 2f+1.
    pub fn quorum_size(&self) -> usize {
        let f = self.f();
        2 * f + 1
    }

    /// Minimum voting power required for a "2/3 total" quorum.
    ///
    /// Returns ceil(2 * total / 3).
    pub fn two_thirds_vp(&self) -> u64 {
        let total = self.total_voting_power();
        // ceil(2 * total / 3)
        (2 * total).div_ceil(3)
    }

    /// Checks if a set of validators (by id) reaches >= 2/3 of the total voting power.
    ///
    /// Unknown validator ids are ignored (treated as 0 weight).
    pub fn has_quorum<I>(&self, ids: I) -> bool
    where
        I: IntoIterator<Item = ValidatorId>,
    {
        let mut acc: u64 = 0;
        for id in ids {
            if let Some(idx) = self.index_of(id) {
                let entry = &self.validators[idx];
                acc = acc.saturating_add(entry.voting_power);
            }
            // Unknown id: ignore (treat as 0 weight)
        }
        acc >= self.two_thirds_vp()
    }
}

// ============================================================================
// Epoch Types (T100)
// ============================================================================

/// A unique identifier for an epoch.
///
/// Epochs are numbered sequentially starting from 0. The epoch number
/// represents the "era" of the validator set - when validators change,
/// the epoch advances.
///
/// For the initial static configuration, `EpochId(0)` represents the
/// genesis epoch with the initial validator set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct EpochId(pub u64);

impl EpochId {
    /// Create a new `EpochId` from a raw epoch number.
    pub fn new(epoch: u64) -> Self {
        EpochId(epoch)
    }

    /// Get the raw epoch number.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// The genesis epoch (epoch 0).
    pub const GENESIS: EpochId = EpochId(0);
}

impl From<u64> for EpochId {
    fn from(epoch: u64) -> Self {
        EpochId(epoch)
    }
}

impl From<EpochId> for u64 {
    fn from(epoch: EpochId) -> Self {
        epoch.0
    }
}

impl std::fmt::Display for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EpochId({})", self.0)
    }
}

/// The state of a single epoch, combining the epoch identifier with
/// the validator set active during that epoch.
///
/// This is the canonical representation of "who are the validators"
/// at a particular point in the consensus lifecycle.
///
/// # Invariants
///
/// - The validator set must be non-empty.
/// - All validator IDs must be unique.
/// - All validators must have positive voting power.
///
/// These invariants are enforced by `ConsensusValidatorSet::new()`.
///
/// # Usage
///
/// ```ignore
/// use qbind_consensus::validator_set::{EpochId, EpochState, ConsensusValidatorSet, ValidatorSetEntry};
/// use qbind_consensus::ids::ValidatorId;
///
/// // Create a genesis epoch with 3 validators
/// let validators = vec![
///     ValidatorSetEntry { id: ValidatorId::new(0), voting_power: 1 },
///     ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 1 },
///     ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 1 },
/// ];
/// let set = ConsensusValidatorSet::new(validators).unwrap();
/// let epoch_state = EpochState::new(EpochId::GENESIS, set);
/// ```
#[derive(Debug, Clone)]
pub struct EpochState {
    /// The epoch identifier.
    pub epoch: EpochId,
    /// The validator set active during this epoch.
    pub validator_set: ConsensusValidatorSet,
}

impl EpochState {
    /// Create a new `EpochState` with the given epoch ID and validator set.
    ///
    /// The validator set is assumed to already be validated (non-empty,
    /// unique IDs, positive voting power) since `ConsensusValidatorSet::new()`
    /// enforces these invariants.
    pub fn new(epoch: EpochId, validator_set: ConsensusValidatorSet) -> Self {
        EpochState {
            epoch,
            validator_set,
        }
    }

    /// Create a genesis epoch state (epoch 0) with the given validator set.
    ///
    /// This is a convenience constructor for creating the initial epoch.
    pub fn genesis(validator_set: ConsensusValidatorSet) -> Self {
        EpochState {
            epoch: EpochId::GENESIS,
            validator_set,
        }
    }

    /// Get the epoch identifier.
    pub fn epoch_id(&self) -> EpochId {
        self.epoch
    }

    /// Get a reference to the validator set.
    pub fn validators(&self) -> &ConsensusValidatorSet {
        &self.validator_set
    }

    /// Get a validator by their ID.
    ///
    /// Returns `None` if the validator is not in the set.
    pub fn get(&self, id: ValidatorId) -> Option<&ValidatorSetEntry> {
        self.validator_set
            .index_of(id)
            .and_then(|idx| self.validator_set.get(idx))
    }

    /// Check if a validator is in the epoch's validator set.
    pub fn contains(&self, id: ValidatorId) -> bool {
        self.validator_set.contains(id)
    }

    /// Get the total voting power of all validators in the epoch.
    pub fn total_voting_power(&self) -> u64 {
        self.validator_set.total_voting_power()
    }

    /// Get the number of validators in the epoch.
    pub fn len(&self) -> usize {
        self.validator_set.len()
    }

    /// Check if the epoch has no validators.
    ///
    /// Note: This should always return `false` since validator sets must be non-empty.
    pub fn is_empty(&self) -> bool {
        self.validator_set.is_empty()
    }

    /// Iterate over all validators in the epoch.
    pub fn iter(&self) -> impl Iterator<Item = &ValidatorSetEntry> {
        self.validator_set.iter()
    }

    /// Returns all validator IDs in the epoch.
    pub fn validator_ids(&self) -> Vec<ValidatorId> {
        self.validator_set.iter().map(|v| v.id).collect()
    }

    /// Get the single consensus signature suite ID for this epoch.
    ///
    /// Under the single-suite-per-epoch policy (T115), all validators in an epoch
    /// must use the same consensus signature suite. This method extracts that suite
    /// ID from governance.
    ///
    /// # Arguments
    ///
    /// * `governance` - The governance implementation providing consensus keys.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(suite_id))` if all validators use the same suite.
    /// * `Ok(None)` if the epoch has no validators with registered keys.
    /// * `Err(Vec<suite_ids>)` if validators use different suites (mixed suite epoch).
    ///
    /// # Design Note (T115)
    ///
    /// This method is intended for use after `validate_epoch()` has passed the
    /// single-suite-per-epoch check. If mixed suites are detected, the caller
    /// should handle this as an error condition.
    pub fn epoch_suite_id<G>(
        &self,
        governance: &G,
    ) -> Result<Option<qbind_crypto::ConsensusSigSuiteId>, Vec<qbind_crypto::ConsensusSigSuiteId>>
    where
        G: crate::governed_key_registry::ConsensusKeyGovernance + ?Sized,
    {
        let mut suite_ids: std::collections::HashSet<qbind_crypto::ConsensusSigSuiteId> =
            std::collections::HashSet::new();

        for entry in self.validator_set.iter() {
            if let Some((suite_id, _pk)) = governance.get_consensus_key(entry.id.as_u64()) {
                suite_ids.insert(suite_id);
            }
        }

        match suite_ids.len() {
            0 => Ok(None),
            1 => Ok(Some(suite_ids.into_iter().next().unwrap())),
            _ => Err(suite_ids.into_iter().collect()),
        }
    }

    /// Validate this epoch against a governance key registry.
    ///
    /// This method checks that:
    /// 1. Every validator in the epoch has a consensus key registered in governance.
    /// 2. Every consensus key uses a known signature suite (checked against the registry).
    ///
    /// # Arguments
    ///
    /// * `governance` - The governance implementation providing consensus keys.
    /// * `known_suites` - A function that checks if a suite ID is known/registered.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if validation passes.
    /// * `Err(EpochValidationError)` if any validator is missing a key or uses an unknown suite.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use qbind_consensus::validator_set::EpochState;
    /// use qbind_consensus::governed_key_registry::ConsensusKeyGovernance;
    ///
    /// let epoch_state = EpochState::genesis(validator_set);
    /// let backend_registry = /* ... */;
    ///
    /// // Validate with a suite checker
    /// epoch_state.validate_with_governance(
    ///     &governance,
    ///     |suite_id| backend_registry.get_backend(suite_id).is_some()
    /// )?;
    /// ```
    pub fn validate_with_governance<G, F>(
        &self,
        governance: &G,
        is_known_suite: F,
    ) -> Result<(), EpochValidationError>
    where
        G: crate::governed_key_registry::ConsensusKeyGovernance + ?Sized,
        F: Fn(qbind_crypto::ConsensusSigSuiteId) -> bool,
    {
        for entry in self.validator_set.iter() {
            let validator_id = entry.id.as_u64();

            // Check that governance has a key for this validator
            match governance.get_consensus_key(validator_id) {
                Some((suite_id, _pk)) => {
                    // Check that the suite is known
                    if !is_known_suite(suite_id) {
                        return Err(EpochValidationError::UnknownSuite {
                            validator_id: entry.id,
                            suite_id: suite_id.as_u16(),
                        });
                    }
                }
                None => {
                    return Err(EpochValidationError::MissingKey(entry.id));
                }
            }
        }

        Ok(())
    }

    /// Validate this epoch against a governance key registry, also checking for stray keys.
    ///
    /// This is a stricter version of `validate_with_governance` that additionally checks
    /// that no governance keys exist for validators not in the epoch set.
    ///
    /// # Arguments
    ///
    /// * `governance` - The governance implementation providing consensus keys.
    /// * `governance_validator_ids` - All validator IDs known to governance.
    /// * `is_known_suite` - A function that checks if a suite ID is known/registered.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if validation passes.
    /// * `Err(EpochValidationError)` if validation fails.
    pub fn validate_with_governance_strict<G, F>(
        &self,
        governance: &G,
        governance_validator_ids: &[u64],
        is_known_suite: F,
    ) -> Result<(), EpochValidationError>
    where
        G: crate::governed_key_registry::ConsensusKeyGovernance + ?Sized,
        F: Fn(qbind_crypto::ConsensusSigSuiteId) -> bool,
    {
        // First, validate that all epoch validators have keys
        self.validate_with_governance(governance, is_known_suite)?;

        // Then check for stray keys (governance keys for non-epoch validators)
        for &gov_validator_id in governance_validator_ids {
            let validator_id = ValidatorId::new(gov_validator_id);
            if !self.contains(validator_id) {
                // Governance has a key for a validator not in the epoch
                return Err(EpochValidationError::StrayKey(validator_id));
            }
        }

        Ok(())
    }
}

// ============================================================================
// Epoch Validation Error (T100)
// ============================================================================

/// Errors that can occur when validating an epoch against governance.
///
/// These errors indicate misconfiguration between the epoch's validator set
/// and the governance system's key registry.
#[derive(Debug, Clone)]
pub enum EpochValidationError {
    /// A validator in the epoch has no consensus key registered in governance.
    MissingKey(ValidatorId),

    /// A validator's consensus key uses an unknown signature suite.
    UnknownSuite {
        validator_id: ValidatorId,
        suite_id: u16,
    },

    /// A governance key exists for a validator not in the epoch set.
    /// This indicates a mismatch between governance and the epoch configuration.
    StrayKey(ValidatorId),

    /// Other validation error.
    Other(String),
}

impl std::fmt::Display for EpochValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpochValidationError::MissingKey(id) => {
                write!(f, "validator {:?} has no consensus key in governance", id)
            }
            EpochValidationError::UnknownSuite {
                validator_id,
                suite_id,
            } => {
                write!(
                    f,
                    "validator {:?} uses unknown signature suite {}",
                    validator_id, suite_id
                )
            }
            EpochValidationError::StrayKey(id) => {
                write!(
                    f,
                    "governance has a key for validator {:?} which is not in the epoch set",
                    id
                )
            }
            EpochValidationError::Other(msg) => {
                write!(f, "epoch validation error: {}", msg)
            }
        }
    }
}

impl std::error::Error for EpochValidationError {}

// ============================================================================
// Epoch Reconfiguration Payload (T102)
// ============================================================================

/// Payload carried by a reconfiguration block indicating epoch transition.
///
/// A reconfiguration block is a special block that, when committed, triggers
/// an epoch transition. The payload carries the identifier of the next epoch.
///
/// # Design Note (T102)
///
/// For this task, the payload only contains `next_epoch: EpochId`. The actual
/// `EpochState` for the new epoch is fetched from an `EpochStateProvider` at
/// commit time. Future tasks may extend this to carry a full `EpochState`
/// reference or hash.
///
/// # Safety
///
/// The reconfig payload is included in the block's signed preimage, ensuring
/// that leaders cannot undetectably change epoch info after proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconfigPayload {
    /// The epoch ID that the network will transition to when this block commits.
    pub next_epoch: EpochId,
}

impl ReconfigPayload {
    /// Create a new reconfiguration payload for transitioning to the given epoch.
    pub fn new(next_epoch: EpochId) -> Self {
        ReconfigPayload { next_epoch }
    }
}

/// Block payload type indicator for consensus blocks.
///
/// This enum distinguishes between normal transaction blocks and special
/// reconfiguration blocks that trigger epoch transitions.
///
/// # Variants
///
/// - `Normal`: A regular block containing transactions. No epoch change.
/// - `Reconfig`: A reconfiguration block that triggers an epoch transition.
///
/// # Design Note (T102)
///
/// For now, we keep this simple with just two variants. Future tasks may add:
/// - `Checkpoint`: For periodic state checkpoints
/// - `Governance`: For on-chain governance proposals
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BlockPayloadType {
    /// Normal transaction block - no epoch change.
    #[default]
    Normal,
    /// Reconfiguration block - triggers epoch transition.
    Reconfig(ReconfigPayload),
}

impl BlockPayloadType {
    /// Create a normal (non-reconfig) payload.
    pub fn normal() -> Self {
        BlockPayloadType::Normal
    }

    /// Create a reconfiguration payload for the given next epoch.
    pub fn reconfig(next_epoch: EpochId) -> Self {
        BlockPayloadType::Reconfig(ReconfigPayload::new(next_epoch))
    }

    /// Returns `true` if this is a reconfiguration block.
    pub fn is_reconfig(&self) -> bool {
        matches!(self, BlockPayloadType::Reconfig(_))
    }

    /// Returns the reconfig payload if this is a reconfig block, or `None` otherwise.
    pub fn reconfig_payload(&self) -> Option<&ReconfigPayload> {
        match self {
            BlockPayloadType::Reconfig(p) => Some(p),
            BlockPayloadType::Normal => None,
        }
    }

    /// Returns the next epoch if this is a reconfig block, or `None` otherwise.
    pub fn next_epoch(&self) -> Option<EpochId> {
        self.reconfig_payload().map(|p| p.next_epoch)
    }
}

// ============================================================================
// EpochStateProvider Trait (T102)
// ============================================================================

/// Provider abstraction for fetching epoch states.
///
/// This trait allows the consensus layer to fetch `EpochState` for a given
/// epoch without coupling to a specific source (config, governance, etc.).
///
/// # Usage
///
/// - At commit time, when a reconfig block is committed, the driver uses
///   this provider to fetch the `EpochState` for the next epoch.
/// - In tests, use `StaticEpochStateProvider` configured with known epochs.
/// - In production, this will be backed by on-chain governance.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow sharing across threads.
pub trait EpochStateProvider: Send + Sync + std::fmt::Debug {
    /// Get the `EpochState` for the given epoch ID.
    ///
    /// Returns `None` if the epoch is not known to this provider.
    fn get_epoch_state(&self, epoch: EpochId) -> Option<EpochState>;
}

/// A static epoch state provider configured with a map of known epochs.
///
/// This is a test-only implementation that returns epoch states from a
/// pre-configured map. Used for testing epoch transitions without
/// requiring on-chain governance.
///
/// # Example
///
/// ```ignore
/// use qbind_consensus::validator_set::{EpochId, EpochState, StaticEpochStateProvider};
///
/// let epoch0 = EpochState::genesis(validator_set.clone());
/// let epoch1 = EpochState::new(EpochId::new(1), validator_set);
///
/// let provider = StaticEpochStateProvider::new()
///     .with_epoch(epoch0)
///     .with_epoch(epoch1);
///
/// assert!(provider.get_epoch_state(EpochId::new(0)).is_some());
/// assert!(provider.get_epoch_state(EpochId::new(1)).is_some());
/// assert!(provider.get_epoch_state(EpochId::new(99)).is_none());
/// ```
#[derive(Debug, Clone, Default)]
pub struct StaticEpochStateProvider {
    epochs: HashMap<EpochId, EpochState>,
}

impl StaticEpochStateProvider {
    /// Create a new empty static epoch state provider.
    pub fn new() -> Self {
        StaticEpochStateProvider {
            epochs: HashMap::new(),
        }
    }

    /// Add an epoch state to this provider.
    ///
    /// The epoch ID is taken from the `EpochState.epoch` field.
    /// Returns `self` for method chaining.
    pub fn with_epoch(mut self, state: EpochState) -> Self {
        self.epochs.insert(state.epoch_id(), state);
        self
    }

    /// Insert an epoch state into this provider.
    ///
    /// This is the non-consuming version of `with_epoch`.
    pub fn insert(&mut self, state: EpochState) {
        self.epochs.insert(state.epoch_id(), state);
    }

    /// Returns the number of epochs in this provider.
    pub fn len(&self) -> usize {
        self.epochs.len()
    }

    /// Returns `true` if this provider has no epochs.
    pub fn is_empty(&self) -> bool {
        self.epochs.is_empty()
    }

    /// Returns an iterator over all epoch IDs in this provider.
    pub fn epoch_ids(&self) -> impl Iterator<Item = &EpochId> {
        self.epochs.keys()
    }
}

impl EpochStateProvider for StaticEpochStateProvider {
    fn get_epoch_state(&self, epoch: EpochId) -> Option<EpochState> {
        self.epochs.get(&epoch).cloned()
    }
}

// ============================================================================
// M2.2: Stake Filtering Epoch State Provider
// ============================================================================

/// Error returned when stake filtering excludes all validators.
///
/// This is a fail-closed guard: if minimum stake filtering would result in
/// an empty validator set, the epoch transition must fail rather than
/// proceeding with undefined consensus behavior.
#[derive(Debug, Clone)]
pub struct StakeFilterEmptySetError {
    /// The epoch that was being transitioned to.
    pub epoch: EpochId,
    /// Number of validators that were candidates before filtering.
    pub total_candidates: usize,
    /// The minimum stake threshold that excluded all candidates.
    pub min_stake: u64,
}

impl std::fmt::Display for StakeFilterEmptySetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stake filtering for epoch {} excluded all {} validators (min_stake={}). \
             This is a Pre-TestNet fail-closed guard.",
            self.epoch, self.total_candidates, self.min_stake
        )
    }
}

impl std::error::Error for StakeFilterEmptySetError {}

/// A stake-filtering wrapper around an inner `EpochStateProvider`.
///
/// This provider applies minimum stake filtering to validator sets at epoch
/// boundaries. It wraps an inner provider that supplies validator candidates
/// with their stake amounts, then filters out validators with insufficient stake.
///
/// # M2.2 Integration
///
/// This provider is the canonical integration point for minimum stake enforcement
/// at epoch transitions. When `get_epoch_state()` is called:
///
/// 1. The inner provider supplies validator candidates with stake amounts
/// 2. `build_validator_set_with_stake_filter()` filters out validators below threshold
/// 3. A new `EpochState` is constructed with only the eligible validators
///
/// # Fail-Closed Behavior
///
/// If filtering would result in an empty validator set (all candidates below
/// minimum stake), `get_epoch_state()` returns `None` rather than proceeding
/// with undefined consensus behavior. The `last_filter_error()` method can
/// be called to retrieve details about why filtering failed.
///
/// # Determinism
///
/// The filtering is deterministic: validators are sorted by `ValidatorId`
/// before filtering, ensuring all nodes derive the same validator set.
///
/// # Example
///
/// ```ignore
/// use qbind_consensus::validator_set::{
///     EpochStateProvider, StaticEpochStateProvider, StakeFilteringEpochStateProvider,
///     EpochState, EpochId, ValidatorCandidate,
/// };
/// use std::sync::Arc;
///
/// // Create inner provider with validator candidates
/// let inner = Arc::new(StaticEpochStateProvider::new().with_epoch(epoch_state));
///
/// // Create stake-filtering provider with 1 QBIND minimum stake
/// let provider = StakeFilteringEpochStateProvider::new(inner, 1_000_000);
///
/// // get_epoch_state now returns filtered validator set
/// let filtered_state = provider.get_epoch_state(EpochId::new(1));
/// ```
#[derive(Debug)]
pub struct StakeFilteringEpochStateProvider<P: EpochStateProvider> {
    inner: P,
    min_validator_stake: u64,
    /// Last error encountered during filtering (for diagnostics).
    /// This is used for fail-closed error reporting.
    last_filter_error: std::sync::Mutex<Option<StakeFilterEmptySetError>>,
}

impl<P: EpochStateProvider> StakeFilteringEpochStateProvider<P> {
    /// Create a new stake-filtering provider wrapping an inner provider.
    ///
    /// # Arguments
    ///
    /// * `inner` - The inner provider supplying validator candidates.
    /// * `min_validator_stake` - Minimum stake required for inclusion (in microQBIND).
    ///
    /// # Notes
    ///
    /// The inner provider must supply `EpochState` objects where validators
    /// have stake information available. For production use, this typically
    /// means the inner provider reads from ledger state.
    pub fn new(inner: P, min_validator_stake: u64) -> Self {
        Self {
            inner,
            min_validator_stake,
            last_filter_error: std::sync::Mutex::new(None),
        }
    }

    /// Get the minimum stake threshold used for filtering.
    pub fn min_validator_stake(&self) -> u64 {
        self.min_validator_stake
    }

    /// Get the last filter error, if any.
    ///
    /// This is useful for diagnostics when `get_epoch_state()` returns `None`
    /// due to stake filtering excluding all validators.
    pub fn last_filter_error(&self) -> Option<StakeFilterEmptySetError> {
        self.last_filter_error.lock().unwrap().clone()
    }

    /// Clear the last filter error.
    pub fn clear_last_filter_error(&self) {
        *self.last_filter_error.lock().unwrap() = None;
    }
}

impl<P: EpochStateProvider> EpochStateProvider for StakeFilteringEpochStateProvider<P> {
    fn get_epoch_state(&self, epoch: EpochId) -> Option<EpochState> {
        // Get the epoch state from the inner provider
        let inner_state = self.inner.get_epoch_state(epoch)?;

        // If min_validator_stake is 0, no filtering needed - pass through
        if self.min_validator_stake == 0 {
            return Some(inner_state);
        }

        // Convert validators to candidates for stake filtering
        // NOTE: In this implementation, we use voting_power as a proxy for stake
        // since the current EpochState doesn't carry explicit stake values.
        // For production ledger-backed providers, this should be replaced with
        // actual stake values from ValidatorRecord.stake.
        let candidates: Vec<ValidatorCandidate> = inner_state
            .validator_set
            .iter()
            .map(|entry| {
                // Use voting_power as stake proxy. In production, this would be
                // replaced with actual ledger stake lookup.
                ValidatorCandidate::new(entry.id, entry.voting_power, entry.voting_power)
            })
            .collect();

        let total_candidates = candidates.len();

        // Apply stake filtering
        match build_validator_set_with_stake_filter(candidates, self.min_validator_stake) {
            Ok(result) => {
                // Clear any previous error
                self.clear_last_filter_error();

                // Log excluded validators for observability
                if !result.excluded.is_empty() {
                    eprintln!(
                        "[M2.2] Epoch {} stake filtering: {} validators included, {} excluded (min_stake={})",
                        epoch.as_u64(),
                        result.validator_set.len(),
                        result.excluded.len(),
                        self.min_validator_stake
                    );
                    for excluded in &result.excluded {
                        eprintln!(
                            "[M2.2]   Excluded validator {} (stake={} < min_stake={})",
                            excluded.validator_id.as_u64(),
                            excluded.stake,
                            self.min_validator_stake
                        );
                    }
                }

                Some(EpochState::new(epoch, result.validator_set))
            }
            Err(_) => {
                // Fail closed: all validators excluded
                let error = StakeFilterEmptySetError {
                    epoch,
                    total_candidates,
                    min_stake: self.min_validator_stake,
                };
                eprintln!(
                    "[M2.2] FAIL CLOSED: {}",
                    error
                );
                *self.last_filter_error.lock().unwrap() = Some(error);
                None
            }
        }
    }
}

// ============================================================================
// Epoch Transition Error (T102)
// ============================================================================

/// Errors that can occur during epoch transition.
///
/// These errors indicate problems when processing a reconfiguration block
/// and transitioning to a new epoch.
#[derive(Debug, Clone)]
pub enum EpochTransitionError {
    /// The next epoch is not available from the epoch state provider.
    MissingEpochState(EpochId),

    /// The epoch state failed governance validation.
    ValidationFailed {
        epoch: EpochId,
        error: EpochValidationError,
    },

    /// Attempted to transition to an epoch that's not the immediate successor.
    ///
    /// Epoch transitions must be sequential: N → N+1.
    NonSequentialEpoch {
        current: EpochId,
        requested: EpochId,
    },

    /// Other epoch transition error.
    Other(String),
}

impl std::fmt::Display for EpochTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpochTransitionError::MissingEpochState(epoch) => {
                write!(f, "epoch state not available for {:?}", epoch)
            }
            EpochTransitionError::ValidationFailed { epoch, error } => {
                write!(f, "epoch {:?} validation failed: {}", epoch, error)
            }
            EpochTransitionError::NonSequentialEpoch { current, requested } => {
                write!(
                    f,
                    "non-sequential epoch transition: current {:?}, requested {:?}",
                    current, requested
                )
            }
            EpochTransitionError::Other(msg) => {
                write!(f, "epoch transition error: {}", msg)
            }
        }
    }
}

impl std::error::Error for EpochTransitionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_set_basic_creation() {
        let validators = vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 20,
            },
        ];

        let set = ConsensusValidatorSet::new(validators).expect("should succeed");
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        assert_eq!(set.total_voting_power(), 30);
    }

    #[test]
    fn validator_set_get_by_index() {
        let validators = vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 20,
            },
        ];

        let set = ConsensusValidatorSet::new(validators).expect("should succeed");

        let v0 = set.get(0).expect("index 0 should exist");
        assert_eq!(v0.id, ValidatorId::new(1));
        assert_eq!(v0.voting_power, 10);

        let v1 = set.get(1).expect("index 1 should exist");
        assert_eq!(v1.id, ValidatorId::new(2));
        assert_eq!(v1.voting_power, 20);

        assert!(set.get(2).is_none());
    }

    #[test]
    fn validator_set_f_calculation() {
        // n=1: f = (1-1)/3 = 0
        let set1 = ConsensusValidatorSet::new(vec![ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 10,
        }])
        .unwrap();
        assert_eq!(set1.f(), 0);

        // n=3: f = (3-1)/3 = 0  (floor)
        let set3 = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(3),
                voting_power: 10,
            },
        ])
        .unwrap();
        assert_eq!(set3.f(), 0);

        // n=4: f = (4-1)/3 = 1
        let set4 = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(3),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(4),
                voting_power: 10,
            },
        ])
        .unwrap();
        assert_eq!(set4.f(), 1);

        // n=7: f = (7-1)/3 = 2
        let set7 = ConsensusValidatorSet::new((1..=7).map(|i| ValidatorSetEntry {
            id: ValidatorId::new(i),
            voting_power: 10,
        }))
        .unwrap();
        assert_eq!(set7.f(), 2);
    }

    #[test]
    fn validator_set_quorum_size_calculation() {
        // n=4, f=1 => quorum_size = 2*1+1 = 3
        let set4 = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(3),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(4),
                voting_power: 10,
            },
        ])
        .unwrap();
        assert_eq!(set4.quorum_size(), 3);

        // n=7, f=2 => quorum_size = 2*2+1 = 5
        let set7 = ConsensusValidatorSet::new((1..=7).map(|i| ValidatorSetEntry {
            id: ValidatorId::new(i),
            voting_power: 10,
        }))
        .unwrap();
        assert_eq!(set7.quorum_size(), 5);
    }

    #[test]
    fn validator_set_two_thirds_vp() {
        // total_power = 30, two_thirds = ceil(2*30/3) = ceil(60/3) = 20
        let set = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(3),
                voting_power: 10,
            },
        ])
        .unwrap();
        assert_eq!(set.total_voting_power(), 30);
        assert_eq!(set.two_thirds_vp(), 20);

        // total_power = 100, two_thirds = ceil(200/3) = 67
        let set100 = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 50,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 50,
            },
        ])
        .unwrap();
        assert_eq!(set100.total_voting_power(), 100);
        assert_eq!(set100.two_thirds_vp(), 67);
    }

    #[test]
    fn validator_set_has_quorum() {
        // 3 validators with power 10 each => total = 30, need >= 20 for quorum
        let set = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(3),
                voting_power: 10,
            },
        ])
        .unwrap();

        // Single validator (10) does not reach quorum (20)
        assert!(!set.has_quorum([ValidatorId::new(1)]));

        // Two validators (20) reaches quorum (20)
        assert!(set.has_quorum([ValidatorId::new(1), ValidatorId::new(2)]));

        // All three (30) reaches quorum
        assert!(set.has_quorum([
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(3)
        ]));

        // Unknown validator is ignored
        assert!(!set.has_quorum([ValidatorId::new(999)]));

        // Unknown validator + one known (10) does not reach quorum
        assert!(!set.has_quorum([ValidatorId::new(1), ValidatorId::new(999)]));

        // Two known validators + one unknown reaches quorum
        assert!(set.has_quorum([
            ValidatorId::new(1),
            ValidatorId::new(2),
            ValidatorId::new(999)
        ]));
    }

    #[test]
    fn validator_set_has_quorum_weighted() {
        // Weighted validators: 10 + 20 + 70 = 100, need >= 67 for quorum
        let set = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 20,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(3),
                voting_power: 70,
            },
        ])
        .unwrap();

        // Validator 3 alone (70) reaches quorum (67)
        assert!(set.has_quorum([ValidatorId::new(3)]));

        // Validators 1+2 (30) does not reach quorum (67)
        assert!(!set.has_quorum([ValidatorId::new(1), ValidatorId::new(2)]));

        // Validators 2+3 (90) reaches quorum
        assert!(set.has_quorum([ValidatorId::new(2), ValidatorId::new(3)]));
    }

    // ========================================================================
    // Epoch Type Tests (T100)
    // ========================================================================

    #[test]
    fn epoch_id_basic_operations() {
        let epoch0 = EpochId::new(0);
        let epoch1 = EpochId::new(1);
        let epoch_from: EpochId = 42.into();

        assert_eq!(epoch0.as_u64(), 0);
        assert_eq!(epoch1.as_u64(), 1);
        assert_eq!(epoch_from.as_u64(), 42);

        // Genesis constant
        assert_eq!(EpochId::GENESIS, EpochId::new(0));
        assert_eq!(EpochId::GENESIS.as_u64(), 0);

        // Ordering
        assert!(epoch0 < epoch1);
        assert_eq!(EpochId::new(5), EpochId::new(5));

        // Into u64
        let raw: u64 = epoch_from.into();
        assert_eq!(raw, 42);
    }

    #[test]
    fn epoch_id_display() {
        let epoch = EpochId::new(123);
        let s = format!("{}", epoch);
        assert_eq!(s, "EpochId(123)");
    }

    #[test]
    fn epoch_state_basic_creation() {
        let validators = vec![
            ValidatorSetEntry {
                id: ValidatorId::new(0),
                voting_power: 1,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 1,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 1,
            },
        ];
        let set = ConsensusValidatorSet::new(validators).unwrap();
        let epoch_state = EpochState::new(EpochId::new(5), set);

        assert_eq!(epoch_state.epoch_id(), EpochId::new(5));
        assert_eq!(epoch_state.len(), 3);
        assert_eq!(epoch_state.total_voting_power(), 3);
        assert!(!epoch_state.is_empty());
    }

    #[test]
    fn epoch_state_genesis_constructor() {
        let validators = vec![
            ValidatorSetEntry {
                id: ValidatorId::new(0),
                voting_power: 1,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 1,
            },
        ];
        let set = ConsensusValidatorSet::new(validators).unwrap();
        let epoch_state = EpochState::genesis(set);

        assert_eq!(epoch_state.epoch_id(), EpochId::GENESIS);
        assert_eq!(epoch_state.epoch_id().as_u64(), 0);
    }

    #[test]
    fn epoch_state_get_and_contains() {
        let validators = vec![
            ValidatorSetEntry {
                id: ValidatorId::new(10),
                voting_power: 100,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(20),
                voting_power: 200,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(30),
                voting_power: 300,
            },
        ];
        let set = ConsensusValidatorSet::new(validators).unwrap();
        let epoch_state = EpochState::genesis(set);

        // Test get
        let v10 = epoch_state
            .get(ValidatorId::new(10))
            .expect("should find validator 10");
        assert_eq!(v10.id, ValidatorId::new(10));
        assert_eq!(v10.voting_power, 100);

        let v30 = epoch_state
            .get(ValidatorId::new(30))
            .expect("should find validator 30");
        assert_eq!(v30.voting_power, 300);

        assert!(epoch_state.get(ValidatorId::new(99)).is_none());

        // Test contains
        assert!(epoch_state.contains(ValidatorId::new(10)));
        assert!(epoch_state.contains(ValidatorId::new(20)));
        assert!(epoch_state.contains(ValidatorId::new(30)));
        assert!(!epoch_state.contains(ValidatorId::new(99)));
    }

    #[test]
    fn epoch_state_iterator_and_validator_ids() {
        let validators = vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 20,
            },
        ];
        let set = ConsensusValidatorSet::new(validators).unwrap();
        let epoch_state = EpochState::genesis(set);

        // Test iter
        let collected: Vec<&ValidatorSetEntry> = epoch_state.iter().collect();
        assert_eq!(collected.len(), 2);

        // Test validator_ids
        let ids = epoch_state.validator_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&ValidatorId::new(1)));
        assert!(ids.contains(&ValidatorId::new(2)));
    }

    #[test]
    fn epoch_validation_error_display() {
        let err1 = EpochValidationError::MissingKey(ValidatorId::new(42));
        assert!(err1.to_string().contains("42"));
        assert!(err1.to_string().contains("no consensus key"));

        let err2 = EpochValidationError::UnknownSuite {
            validator_id: ValidatorId::new(5),
            suite_id: 99,
        };
        assert!(err2.to_string().contains("5"));
        assert!(err2.to_string().contains("99"));
        assert!(err2.to_string().contains("unknown signature suite"));

        let err3 = EpochValidationError::StrayKey(ValidatorId::new(123));
        assert!(err3.to_string().contains("123"));
        assert!(err3.to_string().contains("not in the epoch set"));

        let err4 = EpochValidationError::Other("test error".to_string());
        assert!(err4.to_string().contains("test error"));
    }
}