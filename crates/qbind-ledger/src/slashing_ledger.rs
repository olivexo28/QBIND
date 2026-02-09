//! Slashing Ledger trait and implementations (T230).
//!
//! This module provides the `SlashingLedger` trait that abstracts validator stake
//! and jailing state management for the slashing system. It enables the slashing
//! backend in `qbind-consensus` to apply penalties without knowing implementation
//! details of the staking/validator registry.
//!
//! # Design (T230)
//!
//! Following the existing `AccountStore` pattern in this crate, we provide:
//! - `SlashingLedger` trait: Minimal interface for slashing operations
//! - `InMemorySlashingLedger`: HashMap-backed implementation for tests
//!
//! # Future Work
//!
//! T23x will add:
//! - Persistent RocksDB-backed implementation
//! - On-chain slashing evidence transactions
//! - Governance transactions for parameter adjustments

use std::collections::HashMap;

/// Unique identifier for a validator in the slashing ledger.
///
/// This is a u64 that matches the ValidatorId used in qbind-consensus.
pub type ValidatorLedgerId = u64;

/// Amount of stake in native units (e.g., microQBIND).
pub type StakeAmount = u64;

/// Epoch number for jail expiration.
pub type EpochNumber = u64;

/// Validator state tracked by the slashing ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatorSlashingState {
    /// Current stake amount.
    pub stake: StakeAmount,
    /// Epoch at which the validator will be unjailed (None = not jailed).
    pub jailed_until_epoch: Option<EpochNumber>,
    /// Total stake slashed (cumulative, for audit purposes).
    pub total_slashed: StakeAmount,
    /// Number of times this validator has been jailed.
    pub jail_count: u32,
}

/// Slashing record persisted in the ledger for audit/CLI inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingRecord {
    /// The validator that was slashed.
    pub validator_id: ValidatorLedgerId,
    /// The offense kind (as string for serialization).
    pub offense_kind: String,
    /// Amount of stake burned.
    pub slashed_amount: StakeAmount,
    /// Whether the validator was jailed.
    pub jailed: bool,
    /// Epoch at which the validator will be unjailed (if jailed).
    pub jailed_until_epoch: Option<EpochNumber>,
    /// Block height at which the slashing occurred.
    pub height: u64,
    /// View at which the slashing occurred.
    pub view: u64,
    /// Epoch at which the slashing occurred.
    pub epoch: u64,
}

/// Error type for slashing ledger operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlashingLedgerError {
    /// Validator not found in the registry.
    ValidatorNotFound(ValidatorLedgerId),
    /// Insufficient stake to slash.
    InsufficientStake {
        validator_id: ValidatorLedgerId,
        required_bps: u16,
        available_stake: StakeAmount,
    },
    /// Validator already jailed.
    AlreadyJailed(ValidatorLedgerId),
    /// Storage error.
    StorageError(String),
    /// Other error.
    Other(String),
}

impl std::fmt::Display for SlashingLedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlashingLedgerError::ValidatorNotFound(id) => {
                write!(f, "validator {} not found", id)
            }
            SlashingLedgerError::InsufficientStake {
                validator_id,
                required_bps,
                available_stake,
            } => {
                write!(
                    f,
                    "validator {} has insufficient stake ({}) for {} bps slash",
                    validator_id, available_stake, required_bps
                )
            }
            SlashingLedgerError::AlreadyJailed(id) => {
                write!(f, "validator {} is already jailed", id)
            }
            SlashingLedgerError::StorageError(msg) => write!(f, "storage error: {}", msg),
            SlashingLedgerError::Other(msg) => write!(f, "slashing ledger error: {}", msg),
        }
    }
}

impl std::error::Error for SlashingLedgerError {}

/// Abstract slashing ledger trait (T230).
///
/// This trait provides the minimal operations needed by the slashing backend
/// to apply penalties. Implementations can be in-memory (for tests) or
/// persistent (for nodes).
///
/// # Design Notes
///
/// The trait is designed to be:
/// - Minimal: Only exposes what the slashing backend needs
/// - Testable: In-memory implementation for unit tests
/// - Extensible: Future persistent implementations can add state commits
pub trait SlashingLedger {
    /// Get a validator's current slashing state.
    fn get_validator_state(
        &self,
        validator_id: ValidatorLedgerId,
    ) -> Option<ValidatorSlashingState>;

    /// Get a validator's current stake.
    fn get_stake(&self, validator_id: ValidatorLedgerId) -> Option<StakeAmount>;

    /// Reduce a validator's stake by a percentage (basis points).
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to slash
    /// * `slash_bps` - Slash percentage in basis points (1 bps = 0.01%)
    ///
    /// # Returns
    ///
    /// The amount of stake actually burned.
    fn slash_stake(
        &mut self,
        validator_id: ValidatorLedgerId,
        slash_bps: u16,
    ) -> Result<StakeAmount, SlashingLedgerError>;

    /// Mark a validator as jailed until a specific epoch.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to jail
    /// * `until_epoch` - The epoch at which the validator will be unjailed
    ///
    /// # Returns
    ///
    /// The epoch at which the validator will be unjailed.
    fn jail_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
        until_epoch: EpochNumber,
    ) -> Result<EpochNumber, SlashingLedgerError>;

    /// Check if a validator is currently jailed.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to check
    /// * `current_epoch` - The current epoch (for comparing against jail expiration)
    fn is_jailed(&self, validator_id: ValidatorLedgerId, current_epoch: EpochNumber) -> bool;

    /// Clear a validator's jail status (for unjailing at epoch boundary).
    fn unjail_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
    ) -> Result<(), SlashingLedgerError>;

    /// Store a slashing record for audit purposes.
    fn store_slashing_record(&mut self, record: SlashingRecord) -> Result<(), SlashingLedgerError>;

    /// Get all slashing records for a validator.
    fn get_slashing_records(
        &self,
        validator_id: ValidatorLedgerId,
    ) -> Vec<SlashingRecord>;

    /// Get all slashing records in the ledger.
    fn get_all_slashing_records(&self) -> Vec<SlashingRecord>;
}

// ============================================================================
// In-Memory Implementation
// ============================================================================

/// In-memory slashing ledger for tests (T230).
///
/// Tracks per-validator stake and jail status in memory.
/// Used by unit tests and integration harnesses.
#[derive(Debug, Default)]
pub struct InMemorySlashingLedger {
    /// Per-validator slashing state.
    validator_states: HashMap<ValidatorLedgerId, ValidatorSlashingState>,
    /// All slashing records (for audit purposes).
    records: Vec<SlashingRecord>,
}

impl InMemorySlashingLedger {
    /// Create a new empty in-memory slashing ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an in-memory ledger with initial validator stakes.
    ///
    /// # Arguments
    ///
    /// * `initial_stakes` - Iterator of (validator_id, stake) pairs
    pub fn with_stakes(initial_stakes: impl IntoIterator<Item = (ValidatorLedgerId, StakeAmount)>) -> Self {
        let validator_states: HashMap<_, _> = initial_stakes
            .into_iter()
            .map(|(id, stake)| {
                (
                    id,
                    ValidatorSlashingState {
                        stake,
                        jailed_until_epoch: None,
                        total_slashed: 0,
                        jail_count: 0,
                    },
                )
            })
            .collect();
        Self {
            validator_states,
            records: Vec::new(),
        }
    }

    /// Set a validator's stake (for testing).
    pub fn set_stake(&mut self, validator_id: ValidatorLedgerId, stake: StakeAmount) {
        self.validator_states
            .entry(validator_id)
            .or_default()
            .stake = stake;
    }

    /// Get the number of validators tracked.
    pub fn validator_count(&self) -> usize {
        self.validator_states.len()
    }

    /// Get total stake across all validators.
    pub fn total_stake(&self) -> StakeAmount {
        self.validator_states.values().map(|s| s.stake).sum()
    }

    /// Get total amount slashed across all validators.
    pub fn total_slashed(&self) -> StakeAmount {
        self.validator_states.values().map(|s| s.total_slashed).sum()
    }
}

impl SlashingLedger for InMemorySlashingLedger {
    fn get_validator_state(
        &self,
        validator_id: ValidatorLedgerId,
    ) -> Option<ValidatorSlashingState> {
        self.validator_states.get(&validator_id).cloned()
    }

    fn get_stake(&self, validator_id: ValidatorLedgerId) -> Option<StakeAmount> {
        self.validator_states.get(&validator_id).map(|s| s.stake)
    }

    fn slash_stake(
        &mut self,
        validator_id: ValidatorLedgerId,
        slash_bps: u16,
    ) -> Result<StakeAmount, SlashingLedgerError> {
        let state = self
            .validator_states
            .get_mut(&validator_id)
            .ok_or(SlashingLedgerError::ValidatorNotFound(validator_id))?;

        // Calculate slash amount: stake * slash_bps / 10000
        let slash_amount = (state.stake as u128 * u128::from(slash_bps) / 10000) as u64;

        // Apply slash
        state.stake = state.stake.saturating_sub(slash_amount);
        state.total_slashed += slash_amount;

        eprintln!(
            "[SLASHING_LEDGER] Slashed {} from validator {} ({} bps), remaining stake: {}",
            slash_amount, validator_id, slash_bps, state.stake
        );

        Ok(slash_amount)
    }

    fn jail_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
        until_epoch: EpochNumber,
    ) -> Result<EpochNumber, SlashingLedgerError> {
        let state = self
            .validator_states
            .get_mut(&validator_id)
            .ok_or(SlashingLedgerError::ValidatorNotFound(validator_id))?;

        // Update jail status (extend if already jailed to a later epoch)
        let current_jail = state.jailed_until_epoch.unwrap_or(0);
        if until_epoch > current_jail {
            state.jailed_until_epoch = Some(until_epoch);
            state.jail_count += 1;
            eprintln!(
                "[SLASHING_LEDGER] Jailed validator {} until epoch {} (jail count: {})",
                validator_id, until_epoch, state.jail_count
            );
        }

        Ok(until_epoch)
    }

    fn is_jailed(&self, validator_id: ValidatorLedgerId, current_epoch: EpochNumber) -> bool {
        self.validator_states
            .get(&validator_id)
            .and_then(|s| s.jailed_until_epoch)
            .map(|until| current_epoch < until)
            .unwrap_or(false)
    }

    fn unjail_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
    ) -> Result<(), SlashingLedgerError> {
        let state = self
            .validator_states
            .get_mut(&validator_id)
            .ok_or(SlashingLedgerError::ValidatorNotFound(validator_id))?;

        state.jailed_until_epoch = None;
        eprintln!("[SLASHING_LEDGER] Unjailed validator {}", validator_id);

        Ok(())
    }

    fn store_slashing_record(&mut self, record: SlashingRecord) -> Result<(), SlashingLedgerError> {
        self.records.push(record);
        Ok(())
    }

    fn get_slashing_records(&self, validator_id: ValidatorLedgerId) -> Vec<SlashingRecord> {
        self.records
            .iter()
            .filter(|r| r.validator_id == validator_id)
            .cloned()
            .collect()
    }

    fn get_all_slashing_records(&self) -> Vec<SlashingRecord> {
        self.records.clone()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_slashing_ledger_basic() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![
            (1, 100_000),
            (2, 200_000),
            (3, 50_000),
        ]);

        // Verify initial state
        assert_eq!(ledger.get_stake(1), Some(100_000));
        assert_eq!(ledger.get_stake(2), Some(200_000));
        assert_eq!(ledger.get_stake(3), Some(50_000));
        assert_eq!(ledger.get_stake(999), None);

        // Slash validator 1 by 750 bps (7.5%)
        let slashed = ledger.slash_stake(1, 750).unwrap();
        assert_eq!(slashed, 7_500); // 100_000 * 750 / 10000 = 7500
        assert_eq!(ledger.get_stake(1), Some(92_500));

        // Verify total slashed
        assert_eq!(ledger.total_slashed(), 7_500);
    }

    #[test]
    fn test_in_memory_slashing_ledger_jail() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![
            (1, 100_000),
            (2, 200_000),
        ]);

        // Jail validator 1 until epoch 10
        let until = ledger.jail_validator(1, 10).unwrap();
        assert_eq!(until, 10);

        // Check jail status at various epochs
        assert!(ledger.is_jailed(1, 5)); // Before epoch 10
        assert!(ledger.is_jailed(1, 9)); // Still before epoch 10
        assert!(!ledger.is_jailed(1, 10)); // At epoch 10, no longer jailed
        assert!(!ledger.is_jailed(1, 15)); // After epoch 10

        // Validator 2 should not be jailed
        assert!(!ledger.is_jailed(2, 5));

        // Extend jail period
        ledger.jail_validator(1, 20).unwrap();
        assert!(ledger.is_jailed(1, 15)); // Now jailed until 20
        assert!(!ledger.is_jailed(1, 25)); // After epoch 20

        // Verify jail count
        let state = ledger.get_validator_state(1).unwrap();
        assert_eq!(state.jail_count, 2);
    }

    #[test]
    fn test_in_memory_slashing_ledger_unjail() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000)]);

        // Jail and then unjail
        ledger.jail_validator(1, 100).unwrap();
        assert!(ledger.is_jailed(1, 50));

        ledger.unjail_validator(1).unwrap();
        assert!(!ledger.is_jailed(1, 50));
    }

    #[test]
    fn test_in_memory_slashing_ledger_records() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![
            (1, 100_000),
            (2, 200_000),
        ]);

        // Store some slashing records
        let record1 = SlashingRecord {
            validator_id: 1,
            offense_kind: "O1_double_sign".to_string(),
            slashed_amount: 7_500,
            jailed: true,
            jailed_until_epoch: Some(10),
            height: 1000,
            view: 100,
            epoch: 5,
        };
        let record2 = SlashingRecord {
            validator_id: 2,
            offense_kind: "O2_invalid_proposer_sig".to_string(),
            slashed_amount: 10_000,
            jailed: false,
            jailed_until_epoch: None,
            height: 2000,
            view: 200,
            epoch: 6,
        };

        ledger.store_slashing_record(record1.clone()).unwrap();
        ledger.store_slashing_record(record2.clone()).unwrap();

        // Get records for validator 1
        let records_1 = ledger.get_slashing_records(1);
        assert_eq!(records_1.len(), 1);
        assert_eq!(records_1[0], record1);

        // Get all records
        let all_records = ledger.get_all_slashing_records();
        assert_eq!(all_records.len(), 2);
    }

    #[test]
    fn test_in_memory_slashing_ledger_validator_not_found() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000)]);

        // Try to slash unknown validator
        let result = ledger.slash_stake(999, 100);
        assert!(matches!(
            result,
            Err(SlashingLedgerError::ValidatorNotFound(999))
        ));

        // Try to jail unknown validator
        let result = ledger.jail_validator(999, 10);
        assert!(matches!(
            result,
            Err(SlashingLedgerError::ValidatorNotFound(999))
        ));
    }

    #[test]
    fn test_in_memory_slashing_ledger_zero_slash() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100)]);

        // Slash 0 bps should result in 0 slashed
        let slashed = ledger.slash_stake(1, 0).unwrap();
        assert_eq!(slashed, 0);
        assert_eq!(ledger.get_stake(1), Some(100));
    }

    #[test]
    fn test_in_memory_slashing_ledger_full_slash() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000)]);

        // Slash 100% (10000 bps)
        let slashed = ledger.slash_stake(1, 10000).unwrap();
        assert_eq!(slashed, 100_000);
        assert_eq!(ledger.get_stake(1), Some(0));

        // Subsequent slashes should return 0
        let slashed2 = ledger.slash_stake(1, 750).unwrap();
        assert_eq!(slashed2, 0);
    }
}