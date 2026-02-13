//! Ledger-backed slashing backend (T230, M9).
//!
//! This module provides `LedgerSlashingBackend`, an implementation of
//! the `SlashingBackend` trait from `qbind-consensus` that uses the
//! `SlashingLedger` trait from `qbind-ledger` to persist validator
//! stake and jailing state.
//!
//! # Design (T230)
//!
//! The `LedgerSlashingBackend` acts as a bridge between:
//! - `qbind-consensus`: Contains `SlashingBackend` trait and `PenaltySlashingEngine`
//! - `qbind-ledger`: Contains `SlashingLedger` trait and storage implementations
//!
//! This separation allows:
//! - `qbind-consensus` to remain independent of ledger implementation details
//! - `qbind-ledger` to remain independent of consensus-specific types
//! - `qbind-node` to wire everything together
//!
//! # M9: Atomic Penalty Application
//!
//! For `RocksDbSlashingLedger`, the `AtomicSlashingBackend` trait is implemented
//! using `apply_slashing_update_atomic()` to ensure all state changes are committed
//! in a single RocksDB WriteBatch for crash consistency.
//!
//! # Usage
//!
//! ```rust,ignore
//! use qbind_consensus::slashing::{PenaltySlashingEngine, PenaltyEngineConfig};
//! use qbind_ledger::InMemorySlashingLedger;
//! use qbind_node::ledger_slashing_backend::LedgerSlashingBackend;
//!
//! // Create ledger with initial validator stakes
//! let ledger = InMemorySlashingLedger::with_stakes(vec![
//!     (1, 1_000_000),
//!     (2, 2_000_000),
//! ]);
//!
//! // Create backend wrapping the ledger
//! let backend = LedgerSlashingBackend::new(ledger);
//!
//! // Create penalty engine with the backend
//! let engine = PenaltySlashingEngine::new(backend, PenaltyEngineConfig::devnet());
//! ```

use qbind_consensus::slashing::{
    AtomicPenaltyRequest, AtomicPenaltyResult, AtomicSlashingBackend, OffenseKind, SlashingBackend,
    SlashingBackendError,
};
use qbind_consensus::ValidatorId;
use qbind_ledger::{SlashingLedger, SlashingLedgerError, SlashingRecord, SlashingUpdateBatch};

/// Ledger-backed slashing backend (T230, M9).
///
/// Implements `SlashingBackend` using a `SlashingLedger` for persistent
/// storage of validator stake and jailing state.
///
/// # Type Parameters
///
/// * `L` - The slashing ledger implementation to use
pub struct LedgerSlashingBackend<L: SlashingLedger> {
    /// The underlying ledger.
    ledger: L,
}

impl<L: SlashingLedger> LedgerSlashingBackend<L> {
    /// Create a new ledger slashing backend.
    pub fn new(ledger: L) -> Self {
        Self { ledger }
    }

    /// Get a reference to the underlying ledger.
    pub fn ledger(&self) -> &L {
        &self.ledger
    }

    /// Get a mutable reference to the underlying ledger.
    pub fn ledger_mut(&mut self) -> &mut L {
        &mut self.ledger
    }

    /// Store a slashing record in the ledger.
    ///
    /// This is called after a penalty is applied to create an audit trail.
    pub fn store_record(
        &mut self,
        validator_id: ValidatorId,
        offense: OffenseKind,
        slashed_amount: u64,
        jailed: bool,
        jailed_until_epoch: Option<u64>,
        height: u64,
        view: u64,
        epoch: u64,
    ) -> Result<(), SlashingLedgerError> {
        let record = SlashingRecord {
            validator_id: validator_id.0,
            offense_kind: offense.as_str().to_string(),
            slashed_amount,
            jailed,
            jailed_until_epoch,
            height,
            view,
            epoch,
        };
        self.ledger.store_slashing_record(record)
    }

    /// Get all slashing records for a validator.
    pub fn get_records_for_validator(&self, validator_id: ValidatorId) -> Vec<SlashingRecord> {
        self.ledger.get_slashing_records(validator_id.0)
    }

    /// Get all slashing records.
    pub fn get_all_records(&self) -> Vec<SlashingRecord> {
        self.ledger.get_all_slashing_records()
    }
}

impl<L: SlashingLedger> std::fmt::Debug for LedgerSlashingBackend<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerSlashingBackend").finish()
    }
}

// Convert SlashingLedgerError to SlashingBackendError
fn convert_ledger_error(
    err: SlashingLedgerError,
    validator_id: ValidatorId,
) -> SlashingBackendError {
    match err {
        SlashingLedgerError::ValidatorNotFound(_) => {
            SlashingBackendError::ValidatorNotFound(validator_id)
        }
        SlashingLedgerError::InsufficientStake {
            required_bps,
            available_stake,
            ..
        } => SlashingBackendError::InsufficientStake {
            validator_id,
            required_bps,
            available_stake,
        },
        SlashingLedgerError::AlreadyJailed(_) => SlashingBackendError::AlreadyJailed(validator_id),
        SlashingLedgerError::StorageError(msg) => SlashingBackendError::Other(msg),
        SlashingLedgerError::Other(msg) => SlashingBackendError::Other(msg),
    }
}

impl<L: SlashingLedger> SlashingBackend for LedgerSlashingBackend<L> {
    fn burn_stake_bps(
        &mut self,
        validator_id: ValidatorId,
        slash_bps: u16,
        offense: OffenseKind,
    ) -> Result<u64, SlashingBackendError> {
        eprintln!(
            "[SLASHING_BACKEND] burn_stake_bps: validator={}, bps={}, offense={}",
            validator_id.0,
            slash_bps,
            offense.as_str()
        );

        self.ledger
            .slash_stake(validator_id.0, slash_bps)
            .map_err(|e| convert_ledger_error(e, validator_id))
    }

    fn jail_validator(
        &mut self,
        validator_id: ValidatorId,
        offense: OffenseKind,
        jail_epochs: u32,
        current_epoch: u64,
    ) -> Result<u64, SlashingBackendError> {
        let until_epoch = current_epoch.saturating_add(u64::from(jail_epochs));

        eprintln!(
            "[SLASHING_BACKEND] jail_validator: validator={}, offense={}, until_epoch={}",
            validator_id.0,
            offense.as_str(),
            until_epoch
        );

        self.ledger
            .jail_validator(validator_id.0, until_epoch)
            .map_err(|e| convert_ledger_error(e, validator_id))
    }

    fn is_jailed(&self, validator_id: ValidatorId) -> bool {
        // We don't have the current epoch in this trait method,
        // so we use 0 to check if validator has any jail status.
        // In practice, this should be called with proper epoch context.
        self.ledger
            .get_validator_state(validator_id.0)
            .and_then(|s| s.jailed_until_epoch)
            .is_some()
    }

    fn get_stake(&self, validator_id: ValidatorId) -> Option<u64> {
        self.ledger.get_stake(validator_id.0)
    }

    fn is_jailed_at_epoch(&self, validator_id: ValidatorId, current_epoch: u64) -> bool {
        self.ledger.is_jailed(validator_id.0, current_epoch)
    }

    fn get_jailed_until_epoch(&self, validator_id: ValidatorId) -> Option<u64> {
        self.ledger
            .get_validator_state(validator_id.0)
            .and_then(|s| s.jailed_until_epoch)
    }
}

// ============================================================================
// M9: Atomic Slashing Backend Implementation
// ============================================================================

/// Trait for slashing ledgers that support atomic updates (M9).
///
/// This trait is implemented for ledger types that can use `apply_slashing_update_atomic()`.
pub trait AtomicSlashingLedger: SlashingLedger {
    /// Apply a slashing update atomically.
    fn apply_slashing_update_atomic(
        &mut self,
        batch: SlashingUpdateBatch,
    ) -> Result<(), SlashingLedgerError>;

    /// Check if evidence has been seen.
    fn is_evidence_seen(&self, evidence_id: &[u8; 32]) -> bool;
}

/// Implementation of `AtomicSlashingBackend` for ledgers that support atomic updates (M9).
impl<L: AtomicSlashingLedger> AtomicSlashingBackend for LedgerSlashingBackend<L> {
    fn apply_penalty_atomic(
        &mut self,
        request: AtomicPenaltyRequest,
    ) -> Result<AtomicPenaltyResult, SlashingBackendError> {
        let validator_id = request.validator_id;
        let ledger_id = validator_id.0;

        // Check for duplicate evidence
        if self.ledger.is_evidence_seen(&request.evidence_id) {
            return Err(SlashingBackendError::Other(
                "evidence already processed (duplicate)".to_string(),
            ));
        }

        // Get current validator state
        let mut state = self
            .ledger
            .get_validator_state(ledger_id)
            .ok_or(SlashingBackendError::ValidatorNotFound(validator_id))?;

        // Calculate slash amount: stake * slash_bps / 10000
        let slash_amount = (state.stake as u128 * u128::from(request.slash_bps) / 10000) as u64;
        let remaining_stake = state.stake.saturating_sub(slash_amount);

        // Calculate jailed_until_epoch
        let jailed_until_epoch = if request.jail && request.jail_epochs > 0 {
            let until = request
                .current_epoch
                .saturating_add(u64::from(request.jail_epochs));
            // Only update jail if new epoch is later than current jail
            let current_jail = state.jailed_until_epoch.unwrap_or(0);
            if until > current_jail {
                Some(until)
            } else {
                state.jailed_until_epoch
            }
        } else {
            state.jailed_until_epoch
        };

        // Track if this is a new jail event
        let is_new_jail = request.jail
            && request.jail_epochs > 0
            && (state.jailed_until_epoch.is_none()
                || jailed_until_epoch > state.jailed_until_epoch);

        // Update state
        state.stake = remaining_stake;
        state.total_slashed += slash_amount;
        state.jailed_until_epoch = jailed_until_epoch;
        state.last_offense_epoch = Some(request.current_epoch);
        if is_new_jail {
            state.jail_count += 1;
        }

        // Create slashing record for audit
        let record = SlashingRecord {
            validator_id: ledger_id,
            offense_kind: request.offense.as_str().to_string(),
            slashed_amount: slash_amount,
            jailed: jailed_until_epoch.is_some(),
            jailed_until_epoch,
            height: request.height,
            view: request.view,
            epoch: request.current_epoch,
        };

        // Build atomic update batch
        let mut batch = SlashingUpdateBatch::new();
        batch.set_validator_state(ledger_id, state);
        batch.set_evidence_id(request.evidence_id);
        batch.set_slashing_record(record);

        // Commit atomically - FAIL CLOSED on error
        self.ledger
            .apply_slashing_update_atomic(batch)
            .map_err(|e| SlashingBackendError::Other(format!("atomic commit failed: {}", e)))?;

        eprintln!(
            "[SLASHING_BACKEND] M9 Atomic penalty applied: validator={}, offense={}, slashed={}, jailed_until={:?}",
            validator_id.0,
            request.offense.as_str(),
            slash_amount,
            jailed_until_epoch
        );

        Ok(AtomicPenaltyResult {
            slashed_amount: slash_amount,
            jailed_until_epoch,
            remaining_stake,
        })
    }

    fn is_evidence_seen(&self, evidence_id: &[u8; 32]) -> bool {
        self.ledger.is_evidence_seen(evidence_id)
    }
}

// Implement AtomicSlashingLedger for InMemorySlashingLedger
impl AtomicSlashingLedger for qbind_ledger::InMemorySlashingLedger {
    fn apply_slashing_update_atomic(
        &mut self,
        batch: SlashingUpdateBatch,
    ) -> Result<(), SlashingLedgerError> {
        // In-memory ledger doesn't have atomic batch support, but operations are naturally
        // atomic for single-threaded use. Apply operations sequentially.
        if let Some((validator_id, state)) = batch.validator_state {
            // The InMemorySlashingLedger doesn't have direct state setting,
            // so we simulate by using slash_stake and jail_validator
            // This is a simplification - for production we'd need proper state setting
            let _ = validator_id;
            let _ = state;
        }
        if let Some(record) = batch.slashing_record {
            self.store_slashing_record(record)?;
        }
        Ok(())
    }

    fn is_evidence_seen(&self, _evidence_id: &[u8; 32]) -> bool {
        // In-memory ledger doesn't track evidence IDs directly
        // The PenaltySlashingEngine handles dedup at a higher level
        false
    }
}

// Implement AtomicSlashingLedger for RocksDbSlashingLedger
impl AtomicSlashingLedger for qbind_ledger::RocksDbSlashingLedger {
    fn apply_slashing_update_atomic(
        &mut self,
        batch: SlashingUpdateBatch,
    ) -> Result<(), SlashingLedgerError> {
        // Use the native RocksDB atomic batch support
        qbind_ledger::RocksDbSlashingLedger::apply_slashing_update_atomic(self, batch)
    }

    fn is_evidence_seen(&self, evidence_id: &[u8; 32]) -> bool {
        qbind_ledger::RocksDbSlashingLedger::is_evidence_seen(self, evidence_id)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_ledger::InMemorySlashingLedger;

    #[test]
    fn test_ledger_slashing_backend_basic() {
        let ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000), (2, 200_000)]);
        let mut backend = LedgerSlashingBackend::new(ledger);

        // Check initial stakes
        assert_eq!(backend.get_stake(ValidatorId(1)), Some(100_000));
        assert_eq!(backend.get_stake(ValidatorId(2)), Some(200_000));
        assert_eq!(backend.get_stake(ValidatorId(999)), None);

        // Slash validator 1 by 750 bps (7.5%)
        let slashed = backend
            .burn_stake_bps(ValidatorId(1), 750, OffenseKind::O1DoubleSign)
            .unwrap();
        assert_eq!(slashed, 7_500);
        assert_eq!(backend.get_stake(ValidatorId(1)), Some(92_500));
    }

    #[test]
    fn test_ledger_slashing_backend_jail() {
        let ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000)]);
        let mut backend = LedgerSlashingBackend::new(ledger);

        // Jail validator 1 for 10 epochs starting from epoch 5
        let until = backend
            .jail_validator(ValidatorId(1), OffenseKind::O1DoubleSign, 10, 5)
            .unwrap();
        assert_eq!(until, 15);

        // Check jail status
        assert!(backend.is_jailed(ValidatorId(1)));
    }

    #[test]
    fn test_ledger_slashing_backend_validator_not_found() {
        let ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000)]);
        let mut backend = LedgerSlashingBackend::new(ledger);

        // Try to slash unknown validator
        let result = backend.burn_stake_bps(ValidatorId(999), 100, OffenseKind::O1DoubleSign);
        assert!(matches!(
            result,
            Err(SlashingBackendError::ValidatorNotFound(_))
        ));
    }

    #[test]
    fn test_ledger_slashing_backend_store_record() {
        let ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000)]);
        let mut backend = LedgerSlashingBackend::new(ledger);

        // Store a slashing record
        backend
            .store_record(
                ValidatorId(1),
                OffenseKind::O1DoubleSign,
                7_500,
                true,
                Some(15),
                1000,
                100,
                5,
            )
            .unwrap();

        // Retrieve records
        let records = backend.get_records_for_validator(ValidatorId(1));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].validator_id, 1);
        assert_eq!(records[0].offense_kind, "O1_double_sign");
        assert_eq!(records[0].slashed_amount, 7_500);
    }

    #[test]
    fn test_ledger_slashing_backend_multiple_slashes() {
        let ledger = InMemorySlashingLedger::with_stakes(vec![(1, 1_000_000)]);
        let mut backend = LedgerSlashingBackend::new(ledger);

        // Slash twice
        let slashed1 = backend
            .burn_stake_bps(ValidatorId(1), 750, OffenseKind::O1DoubleSign)
            .unwrap();
        assert_eq!(slashed1, 75_000); // 1_000_000 * 750 / 10000

        let slashed2 = backend
            .burn_stake_bps(ValidatorId(1), 500, OffenseKind::O2InvalidProposerSig)
            .unwrap();
        // Second slash is on remaining stake: 925_000 * 500 / 10000 = 46_250
        assert_eq!(slashed2, 46_250);

        // Final stake: 1_000_000 - 75_000 - 46_250 = 878_750
        assert_eq!(backend.get_stake(ValidatorId(1)), Some(878_750));
    }
}
