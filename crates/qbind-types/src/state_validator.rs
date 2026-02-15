//! ValidatorRecord and SlashingEvent state types for qbind.
//!
//! # M13: Canonical Economic State Unification
//!
//! This module defines `ValidatorRecord` as the canonical source of truth for
//! validator economic state. Per M13, the following fields form the unified
//! economic state:
//!
//! - `stake`: Canonical stake amount (reduced by slashing)
//! - `jailed_until_epoch`: Canonical jail expiration (set by slashing)
//! - `status`: Validator status (may be `Jailed` when jailed_until_epoch is set)
//!
//! The slashing ledger (`ValidatorSlashingState`) maintains:
//! - Historical slashing records
//! - Offense counters and metadata
//! - `total_slashed` audit trail
//!
//! But NOT authoritative stake or jail state. Those derive from this record.

use crate::primitives::AccountId;

/// Validator status in the protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ValidatorStatus {
    Inactive = 0,
    Active = 1,
    Jailed = 2,
    Exiting = 3,
}

/// Canonical validator record stored in the ledger.
///
/// # M13: Canonical Economic State
///
/// This structure is the single source of truth for validator economic state:
/// - `stake`: Current stake amount (canonical, reduced by slashing)
/// - `jailed_until_epoch`: Epoch at which jail expires (canonical)
/// - `status`: Current validator status
///
/// Eligibility for consensus is determined by reading these fields directly.
/// No secondary or shadow stake tracking is allowed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorRecord {
    pub version: u8,
    pub status: ValidatorStatus,
    pub reserved0: [u8; 2],
    pub owner_keyset_id: AccountId,
    pub consensus_suite_id: u8,
    pub reserved1: [u8; 3],
    pub consensus_pk: Vec<u8>,
    pub network_suite_id: u8,
    pub reserved2: [u8; 3],
    pub network_pk: Vec<u8>,
    /// Canonical stake amount in microQBIND.
    ///
    /// This is the single source of truth for validator stake.
    /// Slashing penalties reduce this value atomically.
    pub stake: u64,
    pub last_slash_height: u64,
    /// Epoch at which the validator's jail term expires.
    ///
    /// - `None`: Validator is not jailed
    /// - `Some(epoch)`: Validator is jailed until `current_epoch >= epoch`
    ///
    /// # M13: Canonical Jail State
    ///
    /// This field is the single source of truth for jail status.
    /// The eligibility predicate must read this field directly.
    /// The `status` field should be `Jailed` when this is `Some(future_epoch)`.
    pub jailed_until_epoch: Option<u64>,
    pub ext_bytes: Vec<u8>,
}

impl ValidatorRecord {
    /// Check if the validator is jailed at the given epoch.
    ///
    /// # M13: Canonical Jail Check
    ///
    /// This method reads from `jailed_until_epoch` (canonical source).
    /// Returns `true` if `current_epoch < jailed_until_epoch`.
    pub fn is_jailed_at_epoch(&self, current_epoch: u64) -> bool {
        self.jailed_until_epoch
            .map(|until| current_epoch < until)
            .unwrap_or(false)
    }

    /// Check if the validator is eligible for consensus at the given epoch.
    ///
    /// # M13: Canonical Eligibility Predicate
    ///
    /// A validator is eligible if:
    /// - `status` is `Active`
    /// - Not jailed at the current epoch (`!is_jailed_at_epoch(current_epoch)`)
    /// - Has non-zero stake
    ///
    /// Stake threshold enforcement (min_validator_stake) is handled separately
    /// by the validator set builder.
    pub fn is_eligible_at_epoch(&self, current_epoch: u64) -> bool {
        self.status == ValidatorStatus::Active
            && !self.is_jailed_at_epoch(current_epoch)
            && self.stake > 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingEvent {
    pub version: u8,
    pub reserved0: [u8; 3],
    pub validator_id: AccountId,
    pub height: u64,
    pub round: u64,
    pub step: u8,
    pub reserved1: [u8; 7],
}