//! Governance-related state types for qbind.

use crate::primitives::{AccountId, Hash32, MainnetStatus};
use crate::state_suite::SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyCouncilKeyAccount {
    pub version: u8,
    pub suite_id: u8,
    pub reserved0: [u8; 2],
    pub pk_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyCouncilKeyset {
    pub version: u8,
    pub threshold: u8,
    pub member_count: u8,
    pub reserved0: u8,
    pub members: Vec<AccountId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchChecklist {
    pub version: u8,
    pub reserved0: [u8; 3],
    pub devnet_ok: bool,
    pub testnet_ok: bool,
    pub perf_ok: bool,
    pub adversarial_ok: bool,
    pub crypto_audit_ok: bool,
    pub proto_audit_ok: bool,
    pub spec_ok: bool,
    pub reserved1: u8,
    pub devnet_report_hash: Hash32,
    pub testnet_report_hash: Hash32,
    pub perf_report_hash: Hash32,
    pub adversarial_report_hash: Hash32,
    pub crypto_audit_hash: Hash32,
    pub proto_audit_hash: Hash32,
    pub spec_hash: Hash32,
}

/// M14: Slashing Penalty Schedule
///
/// Defines the penalty parameters for all offense classes (O1-O5).
/// These parameters are read from governance state and applied by the
/// PenaltySlashingEngine. Updates activate at epoch boundaries.
///
/// | Offense | Description                      | Default Slash (bps) | Default Jail (epochs) |
/// |---------|----------------------------------|--------------------|-----------------------|
/// | O1      | Double-signing                   | 750 (7.5%)         | 10                    |
/// | O2      | Invalid proposer signature       | 500 (5%)           | 5                     |
/// | O3      | Invalid vote (lazy/malicious)    | 300 (3%)           | 3                     |
/// | O4      | Censorship (proposal withholding)| 200 (2%)           | 2                     |
/// | O5      | Availability failure             | 100 (1%)           | 1                     |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingPenaltySchedule {
    /// Version of this schedule (for future compatibility).
    pub version: u8,
    /// Reserved byte for alignment.
    pub reserved0: u8,

    // O1: Double-signing (critical offense)
    /// Slash percentage for O1 in basis points (1 bps = 0.01%). Default: 750 (7.5%)
    pub slash_bps_o1: u16,
    /// Number of epochs to jail for O1. Default: 10
    pub jail_epochs_o1: u32,

    // O2: Invalid proposer signature (high severity)
    /// Slash percentage for O2 in basis points. Default: 500 (5%)
    pub slash_bps_o2: u16,
    /// Number of epochs to jail for O2. Default: 5
    pub jail_epochs_o2: u32,

    // O3: Invalid vote (medium severity)
    /// Slash percentage for O3 in basis points. Default: 300 (3%)
    pub slash_bps_o3: u16,
    /// Number of epochs to jail for O3. Default: 3
    pub jail_epochs_o3: u32,

    // O4: Censorship (medium-high severity)
    /// Slash percentage for O4 in basis points. Default: 200 (2%)
    pub slash_bps_o4: u16,
    /// Number of epochs to jail for O4. Default: 2
    pub jail_epochs_o4: u32,

    // O5: Availability failure (medium severity)
    /// Slash percentage for O5 in basis points. Default: 100 (1%)
    pub slash_bps_o5: u16,
    /// Number of epochs to jail for O5. Default: 1
    pub jail_epochs_o5: u32,

    /// Epoch at which this schedule activates.
    /// Schedule changes are applied at epoch boundaries.
    /// A value of 0 means "active from genesis".
    pub activation_epoch: u64,
}

impl Default for SlashingPenaltySchedule {
    fn default() -> Self {
        Self {
            version: 1,
            reserved0: 0,
            slash_bps_o1: 750,    // 7.5%
            jail_epochs_o1: 10,
            slash_bps_o2: 500,    // 5%
            jail_epochs_o2: 5,
            slash_bps_o3: 300,    // 3%
            jail_epochs_o3: 3,
            slash_bps_o4: 200,    // 2%
            jail_epochs_o4: 2,
            slash_bps_o5: 100,    // 1%
            jail_epochs_o5: 1,
            activation_epoch: 0, // Active from genesis
        }
    }
}

impl SlashingPenaltySchedule {
    /// Check if this schedule is active at the given epoch.
    pub fn is_active_at_epoch(&self, epoch: u64) -> bool {
        epoch >= self.activation_epoch
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamRegistry {
    pub version: u8,
    pub mainnet_status: MainnetStatus,
    pub reserved0: [u8; 6],
    // slashing parameters (basis points out of 10_000)
    // Note: These are legacy fields for backward compatibility.
    // M14: Use slashing_schedule for production penalty parameters.
    pub slash_bps_prevote: u16,
    pub slash_bps_precommit: u16,
    pub reporter_reward_bps: u16,
    pub reserved1: u16,
    // M2: Minimum stake requirement for validator registration and eligibility
    // Validators must have at least this much stake (in microQBIND) to:
    // 1. Register as a validator
    // 2. Remain eligible for the validator set at epoch boundaries
    pub min_validator_stake: u64,

    // M14: Slashing penalty schedule (governance-controlled).
    // This schedule contains all O1-O5 penalty parameters and is
    // the canonical source for the PenaltySlashingEngine.
    // If None, TestNet/MainNet must fail-closed; DevNet may use defaults.
    pub slashing_schedule: Option<SlashingPenaltySchedule>,
}

/// Canonical SafetyCouncilKeyset for qbind v1 genesis.
///
/// We model a 5-of-7 council over a single Cat-5 lattice suite (ML-DSA-87).
/// The member AccountIds reference `SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS` from
/// `qbind_system::governance_program`.
pub fn genesis_safety_council_keyset(member_ids: &[AccountId; 7]) -> SafetyCouncilKeyset {
    SafetyCouncilKeyset {
        version: 1,
        threshold: 5,
        member_count: 7,
        reserved0: 0,
        members: member_ids.to_vec(),
    }
}

/// Canonical SafetyCouncilKeyAccount entries for qbind v1 genesis.
///
/// Returns 7 SafetyCouncilKeyAccount entries, each using the Cat-5 lattice
/// suite (ML-DSA-87) and placeholder public key bytes. In production,
/// operators should replace these with real keys.
pub fn genesis_safety_council_accounts() -> Vec<SafetyCouncilKeyAccount> {
    (0..7)
        .map(|i| {
            // Distinct placeholder keys for each member to avoid accidental reuse.
            // Byte pattern: 0xD1 for member 0, 0xD2 for member 1, etc.
            let pk_byte = 0xD1u8 + i;
            SafetyCouncilKeyAccount {
                version: 1,
                suite_id: SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024,
                reserved0: [0u8; 2],
                pk_bytes: vec![pk_byte; 32],
            }
        })
        .collect()
}