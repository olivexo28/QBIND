//! M13 Economic State Unification Restart Safety Tests
//!
//! This test file validates that after restart, the canonical economic state
//! (stake, jail, eligibility) is preserved correctly and deterministically.
//!
//! # M13 Canonical Economic State Unification
//!
//! Per M13, `ValidatorRecord` is the single source of truth for:
//! - `stake`: Canonical stake (reduced by slashing)
//! - `jailed_until_epoch`: Canonical jail expiration
//!
//! The slashing ledger (`ValidatorSlashingState`) mirrors these values but
//! is NOT authoritative for eligibility decisions.
//!
//! # Test Coverage
//!
//! A) Slash O1 → restart → stake reduced in ledger
//! B) Jail O3 → restart → excluded from validator set
//! C) Multiple offenses → restart → consistent state
//! D) Crash during slashing batch → no partial economic state
//! E) Deterministic eligibility across two nodes from same DB

use tempfile::TempDir;

use qbind_consensus::slashing::{AtomicPenaltyRequest, AtomicSlashingBackend, OffenseKind, SlashingBackend};
use qbind_consensus::validator_set::{
    build_validator_set_with_stake_and_jail_filter, ValidatorCandidateWithJailStatus,
};
use qbind_consensus::ValidatorId;
use qbind_ledger::{
    RocksDbSlashingLedger, SlashingLedger, SlashingRecord, SlashingUpdateBatch,
    ValidatorSlashingState,
};
use qbind_node::ledger_slashing_backend::LedgerSlashingBackend;
use qbind_types::{ValidatorRecord, ValidatorStatus};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a sample ValidatorRecord for testing.
///
/// Note: The `status` field is independent of `jailed_until_epoch`. In the real
/// protocol, a validator's status transitions from Active to Jailed when jailed,
/// and should transition back to Active after unjailing. The `is_eligible_at_epoch`
/// method checks both `status == Active` AND `!is_jailed_at_epoch()`.
fn make_validator_record(stake: u64, jailed_until_epoch: Option<u64>, status: ValidatorStatus) -> ValidatorRecord {
    ValidatorRecord {
        version: 1,
        status,
        reserved0: [0; 2],
        owner_keyset_id: [0x01; 32],
        consensus_suite_id: 100, // ML-DSA-44
        reserved1: [0; 3],
        consensus_pk: vec![0xAA; 64],
        network_suite_id: 1,
        reserved2: [0; 3],
        network_pk: vec![0xBB; 32],
        stake,
        last_slash_height: 0,
        jailed_until_epoch,
        ext_bytes: Vec::new(),
    }
}

/// Generate a unique evidence ID for a given validator and offense.
fn make_evidence_id(validator_id: u64, offense_idx: u32) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"m13_test_evidence:");
    input.extend_from_slice(&validator_id.to_be_bytes());
    input.extend_from_slice(&offense_idx.to_be_bytes());
    qbind_hash::sha3_256(&input)
}

// ============================================================================
// A) Slash O1 → restart → stake reduced in ledger
// ============================================================================

#[test]
fn test_a1_slash_o1_persists_stake_reduction_across_restart() {
    let temp_dir = TempDir::new().unwrap();
    let initial_stake: u64 = 1_000_000;
    let slash_bps: u16 = 750; // 7.5%
    let expected_slash = (initial_stake as u128 * slash_bps as u128 / 10000) as u64; // 75_000
    let expected_remaining = initial_stake - expected_slash; // 925_000

    // Session 1: Initialize and apply O1 slash
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        ledger.initialize_validator(1, initial_stake).unwrap();

        let mut backend = LedgerSlashingBackend::new(ledger);
        let evidence_id = make_evidence_id(1, 1);

        let request = AtomicPenaltyRequest {
            validator_id: ValidatorId(1),
            slash_bps,
            jail: true,
            jail_epochs: 10,
            current_epoch: 5,
            offense: OffenseKind::O1DoubleSign,
            evidence_id,
            height: 100,
            view: 0,
        };

        let result = backend.apply_penalty_atomic(request).unwrap();
        assert_eq!(result.slashed_amount, expected_slash);
        assert_eq!(result.remaining_stake, expected_remaining);

        // Verify in-session
        let stake = backend.get_stake(ValidatorId(1));
        assert_eq!(stake, Some(expected_remaining));
    }

    // Session 2: Reopen and verify stake is still reduced (simulates restart)
    {
        let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        let backend = LedgerSlashingBackend::new(ledger);

        let stake = backend.get_stake(ValidatorId(1));
        assert_eq!(
            stake,
            Some(expected_remaining),
            "Stake should remain reduced after restart"
        );

        // Also verify the jailed_until_epoch
        let jailed_until = backend.get_jailed_until_epoch(ValidatorId(1));
        assert_eq!(jailed_until, Some(15), "Jail should persist after restart");
    }
}

#[test]
fn test_a2_slash_preserves_validator_record_stake_semantics() {
    // This test verifies that ValidatorRecord.stake would be correctly
    // updated if we sync it with the slashing ledger stake.

    let initial_stake: u64 = 1_000_000;
    let jailed_until: Option<u64> = Some(15);

    // Create a ValidatorRecord representing post-slash state
    // Status is Active - the jail is controlled by jailed_until_epoch, not status.
    // In a real scenario, the validator would be re-activated after unjail.
    let record = make_validator_record(initial_stake - 75_000, jailed_until, ValidatorStatus::Active);

    // Verify the M13 canonical eligibility checks
    // During jail (before epoch 15), not eligible due to jailed_until_epoch check
    assert!(!record.is_eligible_at_epoch(10), "Jailed validator not eligible");
    // After jail expires (epoch 15+), eligible again
    assert!(
        record.is_eligible_at_epoch(15),
        "Validator eligible after jail expires"
    );

    // Verify canonical jail check
    assert!(record.is_jailed_at_epoch(10), "Should be jailed at epoch 10");
    assert!(record.is_jailed_at_epoch(14), "Should be jailed at epoch 14");
    assert!(!record.is_jailed_at_epoch(15), "Should be unjailed at epoch 15");
}

// ============================================================================
// B) Jail O3 → restart → excluded from validator set
// ============================================================================

#[test]
fn test_b1_jail_excludes_validator_from_set_after_restart() {
    let temp_dir = TempDir::new().unwrap();
    let initial_stake: u64 = 1_000_000;
    let _jail_until_epoch: u64 = 15;

    // Session 1: Initialize and jail validator
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        ledger.initialize_validator(1, initial_stake).unwrap();
        ledger.initialize_validator(2, initial_stake).unwrap();
        ledger.initialize_validator(3, initial_stake).unwrap();

        let mut backend = LedgerSlashingBackend::new(ledger);
        let evidence_id = make_evidence_id(2, 1);

        // Jail validator 2 (O3 - Invalid Vote)
        let request = AtomicPenaltyRequest {
            validator_id: ValidatorId(2),
            slash_bps: 300, // 3%
            jail: true,
            jail_epochs: 10, // Until epoch 15
            current_epoch: 5,
            offense: OffenseKind::O3aLazyVoteSingle,
            evidence_id,
            height: 100,
            view: 0,
        };

        backend.apply_penalty_atomic(request).unwrap();
    }

    // Session 2: Reopen and verify jail exclusion
    {
        let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        let backend = LedgerSlashingBackend::new(ledger);

        // Build validator set at epoch 10 (validator 2 still jailed)
        let candidates = vec![
            ValidatorCandidateWithJailStatus::new(
                ValidatorId::new(1),
                backend.get_stake(ValidatorId(1)).unwrap(),
                1,
                backend.get_jailed_until_epoch(ValidatorId(1)),
            ),
            ValidatorCandidateWithJailStatus::new(
                ValidatorId::new(2),
                backend.get_stake(ValidatorId(2)).unwrap(),
                1,
                backend.get_jailed_until_epoch(ValidatorId(2)),
            ),
            ValidatorCandidateWithJailStatus::new(
                ValidatorId::new(3),
                backend.get_stake(ValidatorId(3)).unwrap(),
                1,
                backend.get_jailed_until_epoch(ValidatorId(3)),
            ),
        ];

        // At epoch 10, validator 2 should be excluded (jailed until 15)
        let result = build_validator_set_with_stake_and_jail_filter(candidates.clone(), 0, 10).unwrap();
        assert_eq!(result.validator_set.len(), 2);
        assert_eq!(result.excluded_jailed.len(), 1);
        assert_eq!(result.excluded_jailed[0].validator_id, ValidatorId::new(2));

        // At epoch 15, validator 2 should be included (jail expired)
        let result2 = build_validator_set_with_stake_and_jail_filter(candidates, 0, 15).unwrap();
        assert_eq!(result2.validator_set.len(), 3);
        assert_eq!(result2.excluded_jailed.len(), 0);
    }
}

#[test]
fn test_b2_jailed_validator_not_eligible_via_validator_record() {
    let temp_dir = TempDir::new().unwrap();

    // Session 1: Jail validator
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        ledger.initialize_validator(1, 1_000_000).unwrap();

        let mut backend = LedgerSlashingBackend::new(ledger);
        let evidence_id = make_evidence_id(1, 1);

        let request = AtomicPenaltyRequest {
            validator_id: ValidatorId(1),
            slash_bps: 300,
            jail: true,
            jail_epochs: 10,
            current_epoch: 5,
            offense: OffenseKind::O3aLazyVoteSingle,
            evidence_id,
            height: 100,
            view: 0,
        };

        backend.apply_penalty_atomic(request).unwrap();
    }

    // Session 2: Verify ValidatorRecord eligibility predicate
    {
        let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        let backend = LedgerSlashingBackend::new(ledger);

        let state = backend.ledger().get_validator_state(1).unwrap();

        // Create a ValidatorRecord with the canonical state
        // Status remains Active - jail is enforced via jailed_until_epoch
        let record = make_validator_record(state.stake, state.jailed_until_epoch, ValidatorStatus::Active);

        assert!(!record.is_eligible_at_epoch(10));
        assert!(!record.is_eligible_at_epoch(14));
        assert!(record.is_eligible_at_epoch(15));
    }
}

// ============================================================================
// C) Multiple offenses → restart → consistent state
// ============================================================================

#[test]
fn test_c1_multiple_offenses_accumulate_correctly_across_restart() {
    let temp_dir = TempDir::new().unwrap();
    let initial_stake: u64 = 1_000_000;

    // Session 1: Apply two different offenses
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        ledger.initialize_validator(1, initial_stake).unwrap();

        let mut backend = LedgerSlashingBackend::new(ledger);

        // First offense: O1 (7.5% slash)
        let request1 = AtomicPenaltyRequest {
            validator_id: ValidatorId(1),
            slash_bps: 750,
            jail: true,
            jail_epochs: 10,
            current_epoch: 5,
            offense: OffenseKind::O1DoubleSign,
            evidence_id: make_evidence_id(1, 1),
            height: 100,
            view: 0,
        };

        let result1 = backend.apply_penalty_atomic(request1).unwrap();
        // 1_000_000 * 750 / 10000 = 75_000
        assert_eq!(result1.slashed_amount, 75_000);
        assert_eq!(result1.remaining_stake, 925_000);

        // Second offense: O2 (5% slash on remaining)
        let request2 = AtomicPenaltyRequest {
            validator_id: ValidatorId(1),
            slash_bps: 500,
            jail: true,
            jail_epochs: 5, // This won't extend jail since O1 jail is longer
            current_epoch: 6,
            offense: OffenseKind::O2InvalidProposerSig,
            evidence_id: make_evidence_id(1, 2),
            height: 101,
            view: 0,
        };

        let result2 = backend.apply_penalty_atomic(request2).unwrap();
        // 925_000 * 500 / 10000 = 46_250
        assert_eq!(result2.slashed_amount, 46_250);
        assert_eq!(result2.remaining_stake, 878_750);
    }

    // Session 2: Verify accumulated state
    {
        let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        let backend = LedgerSlashingBackend::new(ledger);

        let stake = backend.get_stake(ValidatorId(1));
        assert_eq!(stake, Some(878_750), "Stake should reflect both slashes");

        let jailed_until = backend.get_jailed_until_epoch(ValidatorId(1));
        assert_eq!(jailed_until, Some(15), "Jail should be from longer sentence (O1)");

        // Verify total slashed via state
        let state = backend.ledger().get_validator_state(1).unwrap();
        assert_eq!(state.total_slashed, 121_250); // 75_000 + 46_250
        assert_eq!(state.jail_count, 1); // O2 jail didn't extend, so only 1 jail event counted
    }
}

#[test]
fn test_c2_multiple_validators_slashed_independently() {
    let temp_dir = TempDir::new().unwrap();

    // Session 1: Slash multiple validators
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        ledger.initialize_validator(1, 1_000_000).unwrap();
        ledger.initialize_validator(2, 2_000_000).unwrap();
        ledger.initialize_validator(3, 3_000_000).unwrap();

        let mut backend = LedgerSlashingBackend::new(ledger);

        // Slash validator 1
        let request1 = AtomicPenaltyRequest {
            validator_id: ValidatorId(1),
            slash_bps: 750,
            jail: true,
            jail_epochs: 10,
            current_epoch: 5,
            offense: OffenseKind::O1DoubleSign,
            evidence_id: make_evidence_id(1, 1),
            height: 100,
            view: 0,
        };
        backend.apply_penalty_atomic(request1).unwrap();

        // Slash validator 3
        let request3 = AtomicPenaltyRequest {
            validator_id: ValidatorId(3),
            slash_bps: 300,
            jail: true,
            jail_epochs: 3,
            current_epoch: 5,
            offense: OffenseKind::O3aLazyVoteSingle,
            evidence_id: make_evidence_id(3, 1),
            height: 100,
            view: 0,
        };
        backend.apply_penalty_atomic(request3).unwrap();
    }

    // Session 2: Verify each validator's state
    {
        let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        let backend = LedgerSlashingBackend::new(ledger);

        // Validator 1: slashed 7.5%
        assert_eq!(backend.get_stake(ValidatorId(1)), Some(925_000));
        assert_eq!(backend.get_jailed_until_epoch(ValidatorId(1)), Some(15));

        // Validator 2: untouched
        assert_eq!(backend.get_stake(ValidatorId(2)), Some(2_000_000));
        assert_eq!(backend.get_jailed_until_epoch(ValidatorId(2)), None);

        // Validator 3: slashed 3%
        assert_eq!(backend.get_stake(ValidatorId(3)), Some(2_910_000)); // 3_000_000 - 90_000
        assert_eq!(backend.get_jailed_until_epoch(ValidatorId(3)), Some(8)); // 5 + 3
    }
}

// ============================================================================
// D) Crash during slashing batch → no partial economic state
// ============================================================================

// Note: The write failure injection tests (test_d1, test_d2) are located in
// qbind_ledger/src/slashing_ledger.rs as they require access to #[cfg(test)]
// methods like set_inject_write_failure().
//
// These tests verify that atomic batch operations truly are atomic by testing
// that normal operations work correctly, and relying on the lower-level tests
// for failure injection.

#[test]
fn test_d1_atomic_batch_all_or_nothing() {
    // This test verifies that a successful atomic batch applies all changes together
    let temp_dir = TempDir::new().unwrap();
    let initial_stake: u64 = 1_000_000;
    let evidence_id = make_evidence_id(1, 1);

    // Session 1: Apply atomic batch
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        ledger.initialize_validator(1, initial_stake).unwrap();

        // Build atomic batch with all three operations
        let updated_state = ValidatorSlashingState {
            stake: 925_000,
            jailed_until_epoch: Some(15),
            total_slashed: 75_000,
            jail_count: 1,
            last_offense_epoch: Some(5),
        };

        let record = SlashingRecord {
            validator_id: 1,
            offense_kind: "O1_double_sign".to_string(),
            slashed_amount: 75_000,
            jailed: true,
            jailed_until_epoch: Some(15),
            height: 100,
            view: 0,
            epoch: 5,
        };

        let mut batch = SlashingUpdateBatch::new();
        batch.set_validator_state(1, updated_state);
        batch.set_evidence_id(evidence_id);
        batch.set_slashing_record(record);

        // Apply the batch
        ledger.apply_slashing_update_atomic(batch).unwrap();
    }

    // Session 2: Verify ALL changes persisted together after restart
    {
        let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

        // State should be updated
        let state = ledger.get_validator_state(1).unwrap();
        assert_eq!(state.stake, 925_000, "Stake should be updated");
        assert_eq!(state.jailed_until_epoch, Some(15), "Jail should be updated");
        assert_eq!(state.total_slashed, 75_000, "Total slashed should be updated");

        // Evidence should be marked as seen
        assert!(
            ledger.is_evidence_seen(&evidence_id),
            "Evidence should be marked as seen"
        );

        // Slashing record should exist
        let records = ledger.get_slashing_records(1);
        assert_eq!(records.len(), 1, "Slashing record should exist");
        assert_eq!(records[0].slashed_amount, 75_000);
    }
}

#[test]
fn test_d2_duplicate_evidence_rejected_prevents_double_slash() {
    // This test verifies that duplicate evidence is rejected, which prevents
    // partial state corruption from re-applying penalties
    let temp_dir = TempDir::new().unwrap();
    let evidence_id = make_evidence_id(1, 1);

    // Session 1: Apply first penalty
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        ledger.initialize_validator(1, 1_000_000).unwrap();

        let mut backend = LedgerSlashingBackend::new(ledger);

        let request = AtomicPenaltyRequest {
            validator_id: ValidatorId(1),
            slash_bps: 750,
            jail: true,
            jail_epochs: 10,
            current_epoch: 5,
            offense: OffenseKind::O1DoubleSign,
            evidence_id,
            height: 100,
            view: 0,
        };

        let result = backend.apply_penalty_atomic(request);
        assert!(result.is_ok());
    }

    // Session 2: Attempt to re-apply same evidence after restart
    {
        let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        let mut backend = LedgerSlashingBackend::new(ledger);

        let request = AtomicPenaltyRequest {
            validator_id: ValidatorId(1),
            slash_bps: 750,
            jail: true,
            jail_epochs: 10,
            current_epoch: 5,
            offense: OffenseKind::O1DoubleSign,
            evidence_id, // Same evidence ID
            height: 100,
            view: 0,
        };

        let result = backend.apply_penalty_atomic(request);
        assert!(
            result.is_err(),
            "Duplicate evidence should be rejected after restart"
        );

        // Stake should still be 925_000 (not double-slashed)
        let stake = backend.get_stake(ValidatorId(1));
        assert_eq!(stake, Some(925_000), "Stake should not be double-slashed");
    }
}

// ============================================================================
// E) Deterministic eligibility across two nodes from same DB
// ============================================================================

#[test]
fn test_e1_deterministic_validator_set_from_same_state() {
    let temp_dir = TempDir::new().unwrap();

    // Session 1: Create state
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        ledger.initialize_validator(1, 1_000_000).unwrap();
        ledger.initialize_validator(2, 2_000_000).unwrap();
        ledger.initialize_validator(3, 3_000_000).unwrap();

        let mut backend = LedgerSlashingBackend::new(ledger);

        // Jail validator 2
        let request = AtomicPenaltyRequest {
            validator_id: ValidatorId(2),
            slash_bps: 300,
            jail: true,
            jail_epochs: 10,
            current_epoch: 5,
            offense: OffenseKind::O3aLazyVoteSingle,
            evidence_id: make_evidence_id(2, 1),
            height: 100,
            view: 0,
        };
        backend.apply_penalty_atomic(request).unwrap();
    }

    // Simulate determinism: Read state and derive validator set twice (sequentially)
    // In a real deployment, two different nodes would have their own DB copies
    // from replication. Here we simulate by re-opening the same DB twice sequentially.

    // First read
    let result_a = {
        let ledger_a = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        let backend_a = LedgerSlashingBackend::new(ledger_a);

        let candidates_a = vec![
            ValidatorCandidateWithJailStatus::new(
                ValidatorId::new(1),
                backend_a.get_stake(ValidatorId(1)).unwrap(),
                1,
                backend_a.get_jailed_until_epoch(ValidatorId(1)),
            ),
            ValidatorCandidateWithJailStatus::new(
                ValidatorId::new(2),
                backend_a.get_stake(ValidatorId(2)).unwrap(),
                1,
                backend_a.get_jailed_until_epoch(ValidatorId(2)),
            ),
            ValidatorCandidateWithJailStatus::new(
                ValidatorId::new(3),
                backend_a.get_stake(ValidatorId(3)).unwrap(),
                1,
                backend_a.get_jailed_until_epoch(ValidatorId(3)),
            ),
        ];

        build_validator_set_with_stake_and_jail_filter(candidates_a, 500_000, 10).unwrap()
    };

    // Second read (after closing first connection)
    let result_b = {
        let ledger_b = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        let backend_b = LedgerSlashingBackend::new(ledger_b);

        let candidates_b = vec![
            ValidatorCandidateWithJailStatus::new(
                ValidatorId::new(1),
                backend_b.get_stake(ValidatorId(1)).unwrap(),
                1,
                backend_b.get_jailed_until_epoch(ValidatorId(1)),
            ),
            ValidatorCandidateWithJailStatus::new(
                ValidatorId::new(2),
                backend_b.get_stake(ValidatorId(2)).unwrap(),
                1,
                backend_b.get_jailed_until_epoch(ValidatorId(2)),
            ),
            ValidatorCandidateWithJailStatus::new(
                ValidatorId::new(3),
                backend_b.get_stake(ValidatorId(3)).unwrap(),
                1,
                backend_b.get_jailed_until_epoch(ValidatorId(3)),
            ),
        ];

        build_validator_set_with_stake_and_jail_filter(candidates_b, 500_000, 10).unwrap()
    };

    // Verify deterministic results
    assert_eq!(
        result_a.validator_set.len(),
        result_b.validator_set.len(),
        "Both reads should derive same validator set size"
    );
    assert_eq!(
        result_a.excluded_jailed.len(),
        result_b.excluded_jailed.len(),
        "Both reads should have same excluded jailed count"
    );
    assert_eq!(
        result_a.excluded_low_stake.len(),
        result_b.excluded_low_stake.len(),
        "Both reads should have same excluded low stake count"
    );

    // Specifically check validator 2 is excluded on both
    assert_eq!(result_a.excluded_jailed.len(), 1);
    assert_eq!(result_a.excluded_jailed[0].validator_id, ValidatorId::new(2));
    assert_eq!(result_b.excluded_jailed[0].validator_id, ValidatorId::new(2));
}

#[test]
fn test_e2_quorum_voting_power_consistent_after_restart() {
    let temp_dir = TempDir::new().unwrap();

    // Session 1: Setup initial state with some validators slashed
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        // 4 validators with equal voting power
        ledger.initialize_validator(1, 1_000_000).unwrap();
        ledger.initialize_validator(2, 1_000_000).unwrap();
        ledger.initialize_validator(3, 1_000_000).unwrap();
        ledger.initialize_validator(4, 1_000_000).unwrap();

        let mut backend = LedgerSlashingBackend::new(ledger);

        // Jail validator 3
        let request = AtomicPenaltyRequest {
            validator_id: ValidatorId(3),
            slash_bps: 300,
            jail: true,
            jail_epochs: 10,
            current_epoch: 5,
            offense: OffenseKind::O3aLazyVoteSingle,
            evidence_id: make_evidence_id(3, 1),
            height: 100,
            view: 0,
        };
        backend.apply_penalty_atomic(request).unwrap();
    }

    // Session 2: Build validator set and check quorum
    {
        let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        let backend = LedgerSlashingBackend::new(ledger);

        let candidates = (1..=4)
            .map(|i| {
                ValidatorCandidateWithJailStatus::new(
                    ValidatorId::new(i),
                    backend.get_stake(ValidatorId(i)).unwrap(),
                    1, // uniform voting power
                    backend.get_jailed_until_epoch(ValidatorId(i)),
                )
            })
            .collect::<Vec<_>>();

        // At epoch 10, validator 3 is still jailed
        let result = build_validator_set_with_stake_and_jail_filter(candidates, 0, 10).unwrap();

        // Should have 3 validators (1, 2, 4) - validator 3 excluded
        assert_eq!(result.validator_set.len(), 3);

        // Total voting power = 3
        assert_eq!(result.validator_set.total_voting_power(), 3);

        // Quorum threshold should be ceil(2 * 3 / 3) = 2
        // (This tests that voting power calculation is consistent)
        assert_eq!(result.validator_set.two_thirds_vp(), 2);

        // Verify that the quorum calculation would work correctly
        // For 3 validators with VP=1 each, quorum requires >= 2 VP
        // Using has_quorum with validator IDs:
        assert!(
            !result.validator_set.has_quorum(vec![ValidatorId::new(1)]),
            "1 vote should not be quorum for 3 validators"
        );
        assert!(
            result.validator_set.has_quorum(vec![ValidatorId::new(1), ValidatorId::new(2)]),
            "2 votes should be quorum for 3 validators"
        );
        assert!(
            result.validator_set.has_quorum(vec![ValidatorId::new(1), ValidatorId::new(2), ValidatorId::new(4)]),
            "3 votes should be quorum for 3 validators"
        );
    }
}

// ============================================================================
// F) Additional M13 invariant tests
// ============================================================================

#[test]
fn test_f1_no_jailed_validator_enters_early() {
    let temp_dir = TempDir::new().unwrap();

    // Session 1: Jail validator
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        ledger.initialize_validator(1, 1_000_000).unwrap();

        let mut backend = LedgerSlashingBackend::new(ledger);

        let request = AtomicPenaltyRequest {
            validator_id: ValidatorId(1),
            slash_bps: 300,
            jail: true,
            jail_epochs: 10, // Jailed until epoch 15
            current_epoch: 5,
            offense: OffenseKind::O3aLazyVoteSingle,
            evidence_id: make_evidence_id(1, 1),
            height: 100,
            view: 0,
        };
        backend.apply_penalty_atomic(request).unwrap();
    }

    // Session 2: Verify validator cannot enter set early
    {
        let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        let backend = LedgerSlashingBackend::new(ledger);

        let jailed_until = backend.get_jailed_until_epoch(ValidatorId(1)).unwrap();

        // Test every epoch from 5 to 16
        for epoch in 5..=16 {
            let candidates = vec![ValidatorCandidateWithJailStatus::new(
                ValidatorId::new(1),
                backend.get_stake(ValidatorId(1)).unwrap(),
                1,
                Some(jailed_until),
            )];

            let result = build_validator_set_with_stake_and_jail_filter(candidates, 0, epoch);

            if epoch < jailed_until {
                // Should be excluded when still jailed
                match result {
                    Ok(r) => {
                        assert_eq!(
                            r.validator_set.len(),
                            0,
                            "Jailed validator should not be in set at epoch {}",
                            epoch
                        );
                    }
                    Err(_) => {
                        // Empty set error is expected when all validators excluded
                    }
                }
            } else {
                // Should be included after jail expires
                let r = result.expect("Should succeed after jail expires");
                assert_eq!(
                    r.validator_set.len(),
                    1,
                    "Validator should be in set at epoch {} (jail expired at {})",
                    epoch,
                    jailed_until
                );
            }
        }
    }
}

#[test]
fn test_f2_stake_discrepancy_prevented() {
    // This test verifies that the atomic update mechanism prevents stake discrepancies
    let temp_dir = TempDir::new().unwrap();
    let evidence_id = make_evidence_id(1, 1);

    // Session 1: Verify atomic batch updates both stake and evidence together
    {
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
        ledger.initialize_validator(1, 1_000_000).unwrap();

        let mut backend = LedgerSlashingBackend::new(ledger);

        let request = AtomicPenaltyRequest {
            validator_id: ValidatorId(1),
            slash_bps: 750,
            jail: true,
            jail_epochs: 10,
            current_epoch: 5,
            offense: OffenseKind::O1DoubleSign,
            evidence_id,
            height: 100,
            view: 0,
        };

        // Apply penalty - this is atomic
        backend.apply_penalty_atomic(request).unwrap();
    }

    // Session 2: Verify stake and evidence marker are both present (no partial state)
    {
        let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

        // Both stake reduction AND evidence marker should be present
        let state = ledger.get_validator_state(1).unwrap();
        assert_eq!(state.stake, 925_000, "Stake should be reduced");
        assert!(
            ledger.is_evidence_seen(&evidence_id),
            "Evidence marker should be present"
        );

        // If only one was present, it would indicate non-atomic behavior
    }
}
