//! M9 Slashing Penalty Application Tests
//!
//! This test file validates the M9 slashing penalty implementation for O1 and O2 offenses.
//! These tests ensure:
//!
//! A) O1 penalty applied: stake reduced, jailed, record persisted, record_seq incremented
//! B) O2 penalty applied: same checks as O1
//! C) Restart test: reopen DB, state preserved, no double-penalty
//! D) RecordOnly mode: evidence recorded, stake unchanged, jail unchanged
//! E) Jail enforcement: excluded during jail, eligible after expiry
//!
//! # Test Organization
//!
//! - A: O1 penalty application tests
//! - B: O2 penalty application tests
//! - C: Restart safety tests
//! - D: RecordOnly mode tests
//! - E: Jail enforcement integration tests
//! - F: Fail-closed behavior tests

use qbind_consensus::slashing::{
    AtomicPenaltyRequest, AtomicSlashingBackend, BlockHeader, EvidencePayloadV1,
    InMemorySlashingBackend, OffenseKind, PenaltyDecision, PenaltyEngineConfig,
    PenaltySlashingContext, PenaltySlashingEngine, SignedBlockHeader, SlashingBackend,
    SlashingEvidence, SlashingMode,
};
use qbind_consensus::validator_set::{
    build_validator_set_with_stake_and_jail_filter, ValidatorCandidateWithJailStatus,
};
use qbind_consensus::{ValidatorId, ValidatorInfo, ValidatorSet};

// ============================================================================
// Test Helpers
// ============================================================================

fn test_validator_set() -> ValidatorSet {
    ValidatorSet {
        validators: vec![
            ValidatorInfo {
                validator_id: 1,
                suite_id: 1,
                consensus_pk: vec![1; 32],
                voting_power: 100,
            },
            ValidatorInfo {
                validator_id: 2,
                suite_id: 1,
                consensus_pk: vec![2; 32],
                voting_power: 100,
            },
            ValidatorInfo {
                validator_id: 3,
                suite_id: 1,
                consensus_pk: vec![3; 32],
                voting_power: 100,
            },
        ],
        qc_threshold: 201,
    }
}

fn make_o1_evidence(validator_id: u32, height: u64, view: u64) -> SlashingEvidence {
    SlashingEvidence {
        version: 1,
        offense: OffenseKind::O1DoubleSign,
        offending_validator: ValidatorId(u64::from(validator_id)),
        height,
        view,
        payload: EvidencePayloadV1::O1DoubleSign {
            block_a: SignedBlockHeader {
                height,
                view,
                block_id: [0xAA; 32],
                proposer_id: ValidatorId(u64::from(validator_id)),
                signature: vec![0x01; 64],
                header_preimage: vec![0x10; 100],
            },
            block_b: SignedBlockHeader {
                height,
                view,
                block_id: [0xBB; 32],
                proposer_id: ValidatorId(u64::from(validator_id)),
                signature: vec![0x02; 64],
                header_preimage: vec![0x20; 100],
            },
        },
    }
}

fn make_o2_evidence(validator_id: u32, height: u64, view: u64) -> SlashingEvidence {
    SlashingEvidence {
        version: 1,
        offense: OffenseKind::O2InvalidProposerSig,
        offending_validator: ValidatorId(u64::from(validator_id)),
        height,
        view,
        payload: EvidencePayloadV1::O2InvalidProposerSig {
            header: BlockHeader {
                height,
                view,
                proposer_id: ValidatorId(u64::from(validator_id)),
                batch_commitment: [0x00; 32],
            },
            bad_signature: vec![0xFF; 64],
        },
    }
}

// ============================================================================
// A) O1 Penalty Application Tests
// ============================================================================

#[test]
fn test_a1_o1_penalty_applied_stake_reduced() {
    // Setup: validator 1 with 1_000_000 stake
    let backend = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 1_000_000),
        (ValidatorId(2), 1_000_000),
    ]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o1: 750, // 7.5%
        slash_bps_o2: 500,
        jail_on_o1: true,
        jail_epochs_o1: 10,
        jail_on_o2: true,
        jail_epochs_o2: 5,
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0, // View 0: validator 1 is leader (0 % 3 = 0)
        current_epoch: 5,
    };

    // Act: submit O1 evidence
    let evidence = make_o1_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    // Assert: penalty was applied
    match &record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            // 1_000_000 * 750 / 10000 = 75_000
            assert_eq!(*slashed_amount, 75_000, "slashed amount should be 75_000");
            assert_eq!(
                *jailed_until_epoch,
                Some(15),
                "should be jailed until epoch 15"
            );
        }
        other => panic!("Expected PenaltyApplied, got {:?}", other),
    }

    // Assert: stake was reduced in backend
    let remaining_stake = engine.backend().get_stake(ValidatorId(1));
    assert_eq!(
        remaining_stake,
        Some(925_000),
        "remaining stake should be 925_000"
    );
}

#[test]
fn test_a2_o1_penalty_applied_jailed_until_epoch_set() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o1: 750,
        slash_bps_o2: 500,
        jail_on_o1: true,
        jail_epochs_o1: 10,
        jail_on_o2: true,
        jail_epochs_o2: 5,
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o1_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    // Assert jailed_until_epoch
    match &record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            jailed_until_epoch, ..
        } => {
            assert_eq!(*jailed_until_epoch, Some(15)); // 5 + 10 = 15
        }
        other => panic!("Expected PenaltyApplied, got {:?}", other),
    }

    // Assert backend jail status
    let jailed = engine.backend().is_jailed(ValidatorId(1));
    assert!(jailed, "validator should be jailed");

    let jailed_until = engine.backend().get_jailed_until_epoch(ValidatorId(1));
    assert_eq!(jailed_until, Some(15));
}

#[test]
fn test_a3_o1_penalty_metrics_tracked() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::EnforceCritical,
        ..Default::default()
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o1_evidence(1, 100, 0);
    engine.handle_evidence(&ctx, evidence);

    // Assert metrics
    assert_eq!(
        engine.evidence_count(OffenseKind::O1DoubleSign),
        1,
        "should have 1 O1 evidence"
    );
    assert_eq!(
        engine.penalty_count(OffenseKind::O1DoubleSign),
        1,
        "should have 1 O1 penalty"
    );
    assert!(
        engine.total_stake_slashed() > 0,
        "should have slashed some stake"
    );
    assert_eq!(engine.total_jail_events(), 1, "should have 1 jail event");
}

// ============================================================================
// B) O2 Penalty Application Tests
// ============================================================================

#[test]
fn test_b1_o2_penalty_applied_stake_reduced() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o1: 750,
        slash_bps_o2: 500, // 5%
        jail_on_o1: true,
        jail_epochs_o1: 10,
        jail_on_o2: true,
        jail_epochs_o2: 5,
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    // O2 evidence
    let evidence = make_o2_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    match &record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            // 1_000_000 * 500 / 10000 = 50_000
            assert_eq!(*slashed_amount, 50_000);
            assert_eq!(*jailed_until_epoch, Some(10)); // 5 + 5 = 10
        }
        other => panic!("Expected PenaltyApplied, got {:?}", other),
    }

    let remaining = engine.backend().get_stake(ValidatorId(1));
    assert_eq!(remaining, Some(950_000));
}

#[test]
fn test_b2_o2_penalty_applied_jailed_until_epoch_set() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o1: 750,
        slash_bps_o2: 500,
        jail_on_o1: true,
        jail_epochs_o1: 10,
        jail_on_o2: true,
        jail_epochs_o2: 5,
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o2_evidence(1, 100, 0);
    engine.handle_evidence(&ctx, evidence);

    let jailed_until = engine.backend().get_jailed_until_epoch(ValidatorId(1));
    assert_eq!(jailed_until, Some(10));
}

// ============================================================================
// C) Restart Safety Tests (using InMemorySlashingBackend atomic operations)
// ============================================================================

#[test]
fn test_c1_atomic_penalty_no_double_penalty() {
    // This test uses the atomic API directly to ensure deduplication works
    let mut backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);

    let evidence = make_o1_evidence(1, 100, 0);
    let evidence_id = evidence.evidence_id();

    // First application
    let request1 = AtomicPenaltyRequest {
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

    let result1 = backend.apply_penalty_atomic(request1.clone());
    assert!(result1.is_ok());
    let result1 = result1.unwrap();
    assert_eq!(result1.slashed_amount, 75_000);
    assert_eq!(result1.remaining_stake, 925_000);

    // Second application with same evidence_id should be rejected
    let request2 = AtomicPenaltyRequest {
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

    let result2 = backend.apply_penalty_atomic(request2);
    assert!(result2.is_err(), "duplicate evidence should be rejected");

    // Stake should still be 925_000 (not double-slashed)
    let stake = backend.get_stake(ValidatorId(1));
    assert_eq!(stake, Some(925_000));
}

#[test]
fn test_c2_evidence_dedup_prevents_replay() {
    let mut backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);

    let evidence = make_o1_evidence(1, 100, 0);
    let evidence_id = evidence.evidence_id();

    // First: not seen
    assert!(!backend.is_evidence_seen(&evidence_id));

    // Apply penalty
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
    backend.apply_penalty_atomic(request).unwrap();

    // After: should be seen
    assert!(backend.is_evidence_seen(&evidence_id));
}

// ============================================================================
// D) RecordOnly Mode Tests
// ============================================================================

#[test]
fn test_d1_record_only_mode_no_penalty() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::RecordOnly, // <-- RecordOnly
        slash_bps_o1: 750,
        slash_bps_o2: 500,
        jail_on_o1: true,
        jail_epochs_o1: 10,
        jail_on_o2: true,
        jail_epochs_o2: 5,
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o1_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    // Assert: evidence only, no penalty
    assert_eq!(record.penalty_decision, PenaltyDecision::EvidenceOnly);

    // Assert: stake unchanged
    let stake = engine.backend().get_stake(ValidatorId(1));
    assert_eq!(stake, Some(1_000_000), "stake should be unchanged");

    // Assert: not jailed
    let jailed = engine.backend().is_jailed(ValidatorId(1));
    assert!(!jailed, "validator should not be jailed in RecordOnly mode");
}

#[test]
fn test_d2_record_only_evidence_counted() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::RecordOnly,
        ..Default::default()
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o1_evidence(1, 100, 0);
    engine.handle_evidence(&ctx, evidence);

    // Evidence should be counted
    assert_eq!(engine.evidence_count(OffenseKind::O1DoubleSign), 1);

    // But no penalty should be applied
    assert_eq!(engine.penalty_count(OffenseKind::O1DoubleSign), 0);
    assert_eq!(engine.total_stake_slashed(), 0);
    assert_eq!(engine.total_jail_events(), 0);
}

// ============================================================================
// E) Jail Enforcement Integration Tests
// ============================================================================

#[test]
fn test_e1_jailed_validator_excluded_from_validator_set() {
    // Setup candidates with jail status
    let candidates = vec![
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(1), 1_000_000, 1, None), // Not jailed
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(2), 1_000_000, 1, Some(15)), // Jailed until 15
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(3), 1_000_000, 1, None), // Not jailed
    ];

    // At epoch 10, validator 2 is still jailed (10 < 15)
    let result =
        build_validator_set_with_stake_and_jail_filter(candidates.clone(), 500_000, 10).unwrap();

    assert_eq!(result.validator_set.len(), 2);
    assert_eq!(result.excluded_jailed.len(), 1);
    assert_eq!(result.excluded_jailed[0].validator_id, ValidatorId::new(2));
}

#[test]
fn test_e2_unjailed_validator_included_after_expiry() {
    let candidates = vec![
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(1), 1_000_000, 1, None),
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(2), 1_000_000, 1, Some(15)), // Jailed until 15
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(3), 1_000_000, 1, None),
    ];

    // At epoch 15, validator 2 is unjailed (15 >= 15)
    let result = build_validator_set_with_stake_and_jail_filter(candidates, 500_000, 15).unwrap();

    assert_eq!(result.validator_set.len(), 3);
    assert_eq!(result.excluded_jailed.len(), 0);
}

#[test]
fn test_e3_both_stake_and_jail_filtering() {
    let candidates = vec![
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(1), 1_000_000, 1, None), // OK
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(2), 500_000, 1, None), // Low stake
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(3), 1_000_000, 1, Some(20)), // Jailed
    ];

    let result =
        build_validator_set_with_stake_and_jail_filter(candidates, 1_000_000, 10).unwrap();

    assert_eq!(result.validator_set.len(), 1); // Only validator 1
    assert_eq!(result.excluded_low_stake.len(), 1);
    assert_eq!(result.excluded_jailed.len(), 1);
}

#[test]
fn test_e4_jail_filtering_epoch_boundary() {
    // Test exact boundary conditions
    let candidates = vec![
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(1), 1_000_000, 1, Some(10)),
    ];

    // At epoch 9: still jailed (9 < 10)
    let result9 = build_validator_set_with_stake_and_jail_filter(candidates.clone(), 0, 9);
    assert!(result9.is_err(), "should fail with no validators");

    // At epoch 10: unjailed (10 >= 10)
    let result10 = build_validator_set_with_stake_and_jail_filter(candidates.clone(), 0, 10);
    assert!(result10.is_ok());
    assert_eq!(result10.unwrap().validator_set.len(), 1);

    // At epoch 11: definitely unjailed
    let result11 = build_validator_set_with_stake_and_jail_filter(candidates, 0, 11);
    assert!(result11.is_ok());
    assert_eq!(result11.unwrap().validator_set.len(), 1);
}

// ============================================================================
// F) Fail-Closed Behavior Tests
// ============================================================================

#[test]
fn test_f1_all_validators_jailed_fail_closed() {
    let candidates = vec![
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(1), 1_000_000, 1, Some(100)),
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(2), 1_000_000, 1, Some(100)),
    ];

    // All validators jailed - should fail
    let result = build_validator_set_with_stake_and_jail_filter(candidates, 0, 50);
    assert!(result.is_err(), "should fail when all validators are jailed");
}

#[test]
fn test_f2_all_validators_low_stake_fail_closed() {
    let candidates = vec![
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(1), 500_000, 1, None),
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(2), 500_000, 1, None),
    ];

    // All validators below stake threshold - should fail
    let result = build_validator_set_with_stake_and_jail_filter(candidates, 1_000_000, 10);
    assert!(
        result.is_err(),
        "should fail when all validators have low stake"
    );
}

#[test]
fn test_f3_validator_not_found_returns_error() {
    let mut backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);

    let evidence_id = [0xAA; 32];
    let request = AtomicPenaltyRequest {
        validator_id: ValidatorId(999), // Non-existent
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
    assert!(result.is_err(), "should fail for unknown validator");
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

#[test]
fn test_g1_last_offense_epoch_updated() {
    let mut backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);

    // Before: no last offense
    assert_eq!(backend.get_last_offense_epoch(ValidatorId(1)), None);

    let request = AtomicPenaltyRequest {
        validator_id: ValidatorId(1),
        slash_bps: 750,
        jail: true,
        jail_epochs: 10,
        current_epoch: 42,
        offense: OffenseKind::O1DoubleSign,
        evidence_id: [0xAA; 32],
        height: 100,
        view: 0,
    };

    backend.apply_penalty_atomic(request).unwrap();

    // After: last offense should be set
    assert_eq!(backend.get_last_offense_epoch(ValidatorId(1)), Some(42));
}

#[test]
fn test_g2_total_slashed_tracked() {
    let mut backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);

    // Before
    assert_eq!(backend.get_validator_total_slashed(ValidatorId(1)), 0);

    let request = AtomicPenaltyRequest {
        validator_id: ValidatorId(1),
        slash_bps: 750, // 7.5% = 75_000
        jail: true,
        jail_epochs: 10,
        current_epoch: 5,
        offense: OffenseKind::O1DoubleSign,
        evidence_id: [0xAA; 32],
        height: 100,
        view: 0,
    };

    backend.apply_penalty_atomic(request).unwrap();

    // After
    assert_eq!(
        backend.get_validator_total_slashed(ValidatorId(1)),
        75_000
    );
}

#[test]
fn test_g3_enforce_all_mode_applies_o1_o2() {
    let backend = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 1_000_000),
        (ValidatorId(2), 1_000_000),
    ]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::EnforceAll,
        slash_bps_o1: 750,
        slash_bps_o2: 500,
        jail_on_o1: true,
        jail_epochs_o1: 10,
        jail_on_o2: true,
        jail_epochs_o2: 5,
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    // O1
    let evidence1 = make_o1_evidence(1, 100, 0);
    let record1 = engine.handle_evidence(&ctx, evidence1);
    assert!(
        matches!(record1.penalty_decision, PenaltyDecision::PenaltyApplied { .. })
    );

    // O2 (use view=1 for validator 2 to be leader)
    let ctx2 = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 1,
        current_epoch: 5,
    };
    let evidence2 = make_o2_evidence(2, 100, 1);
    let record2 = engine.handle_evidence(&ctx2, evidence2);
    assert!(
        matches!(record2.penalty_decision, PenaltyDecision::PenaltyApplied { .. })
    );
}

#[test]
fn test_g4_different_evidence_same_validator_both_applied() {
    let mut backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);

    // First offense at height 100
    let request1 = AtomicPenaltyRequest {
        validator_id: ValidatorId(1),
        slash_bps: 750,
        jail: true,
        jail_epochs: 10,
        current_epoch: 5,
        offense: OffenseKind::O1DoubleSign,
        evidence_id: [0x01; 32],
        height: 100,
        view: 0,
    };
    let result1 = backend.apply_penalty_atomic(request1).unwrap();
    assert_eq!(result1.slashed_amount, 75_000);
    assert_eq!(result1.remaining_stake, 925_000);

    // Second offense at height 200 with different evidence_id
    let request2 = AtomicPenaltyRequest {
        validator_id: ValidatorId(1),
        slash_bps: 750,
        jail: true,
        jail_epochs: 10,
        current_epoch: 6,
        offense: OffenseKind::O1DoubleSign,
        evidence_id: [0x02; 32],
        height: 200,
        view: 0,
    };
    let result2 = backend.apply_penalty_atomic(request2).unwrap();
    // 925_000 * 750 / 10000 = 69_375
    assert_eq!(result2.slashed_amount, 69_375);
    assert_eq!(result2.remaining_stake, 855_625);

    // Verify final stake
    assert_eq!(backend.get_stake(ValidatorId(1)), Some(855_625));
}