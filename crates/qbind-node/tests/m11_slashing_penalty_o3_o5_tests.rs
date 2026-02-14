//! M11 Slashing Penalty Application Tests for O3-O5 Offenses
//!
//! This test file validates the M11 slashing penalty implementation for O3, O4, and O5 offenses.
//! These tests ensure:
//!
//! A) O3 penalty reduces stake + jails validator
//! B) O4 penalty reduces stake + jails validator
//! C) O5 penalty reduces stake + jails validator
//! D) Restart safety (no double penalty after restart)
//! E) RecordOnly mode does not apply penalty
//! F) Off mode rejects evidence
//! G) All validators jailed -> fail closed
//! H) Deterministic outcome across two engines with same inputs
//!
//! # M11 Penalty Parameters (from governance)
//!
//! | Offense | Slash (bps) | Jail (epochs) |
//! |---------|-------------|---------------|
//! | O3      | 300 (3%)    | 3             |
//! | O4      | 200 (2%)    | 2             |
//! | O5      | 100 (1%)    | 1             |

use qbind_consensus::slashing::{
    AtomicPenaltyRequest, AtomicSlashingBackend, BlockHeader, DagCertificate, DagStateProof,
    DagValidationFailure, EvidencePayloadV1, InMemorySlashingBackend, LazyVoteInvalidReason,
    OffenseKind, PenaltyDecision, PenaltyEngineConfig, PenaltySlashingContext,
    PenaltySlashingEngine, SignedVote, SlashingBackend, SlashingEvidence, SlashingMode,
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

/// Create O3 lazy vote evidence for a validator
fn make_o3_evidence(validator_id: u32, height: u64, view: u64) -> SlashingEvidence {
    SlashingEvidence {
        version: 1,
        offense: OffenseKind::O3aLazyVoteSingle,
        offending_validator: ValidatorId(u64::from(validator_id)),
        height,
        view,
        payload: EvidencePayloadV1::O3LazyVote {
            vote: SignedVote {
                validator_id: ValidatorId(u64::from(validator_id)),
                height,
                view,
                block_id: [0xCC; 32],
                signature: vec![0x03; 64],
            },
            invalid_reason: LazyVoteInvalidReason::InvalidProposerSig,
        },
    }
}

/// Create O4 censorship/invalid DAG cert evidence for a validator
fn make_o4_evidence(validator_id: u32, height: u64, view: u64) -> SlashingEvidence {
    SlashingEvidence {
        version: 1,
        offense: OffenseKind::O4InvalidDagCert,
        offending_validator: ValidatorId(u64::from(validator_id)),
        height,
        view,
        payload: EvidencePayloadV1::O4InvalidDagCert {
            cert: DagCertificate {
                batch_commitment: [0xDD; 32],
                dag_round: 100,
                signers: vec![ValidatorId(u64::from(validator_id))],
                signatures: vec![vec![0x04; 64]],
            },
            failure_reason: DagValidationFailure::QuorumNotMet {
                valid_count: 1,
                required: 3,
            },
        },
    }
}

/// Create O5 availability failure evidence for a validator
fn make_o5_evidence(validator_id: u32, height: u64, view: u64) -> SlashingEvidence {
    SlashingEvidence {
        version: 1,
        offense: OffenseKind::O5DagCouplingViolation,
        offending_validator: ValidatorId(u64::from(validator_id)),
        height,
        view,
        payload: EvidencePayloadV1::O5DagCouplingViolation {
            block: BlockHeader {
                height,
                view,
                proposer_id: ValidatorId(u64::from(validator_id)),
                batch_commitment: [0xEE; 32], // Invalid commitment not in DAG frontier
            },
            dag_state_proof: DagStateProof {
                dag_round: 100,
                frontier_commitments: vec![
                    [0xF1; 32], // Valid commitments that DO exist
                    [0xF2; 32],
                ],
                merkle_proof: None,
            },
        },
    }
}

fn default_m11_config() -> PenaltyEngineConfig {
    PenaltyEngineConfig {
        mode: SlashingMode::EnforceCritical,
        // O1/O2 defaults
        slash_bps_o1: 750,
        slash_bps_o2: 500,
        jail_on_o1: true,
        jail_epochs_o1: 10,
        jail_on_o2: true,
        jail_epochs_o2: 5,
        // M11: O3-O5 parameters per problem statement
        slash_bps_o3: 300, // 3%
        jail_on_o3: true,
        jail_epochs_o3: 3,
        slash_bps_o4: 200, // 2%
        jail_on_o4: true,
        jail_epochs_o4: 2,
        slash_bps_o5: 100, // 1%
        jail_on_o5: true,
        jail_epochs_o5: 1,
    }
}

// ============================================================================
// A) O3 Penalty Application Tests
// ============================================================================

#[test]
fn test_a1_o3_penalty_applied_stake_reduced() {
    // Setup: validator 1 with 1_000_000 stake
    let backend = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 1_000_000),
        (ValidatorId(2), 1_000_000),
    ]);
    let config = default_m11_config();
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    // Act: submit O3 evidence
    let evidence = make_o3_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    // Assert: penalty was applied
    match &record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            // 1_000_000 * 300 / 10000 = 30_000 (3%)
            assert_eq!(*slashed_amount, 30_000, "O3 should slash 3% (30_000)");
            assert_eq!(
                *jailed_until_epoch,
                Some(8),
                "O3 should jail for 3 epochs (5 + 3 = 8)"
            );
        }
        other => panic!("Expected PenaltyApplied, got {:?}", other),
    }

    // Assert: stake was reduced in backend
    let remaining_stake = engine.backend().get_stake(ValidatorId(1));
    assert_eq!(remaining_stake, Some(970_000), "remaining stake should be 970_000");
}

#[test]
fn test_a2_o3_penalty_jails_validator() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = default_m11_config();
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o3_evidence(1, 100, 0);
    engine.handle_evidence(&ctx, evidence);

    // Assert jail status
    let jailed = engine.backend().is_jailed(ValidatorId(1));
    assert!(jailed, "validator should be jailed after O3 offense");

    let jailed_until = engine.backend().get_jailed_until_epoch(ValidatorId(1));
    assert_eq!(jailed_until, Some(8), "O3 jail should be 3 epochs (5+3=8)");
}

// ============================================================================
// B) O4 Penalty Application Tests
// ============================================================================

#[test]
fn test_b1_o4_penalty_applied_stake_reduced() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = default_m11_config();
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    // Act: submit O4 evidence
    let evidence = make_o4_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    // Assert: penalty was applied
    match &record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            // 1_000_000 * 200 / 10000 = 20_000 (2%)
            assert_eq!(*slashed_amount, 20_000, "O4 should slash 2% (20_000)");
            assert_eq!(
                *jailed_until_epoch,
                Some(7),
                "O4 should jail for 2 epochs (5 + 2 = 7)"
            );
        }
        other => panic!("Expected PenaltyApplied, got {:?}", other),
    }

    // Assert: stake was reduced
    let remaining = engine.backend().get_stake(ValidatorId(1));
    assert_eq!(remaining, Some(980_000));
}

#[test]
fn test_b2_o4_penalty_jails_validator() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = default_m11_config();
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o4_evidence(1, 100, 0);
    engine.handle_evidence(&ctx, evidence);

    // Assert jail status
    let jailed = engine.backend().is_jailed(ValidatorId(1));
    assert!(jailed, "validator should be jailed after O4 offense");

    let jailed_until = engine.backend().get_jailed_until_epoch(ValidatorId(1));
    assert_eq!(jailed_until, Some(7), "O4 jail should be 2 epochs (5+2=7)");
}

// ============================================================================
// C) O5 Penalty Application Tests
// ============================================================================

#[test]
fn test_c1_o5_penalty_applied_stake_reduced() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = default_m11_config();
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    // Act: submit O5 evidence
    let evidence = make_o5_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    // Assert: penalty was applied
    match &record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            // 1_000_000 * 100 / 10000 = 10_000 (1%)
            assert_eq!(*slashed_amount, 10_000, "O5 should slash 1% (10_000)");
            assert_eq!(
                *jailed_until_epoch,
                Some(6),
                "O5 should jail for 1 epoch (5 + 1 = 6)"
            );
        }
        other => panic!("Expected PenaltyApplied, got {:?}", other),
    }

    // Assert: stake was reduced
    let remaining = engine.backend().get_stake(ValidatorId(1));
    assert_eq!(remaining, Some(990_000));
}

#[test]
fn test_c2_o5_penalty_jails_validator() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = default_m11_config();
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o5_evidence(1, 100, 0);
    engine.handle_evidence(&ctx, evidence);

    // Assert jail status
    let jailed = engine.backend().is_jailed(ValidatorId(1));
    assert!(jailed, "validator should be jailed after O5 offense");

    let jailed_until = engine.backend().get_jailed_until_epoch(ValidatorId(1));
    assert_eq!(jailed_until, Some(6), "O5 jail should be 1 epoch (5+1=6)");
}

// ============================================================================
// D) Restart Safety Tests (no double penalty after restart)
// ============================================================================

#[test]
fn test_d1_atomic_penalty_no_double_penalty_o3() {
    let mut backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);

    let evidence = make_o3_evidence(1, 100, 0);
    let evidence_id = evidence.evidence_id();

    // First application
    let request1 = AtomicPenaltyRequest {
        validator_id: ValidatorId(1),
        slash_bps: 300, // 3%
        jail: true,
        jail_epochs: 3,
        current_epoch: 5,
        offense: OffenseKind::O3aLazyVoteSingle,
        evidence_id,
        height: 100,
        view: 0,
    };

    let result1 = backend.apply_penalty_atomic(request1.clone());
    assert!(result1.is_ok());
    let result1 = result1.unwrap();
    assert_eq!(result1.slashed_amount, 30_000);
    assert_eq!(result1.remaining_stake, 970_000);

    // Second application with same evidence_id should be rejected
    let request2 = AtomicPenaltyRequest {
        validator_id: ValidatorId(1),
        slash_bps: 300,
        jail: true,
        jail_epochs: 3,
        current_epoch: 5,
        offense: OffenseKind::O3aLazyVoteSingle,
        evidence_id,
        height: 100,
        view: 0,
    };

    let result2 = backend.apply_penalty_atomic(request2);
    assert!(result2.is_err(), "duplicate evidence should be rejected");

    // Stake should still be 970_000 (not double-slashed)
    let stake = backend.get_stake(ValidatorId(1));
    assert_eq!(stake, Some(970_000));
}

#[test]
fn test_d2_evidence_dedup_prevents_replay_o4() {
    let mut backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);

    let evidence = make_o4_evidence(1, 100, 0);
    let evidence_id = evidence.evidence_id();

    // First: not seen
    assert!(!backend.is_evidence_seen(&evidence_id));

    // Apply penalty
    let request = AtomicPenaltyRequest {
        validator_id: ValidatorId(1),
        slash_bps: 200,
        jail: true,
        jail_epochs: 2,
        current_epoch: 5,
        offense: OffenseKind::O4InvalidDagCert,
        evidence_id,
        height: 100,
        view: 0,
    };
    backend.apply_penalty_atomic(request).unwrap();

    // After: should be seen
    assert!(backend.is_evidence_seen(&evidence_id));
}

// ============================================================================
// E) RecordOnly Mode Tests (no penalty applied)
// ============================================================================

#[test]
fn test_e1_record_only_mode_no_penalty_o3() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::RecordOnly, // <-- RecordOnly
        ..default_m11_config()
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o3_evidence(1, 100, 0);
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
fn test_e2_record_only_mode_no_penalty_o4() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::RecordOnly,
        ..default_m11_config()
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o4_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    assert_eq!(record.penalty_decision, PenaltyDecision::EvidenceOnly);
    assert_eq!(engine.backend().get_stake(ValidatorId(1)), Some(1_000_000));
    assert!(!engine.backend().is_jailed(ValidatorId(1)));
}

#[test]
fn test_e3_record_only_mode_no_penalty_o5() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::RecordOnly,
        ..default_m11_config()
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o5_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    assert_eq!(record.penalty_decision, PenaltyDecision::EvidenceOnly);
    assert_eq!(engine.backend().get_stake(ValidatorId(1)), Some(1_000_000));
    assert!(!engine.backend().is_jailed(ValidatorId(1)));
}

// ============================================================================
// F) Off Mode Tests (evidence rejected)
// ============================================================================

#[test]
fn test_f1_off_mode_rejects_o3_evidence() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::Off, // <-- Off
        ..default_m11_config()
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o3_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    // Off mode should reject evidence with Legacy(RejectedInvalid)
    match &record.penalty_decision {
        PenaltyDecision::Legacy(qbind_consensus::slashing::SlashingDecisionKind::RejectedInvalid) => {
            // Expected
        }
        other => panic!("Off mode should reject evidence, got {:?}", other),
    }
}

#[test]
fn test_f2_off_mode_rejects_o4_evidence() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::Off,
        ..default_m11_config()
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o4_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    match &record.penalty_decision {
        PenaltyDecision::Legacy(qbind_consensus::slashing::SlashingDecisionKind::RejectedInvalid) => {
            // Expected
        }
        other => panic!("Off mode should reject evidence, got {:?}", other),
    }
}

#[test]
fn test_f3_off_mode_rejects_o5_evidence() {
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::Off,
        ..default_m11_config()
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    let evidence = make_o5_evidence(1, 100, 0);
    let record = engine.handle_evidence(&ctx, evidence);

    match &record.penalty_decision {
        PenaltyDecision::Legacy(qbind_consensus::slashing::SlashingDecisionKind::RejectedInvalid) => {
            // Expected
        }
        other => panic!("Off mode should reject evidence, got {:?}", other),
    }
}

// ============================================================================
// G) All Validators Jailed -> Fail Closed
// ============================================================================

#[test]
fn test_g1_all_validators_jailed_fail_closed() {
    // Create candidates where ALL validators are jailed
    let candidates = vec![
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(1), 1_000_000, 1, Some(100)),
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(2), 1_000_000, 1, Some(100)),
    ];

    // All validators jailed at epoch 50 (before jail expiry at epoch 100)
    let result = build_validator_set_with_stake_and_jail_filter(candidates, 0, 50);
    assert!(result.is_err(), "should fail when all validators are jailed");
}

#[test]
fn test_g2_some_validators_jailed_still_works() {
    // Create candidates where only ONE validator is jailed
    let candidates = vec![
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(1), 1_000_000, 1, Some(100)), // Jailed
        ValidatorCandidateWithJailStatus::new(ValidatorId::new(2), 1_000_000, 1, None),       // Not jailed
    ];

    // At epoch 50, validator 1 is jailed (50 < 100), validator 2 is not
    let result = build_validator_set_with_stake_and_jail_filter(candidates, 0, 50);
    assert!(result.is_ok(), "should succeed when some validators are not jailed");
    assert_eq!(result.unwrap().validator_set.len(), 1);
}

// ============================================================================
// H) Deterministic Outcome Tests
// ============================================================================

#[test]
fn test_h1_deterministic_outcome_o3() {
    // Create two engines with identical initial state
    let backend1 = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 1_000_000),
        (ValidatorId(2), 1_000_000),
    ]);
    let backend2 = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 1_000_000),
        (ValidatorId(2), 1_000_000),
    ]);
    let config = default_m11_config();
    let mut engine1 = PenaltySlashingEngine::new(backend1, config.clone());
    let mut engine2 = PenaltySlashingEngine::new(backend2, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    // Apply identical O3 evidence to both engines
    let evidence1 = make_o3_evidence(1, 100, 0);
    let evidence2 = make_o3_evidence(1, 100, 0);

    let record1 = engine1.handle_evidence(&ctx, evidence1);
    let record2 = engine2.handle_evidence(&ctx, evidence2);

    // Assert both engines produce same outcome
    match (&record1.penalty_decision, &record2.penalty_decision) {
        (
            PenaltyDecision::PenaltyApplied {
                slashed_amount: s1,
                jailed_until_epoch: j1,
            },
            PenaltyDecision::PenaltyApplied {
                slashed_amount: s2,
                jailed_until_epoch: j2,
            },
        ) => {
            assert_eq!(s1, s2, "slashed amounts should be identical");
            assert_eq!(j1, j2, "jail epochs should be identical");
        }
        _ => panic!("both engines should produce PenaltyApplied"),
    }

    // Assert final stakes are identical
    assert_eq!(
        engine1.backend().get_stake(ValidatorId(1)),
        engine2.backend().get_stake(ValidatorId(1)),
        "final stakes should be identical"
    );
}

#[test]
fn test_h2_deterministic_outcome_o4_o5() {
    let backend1 = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let backend2 = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = default_m11_config();
    let mut engine1 = PenaltySlashingEngine::new(backend1, config.clone());
    let mut engine2 = PenaltySlashingEngine::new(backend2, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    // Apply O4 and O5 to both engines in same order
    let o4_1 = make_o4_evidence(1, 100, 0);
    let o4_2 = make_o4_evidence(1, 100, 0);
    let o5_1 = make_o5_evidence(1, 200, 1);
    let o5_2 = make_o5_evidence(1, 200, 1);

    engine1.handle_evidence(&ctx, o4_1);
    engine1.handle_evidence(&ctx, o5_1);
    engine2.handle_evidence(&ctx, o4_2);
    engine2.handle_evidence(&ctx, o5_2);

    // Final stakes should be identical
    assert_eq!(
        engine1.backend().get_stake(ValidatorId(1)),
        engine2.backend().get_stake(ValidatorId(1)),
        "final stakes after O4+O5 should be identical"
    );
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

#[test]
fn test_i1_enforce_all_mode_applies_o3_o4_o5() {
    let backend = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 1_000_000),
        (ValidatorId(2), 1_000_000),
        (ValidatorId(3), 1_000_000),
    ]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::EnforceAll,
        ..default_m11_config()
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    // O3
    let o3 = make_o3_evidence(1, 100, 0);
    let r3 = engine.handle_evidence(&ctx, o3);
    assert!(matches!(r3.penalty_decision, PenaltyDecision::PenaltyApplied { .. }));

    // O4
    let o4 = make_o4_evidence(2, 101, 1);
    let r4 = engine.handle_evidence(&ctx, o4);
    assert!(matches!(r4.penalty_decision, PenaltyDecision::PenaltyApplied { .. }));

    // O5
    let o5 = make_o5_evidence(3, 102, 2);
    let r5 = engine.handle_evidence(&ctx, o5);
    assert!(matches!(r5.penalty_decision, PenaltyDecision::PenaltyApplied { .. }));
}

#[test]
fn test_i2_multiple_o3_offenses_compound() {
    let mut backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);

    // First O3 offense
    let request1 = AtomicPenaltyRequest {
        validator_id: ValidatorId(1),
        slash_bps: 300, // 3%
        jail: true,
        jail_epochs: 3,
        current_epoch: 5,
        offense: OffenseKind::O3aLazyVoteSingle,
        evidence_id: [0x01; 32],
        height: 100,
        view: 0,
    };
    let result1 = backend.apply_penalty_atomic(request1).unwrap();
    assert_eq!(result1.slashed_amount, 30_000);
    assert_eq!(result1.remaining_stake, 970_000);

    // Second O3 offense (different evidence_id)
    let request2 = AtomicPenaltyRequest {
        validator_id: ValidatorId(1),
        slash_bps: 300, // 3% of remaining
        jail: true,
        jail_epochs: 3,
        current_epoch: 10, // After first jail expired
        offense: OffenseKind::O3aLazyVoteSingle,
        evidence_id: [0x02; 32],
        height: 200,
        view: 0,
    };
    let result2 = backend.apply_penalty_atomic(request2).unwrap();
    // 970_000 * 300 / 10000 = 29_100
    assert_eq!(result2.slashed_amount, 29_100);
    assert_eq!(result2.remaining_stake, 940_900);
}

#[test]
fn test_i3_o3b_repeated_lazy_vote_same_penalty_as_o3a() {
    // O3a and O3b should use the same penalty parameters
    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 1_000_000)]);
    let config = default_m11_config();
    let mut engine = PenaltySlashingEngine::new(backend, config);
    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    // Create O3b evidence (repeated lazy votes)
    let evidence = SlashingEvidence {
        version: 1,
        offense: OffenseKind::O3bLazyVoteRepeated,
        offending_validator: ValidatorId(1),
        height: 100,
        view: 0,
        payload: EvidencePayloadV1::O3LazyVote {
            vote: SignedVote {
                validator_id: ValidatorId(1),
                height: 100,
                view: 0,
                block_id: [0xCC; 32],
                signature: vec![0x03; 64],
            },
            invalid_reason: LazyVoteInvalidReason::InvalidQcSignature,
        },
    };
    let record = engine.handle_evidence(&ctx, evidence);

    // O3b should have same penalty as O3a (3% slash, 3 epoch jail)
    match &record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            assert_eq!(*slashed_amount, 30_000, "O3b should slash 3%");
            assert_eq!(*jailed_until_epoch, Some(8), "O3b should jail 3 epochs");
        }
        other => panic!("Expected PenaltyApplied, got {:?}", other),
    }
}
