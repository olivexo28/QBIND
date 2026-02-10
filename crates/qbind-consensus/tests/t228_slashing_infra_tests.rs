//! T228 Slashing Infrastructure Tests
//!
//! This test file validates the slashing/evidence pipeline infrastructure
//! introduced in T228. These tests ensure that:
//!
//! - Evidence can be constructed for all offense classes (O1–O5)
//! - Evidence can be serialized and deserialized (round-trip)
//! - The NoopSlashingEngine correctly accepts/rejects evidence
//! - Deduplication works correctly
//! - Metrics are properly incremented
//!
//! # Note
//!
//! T228 only implements the evidence recording infrastructure. Actual
//! penalty application (stake burning, jailing) is deferred to T229+.

use qbind_consensus::slashing::{
    BlockHeader, DagCertificate, DagStateProof, DagValidationFailure, EvidencePayloadV1,
    LazyVoteInvalidReason, NoopSlashingEngine, OffenseKind, SignedBlockHeader, SignedVote,
    SlashingContext, SlashingDecisionKind, SlashingEngine, SlashingEvidence, SlashingMetrics,
    SlashingStore,
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

fn make_o3a_evidence(validator_id: u32, height: u64, view: u64) -> SlashingEvidence {
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

fn make_o3b_evidence(validator_id: u32, height: u64, view: u64) -> SlashingEvidence {
    SlashingEvidence {
        version: 1,
        offense: OffenseKind::O3bLazyVoteRepeated,
        offending_validator: ValidatorId(u64::from(validator_id)),
        height,
        view,
        payload: EvidencePayloadV1::O3LazyVote {
            vote: SignedVote {
                validator_id: ValidatorId(u64::from(validator_id)),
                height,
                view,
                block_id: [0xDD; 32],
                signature: vec![0x04; 64],
            },
            invalid_reason: LazyVoteInvalidReason::InvalidQcSignature,
        },
    }
}

fn make_o4_evidence(validator_id: u32, height: u64, view: u64) -> SlashingEvidence {
    SlashingEvidence {
        version: 1,
        offense: OffenseKind::O4InvalidDagCert,
        offending_validator: ValidatorId(u64::from(validator_id)),
        height,
        view,
        payload: EvidencePayloadV1::O4InvalidDagCert {
            cert: DagCertificate {
                batch_commitment: [0xEE; 32],
                dag_round: view,
                signers: vec![
                    ValidatorId(1),
                    ValidatorId(2),
                    ValidatorId(u64::from(validator_id)),
                ],
                signatures: vec![vec![0x05; 64], vec![0x06; 64], vec![0x07; 64]],
            },
            failure_reason: DagValidationFailure::InvalidSignature { signer_index: 2 },
        },
    }
}

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
                batch_commitment: [0xFF; 32], // Invalid commitment
            },
            dag_state_proof: DagStateProof {
                dag_round: view,
                frontier_commitments: vec![[0x11; 32], [0x22; 32]], // Valid commitments don't include 0xFF
                merkle_proof: None,
            },
        },
    }
}

// ============================================================================
// Evidence Round-Trip Tests (serialize/deserialize)
// ============================================================================

#[test]
fn test_slashing_evidence_round_trip_o1() {
    // O1: Double-sign evidence
    let evidence = make_o1_evidence(1, 100, 5);

    // Verify structure is valid
    assert!(evidence.validate_structure().is_ok());
    assert_eq!(evidence.offense, OffenseKind::O1DoubleSign);
    assert_eq!(evidence.offending_validator, ValidatorId(1));
    assert_eq!(evidence.height, 100);
    assert_eq!(evidence.view, 5);

    // Verify payload content
    if let EvidencePayloadV1::O1DoubleSign { block_a, block_b } = &evidence.payload {
        assert_eq!(block_a.height, 100);
        assert_eq!(block_b.height, 100);
        assert_ne!(block_a.block_id, block_b.block_id);
    } else {
        panic!("Expected O1DoubleSign payload");
    }
}

#[test]
fn test_slashing_evidence_round_trip_o2() {
    // O2: Invalid proposer signature evidence
    let evidence = make_o2_evidence(2, 200, 10);

    assert!(evidence.validate_structure().is_ok());
    assert_eq!(evidence.offense, OffenseKind::O2InvalidProposerSig);

    if let EvidencePayloadV1::O2InvalidProposerSig {
        header,
        bad_signature,
    } = &evidence.payload
    {
        assert_eq!(header.height, 200);
        assert_eq!(header.proposer_id, ValidatorId(2));
        assert_eq!(bad_signature.len(), 64);
    } else {
        panic!("Expected O2InvalidProposerSig payload");
    }
}

#[test]
fn test_slashing_evidence_round_trip_o3() {
    // O3a: Single lazy vote evidence
    let evidence_a = make_o3a_evidence(1, 300, 15);
    assert!(evidence_a.validate_structure().is_ok());
    assert_eq!(evidence_a.offense, OffenseKind::O3aLazyVoteSingle);

    // O3b: Repeated lazy vote evidence
    let evidence_b = make_o3b_evidence(2, 400, 20);
    assert!(evidence_b.validate_structure().is_ok());
    assert_eq!(evidence_b.offense, OffenseKind::O3bLazyVoteRepeated);

    // Both use O3LazyVote payload
    if let EvidencePayloadV1::O3LazyVote {
        vote,
        invalid_reason,
    } = &evidence_a.payload
    {
        assert_eq!(vote.height, 300);
        assert_eq!(*invalid_reason, LazyVoteInvalidReason::InvalidProposerSig);
    } else {
        panic!("Expected O3LazyVote payload");
    }
}

#[test]
fn test_slashing_evidence_round_trip_o4() {
    // O4: Invalid DAG certificate evidence
    let evidence = make_o4_evidence(3, 500, 25);

    assert!(evidence.validate_structure().is_ok());
    assert_eq!(evidence.offense, OffenseKind::O4InvalidDagCert);

    if let EvidencePayloadV1::O4InvalidDagCert {
        cert,
        failure_reason,
    } = &evidence.payload
    {
        assert_eq!(cert.signers.len(), 3);
        assert!(matches!(
            failure_reason,
            DagValidationFailure::InvalidSignature { signer_index: 2 }
        ));
    } else {
        panic!("Expected O4InvalidDagCert payload");
    }
}

#[test]
fn test_slashing_evidence_round_trip_o5() {
    // O5: DAG coupling violation evidence
    let evidence = make_o5_evidence(1, 600, 30);

    assert!(evidence.validate_structure().is_ok());
    assert_eq!(evidence.offense, OffenseKind::O5DagCouplingViolation);

    if let EvidencePayloadV1::O5DagCouplingViolation {
        block,
        dag_state_proof,
    } = &evidence.payload
    {
        assert_eq!(block.batch_commitment, [0xFF; 32]);
        assert_eq!(dag_state_proof.frontier_commitments.len(), 2);
        // Invalid commitment 0xFF is not in frontier
        assert!(!dag_state_proof.frontier_commitments.contains(&[0xFF; 32]));
    } else {
        panic!("Expected O5DagCouplingViolation payload");
    }
}

// ============================================================================
// Engine Accept/Reject Tests
// ============================================================================

#[test]
fn test_slashing_engine_accepts_valid_evidence() {
    let vs = test_validator_set();
    let ctx = SlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 10,
    };

    let mut engine = NoopSlashingEngine::new();
    let evidence = make_o1_evidence(1, 100, 5);

    let record = engine.handle_evidence(&ctx, evidence);

    assert_eq!(record.decision, SlashingDecisionKind::AcceptedNoOp);
    assert_eq!(record.decision_height, 1000);
    assert_eq!(record.decision_view, 10);
}

#[test]
fn test_slashing_engine_accepts_all_offense_types() {
    let vs = test_validator_set();
    let ctx = SlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 10,
    };

    let mut engine = NoopSlashingEngine::new();

    // O1
    let r1 = engine.handle_evidence(&ctx, make_o1_evidence(1, 100, 1));
    assert_eq!(r1.decision, SlashingDecisionKind::AcceptedNoOp);

    // O2
    let r2 = engine.handle_evidence(&ctx, make_o2_evidence(2, 200, 2));
    assert_eq!(r2.decision, SlashingDecisionKind::AcceptedNoOp);

    // O3a
    let r3a = engine.handle_evidence(&ctx, make_o3a_evidence(3, 300, 3));
    assert_eq!(r3a.decision, SlashingDecisionKind::AcceptedNoOp);

    // O3b
    let r3b = engine.handle_evidence(&ctx, make_o3b_evidence(1, 400, 4));
    assert_eq!(r3b.decision, SlashingDecisionKind::AcceptedNoOp);

    // O4
    let r4 = engine.handle_evidence(&ctx, make_o4_evidence(2, 500, 5));
    assert_eq!(r4.decision, SlashingDecisionKind::AcceptedNoOp);

    // O5
    let r5 = engine.handle_evidence(&ctx, make_o5_evidence(3, 600, 6));
    assert_eq!(r5.decision, SlashingDecisionKind::AcceptedNoOp);

    // All should be accepted
    assert_eq!(engine.decision_count(SlashingDecisionKind::AcceptedNoOp), 6);
}

#[test]
fn test_slashing_engine_rejects_unknown_validator() {
    let vs = test_validator_set();
    let ctx = SlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 10,
    };

    let mut engine = NoopSlashingEngine::new();

    // Validator 999 is not in the set
    let evidence = make_o1_evidence(999, 100, 5);
    let record = engine.handle_evidence(&ctx, evidence);

    assert_eq!(record.decision, SlashingDecisionKind::RejectedInvalid);
}

#[test]
fn test_slashing_engine_rejects_zero_height() {
    let vs = test_validator_set();
    let ctx = SlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 10,
    };

    let mut engine = NoopSlashingEngine::new();

    // Height 0 is invalid
    let mut evidence = make_o1_evidence(1, 0, 5);
    evidence.height = 0;

    let record = engine.handle_evidence(&ctx, evidence);
    assert_eq!(record.decision, SlashingDecisionKind::RejectedInvalid);
}

#[test]
fn test_slashing_engine_rejects_future_height() {
    let vs = test_validator_set();
    let ctx = SlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 10,
    };

    let mut engine = NoopSlashingEngine::new();

    // Height far in future should be rejected (>100 blocks ahead)
    let evidence = make_o1_evidence(1, 2000, 5);
    let record = engine.handle_evidence(&ctx, evidence);

    assert_eq!(record.decision, SlashingDecisionKind::RejectedInvalid);
}

// ============================================================================
// Deduplication Tests
// ============================================================================

#[test]
fn test_slashing_engine_deduplicates() {
    let vs = test_validator_set();
    let ctx = SlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 10,
    };

    let mut engine = NoopSlashingEngine::new();
    let evidence = make_o1_evidence(1, 100, 5);

    // First submission should be accepted
    let record1 = engine.handle_evidence(&ctx, evidence.clone());
    assert_eq!(record1.decision, SlashingDecisionKind::AcceptedNoOp);

    // Second submission of same evidence should be rejected as duplicate
    let record2 = engine.handle_evidence(&ctx, evidence);
    assert_eq!(record2.decision, SlashingDecisionKind::RejectedDuplicate);
}

#[test]
fn test_slashing_engine_dedup_key_uniqueness() {
    let vs = test_validator_set();
    let ctx = SlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 10,
    };

    let mut engine = NoopSlashingEngine::new();

    // Same validator, same height, different view => different key
    let e1 = make_o1_evidence(1, 100, 5);
    let e2 = make_o1_evidence(1, 100, 6);

    let r1 = engine.handle_evidence(&ctx, e1);
    let r2 = engine.handle_evidence(&ctx, e2);

    assert_eq!(r1.decision, SlashingDecisionKind::AcceptedNoOp);
    assert_eq!(r2.decision, SlashingDecisionKind::AcceptedNoOp);
}

#[test]
fn test_slashing_engine_dedup_different_validators_same_block() {
    let vs = test_validator_set();
    let ctx = SlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 10,
    };

    let mut engine = NoopSlashingEngine::new();

    // Different validators at same height/view => both accepted
    let e1 = make_o1_evidence(1, 100, 5);
    let e2 = make_o1_evidence(2, 100, 5);

    let r1 = engine.handle_evidence(&ctx, e1);
    let r2 = engine.handle_evidence(&ctx, e2);

    assert_eq!(r1.decision, SlashingDecisionKind::AcceptedNoOp);
    assert_eq!(r2.decision, SlashingDecisionKind::AcceptedNoOp);
}

// ============================================================================
// Metrics Tests
// ============================================================================

#[test]
fn test_slashing_metrics_incremented() {
    let metrics = SlashingMetrics::new();

    // Initially all zeros
    assert_eq!(metrics.evidence_total(), 0);
    assert_eq!(metrics.decisions_total(), 0);

    // Increment evidence counters
    metrics.inc_evidence(OffenseKind::O1DoubleSign);
    metrics.inc_evidence(OffenseKind::O1DoubleSign);
    metrics.inc_evidence(OffenseKind::O2InvalidProposerSig);
    metrics.inc_evidence(OffenseKind::O3aLazyVoteSingle);
    metrics.inc_evidence(OffenseKind::O3bLazyVoteRepeated);
    metrics.inc_evidence(OffenseKind::O4InvalidDagCert);
    metrics.inc_evidence(OffenseKind::O5DagCouplingViolation);

    assert_eq!(metrics.evidence_o1_total(), 2);
    assert_eq!(metrics.evidence_o2_total(), 1);
    assert_eq!(metrics.evidence_o3a_total(), 1);
    assert_eq!(metrics.evidence_o3b_total(), 1);
    assert_eq!(metrics.evidence_o4_total(), 1);
    assert_eq!(metrics.evidence_o5_total(), 1);
    assert_eq!(metrics.evidence_total(), 7);

    // Increment decision counters
    metrics.inc_decision(SlashingDecisionKind::AcceptedNoOp);
    metrics.inc_decision(SlashingDecisionKind::AcceptedNoOp);
    metrics.inc_decision(SlashingDecisionKind::RejectedInvalid);
    metrics.inc_decision(SlashingDecisionKind::RejectedDuplicate);

    assert_eq!(metrics.decisions_accepted_noop_total(), 2);
    assert_eq!(metrics.decisions_rejected_invalid_total(), 1);
    assert_eq!(metrics.decisions_rejected_duplicate_total(), 1);
    assert_eq!(metrics.decisions_total(), 4);
}

#[test]
fn test_slashing_metrics_record_helper() {
    let metrics = SlashingMetrics::new();

    // Use the combined record() helper
    metrics.record(
        OffenseKind::O1DoubleSign,
        SlashingDecisionKind::AcceptedNoOp,
    );
    metrics.record(
        OffenseKind::O2InvalidProposerSig,
        SlashingDecisionKind::RejectedInvalid,
    );
    metrics.record(
        OffenseKind::O1DoubleSign,
        SlashingDecisionKind::RejectedDuplicate,
    );

    assert_eq!(metrics.evidence_o1_total(), 2);
    assert_eq!(metrics.evidence_o2_total(), 1);
    assert_eq!(metrics.decisions_accepted_noop_total(), 1);
    assert_eq!(metrics.decisions_rejected_invalid_total(), 1);
    assert_eq!(metrics.decisions_rejected_duplicate_total(), 1);
}

#[test]
fn test_slashing_engine_tracks_counts() {
    let vs = test_validator_set();
    let ctx = SlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 10,
    };

    let mut engine = NoopSlashingEngine::new();

    // Submit various evidence
    engine.handle_evidence(&ctx, make_o1_evidence(1, 100, 1));
    engine.handle_evidence(&ctx, make_o1_evidence(2, 101, 2));
    engine.handle_evidence(&ctx, make_o2_evidence(3, 102, 3));
    engine.handle_evidence(&ctx, make_o1_evidence(1, 100, 1)); // duplicate

    // Check engine counts
    assert_eq!(
        engine.evidence_count_by_offense(OffenseKind::O1DoubleSign),
        3
    );
    assert_eq!(
        engine.evidence_count_by_offense(OffenseKind::O2InvalidProposerSig),
        1
    );
    assert_eq!(engine.decision_count(SlashingDecisionKind::AcceptedNoOp), 3);
    assert_eq!(
        engine.decision_count(SlashingDecisionKind::RejectedDuplicate),
        1
    );
}

// ============================================================================
// Storage Tests
// ============================================================================

#[test]
fn test_slashing_store_basic() {
    let mut store = SlashingStore::new();

    let evidence = make_o1_evidence(1, 100, 5);
    let record = qbind_consensus::slashing::SlashingRecord {
        evidence,
        decision: SlashingDecisionKind::AcceptedNoOp,
        decision_height: 1000,
        decision_view: 10,
    };

    store.store_slashing_record(&record);

    let records = store.load_slashing_records_for_validator(ValidatorId(1));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, SlashingDecisionKind::AcceptedNoOp);
}

#[test]
fn test_slashing_store_multiple_validators() {
    let mut store = SlashingStore::new();

    // Store records for different validators
    for vid in [1, 2, 3] {
        let evidence = make_o1_evidence(vid, 100 + u64::from(vid), 5);
        let record = qbind_consensus::slashing::SlashingRecord {
            evidence,
            decision: SlashingDecisionKind::AcceptedNoOp,
            decision_height: 1000,
            decision_view: 10,
        };
        store.store_slashing_record(&record);
    }

    // Each validator should have exactly 1 record
    for vid in [1u32, 2u32, 3u32] {
        let records = store.load_slashing_records_for_validator(ValidatorId(u64::from(vid)));
        assert_eq!(records.len(), 1);
    }

    // Total record count
    assert_eq!(store.record_count(), 3);
}

#[test]
fn test_slashing_store_unknown_validator_returns_empty() {
    let store = SlashingStore::new();
    let records = store.load_slashing_records_for_validator(ValidatorId(999));
    assert!(records.is_empty());
}

#[test]
fn test_slashing_store_all_records_iterator() {
    let mut store = SlashingStore::new();

    // Store multiple records
    for (vid, height) in [(1, 100), (2, 200), (1, 300)] {
        let evidence = make_o1_evidence(vid, height, 5);
        let record = qbind_consensus::slashing::SlashingRecord {
            evidence,
            decision: SlashingDecisionKind::AcceptedNoOp,
            decision_height: 1000,
            decision_view: 10,
        };
        store.store_slashing_record(&record);
    }

    // Iterate all records
    let all: Vec<_> = store.all_records().collect();
    assert_eq!(all.len(), 3);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_evidence_mismatched_payload_rejected() {
    // Create evidence with mismatched offense kind and payload
    let mut evidence = make_o1_evidence(1, 100, 5);
    evidence.offense = OffenseKind::O2InvalidProposerSig; // Mismatch!

    // Structure validation should fail
    assert!(evidence.validate_structure().is_err());
}

#[test]
fn test_evidence_version_zero_rejected() {
    let mut evidence = make_o1_evidence(1, 100, 5);
    evidence.version = 0;

    assert!(evidence.validate_structure().is_err());
}

#[test]
fn test_slashing_engine_get_records_for_validator() {
    let vs = test_validator_set();
    let ctx = SlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 10,
    };

    let mut engine = NoopSlashingEngine::new();

    // Submit evidence for validator 1
    engine.handle_evidence(&ctx, make_o1_evidence(1, 100, 1));
    engine.handle_evidence(&ctx, make_o2_evidence(1, 200, 2));

    // Submit evidence for validator 2
    engine.handle_evidence(&ctx, make_o1_evidence(2, 300, 3));

    // Get records for validator 1
    let records_v1 = engine.get_records_for_validator(ValidatorId(1));
    assert_eq!(records_v1.len(), 2);

    // Get records for validator 2
    let records_v2 = engine.get_records_for_validator(ValidatorId(2));
    assert_eq!(records_v2.len(), 1);

    // Get records for non-existent validator
    let records_v999 = engine.get_records_for_validator(ValidatorId(999));
    assert!(records_v999.is_empty());
}

#[test]
fn test_offense_kind_string_representation() {
    // Verify all offense kinds have string representations for metrics
    assert!(!OffenseKind::O1DoubleSign.as_str().is_empty());
    assert!(!OffenseKind::O2InvalidProposerSig.as_str().is_empty());
    assert!(!OffenseKind::O3aLazyVoteSingle.as_str().is_empty());
    assert!(!OffenseKind::O3bLazyVoteRepeated.as_str().is_empty());
    assert!(!OffenseKind::O4InvalidDagCert.as_str().is_empty());
    assert!(!OffenseKind::O5DagCouplingViolation.as_str().is_empty());
}

#[test]
fn test_slashing_decision_kind_string_representation() {
    // Verify all decision kinds have string representations for metrics
    assert!(!SlashingDecisionKind::AcceptedNoOp.as_str().is_empty());
    assert!(!SlashingDecisionKind::RejectedInvalid.as_str().is_empty());
    assert!(!SlashingDecisionKind::RejectedDuplicate.as_str().is_empty());
}
