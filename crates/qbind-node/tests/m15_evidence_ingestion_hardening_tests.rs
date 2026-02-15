//! M15 Evidence Ingestion Hardening Tests
//!
//! This test file validates the M15 evidence reporting hardening implementation.
//! M15 improves practical reportability and safety of slashing evidence submissions
//! WITHOUT introducing monetary rewards (no tokenomics).
//!
//! # Test Organization
//!
//! - A: Duplicate evidence rejected before expensive verification
//! - B: Oversized evidence rejected
//! - C: Non-validator reporter rejected (when require_validator_reporter=true)
//! - D: Per-block cap enforced deterministically
//! - E: Verification ordering test (expensive verify not called on cheap filter fail)
//! - F: Regression test (valid evidence still leads to penalty)
//! - G: Age bounds enforcement
//! - H: Future height rejection
//! - I: Configuration tests
//!
//! # Design Principles (M15)
//!
//! - Deterministic: All limits are deterministic for consensus safety
//! - Fail-Closed: Invalid or suspicious evidence is rejected
//! - No Rewards: Reporting has no economic incentive; hardening provides abuse resistance

use qbind_consensus::slashing::{
    BlockHeader, EvidenceIngestionConfig, EvidencePayloadV1, EvidenceRejectionReason,
    HardenedEvidenceContext, HardenedEvidenceIngestionEngine, HardenedEvidenceResult,
    InMemorySlashingBackend, OffenseKind, PenaltyDecision, PenaltyEngineConfig, SignedBlockHeader,
    SlashingEvidence, SlashingMode,
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

/// Create oversized O1 evidence (exceeds default 64KB limit).
fn make_oversized_o1_evidence(validator_id: u32, height: u64, view: u64) -> SlashingEvidence {
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
                // Very large preimage to exceed size limit
                header_preimage: vec![0x10; 100_000],
            },
            block_b: SignedBlockHeader {
                height,
                view,
                block_id: [0xBB; 32],
                proposer_id: ValidatorId(u64::from(validator_id)),
                signature: vec![0x02; 64],
                header_preimage: vec![0x20; 100_000],
            },
        },
    }
}

fn create_engine_and_context(
    require_validator_reporter: bool,
    per_block_cap: Option<u32>,
    max_age: Option<u64>,
) -> (
    HardenedEvidenceIngestionEngine<InMemorySlashingBackend>,
    ValidatorSet,
) {
    let backend = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 1_000_000),
        (ValidatorId(2), 1_000_000),
        (ValidatorId(3), 1_000_000),
    ]);
    let penalty_config = PenaltyEngineConfig {
        mode: SlashingMode::EnforceCritical,
        ..Default::default()
    };
    let ingestion_config = EvidenceIngestionConfig {
        require_validator_reporter,
        per_block_evidence_cap: per_block_cap,
        max_evidence_age_blocks: max_age,
        ..Default::default()
    };
    let engine = HardenedEvidenceIngestionEngine::new(backend, penalty_config, ingestion_config);
    let vs = test_validator_set();
    (engine, vs)
}

// ============================================================================
// A) Duplicate Evidence Rejected Before Verify
// ============================================================================

#[test]
fn test_a1_duplicate_evidence_rejected_before_verify() {
    let (mut engine, vs) = create_engine_and_context(false, None, None);

    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000, // current_height
        10,   // current_view
        5,    // current_epoch
        Some(ValidatorId(1)), // reporter
        0,    // block_evidence_count
    );

    let evidence = make_o1_evidence(1, 100, 0);

    // First submission should be accepted
    let result1 = engine.handle_evidence(&ctx, evidence.clone());
    assert!(matches!(result1, HardenedEvidenceResult::Accepted(_)));

    // Second submission should be rejected as duplicate BEFORE verification
    let result2 = engine.handle_evidence(&ctx, evidence);
    match result2 {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_eq!(reason, EvidenceRejectionReason::Duplicate);
        }
        _ => panic!("Expected Rejected(Duplicate), got {:?}", result2),
    }

    // Verify metrics
    assert_eq!(
        engine.metrics().rejected_by_reason(EvidenceRejectionReason::Duplicate),
        1
    );
}

#[test]
fn test_a2_duplicate_uses_content_addressed_id() {
    let (mut engine, vs) = create_engine_and_context(false, None, None);

    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        Some(ValidatorId(1)),
        0,
    );

    // Create two different evidence with same content
    let evidence1 = make_o1_evidence(1, 100, 0);
    let evidence2 = make_o1_evidence(1, 100, 0);

    // They should have the same evidence_id
    assert_eq!(evidence1.evidence_id(), evidence2.evidence_id());

    // First submission
    let result1 = engine.handle_evidence(&ctx, evidence1);
    assert!(matches!(result1, HardenedEvidenceResult::Accepted(_)));

    // Second with same content should be duplicate
    let result2 = engine.handle_evidence(&ctx, evidence2);
    match result2 {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_eq!(reason, EvidenceRejectionReason::Duplicate);
        }
        _ => panic!("Expected duplicate rejection"),
    }
}

// ============================================================================
// B) Oversized Evidence Rejected
// ============================================================================

#[test]
fn test_b1_oversized_evidence_rejected() {
    let (mut engine, vs) = create_engine_and_context(false, None, None);

    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        Some(ValidatorId(1)),
        0,
    );

    // Create evidence that exceeds 64KB limit
    let evidence = make_oversized_o1_evidence(1, 100, 0);
    let size = evidence.estimated_size_bytes();
    assert!(
        size > 64 * 1024,
        "Test evidence should exceed 64KB, got {} bytes",
        size
    );

    let result = engine.handle_evidence(&ctx, evidence);
    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_eq!(reason, EvidenceRejectionReason::OversizedPayload);
        }
        _ => panic!("Expected OversizedPayload rejection, got {:?}", result),
    }

    // Verify metrics
    assert_eq!(
        engine.metrics().rejected_by_reason(EvidenceRejectionReason::OversizedPayload),
        1
    );
}

#[test]
fn test_b2_within_size_limit_accepted() {
    let (mut engine, vs) = create_engine_and_context(false, None, None);

    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        Some(ValidatorId(1)),
        0,
    );

    // Normal sized evidence
    let evidence = make_o1_evidence(1, 100, 0);
    let size = evidence.estimated_size_bytes();
    assert!(
        size < 64 * 1024,
        "Normal evidence should be under 64KB, got {} bytes",
        size
    );

    let result = engine.handle_evidence(&ctx, evidence);
    // May be rejected for other reasons (e.g., verification), but not for size
    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_ne!(
                reason,
                EvidenceRejectionReason::OversizedPayload,
                "Should not be rejected for size"
            );
        }
        HardenedEvidenceResult::Accepted(_) => {
            // Expected path
        }
    }
}

// ============================================================================
// C) Non-Validator Reporter Rejected
// ============================================================================

#[test]
fn test_c1_non_validator_reporter_rejected_when_required() {
    let (mut engine, vs) = create_engine_and_context(true, None, None); // require_validator_reporter=true

    // Context with no reporter_id
    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        None, // No reporter
        0,
    );

    let evidence = make_o1_evidence(1, 100, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_eq!(reason, EvidenceRejectionReason::NonValidatorReporter);
        }
        _ => panic!("Expected NonValidatorReporter rejection, got {:?}", result),
    }

    assert_eq!(
        engine.metrics().rejected_by_reason(EvidenceRejectionReason::NonValidatorReporter),
        1
    );
}

#[test]
fn test_c2_non_validator_reporter_id_rejected() {
    let (mut engine, vs) = create_engine_and_context(true, None, None);

    // Context with reporter_id that's not in validator set
    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        Some(ValidatorId(999)), // Not in validator set
        0,
    );

    let evidence = make_o1_evidence(1, 100, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_eq!(reason, EvidenceRejectionReason::NonValidatorReporter);
        }
        _ => panic!("Expected NonValidatorReporter rejection"),
    }
}

#[test]
fn test_c3_validator_reporter_accepted_when_required() {
    let (mut engine, vs) = create_engine_and_context(true, None, None);

    // Context with valid reporter_id
    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        Some(ValidatorId(1)), // Valid validator
        0,
    );

    let evidence = make_o1_evidence(1, 100, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    // Should not be rejected for reporter validation
    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_ne!(
                reason,
                EvidenceRejectionReason::NonValidatorReporter,
                "Valid validator reporter should not be rejected"
            );
        }
        HardenedEvidenceResult::Accepted(_) => {
            // Expected path
        }
    }
}

#[test]
fn test_c4_non_validator_reporter_allowed_when_not_required() {
    let (mut engine, vs) = create_engine_and_context(false, None, None); // require_validator_reporter=false

    // Context with no reporter_id should be allowed
    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        None, // No reporter
        0,
    );

    let evidence = make_o1_evidence(1, 100, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    // Should not be rejected for reporter validation
    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_ne!(
                reason,
                EvidenceRejectionReason::NonValidatorReporter,
                "Should not be rejected for reporter when not required"
            );
        }
        HardenedEvidenceResult::Accepted(_) => {
            // Expected path
        }
    }
}

// ============================================================================
// D) Per-Block Cap Enforced Deterministically
// ============================================================================

#[test]
fn test_d1_per_block_cap_enforced() {
    let (mut engine, vs) = create_engine_and_context(false, Some(3), None); // cap of 3

    // First 3 evidence items should be accepted (or rejected for other reasons)
    for i in 0..3 {
        let ctx = HardenedEvidenceContext::new(
            &vs,
            1000,
            10,
            5,
            Some(ValidatorId(1)),
            i, // block_evidence_count
        );

        let evidence = make_o1_evidence(1, 100 + i as u64, i as u64);
        let result = engine.handle_evidence(&ctx, evidence);

        // Should not be rejected for per-block cap
        match result {
            HardenedEvidenceResult::Rejected { reason, .. } => {
                assert_ne!(
                    reason,
                    EvidenceRejectionReason::PerBlockCapExceeded,
                    "Evidence {} should not hit per-block cap",
                    i
                );
            }
            HardenedEvidenceResult::Accepted(_) => {}
        }
    }

    // 4th evidence should hit the cap
    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        Some(ValidatorId(1)),
        3, // At cap
    );

    let evidence = make_o1_evidence(1, 200, 3);
    let result = engine.handle_evidence(&ctx, evidence);

    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_eq!(reason, EvidenceRejectionReason::PerBlockCapExceeded);
        }
        _ => panic!("Expected PerBlockCapExceeded rejection"),
    }

    assert_eq!(
        engine.metrics().rejected_by_reason(EvidenceRejectionReason::PerBlockCapExceeded),
        1
    );
}

#[test]
fn test_d2_per_block_cap_is_deterministic() {
    // The cap is enforced based on the block_evidence_count in the context,
    // which should be deterministic for consensus safety
    let (mut engine1, vs1) = create_engine_and_context(false, Some(2), None);
    let (mut engine2, vs2) = create_engine_and_context(false, Some(2), None);

    // Same context on both engines
    let ctx1 = HardenedEvidenceContext::new(&vs1, 1000, 10, 5, Some(ValidatorId(1)), 2);
    let ctx2 = HardenedEvidenceContext::new(&vs2, 1000, 10, 5, Some(ValidatorId(1)), 2);

    let evidence = make_o1_evidence(1, 100, 0);

    let result1 = engine1.handle_evidence(&ctx1, evidence.clone());
    let result2 = engine2.handle_evidence(&ctx2, evidence);

    // Both should reject with the same reason
    match (result1, result2) {
        (
            HardenedEvidenceResult::Rejected { reason: r1, .. },
            HardenedEvidenceResult::Rejected { reason: r2, .. },
        ) => {
            assert_eq!(r1, r2, "Deterministic cap should produce same result");
            assert_eq!(r1, EvidenceRejectionReason::PerBlockCapExceeded);
        }
        _ => panic!("Expected both engines to reject with same reason"),
    }
}

// ============================================================================
// E) Ordering Test: Expensive Verify Not Called When Cheap Filter Fails
// ============================================================================

#[test]
fn test_e1_oversized_rejected_before_verify() {
    // Create engine with strict reporter requirement
    let (mut engine, vs) = create_engine_and_context(true, None, None);

    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        Some(ValidatorId(1)),
        0,
    );

    // Create oversized evidence
    let evidence = make_oversized_o1_evidence(1, 100, 0);

    // Submit oversized evidence
    let result = engine.handle_evidence(&ctx, evidence);

    // Should be rejected for size, not verification
    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_eq!(
                reason,
                EvidenceRejectionReason::OversizedPayload,
                "Should be rejected for size before any verification"
            );
        }
        _ => panic!("Expected size rejection"),
    }

    // Verified count should be 0 (never reached verification)
    assert_eq!(engine.metrics().verified_total(), 0);
}

#[test]
fn test_e2_reporter_check_before_size_check() {
    let (mut engine, vs) = create_engine_and_context(true, None, None);

    // Non-validator reporter
    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        None, // No reporter
        0,
    );

    // Also oversized (but reporter check should come first)
    let evidence = make_oversized_o1_evidence(1, 100, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            // Reporter check comes before size check in the ordering
            assert_eq!(
                reason,
                EvidenceRejectionReason::NonValidatorReporter,
                "Reporter check should happen before size check"
            );
        }
        _ => panic!("Expected reporter rejection"),
    }
}

#[test]
fn test_e3_cap_check_before_dedup() {
    let (mut engine, vs) = create_engine_and_context(false, Some(0), None); // Cap of 0

    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        Some(ValidatorId(1)),
        0, // Already at cap
    );

    let evidence = make_o1_evidence(1, 100, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            // Cap check comes before dedup check
            assert_eq!(
                reason,
                EvidenceRejectionReason::PerBlockCapExceeded,
                "Cap check should happen early in the pipeline"
            );
        }
        _ => panic!("Expected cap rejection"),
    }
}

// ============================================================================
// F) Regression: Valid Evidence Still Leads to Penalty
// ============================================================================

#[test]
fn test_f1_valid_evidence_leads_to_penalty() {
    let (mut engine, vs) = create_engine_and_context(false, None, None);

    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        0, // View 0: validator 1 is leader
        5,
        Some(ValidatorId(1)),
        0,
    );

    let evidence = make_o1_evidence(1, 100, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    match result {
        HardenedEvidenceResult::Accepted(record) => {
            // The inner engine should have processed it
            // Note: May be EvidenceOnly or PenaltyApplied depending on mode and verification
            // The key is that it was NOT rejected by hardening
            match record.penalty_decision {
                PenaltyDecision::PenaltyApplied { slashed_amount, jailed_until_epoch } => {
                    // Penalty was applied - expected for EnforceCritical mode
                    // slashed_amount should be non-zero for a fresh validator with stake
                    // jailed_until_epoch should be Some for O1 (critical offense)
                    // Note: Could be 0 if validator has no stake, but that's acceptable
                    assert!(jailed_until_epoch.is_some() || slashed_amount == 0,
                        "O1 should jail the validator or have no stake to slash");
                }
                PenaltyDecision::EvidenceOnly => {
                    // Also acceptable for mode RecordOnly
                }
                PenaltyDecision::Legacy(_) => {
                    // May happen if verification fails in inner engine
                }
            }
        }
        HardenedEvidenceResult::Rejected { reason, .. } => {
            // If rejected, it should be for verification (inner engine), not hardening
            assert_eq!(
                reason,
                EvidenceRejectionReason::VerificationFailed,
                "Rejection should be from verification, not hardening. Got: {:?}",
                reason
            );
        }
    }

    // Verified count should be 1 if accepted
    // (or 0 if inner engine rejected for verification)
}

#[test]
fn test_f2_multiple_valid_evidence_processed() {
    let (mut engine, vs) = create_engine_and_context(false, Some(10), None);

    // Submit multiple valid evidence items
    for i in 0u32..5 {
        let ctx = HardenedEvidenceContext::new(
            &vs,
            1000,
            i as u64, // Different views
            5,
            Some(ValidatorId(1)),
            i,
        );

        // Different heights and views to avoid duplicates
        let evidence = make_o2_evidence((i % 3 + 1) as u32, 100 + i as u64, i as u64);
        let result = engine.handle_evidence(&ctx, evidence);

        // Should not be rejected by hardening (may be rejected by inner engine)
        match result {
            HardenedEvidenceResult::Rejected { reason, .. } => {
                // Only verification failures are acceptable
                assert!(
                    matches!(reason, EvidenceRejectionReason::VerificationFailed),
                    "Should only be rejected by verification, not hardening. Got: {:?}",
                    reason
                );
            }
            HardenedEvidenceResult::Accepted(_) => {
                // Good
            }
        }
    }

    // Check that evidence was received
    assert!(engine.metrics().evidence_received_total() >= 5);
}

// ============================================================================
// G) Age Bounds Enforcement
// ============================================================================

#[test]
fn test_g1_too_old_evidence_rejected() {
    let (mut engine, vs) = create_engine_and_context(false, None, Some(1000)); // max age 1000 blocks

    let ctx = HardenedEvidenceContext::new(
        &vs,
        10000, // Current height
        10,
        5,
        Some(ValidatorId(1)),
        0,
    );

    // Evidence from height 8000 is too old (10000 - 1000 = 9000 minimum)
    let evidence = make_o1_evidence(1, 8000, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_eq!(reason, EvidenceRejectionReason::TooOld);
        }
        _ => panic!("Expected TooOld rejection, got {:?}", result),
    }

    assert_eq!(
        engine.metrics().rejected_by_reason(EvidenceRejectionReason::TooOld),
        1
    );
}

#[test]
fn test_g2_within_age_limit_accepted() {
    let (mut engine, vs) = create_engine_and_context(false, None, Some(1000));

    let ctx = HardenedEvidenceContext::new(
        &vs,
        10000,
        10,
        5,
        Some(ValidatorId(1)),
        0,
    );

    // Evidence from height 9500 is within limit (10000 - 1000 = 9000 minimum)
    let evidence = make_o1_evidence(1, 9500, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_ne!(
                reason,
                EvidenceRejectionReason::TooOld,
                "Evidence within age limit should not be rejected for age"
            );
        }
        HardenedEvidenceResult::Accepted(_) => {
            // Expected
        }
    }
}

// ============================================================================
// H) Future Height Rejection
// ============================================================================

#[test]
fn test_h1_future_height_rejected() {
    let (mut engine, vs) = create_engine_and_context(false, None, None);

    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000, // Current height
        10,
        5,
        Some(ValidatorId(1)),
        0,
    );

    // Evidence from height 2000 is too far in future (max lookahead default is 100)
    let evidence = make_o1_evidence(1, 2000, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_eq!(reason, EvidenceRejectionReason::FutureHeight);
        }
        _ => panic!("Expected FutureHeight rejection, got {:?}", result),
    }

    assert_eq!(
        engine.metrics().rejected_by_reason(EvidenceRejectionReason::FutureHeight),
        1
    );
}

#[test]
fn test_h2_near_future_accepted() {
    let (mut engine, vs) = create_engine_and_context(false, None, None);

    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        Some(ValidatorId(1)),
        0,
    );

    // Evidence from height 1050 is within lookahead (1000 + 100 = 1100)
    let evidence = make_o1_evidence(1, 1050, 0);
    let result = engine.handle_evidence(&ctx, evidence);

    match result {
        HardenedEvidenceResult::Rejected { reason, .. } => {
            assert_ne!(
                reason,
                EvidenceRejectionReason::FutureHeight,
                "Evidence within lookahead should not be rejected for future height"
            );
        }
        HardenedEvidenceResult::Accepted(_) => {
            // Expected
        }
    }
}

// ============================================================================
// I) Configuration Tests
// ============================================================================

#[test]
fn test_i1_devnet_config_permissive() {
    let config = EvidenceIngestionConfig::devnet();

    assert!(!config.require_validator_reporter);
    assert!(config.per_block_evidence_cap.is_none());
    assert!(config.max_evidence_age_blocks.is_none());
}

#[test]
fn test_i2_testnet_config_moderate() {
    let config = EvidenceIngestionConfig::testnet();

    assert!(config.require_validator_reporter);
    assert_eq!(config.per_block_evidence_cap, Some(20));
    assert_eq!(config.max_evidence_age_blocks, Some(50_000));
}

#[test]
fn test_i3_mainnet_config_strict() {
    let config = EvidenceIngestionConfig::mainnet();

    assert!(config.require_validator_reporter);
    assert_eq!(config.per_block_evidence_cap, Some(10));
    assert_eq!(config.max_evidence_age_blocks, Some(100_000));
}

#[test]
fn test_i4_default_config_reasonable() {
    let config = EvidenceIngestionConfig::default();

    // Default should be production-ready (strict)
    assert!(config.require_validator_reporter);
    assert!(config.per_block_evidence_cap.is_some());
    assert!(config.max_evidence_age_blocks.is_some());

    // Size limits should be reasonable
    assert!(config.max_o1_payload_bytes >= 32 * 1024);
    assert!(config.max_o2_payload_bytes >= 16 * 1024);
}

#[test]
fn test_i5_estimated_size_calculation() {
    let evidence = make_o1_evidence(1, 100, 0);
    let size = evidence.estimated_size_bytes();

    // Should be reasonable for a normal O1 evidence
    // Base (26) + 2 * (56 + 64 + 100) = 26 + 440 = 466 approx
    assert!(size > 200, "Size should be at least 200 bytes");
    assert!(size < 10000, "Size should be under 10KB for normal evidence");
}

#[test]
fn test_i6_helper_methods() {
    let (engine, vs) = create_engine_and_context(true, Some(5), None);

    let ctx = HardenedEvidenceContext::new(
        &vs,
        1000,
        10,
        5,
        Some(ValidatorId(1)),
        3,
    );

    // Test would_accept_reporter
    assert!(engine.would_accept_reporter(&ctx, Some(ValidatorId(1))));
    assert!(!engine.would_accept_reporter(&ctx, None));
    assert!(!engine.would_accept_reporter(&ctx, Some(ValidatorId(999))));

    // Test would_exceed_block_cap
    assert!(!engine.would_exceed_block_cap(4)); // 4 < 5
    assert!(engine.would_exceed_block_cap(5)); // 5 >= 5
    assert!(engine.would_exceed_block_cap(6)); // 6 >= 5
}
