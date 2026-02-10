//! T230 Slashing Ledger Backend Integration Tests
//!
//! This test file validates the integration of the slashing ledger backend
//! with the penalty slashing engine introduced in T230. These tests ensure:
//!
//! - LedgerSlashingBackend correctly implements SlashingBackend trait
//! - Integration with PenaltySlashingEngine works correctly
//! - Slashing records are properly persisted in the ledger
//! - SlashingMetrics are correctly updated when penalties are applied
//!
//! # Test Organization
//!
//! - LedgerSlashingBackend unit tests (more in ledger_slashing_backend.rs)
//! - Integration tests with PenaltySlashingEngine
//! - End-to-end penalty application tests

use qbind_consensus::slashing::{
    BlockHeader, EvidencePayloadV1, OffenseKind, PenaltyDecision, PenaltyEngineConfig,
    PenaltySlashingContext, PenaltySlashingEngine, SignedBlockHeader, SlashingBackend,
    SlashingEvidence, SlashingMode,
};
use qbind_consensus::{ValidatorId, ValidatorInfo, ValidatorSet};
use qbind_ledger::InMemorySlashingLedger;
use qbind_node::ledger_slashing_backend::LedgerSlashingBackend;
use qbind_node::metrics::SlashingMetrics;

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

fn make_context(validator_set: &ValidatorSet, current_epoch: u64) -> PenaltySlashingContext<'_> {
    PenaltySlashingContext {
        validator_set,
        current_height: 1000,
        current_view: 100,
        current_epoch,
    }
}

// ============================================================================
// LedgerSlashingBackend Integration Tests
// ============================================================================

#[test]
fn test_ledger_backend_with_penalty_engine_o1() {
    // Create ledger with initial stakes
    let ledger =
        InMemorySlashingLedger::with_stakes(vec![(1, 1_000_000), (2, 2_000_000), (3, 3_000_000)]);

    // Create backend and engine with EnforceCritical mode
    let backend = LedgerSlashingBackend::new(ledger);
    let config = PenaltyEngineConfig::devnet(); // EnforceCritical mode
    let mut engine = PenaltySlashingEngine::new(backend, config);

    let vs = test_validator_set();
    let ctx = make_context(&vs, 10);

    // Submit O1 evidence for validator 1
    let evidence = make_o1_evidence(1, 100, 50);
    let record = engine.handle_evidence(&ctx, evidence);

    // Verify penalty was applied
    assert!(
        matches!(
            record.penalty_decision,
            PenaltyDecision::PenaltyApplied { .. }
        ),
        "Expected PenaltyApplied, got {:?}",
        record.penalty_decision
    );

    if let PenaltyDecision::PenaltyApplied {
        slashed_amount,
        jailed_until_epoch,
    } = &record.penalty_decision
    {
        // 1_000_000 * 750 / 10000 = 75_000
        assert_eq!(*slashed_amount, 75_000);
        // Jailed for 10 epochs starting from epoch 10
        assert_eq!(*jailed_until_epoch, Some(20));
    }

    // Verify stake was reduced in ledger
    assert_eq!(engine.backend().get_stake(ValidatorId(1)), Some(925_000));

    // Verify validator is jailed in ledger
    assert!(engine.backend().is_jailed(ValidatorId(1)));
}

#[test]
fn test_ledger_backend_with_penalty_engine_o2() {
    let ledger = InMemorySlashingLedger::with_stakes(vec![(2, 500_000)]);

    let backend = LedgerSlashingBackend::new(ledger);
    let config = PenaltyEngineConfig::devnet();
    let mut engine = PenaltySlashingEngine::new(backend, config);

    let vs = test_validator_set();
    let ctx = make_context(&vs, 5);

    // Submit O2 evidence for validator 2
    let evidence = make_o2_evidence(2, 200, 80);
    let record = engine.handle_evidence(&ctx, evidence);

    if let PenaltyDecision::PenaltyApplied {
        slashed_amount,
        jailed_until_epoch,
    } = &record.penalty_decision
    {
        // 500_000 * 500 / 10000 = 25_000
        assert_eq!(*slashed_amount, 25_000);
        // Jailed for 5 epochs starting from epoch 5
        assert_eq!(*jailed_until_epoch, Some(10));
    }

    // Verify stake was reduced
    assert_eq!(engine.backend().get_stake(ValidatorId(2)), Some(475_000));
}

#[test]
fn test_ledger_backend_record_only_mode() {
    let ledger = InMemorySlashingLedger::with_stakes(vec![(1, 1_000_000)]);

    let backend = LedgerSlashingBackend::new(ledger);
    let config = PenaltyEngineConfig::record_only();
    let mut engine = PenaltySlashingEngine::new(backend, config);

    let vs = test_validator_set();
    let ctx = make_context(&vs, 10);

    // Submit O1 evidence
    let evidence = make_o1_evidence(1, 100, 50);
    let record = engine.handle_evidence(&ctx, evidence);

    // In RecordOnly mode, should get EvidenceOnly decision
    assert!(
        matches!(record.penalty_decision, PenaltyDecision::EvidenceOnly),
        "Expected EvidenceOnly in RecordOnly mode, got {:?}",
        record.penalty_decision
    );

    // Verify stake was NOT reduced
    assert_eq!(engine.backend().get_stake(ValidatorId(1)), Some(1_000_000));

    // Verify validator is NOT jailed
    assert!(!engine.backend().is_jailed(ValidatorId(1)));
}

#[test]
fn test_ledger_backend_multiple_penalties() {
    let ledger = InMemorySlashingLedger::with_stakes(vec![(1, 1_000_000)]);

    let backend = LedgerSlashingBackend::new(ledger);
    let config = PenaltyEngineConfig::devnet();
    let mut engine = PenaltySlashingEngine::new(backend, config);

    let vs = test_validator_set();
    let ctx = make_context(&vs, 10);

    // First penalty: O1 at height 100
    let evidence1 = make_o1_evidence(1, 100, 50);
    engine.handle_evidence(&ctx, evidence1);

    // After O1: stake = 1_000_000 - 75_000 = 925_000
    assert_eq!(engine.backend().get_stake(ValidatorId(1)), Some(925_000));

    // Second penalty: O2 at height 200 (different evidence)
    let evidence2 = make_o2_evidence(1, 200, 80);
    engine.handle_evidence(&ctx, evidence2);

    // After O2: stake = 925_000 - 46_250 = 878_750
    assert_eq!(engine.backend().get_stake(ValidatorId(1)), Some(878_750));
}

#[test]
fn test_ledger_backend_persists_records() {
    let ledger = InMemorySlashingLedger::with_stakes(vec![(1, 1_000_000), (2, 2_000_000)]);

    let mut backend = LedgerSlashingBackend::new(ledger);

    // Manually store a record
    backend
        .store_record(
            ValidatorId(1),
            OffenseKind::O1DoubleSign,
            75_000,
            true,
            Some(20),
            1000,
            100,
            10,
        )
        .unwrap();

    backend
        .store_record(
            ValidatorId(2),
            OffenseKind::O2InvalidProposerSig,
            100_000,
            false,
            None,
            2000,
            200,
            15,
        )
        .unwrap();

    // Retrieve records
    let records_1 = backend.get_records_for_validator(ValidatorId(1));
    assert_eq!(records_1.len(), 1);
    assert_eq!(records_1[0].validator_id, 1);
    assert_eq!(records_1[0].offense_kind, "O1_double_sign");
    assert_eq!(records_1[0].slashed_amount, 75_000);
    assert!(records_1[0].jailed);

    let records_2 = backend.get_records_for_validator(ValidatorId(2));
    assert_eq!(records_2.len(), 1);
    assert_eq!(records_2[0].offense_kind, "O2_invalid_proposer_sig");
    assert!(!records_2[0].jailed);

    // Get all records
    let all = backend.get_all_records();
    assert_eq!(all.len(), 2);
}

// ============================================================================
// SlashingMetrics Tests
// ============================================================================

#[test]
fn test_slashing_metrics_evidence_counters() {
    let metrics = SlashingMetrics::new();

    // Increment evidence counters
    metrics.inc_evidence_o1();
    metrics.inc_evidence_o1();
    metrics.inc_evidence_o2();
    metrics.inc_evidence_o3a();

    assert_eq!(metrics.evidence_o1_total(), 2);
    assert_eq!(metrics.evidence_o2_total(), 1);
    assert_eq!(metrics.evidence_total(), 4);
}

#[test]
fn test_slashing_metrics_penalty_counters() {
    let metrics = SlashingMetrics::new();

    metrics.inc_penalty_o1();
    metrics.inc_penalty_o2();
    metrics.inc_penalty_o2();

    assert_eq!(metrics.penalty_o1_total(), 1);
    assert_eq!(metrics.penalty_o2_total(), 2);
    assert_eq!(metrics.penalty_total(), 3);
}

#[test]
fn test_slashing_metrics_stake_and_jail() {
    let metrics = SlashingMetrics::new();

    metrics.add_stake_burned(100_000);
    metrics.add_stake_burned(50_000);
    metrics.inc_jail_event();
    metrics.inc_jail_event();
    metrics.inc_jail_event();

    assert_eq!(metrics.total_stake_burned(), 150_000);
    assert_eq!(metrics.total_jail_events(), 3);
}

#[test]
fn test_slashing_metrics_mode() {
    let metrics = SlashingMetrics::new();

    // Default is 0 (Off)
    assert_eq!(metrics.current_mode(), 0);
    assert_eq!(metrics.current_mode_str(), "off");

    // Set to RecordOnly
    metrics.set_mode(1);
    assert_eq!(metrics.current_mode_str(), "record_only");

    // Set to EnforceCritical
    metrics.set_mode(2);
    assert_eq!(metrics.current_mode_str(), "enforce_critical");

    // Set to EnforceAll
    metrics.set_mode(3);
    assert_eq!(metrics.current_mode_str(), "enforce_all");
}

#[test]
fn test_slashing_metrics_prometheus_format() {
    let metrics = SlashingMetrics::new();

    metrics.inc_evidence_o1();
    metrics.inc_penalty_o1();
    metrics.add_stake_burned(75_000);
    metrics.inc_jail_event();
    metrics.set_mode(2);

    let output = metrics.format_metrics();

    // Verify Prometheus format contains expected lines
    assert!(output.contains("qbind_slashing_evidence_total{offense=\"O1_double_sign\"} 1"));
    assert!(output.contains("qbind_slashing_penalty_total{offense=\"O1_double_sign\"} 1"));
    assert!(output.contains("qbind_slashing_stake_burned_total 75000"));
    assert!(output.contains("qbind_slashing_jail_events_total 1"));
    assert!(output.contains("qbind_slashing_mode_info{mode=\"enforce_critical\"} 1"));
}

#[test]
fn test_slashing_metrics_rejection_counters() {
    let metrics = SlashingMetrics::new();

    metrics.inc_rejected_invalid();
    metrics.inc_rejected_invalid();
    metrics.inc_rejected_duplicate();

    assert_eq!(metrics.rejected_invalid_total(), 2);
    assert_eq!(metrics.rejected_duplicate_total(), 1);
}

// ============================================================================
// End-to-End Integration Tests
// ============================================================================

#[test]
fn test_end_to_end_penalty_workflow() {
    // This test simulates a complete penalty application workflow:
    // 1. Create ledger with validator stakes
    // 2. Create penalty engine in EnforceCritical mode
    // 3. Submit O1 double-signing evidence
    // 4. Verify penalty is applied
    // 5. Verify metrics are updated
    // 6. Verify records are persisted

    // Step 1: Create ledger
    let ledger = InMemorySlashingLedger::with_stakes(vec![
        (1, 10_000_000), // 10M stake
    ]);

    // Step 2: Create engine
    let backend = LedgerSlashingBackend::new(ledger);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o1: 750, // 7.5%
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
        current_height: 5000,
        current_view: 500,
        current_epoch: 100,
    };

    // Step 3: Submit O1 evidence
    let evidence = make_o1_evidence(1, 4990, 490);
    let record = engine.handle_evidence(&ctx, evidence);

    // Step 4: Verify penalty applied
    match &record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            // Expected slash: 10_000_000 * 750 / 10000 = 750_000
            assert_eq!(*slashed_amount, 750_000);
            // Expected jail until: 100 + 10 = 110
            assert_eq!(*jailed_until_epoch, Some(110));
        }
        other => panic!("Expected PenaltyApplied, got {:?}", other),
    }

    // Step 5: Verify engine counters
    assert_eq!(engine.total_stake_slashed(), 750_000);
    assert_eq!(engine.total_jail_events(), 1);
    assert_eq!(engine.penalty_count(OffenseKind::O1DoubleSign), 1);
    assert_eq!(engine.evidence_count(OffenseKind::O1DoubleSign), 1);

    // Step 6: Verify ledger state
    assert_eq!(
        engine.backend().get_stake(ValidatorId(1)),
        Some(9_250_000) // 10M - 750K
    );
    assert!(engine.backend().is_jailed(ValidatorId(1)));

    // Verify records
    let records = engine.get_records_for_validator(ValidatorId(1));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].evidence.offense, OffenseKind::O1DoubleSign);
}

#[test]
fn test_mainnet_record_only_workflow() {
    // Simulates MainNet behavior where mode is RecordOnly
    // Penalties should NOT be applied, but evidence should be recorded

    let ledger = InMemorySlashingLedger::with_stakes(vec![(1, 10_000_000)]);

    let backend = LedgerSlashingBackend::new(ledger);
    let config = PenaltyEngineConfig::record_only(); // MainNet default
    let mut engine = PenaltySlashingEngine::new(backend, config);

    let vs = test_validator_set();
    let ctx = make_context(&vs, 50);

    // Submit evidence
    let evidence = make_o1_evidence(1, 1000, 100);
    let record = engine.handle_evidence(&ctx, evidence);

    // Verify no penalty applied
    assert!(
        matches!(record.penalty_decision, PenaltyDecision::EvidenceOnly),
        "MainNet should use EvidenceOnly"
    );

    // Verify stake unchanged
    assert_eq!(engine.backend().get_stake(ValidatorId(1)), Some(10_000_000));

    // Verify not jailed
    assert!(!engine.backend().is_jailed(ValidatorId(1)));

    // But evidence is recorded
    assert_eq!(engine.evidence_count(OffenseKind::O1DoubleSign), 1);

    // No penalty counters
    assert_eq!(engine.penalty_count(OffenseKind::O1DoubleSign), 0);
    assert_eq!(engine.total_stake_slashed(), 0);
}
