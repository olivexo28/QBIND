//! T229 Slashing Penalty Engine Tests
//!
//! This test file validates the slashing penalty engine infrastructure
//! introduced in T229. These tests ensure that:
//!
//! - Slashing modes (Off/RecordOnly/EnforceCritical/EnforceAll) work correctly
//! - O1 and O2 offenses trigger penalties when mode is EnforceCritical
//! - O3/O4/O5 are enforced in EnforceCritical mode (M11)
//! - InMemorySlashingBackend correctly applies slashes and jails
//! - SlashingConfig validation works for MainNet invariants
//!
//! # Test Organization
//!
//! - Slashing mode configuration tests
//! - SlashingConfig validation tests
//! - InMemorySlashingBackend unit tests
//! - PenaltySlashingEngine mode gating tests
//! - Integration-style tests with fake backend

use qbind_consensus::slashing::{
    BlockHeader, EvidencePayloadV1, InMemorySlashingBackend, OffenseKind, PenaltyDecision,
    PenaltyEngineConfig, PenaltySlashingContext, PenaltySlashingEngine, PenaltySlashingMetrics,
    SignedBlockHeader, SlashingBackend, SlashingBackendError, SlashingEvidence, SlashingMode,
};
use qbind_consensus::{ValidatorId, ValidatorInfo, ValidatorSet};
use qbind_node::node_config::{
    MainnetConfigError, NodeConfig, SlashingConfig, SlashingMode as NodeSlashingMode,
};

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
    use qbind_consensus::slashing::{LazyVoteInvalidReason, SignedVote};

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

fn test_penalty_context(vs: &ValidatorSet) -> PenaltySlashingContext<'_> {
    PenaltySlashingContext {
        validator_set: vs,
        current_height: 1000,
        current_view: 10,
        current_epoch: 100,
    }
}

// ============================================================================
// SlashingConfig Tests
// ============================================================================

#[test]
fn test_slashing_config_devnet_default() {
    let config = SlashingConfig::devnet_default();
    assert_eq!(config.mode, NodeSlashingMode::EnforceCritical);
    assert_eq!(config.slash_bps_o1_double_sign, 750);
    assert_eq!(config.slash_bps_o2_invalid_proposer_sig, 500);
    assert!(config.jail_on_o1);
    assert_eq!(config.jail_epochs_o1, 10);
    assert!(config.jail_on_o2);
    assert_eq!(config.jail_epochs_o2, 5);
}

#[test]
fn test_slashing_config_mainnet_default() {
    let config = SlashingConfig::mainnet_default();
    // M4: MainNet default is now EnforceCritical, not RecordOnly
    assert_eq!(config.mode, NodeSlashingMode::EnforceCritical);
    // Same parameters, ready for enforcement
    assert_eq!(config.slash_bps_o1_double_sign, 750);
    assert_eq!(config.slash_bps_o2_invalid_proposer_sig, 500);
}

#[test]
fn test_slashing_config_is_enforcing() {
    // M4: MainNet default is now EnforceCritical (enforcing)
    let mainnet_default = SlashingConfig::mainnet_default();
    assert!(mainnet_default.is_enforcing());

    let enforce_critical = SlashingConfig::devnet_default();
    assert!(enforce_critical.is_enforcing());
    
    // RecordOnly is not enforcing
    let record_only = SlashingConfig {
        mode: NodeSlashingMode::RecordOnly,
        ..SlashingConfig::mainnet_default()
    };
    assert!(!record_only.is_enforcing());
}

#[test]
fn test_slashing_config_validate_for_mainnet_rejects_record_only() {
    // M4: RecordOnly is now forbidden for MainNet
    let config = SlashingConfig {
        mode: NodeSlashingMode::RecordOnly,
        ..SlashingConfig::mainnet_default()
    };
    let result = config.validate_for_mainnet();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("record_only") || err.contains("RecordOnly"),
        "Expected error about 'record_only' mode, got: {}",
        err
    );
}

#[test]
fn test_slashing_config_validate_for_mainnet_accepts_enforce_critical() {
    let config = SlashingConfig::mainnet_default();
    assert!(config.validate_for_mainnet().is_ok());
}

#[test]
fn test_slashing_config_validate_for_mainnet_rejects_off() {
    let config = SlashingConfig::disabled();
    let result = config.validate_for_mainnet();
    assert!(result.is_err());
    let err = result.unwrap_err();
    // M4: Updated error message
    assert!(
        err.contains("off") || err.contains("Off") || err.contains("forbidden"),
        "Expected error about 'off' mode, got: {}",
        err
    );
}

#[test]
fn test_slashing_config_validate_for_mainnet_checks_slash_ranges() {
    // O1 slash too low
    let mut config = SlashingConfig::devnet_default();
    config.slash_bps_o1_double_sign = 100; // Below 500 minimum
    let result = config.validate_for_mainnet();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("slash_bps_o1"));

    // O1 slash too high
    let mut config = SlashingConfig::devnet_default();
    config.slash_bps_o1_double_sign = 2000; // Above 1000 maximum
    let result = config.validate_for_mainnet();
    assert!(result.is_err());

    // O2 slash out of range
    let mut config = SlashingConfig::devnet_default();
    config.slash_bps_o2_invalid_proposer_sig = 1000; // Above 550 max
    let result = config.validate_for_mainnet();
    assert!(result.is_err());
}

#[test]
fn test_slashing_config_validate_for_mainnet_checks_jail_epochs() {
    // Zero jail epochs with jailing enabled
    let mut config = SlashingConfig::devnet_default();
    config.jail_epochs_o1 = 0;
    let result = config.validate_for_mainnet();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("jail_epochs_o1"));

    // Excessive jail epochs
    let mut config = SlashingConfig::devnet_default();
    config.jail_epochs_o1 = 2_000_000;
    let result = config.validate_for_mainnet();
    assert!(result.is_err());
}

// ============================================================================
// NodeConfig Slashing Integration Tests
// ============================================================================

#[test]
fn test_nodeconfig_devnet_preset_has_enforce_critical() {
    let config = NodeConfig::devnet_v0_preset();
    assert_eq!(config.slashing.mode, NodeSlashingMode::EnforceCritical);
}

#[test]
fn test_nodeconfig_mainnet_preset_has_enforce_critical() {
    // M4: MainNet preset now uses EnforceCritical
    let config = NodeConfig::mainnet_preset();
    assert_eq!(config.slashing.mode, NodeSlashingMode::EnforceCritical);
}

#[test]
fn test_nodeconfig_with_slashing_config_builder() {
    let custom_config = SlashingConfig {
        mode: NodeSlashingMode::EnforceAll,
        slash_bps_o1_double_sign: 1000,
        slash_bps_o2_invalid_proposer_sig: 500,
        jail_on_o1: true,
        jail_epochs_o1: 20,
        jail_on_o2: false,
        jail_epochs_o2: 0,
    };

    let config = NodeConfig::devnet_v0_preset().with_slashing_config(custom_config.clone());
    assert_eq!(config.slashing.mode, NodeSlashingMode::EnforceAll);
    assert_eq!(config.slashing.slash_bps_o1_double_sign, 1000);
    assert_eq!(config.slashing.jail_epochs_o1, 20);
}

#[test]
fn test_nodeconfig_with_slashing_mode_builder() {
    let config = NodeConfig::devnet_v0_preset().with_slashing_mode(NodeSlashingMode::RecordOnly);
    assert_eq!(config.slashing.mode, NodeSlashingMode::RecordOnly);
}

// ============================================================================
// InMemorySlashingBackend Tests
// ============================================================================

#[test]
fn test_inmemory_backend_burn_stake() {
    let initial_stakes = vec![(ValidatorId(1), 10_000), (ValidatorId(2), 20_000)];
    let mut backend = InMemorySlashingBackend::with_stakes(initial_stakes);

    // Slash validator 1 by 10% (1000 bps)
    let result = backend.burn_stake_bps(ValidatorId(1), 1000, OffenseKind::O1DoubleSign);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1000); // 10% of 10,000

    // Check remaining stake
    assert_eq!(backend.get_stake(ValidatorId(1)), Some(9_000));

    // Total slashed should be tracked
    assert_eq!(backend.total_slashed(), 1000);
}

#[test]
fn test_inmemory_backend_burn_stake_unknown_validator() {
    let mut backend = InMemorySlashingBackend::new();

    let result = backend.burn_stake_bps(ValidatorId(999), 500, OffenseKind::O1DoubleSign);
    assert!(result.is_err());
    match result.unwrap_err() {
        SlashingBackendError::ValidatorNotFound(id) => assert_eq!(id, ValidatorId(999)),
        _ => panic!("Expected ValidatorNotFound error"),
    }
}

#[test]
fn test_inmemory_backend_jail_validator() {
    let initial_stakes = vec![(ValidatorId(1), 10_000)];
    let mut backend = InMemorySlashingBackend::with_stakes(initial_stakes);

    // Jail validator 1 for 10 epochs starting from epoch 100
    let result = backend.jail_validator(ValidatorId(1), OffenseKind::O1DoubleSign, 10, 100);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 110); // unjail at epoch 110

    // Check jail status
    assert!(backend.is_jailed(ValidatorId(1)));
    assert!(!backend.is_jailed(ValidatorId(2)));

    // Total jail events should be tracked
    assert_eq!(backend.total_jail_events(), 1);
}

#[test]
fn test_inmemory_backend_jail_extends_existing() {
    let initial_stakes = vec![(ValidatorId(1), 10_000)];
    let mut backend = InMemorySlashingBackend::with_stakes(initial_stakes);

    // First jail until epoch 110
    backend
        .jail_validator(ValidatorId(1), OffenseKind::O1DoubleSign, 10, 100)
        .unwrap();

    // Second offense - jail for 5 more epochs from epoch 105
    // Should extend to 110, but 110 > 110, so no extension
    let result = backend.jail_validator(ValidatorId(1), OffenseKind::O2InvalidProposerSig, 5, 105);
    assert!(result.is_ok());
    // Original jail of 110 should remain since 105+5=110 is not > 110
}

// ============================================================================
// PenaltySlashingEngine Mode Gating Tests
// ============================================================================

#[test]
fn test_penalty_engine_record_only_mode() {
    let vs = test_validator_set();
    let ctx = test_penalty_context(&vs);

    let backend = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 10_000),
        (ValidatorId(2), 10_000),
    ]);
    let config = PenaltyEngineConfig::record_only();
    let mut engine = PenaltySlashingEngine::new(backend, config);

    // Submit O1 evidence - should be accepted but no penalty
    let evidence = make_o1_evidence(1, 100, 5);
    let record = engine.handle_evidence(&ctx, evidence);

    assert!(matches!(
        record.penalty_decision,
        PenaltyDecision::EvidenceOnly
    ));
    assert_eq!(engine.total_stake_slashed(), 0);
    assert_eq!(engine.total_jail_events(), 0);
}

#[test]
fn test_penalty_engine_enforce_critical_o1() {
    let vs = test_validator_set();
    let ctx = test_penalty_context(&vs);

    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 10_000)]);
    let config = PenaltyEngineConfig::devnet(); // EnforceCritical mode
    let mut engine = PenaltySlashingEngine::new(backend, config);

    // Submit O1 evidence - should have penalty applied
    let evidence = make_o1_evidence(1, 100, 5);
    let record = engine.handle_evidence(&ctx, evidence);

    match record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            // 750 bps of 10,000 = 750
            assert_eq!(slashed_amount, 750);
            // Jailed for 10 epochs from epoch 100 = 110
            assert_eq!(jailed_until_epoch, Some(110));
        }
        _ => panic!("Expected PenaltyApplied decision"),
    }

    assert_eq!(engine.total_stake_slashed(), 750);
    assert_eq!(engine.total_jail_events(), 1);
    assert_eq!(engine.penalty_count(OffenseKind::O1DoubleSign), 1);
}

#[test]
fn test_penalty_engine_enforce_critical_o2() {
    let vs = test_validator_set();
    let ctx = test_penalty_context(&vs);

    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(2), 20_000)]);
    let config = PenaltyEngineConfig::devnet();
    let mut engine = PenaltySlashingEngine::new(backend, config);

    // Submit O2 evidence
    let evidence = make_o2_evidence(2, 100, 5);
    let record = engine.handle_evidence(&ctx, evidence);

    match record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            // 500 bps of 20,000 = 1000
            assert_eq!(slashed_amount, 1000);
            // Jailed for 5 epochs from epoch 100 = 105
            assert_eq!(jailed_until_epoch, Some(105));
        }
        _ => panic!("Expected PenaltyApplied decision"),
    }
}

#[test]
fn test_penalty_engine_o3_enforced_in_enforce_critical() {
    let vs = test_validator_set();
    let ctx = test_penalty_context(&vs);

    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 10_000)]);
    let config = PenaltyEngineConfig::devnet(); // EnforceCritical mode
    let mut engine = PenaltySlashingEngine::new(backend, config);

    // Submit O3a evidence - should be enforced in EnforceCritical
    let evidence = make_o3a_evidence(1, 100, 5);
    let record = engine.handle_evidence(&ctx, evidence);

    match record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            // 10_000 * 300 / 10_000 = 300 (3%)
            assert_eq!(slashed_amount, 300);
            // Jailed for 3 epochs from epoch 100 = 103
            assert_eq!(jailed_until_epoch, Some(103));
        }
        _ => panic!("Expected PenaltyApplied decision"),
    }
    assert_eq!(engine.total_stake_slashed(), 300);
    assert_eq!(engine.total_jail_events(), 1);
}

#[test]
fn test_penalty_engine_off_mode_rejects_all() {
    let vs = test_validator_set();
    let ctx = test_penalty_context(&vs);

    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 10_000)]);
    let config = PenaltyEngineConfig {
        mode: SlashingMode::Off,
        ..PenaltyEngineConfig::default()
    };
    let mut engine = PenaltySlashingEngine::new(backend, config);

    // Submit evidence - should be rejected in Off mode
    let evidence = make_o1_evidence(1, 100, 5);
    let record = engine.handle_evidence(&ctx, evidence);

    match record.penalty_decision {
        PenaltyDecision::Legacy(kind) => {
            assert_eq!(kind.as_str(), "rejected_invalid");
        }
        _ => panic!("Expected Legacy(RejectedInvalid) decision"),
    }
}

#[test]
fn test_penalty_engine_deduplication() {
    let vs = test_validator_set();
    let ctx = test_penalty_context(&vs);

    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 100_000)]);
    let config = PenaltyEngineConfig::devnet();
    let mut engine = PenaltySlashingEngine::new(backend, config);

    // Submit same evidence twice
    let evidence = make_o1_evidence(1, 100, 5);
    let record1 = engine.handle_evidence(&ctx, evidence.clone());
    let record2 = engine.handle_evidence(&ctx, evidence);

    // First should apply penalty
    assert!(matches!(
        record1.penalty_decision,
        PenaltyDecision::PenaltyApplied { .. }
    ));

    // Second should be duplicate
    match record2.penalty_decision {
        PenaltyDecision::Legacy(kind) => {
            assert_eq!(kind.as_str(), "rejected_duplicate");
        }
        _ => panic!("Expected duplicate rejection"),
    }

    // Only one penalty should have been applied
    assert_eq!(engine.penalty_count(OffenseKind::O1DoubleSign), 1);
}

#[test]
fn test_penalty_engine_unknown_validator_rejected() {
    let vs = test_validator_set();
    let ctx = test_penalty_context(&vs);

    let backend = InMemorySlashingBackend::with_stakes(vec![(ValidatorId(1), 10_000)]);
    let config = PenaltyEngineConfig::devnet();
    let mut engine = PenaltySlashingEngine::new(backend, config);

    // Submit evidence for unknown validator (999 not in validator set)
    let evidence = make_o1_evidence(999, 100, 5);
    let record = engine.handle_evidence(&ctx, evidence);

    match record.penalty_decision {
        PenaltyDecision::Legacy(kind) => {
            assert_eq!(kind.as_str(), "rejected_invalid");
        }
        _ => panic!("Expected rejection for unknown validator"),
    }
}

// ============================================================================
// PenaltySlashingMetrics Tests
// ============================================================================

#[test]
fn test_penalty_metrics() {
    let metrics = PenaltySlashingMetrics::new();

    metrics.inc_penalty(OffenseKind::O1DoubleSign);
    metrics.inc_penalty(OffenseKind::O1DoubleSign);
    metrics.inc_penalty(OffenseKind::O2InvalidProposerSig);
    metrics.add_slashed_stake(1000);
    metrics.add_slashed_stake(500);
    metrics.inc_jail_event();

    assert_eq!(metrics.penalties_o1_total(), 2);
    assert_eq!(metrics.penalties_o2_total(), 1);
    assert_eq!(metrics.penalties_total(), 3);
    assert_eq!(metrics.total_stake_slashed(), 1500);
    assert_eq!(metrics.total_jail_events(), 1);
}

// ============================================================================
// MainNet Invariant Validation Tests
// ============================================================================

#[test]
fn test_mainnet_invariants_reject_slashing_off() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_keystore_path("/data/qbind/keystore")
        .with_snapshot_dir("/data/qbind/snapshots");

    config.slashing.mode = NodeSlashingMode::Off;

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result.unwrap_err() {
        MainnetConfigError::SlashingMisconfigured { reason } => {
            assert!(reason.contains("off"));
        }
        other => panic!("Expected SlashingMisconfigured, got {:?}", other),
    }
}

#[test]
fn test_mainnet_invariants_reject_record_only() {
    // M4: RecordOnly is now forbidden for MainNet
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_keystore_path("/data/qbind/keystore")
        .with_snapshot_dir("/data/qbind/snapshots");

    config.slashing.mode = NodeSlashingMode::RecordOnly;

    // Slashing config validation should fail
    let result = config.slashing.validate_for_mainnet();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("record_only") || err.contains("RecordOnly"),
        "Expected error about 'record_only' mode, got: {}",
        err
    );
}

#[test]
fn test_mainnet_invariants_accept_enforce_critical() {
    // M4: MainNet preset uses EnforceCritical by default
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_keystore_path("/data/qbind/keystore")
        .with_snapshot_dir("/data/qbind/snapshots");

    // MainNet default is now EnforceCritical
    assert_eq!(config.slashing.mode, NodeSlashingMode::EnforceCritical);
    assert!(config.slashing.validate_for_mainnet().is_ok());
}