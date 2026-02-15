//! M14 Governance Slashing Parameters Wiring Tests
//!
//! This test file validates the M14 implementation for wiring governance slashing
//! parameters into the penalty engine. These tests ensure:
//!
//! A) Deterministic schedule load:
//!    Same ParamRegistry state => same PenaltyEngineConfig across two nodes
//!
//! B) Governance update activation:
//!    Schedule change committed at epoch E activates at epoch E+1 (activation_epoch)
//!
//! C) Fail-closed:
//!    TestNet/MainNet rejects missing schedule
//!
//! D) Regression:
//!    O1-O5 penalties still apply as before, but now using schedule from governance state
//!
//! # M14 Design Summary
//!
//! - SlashingPenaltySchedule is stored in ParamRegistry (on-chain governance state)
//! - PenaltyEngineConfig can be constructed from GovernanceSlashingSchedule
//! - All nodes read the same schedule from the same committed state (deterministic)
//! - DevNet may use fallback defaults; TestNet/MainNet must have schedule present

use qbind_consensus::slashing::{
    EvidencePayloadV1, GovernanceSlashingSchedule,
    InMemorySlashingBackend, OffenseKind, PenaltyDecision, PenaltyEngineConfig,
    PenaltySlashingContext, PenaltySlashingEngine, SignedBlockHeader,
    SlashingEvidence, SlashingMode,
};
use qbind_consensus::{ValidatorId, ValidatorInfo, ValidatorSet};
use qbind_types::{MainnetStatus, NetworkEnvironment, ParamRegistry, SlashingPenaltySchedule};

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

/// Helper to create a ParamRegistry with slashing schedule
fn create_param_registry_with_schedule(schedule: SlashingPenaltySchedule) -> ParamRegistry {
    ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::Ready,
        reserved0: [0u8; 6],
        slash_bps_prevote: 100,
        slash_bps_precommit: 10_000,
        reporter_reward_bps: 1_000,
        reserved1: 0,
        min_validator_stake: 1_000_000,
        slashing_schedule: Some(schedule),
    }
}

/// Helper to convert SlashingPenaltySchedule to GovernanceSlashingSchedule
fn to_governance_schedule(schedule: &SlashingPenaltySchedule) -> GovernanceSlashingSchedule {
    GovernanceSlashingSchedule {
        slash_bps_o1: schedule.slash_bps_o1,
        jail_epochs_o1: schedule.jail_epochs_o1,
        slash_bps_o2: schedule.slash_bps_o2,
        jail_epochs_o2: schedule.jail_epochs_o2,
        slash_bps_o3: schedule.slash_bps_o3,
        jail_epochs_o3: schedule.jail_epochs_o3,
        slash_bps_o4: schedule.slash_bps_o4,
        jail_epochs_o4: schedule.jail_epochs_o4,
        slash_bps_o5: schedule.slash_bps_o5,
        jail_epochs_o5: schedule.jail_epochs_o5,
    }
}

// ============================================================================
// A) Deterministic Schedule Load Tests
// ============================================================================

#[test]
fn test_a1_deterministic_schedule_same_param_registry_same_config() {
    // Same ParamRegistry state should produce identical PenaltyEngineConfig

    let schedule = SlashingPenaltySchedule {
        version: 1,
        reserved0: 0,
        slash_bps_o1: 800,
        jail_epochs_o1: 12,
        slash_bps_o2: 600,
        jail_epochs_o2: 8,
        slash_bps_o3: 400,
        jail_epochs_o3: 4,
        slash_bps_o4: 250,
        jail_epochs_o4: 3,
        slash_bps_o5: 150,
        jail_epochs_o5: 2,
        activation_epoch: 0,
    };

    // Simulate two nodes reading the same ParamRegistry state
    let registry = create_param_registry_with_schedule(schedule.clone());
    let gov_schedule = to_governance_schedule(&registry.slashing_schedule.as_ref().unwrap());

    let config_node1 =
        PenaltyEngineConfig::from_governance_schedule(&gov_schedule, SlashingMode::EnforceCritical);
    let config_node2 =
        PenaltyEngineConfig::from_governance_schedule(&gov_schedule, SlashingMode::EnforceCritical);

    // Both nodes should have identical configurations
    assert_eq!(config_node1, config_node2);
    assert_eq!(config_node1.slash_bps_o1, 800);
    assert_eq!(config_node1.jail_epochs_o1, 12);
    assert_eq!(config_node1.slash_bps_o5, 150);
    assert_eq!(config_node1.jail_epochs_o5, 2);
}

#[test]
fn test_a2_deterministic_penalty_application_two_engines() {
    // Two engines with same config should apply identical penalties

    let schedule = SlashingPenaltySchedule::default();
    let gov_schedule = to_governance_schedule(&schedule);
    let config =
        PenaltyEngineConfig::from_governance_schedule(&gov_schedule, SlashingMode::EnforceCritical);

    // Create two engines with identical configuration
    let backend1 = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 1_000_000),
        (ValidatorId(2), 1_000_000),
    ]);
    let backend2 = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 1_000_000),
        (ValidatorId(2), 1_000_000),
    ]);

    let mut engine1 = PenaltySlashingEngine::new(backend1, config.clone());
    let mut engine2 = PenaltySlashingEngine::new(backend2, config);

    let vs = test_validator_set();
    let ctx = PenaltySlashingContext {
        validator_set: &vs,
        current_height: 1000,
        current_view: 0,
        current_epoch: 5,
    };

    // Submit same evidence to both engines
    let evidence = make_o1_evidence(1, 100, 0);
    let record1 = engine1.handle_evidence(&ctx, evidence.clone());
    let record2 = engine2.handle_evidence(&ctx, evidence);

    // Both should have same penalty decision
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
            assert_eq!(s1, s2, "slashed amounts should be equal");
            assert_eq!(j1, j2, "jail epochs should be equal");
        }
        _ => panic!("Expected PenaltyApplied for both engines"),
    }
}

#[test]
fn test_a3_schedule_roundtrip_to_governance_schedule() {
    // Verify PenaltyEngineConfig.to_governance_schedule() roundtrips correctly

    let schedule = SlashingPenaltySchedule {
        version: 1,
        reserved0: 0,
        slash_bps_o1: 900,
        jail_epochs_o1: 15,
        slash_bps_o2: 700,
        jail_epochs_o2: 7,
        slash_bps_o3: 350,
        jail_epochs_o3: 4,
        slash_bps_o4: 180,
        jail_epochs_o4: 2,
        slash_bps_o5: 80,
        jail_epochs_o5: 1,
        activation_epoch: 0,
    };

    let gov_schedule = to_governance_schedule(&schedule);
    let config =
        PenaltyEngineConfig::from_governance_schedule(&gov_schedule, SlashingMode::EnforceCritical);
    let roundtripped = config.to_governance_schedule();

    assert_eq!(gov_schedule, roundtripped);
}

// ============================================================================
// B) Governance Update Activation Tests
// ============================================================================

#[test]
fn test_b1_schedule_is_active_at_epoch() {
    let schedule = SlashingPenaltySchedule {
        activation_epoch: 10,
        ..Default::default()
    };

    // Schedule not active before activation_epoch
    assert!(!schedule.is_active_at_epoch(0));
    assert!(!schedule.is_active_at_epoch(5));
    assert!(!schedule.is_active_at_epoch(9));

    // Schedule active at and after activation_epoch
    assert!(schedule.is_active_at_epoch(10));
    assert!(schedule.is_active_at_epoch(11));
    assert!(schedule.is_active_at_epoch(100));
}

#[test]
fn test_b2_schedule_selection_by_epoch() {
    // Simulate selecting the correct schedule based on epoch

    let old_schedule = SlashingPenaltySchedule {
        slash_bps_o1: 500,
        jail_epochs_o1: 5,
        activation_epoch: 0,
        ..Default::default()
    };

    let new_schedule = SlashingPenaltySchedule {
        slash_bps_o1: 1000,
        jail_epochs_o1: 20,
        activation_epoch: 50,
        ..Default::default()
    };

    // At epoch 25, use old schedule
    let current_epoch = 25;
    let active_schedule = if new_schedule.is_active_at_epoch(current_epoch) {
        &new_schedule
    } else {
        &old_schedule
    };
    assert_eq!(active_schedule.slash_bps_o1, 500);

    // At epoch 50, use new schedule
    let current_epoch = 50;
    let active_schedule = if new_schedule.is_active_at_epoch(current_epoch) {
        &new_schedule
    } else {
        &old_schedule
    };
    assert_eq!(active_schedule.slash_bps_o1, 1000);

    // At epoch 100, use new schedule
    let current_epoch = 100;
    let active_schedule = if new_schedule.is_active_at_epoch(current_epoch) {
        &new_schedule
    } else {
        &old_schedule
    };
    assert_eq!(active_schedule.slash_bps_o1, 1000);
}

#[test]
fn test_b3_default_schedule_active_from_genesis() {
    let schedule = SlashingPenaltySchedule::default();
    assert_eq!(schedule.activation_epoch, 0);
    assert!(schedule.is_active_at_epoch(0));
    assert!(schedule.is_active_at_epoch(1));
}

// ============================================================================
// C) Fail-Closed Behavior Tests
// ============================================================================

/// Helper function to simulate fail-closed validation for network environment
fn validate_slashing_schedule_for_environment(
    registry: &ParamRegistry,
    env: NetworkEnvironment,
) -> Result<(), &'static str> {
    match env {
        NetworkEnvironment::Devnet => {
            // DevNet: allow missing schedule (use defaults)
            Ok(())
        }
        NetworkEnvironment::Testnet | NetworkEnvironment::Mainnet => {
            // TestNet/MainNet: require slashing schedule
            if registry.slashing_schedule.is_none() {
                Err("slashing_schedule is required for TestNet/MainNet")
            } else {
                Ok(())
            }
        }
    }
}

#[test]
fn test_c1_devnet_allows_missing_schedule() {
    let registry = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0u8; 6],
        slash_bps_prevote: 100,
        slash_bps_precommit: 10_000,
        reporter_reward_bps: 1_000,
        reserved1: 0,
        min_validator_stake: 1_000_000,
        slashing_schedule: None, // No schedule
    };

    // DevNet should allow missing schedule
    let result = validate_slashing_schedule_for_environment(&registry, NetworkEnvironment::Devnet);
    assert!(result.is_ok());
}

#[test]
fn test_c2_testnet_rejects_missing_schedule() {
    let registry = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0u8; 6],
        slash_bps_prevote: 100,
        slash_bps_precommit: 10_000,
        reporter_reward_bps: 1_000,
        reserved1: 0,
        min_validator_stake: 1_000_000,
        slashing_schedule: None, // No schedule
    };

    // TestNet should reject missing schedule
    let result = validate_slashing_schedule_for_environment(&registry, NetworkEnvironment::Testnet);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "slashing_schedule is required for TestNet/MainNet"
    );
}

#[test]
fn test_c3_mainnet_rejects_missing_schedule() {
    let registry = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::Ready,
        reserved0: [0u8; 6],
        slash_bps_prevote: 100,
        slash_bps_precommit: 10_000,
        reporter_reward_bps: 1_000,
        reserved1: 0,
        min_validator_stake: 1_000_000,
        slashing_schedule: None, // No schedule
    };

    // MainNet should reject missing schedule
    let result = validate_slashing_schedule_for_environment(&registry, NetworkEnvironment::Mainnet);
    assert!(result.is_err());
}

#[test]
fn test_c4_testnet_accepts_present_schedule() {
    let registry = create_param_registry_with_schedule(SlashingPenaltySchedule::default());

    // TestNet should accept present schedule
    let result = validate_slashing_schedule_for_environment(&registry, NetworkEnvironment::Testnet);
    assert!(result.is_ok());
}

#[test]
fn test_c5_mainnet_accepts_present_schedule() {
    let registry = create_param_registry_with_schedule(SlashingPenaltySchedule::default());

    // MainNet should accept present schedule
    let result = validate_slashing_schedule_for_environment(&registry, NetworkEnvironment::Mainnet);
    assert!(result.is_ok());
}

// ============================================================================
// D) O1-O5 Regression Tests with Governance Schedule
// ============================================================================

#[test]
fn test_d1_o1_penalty_with_governance_schedule() {
    // O1 penalty should apply using governance schedule parameters

    let schedule = SlashingPenaltySchedule {
        slash_bps_o1: 800, // 8% (different from default 7.5%)
        jail_epochs_o1: 15, // 15 epochs (different from default 10)
        ..Default::default()
    };

    let gov_schedule = to_governance_schedule(&schedule);
    let config =
        PenaltyEngineConfig::from_governance_schedule(&gov_schedule, SlashingMode::EnforceCritical);

    let backend = InMemorySlashingBackend::with_stakes(vec![
        (ValidatorId(1), 1_000_000),
        (ValidatorId(2), 1_000_000),
    ]);

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

    match &record.penalty_decision {
        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        } => {
            // 1_000_000 * 800 / 10000 = 80_000 (8%)
            assert_eq!(*slashed_amount, 80_000, "slashed amount should be 80_000");
            assert_eq!(
                *jailed_until_epoch,
                Some(20),
                "jailed until epoch 5+15=20"
            );
        }
        _ => panic!("Expected PenaltyApplied"),
    }
}

#[test]
fn test_d2_default_schedule_matches_existing_defaults() {
    // Verify default SlashingPenaltySchedule matches the existing PenaltyEngineConfig defaults

    let schedule = SlashingPenaltySchedule::default();
    let gov_schedule = to_governance_schedule(&schedule);
    let config =
        PenaltyEngineConfig::from_governance_schedule(&gov_schedule, SlashingMode::EnforceCritical);

    let default_config = PenaltyEngineConfig::default();

    // Verify O1-O5 parameters match
    assert_eq!(config.slash_bps_o1, default_config.slash_bps_o1);
    assert_eq!(config.jail_epochs_o1, default_config.jail_epochs_o1);
    assert_eq!(config.slash_bps_o2, default_config.slash_bps_o2);
    assert_eq!(config.jail_epochs_o2, default_config.jail_epochs_o2);
    assert_eq!(config.slash_bps_o3, default_config.slash_bps_o3);
    assert_eq!(config.jail_epochs_o3, default_config.jail_epochs_o3);
    assert_eq!(config.slash_bps_o4, default_config.slash_bps_o4);
    assert_eq!(config.jail_epochs_o4, default_config.jail_epochs_o4);
    assert_eq!(config.slash_bps_o5, default_config.slash_bps_o5);
    assert_eq!(config.jail_epochs_o5, default_config.jail_epochs_o5);
}

#[test]
fn test_d3_different_schedules_produce_different_configs() {
    let schedule1 = SlashingPenaltySchedule {
        slash_bps_o1: 500,
        ..Default::default()
    };

    let schedule2 = SlashingPenaltySchedule {
        slash_bps_o1: 1000,
        ..Default::default()
    };

    let gov_schedule1 = to_governance_schedule(&schedule1);
    let gov_schedule2 = to_governance_schedule(&schedule2);

    let config1 = PenaltyEngineConfig::from_governance_schedule(
        &gov_schedule1,
        SlashingMode::EnforceCritical,
    );
    let config2 = PenaltyEngineConfig::from_governance_schedule(
        &gov_schedule2,
        SlashingMode::EnforceCritical,
    );

    assert_ne!(config1.slash_bps_o1, config2.slash_bps_o1);
    assert_eq!(config1.slash_bps_o1, 500);
    assert_eq!(config2.slash_bps_o1, 1000);
}

#[test]
fn test_d4_jail_enabled_based_on_epochs() {
    // jail_on_oX should be true when jail_epochs_oX > 0

    let schedule_with_jail = SlashingPenaltySchedule {
        jail_epochs_o1: 10,
        jail_epochs_o2: 0, // No jail for O2
        ..Default::default()
    };

    let gov_schedule = to_governance_schedule(&schedule_with_jail);
    let config =
        PenaltyEngineConfig::from_governance_schedule(&gov_schedule, SlashingMode::EnforceCritical);

    assert!(config.jail_on_o1, "O1 should have jailing enabled");
    assert!(!config.jail_on_o2, "O2 should NOT have jailing enabled");
}
