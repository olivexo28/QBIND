use qbind_types::{LaunchChecklist, MainnetStatus, ParamRegistry, SafetyCouncilKeyset, SlashingPenaltySchedule};

#[test]
fn test_safety_council_keyset_genesis() {
    let keyset = SafetyCouncilKeyset {
        version: 1,
        threshold: 5,
        member_count: 7,
        reserved0: 0,
        members: vec![[0; 32]; 7],
    };

    assert_eq!(keyset.version, 1);
    assert_eq!(keyset.threshold, 5);
    assert_eq!(keyset.member_count, 7);
    assert_eq!(keyset.members.len(), 7);
}

#[test]
fn test_launch_checklist_genesis() {
    let checklist = LaunchChecklist {
        version: 1,
        reserved0: [0; 3],
        devnet_ok: false,
        testnet_ok: false,
        perf_ok: false,
        adversarial_ok: false,
        crypto_audit_ok: false,
        proto_audit_ok: false,
        spec_ok: false,
        reserved1: 0,
        devnet_report_hash: [0; 32],
        testnet_report_hash: [0; 32],
        perf_report_hash: [0; 32],
        adversarial_report_hash: [0; 32],
        crypto_audit_hash: [0; 32],
        proto_audit_hash: [0; 32],
        spec_hash: [0; 32],
    };

    assert_eq!(checklist.version, 1);
    assert!(!checklist.devnet_ok);
    assert!(!checklist.testnet_ok);
    assert!(!checklist.perf_ok);
    assert!(!checklist.adversarial_ok);
    assert!(!checklist.crypto_audit_ok);
    assert!(!checklist.proto_audit_ok);
    assert!(!checklist.spec_ok);
    assert_eq!(checklist.devnet_report_hash, [0; 32]);
}

#[test]
fn test_param_registry_genesis() {
    let params = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0; 6],
        slash_bps_prevote: 100,
        slash_bps_precommit: 10_000,
        reporter_reward_bps: 5_000,
        reserved1: 0,
        min_validator_stake: 0,
        slashing_schedule: None,
    };

    assert_eq!(params.version, 1);
    assert_eq!(params.mainnet_status, MainnetStatus::PreGenesis);
    assert_eq!(params.slash_bps_prevote, 100);
    assert_eq!(params.slash_bps_precommit, 10_000);
    assert_eq!(params.reporter_reward_bps, 5_000);
}

// ============================================================================
// M14: SlashingPenaltySchedule tests
// ============================================================================

#[test]
fn test_m14_slashing_penalty_schedule_default() {
    let schedule = SlashingPenaltySchedule::default();

    // Verify default penalty parameters
    assert_eq!(schedule.version, 1);
    assert_eq!(schedule.slash_bps_o1, 750);   // 7.5%
    assert_eq!(schedule.jail_epochs_o1, 10);
    assert_eq!(schedule.slash_bps_o2, 500);   // 5%
    assert_eq!(schedule.jail_epochs_o2, 5);
    assert_eq!(schedule.slash_bps_o3, 300);   // 3%
    assert_eq!(schedule.jail_epochs_o3, 3);
    assert_eq!(schedule.slash_bps_o4, 200);   // 2%
    assert_eq!(schedule.jail_epochs_o4, 2);
    assert_eq!(schedule.slash_bps_o5, 100);   // 1%
    assert_eq!(schedule.jail_epochs_o5, 1);
    assert_eq!(schedule.activation_epoch, 0); // Active from genesis
}

#[test]
fn test_m14_slashing_penalty_schedule_is_active_at_epoch() {
    let schedule = SlashingPenaltySchedule {
        activation_epoch: 10,
        ..Default::default()
    };

    assert!(!schedule.is_active_at_epoch(0));
    assert!(!schedule.is_active_at_epoch(5));
    assert!(!schedule.is_active_at_epoch(9));
    assert!(schedule.is_active_at_epoch(10));
    assert!(schedule.is_active_at_epoch(11));
    assert!(schedule.is_active_at_epoch(100));
}

#[test]
fn test_m14_param_registry_with_slashing_schedule() {
    let params = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::Ready,
        reserved0: [0; 6],
        slash_bps_prevote: 100,
        slash_bps_precommit: 10_000,
        reporter_reward_bps: 5_000,
        reserved1: 0,
        min_validator_stake: 1_000_000,
        slashing_schedule: Some(SlashingPenaltySchedule::default()),
    };

    assert!(params.slashing_schedule.is_some());
    let schedule = params.slashing_schedule.unwrap();
    assert_eq!(schedule.slash_bps_o1, 750);
}