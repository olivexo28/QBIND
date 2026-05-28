use qbind_serde::{StateDecode, StateEncode};
use qbind_types::{
    AccountId, Hash32, LaunchChecklist, MainnetStatus, ParamRegistry, SafetyCouncilKeyAccount,
    SafetyCouncilKeyset, SlashingPenaltySchedule,
};

fn zero_hash() -> Hash32 {
    [0u8; 32]
}

fn test_member_id(n: u8) -> AccountId {
    [n; 32]
}

#[test]
fn safety_council_key_account_roundtrip() {
    let account = SafetyCouncilKeyAccount {
        version: 1,
        suite_id: 0x01,
        reserved0: [0u8; 2],
        pk_bytes: vec![0xAA; 100],
    };

    let mut buf = Vec::new();
    account.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SafetyCouncilKeyAccount::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, account);
    assert!(slice.is_empty());
}

#[test]
fn safety_council_key_account_large_pk() {
    // ML-DSA-65 pk is 2592 bytes
    let account = SafetyCouncilKeyAccount {
        version: 1,
        suite_id: 0x01,
        reserved0: [0u8; 2],
        pk_bytes: vec![0xBB; 2592],
    };

    let mut buf = Vec::new();
    account.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SafetyCouncilKeyAccount::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, account);
    assert!(slice.is_empty());
}

#[test]
fn safety_council_keyset_roundtrip() {
    let keyset = SafetyCouncilKeyset {
        version: 1,
        threshold: 3,
        member_count: 5,
        reserved0: 0,
        members: vec![
            test_member_id(1),
            test_member_id(2),
            test_member_id(3),
            test_member_id(4),
            test_member_id(5),
        ],
    };

    let mut buf = Vec::new();
    keyset.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SafetyCouncilKeyset::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, keyset);
    assert!(slice.is_empty());
}

#[test]
fn safety_council_keyset_empty() {
    let keyset = SafetyCouncilKeyset {
        version: 1,
        threshold: 0,
        member_count: 0,
        reserved0: 0,
        members: Vec::new(),
    };

    let mut buf = Vec::new();
    keyset.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SafetyCouncilKeyset::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, keyset);
    assert!(slice.is_empty());
}

#[test]
fn launch_checklist_roundtrip() {
    let checklist = LaunchChecklist {
        version: 1,
        reserved0: [0u8; 3],
        devnet_ok: false,
        testnet_ok: false,
        perf_ok: false,
        adversarial_ok: false,
        crypto_audit_ok: false,
        proto_audit_ok: false,
        spec_ok: false,
        reserved1: 0,
        devnet_report_hash: zero_hash(),
        testnet_report_hash: zero_hash(),
        perf_report_hash: zero_hash(),
        adversarial_report_hash: zero_hash(),
        crypto_audit_hash: zero_hash(),
        proto_audit_hash: zero_hash(),
        spec_hash: zero_hash(),
    };

    let mut buf = Vec::new();
    checklist.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = LaunchChecklist::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, checklist);
    assert!(slice.is_empty());
}

#[test]
fn launch_checklist_roundtrip_all_ok() {
    let checklist = LaunchChecklist {
        version: 1,
        reserved0: [0u8; 3],
        devnet_ok: true,
        testnet_ok: true,
        perf_ok: true,
        adversarial_ok: true,
        crypto_audit_ok: true,
        proto_audit_ok: true,
        spec_ok: true,
        reserved1: 0,
        devnet_report_hash: [0x11; 32],
        testnet_report_hash: [0x22; 32],
        perf_report_hash: [0x33; 32],
        adversarial_report_hash: [0x44; 32],
        crypto_audit_hash: [0x55; 32],
        proto_audit_hash: [0x66; 32],
        spec_hash: [0x77; 32],
    };

    let mut buf = Vec::new();
    checklist.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = LaunchChecklist::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, checklist);
    assert!(slice.is_empty());
}

#[test]
fn param_registry_roundtrip() {
    let registry = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0u8; 6],
        slash_bps_prevote: 100,
        slash_bps_precommit: 200,
        reporter_reward_bps: 10,
        reserved1: 0,
        min_validator_stake: 0,
        slashing_schedule: None,
    };

    let mut buf = Vec::new();
    registry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = ParamRegistry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, registry);
    assert!(slice.is_empty());
}

#[test]
fn param_registry_roundtrip_all_statuses() {
    let statuses = [
        MainnetStatus::PreGenesis,
        MainnetStatus::Ready,
        MainnetStatus::Activated,
    ];

    for status in statuses {
        let registry = ParamRegistry {
            version: 1,
            mainnet_status: status,
            reserved0: [0u8; 6],
            slash_bps_prevote: 500,
            slash_bps_precommit: 1000,
            reporter_reward_bps: 50,
            reserved1: 0,
            min_validator_stake: 0,
            slashing_schedule: Some(SlashingPenaltySchedule::default()),
        };

        let mut buf = Vec::new();
        registry.encode_state(&mut buf);

        let mut slice: &[u8] = &buf;
        let decoded = ParamRegistry::decode_state(&mut slice).expect("decode");
        assert_eq!(decoded, registry);
        assert!(slice.is_empty());
    }
}

#[test]
fn param_registry_max_values() {
    let registry = ParamRegistry {
        version: 255,
        mainnet_status: MainnetStatus::Activated,
        reserved0: [0xFF; 6],
        slash_bps_prevote: u16::MAX,
        slash_bps_precommit: u16::MAX,
        reporter_reward_bps: u16::MAX,
        reserved1: u16::MAX,
        min_validator_stake: u64::MAX,
        slashing_schedule: Some(SlashingPenaltySchedule {
            version: 255,
            reserved0: 255,
            slash_bps_o1: u16::MAX,
            jail_epochs_o1: u32::MAX,
            slash_bps_o2: u16::MAX,
            jail_epochs_o2: u32::MAX,
            slash_bps_o3: u16::MAX,
            jail_epochs_o3: u32::MAX,
            slash_bps_o4: u16::MAX,
            jail_epochs_o4: u32::MAX,
            slash_bps_o5: u16::MAX,
            jail_epochs_o5: u32::MAX,
            activation_epoch: u64::MAX,
        }),
    };

    let mut buf = Vec::new();
    registry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = ParamRegistry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, registry);
    assert!(slice.is_empty());
}

// Genesis SafetyCouncil roundtrip tests

#[test]
fn genesis_safety_council_keyset_roundtrip() {
    let member_ids: [AccountId; 7] = [
        [0xB1; 32], [0xB2; 32], [0xB3; 32], [0xB4; 32], [0xB5; 32], [0xB6; 32], [0xB7; 32],
    ];

    let keyset = qbind_types::genesis_safety_council_keyset(&member_ids);

    let mut buf = Vec::new();
    keyset.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SafetyCouncilKeyset::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, keyset);
    assert!(slice.is_empty());

    // Verify expected values.
    assert_eq!(decoded.threshold, 5);
    assert_eq!(decoded.member_count, 7);
}

#[test]
fn genesis_safety_council_accounts_roundtrip() {
    let accounts = qbind_types::genesis_safety_council_accounts();
    assert_eq!(accounts.len(), 7);

    for account in accounts {
        let mut buf = Vec::new();
        account.encode_state(&mut buf);

        let mut slice: &[u8] = &buf;
        let decoded = SafetyCouncilKeyAccount::decode_state(&mut slice).expect("decode");
        assert_eq!(decoded, account);
        assert!(slice.is_empty());

        // Verify expected values.
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.suite_id, 0x02); // SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024
        assert!(!decoded.pk_bytes.is_empty());
    }
}

// ============================================================================
// M14: SlashingPenaltySchedule roundtrip tests
// ============================================================================

#[test]
fn m14_slashing_penalty_schedule_roundtrip() {
    let schedule = SlashingPenaltySchedule {
        version: 1,
        reserved0: 0,
        slash_bps_o1: 750,
        jail_epochs_o1: 10,
        slash_bps_o2: 500,
        jail_epochs_o2: 5,
        slash_bps_o3: 300,
        jail_epochs_o3: 3,
        slash_bps_o4: 200,
        jail_epochs_o4: 2,
        slash_bps_o5: 100,
        jail_epochs_o5: 1,
        activation_epoch: 42,
    };

    let mut buf = Vec::new();
    schedule.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SlashingPenaltySchedule::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, schedule);
    assert!(slice.is_empty());
}

#[test]
fn m14_slashing_penalty_schedule_default_roundtrip() {
    let schedule = SlashingPenaltySchedule::default();

    let mut buf = Vec::new();
    schedule.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SlashingPenaltySchedule::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, schedule);

    // Verify default values
    assert_eq!(decoded.slash_bps_o1, 750);
    assert_eq!(decoded.jail_epochs_o1, 10);
    assert_eq!(decoded.slash_bps_o5, 100);
    assert_eq!(decoded.jail_epochs_o5, 1);
    assert_eq!(decoded.activation_epoch, 0);
}

#[test]
fn m14_param_registry_with_slashing_schedule_roundtrip() {
    let registry = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::Ready,
        reserved0: [0u8; 6],
        slash_bps_prevote: 100,
        slash_bps_precommit: 200,
        reporter_reward_bps: 10,
        reserved1: 0,
        min_validator_stake: 1_000_000,
        slashing_schedule: Some(SlashingPenaltySchedule::default()),
    };

    let mut buf = Vec::new();
    registry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = ParamRegistry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, registry);
    assert!(slice.is_empty());

    // Verify slashing schedule is present
    assert!(decoded.slashing_schedule.is_some());
    let schedule = decoded.slashing_schedule.unwrap();
    assert_eq!(schedule.slash_bps_o1, 750);
    assert_eq!(schedule.jail_epochs_o1, 10);
}

#[test]
fn m14_param_registry_backward_compatibility() {
    // Test that old data without slashing_schedule decodes correctly (with None)
    let old_registry = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0u8; 6],
        slash_bps_prevote: 100,
        slash_bps_precommit: 200,
        reporter_reward_bps: 10,
        reserved1: 0,
        min_validator_stake: 1_000_000,
        slashing_schedule: None,
    };

    // Manually encode the old format (without slashing_schedule presence flag)
    let mut old_buf = Vec::new();
    old_buf.push(old_registry.version);
    old_buf.push(old_registry.mainnet_status as u8);
    old_buf.extend_from_slice(&old_registry.reserved0);
    old_buf.extend_from_slice(&old_registry.slash_bps_prevote.to_le_bytes());
    old_buf.extend_from_slice(&old_registry.slash_bps_precommit.to_le_bytes());
    old_buf.extend_from_slice(&old_registry.reporter_reward_bps.to_le_bytes());
    old_buf.extend_from_slice(&old_registry.reserved1.to_le_bytes());
    old_buf.extend_from_slice(&old_registry.min_validator_stake.to_le_bytes());
    // No slashing_schedule presence flag - old format

    let mut slice: &[u8] = &old_buf;
    let decoded = ParamRegistry::decode_state(&mut slice).expect("decode");

    // Should decode with slashing_schedule = None
    assert_eq!(decoded.slashing_schedule, None);
    assert!(slice.is_empty());
}
