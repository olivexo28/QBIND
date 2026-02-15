use qbind_types::{ValidatorRecord, ValidatorStatus};

#[test]
fn test_validator_status_discriminants() {
    assert_eq!(ValidatorStatus::Inactive as u8, 0);
    assert_eq!(ValidatorStatus::Active as u8, 1);
    assert_eq!(ValidatorStatus::Jailed as u8, 2);
    assert_eq!(ValidatorStatus::Exiting as u8, 3);
}

#[test]
fn test_validator_record_clone() {
    let record = ValidatorRecord {
        version: 1,
        status: ValidatorStatus::Active,
        reserved0: [0; 2],
        owner_keyset_id: [0x01; 32],
        consensus_suite_id: 0x01,
        reserved1: [0; 3],
        consensus_pk: vec![0xAA; 64],
        network_suite_id: 0x02,
        reserved2: [0; 3],
        network_pk: vec![0xBB; 32],
        stake: 1_000_000,
        last_slash_height: 0,
        jailed_until_epoch: None, // M13
        ext_bytes: Vec::new(),
    };

    let cloned = record.clone();

    assert_eq!(cloned.version, record.version);
    assert_eq!(cloned.status, record.status);
    assert_eq!(cloned.owner_keyset_id, record.owner_keyset_id);
    assert_eq!(cloned.consensus_suite_id, record.consensus_suite_id);
    assert_eq!(cloned.consensus_pk, record.consensus_pk);
    assert_eq!(cloned.network_suite_id, record.network_suite_id);
    assert_eq!(cloned.network_pk, record.network_pk);
    assert_eq!(cloned.stake, record.stake);
    assert_eq!(cloned.last_slash_height, record.last_slash_height);
    assert_eq!(cloned.jailed_until_epoch, record.jailed_until_epoch); // M13
    assert_eq!(cloned, record);
}

// ============================================================================
// M13: Canonical Jail Status Tests
// ============================================================================

#[test]
fn test_validator_record_is_jailed_at_epoch() {
    let mut record = ValidatorRecord {
        version: 1,
        status: ValidatorStatus::Jailed,
        reserved0: [0; 2],
        owner_keyset_id: [0x01; 32],
        consensus_suite_id: 0x01,
        reserved1: [0; 3],
        consensus_pk: vec![0xAA; 64],
        network_suite_id: 0x02,
        reserved2: [0; 3],
        network_pk: vec![0xBB; 32],
        stake: 1_000_000,
        last_slash_height: 100,
        jailed_until_epoch: Some(15), // Jailed until epoch 15
        ext_bytes: Vec::new(),
    };

    // Before epoch 15, validator is jailed
    assert!(record.is_jailed_at_epoch(0));
    assert!(record.is_jailed_at_epoch(10));
    assert!(record.is_jailed_at_epoch(14));

    // At or after epoch 15, validator is no longer jailed
    assert!(!record.is_jailed_at_epoch(15));
    assert!(!record.is_jailed_at_epoch(16));
    assert!(!record.is_jailed_at_epoch(100));

    // Validator without jail (None) is never jailed
    record.jailed_until_epoch = None;
    assert!(!record.is_jailed_at_epoch(0));
    assert!(!record.is_jailed_at_epoch(100));
}

#[test]
fn test_validator_record_is_eligible_at_epoch() {
    // Active validator with stake and no jail - eligible
    let eligible = ValidatorRecord {
        version: 1,
        status: ValidatorStatus::Active,
        reserved0: [0; 2],
        owner_keyset_id: [0x01; 32],
        consensus_suite_id: 0x01,
        reserved1: [0; 3],
        consensus_pk: vec![0xAA; 64],
        network_suite_id: 0x02,
        reserved2: [0; 3],
        network_pk: vec![0xBB; 32],
        stake: 1_000_000,
        last_slash_height: 0,
        jailed_until_epoch: None,
        ext_bytes: Vec::new(),
    };
    assert!(eligible.is_eligible_at_epoch(10));

    // Jailed validator - not eligible during jail
    let jailed = ValidatorRecord {
        jailed_until_epoch: Some(20),
        ..eligible.clone()
    };
    assert!(!jailed.is_eligible_at_epoch(10)); // epoch 10 < 20, still jailed
    assert!(jailed.is_eligible_at_epoch(20)); // epoch 20 >= 20, no longer jailed

    // Inactive validator - not eligible
    let inactive = ValidatorRecord {
        status: ValidatorStatus::Inactive,
        ..eligible.clone()
    };
    assert!(!inactive.is_eligible_at_epoch(10));

    // Zero stake validator - not eligible
    let zero_stake = ValidatorRecord {
        stake: 0,
        ..eligible.clone()
    };
    assert!(!zero_stake.is_eligible_at_epoch(10));
}
