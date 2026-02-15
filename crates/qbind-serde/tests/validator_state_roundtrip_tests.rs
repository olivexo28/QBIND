use qbind_serde::{StateDecode, StateEncode};
use qbind_types::{AccountId, SlashingEvent, ValidatorRecord, ValidatorStatus};

fn test_owner_id() -> AccountId {
    [0x11; 32]
}

fn test_validator_id() -> AccountId {
    [0xAB; 32]
}

#[test]
fn validator_record_roundtrip() {
    let record = ValidatorRecord {
        version: 1,
        status: ValidatorStatus::Active,
        reserved0: [0u8; 2],
        owner_keyset_id: test_owner_id(),
        consensus_suite_id: 0x01,
        reserved1: [0u8; 3],
        consensus_pk: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        network_suite_id: 0x02,
        reserved2: [0u8; 3],
        network_pk: vec![0x06, 0x07, 0x08, 0x09, 0x0A],
        stake: 1000000,
        last_slash_height: 0,
        jailed_until_epoch: None, // M13: Not jailed
        ext_bytes: Vec::new(),
    };

    let mut buf = Vec::new();
    record.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = ValidatorRecord::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, record);
    assert!(slice.is_empty());
}

#[test]
fn validator_record_roundtrip_all_statuses() {
    let statuses = [
        ValidatorStatus::Inactive,
        ValidatorStatus::Active,
        ValidatorStatus::Jailed,
        ValidatorStatus::Exiting,
    ];

    for status in statuses {
        let record = ValidatorRecord {
            version: 1,
            status,
            reserved0: [0u8; 2],
            owner_keyset_id: test_owner_id(),
            consensus_suite_id: 0x01,
            reserved1: [0u8; 3],
            consensus_pk: vec![0x01; 100],
            network_suite_id: 0x02,
            reserved2: [0u8; 3],
            network_pk: vec![0x02; 200],
            stake: 5000000,
            last_slash_height: 12345,
            jailed_until_epoch: if status == ValidatorStatus::Jailed { Some(100) } else { None }, // M13
            ext_bytes: vec![0xAA, 0xBB, 0xCC],
        };

        let mut buf = Vec::new();
        record.encode_state(&mut buf);

        let mut slice: &[u8] = &buf;
        let decoded = ValidatorRecord::decode_state(&mut slice).expect("decode");
        assert_eq!(decoded, record);
        assert!(slice.is_empty());
    }
}

#[test]
fn validator_record_large_pk() {
    // Test with ML-DSA-like pk (2592 bytes for ML-DSA-65)
    let record = ValidatorRecord {
        version: 1,
        status: ValidatorStatus::Active,
        reserved0: [0u8; 2],
        owner_keyset_id: test_owner_id(),
        consensus_suite_id: 0x01,
        reserved1: [0u8; 3],
        consensus_pk: vec![0xAA; 2592],
        network_suite_id: 0x02,
        reserved2: [0u8; 3],
        network_pk: vec![0xBB; 1952],
        stake: 1000000000,
        last_slash_height: 9999999,
        jailed_until_epoch: Some(500), // M13: Test with jailed state
        ext_bytes: vec![0xCC; 256],
    };

    let mut buf = Vec::new();
    record.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = ValidatorRecord::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, record);
    assert!(slice.is_empty());
}

#[test]
fn slashing_event_roundtrip() {
    let event = SlashingEvent {
        version: 1,
        reserved0: [0u8; 3],
        validator_id: test_validator_id(),
        height: 12345,
        round: 67,
        step: 0,
        reserved1: [0u8; 7],
    };

    let mut buf = Vec::new();
    event.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SlashingEvent::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, event);
    assert!(slice.is_empty());
}

#[test]
fn slashing_event_roundtrip_large_values() {
    let event = SlashingEvent {
        version: 2,
        reserved0: [0x11, 0x22, 0x33],
        validator_id: [0xFF; 32],
        height: u64::MAX,
        round: u64::MAX - 1,
        step: 255,
        reserved1: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00],
    };

    let mut buf = Vec::new();
    event.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SlashingEvent::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, event);
    assert!(slice.is_empty());
}