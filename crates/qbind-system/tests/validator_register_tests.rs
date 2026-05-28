use std::sync::Arc;

use qbind_crypto::CryptoProvider;
use qbind_ledger::{AccountStore, ExecutionContext, ExecutionError, InMemoryAccountStore, Program};
use qbind_serde::StateDecode;
use qbind_system::{is_stake_sufficient, ValidatorProgram};
use qbind_types::{AccountId, ValidatorRecord, ValidatorStatus};
use qbind_wire::io::WireEncode;
use qbind_wire::tx::{Transaction, TxAccountMeta};
use qbind_wire::validator::RegisterValidatorCall;

// Dummy CryptoProvider for tests; we don't use crypto here.
struct DummyCryptoProvider;

impl CryptoProvider for DummyCryptoProvider {
    fn signature_suite(&self, _suite_id: u8) -> Option<&dyn qbind_crypto::SignatureSuite> {
        None
    }
    fn kem_suite(&self, _suite_id: u8) -> Option<&dyn qbind_crypto::KemSuite> {
        None
    }
    fn aead_suite(&self, _suite_id: u8) -> Option<&dyn qbind_crypto::AeadSuite> {
        None
    }
}

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

#[test]
fn register_validator_creates_validator_record_account() {
    let validator_id = dummy_account_id(0xAA);
    let owner_keyset_id = dummy_account_id(0xBB);

    // Build RegisterValidatorCall.
    let call = RegisterValidatorCall {
        version: 1,
        validator_id,
        owner_keyset_id,
        consensus_suite_id: 0x01,
        consensus_pk: vec![0x11, 0x22, 0x33],
        network_suite_id: 0x02,
        network_pk: vec![0x44, 0x55],
        stake: 1_000_000,
    };

    // Encode call_data.
    let mut call_data = Vec::new();
    call.encode(&mut call_data);

    // Build a Transaction targeting VALIDATOR_PROGRAM_ID.
    let validator_program = ValidatorProgram::new();
    let program_id = ValidatorProgram::id();

    let tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 42,
        fee_limit: 1_000_000,
        accounts: vec![TxAccountMeta {
            account_id: validator_id,
            flags: 0b0000_0011, // signer + writable (advisory only for now)
            access_hint: 0b0000_0011,
            reserved0: [0u8; 2],
        }],
        program_id,
        call_data,
        auths: Vec::new(), // auths not used yet
    };

    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(DummyCryptoProvider) as Arc<dyn CryptoProvider>;
    let mut ctx = ExecutionContext::new(&mut store, crypto);

    // Execute program.
    validator_program
        .execute(&mut ctx, &tx)
        .expect("execute should succeed");

    // Check that the validator account exists and decodes correctly.
    let stored = store.get(&validator_id).expect("validator account created");
    assert_eq!(stored.id, validator_id);
    assert_eq!(stored.header.owner, program_id);

    let mut slice: &[u8] = &stored.data;
    let decoded = ValidatorRecord::decode_state(&mut slice).expect("decode ValidatorRecord");
    assert!(slice.is_empty());

    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.status, ValidatorStatus::Active);
    assert_eq!(decoded.owner_keyset_id, owner_keyset_id);
    assert_eq!(decoded.consensus_suite_id, 0x01);
    assert_eq!(decoded.consensus_pk, vec![0x11, 0x22, 0x33]);
    assert_eq!(decoded.network_suite_id, 0x02);
    assert_eq!(decoded.network_pk, vec![0x44, 0x55]);
    assert_eq!(decoded.stake, 1_000_000);
    assert_eq!(decoded.last_slash_height, 0);
    assert!(decoded.ext_bytes.is_empty());
}

#[test]
fn register_validator_fails_if_already_exists() {
    let validator_id = dummy_account_id(0xCC);
    let owner_keyset_id = dummy_account_id(0xDD);

    let call = RegisterValidatorCall {
        version: 1,
        validator_id,
        owner_keyset_id,
        consensus_suite_id: 0x01,
        consensus_pk: vec![0xAA],
        network_suite_id: 0x02,
        network_pk: vec![0xBB],
        stake: 10,
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);

    let program_id = ValidatorProgram::id();
    let tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000,
        accounts: vec![TxAccountMeta {
            account_id: validator_id,
            flags: 0b0000_0011,
            access_hint: 0b0000_0011,
            reserved0: [0u8; 2],
        }],
        program_id,
        call_data,
        auths: Vec::new(),
    };

    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(DummyCryptoProvider) as Arc<dyn CryptoProvider>;
    let mut ctx = ExecutionContext::new(&mut store, crypto);

    let program = ValidatorProgram::new();

    // First registration should succeed.
    program.execute(&mut ctx, &tx).expect("first register ok");

    // Second registration should fail with ProgramError.
    let err = program
        .execute(&mut ctx, &tx)
        .expect_err("second register must fail");
    match err {
        ExecutionError::ProgramError(msg) => {
            assert!(msg.contains("validator already exists"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

// ============================================================================
// M2: Minimum Stake Enforcement Tests
// ============================================================================

/// Test that registration fails when stake is below minimum threshold.
#[test]
fn register_validator_rejects_stake_below_minimum() {
    let validator_id = dummy_account_id(0xEE);
    let owner_keyset_id = dummy_account_id(0xFF);
    let min_stake = 1_000_000; // 1 QBIND minimum

    // Stake is below minimum (only 999_999)
    let call = RegisterValidatorCall {
        version: 1,
        validator_id,
        owner_keyset_id,
        consensus_suite_id: 0x01,
        consensus_pk: vec![0x11, 0x22],
        network_suite_id: 0x02,
        network_pk: vec![0x33, 0x44],
        stake: 999_999, // Below min_stake
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);

    let program_id = ValidatorProgram::id();
    let tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts: vec![TxAccountMeta {
            account_id: validator_id,
            flags: 0b0000_0011,
            access_hint: 0b0000_0011,
            reserved0: [0u8; 2],
        }],
        program_id,
        call_data,
        auths: Vec::new(),
    };

    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(DummyCryptoProvider) as Arc<dyn CryptoProvider>;
    // Use new_with_min_stake to set the minimum stake threshold
    let mut ctx = ExecutionContext::new_with_min_stake(&mut store, crypto, min_stake);

    let program = ValidatorProgram::new();

    // Registration should fail due to insufficient stake
    let err = program
        .execute(&mut ctx, &tx)
        .expect_err("registration should fail with stake below minimum");

    match err {
        ExecutionError::ProgramError(msg) => {
            assert!(
                msg.contains("stake below minimum"),
                "expected stake error message, got: {}",
                msg
            );
        }
        other => panic!("unexpected error: {:?}", other),
    }

    // Verify the account was not created
    assert!(
        store.get(&validator_id).is_none(),
        "validator account should not be created"
    );
}

/// Test that registration succeeds when stake equals minimum threshold.
#[test]
fn register_validator_accepts_stake_at_minimum() {
    let validator_id = dummy_account_id(0xA1);
    let owner_keyset_id = dummy_account_id(0xA2);
    let min_stake = 1_000_000; // 1 QBIND minimum

    // Stake is exactly at minimum
    let call = RegisterValidatorCall {
        version: 1,
        validator_id,
        owner_keyset_id,
        consensus_suite_id: 0x01,
        consensus_pk: vec![0x11, 0x22],
        network_suite_id: 0x02,
        network_pk: vec![0x33, 0x44],
        stake: min_stake, // Exactly at minimum
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);

    let program_id = ValidatorProgram::id();
    let tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts: vec![TxAccountMeta {
            account_id: validator_id,
            flags: 0b0000_0011,
            access_hint: 0b0000_0011,
            reserved0: [0u8; 2],
        }],
        program_id,
        call_data,
        auths: Vec::new(),
    };

    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(DummyCryptoProvider) as Arc<dyn CryptoProvider>;
    let mut ctx = ExecutionContext::new_with_min_stake(&mut store, crypto, min_stake);

    let program = ValidatorProgram::new();

    // Registration should succeed with stake at minimum
    program
        .execute(&mut ctx, &tx)
        .expect("registration should succeed with stake at minimum");

    // Verify the account was created
    let stored = store.get(&validator_id).expect("validator account created");
    assert_eq!(stored.id, validator_id);

    let mut slice: &[u8] = &stored.data;
    let decoded = ValidatorRecord::decode_state(&mut slice).expect("decode ValidatorRecord");
    assert_eq!(decoded.stake, min_stake);
}

/// Test that registration succeeds when stake is above minimum threshold.
#[test]
fn register_validator_accepts_stake_above_minimum() {
    let validator_id = dummy_account_id(0xB1);
    let owner_keyset_id = dummy_account_id(0xB2);
    let min_stake = 1_000_000; // 1 QBIND minimum

    // Stake is above minimum
    let call = RegisterValidatorCall {
        version: 1,
        validator_id,
        owner_keyset_id,
        consensus_suite_id: 0x01,
        consensus_pk: vec![0x11, 0x22],
        network_suite_id: 0x02,
        network_pk: vec![0x33, 0x44],
        stake: 10_000_000_000, // 10,000 QBIND - well above minimum
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);

    let program_id = ValidatorProgram::id();
    let tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts: vec![TxAccountMeta {
            account_id: validator_id,
            flags: 0b0000_0011,
            access_hint: 0b0000_0011,
            reserved0: [0u8; 2],
        }],
        program_id,
        call_data,
        auths: Vec::new(),
    };

    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(DummyCryptoProvider) as Arc<dyn CryptoProvider>;
    let mut ctx = ExecutionContext::new_with_min_stake(&mut store, crypto, min_stake);

    let program = ValidatorProgram::new();

    // Registration should succeed with stake above minimum
    program
        .execute(&mut ctx, &tx)
        .expect("registration should succeed with stake above minimum");

    // Verify the account was created with correct stake
    let stored = store.get(&validator_id).expect("validator account created");
    let mut slice: &[u8] = &stored.data;
    let decoded = ValidatorRecord::decode_state(&mut slice).expect("decode ValidatorRecord");
    assert_eq!(decoded.stake, 10_000_000_000);
}

/// Test that zero stake is rejected when min_stake > 0.
#[test]
fn register_validator_rejects_zero_stake_when_min_is_set() {
    let validator_id = dummy_account_id(0xC1);
    let owner_keyset_id = dummy_account_id(0xC2);
    let min_stake = 1_000_000; // 1 QBIND minimum

    // Zero stake should be rejected
    let call = RegisterValidatorCall {
        version: 1,
        validator_id,
        owner_keyset_id,
        consensus_suite_id: 0x01,
        consensus_pk: vec![0x11, 0x22],
        network_suite_id: 0x02,
        network_pk: vec![0x33, 0x44],
        stake: 0, // Zero stake
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);

    let program_id = ValidatorProgram::id();
    let tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts: vec![TxAccountMeta {
            account_id: validator_id,
            flags: 0b0000_0011,
            access_hint: 0b0000_0011,
            reserved0: [0u8; 2],
        }],
        program_id,
        call_data,
        auths: Vec::new(),
    };

    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(DummyCryptoProvider) as Arc<dyn CryptoProvider>;
    let mut ctx = ExecutionContext::new_with_min_stake(&mut store, crypto, min_stake);

    let program = ValidatorProgram::new();

    // Registration should fail with zero stake
    let err = program
        .execute(&mut ctx, &tx)
        .expect_err("registration should fail with zero stake");

    match err {
        ExecutionError::ProgramError(msg) => {
            assert!(
                msg.contains("stake below minimum"),
                "expected stake error message, got: {}",
                msg
            );
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

/// Test the is_stake_sufficient helper function.
#[test]
fn test_is_stake_sufficient_helper() {
    // Below minimum
    assert!(!is_stake_sufficient(999_999, 1_000_000));

    // At minimum
    assert!(is_stake_sufficient(1_000_000, 1_000_000));

    // Above minimum
    assert!(is_stake_sufficient(1_000_001, 1_000_000));

    // Zero min_stake allows any stake (including zero)
    assert!(is_stake_sufficient(0, 0));
    assert!(is_stake_sufficient(1, 0));

    // Edge case: max stake values
    assert!(is_stake_sufficient(u64::MAX, u64::MAX));
    assert!(!is_stake_sufficient(u64::MAX - 1, u64::MAX));
}
