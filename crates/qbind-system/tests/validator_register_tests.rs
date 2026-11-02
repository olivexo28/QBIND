use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use qbind_crypto::CryptoProvider;
use qbind_ledger::{Account, AccountStore, ExecutionContext, ExecutionError, Program};
use qbind_system::{is_stake_sufficient, ValidatorProgram};
use qbind_types::AccountId;
use qbind_wire::io::WireEncode;
use qbind_wire::tx::{Transaction, TxAccountMeta};
use qbind_wire::validator::RegisterValidatorCall;

// Direct Program fixtures expect zero transaction-verifier calls.
struct DummyCryptoProvider;

impl CryptoProvider for DummyCryptoProvider {
    fn signature_suite(&self, _suite_id: u8) -> Option<&dyn qbind_crypto::SignatureSuite> {
        panic!("direct Program fixtures must not invoke transaction verification")
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

#[derive(Default)]
struct WitnessStore {
    accounts: HashMap<AccountId, Account>,
    reads: RefCell<Vec<AccountId>>,
    writes: Vec<AccountId>,
    deletes: Vec<AccountId>,
}

impl AccountStore for WitnessStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.reads.borrow_mut().push(*id);
        self.accounts.get(id).cloned()
    }

    fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
        self.writes.push(account.id);
        self.accounts.insert(account.id, account);
        Ok(())
    }

    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
        self.deletes.push(*id);
        self.accounts.remove(id);
        Ok(())
    }
}

// Direct Program/context fixtures do not establish TxExecutor authentication.
fn assert_direct_refusal(
    store: &mut WitnessStore,
    tx: &Transaction,
    minimum: u64,
    expected: &'static str,
) {
    let before = store.accounts.clone();
    let tx_before = tx.clone();
    let mut wire_before = Vec::new();
    tx.encode(&mut wire_before);
    store.reads.borrow_mut().clear();
    store.writes.clear();
    store.deletes.clear();
    let crypto = Arc::new(DummyCryptoProvider) as Arc<dyn CryptoProvider>;
    let mut ctx = ExecutionContext::new_with_min_stake(store, crypto, minimum);
    let error = ValidatorProgram::new()
        .execute(&mut ctx, tx)
        .expect_err("direct registration must refuse");
    match error {
        ExecutionError::ProgramError(message) => assert_eq!(message, expected),
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(*store.reads.borrow(), vec![tx.accounts[0].account_id]);
    assert!(store.writes.is_empty());
    assert!(store.deletes.is_empty());
    assert_eq!(store.accounts, before);
    assert_eq!(*tx, tx_before);
    let mut wire_after = Vec::new();
    tx.encode(&mut wire_after);
    assert_eq!(wire_after, wire_before);
}

#[test]
fn direct_register_validator_refuses_without_creating_record_account() {
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
        auths: Vec::new(), // direct Program test, not authenticated execution
    };

    let mut store = WitnessStore::default();
    store.accounts.insert(
        dummy_account_id(0x99),
        Account::new(dummy_account_id(0x99), [0x98; 32], 123, vec![9, 8, 7]),
    );
    for _ in 0..2 {
        assert_direct_refusal(
            &mut store,
            &tx,
            0,
            "native validator registration authority unavailable",
        );
    }
}

#[test]
fn direct_register_validator_fails_if_seeded_target_already_exists() {
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

    let mut store = WitnessStore::default();
    let seeded = Account::new(validator_id, [0x98; 32], 345, vec![9, 8, 7]);
    store.accounts.insert(validator_id, seeded.clone());
    assert_direct_refusal(&mut store, &tx, 11, "validator already exists");
    assert_eq!(store.accounts.get(&validator_id), Some(&seeded));
}

// ============================================================================
// M2: Minimum Stake Enforcement Tests
// ============================================================================

/// Test that registration fails when stake is below minimum threshold.
#[test]
fn direct_register_validator_rejects_stake_below_minimum() {
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

    let mut store = WitnessStore::default();
    assert_direct_refusal(
        &mut store,
        &tx,
        min_stake,
        "stake below minimum required for validator registration",
    );
}

/// Equality passes the fixture-only comparison, not registration authority.
#[test]
fn direct_register_validator_at_minimum_reaches_unavailable_refusal() {
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

    let mut store = WitnessStore::default();
    assert_direct_refusal(
        &mut store,
        &tx,
        min_stake,
        "native validator registration authority unavailable",
    );
}

/// Above-minimum stake cannot supply independent registration authority.
#[test]
fn direct_register_validator_above_minimum_reaches_unavailable_refusal() {
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

    let mut store = WitnessStore::default();
    assert_direct_refusal(
        &mut store,
        &tx,
        min_stake,
        "native validator registration authority unavailable",
    );
}

/// Test that zero stake is rejected when min_stake > 0.
#[test]
fn direct_register_validator_rejects_zero_stake_when_min_is_set() {
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

    let mut store = WitnessStore::default();
    assert_direct_refusal(
        &mut store,
        &tx,
        min_stake,
        "stake below minimum required for validator registration",
    );
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
