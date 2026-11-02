use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use qbind_crypto::{CryptoProvider, StaticCryptoProvider};
use qbind_ledger::{Account, AccountStore, ExecutionContext, ExecutionError, Program};
use qbind_system::keyset_program::KEYSET_PROGRAM_ID;
use qbind_system::KeysetProgram;
use qbind_types::{AccountId, ProgramId};
use qbind_wire::io::WireEncode;
use qbind_wire::keyset::{CreateKeysetCall, WireKeyEntry};
use qbind_wire::tx::Transaction;

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn empty_crypto() -> Arc<dyn CryptoProvider> {
    Arc::new(StaticCryptoProvider::new())
}

#[derive(Default)]
struct WitnessStore {
    accounts: HashMap<AccountId, Account>,
    reads: RefCell<Vec<AccountId>>,
    puts: Vec<AccountId>,
    deletes: Vec<AccountId>,
}

impl WitnessStore {
    fn seed(&mut self, account: Account) {
        self.accounts.insert(account.id, account);
    }

    fn snapshot(&self) -> HashMap<AccountId, Account> {
        self.accounts.clone()
    }
}

impl AccountStore for WitnessStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.reads.borrow_mut().push(*id);
        self.accounts.get(id).cloned()
    }

    fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
        self.puts.push(account.id);
        self.accounts.insert(account.id, account);
        Ok(())
    }

    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
        self.deletes.push(*id);
        self.accounts.remove(id);
        Ok(())
    }
}

fn base_tx(program_id: ProgramId, call_data: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts: Vec::new(),
        program_id,
        call_data,
        auths: Vec::new(),
    }
}

fn create_call(target_id: AccountId) -> CreateKeysetCall {
    CreateKeysetCall {
        version: 1,
        target_id,
        threshold: 10,
        entries: vec![WireKeyEntry {
            suite_id: 0x01,
            weight: 10,
            pubkey_bytes: vec![9, 8, 7],
        }],
    }
}

fn encode_call(call: &CreateKeysetCall) -> Vec<u8> {
    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    call_data
}

fn execute(store: &mut WitnessStore, tx: &Transaction) -> Result<(), ExecutionError> {
    let mut ctx = ExecutionContext::new(store, empty_crypto());
    KeysetProgram::new().execute(&mut ctx, tx)
}

fn wire_bytes(tx: &Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    tx.encode(&mut bytes);
    bytes
}

#[test]
fn direct_program_absent_target_refuses_without_mutation() {
    let target = dummy_account_id(0xEE);
    let tx = base_tx(KEYSET_PROGRAM_ID, encode_call(&create_call(target)));
    let original_tx = tx.clone();
    let original_bytes = wire_bytes(&tx);
    let mut store = WitnessStore::default();
    let before = store.snapshot();

    let error = execute(&mut store, &tx).expect_err("native creation has no authority");

    assert!(matches!(
        error,
        ExecutionError::ProgramError("native keyset creation authority unavailable")
    ));
    assert_eq!(*store.reads.borrow(), [target]);
    assert!(store.puts.is_empty());
    assert!(store.deletes.is_empty());
    assert_eq!(store.snapshot(), before);
    assert_eq!(tx, original_tx);
    assert_eq!(wire_bytes(&tx), original_bytes);
}

#[test]
fn direct_program_existing_target_is_preserved() {
    let target = dummy_account_id(0xEF);
    let tx = base_tx(KEYSET_PROGRAM_ID, encode_call(&create_call(target)));
    let mut store = WitnessStore::default();
    let mut existing = Account::new(target, [0xA5; 32], 765_432, vec![0xDE, 0xAD, 0xBE]);
    existing.header.is_executable = true;
    existing.header.rent_epoch = 71;
    existing.header.reserved = [0xBC; 8];
    store.seed(existing);
    let before = store.snapshot();

    let error = execute(&mut store, &tx).expect_err("existing target must retain precedence");

    assert!(matches!(
        error,
        ExecutionError::ProgramError("keyset account already exists")
    ));
    assert_eq!(*store.reads.borrow(), [target]);
    assert!(store.puts.is_empty());
    assert!(store.deletes.is_empty());
    assert_eq!(store.snapshot(), before);
}

#[test]
fn direct_program_validation_and_framing_precede_target_lookup() {
    let target = dummy_account_id(0xF0);
    let valid = encode_call(&create_call(target));
    let mut truncated = valid.clone();
    truncated.pop();
    let mut trailing = valid.clone();
    trailing.push(0xA7);
    let cases = [
        (
            base_tx([0xFE; 32], Vec::new()),
            ExecutionError::ProgramError("program_id mismatch for KeysetProgram"),
        ),
        (
            base_tx(KEYSET_PROGRAM_ID, Vec::new()),
            ExecutionError::InvalidCallData("empty call_data"),
        ),
        (
            base_tx(KEYSET_PROGRAM_ID, vec![0xFF]),
            ExecutionError::ProgramError("unsupported keyset opcode"),
        ),
        (
            base_tx(KEYSET_PROGRAM_ID, truncated),
            ExecutionError::InvalidCallData("invalid CreateKeysetCall"),
        ),
        (
            base_tx(KEYSET_PROGRAM_ID, trailing),
            ExecutionError::InvalidCallData("extra bytes after CreateKeysetCall"),
        ),
    ];

    for (tx, expected) in cases {
        let mut store = WitnessStore::default();
        let mut existing = Account::new(target, [0xA5; 32], 765_432, vec![1, 2, 3]);
        existing.header.reserved = [0xBC; 8];
        store.seed(existing);
        let before = store.snapshot();

        let error = execute(&mut store, &tx).expect_err("framing control must refuse");

        match (error, expected) {
            (ExecutionError::ProgramError(actual), ExecutionError::ProgramError(expected))
            | (
                ExecutionError::InvalidCallData(actual),
                ExecutionError::InvalidCallData(expected),
            ) => {
                assert_eq!(actual, expected);
            }
            (actual, expected) => panic!("unexpected error: {actual:?} != {expected:?}"),
        }
        assert!(store.reads.borrow().is_empty());
        assert!(store.puts.is_empty());
        assert!(store.deletes.is_empty());
        assert_eq!(store.snapshot(), before);
    }
}
