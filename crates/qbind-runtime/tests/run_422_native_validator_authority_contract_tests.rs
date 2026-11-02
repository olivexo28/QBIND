// Migrated from the successful-write characterization at
// 8769118ef4b5b27631a4177862b1dc91cd66c7ca; current registrations must refuse.
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use qbind_crypto::error::CryptoError;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::ml_kem768::{MlKem768Backend, KEM_SUITE_ML_KEM_768};
use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
use qbind_crypto::{
    ml_dsa_44_sign_digest, CryptoProvider, KemSuite, MlDsa44SignatureSuite, StaticCryptoProvider,
};
use qbind_hash::tx::tx_digest;
use qbind_ledger::{Account, AccountStore, ExecutionContext, ExecutionError, Program};
use qbind_runtime::TxExecutor;
use qbind_serde::{StateDecode, StateEncode};
use qbind_system::keyset_program::KEYSET_PROGRAM_ID;
use qbind_system::validator_program::VALIDATOR_PROGRAM_ID;
use qbind_system::ValidatorProgram;
use qbind_types::{
    AccountId, Hash32, KeysetAccount, KeysetEntry, ValidatorRecord, ValidatorStatus,
};
use qbind_wire::io::{WireDecode, WireEncode};
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};
use qbind_wire::validator::{RegisterValidatorCall, OP_REGISTER_VALIDATOR};

const AUTH_SUITE_ID: u8 = 100;
const CONSENSUS_SUITE_ID: u8 = 3;
const SIGNER_ID: AccountId = [0x11; 32];
const OWNER_ID: AccountId = [0x22; 32];
const PAYER_ID: AccountId = [0x33; 32];
const TARGET_ID: AccountId = [0x44; 32];
const SENTINEL_ID: AccountId = [0x55; 32];
const PAYER_OWNER_ID: AccountId = [0x66; 32];
const SENTINEL_OWNER_ID: AccountId = [0x77; 32];
const AUTHORITY_UNAVAILABLE: &str = "native validator registration authority unavailable";

#[derive(Default, Debug, PartialEq, Eq)]
struct StoreEvents {
    reads: Vec<AccountId>,
    writes: Vec<AccountId>,
    deletes: Vec<AccountId>,
}

#[derive(Default)]
struct WitnessStore {
    accounts: HashMap<AccountId, Account>,
    reads: RefCell<Vec<AccountId>>,
    writes: Vec<AccountId>,
    deletes: Vec<AccountId>,
}

impl WitnessStore {
    fn seed(&mut self, account: Account) {
        self.accounts.insert(account.id, account);
    }

    fn clear_events(&mut self) {
        self.reads.borrow_mut().clear();
        self.writes.clear();
        self.deletes.clear();
    }

    fn take_events(&mut self) -> StoreEvents {
        StoreEvents {
            reads: std::mem::take(&mut *self.reads.borrow_mut()),
            writes: std::mem::take(&mut self.writes),
            deletes: std::mem::take(&mut self.deletes),
        }
    }

    fn complete_state(&self) -> HashMap<AccountId, Account> {
        self.accounts.clone()
    }
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

struct CountedSuite {
    inner: MlDsa44SignatureSuite,
    verifications: Arc<AtomicUsize>,
}

impl SignatureSuite for CountedSuite {
    fn suite_id(&self) -> u8 {
        self.inner.suite_id()
    }

    fn public_key_len(&self) -> usize {
        self.inner.public_key_len()
    }

    fn signature_len(&self) -> usize {
        self.inner.signature_len()
    }

    fn canonical_key_descriptor<'a>(
        &self,
        key: &'a [u8],
    ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
        self.inner.canonical_key_descriptor(key)
    }

    fn verify(&self, key: &[u8], digest: &Hash32, signature: &[u8]) -> Result<(), CryptoError> {
        self.verifications.fetch_add(1, Ordering::SeqCst);
        self.inner.verify(key, digest, signature)
    }
}

struct FixtureSetupChecks {
    consensus_signatures_verified: usize,
    network_kem_round_trips: usize,
}

struct Fixture {
    store: WitnessStore,
    transaction: Transaction,
    signer_secret: Vec<u8>,
    crypto: Arc<dyn CryptoProvider>,
    verifications: Arc<AtomicUsize>,
    setup_checks: FixtureSetupChecks,
    executor: TxExecutor<WitnessStore>,
}

impl Fixture {
    fn new(target_id: AccountId, owner_exists: bool, stake: u64) -> Self {
        assert_distinct_identities(target_id);

        let (signer_public, signer_secret) =
            MlDsa44Backend::generate_keypair().expect("genuine signer ML-DSA-44 key");
        let (owner_public, _) =
            MlDsa44Backend::generate_keypair().expect("genuine owner ML-DSA-44 key");
        let (consensus_pk, consensus_sk) =
            MlDsa44Backend::generate_keypair().expect("genuine consensus ML-DSA-44 key");
        let (network_pk, network_sk) =
            MlKem768Backend::generate_keypair().expect("genuine network ML-KEM-768 key");

        let setup_message = [0xA5; 32];
        let setup_signature =
            MlDsa44Backend::sign(&consensus_sk, &setup_message).expect("consensus key signs");
        MlDsa44Backend::verify(&consensus_pk, &setup_message, &setup_signature)
            .expect("consensus public key verifies generated signature");
        let (ciphertext, encapsulated_secret) = MlKem768Backend::new()
            .encaps(&network_pk)
            .expect("network public key accepts encapsulation");
        let decapsulated_secret = MlKem768Backend::new()
            .decaps(&network_sk, &ciphertext)
            .expect("network secret key decapsulates fixture ciphertext");
        assert_eq!(encapsulated_secret, decapsulated_secret);
        let setup_checks = FixtureSetupChecks {
            consensus_signatures_verified: 1,
            network_kem_round_trips: 1,
        };
        assert_eq!(setup_checks.consensus_signatures_verified, 1);
        assert_eq!(setup_checks.network_kem_round_trips, 1);

        let mut store = WitnessStore::default();
        store.seed(keyset_account(SIGNER_ID, signer_public));
        if owner_exists {
            store.seed(keyset_account(OWNER_ID, owner_public));
        }
        store.seed(Account::new(
            PAYER_ID,
            PAYER_OWNER_ID,
            987_654,
            vec![1, 2, 3],
        ));
        store.seed(Account::new(
            SENTINEL_ID,
            SENTINEL_OWNER_ID,
            456_789,
            vec![4, 5, 6, 7],
        ));

        let call = RegisterValidatorCall {
            version: 1,
            validator_id: target_id,
            owner_keyset_id: OWNER_ID,
            consensus_suite_id: CONSENSUS_SUITE_ID,
            consensus_pk,
            network_suite_id: KEM_SUITE_ML_KEM_768,
            network_pk,
            stake,
        };
        let mut call_data = Vec::new();
        call.encode(&mut call_data);
        assert_eq!(call_data[0], OP_REGISTER_VALIDATOR);

        let mut transaction = Transaction {
            version: 1,
            chain_id: 1,
            payer: PAYER_ID,
            nonce: 42,
            fee_limit: 100_000,
            accounts: vec![
                TxAccountMeta {
                    account_id: SIGNER_ID,
                    flags: 1,
                    access_hint: 0,
                    reserved0: [0; 2],
                },
                TxAccountMeta {
                    account_id: target_id,
                    flags: 2,
                    access_hint: 0,
                    reserved0: [0; 2],
                },
                TxAccountMeta {
                    account_id: OWNER_ID,
                    flags: 0,
                    access_hint: 0,
                    reserved0: [0; 2],
                },
                TxAccountMeta {
                    account_id: PAYER_ID,
                    flags: 0,
                    access_hint: 0,
                    reserved0: [0; 2],
                },
                TxAccountMeta {
                    account_id: SENTINEL_ID,
                    flags: 0,
                    access_hint: 0,
                    reserved0: [0; 2],
                },
            ],
            program_id: VALIDATOR_PROGRAM_ID,
            call_data,
            auths: Vec::new(),
        };
        sign(&mut transaction, &signer_secret);

        let verifications = Arc::new(AtomicUsize::new(0));
        let crypto: Arc<dyn CryptoProvider> = Arc::new(
            StaticCryptoProvider::new().with_signature_suite(Arc::new(CountedSuite {
                inner: MlDsa44SignatureSuite::new(AUTH_SUITE_ID),
                verifications: Arc::clone(&verifications),
            })),
        );
        store.clear_events();
        Self {
            store,
            transaction,
            signer_secret,
            crypto,
            verifications,
            setup_checks,
            executor: TxExecutor::new(),
        }
    }

    fn verify_count(&self) -> usize {
        self.verifications.load(Ordering::SeqCst)
    }

    fn execute(&mut self, tx: &Transaction) -> Result<(), ExecutionError> {
        self.executor
            .execute_transaction(&mut self.store, Arc::clone(&self.crypto), tx)
    }
}

fn assert_distinct_identities(target_id: AccountId) {
    for (left, right) in [
        (SIGNER_ID, OWNER_ID),
        (SIGNER_ID, target_id),
        (SIGNER_ID, PAYER_ID),
        (SIGNER_ID, SENTINEL_ID),
        (OWNER_ID, target_id),
        (OWNER_ID, PAYER_ID),
        (OWNER_ID, SENTINEL_ID),
        (target_id, PAYER_ID),
        (target_id, SENTINEL_ID),
        (PAYER_ID, SENTINEL_ID),
    ] {
        assert_ne!(left, right, "test identities must be distinct");
    }
}

fn keyset_account(id: AccountId, public_key: Vec<u8>) -> Account {
    let keyset = KeysetAccount {
        version: 1,
        reserved0: [0; 3],
        threshold: 1,
        entry_count: 1,
        reserved1: [0; 4],
        entries: vec![KeysetEntry {
            suite_id: AUTH_SUITE_ID,
            weight: 1,
            reserved0: [0; 1],
            pubkey_len: u16::try_from(public_key.len()).unwrap(),
            pubkey_bytes: public_key,
        }],
    };
    let mut data = Vec::new();
    keyset.encode_state(&mut data);
    let account = Account::new(id, KEYSET_PROGRAM_ID, 0, data);
    assert_eq!(account.header.owner, KEYSET_PROGRAM_ID);
    assert!(!account.header.is_executable);
    let mut input: &[u8] = &account.data;
    let decoded = KeysetAccount::decode_state(&mut input).expect("keyset fixture decodes");
    assert!(input.is_empty());
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.threshold, 1);
    assert_eq!(decoded.entry_count, 1);
    assert_eq!(decoded.entries.len(), 1);
    assert_eq!(decoded.entries[0].weight, 1);
    assert_eq!(
        usize::from(decoded.entries[0].pubkey_len),
        decoded.entries[0].pubkey_bytes.len()
    );
    account
}

fn sign(tx: &mut Transaction, secret: &[u8]) {
    tx.auths = vec![TxAuth {
        account_index: 0,
        suite_id: AUTH_SUITE_ID,
        reserved: 0,
        signature: Vec::new(),
    }];
    tx.auths[0].signature =
        ml_dsa_44_sign_digest(secret, &tx_digest(tx)).expect("genuine ML-DSA-44 tx signature");
}

fn transaction_bytes(tx: &Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    tx.encode(&mut bytes);
    bytes
}

fn fixture_record(tx: &Transaction) -> ValidatorRecord {
    let mut input: &[u8] = &tx.call_data;
    let call = RegisterValidatorCall::decode(&mut input).expect("valid registration fixture");
    assert!(input.is_empty());
    ValidatorRecord {
        version: 1,
        status: ValidatorStatus::Active,
        reserved0: [0; 2],
        owner_keyset_id: call.owner_keyset_id,
        consensus_suite_id: call.consensus_suite_id,
        reserved1: [0; 3],
        consensus_pk: call.consensus_pk,
        network_suite_id: call.network_suite_id,
        reserved2: [0; 3],
        network_pk: call.network_pk,
        stake: call.stake,
        last_slash_height: 0,
        jailed_until_epoch: None,
        ext_bytes: Vec::new(),
    }
}

fn fixture_record_account(tx: &Transaction) -> Account {
    let target_id = tx.accounts[1].account_id;
    let mut data = Vec::new();
    fixture_record(tx).encode_state(&mut data);
    Account::new(target_id, VALIDATOR_PROGRAM_ID, 0, data)
}

fn assert_execution_error(actual: ExecutionError, expected: ExecutionError) {
    match (actual, expected) {
        (ExecutionError::InvalidCallData(actual), ExecutionError::InvalidCallData(expected))
        | (ExecutionError::CryptoError(actual), ExecutionError::CryptoError(expected))
        | (ExecutionError::ProgramError(actual), ExecutionError::ProgramError(expected)) => {
            assert_eq!(actual, expected)
        }
        (actual, expected) => panic!("error category mismatch: {actual:?} != {expected:?}"),
    }
}

fn assert_refusal_unchanged(
    fixture: &mut Fixture,
    tx: &Transaction,
    expected_error: ExecutionError,
    expected_reads: &[AccountId],
    expected_verification_delta: usize,
) {
    let state_before = fixture.store.complete_state();
    let tx_before = tx.clone();
    let wire_before = transaction_bytes(tx);
    let verify_before = fixture.verify_count();
    fixture.store.clear_events();

    assert_execution_error(
        fixture.execute(tx).expect_err("expected refusal"),
        expected_error,
    );
    let events = fixture.store.take_events();
    assert_eq!(events.reads, expected_reads);
    assert!(events.writes.is_empty());
    assert!(events.deletes.is_empty());
    assert_eq!(
        fixture.verify_count(),
        verify_before + expected_verification_delta
    );
    assert_eq!(fixture.store.complete_state(), state_before);
    assert_eq!(*tx, tx_before);
    assert_eq!(transaction_bytes(tx), wire_before);
}

fn assert_unavailable_then_retry(fixture: &mut Fixture, tx: &Transaction) {
    let target_id = tx.accounts[1].account_id;
    assert!(!fixture.store.complete_state().contains_key(&target_id));
    for _ in 0..2 {
        assert_refusal_unchanged(
            fixture,
            tx,
            ExecutionError::ProgramError(AUTHORITY_UNAVAILABLE),
            &[SIGNER_ID, target_id],
            1,
        );
        assert!(!fixture.store.complete_state().contains_key(&target_id));
    }
}

fn assert_direct_refusal_unchanged(
    fixture: &mut Fixture,
    tx: &Transaction,
    fixture_minimum: u64,
    expected_error: ExecutionError,
    expected_reads: &[AccountId],
) {
    let before = fixture.store.complete_state();
    let tx_before = tx.clone();
    let wire_before = transaction_bytes(tx);
    assert_eq!(
        fixture.verify_count(),
        0,
        "direct Program test, not TxExecutor"
    );
    fixture.store.clear_events();

    let mut context = ExecutionContext::new_with_min_stake(
        &mut fixture.store,
        Arc::clone(&fixture.crypto),
        fixture_minimum,
    );
    assert_execution_error(
        ValidatorProgram::new()
            .execute(&mut context, tx)
            .expect_err("direct Program refusal"),
        expected_error,
    );
    let events = fixture.store.take_events();
    assert_eq!(events.reads, expected_reads);
    assert!(events.writes.is_empty());
    assert!(events.deletes.is_empty());
    assert_eq!(fixture.verify_count(), 0, "no transaction verifier invoked");
    assert_eq!(fixture.store.complete_state(), before);
    assert_eq!(*tx, tx_before);
    assert_eq!(transaction_bytes(tx), wire_before);
}

#[test]
fn authenticated_unrelated_existing_owner_reaches_unavailable_refusal() {
    let mut fixture = Fixture::new(TARGET_ID, true, 71);
    let before = fixture.store.complete_state();
    let owner = before.get(&OWNER_ID).expect("owner keyset exists");
    assert_eq!(owner.header.owner, KEYSET_PROGRAM_ID);
    assert!(!owner.header.is_executable);
    assert_eq!(fixture.transaction.auths.len(), 1);
    assert_eq!(fixture.transaction.auths[0].account_index, 0);
    assert_eq!(fixture.transaction.accounts[2].flags & 1, 0);
    assert_eq!(fixture.setup_checks.consensus_signatures_verified, 1);
    assert_eq!(fixture.setup_checks.network_kem_round_trips, 1);

    let tx = fixture.transaction.clone();
    assert_unavailable_then_retry(&mut fixture, &tx);
    assert_eq!(fixture.store.complete_state(), before);
}

#[test]
fn authenticated_absent_owner_reaches_unavailable_refusal() {
    let mut fixture = Fixture::new(TARGET_ID, false, 72);
    let before = fixture.store.complete_state();
    assert!(!before.contains_key(&OWNER_ID));

    let tx = fixture.transaction.clone();
    assert_unavailable_then_retry(&mut fixture, &tx);
    assert_eq!(fixture.store.complete_state(), before);
    assert!(!fixture.store.complete_state().contains_key(&OWNER_ID));
}

#[test]
fn authenticated_large_declared_stake_and_usable_keys_cannot_bypass_refusal() {
    let mut fixture = Fixture::new(TARGET_ID, true, 9_876_543);
    let before = fixture.store.complete_state();
    let payer_before = before.get(&PAYER_ID).unwrap().clone();
    let owner_before = before.get(&OWNER_ID).unwrap().clone();

    let tx = fixture.transaction.clone();
    assert_unavailable_then_retry(&mut fixture, &tx);
    let after = fixture.store.complete_state();
    assert_eq!(after.get(&PAYER_ID), Some(&payer_before));
    assert_eq!(after.get(&OWNER_ID), Some(&owner_before));
    assert_eq!(after, before);
}

#[test]
fn authenticated_zero_stake_reaches_refusal_in_default_executor_context() {
    let mut fixture = Fixture::new(TARGET_ID, false, 0);
    let before = fixture.store.complete_state();
    let tx = fixture.transaction.clone();
    assert_unavailable_then_retry(&mut fixture, &tx);
    assert_eq!(fixture.store.complete_state(), before);
}

#[test]
fn authenticated_matching_owner_identity_does_not_manufacture_authority() {
    let mut fixture = Fixture::new(TARGET_ID, true, 73);
    let mut input: &[u8] = &fixture.transaction.call_data;
    let mut call = RegisterValidatorCall::decode(&mut input).unwrap();
    assert!(input.is_empty());
    call.owner_keyset_id = SIGNER_ID;
    fixture.transaction.call_data.clear();
    call.encode(&mut fixture.transaction.call_data);
    fixture.transaction.accounts[2].account_id = SIGNER_ID;
    sign(&mut fixture.transaction, &fixture.signer_secret);
    assert_eq!(
        call.owner_keyset_id,
        fixture.transaction.accounts[0].account_id
    );
    let tx = fixture.transaction.clone();
    assert_unavailable_then_retry(&mut fixture, &tx);
}

#[test]
fn direct_context_fixture_minimum_rejects_below_and_zero_without_authentication() {
    for stake in [79, 0] {
        let mut fixture = Fixture::new(TARGET_ID, true, stake);
        let tx = fixture.transaction.clone();
        assert_direct_refusal_unchanged(
            &mut fixture,
            &tx,
            80,
            ExecutionError::ProgramError("stake below minimum required for validator registration"),
            &[TARGET_ID],
        );
    }
}

#[test]
fn direct_context_equality_and_above_minimum_reach_refusal_without_authentication() {
    for stake in [80, u64::MAX] {
        let mut fixture = Fixture::new(TARGET_ID, true, stake);
        let tx = fixture.transaction.clone();
        assert_direct_refusal_unchanged(
            &mut fixture,
            &tx,
            80,
            ExecutionError::ProgramError(AUTHORITY_UNAVAILABLE),
            &[TARGET_ID],
        );
    }
}

#[test]
fn direct_context_existing_target_precedes_below_minimum_without_authentication() {
    let mut fixture = Fixture::new(TARGET_ID, true, 0);
    let tx = fixture.transaction.clone();
    fixture.store.seed(fixture_record_account(&tx));
    assert_direct_refusal_unchanged(
        &mut fixture,
        &tx,
        80,
        ExecutionError::ProgramError("validator already exists"),
        &[TARGET_ID],
    );
}

#[test]
fn direct_context_validation_precedes_existing_target_and_minimum_without_authentication() {
    let mut fixture = Fixture::new(TARGET_ID, true, 0);
    let genuine = fixture.transaction.clone();
    fixture.store.seed(fixture_record_account(&genuine));

    let mut wrong_program = genuine.clone();
    wrong_program.program_id = [0xFF; 32];
    wrong_program.call_data.clear();
    let mut empty = genuine.clone();
    empty.call_data.clear();
    let mut unsupported = genuine.clone();
    unsupported.call_data = vec![0x02];
    let mut truncated = genuine.clone();
    truncated.call_data.pop();
    let mut trailing = genuine.clone();
    trailing.call_data.push(0xAA);
    for (tx, error) in [
        (
            wrong_program,
            ExecutionError::ProgramError("program_id mismatch for ValidatorProgram"),
        ),
        (empty, ExecutionError::InvalidCallData("empty call_data")),
        (
            unsupported,
            ExecutionError::ProgramError("unsupported validator opcode"),
        ),
        (
            truncated,
            ExecutionError::InvalidCallData("invalid RegisterValidatorCall"),
        ),
        (
            trailing,
            ExecutionError::InvalidCallData("extra bytes after RegisterValidatorCall"),
        ),
    ] {
        assert_direct_refusal_unchanged(&mut fixture, &tx, 80, error, &[]);
    }
}

#[test]
fn signed_stake_change_is_rejected_until_the_changed_body_is_resigned() {
    let mut fixture = Fixture::new(TARGET_ID, true, 81);
    let before = fixture.store.complete_state();
    let original = fixture.transaction.clone();
    let original_wire = transaction_bytes(&original);

    let mut changed = original.clone();
    let mut original_call_input: &[u8] = &original.call_data;
    let original_call =
        RegisterValidatorCall::decode(&mut original_call_input).expect("original call");
    assert!(original_call_input.is_empty());
    let mut input: &[u8] = &changed.call_data;
    let mut call = RegisterValidatorCall::decode(&mut input).expect("original call");
    assert!(input.is_empty());
    call.stake = 82;
    changed.call_data.clear();
    call.encode(&mut changed.call_data);
    let mut changed_call_input: &[u8] = &changed.call_data;
    let changed_call =
        RegisterValidatorCall::decode(&mut changed_call_input).expect("changed call");
    assert!(changed_call_input.is_empty());
    assert_eq!(changed_call.version, original_call.version);
    assert_eq!(changed_call.validator_id, original_call.validator_id);
    assert_eq!(changed_call.owner_keyset_id, original_call.owner_keyset_id);
    assert_eq!(
        changed_call.consensus_suite_id,
        original_call.consensus_suite_id
    );
    assert_eq!(changed_call.consensus_pk, original_call.consensus_pk);
    assert_eq!(
        changed_call.network_suite_id,
        original_call.network_suite_id
    );
    assert_eq!(changed_call.network_pk, original_call.network_pk);
    assert_eq!(changed_call.stake, original_call.stake + 1);
    assert!(!before.contains_key(&TARGET_ID), "target is fresh");
    assert_eq!(changed.version, original.version);
    assert_eq!(changed.chain_id, original.chain_id);
    assert_eq!(changed.payer, original.payer);
    assert_eq!(changed.nonce, original.nonce);
    assert_eq!(changed.fee_limit, original.fee_limit);
    assert_eq!(changed.accounts, original.accounts);
    assert_eq!(changed.program_id, original.program_id);
    assert_eq!(changed.auths, original.auths);

    assert_refusal_unchanged(
        &mut fixture,
        &changed,
        ExecutionError::CryptoError("signature verification failed"),
        &[SIGNER_ID],
        1,
    );
    assert_eq!(fixture.store.complete_state(), before);
    assert_unavailable_then_retry(&mut fixture, &original);

    let changed_body = changed.call_data.clone();
    sign(&mut changed, &fixture.signer_secret);
    assert_eq!(changed.version, original.version);
    assert_eq!(changed.chain_id, original.chain_id);
    assert_eq!(changed.payer, original.payer);
    assert_eq!(changed.nonce, original.nonce);
    assert_eq!(changed.fee_limit, original.fee_limit);
    assert_eq!(changed.accounts, original.accounts);
    assert_eq!(changed.program_id, original.program_id);
    assert_eq!(changed.call_data, changed_body);
    assert_eq!(
        changed.auths[0].account_index,
        original.auths[0].account_index
    );
    assert_eq!(changed.auths[0].suite_id, original.auths[0].suite_id);
    assert_eq!(changed.auths[0].reserved, original.auths[0].reserved);
    assert_unavailable_then_retry(&mut fixture, &changed);
    assert_eq!(fixture.store.complete_state(), before);
    assert_eq!(transaction_bytes(&original), original_wire);
    assert_eq!(original, fixture.transaction);
}

#[test]
fn empty_auth_and_tampered_signature_refuse_then_genuine_retry_reaches_gate() {
    let mut empty_auth = Fixture::new(TARGET_ID, true, 83);
    let before = empty_auth.store.complete_state();
    let valid_retry = empty_auth.transaction.clone();
    let mut no_auth = valid_retry.clone();
    no_auth.auths.clear();
    assert_refusal_unchanged(
        &mut empty_auth,
        &no_auth,
        ExecutionError::InvalidCallData("transaction requires at least one authentication entry"),
        &[],
        0,
    );
    assert_unavailable_then_retry(&mut empty_auth, &valid_retry);
    assert_eq!(empty_auth.store.complete_state(), before);

    let mut tampered = Fixture::new(TARGET_ID, true, 84);
    let before = tampered.store.complete_state();
    let valid_retry = tampered.transaction.clone();
    let mut bad_signature = valid_retry.clone();
    bad_signature.auths[0].signature[0] ^= 1;
    assert_refusal_unchanged(
        &mut tampered,
        &bad_signature,
        ExecutionError::CryptoError("signature verification failed"),
        &[SIGNER_ID],
        1,
    );
    assert_unavailable_then_retry(&mut tampered, &valid_retry);
    assert_eq!(tampered.store.complete_state(), before);
}

#[test]
fn repeated_fresh_target_registration_authenticates_and_refuses_each_time() {
    let mut fixture = Fixture::new(TARGET_ID, true, 85);
    let tx = fixture.transaction.clone();
    let before = fixture.store.complete_state();
    assert_unavailable_then_retry(&mut fixture, &tx);
    assert_eq!(fixture.verify_count(), 2);
    assert_eq!(fixture.store.complete_state(), before);
}

#[test]
fn preexisting_validator_record_seeded_directly_is_not_overwritten() {
    let mut fixture = Fixture::new(TARGET_ID, true, 85);
    let tx = fixture.transaction.clone();
    let stored = fixture_record_account(&tx);
    fixture.store.seed(stored.clone());
    for _ in 0..2 {
        assert_refusal_unchanged(
            &mut fixture,
            &tx,
            ExecutionError::ProgramError("validator already exists"),
            &[SIGNER_ID, TARGET_ID],
            1,
        );
        assert_eq!(
            fixture.store.complete_state().get(&TARGET_ID),
            Some(&stored)
        );
    }
}

#[test]
fn preexisting_unrelated_target_is_not_overwritten() {
    let mut fixture = Fixture::new(TARGET_ID, true, 86);
    let mut unrelated = Account::new(TARGET_ID, [0x98; 32], 345, vec![9, 8, 7]);
    unrelated.header.rent_epoch = 123;
    unrelated.header.reserved = [0xA5; 8];
    fixture.store.seed(unrelated.clone());
    let before = fixture.store.complete_state();

    let tx = fixture.transaction.clone();
    for _ in 0..2 {
        assert_refusal_unchanged(
            &mut fixture,
            &tx,
            ExecutionError::ProgramError("validator already exists"),
            &[SIGNER_ID, TARGET_ID],
            1,
        );
    }
    assert_eq!(
        fixture.store.complete_state().get(&TARGET_ID),
        Some(&unrelated)
    );
    assert_eq!(fixture.store.complete_state(), before);
}

#[test]
fn authenticated_framing_controls_refuse_before_target_lookup() {
    let mut truncated = Fixture::new(TARGET_ID, true, 87);
    let genuine_retry = truncated.transaction.clone();
    truncated.transaction.call_data.pop();
    sign(&mut truncated.transaction, &truncated.signer_secret);
    let truncated_tx = truncated.transaction.clone();
    assert_refusal_unchanged(
        &mut truncated,
        &truncated_tx,
        ExecutionError::InvalidCallData("invalid RegisterValidatorCall"),
        &[SIGNER_ID],
        1,
    );
    assert_unavailable_then_retry(&mut truncated, &genuine_retry);

    let mut trailing = Fixture::new(TARGET_ID, true, 88);
    let genuine_retry = trailing.transaction.clone();
    trailing.transaction.call_data.push(0xAA);
    sign(&mut trailing.transaction, &trailing.signer_secret);
    let trailing_tx = trailing.transaction.clone();
    assert_refusal_unchanged(
        &mut trailing,
        &trailing_tx,
        ExecutionError::InvalidCallData("extra bytes after RegisterValidatorCall"),
        &[SIGNER_ID],
        1,
    );
    assert_unavailable_then_retry(&mut trailing, &genuine_retry);

    let mut unsupported = Fixture::new(TARGET_ID, true, 89);
    let genuine_retry = unsupported.transaction.clone();
    unsupported.transaction.call_data[0] = 0x02;
    sign(&mut unsupported.transaction, &unsupported.signer_secret);
    let unsupported_tx = unsupported.transaction.clone();
    assert_refusal_unchanged(
        &mut unsupported,
        &unsupported_tx,
        ExecutionError::ProgramError("unsupported validator opcode"),
        &[SIGNER_ID],
        1,
    );
    assert_unavailable_then_retry(&mut unsupported, &genuine_retry);

    let mut empty = Fixture::new(TARGET_ID, true, 89);
    let genuine_retry = empty.transaction.clone();
    empty.transaction.call_data.clear();
    sign(&mut empty.transaction, &empty.signer_secret);
    let empty_tx = empty.transaction.clone();
    assert_refusal_unchanged(
        &mut empty,
        &empty_tx,
        ExecutionError::InvalidCallData("empty call_data"),
        &[SIGNER_ID],
        1,
    );
    assert_unavailable_then_retry(&mut empty, &genuine_retry);

    let mut valid = Fixture::new(TARGET_ID, true, 90);
    let tx = valid.transaction.clone();
    assert_unavailable_then_retry(&mut valid, &tx);
}
