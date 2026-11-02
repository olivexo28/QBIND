//! Unavailable-authority refusal controls, not an approved creation or signer policy.
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use qbind_crypto::error::CryptoError;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
use qbind_crypto::{
    ml_dsa_44_sign_digest, CryptoProvider, MlDsa44SignatureSuite, StaticCryptoProvider,
};
use qbind_hash::tx::tx_digest;
use qbind_ledger::{Account, AccountHeader, AccountStore, ExecutionError};
use qbind_runtime::TxExecutor;
use qbind_serde::StateDecode;
use qbind_system::keyset_program::KEYSET_PROGRAM_ID;
use qbind_types::{AccountId, Hash32, KeysetAccount, KeysetEntry};
use qbind_wire::io::{WireDecode, WireEncode};
use qbind_wire::keyset::{CreateKeysetCall, WireKeyEntry, OP_KEYSET_CREATE};
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};

const SUITE: u8 = 100;
const SIGNER: AccountId = [0x11; 32];
const TARGET: AccountId = [0x22; 32];
const FRESH: AccountId = [0x33; 32];
const PAYER: AccountId = [0x44; 32];
const SENTINEL: AccountId = [0x55; 32];

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

    // Snapshots bypass get so they cannot contaminate the measured trace.
    fn snapshot(&self) -> HashMap<AccountId, Account> {
        self.accounts.clone()
    }

    fn reset(&mut self) {
        self.reads.borrow_mut().clear();
        self.puts.clear();
        self.deletes.clear();
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

#[derive(Debug, PartialEq, Eq)]
struct Verification {
    key: Vec<u8>,
    digest: Hash32,
    signature: Vec<u8>,
}

#[derive(Default)]
struct CryptoWork {
    verifications: Mutex<Vec<Verification>>,
    descriptors: AtomicUsize,
}

struct CountedSuite {
    inner: MlDsa44SignatureSuite,
    work: Arc<CryptoWork>,
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
        self.work.descriptors.fetch_add(1, Ordering::SeqCst);
        self.inner.canonical_key_descriptor(key)
    }

    fn verify(&self, key: &[u8], digest: &Hash32, signature: &[u8]) -> Result<(), CryptoError> {
        self.work.verifications.lock().unwrap().push(Verification {
            key: key.to_vec(),
            digest: *digest,
            signature: signature.to_vec(),
        });
        self.inner.verify(key, digest, signature)
    }
}

struct Key {
    public: Vec<u8>,
    secret: Vec<u8>,
}

impl Key {
    fn genuine() -> Self {
        let (public, secret) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair");
        let digest = [0xA5; 32];
        let signature = ml_dsa_44_sign_digest(&secret, &digest).expect("fixture key signs");
        MlDsa44SignatureSuite::new(SUITE)
            .verify(&public, &digest, &signature)
            .expect("independent fixture usability, outside measured execution");
        Self { public, secret }
    }

    fn entry(&self, weight: u16) -> WireKeyEntry {
        WireKeyEntry {
            suite_id: SUITE,
            weight,
            pubkey_bytes: self.public.clone(),
        }
    }
}

struct Fixture {
    store: WitnessStore,
    signer: Key,
    candidate: Key,
    work: Arc<CryptoWork>,
    provider: Arc<dyn CryptoProvider>,
    executor: TxExecutor<WitnessStore>,
}

enum Outcome {
    Refused(ExecutionError),
}

impl Fixture {
    fn new() -> Self {
        let signer = Key::genuine();
        let candidate = Key::genuine();
        assert_ne!(signer.public, candidate.public);
        let mut store = WitnessStore::default();
        store.seed(fixture_keyset_account(&call(
            SIGNER,
            1,
            vec![signer.entry(1)],
        )));
        let mut sentinel = Account::new(SENTINEL, [0x66; 32], 987_654, vec![9, 8, 7]);
        sentinel.header.is_executable = true;
        sentinel.header.rent_epoch = 123;
        sentinel.header.reserved = [0xA6; 8];
        store.seed(sentinel);
        let work = Arc::new(CryptoWork::default());
        let provider: Arc<dyn CryptoProvider> = Arc::new(
            StaticCryptoProvider::new().with_signature_suite(Arc::new(CountedSuite {
                inner: MlDsa44SignatureSuite::new(SUITE),
                work: Arc::clone(&work),
            })),
        );
        Self {
            store,
            signer,
            candidate,
            work,
            provider,
            executor: TxExecutor::new(),
        }
    }

    fn ordinary_call(&self, target: AccountId) -> CreateKeysetCall {
        call(target, 1, vec![self.candidate.entry(1)])
    }

    fn signed(&self, call: &CreateKeysetCall) -> Transaction {
        let mut tx = transaction(call);
        sign(&mut tx, &self.signer);
        tx
    }

    fn invoke(
        &mut self,
        tx: &Transaction,
        outcome: Outcome,
        reads: &[AccountId],
        verification_count: usize,
    ) {
        let before = self.store.snapshot();
        let original_tx = tx.clone();
        let original_wire = wire_bytes(tx);
        let mut remaining = original_wire.as_slice();
        assert_eq!(Transaction::decode(&mut remaining).unwrap(), *tx);
        assert!(remaining.is_empty());
        let expected_verifications = if verification_count == 0 {
            Vec::new()
        } else {
            assert_eq!(verification_count, 1, "bounded single-proof cases");
            let auth = &tx.auths[0];
            let account = &before[&tx.accounts[usize::from(auth.account_index)].account_id];
            let mut input = account.data.as_slice();
            let keyset = KeysetAccount::decode_state(&mut input).unwrap();
            assert!(input.is_empty());
            vec![Verification {
                key: keyset.entries[0].pubkey_bytes.clone(),
                digest: tx_digest(tx),
                signature: auth.signature.clone(),
            }]
        };
        self.store.reset();
        self.work.verifications.lock().unwrap().clear();
        self.work.descriptors.store(0, Ordering::SeqCst);

        let result =
            self.executor
                .execute_transaction(&mut self.store, Arc::clone(&self.provider), tx);

        assert_eq!(*self.store.reads.borrow(), reads);
        assert!(self.store.deletes.is_empty());
        assert_eq!(
            *self.work.verifications.lock().unwrap(),
            expected_verifications
        );
        assert_eq!(self.work.descriptors.load(Ordering::SeqCst), 0);
        let Outcome::Refused(expected) = outcome;
        assert_error(
            result.expect_err("native keyset creation must refuse"),
            expected,
        );
        assert!(self.store.puts.is_empty());
        assert_eq!(self.store.snapshot(), before);
        if let Some(target) = tx.call_data.get(2..34) {
            let mut target_id = [0; 32];
            target_id.copy_from_slice(target);
            assert_eq!(
                self.store.snapshot().contains_key(&target_id),
                before.contains_key(&target_id)
            );
        }
        assert_eq!(*tx, original_tx);
        assert_eq!(wire_bytes(tx), original_wire);
    }
}

fn call(target: AccountId, threshold: u16, entries: Vec<WireKeyEntry>) -> CreateKeysetCall {
    CreateKeysetCall {
        version: 1,
        target_id: target,
        threshold,
        entries,
    }
}

// Fixture-only account construction for pre-existing signer state.
fn fixture_keyset_account(call: &CreateKeysetCall) -> Account {
    let count = u16::try_from(call.entries.len()).unwrap();
    let mut data = vec![call.version, 0, 0, 0];
    data.extend_from_slice(&call.threshold.to_le_bytes());
    data.extend_from_slice(&count.to_le_bytes());
    data.extend_from_slice(&[0; 4]);
    let mut entries = Vec::new();
    for entry in &call.entries {
        let length = u16::try_from(entry.pubkey_bytes.len()).unwrap();
        data.push(entry.suite_id);
        data.extend_from_slice(&entry.weight.to_le_bytes());
        data.push(0);
        data.extend_from_slice(&length.to_le_bytes());
        data.extend_from_slice(&entry.pubkey_bytes);
        entries.push(KeysetEntry {
            suite_id: entry.suite_id,
            weight: entry.weight,
            reserved0: [0],
            pubkey_len: length,
            pubkey_bytes: entry.pubkey_bytes.clone(),
        });
    }
    let mut input = data.as_slice();
    assert_eq!(
        KeysetAccount::decode_state(&mut input).unwrap(),
        KeysetAccount {
            version: call.version,
            reserved0: [0; 3],
            threshold: call.threshold,
            entry_count: count,
            reserved1: [0; 4],
            entries,
        }
    );
    assert!(input.is_empty());
    Account {
        id: call.target_id,
        header: AccountHeader {
            owner: KEYSET_PROGRAM_ID,
            lamports: 0,
            is_executable: false,
            rent_epoch: 0,
            reserved: [0; 8],
        },
        data,
    }
}

fn transaction(call: &CreateKeysetCall) -> Transaction {
    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    Transaction {
        version: 1,
        chain_id: 1,
        payer: PAYER,
        nonce: 42,
        fee_limit: 100_000,
        accounts: vec![
            TxAccountMeta {
                account_id: SIGNER,
                flags: 1,
                access_hint: 1,
                reserved0: [0; 2],
            },
            TxAccountMeta {
                account_id: call.target_id,
                flags: 2,
                access_hint: 3,
                reserved0: [0; 2],
            },
        ],
        program_id: KEYSET_PROGRAM_ID,
        call_data,
        auths: Vec::new(),
    }
}

fn sign(tx: &mut Transaction, key: &Key) {
    tx.auths = vec![TxAuth {
        account_index: 0,
        suite_id: SUITE,
        reserved: 0,
        signature: ml_dsa_44_sign_digest(&key.secret, &tx_digest(tx))
            .expect("genuine tx signature"),
    }];
}

fn wire_bytes(tx: &Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    tx.encode(&mut bytes);
    bytes
}

fn assert_error(actual: ExecutionError, expected: ExecutionError) {
    match (actual, expected) {
        (ExecutionError::AccountNotFound, ExecutionError::AccountNotFound) => {}
        (ExecutionError::InvalidCallData(a), ExecutionError::InvalidCallData(b))
        | (ExecutionError::CryptoError(a), ExecutionError::CryptoError(b))
        | (ExecutionError::ProgramError(a), ExecutionError::ProgramError(b)) => assert_eq!(a, b),
        (a, b) => panic!("exact error variant mismatch: {a:?} != {b:?}"),
    }
}

#[test]
fn authenticated_creation_reaches_unavailable_authority() {
    let mut f = Fixture::new();
    let call = f.ordinary_call(TARGET);
    let tx = f.signed(&call);
    assert_ne!(SIGNER, TARGET);
    assert_eq!(tx.accounts[1].flags & 1, 0);
    assert_eq!(tx.auths.len(), 1);
    assert_eq!(tx.auths[0].account_index, 0);
    let signature = &tx.auths[0].signature;
    assert!(MlDsa44SignatureSuite::new(SUITE)
        .verify(&f.candidate.public, &tx_digest(&tx), signature)
        .is_err());
    f.invoke(
        &tx,
        Outcome::Refused(ExecutionError::ProgramError(
            "native keyset creation authority unavailable",
        )),
        &[SIGNER, TARGET],
        1,
    );
}

#[test]
fn payer_is_signed_data_not_independent_authority_or_fee_payment() {
    for seed_payer in [false, true] {
        let mut f = Fixture::new();
        if seed_payer {
            let mut payer = Account::new(PAYER, [0x77; 32], 765_432, vec![1, 3, 5]);
            payer.header.rent_epoch = 71;
            payer.header.reserved = [0xBC; 8];
            f.store.seed(payer);
        }
        let call = f.ordinary_call(TARGET);
        let tx = f.signed(&call);
        assert_eq!(tx.payer, PAYER);
        assert_ne!(tx.payer, SIGNER);
        assert!(tx.accounts.iter().all(|meta| meta.account_id != PAYER));
        f.invoke(
            &tx,
            Outcome::Refused(ExecutionError::ProgramError(
                "native keyset creation authority unavailable",
            )),
            &[SIGNER, TARGET],
            1,
        );
    }
}

#[test]
fn signed_target_binding_and_resigned_fresh_state() {
    let mut f = Fixture::new();
    let original_call = f.ordinary_call(TARGET);
    let original_tx = f.signed(&original_call);
    let original_value = original_tx.clone();
    let original_bytes = wire_bytes(&original_tx);
    let changed_call = f.ordinary_call(FRESH);
    let mut changed = original_tx.clone();
    changed.call_data.clear();
    changed_call.encode(&mut changed.call_data);
    let mut expected_body_change = original_tx.clone();
    expected_body_change.call_data = changed.call_data.clone();
    assert_eq!(changed, expected_body_change);
    assert_ne!(tx_digest(&original_tx), tx_digest(&changed));
    f.invoke(
        &changed,
        Outcome::Refused(ExecutionError::CryptoError("signature verification failed")),
        &[SIGNER],
        1,
    );
    // Only the call target changes; the signed metadata still names TARGET.
    sign(&mut changed, &f.signer);
    assert_eq!(changed.accounts, original_tx.accounts);
    f.invoke(
        &changed,
        Outcome::Refused(ExecutionError::ProgramError(
            "native keyset creation authority unavailable",
        )),
        &[SIGNER, FRESH],
        1,
    );
    assert_eq!(original_tx, original_value);
    assert_eq!(wire_bytes(&original_tx), original_bytes);
}

#[test]
fn authentication_refusals_then_valid_retry() {
    let mut f = Fixture::new();
    let call = f.ordinary_call(TARGET);
    let valid = f.signed(&call);
    let mut empty = valid.clone();
    empty.auths.clear();
    f.invoke(
        &empty,
        Outcome::Refused(ExecutionError::InvalidCallData(
            "transaction requires at least one authentication entry",
        )),
        &[],
        0,
    );
    let mut malformed = valid.clone();
    malformed.auths[0].signature.pop();
    let mut tampered = valid.clone();
    tampered.auths[0].signature[100] ^= 0x80;
    for tx in [&malformed, &tampered] {
        f.invoke(
            tx,
            Outcome::Refused(ExecutionError::CryptoError("signature verification failed")),
            &[SIGNER],
            1,
        );
    }
    f.invoke(
        &valid,
        Outcome::Refused(ExecutionError::ProgramError(
            "native keyset creation authority unavailable",
        )),
        &[SIGNER, TARGET],
        1,
    );
}

#[test]
fn repeated_absent_target_and_same_nonce_requests_refuse_without_writes() {
    let mut f = Fixture::new();
    let call = f.ordinary_call(TARGET);
    let tx = f.signed(&call);
    f.invoke(
        &tx,
        Outcome::Refused(ExecutionError::ProgramError(
            "native keyset creation authority unavailable",
        )),
        &[SIGNER, TARGET],
        1,
    );
    assert!(!f.store.snapshot().contains_key(&TARGET));
    f.invoke(
        &tx,
        Outcome::Refused(ExecutionError::ProgramError(
            "native keyset creation authority unavailable",
        )),
        &[SIGNER, TARGET],
        1,
    );
    assert!(!f.store.snapshot().contains_key(&TARGET));
    let fresh_call = f.ordinary_call(FRESH);
    let fresh_tx = f.signed(&fresh_call);
    assert_eq!(fresh_tx.nonce, tx.nonce);
    f.invoke(
        &fresh_tx,
        Outcome::Refused(ExecutionError::ProgramError(
            "native keyset creation authority unavailable",
        )),
        &[SIGNER, FRESH],
        1,
    );

    let mut unrelated = Fixture::new();
    let mut existing = Account::new(TARGET, [0x88; 32], 123_456, vec![0xDE, 0xAD]);
    existing.header.is_executable = true;
    existing.header.rent_epoch = 99;
    existing.header.reserved = [0xCE; 8];
    unrelated.store.seed(existing);
    let tx = unrelated.signed(&unrelated.ordinary_call(TARGET));
    unrelated.invoke(
        &tx,
        Outcome::Refused(ExecutionError::ProgramError(
            "keyset account already exists",
        )),
        &[SIGNER, TARGET],
        1,
    );
}

#[test]
fn structurally_decodable_candidate_variants_all_reach_unavailable_authority() {
    let mut f = Fixture::new();
    let duplicate = f.candidate.entry(1);
    let mut inconsistent = duplicate.clone();
    inconsistent.weight = 2;
    let cases = [
        ("empty entries", 1, vec![]),
        ("unreachable threshold", 2, vec![f.candidate.entry(1)]),
        ("zero weight", 1, vec![f.candidate.entry(0)]),
        ("zero threshold", 0, vec![f.candidate.entry(1)]),
        ("both zero", 0, vec![f.candidate.entry(0)]),
        (
            "inconsistent duplicate weights",
            2,
            vec![duplicate, inconsistent],
        ),
        (
            "unsupported suite",
            1,
            vec![WireKeyEntry {
                suite_id: 0xFE,
                weight: 1,
                pubkey_bytes: vec![1, 2, 3],
            }],
        ),
        (
            "malformed ML-DSA-44 key",
            1,
            vec![WireKeyEntry {
                suite_id: SUITE,
                weight: 1,
                pubkey_bytes: vec![0],
            }],
        ),
    ];
    for (index, (label, threshold, entries)) in cases.into_iter().enumerate() {
        let target = [0x80 + u8::try_from(index).unwrap(); 32];
        let call = call(target, threshold, entries);
        let tx = f.signed(&call);
        println!("structural candidate case: {label}");
        f.invoke(
            &tx,
            Outcome::Refused(ExecutionError::ProgramError(
                "native keyset creation authority unavailable",
            )),
            &[SIGNER, target],
            1,
        );
    }
}

#[test]
fn preseeded_threshold_two_and_threshold_one_controls_reach_unavailable_authority() {
    for threshold in [2, 1] {
        let mut f = Fixture::new();
        let second = Key::genuine();
        assert_ne!(f.candidate.public, second.public);
        let entries = if threshold == 2 {
            vec![f.candidate.entry(1), second.entry(1)]
        } else {
            vec![f.candidate.entry(1)]
        };
        let threshold_call = call(TARGET, threshold, entries);
        let initial_attempt = f.signed(&threshold_call);
        f.invoke(
            &initial_attempt,
            Outcome::Refused(ExecutionError::ProgramError(
                "native keyset creation authority unavailable",
            )),
            &[SIGNER, TARGET],
            1,
        );
        assert!(!f.store.snapshot().contains_key(&TARGET));
        // Fixture setup only: the production create refusal above left TARGET absent.
        f.store.seed(fixture_keyset_account(&threshold_call));
        let next = call(FRESH, 1, vec![second.entry(1)]);
        let mut later_tx = transaction(&next);
        later_tx.accounts[0].account_id = TARGET;
        sign(&mut later_tx, &f.candidate);
        assert_eq!(later_tx.auths.len(), 1);
        assert_eq!(threshold_call.entries[0].weight, 1);
        assert_eq!(threshold_call.threshold, threshold);
        assert_ne!(
            later_tx.auths[0].signature,
            initial_attempt.auths[0].signature
        );
        f.invoke(
            &later_tx,
            Outcome::Refused(ExecutionError::ProgramError(
                "native keyset creation authority unavailable",
            )),
            &[TARGET, FRESH],
            1,
        );
    }
}

#[test]
fn absent_signer_keyset_cannot_bootstrap_its_own_creation() {
    let mut f = Fixture::new();
    let call = f.ordinary_call(TARGET);
    let mut tx = transaction(&call);
    tx.accounts[0].account_id = TARGET;
    sign(&mut tx, &f.candidate);
    MlDsa44SignatureSuite::new(SUITE)
        .verify(&f.candidate.public, &tx_digest(&tx), &tx.auths[0].signature)
        .expect("mathematically valid signature, not pre-state authority");
    f.invoke(
        &tx,
        Outcome::Refused(ExecutionError::AccountNotFound),
        &[TARGET],
        0,
    );
}

#[test]
fn authenticated_framing_controls_refuse_before_target_access() {
    let mut f = Fixture::new();
    let call = f.ordinary_call(TARGET);
    let valid = f.signed(&call);
    let mut truncated = valid.call_data.clone();
    truncated.pop();
    let mut trailing = valid.call_data.clone();
    trailing.push(0xA7);
    let cases = [
        (vec![], ExecutionError::InvalidCallData("empty call_data")),
        (
            vec![0xFF],
            ExecutionError::ProgramError("unsupported keyset opcode"),
        ),
        (
            vec![OP_KEYSET_CREATE],
            ExecutionError::InvalidCallData("invalid CreateKeysetCall"),
        ),
        (
            truncated,
            ExecutionError::InvalidCallData("invalid CreateKeysetCall"),
        ),
        (
            trailing,
            ExecutionError::InvalidCallData("extra bytes after CreateKeysetCall"),
        ),
    ];
    for (data, error) in cases {
        let mut tx = valid.clone();
        tx.call_data = data;
        sign(&mut tx, &f.signer);
        f.invoke(&tx, Outcome::Refused(error), &[SIGNER], 1);
    }
}
