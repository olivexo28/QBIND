use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use qbind_crypto::{
    ml_dsa_44_sign_digest, AeadSuite, CryptoError, CryptoProvider, KemSuite, MlDsa44SignatureSuite,
    SignatureSuite, StaticCryptoProvider,
};
use qbind_ledger::auth::verify_transaction_auth;
use qbind_ledger::{Account, AccountStore, ExecutionContext, ExecutionError, InMemoryAccountStore};
use qbind_serde::StateEncode;
use qbind_types::{AccountId, Hash32, KeysetAccount, KeysetEntry, ProgramId};
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};

const EMPTY_AUTH_ERROR: &str = "transaction requires at least one authentication entry";

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn dummy_program_id(byte: u8) -> ProgramId {
    [byte; 32]
}

/// Structural-only provider control; it is not cryptographic acceptance evidence.
struct AcceptAllSignatureSuite;

impl SignatureSuite for AcceptAllSignatureSuite {
    fn suite_id(&self) -> u8 {
        1
    }

    fn public_key_len(&self) -> usize {
        0 // Variable/unknown
    }

    fn signature_len(&self) -> usize {
        0 // Variable/unknown
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &Hash32, _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// Structural-only provider control; it is not cryptographic acceptance evidence.
struct RejectAllSignatureSuite;

impl SignatureSuite for RejectAllSignatureSuite {
    fn suite_id(&self) -> u8 {
        2
    }

    fn public_key_len(&self) -> usize {
        0
    }

    fn signature_len(&self) -> usize {
        0
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &Hash32, _sig: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::InvalidSignature)
    }
}

/// Structural/provider controls only; these suites are not cryptographic evidence.
/// The real ML-DSA-44 adapter is exercised in a separate test below.
///
/// Returns AcceptAllSignatureSuite for suite_id 1, RejectAllSignatureSuite for
/// suite_id 2, and None for others.
struct TestCryptoProvider {
    accept_suite: AcceptAllSignatureSuite,
    reject_suite: RejectAllSignatureSuite,
}

impl TestCryptoProvider {
    fn new() -> Self {
        Self {
            accept_suite: AcceptAllSignatureSuite,
            reject_suite: RejectAllSignatureSuite,
        }
    }
}

impl CryptoProvider for TestCryptoProvider {
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
        match suite_id {
            1 => Some(&self.accept_suite),
            2 => Some(&self.reject_suite),
            _ => None,
        }
    }

    fn kem_suite(&self, _suite_id: u8) -> Option<&dyn qbind_crypto::KemSuite> {
        None
    }

    fn aead_suite(&self, _suite_id: u8) -> Option<&dyn qbind_crypto::AeadSuite> {
        None
    }
}

fn make_keyset_account(suite_id: u8, pubkey_bytes: Vec<u8>) -> KeysetAccount {
    // In test code, we expect small pubkey_bytes that fit in u16.
    assert!(
        pubkey_bytes.len() <= u16::MAX as usize,
        "pubkey_bytes too large for test"
    );
    let pubkey_len = pubkey_bytes.len() as u16;
    let entry = KeysetEntry {
        suite_id,
        weight: 1,
        reserved0: [0u8; 1],
        pubkey_len,
        pubkey_bytes,
    };
    KeysetAccount {
        version: 1,
        reserved0: [0u8; 3],
        threshold: 1,
        entry_count: 1, // matches entries.len() below
        reserved1: [0u8; 4],
        entries: vec![entry],
    }
}

fn make_transaction(accounts: Vec<TxAccountMeta>, auths: Vec<TxAuth>) -> Transaction {
    Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000,
        accounts,
        program_id: dummy_program_id(0x99),
        call_data: Vec::new(),
        auths,
    }
}

#[derive(Default)]
struct OperationCounts {
    reads: Cell<usize>,
    writes: Cell<usize>,
    deletes: Cell<usize>,
}

#[derive(Default)]
struct CountingStore {
    accounts: HashMap<AccountId, Account>,
    counts: OperationCounts,
}

impl CountingStore {
    fn seed(&mut self, account: Account) {
        self.accounts.insert(account.id, account);
    }

    fn snapshot(&self) -> HashMap<AccountId, Account> {
        self.accounts.clone()
    }

    fn reset_counts(&self) {
        self.counts.reads.set(0);
        self.counts.writes.set(0);
        self.counts.deletes.set(0);
    }
}

impl AccountStore for CountingStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.counts.reads.set(self.counts.reads.get() + 1);
        self.accounts.get(id).cloned()
    }

    fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
        self.counts.writes.set(self.counts.writes.get() + 1);
        self.accounts.insert(account.id, account);
        Ok(())
    }

    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
        self.counts.deletes.set(self.counts.deletes.get() + 1);
        self.accounts.remove(id);
        Ok(())
    }
}

struct CountingSignatureSuite {
    calls: Arc<AtomicUsize>,
}

impl SignatureSuite for CountingSignatureSuite {
    fn suite_id(&self) -> u8 {
        1
    }

    fn public_key_len(&self) -> usize {
        0
    }

    fn signature_len(&self) -> usize {
        0
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &Hash32, _sig: &[u8]) -> Result<(), CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct CountingCryptoProvider {
    lookups: Arc<AtomicUsize>,
    suite: CountingSignatureSuite,
}

impl CountingCryptoProvider {
    fn new() -> Self {
        let calls = Arc::new(AtomicUsize::new(0));
        Self {
            lookups: Arc::new(AtomicUsize::new(0)),
            suite: CountingSignatureSuite { calls },
        }
    }

    fn verification_calls(&self) -> usize {
        self.suite.calls.load(Ordering::SeqCst)
    }
}

impl CryptoProvider for CountingCryptoProvider {
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        (suite_id == 1).then_some(&self.suite)
    }

    fn kem_suite(&self, _suite_id: u8) -> Option<&dyn KemSuite> {
        None
    }

    fn aead_suite(&self, _suite_id: u8) -> Option<&dyn AeadSuite> {
        None
    }
}

fn seeded_counting_store() -> CountingStore {
    let keyset_id = dummy_account_id(0xAA);
    let mut encoded = Vec::new();
    make_keyset_account(1, vec![1, 2, 3]).encode_state(&mut encoded);
    let mut store = CountingStore::default();
    store.seed(Account::new(keyset_id, dummy_program_id(0x4B), 0, encoded));
    store.reset_counts();
    store
}

fn signed_native_fixture() -> (CountingStore, Arc<dyn CryptoProvider>, Transaction) {
    let keyset_id = dummy_account_id(0xA1);
    let (public_key, secret_key) =
        qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
    let keyset = make_keyset_account(100, public_key);
    let mut encoded = Vec::new();
    keyset.encode_state(&mut encoded);

    let mut store = CountingStore::default();
    store.seed(Account::new(keyset_id, dummy_program_id(0x4B), 0, encoded));

    let mut tx = make_transaction(
        vec![TxAccountMeta {
            account_id: keyset_id,
            flags: 1,
            access_hint: 0,
            reserved0: [0; 2],
        }],
        vec![TxAuth {
            account_index: 0,
            suite_id: 100,
            reserved: 0,
            signature: Vec::new(),
        }],
    );
    let digest = qbind_hash::tx::tx_digest(&tx);
    tx.auths[0].signature =
        ml_dsa_44_sign_digest(&secret_key, &digest).expect("sign canonical tx_digest");
    let crypto: Arc<dyn CryptoProvider> = Arc::new(
        StaticCryptoProvider::new().with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(100))),
    );
    (store, crypto, tx)
}

fn two_signer_fixture(
    duplicate_ids: bool,
) -> (CountingStore, Arc<dyn CryptoProvider>, Transaction) {
    let mut store = CountingStore::default();
    let (public_key, secret_key) =
        qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
    let first_id = dummy_account_id(0xA1);
    let second_id = if duplicate_ids {
        first_id
    } else {
        dummy_account_id(0xA2)
    };
    let mut encoded = Vec::new();
    make_keyset_account(100, public_key).encode_state(&mut encoded);
    store.seed(Account::new(second_id, dummy_program_id(0x4B), 0, encoded));
    let (first_pk, first_sk) =
        qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
    let mut first_data = Vec::new();
    make_keyset_account(100, first_pk).encode_state(&mut first_data);
    store.seed(Account::new(
        first_id,
        dummy_program_id(0x4B),
        0,
        first_data,
    ));
    let mut tx = make_transaction(
        [first_id, second_id]
            .into_iter()
            .map(|account_id| TxAccountMeta {
                account_id,
                flags: 1,
                access_hint: 0,
                reserved0: [0; 2],
            })
            .collect(),
        (0..2)
            .map(|account_index| TxAuth {
                account_index,
                suite_id: 100,
                reserved: 0,
                signature: Vec::new(),
            })
            .collect(),
    );
    let digest = qbind_hash::tx::tx_digest(&tx);
    tx.auths[0].signature = ml_dsa_44_sign_digest(&first_sk, &digest).expect("sign first");
    let second_sk = if duplicate_ids {
        &first_sk
    } else {
        &secret_key
    };
    tx.auths[1].signature = ml_dsa_44_sign_digest(second_sk, &digest).expect("sign second");
    store.reset_counts();
    let crypto: Arc<dyn CryptoProvider> = Arc::new(
        StaticCryptoProvider::new().with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(100))),
    );
    (store, crypto, tx)
}

#[test]
fn genuine_required_signers_use_exact_indices_not_account_ids_or_auth_count() {
    for duplicate_ids in [false, true] {
        let (mut store, crypto, tx) = two_signer_fixture(duplicate_ids);
        verify_transaction_auth(&mut store, crypto.clone(), &tx).expect("two genuine signatures");
        let witness = store.snapshot();
        let mut partial = tx.clone();
        let removed = partial.auths.pop().unwrap();
        assert_eq!(partial.auths.len(), 1);
        assert_eq!(partial.auths[0], tx.auths[0]);
        assert_eq!(
            qbind_hash::tx::tx_digest(&partial),
            qbind_hash::tx::tx_digest(&tx)
        );
        let mut restored = partial.clone();
        restored.auths.push(removed);
        assert_eq!(restored, tx);
        for candidate in [partial.clone(), {
            let mut duplicated = partial;
            duplicated.auths.push(duplicated.auths[0].clone());
            duplicated
        }] {
            store.reset_counts();
            assert!(matches!(
                verify_transaction_auth(&mut store, crypto.clone(), &candidate),
                Err(ExecutionError::InvalidCallData(
                    "required signer authentication missing"
                ))
            ));
            assert_eq!(store.counts.reads.get(), 0);
            assert!(store.snapshot() == witness);
        }
        let mut invalid_extra = tx.clone();
        let mut extra = invalid_extra.auths[0].clone();
        extra.signature[0] ^= 0x80;
        invalid_extra.auths.push(extra);
        store.reset_counts();
        assert!(matches!(
            verify_transaction_auth(&mut store, crypto, &invalid_extra),
            Err(ExecutionError::CryptoError("signature verification failed"))
        ));
        assert_eq!(
            store.counts.reads.get(),
            3,
            "every auth including extra was checked"
        );
        assert!(store.snapshot() == witness);
    }
}

/// Counting providers below establish structural ordering only, not signature validity.
#[test]
fn structural_preflight_refuses_before_store_provider_or_backend_work() {
    let mut store = seeded_counting_store();
    let crypto = Arc::new(CountingCryptoProvider::new());
    let meta = TxAccountMeta {
        account_id: dummy_account_id(0xAA),
        flags: 1,
        access_hint: 0,
        reserved0: [0; 2],
    };
    let auth = TxAuth {
        account_index: 0,
        suite_id: 1,
        reserved: 0,
        signature: vec![0xAA],
    };
    let base = make_transaction(vec![meta.clone()], vec![auth.clone()]);
    let cases = [
        (
            make_transaction(vec![meta.clone(); 65536], vec![]),
            EMPTY_AUTH_ERROR,
        ),
        (
            make_transaction(vec![meta.clone(); 65536], vec![auth.clone()]),
            "transaction account count exceeds wire limit",
        ),
        (
            make_transaction(vec![meta.clone()], vec![auth.clone(); 65536]),
            "transaction authentication count exceeds wire limit",
        ),
        (
            {
                let mut tx = base.clone();
                tx.auths.push(TxAuth {
                    account_index: 1,
                    ..auth.clone()
                });
                tx
            },
            "auth.account_index out of range",
        ),
        (
            {
                let mut tx = base.clone();
                tx.accounts[0].flags = 2;
                tx
            },
            "authentication account is not a required signer",
        ),
        (
            {
                let mut tx = base.clone();
                tx.accounts.push(meta);
                tx
            },
            "required signer authentication missing",
        ),
    ];
    let state = store.snapshot();
    for (tx, expected) in cases {
        let witness = tx.clone();
        assert!(matches!(
            verify_transaction_auth(&mut store, crypto.clone(), &tx),
            Err(ExecutionError::InvalidCallData(message)) if message == expected
        ));
        assert_eq!(tx, witness);
        assert!(store.snapshot() == state);
        assert_eq!(store.counts.reads.get(), 0);
        assert_eq!(store.counts.writes.get(), 0);
        assert_eq!(store.counts.deletes.get(), 0);
        assert_eq!(crypto.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(crypto.verification_calls(), 0);
    }
}

#[test]
fn wire_count_and_index_boundaries_are_structural_controls() {
    let mut store = seeded_counting_store();
    let crypto = Arc::new(CountingCryptoProvider::new());
    let writable = TxAccountMeta {
        account_id: dummy_account_id(0xAA),
        flags: 2,
        access_hint: 0,
        reserved0: [0; 2],
    };
    let mut accounts = vec![writable; usize::from(u16::MAX)];
    accounts[65534].flags = 1;
    let mut tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 65534,
            suite_id: 1,
            reserved: 0,
            signature: vec![0xAA],
        }],
    );
    verify_transaction_auth(&mut store, crypto.clone(), &tx)
        .expect("highest usable index and writable-only accounts pass structure");
    assert_eq!(crypto.verification_calls(), 1);
    tx.auths[0].account_index = u16::MAX;
    store.reset_counts();
    assert!(matches!(
        verify_transaction_auth(&mut store, crypto.clone(), &tx),
        Err(ExecutionError::InvalidCallData(
            "auth.account_index out of range"
        ))
    ));
    assert_eq!(store.counts.reads.get(), 0);
    assert_eq!(crypto.verification_calls(), 1);
    tx.auths[0].account_index = 65534;
    tx.auths = vec![tx.auths[0].clone(); usize::from(u16::MAX)];
    verify_transaction_auth(&mut store, crypto.clone(), &tx)
        .expect("maximum representable auth count passes structure");
    assert_eq!(crypto.verification_calls(), 65536);
    assert_eq!(store.counts.reads.get(), 65535);
}

#[test]
fn verify_transaction_auth_structural_accept_all_provider_control() {
    let keyset_id = dummy_account_id(0xAA);

    // Build a KeysetAccount with one entry (suite_id 1).
    let keyset = make_keyset_account(1, vec![0x01, 0x02, 0x03]);

    let mut data = Vec::new();
    keyset.encode_state(&mut data);

    let mut store = InMemoryAccountStore::new();
    let account = Account::new(keyset_id, dummy_program_id(0x4B), 0, data);
    store.put(account).unwrap();

    // Build a Transaction with one account meta and one auth.
    let accounts = vec![TxAccountMeta {
        account_id: keyset_id,
        flags: 0b0000_0001,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    let tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 0,
            suite_id: 1,
            reserved: 0,
            signature: vec![0xAA, 0xBB],
        }],
    );

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let result = verify_transaction_auth(&mut store, crypto, &tx);
    assert!(result.is_ok());
}

#[test]
fn empty_auth_is_refused_without_store_crypto_or_witness_changes() {
    let keyset_id = dummy_account_id(0xAA);
    let mut store = seeded_counting_store();
    let crypto = Arc::new(CountingCryptoProvider::new());
    let crypto_provider: Arc<dyn CryptoProvider> = crypto.clone();
    let tx = make_transaction(
        vec![TxAccountMeta {
            account_id: keyset_id,
            flags: 3,
            access_hint: 0,
            reserved0: [0; 2],
        }],
        Vec::new(),
    );
    let tx_witness = tx.clone();
    let account_witness = store.snapshot();

    let err = verify_transaction_auth(&mut store, crypto_provider, &tx)
        .expect_err("empty authentication must be refused");
    assert!(matches!(
        err,
        ExecutionError::InvalidCallData(EMPTY_AUTH_ERROR)
    ));
    assert!(tx == tx_witness, "empty-auth transaction witness changed");
    assert!(
        store.snapshot() == account_witness,
        "empty-auth refusal changed complete account state"
    );
    assert_eq!(store.counts.reads.get(), 0, "unexpected account read");
    assert_eq!(store.counts.writes.get(), 0, "unexpected account write");
    assert_eq!(store.counts.deletes.get(), 0, "unexpected account delete");
    assert_eq!(
        crypto.lookups.load(Ordering::SeqCst),
        0,
        "unexpected signature-suite lookup"
    );
    assert_eq!(
        crypto.verification_calls(),
        0,
        "unexpected signature verify"
    );

    store.reset_counts();
    let context_tx_witness = tx.clone();
    let context_account_witness = store.snapshot();
    let mut context = ExecutionContext::new(&mut store, crypto.clone());
    let err = context
        .verify_tx_auth(&tx)
        .expect_err("context wrapper must preserve empty-auth refusal");
    assert!(matches!(
        err,
        ExecutionError::InvalidCallData(EMPTY_AUTH_ERROR)
    ));
    assert!(
        tx == context_tx_witness,
        "context transaction witness changed"
    );
    assert!(
        context.store.snapshot() == context_account_witness,
        "context refusal changed complete account state"
    );
    assert_eq!(
        context.store.counts.reads.get(),
        0,
        "unexpected account read"
    );
    assert_eq!(
        context.store.counts.writes.get(),
        0,
        "unexpected account write"
    );
    assert_eq!(
        context.store.counts.deletes.get(),
        0,
        "unexpected account delete"
    );
    assert_eq!(
        crypto.lookups.load(Ordering::SeqCst),
        0,
        "unexpected signature-suite lookup"
    );
    assert_eq!(
        crypto.verification_calls(),
        0,
        "unexpected signature verify"
    );
}

#[test]
fn genuine_mldsa44_authentication_accepts_and_removal_or_tampering_fails() {
    let (mut store, crypto, tx) = signed_native_fixture();
    verify_transaction_auth(&mut store, crypto.clone(), &tx)
        .expect("genuinely signed native transaction must verify");

    let mut removed = tx.clone();
    removed.auths.clear();
    let err = verify_transaction_auth(&mut store, crypto.clone(), &removed)
        .expect_err("removing all auth entries must fail");
    assert!(matches!(
        err,
        ExecutionError::InvalidCallData(EMPTY_AUTH_ERROR)
    ));

    let mut tampered = tx.clone();
    tampered.auths[0].signature[0] ^= 0x80;
    let err = verify_transaction_auth(&mut store, crypto.clone(), &tampered)
        .expect_err("tampered nonempty signature must fail cryptographically");
    assert!(matches!(
        err,
        ExecutionError::CryptoError("signature verification failed")
    ));

    let mut malformed = tx;
    malformed.auths[0].signature.clear();
    let err = verify_transaction_auth(&mut store, crypto, &malformed)
        .expect_err("malformed nonempty signature must fail cryptographically");
    assert!(matches!(
        err,
        ExecutionError::CryptoError("signature verification failed")
    ));
}

#[test]
fn verify_transaction_auth_fails_on_bad_index() {
    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let tx = make_transaction(
        Vec::new(), // No accounts
        vec![TxAuth {
            account_index: 0, // Invalid, no accounts
            suite_id: 1,
            reserved: 0,
            signature: vec![0xAA],
        }],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::InvalidCallData(msg) => assert!(msg.contains("account_index")),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn verify_transaction_auth_fails_on_missing_keyset() {
    let keyset_id = dummy_account_id(0xAA);
    let mut store = InMemoryAccountStore::new();
    // Do NOT add any account to the store

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![TxAccountMeta {
        account_id: keyset_id,
        flags: 0b0000_0001,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    let tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 0,
            suite_id: 1,
            reserved: 0,
            signature: vec![0xAA],
        }],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::AccountNotFound => {}
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn verify_transaction_auth_fails_on_wrong_suite_id() {
    let keyset_id = dummy_account_id(0xAA);

    // Build a KeysetAccount with suite_id 1
    let keyset = make_keyset_account(1, vec![0x01, 0x02, 0x03]);

    let mut data = Vec::new();
    keyset.encode_state(&mut data);

    let mut store = InMemoryAccountStore::new();
    let account = Account::new(keyset_id, dummy_program_id(0x4B), 0, data);
    store.put(account).unwrap();

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![TxAccountMeta {
        account_id: keyset_id,
        flags: 0b0000_0001,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    // Auth uses suite_id 99 which doesn't match the keyset entry (suite_id 1)
    let tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 0,
            suite_id: 99, // Not in keyset
            reserved: 0,
            signature: vec![0xAA],
        }],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::InvalidCallData(msg) => assert!(msg.contains("suite_id")),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn verify_transaction_auth_fails_on_unknown_suite() {
    let keyset_id = dummy_account_id(0xAA);

    // Build a KeysetAccount with suite_id 99 (which the CryptoProvider doesn't support)
    let keyset = make_keyset_account(99, vec![0x01, 0x02, 0x03]);

    let mut data = Vec::new();
    keyset.encode_state(&mut data);

    let mut store = InMemoryAccountStore::new();
    let account = Account::new(keyset_id, dummy_program_id(0x4B), 0, data);
    store.put(account).unwrap();

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![TxAccountMeta {
        account_id: keyset_id,
        flags: 0b0000_0001,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    let tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 0,
            suite_id: 99, // Keyset has this, but CryptoProvider doesn't
            reserved: 0,
            signature: vec![0xAA],
        }],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::CryptoError(msg) => assert!(msg.contains("suite")),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn verify_transaction_auth_fails_on_invalid_signature() {
    let keyset_id = dummy_account_id(0xAA);

    // Build a KeysetAccount with suite_id 2 (RejectAllSignatureSuite)
    let keyset = make_keyset_account(2, vec![0x01, 0x02, 0x03]);

    let mut data = Vec::new();
    keyset.encode_state(&mut data);

    let mut store = InMemoryAccountStore::new();
    let account = Account::new(keyset_id, dummy_program_id(0x4B), 0, data);
    store.put(account).unwrap();

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![TxAccountMeta {
        account_id: keyset_id,
        flags: 0b0000_0001,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    let tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 0,
            suite_id: 2, // Uses RejectAllSignatureSuite
            reserved: 0,
            signature: vec![0xAA],
        }],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::CryptoError(msg) => assert!(msg.contains("verification")),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn verify_transaction_auth_multiple_auths_structural_provider_control() {
    let keyset_id1 = dummy_account_id(0xAA);
    let keyset_id2 = dummy_account_id(0xBB);

    // Build two KeysetAccounts
    let keyset1 = make_keyset_account(1, vec![0x01, 0x02, 0x03]);
    let keyset2 = make_keyset_account(1, vec![0x04, 0x05, 0x06]);

    let mut data1 = Vec::new();
    keyset1.encode_state(&mut data1);
    let mut data2 = Vec::new();
    keyset2.encode_state(&mut data2);

    let mut store = InMemoryAccountStore::new();
    store
        .put(Account::new(keyset_id1, dummy_program_id(0x4B), 0, data1))
        .unwrap();
    store
        .put(Account::new(keyset_id2, dummy_program_id(0x4B), 0, data2))
        .unwrap();

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![
        TxAccountMeta {
            account_id: keyset_id1,
            flags: 0b0000_0001,
            access_hint: 0,
            reserved0: [0u8; 2],
        },
        TxAccountMeta {
            account_id: keyset_id2,
            flags: 0b0000_0001,
            access_hint: 0,
            reserved0: [0u8; 2],
        },
    ];

    let tx = make_transaction(
        accounts,
        vec![
            TxAuth {
                account_index: 0,
                suite_id: 1,
                reserved: 0,
                signature: vec![0xAA],
            },
            TxAuth {
                account_index: 1,
                suite_id: 1,
                reserved: 0,
                signature: vec![0xBB],
            },
        ],
    );

    let result = verify_transaction_auth(&mut store, crypto, &tx);
    assert!(result.is_ok());
}

#[test]
fn verify_transaction_auth_multiple_auths_reject_control() {
    let keyset_id1 = dummy_account_id(0xAA);
    let keyset_id2 = dummy_account_id(0xBB);

    // keyset1 uses suite_id 1 (AcceptAll), keyset2 uses suite_id 2 (RejectAll)
    let keyset1 = make_keyset_account(1, vec![0x01, 0x02, 0x03]);
    let keyset2 = make_keyset_account(2, vec![0x04, 0x05, 0x06]);

    let mut data1 = Vec::new();
    keyset1.encode_state(&mut data1);
    let mut data2 = Vec::new();
    keyset2.encode_state(&mut data2);

    let mut store = InMemoryAccountStore::new();
    store
        .put(Account::new(keyset_id1, dummy_program_id(0x4B), 0, data1))
        .unwrap();
    store
        .put(Account::new(keyset_id2, dummy_program_id(0x4B), 0, data2))
        .unwrap();

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![
        TxAccountMeta {
            account_id: keyset_id1,
            flags: 0b0000_0001,
            access_hint: 0,
            reserved0: [0u8; 2],
        },
        TxAccountMeta {
            account_id: keyset_id2,
            flags: 0b0000_0001,
            access_hint: 0,
            reserved0: [0u8; 2],
        },
    ];

    let tx = make_transaction(
        accounts,
        vec![
            TxAuth {
                account_index: 0,
                suite_id: 1, // Will succeed
                reserved: 0,
                signature: vec![0xAA],
            },
            TxAuth {
                account_index: 1,
                suite_id: 2, // Will fail
                reserved: 0,
                signature: vec![0xBB],
            },
        ],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::CryptoError(_) => {}
        other => panic!("unexpected error: {:?}", other),
    }
}
