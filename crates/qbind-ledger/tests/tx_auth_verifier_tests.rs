use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use qbind_crypto::{
    ml_dsa_44_sign_digest, AeadSuite, CryptoError, CryptoProvider, KemSuite, MlDsa44SignatureSuite,
    SignatureSuite, StaticCryptoProvider,
};
use qbind_ledger::auth::verify_transaction_auth;
use qbind_ledger::{Account, AccountStore, ExecutionContext, ExecutionError, InMemoryAccountStore};
use qbind_serde::StateEncode;
use qbind_types::{AccountId, Hash32, KeysetAccount, KeysetEntry, ProgramId, KEYSET_PROGRAM_ID};
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
    reported_accounts: HashMap<AccountId, Account>,
    counts: OperationCounts,
    read_ids: RefCell<Vec<AccountId>>,
    returned_data_range: Cell<Option<(usize, usize)>>,
}

impl CountingStore {
    fn seed(&mut self, account: Account) {
        self.accounts.insert(account.id, account);
    }

    fn snapshot(&self) -> HashMap<AccountId, Account> {
        self.accounts.clone()
    }

    fn report_account(&mut self, requested_id: AccountId, account: Account) {
        self.reported_accounts.insert(requested_id, account);
    }

    fn reset_counts(&self) {
        self.counts.reads.set(0);
        self.counts.writes.set(0);
        self.counts.deletes.set(0);
        self.read_ids.borrow_mut().clear();
        self.returned_data_range.set(None);
    }

    fn returned_data_range(&self) -> Option<(usize, usize)> {
        self.returned_data_range.get()
    }
}

impl AccountStore for CountingStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.counts.reads.set(self.counts.reads.get() + 1);
        self.read_ids.borrow_mut().push(*id);
        let account = self
            .reported_accounts
            .get(id)
            .or_else(|| self.accounts.get(id))
            .cloned();
        if let Some(account) = &account {
            self.returned_data_range
                .set(Some((account.data.as_ptr() as usize, account.data.len())));
        }
        account
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

struct RecordingMlDsa44Suite {
    inner: MlDsa44SignatureSuite,
    reported_ids: Vec<u8>,
    id_observations: AtomicUsize,
    digests: Arc<Mutex<Vec<Hash32>>>,
    public_keys: Arc<Mutex<Vec<(usize, Vec<u8>)>>>,
}

impl SignatureSuite for RecordingMlDsa44Suite {
    fn suite_id(&self) -> u8 {
        let index = self.id_observations.fetch_add(1, Ordering::SeqCst);
        self.reported_ids.get(index).copied().unwrap_or(100)
    }

    fn public_key_len(&self) -> usize {
        self.inner.public_key_len()
    }

    fn signature_len(&self) -> usize {
        self.inner.signature_len()
    }

    fn verify(
        &self,
        public_key: &[u8],
        digest: &Hash32,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.digests
            .lock()
            .expect("recorded digest lock")
            .push(*digest);
        self.public_keys
            .lock()
            .expect("recorded public-key lock")
            .push((public_key.as_ptr() as usize, public_key.to_vec()));
        self.inner.verify(public_key, digest, signature)
    }
}

struct RecordingCryptoProvider {
    lookups: AtomicUsize,
    requested_ids: Mutex<Vec<u8>>,
    suite: RecordingMlDsa44Suite,
}

impl RecordingCryptoProvider {
    fn new() -> Self {
        Self::with_reported_ids(Vec::new())
    }

    // Nonmatching reported IDs inject a synthetic provider fault, not a new algorithm.
    fn with_reported_ids(reported_ids: Vec<u8>) -> Self {
        Self {
            lookups: AtomicUsize::new(0),
            requested_ids: Mutex::new(Vec::new()),
            suite: RecordingMlDsa44Suite {
                inner: MlDsa44SignatureSuite::new(100),
                reported_ids,
                id_observations: AtomicUsize::new(0),
                digests: Arc::new(Mutex::new(Vec::new())),
                public_keys: Arc::new(Mutex::new(Vec::new())),
            },
        }
    }

    fn reset(&self) {
        self.lookups.store(0, Ordering::SeqCst);
        self.requested_ids.lock().unwrap().clear();
        self.suite.id_observations.store(0, Ordering::SeqCst);
        self.suite
            .digests
            .lock()
            .expect("recorded digest lock")
            .clear();
        self.suite
            .public_keys
            .lock()
            .expect("recorded public-key lock")
            .clear();
    }

    fn recorded_digests(&self) -> Vec<Hash32> {
        self.suite
            .digests
            .lock()
            .expect("recorded digest lock")
            .clone()
    }

    fn recorded_public_keys(&self) -> Vec<(usize, Vec<u8>)> {
        self.suite
            .public_keys
            .lock()
            .expect("recorded public-key lock")
            .clone()
    }
}

impl CryptoProvider for RecordingCryptoProvider {
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        self.requested_ids.lock().unwrap().push(suite_id);
        (suite_id == 100).then_some(&self.suite)
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
    store.seed(Account::new(keyset_id, KEYSET_PROGRAM_ID, 0, encoded));
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
    let mut account = Account::new(keyset_id, KEYSET_PROGRAM_ID, 0x0102_0304_0506_0708, encoded);
    account.header.rent_epoch = 0x1112_1314_1516_1718;
    account.header.reserved = [0xA5; 8];
    store.seed(account);

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

fn raw_keyset_header(entry_count: u16) -> Vec<u8> {
    let mut bytes = vec![1, 0, 0, 0, 1, 0];
    bytes.extend_from_slice(&entry_count.to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes
}

fn append_raw_keyset_entry(bytes: &mut Vec<u8>, suite_id: u8, pubkey: &[u8]) {
    bytes.push(suite_id);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&(pubkey.len() as u16).to_le_bytes());
    bytes.extend_from_slice(pubkey);
}

fn assert_format_observations(
    store: &CountingStore,
    crypto: &RecordingCryptoProvider,
    tx: &Transaction,
    reads: &[AccountId],
    verifications: usize,
) {
    assert_eq!(store.counts.reads.get(), reads.len());
    assert_eq!(&*store.read_ids.borrow(), reads);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), verifications);
    assert_eq!(
        &*crypto.requested_ids.lock().unwrap(),
        &vec![100; verifications]
    );
    assert_eq!(
        crypto.suite.id_observations.load(Ordering::SeqCst),
        verifications
    );
    assert_eq!(
        crypto.recorded_digests(),
        vec![qbind_hash::tx::tx_digest(tx); verifications]
    );
    assert_eq!(crypto.recorded_public_keys().len(), verifications);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
}

#[test]
fn stored_format_independent_refusals_and_genuine_control_share_response_path() {
    let (mut store, _, tx) = signed_native_fixture();
    let id = tx.accounts[0].account_id;
    let valid = store.accounts[&id].clone();
    let tx_before = tx.clone();
    let backing_before = store.snapshot();
    // AccountHeader metadata is deliberately nonzero and is not keyset data.
    assert_ne!(valid.header.reserved, [0; 8]);
    let mut cases = vec![(0, 0), (0, 2), (0, 255)];
    cases.extend((1..4).map(|offset| (offset, 1)));
    cases.extend((8..12).map(|offset| (offset, 1)));
    cases.push((15, 1));
    for fault in std::iter::once(None).chain(cases.into_iter().map(Some)) {
        let mut response = valid.clone();
        if let Some((offset, value)) = fault {
            response.data[offset] = value;
        }
        store.report_account(id, response);
        let responses_before = store.reported_accounts.clone();
        store.reset_counts();
        let crypto = Arc::new(RecordingCryptoProvider::new());
        let result = verify_transaction_auth(&mut store, crypto.clone(), &tx);
        if let Some((offset, _)) = fault {
            let expected = match offset {
                0 => "unsupported keyset account version",
                15 => "nonzero keyset entry reserved bytes",
                _ => "nonzero keyset account reserved bytes",
            };
            assert!(matches!(result, Err(ExecutionError::InvalidCallData(s)) if s == expected));
        } else {
            result.expect("same get-response path genuinely authenticates admissible format");
        }
        assert_format_observations(&store, &crypto, &tx, &[id], usize::from(fault.is_none()));
        assert_eq!(tx, tx_before);
        assert_eq!(store.snapshot(), backing_before);
        assert_eq!(store.reported_accounts, responses_before);
    }
}

#[test]
fn stored_format_admits_every_entry_before_selecting_genuine_first_key() {
    let (mut store, _, tx) = signed_native_fixture();
    let id = tx.accounts[0].account_id;
    let valid = store.accounts[&id].clone();
    let backing_before = store.snapshot();
    let tx_before = tx.clone();
    for unused_suite in [100, 255] {
        let mut response = valid.clone();
        response.data[6..8].copy_from_slice(&2u16.to_le_bytes());
        let later_offset = response.data.len();
        append_raw_keyset_entry(&mut response.data, unused_suite, &[0xFF]);
        for reserved in [0, 1] {
            response.data[later_offset + 3] = reserved;
            store.report_account(id, response.clone());
            let responses_before = store.reported_accounts.clone();
            store.reset_counts();
            let crypto = Arc::new(RecordingCryptoProvider::new());
            let result = verify_transaction_auth(&mut store, crypto.clone(), &tx);
            if reserved == 0 {
                result.expect("unused unsupported suite/key is not semantic admission");
            } else {
                assert!(matches!(
                    result,
                    Err(ExecutionError::InvalidCallData(
                        "nonzero keyset entry reserved bytes"
                    ))
                ));
            }
            assert_format_observations(&store, &crypto, &tx, &[id], usize::from(reserved == 0));
            assert_eq!(tx, tx_before);
            assert_eq!(store.snapshot(), backing_before);
            assert_eq!(store.reported_accounts, responses_before);
        }
    }
}

#[test]
fn stored_format_combined_fault_precedence_before_selection_provider_and_signature() {
    let (mut store, _, tx) = signed_native_fixture();
    let id = tx.accounts[0].account_id;
    let valid = store.accounts[&id].clone();
    let backing_before = store.snapshot();
    let mut all_faults = valid.data.clone();
    all_faults[0] = 2;
    all_faults[1] = 1;
    all_faults[8] = 1;
    all_faults[15] = 1;
    let mut malformed = all_faults.clone();
    malformed[6..8].copy_from_slice(&2u16.to_le_bytes());
    malformed.push(255); // Matching first entry cannot hide incomplete later framing.
    let mut trailing = all_faults.clone();
    trailing.push(0);
    let mut cases = vec![
        (malformed, true, "decode KeysetAccount"),
        (trailing, true, "trailing bytes in KeysetAccount account"),
        (
            all_faults.clone(),
            false,
            "unsupported keyset account version",
        ),
    ];
    for offset in [1, 8] {
        let mut header_and_entry = valid.data.clone();
        header_and_entry[offset] = 1;
        header_and_entry[15] = 1;
        cases.push((
            header_and_entry,
            false,
            "nonzero keyset account reserved bytes",
        ));
    }
    for offset in [0, 1, 15] {
        let mut missing_match = valid.data.clone();
        missing_match[12] = 255;
        missing_match[offset] = 2;
        let expected = match offset {
            0 => "unsupported keyset account version",
            1 => "nonzero keyset account reserved bytes",
            _ => "nonzero keyset entry reserved bytes",
        };
        cases.push((missing_match, false, expected));
        let mut matching = valid.data.clone();
        matching[offset] = 2;
        cases.push((matching, false, expected));
    }
    let mut invalid_signature = tx.clone();
    invalid_signature.auths[0].signature[0] ^= 0x80;
    for candidate in [&tx, &invalid_signature] {
        let tx_before = candidate.clone();
        for (data, parser_error, expected) in &cases {
            let mut response = valid.clone();
            response.data = data.clone();
            store.report_account(id, response);
            let responses_before = store.reported_accounts.clone();
            store.reset_counts();
            // Deliberately inconsistent provider; must never be consulted.
            let crypto = Arc::new(RecordingCryptoProvider::with_reported_ids(vec![3]));
            let error = verify_transaction_auth(&mut store, crypto.clone(), candidate).unwrap_err();
            match error {
                ExecutionError::SerializationError(s) if *parser_error => assert_eq!(s, *expected),
                ExecutionError::InvalidCallData(s) if !*parser_error => assert_eq!(s, *expected),
                other => panic!("unexpected precedence error: {other:?}"),
            }
            assert_format_observations(&store, &crypto, candidate, &[id], 0);
            assert_eq!(*candidate, tx_before);
            assert_eq!(store.snapshot(), backing_before);
            assert_eq!(store.reported_accounts, responses_before);
        }
    }
}

#[test]
fn genuine_multi_auth_later_format_refusal_and_fresh_corrected_store_retry() {
    for (offset, expected) in [
        (0, "unsupported keyset account version"),
        (8, "nonzero keyset account reserved bytes"),
        (15, "nonzero keyset entry reserved bytes"),
    ] {
        let (mut store, _, tx) = two_signer_fixture(false);
        let ids = [tx.accounts[0].account_id, tx.accounts[1].account_id];
        let original = store.accounts[&ids[1]].data[offset];
        store.accounts.get_mut(&ids[1]).unwrap().data[offset] = 2;
        let rejected_store = store.snapshot();
        let tx_before = tx.clone();
        let responses_before = store.reported_accounts.clone();
        let crypto = Arc::new(RecordingCryptoProvider::new());
        assert!(matches!(
            verify_transaction_auth(&mut store, crypto.clone(), &tx),
            Err(ExecutionError::InvalidCallData(s)) if s == expected
        ));
        assert_format_observations(&store, &crypto, &tx, &ids, 1);
        assert_eq!(store.snapshot(), rejected_store);
        assert_eq!(store.reported_accounts, responses_before);
        assert_eq!(tx, tx_before);

        store.accounts.get_mut(&ids[1]).unwrap().data[offset] = original;
        let corrected_store = store.snapshot();
        store.reset_counts();
        let fresh = Arc::new(RecordingCryptoProvider::new());
        verify_transaction_auth(&mut store, fresh.clone(), &tx).expect("all proofs verify again");
        assert_format_observations(&store, &fresh, &tx, &ids, 2);
        assert_eq!(store.snapshot(), corrected_store);
        assert_eq!(store.reported_accounts, responses_before);
        assert_eq!(tx, tx_before);
    }
}

fn transaction_for_keyset(keyset_id: AccountId, suite_id: u8) -> Transaction {
    make_transaction(
        vec![TxAccountMeta {
            account_id: keyset_id,
            flags: 1,
            access_hint: 0,
            reserved0: [0; 2],
        }],
        vec![TxAuth {
            account_index: 0,
            suite_id,
            reserved: 0,
            signature: vec![0xAA],
        }],
    )
}

#[test]
fn genuine_mldsa44_verification_borrows_selected_key_from_returned_account() {
    let keyset_id = dummy_account_id(0xB4);
    let (public_key, secret_key) =
        qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
    let mut encoded = Vec::new();
    make_keyset_account(100, public_key.clone()).encode_state(&mut encoded);

    let mut store = CountingStore::default();
    let mut account = Account::new(keyset_id, KEYSET_PROGRAM_ID, 19, encoded);
    account.header.rent_epoch = 0x2122_2324_2526_2728;
    account.header.reserved = [0x5A; 8];
    store.seed(account);
    let mut tx = transaction_for_keyset(keyset_id, 100);
    let oracle_digest = qbind_hash::tx::tx_digest(&tx);
    tx.auths[0].signature =
        ml_dsa_44_sign_digest(&secret_key, &oracle_digest).expect("sign genuine transaction");

    let crypto = Arc::new(RecordingCryptoProvider::new());
    let original_tx = tx.clone();
    let original_store = store.snapshot();
    verify_transaction_auth(&mut store, crypto.clone(), &tx)
        .expect("genuine ML-DSA-44 signature must verify");

    let (data_start, data_len) = store
        .returned_data_range()
        .expect("observed returned Account");
    let returned_account = store.accounts.get(&keyset_id).expect("stored account");
    assert_eq!(returned_account.header.lamports, 19);
    assert_eq!(returned_account.header.rent_epoch, 0x2122_2324_2526_2728);
    assert_eq!(returned_account.header.reserved, [0x5A; 8]);
    let (key_start, observed_key) = crypto
        .recorded_public_keys()
        .into_iter()
        .next()
        .expect("actual signature verification observed its key");
    let expected_key_start = data_start
        .checked_add(12 + 6)
        .expect("key offset is within address range");
    assert_eq!(store.counts.reads.get(), 1);
    assert_eq!(data_len, 12 + 6 + public_key.len());
    assert_eq!(key_start, expected_key_start);
    assert_eq!(observed_key.len(), public_key.len());
    assert_eq!(observed_key, public_key);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(crypto.recorded_digests(), vec![oracle_digest]);
    assert_eq!(tx, original_tx);
    assert_eq!(store.snapshot(), original_store);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
}

#[test]
fn returned_account_metadata_refusals_precede_parsing_and_crypto() {
    let (mut store, _, tx) = signed_native_fixture();
    let keyset_id = tx.accounts[0].account_id;
    let valid_account = store.accounts.get(&keyset_id).unwrap().clone();
    let tx_witness = tx.clone();
    let store_witness = store.snapshot();
    let crypto = Arc::new(RecordingCryptoProvider::new());

    // The same controlled get-response route accepts the exact signed keyset
    // bytes when all returned metadata matches the requested account.
    store.report_account(keyset_id, valid_account.clone());
    let valid_responses = store.reported_accounts.clone();
    store.reset_counts();
    crypto.reset();
    verify_transaction_auth(&mut store, crypto.clone(), &tx)
        .expect("matching returned metadata accepts the genuine signed transaction");
    assert_eq!(store.counts.reads.get(), 1);
    assert_eq!(&*store.read_ids.borrow(), &[keyset_id]);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(
        crypto.recorded_digests(),
        vec![qbind_hash::tx::tx_digest(&tx)]
    );
    assert_eq!(crypto.recorded_public_keys().len(), 1);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(tx, tx_witness);
    assert_eq!(store.snapshot(), store_witness);
    assert_eq!(store.reported_accounts, valid_responses);
    assert_eq!(store.reported_accounts[&keyset_id], valid_account);

    // The returned-ID case is a synthetic backend response: the account is
    // stored under the requested key, but get deliberately reports another ID.
    let cases = [
        ("returned id wins", 0u8),
        ("owner wins", 1u8),
        ("executable", 2u8),
    ];
    for (name, fault) in cases {
        let mut response = valid_account.clone();
        match fault {
            0 => response.id = dummy_account_id(0xFE),
            1 => response.header.owner = dummy_program_id(0xFC),
            2 => response.header.is_executable = true,
            _ => unreachable!(),
        }
        assert_eq!(response.data, valid_account.data, "{name}");
        store.report_account(keyset_id, response.clone());
        let responses_before = store.reported_accounts.clone();
        store.reset_counts();
        crypto.reset();

        let error = verify_transaction_auth(&mut store, crypto.clone(), &tx)
            .expect_err("invalid returned metadata must refuse");
        match (fault, error) {
            (0, ExecutionError::InvalidCallData("keyset account id mismatch")) => {}
            (1, ExecutionError::AccountOwnerMismatch) => {}
            (2, ExecutionError::InvalidCallData("keyset account is executable")) => {}
            (_, other) => panic!("{name}: unexpected error {other:?}"),
        }
        assert_eq!(store.counts.reads.get(), 1, "{name}");
        assert_eq!(&*store.read_ids.borrow(), &[keyset_id], "{name}");
        assert_eq!(crypto.lookups.load(Ordering::SeqCst), 0, "{name}");
        assert!(crypto.recorded_digests().is_empty(), "{name}");
        assert!(crypto.recorded_public_keys().is_empty(), "{name}");
        assert_eq!(store.counts.writes.get(), 0, "{name}");
        assert_eq!(store.counts.deletes.get(), 0, "{name}");
        assert_eq!(tx, tx_witness, "{name}");
        assert_eq!(store.snapshot(), store_witness, "{name}");
        assert_eq!(store.reported_accounts, responses_before, "{name}");
        assert_eq!(store.reported_accounts[&keyset_id], response, "{name}");
    }

    // Owner mismatch precedes executable status and malformed account data.
    // Executable status likewise precedes parsing when identity and owner match.
    for (name, fault) in [
        ("owner before executable and parser", 0u8),
        ("executable before parser", 1u8),
    ] {
        let mut response = valid_account.clone();
        match fault {
            0 => {
                response.header.owner = dummy_program_id(0xFD);
                response.header.is_executable = true;
            }
            1 => response.header.is_executable = true,
            _ => unreachable!(),
        }
        response.data = vec![0xFF];
        let supplied_account = response.clone();
        store.report_account(keyset_id, response);
        let responses_before = store.reported_accounts.clone();
        let store_before = store.snapshot();
        store.reset_counts();
        crypto.reset();

        let error = verify_transaction_auth(&mut store, crypto.clone(), &tx)
            .expect_err("metadata refusal must precede malformed-data parsing");
        match (fault, error) {
            (0, ExecutionError::AccountOwnerMismatch) => {}
            (1, ExecutionError::InvalidCallData("keyset account is executable")) => {}
            (_, other) => panic!("{name}: unexpected error {other:?}"),
        }
        assert_eq!(store.counts.reads.get(), 1, "{name}");
        assert_eq!(&*store.read_ids.borrow(), &[keyset_id], "{name}");
        assert_eq!(crypto.lookups.load(Ordering::SeqCst), 0, "{name}");
        assert!(crypto.recorded_digests().is_empty(), "{name}");
        assert!(crypto.recorded_public_keys().is_empty(), "{name}");
        assert_eq!(store.counts.writes.get(), 0, "{name}");
        assert_eq!(store.counts.deletes.get(), 0, "{name}");
        assert_eq!(tx, tx_witness, "{name}");
        assert_eq!(store.snapshot(), store_before, "{name}");
        assert_eq!(store.reported_accounts, responses_before, "{name}");
        assert_eq!(
            store.reported_accounts[&keyset_id], supplied_account,
            "{name}"
        );
    }

    // Combined faults remain a separate control: returned ID is checked
    // before owner and executable, even when data is malformed.
    let mut combined_fault = valid_account.clone();
    combined_fault.id = dummy_account_id(0xFE);
    combined_fault.header.owner = dummy_program_id(0xFD);
    combined_fault.header.is_executable = true;
    combined_fault.data = vec![0xFF];
    store.report_account(keyset_id, combined_fault.clone());
    let responses_before = store.reported_accounts.clone();
    store.reset_counts();
    crypto.reset();
    assert!(matches!(
        verify_transaction_auth(&mut store, crypto.clone(), &tx),
        Err(ExecutionError::InvalidCallData(
            "keyset account id mismatch"
        ))
    ));
    assert_eq!(store.counts.reads.get(), 1);
    assert_eq!(&*store.read_ids.borrow(), &[keyset_id]);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 0);
    assert!(crypto.recorded_digests().is_empty());
    assert!(crypto.recorded_public_keys().is_empty());
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(tx, tx_witness);
    assert_eq!(store.snapshot(), store_witness);
    assert_eq!(store.reported_accounts, responses_before);
    assert_eq!(store.reported_accounts[&keyset_id], combined_fault);

    // A valid-metadata malformed account continues to expose the parser's
    // existing error rather than a metadata refusal.
    let mut malformed = valid_account;
    malformed.data = vec![0xFF];
    store.report_account(keyset_id, malformed.clone());
    store.reset_counts();
    crypto.reset();
    assert!(matches!(
        verify_transaction_auth(&mut store, crypto.clone(), &tx),
        Err(ExecutionError::SerializationError("decode KeysetAccount"))
    ));
    assert_eq!(store.counts.reads.get(), 1);
    assert_eq!(&*store.read_ids.borrow(), &[keyset_id]);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 0);
    assert!(crypto.recorded_digests().is_empty());
    assert_eq!(store.snapshot(), store_witness);
    assert_eq!(tx, tx_witness);
}

#[test]
fn stored_keyset_framing_refusals_precede_provider_and_preserve_state() {
    let truncated_header = vec![0xA5; 11];

    let insufficient_entry = raw_keyset_header(1);

    let mut truncated_body = raw_keyset_header(1);
    truncated_body.push(1);
    truncated_body.extend_from_slice(&1u16.to_le_bytes());
    truncated_body.push(0);
    truncated_body.extend_from_slice(&3u16.to_le_bytes());
    truncated_body.extend_from_slice(&[0x11, 0x22]);

    let mut malformed_unused_entry = raw_keyset_header(2);
    append_raw_keyset_entry(&mut malformed_unused_entry, 1, &[0x51]);
    malformed_unused_entry.push(2);
    malformed_unused_entry.extend_from_slice(&1u16.to_le_bytes());
    malformed_unused_entry.push(0);
    malformed_unused_entry.extend_from_slice(&3u16.to_le_bytes());
    malformed_unused_entry.extend_from_slice(&[0x61, 0x62]);

    let mut trailing = raw_keyset_header(1);
    append_raw_keyset_entry(&mut trailing, 1, &[0x71]);
    trailing.push(0xFF);

    let large_advertised_count = raw_keyset_header(u16::MAX);
    let cases = [
        ("truncated header", truncated_header, false),
        ("insufficient entry data", insufficient_entry, false),
        ("truncated key body", truncated_body, false),
        ("malformed unused entry", malformed_unused_entry, false),
        ("trailing bytes", trailing, true),
        (
            "large advertised count with short buffer",
            large_advertised_count,
            false,
        ),
    ];

    for (name, data, trailing_error) in cases {
        let keyset_id = dummy_account_id(0xD2);
        let mut store = CountingStore::default();
        store.seed(Account::new(keyset_id, KEYSET_PROGRAM_ID, 27, data));
        let tx = transaction_for_keyset(keyset_id, 1);
        let tx_witness = tx.clone();
        let store_witness = store.snapshot();
        let crypto = Arc::new(CountingCryptoProvider::new());

        let error = verify_transaction_auth(&mut store, crypto.clone(), &tx)
            .expect_err(&format!("{name} must be refused"));
        if trailing_error {
            assert!(matches!(
                error,
                ExecutionError::SerializationError("trailing bytes in KeysetAccount account")
            ));
        } else {
            assert!(matches!(
                error,
                ExecutionError::SerializationError("decode KeysetAccount")
            ));
        }
        assert_eq!(tx, tx_witness, "{name} changed transaction");
        assert_eq!(
            store.snapshot(),
            store_witness,
            "{name} changed complete store"
        );
        assert_eq!(store.counts.reads.get(), 1, "{name} get count");
        assert_eq!(store.counts.writes.get(), 0, "{name} write count");
        assert_eq!(store.counts.deletes.get(), 0, "{name} delete count");
        assert_eq!(
            crypto.lookups.load(Ordering::SeqCst),
            0,
            "{name} lookup count"
        );
        assert_eq!(crypto.verification_calls(), 0, "{name} verify count");
    }
}

#[test]
fn zero_entry_missing_account_suite_and_provider_outcomes_are_exact() {
    let keyset_id = dummy_account_id(0xD3);
    let crypto = Arc::new(CountingCryptoProvider::new());
    let cases = [
        (
            Some(raw_keyset_header(0)),
            1,
            "zero-entry",
            1,
            0,
            "no matching key",
        ),
        (
            Some({
                let mut bytes = raw_keyset_header(1);
                append_raw_keyset_entry(&mut bytes, 2, &[0x22]);
                bytes
            }),
            1,
            "missing matching suite",
            1,
            0,
            "no matching key",
        ),
        (None, 1, "missing account", 1, 0, "missing account"),
        (
            Some({
                let mut bytes = raw_keyset_header(1);
                append_raw_keyset_entry(&mut bytes, 99, &[0x99]);
                bytes
            }),
            99,
            "provider unavailable",
            1,
            1,
            "provider unavailable",
        ),
    ];

    for (data, suite_id, name, expected_reads, expected_lookups, expected_error) in cases {
        let mut store = CountingStore::default();
        if let Some(data) = data {
            store.seed(Account::new(keyset_id, KEYSET_PROGRAM_ID, 31, data));
        }
        let tx = transaction_for_keyset(keyset_id, suite_id);
        let tx_witness = tx.clone();
        let store_witness = store.snapshot();
        crypto.lookups.store(0, Ordering::SeqCst);
        let error = verify_transaction_auth(&mut store, crypto.clone(), &tx).unwrap_err();
        match expected_error {
            "no matching key" => assert!(matches!(
                error,
                ExecutionError::InvalidCallData("no key in keyset for given suite_id")
            )),
            "missing account" => assert!(matches!(error, ExecutionError::AccountNotFound)),
            "provider unavailable" => assert!(matches!(
                error,
                ExecutionError::CryptoError("signature suite not found")
            )),
            _ => unreachable!("test expectation is defined above"),
        }
        assert_eq!(tx, tx_witness, "{name} changed transaction");
        assert_eq!(
            store.snapshot(),
            store_witness,
            "{name} changed complete store"
        );
        assert_eq!(store.counts.reads.get(), expected_reads, "{name} get count");
        assert_eq!(store.counts.writes.get(), 0, "{name} write count");
        assert_eq!(store.counts.deletes.get(), 0, "{name} delete count");
        assert_eq!(
            crypto.lookups.load(Ordering::SeqCst),
            expected_lookups,
            "{name} lookup count"
        );
        assert_eq!(crypto.verification_calls(), 0, "{name} verify count");
    }
}

#[test]
fn genuine_same_suite_selection_uses_first_key_without_threshold_or_weight_enforcement() {
    let keyset_id = dummy_account_id(0xD4);
    let (wrong_public_key, _wrong_secret_key) =
        qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair().expect("wrong keypair");
    let (valid_public_key, valid_secret_key) =
        qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair().expect("valid keypair");
    let make_entries = |first: Vec<u8>, second: Vec<u8>| KeysetAccount {
        version: 1,
        reserved0: [0; 3],
        threshold: 0,
        entry_count: 2,
        reserved1: [0; 4],
        entries: vec![
            KeysetEntry {
                suite_id: 100,
                weight: 0,
                reserved0: [0],
                pubkey_len: first.len() as u16,
                pubkey_bytes: first,
            },
            KeysetEntry {
                suite_id: 100,
                weight: u16::MAX,
                reserved0: [0],
                pubkey_len: second.len() as u16,
                pubkey_bytes: second,
            },
        ],
    };

    let mut store = CountingStore::default();
    let mut wrong_first = Vec::new();
    make_entries(wrong_public_key.clone(), valid_public_key.clone()).encode_state(&mut wrong_first);
    store.seed(Account::new(keyset_id, KEYSET_PROGRAM_ID, 41, wrong_first));
    let wrong_first_store_witness = store.snapshot();
    let mut tx = transaction_for_keyset(keyset_id, 100);
    let digest = qbind_hash::tx::tx_digest(&tx);
    tx.auths[0].signature =
        ml_dsa_44_sign_digest(&valid_secret_key, &digest).expect("sign with later matching key");
    let tx_witness = tx.clone();
    let crypto = Arc::new(RecordingCryptoProvider::new());

    assert!(
        matches!(
            verify_transaction_auth(&mut store, crypto.clone(), &tx),
            Err(ExecutionError::CryptoError("signature verification failed"))
        ),
        "signature valid only for a later matching key must fail"
    );
    assert_eq!(store.counts.reads.get(), 1);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(crypto.recorded_digests(), vec![digest]);
    assert_eq!(crypto.recorded_public_keys()[0].1, wrong_public_key);
    assert_eq!(tx, tx_witness);
    assert_eq!(store.snapshot(), wrong_first_store_witness);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);

    let mut valid_first = Vec::new();
    make_entries(valid_public_key.clone(), wrong_public_key.clone()).encode_state(&mut valid_first);
    store.seed(Account::new(keyset_id, KEYSET_PROGRAM_ID, 41, valid_first));
    let valid_first_store_witness = store.snapshot();
    store.reset_counts();
    crypto.reset();
    verify_transaction_auth(&mut store, crypto.clone(), &tx)
        .expect("same signature succeeds when its key is first");
    assert_eq!(store.counts.reads.get(), 1);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(crypto.recorded_digests(), vec![digest]);
    assert_eq!(crypto.recorded_public_keys()[0].1, valid_public_key);
    assert_eq!(tx, tx_witness);
    assert_eq!(store.snapshot(), valid_first_store_witness);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
}

#[test]
fn genuine_mldsa44_streaming_caller_compatibility_and_retry() {
    let first_id = dummy_account_id(0x31);
    let second_id = dummy_account_id(0x72);
    let (first_public_key, first_secret_key) =
        qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair().expect("first ML-DSA-44 keygen");
    let (second_public_key, second_secret_key) =
        qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair()
            .expect("second ML-DSA-44 keygen");
    let mut store = CountingStore::default();
    for (account_id, public_key, lamports) in [
        (first_id, first_public_key, 91),
        (second_id, second_public_key, 207),
    ] {
        let mut encoded = Vec::new();
        make_keyset_account(100, public_key).encode_state(&mut encoded);
        store.seed(Account::new(
            account_id,
            KEYSET_PROGRAM_ID,
            lamports,
            encoded,
        ));
    }

    let mut tx = make_transaction(
        vec![
            TxAccountMeta {
                account_id: first_id,
                flags: 3,
                access_hint: 0x34,
                reserved0: [0x5A, 0xA5],
            },
            TxAccountMeta {
                account_id: second_id,
                flags: 5,
                access_hint: 0xCD,
                reserved0: [0xC3, 0x3C],
            },
        ],
        vec![
            TxAuth {
                account_index: 0,
                suite_id: 100,
                reserved: 0,
                signature: Vec::new(),
            },
            TxAuth {
                account_index: 1,
                suite_id: 100,
                reserved: 0,
                signature: Vec::new(),
            },
        ],
    );
    tx.version = 2;
    tx.chain_id = 0xA1B2_C3D4;
    tx.payer = dummy_account_id(0xE7);
    tx.nonce = 0x0102_0304_0506_0708;
    tx.fee_limit = 987_654_321;
    tx.program_id = dummy_program_id(0x6D);
    tx.call_data = (0..256 * 1024)
        .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
        .collect();

    // The legacy digest is an independent signing oracle, outside verifier counters.
    let oracle_digest = qbind_hash::tx::tx_digest(&tx);
    tx.auths[0].signature =
        ml_dsa_44_sign_digest(&first_secret_key, &oracle_digest).expect("sign first proof");
    tx.auths[1].signature =
        ml_dsa_44_sign_digest(&second_secret_key, &oracle_digest).expect("sign second proof");

    let crypto = Arc::new(RecordingCryptoProvider::new());
    let crypto_provider: Arc<dyn CryptoProvider> = crypto.clone();
    let original_tx = tx.clone();
    let original_store = store.snapshot();

    verify_transaction_auth(&mut store, crypto_provider.clone(), &tx)
        .expect("legacy-oracle signatures must pass the streaming caller");
    assert_eq!(
        tx, original_tx,
        "successful verification changed transaction"
    );
    assert_eq!(
        store.snapshot(),
        original_store,
        "success changed full store"
    );
    assert_eq!(store.counts.reads.get(), 2);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 2);
    assert_eq!(crypto.recorded_digests(), vec![oracle_digest; 2]);

    let mut changed_body = tx.clone();
    changed_body.call_data[131_071] ^= 0x80;
    let changed_oracle_digest = qbind_hash::tx::tx_digest(&changed_body);
    let changed_witness = changed_body.clone();
    store.reset_counts();
    crypto.reset();
    assert!(matches!(
        verify_transaction_auth(&mut store, crypto_provider.clone(), &changed_body),
        Err(ExecutionError::CryptoError("signature verification failed"))
    ));
    assert_eq!(changed_body, changed_witness);
    assert_eq!(
        store.snapshot(),
        original_store,
        "refusal changed full store"
    );
    assert_eq!(store.counts.reads.get(), 1);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(crypto.recorded_digests(), vec![changed_oracle_digest]);

    let mut invalid_later_proof = tx.clone();
    invalid_later_proof.auths[1].signature[0] ^= 0x80;
    let invalid_witness = invalid_later_proof.clone();
    store.reset_counts();
    crypto.reset();
    assert!(matches!(
        verify_transaction_auth(&mut store, crypto_provider.clone(), &invalid_later_proof),
        Err(ExecutionError::CryptoError("signature verification failed"))
    ));
    assert_eq!(invalid_later_proof, invalid_witness);
    assert_eq!(
        store.snapshot(),
        original_store,
        "later refusal changed full store"
    );
    assert_eq!(store.counts.reads.get(), 2);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 2);
    assert_eq!(crypto.recorded_digests(), vec![oracle_digest; 2]);

    changed_body.auths[0].signature =
        ml_dsa_44_sign_digest(&first_secret_key, &changed_oracle_digest)
            .expect("re-sign changed body first proof");
    changed_body.auths[1].signature =
        ml_dsa_44_sign_digest(&second_secret_key, &changed_oracle_digest)
            .expect("re-sign changed body second proof");
    let retry_witness = changed_body.clone();
    store.reset_counts();
    crypto.reset();
    verify_transaction_auth(&mut store, crypto_provider, &changed_body)
        .expect("valid re-signed retry must verify");
    assert_eq!(changed_body, retry_witness);
    assert_eq!(store.snapshot(), original_store, "retry changed full store");
    assert_eq!(store.counts.reads.get(), 2);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 2);
    assert_eq!(crypto.recorded_digests(), vec![changed_oracle_digest; 2]);
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
    store.seed(Account::new(second_id, KEYSET_PROGRAM_ID, 0, encoded));
    let (first_pk, first_sk) =
        qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
    let mut first_data = Vec::new();
    make_keyset_account(100, first_pk).encode_state(&mut first_data);
    store.seed(Account::new(first_id, KEYSET_PROGRAM_ID, 0, first_data));
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
fn returned_suite_id_admission_genuine_positive_mismatch_and_invalid_retry() {
    let (mut store, _, tx) = signed_native_fixture();
    let tx_witness = tx.clone();
    let store_witness = store.snapshot();
    let responses_witness = store.reported_accounts.clone();
    let matched = Arc::new(RecordingCryptoProvider::with_reported_ids(vec![100]));
    verify_transaction_auth(&mut store, matched.clone(), &tx).expect("genuine matched proof");
    assert_eq!(
        matched.recorded_digests(),
        vec![qbind_hash::tx::tx_digest(&tx)]
    );
    assert_eq!(matched.recorded_public_keys().len(), 1);
    assert_eq!(matched.suite.id_observations.load(Ordering::SeqCst), 1);
    assert_eq!(&*matched.requested_ids.lock().unwrap(), &[100]);
    assert_eq!(&*store.read_ids.borrow(), &[tx.accounts[0].account_id]);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(store.snapshot(), store_witness);
    assert_eq!(tx, tx_witness);

    let mut invalid = tx.clone();
    invalid.auths[0].signature[0] ^= 0x80;
    for candidate in [&tx, &invalid] {
        let candidate_witness = candidate.clone();
        store.reset_counts();
        let fault = Arc::new(RecordingCryptoProvider::with_reported_ids(vec![3]));
        assert!(matches!(
            verify_transaction_auth(&mut store, fault.clone(), candidate),
            Err(ExecutionError::CryptoError("signature suite id mismatch"))
        ));
        assert_eq!(store.counts.reads.get(), 1);
        assert_eq!(&*store.read_ids.borrow(), &[tx.accounts[0].account_id]);
        assert_eq!(fault.lookups.load(Ordering::SeqCst), 1);
        assert_eq!(&*fault.requested_ids.lock().unwrap(), &[100]);
        assert_eq!(fault.suite.id_observations.load(Ordering::SeqCst), 1);
        assert!(fault.recorded_digests().is_empty());
        assert!(fault.recorded_public_keys().is_empty());
        assert_eq!(store.counts.writes.get(), 0);
        assert_eq!(store.counts.deletes.get(), 0);
        assert_eq!(*candidate, candidate_witness);
        assert_eq!(store.snapshot(), store_witness);
        assert_eq!(store.reported_accounts, responses_witness);
    }

    store.reset_counts();
    matched.reset();
    let invalid_witness = invalid.clone();
    assert!(matches!(
        verify_transaction_auth(&mut store, matched.clone(), &invalid),
        Err(ExecutionError::CryptoError("signature verification failed"))
    ));
    assert_eq!(matched.recorded_digests().len(), 1);
    assert_eq!(matched.recorded_public_keys().len(), 1);
    assert_eq!(matched.suite.id_observations.load(Ordering::SeqCst), 1);
    assert_eq!(&*matched.requested_ids.lock().unwrap(), &[100]);
    assert_eq!(&*store.read_ids.borrow(), &[tx.accounts[0].account_id]);
    assert_eq!(invalid, invalid_witness);
    assert_eq!(store.snapshot(), store_witness);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);

    store.reset_counts();
    matched.reset();
    verify_transaction_auth(&mut store, matched.clone(), &tx).expect("corrected genuine retry");
    assert_eq!(matched.recorded_digests().len(), 1);
    assert_eq!(matched.recorded_public_keys().len(), 1);
    assert_eq!(matched.suite.id_observations.load(Ordering::SeqCst), 1);
    assert_eq!(&*matched.requested_ids.lock().unwrap(), &[100]);
    assert_eq!(&*store.read_ids.borrow(), &[tx.accounts[0].account_id]);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(store.snapshot(), store_witness);
    assert_eq!(store.reported_accounts, responses_witness);
    assert_eq!(tx, tx_witness);
}

#[test]
fn correctly_registered_mldsa44_alias_remains_compatible() {
    let (mut store, _, mut tx) = signed_native_fixture();
    // TxAuth is outside the signed body; keyset suite ID is outside it as well.
    tx.auths[0].suite_id = 3;
    store
        .accounts
        .get_mut(&tx.accounts[0].account_id)
        .unwrap()
        .data[12] = 3;
    let tx_witness = tx.clone();
    let store_witness = store.snapshot();
    let crypto = Arc::new(
        StaticCryptoProvider::new().with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(3))),
    );
    verify_transaction_auth(&mut store, crypto, &tx).expect("registered genuine ML-DSA-44 alias");
    assert_eq!(&*store.read_ids.borrow(), &[tx.accounts[0].account_id]);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(tx, tx_witness);
    assert_eq!(store.snapshot(), store_witness);
}

#[test]
fn complete_framing_and_missing_entry_precede_synthetic_provider_mismatch() {
    for malformed in [true, false] {
        let (mut store, _, tx) = signed_native_fixture();
        let data = &mut store
            .accounts
            .get_mut(&tx.accounts[0].account_id)
            .unwrap()
            .data;
        if malformed {
            // A valid matching first entry must not hide a malformed trailing entry.
            data[6..8].copy_from_slice(&2u16.to_le_bytes());
            data.push(3);
        } else {
            data[12] = 3;
        }
        let store_witness = store.snapshot();
        let tx_witness = tx.clone();
        let fault = Arc::new(RecordingCryptoProvider::with_reported_ids(vec![3]));
        let error = verify_transaction_auth(&mut store, fault.clone(), &tx).unwrap_err();
        if malformed {
            assert!(matches!(
                error,
                ExecutionError::SerializationError("decode KeysetAccount")
            ));
        } else {
            assert!(matches!(
                error,
                ExecutionError::InvalidCallData("no key in keyset for given suite_id")
            ));
        }
        assert_eq!(&*store.read_ids.borrow(), &[tx.accounts[0].account_id]);
        assert_eq!(store.counts.reads.get(), 1);
        assert_eq!(fault.lookups.load(Ordering::SeqCst), 0);
        assert!(fault.requested_ids.lock().unwrap().is_empty());
        assert_eq!(fault.suite.id_observations.load(Ordering::SeqCst), 0);
        assert!(fault.recorded_digests().is_empty());
        assert!(fault.recorded_public_keys().is_empty());
        assert_eq!(store.counts.writes.get(), 0);
        assert_eq!(store.counts.deletes.get(), 0);
        assert_eq!(store.snapshot(), store_witness);
        assert_eq!(tx, tx_witness);
    }
}

#[test]
fn genuine_multi_auth_later_suite_mismatch_and_fresh_matched_retry() {
    let (mut store, _, tx) = two_signer_fixture(false);
    let tx_witness = tx.clone();
    let store_witness = store.snapshot();
    for (reported_ids, expected_verifications) in [(vec![100, 3], 1), (vec![100, 100], 2)] {
        store.reset_counts();
        let crypto = Arc::new(RecordingCryptoProvider::with_reported_ids(reported_ids));
        let result = verify_transaction_auth(&mut store, crypto.clone(), &tx);
        if expected_verifications == 1 {
            assert!(matches!(
                result,
                Err(ExecutionError::CryptoError("signature suite id mismatch"))
            ));
        } else {
            result.expect("fresh matched retry");
        }
        assert_eq!(
            &*store.read_ids.borrow(),
            &[tx.accounts[0].account_id, tx.accounts[1].account_id]
        );
        assert_eq!(store.counts.reads.get(), 2);
        assert_eq!(crypto.lookups.load(Ordering::SeqCst), 2);
        assert_eq!(&*crypto.requested_ids.lock().unwrap(), &[100, 100]);
        assert_eq!(crypto.suite.id_observations.load(Ordering::SeqCst), 2);
        assert_eq!(
            crypto.recorded_digests(),
            vec![qbind_hash::tx::tx_digest(&tx); expected_verifications]
        );
        assert_eq!(crypto.recorded_public_keys().len(), expected_verifications);
        assert_eq!(store.counts.writes.get(), 0);
        assert_eq!(store.counts.deletes.get(), 0);
        assert_eq!(tx, tx_witness);
        assert_eq!(store.snapshot(), store_witness);
    }
}

#[test]
fn genuine_multi_auth_metadata_refusal_preserves_first_proof_and_retries() {
    let (mut store, _, tx) = two_signer_fixture(false);
    let first_id = dummy_account_id(0xA1);
    let second_id = dummy_account_id(0xA2);
    store.accounts.get_mut(&second_id).unwrap().header.owner = dummy_program_id(0xFC);
    let tx_witness = tx.clone();
    let rejected_store = store.snapshot();
    let crypto = Arc::new(RecordingCryptoProvider::new());

    assert!(matches!(
        verify_transaction_auth(&mut store, crypto.clone(), &tx),
        Err(ExecutionError::AccountOwnerMismatch)
    ));
    assert_eq!(&*store.read_ids.borrow(), &[first_id, second_id]);
    assert_eq!(store.counts.reads.get(), 2);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(
        crypto.recorded_digests(),
        vec![qbind_hash::tx::tx_digest(&tx)]
    );
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(tx, tx_witness);
    assert_eq!(store.snapshot(), rejected_store);

    // Correct only the fixture metadata outside the invocation. Signed bytes
    // remain untouched, and both genuine proofs then verify.
    store.accounts.get_mut(&second_id).unwrap().header.owner = KEYSET_PROGRAM_ID;
    let corrected_store = store.snapshot();
    store.reset_counts();
    crypto.reset();
    verify_transaction_auth(&mut store, crypto.clone(), &tx)
        .expect("corrected fixture metadata permits an unchanged signed retry");
    assert_eq!(&*store.read_ids.borrow(), &[first_id, second_id]);
    assert_eq!(store.counts.reads.get(), 2);
    assert_eq!(crypto.lookups.load(Ordering::SeqCst), 2);
    assert_eq!(
        crypto.recorded_digests(),
        vec![qbind_hash::tx::tx_digest(&tx); 2]
    );
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    assert_eq!(tx, tx_witness);
    assert_eq!(store.snapshot(), corrected_store);
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
    let account = Account::new(keyset_id, KEYSET_PROGRAM_ID, 0, data);
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
    let account = Account::new(keyset_id, KEYSET_PROGRAM_ID, 0, data);
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
    let account = Account::new(keyset_id, KEYSET_PROGRAM_ID, 0, data);
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
    let account = Account::new(keyset_id, KEYSET_PROGRAM_ID, 0, data);
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
        .put(Account::new(keyset_id1, KEYSET_PROGRAM_ID, 0, data1))
        .unwrap();
    store
        .put(Account::new(keyset_id2, KEYSET_PROGRAM_ID, 0, data2))
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
        .put(Account::new(keyset_id1, KEYSET_PROGRAM_ID, 0, data1))
        .unwrap();
    store
        .put(Account::new(keyset_id2, KEYSET_PROGRAM_ID, 0, data2))
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
