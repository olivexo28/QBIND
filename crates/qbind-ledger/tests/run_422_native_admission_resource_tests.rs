use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use qbind_crypto::error::CryptoError;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
use qbind_crypto::{
    ml_dsa_44_sign_digest, AeadSuite, CryptoProvider, KemSuite, MlDsa44SignatureSuite,
    StaticCryptoProvider,
};
use qbind_hash::tx::try_tx_digest_streaming;
use qbind_ledger::auth::verify_transaction_auth;
use qbind_ledger::keyset_account::KeysetAccountReadError;
use qbind_ledger::keyset_create::{
    prepare_keyset_account_bounded, KeysetCreatePreparationError, KeysetCreatePreparationLimits,
};
use qbind_ledger::native_tx_proof::{
    evaluate_native_transaction_proofs, NativeTransactionProofError, NativeTransactionProofLimits,
    NativeTransactionProofStructureError, NativeTransactionProofSummary,
};
use qbind_ledger::{Account, AccountStore, ExecutionError, InMemoryAccountStore};
use qbind_serde::keyset::StoredKeysetLimits;
use qbind_serde::keyset::StoredKeysetParseError;
use qbind_serde::StateEncode;
use qbind_types::{AccountId, Hash32, KeysetAccount, KeysetEntry, KEYSET_PROGRAM_ID};
use qbind_wire::io::WireEncode;
use qbind_wire::keyset::{CreateKeysetCall, CreateKeysetLimits, WireKeyEntry};
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};

const SUITE_ID: u8 = 100;
const GROUPS: usize = 8;
const PROOFS: usize = 8;
const ENTRIES: usize = 16;
const REPETITIONS: usize = 3;
const SIGNATURE_LIMIT: usize = 8_192;
const AGGREGATE_SIGNATURE_LIMIT: usize = 65_536;
const IDENTIFIER_LIMIT: usize = 128;
const DATA_LIMIT: usize = 65_536;
const KEY_LIMIT: usize = 4_096;
const AGGREGATE_KEY_LIMIT: usize = 65_536;

type Keypair = (Vec<u8>, Vec<u8>);

#[derive(Default)]
struct CryptoCounts {
    lookups: AtomicUsize,
    descriptors: AtomicUsize,
    verifications: AtomicUsize,
}

impl CryptoCounts {
    fn reset(&self) {
        self.lookups.store(0, Ordering::SeqCst);
        self.descriptors.store(0, Ordering::SeqCst);
        self.verifications.store(0, Ordering::SeqCst);
    }

    fn assert_work(&self, descriptors: usize, verifications: usize) {
        assert_eq!(self.lookups.load(Ordering::SeqCst), descriptors);
        assert_eq!(self.descriptors.load(Ordering::SeqCst), descriptors);
        assert_eq!(self.verifications.load(Ordering::SeqCst), verifications);
    }
}

struct CountedMlDsa44 {
    inner: MlDsa44SignatureSuite,
    counts: Arc<CryptoCounts>,
}

impl SignatureSuite for CountedMlDsa44 {
    fn suite_id(&self) -> u8 {
        self.inner.suite_id()
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
        self.counts.verifications.fetch_add(1, Ordering::SeqCst);
        self.inner.verify(public_key, digest, signature)
    }

    fn canonical_key_descriptor<'a>(
        &self,
        public_key: &'a [u8],
    ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
        self.counts.descriptors.fetch_add(1, Ordering::SeqCst);
        self.inner.canonical_key_descriptor(public_key)
    }
}

struct CountedProvider {
    inner: StaticCryptoProvider,
    counts: Arc<CryptoCounts>,
}

impl CountedProvider {
    fn new() -> Self {
        let counts = Arc::new(CryptoCounts::default());
        let suite = CountedMlDsa44 {
            inner: MlDsa44SignatureSuite::new(SUITE_ID),
            counts: Arc::clone(&counts),
        };
        Self {
            inner: StaticCryptoProvider::new().with_signature_suite(Arc::new(suite)),
            counts,
        }
    }
}

impl CryptoProvider for CountedProvider {
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
        self.counts.lookups.fetch_add(1, Ordering::SeqCst);
        self.inner.signature_suite(suite_id)
    }

    fn kem_suite(&self, suite_id: u8) -> Option<&dyn KemSuite> {
        self.inner.kem_suite(suite_id)
    }

    fn aead_suite(&self, suite_id: u8) -> Option<&dyn AeadSuite> {
        self.inner.aead_suite(suite_id)
    }
}

#[derive(Default)]
struct StoreCounts {
    bounded_reads: Cell<usize>,
    max_returned_data_capacity: Cell<usize>,
    legacy_reads: Cell<usize>,
    writes: Cell<usize>,
    deletes: Cell<usize>,
}

struct CountedStore {
    inner: InMemoryAccountStore,
    counts: StoreCounts,
}

impl CountedStore {
    fn new() -> Self {
        Self {
            inner: InMemoryAccountStore::new(),
            counts: StoreCounts::default(),
        }
    }

    // Fixture setup deliberately bypasses the measured AccountStore surface.
    fn seed_fixture(&mut self, account: Account) {
        self.inner.put(account).expect("fixture insertion");
    }

    fn reset_counts(&self) {
        self.counts.bounded_reads.set(0);
        self.counts.max_returned_data_capacity.set(0);
        self.counts.legacy_reads.set(0);
        self.counts.writes.set(0);
        self.counts.deletes.set(0);
    }

    fn assert_accesses(&self, bounded_reads: usize) {
        assert_eq!(self.counts.bounded_reads.get(), bounded_reads);
        assert_eq!(self.counts.legacy_reads.get(), 0);
        assert_eq!(self.counts.writes.get(), 0);
        assert_eq!(self.counts.deletes.get(), 0);
    }
}

impl AccountStore for CountedStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.counts
            .legacy_reads
            .set(self.counts.legacy_reads.get() + 1);
        self.inner.get(id)
    }

    fn get_bounded(
        &self,
        id: &AccountId,
        max_data_bytes: usize,
    ) -> Result<Option<Account>, qbind_ledger::store::BoundedReadError> {
        self.counts
            .bounded_reads
            .set(self.counts.bounded_reads.get() + 1);
        let account = self.inner.get_bounded(id, max_data_bytes)?;
        if let Some(account) = &account {
            self.counts.max_returned_data_capacity.set(
                self.counts
                    .max_returned_data_capacity
                    .get()
                    .max(account.data.capacity()),
            );
        }
        Ok(account)
    }

    fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
        self.counts.writes.set(self.counts.writes.get() + 1);
        self.inner.put(account)
    }

    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
        self.counts.deletes.set(self.counts.deletes.get() + 1);
        self.inner.delete(id)
    }
}

struct ReportedAccountStore {
    account: Account,
    legacy_reads: Cell<usize>,
    requested_ids: RefCell<Vec<AccountId>>,
    bounded_reads: Cell<usize>,
    writes: Cell<usize>,
    deletes: Cell<usize>,
}

impl ReportedAccountStore {
    fn new(account: Account) -> Self {
        Self {
            account,
            legacy_reads: Cell::new(0),
            requested_ids: RefCell::new(Vec::new()),
            bounded_reads: Cell::new(0),
            writes: Cell::new(0),
            deletes: Cell::new(0),
        }
    }

    fn reset_reads(&self) {
        self.legacy_reads.set(0);
        self.requested_ids.borrow_mut().clear();
        self.bounded_reads.set(0);
    }
}

impl AccountStore for ReportedAccountStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.legacy_reads.set(self.legacy_reads.get() + 1);
        self.requested_ids.borrow_mut().push(*id);
        Some(self.account.clone())
    }

    fn get_bounded(
        &self,
        _id: &AccountId,
        max_data_bytes: usize,
    ) -> Result<Option<Account>, qbind_ledger::store::BoundedReadError> {
        self.bounded_reads.set(self.bounded_reads.get() + 1);
        if self.account.data.len() > max_data_bytes {
            return Err(qbind_ledger::store::BoundedReadError::Oversized);
        }
        Ok(Some(self.account.clone()))
    }

    fn put(&mut self, _account: Account) -> Result<(), ExecutionError> {
        self.writes.set(self.writes.get() + 1);
        Err(ExecutionError::InvalidCallData("unexpected fixture write"))
    }

    fn delete(&mut self, _id: &AccountId) -> Result<(), ExecutionError> {
        self.deletes.set(self.deletes.get() + 1);
        Err(ExecutionError::InvalidCallData("unexpected fixture delete"))
    }
}

struct LegacyOnlyStore {
    inner: InMemoryAccountStore,
    legacy_reads: Cell<usize>,
}

impl LegacyOnlyStore {
    fn new(account: Account) -> Self {
        let mut inner = InMemoryAccountStore::new();
        inner.put(account).expect("fixture insertion");
        Self {
            inner,
            legacy_reads: Cell::new(0),
        }
    }
}

impl AccountStore for LegacyOnlyStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.legacy_reads.set(self.legacy_reads.get() + 1);
        self.inner.get(id)
    }

    fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
        self.inner.put(account)
    }

    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
        self.inner.delete(id)
    }
}

fn native_limits() -> NativeTransactionProofLimits {
    NativeTransactionProofLimits {
        max_required_signer_indices: 8,
        max_keyset_account_count: 8,
        max_authentication_proof_count: 8,
        max_signature_bytes: SIGNATURE_LIMIT,
        max_aggregate_signature_bytes: AGGREGATE_SIGNATURE_LIMIT,
        stored_keyset: StoredKeysetLimits {
            max_encoded_bytes: DATA_LIMIT,
            max_entries: ENTRIES,
            max_key_bytes: KEY_LIMIT,
            max_total_key_bytes: AGGREGATE_KEY_LIMIT,
        },
        max_algorithm_parameter_identifier_bytes: IDENTIFIER_LIMIT,
    }
}

fn create_limits() -> KeysetCreatePreparationLimits {
    KeysetCreatePreparationLimits {
        create_keyset: CreateKeysetLimits {
            max_encoded_bytes: DATA_LIMIT,
            max_entries: ENTRIES,
            max_key_bytes: KEY_LIMIT,
            max_total_key_bytes: AGGREGATE_KEY_LIMIT,
        },
        max_stored_data_bytes: DATA_LIMIT,
        max_distinct_key_proofs: 8,
        max_algorithm_parameter_identifier_bytes: IDENTIFIER_LIMIT,
    }
}

fn generate_keypairs(count: usize) -> Vec<Keypair> {
    (0..count)
        .map(|_| MlDsa44Backend::generate_keypair().expect("genuine ML-DSA-44 keygen"))
        .collect()
}

fn stored_account(id: AccountId, keys: &[Keypair], threshold: u16) -> Account {
    let entries = keys
        .iter()
        .map(|(public_key, _)| KeysetEntry {
            suite_id: SUITE_ID,
            weight: 1,
            reserved0: [0],
            pubkey_len: u16::try_from(public_key.len()).expect("key length fits wire field"),
            pubkey_bytes: public_key.clone(),
        })
        .collect::<Vec<_>>();
    stored_account_with_entries(id, entries, threshold)
}

fn stored_account_with_entries(
    id: AccountId,
    entries: Vec<KeysetEntry>,
    threshold: u16,
) -> Account {
    let state = KeysetAccount {
        version: 1,
        reserved0: [0; 3],
        threshold,
        entry_count: u16::try_from(entries.len()).expect("entry count fits wire field"),
        reserved1: [0; 4],
        entries,
    };
    let mut data = Vec::new();
    state.encode_state(&mut data);
    Account::new(id, KEYSET_PROGRAM_ID, 0, data)
}

fn synthetic_stored_account(id: AccountId, entry_count: usize) -> Account {
    let entries = (0..entry_count)
        .map(|index| KeysetEntry {
            suite_id: SUITE_ID,
            weight: 1,
            reserved0: [0],
            pubkey_len: 1,
            pubkey_bytes: vec![u8::try_from(index).expect("small synthetic index")],
        })
        .collect::<Vec<_>>();
    let state = KeysetAccount {
        version: 1,
        reserved0: [0; 3],
        threshold: 1,
        entry_count: u16::try_from(entry_count).expect("entry count fits wire field"),
        reserved1: [0; 4],
        entries,
    };
    let mut data = Vec::new();
    state.encode_state(&mut data);
    Account::new(id, KEYSET_PROGRAM_ID, 0, data)
}

fn signed_transaction(
    account_ids: &[AccountId],
    signers: &[(u16, &[u8])],
    call_data: Vec<u8>,
) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: [0xA1; 32],
        nonce: 7,
        fee_limit: 10_000,
        accounts: account_ids
            .iter()
            .copied()
            .map(|account_id| TxAccountMeta {
                account_id,
                flags: 1,
                access_hint: 0,
                reserved0: [0; 2],
            })
            .collect(),
        program_id: [0x91; 32],
        call_data,
        auths: signers
            .iter()
            .map(|(account_index, _)| TxAuth {
                account_index: *account_index,
                suite_id: SUITE_ID,
                reserved: 0,
                signature: Vec::new(),
            })
            .collect(),
    };
    let digest = try_tx_digest_streaming(&tx).expect("checked fixture digest");
    for (auth, (_, secret_key)) in tx.auths.iter_mut().zip(signers) {
        auth.signature =
            ml_dsa_44_sign_digest(secret_key, &digest).expect("genuine ML-DSA-44 sign");
    }
    tx
}

fn timed_repetitions<B, F>(
    label: &str,
    expected_repetitions: usize,
    mut before_sample: B,
    mut run: F,
) -> Vec<Duration>
where
    B: FnMut(usize),
    F: FnMut(usize),
{
    assert_eq!(expected_repetitions, REPETITIONS);
    let mut elapsed = Vec::with_capacity(REPETITIONS);
    for sample in 0..REPETITIONS {
        before_sample(sample);
        let start = Instant::now();
        run(sample);
        elapsed.push(start.elapsed());
    }
    println!(
        "RUN422 timing profile={} workload={} repetitions={} first={:?} subsequent={:?}",
        if cfg!(debug_assertions) {
            "ordinary"
        } else {
            "optimized"
        },
        label,
        REPETITIONS,
        elapsed[0],
        &elapsed[1..]
    );
    elapsed
}

fn assert_summary(
    actual: NativeTransactionProofSummary,
    required: usize,
    groups: usize,
    proofs: usize,
) {
    assert_eq!(
        actual,
        NativeTransactionProofSummary {
            required_signer_index_count: required,
            distinct_keyset_account_count: groups,
            evaluated_authentication_proof_count: proofs,
        }
    );
}

#[test]
fn run422_native_resource_eight_groups_full_descriptor_and_signature_scan() {
    let group_keys = (0..GROUPS)
        .map(|_| generate_keypairs(ENTRIES))
        .collect::<Vec<_>>();
    let ids = (0..GROUPS)
        .map(|group| [u8::try_from(group + 1).unwrap(); 32])
        .collect::<Vec<_>>();
    let mut store = CountedStore::new();
    let expected_accounts = group_keys
        .iter()
        .zip(&ids)
        .map(|(keys, id)| {
            let account = stored_account(*id, keys, 1);
            store.seed_fixture(account.clone());
            account
        })
        .collect::<Vec<_>>();
    let signers = group_keys
        .iter()
        .enumerate()
        .map(|(index, keys)| (u16::try_from(index).unwrap(), keys[0].1.as_slice()))
        .collect::<Vec<_>>();
    let tx = signed_transaction(&ids, &signers, Vec::new());
    let tx_before = tx.clone();
    let provider = CountedProvider::new();
    let limits = native_limits();

    timed_repetitions(
        "eight-groups-16-keys-8-proofs",
        REPETITIONS,
        |_| {
            store.reset_counts();
            provider.counts.reset();
        },
        |_| {
            let result = evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
                &tx, &store, &provider, limits,
            )
            .expect("all eight genuine groups verify");
            assert_summary(result, 8, 8, 8);
            store.assert_accesses(8);
            provider.counts.assert_work(128, 128);
        },
    );

    assert_eq!(tx, tx_before);
    for expected in &expected_accounts {
        assert_eq!(store.inner.get(&expected.id), Some(expected.clone()));
    }
    println!(
        "RUN422 workload=A provider-descriptors=128 signature-attempts=128 bounded-reads=8 legacy-reads=0 writes=0 deletes=0 public-key-bytes={} signature-bytes={}",
        group_keys[0][0].0.len(),
        tx.auths[0].signature.len()
    );
    println!(
        "RUN422 public-object-bytes transaction={} account={} auth={} account-meta={} limits={} summary={} error={}",
        core::mem::size_of::<Transaction>(),
        core::mem::size_of::<Account>(),
        core::mem::size_of::<TxAuth>(),
        core::mem::size_of::<TxAccountMeta>(),
        core::mem::size_of::<NativeTransactionProofLimits>(),
        core::mem::size_of::<NativeTransactionProofSummary>(),
        core::mem::size_of::<NativeTransactionProofError>()
    );
    println!(
        "RUN422 workload=A max-observed-returned-data-capacity={} logical-limit={}",
        store.counts.max_returned_data_capacity.get(),
        DATA_LIMIT
    );
}

#[test]
fn run422_native_resource_all_proofs_run_after_threshold_and_late_invalid_refuses() {
    let id = [0xB2; 32];
    let keys = generate_keypairs(ENTRIES);
    let account = stored_account(id, &keys, 1);
    let mut store = CountedStore::new();
    store.seed_fixture(account.clone());
    let ids = vec![id; PROOFS];
    let signers = (0..PROOFS)
        .map(|index| (u16::try_from(index).unwrap(), keys[index].1.as_slice()))
        .collect::<Vec<_>>();
    let tx = signed_transaction(&ids, &signers, Vec::new());
    let tx_before = tx.clone();
    let provider = CountedProvider::new();
    let limits = native_limits();

    timed_repetitions(
        "one-group-16-keys-8-proofs-threshold-1",
        REPETITIONS,
        |_| {
            store.reset_counts();
            provider.counts.reset();
        },
        |_| {
            let result = evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
                &tx, &store, &provider, limits,
            )
            .expect("all eight genuine proofs are checked");
            assert_summary(result, 8, 1, 8);
            store.assert_accesses(1);
            provider.counts.assert_work(16, 128);
        },
    );

    let mut late_invalid = tx.clone();
    *late_invalid.auths[7]
        .signature
        .first_mut()
        .expect("ML-DSA signature is non-empty") ^= 1;
    let late_invalid_before = late_invalid.clone();
    store.reset_counts();
    provider.counts.reset();
    assert_eq!(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &late_invalid,
            &store,
            &provider,
            native_limits(),
        ),
        Err(NativeTransactionProofError::KeysetProof(
            qbind_ledger::keyset_proof::KeysetProofEvaluationError::InvalidProof
        ))
    );
    store.assert_accesses(1);
    provider.counts.assert_work(16, 128);
    assert_eq!(late_invalid, late_invalid_before);
    assert_eq!(tx, tx_before);
    assert_eq!(store.inner.get(&id), Some(account));
    println!(
        "RUN422 workload=B descriptors=16 signature-attempts=128 supplied-proofs=8 late-invalid-signature-attempts=128 threshold=1"
    );
}

#[test]
fn run422_native_resource_global_proof_and_entry_boundaries_refuse_then_retry() {
    let id = [0xC3; 32];
    let keys = generate_keypairs(ENTRIES);
    let account = stored_account(id, &keys, 1);
    let mut store = CountedStore::new();
    store.seed_fixture(account.clone());
    let provider = CountedProvider::new();

    let over_budget = Transaction {
        version: 1,
        chain_id: 1,
        payer: [0xA1; 32],
        nonce: 7,
        fee_limit: 10_000,
        accounts: vec![TxAccountMeta {
            account_id: id,
            flags: 1,
            access_hint: 0,
            reserved0: [0; 2],
        }],
        program_id: [0x91; 32],
        call_data: Vec::new(),
        auths: (0..9)
            .map(|_| TxAuth {
                account_index: 0,
                suite_id: SUITE_ID,
                reserved: 0,
                signature: Vec::new(),
            })
            .collect(),
    };
    let over_budget_before = over_budget.clone();
    store.reset_counts();
    provider.counts.reset();
    assert_eq!(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &over_budget,
            &store,
            &provider,
            native_limits(),
        ),
        Err(NativeTransactionProofError::Structure(
            NativeTransactionProofStructureError::AuthenticationProofCountLimit
        ))
    );
    store.assert_accesses(0);
    provider.counts.assert_work(0, 0);
    assert_eq!(over_budget, over_budget_before);

    let retry = signed_transaction(&[id], &[(0, keys[0].1.as_slice())], Vec::new());
    let retry_before = retry.clone();
    store.reset_counts();
    provider.counts.reset();
    assert_summary(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &retry,
            &store,
            &provider,
            native_limits(),
        )
        .expect("valid input retries after proof-budget refusal"),
        1,
        1,
        1,
    );
    store.assert_accesses(1);
    provider.counts.assert_work(16, 16);
    assert_eq!(retry, retry_before);

    // This synthetic structural control exercises E=16 directly. Its short
    // keys are intentionally not genuine ML-DSA material and never reach crypto.
    let synthetic = synthetic_stored_account(id, ENTRIES + 1);
    store.seed_fixture(synthetic.clone());
    let structural_tx = Transaction {
        auths: vec![TxAuth {
            account_index: 0,
            suite_id: SUITE_ID,
            reserved: 0,
            signature: Vec::new(),
        }],
        ..retry.clone()
    };
    let structural_tx_before = structural_tx.clone();
    store.reset_counts();
    provider.counts.reset();
    assert_eq!(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &structural_tx,
            &store,
            &provider,
            native_limits(),
        ),
        Err(NativeTransactionProofError::KeysetParse(
            StoredKeysetParseError::EntryCountLimit
        ))
    );
    store.assert_accesses(1);
    provider.counts.assert_work(0, 0);
    assert_eq!(structural_tx, structural_tx_before);

    store.seed_fixture(account.clone());
    store.reset_counts();
    provider.counts.reset();
    assert_summary(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &retry,
            &store,
            &provider,
            native_limits(),
        )
        .expect("valid 16-entry ML-DSA keyset retries after E=16 refusal"),
        1,
        1,
        1,
    );
    store.assert_accesses(1);
    provider.counts.assert_work(16, 16);
    assert_eq!(retry, retry_before);
    assert_eq!(store.inner.get(&id), Some(account));

    // Both over-budget and structural input storage remain caller-owned.
    assert_eq!(over_budget, over_budget_before);
    println!(
        "RUN422 workload=C proof-boundary=9/8 reads=0 descriptors=0 verifies=0 retry=success; synthetic-entry-limit=17/16 exact-error=EntryCountLimit reads=1 descriptors=0 verifies=0 retry=success"
    );
}

fn create_call_data(target_id: AccountId, keys: &[Keypair], threshold: u16) -> Vec<u8> {
    let call = CreateKeysetCall {
        version: 1,
        target_id,
        threshold,
        entries: keys
            .iter()
            .map(|(public_key, _)| WireKeyEntry {
                suite_id: SUITE_ID,
                weight: 1,
                pubkey_bytes: public_key.clone(),
            })
            .collect(),
    };
    let mut encoded = Vec::new();
    call.encode(&mut encoded);
    encoded
}

#[test]
fn run422_native_resource_genuine_create_preparation_and_composed_evaluation() {
    let id = [0xD4; 32];
    let keys = generate_keypairs(ENTRIES);
    let call_data = create_call_data(id, &keys, 8);
    let call_data_before = call_data.clone();
    let provider = CountedProvider::new();
    let limits = create_limits();
    let expected = stored_account(id, &keys, 8);
    let expected_requested_bytes = expected.data.len();
    let actual_key_bytes = keys[0].0.len();
    let create_input_bytes = call_data.len();
    let observed_output_len = Cell::new(0);
    let observed_output_capacity = Cell::new(0);

    timed_repetitions(
        "create-preparation-16-genuine-keys-threshold-8",
        REPETITIONS,
        |_| provider.counts.reset(),
        |_| {
            let prepared = prepare_keyset_account_bounded::<ENTRIES>(&call_data, &provider, limits)
                .expect("16 genuine keys and threshold 8 fit the create budget");
            assert_eq!(prepared, expected);
            assert_eq!(prepared.data.len(), expected_requested_bytes);
            provider.counts.assert_work(16, 0);
            observed_output_len.set(prepared.data.len());
            observed_output_capacity.set(prepared.data.capacity());
        },
    );
    println!(
        "RUN422 create-output logical_len={} source_derived_expected_reservation_request={} observed_capacity={}",
        observed_output_len.get(),
        expected_requested_bytes,
        observed_output_capacity.get()
    );

    let unreachable = create_call_data(id, &keys, 9);
    let unreachable_before = unreachable.clone();
    provider.counts.reset();
    assert_eq!(
        prepare_keyset_account_bounded::<ENTRIES>(&unreachable, &provider, limits),
        Err(KeysetCreatePreparationError::Semantics(
            qbind_ledger::keyset_validation::KeysetSemanticAnalysisError::ThresholdUnreachable
        ))
    );
    provider.counts.assert_work(16, 0);
    assert_eq!(unreachable, unreachable_before);

    provider.counts.reset();
    let prepared = prepare_keyset_account_bounded::<ENTRIES>(&call_data, &provider, limits)
        .expect("actual prepared account for fixture-only handoff");
    assert_eq!(prepared, expected);
    provider.counts.assert_work(16, 0);
    let mut store = CountedStore::new();
    // This is fixture-only insertion. Preparation itself never writes a store.
    store.seed_fixture(prepared);
    let ids = vec![id; 8];
    let signers = (0..8)
        .map(|index| (u16::try_from(index).unwrap(), keys[index].1.as_slice()))
        .collect::<Vec<_>>();
    let tx = signed_transaction(&ids, &signers, Vec::new());
    let tx_before = tx.clone();
    let proof_limits = native_limits();

    timed_repetitions(
        "prepared-account-8-proof-composition",
        REPETITIONS,
        |_| {
            store.reset_counts();
            provider.counts.reset();
        },
        |_| {
            assert_summary(
                evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
                    &tx,
                    &store,
                    &provider,
                    proof_limits,
                )
                .expect("prepared 16-entry account verifies eight distinct genuine proofs"),
                8,
                1,
                8,
            );
            store.assert_accesses(1);
            provider.counts.assert_work(16, 128);
        },
    );
    assert_eq!(call_data, call_data_before);
    assert_eq!(unreachable, unreachable_before);
    assert_eq!(tx, tx_before);
    assert_eq!(store.inner.get(&id), Some(expected));
    println!(
        "RUN422 workload=D prepared-entry-count=16 threshold=8 max-distinct-proofs=8 input-bytes={} input-limit=65536-assessment-choice output-bytes={} output-limit=65536 public-key-bytes={} signature-bytes={} composed-summary=(8,1,8)",
        create_input_bytes,
        expected_requested_bytes,
        actual_key_bytes,
        tx.auths[0].signature.len()
    );
}

fn compatibility_account(id: AccountId, keys: &[Keypair], threshold: u16) -> Account {
    stored_account(id, keys, threshold)
}

#[test]
fn run422_native_compatibility_witnesses_legacy_and_isolated_semantics() {
    let id = [0xE5; 32];
    let keys = generate_keypairs(2);
    let account = compatibility_account(id, &keys, 1);
    let mut store = CountedStore::new();
    store.seed_fixture(account.clone());
    let ids = [id];
    let signers = [(0, keys[1].1.as_slice())];
    let tx = signed_transaction(&ids, &signers, Vec::new());
    let tx_before = tx.clone();
    let provider = Arc::new(CountedProvider::new());

    // Legacy chooses only the first matching suite entry and therefore rejects
    // a signature for the second valid same-suite key. The isolated path scans
    // both candidates and accepts the actual matching key.
    store.reset_counts();
    assert!(matches!(
        verify_transaction_auth(&mut store, provider.clone(), &tx),
        Err(ExecutionError::CryptoError("signature verification failed"))
    ));
    assert_eq!(store.counts.legacy_reads.get(), 1);
    assert_eq!(store.counts.bounded_reads.get(), 0);
    store.reset_counts();
    provider.counts.reset();
    assert_summary(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &tx,
            &store,
            provider.as_ref(),
            native_limits(),
        )
        .expect("isolated complete candidate scan finds second key"),
        1,
        1,
        1,
    );
    store.assert_accesses(1);
    provider.counts.assert_work(2, 2);

    // Historical legacy success is now an individual-weight refusal; the
    // isolated path still refuses unreachable aggregate threshold semantics.
    let one_key = generate_keypairs(1);
    let unreachable_account = compatibility_account(id, &one_key, 2);
    store.seed_fixture(unreachable_account.clone());
    let unreachable_tx = signed_transaction(&[id], &[(0, one_key[0].1.as_slice())], Vec::new());
    let unreachable_tx_before = unreachable_tx.clone();
    store.reset_counts();
    provider.counts.reset();
    assert!(matches!(
        verify_transaction_auth(&mut store, provider.clone(), &unreachable_tx),
        Err(ExecutionError::InvalidCallData(
            "selected key weight below keyset threshold"
        ))
    ));
    assert_eq!(store.counts.legacy_reads.get(), 1);
    assert_eq!(store.counts.bounded_reads.get(), 0);
    assert_eq!(store.counts.writes.get(), 0);
    assert_eq!(store.counts.deletes.get(), 0);
    provider.counts.assert_work(0, 0);
    assert_eq!(unreachable_tx, unreachable_tx_before);
    assert_eq!(store.inner.get(&id), Some(unreachable_account.clone()));
    store.reset_counts();
    provider.counts.reset();
    assert_eq!(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &unreachable_tx,
            &store,
            provider.as_ref(),
            native_limits(),
        ),
        Err(NativeTransactionProofError::KeysetProof(
            qbind_ledger::keyset_proof::KeysetProofEvaluationError::ThresholdUnreachable
        ))
    );
    store.assert_accesses(1);
    provider.counts.assert_work(1, 0);
    assert_eq!(tx, tx_before);
    assert_eq!(unreachable_tx, unreachable_tx_before);
    assert_eq!(store.inner.get(&id), Some(unreachable_account));

    let duplicate = KeysetEntry {
        suite_id: SUITE_ID,
        weight: 1,
        reserved0: [0],
        pubkey_len: u16::try_from(one_key[0].0.len()).unwrap(),
        pubkey_bytes: one_key[0].0.clone(),
    };
    let conflicting_duplicate = stored_account_with_entries(
        id,
        vec![
            duplicate.clone(),
            KeysetEntry {
                weight: 2,
                ..duplicate.clone()
            },
        ],
        1,
    );
    store.seed_fixture(conflicting_duplicate);
    let duplicate_tx = signed_transaction(&[id], &[(0, one_key[0].1.as_slice())], Vec::new());
    let duplicate_tx_before = duplicate_tx.clone();
    store.reset_counts();
    verify_transaction_auth(&mut store, provider.clone(), &duplicate_tx)
        .expect("legacy checks the first matching duplicate only");
    assert_eq!(store.counts.legacy_reads.get(), 1);
    store.reset_counts();
    provider.counts.reset();
    assert_eq!(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &duplicate_tx,
            &store,
            provider.as_ref(),
            native_limits(),
        ),
        Err(NativeTransactionProofError::KeysetProof(
            qbind_ledger::keyset_proof::KeysetProofEvaluationError::ConflictingDuplicateWeights
        ))
    );
    store.assert_accesses(1);
    provider.counts.assert_work(2, 0);
    assert_eq!(duplicate_tx, duplicate_tx_before);

    let unsupported_unused = stored_account_with_entries(
        id,
        vec![
            duplicate,
            KeysetEntry {
                suite_id: SUITE_ID + 1,
                weight: 1,
                reserved0: [0],
                pubkey_len: u16::try_from(one_key[0].0.len()).unwrap(),
                pubkey_bytes: one_key[0].0.clone(),
            },
        ],
        1,
    );
    store.seed_fixture(unsupported_unused.clone());
    let unused_tx = signed_transaction(&[id], &[(0, one_key[0].1.as_slice())], Vec::new());
    let unused_tx_before = unused_tx.clone();
    store.reset_counts();
    verify_transaction_auth(&mut store, provider.clone(), &unused_tx)
        .expect("legacy ignores a well-framed unused suite entry");
    assert_eq!(store.counts.legacy_reads.get(), 1);
    store.reset_counts();
    provider.counts.reset();
    assert_eq!(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &unused_tx,
            &store,
            provider.as_ref(),
            native_limits(),
        ),
        Err(NativeTransactionProofError::KeysetProof(
            qbind_ledger::keyset_proof::KeysetProofEvaluationError::SuiteNotFound
        ))
    );
    store.assert_accesses(1);
    assert_eq!(store.inner.get(&id), Some(unsupported_unused));
    assert_eq!(provider.counts.lookups.load(Ordering::SeqCst), 2);
    assert_eq!(provider.counts.descriptors.load(Ordering::SeqCst), 1);
    assert_eq!(provider.counts.verifications.load(Ordering::SeqCst), 0);
    assert_eq!(unused_tx, unused_tx_before);
}

#[test]
fn run422_native_compatibility_witnesses_metadata_bounded_read_and_proof_limit() {
    let id = [0xE6; 32];
    let keys = generate_keypairs(1);
    let tx = signed_transaction(&[id], &[(0, keys[0].1.as_slice())], Vec::new());
    let tx_before = tx.clone();
    let provider = Arc::new(CountedProvider::new());

    for (name, mutate, expected) in [
        (
            "owner",
            0u8,
            NativeTransactionProofError::AccountRead(KeysetAccountReadError::OwnerMismatch),
        ),
        (
            "executable",
            1u8,
            NativeTransactionProofError::AccountRead(KeysetAccountReadError::Executable),
        ),
        (
            "returned-id",
            2u8,
            NativeTransactionProofError::AccountRead(KeysetAccountReadError::AccountIdMismatch),
        ),
    ] {
        let mut account = stored_account(id, &keys, 1);
        match mutate {
            0 => account.header.owner = [0xE7; 32],
            1 => account.header.is_executable = true,
            2 => account.id = [0xE8; 32],
            _ => unreachable!(),
        }
        let account_before = account.clone();
        let mut store = ReportedAccountStore::new(account);

        provider.counts.reset();
        let native_error = verify_transaction_auth(&mut store, provider.clone(), &tx)
            .expect_err("native verifier refuses invalid returned-account metadata");
        match mutate {
            0 => assert!(matches!(native_error, ExecutionError::AccountOwnerMismatch)),
            1 => assert!(matches!(
                native_error,
                ExecutionError::InvalidCallData("keyset account is executable")
            )),
            2 => assert!(matches!(
                native_error,
                ExecutionError::InvalidCallData("keyset account id mismatch")
            )),
            _ => unreachable!(),
        }
        assert_eq!(store.legacy_reads.get(), 1, "{name}");
        assert_eq!(&*store.requested_ids.borrow(), &[id], "{name}");
        assert_eq!(store.bounded_reads.get(), 0, "{name}");
        provider.counts.assert_work(0, 0);
        assert_eq!(store.writes.get(), 0, "{name}");
        assert_eq!(store.deletes.get(), 0, "{name}");
        assert_eq!(tx, tx_before, "{name}");
        assert_eq!(store.account, account_before, "{name}");

        store.reset_reads();
        provider.counts.reset();
        assert_eq!(
            evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
                &tx,
                &store,
                provider.as_ref(),
                native_limits(),
            ),
            Err(expected),
            "{name}"
        );
        assert_eq!(store.bounded_reads.get(), 1, "{name}");
        assert_eq!(store.legacy_reads.get(), 0, "{name}");
        assert_eq!(store.writes.get(), 0, "{name}");
        assert_eq!(store.deletes.get(), 0, "{name}");
        provider.counts.assert_work(0, 0);
        assert_eq!(store.account, account_before, "{name}");
    }

    let legacy_account = stored_account(id, &keys, 1);
    let mut legacy_only = LegacyOnlyStore::new(legacy_account.clone());
    provider.counts.reset();
    verify_transaction_auth(&mut legacy_only, provider.clone(), &tx)
        .expect("legacy verifier works with a get-only store");
    assert_eq!(legacy_only.legacy_reads.get(), 1);
    assert_eq!(provider.counts.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(provider.counts.descriptors.load(Ordering::SeqCst), 0);
    assert_eq!(provider.counts.verifications.load(Ordering::SeqCst), 1);
    legacy_only.legacy_reads.set(0);
    provider.counts.reset();
    assert_eq!(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &tx,
            &legacy_only,
            provider.as_ref(),
            native_limits(),
        ),
        Err(NativeTransactionProofError::AccountRead(
            KeysetAccountReadError::Unsupported
        ))
    );
    assert_eq!(legacy_only.legacy_reads.get(), 0, "no fallback to get");
    provider.counts.assert_work(0, 0);
    assert_eq!(legacy_only.inner.get(&id), Some(legacy_account));

    let nine_signers = (0..9)
        .map(|_| (0, keys[0].1.as_slice()))
        .collect::<Vec<_>>();
    let nine_proofs = signed_transaction(&[id], &nine_signers, Vec::new());
    let nine_proofs_before = nine_proofs.clone();
    let mut store = CountedStore::new();
    let stored = stored_account(id, &keys, 1);
    store.seed_fixture(stored.clone());
    provider.counts.reset();
    verify_transaction_auth(&mut store, provider.clone(), &nine_proofs)
        .expect("legacy accepts nine genuine proofs covering the same signer index");
    assert_eq!(store.counts.legacy_reads.get(), 9);
    assert_eq!(store.counts.bounded_reads.get(), 0);
    assert_eq!(provider.counts.lookups.load(Ordering::SeqCst), 9);
    assert_eq!(provider.counts.descriptors.load(Ordering::SeqCst), 0);
    assert_eq!(provider.counts.verifications.load(Ordering::SeqCst), 9);

    store.reset_counts();
    provider.counts.reset();
    assert_eq!(
        evaluate_native_transaction_proofs::<GROUPS, PROOFS, ENTRIES>(
            &nine_proofs,
            &store,
            provider.as_ref(),
            native_limits(),
        ),
        Err(NativeTransactionProofError::Structure(
            NativeTransactionProofStructureError::AuthenticationProofCountLimit
        ))
    );
    store.assert_accesses(0);
    provider.counts.assert_work(0, 0);
    assert_eq!(nine_proofs, nine_proofs_before);
    assert_eq!(tx, tx_before);
    assert_eq!(store.inner.get(&id), Some(stored));
    println!(
        "RUN422 compatibility metadata=native-refuses owner-executable-returned-id/isolated-typed-refusals; bounded-read=legacy-accepts/new-unsupported; proof-count=legacy-accepts-9/new-refuses-9-before-work"
    );
}
