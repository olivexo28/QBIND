use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use qbind_crypto::error::CryptoError;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
use qbind_crypto::{
    ml_dsa_44_sign_digest, AeadSuite, CryptoProvider, KemSuite, MlDsa44SignatureSuite,
    StaticCryptoProvider,
};
use qbind_hash::tx::try_tx_digest_streaming;
use qbind_ledger::keyset_proof::KeysetProofEvaluationError;
use qbind_ledger::native_tx_proof::{
    evaluate_native_transaction_proofs, NativeTransactionProofError, NativeTransactionProofLimits,
    NativeTransactionProofSummary,
};
use qbind_ledger::store::BoundedReadError;
use qbind_ledger::{Account, AccountStore, ExecutionError, InMemoryAccountStore};
use qbind_serde::keyset::StoredKeysetLimits;
use qbind_serde::StateEncode;
use qbind_types::{AccountId, Hash32, KeysetAccount, KeysetEntry, KEYSET_PROGRAM_ID};
use qbind_wire::io::WireEncode;
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};

const A: AccountId = [0xA0; 32];
const B: AccountId = [0xB0; 32];
const SUITE: u8 = 100;
type Keypair = (Vec<u8>, Vec<u8>);

// Identical to the completed assessment's UNAPPROVED candidate configuration.
fn candidate_limits() -> NativeTransactionProofLimits {
    NativeTransactionProofLimits {
        max_required_signer_indices: 8,
        max_keyset_account_count: 8,
        max_authentication_proof_count: 8,
        max_signature_bytes: 8_192,
        max_aggregate_signature_bytes: 65_536,
        stored_keyset: StoredKeysetLimits {
            max_encoded_bytes: 65_536,
            max_entries: 16,
            max_key_bytes: 4_096,
            max_total_key_bytes: 65_536,
        },
        max_algorithm_parameter_identifier_bytes: 128,
    }
}

#[derive(Default)]
struct CryptoCounts {
    lookups: AtomicUsize,
    descriptors: AtomicUsize,
    verifications: AtomicUsize,
}

struct CountedSuite {
    inner: MlDsa44SignatureSuite,
    counts: Arc<CryptoCounts>,
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
        public_key: &'a [u8],
    ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
        self.counts.descriptors.fetch_add(1, Ordering::SeqCst);
        self.inner.canonical_key_descriptor(public_key)
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
}

struct CountedProvider {
    inner: StaticCryptoProvider,
    counts: Arc<CryptoCounts>,
}

impl CountedProvider {
    fn new() -> Self {
        let counts = Arc::new(CryptoCounts::default());
        Self {
            inner: StaticCryptoProvider::new().with_signature_suite(Arc::new(CountedSuite {
                inner: MlDsa44SignatureSuite::new(SUITE),
                counts: Arc::clone(&counts),
            })),
            counts,
        }
    }

    fn assert_work(&self, count: usize) {
        assert_eq!(self.counts.lookups.load(Ordering::SeqCst), count);
        assert_eq!(self.counts.descriptors.load(Ordering::SeqCst), count);
        assert_eq!(self.counts.verifications.load(Ordering::SeqCst), count);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Generation {
    S0,
    S1,
}

struct Fixture {
    keys: [Keypair; 4],
    stores: [InMemoryAccountStore; 2],
    expected: [[Account; 2]; 2],
}

fn keyset(id: AccountId, public_key: &[u8]) -> Account {
    assert_eq!(public_key.len(), 1_312);
    let state = KeysetAccount {
        version: 1,
        reserved0: [0; 3],
        threshold: 1,
        entry_count: 1,
        reserved1: [0; 4],
        entries: vec![KeysetEntry {
            suite_id: SUITE,
            weight: 1,
            reserved0: [0],
            pubkey_len: u16::try_from(public_key.len()).expect("genuine key fits wire"),
            pubkey_bytes: public_key.to_vec(),
        }],
    };
    let mut data = Vec::new();
    state.encode_state(&mut data);
    Account::new(id, KEYSET_PROGRAM_ID, 0, data)
}

impl Fixture {
    fn new() -> Self {
        let keys = std::array::from_fn(|_| {
            MlDsa44Backend::generate_keypair().expect("genuine ML-DSA-44 keygen")
        });
        for i in 0..keys.len() {
            for j in 0..i {
                assert_ne!(keys[i].0, keys[j].0);
                assert_ne!(keys[i].1, keys[j].1);
            }
        }
        // Only these two complete generations are published, never A0+B1.
        let expected = [
            [keyset(A, &keys[0].0), keyset(B, &keys[1].0)],
            [keyset(A, &keys[2].0), keyset(B, &keys[3].0)],
        ];
        let stores = std::array::from_fn(|generation| {
            let mut store = InMemoryAccountStore::new();
            for account in &expected[generation] {
                store.put(account.clone()).expect("fixture insertion");
            }
            store
        });
        Self {
            keys,
            stores,
            expected,
        }
    }

    fn store(&self, generation: Generation) -> &InMemoryAccountStore {
        &self.stores[match generation {
            Generation::S0 => 0,
            Generation::S1 => 1,
        }]
    }

    fn assert_preserved(&self) {
        for (store, accounts) in self.stores.iter().zip(&self.expected) {
            for account in accounts {
                assert_eq!(store.get(&account.id), Some(account.clone()));
            }
        }
    }

    fn transaction(&self, a_key: usize, b_key: usize) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            chain_id: 1,
            payer: [0xC0; 32],
            nonce: 7,
            fee_limit: 10_000,
            accounts: [A, B]
                .into_iter()
                .map(|account_id| TxAccountMeta {
                    account_id,
                    flags: 1,
                    access_hint: 0,
                    reserved0: [0; 2],
                })
                .collect(),
            program_id: [0x91; 32],
            call_data: vec![1, 2, 3],
            auths: Vec::new(),
        };
        let digest = try_tx_digest_streaming(&tx).expect("checked fixture digest");
        for (index, key_index) in [a_key, b_key].into_iter().enumerate() {
            let signature = ml_dsa_44_sign_digest(&self.keys[key_index].1, &digest)
                .expect("genuine ML-DSA-44 signing");
            assert_eq!(signature.len(), 2_420);
            tx.auths.push(TxAuth {
                account_index: u16::try_from(index).expect("two fixture indices"),
                suite_id: SUITE,
                reserved: 0,
                signature,
            });
        }
        tx
    }
}

struct ReadBoundaryStore<'a> {
    fixture: &'a Fixture,
    current: Cell<Generation>,
    switch_after_first_read: bool,
    history: RefCell<Vec<(AccountId, Generation, usize)>>,
    transitions: Cell<usize>,
    legacy_reads: Cell<usize>,
    writes: Cell<usize>,
    deletes: Cell<usize>,
}

impl<'a> ReadBoundaryStore<'a> {
    fn new(fixture: &'a Fixture, initial: Generation, switch_after_first_read: bool) -> Self {
        Self {
            fixture,
            current: Cell::new(initial),
            switch_after_first_read,
            history: RefCell::new(Vec::new()),
            transitions: Cell::new(0),
            legacy_reads: Cell::new(0),
            writes: Cell::new(0),
            deletes: Cell::new(0),
        }
    }

    fn assert_accesses(&self, expected: &[(AccountId, Generation)], transitions: usize) {
        let expected = expected
            .iter()
            .map(|&(id, generation)| (id, generation, 65_536))
            .collect::<Vec<_>>();
        assert_eq!(*self.history.borrow(), expected);
        assert_eq!(self.transitions.get(), transitions);
        assert_eq!(self.legacy_reads.get(), 0);
        assert_eq!(self.writes.get(), 0);
        assert_eq!(self.deletes.get(), 0);
    }
}

impl AccountStore for ReadBoundaryStore<'_> {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.legacy_reads.set(self.legacy_reads.get() + 1);
        self.fixture.store(self.current.get()).get(id)
    }

    fn get_bounded(
        &self,
        id: &AccountId,
        max_data_bytes: usize,
    ) -> Result<Option<Account>, BoundedReadError> {
        let generation = self.current.get();
        let result = self
            .fixture
            .store(generation)
            .get_bounded(id, max_data_bytes);
        if let Ok(Some(account)) = &result {
            let index = match generation {
                Generation::S0 => 0,
                Generation::S1 => 1,
            };
            let expected = self.fixture.expected[index]
                .iter()
                .find(|account| account.id == *id)
                .expect("requested fixture account");
            assert_eq!(account, expected);
            assert!(account.data.len() <= max_data_bytes);
        }
        self.history
            .borrow_mut()
            .push((*id, generation, max_data_bytes));
        // Explicit boundary AFTER the complete first materialization.
        if self.switch_after_first_read && self.history.borrow().len() == 1 {
            assert_eq!(generation, Generation::S0);
            self.current.set(Generation::S1);
            self.transitions.set(self.transitions.get() + 1);
        }
        result
    }

    fn put(&mut self, _account: Account) -> Result<(), ExecutionError> {
        self.writes.set(self.writes.get() + 1);
        Err(ExecutionError::InvalidCallData(
            "unexpected evaluator write",
        ))
    }

    fn delete(&mut self, _id: &AccountId) -> Result<(), ExecutionError> {
        self.deletes.set(self.deletes.get() + 1);
        Err(ExecutionError::InvalidCallData(
            "unexpected evaluator delete",
        ))
    }
}

fn evaluate(
    tx: &Transaction,
    store: &ReadBoundaryStore<'_>,
    expected: Result<NativeTransactionProofSummary, NativeTransactionProofError>,
    work: usize,
) {
    let before = tx.clone();
    let mut before_bytes = Vec::new();
    tx.encode(&mut before_bytes);
    let provider = CountedProvider::new();
    assert_eq!(
        evaluate_native_transaction_proofs::<8, 8, 16>(tx, store, &provider, candidate_limits()),
        expected
    );
    provider.assert_work(work);
    let mut after_bytes = Vec::new();
    tx.encode(&mut after_bytes);
    assert_eq!(after_bytes, before_bytes);
    assert_eq!(tx, &before);
    store.fixture.assert_preserved();
}

fn success() -> Result<NativeTransactionProofSummary, NativeTransactionProofError> {
    Ok(NativeTransactionProofSummary {
        required_signer_index_count: 2,
        distinct_keyset_account_count: 2,
        evaluated_authentication_proof_count: 2,
    })
}

#[test]
fn mixed_proofs_refuse_fixed_generations_but_pass_coherent_switching_reads() {
    let fixture = Fixture::new();
    let mixed = fixture.transaction(0, 3);
    let refusal = Err(NativeTransactionProofError::KeysetProof(
        KeysetProofEvaluationError::InvalidProof,
    ));
    let s0 = ReadBoundaryStore::new(&fixture, Generation::S0, false);
    evaluate(&mixed, &s0, refusal.clone(), 2);
    s0.assert_accesses(&[(A, Generation::S0), (B, Generation::S0)], 0);
    let s1 = ReadBoundaryStore::new(&fixture, Generation::S1, false);
    evaluate(&mixed, &s1, refusal, 1);
    s1.assert_accesses(&[(A, Generation::S1)], 0);
    let switching = ReadBoundaryStore::new(&fixture, Generation::S0, true);
    evaluate(&mixed, &switching, success(), 2);
    switching.assert_accesses(&[(A, Generation::S0), (B, Generation::S1)], 1);
    assert_eq!(switching.current.get(), Generation::S1);
}

#[test]
fn matched_genuine_proofs_pass_separate_fixed_generation_controls() {
    let fixture = Fixture::new();
    for (generation, keys) in [(Generation::S0, (0, 1)), (Generation::S1, (2, 3))] {
        let matched = fixture.transaction(keys.0, keys.1);
        let fixed = ReadBoundaryStore::new(&fixture, generation, false);
        evaluate(&matched, &fixed, success(), 2);
        fixed.assert_accesses(&[(A, generation), (B, generation)], 0);
    }
}
