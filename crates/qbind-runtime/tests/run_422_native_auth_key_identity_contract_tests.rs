//! Characterization only: current native authentication and isolated key identity semantics.
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use qbind_crypto::error::CryptoError;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
use qbind_crypto::{
    ml_dsa_44_sign_digest, CryptoProvider, MlDsa44SignatureSuite, StaticCryptoProvider,
};
use qbind_hash::tx::tx_digest;
use qbind_ledger::keyset_proof::{
    evaluate_stored_keyset_proofs, KeysetProofEvaluationError, KeysetProofEvaluationLimits,
    KeysetSignatureProof,
};
use qbind_ledger::keyset_validation::{
    analyze_stored_keyset_semantics, KeysetSemanticAnalysisError,
};
use qbind_ledger::{Account, AccountHeader, AccountStore, ExecutionError};
use qbind_runtime::TxExecutor;
use qbind_serde::keyset::{parse_stored_keyset, StoredKeysetLimits, StoredKeysetView};
use qbind_system::keyset_program::KEYSET_PROGRAM_ID;
use qbind_types::{AccountId, Hash32, KEYSET_PROGRAM_ID as SHARED_KEYSET_PROGRAM_ID};
use qbind_wire::io::WireEncode;
use qbind_wire::keyset::{CreateKeysetCall, WireKeyEntry};
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};

const SUITE_A: u8 = 100;
const SUITE_B: u8 = 101;
const SIGNER: AccountId = [0x41; 32];
const TARGET: AccountId = [0x42; 32];
const PAYER: AccountId = [0x43; 32];
const WORKSPACE_ENTRIES: usize = 8;
const TEST_MAX_PROOFS: usize = 4;
const TEST_MAX_SIGNATURE_BYTES: usize = 4096;
const TEST_MAX_AGGREGATE_SIGNATURE_BYTES: usize = 8192;
const TEST_MAX_IDENTIFIER_BYTES: usize = 32;

#[derive(Default)]
struct Store {
    accounts: HashMap<AccountId, Account>,
    reads: RefCell<Vec<AccountId>>,
    responses: RefCell<Vec<(AccountId, Option<Account>)>>,
    puts: Vec<AccountId>,
    deletes: Vec<AccountId>,
}

impl Store {
    fn seed(&mut self, account: Account) {
        self.accounts.insert(account.id, account);
    }

    fn snapshot(&self) -> HashMap<AccountId, Account> {
        self.accounts.clone()
    }

    fn reset(&mut self) {
        self.reads.borrow_mut().clear();
        self.responses.borrow_mut().clear();
        self.puts.clear();
        self.deletes.clear();
    }
}

impl AccountStore for Store {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.reads.borrow_mut().push(*id);
        let response = self.accounts.get(id).cloned();
        self.responses.borrow_mut().push((*id, response.clone()));
        response
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct Attempt {
    suite_id: u8,
    key: Vec<u8>,
    digest: Hash32,
    signature: Vec<u8>,
}

#[derive(Default)]
struct Work {
    lookups: Mutex<Vec<u8>>,
    suite_ids: Mutex<Vec<u8>>,
    descriptors: Mutex<Vec<(u8, Vec<u8>)>>,
    attempts: Mutex<Vec<Attempt>>,
}

impl Work {
    fn reset(&self) {
        self.lookups.lock().unwrap().clear();
        self.suite_ids.lock().unwrap().clear();
        self.descriptors.lock().unwrap().clear();
        self.attempts.lock().unwrap().clear();
    }
}

struct CountedSuite {
    inner: MlDsa44SignatureSuite,
    work: Arc<Work>,
}

impl SignatureSuite for CountedSuite {
    fn suite_id(&self) -> u8 {
        let id = self.inner.suite_id();
        self.work.suite_ids.lock().unwrap().push(id);
        id
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
        self.work
            .descriptors
            .lock()
            .unwrap()
            .push((self.inner.suite_id(), key.to_vec()));
        self.inner.canonical_key_descriptor(key)
    }

    fn verify(&self, key: &[u8], digest: &Hash32, signature: &[u8]) -> Result<(), CryptoError> {
        self.work.attempts.lock().unwrap().push(Attempt {
            suite_id: self.inner.suite_id(),
            key: key.to_vec(),
            digest: *digest,
            signature: signature.to_vec(),
        });
        self.inner.verify(key, digest, signature)
    }
}

struct CountedProvider {
    inner: StaticCryptoProvider,
    work: Arc<Work>,
}

impl CryptoProvider for CountedProvider {
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
        self.work.lookups.lock().unwrap().push(suite_id);
        self.inner.signature_suite(suite_id)
    }

    fn kem_suite(&self, _suite_id: u8) -> Option<&dyn qbind_crypto::KemSuite> {
        None
    }

    fn aead_suite(&self, _suite_id: u8) -> Option<&dyn qbind_crypto::AeadSuite> {
        None
    }
}

struct Key {
    public: Vec<u8>,
    secret: Vec<u8>,
}

impl Key {
    fn genuine() -> Self {
        let (public, secret) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keypair");
        Self { public, secret }
    }

    fn entry(&self, suite_id: u8, weight: u16) -> WireKeyEntry {
        WireKeyEntry {
            suite_id,
            weight,
            pubkey_bytes: self.public.clone(),
        }
    }
}

struct Fixture {
    store: Store,
    key: Key,
    work: Arc<Work>,
    provider: Arc<dyn CryptoProvider>,
    executor: TxExecutor<Store>,
}

impl Fixture {
    fn new() -> Self {
        assert_eq!(KEYSET_PROGRAM_ID, SHARED_KEYSET_PROGRAM_ID);
        let key = Key::genuine();
        let work = Arc::new(Work::default());
        let inner = StaticCryptoProvider::new()
            .with_signature_suite(Arc::new(CountedSuite {
                inner: MlDsa44SignatureSuite::new(SUITE_A),
                work: Arc::clone(&work),
            }))
            .with_signature_suite(Arc::new(CountedSuite {
                inner: MlDsa44SignatureSuite::new(SUITE_B),
                work: Arc::clone(&work),
            }));
        let provider: Arc<dyn CryptoProvider> = Arc::new(CountedProvider {
            inner,
            work: Arc::clone(&work),
        });
        Self {
            store: Store::default(),
            key,
            work,
            provider,
            executor: TxExecutor::new(),
        }
    }

    fn seed_entries(&mut self, threshold: u16, entries: &[WireKeyEntry]) {
        self.store.seed(keyset_account(SIGNER, threshold, entries));
    }

    fn transaction(&self, aliases: &[u8]) -> Transaction {
        let call = CreateKeysetCall {
            version: 1,
            target_id: TARGET,
            threshold: 1,
            entries: vec![self.key.entry(SUITE_A, 1)],
        };
        let mut call_data = Vec::new();
        call.encode(&mut call_data);
        let mut tx = Transaction {
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
                    account_id: TARGET,
                    flags: 2,
                    access_hint: 3,
                    reserved0: [0; 2],
                },
            ],
            program_id: KEYSET_PROGRAM_ID,
            call_data,
            auths: Vec::new(),
        };
        let digest = tx_digest(&tx);
        tx.auths = aliases
            .iter()
            .map(|suite_id| TxAuth {
                account_index: 0,
                suite_id: *suite_id,
                reserved: 0,
                signature: ml_dsa_44_sign_digest(&self.key.secret, &digest)
                    .expect("genuine transaction signature"),
            })
            .collect();
        tx
    }

    fn execute(&mut self, tx: &Transaction) -> Result<(), ExecutionError> {
        self.store.reset();
        self.work.reset();
        self.executor
            .execute_transaction(&mut self.store, Arc::clone(&self.provider), tx)
    }
}

fn keyset_account(id: AccountId, threshold: u16, entries: &[WireKeyEntry]) -> Account {
    let mut data = vec![1, 0, 0, 0];
    data.extend_from_slice(&threshold.to_le_bytes());
    data.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
    data.extend_from_slice(&[0; 4]);
    for entry in entries {
        data.push(entry.suite_id);
        data.extend_from_slice(&entry.weight.to_le_bytes());
        data.push(0);
        data.extend_from_slice(
            &u16::try_from(entry.pubkey_bytes.len())
                .unwrap()
                .to_le_bytes(),
        );
        data.extend_from_slice(&entry.pubkey_bytes);
    }
    Account {
        id,
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

fn with_appended_entry(account: &Account, entry: &WireKeyEntry) -> Account {
    let mut changed = account.clone();
    let count = u16::from_le_bytes([changed.data[6], changed.data[7]]);
    changed.data[6..8].copy_from_slice(&count.checked_add(1).unwrap().to_le_bytes());
    changed.data.push(entry.suite_id);
    changed.data.extend_from_slice(&entry.weight.to_le_bytes());
    changed.data.push(0);
    changed.data.extend_from_slice(
        &u16::try_from(entry.pubkey_bytes.len())
            .unwrap()
            .to_le_bytes(),
    );
    changed.data.extend_from_slice(&entry.pubkey_bytes);
    changed
}

fn stored_view(bytes: &[u8]) -> StoredKeysetView<'_> {
    parse_stored_keyset(
        bytes,
        StoredKeysetLimits {
            max_encoded_bytes: 8192,
            max_entries: WORKSPACE_ENTRIES,
            max_key_bytes: 1312,
            max_total_key_bytes: 8192,
        },
    )
    .expect("complete well-framed test keyset")
}

fn proof_limits() -> KeysetProofEvaluationLimits {
    KeysetProofEvaluationLimits {
        max_proof_count: TEST_MAX_PROOFS,
        max_signature_bytes: TEST_MAX_SIGNATURE_BYTES,
        max_aggregate_signature_bytes: TEST_MAX_AGGREGATE_SIGNATURE_BYTES,
        max_algorithm_parameter_identifier_bytes: TEST_MAX_IDENTIFIER_BYTES,
    }
}

fn exact_error(actual: ExecutionError, expected: ExecutionError) {
    match (actual, expected) {
        (ExecutionError::InvalidCallData(a), ExecutionError::InvalidCallData(b))
        | (ExecutionError::CryptoError(a), ExecutionError::CryptoError(b))
        | (ExecutionError::ProgramError(a), ExecutionError::ProgramError(b)) => assert_eq!(a, b),
        (a, b) => panic!("unexpected error: {a:?}, expected {b:?}"),
    }
}

fn assert_executor_refusal(
    f: &mut Fixture,
    tx: &Transaction,
    error: ExecutionError,
    expected_reads: &[AccountId],
    expected_lookups: &[u8],
    expected_attempts: usize,
) {
    let before_store = f.store.snapshot();
    let before_tx = tx.clone();
    let before_tx_wire = {
        let mut bytes = Vec::new();
        tx.encode(&mut bytes);
        bytes
    };
    let expected_responses: Vec<_> = expected_reads
        .iter()
        .map(|id| (*id, before_store.get(id).cloned()))
        .collect();
    let digest = tx_digest(tx);
    let expected_attempts: Vec<_> = tx
        .auths
        .iter()
        .take(expected_attempts)
        .map(|auth| {
            let account_id = tx.accounts[usize::from(auth.account_index)].account_id;
            let view = stored_view(&before_store[&account_id].data);
            let key = view
                .entries()
                .find(|entry| entry.suite_id == auth.suite_id)
                .expect("measured production proof has a selected suite entry");
            Attempt {
                suite_id: auth.suite_id,
                key: key.pubkey_bytes.to_vec(),
                digest,
                signature: auth.signature.clone(),
            }
        })
        .collect();
    let result = f.execute(tx);
    exact_error(
        result.expect_err("the keyset program must refuse creation"),
        error,
    );
    assert_eq!(*f.store.reads.borrow(), expected_reads);
    assert_eq!(*f.store.responses.borrow(), expected_responses);
    assert!(f.store.puts.is_empty());
    assert!(f.store.deletes.is_empty());
    assert_eq!(*f.work.lookups.lock().unwrap(), expected_lookups);
    assert_eq!(*f.work.suite_ids.lock().unwrap(), expected_lookups);
    assert_eq!(*f.work.attempts.lock().unwrap(), expected_attempts);
    assert_eq!(f.work.descriptors.lock().unwrap().len(), 0);
    assert_eq!(f.store.snapshot(), before_store);
    assert_eq!(*tx, before_tx);
    let mut after_tx_wire = Vec::new();
    tx.encode(&mut after_tx_wire);
    assert_eq!(after_tx_wire, before_tx_wire);
}

fn assert_isolated_work(
    f: &Fixture,
    lookup_ids: &[u8],
    suite_ids: &[u8],
    descriptor_ids: &[u8],
    signature_attempts: usize,
) {
    assert_eq!(*f.work.lookups.lock().unwrap(), lookup_ids);
    assert_eq!(*f.work.suite_ids.lock().unwrap(), suite_ids);
    let descriptors = f.work.descriptors.lock().unwrap();
    assert_eq!(
        descriptors.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        descriptor_ids
    );
    assert_eq!(f.work.attempts.lock().unwrap().len(), signature_attempts);
}

fn direct_semantics(
    f: &Fixture,
    bytes: &[u8],
    max_proofs: usize,
) -> Result<
    qbind_ledger::keyset_validation::KeysetSemanticAnalysisSummary,
    KeysetSemanticAnalysisError,
> {
    f.work.reset();
    analyze_stored_keyset_semantics::<WORKSPACE_ENTRIES>(
        stored_view(bytes),
        f.provider.as_ref(),
        max_proofs,
        TEST_MAX_IDENTIFIER_BYTES,
    )
}

fn direct_proofs<'a>(
    f: &Fixture,
    bytes: &'a [u8],
    digest: &Hash32,
    proofs: &[KeysetSignatureProof<'_>],
) -> Result<qbind_ledger::keyset_proof::KeysetProofEvaluationSummary, KeysetProofEvaluationError> {
    f.work.reset();
    evaluate_stored_keyset_proofs::<WORKSPACE_ENTRIES>(
        stored_view(bytes),
        f.provider.as_ref(),
        digest,
        proofs,
        proof_limits(),
    )
}

fn assert_conflicting_isolation(f: &Fixture, bytes: &[u8], tx: &Transaction) {
    assert_eq!(
        direct_semantics(f, bytes, 2),
        Err(KeysetSemanticAnalysisError::ConflictingDuplicateWeights)
    );
    assert_isolated_work(
        f,
        &[tx.auths[0].suite_id, tx.auths[0].suite_id],
        &[tx.auths[0].suite_id, tx.auths[0].suite_id],
        &[tx.auths[0].suite_id, tx.auths[0].suite_id],
        0,
    );
    let proof = [KeysetSignatureProof {
        suite_id: tx.auths[0].suite_id,
        signature_bytes: &tx.auths[0].signature,
    }];
    assert_eq!(
        direct_proofs(f, bytes, &tx_digest(tx), &proof),
        Err(KeysetProofEvaluationError::ConflictingDuplicateWeights)
    );
    assert_isolated_work(
        f,
        &[tx.auths[0].suite_id, tx.auths[0].suite_id],
        &[tx.auths[0].suite_id, tx.auths[0].suite_id],
        &[tx.auths[0].suite_id, tx.auths[0].suite_id],
        0,
    );
}

#[test]
fn aliases_share_content_identity_but_production_verifies_each_proof() {
    let mut f = Fixture::new();
    let same_bytes_other_buffer = f.key.public.clone();
    assert_ne!(same_bytes_other_buffer.as_ptr(), f.key.public.as_ptr());
    let suite_a = MlDsa44SignatureSuite::new(SUITE_A);
    let suite_b = MlDsa44SignatureSuite::new(SUITE_B);
    assert_eq!(
        suite_a.canonical_key_descriptor(&f.key.public).unwrap(),
        suite_b
            .canonical_key_descriptor(&same_bytes_other_buffer)
            .unwrap()
    );
    let other = Key::genuine();
    assert_ne!(
        suite_a.canonical_key_descriptor(&f.key.public).unwrap(),
        suite_a.canonical_key_descriptor(&other.public).unwrap()
    );

    f.seed_entries(
        1,
        &[
            f.key.entry(SUITE_A, 1),
            Key {
                public: same_bytes_other_buffer,
                secret: Vec::new(),
            }
            .entry(SUITE_B, 1),
        ],
    );
    let tx = f.transaction(&[SUITE_A, SUITE_B]);
    let account_before = f.store.snapshot();
    assert_executor_refusal(
        &mut f,
        &tx,
        ExecutionError::ProgramError("native keyset creation authority unavailable"),
        &[SIGNER, SIGNER, TARGET],
        &[SUITE_A, SUITE_B],
        2,
    );
    assert_eq!(f.store.snapshot(), account_before);
    let descriptor_a = suite_a.canonical_key_descriptor(&f.key.public).unwrap();
    let descriptor_b = suite_b.canonical_key_descriptor(&f.key.public).unwrap();
    assert_eq!(descriptor_a, descriptor_b);

    let account_bytes = &account_before[&SIGNER].data;
    let summary = direct_semantics(&f, account_bytes, 2).expect("equal alias weights are coherent");
    assert_eq!(summary.encoded_entry_count, 2);
    assert_eq!(summary.distinct_canonical_identity_count, 1);
    assert_eq!(summary.total_distinct_key_weight, 1);
    assert_eq!(summary.attainable_weight, 1);
    assert_eq!(
        f.work.lookups.lock().unwrap().as_slice(),
        &[SUITE_A, SUITE_B]
    );
    assert_eq!(
        f.work.suite_ids.lock().unwrap().as_slice(),
        &[SUITE_A, SUITE_B]
    );
    assert_eq!(f.work.descriptors.lock().unwrap().len(), 2);
    assert!(f.work.attempts.lock().unwrap().is_empty());
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        0,
    );

    let proofs = [
        KeysetSignatureProof {
            suite_id: SUITE_A,
            signature_bytes: &tx.auths[0].signature,
        },
        KeysetSignatureProof {
            suite_id: SUITE_B,
            signature_bytes: &tx.auths[1].signature,
        },
    ];
    let evaluated = direct_proofs(&f, account_bytes, &tx_digest(&tx), &proofs)
        .expect("both genuine alias proofs evaluate");
    assert_eq!(evaluated.evaluated_proof_count, 2);
    assert_eq!(evaluated.verified_distinct_key_count, 1);
    assert_eq!(evaluated.verified_distinct_key_weight, 1);
    assert_eq!(
        f.work.lookups.lock().unwrap().as_slice(),
        &[SUITE_A, SUITE_B]
    );
    assert_eq!(
        f.work.suite_ids.lock().unwrap().as_slice(),
        &[SUITE_A, SUITE_B]
    );
    assert_eq!(f.work.descriptors.lock().unwrap().len(), 2);
    assert_eq!(f.work.attempts.lock().unwrap().len(), 2);
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        2,
    );
    let alias_attempts = f.work.attempts.lock().unwrap();
    assert!(alias_attempts
        .iter()
        .all(|attempt| attempt.key == f.key.public && attempt.digest == tx_digest(&tx)));
    assert_eq!(
        alias_attempts
            .iter()
            .map(|attempt| attempt.signature.as_slice())
            .collect::<Vec<_>>(),
        vec![
            tx.auths[0].signature.as_slice(),
            tx.auths[1].signature.as_slice()
        ]
    );
}

#[test]
fn conflicting_duplicate_weights_are_order_and_alias_selected_in_production_only() {
    let mut f = Fixture::new();
    let low = f.key.entry(SUITE_A, 1);
    let high = f.key.entry(SUITE_A, 2);
    let tx = f.transaction(&[SUITE_A]);

    for entries in [[low.clone(), high.clone()], [high.clone(), low.clone()]] {
        f.seed_entries(1, &entries);
        assert_executor_refusal(
            &mut f,
            &tx,
            ExecutionError::ProgramError("native keyset creation authority unavailable"),
            &[SIGNER, TARGET],
            &[SUITE_A],
            1,
        );
        let snapshot = f.store.snapshot();
        let bytes = &snapshot[&SIGNER].data;
        assert_eq!(
            direct_semantics(&f, bytes, 2),
            Err(KeysetSemanticAnalysisError::ConflictingDuplicateWeights)
        );
        assert_eq!(
            f.work.attempts.lock().unwrap().len(),
            0,
            "semantic conflict is found before proof verification"
        );
        assert_isolated_work(
            &f,
            &[SUITE_A, SUITE_A],
            &[SUITE_A, SUITE_A],
            &[SUITE_A, SUITE_A],
            0,
        );
        let proof = [KeysetSignatureProof {
            suite_id: SUITE_A,
            signature_bytes: &tx.auths[0].signature,
        }];
        assert_eq!(
            direct_proofs(&f, bytes, &tx_digest(&tx), &proof),
            Err(KeysetProofEvaluationError::ConflictingDuplicateWeights)
        );
        assert!(f.work.attempts.lock().unwrap().is_empty());
        assert_isolated_work(
            &f,
            &[SUITE_A, SUITE_A],
            &[SUITE_A, SUITE_A],
            &[SUITE_A, SUITE_A],
            0,
        );
    }

    f.seed_entries(2, &[low.clone(), high.clone()]);
    assert_executor_refusal(
        &mut f,
        &tx,
        ExecutionError::InvalidCallData("selected key weight below keyset threshold"),
        &[SIGNER],
        &[],
        0,
    );
    let low_first = f.store.snapshot();
    assert_conflicting_isolation(&f, &low_first[&SIGNER].data, &tx);
    f.seed_entries(2, &[high.clone(), low.clone()]);
    assert_executor_refusal(
        &mut f,
        &tx,
        ExecutionError::ProgramError("native keyset creation authority unavailable"),
        &[SIGNER, TARGET],
        &[SUITE_A],
        1,
    );
    let high_first = f.store.snapshot();
    assert_conflicting_isolation(&f, &high_first[&SIGNER].data, &tx);

    let alias_entries = [f.key.entry(SUITE_A, 1), f.key.entry(SUITE_B, 2)];
    f.seed_entries(1, &alias_entries);
    let tx_a = f.transaction(&[SUITE_A]);
    assert_executor_refusal(
        &mut f,
        &tx_a,
        ExecutionError::ProgramError("native keyset creation authority unavailable"),
        &[SIGNER, TARGET],
        &[SUITE_A],
        1,
    );
    let tx_b = f.transaction(&[SUITE_B]);
    assert_executor_refusal(
        &mut f,
        &tx_b,
        ExecutionError::ProgramError("native keyset creation authority unavailable"),
        &[SIGNER, TARGET],
        &[SUITE_B],
        1,
    );
    let alias_snapshot = f.store.snapshot();
    let alias_bytes = &alias_snapshot[&SIGNER].data;
    assert_eq!(
        direct_semantics(&f, alias_bytes, 2),
        Err(KeysetSemanticAnalysisError::ConflictingDuplicateWeights)
    );
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        0,
    );
    let both_alias_proofs = [
        KeysetSignatureProof {
            suite_id: SUITE_A,
            signature_bytes: &tx_a.auths[0].signature,
        },
        KeysetSignatureProof {
            suite_id: SUITE_B,
            signature_bytes: &tx_b.auths[0].signature,
        },
    ];
    assert_eq!(
        direct_proofs(&f, alias_bytes, &tx_digest(&tx_a), &both_alias_proofs),
        Err(KeysetProofEvaluationError::ConflictingDuplicateWeights)
    );
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        0,
    );

    f.seed_entries(2, &alias_entries);
    let tx_a = f.transaction(&[SUITE_A]);
    assert_executor_refusal(
        &mut f,
        &tx_a,
        ExecutionError::InvalidCallData("selected key weight below keyset threshold"),
        &[SIGNER],
        &[],
        0,
    );
    let tx_b = f.transaction(&[SUITE_B]);
    assert_executor_refusal(
        &mut f,
        &tx_b,
        ExecutionError::ProgramError("native keyset creation authority unavailable"),
        &[SIGNER, TARGET],
        &[SUITE_B],
        1,
    );
    let alias_snapshot = f.store.snapshot();
    let alias_bytes = &alias_snapshot[&SIGNER].data;
    assert_eq!(
        direct_semantics(&f, alias_bytes, 2),
        Err(KeysetSemanticAnalysisError::ConflictingDuplicateWeights)
    );
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        0,
    );
    let proof = [KeysetSignatureProof {
        suite_id: SUITE_B,
        signature_bytes: &tx_b.auths[0].signature,
    }];
    assert_eq!(
        direct_proofs(&f, alias_bytes, &tx_digest(&tx_b), &proof),
        Err(KeysetProofEvaluationError::ConflictingDuplicateWeights)
    );
    assert!(f.work.attempts.lock().unwrap().is_empty());
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        0,
    );
}

#[test]
fn repeated_proofs_do_not_create_weight_for_equal_duplicate_aliases() {
    let mut f = Fixture::new();
    let tx = f.transaction(&[SUITE_A, SUITE_B]);
    let cases = [
        vec![f.key.entry(SUITE_A, 1), f.key.entry(SUITE_A, 1)],
        vec![f.key.entry(SUITE_A, 1), f.key.entry(SUITE_B, 1)],
    ];
    for entries in cases {
        f.seed_entries(2, &entries);
        assert_executor_refusal(
            &mut f,
            &tx,
            ExecutionError::InvalidCallData("selected key weight below keyset threshold"),
            &[SIGNER],
            &[],
            0,
        );
        let snapshot = f.store.snapshot();
        let bytes = &snapshot[&SIGNER].data;
        assert_eq!(
            direct_semantics(&f, bytes, 2),
            Err(KeysetSemanticAnalysisError::ThresholdUnreachable),
            "the analyzer refuses reachability before proof evaluation"
        );
        assert_isolated_work(
            &f,
            &[SUITE_A, entries[1].suite_id],
            &[SUITE_A, entries[1].suite_id],
            &[SUITE_A, entries[1].suite_id],
            0,
        );
        let proofs = [
            KeysetSignatureProof {
                suite_id: SUITE_A,
                signature_bytes: &tx.auths[0].signature,
            },
            KeysetSignatureProof {
                suite_id: SUITE_B,
                signature_bytes: &tx.auths[1].signature,
            },
        ];
        assert_eq!(
            direct_proofs(&f, bytes, &tx_digest(&tx), &proofs),
            Err(KeysetProofEvaluationError::ThresholdUnreachable)
        );
        assert!(f.work.attempts.lock().unwrap().is_empty());
        assert_isolated_work(
            &f,
            &[SUITE_A, entries[1].suite_id],
            &[SUITE_A, entries[1].suite_id],
            &[SUITE_A, entries[1].suite_id],
            0,
        );
    }
}

#[test]
fn first_matching_production_key_differs_from_isolated_complete_candidate_scan() {
    let mut f = Fixture::new();
    let other = Key::genuine();
    let digest_tx = f.transaction(&[SUITE_A]);
    let first_signature = ml_dsa_44_sign_digest(&f.key.secret, &tx_digest(&digest_tx))
        .expect("genuine key signs fixed transaction digest");
    let mut tx = digest_tx;
    tx.auths[0].signature = first_signature.clone();
    let right = f.key.entry(SUITE_A, 2);
    let wrong = other.entry(SUITE_A, 2);

    f.seed_entries(2, &[wrong.clone(), right.clone()]);
    assert_executor_refusal(
        &mut f,
        &tx,
        ExecutionError::CryptoError("signature verification failed"),
        &[SIGNER],
        &[SUITE_A],
        1,
    );
    assert_eq!(f.work.attempts.lock().unwrap()[0].key, other.public);
    let wrong_first = f.store.snapshot();
    let first_order_result = direct_proofs(
        &f,
        &wrong_first[&SIGNER].data,
        &tx_digest(&tx),
        &[KeysetSignatureProof {
            suite_id: SUITE_A,
            signature_bytes: &tx.auths[0].signature,
        }],
    )
    .expect("isolated scan succeeds regardless of encoded order");
    assert_eq!(first_order_result.verified_distinct_key_weight, 2);
    assert_eq!(f.work.attempts.lock().unwrap().len(), 2);
    assert_eq!(
        f.work.attempts.lock().unwrap()[0].key,
        other.public,
        "complete scan follows stored order"
    );
    assert_eq!(
        f.work.attempts.lock().unwrap()[1].key,
        f.key.public,
        "complete scan reaches matching later key"
    );
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_A],
        &[SUITE_A, SUITE_A],
        &[SUITE_A, SUITE_A],
        2,
    );

    f.seed_entries(2, &[right.clone(), wrong.clone()]);
    assert_executor_refusal(
        &mut f,
        &tx,
        ExecutionError::ProgramError("native keyset creation authority unavailable"),
        &[SIGNER, TARGET],
        &[SUITE_A],
        1,
    );
    assert_eq!(f.work.attempts.lock().unwrap()[0].key, f.key.public);

    let proofs = [KeysetSignatureProof {
        suite_id: SUITE_A,
        signature_bytes: &tx.auths[0].signature,
    }];
    let snapshot = f.store.snapshot();
    let bytes = &snapshot[&SIGNER].data;
    let result = direct_proofs(&f, bytes, &tx_digest(&tx), &proofs)
        .expect("isolated scan finds the actual matching candidate");
    assert_eq!(result.evaluated_proof_count, 1);
    assert_eq!(result.verified_distinct_key_count, 1);
    assert_eq!(result.verified_distinct_key_weight, 2);
    let attempts = f.work.attempts.lock().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].key, f.key.public);
    assert_eq!(attempts[1].key, other.public);
    assert!(attempts
        .iter()
        .all(|attempt| attempt.signature == first_signature));
    assert!(attempts
        .iter()
        .all(|attempt| attempt.digest == tx_digest(&tx)));
    drop(attempts);
    assert_eq!(
        f.work.lookups.lock().unwrap().as_slice(),
        &[SUITE_A, SUITE_A]
    );
    assert_eq!(
        f.work.suite_ids.lock().unwrap().as_slice(),
        &[SUITE_A, SUITE_A]
    );
    assert_eq!(f.work.descriptors.lock().unwrap().len(), 2);
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_A],
        &[SUITE_A, SUITE_A],
        &[SUITE_A, SUITE_A],
        2,
    );
}

#[test]
fn unused_invalid_entries_are_isolated_admission_refusals() {
    let mut f = Fixture::new();
    let tx = f.transaction(&[SUITE_A]);
    let selected = f.key.entry(SUITE_A, 1);

    f.seed_entries(1, std::slice::from_ref(&selected));
    assert_executor_refusal(
        &mut f,
        &tx,
        ExecutionError::ProgramError("native keyset creation authority unavailable"),
        &[SIGNER, TARGET],
        &[SUITE_A],
        1,
    );
    let control_snapshot = f.store.snapshot();
    let control_account = control_snapshot[&SIGNER].clone();
    let control = control_account.data.clone();
    let proof = [KeysetSignatureProof {
        suite_id: SUITE_A,
        signature_bytes: &tx.auths[0].signature,
    }];
    let ok = direct_proofs(&f, &control, &tx_digest(&tx), &proof).unwrap();
    assert_eq!(ok.verified_distinct_key_weight, 1);
    assert_eq!(f.work.attempts.lock().unwrap().len(), 1);
    let control_attempts = f.work.attempts.lock().unwrap();
    let control_attempt = &control_attempts[0];
    assert_eq!(control_attempt.key, f.key.public);
    assert_eq!(control_attempt.digest, tx_digest(&tx));
    assert_eq!(control_attempt.signature, tx.auths[0].signature);
    drop(control_attempts);
    assert_isolated_work(&f, &[SUITE_A], &[SUITE_A], &[SUITE_A], 1);

    for (invalid, expected) in [
        (
            WireKeyEntry {
                suite_id: 0xFE,
                weight: 1,
                pubkey_bytes: f.key.public.clone(),
            },
            KeysetProofEvaluationError::SuiteNotFound,
        ),
        (
            WireKeyEntry {
                suite_id: SUITE_B,
                weight: 1,
                pubkey_bytes: vec![0xAA],
            },
            KeysetProofEvaluationError::DescriptorMalformed,
        ),
    ] {
        let fault_account = with_appended_entry(&control_account, &invalid);
        let fault_bytes = fault_account.data.clone();
        let mut fault_store = control_snapshot.clone();
        fault_store.insert(SIGNER, fault_account);
        f.store.accounts = fault_store;
        assert_executor_refusal(
            &mut f,
            &tx,
            ExecutionError::ProgramError("native keyset creation authority unavailable"),
            &[SIGNER, TARGET],
            &[SUITE_A],
            1,
        );
        assert_eq!(
            direct_semantics(&f, &fault_bytes, 2),
            Err(match expected {
                KeysetProofEvaluationError::SuiteNotFound => {
                    KeysetSemanticAnalysisError::SuiteNotFound
                }
                KeysetProofEvaluationError::DescriptorMalformed => {
                    KeysetSemanticAnalysisError::DescriptorMalformed
                }
                _ => unreachable!(),
            })
        );
        if expected == KeysetProofEvaluationError::SuiteNotFound {
            assert_isolated_work(&f, &[SUITE_A, 0xFE], &[SUITE_A], &[SUITE_A], 0);
        } else {
            assert_isolated_work(
                &f,
                &[SUITE_A, SUITE_B],
                &[SUITE_A, SUITE_B],
                &[SUITE_A, SUITE_B],
                0,
            );
        }
        assert_eq!(
            direct_proofs(&f, &fault_bytes, &tx_digest(&tx), &proof),
            Err(expected)
        );
        let expected_lookups = if expected == KeysetProofEvaluationError::SuiteNotFound {
            vec![SUITE_A, 0xFE]
        } else {
            vec![SUITE_A, SUITE_B]
        };
        assert_eq!(*f.work.lookups.lock().unwrap(), expected_lookups);
        assert_eq!(f.work.attempts.lock().unwrap().len(), 0);
        assert_eq!(
            f.work.descriptors.lock().unwrap().len(),
            if expected == KeysetProofEvaluationError::SuiteNotFound {
                1
            } else {
                2
            }
        );
        if expected == KeysetProofEvaluationError::SuiteNotFound {
            assert_isolated_work(&f, &[SUITE_A, 0xFE], &[SUITE_A], &[SUITE_A], 0);
        } else {
            assert_isolated_work(
                &f,
                &[SUITE_A, SUITE_B],
                &[SUITE_A, SUITE_B],
                &[SUITE_A, SUITE_B],
                0,
            );
        }
    }
}

#[test]
fn conflicting_account_corrected_retry_preserves_transaction_and_store() {
    let mut f = Fixture::new();
    let entries = [f.key.entry(SUITE_A, 1), f.key.entry(SUITE_B, 2)];
    f.seed_entries(1, &entries);
    let tx = f.transaction(&[SUITE_A]);
    let tx_before = tx.clone();
    let initial_store = f.store.snapshot();
    let rejected = initial_store[&SIGNER].data.clone();
    let proof = [KeysetSignatureProof {
        suite_id: SUITE_A,
        signature_bytes: &tx.auths[0].signature,
    }];
    assert_eq!(
        direct_proofs(&f, &rejected, &tx_digest(&tx), &proof),
        Err(KeysetProofEvaluationError::ConflictingDuplicateWeights)
    );
    assert!(f.work.attempts.lock().unwrap().is_empty());
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        0,
    );

    let mut corrected_entries = entries.clone();
    corrected_entries[1].weight = 1;
    let corrected_account = keyset_account(SIGNER, 1, &corrected_entries);
    let expected_corrected_store = HashMap::from([(SIGNER, corrected_account.clone())]);
    f.store.accounts.insert(SIGNER, corrected_account);
    let corrected_store_before = f.store.snapshot();
    assert_eq!(corrected_store_before, expected_corrected_store);
    let summary = direct_semantics(&f, &corrected_store_before[&SIGNER].data, 2)
        .expect("corrected canonical aliases are consistent");
    assert_eq!(summary.distinct_canonical_identity_count, 1);
    assert_eq!(summary.total_distinct_key_weight, 1);
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        0,
    );
    let evaluated = direct_proofs(
        &f,
        &corrected_store_before[&SIGNER].data,
        &tx_digest(&tx),
        &proof,
    )
    .expect("genuine proof remains valid after state-only weight correction");
    assert_eq!(evaluated.verified_distinct_key_count, 1);
    assert_eq!(evaluated.verified_distinct_key_weight, 1);
    assert_isolated_work(
        &f,
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        &[SUITE_A, SUITE_B],
        1,
    );
    let retry_attempts = f.work.attempts.lock().unwrap();
    let retry_attempt = &retry_attempts[0];
    assert_eq!(retry_attempt.key, f.key.public);
    assert_eq!(retry_attempt.digest, tx_digest(&tx));
    assert_eq!(retry_attempt.signature, tx.auths[0].signature);
    assert_eq!(tx, tx_before);
    assert_eq!(f.store.snapshot(), corrected_store_before);
    assert!(f.store.puts.is_empty());
    assert!(f.store.deletes.is_empty());
}
