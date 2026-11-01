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
use qbind_ledger::keyset_account::KeysetAccountReadError;
use qbind_ledger::keyset_proof::KeysetProofEvaluationError;
use qbind_ledger::native_admission_context::{
    FixtureBinding, FixtureProfileStatus, NativeAdmissionContext, NativeAdmissionContextError,
    PrototypeFixture, PrototypePolicy,
};
use qbind_ledger::native_tx_proof::{
    evaluate_native_transaction_proofs, NativeTransactionProofError, NativeTransactionProofLimits,
    NativeTransactionProofSummary,
};
use qbind_ledger::{Account, AccountStore, InMemoryAccountStore};
use qbind_serde::keyset::{StoredKeysetLimits, StoredKeysetParseError};
use qbind_serde::{StateEncode, StateError};
use qbind_types::{AccountId, Hash32, KeysetAccount, KeysetEntry, KEYSET_PROGRAM_ID};
use qbind_wire::io::WireEncode;
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};

const A: AccountId = [0xA0; 32];
const B: AccountId = [0xB0; 32];
const SUITE: u8 = 100;
type Context<'a> = NativeAdmissionContext<'a, 8, 8, 16>;
type Keypair = (Vec<u8>, Vec<u8>);

// Completed assessment candidate, all numerical limits UNAPPROVED.
fn binding(generation: u8) -> FixtureBinding {
    FixtureBinding {
        chain_id: 1,
        execution_pre_state: [generation; 32],
        policy: PrototypePolicy {
            identity: [0x42; 32],
            version: 1,
            limits: NativeTransactionProofLimits {
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
            },
        },
        provider_identity: [0x44; 32],
    }
}

#[derive(Default)]
struct Counts {
    lookups: AtomicUsize,
    descriptors: AtomicUsize,
    verifications: AtomicUsize,
}

#[derive(Clone, Copy)]
enum ProviderMode {
    Genuine,
    InjectedVerificationFailure,
    InjectedVerificationPanic,
}

struct CountedSuite {
    inner: MlDsa44SignatureSuite,
    counts: Arc<Counts>,
    mode: ProviderMode,
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
        match self.mode {
            ProviderMode::Genuine => self.inner.verify(public_key, digest, signature),
            ProviderMode::InjectedVerificationFailure => {
                Err(CryptoError::InternalError("injected provider control"))
            }
            ProviderMode::InjectedVerificationPanic => panic!("injected provider unwind control"),
        }
    }
}

struct CountedProvider {
    inner: StaticCryptoProvider,
    counts: Arc<Counts>,
}

impl CountedProvider {
    fn new(mode: ProviderMode) -> Self {
        let counts = Arc::new(Counts::default());
        Self {
            inner: StaticCryptoProvider::new().with_signature_suite(Arc::new(CountedSuite {
                inner: MlDsa44SignatureSuite::new(SUITE),
                counts: Arc::clone(&counts),
                mode,
            })),
            counts,
        }
    }

    fn assert_work(&self, lookups: usize, descriptors: usize, verifications: usize) {
        assert_eq!(self.counts.lookups.load(Ordering::SeqCst), lookups);
        assert_eq!(self.counts.descriptors.load(Ordering::SeqCst), descriptors);
        assert_eq!(
            self.counts.verifications.load(Ordering::SeqCst),
            verifications
        );
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
            pubkey_len: u16::try_from(public_key.len()).unwrap(),
            pubkey_bytes: public_key.to_vec(),
        }],
    };
    let mut data = Vec::new();
    state.encode_state(&mut data);
    Account::new(id, KEYSET_PROGRAM_ID, 0, data)
}

impl Fixture {
    fn new() -> Self {
        let keys = std::array::from_fn(|_| MlDsa44Backend::generate_keypair().unwrap());
        for i in 0..4 {
            for j in 0..i {
                assert_ne!(keys[i].0, keys[j].0);
                assert_ne!(keys[i].1, keys[j].1);
            }
        }
        let expected = [
            [keyset(A, &keys[0].0), keyset(B, &keys[1].0)],
            [keyset(A, &keys[2].0), keyset(B, &keys[3].0)],
        ];
        let stores = std::array::from_fn(|g| store_with(&expected[g]));
        Self {
            keys,
            stores,
            expected,
        }
    }

    fn assert_preserved(&self) {
        for (store, expected) in self.stores.iter().zip(&self.expected) {
            assert_accounts(store, expected);
        }
    }

    fn transaction(&self, a: usize, b: usize) -> Transaction {
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
        let digest = try_tx_digest_streaming(&tx).unwrap();
        for (index, key) in [a, b].into_iter().enumerate() {
            let signature = ml_dsa_44_sign_digest(&self.keys[key].1, &digest).unwrap();
            assert_eq!(signature.len(), 2_420);
            tx.auths.push(TxAuth {
                account_index: u16::try_from(index).unwrap(),
                suite_id: SUITE,
                reserved: 0,
                signature,
            });
        }
        tx
    }
}

fn store_with(accounts: &[Account]) -> InMemoryAccountStore {
    let mut store = InMemoryAccountStore::new();
    for account in accounts {
        store.put(account.clone()).unwrap();
    }
    store
}

fn assert_accounts(store: &InMemoryAccountStore, accounts: &[Account]) {
    for account in accounts {
        assert_eq!(store.get(&account.id), Some(account.clone()));
    }
}

fn wire(tx: &Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    tx.encode(&mut bytes);
    bytes
}

fn evaluate(
    store: &InMemoryAccountStore,
    tx: &Transaction,
    provider: &dyn CryptoProvider,
    generation: u8,
) -> Result<NativeTransactionProofSummary, NativeTransactionProofError> {
    let fixture = PrototypeFixture::new_for_fixture(
        store,
        provider,
        binding(generation),
        FixtureProfileStatus::Active,
    );
    Context::new_for_fixture(Some(&fixture), Some(binding(generation)), tx)
        .unwrap()
        .evaluate()
}

fn success() -> NativeTransactionProofSummary {
    NativeTransactionProofSummary {
        required_signer_index_count: 2,
        distinct_keyset_account_count: 2,
        evaluated_authentication_proof_count: 2,
    }
}

#[test]
fn pinned_generations_refuse_mixed_genuine_proofs_and_accept_matched_controls() {
    let fixture = Fixture::new();
    let mixed = fixture.transaction(0, 3);
    let s0 = fixture.transaction(0, 1);
    let s1 = fixture.transaction(2, 3);
    let originals = [mixed.clone(), s0.clone(), s1.clone()];
    let bytes = originals.each_ref().map(wire);
    for (tx, generation, attempts, result) in [
        (
            &mixed,
            0,
            2,
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::InvalidProof,
            )),
        ),
        (
            &mixed,
            1,
            1,
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::InvalidProof,
            )),
        ),
        (&s0, 0, 2, Ok(success())),
        (&s1, 1, 2, Ok(success())),
    ] {
        let provider = CountedProvider::new(ProviderMode::Genuine);
        assert_eq!(
            evaluate(&fixture.stores[generation], tx, &provider, generation as u8),
            result
        );
        provider.assert_work(attempts, attempts, attempts);
        fixture.assert_preserved();
        for (index, current) in [&mixed, &s0, &s1].into_iter().enumerate() {
            assert_eq!(current, &originals[index]);
            assert_eq!(wire(current), bytes[index]);
        }
    }
}

fn refusal<const G: usize, const P: usize, const E: usize>(
    fixture: Option<&PrototypeFixture<'_>>,
    requested: Option<FixtureBinding>,
    tx: &Transaction,
    expected: NativeAdmissionContextError,
) {
    match NativeAdmissionContext::<G, P, E>::new_for_fixture(fixture, requested, tx) {
        Err(error) => assert_eq!(error, expected),
        Ok(_) => panic!("expected early construction refusal {expected:?}"),
    }
}

#[test]
fn fixture_selection_refusals_and_small_transaction_workspace_controls() {
    use NativeAdmissionContextError as Error;
    let fixture = Fixture::new();
    let tx = fixture.transaction(0, 1);
    let original = tx.clone();
    let bytes = wire(&tx);
    let provider = CountedProvider::new(ProviderMode::Genuine);
    let selected = binding(0);
    let source = PrototypeFixture::new_for_fixture(
        &fixture.stores[0],
        &provider,
        selected,
        FixtureProfileStatus::Active,
    );
    refusal::<8, 8, 16>(Some(&source), None, &tx, Error::MissingBinding);
    refusal::<8, 8, 16>(None, Some(selected), &tx, Error::UnavailableFixture);
    for (status, error) in [
        (FixtureProfileStatus::Inactive, Error::InactiveProfile),
        (
            FixtureProfileStatus::Unavailable,
            Error::UnavailableSelection,
        ),
    ] {
        let source =
            PrototypeFixture::new_for_fixture(&fixture.stores[0], &provider, selected, status);
        refusal::<8, 8, 16>(Some(&source), Some(selected), &tx, error);
    }
    let mut wrong_chain = selected;
    wrong_chain.chain_id = 2;
    let mut wrong_position = selected;
    wrong_position.execution_pre_state = [9; 32];
    let mut unknown = selected;
    unknown.policy.identity = [9; 32];
    let mut wrong_version = selected;
    wrong_version.policy.version = 2;
    let mut wrong_limits = selected;
    wrong_limits.policy.limits.max_signature_bytes -= 1;
    let mut wrong_provider = selected;
    wrong_provider.provider_identity = [9; 32];
    for (requested, error) in [
        (wrong_chain, Error::ChainMismatch),
        (wrong_position, Error::ExecutionPreStateMismatch),
        (unknown, Error::UnknownProfile),
        (wrong_version, Error::ProfileMismatch),
        (wrong_limits, Error::ProfileMismatch),
        (wrong_provider, Error::ProviderMismatch),
    ] {
        refusal::<8, 8, 16>(Some(&source), Some(requested), &tx, error);
        fixture.assert_preserved();
        provider.assert_work(0, 0, 0);
        assert_eq!(tx, original);
        assert_eq!(wire(&tx), bytes);
    }
    let mut wrong_tx_chain = tx.clone();
    wrong_tx_chain.chain_id = 2;
    let wrong_tx_original = wrong_tx_chain.clone();
    refusal::<8, 8, 16>(
        Some(&source),
        Some(selected),
        &wrong_tx_chain,
        Error::ChainMismatch,
    );
    assert_eq!(wrong_tx_chain, wrong_tx_original);
    refusal::<2, 8, 16>(
        Some(&source),
        Some(selected),
        &tx,
        Error::GroupWorkspaceUnsupported,
    );
    refusal::<8, 2, 16>(
        Some(&source),
        Some(selected),
        &tx,
        Error::ProofWorkspaceUnsupported,
    );
    refusal::<8, 8, 1>(
        Some(&source),
        Some(selected),
        &tx,
        Error::EntryWorkspaceUnsupported,
    );
    provider.assert_work(0, 0, 0);
    // This actual transaction fits smaller arrays, but the selected policy does not.
    assert_eq!(
        evaluate_native_transaction_proofs::<2, 2, 1>(
            &tx,
            &fixture.stores[0],
            &provider,
            selected.policy.limits,
        ),
        Ok(success())
    );
    provider.assert_work(2, 2, 2);
    assert_eq!(
        evaluate(&fixture.stores[0], &tx, &provider, 0),
        Ok(success())
    );
    provider.assert_work(4, 4, 4);
    fixture.assert_preserved();
    assert_eq!(tx, original);
    assert_eq!(wire(&tx), bytes);
}

#[test]
fn complete_transaction_binding_does_not_use_signing_digest_as_proof_identity() {
    let fixture = Fixture::new();
    let tx = fixture.transaction(0, 1);
    let mut altered = tx.clone();
    altered.auths[1].signature[0] ^= 1;
    let mut late_invalid = tx.clone();
    let mut extra = altered.auths[1].clone();
    extra.account_index = 0;
    late_invalid.auths.push(extra);
    let originals = [tx.clone(), altered.clone(), late_invalid.clone()];
    let bytes = originals.each_ref().map(wire);
    assert_eq!(
        try_tx_digest_streaming(&tx),
        try_tx_digest_streaming(&altered)
    );
    assert_eq!(
        try_tx_digest_streaming(&tx),
        try_tx_digest_streaming(&late_invalid)
    );
    assert_ne!(wire(&tx), wire(&altered));
    let provider = CountedProvider::new(ProviderMode::Genuine);
    let source = PrototypeFixture::new_for_fixture(
        &fixture.stores[0],
        &provider,
        binding(0),
        FixtureProfileStatus::Active,
    );
    let mut requested = binding(0);
    let context = Context::new_for_fixture(Some(&source), Some(requested), &tx).unwrap();
    // The caller's copied request can change, not the selected context inputs.
    requested.policy.limits.max_authentication_proof_count = 1;
    refusal::<8, 8, 16>(
        Some(&source),
        Some(requested),
        &tx,
        NativeAdmissionContextError::ProfileMismatch,
    );
    provider.assert_work(0, 0, 0);
    assert_eq!(context.evaluate(), Ok(success()));
    provider.assert_work(2, 2, 2);
    assert_eq!(
        evaluate(&fixture.stores[0], &altered, &provider, 0),
        Err(NativeTransactionProofError::KeysetProof(
            KeysetProofEvaluationError::InvalidProof
        ))
    );
    provider.assert_work(4, 4, 4);
    // Every supplied proof is checked, even after A's threshold is attained.
    assert_eq!(
        evaluate(&fixture.stores[0], &late_invalid, &provider, 0),
        Err(NativeTransactionProofError::KeysetProof(
            KeysetProofEvaluationError::InvalidProof
        ))
    );
    provider.assert_work(5, 5, 6);
    assert_eq!(context.evaluate(), Ok(success()));
    provider.assert_work(7, 7, 8);
    context.cancel();
    fixture.assert_preserved();
    for (index, current) in [&tx, &altered, &late_invalid].into_iter().enumerate() {
        assert_eq!(current, &originals[index]);
        assert_eq!(wire(current), bytes[index]);
    }
}

#[test]
fn concrete_bounded_read_and_existing_evidence_refusals_preserve_state() {
    let fixture = Fixture::new();
    let tx = fixture.transaction(0, 1);
    let original = tx.clone();
    let bytes = wire(&tx);
    let a = fixture.expected[0][0].clone();
    let b = fixture.expected[0][1].clone();
    let mut oversized = b.clone();
    oversized.data = vec![0; 65_537];
    let mut malformed = b.clone();
    malformed.data.clear();
    let mut wrong_owner = b.clone();
    wrong_owner.header.owner = [0xEE; 32];
    let mut executable = b.clone();
    executable.header.is_executable = true;
    for (account, error) in [
        (
            None,
            NativeTransactionProofError::AccountRead(KeysetAccountReadError::MissingAccount),
        ),
        (
            Some(oversized),
            NativeTransactionProofError::AccountRead(KeysetAccountReadError::Oversized),
        ),
        (
            Some(malformed),
            NativeTransactionProofError::KeysetParse(StoredKeysetParseError::Malformed(
                StateError::UnexpectedEof,
            )),
        ),
        (
            Some(wrong_owner),
            NativeTransactionProofError::AccountRead(KeysetAccountReadError::OwnerMismatch),
        ),
        (
            Some(executable),
            NativeTransactionProofError::AccountRead(KeysetAccountReadError::Executable),
        ),
    ] {
        let mut expected = vec![a.clone()];
        if let Some(account) = account {
            expected.push(account);
        }
        let store = store_with(&expected);
        let provider = CountedProvider::new(ProviderMode::Genuine);
        assert_eq!(evaluate(&store, &tx, &provider, 0), Err(error));
        provider.assert_work(1, 1, 1);
        assert_accounts(&store, &expected);
        if expected.len() == 1 {
            assert_eq!(store.get(&B), None);
        }
        fixture.assert_preserved();
        assert_eq!(tx, original);
        assert_eq!(wire(&tx), bytes);
        assert_eq!(
            evaluate(&fixture.stores[0], &tx, &provider, 0),
            Ok(success())
        );
        provider.assert_work(3, 3, 3);
        fixture.assert_preserved();
    }
}

#[test]
fn injected_provider_failure_and_unwind_release_only_context_borrows() {
    let fixture = Fixture::new();
    let tx = fixture.transaction(0, 1);
    let original = tx.clone();
    let bytes = wire(&tx);
    let mut store = store_with(&fixture.expected[0]);
    let provider = CountedProvider::new(ProviderMode::InjectedVerificationFailure);
    assert_eq!(
        evaluate(&store, &tx, &provider, 0),
        Err(NativeTransactionProofError::KeysetProof(
            KeysetProofEvaluationError::VerificationFailure
        ))
    );
    provider.assert_work(1, 1, 1);
    assert_accounts(&store, &fixture.expected[0]);
    let panic_provider = CountedProvider::new(ProviderMode::InjectedVerificationPanic);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let source = PrototypeFixture::new_for_fixture(
            &store,
            &panic_provider,
            binding(0),
            FixtureProfileStatus::Active,
        );
        let context = Context::new_for_fixture(Some(&source), Some(binding(0)), &tx).unwrap();
        let _ = context.evaluate();
    }));
    assert!(unwind.is_err());
    panic_provider.assert_work(1, 1, 1);
    assert_accounts(&store, &fixture.expected[0]);
    assert_eq!(tx, original);
    assert_eq!(wire(&tx), bytes);
    fixture.assert_preserved();
    // Caller owners survived the unwind. Mutation is possible after borrow release.
    store.put(fixture.expected[0][0].clone()).unwrap();
    let genuine = CountedProvider::new(ProviderMode::Genuine);
    assert_eq!(evaluate(&store, &tx, &genuine, 0), Ok(success()));
    genuine.assert_work(2, 2, 2);
    assert_accounts(&store, &fixture.expected[0]);
    assert_eq!(tx, original);
}

#[test]
fn cancellation_and_drop_do_not_evaluate_or_destroy_caller_owners() {
    let fixture = Fixture::new();
    let mut tx = fixture.transaction(0, 1);
    let original = tx.clone();
    let mut store = store_with(&fixture.expected[0]);
    let provider = CountedProvider::new(ProviderMode::Genuine);
    for cancel in [true, false] {
        let source = PrototypeFixture::new_for_fixture(
            &store,
            &provider,
            binding(0),
            FixtureProfileStatus::Active,
        );
        let context = Context::new_for_fixture(Some(&source), Some(binding(0)), &tx).unwrap();
        if cancel {
            context.cancel();
        } else {
            drop(context);
        }
        provider.assert_work(0, 0, 0);
        assert_accounts(&store, &fixture.expected[0]);
        assert_eq!(tx, original);
        store.delete(&B).unwrap();
        store.put(fixture.expected[0][1].clone()).unwrap();
        tx.auths.clear();
        tx.auths = original.auths.clone();
    }
    assert_eq!(evaluate(&store, &tx, &provider, 0), Ok(success()));
    provider.assert_work(2, 2, 2);
    assert_accounts(&store, &fixture.expected[0]);
    assert_eq!(tx, original);
    fixture.assert_preserved();
}

#[test]
fn report_fixed_context_and_configuration_sizes() {
    use std::mem::size_of;
    let context = size_of::<Context<'_>>();
    assert_eq!(context, size_of::<NativeAdmissionContext<'_, 0, 0, 0>>());
    assert_eq!(context, size_of::<NativeAdmissionContext<'_, 32, 32, 32>>());
    println!(
        "context={context} fixture={} binding={} policy={} context_error={} evaluator_error={} \
         limits={} summary={} transaction={} account={} provider_reference={} store_reference={}",
        size_of::<PrototypeFixture<'_>>(),
        size_of::<FixtureBinding>(),
        size_of::<PrototypePolicy>(),
        size_of::<NativeAdmissionContextError>(),
        size_of::<NativeTransactionProofError>(),
        size_of::<NativeTransactionProofLimits>(),
        size_of::<NativeTransactionProofSummary>(),
        size_of::<Transaction>(),
        size_of::<Account>(),
        size_of::<&dyn CryptoProvider>(),
        size_of::<&InMemoryAccountStore>(),
    );
}
