use qbind_crypto::error::CryptoError;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
use qbind_crypto::{
    ml_dsa_44_sign_digest, AeadSuite, CryptoProvider, KemSuite, MlDsa44SignatureSuite,
    StaticCryptoProvider,
};
use qbind_hash::tx::try_tx_digest_streaming;
use qbind_ledger::keyset_account::KeysetAccountReadError;
use qbind_ledger::keyset_create::{KeysetCreatePreparationError, KeysetCreatePreparationLimits};
use qbind_ledger::keyset_proof::KeysetProofEvaluationError;
use qbind_ledger::keyset_validation::KeysetSemanticAnalysisError;
use qbind_ledger::native_admission_context::{
    FixtureBinding, FixtureProfileStatus, NativeAdmissionContextError, PrototypePolicy,
};
use qbind_ledger::native_keyset_create_model::{
    KeysetCreateFixtureConfig, KeysetCreateFixtureSelection, KeysetCreateModelError,
    NativeKeysetCreateModel,
};
use qbind_ledger::native_staged_effects::{
    FixtureBeginError, FixtureStageLimits, FixtureStageRefusal,
};
use qbind_ledger::native_tx_proof::{
    NativeTransactionProofError, NativeTransactionProofLimits, NativeTransactionProofStructureError,
};
use qbind_ledger::{Account, AccountStore, InMemoryAccountStore};
use qbind_serde::keyset::StoredKeysetLimits;
use qbind_serde::StateEncode;
use qbind_types::{Hash32, KeysetAccount, KeysetEntry, KEYSET_PROGRAM_ID};
use qbind_wire::error::WireError;
use qbind_wire::io::WireEncode;
use qbind_wire::keyset::{
    CreateKeysetCall, CreateKeysetLimits, CreateKeysetParseError, WireKeyEntry,
};
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub(crate) type Model<'a> = NativeKeysetCreateModel<'a, 2, 4, 4>;
pub(crate) const AUTH: [u8; 32] = [1; 32];
pub(crate) const TARGET: [u8; 32] = [2; 32];
const UNRELATED: [u8; 32] = [3; 32];

#[derive(Default)]
struct Counts {
    verify: AtomicUsize,
    descriptors: AtomicUsize,
    lookups: AtomicUsize,
    injection: AtomicUsize,
}
struct Suite(Arc<Counts>);
impl SignatureSuite for Suite {
    fn suite_id(&self) -> u8 {
        100
    }
    fn public_key_len(&self) -> usize {
        1312
    }
    fn signature_len(&self) -> usize {
        2420
    }
    fn canonical_key_descriptor<'a>(
        &self,
        key: &'a [u8],
    ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
        let prior = self.0.descriptors.fetch_add(1, Ordering::SeqCst);
        if prior > 0 {
            match self.0.injection.load(Ordering::SeqCst) {
                3 => return Err(KeyDescriptorError::Unsupported),
                4 => panic!("explicit synthetic create semantic provider unwind"),
                _ => {}
            }
        }
        MlDsa44SignatureSuite::new(100).canonical_key_descriptor(key)
    }
    fn verify(&self, key: &[u8], digest: &Hash32, sig: &[u8]) -> Result<(), CryptoError> {
        self.0.verify.fetch_add(1, Ordering::SeqCst);
        match self.0.injection.load(Ordering::SeqCst) {
            1 => return Err(CryptoError::InvalidSignature),
            2 => panic!("explicit synthetic provider unwind"),
            _ => {}
        }
        MlDsa44SignatureSuite::new(100).verify(key, digest, sig)
    }
}
pub(crate) struct Provider {
    inner: StaticCryptoProvider,
    counts: Arc<Counts>,
}
impl Provider {
    fn new() -> Self {
        let counts = Arc::new(Counts::default());
        Self {
            inner: StaticCryptoProvider::new()
                .with_signature_suite(Arc::new(Suite(counts.clone()))),
            counts,
        }
    }
    pub(crate) fn work(&self) -> (usize, usize, usize) {
        (
            self.counts.lookups.load(Ordering::SeqCst),
            self.counts.descriptors.load(Ordering::SeqCst),
            self.counts.verify.load(Ordering::SeqCst),
        )
    }
}
impl CryptoProvider for Provider {
    fn signature_suite(&self, id: u8) -> Option<&dyn SignatureSuite> {
        self.counts.lookups.fetch_add(1, Ordering::SeqCst);
        self.inner.signature_suite(id)
    }
    fn kem_suite(&self, id: u8) -> Option<&dyn KemSuite> {
        self.inner.kem_suite(id)
    }
    fn aead_suite(&self, id: u8) -> Option<&dyn AeadSuite> {
        self.inner.aead_suite(id)
    }
}

pub(crate) fn binding() -> FixtureBinding {
    FixtureBinding {
        chain_id: 1,
        execution_pre_state: [9; 32],
        provider_identity: [8; 32],
        policy: PrototypePolicy {
            identity: [7; 32],
            version: 1,
            limits: NativeTransactionProofLimits {
                max_required_signer_indices: 2,
                max_keyset_account_count: 2,
                max_authentication_proof_count: 4,
                max_signature_bytes: 2420,
                max_aggregate_signature_bytes: 9680,
                stored_keyset: StoredKeysetLimits {
                    max_encoded_bytes: 4096,
                    max_entries: 4,
                    max_key_bytes: 1312,
                    max_total_key_bytes: 5248,
                },
                max_algorithm_parameter_identifier_bytes: 128,
            },
        },
    }
}
pub(crate) fn config() -> KeysetCreateFixtureConfig {
    KeysetCreateFixtureConfig {
        preparation: KeysetCreatePreparationLimits {
            create_keyset: CreateKeysetLimits {
                max_encoded_bytes: 4096,
                max_entries: 4,
                max_key_bytes: 1312,
                max_total_key_bytes: 5248,
            },
            max_stored_data_bytes: 1330,
            max_distinct_key_proofs: 4,
            max_algorithm_parameter_identifier_bytes: 128,
        },
        staging: FixtureStageLimits {
            max_operations: 1,
            max_data_len: 1330,
            max_account_capacity: 4096,
            max_aggregate_capacity: 4096,
        },
    }
}
pub(crate) fn selection(p: &Provider) -> KeysetCreateFixtureSelection<'_> {
    KeysetCreateFixtureSelection::new_for_fixture(p, binding(), FixtureProfileStatus::Active)
}
fn stored(id: [u8; 32], version: u8, key: &[u8]) -> Account {
    let mut data = Vec::new();
    KeysetAccount {
        version,
        reserved0: [0; 3],
        threshold: 1,
        entry_count: 1,
        reserved1: [0; 4],
        entries: vec![KeysetEntry {
            suite_id: 100,
            weight: 1,
            reserved0: [0],
            pubkey_len: 1312,
            pubkey_bytes: key.to_vec(),
        }],
    }
    .encode_state(&mut data);
    Account::new(id, KEYSET_PROGRAM_ID, 0, data)
}
fn bytes(tx: &Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    tx.encode(&mut bytes);
    bytes
}

pub(crate) struct Fixture {
    pub(crate) store: InMemoryAccountStore,
    pub(crate) tx: Transaction,
    pub(crate) provider: Provider,
    pub(crate) expected: Account,
    before: [Account; 2],
    secret: Vec<u8>,
    new_secret: Vec<u8>,
}
impl Fixture {
    pub(crate) fn new() -> Self {
        let (key, secret) = MlDsa44Backend::generate_keypair().unwrap();
        let (new_key, new_secret) = MlDsa44Backend::generate_keypair().unwrap();
        let mut unrelated = Account::new(UNRELATED, [5; 32], 99, vec![7; 3]);
        unrelated.header.rent_epoch = 42;
        unrelated.header.reserved = [8; 8];
        unrelated.header.is_executable = true;
        let before = [stored(AUTH, 1, &key), unrelated];
        let mut store = InMemoryAccountStore::new();
        for account in &before {
            store.put(account.clone()).unwrap();
        }
        let mut call_data = Vec::new();
        CreateKeysetCall {
            version: 1,
            target_id: TARGET,
            threshold: 1,
            entries: vec![WireKeyEntry {
                suite_id: 100,
                weight: 1,
                pubkey_bytes: new_key.clone(),
            }],
        }
        .encode(&mut call_data);
        call_data[38..42].copy_from_slice(&[9; 4]);
        let tx = Transaction {
            version: 1,
            chain_id: 1,
            payer: [6; 32],
            nonce: 7,
            fee_limit: 10,
            accounts: vec![TxAccountMeta {
                account_id: AUTH,
                flags: 1,
                access_hint: 0,
                reserved0: [0; 2],
            }],
            program_id: KEYSET_PROGRAM_ID,
            call_data,
            auths: vec![],
        };
        let mut f = Self {
            store,
            tx,
            provider: Provider::new(),
            expected: stored(TARGET, 1, &new_key),
            before,
            secret,
            new_secret,
        };
        f.resign(false);
        f
    }
    pub(crate) fn resign(&mut self, new_key: bool) {
        let digest = try_tx_digest_streaming(&self.tx).unwrap();
        self.tx.auths = vec![TxAuth {
            account_index: 0,
            suite_id: 100,
            reserved: 0,
            signature: ml_dsa_44_sign_digest(
                if new_key {
                    &self.new_secret
                } else {
                    &self.secret
                },
                &digest,
            )
            .unwrap(),
        }];
    }
    pub(crate) fn begin(&mut self) -> Result<Model<'_>, KeysetCreateModelError> {
        Model::begin_for_fixture(
            &mut self.store,
            &self.tx,
            Some(selection(&self.provider)),
            Some(binding()),
            config(),
        )
    }
    pub(crate) fn preserved(&self) {
        for account in &self.before {
            assert_eq!(self.store.get(&account.id), Some(account.clone()));
        }
    }
    fn refused(&mut self) -> KeysetCreateModelError {
        match self.begin() {
            Ok(_) => panic!("expected construction refusal"),
            Err(error) => error,
        }
    }
}

#[test]
fn genuine_success_complete_account_and_transaction() {
    let mut f = Fixture::new();
    assert_ne!(AUTH, TARGET);
    assert!(f.store.get(&TARGET).is_none());
    let original = bytes(&f.tx);
    let summary = f.begin().unwrap().publish_for_fixture().unwrap();
    assert_eq!(
        (
            summary.operations,
            summary.creates,
            summary.replaces,
            summary.deletes
        ),
        (1, 1, 0, 0)
    );
    assert_eq!(f.store.get(&TARGET), Some(f.expected.clone()));
    assert_eq!(bytes(&f.tx), original);
    f.preserved();
    let (lookups, descriptors, verifies) = f.provider.work();
    assert!(lookups > 0 && descriptors >= 2);
    assert_eq!(verifies, 1);
}

#[test]
fn existing_target_preserves_complete_nondefault_account() {
    let mut f = Fixture::new();
    let mut original = Account::new(TARGET, [77; 32], 987, vec![88; 17]);
    original.header.is_executable = true;
    original.header.rent_epoch = 654;
    original.header.reserved = [33; 8];
    f.store.put(original.clone()).unwrap();
    let tx_bytes = bytes(&f.tx);
    assert_eq!(
        f.begin().unwrap().publish_for_fixture(),
        Err(FixtureStageRefusal::CreateExisting)
    );
    assert_eq!(f.store.get(&TARGET), Some(original));
    assert_eq!(bytes(&f.tx), tx_bytes);
    f.preserved();
}

#[test]
fn early_program_and_configuration_have_zero_provider_work() {
    let mut f = Fixture::new();
    f.tx.program_id = [0; 32];
    assert_eq!(f.refused(), KeysetCreateModelError::WrongProgram);
    f.tx.program_id = KEYSET_PROGRAM_ID;
    for case in 0..5 {
        let mut c = config();
        match case {
            0 => c.preparation.create_keyset.max_entries = 5,
            1 => c.staging.max_operations = 0,
            2 => c.staging.max_operations = 2,
            3 => c.preparation.max_stored_data_bytes = 1331,
            _ => c.staging.max_account_capacity = 4097,
        }
        assert!(matches!(
            Model::begin_for_fixture(
                &mut f.store,
                &f.tx,
                Some(selection(&f.provider)),
                Some(binding()),
                c
            ),
            Err(KeysetCreateModelError::Configuration)
        ));
    }
    assert_eq!(f.provider.work(), (0, 0, 0));
    f.preserved();
    assert!(f.store.get(&TARGET).is_none());
}

#[test]
fn native_selection_distinctions_before_external_work() {
    use NativeAdmissionContextError as E;
    let mut f = Fixture::new();
    for (selected_present, requested_present, status, alteration, expected) in [
        (
            true,
            false,
            FixtureProfileStatus::Active,
            0,
            E::MissingBinding,
        ),
        (
            false,
            true,
            FixtureProfileStatus::Active,
            0,
            E::UnavailableFixture,
        ),
        (
            true,
            true,
            FixtureProfileStatus::Unavailable,
            0,
            E::UnavailableSelection,
        ),
        (
            true,
            true,
            FixtureProfileStatus::Inactive,
            0,
            E::InactiveProfile,
        ),
        (
            true,
            true,
            FixtureProfileStatus::Active,
            1,
            E::ProviderMismatch,
        ),
        (
            true,
            true,
            FixtureProfileStatus::Active,
            2,
            E::ExecutionPreStateMismatch,
        ),
        (
            true,
            true,
            FixtureProfileStatus::Active,
            3,
            E::ProfileMismatch,
        ),
        (
            true,
            true,
            FixtureProfileStatus::Active,
            4,
            E::GroupWorkspaceUnsupported,
        ),
        (
            true,
            true,
            FixtureProfileStatus::Active,
            5,
            E::ProofWorkspaceUnsupported,
        ),
        (
            true,
            true,
            FixtureProfileStatus::Active,
            6,
            E::EntryWorkspaceUnsupported,
        ),
    ] {
        let mut selected = binding();
        let mut requested = binding();
        match alteration {
            1 => requested.provider_identity = [0; 32],
            2 => requested.execution_pre_state = [0; 32],
            3 => requested.policy.version += 1,
            4 => {
                selected.policy.limits.max_keyset_account_count = 3;
                requested = selected;
            }
            5 => {
                selected.policy.limits.max_authentication_proof_count = 5;
                requested = selected;
            }
            6 => {
                selected.policy.limits.stored_keyset.max_entries = 5;
                requested = selected;
            }
            _ => {}
        }
        assert!(matches!(
            Model::begin_for_fixture(&mut f.store, &f.tx,
                selected_present.then(|| KeysetCreateFixtureSelection::new_for_fixture(&f.provider, selected, status)),
                requested_present.then_some(requested), config()),
            Err(KeysetCreateModelError::Admission(FixtureBeginError::Context(e))) if e == expected
        ));
    }
    assert_eq!(f.provider.work(), (0, 0, 0));
    f.preserved();
}

#[test]
fn genuine_negative_proofs_auth_vectors_and_no_bootstrap() {
    let mut f = Fixture::new();
    f.begin().unwrap().cancel();
    let digest = try_tx_digest_streaming(&f.tx).unwrap();
    f.tx.auths[0].signature[10] ^= 1;
    assert_eq!(digest, try_tx_digest_streaming(&f.tx).unwrap());
    assert_eq!(
        f.refused(),
        KeysetCreateModelError::Admission(FixtureBeginError::Proof(
            NativeTransactionProofError::KeysetProof(KeysetProofEvaluationError::InvalidProof)
        ))
    );
    f.tx.auths.clear();
    assert_eq!(digest, try_tx_digest_streaming(&f.tx).unwrap());
    assert_eq!(
        f.refused(),
        KeysetCreateModelError::Admission(FixtureBeginError::Proof(
            NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::EmptyAuths
            )
        ))
    );
    f.tx.accounts.push(f.tx.accounts[0].clone());
    f.resign(false);
    assert_eq!(
        f.refused(),
        KeysetCreateModelError::Admission(FixtureBeginError::Proof(
            NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::MissingRequiredSignerAuth
            )
        ))
    );
    f.tx.accounts.pop();
    f.resign(false);
    let mut extra = f.tx.auths[0].clone();
    extra.signature[20] ^= 1;
    f.tx.auths.push(extra);
    let before = f.provider.work().2;
    assert_eq!(
        f.refused(),
        KeysetCreateModelError::Admission(FixtureBeginError::Proof(
            NativeTransactionProofError::KeysetProof(KeysetProofEvaluationError::InvalidProof)
        ))
    );
    assert_eq!(f.provider.work().2 - before, 2);
    f.tx.accounts[0].account_id = TARGET;
    f.resign(true);
    assert_eq!(
        f.refused(),
        KeysetCreateModelError::Admission(FixtureBeginError::Proof(
            NativeTransactionProofError::AccountRead(KeysetAccountReadError::MissingAccount)
        ))
    );
    f.preserved();
    assert!(f.store.get(&TARGET).is_none());
}

#[test]
fn actual_altered_body_signed_preparation_refusals() {
    for case in 0..4 {
        let mut f = Fixture::new();
        match case {
            0 => f.tx.call_data[0] = 0,
            1 => f.tx.call_data.push(0),
            2 => f.tx.call_data[34..36].copy_from_slice(&0u16.to_le_bytes()),
            _ => {}
        }
        f.resign(false);
        let original = bytes(&f.tx);
        let mut c = config();
        if case == 3 {
            c.preparation.max_stored_data_bytes = 1329;
        }
        let error = match Model::begin_for_fixture(
            &mut f.store,
            &f.tx,
            Some(selection(&f.provider)),
            Some(binding()),
            c,
        ) {
            Ok(_) => panic!("expected preparer refusal"),
            Err(e) => e,
        };
        match case {
            0 | 1 => assert_eq!(
                error,
                KeysetCreateModelError::Preparation(KeysetCreatePreparationError::Parse(
                    CreateKeysetParseError::Malformed(WireError::InvalidValue(if case == 0 {
                        "unexpected op_code for CreateKeysetCall"
                    } else {
                        "trailing create keyset bytes"
                    }))
                ))
            ),
            2 => assert_eq!(
                error,
                KeysetCreateModelError::Preparation(KeysetCreatePreparationError::Semantics(
                    KeysetSemanticAnalysisError::ZeroThreshold
                ))
            ),
            _ => assert_eq!(
                error,
                KeysetCreateModelError::Preparation(
                    KeysetCreatePreparationError::StoredDataBytesLimit
                )
            ),
        }
        assert_eq!(f.provider.work().2, 1, "genuine proof reached preparation");
        assert_eq!(bytes(&f.tx), original);
        f.preserved();
        assert!(f.store.get(&TARGET).is_none());
    }
}

#[test]
fn lifecycle_synthetic_failure_and_unwind_fresh_retry() {
    let mut f = Fixture::new();
    f.begin().unwrap().cancel();
    drop(f.begin().unwrap());
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _model = f.begin().unwrap();
        panic!("caller prepublication unwind");
    }))
    .is_err());
    for injection in [1, 2] {
        f.provider
            .counts
            .injection
            .store(injection, Ordering::SeqCst);
        if injection == 1 {
            assert!(matches!(
                f.refused(),
                KeysetCreateModelError::Admission(FixtureBeginError::Proof(_))
            ));
        } else {
            assert!(catch_unwind(AssertUnwindSafe(|| {
                let _ = f.begin();
            }))
            .is_err());
        }
        f.preserved();
        assert!(f.store.get(&TARGET).is_none());
    }
    f.provider.counts.injection.store(0, Ordering::SeqCst);
    let work = f.provider.work();
    f.begin().unwrap().publish_for_fixture().unwrap();
    assert!(f.provider.work().1 > work.1 && f.provider.work().2 > work.2);
    assert_eq!(f.store.get(&TARGET), Some(f.expected.clone()));
    f.preserved();
}

#[test]
fn synthetic_preparation_provider_failure_and_unwind_after_genuine_proof() {
    for injection in [3, 4] {
        let mut f = Fixture::new();
        f.provider
            .counts
            .injection
            .store(injection, Ordering::SeqCst);
        if injection == 3 {
            assert_eq!(
                f.refused(),
                KeysetCreateModelError::Preparation(KeysetCreatePreparationError::Semantics(
                    KeysetSemanticAnalysisError::DescriptorUnsupported
                ))
            );
        } else {
            assert!(catch_unwind(AssertUnwindSafe(|| {
                let _ = f.begin();
            }))
            .is_err());
        }
        assert_eq!(f.provider.work().2, 1);
        f.preserved();
        assert!(f.store.get(&TARGET).is_none());
        f.provider.counts.injection.store(0, Ordering::SeqCst);
        f.begin().unwrap().publish_for_fixture().unwrap();
        assert_eq!(f.store.get(&TARGET), Some(f.expected.clone()));
        f.preserved();
    }
}

#[test]
fn sequential_genuine_new_keyset_and_later_refusal_preserve_success() {
    let mut f = Fixture::new();
    f.begin().unwrap().publish_for_fixture().unwrap();
    assert_eq!(
        f.begin().unwrap().publish_for_fixture(),
        Err(FixtureStageRefusal::CreateExisting)
    );
    f.begin().unwrap().cancel();
    assert_eq!(f.store.get(&TARGET), Some(f.expected.clone()));
    f.tx.accounts[0].account_id = TARGET;
    f.tx.call_data[2..34].copy_from_slice(&[4; 32]);
    f.resign(true);
    let mut position = binding();
    position.execution_pre_state = [10; 32]; // Trusted label, not production freshness.
    let work = f.provider.work().2;
    Model::begin_for_fixture(
        &mut f.store,
        &f.tx,
        Some(KeysetCreateFixtureSelection::new_for_fixture(
            &f.provider,
            position,
            FixtureProfileStatus::Active,
        )),
        Some(position),
        config(),
    )
    .unwrap()
    .cancel();
    assert_eq!(f.provider.work().2, work + 1);
    assert!(f.store.get(&[4; 32]).is_none());
    assert_eq!(f.store.get(&TARGET), Some(f.expected.clone()));
    f.preserved();
}

#[test]
fn compiler_measured_fixed_sizes() {
    use std::mem::size_of;
    println!(
        "wrapper={} config={} selection={} error={} summary={}",
        size_of::<Model<'_>>(),
        size_of::<KeysetCreateFixtureConfig>(),
        size_of::<KeysetCreateFixtureSelection<'_>>(),
        size_of::<KeysetCreateModelError>(),
        size_of::<qbind_ledger::native_staged_effects::FixturePublicationSummary>()
    );
    assert!(size_of::<KeysetCreateModelError>() <= 128);
}
