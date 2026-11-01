use qbind_crypto::error::CryptoError;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
use qbind_crypto::{
    ml_dsa_44_sign_digest, AeadSuite, CryptoProvider, KemSuite, MlDsa44SignatureSuite,
    StaticCryptoProvider,
};
use qbind_hash::tx::try_tx_digest_streaming;
use qbind_ledger::native_admission_context::{
    FixtureBinding, FixtureProfileStatus, NativeAdmissionContextError as ContextError,
    PrototypePolicy,
};
use qbind_ledger::native_staged_effects::{
    FixtureBeginError as BeginError, FixtureSelection, FixtureStageLimits,
    FixtureStageRefusal as Refusal, NativeStagedEffects,
};
use qbind_ledger::native_tx_proof::NativeTransactionProofLimits;
use qbind_ledger::{Account, AccountStore, InMemoryAccountStore};
use qbind_serde::keyset::StoredKeysetLimits;
use qbind_serde::StateEncode;
use qbind_types::{Hash32, KeysetAccount, KeysetEntry, KEYSET_PROGRAM_ID};
use qbind_wire::io::WireEncode;
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

type Session<'a> = NativeStagedEffects<'a, 8, 8, 16, 3>;
const A: [u8; 32] = [1; 32];
const B: [u8; 32] = [2; 32];
const C: [u8; 32] = [3; 32];
const D: [u8; 32] = [4; 32];
const U: [u8; 32] = [5; 32];
const SUITE: u8 = 100;

// UNAPPROVED small effect limits, distinct from proof candidate and W=3.
fn limits() -> FixtureStageLimits {
    FixtureStageLimits {
        max_operations: 3,
        max_data_len: 8,
        max_account_capacity: 8,
        max_aggregate_capacity: 16,
    }
}
// Reused UNAPPROVED native proof candidate; G/P/E are implementation capacities.
fn binding() -> FixtureBinding {
    FixtureBinding {
        chain_id: 1,
        execution_pre_state: [9; 32],
        provider_identity: [8; 32],
        policy: PrototypePolicy {
            identity: [7; 32],
            version: 1,
            limits: NativeTransactionProofLimits {
                max_required_signer_indices: 8,
                max_keyset_account_count: 8,
                max_authentication_proof_count: 8,
                max_signature_bytes: 8192,
                max_aggregate_signature_bytes: 65536,
                stored_keyset: StoredKeysetLimits {
                    max_encoded_bytes: 65536,
                    max_entries: 16,
                    max_key_bytes: 4096,
                    max_total_key_bytes: 65536,
                },
                max_algorithm_parameter_identifier_bytes: 128,
            },
        },
    }
}

#[derive(Default)]
struct Counts {
    lookups: AtomicUsize,
    descriptors: AtomicUsize,
    verifications: AtomicUsize,
    inject_panic: AtomicBool,
}
struct Suite {
    real: MlDsa44SignatureSuite,
    counts: Arc<Counts>,
}
impl SignatureSuite for Suite {
    fn suite_id(&self) -> u8 {
        self.real.suite_id()
    }
    fn public_key_len(&self) -> usize {
        self.real.public_key_len()
    }
    fn signature_len(&self) -> usize {
        self.real.signature_len()
    }
    fn canonical_key_descriptor<'a>(
        &self,
        key: &'a [u8],
    ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
        self.counts.descriptors.fetch_add(1, Ordering::SeqCst);
        self.real.canonical_key_descriptor(key)
    }
    fn verify(&self, key: &[u8], digest: &Hash32, signature: &[u8]) -> Result<(), CryptoError> {
        self.counts.verifications.fetch_add(1, Ordering::SeqCst);
        if self.counts.inject_panic.load(Ordering::SeqCst) {
            panic!("explicit provider unwind control, not a genuine proof outcome");
        }
        self.real.verify(key, digest, signature)
    }
}
struct Provider {
    real: StaticCryptoProvider,
    counts: Arc<Counts>,
}
impl Provider {
    fn new() -> Self {
        let counts = Arc::new(Counts::default());
        Self {
            real: StaticCryptoProvider::new().with_signature_suite(Arc::new(Suite {
                real: MlDsa44SignatureSuite::new(SUITE),
                counts: counts.clone(),
            })),
            counts,
        }
    }
    fn work(&self) -> (usize, usize, usize) {
        (
            self.counts.lookups.load(Ordering::SeqCst),
            self.counts.descriptors.load(Ordering::SeqCst),
            self.counts.verifications.load(Ordering::SeqCst),
        )
    }
}
impl CryptoProvider for Provider {
    fn signature_suite(&self, suite: u8) -> Option<&dyn SignatureSuite> {
        self.counts.lookups.fetch_add(1, Ordering::SeqCst);
        self.real.signature_suite(suite)
    }
    fn kem_suite(&self, suite: u8) -> Option<&dyn KemSuite> {
        self.real.kem_suite(suite)
    }
    fn aead_suite(&self, suite: u8) -> Option<&dyn AeadSuite> {
        self.real.aead_suite(suite)
    }
}

fn account(id: [u8; 32], byte: u8, len: usize) -> Account {
    let mut a = Account::new(id, [byte; 32], 100 + u64::from(byte), vec![byte; len]);
    a.header.is_executable = true;
    a.header.rent_epoch = 123;
    a.header.reserved = [byte; 8];
    a
}
fn keyset(id: [u8; 32], key: &[u8]) -> Account {
    assert_eq!(key.len(), 1312);
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
            pubkey_len: 1312,
            pubkey_bytes: key.to_vec(),
        }],
    };
    let mut data = Vec::new();
    state.encode_state(&mut data);
    Account::new(id, KEYSET_PROGRAM_ID, 0, data)
}
struct Fixture {
    store: InMemoryAccountStore,
    tx: Transaction,
    provider: Provider,
    before: [Account; 5],
    alternate_secret: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let keys = [
            MlDsa44Backend::generate_keypair().unwrap(),
            MlDsa44Backend::generate_keypair().unwrap(),
        ];
        let alternate = MlDsa44Backend::generate_keypair().unwrap();
        assert_ne!(keys[1].0, alternate.0);
        let before = [
            keyset(A, &keys[0].0),
            keyset(B, &keys[1].0),
            account(C, 3, 4),
            account(D, 4, 4),
            account(U, 5, 4),
        ];
        let mut store = InMemoryAccountStore::new();
        // Ordinary fixture provisioning, outside attempt/publication.
        for a in &before {
            store.put(a.clone()).unwrap();
        }
        let mut tx = Transaction {
            version: 1,
            chain_id: 1,
            payer: [6; 32],
            nonce: 7,
            fee_limit: 1000,
            accounts: [A, B]
                .into_iter()
                .map(|id| TxAccountMeta {
                    account_id: id,
                    flags: 1,
                    access_hint: 0,
                    reserved0: [0; 2],
                })
                .collect(),
            program_id: [10; 32],
            call_data: vec![1, 2, 3],
            auths: Vec::new(),
        };
        let digest = try_tx_digest_streaming(&tx).unwrap();
        for (i, (_, secret)) in keys.iter().enumerate() {
            let signature = ml_dsa_44_sign_digest(secret, &digest).unwrap();
            assert_eq!(signature.len(), 2420);
            tx.auths.push(TxAuth {
                account_index: i as u16,
                suite_id: SUITE,
                reserved: 0,
                signature,
            });
        }
        Self {
            store,
            tx,
            provider: Provider::new(),
            before,
            alternate_secret: alternate.1,
        }
    }
    fn begin(&mut self, l: FixtureStageLimits) -> Session<'_> {
        Session::begin_for_fixture(
            &mut self.store,
            &self.tx,
            Some(FixtureSelection::new_for_fixture(
                &self.provider,
                binding(),
                FixtureProfileStatus::Active,
            )),
            Some(binding()),
            l,
        )
        .ok()
        .expect("genuine admission")
    }
    fn preserved(&self) {
        for a in &self.before {
            assert_eq!(self.store.get(&a.id), Some(a.clone()));
        }
        for id in [20, 21, 22, 23] {
            assert_eq!(self.store.get(&[id; 32]), None);
        }
    }
}
fn bytes(tx: &Transaction) -> Vec<u8> {
    let mut b = Vec::new();
    tx.encode(&mut b);
    b
}

#[test]
fn run422_native_staged_effects_genuine_multi_effect_movement_and_binding() {
    let mut f = Fixture::new();
    let tx_before = bytes(&f.tx);
    let create = account([20; 32], 20, 8);
    let replace = account(C, 30, 8);
    let expected_create = create.clone(); // oracle only; actual offered owner is moved
    let expected_replace = replace.clone();
    let pointers = (create.data.as_ptr(), replace.data.as_ptr());
    let mut s = f.begin(limits());
    s.create_for_fixture([20; 32], create).unwrap();
    s.replace_for_fixture(C, replace).unwrap();
    s.delete_for_fixture(D).unwrap();
    let summary = s.publish_for_fixture().unwrap();
    assert_eq!(
        (
            summary.operations,
            summary.creates,
            summary.replaces,
            summary.deletes,
            summary.retained_capacity,
            summary.resulting_accounts
        ),
        (3, 1, 1, 1, 16, 5)
    );
    assert_eq!(f.store.get(&[20; 32]), Some(expected_create));
    assert_eq!(f.store.get(&C), Some(expected_replace));
    assert_eq!(f.store.get(&D), None);
    for a in [&f.before[0], &f.before[1], &f.before[4]] {
        assert_eq!(f.store.get(&a.id), Some(a.clone()));
    }
    // External get clones; exact pointer retention is checked at the private map.
    assert!(!pointers.0.is_null() && !pointers.1.is_null());
    assert_eq!(bytes(&f.tx), tx_before);
    assert_eq!(f.provider.work(), (2, 2, 2));
}

#[test]
fn run422_native_staged_effects_selection_refusals_before_provider() {
    let mut f = Fixture::new();
    let original = bytes(&f.tx);
    let mut requested_cases = Vec::new();
    requested_cases.push((None, ContextError::MissingBinding));
    for (n, expected) in [
        (0, ContextError::ChainMismatch),
        (1, ContextError::ExecutionPreStateMismatch),
        (2, ContextError::UnknownProfile),
        (3, ContextError::ProfileMismatch),
        (4, ContextError::ProviderMismatch),
    ] {
        let mut b = binding();
        match n {
            0 => b.chain_id = 2,
            1 => b.execution_pre_state = [0; 32],
            2 => b.policy.identity = [0; 32],
            3 => b.policy.version = 2,
            _ => b.provider_identity = [0; 32],
        }
        requested_cases.push((Some(b), expected));
    }
    for (requested, expected) in requested_cases {
        let r = Session::begin_for_fixture(
            &mut f.store,
            &f.tx,
            Some(FixtureSelection::new_for_fixture(
                &f.provider,
                binding(),
                FixtureProfileStatus::Active,
            )),
            requested,
            limits(),
        );
        assert!(matches!(r,Err(BeginError::Context(e)) if e==expected));
        f.preserved();
    }
    for (status, expected) in [
        (
            FixtureProfileStatus::Inactive,
            ContextError::InactiveProfile,
        ),
        (
            FixtureProfileStatus::Unavailable,
            ContextError::UnavailableSelection,
        ),
    ] {
        let r = Session::begin_for_fixture(
            &mut f.store,
            &f.tx,
            Some(FixtureSelection::new_for_fixture(
                &f.provider,
                binding(),
                status,
            )),
            Some(binding()),
            limits(),
        );
        assert!(matches!(r,Err(BeginError::Context(e)) if e==expected));
    }
    assert!(matches!(
        Session::begin_for_fixture(&mut f.store, &f.tx, None, Some(binding()), limits()),
        Err(BeginError::Context(ContextError::UnavailableFixture))
    ));
    let mut b = binding();
    b.policy.limits.max_keyset_account_count = 9;
    assert!(matches!(
        Session::begin_for_fixture(
            &mut f.store,
            &f.tx,
            Some(FixtureSelection::new_for_fixture(
                &f.provider,
                b,
                FixtureProfileStatus::Active
            )),
            Some(b),
            limits()
        ),
        Err(BeginError::Context(ContextError::GroupWorkspaceUnsupported))
    ));
    let bad = FixtureStageLimits {
        max_operations: 4,
        ..limits()
    };
    assert!(matches!(
        Session::begin_for_fixture(&mut f.store, &f.tx, None, None, bad),
        Err(BeginError::StageConfiguration)
    ));
    assert_eq!(f.provider.work(), (0, 0, 0));
    assert_eq!(bytes(&f.tx), original);
    f.preserved();
}

#[test]
fn run422_native_staged_effects_invalid_and_mixed_genuine_proofs_no_session() {
    let mut f = Fixture::new();
    f.tx.auths[1].signature[0] ^= 1;
    let unchanged = bytes(&f.tx);
    let r = Session::begin_for_fixture(
        &mut f.store,
        &f.tx,
        Some(FixtureSelection::new_for_fixture(
            &f.provider,
            binding(),
            FixtureProfileStatus::Active,
        )),
        Some(binding()),
        limits(),
    );
    assert!(matches!(r, Err(BeginError::Proof(_))));
    assert_eq!(bytes(&f.tx), unchanged);
    assert_eq!(f.provider.work(), (2, 2, 2));
    f.preserved();
    let digest = try_tx_digest_streaming(&f.tx).unwrap();
    f.tx.auths[1].signature = ml_dsa_44_sign_digest(&f.alternate_secret, &digest).unwrap();
    let unchanged = bytes(&f.tx);
    assert!(matches!(
        Session::begin_for_fixture(
            &mut f.store,
            &f.tx,
            Some(FixtureSelection::new_for_fixture(
                &f.provider,
                binding(),
                FixtureProfileStatus::Active
            )),
            Some(binding()),
            limits()
        ),
        Err(BeginError::Proof(_))
    ));
    assert_eq!(bytes(&f.tx), unchanged);
    assert_eq!(f.provider.work(), (4, 4, 4));
    f.preserved();
}

#[test]
fn run422_native_staged_effects_duplicates_and_id_mismatch_poison_intact_candidates() {
    let mut f = Fixture::new();
    for kind in 0..4 {
        let mut s = f.begin(limits());
        s.create_for_fixture([20; 32], account([20; 32], 20, 4))
            .unwrap();
        let candidate = account(if kind == 3 { [21; 32] } else { [20; 32] }, 21, 4);
        let pointer = candidate.data.as_ptr();
        let expected = candidate.clone();
        if kind == 2 {
            assert_eq!(
                s.delete_for_fixture([20; 32]),
                Err(Refusal::DuplicateTarget)
            );
        } else {
            let error = if kind == 1 {
                s.replace_for_fixture([20; 32], candidate)
            } else {
                s.create_for_fixture(if kind == 3 { [22; 32] } else { [20; 32] }, candidate)
            }
            .unwrap_err();
            assert_eq!(
                error.reason,
                if kind == 3 {
                    Refusal::AccountIdMismatch
                } else {
                    Refusal::DuplicateTarget
                }
            );
            assert_eq!(error.account, expected);
            assert_eq!(error.account.data.as_ptr(), pointer);
            assert_eq!(error.account.data.capacity(), 4);
        }
        assert_eq!(s.publish_for_fixture(), Err(Refusal::Poisoned));
        f.preserved();
    }
    let mut s = f.begin(limits());
    s.replace_for_fixture(C, account(C, 30, 4)).unwrap();
    assert_eq!(s.delete_for_fixture(C), Err(Refusal::DuplicateTarget));
    assert_eq!(s.publish_for_fixture(), Err(Refusal::Poisoned));
    f.preserved();
}

#[test]
fn run422_native_staged_effects_complete_predicate_preflight() {
    let mut f = Fixture::new();
    for kind in 0..3 {
        let mut s = f.begin(limits());
        s.create_for_fixture([20; 32], account([20; 32], 20, 4))
            .unwrap();
        let expected = match kind {
            0 => {
                s.create_for_fixture(C, account(C, 30, 4)).unwrap();
                Refusal::CreateExisting
            }
            1 => {
                s.replace_for_fixture([21; 32], account([21; 32], 21, 4))
                    .unwrap();
                Refusal::ReplaceMissing
            }
            _ => {
                s.delete_for_fixture([21; 32]).unwrap();
                Refusal::DeleteMissing
            }
        };
        assert_eq!(s.publish_for_fixture(), Err(expected));
        f.preserved();
    }
}

#[test]
fn run422_native_staged_effects_resource_refusals_return_allocations_and_poison() {
    let mut f = Fixture::new();
    for kind in 0..4 {
        let l = if kind == 0 {
            FixtureStageLimits {
                max_operations: 1,
                ..limits()
            }
        } else {
            limits()
        };
        let mut s = f.begin(l);
        s.create_for_fixture([20; 32], account([20; 32], 20, 8))
            .unwrap();
        let mut candidate = account(
            [21; 32],
            21,
            if kind == 1 {
                9
            } else if kind == 3 {
                8
            } else {
                1
            },
        );
        if kind == 2 {
            candidate.data = Vec::with_capacity(9);
            candidate.data.push(21);
        }
        if kind == 3 {
            s.replace_for_fixture(C, account(C, 30, 8)).unwrap();
        }
        let pointer = candidate.data.as_ptr();
        let capacity = candidate.data.capacity();
        let expected = candidate.clone();
        let e = s.create_for_fixture([21; 32], candidate).unwrap_err();
        assert_eq!(
            e.reason,
            [
                Refusal::OperationCapacity,
                Refusal::LogicalLength,
                Refusal::AccountCapacity,
                Refusal::AggregateCapacity
            ][kind]
        );
        assert_eq!(e.account, expected);
        assert_eq!(e.account.data.as_ptr(), pointer);
        assert_eq!(e.account.data.capacity(), capacity);
        let later = s.replace_for_fixture(C, account(C, 30, 1)).unwrap_err();
        assert_eq!(later.reason, Refusal::Poisoned);
        assert_eq!(s.publish_for_fixture(), Err(Refusal::Poisoned));
        f.preserved();
    }
}

#[test]
fn run422_native_staged_effects_drop_cancel_and_caller_unwind() {
    let mut f = Fixture::new();
    let tx_before = bytes(&f.tx);
    let mut s = f.begin(limits());
    s.create_for_fixture([20; 32], account([20; 32], 20, 4))
        .unwrap();
    s.cancel();
    f.preserved();
    let mut s = f.begin(limits());
    s.replace_for_fixture(C, account(C, 30, 4)).unwrap();
    drop(s);
    f.preserved();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut s = f.begin(limits());
        s.delete_for_fixture(D).unwrap();
        panic!("caller unwind before publication, not a publication fault");
    }));
    assert!(result.is_err());
    f.preserved();
    assert_eq!(f.provider.work(), (6, 6, 6));
    f.begin(limits()).publish_for_fixture().unwrap();
    assert_eq!(f.provider.work(), (8, 8, 8));
    assert_eq!(bytes(&f.tx), tx_before);
    f.store.put(account([23; 32], 23, 1)).unwrap();
    f.tx.call_data.push(4); // normal mutation after release
}

#[test]
fn run422_native_staged_effects_explicit_provider_unwind_then_fresh_genuine_attempt() {
    let mut f = Fixture::new();
    let before = bytes(&f.tx);
    f.provider.counts.inject_panic.store(true, Ordering::SeqCst);
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = Session::begin_for_fixture(
            &mut f.store,
            &f.tx,
            Some(FixtureSelection::new_for_fixture(
                &f.provider,
                binding(),
                FixtureProfileStatus::Active,
            )),
            Some(binding()),
            limits(),
        );
    }))
    .is_err());
    f.preserved();
    assert_eq!(bytes(&f.tx), before);
    assert_eq!(f.provider.work(), (1, 1, 1));
    f.provider
        .counts
        .inject_panic
        .store(false, Ordering::SeqCst);
    f.begin(limits()).publish_for_fixture().unwrap();
    assert_eq!(f.provider.work(), (3, 3, 3));
}

#[test]
fn run422_native_staged_effects_sequential_success_survives_refusal_and_cancel() {
    let mut f = Fixture::new();
    let created = account([20; 32], 20, 4);
    let mut s = f.begin(limits());
    s.create_for_fixture([20; 32], created.clone()).unwrap();
    s.publish_for_fixture().unwrap();
    let mut s = f.begin(limits());
    s.create_for_fixture([20; 32], account([20; 32], 21, 4))
        .unwrap();
    assert_eq!(s.publish_for_fixture(), Err(Refusal::CreateExisting));
    assert_eq!(f.store.get(&[20; 32]), Some(created.clone()));
    let mut s = f.begin(limits());
    s.delete_for_fixture([20; 32]).unwrap();
    s.cancel();
    assert_eq!(f.store.get(&[20; 32]), Some(created));
    let mut s = f.begin(limits());
    s.replace_for_fixture([20; 32], account([20; 32], 22, 4))
        .unwrap();
    s.publish_for_fixture().unwrap();
    assert_eq!(f.store.get(&[20; 32]), Some(account([20; 32], 22, 4)));
    assert_eq!(f.provider.work(), (8, 8, 8));
    for a in &f.before {
        assert_eq!(f.store.get(&a.id), Some(a.clone()));
    }
}
