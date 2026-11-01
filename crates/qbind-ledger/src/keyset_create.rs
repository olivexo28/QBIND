//! Isolated preparation of owned keyset account data, with explicit bounds.
//!
//! This unused helper does not authorize creation, check target absence, access
//! a store, or establish current authority or a common state snapshot. `E` and
//! all limits are caller-selected implementation inputs, not approved policy.
//! Successful preparation allocates one destination buffer; input keys and
//! semantic descriptors stay borrowed until admission and do not escape.

use crate::keyset_validation::{analyze_create_keyset_semantics, KeysetSemanticAnalysisError};
use crate::Account;
use qbind_crypto::CryptoProvider;
use qbind_serde::io::put_bytes;
use qbind_types::KEYSET_PROGRAM_ID;
use qbind_wire::keyset::{parse_create_keyset, CreateKeysetLimits, CreateKeysetParseError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeysetCreatePreparationLimits {
    pub create_keyset: CreateKeysetLimits,
    pub max_stored_data_bytes: usize,
    pub max_distinct_key_proofs: usize,
    pub max_algorithm_parameter_identifier_bytes: usize,
}

/// Fixed-size errors; no input bytes, keys, or allocator/backend text is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeysetCreatePreparationError {
    Parse(CreateKeysetParseError),
    EntryWorkspaceCapacity,
    StoredLengthOverflow,
    StoredDataBytesLimit,
    Semantics(KeysetSemanticAnalysisError),
    DestinationReservation,
    EncodingLengthMismatch,
}

fn stored_encoding_length(
    entry_count: usize,
    total_key_bytes: usize,
) -> Result<usize, KeysetCreatePreparationError> {
    entry_count
        .checked_mul(6)
        .and_then(|n| n.checked_add(12))
        .and_then(|n| n.checked_add(total_key_bytes))
        .ok_or(KeysetCreatePreparationError::StoredLengthOverflow)
}

fn reserve_destination(
    data: &mut Vec<u8>,
    length: usize,
) -> Result<(), KeysetCreatePreparationError> {
    #[cfg(test)]
    observation::before_reserve(length)?;
    data.try_reserve_exact(length)
        .map_err(|_| KeysetCreatePreparationError::DestinationReservation)?;
    #[cfg(test)]
    observation::destination(data);
    Ok(())
}

fn append_bounded(
    data: &mut Vec<u8>,
    bytes: &[u8],
    length: usize,
) -> Result<(), KeysetCreatePreparationError> {
    let end = data
        .len()
        .checked_add(bytes.len())
        .ok_or(KeysetCreatePreparationError::EncodingLengthMismatch)?;
    if end > length || end > data.capacity() {
        return Err(KeysetCreatePreparationError::EncodingLengthMismatch);
    }
    put_bytes(data, bytes);
    #[cfg(test)]
    observation::destination(data);
    Ok(())
}

/// Completely parse, size and semantically admit a create call before reserving
/// or copying output. The stored transformation matches KeysetProgram for
/// accepted inputs, including retaining version/order/duplicates/aliases while
/// zeroing stored reserved fields. No version or reserved-input policy is added.
///
/// Parser, sizing, semantics and encoding each traverse the entries once.
/// Semantics uses fixed E-sized identity workspace and scalar threshold scratch,
/// exact descriptor comparisons and weight ordering; provider/crypto internals
/// are outside these bounds. After semantics returns, its workspace is gone
/// before destination reservation. Logical length and requested reservation do
/// not bound Vec capacity, allocator overhead, compiler frames or RSS.
pub fn prepare_keyset_account_bounded<const E: usize>(
    call_data: &[u8],
    provider: &dyn CryptoProvider,
    limits: KeysetCreatePreparationLimits,
) -> Result<Account, KeysetCreatePreparationError> {
    let call = parse_create_keyset(call_data, limits.create_keyset)
        .map_err(KeysetCreatePreparationError::Parse)?;
    if usize::from(call.entry_count()) > E {
        return Err(KeysetCreatePreparationError::EntryWorkspaceCapacity);
    }
    let total_key_bytes = call.entries().try_fold(0usize, |total, entry| {
        total
            .checked_add(entry.pubkey_bytes.len())
            .ok_or(KeysetCreatePreparationError::StoredLengthOverflow)
    })?;
    let length = stored_encoding_length(usize::from(call.entry_count()), total_key_bytes)?;
    if length > limits.max_stored_data_bytes {
        return Err(KeysetCreatePreparationError::StoredDataBytesLimit);
    }
    analyze_create_keyset_semantics::<E>(
        call,
        provider,
        limits.max_distinct_key_proofs,
        limits.max_algorithm_parameter_identifier_bytes,
    )
    .map_err(KeysetCreatePreparationError::Semantics)?;

    let mut data = Vec::new();
    reserve_destination(&mut data, length)?;
    append_bounded(&mut data, &[call.version(), 0, 0, 0], length)?;
    append_bounded(&mut data, &call.threshold().to_le_bytes(), length)?;
    append_bounded(&mut data, &call.entry_count().to_le_bytes(), length)?;
    append_bounded(&mut data, &[0; 4], length)?;
    for entry in call.entries() {
        append_bounded(&mut data, &[entry.suite_id], length)?;
        append_bounded(&mut data, &entry.weight.to_le_bytes(), length)?;
        append_bounded(&mut data, &[0], length)?;
        append_bounded(&mut data, &entry.pubkey_len.to_le_bytes(), length)?;
        append_bounded(&mut data, entry.pubkey_bytes, length)?;
    }
    if data.len() != length {
        return Err(KeysetCreatePreparationError::EncodingLengthMismatch);
    }
    Ok(Account::new(call.target_id(), KEYSET_PROGRAM_ID, 0, data))
}

#[cfg(test)]
mod observation {
    use super::KeysetCreatePreparationError;
    use std::cell::RefCell;

    #[derive(Default, Debug)]
    pub(super) struct Observation {
        pub requests: Vec<usize>,
        pub snapshots: Vec<(usize, usize, usize)>,
        pub refuse_next: bool,
    }

    thread_local! {
        static ACTIVE: RefCell<Option<Observation>> = const { RefCell::new(None) };
    }

    pub(super) struct Guard(Option<Observation>);

    impl Guard {
        pub fn new(refuse_next: bool) -> Self {
            Self(ACTIVE.with(|active| {
                active.replace(Some(Observation {
                    refuse_next,
                    ..Observation::default()
                }))
            }))
        }

        pub fn take(&self) -> Observation {
            ACTIVE.with(|active| {
                let mut active = active.borrow_mut();
                std::mem::take(active.as_mut().expect("active observer guard"))
            })
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE.with(|active| {
                active.replace(self.0.take());
            });
        }
    }

    pub(super) fn before_reserve(length: usize) -> Result<(), KeysetCreatePreparationError> {
        ACTIVE.with(|active| {
            if let Some(observation) = active.borrow_mut().as_mut() {
                observation.requests.push(length);
                if std::mem::take(&mut observation.refuse_next) {
                    return Err(KeysetCreatePreparationError::DestinationReservation);
                }
            }
            Ok(())
        })
    }

    pub(super) fn destination(data: &Vec<u8>) {
        ACTIVE.with(|active| {
            if let Some(observation) = active.borrow_mut().as_mut() {
                observation
                    .snapshots
                    .push((data.len(), data.capacity(), data.as_ptr() as usize));
            }
        });
    }
}

#[cfg(test)]
mod run422_keyset_create_preparation_tests {
    use super::*;
    use crate::keyset_validation::Workspace;
    use crate::native_tx_proof::{
        evaluate_native_transaction_proofs, NativeTransactionProofError,
        NativeTransactionProofLimits, NativeTransactionProofSummary,
    };
    use crate::{AccountHeader, AccountStore, InMemoryAccountStore};
    use qbind_crypto::error::CryptoError;
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
    use qbind_crypto::{AeadSuite, KemSuite, MlDsa44SignatureSuite, StaticCryptoProvider};
    use qbind_hash::tx::try_tx_digest_streaming;
    use qbind_serde::keyset::{parse_stored_keyset, StoredKeysetLimits};
    use qbind_serde::StateEncode;
    use qbind_types::{Hash32, KeysetAccount, KeysetEntry};
    use qbind_wire::error::WireError;
    use qbind_wire::io::WireEncode;
    use qbind_wire::keyset::{CreateKeysetCall, CreateKeysetView, WireKeyEntry};
    use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Default)]
    struct SuiteCalls {
        descriptors: AtomicUsize,
        verifications: AtomicUsize,
    }

    #[derive(Clone, Copy)]
    enum DescriptorMode {
        Genuine,
        Unsupported,
        NonCanonical,
    }

    struct CountedSuite {
        inner: MlDsa44SignatureSuite,
        calls: Arc<SuiteCalls>,
        mode: DescriptorMode,
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
        fn verify(&self, key: &[u8], digest: &Hash32, signature: &[u8]) -> Result<(), CryptoError> {
            self.calls
                .verifications
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.verify(key, digest, signature)
        }
        fn canonical_key_descriptor<'a>(
            &self,
            key: &'a [u8],
        ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
            self.calls
                .descriptors
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match self.mode {
                DescriptorMode::Genuine => self.inner.canonical_key_descriptor(key),
                DescriptorMode::Unsupported => Err(KeyDescriptorError::Unsupported),
                DescriptorMode::NonCanonical => Err(KeyDescriptorError::NonCanonical),
            }
        }
    }

    struct Provider {
        inner: StaticCryptoProvider,
        lookups: AtomicUsize,
        calls: Arc<SuiteCalls>,
    }

    impl Provider {
        fn new(mode: DescriptorMode) -> Self {
            let calls = Arc::new(SuiteCalls::default());
            let inner = [100, 101]
                .into_iter()
                .fold(StaticCryptoProvider::new(), |provider, id| {
                    provider.with_signature_suite(Arc::new(CountedSuite {
                        inner: MlDsa44SignatureSuite::new(id),
                        calls: Arc::clone(&calls),
                        mode,
                    }))
                });
            Self {
                inner,
                lookups: AtomicUsize::new(0),
                calls,
            }
        }
        fn counts(&self) -> (usize, usize, usize) {
            (
                self.lookups.load(Ordering::SeqCst),
                self.calls
                    .descriptors
                    .load(std::sync::atomic::Ordering::SeqCst),
                self.calls
                    .verifications
                    .load(std::sync::atomic::Ordering::SeqCst),
            )
        }
    }

    impl CryptoProvider for Provider {
        fn signature_suite(&self, id: u8) -> Option<&dyn SignatureSuite> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            self.inner.signature_suite(id)
        }
        fn kem_suite(&self, id: u8) -> Option<&dyn KemSuite> {
            self.inner.kem_suite(id)
        }
        fn aead_suite(&self, id: u8) -> Option<&dyn AeadSuite> {
            self.inner.aead_suite(id)
        }
    }

    fn entry(suite_id: u8, weight: u16, key: &[u8]) -> WireKeyEntry {
        WireKeyEntry {
            suite_id,
            weight,
            pubkey_bytes: key.to_vec(),
        }
    }

    fn call(threshold: u16, entries: Vec<WireKeyEntry>) -> CreateKeysetCall {
        CreateKeysetCall {
            version: 0x91,
            target_id: [0x42; 32],
            threshold,
            entries,
        }
    }

    fn bytes(call: &CreateKeysetCall) -> Vec<u8> {
        let mut input = Vec::new();
        call.encode(&mut input);
        input[38..42].copy_from_slice(&[0xA1, 0xA2, 0xA3, 0xA4]);
        input
    }

    fn exact(call: &CreateKeysetCall) -> KeysetCreatePreparationLimits {
        let key_bytes: usize = call
            .entries
            .iter()
            .map(|entry| entry.pubkey_bytes.len())
            .sum();
        KeysetCreatePreparationLimits {
            create_keyset: CreateKeysetLimits {
                max_encoded_bytes: 42 + 5 * call.entries.len() + key_bytes,
                max_entries: call.entries.len(),
                max_key_bytes: call
                    .entries
                    .iter()
                    .map(|entry| entry.pubkey_bytes.len())
                    .max()
                    .unwrap_or(0),
                max_total_key_bytes: key_bytes,
            },
            max_stored_data_bytes: 12 + 6 * call.entries.len() + key_bytes,
            max_distinct_key_proofs: call.entries.len(),
            max_algorithm_parameter_identifier_bytes: 16,
        }
    }

    fn expected(call: &CreateKeysetCall) -> Account {
        let state = KeysetAccount {
            version: call.version,
            reserved0: [0; 3],
            threshold: call.threshold,
            entry_count: u16::try_from(call.entries.len()).unwrap(),
            reserved1: [0; 4],
            entries: call
                .entries
                .iter()
                .map(|entry| KeysetEntry {
                    suite_id: entry.suite_id,
                    weight: entry.weight,
                    reserved0: [0],
                    pubkey_len: u16::try_from(entry.pubkey_bytes.len()).unwrap(),
                    pubkey_bytes: entry.pubkey_bytes.clone(),
                })
                .collect(),
        };
        let mut data = Vec::new();
        state.encode_state(&mut data);
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

    fn prepare<const E: usize>(
        input: &[u8],
        provider: &Provider,
        limits: KeysetCreatePreparationLimits,
    ) -> (
        Result<Account, KeysetCreatePreparationError>,
        observation::Observation,
    ) {
        let original = input.to_vec();
        let guard = observation::Guard::new(false);
        let result = prepare_keyset_account_bounded::<E>(input, provider, limits);
        let observed = guard.take();
        assert_eq!(input, original);
        assert_eq!(
            provider.counts().2,
            0,
            "preparation never verifies signatures"
        );
        if let Ok(account) = &result {
            assert_success_observation(&observed, account);
        } else {
            assert!(observed.requests.is_empty());
            assert!(observed.snapshots.is_empty());
        }
        (result, observed)
    }

    fn assert_success_observation(observed: &observation::Observation, account: &Account) {
        assert_eq!(observed.requests, [account.data.len()]);
        assert_eq!(
            observed.snapshots.len(),
            5 + 5 * usize::from(u16::from_le_bytes([account.data[6], account.data[7]]))
        );
        let &(initial_len, capacity, backing) = observed.snapshots.first().unwrap();
        assert_eq!(initial_len, 0);
        assert!(capacity >= account.data.len());
        for &(len, cap, ptr) in &observed.snapshots {
            assert!(len <= account.data.len());
            assert_eq!(cap, capacity);
            assert_eq!(ptr, backing);
        }
        assert_eq!(account.data.capacity(), capacity);
        assert_eq!(account.data.as_ptr() as usize, backing);
        assert_eq!(observed.snapshots.last().unwrap().0, account.data.len());
    }

    #[test]
    fn run422_keyset_create_preparation_genuine_encoding_ownership_and_aliases() {
        let (key_a, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b, _) = MlDsa44Backend::generate_keypair().unwrap();
        let call = call(
            5,
            vec![
                entry(100, 3, &key_a),
                entry(101, 3, &key_a),
                entry(100, 2, &key_b),
                entry(100, 3, &key_a),
            ],
        );
        let expected = expected(&call);
        let mut limits = exact(&call);
        limits.max_distinct_key_proofs = 2;
        let provider = Provider::new(DescriptorMode::Genuine);
        let account = {
            let mut input = bytes(&call);
            let view = parse_create_keyset(&input, limits.create_keyset).unwrap();
            assert_eq!(view.version(), 0x91);
            assert_eq!(view.reserved0(), [0xA1, 0xA2, 0xA3, 0xA4]);
            let (result, observed) = prepare::<4>(&input, &provider, limits);
            eprintln!(
                "destination logical={} requested={} observed_capacity={} stable_snapshots={}",
                expected.data.len(),
                observed.requests[0],
                observed.snapshots[0].1,
                observed.snapshots.len()
            );
            let account = result.unwrap();
            assert_eq!(provider.counts(), (4, 4, 0));
            input.fill(0);
            assert_eq!(account, expected);
            account
        };
        drop(provider);
        assert_eq!(account, expected);
        assert_eq!(account.data.len(), limits.max_stored_data_bytes);
        let parsed = parse_stored_keyset(
            &account.data,
            StoredKeysetLimits {
                max_encoded_bytes: account.data.len(),
                max_entries: 4,
                max_key_bytes: key_a.len(),
                max_total_key_bytes: 3 * key_a.len() + key_b.len(),
            },
        )
        .unwrap();
        assert_eq!(parsed.version(), 0x91);
        assert_eq!(parsed.reserved0(), [0; 3]);
        assert_eq!(parsed.reserved1(), [0; 4]);
        assert_eq!(parsed.threshold(), 5);
        for (actual, expected) in parsed.entries().zip(&call.entries) {
            assert_eq!(actual.suite_id, expected.suite_id);
            assert_eq!(actual.weight, expected.weight);
            assert_eq!(actual.reserved0, [0]);
            assert_eq!(actual.pubkey_bytes, expected.pubkey_bytes);
        }
    }

    #[test]
    fn run422_keyset_create_preparation_semantic_refusals_before_reservation() {
        use KeysetSemanticAnalysisError as Semantic;
        let (key_a, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cases = [
            (call(1, vec![]), Semantic::EmptyKeyset, (0, 0, 0)),
            (
                call(0, vec![entry(100, 1, &key_a)]),
                Semantic::ZeroThreshold,
                (0, 0, 0),
            ),
            (
                call(3, vec![entry(100, 1, &key_a), entry(100, 1, &key_b)]),
                Semantic::ThresholdUnreachable,
                (2, 2, 0),
            ),
            (
                call(2, vec![entry(100, 1, &key_a), entry(101, 1, &key_a)]),
                Semantic::ThresholdUnreachable,
                (2, 2, 0),
            ),
            (
                call(1, vec![entry(100, 1, &key_a), entry(101, 2, &key_a)]),
                Semantic::ConflictingDuplicateWeights,
                (2, 2, 0),
            ),
            (
                call(1, vec![entry(100, 0, &key_a)]),
                Semantic::ThresholdUnreachable,
                (1, 1, 0),
            ),
            (
                call(1, vec![entry(99, 1, &key_a)]),
                Semantic::SuiteNotFound,
                (1, 0, 0),
            ),
            (
                call(1, vec![entry(100, 1, &key_a[..key_a.len() - 1])]),
                Semantic::DescriptorMalformed,
                (1, 1, 0),
            ),
            (
                call(1, vec![entry(100, 1, &key_a), entry(100, 0, &[0xFF])]),
                Semantic::DescriptorMalformed,
                (2, 2, 0),
            ),
        ];
        for (call, error, counts) in cases {
            let provider = Provider::new(DescriptorMode::Genuine);
            let (result, _) = prepare::<2>(&bytes(&call), &provider, exact(&call));
            assert_eq!(result, Err(KeysetCreatePreparationError::Semantics(error)));
            assert_eq!(provider.counts(), counts);
        }
    }

    #[test]
    fn run422_keyset_create_preparation_proof_identifier_and_zero_weight_boundaries() {
        let (key_a, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b, _) = MlDsa44Backend::generate_keypair().unwrap();
        let weighted_call = call(3, vec![entry(100, 2, &key_a), entry(100, 1, &key_b)]);
        let mut below = exact(&weighted_call);
        below.max_distinct_key_proofs = 1;
        for budget in [0, 1] {
            below.max_distinct_key_proofs = budget;
            let provider = Provider::new(DescriptorMode::Genuine);
            assert_eq!(
                prepare::<2>(&bytes(&weighted_call), &provider, below).0,
                Err(KeysetCreatePreparationError::Semantics(
                    KeysetSemanticAnalysisError::ThresholdUnreachable
                ))
            );
            assert_eq!(provider.counts(), (2, 2, 0));
        }
        let provider = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            prepare::<2>(&bytes(&weighted_call), &provider, exact(&weighted_call))
                .0
                .unwrap(),
            expected(&weighted_call)
        );
        assert_eq!(provider.counts(), (2, 2, 0));
        for budget in [0, 15] {
            let mut limits = exact(&weighted_call);
            limits.max_algorithm_parameter_identifier_bytes = budget;
            let provider = Provider::new(DescriptorMode::Genuine);
            assert_eq!(
                prepare::<2>(&bytes(&weighted_call), &provider, limits).0,
                Err(KeysetCreatePreparationError::Semantics(
                    KeysetSemanticAnalysisError::IdentifierLengthLimit
                ))
            );
            assert_eq!(provider.counts(), (1, 1, 0));
        }
        let zero_weight = call(2, vec![entry(100, 2, &key_a), entry(100, 0, &key_b)]);
        let provider = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            prepare::<2>(&bytes(&zero_weight), &provider, exact(&zero_weight))
                .0
                .unwrap(),
            expected(&zero_weight)
        );
    }

    #[test]
    fn run422_keyset_create_preparation_synthetic_descriptor_refusals() {
        // These injected descriptor responses are defensive control-flow
        // fixtures, not evidence of a genuine noncanonical ML-DSA encoding.
        let (key, _) = MlDsa44Backend::generate_keypair().unwrap();
        let call = call(1, vec![entry(100, 1, &key)]);
        for (mode, error) in [
            (
                DescriptorMode::Unsupported,
                KeysetSemanticAnalysisError::DescriptorUnsupported,
            ),
            (
                DescriptorMode::NonCanonical,
                KeysetSemanticAnalysisError::DescriptorNonCanonical,
            ),
        ] {
            let provider = Provider::new(mode);
            assert_eq!(
                prepare::<1>(&bytes(&call), &provider, exact(&call)).0,
                Err(KeysetCreatePreparationError::Semantics(error))
            );
            assert_eq!(provider.counts(), (1, 1, 0));
        }
    }

    #[test]
    fn run422_keyset_create_preparation_complete_framing_precedes_external_work() {
        let (key, _) = MlDsa44Backend::generate_keypair().unwrap();
        let call = call(1, vec![entry(100, 1, &key)]);
        let input = bytes(&call);
        let mut cases = Vec::new();
        let mut wrong_opcode = input.clone();
        wrong_opcode[0] ^= 1;
        cases.push((
            wrong_opcode,
            WireError::InvalidValue("unexpected op_code for CreateKeysetCall"),
        ));
        for end in [0, 41, 42, 46, input.len() - 1] {
            cases.push((input[..end].to_vec(), WireError::UnexpectedEof));
        }
        let mut trailing = input.clone();
        trailing.push(0);
        cases.push((
            trailing,
            WireError::InvalidValue("trailing create keyset bytes"),
        ));
        for (input, error) in cases {
            let mut limits = exact(&call);
            limits.create_keyset.max_encoded_bytes += 1;
            let provider = Provider::new(DescriptorMode::Genuine);
            assert_eq!(
                prepare::<1>(&input, &provider, limits).0,
                Err(KeysetCreatePreparationError::Parse(
                    CreateKeysetParseError::Malformed(error)
                ))
            );
            assert_eq!(provider.counts(), (0, 0, 0));
        }
    }

    #[test]
    fn run422_keyset_create_preparation_input_output_and_key_limits_are_independent() {
        let (key_a, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b, _) = MlDsa44Backend::generate_keypair().unwrap();
        let call = call(2, vec![entry(100, 1, &key_a), entry(100, 1, &key_b)]);
        let limits = exact(&call);
        let input = bytes(&call);
        assert_eq!(input.len(), limits.create_keyset.max_encoded_bytes);
        assert_eq!(expected(&call).data.len(), limits.max_stored_data_bytes);
        assert_eq!(
            input.len() - limits.max_stored_data_bytes,
            30 - call.entries.len()
        );
        for (configured, error) in [
            (
                {
                    let mut l = limits;
                    l.create_keyset.max_encoded_bytes = 0;
                    l
                },
                KeysetCreatePreparationError::Parse(CreateKeysetParseError::EncodedBytesLimit),
            ),
            (
                {
                    let mut l = limits;
                    l.create_keyset.max_encoded_bytes -= 1;
                    l
                },
                KeysetCreatePreparationError::Parse(CreateKeysetParseError::EncodedBytesLimit),
            ),
            (
                {
                    let mut l = limits;
                    l.max_stored_data_bytes = 0;
                    l
                },
                KeysetCreatePreparationError::StoredDataBytesLimit,
            ),
            (
                {
                    let mut l = limits;
                    l.max_stored_data_bytes -= 1;
                    l
                },
                KeysetCreatePreparationError::StoredDataBytesLimit,
            ),
            (
                {
                    let mut l = limits;
                    l.create_keyset.max_entries = 0;
                    l
                },
                KeysetCreatePreparationError::Parse(CreateKeysetParseError::EntryCountLimit),
            ),
            (
                {
                    let mut l = limits;
                    l.create_keyset.max_entries = 1;
                    l
                },
                KeysetCreatePreparationError::Parse(CreateKeysetParseError::EntryCountLimit),
            ),
            (
                {
                    let mut l = limits;
                    l.create_keyset.max_key_bytes = 0;
                    l
                },
                KeysetCreatePreparationError::Parse(CreateKeysetParseError::PerKeyBytesLimit),
            ),
            (
                {
                    let mut l = limits;
                    l.create_keyset.max_key_bytes -= 1;
                    l
                },
                KeysetCreatePreparationError::Parse(CreateKeysetParseError::PerKeyBytesLimit),
            ),
            (
                {
                    let mut l = limits;
                    l.create_keyset.max_total_key_bytes = 0;
                    l
                },
                KeysetCreatePreparationError::Parse(CreateKeysetParseError::AggregateKeyBytesLimit),
            ),
            (
                {
                    let mut l = limits;
                    l.create_keyset.max_total_key_bytes -= 1;
                    l
                },
                KeysetCreatePreparationError::Parse(CreateKeysetParseError::AggregateKeyBytesLimit),
            ),
        ] {
            let provider = Provider::new(DescriptorMode::Genuine);
            assert_eq!(prepare::<2>(&input, &provider, configured).0, Err(error));
            assert_eq!(provider.counts(), (0, 0, 0));
        }
        assert!(
            limits.create_keyset.max_total_key_bytes - 1 >= key_a.len(),
            "cumulative ceiling must admit the first entry"
        );
        let provider = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            prepare::<2>(&input, &provider, limits).0.unwrap(),
            expected(&call)
        );
        assert_eq!(provider.counts(), (2, 2, 0));
        // Independently relax only one of the exact byte ceilings.
        for configured in [
            {
                let mut l = limits;
                l.create_keyset.max_encoded_bytes += 1;
                l
            },
            {
                let mut l = limits;
                l.max_stored_data_bytes += 1;
                l
            },
        ] {
            let provider = Provider::new(DescriptorMode::Genuine);
            assert_eq!(
                prepare::<2>(&input, &provider, configured).0.unwrap(),
                expected(&call)
            );
        }
    }

    #[test]
    fn run422_keyset_create_preparation_workspace_zero_exact_and_one_above() {
        let (key, _) = MlDsa44Backend::generate_keypair().unwrap();
        let one = call(1, vec![entry(100, 1, &key)]);
        let provider = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            prepare::<0>(&bytes(&one), &provider, exact(&one)).0,
            Err(KeysetCreatePreparationError::EntryWorkspaceCapacity)
        );
        assert_eq!(provider.counts(), (0, 0, 0));
        let provider = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            prepare::<1>(&bytes(&one), &provider, exact(&one))
                .0
                .unwrap(),
            expected(&one)
        );
        let two = call(1, vec![entry(100, 1, &key), entry(101, 1, &key)]);
        let provider = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            prepare::<1>(&bytes(&two), &provider, exact(&two)).0,
            Err(KeysetCreatePreparationError::EntryWorkspaceCapacity)
        );
        assert_eq!(provider.counts(), (0, 0, 0));
        let provider = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            prepare::<2>(&bytes(&two), &provider, exact(&two))
                .0
                .unwrap(),
            expected(&two)
        );
    }

    #[test]
    fn run422_keyset_create_preparation_stored_length_can_exceed_input_length() {
        let (key, _) = MlDsa44Backend::generate_keypair().unwrap();
        let call = call(1, (0..31).map(|_| entry(100, 1, &key)).collect());
        let input = bytes(&call);
        let mut limits = exact(&call);
        assert_eq!(limits.max_stored_data_bytes, input.len() + 1);
        limits.max_stored_data_bytes = input.len();
        let provider = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            prepare::<31>(&input, &provider, limits).0,
            Err(KeysetCreatePreparationError::StoredDataBytesLimit)
        );
        assert_eq!(provider.counts(), (0, 0, 0));
        limits.max_stored_data_bytes += 1;
        limits.max_distinct_key_proofs = 1;
        let provider = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            prepare::<31>(&input, &provider, limits).0.unwrap(),
            expected(&call)
        );
        assert_eq!(provider.counts(), (31, 31, 0));
    }

    #[test]
    fn run422_keyset_create_preparation_checked_length_and_append_scalar_controls() {
        assert_eq!(stored_encoding_length(0, 0), Ok(12));
        assert_eq!(stored_encoding_length(2, 3), Ok(27));
        for (entries, keys) in [(usize::MAX, 0), (0, usize::MAX), (usize::MAX / 6, 0)] {
            assert_eq!(
                stored_encoding_length(entries, keys),
                Err(KeysetCreatePreparationError::StoredLengthOverflow)
            );
        }
        // Scalar sizing controls, not impractically large input allocations.
        let mut data = Vec::new();
        assert_eq!(
            append_bounded(&mut data, &[1], 1),
            Err(KeysetCreatePreparationError::EncodingLengthMismatch)
        );
        data.try_reserve_exact(2).unwrap();
        append_bounded(&mut data, &[1], 1).unwrap();
        assert_eq!(
            append_bounded(&mut data, &[2], 1),
            Err(KeysetCreatePreparationError::EncodingLengthMismatch)
        );
        assert_eq!(data, [1]);
    }

    #[test]
    fn run422_keyset_create_preparation_reservation_injection_retry_and_guard_restore() {
        let (key, _) = MlDsa44Backend::generate_keypair().unwrap();
        let call = call(1, vec![entry(100, 1, &key)]);
        let input = bytes(&call);
        let original = input.clone();
        let limits = exact(&call);
        let provider = Provider::new(DescriptorMode::Genuine);
        let outer = observation::Guard::new(false);
        {
            // Thread-scoped synthetic refusal before try_reserve_exact, not
            // an observed allocator failure. Drop restores the outer observer.
            let guard = observation::Guard::new(true);
            assert_eq!(
                prepare_keyset_account_bounded::<1>(&input, &provider, limits),
                Err(KeysetCreatePreparationError::DestinationReservation)
            );
            let failure = guard.take();
            assert_eq!(failure.requests, [limits.max_stored_data_bytes]);
            assert!(failure.snapshots.is_empty());
            assert_eq!(provider.counts(), (1, 1, 0));
            let account = prepare_keyset_account_bounded::<1>(&input, &provider, limits).unwrap();
            assert_eq!(account, expected(&call));
            assert_success_observation(&guard.take(), &account);
            assert_eq!(provider.counts(), (2, 2, 0));
        }
        assert!(outer.take().requests.is_empty());
        let account = prepare_keyset_account_bounded::<1>(&input, &provider, limits).unwrap();
        assert_success_observation(&outer.take(), &account);
        assert_eq!(input, original);
        // Actual standard-library capacity failure is checked separately at
        // the reservation helper; no huge backing allocation is attempted.
        let mut data = Vec::new();
        assert_eq!(
            reserve_destination(&mut data, usize::MAX),
            Err(KeysetCreatePreparationError::DestinationReservation)
        );
        let failure = outer.take();
        assert_eq!(failure.requests, [usize::MAX]);
        assert!(failure.snapshots.is_empty());
        assert!(data.is_empty());
        reserve_destination(&mut data, limits.max_stored_data_bytes).unwrap();
        let retry = outer.take();
        assert_eq!(retry.requests, [limits.max_stored_data_bytes]);
        assert_eq!(retry.snapshots.len(), 1);
        assert!(data.capacity() >= limits.max_stored_data_bytes);
    }

    #[test]
    fn run422_keyset_create_preparation_composes_with_transaction_proof_evaluation() {
        use crate::keyset_proof::KeysetProofEvaluationError;
        let (key_a, secret_a) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b, secret_b) = MlDsa44Backend::generate_keypair().unwrap();
        let call = call(2, vec![entry(100, 1, &key_a), entry(100, 1, &key_b)]);
        let provider = Provider::new(DescriptorMode::Genuine);
        let account = prepare::<2>(&bytes(&call), &provider, exact(&call))
            .0
            .unwrap();
        let mut store = InMemoryAccountStore::new();
        store.put(account).unwrap();
        let body = Transaction {
            version: 1,
            chain_id: 7,
            payer: [0x41; 32],
            nonce: 8,
            fee_limit: 99,
            accounts: vec![TxAccountMeta {
                account_id: call.target_id,
                flags: 1,
                access_hint: 0,
                reserved0: [0; 2],
            }],
            program_id: [0x51; 32],
            call_data: vec![1, 3, 3, 7],
            auths: vec![],
        };
        let digest = try_tx_digest_streaming(&body).unwrap();
        let signature_a = MlDsa44Backend::sign(&secret_a, &digest).unwrap();
        let signature_b = MlDsa44Backend::sign(&secret_b, &digest).unwrap();
        let tx_auth = |signature: Vec<u8>| TxAuth {
            account_index: 0,
            suite_id: 100,
            reserved: 0,
            signature,
        };
        let limits = NativeTransactionProofLimits {
            max_required_signer_indices: 1,
            max_keyset_account_count: 1,
            max_authentication_proof_count: 2,
            max_signature_bytes: signature_a.len(),
            max_aggregate_signature_bytes: 2 * signature_a.len(),
            stored_keyset: StoredKeysetLimits {
                max_encoded_bytes: exact(&call).max_stored_data_bytes,
                max_entries: 2,
                max_key_bytes: key_a.len(),
                max_total_key_bytes: key_a.len() + key_b.len(),
            },
            max_algorithm_parameter_identifier_bytes: 16,
        };
        let mut repeated = body.clone();
        repeated.auths = vec![tx_auth(signature_a.clone()), tx_auth(signature_a.clone())];
        let original = repeated.clone();
        let verifier = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 2, 2>(&repeated, &store, &verifier, limits),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::InsufficientVerifiedWeight
            ))
        );
        assert_eq!(verifier.counts(), (2, 2, 4));
        assert_eq!(repeated, original);
        let mut accepted = body;
        accepted.auths = vec![tx_auth(signature_a), tx_auth(signature_b)];
        let original = accepted.clone();
        let verifier = Provider::new(DescriptorMode::Genuine);
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 2, 2>(&accepted, &store, &verifier, limits),
            Ok(NativeTransactionProofSummary {
                required_signer_index_count: 1,
                distinct_keyset_account_count: 1,
                evaluated_authentication_proof_count: 2,
            })
        );
        assert_eq!(verifier.counts(), (2, 2, 4));
        assert_eq!(accepted, original);
    }

    #[test]
    fn run422_keyset_create_preparation_compiler_object_inventory() {
        use core::mem::size_of;
        eprintln!(
            "object bytes: CreateKeysetView={} Workspace<E=0/1/2/4>={}/{}/{}/{} threshold<E=2>={} limits={} error={} semantic_summary={} Vec={} Account={} return={} usize={} borrow={}",
            size_of::<CreateKeysetView<'static>>(),
            size_of::<Workspace<'static, 0>>(), size_of::<Workspace<'static, 1>>(),
            size_of::<Workspace<'static, 2>>(), size_of::<Workspace<'static, 4>>(),
            size_of::<[u16; 2]>(), size_of::<KeysetCreatePreparationLimits>(),
            size_of::<KeysetCreatePreparationError>(),
            size_of::<crate::keyset_validation::KeysetSemanticAnalysisSummary>(),
            size_of::<Vec<u8>>(), size_of::<Account>(),
            size_of::<Result<Account, KeysetCreatePreparationError>>(),
            size_of::<usize>(), size_of::<&[u8]>(),
        );
    }
}
