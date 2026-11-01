//! Bounded, isolated verification of proofs against one borrowed stored keyset.
//!
//! Success reports cryptographic matches and distinct-key weight for this
//! keyset and caller-supplied digest only. It is not transaction authorization,
//! current authority, account ownership, or permission to execute, and has no
//! production caller.
//!
//! `N` is a trusted caller-selected workspace capacity, not a protocol limit.
//! All other budgets are explicit inputs. The helper does not establish a
//! provider epoch, governance authorization, freshness, revocation, snapshot,
//! or persistent-read guarantee.

use crate::keyset_validation::{
    identity_weight, prepare_entries, summarize_workspace, KeysetSemanticAnalysisError,
    PreparedCandidate, Workspace,
};
use qbind_crypto::error::CryptoError;
use qbind_crypto::CryptoProvider;
use qbind_serde::keyset::StoredKeysetView;
use qbind_types::Hash32;

/// One caller-owned signature and its suite identifier.
#[derive(Clone, Copy)]
pub struct KeysetSignatureProof<'a> {
    pub suite_id: u8,
    pub signature_bytes: &'a [u8],
}

/// Per-call limits. These are caller inputs, not an approved policy profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeysetProofEvaluationLimits {
    pub max_proof_count: usize,
    pub max_signature_bytes: usize,
    pub max_aggregate_signature_bytes: usize,
    pub max_algorithm_parameter_identifier_bytes: usize,
}

/// Fixed-size refusal categories; no input bytes or backend strings are kept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeysetProofEvaluationError {
    EmptyProofs,
    EntryCountExceedsWorkspace,
    ProofCountLimit,
    SignatureByteLimit,
    AggregateSignatureByteOverflow,
    AggregateSignatureByteLimit,
    EmptyKeyset,
    ZeroThreshold,
    SuiteNotFound,
    SuiteIdMismatch,
    DescriptorUnsupported,
    DescriptorMalformed,
    DescriptorNonCanonical,
    IdentifierLengthOverflow,
    IdentifierLengthLimit,
    DescriptorKeySpanMismatch,
    ConflictingDuplicateWeights,
    WeightOverflow,
    ThresholdUnreachable,
    InsufficientVerifiedWeight,
    NoMatchingSuiteEntry,
    InvalidProof,
    AmbiguousProof,
    VerificationFailure,
}

/// Successful evidence summary for one keyset and digest only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeysetProofEvaluationSummary {
    pub evaluated_proof_count: usize,
    pub verified_distinct_key_count: usize,
    pub verified_distinct_key_weight: u64,
}

struct ProofWorkspace<'key, 'provider, const N: usize> {
    candidates: [Option<PreparedCandidate<'key, 'provider>>; N],
    identities: Workspace<'key, N>,
    verified_identities: [bool; N],
}

/// Verify all supplied proofs against every encoded keyset entry of the same
/// suite, using exact canonical identity to disambiguate and count weight.
///
/// The complete keyset is prepared and checked before any signature operation.
/// Every proof is evaluated even after the verified weight reaches threshold;
/// a later malformed, absent-suite, invalid, ambiguous, or backend-failing
/// proof therefore still refuses the call.
///
/// Fixed helper workspace is bounded by `N`: candidate references, canonical
/// identity records, and one verified flag per identity. Provider suites,
/// keyset bytes, proof bytes and the digest are borrowed. This says nothing
/// about caller-owned storage, parser/account materialization, provider or
/// cryptographic internals, allocator behavior, physical stack/RSS, or
/// operational latency.
pub fn evaluate_stored_keyset_proofs<const N: usize>(
    keyset: StoredKeysetView<'_>,
    provider: &dyn CryptoProvider,
    digest: &Hash32,
    proofs: &[KeysetSignatureProof<'_>],
    limits: KeysetProofEvaluationLimits,
) -> Result<KeysetProofEvaluationSummary, KeysetProofEvaluationError> {
    use KeysetProofEvaluationError as Error;

    if proofs.is_empty() {
        return Err(Error::EmptyProofs);
    }
    if usize::from(keyset.entry_count()) > N {
        return Err(Error::EntryCountExceedsWorkspace);
    }
    if proofs.len() > limits.max_proof_count {
        return Err(Error::ProofCountLimit);
    }
    checked_aggregate_signature_bytes(proofs, limits)?;

    let mut candidates = [None; N];
    let identities = prepare_entries::<N, _>(
        keyset.threshold(),
        keyset.entry_count(),
        keyset
            .entries()
            .map(|entry| (entry.suite_id, entry.weight, entry.pubkey_bytes)),
        provider,
        limits.max_algorithm_parameter_identifier_bytes,
        Some(&mut candidates),
    )
    .map_err(map_semantic_error)?;
    let mut workspace = ProofWorkspace {
        candidates,
        identities,
        verified_identities: [false; N],
    };

    // This uses the same canonical identities and reachability semantics as
    // stored/create analysis, before any signature verification.
    summarize_workspace(
        &workspace.identities,
        keyset.threshold(),
        keyset.entry_count(),
        limits.max_proof_count,
    )
    .map_err(map_semantic_error)?;

    let mut verified_distinct_key_count = 0usize;
    let mut verified_distinct_key_weight = 0u64;
    for proof in proofs {
        let mut has_matching_entry = false;
        let mut successful_identity = None;
        let mut ambiguous = false;

        for candidate in workspace.candidates[..usize::from(keyset.entry_count())]
            .iter()
            .flatten()
        {
            if candidate.suite_id != proof.suite_id {
                continue;
            }
            has_matching_entry = true;
            match candidate
                .suite
                .verify(candidate.public_key, digest, proof.signature_bytes)
            {
                Ok(()) => match successful_identity {
                    None => successful_identity = Some(candidate.identity_index),
                    Some(index) if index != candidate.identity_index => ambiguous = true,
                    Some(_) => {}
                },
                Err(CryptoError::InvalidSignature) => {}
                Err(_) => return Err(Error::VerificationFailure),
            }
        }

        if !has_matching_entry {
            return Err(Error::NoMatchingSuiteEntry);
        }
        if ambiguous {
            return Err(Error::AmbiguousProof);
        }
        let identity_index = successful_identity.ok_or(Error::InvalidProof)?;
        if !workspace.verified_identities[identity_index] {
            workspace.verified_identities[identity_index] = true;
            verified_distinct_key_count += 1;
            verified_distinct_key_weight = verified_distinct_key_weight
                .checked_add(u64::from(
                    identity_weight(&workspace.identities, identity_index)
                        .ok_or(Error::WeightOverflow)?,
                ))
                .ok_or(Error::WeightOverflow)?;
        }
    }

    if verified_distinct_key_weight < u64::from(keyset.threshold()) {
        return Err(Error::InsufficientVerifiedWeight);
    }

    Ok(KeysetProofEvaluationSummary {
        evaluated_proof_count: proofs.len(),
        verified_distinct_key_count,
        verified_distinct_key_weight,
    })
}

fn checked_aggregate_signature_bytes(
    proofs: &[KeysetSignatureProof<'_>],
    limits: KeysetProofEvaluationLimits,
) -> Result<usize, KeysetProofEvaluationError> {
    let mut total = 0usize;
    for proof in proofs {
        if proof.signature_bytes.len() > limits.max_signature_bytes {
            return Err(KeysetProofEvaluationError::SignatureByteLimit);
        }
        total = checked_add_signature_bytes(
            total,
            proof.signature_bytes.len(),
            limits.max_aggregate_signature_bytes,
        )?;
    }
    Ok(total)
}

fn checked_add_signature_bytes(
    total: usize,
    next: usize,
    limit: usize,
) -> Result<usize, KeysetProofEvaluationError> {
    let total = total
        .checked_add(next)
        .ok_or(KeysetProofEvaluationError::AggregateSignatureByteOverflow)?;
    if total > limit {
        return Err(KeysetProofEvaluationError::AggregateSignatureByteLimit);
    }
    Ok(total)
}

fn map_semantic_error(error: KeysetSemanticAnalysisError) -> KeysetProofEvaluationError {
    use KeysetProofEvaluationError as ProofError;
    use KeysetSemanticAnalysisError as SemanticError;

    match error {
        SemanticError::EntryCountExceedsWorkspace => ProofError::EntryCountExceedsWorkspace,
        SemanticError::EmptyKeyset => ProofError::EmptyKeyset,
        SemanticError::ZeroThreshold => ProofError::ZeroThreshold,
        SemanticError::SuiteNotFound => ProofError::SuiteNotFound,
        SemanticError::SuiteIdMismatch => ProofError::SuiteIdMismatch,
        SemanticError::DescriptorUnsupported => ProofError::DescriptorUnsupported,
        SemanticError::DescriptorMalformed => ProofError::DescriptorMalformed,
        SemanticError::DescriptorNonCanonical => ProofError::DescriptorNonCanonical,
        SemanticError::IdentifierLengthOverflow => ProofError::IdentifierLengthOverflow,
        SemanticError::IdentifierLengthLimit => ProofError::IdentifierLengthLimit,
        SemanticError::DescriptorKeySpanMismatch => ProofError::DescriptorKeySpanMismatch,
        SemanticError::ConflictingDuplicateWeights => ProofError::ConflictingDuplicateWeights,
        SemanticError::WeightOverflow => ProofError::WeightOverflow,
        SemanticError::ThresholdUnreachable => ProofError::ThresholdUnreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyset_account::read_keyset_owned_account_bounded;
    use crate::keyset_validation::{checked_identifier_byte_len, KeysetSemanticAnalysisSummary};
    use crate::{store::AccountStore, Account, AccountHeader, ExecutionError};
    use qbind_crypto::error::CryptoError;
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
    use qbind_crypto::{MlDsa44SignatureSuite, StaticCryptoProvider};
    use qbind_hash::tx::try_tx_digest_streaming;
    use qbind_serde::keyset::{parse_stored_keyset, StoredKeysetLimits};
    use qbind_types::{AccountId, Hash32, KEYSET_PROGRAM_ID};
    use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Default)]
    struct Calls {
        descriptors: AtomicUsize,
        verifications: AtomicUsize,
    }

    #[derive(Clone, Copy)]
    enum DescriptorMode {
        Normal,
        Unsupported,
        Malformed,
        NonCanonical,
        SubstituteSpan,
    }

    #[derive(Clone, Copy)]
    enum VerifyMode {
        SignatureEqualsKey,
        AcceptAny,
        FailOnKey(u8),
    }

    struct TestSuite {
        reported_id: u8,
        algorithm_id: &'static [u8],
        parameter_id: &'static [u8],
        descriptor_mode: DescriptorMode,
        verify_mode: VerifyMode,
        calls: Arc<Calls>,
    }

    impl TestSuite {
        fn new(id: u8, calls: Arc<Calls>) -> Self {
            Self {
                reported_id: id,
                algorithm_id: b"test-algorithm",
                parameter_id: b"test-parameters",
                descriptor_mode: DescriptorMode::Normal,
                verify_mode: VerifyMode::SignatureEqualsKey,
                calls,
            }
        }
    }

    impl SignatureSuite for TestSuite {
        fn suite_id(&self) -> u8 {
            self.reported_id
        }

        fn public_key_len(&self) -> usize {
            0
        }

        fn signature_len(&self) -> usize {
            0
        }

        fn verify(
            &self,
            key: &[u8],
            _digest: &Hash32,
            signature: &[u8],
        ) -> Result<(), CryptoError> {
            self.calls.verifications.fetch_add(1, Ordering::SeqCst);
            match self.verify_mode {
                VerifyMode::SignatureEqualsKey if key == signature => Ok(()),
                VerifyMode::SignatureEqualsKey => Err(CryptoError::InvalidSignature),
                VerifyMode::AcceptAny => Ok(()),
                VerifyMode::FailOnKey(byte) if key.first() == Some(&byte) => {
                    Err(CryptoError::InternalError("synthetic backend failure"))
                }
                VerifyMode::FailOnKey(_) if key == signature => Ok(()),
                VerifyMode::FailOnKey(_) => Err(CryptoError::InvalidSignature),
            }
        }

        fn canonical_key_descriptor<'a>(
            &self,
            key: &'a [u8],
        ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
            self.calls.descriptors.fetch_add(1, Ordering::SeqCst);
            match self.descriptor_mode {
                DescriptorMode::Unsupported => Err(KeyDescriptorError::Unsupported),
                DescriptorMode::Malformed => Err(KeyDescriptorError::Malformed),
                DescriptorMode::NonCanonical => Err(KeyDescriptorError::NonCanonical),
                DescriptorMode::Normal => Ok(CanonicalKeyDescriptor {
                    algorithm_id: self.algorithm_id,
                    parameter_id: self.parameter_id,
                    public_key_encoding: key,
                }),
                DescriptorMode::SubstituteSpan => Ok(CanonicalKeyDescriptor {
                    algorithm_id: self.algorithm_id,
                    parameter_id: self.parameter_id,
                    public_key_encoding: b"substituted-span",
                }),
            }
        }
    }

    struct TestProvider {
        suites: Vec<(u8, Box<dyn SignatureSuite>)>,
        lookups: AtomicUsize,
    }

    impl TestProvider {
        fn new(suites: Vec<(u8, Box<dyn SignatureSuite>)>) -> Self {
            Self {
                suites,
                lookups: AtomicUsize::new(0),
            }
        }
    }

    impl CryptoProvider for TestProvider {
        fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            self.suites
                .iter()
                .find(|(registered_id, _)| *registered_id == suite_id)
                .map(|(_, suite)| suite.as_ref())
        }

        fn kem_suite(&self, _suite_id: u8) -> Option<&dyn qbind_crypto::KemSuite> {
            None
        }

        fn aead_suite(&self, _suite_id: u8) -> Option<&dyn qbind_crypto::AeadSuite> {
            None
        }
    }

    struct CountedMlDsa {
        inner: MlDsa44SignatureSuite,
        calls: Arc<Calls>,
    }

    impl SignatureSuite for CountedMlDsa {
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
            self.calls.verifications.fetch_add(1, Ordering::SeqCst);
            self.inner.verify(key, digest, signature)
        }

        fn canonical_key_descriptor<'a>(
            &self,
            key: &'a [u8],
        ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
            self.calls.descriptors.fetch_add(1, Ordering::SeqCst);
            self.inner.canonical_key_descriptor(key)
        }
    }

    fn test_provider(suite_id: u8, suite: TestSuite) -> TestProvider {
        TestProvider::new(vec![(suite_id, Box::new(suite))])
    }

    fn encode_keyset(threshold: u16, entries: &[(u8, u16, &[u8])]) -> Vec<u8> {
        let mut bytes = vec![1, 0, 0, 0];
        bytes.extend_from_slice(&threshold.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        for (suite_id, weight, key) in entries {
            bytes.push(*suite_id);
            bytes.extend_from_slice(&weight.to_le_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&u16::try_from(key.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(key);
        }
        bytes
    }

    fn view(bytes: &[u8]) -> StoredKeysetView<'_> {
        parse_stored_keyset(
            bytes,
            StoredKeysetLimits {
                max_encoded_bytes: usize::MAX,
                max_entries: usize::MAX,
                max_key_bytes: usize::MAX,
                max_total_key_bytes: usize::MAX,
            },
        )
        .unwrap()
    }

    fn proof<'a>(suite_id: u8, signature_bytes: &'a [u8]) -> KeysetSignatureProof<'a> {
        KeysetSignatureProof {
            suite_id,
            signature_bytes,
        }
    }

    fn limits(
        max_proof_count: usize,
        max_signature_bytes: usize,
        max_aggregate_signature_bytes: usize,
    ) -> KeysetProofEvaluationLimits {
        KeysetProofEvaluationLimits {
            max_proof_count,
            max_signature_bytes,
            max_aggregate_signature_bytes,
            max_algorithm_parameter_identifier_bytes: usize::MAX,
        }
    }

    fn counted_mldsa_provider(suite_ids: &[u8], calls: &Arc<Calls>) -> StaticCryptoProvider {
        suite_ids
            .iter()
            .fold(StaticCryptoProvider::new(), |provider, id| {
                provider.with_signature_suite(Arc::new(CountedMlDsa {
                    inner: MlDsa44SignatureSuite::new(*id),
                    calls: Arc::clone(calls),
                }))
            })
    }

    #[test]
    fn run422_keyset_proof_genuine_later_entry_exact_threshold_and_full_scan() {
        let (first_key, first_secret) = MlDsa44Backend::generate_keypair().unwrap();
        let (second_key, second_secret) = MlDsa44Backend::generate_keypair().unwrap();
        let digest = [0x42; 32];
        let first_signature = MlDsa44Backend::sign(&first_secret, &digest).unwrap();
        let second_signature = MlDsa44Backend::sign(&second_secret, &digest).unwrap();
        let entries = [
            (100, 2, first_key.as_slice()),
            (100, 3, second_key.as_slice()),
        ];
        let bytes = encode_keyset(5, &entries);
        let calls = Arc::new(Calls::default());
        let provider = counted_mldsa_provider(&[100], &calls);
        let proofs = [proof(100, &second_signature), proof(100, &first_signature)];

        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&bytes),
                &provider,
                &digest,
                &proofs,
                limits(2, usize::MAX, usize::MAX),
            ),
            Ok(KeysetProofEvaluationSummary {
                evaluated_proof_count: 2,
                verified_distinct_key_count: 2,
                verified_distinct_key_weight: 5,
            })
        );
        assert_eq!(calls.descriptors.load(Ordering::SeqCst), 2);
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn run422_keyset_proof_genuine_invalid_inputs_and_late_extra_proof() {
        let (first_key, first_secret) = MlDsa44Backend::generate_keypair().unwrap();
        let (second_key, second_secret) = MlDsa44Backend::generate_keypair().unwrap();
        let digest = [0x39; 32];
        let first_signature = MlDsa44Backend::sign(&first_secret, &digest).unwrap();
        let second_signature = MlDsa44Backend::sign(&second_secret, &digest).unwrap();
        let entries = [
            (100, 2, first_key.as_slice()),
            (100, 3, second_key.as_slice()),
        ];
        let bytes = encode_keyset(5, &entries);
        let calls = Arc::new(Calls::default());
        let provider = counted_mldsa_provider(&[100], &calls);

        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&bytes),
                &provider,
                &digest,
                &[proof(100, &first_signature)],
                limits(2, usize::MAX, usize::MAX),
            ),
            Err(KeysetProofEvaluationError::InsufficientVerifiedWeight)
        );

        let mut tampered = second_signature.clone();
        tampered[0] ^= 0x80;
        for (supplied_digest, signature) in [
            ([0x38; 32], first_signature.as_slice()),
            (digest, tampered.as_slice()),
            (digest, &[][..]),
        ] {
            assert_eq!(
                evaluate_stored_keyset_proofs::<2>(
                    view(&bytes),
                    &provider,
                    &supplied_digest,
                    &[proof(100, signature)],
                    limits(2, usize::MAX, usize::MAX),
                ),
                Err(KeysetProofEvaluationError::InvalidProof)
            );
        }

        calls.verifications.store(0, Ordering::SeqCst);
        let invalid_extra = [0x55; 2420];
        let proofs = [
            proof(100, &first_signature),
            proof(100, &second_signature),
            proof(100, &invalid_extra),
        ];
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&bytes),
                &provider,
                &digest,
                &proofs,
                limits(3, usize::MAX, usize::MAX),
            ),
            Err(KeysetProofEvaluationError::InvalidProof)
        );
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 6);

        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&bytes),
                &provider,
                &digest,
                &[],
                limits(0, usize::MAX, usize::MAX),
            ),
            Err(KeysetProofEvaluationError::EmptyProofs)
        );
    }

    #[test]
    fn run422_keyset_proof_duplicate_alias_repeated_and_distinct_signatures_count_once() {
        let (key, secret) = MlDsa44Backend::generate_keypair().unwrap();
        let digest = [0x72; 32];
        let signature_a = MlDsa44Backend::sign(&secret, &digest).unwrap();
        let signature_b = MlDsa44Backend::sign(&secret, &digest).unwrap();
        let entries = [(100, 4, key.as_slice()), (100, 4, key.as_slice())];
        let bytes = encode_keyset(4, &entries);
        let calls = Arc::new(Calls::default());
        let provider = counted_mldsa_provider(&[100, 101], &calls);
        let proofs = [
            proof(100, &signature_a),
            proof(100, &signature_a),
            proof(100, &signature_b),
        ];
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&bytes),
                &provider,
                &digest,
                &proofs,
                limits(3, usize::MAX, usize::MAX),
            ),
            Ok(KeysetProofEvaluationSummary {
                evaluated_proof_count: 3,
                verified_distinct_key_count: 1,
                verified_distinct_key_weight: 4,
            })
        );
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 6);

        let alias_entries = [(100, 4, key.as_slice()), (101, 4, key.as_slice())];
        let alias_bytes = encode_keyset(4, &alias_entries);
        let alias_proofs = [proof(100, &signature_a), proof(101, &signature_b)];
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&alias_bytes),
                &provider,
                &digest,
                &alias_proofs,
                limits(2, usize::MAX, usize::MAX),
            ),
            Ok(KeysetProofEvaluationSummary {
                evaluated_proof_count: 2,
                verified_distinct_key_count: 1,
                verified_distinct_key_weight: 4,
            })
        );
        assert_ne!(
            signature_a, signature_b,
            "ML-DSA signing API should provide distinct valid signatures when randomized"
        );
    }

    #[test]
    fn run422_keyset_proof_conflicting_duplicates_refuse_before_crypto() {
        let calls = Arc::new(Calls::default());
        let suite = TestSuite::new(1, Arc::clone(&calls));
        let provider = test_provider(1, suite);
        let key = [1u8];
        for entries in [
            [(1, 0, key.as_slice()), (1, 2, key.as_slice())],
            [(1, 2, key.as_slice()), (1, 0, key.as_slice())],
        ] {
            let bytes = encode_keyset(1, &entries);
            assert_eq!(
                evaluate_stored_keyset_proofs::<2>(
                    view(&bytes),
                    &provider,
                    &[0; 32],
                    &[proof(1, &key)],
                    limits(1, 1, 1),
                ),
                Err(KeysetProofEvaluationError::ConflictingDuplicateWeights)
            );
        }
        let first = TestSuite::new(1, Arc::clone(&calls));
        let second = TestSuite::new(2, Arc::clone(&calls));
        let alias_provider = TestProvider::new(vec![(1, Box::new(first)), (2, Box::new(second))]);
        let alias_conflict = encode_keyset(1, &[(1, 0, &key), (2, 2, &key)]);
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&alias_conflict),
                &alias_provider,
                &[0; 32],
                &[proof(1, &key)],
                limits(1, 1, 1),
            ),
            Err(KeysetProofEvaluationError::ConflictingDuplicateWeights)
        );
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn run422_keyset_proof_zero_weight_and_permutations_preserve_result() {
        let calls = Arc::new(Calls::default());
        let mut suite = TestSuite::new(1, Arc::clone(&calls));
        suite.verify_mode = VerifyMode::SignatureEqualsKey;
        let provider = test_provider(1, suite);
        let a = [1u8];
        let b = [2u8];
        let entries_a = [(1, 0, a.as_slice()), (1, 3, b.as_slice())];
        let entries_b = [(1, 3, b.as_slice()), (1, 0, a.as_slice())];
        let bytes_a = encode_keyset(3, &entries_a);
        let bytes_b = encode_keyset(3, &entries_b);
        let proofs_a = [proof(1, &a), proof(1, &b)];
        let proofs_b = [proof(1, &b), proof(1, &a)];
        let expected = KeysetProofEvaluationSummary {
            evaluated_proof_count: 2,
            verified_distinct_key_count: 2,
            verified_distinct_key_weight: 3,
        };
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&bytes_a),
                &provider,
                &[0; 32],
                &proofs_a,
                limits(2, 1, 2),
            ),
            Ok(expected)
        );
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&bytes_b),
                &provider,
                &[0; 32],
                &proofs_b,
                limits(2, 1, 2),
            ),
            Ok(expected)
        );
    }

    #[test]
    fn run422_keyset_proof_synthetic_ambiguity_and_identity_field_separation() {
        let calls = Arc::new(Calls::default());
        let mut suite = TestSuite::new(1, Arc::clone(&calls));
        suite.verify_mode = VerifyMode::AcceptAny;
        let provider = test_provider(1, suite);
        let first = [1u8];
        let second = [2u8];
        let ambiguous = encode_keyset(1, &[(1, 1, &first), (1, 1, &second)]);
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&ambiguous),
                &provider,
                &[0; 32],
                &[proof(1, b"synthetic")],
                limits(1, 9, 9),
            ),
            Err(KeysetProofEvaluationError::AmbiguousProof)
        );
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 2);

        let one_identity = encode_keyset(1, &[(1, 1, &first)]);
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&one_identity),
                &provider,
                &[0; 32],
                &[proof(1, b"synthetic")],
                limits(1, 9, 9),
            )
            .unwrap()
            .verified_distinct_key_weight,
            1
        );

        let same_bytes = [9u8];
        let mut base = TestSuite::new(1, Arc::clone(&calls));
        base.verify_mode = VerifyMode::AcceptAny;
        let mut other_algorithm = TestSuite::new(2, Arc::clone(&calls));
        other_algorithm.algorithm_id = b"other-algorithm";
        other_algorithm.verify_mode = VerifyMode::AcceptAny;
        let mut other_parameters = TestSuite::new(3, Arc::clone(&calls));
        other_parameters.parameter_id = b"other-parameters";
        other_parameters.verify_mode = VerifyMode::AcceptAny;
        let provider = TestProvider::new(vec![
            (1, Box::new(base)),
            (2, Box::new(other_algorithm)),
            (3, Box::new(other_parameters)),
        ]);
        let bytes = encode_keyset(
            3,
            &[
                (1, 1, &same_bytes),
                (2, 1, &same_bytes),
                (3, 1, &same_bytes),
            ],
        );
        assert_eq!(
            evaluate_stored_keyset_proofs::<3>(
                view(&bytes),
                &provider,
                &[0; 32],
                &[
                    proof(1, b"synthetic"),
                    proof(2, b"synthetic"),
                    proof(3, b"synthetic"),
                ],
                limits(3, 9, 27),
            ),
            Ok(KeysetProofEvaluationSummary {
                evaluated_proof_count: 3,
                verified_distinct_key_count: 3,
                verified_distinct_key_weight: 3,
            })
        );
    }

    #[test]
    fn run422_keyset_proof_missing_suite_descriptor_and_identifier_refusals() {
        let calls = Arc::new(Calls::default());
        let key = [1u8];
        let bytes = encode_keyset(1, &[(1, 1, &key)]);
        let missing = TestProvider::new(Vec::new());
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &missing,
                &[0; 32],
                &[proof(1, &key)],
                limits(1, 1, 1),
            ),
            Err(KeysetProofEvaluationError::SuiteNotFound)
        );
        let no_matching_suite = test_provider(1, TestSuite::new(1, Arc::clone(&calls)));
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &no_matching_suite,
                &[0; 32],
                &[proof(2, &key)],
                limits(1, 1, 1),
            ),
            Err(KeysetProofEvaluationError::NoMatchingSuiteEntry)
        );
        let mut mismatch_suite = TestSuite::new(2, Arc::clone(&calls));
        mismatch_suite.verify_mode = VerifyMode::AcceptAny;
        let mismatch = TestProvider::new(vec![(1, Box::new(mismatch_suite))]);
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &mismatch,
                &[0; 32],
                &[proof(1, b"x")],
                limits(1, 1, 1),
            ),
            Err(KeysetProofEvaluationError::SuiteIdMismatch)
        );

        for (mode, expected) in [
            (
                DescriptorMode::Unsupported,
                KeysetProofEvaluationError::DescriptorUnsupported,
            ),
            (
                DescriptorMode::Malformed,
                KeysetProofEvaluationError::DescriptorMalformed,
            ),
            (
                DescriptorMode::NonCanonical,
                KeysetProofEvaluationError::DescriptorNonCanonical,
            ),
            (
                DescriptorMode::SubstituteSpan,
                KeysetProofEvaluationError::DescriptorKeySpanMismatch,
            ),
        ] {
            let mut suite = TestSuite::new(1, Arc::clone(&calls));
            suite.descriptor_mode = mode;
            let provider = test_provider(1, suite);
            assert_eq!(
                evaluate_stored_keyset_proofs::<1>(
                    view(&bytes),
                    &provider,
                    &[0; 32],
                    &[proof(1, &key)],
                    limits(1, 1, 1),
                ),
                Err(expected)
            );
        }

        let provider = test_provider(1, TestSuite::new(1, Arc::clone(&calls)));
        let mut short_identifiers = limits(1, 1, 1);
        short_identifiers.max_algorithm_parameter_identifier_bytes =
            b"test-algorithm".len() + b"test-parameters".len() - 1;
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &provider,
                &[0; 32],
                &[proof(1, &key)],
                short_identifiers,
            ),
            Err(KeysetProofEvaluationError::IdentifierLengthLimit)
        );
        let mut exact_identifiers = short_identifiers;
        exact_identifiers.max_algorithm_parameter_identifier_bytes += 1;
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &provider,
                &[0; 32],
                &[proof(1, &key)],
                exact_identifiers,
            )
            .unwrap()
            .verified_distinct_key_weight,
            1
        );
    }

    #[test]
    fn run422_keyset_proof_non_invalid_backend_failure_fails_closed() {
        let calls = Arc::new(Calls::default());
        let mut suite = TestSuite::new(1, Arc::clone(&calls));
        suite.verify_mode = VerifyMode::FailOnKey(2);
        let provider = test_provider(1, suite);
        let first = [1u8];
        let second = [2u8];
        let bytes = encode_keyset(1, &[(1, 1, &first), (1, 1, &second)]);
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&bytes),
                &provider,
                &[0; 32],
                &[proof(1, &first)],
                limits(1, 1, 1),
            ),
            Err(KeysetProofEvaluationError::VerificationFailure)
        );
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn run422_keyset_proof_preflight_capacity_and_byte_limits() {
        let calls = Arc::new(Calls::default());
        let suite = TestSuite::new(1, Arc::clone(&calls));
        let provider = test_provider(1, suite);
        let key = [1u8];
        let bytes = encode_keyset(1, &[(1, 1, &key)]);
        let one = [proof(1, &key)];

        assert_eq!(
            evaluate_stored_keyset_proofs::<0>(
                view(&bytes),
                &provider,
                &[0; 32],
                &one,
                limits(1, 1, 1),
            ),
            Err(KeysetProofEvaluationError::EntryCountExceedsWorkspace)
        );
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &provider,
                &[0; 32],
                &one,
                limits(0, 1, 1),
            ),
            Err(KeysetProofEvaluationError::ProofCountLimit)
        );
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &provider,
                &[0; 32],
                &one,
                limits(1, 0, 1),
            ),
            Err(KeysetProofEvaluationError::SignatureByteLimit)
        );
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &provider,
                &[0; 32],
                &one,
                limits(1, 1, 0),
            ),
            Err(KeysetProofEvaluationError::AggregateSignatureByteLimit)
        );
        assert_eq!(provider.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(calls.descriptors.load(Ordering::SeqCst), 0);
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 0);

        let exact = limits(1, 1, 1);
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(view(&bytes), &provider, &[0; 32], &one, exact,)
                .unwrap()
                .verified_distinct_key_weight,
            1
        );
        let over_capacity = encode_keyset(1, &[(1, 1, &key), (1, 1, &[2])]);
        let calls_before = provider.lookups.load(Ordering::SeqCst);
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&over_capacity),
                &provider,
                &[0; 32],
                &one,
                exact,
            ),
            Err(KeysetProofEvaluationError::EntryCountExceedsWorkspace)
        );
        assert_eq!(provider.lookups.load(Ordering::SeqCst), calls_before);

        let two_proofs = [proof(1, &key), proof(1, &key)];
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &provider,
                &[0; 32],
                &two_proofs,
                limits(2, 1, 2),
            )
            .unwrap()
            .evaluated_proof_count,
            2
        );
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &provider,
                &[0; 32],
                &two_proofs,
                limits(2, 1, 1),
            ),
            Err(KeysetProofEvaluationError::AggregateSignatureByteLimit)
        );

        let empty_signature = [proof(1, &[])];
        let mut accepts_empty = TestSuite::new(1, Arc::new(Calls::default()));
        accepts_empty.verify_mode = VerifyMode::AcceptAny;
        let empty_provider = test_provider(1, accepts_empty);
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&bytes),
                &empty_provider,
                &[0; 32],
                &empty_signature,
                limits(1, 0, 0),
            )
            .unwrap()
            .verified_distinct_key_weight,
            1
        );
    }

    #[test]
    fn run422_keyset_proof_semantic_refusals_and_threshold_budget() {
        let calls = Arc::new(Calls::default());
        let mut suite = TestSuite::new(1, Arc::clone(&calls));
        suite.verify_mode = VerifyMode::SignatureEqualsKey;
        let provider = test_provider(1, suite);
        let one = [1u8];
        let two = [2u8];
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&encode_keyset(1, &[])),
                &provider,
                &[0; 32],
                &[proof(1, &one)],
                limits(1, 1, 1),
            ),
            Err(KeysetProofEvaluationError::EmptyKeyset)
        );
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                view(&encode_keyset(0, &[(1, 1, &one)])),
                &provider,
                &[0; 32],
                &[proof(1, &one)],
                limits(1, 1, 1),
            ),
            Err(KeysetProofEvaluationError::ZeroThreshold)
        );
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&encode_keyset(3, &[(1, 2, &one), (1, 2, &two)])),
                &provider,
                &[0; 32],
                &[proof(1, &one)],
                limits(1, 1, 2),
            ),
            Err(KeysetProofEvaluationError::ThresholdUnreachable)
        );

        let reachable = encode_keyset(3, &[(1, 2, &one), (1, 2, &two)]);
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&reachable),
                &provider,
                &[0; 32],
                &[proof(1, &one)],
                limits(2, 1, 1),
            ),
            Err(KeysetProofEvaluationError::InsufficientVerifiedWeight)
        );
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&reachable),
                &provider,
                &[0; 32],
                &[proof(1, &one), proof(1, &two)],
                limits(2, 1, 2),
            )
            .unwrap()
            .verified_distinct_key_weight,
            4
        );

        let mut invalid_unused = TestSuite::new(2, Arc::clone(&calls));
        invalid_unused.descriptor_mode = DescriptorMode::Malformed;
        let valid_suite = TestSuite::new(1, Arc::clone(&calls));
        let all_entries_provider = TestProvider::new(vec![
            (1, Box::new(valid_suite)),
            (2, Box::new(invalid_unused)),
        ]);
        let invalid_unused_bytes = encode_keyset(1, &[(1, 1, &one), (2, 0, &two)]);
        calls.verifications.store(0, Ordering::SeqCst);
        assert_eq!(
            evaluate_stored_keyset_proofs::<2>(
                view(&invalid_unused_bytes),
                &all_entries_provider,
                &[0; 32],
                &[proof(1, &one)],
                limits(1, 1, 1),
            ),
            Err(KeysetProofEvaluationError::DescriptorMalformed)
        );
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn run422_keyset_proof_scalar_aggregate_overflow_and_workspaces() {
        assert_eq!(
            checked_identifier_byte_len(usize::MAX, 1),
            Err(KeysetSemanticAnalysisError::IdentifierLengthOverflow)
        );
        assert_eq!(
            checked_add_signature_bytes(usize::MAX, 1, usize::MAX),
            Err(KeysetProofEvaluationError::AggregateSignatureByteOverflow)
        );
        assert_eq!(
            core::mem::size_of::<ProofWorkspace<'static, 'static, 0>>(),
            core::mem::size_of::<Workspace<'static, 0>>()
        );
        eprintln!(
            "proof workspace bytes: N=0 {} N=1 {} N=2 {} N=16 {}; identities N=0 {} N=1 {} N=2 {} N=16 {}; candidate={} candidate_option={} signature_proof={} limits={} semantic_summary={} result_summary={} error={}",
            core::mem::size_of::<ProofWorkspace<'static, 'static, 0>>(),
            core::mem::size_of::<ProofWorkspace<'static, 'static, 1>>(),
            core::mem::size_of::<ProofWorkspace<'static, 'static, 2>>(),
            core::mem::size_of::<ProofWorkspace<'static, 'static, 16>>(),
            core::mem::size_of::<Workspace<'static, 0>>(),
            core::mem::size_of::<Workspace<'static, 1>>(),
            core::mem::size_of::<Workspace<'static, 2>>(),
            core::mem::size_of::<Workspace<'static, 16>>(),
            core::mem::size_of::<PreparedCandidate<'static, 'static>>(),
            core::mem::size_of::<Option<PreparedCandidate<'static, 'static>>>(),
            core::mem::size_of::<KeysetSignatureProof<'static>>(),
            core::mem::size_of::<KeysetProofEvaluationLimits>(),
            core::mem::size_of::<KeysetSemanticAnalysisSummary>(),
            core::mem::size_of::<KeysetProofEvaluationSummary>(),
            core::mem::size_of::<KeysetProofEvaluationError>(),
        );
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestAccount {
        id: AccountId,
        header: AccountHeader,
        data: Vec<u8>,
    }

    struct RecordingStore {
        response: RefCell<Option<Account>>,
        requested: Cell<Option<(AccountId, usize)>>,
        bounded_reads: Cell<usize>,
        gets: Cell<usize>,
        puts: Cell<usize>,
        deletes: Cell<usize>,
    }

    impl AccountStore for RecordingStore {
        fn get(&self, _id: &AccountId) -> Option<Account> {
            self.gets.set(self.gets.get() + 1);
            panic!("legacy get must not be used by this composition");
        }

        fn get_bounded(
            &self,
            id: &AccountId,
            max_data_bytes: usize,
        ) -> Result<Option<Account>, crate::store::BoundedReadError> {
            self.bounded_reads.set(self.bounded_reads.get() + 1);
            self.requested.set(Some((*id, max_data_bytes)));
            let account = self.response.borrow_mut().take();
            if account
                .as_ref()
                .is_some_and(|account| account.data.len() > max_data_bytes)
            {
                return Err(crate::store::BoundedReadError::Oversized);
            }
            Ok(account)
        }

        fn put(&mut self, _account: Account) -> Result<(), ExecutionError> {
            self.puts.set(self.puts.get() + 1);
            panic!("evaluation must not write accounts");
        }

        fn delete(&mut self, _id: &AccountId) -> Result<(), ExecutionError> {
            self.deletes.set(self.deletes.get() + 1);
            panic!("evaluation must not delete accounts");
        }
    }

    #[test]
    fn run422_keyset_proof_composes_bounded_read_parser_streaming_digest() {
        let (key, secret) = MlDsa44Backend::generate_keypair().unwrap();
        let keyset_data = encode_keyset(1, &[(100, 1, &key)]);
        let account_id = [0x31; 32];
        let account = Account {
            id: account_id,
            header: AccountHeader {
                owner: KEYSET_PROGRAM_ID,
                lamports: 19,
                is_executable: false,
                rent_epoch: 7,
                reserved: [0xA5; 8],
            },
            data: keyset_data,
        };
        let original_account = TestAccount {
            id: account.id,
            header: account.header.clone(),
            data: account.data.clone(),
        };
        let store = RecordingStore {
            response: RefCell::new(Some(account)),
            requested: Cell::new(None),
            bounded_reads: Cell::new(0),
            gets: Cell::new(0),
            puts: Cell::new(0),
            deletes: Cell::new(0),
        };
        let mut transaction = Transaction {
            version: 1,
            chain_id: 7,
            payer: [0x41; 32],
            nonce: 8,
            fee_limit: 99,
            accounts: vec![TxAccountMeta {
                account_id,
                flags: 1,
                access_hint: 1,
                reserved0: [0; 2],
            }],
            program_id: [0x51; 32],
            call_data: vec![1, 3, 3, 7],
            auths: Vec::new(),
        };
        let original_transaction = transaction.clone();
        let returned =
            read_keyset_owned_account_bounded(&store, &account_id, original_account.data.len())
                .unwrap();
        assert_eq!(store.bounded_reads.get(), 1);
        assert_eq!(
            store.requested.get(),
            Some((account_id, original_account.data.len()))
        );
        assert_eq!(store.gets.get(), 0);
        assert_eq!(store.puts.get(), 0);
        assert_eq!(store.deletes.get(), 0);
        assert_eq!(
            returned,
            Account {
                id: original_account.id,
                header: original_account.header.clone(),
                data: original_account.data.clone(),
            }
        );

        let keyset = parse_stored_keyset(
            &returned.data,
            StoredKeysetLimits {
                max_encoded_bytes: returned.data.len(),
                max_entries: 1,
                max_key_bytes: key.len(),
                max_total_key_bytes: key.len(),
            },
        )
        .unwrap();
        let digest = try_tx_digest_streaming(&transaction).unwrap();
        let signature = MlDsa44Backend::sign(&secret, &digest).unwrap();
        transaction.auths.push(TxAuth {
            account_index: 0,
            suite_id: 100,
            reserved: 0,
            signature: signature.clone(),
        });
        let proof = proof(100, &signature);
        let provider = StaticCryptoProvider::new()
            .with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(100)));
        assert_eq!(
            evaluate_stored_keyset_proofs::<1>(
                keyset,
                &provider,
                &digest,
                &[proof],
                limits(1, signature.len(), signature.len()),
            )
            .unwrap(),
            KeysetProofEvaluationSummary {
                evaluated_proof_count: 1,
                verified_distinct_key_count: 1,
                verified_distinct_key_weight: 1,
            }
        );
        assert_eq!(transaction, {
            let mut expected = original_transaction;
            expected.auths.push(TxAuth {
                account_index: 0,
                suite_id: 100,
                reserved: 0,
                signature,
            });
            expected
        });
        assert_eq!(
            returned,
            Account {
                id: original_account.id,
                header: original_account.header,
                data: original_account.data,
            }
        );
        assert_eq!(store.bounded_reads.get(), 1);
        assert_eq!(store.gets.get(), 0);
        assert_eq!(store.puts.get(), 0);
        assert_eq!(store.deletes.get(), 0);
        assert!(store.response.borrow().is_none());
    }
}
