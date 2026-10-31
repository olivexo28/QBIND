//! Bounded canonical-keyset semantics analysis.
//!
//! These APIs report descriptor consistency and mathematical threshold
//! reachability only. They do not verify signatures, admit account metadata,
//! establish current authorization, or authorize execution.

use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError};
use qbind_crypto::CryptoProvider;
use qbind_serde::keyset::StoredKeysetView;
use qbind_wire::keyset::CreateKeysetView;

/// Fixed-size refusal reasons; no input bytes are retained or formatted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeysetSemanticAnalysisError {
    EntryCountExceedsWorkspace,
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
}

/// Mathematical summary only; this is not a signature, authorization, or
/// permission to execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeysetSemanticAnalysisSummary {
    pub encoded_entry_count: u16,
    pub distinct_canonical_identity_count: u16,
    pub total_distinct_key_weight: u64,
    pub attainable_weight: u64,
    pub minimum_distinct_key_proofs: u16,
}

#[derive(Clone, Copy)]
struct Record<'a> {
    descriptor: Option<CanonicalKeyDescriptor<'a>>,
    weight: u16,
}

impl Record<'_> {
    const EMPTY: Self = Self {
        descriptor: None,
        weight: 0,
    };
}

struct Workspace<'a, const N: usize> {
    records: [Record<'a>; N],
    distinct_count: usize,
}

impl<'a, const N: usize> Workspace<'a, N> {
    const fn new() -> Self {
        Self {
            records: [Record::EMPTY; N],
            distinct_count: 0,
        }
    }
}

/// Analyze fully parsed stored-state metadata using caller-selected bounds.
///
/// `N` is an implementation capacity chosen at compile time by the caller,
/// not a protocol limit. The proof and identifier budgets are scalar inputs
/// and never control storage size.
pub fn analyze_stored_keyset_semantics<const N: usize>(
    keyset: StoredKeysetView<'_>,
    provider: &dyn CryptoProvider,
    max_distinct_key_proofs: usize,
    max_algorithm_parameter_identifier_bytes: usize,
) -> Result<KeysetSemanticAnalysisSummary, KeysetSemanticAnalysisError> {
    analyze_entries::<N, _>(
        keyset.threshold(),
        keyset.entry_count(),
        keyset
            .entries()
            .map(|entry| (entry.suite_id, entry.weight, entry.pubkey_bytes)),
        provider,
        max_distinct_key_proofs,
        max_algorithm_parameter_identifier_bytes,
    )
}

/// Analyze fully parsed create-call metadata using caller-selected bounds.
///
/// `N` is an implementation capacity chosen at compile time by the caller,
/// not a protocol limit. The proof and identifier budgets are scalar inputs
/// and never control storage size.
pub fn analyze_create_keyset_semantics<const N: usize>(
    keyset: CreateKeysetView<'_>,
    provider: &dyn CryptoProvider,
    max_distinct_key_proofs: usize,
    max_algorithm_parameter_identifier_bytes: usize,
) -> Result<KeysetSemanticAnalysisSummary, KeysetSemanticAnalysisError> {
    analyze_entries::<N, _>(
        keyset.threshold(),
        keyset.entry_count(),
        keyset
            .entries()
            .map(|entry| (entry.suite_id, entry.weight, entry.pubkey_bytes)),
        provider,
        max_distinct_key_proofs,
        max_algorithm_parameter_identifier_bytes,
    )
}

fn analyze_entries<'a, const N: usize, I>(
    threshold: u16,
    entry_count: u16,
    entries: I,
    provider: &dyn CryptoProvider,
    max_distinct_key_proofs: usize,
    max_identifier_bytes: usize,
) -> Result<KeysetSemanticAnalysisSummary, KeysetSemanticAnalysisError>
where
    I: Iterator<Item = (u8, u16, &'a [u8])>,
{
    use KeysetSemanticAnalysisError as Error;

    // Charge encoded entries, before any provider lookup or descriptor call.
    if usize::from(entry_count) > N {
        return Err(Error::EntryCountExceedsWorkspace);
    }
    if entry_count == 0 {
        return Err(Error::EmptyKeyset);
    }
    if threshold == 0 {
        return Err(Error::ZeroThreshold);
    }

    let mut workspace = Workspace::<N>::new();
    for (requested_suite_id, weight, original_key_span) in entries {
        let suite = provider
            .signature_suite(requested_suite_id)
            .ok_or(Error::SuiteNotFound)?;
        if suite.suite_id() != requested_suite_id {
            return Err(Error::SuiteIdMismatch);
        }

        let descriptor = suite
            .canonical_key_descriptor(original_key_span)
            .map_err(|error| match error {
                KeyDescriptorError::Unsupported => Error::DescriptorUnsupported,
                KeyDescriptorError::Malformed => Error::DescriptorMalformed,
                KeyDescriptorError::NonCanonical => Error::DescriptorNonCanonical,
            })?;

        let identifier_bytes = descriptor
            .algorithm_id
            .len()
            .checked_add(descriptor.parameter_id.len())
            .ok_or(Error::IdentifierLengthOverflow)?;
        if identifier_bytes > max_identifier_bytes {
            return Err(Error::IdentifierLengthLimit);
        }

        // The descriptor API promises a borrowed, non-normalizing key slice.
        // Pointer equality checks provenance only; identity below is exact
        // content equality of all three descriptor fields.
        if descriptor.public_key_encoding.len() != original_key_span.len()
            || !core::ptr::eq(
                descriptor.public_key_encoding.as_ptr(),
                original_key_span.as_ptr(),
            )
        {
            return Err(Error::DescriptorKeySpanMismatch);
        }

        let duplicate = workspace.records[..workspace.distinct_count]
            .iter()
            .position(|record| record.descriptor == Some(descriptor));
        if let Some(index) = duplicate {
            if workspace.records[index].weight != weight {
                return Err(Error::ConflictingDuplicateWeights);
            }
        } else {
            if workspace.distinct_count == N {
                return Err(Error::EntryCountExceedsWorkspace);
            }
            workspace.records[workspace.distinct_count] = Record {
                descriptor: Some(descriptor),
                weight,
            };
            workspace.distinct_count += 1;
        }
    }

    let mut total_distinct_key_weight = 0u64;
    for record in &workspace.records[..workspace.distinct_count] {
        total_distinct_key_weight = total_distinct_key_weight
            .checked_add(u64::from(record.weight))
            .ok_or(Error::WeightOverflow)?;
    }

    // Selection ordering is in-place and O(u^2), where u is the number of
    // distinct identities. Descriptors are never reconstructed or copied.
    for index in 0..workspace.distinct_count {
        let mut greatest = index;
        for candidate in (index + 1)..workspace.distinct_count {
            if workspace.records[candidate].weight > workspace.records[greatest].weight {
                greatest = candidate;
            }
        }
        workspace.records.swap(index, greatest);
    }

    let reachable_count = max_distinct_key_proofs.min(workspace.distinct_count);
    let mut attainable_weight = 0u64;
    for record in &workspace.records[..reachable_count] {
        attainable_weight = attainable_weight
            .checked_add(u64::from(record.weight))
            .ok_or(Error::WeightOverflow)?;
    }
    if u64::from(threshold) > attainable_weight {
        return Err(Error::ThresholdUnreachable);
    }

    let mut minimum_distinct_key_proofs = 0usize;
    let mut highest_weight_sum = 0u64;
    for record in &workspace.records[..reachable_count] {
        highest_weight_sum = highest_weight_sum
            .checked_add(u64::from(record.weight))
            .ok_or(Error::WeightOverflow)?;
        minimum_distinct_key_proofs += 1;
        if highest_weight_sum >= u64::from(threshold) {
            break;
        }
    }

    Ok(KeysetSemanticAnalysisSummary {
        encoded_entry_count: entry_count,
        distinct_canonical_identity_count: u16::try_from(workspace.distinct_count)
            .map_err(|_| Error::EntryCountExceedsWorkspace)?,
        total_distinct_key_weight,
        attainable_weight,
        minimum_distinct_key_proofs: u16::try_from(minimum_distinct_key_proofs)
            .map_err(|_| Error::EntryCountExceedsWorkspace)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_crypto::error::CryptoError;
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_crypto::signature::SignatureSuite;
    use qbind_serde::keyset::{parse_stored_keyset, StoredKeysetLimits};
    use qbind_types::Hash32;
    use qbind_wire::keyset::{parse_create_keyset, CreateKeysetLimits};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Clone, Copy)]
    struct Entry<'a> {
        suite_id: u8,
        weight: u16,
        key: &'a [u8],
    }

    fn stored_bytes(threshold: u16, entries: &[Entry<'_>]) -> Vec<u8> {
        let mut bytes = vec![1, 0, 0, 0];
        bytes.extend_from_slice(&threshold.to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        for entry in entries {
            bytes.push(entry.suite_id);
            bytes.extend_from_slice(&entry.weight.to_le_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&(entry.key.len() as u16).to_le_bytes());
            bytes.extend_from_slice(entry.key);
        }
        bytes
    }

    fn create_bytes(threshold: u16, entries: &[Entry<'_>]) -> Vec<u8> {
        let mut bytes = vec![0x30, 1];
        bytes.extend_from_slice(&[0; 32]);
        bytes.extend_from_slice(&threshold.to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        for entry in entries {
            bytes.push(entry.suite_id);
            bytes.extend_from_slice(&entry.weight.to_le_bytes());
            bytes.extend_from_slice(&(entry.key.len() as u16).to_le_bytes());
            bytes.extend_from_slice(entry.key);
        }
        bytes
    }

    fn stored_view(bytes: &[u8]) -> StoredKeysetView<'_> {
        parse_stored_keyset(
            bytes,
            StoredKeysetLimits {
                max_encoded_bytes: usize::MAX,
                max_entries: usize::MAX,
                max_key_bytes: usize::MAX,
                max_total_key_bytes: usize::MAX,
            },
        )
        .expect("valid stored fixture")
    }

    fn create_view(bytes: &[u8]) -> CreateKeysetView<'_> {
        parse_create_keyset(
            bytes,
            CreateKeysetLimits {
                max_encoded_bytes: usize::MAX,
                max_entries: usize::MAX,
                max_key_bytes: usize::MAX,
                max_total_key_bytes: usize::MAX,
            },
        )
        .expect("valid create fixture")
    }

    #[derive(Default)]
    struct Calls {
        descriptors: AtomicUsize,
        verifications: AtomicUsize,
    }

    #[derive(Clone, Copy)]
    enum DescriptorResult {
        Normal,
        Unsupported,
        Malformed,
        NonCanonical,
        SubstituteSpan,
    }

    struct TestSuite {
        reported_id: u8,
        algorithm_id: &'static [u8],
        parameter_id: &'static [u8],
        result: DescriptorResult,
        calls: Arc<Calls>,
    }

    struct DefaultUnsupportedSuite;

    impl SignatureSuite for DefaultUnsupportedSuite {
        fn suite_id(&self) -> u8 {
            1
        }

        fn public_key_len(&self) -> usize {
            0
        }

        fn signature_len(&self) -> usize {
            0
        }

        fn verify(&self, _pk: &[u8], _digest: &Hash32, _sig: &[u8]) -> Result<(), CryptoError> {
            Err(CryptoError::InvalidSignature)
        }
    }

    impl TestSuite {
        fn new(suite_id: u8) -> Self {
            Self {
                reported_id: suite_id,
                algorithm_id: b"test-algorithm",
                parameter_id: b"test-parameters",
                result: DescriptorResult::Normal,
                calls: Arc::new(Calls::default()),
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

        fn verify(&self, _pk: &[u8], _digest: &Hash32, _sig: &[u8]) -> Result<(), CryptoError> {
            self.calls.verifications.fetch_add(1, Ordering::SeqCst);
            Err(CryptoError::InvalidSignature)
        }

        fn canonical_key_descriptor<'a>(
            &self,
            encoded_public_key: &'a [u8],
        ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
            self.calls.descriptors.fetch_add(1, Ordering::SeqCst);
            match self.result {
                DescriptorResult::Unsupported => Err(KeyDescriptorError::Unsupported),
                DescriptorResult::Malformed => Err(KeyDescriptorError::Malformed),
                DescriptorResult::NonCanonical => Err(KeyDescriptorError::NonCanonical),
                DescriptorResult::Normal => Ok(CanonicalKeyDescriptor {
                    algorithm_id: self.algorithm_id,
                    parameter_id: self.parameter_id,
                    public_key_encoding: encoded_public_key,
                }),
                DescriptorResult::SubstituteSpan => Ok(CanonicalKeyDescriptor {
                    algorithm_id: self.algorithm_id,
                    parameter_id: self.parameter_id,
                    public_key_encoding: b"substituted-key-span",
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

    fn test_suite(id: u8) -> (Box<TestSuite>, Arc<Calls>) {
        let suite = Box::new(TestSuite::new(id));
        let calls = Arc::clone(&suite.calls);
        (suite, calls)
    }

    fn provider_with_one_suite() -> (TestProvider, Arc<Calls>) {
        let (suite, calls) = test_suite(1);
        (TestProvider::new(vec![(1, suite)]), calls)
    }

    #[test]
    fn run422_keyset_semantics_genuine_mldsa_stored_and_create_aliases() {
        let (first_key, _) = MlDsa44Backend::generate_keypair().expect("first genuine key");
        let (second_key, _) = MlDsa44Backend::generate_keypair().expect("second genuine key");
        let first_copy = first_key.clone();
        let entries = [
            Entry {
                suite_id: 100,
                weight: 3,
                key: &first_key,
            },
            Entry {
                suite_id: 100,
                weight: 5,
                key: &second_key,
            },
            Entry {
                suite_id: 101,
                weight: 3,
                key: &first_copy,
            },
        ];
        let provider = TestProvider::new(vec![
            (100, Box::new(qbind_crypto::MlDsa44SignatureSuite::new(100))),
            (101, Box::new(qbind_crypto::MlDsa44SignatureSuite::new(101))),
        ]);
        let stored = stored_bytes(8, &entries);
        let stored_summary =
            analyze_stored_keyset_semantics::<3>(stored_view(&stored), &provider, 2, usize::MAX)
                .expect("stored genuine keys analyze");
        let create = create_bytes(8, &entries);
        let create_summary =
            analyze_create_keyset_semantics::<3>(create_view(&create), &provider, 2, usize::MAX)
                .expect("create genuine keys analyze");

        let expected = KeysetSemanticAnalysisSummary {
            encoded_entry_count: 3,
            distinct_canonical_identity_count: 2,
            total_distinct_key_weight: 8,
            attainable_weight: 8,
            minimum_distinct_key_proofs: 2,
        };
        assert_eq!(stored_summary, expected);
        assert_eq!(create_summary, expected);
    }

    #[test]
    fn run422_keyset_semantics_duplicate_weights_conflict_in_any_order_and_alias() {
        let (suite_one, _) = test_suite(1);
        let (mut suite_alias, _) = test_suite(2);
        suite_alias.algorithm_id = suite_one.algorithm_id;
        suite_alias.parameter_id = suite_one.parameter_id;
        let provider = TestProvider::new(vec![(1, suite_one), (2, suite_alias)]);
        let key = [7u8, 8, 9];

        for entries in [
            [
                Entry {
                    suite_id: 1,
                    weight: 2,
                    key: &key,
                },
                Entry {
                    suite_id: 1,
                    weight: 3,
                    key: &key,
                },
            ],
            [
                Entry {
                    suite_id: 2,
                    weight: 3,
                    key: &key,
                },
                Entry {
                    suite_id: 1,
                    weight: 2,
                    key: &key,
                },
            ],
            [
                Entry {
                    suite_id: 1,
                    weight: 3,
                    key: &key,
                },
                Entry {
                    suite_id: 1,
                    weight: 2,
                    key: &key,
                },
            ],
            [
                Entry {
                    suite_id: 1,
                    weight: 2,
                    key: &key,
                },
                Entry {
                    suite_id: 2,
                    weight: 3,
                    key: &key,
                },
            ],
        ] {
            let bytes = stored_bytes(1, &entries);
            assert_eq!(
                analyze_stored_keyset_semantics::<2>(stored_view(&bytes), &provider, 2, usize::MAX),
                Err(KeysetSemanticAnalysisError::ConflictingDuplicateWeights)
            );
        }

        let equal_entries = [
            Entry {
                suite_id: 1,
                weight: 4,
                key: &key,
            },
            Entry {
                suite_id: 2,
                weight: 4,
                key: &key,
            },
        ];
        let bytes = create_bytes(4, &equal_entries);
        assert_eq!(
            analyze_create_keyset_semantics::<2>(create_view(&bytes), &provider, 1, usize::MAX)
                .expect("equal duplicate weights coalesce"),
            KeysetSemanticAnalysisSummary {
                encoded_entry_count: 2,
                distinct_canonical_identity_count: 1,
                total_distinct_key_weight: 4,
                attainable_weight: 4,
                minimum_distinct_key_proofs: 1,
            }
        );
    }

    #[test]
    fn run422_keyset_semantics_exact_descriptor_fields_remain_distinct() {
        let (base, _) = test_suite(1);
        let (mut other_algorithm, _) = test_suite(2);
        other_algorithm.algorithm_id = b"test-algorithm-other";
        let (mut other_parameters, _) = test_suite(3);
        other_parameters.parameter_id = b"test-parameters-other";
        let provider =
            TestProvider::new(vec![(1, base), (2, other_algorithm), (3, other_parameters)]);
        let common_key = [10u8, 20, 30];
        let other_key = [10u8, 20, 31];
        let entries = [
            Entry {
                suite_id: 1,
                weight: 2,
                key: &common_key,
            },
            Entry {
                suite_id: 2,
                weight: 3,
                key: &common_key,
            },
            Entry {
                suite_id: 3,
                weight: 4,
                key: &common_key,
            },
            Entry {
                suite_id: 1,
                weight: 5,
                key: &other_key,
            },
        ];
        let bytes = stored_bytes(14, &entries);
        assert_eq!(
            analyze_stored_keyset_semantics::<4>(stored_view(&bytes), &provider, 4, usize::MAX)
                .expect("field-distinct identities stay separate"),
            KeysetSemanticAnalysisSummary {
                encoded_entry_count: 4,
                distinct_canonical_identity_count: 4,
                total_distinct_key_weight: 14,
                attainable_weight: 14,
                minimum_distinct_key_proofs: 4,
            }
        );
    }

    #[test]
    fn run422_keyset_semantics_zero_weight_validates_and_conflicts() {
        let (suite, calls) = provider_with_one_suite();
        let provider = suite;
        let key = [1u8];
        let entries = [
            Entry {
                suite_id: 1,
                weight: 0,
                key: &key,
            },
            Entry {
                suite_id: 1,
                weight: 2,
                key: &[2],
            },
        ];
        let bytes = create_bytes(2, &entries);
        assert_eq!(
            analyze_create_keyset_semantics::<2>(create_view(&bytes), &provider, 1, usize::MAX)
                .expect("zero-weight distinct key is valid"),
            KeysetSemanticAnalysisSummary {
                encoded_entry_count: 2,
                distinct_canonical_identity_count: 2,
                total_distinct_key_weight: 2,
                attainable_weight: 2,
                minimum_distinct_key_proofs: 1,
            }
        );
        assert_eq!(calls.descriptors.load(Ordering::SeqCst), 2);

        let mut invalid_suite = TestSuite::new(1);
        invalid_suite.result = DescriptorResult::Malformed;
        let invalid_provider = TestProvider::new(vec![(1, Box::new(invalid_suite))]);
        let zero_weight = [Entry {
            suite_id: 1,
            weight: 0,
            key: &key,
        }];
        let bytes = stored_bytes(1, &zero_weight);
        assert_eq!(
            analyze_stored_keyset_semantics::<1>(
                stored_view(&bytes),
                &invalid_provider,
                1,
                usize::MAX
            ),
            Err(KeysetSemanticAnalysisError::DescriptorMalformed)
        );

        let conflict = [
            Entry {
                suite_id: 1,
                weight: 0,
                key: &key,
            },
            Entry {
                suite_id: 1,
                weight: 1,
                key: &key,
            },
        ];
        let bytes = create_bytes(1, &conflict);
        assert_eq!(
            analyze_create_keyset_semantics::<2>(create_view(&bytes), &provider, 2, usize::MAX),
            Err(KeysetSemanticAnalysisError::ConflictingDuplicateWeights)
        );
    }

    #[test]
    fn run422_keyset_semantics_threshold_and_proof_budget_math() {
        let (provider, _) = provider_with_one_suite();
        let one = [1u8];
        let two = [2u8];
        let entries = [
            Entry {
                suite_id: 1,
                weight: 3,
                key: &one,
            },
            Entry {
                suite_id: 1,
                weight: 2,
                key: &two,
            },
        ];
        let exact = stored_bytes(5, &entries);
        assert_eq!(
            analyze_stored_keyset_semantics::<2>(stored_view(&exact), &provider, 2, usize::MAX)
                .expect("exact threshold is reachable")
                .minimum_distinct_key_proofs,
            2
        );
        let below_budget = create_bytes(4, &entries);
        assert_eq!(
            analyze_create_keyset_semantics::<2>(
                create_view(&below_budget),
                &provider,
                1,
                usize::MAX
            ),
            Err(KeysetSemanticAnalysisError::ThresholdUnreachable)
        );
        assert_eq!(
            analyze_stored_keyset_semantics::<2>(stored_view(&exact), &provider, 0, usize::MAX),
            Err(KeysetSemanticAnalysisError::ThresholdUnreachable)
        );

        let zero_threshold = stored_bytes(0, &entries);
        assert_eq!(
            analyze_stored_keyset_semantics::<2>(
                stored_view(&zero_threshold),
                &provider,
                2,
                usize::MAX
            ),
            Err(KeysetSemanticAnalysisError::ZeroThreshold)
        );
        let empty = stored_bytes(1, &[]);
        assert_eq!(
            analyze_stored_keyset_semantics::<2>(stored_view(&empty), &provider, 2, usize::MAX),
            Err(KeysetSemanticAnalysisError::EmptyKeyset)
        );

        let sixteen_keys: Vec<[u8; 1]> = (0..16).map(|value| [value]).collect();
        let many: Vec<Entry<'_>> = sixteen_keys
            .iter()
            .map(|key| Entry {
                suite_id: 1,
                weight: 1,
                key,
            })
            .collect();
        let sixteen = create_bytes(16, &many);
        assert_eq!(
            analyze_create_keyset_semantics::<16>(create_view(&sixteen), &provider, 8, usize::MAX),
            Err(KeysetSemanticAnalysisError::ThresholdUnreachable)
        );
        assert_eq!(
            analyze_create_keyset_semantics::<16>(create_view(&sixteen), &provider, 16, usize::MAX)
                .expect("all sixteen proofs reach threshold")
                .minimum_distinct_key_proofs,
            16
        );
    }

    #[test]
    fn run422_keyset_semantics_weight_sum_exceeds_u16_without_wrapping() {
        let (provider, _) = provider_with_one_suite();
        let first = [1u8];
        let second = [2u8];
        let entries = [
            Entry {
                suite_id: 1,
                weight: u16::MAX,
                key: &first,
            },
            Entry {
                suite_id: 1,
                weight: 1,
                key: &second,
            },
        ];
        let bytes = stored_bytes(u16::MAX, &entries);
        let summary =
            analyze_stored_keyset_semantics::<2>(stored_view(&bytes), &provider, 2, usize::MAX)
                .expect("sum above u16 maximum is represented");
        assert_eq!(summary.total_distinct_key_weight, 65_536);
        assert_eq!(summary.attainable_weight, 65_536);
        assert_eq!(summary.minimum_distinct_key_proofs, 1);
    }

    #[test]
    fn run422_keyset_semantics_suite_and_descriptor_failures() {
        let key = [1u8];
        let entry = [Entry {
            suite_id: 1,
            weight: 1,
            key: &key,
        }];
        let missing_provider = TestProvider::new(Vec::new());
        let bytes = stored_bytes(1, &entry);
        assert_eq!(
            analyze_stored_keyset_semantics::<1>(
                stored_view(&bytes),
                &missing_provider,
                1,
                usize::MAX
            ),
            Err(KeysetSemanticAnalysisError::SuiteNotFound)
        );

        let mismatch = TestSuite::new(2);
        let mismatch_provider = TestProvider::new(vec![(1, Box::new(mismatch))]);
        assert_eq!(
            analyze_stored_keyset_semantics::<1>(
                stored_view(&bytes),
                &mismatch_provider,
                1,
                usize::MAX
            ),
            Err(KeysetSemanticAnalysisError::SuiteIdMismatch)
        );

        for (result, expected) in [
            (
                DescriptorResult::Unsupported,
                KeysetSemanticAnalysisError::DescriptorUnsupported,
            ),
            (
                DescriptorResult::Malformed,
                KeysetSemanticAnalysisError::DescriptorMalformed,
            ),
            (
                DescriptorResult::NonCanonical,
                KeysetSemanticAnalysisError::DescriptorNonCanonical,
            ),
        ] {
            let mut controlled = TestSuite::new(1);
            controlled.result = result;
            let controlled_provider = TestProvider::new(vec![(1, Box::new(controlled))]);
            assert_eq!(
                analyze_create_keyset_semantics::<1>(
                    create_view(&create_bytes(1, &entry)),
                    &controlled_provider,
                    1,
                    usize::MAX
                ),
                Err(expected)
            );
        }

        let default_provider = TestProvider::new(vec![(1, Box::new(DefaultUnsupportedSuite))]);
        assert_eq!(
            analyze_stored_keyset_semantics::<1>(
                stored_view(&bytes),
                &default_provider,
                1,
                usize::MAX
            ),
            Err(KeysetSemanticAnalysisError::DescriptorUnsupported)
        );
    }

    #[test]
    fn run422_keyset_semantics_descriptor_span_and_identifier_limits() {
        let key = [1u8];
        let entry = [Entry {
            suite_id: 1,
            weight: 1,
            key: &key,
        }];
        let bytes = stored_bytes(1, &entry);

        let mut substituted = TestSuite::new(1);
        substituted.result = DescriptorResult::SubstituteSpan;
        let substituted_provider = TestProvider::new(vec![(1, Box::new(substituted))]);
        assert_eq!(
            analyze_stored_keyset_semantics::<1>(
                stored_view(&bytes),
                &substituted_provider,
                1,
                usize::MAX
            ),
            Err(KeysetSemanticAnalysisError::DescriptorKeySpanMismatch)
        );

        let (provider, _) = provider_with_one_suite();
        assert_eq!(
            analyze_stored_keyset_semantics::<1>(
                stored_view(&bytes),
                &provider,
                1,
                b"test-algorithm".len() + b"test-parameters".len()
            )
            .expect("exact identifier budget"),
            KeysetSemanticAnalysisSummary {
                encoded_entry_count: 1,
                distinct_canonical_identity_count: 1,
                total_distinct_key_weight: 1,
                attainable_weight: 1,
                minimum_distinct_key_proofs: 1,
            }
        );
        assert_eq!(
            analyze_create_keyset_semantics::<1>(
                create_view(&create_bytes(1, &entry)),
                &provider,
                1,
                b"test-algorithm".len() + b"test-parameters".len() - 1
            ),
            Err(KeysetSemanticAnalysisError::IdentifierLengthLimit)
        );
    }

    #[test]
    fn run422_keyset_semantics_checks_final_and_zero_weight_entries() {
        let key_a = [1u8];
        let key_b = [2u8];
        let mut malformed = TestSuite::new(2);
        malformed.result = DescriptorResult::Malformed;
        let (normal, calls) = test_suite(1);
        let provider = TestProvider::new(vec![(1, normal), (2, Box::new(malformed))]);

        let final_invalid = [
            Entry {
                suite_id: 1,
                weight: 2,
                key: &key_a,
            },
            Entry {
                suite_id: 2,
                weight: 0,
                key: &key_b,
            },
        ];
        let bytes = stored_bytes(1, &final_invalid);
        assert_eq!(
            analyze_stored_keyset_semantics::<2>(stored_view(&bytes), &provider, 2, usize::MAX),
            Err(KeysetSemanticAnalysisError::DescriptorMalformed)
        );
        assert_eq!(calls.descriptors.load(Ordering::SeqCst), 1);

        let invalid_zero = [Entry {
            suite_id: 2,
            weight: 0,
            key: &key_b,
        }];
        let bytes = create_bytes(1, &invalid_zero);
        assert_eq!(
            analyze_create_keyset_semantics::<1>(create_view(&bytes), &provider, 1, usize::MAX),
            Err(KeysetSemanticAnalysisError::DescriptorMalformed)
        );
    }

    #[test]
    fn run422_keyset_semantics_capacity_refuses_before_provider_calls() {
        let (provider, _) = provider_with_one_suite();
        let (over_provider, over_calls) = provider_with_one_suite();
        let keys = [[1u8], [2u8], [3u8]];
        let entries: Vec<Entry<'_>> = keys
            .iter()
            .map(|key| Entry {
                suite_id: 1,
                weight: 1,
                key,
            })
            .collect();
        let exact_capacity = stored_bytes(1, &entries[..2]);
        assert!(analyze_stored_keyset_semantics::<2>(
            stored_view(&exact_capacity),
            &provider,
            2,
            usize::MAX
        )
        .is_ok());

        let too_many = create_bytes(1, &entries);
        assert_eq!(
            analyze_create_keyset_semantics::<2>(
                create_view(&too_many),
                &over_provider,
                usize::MAX,
                usize::MAX
            ),
            Err(KeysetSemanticAnalysisError::EntryCountExceedsWorkspace)
        );
        assert_eq!(over_provider.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(over_calls.descriptors.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn run422_keyset_semantics_usize_max_budgets_are_not_storage_sizes() {
        let (provider, _) = provider_with_one_suite();
        let key = [1u8];
        let entry = [Entry {
            suite_id: 1,
            weight: 7,
            key: &key,
        }];
        let bytes = create_bytes(7, &entry);
        let summary = analyze_create_keyset_semantics::<1>(
            create_view(&bytes),
            &provider,
            usize::MAX,
            usize::MAX,
        )
        .expect("maximum scalar budgets do not change workspace");
        assert_eq!(summary.attainable_weight, 7);
        eprintln!(
            "workspace layout: Record={} bytes; Workspace<1>={} bytes; Workspace<16>={} bytes",
            core::mem::size_of::<Record<'static>>(),
            core::mem::size_of::<Workspace<'static, 1>>(),
            core::mem::size_of::<Workspace<'static, 16>>()
        );
    }

    #[test]
    fn run422_keyset_semantics_permutations_preserve_results_and_conflicts() {
        let (provider, _) = provider_with_one_suite();
        let first = [1u8];
        let second = [2u8];
        let third = [3u8];
        let permutations = [
            [&first[..], &second[..], &third[..]],
            [&third[..], &first[..], &second[..]],
            [&second[..], &third[..], &first[..]],
        ];
        let expected = KeysetSemanticAnalysisSummary {
            encoded_entry_count: 3,
            distinct_canonical_identity_count: 3,
            total_distinct_key_weight: 9,
            attainable_weight: 7,
            minimum_distinct_key_proofs: 2,
        };
        for permutation in permutations {
            let entries: Vec<Entry<'_>> = permutation
                .iter()
                .map(|key| Entry {
                    suite_id: 1,
                    weight: if key[0] == 1 { 5 } else { 2 },
                    key,
                })
                .collect();
            let bytes = create_bytes(7, &entries);
            assert_eq!(
                analyze_create_keyset_semantics::<3>(create_view(&bytes), &provider, 2, usize::MAX),
                Ok(expected)
            );
        }
        let conflicting = [
            Entry {
                suite_id: 1,
                weight: 1,
                key: &first,
            },
            Entry {
                suite_id: 1,
                weight: 2,
                key: &first,
            },
            Entry {
                suite_id: 1,
                weight: 1,
                key: &second,
            },
        ];
        let bytes = create_bytes(1, &conflicting);
        assert_eq!(
            analyze_create_keyset_semantics::<3>(create_view(&bytes), &provider, 3, usize::MAX),
            Err(KeysetSemanticAnalysisError::ConflictingDuplicateWeights)
        );
        let reversed = [conflicting[2], conflicting[1], conflicting[0]];
        let bytes = stored_bytes(1, &reversed);
        assert_eq!(
            analyze_stored_keyset_semantics::<3>(stored_view(&bytes), &provider, 3, usize::MAX),
            Err(KeysetSemanticAnalysisError::ConflictingDuplicateWeights)
        );
    }

    #[test]
    fn run422_keyset_semantics_calls_once_preserves_bytes_and_repeats() {
        let (provider, calls) = provider_with_one_suite();
        let first = [1u8, 2];
        let second = [3u8, 4];
        let entries = [
            Entry {
                suite_id: 1,
                weight: 2,
                key: &first,
            },
            Entry {
                suite_id: 1,
                weight: 2,
                key: &second,
            },
            Entry {
                suite_id: 1,
                weight: 2,
                key: &first,
            },
        ];
        let stored = stored_bytes(4, &entries);
        let original_stored = stored.clone();
        let view = stored_view(&stored);
        let expected = analyze_stored_keyset_semantics::<3>(view, &provider, 2, usize::MAX)
            .expect("complete analysis");
        assert_eq!(
            analyze_stored_keyset_semantics::<3>(view, &provider, 2, usize::MAX),
            Ok(expected)
        );
        assert_eq!(stored, original_stored);

        let create = create_bytes(4, &entries);
        let original_create = create.clone();
        let create_view = create_view(&create);
        assert_eq!(
            analyze_create_keyset_semantics::<3>(create_view, &provider, 2, usize::MAX),
            Ok(expected)
        );
        assert_eq!(create, original_create);
        assert_eq!(provider.lookups.load(Ordering::SeqCst), 9);
        assert_eq!(calls.descriptors.load(Ordering::SeqCst), 9);
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn run422_keyset_semantics_workspace_has_fixed_record_layout() {
        assert_eq!(
            core::mem::size_of::<Workspace<'static, 16>>(),
            16 * core::mem::size_of::<Record<'static>>() + core::mem::size_of::<usize>()
        );
    }
}
