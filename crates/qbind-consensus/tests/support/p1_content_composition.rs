//! Test-only composition of the provider with the existing content experiment.

use super::*;
#[path = "../content_binding_experiment_tests.rs"]
mod content;

struct Fixture {
    expected: ExpectedCatalogFixture,
    experiment: content::Fixture,
}

impl Fixture {
    fn new() -> Self {
        let experiment = content::Fixture::new(content::TestDefect::default());
        let mut expected = ExpectedCatalogFixture::new();
        let statement = &experiment.statement;
        expected.context.network = [0; 32];
        expected.context.network[..8].copy_from_slice(&statement.chain.to_le_bytes());
        expected.context.schema_version = statement.version;
        expected.context.purpose = statement.purpose;
        expected.context.epoch = statement.epoch;
        expected.context.authority = statement.authority;
        expected.context.members = experiment
            .public
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let mut identity = [0; 32];
                identity[..2].copy_from_slice(&(index as u16).to_le_bytes());
                Member {
                    identity,
                    public_key: key.clone(),
                    weight: 1,
                }
            })
            .collect();
        expected.context.threshold = content::QUORUM as u64;
        validate_candidate(&expected.context, &Rc::new(RefCell::new(Trace::default()))).unwrap();
        Self {
            expected,
            experiment,
        }
    }

    fn admit(&self, slot: &ProviderSlot) -> AdmittedTestContext {
        slot.admit_decoded(
            &self.expected,
            self.expected.context.clone(),
            Currentness::Available,
        )
        .unwrap()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CompositionRefusal {
    Provider(Refusal),
    ContextMismatch,
    MappingMismatch,
    Verification(content::Refusal),
}

#[derive(Default)]
struct CompositionTrace {
    callbacks: usize,
    context_checks: usize,
    mapping_checks: usize,
    signature_copy_bytes: usize,
    frame_constructions: usize,
    frame_bytes: usize,
    frame_signature_bytes: usize,
    verifier_calls: usize,
    verification_successes: usize,
    selected: Option<Candidate>,
    verification: content::Trace,
}

#[derive(Clone, Copy)]
enum Selection {
    Bound,
    WitnessDefect,
}

fn build_evidence_frame(
    entries: &[&[u8]],
    trace: &mut CompositionTrace,
) -> Result<Vec<u8>, Refusal> {
    let lengths = entries.iter().map(|entry| entry.len()).collect::<Vec<_>>();
    let total = checked_borrowed_evidence_frame_len(&lengths)?;
    let count = u8::try_from(entries.len()).map_err(|_| Refusal::LengthOverflow)?;
    let declared_total = u32::try_from(total).map_err(|_| Refusal::LengthOverflow)?;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(EVIDENCE_MAGIC);
    bytes.extend_from_slice(&declared_total.to_le_bytes());
    bytes.push(count);
    for entry in entries {
        let length = u16::try_from(entry.len()).map_err(|_| Refusal::LengthOverflow)?;
        bytes.extend_from_slice(&length.to_le_bytes());
        trace.frame_signature_bytes += entry.len();
        bytes.extend_from_slice(entry);
    }
    if bytes.len() != total {
        return Err(Refusal::Malformed);
    }
    Ok(bytes)
}

fn mapped_keys(
    candidate: &Candidate,
    statement: &content::Statement,
) -> Result<[Vec<u8>; content::COMMITTEE], CompositionRefusal> {
    let mut network = [0; 32];
    network[..8].copy_from_slice(&statement.chain.to_le_bytes());
    if candidate.network != network
        || candidate.schema_version != statement.version
        || candidate.purpose != statement.purpose
        || candidate.epoch != statement.epoch
        || candidate.authority != statement.authority
        || candidate.members.len() != content::COMMITTEE
        || candidate.threshold != content::QUORUM as u64
    {
        return Err(CompositionRefusal::MappingMismatch);
    }
    for (index, member) in candidate.members.iter().enumerate() {
        let mut identity = [0; 32];
        identity[..2].copy_from_slice(&(index as u16).to_le_bytes());
        if member.identity != identity || member.weight != 1 || member.public_key.len() != KEY_BYTES
        {
            return Err(CompositionRefusal::MappingMismatch);
        }
    }
    Ok(std::array::from_fn(|index| {
        candidate.members[index].public_key.clone()
    }))
}

fn compose(
    slot: &ProviderSlot,
    fixture: &ExpectedCatalogFixture,
    lease: &AdmittedTestContext,
    currentness: Currentness,
    witness: &Candidate,
    statement: &content::Statement,
    endorsements: &[content::Endorsement],
    selection: Selection,
    trace: &mut CompositionTrace,
) -> Result<usize, CompositionRefusal> {
    let borrowed_entries = endorsements
        .iter()
        .map(|entry| entry.signature.as_slice())
        .collect::<Vec<_>>();
    let mut result = None;
    slot.verify_use_with_borrowed_entries(
        fixture,
        lease,
        currentness,
        &borrowed_entries,
        |snapshot| {
            trace.callbacks += 1;
            trace.context_checks += 1;
            let selected = match selection {
                Selection::Bound => {
                    if witness != snapshot {
                        result = Some(Err(CompositionRefusal::ContextMismatch));
                        return;
                    }
                    snapshot
                }
                Selection::WitnessDefect => witness,
            };
            trace.selected = Some(selected.clone());
            trace.mapping_checks += 1;
            let keys = match mapped_keys(selected, statement) {
                Ok(keys) => keys,
                Err(error) => {
                    result = Some(Err(error));
                    return;
                }
            };
            let copied_endorsements = endorsements
                .iter()
                .map(|endorsement| {
                    trace.signature_copy_bytes += endorsement.signature.len();
                    content::Endorsement {
                        signer: endorsement.signer,
                        signature: endorsement.signature.clone(),
                    }
                })
                .collect::<Vec<_>>();
            let copied_entries = copied_endorsements
                .iter()
                .map(|endorsement| endorsement.signature.as_slice())
                .collect::<Vec<_>>();
            trace.frame_constructions += 1;
            let evidence = match build_evidence_frame(&copied_entries, trace) {
                Ok(frame) => frame,
                Err(error) => {
                    result = Some(Err(CompositionRefusal::Provider(error)));
                    return;
                }
            };
            trace.frame_bytes = evidence.len();
            let framed_entries = match scan_evidence(&evidence, 0, &slot.trace) {
                Ok(entries) => entries,
                Err(error) => {
                    result = Some(Err(CompositionRefusal::Provider(error)));
                    return;
                }
            };
            if framed_entries.len() != copied_entries.len()
                || framed_entries
                    .iter()
                    .zip(&copied_entries)
                    .any(|(framed, copied)| *framed != *copied)
            {
                result = Some(Err(CompositionRefusal::Provider(
                    Refusal::DescriptorMismatch,
                )));
                return;
            }
            trace.verifier_calls += 1;
            let verification = content::test_verify(
                statement,
                &copied_endorsements,
                &keys,
                content::TestDefect::default(),
                &mut trace.verification,
            );
            if verification.is_ok() {
                trace.verification_successes += 1;
            }
            result = Some(verification.map_err(CompositionRefusal::Verification));
        },
    )
    .map_err(CompositionRefusal::Provider)?;
    result.expect("provider callback ran")
}

fn oracle(trace: &CompositionTrace, expected: &Candidate) -> bool {
    trace
        .selected
        .as_ref()
        .is_none_or(|selected| selected == expected)
}

fn refusal_precedes_materialization(trace: &CompositionTrace) -> bool {
    trace.signature_copy_bytes == 0 && trace.frame_constructions == 0
}

fn run(
    f: &Fixture,
    slot: &ProviderSlot,
    lease: &AdmittedTestContext,
    statement: &content::Statement,
    endorsements: &[content::Endorsement],
) -> (Result<usize, CompositionRefusal>, CompositionTrace) {
    let mut trace = CompositionTrace::default();
    let result = compose(
        slot,
        &f.expected,
        lease,
        Currentness::Available,
        &f.expected.context,
        statement,
        endorsements,
        Selection::Bound,
        &mut trace,
    );
    (result, trace)
}

#[test]
fn composition_preflight_limits_before_signature_copy_and_frame() {
    let f = Fixture::new();
    let slot = ProviderSlot::new(&f.expected);
    let lease = f.admit(&slot);
    assert!(f
        .experiment
        .endorsements
        .iter()
        .all(|entry| entry.signature.len() == MAX_ENTRY_BYTES));
    let (valid, valid_trace) = run(
        &f,
        &slot,
        &lease,
        &f.experiment.statement,
        &f.experiment.endorsements,
    );
    assert_eq!(valid, Ok(3));
    assert_eq!(
        (
            valid_trace.signature_copy_bytes,
            valid_trace.frame_constructions,
            valid_trace.frame_signature_bytes,
            valid_trace.frame_bytes,
            valid_trace.verification.backend_calls,
            valid_trace.verification_successes
        ),
        (
            3 * MAX_ENTRY_BYTES,
            1,
            3 * MAX_ENTRY_BYTES,
            EVIDENCE_HEADER + 3 * (2 + MAX_ENTRY_BYTES),
            3,
            1
        )
    );
    let max_entries = (0..MAX_EVIDENCE_ENTRIES)
        .map(|_| vec![0xA5; MAX_ENTRY_BYTES])
        .collect::<Vec<_>>();
    let max_endorsements = max_entries
        .iter()
        .enumerate()
        .map(|(index, signature)| content::Endorsement {
            signer: index as u16,
            signature: signature.clone(),
        })
        .collect::<Vec<_>>();
    let before = slot.trace();
    let mut trace = CompositionTrace::default();
    assert_eq!(
        compose(
            &slot,
            &f.expected,
            &lease,
            Currentness::Available,
            &f.expected.context,
            &f.experiment.statement,
            &max_endorsements,
            Selection::Bound,
            &mut trace
        ),
        Err(CompositionRefusal::Verification(
            content::Refusal::TooManyEndorsements
        ))
    );
    let after = slot.trace();
    assert_eq!(
        after.borrowed_entry_count_checks,
        before.borrowed_entry_count_checks + 1
    );
    assert_eq!(
        after.borrowed_entry_length_checks,
        before.borrowed_entry_length_checks + 1
    );
    assert_eq!(
        after.borrowed_entry_aggregate_checks,
        before.borrowed_entry_aggregate_checks + 1
    );
    assert_eq!(after.sentinel_effects, before.sentinel_effects + 1);
    assert_eq!(
        trace.signature_copy_bytes,
        MAX_EVIDENCE_ENTRIES * MAX_ENTRY_BYTES
    );
    assert_eq!(trace.frame_constructions, 1);
    assert_eq!(trace.frame_bytes, MAX_EVIDENCE);
    assert_eq!(
        trace.frame_signature_bytes,
        MAX_EVIDENCE_ENTRIES * MAX_ENTRY_BYTES
    );
    assert_eq!(trace.verifier_calls, 1);
    assert_eq!(trace.verification.encoding_calls, 0);
    assert_eq!(trace.verification.backend_calls, 0);

    let count_over = (0..=MAX_EVIDENCE_ENTRIES)
        .map(|index| content::Endorsement {
            signer: index as u16,
            signature: vec![1],
        })
        .collect::<Vec<_>>();
    let length_over = vec![content::Endorsement {
        signer: 0,
        signature: vec![1; MAX_ENTRY_BYTES + 1],
    }];
    for (entries, refusal) in [
        (&count_over, Refusal::EvidenceEntryCountExceeded),
        (&length_over, Refusal::EvidenceEntryTooLarge),
    ] {
        let before = slot.trace();
        let mut trace = CompositionTrace::default();
        assert_eq!(
            compose(
                &slot,
                &f.expected,
                &lease,
                Currentness::Available,
                &f.expected.context,
                &f.experiment.statement,
                entries,
                Selection::Bound,
                &mut trace
            ),
            Err(CompositionRefusal::Provider(refusal))
        );
        let after = slot.trace();
        assert_eq!(
            after.fixture_binding_checks,
            before.fixture_binding_checks + 1
        );
        assert_eq!(
            after.lease_identity_checks,
            before.lease_identity_checks + 1
        );
        assert_eq!(after.currentness_checks, before.currentness_checks + 1);
        assert_eq!(
            after.borrowed_entry_count_checks,
            before.borrowed_entry_count_checks + 1
        );
        assert_eq!(
            after.borrowed_entry_length_checks,
            before.borrowed_entry_length_checks
                + usize::from(refusal == Refusal::EvidenceEntryTooLarge)
        );
        assert_eq!(
            after.borrowed_entry_aggregate_checks,
            before.borrowed_entry_aggregate_checks
        );
        assert_eq!(after.sentinel_effects, before.sentinel_effects);
        assert_eq!(
            (
                trace.callbacks,
                trace.signature_copy_bytes,
                trace.frame_constructions,
                trace.frame_signature_bytes,
                trace.verifier_calls,
                trace.verification.backend_calls
            ),
            (0, 0, 0, 0, 0, 0)
        );
    }

    assert_eq!(
        checked_borrowed_evidence_frame_len(&[MAX_ENTRY_BYTES; MAX_EVIDENCE_ENTRIES]),
        Ok(MAX_EVIDENCE)
    );
    assert_eq!(
        checked_borrowed_evidence_frame_len(&[usize::MAX]),
        Err(Refusal::LengthOverflow)
    );
    let arithmetic_trace = Rc::new(RefCell::new(Trace::default()));
    assert_eq!(
        check_borrowed_evidence_aggregate(&[usize::MAX], &arithmetic_trace),
        Err(Refusal::LengthOverflow)
    );
    assert_eq!(arithmetic_trace.borrow().borrowed_entry_aggregate_checks, 1);
    assert_eq!(
        checked_borrowed_evidence_frame_len(&[]),
        Ok(EVIDENCE_HEADER)
    );
    println!("ORDERING valid 3x2420 signatures reached backend; bounded 8x2420 frame passed preflight then verifier committee cap; 9 entries/2421 bytes refused before copy/frame; checked frame arithmetic at cap/overflow");
}

#[test]
fn composition_provider_and_currentness_refuse_before_evidence_copy_or_frame() {
    let a = Fixture::new();
    let b = Fixture::new();
    let slot = ProviderSlot::new(&a.expected);
    let lease = a.admit(&slot);
    let invalidated = vec![content::Endorsement {
        signer: 0,
        signature: a.experiment.endorsements[0].signature.clone(),
    }];
    slot.replace_current(&b.expected).unwrap();
    let before = slot.trace();
    let mut trace = CompositionTrace::default();
    assert_eq!(
        compose(
            &slot,
            &b.expected,
            &lease,
            Currentness::Available,
            &b.expected.context,
            &b.experiment.statement,
            &invalidated,
            Selection::Bound,
            &mut trace
        ),
        Err(CompositionRefusal::Provider(Refusal::ProviderReplaced))
    );
    assert_eq!(
        slot.trace().provider_identity_checks,
        before.provider_identity_checks + 1
    );
    assert_eq!(slot.trace().currentness_checks, before.currentness_checks);
    assert_eq!(
        (
            trace.signature_copy_bytes,
            trace.frame_constructions,
            trace.verifier_calls,
            trace.verification.backend_calls
        ),
        (0, 0, 0, 0)
    );

    let new_lease = b.admit(&slot);
    for (currentness, refusal) in [
        (Currentness::Stale, Refusal::StaleContext),
        (Currentness::Unknown, Refusal::CurrentnessUnknown),
    ] {
        let before = slot.trace();
        let mut trace = CompositionTrace::default();
        assert_eq!(
            compose(
                &slot,
                &b.expected,
                &new_lease,
                currentness,
                &b.expected.context,
                &b.experiment.statement,
                &b.experiment.endorsements,
                Selection::Bound,
                &mut trace
            ),
            Err(CompositionRefusal::Provider(refusal))
        );
        let after = slot.trace();
        assert_eq!(
            after.fixture_binding_checks,
            before.fixture_binding_checks + 1
        );
        assert_eq!(
            after.lease_identity_checks,
            before.lease_identity_checks + 1
        );
        assert_eq!(after.currentness_checks, before.currentness_checks + 1);
        assert_eq!(
            after.borrowed_entry_count_checks,
            before.borrowed_entry_count_checks
        );
        assert_eq!(after.sentinel_effects, before.sentinel_effects);
        assert_eq!(
            (
                trace.callbacks,
                trace.signature_copy_bytes,
                trace.frame_constructions,
                trace.verifier_calls,
                trace.verification.backend_calls
            ),
            (0, 0, 0, 0, 0)
        );
    }
    let mut restored = CompositionTrace::default();
    assert_eq!(
        compose(
            &slot,
            &b.expected,
            &new_lease,
            Currentness::Available,
            &b.expected.context,
            &b.experiment.statement,
            &b.experiment.endorsements,
            Selection::Bound,
            &mut restored
        ),
        Ok(3)
    );
    assert_eq!(
        (
            restored.signature_copy_bytes,
            restored.frame_constructions,
            restored.frame_signature_bytes,
            restored.verification.backend_calls
        ),
        (3 * MAX_ENTRY_BYTES, 1, 3 * MAX_ENTRY_BYTES, 3)
    );
    slot.destroy_current();
    let before = slot.trace();
    let mut destroyed = CompositionTrace::default();
    assert_eq!(
        compose(
            &slot,
            &b.expected,
            &new_lease,
            Currentness::Available,
            &b.expected.context,
            &b.experiment.statement,
            &b.experiment.endorsements,
            Selection::Bound,
            &mut destroyed
        ),
        Err(CompositionRefusal::Provider(Refusal::ProviderDestroyed))
    );
    assert_eq!(slot.trace().liveness_checks, before.liveness_checks + 1);
    assert_eq!(
        (
            destroyed.signature_copy_bytes,
            destroyed.frame_constructions,
            destroyed.frame_signature_bytes,
            destroyed.verification.backend_calls
        ),
        (0, 0, 0, 0)
    );
    println!("ORDERING replaced/stale/unknown/destroyed refused before copy/frame/backend; restored B passed real verifier");
}

#[test]
fn defective_order_copies_and_frames_before_provider_refusal_is_detected() {
    let f = Fixture::new();
    let slot = ProviderSlot::new(&f.expected);
    let lease = f.admit(&slot);
    slot.destroy_current();
    let borrowed = f
        .experiment
        .endorsements
        .iter()
        .map(|entry| entry.signature.as_slice())
        .collect::<Vec<_>>();
    let mut trace = CompositionTrace::default();
    let signatures = borrowed
        .iter()
        .map(|signature| {
            trace.signature_copy_bytes += signature.len();
            signature.to_vec()
        })
        .collect::<Vec<_>>();
    trace.frame_constructions += 1;
    let copied_entries = signatures.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let evidence = build_evidence_frame(&copied_entries, &mut trace).unwrap();
    trace.frame_bytes = evidence.len();
    assert_eq!(
        slot.verify_use(
            &f.expected,
            &lease,
            Currentness::Available,
            &evidence,
            |_| {
                trace.callbacks += 1;
            }
        ),
        Err(Refusal::ProviderDestroyed)
    );
    let after = slot.trace();
    assert_eq!(
        (
            trace.signature_copy_bytes,
            trace.frame_constructions,
            trace.frame_signature_bytes,
            trace.callbacks
        ),
        (3 * MAX_ENTRY_BYTES, 1, 3 * MAX_ENTRY_BYTES, 0)
    );
    assert_eq!(
        (trace.verifier_calls, trace.verification.backend_calls),
        (0, 0)
    );
    assert_eq!(after.liveness_checks, 1);
    assert!(!refusal_precedes_materialization(&trace));
    println!("DEFECT ORDER destroyed provider still had signature copies={} frame_constructions=1; corrected oracle requires both zero", trace.signature_copy_bytes);
}

#[test]
fn composition_requires_exact_fixture_threshold_weights_and_identity_mapping() {
    let f = Fixture::new();
    for kind in ["threshold", "weight", "identity", "network"] {
        let mut altered = f.expected.clone();
        match kind {
            "threshold" => altered.context.threshold = 2,
            "weight" => altered.context.members[0].weight = 2,
            "identity" => altered.context.members[0].identity[2] = 1,
            "network" => altered.context.network[8] = 1,
            _ => unreachable!(),
        }
        validate_candidate(&altered.context, &Rc::new(RefCell::new(Trace::default()))).unwrap();
        let slot = ProviderSlot::new(&altered);
        let lease = slot
            .admit_decoded(&altered, altered.context.clone(), Currentness::Available)
            .unwrap();
        let before = slot.trace();
        let mut trace = CompositionTrace::default();
        assert_eq!(
            compose(
                &slot,
                &altered,
                &lease,
                Currentness::Available,
                &altered.context,
                &f.experiment.statement,
                &f.experiment.endorsements,
                Selection::Bound,
                &mut trace
            ),
            Err(CompositionRefusal::MappingMismatch)
        );
        let after = slot.trace();
        assert_eq!(
            after.fixture_binding_checks,
            before.fixture_binding_checks + 1
        );
        assert_eq!(after.currentness_checks, before.currentness_checks + 1);
        assert_eq!(after.sentinel_effects, before.sentinel_effects + 1);
        assert_eq!(
            (
                trace.callbacks,
                trace.context_checks,
                trace.mapping_checks,
                trace.verifier_calls,
                trace.verification.backend_calls
            ),
            (1, 1, 1, 0, 0)
        );
    }
    let slot = ProviderSlot::new(&f.expected);
    let lease = f.admit(&slot);
    let (result, trace) = run(
        &f,
        &slot,
        &lease,
        &f.experiment.statement,
        &f.experiment.endorsements,
    );
    assert_eq!(result, Ok(3));
    assert_eq!(
        (
            trace.mapping_checks,
            trace.verification.backend_calls,
            trace.verification_successes
        ),
        (1, 3, 1)
    );
    println!("COMPOSITION threshold/weight/identity/network mapping mismatches refused before verifier; original restored");
}

#[test]
fn composition_parent_content_mutations_and_restored_positive() {
    let f = Fixture::new();
    let slot = ProviderSlot::new(&f.expected);
    let lease = f.admit(&slot);
    let original = &f.experiment.statement;
    for variant in ["original", "parent", "content", "restored"] {
        let mut statement = original.clone();
        if variant == "parent" {
            statement.parent[31] ^= 1;
        }
        if variant == "content" {
            statement.content[255] ^= 1;
        }
        let before = slot.trace();
        let (result, trace) = run(&f, &slot, &lease, &statement, &f.experiment.endorsements);
        let after = slot.trace();
        let success = variant == "original" || variant == "restored";
        assert_eq!(
            result,
            if success {
                Ok(3)
            } else {
                Err(CompositionRefusal::Verification(
                    content::Refusal::InvalidSignature(0),
                ))
            }
        );
        assert_eq!(
            after.fixture_binding_checks,
            before.fixture_binding_checks + 1
        );
        assert_eq!(
            after.lease_identity_checks,
            before.lease_identity_checks + 1
        );
        assert_eq!(after.currentness_checks, before.currentness_checks + 1);
        assert_eq!(after.sentinel_effects, before.sentinel_effects + 1);
        assert_eq!(
            (
                trace.callbacks,
                trace.context_checks,
                trace.verifier_calls,
                trace.verification.encoding_calls
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(
            trace.verification.backend_calls,
            if success { 3 } else { 1 }
        );
        assert_eq!(
            trace.verification.verified_entries,
            if success { 3 } else { 0 }
        );
        assert_eq!(trace.verification_successes, usize::from(success));
        assert!(oracle(&trace, &f.expected.context));
    }
    println!(
        "COMPOSITION original/parent/content/restored: backend calls 3/1/1/3; success 1/0/0/1"
    );
}

#[test]
fn composition_duplicate_unauthorized_and_insufficient_stage_controls() {
    let f = Fixture::new();
    let slot = ProviderSlot::new(&f.expected);
    let lease = f.admit(&slot);
    let original = &f.experiment.endorsements;
    let mut duplicate = original.clone();
    duplicate[1] = duplicate[0].clone();
    let mut unauthorized = original.clone();
    unauthorized[1].signer = 4;
    let insufficient = original[..2].to_vec();
    for (entries, result, encoding, calls, verified) in [
        (&duplicate, content::Refusal::Duplicate(0), 0, 0, 0),
        (&unauthorized, content::Refusal::Unauthorized(4), 0, 0, 0),
        (
            &insufficient,
            content::Refusal::Insufficient { have: 2, need: 3 },
            1,
            2,
            2,
        ),
    ] {
        let before = slot.trace();
        let (actual, trace) = run(&f, &slot, &lease, &f.experiment.statement, entries);
        assert_eq!(actual, Err(CompositionRefusal::Verification(result)));
        assert_eq!(slot.trace().sentinel_effects, before.sentinel_effects + 1);
        assert_eq!(
            (
                trace.callbacks,
                trace.context_checks,
                trace.verifier_calls,
                trace.verification_successes
            ),
            (1, 1, 1, 0)
        );
        assert_eq!(
            (
                trace.verification.encoding_calls,
                trace.verification.backend_calls,
                trace.verification.verified_entries
            ),
            (encoding, calls, verified)
        );
        assert!(oracle(&trace, &f.expected.context));
        let (restored, trace) = run(&f, &slot, &lease, &f.experiment.statement, original);
        assert_eq!(restored, Ok(3));
        assert_eq!(
            (
                trace.verification.backend_calls,
                trace.verification_successes
            ),
            (3, 1)
        );
    }
    println!("COMPOSITION duplicate/unauthorized pre-encoding; insufficient verifies two then refuses threshold; restored");
}

#[test]
fn composition_same_label_selection_mutant_preserves_real_verification() {
    let a = Fixture::new();
    let b = Fixture::new();
    assert_eq!(a.expected.identity, b.expected.identity);
    assert_ne!(a.expected.context.members, b.expected.context.members);
    let slot = ProviderSlot::new(&a.expected);
    let lease = a.admit(&slot);
    for (selection, expected, backend, oracle_pass) in [
        (
            Selection::Bound,
            Err(CompositionRefusal::ContextMismatch),
            0,
            true,
        ),
        (Selection::WitnessDefect, Ok(3), 3, false),
    ] {
        let mut trace = CompositionTrace::default();
        let before = slot.trace();
        let actual = compose(
            &slot,
            &a.expected,
            &lease,
            Currentness::Available,
            &b.expected.context,
            &b.experiment.statement,
            &b.experiment.endorsements,
            selection,
            &mut trace,
        );
        assert_eq!(actual, expected);
        assert_eq!(slot.trace().sentinel_effects, before.sentinel_effects + 1);
        assert_eq!(
            (
                trace.callbacks,
                trace.context_checks,
                trace.verification.backend_calls
            ),
            (1, 1, backend)
        );
        assert_eq!(oracle(&trace, &a.expected.context), oracle_pass);
        assert_eq!(trace.verification_successes, usize::from(backend == 3));
    }
    let (result, trace) = run(
        &a,
        &slot,
        &lease,
        &a.experiment.statement,
        &a.experiment.endorsements,
    );
    assert_eq!(result, Ok(3));
    assert!(oracle(&trace, &a.expected.context));
    assert_eq!(
        (
            trace.verification.backend_calls,
            trace.verification_successes
        ),
        (3, 1)
    );
    println!("COMPOSITION strict B refused; mutant B verified three signatures but failed same selection oracle; A restored");
}

#[test]
fn composition_currentness_replacement_and_destroyed_lease_precede_verification() {
    let a = Fixture::new();
    let b = Fixture::new();
    let slot = ProviderSlot::new(&a.expected);
    let old = a.admit(&slot);
    for (currentness, refusal) in [
        (Currentness::Stale, Refusal::StaleContext),
        (Currentness::Unknown, Refusal::CurrentnessUnknown),
    ] {
        let before = slot.trace();
        let mut trace = CompositionTrace::default();
        assert_eq!(
            compose(
                &slot,
                &a.expected,
                &old,
                currentness,
                &a.expected.context,
                &a.experiment.statement,
                &a.experiment.endorsements,
                Selection::Bound,
                &mut trace
            ),
            Err(CompositionRefusal::Provider(refusal))
        );
        let after = slot.trace();
        assert_eq!(
            after.fixture_binding_checks,
            before.fixture_binding_checks + 1
        );
        assert_eq!(
            after.lease_identity_checks,
            before.lease_identity_checks + 1
        );
        assert_eq!(after.currentness_checks, before.currentness_checks + 1);
        assert_eq!(after.sentinel_effects, before.sentinel_effects);
        assert_eq!(
            (
                trace.callbacks,
                trace.verifier_calls,
                trace.verification.backend_calls
            ),
            (0, 0, 0)
        );
    }
    let (result, trace) = run(
        &a,
        &slot,
        &old,
        &a.experiment.statement,
        &a.experiment.endorsements,
    );
    assert_eq!(result, Ok(3));
    assert_eq!(trace.verification.backend_calls, 3);
    slot.replace_current(&b.expected).unwrap();
    let before = slot.trace();
    let mut trace = CompositionTrace::default();
    assert_eq!(
        compose(
            &slot,
            &b.expected,
            &old,
            Currentness::Available,
            &b.expected.context,
            &b.experiment.statement,
            &b.experiment.endorsements,
            Selection::Bound,
            &mut trace
        ),
        Err(CompositionRefusal::Provider(Refusal::ProviderReplaced))
    );
    assert_eq!(
        slot.trace().provider_identity_checks,
        before.provider_identity_checks + 1
    );
    assert_eq!(slot.trace().currentness_checks, before.currentness_checks);
    assert_eq!((trace.callbacks, trace.verification.backend_calls), (0, 0));
    let new = b.admit(&slot);
    let (result, trace) = run(
        &b,
        &slot,
        &new,
        &b.experiment.statement,
        &b.experiment.endorsements,
    );
    assert_eq!(result, Ok(3));
    assert!(oracle(&trace, &b.expected.context));
    assert_eq!(
        (
            trace.verification.backend_calls,
            trace.verification_successes
        ),
        (3, 1)
    );
    slot.destroy_current();
    let before = slot.trace();
    let mut trace = CompositionTrace::default();
    assert_eq!(
        compose(
            &slot,
            &b.expected,
            &new,
            Currentness::Available,
            &b.expected.context,
            &b.experiment.statement,
            &b.experiment.endorsements,
            Selection::Bound,
            &mut trace
        ),
        Err(CompositionRefusal::Provider(Refusal::ProviderDestroyed))
    );
    assert_eq!(slot.trace().liveness_checks, before.liveness_checks + 1);
    assert_eq!(slot.trace().currentness_checks, before.currentness_checks);
    assert_eq!((trace.callbacks, trace.verification.backend_calls), (0, 0));
    println!("COMPOSITION stale/unknown/replaced/destroyed refused before backend; new B admitted and verified");
}
