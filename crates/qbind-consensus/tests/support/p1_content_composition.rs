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
    let evidence = encode_evidence(
        &endorsements
            .iter()
            .map(|entry| entry.signature.clone())
            .collect::<Vec<_>>(),
    );
    let mut result = None;
    slot.verify_use(fixture, lease, currentness, &evidence, |snapshot| {
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
        trace.verifier_calls += 1;
        let verification = content::test_verify(
            statement,
            endorsements,
            &keys,
            content::TestDefect::default(),
            &mut trace.verification,
        );
        if verification.is_ok() {
            trace.verification_successes += 1;
        }
        result = Some(verification.map_err(CompositionRefusal::Verification));
    })
    .map_err(CompositionRefusal::Provider)?;
    result.expect("provider callback ran")
}

fn oracle(trace: &CompositionTrace, expected: &Candidate) -> bool {
    trace
        .selected
        .as_ref()
        .is_none_or(|selected| selected == expected)
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
