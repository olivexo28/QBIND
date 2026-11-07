//! Test-only handoff to the real signature backend, not a recovery protocol.

use super::*;
use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::ml_dsa44::MlDsa44Backend;

const MESSAGE: &[u8] = b"QBIND-TEST-P1-HANDOFF-v1:synthetic-statement";

struct Fixture {
    expected: ExpectedCatalogFixture,
    evidence: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let (public, mut secret) = MlDsa44Backend::generate_keypair().expect("synthetic keygen");
        let signature = MlDsa44Backend::sign(&secret, MESSAGE).expect("synthetic signature");
        secret.fill(0);
        let mut expected = ExpectedCatalogFixture::new();
        expected.context.members.truncate(1);
        expected.context.members[0].public_key = public;
        expected.context.threshold = 1;
        validate_candidate(&expected.context, &Rc::new(RefCell::new(Trace::default()))).unwrap();
        assert_eq!(signature.len(), MAX_ENTRY_BYTES);
        Self {
            expected,
            evidence: encode_evidence(&[signature]),
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
enum HandoffRefusal {
    Provider(Refusal),
    ContextMismatch,
    InvalidSignature,
}

#[derive(Default, Debug)]
struct HandoffTrace {
    context_checks: usize,
    verifier_calls: usize,
    success_sentinel: usize,
    selected: Option<Candidate>,
}

#[derive(Clone, Copy)]
enum Selection {
    Bound,
    WitnessDefect,
}

fn handoff(
    slot: &ProviderSlot,
    fixture: &ExpectedCatalogFixture,
    lease: &AdmittedTestContext,
    currentness: Currentness,
    witness: &Candidate,
    evidence: &[u8],
    selection: Selection,
    trace: &mut HandoffTrace,
) -> Result<(), HandoffRefusal> {
    let mut result = None;
    slot.verify_use(fixture, lease, currentness, evidence, |snapshot| {
        trace.context_checks += 1;
        let selected = match selection {
            Selection::Bound => {
                if witness != snapshot {
                    result = Some(Err(HandoffRefusal::ContextMismatch));
                    return;
                }
                snapshot
            }
            Selection::WitnessDefect => witness,
        };
        trace.selected = Some(selected.clone());
        // The provider scanner has already checked the complete one-entry frame.
        // This handoff accepts exactly one entry and verifies those same bytes.
        if evidence[12] != 1 || evidence.len() != EVIDENCE_HEADER + 2 + MAX_ENTRY_BYTES {
            result = Some(Err(HandoffRefusal::Provider(Refusal::Malformed)));
            return;
        }
        let member = &selected.members[0];
        trace.verifier_calls += 1;
        result = Some(
            match MlDsa44Backend.verify_vote(
                u64::from(member.identity[0]),
                &member.public_key,
                MESSAGE,
                &evidence[EVIDENCE_HEADER + 2..],
            ) {
                Ok(()) => {
                    trace.success_sentinel += 1;
                    Ok(())
                }
                Err(ConsensusSigError::InvalidSignature) => Err(HandoffRefusal::InvalidSignature),
                Err(error) => panic!("unexpected real-backend failure: {error}"),
            },
        );
    })
    .map_err(HandoffRefusal::Provider)?;
    result.expect("provider callback ran")
}

fn selection_oracle(trace: &HandoffTrace, expected: &Candidate) -> bool {
    trace
        .selected
        .as_ref()
        .is_none_or(|selected| selected == expected)
}

#[test]
fn matching_corrupted_and_restored_signature_reach_real_backend() {
    let f = Fixture::new();
    let slot = ProviderSlot::new(&f.expected);
    let lease = f.admit(&slot);
    let mut corrupt = f.evidence.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for (evidence, expected_result, success) in [
        (&f.evidence, Ok(()), 1),
        (&corrupt, Err(HandoffRefusal::InvalidSignature), 0),
        (&f.evidence, Ok(()), 1),
    ] {
        let before = slot.trace();
        let mut trace = HandoffTrace::default();
        assert_eq!(
            handoff(
                &slot,
                &f.expected,
                &lease,
                Currentness::Available,
                &f.expected.context,
                evidence,
                Selection::Bound,
                &mut trace
            ),
            expected_result
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
            after.evidence_decoder_calls,
            before.evidence_decoder_calls + 1
        );
        assert_eq!(after.sentinel_effects, before.sentinel_effects + 1);
        assert_eq!(
            (
                trace.context_checks,
                trace.verifier_calls,
                trace.success_sentinel
            ),
            (1, 1, success)
        );
        assert!(selection_oracle(&trace, &f.expected.context));
    }
    println!("HANDOFF matching/corrupt/restored: real backend calls 1/1/1; success 1/0/1");
}

#[test]
fn same_label_witness_replacement_strict_and_defective_selection_oracle() {
    let a = Fixture::new();
    let mut b = Fixture::new();
    b.expected.identity = a.expected.identity;
    assert_eq!(a.expected.identity, b.expected.identity);
    assert_ne!(a.expected.context.members, b.expected.context.members);
    let slot = ProviderSlot::new(&a.expected);
    let lease = a.admit(&slot);
    let mut strict = HandoffTrace::default();
    assert_eq!(
        handoff(
            &slot,
            &a.expected,
            &lease,
            Currentness::Available,
            &b.expected.context,
            &b.evidence,
            Selection::Bound,
            &mut strict
        ),
        Err(HandoffRefusal::ContextMismatch)
    );
    assert_eq!(
        (
            strict.context_checks,
            strict.verifier_calls,
            strict.success_sentinel
        ),
        (1, 0, 0)
    );
    assert!(selection_oracle(&strict, &a.expected.context));
    let mut mutant = HandoffTrace::default();
    assert_eq!(
        handoff(
            &slot,
            &a.expected,
            &lease,
            Currentness::Available,
            &b.expected.context,
            &b.evidence,
            Selection::WitnessDefect,
            &mut mutant
        ),
        Ok(())
    );
    assert_eq!(
        (
            mutant.context_checks,
            mutant.verifier_calls,
            mutant.success_sentinel
        ),
        (1, 1, 1)
    );
    assert!(!selection_oracle(&mutant, &a.expected.context));
    let mut restored = HandoffTrace::default();
    assert_eq!(
        handoff(
            &slot,
            &a.expected,
            &lease,
            Currentness::Available,
            &a.expected.context,
            &a.evidence,
            Selection::Bound,
            &mut restored
        ),
        Ok(())
    );
    assert_eq!(
        (
            restored.context_checks,
            restored.verifier_calls,
            restored.success_sentinel
        ),
        (1, 1, 1)
    );
    assert!(selection_oracle(&restored, &a.expected.context));
    println!("HANDOFF selection: strict refused; witness-selected mutant verified B but failed same bound-context oracle; A restored");
}

#[test]
fn currentness_and_provider_lifetime_refuse_before_backend_then_replacement_succeeds() {
    let a = Fixture::new();
    let mut b = Fixture::new();
    b.expected.identity = a.expected.identity;
    let slot = ProviderSlot::new(&a.expected);
    let old = a.admit(&slot);
    let before = slot.trace();
    let mut trace = HandoffTrace::default();
    assert_eq!(
        handoff(
            &slot,
            &b.expected,
            &old,
            Currentness::Available,
            &b.expected.context,
            &b.evidence,
            Selection::Bound,
            &mut trace,
        ),
        Err(HandoffRefusal::Provider(Refusal::FixtureMismatch))
    );
    let after = slot.trace();
    assert_eq!(
        after.provider_identity_checks,
        before.provider_identity_checks + 1
    );
    assert_eq!(
        after.fixture_binding_checks,
        before.fixture_binding_checks + 1
    );
    assert_eq!(after.lease_identity_checks, before.lease_identity_checks);
    assert_eq!(after.currentness_checks, before.currentness_checks);
    assert_eq!(after.sentinel_effects, before.sentinel_effects);
    assert_eq!(
        (
            trace.context_checks,
            trace.verifier_calls,
            trace.success_sentinel
        ),
        (0, 0, 0)
    );
    for (state, refusal) in [
        (Currentness::Stale, Refusal::StaleContext),
        (Currentness::Unknown, Refusal::CurrentnessUnknown),
        (Currentness::Unavailable, Refusal::CurrentnessUnavailable),
    ] {
        let before = slot.trace();
        let mut trace = HandoffTrace::default();
        assert_eq!(
            handoff(
                &slot,
                &a.expected,
                &old,
                state,
                &a.expected.context,
                &a.evidence,
                Selection::Bound,
                &mut trace
            ),
            Err(HandoffRefusal::Provider(refusal))
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
                trace.context_checks,
                trace.verifier_calls,
                trace.success_sentinel
            ),
            (0, 0, 0)
        );
    }
    let mut trace = HandoffTrace::default();
    assert_eq!(
        handoff(
            &slot,
            &a.expected,
            &old,
            Currentness::Available,
            &a.expected.context,
            &a.evidence,
            Selection::Bound,
            &mut trace
        ),
        Ok(())
    );
    assert_eq!(trace.verifier_calls, 1);
    slot.replace_current(&b.expected).unwrap();
    let before = slot.trace();
    let mut trace = HandoffTrace::default();
    assert_eq!(
        handoff(
            &slot,
            &b.expected,
            &old,
            Currentness::Available,
            &b.expected.context,
            &b.evidence,
            Selection::Bound,
            &mut trace
        ),
        Err(HandoffRefusal::Provider(Refusal::ProviderReplaced))
    );
    assert_eq!(
        slot.trace().provider_identity_checks,
        before.provider_identity_checks + 1
    );
    assert_eq!(slot.trace().currentness_checks, before.currentness_checks);
    assert_eq!(trace.verifier_calls, 0);
    let new = b.admit(&slot);
    let mut trace = HandoffTrace::default();
    assert_eq!(
        handoff(
            &slot,
            &b.expected,
            &new,
            Currentness::Available,
            &a.expected.context,
            &a.evidence,
            Selection::Bound,
            &mut trace
        ),
        Err(HandoffRefusal::ContextMismatch)
    );
    assert_eq!((trace.context_checks, trace.verifier_calls), (1, 0));
    let mut trace = HandoffTrace::default();
    assert_eq!(
        handoff(
            &slot,
            &b.expected,
            &new,
            Currentness::Available,
            &b.expected.context,
            &b.evidence,
            Selection::Bound,
            &mut trace
        ),
        Ok(())
    );
    assert!(selection_oracle(&trace, &b.expected.context));
    assert_eq!((trace.verifier_calls, trace.success_sentinel), (1, 1));
    slot.destroy_current();
    let before = slot.trace();
    let mut trace = HandoffTrace::default();
    assert_eq!(
        handoff(
            &slot,
            &b.expected,
            &new,
            Currentness::Available,
            &b.expected.context,
            &b.evidence,
            Selection::Bound,
            &mut trace
        ),
        Err(HandoffRefusal::Provider(Refusal::ProviderDestroyed))
    );
    assert_eq!(slot.trace().liveness_checks, before.liveness_checks + 1);
    assert_eq!(slot.trace().currentness_checks, before.currentness_checks);
    assert_eq!(trace.verifier_calls, 0);
    println!("HANDOFF stale/unknown/unavailable and replaced/destroyed refused before backend; new B succeeds");
}
