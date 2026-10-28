//! Isolated received-QC -> ordinary O4 -> ordinary QC effects composition.
//! Uncertain O4 recovery requires explicit ordinary O5 and an exact-QC gate.
//! Immutable fixture authority is an assumption, NOT production current authority.

use super::super::{
    accounting::{max_transient_decoded_working_set, Reservation},
    backend::{InjectFault, SafetyBackendPolicy, TryLockDomainOutcome},
    profile::{max_decoded_evidence_backing_bytes, max_qc_generation_bytes},
    record::{CommittedAnchor, WireQc},
    validate::FixtureCommittedHistory,
};
use super::*;
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_consensus::{
    basic_hotstuff_engine::{
        received_qc_effect_test_support as support, ConsensusProgressRecorder,
        ValidatorVoteRecorder,
    },
    crypto_verifier::SimpleBackendRegistry,
    key_registry::SuiteAwareValidatorKeyProvider,
    qc_verify_domain::verify_quorum_certificate_with_domain,
    validator_set::{ConsensusValidatorSet, ValidatorSetEntry},
    BasicHotStuffEngine, ValidatorId,
};
use qbind_crypto::{ml_dsa44::MlDsa44Backend, ConsensusSigSuiteId, SUITE_PQ_RESERVED_1};
use qbind_wire::{consensus::Vote, pv_signing_domain::ProposalVoteSigningDomainV2};
use std::{
    mem::size_of,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

const SIG: usize = qbind_crypto::ML_DSA_44_SIGNATURE_SIZE;
const IDS: [[u8; 32]; 4] = [[0xA1; 32], [0xA2; 32], [0xA3; 32], [0xA4; 32]];

struct Authority {
    domain: ProposalVoteSigningDomainV2,
    members: [(ValidatorId, u64, Vec<u8>); 4],
    secrets: [Vec<u8>; 4],
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IndependentTestAuthority(redacted)")
    }
}

impl Authority {
    fn new() -> Self {
        let pairs = std::array::from_fn::<_, 4, _>(|_| MlDsa44Backend::generate_keypair().unwrap());
        let mut digest = Sha3_256::new();
        digest.update(b"RUN422-independent-received-QC-fixture-v1");
        digest.update(qbind_types::QBIND_DEVNET_CHAIN_ID.0.to_le_bytes());
        digest.update(7u32.to_le_bytes());
        digest.update([0x71; 32]);
        digest.update(0u64.to_le_bytes());
        for (i, (pk, _)) in pairs.iter().enumerate() {
            digest.update((i as u64).to_le_bytes());
            digest.update(1u64.to_le_bytes());
            digest.update(SUITE_PQ_RESERVED_1.0.to_le_bytes());
            digest.update((pk.len() as u64).to_le_bytes());
            digest.update(pk);
        }
        let commitment = digest.finalize().into();
        let domain = ProposalVoteSigningDomainV2::try_new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            7,
            [0x71; 32],
            commitment,
        )
        .unwrap();
        let members = std::array::from_fn(|i| (ValidatorId(i as u64), 1, pairs[i].0.clone()));
        let secrets = pairs.map(|(_, secret)| secret);
        Self {
            domain,
            members,
            secrets,
        }
    }

    fn pinned(&self) -> PinnedSafetyContext {
        PinnedSafetyContext {
            network_genesis_id: *self.domain.genesis_identity(),
            authority_context_ref: *self.domain.authority_commitment(),
            chain_id: self.domain.expected_wire_chain_id(),
            epoch: 0,
            qc_suite_id: SUITE_PQ_RESERVED_1.0,
            timeout_suite_id: 100,
            s_sig: SIG,
            validators: self
                .members
                .iter()
                .map(|(id, power, _)| (*id, *power))
                .collect(),
            require_height_equals_round: false,
        }
    }

    fn set(&self) -> ConsensusValidatorSet {
        ConsensusValidatorSet::new(self.members.iter().map(|(id, power, _)| ValidatorSetEntry {
            id: *id,
            voting_power: *power,
        }))
        .unwrap()
    }

    fn vote(&self, index: usize, height: u64, round: u64) -> Vote {
        let mut vote = Vote {
            version: 1,
            chain_id: 7,
            epoch: 0,
            height,
            round,
            step: 0,
            block_id: IDS[(height - 1) as usize],
            validator_index: index as u16,
            suite_id: SUITE_PQ_RESERVED_1.0,
            signature: Vec::new(),
        };
        vote.signature =
            MlDsa44Backend::sign(&self.secrets[index], &self.domain.vote_preimage(&vote))
                .unwrap()
                .into_boxed_slice()
                .into_vec();
        assert_eq!(
            (vote.signature.len(), vote.signature.capacity()),
            (2420, 2420)
        );
        vote
    }

    fn corresponds(&self, pinned: &PinnedSafetyContext) -> bool {
        pinned.validate().is_ok()
            && self.domain.runtime_chain_id() == qbind_types::QBIND_DEVNET_CHAIN_ID
            && pinned.network_genesis_id == *self.domain.genesis_identity()
            && pinned.authority_context_ref == *self.domain.authority_commitment()
            && pinned.chain_id == self.domain.expected_wire_chain_id()
            && pinned.epoch == 0
            && pinned.qc_suite_id == SUITE_PQ_RESERVED_1.0
            && pinned.timeout_suite_id == 100
            && pinned.s_sig == 2420
            && !pinned.require_height_equals_round
            && pinned.n() == 4
            && pinned.b_span() == 1
            && pinned
                .validators
                .iter()
                .zip(&self.members)
                .all(|((id, power), (a, b, key))| {
                    id == a && power == b && key.len() == qbind_crypto::ML_DSA_44_PUBLIC_KEY_SIZE
                })
    }

    fn verify_test_evidence(&self, wire: &WireQc) {
        let registry =
            SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend));
        assert!(
            verify_quorum_certificate_with_domain(
                wire,
                &self.domain,
                0,
                &self.set(),
                self,
                &registry,
            )
            .is_ok(),
            "domain-aware test evidence verification failed (redacted)"
        );
    }
}

impl SuiteAwareValidatorKeyProvider for Authority {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.members
            .iter()
            .find(|(member, _, _)| *member == id)
            .map(|(_, _, key)| (SUITE_PQ_RESERVED_1, key.clone()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Publication {
    RefusedPreWrite,
    WriteFailedAmbiguous,
    UncertainDurable,
    DurableAcknowledged(u64),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    Context,
    Loader,
    Revision,
    Lock,
    NonAdvancing,
    CandidatePressure,
    O4Capacity,
    RecoveryRequired,
    PublicationChanged,
    Predecessor,
    Certificate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Effects {
    lock: Option<([u8; 32], u64)>,
    own_qc: bool,
    committed: Option<([u8; 32], u64)>,
    log_len: usize,
    view: u64,
}

impl Effects {
    fn capture(engine: &BasicHotStuffEngine<[u8; 32]>, target: [u8; 32]) -> Self {
        Self {
            lock: engine.locked_qc().map(|q| (q.block_id, q.view)),
            own_qc: engine
                .state()
                .get_block(&target)
                .is_some_and(|b| b.own_qc.is_some()),
            committed: engine
                .committed_block()
                .copied()
                .zip(engine.committed_height()),
            log_len: engine.commit_log().len(),
            view: engine.current_view(),
        }
    }
}

// Field order is intentional: report/backing is destroyed before coverage.
struct ModelResult {
    route: Result<support::Report, support::Refusal>,
    publication: Option<Publication>,
    refused: Option<Refused>,
    gate_calls: usize,
    submitted: usize,
    after_route: (u128, u128),
    _coverage: Reservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionRefusal {
    Capacity,
}

// Like the accepted leader-route admission: no token or large outcome is
// transferred until this opaque owner has admitted the route's coverage.
struct Admission<'owner> {
    owner: &'owner SafetyRecordOwner,
    coverage: Reservation,
}

fn admit_composition(owner: &SafetyRecordOwner) -> Result<Admission<'_>, AdmissionRefusal> {
    let coverage = owner
        .backend
        .accounting()
        .reserve(adapter_charge())
        .map_err(|_| AdmissionRefusal::Capacity)?;
    Ok(Admission { owner, coverage })
}

struct Gate<'o, 'g> {
    owner: &'o SafetyRecordOwner,
    guard: &'o std::sync::MutexGuard<'g, super::super::backend::SerializationDomain>,
    history: &'o FixtureCommittedHistory,
    expected: u64,
    context_matches: bool,
    publication: Option<Publication>,
    refused: Option<Refused>,
    calls: usize,
    submitted: usize,
}

impl Gate<'_, '_> {
    fn evaluate(&mut self, input: support::Input<'_>) -> bool {
        self.calls += 1;
        match self.publish(&input) {
            Ok(outcome) => {
                let allow = matches!(outcome, Publication::DurableAcknowledged(_));
                self.publication = Some(outcome);
                allow
            }
            Err(reason) => {
                self.refused = Some(reason);
                false
            }
        }
    }

    fn publish(&mut self, input: &support::Input<'_>) -> Result<Publication, Refused> {
        if !self.context_matches {
            return Err(Refused::Context);
        }
        let wire = input.wire();
        let logical = input.logical();
        let ctx = self.owner.pinned();
        if wire.block_id != logical.block_id
            || wire.height != logical.view
            || wire.chain_id != ctx.chain_id
            || wire.epoch != ctx.epoch
            || wire.suite_id != ctx.qc_suite_id
            || wire.signatures.len() != logical.signers.len()
            || wire.signatures.iter().any(|sig| sig.len() != ctx.s_sig)
        {
            return Err(Refused::Context);
        }

        // Admit the caller-owned candidate before any candidate copy, including
        // the loader interval. Early admission makes independent candidate
        // pressure a pre-loader boundary, not a simulated allocation failure.
        let candidate_lease = self
            .owner
            .backend
            .accounting()
            .reserve(candidate_charge(ctx))
            .map_err(|_| Refused::CandidatePressure)?;
        let current = self
            .owner
            .load_current_validated_locked(self.guard, Some(self.history))
            .map_err(|_| Refused::Loader)?;
        if current.publication_revision() != self.expected {
            return Err(Refused::Revision);
        }
        let (stored_lock, anchor) = match &current.retained().record {
            SafetyRecord::BootstrapNoLock { .. } => (None, None),
            SafetyRecord::Locked(record) => (
                Some((record.lock_block_id, record.lock_view)),
                record.committed_anchor.clone(),
            ),
        };
        if stored_lock != input.lock() {
            return Err(Refused::Lock);
        }
        if stored_lock.is_some_and(|(_, view)| logical.view <= view) {
            return Err(Refused::NonAdvancing);
        }
        if let Some(anchor) = &anchor {
            if !self
                .history
                .contains_committed(&anchor.block_id, anchor.height)
            {
                return Err(Refused::Lock);
            }
        }
        // Do NOT infer an anchor from the commit on_qc has not produced yet.
        drop(current);

        // Before the only node-owned QC copy. This caller-owned candidate is
        // not covered by O4's later working-set admission.
        let candidate = LockedRecord {
            lock_block_id: logical.block_id,
            lock_view: logical.view,
            evidence_lock_binding: [0; 32],
            authority_context_ref: ctx.authority_context_ref,
            committed_anchor: anchor,
            predecessor_ref: Some(self.expected),
            evidence: SupportingEvidence::QcDerived(wire.clone()),
        };
        self.submitted += 1;
        let result = self.owner.publish_locked_held(
            self.guard,
            candidate,
            self.expected,
            Some(self.history),
        );
        let outcome = match result {
            PublishResult::DurableAcknowledged { new_revision } => {
                Publication::DurableAcknowledged(new_revision)
            }
            PublishResult::WriteFailedAmbiguous(_) => Publication::WriteFailedAmbiguous,
            PublishResult::UncertainDurable => Publication::UncertainDurable,
            PublishResult::RefusedPreWrite(error) => {
                if matches!(error, SafetyStoreError::CapacityRefusal(_)) {
                    self.refused = Some(Refused::O4Capacity);
                }
                Publication::RefusedPreWrite
            }
        };
        // O4 consumed and destroyed its candidate, then its working-set lease.
        drop(candidate_lease);
        Ok(outcome)
    }
}

fn candidate_charge(ctx: &PinnedSafetyContext) -> u128 {
    size_of::<LockedRecord>() as u128
        + ctx.b_span()
        + ctx.n() as u128 * (size_of::<Vec<u8>>() + ctx.s_sig) as u128
}

// Source-derived inventory, NOT physical memory inferred from reservation sums.
// Admission, active invocation and returned-owner conversion are disjoint
// phases. Embedded route results/reservations are not charged a second time.
fn adapter_phase_charges() -> (u128, u128, u128) {
    let admission = size_of::<Admission<'static>>()
        + size_of::<Result<Admission<'static>, AdmissionRefusal>>()
        + size_of::<Result<Reservation, SafetyStoreError>>();
    let invocation = support::control_bytes() as usize
        + size_of::<Admission<'static>>()
        // Baseline, actual/expected comparison and by-value snapshot return.
        + 4 * size_of::<StorageSnapshot>()
        // The large invocation return slot exists only AFTER admission.
        + size_of::<ModelResult>()
        + 2 * size_of::<Gate<'static, 'static>>()
        + 2 * size_of::<PublishResult>()
        + size_of::<Result<Publication, Refused>>()
        + size_of::<WireQc>()
        + size_of::<LockedRecord>()
        + 2 * size_of::<Option<CommittedAnchor>>()
        + size_of::<Result<ValidatedRecord, super::super::decision_capture::CurrentLoadFailure>>()
        + size_of::<std::sync::MutexGuard<'static, super::super::backend::SerializationDomain>>()
        // Only the standalone candidate lease. Admission and loader-result
        // reservation controls are already embedded in their whole layouts.
        + size_of::<Reservation>();
    // Both complete owner layouts include their route and coverage. The
    // partially consumed admission is bounded separately during conversion.
    let returned = 2 * size_of::<ModelResult>()
        + size_of::<Admission<'static>>()
        + size_of::<StorageSnapshot>();
    (admission as u128, invocation as u128, returned as u128)
}

fn adapter_charge() -> u128 {
    let (admission, invocation, returned) = adapter_phase_charges();
    admission.max(invocation).max(returned)
}

impl Admission<'_> {
    fn invoke(
        self,
        engine: &mut BasicHotStuffEngine<[u8; 32]>,
        authority: &Authority,
        token: support::Token,
        expected: u64,
        history: &FixtureCommittedHistory,
    ) -> ModelResult {
        let Self { owner, coverage } = self;
        let storage = StorageSnapshot::capture(owner);
        let guard = owner.backend.lock_domain();
        let mut gate = Gate {
            owner,
            guard: &guard,
            history,
            expected,
            context_matches: authority.corresponds(owner.pinned())
                && support::context_matches(engine, &authority.domain, 0, &authority.members),
            publication: None,
            refused: None,
            calls: 0,
            submitted: 0,
        };
        let route = support::invoke(engine, token, &mut |input| gate.evaluate(input));
        let publication = gate.publication;
        let refused = gate.refused;
        let gate_calls = gate.calls;
        let submitted = gate.submitted;
        // The domain covers the synchronous QC application AND success callbacks.
        drop(gate);
        drop(guard);
        let after_route = (
            owner.backend.accounting_current(),
            owner.backend.accounting_aggregate_current(),
        );
        storage.assert_unchanged(owner);
        ModelResult {
            route,
            publication,
            refused,
            gate_calls,
            submitted,
            after_route,
            _coverage: coverage,
        }
    }
}

// Recovery retains the actual failed report (including its consensus-charged
// staged certificate), rather than reconstructing an attempt from QC identity.
struct Interrupted<'a> {
    result: InterruptedRoute,
    predecessor: Predecessor,
    authority: &'a Authority,
    history: &'a FixtureCommittedHistory,
    incarnation: u64,
    expected: u64,
    _coverage: Reservation,
}

struct InterruptedRoute {
    route: Result<support::Report, support::Refusal>,
    publication: Option<Publication>,
    submitted: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Predecessor {
    effects: Effects,
    applications: usize,
    engine: usize,
    // The immutable four-member fixture bounds the entire logical lock, not
    // merely its block/view. No heap-backed predecessor copy is necessary.
    signers: [Option<ValidatorId>; 4],
}

impl Predecessor {
    fn capture(engine: &BasicHotStuffEngine<[u8; 32]>, target: [u8; 32]) -> Self {
        let mut signers = [None; 4];
        if let Some(qc) = engine.locked_qc() {
            assert!(qc.signers.len() <= signers.len());
            for (slot, signer) in signers.iter_mut().zip(&qc.signers) {
                *slot = Some(*signer);
            }
        }
        Self {
            effects: Effects::capture(engine, target),
            applications: support::applications(engine),
            engine: engine as *const _ as usize,
            signers,
        }
    }
}

struct InterruptionAdmission<'a> {
    route: Admission<'a>,
    coverage: Reservation,
}

fn interruption_charge() -> u128 {
    // Separate from the unchanged adapter charge. Includes both conversion
    // slots and the pre-call snapshot; all backing remains in the charged report.
    (2 * size_of::<Interrupted<'static>>()
        + 2 * size_of::<InterruptionAdmission<'static>>()
        + size_of::<Result<InterruptionAdmission<'static>, AdmissionRefusal>>()
        + size_of::<Result<Reservation, SafetyStoreError>>()
        + size_of::<Predecessor>()) as u128
}

fn admit_interruption(
    owner: &SafetyRecordOwner,
) -> Result<InterruptionAdmission<'_>, AdmissionRefusal> {
    let coverage = owner
        .backend
        .accounting()
        .reserve(interruption_charge())
        .map_err(|_| AdmissionRefusal::Capacity)?;
    let route = admit_composition(owner)?;
    Ok(InterruptionAdmission { route, coverage })
}

impl InterruptionAdmission<'_> {
    fn invoke<'a>(
        self,
        engine: &mut BasicHotStuffEngine<[u8; 32]>,
        authority: &'a Authority,
        token: support::Token,
        expected: u64,
        history: &'a FixtureCommittedHistory,
    ) -> Interrupted<'a> {
        let predecessor = Predecessor::capture(engine, token.vote().block_id);
        let incarnation = self.route.owner.backend.incarnation();
        let ModelResult {
            route,
            publication,
            submitted,
            _coverage,
            ..
        } = self
            .route
            .invoke(engine, authority, token, expected, history);
        let result = InterruptedRoute {
            route,
            publication,
            submitted,
        };
        // The returned report keeps its independent consensus reservations.
        // Its model controls now belong to interruption coverage, so the
        // original adapter's invocation coverage need not remain pinned.
        drop(_coverage);
        Interrupted {
            result,
            predecessor,
            authority,
            history,
            incarnation,
            expected,
            _coverage: self.coverage,
        }
    }
}

struct RecoveryAdmission<'a> {
    owner: &'a SafetyRecordOwner,
    coverage: Reservation,
}

// A borrowed, private model owner, not a certificate-verification capability.
// Neither the original attempt nor the genuine O3 proof is copied or consumed.
struct Acknowledged<'a> {
    attempt: &'a Interrupted<'a>,
    proof: &'a ValidatedRecord,
    _coverage: Reservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryOutcome {
    AttemptMismatch,
    RefusedPreWrite,
    WriteFailedAmbiguous,
    UncertainDurable,
}

fn recovery_charge() -> u128 {
    (2 * size_of::<RecoveryAdmission<'static>>()
        + size_of::<Result<RecoveryAdmission<'static>, AdmissionRefusal>>()
        + 2 * size_of::<Result<Acknowledged<'static>, RecoveryOutcome>>()
        + 2 * size_of::<PublishResult>()
        + size_of::<&Interrupted<'static>>()
        + size_of::<&ValidatedRecord>()
        + 2 * size_of::<Option<&WireQc>>()
        + size_of::<Result<Reservation, SafetyStoreError>>()) as u128
}

fn admit_recovery(owner: &SafetyRecordOwner) -> Result<RecoveryAdmission<'_>, AdmissionRefusal> {
    let coverage = owner
        .backend
        .accounting()
        .reserve(recovery_charge())
        .map_err(|_| AdmissionRefusal::Capacity)?;
    Ok(RecoveryAdmission { owner, coverage })
}

fn stored_qc(proof: &ValidatedRecord) -> Option<&WireQc> {
    match &proof.retained().record {
        SafetyRecord::Locked(LockedRecord {
            evidence: SupportingEvidence::QcDerived(qc),
            ..
        }) => Some(qc),
        _ => None,
    }
}

impl RecoveryAdmission<'_> {
    fn acknowledge<'a>(
        self,
        attempt: &'a Interrupted<'a>,
        proof: &'a ValidatedRecord,
    ) -> Result<Acknowledged<'a>, RecoveryOutcome> {
        if attempt.result.publication != Some(Publication::UncertainDurable)
            || attempt.result.submitted != 1
            || attempt.incarnation != self.owner.backend.incarnation()
            || Some(proof.publication_revision()) != attempt.expected.checked_add(1)
            || stored_qc(proof) != attempt.result.route.as_ref().ok().and_then(|r| r.wire())
        {
            return Err(RecoveryOutcome::AttemptMismatch);
        }
        match self.owner.reacknowledge(proof) {
            PublishResult::DurableAcknowledged { new_revision } => {
                assert_eq!(new_revision, proof.publication_revision());
                Ok(Acknowledged {
                    attempt,
                    proof,
                    _coverage: self.coverage,
                })
            }
            PublishResult::RefusedPreWrite(_) => Err(RecoveryOutcome::RefusedPreWrite),
            PublishResult::WriteFailedAmbiguous(_) => Err(RecoveryOutcome::WriteFailedAmbiguous),
            PublishResult::UncertainDurable => Err(RecoveryOutcome::UncertainDurable),
        }
    }
}

struct ResumptionAdmission<'a> {
    owner: &'a SafetyRecordOwner,
    coverage: Reservation,
}

struct ResumptionGate<'a, 'g> {
    owner: &'a SafetyRecordOwner,
    guard: &'a std::sync::MutexGuard<'g, super::super::backend::SerializationDomain>,
    acknowledged: &'a Acknowledged<'a>,
    predecessor: Predecessor,
    context_matches: bool,
    refused: Option<Refused>,
    calls: usize,
    probe: Option<&'a dyn Fn()>,
}

fn resumption_charge() -> u128 {
    // Invocation includes the complete route/facade slots, fresh charged-loader
    // result controls, both gate slots, and caller/return conversion overlap.
    adapter_charge()
        + (2 * size_of::<ResumptionGate<'static, 'static>>()
            + 2 * size_of::<ResumptionAdmission<'static>>()
            + size_of::<Result<ResumptionAdmission<'static>, AdmissionRefusal>>()
            + 2 * size_of::<Predecessor>()
            + 2 * size_of::<Option<&dyn Fn()>>()
            + 2 * size_of::<&ValidatedRecord>()
            + 2 * size_of::<&Interrupted<'static>>()
            + 4 * size_of::<Option<&WireQc>>()
            + size_of::<Result<(), Refused>>()) as u128
}

fn admit_resumption(
    owner: &SafetyRecordOwner,
) -> Result<ResumptionAdmission<'_>, AdmissionRefusal> {
    let coverage = owner
        .backend
        .accounting()
        .reserve(resumption_charge())
        .map_err(|_| AdmissionRefusal::Capacity)?;
    Ok(ResumptionAdmission { owner, coverage })
}

impl ResumptionGate<'_, '_> {
    fn check(&self, input: &support::Input<'_>) -> Result<(), Refused> {
        let acknowledged = self.acknowledged;
        let attempt = acknowledged.attempt;
        let proof = acknowledged.proof;
        if self.owner.recovery_required() {
            return Err(Refused::RecoveryRequired);
        }
        if !self.context_matches
            || attempt.incarnation != self.owner.backend.incarnation()
            || proof.recovery_backend_incarnation() != Some(attempt.incarnation)
            || proof.origin_context_digest() != &context_digest(self.owner.pinned())
        {
            return Err(Refused::Context);
        }
        let current = self
            .owner
            .load_current_validated_locked(self.guard, Some(attempt.history))
            .map_err(|_| Refused::Loader)?;
        if current.publication_revision() != proof.publication_revision()
            || current.encoded() != proof.encoded()
            || current.recovery_backend_incarnation() != proof.recovery_backend_incarnation()
            || current.origin_context_digest() != proof.origin_context_digest()
        {
            return Err(Refused::PublicationChanged);
        }
        if self.predecessor != attempt.predecessor
            || input.lock() != attempt.predecessor.effects.lock
            || input.committed() != attempt.predecessor.effects.committed
            || input.current_view() != attempt.predecessor.effects.view
            || input.target_has_qc()
        {
            return Err(Refused::Predecessor);
        }
        let logical = input.logical();
        let wire = input.wire();
        if input.lock().is_some_and(|(_, view)| logical.view <= view) {
            return Err(Refused::NonAdvancing);
        }
        // Logical signers are mapped to exact bitmap positions without allocation.
        // Full wire equality below includes round, step, signature descriptors
        // and every signature byte; height is never substituted for round.
        let ctx = self.owner.pinned();
        if logical.block_id != wire.block_id
            || logical.view != wire.height
            || wire.chain_id != ctx.chain_id
            || wire.epoch != ctx.epoch
            || wire.suite_id != ctx.qc_suite_id
            || wire.signatures.len() != logical.signers.len()
            || wire.signer_bitmap.len() != ctx.b_span() as usize
            || logical
                .signers
                .iter()
                .enumerate()
                .any(|(position, signer)| {
                    !ctx.validators.iter().enumerate().any(|(index, (id, _))| {
                        id == signer
                            && wire.signer_bitmap[index / 8] & (1 << (index % 8)) != 0
                            && logical.signers[..position]
                                .iter()
                                .all(|previous| previous != signer)
                    })
                })
            || wire
                .signer_bitmap
                .iter()
                .map(|b| b.count_ones() as usize)
                .sum::<usize>()
                != logical.signers.len()
            || stored_qc(&current) != Some(wire)
            || stored_qc(proof) != Some(wire)
            || attempt.result.route.as_ref().ok().and_then(|r| r.wire()) != Some(wire)
        {
            return Err(Refused::Certificate);
        }
        Ok(())
    }

    fn evaluate(&mut self, input: support::Input<'_>) -> bool {
        self.calls += 1;
        match self.check(&input) {
            Ok(()) => {
                if let Some(probe) = self.probe {
                    probe();
                }
                true
            }
            Err(reason) => {
                self.refused = Some(reason);
                false
            }
        }
    }
}

impl ResumptionAdmission<'_> {
    fn invoke(
        self,
        engine: &mut BasicHotStuffEngine<[u8; 32]>,
        token: support::Token,
        acknowledged: &Acknowledged<'_>,
    ) -> ModelResult {
        self.invoke_observed(engine, token, acknowledged, None)
    }

    fn invoke_observed(
        self,
        engine: &mut BasicHotStuffEngine<[u8; 32]>,
        token: support::Token,
        acknowledged: &Acknowledged<'_>,
        probe: Option<&dyn Fn()>,
    ) -> ModelResult {
        let storage = StorageSnapshot::capture(self.owner);
        let guard = self.owner.backend.lock_domain();
        let mut gate = ResumptionGate {
            owner: self.owner,
            guard: &guard,
            acknowledged,
            predecessor: Predecessor::capture(engine, token.vote().block_id),
            context_matches: acknowledged
                .attempt
                .authority
                .corresponds(self.owner.pinned())
                && support::context_matches(
                    engine,
                    &acknowledged.attempt.authority.domain,
                    0,
                    &acknowledged.attempt.authority.members,
                ),
            refused: None,
            calls: 0,
            probe,
        };
        let route = support::invoke(engine, token, &mut |input| gate.evaluate(input));
        let refused = gate.refused;
        let gate_calls = gate.calls;
        drop(gate);
        // Includes ordinary on_qc, callbacks, and route return above. The
        // domain guard remains live through result construction and return.
        if let Some(probe) = probe {
            probe();
        }
        storage.assert_unchanged(self.owner);
        ModelResult {
            route,
            publication: None,
            refused,
            gate_calls,
            submitted: 0,
            after_route: (storage.operational, storage.aggregate),
            _coverage: self.coverage,
        }
    }
}

#[derive(Debug, Default)]
struct Notifications {
    vote: AtomicUsize,
    validator: AtomicUsize,
    qc: AtomicUsize,
    view: AtomicUsize,
    leader: AtomicUsize,
    reset: AtomicUsize,
    guarded_backend: Mutex<Option<SafetyBackend>>,
}
impl Notifications {
    fn successes(&self) -> [usize; 4] {
        let sample = self.sample();
        [sample[2], sample[3], sample[4], sample[5]]
    }

    fn sample(&self) -> [usize; 6] {
        [
            &self.vote,
            &self.validator,
            &self.qc,
            &self.view,
            &self.leader,
            &self.reset,
        ]
        .map(|counter| counter.load(Ordering::SeqCst))
    }

    fn observe_interval(&self) {
        if let Some(backend) = self.guarded_backend.lock().unwrap().as_ref() {
            assert!(
                matches!(
                    backend.try_lock_domain_for_test(),
                    TryLockDomainOutcome::WouldBlock
                ),
                "ordinary synchronous callbacks must remain inside the domain"
            );
        }
    }
}
impl ConsensusProgressRecorder for Notifications {
    fn record_vote_observed(&self, _: bool) {
        self.observe_interval();
        self.vote.fetch_add(1, Ordering::SeqCst);
    }
    fn record_qc_formed(&self) {
        self.observe_interval();
        self.qc.fetch_add(1, Ordering::SeqCst);
    }
    fn record_view_change(&self, _: u64, _: u64) {
        self.observe_interval();
        self.view.fetch_add(1, Ordering::SeqCst);
    }
    fn record_leader_change(&self) {
        self.observe_interval();
        self.leader.fetch_add(1, Ordering::SeqCst);
    }
    fn reset_current_view_votes(&self) {
        self.observe_interval();
        self.reset.fetch_add(1, Ordering::SeqCst);
    }
}
impl ValidatorVoteRecorder for Notifications {
    fn on_validator_vote(&self, _: ValidatorId, _: u64) {
        self.validator.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StorageSnapshot {
    operational: u128,
    aggregate: u128,
    context: u128,
    operational_cap: Option<u128>,
    aggregate_cap: Option<u128>,
    context_cap: Option<u128>,
}

impl StorageSnapshot {
    fn capture(owner: &SafetyRecordOwner) -> Self {
        Self::capture_backend(&owner.backend)
    }

    fn capture_backend(backend: &SafetyBackend) -> Self {
        Self {
            operational: backend.accounting_current(),
            aggregate: backend.accounting_aggregate_current(),
            context: backend.context_accounting_current(),
            operational_cap: backend.accounting_cap(),
            aggregate_cap: backend.accounting_aggregate_cap(),
            context_cap: backend.context_accounting_cap(),
        }
    }

    fn assert_occupancy(&self, owner: &SafetyRecordOwner, operational: u128, aggregate: u128) {
        assert_eq!(
            Self::capture(owner),
            Self {
                operational,
                aggregate,
                ..*self
            }
        );
    }

    fn assert_unchanged(&self, owner: &SafetyRecordOwner) {
        self.assert_occupancy(owner, self.operational, self.aggregate);
    }

    fn assert_returned(&self, owner: &SafetyRecordOwner, result: &ModelResult) {
        let expected = (
            self.operational + adapter_charge(),
            self.aggregate + adapter_charge(),
        );
        assert_eq!(result.after_route, expected);
        self.assert_occupancy(owner, expected.0, expected.1);
    }
}

struct VoteWitness {
    vote: Vote,
    signature_ptr: *const u8,
    signature_capacity: usize,
}

impl VoteWitness {
    fn capture(vote: &Vote) -> Self {
        Self {
            vote: vote.clone(),
            signature_ptr: vote.signature.as_ptr(),
            signature_capacity: vote.signature.capacity(),
        }
    }

    fn assert_original(&self, actual: &Vote) {
        assert!(actual == &self.vote, "complete Vote differs (redacted)");
        assert_eq!(actual.signature.as_ptr(), self.signature_ptr);
        assert_eq!(actual.signature.capacity(), self.signature_capacity);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EngineWitness {
    effects: Effects,
    applications: usize,
    votes: usize,
    notifications: [usize; 6],
    cap: u64,
}

impl EngineWitness {
    fn capture(f: &Fixture, vote: &Vote) -> Self {
        Self {
            effects: Effects::capture(&f.engine, vote.block_id),
            applications: support::applications(&f.engine),
            votes: support::vote_count(&f.engine, vote.height, &vote.block_id),
            notifications: f.notifications.sample(),
            cap: f.engine.state().max_retained_evidence_bytes(),
        }
    }

    fn assert_unchanged(&self, f: &Fixture, vote: &Vote) {
        assert_eq!(Self::capture(f, vote), *self);
    }

    fn assert_retained_refusal(
        &self,
        f: &Fixture,
        witness: &VoteWitness,
        report: &support::Report,
    ) {
        assert_eq!(report.application(), support::Application::Refused);
        assert!(report.logical_quorum() && report.retained() && !report.duplicate());
        assert!(!report.view_advanced());
        let mut expected = *self;
        expected.votes += 1;
        expected.notifications[0] += 1;
        expected.notifications[1] += 1;
        assert_eq!(Self::capture(f, &witness.vote), expected);
        witness.assert_original(
            support::retained_vote(&f.engine, witness.vote.height, witness.vote.validator_index)
                .unwrap(),
        );
    }

    fn assert_success(
        &self,
        f: &Fixture,
        witness: &VoteWitness,
        result: &ModelResult,
        duplicate: bool,
    ) {
        assert_eq!(
            result.publication,
            Some(Publication::DurableAcknowledged(f.revision + 1))
        );
        assert_eq!((result.gate_calls, result.submitted), (1, 1));
        assert!(result.refused.is_none());
        let report = result.route.as_ref().ok().unwrap();
        assert_eq!(report.application(), support::Application::Applied);
        assert!(report.logical_quorum() && report.view_advanced());
        assert_eq!(report.duplicate(), duplicate);
        assert_eq!(report.retained(), !duplicate);
        // Consumed-Vote retries deliberately use a different genuinely signed
        // round; the retained first Vote, not the incoming duplicate, wins.
        assert_eq!(report.first_retained_conflict(), duplicate);
        assert_eq!(report.wire().unwrap().round, witness.vote.round);
        let actual = Self::capture(f, &witness.vote);
        assert_eq!(actual.applications, self.applications + 1);
        assert_eq!(
            actual.votes,
            if duplicate {
                self.votes
            } else {
                self.votes + 1
            }
        );
        assert_eq!(actual.cap, self.cap);
        assert_eq!(
            actual.notifications,
            self.notifications.map(|count| count + 1)
        );
        assert_eq!(
            actual.effects,
            Effects {
                lock: Some((witness.vote.block_id, witness.vote.height)),
                own_qc: true,
                view: self.effects.view + 1,
                ..self.effects
            }
        );
        witness.assert_original(
            support::retained_vote(&f.engine, witness.vote.height, witness.vote.validator_index)
                .unwrap(),
        );
    }
}

struct Fixture {
    authority: Authority,
    engine: BasicHotStuffEngine<[u8; 32]>,
    owner: SafetyRecordOwner,
    history: FixtureCommittedHistory,
    notifications: Arc<Notifications>,
    revision: u64,
    _dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let authority = Authority::new();
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), authority.set());
        support::install(&mut engine, &authority.domain, 0, &authority.members);
        for i in 0..4 {
            support::register(
                &mut engine,
                IDS[i],
                i as u64 + 1,
                i.checked_sub(1).map(|p| IDS[p]),
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let backend = SafetyBackend::open_or_initialize(
            dir.path(),
            SafetyBackendPolicy::EnabledForTesting,
            TrustBundleEnvironment::Devnet,
        )
        .unwrap();
        let owner = SafetyRecordOwner::attach(backend, authority.pinned()).unwrap();
        let revision = owner.initialize(true).unwrap();
        let notifications = Arc::new(Notifications::default());
        engine.set_progress_recorder(notifications.clone());
        engine.set_validator_vote_recorder(notifications.clone());
        Self {
            authority,
            engine,
            owner,
            history: FixtureCommittedHistory::new(),
            notifications,
            revision,
            _dir: dir,
        }
    }
    fn token(&mut self, signer: usize, view: u64, round: u64) -> support::Token {
        let vote = self.authority.vote(signer, view, round);
        support::admit(&mut self.engine, ValidatorId(signer as u64), vote).unwrap()
    }
    fn seed(&mut self, view: u64) {
        for signer in 0..3 {
            let token = self.token(signer, view, 9);
            let admission = admit_composition(&self.owner).unwrap();
            let result = admission.invoke(
                &mut self.engine,
                &self.authority,
                token,
                self.revision,
                &self.history,
            );
            let report = result
                .route
                .as_ref()
                .unwrap_or_else(|_| panic!("seed preparation refused"));
            if signer == 2 {
                assert_eq!(report.application(), support::Application::Applied);
                let Some(Publication::DurableAcknowledged(revision)) = result.publication else {
                    panic!("seed must acknowledge");
                };
                self.revision = revision;
            } else {
                assert_eq!(report.application(), support::Application::NotAttempted);
                assert_eq!(result.gate_calls, 0);
            }
            self.assert_released(result);
        }
    }
    fn ready(&mut self, view: u64, mixed: bool) -> support::Token {
        for signer in 0..2 {
            let token = self.token(signer, view, if mixed && signer == 0 { 10 } else { 9 });
            let admission = admit_composition(&self.owner).unwrap();
            let result = admission.invoke(
                &mut self.engine,
                &self.authority,
                token,
                self.revision,
                &self.history,
            );
            assert_eq!(result.gate_calls, 0);
        }
        self.token(2, view, 9)
    }
    fn assert_released(&self, result: ModelResult) {
        let storage = StorageSnapshot::capture(&self.owner);
        assert_eq!(
            (storage.operational, storage.aggregate),
            (adapter_charge(), storage.context + adapter_charge())
        );
        assert_eq!(result.after_route, (storage.operational, storage.aggregate));
        drop(result);
        // Before any diagnostic readback allocation.
        storage.assert_occupancy(&self.owner, 0, storage.context);
    }
    fn read(&self) -> ValidatedRecord {
        self.owner.read_validate(Some(&self.history)).unwrap()
    }
}

#[test]
fn acknowledged_three_chain_post_ack_order_and_serialization() {
    let mut f = Fixture::new();
    f.seed(1);
    f.seed(2);
    let token = f.ready(3, false);
    let applications = support::applications(&f.engine);
    let qc_notifications = f.notifications.qc.load(Ordering::SeqCst);
    let view_notifications = f.notifications.view.load(Ordering::SeqCst);
    let notes = f.notifications.clone();
    let backend = f.owner.backend.clone();
    let hooks = Arc::new(AtomicUsize::new(0));
    let observed = hooks.clone();
    f.owner
        .backend
        .set_pre_effective_hook(Arc::new(move |op, _| {
            assert_eq!(op, "O4");
            assert_eq!(support::application_count(), applications);
            assert_eq!(notes.qc.load(Ordering::SeqCst), qc_notifications);
            assert_eq!(notes.view.load(Ordering::SeqCst), view_notifications);
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let competitor = backend.clone();
            let thread = std::thread::spawn(move || {
                tx.send(matches!(
                    competitor.try_lock_domain_for_test(),
                    TryLockDomainOutcome::WouldBlock
                ))
                .unwrap();
            });
            assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
            thread.join().unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
        }));
    let old_view = f.engine.current_view();
    *f.notifications.guarded_backend.lock().unwrap() = Some(f.owner.backend.clone());
    let admission = admit_composition(&f.owner).unwrap();
    let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    *f.notifications.guarded_backend.lock().unwrap() = None;
    f.owner.backend.set_pre_effective_hook(Arc::new(|_, _| {}));
    assert_eq!(f.owner.backend.accounting_current(), adapter_charge());
    assert_eq!(
        f.owner.backend.accounting_aggregate_current(),
        f.owner.backend.context_accounting_current() + adapter_charge()
    );
    assert_eq!(hooks.load(Ordering::SeqCst), 1);
    assert_eq!(
        result.publication,
        Some(Publication::DurableAcknowledged(f.revision + 1))
    );
    assert_eq!((result.gate_calls, result.submitted), (1, 1));
    let report = result
        .route
        .as_ref()
        .unwrap_or_else(|_| panic!("prepared route refused"));
    assert_eq!(report.application(), support::Application::Applied);
    assert!(report.logical_quorum() && report.view_advanced() && report.retained());
    assert_eq!(support::applications(&f.engine), applications + 1);
    let target_qc = f
        .engine
        .state()
        .get_block(&IDS[2])
        .unwrap()
        .own_qc
        .as_ref()
        .unwrap();
    assert_eq!(
        (target_qc.block_id, target_qc.view, target_qc.signers.len()),
        (IDS[2], 3, 3)
    );
    assert_eq!(f.engine.committed_block(), Some(&IDS[0]));
    assert_eq!(f.engine.committed_height(), Some(0));
    assert!(f.engine.current_view() > old_view);
    assert_eq!(
        f.notifications.qc.load(Ordering::SeqCst),
        qc_notifications + 1
    );
    assert!(matches!(
        f.owner.backend.try_lock_domain_for_test(),
        TryLockDomainOutcome::Acquired(_)
    ));
    f.authority.verify_test_evidence(report.wire().unwrap());
    let proof = f.read();
    assert_eq!(proof.evidence_status(), EvidenceStatus::Unverified);
    let SafetyRecord::Locked(locked) = &proof.retained().record else {
        panic!("locked");
    };
    assert_eq!((locked.lock_block_id, locked.lock_view), (IDS[2], 3));
    assert!(
        locked.committed_anchor.is_none(),
        "later commit must not become earlier history"
    );
    let SupportingEvidence::QcDerived(qc) = &locked.evidence else {
        panic!("QC");
    };
    assert!(
        qc == report.wire().unwrap(),
        "exact staged wire QC differs (redacted)"
    );
    assert_eq!(qc.round, 9);
    drop(proof);
    f.assert_released(result);
    println!("A: acknowledged -> Allow -> one on_qc; genuine three-chain commit/view; competing try-lock blocked");
}

#[test]
fn prewrite_refusal_and_genuine_duplicate_retry_first_retained() {
    let mut f = Fixture::new();
    f.seed(1);
    f.seed(2);
    let token = f.ready(3, false);
    let ptr = token.vote().signature.as_ptr();
    let capacity = token.vote().signature.capacity();
    let diagnostic_lease = f
        .owner
        .backend
        .accounting()
        .reserve(
            max_safety_record_bytes(f.owner.pinned()).unwrap()
                + size_of::<Vec<u8>>() as u128
                + size_of::<Reservation>() as u128,
        )
        .unwrap();
    let before = f.read();
    let bytes = before.encoded().to_vec();
    drop(before);
    let apps = support::applications(&f.engine);
    let effects = Effects::capture(&f.engine, IDS[2]);
    let votes = f.notifications.vote.load(Ordering::SeqCst);
    let qcs = f.notifications.qc.load(Ordering::SeqCst);
    f.owner.backend.set_inject(InjectFault::FailBeforeSubmit);
    let admission = admit_composition(&f.owner).unwrap();
    let refused = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    assert_eq!(refused.publication, Some(Publication::RefusedPreWrite));
    let report = refused
        .route
        .as_ref()
        .unwrap_or_else(|_| panic!("preparation"));
    assert_eq!(report.application(), support::Application::Refused);
    assert!(report.retained() && report.logical_quorum() && report.wire().is_some());
    assert_eq!(support::vote_count(&f.engine, 3, &IDS[2]), 3);
    assert_eq!(support::applications(&f.engine), apps);
    assert_eq!(Effects::capture(&f.engine, IDS[2]), effects);
    assert_eq!(f.notifications.vote.load(Ordering::SeqCst), votes + 1);
    assert_eq!(f.notifications.validator.load(Ordering::SeqCst), votes + 1);
    assert_eq!(f.notifications.qc.load(Ordering::SeqCst), qcs);
    assert!(f.engine.committed_block().is_none());
    assert!(!f.owner.recovery_required());
    assert_eq!(
        f.owner.backend.accounting_current(),
        adapter_charge() + diagnostic_lease.charge()
    );
    drop(refused);
    assert_eq!(
        f.owner.backend.accounting_current(),
        diagnostic_lease.charge()
    );
    assert_eq!(
        f.owner.backend.accounting_aggregate_current(),
        f.owner.backend.context_accounting_current() + diagnostic_lease.charge()
    );
    let proof = f.read();
    assert!(
        proof.encoded() == bytes,
        "predecessor bytes changed (redacted)"
    );
    assert_eq!(proof.publication_revision(), f.revision);
    drop(proof);
    drop(bytes);
    drop(diagnostic_lease);
    assert_eq!(f.owner.backend.accounting_current(), 0);
    f.owner.backend.set_inject(InjectFault::None);
    let token = f.token(2, 3, 19);
    let admission = admit_composition(&f.owner).unwrap();
    let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    let report = result
        .route
        .as_ref()
        .unwrap_or_else(|_| panic!("duplicate preparation"));
    assert!(report.duplicate() && report.first_retained_conflict());
    assert_eq!(report.application(), support::Application::Applied);
    assert_eq!(report.wire().unwrap().round, 9);
    f.authority.verify_test_evidence(report.wire().unwrap());
    let retained = support::retained_vote(&f.engine, 3, 2).unwrap();
    assert_eq!(
        (retained.signature.as_ptr(), retained.signature.capacity()),
        (ptr, capacity)
    );
    assert_eq!(support::applications(&f.engine), apps + 1);
    assert_eq!(f.engine.committed_block(), Some(&IDS[0]));
    f.assert_released(result);
    println!("B: pre-submit refusal leaves predecessor; real duplicate retains original round/signature and applies once");
}

#[test]
fn ambiguous_publication_latches_without_assuming_unchanged() {
    publication_failure(
        InjectFault::WriteErrors,
        Publication::WriteFailedAmbiguous,
        false,
    );
}
#[test]
fn uncertain_publication_survives_and_lock_mismatch_stays_blocked() {
    publication_failure(
        InjectFault::UncertainAfterWrite,
        Publication::UncertainDurable,
        true,
    );
}
fn publication_failure(fault: InjectFault, outcome: Publication, newer: bool) {
    let mut f = Fixture::new();
    f.seed(1);
    f.seed(2);
    let token = f.ready(3, false);
    let apps = support::applications(&f.engine);
    let effects = Effects::capture(&f.engine, IDS[2]);
    let qcs = f.notifications.qc.load(Ordering::SeqCst);
    let view = f.engine.current_view();
    f.owner.backend.set_inject(fault);
    let admission = admit_composition(&f.owner).unwrap();
    let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    assert_eq!(result.publication, Some(outcome));
    assert_eq!(
        result.route.as_ref().ok().unwrap().application(),
        support::Application::Refused
    );
    assert!(f.owner.recovery_required());
    assert_eq!(support::applications(&f.engine), apps);
    assert_eq!(Effects::capture(&f.engine, IDS[2]), effects);
    assert_eq!(f.notifications.qc.load(Ordering::SeqCst), qcs);
    assert_eq!(f.engine.current_view(), view);
    assert!(f.engine.committed_block().is_none());
    f.assert_released(result);
    f.owner.backend.set_inject(InjectFault::None);
    let proof = f.read();
    // These are actual injected-backend results, not claims about arbitrary errors.
    assert_eq!(proof.publication_revision(), f.revision + u64::from(newer));
    let SafetyRecord::Locked(lock) = &proof.retained().record else {
        panic!("locked");
    };
    assert_eq!(
        (lock.lock_block_id, lock.lock_view),
        if newer { (IDS[2], 3) } else { (IDS[1], 2) },
    );
    drop(proof);
    if newer {
        f.revision += 1;
    }
    let token = f.token(2, 3, 9);
    let admission = admit_composition(&f.owner).unwrap();
    let retry = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    if newer {
        assert_eq!(retry.refused, Some(Refused::Lock));
        assert_eq!(retry.submitted, 0);
        assert!(retry.publication.is_none());
    } else {
        assert_eq!(retry.publication, Some(Publication::RefusedPreWrite));
    }
    assert!(f.owner.recovery_required());
    assert_eq!(support::applications(&f.engine), apps);
    assert_eq!(Effects::capture(&f.engine, IDS[2]), effects);
    f.assert_released(retry);
    println!("C: {outcome:?}; surviving_newer={newer}; latch remains set, no O5/catch-up");
}

#[test]
fn stale_revision_context_and_durable_engine_mismatch_refuse_before_submission() {
    for mode in 0..3 {
        let mut f = Fixture::new();
        f.seed(1);
        if mode == 0 {
            f.revision += 1;
        }
        if mode == 1 {
            // A fresh engine honestly has no lock; the durable restriction is 1.
            let mut other = BasicHotStuffEngine::new(ValidatorId(0), f.authority.set());
            support::install(&mut other, &f.authority.domain, 0, &f.authority.members);
            f.engine = other;
        }
        let token = f.ready(2, false);
        let bad_authority = Authority::new();
        let apps = support::applications(&f.engine);
        let effects = Effects::capture(&f.engine, IDS[1]);
        let storage = StorageSnapshot::capture(&f.owner);
        let result = admit_composition(&f.owner).unwrap().invoke(
            &mut f.engine,
            if mode == 2 {
                &bad_authority
            } else {
                &f.authority
            },
            token,
            f.revision,
            &f.history,
        );
        storage.assert_returned(&f.owner, &result);
        assert_eq!(
            result.refused,
            Some([Refused::Revision, Refused::Lock, Refused::Context][mode])
        );
        assert_eq!(result.submitted, 0);
        assert!(result.publication.is_none());
        assert_eq!(support::applications(&f.engine), apps);
        assert_eq!(Effects::capture(&f.engine, IDS[1]), effects);
        f.assert_released(result);
    }
}

#[test]
fn equal_and_lower_real_candidates_refuse_without_publication() {
    let mut f = Fixture::new();
    f.seed(1);
    f.seed(2);
    let apps = support::applications(&f.engine);
    for view in [2, 1] {
        let effects = Effects::capture(&f.engine, IDS[(view - 1) as usize]);
        let token = f.token(2, view, 9);
        let admission = admit_composition(&f.owner).unwrap();
        let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
        assert_eq!(result.refused, Some(Refused::NonAdvancing));
        assert_eq!(result.submitted, 0);
        assert!(result.publication.is_none());
        assert_eq!(support::applications(&f.engine), apps);
        assert_eq!(
            Effects::capture(&f.engine, IDS[(view - 1) as usize]),
            effects
        );
        f.assert_released(result);
    }
}

#[test]
fn inconsistent_complete_evidence_never_calls_publication_gate() {
    let mut f = Fixture::new();
    let token = f.ready(1, true);
    let apps = support::applications(&f.engine);
    let admission = admit_composition(&f.owner).unwrap();
    let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    let report = result.route.as_ref().ok().unwrap();
    assert!(report.logical_quorum() && report.incomplete() && report.retained());
    assert!(report.wire().is_none());
    assert_eq!(report.application(), support::Application::Suppressed);
    assert_eq!((result.gate_calls, result.submitted), (0, 0));
    assert!(result.publication.is_none());
    assert_eq!(support::vote_count(&f.engine, 1, &IDS[0]), 3);
    assert_eq!(support::applications(&f.engine), apps);
    assert!(f.engine.locked_qc().is_none());
    assert_eq!(f.notifications.vote.load(Ordering::SeqCst), 3);
    f.assert_released(result);
}

#[test]
fn missing_retained_evidence_from_ordinary_legacy_vote_never_calls_gate() {
    let mut f = Fixture::new();
    let vote = f.authority.vote(0, 1, 9);
    // Reachable ordinary legacy entrypoint, once only; no private-ledger mutation.
    assert!(f
        .engine
        .on_vote_event(ValidatorId(0), &vote)
        .unwrap()
        .is_none());
    let token = f.token(1, 1, 9);
    let admission = admit_composition(&f.owner).unwrap();
    let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    assert_eq!(result.gate_calls, 0);
    f.assert_released(result);
    let token = f.token(2, 1, 9);
    let apps = support::applications(&f.engine);
    let admission = admit_composition(&f.owner).unwrap();
    let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    let report = result.route.as_ref().ok().unwrap();
    assert!(report.logical_quorum() && report.incomplete() && report.retained());
    assert_eq!(report.application(), support::Application::Suppressed);
    assert_eq!((result.gate_calls, result.submitted), (0, 0));
    assert_eq!(support::applications(&f.engine), apps);
    assert_eq!(f.notifications.vote.load(Ordering::SeqCst), 3);
    assert_eq!(f.notifications.qc.load(Ordering::SeqCst), 0);
    assert_eq!(support::vote_count(&f.engine, 1, &IDS[0]), 3);
    f.assert_released(result);
}

#[test]
fn bootstrap_storage_does_not_hide_an_existing_engine_lock() {
    let mut f = Fixture::new();
    f.seed(1);
    let token = f.ready(2, false);
    let dir = tempfile::tempdir().unwrap();
    let backend = SafetyBackend::open_or_initialize(
        dir.path(),
        SafetyBackendPolicy::EnabledForTesting,
        TrustBundleEnvironment::Devnet,
    )
    .unwrap();
    let owner = SafetyRecordOwner::attach(backend, f.authority.pinned()).unwrap();
    let revision = owner.initialize(true).unwrap();
    let before = Effects::capture(&f.engine, IDS[1]);
    let ledger = support::ledger(&f.engine);
    let consensus_before = ledger.sample();
    let storage = StorageSnapshot::capture(&owner);
    let result = admit_composition(&owner).unwrap().invoke(
        &mut f.engine,
        &f.authority,
        token,
        revision,
        &f.history,
    );
    storage.assert_returned(&owner, &result);
    assert_eq!(result.refused, Some(Refused::Lock));
    assert_eq!(result.submitted, 0);
    assert!(result.publication.is_none());
    assert_eq!(Effects::capture(&f.engine, IDS[1]), before);
    assert_report_ledger(
        &ledger,
        consensus_before,
        result.route.as_ref().ok().unwrap(),
    );
    drop(result);
    storage.assert_unchanged(&owner);
    assert_retained_ledger(&ledger, consensus_before);
}

#[test]
fn incompatible_pinned_profile_fields_refuse_before_submission() {
    for field in 0..9 {
        let mut f = Fixture::new();
        let mut ctx = f.authority.pinned();
        match field {
            0 => ctx.network_genesis_id[0] ^= 1,
            1 => ctx.authority_context_ref[0] ^= 1,
            2 => ctx.chain_id += 1,
            3 => ctx.epoch += 1,
            4 => ctx.qc_suite_id += 1,
            5 => ctx.s_sig -= 1,
            6 => ctx.validators[0].1 += 1,
            7 => ctx.require_height_equals_round = true,
            _ => ctx.timeout_suite_id += 1,
        }
        let dir = tempfile::tempdir().unwrap();
        let backend = SafetyBackend::open_or_initialize(
            dir.path(),
            SafetyBackendPolicy::EnabledForTesting,
            TrustBundleEnvironment::Devnet,
        )
        .unwrap();
        let owner = SafetyRecordOwner::attach(backend, ctx).unwrap();
        let revision = owner.initialize(true).unwrap();
        let token = f.ready(1, false);
        let apps = support::applications(&f.engine);
        let ledger = support::ledger(&f.engine);
        let consensus_before = ledger.sample();
        let storage = StorageSnapshot::capture(&owner);
        let result = admit_composition(&owner).unwrap().invoke(
            &mut f.engine,
            &f.authority,
            token,
            revision,
            &f.history,
        );
        storage.assert_returned(&owner, &result);
        assert_eq!(result.refused, Some(Refused::Context));
        assert_eq!(result.submitted, 0);
        assert!(result.publication.is_none());
        assert_eq!(support::applications(&f.engine), apps);
        assert_report_ledger(
            &ledger,
            consensus_before,
            result.route.as_ref().ok().unwrap(),
        );
        drop(result);
        storage.assert_unchanged(&owner);
        assert_retained_ledger(&ledger, consensus_before);
    }
}

#[test]
fn existing_anchor_is_preserved_and_requires_independent_history() {
    let mut f = Fixture::new();
    f.seed(1);
    f.seed(2);
    f.seed(3);
    assert_eq!(f.engine.committed_block(), Some(&IDS[0]));
    f.history = FixtureCommittedHistory::new().with(IDS[0], 0);
    let token = f.token(2, 3, 9);
    let admission = admit_composition(&f.owner).unwrap();
    let report = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    assert_eq!(report.refused, Some(Refused::NonAdvancing));
    // Independent anchored predecessor fixture, published with ordinary O4
    // using the genuinely staged certificate AFTER the grandparent commit exists.
    let dir = tempfile::tempdir().unwrap();
    let backend = SafetyBackend::open_or_initialize(
        dir.path(),
        SafetyBackendPolicy::EnabledForTesting,
        TrustBundleEnvironment::Devnet,
    )
    .unwrap();
    let owner = SafetyRecordOwner::attach(backend, f.authority.pinned()).unwrap();
    let revision = owner.initialize(true).unwrap();
    let setup_lease = owner
        .backend
        .accounting()
        .reserve(
            candidate_charge(owner.pinned()) + max_safety_record_bytes(owner.pinned()).unwrap(),
        )
        .unwrap();
    let qc = report.route.as_ref().ok().unwrap().wire().unwrap();
    let candidate = make_locked_qc(
        owner.pinned(),
        IDS[2],
        3,
        qc.clone(),
        Some(CommittedAnchor {
            block_id: IDS[0],
            height: 0,
        }),
    )
    .unwrap();
    let PublishResult::DurableAcknowledged { new_revision } =
        owner.publish_locked(candidate, revision, Some(&f.history))
    else {
        panic!("anchored fixture");
    };
    drop(setup_lease);
    f.assert_released(report);
    f.owner = owner;
    f.revision = new_revision;
    f.history = FixtureCommittedHistory::new();
    let token = f.ready(4, false);
    let admission = admit_composition(&f.owner).unwrap();
    let refused = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    assert_eq!(refused.refused, Some(Refused::Loader));
    assert_eq!(refused.submitted, 0);
    f.assert_released(refused);
    f.history = FixtureCommittedHistory::new().with(IDS[0], 0);
    let storage = StorageSnapshot::capture(&f.owner);
    let ledger = support::ledger(&f.engine);
    let retained_before = ledger.sample();
    let token = f.token(2, 4, 9);
    let token_bytes = support::token_inline_bytes() + token.vote().signature.capacity() as u64;
    let consensus_before = ledger.sample();
    let admission = admit_composition(&f.owner).unwrap();
    let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    // Both storage ledgers and their independently sampled ceilings are checked
    // at return, BEFORE diagnostic readback admits any loader objects.
    storage.assert_returned(&f.owner, &result);
    assert_eq!(
        result.route.as_ref().ok().unwrap().application(),
        support::Application::Applied
    );
    assert_eq!(f.engine.committed_block(), Some(&IDS[1]));
    let report = result.route.as_ref().ok().unwrap();
    assert!(report.duplicate());
    let (a, p) = report.charges();
    assert_eq!(
        ledger.sample(),
        (
            consensus_before.0 + a + p - token_bytes,
            0,
            consensus_before.2,
            0,
            consensus_before.4 + 1,
            0,
        )
    );
    let proof = f.read();
    let SafetyRecord::Locked(lock) = &proof.retained().record else {
        panic!("locked");
    };
    assert_eq!(
        lock.committed_anchor,
        Some(CommittedAnchor {
            block_id: IDS[0],
            height: 0
        })
    );
    assert_eq!(proof.evidence_status(), EvidenceStatus::Unverified);
    drop(proof);
    storage.assert_returned(&f.owner, &result);
    f.assert_released(result);
    storage.assert_unchanged(&f.owner);
    assert_eq!(ledger.sample(), retained_before);
}

#[test]
fn consensus_preparation_pressure_returns_original_token_and_restores_ledgers() {
    let mut f = Fixture::new();
    let token = f.ready(1, false);
    let witness = VoteWitness::capture(token.vote());
    let ledger = support::ledger(&f.engine);
    let before = ledger.sample();
    let storage = StorageSnapshot::capture(&f.owner);
    let original_cap = f.engine.state().max_retained_evidence_bytes();
    support::set_cap(&mut f.engine, before.0);
    let engine = EngineWitness::capture(&f, &witness.vote);
    let admission = admit_composition(&f.owner).unwrap();
    let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    storage.assert_returned(&f.owner, &result);
    assert_eq!((result.gate_calls, result.submitted), (0, 0));
    assert!(result.publication.is_none() && result.refused.is_none());
    let refusal = result.route.as_ref().err().unwrap();
    assert!(refusal.preparation_pressure());
    witness.assert_original(refusal.vote());
    assert_eq!(ledger.sample(), before);
    engine.assert_unchanged(&f, &witness.vote);
    assert!(support::retained_vote(&f.engine, 1, 2).is_none());
    let ModelResult {
        route, _coverage, ..
    } = result;
    let token = route.err().unwrap().into_token();
    drop(_coverage);
    witness.assert_original(token.vote());
    storage.assert_unchanged(&f.owner);
    assert_eq!(ledger.sample(), before);
    engine.assert_unchanged(&f, &witness.vote);
    support::set_cap(&mut f.engine, original_cap);
    assert_eq!(f.engine.state().max_retained_evidence_bytes(), original_cap);
    let retry_engine = EngineWitness::capture(&f, &witness.vote);
    let admission = admit_composition(&f.owner).unwrap();
    let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    storage.assert_returned(&f.owner, &result);
    retry_engine.assert_success(&f, &witness, &result, false);
    assert_report_ledger(&ledger, before, result.route.as_ref().ok().unwrap());
    f.assert_released(result);
    storage.assert_unchanged(&f.owner);
    assert_retained_ledger(&ledger, before);
    assert_eq!(f.engine.state().max_retained_evidence_bytes(), original_cap);
}

#[test]
fn adapter_candidate_and_o4_pressure_are_distinct_and_cleanup_is_immediate() {
    for boundary in 0..3 {
        let mut f = Fixture::new();
        let token = f.ready(1, false);
        let witness = VoteWitness::capture(token.vote());
        let ledger = support::ledger(&f.engine);
        let before = ledger.sample();
        let storage = StorageSnapshot::capture(&f.owner);
        let engine = EngineWitness::capture(&f, &witness.vote);
        let cap = storage.aggregate_cap.unwrap();
        // Leave exact space for successively deeper real admissions.
        let loader = f.owner.retained_holder_charge().unwrap()
            + max_transient_decoded_working_set(f.owner.pinned())
                .unwrap()
                .saturating_sub(
                    max_retained_generation_bytes(f.owner.pinned(), size_of_timeout_msg()).unwrap(),
                )
            + max_safety_record_bytes(f.owner.pinned()).unwrap();
        let leave = match boundary {
            0 => adapter_charge() - 1,
            1 => adapter_charge() + candidate_charge(f.owner.pinned()) - 1,
            _ => adapter_charge() + loader + candidate_charge(f.owner.pinned()),
        };
        let held = f
            .owner
            .backend
            .accounting()
            .reserve(cap - storage.aggregate - leave)
            .unwrap();
        storage.assert_occupancy(
            &f.owner,
            storage.operational + held.charge(),
            storage.aggregate + held.charge(),
        );
        let pressure_storage = StorageSnapshot::capture(&f.owner);
        // The token stays in this caller's slot during admission. In
        // particular the failure carrier cannot contain a ModelResult.
        let admission = admit_composition(&f.owner);
        if boundary == 0 {
            assert!(matches!(admission, Err(AdmissionRefusal::Capacity)));
            witness.assert_original(token.vote());
            assert_eq!(ledger.sample(), before);
            pressure_storage.assert_unchanged(&f.owner);
            engine.assert_unchanged(&f, &witness.vote);
            assert!(support::retained_vote(&f.engine, 1, 2).is_none());
            drop(held);
            storage.assert_unchanged(&f.owner);
            engine.assert_unchanged(&f, &witness.vote);
            assert_eq!(ledger.sample(), before);
            let admission = admit_composition(&f.owner).unwrap();
            storage.assert_occupancy(
                &f.owner,
                storage.operational + adapter_charge(),
                storage.aggregate + adapter_charge(),
            );
            witness.assert_original(token.vote());
            engine.assert_unchanged(&f, &witness.vote);
            assert_eq!(ledger.sample(), before);
            let result =
                admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
            storage.assert_returned(&f.owner, &result);
            engine.assert_success(&f, &witness, &result, false);
            assert_report_ledger(&ledger, before, result.route.as_ref().ok().unwrap());
            f.assert_released(result);
            storage.assert_unchanged(&f.owner);
            assert_retained_ledger(&ledger, before);
        } else {
            let result = admission.unwrap().invoke(
                &mut f.engine,
                &f.authority,
                token,
                f.revision,
                &f.history,
            );
            pressure_storage.assert_returned(&f.owner, &result);
            let report = result.route.as_ref().ok().unwrap();
            assert_report_ledger(&ledger, before, report);
            engine.assert_retained_refusal(&f, &witness, report);
            if boundary == 1 {
                assert!(result.publication.is_none());
                assert_eq!(result.refused, Some(Refused::CandidatePressure));
                assert_eq!(result.submitted, 0);
            } else {
                assert_eq!(result.publication, Some(Publication::RefusedPreWrite));
                assert_eq!(result.refused, Some(Refused::O4Capacity));
                assert_eq!(result.submitted, 1);
            }
            drop(result);
            assert_retained_ledger(&ledger, before);
            pressure_storage.assert_unchanged(&f.owner);
            drop(held);
            storage.assert_unchanged(&f.owner);
            let retry_engine = EngineWitness::capture(&f, &witness.vote);
            let token = f.token(2, 1, 19);
            let retry_ledger = ledger.sample();
            let admission = admit_composition(&f.owner).unwrap();
            let result =
                admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
            storage.assert_returned(&f.owner, &result);
            retry_engine.assert_success(&f, &witness, &result, true);
            // A duplicate consumes its own token/signature, while the
            // original retained Vote remains. Report coverage is independent.
            let (a, p) = result.route.as_ref().ok().unwrap().charges();
            assert_eq!(
                ledger.sample(),
                (
                    retry_ledger.0 + a + p
                        - support::token_inline_bytes()
                        - witness.signature_capacity as u64,
                    0,
                    retry_ledger.2,
                    0,
                    retry_ledger.4 + 1,
                    0,
                )
            );
            f.assert_released(result);
            storage.assert_unchanged(&f.owner);
            assert_retained_ledger(&ledger, before);
        }
    }
}

fn assert_report_ledger(
    ledger: &support::Ledger,
    before: (u64, u64, usize, usize, usize, usize),
    report: &support::Report,
) {
    let (a, p) = report.charges();
    assert_eq!(
        ledger.sample(),
        (
            before.0 + a + p - support::token_inline_bytes(),
            0,
            before.2,
            0,
            before.4 + 1,
            0,
        )
    );
}

fn assert_retained_ledger(
    ledger: &support::Ledger,
    before: (u64, u64, usize, usize, usize, usize),
) {
    assert_eq!(
        ledger.sample(),
        (
            before.0 - support::token_inline_bytes(),
            0,
            before.2,
            0,
            before.4,
            0,
        )
    );
}

#[test]
fn existing_post_ack_hook_unwind_releases_both_ledgers() {
    let mut f = Fixture::new();
    let token = f.ready(1, false);
    let ledger = support::ledger(&f.engine);
    let storage = StorageSnapshot::capture(&f.owner);
    f.owner.backend.set_pre_effective_hook(Arc::new(|_, _| {
        panic!("existing post-ack hook test unwind")
    }));
    let admission = admit_composition(&f.owner).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history)
    }));
    assert!(result.is_err());
    storage.assert_unchanged(&f.owner);
    let sample = ledger.sample();
    assert_eq!((sample.1, sample.3, sample.4, sample.5), (0, 0, 0, 0));
    // Poisoned owner is not reused or silently recovered.
    let backend = f.owner.backend.clone();
    drop(f);
    assert_eq!(ledger.sample(), support::empty_ledger_floor());
    assert_eq!(
        StorageSnapshot::capture_backend(&backend),
        StorageSnapshot {
            operational: 0,
            aggregate: 0,
            context: 0,
            ..storage
        }
    );
}

#[test]
fn ownership_phase_operands_and_independent_final_floors() {
    let mut f = Fixture::new();
    let ctx = f.owner.pinned();
    let r = max_safety_record_bytes(ctx).unwrap();
    let g = max_retained_generation_bytes(ctx, size_of_timeout_msg()).unwrap();
    let t = max_transient_decoded_working_set(ctx).unwrap();
    let o4 = 2 * t + 3 * r + super::super::backend::META_ENCODED_LEN;
    let loader = f.owner.retained_holder_charge().unwrap() + t.saturating_sub(g) + r;
    let a = adapter_charge();
    let c = candidate_charge(ctx);
    let context = f.owner.backend.context_accounting_current();
    assert_eq!(ctx.s_sig, 2420);
    assert_eq!(ctx.n(), 4);
    assert_eq!(ctx.b_span(), 1);
    assert!(a + c + o4 + context <= f.owner.backend.accounting_aggregate_cap().unwrap());
    println!("operands N=4 S_sig=2420 B_span=1 R={r} G={g} T={t} QC_G={} backing={} A={a} C={c} context={context}",
        max_qc_generation_bytes(ctx).unwrap(), max_decoded_evidence_backing_bytes(ctx, size_of_timeout_msg()).unwrap());
    println!("adapter operands facade={} gate={} result={} publish={} wire={} locked={} anchor={} loader_result={} guard={} reservation={}",
        support::control_bytes(), size_of::<Gate<'static, 'static>>(), size_of::<ModelResult>(),
        size_of::<PublishResult>(), size_of::<WireQc>(), size_of::<LockedRecord>(),
        size_of::<Option<CommittedAnchor>>(),
        size_of::<Result<ValidatedRecord, super::super::decision_capture::CurrentLoadFailure>>(),
        size_of::<std::sync::MutexGuard<'static, super::super::backend::SerializationDomain>>(),
        size_of::<Reservation>());
    let (admission, invocation, returned) = adapter_phase_charges();
    println!("corrected carrier layouts: admission_owner={} admission_result={} admission_diagnostic={} reserve_result={} invocation_result={} route_result={} returned_owner={} storage_snapshot={}",
        size_of::<Admission<'static>>(), size_of::<Result<Admission<'static>, AdmissionRefusal>>(),
        size_of::<AdmissionRefusal>(), size_of::<Result<Reservation, SafetyStoreError>>(),
        size_of::<ModelResult>(), size_of::<Result<support::Report, support::Refusal>>(),
        size_of::<ModelResult>(), size_of::<StorageSnapshot>());
    println!("corrected control phase bounds: admission={admission} invocation={invocation} returned_conversion={returned} selected={a}");
    assert!(size_of::<Result<Admission<'static>, AdmissionRefusal>>() < size_of::<ModelResult>());
    println!(
        "source phase bounds: loader={} candidate={} O4={} returned={} aggregate_cap={}",
        context + a + c + loader,
        context + a + c,
        context + a + c + o4,
        context + a,
        f.owner.backend.accounting_aggregate_cap().unwrap()
    );
    let token = f.ready(1, false);
    let ledger = support::ledger(&f.engine);
    let storage = StorageSnapshot::capture(&f.owner);
    let admission = admit_composition(&f.owner).unwrap();
    let result = admission.invoke(&mut f.engine, &f.authority, token, f.revision, &f.history);
    storage.assert_returned(&f.owner, &result);
    let report_live = ledger.sample();
    let charges = result.route.as_ref().ok().unwrap().charges();
    assert_eq!(
        (report_live.1, report_live.3, report_live.4, report_live.5),
        (0, 0, 1, 0)
    );
    println!("executed independent samples: consensus={report_live:?} report_A={} wire_P={}; storage current={} peak={} aggregate_current={} aggregate_peak={}",
        charges.0, charges.1,
        f.owner.backend.accounting_current(), f.owner.backend.accounting_peak(),
        f.owner.backend.accounting_aggregate_current(), f.owner.backend.accounting_aggregate_peak());
    let o4_live = o4_owned_live_objects().unwrap();
    println!(
        "executed O4 post-ack live object sample={o4_live:?} total={}",
        o4_live.total()
    );
    f.assert_released(result);
    storage.assert_unchanged(&f.owner);
    let standing = ledger.sample();
    assert_eq!(
        (standing.1, standing.3, standing.4, standing.5),
        (0, 0, 0, 0)
    );
    let backend = f.owner.backend.clone();
    drop(f);
    assert_eq!(ledger.sample(), support::empty_ledger_floor());
    println!("independent consensus floors: standing={standing:?} observer_only={:?}; storage final=0 context final=0 aggregate final=0",
        ledger.sample());
    assert_eq!(
        StorageSnapshot::capture_backend(&backend),
        StorageSnapshot {
            operational: 0,
            aggregate: 0,
            context: 0,
            ..storage
        }
    );
}

// Test-harness assertions below allocate no component-owned backing.
fn acknowledged_checked<'a>(
    owner: &SafetyRecordOwner,
    attempt: &'a Interrupted<'a>,
    proof: &'a ValidatedRecord,
) -> Acknowledged<'a> {
    let before = StorageSnapshot::capture(owner);
    let ack = admit_recovery(owner)
        .unwrap()
        .acknowledge(attempt, proof)
        .ok()
        .unwrap();
    before.assert_occupancy(
        owner,
        before.operational + recovery_charge(),
        before.aggregate + recovery_charge(),
    );
    ack
}

macro_rules! release_recovery {
    ($owner:expr, $ack:ident, $proof:ident, $attempt:ident) => {{
        let before = StorageSnapshot::capture(&$owner);
        drop($ack);
        before.assert_occupancy(
            &$owner,
            before.operational - recovery_charge(),
            before.aggregate - recovery_charge(),
        );
        drop($proof);
        let removed = recovery_charge() + $owner.retained_holder_charge().unwrap();
        before.assert_occupancy(
            &$owner,
            before.operational - removed,
            before.aggregate - removed,
        );
        drop($attempt);
        before.assert_occupancy(
            &$owner,
            before.operational - removed - interruption_charge(),
            before.aggregate - removed - interruption_charge(),
        );
    }};
}

fn teardown_recovery(f: Fixture, ledger: &support::Ledger) {
    let before = StorageSnapshot::capture(&f.owner);
    assert_eq!(before.operational, 0);
    assert_eq!(before.aggregate, before.context);
    let backend = f.owner.backend.clone();
    drop(f);
    assert_eq!(ledger.sample(), support::empty_ledger_floor());
    assert_eq!(
        StorageSnapshot::capture_backend(&backend),
        StorageSnapshot {
            operational: 0,
            aggregate: 0,
            context: 0,
            ..before
        }
    );
}

fn uncertain_token(f: &mut Fixture) -> support::Token {
    f.seed(1);
    f.seed(2);
    f.ready(3, false)
}

fn duplicate(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    authority: &Authority,
    signer: usize,
    round: u64,
) -> support::Token {
    support::admit(
        engine,
        ValidatorId(signer as u64),
        authority.vote(signer, 3, round),
    )
    .unwrap()
}

fn assert_recovery_provenance(
    proof: &ValidatedRecord,
    owner: &SafetyRecordOwner,
    pointer: *const u8,
) {
    assert_eq!(proof.encoded().as_ptr(), pointer);
    assert_eq!(
        proof.recovery_backend_incarnation(),
        Some(owner.backend.incarnation())
    );
    assert!(
        proof.origin_context_digest() == &context_digest(owner.pinned()),
        "context differs (redacted)"
    );
    assert_eq!(proof.evidence_status(), EvidenceStatus::Unverified);
}

fn release_duplicate_result(
    owner: &SafetyRecordOwner,
    storage: StorageSnapshot,
    ledger: &support::Ledger,
    before: (u64, u64, usize, usize, usize, usize),
    result: ModelResult,
) {
    storage.assert_occupancy(
        owner,
        storage.operational + resumption_charge(),
        storage.aggregate + resumption_charge(),
    );
    assert_eq!(
        result.after_route,
        (
            storage.operational + resumption_charge(),
            storage.aggregate + resumption_charge()
        )
    );
    assert_eq!(result.submitted, 0);
    assert!(result.publication.is_none());
    let report = result.route.as_ref().ok().unwrap();
    assert!(report.duplicate() && !report.retained() && report.logical_quorum());
    let (a, p) = report.charges();
    let consumed = support::token_inline_bytes() + SIG as u64;
    assert_eq!(
        ledger.sample(),
        (before.0 + a + p - consumed, 0, before.2, 0, before.4 + 1, 0)
    );
    drop(result);
    storage.assert_unchanged(owner);
    assert_eq!(
        ledger.sample(),
        (before.0 - consumed, 0, before.2, 0, before.4, 0)
    );
}

#[test]
fn uncertain_o4_explicit_o5_exact_three_chain_resumption_and_repeated_use() {
    let mut f = Fixture::new();
    let token = uncertain_token(&mut f);
    let first = VoteWitness::capture(token.vote());
    let effects = Effects::capture(&f.engine, IDS[2]);
    let apps = support::applications(&f.engine);
    let notes = f.notifications.sample();
    let ledger = support::ledger(&f.engine);
    let base = StorageSnapshot::capture(&f.owner);
    f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
    let attempt = admit_interruption(&f.owner).unwrap().invoke(
        &mut f.engine,
        &f.authority,
        token,
        f.revision,
        &f.history,
    );
    base.assert_occupancy(
        &f.owner,
        interruption_charge(),
        base.context + interruption_charge(),
    );
    assert_eq!(
        attempt.result.publication,
        Some(Publication::UncertainDurable)
    );
    assert_eq!(
        attempt.result.route.as_ref().ok().unwrap().application(),
        support::Application::Refused
    );
    assert_eq!(Effects::capture(&f.engine, IDS[2]), effects);
    assert_eq!(support::applications(&f.engine), apps);
    assert_eq!(
        f.notifications.sample(),
        [
            notes[0] + 1,
            notes[1] + 1,
            notes[2],
            notes[3],
            notes[4],
            notes[5]
        ]
    );
    assert!(f.owner.recovery_required());
    first.assert_original(support::retained_vote(&f.engine, 3, 2).unwrap());
    f.owner.backend.set_inject(InjectFault::None);
    let storage = StorageSnapshot::capture(&f.owner);
    let proof = f.read();
    storage.assert_occupancy(
        &f.owner,
        storage.operational + f.owner.retained_holder_charge().unwrap(),
        storage.aggregate + f.owner.retained_holder_charge().unwrap(),
    );
    assert_eq!(proof.publication_revision(), f.revision + 1);
    assert!(
        stored_qc(&proof) == attempt.result.route.as_ref().ok().unwrap().wire(),
        "surviving QC differs from interrupted complete QC (redacted)"
    );
    f.authority.verify_test_evidence(stored_qc(&proof).unwrap());
    // O2/O3 does not create an Acknowledged owner, clear recovery, or unblock
    // the original advancing route.
    let token = duplicate(&mut f.engine, &f.authority, 2, 19);
    let blocked = admit_composition(&f.owner).unwrap().invoke(
        &mut f.engine,
        &f.authority,
        token,
        proof.publication_revision(),
        &f.history,
    );
    assert_eq!(blocked.refused, Some(Refused::Lock));
    assert_eq!(
        blocked.route.as_ref().ok().unwrap().application(),
        support::Application::Refused
    );
    assert_eq!(support::applications(&f.engine), apps);
    drop(blocked);
    assert!(f.owner.recovery_required());
    let before_o5 = StorageSnapshot::capture(&f.owner);
    let pointer = proof.encoded().as_ptr();
    let acknowledged = acknowledged_checked(&f.owner, &attempt, &proof);
    before_o5.assert_occupancy(
        &f.owner,
        before_o5.operational + recovery_charge(),
        before_o5.aggregate + recovery_charge(),
    );
    assert!(!f.owner.recovery_required());
    assert_recovery_provenance(&proof, &f.owner, pointer);
    // Diagnostic loader only AFTER the immediate O5 restoration assertion.
    let readback = f.read();
    assert!(
        readback.encoded() == proof.encoded(),
        "O5 changed publication bytes (redacted)"
    );
    assert_eq!(
        readback.publication_revision(),
        proof.publication_revision()
    );
    drop(readback);
    let token = duplicate(&mut f.engine, &f.authority, 2, 19);
    let before = ledger.sample();
    let storage = StorageSnapshot::capture(&f.owner);
    let notes = f.notifications.sample();
    *f.notifications.guarded_backend.lock().unwrap() = Some(f.owner.backend.clone());
    let observations = AtomicUsize::new(0);
    let backend = f.owner.backend.clone();
    let notifications = f.notifications.clone();
    let probe = || {
        let phase = observations.fetch_add(1, Ordering::SeqCst);
        assert_eq!(support::application_count(), apps + phase);
        assert_eq!(notifications.qc.load(Ordering::SeqCst), notes[2] + phase);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let contender = backend.clone();
        let thread = std::thread::spawn(move || {
            tx.send(matches!(
                contender.try_lock_domain_for_test(),
                TryLockDomainOutcome::WouldBlock
            ))
            .unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
        thread.join().unwrap();
    };
    let result = admit_resumption(&f.owner).unwrap().invoke_observed(
        &mut f.engine,
        token,
        &acknowledged,
        Some(&probe),
    );
    assert_eq!(observations.load(Ordering::SeqCst), 2);
    *f.notifications.guarded_backend.lock().unwrap() = None;
    let report = result.route.as_ref().ok().unwrap();
    assert_eq!(report.application(), support::Application::Applied);
    assert!(report.first_retained_conflict() && report.view_advanced());
    assert_eq!(result.gate_calls, 1);
    assert!(result.refused.is_none());
    assert!(
        report.wire() == stored_qc(&proof),
        "resumed QC differs (redacted)"
    );
    assert_eq!(report.wire().unwrap().round, 9);
    assert_eq!(support::applications(&f.engine), apps + 1);
    assert_eq!(
        f.engine.locked_qc().map(|q| (q.block_id, q.view)),
        Some((IDS[2], 3))
    );
    let own = f
        .engine
        .state()
        .get_block(&IDS[2])
        .unwrap()
        .own_qc
        .as_ref()
        .unwrap();
    assert_eq!((own.block_id, own.view), (IDS[2], 3));
    assert_eq!(own.signers.len(), 3);
    assert!(own.signers.iter().all(|id| id.as_u64() < 3));
    assert_eq!(f.engine.committed_block(), Some(&IDS[0]));
    assert_eq!(f.engine.committed_height(), Some(0));
    assert_eq!(f.engine.current_view(), effects.view + 1);
    assert_eq!(
        f.notifications.sample(),
        [
            notes[0] + 1,
            notes[1] + 1,
            notes[2] + 1,
            notes[3] + 1,
            notes[4] + 1,
            notes[5] + 1
        ]
    );
    first.assert_original(support::retained_vote(&f.engine, 3, 2).unwrap());
    release_duplicate_result(&f.owner, storage, &ledger, before, result);
    let post = Effects::capture(&f.engine, IDS[2]);
    let notes = f.notifications.sample();
    let token = duplicate(&mut f.engine, &f.authority, 2, 29);
    let before = ledger.sample();
    let result = admit_resumption(&f.owner)
        .unwrap()
        .invoke(&mut f.engine, token, &acknowledged);
    assert_eq!(result.refused, Some(Refused::Predecessor));
    assert_eq!(
        result.route.as_ref().ok().unwrap().application(),
        support::Application::Refused
    );
    assert_eq!(Effects::capture(&f.engine, IDS[2]), post);
    assert_eq!(support::applications(&f.engine), apps + 1);
    assert_eq!(
        f.notifications.sample(),
        [
            notes[0] + 1,
            notes[1] + 1,
            notes[2],
            notes[3],
            notes[4],
            notes[5]
        ]
    );
    release_duplicate_result(&f.owner, storage, &ledger, before, result);
    drop(acknowledged);
    before_o5.assert_unchanged(&f.owner);
    drop(proof);
    let live = StorageSnapshot::capture(&f.owner);
    assert_eq!(live.operational, interruption_charge());
    drop(attempt);
    base.assert_unchanged(&f.owner);
    let backend = f.owner.backend.clone();
    drop(f);
    assert_eq!(ledger.sample(), support::empty_ledger_floor());
    assert_eq!(
        StorageSnapshot::capture_backend(&backend),
        StorageSnapshot {
            operational: 0,
            aggregate: 0,
            context: 0,
            ..base
        }
    );
    println!("O5-A: uncertain O4 -> genuine O3 alone blocked -> explicit O5 unchanged bytes/revision -> exact duplicate QC Applied once; repeated use refused; final independent floors zero");
}

#[test]
fn ordinary_o5_fault_outcomes_cleanup_and_acknowledged_retry() {
    for (fault, outcome) in [
        (
            InjectFault::FailBeforeSubmit,
            RecoveryOutcome::RefusedPreWrite,
        ),
        (
            InjectFault::WriteErrors,
            RecoveryOutcome::WriteFailedAmbiguous,
        ),
        (
            InjectFault::UncertainAfterWrite,
            RecoveryOutcome::UncertainDurable,
        ),
    ] {
        let mut f = Fixture::new();
        let token = uncertain_token(&mut f);
        f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
        let attempt = admit_interruption(&f.owner).unwrap().invoke(
            &mut f.engine,
            &f.authority,
            token,
            f.revision,
            &f.history,
        );
        let proof = f.read();
        let before = StorageSnapshot::capture(&f.owner);
        let effects = Effects::capture(&f.engine, IDS[2]);
        let apps = support::applications(&f.engine);
        let pointer = proof.encoded().as_ptr();
        f.owner.backend.set_inject(fault);
        let failed = admit_recovery(&f.owner)
            .unwrap()
            .acknowledge(&attempt, &proof);
        assert!(matches!(failed, Err(actual) if actual == outcome));
        before.assert_unchanged(&f.owner);
        assert!(f.owner.recovery_required());
        assert_eq!(Effects::capture(&f.engine, IDS[2]), effects);
        assert_eq!(support::applications(&f.engine), apps);
        assert_recovery_provenance(&proof, &f.owner, pointer);
        drop(failed);
        before.assert_unchanged(&f.owner);
        // No assumption about arbitrary ambiguous-failure storage contents.
        f.owner.backend.set_inject(InjectFault::None);
        let ack = acknowledged_checked(&f.owner, &attempt, &proof);
        before.assert_occupancy(
            &f.owner,
            before.operational + recovery_charge(),
            before.aggregate + recovery_charge(),
        );
        assert!(!f.owner.recovery_required());
        let ledger = support::ledger(&f.engine);
        let token = duplicate(&mut f.engine, &f.authority, 2, 19);
        let consensus = ledger.sample();
        let storage = StorageSnapshot::capture(&f.owner);
        let resumed = admit_resumption(&f.owner)
            .unwrap()
            .invoke(&mut f.engine, token, &ack);
        assert_eq!(
            resumed.route.as_ref().ok().unwrap().application(),
            support::Application::Applied
        );
        release_duplicate_result(&f.owner, storage, &ledger, consensus, resumed);
        release_recovery!(f.owner, ack, proof, attempt);
        teardown_recovery(f, &ledger);
        println!("O5-B: {outcome:?}, recovery remains required; cleared-fault ordinary O5 retry acknowledges before Applied");
    }
}

#[test]
fn ordinary_foreign_and_stale_o5_proofs_and_changed_publication_are_fenced() {
    let mut f = Fixture::new();
    let token = uncertain_token(&mut f);
    f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
    let attempt = admit_interruption(&f.owner).unwrap().invoke(
        &mut f.engine,
        &f.authority,
        token,
        f.revision,
        &f.history,
    );
    f.owner.backend.set_inject(InjectFault::None);
    let proof = f.read();
    let other_dir = tempfile::tempdir().unwrap();
    let other_backend = SafetyBackend::open_or_initialize(
        other_dir.path(),
        SafetyBackendPolicy::EnabledForTesting,
        TrustBundleEnvironment::Devnet,
    )
    .unwrap();
    let other = SafetyRecordOwner::attach(other_backend, f.authority.pinned()).unwrap();
    other.initialize(true).unwrap();
    let foreign = other.read_validate(Some(&f.history)).unwrap();
    let before = StorageSnapshot::capture(&f.owner);
    assert!(
        foreign.origin_context_digest() == proof.origin_context_digest(),
        "fixture context differs (redacted)"
    );
    assert_ne!(
        foreign.recovery_backend_incarnation(),
        proof.recovery_backend_incarnation()
    );
    assert!(matches!(
        f.owner.reacknowledge(&foreign),
        PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(_))
    ));
    before.assert_unchanged(&f.owner);
    assert!(f.owner.recovery_required());
    drop(foreign);
    let ack = acknowledged_checked(&f.owner, &attempt, &proof);
    let storage = StorageSnapshot::capture(&f.owner);
    // Stage a real, independently signed successor via the accepted Vote route,
    // but deliberately refuse its gate so the engine still has predecessor 2.
    let mut staged = None;
    for signer in 0..3 {
        let vote = f.authority.vote(signer, 4, 17);
        let token = support::admit(&mut f.engine, ValidatorId(signer as u64), vote).unwrap();
        let report = support::invoke(&mut f.engine, token, &mut |_| false)
            .ok()
            .unwrap();
        if signer == 2 {
            staged = Some(report);
        }
    }
    let staged = staged.unwrap();
    let wire = staged.wire().unwrap();
    f.authority.verify_test_evidence(wire);
    // This ordinary O4 setup owns exactly three signatures, not the profile's
    // four-signature maximum. Admit the precise clone capacities before copying.
    let exact_candidate = size_of::<LockedRecord>() as u128
        + wire.signer_bitmap.len() as u128
        + (wire.signatures.len() * size_of::<Vec<u8>>()) as u128
        + wire
            .signatures
            .iter()
            .map(|sig| sig.len() as u128)
            .sum::<u128>();
    let candidate_lease = f
        .owner
        .backend
        .accounting()
        .reserve(exact_candidate)
        .unwrap();
    let candidate = LockedRecord {
        lock_block_id: wire.block_id,
        lock_view: wire.height,
        evidence_lock_binding: [0; 32],
        authority_context_ref: f.owner.pinned().authority_context_ref,
        committed_anchor: None,
        predecessor_ref: Some(proof.publication_revision()),
        evidence: SupportingEvidence::QcDerived(wire.clone()),
    };
    let SupportingEvidence::QcDerived(candidate_qc) = &candidate.evidence else {
        unreachable!()
    };
    assert_eq!(
        candidate_qc.signer_bitmap.capacity(),
        wire.signer_bitmap.len()
    );
    assert_eq!(candidate_qc.signatures.capacity(), wire.signatures.len());
    assert!(candidate_qc
        .signatures
        .iter()
        .zip(&wire.signatures)
        .all(|(a, b)| a.capacity() == b.len()));
    let published =
        f.owner
            .publish_locked(candidate, proof.publication_revision(), Some(&f.history));
    assert!(
        matches!(published, PublishResult::DurableAcknowledged { new_revision } if new_revision == proof.publication_revision() + 1)
    );
    drop(candidate_lease);
    storage.assert_unchanged(&f.owner);
    println!(
        "O5 changed-publication executed storage peak: op={} aggregate={} cap={:?}",
        f.owner.backend.accounting_peak(),
        f.owner.backend.accounting_aggregate_peak(),
        storage.aggregate_cap
    );
    let ledger = support::ledger(&f.engine);
    let token = duplicate(&mut f.engine, &f.authority, 2, 19);
    let before = ledger.sample();
    let effects = Effects::capture(&f.engine, IDS[2]);
    let successes = f.notifications.successes();
    let result = admit_resumption(&f.owner)
        .unwrap()
        .invoke(&mut f.engine, token, &ack);
    assert_eq!(result.refused, Some(Refused::PublicationChanged));
    assert_eq!(
        result.route.as_ref().ok().unwrap().application(),
        support::Application::Refused
    );
    assert_eq!(Effects::capture(&f.engine, IDS[2]), effects);
    assert_eq!(f.notifications.successes(), successes);
    release_duplicate_result(&f.owner, storage, &ledger, before, result);
    let before = StorageSnapshot::capture(&f.owner);
    assert!(matches!(
        f.owner.reacknowledge(&proof),
        PublishResult::RefusedPreWrite(SafetyStoreError::PublicationMismatch(_))
    ));
    before.assert_unchanged(&f.owner);
    drop(staged);
    release_recovery!(f.owner, ack, proof, attempt);
    teardown_recovery(f, &ledger);
    println!("O5-C: ordinary foreign/stale proof refusals; valid advancing O4 after O5 invalidates earlier acknowledgement; no sealed-proof mutation");
}

#[test]
fn genuine_alternative_complete_signer_membership_is_not_exact_resumption() {
    let mut f = Fixture::new();
    let token = uncertain_token(&mut f);
    f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
    let attempt = admit_interruption(&f.owner).unwrap().invoke(
        &mut f.engine,
        &f.authority,
        token,
        f.revision,
        &f.history,
    );
    f.owner.backend.set_inject(InjectFault::None);
    let proof = f.read();
    let ack = acknowledged_checked(&f.owner, &attempt, &proof);
    // Adding the fourth genuine Vote forms a valid four-signer QC for the SAME
    // block/view/round. No retained evidence is removed or replaced.
    let token = duplicate(&mut f.engine, &f.authority, 3, 9);
    let witness = VoteWitness::capture(token.vote());
    let ledger = support::ledger(&f.engine);
    let before = ledger.sample();
    let storage = StorageSnapshot::capture(&f.owner);
    let effects = Effects::capture(&f.engine, IDS[2]);
    let apps = support::applications(&f.engine);
    let successes = f.notifications.successes();
    let result = admit_resumption(&f.owner)
        .unwrap()
        .invoke(&mut f.engine, token, &ack);
    storage.assert_occupancy(
        &f.owner,
        storage.operational + resumption_charge(),
        storage.aggregate + resumption_charge(),
    );
    assert_eq!(result.refused, Some(Refused::Certificate));
    let report = result.route.as_ref().ok().unwrap();
    assert_eq!(report.application(), support::Application::Refused);
    assert!(report.retained() && !report.duplicate() && report.logical_quorum());
    let alternative = report.wire().unwrap();
    f.authority.verify_test_evidence(alternative);
    let original = stored_qc(&proof).unwrap();
    assert_eq!(
        (alternative.block_id, alternative.height, alternative.round),
        (original.block_id, original.height, original.round)
    );
    assert!(
        alternative.signer_bitmap != original.signer_bitmap,
        "alternative membership did not differ (redacted)"
    );
    assert_eq!(
        (alternative.signatures.len(), original.signatures.len()),
        (4, 3)
    );
    assert_eq!(Effects::capture(&f.engine, IDS[2]), effects);
    assert_eq!(support::applications(&f.engine), apps);
    assert_eq!(f.notifications.successes(), successes);
    assert_report_ledger(&ledger, before, report);
    witness.assert_original(support::retained_vote(&f.engine, 3, 3).unwrap());
    drop(result);
    storage.assert_unchanged(&f.owner);
    assert_retained_ledger(&ledger, before);
    release_recovery!(f.owner, ack, proof, attempt);
    teardown_recovery(f, &ledger);
    println!("O5-D: genuinely admitted and cryptographically verified alternative four-signer QC refused; original three-signer certificate retained exactly");
}

#[test]
fn independently_advanced_engine_cannot_resume_interrupted_predecessor() {
    let mut f = Fixture::new();
    let token = uncertain_token(&mut f);
    f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
    let attempt = admit_interruption(&f.owner).unwrap().invoke(
        &mut f.engine,
        &f.authority,
        token,
        f.revision,
        &f.history,
    );
    f.owner.backend.set_inject(InjectFault::None);
    let proof = f.read();
    let ack = acknowledged_checked(&f.owner, &attempt, &proof);
    for signer in 0..3 {
        let vote = f.authority.vote(signer, 4, 9);
        f.engine
            .on_vote_event(ValidatorId(signer as u64), &vote)
            .unwrap();
    }

    assert_eq!(f.engine.locked_qc().unwrap().view, 4);
    let effects = Effects::capture(&f.engine, IDS[2]);
    let apps = support::applications(&f.engine);
    let successes = f.notifications.successes();
    let token = duplicate(&mut f.engine, &f.authority, 2, 19);
    let ledger = support::ledger(&f.engine);
    let before = ledger.sample();
    let storage = StorageSnapshot::capture(&f.owner);
    let result = admit_resumption(&f.owner)
        .unwrap()
        .invoke(&mut f.engine, token, &ack);
    assert_eq!(result.refused, Some(Refused::Predecessor));
    assert_eq!(Effects::capture(&f.engine, IDS[2]), effects);
    assert_eq!(support::applications(&f.engine), apps);
    assert_eq!(f.notifications.successes(), successes);
    release_duplicate_result(&f.owner, storage, &ledger, before, result);
    release_recovery!(f.owner, ack, proof, attempt);
    teardown_recovery(f, &ledger);
}

#[test]
fn interruption_admission_preserves_original_vote_under_real_pressure() {
    let mut f = Fixture::new();
    let token = uncertain_token(&mut f);
    let witness = VoteWitness::capture(token.vote());
    let ledger = support::ledger(&f.engine);
    let consensus = ledger.sample();
    let storage = StorageSnapshot::capture(&f.owner);
    let held = f
        .owner
        .backend
        .accounting()
        .reserve(
            storage.aggregate_cap.unwrap()
                - storage.aggregate
                - interruption_charge()
                - adapter_charge()
                + 1,
        )
        .unwrap();
    let pressured = StorageSnapshot::capture(&f.owner);
    assert!(matches!(
        admit_interruption(&f.owner),
        Err(AdmissionRefusal::Capacity)
    ));
    pressured.assert_unchanged(&f.owner);
    witness.assert_original(token.vote());
    assert_eq!(ledger.sample(), consensus);
    drop(held);
    storage.assert_unchanged(&f.owner);
    f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
    let attempt = admit_interruption(&f.owner).unwrap().invoke(
        &mut f.engine,
        &f.authority,
        token,
        f.revision,
        &f.history,
    );
    assert_eq!(
        attempt.result.publication,
        Some(Publication::UncertainDurable)
    );
    f.owner.backend.set_inject(InjectFault::None);
    let proof = f.read();
    let ack = acknowledged_checked(&f.owner, &attempt, &proof);
    let token = duplicate(&mut f.engine, &f.authority, 2, 19);
    let before = ledger.sample();
    let live = StorageSnapshot::capture(&f.owner);
    let result = admit_resumption(&f.owner)
        .unwrap()
        .invoke(&mut f.engine, token, &ack);
    assert_eq!(
        result.route.as_ref().ok().unwrap().application(),
        support::Application::Applied
    );
    release_duplicate_result(&f.owner, live, &ledger, before, result);
    witness.assert_original(support::retained_vote(&f.engine, 3, 2).unwrap());
    release_recovery!(f.owner, ack, proof, attempt);
    storage.assert_unchanged(&f.owner);
    teardown_recovery(f, &ledger);
}

#[test]
fn recovery_admission_and_ordinary_o5_working_set_pressure_preserve_borrowed_proofs() {
    for boundary in 0..2 {
        let mut f = Fixture::new();
        let token = uncertain_token(&mut f);
        f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
        let attempt = admit_interruption(&f.owner).unwrap().invoke(
            &mut f.engine,
            &f.authority,
            token,
            f.revision,
            &f.history,
        );
        f.owner.backend.set_inject(InjectFault::None);
        let proof = f.read();
        let pointer = proof.encoded().as_ptr();
        let token = duplicate(&mut f.engine, &f.authority, 2, 19);
        let witness = VoteWitness::capture(token.vote());
        let ledger = support::ledger(&f.engine);
        let consensus = ledger.sample();
        let storage = StorageSnapshot::capture(&f.owner);
        let leave = if boundary == 0 {
            recovery_charge() - 1
        } else {
            recovery_charge()
        };
        let held = f
            .owner
            .backend
            .accounting()
            .reserve(storage.aggregate_cap.unwrap() - storage.aggregate - leave)
            .unwrap();
        let pressured = StorageSnapshot::capture(&f.owner);
        if boundary == 0 {
            assert!(matches!(
                admit_recovery(&f.owner),
                Err(AdmissionRefusal::Capacity)
            ));
        } else {
            let result = admit_recovery(&f.owner)
                .unwrap()
                .acknowledge(&attempt, &proof);
            assert!(matches!(result, Err(RecoveryOutcome::RefusedPreWrite)));
            drop(result);
        }
        pressured.assert_unchanged(&f.owner);
        witness.assert_original(token.vote());
        assert_recovery_provenance(&proof, &f.owner, pointer);
        assert_eq!(ledger.sample(), consensus);
        assert!(f.owner.recovery_required());
        drop(held);
        storage.assert_unchanged(&f.owner);
        let ack = acknowledged_checked(&f.owner, &attempt, &proof);
        storage.assert_occupancy(
            &f.owner,
            storage.operational + recovery_charge(),
            storage.aggregate + recovery_charge(),
        );
        witness.assert_original(token.vote());
        assert_recovery_provenance(&proof, &f.owner, pointer);
        let live = StorageSnapshot::capture(&f.owner);
        let result = admit_resumption(&f.owner)
            .unwrap()
            .invoke(&mut f.engine, token, &ack);
        assert_eq!(
            result.route.as_ref().ok().unwrap().application(),
            support::Application::Applied
        );
        release_duplicate_result(&f.owner, live, &ledger, consensus, result);
        release_recovery!(f.owner, ack, proof, attempt);
        teardown_recovery(f, &ledger);
    }
}

#[test]
fn resumption_admission_loader_and_consensus_pressure_restore_before_retry() {
    for boundary in 0..3 {
        let mut f = Fixture::new();
        let token = uncertain_token(&mut f);
        f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
        let attempt = admit_interruption(&f.owner).unwrap().invoke(
            &mut f.engine,
            &f.authority,
            token,
            f.revision,
            &f.history,
        );
        f.owner.backend.set_inject(InjectFault::None);
        let proof = f.read();
        let pointer = proof.encoded().as_ptr();
        let ack = acknowledged_checked(&f.owner, &attempt, &proof);
        let token = duplicate(&mut f.engine, &f.authority, 2, 19);
        let witness = VoteWitness::capture(token.vote());
        let ledger = support::ledger(&f.engine);
        let before = ledger.sample();
        let effects = Effects::capture(&f.engine, IDS[2]);
        let apps = support::applications(&f.engine);
        let successes = f.notifications.successes();
        let storage = StorageSnapshot::capture(&f.owner);
        let original_cap = f.engine.state().max_retained_evidence_bytes();
        let mut retry = None;
        if boundary < 2 {
            let leave = resumption_charge() - u128::from(boundary == 0);
            let held = f
                .owner
                .backend
                .accounting()
                .reserve(storage.aggregate_cap.unwrap() - storage.aggregate - leave)
                .unwrap();
            let pressured = StorageSnapshot::capture(&f.owner);
            if boundary == 0 {
                assert!(matches!(
                    admit_resumption(&f.owner),
                    Err(AdmissionRefusal::Capacity)
                ));
                witness.assert_original(token.vote());
                retry = Some(token);
                assert_eq!(ledger.sample(), before);
                pressured.assert_unchanged(&f.owner);
            } else {
                let result = admit_resumption(&f.owner)
                    .unwrap()
                    .invoke(&mut f.engine, token, &ack);
                assert_eq!(result.refused, Some(Refused::Loader));
                assert_eq!(
                    result.route.as_ref().ok().unwrap().application(),
                    support::Application::Refused
                );
                release_duplicate_result(&f.owner, pressured, &ledger, before, result);
            }

            assert_recovery_provenance(&proof, &f.owner, pointer);
            drop(held);
            storage.assert_unchanged(&f.owner);
        } else {
            support::set_cap(&mut f.engine, before.0);
            let result = admit_resumption(&f.owner)
                .unwrap()
                .invoke(&mut f.engine, token, &ack);
            storage.assert_occupancy(
                &f.owner,
                storage.operational + resumption_charge(),
                storage.aggregate + resumption_charge(),
            );
            assert_eq!(result.gate_calls, 0);
            let refusal = result.route.as_ref().err().unwrap();
            assert!(refusal.preparation_pressure());
            witness.assert_original(refusal.vote());
            assert_eq!(ledger.sample(), before);
            let ModelResult {
                route, _coverage, ..
            } = result;
            retry = Some(route.err().unwrap().into_token());
            drop(_coverage);
            storage.assert_unchanged(&f.owner);
            assert_recovery_provenance(&proof, &f.owner, pointer);
            support::set_cap(&mut f.engine, original_cap);
        }
        assert_eq!(Effects::capture(&f.engine, IDS[2]), effects);
        assert_eq!(support::applications(&f.engine), apps);
        assert_eq!(f.notifications.successes(), successes);
        let token = retry.unwrap_or_else(|| duplicate(&mut f.engine, &f.authority, 2, 19));
        if boundary != 1 {
            witness.assert_original(token.vote());
        }
        let before = ledger.sample();
        let result = admit_resumption(&f.owner)
            .unwrap()
            .invoke(&mut f.engine, token, &ack);
        assert_eq!(
            result.route.as_ref().ok().unwrap().application(),
            support::Application::Applied
        );
        assert_eq!(support::applications(&f.engine), apps + 1);
        release_duplicate_result(&f.owner, storage, &ledger, before, result);
        assert_eq!(f.engine.state().max_retained_evidence_bytes(), original_cap);
        release_recovery!(f.owner, ack, proof, attempt);
        teardown_recovery(f, &ledger);
    }
}

#[test]
fn renewed_recovery_requirement_blocks_a_previously_acknowledged_attempt() {
    let mut f = Fixture::new();
    let token = uncertain_token(&mut f);
    f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
    let attempt = admit_interruption(&f.owner).unwrap().invoke(
        &mut f.engine,
        &f.authority,
        token,
        f.revision,
        &f.history,
    );
    f.owner.backend.set_inject(InjectFault::None);
    let proof = f.read();
    let ack = acknowledged_checked(&f.owner, &attempt, &proof);
    let storage = StorageSnapshot::capture(&f.owner);
    f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
    assert!(matches!(
        f.owner.reacknowledge(&proof),
        PublishResult::UncertainDurable
    ));
    storage.assert_unchanged(&f.owner);
    assert!(f.owner.recovery_required());
    let apps = support::applications(&f.engine);
    let successes = f.notifications.successes();
    let token = duplicate(&mut f.engine, &f.authority, 2, 19);
    let ledger = support::ledger(&f.engine);
    let before = ledger.sample();
    let result = admit_resumption(&f.owner)
        .unwrap()
        .invoke(&mut f.engine, token, &ack);
    assert_eq!(result.refused, Some(Refused::RecoveryRequired));
    assert_eq!(support::applications(&f.engine), apps);
    assert_eq!(f.notifications.successes(), successes);
    release_duplicate_result(&f.owner, storage, &ledger, before, result);
    drop(ack);
    storage.assert_occupancy(
        &f.owner,
        storage.operational - recovery_charge(),
        storage.aggregate - recovery_charge(),
    );
    f.owner.backend.set_inject(InjectFault::None);
    let ack = acknowledged_checked(&f.owner, &attempt, &proof);
    let token = duplicate(&mut f.engine, &f.authority, 2, 19);
    let before = ledger.sample();
    let storage = StorageSnapshot::capture(&f.owner);
    let result = admit_resumption(&f.owner)
        .unwrap()
        .invoke(&mut f.engine, token, &ack);
    assert_eq!(
        result.route.as_ref().ok().unwrap().application(),
        support::Application::Applied
    );
    release_duplicate_result(&f.owner, storage, &ledger, before, result);
    release_recovery!(f.owner, ack, proof, attempt);
    teardown_recovery(f, &ledger);
}

#[test]
fn recovery_phase_inventory_and_independent_ledger_maxima() {
    let mut f = Fixture::new();
    let token = uncertain_token(&mut f);
    let ctx = f.owner.pinned();
    let r = max_safety_record_bytes(ctx).unwrap();
    let g = max_retained_generation_bytes(ctx, size_of_timeout_msg()).unwrap();
    let t = max_transient_decoded_working_set(ctx).unwrap();
    let h = f.owner.retained_holder_charge().unwrap();
    let loader = h + t.saturating_sub(g) + r;
    let o4 = 2 * t + 3 * r + super::super::backend::META_ENCODED_LEN;
    let o5 = r
        + super::super::backend::META_ENCODED_LEN
        + t
        + super::super::accounting::publication_staging_charge(ctx).unwrap();
    let a = adapter_charge();
    let i = interruption_charge();
    let k = recovery_charge();
    let s = resumption_charge();
    let c = candidate_charge(ctx);
    let c3 = size_of::<LockedRecord>() as u128
        + ctx.b_span()
        + 3 * (size_of::<Vec<u8>>() + ctx.s_sig) as u128;
    let storage = StorageSnapshot::capture(&f.owner);
    let cap = storage.aggregate_cap.unwrap();
    println!("O5 inventory types: interrupted={} interrupted_route={} predecessor={} interruption_admission={} interruption_result={} recovery_admission={} recovery_admission_result={} acknowledged={} acknowledgement_result={} recovery_outcome={} resumption_admission={} resumption_result={} resumption_gate={} check_result={}",
        size_of::<Interrupted<'static>>(), size_of::<InterruptedRoute>(), size_of::<Predecessor>(),
        size_of::<InterruptionAdmission<'static>>(),
        size_of::<Result<InterruptionAdmission<'static>, AdmissionRefusal>>(),
        size_of::<RecoveryAdmission<'static>>(),
        size_of::<Result<RecoveryAdmission<'static>, AdmissionRefusal>>(),
        size_of::<Acknowledged<'static>>(),
        size_of::<Result<Acknowledged<'static>, RecoveryOutcome>>(),
        size_of::<RecoveryOutcome>(), size_of::<ResumptionAdmission<'static>>(),
        size_of::<Result<ResumptionAdmission<'static>, AdmissionRefusal>>(),
        size_of::<ResumptionGate<'static, 'static>>(), size_of::<Result<(), Refused>>());
    println!("O5 source operands N=4 S_sig=2420 R={r} G={g} T={t} H={h} loader={loader} O4={o4} O5={o5} A={a} I={i} K={k} S={s} C={c} C3={c3} context={} op_cap={:?} context_cap={:?} aggregate_cap={cap}",
        storage.context, storage.operational_cap, storage.context_cap);
    for (phase, bound) in [
        ("interrupted O4", storage.context + i + a + c + o4),
        ("interrupted loader", storage.context + i + a + c + loader),
        ("O3 proof", storage.context + i + loader),
        ("explicit O5", storage.context + i + h + k + o5),
        (
            "resumption loader",
            storage.context + i + h + k + s + loader,
        ),
        ("resumption returned", storage.context + i + h + k + s),
        (
            "changed publication O4",
            storage.context + i + h + k + c3 + o4,
        ),
    ] {
        println!("O5 source-derived phase {phase}: aggregate bound={bound} cap={cap}");
        assert!(
            bound <= cap,
            "source-derived phase {phase} exceeds unchanged aggregate"
        );
    }
    let ledger = support::ledger(&f.engine);
    f.owner.backend.set_inject(InjectFault::UncertainAfterWrite);
    let attempt = admit_interruption(&f.owner).unwrap().invoke(
        &mut f.engine,
        &f.authority,
        token,
        f.revision,
        &f.history,
    );
    f.owner.backend.set_inject(InjectFault::None);
    let proof = f.read();
    let ack = acknowledged_checked(&f.owner, &attempt, &proof);
    let before = StorageSnapshot::capture(&f.owner);
    before.assert_occupancy(&f.owner, i + h + k, storage.context + i + h + k);
    let token = duplicate(&mut f.engine, &f.authority, 2, 19);
    let consensus = ledger.sample();
    let result = admit_resumption(&f.owner)
        .unwrap()
        .invoke(&mut f.engine, token, &ack);
    assert_eq!(
        result.route.as_ref().ok().unwrap().application(),
        support::Application::Applied
    );
    println!("O5 executed independent ledgers: consensus={:?} storage_op={} storage_op_peak={} storage_aggregate={} storage_aggregate_peak={} context={}",
        ledger.sample(), f.owner.backend.accounting_current(), f.owner.backend.accounting_peak(),
        f.owner.backend.accounting_aggregate_current(), f.owner.backend.accounting_aggregate_peak(),
        f.owner.backend.context_accounting_current());
    release_duplicate_result(&f.owner, before, &ledger, consensus, result);
    drop(ack);
    before.assert_occupancy(&f.owner, i + h, storage.context + i + h);
    drop(proof);
    before.assert_occupancy(&f.owner, i, storage.context + i);
    drop(attempt);
    storage.assert_unchanged(&f.owner);
    let backend = f.owner.backend.clone();
    drop(f);
    assert_eq!(ledger.sample(), support::empty_ledger_floor());
    assert_eq!(
        StorageSnapshot::capture_backend(&backend),
        StorageSnapshot {
            operational: 0,
            aggregate: 0,
            context: 0,
            ..storage
        }
    );
}
