//! Isolated restriction publication, not an inbound handler or authorization.
//! Fixture authentication is independent of the always-Unverified stored carry.

use super::super::{
    accounting::{max_transient_decoded_working_set, Reservation},
    backend::{InjectFault, SafetyBackendPolicy, TryLockDomainOutcome},
    record::{CommittedAnchor, LogicalQc, TimeoutCert, TimeoutMessage, WireQc},
    validate::FixtureCommittedHistory,
};
use super::received_qc_publication_model::Authority;
use super::*;
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_consensus::{
    basic_hotstuff_engine::{ConsensusProgressRecorder, TimeoutCertificateOutcome},
    crypto_verifier::SimpleBackendRegistry,
    qc_verify_domain::VerifiedQuorumCertificate,
    timeout_verify::verify_timeout_certificate_with_evidence,
    validator_set::{ConsensusValidatorSet, ValidatorSetEntry},
    BasicHotStuffEngine, ValidatorId,
};
use qbind_crypto::{ml_dsa44::MlDsa44Backend, SUITE_PQ_RESERVED_1};
use std::{
    mem::size_of,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Capacity,
    Arithmetic,
    Context,
    SelectedQc,
    RecoveryRequired,
    Loader,
    Revision,
    Predecessor,
    NonAdvancing,
    Publication,
}

#[derive(Default)]
struct Controls {
    publication: Option<PublishResult>,
    refused: Option<Refusal>,
    gate_calls: usize,
    submitted: usize,
}

// Field order destroys all result controls before releasing their coverage.
struct Report {
    outcome: Option<
        Result<
            TimeoutCertificateOutcome<Refusal>,
            qbind_consensus::timeout::TimeoutValidationError,
        >,
    >,
    controls: Controls,
    _coverage: Reservation,
}

#[derive(Debug, Clone, Copy)]
struct Inventory {
    route: u128,
    candidate: u128,
    loader: u128,
    o4: u128,
}

fn add(a: u128, b: u128) -> Result<u128, Refusal> {
    a.checked_add(b).ok_or(Refusal::Arithmetic)
}

fn mul(a: u128, b: u128) -> Result<u128, Refusal> {
    a.checked_mul(b).ok_or(Refusal::Arithmetic)
}

fn qc_backing(qc: &LogicalQc, n: usize) -> Result<u128, Refusal> {
    if qc.signers.capacity() > n {
        return Err(Refusal::Capacity);
    }
    mul(
        qc.signers.capacity() as u128,
        size_of::<ValidatorId>() as u128,
    )
}

impl Inventory {
    fn checked(owner: &SafetyRecordOwner, tc: &TimeoutCert) -> Result<Self, Refusal> {
        let ctx = owner.pinned();
        if tc.signers.capacity() > ctx.n() || tc.signed_timeouts.capacity() > ctx.n() {
            return Err(Refusal::Capacity);
        }
        let mut backing = mul(
            tc.signers.capacity() as u128,
            size_of::<ValidatorId>() as u128,
        )?;
        backing = add(
            backing,
            mul(
                tc.signed_timeouts.capacity() as u128,
                size_of::<TimeoutMessage>() as u128,
            )?,
        )?;
        if let Some(qc) = &tc.high_qc {
            // Separate owners: TC high-QC and record-level high-QC.
            backing = add(backing, mul(2, qc_backing(qc, ctx.n())?)?)?;
        }
        for timeout in &tc.signed_timeouts {
            if timeout.signature.capacity() > ctx.s_sig {
                return Err(Refusal::Capacity);
            }
            backing = add(backing, timeout.signature.capacity() as u128)?;
            if let Some(qc) = &timeout.high_qc {
                backing = add(backing, qc_backing(qc, ctx.n())?)?;
            }
        }
        // Named controls, argument/return transfer overlap, safe copy temporaries,
        // and reservation handles are separate from the backing inventory.
        let route = [
            2 * size_of::<Report>(),
            2 * size_of::<Admission<'static>>(),
            size_of::<Gate<'static, 'static>>(),
            size_of::<Inventory>(),
            size_of::<Result<Inventory, Refusal>>(),
            size_of::<Result<Admission<'static>, Refusal>>(),
            size_of::<Result<PublishResult, Refusal>>(),
            size_of::<
                Option<
                    Result<
                        TimeoutCertificateOutcome<Refusal>,
                        qbind_consensus::timeout::TimeoutValidationError,
                    >,
                >,
            >(),
            8 * size_of::<usize>(),
            12 * size_of::<&()>(),
        ]
        .into_iter()
        .try_fold(0u128, |a, b| add(a, b as u128))?;
        let copy_controls = [
            2 * size_of::<LockedRecord>(),
            size_of::<TimeoutMessage>(),
            2 * size_of::<LogicalQc>(),
            4 * size_of::<Vec<u8>>(),
            2 * size_of::<Reservation>(),
            size_of::<Option<CommittedAnchor>>(),
        ]
        .into_iter()
        .try_fold(0u128, |a, b| add(a, b as u128))?;
        let candidate = add(backing, copy_controls)?;
        let transient = max_transient_decoded_working_set(ctx).map_err(|_| Refusal::Arithmetic)?;
        let rec = max_safety_record_bytes(ctx).map_err(|_| Refusal::Arithmetic)?;
        let retained = max_retained_generation_bytes(ctx, size_of_timeout_msg())
            .map_err(|_| Refusal::Arithmetic)?;
        let holder = owner
            .retained_holder_charge()
            .map_err(|_| Refusal::Arithmetic)?;
        let loader = add(holder, add(transient.saturating_sub(retained), rec)?)?;
        let o4 = add(
            add(mul(2, transient)?, mul(3, rec)?)?,
            super::super::backend::META_ENCODED_LEN,
        )?;
        Ok(Self {
            route,
            candidate,
            loader,
            o4,
        })
    }

    fn peak(self) -> Result<u128, Refusal> {
        add(self.route, self.loader.max(add(self.candidate, self.o4)?))
    }
}

struct Admission<'a> {
    owner: &'a SafetyRecordOwner,
    input: &'a TimeoutCert,
    inventory: Inventory,
    coverage: Reservation,
}

fn admit<'a>(owner: &'a SafetyRecordOwner, tc: &'a TimeoutCert) -> Result<Admission<'a>, Refusal> {
    let inventory = Inventory::checked(owner, tc)?;
    inventory.peak()?;
    // No large report or candidate exists until this succeeds.
    let coverage = owner
        .backend
        .accounting()
        .reserve(inventory.route)
        .map_err(|_| Refusal::Capacity)?;
    Ok(Admission {
        owner,
        input: tc,
        inventory,
        coverage,
    })
}

fn context_matches(
    owner: &SafetyRecordOwner,
    engine: &BasicHotStuffEngine<[u8; 32]>,
    authority: &Authority,
) -> bool {
    let ctx = owner.pinned();
    ctx.validate().is_ok()
        && ctx.network_genesis_id == *authority.domain.genesis_identity()
        && ctx.authority_context_ref == *authority.domain.authority_commitment()
        && ctx.chain_id == authority.domain.expected_wire_chain_id()
        && authority.domain.runtime_chain_id() == qbind_types::QBIND_DEVNET_CHAIN_ID
        && ctx.epoch == 0
        && ctx.qc_suite_id == SUITE_PQ_RESERVED_1.0
        && ctx.timeout_suite_id == 100
        && ctx.s_sig == qbind_crypto::ML_DSA_44_SIGNATURE_SIZE
        && !ctx.require_height_equals_round
        && ctx.validators.len() == authority.members.len()
        && ctx.validators.iter().zip(&authority.members).all(
            |((id, power), (member, member_power, key))| {
                id == member
                    && power == member_power
                    && key.len() == qbind_crypto::ML_DSA_44_PUBLIC_KEY_SIZE
            },
        )
        && engine.validators().len() == authority.members.len()
        && authority
            .members
            .iter()
            .enumerate()
            .all(|(index, (id, power, _))| {
                engine
                    .validators()
                    .get(index)
                    .is_some_and(|entry| entry.id == *id && entry.voting_power == *power)
            })
}

// Safe standard-library copies; no shrink_to_fit or raw ownership transfer.
// Each requested capacity is <= the separately admitted source capacity.
fn copy_qc(source: &LogicalQc) -> LogicalQc {
    LogicalQc::new(source.block_id, source.view, source.signers.to_vec())
}

fn copy_candidate(
    tc: &TimeoutCert,
    ctx: &PinnedSafetyContext,
    anchor: Option<CommittedAnchor>,
    revision: u64,
) -> LockedRecord {
    let high = tc.high_qc.as_ref().expect("strict raise has a selected QC");
    let mut timeouts = Vec::with_capacity(tc.signed_timeouts.len());
    for source in &tc.signed_timeouts {
        timeouts.push(TimeoutMessage {
            view: source.view,
            high_qc: source.high_qc.as_ref().map(copy_qc),
            validator_id: source.validator_id,
            suite_id: source.suite_id,
            signature: source.signature.to_vec(),
        });
    }
    LockedRecord {
        lock_block_id: high.block_id,
        lock_view: high.view,
        evidence_lock_binding: [0; 32], // Ordinary O4 computes and validates it.
        authority_context_ref: ctx.authority_context_ref,
        committed_anchor: anchor,
        predecessor_ref: Some(revision),
        evidence: SupportingEvidence::TcDerived {
            high_qc: copy_qc(high),
            tc: TimeoutCert {
                view: tc.view,
                timeout_view: tc.timeout_view,
                high_qc: Some(copy_qc(high)),
                signers: tc.signers.to_vec(),
                signed_timeouts: timeouts,
            },
        },
    }
}

struct Gate<'a, 'g> {
    owner: &'a SafetyRecordOwner,
    guard: &'a std::sync::MutexGuard<'g, super::super::backend::SerializationDomain>,
    history: Option<&'a FixtureCommittedHistory>,
    expected: u64,
    inventory: Inventory,
    controls: Controls,
    anchor: Option<CommittedAnchor>,
}

impl Gate<'_, '_> {
    fn check_predecessor(&mut self, engine: &BasicHotStuffEngine<[u8; 32]>) -> Result<(), Refusal> {
        if self.owner.backend.recovery_required() {
            return Err(Refusal::RecoveryRequired);
        }
        let current = self
            .owner
            .load_current_validated_locked(self.guard, self.history)
            .map_err(|_| Refusal::Loader)?;
        if current.publication_revision() != self.expected {
            return Err(Refusal::Revision);
        }
        let (predecessor, anchor) = match &current.retained().record {
            SafetyRecord::BootstrapNoLock { .. } => (None, None),
            SafetyRecord::Locked(record) => (
                Some((record.lock_block_id, record.lock_view)),
                record.committed_anchor.clone(),
            ),
        };
        if predecessor != engine.locked_qc().map(|q| (q.block_id, q.view)) {
            return Err(Refusal::Predecessor);
        }
        // The charged loader validated any anchor against independent history.
        // It is destroyed before candidate/O4 coexistence.
        self.anchor = anchor;
        Ok(())
    }

    fn publish(
        &mut self,
        engine: &BasicHotStuffEngine<[u8; 32]>,
        tc: &TimeoutCert,
        high: &LogicalQc,
        selected: Option<&VerifiedQuorumCertificate>,
    ) -> Result<(), Refusal> {
        if self.owner.backend.recovery_required() {
            return Err(Refusal::RecoveryRequired);
        }
        let selected = selected.ok_or(Refusal::SelectedQc)?;
        let wire = selected.certificate();
        if wire.block_id != high.block_id
            || wire.height != high.view
            || wire.chain_id != self.owner.pinned().chain_id
            || wire.epoch != self.owner.pinned().epoch
            || wire.suite_id != self.owner.pinned().qc_suite_id
            || selected.signers() != high.signers.as_slice()
        {
            return Err(Refusal::SelectedQc);
        }
        if engine.locked_qc().is_some_and(|q| high.view <= q.view) {
            return Err(Refusal::NonAdvancing);
        }
        let candidate_lease = self
            .owner
            .backend
            .accounting()
            .reserve(self.inventory.candidate)
            .map_err(|_| Refusal::Capacity)?;
        let candidate = copy_candidate(tc, self.owner.pinned(), self.anchor.clone(), self.expected);
        let actual = super::super::accounting::evidence_backing_capacity(&candidate.evidence)
            .map_err(|_| Refusal::Arithmetic)?;
        assert!(
            actual + (2 * size_of::<LockedRecord>()) as u128 <= self.inventory.candidate,
            "admitted copy layout exceeded (redacted)"
        );
        self.controls.submitted += 1;
        let publication =
            self.owner
                .publish_locked_held(self.guard, candidate, self.expected, self.history);
        // Only the actual ordinary O4 result can permit the pending engine raise.
        let allow = matches!(publication, PublishResult::DurableAcknowledged { .. });
        self.controls.publication = Some(publication);
        drop(candidate_lease);
        if allow {
            Ok(())
        } else {
            Err(Refusal::Publication)
        }
    }
}

impl Admission<'_> {
    fn invoke(
        self,
        engine: &mut BasicHotStuffEngine<[u8; 32]>,
        authority: &Authority,
        selected: Option<&VerifiedQuorumCertificate>,
        expected: u64,
        history: Option<&FixtureCommittedHistory>,
        mut post_ack: impl FnMut(&BasicHotStuffEngine<[u8; 32]>),
        mut returning: impl FnMut(&BasicHotStuffEngine<[u8; 32]>),
    ) -> Report {
        let Self {
            owner,
            input,
            inventory,
            coverage,
        } = self;
        let guard = owner.backend.lock_domain();
        let mut gate = Gate {
            owner,
            guard: &guard,
            history,
            expected,
            inventory,
            controls: Controls::default(),
            anchor: None,
        };
        let outcome = if !context_matches(owner, engine, authority) {
            gate.controls.refused = Some(Refusal::Context);
            None
        } else if let Err(error) = input.validate(engine.validators()) {
            Some(Err(error))
        } else if input.view > engine.current_view() && {
            match gate.check_predecessor(engine) {
                Ok(()) => false,
                Err(reason) => {
                    gate.controls.refused = Some(reason);
                    true
                }
            }
        } {
            None
        } else {
            Some(
                engine.on_timeout_certificate_gated(input, &mut |old, exact, high| {
                    gate.controls.gate_calls += 1;
                    let result = if selected.is_some_and(|qc| {
                        qc.domain() != &authority.domain
                            || qc.authorized_epoch() != owner.pinned().epoch
                    }) {
                        Err(Refusal::SelectedQc)
                    } else {
                        gate.publish(old, exact, high, selected)
                    };
                    if let Err(reason) = result {
                        gate.controls.refused = Some(reason);
                    } else {
                        post_ack(old);
                    }
                    result
                }),
            )
        };
        let report = Report {
            outcome,
            controls: gate.controls,
            _coverage: coverage,
        };
        // The domain includes synchronous engine callbacks AND result construction.
        returning(engine);
        drop(guard);
        report
    }
}

fn validator_set(authority: &Authority) -> ConsensusValidatorSet {
    ConsensusValidatorSet::new(
        authority
            .members
            .iter()
            .map(|(id, power, _)| ValidatorSetEntry {
                id: *id,
                voting_power: *power,
            }),
    )
    .unwrap()
}

struct Fixture {
    authority: Authority,
    owner: SafetyRecordOwner,
    engine: BasicHotStuffEngine<[u8; 32]>,
    selected: Arc<VerifiedQuorumCertificate>,
    tc: TimeoutCert,
    history: FixtureCommittedHistory,
    revision: u64,
    notes: Arc<Notes>,
    latches: (bool, bool, bool, Option<Instant>),
    _dir: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let ledger = ConsensusLedger::capture(&self.engine);
        assert_eq!(
            ledger.retained, 0,
            "TC composition retained no verified-QC payload"
        );
        assert!(ledger.ceiling > 0);
        assert_eq!(
            Arc::strong_count(&self.selected),
            1,
            "fixture verified-QC Arc is independently caller-owned"
        );
    }
}

#[derive(Debug, Default)]
struct Notes {
    qc: AtomicUsize,
    vote: AtomicUsize,
    view: AtomicUsize,
    leader: AtomicUsize,
    reset: AtomicUsize,
    panic: AtomicBool,
    competitor: std::sync::Mutex<Option<Arc<Competitor>>>,
    observers: std::sync::Mutex<Option<Arc<BoundaryObservations>>>,
}

#[derive(Debug, Default)]
struct BoundaryObservations {
    post_ack: AtomicUsize,
    recorder: AtomicUsize,
    return_boundary: AtomicUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationPhase {
    PostAckPreEffect,
    Recorder,
    ReturnBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationStatus {
    Complete,
    Missing(ObservationPhase),
}

impl BoundaryObservations {
    fn status(&self) -> ObservationStatus {
        for (phase, count) in [
            (ObservationPhase::PostAckPreEffect, &self.post_ack),
            (ObservationPhase::Recorder, &self.recorder),
            (ObservationPhase::ReturnBoundary, &self.return_boundary),
        ] {
            if count.load(Ordering::SeqCst) != 1 {
                return ObservationStatus::Missing(phase);
            }
        }
        ObservationStatus::Complete
    }
}

impl ConsensusProgressRecorder for Notes {
    fn record_qc_formed(&self) {
        self.qc.fetch_add(1, Ordering::SeqCst);
    }
    fn record_vote_observed(&self, _: bool) {
        self.vote.fetch_add(1, Ordering::SeqCst);
    }
    fn record_view_change(&self, _: u64, _: u64) {
        if let Some(competitor) = self.competitor.lock().unwrap().as_ref() {
            competitor.expect(false);
        }
        if let Some(observers) = self.observers.lock().unwrap().as_ref() {
            observers.recorder.fetch_add(1, Ordering::SeqCst);
        }
        self.view.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.panic.load(Ordering::SeqCst),
            "controlled callback unwind"
        );
    }
    fn record_leader_change(&self) {
        self.leader.fetch_add(1, Ordering::SeqCst);
    }
    fn reset_current_view_votes(&self) {
        self.reset.fetch_add(1, Ordering::SeqCst);
    }
}

impl Fixture {
    fn new() -> Self {
        let authority = Authority::new_for_wire_chain(7);
        let mut wire = WireQc {
            version: 1,
            chain_id: 7,
            epoch: 0,
            height: 6,
            round: 5,
            step: 0,
            block_id: [0xB6; 32],
            suite_id: SUITE_PQ_RESERVED_1.0,
            signer_bitmap: vec![0b111],
            signatures: Vec::with_capacity(3),
        };
        let template = qbind_wire::consensus::Vote {
            version: wire.version,
            chain_id: wire.chain_id,
            epoch: wire.epoch,
            height: wire.height,
            round: wire.round,
            step: wire.step,
            block_id: wire.block_id,
            suite_id: wire.suite_id,
            validator_index: 0,
            signature: Vec::new(),
        };
        for signer in 0..3 {
            wire.signatures
                .push(authority.sign_like_vote(&template, signer).signature);
        }
        let selected = authority.verified_test_evidence(&wire);
        let high = LogicalQc::new(wire.block_id, wire.height, selected.signers().to_vec());
        let mut timeouts = Vec::with_capacity(3);
        for signer in 0..3 {
            let mut timeout = TimeoutMessage::new(7, Some(high.clone()), ValidatorId(signer));
            timeout.suite_id = 100;
            timeout.signature =
                MlDsa44Backend::sign(authority.secret(signer as usize), &timeout.signing_bytes())
                    .unwrap();
            timeouts.push(timeout);
        }
        let tc = TimeoutCert::new_with_evidence(
            7,
            Some(high),
            vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
            timeouts,
        );
        let registry =
            SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend));
        let verified = verify_timeout_certificate_with_evidence(
            &tc,
            &tc.signed_timeouts,
            &validator_set(&authority),
            &authority,
            &registry,
            qbind_types::QBIND_DEVNET_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(verified.0, 3);
        assert!(
            verified.1.as_ref() == tc.high_qc.as_ref(),
            "selected test QC differs (redacted)"
        );
        let dir = tempfile::tempdir().unwrap();
        let backend = SafetyBackend::open_or_initialize(
            dir.path(),
            SafetyBackendPolicy::EnabledForTesting,
            TrustBundleEnvironment::Devnet,
        )
        .unwrap();
        let owner = SafetyRecordOwner::attach(backend, authority.pinned()).unwrap();
        let revision = owner.initialize(true).unwrap();
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), validator_set(&authority));
        // Complete ingestion happens before the composed TC operation and survives refusal.
        for timeout in &tc.signed_timeouts {
            engine
                .on_timeout_msg(timeout.validator_id, timeout.clone())
                .unwrap();
        }
        let notes = Arc::new(Notes::default());
        engine.set_progress_recorder(notes.clone());
        let latches = engine.timeout_effect_latches_for_test();
        Self {
            authority,
            owner,
            engine,
            selected,
            tc,
            history: FixtureCommittedHistory::new(),
            revision,
            notes,
            latches,
            _dir: dir,
        }
    }

    fn run(&mut self) -> Report {
        admit(&self.owner, &self.tc).unwrap().invoke(
            &mut self.engine,
            &self.authority,
            Some(&self.selected),
            self.revision,
            Some(&self.history),
            |_| {},
            |_| {},
        )
    }

    fn sample(&self) -> Ledger {
        Ledger::capture(&self.owner.backend)
    }

    fn read(&self) -> ValidatedRecord {
        self.owner.read_validate(Some(&self.history)).unwrap()
    }

    fn unchanged(&self) {
        assert!(self.engine.locked_qc().is_none());
        assert_eq!(self.engine.current_view(), 0);
        assert_eq!(self.engine.timeout_count(7), 3);
        assert_eq!(self.engine.timeout_effect_latches_for_test(), self.latches);
        assert_eq!(self.notes.view.load(Ordering::SeqCst), 0);
        assert_eq!(self.notes.leader.load(Ordering::SeqCst), 0);
        assert_eq!(self.notes.reset.load(Ordering::SeqCst), 0);
    }

    fn seed(&mut self, anchor: Option<CommittedAnchor>) {
        self.seed_view(anchor, 5);
    }

    fn seed_view(&mut self, anchor: Option<CommittedAnchor>, view: u64) {
        let lease = self
            .owner
            .backend
            .accounting()
            .reserve(Inventory::checked(&self.owner, &self.tc).unwrap().candidate)
            .unwrap();
        let mut candidate = copy_candidate(&self.tc, self.owner.pinned(), anchor, self.revision);
        candidate.lock_view = view;
        candidate.lock_block_id = [0xB5; 32];
        let SupportingEvidence::TcDerived { high_qc, tc } = &mut candidate.evidence else {
            unreachable!()
        };
        high_qc.view = view;
        high_qc.block_id = [0xB5; 32];
        tc.high_qc = Some(high_qc.clone());
        for timeout in &mut tc.signed_timeouts {
            timeout.high_qc = Some(high_qc.clone());
        }
        // Helper-only semantic predecessor, not authenticated TC ingress.
        assert_eq!(
            self.owner
                .publish_locked(candidate, self.revision, Some(&self.history)),
            PublishResult::DurableAcknowledged {
                new_revision: self.revision + 1
            }
        );
        self.revision += 1;
        drop(lease);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ledger {
    operational: u128,
    context: u128,
    aggregate: u128,
    operational_cap: Option<u128>,
    context_cap: Option<u128>,
    aggregate_cap: Option<u128>,
}
impl Ledger {
    fn capture(backend: &SafetyBackend) -> Self {
        Self {
            operational: backend.accounting_current(),
            context: backend.context_accounting_current(),
            aggregate: backend.accounting_aggregate_current(),
            operational_cap: backend.accounting_cap(),
            context_cap: backend.context_accounting_cap(),
            aggregate_cap: backend.accounting_aggregate_cap(),
        }
    }
    fn returned(self, f: &Fixture, route: u128) {
        assert_eq!(
            f.sample(),
            Self {
                operational: self.operational + route,
                aggregate: self.aggregate + route,
                ..self
            }
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConsensusLedger {
    retained: u64,
    ceiling: u64,
}

impl ConsensusLedger {
    fn capture(engine: &BasicHotStuffEngine<[u8; 32]>) -> Self {
        Self {
            retained: engine.state().retained_evidence_bytes(),
            ceiling: engine.state().max_retained_evidence_bytes(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecorderCounters {
    qc: usize,
    vote: usize,
    view: usize,
    leader: usize,
    reset: usize,
}

impl RecorderCounters {
    fn capture(notes: &Notes) -> Self {
        Self {
            qc: notes.qc.load(Ordering::SeqCst),
            vote: notes.vote.load(Ordering::SeqCst),
            view: notes.view.load(Ordering::SeqCst),
            leader: notes.leader.load(Ordering::SeqCst),
            reset: notes.reset.load(Ordering::SeqCst),
        }
    }
}

struct RefusalBaseline {
    tc: TimeoutCert,
    input_backings: [usize; 32],
    engine_lock: Option<LogicalQc>,
    engine_lock_backing: [usize; 2],
    engine_view: u64,
    engine_latches: (bool, bool, bool, Option<Instant>),
    retained_timeouts: Vec<TimeoutMessage>,
    retained_timeout_backings: [[usize; 4]; 4],
    recorder: RecorderCounters,
    node: Ledger,
    consensus: ConsensusLedger,
    selected_arc_strong_count: usize,
}

impl RefusalBaseline {
    fn capture(f: &Fixture) -> Self {
        let mut retained_timeout_backings = [[0; 4]; 4];
        if let Some(messages) = f.engine.timeout_accumulator().get_timeouts(7) {
            for timeout in messages.values() {
                let slot = &mut retained_timeout_backings[timeout.validator_id.0 as usize];
                slot[0] = timeout.signature.as_ptr() as usize;
                slot[1] = timeout.signature.capacity();
                if let Some(qc) = &timeout.high_qc {
                    slot[2] = qc.signers.as_ptr() as usize;
                    slot[3] = qc.signers.capacity();
                }
            }
        }
        let engine_lock_backing = f.engine.locked_qc().map_or([0; 2], |qc| {
            [qc.signers.as_ptr() as usize, qc.signers.capacity()]
        });
        let mut retained_timeouts: Vec<_> = f
            .engine
            .timeout_accumulator()
            .get_timeouts(7)
            .into_iter()
            .flat_map(|messages| messages.values().cloned())
            .collect();
        retained_timeouts.sort_by_key(|timeout| timeout.validator_id);
        Self {
            tc: f.tc.clone(),
            input_backings: input_backings(&f.tc),
            engine_lock: f.engine.locked_qc().cloned(),
            engine_lock_backing,
            engine_view: f.engine.current_view(),
            engine_latches: f.engine.timeout_effect_latches_for_test(),
            retained_timeouts,
            retained_timeout_backings,
            recorder: RecorderCounters::capture(&f.notes),
            node: f.sample(),
            consensus: ConsensusLedger::capture(&f.engine),
            selected_arc_strong_count: Arc::strong_count(&f.selected),
        }
    }

    fn assert_input_and_consensus(&self, f: &Fixture) {
        assert!(f.tc == self.tc, "complete input TC differs (redacted)");
        assert!(
            input_backings(&f.tc) == self.input_backings,
            "input backing identity/capacity differs (redacted)"
        );
        assert_eq!(ConsensusLedger::capture(&f.engine), self.consensus);
        assert_eq!(
            Arc::strong_count(&f.selected),
            self.selected_arc_strong_count,
            "caller-owned verified-QC Arc strong count differs"
        );
    }

    fn assert_input_engine_consensus(&self, f: &Fixture) {
        self.assert_input_and_consensus(f);
        assert!(
            f.engine.locked_qc() == self.engine_lock.as_ref(),
            "engine lock differs (redacted)"
        );
        let lock_backing = f.engine.locked_qc().map_or([0; 2], |qc| {
            [qc.signers.as_ptr() as usize, qc.signers.capacity()]
        });
        assert_eq!(lock_backing, self.engine_lock_backing);
        assert_eq!(f.engine.current_view(), self.engine_view);
        assert_eq!(
            f.engine.timeout_effect_latches_for_test(),
            self.engine_latches
        );
        let actual_timeouts = f.engine.timeout_accumulator().get_timeouts(7);
        assert_eq!(
            actual_timeouts.map_or(0, |messages| messages.len()),
            self.retained_timeouts.len()
        );
        for expected in &self.retained_timeouts {
            let actual = actual_timeouts.and_then(|messages| messages.get(&expected.validator_id));
            assert!(
                actual == Some(expected),
                "retained Timeout input differs (redacted)"
            );
            let slot = &self.retained_timeout_backings[expected.validator_id.0 as usize];
            let backing = actual.map_or([0; 4], |timeout| {
                let mut value = [
                    timeout.signature.as_ptr() as usize,
                    timeout.signature.capacity(),
                    0,
                    0,
                ];
                if let Some(qc) = &timeout.high_qc {
                    value[2] = qc.signers.as_ptr() as usize;
                    value[3] = qc.signers.capacity();
                }
                value
            });
            assert_eq!(
                backing, *slot,
                "retained Timeout backing differs (redacted)"
            );
        }
        assert_eq!(RecorderCounters::capture(&f.notes), self.recorder);
    }

    fn assert_admission_refusal(&self, f: &Fixture) {
        self.assert_input_engine_consensus(f);
        assert_eq!(f.sample(), self.node);
    }

    fn assert_route_refusal(&self, f: &Fixture, route: u128) {
        self.assert_input_engine_consensus(f);
        assert_eq!(
            f.sample(),
            Ledger {
                operational: self.node.operational + route,
                aggregate: self.node.aggregate + route,
                ..self.node
            }
        );
    }

    fn assert_route_returned(&self, f: &Fixture) {
        self.assert_input_engine_consensus(f);
        assert_eq!(f.sample(), self.node);
    }

    fn assert_report_released(&self, f: &Fixture, node: Ledger) {
        self.assert_input_engine_consensus(f);
        assert_eq!(f.sample(), node);
    }

    fn assert_applied(&self, f: &Fixture, node: Ledger) {
        self.assert_input_and_consensus(f);
        assert_eq!(f.engine.locked_qc(), self.tc.high_qc.as_ref());
        assert_eq!(f.engine.current_view(), self.tc.view);
        let latches = f.engine.timeout_effect_latches_for_test();
        assert!(!latches.0 && !latches.1 && !latches.2);
        assert_eq!(f.engine.timeout_count(self.tc.timeout_view), 0);
        assert_eq!(
            RecorderCounters::capture(&f.notes),
            RecorderCounters {
                qc: self.recorder.qc,
                vote: self.recorder.vote,
                view: self.recorder.view + 1,
                leader: self.recorder.leader,
                reset: self.recorder.reset + 1,
            }
        );
        assert_eq!(f.sample(), node);
    }
}

fn input_backings(tc: &TimeoutCert) -> [usize; 32] {
    let mut result = [0; 32];
    let mut used = 0;
    let mut push = |pointer: usize, capacity: usize| {
        result[used] = pointer;
        result[used + 1] = capacity;
        used += 2;
    };
    push(tc.signers.as_ptr() as usize, tc.signers.capacity());
    push(
        tc.signed_timeouts.as_ptr() as usize,
        tc.signed_timeouts.capacity(),
    );
    if let Some(qc) = &tc.high_qc {
        push(qc.signers.as_ptr() as usize, qc.signers.capacity());
    }
    for timeout in &tc.signed_timeouts {
        push(
            timeout.signature.as_ptr() as usize,
            timeout.signature.capacity(),
        );
        if let Some(qc) = &timeout.high_qc {
            push(qc.signers.as_ptr() as usize, qc.signers.capacity());
        }
    }
    result
}

// One supervised competitor, bounded request/response; no detached worker.
#[derive(Debug)]
enum CompetitorRequest {
    Observe,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompetitorObservation {
    Acquired,
    WouldBlock,
    Missing,
}

#[derive(Debug)]
struct Competitor {
    tx: std::sync::mpsc::SyncSender<CompetitorRequest>,
    rx: std::sync::Mutex<std::sync::mpsc::Receiver<bool>>,
    shutdown_ack: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    requests: AtomicUsize,
    joined: AtomicBool,
}
impl Competitor {
    fn new(backend: SafetyBackend) -> Arc<Self> {
        let (tx, requests) = std::sync::mpsc::sync_channel(1);
        let (responses, rx) = std::sync::mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_ack) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || loop {
            match requests.recv_timeout(Duration::from_secs(10)) {
                Ok(CompetitorRequest::Observe) => {
                    let until = Instant::now() + Duration::from_secs(2);
                    let acquired = loop {
                        match backend.try_lock_domain_for_test() {
                            TryLockDomainOutcome::Acquired(_) => break true,
                            TryLockDomainOutcome::WouldBlock => break false,
                            _ if Instant::now() < until => std::thread::yield_now(),
                            _ => panic!("competitor observed poisoned domain"),
                        }
                    };
                    if responses.send(acquired).is_err() {
                        break;
                    }
                }
                Ok(CompetitorRequest::Shutdown)
                | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = shutdown_tx.send(());
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            }
        });
        Arc::new(Self {
            tx,
            rx: std::sync::Mutex::new(rx),
            shutdown_ack: std::sync::Mutex::new(shutdown_ack),
            thread: std::sync::Mutex::new(Some(thread)),
            requests: AtomicUsize::new(0),
            joined: AtomicBool::new(false),
        })
    }
    fn expect(&self, acquired: bool) {
        self.tx.send(CompetitorRequest::Observe).unwrap();
        self.requests.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            self.rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap(),
            acquired
        );
    }

    fn wait_for_skipped_observation(&self, timeout: Duration) -> CompetitorObservation {
        match self.rx.lock().unwrap().recv_timeout(timeout) {
            Ok(true) => CompetitorObservation::Acquired,
            Ok(false) => CompetitorObservation::WouldBlock,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => CompetitorObservation::Missing,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("supervised observer disconnected")
            }
        }
    }

    fn shutdown(&self) -> bool {
        if self.joined.load(Ordering::SeqCst) {
            return true;
        }
        if self.tx.send(CompetitorRequest::Shutdown).is_err()
            || self
                .shutdown_ack
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .is_err()
        {
            return false;
        }
        let Some(thread) = self.thread.lock().unwrap().take() else {
            return false;
        };
        let joined = thread.join().is_ok();
        self.joined.store(joined, Ordering::SeqCst);
        joined
    }
}
impl Drop for Competitor {
    fn drop(&mut self) {
        if !self.joined.load(Ordering::SeqCst) {
            let _ = self.tx.try_send(CompetitorRequest::Shutdown);
            if let Some(thread) = self.thread.get_mut().unwrap().take() {
                let _ = thread.join();
            }
        }
    }
}

#[test]
fn acknowledged_exact_tc_unverified_order_domain_and_ledgers() {
    let mut f = Fixture::new();
    let before = f.sample();
    let inventory = Inventory::checked(&f.owner, &f.tc).unwrap();
    let unchanged = RefusalBaseline::capture(&f);
    assert!(inventory.peak().unwrap() + before.context <= before.aggregate_cap.unwrap());
    let competitor = Competitor::new(f.owner.backend.clone());
    competitor.expect(true); // Discriminating observation control.
    let observations = Arc::new(BoundaryObservations::default());
    *f.notes.observers.lock().unwrap() = Some(observations.clone());
    let hook_competitor = competitor.clone();
    let hook_backend = f.owner.backend.clone();
    let hooks = Arc::new(AtomicUsize::new(0));
    let observed_hooks = hooks.clone();
    f.owner
        .backend
        .set_pre_effective_hook(Arc::new(move |op, _| {
            assert_eq!(op, "O4");
            hook_competitor.expect(false);
            assert_eq!(
                hook_backend.accounting_current(),
                inventory.route + inventory.candidate + inventory.o4
            );
            assert!(o4_owned_live_objects().is_some());
            observed_hooks.fetch_add(1, Ordering::SeqCst);
        }));
    *f.notes.competitor.lock().unwrap() = Some(competitor.clone());
    let post = competitor.clone();
    let returning = competitor.clone();
    let calls = std::cell::Cell::new(0);
    let result = admit(&f.owner, &f.tc).unwrap().invoke(
        &mut f.engine,
        &f.authority,
        Some(&f.selected),
        f.revision,
        Some(&f.history),
        |old| {
            assert!(old.locked_qc().is_none());
            assert_eq!(old.current_view(), 0);
            assert_eq!(old.timeout_count(7), 3);
            post.expect(false);
            observations.post_ack.fetch_add(1, Ordering::SeqCst);
            calls.set(calls.get() + 1);
        },
        |applied| {
            assert_eq!(applied.current_view(), 8);
            assert_eq!(applied.locked_qc().map(|q| q.view), Some(6));
            returning.expect(false);
            observations.return_boundary.fetch_add(1, Ordering::SeqCst);
        },
    );
    // Observe independently BEFORE allocating readback witnesses.
    before.returned(&f, inventory.route);
    assert_eq!(hooks.load(Ordering::SeqCst), 1);
    f.owner.backend.set_pre_effective_hook(Arc::new(|_, _| {}));
    assert_eq!(calls.get(), 1);
    assert_eq!(observations.status(), ObservationStatus::Complete);
    assert_eq!(observations.post_ack.load(Ordering::SeqCst), 1);
    assert_eq!(observations.recorder.load(Ordering::SeqCst), 1);
    assert_eq!(observations.return_boundary.load(Ordering::SeqCst), 1);
    assert_eq!(
        result.outcome,
        Some(Ok(TimeoutCertificateOutcome::LockRaised { view: 8 }))
    );
    assert_eq!(
        result.controls.publication,
        Some(PublishResult::DurableAcknowledged {
            new_revision: f.revision + 1
        })
    );
    assert_eq!(
        (result.controls.gate_calls, result.controls.submitted),
        (1, 1)
    );
    assert_eq!(
        RecorderCounters::capture(&f.notes),
        RecorderCounters {
            qc: unchanged.recorder.qc,
            vote: unchanged.recorder.vote,
            view: unchanged.recorder.view + 1,
            leader: unchanged.recorder.leader,
            reset: unchanged.recorder.reset + 1,
        }
    );
    assert_eq!(ConsensusLedger::capture(&f.engine), unchanged.consensus);
    // The verified certificate is the caller-owned fixture Arc, not a consensus
    // ledger entry; this route retained no verified-QC payload in engine state.
    assert_eq!(f.engine.state().retained_evidence_bytes(), 0);
    assert_eq!(
        Arc::strong_count(&f.selected),
        unchanged.selected_arc_strong_count
    );
    assert_eq!(f.engine.timeout_count(7), 0);
    competitor.expect(true);
    let proof = f.read();
    assert_eq!(proof.evidence_status(), EvidenceStatus::Unverified);
    let SafetyRecord::Locked(record) = &proof.retained().record else {
        panic!("expected lock")
    };
    let SupportingEvidence::TcDerived { high_qc, tc } = &record.evidence else {
        panic!("expected TC")
    };
    assert!(
        tc == &f.tc && Some(high_qc) == f.tc.high_qc.as_ref(),
        "exact TC differs (redacted)"
    );
    assert_eq!(
        (record.lock_block_id, record.lock_view),
        (high_qc.block_id, high_qc.view)
    );
    assert_eq!(proof.publication_revision(), f.revision + 1);
    drop(proof);
    drop(result);
    assert_eq!(ConsensusLedger::capture(&f.engine), unchanged.consensus);
    assert_eq!(
        Arc::strong_count(&f.selected),
        unchanged.selected_arc_strong_count
    );
    assert!(f.tc == unchanged.tc, "complete input TC differs (redacted)");
    assert!(
        input_backings(&f.tc) == unchanged.input_backings,
        "input backing differs (redacted)"
    );
    assert_eq!(ConsensusLedger::capture(&f.engine), unchanged.consensus);
    assert_eq!(
        Arc::strong_count(&f.selected),
        unchanged.selected_arc_strong_count
    );
    assert_eq!(f.sample(), before);
    let backend = f.owner.backend.clone();
    *f.notes.observers.lock().unwrap() = None;
    *f.notes.competitor.lock().unwrap() = None;
    assert!(competitor.shutdown());
    assert!(competitor.joined.load(Ordering::SeqCst));
    drop(competitor);
    drop(f);
    let final_ledger = Ledger::capture(&backend);
    assert_eq!(
        (
            final_ledger.operational,
            final_ledger.context,
            final_ledger.aggregate
        ),
        (0, 0, 0)
    );
    println!(
        "TC O4 phase bytes: route={} candidate={} loader={} O4={} peak={} context={} shared_cap={}",
        inventory.route,
        inventory.candidate,
        inventory.loader,
        inventory.o4,
        inventory.peak().unwrap(),
        before.context,
        before.aggregate_cap.unwrap()
    );
}

#[test]
fn skipped_serialization_observation_is_bounded_and_worker_joins() {
    let f = Fixture::new();
    let competitor = Competitor::new(f.owner.backend.clone());
    competitor.expect(true); // Positive control: observer and reply channel work.
    let observations = BoundaryObservations::default();
    // Deliberately skip post-ack/pre-effect, recorder and return callbacks.
    assert_eq!(
        observations.status(),
        ObservationStatus::Missing(ObservationPhase::PostAckPreEffect)
    );
    assert_eq!(
        competitor.wait_for_skipped_observation(Duration::from_millis(20)),
        CompetitorObservation::Missing
    );
    assert_eq!(competitor.requests.load(Ordering::SeqCst), 1);
    assert!(
        competitor.shutdown(),
        "bounded supervisor shutdown must be acknowledged"
    );
    assert!(competitor.joined.load(Ordering::SeqCst));
    drop(competitor);
}

#[test]
fn actual_publication_failures_surviving_storage_and_recovery_fenced_retry() {
    for fault in [
        InjectFault::FailBeforeSubmit,
        InjectFault::WriteErrors,
        InjectFault::UncertainAfterWrite,
    ] {
        let mut f = Fixture::new();
        let before = f.sample();
        let inventory = Inventory::checked(&f.owner, &f.tc).unwrap();
        let unchanged = RefusalBaseline::capture(&f);
        let original = f.tc.clone();
        let original_bytes = f.read().encoded().to_vec();
        let backings = input_backings(&f.tc);
        f.owner.backend.set_inject(fault);
        let result = f.run();
        unchanged.assert_route_refusal(&f, inventory.route);
        assert_eq!(result.controls.refused, Some(Refusal::Publication));
        assert_eq!(
            (result.controls.gate_calls, result.controls.submitted),
            (1, 1)
        );
        assert_eq!(
            result.outcome,
            Some(Ok(TimeoutCertificateOutcome::Refused {
                reason: Refusal::Publication
            }))
        );
        assert_eq!(result.controls.submitted, 1);
        match (&result.controls.publication, fault) {
            (Some(PublishResult::RefusedPreWrite(_)), InjectFault::FailBeforeSubmit)
            | (Some(PublishResult::WriteFailedAmbiguous(_)), InjectFault::WriteErrors)
            | (Some(PublishResult::UncertainDurable), InjectFault::UncertainAfterWrite) => {}
            _ => panic!("wrong actual publication classification (redacted)"),
        }
        f.unchanged();
        assert!(f.tc == original, "input changed (redacted)");
        assert!(
            input_backings(&f.tc) == backings,
            "input backing changed (redacted)"
        );
        drop(result);
        assert_eq!(f.sample(), before);
        let proof = f.read();
        let survived = fault == InjectFault::UncertainAfterWrite;
        assert_eq!(
            proof.publication_revision(),
            f.revision + u64::from(survived)
        );
        assert_eq!(proof.retained().is_locked(), survived);
        if survived {
            let SafetyRecord::Locked(record) = &proof.retained().record else {
                unreachable!()
            };
            let SupportingEvidence::TcDerived { tc, .. } = &record.evidence else {
                unreachable!()
            };
            assert!(tc == &f.tc, "surviving full TC differs (redacted)");
        } else {
            assert!(
                proof.encoded() == original_bytes,
                "surviving predecessor bytes differ (redacted)"
            );
        }
        drop(proof);
        assert_eq!(
            f.owner.backend.recovery_required(),
            fault != InjectFault::FailBeforeSubmit
        );
        f.owner.backend.set_inject(InjectFault::None);
        let retry = f.run();
        if fault == InjectFault::FailBeforeSubmit {
            assert!(f.tc == unchanged.tc, "complete input TC differs (redacted)");
            assert!(
                input_backings(&f.tc) == unchanged.input_backings,
                "input backing differs (redacted)"
            );
            assert_eq!(ConsensusLedger::capture(&f.engine), unchanged.consensus);
            assert_eq!(
                Arc::strong_count(&f.selected),
                unchanged.selected_arc_strong_count
            );
            before.returned(&f, inventory.route);
            assert_eq!(retry.controls.refused, None);
            assert!(matches!(
                retry.controls.publication,
                Some(PublishResult::DurableAcknowledged { .. })
            ));
            assert_eq!(
                (retry.controls.gate_calls, retry.controls.submitted),
                (1, 1)
            );
            unchanged.assert_applied(
                &f,
                Ledger {
                    operational: before.operational + inventory.route,
                    aggregate: before.aggregate + inventory.route,
                    ..before
                },
            );
        } else {
            unchanged.assert_route_refusal(&f, inventory.route);
            assert_eq!(retry.controls.refused, Some(Refusal::RecoveryRequired));
            assert_eq!(
                (retry.controls.gate_calls, retry.controls.submitted),
                (0, 0)
            );
            assert!(retry.controls.publication.is_none());
            f.unchanged();
        }
        drop(retry);
        if fault == InjectFault::FailBeforeSubmit {
            unchanged.assert_applied(&f, before);
        } else {
            unchanged.assert_route_returned(&f);
        }
    }
}

#[test]
fn independent_revision_context_selected_and_predecessor_fences() {
    for case in 0..10 {
        let mut f = Fixture::new();
        if (4..=7).contains(&case) {
            f.seed(None);
        }
        if case == 3 || (5..=7).contains(&case) {
            let mut lock = f.tc.high_qc.as_ref().unwrap().clone();
            lock.view = if case >= 6 { 5 } else { 4 };
            lock.block_id = if case == 7 { [0xB5; 32] } else { [0x44; 32] };
            f.engine.state_mut().set_locked_qc(lock);
        }
        if case == 8 {
            f.engine = BasicHotStuffEngine::new(
                ValidatorId(0),
                ConsensusValidatorSet::new((0..4).map(|id| ValidatorSetEntry {
                    id: ValidatorId(id),
                    voting_power: if id == 3 { 2 } else { 1 },
                }))
                .unwrap(),
            );
            for timeout in &f.tc.signed_timeouts {
                f.engine
                    .on_timeout_msg(timeout.validator_id, timeout.clone())
                    .unwrap();
            }
        }
        let unchanged = RefusalBaseline::capture(&f);
        let before = f.sample();
        let expected = if case == 0 {
            f.revision + 1
        } else {
            f.revision
        };
        let wrong = Authority::new_for_wire_chain(8);
        let authority = if case == 1 { &wrong } else { &f.authority };
        let foreign = Fixture::new();
        let selected = if case == 2 {
            None
        } else if case == 9 {
            Some(foreign.selected.as_ref())
        } else {
            Some(f.selected.as_ref())
        };
        let route = Inventory::checked(&f.owner, &f.tc).unwrap().route;
        let result = admit(&f.owner, &f.tc).unwrap().invoke(
            &mut f.engine,
            authority,
            selected,
            expected,
            Some(&f.history),
            |_| {},
            |_| {},
        );
        if case == 7 {
            unchanged.assert_applied(
                &f,
                Ledger {
                    operational: before.operational + route,
                    aggregate: before.aggregate + route,
                    ..before
                },
            );
            assert_eq!(result.controls.refused, None);
            assert_eq!(
                (result.controls.gate_calls, result.controls.submitted),
                (1, 1)
            );
            assert!(matches!(
                result.controls.publication,
                Some(PublishResult::DurableAcknowledged { .. })
            ));
        } else {
            unchanged.assert_route_refusal(&f, route);
            let reason = match case {
                0 => Refusal::Revision,
                1 | 8 => Refusal::Context,
                2 | 9 => Refusal::SelectedQc,
                _ => Refusal::Predecessor,
            };
            assert_eq!(result.controls.refused, Some(reason));
            let expected_gate_calls = usize::from(case == 2 || case == 9);
            assert_eq!(
                (result.controls.gate_calls, result.controls.submitted),
                (expected_gate_calls, 0)
            );
            assert_eq!(f.engine.current_view(), 0);
        }
        drop(result);
        if case == 7 {
            unchanged.assert_applied(&f, before);
            assert_eq!(ConsensusLedger::capture(&f.engine), unchanged.consensus);
            assert_eq!(
                Arc::strong_count(&f.selected),
                unchanged.selected_arc_strong_count
            );
        } else {
            unchanged.assert_route_returned(&f);
        }
        assert_eq!(f.sample(), before);
    }
}

#[test]
fn anchored_predecessor_requires_independent_history_and_preserves_anchor() {
    for case in 0..3 {
        let mut f = Fixture::new();
        let anchor = CommittedAnchor {
            block_id: [0xC1; 32],
            height: 1,
        };
        f.history = FixtureCommittedHistory::new().with(anchor.block_id, anchor.height);
        f.seed(Some(anchor.clone()));
        f.engine.state_mut().set_locked_qc(LogicalQc::new(
            [0xB5; 32],
            5,
            vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
        ));
        let wrong = FixtureCommittedHistory::new().with([0xC2; 32], 1);
        let history = match case {
            0 => None,
            1 => Some(&wrong),
            _ => Some(&f.history),
        };
        let unchanged = RefusalBaseline::capture(&f);
        let before = f.sample();
        let route = Inventory::checked(&f.owner, &f.tc).unwrap().route;
        let report = admit(&f.owner, &f.tc).unwrap().invoke(
            &mut f.engine,
            &f.authority,
            Some(&f.selected),
            f.revision,
            history,
            |_| {},
            |_| {},
        );
        if case < 2 {
            unchanged.assert_route_refusal(&f, route);
            assert_eq!(report.controls.refused, Some(Refusal::Loader));
            assert_eq!(
                (report.controls.gate_calls, report.controls.submitted),
                (0, 0)
            );
        } else {
            unchanged.assert_applied(
                &f,
                Ledger {
                    operational: before.operational + route,
                    aggregate: before.aggregate + route,
                    ..before
                },
            );
            assert!(matches!(
                report.controls.publication,
                Some(PublishResult::DurableAcknowledged { .. })
            ));
        }
        drop(report);
        if case < 2 {
            unchanged.assert_route_returned(&f);
        } else {
            unchanged.assert_applied(&f, before);
        }
        assert_eq!(f.sample(), before);
        let proof = f.read();
        let SafetyRecord::Locked(record) = &proof.retained().record else {
            unreachable!()
        };
        assert_eq!(record.committed_anchor, Some(anchor));
    }
}

#[test]
fn genuine_target_substitution_and_stale_none_equal_lower_controls() {
    for case in 0..7 {
        let mut f = Fixture::new();
        match case {
            0 => f.tc.view += 1, // Only unsigned target substituted in genuine signed evidence.
            1 => {
                f.engine.try_advance_to_view(8);
            }
            2 => {
                // Genuine None timeouts: re-sign the actual changed preimages.
                f.tc.high_qc = None;
                for timeout in &mut f.tc.signed_timeouts {
                    timeout.high_qc = None;
                    timeout.signature = MlDsa44Backend::sign(
                        f.authority.secret(timeout.validator_id.0 as usize),
                        &timeout.signing_bytes(),
                    )
                    .unwrap();
                }
            }
            3 | 4 => {
                let view = if case == 3 { 6 } else { 7 };
                f.seed_view(None, view);
                f.engine.state_mut().set_locked_qc(LogicalQc::new(
                    [0xB5; 32],
                    view,
                    vec![ValidatorId(0)],
                ));
            }
            _ => {
                f.tc.timeout_view = if case == 5 { u64::MAX - 1 } else { u64::MAX };
                f.tc.view = u64::MAX;
                for timeout in &mut f.tc.signed_timeouts {
                    timeout.view = f.tc.timeout_view;
                    timeout.signature = MlDsa44Backend::sign(
                        f.authority.secret(timeout.validator_id.0 as usize),
                        &timeout.signing_bytes(),
                    )
                    .unwrap();
                }
            }
        }
        let registry =
            SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend));
        let verified = verify_timeout_certificate_with_evidence(
            &f.tc,
            &f.tc.signed_timeouts,
            f.engine.validators(),
            &f.authority,
            &registry,
            qbind_types::QBIND_DEVNET_CHAIN_ID,
        );
        assert_eq!(verified.is_ok(), case != 0 && case != 6);
        let before = f.sample();
        let report = f.run();
        before.returned(&f, Inventory::checked(&f.owner, &f.tc).unwrap().route);
        if case == 0 || case == 6 {
            assert!(matches!(report.outcome, Some(Err(_))));
        } else if case == 1 {
            assert_eq!(
                report.outcome,
                Some(Ok(TimeoutCertificateOutcome::Stale { view: 8 }))
            );
        } else if case == 5 {
            assert_eq!(
                report.outcome,
                Some(Ok(TimeoutCertificateOutcome::LockRaised { view: u64::MAX }))
            );
        } else {
            assert_eq!(
                report.outcome,
                Some(Ok(TimeoutCertificateOutcome::AdvancedWithoutLockRaise {
                    view: 8
                }))
            );
        }
        assert_eq!(report.controls.submitted, usize::from(case == 5));
        drop(report);
        assert_eq!(f.sample(), before);
    }
}

#[test]
fn admission_pressure_relief_retry_and_valid_over_capacity() {
    let mut f = Fixture::new();
    let before = f.sample();
    let plan = Inventory::checked(&f.owner, &f.tc).unwrap();
    let free = before.aggregate_cap.unwrap() - before.aggregate;
    let abandoned = admit(&f.owner, &f.tc).unwrap();
    before.returned(&f, plan.route);
    drop(abandoned);
    assert_eq!(f.sample(), before);
    let pressure = f.owner.backend.accounting().reserve(free).unwrap();
    let unchanged = RefusalBaseline::capture(&f);
    let refused = admit(&f.owner, &f.tc);
    assert!(matches!(refused, Err(Refusal::Capacity)));
    unchanged.assert_admission_refusal(&f);
    assert_eq!(
        f.sample(),
        Ledger {
            operational: before.operational + free,
            aggregate: before.aggregate + free,
            ..before
        }
    );
    drop(pressure);
    unchanged.assert_input_engine_consensus(&f);
    assert_eq!(f.sample(), before);
    let admission = admit(&f.owner, &f.tc).unwrap();
    let pressure = f
        .owner
        .backend
        .accounting()
        .reserve(free - plan.route)
        .unwrap();
    let under_loader_pressure = RefusalBaseline::capture(&f);
    let result = admission.invoke(
        &mut f.engine,
        &f.authority,
        Some(&f.selected),
        f.revision,
        Some(&f.history),
        |_| {},
        |_| {},
    );
    under_loader_pressure.assert_route_returned(&f);
    assert_eq!(result.controls.refused, Some(Refusal::Loader));
    assert_eq!(
        (result.controls.gate_calls, result.controls.submitted),
        (0, 0)
    );
    drop(result);
    under_loader_pressure.assert_report_released(
        &f,
        Ledger {
            operational: under_loader_pressure.node.operational - plan.route,
            aggregate: under_loader_pressure.node.aggregate - plan.route,
            ..under_loader_pressure.node
        },
    );
    drop(pressure);
    assert_eq!(f.sample(), before);
    let success = f.run();
    before.returned(&f, plan.route);
    assert!(matches!(
        success.controls.publication,
        Some(PublishResult::DurableAcknowledged { .. })
    ));
    assert_eq!(
        (success.controls.gate_calls, success.controls.submitted),
        (1, 1)
    );
    unchanged.assert_applied(
        &f,
        Ledger {
            operational: before.operational + plan.route,
            aggregate: before.aggregate + plan.route,
            ..before
        },
    );
    drop(success);
    unchanged.assert_applied(&f, before);
    assert_eq!(f.sample(), before);

    let mut f = Fixture::new();
    let before = f.sample();
    let plan = Inventory::checked(&f.owner, &f.tc).unwrap();
    let free = before.aggregate_cap.unwrap() - before.aggregate;
    let available = plan.route + plan.loader.max(plan.candidate);
    let pressure = f
        .owner
        .backend
        .accounting()
        .reserve(free - available)
        .unwrap();
    let under_o4_pressure = RefusalBaseline::capture(&f);
    let result = f.run();
    under_o4_pressure.assert_route_refusal(&f, plan.route);
    assert_eq!(result.controls.submitted, 1);
    assert!(matches!(
        result.controls.publication,
        Some(PublishResult::RefusedPreWrite(
            SafetyStoreError::CapacityRefusal(_)
        ))
    ));
    assert_eq!(result.controls.refused, Some(Refusal::Publication));
    assert_eq!(
        (result.controls.gate_calls, result.controls.submitted),
        (1, 1)
    );
    assert_eq!(
        f.sample(),
        Ledger {
            operational: before.operational + free - available + plan.route,
            aggregate: before.aggregate + free - available + plan.route,
            ..before
        }
    );
    drop(result);
    under_o4_pressure.assert_report_released(
        &f,
        Ledger {
            operational: before.operational + free - available,
            aggregate: before.aggregate + free - available,
            ..before
        },
    );
    drop(pressure);
    assert_eq!(f.sample(), before);
    let result = f.run();
    before.returned(&f, plan.route);
    assert!(matches!(
        result.controls.publication,
        Some(PublishResult::DurableAcknowledged { .. })
    ));
    assert_eq!(
        (result.controls.gate_calls, result.controls.submitted),
        (1, 1)
    );
    under_o4_pressure.assert_applied(
        &f,
        Ledger {
            operational: before.operational + plan.route,
            aggregate: before.aggregate + plan.route,
            ..before
        },
    );
    drop(result);
    assert_eq!(
        ConsensusLedger::capture(&f.engine),
        under_o4_pressure.consensus
    );
    assert_eq!(
        Arc::strong_count(&f.selected),
        under_o4_pressure.selected_arc_strong_count
    );
    assert_eq!(f.sample(), before);

    let mut f = Fixture::new();
    // Preserve valid cryptography, lengths, quorum and powers; only backing is over cap.
    let signature = &mut f.tc.signed_timeouts[0].signature;
    let mut oversized = Vec::with_capacity(f.owner.pinned().s_sig + 1);
    oversized.extend_from_slice(signature);
    *signature = oversized;
    let registry =
        SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend));
    assert!(verify_timeout_certificate_with_evidence(
        &f.tc,
        &f.tc.signed_timeouts,
        f.engine.validators(),
        &f.authority,
        &registry,
        qbind_types::QBIND_DEVNET_CHAIN_ID
    )
    .is_ok());
    let before = f.sample();
    let unchanged = RefusalBaseline::capture(&f);
    let refused = admit(&f.owner, &f.tc);
    assert!(matches!(refused, Err(Refusal::Capacity)));
    unchanged.assert_admission_refusal(&f);
    assert_eq!(f.sample(), before);
}

#[test]
fn helper_only_strict_publication_rejects_equal_and_lower_candidates() {
    for predecessor_view in [6, 7] {
        let mut f = Fixture::new();
        f.seed_view(None, predecessor_view);
        f.engine.state_mut().set_locked_qc(LogicalQc::new(
            [0xB5; 32],
            predecessor_view,
            vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
        ));
        let before = f.sample();
        let admission = admit(&f.owner, &f.tc).unwrap();
        let guard = f.owner.backend.lock_domain();
        let mut gate = Gate {
            owner: &f.owner,
            guard: &guard,
            history: Some(&f.history),
            expected: f.revision,
            inventory: admission.inventory,
            controls: Controls::default(),
            anchor: None,
        };
        gate.check_predecessor(&f.engine).unwrap();
        assert_eq!(
            gate.publish(
                &f.engine,
                &f.tc,
                f.tc.high_qc.as_ref().unwrap(),
                Some(&f.selected)
            ),
            Err(Refusal::NonAdvancing)
        );
        assert_eq!(gate.controls.submitted, 0);
        drop(gate);
        drop(guard);
        drop(admission);
        assert_eq!(f.sample(), before);
    }
}

#[test]
fn nonraising_effective_operation_cannot_skip_authoritative_fences() {
    for mismatch in [false, true] {
        let mut f = Fixture::new();
        if mismatch {
            f.engine
                .state_mut()
                .set_locked_qc(f.tc.high_qc.as_ref().unwrap().clone());
        } else {
            f.tc.high_qc = None;
            f.revision += 1;
            for timeout in &mut f.tc.signed_timeouts {
                timeout.high_qc = None;
                timeout.signature = MlDsa44Backend::sign(
                    f.authority.secret(timeout.validator_id.0 as usize),
                    &timeout.signing_bytes(),
                )
                .unwrap();
            }
        }
        let before = f.sample();
        let result = f.run();
        before.returned(&f, Inventory::checked(&f.owner, &f.tc).unwrap().route);
        assert_eq!(
            result.controls.refused,
            Some(if mismatch {
                Refusal::Predecessor
            } else {
                Refusal::Revision
            })
        );
        assert_eq!(
            (result.controls.gate_calls, result.controls.submitted),
            (0, 0)
        );
        assert_eq!(f.engine.current_view(), 0);
        assert_eq!(f.engine.timeout_count(7), 3);
        drop(result);
        assert_eq!(f.sample(), before);
    }
}

#[test]
fn controlled_unwind_distinguishes_pre_effect_and_applied_callback() {
    for boundary in 0..3 {
        let mut f = Fixture::new();
        let before = f.sample();
        if boundary == 1 {
            f.notes.panic.store(true, Ordering::SeqCst);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = admit(&f.owner, &f.tc).unwrap().invoke(
                &mut f.engine,
                &f.authority,
                Some(&f.selected),
                f.revision,
                Some(&f.history),
                |_| {
                    assert!(boundary != 0, "controlled post-ack/pre-effect unwind");
                },
                |_| {
                    assert!(boundary != 2, "controlled return unwind");
                },
            );
        }));
        assert!(result.is_err());
        assert_eq!(f.sample(), before);
        // Domain poisoning is real, not bypassed by recovery. Reservations still unwind.
        assert!(matches!(
            f.owner.backend.try_lock_domain_for_test(),
            TryLockDomainOutcome::Poisoned
        ));
        assert!(!f.owner.backend.recovery_required());
        if boundary != 0 {
            assert_eq!(f.engine.locked_qc().map(|q| q.view), Some(6));
            assert_eq!(f.engine.current_view(), if boundary == 1 { 0 } else { 8 });
            assert_eq!(f.engine.timeout_count(7), if boundary == 1 { 3 } else { 0 });
        } else {
            f.unchanged();
        }
        // Read actual surviving bytes without acquiring the poisoned domain.
        let bytes = f
            .owner
            .backend
            .read_record(max_safety_record_bytes(f.owner.pinned()).unwrap())
            .unwrap()
            .unwrap();
        let decoded = super::super::codec::decode_record(&bytes, f.owner.pinned()).unwrap();
        assert_eq!(decoded.publication_revision, f.revision + 1);
        assert!(
            decoded.is_locked(),
            "acknowledged storage is not rolled back"
        );
    }
}
