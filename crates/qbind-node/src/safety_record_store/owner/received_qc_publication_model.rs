//! Isolated received-QC -> ordinary O4 -> ordinary QC effects composition.
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
// Includes both gate control copies, caller/result carriers and by-value
// conversion/binding control temporaries; nested QC backing is charged separately.
fn adapter_charge() -> u128 {
    support::control_bytes()
        + (2 * size_of::<Gate<'static, 'static>>()
            + 2 * size_of::<ModelResult>()
            + 2 * size_of::<PublishResult>()
            + size_of::<WireQc>()
            + size_of::<LockedRecord>()
            + 2 * size_of::<Option<CommittedAnchor>>()
            + size_of::<Result<ValidatedRecord, super::super::decision_capture::CurrentLoadFailure>>(
            )
            + size_of::<std::sync::MutexGuard<'static, super::super::backend::SerializationDomain>>(
            )
            + 4 * size_of::<Reservation>()) as u128
}

fn compose(
    owner: &SafetyRecordOwner,
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    authority: &Authority,
    token: support::Token,
    expected: u64,
    history: &FixtureCommittedHistory,
) -> Result<ModelResult, support::Token> {
    let coverage = match owner.backend.accounting().reserve(adapter_charge()) {
        Ok(lease) => lease,
        Err(_) => return Err(token), // pre-consumption pressure, exact token returned
    };
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
    Ok(ModelResult {
        route,
        publication,
        refused,
        gate_calls,
        submitted,
        after_route,
        _coverage: coverage,
    })
}

#[derive(Debug, Default)]
struct Notifications {
    vote: AtomicUsize,
    validator: AtomicUsize,
    qc: AtomicUsize,
    view: AtomicUsize,
    guarded_backend: Mutex<Option<SafetyBackend>>,
}
impl Notifications {
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
    fn record_leader_change(&self) {}
    fn reset_current_view_votes(&self) {}
}
impl ValidatorVoteRecorder for Notifications {
    fn on_validator_vote(&self, _: ValidatorId, _: u64) {
        self.validator.fetch_add(1, Ordering::SeqCst);
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
    fn run(&mut self, token: support::Token) -> ModelResult {
        match compose(
            &self.owner,
            &mut self.engine,
            &self.authority,
            token,
            self.revision,
            &self.history,
        ) {
            Ok(result) => result,
            Err(_) => panic!("unexpected adapter admission refusal"),
        }
    }
    fn seed(&mut self, view: u64) {
        for signer in 0..3 {
            let token = self.token(signer, view, 9);
            let result = self.run(token);
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
            drop(result);
            assert_eq!(self.owner.backend.accounting_current(), 0);
        }
    }
    fn ready(&mut self, view: u64, mixed: bool) -> support::Token {
        for signer in 0..2 {
            let token = self.token(signer, view, if mixed && signer == 0 { 10 } else { 9 });
            let result = self.run(token);
            assert_eq!(result.gate_calls, 0);
        }
        self.token(2, view, 9)
    }
    fn assert_released(&self, result: ModelResult) {
        let context = self.owner.backend.context_accounting_current();
        assert_eq!(
            result.after_route,
            (adapter_charge(), context + adapter_charge())
        );
        drop(result);
        // Before any diagnostic readback allocation.
        assert_eq!(self.owner.backend.accounting_current(), 0);
        assert_eq!(self.owner.backend.accounting_aggregate_current(), context);
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
    let result = f.run(token);
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
    let refused = f.run(token);
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
    let result = f.run(token);
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
    let result = f.run(token);
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
    assert_eq!(lock.lock_view, if newer { 3 } else { 2 });
    drop(proof);
    if newer {
        f.revision += 1;
    }
    let token = f.token(2, 3, 9);
    let retry = f.run(token);
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
        let result = compose(
            &f.owner,
            &mut f.engine,
            if mode == 2 {
                &bad_authority
            } else {
                &f.authority
            },
            token,
            f.revision,
            &f.history,
        )
        .ok()
        .unwrap();
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
        let result = f.run(token);
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
    let result = f.run(token);
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
    let result = f.run(token);
    assert_eq!(result.gate_calls, 0);
    f.assert_released(result);
    let token = f.token(2, 1, 9);
    let apps = support::applications(&f.engine);
    let result = f.run(token);
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
    let result = compose(
        &owner,
        &mut f.engine,
        &f.authority,
        token,
        revision,
        &f.history,
    )
    .ok()
    .unwrap();
    assert_eq!(result.refused, Some(Refused::Lock));
    assert_eq!(result.submitted, 0);
    assert!(result.publication.is_none());
    assert_eq!(Effects::capture(&f.engine, IDS[1]), before);
    drop(result);
    assert_eq!(owner.backend.accounting_current(), 0);
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
        let result = compose(
            &owner,
            &mut f.engine,
            &f.authority,
            token,
            revision,
            &f.history,
        )
        .ok()
        .unwrap();
        assert_eq!(result.refused, Some(Refused::Context));
        assert_eq!(result.submitted, 0);
        assert!(result.publication.is_none());
        assert_eq!(support::applications(&f.engine), apps);
        drop(result);
        assert_eq!(owner.backend.accounting_current(), 0);
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
    let report = f.run(token);
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
    let refused = f.run(token);
    assert_eq!(refused.refused, Some(Refused::Loader));
    assert_eq!(refused.submitted, 0);
    f.assert_released(refused);
    f.history = FixtureCommittedHistory::new().with(IDS[0], 0);
    let token = f.token(2, 4, 9);
    let result = f.run(token);
    assert_eq!(
        result.route.as_ref().ok().unwrap().application(),
        support::Application::Applied
    );
    assert_eq!(f.engine.committed_block(), Some(&IDS[1]));
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
    f.assert_released(result);
}

#[test]
fn consensus_preparation_pressure_returns_original_token_and_restores_ledgers() {
    let mut f = Fixture::new();
    let token = f.ready(1, false);
    let ptr = token.vote().signature.as_ptr();
    let capacity = token.vote().signature.capacity();
    let ledger = support::ledger(&f.engine);
    let before = ledger.sample();
    let apps = support::applications(&f.engine);
    support::set_cap(&mut f.engine, before.0);
    let result = f.run(token);
    assert_eq!((result.gate_calls, result.submitted), (0, 0));
    let refusal = result.route.as_ref().err().unwrap();
    assert!(refusal.preparation_pressure());
    assert_eq!(
        (
            refusal.vote().signature.as_ptr(),
            refusal.vote().signature.capacity()
        ),
        (ptr, capacity)
    );
    assert_eq!(ledger.sample(), before);
    assert_eq!(support::applications(&f.engine), apps);
    assert_eq!(support::vote_count(&f.engine, 1, &IDS[0]), 2);
    let ModelResult {
        route, _coverage, ..
    } = result;
    let token = route.err().unwrap().into_token();
    drop(_coverage);
    assert_eq!(f.owner.backend.accounting_current(), 0);
    support::set_cap(&mut f.engine, u64::MAX);
    let result = f.run(token);
    assert_eq!(
        result.route.as_ref().ok().unwrap().application(),
        support::Application::Applied
    );
    f.assert_released(result);
}

#[test]
fn adapter_candidate_and_o4_pressure_are_distinct_and_cleanup_is_immediate() {
    for boundary in 0..3 {
        let mut f = Fixture::new();
        let token = f.ready(1, false);
        let ptr = token.vote().signature.as_ptr();
        let capacity = token.vote().signature.capacity();
        let ledger = support::ledger(&f.engine);
        let before = ledger.sample();
        let context = f.owner.backend.context_accounting_current();
        let cap = f.owner.backend.accounting_aggregate_cap().unwrap();
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
            .reserve(cap - context - leave)
            .unwrap();
        let result = compose(
            &f.owner,
            &mut f.engine,
            &f.authority,
            token,
            f.revision,
            &f.history,
        );
        if boundary == 0 {
            let token = result.err().expect("adapter must refuse");
            assert_eq!(
                (
                    token.vote().signature.as_ptr(),
                    token.vote().signature.capacity()
                ),
                (ptr, capacity)
            );
            assert_eq!(ledger.sample(), before);
            drop(held);
            assert_eq!(f.owner.backend.accounting_current(), 0);
            let result = f.run(token);
            f.assert_released(result);
        } else {
            let result = result.ok().unwrap();
            let report = result.route.as_ref().ok().unwrap();
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
            assert_eq!(f.owner.backend.accounting_current(), held.charge());
            assert_eq!(
                f.owner.backend.accounting_aggregate_current(),
                context + held.charge()
            );
            assert_eq!(ledger.sample().1, 0);
            assert_eq!(ledger.sample().4, 0);
            drop(held);
            let token = f.token(2, 1, 9);
            let result = f.run(token);
            f.assert_released(result);
        }
    }
}

#[test]
fn existing_post_ack_hook_unwind_releases_both_ledgers() {
    let mut f = Fixture::new();
    let token = f.ready(1, false);
    let ledger = support::ledger(&f.engine);
    let context = f.owner.backend.context_accounting_current();
    f.owner.backend.set_pre_effective_hook(Arc::new(|_, _| {
        panic!("existing post-ack hook test unwind")
    }));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.run(token)));
    assert!(result.is_err());
    assert_eq!(f.owner.backend.accounting_current(), 0);
    assert_eq!(f.owner.backend.accounting_aggregate_current(), context);
    let sample = ledger.sample();
    assert_eq!((sample.1, sample.3, sample.4, sample.5), (0, 0, 0, 0));
    // Poisoned owner is not reused or silently recovered.
    let backend = f.owner.backend.clone();
    drop(f);
    assert_eq!(ledger.sample(), support::empty_ledger_floor());
    assert_eq!(backend.accounting_aggregate_current(), 0);
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
    let result = f.run(token);
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
    assert_eq!(backend.accounting_current(), 0);
    assert_eq!(backend.context_accounting_current(), 0);
    assert_eq!(backend.accounting_aggregate_current(), 0);
}
