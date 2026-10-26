//! RUN 422 §13.6 — Owner-controlled decision/capture binding (ISOLATED).
//!
//! These tests exercise the owner-controlled route
//! [`SafetyRecordOwner::decide_and_capture_owned`]: the owner acquires the
//! backend serialization domain, invokes the existing owning engine entrypoint,
//! the real safety decision runs under L0, correspondence / projection /
//! input-policy / ancestry checks and the capture run under that SAME held
//! guard, the existing self-vote may raise L1, and the existing closed
//! `DecidedVote<OwningCapturePayload>` envelope is produced.
//!
//! The route authenticates nothing: the proposal commitment and ancestry
//! binding are a *volatile decision association*, not a certificate check. The
//! whole target is gated behind `test-utils` (it uses the `test-utils`-gated
//! observation seams `backend_for_test`, `accounting_current`,
//! `reserve_standing_for_test`, `prepared_registry_for_test`,
//! `try_lock_domain_for_test`, `set_capture_interval_hook`) and carries no
//! production caller. Activation remains DISABLED.

#![cfg(feature = "test-utils")]

use std::sync::mpsc;
use std::time::Duration;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::qc_verify_domain::{
    verify_quorum_certificate_with_domain, VerifiedQuorumCertificate,
};
use qbind_consensus::validator_set::ValidatorSetEntry;
use qbind_consensus::{BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet};
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::{ConsensusSigSuiteId, SUITE_PQ_RESERVED_1};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::safety_record_store::backend::{
    SafetyBackend, SafetyBackendPolicy, TryLockDomainOutcome,
};
use qbind_node::safety_record_store::decision_capture::{
    covering_charge_for_test, scratch_charge_for_test, EntrypointKind, OwnedCaptureRefusal,
    OwnedDecisionOutcome, PreparedDecisionInputLimits, ProjectionMismatch,
};
use qbind_node::safety_record_store::owner::{
    clear_binding_phase_hook, clear_capture_interval_hook, clear_pre_ingestion_hook,
    make_locked_qc, set_binding_phase_hook, set_capture_interval_hook, set_pre_ingestion_hook,
    PublishResult, SafetyRecordOwner,
};
use qbind_node::safety_record_store::prepared::{registry_cell_charge_bytes, CaptureRefusal};
use qbind_node::safety_record_store::profile::PinnedSafetyContext;
use qbind_node::safety_record_store::record::WireQc as StoreWireQc;
use qbind_node::safety_record_store::validate::FixtureCommittedHistory;
use qbind_types::ChainId;
use qbind_wire::consensus::{
    BlockHeader, BlockProposal, QuorumCertificate as EngineWireQc, Vote,
};
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;
use sha3::{Digest, Sha3_256};

// ===========================================================================
// Fixtures (mirrors of the owning-handoff node test fixtures)
// ===========================================================================

const QC_SUITE: u16 = 7;
const TIMEOUT_SUITE: u8 = 100;
const S_SIG: usize = 8;
const CHAIN_ID: u32 = 42;
const EPOCH: u64 = 7;

fn ctx_n(n: u64) -> PinnedSafetyContext {
    let validators = (0..n).map(|i| (ValidatorId::new(i), 1u64)).collect();
    PinnedSafetyContext {
        network_genesis_id: [1u8; 32],
        authority_context_ref: [2u8; 32],
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        qc_suite_id: QC_SUITE,
        timeout_suite_id: TIMEOUT_SUITE,
        s_sig: S_SIG,
        validators,
        require_height_equals_round: false,
    }
}

fn valid_wire_qc(ctx: &PinnedSafetyContext, block_id: [u8; 32], view: u64) -> StoreWireQc {
    let n = ctx.n() as u64;
    let mut bitmap = vec![0u8; ((n + 7) / 8).max(1) as usize];
    let mut signatures = Vec::new();
    for i in 0..n {
        bitmap[(i / 8) as usize] |= 1 << (i % 8);
        signatures.push(vec![0xABu8; S_SIG]);
    }
    signatures.shrink_to_fit();
    StoreWireQc {
        version: 1,
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        height: view,
        round: view,
        step: 0,
        block_id,
        suite_id: QC_SUITE,
        signer_bitmap: bitmap,
        signatures,
    }
}

fn open_enabled(dir: &std::path::Path) -> SafetyBackend {
    SafetyBackend::open_or_initialize(
        dir,
        SafetyBackendPolicy::EnabledForTesting,
        TrustBundleEnvironment::Devnet,
    )
    .expect("enabled devnet backend opens")
}

fn init_owner(dir: &std::path::Path, ctx: &PinnedSafetyContext) -> SafetyRecordOwner {
    let backend = open_enabled(dir);
    let owner = SafetyRecordOwner::attach(backend, ctx.clone()).expect("attach");
    owner.initialize(true).expect("O1 initialize");
    owner
}

/// Publish one Locked restriction and return the new authoritative revision.
fn publish_qc(
    owner: &SafetyRecordOwner,
    ctx: &PinnedSafetyContext,
    block: [u8; 32],
    view: u64,
    expected: u64,
) -> u64 {
    let qc = valid_wire_qc(ctx, block, view);
    let l = make_locked_qc(ctx, block, view, qc, None).unwrap();
    match owner.publish_locked(l, expected, None::<&FixtureCommittedHistory>) {
        PublishResult::DurableAcknowledged { new_revision } => new_revision,
        other => panic!("expected DurableAcknowledged, got {other:?}"),
    }
}

fn op_current(owner: &SafetyRecordOwner) -> u128 {
    owner.backend_for_test().accounting_current()
}

/// The shared **aggregate** admission authority's current combined charge, read
/// through the backend's test seam. Distinct from [`op_current`] (the operational
/// sub-partition): the aggregate authority admits BOTH the operational and context
/// partitions against the one accepted profile ceiling.
fn agg_current(owner: &SafetyRecordOwner) -> u128 {
    owner.backend_for_test().accounting_aggregate_current()
}

/// A paired snapshot of BOTH admission ledgers taken through independent backend
/// test seams: the operational sub-partition charge ([`op_current`]) AND the
/// shared aggregate authority charge ([`agg_current`]). Neither counter is
/// inferred from the other — each is read directly — so a refusal that leaks on
/// one ledger but not the other is caught. Used to assert exact restoration of
/// both counters across refusals while a returned proof is still held.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct LedgerSnapshot {
    operational: u128,
    aggregate: u128,
    operational_ceiling: Option<u128>,
    aggregate_ceiling: Option<u128>,
}

fn ledger_snapshot(owner: &SafetyRecordOwner) -> LedgerSnapshot {
    let backend = owner.backend_for_test();
    LedgerSnapshot {
        operational: backend.accounting_current(),
        aggregate: backend.accounting_aggregate_current(),
        operational_ceiling: backend.accounting_cap(),
        aggregate_ceiling: backend.accounting_aggregate_cap(),
    }
}

fn registry_occupied(owner: &SafetyRecordOwner) -> usize {
    match owner.backend_for_test().prepared_registry_for_test() {
        Some(reg) => reg.lock().unwrap().occupied(),
        None => 0,
    }
}

fn limits(ctx: &PinnedSafetyContext) -> PreparedDecisionInputLimits {
    PreparedDecisionInputLimits::from_pinned(ctx).expect("pinned context yields a valid policy")
}

// ===========================================================================
// Bounded coordination (§2)
// ===========================================================================

/// Upper bound on every cross-thread wait in the serialization observation
/// tests. It is NOT a synchronization sleep: coordination is driven by actual
/// channel signals (the owner's hook announces its pause; the observer announces
/// release). The bound exists only so that an early owner refusal, a missing
/// hook invocation, an observer failure, or an assertion failure can never leave
/// a scoped thread waiting indefinitely — a stuck test fails within the bound
/// instead of hanging. It is generous relative to the microseconds a real
/// hand-off takes.
const COORD_TIMEOUT: Duration = Duration::from_secs(30);

/// Classification of a non-blocking same-domain acquisition that does NOT retain
/// an acquired guard: any `Acquired` guard is dropped at the match arm, so the
/// classification never itself holds the serialization domain. This distinguishes
/// contention (`WouldBlock`), successful acquisition, and poisoning.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DomainObservation {
    WouldBlock,
    Acquired,
    Poisoned,
}

fn classify_try_lock(outcome: TryLockDomainOutcome<'_>) -> DomainObservation {
    match outcome {
        TryLockDomainOutcome::WouldBlock => DomainObservation::WouldBlock,
        // Drop the acquired guard immediately: the classification must never
        // retain the domain it is merely observing.
        TryLockDomainOutcome::Acquired(_g) => DomainObservation::Acquired,
        TryLockDomainOutcome::Poisoned => DomainObservation::Poisoned,
    }
}

/// The four explicitly recorded legs of the bounded two-way observation
/// handshake (§3). Each is `None` until attempted, then `Some(true)` on success
/// or `Some(false)` on an actual channel failure (timeout or disconnect). The
/// test credits an observation as evidence of the intended paused phase ONLY when
/// [`HandshakeLegs::fully_completed`] holds; a silent timeout or a dropped
/// endpoint therefore produces a DISTINCT, recorded test failure rather than
/// being accepted as successful coordination.
#[derive(Clone, Copy, Default, Debug)]
struct HandshakeLegs {
    owner_entry_signalled: Option<bool>,
    owner_release_received: Option<bool>,
    observer_entry_received: Option<bool>,
    observer_release_acked: Option<bool>,
}

impl HandshakeLegs {
    fn fully_completed(&self) -> bool {
        self.owner_entry_signalled == Some(true)
            && self.owner_release_received == Some(true)
            && self.observer_entry_received == Some(true)
            && self.observer_release_acked == Some(true)
    }
}

/// Owner-side coordination handle, used INSIDE the serialization hook. The hook
/// bound is `Fn() + Send + Sync + 'static`, so the single-consumer endpoints are
/// wrapped in `Mutex` (both `Sender`/`Receiver` are `Send`). The hook only
/// signals and waits; it records outcomes into the shared legs and never panics,
/// so a failed hand-off cannot poison the held domain guard.
struct OwnerHookCoord {
    entry_tx: std::sync::Mutex<mpsc::Sender<()>>,
    release_rx: std::sync::Mutex<mpsc::Receiver<()>>,
    legs: std::sync::Arc<std::sync::Mutex<HandshakeLegs>>,
}

impl OwnerHookCoord {
    /// Signal entry (guard held, paused) and wait for the observer's release
    /// acknowledgement under the bounded timeout. Both outcomes are recorded; a
    /// send failure or a timeout/disconnect is captured as `Some(false)`.
    fn signal_entry_and_await_release(&self) {
        let sent = self.entry_tx.lock().unwrap().send(()).is_ok();
        self.legs.lock().unwrap().owner_entry_signalled = Some(sent);
        let released = self
            .release_rx
            .lock()
            .unwrap()
            .recv_timeout(COORD_TIMEOUT)
            .is_ok();
        self.legs.lock().unwrap().owner_release_received = Some(released);
    }
}

/// Observer-side coordination handle, owned by the single observer thread. Raw
/// endpoints (no `Mutex`) since it is used from one thread only. Dropping it
/// WITHOUT calling [`ObserverCoord::ack_release`] disconnects the owner's release
/// channel — the actual-channel-failure negative control.
struct ObserverCoord {
    entry_rx: mpsc::Receiver<()>,
    release_tx: mpsc::Sender<()>,
    legs: std::sync::Arc<std::sync::Mutex<HandshakeLegs>>,
}

impl ObserverCoord {
    /// Bounded wait for the owner's entry signal. Records and returns whether the
    /// signal arrived; a timeout/disconnect returns `false` so the caller does NOT
    /// credit any subsequent observation.
    fn await_entry(&self) -> bool {
        let got = self.entry_rx.recv_timeout(COORD_TIMEOUT).is_ok();
        self.legs.lock().unwrap().observer_entry_received = Some(got);
        got
    }

    /// Acknowledge release so the owner's bounded wait completes. Records whether
    /// the acknowledgement was delivered.
    fn ack_release(&self) {
        let acked = self.release_tx.send(()).is_ok();
        self.legs.lock().unwrap().observer_release_acked = Some(acked);
    }
}

/// Build a fresh bounded handshake: an [`OwnerHookCoord`] for the hook, an
/// [`ObserverCoord`] for the observer thread, and the shared [`HandshakeLegs`]
/// the test inspects (OUTSIDE the guarded hook) to require successful
/// coordination before crediting any observation.
fn make_handshake() -> (
    OwnerHookCoord,
    ObserverCoord,
    std::sync::Arc<std::sync::Mutex<HandshakeLegs>>,
) {
    let (entry_tx, entry_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let legs = std::sync::Arc::new(std::sync::Mutex::new(HandshakeLegs::default()));
    let owner = OwnerHookCoord {
        entry_tx: std::sync::Mutex::new(entry_tx),
        release_rx: std::sync::Mutex::new(release_rx),
        legs: std::sync::Arc::clone(&legs),
    };
    let observer = ObserverCoord {
        entry_rx,
        release_tx,
        legs: std::sync::Arc::clone(&legs),
    };
    (owner, observer, legs)
}

// ===========================================================================
// Returned-proof preservation (§3/§4)
// ===========================================================================

/// A read-only fingerprint of a [`ValidatedRecord`]'s externally observable
/// identity, taken BEFORE an owner-route call so the SAME returned proof can be
/// shown to be preserved — its original validated bytes, its publication
/// revision, and its originating pinned-context provenance digest. This compares
/// the ACTUAL returned proof (not a fresh `read_validate`) against the snapshot.
#[derive(Clone, PartialEq, Eq, Debug)]
struct ProofFingerprint {
    encoded: Vec<u8>,
    revision: u64,
    origin: [u8; 32],
    recovery_backend_incarnation: Option<u64>,
}

fn fingerprint(proof: &qbind_node::safety_record_store::ValidatedRecord) -> ProofFingerprint {
    ProofFingerprint {
        encoded: proof.encoded().to_vec(),
        revision: proof.publication_revision(),
        origin: *proof.origin_context_digest(),
        recovery_backend_incarnation: proof.recovery_backend_incarnation(),
    }
}

fn assert_same_proof_fingerprint(
    proof: &qbind_node::safety_record_store::ValidatedRecord,
    expected: &ProofFingerprint,
) {
    assert!(
        &fingerprint(proof) == expected,
        "returned proof differs from original bytes or provenance (redacted)"
    );
}

// ===========================================================================
// Consensus helpers
// ===========================================================================

fn engine_validator_set(num: u64) -> ConsensusValidatorSet {
    let entries = (1..=num)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId::new(i),
            voting_power: 1,
        })
        .collect::<Vec<_>>();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

fn make_proposal(view: u64, parent_block_id: [u8; 32], proposer_index: u16) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: view,
            round: view,
            parent_block_id,
            payload_hash: [0u8; 32],
            proposer_index,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

fn logical_qc(block_id: [u8; 32], height: u64) -> EngineWireQc {
    EngineWireQc {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round: height,
        step: 0,
        block_id,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![],
        signatures: vec![],
    }
}

/// A single-validator engine locked at view 0, advanced to view 1, together with
/// a safe view-1 proposal (ViewSufficiency branch) and the engine's L0 lock id.
fn engine_locked_and_safe_view1() -> (BasicHotStuffEngine<[u8; 32]>, BlockProposal, [u8; 32]) {
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId::new(1), engine_validator_set(1));
    let p0 = make_proposal(0, [0xFF; 32], 1);
    let a0 = engine.on_proposal_event(ValidatorId::new(1), &p0);
    assert!(matches!(a0, Some(ConsensusEngineAction::BroadcastVote(_))));
    let l0_block = engine.locked_qc().expect("L0 lock").block_id;
    engine.advance_view();
    assert_eq!(engine.current_view(), 1);
    let mut p1 = make_proposal(1, l0_block, 1);
    p1.qc = Some(logical_qc(l0_block, 0));
    (engine, p1, l0_block)
}

#[derive(Debug)]
struct OwnerVerifiedKeyProvider(Vec<u8>);

impl SuiteAwareValidatorKeyProvider for OwnerVerifiedKeyProvider {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        (id == ValidatorId::new(1)).then(|| (SUITE_PQ_RESERVED_1, self.0.clone()))
    }
}

fn verified_parent_qc(block_id: [u8; 32], view: u64) -> std::sync::Arc<VerifiedQuorumCertificate> {
    let (public_key, secret_key) = MlDsa44Backend::generate_keypair().expect("keygen");
    let domain = ProposalVoteSigningDomainV2::try_new(
        ChainId(1),
        1,
        [9u8; 32],
        [8u8; 32],
    )
    .expect("signing domain");
    let mut qc = EngineWireQc {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: view,
        round: view,
        step: 1,
        block_id,
        suite_id: 100,
        signer_bitmap: vec![0b10],
        signatures: Vec::new(),
    };
    let vote = Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: view,
        round: view,
        step: 1,
        block_id,
        validator_index: 1,
        suite_id: 100,
        signature: Vec::new(),
    };
    qc.signatures.push(
        MlDsa44Backend::sign(&secret_key, &domain.vote_preimage(&vote)).expect("QC signature"),
    );
    let validators = ConsensusValidatorSet::new(vec![ValidatorSetEntry {
        id: ValidatorId::new(1),
        voting_power: 1,
    }])
    .expect("validator set");
    let keys = OwnerVerifiedKeyProvider(public_key);
    let registry = SimpleBackendRegistry::with_backend(
        SUITE_PQ_RESERVED_1,
        std::sync::Arc::new(MlDsa44Backend),
    );
    std::sync::Arc::new(
        verify_quorum_certificate_with_domain(&qc, &domain, 0, &validators, &keys, &registry)
            .expect("QC verification"),
    )
}

/// Mint a Locked proof whose retained lock matches the engine's L0 lock, so the
/// owner-route correspondence check accepts it. Returns (owner, proof, limits).
fn owner_with_matching_proof(
    dir: &std::path::Path,
    ctx: &PinnedSafetyContext,
    l0_block: [u8; 32],
) -> SafetyRecordOwner {
    let owner = init_owner(dir, ctx);
    // Lock block id = engine L0 block, lock view 0 -> revision 1.
    publish_qc(&owner, ctx, l0_block, 0, 0);
    owner
}

#[test]
fn verified_owner_route_captures_before_self_vote_and_retains_evidence() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut proposal, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let evidence = verified_parent_qc(l0_block, 0);
    proposal.qc = Some(evidence.certificate().clone());
    let baseline_without_proof = ledger_snapshot(&owner);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let baseline_with_proof = ledger_snapshot(&owner);
    assert!(
        baseline_with_proof.operational > baseline_without_proof.operational
            && baseline_with_proof.aggregate > baseline_without_proof.aggregate,
        "the live proof contributes to both pre-call ledgers"
    );
    let limits = limits(&ctx);
    let standing_cell = registry_cell_charge_bytes();

    let decided = match owner.decide_verified_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &proposal,
        std::sync::Arc::clone(&evidence),
        &limits,
        1,
        proof,
    ) {
        OwnedDecisionOutcome::Decided(decided) => decided,
        _ => panic!("verified owner route should decide and capture"),
    };
    let occupied = ledger_snapshot(&owner);
    assert_eq!(
        occupied.operational_ceiling,
        baseline_with_proof.operational_ceiling
    );
    assert_eq!(occupied.aggregate_ceiling, baseline_with_proof.aggregate_ceiling);
    assert!(
        occupied.operational > baseline_without_proof.operational + standing_cell
            && occupied.aggregate > baseline_without_proof.aggregate + standing_cell,
        "captured pin/envelope and standing registry are charged above the proof-free base"
    );
    assert_eq!(registry_occupied(&owner), 1);

    let candidate_id = decided.vote().block_id;
    assert_eq!(decided.vote().height, 1);
    assert_eq!(
        engine.locked_qc().map(|qc| qc.view),
        Some(1),
        "the self-vote's L1 transition occurs after owner capture"
    );
    assert_eq!(
        decided.payload().meta().entrypoint(),
        EntrypointKind::Verified,
        "entrypoint provenance comes from the engine decision view"
    );
    assert_eq!(
        decided.payload().meta().candidate_id(),
        &candidate_id,
        "the envelope is bound to the engine-produced candidate"
    );
    let mut expected_binding = Sha3_256::new();
    expected_binding.update(b"QBIND-D7D14-PREPARED-PROPOSAL-BINDING-v1");
    expected_binding.update(proposal.canonical_body());
    let digest = expected_binding.finalize();
    assert_eq!(
        decided.payload().proposal_binding().as_slice(),
        digest.as_slice(),
        "the stored commitment covers the exact immutable proposal"
    );
    let retained = engine
        .state()
        .verified_justification(&candidate_id)
        .expect("the candidate retains its verified justification");
    assert!(
        std::ptr::eq(retained, evidence.as_ref()),
        "engine retained the supplied verified-evidence object"
    );
    assert!(
        retained.certificate() == evidence.certificate(),
        "retained certificate contents match the supplied evidence (redacted)"
    );
    let identities = owner
        .backend_for_test()
        .prepared_registry_for_test()
        .expect("capture installed registry")
        .lock()
        .unwrap()
        .occupied_identities_for_test();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].lock_view, 0, "captured generation remains L0");
    assert_eq!(identities[0].lock_block_id, l0_block);
    drop(decided);
    let after_drop = ledger_snapshot(&owner);
    assert_eq!(registry_occupied(&owner), 0, "dropping the envelope releases its pin");
    assert_eq!(
        after_drop.operational,
        baseline_without_proof.operational + standing_cell,
        "proof-to-pin conversion and envelope destruction leave only the standing registry charge"
    );
    assert_eq!(
        after_drop.aggregate,
        baseline_without_proof.aggregate + standing_cell,
        "aggregate ledger retains only the standing registry charge"
    );
    assert_eq!(
        after_drop.operational_ceiling,
        baseline_without_proof.operational_ceiling
    );
    assert_eq!(
        after_drop.aggregate_ceiling,
        baseline_without_proof.aggregate_ceiling
    );
    assert!(
        engine.state().verified_justification(&candidate_id).is_some(),
        "engine retains the admitted evidence independently of envelope lifetime"
    );
}

#[test]
fn verified_owner_route_returns_proof_on_ingest_and_owner_refusals() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut proposal, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let evidence = verified_parent_qc(l0_block, 0);
    proposal.qc = Some(evidence.certificate().clone());
    let limits = limits(&ctx);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let before = fingerprint(&proof);
    let ledger_before = ledger_snapshot(&owner);
    let mut missing_qc_proposal = proposal.clone();
    missing_qc_proposal.qc = None;
    let outcome = owner.decide_verified_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &missing_qc_proposal,
        std::sync::Arc::clone(&evidence),
        &limits,
        1,
        proof,
    );
    let ledger_after = ledger_snapshot(&owner);
    assert_eq!(ledger_after, ledger_before, "ingest refusal restores both ledgers and ceilings");
    let returned = match outcome {
        OwnedDecisionOutcome::Refused {
            proof,
            reason: OwnedCaptureRefusal::VerifiedIngest(
                qbind_consensus::VerifiedProposalIngestError::MissingEmbeddedQc,
            ),
        } => proof,
        _ => panic!("missing embedded QC should be a typed ingest refusal"),
    };
    assert_same_proof_fingerprint(&returned, &before);
    assert_eq!(engine.current_view(), 1);
    assert_eq!(engine.locked_qc().map(|qc| qc.view), Some(0));
    assert_eq!(engine.state().retained_evidence_bytes(), 0);
    drop(returned);

    // The evidence-bearing proposal reaches the decision hook, but a separately
    // published L0 restriction refuses correspondence. This is not rollback:
    // verified evidence may already have been admitted by the engine.
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine;
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let before = fingerprint(&proof);
    let ledger_before = ledger_snapshot(&owner);
    let outcome = owner.decide_verified_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &proposal,
        evidence,
        &limits,
        1,
        proof,
    );
    let ledger_after = ledger_snapshot(&owner);
    assert_eq!(
        ledger_after, ledger_before,
        "correspondence refusal restores both ledgers and ceilings"
    );
    let returned = match outcome {
        OwnedDecisionOutcome::Refused {
            proof,
            reason: OwnedCaptureRefusal::Correspondence(_),
        } => proof,
        _ => panic!("owner correspondence gate should refuse"),
    };
    assert_same_proof_fingerprint(&returned, &before);
    assert_eq!(engine.locked_qc().map(|qc| qc.view), Some(0));
    assert!(
        engine.state().retained_evidence_bytes() > 0,
        "engine evidence admission is separate from safety-store refusal"
    );
    assert_eq!(registry_occupied(&owner), 0);
}

#[test]
fn verified_owner_route_distinguishes_ordinary_rejection_and_recovers_from_pressure() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut safe_proposal, l0_block) = engine_locked_and_safe_view1();
    let safe_evidence = verified_parent_qc(l0_block, 0);
    safe_proposal.qc = Some(safe_evidence.certificate().clone());
    assert!(matches!(
        engine.on_verified_proposal_event(
            ValidatorId::new(1),
            &safe_proposal,
            std::sync::Arc::clone(&safe_evidence),
        ),
        Ok(Some(ConsensusEngineAction::BroadcastVote(_)))
    ));
    assert_eq!(engine.current_view(), 1);
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let limits = limits(&ctx);
    let baseline_without_proof = ledger_snapshot(&owner);

    // The engine has already self-voted in view 1 above. This same-view attempt
    // demonstrates the engine's ordinary already-voted rejection, not an unsafe
    // candidate evaluation.
    let mut repeated_view = make_proposal(1, [0x77u8; 32], 1);
    let repeated_evidence = verified_parent_qc([0x77u8; 32], 0);
    repeated_view.qc = Some(repeated_evidence.certificate().clone());
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let before = fingerprint(&proof);
    let baseline_with_proof = ledger_snapshot(&owner);
    let outcome = owner.decide_verified_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &repeated_view,
        repeated_evidence,
        &limits,
        1,
        proof,
    );
    let after_ordinary_rejection = ledger_snapshot(&owner);
    assert_eq!(
        after_ordinary_rejection, baseline_with_proof,
        "ordinary rejection restores both ledgers with the original proof held"
    );
    let returned = match outcome {
        OwnedDecisionOutcome::Refused {
            proof,
            reason: OwnedCaptureRefusal::OrdinaryEngineRejection,
        } => proof,
        _ => panic!("same-view already-voted attempt should refuse ordinarily"),
    };
    assert_same_proof_fingerprint(&returned, &before);
    assert_eq!(engine.locked_qc().map(|qc| qc.view), Some(1));
    assert!(engine.state().retained_evidence_bytes() > 0);

    let (mut engine, mut proposal, l0_block) = engine_locked_and_safe_view1();
    let evidence = verified_parent_qc(l0_block, 0);
    proposal.qc = Some(evidence.certificate().clone());
    let with_proof = ledger_snapshot(&owner);
    assert_eq!(with_proof, baseline_with_proof);
    let standing_cell = registry_cell_charge_bytes();
    let backend = owner.backend_for_test();
    let op_headroom =
        backend.accounting_cap().expect("operational ceiling") - backend.accounting_current();
    let agg_headroom = backend
        .accounting_aggregate_cap()
        .expect("aggregate ceiling")
        - backend.accounting_aggregate_current();
    let headroom = op_headroom.min(agg_headroom);
    let standing = backend
        .reserve_standing_for_test(headroom - 8)
        .expect("reserve pressure while leaving insufficient covering headroom");
    let starved = ledger_snapshot(&owner);
    let outcome = owner.decide_verified_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &proposal,
        std::sync::Arc::clone(&evidence),
        &limits,
        1,
        returned,
    );
    let returned = match outcome {
        OwnedDecisionOutcome::Refused {
            proof,
            reason: OwnedCaptureRefusal::Capture(CaptureRefusal::Admission(_)),
        } => proof,
        _ => panic!("expected a capture admission refusal"),
    };
    assert_same_proof_fingerprint(&returned, &before);
    let after_admission_refusal = ledger_snapshot(&owner);
    assert_eq!(after_admission_refusal, starved);
    assert_eq!(engine.locked_qc().map(|qc| qc.view), Some(0));
    assert_eq!(registry_occupied(&owner), 0);

    drop(standing);
    assert_eq!(ledger_snapshot(&owner), with_proof);
    let retry = owner.decide_verified_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &proposal,
        evidence,
        &limits,
        1,
        returned,
    );
    let decided = match retry {
        OwnedDecisionOutcome::Decided(decided) => decided,
        _ => panic!("pressure relief permits retry with the returned proof"),
    };
    let retry_occupied = ledger_snapshot(&owner);
    assert_eq!(
        retry_occupied.operational_ceiling,
        baseline_with_proof.operational_ceiling
    );
    assert_eq!(retry_occupied.aggregate_ceiling, baseline_with_proof.aggregate_ceiling);
    assert_eq!(decided.vote().height, 1);
    assert_eq!(registry_occupied(&owner), 1);
    drop(decided);
    let after_retry_drop = ledger_snapshot(&owner);
    assert_eq!(registry_occupied(&owner), 0);
    assert_eq!(
        after_retry_drop.operational,
        baseline_without_proof.operational + standing_cell
    );
    assert_eq!(
        after_retry_drop.aggregate,
        baseline_without_proof.aggregate + standing_cell
    );
    assert_eq!(
        after_retry_drop.operational_ceiling,
        baseline_without_proof.operational_ceiling
    );
    assert_eq!(
        after_retry_drop.aggregate_ceiling,
        baseline_without_proof.aggregate_ceiling
    );
}

#[test]
fn verified_owner_route_refuses_stale_revision_and_recovery_required() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut proposal, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let evidence = verified_parent_qc(l0_block, 0);
    proposal.qc = Some(evidence.certificate().clone());
    let limits = limits(&ctx);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 proof");
    let before = fingerprint(&proof);
    let ledger_before_stale = ledger_snapshot(&owner);
    let stale = owner.decide_verified_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &proposal,
        std::sync::Arc::clone(&evidence),
        &limits,
        0,
        proof,
    );
    let ledger_after_stale = ledger_snapshot(&owner);
    assert_eq!(
        ledger_after_stale, ledger_before_stale,
        "stale refusal restores both ledgers and ceilings"
    );
    let proof = match stale {
        OwnedDecisionOutcome::Refused {
            proof,
            reason:
                OwnedCaptureRefusal::Capture(CaptureRefusal::StaleRevision {
                    expected: 0,
                    found: 1,
                }),
        } => proof,
        _ => panic!("expected exact stale-revision refusal"),
    };
    assert_same_proof_fingerprint(&proof, &before);
    assert_eq!(engine.locked_qc().map(|qc| qc.view), Some(0));

    let mut next = valid_wire_qc(&ctx, [0x99u8; 32], 1);
    next.signatures.shrink_to_fit();
    let locked = make_locked_qc(&ctx, [0x99u8; 32], 1, next, None).expect("locked QC");
    owner
        .backend_for_test()
        .set_inject(qbind_node::safety_record_store::backend::InjectFault::UncertainAfterWrite);
    assert!(matches!(
        owner.publish_locked(locked, 1, None::<&FixtureCommittedHistory>),
        PublishResult::UncertainDurable
    ));
    owner
        .backend_for_test()
        .set_inject(qbind_node::safety_record_store::backend::InjectFault::None);
    assert!(owner.recovery_required());

    let ledger_before_recovery = ledger_snapshot(&owner);
    let recovery = owner.decide_verified_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &proposal,
        evidence,
        &limits,
        1,
        proof,
    );
    let ledger_after_recovery = ledger_snapshot(&owner);
    assert_eq!(
        ledger_after_recovery, ledger_before_recovery,
        "recovery-required refusal restores both ledgers and ceilings"
    );
    let returned = match recovery {
        OwnedDecisionOutcome::Refused {
            proof,
            reason: OwnedCaptureRefusal::Precheck(CaptureRefusal::RecoveryRequired),
        } => proof,
        _ => panic!("recovery-required state must block capture"),
    };
    assert_same_proof_fingerprint(&returned, &before);
    assert_eq!(engine.locked_qc().map(|qc| qc.view), Some(0));
    assert_eq!(registry_occupied(&owner), 0);
}

// ===========================================================================
// 1. Real L0 decision/capture -> same-event self-vote L1; retain original L0.
// ===========================================================================

#[test]
fn owner_route_decides_l0_captures_and_self_votes_l1() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let baseline = op_current(&owner);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);

    let decided = match outcome {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided, got {other:?}"),
    };

    // The real self-vote raised L1 AFTER the L0 decision/capture; the engine's
    // own live lock is now view 1, while the captured payload retains the L0
    // association (lock view 0) that drove the decision.
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(1),
        "self-vote raised L1"
    );
    assert_eq!(
        registry_occupied(&owner),
        1,
        "the envelope owns one live pin"
    );
    assert!(
        op_current(&owner) > baseline,
        "pin + reservations charged while owned"
    );

    // The envelope carries the engine's own unsigned self-vote (read-only).
    assert_eq!(decided.vote().height, 1);
    assert_eq!(decided.vote().signature.capacity(), 0, "unsigned self-vote");

    drop(decided);
    assert_eq!(registry_occupied(&owner), 0, "abandoning frees the slot");
}

// ===========================================================================
// 2. Engine L0 lock vs sealed-proof retained restriction mismatch -> a GATE
//    `Correspondence` refusal (produced INSIDE the fallible owning gate AFTER a
//    safe engine decision, NOT an ordinary pre-gate engine rejection), with the
//    SAME proof returned intact and no self-vote. The distinct ordinary
//    pre-gate rejection is covered separately by
//    `ordinary_engine_rejection_refuses_with_proof_and_no_self_vote`.
// ===========================================================================

#[test]
fn lock_mismatch_refuses_with_proof_returned_and_no_self_vote() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, _l0_block) = engine_locked_and_safe_view1();
    let owner = init_owner(dir.path(), &ctx);
    // Publish a DIFFERENT durable lock than the engine's L0 (block [9;32]@5).
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    let baseline = op_current(&owner);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let before = fingerprint(&proof);
    let lim = limits(&ctx);
    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);

    match outcome {
        OwnedDecisionOutcome::Refused {
            proof: returned,
            reason,
        } => {
            // This is a GATE correspondence refusal (raised inside the owning
            // gate after the engine decided safe), NOT an ordinary engine
            // rejection taken before the gate was consulted.
            assert!(
                matches!(reason, OwnedCaptureRefusal::Correspondence(_)),
                "expected a gate correspondence refusal, got {reason:?}"
            );
            // The SAME returned proof is preserved byte-for-byte (bytes, revision,
            // provenance), not a re-read substitute.
            assert_eq!(
                fingerprint(&returned),
                before,
                "the returned proof is the intact original"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    // No self-vote raised L1; the engine's live lock is still L0 (view 0).
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no self-vote on refusal"
    );
    assert_eq!(registry_occupied(&owner), 0, "no capture on refusal");
    assert_eq!(op_current(&owner), baseline, "charges returned to baseline");
}

// ===========================================================================
// 3. Projection mismatch (via the test-only mismatched-input seam) -> refusal,
//    proof returned, no capture. The engine decides on the real proposal while
//    the gate projects a substituted proposal; this is NOT a production API.
// ===========================================================================

#[test]
fn projection_mismatch_via_seam_refuses_with_proof_returned() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let baseline = op_current(&owner);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    // Gate projects a proposal whose candidate view / id disagree with the
    // engine's actual decision (height 2 vs the engine's view-1 decision).
    let mut mismatched = p1.clone();
    mismatched.header.height = 2;
    mismatched.header.round = 2;

    let outcome = owner.decide_and_capture_owned_projection_seam(
        &mut engine,
        ValidatorId::new(1),
        &p1,
        &mismatched,
        &lim,
        1,
        proof,
    );

    match outcome {
        OwnedDecisionOutcome::Refused {
            proof: _returned,
            reason,
        } => {
            assert!(
                matches!(reason, OwnedCaptureRefusal::Projection(_)),
                "expected a projection refusal, got {reason:?}"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    assert_eq!(
        registry_occupied(&owner),
        0,
        "no capture on projection refusal"
    );
    assert_eq!(op_current(&owner), baseline, "charges returned to baseline");
}

// ===========================================================================
// 4. Proof return on pre-consumption exits: owner-precheck BootstrapUnresolved
//    (no durable lock yet) returns the intact proof before the engine call.
// ===========================================================================

#[test]
fn bootstrap_unresolved_precheck_returns_proof_before_engine() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, _l0) = engine_locked_and_safe_view1();
    let owner = init_owner(dir.path(), &ctx);
    // No publish_qc: the authoritative restriction is BootstrapNoLock.
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 0, proof);
    match outcome {
        OwnedDecisionOutcome::Refused { proof: _p, reason } => {
            assert!(
                matches!(
                    reason,
                    OwnedCaptureRefusal::Precheck(CaptureRefusal::BootstrapUnresolved)
                ),
                "expected BootstrapUnresolved precheck, got {reason:?}"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    // The engine was never consulted: still at L0 view 0.
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(0));
}

// ===========================================================================
// 5. Scratch/envelope admission refusal: with headroom reduced below the
//    required charge, the route refuses WITHOUT a dependent self-vote or
//    envelope, returns the proof, restores capacity, and a subsequent attempt
//    (headroom restored) succeeds.
// ===========================================================================

#[test]
fn admission_refusal_then_admissible_retry() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let lim = limits(&ctx);

    // Read the proof FIRST (its O3 holder charge is now live), then starve the
    // remaining headroom so the route's FIRST additional reservation — the
    // covering envelope/data reservation, which the corrected route admits BEFORE
    // the transient hashing/traversal scratch — is refused, without disturbing the
    // already-held proof.
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    // Paired (operational, aggregate) baseline that DOES include the live input
    // proof's O3 holder charge but NOT the temporary pressure reservation.
    let with_proof = ledger_snapshot(&owner);
    let backend = owner.backend_for_test();
    let op_headroom =
        backend.accounting_cap().expect("operational ceiling") - backend.accounting_current();
    let agg_headroom = backend
        .accounting_aggregate_cap()
        .expect("aggregate ceiling")
        - backend.accounting_aggregate_current();
    let headroom = op_headroom.min(agg_headroom);
    // Leave only 8 bytes: far below the route's covering reservation. `standing`
    // is the temporary pressure reservation.
    let standing = backend
        .reserve_standing_for_test(headroom - 8)
        .expect("reserve standing to starve the route");
    // Paired baseline that NOW also includes the temporary pressure reservation.
    let starved = ledger_snapshot(&owner);

    // Snapshot the proof's observable identity BEFORE the call, so the SAME
    // returned proof can be shown preserved (not a fresh `read_validate`).
    let before = fingerprint(&proof);
    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
    let returned_proof = match outcome {
        OwnedDecisionOutcome::Refused { proof: p, reason } => {
            assert!(
                matches!(
                    reason,
                    OwnedCaptureRefusal::Capture(CaptureRefusal::Admission(_))
                ),
                "expected an admission refusal, got {reason:?}"
            );
            // The ACTUAL returned proof is byte-, revision- and provenance-identical
            // to the pre-call snapshot: the refusal preserved the input proof.
            assert_eq!(
                fingerprint(&p),
                before,
                "the returned proof is preserved unchanged across the refusal"
            );
            p
        }
        other => panic!("expected admission Refused, got {other:?}"),
    };
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no dependent self-vote"
    );
    assert_eq!(
        registry_occupied(&owner),
        0,
        "no envelope/pin on admission refusal"
    );
    // BOTH ledgers restore EXACTLY to the proof+pressure baseline with the returned
    // proof still live: the covering reservation and every transient were released.
    assert_eq!(
        ledger_snapshot(&owner),
        starved,
        "operational AND aggregate charges restored to the proof+pressure baseline"
    );

    // Remove the temporary pressure and confirm its charge leaves BOTH ledgers
    // WITHOUT discarding the returned proof: the ledgers return to the proof-held
    // (pressure-free) baseline. Then retry with the SAME returned proof (NOT a
    // fresh read): proof preservation enables reuse once the pressure is gone.
    drop(standing);
    assert_eq!(
        ledger_snapshot(&owner),
        with_proof,
        "temporary pressure removed from BOTH ledgers; the returned proof remains held"
    );
    let retry = owner.decide_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &p1,
        &lim,
        1,
        returned_proof,
    );
    let decided = match retry {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected admissible retry to Decide, got {other:?}"),
    };
    assert_eq!(decided.vote().height, 1);
    assert_eq!(registry_occupied(&owner), 1, "retry captured one pin");
    drop(decided);
}

// ===========================================================================
// 6. Ordinary pins and envelopes share the SAME existing two-slot population:
//    an ordinary capture + an owner-route envelope fill both slots; a third
//    refuses RegistryFull with the proof intact.
// ===========================================================================

#[test]
fn envelope_shares_the_two_existing_prepared_slots() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let lim = limits(&ctx);

    // Slot 1: an ordinary capture.
    let proof_a = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let _ordinary = owner
        .capture_prepared_decision(proof_a, 1)
        .expect("ordinary capture takes slot 1");
    assert_eq!(registry_occupied(&owner), 1);

    // Slot 2: an owner-route envelope.
    let proof_b = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let _decided = match owner.decide_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &p1,
        &lim,
        1,
        proof_b,
    ) {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided, got {other:?}"),
    };
    assert_eq!(registry_occupied(&owner), 2, "both existing slots occupied");

    // A third capture refuses RegistryFull, proof intact — no new multiplicity.
    let proof_c = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    match owner.capture_prepared_decision(proof_c, 1) {
        Err((_proof, CaptureRefusal::RegistryFull)) => {}
        other => panic!("expected RegistryFull with proof returned, got {other:?}"),
    }
    assert_eq!(registry_occupied(&owner), 2, "refusal consumed no slot");
}

// ===========================================================================
// 7. Complete outgoing Vote parity: all ten fields match the engine's own
//    ungated self-vote, and the carried signature has zero capacity.
// ===========================================================================

#[test]
fn outgoing_vote_parity_all_ten_fields_and_zero_signature_capacity() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();

    // Reference engine (ungated) produces the canonical self-vote.
    let (mut ref_engine, ref_p1, _l0_ref) = engine_locked_and_safe_view1();
    let ref_action = ref_engine.on_proposal_event(ValidatorId::new(1), &ref_p1);
    let ref_vote = match ref_action {
        Some(ConsensusEngineAction::BroadcastVote(v)) => v,
        other => panic!("reference engine must self-vote, got {other:?}"),
    };

    // Owner-route engine produces the SAME self-vote inside the envelope.
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);
    let decided =
        match owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof)
        {
            OwnedDecisionOutcome::Decided(dv) => dv,
            other => panic!("expected Decided, got {other:?}"),
        };
    let got = decided.vote();

    assert_eq!(got.version, ref_vote.version, "field 1: version");
    assert_eq!(got.chain_id, ref_vote.chain_id, "field 2: chain_id");
    assert_eq!(got.epoch, ref_vote.epoch, "field 3: epoch");
    assert_eq!(got.height, ref_vote.height, "field 4: height");
    assert_eq!(got.round, ref_vote.round, "field 5: round");
    assert_eq!(got.step, ref_vote.step, "field 6: step");
    assert_eq!(got.block_id, ref_vote.block_id, "field 7: block_id");
    assert_eq!(
        got.validator_index, ref_vote.validator_index,
        "field 8: validator_index"
    );
    assert_eq!(got.suite_id, ref_vote.suite_id, "field 9: suite_id");
    assert_eq!(
        got.signature, ref_vote.signature,
        "field 10: signature bytes"
    );
    assert_eq!(
        got.signature.capacity(),
        0,
        "unsigned: zero signature capacity"
    );
}

// ===========================================================================
// 8. §3 — Successful-envelope abandonment: exact operational AND aggregate
//    restoration, the intentionally retained standing registry cell, and final
//    teardown to zero observed through an INDEPENDENT accounting handle after
//    every owner, proof, envelope, pin, backend and registry inspector handle
//    has been released.
//
//    Baselines are MEASURED through the existing authoritative accounting seams
//    (not magic constants); the one standing charge that intentionally survives
//    abandonment — the lazily installed registry cell — is identified by the
//    existing `registry_cell_charge_bytes()` helper. Reservation counters are
//    NOT interpreted as object-lifetime measurements: the final teardown-to-zero
//    is observed only AFTER the live objects (proof, envelope, pin, registry)
//    have actually been dropped, through an accounting handle that is itself not
//    one of those objects.
// ===========================================================================

#[test]
fn abandonment_restores_baseline_leaving_only_standing_registry() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);

    // Operational AND aggregate baselines with NO input proof held yet. This is
    // the baseline that does NOT include the still-live input proof.
    let op_base = op_current(&owner);
    let agg_base = agg_current(&owner);

    // An INDEPENDENT accounting handle, taken now, that shares the same underlying
    // ledger but is NOT the owner/backend/proof/envelope it observes — so it can
    // report the final charge AFTER all of those have been dropped. (The observer
    // must not retain the objects whose destruction it is meant to observe.)
    let independent = owner.backend_for_test().accounting_handle_for_test();

    // Read the input proof: its O3 holder charge is now live. This establishes the
    // SEPARATE baseline that DOES include the still-live input proof.
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let op_with_proof = op_current(&owner);
    let agg_with_proof = agg_current(&owner);
    assert!(
        op_with_proof > op_base,
        "the live input proof adds an operational holder charge"
    );
    assert!(
        agg_with_proof > agg_base,
        "the live input proof is admitted against the aggregate authority too"
    );

    let lim = limits(&ctx);
    let decided =
        match owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof)
        {
            OwnedDecisionOutcome::Decided(dv) => dv,
            other => panic!("expected Decided, got {other:?}"),
        };
    // On SUCCESS the input proof is CONSUMED into the envelope's retained
    // generation (it is not returned); `op_with_proof` was the baseline that
    // included the still-live input proof, and it no longer applies once the proof
    // has been moved into the capture.
    let occupied_op = op_current(&owner);
    let occupied_agg = agg_current(&owner);
    assert!(
        occupied_op > op_base,
        "pin + envelope + retained generation charged above the empty baseline"
    );
    assert_eq!(registry_occupied(&owner), 1, "one occupied registry slot");

    // Abandonment: the covered objects (envelope, pin, retained generation derived
    // from the consumed proof) are destroyed before their covering reservations
    // release; the lazily installed registry CELL persists as a standing charge
    // (its slot is now free, but the cell itself is retained).
    let standing_cell = registry_cell_charge_bytes();
    drop(decided);
    let after_op = op_current(&owner);
    let after_agg = agg_current(&owner);
    assert_eq!(registry_occupied(&owner), 0, "the occupied slot is freed");
    assert_eq!(
        after_op,
        op_base + standing_cell,
        "operational charge restored EXACTLY to the empty baseline plus the one \
         intentionally retained standing registry cell (the consumed proof's \
         generation was destroyed with the envelope)"
    );
    assert_eq!(
        after_agg,
        agg_base + standing_cell,
        "aggregate charge restored EXACTLY to the empty baseline plus the one \
         standing registry cell"
    );
    assert!(
        after_op < occupied_op && after_agg < occupied_agg,
        "pin + envelope + scratch + retained generation released on abandonment"
    );

    // Final teardown to ZERO, observed through the independent handle AFTER the
    // owner (hence its backend, the installed registry and every reservation) has
    // been dropped. `op_base`/`agg_base` here are the O1 initialization charges,
    // which the backend owns and releases on drop, so the independent ledger goes
    // fully to zero.
    drop(engine);
    drop(owner);
    assert_eq!(
        independent.current(),
        0,
        "operational ledger torn down to zero after every owner/backend/registry \
         handle released"
    );
    assert_eq!(
        independent.aggregate().current(),
        0,
        "aggregate ledger torn down to zero after full teardown"
    );
}

// ===========================================================================
// 9. Required-ancestry not-applicable branch: a ViewSufficiency decision records
//    the not-applicable ancestry without a walk and still captures.
// ===========================================================================

#[test]
fn view_sufficiency_records_not_applicable_ancestry() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    // engine_locked_and_safe_view1 yields a ViewSufficiency decision (justify
    // view 0 >= locked view 0): no ancestry walk is required.
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);
    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
    assert!(
        matches!(outcome, OwnedDecisionOutcome::Decided(_)),
        "ViewSufficiency captures with not-applicable ancestry"
    );
    assert_eq!(registry_occupied(&owner), 1);
}

// ===========================================================================
// 10. Serialization: independently exercise legacy and verified owner entrypoints.
//     An observer against the SAME domain sees `WouldBlock` while paused at the
//     existing capture-interval hook under the guard, then `Acquired` after release.
//     Bounded coordination (channels), no timing sleeps.
// ===========================================================================

#[test]
fn legacy_owner_route_holds_domain_until_release_observed_as_would_block() {
    exercise_owner_route_domain_serialization(false);
}

#[test]
fn verified_owner_route_holds_domain_until_release_observed_as_would_block() {
    exercise_owner_route_domain_serialization(true);
}

fn exercise_owner_route_domain_serialization(verified: bool) {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let evidence = verified.then(|| verified_parent_qc(l0_block, 0));
    if let Some(evidence) = evidence.as_ref() {
        p1.qc = Some(evidence.certificate().clone());
    }
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    // Bounded two-way handshake with EXPLICITLY recorded legs (§3): the hook
    // signals "paused, guard held" and waits for release; the observer waits for
    // that entry signal, classifies the same-domain non-blocking acquisition, then
    // ALWAYS acknowledges release. A timeout, disconnect, missed entry, or failed
    // signalling is RECORDED (not silently accepted) and fails the test below, so a
    // coordination failure can never masquerade as successful serialization.
    let (owner_coord, observer_coord, legs) = make_handshake();
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None::<DomainObservation>));
    let observed_obs = std::sync::Arc::clone(&observed);

    std::thread::scope(|scope| {
        let obs = &owner;
        let observer = scope.spawn(move || {
            // Only classify after a SUCCESSFUL bounded entry handshake: no
            // observation made after a failed handshake is credited as evidence.
            if observer_coord.await_entry() {
                *observed_obs.lock().unwrap() =
                    Some(classify_try_lock(obs.backend_for_test().try_lock_domain_for_test()));
            }
            // ALWAYS acknowledge release so the owner's bounded wait completes,
            // even if we observed nothing (recorded as a handshake failure).
            observer_coord.ack_release();
        });

        // Owner thread: install the one-shot pause hook, then run the route. The
        // hook never panics (so a failed hand-off cannot poison the held domain
        // guard) and waits only under the bounded timeout.
        set_capture_interval_hook(move || owner_coord.signal_entry_and_await_release());
        let outcome = if let Some(evidence) = evidence {
            owner.decide_verified_and_capture_owned(
                &mut engine,
                ValidatorId::new(1),
                &p1,
                evidence,
                &lim,
                1,
                proof,
            )
        } else {
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof)
        };
        clear_capture_interval_hook();

        observer.join().expect("observer thread");

        // Assertions OUTSIDE the hook critical section: a failure here cannot leave
        // a thread waiting or poison the domain. Require SUCCESSFUL coordination on
        // every leg BEFORE crediting the observation.
        let final_legs = *legs.lock().unwrap();
        assert!(
            final_legs.fully_completed(),
            "the bounded entry/release handshake completed on both sides \
             (no timeout, disconnect, or dropped endpoint): {final_legs:?}"
        );
        assert_eq!(
            *observed.lock().unwrap(),
            Some(DomainObservation::WouldBlock),
            "same-domain acquisition observed contention (not poisoning) while the \
             owner held the guard at set_capture_interval_hook"
        );
        assert!(
            matches!(outcome, OwnedDecisionOutcome::Decided(_)),
            "route completes after release"
        );

        // The capture committed under the guard: the envelope (still alive here)
        // owns one live pin.
        assert_eq!(
            registry_occupied(&owner),
            1,
            "the capture committed under the guard"
        );

        // After normal release, a late acquisition now succeeds (publication can
        // make progress); restore it immediately, byte-identically.
        match owner.backend_for_test().try_lock_domain_for_test() {
            TryLockDomainOutcome::Acquired(_g) => {}
            other => panic!("expected Acquired after release, got {other:?}"),
        }
    });
}

// ===========================================================================
// 11. §2 — Bind the effective input policy to the owner's pinned context. A
//     policy constructed for a LARGER validator set carries a relaxed
//     QC-signature-count cap; the owner route must refuse it (typed,
//     allocation-free) BEFORE the engine decision, so no dependent self-vote
//     occurs. The correctly bounded owner-derived policy is then accepted.
// ===========================================================================

#[test]
fn owner_route_rejects_policy_built_for_larger_validator_set() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    // Proof-free paired (operational, aggregate) baseline.
    let baseline = ledger_snapshot(&owner);

    // N=8 policy relaxes the QC-signature-count cap to 8; the owner's pinned N=4
    // caps it at 4. The larger policy must not be admitted by the owner route.
    let larger = limits(&ctx_n(8));
    assert_eq!(larger.max_qc_sig_count(), 8, "larger policy admits 8 signatures");
    assert_eq!(limits(&ctx).max_qc_sig_count(), 4, "owner-derived caps at 4");

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let before = fingerprint(&proof);
    // Paired baseline with ONLY the live input proof held; the refusal returns this
    // same proof, so the post-refusal charge is exactly this (nothing else is
    // retained), distinct from the proof-free `baseline`. No temporary pressure.
    let with_proof = ledger_snapshot(&owner);
    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &larger, 1, proof);
    let returned_proof = match outcome {
        OwnedDecisionOutcome::Refused { proof: p, reason } => {
            assert!(
                matches!(reason, OwnedCaptureRefusal::EffectivePolicyMismatch),
                "expected EffectivePolicyMismatch, got {reason:?}"
            );
            assert_eq!(
                fingerprint(&p),
                before,
                "the returned proof is preserved unchanged across the policy refusal"
            );
            p
        }
        other => panic!("expected Refused, got {other:?}"),
    };
    // The larger policy's four-plus-signature cap was never exercised: the engine
    // was never consulted (still L0 view 0), so no dependent self-vote occurred.
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no self-vote on policy refusal"
    );
    assert_eq!(registry_occupied(&owner), 0, "no capture on policy refusal");
    // BOTH ledgers restored to the proof-held baseline (the returned proof remains
    // live, nothing else retained), and that baseline sits above the proof-free one.
    assert_eq!(
        ledger_snapshot(&owner),
        with_proof,
        "operational AND aggregate charges restored to the proof-held baseline (only the returned proof remains)"
    );
    assert!(
        with_proof.operational > baseline.operational
            && with_proof.aggregate > baseline.aggregate,
        "the proof-held baseline sits above the proof-free baseline on BOTH ledgers"
    );

    // Correct the input (supply the correctly bounded owner-derived N=4 policy) and
    // retry with the SAME returned proof — NOT a fresh read.
    let lim = limits(&ctx);
    let decided = match owner.decide_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &p1,
        &lim,
        1,
        returned_proof,
    ) {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided with owner-derived policy, got {other:?}"),
    };
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(1), "self-vote on accept");
    assert_eq!(registry_occupied(&owner), 1);
    drop(decided);
}

// ===========================================================================
// 12. §4 — The header-to-originating-proposer projection check. The engine
//     derives the candidate id from the originating `from`, not from
//     `header.proposer_index`, so changing ONLY the header's proposer identity
//     must be caught by the projection check (not the candidate-id check), with
//     the proof returned intact and no dependent self-vote. The matching header
//     succeeds.
// ===========================================================================

#[test]
fn header_proposer_index_mismatch_refuses_projection() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    // Proof-free paired (operational, aggregate) baseline.
    let baseline = ledger_snapshot(&owner);
    let lim = limits(&ctx);

    // Change ONLY the header's proposer identity (2 != originating proposer 1).
    let mut mismatched = p1.clone();
    mismatched.header.proposer_index = 2;

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let before = fingerprint(&proof);
    // Paired baseline with ONLY the live input proof held; the refusal returns this
    // same proof, so the post-refusal charge is exactly this. No temporary pressure.
    let with_proof = ledger_snapshot(&owner);
    let outcome = owner.decide_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &mismatched,
        &lim,
        1,
        proof,
    );
    let returned_proof = match outcome {
        OwnedDecisionOutcome::Refused { proof: p, reason } => {
            assert!(
                matches!(
                    reason,
                    OwnedCaptureRefusal::Projection(ProjectionMismatch::Proposer)
                ),
                "expected Projection(Proposer), got {reason:?}"
            );
            assert_eq!(
                fingerprint(&p),
                before,
                "the returned proof is preserved unchanged across the projection refusal"
            );
            p
        }
        other => panic!("expected Refused, got {other:?}"),
    };
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no dependent self-vote on projection refusal"
    );
    assert_eq!(registry_occupied(&owner), 0, "no capture on projection refusal");
    // BOTH ledgers restored to the proof-held baseline (returned proof still live),
    // which sits above the proof-free baseline.
    assert_eq!(
        ledger_snapshot(&owner),
        with_proof,
        "operational AND aggregate charges restored to the proof-held baseline (only the returned proof remains)"
    );
    assert!(
        with_proof.operational > baseline.operational
            && with_proof.aggregate > baseline.aggregate,
        "the proof-held baseline sits above the proof-free baseline on BOTH ledgers"
    );

    // Correct the input (the matching header, proposer_index == originating
    // proposer 1) and retry with the SAME returned proof on the still-unvoted
    // engine — NOT a fresh read.
    let decided = match owner.decide_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &p1,
        &lim,
        1,
        returned_proof,
    ) {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided for matching header, got {other:?}"),
    };
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(1), "self-vote on accept");
    drop(decided);
}

// ===========================================================================
// 13. §3 — Admission-before-construction: the additional `covering` (envelope/
//     data) reservation is admitted BEFORE the binding values it covers. A
//     discriminating observation reads the accounting occupancy at the binding
//     phase (an observer thread, while the owner is paused holding the guard) and
//     confirms the occupancy already includes BOTH `covering` and `scratch` — the
//     reservation overlap that only holds when `covering` was admitted first. The
//     reviewed order (covering admitted AFTER the bindings) would show only
//     `scratch` at this phase.
// ===========================================================================

#[test]
fn binding_phase_reservation_overlaps_covering() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    // Occupancy with the proof held, before the route runs (the registry is still
    // unallocated and is only created during capture, AFTER this binding phase).
    let before = op_current(&owner);
    let covering = covering_charge_for_test().expect("covering charge");
    let scratch = scratch_charge_for_test();

    // Bounded two-way handshake with EXPLICITLY recorded legs (§3): the observer
    // records the live accounting occupancy only after a SUCCESSFUL entry
    // handshake, then ALWAYS acknowledges release. A coordination failure is
    // recorded and fails the test below rather than being silently accepted.
    let (owner_coord, observer_coord, legs) = make_handshake();
    let snapshot = std::sync::Arc::new(std::sync::Mutex::new(None::<u128>));
    let snapshot_obs = std::sync::Arc::clone(&snapshot);

    std::thread::scope(|scope| {
        let obs = &owner;
        let observer = scope.spawn(move || {
            if observer_coord.await_entry() {
                // Accounting is a SEPARATE mutex from the serialization domain, so
                // this read does not contend with the held domain guard.
                let occ = obs.backend_for_test().accounting_current();
                *snapshot_obs.lock().unwrap() = Some(occ);
            }
            observer_coord.ack_release();
        });

        set_binding_phase_hook(move || owner_coord.signal_entry_and_await_release());
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        clear_binding_phase_hook();
        observer.join().expect("observer thread");

        // Require SUCCESSFUL coordination before crediting the occupancy snapshot.
        let final_legs = *legs.lock().unwrap();
        assert!(
            final_legs.fully_completed(),
            "the bounded binding-phase handshake completed on both sides: {final_legs:?}"
        );
        assert!(
            matches!(outcome, OwnedDecisionOutcome::Decided(_)),
            "route completes after the binding-phase observation"
        );
    });

    let occ = snapshot.lock().unwrap().expect("binding-phase occupancy recorded");
    assert_eq!(
        occ,
        before + covering + scratch,
        "covering and scratch overlap at the binding phase: covering was admitted \
         BEFORE the covered binding values (the corrected admission order)"
    );
}

// ===========================================================================
// 14. §3 — Continuous coverage on every refusal: the envelope (covering)
//     admission refusal, the scratch admission refusal, and the capture refusal
//     each destroy the covered objects before releasing their covering
//     reservations, returning the proof intact and the charges exactly to the
//     starved baseline, with no dependent self-vote.
// ===========================================================================

#[test]
fn covering_scratch_and_capture_refusals_restore_baseline() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let lim = limits(&ctx);
    let covering = covering_charge_for_test().expect("covering charge");

    // --- envelope (covering) admission refusal: leave < covering ------------
    {
        let proof = owner
            .read_validate(None::<&FixtureCommittedHistory>)
            .unwrap();
        // Proof-held, pressure-free paired (operational, aggregate) baseline.
        let with_proof = ledger_snapshot(&owner);
        let backend = owner.backend_for_test();
        let op_headroom =
            backend.accounting_cap().expect("op ceiling") - backend.accounting_current();
        let agg_headroom = backend
            .accounting_aggregate_cap()
            .expect("agg ceiling")
            - backend.accounting_aggregate_current();
        let headroom = op_headroom.min(agg_headroom);
        // Leave covering-1 bytes: the FIRST reservation (covering) is refused.
        // `standing` is the temporary pressure reservation.
        let standing = backend
            .reserve_standing_for_test(headroom - (covering - 1))
            .expect("starve below covering");
        // Paired baseline that NOW also includes the temporary pressure.
        let starved = ledger_snapshot(&owner);
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        let returned = match outcome {
            OwnedDecisionOutcome::Refused {
                proof: p,
                reason: OwnedCaptureRefusal::Capture(CaptureRefusal::Admission(_)),
            } => p,
            other => panic!("expected a covering admission refusal, got {other:?}"),
        };
        assert_eq!(engine.locked_qc().map(|q| q.view), Some(0), "no self-vote");
        assert_eq!(registry_occupied(&owner), 0);
        // Both ledgers restored to the proof+pressure baseline with the returned
        // proof still held: covering was released before its covered objects leaked.
        assert_eq!(
            ledger_snapshot(&owner),
            starved,
            "covering released; operational AND aggregate restored to the proof+pressure baseline"
        );
        // Releasing the temporary pressure removes its charge from BOTH ledgers
        // without discarding the returned proof.
        drop(standing);
        assert_eq!(
            ledger_snapshot(&owner),
            with_proof,
            "temporary pressure removed from BOTH ledgers; the returned proof is retained"
        );
        drop(returned);
    }

    // --- scratch admission refusal: leave exactly covering ------------------
    {
        let proof = owner
            .read_validate(None::<&FixtureCommittedHistory>)
            .unwrap();
        // Proof-held, pressure-free paired baseline.
        let with_proof = ledger_snapshot(&owner);
        let backend = owner.backend_for_test();
        let op_headroom =
            backend.accounting_cap().expect("op ceiling") - backend.accounting_current();
        let agg_headroom = backend
            .accounting_aggregate_cap()
            .expect("agg ceiling")
            - backend.accounting_aggregate_current();
        let headroom = op_headroom.min(agg_headroom);
        // Leave exactly covering bytes: covering succeeds, then scratch is refused.
        // `standing` is the temporary pressure reservation.
        let standing = backend
            .reserve_standing_for_test(headroom - covering)
            .expect("starve to exactly covering");
        // Paired baseline that NOW also includes the temporary pressure.
        let starved = ledger_snapshot(&owner);
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        let returned = match outcome {
            OwnedDecisionOutcome::Refused {
                proof: p,
                reason: OwnedCaptureRefusal::Capture(CaptureRefusal::Admission(_)),
            } => p,
            other => panic!("expected a scratch admission refusal, got {other:?}"),
        };
        assert_eq!(engine.locked_qc().map(|q| q.view), Some(0), "no self-vote");
        assert_eq!(registry_occupied(&owner), 0);
        // Both ledgers restored to the proof+pressure baseline (covering + scratch
        // released) with the returned proof still held.
        assert_eq!(
            ledger_snapshot(&owner),
            starved,
            "covering + scratch released; operational AND aggregate restored to the proof+pressure baseline"
        );
        // Releasing the temporary pressure removes its charge from BOTH ledgers
        // without discarding the returned proof.
        drop(standing);
        assert_eq!(
            ledger_snapshot(&owner),
            with_proof,
            "temporary pressure removed from BOTH ledgers; the returned proof is retained"
        );
        drop(returned);
    }

    // --- capture refusal (stale expected revision): covering + scratch admitted,
    //     bindings computed, then the capture conversion refuses; covered objects
    //     destroyed before the reservations release ----------------------------
    {
        let proof = owner
            .read_validate(None::<&FixtureCommittedHistory>)
            .unwrap();
        // Proof-held paired baseline (no temporary pressure in this sub-case).
        let baseline = ledger_snapshot(&owner);
        // expected revision 2 disagrees with the current authoritative revision 1.
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 2, proof);
        let returned = match outcome {
            OwnedDecisionOutcome::Refused {
                proof: p,
                reason: OwnedCaptureRefusal::Capture(CaptureRefusal::StaleRevision { .. }),
            } => p,
            other => panic!("expected a stale-revision capture refusal, got {other:?}"),
        };
        assert_eq!(engine.locked_qc().map(|q| q.view), Some(0), "no self-vote");
        assert_eq!(registry_occupied(&owner), 0);
        // Covering + scratch released; both ledgers restored to the proof-held
        // baseline with the returned proof still live.
        assert_eq!(
            ledger_snapshot(&owner),
            baseline,
            "covering + scratch released on capture refusal; operational AND aggregate restored (returned proof held)"
        );
        drop(returned);
    }
}

// ===========================================================================
// 15. §5 — The pre-ingestion serialization observation point. A competing,
//     non-blocking same-domain acquisition observes `WouldBlock` (contention,
//     not poisoning) at the fixed semantic boundary immediately BEFORE the owner
//     invokes the engine ingestion, establishing that the owner held the one
//     serialization domain before ingestion. After normal release the route
//     completes and an actual eligible publication succeeds (publication
//     completion, not mere lock availability).
// ===========================================================================

#[test]
fn pre_ingestion_hook_observes_would_block_before_ingestion() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    // Bounded two-way handshake with EXPLICITLY recorded legs (§3): the hook fires
    // strictly BEFORE the engine call, signals its pause, and waits for release;
    // the observer waits for that entry, classifies the same-domain non-blocking
    // acquisition, then ALWAYS acknowledges release. A timeout, disconnect, missed
    // entry, or failed signalling is RECORDED and fails the test, so no observation
    // after a failed handshake is credited as the paused pre-ingestion phase.
    let (owner_coord, observer_coord, legs) = make_handshake();
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None::<DomainObservation>));
    let observed_obs = std::sync::Arc::clone(&observed);

    std::thread::scope(|scope| {
        let obs = &owner;
        let observer = scope.spawn(move || {
            if observer_coord.await_entry() {
                // Same-domain non-blocking acquisition: contention, not poisoning.
                // Classified without retaining any acquired guard.
                *observed_obs.lock().unwrap() =
                    Some(classify_try_lock(obs.backend_for_test().try_lock_domain_for_test()));
            }
            observer_coord.ack_release();
        });

        // Install the pre-ingestion hook (fires strictly BEFORE the engine call).
        // It never panics and waits only under the bounded timeout.
        set_pre_ingestion_hook(move || owner_coord.signal_entry_and_await_release());
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        clear_pre_ingestion_hook();
        observer.join().expect("observer thread");

        // Require SUCCESSFUL coordination before crediting the observation, OUTSIDE
        // the hook critical section.
        let final_legs = *legs.lock().unwrap();
        assert!(
            final_legs.fully_completed(),
            "the bounded pre-ingestion handshake completed on both sides \
             (no timeout, disconnect, or dropped endpoint): {final_legs:?}"
        );
        assert_eq!(
            *observed.lock().unwrap(),
            Some(DomainObservation::WouldBlock),
            "same-domain acquisition observed contention (not poisoning) before ingestion"
        );
        let decided = match outcome {
            OwnedDecisionOutcome::Decided(dv) => dv,
            other => panic!("route completes after release, got {other:?}"),
        };

        // The self-vote ran AFTER the pre-ingestion point, raising L1.
        assert_eq!(engine.locked_qc().map(|q| q.view), Some(1), "ingestion ran after release");
        drop(decided);
    });

    // After the route released the domain, perform an ACTUAL eligible publication
    // (not merely a successful try_lock) and assert it completes, advancing the
    // authoritative revision from 1 to 2.
    let new_rev = publish_qc(&owner, &ctx, [0x5Au8; 32], 2, 1);
    assert_eq!(new_rev, 2, "publication completed after normal release");
}

// ===========================================================================
// 15b. §3 — Negative control for the coordination-validation path. Using an
//      ACTUAL channel failure (the observer receives the entry signal and then
//      drops its endpoints WITHOUT acknowledging release, so the owner's bounded
//      release wait returns `Disconnected` immediately — no synchronization sleep
//      and no timing-dependent success), the SAME handshake validation rejects the
//      failed handshake: the release-acknowledgement leg is recorded as a failure,
//      `fully_completed()` is false, and no observation is credited as the paused
//      phase. The route itself still completes normally, proving the rejection is
//      the coordination check and not a route failure.
// ===========================================================================

#[test]
fn failed_handshake_is_not_credited_as_coordination() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    let (owner_coord, observer_coord, legs) = make_handshake();
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None::<DomainObservation>));
    let observed_obs = std::sync::Arc::clone(&observed);

    std::thread::scope(|scope| {
        let obs = &owner;
        let observer = scope.spawn(move || {
            if observer_coord.await_entry() {
                *observed_obs.lock().unwrap() =
                    Some(classify_try_lock(obs.backend_for_test().try_lock_domain_for_test()));
            }
            // Deliberately DO NOT acknowledge release: drop the endpoints instead.
            // This disconnects the owner's release channel, so its bounded wait
            // returns `Disconnected` at once (actual channel failure, no sleep).
            drop(observer_coord);
        });

        set_pre_ingestion_hook(move || owner_coord.signal_entry_and_await_release());
        let outcome =
            owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof);
        clear_pre_ingestion_hook();
        observer.join().expect("observer thread");

        // The SAME validation path rejects the failed handshake: the entry leg may
        // have signalled, but the release acknowledgement never arrived, so the
        // handshake is NOT fully completed and the observation is not credited.
        let final_legs = *legs.lock().unwrap();
        assert!(
            !final_legs.fully_completed(),
            "a disconnected release handshake is rejected, not credited: {final_legs:?}"
        );
        assert_eq!(
            final_legs.owner_release_received,
            Some(false),
            "the owner recorded the release wait as a FAILURE (disconnect), not success"
        );
        assert_eq!(
            final_legs.observer_release_acked, None,
            "the observer never acknowledged release"
        );

        // The route itself still completes normally: the rejection came from the
        // coordination check, not from the owner route.
        assert!(
            matches!(outcome, OwnedDecisionOutcome::Decided(_)),
            "the owner route still completes despite the failed handshake"
        );
    });
}

// ===========================================================================
// 16. §6 Retained L0 — after the real self-vote raises the engine to L1, the
//     ACTUAL captured generation identity still carries the L0 lock (view 0,
//     block = the engine's L0 lock), established by inspecting the retained
//     generation's provenance, not by registry occupancy alone.
// ===========================================================================

#[test]
fn captured_generation_retains_l0_provenance_after_self_vote_l1() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, p1, l0_block) = engine_locked_and_safe_view1();
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let lim = limits(&ctx);

    let decided = match owner
        .decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p1, &lim, 1, proof)
    {
        OwnedDecisionOutcome::Decided(dv) => dv,
        other => panic!("expected Decided, got {other:?}"),
    };
    // The engine's own live lock advanced to L1 via the self-vote.
    assert_eq!(engine.locked_qc().map(|q| q.view), Some(1), "self-vote raised L1");

    // The captured generation's provenance is still L0: inspect the actual
    // retained identity (not merely the occupancy count).
    let reg = owner
        .backend_for_test()
        .prepared_registry_for_test()
        .expect("registry allocated by the capture");
    let identities = reg.lock().unwrap().occupied_identities_for_test();
    assert_eq!(identities.len(), 1, "exactly one captured generation");
    assert_eq!(
        identities[0].lock_view, 0,
        "captured generation retains the L0 lock view despite the engine at L1"
    );
    assert_eq!(
        identities[0].lock_block_id, l0_block,
        "captured generation retains the L0 lock block id"
    );

    drop(decided);
    assert_eq!(registry_occupied(&owner), 0, "abandoning frees the slot");
}
// ===========================================================================
// 17. §4 — Owner-route OrdinaryEngineRejection: `engine_locked_and_safe_view1`
//     first processes the view-0 proposal and establishes L0, then calls
//     `advance_view()` (which clears `voted_in_view`) and returns a safe view-1
//     proposal without ingesting it. This test discards that proposal and submits
//     a view-1 proposal with no justification QC and an unregistered conflicting
//     parent; the engine rejects it during unsafe-candidate evaluation before the
//     owner gate. The owner/proof is otherwise admissible (durable lock matches
//     L0, policy derived from pinned context). The SAME proof is returned intact,
//     no dependent self-vote or capture occurs, and the charges return exactly to
//     baseline. This differs from the already-voted refusal in
//     `verified_owner_route_distinguishes_ordinary_rejection_and_recovers_from_pressure`
//     and from the gate `Correspondence` refusal in
//     `lock_mismatch_refuses_with_proof_returned_and_no_self_vote`.
// ===========================================================================

#[test]
fn ordinary_engine_rejection_refuses_with_proof_and_no_self_vote() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    // The helper only ingests the view-0 proposal. It establishes L0, advances to
    // view 1 (clearing `voted_in_view`), and returns an un-ingested safe view-1
    // proposal. This test discards that proposal.
    let (mut engine, _safe_p1, l0_block) = engine_locked_and_safe_view1();
    // No justify QC and an unregistered conflicting parent reach unsafe-candidate
    // evaluation, which rejects before the gate. The owner/proof is independently
    // admissible: the durable lock matches L0 and policy is owner-derived.
    let repeated_view = make_proposal(1, [0x77u8; 32], 1);
    let owner = owner_with_matching_proof(dir.path(), &ctx, l0_block);
    // Proof-free paired (operational, aggregate) baseline.
    let baseline = ledger_snapshot(&owner);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let before = fingerprint(&proof);
    // Paired baseline with ONLY the live input proof held. No temporary pressure.
    let with_proof = ledger_snapshot(&owner);
    let lim = limits(&ctx);

    let outcome = owner.decide_and_capture_owned(
        &mut engine,
        ValidatorId::new(1),
        &repeated_view,
        &lim,
        1,
        proof,
    );
    let returned_proof = match outcome {
        OwnedDecisionOutcome::Refused {
            proof: returned,
            reason,
        } => {
            assert!(
                matches!(reason, OwnedCaptureRefusal::OrdinaryEngineRejection),
                "expected an ordinary pre-gate engine rejection, got {reason:?}"
            );
            assert_eq!(
                fingerprint(&returned),
                before,
                "the same proof is returned intact"
            );
            returned
        }
        other => panic!("expected Refused, got {other:?}"),
    };
    // The engine was consulted but rejected before the gate: no self-vote (still
    // L0 view 0), no capture.
    assert_eq!(
        engine.locked_qc().map(|q| q.view),
        Some(0),
        "no dependent self-vote on an ordinary engine rejection"
    );
    assert_eq!(registry_occupied(&owner), 0, "no capture on ordinary rejection");
    // BOTH ledgers restored to the proof-held baseline while the returned proof is
    // still live (every transient the engine-rejection path touched was released).
    assert_eq!(
        ledger_snapshot(&owner),
        with_proof,
        "operational AND aggregate charges restored to the proof-held baseline (returned proof live)"
    );
    // Releasing the returned proof drops its O3 holder charge from BOTH ledgers,
    // returning to the proof-free baseline.
    drop(returned_proof);
    assert_eq!(
        ledger_snapshot(&owner),
        baseline,
        "operational AND aggregate charges returned to the proof-free baseline after the proof is released"
    );
}

// ===========================================================================
// 18. §4 — Owner-route MissingCandidate: the existing engine missing-candidate
//     path, reached through existing configuration (`max_pending_blocks == 0`)
//     and the owner entrypoint. Under that block-slot pressure the just-
//     registered candidate is immediately evicted, and a `NoLock` engine decision
//     (the engine itself holds no lock) succeeds WITHOUT a candidate lookup; the
//     owning gate then finds the required decision-view candidate absent and
//     refuses `MissingCandidate` BEFORE any self-vote. The owner still holds a
//     durable restriction (so the provenance precheck passes) and an admissible
//     policy; the SAME proof is returned intact, no capture occurs, and the
//     charges return exactly to baseline. This is an engine missing-candidate
//     refusal, kept distinct from a storage bootstrap refusal.
// ===========================================================================

#[test]
fn missing_candidate_refuses_with_proof_and_no_self_vote() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    // Fresh engine with NO lock and `max_pending_blocks == 0`: the candidate is
    // evicted on registration and the decision is `NoLock` (no candidate lookup).
    let limits_cfg = qbind_consensus::ConsensusLimitsConfig {
        max_pending_blocks: 0,
        ..Default::default()
    };
    let mut engine: BasicHotStuffEngine<[u8; 32]> = BasicHotStuffEngine::with_state_limits(
        ValidatorId::new(1),
        engine_validator_set(1),
        limits_cfg,
    );
    let p = make_proposal(0, [0xFFu8; 32], 1);
    // Owner holds a durable restriction so the provenance precheck passes; the
    // engine lock is absent, but correspondence is never reached.
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [0x42u8; 32], 3, 0);
    // Proof-free paired (operational, aggregate) baseline.
    let baseline = ledger_snapshot(&owner);
    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .unwrap();
    let before = fingerprint(&proof);
    // Paired baseline with ONLY the live input proof held. No temporary pressure.
    let with_proof = ledger_snapshot(&owner);
    let lim = limits(&ctx);

    let outcome =
        owner.decide_and_capture_owned(&mut engine, ValidatorId::new(1), &p, &lim, 1, proof);
    let returned_proof = match outcome {
        OwnedDecisionOutcome::Refused {
            proof: returned,
            reason,
        } => {
            assert!(
                matches!(reason, OwnedCaptureRefusal::MissingCandidate),
                "expected a missing-candidate refusal, got {reason:?}"
            );
            assert_eq!(
                fingerprint(&returned),
                before,
                "the same proof is returned intact"
            );
            returned
        }
        other => panic!("expected Refused, got {other:?}"),
    };
    // The engine held no lock to begin with, so there is nothing to self-vote
    // into; no capture occurs.
    assert!(
        engine.locked_qc().is_none(),
        "engine remains unlocked; no self-vote"
    );
    assert_eq!(
        registry_occupied(&owner),
        0,
        "no capture on missing-candidate refusal"
    );
    // BOTH ledgers restored to the proof-held baseline while the returned proof is
    // still live.
    assert_eq!(
        ledger_snapshot(&owner),
        with_proof,
        "operational AND aggregate charges restored to the proof-held baseline (returned proof live)"
    );
    // Releasing the returned proof drops its O3 holder charge from BOTH ledgers,
    // returning to the proof-free baseline.
    drop(returned_proof);
    assert_eq!(
        ledger_snapshot(&owner),
        baseline,
        "operational AND aggregate charges returned to the proof-free baseline after the proof is released"
    );
}