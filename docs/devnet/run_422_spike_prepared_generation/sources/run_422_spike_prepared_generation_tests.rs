//! RUN 422 — generation-only prepared-decision L0 ownership feasibility spike.
//!
//! Executable, discriminating tests for the §13.6 prepared-decision L0
//! experiment built on the accepted `safety_record_store` component. They use
//! **real RocksDB-backed storage** and the maximum complete QC/TC fixtures at
//! N=1 and N=4, assert fixture dimensions/capacities before measuring, and
//! measure owned capacities + inline objects **independently** of reservation
//! counters.
//!
//! Non-authorizing: capture establishes no engine decision timing, verification,
//! freshness, or activation. Activation stays DISABLED; public DevNet is NO-GO.

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::qc::QuorumCertificate as LogicalQc;
use qbind_consensus::timeout::{TimeoutCertificate, TimeoutMsg};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::safety_record_store::accounting::prepared_generation_charge;
use qbind_node::safety_record_store::backend::{InjectFault, SafetyBackend, SafetyBackendPolicy};
use qbind_node::safety_record_store::codec::encode_record;
use qbind_node::safety_record_store::owner::{make_locked_qc, PublishResult, SafetyRecordOwner};
use qbind_node::safety_record_store::prepared::{
    prepared_entry_charge_bytes, size_of_generation_backing, size_of_prepared_entry,
    size_of_prepared_handle, size_of_prepared_registry, CaptureRefusal, ReleaseOutcome,
};
use qbind_node::safety_record_store::profile::{max_retained_generation_bytes, PinnedSafetyContext};
use qbind_node::safety_record_store::record::{
    size_of_timeout_msg, DecodedRecord, EvidenceStatus, LockedRecord, SafetyRecord,
    SupportingEvidence, WireQc,
};
use qbind_node::safety_record_store::validate::{validate_decoded, FixtureCommittedHistory};

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

/// A context with the SAME dimensions (so the per-context ceiling is identical,
/// `attach` binds idempotently) but a DIFFERENT `authority_context_ref`, so its
/// context digest differs — used to reach the ForeignContext gate in isolation.
fn ctx_n_foreign(n: u64) -> PinnedSafetyContext {
    let mut c = ctx_n(n);
    c.authority_context_ref = [0x5Au8; 32];
    c
}

fn valid_wire_qc(ctx: &PinnedSafetyContext, block_id: [u8; 32], view: u64) -> WireQc {
    let n = ctx.n();
    let need = ((2 * n) + 2) / 3; // ceil(2N/3)
    let mut bitmap = vec![0u8; ((n + 7) / 8).max(1)];
    let mut signatures = Vec::new();
    for i in 0..need {
        bitmap[i / 8] |= 1 << (i % 8);
        signatures.push(vec![0xABu8; S_SIG]);
    }
    signatures.shrink_to_fit();
    WireQc {
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

/// The maximum complete TC-derived record for `ctx` (every decoded row present:
/// record-level + nested high-QC signers, N signed timeouts with signatures and
/// nested high-QCs) — the heaviest generation the per-class ceiling admits.
fn valid_tc_record(ctx: &PinnedSafetyContext, lock_view: u64, timeout_view: u64) -> LockedRecord {
    let need = ((2 * ctx.n()) + 2) / 3;
    let high = LogicalQc::new(
        [9u8; 32],
        lock_view,
        (0..need as u64).map(ValidatorId::new).collect(),
    );
    let mut signed = Vec::new();
    for i in 0..need as u64 {
        let mut t = TimeoutMsg::new(timeout_view, Some(high.clone()), ValidatorId::new(i));
        t.set_signature(vec![0xCD; S_SIG]);
        signed.push(t);
    }
    signed.shrink_to_fit();
    let tc = TimeoutCertificate {
        view: timeout_view + 1,
        high_qc: Some(high.clone()),
        signers: (0..need as u64).map(ValidatorId::new).collect(),
        signed_timeouts: signed,
        timeout_view,
    };
    let evidence = SupportingEvidence::TcDerived {
        high_qc: high.clone(),
        tc,
    };
    let binding = qbind_node::safety_record_store::codec::compute_evidence_lock_binding(
        &[9u8; 32],
        lock_view,
        &evidence,
        &ctx.authority_context_ref,
        ctx,
    )
    .unwrap();
    LockedRecord {
        lock_block_id: [9u8; 32],
        lock_view,
        evidence_lock_binding: binding,
        authority_context_ref: ctx.authority_context_ref,
        committed_anchor: None,
        predecessor_ref: None,
        evidence,
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

/// Publish one QC-derived restriction and return (owner, new_revision).
fn publish_qc(owner: &SafetyRecordOwner, ctx: &PinnedSafetyContext, block: [u8; 32], view: u64, expected: u64) -> u64 {
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

// ===========================================================================
// 1. Fixture dimensions + generation-only charge is strictly smaller than the
//    full-proof holder charge (the whole point of generation-only retention).
// ===========================================================================

fn dimensions_and_charges(n: u64) {
    let ctx = ctx_n(n);
    // Assert fixture dimensions BEFORE measurement.
    assert_eq!(ctx.n() as u64, n, "fixture N");
    assert_eq!(ctx.s_sig, S_SIG, "fixture S_sig");

    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 read-validate");
    // The retained generation owns a non-empty evidence backing (capacity),
    // measured independently of any reservation counter.
    assert!(
        proof.retained_evidence_capacity() > 0,
        "retained generation must own a live evidence backing"
    );
    assert!(proof.encoded_capacity() > 0, "proof still owns its original encoded buffer pre-capture");

    let gen_charge = prepared_generation_charge(&ctx, proof.retained()).unwrap();
    let gen_ceiling = max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap();
    assert!(gen_charge <= gen_ceiling, "gen-only charge within the retained ceiling (no increase)");
    assert_eq!(prepared_entry_charge_bytes(), 48, "per-entry = identity 40 + arc_handle 8");

    // The holder charge the full proof reserves (encoded + generation + handle)
    // is strictly larger than the generation-only charge: generation-only
    // retention does NOT reuse the full-proof holder charge.
    let holder_live = op_current(&owner); // proof holder live
    assert!(
        holder_live > gen_charge + prepared_entry_charge_bytes(),
        "full-proof holder ({holder_live}) must exceed gen-only charge ({}+48)",
        gen_charge
    );

    println!(
        "[dims N={n}] gen_charge={gen_charge} gen_ceiling={gen_ceiling} full_holder={holder_live} \
         sizeof(registry={},entry={},backing={},handle={})",
        size_of_prepared_registry(),
        size_of_prepared_entry(),
        size_of_generation_backing(),
        size_of_prepared_handle(),
    );
}

#[test]
fn spike_dimensions_and_charges_n1() {
    dimensions_and_charges(1);
}
#[test]
fn spike_dimensions_and_charges_n4() {
    dimensions_and_charges(4);
}

// ===========================================================================
// 2. Shared generation: two entries, ONE generation charge; first drop retains
//    it, final drop releases it.
// ===========================================================================

fn shared_generation(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    let baseline = op_current(&owner);
    assert_eq!(baseline, 0, "no live operational holders at baseline");

    let proof1 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let gen = prepared_generation_charge(&ctx, proof1.retained()).unwrap();
    let entry = prepared_entry_charge_bytes();

    let pin1 = owner
        .capture_prepared_decision(proof1, 1)
        .expect("capture 1");
    assert_eq!(op_current(&owner), gen + entry, "one gen + one entry live; full holder released");

    // Second, EQUAL proof shares the one generation backing.
    let proof2 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin2 = owner
        .capture_prepared_decision(proof2, 1)
        .expect("capture 2 (shared)");
    assert_eq!(
        op_current(&owner),
        gen + entry + entry,
        "ONE generation charge for two entries (+ two per-entry charges)"
    );

    // Measure object coverage independently of counters: both entries share the
    // one backing (strong_count 2) and carry the same generation charge.
    let reg = owner.backend_for_test().prepared_registry_for_test();
    {
        let g = reg.lock().unwrap();
        let v1 = g.inspect(pin1.handle()).expect("entry 1 live");
        let v2 = g.inspect(pin2.handle()).expect("entry 2 live");
        assert_eq!(v1.backing_shares, 2, "generation backing shared by both entries");
        assert_eq!(v2.backing_shares, 2);
        assert_eq!(v1.generation_charge, gen);
        assert_eq!(v2.generation_charge, gen);
        assert_eq!(v1.entry_charge, entry);
        assert!(v1.evidence_backing_capacity > 0);
        assert!(matches!(v1.evidence_status, EvidenceStatus::Unverified));
    }

    // First drop RETAINS the generation (second entry still shares it).
    assert_eq!(pin1.release(), ReleaseOutcome::Released);
    assert_eq!(op_current(&owner), gen + entry, "generation retained after first drop");

    // Final drop RELEASES the generation.
    assert_eq!(pin2.release(), ReleaseOutcome::Released);
    assert_eq!(op_current(&owner), 0, "generation released after final drop");

    println!("[shared N={n}] gen={gen} entry={entry} two_entries_current={}", gen + 2 * entry);
}

#[test]
fn spike_shared_generation_n1() {
    shared_generation(1);
}
#[test]
fn spike_shared_generation_n4() {
    shared_generation(4);
}

// ===========================================================================
// 3. Distinct generations across replacement + coexistence during O4; and a
//    full registry refuses a third capture WITHOUT eviction.
// ===========================================================================

fn distinct_generations_and_full(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);

    // rev 1: lock A (QC). Capture entry 1.
    publish_qc(&owner, &ctx, [0x11u8; 32], 5, 0);
    let pa = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let ga = prepared_generation_charge(&ctx, pa.retained()).unwrap();
    let pin1 = owner.capture_prepared_decision(pa, 1).expect("capture A");
    let entry = prepared_entry_charge_bytes();
    assert_eq!(op_current(&owner), ga + entry);

    // O4 publishes rev 2 (a distinct lock B) WHILE entry 1 is pinned —
    // contemporaneous live objects + reservations during O4. Report success.
    let rev2 = publish_qc(&owner, &ctx, [0x22u8; 32], 9, 1);
    assert_eq!(rev2, 2, "O4 succeeds while a prepared entry is pinned (coexistence)");

    // rev 2: capture entry 2 — a DISTINCT generation (different lock identity).
    let pb = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let gb = prepared_generation_charge(&ctx, pb.retained()).unwrap();
    let pin2 = owner.capture_prepared_decision(pb, 2).expect("capture B");

    // Two DISTINCT generation charges coexist (NOT shared): current carries both
    // gen charges, not one. If they had shared, current would be ga + 2*entry.
    assert_eq!(
        op_current(&owner),
        ga + gb + 2 * entry,
        "two distinct generations coexist (combined live objects)"
    );
    let cap = owner.backend_for_test().accounting_aggregate_cap().unwrap();
    assert!(op_current(&owner) <= cap, "coexistence fits the unchanged aggregate ceiling");
    {
        let reg = owner.backend_for_test().prepared_registry_for_test();
        let g = reg.lock().unwrap();
        assert_eq!(g.inspect(pin1.handle()).unwrap().backing_shares, 1, "distinct backing A");
        assert_eq!(g.inspect(pin2.handle()).unwrap().backing_shares, 1, "distinct backing B");
        assert_eq!(g.occupied(), 2);
        assert!(g.is_full(), "both slots occupied");
    }

    // rev 3 published, then a THIRD capture is refused WITHOUT eviction; the
    // returned proof is intact.
    let rev3 = publish_qc(&owner, &ctx, [0x33u8; 32], 13, 2);
    assert_eq!(rev3, 3);
    let pc = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pc_rev = pc.publication_revision();
    let pc_enc_cap = pc.encoded_capacity();
    match owner.capture_prepared_decision(pc, 3) {
        Err((returned, CaptureRefusal::RegistryFull)) => {
            assert_eq!(returned.publication_revision(), pc_rev, "refused proof revision intact");
            assert_eq!(returned.encoded_capacity(), pc_enc_cap, "refused proof original bytes intact");
            assert!(returned.recovery_backend_incarnation().is_some(), "refused proof O5 capability intact");
        }
        other => panic!("expected RegistryFull, got {other:?}"),
    }
    {
        // No eviction: the two prior entries are still present.
        let reg = owner.backend_for_test().prepared_registry_for_test();
        assert_eq!(reg.lock().unwrap().occupied(), 2, "no eviction on refusal");
    }

    println!("[distinct N={n}] ga={ga} gb={gb} coexist_current={} cap={cap}", ga + gb + 2 * entry);
    drop(pin1);
    drop(pin2);
}

#[test]
fn spike_distinct_generations_and_full_n1() {
    distinct_generations_and_full(1);
}
#[test]
fn spike_distinct_generations_and_full_n4() {
    distinct_generations_and_full(4);
}

// ===========================================================================
// 4. Normal release AND automatic abandonment (Drop) both clean up to the
//    baseline while the backend stays alive; backend remains usable afterwards.
// ===========================================================================

fn release_and_abandonment(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    // Normal explicit release.
    let p1 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin1 = owner.capture_prepared_decision(p1, 1).unwrap();
    assert!(op_current(&owner) > 0);
    assert_eq!(owner.release_prepared(pin1), ReleaseOutcome::Released);
    assert_eq!(op_current(&owner), 0, "normal release cleans to baseline");

    // Automatic abandonment: drop the pin WITHOUT releasing.
    let p2 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin2 = owner.capture_prepared_decision(p2, 1).unwrap();
    assert!(op_current(&owner) > 0);
    drop(pin2); // non-Copy guard Drop performs cleanup
    assert_eq!(op_current(&owner), 0, "abandonment (Drop) cleans to baseline");
    {
        let reg = owner.backend_for_test().prepared_registry_for_test();
        assert_eq!(reg.lock().unwrap().occupied(), 0);
    }

    // Backend still alive and usable (existing O5-style read path intact).
    let p3 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    assert!(p3.recovery_backend_incarnation().is_some(), "backend alive after abandonment");
}

#[test]
fn spike_release_and_abandonment_n1() {
    release_and_abandonment(1);
}
#[test]
fn spike_release_and_abandonment_n4() {
    release_and_abandonment(4);
}

// ===========================================================================
// 5. Provenance-gate refusals — each returns the proof intact and mints nothing.
// ===========================================================================

#[test]
fn spike_refuse_bootstrap_unresolved() {
    // A freshly initialized store is BootstrapNoLock (rev 0): capture refuses,
    // leaving bootstrap explicitly unresolved.
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    assert!(matches!(proof.retained().record, SafetyRecord::BootstrapNoLock { .. }));
    match owner.capture_prepared_decision(proof, 0) {
        Err((p, CaptureRefusal::BootstrapUnresolved)) => {
            assert_eq!(p.publication_revision(), 0);
        }
        other => panic!("expected BootstrapUnresolved, got {other:?}"),
    }
}

#[test]
fn spike_refuse_stale_revision() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    let stale = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap(); // rev 1
    publish_qc(&owner, &ctx, [0x22u8; 32], 9, 1); // authoritative now rev 2
    match owner.capture_prepared_decision(stale, 1) {
        Err((p, CaptureRefusal::StaleRevision { expected, found })) => {
            assert_eq!(expected, 1);
            assert_eq!(found, 2);
            assert_eq!(p.publication_revision(), 1, "stale proof returned intact");
        }
        other => panic!("expected StaleRevision, got {other:?}"),
    }
}

#[test]
fn spike_refuse_foreign_incarnation() {
    // A proof minted by backend A is refused by an owner on backend B (a
    // different ownership incarnation) — the incarnation check also guards
    // capture, not only O5.
    let ctx = ctx_n(4);
    let dir_a = tempfile::tempdir().unwrap();
    let owner_a = init_owner(dir_a.path(), &ctx);
    publish_qc(&owner_a, &ctx, [9u8; 32], 5, 0);
    let proof_a = owner_a.read_validate(None::<&FixtureCommittedHistory>).unwrap();

    let dir_b = tempfile::tempdir().unwrap();
    let owner_b = init_owner(dir_b.path(), &ctx); // distinct incarnation
    match owner_b.capture_prepared_decision(proof_a, 1) {
        Err((p, CaptureRefusal::ForeignOrUncharged)) => {
            assert!(p.recovery_backend_incarnation().is_some());
        }
        other => panic!("expected ForeignOrUncharged, got {other:?}"),
    }
}

#[test]
fn spike_refuse_standalone_uncharged_none() {
    // A standalone semantic/codec proof carries NO O5 capability (None) and NO
    // holder reservation: capture refuses it as uncharged.
    let ctx = ctx_n(4);
    let qc = valid_wire_qc(&ctx, [9u8; 32], 5);
    let l = make_locked_qc(&ctx, [9u8; 32], 5, qc, None).unwrap();
    let decoded = DecodedRecord {
        persistence_format_version: 1,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: 1,
        record: SafetyRecord::Locked(l),
    };
    let bytes = encode_record(&decoded, &ctx).unwrap();
    let standalone = validate_decoded(decoded, bytes, &ctx, None::<&FixtureCommittedHistory>).unwrap();
    assert!(standalone.recovery_backend_incarnation().is_none(), "standalone proof has no capability");

    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    match owner.capture_prepared_decision(standalone, 1) {
        Err((p, CaptureRefusal::ForeignOrUncharged)) => {
            assert!(p.recovery_backend_incarnation().is_none());
        }
        other => panic!("expected ForeignOrUncharged (standalone), got {other:?}"),
    }
}

#[test]
fn spike_refuse_foreign_context() {
    // Same backend (so the incarnation matches), but a second owner handle with
    // a different context digest: the ForeignContext gate (checked before the
    // domain) refuses, and the revision/metadata path is never reached.
    let ctx = ctx_n(4);
    let foreign = ctx_n_foreign(4);
    let dir = tempfile::tempdir().unwrap();
    let backend = open_enabled(dir.path());
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    owner.initialize(true).unwrap();
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();

    // A second handle on the SAME backend with the foreign context (same N, so
    // attach binds the identical ceiling idempotently).
    let owner_foreign = SafetyRecordOwner::attach(backend, foreign).unwrap();
    match owner_foreign.capture_prepared_decision(proof, 1) {
        Err((p, CaptureRefusal::ForeignContext)) => {
            assert_eq!(p.publication_revision(), 1, "proof intact on ForeignContext");
        }
        other => panic!("expected ForeignContext, got {other:?}"),
    }
}

#[test]
fn spike_refuse_recovery_required() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let backend = open_enabled(dir.path());
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    owner.initialize(true).unwrap();
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();

    // Drive the backend into recovery-required via an uncertain-but-durable O4.
    backend.set_inject(InjectFault::UncertainAfterWrite);
    let _ = owner.publish_locked(
        make_locked_qc(&ctx, [0x22u8; 32], 9, valid_wire_qc(&ctx, [0x22u8; 32], 9), None).unwrap(),
        1,
        None::<&FixtureCommittedHistory>,
    );
    backend.set_inject(InjectFault::None);
    assert!(owner.recovery_required(), "uncertain O4 sets the recovery latch");

    match owner.capture_prepared_decision(proof, 1) {
        Err((_p, CaptureRefusal::RecoveryRequired)) => {}
        other => panic!("expected RecoveryRequired, got {other:?}"),
    }
}

// ===========================================================================
// 6. Counter exhaustion fails closed BEFORE mutation (bounded test seam); and
//    stale/foreign handles are refused on handle-based release.
// ===========================================================================

#[test]
fn spike_counter_exhaustion_fails_closed() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();

    let before = op_current(&owner); // proof holder live
    {
        let reg = owner.backend_for_test().prepared_registry_for_test();
        reg.lock().unwrap().force_next_serial(u64::MAX);
    }
    match owner.capture_prepared_decision(proof, 1) {
        Err((p, CaptureRefusal::CounterExhausted)) => {
            assert!(p.recovery_backend_incarnation().is_some(), "proof intact on counter exhaustion");
            // Fail-closed BEFORE any mutation/allocation: while the refused proof
            // is still alive, only its holder is charged — no +48 entry leaked.
            assert_eq!(op_current(&owner), before, "no charge leaked on counter exhaustion");
        }
        other => panic!("expected CounterExhausted, got {other:?}"),
    }
    assert_eq!(
        owner.backend_for_test().prepared_registry_for_test().lock().unwrap().occupied(),
        0,
        "no entry inserted"
    );
}

#[test]
fn spike_stale_and_foreign_handles_refused() {
    let ctx = ctx_n(4);
    // Backend A: capture a real entry, remember its handle.
    let dir_a = tempfile::tempdir().unwrap();
    let owner_a = init_owner(dir_a.path(), &ctx);
    publish_qc(&owner_a, &ctx, [9u8; 32], 5, 0);
    let pa = owner_a.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin = owner_a.capture_prepared_decision(pa, 1).unwrap();
    let handle = pin.handle();

    // Foreign incarnation: present A's handle to B's registry.
    let dir_b = tempfile::tempdir().unwrap();
    let owner_b = init_owner(dir_b.path(), &ctx);
    {
        let reg_b = owner_b.backend_for_test().prepared_registry_for_test();
        assert_eq!(
            reg_b.lock().unwrap().release_by_handle(handle),
            ReleaseOutcome::ForeignIncarnation,
            "foreign-incarnation handle refused"
        );
    }

    // Stale serial: release the real entry, then re-release the same handle.
    let reg_a = owner_a.backend_for_test().prepared_registry_for_test();
    assert_eq!(reg_a.lock().unwrap().release_by_handle(handle), ReleaseOutcome::Released);
    assert_eq!(
        reg_a.lock().unwrap().release_by_handle(handle),
        ReleaseOutcome::NotFound,
        "stale serial refused"
    );
    // The owning pin's Drop now finds nothing to release (idempotent).
    drop(pin);
}

// ===========================================================================
// 7. Admission refusal BEFORE new allocation; cleanup to the correct baseline;
//    subsequent readmission; and the refused proof's existing O5 recovery path.
// ===========================================================================

fn admission_refusal_and_readmission(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    let cap = owner.backend_for_test().accounting_aggregate_cap().unwrap();

    // Read the real proof we will try (and fail) to capture. Its holder is now
    // live and charged against the aggregate.
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let gen = prepared_generation_charge(&ctx, proof.retained()).unwrap();
    let proof_rev = proof.publication_revision();

    // Current aggregate = context partition + the live proof holder. Add a
    // standing reservation leaving headroom of exactly (entry + gen - 1): enough
    // for the per-entry (48) reservation to succeed, but one byte short of the
    // generation. Thus admission of the generation is refused AFTER the per-entry
    // reservation — exercising cleanup-to-baseline (release of the per-entry).
    let entry = prepared_entry_charge_bytes();
    let used = owner.backend_for_test().accounting_aggregate_current();
    let standing_charge = cap - used - entry - (gen - 1);
    let standing = owner
        .backend_for_test()
        .reserve_standing_for_test(standing_charge)
        .expect("standing reservation admits (holder + entry fit, gen does not)");
    let baseline_under_pressure = owner.backend_for_test().accounting_aggregate_current();

    match owner.capture_prepared_decision(proof, 1) {
        Err((returned, CaptureRefusal::Admission(_))) => {
            // The refused proof is intact and still an O5-usable recovery token.
            assert!(returned.recovery_backend_incarnation().is_some());
            assert!(returned.encoded_capacity() > 0, "refused proof original bytes intact");
            assert_eq!(returned.publication_revision(), proof_rev, "revision unchanged");
            // Cleanup to the correct baseline: the per-entry reservation taken
            // before the generation admission failed is released; only the
            // returned proof holder + our standing remain.
            assert_eq!(
                owner.backend_for_test().accounting_aggregate_current(),
                baseline_under_pressure,
                "per-entry reservation released on generation-admission refusal"
            );
            assert_eq!(
                owner.backend_for_test().prepared_registry_for_test().lock().unwrap().occupied(),
                0,
                "no entry inserted on refusal"
            );
            drop(returned);
        }
        other => panic!("expected Admission refusal, got {other:?}"),
    }

    // Readmission: release the pressure and capture a freshly read proof.
    drop(standing);
    let fresh = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    assert!(fresh.recovery_backend_incarnation().is_some());
    let pin = owner
        .capture_prepared_decision(fresh, 1)
        .map_err(|(_, r)| r)
        .expect("readmission succeeds once pressure is released");
    assert_eq!(
        owner.backend_for_test().prepared_registry_for_test().lock().unwrap().occupied(),
        1,
        "readmitted entry present"
    );
    owner.release_prepared(pin);
}

#[test]
fn spike_admission_refusal_and_readmission_n1() {
    admission_refusal_and_readmission(1);
}
#[test]
fn spike_admission_refusal_and_readmission_n4() {
    admission_refusal_and_readmission(4);
}

// ===========================================================================
// 8. Capture / publication interleaving under the serialization boundary: a
//    capture and an O4 publication are linearized; a capture reflects only the
//    authoritative revision read under the domain.
// ===========================================================================

#[test]
fn spike_capture_publication_interleaving() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0); // rev 1

    // A proof read at rev 1, then an O4 advances to rev 2 BEFORE the capture:
    // capture reads the authoritative revision under the domain and refuses the
    // now-stale proof (linearization with publication).
    let p_rev1 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    publish_qc(&owner, &ctx, [0x22u8; 32], 9, 1); // rev 2
    match owner.capture_prepared_decision(p_rev1, 1) {
        Err((_p, CaptureRefusal::StaleRevision { found, .. })) => assert_eq!(found, 2),
        other => panic!("expected StaleRevision under interleaving, got {other:?}"),
    }
    // A fresh read at the authoritative rev 2 captures successfully.
    let p_rev2 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin = owner.capture_prepared_decision(p_rev2, 2).expect("capture at authoritative rev");
    assert!(op_current(&owner) > 0);
    drop(pin);
}

// ===========================================================================
// 9. Maximum complete TC-derived generation: capture retains the heaviest
//    complete generation within the unchanged ceiling.
// ===========================================================================

fn tc_generation_capture(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);

    // Publish a maximum complete TC-derived restriction.
    let ltc = valid_tc_record(&ctx, 5, 4);
    assert!(
        matches!(&ltc.evidence, SupportingEvidence::TcDerived { tc, .. } if !tc.signed_timeouts.is_empty()),
        "TC fixture carries complete signed timeouts"
    );
    match owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>) {
        PublishResult::DurableAcknowledged { new_revision: 1 } => {}
        other => panic!("TC publish: {other:?}"),
    }

    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    assert!(
        matches!(proof.retained().record, SafetyRecord::Locked(ref l) if matches!(l.evidence, SupportingEvidence::TcDerived { .. })),
        "retained TC generation"
    );
    let gen = prepared_generation_charge(&ctx, proof.retained()).unwrap();
    let ceiling = max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap();
    assert!(gen <= ceiling, "complete TC generation within the unchanged ceiling");

    let pin = owner.capture_prepared_decision(proof, 1).expect("capture TC generation");
    assert_eq!(op_current(&owner), gen + prepared_entry_charge_bytes());
    println!("[tc N={n}] tc_gen_charge={gen} ceiling={ceiling}");
    drop(pin);
    assert_eq!(op_current(&owner), 0);
}

#[test]
fn spike_tc_generation_capture_n1() {
    tc_generation_capture(1);
}
#[test]
fn spike_tc_generation_capture_n4() {
    tc_generation_capture(4);
}

// ===========================================================================
// 10. Evidence/context binding correctness: the captured entry carries exactly
//     the proof's provenance (context digest, incarnation, revision, evidence).
// ===========================================================================

fn evidence_context_binding(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let expect_digest = *proof.origin_context_digest();
    let expect_incarnation = proof.recovery_backend_incarnation().unwrap();
    let expect_rev = proof.publication_revision();

    let pin = owner.capture_prepared_decision(proof, 1).unwrap();
    let reg = owner.backend_for_test().prepared_registry_for_test();
    let g = reg.lock().unwrap();
    let view = g.inspect(pin.handle()).unwrap();
    assert_eq!(view.origin_context_digest, expect_digest, "bound to the originating context");
    assert_eq!(view.recovery_backend_incarnation, expect_incarnation, "bound to the originating incarnation");
    assert_eq!(view.captured_revision, expect_rev, "bound to the captured revision");
    assert!(matches!(view.evidence_status, EvidenceStatus::Unverified), "capture mints no verified status");
    drop(g);
    drop(pin);
}

#[test]
fn spike_evidence_context_binding_n1() {
    evidence_context_binding(1);
}
#[test]
fn spike_evidence_context_binding_n4() {
    evidence_context_binding(4);
}