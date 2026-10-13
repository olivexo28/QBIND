//! RUN 422 — generation-only prepared-decision L0 ownership feasibility spike.
//!
//! Executable, discriminating tests for the §13.6 prepared-decision L0
//! experiment built on the accepted `safety_record_store` component. They use
//! **real RocksDB-backed storage** and the maximum complete QC/TC fixtures at
//! N=1 and N=4, assert fixture dimensions/capacities before measuring, and
//! measure the ACTUAL live objects (the `Arc<GenerationBacking>` allocation, the
//! `Mutex<PreparedRegistry>` cell, and each `PreparedPin`) against their covering
//! reservations — never a synthetic wrapper or a bare counter.
//!
//! §1 ACTUAL-OBJECT ACCOUNTING: the prepared generation is retained as a private
//! `GenerationBacking` allocation, NOT the synthetic `RetainedGeneration`. Its live
//! footprint (`size_of::<GenerationBacking>()` inline + owned evidence backings +
//! `Arc` overhead) is covered by TWO reservations — the generation-core charge and
//! the holder/control charge — whose sum equals the full allocation exactly. The
//! registry cell and each owning pin carry their own charges. Measurement failure
//! is explicit (no silent `unwrap_or(0)` substitution).
//!
//! §2 SHARING-PATH LIFETIME: a shared capture destroys the duplicate proof's
//! separately owned evidence backings BEFORE releasing the reservation that
//! covered them, so no live byte is ever uncharged across the conversion. A
//! discriminating regression distinguishes this correct ordering from the
//! premature-release defect.
//!
//! Non-authorizing: capture establishes no engine decision timing, verification,
//! freshness, or activation. Activation stays DISABLED; public DevNet is NO-GO.

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::qc::QuorumCertificate as LogicalQc;
use qbind_consensus::timeout::{TimeoutCertificate, TimeoutMsg};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::safety_record_store::accounting::{
    decoded_working_set_charge, prepared_generation_charge, prepared_holder_control_charge,
};
use qbind_node::safety_record_store::backend::{InjectFault, SafetyBackend, SafetyBackendPolicy};
use qbind_node::safety_record_store::codec::encode_record;
use qbind_node::safety_record_store::error::{CapacityRefusalDetail, SafetyStoreError};
use qbind_node::safety_record_store::owner::{
    dup_backing_live_at_release, make_locked_qc, set_capture_interval_hook, set_shared_release_order,
    shared_dup_live_at_release, PublishResult, SafetyRecordOwner, SharedReleaseOrder,
};
use qbind_node::safety_record_store::prepared::{
    generation_backing_struct_size_bytes, pin_charge_bytes, registry_cell_charge_bytes,
    size_of_generation_backing, size_of_prepared_entry, size_of_prepared_handle,
    size_of_prepared_pin, size_of_prepared_registry, size_of_prepared_registry_cell,
    CaptureRefusal, PreparedEntryView, PreparedHandle, ReleaseOutcome,
};
use qbind_node::safety_record_store::profile::{
    max_retained_generation_bytes, max_safety_record_bytes, PinnedSafetyContext, ARC_CTRL,
};
use qbind_node::safety_record_store::record::{
    size_of_retained_record, size_of_timeout_msg, CommittedAnchor, DecodedRecord, EvidenceStatus,
    LockedRecord, SafetyRecord, SupportingEvidence, WireQc,
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

/// The block id and height of the independently-supplied committed anchor the
/// maximum fixtures reference. The matching committed history is built by
/// [`committed_history`]; a maximum complete record is anchored (P3 requires the
/// supplied history to affirm it) and carries a predecessor reference.
const ANCHOR_BLOCK_ID: [u8; 32] = [0xA7u8; 32];
const ANCHOR_HEIGHT: u64 = 4;
const PREDECESSOR_REF: u64 = 3;

/// The independently-supplied committed history that affirms the maximum
/// fixtures' committed anchor (never derived from the candidate record).
fn committed_history() -> FixtureCommittedHistory {
    FixtureCommittedHistory::new().with(ANCHOR_BLOCK_ID, ANCHOR_HEIGHT)
}

/// The maximum complete committed anchor the maximum fixtures carry.
fn max_committed_anchor() -> CommittedAnchor {
    CommittedAnchor {
        block_id: ANCHOR_BLOCK_ID,
        height: ANCHOR_HEIGHT,
    }
}

fn valid_wire_qc(ctx: &PinnedSafetyContext, block_id: [u8; 32], view: u64) -> WireQc {
    let n = ctx.n() as u64;
    // Maximum complete QC: ALL N signers present (not merely a ceil(2N/3) quorum),
    // each with a maximum-length (`S_sig`) signature and a set bitmap bit.
    let mut bitmap = vec![0u8; ((n + 7) / 8).max(1) as usize];
    let mut signatures = Vec::new();
    for i in 0..n {
        bitmap[(i / 8) as usize] |= 1 << (i % 8);
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
/// record-level + nested high-QC signers, ALL N signed timeouts with
/// maximum-length signatures and nested high-QCs) — the heaviest generation the
/// per-class ceiling admits — anchored to the independently-supplied committed
/// history ([`committed_history`]) with a predecessor reference.
fn valid_tc_record(ctx: &PinnedSafetyContext, lock_view: u64, timeout_view: u64) -> LockedRecord {
    let n = ctx.n() as u64;
    // ALL N signers in the record-level and nested high-QC signer arrays.
    let high = LogicalQc::new(
        [9u8; 32],
        lock_view,
        (0..n).map(ValidatorId::new).collect(),
    );
    let mut signed = Vec::new();
    for i in 0..n {
        let mut t = TimeoutMsg::new(timeout_view, Some(high.clone()), ValidatorId::new(i));
        t.set_signature(vec![0xCD; S_SIG]);
        signed.push(t);
    }
    signed.shrink_to_fit();
    let tc = TimeoutCertificate {
        view: timeout_view + 1,
        high_qc: Some(high.clone()),
        signers: (0..n).map(ValidatorId::new).collect(),
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
        committed_anchor: Some(max_committed_anchor()),
        predecessor_ref: Some(PREDECESSOR_REF),
        evidence,
    }
}

/// A maximum complete QC-derived locked record: ALL N signers with maximum-length
/// signatures (via [`valid_wire_qc`]), anchored to the independently-supplied
/// committed history ([`committed_history`]) with a predecessor reference.
fn max_qc_lock(ctx: &PinnedSafetyContext, block: [u8; 32], view: u64) -> LockedRecord {
    let qc = valid_wire_qc(ctx, block, view);
    let mut l = make_locked_qc(ctx, block, view, qc, Some(max_committed_anchor())).unwrap();
    l.predecessor_ref = Some(PREDECESSOR_REF);
    l
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

/// The operational partition's current charged total (holds the prepared
/// reservations: generation-core, holder/control, registry-cell, and pins).
fn op_current(owner: &SafetyRecordOwner) -> u128 {
    owner.backend_for_test().accounting_current()
}

/// The full aggregate (operational + context partitions) current charge.
fn agg_current(owner: &SafetyRecordOwner) -> u128 {
    owner.backend_for_test().accounting_aggregate_current()
}

// ---- corrected, actual-object charge constants (derived at runtime) ---------

/// The holder/control charge = `size_of::<GenerationBacking>() -
/// size_of::<RetainedRecord>()`, covering the wrapper's provenance, inline
/// reservation, and padding beyond the generation core.
fn control_charge() -> u128 {
    prepared_holder_control_charge(generation_backing_struct_size_bytes()).unwrap()
}

/// The registry-storage charge (the whole `Mutex<PreparedRegistry>` cell + Arc),
/// charged once while the registry is occupied.
fn registry_cell() -> u128 {
    registry_cell_charge_bytes()
}

/// The owning-pin charge (`size_of::<PreparedPin>()`), charged per live pin.
fn pin_bytes() -> u128 {
    pin_charge_bytes()
}

/// The number of occupied registry slots (acquires the domain lock itself; must
/// not be called while a capture holds the domain guard).
fn registry_occupied(owner: &SafetyRecordOwner) -> usize {
    owner
        .backend_for_test()
        .prepared_registry_for_test()
        .expect("registry installed")
        .lock()
        .unwrap()
        .occupied()
}

/// Resolve a pin handle to its live entry's retained generation
/// identity/provenance view, or `None` if it no longer resolves.
fn inspect_pin(owner: &SafetyRecordOwner, h: PreparedHandle) -> Option<PreparedEntryView> {
    owner
        .backend_for_test()
        .prepared_registry_for_test()
        .expect("registry installed")
        .lock()
        .unwrap()
        .inspect(h)
}

/// Assert that a pin still resolves to the SAME retained generation identity and
/// provenance it did before — occupancy alone is insufficient. Compares the
/// pinned identity, the entry serial, the captured revision, the originating
/// backend incarnation, the originating context digest, the evidence status, and
/// the retained evidence-backing capacity field by field.
fn assert_same_provenance(label: &str, before: &PreparedEntryView, after: &PreparedEntryView) {
    assert_eq!(
        after.identity, before.identity,
        "{label}: retained generation identity unchanged"
    );
    assert_eq!(
        after.serial, before.serial,
        "{label}: entry serial (retained generation) unchanged"
    );
    assert_eq!(
        after.captured_revision, before.captured_revision,
        "{label}: captured revision unchanged"
    );
    assert_eq!(
        after.recovery_backend_incarnation, before.recovery_backend_incarnation,
        "{label}: originating backend incarnation unchanged"
    );
    assert_eq!(
        after.origin_context_digest, before.origin_context_digest,
        "{label}: originating context digest unchanged"
    );
    assert_eq!(
        after.evidence_status, before.evidence_status,
        "{label}: evidence status unchanged"
    );
    assert_eq!(
        after.evidence_backing_capacity, before.evidence_backing_capacity,
        "{label}: retained evidence backing capacity unchanged"
    );
}

// ===========================================================================
// §1. ACTUAL-OBJECT ACCOUNTING — the discriminating reproduction.
//
// The live generation is an `Arc<GenerationBacking>`, NOT the synthetic
// `RetainedGeneration`. Its complete allocation (inline wrapper + owned evidence
// backings + Arc overhead) is covered EXACTLY by generation-core + holder/control.
// The OLD core-only coverage (what `prepared_generation_charge` reserved alone)
// falls short by exactly the holder/control charge — the reproduced discrepancy.
// ===========================================================================

fn actual_object_accounting(n: u64) {
    let ctx = ctx_n(n);
    // Explicit dimension assertions BEFORE measurement.
    assert_eq!(ctx.n() as u64, n, "fixture N");
    assert_eq!(ctx.s_sig, S_SIG, "fixture S_sig");

    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    // Maximum complete TC-derived generation (the heaviest the ceiling admits):
    // ALL N signed timeouts with maximum-length signatures and full nested signer
    // arrays, anchored to the independently-supplied committed history.
    let ltc = valid_tc_record(&ctx, 5, 4);
    assert!(
        matches!(&ltc.evidence, SupportingEvidence::TcDerived { tc, high_qc }
            if tc.signed_timeouts.len() as u64 == n
                && tc.signers.len() as u64 == n
                && high_qc.signers.len() as u64 == n
                && tc.high_qc.as_ref().is_some_and(|h| h.signers.len() as u64 == n)
                && tc.signed_timeouts.iter().all(|t| t.signature.len() == S_SIG
                    && t.high_qc.as_ref().is_some_and(|h| h.signers.len() as u64 == n))),
        "TC fixture carries ALL N signed timeouts with maximum-length signatures and full nested signer arrays"
    );
    assert!(
        ltc.committed_anchor.is_some() && ltc.predecessor_ref.is_some(),
        "maximum fixture carries a committed anchor and a predecessor reference"
    );
    let history = committed_history();
    match owner.publish_locked(ltc, 0, Some(&history)) {
        PublishResult::DurableAcknowledged { new_revision: 1 } => {}
        other => panic!("TC publish: {other:?}"),
    }

    let proof = owner
        .read_validate(Some(&history))
        .expect("O3 read-validate");
    // Capacity assertion BEFORE measurement: the retained generation owns a
    // non-empty evidence backing (measured independently of any counter).
    let owned_backings = proof
        .retained_evidence_capacity()
        .expect("retained evidence capacity measurement must be explicit");
    assert!(owned_backings > 0, "retained generation owns live evidence backings");

    // The covering reservations.
    let core = prepared_generation_charge(&ctx, proof.retained()).unwrap();
    let control = control_charge();
    let gen_ceiling = max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap();

    // The ACTUAL live `Arc<GenerationBacking>` allocation:
    //   inline wrapper  +  owned evidence backings  +  Arc overhead.
    let backing_inline = size_of_generation_backing() as u128;
    let arc_overhead = ARC_CTRL;
    let actual_allocation = backing_inline + owned_backings as u128 + arc_overhead;

    // (a) generation-core stays within the unchanged retained ceiling.
    assert!(core <= gen_ceiling, "generation-core within the retained ceiling (no ceiling increase)");

    // (b) THE DISCREPANCY: the OLD core-only coverage is strictly LESS than the
    //     actual allocation, short by EXACTLY the holder/control charge.
    assert!(
        core < actual_allocation,
        "core-only ({core}) under-covers the actual GenerationBacking allocation ({actual_allocation})"
    );
    assert_eq!(
        actual_allocation - core,
        control,
        "the uncovered remainder is exactly the holder/control charge"
    );

    // (c) THE CORRECTION: generation-core + holder/control cover every live byte
    //     of the allocation exactly (inline + backings + Arc).
    assert_eq!(
        core + control,
        actual_allocation,
        "core + control covers the whole Arc<GenerationBacking> allocation exactly"
    );

    // (d) the inline split is exact by construction: core's inline part is the
    //     embedded RetainedRecord; control is the rest of the wrapper.
    assert_eq!(
        control,
        backing_inline - size_of_retained_record(),
        "control = size_of(GenerationBacking) - size_of(RetainedRecord)"
    );

    // Capture and confirm the LIVE reservations equal the decomposition (plus the
    // registry cell charged once and the owning pin).
    let pin1 = owner.capture_prepared_decision(proof, 1).expect("capture");
    assert_eq!(
        op_current(&owner),
        core + control + registry_cell() + pin_bytes(),
        "live reservations = core + control + registry-cell + pin"
    );
    {
        let reg = owner
            .backend_for_test()
            .prepared_registry_for_test()
            .expect("registry lazily installed by the capture");
        let g = reg.lock().unwrap();
        let v = g.inspect(pin1.handle()).expect("entry live");
        assert_eq!(v.generation_core_charge, core, "inspected core charge");
        assert_eq!(v.generation_control_charge, control, "inspected control charge");
        assert_eq!(v.evidence_backing_capacity, owned_backings, "inspected owned backings");
        assert_eq!(v.backing_shares, 1);
        // The registry holds its standing storage reservation for the whole
        // allocation lifetime (admitted before the allocation existed).
        assert_eq!(g.registry_reservation_charge(), registry_cell(), "standing registry reservation");
    }
    println!(
        "[§1 N={n}] backing_inline={backing_inline} owned_backings={owned_backings} arc={arc_overhead} \
         actual_allocation={actual_allocation} core={core} control={control} \
         registry_cell={} pin={} sizeof(registry={},registry_cell={},entry={},backing={},pin={},handle={})",
        registry_cell(),
        pin_bytes(),
        size_of_prepared_registry(),
        size_of_prepared_registry_cell(),
        size_of_prepared_entry(),
        size_of_generation_backing(),
        size_of_prepared_pin(),
        size_of_prepared_handle(),
    );
    assert_eq!(pin1.release(), ReleaseOutcome::Released);
    // Last entry released while the backend is still alive: the registry allocation
    // is RETAINED and its storage reservation remains charged (deallocation when
    // empty is not required). The operational baseline is now the standing cell.
    assert_eq!(
        op_current(&owner),
        registry_cell(),
        "retained empty registry keeps its standing reservation after the last release"
    );
    assert_eq!(
        owner
            .backend_for_test()
            .prepared_registry_for_test()
            .expect("registry retained")
            .lock()
            .unwrap()
            .occupied(),
        0,
        "registry retained but empty after the last release"
    );
}

#[test]
fn spike_actual_object_accounting_n1() {
    actual_object_accounting(1);
}
#[test]
fn spike_actual_object_accounting_n4() {
    actual_object_accounting(4);
}

// ===========================================================================
// §1. Generation-only charge is strictly smaller than the full-proof holder it
//     replaces, and within the retained ceiling (QC fixtures, N=1 and N=4).
// ===========================================================================

fn dimensions_and_charges(n: u64) {
    let ctx = ctx_n(n);
    assert_eq!(ctx.n() as u64, n, "fixture N");
    assert_eq!(ctx.s_sig, S_SIG, "fixture S_sig");

    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
        .expect("O3 read-validate");
    assert!(
        proof.retained_evidence_capacity().expect("explicit capacity") > 0,
        "retained generation must own a live evidence backing"
    );
    assert!(proof.encoded_capacity() > 0, "proof still owns its original encoded buffer pre-capture");

    let core = prepared_generation_charge(&ctx, proof.retained()).unwrap();
    let gen_ceiling = max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap();
    assert!(core <= gen_ceiling, "gen-only core within the retained ceiling (no increase)");

    // The full-proof holder charge the proof reserves is strictly larger than the
    // generation-only core+control: generation-only retention does NOT reuse it.
    let holder_live = op_current(&owner); // proof holder live
    assert!(
        holder_live > core + control_charge(),
        "full-proof holder ({holder_live}) must exceed gen-only core+control ({}+{})",
        core,
        control_charge()
    );
    println!("[dims N={n}] core={core} control={} gen_ceiling={gen_ceiling} full_holder={holder_live}", control_charge());
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
// §1/§2. Shared generation: two entries, ONE generation backing (one core + one
// control). First drop retains the generation; final drop releases it. Each live
// pin carries its own pin charge; the registry cell is charged once.
// ===========================================================================

fn shared_generation(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    let baseline = op_current(&owner);
    assert_eq!(baseline, 0, "no live operational holders at baseline");

    let proof1 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let core = prepared_generation_charge(&ctx, proof1.retained()).unwrap();
    let control = control_charge();

    let pin1 = owner
        .capture_prepared_decision(proof1, 1)
        .expect("capture 1");
    assert_eq!(
        op_current(&owner),
        core + control + registry_cell() + pin_bytes(),
        "one generation (core+control) + registry-cell + one pin"
    );

    // Second, EQUAL proof shares the one generation backing (default = corrected
    // ordering).
    let proof2 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin2 = owner
        .capture_prepared_decision(proof2, 1)
        .expect("capture 2 (shared)");
    assert_eq!(
        op_current(&owner),
        core + control + registry_cell() + 2 * pin_bytes(),
        "ONE generation charge for two entries (+ a second pin only)"
    );
    // The corrected sharing lifetime destroyed the duplicate's evidence before
    // releasing its covering reservation: nothing was live-but-uncharged.
    assert_eq!(
        shared_dup_live_at_release(),
        Some(0),
        "corrected ordering: duplicate evidence destroyed before its reservation released"
    );

    // Object coverage independent of counters: both entries share one backing.
    let reg = owner
        .backend_for_test()
        .prepared_registry_for_test()
        .expect("registry lazily installed by the first capture");
    {
        let g = reg.lock().unwrap();
        let v1 = g.inspect(pin1.handle()).expect("entry 1 live");
        let v2 = g.inspect(pin2.handle()).expect("entry 2 live");
        assert_eq!(v1.backing_shares, 2, "generation backing shared by both entries");
        assert_eq!(v2.backing_shares, 2);
        assert_eq!(v1.generation_core_charge, core);
        assert_eq!(v1.generation_control_charge, control);
        assert_eq!(v2.generation_core_charge, core);
        assert!(v1.evidence_backing_capacity > 0);
        assert!(matches!(v1.evidence_status, EvidenceStatus::Unverified));
        // Shared handles cover ONE registry and ONE covering reservation.
        assert_eq!(g.registry_reservation_charge(), registry_cell(), "one covering registry reservation");
    }

    // First drop RETAINS the generation (second entry still shares it).
    assert_eq!(pin1.release(), ReleaseOutcome::Released);
    assert_eq!(
        op_current(&owner),
        core + control + registry_cell() + pin_bytes(),
        "generation retained after first drop (one pin released)"
    );

    // Final drop releases the generation and the last pin; the registry allocation
    // is RETAINED with its standing reservation (backend still alive).
    assert_eq!(pin2.release(), ReleaseOutcome::Released);
    assert_eq!(
        op_current(&owner),
        registry_cell(),
        "generation released; retained empty registry keeps its standing reservation"
    );

    println!("[shared N={n}] core={core} control={control}");
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
// §2. SHARING-PATH LIFETIME REGRESSION (discriminating). The duplicate proof's
// separately owned evidence backings MUST be destroyed before releasing the
// reservation that covered them. The premature ordering leaves those bytes live
// while their covering reservation is already gone (an uncharged interval); the
// corrected ordering leaves zero. Covers fresh, shared, refusal, explicit
// release, and automatic Drop. Sensitivity mutations are restored before return.
// ===========================================================================

fn sharing_lifetime_regression(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    // FRESH conversion establishes the shared backing (slot 1). A fresh capture is
    // NOT a shared conversion, so it records no shared-release observation. The
    // registry admits MAX_OUTSTANDING_PREPARED_L0 = 2 entries, so each subsequent
    // shared capture is released before the next.
    let p1 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let dup_bytes = p1.retained_evidence_capacity().expect("explicit capacity");
    assert!(dup_bytes > 0, "the duplicate will own non-empty evidence backings");
    let pin1 = owner.capture_prepared_decision(p1, 1).expect("fresh capture");

    // (1) CORRECTED ordering (default): the duplicate's evidence is destroyed
    //     BEFORE its covering reservation is released — zero live-at-release.
    let pc = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin_c = owner.capture_prepared_decision(pc, 1).expect("shared capture (corrected)");
    assert_eq!(
        shared_dup_live_at_release(),
        Some(0),
        "CORRECTED: no duplicate evidence live when its reservation is released"
    );
    assert_eq!(pin_c.release(), ReleaseOutcome::Released); // EXPLICIT release

    // (2) PREMATURE ordering (armed defect reproduction): the covering reservation
    //     is released while the duplicate's evidence is still alive — a nonzero
    //     uncharged interval equal to the duplicate's owned backings. This is the
    //     discriminating regression: it FAILS (nonzero) under the premature ordering
    //     and PASSES (zero) under the correction.
    set_shared_release_order(SharedReleaseOrder::HolderBeforeRetained);
    let pp = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin_p = owner.capture_prepared_decision(pp, 1).expect("shared capture (premature)");
    assert_eq!(
        shared_dup_live_at_release(),
        Some(dup_bytes),
        "PREMATURE: the duplicate's evidence bytes are live-but-uncharged at release"
    );
    assert_eq!(pin_p.release(), ReleaseOutcome::Released);

    // (3) The seam is one-shot; the next shared capture is back to the correction.
    let pr = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin_r = owner.capture_prepared_decision(pr, 1).expect("shared capture (reset)");
    assert_eq!(
        shared_dup_live_at_release(),
        Some(0),
        "seam auto-reset to the corrected ordering after one shared capture"
    );
    drop(pin_r); // AUTOMATIC Drop cleanup of a shared entry

    // AUTOMATIC Drop of the fresh backing holder releases the last pin. The
    // registry allocation is RETAINED with its standing reservation (backend alive).
    drop(pin1);
    assert_eq!(
        op_current(&owner),
        registry_cell(),
        "all pins released/dropped; retained empty registry keeps its standing reservation"
    );

    // REFUSAL path shares nothing: a fresh proof read at the authoritative revision
    // but presented with a MISMATCHED expected revision is fenced out (StaleRevision)
    // before any conversion. On refusal the proof is returned and dropped; no entry
    // is created or shared, and the (already-installed) registry stays empty.
    let fresh = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    match owner.capture_prepared_decision(fresh, 999) {
        Err((_p, CaptureRefusal::StaleRevision { expected, found })) => {
            assert_eq!(expected, 999);
            assert_eq!(found, 1);
        }
        other => panic!("expected StaleRevision on refusal, got {other:?}"),
    }
    assert_eq!(
        op_current(&owner),
        registry_cell(),
        "refusal shares nothing; retained registry keeps only its standing reservation"
    );
    assert_eq!(
        owner
            .backend_for_test()
            .prepared_registry_for_test()
            .expect("registry retained")
            .lock()
            .unwrap()
            .occupied(),
        0,
        "no entry created on refusal"
    );

    // Restore sensitivity mutation explicitly (belt-and-braces).
    set_shared_release_order(SharedReleaseOrder::RetainedBeforeHolder);
    println!("[§2 lifetime N={n}] dup_bytes={dup_bytes} corrected=0 premature={dup_bytes}");
}

#[test]
fn spike_sharing_lifetime_regression_n1() {
    sharing_lifetime_regression(1);
}
#[test]
fn spike_sharing_lifetime_regression_n4() {
    sharing_lifetime_regression(4);
}

// ===========================================================================
// §2. DISCRIMINATING duplicate-release invariant, observed by an INDEPENDENT
// owned-object destruction probe (RUN 422 §2 B). A shared conversion must leave
// ZERO duplicate backing bytes alive when the covering reservation is released.
// This test asserts ONLY the correct outcome (`Some(0)`) read from
// `dup_backing_live_at_release()`, which samples the ACTUAL live-backing byte
// total at the release boundary (measured owned-object destruction, not
// allocation-address/identity tracing) — it is NOT derived from the selected
// `SharedReleaseOrder` branch (that narrower, branch-assigned observer is
// exercised separately by `spike_sharing_lifetime_regression`) and it is NOT a
// hard-coded expectation. Under the shipped source it PASSES; a source mutation
// that moves the covering reservation's release BEFORE the duplicate backing's
// destruction — with THIS observer and assertion left unchanged — makes it FAIL
// with a nonzero live count. The raw FAIL (mutated) and PASS (restored
// byte-identically) command outcomes are preserved in the evidence package
// (logs/04_dup_release_mutation_fail.log, 05_dup_release_restored_pass.log).
// ===========================================================================

fn duplicate_release_invariant(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    // Fresh conversion establishes the shared backing (slot 1).
    let p1 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let dup_bytes = p1.retained_evidence_capacity().expect("explicit capacity");
    assert!(dup_bytes > 0, "the duplicate will own non-empty evidence backings");
    let pin1 = owner.capture_prepared_decision(p1, 1).expect("fresh capture");

    // Shared conversion on the DEFAULT (shipped) ordering — NO seam is armed. The
    // duplicate's separately owned backings must be destroyed BEFORE the
    // reservation covering them is released. The INDEPENDENT probe measures the
    // real destruction of the duplicate backing object (by byte size) at the
    // release boundary.
    let pc = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin_c = owner
        .capture_prepared_decision(pc, 1)
        .expect("shared capture (default ordering)");
    assert_eq!(
        dup_backing_live_at_release(),
        Some(0),
        "INVARIANT: zero duplicate backing bytes remain live when their covering reservation is released"
    );
    assert_eq!(pin_c.release(), ReleaseOutcome::Released);
    drop(pin1);
    // The retained empty registry keeps its standing reservation (backend alive).
    assert_eq!(op_current(&owner), registry_cell());
    println!("[§2-inv N={n}] dup_bytes={dup_bytes} independent_live_at_release=0 (discriminating; nonzero under a release-before-destruction source mutation)");
}

#[test]
fn spike_duplicate_release_invariant_n1() {
    duplicate_release_invariant(1);
}
#[test]
fn spike_duplicate_release_invariant_n4() {
    duplicate_release_invariant(4);
}

// ===========================================================================
// §3. Distinct generations coexisting through O4 while TWO prepared generations
// remain pinned; the complete accounting (context ownership + both generations +
// registry cell + pins + the O4 publication reservation) is measured against the
// UNCHANGED aggregate ceiling. A full registry refuses a third capture WITHOUT
// eviction. Reports honest success (coexistence fits) or the exact shortfall.
// ===========================================================================

/// The contemporaneous in-operation O4 observation, captured by a bounded,
/// one-shot pre-effective sampler fired at the real O4 phase (after the
/// publication's durability acknowledgement and BEFORE the O4 working-set
/// reservation is released, while both prepared generations remain pinned). It
/// records BOTH kinds of evidence kept deliberately distinct:
/// * `in_op` / `in_agg` — the **reservation observations** (the operational and
///   aggregate charges sampled from the shared ledger at that phase), and
/// * `measured_prepared_objects` / `occupied` — an **object measurement** of the
///   live pinned-generation graph (each live `Arc<GenerationBacking>` measured in
///   place from its retained inline size + its MEASURED evidence-backing
///   capacity + the shared-allocation overhead + the holder/control bytes, plus
///   the registry cell once and one pin per live pin). It is derived from the
///   live objects, never from a reservation counter.
struct O4LiveSample {
    in_op: u128,
    in_agg: u128,
    measured_prepared_objects: u128,
    occupied: usize,
}

fn distinct_generations_and_full(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    let cap = owner.backend_for_test().accounting_aggregate_cap().unwrap();
    let history = committed_history();

    // Context ownership is a standing partition charge present before any capture.
    let context_ownership = agg_current(&owner);
    assert!(context_ownership > 0, "context ownership partition is charged standing");

    // rev 1: lock A — a MAXIMUM complete anchored QC fixture (ALL N signers,
    // maximum-length signatures, committed anchor + predecessor, affirmed by the
    // independently-supplied committed history). Capture entry 1 (generation A).
    match owner.publish_locked(max_qc_lock(&ctx, [0x11u8; 32], 5), 0, Some(&history)) {
        PublishResult::DurableAcknowledged { new_revision: 1 } => {}
        other => panic!("lock A publish: {other:?}"),
    }
    let pa = owner.read_validate(Some(&history)).unwrap();
    let ga = prepared_generation_charge(&ctx, pa.retained()).unwrap();
    assert!(ga <= max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap());
    let pin1 = owner.capture_prepared_decision(pa, 1).expect("capture A");
    let control = control_charge();
    assert_eq!(op_current(&owner), ga + control + registry_cell() + pin_bytes());
    let agg_one_pinned = agg_current(&owner);
    assert_eq!(agg_one_pinned, context_ownership + ga + control + registry_cell() + pin_bytes());

    // Assembling a SECOND distinct generation requires an O4 publication (a new
    // authoritative lock B, again a maximum anchored QC fixture) WHILE entry 1 is
    // pinned — the capture reservations and the O4 publication reservation must
    // overlap (conversion overlap). Measure the ACTUAL outcome honestly against the
    // UNCHANGED aggregate ceiling; do NOT raise limits or redefine exclusions.
    let lock_b = max_qc_lock(&ctx, [0x22u8; 32], 9);
    let lock_b_same = lock_b.clone(); // retained to retry the SAME publication on refusal
    match owner.publish_locked(lock_b, 1, Some(&history)) {
        // --- SUCCESS: the two distinct generations can coexist through O4 ---------
        PublishResult::DurableAcknowledged { new_revision: 2 } => {
            let pb = owner.read_validate(Some(&history)).unwrap();
            let gb = prepared_generation_charge(&ctx, pb.retained()).unwrap();
            let pin2 = owner.capture_prepared_decision(pb, 2).expect("capture B");

            // Two DISTINCT generations (NOT shared): two cores + two controls + one
            // registry cell + two pins.
            let coexist = ga + gb + 2 * control + registry_cell() + 2 * pin_bytes();
            assert_eq!(op_current(&owner), coexist, "two distinct generations' combined live objects");
            {
                let reg = owner.backend_for_test().prepared_registry_for_test().expect("registry installed");
                let g = reg.lock().unwrap();
                assert_eq!(g.inspect(pin1.handle()).unwrap().backing_shares, 1, "distinct backing A");
                assert_eq!(g.inspect(pin2.handle()).unwrap().backing_shares, 1, "distinct backing B");
                assert_eq!(g.occupied(), 2);
                assert!(g.is_full(), "both slots occupied");
            }
            let aggregate_with_two = agg_current(&owner);
            assert_eq!(
                aggregate_with_two,
                context_ownership + coexist,
                "aggregate = context ownership + the two pinned generations' objects"
            );
            assert!(
                aggregate_with_two <= cap,
                "COEXISTENCE FITS: aggregate {aggregate_with_two} <= ceiling {cap}"
            );

            // PRE-OPERATION headroom: the ceiling slack measured BEFORE the O4 even
            // begins (the sample `aggregate_with_two` is taken while both generations
            // are pinned but no O4 reservation is yet live). Reported separately from
            // the contemporaneous in-operation observation below.
            let pre_operation_headroom = cap - aggregate_with_two;

            // Task 1 — CONTEMPORANEOUS in-operation O4 observation. Install a bounded,
            // one-shot sampler fired at a REAL O4 phase: after the publication's
            // durability acknowledgement and BEFORE the O4 working-set reservation is
            // released, while BOTH prepared generations remain pinned. At that phase it
            // records (a) the RESERVATION observations (operational + aggregate charges)
            // and (b) an independent OBJECT MEASUREMENT of the live pinned-generation
            // graph — each live `Arc<GenerationBacking>` measured in place from its
            // retained inline size + its MEASURED evidence-backing capacity + the
            // shared-allocation overhead + the holder/control bytes, plus the registry
            // cell once and one pin per live pin. The pinned graph is inspected through
            // the registry's LEAF mutex (never the serialization domain the publish
            // holds), so no clone of the measured graph is taken and no lifetime is
            // extended. On a REFUSED O4 (N=1 below) the publication never reaches this
            // phase, so the slot stays `None` — no admitted O4 phase is fabricated.
            //
            // Task 2 — the sampler is NON-CYCLIC: it captures an independent accounting
            // handle (`accounting_handle_for_test`) and a leaf registry `Arc`, NOT a
            // cloned `SafetyBackend`. The earlier cloned-backend callback was retained
            // by the backend's own shared hook slot, forming a reference cycle that kept
            // the backend (and thus the registry reservation) alive forever; capturing
            // the ledger/registry handles instead breaks that cycle.
            let o4_phase_sample: std::sync::Arc<std::sync::Mutex<Option<O4LiveSample>>> =
                std::sync::Arc::new(std::sync::Mutex::new(None));
            {
                let acct = owner.backend_for_test().accounting_handle_for_test();
                let reg = owner
                    .backend_for_test()
                    .prepared_registry_for_test()
                    .expect("registry installed before the O4 sampler");
                let h1 = pin1.handle();
                let h2 = pin2.handle();
                let reg_cell = registry_cell();
                let pin_each = pin_bytes();
                let rr_inline = size_of_retained_record();
                let control = control_charge();
                let slot = std::sync::Arc::clone(&o4_phase_sample);
                owner
                    .backend_for_test()
                    .set_pre_effective_hook(std::sync::Arc::new(move |op, _rev| {
                        if op == "O4" {
                            let mut g = slot.lock().unwrap();
                            if g.is_none() {
                                // Object measurement of the live pinned-generation graph
                                // (leaf registry lock; the publish holds only the domain).
                                let reg_guard = reg.lock().unwrap();
                                let occupied = reg_guard.occupied();
                                // PHASE GUARD: record ONLY the genuine TWO-PIN O4 — the
                                // phase at which both measured prepared generations are
                                // actually live. A later admitted O4 on this backend (the
                                // N=1 abandon-and-retry below, which runs with one pin
                                // already released) is NOT the sampled phase, so it is
                                // skipped rather than fabricating a sample for objects that
                                // are no longer all live. The two-pin O4 is refused at N=1,
                                // so the slot correctly stays `None` there.
                                if occupied != 2 {
                                    return;
                                }
                                // Reservation observations (sampled from the shared
                                // ledger via the independent handle).
                                let in_op = acct.current();
                                let in_agg = acct.aggregate().current();
                                let mut measured_prepared_objects =
                                    reg_cell + (occupied as u128) * pin_each;
                                for h in [h1, h2] {
                                    // Missing measurement fails explicitly (the inspector
                                    // panics on a failed backing-capacity measurement) —
                                    // never a silent 0.
                                    let v = reg_guard
                                        .inspect(h)
                                        .expect("pinned generation live at the two-pin O4 phase");
                                    // actual object = generation core (retained inline +
                                    // MEASURED evidence backings + Arc overhead) +
                                    // holder/control bytes.
                                    measured_prepared_objects += rr_inline
                                        + (v.evidence_backing_capacity as u128)
                                        + ARC_CTRL
                                        + control;
                                }
                                *g = Some(O4LiveSample {
                                    in_op,
                                    in_agg,
                                    measured_prepared_objects,
                                    occupied,
                                });
                            }
                        }
                    }));
            }

            // Measure THROUGH O4 (a further authoritative publication, lock C) WHILE
            // BOTH distinct generations remain pinned. This overlaps the two live
            // generations' reservations with an O4 publication reservation. Honour the
            // UNCHANGED ceiling: report the ACTUAL outcome, do not raise limits. The
            // candidate is CLONED so the SAME publication can be retried on refusal.
            let lock_c = max_qc_lock(&ctx, [0x33u8; 32], 13);
            let lock_c_same = lock_c.clone();

            // BEFORE the two-pin O4 (Task 2): snapshot the ACTUAL comparable state so
            // the refusal can be shown to mutate nothing. Capture the COMPLETE stored
            // record bytes and COMPLETE stored metadata bytes by value; the publication
            // revision, the owner's recovery_required() latch, and both retained pins'
            // generation identities/provenance separately. Every temporary read proof
            // is released BEFORE the operational/aggregate baselines are sampled, so no
            // transient reservation perturbs the measured baselines.
            let record_bound = max_safety_record_bytes(&ctx).unwrap();
            let before_record_bytes = owner
                .backend_for_test()
                .read_record(record_bound)
                .unwrap()
                .expect("authoritative record present before the refused O4");
            let before_meta_bytes = owner
                .backend_for_test()
                .read_meta(record_bound)
                .unwrap()
                .expect("authoritative metadata present before the refused O4");
            let before_rev = {
                let before = owner.read_validate(Some(&history)).unwrap();
                assert!(
                    before.recovery_backend_incarnation().is_some(),
                    "recovery (O5) capability present before the refused O4"
                );
                before.publication_revision()
            };
            let before_recovery_required = owner.recovery_required();
            // Both pins' retained generation identities/provenance (not occupancy):
            // identity, serial, captured revision, originating incarnation/context,
            // evidence status, and retained evidence-backing capacity.
            let before_pin1 =
                inspect_pin(&owner, pin1.handle()).expect("pin1 live before the refused O4");
            let before_pin2 =
                inspect_pin(&owner, pin2.handle()).expect("pin2 live before the refused O4");
            let before_occupied = registry_occupied(&owner);
            assert_eq!(before_occupied, 2, "both pins retained before the refused O4");
            // Operational AND aggregate baselines sampled LAST, after every temporary
            // proof above is dropped.
            let before_op = op_current(&owner);
            let before_agg = agg_current(&owner);

            match owner.publish_locked(lock_c, 2, Some(&history)) {
                PublishResult::DurableAcknowledged { new_revision: 3 } => {
                    assert_eq!(op_current(&owner), coexist, "O4 reservation released; two generations intact");

                    // Task 1 — the CONTEMPORANEOUS in-operation O4 observation (reached
                    // only on the N=4 success path, where the O4 was actually admitted).
                    // Distinct from the pre-operation headroom captured above.
                    let O4LiveSample {
                        in_op,
                        in_agg,
                        measured_prepared_objects,
                        occupied,
                    } = o4_phase_sample
                        .lock()
                        .unwrap()
                        .take()
                        .expect("the O4 post-acknowledgement / pre-release phase was sampled");
                    assert_eq!(occupied, 2, "both prepared generations were live at the sampled O4 phase");

                    // OBJECT MEASUREMENT (kept separate from the reservation counters and
                    // from the source-derived `coexist` arithmetic): the live pinned graph
                    // measured in place equals the source-derived `coexist` charge exactly.
                    assert_eq!(
                        measured_prepared_objects, coexist,
                        "measured live pinned-generation objects equal the source-derived coexist charge"
                    );

                    // The O4-OWNED live objects at the pre-effective phase: the transient
                    // decoded working set plus the retained encoded publication buffer the
                    // publication still holds live at that phase. Derived INDEPENDENTLY from
                    // the SAME lock C fixture (actual inline sizes + MEASURED evidence-backing
                    // capacities + the real encoded length), not from the live graph and not
                    // from a reservation counter. The already-destroyed staging envelopes are
                    // NOT counted: `publish_atomic` has returned by this phase.
                    let decoded_c = DecodedRecord {
                        persistence_format_version: 1,
                        network_genesis_id: ctx.network_genesis_id,
                        publication_revision: 3,
                        record: SafetyRecord::Locked(lock_c_same),
                    };
                    let o4_decoded_object = decoded_working_set_charge(&decoded_c)
                        .expect("O4 decoded working-set object measurement");
                    let o4_encoded_object = encode_record(&decoded_c, &ctx)
                        .expect("O4 encoded publication buffer measurement")
                        .len() as u128;
                    let o4_owned_objects = o4_decoded_object + o4_encoded_object;

                    // The MEASURED live-object total at the O4 phase (object measurements
                    // only; NOT a reservation counter).
                    let measured_live_objects = measured_prepared_objects + o4_owned_objects;

                    // (1) measured live-object charge <= contemporaneous covering operational
                    // reservation.
                    assert!(
                        measured_live_objects <= in_op,
                        "measured live objects {measured_live_objects} (pinned {measured_prepared_objects} + O4-owned {o4_owned_objects}) <= contemporaneous operational reservation {in_op}"
                    );
                    // (2) context + operational reservations <= UNCHANGED aggregate ceiling,
                    // AT the phase (not merely before it).
                    assert_eq!(
                        in_agg,
                        context_ownership + in_op,
                        "aggregate = context ownership + operational AT the O4 phase"
                    );
                    assert!(
                        in_agg <= cap,
                        "the UNCHANGED aggregate ceiling {cap} is honored AT the O4 phase (in-operation aggregate {in_agg}), not merely before it"
                    );

                    // Source-derived bound, kept separate from the two measurements above:
                    // the live O4 working-set reservation at the sampled phase.
                    let o4_reservation = in_op - coexist;
                    assert!(
                        o4_reservation > 0,
                        "a real O4 working-set reservation was held at the sampled phase"
                    );
                    let in_operation_headroom = cap - in_agg;

                    // A THIRD capture is refused WITHOUT eviction; returned proof intact.
                    let pc = owner.read_validate(Some(&history)).unwrap();
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
                    assert_eq!(
                        owner.backend_for_test().prepared_registry_for_test().expect("registry installed").lock().unwrap().occupied(),
                        2,
                        "no eviction on refusal"
                    );
                    println!(
                        "[§3 distinct N={n}] RESULT=COEXIST_THROUGH_O4 context_ownership={context_ownership} ga={ga}                  gb={gb} coexist={coexist} aggregate={aggregate_with_two} cap={cap}                  pre_operation_headroom={pre_operation_headroom}                  in_operation[op={in_op} agg={in_agg} o4_reservation={o4_reservation} headroom={in_operation_headroom}]                  measured_live_objects[total={measured_live_objects} pinned={measured_prepared_objects} o4_owned={o4_owned_objects} (decoded={o4_decoded_object} encoded={o4_encoded_object})]                  (pre-operation headroom is the slack BEFORE the O4; the in-operation sample is taken at a real O4 phase while both generations stay pinned and the O4 reservation is live; the measured live-object total is <= the operational reservation and the unchanged ceiling holds AT that phase)"
                    );

                    // Cleanup/readmission: release both; the registry allocation is
                    // retained with its standing reservation (backend alive).
                    assert_eq!(owner.release_prepared(pin1), ReleaseOutcome::Released);
                    assert_eq!(owner.release_prepared(pin2), ReleaseOutcome::Released);
                    assert_eq!(op_current(&owner), registry_cell(), "both released; retained registry charged");
                    assert_eq!(
                        agg_current(&owner),
                        context_ownership + registry_cell(),
                        "aggregate back to context ownership + the standing registry reservation"
                    );

                    // Task 2 — sampler teardown. With the backend-retaining cycle removed,
                    // dropping the owner releases the backend, its serialization domain, the
                    // installed registry, AND the installed sampler (which held only the
                    // independent ledger/registry handles). An INDEPENDENT accountant,
                    // captured before teardown, then observes NO remaining registry or
                    // generation reservation. (Retaining the empty charged registry while a
                    // genuine backend owner remained alive — asserted just above — was still
                    // correct; this verifies the final release once that owner drops too.)
                    let teardown_acct = owner.backend_for_test().accounting_handle_for_test();
                    drop(owner);
                    assert_eq!(
                        teardown_acct.current(),
                        0,
                        "after pins, proofs, owner/backend, and the non-cyclic sampler are released, no registry or generation reservation remains"
                    );
                }
                // --- TWO-PIN PUBLICATION REFUSAL: the actual before/after/abandon/retry ---
                PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(
                    CapacityRefusalDetail::AdmissionOverflow { next, cap: ov_cap, .. },
                )) => {
                    assert_eq!(ov_cap, cap, "refusal is against the unchanged aggregate ceiling");
                    let shortfall = next - cap;
                    assert!(shortfall > 0, "a positive shortfall is reported");
                    // Honest N=1 refusal: the O4 was never admitted, so no in-operation
                    // O4 phase was sampled. Do not fabricate an admitted phase.
                    assert!(
                        o4_phase_sample.lock().unwrap().is_none(),
                        "no admitted O4 phase was sampled for the REFUSED operation"
                    );
                    // AFTER the refused two-pin O4 (Task 2): the refusal mutated NOTHING.
                    // Compare the COMPLETE stored record bytes, the COMPLETE stored
                    // metadata bytes, the publication revision (separately), the owner's
                    // recovery_required() latch, and both pins' retained generation
                    // identities/provenance. Occupancy alone is insufficient — the pin
                    // identities are compared field by field. Temporary read proofs are
                    // released before the operational/aggregate baselines are compared.
                    let after_record_bytes = owner
                        .backend_for_test()
                        .read_record(record_bound)
                        .unwrap()
                        .expect("authoritative record still present after the refused O4");
                    let after_meta_bytes = owner
                        .backend_for_test()
                        .read_meta(record_bound)
                        .unwrap()
                        .expect("authoritative metadata still present after the refused O4");
                    assert_eq!(
                        after_record_bytes, before_record_bytes,
                        "complete stored record bytes unchanged by the refused O4"
                    );
                    assert_eq!(
                        after_meta_bytes, before_meta_bytes,
                        "complete stored metadata bytes unchanged by the refused O4"
                    );
                    {
                        let after = owner.read_validate(Some(&history)).unwrap();
                        assert_eq!(
                            after.publication_revision(),
                            before_rev,
                            "publication revision unchanged by the refused O4"
                        );
                    }
                    assert_eq!(
                        owner.recovery_required(),
                        before_recovery_required,
                        "owner.recovery_required() unchanged by the refused O4"
                    );
                    let after_pin1 = inspect_pin(&owner, pin1.handle())
                        .expect("pin1 still resolves to its retained generation after the refused O4");
                    let after_pin2 = inspect_pin(&owner, pin2.handle())
                        .expect("pin2 still resolves to its retained generation after the refused O4");
                    assert_same_provenance("pin1", &before_pin1, &after_pin1);
                    assert_same_provenance("pin2", &before_pin2, &after_pin2);
                    assert_eq!(
                        registry_occupied(&owner),
                        before_occupied,
                        "both generations stay pinned; the refused O4 mutated nothing"
                    );
                    // Operational AND aggregate reservations returned to the pre-operation
                    // baseline sampled before the refusal.
                    assert_eq!(
                        op_current(&owner),
                        before_op,
                        "operational reservation returned to the pre-operation baseline"
                    );
                    assert_eq!(
                        agg_current(&owner),
                        before_agg,
                        "aggregate reservation returned to the pre-operation baseline"
                    );
                    assert_eq!(op_current(&owner), coexist, "operational charge is still the two pinned generations");

                    // ABANDON the necessary pin (pin1) to create headroom. The registry
                    // allocation is retained with its standing reservation; one slot frees.
                    assert_eq!(owner.release_prepared(pin1), ReleaseOutcome::Released);
                    assert_eq!(
                        owner.backend_for_test().prepared_registry_for_test().expect("registry installed").lock().unwrap().occupied(),
                        1,
                        "one slot freed after abandoning pin1; the other generation stays pinned"
                    );
                    assert_eq!(op_current(&owner), gb + control + registry_cell() + pin_bytes(), "one generation + standing registry remain");

                    // RETRY the SAME refused publication (byte-identical lock C, same
                    // expected revision 2). Readmission now succeeds to rev 3.
                    match owner.publish_locked(lock_c_same, 2, Some(&history)) {
                        PublishResult::DurableAcknowledged { new_revision: 3 } => {}
                        other => panic!("readmitted SAME lock C publish: {other:?}"),
                    }
                    // CLEANUP + readmission of a capture against the readmitted rev 3.
                    let pc2 = owner.read_validate(Some(&history)).unwrap();
                    let gc = prepared_generation_charge(&ctx, pc2.retained()).unwrap();
                    let pin3 = owner.capture_prepared_decision(pc2, 3).expect("readmitted capture into the freed slot");
                    assert_eq!(op_current(&owner), gb + gc + 2 * control + registry_cell() + 2 * pin_bytes(), "readmitted second generation pinned");
                    println!(
                        "[§3 distinct N={n}] RESULT=COEXIST_REFUSE_O4 context_ownership={context_ownership} ga={ga}                  gb={gb} coexist={coexist} aggregate={aggregate_with_two} cap={cap} pre_operation_headroom={pre_operation_headroom}                  o4_next={next} shortfall={shortfall} in_operation_o4_phase=NONE(refused)                  (two generations coexist while pinned; the O4 through both is REFUSED against the unchanged ceiling, so there is no admitted in-operation O4 phase; the refusal mutated nothing; abandon pin1, retry the SAME lock C -> readmitted rev 3)"
                    );

                    // Release everything; the registry keeps its standing reservation.
                    assert_eq!(owner.release_prepared(pin2), ReleaseOutcome::Released);
                    assert_eq!(owner.release_prepared(pin3), ReleaseOutcome::Released);
                    assert_eq!(op_current(&owner), registry_cell(), "all released; retained registry charged");
                    assert_eq!(
                        agg_current(&owner),
                        context_ownership + registry_cell(),
                        "aggregate back to context ownership + the standing registry reservation"
                    );
                }
                other => panic!("unexpected O4-through-two-pinned outcome: {other:?}"),
            }
        }
        // --- CONSERVATIVE REFUSAL: complete accounting prevents even a second gen ---
        PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(
            CapacityRefusalDetail::AdmissionOverflow { next, cap: ov_cap, .. },
        )) => {
            assert_eq!(ov_cap, cap, "refusal is against the unchanged aggregate ceiling");
            let shortfall = next - cap;
            assert!(shortfall > 0, "a positive shortfall is reported");
            // The registry is unchanged; the first generation is still pinned/intact.
            assert_eq!(
                owner.backend_for_test().prepared_registry_for_test().expect("registry installed").lock().unwrap().occupied(),
                1,
                "the first generation stays pinned; the refusal mutated nothing"
            );
            assert_eq!(agg_current(&owner), agg_one_pinned, "no charge leaked by the refused O4");

            // CLEANUP: abandon the first generation so the aggregate has headroom.
            assert_eq!(owner.release_prepared(pin1), ReleaseOutcome::Released);
            assert_eq!(op_current(&owner), registry_cell(), "cleanup; retained registry charged");

            // READMISSION: the SAME O4 (byte-identical lock B) now succeeds once the pin
            // is gone, and a fresh generation can be captured against it.
            match owner.publish_locked(lock_b_same, 1, Some(&history)) {
                PublishResult::DurableAcknowledged { new_revision: 2 } => {}
                other => panic!("readmitted SAME lock B publish: {other:?}"),
            }
            let pb = owner.read_validate(Some(&history)).unwrap();
            let gb = prepared_generation_charge(&ctx, pb.retained()).unwrap();
            let pin2 = owner.capture_prepared_decision(pb, 2).expect("readmitted capture B");
            assert_eq!(op_current(&owner), gb + control + registry_cell() + pin_bytes());
            println!(
                "[§3 distinct N={n}] RESULT=CONSERVATIVE_REFUSAL context_ownership={context_ownership}                  ga={ga} one_pinned_aggregate={agg_one_pinned} cap={cap} o4_next={next} shortfall={shortfall}                  (coexistence of a pinned generation with a concurrent O4 exceeds the unchanged ceiling;                  abandon pin1, retry the SAME lock B -> readmitted)"
            );
            assert_eq!(owner.release_prepared(pin2), ReleaseOutcome::Released);
            assert_eq!(op_current(&owner), registry_cell(), "readmitted generation released; registry retained");
        }
        other => panic!("unexpected O4-while-pinned outcome: {other:?}"),
    }
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
// §2/§3. Normal explicit release AND automatic abandonment (Drop) both clean up
// to the baseline while the backend stays alive and usable.
// ===========================================================================

fn release_and_abandonment(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    // Normal explicit release. The registry allocation (installed by this capture)
    // is RETAINED with its standing reservation after the entry is released.
    let p1 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin1 = owner.capture_prepared_decision(p1, 1).unwrap();
    assert!(op_current(&owner) > 0);
    assert_eq!(owner.release_prepared(pin1), ReleaseOutcome::Released);
    assert_eq!(op_current(&owner), registry_cell(), "normal release; retained registry charged");

    // Automatic abandonment: drop the pin WITHOUT releasing (registry reused, no
    // duplicate charge). Cleanup leaves the retained registry with its reservation.
    let p2 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin2 = owner.capture_prepared_decision(p2, 1).unwrap();
    // One registry charge only (reused): live total is the registry cell + the
    // entry's generation/pin charges, strictly above the standing baseline.
    assert!(op_current(&owner) > registry_cell(), "reused registry carries an entry above the standing cell");
    drop(pin2); // non-Copy guard Drop performs cleanup
    assert_eq!(op_current(&owner), registry_cell(), "abandonment (Drop) cleans to the retained-registry baseline");
    {
        let reg = owner.backend_for_test().prepared_registry_for_test().expect("registry installed");
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
// Provenance-gate refusals — each returns the proof intact and mints nothing.
// ===========================================================================

#[test]
fn spike_refuse_bootstrap_unresolved() {
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
    let ctx = ctx_n(4);
    let foreign = ctx_n_foreign(4);
    let dir = tempfile::tempdir().unwrap();
    let backend = open_enabled(dir.path());
    let owner = SafetyRecordOwner::attach(backend.clone(), ctx.clone()).unwrap();
    owner.initialize(true).unwrap();
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();

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
// Counter exhaustion fails closed BEFORE mutation; stale/foreign handles refused.
// ===========================================================================

#[test]
fn spike_counter_exhaustion_fails_closed() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    // A first successful capture lazily ALLOCATES and installs the registry (with
    // its standing reservation). Only now can the serial counter be driven to the
    // brink — before any capture there is no registry to exhaust.
    let p0 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin0 = owner.capture_prepared_decision(p0, 1).expect("first capture installs the registry");
    {
        let reg = owner.backend_for_test().prepared_registry_for_test().expect("registry installed");
        reg.lock().unwrap().force_next_serial(u64::MAX);
    }

    // A second capture now refuses with CounterExhausted, failing closed BEFORE any
    // mutation. The refusal is AFTER registry initialization: the installed registry
    // (and its standing reservation) is RETAINED, not revived or re-charged.
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let before = op_current(&owner); // pin0 entry + registry cell + refused proof holder
    match owner.capture_prepared_decision(proof, 1) {
        Err((p, CaptureRefusal::CounterExhausted)) => {
            assert!(p.recovery_backend_incarnation().is_some(), "proof intact on counter exhaustion");
            // Fail-closed BEFORE any mutation: no new prepared reservation leaked and
            // the retained registry keeps exactly its standing + first-entry charges.
            assert_eq!(op_current(&owner), before, "no charge leaked on counter exhaustion");
        }
        other => panic!("expected CounterExhausted, got {other:?}"),
    }
    assert_eq!(
        owner.backend_for_test().prepared_registry_for_test().expect("registry installed").lock().unwrap().occupied(),
        1,
        "no new entry inserted; only the first capture's entry remains"
    );
    drop(pin0);
}

#[test]
fn spike_stale_and_foreign_handles_refused() {
    let ctx = ctx_n(4);
    let dir_a = tempfile::tempdir().unwrap();
    let owner_a = init_owner(dir_a.path(), &ctx);
    publish_qc(&owner_a, &ctx, [9u8; 32], 5, 0);
    let pa = owner_a.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin = owner_a.capture_prepared_decision(pa, 1).unwrap();
    let handle = pin.handle();

    // Foreign incarnation: present A's handle to B's registry. B must first capture
    // once to lazily allocate its own (distinct-incarnation) registry.
    let dir_b = tempfile::tempdir().unwrap();
    let owner_b = init_owner(dir_b.path(), &ctx);
    publish_qc(&owner_b, &ctx, [9u8; 32], 5, 0);
    let pb = owner_b.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin_b = owner_b.capture_prepared_decision(pb, 1).expect("B installs its own registry");
    {
        let reg_b = owner_b
            .backend_for_test()
            .prepared_registry_for_test()
            .expect("B registry installed");
        assert_eq!(
            reg_b.lock().unwrap().release_by_handle(handle),
            ReleaseOutcome::ForeignIncarnation,
            "foreign-incarnation handle refused"
        );
    }
    drop(pin_b);

    // Stale serial: release the real entry, then re-release the same handle.
    let reg_a = owner_a.backend_for_test().prepared_registry_for_test().expect("registry installed");
    assert_eq!(reg_a.lock().unwrap().release_by_handle(handle), ReleaseOutcome::Released);
    assert_eq!(
        reg_a.lock().unwrap().release_by_handle(handle),
        ReleaseOutcome::NotFound,
        "stale serial refused"
    );
    drop(pin);
}

// ===========================================================================
// §3. Admission refusal BEFORE new allocation; cleanup to the correct baseline;
// O5 recovery exercised with the ACTUAL returned refused proof after releasing
// artificial pressure (byte-for-byte comparison + recovery outcome); readmission.
// ===========================================================================

fn admission_refusal_and_readmission(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    let cap = owner.backend_for_test().accounting_aggregate_cap().unwrap();

    // Read the real proof we will try (and fail) to capture; its holder is live.
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let core = prepared_generation_charge(&ctx, proof.retained()).unwrap();
    let control = control_charge();
    let proof_rev = proof.publication_revision();
    let proof_enc_cap = proof.encoded_capacity();

    // The capture reserves, in order: the registry cell (lazy allocation, admitted
    // before the registry is created), the owning pin, then the generation core,
    // then the control. Leave headroom for registry-cell + pin + core but ONE byte
    // short of the control, so admission is refused on the LAST reservation —
    // exercising cleanup of the pin + core, with the just-installed registry RETAINED.
    let entry_pre = registry_cell() + pin_bytes() + core;
    let used = owner.backend_for_test().accounting_aggregate_current();
    let standing_charge = cap - used - entry_pre - (control - 1);
    let standing = owner
        .backend_for_test()
        .reserve_standing_for_test(standing_charge)
        .expect("standing reservation admits (cell + pin + core fit, control does not)");
    let baseline_under_pressure = owner.backend_for_test().accounting_aggregate_current();

    match owner.capture_prepared_decision(proof, 1) {
        Err((returned, CaptureRefusal::Admission(_))) => {
            assert!(returned.recovery_backend_incarnation().is_some());
            assert_eq!(returned.encoded_capacity(), proof_enc_cap, "refused proof original bytes intact");
            assert_eq!(returned.publication_revision(), proof_rev, "revision unchanged");
            // A later capture step (the control reservation) refused AFTER registry
            // initialization: the chosen behavior is to RETAIN the just-installed
            // registry with its standing reservation. The pin + core reservations
            // taken before the failed one are released; no entry is published.
            assert_eq!(
                owner.backend_for_test().accounting_aggregate_current(),
                baseline_under_pressure + registry_cell(),
                "pin + core released; the just-installed registry is retained with its reservation"
            );
            assert_eq!(
                owner.backend_for_test().prepared_registry_for_test().expect("registry retained after refusal").lock().unwrap().occupied(),
                0,
                "no entry inserted on refusal"
            );

            // O5 with the ACTUAL returned refused proof, after releasing pressure.
            drop(standing);
            match owner.reacknowledge(&returned) {
                PublishResult::DurableAcknowledged { new_revision } => {
                    assert_eq!(new_revision, proof_rev, "O5 re-acknowledges the SAME revision");
                }
                other => panic!("expected O5 DurableAcknowledged on intact refused proof, got {other:?}"),
            }
            drop(returned);
        }
        other => panic!("expected Admission refusal, got {other:?}"),
    }

    // Readmission: capture a freshly read proof now that pressure is gone.
    let fresh = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    assert!(fresh.recovery_backend_incarnation().is_some());
    let pin = owner
        .capture_prepared_decision(fresh, 1)
        .map_err(|(_, r)| r)
        .expect("readmission succeeds once pressure is released");
    assert_eq!(
        owner.backend_for_test().prepared_registry_for_test().expect("registry installed").lock().unwrap().occupied(),
        1,
        "readmitted entry present"
    );
    assert_eq!(op_current(&owner), core + control + registry_cell() + pin_bytes(), "readmitted full charge (registry reused, charged once)");
    owner.release_prepared(pin);
    assert_eq!(op_current(&owner), registry_cell(), "readmitted entry released; registry retained with its reservation");
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
// §3. Deterministic capture/publication boundary: the capture reads the
// authoritative revision UNDER THE SERIALIZATION DOMAIN, so it linearizes with an
// O4 publication. This distinguishes correct serialization (a proof read before a
// publication boundary is refused as stale) from its removal (which would admit
// the stale proof). Deterministic — no threads, no timing.
// ===========================================================================

#[test]
fn spike_capture_publication_boundary() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0); // rev 1

    // A proof read at rev 1 is captured successfully BEFORE any boundary: the
    // authoritative revision read under the domain equals the proof's revision.
    let p_before = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin = owner
        .capture_prepared_decision(p_before, 1)
        .expect("capture at the authoritative revision (pre-boundary)");
    drop(pin);

    // Now cross a publication boundary: O4 advances to rev 2. A proof read at rev 1
    // and presented AFTER the boundary must be refused as stale — the capture re-reads
    // the authoritative revision under the domain rather than trusting the proof.
    let p_rev1 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    publish_qc(&owner, &ctx, [0x22u8; 32], 9, 1); // rev 2 (the boundary)
    match owner.capture_prepared_decision(p_rev1, 1) {
        Err((p, CaptureRefusal::StaleRevision { expected, found })) => {
            assert_eq!(expected, 1);
            assert_eq!(found, 2, "capture observed the post-boundary authoritative revision");
            assert_eq!(p.publication_revision(), 1, "stale proof returned intact");
        }
        other => panic!("expected StaleRevision across the boundary, got {other:?}"),
    }
    // Even asking for the correct new revision with a stale proof is refused (the
    // proof itself still carries rev 1): the boundary is on the authoritative read,
    // not merely the caller's expectation.
    let p_rev1b = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    publish_qc(&owner, &ctx, [0x33u8; 32], 13, 2); // rev 3
    // p_rev1b is now stale (rev 2 at read time, authoritative advanced to 3).
    match owner.capture_prepared_decision(p_rev1b, 2) {
        Err((_p, CaptureRefusal::StaleRevision { found, .. })) => assert_eq!(found, 3),
        other => panic!("expected StaleRevision, got {other:?}"),
    }
    // A fresh read at the authoritative revision captures successfully.
    let p_fresh = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin = owner.capture_prepared_decision(p_fresh, 3).expect("capture at authoritative rev");
    assert!(op_current(&owner) > 0);
    drop(pin);
}

// ===========================================================================
// §3. DISCRIMINATING capture/publication serialization OVERLAP (coordinated, not
// sequential). A capturer thread and a publisher thread are coordinated via a
// bounded test hook so the publisher attempts an O4 publication at the EXACT
// interval between the capture's authoritative-state check and its registry
// insertion. Because BOTH the capture and `publish_locked` take the shared
// serialization domain lock, correct serialization keeps the publisher BLOCKED
// for the whole interval: the capturer observes that the publication has NOT
// progressed (`observed_publish_during_interval == false`). Removing the
// serialization protection — a source mutation that releases the domain guard
// across this interval — lets the publisher interleave, the capturer observes the
// publication completing mid-interval, and THIS test FAILS. Raw fail/restore
// command outcomes are preserved in the evidence package
// (logs/06_serialization_mutation_fail.log, 07_serialization_restored_pass.log).
// ===========================================================================
#[test]
fn spike_capture_publication_serialization_overlap() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let ctx = Arc::new(ctx_n(4));
    let dir = tempfile::tempdir().unwrap();
    let owner = Arc::new(init_owner(dir.path(), &ctx));
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0); // rev 1

    // Prime the shared registry with a first fresh capture, so the instrumented
    // capture below exercises the check->insert interval on registry REUSE (the
    // serialization boundary in isolation, not first-initialization).
    let p0 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let prime = owner.capture_prepared_decision(p0, 1).expect("prime registry");
    assert_eq!(prime.release(), ReleaseOutcome::Released);

    let publisher_may_start = Arc::new(AtomicBool::new(false));
    let publisher_done = Arc::new(AtomicBool::new(false));
    let observed_publish_during_interval = Arc::new(AtomicBool::new(false));

    // Publisher thread: once released, attempt an O4 publication over rev 1. Under
    // correct serialization it blocks on the domain lock until the capturer's whole
    // check->insert interval completes.
    let publisher = {
        let owner = Arc::clone(&owner);
        let ctx = Arc::clone(&ctx);
        let may_start = Arc::clone(&publisher_may_start);
        let done = Arc::clone(&publisher_done);
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !may_start.load(Ordering::Acquire) {
                if Instant::now() > deadline {
                    break;
                }
                std::thread::yield_now();
            }
            // Blocks here on the serialization domain if the capturer holds it.
            let new_rev = publish_qc(&owner, &ctx, [0x22u8; 32], 9, 1);
            assert_eq!(new_rev, 2, "publisher advanced the authoritative revision to 2");
            done.store(true, Ordering::Release);
        })
    };

    // Capturer (this thread): install the one-shot interval hook, which releases the
    // publisher and then waits a bounded window before sampling whether the
    // publication has progressed. Correct serialization keeps it blocked ⇒ false.
    {
        let may_start = Arc::clone(&publisher_may_start);
        let done = Arc::clone(&publisher_done);
        let observed = Arc::clone(&observed_publish_during_interval);
        set_capture_interval_hook(move || {
            may_start.store(true, Ordering::Release);
            std::thread::sleep(Duration::from_millis(300));
            observed.store(done.load(Ordering::Acquire), Ordering::Release);
        });
    }

    let p = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin = owner
        .capture_prepared_decision(p, 1)
        .expect("capture succeeds at the unchanged revision under serialization");
    // The capture completed its guarded check->insert interval; release the pin.
    assert_eq!(pin.release(), ReleaseOutcome::Released);

    publisher.join().expect("publisher thread");

    // DISCRIMINATING assertion: the publication did NOT complete during the
    // capturer's guarded check->insert interval. A source mutation that drops the
    // serialization protection across this interval flips this to `true`.
    assert!(
        !observed_publish_during_interval.load(Ordering::Acquire),
        "SERIALIZATION: publication must not progress during the capture's guarded interval"
    );
    // The publication did eventually complete (strictly after the capture released
    // the domain), advancing the revision to 2.
    assert!(publisher_done.load(Ordering::Acquire), "publication completed after the capture");
    println!("[§3 overlap] serialized: publication blocked for the whole guarded interval; captured at rev 1, published rev 2 after release");
}

// ===========================================================================
// §3. Maximum complete TC-derived generation: capture retains the heaviest
// complete generation within the unchanged ceiling; charge decomposition holds.
// ===========================================================================

fn tc_generation_capture(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);

    let ltc = valid_tc_record(&ctx, 5, 4);
    assert!(
        matches!(&ltc.evidence, SupportingEvidence::TcDerived { tc, high_qc }
            if tc.signed_timeouts.len() as u64 == n
                && tc.signers.len() as u64 == n
                && high_qc.signers.len() as u64 == n
                && tc.high_qc.as_ref().is_some_and(|h| h.signers.len() as u64 == n)),
        "TC fixture: ALL N signer + timeout entries with full nested high-QC signers"
    );
    assert!(
        ltc.committed_anchor.is_some() && ltc.predecessor_ref.is_some(),
        "maximum fixture carries a committed anchor and a predecessor reference"
    );
    let history = committed_history();
    match owner.publish_locked(ltc, 0, Some(&history)) {
        PublishResult::DurableAcknowledged { new_revision: 1 } => {}
        other => panic!("TC publish: {other:?}"),
    }

    let proof = owner.read_validate(Some(&history)).unwrap();
    assert!(
        matches!(proof.retained().record, SafetyRecord::Locked(ref l) if matches!(l.evidence, SupportingEvidence::TcDerived { .. })),
        "retained TC generation"
    );
    let core = prepared_generation_charge(&ctx, proof.retained()).unwrap();
    let ceiling = max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap();
    assert!(core <= ceiling, "complete TC generation core within the unchanged ceiling");

    let pin = owner.capture_prepared_decision(proof, 1).expect("capture TC generation");
    assert_eq!(op_current(&owner), core + control_charge() + registry_cell() + pin_bytes());
    println!("[tc N={n}] tc_core={core} control={} ceiling={ceiling}", control_charge());
    drop(pin);
    assert_eq!(op_current(&owner), registry_cell(), "entry released; registry retained with its reservation");
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
// Evidence/context binding: the captured entry carries exactly the proof's
// provenance (context digest, incarnation, revision, evidence status).
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
    let reg = owner.backend_for_test().prepared_registry_for_test().expect("registry installed");
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

// ===========================================================================
// §LT. FOCUSED ALLOCATION-LIFETIME EVIDENCE (lazy registry allocation).
//
// These tests exercise the registry's ACTUAL allocation lifetime directly —
// using `prepared_registry_for_test()` (allocation presence) alongside the
// aggregate charge (reservation presence):
//   - open/attach without capture        -> no allocation, no charge
//   - first-capture admission refusal     -> no uncharged allocation
//   - successful first capture            -> admission precedes allocation
//   - shared handles                      -> one registry, one covering reservation
//   - last entry release, backend alive   -> retained registry stays charged
//   - subsequent capture                  -> reuse, no duplicate charge
//   - final destruction, pin > owner      -> reservation released at the end
// ===========================================================================

#[test]
fn spike_lt_open_attach_without_capture_no_allocation() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);

    // Before any prepared capture there is NO registry allocation and NO
    // prepared/registry charge on the operational ledger.
    assert!(
        owner.backend_for_test().prepared_registry_for_test().is_none(),
        "no registry allocation exists before the first prepared capture"
    );
    assert_eq!(op_current(&owner), 0, "no prepared storage charged at open/attach");

    // Ordinary attachment work (an O4 publish) does not allocate the registry.
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);
    assert!(
        owner.backend_for_test().prepared_registry_for_test().is_none(),
        "ordinary publish does not allocate the prepared registry"
    );
    assert_eq!(op_current(&owner), 0, "ordinary publish charges no prepared storage");

    // A read-validate alone (no capture) still does not allocate.
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    assert!(
        owner.backend_for_test().prepared_registry_for_test().is_none(),
        "read-validate without capture does not allocate the registry"
    );
    drop(proof);
}

#[test]
fn spike_lt_first_capture_admission_refusal_no_uncharged_allocation() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let cap = owner.backend_for_test().accounting_aggregate_cap().unwrap();
    let used = owner.backend_for_test().accounting_aggregate_current();

    // Leave headroom ONE byte short of the registry-storage charge, so the FIRST
    // persistent reservation of the capture (the registry cell, admitted before
    // any allocation) is refused — exercising insufficient admission on the very
    // first prepared capture.
    let standing_charge = cap - used - (registry_cell() - 1);
    let standing = owner
        .backend_for_test()
        .reserve_standing_for_test(standing_charge)
        .expect("standing reservation admits (one byte short of the registry cell)");
    let before = owner.backend_for_test().accounting_aggregate_current();

    match owner.capture_prepared_decision(proof, 1) {
        Err((returned, CaptureRefusal::Admission(_))) => {
            assert!(returned.recovery_backend_incarnation().is_some(), "proof returned intact");
            // No registry storage was created and no charge leaked: the proof is
            // returned intact WITHOUT publishing an entry or allocating a registry.
            assert!(
                owner.backend_for_test().prepared_registry_for_test().is_none(),
                "no registry allocation created on insufficient admission"
            );
            assert_eq!(
                owner.backend_for_test().accounting_aggregate_current(),
                before,
                "no uncharged allocation; nothing leaked on first-capture refusal"
            );
            drop(returned);
        }
        other => panic!("expected Admission refusal on the registry cell, got {other:?}"),
    }
    drop(standing);

    // Pressure released: the first capture now succeeds and lazily allocates.
    let fresh = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin = owner
        .capture_prepared_decision(fresh, 1)
        .map_err(|(_, r)| r)
        .expect("first capture succeeds once pressure is released");
    assert!(
        owner.backend_for_test().prepared_registry_for_test().is_some(),
        "registry lazily allocated on the first successful capture"
    );
    drop(pin);
}

#[test]
fn spike_lt_admission_precedes_allocation_then_retained_reuse() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    // None before, Some after: the registry is allocated by (and only by) the
    // first successful capture.
    assert!(owner.backend_for_test().prepared_registry_for_test().is_none(), "no allocation before capture");
    let p0 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let pin0 = owner.capture_prepared_decision(p0, 1).expect("first capture");
    let reg = owner.backend_for_test().prepared_registry_for_test().expect("allocated by first capture");
    {
        let g = reg.lock().unwrap();
        assert_eq!(g.occupied(), 1, "first entry present");
        assert_eq!(g.registry_reservation_charge(), registry_cell(), "standing reservation covers the allocation");
    }

    // Last entry release with the backend still alive: the registry allocation is
    // RETAINED and its standing reservation remains charged across the zero-entry
    // period (deallocation-when-empty is NOT required).
    owner.release_prepared(pin0);
    {
        let g = reg.lock().unwrap();
        assert_eq!(g.occupied(), 0, "registry empty after last release");
        assert_eq!(g.registry_reservation_charge(), registry_cell(), "standing reservation retained while empty");
    }
    assert!(
        owner.backend_for_test().prepared_registry_for_test().is_some(),
        "empty registry retained until its final owner drops"
    );
    assert_eq!(op_current(&owner), registry_cell(), "only the retained registry reservation remains");

    // Subsequent capture: SAFE REUSE of the retained registry — no duplicate
    // registry charge and no stale-handle revival (fresh serial).
    let p1 = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let core = prepared_generation_charge(&ctx, p1.retained()).unwrap();
    let pin1 = owner.capture_prepared_decision(p1, 1).expect("subsequent capture reuses the retained registry");
    let reg2 = owner.backend_for_test().prepared_registry_for_test().expect("still the one registry");
    assert!(std::sync::Arc::ptr_eq(&reg, &reg2), "the SAME shared registry is reused, not re-created");
    assert_eq!(
        op_current(&owner),
        core + control_charge() + registry_cell() + pin_bytes(),
        "reuse charges the new entry but NOT a duplicate registry cell"
    );
    drop(pin1);
}

#[test]
fn spike_lt_pin_outliving_owner_releases_reservation_at_end() {
    let ctx = ctx_n(4);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    publish_qc(&owner, &ctx, [9u8; 32], 5, 0);

    // Observe the shared operational ledger through an independent handle so the
    // charge can be read AFTER the owner/backend have dropped.
    let acct = owner.backend_for_test().accounting_handle_for_test();

    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let core = prepared_generation_charge(&ctx, proof.retained()).unwrap();
    let pin = owner.capture_prepared_decision(proof, 1).expect("capture installs the registry");
    assert_eq!(
        acct.current(),
        core + control_charge() + registry_cell() + pin_bytes(),
        "entry + registry fully charged while the owner is alive"
    );

    // Drop the owner (and the only backend handle) while the PIN is still alive.
    // The pin holds a clone of the shared registry `Arc`, so the registry — and
    // its standing reservation — follow actual shared ownership and remain alive.
    drop(owner);
    assert_eq!(
        acct.current(),
        core + control_charge() + registry_cell() + pin_bytes(),
        "pin outliving its owner keeps the generation + registry reservation charged"
    );

    // Dropping the final owner (the pin) tears down the entry AND the retained
    // registry, releasing every reservation — correct end-of-life cleanup.
    drop(pin);
    assert_eq!(acct.current(), 0, "last owner (the outliving pin) released all prepared reservations");
}