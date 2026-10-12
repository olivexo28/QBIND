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
    prepared_generation_charge, prepared_holder_control_charge,
};
use qbind_node::safety_record_store::backend::{InjectFault, SafetyBackend, SafetyBackendPolicy};
use qbind_node::safety_record_store::codec::encode_record;
use qbind_node::safety_record_store::error::{CapacityRefusalDetail, SafetyStoreError};
use qbind_node::safety_record_store::owner::{
    make_locked_qc, set_shared_release_order, shared_dup_live_at_release, PublishResult,
    SafetyRecordOwner, SharedReleaseOrder,
};
use qbind_node::safety_record_store::prepared::{
    generation_backing_struct_size_bytes, pin_charge_bytes, registry_cell_charge_bytes,
    size_of_generation_backing, size_of_prepared_entry, size_of_prepared_handle,
    size_of_prepared_pin, size_of_prepared_registry, size_of_prepared_registry_cell,
    CaptureRefusal, ReleaseOutcome,
};
use qbind_node::safety_record_store::profile::{
    max_retained_generation_bytes, PinnedSafetyContext, ARC_CTRL,
};
use qbind_node::safety_record_store::record::{
    size_of_retained_record, size_of_timeout_msg, DecodedRecord, EvidenceStatus, LockedRecord,
    SafetyRecord, SupportingEvidence, WireQc,
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
/// record-level + nested high-QC signers, N signed timeouts with maximum-length
/// signatures and nested high-QCs) — the heaviest generation the per-class
/// ceiling admits.
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
    // Maximum complete TC-derived generation (the heaviest the ceiling admits).
    let ltc = valid_tc_record(&ctx, 5, 4);
    assert!(
        matches!(&ltc.evidence, SupportingEvidence::TcDerived { tc, .. }
            if tc.signed_timeouts.len() as u64 == ((2 * n) + 2) / 3
                && tc.signed_timeouts.iter().all(|t| t.signature.len() == S_SIG)),
        "TC fixture carries N signed timeouts with maximum-length signatures"
    );
    match owner.publish_locked(ltc, 0, None::<&FixtureCommittedHistory>) {
        PublishResult::DurableAcknowledged { new_revision: 1 } => {}
        other => panic!("TC publish: {other:?}"),
    }

    let proof = owner
        .read_validate(None::<&FixtureCommittedHistory>)
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
        let reg = owner.backend_for_test().prepared_registry_for_test();
        let g = reg.lock().unwrap();
        let v = g.inspect(pin1.handle()).expect("entry live");
        assert_eq!(v.generation_core_charge, core, "inspected core charge");
        assert_eq!(v.generation_control_charge, control, "inspected control charge");
        assert_eq!(v.evidence_backing_capacity, owned_backings, "inspected owned backings");
        assert_eq!(v.backing_shares, 1);
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
    assert_eq!(op_current(&owner), 0, "all prepared reservations released to baseline");
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
    let reg = owner.backend_for_test().prepared_registry_for_test();
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
    }

    // First drop RETAINS the generation (second entry still shares it).
    assert_eq!(pin1.release(), ReleaseOutcome::Released);
    assert_eq!(
        op_current(&owner),
        core + control + registry_cell() + pin_bytes(),
        "generation retained after first drop (one pin released)"
    );

    // Final drop RELEASES the generation, the registry cell, and the last pin.
    assert_eq!(pin2.release(), ReleaseOutcome::Released);
    assert_eq!(op_current(&owner), 0, "generation released after final drop");

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

    // AUTOMATIC Drop of the fresh backing holder returns to baseline.
    drop(pin1);
    assert_eq!(op_current(&owner), 0, "all pins released/dropped to baseline");

    // REFUSAL path shares nothing: a fresh proof read at the authoritative revision
    // but presented with a MISMATCHED expected revision is fenced out (StaleRevision)
    // before any conversion. On refusal the proof is returned and dropped; no entry
    // is created or shared, and the registry stays empty.
    let fresh = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    match owner.capture_prepared_decision(fresh, 999) {
        Err((_p, CaptureRefusal::StaleRevision { expected, found })) => {
            assert_eq!(expected, 999);
            assert_eq!(found, 1);
        }
        other => panic!("expected StaleRevision on refusal, got {other:?}"),
    }
    assert_eq!(op_current(&owner), 0, "refusal shares nothing; registry stays empty");
    assert_eq!(
        owner.backend_for_test().prepared_registry_for_test().lock().unwrap().occupied(),
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
// §3. Distinct generations coexisting through O4 while TWO prepared generations
// remain pinned; the complete accounting (context ownership + both generations +
// registry cell + pins + the O4 publication reservation) is measured against the
// UNCHANGED aggregate ceiling. A full registry refuses a third capture WITHOUT
// eviction. Reports honest success (coexistence fits) or the exact shortfall.
// ===========================================================================

fn distinct_generations_and_full(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);
    let cap = owner.backend_for_test().accounting_aggregate_cap().unwrap();

    // Context ownership is a standing partition charge present before any capture.
    let context_ownership = agg_current(&owner);
    assert!(context_ownership > 0, "context ownership partition is charged standing");

    // rev 1: lock A (QC). Capture entry 1 (DISTINCT generation A).
    publish_qc(&owner, &ctx, [0x11u8; 32], 5, 0);
    let pa = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
    let ga = prepared_generation_charge(&ctx, pa.retained()).unwrap();
    assert!(ga <= max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap());
    let pin1 = owner.capture_prepared_decision(pa, 1).expect("capture A");
    let control = control_charge();
    assert_eq!(op_current(&owner), ga + control + registry_cell() + pin_bytes());
    let agg_one_pinned = agg_current(&owner);
    assert_eq!(agg_one_pinned, context_ownership + ga + control + registry_cell() + pin_bytes());

    // Assembling a SECOND distinct generation requires an O4 publication (a new
    // authoritative lock B) WHILE entry 1 is pinned — the capture reservations and
    // the O4 publication reservation must overlap (conversion overlap). Measure the
    // ACTUAL outcome honestly against the UNCHANGED aggregate ceiling; do NOT raise
    // limits or redefine exclusions to force a pass.
    let lock_b = make_locked_qc(&ctx, [0x22u8; 32], 9, valid_wire_qc(&ctx, [0x22u8; 32], 9), None).unwrap();
    match owner.publish_locked(lock_b, 1, None::<&FixtureCommittedHistory>) {
        // --- SUCCESS: the two distinct generations can coexist through O4 ---------
        PublishResult::DurableAcknowledged { new_revision: 2 } => {
            let pb = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
            let gb = prepared_generation_charge(&ctx, pb.retained()).unwrap();
            let pin2 = owner.capture_prepared_decision(pb, 2).expect("capture B");

            // Two DISTINCT generations (NOT shared): two cores + two controls + one
            // registry cell + two pins.
            let coexist = ga + gb + 2 * control + registry_cell() + 2 * pin_bytes();
            assert_eq!(op_current(&owner), coexist, "two distinct generations' combined live objects");
            {
                let reg = owner.backend_for_test().prepared_registry_for_test();
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

            // Measure THROUGH O4 (a further authoritative publication) WHILE BOTH
            // distinct generations remain pinned. This overlaps the two live
            // generations' reservations with an O4 publication reservation. Honour
            // the UNCHANGED ceiling: report the ACTUAL outcome, do not raise limits.
            let lock_c = make_locked_qc(&ctx, [0x33u8; 32], 13, valid_wire_qc(&ctx, [0x33u8; 32], 13), None).unwrap();
            match owner.publish_locked(lock_c, 2, None::<&FixtureCommittedHistory>) {
                PublishResult::DurableAcknowledged { new_revision: 3 } => {
                    assert_eq!(op_current(&owner), coexist, "O4 reservation released; two generations intact");

                    // A THIRD capture is refused WITHOUT eviction; returned proof intact.
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
                    assert_eq!(
                        owner.backend_for_test().prepared_registry_for_test().lock().unwrap().occupied(),
                        2,
                        "no eviction on refusal"
                    );
                    println!(
                        "[§3 distinct N={n}] RESULT=COEXIST_THROUGH_O4 context_ownership={context_ownership} ga={ga}                  gb={gb} coexist={coexist} aggregate={aggregate_with_two} cap={cap} headroom={}",
                        cap - aggregate_with_two
                    );
                }
                PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(
                    CapacityRefusalDetail::AdmissionOverflow { next, cap: ov_cap, .. },
                )) => {
                    // Honest, conservative refusal: the two distinct generations COEXIST
                    // while pinned (aggregate_with_two <= cap, asserted above), but an O4
                    // publication THROUGH both of them overlaps past the UNCHANGED ceiling.
                    assert_eq!(ov_cap, cap, "refusal is against the unchanged aggregate ceiling");
                    let shortfall = next - cap;
                    assert!(shortfall > 0, "a positive shortfall is reported");
                    // The refusal mutated nothing: both generations still pinned, registry full.
                    assert_eq!(op_current(&owner), coexist, "no charge leaked by the refused O4");
                    assert_eq!(
                        owner.backend_for_test().prepared_registry_for_test().lock().unwrap().occupied(),
                        2,
                        "both generations stay pinned; the refused O4 mutated nothing"
                    );
                    println!(
                        "[§3 distinct N={n}] RESULT=COEXIST_REFUSE_O4 context_ownership={context_ownership} ga={ga}                  gb={gb} coexist={coexist} aggregate={aggregate_with_two} cap={cap} o4_next={next} shortfall={shortfall}                  (two generations coexist while pinned, but an O4 through both exceeds the unchanged ceiling)"
                    );
                }
                other => panic!("unexpected O4-through-two-pinned outcome: {other:?}"),
            }

            // Cleanup/readmission: release both, return to the standing baseline.
            assert_eq!(owner.release_prepared(pin1), ReleaseOutcome::Released);
            assert_eq!(owner.release_prepared(pin2), ReleaseOutcome::Released);
            assert_eq!(op_current(&owner), 0, "both released to operational baseline");
            assert_eq!(agg_current(&owner), context_ownership, "aggregate back to context ownership only");
        }
        // --- CONSERVATIVE REFUSAL: complete accounting prevents coexistence -------
        PublishResult::RefusedPreWrite(SafetyStoreError::CapacityRefusal(
            CapacityRefusalDetail::AdmissionOverflow { next, cap: ov_cap, .. },
        )) => {
            // Honest, conservative refusal: assembling a second distinct generation
            // (a fresh O4 publication) while the first is pinned would push the
            // aggregate past the UNCHANGED ceiling. Report the EXACT shortfall and
            // demonstrate cleanup + readmission instead of raising any limit.
            assert_eq!(ov_cap, cap, "refusal is against the unchanged aggregate ceiling");
            let shortfall = next - cap;
            assert!(shortfall > 0, "a positive shortfall is reported");
            // The registry is unchanged; the first generation is still pinned/intact.
            assert_eq!(
                owner.backend_for_test().prepared_registry_for_test().lock().unwrap().occupied(),
                1,
                "the first generation stays pinned; the refusal mutated nothing"
            );
            assert_eq!(agg_current(&owner), agg_one_pinned, "no charge leaked by the refused O4");

            // CLEANUP: release the first generation so the aggregate has headroom.
            assert_eq!(owner.release_prepared(pin1), ReleaseOutcome::Released);
            assert_eq!(op_current(&owner), 0, "cleanup to operational baseline");

            // READMISSION: the SAME O4 now succeeds once the pin is gone, and a fresh
            // generation can be captured against the authoritative revision.
            let rev2 = publish_qc(&owner, &ctx, [0x22u8; 32], 9, 1);
            assert_eq!(rev2, 2, "O4 succeeds after cleanup (readmission)");
            let pb = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();
            let gb = prepared_generation_charge(&ctx, pb.retained()).unwrap();
            let pin2 = owner.capture_prepared_decision(pb, 2).expect("readmitted capture B");
            assert_eq!(op_current(&owner), gb + control + registry_cell() + pin_bytes());
            println!(
                "[§3 distinct N={n}] RESULT=CONSERVATIVE_REFUSAL context_ownership={context_ownership}                  ga={ga} one_pinned_aggregate={agg_one_pinned} cap={cap} o4_next={next} shortfall={shortfall}                  (coexistence of a pinned generation with a concurrent O4 exceeds the unchanged ceiling;                  cleanup+readmission demonstrated)"
            );
            assert_eq!(owner.release_prepared(pin2), ReleaseOutcome::Released);
            assert_eq!(op_current(&owner), 0, "readmitted generation cleaned up");
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
    let proof = owner.read_validate(None::<&FixtureCommittedHistory>).unwrap();

    let before = op_current(&owner); // proof holder live
    {
        let reg = owner.backend_for_test().prepared_registry_for_test();
        reg.lock().unwrap().force_next_serial(u64::MAX);
    }
    match owner.capture_prepared_decision(proof, 1) {
        Err((p, CaptureRefusal::CounterExhausted)) => {
            assert!(p.recovery_backend_incarnation().is_some(), "proof intact on counter exhaustion");
            // Fail-closed BEFORE any mutation/allocation: while the refused proof is
            // still alive, only its holder is charged — no prepared reservation leaked.
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

    // The capture reserves, in order: the registry cell (empty -> occupied), the
    // owning pin, then the generation core, then the control. Leave headroom for
    // registry-cell + pin + core but ONE byte short of the control, so admission is
    // refused on the LAST reservation — exercising cleanup of the earlier ones.
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
            // Cleanup to the correct baseline: every reservation taken before the
            // failed one is released; only the returned proof holder + standing remain.
            assert_eq!(
                owner.backend_for_test().accounting_aggregate_current(),
                baseline_under_pressure,
                "earlier prepared reservations released on admission refusal"
            );
            assert_eq!(
                owner.backend_for_test().prepared_registry_for_test().lock().unwrap().occupied(),
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
        owner.backend_for_test().prepared_registry_for_test().lock().unwrap().occupied(),
        1,
        "readmitted entry present"
    );
    assert_eq!(op_current(&owner), core + control + registry_cell() + pin_bytes(), "readmitted full charge");
    owner.release_prepared(pin);
    assert_eq!(op_current(&owner), 0, "readmitted entry cleaned up");
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
// §3. Maximum complete TC-derived generation: capture retains the heaviest
// complete generation within the unchanged ceiling; charge decomposition holds.
// ===========================================================================

fn tc_generation_capture(n: u64) {
    let ctx = ctx_n(n);
    let dir = tempfile::tempdir().unwrap();
    let owner = init_owner(dir.path(), &ctx);

    let ltc = valid_tc_record(&ctx, 5, 4);
    let need = ((2 * n) + 2) / 3;
    assert!(
        matches!(&ltc.evidence, SupportingEvidence::TcDerived { tc, high_qc }
            if tc.signed_timeouts.len() as u64 == need
                && tc.signers.len() as u64 == need
                && high_qc.signers.len() as u64 == need),
        "TC fixture: N signer + timeout entries with nested high-QC signers"
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
    let core = prepared_generation_charge(&ctx, proof.retained()).unwrap();
    let ceiling = max_retained_generation_bytes(&ctx, size_of_timeout_msg()).unwrap();
    assert!(core <= ceiling, "complete TC generation core within the unchanged ceiling");

    let pin = owner.capture_prepared_decision(proof, 1).expect("capture TC generation");
    assert_eq!(op_current(&owner), core + control_charge() + registry_cell() + pin_bytes());
    println!("[tc N={n}] tc_core={core} control={} ceiling={ceiling}", control_charge());
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
