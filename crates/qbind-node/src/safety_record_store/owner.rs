//! Run 422 D7-D14 — the O1–O5 operations and the enforced single-writer
//! ownership / expected-revision fencing boundary (§ 13.4 / § 13.5).
//!
//! Every mutating operation takes the one shared serialization domain of the
//! attached [`SafetyBackend`] instance, re-reads the authoritative revision
//! under that lock, fences on the caller's expected revision, and only then
//! performs the checked, atomic, synchronous publication. Validation refusal,
//! write failure, uncertain publication, acknowledged durable success, and
//! in-memory effectiveness are returned as distinct outcomes.

use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use super::backend::{PublishOutcome, SafetyBackend};
use super::codec::{compute_evidence_lock_binding, decode_record, encode_record};
use super::error::{
    AlreadyEstablishedKind, ArithmeticOverflowSite, CapacityRefusalDetail,
    MissingIndependentInputSite, RecoveryRequiredReason, SafetyStoreError, StructuralRefusalDetail,
};
use super::profile::{
    context_owner_ceiling_term, context_ownership_charge, max_component_aggregate_bytes,
    max_context_ownership_bytes, max_retained_generation_bytes, max_safety_record_bytes,
    PinnedSafetyContext,
};
use super::record::{
    size_of_timeout_msg, validated_holder_handle_bytes, DecodedRecord, EvidenceStatus,
    LockedRecord, SafetyRecord, SupportingEvidence, ValidatedRecord,
};
use super::validate::{validate_decoded, CommittedHistory};

const META_FORMAT_VERSION: u16 = 1;
const DOMAIN_META: &[u8] = b"QBIND-D7D14-SAFETY-META-v1";

// Test-only observation of the OPERATIONAL reservation held at the O3
// allocation phase (RUN 422 D7-D14 R3). `read_validate` samples the operational
// accountant's live charge immediately before `validate_decoded` — the point at
// which the retained-holder AND the O3 transient/validation scratch reservations
// must BOTH be active to cover the live transient decoded object and the
// record-sized validation buffer. A regression reads this sample to detect an O3
// scratch reservation that is missing (never taken) OR released before the phase
// it must cover: in either case the sampled charge collapses to the bare holder.
// Gated behind `cfg(test)`/`test-utils`; it never affects production behaviour.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static O3_PHASE_RESERVATION_SAMPLE: std::cell::Cell<u128> = const { std::cell::Cell::new(0) };
}

/// Test-only: the operational reservation sampled at the last O3 allocation phase.
#[cfg(any(test, feature = "test-utils"))]
pub fn o3_phase_reservation_sample() -> u128 {
    O3_PHASE_RESERVATION_SAMPLE.with(|c| c.get())
}

// Test-only in-validation reservation observation (RUN 422 D7-D14 L1). The
// `O3_PHASE_RESERVATION_SAMPLE` above samples immediately BEFORE
// `validate_decoded`; this complementary hook samples the SAME operational
// accountant from INSIDE `validate_decoded`, while its record-sized correspondence
// re-encode buffer is still live. A regression that releases the O3 scratch
// reservation after the pre-validation sample but before the validation allocation
// is therefore still detected: this in-validation sample collapses to the bare
// holder. A cloned `SharedAccountant` handle is armed around the call by
// `read_validate`; the hook is a no-op unless armed. Gated behind
// `cfg(test)`/`test-utils`; it never affects production behaviour.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static O3_IN_VALIDATION_SAMPLE: std::cell::Cell<u128> = const { std::cell::Cell::new(0) };
    static O3_IN_VALIDATION_SAMPLER: std::cell::RefCell<
        Option<super::accounting::SharedAccountant>,
    > = const { std::cell::RefCell::new(None) };
}

/// Test-only: the operational reservation sampled from INSIDE `validate_decoded`
/// during the last O3 validation allocation phase, while the record-sized
/// correspondence re-encode buffer was live.
#[cfg(any(test, feature = "test-utils"))]
pub fn o3_in_validation_reservation_sample() -> u128 {
    O3_IN_VALIDATION_SAMPLE.with(|c| c.get())
}

/// Test-only: arm the in-validation sampler with a cloned operational accountant
/// handle. Called by `read_validate` immediately before `validate_decoded`.
#[cfg(any(test, feature = "test-utils"))]
fn arm_in_validation_sampler(acct: super::accounting::SharedAccountant) {
    O3_IN_VALIDATION_SAMPLER.with(|s| *s.borrow_mut() = Some(acct));
}

/// Test-only: disarm the in-validation sampler. Called by `read_validate`
/// immediately after `validate_decoded` so no later call resamples a stale handle.
#[cfg(any(test, feature = "test-utils"))]
fn disarm_in_validation_sampler() {
    O3_IN_VALIDATION_SAMPLER.with(|s| *s.borrow_mut() = None);
}

/// Crate/test-only: invoked by `validate_decoded` while its record-sized
/// correspondence re-encode buffer is live, to record the active operational
/// reservation at the validation allocation peak. A no-op unless a sampler was
/// armed by `read_validate`.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn observe_in_validation_reservation() {
    O3_IN_VALIDATION_SAMPLER.with(|s| {
        if let Some(acct) = s.borrow().as_ref() {
            let current = acct.current();
            O3_IN_VALIDATION_SAMPLE.with(|c| c.set(current));
        }
    });
}

// Test-only ACTUAL O3 live-object-charge observation (RUN 422 D7-D14 M1). Unlike
// the reservation samples above — which read `acct.current()` (a reservation
// amount, NOT a live-object measurement) — these records measure the ACTUAL
// simultaneously component-owned objects alive at each O3 validation phase, by
// walking the real objects' capacities. Two bounded scalar records are produced
// per O3 `read_validate`:
//
//   * the correspondence RE-ENCODE phase — while `validate_decoded`'s record-sized
//     re-encode buffer is live (before its `drop(reencoded)`), coexisting with the
//     original backend-read encoded buffer and the live transient decoded object;
//   * the certificate-BINDING phase — while `compute_evidence_lock_binding`'s `cert`
//     scratch is live (after the re-encode buffer was released), coexisting with the
//     same original encoded buffer and transient decoded object.
//
// The records hold only scalar byte counts; the observation clones no measured
// object graph, allocates no diagnostic string inside the protected interval, and
// extends no allocation's lifetime. Each is a no-op unless `read_validate` armed
// the observation around its own `validate_decoded`. Gated behind
// `cfg(test)`/`test-utils`; never affects production behaviour.
/// Test-only (RUN 422 D7-D14 S1): which O3 validation phase an
/// [`O3LiveObjectCharge`] record was sampled at. Carried in the record so a
/// consumer can distinguish the re-encode row from the binding row and reject a
/// record that is absent or sampled at the wrong phase.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum O3Phase {
    /// The correspondence re-encode phase (re-encode buffer live).
    #[default]
    Reencode,
    /// The certificate-binding phase (`cert` scratch live, re-encode released).
    Binding,
}

#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct O3LiveObjectCharge {
    /// The O3 validation phase this record was sampled at (explicit phase
    /// identity, so a consumer can reject a record sampled at the wrong phase).
    pub phase: O3Phase,
    /// Original backend-read encoded record buffer capacity (`ENC_INPUT` backing,
    /// the bytes `load_established` copied out of the backend — the SAME buffer the
    /// proof retains, not a fixture clone).
    pub original_encoded_cap: u128,
    /// The live TRANSIENT decoded object's measured charge: its inline
    /// `DecodedRecord` footprint plus the `Vec::capacity()` of every nested backing
    /// it actually owns (outer descriptor arrays, each signer backing, each
    /// signature buffer, the bitmap). Measured in place via
    /// `accounting::decoded_working_set_charge` — borrowed, non-cloning.
    pub transient_decoded_charge: u128,
    /// The single live validation scratch buffer capacity at THIS phase: the
    /// correspondence re-encode buffer (re-encode phase) or the certificate-binding
    /// `cert` buffer (binding phase). Only ONE record-sized validation buffer is
    /// ever live at a time (the re-encode is dropped before the cert is allocated),
    /// so this is a single measured capacity, not a sum of two.
    pub validation_scratch_cap: u128,
    /// The ACTIVE OPERATIONAL reservation sampled from the executing backend's
    /// operational accountant AT THIS PHASE, while the phase's scratch allocation
    /// is live. Sampled separately at each phase (not carried over from the
    /// re-encode phase, not a profile-derived expected value): it is the live
    /// `acct.current()` of the same backend whose `read_validate` is executing.
    pub observed_active_operational_reservation: u128,
    /// The ACTIVE AGGREGATE reservation sampled from the executing backend's shared
    /// aggregate authority AT THIS PHASE (operational + context partitions
    /// combined), while the phase's scratch allocation is live. Sampled separately
    /// at each phase.
    pub observed_active_aggregate_reservation: u128,
}

#[cfg(any(test, feature = "test-utils"))]
impl O3LiveObjectCharge {
    /// The total simultaneously component-owned live object charge at this O3 phase
    /// (the three measured object terms; the reservation samples are NOT objects
    /// and are never summed into the object charge).
    pub fn total(&self) -> u128 {
        self.original_encoded_cap
            .saturating_add(self.transient_decoded_charge)
            .saturating_add(self.validation_scratch_cap)
    }
}

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    // Armed (Some) only around the `read_validate` `validate_decoded` call. Carries
    // the two phase-invariant live terms measured once in `validate_decoded`
    // (original encoded capacity, transient decoded charge); the per-phase scratch
    // capacity is combined with these when each phase records its object charge.
    static O3_OBJ_STABLE: std::cell::Cell<Option<(u128, u128)>> = const { std::cell::Cell::new(None) };
    // The executing backend's cloned operational accountant handle, armed by
    // `read_validate` around its `validate_decoded`. Presence (Some) is the ARMED
    // marker: a standalone `validate_decoded` or a later binding call finds it None
    // and records nothing. Each phase hook samples the active operational and
    // aggregate reservations from THIS handle, separately, while that phase's
    // scratch allocation is live.
    static O3_OBJ_ACCT: std::cell::RefCell<
        Option<super::accounting::SharedAccountant>,
    > = const { std::cell::RefCell::new(None) };
    static O3_REENCODE_OBJ: std::cell::Cell<Option<O3LiveObjectCharge>> =
        const { std::cell::Cell::new(None) };
    static O3_BINDING_OBJ: std::cell::Cell<Option<O3LiveObjectCharge>> =
        const { std::cell::Cell::new(None) };
}

/// Test-only: arm/reset the O3 live-object-charge observation for the current
/// thread with the executing backend's operational accountant handle. Called by
/// `read_validate` immediately before `validate_decoded`. Arming the accountant
/// handle is what RESTRICTS recording to this operation: a standalone
/// `validate_decoded` (or a later binding call) never arms it, so its hooks are
/// no-ops and cannot populate an apparently valid observation for another
/// operation.
#[cfg(any(test, feature = "test-utils"))]
fn arm_o3_object_observation(acct: super::accounting::SharedAccountant) {
    O3_OBJ_STABLE.with(|c| c.set(None));
    O3_OBJ_ACCT.with(|s| *s.borrow_mut() = Some(acct));
    O3_REENCODE_OBJ.with(|c| c.set(None));
    O3_BINDING_OBJ.with(|c| c.set(None));
}

/// Test-only: mark the observation armed and record the two phase-invariant live
/// terms. Called by `validate_decoded` while the original encoded buffer and the
/// transient decoded object are both live. A no-op unless `read_validate` armed
/// the observation (the accountant handle is present), so a standalone
/// `validate_decoded` records nothing.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn set_o3_object_stable(original_encoded_cap: u128, transient_decoded_charge: u128) {
    if O3_OBJ_ACCT.with(|s| s.borrow().is_some()) {
        O3_OBJ_STABLE.with(|c| c.set(Some((original_encoded_cap, transient_decoded_charge))));
    }
}

/// Test-only: disarm the O3 live-object observation. Called by `read_validate`
/// immediately after `validate_decoded` so no later binding call records a stale
/// phase. The recorded `O3_REENCODE_OBJ`/`O3_BINDING_OBJ` values survive for the
/// test to read.
#[cfg(any(test, feature = "test-utils"))]
fn disarm_o3_object_observation() {
    O3_OBJ_STABLE.with(|c| c.set(None));
    O3_OBJ_ACCT.with(|s| *s.borrow_mut() = None);
}

/// Test-only: sample the active `(operational, aggregate)` reservations from the
/// armed backend accountant handle. Returns `None` when not armed. A bounded
/// read of two live charges — no allocation, no object cloning.
#[cfg(any(test, feature = "test-utils"))]
fn sample_o3_reservations() -> Option<(u128, u128)> {
    O3_OBJ_ACCT.with(|s| {
        s.borrow()
            .as_ref()
            .map(|a| (a.current(), a.aggregate().current()))
    })
}

/// Crate/test-only: record the ACTUAL re-encode-phase live object charge while the
/// correspondence re-encode buffer is live, pairing it with the operational and
/// aggregate reservations sampled AT THIS PHASE. A no-op unless armed via
/// `read_validate`.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn observe_o3_reencode_object(reencode_scratch_cap: u128) {
    if let (Some((original, transient)), Some((op_res, agg_res))) =
        (O3_OBJ_STABLE.with(|c| c.get()), sample_o3_reservations())
    {
        O3_REENCODE_OBJ.with(|c| {
            c.set(Some(O3LiveObjectCharge {
                phase: O3Phase::Reencode,
                original_encoded_cap: original,
                transient_decoded_charge: transient,
                validation_scratch_cap: reencode_scratch_cap,
                observed_active_operational_reservation: op_res,
                observed_active_aggregate_reservation: agg_res,
            }))
        });
    }
}

/// Crate/test-only: record the ACTUAL certificate-binding-phase live object charge
/// while the `cert` scratch is live, pairing it with the operational and aggregate
/// reservations sampled AT THIS PHASE (separately from the re-encode phase). A
/// no-op unless armed via `read_validate`.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn observe_o3_binding_object(binding_scratch_cap: u128) {
    if let (Some((original, transient)), Some((op_res, agg_res))) =
        (O3_OBJ_STABLE.with(|c| c.get()), sample_o3_reservations())
    {
        O3_BINDING_OBJ.with(|c| {
            c.set(Some(O3LiveObjectCharge {
                phase: O3Phase::Binding,
                original_encoded_cap: original,
                transient_decoded_charge: transient,
                validation_scratch_cap: binding_scratch_cap,
                observed_active_operational_reservation: op_res,
                observed_active_aggregate_reservation: agg_res,
            }))
        });
    }
}

/// Test-only: the ACTUAL re-encode-phase O3 live object charge recorded at the last
/// armed `read_validate`, or `None` if that phase was not reached.
#[cfg(any(test, feature = "test-utils"))]
pub fn o3_reencode_object_charge() -> Option<O3LiveObjectCharge> {
    O3_REENCODE_OBJ.with(|c| c.get())
}

/// Test-only: the ACTUAL certificate-binding-phase O3 live object charge recorded at
/// the last armed `read_validate`, or `None` if that phase was not reached.
#[cfg(any(test, feature = "test-utils"))]
pub fn o3_binding_object_charge() -> Option<O3LiveObjectCharge> {
    O3_BINDING_OBJ.with(|c| c.get())
}

// Test-only O5 measurement-fault seam (RUN 422 D7-D14 S2). The O5 live-object
// observation measures two component charges through fallible accounting
// helpers: the retained proof's evidence backing (`evidence_backing_capacity`)
// and the fresh read-back's transient decode (`decoded_working_set_charge`). In
// the real fixture both succeed; a bounded test seam forces either one to the
// error branch WITHOUT fabricating enormous vectors or performing unsafe
// allocations, so the fail-closed observation path can be exercised. It never
// affects production behaviour (cfg-gated) and never changes storage behaviour.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum O5MeasurementFault {
    /// No injected fault: both measurements run for real.
    #[default]
    None,
    /// Force the retained-backing measurement to the error branch.
    RetainedBacking,
    /// Force the transient-decode measurement to the error branch.
    TransientDecode,
}

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static O5_MEASUREMENT_FAULT: std::cell::Cell<O5MeasurementFault> =
        const { std::cell::Cell::new(O5MeasurementFault::None) };
}

// Test-only O1 sensitivity-experiment seam (RUN 422 D7-D14 F1). When armed, the
// NEXT `initialize` on this thread reserves the PRE-CORRECTION O1 publication charge
// (`E + publication_staging_charge`, omitting the inline decoded footprint D and the
// metadata payload M) instead of the corrected `D + E + M + staging`. This is an
// INSTRUMENTED reproduction of the historical under-count — the corrected live-object
// observer is retained — NOT an unmodified historical checkout. The flag is consumed
// (reset to `false`) by the operation that reads it, so it affects exactly one
// `initialize`. Absent from production builds.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static O1_FORCE_OLD_RESERVATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only (RUN 422 D7-D14 F1 sensitivity experiment): arm the instrumented
/// old-reservation reproduction for the next `initialize` on this thread. See
/// [`O1_FORCE_OLD_RESERVATION`].
#[cfg(any(test, feature = "test-utils"))]
pub fn set_force_o1_old_reservation(on: bool) {
    O1_FORCE_OLD_RESERVATION.with(|c| c.set(on));
}

/// Test-only: arm (or clear) the O5 measurement-fault seam for the current thread.
/// The fault applies to the next `reacknowledge` snapshot construction.
#[cfg(any(test, feature = "test-utils"))]
pub fn inject_o5_measurement_fault(fault: O5MeasurementFault) {
    O5_MEASUREMENT_FAULT.with(|c| c.set(fault));
}

/// Test-only: measure the retained proof's evidence backing for the O5 snapshot,
/// honouring the fault seam. Returns the SAME `SafetyStoreError` the real helper
/// would raise on arithmetic failure when the fault is armed.
#[cfg(any(test, feature = "test-utils"))]
fn measure_o5_evidence_backing(evidence: &SupportingEvidence) -> Result<u128, SafetyStoreError> {
    if O5_MEASUREMENT_FAULT.with(|c| c.get()) == O5MeasurementFault::RetainedBacking {
        return Err(SafetyStoreError::ArithmeticOverflow(
            ArithmeticOverflowSite::AccountingSum,
        ));
    }
    super::accounting::evidence_backing_capacity(evidence)
}

/// Test-only: measure the fresh read-back's transient decode for the O5 snapshot,
/// honouring the fault seam.
#[cfg(any(test, feature = "test-utils"))]
fn measure_o5_transient_decode(decoded: &DecodedRecord) -> Result<u128, SafetyStoreError> {
    if O5_MEASUREMENT_FAULT.with(|c| c.get()) == O5MeasurementFault::TransientDecode {
        return Err(SafetyStoreError::ArithmeticOverflow(
            ArithmeticOverflowSite::O5ReadBackWorkingSet,
        ));
    }
    super::accounting::decoded_working_set_charge(decoded)
}

/// Decoded initialization metadata (one per backend DB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyMeta {
    pub meta_format_version: u16,
    /// Digest binding the pinned context used at initialization.
    pub context_digest: [u8; 32],
    /// The authoritative current publication revision.
    pub current_revision: u64,
}

impl SafetyMeta {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 32 + 8);
        out.extend_from_slice(&self.meta_format_version.to_be_bytes());
        out.extend_from_slice(&self.context_digest);
        out.extend_from_slice(&self.current_revision.to_be_bytes());
        out
    }
    fn decode(buf: &[u8]) -> Result<Self, SafetyStoreError> {
        if buf.len() != 2 + 32 + 8 {
            return Err(SafetyStoreError::StructuralRefusal(
                super::error::StructuralRefusalDetail::Static("metadata length"),
            ));
        }
        let meta_format_version = u16::from_be_bytes([buf[0], buf[1]]);
        if meta_format_version != META_FORMAT_VERSION {
            return Err(SafetyStoreError::UnsupportedVersion(meta_format_version));
        }
        let mut context_digest = [0u8; 32];
        context_digest.copy_from_slice(&buf[2..34]);
        let mut rev = [0u8; 8];
        rev.copy_from_slice(&buf[34..42]);
        Ok(SafetyMeta {
            meta_format_version,
            context_digest,
            current_revision: u64::from_be_bytes(rev),
        })
    }
}

/// Compute a stable digest of the pinned context (identity fence for open).
pub fn context_digest(ctx: &PinnedSafetyContext) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_META);
    h.update(ctx.network_genesis_id);
    h.update(ctx.authority_context_ref);
    h.update(ctx.chain_id.to_be_bytes());
    h.update(ctx.epoch.to_be_bytes());
    h.update(ctx.qc_suite_id.to_be_bytes());
    h.update([ctx.timeout_suite_id]);
    h.update((ctx.s_sig as u64).to_be_bytes());
    h.update([ctx.require_height_equals_round as u8]);
    h.update((ctx.validators.len() as u64).to_be_bytes());
    for (id, p) in &ctx.validators {
        h.update(id.as_u64().to_be_bytes());
        h.update(p.to_be_bytes());
    }
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// A pinned context plus the retained **context-ownership reservation** charged
/// for its distinct allocation (§ 13.7B). Held behind the owner's single `Arc`,
/// so cloning an owner shares this one allocation *and* its one charge; the
/// charge releases (via the reservation's drop) only when the **last** owner
/// clone drops the `Arc`. Each independent `attach()` builds a fresh
/// `OwnedContext` with its own reservation, so distinct retained contexts are
/// charged distinctly against the backend's dedicated context accountant.
#[derive(Debug)]
struct OwnedContext {
    ctx: PinnedSafetyContext,
    /// The retained context-ownership charge; released when this (clone-shared)
    /// context allocation is finally dropped. Field is never read directly — its
    /// lifetime *is* the accounting (RAII).
    _context_reservation: super::accounting::Reservation,
}

/// Measured in-memory size of the complete `OwnedContext` wrapper **value** on
/// the supported target (`size_of::<OwnedContext>()`): the inline
/// [`PinnedSafetyContext`] + the inline retained `Reservation` + any required
/// layout padding, each counted once. This is the whole value retained behind
/// `Arc<OwnedContext>`, so charging it (plus the validator-vector heap backing
/// and the Arc header) leaves no inline field — in particular the reservation —
/// uncharged (§ 13.7B, finding #3). The separately-charged validator-vector heap
/// backing and the `Arc` shared-allocation header are deliberately NOT included
/// here; `context_ownership_charge` adds them.
pub fn size_of_owned_context_wrapper() -> u128 {
    std::mem::size_of::<OwnedContext>() as u128
}

/// The owner of a safety-record store: one attached handle to a shared
/// [`SafetyBackend`] instance plus the pinned context.
///
/// The pinned [`PinnedSafetyContext`] (which owns a validator vector) is held
/// behind an [`Arc`] so that cloning an owner handle shares the single immutable
/// context allocation rather than copying the validator vector into an
/// unaccounted second buffer (§ 13.7B). The distinct retained context allocation
/// is charged against the backend's dedicated context-ownership accountant at
/// [`SafetyRecordOwner::attach`] and released when the last clone drops; every
/// clone observes the same backend serialization domain, the same shared
/// accountant, and the same single context charge. Attaching or cloning a handle
/// therefore cannot mint an uncharged per-handle context copy.
#[derive(Debug, Clone)]
pub struct SafetyRecordOwner {
    backend: SafetyBackend,
    ctx: Arc<OwnedContext>,
}

/// The result of O4/O5 publication, distinguishing every outcome class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishResult {
    /// Refused before any write (validation/eligibility/revision). Prior state intact.
    RefusedPreWrite(SafetyStoreError),
    /// The write errored; durable outcome ambiguous — predecessor NOT assumed
    /// stored. Carries a fixed `&'static str` (D7-D14 G1b allocation-free
    /// correction): the backend supplies only a compile-time ambiguous-write
    /// diagnostic, so moving it into this outcome allocates no owned `String` while
    /// the O4/O5 publication reservation is still live.
    WriteFailedAmbiguous(&'static str),
    /// The write durably succeeded but no success was delivered; a complete
    /// successor may survive. The caller must block dependent use until explicit
    /// recovery re-establishes state.
    UncertainDurable,
    /// Durable success acknowledged; the new restriction is now effective.
    DurableAcknowledged { new_revision: u64 },
}

impl SafetyRecordOwner {
    /// Attach an owner handle to an open backend instance. Every handle attached
    /// to the same backend shares its single serialization domain.
    pub fn attach(
        backend: SafetyBackend,
        ctx: PinnedSafetyContext,
    ) -> Result<Self, SafetyStoreError> {
        ctx.validate()?;
        // Bind the shared aggregate accounting ceiling for this store's pinned
        // context (§ 13.7 / § 13.7B). The first handle establishes it; every
        // later handle on the same backend shares it and a divergent (foreign)
        // context ceiling is refused rather than silently widening the budget.
        // The validation re-encode scratch (one record-sized buffer) is included
        // in the aggregate so the complete-content comparison does not add an
        // uncharged record-sized buffer.
        let validation_scratch = max_safety_record_bytes(&ctx)?;
        backend.accounting().bind(&ctx, validation_scratch)?;

        // Account for this attachment's *distinct* retained context allocation
        // (§ 13.7B). `bind()` above only establishes the operational sub-ceiling;
        // it does NOT reserve context ownership. Here we:
        //   1. bind the dedicated context-ownership accountant's sub-ceiling (a
        //      bounded multiplicity of the per-owner context term, stable across
        //      every same-profile handle) AND the shared aggregate ceiling, which
        //      is the accepted **profile-derived aggregate** that bounds the
        //      operational + context partitions *jointly* — the aggregate is NOT
        //      enlarged by the context sub-cap (§ 13.7, finding #4 correction),
        //   2. refuse an over-capacity validator vector (actual capacity beyond
        //      the normalized per-owner term) before charging it, and
        //   3. admit (reserve) the actual context charge BEFORE the `Arc<OwnedContext>`
        //      retains the context — so the charge precedes the retained allocation
        //      and is admitted against the *shared* aggregate, consuming capacity
        //      operations must then compete for.
        // The charge measures the COMPLETE `OwnedContext` wrapper value (the
        // inline pinned context + the inline reservation + layout padding), not a
        // partial inner type, so the reservation field is never uncharged.
        // The reservation is moved into the `Arc<OwnedContext>`: a clone shares it
        // (one charge), an independent `attach()` takes its own, and the charge is
        // released when the last clone drops. A capacity refusal here leaves the
        // backend and any already-attached handles untouched.
        let wrapper_size = size_of_owned_context_wrapper();
        backend
            .context_accounting()
            .bind_cap(max_context_ownership_bytes(&ctx, wrapper_size)?)?;
        backend
            .accounting()
            .bind_aggregate(max_component_aggregate_bytes(
                &ctx,
                size_of_timeout_msg(),
                validation_scratch,
            )?)?;
        let charge = context_ownership_charge(&ctx, wrapper_size)?;
        if charge > context_owner_ceiling_term(&ctx, wrapper_size)? {
            return Err(SafetyStoreError::CapacityRefusal(
                CapacityRefusalDetail::ContextOwnerExceeded {
                    capacity: ctx.validators.capacity() as u128,
                    limit: context_owner_ceiling_term(&ctx, wrapper_size)?,
                },
            ));
        }
        let context_reservation = backend.context_accounting().reserve(charge)?;
        Ok(SafetyRecordOwner {
            backend,
            ctx: Arc::new(OwnedContext {
                ctx,
                _context_reservation: context_reservation,
            }),
        })
    }

    /// The conservative retained-holder charge for a single O3-minted proof: the
    /// **complete operational representation** of one retained [`ValidatedRecord`]
    /// (§ 13.7A / § 13.7B), charged once against the shared aggregate accountant
    /// for the lifetime of the returned proof. Three distinct terms, each counted
    /// exactly once and never double-counting a generation or backing:
    ///
    /// * `rec` — the retained record-sized `encoded` publication **buffer backing**
    ///   (`MAX_SAFETY_RECORD_BYTES`), the heap allocation behind the inline `Vec`
    ///   descriptor;
    /// * `gen` — the one decoded **generation** (`MAX_RETAINED_GENERATION_BYTES`),
    ///   covering the inline `RetainedRecord` struct and its heap backings
    ///   (signer bitmaps, signature buffers, timeout backing); and
    /// * `handle` — the inline holder/accounting **metadata** the proof carries
    ///   beyond its generation (`validated_holder_handle_bytes`: the evidence-status
    ///   discriminant, the `encoded` `Vec` descriptor handle, the origin-context
    ///   digest, the O5 recovery incarnation discriminant, and the inline holder
    ///   [`super::accounting::Reservation`] option). This is the finding-#2
    ///   correction: the handle fields are now an **enforced** reserved term, not
    ///   merely an asserted size-ordering. The compile-time inequality in
    ///   [`super`] independently proves `handle` covers the real inline layout.
    ///
    /// The same charge is taken by [`ValidatedRecord::try_clone`] (via
    /// [`super::accounting::Reservation::try_duplicate`]), so a cloned proof —
    /// which owns its own separate buffer, generation, and inline handle — is
    /// charged identically and cannot mint an uncharged holder. The reservation is
    /// released when the proof (or clone) drops, on the correct lifetime boundary.
    fn retained_holder_charge(&self) -> Result<u128, SafetyStoreError> {
        let rec = max_safety_record_bytes(self.pinned())?;
        let gen = max_retained_generation_bytes(self.pinned(), size_of_timeout_msg())?;
        let handle = validated_holder_handle_bytes();
        rec.checked_add(gen)
            .and_then(|t| t.checked_add(handle))
            .ok_or(SafetyStoreError::ArithmeticOverflow(
                ArithmeticOverflowSite::RetainedHolderCharge,
            ))
    }

    /// The pinned context (immutable), reached through the shared `Arc<OwnedContext>`.
    pub fn context(&self) -> &PinnedSafetyContext {
        &self.ctx.ctx
    }

    /// Crate-internal shorthand for the pinned context behind the shared Arc.
    #[inline]
    fn pinned(&self) -> &PinnedSafetyContext {
        &self.ctx.ctx
    }

    /// Source/test-only: the shared backend handle, so accounting regressions can
    /// observe the real shared accountant (peak / current / cap) this owner's
    /// operations reserve against. Gated behind `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn backend_for_test(&self) -> &SafetyBackend {
        &self.backend
    }

    /// Source/test-only: the identity (allocation address) of this handle's shared
    /// pinned context. Two owner handles that share the one immutable
    /// `Arc<OwnedContext>` return the **same** pointer; a by-value context copy
    /// (the escape this closes) would return distinct pointers. Used by the
    /// owner-clone context-sharing regression. Gated behind `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn context_ptr_for_test(&self) -> *const PinnedSafetyContext {
        &self.ctx.ctx as *const PinnedSafetyContext
    }

    /// Whether the shared backend is currently in a recovery-required state
    /// (a prior ambiguous/uncertain publication under any handle has not yet
    /// been cleared by the required successful recovery operation).
    pub fn recovery_required(&self) -> bool {
        self.backend.recovery_required()
    }

    /// Load and establish the authoritative state under the ownership boundary,
    /// enforcing **every** prerequisite a dependent operation relies on (§ 13.4
    /// O2/O3 / § 13.5), rather than trusting callers to invoke `open` first:
    ///
    /// * metadata and record **presence** and valid **structure** (bounded decode);
    /// * **record revision equals metadata revision** (established here, not left
    ///   to each caller);
    /// * **pinned-context correspondence** (stored context digest matches this
    ///   handle's pinned context) — a foreign-context handle is refused.
    ///
    /// This is the single place the metadata↔record consistency is established;
    /// O3/O4/O5 consume the returned decoded predecessor and never re-derive a
    /// weaker check. Semantic association (P1–P4 / TA1–TA8) and committed-history
    /// membership remain the caller's explicit stage-3 step (O3), kept distinct
    /// from this structural establishment (O2).
    fn load_established(&self) -> Result<(SafetyMeta, Vec<u8>, DecodedRecord), SafetyStoreError> {
        let meta_bytes = self
            .backend
            .read_meta(super::backend::META_ENCODED_LEN)?
            .ok_or(SafetyStoreError::MissingEstablishedState("no metadata"))?;
        let record_bytes = self
            .backend
            .read_record(super::profile::max_safety_record_bytes(self.pinned())?)?
            .ok_or(SafetyStoreError::StructuralRefusal(
                super::error::StructuralRefusalDetail::Static("metadata without record"),
            ))?;
        let meta = SafetyMeta::decode(&meta_bytes)?;
        if meta.context_digest != context_digest(self.pinned()) {
            return Err(SafetyStoreError::SemanticRefusal(
                super::error::SemanticRefusalDetail::PinnedContextDisagreement,
            ));
        }
        // Structural decode (bounds-checked) and metadata↔record revision
        // consistency are established here, once, for every dependent operation.
        let decoded = decode_record(&record_bytes, self.pinned())?;
        if decoded.publication_revision != meta.current_revision {
            return Err(SafetyStoreError::SemanticRefusal(
                super::error::SemanticRefusalDetail::RecordMetaRevisionDisagreement {
                    record_revision: decoded.publication_revision,
                    meta_revision: meta.current_revision,
                },
            ));
        }
        Ok((meta, record_bytes, decoded))
    }

    /// Source/test-only: overwrite the stored record bytes out-of-band to
    /// simulate a surviving divergent publication (used to exercise O5's
    /// byte-for-byte refusal). Never called by production. Gated behind
    /// `test-utils` so it is not a production-reachable escape.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn debug_overwrite_record_for_test(
        &self,
        record_bytes: &[u8],
    ) -> Result<(), SafetyStoreError> {
        let _guard = self.backend.lock_domain();
        self.backend.debug_overwrite_record(record_bytes)
    }

    // -----------------------------------------------------------------------
    // O1 — initialize
    // -----------------------------------------------------------------------

    /// **O1**: explicit first-use initialization. Requires the independent
    /// `first_use_intent` assertion and a genuinely unused backend (no metadata,
    /// no record). Refuses established / partial / malformed state. An empty
    /// directory alone does not authorize initialization. Writes initialization
    /// metadata and a `BootstrapNoLock` record atomically at revision 0.
    pub fn initialize(&self, first_use_intent: bool) -> Result<u64, SafetyStoreError> {
        if !first_use_intent {
            return Err(SafetyStoreError::MissingIndependentInput(
                MissingIndependentInputSite::O1FirstUseIntent,
            ));
        }
        let guard = self.backend.lock_domain();
        // Admit O1's existing/partial/malformed-state inspection working set (the
        // record-sized read-back buffer plus the fixed-size metadata buffer)
        // against the shared aggregate budget BEFORE reading any existing bytes
        // out of the backend into component-owned buffers (§ 13.7). The per-record
        // length bound enforced in `read_checksummed` is necessary but does not
        // prove the inspection copies fit the aggregate budget; the established /
        // partial / malformed refusal paths allocate those copies and must be
        // admitted too. This reservation is scoped so it releases BEFORE the
        // bootstrap publication reservation below (which it must not coexist
        // with), and it releases on every exit via its drop.
        let rec_bound = super::profile::max_safety_record_bytes(self.pinned())?;
        let inspect_charge = rec_bound
            .checked_add(super::backend::META_ENCODED_LEN)
            .ok_or(SafetyStoreError::ArithmeticOverflow(
                ArithmeticOverflowSite::O1InspectionWorkingSet,
            ))?;
        let (meta_present, record_present) = {
            let _inspect_res = self.backend.accounting().reserve(inspect_charge)?;
            let meta = self.backend.read_meta(super::backend::META_ENCODED_LEN)?;
            let record = self.backend.read_record(rec_bound)?;
            (meta.is_some(), record.is_some())
        };
        match (meta_present, record_present) {
            (true, _) => {
                return Err(SafetyStoreError::AlreadyEstablished(
                    AlreadyEstablishedKind::MetadataPresent,
                ))
            }
            (false, true) => {
                return Err(SafetyStoreError::StructuralRefusal(
                    StructuralRefusalDetail::RecordPresentWithoutMetadata,
                ))
            }
            (false, false) => {}
        }

        // Bounded namespace classification (§ 13.3A): distinguish a genuinely
        // unused safety namespace from established / partial / malformed / legacy
        // / unknown safety state. Any key in the component-owned `safetyrec:`
        // namespace other than the two recognized current-format keys causes the
        // contract-prescribed refusal — with NO migration, deletion, repair, or
        // initialization over it.
        if let Some(unknown_len) = self.backend.first_unrecognized_safety_key()? {
            return Err(SafetyStoreError::StructuralRefusal(
                StructuralRefusalDetail::UnknownLegacySafetyNamespaceKey {
                    len: unknown_len as u128,
                },
            ));
        }

        // Reserve the bootstrap publication phase against the shared aggregate
        // accountant BEFORE constructing the decoded local or encoding it (§ 13.7:
        // admission precedes the construction/allocation it protects). The
        // canonical inventory's `INV-O1-5` claimed `encode_record` *consumes* the
        // bootstrap `DecodedRecord`; the implementation calls
        // `encode_record(&decoded, …)`, which **borrows** it, so the decoded local
        // remains in scope and coexists with every publication buffer through
        // `publish_atomic`. The phase charge therefore sums every object that is
        // simultaneously live from the decoded construction through publication
        // (D7-D14 Finding A correction):
        //
        //   * the inline decoded bootstrap object (`size_of::<DecodedRecord>()`) —
        //     a stack-resident footprint a heap allocation counter cannot see, so
        //     it is charged explicitly rather than inferred from headroom;
        //   * the encoded record buffer at its profile-sized capacity
        //     (`max_safety_record_bytes`; the bootstrap serializes to only 81
        //     bytes, but the backing is pre-sized to the profile cap);
        //   * the metadata payload buffer (`META_ENCODED_LEN`); and
        //   * the two CRC-framing envelopes `publish_atomic` wraps
        //     (`publication_staging_charge`).
        //
        // The reservation releases on every exit (success, refusal, error,
        // uncertainty) via its drop at end of scope.
        let decoded_inline = super::accounting::size_of_decoded_record_inline();
        let o1_pub_charge = decoded_inline
            .checked_add(max_safety_record_bytes(self.pinned())?)
            .and_then(|s| s.checked_add(super::backend::META_ENCODED_LEN))
            .and_then(|s| {
                super::accounting::publication_staging_charge(self.pinned())
                    .ok()
                    .and_then(|staging| s.checked_add(staging))
            })
            .ok_or(SafetyStoreError::ArithmeticOverflow(
                ArithmeticOverflowSite::O1BootstrapPublicationCharge,
            ))?;
        // F1 sensitivity experiment (test-only, RUN 422 D7-D14): when armed, reserve
        // the PRE-CORRECTION amount (`E + publication_staging_charge`, omitting the
        // inline decoded footprint D and the metadata payload M) for THIS operation
        // only — an INSTRUMENTED reproduction of the historical under-count, NOT an
        // unmodified historical checkout. The corrected live-object observer below is
        // retained, so a test can demonstrate the observed live charge exceeds this
        // old reservation. The flag is consumed by the operation that reads it. In
        // production builds this block is absent and `o1_pub_charge` is the corrected
        // value unconditionally.
        #[cfg(any(test, feature = "test-utils"))]
        let o1_pub_charge = if O1_FORCE_OLD_RESERVATION.with(|c| c.replace(false)) {
            max_safety_record_bytes(self.pinned())?
                .checked_add(super::accounting::publication_staging_charge(self.pinned())?)
                .ok_or(SafetyStoreError::ArithmeticOverflow(
                    ArithmeticOverflowSite::O1BootstrapPublicationCharge,
                ))?
        } else {
            o1_pub_charge
        };
        let _pub_res = self.backend.accounting().reserve(o1_pub_charge)?;

        let decoded = DecodedRecord {
            persistence_format_version: super::profile::SAFETY_PERSISTENCE_FORMAT_VERSION,
            network_genesis_id: self.pinned().network_genesis_id,
            publication_revision: 0,
            record: SafetyRecord::BootstrapNoLock {
                authority_context_ref: self.pinned().authority_context_ref,
                predecessor_ref: None,
            },
        };
        debug_assert!(
            super::accounting::decoded_working_set_charge(&decoded)
                .map(|c| c <= decoded_inline)
                .unwrap_or(false),
            "O1 bootstrap decoded working set exceeded its reserved inline charge"
        );
        let encoded = encode_record(&decoded, self.pinned())?;
        debug_assert!(
            encoded.capacity() as u128 <= _pub_res.charge(),
            "O1 bootstrap encoding exceeded its reserved charge"
        );
        let meta = SafetyMeta {
            meta_format_version: META_FORMAT_VERSION,
            context_digest: context_digest(self.pinned()),
            current_revision: 0,
        };
        // Name the metadata encode buffer as a local so its capacity can be measured
        // and so the SAME object is the one passed to `publish_atomic` (behaviour is
        // unchanged — the bytes are identical to `meta.encode()` inline).
        let meta_encoded = meta.encode();
        // F1 (test-only, RUN 422 D7-D14): record the owner-held live-object scalar
        // snapshot while ALL of these O1 objects are alive, immediately before
        // `publish_atomic`: the borrowed bootstrap decoded local (measured IN PLACE
        // via `decoded_working_set_charge` — no clone), the profile-sized encoded
        // record backing, and the metadata payload buffer. `decoded`, `encoded`, and
        // `meta_encoded` all remain in scope through the `publish_atomic` call below,
        // which itself borrows `&encoded`/`&meta_encoded`, so every snapshotted object
        // is live and unchanged at the boundary. The backend boundary adds the two CRC
        // staging envelopes and the active reservations. No-op in production builds.
        #[cfg(any(test, feature = "test-utils"))]
        {
            if let Ok(decoded_charge) = super::accounting::decoded_working_set_charge(&decoded) {
                super::backend::set_o1_owner_live_snapshot(
                    decoded_charge,
                    encoded.capacity() as u128,
                    meta_encoded.capacity() as u128,
                );
            }
        }
        match self
            .backend
            .publish_atomic(&guard, &meta_encoded, &encoded)
        {
            PublishOutcome::DurableAcknowledged => {
                // An acknowledged explicit O1 initialization establishes fresh
                // bootstrap effectiveness through its permitted path.
                self.backend.mark_effective();
                Ok(0)
            }
            PublishOutcome::PreWriteRefused(m) => Err(SafetyStoreError::WriteFailed(
                super::error::WriteFailedDetail::Static(m),
            )),
            PublishOutcome::WriteError(m) => Err(SafetyStoreError::WriteFailed(
                super::error::WriteFailedDetail::Static(m),
            )),
            PublishOutcome::UncertainDurable => Err(SafetyStoreError::UncertainPublication(
                "O1 metadata+bootstrap publish outcome uncertain",
            )),
        }
    }

    // -----------------------------------------------------------------------
    // O2 — open
    // -----------------------------------------------------------------------

    /// **O2**: open established state without auto-initialization, migration,
    /// repair, or any safety-state write. Requires consistent metadata + record
    /// (structure + revision) and a matching pinned-context digest. Opening does
    /// **not** make the surviving state effective: dependent O4 remains blocked
    /// until a successful O5 (or an acknowledged O1), so a reopen cannot bypass
    /// the recovery requirement.
    pub fn open(&self) -> Result<SafetyMeta, SafetyStoreError> {
        let _guard = self.backend.lock_domain();
        // Admit O2's read/decode working set (the record-sized read-back buffer,
        // the fixed metadata buffer, and the one TRANSIENT decoded object produced
        // by `load_established`) against the shared aggregate budget BEFORE those
        // component-owned allocations/copies occur (§ 13.7). The decoded object is
        // reserved at the TRANSIENT decoded ceiling (`max_transient_decoded_working_set`),
        // NOT the retained-generation ceiling: a `DecodedRecord` carries the two
        // validated-then-discarded identity-header fields and so is strictly larger
        // than the retained generation, and the retained inline ceiling is not the
        // transient decoder's size. O2 is an inspection path and, unlike O3/O4/O5,
        // previously invoked `load_established` without any operation reservation,
        // so an established read-back and decode could escape aggregate admission.
        // The reservation releases on every exit (success or refusal) via its drop.
        let transient = super::accounting::max_transient_decoded_working_set(self.pinned())?;
        let o2_charge = super::profile::max_safety_record_bytes(self.pinned())?
            .checked_add(super::backend::META_ENCODED_LEN)
            .and_then(|b| b.checked_add(transient))
            .ok_or(SafetyStoreError::ArithmeticOverflow(
                ArithmeticOverflowSite::O2ReadDecodeWorkingSet,
            ))?;
        let _o2_res = self.backend.accounting().reserve(o2_charge)?;
        let (meta, _record_bytes, _decoded) = self.load_established()?;
        Ok(meta)
    }

    // -----------------------------------------------------------------------
    // O3 — read / validate
    // -----------------------------------------------------------------------

    /// **O3**: read and validate without writing. Returns the validated record,
    /// its explicit (always `Unverified`) evidence status, and the retained
    /// original encoded publication bytes needed by O5. Inspecting/validating
    /// surviving state here does **not** make it effective.
    pub fn read_validate<H: CommittedHistory + ?Sized>(
        &self,
        history: Option<&H>,
    ) -> Result<ValidatedRecord, SafetyStoreError> {
        let _guard = self.backend.lock_domain();
        // Reserve this proof's retained-holder charge (the retained `encoded`
        // buffer + its decoded generation + inline handle) BEFORE `load_established`
        // copies the stored payload into a component-owned buffer (§ 13.7:
        // reservations precede the allocation/copy). The holder reservation is moved
        // into the returned proof and lives for its lifetime; the O3 validation
        // scratch reserved just below releases at O3 return.
        let holder_res = self
            .backend
            .accounting()
            .reserve(self.retained_holder_charge()?)?;
        // O3 transient validation scratch (§ 13.7, D7-D14 O3 validation-coexistence
        // correction). Beyond the long-lived retained-holder reservation above,
        // O3's decode→validation phase additionally holds a LIVE TRANSIENT decoded
        // object and, at its peak, exactly ONE record-sized validation buffer (the
        // correspondence re-encode, which `validate_decoded` now drops before the
        // certificate-binding scratch is allocated, so the two never coexist). Two
        // facts make the earlier single record-sized scratch an under-reservation:
        //
        //   1. The retained holder's generation term reserves the RETAINED
        //      generation ceiling (`max_retained_generation_bytes`), which is
        //      strictly SMALLER than the live transient decoded object
        //      (`max_transient_decoded_working_set`): the transient carries the
        //      two validated-then-discarded identity-header fields. Charging only
        //      the retained ceiling for the transient under-reserves it by exactly
        //      that delta.
        //   2. Before the drop correction, the re-encode and certificate-binding
        //      buffers coexisted, so TWO record-sized buffers were live while only
        //      one was reserved.
        //
        // Reserve the transient's excess over the retained ceiling PLUS one
        // record-sized validation buffer. The O3 phase maximum is then fully
        // admitted before any O3 allocation/copy: the retained holder covers the
        // retained `encoded` buffer and the transient's first `retained_gen` bytes
        // (the transient converts INTO the retained generation, so they are never
        // simultaneously live), and this term covers the transient's excess plus
        // the single live validation buffer. The scratch releases at O3 return; the
        // holder reservation is moved into the returned proof.
        let transient = super::accounting::max_transient_decoded_working_set(self.pinned())?;
        let retained_gen = max_retained_generation_bytes(self.pinned(), size_of_timeout_msg())?;
        let transient_excess = transient.saturating_sub(retained_gen);
        let o3_scratch = transient_excess
            .checked_add(max_safety_record_bytes(self.pinned())?)
            .ok_or(SafetyStoreError::ArithmeticOverflow(
                ArithmeticOverflowSite::O3ValidationScratchCharge,
            ))?;
        let _scratch_res = self.backend.accounting().reserve(o3_scratch)?;
        // Enforce the established-state + pinned-context + revision-consistency
        // prerequisites centrally (do not rely on the caller having invoked
        // `open`). Reject missing/partial, foreign-context, or revision-
        // inconsistent metadata before validating the record.
        let (_meta, record_bytes, decoded) = self.load_established()?;
        // R3 (test-only): sample the operational reservation entering the O3
        // heaviest allocation phase. Both the retained-holder and the O3 scratch
        // reservations must be live here to cover the transient decoded object and
        // the record-sized validation buffer `validate_decoded` is about to build.
        #[cfg(any(test, feature = "test-utils"))]
        O3_PHASE_RESERVATION_SAMPLE.with(|c| c.set(self.backend.accounting_current()));
        // Semantic/codec validation produces a proof WITHOUT an O5 capability;
        // O3 on this established backend then grants the backend-bound recovery
        // capability, stamped with THIS backend's ownership incarnation. Only a
        // successful O3 on an established backend mints an O5-usable token — the
        // public `validate_decoded` and the bootstrap builder never do.
        // L1 (test-only): arm the in-validation reservation sampler with a cloned
        // operational accountant handle so `validate_decoded` can observe the active
        // reservation WHILE its record-sized correspondence re-encode buffer is live
        // (RUN 422 D7-D14 L1) — establishing the O3 scratch stays active THROUGH the
        // validation allocation phase, not merely up to the sample above. Disarmed
        // immediately after so no later `validate_decoded` resamples a stale handle.
        #[cfg(any(test, feature = "test-utils"))]
        arm_in_validation_sampler(self.backend.accounting().clone());
        // M1 (test-only): arm the ACTUAL O3 live-object-charge observation so
        // `validate_decoded` records, at each validation phase, the real
        // simultaneously component-owned object charge (original encoded buffer +
        // transient decoded object + the single live validation scratch) — a
        // measurement of the live objects, distinct from the reservation samples
        // above. Disarmed immediately after the call.
        #[cfg(any(test, feature = "test-utils"))]
        arm_o3_object_observation(self.backend.accounting().clone());
        let validated = validate_decoded(decoded, record_bytes, self.pinned(), history);
        #[cfg(any(test, feature = "test-utils"))]
        disarm_in_validation_sampler();
        #[cfg(any(test, feature = "test-utils"))]
        disarm_o3_object_observation();
        let validated = validated?;
        Ok(validated
            .with_holder(holder_res)
            .grant_recovery_capability(self.backend.incarnation()))
    }

    // -----------------------------------------------------------------------
    // O4 — publish a new restriction
    // -----------------------------------------------------------------------

    /// **O4**: validate a candidate `Locked` transition, fence on the expected
    /// revision, use a checked revision increment, and publish atomically and
    /// synchronously. The new restriction becomes effective only after an
    /// acknowledged durable success.
    pub fn publish_locked<H: CommittedHistory + ?Sized>(
        &self,
        candidate: LockedRecord,
        expected_revision: u64,
        history: Option<&H>,
    ) -> PublishResult {
        let guard = self.backend.lock_domain();

        // A fresh durability acknowledgement is required before dependent
        // publication: a newly opened established store (no inherited
        // acknowledgement knowledge) or a prior ambiguous/uncertain publication
        // blocks further O4 until a successful recovery operation (O5) — or an
        // acknowledged O1 — re-establishes effectiveness. Refuse before any
        // read/write. Reopening does not bypass this.
        if self.backend.recovery_required() {
            return PublishResult::RefusedPreWrite(SafetyStoreError::RecoveryRequired(
                RecoveryRequiredReason::FreshAcknowledgementRequired,
            ));
        }

        // Allocation-free structural/capacity PREFLIGHT of the by-value candidate
        // (§ 13.2A / § 13.7, D7-D14 O4 admission-order correction): the candidate is
        // owned at by-value entry, so its evidence counts/lengths/widths can be refused
        // here — before the O4 reservation, the authoritative predecessor read/decode/
        // validation (`load_established` + predecessor `validate_decoded`), and every
        // component-owned candidate clone, binding `cert` scratch, or `encode_record`
        // buffer. A candidate that must be refused for an over-bound count/length/width
        // (e.g. `S_sig=8` with a 9-byte signature) therefore pays no avoidable
        // predecessor read or encode. This preflight performs no allocation and does NOT
        // substitute for the authoritative predecessor validation enforced below.
        if let Err(e) = super::codec::admit_supporting_evidence(&candidate.evidence, self.pinned())
        {
            return PublishResult::RefusedPreWrite(e);
        }

        // Reserve the O4 working-set peak against the shared aggregate accountant
        // BEFORE any O4 allocation/copy (§ 13.7 / § 13.7B). It bounds the
        // simultaneous coexistence of the live TRANSIENT decoded objects and the
        // record-sized buffers that peak together across the operation. The two
        // decoded terms are reserved at the TRANSIENT decoded ceiling
        // (`max_transient_decoded_working_set`) — a `DecodedRecord` is larger than
        // the retained generation, so the retained-generation ceiling under-reserves
        // it — covering: (phase A) the authoritative predecessor decoded + its
        // validation copy, then (phase B) the candidate decoded; plus the three
        // record-sized buffers (predecessor read-back, candidate publication, and
        // the validation re-encode scratch) and the fixed metadata buffer. The
        // predecessor decoded is dropped before the candidate is built and the final
        // candidate validation consumes (does not clone) the decoded + encoded
        // operands, so no more than two transient decoded objects and three
        // record-sized buffers are ever simultaneously live. A capacity refusal here
        // is a pre-write refusal that leaves the established evidence and any admitted
        // retained holders untouched; the reservation releases on every exit (refusal,
        // error, uncertainty, success) via its drop at end of scope.
        let transient = match super::accounting::max_transient_decoded_working_set(self.pinned()) {
            Ok(v) => v,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        let rec = match max_safety_record_bytes(self.pinned()) {
            Ok(v) => v,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        // NOTE: unlike O1/O5, the O4 reservation already conservatively covers the
        // publish-time CRC-framing envelopes: it reserves THREE record-sized buffers
        // (predecessor read-back, candidate publication, validation re-encode
        // scratch) as a whole-operation peak, but the predecessor decoded + its
        // read-back are dropped and the validation operands consumed before
        // `publish_atomic` runs, so at the write boundary the live set
        // (candidate publication + its `wrap` envelope + metadata + its `wrap`
        // envelope) fits within the already-reserved three-record peak. Adding a
        // separate staging term here would double-count and make a valid O4 that
        // coexists with a live O3 holder unadmittable within the unchanged aggregate.
        let o4_charge = transient
            .checked_mul(2)
            .and_then(|g| rec.checked_mul(3).and_then(|r| g.checked_add(r)))
            .and_then(|s| s.checked_add(super::backend::META_ENCODED_LEN));
        let o4_charge = match o4_charge {
            Some(v) => v,
            None => {
                return PublishResult::RefusedPreWrite(SafetyStoreError::ArithmeticOverflow(
                    ArithmeticOverflowSite::O4WorkingSetCharge,
                ))
            }
        };
        let _o4_res = match self.backend.accounting().reserve(o4_charge) {
            Ok(r) => r,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };

        // Re-read and establish authoritative state under the ownership boundary:
        // presence, structure, metadata↔record revision consistency, and
        // pinned-context correspondence are all enforced centrally.
        let (meta, current_bytes, current) = match self.load_established() {
            Ok(triple) => triple,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        // Expected-revision fence.
        if meta.current_revision != expected_revision {
            return PublishResult::RefusedPreWrite(SafetyStoreError::StaleRevision {
                expected: expected_revision,
                stored: meta.current_revision,
            });
        }

        // Capture the predecessor lock view for the eligibility check BEFORE the
        // predecessor decoded object is consumed by validation, so the authoritative
        // predecessor can be validated by VALUE (no retained clone) while its one
        // cheap scalar field remains available afterwards.
        let predecessor_lock_view = match &current.record {
            SafetyRecord::Locked(cur) => Some(cur.lock_view),
            _ => None,
        };

        // Validate the authoritative PREDECESSOR itself (structural + semantic)
        // before relying on it as the eligibility base; O4 must not act on an
        // unvalidated predecessor. The predecessor decoded object and its read-back
        // bytes are CONSUMED here (not cloned): the predecessor is dropped before the
        // candidate decoded object is built, so the two transient decoded objects do
        // not coexist. The candidate is validated separately below.
        if let Err(e) = validate_decoded(current, current_bytes, self.pinned(), history) {
            return PublishResult::RefusedPreWrite(e);
        }

        // Transition eligibility: strictly-increasing lock view.
        if let Some(cur_lock_view) = predecessor_lock_view {
            if candidate.lock_view <= cur_lock_view {
                // G1: typed, allocation-free transition-eligibility refusal. The two
                // `u64` lock views are carried as `Copy` scalars, so this diagnostic
                // is constructed with ZERO heap allocation inside the active O4
                // reservation (no `format!` String whose backing-capacity growth could
                // exceed the admitted charge).
                return PublishResult::RefusedPreWrite(SafetyStoreError::TransitionIneligible(
                    super::error::TransitionIneligibleDetail {
                        candidate_lock_view: candidate.lock_view,
                        current_lock_view: cur_lock_view,
                    },
                ));
            }
        }

        // Recompute the evidence binding so the stored record is self-consistent,
        // then validate the full candidate semantics before writing.
        let binding = match compute_evidence_lock_binding(
            &candidate.lock_block_id,
            candidate.lock_view,
            &candidate.evidence,
            &candidate.authority_context_ref,
            self.pinned(),
        ) {
            Ok(b) => b,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        let mut candidate = candidate;
        candidate.evidence_lock_binding = binding;

        // Checked revision increment.
        let new_revision = match meta.current_revision.checked_add(1) {
            Some(v) => v,
            None => {
                return PublishResult::RefusedPreWrite(SafetyStoreError::ArithmeticOverflow(
                    ArithmeticOverflowSite::PublicationRevisionExhausted,
                ))
            }
        };

        let decoded = DecodedRecord {
            persistence_format_version: super::profile::SAFETY_PERSISTENCE_FORMAT_VERSION,
            network_genesis_id: self.pinned().network_genesis_id,
            publication_revision: new_revision,
            record: SafetyRecord::Locked(candidate),
        };
        // Full semantic validation of the candidate before any write. The decoded
        // candidate and its encoded bytes are CONSUMED (not cloned) by validation,
        // which re-encodes the decoded content and establishes decoded↔encoded
        // correspondence; the validated proof RETAINS those exact encoded bytes, so
        // the subsequent atomic publish reuses `validated.encoded()` rather than a
        // second copy of the publication buffer.
        let encoded = match encode_record(&decoded, self.pinned()) {
            Ok(b) => b,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        let validated = match validate_decoded(decoded, encoded, self.pinned(), history) {
            Ok(v) => v,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };

        let new_meta = SafetyMeta {
            meta_format_version: META_FORMAT_VERSION,
            context_digest: meta.context_digest,
            current_revision: new_revision,
        };
        match self
            .backend
            .publish_atomic(&guard, &new_meta.encode(), validated.encoded())
        {
            PublishOutcome::DurableAcknowledged => {
                // Deterministic post-acknowledgement / pre-effectiveness crash
                // boundary (§ 13.5): the durable acknowledgement has returned, but
                // the in-memory effectiveness transition has NOT yet happened. A
                // test-only hook (unavailable in a default/release build) may
                // identify and terminate at exactly this point, proving that
                // termination precedes the transition and that a reopen starts
                // without inherited effectiveness.
                #[cfg(any(test, feature = "test-utils"))]
                self.backend.run_pre_effective_hook("O4", new_revision);
                // An acknowledged O4 durable success keeps the shared state
                // effective for subsequent eligible transitions.
                self.backend.mark_effective();
                PublishResult::DurableAcknowledged { new_revision }
            }
            PublishOutcome::PreWriteRefused(m) => PublishResult::RefusedPreWrite(
                SafetyStoreError::WriteFailed(super::error::WriteFailedDetail::Static(m)),
            ),
            PublishOutcome::WriteError(m) => PublishResult::WriteFailedAmbiguous(m),
            PublishOutcome::UncertainDurable => PublishResult::UncertainDurable,
        }
    }

    // -----------------------------------------------------------------------
    // O5 — re-acknowledge
    // -----------------------------------------------------------------------

    /// **O5**: compare the retained original validated publication (`ENC_INPUT`)
    /// against a fresh read of the currently stored publication, **byte for
    /// byte**, under the owner/revision boundary. On complete equality,
    /// republish the original bytes verbatim and require a fresh durability
    /// acknowledgement. A stale O5 (stored state no longer equals the retained
    /// original) refuses without overwriting newer state.
    pub fn reacknowledge(&self, retained: &ValidatedRecord) -> PublishResult {
        let guard = self.backend.lock_domain();

        // Reserve the O5 working set against the shared aggregate accountant BEFORE
        // `load_established` copies the stored payload into a component-owned buffer
        // (§ 13.7: reservations precede the copy). `load_established` builds THREE
        // live objects O5 must cover: the record-sized read-back buffer, the fixed
        // metadata buffer, and one TRANSIENT decoded object (reserved at the
        // transient decoded ceiling, NOT the smaller retained-generation ceiling).
        // The retained original operand is already charged by the holder reservation
        // carried in `retained`, so O5 does not add an uncharged record-sized buffer
        // for it; this read-back + metadata + transient-decode reservation plus the
        // pre-charged retained holder bound the O5 complete-content comparison.
        //
        // PUBLICATION-ENVELOPE COEXISTENCE (§ 13.5, D7-D14 item-5 correction): the
        // retained `stored` read-back and `_stored_decoded` transient remain live
        // when `publish_atomic` wraps the republished bytes, so the two CRC-wrapped
        // staging envelopes (`SafetyBackend::wrap` over the record and over the
        // metadata) coexist with them. Those component-owned framing buffers were
        // previously uncharged; `publication_staging_charge` now reserves them here
        // too, BEFORE `wrap` allocates them. Releases on every exit via drop at end
        // of scope.
        let o5_readback = match max_safety_record_bytes(self.pinned()) {
            Ok(v) => v,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        let o5_transient = match super::accounting::max_transient_decoded_working_set(self.pinned())
        {
            Ok(v) => v,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        let o5_staging = match super::accounting::publication_staging_charge(self.pinned()) {
            Ok(v) => v,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        let o5_charge = o5_readback
            .checked_add(super::backend::META_ENCODED_LEN)
            .and_then(|b| b.checked_add(o5_transient))
            .and_then(|b| b.checked_add(o5_staging));
        let o5_charge = match o5_charge {
            Some(v) => v,
            None => {
                return PublishResult::RefusedPreWrite(SafetyStoreError::ArithmeticOverflow(
                    ArithmeticOverflowSite::O5ReadBackWorkingSet,
                ))
            }
        };
        let _o5_res = match self.backend.accounting().reserve(o5_charge) {
            Ok(r) => r,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };

        // O5 is the recovery operation; it is permitted to run while the shared
        // recovery requirement is set, and a successful fresh acknowledgement is
        // what clears it. Enforce the established-state + pinned-context
        // prerequisites first (foreign-context metadata is refused).
        let (meta, stored, _stored_decoded) = match self.load_established() {
            Ok(triple) => triple,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };

        // The retained proof must have been sealed under THIS handle's pinned
        // context; a proof produced under a foreign context cannot authorize a
        // re-publication here.
        if retained.origin_context_digest() != &context_digest(self.pinned()) {
            return PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(
                super::error::SemanticRefusalDetail::Static(
                    "retained publication was validated under a different pinned context",
                ),
            ));
        }

        // The retained proof must carry an O5 recovery capability bound to THIS
        // backend's ownership incarnation (§ 13.4 / § 13.5). Identical pinned
        // contexts are shared by different stores, so the context digest alone is
        // NOT backend identity. A token minted by O3 on a DIFFERENT backend
        // instance (another store, or a reopened incarnation of the same DB) is
        // refused even when context, revision, and publication bytes are
        // identical; a semantic/codec-only proof (public `validate_decoded`) or a
        // bootstrap-builder proof carries no capability and is refused here. Only
        // a fresh O3 on this exact backend incarnation yields an O5-usable token.
        match retained.recovery_backend_incarnation() {
            Some(inc) if inc == self.backend.incarnation() => {}
            _ => {
                return PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(
                    super::error::SemanticRefusalDetail::Static(
                        "retained publication is not an O5 recovery capability for this backend \
                         incarnation (no cross-store / cross-reopen transfer of recovery authority)",
                    ),
                ))
            }
        }

        // Complete byte-for-byte equality — NOT a digest, NOT a re-encode, NOT a
        // normalization. Divergence anywhere (even outside the binding digest's
        // coverage) refuses.
        if stored.as_slice() != retained.encoded() {
            return PublishResult::RefusedPreWrite(SafetyStoreError::PublicationMismatch(
                "stored publication differs from retained original (byte-for-byte)",
            ));
        }
        // The retained revision must also still be the authoritative revision.
        if retained.publication_revision() != meta.current_revision {
            return PublishResult::RefusedPreWrite(SafetyStoreError::StaleRevision {
                expected: retained.publication_revision(),
                stored: meta.current_revision,
            });
        }

        // Republish the ORIGINAL bytes verbatim; metadata revision is unchanged.
        // Name the metadata encode buffer as a local so its capacity can be measured
        // and so the SAME object is the one passed to `publish_atomic` (behaviour is
        // unchanged — the bytes are identical to `meta.encode()` inline).
        let meta_encoded = meta.encode();
        // M2 (test-only, RUN 422 D7-D14): record the owner-held live-object scalar
        // snapshot while ALL of these objects are alive, immediately before
        // `publish_atomic`: the retained proof's encoded buffer, its retained
        // representation + nested backings, the contract-charged holder handle, the
        // fresh read-back buffer, the transient decoded object, and the metadata
        // payload buffer. The backend boundary adds the two CRC staging envelopes.
        // `stored` and `_stored_decoded` remain alive through the call below (they are
        // in scope until end of function), and `retained`/`meta_encoded` are borrowed
        // by the `publish_atomic` call itself, so every snapshotted object is live and
        // unchanged at the boundary. No-op in production builds.
        #[cfg(any(test, feature = "test-utils"))]
        {
            // RUN 422 D7-D14 S2: measure the two component charges EXPLICITLY. A
            // failed measurement must NOT silently substitute zero, must NOT yield a
            // valid partial total, and must NOT leave an earlier successful snapshot
            // available as the current result. On either failure the observation is
            // fail-closed (invalidated) and the typed error is recorded for the test;
            // the real `publish_atomic` below is unaffected (storage behaviour and
            // production semantics are unchanged).
            let retained_generation_charge = match &retained.retained().record {
                super::record::SafetyRecord::Locked(l) => measure_o5_evidence_backing(&l.evidence)
                    .map(|backing| super::record::size_of_retained_record() + backing),
                super::record::SafetyRecord::BootstrapNoLock { .. } => {
                    Ok(super::record::size_of_retained_record())
                }
            };
            let transient_decoded_charge = measure_o5_transient_decode(&_stored_decoded);
            match (retained_generation_charge, transient_decoded_charge) {
                (Ok(retained_generation_charge), Ok(transient_decoded_charge)) => {
                    super::backend::set_o5_owner_live_snapshot(
                        retained.encoded_capacity() as u128,
                        retained_generation_charge,
                        super::record::validated_holder_handle_bytes(),
                        stored.capacity() as u128,
                        transient_decoded_charge,
                        meta_encoded.capacity() as u128,
                    );
                }
                (Err(_), _) => super::backend::invalidate_o5_live_object_observation(
                    super::backend::O5ObservationError::RetainedBackingMeasurementFailed,
                ),
                (_, Err(_)) => super::backend::invalidate_o5_live_object_observation(
                    super::backend::O5ObservationError::TransientDecodeMeasurementFailed,
                ),
            }
        }
        match self
            .backend
            .publish_atomic(&guard, &meta_encoded, retained.encoded())
        {
            PublishOutcome::DurableAcknowledged => {
                // The required successful recovery durability operation marks the
                // shared state effective again for every handle.
                self.backend.mark_effective();
                PublishResult::DurableAcknowledged {
                    new_revision: meta.current_revision,
                }
            }
            PublishOutcome::PreWriteRefused(m) => PublishResult::RefusedPreWrite(
                SafetyStoreError::WriteFailed(super::error::WriteFailedDetail::Static(m)),
            ),
            PublishOutcome::WriteError(m) => PublishResult::WriteFailedAmbiguous(m),
            PublishOutcome::UncertainDurable => PublishResult::UncertainDurable,
        }
    }
}

/// Build a `BootstrapNoLock` validated record view (used by callers/tests that
/// need the explicit bootstrap variant with the always-`Unverified` status).
pub fn bootstrap_validated(
    ctx: &PinnedSafetyContext,
    revision: u64,
) -> Result<ValidatedRecord, SafetyStoreError> {
    let decoded = DecodedRecord {
        persistence_format_version: super::profile::SAFETY_PERSISTENCE_FORMAT_VERSION,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: revision,
        record: SafetyRecord::BootstrapNoLock {
            authority_context_ref: ctx.authority_context_ref,
            predecessor_ref: None,
        },
    };
    let encoded = encode_record(&decoded, ctx)?;
    // Discard the validated identity-header fields from the retained generation
    // (§ 13.7A(c.4)); their bytes remain only in `encoded`.
    let retained = super::record::RetainedRecord {
        publication_revision: decoded.publication_revision,
        record: decoded.record,
    };
    Ok(ValidatedRecord::seal(
        retained,
        EvidenceStatus::Unverified,
        encoded,
        context_digest(ctx),
    ))
}

/// Helper to construct a QC-derived locked record for callers/tests, with the
/// binding digest computed consistently.
pub fn make_locked_qc(
    ctx: &PinnedSafetyContext,
    lock_block_id: [u8; 32],
    lock_view: u64,
    qc: super::record::WireQc,
    committed_anchor: Option<super::record::CommittedAnchor>,
) -> Result<LockedRecord, SafetyStoreError> {
    let evidence = SupportingEvidence::QcDerived(qc);
    // Public builder: admit the evidence structure BEFORE the evidence-binding
    // allocation (same discipline as O4). An over-bound signature/count/width is
    // refused before `compute_evidence_lock_binding` owns any variable-size buffer.
    super::codec::admit_supporting_evidence(&evidence, ctx)?;
    let binding = compute_evidence_lock_binding(
        &lock_block_id,
        lock_view,
        &evidence,
        &ctx.authority_context_ref,
        ctx,
    )?;
    Ok(LockedRecord {
        lock_block_id,
        lock_view,
        evidence_lock_binding: binding,
        authority_context_ref: ctx.authority_context_ref,
        committed_anchor,
        predecessor_ref: None,
        evidence,
    })
}