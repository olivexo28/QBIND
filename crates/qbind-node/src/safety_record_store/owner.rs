//! Run 422 D7-D14 — the O1–O5 operations and the enforced single-writer
//! ownership / expected-revision fencing boundary (§ 13.4 / § 13.5).
//!
//! Every mutating operation takes the one shared serialization domain of the
//! attached [`SafetyBackend`] instance, re-reads the authoritative revision
//! under that lock, fences on the caller's expected revision, and only then
//! performs the checked, atomic, synchronous publication. Validation refusal,
//! write failure, uncertain publication, acknowledged durable success, and
//! in-memory effectiveness are returned as distinct outcomes.

use std::sync::{Arc, Mutex};

use sha3::{Digest, Sha3_256};

use super::backend::{PublishOutcome, SafetyBackend};
use super::codec::{compute_evidence_lock_binding, decode_record, encode_record};
use super::error::{
    AlreadyEstablishedKind, ArithmeticOverflowSite, CapacityRefusalDetail,
    MissingIndependentInputSite, RecoveryRequiredReason, SafetyStoreError, StructuralRefusalDetail,
};
use super::accounting::prepared_generation_charge;
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

// Test-only CONTEMPORANEOUS late-O2 reservation observation (RUN 422 D7-D14, late
// reservation-lifetime evidence). The existing late-O2 regression established that
// the malformed maximum-TC record refuses only AFTER the full TC evidence graph and
// committed anchor are decoded, and bracketed the O2 reservation by headroom and by
// the historical aggregate PEAK. Neither establishes that the O2 reservation is still
// active AT the late decode point: a successful initial admission followed by a
// premature release would still satisfy a historical-peak/headroom assertion. This
// hook closes that gap by sampling the executing backend's live operational AND
// aggregate accounting from INSIDE `decode_record`, at the exact late phase — after
// `decode_timeout_cert` and `read_optional_anchor` have decoded the TC evidence graph
// and committed anchor, immediately before `read_optional_predecessor` rejects the
// invalid predecessor discriminant and unwinds them.
//
// The observation is RESTRICTED to the armed O2 operation and its accountant: `open()`
// arms the hook with a cloned handle of the SAME backend operational accountant it
// reserved against, and disarms immediately after `load_established` returns. A
// standalone `decode_record`, a later operation, or an O2 that refuses before this
// phase therefore records NOTHING — the slot stays `None`, and the accessor returns
// `None` (a missing observation is an explicit failure for the test, never a zero
// substitution). The hook samples two live scalar charges; it clones no object graph,
// allocates nothing, and extends no production object's lifetime. Gated behind
// `cfg(test)`/`test-utils`; absent from production builds.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    // The executing backend's cloned operational accountant handle, armed by `open()`
    // around its `load_established`. Presence (Some) is the ARMED marker; the decode
    // hook samples `(operational.current(), aggregate.current())` from THIS handle.
    static O2_LATE_DECODE_ACCT: std::cell::RefCell<
        Option<super::accounting::SharedAccountant>,
    > = const { std::cell::RefCell::new(None) };
    // The `(operational, aggregate)` reservation pair sampled at the late decode phase.
    // Reset to `None` on each arm, so a missing phase cannot reuse an earlier result.
    static O2_LATE_DECODE_OBS: std::cell::Cell<Option<(u128, u128)>> =
        const { std::cell::Cell::new(None) };
}

/// Test-only: arm/reset the contemporaneous late-O2 reservation observation for the
/// current thread with the executing backend's operational accountant handle. Called
/// by `open()` immediately before `load_established`. Arming the accountant handle is
/// what RESTRICTS recording to this O2 operation: a standalone `decode_record` (or a
/// later operation) never arms it, so its hook is a no-op. Resetting the slot to
/// `None` here ensures a missing late phase cannot reuse an earlier successful sample.
#[cfg(any(test, feature = "test-utils"))]
fn arm_o2_late_decode_observation(acct: super::accounting::SharedAccountant) {
    O2_LATE_DECODE_ACCT.with(|s| *s.borrow_mut() = Some(acct));
    O2_LATE_DECODE_OBS.with(|c| c.set(None));
}

/// Test-only: reset the late-O2 observation at the START of each `open()` attempt,
/// before any fallible charge calculation or reservation admission can return early.
/// Clears BOTH the recorded sample (`O2_LATE_DECODE_OBS` → `None`) and any lingering
/// armed handle (`O2_LATE_DECODE_ACCT` → `None`), so an admission-refused O2 that
/// returns before `arm_o2_late_decode_observation` cannot expose the PREVIOUS
/// operation's sample, and no stale accountant survives into the next attempt. The
/// arming performed after admission is what later RESTRICTS recording to the admitted
/// operation's decode interval; this entry reset is what guarantees a never-armed or
/// pre-admission-refused operation exposes `None`.
#[cfg(any(test, feature = "test-utils"))]
fn reset_o2_late_decode_observation() {
    O2_LATE_DECODE_ACCT.with(|s| *s.borrow_mut() = None);
    O2_LATE_DECODE_OBS.with(|c| c.set(None));
}

/// Test-only: disarm the late-O2 observation. Called by `open()` immediately after
/// `load_established` so no later `decode_record` resamples a stale handle. The
/// recorded `O2_LATE_DECODE_OBS` value survives for the test to read.
#[cfg(any(test, feature = "test-utils"))]
fn disarm_o2_late_decode_observation() {
    O2_LATE_DECODE_ACCT.with(|s| *s.borrow_mut() = None);
}

/// Crate/test-only: invoked by `decode_record` at the late decode phase — after the
/// TC evidence graph and committed anchor are decoded and owned, immediately before
/// the optional-predecessor discriminant is validated. Records the active
/// `(operational, aggregate)` reservations of the armed backend accountant. A no-op
/// unless `open()` armed the observation, so a standalone `decode_record` records
/// nothing.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn observe_o2_late_decode_reservation() {
    O2_LATE_DECODE_ACCT.with(|s| {
        if let Some(acct) = s.borrow().as_ref() {
            let sample = (acct.current(), acct.aggregate().current());
            O2_LATE_DECODE_OBS.with(|c| c.set(Some(sample)));
        }
    });
}

/// Test-only: the `(operational, aggregate)` reservation pair sampled CONTEMPORANEOUSLY
/// at the last armed O2 late decode phase, or `None` if that phase was not reached
/// (a missing observation is an explicit failure, never a zero substitution).
#[cfg(any(test, feature = "test-utils"))]
pub fn observed_o2_late_decode_reservation() -> Option<(u128, u128)> {
    O2_LATE_DECODE_OBS.with(|c| c.get())
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

// Test-only shared-conversion lifetime seam (RUN 422 §13.6 §2 correction). The
// shared capture path must DESTROY the duplicate proof's separately owned evidence
// backings BEFORE releasing `prior_holder` â the reservation that covered them â
// so those live bytes are never uncharged across the conversion. When this seam is
// armed, the NEXT shared capture on this thread uses the PREMATURE ordering (release
// the covering reservation first, while the duplicate evidence is still alive): an
// INSTRUMENTED reproduction of the historical defect, consumed (reset to `Correct`)
// by the shared capture that reads it. Absent from production builds; the production
// path always uses the corrected `RetainedBeforeHolder` ordering.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SharedReleaseOrder {
    /// Corrected ordering: drop the duplicate's evidence backings, THEN release the
    /// covering `prior_holder` reservation.
    #[default]
    RetainedBeforeHolder,
    /// Premature ordering (defect reproduction): release `prior_holder` while the
    /// duplicate's evidence backings are still alive.
    HolderBeforeRetained,
}

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static SHARED_RELEASE_ORDER: std::cell::Cell<SharedReleaseOrder> =
        const { std::cell::Cell::new(SharedReleaseOrder::RetainedBeforeHolder) };
    static SHARED_DUP_LIVE_AT_RELEASE: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// Test-only (RUN 422 §2 lifetime regression): force the NEXT shared capture on this
/// thread to use the given release ordering. The flag is consumed by that capture.
#[cfg(any(test, feature = "test-utils"))]
pub fn set_shared_release_order(order: SharedReleaseOrder) {
    SHARED_RELEASE_ORDER.with(|c| c.set(order));
}

/// Test-only (RUN 422 §2 lifetime regression): the duplicate's evidence-backing
/// bytes still live when its covering reservation was released by the most recent
/// shared capture. `Some(0)` after the corrected ordering, `Some(n>0)` after the
/// premature ordering. `None` if no shared capture has run on this thread.
///
/// NOTE (RUN 422 §2 B): this is the earlier, NARROWER **branch-assigned** observer
/// — the capture path *sets* it from the selected [`SharedReleaseOrder`] branch
/// (`Some(0)` in the corrected branch, `Some(dup_bytes)` in the premature branch).
/// It reports which branch ran and what that branch claims; it does not
/// independently observe backing destruction. The independent observer is
/// [`dup_backing_live_at_release`] below. This one is retained as historical
/// evidence for the branch-selection experiment (`spike_sharing_lifetime_regression`).
#[cfg(any(test, feature = "test-utils"))]
pub fn shared_dup_live_at_release() -> Option<usize> {
    SHARED_DUP_LIVE_AT_RELEASE.with(|c| c.get())
}

// Independent duplicate-backing OWNED-OBJECT DESTRUCTION probe (RUN 422 §2 B).
// Unlike the branch-assigned `shared_dup_live_at_release` observer above — which
// the capture path SETS from the selected release-order flag — this probe
// measures the ACTUAL destruction of the duplicate proof's owned evidence-backing
// objects by their MEASURED BACKING BYTES (it does NOT trace allocation
// addresses or object identities). Each duplicate backing is registered as live
// with its measured byte size and a `Drop` probe is bundled onto the retained
// object; the probe decrements the live byte total when (and ONLY when) that
// owned object is actually destroyed. At the covering-reservation release
// boundary the still-live total is sampled. The sample is therefore derived from
// real owned-object destruction — not from the branch chosen and not from any
// hard-coded expected value. A source mutation that releases the covering
// reservation before destroying the duplicate's backing leaves the probe
// un-dropped at the sample, so it reports the still-live bytes and the invariant
// fails — demonstrating its release-order sensitivity.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static DUP_BACKING_LIVE_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DUP_BACKING_LIVE_AT_RELEASE: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// A bounded **owned-object destruction probe** with measured backing bytes,
/// bundled onto the duplicate proof's retained evidence backing: constructing it
/// registers `bytes` live; dropping it (which happens exactly when the bundled
/// owned object is destroyed) removes them. It measures owned-object destruction
/// by byte size, not allocation-address/identity tracing, and is independent of
/// the release-order branch.
#[cfg(any(test, feature = "test-utils"))]
struct DupBackingLiveProbe {
    bytes: usize,
}

#[cfg(any(test, feature = "test-utils"))]
impl Drop for DupBackingLiveProbe {
    fn drop(&mut self) {
        DUP_BACKING_LIVE_BYTES.with(|c| c.set(c.get().saturating_sub(self.bytes)));
    }
}

/// Test-only (RUN 422 §2 B): the number of duplicate evidence-backing bytes that
/// were still live at the moment the most recent shared capture released the
/// reservation covering them, measured by the INDEPENDENT owned-object
/// destruction probe (not the release-order flag, not a hard-coded value).
/// `Some(0)` means the invariant held — no duplicate byte outlived its covering
/// reservation; `Some(n>0)` means `n` bytes were live-but-uncharged at the
/// release boundary. `None` if no shared capture has run on this thread.
#[cfg(any(test, feature = "test-utils"))]
pub fn dup_backing_live_at_release() -> Option<usize> {
    DUP_BACKING_LIVE_AT_RELEASE.with(|c| c.get())
}

// ---------------------------------------------------------------------------
// Test-only (RUN 422 §3 serialization regression): a one-shot hook fired by the
// capture path at the EXACT interval between the authoritative-state check and
// the registry insertion, WHILE the serialization domain guard is held. It lets
// a focused test create a coordinated capture/publication OVERLAP: a concurrent
// O4 publication (which must take the SAME domain lock, see `publish_locked`)
// cannot make progress while this hook runs, so correct serialization keeps the
// two mutually exclusive. The hook is thread-local (fires on the capturing
// thread) and consumed on first fire. Absent from production/release builds.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static CAPTURE_INTERVAL_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only (RUN 422 §3): install a one-shot capture-interval hook on this
/// thread. The NEXT prepared capture on this thread fires it once (between the
/// authoritative-state check and the registry insertion, under the domain guard)
/// and clears it.
#[cfg(any(test, feature = "test-utils"))]
pub fn set_capture_interval_hook<F: Fn() + Send + Sync + 'static>(f: F) {
    CAPTURE_INTERVAL_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

/// Test-only (RUN 422 §3): clear any installed capture-interval hook on this
/// thread.
#[cfg(any(test, feature = "test-utils"))]
pub fn clear_capture_interval_hook() {
    CAPTURE_INTERVAL_HOOK.with(|h| *h.borrow_mut() = None);
}

/// Fire and consume the one-shot capture-interval hook, if installed. Called by
/// the capture path while holding the serialization domain guard.
#[cfg(any(test, feature = "test-utils"))]
fn fire_capture_interval_hook() {
    let cb = CAPTURE_INTERVAL_HOOK.with(|h| h.borrow_mut().take());
    if let Some(cb) = cb {
        cb();
    }
}

// Test-only (RUN 422 §5 pre-ingestion serialization observation). This hook
// fires on the owner thread IMMEDIATELY BEFORE the owner invokes
// `on_proposal_event_gated_owning`, i.e. after the single serialization-domain
// guard has been acquired but before engine ingestion begins. Its semantic
// location is fixed at the pre-ingestion boundary: unlike the capture-interval
// hook (which fires inside capture, after ingestion has begun), this one can
// establish that the owner held the domain BEFORE ingestion. A focused
// serialization regression installs a hook here that signals a competing,
// non-blocking same-domain acquisition (which must observe `WouldBlock`, not
// poisoning) and then awaits release under a bounded wait. Thread-local,
// one-shot, consumed on first fire. Absent from production/release builds.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static PRE_INGESTION_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only (RUN 422 §5): install a one-shot pre-ingestion hook on this thread.
/// The NEXT owner-route decision on this thread fires it once, strictly before
/// `on_proposal_event_gated_owning`, while the serialization domain guard is
/// held, and clears it.
#[cfg(any(test, feature = "test-utils"))]
pub fn set_pre_ingestion_hook<F: Fn() + Send + Sync + 'static>(f: F) {
    PRE_INGESTION_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

/// Test-only (RUN 422 §5): clear any installed pre-ingestion hook on this thread.
#[cfg(any(test, feature = "test-utils"))]
pub fn clear_pre_ingestion_hook() {
    PRE_INGESTION_HOOK.with(|h| *h.borrow_mut() = None);
}

/// Fire and consume the one-shot pre-ingestion hook, if installed. Called by the
/// owner route while holding the serialization domain guard, before ingestion.
#[cfg(any(test, feature = "test-utils"))]
fn fire_pre_ingestion_hook() {
    let cb = PRE_INGESTION_HOOK.with(|h| h.borrow_mut().take());
    if let Some(cb) = cb {
        cb();
    }
}

// Test-only (RUN 422 §3 binding-phase reservation-overlap observation). This
// hook fires on the owner thread at the capture binding phase — after the
// additional `covering` (envelope/data) reservation has been admitted and the
// transient `scratch` reservation has been admitted, but BEFORE any covered
// binding value (the proposal commitment / ancestry binding) is produced. At
// that instant the baseline proof, the `covering` reservation and the `scratch`
// reservation are all live simultaneously (the actual reservation overlap). A
// discriminating regression reads the accounting occupancy here and confirms the
// occupancy already includes `covering` — proving `covering` was admitted BEFORE
// this phase (the corrected admission order), not afterwards as in the reviewed
// order. Thread-local, one-shot. Absent from production/release builds.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static BINDING_PHASE_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only (RUN 422 §3): install a one-shot binding-phase observation hook on
/// this thread. The NEXT owner-route capture on this thread fires it once, at the
/// binding phase (covering + scratch both admitted, before the covered binding
/// values are produced), and clears it.
#[cfg(any(test, feature = "test-utils"))]
pub fn set_binding_phase_hook<F: Fn() + Send + Sync + 'static>(f: F) {
    BINDING_PHASE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

/// Test-only (RUN 422 §3): clear any installed binding-phase hook on this thread.
#[cfg(any(test, feature = "test-utils"))]
pub fn clear_binding_phase_hook() {
    BINDING_PHASE_HOOK.with(|h| *h.borrow_mut() = None);
}

/// Fire and consume the one-shot binding-phase hook, if installed. Called by the
/// owner route at the binding phase while holding the serialization domain guard.
#[cfg(any(test, feature = "test-utils"))]
fn fire_binding_phase_hook() {
    let cb = BINDING_PHASE_HOOK.with(|h| h.borrow_mut().take());
    if let Some(cb) = cb {
        cb();
    }
}

// Test-only (RUN 422 §13.6 observation working-set admission + serialization
// observation). This hook fires on the observing thread INSIDE
// `observe_retained_decision`, WHILE the single serialization-domain guard is
// held, AFTER the loader phase has already admitted and released its own
// reservations (its holder reservation stays live, its O3 scratch is gone) and
// the engine<->durable correspondence has passed, but strictly BEFORE the
// observation working-set reservation is admitted and before any covered
// restriction-identity / provenance / context-digest / commitment-ancestry
// object is used in the bounded checks.
//
// It lets a focused regression do two separable things that the loader-phase
// hook cannot:
//   * ISOLATE the LATER admission phase — install a hook that reserves the
//     remaining aggregate budget here, after the loader already succeeded, so
//     ONLY the observation-working-set reservation is refused (`Admission`),
//     proving the two admission phases are charged and can fail independently;
//   * COORDINATE a publication-exclusion handshake — a concurrent publication
//     must take the SAME domain lock, so while this hook pauses holding the
//     guard a competing non-blocking acquisition observes `WouldBlock`, and an
//     eligible publication succeeds only AFTER the observation releases.
// Thread-local, one-shot, consumed on first fire. Absent from production builds.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static OBSERVATION_WS_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only (RUN 422 §13.6): install a one-shot observation-working-set hook on
/// this thread. The NEXT `observe_retained_decision` on this thread fires it once
/// (domain guard held, loader phase complete, before the observation working-set
/// reservation is admitted) and clears it.
#[cfg(any(test, feature = "test-utils"))]
pub fn set_observation_working_set_hook<F: Fn() + Send + Sync + 'static>(f: F) {
    OBSERVATION_WS_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

/// Test-only (RUN 422 §13.6): clear any installed observation-working-set hook on
/// this thread.
#[cfg(any(test, feature = "test-utils"))]
pub fn clear_observation_working_set_hook() {
    OBSERVATION_WS_HOOK.with(|h| *h.borrow_mut() = None);
}

/// Fire and consume the one-shot observation-working-set hook, if installed.
/// Called by `observe_retained_decision` while holding the serialization domain
/// guard, before the observation working-set reservation is admitted. A no-op in
/// production (the hook is never installed there).
#[cfg(any(test, feature = "test-utils"))]
fn fire_observation_working_set_hook() {
    let cb = OBSERVATION_WS_HOOK.with(|h| h.borrow_mut().take());
    if let Some(cb) = cb {
        cb();
    }
}

// ---------------------------------------------------------------------------
// Test-only (RUN 422 §3 pre-effective O4-owned live-object observation). At the
// post-acknowledgement / pre-effectiveness O4 phase, the publish path holds the
// ACTUAL live publication objects: the validated proof (`validated`, a
// `ValidatedRecord` — NOT a transient `DecodedRecord`), whose embedded retained
// generation still owns its evidence heap backings and whose `encoded` buffer is
// retained verbatim, and the component-owned metadata-encoding temporary
// (`meta_encoded`), which stays live through the publish match arm. The CRC
// staging envelopes inside `publish_atomic` have already been destroyed (the call
// has returned by this phase) and are deliberately NOT counted.
//
// At exactly that phase the publish path measures those live objects IN PLACE —
// the complete `ValidatedRecord` inline size counted once, its MEASURED owned
// evidence-backing capacity, its retained `encoded` buffer capacity, and the live
// metadata payload capacity — and records them here for the one-shot sampler to
// read. A missing measurement fails EXPLICITLY (the capacity read surfaces its
// `Err`) rather than being silently substituted. The graph is never cloned, no
// lifetime is extended, and nothing is derived from a reservation counter.
// Absent from production/release builds.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct O4OwnedLiveObjects {
    /// `size_of::<ValidatedRecord>()` — the complete inline proof object the O4
    /// phase holds live, counted ONCE (it embeds its own retained generation
    /// inline; that embedded record is never counted separately here).
    pub validated_inline: u128,
    /// The MEASURED `Vec::capacity()` of the evidence heap backings the live
    /// validated proof's retained generation owns.
    pub retained_evidence_capacity: u128,
    /// The MEASURED `Vec::capacity()` of the proof's retained `encoded`
    /// publication buffer.
    pub retained_encoded_capacity: u128,
    /// The MEASURED `Vec::capacity()` of the live component-owned metadata
    /// encoding temporary still held through the publish match arm.
    pub metadata_payload_capacity: u128,
}

#[cfg(any(test, feature = "test-utils"))]
impl O4OwnedLiveObjects {
    /// The total O4-owned live-object bytes at the pre-effective phase.
    pub fn total(&self) -> u128 {
        self.validated_inline
            + self.retained_evidence_capacity
            + self.retained_encoded_capacity
            + self.metadata_payload_capacity
    }
}

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static O4_OWNED_LIVE_OBJECTS: std::cell::Cell<Option<O4OwnedLiveObjects>> =
        const { std::cell::Cell::new(None) };
}

// Test-only (RUN 422 §3 correction): a one-shot fault that forces the next
// O4-owned live-object measurement on THIS thread to fail, exercising the
// post-acknowledgement instrumentation-failure path through the REAL publication.
// Absent from production/release builds.
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static O4_MEASUREMENT_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only (RUN 422 §3 correction): arm a one-shot fault so the next O4-owned
/// live-object measurement on this thread returns `Err`, letting a bounded
/// regression reach the post-acknowledgement instrumentation-failure path via the
/// real publication. The fault is consumed (cleared) by the measurement it fails.
#[cfg(any(test, feature = "test-utils"))]
pub fn arm_o4_measurement_fault() {
    O4_MEASUREMENT_FAULT.with(|c| c.set(true));
}

/// Test-only (RUN 422 §3): the O4-owned live-object measurement recorded by the
/// most recent acknowledged O4 publication at its pre-effective phase, read by the
/// one-shot pre-effective sampler on the SAME (publishing) thread. `None` until an
/// acknowledged O4 reaches the pre-effective phase on this thread.
#[cfg(any(test, feature = "test-utils"))]
pub fn o4_owned_live_objects() -> Option<O4OwnedLiveObjects> {
    O4_OWNED_LIVE_OBJECTS.with(|c| c.get())
}

/// Test-only (RUN 422 §3): measure the ACTUAL live O4-owned objects held by the
/// publish path at the pre-effective phase and record them for the sampler. A
/// failed evidence-capacity measurement is surfaced EXPLICITLY (`Err`), never a
/// silent `0`.
#[cfg(any(test, feature = "test-utils"))]
fn record_o4_owned_live_objects(
    validated: &ValidatedRecord,
    meta_encoded: &[u8],
    meta_encoded_capacity: usize,
) -> Result<(), SafetyStoreError> {
    let _ = meta_encoded;
    // Test-only (RUN 422 §3 correction): consume a one-shot armed fault so a
    // bounded regression can reach the post-acknowledgement instrumentation
    // failure through the real publication path.
    if O4_MEASUREMENT_FAULT.with(|c| c.replace(false)) {
        return Err(SafetyStoreError::ArithmeticOverflow(
            super::error::ArithmeticOverflowSite::O4WorkingSetCharge,
        ));
    }
    let sample = O4OwnedLiveObjects {
        validated_inline: super::record::size_of_validated_record(),
        retained_evidence_capacity: validated.retained_evidence_capacity()? as u128,
        retained_encoded_capacity: validated.encoded_capacity() as u128,
        metadata_payload_capacity: meta_encoded_capacity as u128,
    };
    O4_OWNED_LIVE_OBJECTS.with(|c| c.set(Some(sample)));
    Ok(())
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

/// A successful, proof-bound admission for one isolated leader route. The proof
/// remains caller-owned until `propose_and_capture` consumes it.
pub struct LeaderRouteAdmission<'owner> {
    owner: &'owner SafetyRecordOwner,
    identity: super::prepared::GenerationIdentity,
    expected_revision: u64,
    proof_publication_revision: u64,
    proof_backend_incarnation: u64,
    proof_context_digest: [u8; 32],
    limits: super::decision_capture::PreparedDecisionInputLimits,
    route: super::accounting::Reservation,
}

impl<'owner> LeaderRouteAdmission<'owner> {
    /// Consume this admission, taking the proof only after admission/proof
    /// correspondence is checked. Every returned owner outcome carries R.
    pub fn propose_and_capture(
        self,
        engine: &mut qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
        proof: &mut Option<ValidatedRecord>,
    ) -> super::decision_capture::LeaderOwnerOutcome {
        use super::decision_capture::{
            LeaderOwnerOutcome, LeaderOwnerRefusal,
        };

        let LeaderRouteAdmission {
            owner,
            identity,
            expected_revision,
            proof_publication_revision,
            proof_backend_incarnation,
            proof_context_digest,
            limits,
            route,
        } = self;
        let Some(candidate_proof) = proof.as_ref() else {
            return LeaderOwnerOutcome::refused(
                None,
                LeaderOwnerRefusal::AdmissionProofMissing,
                route,
            );
        };
        let proof_matches = super::prepared::GenerationIdentity::from_retained(
            candidate_proof.retained(),
        ) == Some(identity)
            && candidate_proof.publication_revision() == proof_publication_revision
            && candidate_proof.recovery_backend_incarnation() == Some(proof_backend_incarnation)
            && candidate_proof.origin_context_digest() == &proof_context_digest;
        if !proof_matches {
            return LeaderOwnerOutcome::refused(
                proof.take(),
                LeaderOwnerRefusal::AdmissionProofMismatch,
                route,
            );
        }
        let mut guard = owner.backend.lock_domain();
        let proof = proof.take().expect("proof was checked above");
        let mut gate = LeaderCaptureGate {
            owner,
            guard: &mut guard,
            proof: Some(proof),
            identity,
            expected_revision,
            limits,
            proposer: engine.local_id(),
            reason: None,
        };

        #[cfg(any(test, feature = "test-utils"))]
        fire_pre_ingestion_hook();

        let engine_result = engine.try_propose_gated_owning(&mut gate);
        let LeaderCaptureGate {
            proof: returned_proof,
            reason,
            ..
        } = gate;
        let outcome = match engine_result {
            qbind_consensus::LeaderProposalRouteResult::PostCapture(failure) => {
                let diagnostic = failure.into_diagnostic();
                LeaderOwnerOutcome::refused(
                    None,
                    LeaderOwnerRefusal::PostCapture(diagnostic),
                    route,
                )
            }
            qbind_consensus::LeaderProposalRouteResult::Decided(decided) => {
                LeaderOwnerOutcome::decided(decided, route)
            }
            qbind_consensus::LeaderProposalRouteResult::Refused(engine_reason) => {
                let refusal = reason
                    .map(LeaderOwnerRefusal::Capture)
                    .unwrap_or(LeaderOwnerRefusal::Engine(engine_reason));
                LeaderOwnerOutcome::refused(returned_proof, refusal, route)
            }
        };
        drop(guard);
        outcome
    }
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
        // Reset the contemporaneous late-O2 observation at operation ENTRY — before the
        // fallible transient/charge arithmetic or the `reserve(o2_charge)?` admission
        // below can return early. A previous O2 that reached the late decode phase leaves
        // a `Some(sample)` in the slot; without this reset an admission-refused O2 (which
        // returns before `arm_o2_late_decode_observation`) would expose that stale sample.
        // Clearing here guarantees that an O2 which never reaches the late phase exposes
        // `None`, and that no stale accountant handle survives armed. Absent from
        // production builds.
        #[cfg(any(test, feature = "test-utils"))]
        reset_o2_late_decode_observation();
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
        // Arm the contemporaneous late-O2 reservation observation (test-only) with a
        // cloned handle of the SAME operational accountant this O2 reserved against, so
        // the decode hook can sample the live operational + aggregate charge AT the late
        // decode phase (after the TC evidence graph and committed anchor are decoded,
        // immediately before the invalid-predecessor refusal). Disarmed immediately after
        // `load_established` so no later decode resamples a stale handle. Absent from
        // production builds.
        #[cfg(any(test, feature = "test-utils"))]
        arm_o2_late_decode_observation(self.backend.accounting().clone());
        let loaded = self.load_established();
        #[cfg(any(test, feature = "test-utils"))]
        disarm_o2_late_decode_observation();
        let (meta, _record_bytes, _decoded) = loaded?;
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
    // §13.6 — prepared-decision L0 capture (generation-only, non-authorizing)
    // -----------------------------------------------------------------------

    /// Read the current authoritative publication revision **under an
    /// already-held serialization-domain guard**, charging the component-owned
    /// metadata buffer *before* it is allocated (§ 13.7: reservations precede the
    /// copy). The transient `META_ENCODED_LEN` scratch releases at return.
    fn authoritative_revision_locked(
        &self,
        _guard: &std::sync::MutexGuard<'_, super::backend::SerializationDomain>,
    ) -> Result<u64, SafetyStoreError> {
        // Cover the metadata-read allocation before `read_meta` copies the stored
        // payload into a component-owned buffer.
        let _meta_scratch = self
            .backend
            .accounting()
            .reserve(super::backend::META_ENCODED_LEN)?;
        let meta_bytes = self
            .backend
            .read_meta(super::backend::META_ENCODED_LEN)?
            .ok_or(SafetyStoreError::MissingEstablishedState("no metadata"))?;
        let meta = SafetyMeta::decode(&meta_bytes)?;
        if meta.context_digest != context_digest(self.pinned()) {
            return Err(SafetyStoreError::SemanticRefusal(
                super::error::SemanticRefusalDetail::PinnedContextDisagreement,
            ));
        }
        Ok(meta.current_revision)
        // `_meta_scratch` drops here, releasing the metadata-read charge.
    }

    // -----------------------------------------------------------------------
    // §13.6 — isolated non-consuming retained-decision observation
    // -----------------------------------------------------------------------

    /// Map a heap-bearing [`SafetyStoreError`] from the current-record load to a
    /// bounded, `Copy` [`LoaderDiagnostic`] (RUN 422 §13.6). No owned diagnostic
    /// `String` is ever forwarded into the observation; the message-bearing
    /// variants collapse to fixed discriminants. The mapping covers storage-read
    /// failure and missing independent committed history explicitly.
    fn map_loader_error(e: SafetyStoreError) -> super::decision_capture::LoaderDiagnostic {
        use super::decision_capture::LoaderDiagnostic as D;
        use super::error::SemanticRefusalDetail as S;
        match e {
            SafetyStoreError::MissingEstablishedState(_)
            | SafetyStoreError::AlreadyEstablished(_) => D::MissingEstablishedState,
            SafetyStoreError::ReadFailed(_) | SafetyStoreError::WriteFailed(_) => D::StorageRead,
            SafetyStoreError::StructuralRefusal(_) => D::StructuralRejected,
            SafetyStoreError::SemanticRefusal(d) => match d {
                S::PinnedContextDisagreement => D::PinnedContextDisagreement,
                S::RecordMetaRevisionDisagreement {
                    record_revision,
                    meta_revision,
                } => D::RecordMetaRevisionDisagreement {
                    record: record_revision,
                    meta: meta_revision,
                },
                _ => D::SemanticRejected,
            },
            SafetyStoreError::MissingIndependentInput(_) => D::MissingIndependentHistory,
            SafetyStoreError::UnsupportedVersion(_) => D::UnsupportedVersion,
            SafetyStoreError::Oversize { .. } | SafetyStoreError::DeclaredBoundExceeded(_) => {
                D::Oversize
            }
            SafetyStoreError::ArithmeticOverflow(_) => D::Arithmetic,
            _ => D::Other,
        }
    }

    /// Read a prepared pin's scalar provenance **under the already-held
    /// serialization-domain guard** (RUN 422 §13.6). The owner's installed
    /// registry is obtained THROUGH the held `guard` (never re-acquiring the
    /// domain); its leaf mutex is then held only for the duration of a single
    /// scalar read and released immediately. Beyond the registry's own
    /// incarnation/slot/serial checks, the generation's minted recovery
    /// incarnation and sealed origin-context digest are required to match THIS
    /// backend and owner (a foreign generation is refused). A typed
    /// [`ProvenanceRefusal`] preserves the Missing / Stale / Foreign distinction.
    fn pin_provenance_locked(
        &self,
        guard: &std::sync::MutexGuard<'_, super::backend::SerializationDomain>,
        pin: &super::prepared::PreparedPin,
    ) -> Result<super::prepared::PreparedProvenance, super::prepared::ProvenanceRefusal> {
        use super::prepared::ProvenanceRefusal;
        let registry = match self.backend.prepared_registry_installed(guard) {
            Some(r) => r,
            None => return Err(ProvenanceRefusal::Missing),
        };
        let prov = {
            let reg = registry.lock().expect("prepared registry poisoned");
            reg.provenance_by_handle(pin.handle())?
            // leaf guard released here — the domain is never re-entered.
        };
        if prov.recovery_backend_incarnation != self.backend.incarnation() {
            return Err(ProvenanceRefusal::Foreign);
        }
        if prov.origin_context_digest != context_digest(self.pinned()) {
            return Err(ProvenanceRefusal::Foreign);
        }
        Ok(prov)
    }

    /// Load and validate the **current** authoritative record **under an
    /// already-held serialization-domain guard** (RUN 422 §13.6), returning an
    /// owned [`ValidatedRecord`] that carries its covering holder reservation for
    /// the caller to keep alive across the remaining observation checks.
    ///
    /// This mirrors [`Self::read_validate`]'s O3 charging and validation EXACTLY
    /// but never acquires the domain (the caller holds it), so it cannot
    /// self-deadlock the observation. It is a single sequential operation:
    /// admit the retained-holder reservation and the O3 validation scratch,
    /// load + validate, then destroy the validation temporaries and release the
    /// O3 scratch **inside** this helper, returning the record still covered by
    /// its holder reservation. It never pauses halfway for the caller to admit
    /// another reservation.
    ///
    /// The typed [`CurrentLoadFailure`] keeps an **admission** failure (a
    /// covering reservation refused) distinct from a **validation** failure
    /// (the record read but rejected), and validation failures carry only a
    /// bounded `Copy` diagnostic — no owned error string is forwarded.
    fn load_current_validated_locked<H: CommittedHistory + ?Sized>(
        &self,
        _guard: &std::sync::MutexGuard<'_, super::backend::SerializationDomain>,
        history: Option<&H>,
    ) -> Result<ValidatedRecord, super::decision_capture::CurrentLoadFailure> {
        use super::decision_capture::CurrentLoadFailure;
        // Admit the retained-holder charge BEFORE the stored payload is copied
        // (reservations precede the copy). It is moved into the returned proof.
        let holder_charge = self
            .retained_holder_charge()
            .map_err(|_| CurrentLoadFailure::Admission)?;
        let holder_res = self
            .backend
            .accounting()
            .reserve(holder_charge)
            .map_err(|_| CurrentLoadFailure::Admission)?;
        // O3 transient/validation scratch (identical terms to `read_validate`):
        // the transient decoded object's excess over the retained ceiling plus a
        // single record-sized validation buffer. Released inside this helper when
        // the validation temporaries are destroyed (at return).
        let transient = super::accounting::max_transient_decoded_working_set(self.pinned())
            .map_err(|_| CurrentLoadFailure::Admission)?;
        let retained_gen = max_retained_generation_bytes(self.pinned(), size_of_timeout_msg())
            .map_err(|_| CurrentLoadFailure::Admission)?;
        let transient_excess = transient.saturating_sub(retained_gen);
        let record_buf =
            max_safety_record_bytes(self.pinned()).map_err(|_| CurrentLoadFailure::Admission)?;
        let o3_scratch = transient_excess
            .checked_add(record_buf)
            .ok_or(CurrentLoadFailure::Admission)?;
        let scratch_res = self
            .backend
            .accounting()
            .reserve(o3_scratch)
            .map_err(|_| CurrentLoadFailure::Admission)?;
        // Load + validate under the caller's held guard (NO domain re-acquisition).
        let (_meta, record_bytes, decoded) = self
            .load_established()
            .map_err(|e| CurrentLoadFailure::Validation(Self::map_loader_error(e)))?;
        let validated = validate_decoded(decoded, record_bytes, self.pinned(), history)
            .map_err(|e| CurrentLoadFailure::Validation(Self::map_loader_error(e)))?;
        // Validation temporaries are destroyed; release the O3 scratch BEFORE
        // returning the still-covered record.
        drop(scratch_res);
        Ok(validated
            .with_holder(holder_res)
            .grant_recovery_capability(self.backend.incarnation()))
    }

    /// **§13.6 isolated non-consuming retained-decision observation.** Borrow a
    /// retained [`DecidedVote`] envelope and the exact proposal it was captured
    /// for, validate the current durable restriction with the applicable
    /// independent committed history, verify the pin's provenance and the
    /// candidate correspondence, and perform a bounded safe-voting
    /// re-evaluation — all under a SINGLE acquisition of the serialization
    /// domain. Nothing is consumed, re-ingested, signed, or published: the
    /// original envelope, its `Vote`, and its pin are preserved, and the result
    /// is a `Copy` diagnostic describing ONLY the checked state (no signing
    /// permission, freshness, retained-result-reuse authorization, or
    /// certificate verification).
    ///
    /// The engine is borrowed read-only; the existing unbounded ancestry walk is
    /// never invoked. The registry leaf lookup releases promptly and the domain
    /// is never re-entered.
    pub fn observe_retained_decision<H: CommittedHistory + ?Sized>(
        &self,
        engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
        decided: &qbind_consensus::DecidedVote<super::decision_capture::OwningCapturePayload>,
        proposal: &qbind_wire::consensus::BlockProposal,
        limits: &super::decision_capture::PreparedDecisionInputLimits,
        history: Option<&H>,
    ) -> super::decision_capture::RetainedDecisionObservation {
        use super::decision_capture::{
            PreparedDecisionInputLimits, RetainedDecisionObservation, RetainedDecisionReject,
        };

        // 1. Bind the caller's effective limits to the owner's pinned policy
        //    (a resource-policy binding only; authenticates nothing). This runs
        //    BEFORE the serialization domain is acquired and is NOT delegated to
        //    the held-guard helper, so a policy mismatch is refused without ever
        //    taking the lock.
        match PreparedDecisionInputLimits::from_pinned(self.pinned()) {
            Ok(expected) => {
                if *limits != expected {
                    return RetainedDecisionObservation::Rejected(
                        RetainedDecisionReject::EffectivePolicyMismatch,
                    );
                }
            }
            Err(e) => {
                return RetainedDecisionObservation::Rejected(
                    RetainedDecisionReject::OwnerPolicyUnavailable(e),
                )
            }
        }

        // 2. One acquisition of the serialization domain for the whole operation.
        //    The post-lock observation checks are delegated to the private
        //    held-guard helper, which borrows this guard and never reacquires it.
        let guard = self.backend.lock_domain();
        self.observe_checks_locked(&guard, engine, decided, proposal, limits, history)
    }

    /// Private held-guard tail of [`Self::observe_retained_decision`] (RUN 422
    /// §13.6): steps 3–9 of the isolated non-consuming observation, performed
    /// under a serialization-domain guard the caller already holds. It borrows
    /// the guard and NEVER reacquires the domain (the single acquisition stays in
    /// the public method), leaving the owner-derived policy binding — which must
    /// precede the lock — to the caller. The check order, typed outcomes,
    /// accounting admission, reservation lifetimes, and destruction-before-release
    /// ordering are byte-for-byte the previously inlined sequence; this is a
    /// behavior-preserving extraction only. It does NOT consume, sign, re-ingest,
    /// or publish anything, and establishes no signing permission.
    fn observe_checks_locked<H: CommittedHistory + ?Sized>(
        &self,
        guard: &std::sync::MutexGuard<'_, super::backend::SerializationDomain>,
        engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
        decided: &qbind_consensus::DecidedVote<super::decision_capture::OwningCapturePayload>,
        proposal: &qbind_wire::consensus::BlockProposal,
        limits: &super::decision_capture::PreparedDecisionInputLimits,
        history: Option<&H>,
    ) -> super::decision_capture::RetainedDecisionObservation {
        use super::decision_capture::{
            commit_proposal, derive_block_id_local, observation_working_set_charge,
            BoundedAncestryReject, CorrespondenceRefusal, CurrentLoadFailure, MetaField,
            ProjectionMismatch, RetainedDecisionBlocked, RetainedDecisionObservation,
            RetainedDecisionReject,
        };
        use qbind_consensus::BoundedSafetyOutcome;

        let reject = RetainedDecisionObservation::Rejected;
        let blocked = RetainedDecisionObservation::Inconclusive;

        let payload = decided.payload();

        // 3. An actually observed recovery-required state blocks (distinct from an
        //    engine/durable disagreement below).
        if self.backend.recovery_required() {
            return blocked(RetainedDecisionBlocked::RecoveryRequired);
        }

        // 4. Validate the CURRENT durable restriction under the held guard. The
        //    returned record carries its holder reservation and stays covered
        //    through every check below; its O3 validation scratch released inside
        //    the helper.
        let validated = match self.load_current_validated_locked(guard, history) {
            Ok(v) => v,
            Err(CurrentLoadFailure::Admission) => {
                return blocked(RetainedDecisionBlocked::Admission)
            }
            Err(CurrentLoadFailure::Validation(d)) => {
                return blocked(RetainedDecisionBlocked::EvidenceUnavailable(d))
            }
        };

        // 5. Admit the observation WORKING SET before constructing any of the
        //    internal objects it covers (RUN 422 §13.6 accounting completion).
        //    The earlier reviewed order built the restriction identity, the
        //    provenance, and the context-digest BEFORE admitting any observation
        //    reservation; here a single working-set reservation — sized for the
        //    restriction-identity, the scalar provenance, the context-digest
        //    hashing state, AND the commitment/ancestry scratch + control — is
        //    admitted FIRST, while the loaded record stays holder-covered. It is
        //    released after the bounded checks (its covered transient objects are
        //    destroyed inside the steps below, before this release), so no covered
        //    object is ever constructed uncharged. A refused admission blocks,
        //    distinct from the loader-phase admission failure above.
        #[cfg(any(test, feature = "test-utils"))]
        fire_observation_working_set_hook();
        let obs_ws = match self
            .backend
            .accounting()
            .reserve(observation_working_set_charge())
        {
            Ok(r) => r,
            Err(_) => return blocked(RetainedDecisionBlocked::Admission),
        };

        // 6. The effective durable restriction identity (restriction-identity
        //    object, covered by `obs_ws`). A `BootstrapNoLock` record leaves this
        //    Locked-only route explicitly unresolved.
        let durable = match super::prepared::GenerationIdentity::from_retained(validated.retained())
        {
            Some(id) => id,
            None => return blocked(RetainedDecisionBlocked::BootstrapUnresolved),
        };

        // 7. The pin's provenance (provenance + context-digest objects, covered by
        //    `obs_ws`), read through the held guard (leaf lock brief).
        if let Err(r) = self.pin_provenance_locked(guard, payload.pin()) {
            return reject(RetainedDecisionReject::Provenance(r));
        }

        // 8. Engine ↔ durable correspondence. Engine NoLock is refused on this
        //    Locked-only route; an engine/durable lock disagreement blocks
        //    conservatively (NOT a recovery-required state).
        let (engine_lock_id, engine_lock_view) = match engine.locked_qc() {
            Some(qc) => (qc.block_id, qc.view),
            None => {
                return reject(RetainedDecisionReject::Correspondence(
                    CorrespondenceRefusal::EngineNoLock,
                ))
            }
        };
        if engine_lock_id != durable.lock_block_id || engine_lock_view != durable.lock_view {
            return blocked(RetainedDecisionBlocked::EngineDurableDisagreement);
        }

        // Perform the remaining checks, then release `obs_ws` before the
        // result is produced (its commitment/ancestry SHA3 / traversal temporaries
        // live only inside the calls below). `result` is a `Copy` diagnostic;
        // `validated` drops as this helper returns and the borrowed domain guard
        // drops in the caller afterwards (same obs_ws → validated → guard order).
        let result = (|| {
            // 9a. Recompute the proposal commitment and compare to the retained
            //     binding (substitution / projection refusal).
            let recomputed = match commit_proposal(proposal, limits) {
                Ok(c) => c,
                Err(e) => return reject(RetainedDecisionReject::InputBound(e)),
            };
            if &recomputed != payload.proposal_binding() {
                return reject(RetainedDecisionReject::CommitmentMismatch);
            }

            // 9b. Retained fixed metadata ↔ the supplied proposal.
            let meta = payload.meta();
            if meta.proposer() != u64::from(proposal.header.proposer_index) {
                return reject(RetainedDecisionReject::Metadata(MetaField::Proposer));
            }
            let view = proposal.header.height;
            if meta.candidate_view() != view {
                return reject(RetainedDecisionReject::Metadata(MetaField::CandidateView));
            }
            let parent_field = proposal.header.parent_block_id;
            let reproduced = derive_block_id_local(meta.proposer(), view, &parent_field);
            if meta.candidate_id() != &reproduced {
                return reject(RetainedDecisionReject::Metadata(MetaField::CandidateId));
            }

            // 9c. Projection ↔ the registered candidate node (view, full parent
            //     incl. the `[0xFF; 32]` sentinel, justify presence/block/view).
            //     An absent candidate is reported by the bounded evaluation.
            let candidate_id = *meta.candidate_id();
            if let Some(node) = engine.state().get_block(&candidate_id) {
                if node.view != view {
                    return reject(RetainedDecisionReject::Projection(
                        ProjectionMismatch::CandidateView,
                    ));
                }
                match node.parent_id {
                    None => {
                        if parent_field != [0xFF; 32] {
                            return reject(RetainedDecisionReject::Projection(
                                ProjectionMismatch::Parent,
                            ));
                        }
                    }
                    Some(p) => {
                        if parent_field == [0xFF; 32] || p != parent_field {
                            return reject(RetainedDecisionReject::Projection(
                                ProjectionMismatch::Parent,
                            ));
                        }
                    }
                }
                if node.id != reproduced {
                    return reject(RetainedDecisionReject::Projection(
                        ProjectionMismatch::CandidateId,
                    ));
                }
                match &proposal.qc {
                    Some(qc) => {
                        match node.justify_qc.as_ref() {
                            Some(j) if j.block_id == qc.block_id => {}
                            _ => {
                                return reject(RetainedDecisionReject::Projection(
                                    ProjectionMismatch::JustifyBlockId,
                                ))
                            }
                        }
                        match node.justify_qc.as_ref() {
                            Some(j) if j.view == qc.height => {}
                            _ => {
                                return reject(RetainedDecisionReject::Projection(
                                    ProjectionMismatch::JustifyView,
                                ))
                            }
                        }
                    }
                    None => {
                        if node.justify_qc.is_some() {
                            return reject(RetainedDecisionReject::Projection(
                                ProjectionMismatch::JustifyPresence,
                            ));
                        }
                    }
                }
            }

            // 9d. Bounded safe-voting re-evaluation against the effective
            //     restriction. The unbounded walk is never invoked first.
            match engine
                .state()
                .bounded_safety_decision(&candidate_id, limits.max_ancestry_hops())
            {
                o @ (BoundedSafetyOutcome::SafeNoLock
                | BoundedSafetyOutcome::SafeViewSufficiency
                | BoundedSafetyOutcome::SafeAncestry { .. }) => {
                    RetainedDecisionObservation::Revalidated(o)
                }
                BoundedSafetyOutcome::CandidateAbsent => {
                    reject(RetainedDecisionReject::Ancestry(BoundedAncestryReject::CandidateAbsent))
                }
                BoundedSafetyOutcome::ParentAbsent => {
                    reject(RetainedDecisionReject::Ancestry(BoundedAncestryReject::ParentAbsent))
                }
                BoundedSafetyOutcome::NoParentLink => {
                    reject(RetainedDecisionReject::Ancestry(BoundedAncestryReject::NoParentLink))
                }
                BoundedSafetyOutcome::BoundExhausted => {
                    reject(RetainedDecisionReject::Ancestry(BoundedAncestryReject::OverBound {
                        max: limits.max_ancestry_hops(),
                    }))
                }
            }
        })();

        // Release the observation working set (its covered transients are gone),
        // then the result is returned; `validated` (backings before holder) drops
        // as this helper returns and the borrowed domain guard drops in the caller
        // afterwards.
        drop(obs_ws);
        result
    }

    /// Borrowed-proof provenance precheck shared by the public capture wrapper and
    /// the owner-controlled route (no consumption, no domain acquisition): refuse a
    /// recovery-required backend, a foreign/uncharged incarnation, a foreign pinned
    /// context, and a `BootstrapNoLock` proof (left explicitly unresolved). On
    /// success it returns the retained generation identity used under the guard.
    fn capture_precheck(
        &self,
        proof: &ValidatedRecord,
    ) -> Result<super::prepared::GenerationIdentity, super::prepared::CaptureRefusal> {
        use super::prepared::CaptureRefusal;
        if self.backend.recovery_required() {
            return Err(CaptureRefusal::RecoveryRequired);
        }
        let incarnation = self.backend.incarnation();
        // Foreign incarnation OR standalone/uncharged (None) proof — both refused.
        if proof.recovery_backend_incarnation() != Some(incarnation) {
            return Err(CaptureRefusal::ForeignOrUncharged);
        }
        if proof.origin_context_digest() != &context_digest(self.pinned()) {
            return Err(CaptureRefusal::ForeignContext);
        }
        // BootstrapNoLock — left explicitly unresolved (Locked-only).
        super::prepared::GenerationIdentity::from_retained(proof.retained())
            .ok_or(CaptureRefusal::BootstrapUnresolved)
    }

    /// **§ 13.6 prepared-decision L0 capture** — retain, for a prepared signing
    /// decision, the **generation only** of a read-validated proof plus the
    /// provenance required to rebind it, charged under the terms the aggregate
    /// already budgets for a prepared holder. **Non-authorizing**: it mints no
    /// authorization, freshness, durability acknowledgement, or verified-evidence
    /// status, and establishes no engine decision timing.
    ///
    /// The complete provenance gate runs on the **borrowed** proof first; on any
    /// refusal the original proof is returned **intact** (its original bytes and
    /// holder reservation untouched). Only after the generation-only and
    /// per-entry reservations are admitted is the proof consumed; its original
    /// full-proof holder reservation is released **after** the new reservations
    /// are live, so no live object is uncharged across the conversion.
    ///
    /// Capture is linearized with publication under the backend serialization
    /// domain (the outer lock); the registry mutex is a leaf taken under it.
    pub fn capture_prepared_decision(
        &self,
        proof: ValidatedRecord,
        expected_authoritative_revision: u64,
    ) -> Result<super::prepared::PreparedPin, (ValidatedRecord, super::prepared::CaptureRefusal)>
    {
        // --- provenance gate on the borrowed proof (no consumption) ---
        let identity = match self.capture_precheck(&proof) {
            Ok(id) => id,
            Err(e) => return Err((proof, e)),
        };

        // --- linearize with publication under the serialization domain ---
        // A single acquisition of the shared serialization domain; the held-guard
        // tail is shared verbatim with the owner-controlled route through the
        // private held-guard helper below (no re-acquisition, no duplicated capture
        // body, no public raw-guard API).
        let mut guard = self.backend.lock_domain();
        self.capture_prepared_decision_locked(
            &mut guard,
            proof,
            expected_authoritative_revision,
            identity,
        )
    }

    /// Held-guard capture tail shared by the public
    /// [`Self::capture_prepared_decision`] wrapper and the owner-controlled
    /// `decide_and_capture_owned` route. The caller has already run the
    /// borrowed-proof provenance precheck and acquired the one serialization-domain
    /// `guard`; this performs the under-lock recovery recheck, authoritative-revision
    /// fence, lazy registry allocation, slot/serial checks, all admissions,
    /// generation sharing, the generation-only proof conversion and
    /// destruction-before-release ordering, and returns the owning [`PreparedPin`].
    /// It only **borrows** the guard (never re-acquires or releases the domain) so
    /// the owner route can keep holding it across the engine decision; the borrow
    /// ends when this returns, before the owner releases the guard.
    fn capture_prepared_decision_locked(
        &self,
        guard: &mut std::sync::MutexGuard<'_, super::backend::SerializationDomain>,
        proof: ValidatedRecord,
        expected_authoritative_revision: u64,
        identity: super::prepared::GenerationIdentity,
    ) -> Result<super::prepared::PreparedPin, (ValidatedRecord, super::prepared::CaptureRefusal)>
    {
        use super::prepared::CaptureRefusal;
        let incarnation = self.backend.incarnation();
        if self.backend.recovery_required() {
            return Err((proof, CaptureRefusal::RecoveryRequired));
        }
        let current = match self.authoritative_revision_locked(&*guard) {
            Ok(rev) => rev,
            Err(e) => return Err((proof, CaptureRefusal::MetadataUnavailable(e))),
        };
        // The proof must reflect the current authoritative revision, and the
        // caller's expectation must agree with it (stale-work fencing, § 13.5).
        if proof.publication_revision() != current || expected_authoritative_revision != current {
            return Err((
                proof,
                CaptureRefusal::StaleRevision {
                    expected: expected_authoritative_revision,
                    found: current,
                },
            ));
        }

        // Source/test-only: fire the capture-interval hook (if installed) at the
        // EXACT point between the authoritative-state check above and the registry
        // insertion below, WHILE the serialization domain `guard` is held. A focused
        // serialization regression installs a hook here that signals a concurrent O4
        // publisher and then waits briefly: because that publisher must take the same
        // domain lock (`publish_locked`), correct serialization keeps it blocked for
        // the whole interval. Compiled only under `test`/`test-utils`; unreachable in
        // a default/release build.
        #[cfg(any(test, feature = "test-utils"))]
        fire_capture_interval_hook();

        // --- lazy registry allocation (charge admitted before allocation) ------
        // Before the first prepared capture no registry allocation exists. Obtain
        // the one shared registry, allocating it lazily on first capture: admit the
        // registry-storage charge BEFORE the allocation is created, then install
        // exactly one shared registry under the held serialization-domain `guard`
        // (first-initialization is serialized across all handles sharing the
        // backend, so concurrent captures cannot install bypass registries). The
        // installed registry owns its standing reservation for the ENTIRE allocation
        // lifetime — including zero-entry periods — releasing it only when the
        // allocation is destroyed (its last owner, the backend slot plus any
        // outstanding pin, drops). A reused registry is NOT re-charged.
        let registry_arc = match self.backend.prepared_registry_installed(&*guard) {
            Some(existing) => existing,
            None => {
                // On insufficient admission, return the proof intact WITHOUT
                // creating any registry storage or publishing an entry.
                let registry_res = match self
                    .backend
                    .accounting()
                    .reserve(super::prepared::registry_cell_charge())
                {
                    Ok(r) => r,
                    Err(e) => return Err((proof, CaptureRefusal::Admission(e))),
                };
                let fresh = Arc::new(Mutex::new(super::prepared::PreparedRegistry::new(
                    incarnation,
                    registry_res,
                )));
                self.backend.install_prepared_registry(&mut *guard, fresh)
            }
        };
        let mut reg = registry_arc.lock().expect("prepared registry poisoned");

        // Refuse a full registry WITHOUT eviction; proof returned intact. (A
        // registry just installed by this capture is empty, so this only fires for
        // a reused registry.) The retained registry keeps its standing reservation.
        if reg.free_slot().is_none() {
            return Err((proof, CaptureRefusal::RegistryFull));
        }
        // Fail closed BEFORE any mutation if the serial counter is exhausted; the
        // retained registry (and its standing reservation) is left intact. This is a
        // later capture step refusing AFTER registry initialization: the chosen
        // behavior is to RETAIN the allocation with its reservation (documented and
        // tested), never a stale-handle revival.
        if reg.next_serial_checked().is_none() {
            return Err((proof, CaptureRefusal::CounterExhausted));
        }

        // Admission-before-allocation for the owning-pin object. (The registry
        // storage charge was already admitted before the registry was allocated
        // above.) The pin is reserved WHILE the proof's full holder is still live,
        // so no live object is ever uncharged across the conversion. If this refuses
        // after a just-installed registry, that empty registry is retained with its
        // standing reservation (chosen behavior for a post-initialization refusal).
        let pin_res = match self
            .backend
            .accounting()
            .reserve(super::prepared::pin_charge())
        {
            Ok(r) => r,
            Err(e) => return Err((proof, CaptureRefusal::Admission(e))),
        };

        // Share an existing generation backing if one holds an equal retained
        // generation (its core + control charges cover both entries); otherwise
        // reserve a fresh generation core + holder/control charge WHILE the proof's
        // full holder is still live, so the moved evidence is never uncharged
        // across the conversion.
        let shared = reg.shareable_backing_for(proof.retained());
        let handle = if let Some(backing) = shared {
            // Shared path: consume the proof and reuse the existing backing. The
            // duplicate proof's SEPARATELY OWNED evidence backings (`parts.retained`)
            // must be DESTROYED before the proof's prior holder reservation — which
            // covered them — is released, so those live bytes are never uncharged.
            let parts = proof.into_prepared_parts();
            let prior_holder = parts.prior_holder;
            // Measure the duplicate's separately owned evidence backings BEFORE any
            // teardown, so both observers can see whether they were still live when
            // the covering reservation was released.
            #[cfg(any(test, feature = "test-utils"))]
            let dup_evidence_bytes = parts
                .retained
                .evidence_backing_capacity()
                .expect("duplicate evidence backing capacity measurement failed");
            // INDEPENDENT owned-object destruction probe (RUN 422 §2 B): register the
            // duplicate backing's measured bytes as live and bundle a Drop probe onto
            // the retained object so the live byte total is decremented exactly when
            // the owned backing object is actually destroyed — measured from real
            // owned-object destruction (by byte size, not allocation-address/identity
            // tracing), never derived from the branch below or a hard-coded value.
            #[cfg(any(test, feature = "test-utils"))]
            DUP_BACKING_LIVE_BYTES.with(|c| c.set(c.get() + dup_evidence_bytes));
            #[cfg(any(test, feature = "test-utils"))]
            let retained = (
                parts.retained,
                DupBackingLiveProbe {
                    bytes: dup_evidence_bytes,
                },
            );
            #[cfg(not(any(test, feature = "test-utils")))]
            let retained = parts.retained;

            #[cfg(any(test, feature = "test-utils"))]
            let premature = SHARED_RELEASE_ORDER.with(|c| {
                let o = c.get();
                c.set(SharedReleaseOrder::RetainedBeforeHolder); // consume (one-shot)
                o == SharedReleaseOrder::HolderBeforeRetained
            });
            #[cfg(not(any(test, feature = "test-utils")))]
            let premature = false;

            if premature {
                // PREMATURE ordering (historical branch-selection experiment, §2):
                // release the covering reservation while the duplicate's evidence is
                // still alive, leaving those live bytes uncharged for the interval.
                #[cfg(any(test, feature = "test-utils"))]
                SHARED_DUP_LIVE_AT_RELEASE.with(|c| c.set(Some(dup_evidence_bytes)));
                #[cfg(any(test, feature = "test-utils"))]
                DUP_BACKING_LIVE_AT_RELEASE
                    .with(|c| c.set(Some(DUP_BACKING_LIVE_BYTES.with(|b| b.get()))));
                if let Some(h) = prior_holder {
                    h.release_now();
                }
                drop(retained);
            } else {
                // CORRECTED NORMAL ordering: destroy the duplicate's evidence backings
                // (and, with them, the tracker probe — decrementing the live total)
                // FIRST, then sample the independent tracker at the release boundary
                // and release the reservation that covered them, so no live byte is
                // ever uncharged across the conversion.
                drop(retained);
                #[cfg(any(test, feature = "test-utils"))]
                SHARED_DUP_LIVE_AT_RELEASE.with(|c| c.set(Some(0)));
                #[cfg(any(test, feature = "test-utils"))]
                DUP_BACKING_LIVE_AT_RELEASE
                    .with(|c| c.set(Some(DUP_BACKING_LIVE_BYTES.with(|b| b.get()))));
                if let Some(h) = prior_holder {
                    h.release_now();
                }
            }
            reg.insert_shared(identity, backing)
                .expect("free slot + serial pre-checked under the held registry lock")
        } else {
            let gen_charge = match prepared_generation_charge(self.pinned(), proof.retained()) {
                Ok(c) => c,
                Err(e) => {
                    drop(pin_res);
                    return Err((proof, CaptureRefusal::Admission(e)));
                }
            };
            // The holder/control charge is derived from the ACTUAL private
            // `GenerationBacking` wrapper size (provenance + inline reservation +
            // padding), not a synthetic wrapper.
            let control_charge = match super::accounting::prepared_holder_control_charge(
                super::prepared::generation_backing_struct_size(),
            ) {
                Ok(c) => c,
                Err(e) => {
                    drop(pin_res);
                    return Err((proof, CaptureRefusal::Admission(e)));
                }
            };
            // Reserve the generation core + control charges while the proof holder
            // is live (conversion overlap; no uncharged interval).
            let gen_res = match self.backend.accounting().reserve(gen_charge) {
                Ok(r) => r,
                Err(e) => {
                    drop(pin_res);
                    return Err((proof, CaptureRefusal::Admission(e)));
                }
            };
            let control_res = match self.backend.accounting().reserve(control_charge) {
                Ok(r) => r,
                Err(e) => {
                    drop(gen_res);
                    drop(pin_res);
                    return Err((proof, CaptureRefusal::Admission(e)));
                }
            };
            // Now consume the proof: move the retained generation in, drop the
            // encoded buffer, insert, and release the proof's full holder AFTER the
            // core + control (+ pin) reservations are live. The registry already
            // owns its standing registry-storage reservation.
            let parts = proof.into_prepared_parts();
            let prior_holder = parts.prior_holder;
            let recovery_incarnation = parts
                .recovery_backend_incarnation
                .expect("gate verified Some(incarnation)");
            let handle = reg
                .insert_fresh(
                    identity,
                    parts.retained,
                    parts.origin_context_digest,
                    recovery_incarnation,
                    parts.evidence_status,
                    current,
                    gen_res,
                    control_res,
                )
                .expect("free slot + serial pre-checked under the held registry lock");
            if let Some(h) = prior_holder {
                h.release_now();
            }
            handle
        };

        drop(reg);
        // NOTE: the serialization-domain `guard` is only borrowed here; the caller
        // (public wrapper or owner route) owns and releases it after this returns.
        Ok(super::prepared::PreparedPin::new(registry_arc, handle, pin_res))
    }

    /// **§ 13.6 owner-controlled decide-and-capture** (isolated, opt-in, no
    /// production caller). Acquire the one serialization domain, invoke the
    /// existing legacy/logical owning engine entrypoint under it, and — at the real
    /// L0 safe-voting decision and strictly before the dependent self-vote — run the
    /// correspondence/projection checks, compute the streaming proposal commitment
    /// and bounded ancestry binding, admit the additional charges, and consume the
    /// proof through the shared held-guard capture helper. The engine then raises L1
    /// via its own self-vote and seals a closed [`qbind_consensus::DecidedVote`].
    ///
    /// Ownership is explicit: a successful envelope moves the payload exactly once;
    /// every pre-consumption refusal returns the intact proof and a typed reason;
    /// the engine's defensive post-consumption pairing branch surfaces as an
    /// invariant violation carrying no fabricated proof. **Non-authorizing**: it
    /// mints no authorization, freshness, durability acknowledgement, or verified
    /// status; the commitment is volatile decision association only.
    pub fn decide_and_capture_owned(
        &self,
        engine: &mut qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
        from: qbind_consensus::ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        limits: &super::decision_capture::PreparedDecisionInputLimits,
        expected_authoritative_revision: u64,
        proof: ValidatedRecord,
    ) -> super::decision_capture::OwnedDecisionOutcome {
        // Production/normal route: the engine decides on, and the gate projects /
        // commits, the SAME immutable proposal argument.
        self.decide_and_capture_owned_inner(
            engine,
            from,
            proposal,
            proposal,
            limits,
            expected_authoritative_revision,
            proof,
        )
    }

    /// Admit a leader route without taking ownership of the proof. A refusal
    /// returns only the small preparation error; the caller's proof slot remains
    /// intact and no `LeaderOwnerOutcome` is constructed.
    pub fn prepare_leader_route<'owner>(
        &'owner self,
        limits: &super::decision_capture::PreparedDecisionInputLimits,
        expected_authoritative_revision: u64,
        proof: &ValidatedRecord,
    ) -> Result<
        LeaderRouteAdmission<'owner>,
        super::decision_capture::LeaderRoutePreparationRefusal,
    > {
        use super::decision_capture::{
            LeaderCaptureRefusal, LeaderRoutePreparationRefusal,
        };

        let identity = match self.capture_precheck(proof) {
            Ok(identity) => identity,
            Err(reason) => return Err(LeaderRoutePreparationRefusal::Capture(
                LeaderCaptureRefusal::Precheck(reason),
            )),
        };
        let expected_limits =
            match super::decision_capture::PreparedDecisionInputLimits::from_pinned(self.pinned())
            {
                Ok(expected) => expected,
                Err(error) => return Err(LeaderRoutePreparationRefusal::Capture(
                    LeaderCaptureRefusal::OwnerPolicyUnavailable(error),
                )),
            };
        if *limits != expected_limits {
            return Err(LeaderRoutePreparationRefusal::Capture(
                LeaderCaptureRefusal::EffectivePolicyMismatch,
            ));
        }

        let charge_report = leader_route_charge::<LeaderCaptureGate<'static, 'static>>(
            limits.max_qc_sig_count() as usize,
        )
        .map_err(LeaderRoutePreparationRefusal::RouteAdmission)?;
        let route = match self.backend.accounting().reserve(charge_report.selected) {
            Ok(route) => route,
            Err(error) => return Err(LeaderRoutePreparationRefusal::RouteAdmission(error)),
        };
        Ok(LeaderRouteAdmission {
            owner: self,
            identity,
            expected_revision: expected_authoritative_revision,
            proof_publication_revision: proof.publication_revision(),
            proof_backend_incarnation: proof
                .recovery_backend_incarnation()
                .expect("capture precheck established backend provenance"),
            proof_context_digest: *proof.origin_context_digest(),
            limits: *limits,
            route,
        })
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn leader_route_charge_report_for_test(
        &self,
        limits: &super::decision_capture::PreparedDecisionInputLimits,
    ) -> Result<LeaderRouteChargeReport, SafetyStoreError> {
        leader_route_charge::<LeaderCaptureGate<'static, 'static>>(
            limits.max_qc_sig_count() as usize,
        )
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn leader_accounting_observer_for_test(
        &self,
    ) -> super::accounting::SharedAccountant {
        self.backend.accounting().clone()
    }

    /// **§ 13.6 verified-Proposal decide-and-capture** (isolated, opt-in).
    /// Reuses the engine's verified-ingestion pre-checks, then captures the
    /// actual safe decision under the same serialization-domain guard before
    /// its dependent self-vote. The supplied verified evidence is moved into
    /// the engine's existing retention path; this route does not re-verify or
    /// downgrade to logical ingestion.
    #[allow(clippy::too_many_arguments)]
    pub fn decide_verified_and_capture_owned(
        &self,
        engine: &mut qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
        from: qbind_consensus::ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        evidence: std::sync::Arc<qbind_consensus::qc_verify_domain::VerifiedQuorumCertificate>,
        limits: &super::decision_capture::PreparedDecisionInputLimits,
        expected_authoritative_revision: u64,
        proof: ValidatedRecord,
    ) -> super::decision_capture::OwnedDecisionOutcome {
        use super::decision_capture::{OwnedCaptureRefusal, OwnedDecisionOutcome};

        let identity = match self.capture_precheck(&proof) {
            Ok(id) => id,
            Err(reason) => {
                return OwnedDecisionOutcome::Refused {
                    proof,
                    reason: OwnedCaptureRefusal::Precheck(reason),
                };
            }
        };

        match super::decision_capture::PreparedDecisionInputLimits::from_pinned(self.pinned()) {
            Ok(expected) if *limits == expected => {}
            Ok(_) => {
                return OwnedDecisionOutcome::Refused {
                    proof,
                    reason: OwnedCaptureRefusal::EffectivePolicyMismatch,
                };
            }
            Err(error) => {
                return OwnedDecisionOutcome::Refused {
                    proof,
                    reason: OwnedCaptureRefusal::OwnerPolicyUnavailable(error),
                };
            }
        }

        let mut guard = self.backend.lock_domain();
        let mut gate = OwningCaptureGate {
            owner: self,
            guard: &mut guard,
            proof: Some(proof),
            limits,
            expected_rev: expected_authoritative_revision,
            proposer: from,
            proposal,
            identity,
            reason: None,
        };

        #[cfg(any(test, feature = "test-utils"))]
        fire_pre_ingestion_hook();

        let result = engine.on_verified_proposal_event_gated_owning(
            from,
            proposal,
            evidence,
            &mut gate,
        );

        let OwningCaptureGate {
            proof: returned_proof,
            reason,
            ..
        } = gate;
        drop(guard);

        match result {
            Ok(Some(decided)) => OwnedDecisionOutcome::Decided(decided),
            Ok(None) => match returned_proof {
                Some(proof) => OwnedDecisionOutcome::Refused {
                    proof,
                    reason: reason.unwrap_or(OwnedCaptureRefusal::OrdinaryEngineRejection),
                },
                None => OwnedDecisionOutcome::InvariantViolation,
            },
            Err(qbind_consensus::GatedVerifiedProposalError::Ingest(error)) => {
                OwnedDecisionOutcome::Refused {
                    proof: returned_proof.expect("verified pre-check does not consult the gate"),
                    reason: OwnedCaptureRefusal::VerifiedIngest(error),
                }
            }
            Err(qbind_consensus::GatedVerifiedProposalError::Gate(
                qbind_consensus::GatedSelfVoteRefusal::GateRejected(_),
            )) => OwnedDecisionOutcome::Refused {
                proof: returned_proof.expect("owner gate refusal restores the proof"),
                reason: reason.expect("owner gate refusal records its typed reason"),
            },
            Err(qbind_consensus::GatedVerifiedProposalError::Gate(
                qbind_consensus::GatedSelfVoteRefusal::MissingCandidate,
            )) => OwnedDecisionOutcome::Refused {
                proof: returned_proof.expect("missing candidate does not consult the gate"),
                reason: OwnedCaptureRefusal::MissingCandidate,
            },
        }
    }

    /// Test-only mismatched-input seam (§9): the engine decides on
    /// `engine_proposal` while the gate projects and commits `gate_proposal`,
    /// so a substitution test can force a projection mismatch without any
    /// production substitution API. Gated behind `test`/`test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    #[allow(clippy::too_many_arguments)]
    pub fn decide_and_capture_owned_projection_seam(
        &self,
        engine: &mut qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
        from: qbind_consensus::ValidatorId,
        engine_proposal: &qbind_wire::consensus::BlockProposal,
        gate_proposal: &qbind_wire::consensus::BlockProposal,
        limits: &super::decision_capture::PreparedDecisionInputLimits,
        expected_authoritative_revision: u64,
        proof: ValidatedRecord,
    ) -> super::decision_capture::OwnedDecisionOutcome {
        self.decide_and_capture_owned_inner(
            engine,
            from,
            engine_proposal,
            gate_proposal,
            limits,
            expected_authoritative_revision,
            proof,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn decide_and_capture_owned_inner(
        &self,
        engine: &mut qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
        from: qbind_consensus::ValidatorId,
        engine_proposal: &qbind_wire::consensus::BlockProposal,
        gate_proposal: &qbind_wire::consensus::BlockProposal,
        limits: &super::decision_capture::PreparedDecisionInputLimits,
        expected_authoritative_revision: u64,
        proof: ValidatedRecord,
    ) -> super::decision_capture::OwnedDecisionOutcome {
        use super::decision_capture::{OwnedCaptureRefusal, OwnedDecisionOutcome};

        // Borrowed-proof provenance precheck BEFORE acquiring the domain or invoking
        // the engine (no consumption).
        let identity = match self.capture_precheck(&proof) {
            Ok(id) => id,
            Err(reason) => {
                return OwnedDecisionOutcome::Refused {
                    proof,
                    reason: OwnedCaptureRefusal::Precheck(reason),
                };
            }
        };

        // Bind the effective input policy to the owner's pinned context (§2): a
        // caller-supplied policy constructed for a larger validator set would relax
        // the owner's intended QC-signature-count restriction. Derive the expected
        // policy from `self.pinned()` and reject a supplied policy whose effective
        // limits differ. Typed and allocation-free; raised BEFORE acquiring the
        // domain or invoking the engine, so no dependent self-vote can occur. A
        // resource-policy comparison does not establish validator authentication or
        // current authority.
        match super::decision_capture::PreparedDecisionInputLimits::from_pinned(self.pinned()) {
            Ok(expected) => {
                if *limits != expected {
                    return OwnedDecisionOutcome::Refused {
                        proof,
                        reason: OwnedCaptureRefusal::EffectivePolicyMismatch,
                    };
                }
            }
            Err(e) => {
                return OwnedDecisionOutcome::Refused {
                    proof,
                    reason: OwnedCaptureRefusal::OwnerPolicyUnavailable(e),
                };
            }
        }

        // One domain acquisition, held across the engine decision and supplied to
        // the private gate.
        let mut guard = self.backend.lock_domain();
        let mut gate = OwningCaptureGate {
            owner: self,
            guard: &mut guard,
            proof: Some(proof),
            limits,
            expected_rev: expected_authoritative_revision,
            proposer: from,
            proposal: gate_proposal,
            identity,
            reason: None,
        };

        // Source/test-only (§5): fire the pre-ingestion serialization observation
        // hook at the fixed semantic boundary — the domain guard is held, but the
        // engine has NOT yet ingested the proposal. A competing non-blocking
        // same-domain acquisition at this instant must observe `WouldBlock`,
        // establishing that the owner held the one serialization domain BEFORE
        // ingestion began. Compiled only under `test`/`test-utils`; unreachable in
        // a default/release build.
        #[cfg(any(test, feature = "test-utils"))]
        fire_pre_ingestion_hook();

        let result = engine.on_proposal_event_gated_owning(from, engine_proposal, &mut gate);

        // End the gate's borrow of the guard BEFORE releasing the guard: move the
        // retained proof/reason out and drop the gate (and its guard borrow) first.
        let OwningCaptureGate {
            proof: returned_proof,
            reason,
            ..
        } = gate;
        drop(guard);

        match result {
            // Success: the engine paired its own self-vote with our payload.
            Ok(Some(decided)) => OwnedDecisionOutcome::Decided(decided),
            Ok(None) => match returned_proof {
                // The gate was never consulted (ordinary pre-decision engine
                // rejection), so the proof is still intact in the gate.
                Some(proof) => OwnedDecisionOutcome::Refused {
                    proof,
                    reason: reason.unwrap_or(OwnedCaptureRefusal::OrdinaryEngineRejection),
                },
                // The proof was consumed but the engine emitted no envelope: the
                // defensive post-consumption pairing invariant. No proof to return.
                None => OwnedDecisionOutcome::InvariantViolation,
            },
            // Our gate declined: recover the restored proof and its typed reason.
            Err(qbind_consensus::GatedSelfVoteRefusal::GateRejected(_)) => {
                let proof = returned_proof.expect("our gate refusal restores the proof");
                let reason = reason.expect("our gate refusal records a typed reason");
                OwnedDecisionOutcome::Refused { proof, reason }
            }
            // The required decision-view candidate was absent: our gate was never
            // consulted, so the proof is intact.
            Err(qbind_consensus::GatedSelfVoteRefusal::MissingCandidate) => {
                let proof = returned_proof.expect("missing-candidate never consults our gate");
                OwnedDecisionOutcome::Refused {
                    proof,
                    reason: OwnedCaptureRefusal::MissingCandidate,
                }
            }
        }
    }

    /// Release a captured prepared entry explicitly (normal completion). Dropping
    /// the pin without calling this performs the same cleanup automatically
    /// (abandonment). Does not alter any D10 signing-journal obligation.
    pub fn release_prepared(
        &self,
        pin: super::prepared::PreparedPin,
    ) -> super::prepared::ReleaseOutcome {
        pin.release()
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
        self.publish_locked_held(&guard, candidate, expected_revision, history)
    }

    fn publish_locked_held<H: CommittedHistory + ?Sized>(
        &self,
        guard: &std::sync::MutexGuard<'_, super::backend::SerializationDomain>,
        candidate: LockedRecord,
        expected_revision: u64,
        history: Option<&H>,
    ) -> PublishResult {

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
        // Bind the component-owned metadata encoding so it is a named live object
        // measurable at the pre-effective phase (it otherwise remains live through
        // this match arm as a temporary). `publish_atomic` borrows it; the
        // measured capacity is read before the match so the live object the O4
        // phase holds is observed, not a reconstruction.
        let meta_encoded = new_meta.encode();
        #[cfg(any(test, feature = "test-utils"))]
        let meta_encoded_capacity = meta_encoded.capacity();
        match self
            .backend
            .publish_atomic(guard, &meta_encoded, validated.encoded())
        {
            PublishOutcome::DurableAcknowledged => {
                // Deterministic post-acknowledgement / pre-effectiveness crash
                // boundary (§ 13.5): the durable acknowledgement has returned, but
                // the in-memory effectiveness transition has NOT yet happened. A
                // test-only hook (unavailable in a default/release build) may
                // identify and terminate at exactly this point, proving that
                // termination precedes the transition and that a reopen starts
                // without inherited effectiveness.
                //
                // At this exact phase the O4-owned live objects are still held:
                // the validated proof (`ValidatedRecord`, not a transient
                // `DecodedRecord`), its retained evidence backings, its retained
                // `encoded` buffer, and the live `meta_encoded` payload. Measure
                // them IN PLACE for the pre-effective sampler BEFORE firing the
                // hook.
                //
                // This measurement is TEST-ONLY instrumentation (absent from a
                // default/release build). A failed measurement is an
                // instrumentation defect, not a publication outcome: the durable
                // write has ALREADY been acknowledged, so it must never be
                // relabelled as a pre-write refusal. Surface the failure as an
                // explicit test failure (`panic!`) under the same `cfg` gate; the
                // default build has no measurement here and its publication
                // behaviour is unchanged.
                #[cfg(any(test, feature = "test-utils"))]
                if let Err(e) =
                    record_o4_owned_live_objects(&validated, &meta_encoded, meta_encoded_capacity)
                {
                    panic!(
                        "O4-owned live-object instrumentation failed at the \
                         post-acknowledgement / pre-effective phase (rev {new_revision}); \
                         an acknowledged durable write is never a pre-write refusal: {e:?}"
                    );
                }
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

/// RUN 422 — Isolated Fresh-Vote Protected-Use Model (TEST-ONLY, NOT wired).
/// A bounded, `#[cfg(test)]`-gated mirror of the production Vote signing path,
/// implemented as a child module of `owner` so it can observe the
/// parent-private `backend` field and the private held-guard helpers. It has no
/// production caller and establishes no signing/authorization permission.
#[cfg(test)]
mod model;

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
#[cfg(all(test, feature = "test-utils"))]
mod received_qc_publication_model;

#[cfg(all(test, feature = "test-utils"))]
mod tc_publication_model;

// ---------------------------------------------------------------------------
// §13.6 owner-controlled capture gate (isolated, no production caller)
// ---------------------------------------------------------------------------

/// The private held-guard gate the owner route supplies to the existing owning
/// engine entrypoint. It retains the unconsumed proof (normally in an `Option`)
/// and a separate typed refusal reason, produces the opaque
/// [`super::decision_capture::OwningCapturePayload`] on the allow path, and
/// restores the intact proof on any pre-consumption refusal.
///
/// The guard is borrowed with a lifetime (`'o`) that is **separate** from the
/// underlying `MutexGuard`'s own lifetime (`'g`): the mutable borrow ends when
/// the gate is dropped, strictly before the owner releases the guard. This
/// deliberately avoids the incorrect `&'g mut MutexGuard<'g, …>` design.
struct OwningCaptureGate<'o, 'g> {
    owner: &'o SafetyRecordOwner,
    guard: &'o mut std::sync::MutexGuard<'g, super::backend::SerializationDomain>,
    /// The unconsumed proof, restored here on any capture refusal.
    proof: Option<ValidatedRecord>,
    limits: &'o super::decision_capture::PreparedDecisionInputLimits,
    expected_rev: u64,
    proposer: qbind_consensus::ValidatorId,
    proposal: &'o qbind_wire::consensus::BlockProposal,
    identity: super::prepared::GenerationIdentity,
    /// A separate typed refusal reason (a `SafetyGateRefusal` is only a unit
    /// marker and cannot carry detail).
    reason: Option<super::decision_capture::OwnedCaptureRefusal>,
}

impl OwningCaptureGate<'_, '_> {
    /// Run every pre-consumption check on the borrowed proof, then consume it
    /// through the shared held-guard capture helper. On any refusal the intact
    /// proof is returned alongside a typed reason (no consumption has occurred).
    fn try_capture(
        &mut self,
        decision: &qbind_consensus::SafetyDecisionView<'_, [u8; 32]>,
        proof: ValidatedRecord,
    ) -> Result<
        super::decision_capture::OwningCapturePayload,
        (ValidatedRecord, super::decision_capture::OwnedCaptureRefusal),
    > {
        use super::decision_capture::{
            bind_ancestry, commit_proposal, derive_block_id_local, envelope_extra_charge,
            scratch_charge, CorrespondenceRefusal, DecisionMetadata, EntrypointKind, MetaBranch,
            OwnedCaptureRefusal, OwningCapturePayload, ProjectionMismatch,
        };
        use super::prepared::CaptureRefusal;
        use qbind_consensus::SafetyBranch;

        let owner = self.owner;
        let limits = self.limits;
        let proposal = self.proposal;
        let proposer = self.proposer;
        let identity = self.identity;

        // --- correspondence: require a Locked decision (refuse engine NoLock) ---
        let branch = decision.branch();
        let (lock_id, lock_view) = match (decision.locked_block_id(), decision.locked_view()) {
            (Some(id), Some(view)) if branch != SafetyBranch::NoLock => (*id, view),
            _ => {
                return Err((
                    proof,
                    OwnedCaptureRefusal::Correspondence(CorrespondenceRefusal::EngineNoLock),
                ));
            }
        };
        // engine L0 lock ↔ sealed proof's retained lock restriction (distinct from
        // the proof-to-current-publication revision fence enforced in the helper).
        if lock_id != identity.lock_block_id {
            return Err((
                proof,
                OwnedCaptureRefusal::Correspondence(CorrespondenceRefusal::LockBlockMismatch),
            ));
        }
        if lock_view != identity.lock_view {
            return Err((
                proof,
                OwnedCaptureRefusal::Correspondence(CorrespondenceRefusal::LockViewMismatch),
            ));
        }

        // --- proposal projection checks against the actual decision view ---
        if decision.from() != proposer {
            return Err((
                proof,
                OwnedCaptureRefusal::Projection(ProjectionMismatch::Proposer),
            ));
        }
        // Enforce the header-to-originating-proposer correspondence (§4): the
        // reviewed `decision.from() == proposer` check only compares the decision
        // view with the SAME originating argument passed to the engine; it never
        // inspects `proposal.header.proposer_index`. A commitment covering the
        // mismatched header is not a substitute for this projection check. Use the
        // existing proposer-index / `ValidatorId` representation (the candidate-id
        // reproduction below already commits to `proposer.as_u64()`), so a header
        // whose proposer identity disagrees with the originating proposer is
        // refused before any charge or consumption.
        if u64::from(proposal.header.proposer_index) != proposer.as_u64() {
            return Err((
                proof,
                OwnedCaptureRefusal::Projection(ProjectionMismatch::Proposer),
            ));
        }
        let view = proposal.header.height;
        if decision.candidate_view() != view {
            return Err((
                proof,
                OwnedCaptureRefusal::Projection(ProjectionMismatch::CandidateView),
            ));
        }
        let parent_field = proposal.header.parent_block_id;
        match decision.candidate_parent() {
            None => {
                // Engine's exact no-parent convention: parent sentinel [0xFF; 32].
                if parent_field != [0xFF; 32] {
                    return Err((
                        proof,
                        OwnedCaptureRefusal::Projection(ProjectionMismatch::Parent),
                    ));
                }
            }
            Some(p) => {
                if parent_field == [0xFF; 32] || *p != parent_field {
                    return Err((
                        proof,
                        OwnedCaptureRefusal::Projection(ProjectionMismatch::Parent),
                    ));
                }
            }
        }
        // Node-local candidate-id reproduction, proven at parity against the
        // engine's own decision view (not a redesign of block identity).
        let reproduced = derive_block_id_local(proposer.as_u64(), view, &parent_field);
        if &reproduced != decision.candidate_id() {
            return Err((
                proof,
                OwnedCaptureRefusal::Projection(ProjectionMismatch::CandidateId),
            ));
        }
        // Justification: wire QC projects to the legacy logical justification.
        match &proposal.qc {
            Some(qc) => {
                match decision.candidate_justify_block_id() {
                    Some(jid) if *jid == qc.block_id => {}
                    _ => {
                        return Err((
                            proof,
                            OwnedCaptureRefusal::Projection(ProjectionMismatch::JustifyBlockId),
                        ));
                    }
                }
                match decision.candidate_justify_view() {
                    Some(jv) if jv == qc.height => {}
                    _ => {
                        return Err((
                            proof,
                            OwnedCaptureRefusal::Projection(ProjectionMismatch::JustifyView),
                        ));
                    }
                }
            }
            None => {
                if decision.candidate_justify_block_id().is_some()
                    || decision.candidate_justify_view().is_some()
                {
                    return Err((
                        proof,
                        OwnedCaptureRefusal::Projection(ProjectionMismatch::JustifyPresence),
                    ));
                }
            }
        }

        // --- §3 admission-before-construction: admit the additional envelope/data
        // coverage BEFORE constructing the metadata and binding values it covers,
        // so every new charged object has continuous covering admission. `covering`
        // is declared (and therefore released) FIRST, so on any refusal below the
        // covered objects (meta, proposal_binding, ancestry) are destroyed before
        // their covering reservation releases. The original proof's own reservation
        // stays intact until the capture conversion transfers ownership; it is not
        // used as spare capacity, and no uncharged temporary wrapper is introduced.
        let covering_charge = match envelope_extra_charge() {
            Some(c) => c,
            None => {
                return Err((
                    proof,
                    OwnedCaptureRefusal::Capture(CaptureRefusal::Admission(
                        super::error::SafetyStoreError::ArithmeticOverflow(
                            super::error::ArithmeticOverflowSite::SizeSum,
                        ),
                    )),
                ));
            }
        };
        let covering = match owner.backend.accounting().reserve(covering_charge) {
            Ok(r) => r,
            Err(e) => {
                return Err((proof, OwnedCaptureRefusal::Capture(CaptureRefusal::Admission(e))))
            }
        };

        // --- fixed decision metadata (covered by `covering`; separate from the
        // commitment oracle) ---
        let meta_branch = match branch {
            SafetyBranch::ViewSufficiency => MetaBranch::ViewSufficiency,
            SafetyBranch::Ancestry => MetaBranch::Ancestry,
            SafetyBranch::NoLock => unreachable!("engine NoLock refused above"),
        };
        let entrypoint = if decision.is_verified_entrypoint() {
            EntrypointKind::Verified
        } else {
            EntrypointKind::LegacyLogical
        };
        let meta = DecisionMetadata::new(
            proposer.as_u64(),
            meta_branch,
            entrypoint,
            decision.origin_view(),
            *decision.candidate_id(),
            decision.candidate_view(),
        );

        // --- admit the hashing/traversal scratch BEFORE creating its covered
        // working objects (the transient SHA3 states live inside the calls below
        // and are destroyed before `scratch` releases). At this binding phase the
        // baseline proof, the `covering` reservation and `scratch` are ALL held
        // simultaneously (the actual reservation overlap). Compute the streaming
        // commitment and bounded ancestry binding, then release the scratch before
        // consumption. On a scratch/commit/ancestry refusal the covered working
        // objects are destroyed before `scratch` releases, and the covered binding
        // values before `covering` releases (declaration order). ---
        let scratch = match owner.backend.accounting().reserve(scratch_charge()) {
            Ok(r) => r,
            Err(e) => {
                return Err((proof, OwnedCaptureRefusal::Capture(CaptureRefusal::Admission(e))))
            }
        };
        // Source/test-only: observe the reservation overlap at this binding phase
        // (baseline + covering + scratch all live) BEFORE any covered binding value
        // is produced. A discriminating regression reads the accounting occupancy
        // here to confirm `covering` was admitted BEFORE this phase — the corrected
        // admission order — rather than afterwards. Compiled only under
        // `test`/`test-utils`; unreachable in a default/release build.
        #[cfg(any(test, feature = "test-utils"))]
        fire_binding_phase_hook();
        let proposal_binding = match commit_proposal(proposal, limits) {
            Ok(c) => c,
            Err(e) => {
                drop(scratch);
                return Err((proof, OwnedCaptureRefusal::InputBound(e)));
            }
        };
        let ancestry = match bind_ancestry(decision, limits) {
            Ok(a) => a,
            Err(e) => {
                drop(scratch);
                return Err((proof, OwnedCaptureRefusal::Ancestry(e)));
            }
        };
        drop(scratch);

        // --- consume the proof through the shared held-guard capture helper ---
        let pin = match owner.capture_prepared_decision_locked(
            &mut *self.guard,
            proof,
            self.expected_rev,
            identity,
        ) {
            Ok(p) => p,
            Err((proof, cr)) => {
                // Destroy the covered binding values before releasing their
                // covering reservation: `covering` was declared first, so returning
                // here drops `ancestry`, `proposal_binding` and `meta` before
                // `covering`. No explicit early release of `covering` (which would
                // invert that order).
                return Err((proof, OwnedCaptureRefusal::Capture(cr)));
            }
        };

        Ok(OwningCapturePayload::new(
            proposal_binding,
            ancestry,
            meta,
            pin,
            covering,
        ))
    }
}

impl qbind_consensus::OwningSafetyDecisionGate<[u8; 32], super::decision_capture::OwningCapturePayload>
    for OwningCaptureGate<'_, '_>
{
    fn evaluate_owning(
        &mut self,
        decision: &qbind_consensus::SafetyDecisionView<'_, [u8; 32]>,
    ) -> Result<super::decision_capture::OwningCapturePayload, qbind_consensus::SafetyGateRefusal>
    {
        // The gate is consulted exactly once per `Safe(_)` decision with the proof
        // present. Take it; on refusal restore it and record the typed reason.
        let proof = self
            .proof
            .take()
            .expect("owning gate consulted once with the proof present");
        match self.try_capture(decision, proof) {
            Ok(payload) => Ok(payload),
            Err((proof, reason)) => {
                self.proof = Some(proof);
                self.reason = Some(reason);
                Err(qbind_consensus::SafetyGateRefusal)
            }
        }
    }
}

struct LeaderCaptureGate<'o, 'g> {
    owner: &'o SafetyRecordOwner,
    guard: &'o mut std::sync::MutexGuard<'g, super::backend::SerializationDomain>,
    proof: Option<ValidatedRecord>,
    identity: super::prepared::GenerationIdentity,
    expected_revision: u64,
    limits: super::decision_capture::PreparedDecisionInputLimits,
    proposer: qbind_consensus::ValidatorId,
    reason: Option<super::decision_capture::LeaderCaptureRefusal>,
}

impl LeaderCaptureGate<'_, '_> {
    fn refuse(
        &mut self,
        reason: super::decision_capture::LeaderCaptureRefusal,
    ) -> Result<
        super::decision_capture::LeaderCapturePayload,
        qbind_consensus::SafetyGateRefusal,
    > {
        self.reason = Some(reason);
        Err(qbind_consensus::SafetyGateRefusal)
    }

    fn validate_projection(
        &self,
        input: &qbind_consensus::LeaderCaptureInput<'_>,
    ) -> Result<(), super::decision_capture::LeaderCaptureRefusal> {
        use super::decision_capture::{
            CorrespondenceRefusal, LeaderCaptureRefusal, ProjectionMismatch,
        };
        let context = input.context();
        let proposal = input.proposal();
        let identity = self.identity;
        if context.proposer() != self.proposer
            || u64::from(proposal.header.proposer_index) != self.proposer.as_u64()
        {
            return Err(LeaderCaptureRefusal::Projection(ProjectionMismatch::Proposer));
        }
        if context.candidate_view() != context.origin_view()
            || proposal.header.height != context.candidate_view()
            || proposal.header.round != context.origin_view()
        {
            return Err(LeaderCaptureRefusal::Projection(
                ProjectionMismatch::CandidateView,
            ));
        }
        if context.epoch() != self.owner.pinned().epoch
            || proposal.header.epoch != context.epoch()
            || proposal.header.chain_id != self.owner.pinned().chain_id
        {
            return Err(LeaderCaptureRefusal::Projection(
                ProjectionMismatch::CandidateView,
            ));
        }
        if context.proposal_suite_id() != qbind_wire::DEFAULT_CONSENSUS_SUITE_ID
            || proposal.header.suite_id != context.proposal_suite_id()
        {
            return Err(LeaderCaptureRefusal::Projection(
                ProjectionMismatch::Proposer,
            ));
        }
        if proposal.header.parent_block_id != *context.parent_block_id() {
            return Err(LeaderCaptureRefusal::Projection(ProjectionMismatch::Parent));
        }
        if proposal.header.payload_kind != context.payload_kind()
            || proposal.header.next_epoch != context.next_epoch()
            || (context.payload_kind() == qbind_wire::PAYLOAD_KIND_NORMAL
                && context.next_epoch() != 0)
            || (context.payload_kind() == qbind_wire::PAYLOAD_KIND_RECONFIG
                && context.next_epoch() <= context.epoch())
        {
            return Err(LeaderCaptureRefusal::Projection(
                ProjectionMismatch::CandidateView,
            ));
        }
        let expected_id = {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&context.proposer().as_u64().to_le_bytes());
            id[8..16].copy_from_slice(&context.candidate_view().to_le_bytes());
            id[16..32].copy_from_slice(&context.parent_block_id()[..16]);
            id
        };
        if expected_id != *context.candidate_id() {
            return Err(LeaderCaptureRefusal::Projection(
                ProjectionMismatch::CandidateId,
            ));
        }
        let justification = context.justification().ok_or(
            LeaderCaptureRefusal::Correspondence(CorrespondenceRefusal::EngineNoLock),
        )?;
        if justification.signer_count > self.limits.max_qc_sig_count() as usize {
            return Err(LeaderCaptureRefusal::Projection(
                ProjectionMismatch::JustifySignerCount,
            ));
        }
        if justification.block_id != identity.lock_block_id {
            return Err(LeaderCaptureRefusal::Correspondence(
                CorrespondenceRefusal::LockBlockMismatch,
            ));
        }
        if justification.view != identity.lock_view {
            return Err(LeaderCaptureRefusal::Correspondence(
                CorrespondenceRefusal::LockViewMismatch,
            ));
        }
        if *context.parent_block_id() != identity.lock_block_id {
            return Err(LeaderCaptureRefusal::Projection(ProjectionMismatch::Parent));
        }
        match &proposal.qc {
            Some(qc)
                if qc.block_id == justification.block_id
                    && qc.height == justification.view
                    && qc.round == justification.view
                    && qc.epoch == context.epoch()
                    && qc.chain_id == self.owner.pinned().chain_id
                    && qc.suite_id == qbind_wire::DEFAULT_CONSENSUS_SUITE_ID
                    && qc.signer_bitmap.is_empty()
                    && qc.signatures.is_empty() => {}
            _ => {
                return Err(LeaderCaptureRefusal::Projection(
                    ProjectionMismatch::JustifyBlockId,
                ))
            }
        }
        if proposal.header.tx_count as usize != proposal.txs.len() {
            return Err(LeaderCaptureRefusal::Projection(
                ProjectionMismatch::CandidateView,
            ));
        }
        Ok(())
    }
}

impl qbind_consensus::LeaderProposalGate<super::decision_capture::LeaderCapturePayload>
    for LeaderCaptureGate<'_, '_>
{
    fn route_limits(&self) -> qbind_consensus::LeaderRouteLimits {
        qbind_consensus::LeaderRouteLimits::new(self.limits.max_qc_sig_count() as usize)
    }

    fn capture_l0(
        &mut self,
        input: &qbind_consensus::LeaderCaptureInput<'_>,
    ) -> Result<
        super::decision_capture::LeaderCapturePayload,
        qbind_consensus::SafetyGateRefusal,
    > {
        use super::decision_capture::{
            commit_proposal, leader_ancestry_not_applicable, scratch_charge,
            DecisionMetadata, EntrypointKind, LeaderCapturePayload, LeaderCaptureRefusal,
            MetaBranch,
        };

        if self.proof.is_none() {
            return self.refuse(LeaderCaptureRefusal::UnexpectedDecisionBranch);
        }
        if let Err(reason) = self.validate_projection(input) {
            return self.refuse(reason);
        }
        let context = input.context();
        let proposal = input.proposal();
        let (binding, ancestry) = {
            let _scratch = match self.owner.backend.accounting().reserve(scratch_charge()) {
                Ok(reservation) => reservation,
                Err(error) => return self.refuse(LeaderCaptureRefusal::Admission(error)),
            };
            let binding = match commit_proposal(proposal, &self.limits) {
                Ok(binding) => binding,
                Err(error) => return self.refuse(LeaderCaptureRefusal::InputBound(error)),
            };
            (binding, leader_ancestry_not_applicable())
        };
        let metadata = DecisionMetadata::new(
            context.proposer().as_u64(),
            MetaBranch::ViewSufficiency,
            EntrypointKind::LeaderLogical,
            context.origin_view(),
            *context.candidate_id(),
            context.candidate_view(),
        );
        let proof = self
            .proof
            .take()
            .expect("leader capture callback is invoked once with an intact proof");
        match self.owner.capture_prepared_decision_locked(
            &mut *self.guard,
            proof,
            self.expected_revision,
            self.identity,
        ) {
            Ok(pin) => Ok(LeaderCapturePayload::new(binding, ancestry, metadata, pin)),
            Err((proof, error)) => {
                self.proof = Some(proof);
                self.refuse(LeaderCaptureRefusal::Capture(error))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderRouteChargeOperands {
    pub gate: u128,
    pub preflight: u128,
    pub context: u128,
    pub callback_input: u128,
    pub registration_plan: u128,
    pub signer_buffer: u128,
    pub signer_backing: u128,
    pub proposal_binding_metadata: u128,
    pub proposal: u128,
    pub vote: u128,
    pub vote_report: u128,
    pub payload: u128,
    pub pin: u128,
    pub proof: u128,
    pub engine_result: u128,
    pub envelope: u128,
    pub owner_result: u128,
    pub admission: u128,
    pub admission_result: u128,
    pub reservation_control: u128,
    pub post_capture_failure: u128,
    pub post_capture_diagnostic: u128,
    pub conversion_excess: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderRouteChargePhases {
    pub admitted_token: u128,
    pub signer: u128,
    pub registration_plan: u128,
    pub binding: u128,
    pub proof_conversion: u128,
    pub captured_payload: u128,
    pub self_vote_before_message: u128,
    pub self_vote_after_message: u128,
    pub engine_result: u128,
    pub engine_to_owner_transfer: u128,
    pub post_capture_cleanup: u128,
    pub returned_proof_outcome: u128,
    pub returned_success_outcome: u128,
    pub returned_post_capture_outcome: u128,
    pub proof_extraction: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderRouteChargeReport {
    pub operands: LeaderRouteChargeOperands,
    pub phases: LeaderRouteChargePhases,
    pub selected: u128,
}

fn leader_route_charge<G>(signer_capacity: usize) -> Result<LeaderRouteChargeReport, SafetyStoreError> {
    use super::decision_capture::{
        DecisionMetadata, LeaderCapturePayload, LeaderOwnerOutcome,
        LeaderRoutePreparationRefusal,
    };
    use super::prepared::PreparedPin;
    use qbind_wire::consensus::{BlockProposal, Vote};
    use std::mem::size_of;

    fn sum(values: &[u128]) -> Result<u128, SafetyStoreError> {
        values.iter().try_fold(0u128, |total, value| {
            total.checked_add(*value).ok_or(SafetyStoreError::ArithmeticOverflow(
                ArithmeticOverflowSite::SizeSum,
            ))
        })
    }
    fn sub(left: u128, right: u128) -> Result<u128, SafetyStoreError> {
        left.checked_sub(right).ok_or(SafetyStoreError::ArithmeticOverflow(
            ArithmeticOverflowSite::SizeSum,
        ))
    }

    let layout = qbind_consensus::leader_route_layout::<LeaderCapturePayload>();
    let gate = size_of::<G>() as u128;
    let proof = size_of::<ValidatedRecord>() as u128;
    let pin = size_of::<PreparedPin>() as u128;
    let proposal = size_of::<BlockProposal>() as u128;
    let vote = size_of::<Vote>() as u128;
    let binding = sum(&[
        size_of::<[u8; 32]>() as u128,
        size_of::<super::decision_capture::AncestryBinding>() as u128,
        size_of::<DecisionMetadata>() as u128,
    ])?;
    let signer_backing = (signer_capacity as u128)
        .checked_mul(size_of::<qbind_consensus::ValidatorId>() as u128)
        .ok_or(SafetyStoreError::ArithmeticOverflow(
            ArithmeticOverflowSite::SizeSum,
        ))?;
    let outcome = size_of::<LeaderOwnerOutcome>() as u128;
    let admission = size_of::<LeaderRouteAdmission<'static>>() as u128;
    let admission_result =
        size_of::<Result<LeaderRouteAdmission<'static>, LeaderRoutePreparationRefusal>>() as u128;
    let reservation_control = size_of::<super::accounting::Reservation>() as u128;
    let envelope = layout.envelope;
    let payload_residual = sub(layout.payload, pin)?;
    let gate_proof_residual = sub(gate, proof)?;
    let owner_proof_residual = sub(outcome, proof)?;
    let owner_pin_residual = sub(outcome, pin)?;
    let post =
        size_of::<qbind_consensus::LeaderPostCaptureFailure<LeaderCapturePayload>>() as u128;
    let diagnostic = size_of::<qbind_consensus::LeaderPostCaptureDiagnostic>() as u128;
    let report = layout.vote_report;
    let buffer = layout.signer_buffer;
    let registration = layout.registration_plan;
    let callback = layout.callback_input;
    let preflight = layout.preflight;
    let phases = LeaderRouteChargePhases {
        admitted_token: admission_result,
        signer: sum(&[
            gate_proof_residual,
            reservation_control,
            buffer,
            signer_backing,
        ])?,
        registration_plan: sum(&[
            gate_proof_residual,
            reservation_control,
            preflight,
            registration,
            buffer,
            signer_backing,
        ])?,
        binding: sum(&[
            gate_proof_residual,
            reservation_control,
            preflight,
            layout.context,
            callback,
            registration,
            buffer,
            signer_backing,
            proposal,
            binding,
        ])?,
        proof_conversion: sum(&[
            gate,
            reservation_control,
            preflight,
            layout.context,
            callback,
            registration,
            buffer,
            signer_backing,
            proposal,
            binding,
            sub(
                size_of::<super::record::ConsumedForPrepared>() as u128,
                size_of::<super::record::RetainedRecord>() as u128,
            )?,
        ])?,
        captured_payload: sum(&[
            gate,
            reservation_control,
            preflight,
            layout.context,
            callback,
            registration,
            buffer,
            signer_backing,
            proposal,
            payload_residual,
        ])?,
        self_vote_before_message: sum(&[
            gate,
            reservation_control,
            preflight,
            proposal,
            payload_residual,
            report,
        ])?,
        self_vote_after_message: sum(&[
            gate,
            reservation_control,
            preflight,
            proposal,
            payload_residual,
            vote,
            report,
        ])?,
        engine_result: sum(&[
            gate,
            reservation_control,
            preflight,
            sub(layout.engine_result, pin)?,
        ])?,
        engine_to_owner_transfer: sum(&[
            gate,
            preflight,
            sub(layout.engine_result, envelope)?,
            owner_pin_residual,
        ])?,
        post_capture_cleanup: sum(&[gate, reservation_control, preflight, post])?,
        returned_proof_outcome: owner_proof_residual,
        returned_success_outcome: owner_pin_residual,
        returned_post_capture_outcome: outcome,
        proof_extraction: outcome,
    };
    let selected = [
        phases.admitted_token,
        phases.signer,
        phases.registration_plan,
        phases.binding,
        phases.proof_conversion,
        phases.captured_payload,
        phases.self_vote_before_message,
        phases.self_vote_after_message,
        phases.engine_result,
        phases.engine_to_owner_transfer,
        phases.post_capture_cleanup,
        phases.returned_proof_outcome,
        phases.returned_success_outcome,
        phases.returned_post_capture_outcome,
        phases.proof_extraction,
    ]
    .into_iter()
    .max()
    .ok_or(SafetyStoreError::ArithmeticOverflow(
        ArithmeticOverflowSite::SizeSum,
    ))?;
    Ok(LeaderRouteChargeReport {
        operands: LeaderRouteChargeOperands {
            gate,
            preflight,
            context: layout.context,
            callback_input: callback,
            registration_plan: registration,
            signer_buffer: buffer,
            signer_backing,
            proposal_binding_metadata: binding,
            proposal,
            vote,
            vote_report: report,
            payload: layout.payload,
            pin,
            proof,
            engine_result: layout.engine_result,
            envelope,
            owner_result: outcome,
            admission,
            admission_result,
            reservation_control,
            post_capture_failure: post,
            post_capture_diagnostic: diagnostic,
            conversion_excess: sub(
                size_of::<super::record::ConsumedForPrepared>() as u128,
                size_of::<super::record::RetainedRecord>() as u128,
            )?,
        },
        phases,
        selected,
    })
}