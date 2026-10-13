//! Run 422 D7-D14 — executable component-level allocation **admission and
//! accounting** (§ 13.7 / § 13.7A / § 13.7B).
//!
//! Every charge is computed with checked `u128` arithmetic and admitted against
//! the aggregate ceiling **before** the application-owned allocation it
//! represents. Releasing a charge is in-memory accounting bookkeeping only; it
//! is never treated as proof that a durable storage write was rolled back.

use std::sync::{Arc, Mutex};

use super::error::{
    ArithmeticOverflowSite, CapacityRefusalDetail, CapnormSiteKind, DeclaredBoundDetail,
    LedgerScope, SafetyStoreError,
};
use super::profile::{
    max_aggregate_retained_bytes, max_retained_generation_bytes, PinnedSafetyContext, ARC_CTRL,
    CAPNORM_SLACK, VALIDATOR_ID_WIDTH,
};
use super::record::{
    size_of_retained_generation, size_of_timeout_msg, DecodedRecord, RetainedGeneration,
    SafetyRecord, SupportingEvidence,
};

fn add(a: u128, b: u128) -> Result<u128, SafetyStoreError> {
    a.checked_add(b).ok_or(SafetyStoreError::ArithmeticOverflow(
        ArithmeticOverflowSite::AccountingSum,
    ))
}
fn mul(a: u128, b: u128) -> Result<u128, SafetyStoreError> {
    a.checked_mul(b).ok_or(SafetyStoreError::ArithmeticOverflow(
        ArithmeticOverflowSite::AccountingProduct,
    ))
}

/// The actual per-generation retained-memory charge (§ 13.7A(c)): the whole-enum
/// wrapper struct + its heap backings + the shared-allocation overhead charged
/// **once**. Always `<= MAX_RETAINED_GENERATION_BYTES`.
pub fn generation_charge(
    ctx: &PinnedSafetyContext,
    gen: &RetainedGeneration,
) -> Result<u128, SafetyStoreError> {
    // Inline wrapper + the actual **capacity**-measured heap backings + the
    // shared-allocation overhead charged once per retained generation.
    let mut total = add(
        size_of_retained_generation(),
        evidence_backing_capacity(&gen.evidence)?,
    )?;
    total = add(total, ARC_CTRL)?;

    let cap = max_retained_generation_bytes(ctx, size_of_timeout_msg())?;
    if total > cap {
        return Err(SafetyStoreError::DeclaredBoundExceeded(
            DeclaredBoundDetail::GenerationChargeExceeds { charge: total, cap },
        ));
    }
    Ok(total)
}

/// The **capacity-measured** heap-backing charge for a supporting-evidence value
/// (§ 13.7A(b), D7-D14 capacity-aware correction).
///
/// Every variable-size backing is charged by its actual `Vec::capacity()`, not
/// its `len()`: a structurally valid evidence value whose length fits the pinned
/// bounds can still own a backing allocation whose **requested capacity** exceeds
/// those bounds (e.g. a caller-supplied `Vec::with_capacity(huge)` holding only a
/// few elements). Length admission alone therefore does **not** establish a
/// retained-memory bound; the capacity charge does. This includes the *outer*
/// descriptor arrays (`signatures`, `signers`, `signed_timeouts`) whose spare
/// capacity is genuine allocated memory, not just the per-element buffers.
pub fn evidence_backing_capacity(evidence: &SupportingEvidence) -> Result<u128, SafetyStoreError> {
    let mut total: u128 = 0;
    match evidence {
        SupportingEvidence::QcDerived(qc) => {
            // signer_bitmap backing + signatures outer descriptor capacity + per-sig bytes.
            total = add(total, qc.signer_bitmap.capacity() as u128)?;
            total = add(total, mul(qc.signatures.capacity() as u128, 24)?)?; // Vec<u8> descriptor array
            for sig in &qc.signatures {
                total = add(total, sig.capacity() as u128)?;
            }
        }
        SupportingEvidence::TcDerived { high_qc, tc } => {
            total = add(
                total,
                mul(high_qc.signers.capacity() as u128, VALIDATOR_ID_WIDTH)?,
            )?;
            total = add(
                total,
                mul(tc.signers.capacity() as u128, VALIDATOR_ID_WIDTH)?,
            )?;
            if let Some(h) = &tc.high_qc {
                total = add(
                    total,
                    mul(h.signers.capacity() as u128, VALIDATOR_ID_WIDTH)?,
                )?;
            }
            total = add(
                total,
                mul(tc.signed_timeouts.capacity() as u128, size_of_timeout_msg())?,
            )?;
            for t in &tc.signed_timeouts {
                total = add(total, t.signature.capacity() as u128)?;
                if let Some(h) = &t.high_qc {
                    total = add(
                        total,
                        mul(h.signers.capacity() as u128, VALIDATOR_ID_WIDTH)?,
                    )?;
                }
            }
        }
    }
    Ok(total)
}

/// Capacity-aware **admission** of a supporting-evidence value against the
/// per-generation retained ceiling (§ 13.7A(c.3), D7-D14 capacity-aware
/// correction). Reuses [`evidence_backing_capacity`] so the *actual* owned
/// backing capacity of caller-supplied evidence — not merely its structurally
/// admitted length — is proven to fit `MAX_RETAINED_GENERATION_BYTES` **before**
/// the component takes ownership, clones, or re-encodes it (the O4 candidate path
/// and every builder/helper). A value whose spare capacity pushes the real
/// footprint past the ceiling is refused with [`SafetyStoreError::CapacityRefusal`]
/// — a pre-allocation refusal that leaves stored state and admitted evidence
/// untouched — rather than admitted on its length and discovered too large only
/// after the owning allocation already exists.
pub fn admit_evidence_capacity(
    evidence: &SupportingEvidence,
    ctx: &PinnedSafetyContext,
) -> Result<(), SafetyStoreError> {
    let backing = evidence_backing_capacity(evidence)?;
    let total = add(add(size_of_retained_generation(), backing)?, ARC_CTRL)?;
    let cap = max_retained_generation_bytes(ctx, size_of_timeout_msg())?;
    if total > cap {
        return Err(SafetyStoreError::CapacityRefusal(
            CapacityRefusalDetail::EvidenceBackingExceeds { charge: total, cap },
        ));
    }
    Ok(())
}

/// Per-vector capacity bound (§ 13.7 capacity policy / § 13.7A generation caps):
/// the individual **per-object** restriction the aggregate
/// [`admit_evidence_capacity`] check does *not*, by itself, enforce.
///
/// Each decoded growable backing a generation owns is bounded by the **pinned
/// profile maximum** for its class plus the normalization slack:
///
/// * `signer_bitmap` ≤ `B_span + CAPNORM_SLACK` bytes,
/// * the `signatures` outer descriptor array ≤ `N + CAPNORM_SLACK` elements,
/// * every per-signature buffer ≤ `S_sig + CAPNORM_SLACK` bytes,
/// * every logical-QC signer vector (record-level `high_qc`, `tc.signers`, the
///   optional TC `high_qc`, and every timeout entry's optional nested `high_qc`)
///   ≤ `N + CAPNORM_SLACK` elements,
/// * the `signed_timeouts` outer descriptor array ≤ `N + CAPNORM_SLACK` elements,
/// * every timeout entry's `signature` buffer ≤ `S_sig + CAPNORM_SLACK` bytes.
///
/// The bound is derived from the accepted profile (`N`, `S_sig`, `B_span`) — the
/// same maxima the § 13.7A generation caps and the aggregate budget reserve — not
/// from the individual vector's own `len()`: a legitimately pre-sized backing
/// (e.g. one grown to the profile maximum) is admitted, so this is **not** an
/// invented "capacity must equal length" rule. Under the initial profile
/// (`CAPNORM_SLACK = 0`) the bound is exactly the profile maximum. A single
/// backing whose `capacity()` exceeds its class maximum by even the smallest
/// amount is refused here with [`SafetyStoreError::CapacityRefusal`] — **before**
/// the component clones, binds, or re-encodes the evidence — even when the *total*
/// footprint still fits the cross-variant generation maximum (precisely the
/// smaller violation the huge-capacity aggregate tests cannot establish).
pub fn admit_evidence_capnorm(
    evidence: &SupportingEvidence,
    ctx: &PinnedSafetyContext,
) -> Result<(), SafetyStoreError> {
    let n = ctx.n() as u128;
    let s_sig = ctx.s_sig as u128;
    let b_span = ctx.b_span();
    match evidence {
        SupportingEvidence::QcDerived(qc) => {
            check_capnorm(
                qc.signer_bitmap.capacity() as u128,
                b_span,
                CapnormSiteKind::QcSignerBitmap,
            )?;
            check_capnorm(
                qc.signatures.capacity() as u128,
                n,
                CapnormSiteKind::QcSignaturesDescriptor,
            )?;
            for (i, sig) in qc.signatures.iter().enumerate() {
                check_capnorm(
                    sig.capacity() as u128,
                    s_sig,
                    CapnormSiteKind::QcSignatureBuffer(i),
                )?;
            }
        }
        SupportingEvidence::TcDerived { high_qc, tc } => {
            check_capnorm(
                high_qc.signers.capacity() as u128,
                n,
                CapnormSiteKind::RecordHighQcSigners,
            )?;
            check_capnorm(tc.signers.capacity() as u128, n, CapnormSiteKind::TcSigners)?;
            if let Some(h) = &tc.high_qc {
                check_capnorm(
                    h.signers.capacity() as u128,
                    n,
                    CapnormSiteKind::TcHighQcSigners,
                )?;
            }
            check_capnorm(
                tc.signed_timeouts.capacity() as u128,
                n,
                CapnormSiteKind::TcSignedTimeoutsDescriptor,
            )?;
            for (i, t) in tc.signed_timeouts.iter().enumerate() {
                check_capnorm(
                    t.signature.capacity() as u128,
                    s_sig,
                    CapnormSiteKind::TcSignedTimeoutSignature(i),
                )?;
                if let Some(h) = &t.high_qc {
                    check_capnorm(
                        h.signers.capacity() as u128,
                        n,
                        CapnormSiteKind::TcSignedTimeoutNestedHighQcSigners(i),
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// A single decoded growable backing passes the capacity bound iff its
/// `capacity()` is within `profile_max + CAPNORM_SLACK` elements/bytes for its
/// class. Over-bound → refuse (no silent over-capacity retention), naming the
/// offending backing and its class maximum. The `site` identifier is the `Copy`
/// [`CapnormSiteKind`] (an inline `usize` index for the array sites), so BOTH
/// the success path AND the refusal path allocate nothing: the refusal carries
/// typed [`CapacityRefusalDetail::PerVector`] `Copy` bound data, and the
/// diagnostic `String` is materialised only if/when the error is rendered via
/// `Display`. This keeps the O4 structural/capacity preflight — which runs
/// BEFORE the O4 operation reservation — allocation-free on the refusal path as
/// well as on success (§ 13.7A, D7-D14 allocation-free preflight correction).
fn check_capnorm(
    capacity: u128,
    profile_max: u128,
    site: CapnormSiteKind,
) -> Result<(), SafetyStoreError> {
    let permitted = add(profile_max, CAPNORM_SLACK)?;
    if capacity > permitted {
        return Err(SafetyStoreError::CapacityRefusal(
            CapacityRefusalDetail::PerVector {
                site,
                capacity,
                profile_max,
                slack: CAPNORM_SLACK,
            },
        ));
    }
    Ok(())
}

/// The actual **live** decoded working-set charge of a transient
/// [`DecodedRecord`], measured on the borrowed object *in place* (§ 13.7A(c.4),
/// D7-D14 O2 measurement correction).
///
/// This observes the real decoded object operations hold across decode→validation
/// — its inline representation plus the `Vec::capacity()` of every backing it
/// actually owns (outer descriptor arrays, each nested signer backing, every
/// signature backing, the bitmap) — **without** cloning it into a synthetic
/// [`RetainedGeneration`]. Charging a `RetainedGeneration::from_locked` clone (as
/// the earlier O2 check did) measures a *second*, freshly-allocated representation
/// whose capacities are the clone's, not the live decoded object's; this borrowed
/// inventory measures the object itself.
pub fn decoded_working_set_charge(decoded: &DecodedRecord) -> Result<u128, SafetyStoreError> {
    let mut total = size_of_decoded_record_inline();
    if let SafetyRecord::Locked(l) = &decoded.record {
        total = add(total, evidence_backing_capacity(&l.evidence)?)?;
    }
    Ok(total)
}

/// The contract-charged **inline** footprint of one live [`DecodedRecord`]
/// (§ 13.7A(c.4)): the measured `size_of::<DecodedRecord>()`, independent of any
/// heap evidence backing. This is the charge the O1 bootstrap publication phase
/// must reserve for its live decoded local — the object `encode_record` *borrows*
/// (it does not consume it) and which therefore remains in scope, coexisting with
/// every publication buffer, through `publish_atomic`. A heap-only allocation
/// counter cannot observe this stack-resident inline footprint, so it must be
/// charged explicitly against the shared aggregate rather than inferred from
/// another reservation's headroom (§ 13.7, D7-D14 Finding A correction).
pub fn size_of_decoded_record_inline() -> u128 {
    std::mem::size_of::<DecodedRecord>() as u128
}

/// The transient decoded working-set **ceiling** for the pinned context
/// (§ 13.7A(c.4), D7-D14 transient-accounting correction): the measured
/// `size_of::<DecodedRecord>()` inline footprint plus the cross-variant maximum
/// evidence backing. It is a proven upper bound on [`decoded_working_set_charge`]
/// for **every** admitted decoded object (each backing passes
/// [`admit_evidence_capnorm`], so its `capacity()` is within the per-class
/// profile maximum, and the inline size is fixed), and — because the inline
/// `DecodedRecord` size exceeds the retained generation's `GEN_STRUCT_MAX`
/// ceiling — it is strictly larger than, and is **not** substituted by,
/// [`max_retained_generation_bytes`]. Operations that hold a live transient
/// decoded object reserve this term, not the retained-generation ceiling.
pub fn max_transient_decoded_working_set(
    ctx: &PinnedSafetyContext,
) -> Result<u128, SafetyStoreError> {
    super::profile::max_transient_decoded_bytes(
        ctx,
        size_of_decoded_record_inline(),
        size_of_timeout_msg(),
    )
}

/// The fixed CRC prefix (§ 13.4 framing) each component-owned publication
/// envelope carries ahead of its payload.
pub const CRC_PREFIX: u128 = 4;

/// The component-owned **publication-staging** charge (§ 13.5 / § 13.7, D7-D14 O5
/// publication-envelope coexistence correction).
///
/// `backend::publish_atomic` constructs two CRC-wrapped envelopes
/// (`SafetyBackend::wrap`) — one over the record payload, one over the metadata
/// payload — each a fresh `Vec::with_capacity(4 + payload.len())`. These are
/// genuinely **component-owned** allocations: being handed to a RocksDB
/// `WriteBatch` does not make them uncharged, and they coexist with the already
/// live publication-input buffer, the read-back buffer, the transient decoded
/// object, the encoded metadata payload, and (at O5) the retained holder. The
/// earlier O1/O4/O5 reservations charged the payload buffers but **not** these
/// framing envelopes, so a publication peaked above its reservation. This
/// conservative charge covers both envelopes at their worst case (`record` at the
/// maximum serialized record size, `meta` at `META_ENCODED_LEN`), so a
/// publication's component-owned staging is admitted before `wrap` allocates it.
pub fn publication_staging_charge(ctx: &PinnedSafetyContext) -> Result<u128, SafetyStoreError> {
    let record_envelope = add(CRC_PREFIX, super::profile::max_safety_record_bytes(ctx)?)?;
    let meta_envelope = add(CRC_PREFIX, super::backend::META_ENCODED_LEN)?;
    add(record_envelope, meta_envelope)
}

/// The component-level aggregate accountant. Enforces the checked aggregate
/// coexistence ceiling across every charged allocation; tracks the observed
/// peak for evidence.
#[derive(Debug)]
pub struct AllocationAccountant {
    cap: u128,
    current: u128,
    peak: u128,
}

impl AllocationAccountant {
    /// Build an accountant whose ceiling is `MAX_AGGREGATE_RETAINED_BYTES` for
    /// the pinned context, with a bounded validation-scratch reserve.
    pub fn new(
        ctx: &PinnedSafetyContext,
        validation_scratch: u128,
    ) -> Result<Self, SafetyStoreError> {
        let cap = max_aggregate_retained_bytes(ctx, size_of_timeout_msg(), validation_scratch)?;
        Ok(AllocationAccountant {
            cap,
            current: 0,
            peak: 0,
        })
    }

    /// Build an accountant with a directly-supplied aggregate ceiling. Used by
    /// the dedicated **context-ownership** accountant (§ 13.7B), whose ceiling is
    /// the bounded multiplicity of the per-owner context charge rather than the
    /// operational § 13.7A generation/record sum.
    pub fn with_cap(cap: u128) -> Self {
        AllocationAccountant {
            cap,
            current: 0,
            peak: 0,
        }
    }

    /// The configured aggregate ceiling.
    pub fn cap(&self) -> u128 {
        self.cap
    }
    /// The current charged total.
    pub fn current(&self) -> u128 {
        self.current
    }
    /// The observed peak charged total.
    pub fn peak(&self) -> u128 {
        self.peak
    }

    /// Admit `charge` bytes **before** allocating; refuse if it would exceed the
    /// ceiling (checked arithmetic). On success the charge is held until an
    /// explicit [`AllocationAccountant::release`].
    pub fn admit(&mut self, charge: u128) -> Result<(), SafetyStoreError> {
        let next = add(self.current, charge)?;
        if next > self.cap {
            return Err(SafetyStoreError::CapacityRefusal(
                CapacityRefusalDetail::AdmissionOverflow {
                    scope: LedgerScope::Partition,
                    charge,
                    current: self.current,
                    next,
                    cap: self.cap,
                },
            ));
        }
        self.current = next;
        if next > self.peak {
            self.peak = next;
        }
        Ok(())
    }

    /// Release a previously admitted `charge`. This is **accounting bookkeeping
    /// only** (buffer lifetime), never evidence that a durable write was undone.
    pub fn release(&mut self, charge: u128) {
        self.current = self.current.saturating_sub(charge);
    }
}

/// Measured in-memory size of one [`Reservation`] value on the supported target
/// (`size_of::<Reservation>()`). Exposed so a layout regression can establish —
/// independently of any charge helper — that a wrapper which embeds a
/// `Reservation` inline (e.g. the owner's `OwnedContext`) actually accounts for
/// that field rather than silently omitting it (§ 13.7B, finding #3).
pub fn size_of_reservation() -> u128 {
    std::mem::size_of::<Reservation>() as u128
}

/// The shared **aggregate admission authority** enforcing the accepted component
/// coexistence ceiling across BOTH accounting partitions — the operational
/// O1–O5 working set AND the context-ownership allocations (§ 13.7, finding #4
/// combined-bound correction).
///
/// The two partitions keep their own sub-ledgers (so the operational peak /
/// holder numbers are unchanged and the bounded context multiplicity is still
/// refused on its own sub-cap), but **every** reservation — operational or
/// context — must also be admitted here first. The aggregate ceiling is the
/// accepted **profile-derived** aggregate (`max_aggregate_retained_bytes`); it is
/// **not** enlarged by the context sub-cap. The per-class sub-caps therefore sum
/// to *more* than this aggregate, and that surplus is deliberately unreachable:
/// live operational and context charges can never *jointly* exceed the accepted
/// aggregate, so a live context genuinely reduces the capacity available to
/// operations and vice-versa, and a concurrent operation + attachment cannot
/// admit against two independent ceilings whose sum would exceed the permitted
/// coexistence budget.
#[derive(Debug)]
struct AggregateGuard {
    cap: u128,
    current: u128,
    peak: u128,
}

/// The shared, cloneable handle to the single [`AggregateGuard`]. One instance
/// is created per `SafetyBackend` open and shared (the inner `Arc` is cloned,
/// never re-created) by both the operational and the context [`SharedAccountant`]
/// of that backend, so there is exactly one aggregate admission authority per
/// backend instance.
#[derive(Clone, Debug)]
pub struct AggregateAuthority {
    inner: Arc<Mutex<Option<AggregateGuard>>>,
}

impl Default for AggregateAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl AggregateAuthority {
    /// A fresh, unbound aggregate authority (no ceiling until [`AggregateAuthority::bind`]).
    pub fn new() -> Self {
        AggregateAuthority {
            inner: Arc::new(Mutex::new(None)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<AggregateGuard>> {
        self.inner
            .lock()
            .expect("safety aggregate authority poisoned")
    }

    /// Establish (once) the accepted aggregate ceiling. A second bind with the
    /// identical ceiling is a no-op; a divergent ceiling is refused so a foreign
    /// profile can never widen the combined coexistence budget.
    pub fn bind(&self, cap: u128) -> Result<(), SafetyStoreError> {
        let mut g = self.lock();
        match g.as_ref() {
            None => {
                *g = Some(AggregateGuard {
                    cap,
                    current: 0,
                    peak: 0,
                });
                Ok(())
            }
            Some(existing) => {
                if existing.cap != cap {
                    return Err(SafetyStoreError::CapacityRefusal(
                        CapacityRefusalDetail::RebindMismatch {
                            scope: LedgerScope::Aggregate,
                            bound: existing.cap,
                            attempted: cap,
                        },
                    ));
                }
                Ok(())
            }
        }
    }

    /// Admit `charge` against the accepted aggregate ceiling **before** the
    /// protected allocation. Refuses without disturbing the running total when
    /// the combined charge would exceed the aggregate.
    fn admit(&self, charge: u128) -> Result<(), SafetyStoreError> {
        let mut g = self.lock();
        let guard = g.as_mut().ok_or_else(|| {
            SafetyStoreError::CapacityRefusal(CapacityRefusalDetail::Unbound(
                LedgerScope::Aggregate,
            ))
        })?;
        let next = add(guard.current, charge)?;
        if next > guard.cap {
            return Err(SafetyStoreError::CapacityRefusal(
                CapacityRefusalDetail::AdmissionOverflow {
                    scope: LedgerScope::Aggregate,
                    charge,
                    current: guard.current,
                    next,
                    cap: guard.cap,
                },
            ));
        }
        guard.current = next;
        if next > guard.peak {
            guard.peak = next;
        }
        Ok(())
    }

    /// Release a previously admitted aggregate `charge` (accounting bookkeeping
    /// only; never evidence a durable write was undone).
    fn release(&self, charge: u128) {
        if let Some(guard) = self.lock().as_mut() {
            guard.current = guard.current.saturating_sub(charge);
        }
    }

    /// The configured aggregate ceiling, or `None` when not yet bound.
    pub fn cap(&self) -> Option<u128> {
        self.lock().as_ref().map(|g| g.cap)
    }
    /// The current combined charged total across both partitions (0 when unbound).
    pub fn current(&self) -> u128 {
        self.lock().as_ref().map(|g| g.current).unwrap_or(0)
    }
    /// The observed combined peak across both partitions (0 when unbound).
    pub fn peak(&self) -> u128 {
        self.lock().as_ref().map(|g| g.peak).unwrap_or(0)
    }
}

/// The shared, cloneable aggregate accountant owned by a `SafetyBackend` and
/// observed by **every** attached handle / clone (§ 13.7 / § 13.7B). Attaching
/// another handle to the same backend clones the `Arc` below — it never creates
/// an independent budget that could bypass the aggregate ceiling.
///
/// The ceiling is derived from the pinned context the **first** handle binds
/// (`bind`); every legitimate handle on one store shares the same pinned context
/// (enforced by the stored context digest), so a later bind with the same
/// parameters is a no-op and a divergent cap is refused rather than silently
/// widened.
///
/// Each `SharedAccountant` is one **partition** sub-ledger (operational or
/// context); both partitions of one backend share a single
/// [`AggregateAuthority`], so every reservation is admitted against the accepted
/// profile-derived aggregate ceiling as well as its own (subordinate) sub-cap
/// (§ 13.7, finding #4 correction — the aggregate is not the sum of the
/// sub-caps).
#[derive(Clone, Debug)]
pub struct SharedAccountant {
    inner: Arc<Mutex<Option<AllocationAccountant>>>,
    aggregate: AggregateAuthority,
}

impl Default for SharedAccountant {
    fn default() -> Self {
        Self::new(AggregateAuthority::new())
    }
}

impl SharedAccountant {
    /// A fresh, unbound shared accountant (no sub-ceiling until
    /// [`SharedAccountant::bind`]) sharing the supplied aggregate authority with
    /// its sibling partition on the same backend.
    pub fn new(aggregate: AggregateAuthority) -> Self {
        SharedAccountant {
            inner: Arc::new(Mutex::new(None)),
            aggregate,
        }
    }

    /// The shared aggregate admission authority this partition admits against.
    pub fn aggregate(&self) -> &AggregateAuthority {
        &self.aggregate
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<AllocationAccountant>> {
        self.inner.lock().expect("safety accountant poisoned")
    }

    /// Establish (once) the aggregate ceiling from the pinned context. A second
    /// bind with the identical computed ceiling is a no-op; a divergent ceiling
    /// is refused (a foreign-context handle can never widen the shared budget).
    pub fn bind(
        &self,
        ctx: &PinnedSafetyContext,
        validation_scratch: u128,
    ) -> Result<(), SafetyStoreError> {
        let acct = AllocationAccountant::new(ctx, validation_scratch)?;
        let mut g = self.lock();
        match g.as_ref() {
            None => {
                *g = Some(acct);
                Ok(())
            }
            Some(existing) => {
                if existing.cap() != acct.cap() {
                    return Err(SafetyStoreError::CapacityRefusal(
                        CapacityRefusalDetail::RebindMismatch {
                            scope: LedgerScope::SharedOperational,
                            bound: existing.cap(),
                            attempted: acct.cap(),
                        },
                    ));
                }
                Ok(())
            }
        }
    }

    /// Establish (once) a **directly-supplied** aggregate ceiling, used by the
    /// dedicated context-ownership accountant (§ 13.7B) whose ceiling is the
    /// bounded multiplicity of the per-owner context charge. A second bind with
    /// the identical ceiling is a no-op; a divergent ceiling is refused (a
    /// foreign-profile handle can never widen the shared context budget).
    pub fn bind_cap(&self, cap: u128) -> Result<(), SafetyStoreError> {
        let mut g = self.lock();
        match g.as_ref() {
            None => {
                *g = Some(AllocationAccountant::with_cap(cap));
                Ok(())
            }
            Some(existing) => {
                if existing.cap() != cap {
                    return Err(SafetyStoreError::CapacityRefusal(
                        CapacityRefusalDetail::RebindMismatch {
                            scope: LedgerScope::SharedContext,
                            bound: existing.cap(),
                            attempted: cap,
                        },
                    ));
                }
                Ok(())
            }
        }
    }

    /// Bind the shared [`AggregateAuthority`] to the accepted component aggregate
    /// ceiling (§ 13.7, finding #4). Idempotent with the identical ceiling;
    /// delegates to the single authority both partitions share.
    pub fn bind_aggregate(&self, cap: u128) -> Result<(), SafetyStoreError> {
        self.aggregate.bind(cap)
    }

    /// The configured sub-ceiling for this partition, or `None` when not yet bound.
    pub fn cap(&self) -> Option<u128> {
        self.lock().as_ref().map(|a| a.cap())
    }
    /// The current charged total for this partition (0 when unbound).
    pub fn current(&self) -> u128 {
        self.lock().as_ref().map(|a| a.current()).unwrap_or(0)
    }
    /// The observed peak charged total for this partition (0 when unbound).
    pub fn peak(&self) -> u128 {
        self.lock().as_ref().map(|a| a.peak()).unwrap_or(0)
    }

    /// Admit `charge` bytes **before** the protected allocation or copy. The
    /// charge is admitted first against the shared [`AggregateAuthority`] (the
    /// accepted combined coexistence ceiling) and then against this partition's
    /// own sub-ledger; if the partition admission fails the aggregate admission
    /// is rolled back, so neither running total is disturbed by a refusal. On
    /// success returns an RAII [`Reservation`] that releases **both** the
    /// aggregate and the partition charge when dropped. Refuses with
    /// [`SafetyStoreError::CapacityRefusal`] when the charge would exceed either
    /// ceiling.
    pub fn reserve(&self, charge: u128) -> Result<Reservation, SafetyStoreError> {
        self.aggregate.admit(charge)?;
        {
            let mut g = self.lock();
            let acct = match g.as_mut() {
                Some(acct) => acct,
                None => {
                    drop(g);
                    self.aggregate.release(charge);
                    return Err(SafetyStoreError::CapacityRefusal(
                        CapacityRefusalDetail::Unbound(LedgerScope::SharedOperational),
                    ));
                }
            };
            if let Err(e) = acct.admit(charge) {
                drop(g);
                self.aggregate.release(charge);
                return Err(e);
            }
        }
        Ok(Reservation {
            inner: Arc::clone(&self.inner),
            aggregate: self.aggregate.clone(),
            charge,
            released: false,
        })
    }
}

/// An RAII reservation of a charged quantity against a [`SharedAccountant`]. The
/// charge is released when the reservation is dropped, so success, semantic
/// refusal, write error, uncertain outcome, and an early return (via the `?`
/// unwind) **all** release the appropriate reservation without any explicit
/// bookkeeping at every exit. The release is accounting-only (buffer lifetime);
/// it is never evidence that a durable write was undone. Each reservation holds
/// both its partition sub-ledger charge and the shared aggregate charge, and
/// releases both together.
#[derive(Debug)]
pub struct Reservation {
    inner: Arc<Mutex<Option<AllocationAccountant>>>,
    aggregate: AggregateAuthority,
    charge: u128,
    released: bool,
}

impl Reservation {
    /// The charged quantity this reservation holds.
    pub fn charge(&self) -> u128 {
        self.charge
    }

    /// Reserve an **additional** holder of the same charge against the same
    /// shared accountant (both the partition sub-ledger and the shared
    /// aggregate). Used when a charged retained proof is duplicated: a clone owns
    /// a genuinely separate record-sized buffer, so it must take its own
    /// reservation rather than aliasing one — repeated cloning therefore cannot
    /// produce unbounded uncharged holders, and exhausting either the partition
    /// or the aggregate budget refuses the duplication.
    pub fn try_duplicate(&self) -> Result<Reservation, SafetyStoreError> {
        self.aggregate.admit(self.charge)?;
        {
            let mut g = self.inner.lock().expect("safety accountant poisoned");
            let acct = match g.as_mut() {
                Some(acct) => acct,
                None => {
                    drop(g);
                    self.aggregate.release(self.charge);
                    return Err(SafetyStoreError::CapacityRefusal(
                        CapacityRefusalDetail::Unbound(LedgerScope::SharedOperational),
                    ));
                }
            };
            if let Err(e) = acct.admit(self.charge) {
                drop(g);
                self.aggregate.release(self.charge);
                return Err(e);
            }
        }
        Ok(Reservation {
            inner: Arc::clone(&self.inner),
            aggregate: self.aggregate.clone(),
            charge: self.charge,
            released: false,
        })
    }

    /// Explicitly release this reservation early (e.g. to free a transient
    /// working buffer before reserving the next peak contributor). Idempotent
    /// with the eventual drop.
    pub fn release_now(mut self) {
        self.do_release();
    }

    fn do_release(&mut self) {
        if !self.released {
            if let Some(acct) = self
                .inner
                .lock()
                .expect("safety accountant poisoned")
                .as_mut()
            {
                acct.release(self.charge);
            }
            self.aggregate.release(self.charge);
            self.released = true;
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.do_release();
    }
}