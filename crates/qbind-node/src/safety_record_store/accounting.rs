//! Run 422 D7-D14 — executable component-level allocation **admission and
//! accounting** (§ 13.7 / § 13.7A / § 13.7B).
//!
//! Every charge is computed with checked `u128` arithmetic and admitted against
//! the aggregate ceiling **before** the application-owned allocation it
//! represents. Releasing a charge is in-memory accounting bookkeeping only; it
//! is never treated as proof that a durable storage write was rolled back.

use std::sync::{Arc, Mutex};

use super::error::SafetyStoreError;
use super::profile::{
    max_aggregate_retained_bytes, max_retained_generation_bytes, PinnedSafetyContext, ARC_CTRL,
    CAPNORM_SLACK, VALIDATOR_ID_WIDTH,
};
use super::record::{
    size_of_retained_generation, size_of_timeout_msg, DecodedRecord, RetainedGeneration,
    SafetyRecord, SupportingEvidence,
};

fn add(a: u128, b: u128) -> Result<u128, SafetyStoreError> {
    a.checked_add(b)
        .ok_or_else(|| SafetyStoreError::ArithmeticOverflow("accounting sum".into()))
}
fn mul(a: u128, b: u128) -> Result<u128, SafetyStoreError> {
    a.checked_mul(b)
        .ok_or_else(|| SafetyStoreError::ArithmeticOverflow("accounting product".into()))
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
        return Err(SafetyStoreError::DeclaredBoundExceeded(format!(
            "generation charge {total} exceeds MAX_RETAINED_GENERATION_BYTES {cap}"
        )));
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
        return Err(SafetyStoreError::CapacityRefusal(format!(
            "supporting-evidence backing capacity charge {total} exceeds \
             MAX_RETAINED_GENERATION_BYTES {cap} (excess spare capacity)"
        )));
    }
    Ok(())
}

/// Per-vector capacity-normalization bound (§ 13.7, capacity policy): the
/// individual **per-object** restriction the aggregate [`admit_evidence_capacity`]
/// check does *not*, by itself, enforce.
///
/// The contract's capacity-normalization rule bounds **each** decoded growable
/// backing a generation owns by `capacity() <= len() + CAPNORM_SLACK` (elements),
/// refusing any value whose spare capacity exceeds the pinned normalization slack
/// — not an invented "capacity must equal length" rule, but the profile-derived
/// `len() + CAPNORM_SLACK` bound, which under the **initial profile**
/// (`CAPNORM_SLACK = 0`) does reduce to an exact-capacity backing and under a
/// documented non-zero deployment admits exactly that many spare slots. A single
/// over-bound buffer is refused here with [`SafetyStoreError::CapacityRefusal`]
/// even when the *total* footprint still fits the cross-variant generation
/// maximum — precisely the smaller violation the huge-capacity aggregate tests
/// cannot establish.
///
/// It covers every § 13.7 backing class: the `signer_bitmap`, the `signatures`
/// outer descriptor array and each per-signature buffer (QC); the record-level
/// `high_qc.signers`, the `TimeoutCertificate.signers`, the optional TC
/// `high_qc.signers`, the `signed_timeouts` outer descriptor array, and every
/// timeout entry's `signature` buffer and optional nested `high_qc.signers`
/// backing (TC).
pub fn admit_evidence_capnorm(
    evidence: &SupportingEvidence,
    _ctx: &PinnedSafetyContext,
) -> Result<(), SafetyStoreError> {
    match evidence {
        SupportingEvidence::QcDerived(qc) => {
            check_capnorm(qc.signer_bitmap.capacity(), qc.signer_bitmap.len(), "QC signer_bitmap")?;
            check_capnorm(
                qc.signatures.capacity(),
                qc.signatures.len(),
                "QC signatures descriptor array",
            )?;
            for (i, sig) in qc.signatures.iter().enumerate() {
                check_capnorm(sig.capacity(), sig.len(), &format!("QC signature buffer [{i}]"))?;
            }
        }
        SupportingEvidence::TcDerived { high_qc, tc } => {
            check_capnorm(
                high_qc.signers.capacity(),
                high_qc.signers.len(),
                "record-level high_qc.signers",
            )?;
            check_capnorm(tc.signers.capacity(), tc.signers.len(), "tc.signers")?;
            if let Some(h) = &tc.high_qc {
                check_capnorm(h.signers.capacity(), h.signers.len(), "tc.high_qc.signers")?;
            }
            check_capnorm(
                tc.signed_timeouts.capacity(),
                tc.signed_timeouts.len(),
                "tc.signed_timeouts descriptor array",
            )?;
            for (i, t) in tc.signed_timeouts.iter().enumerate() {
                check_capnorm(
                    t.signature.capacity(),
                    t.signature.len(),
                    &format!("tc.signed_timeouts[{i}].signature"),
                )?;
                if let Some(h) = &t.high_qc {
                    check_capnorm(
                        h.signers.capacity(),
                        h.signers.len(),
                        &format!("tc.signed_timeouts[{i}].high_qc.signers"),
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// A single decoded growable backing passes the capacity-normalization bound iff
/// its `capacity()` is within `len() + CAPNORM_SLACK` elements. Over-bound →
/// refuse (no silent over-capacity retention), naming the offending backing.
fn check_capnorm(capacity: usize, len: usize, what: &str) -> Result<(), SafetyStoreError> {
    let permitted = add(len as u128, CAPNORM_SLACK)?;
    if capacity as u128 > permitted {
        return Err(SafetyStoreError::CapacityRefusal(format!(
            "{what} capacity {capacity} exceeds len {len} + CAPNORM_SLACK {CAPNORM_SLACK} \
             (per-vector capacity-normalization bound)"
        )));
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
pub fn decoded_working_set_charge(
    decoded: &DecodedRecord,
) -> Result<u128, SafetyStoreError> {
    let mut total = size_of_decoded_record_inline();
    if let SafetyRecord::Locked(l) = &decoded.record {
        total = add(total, evidence_backing_capacity(&l.evidence)?)?;
    }
    Ok(total)
}

fn size_of_decoded_record_inline() -> u128 {
    std::mem::size_of::<DecodedRecord>() as u128
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
            return Err(SafetyStoreError::CapacityRefusal(format!(
                "admitting {charge} would raise {}→{} over cap {}",
                self.current, next, self.cap
            )));
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
                    return Err(SafetyStoreError::CapacityRefusal(format!(
                        "aggregate authority already bound to cap {} (attempted {})",
                        existing.cap, cap
                    )));
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
            SafetyStoreError::CapacityRefusal("aggregate authority not bound".into())
        })?;
        let next = add(guard.current, charge)?;
        if next > guard.cap {
            return Err(SafetyStoreError::CapacityRefusal(format!(
                "aggregate admission of {charge} would raise {}→{next} over aggregate cap {}",
                guard.current, guard.cap
            )));
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
                    return Err(SafetyStoreError::CapacityRefusal(format!(
                        "shared accountant already bound to cap {} (attempted {})",
                        existing.cap(),
                        acct.cap()
                    )));
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
                    return Err(SafetyStoreError::CapacityRefusal(format!(
                        "shared context accountant already bound to cap {} (attempted {})",
                        existing.cap(),
                        cap
                    )));
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
                        "shared accountant not bound".into(),
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
                        "shared accountant not bound".into(),
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