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
    VALIDATOR_ID_WIDTH,
};
use super::record::{
    size_of_retained_generation, size_of_timeout_msg, RetainedGeneration, SupportingEvidence,
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
    let mut total = size_of_retained_generation();
    // Heap backings depend on the evidence variant.
    match &gen.evidence {
        SupportingEvidence::QcDerived(qc) => {
            // signer_bitmap backing + signatures outer descriptor + per-sig bytes.
            total = add(total, qc.signer_bitmap.capacity() as u128)?;
            total = add(total, mul(qc.signatures.len() as u128, 24)?)?; // Vec<u8> descriptor
            for sig in &qc.signatures {
                total = add(total, sig.capacity() as u128)?;
            }
        }
        SupportingEvidence::TcDerived { high_qc, tc } => {
            total = add(
                total,
                mul(high_qc.signers.len() as u128, VALIDATOR_ID_WIDTH)?,
            )?;
            total = add(total, mul(tc.signers.len() as u128, VALIDATOR_ID_WIDTH)?)?;
            if let Some(h) = &tc.high_qc {
                total = add(total, mul(h.signers.len() as u128, VALIDATOR_ID_WIDTH)?)?;
            }
            total = add(
                total,
                mul(tc.signed_timeouts.len() as u128, size_of_timeout_msg())?,
            )?;
            for t in &tc.signed_timeouts {
                total = add(total, t.signature.capacity() as u128)?;
                if let Some(h) = &t.high_qc {
                    total = add(total, mul(h.signers.len() as u128, VALIDATOR_ID_WIDTH)?)?;
                }
            }
        }
    }
    // Shared allocation overhead charged once per retained generation.
    total = add(total, ARC_CTRL)?;

    let cap = max_retained_generation_bytes(ctx, size_of_timeout_msg())?;
    if total > cap {
        return Err(SafetyStoreError::DeclaredBoundExceeded(format!(
            "generation charge {total} exceeds MAX_RETAINED_GENERATION_BYTES {cap}"
        )));
    }
    Ok(total)
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
/// context — must also be admitted here first. Because the aggregate ceiling is
/// bound to `operational_sub_cap + context_sub_cap`, the live operational and
/// context charges can never *jointly* exceed the accepted aggregate, and a
/// concurrent operation + attachment cannot admit against two independent
/// ceilings whose sum would exceed the permitted coexistence budget.
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
/// aggregate ceiling as well as its own sub-cap (§ 13.7, finding #4).
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