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
#[derive(Clone, Debug)]
pub struct SharedAccountant {
    inner: Arc<Mutex<Option<AllocationAccountant>>>,
}

impl Default for SharedAccountant {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedAccountant {
    /// A fresh, unbound shared accountant (no ceiling until [`SharedAccountant::bind`]).
    pub fn new() -> Self {
        SharedAccountant {
            inner: Arc::new(Mutex::new(None)),
        }
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

    /// The configured aggregate ceiling, or `None` when not yet bound.
    pub fn cap(&self) -> Option<u128> {
        self.lock().as_ref().map(|a| a.cap())
    }
    /// The current shared charged total (0 when unbound).
    pub fn current(&self) -> u128 {
        self.lock().as_ref().map(|a| a.current()).unwrap_or(0)
    }
    /// The observed shared peak charged total (0 when unbound).
    pub fn peak(&self) -> u128 {
        self.lock().as_ref().map(|a| a.peak()).unwrap_or(0)
    }

    /// Admit `charge` bytes against the shared ceiling **before** the protected
    /// allocation or copy. On success returns an RAII [`Reservation`] that holds
    /// the charge until it is dropped (or explicitly released). Refuses with
    /// [`SafetyStoreError::CapacityRefusal`] when the charge would exceed the
    /// shared ceiling — without disturbing any already-admitted charge.
    pub fn reserve(&self, charge: u128) -> Result<Reservation, SafetyStoreError> {
        {
            let mut g = self.lock();
            let acct = g.as_mut().ok_or_else(|| {
                SafetyStoreError::CapacityRefusal("shared accountant not bound".into())
            })?;
            acct.admit(charge)?;
        }
        Ok(Reservation {
            inner: Arc::clone(&self.inner),
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
/// it is never evidence that a durable write was undone.
#[derive(Debug)]
pub struct Reservation {
    inner: Arc<Mutex<Option<AllocationAccountant>>>,
    charge: u128,
    released: bool,
}

impl Reservation {
    /// The charged quantity this reservation holds.
    pub fn charge(&self) -> u128 {
        self.charge
    }

    /// Reserve an **additional** holder of the same charge against the same
    /// shared accountant. Used when a charged retained proof is duplicated: a
    /// clone owns a genuinely separate record-sized buffer, so it must take its
    /// own reservation rather than aliasing one — repeated cloning therefore
    /// cannot produce unbounded uncharged holders, and exhausting the shared
    /// budget refuses the duplication.
    pub fn try_duplicate(&self) -> Result<Reservation, SafetyStoreError> {
        {
            let mut g = self.inner.lock().expect("safety accountant poisoned");
            let acct = g.as_mut().ok_or_else(|| {
                SafetyStoreError::CapacityRefusal("shared accountant not bound".into())
            })?;
            acct.admit(self.charge)?;
        }
        Ok(Reservation {
            inner: Arc::clone(&self.inner),
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
            self.released = true;
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.do_release();
    }
}