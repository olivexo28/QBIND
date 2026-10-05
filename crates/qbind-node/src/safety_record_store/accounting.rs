//! Run 422 D7-D14 — executable component-level allocation **admission and
//! accounting** (§ 13.7 / § 13.7A / § 13.7B).
//!
//! Every charge is computed with checked `u128` arithmetic and admitted against
//! the aggregate ceiling **before** the application-owned allocation it
//! represents. Releasing a charge is in-memory accounting bookkeeping only; it
//! is never treated as proof that a durable storage write was rolled back.

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
