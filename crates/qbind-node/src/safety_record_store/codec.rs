//! Run 422 D7-D14 — versioned safety-record encoding and **bounded** decoding
//! (§ 13.2A). Every declared length/count is validated against its pinned bound
//! **before** the application-owned allocation it protects; there is no
//! unbounded generic deserializer followed by a size check. Checked `u128`
//! arithmetic guards every size sum (overflow → refuse).

use sha3::{Digest, Sha3_256};

use super::error::{
    CapField, DecodeDiagnostic, DeclaredBoundDetail, PrefixField, SafetyStoreError,
    StructuralRefusalDetail,
};
use super::profile::{
    max_qc_bytes, max_safety_record_bytes, max_tc_bytes, PinnedSafetyContext, MAX_BITMAP_LEN,
    MAX_SIGNATURE_LEN,
};
use super::record::{
    CommittedAnchor, DecodedRecord, EvidenceDiscriminant, LockedRecord, LogicalQc, SafetyRecord,
    SupportingEvidence, TimeoutCert, TimeoutMessage, WireQc,
};
use crate::storage::signing_journal_crc32;
use qbind_consensus::ids::ValidatorId;

const DOMAIN_BINDING: &[u8] = b"QBIND-D7D14-SAFETY-RECORD-BINDING-v1";

// ---------------------------------------------------------------------------
// Bounded reader
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], SafetyStoreError> {
        if self.remaining() < n {
            return Err(SafetyStoreError::StructuralRefusal(
                StructuralRefusalDetail::Decode(DecodeDiagnostic::Truncated {
                    need: n as u64,
                    have: self.remaining() as u64,
                }),
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, SafetyStoreError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, SafetyStoreError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, SafetyStoreError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, SafetyStoreError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
    fn arr32(&mut self) -> Result<[u8; 32], SafetyStoreError> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }
}

// ---------------------------------------------------------------------------
// Writer helpers
// ---------------------------------------------------------------------------

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Encode a logical QC's identity (`block_id`, `view`, `signers`). Count prefix
/// `C = 2`, each id `W_id = 8`.
fn encode_logical_qc(out: &mut Vec<u8>, qc: &LogicalQc) -> Result<(), SafetyStoreError> {
    out.extend_from_slice(&qc.block_id);
    put_u64(out, qc.view);
    let count = u16::try_from(qc.signers.len()).map_err(|_| {
        SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::PrefixOverflow {
            field: PrefixField::LogicalQcSignerCount,
        })
    })?;
    put_u16(out, count);
    for s in &qc.signers {
        put_u64(out, s.as_u64());
    }
    Ok(())
}

fn decode_logical_qc(
    r: &mut Reader,
    ctx: &PinnedSafetyContext,
) -> Result<LogicalQc, SafetyStoreError> {
    let block_id = r.arr32()?;
    let view = r.u64()?;
    let count = r.u16()? as usize;
    if count > ctx.n() {
        return Err(SafetyStoreError::DeclaredBoundExceeded(
            DeclaredBoundDetail::LogicalQcSignerCount {
                count: count as u128,
                n: ctx.n() as u128,
            },
        ));
    }
    // Bound checked above before allocation.
    let mut signers = Vec::with_capacity(count);
    for _ in 0..count {
        signers.push(ValidatorId::new(r.u64()?));
    }
    Ok(LogicalQc::new(block_id, view, signers))
}

fn encode_wire_qc(out: &mut Vec<u8>, qc: &WireQc) -> Result<(), SafetyStoreError> {
    out.push(qc.version);
    put_u32(out, qc.chain_id);
    put_u64(out, qc.epoch);
    put_u64(out, qc.height);
    put_u64(out, qc.round);
    out.push(qc.step);
    out.extend_from_slice(&qc.block_id);
    put_u16(out, qc.suite_id);
    let bitmap_len = u16::try_from(qc.signer_bitmap.len()).map_err(|_| {
        SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::PrefixOverflow {
            field: PrefixField::SignerBitmapLength,
        })
    })?;
    put_u16(out, bitmap_len);
    out.extend_from_slice(&qc.signer_bitmap);
    let sig_count = u16::try_from(qc.signatures.len()).map_err(|_| {
        SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::PrefixOverflow {
            field: PrefixField::SignatureCount,
        })
    })?;
    put_u16(out, sig_count);
    for sig in &qc.signatures {
        let sl = u16::try_from(sig.len()).map_err(|_| {
            SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::PrefixOverflow {
                field: PrefixField::SignatureLength,
            })
        })?;
        put_u16(out, sl);
        out.extend_from_slice(sig);
    }
    Ok(())
}

fn decode_wire_qc(r: &mut Reader, ctx: &PinnedSafetyContext) -> Result<WireQc, SafetyStoreError> {
    let version = r.u8()?;
    let chain_id = r.u32()?;
    let epoch = r.u64()?;
    let height = r.u64()?;
    let round = r.u64()?;
    let step = r.u8()?;
    let block_id = r.arr32()?;
    let suite_id = r.u16()?;
    let bitmap_len = r.u16()? as u128;
    if bitmap_len > MAX_BITMAP_LEN || bitmap_len > ctx.b_span() {
        return Err(SafetyStoreError::DeclaredBoundExceeded(
            DeclaredBoundDetail::SignerBitmapSpan {
                len: bitmap_len,
                bound: MAX_BITMAP_LEN.min(ctx.b_span()),
            },
        ));
    }
    let signer_bitmap = r.take(bitmap_len as usize)?.to_vec();
    let sig_count = r.u16()? as usize;
    // Structural threshold: an empty-signer certificate cannot meet ceil(2W/3)≥1.
    if sig_count == 0 {
        return Err(SafetyStoreError::StructuralRefusal(
            StructuralRefusalDetail::EmptySignerCertificate,
        ));
    }
    if sig_count > ctx.n() {
        return Err(SafetyStoreError::DeclaredBoundExceeded(
            DeclaredBoundDetail::SignatureCount {
                count: sig_count as u128,
                n: ctx.n() as u128,
            },
        ));
    }
    let mut signatures = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        let sl = r.u16()? as u128;
        if sl > MAX_SIGNATURE_LEN || sl > ctx.s_sig as u128 {
            return Err(SafetyStoreError::DeclaredBoundExceeded(
                DeclaredBoundDetail::SignatureLength {
                    len: sl,
                    s_sig: ctx.s_sig as u128,
                },
            ));
        }
        signatures.push(r.take(sl as usize)?.to_vec());
    }
    Ok(WireQc {
        version,
        chain_id,
        epoch,
        height,
        round,
        step,
        block_id,
        suite_id,
        signer_bitmap,
        signatures,
    })
}

fn encode_timeout_msg(out: &mut Vec<u8>, t: &TimeoutMessage) -> Result<(), SafetyStoreError> {
    put_u64(out, t.view);
    match &t.high_qc {
        None => out.push(0),
        Some(qc) => {
            out.push(1);
            encode_logical_qc(out, qc)?;
        }
    }
    put_u64(out, t.validator_id.as_u64());
    out.push(t.suite_id);
    let sl = u16::try_from(t.signature.len()).map_err(|_| {
        SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::PrefixOverflow {
            field: PrefixField::TimeoutSignatureLength,
        })
    })?;
    put_u16(out, sl);
    out.extend_from_slice(&t.signature);
    Ok(())
}

fn decode_timeout_msg(
    r: &mut Reader,
    ctx: &PinnedSafetyContext,
) -> Result<TimeoutMessage, SafetyStoreError> {
    let view = r.u64()?;
    let high_qc = match r.u8()? {
        0 => None,
        1 => Some(decode_logical_qc(r, ctx)?),
        other => {
            return Err(SafetyStoreError::StructuralRefusal(
                StructuralRefusalDetail::Decode(
                    DecodeDiagnostic::InvalidTimeoutHighQcDiscriminant(other),
                ),
            ))
        }
    };
    let validator_id = ValidatorId::new(r.u64()?);
    let suite_id = r.u8()?;
    let sl = r.u16()? as u128;
    if sl > MAX_SIGNATURE_LEN || sl > ctx.s_sig as u128 {
        return Err(SafetyStoreError::DeclaredBoundExceeded(
            DeclaredBoundDetail::TimeoutSignatureLength {
                len: sl,
                s_sig: ctx.s_sig as u128,
            },
        ));
    }
    let signature = r.take(sl as usize)?.to_vec();
    Ok(TimeoutMessage {
        view,
        high_qc,
        validator_id,
        suite_id,
        signature,
    })
}

fn encode_timeout_cert(out: &mut Vec<u8>, tc: &TimeoutCert) -> Result<(), SafetyStoreError> {
    put_u64(out, tc.view);
    put_u64(out, tc.timeout_view);
    match &tc.high_qc {
        None => out.push(0),
        Some(qc) => {
            out.push(1);
            encode_logical_qc(out, qc)?;
        }
    }
    let signer_count = u16::try_from(tc.signers.len()).map_err(|_| {
        SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::PrefixOverflow {
            field: PrefixField::TcSignerCount,
        })
    })?;
    put_u16(out, signer_count);
    for s in &tc.signers {
        put_u64(out, s.as_u64());
    }
    let st_count = u16::try_from(tc.signed_timeouts.len()).map_err(|_| {
        SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::PrefixOverflow {
            field: PrefixField::SignedTimeoutsCount,
        })
    })?;
    put_u16(out, st_count);
    for t in &tc.signed_timeouts {
        encode_timeout_msg(out, t)?;
    }
    Ok(())
}

fn decode_timeout_cert(
    r: &mut Reader,
    ctx: &PinnedSafetyContext,
) -> Result<TimeoutCert, SafetyStoreError> {
    let view = r.u64()?;
    let timeout_view = r.u64()?;
    let high_qc = match r.u8()? {
        0 => None,
        1 => Some(decode_logical_qc(r, ctx)?),
        other => {
            return Err(SafetyStoreError::StructuralRefusal(
                StructuralRefusalDetail::Decode(DecodeDiagnostic::InvalidTcHighQcDiscriminant(
                    other,
                )),
            ))
        }
    };
    let signer_count = r.u16()? as usize;
    if signer_count > ctx.n() {
        return Err(SafetyStoreError::DeclaredBoundExceeded(
            DeclaredBoundDetail::TcSignerCount {
                count: signer_count as u128,
                n: ctx.n() as u128,
            },
        ));
    }
    let mut signers = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        signers.push(ValidatorId::new(r.u64()?));
    }
    let st_count = r.u16()? as usize;
    if st_count > ctx.n() {
        return Err(SafetyStoreError::DeclaredBoundExceeded(
            DeclaredBoundDetail::SignedTimeoutsCount {
                count: st_count as u128,
                n: ctx.n() as u128,
            },
        ));
    }
    let mut signed_timeouts = Vec::with_capacity(st_count);
    for _ in 0..st_count {
        signed_timeouts.push(decode_timeout_msg(r, ctx)?);
    }
    Ok(TimeoutCert {
        view,
        high_qc,
        signers,
        signed_timeouts,
        timeout_view,
    })
}

// ---------------------------------------------------------------------------
// Evidence binding digest
// ---------------------------------------------------------------------------

/// Compute `evidence_lock_binding` = SHA3-256 over
/// {`lock_block_id`, `lock_view`, `supporting_certificate`, `authority_context_ref`}
/// using the encoded supporting-certificate bytes (§ 13.2).
///
/// This is a **context-checking entry point**: the pinned context is required so
/// that the single authoritative structural admission ([`admit_supporting_evidence`])
/// runs **before** the component-owned `cert` scratch is allocated or any
/// evidence byte is copied into it. A public caller therefore cannot bypass
/// admission by invoking the binding helper directly with over-bound evidence —
/// an over-bound count/length/width (e.g. `S_sig = 8` with a 9-byte signature,
/// or a nested logical high-QC signer list exceeding `N`) is refused here before
/// the allocation, not after the buffer is already owned.
pub fn compute_evidence_lock_binding(
    lock_block_id: &[u8; 32],
    lock_view: u64,
    evidence: &SupportingEvidence,
    authority_context_ref: &[u8; 32],
    ctx: &PinnedSafetyContext,
) -> Result<[u8; 32], SafetyStoreError> {
    // Admit the evidence structure against the pinned context BEFORE allocating
    // the `cert` buffer or copying any variable-size evidence bytes into it.
    admit_supporting_evidence(evidence, ctx)?;
    // Bounded allocation/write path (§ 13.7A, D7-D14 item-6 correction): pre-size
    // the `cert` scratch to the evidence variant's admitted serialized cap (a safe
    // upper bound on the evidence payload, which is strictly smaller than a full
    // record). Admission above has bounded every count/length/width, so the
    // payload fits and the backing never grows by implicit doubling past the bound
    // the way `Vec::new()` + `extend_from_slice` would.
    let cert_cap = match evidence {
        SupportingEvidence::QcDerived(_) => max_qc_bytes(ctx)?,
        SupportingEvidence::TcDerived { .. } => max_tc_bytes(ctx)?,
    };
    let cert_cap = usize::try_from(cert_cap).map_err(|_| {
        SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::CapExceedsUsize {
            field: CapField::EvidenceCertCap,
        })
    })?;
    let mut cert = Vec::with_capacity(cert_cap);
    encode_evidence_payload(&mut cert, evidence)?;
    debug_assert!(
        cert.capacity() == cert_cap,
        "evidence cert backing capacity {} diverged from the admitted cap {cert_cap}",
        cert.capacity()
    );
    // Test-only (RUN 422 D7-D14 M1): record the ACTUAL certificate-binding-phase
    // live object charge while the `cert` scratch is live. Combined with the
    // phase-invariant original-encoded + transient-decoded terms established in
    // `validate_decoded`, this captures the real simultaneously component-owned set
    // at the binding phase (after the re-encode buffer was released). A no-op unless
    // the O3 `read_validate` armed the observation, so O4/public-builder callers of
    // this function never record; never affects production behaviour.
    #[cfg(any(test, feature = "test-utils"))]
    super::owner::observe_o3_binding_object(cert.capacity() as u128);
    let mut h = Sha3_256::new();
    h.update(DOMAIN_BINDING);
    h.update(lock_block_id);
    h.update(lock_view.to_be_bytes());
    h.update((cert.len() as u64).to_be_bytes());
    h.update(&cert);
    h.update(authority_context_ref);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    Ok(out)
}

// Test-only instrumentation counter. It measures **one specific thing**: the
// number of times a supporting-certificate payload is serialized into a
// component-owned `Vec<u8>` on the current thread via [`encode_evidence_payload`].
// That covers exactly two call sites — the evidence-binding `cert` scratch in
// [`compute_evidence_lock_binding`] and the evidence segment of
// [`encode_record`]. It is a boundary marker for *that* allocation/copy path
// only; it is deliberately NOT a total-allocation meter, an operational
// memory-peak gauge, or an admission counter (those live in
// [`super::accounting`] and the admission helpers). A regression can therefore
// prove that a refusal happened before this evidence serialization — not merely
// that the database was unchanged afterward — by asserting the counter is still
// zero after a refused operation. Absent from default production builds (gated
// behind `test-utils`/`test`).
#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static EVIDENCE_PAYLOAD_ENCODES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Test-only: read the current thread's evidence-payload encode counter. It is
/// thread-local because a component operation and the evidence-binding/encode it
/// drives run on the same thread; this keeps the measurement accurate even when
/// the test harness runs many tests in parallel.
#[cfg(any(test, feature = "test-utils"))]
pub fn evidence_payload_encode_count() -> u64 {
    EVIDENCE_PAYLOAD_ENCODES.with(|c| c.get())
}

/// Test-only: reset the current thread's evidence-payload encode counter.
#[cfg(any(test, feature = "test-utils"))]
pub fn reset_evidence_payload_encode_count() {
    EVIDENCE_PAYLOAD_ENCODES.with(|c| c.set(0));
}

fn encode_evidence_payload(
    out: &mut Vec<u8>,
    evidence: &SupportingEvidence,
) -> Result<(), SafetyStoreError> {
    #[cfg(any(test, feature = "test-utils"))]
    EVIDENCE_PAYLOAD_ENCODES.with(|c| c.set(c.get().saturating_add(1)));
    match evidence {
        SupportingEvidence::QcDerived(qc) => encode_wire_qc(out, qc),
        SupportingEvidence::TcDerived { high_qc, tc } => {
            // Record-level `high_qc` presence discriminant `D` (§ 13.2A(e)
            // `REC_HIGH_QC`). A TcDerived record always carries its own logical
            // high-QC copy (TA1), so the discriminant is always `1` here; it is
            // emitted so the serialized layout matches the profile row and so a
            // malformed record with an absent record-level high-QC is refused on
            // decode rather than silently coerced.
            out.push(1);
            encode_logical_qc(out, high_qc)?;
            encode_timeout_cert(out, tc)
        }
    }
}

// ---------------------------------------------------------------------------
// Authoritative structural admission (§ 13.2A / § 13.7)
// ---------------------------------------------------------------------------

/// The one authoritative structural-admission path, applied **before** any
/// encode/publish allocation or copy and mirrored by the bounded decoder. It
/// enforces every profile-defined count/length/width against the pinned context
/// (signer/signature counts, per-signature length `S_sig`, bitmap span, timeout
/// entries, and nested logical high-QC signer counts) with checked arithmetic.
///
/// Checking a length **after** encoding is not allocation prevention; this
/// admission makes the refusal happen before the component owns the buffer. The
/// concrete prior failure case — with `S_sig = 8`, a QC carrying a 9-byte
/// signature — is refused here even when the whole record is below the total
/// serialized cap.
pub fn admit_record_structure(
    rec: &DecodedRecord,
    ctx: &PinnedSafetyContext,
) -> Result<(), SafetyStoreError> {
    match &rec.record {
        SafetyRecord::BootstrapNoLock { .. } => Ok(()),
        SafetyRecord::Locked(l) => admit_supporting_evidence(&l.evidence, ctx),
    }
}

/// Structural admission of a `Locked` record's supporting evidence against the
/// pinned context, applied **before** any component-owned variable-size
/// allocation or copy that depends on those fields — in particular before the
/// evidence-binding `cert` scratch in [`compute_evidence_lock_binding`], before
/// candidate cloning, and before [`encode_record`]'s buffer growth. This is the
/// single admission path reused by every public builder/helper and by O4; there
/// is no second, weaker admission. It covers QC and TC evidence, all nested
/// counts, signature lengths, bitmap spans, the record-level high-QC signer
/// count, and (via the per-field checks) every length prefix and discriminant,
/// all with checked arithmetic. The concrete prior failure case — with
/// `S_sig = 8`, a QC carrying a 9-byte signature — is refused here even when the
/// whole record is below the total serialized cap.
pub fn admit_supporting_evidence(
    evidence: &SupportingEvidence,
    ctx: &PinnedSafetyContext,
) -> Result<(), SafetyStoreError> {
    let n = ctx.n();
    match evidence {
        SupportingEvidence::QcDerived(qc) => admit_wire_qc(qc, ctx),
        SupportingEvidence::TcDerived { high_qc, tc } => {
            admit_logical_qc_signers(
                high_qc.signers.len(),
                n,
                PrefixField::RecordHighQcSignerCount,
                |count, n| DeclaredBoundDetail::HighQcSignerCount { count, n },
            )?;
            admit_timeout_cert(tc, ctx)
        }
    }?;
    // Capacity-aware bounds (§ 13.7 / § 13.7A, D7-D14): the structural checks above
    // bound the declared **lengths**/counts, but a valid-length backing can still
    // own spare capacity. Enforce BOTH the per-vector capacity-normalization bound
    // (`capacity() <= len() + CAPNORM_SLACK` on every individual backing — the
    // smaller per-object violation the aggregate check alone does not catch) AND
    // the aggregate retained-generation ceiling, BEFORE any component-owned clone /
    // binding-scratch / re-encode allocation depends on this (possibly
    // caller-supplied) evidence.
    super::accounting::admit_evidence_capnorm(evidence, ctx)?;
    super::accounting::admit_evidence_capacity(evidence, ctx)
}

fn admit_count_fits_prefix(count: usize, field: PrefixField) -> Result<(), SafetyStoreError> {
    u16::try_from(count).map(|_| ()).map_err(|_| {
        SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::PrefixOverflow { field })
    })
}

fn admit_logical_qc_signers(
    count: usize,
    n: usize,
    prefix: PrefixField,
    mk: impl Fn(u128, u128) -> DeclaredBoundDetail,
) -> Result<(), SafetyStoreError> {
    admit_count_fits_prefix(count, prefix)?;
    if count > n {
        return Err(SafetyStoreError::DeclaredBoundExceeded(mk(
            count as u128,
            n as u128,
        )));
    }
    Ok(())
}

fn admit_wire_qc(qc: &WireQc, ctx: &PinnedSafetyContext) -> Result<(), SafetyStoreError> {
    let bitmap_len = qc.signer_bitmap.len() as u128;
    admit_count_fits_prefix(qc.signer_bitmap.len(), PrefixField::SignerBitmapLength)?;
    if bitmap_len > MAX_BITMAP_LEN || bitmap_len > ctx.b_span() {
        return Err(SafetyStoreError::DeclaredBoundExceeded(
            DeclaredBoundDetail::SignerBitmapSpan {
                len: bitmap_len,
                bound: MAX_BITMAP_LEN.min(ctx.b_span()),
            },
        ));
    }
    // Structural threshold: an empty-signer certificate cannot meet ceil(2W/3)≥1.
    if qc.signatures.is_empty() {
        return Err(SafetyStoreError::StructuralRefusal(
            StructuralRefusalDetail::EmptySignerCertificate,
        ));
    }
    admit_count_fits_prefix(qc.signatures.len(), PrefixField::SignatureCount)?;
    if qc.signatures.len() > ctx.n() {
        return Err(SafetyStoreError::DeclaredBoundExceeded(
            DeclaredBoundDetail::SignatureCount {
                count: qc.signatures.len() as u128,
                n: ctx.n() as u128,
            },
        ));
    }
    for sig in &qc.signatures {
        let sl = sig.len() as u128;
        admit_count_fits_prefix(sig.len(), PrefixField::SignatureLength)?;
        if sl > MAX_SIGNATURE_LEN || sl > ctx.s_sig as u128 {
            return Err(SafetyStoreError::DeclaredBoundExceeded(
                DeclaredBoundDetail::SignatureLength {
                    len: sl,
                    s_sig: ctx.s_sig as u128,
                },
            ));
        }
    }
    Ok(())
}

fn admit_timeout_cert(tc: &TimeoutCert, ctx: &PinnedSafetyContext) -> Result<(), SafetyStoreError> {
    let n = ctx.n();
    admit_logical_qc_signers(
        tc.signers.len(),
        n,
        PrefixField::TcSignerCount,
        |count, n| DeclaredBoundDetail::TcSignerCount { count, n },
    )?;
    if let Some(h) = &tc.high_qc {
        admit_logical_qc_signers(
            h.signers.len(),
            n,
            PrefixField::TcHighQcSignerCount,
            |count, n| DeclaredBoundDetail::HighQcSignerCount { count, n },
        )?;
    }
    admit_count_fits_prefix(tc.signed_timeouts.len(), PrefixField::SignedTimeoutsCount)?;
    if tc.signed_timeouts.len() > n {
        return Err(SafetyStoreError::DeclaredBoundExceeded(
            DeclaredBoundDetail::SignedTimeoutsCount {
                count: tc.signed_timeouts.len() as u128,
                n: n as u128,
            },
        ));
    }
    for t in &tc.signed_timeouts {
        if let Some(h) = &t.high_qc {
            admit_logical_qc_signers(
                h.signers.len(),
                n,
                PrefixField::SignedTimeoutHighQcSignerCount,
                |count, n| DeclaredBoundDetail::HighQcSignerCount { count, n },
            )?;
        }
        let sl = t.signature.len() as u128;
        admit_count_fits_prefix(t.signature.len(), PrefixField::TimeoutSignatureLength)?;
        if sl > MAX_SIGNATURE_LEN || sl > ctx.s_sig as u128 {
            return Err(SafetyStoreError::DeclaredBoundExceeded(
                DeclaredBoundDetail::TimeoutSignatureLength {
                    len: sl,
                    s_sig: ctx.s_sig as u128,
                },
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Record encode / decode
// ---------------------------------------------------------------------------

/// Serialize a decoded record to its persistence bytes (§ 13.2A layout, F = 0,
/// CRC32 trailer over all preceding bytes).
pub fn encode_record(
    rec: &DecodedRecord,
    ctx: &PinnedSafetyContext,
) -> Result<Vec<u8>, SafetyStoreError> {
    // Authoritative structural admission BEFORE building/copying any buffer
    // (§ 13.2A / § 13.7): refuse an over-bound count/length/width here rather
    // than after encoding.
    admit_record_structure(rec, ctx)?;
    // Bounded allocation/write path (§ 13.7A, D7-D14 item-6 correction): pre-size
    // the output backing to the variant's admitted serialized cap and write into
    // it. Because `admit_record_structure` has already bounded every count/length/
    // width to its profile maximum, the encoded content is guaranteed `<= cap`, so
    // `Vec::with_capacity(cap)` never reallocates and the backing stays at the one
    // admitted allocation — it cannot grow by implicit doubling past the bound the
    // way `Vec::new()` + `extend_from_slice` would. The final `len() > cap` check
    // below remains the content bound; the capacity confirmation is a secondary
    // check, NOT the prevention mechanism.
    let cap = encoded_record_cap(rec, ctx)?;
    let cap_usize = usize::try_from(cap).map_err(|_| {
        SafetyStoreError::DeclaredBoundExceeded(DeclaredBoundDetail::CapExceedsUsize {
            field: CapField::RecordCap,
        })
    })?;
    let mut out = Vec::with_capacity(cap_usize);
    put_u16(&mut out, rec.persistence_format_version);
    out.extend_from_slice(&rec.network_genesis_id);

    match &rec.record {
        SafetyRecord::BootstrapNoLock {
            authority_context_ref,
            predecessor_ref,
        } => {
            out.extend_from_slice(authority_context_ref);
            out.push(EvidenceDiscriminant::Bootstrap as u8); // D_ev
            out.push(0); // D_ca always 0 for bootstrap
            out.push(if predecessor_ref.is_some() { 1 } else { 0 }); // D_pred
            put_u64(&mut out, rec.publication_revision);
            if let Some(p) = predecessor_ref {
                put_u64(&mut out, *p);
            }
        }
        SafetyRecord::Locked(l) => {
            out.extend_from_slice(&l.authority_context_ref);
            let d_ev = match &l.evidence {
                SupportingEvidence::QcDerived(_) => EvidenceDiscriminant::QcDerived,
                SupportingEvidence::TcDerived { .. } => EvidenceDiscriminant::TcDerived,
            };
            out.push(d_ev as u8);
            out.push(if l.committed_anchor.is_some() { 1 } else { 0 }); // D_ca
            out.push(if l.predecessor_ref.is_some() { 1 } else { 0 }); // D_pred
            put_u64(&mut out, rec.publication_revision);
            out.extend_from_slice(&l.lock_block_id);
            put_u64(&mut out, l.lock_view);
            out.extend_from_slice(&l.evidence_lock_binding);
            encode_evidence_payload(&mut out, &l.evidence)?;
            if let Some(a) = &l.committed_anchor {
                out.extend_from_slice(&a.block_id);
                put_u64(&mut out, a.height);
            }
            if let Some(p) = l.predecessor_ref {
                put_u64(&mut out, p);
            }
        }
    }

    let crc = signing_journal_crc32(&out);
    out.extend_from_slice(&crc.to_be_bytes());

    // Enforce the variant-specific serialized cap on the final actual length.
    let actual = out.len() as u128;
    if actual > cap {
        return Err(SafetyStoreError::Oversize {
            len: actual,
            max: cap,
        });
    }
    // Confirmation (NOT the prevention mechanism): the pre-sized backing never
    // grew past the admitted cap. `Vec::with_capacity(cap)` may round the request
    // up, so we confirm against the requested `cap_usize`, below which no implicit
    // doubling occurred.
    debug_assert!(
        out.capacity() == cap_usize,
        "encode backing capacity {} diverged from the admitted cap {cap_usize}",
        out.capacity()
    );
    Ok(out)
}

/// The variant-specific admitted serialized cap for a record (§ 13.2A): the same
/// bound the final `encode_record` length check enforces, hoisted so the output
/// backing can be pre-sized to it for the bounded allocation/write path.
fn encoded_record_cap(
    rec: &DecodedRecord,
    ctx: &PinnedSafetyContext,
) -> Result<u128, SafetyStoreError> {
    match &rec.record {
        SafetyRecord::BootstrapNoLock { .. } => max_safety_record_bytes(ctx),
        SafetyRecord::Locked(l) => match &l.evidence {
            SupportingEvidence::QcDerived(_) => max_qc_bytes(ctx),
            SupportingEvidence::TcDerived { .. } => max_tc_bytes(ctx),
        },
    }
}

/// Decode and structurally validate (stage 1) a persistence buffer into a
/// `DecodedRecord`. Bounds/counts are checked against the pinned context before
/// any application-owned allocation; CRC32 and version are gated first.
pub fn decode_record(
    buf: &[u8],
    ctx: &PinnedSafetyContext,
) -> Result<DecodedRecord, SafetyStoreError> {
    // Pre-discriminant cross-variant size gate.
    let cross_cap = max_safety_record_bytes(ctx)?;
    if buf.len() as u128 > cross_cap {
        return Err(SafetyStoreError::Oversize {
            len: buf.len() as u128,
            max: cross_cap,
        });
    }
    if buf.len() < 4 + 2 {
        return Err(SafetyStoreError::StructuralRefusal(
            StructuralRefusalDetail::Static("record too short"),
        ));
    }
    // CRC32 over all preceding bytes.
    let (body, crc_bytes) = buf.split_at(buf.len() - 4);
    let stored_crc = u32::from_be_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
    if signing_journal_crc32(body) != stored_crc {
        return Err(SafetyStoreError::StructuralRefusal(StructuralRefusalDetail::Static("CRC32 mismatch")));
    }

    let mut r = Reader::new(body);
    let version = r.u16()?;
    if version != super::profile::SAFETY_PERSISTENCE_FORMAT_VERSION {
        return Err(SafetyStoreError::UnsupportedVersion(version));
    }
    let network_genesis_id = r.arr32()?;
    let authority_context_ref = r.arr32()?;
    let d_ev = r.u8()?;
    let d_ca = r.u8()?;
    let d_pred = r.u8()?;
    let publication_revision = r.u64()?;

    let record = match d_ev {
        x if x == EvidenceDiscriminant::Bootstrap as u8 => {
            if d_ca != 0 {
                return Err(SafetyStoreError::StructuralRefusal(
                    StructuralRefusalDetail::Static("bootstrap record must not carry a committed anchor"),
                ));
            }
            let predecessor_ref = read_optional_predecessor(&mut r, d_pred)?;
            SafetyRecord::BootstrapNoLock {
                authority_context_ref,
                predecessor_ref,
            }
        }
        x if x == EvidenceDiscriminant::QcDerived as u8 => {
            let lock_block_id = r.arr32()?;
            let lock_view = r.u64()?;
            let evidence_lock_binding = r.arr32()?;
            let qc = decode_wire_qc(&mut r, ctx)?;
            let committed_anchor = read_optional_anchor(&mut r, d_ca)?;
            let predecessor_ref = read_optional_predecessor(&mut r, d_pred)?;
            SafetyRecord::Locked(LockedRecord {
                lock_block_id,
                lock_view,
                evidence_lock_binding,
                authority_context_ref,
                committed_anchor,
                predecessor_ref,
                evidence: SupportingEvidence::QcDerived(qc),
            })
        }
        x if x == EvidenceDiscriminant::TcDerived as u8 => {
            let lock_block_id = r.arr32()?;
            let lock_view = r.u64()?;
            let evidence_lock_binding = r.arr32()?;
            // Record-level `high_qc` presence discriminant `D` (§ 13.2A(e)).
            // A TcDerived record requires a carried record-level high-QC (TA1);
            // an absent/unknown discriminant is refused, never coerced.
            let high_qc = match r.u8()? {
                1 => decode_logical_qc(&mut r, ctx)?,
                0 => {
                    return Err(SafetyStoreError::StructuralRefusal(
                        StructuralRefusalDetail::Static(
                        "tc-derived record requires a carried record-level high_qc (TA1)",
                    ),
                    ))
                }
                other => {
                    return Err(SafetyStoreError::StructuralRefusal(
                        StructuralRefusalDetail::Decode(
                            DecodeDiagnostic::InvalidRecordHighQcDiscriminant(other),
                        ),
                    ))
                }
            };
            let tc = decode_timeout_cert(&mut r, ctx)?;
            let committed_anchor = read_optional_anchor(&mut r, d_ca)?;
            let predecessor_ref = read_optional_predecessor(&mut r, d_pred)?;
            SafetyRecord::Locked(LockedRecord {
                lock_block_id,
                lock_view,
                evidence_lock_binding,
                authority_context_ref,
                committed_anchor,
                predecessor_ref,
                evidence: SupportingEvidence::TcDerived { high_qc, tc },
            })
        }
        other => {
            return Err(SafetyStoreError::StructuralRefusal(
                StructuralRefusalDetail::Decode(DecodeDiagnostic::UnknownEvidenceDiscriminant(
                    other,
                )),
            ))
        }
    };

    if r.remaining() != 0 {
        return Err(SafetyStoreError::StructuralRefusal(
            StructuralRefusalDetail::Decode(DecodeDiagnostic::TrailingBytes {
                have: r.remaining() as u64,
            }),
        ));
    }

    Ok(DecodedRecord {
        persistence_format_version: version,
        network_genesis_id,
        publication_revision,
        record,
    })
}

fn read_optional_anchor(
    r: &mut Reader,
    d_ca: u8,
) -> Result<Option<CommittedAnchor>, SafetyStoreError> {
    match d_ca {
        0 => Ok(None),
        1 => {
            let block_id = r.arr32()?;
            let height = r.u64()?;
            Ok(Some(CommittedAnchor { block_id, height }))
        }
        other => Err(SafetyStoreError::StructuralRefusal(
            StructuralRefusalDetail::Decode(DecodeDiagnostic::InvalidCommittedAnchorDiscriminant(
                other,
            )),
        )),
    }
}

fn read_optional_predecessor(r: &mut Reader, d_pred: u8) -> Result<Option<u64>, SafetyStoreError> {
    match d_pred {
        0 => Ok(None),
        1 => Ok(Some(r.u64()?)),
        other => Err(SafetyStoreError::StructuralRefusal(
            StructuralRefusalDetail::Decode(DecodeDiagnostic::InvalidPredecessorDiscriminant(
                other,
            )),
        )),
    }
}

/// Convenience: the evidence discriminant of a decoded record.
pub fn evidence_discriminant_of(buf: &[u8]) -> Option<EvidenceDiscriminant> {
    // version(2) + genesis(32) + authctx(32) = 66, then D_ev.
    let idx = 2 + 32 + 32;
    match buf.get(idx)? {
        0 => Some(EvidenceDiscriminant::Bootstrap),
        1 => Some(EvidenceDiscriminant::QcDerived),
        2 => Some(EvidenceDiscriminant::TcDerived),
        _ => None,
    }
}

/// Source/test-only: expose the record CRC-32 over a body so tests can re-seal a
/// mutated buffer. Never used by production code paths.
pub fn record_crc32_for_test(body: &[u8]) -> u32 {
    signing_journal_crc32(body)
}