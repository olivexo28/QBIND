//! Run 422 D7-D14 — pinned profile parameters, independent context, and the
//! checked serialized / decoded size bounds (§ 13.2A, § 13.7A, § 13.7B of
//! `QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`).
//!
//! Every constant here is a **pinned profile parameter** — fixed before any
//! encode/decode, validated against the independently-supplied context, and
//! **never** read as policy from an untrusted record. The serialized caps
//! (`MAX_SAFETY_RECORD_BYTES`) are kept strictly distinct from the
//! decoded-generation in-memory caps (`MAX_RETAINED_GENERATION_BYTES`,
//! `MAX_AGGREGATE_RETAINED_BYTES`); no decoded-memory bound is ever inferred
//! from a serialized length.

use qbind_consensus::ids::ValidatorId;

use super::error::SafetyStoreError;

/// Supported persistence-format version (§ 13.2, `persistence_format_version`).
///
/// Distinct from the wire-message version, the signing-domain/preimage version,
/// and D10's `SIGNING_RECORD_FORMAT_VERSION` / `SIGNING_METADATA_FORMAT_VERSION`.
pub const SAFETY_PERSISTENCE_FORMAT_VERSION: u16 = 1;

/// Width of every length/count prefix in this profile (§ 13.2A(a), `C`).
pub const PREFIX_WIDTH_C: u128 = 2;
/// Encoded width of a `ValidatorId` in the persisted logical form (`W_id`).
pub const VALIDATOR_ID_WIDTH: u128 = 8;
/// Width of a one-byte discriminant / option / variant tag (`D`).
pub const DISCRIMINANT_WIDTH: u128 = 1;

/// Structural over-read guard only (§ 13.2A): `MAX_SIGNATURE_COUNT` bound.
pub const MAX_SIGNATURE_COUNT: u128 = u16::MAX as u128;
/// Structural over-read guard only (§ 13.2A): per-signature byte bound.
pub const MAX_SIGNATURE_LEN: u128 = u16::MAX as u128;
/// Signer-bitmap identifier-span bound reused from `qc_verify_domain` (§ 13.2A).
pub const MAX_BITMAP_LEN: u128 = 8192;

/// Named fixed overhead of the `Locked` serialized record (§ 13.2A(b)):
/// `2 + 32 + 32 + 32 + 8 + 32 + 8 + 4 + 1 + 1 + 1 + 0 = 153`.
pub const FIXED_OVERHEAD: u128 = 153;

/// `QC_FIXED` subtotal (§ 13.2A(d)): `1+4+8+8+8+1+32+2 = 64`.
pub const QC_FIXED: u128 = 64;

/// Proposed ceiling for the single whole-enum decoded wrapper (§ 13.7A(c),
/// Rust-layout correction). Measured and enforced by a compile-time assertion in
/// [`super::record`]; if the measured size exceeds this ceiling the discrepancy
/// is surfaced, never concealed.
pub const GEN_STRUCT_MAX: u128 = 384;

/// `ARC_CTRL` shared-allocation overhead on the 64-bit profile (§ 13.7A(c.6)):
/// `2 × size_of::<AtomicUsize>()` header + `0` padding = 16 B.
pub const ARC_CTRL: u128 = 16;

/// Initial-profile concurrency / capacity limits (§ 13.7 / § 13.7B).
pub const MAX_OUTSTANDING_PREPARED_L0: u128 = 2;
pub const MAX_CONCURRENT_CANDIDATES: u128 = 1;
pub const MAX_CONCURRENT_PUBLICATIONS: u128 = 1;
/// Initial-profile capacity-normalization slack, in **elements** (§ 13.7).
pub const CAPNORM_SLACK: u128 = 0;

/// The independently-supplied, pinned genesis / validator / authority context.
///
/// Obtained from the boot-time pinned genesis identity and the authorized-epoch
/// validator set — **never** trusted from the record's own claim. The record
/// stores identifiers that are *compared* against this context (§ 13.2 / P4).
#[derive(Debug, Clone)]
pub struct PinnedSafetyContext {
    /// Boot-time pinned genesis identity (`network_genesis_id`).
    pub network_genesis_id: [u8; 32],
    /// Authorized-epoch validator-set descriptor digest (`authority_context_ref`).
    pub authority_context_ref: [u8; 32],
    /// Chain id the authorized context interprets certificates under.
    pub chain_id: u32,
    /// Authorized epoch.
    pub epoch: u64,
    /// Consensus (QC) signature suite id.
    pub qc_suite_id: u16,
    /// Timeout signature suite id.
    pub timeout_suite_id: u8,
    /// Per-signature byte length pinned by the suite (`S_sig`).
    pub s_sig: usize,
    /// The authorized-epoch validator set as `(id, voting_power)`, indices
    /// contiguous `0..N-1` (dense-index profile).
    pub validators: Vec<(ValidatorId, u64)>,
    /// Explicit, opt-in profile choice requiring the wire QC's `height == round`
    /// (§ 13.3A). This is an **additional** profile constraint and is never
    /// silently conflated with the P2 logical-view binding (`height == lock_view`),
    /// which is always enforced regardless of this flag.
    pub require_height_equals_round: bool,
}

impl PinnedSafetyContext {
    /// `N` — the pinned authorized-epoch validator/member **count**.
    pub fn n(&self) -> usize {
        self.validators.len()
    }

    /// Is `id` an authorized member of the pinned set?
    pub fn is_member(&self, id: ValidatorId) -> bool {
        self.validators.iter().any(|(v, _)| *v == id)
    }

    /// Voting power of `id`, or `None` if non-member.
    pub fn voting_power(&self, id: ValidatorId) -> Option<u64> {
        self.validators
            .iter()
            .find(|(v, _)| *v == id)
            .map(|(_, p)| *p)
    }

    /// Total voting power `W` (checked `u128`).
    pub fn total_voting_power(&self) -> u128 {
        self.validators.iter().map(|(_, p)| *p as u128).sum()
    }

    /// `ceil(2W/3)` computed in `u128` (§ 13.3A / § 13.2A reuse).
    pub fn two_thirds_vp(&self) -> u128 {
        let total = self.total_voting_power();
        // ceil(2 * total / 3)
        (2 * total).div_ceil(3)
    }

    /// Validate the pinned profile parameters are self-consistent and within the
    /// structural bounds before any encode/decode uses them.
    pub fn validate(&self) -> Result<(), SafetyStoreError> {
        let n = self.n() as u128;
        if n == 0 || n > MAX_SIGNATURE_COUNT {
            return Err(SafetyStoreError::ProfileInvalid(format!(
                "validator count {n} out of range 1..={MAX_SIGNATURE_COUNT}"
            )));
        }
        let s = self.s_sig as u128;
        if s == 0 || s > MAX_SIGNATURE_LEN {
            return Err(SafetyStoreError::ProfileInvalid(format!(
                "s_sig {s} out of range 1..={MAX_SIGNATURE_LEN}"
            )));
        }
        // Dense-index profile: ids must be contiguous 0..N-1.
        for (idx, (id, _)) in self.validators.iter().enumerate() {
            if id.as_u64() != idx as u64 {
                return Err(SafetyStoreError::ProfileInvalid(format!(
                    "non-dense validator index at slot {idx}: id={}",
                    id.as_u64()
                )));
            }
        }
        if self.total_voting_power() == 0 {
            return Err(SafetyStoreError::ProfileInvalid(
                "total voting power is zero".to_string(),
            ));
        }
        Ok(())
    }

    /// `B_span` — the signer-bitmap identifier span in bytes under the
    /// established dense-index profile: `ceil(N/8)` (§ 13.2A(a)).
    pub fn b_span(&self) -> u128 {
        (self.n() as u128).div_ceil(8)
    }
}

/// Checked addition helper (overflow → refuse).
fn add(a: u128, b: u128) -> Result<u128, SafetyStoreError> {
    a.checked_add(b)
        .ok_or_else(|| SafetyStoreError::ArithmeticOverflow("size sum".to_string()))
}

/// Checked multiplication helper (overflow → refuse).
fn mul(a: u128, b: u128) -> Result<u128, SafetyStoreError> {
    a.checked_mul(b)
        .ok_or_else(|| SafetyStoreError::ArithmeticOverflow("size product".to_string()))
}

/// `MAX_QC_BYTES = 269 + B_span + N × (2 + S_sig)` at `C = 2` (§ 13.2A(f)).
pub fn max_qc_bytes(ctx: &PinnedSafetyContext) -> Result<u128, SafetyStoreError> {
    let n = ctx.n() as u128;
    let s = ctx.s_sig as u128;
    // FIXED_OVERHEAD(153) + anchor(40) + predecessor(8) + QC_FIXED(64)
    //   + bitmap-length prefix(2) + signatures-count prefix(2) + B_span
    //   + N × (C + S_sig)
    let base = add(
        add(add(add(FIXED_OVERHEAD, 40)?, 8)?, QC_FIXED)?,
        add(2, 2)?,
    )?; // 269
    let per_sig = mul(n, add(PREFIX_WIDTH_C, s)?)?;
    add(add(base, ctx.b_span())?, per_sig)
}

/// `MAX_TC_BYTES = FIXED_OVERHEAD + [40+8] + REC_HIGH_QC + TC_VIEW + TC_TIMEOUT_VIEW
/// + TC_HIGH_QC + TC_SIGNERS + SIGNED_TIMEOUTS` (§ 13.2A(f)); `D_ev` is already in
/// `FIXED_OVERHEAD` and is **not** re-added.
pub fn max_tc_bytes(ctx: &PinnedSafetyContext) -> Result<u128, SafetyStoreError> {
    let n = ctx.n() as u128;
    let s = ctx.s_sig as u128;
    // REC_HIGH_QC = D + 32 + 8 + (C + N × W_id)
    let rec_high_qc = add(
        add(add(DISCRIMINANT_WIDTH, 40)?, PREFIX_WIDTH_C)?,
        mul(n, VALIDATOR_ID_WIDTH)?,
    )?;
    // TC_HIGH_QC = D + [32 + 8 + (C + N × W_id)] (same shape as REC_HIGH_QC)
    let tc_high_qc = rec_high_qc;
    // TC_SIGNERS = C + N × W_id
    let tc_signers = add(PREFIX_WIDTH_C, mul(n, VALIDATOR_ID_WIDTH)?)?;
    // T_msg = 8 + (D + 32 + 8 + C + N×W_id) + W_id + 1 + (C + S_sig) + 0
    let t_nested = add(
        add(add(DISCRIMINANT_WIDTH, 40)?, PREFIX_WIDTH_C)?,
        mul(n, VALIDATOR_ID_WIDTH)?,
    )?;
    let t_msg = add(
        add(add(add(8, t_nested)?, VALIDATOR_ID_WIDTH)?, 1)?,
        add(PREFIX_WIDTH_C, s)?,
    )?;
    // SIGNED_TIMEOUTS = C + N × T_msg
    let signed_timeouts = add(PREFIX_WIDTH_C, mul(n, t_msg)?)?;
    let anchor_pred = add(40, 8)?;
    let mut total = add(FIXED_OVERHEAD, anchor_pred)?;
    total = add(total, rec_high_qc)?;
    total = add(total, 8)?; // TC_VIEW
    total = add(total, 8)?; // TC_TIMEOUT_VIEW
    total = add(total, tc_high_qc)?;
    total = add(total, tc_signers)?;
    total = add(total, signed_timeouts)?;
    Ok(total)
}

/// `MAX_SAFETY_RECORD_BYTES = max(MAX_QC_BYTES, MAX_TC_BYTES)` (checked `u128`).
pub fn max_safety_record_bytes(ctx: &PinnedSafetyContext) -> Result<u128, SafetyStoreError> {
    Ok(max_qc_bytes(ctx)?.max(max_tc_bytes(ctx)?))
}

/// `MAX_QC_GENERATION_BYTES` — every § 13.7A(a) decoded row summed (checked `u128`).
pub fn max_qc_generation_bytes(ctx: &PinnedSafetyContext) -> Result<u128, SafetyStoreError> {
    let n = ctx.n() as u128;
    let s = ctx.s_sig as u128;
    let gen_struct = GEN_STRUCT_MAX;
    let signers_cap = ctx.b_span(); // signer_bitmap backing ≤ B_span
    let sig_vec_backing = mul(n, 24)?; // signatures outer descriptor array
    let sig_terms = mul(n, s)?; // per-signature buffers
                                // DECODED_SIGNERS = 0, CTX_OWNED = 0, CAPNORM_SLACK_QC = 0 (initial profile)
    let mut total = add(gen_struct, signers_cap)?;
    total = add(total, sig_vec_backing)?;
    total = add(total, sig_terms)?;
    total = add(total, ARC_CTRL)?;
    Ok(total)
}

/// `MAX_TC_GENERATION_BYTES` — every § 13.7A(b) decoded row summed (checked `u128`).
pub fn max_tc_generation_bytes(
    ctx: &PinnedSafetyContext,
    size_of_timeout_msg: u128,
) -> Result<u128, SafetyStoreError> {
    let n = ctx.n() as u128;
    let s = ctx.s_sig as u128;
    let gen_struct = GEN_STRUCT_MAX;
    let rec_high_qc_signers = mul(n, 8)?;
    let tc_signers = mul(n, 8)?;
    let tc_high_qc_signers = mul(n, 8)?;
    let signed_timeouts_backing = mul(n, size_of_timeout_msg)?;
    let timeout_sig_buffers = mul(n, s)?;
    let nested_high_qc_signers = mul(n, mul(n, 8)?)?; // 8N²
    let mut total = add(gen_struct, rec_high_qc_signers)?;
    total = add(total, tc_signers)?;
    total = add(total, tc_high_qc_signers)?;
    total = add(total, signed_timeouts_backing)?;
    total = add(total, timeout_sig_buffers)?;
    total = add(total, nested_high_qc_signers)?;
    total = add(total, ARC_CTRL)?;
    Ok(total)
}

/// `MAX_RETAINED_GENERATION_BYTES = checked_max(MAX_QC_GENERATION_BYTES,
/// MAX_TC_GENERATION_BYTES)` (§ 13.7A(c.3)).
pub fn max_retained_generation_bytes(
    ctx: &PinnedSafetyContext,
    size_of_timeout_msg: u128,
) -> Result<u128, SafetyStoreError> {
    Ok(max_qc_generation_bytes(ctx)?.max(max_tc_generation_bytes(ctx, size_of_timeout_msg)?))
}

/// `MAX_AGGREGATE_RETAINED_BYTES` — the conservative checked peak over the
/// bounded multiplicities of § 13.7 / § 13.7B.
pub fn max_aggregate_retained_bytes(
    ctx: &PinnedSafetyContext,
    size_of_timeout_msg: u128,
    validation_scratch: u128,
) -> Result<u128, SafetyStoreError> {
    let arc_handle: u128 = 8;
    let identity: u128 = 40;
    let gen = max_retained_generation_bytes(ctx, size_of_timeout_msg)?;
    let rec = max_safety_record_bytes(ctx)?;
    // holder term
    let holders = add(
        mul(add(1, MAX_CONCURRENT_CANDIDATES)?, arc_handle)?,
        mul(MAX_OUTSTANDING_PREPARED_L0, add(identity, arc_handle)?)?,
    )?;
    // generation term: (prepared + 1 + candidates) distinct generations
    let gen_mult = add(
        add(MAX_OUTSTANDING_PREPARED_L0, 1)?,
        MAX_CONCURRENT_CANDIDATES,
    )?;
    let gen_term = mul(gen_mult, gen)?;
    // capnorm overlap (0 initial profile)
    let capnorm = mul(MAX_CONCURRENT_CANDIDATES, 0)?;
    // encoded buffers: candidates + 2 × publications
    let enc_mult = add(
        MAX_CONCURRENT_CANDIDATES,
        mul(2, MAX_CONCURRENT_PUBLICATIONS)?,
    )?;
    let enc_term = mul(enc_mult, rec)?;
    let mut total = add(holders, gen_term)?;
    total = add(total, capnorm)?;
    total = add(total, enc_term)?;
    total = add(total, validation_scratch)?;
    Ok(total)
}