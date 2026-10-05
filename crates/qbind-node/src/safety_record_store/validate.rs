//! Run 422 D7-D14 — stage-3 **semantic** validation (§ 13.3 / § 13.3A). Stage 1
//! (structural: version, CRC, bounds, empty-signer threshold, bounded decode)
//! is enforced in [`super::codec`]. Stage 2 (wire-QC signature verification) is
//! deliberately **not** wired here, so every successfully validated record is
//! carried [`EvidenceStatus::Unverified`]; structural/semantic success and
//! durability never manufacture a verified-evidence result.

use super::codec::compute_evidence_lock_binding;
use super::error::SafetyStoreError;
use super::profile::PinnedSafetyContext;
use super::record::{
    DecodedRecord, EvidenceStatus, LockedRecord, SafetyRecord, SupportingEvidence, ValidatedRecord,
};
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::timeout::select_max_high_qc;

/// An **independently supplied** committed-history relation (§ 13.3A P3). A
/// committed anchor is accepted only if this relation independently affirms it;
/// test producers may implement it as a clearly-labelled fixture, but it is
/// never derived from the candidate record being checked.
pub trait CommittedHistory {
    /// Does the recovered committed history contain `block_id` at `height`?
    fn contains_committed(&self, block_id: &[u8; 32], height: u64) -> bool;
}

/// A fixture committed-history relation for tests (clearly labelled; not
/// production history recovery).
#[derive(Debug, Default, Clone)]
pub struct FixtureCommittedHistory {
    entries: Vec<([u8; 32], u64)>,
}

impl FixtureCommittedHistory {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, block_id: [u8; 32], height: u64) -> Self {
        self.entries.push((block_id, height));
        self
    }
}

impl CommittedHistory for FixtureCommittedHistory {
    fn contains_committed(&self, block_id: &[u8; 32], height: u64) -> bool {
        self.entries
            .iter()
            .any(|(b, h)| b == block_id && *h == height)
    }
}

/// Validate an already structurally-decoded record against the pinned context
/// and (for anchored records) the independently-supplied committed history.
///
/// Returns a [`ValidatedRecord`] carrying the retained original `encoded`
/// publication bytes (operand 1 for O5) and the explicit, always-`Unverified`
/// evidence status.
pub fn validate_decoded<H: CommittedHistory + ?Sized>(
    decoded: DecodedRecord,
    encoded: Vec<u8>,
    ctx: &PinnedSafetyContext,
    history: Option<&H>,
) -> Result<ValidatedRecord, SafetyStoreError> {
    // Common identity binding to the pinned context (P4 prelude).
    if decoded.network_genesis_id != ctx.network_genesis_id {
        return Err(SafetyStoreError::SemanticRefusal(
            "network_genesis_id does not match pinned context".into(),
        ));
    }

    match &decoded.record {
        SafetyRecord::BootstrapNoLock {
            authority_context_ref,
            ..
        } => {
            if *authority_context_ref != ctx.authority_context_ref {
                return Err(SafetyStoreError::SemanticRefusal(
                    "bootstrap authority_context_ref mismatch".into(),
                ));
            }
            // No lock, no evidence, no committed anchor. Nothing further to verify.
        }
        SafetyRecord::Locked(locked) => {
            validate_locked(locked, ctx, history)?;
        }
    }

    Ok(ValidatedRecord {
        decoded,
        evidence_status: EvidenceStatus::Unverified,
        encoded,
    })
}

fn validate_locked<H: CommittedHistory + ?Sized>(
    l: &LockedRecord,
    ctx: &PinnedSafetyContext,
    history: Option<&H>,
) -> Result<(), SafetyStoreError> {
    // P4: the authorized-context descriptor must match the pinned context.
    if l.authority_context_ref != ctx.authority_context_ref {
        return Err(SafetyStoreError::SemanticRefusal(
            "locked authority_context_ref mismatch".into(),
        ));
    }

    // evidence_lock_binding integrity: the retained binding digest must be the
    // one derived from {lock_block_id, lock_view, supporting cert, authctx}.
    let recomputed = compute_evidence_lock_binding(
        &l.lock_block_id,
        l.lock_view,
        &l.evidence,
        &l.authority_context_ref,
    )?;
    if recomputed != l.evidence_lock_binding {
        return Err(SafetyStoreError::SemanticRefusal(
            "evidence_lock_binding does not recompute".into(),
        ));
    }

    match &l.evidence {
        SupportingEvidence::QcDerived(qc) => {
            // P4: chain/epoch/suite correspondence.
            if qc.chain_id != ctx.chain_id {
                return Err(SafetyStoreError::SemanticRefusal(
                    "qc chain_id mismatch".into(),
                ));
            }
            if qc.epoch != ctx.epoch {
                return Err(SafetyStoreError::SemanticRefusal(
                    "qc epoch mismatch".into(),
                ));
            }
            if qc.suite_id != ctx.qc_suite_id {
                return Err(SafetyStoreError::SemanticRefusal(
                    "qc suite_id mismatch".into(),
                ));
            }
            // P1: the supporting certificate binds the locked block.
            if qc.block_id != l.lock_block_id {
                return Err(SafetyStoreError::SemanticRefusal(
                    "qc block_id does not equal lock_block_id (P1)".into(),
                ));
            }
            // P2: the QC logical view binds to wire `height`, not `round`.
            if qc.height != l.lock_view {
                return Err(SafetyStoreError::SemanticRefusal(
                    "qc height does not equal lock_view (P2 view-binding)".into(),
                ));
            }
            // Optional, explicit profile choice — never silently conflated with
            // the P2 view binding above.
            if ctx.require_height_equals_round && qc.height != qc.round {
                return Err(SafetyStoreError::SemanticRefusal(
                    "profile requires height == round and it does not hold".into(),
                ));
            }
            // Structural signer-set / quorum checks (separate from stage-2 crypto).
            validate_qc_signers(ctx, qc)?;
        }
        SupportingEvidence::TcDerived { high_qc, tc } => {
            validate_tc(ctx, high_qc, tc, l)?;
        }
    }

    // P3: an anchored record requires the independently supplied committed
    // relation; missing required history refuses.
    if let Some(anchor) = &l.committed_anchor {
        match history {
            None => {
                return Err(SafetyStoreError::MissingIndependentInput(
                    "committed anchor present but no committed-history relation supplied (P3)"
                        .into(),
                ))
            }
            Some(h) => {
                if !h.contains_committed(&anchor.block_id, anchor.height) {
                    return Err(SafetyStoreError::SemanticRefusal(
                        "committed anchor not on supplied committed history (P3)".into(),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Structural QC signer-set and voting-power quorum checks (no cryptographic
/// verification). Bitmap bits map to dense validator indices; the signature
/// count must correspond to the set-bit count; accumulated voting power must
/// meet `ceil(2W/3)`.
fn validate_qc_signers(
    ctx: &PinnedSafetyContext,
    qc: &super::record::WireQc,
) -> Result<(), SafetyStoreError> {
    let mut signer_indices = Vec::new();
    for (byte_idx, byte) in qc.signer_bitmap.iter().enumerate() {
        for bit in 0..8u32 {
            if byte & (1 << bit) != 0 {
                let idx = (byte_idx as u64) * 8 + bit as u64;
                signer_indices.push(idx);
            }
        }
    }
    if signer_indices.is_empty() {
        return Err(SafetyStoreError::SemanticRefusal(
            "qc has no set signer bits".into(),
        ));
    }
    if signer_indices.len() != qc.signatures.len() {
        return Err(SafetyStoreError::SemanticRefusal(
            "qc set-bit count does not match signature count".into(),
        ));
    }
    let mut acc: u128 = 0;
    for idx in &signer_indices {
        let id = ValidatorId::new(*idx);
        match ctx.voting_power(id) {
            None => {
                return Err(SafetyStoreError::SemanticRefusal(format!(
                    "qc signer index {idx} is not an authorized member"
                )))
            }
            Some(p) => acc += p as u128,
        }
    }
    if acc < ctx.two_thirds_vp() {
        return Err(SafetyStoreError::SemanticRefusal(
            "qc accumulated voting power below ceil(2W/3)".into(),
        ));
    }
    Ok(())
}

fn validate_tc(
    ctx: &PinnedSafetyContext,
    record_high_qc: &super::record::LogicalQc,
    tc: &super::record::TimeoutCert,
    l: &LockedRecord,
) -> Result<(), SafetyStoreError> {
    // TA1: timeout signer membership.
    for s in &tc.signers {
        if !ctx.is_member(*s) {
            return Err(SafetyStoreError::SemanticRefusal(format!(
                "tc signer {} not an authorized member (TA1)",
                s.as_u64()
            )));
        }
    }
    // TA2: signer uniqueness.
    let mut seen = std::collections::HashSet::new();
    for s in &tc.signers {
        if !seen.insert(s.as_u64()) {
            return Err(SafetyStoreError::SemanticRefusal(format!(
                "tc duplicate signer {} (TA2)",
                s.as_u64()
            )));
        }
    }
    // TA3: signer-set correspondence between tc.signers and signed_timeouts.
    let mut st_ids = std::collections::HashSet::new();
    for t in &tc.signed_timeouts {
        if !ctx.is_member(t.validator_id) {
            return Err(SafetyStoreError::SemanticRefusal(format!(
                "signed_timeout validator {} not a member (TA3)",
                t.validator_id.as_u64()
            )));
        }
        if !st_ids.insert(t.validator_id.as_u64()) {
            return Err(SafetyStoreError::SemanticRefusal(format!(
                "duplicate signed_timeout validator {} (TA3)",
                t.validator_id.as_u64()
            )));
        }
    }
    if st_ids != seen {
        return Err(SafetyStoreError::SemanticRefusal(
            "tc.signers set does not correspond to signed_timeouts set (TA3)".into(),
        ));
    }
    // TA4: view consistency — every signed timeout is for tc.timeout_view.
    for t in &tc.signed_timeouts {
        if t.view != tc.timeout_view {
            return Err(SafetyStoreError::SemanticRefusal(format!(
                "signed_timeout view {} != tc.timeout_view {} (TA4)",
                t.view, tc.timeout_view
            )));
        }
    }
    // TA5: voting-power quorum over the timeout signer set.
    let mut acc: u128 = 0;
    for s in &tc.signers {
        acc += ctx.voting_power(*s).unwrap_or(0) as u128;
    }
    if acc < ctx.two_thirds_vp() {
        return Err(SafetyStoreError::SemanticRefusal(
            "tc timeout voting power below ceil(2W/3) (TA5)".into(),
        ));
    }
    // TA6: equal-view high-QC selection preserved — the derived max high-QC from
    // the signed timeouts must correspond to the TC's carried high_qc. No
    // tie-break is invented; `select_max_high_qc` keeps first-encountered.
    let derived = select_max_high_qc(tc.signed_timeouts.iter());
    match (&derived, &tc.high_qc) {
        (None, None) => {}
        (Some(d), Some(c)) => {
            if d.block_id != c.block_id || d.view != c.view || d.signers != c.signers {
                return Err(SafetyStoreError::SemanticRefusal(
                    "tc.high_qc does not correspond to select_max_high_qc(signed_timeouts) (TA6)"
                        .into(),
                ));
            }
        }
        _ => {
            return Err(SafetyStoreError::SemanticRefusal(
                "tc.high_qc presence disagrees with derived max high-QC (TA6)".into(),
            ))
        }
    }
    // TA7: both retained high-QC copies correspond (record-level vs TC-level).
    match &tc.high_qc {
        Some(c) => {
            if record_high_qc.block_id != c.block_id
                || record_high_qc.view != c.view
                || record_high_qc.signers != c.signers
            {
                return Err(SafetyStoreError::SemanticRefusal(
                    "record high_qc does not correspond to tc.high_qc (TA7)".into(),
                ));
            }
        }
        None => {
            return Err(SafetyStoreError::SemanticRefusal(
                "tc-derived lock requires a carried high_qc (TA7)".into(),
            ))
        }
    }
    // TA8: the lock binds to the retained high-QC (block + view binding).
    if record_high_qc.block_id != l.lock_block_id {
        return Err(SafetyStoreError::SemanticRefusal(
            "tc record high_qc block_id != lock_block_id (TA8/P1)".into(),
        ));
    }
    if record_high_qc.view != l.lock_view {
        return Err(SafetyStoreError::SemanticRefusal(
            "tc record high_qc view != lock_view (TA8/P2 view-binding)".into(),
        ));
    }
    Ok(())
}