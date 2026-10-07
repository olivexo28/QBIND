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
    DecodedRecord, EvidenceStatus, LockedRecord, RetainedRecord, SafetyRecord, SupportingEvidence,
    ValidatedRecord,
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
/// Returns an opaque [`ValidatedRecord`] carrying the retained original
/// `encoded` publication bytes (operand 1 for O5) and the explicit,
/// always-`Unverified` evidence status.
///
/// Correspondence is **established, not assumed**: the supplied `decoded` and
/// `encoded` must round-trip (`encode_record(decoded) == encoded` under this
/// canonical profile), so a caller cannot staple an unrelated byte buffer onto
/// a semantically-valid decoded record to manufacture a validation proof. The
/// sealed proof is also bound to the originating pinned-context digest.
pub fn validate_decoded<H: CommittedHistory + ?Sized>(
    decoded: DecodedRecord,
    encoded: Vec<u8>,
    ctx: &PinnedSafetyContext,
    history: Option<&H>,
) -> Result<ValidatedRecord, SafetyStoreError> {
    // Establish decoded↔encoded correspondence before anything else: the bytes
    // that will be retained for O5 must be exactly those that re-encode from the
    // decoded content under this canonical profile. Divergence → refuse.
    let reencoded = super::codec::encode_record(&decoded, ctx)?;
    if reencoded != encoded {
        return Err(SafetyStoreError::SemanticRefusal(
            "decoded content does not correspond to the supplied encoded bytes".into(),
        ));
    }

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

    // Construct the contract-compliant retained generation (§ 13.7A(c.4)): keep
    // `publication_revision` + the `SafetyRecord` generation core and **discard**
    // the now-validated identity-header fields (`persistence_format_version` was
    // validated at decode and selects the decoder; `network_genesis_id` was just
    // compared to the pinned context above). Their exact bytes survive only in the
    // retained `encoded` publication (operand 1 for O5, § 13.7A(c.5)); they are
    // not retained as truth in the generation. The `DecodedRecord` is consumed by
    // value, so moving its `record` out leaves no second decoded copy alive.
    let DecodedRecord {
        persistence_format_version: _,
        network_genesis_id: _,
        publication_revision,
        record,
    } = decoded;
    let retained = RetainedRecord {
        publication_revision,
        record,
    };

    Ok(ValidatedRecord::seal(
        retained,
        EvidenceStatus::Unverified,
        encoded,
        super::owner::context_digest(ctx),
    ))
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
        ctx,
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
    // NOTE on TA identifiers: these are reconciled to the §13.3A contract
    // meanings (the earlier in-code numbering did not match the contract rows):
    //   TA1 = lock ↔ TC high_qc identity + record-level/TC high_qc byte-identity
    //   TA2 = TC high_qc ↔ derived max over signed_timeouts (view+block_id only)
    //   TA3 = signer uniqueness
    //   TA4 = authorized signer membership
    //   TA5 = signer-set correspondence (permutation of tc.signers)
    //   TA6 = timeout-view consistency
    //   TA7 = voting-power quorum (power, not count)
    //   TA8 = per-entry timeout-signature cryptography — NOT run here (unverified)

    // TA4: authorized signer membership of the claimed timeout signer set.
    for s in &tc.signers {
        if !ctx.is_member(*s) {
            return Err(SafetyStoreError::SemanticRefusal(format!(
                "tc signer {} not an authorized member (TA4)",
                s.as_u64()
            )));
        }
    }
    // TA3: signer uniqueness over tc.signers.
    let mut seen = std::collections::HashSet::new();
    for s in &tc.signers {
        if !seen.insert(s.as_u64()) {
            return Err(SafetyStoreError::SemanticRefusal(format!(
                "tc duplicate signer {} (TA3)",
                s.as_u64()
            )));
        }
    }
    // TA4/TA5: each signed_timeout validator is an authorized member, unique,
    // and (below) the evidence set corresponds to tc.signers.
    let mut st_ids = std::collections::HashSet::new();
    for t in &tc.signed_timeouts {
        if !ctx.is_member(t.validator_id) {
            return Err(SafetyStoreError::SemanticRefusal(format!(
                "signed_timeout validator {} not a member (TA4)",
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
    // TA5: signer-set correspondence — the evidence set is a permutation of
    // tc.signers (no extras, no missing, equal cardinality).
    if st_ids != seen {
        return Err(SafetyStoreError::SemanticRefusal(
            "tc.signers set does not correspond to signed_timeouts set (TA5)".into(),
        ));
    }
    // TA6: timeout-view consistency — every signed timeout is for tc.timeout_view.
    for t in &tc.signed_timeouts {
        if t.view != tc.timeout_view {
            return Err(SafetyStoreError::SemanticRefusal(format!(
                "signed_timeout view {} != tc.timeout_view {} (TA6)",
                t.view, tc.timeout_view
            )));
        }
    }
    // TA7: voting-power quorum over the claimed timeout signer set (power, not
    // count; kept distinct from the signer count and from TA8 authentication).
    let mut acc: u128 = 0;
    for s in &tc.signers {
        acc += ctx.voting_power(*s).unwrap_or(0) as u128;
    }
    if acc < ctx.two_thirds_vp() {
        return Err(SafetyStoreError::SemanticRefusal(
            "tc timeout voting power below ceil(2W/3) (TA7)".into(),
        ));
    }
    // TA2: the derived max high-QC from the signed timeouts must correspond to
    // the TC's carried high_qc by the contract's `high_qc_eq` rule —
    // `None == None`, else **view AND block_id** equal. The strict-`>`
    // first-encountered selection is preserved; NO signer-array equality is
    // required here (TA2 does not compare signers), and no tie-break is invented.
    let derived = select_max_high_qc(tc.signed_timeouts.iter());
    match (&derived, &tc.high_qc) {
        (None, None) => {}
        (Some(d), Some(c)) => {
            if d.block_id != c.block_id || d.view != c.view {
                return Err(SafetyStoreError::SemanticRefusal(
                    "tc.high_qc does not correspond to select_max_high_qc(signed_timeouts) (TA2)"
                        .into(),
                ));
            }
        }
        _ => {
            return Err(SafetyStoreError::SemanticRefusal(
                "tc.high_qc presence disagrees with derived max high-QC (TA2)".into(),
            ))
        }
    }
    // TA1: the record-level high_qc copy must be **byte-identical** to the TC's
    // own high_qc (exact copy correspondence — block_id, view AND signers).
    match &tc.high_qc {
        Some(c) => {
            if record_high_qc.block_id != c.block_id
                || record_high_qc.view != c.view
                || record_high_qc.signers != c.signers
            {
                return Err(SafetyStoreError::SemanticRefusal(
                    "record high_qc is not byte-identical to tc.high_qc (TA1)".into(),
                ));
            }
        }
        None => {
            return Err(SafetyStoreError::SemanticRefusal(
                "tc-derived lock requires a carried high_qc (TA1)".into(),
            ))
        }
    }
    // TA1: the lock binds to the retained high-QC (block + view identity).
    if record_high_qc.block_id != l.lock_block_id {
        return Err(SafetyStoreError::SemanticRefusal(
            "tc record high_qc block_id != lock_block_id (TA1/P1)".into(),
        ));
    }
    if record_high_qc.view != l.lock_view {
        return Err(SafetyStoreError::SemanticRefusal(
            "tc record high_qc view != lock_view (TA1/P2 view-binding)".into(),
        ));
    }
    Ok(())
}