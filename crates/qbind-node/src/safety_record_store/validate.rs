//! Run 422 D7-D14 — stage-3 **semantic** validation (§ 13.3 / § 13.3A). Stage 1
//! (structural: version, CRC, bounds, empty-signer threshold, bounded decode)
//! is enforced in [`super::codec`]. Stage 2 (wire-QC signature verification) is
//! deliberately **not** wired here, so every successfully validated record is
//! carried [`EvidenceStatus::Unverified`]; structural/semantic success and
//! durability never manufacture a verified-evidence result.

use super::codec::compute_evidence_lock_binding;
use super::error::{
    CapacityRefusalDetail, MissingIndependentInputSite, SafetyStoreError, SemanticRefusalDetail,
};
use super::profile::PinnedSafetyContext;
use super::record::{
    DecodedRecord, EvidenceStatus, LockedRecord, RetainedRecord, SafetyRecord, SupportingEvidence,
    ValidatedRecord,
};
use qbind_consensus::ids::ValidatorId;
use qbind_consensus::qc::QuorumCertificate;
use qbind_consensus::timeout::TimeoutMsg;

/// Storage-local **borrowed** maximum-high-QC selection (§ 13.7A TC-scratch
/// correction, D7-D14 Finding C).
///
/// The general consensus helper `qbind_consensus::timeout::select_max_high_qc`
/// returns an **owned clone** (`qc.clone()`), including the QC's signer / signature
/// / bitmap backings, and its `max_qc = Some(qc.clone())` replacement momentarily
/// holds the previous clone **and** its replacement simultaneously. Inside
/// `validate_tc` the only use of the selection is TA2, which compares **view and
/// block_id only** (never the signer array), so the clone and its replacement
/// overlap are pure, uncharged validation scratch with no semantic purpose.
///
/// This borrowed form returns a `&QuorumCertificate` into the already-admitted
/// decoded TC evidence, allocating nothing and never holding two selections at
/// once. Its selection behaviour is **byte-for-byte identical** to the consensus
/// helper: strict-`>` on view, first-encountered-wins for equal views (the
/// `max.is_none()` seed and the strict comparison reproduce the same choice,
/// including the `view == 0` seed case). It does **not** alter the general
/// consensus helper and introduces no new tie-break.
fn select_max_high_qc_ref<'a>(
    timeouts: impl Iterator<Item = &'a TimeoutMsg<[u8; 32]>>,
) -> Option<&'a QuorumCertificate<[u8; 32]>> {
    let mut max_qc: Option<&'a QuorumCertificate<[u8; 32]>> = None;
    let mut max_view: u64 = 0;
    for timeout in timeouts {
        if let Some(qc) = &timeout.high_qc {
            if max_qc.is_none() || qc.view > max_view {
                max_qc = Some(qc);
                max_view = qc.view;
            }
        }
    }
    max_qc
}

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
            SemanticRefusalDetail::Static(
                "decoded content does not correspond to the supplied encoded bytes",
            ),
        ));
    }
    // The correspondence re-encode has served its ONLY purpose. Drop its
    // record-sized backing explicitly **before** `validate_locked` /
    // `compute_evidence_lock_binding` allocates the certificate-binding scratch
    // (§ 13.7, D7-D14 O3 validation-coexistence correction). Without this drop
    // the re-encode buffer and the certificate-binding buffer — each up to
    // `MAX_SAFETY_RECORD_BYTES` — coexist, so the O3 phase holds TWO record-sized
    // validation buffers at once; dropping it here keeps the live validation
    // scratch to a single record-sized buffer, which is what the O3 reservation in
    // `read_validate` admits. This is a lifetime correction only: it never changes
    // which bytes are retained for O5 (the caller's `encoded` is untouched).
    // Test-only: observe the active operational reservation at the O3 validation
    // allocation peak — while the record-sized correspondence re-encode buffer is
    // still live — so a scratch reservation released after the pre-validation sample
    // but before this point is detected (RUN 422 D7-D14 L1). No-op unless
    // `read_validate` armed the sampler; never affects production behaviour.
    #[cfg(any(test, feature = "test-utils"))]
    super::owner::observe_in_validation_reservation();

    // Test-only (RUN 422 D7-D14 M1): record the ACTUAL re-encode-phase live object
    // charge. The two phase-invariant terms — the original backend-read `encoded`
    // buffer capacity and the live transient `decoded` object's measured charge
    // (walked in place, no clone) — are established here while BOTH are alive, then
    // the record-sized correspondence re-encode buffer (`reencoded`), which is still
    // live at this point, is added as the single live validation scratch. The stable
    // terms are retained for the certificate-binding phase below. No-op unless
    // `read_validate` armed the observation; never affects production behaviour.
    #[cfg(any(test, feature = "test-utils"))]
    {
        let original_encoded_cap = encoded.capacity() as u128;
        let transient_decoded_charge = super::accounting::decoded_working_set_charge(&decoded)?;
        super::owner::set_o3_object_stable(original_encoded_cap, transient_decoded_charge);
        super::owner::observe_o3_reencode_object(reencoded.capacity() as u128);
    }

    drop(reencoded);

    // Common identity binding to the pinned context (P4 prelude).
    if decoded.network_genesis_id != ctx.network_genesis_id {
        return Err(SafetyStoreError::SemanticRefusal(
            SemanticRefusalDetail::Static("network_genesis_id does not match pinned context"),
        ));
    }

    match &decoded.record {
        SafetyRecord::BootstrapNoLock {
            authority_context_ref,
            ..
        } => {
            if *authority_context_ref != ctx.authority_context_ref {
                return Err(SafetyStoreError::SemanticRefusal(
                    SemanticRefusalDetail::Static("bootstrap authority_context_ref mismatch"),
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
            SemanticRefusalDetail::Static("locked authority_context_ref mismatch"),
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
            SemanticRefusalDetail::Static("evidence_lock_binding does not recompute"),
        ));
    }

    match &l.evidence {
        SupportingEvidence::QcDerived(qc) => {
            // P4: chain/epoch/suite correspondence.
            if qc.chain_id != ctx.chain_id {
                return Err(SafetyStoreError::SemanticRefusal(
                    SemanticRefusalDetail::Static("qc chain_id mismatch"),
                ));
            }
            if qc.epoch != ctx.epoch {
                return Err(SafetyStoreError::SemanticRefusal(
                    SemanticRefusalDetail::Static("qc epoch mismatch"),
                ));
            }
            if qc.suite_id != ctx.qc_suite_id {
                return Err(SafetyStoreError::SemanticRefusal(
                    SemanticRefusalDetail::Static("qc suite_id mismatch"),
                ));
            }
            // P1: the supporting certificate binds the locked block.
            if qc.block_id != l.lock_block_id {
                return Err(SafetyStoreError::SemanticRefusal(
                    SemanticRefusalDetail::Static("qc block_id does not equal lock_block_id (P1)"),
                ));
            }
            // P2: the QC logical view binds to wire `height`, not `round`.
            if qc.height != l.lock_view {
                return Err(SafetyStoreError::SemanticRefusal(
                    SemanticRefusalDetail::Static(
                        "qc height does not equal lock_view (P2 view-binding)",
                    ),
                ));
            }
            // Optional, explicit profile choice — never silently conflated with
            // the P2 view binding above.
            if ctx.require_height_equals_round && qc.height != qc.round {
                return Err(SafetyStoreError::SemanticRefusal(
                    SemanticRefusalDetail::Static(
                        "profile requires height == round and it does not hold",
                    ),
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
                    MissingIndependentInputSite::P3CommittedAnchorNoHistory,
                ))
            }
            Some(h) => {
                if !h.contains_committed(&anchor.block_id, anchor.height) {
                    return Err(SafetyStoreError::SemanticRefusal(
                        SemanticRefusalDetail::Static(
                            "committed anchor not on supplied committed history (P3)",
                        ),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// `UNIQ_SET` (§ 13.7 `VALIDATION_SCRATCH`): a **bounded, no-hashing**
/// uniqueness/membership set, held as a **sorted `Vec<u64>`** whose backing is
/// pre-reserved to its `≤ N` term and never grows. Returns `true` when `id` is
/// newly inserted, `false` when it is already present (the present case does
/// **not** allocate). Because callers only insert authorized members and refuse
/// duplicates before growth, the live length never exceeds the reserved `N`, so
/// the backing stays a single admitted allocation (no rehash / no reallocation).
fn uniq_set_insert(set: &mut Vec<u64>, id: u64) -> bool {
    match set.binary_search(&id) {
        Ok(_) => false,
        Err(pos) => {
            set.insert(pos, id);
            true
        }
    }
}

/// Structural QC signer-set and voting-power quorum checks (no cryptographic
/// verification). Bitmap bits map to dense validator indices; the signature
/// count must correspond to the set-bit count; accumulated voting power must
/// meet `ceil(2W/3)`.
fn validate_qc_signers(
    ctx: &PinnedSafetyContext,
    qc: &super::record::WireQc,
) -> Result<(), SafetyStoreError> {
    // `UNIQ_SET` backing for the signer indices: pre-reserved to `N` and bounded
    // so it never grows. Set bits in excess of the authorized member count are a
    // bounded-scratch refusal (a valid QC has `≤ N` set bits, all members).
    let n = ctx.n();
    let mut signer_indices: Vec<u64> = Vec::with_capacity(n);
    for (byte_idx, byte) in qc.signer_bitmap.iter().enumerate() {
        for bit in 0..8u32 {
            if byte & (1 << bit) != 0 {
                if signer_indices.len() >= n {
                    return Err(SafetyStoreError::CapacityRefusal(
                        CapacityRefusalDetail::UniqSetExceeded { bound: n as u128 },
                    ));
                }
                let idx = (byte_idx as u64) * 8 + bit as u64;
                signer_indices.push(idx);
            }
        }
    }
    if signer_indices.is_empty() {
        return Err(SafetyStoreError::SemanticRefusal(
            SemanticRefusalDetail::Static("qc has no set signer bits"),
        ));
    }
    if signer_indices.len() != qc.signatures.len() {
        return Err(SafetyStoreError::SemanticRefusal(
            SemanticRefusalDetail::Static("qc set-bit count does not match signature count"),
        ));
    }
    let mut acc: u128 = 0;
    for idx in &signer_indices {
        let id = ValidatorId::new(*idx);
        match ctx.voting_power(id) {
            None => {
                return Err(SafetyStoreError::SemanticRefusal(
                    SemanticRefusalDetail::QcSignerIndexNotMember { index: *idx },
                ))
            }
            Some(p) => acc += p as u128,
        }
    }
    if acc < ctx.two_thirds_vp() {
        return Err(SafetyStoreError::SemanticRefusal(
            SemanticRefusalDetail::Static("qc accumulated voting power below ceil(2W/3)"),
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
            return Err(SafetyStoreError::SemanticRefusal(
                SemanticRefusalDetail::TcSignerNotMember { signer: s.as_u64() },
            ));
        }
    }
    // TA3: signer uniqueness over tc.signers, held in a bounded no-hashing
    // `UNIQ_SET` (sorted `Vec`, capacity ≤ N).
    let mut seen: Vec<u64> = Vec::with_capacity(ctx.n());
    for s in &tc.signers {
        if !uniq_set_insert(&mut seen, s.as_u64()) {
            return Err(SafetyStoreError::SemanticRefusal(
                SemanticRefusalDetail::TcDuplicateSigner { signer: s.as_u64() },
            ));
        }
    }
    // TA4/TA5: each signed_timeout validator is an authorized member, unique,
    // and (below) the evidence set corresponds to tc.signers. The evidence set
    // is the same bounded no-hashing `UNIQ_SET` representation.
    let mut st_ids: Vec<u64> = Vec::with_capacity(ctx.n());
    for t in &tc.signed_timeouts {
        if !ctx.is_member(t.validator_id) {
            return Err(SafetyStoreError::SemanticRefusal(
                SemanticRefusalDetail::SignedTimeoutValidatorNotMember {
                    validator: t.validator_id.as_u64(),
                },
            ));
        }
        if !uniq_set_insert(&mut st_ids, t.validator_id.as_u64()) {
            return Err(SafetyStoreError::SemanticRefusal(
                SemanticRefusalDetail::DuplicateSignedTimeoutValidator {
                    validator: t.validator_id.as_u64(),
                },
            ));
        }
    }
    // TA5: signer-set correspondence — the evidence set is a permutation of
    // tc.signers (no extras, no missing, equal cardinality). Both sides are
    // sorted unique `UNIQ_SET` vectors, so set equality is a direct comparison.
    if st_ids != seen {
        return Err(SafetyStoreError::SemanticRefusal(
            SemanticRefusalDetail::Static(
                "tc.signers set does not correspond to signed_timeouts set (TA5)",
            ),
        ));
    }
    // TA6: timeout-view consistency — every signed timeout is for tc.timeout_view.
    for t in &tc.signed_timeouts {
        if t.view != tc.timeout_view {
            return Err(SafetyStoreError::SemanticRefusal(
                SemanticRefusalDetail::SignedTimeoutViewMismatch {
                    view: t.view,
                    timeout_view: tc.timeout_view,
                },
            ));
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
            SemanticRefusalDetail::Static("tc timeout voting power below ceil(2W/3) (TA7)"),
        ));
    }
    // TA2: the derived max high-QC from the signed timeouts must correspond to
    // the TC's carried high_qc by the contract's `high_qc_eq` rule —
    // `None == None`, else **view AND block_id** equal. The strict-`>`
    // first-encountered selection is preserved; NO signer-array equality is
    // required here (TA2 does not compare signers), and no tie-break is invented.
    // A **borrowed** selection is used (D7-D14 Finding C): it allocates no cloned
    // signer backing and never overlaps a previous selection with its replacement,
    // so TC validation scratch is exactly the two bounded `UNIQ_SET` vectors above.
    let derived = select_max_high_qc_ref(tc.signed_timeouts.iter());
    match (&derived, &tc.high_qc) {
        (None, None) => {}
        (Some(d), Some(c)) => {
            if d.block_id != c.block_id || d.view != c.view {
                return Err(SafetyStoreError::SemanticRefusal(
                    SemanticRefusalDetail::Static(
                        "tc.high_qc does not correspond to select_max_high_qc(signed_timeouts) (TA2)",
                    ),
                ));
            }
        }
        _ => {
            return Err(SafetyStoreError::SemanticRefusal(
                SemanticRefusalDetail::Static(
                    "tc.high_qc presence disagrees with derived max high-QC (TA2)",
                ),
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
                    SemanticRefusalDetail::Static(
                        "record high_qc is not byte-identical to tc.high_qc (TA1)",
                    ),
                ));
            }
        }
        None => {
            return Err(SafetyStoreError::SemanticRefusal(
                SemanticRefusalDetail::Static("tc-derived lock requires a carried high_qc (TA1)"),
            ))
        }
    }
    // TA1: the lock binds to the retained high-QC (block + view identity).
    if record_high_qc.block_id != l.lock_block_id {
        return Err(SafetyStoreError::SemanticRefusal(
            SemanticRefusalDetail::Static("tc record high_qc block_id != lock_block_id (TA1/P1)"),
        ));
    }
    if record_high_qc.view != l.lock_view {
        return Err(SafetyStoreError::SemanticRefusal(
            SemanticRefusalDetail::Static(
                "tc record high_qc view != lock_view (TA1/P2 view-binding)",
            ),
        ));
    }
    Ok(())
}
#[cfg(test)]
mod fc_borrowed_selection_tests {
    //! Run 422 D7-D14 Finding C — the storage-local **borrowed** high-QC selection
    //! must choose exactly what the general consensus helper chooses (strict-`>`
    //! on view, first-encountered-wins for equal views) while allocating no cloned
    //! signer backing and never overlapping a previous selection with its
    //! replacement. These unit regressions detect a behavioural divergence from
    //! `qbind_consensus::timeout::select_max_high_qc` and a reintroduced clone.
    use super::select_max_high_qc_ref;
    use qbind_consensus::ids::ValidatorId;
    use qbind_consensus::qc::QuorumCertificate;
    use qbind_consensus::timeout::{select_max_high_qc, TimeoutMsg};

    fn qc(block: u8, view: u64) -> QuorumCertificate<[u8; 32]> {
        QuorumCertificate::new([block; 32], view, vec![ValidatorId::new(0)])
    }

    fn tmsg(view: u64, high: Option<QuorumCertificate<[u8; 32]>>) -> TimeoutMsg<[u8; 32]> {
        TimeoutMsg::new(view, high, ValidatorId::new(0))
    }

    /// Across representative sets (all-None, single, increasing, decreasing,
    /// equal-view ties, and a zero-view seed), the borrowed selection returns the
    /// SAME QC the owning-clone consensus helper returns — by value. Equal-view
    /// ties resolve to the first-encountered QC in both.
    #[test]
    fn borrowed_selection_matches_consensus_helper_by_value() {
        let cases: Vec<Vec<TimeoutMsg<[u8; 32]>>> = vec![
            vec![tmsg(1, None), tmsg(2, None)],
            vec![tmsg(1, Some(qc(1, 5)))],
            vec![
                tmsg(1, Some(qc(1, 3))),
                tmsg(1, Some(qc(2, 7))),
                tmsg(1, Some(qc(3, 4))),
            ],
            vec![tmsg(1, Some(qc(1, 9))), tmsg(1, Some(qc(2, 2)))],
            // Equal top view: first-encountered (block 1) must win in BOTH.
            vec![tmsg(1, Some(qc(1, 8))), tmsg(1, Some(qc(2, 8)))],
            // Zero-view seed interacting with the `max.is_none()` seed.
            vec![tmsg(1, Some(qc(1, 0))), tmsg(1, Some(qc(2, 0)))],
            vec![tmsg(1, None), tmsg(1, Some(qc(4, 6))), tmsg(1, None)],
        ];
        for (i, set) in cases.iter().enumerate() {
            let owned = select_max_high_qc(set.iter());
            let borrowed = select_max_high_qc_ref(set.iter());
            assert_eq!(
                borrowed.cloned(),
                owned,
                "case {i}: borrowed selection diverged from the consensus helper"
            );
        }
    }

    /// The borrowed selection returns a reference INTO the input (not a copy): the
    /// returned pointer is the address of the winning entry's `high_qc`, proving no
    /// clone and no replacement-overlap allocation.
    #[test]
    fn borrowed_selection_returns_input_borrow_not_a_clone() {
        let set = vec![
            tmsg(1, Some(qc(1, 3))),
            tmsg(1, Some(qc(2, 7))), // winner (highest view)
            tmsg(1, Some(qc(3, 4))),
        ];
        let winner = select_max_high_qc_ref(set.iter()).expect("a high-QC is selected");
        let expected = set[1].high_qc.as_ref().unwrap();
        assert!(
            std::ptr::eq(winner, expected),
            "borrowed selection must alias the input entry, not a cloned QC"
        );
    }
}