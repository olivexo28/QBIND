//! Run 422 §13.6 — isolated owner-controlled decision/capture binding types.
//!
//! This module holds the **data types and pure, borrowed-input computations** of
//! the isolated owner-controlled decision/capture route: the call-time input
//! policy, the streaming proposal commitment, the bounded ancestry binding, the
//! fixed decision metadata, and the closed owning-capture payload / outcome
//! types. The route itself (one domain acquisition, the engine decision, the
//! held-guard capture) lives in [`super::owner`] because it needs that module's
//! private backend/accountant handles.
//!
//! None of this authorizes, verifies, or signs: a commitment is *volatile
//! decision association only*. The limits here are **isolated-route resource
//! restrictions**, not production throughput targets, verification guarantees,
//! or network-decoder protections.

use sha3::{Digest, Sha3_256};

use qbind_consensus::{
    AncestryRelation, DecidedVote, SafetyAncestorView, SafetyBranch, SafetyDecisionView,
};
use qbind_wire::consensus::{BlockProposal, QuorumCertificate, MSG_TYPE_QC};

use super::prepared::{PreparedPin, PREPARED_SLOTS};
use super::profile::PinnedSafetyContext;
use super::record::ValidatedRecord;

/// Domain-separation prefix for the proposal commitment oracle (§6). The
/// commitment is exactly `Sha3_256(PROPOSAL_DOMAIN || proposal.canonical_body())`.
const PROPOSAL_DOMAIN: &[u8] = b"QBIND-D7D14-PREPARED-PROPOSAL-BINDING-v1";

/// Separate, independently initialized domain-separation prefix for the ancestry
/// binding (§6). Never shares a hasher with the proposal commitment.
const ANCESTRY_DOMAIN: &[u8] = b"QBIND-D7D14-PREPARED-ANCESTRY-BINDING-v1";

// Reviewed isolated-route opt-in restrictions (§7).
const MAX_TX_COUNT: u32 = 1024;
const MAX_TX_LEN: u32 = 1_048_576; // 1 MiB
const MAX_TOTAL_CANONICAL: u64 = 8_388_608; // 8 MiB, independent aggregate cap
const MAX_QC_SIG_LEN: u32 = 8192;
const MAX_ANCESTRY_HOPS: usize = 64;

// -----------------------------------------------------------------------------
// Input policy
// -----------------------------------------------------------------------------

/// A failure constructing the call-time input policy from the owner's pinned
/// context. The QC-signature-count cap is N-dependent (the pinned validator
/// count), so the policy is built from the context rather than a parameterless
/// const constructor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InputPolicyError {
    /// The pinned context carries no validators, so no QC signature-count cap
    /// can be derived.
    EmptyValidatorSet,
    /// The pinned validator count does not fit the cap's width.
    ValidatorCountOverflow,
}

/// An immutable, call-time isolated-route input policy derived from the owner's
/// pinned context (§7). Labelled **resource restrictions**: they bound the work
/// this isolated route will admit, not production throughput, verification, or
/// decoder protection. The 8 MiB total is an independent aggregate cap and does
/// **not** accommodate all individual maxima simultaneously.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PreparedDecisionInputLimits {
    max_tx_count: u32,
    max_tx_len: u32,
    max_total_canonical: u64,
    /// At most the pinned context's validator count `N`.
    max_qc_sig_count: u32,
    max_qc_sig_len: u32,
    max_ancestry_hops: usize,
}

impl PreparedDecisionInputLimits {
    /// Construct and validate the policy from the owner's pinned context. The QC
    /// signature-count cap is the pinned validator count `N`; an empty validator
    /// set is a typed failure.
    pub fn from_pinned(ctx: &PinnedSafetyContext) -> Result<Self, InputPolicyError> {
        let n = ctx.validators.len();
        if n == 0 {
            return Err(InputPolicyError::EmptyValidatorSet);
        }
        let max_qc_sig_count =
            u32::try_from(n).map_err(|_| InputPolicyError::ValidatorCountOverflow)?;
        Ok(Self {
            max_tx_count: MAX_TX_COUNT,
            max_tx_len: MAX_TX_LEN,
            max_total_canonical: MAX_TOTAL_CANONICAL,
            max_qc_sig_count,
            max_qc_sig_len: MAX_QC_SIG_LEN,
            max_ancestry_hops: MAX_ANCESTRY_HOPS,
        })
    }

    /// Maximum admitted transaction count.
    pub fn max_tx_count(&self) -> u32 {
        self.max_tx_count
    }
    /// Maximum admitted individual transaction length.
    pub fn max_tx_len(&self) -> u32 {
        self.max_tx_len
    }
    /// Maximum admitted total canonical proposal byte length.
    pub fn max_total_canonical(&self) -> u64 {
        self.max_total_canonical
    }
    /// Maximum admitted QC signature count (the pinned validator count `N`).
    pub fn max_qc_sig_count(&self) -> u32 {
        self.max_qc_sig_count
    }
    /// Maximum admitted individual QC signature length.
    pub fn max_qc_sig_len(&self) -> u32 {
        self.max_qc_sig_len
    }
    /// Maximum admitted ancestry parent transitions.
    pub fn max_ancestry_hops(&self) -> usize {
        self.max_ancestry_hops
    }
}

// -----------------------------------------------------------------------------
// Typed input-bound refusals (§4 / §6 / §7)
// -----------------------------------------------------------------------------

/// A typed refusal raised while computing the streaming proposal commitment,
/// before any oversized content is admitted or hashed. No truncation, silent
/// normalization, oversized-input panic, or post-allocation admission.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InputBoundRefusal {
    /// `proposal.txs.len()` exceeds the admitted transaction count.
    TxCountExceeded { count: usize, max: u32 },
    /// The header's declared `tx_count` disagrees with `proposal.txs.len()`.
    TxCountInconsistent { header: u32, actual: usize },
    /// An individual transaction exceeds the admitted length.
    TxLenExceeded { index: usize, len: usize, max: u32 },
    /// The total canonical length exceeds the independent aggregate cap.
    TotalCanonicalExceeded { total: u64, max: u64 },
    /// The embedded QC signature count exceeds the admitted (validator-count) cap.
    QcSigCountExceeded { count: usize, max: u32 },
    /// An individual QC signature exceeds the admitted length.
    QcSigLenExceeded { index: usize, len: usize, max: u32 },
    /// The QC signer bitmap length does not fit the wire framing width (`u16`).
    QcBitmapLenOverflow { len: usize },
    /// A checked length/width conversion overflowed (refused before hashing).
    Arithmetic,
}

// -----------------------------------------------------------------------------
// Streaming proposal commitment (§6)
// -----------------------------------------------------------------------------

/// Compute the proposal commitment `Sha3_256(PROPOSAL_DOMAIN ||
/// proposal.canonical_body())` by **streaming** the borrowed fields directly —
/// including the embedded QC bitmap/signatures and every transaction — without
/// allocating a QC buffer, a joined canonical buffer, a certificate clone, or a
/// retained transaction copy. The complete unsigned canonical body is covered;
/// the proposer signature is excluded (this binds the unsigned proposal content,
/// not every byte of a complete signed message).
///
/// Every variable length is taken through checked arithmetic / fallible
/// conversions, and the cumulative total is preflighted against the aggregate cap
/// **before** any bulk content is hashed. Decision metadata is deliberately
/// **not** mixed into this oracle.
pub(crate) fn commit_proposal(
    proposal: &BlockProposal,
    limits: &PreparedDecisionInputLimits,
) -> Result<[u8; 32], InputBoundRefusal> {
    let h = &proposal.header;

    // --- transaction count consistency + bound ---
    let tx_count = proposal.txs.len();
    if tx_count > limits.max_tx_count as usize {
        return Err(InputBoundRefusal::TxCountExceeded {
            count: tx_count,
            max: limits.max_tx_count,
        });
    }
    if h.tx_count as usize != tx_count {
        return Err(InputBoundRefusal::TxCountInconsistent {
            header: h.tx_count,
            actual: tx_count,
        });
    }

    // --- embedded QC encoded length (and per-sig / bitmap / count bounds) ---
    let (qc_len, qc_present) = match &proposal.qc {
        Some(qc) => (qc_encoded_len(qc, limits)?, true),
        None => (0u32, false),
    };

    // --- cumulative length preflight BEFORE hashing bulk content ---
    // Fixed header bytes mirrored from `BlockProposal::canonical_body`:
    // version(1) chain_id(4) epoch(8) height(8) round(8) parent(32) payload(32)
    // proposer_index(2) suite_id(2) tx_count(4) timestamp(8) payload_kind(1)
    // next_epoch(8) batch_commitment(32).
    const HEADER_LEN: u64 = 1 + 4 + 8 + 8 + 8 + 32 + 32 + 2 + 2 + 4 + 8 + 1 + 8 + 32;
    let mut total: u64 = HEADER_LEN
        .checked_add(4) // qc length prefix
        .and_then(|t| t.checked_add(qc_len as u64))
        .ok_or(InputBoundRefusal::Arithmetic)?;
    for (index, tx) in proposal.txs.iter().enumerate() {
        if tx.len() > limits.max_tx_len as usize {
            return Err(InputBoundRefusal::TxLenExceeded {
                index,
                len: tx.len(),
                max: limits.max_tx_len,
            });
        }
        // canonical_body frames each tx length as u32; refuse rather than panic.
        u32::try_from(tx.len()).map_err(|_| InputBoundRefusal::Arithmetic)?;
        total = total
            .checked_add(4)
            .and_then(|t| t.checked_add(tx.len() as u64))
            .ok_or(InputBoundRefusal::Arithmetic)?;
    }
    if total > limits.max_total_canonical {
        return Err(InputBoundRefusal::TotalCanonicalExceeded {
            total,
            max: limits.max_total_canonical,
        });
    }

    // --- stream byte-identically to PROPOSAL_DOMAIN || canonical_body() ---
    let mut hasher = Sha3_256::new();
    hasher.update(PROPOSAL_DOMAIN);
    hasher.update([h.version]);
    hasher.update(h.chain_id.to_le_bytes());
    hasher.update(h.epoch.to_le_bytes());
    hasher.update(h.height.to_le_bytes());
    hasher.update(h.round.to_le_bytes());
    hasher.update(h.parent_block_id);
    hasher.update(h.payload_hash);
    hasher.update(h.proposer_index.to_le_bytes());
    hasher.update(h.suite_id.to_le_bytes());
    hasher.update(h.tx_count.to_le_bytes());
    hasher.update(h.timestamp.to_le_bytes());
    hasher.update([h.payload_kind]);
    hasher.update(h.next_epoch.to_le_bytes());
    hasher.update(h.batch_commitment);
    hasher.update(qc_len.to_le_bytes());
    if qc_present {
        stream_qc(&mut hasher, proposal.qc.as_ref().expect("qc_present"));
    }
    for tx in &proposal.txs {
        // width already validated above; re-use the checked value.
        hasher.update((tx.len() as u32).to_le_bytes());
        hasher.update(tx);
    }

    Ok(finalize(hasher))
}

/// The encoded byte length of `qc` as `QuorumCertificate::encode` would produce,
/// computed with checked arithmetic and with the per-signature / bitmap / count
/// bounds enforced. Never allocates a QC buffer.
fn qc_encoded_len(
    qc: &QuorumCertificate,
    limits: &PreparedDecisionInputLimits,
) -> Result<u32, InputBoundRefusal> {
    let sig_count = qc.signatures.len();
    if sig_count > limits.max_qc_sig_count as usize {
        return Err(InputBoundRefusal::QcSigCountExceeded {
            count: sig_count,
            max: limits.max_qc_sig_count,
        });
    }
    // sig_count is framed as u16 by the wire encoder.
    u16::try_from(sig_count).map_err(|_| InputBoundRefusal::Arithmetic)?;
    let bitmap_len = u16::try_from(qc.signer_bitmap.len()).map_err(|_| {
        InputBoundRefusal::QcBitmapLenOverflow {
            len: qc.signer_bitmap.len(),
        }
    })?;
    // Fixed QC prefix bytes: MSG_TYPE(1) version(1) chain_id(4) epoch(8)
    // height(8) round(8) step(1) block_id(32) suite_id(2) = 65, plus the
    // bitmap_len(2) and sig_count(2) framing words.
    let mut total: u64 = 65u64 + 2 + bitmap_len as u64 + 2;
    for (index, sig) in qc.signatures.iter().enumerate() {
        if sig.len() > limits.max_qc_sig_len as usize {
            return Err(InputBoundRefusal::QcSigLenExceeded {
                index,
                len: sig.len(),
                max: limits.max_qc_sig_len,
            });
        }
        u16::try_from(sig.len()).map_err(|_| InputBoundRefusal::Arithmetic)?;
        total = total
            .checked_add(2)
            .and_then(|t| t.checked_add(sig.len() as u64))
            .ok_or(InputBoundRefusal::Arithmetic)?;
    }
    u32::try_from(total).map_err(|_| InputBoundRefusal::Arithmetic)
}

/// Stream the QC field-by-field into `hasher` in the exact `encode` byte order,
/// without building an intermediate buffer.
fn stream_qc(hasher: &mut Sha3_256, qc: &QuorumCertificate) {
    hasher.update([MSG_TYPE_QC]);
    hasher.update([qc.version]);
    hasher.update(qc.chain_id.to_le_bytes());
    hasher.update(qc.epoch.to_le_bytes());
    hasher.update(qc.height.to_le_bytes());
    hasher.update(qc.round.to_le_bytes());
    hasher.update([qc.step]);
    hasher.update(qc.block_id);
    hasher.update(qc.suite_id.to_le_bytes());
    hasher.update((qc.signer_bitmap.len() as u16).to_le_bytes());
    hasher.update(&qc.signer_bitmap);
    hasher.update((qc.signatures.len() as u16).to_le_bytes());
    for sig in &qc.signatures {
        hasher.update((sig.len() as u16).to_le_bytes());
        hasher.update(sig);
    }
}

fn finalize(hasher: Sha3_256) -> [u8; 32] {
    let d = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// -----------------------------------------------------------------------------
// Bounded ancestry binding (§6)
// -----------------------------------------------------------------------------

/// How the ancestry binding classified the candidate relative to the lock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AncestryKind {
    /// `ViewSufficiency`: not applicable — recorded without any ancestry walk.
    NotApplicable,
    /// The candidate itself is the lock (zero parent transitions).
    CandidateIsLock,
    /// The lock was reached after exactly `hops` parent transitions.
    ReachedLock { hops: usize },
}

/// A typed refusal raised while binding required ancestry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AncestryRefusal {
    /// Required ancestry evidence is unavailable (no lock on a required branch,
    /// a broken parent link, or an absent parent block).
    Unavailable,
    /// Required ancestry exceeded the admitted traversal bound.
    OverBound { max: usize },
    /// The traversal endpoint did not match the engine lock (internal guard).
    EndpointMismatch,
}

/// A bounded commitment to the actual parent chain inspected through the decision
/// view (§3/§6). It identifies the supplied inputs; it does not reconstruct
/// missing ancestry or independently prove its validity, and it does **not**
/// bound the authoritative safety predicate (which, on `ViewSufficiency`, walked
/// no ancestry at all).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AncestryBinding {
    commitment: [u8; 32],
    kind: AncestryKind,
}

impl AncestryBinding {
    /// The 32-byte ancestry commitment.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
    /// How the candidate related to the lock.
    pub fn kind(&self) -> AncestryKind {
        self.kind
    }
}

/// Build the ancestry binding for a decision whose branch is `ViewSufficiency`
/// (not applicable) or `Ancestry` (required). `NoLock` must already have been
/// refused by the caller and is treated here as unavailable.
pub(crate) fn bind_ancestry(
    decision: &SafetyDecisionView<'_, [u8; 32]>,
    limits: &PreparedDecisionInputLimits,
) -> Result<AncestryBinding, AncestryRefusal> {
    match decision.branch() {
        SafetyBranch::ViewSufficiency => {
            // Not applicable: record the marker WITHOUT any ancestry walk.
            let mut h = Sha3_256::new();
            h.update(ANCESTRY_DOMAIN);
            h.update([0u8]); // not-applicable marker
            Ok(AncestryBinding {
                commitment: finalize(h),
                kind: AncestryKind::NotApplicable,
            })
        }
        SafetyBranch::NoLock => Err(AncestryRefusal::Unavailable),
        SafetyBranch::Ancestry => {
            let lock_id = decision
                .locked_block_id()
                .ok_or(AncestryRefusal::Unavailable)?;
            let lock_view = decision.locked_view().ok_or(AncestryRefusal::Unavailable)?;
            match decision.ancestry_relation_to_lock(limits.max_ancestry_hops) {
                AncestryRelation::CandidateIsLock => {
                    let mut h = Sha3_256::new();
                    h.update(ANCESTRY_DOMAIN);
                    h.update([1u8]); // candidate-is-lock marker (zero hops)
                    h.update(decision.candidate_id());
                    h.update(decision.candidate_view().to_le_bytes());
                    h.update(lock_id);
                    h.update(lock_view.to_le_bytes());
                    Ok(AncestryBinding {
                        commitment: finalize(h),
                        kind: AncestryKind::CandidateIsLock,
                    })
                }
                AncestryRelation::ReachedLock { hops } => {
                    let mut h = Sha3_256::new();
                    h.update(ANCESTRY_DOMAIN);
                    h.update([2u8]); // reached-lock marker
                    h.update((hops as u64).to_le_bytes());
                    h.update(decision.candidate_id());
                    h.update(decision.candidate_view().to_le_bytes());
                    // Traverse EXACTLY `hops` parent transitions, committing each
                    // ancestor's id/view and its parent framing in order.
                    let mut walked = 0usize;
                    let mut last_id = *decision.candidate_id();
                    decision.for_each_ancestor(hops, |anc: &SafetyAncestorView<'_, [u8; 32]>| {
                        h.update(anc.id());
                        h.update(anc.view().to_le_bytes());
                        match anc.parent_id() {
                            Some(pid) => {
                                h.update([1u8]); // has-parent framing
                                h.update(pid);
                            }
                            None => {
                                h.update([0u8]); // no-parent framing
                            }
                        }
                        last_id = *anc.id();
                        walked += 1;
                    });
                    if walked != hops {
                        // The relation promised `hops` reachable transitions.
                        return Err(AncestryRefusal::Unavailable);
                    }
                    if &last_id != lock_id {
                        return Err(AncestryRefusal::EndpointMismatch);
                    }
                    h.update(lock_id);
                    h.update(lock_view.to_le_bytes());
                    h.update([0xEEu8]); // terminal marker
                    Ok(AncestryBinding {
                        commitment: finalize(h),
                        kind: AncestryKind::ReachedLock { hops },
                    })
                }
                AncestryRelation::BoundExhausted => Err(AncestryRefusal::OverBound {
                    max: limits.max_ancestry_hops,
                }),
                AncestryRelation::NoLock
                | AncestryRelation::NoParentLink
                | AncestryRelation::ParentAbsent => Err(AncestryRefusal::Unavailable),
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Fixed decision metadata (§5)
// -----------------------------------------------------------------------------

/// The engine safety branch, retained as fixed metadata.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MetaBranch {
    /// `ViewSufficiency` short-circuit (no ancestry walk).
    ViewSufficiency,
    /// `Ancestry` parent-chain walk reached the lock.
    Ancestry,
}

/// The entrypoint kind the decision was produced on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntrypointKind {
    /// The legacy/logical owning entrypoint (the only one used by this route).
    LegacyLogical,
    /// A verified-evidence entrypoint (not used by this route; retained for
    /// faithful metadata only).
    Verified,
}

/// Immutable, fixed-size decision metadata retained alongside the capture (§5),
/// separate from the proposal-commitment oracle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DecisionMetadata {
    proposer: u64,
    safety_branch: MetaBranch,
    entrypoint: EntrypointKind,
    origin_view: u64,
    candidate_id: [u8; 32],
    candidate_view: u64,
}

impl DecisionMetadata {
    pub(crate) fn new(
        proposer: u64,
        safety_branch: MetaBranch,
        entrypoint: EntrypointKind,
        origin_view: u64,
        candidate_id: [u8; 32],
        candidate_view: u64,
    ) -> Self {
        Self {
            proposer,
            safety_branch,
            entrypoint,
            origin_view,
            candidate_id,
            candidate_view,
        }
    }

    /// The originating proposer id.
    pub fn proposer(&self) -> u64 {
        self.proposer
    }
    /// The engine safety branch.
    pub fn safety_branch(&self) -> MetaBranch {
        self.safety_branch
    }
    /// The decision entrypoint kind.
    pub fn entrypoint(&self) -> EntrypointKind {
        self.entrypoint
    }
    /// The origin (proposal) view.
    pub fn origin_view(&self) -> u64 {
        self.origin_view
    }
    /// The candidate block id.
    pub fn candidate_id(&self) -> &[u8; 32] {
        &self.candidate_id
    }
    /// The candidate view.
    pub fn candidate_view(&self) -> u64 {
        self.candidate_view
    }
}

// -----------------------------------------------------------------------------
// Closed owning-capture payload (§5)
// -----------------------------------------------------------------------------

/// The closed owning payload carried into the engine's [`DecidedVote`] envelope
/// (§5). Fields are private and construction is controlled; it owns the proposal
/// commitment, the ancestry binding, the fixed decision metadata, the
/// [`PreparedPin`], and an additional covering reservation **declared last** so
/// the covered pin is destroyed before its covering reservation releases.
#[derive(Debug)]
pub struct OwningCapturePayload {
    proposal_binding: [u8; 32],
    ancestry: AncestryBinding,
    meta: DecisionMetadata,
    pin: PreparedPin,
    /// The additional covering reservation for the remaining envelope fields,
    /// inline binding, reservation control and padding (§8). Declared LAST so it
    /// releases only after `pin` (and the rest) are destroyed.
    _covering: super::accounting::Reservation,
}

impl OwningCapturePayload {
    pub(crate) fn new(
        proposal_binding: [u8; 32],
        ancestry: AncestryBinding,
        meta: DecisionMetadata,
        pin: PreparedPin,
        covering: super::accounting::Reservation,
    ) -> Self {
        Self {
            proposal_binding,
            ancestry,
            meta,
            pin,
            _covering: covering,
        }
    }

    /// The 32-byte proposal commitment.
    pub fn proposal_binding(&self) -> &[u8; 32] {
        &self.proposal_binding
    }
    /// The bounded ancestry binding.
    pub fn ancestry(&self) -> &AncestryBinding {
        &self.ancestry
    }
    /// The fixed decision metadata.
    pub fn meta(&self) -> &DecisionMetadata {
        &self.meta
    }
    /// The owned prepared pin.
    pub fn pin(&self) -> &PreparedPin {
        &self.pin
    }
}

// -----------------------------------------------------------------------------
// Closed owner outcome / refusal (§4)
// -----------------------------------------------------------------------------

/// A correspondence refusal: the engine decision did not correspond to the
/// sealed proof's retained restriction (§5). Distinct from proof-to-current
/// publication fencing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CorrespondenceRefusal {
    /// The engine decided `NoLock` — explicitly refused (no Locked decision).
    EngineNoLock,
    /// The engine L0 lock block id did not match the sealed proof's retained
    /// lock restriction.
    LockBlockMismatch,
    /// The engine L0 lock view did not match the sealed proof's retained lock
    /// restriction.
    LockViewMismatch,
}

/// A proposal-projection mismatch against the actual [`SafetyDecisionView`] (§5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProjectionMismatch {
    /// The originating proposer did not match the decision view.
    Proposer,
    /// The reproduced candidate id did not match the engine's candidate id.
    CandidateId,
    /// The candidate view (`header.height`) did not match the decision view.
    CandidateView,
    /// The parent relationship (incl. the `[0xFF; 32]` no-parent convention) did
    /// not match the decision view.
    Parent,
    /// The wire justification presence did not match the decision view.
    JustifyPresence,
    /// The justification block id did not match the decision view.
    JustifyBlockId,
    /// The justification logical view (wire QC `height`) did not match.
    JustifyView,
}

/// Why the owner-controlled route refused before consuming the proof (§4). Every
/// variant is returned alongside the intact [`ValidatedRecord`].
#[derive(Debug)]
pub enum OwnedCaptureRefusal {
    /// The borrowed-proof provenance precheck refused before the engine call.
    Precheck(super::prepared::CaptureRefusal),
    /// The engine made an ordinary pre-decision rejection (not safe to vote);
    /// the gate was never consulted.
    OrdinaryEngineRejection,
    /// The engine reported a required decision-view candidate absent.
    MissingCandidate,
    /// A correspondence check failed.
    Correspondence(CorrespondenceRefusal),
    /// A proposal-projection check failed.
    Projection(ProjectionMismatch),
    /// An input bound was exceeded computing the proposal commitment.
    InputBound(InputBoundRefusal),
    /// Required ancestry could not be bound.
    Ancestry(AncestryRefusal),
    /// The held-guard capture refused (stale revision, registry full, admission,
    /// …), returning the proof intact.
    Capture(super::prepared::CaptureRefusal),
}

/// The closed outcome of an owner-controlled decide-and-capture (§4). It
/// distinguishes a successful envelope, an expected pre-consumption refusal
/// carrying the intact proof and a typed reason, and an internal post-consumption
/// pairing-invariant violation carrying no fabricated proof.
pub enum OwnedDecisionOutcome {
    /// Success: the closed [`DecidedVote`] envelope owning the payload.
    Decided(DecidedVote<OwningCapturePayload>),
    /// Expected refusal before the proof was consumed: the intact proof and a
    /// typed reason.
    Refused {
        proof: ValidatedRecord,
        reason: OwnedCaptureRefusal,
    },
    /// Internal invariant violation after consumption (the engine's defensive
    /// unexpected-pairing branch returned without an envelope). No proof is
    /// fabricated.
    InvariantViolation,
}

impl std::fmt::Debug for OwnedDecisionOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The `DecidedVote` envelope is deliberately closed (no `Debug`); print
        // only the variant discriminant and the inspectable associated `Vote`.
        match self {
            OwnedDecisionOutcome::Decided(dv) => f.debug_tuple("Decided").field(dv.vote()).finish(),
            OwnedDecisionOutcome::Refused { reason, .. } => {
                f.debug_struct("Refused").field("reason", reason).finish()
            }
            OwnedDecisionOutcome::InvariantViolation => f.write_str("InvariantViolation"),
        }
    }
}

// -----------------------------------------------------------------------------
// Accounting charges (§8)
// -----------------------------------------------------------------------------

/// The additional envelope charge `size_of::<DecidedVote<OwningCapturePayload>>()
/// − size_of::<PreparedPin>()` (§8). The embedded pin remains covered by its
/// existing reservation and is counted exactly once; this delta covers the
/// remaining envelope fields, inline binding, reservation control and padding.
pub(crate) fn envelope_extra_charge() -> Option<u128> {
    let envelope = std::mem::size_of::<DecidedVote<OwningCapturePayload>>();
    let pin = std::mem::size_of::<PreparedPin>();
    (envelope as u128).checked_sub(pin as u128)
}

/// A fixed charge covering the transient hashing / traversal scratch and control
/// objects of the commitment + ancestry computation (§8). Admitted while the
/// original proof is still live (conversion overlap) and released before the
/// proof is consumed, so it never makes a "stack-only therefore free" claim.
pub(crate) fn scratch_charge() -> u128 {
    // Two sequential SHA3-256 states plus the fixed ancestry-binding control.
    (2 * std::mem::size_of::<Sha3_256>() + std::mem::size_of::<AncestryBinding>()) as u128
}

/// Reproduce the engine's current candidate-block-id algorithm node-locally
/// (`derive_block_id_from_header`): proposer id (8, LE) ‖ view (8, LE) ‖
/// parent_block_id[..16]. Parity is proven against the engine's own decision
/// views; this does not redesign block identity.
pub(crate) fn derive_block_id_local(
    proposer: u64,
    view: u64,
    parent_block_id: &[u8; 32],
) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&proposer.to_le_bytes());
    id[8..16].copy_from_slice(&view.to_le_bytes());
    id[16..32].copy_from_slice(&parent_block_id[..16]);
    id
}

/// A compile-time check keeping the fixed inline slot count visible to this
/// module (the registry owns no growable backing).
const _: () = assert!(PREPARED_SLOTS >= 1);

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_consensus::ValidatorId;
    use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate};

    fn ctx_n(n: u64) -> PinnedSafetyContext {
        PinnedSafetyContext {
            network_genesis_id: [1u8; 32],
            authority_context_ref: [2u8; 32],
            chain_id: 42,
            epoch: 7,
            qc_suite_id: 7,
            timeout_suite_id: 100,
            s_sig: 8,
            validators: (0..n).map(|i| (ValidatorId::new(i), 1u64)).collect(),
            require_height_equals_round: false,
        }
    }

    fn header(height: u64, round: u64, parent: [u8; 32], tx_count: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round,
            parent_block_id: parent,
            payload_hash: [7u8; 32],
            proposer_index: 3,
            suite_id: 9,
            tx_count,
            timestamp: 123,
            payload_kind: 0,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        }
    }

    fn qc(sig_count: usize, sig_len: usize) -> QuorumCertificate {
        QuorumCertificate {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 4,
            round: 9,
            step: 0,
            block_id: [5u8; 32],
            suite_id: 9,
            signer_bitmap: vec![0xAB, 0xCD],
            signatures: (0..sig_count).map(|_| vec![0xEEu8; sig_len]).collect(),
        }
    }

    /// `PROPOSAL_DOMAIN || canonical_body()` — the exact oracle this module
    /// streams, computed the allocating way for parity comparison only.
    fn oracle(p: &BlockProposal) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(PROPOSAL_DOMAIN);
        h.update(p.canonical_body());
        finalize(h)
    }

    #[test]
    fn commitment_streams_parity_absent_qc() {
        let p = BlockProposal {
            header: header(1, 1, [0xFF; 32], 0),
            qc: None,
            txs: vec![],
            signature: vec![0xDE; 64], // excluded from the commitment
        };
        let limits = PreparedDecisionInputLimits::from_pinned(&ctx_n(4)).unwrap();
        assert_eq!(commit_proposal(&p, &limits).unwrap(), oracle(&p));
    }

    #[test]
    fn commitment_streams_parity_present_qc_multi_tx_and_height_ne_round() {
        let mut p = BlockProposal {
            header: header(5, 9, [3u8; 32], 2), // height != round
            qc: Some(qc(3, 8)),
            txs: vec![vec![1, 2, 3], vec![9; 100]],
            signature: vec![],
        };
        p.header.tx_count = p.txs.len() as u32;
        let limits = PreparedDecisionInputLimits::from_pinned(&ctx_n(4)).unwrap();
        assert_eq!(commit_proposal(&p, &limits).unwrap(), oracle(&p));
    }

    #[test]
    fn commitment_excludes_proposer_signature() {
        let base = BlockProposal {
            header: header(1, 1, [0xFF; 32], 0),
            qc: None,
            txs: vec![],
            signature: vec![1, 2, 3],
        };
        let mut other = BlockProposal {
            signature: vec![9, 9, 9, 9],
            ..base.clone()
        };
        let limits = PreparedDecisionInputLimits::from_pinned(&ctx_n(4)).unwrap();
        // Differing ONLY in the proposer signature must not change the commitment.
        other.txs = base.txs.clone();
        assert_eq!(
            commit_proposal(&base, &limits).unwrap(),
            commit_proposal(&other, &limits).unwrap()
        );
    }

    #[test]
    fn commitment_sensitive_to_round_only_change() {
        let a = BlockProposal {
            header: header(5, 9, [3u8; 32], 0),
            qc: None,
            txs: vec![],
            signature: vec![],
        };
        let b = BlockProposal {
            header: header(5, 10, [3u8; 32], 0), // round-only change
            ..a.clone()
        };
        let limits = PreparedDecisionInputLimits::from_pinned(&ctx_n(4)).unwrap();
        assert_ne!(
            commit_proposal(&a, &limits).unwrap(),
            commit_proposal(&b, &limits).unwrap()
        );
    }

    #[test]
    fn tx_count_boundary_and_plus_one() {
        let limits = PreparedDecisionInputLimits::from_pinned(&ctx_n(4)).unwrap();
        // At the limit (1024 empty txs) the TOTAL cap is still satisfied.
        let txs = vec![Vec::<u8>::new(); limits.max_tx_count() as usize];
        let mut p = BlockProposal {
            header: header(1, 1, [0xFF; 32], txs.len() as u32),
            qc: None,
            txs,
            signature: vec![],
        };
        assert!(commit_proposal(&p, &limits).is_ok());
        // One over refuses with TxCountExceeded, before hashing.
        p.txs.push(Vec::new());
        p.header.tx_count = p.txs.len() as u32;
        assert!(matches!(
            commit_proposal(&p, &limits),
            Err(InputBoundRefusal::TxCountExceeded { .. })
        ));
    }

    #[test]
    fn tx_count_inconsistent_header_refused() {
        let limits = PreparedDecisionInputLimits::from_pinned(&ctx_n(4)).unwrap();
        let p = BlockProposal {
            header: header(1, 1, [0xFF; 32], 5), // header claims 5, actual 1
            qc: None,
            txs: vec![vec![0u8]],
            signature: vec![],
        };
        assert!(matches!(
            commit_proposal(&p, &limits),
            Err(InputBoundRefusal::TxCountInconsistent { .. })
        ));
    }

    #[test]
    fn total_canonical_cap_boundary() {
        let limits = PreparedDecisionInputLimits::from_pinned(&ctx_n(4)).unwrap();
        // A single tx just large enough to exceed the 8 MiB aggregate cap, while
        // each individual tx-length bound is satisfied is impossible (1 MiB cap),
        // so use several max-size txs to cross the total cap.
        let big = vec![0u8; limits.max_tx_len() as usize]; // 1 MiB
        let txs = vec![big; 9]; // 9 MiB > 8 MiB total
        let p = BlockProposal {
            header: header(1, 1, [0xFF; 32], txs.len() as u32),
            qc: None,
            txs,
            signature: vec![],
        };
        assert!(matches!(
            commit_proposal(&p, &limits),
            Err(InputBoundRefusal::TotalCanonicalExceeded { .. })
        ));
    }

    #[test]
    fn tx_len_boundary_and_plus_one() {
        let limits = PreparedDecisionInputLimits::from_pinned(&ctx_n(4)).unwrap();
        // Exactly at the per-tx cap is admitted (total cap still satisfied).
        let at = vec![0u8; limits.max_tx_len() as usize];
        let p_ok = BlockProposal {
            header: header(1, 1, [0xFF; 32], 1),
            qc: None,
            txs: vec![at],
            signature: vec![],
        };
        assert!(commit_proposal(&p_ok, &limits).is_ok());
        let over = vec![0u8; limits.max_tx_len() as usize + 1];
        let p_bad = BlockProposal {
            header: header(1, 1, [0xFF; 32], 1),
            qc: None,
            txs: vec![over],
            signature: vec![],
        };
        assert!(matches!(
            commit_proposal(&p_bad, &limits),
            Err(InputBoundRefusal::TxLenExceeded { .. })
        ));
    }

    #[test]
    fn qc_sig_count_bound_is_validator_count() {
        // N = 4: four signatures admitted, five refused.
        let limits = PreparedDecisionInputLimits::from_pinned(&ctx_n(4)).unwrap();
        assert_eq!(limits.max_qc_sig_count(), 4);
        let ok = BlockProposal {
            header: header(1, 1, [0xFF; 32], 0),
            qc: Some(qc(4, 8)),
            txs: vec![],
            signature: vec![],
        };
        assert!(commit_proposal(&ok, &limits).is_ok());
        let bad = BlockProposal {
            header: header(1, 1, [0xFF; 32], 0),
            qc: Some(qc(5, 8)),
            txs: vec![],
            signature: vec![],
        };
        assert!(matches!(
            commit_proposal(&bad, &limits),
            Err(InputBoundRefusal::QcSigCountExceeded { .. })
        ));
    }

    #[test]
    fn qc_sig_len_boundary_and_plus_one() {
        let limits = PreparedDecisionInputLimits::from_pinned(&ctx_n(4)).unwrap();
        let ok = BlockProposal {
            header: header(1, 1, [0xFF; 32], 0),
            qc: Some(qc(1, limits.max_qc_sig_len() as usize)),
            txs: vec![],
            signature: vec![],
        };
        assert!(commit_proposal(&ok, &limits).is_ok());
        let bad = BlockProposal {
            header: header(1, 1, [0xFF; 32], 0),
            qc: Some(qc(1, limits.max_qc_sig_len() as usize + 1)),
            txs: vec![],
            signature: vec![],
        };
        assert!(matches!(
            commit_proposal(&bad, &limits),
            Err(InputBoundRefusal::QcSigLenExceeded { .. })
        ));
    }

    #[test]
    fn empty_validator_set_is_typed_policy_error() {
        assert_eq!(
            PreparedDecisionInputLimits::from_pinned(&ctx_n(0)),
            Err(InputPolicyError::EmptyValidatorSet)
        );
    }

    #[test]
    fn derive_block_id_local_matches_engine_algorithm_shape() {
        // proposer(8 LE) || view(8 LE) || parent[..16].
        let parent = {
            let mut p = [0u8; 32];
            for (i, b) in p.iter_mut().enumerate() {
                *b = i as u8;
            }
            p
        };
        let id = derive_block_id_local(0x0102, 0x0304, &parent);
        assert_eq!(&id[..8], &0x0102u64.to_le_bytes());
        assert_eq!(&id[8..16], &0x0304u64.to_le_bytes());
        assert_eq!(&id[16..32], &parent[..16]);
    }

    #[test]
    fn envelope_extra_charge_is_envelope_minus_pin() {
        let envelope = std::mem::size_of::<DecidedVote<OwningCapturePayload>>();
        let pin = std::mem::size_of::<PreparedPin>();
        assert_eq!(envelope_extra_charge(), Some((envelope - pin) as u128));
        assert!(scratch_charge() > 0);
    }
}