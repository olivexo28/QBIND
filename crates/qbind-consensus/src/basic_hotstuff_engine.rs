//! BasicHotStuffEngine: A concrete HotStuff engine with static leader scheduling.
//!
//! This module provides a complete HotStuff-like consensus engine that:
//! - Uses a static leader schedule (round-robin based on view % n)
//! - Generates proposals when acting as leader
//! - Votes on valid proposals from the leader
//! - Integrates with `HotStuffStateEngine` for QC formation and commit tracking
//!
//! # Design Note
//!
//! This is a simplified HotStuff implementation for T56. It implements:
//! - Static leader election (view % num_validators)
//! - Basic proposal generation and voting
//! - QC formation via vote accumulation
//! - 3-chain commit rule via `HotStuffStateEngine`
//!
//! It does NOT implement:
//! - Timeouts or view-change mechanics
//! - Equivocation handling
//! - Leader rotation policies beyond simple round-robin

use crate::driver::{ConsensusEngineAction, HasCommitLog};
use crate::hotstuff_state_engine::{
    CommittedEntry, HotStuffStateEngine, VerifiedQcAdmission, VoteEvidencePlan,
    VoteEvidencePreflightError, VoteHistoryOutcome, VoteMutationReport,
};
use crate::ids::ValidatorId;
use crate::qc::{QcValidationError, QuorumCertificate};
use crate::qc_verify_domain::VerifiedQuorumCertificate;
use crate::received_vote_evidence::{
    qc_admission_control_frame_bytes, qc_buffer_control_frame_bytes, ActiveVoteContext,
    ContextInstallError, ContextInstallRefusal, EvidenceBudget, ReceivedVoteEvidenceTable,
    ReceivedVoteQcIncompleteReason, ReceivedVoteQcReportOwner, ReceivedVoteQcStageError,
    ReceivedVoteQcWire, ReceivedVoteQcWirePreparation, VerifiedVoteToken, VoteAdmissionError,
    VoteAdmissionRefusal, VoteContextInput,
};
use crate::timeout::{TimeoutAccumulator, TimeoutCertificate, TimeoutMsg, TimeoutValidationError};
use crate::validator_set::ConsensusValidatorSet;
use crate::vote_accumulator::VoteAccumulatorDisposition;

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::block_state::BlockNode;
use crate::hotstuff_state_engine::{SafetyBranch, SafetyDecision};

// ============================================================================
// Run 422 §13.6 spike: scoped borrowed safety-decision observation
// ============================================================================

/// Run 422 §13.6 spike: a minimal, opaque, read-only view of a single strict
/// ancestor of the candidate, handed to the ancestry-inspection callback of
/// [`SafetyDecisionView::for_each_ancestor`].
///
/// # Why this exists (closing an API gap)
///
/// An earlier revision passed `&BlockNode` to the ancestry callback. That
/// leaked the node's owned certificate surface: a caller could clone the
/// public `justify_qc`/`own_qc` [`QuorumCertificate`], or the
/// verified-justification `Arc`, or the whole [`BlockNode`], out of the
/// callback. This opaque view exposes **only** identifiers, the parent
/// relationship, and `Copy` scalar fields. It holds a private borrow of the
/// backing node and offers no accessor that yields an owned certificate, an
/// `Arc`, or the raw node. Certificate ownership therefore cannot escape
/// through ancestry inspection.
///
/// Every accessor returns a `Copy` scalar or a reference whose lifetime is
/// tied to the `&SafetyAncestorView` argument (and thus to the call-scoped
/// callback), so no ancestor-backed reference can be stashed beyond the
/// callback through safe code either.
pub struct SafetyAncestorView<'a, BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Private borrow of the backing node. Never exposed.
    node: &'a BlockNode<BlockIdT>,
}

impl<'a, BlockIdT> SafetyAncestorView<'a, BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// The ancestor's block id.
    pub fn id(&self) -> &BlockIdT {
        &self.node.id
    }

    /// The ancestor's view.
    pub fn view(&self) -> u64 {
        self.node.view
    }

    /// The ancestor's height in the block tree.
    pub fn height(&self) -> u64 {
        self.node.height
    }

    /// The ancestor's parent block id, if any.
    pub fn parent_id(&self) -> Option<&BlockIdT> {
        self.node.parent_id.as_ref()
    }

    /// The view of the ancestor's justification QC, if it carries one. This is
    /// a `Copy` scalar read: the certificate itself is never exposed.
    pub fn justify_view(&self) -> Option<u64> {
        self.node.justify_qc.as_ref().map(|qc| qc.view)
    }

    /// The justified block id of the ancestor's justification QC, if it carries
    /// one. A borrowed identifier only; the certificate is never exposed.
    pub fn justify_block_id(&self) -> Option<&BlockIdT> {
        self.node.justify_qc.as_ref().map(|qc| &qc.block_id)
    }

    /// Whether this ancestor carries retained verified-justification evidence.
    /// This is a `Copy` scalar read; the evidence `Arc` is never exposed.
    pub fn has_verified_justification(&self) -> bool {
        self.node.verified_justification.is_some()
    }
}

/// Run 422 §13.6 spike: a borrowed, scoped view of a *successful* safe-voting
/// decision, presented to a [`SafetyDecisionObserver`] at the exact moment the
/// engine decided it is safe to vote — AFTER the safety predicate succeeded and
/// BEFORE the self-vote (which can form a QC and raise the lock) mutates state.
///
/// # What this is NOT
///
/// This is a read-only *observation*, not provenance capture. It holds no owned
/// data, clones no certificate `Arc`, takes no admission token, performs no
/// storage capture, and confers no signing permission. All fields are borrowed
/// from the engine state for the duration of the callback only.
///
/// # Lifetime / escape
///
/// `'eng` is the borrow of the engine state that backs this view. The view is
/// handed to the observer only by shared reference (`&self`), and every
/// accessor returns either a `Copy` scalar or a reference borrowed from the
/// view. Because the observer callback returns `()` and the view never escapes
/// the engine's `&self.state` borrow, no engine-backed reference can be stored
/// beyond the callback through safe code. (Ordinary `Copy` scalars that the
/// observer reads MAY of course be retained — that is plain copied data, not an
/// engine-backed reference.)
///
/// # Ancestry access is deliberately narrow
///
/// Ancestry inspection ([`SafetyDecisionView::for_each_ancestor`]) hands the
/// observer a [`SafetyAncestorView`], **not** a `&BlockNode`. The opaque view
/// exposes only identifiers, parent relationships, and `Copy` scalar fields;
/// it exposes no owned [`QuorumCertificate`], no verified-justification
/// `Arc`, and no raw [`BlockNode`]. Certificate ownership therefore cannot
/// escape through the ancestry interface.
pub struct SafetyDecisionView<'eng, BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Engine state backing ancestry inspection (borrowed, read-only).
    state: &'eng HotStuffStateEngine<BlockIdT>,
    /// The exact candidate block the decision admitted a vote for.
    candidate: &'eng BlockNode<BlockIdT>,
    /// The lock in effect AT the decision. `None` on the NoLock branch.
    locked: Option<&'eng QuorumCertificate<BlockIdT>>,
    /// Which branch of the safe-voting rule decided safety.
    branch: SafetyBranch,
    /// The view the originating proposal/action was processed in.
    origin_view: u64,
    /// The proposer the originating proposal came from.
    from: ValidatorId,
    /// Whether the candidate carries retained verified justification evidence
    /// (i.e. it arrived via the verified entrypoint). This distinguishes the
    /// two entrypoints' evidence guarantees WITHOUT cloning the evidence.
    verified_entrypoint: bool,
}

impl<'eng, BlockIdT> SafetyDecisionView<'eng, BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// The branch of the safe-voting rule that decided this (successful) vote.
    pub fn branch(&self) -> SafetyBranch {
        self.branch
    }

    /// The view the originating proposal was processed in.
    pub fn origin_view(&self) -> u64 {
        self.origin_view
    }

    /// The proposer the originating proposal came from.
    pub fn from(&self) -> ValidatorId {
        self.from
    }

    /// Whether this decision came through the verified entrypoint (the
    /// candidate retains verified justification evidence). `false` for the
    /// legacy entrypoint.
    pub fn is_verified_entrypoint(&self) -> bool {
        self.verified_entrypoint
    }

    /// The exact candidate block id the decision admitted a vote for.
    pub fn candidate_id(&self) -> &BlockIdT {
        &self.candidate.id
    }

    /// The candidate's view.
    pub fn candidate_view(&self) -> u64 {
        self.candidate.view
    }

    /// The candidate's parent block id, if any.
    pub fn candidate_parent(&self) -> Option<&BlockIdT> {
        self.candidate.parent_id.as_ref()
    }

    /// The candidate's justification QC view, if the candidate carries one.
    pub fn candidate_justify_view(&self) -> Option<u64> {
        self.candidate.justify_qc.as_ref().map(|qc| qc.view)
    }

    /// The block id the candidate's justification QC points at, if the candidate
    /// carries a justification.
    ///
    /// This is read directly from the candidate's own logical justification and
    /// returns a *borrowed* identifier only. It never hands out the
    /// [`QuorumCertificate`], the verified-evidence `Arc`, mutable state, or any
    /// new ownership: the QC's full surface stays private to the engine. The
    /// returned reference is confined to the view's lifetime.
    pub fn candidate_justify_block_id(&self) -> Option<&BlockIdT> {
        self.candidate.justify_qc.as_ref().map(|qc| &qc.block_id)
    }

    /// The block id of the lock in effect at the decision, or `None` on the
    /// [`SafetyBranch::NoLock`] branch.
    pub fn locked_block_id(&self) -> Option<&BlockIdT> {
        self.locked.map(|qc| &qc.block_id)
    }

    /// The view of the lock in effect at the decision, or `None` on the
    /// [`SafetyBranch::NoLock`] branch.
    pub fn locked_view(&self) -> Option<u64> {
        self.locked.map(|qc| qc.view)
    }

    /// Bounded, read-only inspection of the candidate's strict ancestors.
    ///
    /// This is *optional* inspection, distinct from the ancestry the predicate
    /// actually used: on the [`SafetyBranch::ViewSufficiency`] branch the
    /// predicate short-circuited and walked NO ancestry, yet an observer may
    /// still wish to inspect it. It never changes the voting rule.
    ///
    /// Traversal starts at the candidate's parent and follows `parent_id`
    /// links. It is bounded by `max_hops` AND terminates early on a missing
    /// parent link or a block absent from the engine, so a cyclic or truncated
    /// graph can neither loop forever nor panic.
    ///
    /// Each ancestor is presented as a [`SafetyAncestorView`] — a minimal
    /// opaque handle over identifiers, the parent relationship and `Copy`
    /// scalar fields. The backing [`BlockNode`] and its owned certificates /
    /// evidence `Arc` are **never** exposed, so certificate ownership cannot
    /// escape through this interface. The block graph is neither cloned nor
    /// retained; each view's lifetime is confined to the callback.
    pub fn for_each_ancestor<F>(&self, max_hops: usize, mut f: F)
    where
        F: FnMut(&SafetyAncestorView<'_, BlockIdT>),
    {
        let mut current = self.candidate;
        let mut hops = 0usize;
        while hops < max_hops {
            let parent_id = match current.parent_id.as_ref() {
                Some(pid) => pid,
                None => break,
            };
            let parent = match self.state.get_block(parent_id) {
                Some(node) => node,
                None => break,
            };
            let ancestor = SafetyAncestorView { node: parent };
            f(&ancestor);
            current = parent;
            hops += 1;
        }
    }

    /// Bounded, read-only classification of how the candidate relates to the
    /// lock in effect at the decision, by walking `parent_id` links.
    ///
    /// This is *optional* inspection. It does NOT re-run or change the engine's
    /// authoritative voting decision: on the [`SafetyBranch::ViewSufficiency`]
    /// branch the predicate short-circuited and walked NO ancestry, yet a caller
    /// may still ask this query what the parent chain looks like. The result is
    /// descriptive only; it never promotes a missing link or an exhausted bound
    /// into proved ancestry.
    ///
    /// # Hop convention
    ///
    /// A "hop" is one parent transition (candidate → parent → grandparent …).
    /// The candidate itself is tested *before* any edge is traversed, so a
    /// candidate that equals the lock is reported as [`AncestryRelation::CandidateIsLock`]
    /// even when `max_hops == 0`. Reaching the lock after `k` parent transitions
    /// is reported as [`AncestryRelation::ReachedLock`] `{ hops: k }`, and the
    /// lock may be reached when `k == max_hops` (the bound is inclusive of the
    /// node arrived at by the `max_hops`-th hop).
    ///
    /// # Termination
    ///
    /// The walk performs at most `max_hops` parent transitions, so it always
    /// terminates within its stated bound — including on a cyclic parent graph,
    /// where it stops with [`AncestryRelation::BoundExhausted`] rather than
    /// looping. It inspects borrowed engine state in place: it allocates no
    /// collection, clones no certificate, and retains nothing.
    ///
    /// # Outcomes
    ///
    /// - [`AncestryRelation::NoLock`] — no lock was in effect at the decision.
    /// - [`AncestryRelation::CandidateIsLock`] — the candidate *is* the lock
    ///   (zero hops).
    /// - [`AncestryRelation::ReachedLock`] — the lock was reached after
    ///   `hops` (`>= 1`) parent transitions.
    /// - [`AncestryRelation::NoParentLink`] — a node on the walk has no parent
    ///   link and it is not the lock (the chain ends before the lock).
    /// - [`AncestryRelation::ParentAbsent`] — a node references a parent block
    ///   that is absent from the engine, so the chain cannot be followed.
    /// - [`AncestryRelation::BoundExhausted`] — `max_hops` parent transitions
    ///   were taken without reaching the lock (also the result for a cycle).
    pub fn ancestry_relation_to_lock(&self, max_hops: usize) -> AncestryRelation {
        let locked_block_id = match self.locked {
            Some(qc) => &qc.block_id,
            None => return AncestryRelation::NoLock,
        };

        let mut current = self.candidate;
        let mut hops = 0usize;
        loop {
            // Test the current node itself before traversing any edge. On the
            // first iteration (hops == 0) this tests the candidate, so a
            // candidate-is-lock is detected even when max_hops == 0.
            if &current.id == locked_block_id {
                return if hops == 0 {
                    AncestryRelation::CandidateIsLock
                } else {
                    AncestryRelation::ReachedLock { hops }
                };
            }

            // Not the lock: we must traverse one more parent edge to continue.
            // If the hop bound is already reached, stop without claiming
            // ancestry.
            if hops == max_hops {
                return AncestryRelation::BoundExhausted;
            }

            let parent_id = match current.parent_id.as_ref() {
                Some(pid) => pid,
                None => return AncestryRelation::NoParentLink,
            };
            current = match self.state.get_block(parent_id) {
                Some(node) => node,
                None => return AncestryRelation::ParentAbsent,
            };
            hops += 1;
        }
    }
}

/// Run 422 §13.6 spike: the bounded outcome of [`SafetyDecisionView::ancestry_relation_to_lock`].
///
/// Each variant describes *literally* what the bounded parent walk observed. A
/// missing parent link, an absent referenced block, or an exhausted hop bound
/// are each distinct from reaching the lock: none of them is presented as proved
/// ancestry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AncestryRelation {
    /// No lock was in effect at the decision (the [`SafetyBranch::NoLock`]
    /// boundary): there is no lock to relate the candidate to.
    NoLock,
    /// The candidate itself equals the lock block (zero parent transitions).
    CandidateIsLock,
    /// The lock block was reached after `hops` (`>= 1`) parent transitions.
    ReachedLock {
        /// The number of parent transitions taken to reach the lock.
        hops: usize,
    },
    /// A node on the walk has no parent link and it is not the lock: the parent
    /// chain ends before the lock is reached.
    NoParentLink,
    /// A node on the walk references a parent block that is absent from the
    /// engine, so the chain cannot be followed further.
    ParentAbsent,
    /// `max_hops` parent transitions were taken without reaching the lock. This
    /// is also the terminating outcome for a cyclic parent graph.
    BoundExhausted,
}

/// Run 422 §13.6 spike: borrowed observer of a successful safe-voting decision.
///
/// Implementors receive a [`SafetyDecisionView`] by shared reference at the
/// instant the engine decides it is safe to vote, before the self-vote mutates
/// state. The callback returns `()`: it cannot hand an owned handle, token, or
/// admission back to the engine, and (by construction of the view) cannot let
/// an engine-backed reference escape. It observes; it does not authorize.
///
/// # Escape is a compile error
///
/// An engine-backed reference obtained from the view cannot be stashed beyond
/// the callback, because every borrowing accessor ties its result to the
/// `&SafetyDecisionView` argument's (anonymous, call-scoped) lifetime:
///
/// ```compile_fail
/// use qbind_consensus::{SafetyDecisionObserver, SafetyDecisionView};
/// struct Escaper<'a> {
///     stash: Vec<&'a [u8; 32]>,
/// }
/// impl<'a> SafetyDecisionObserver<[u8; 32]> for Escaper<'a> {
///     fn observe(&mut self, decision: &SafetyDecisionView<'_, [u8; 32]>) {
///         // ERROR: the borrowed candidate id cannot outlive the callback.
///         self.stash.push(decision.candidate_id());
///     }
/// }
/// ```
///
/// Ordinary *copied* scalar data may of course be retained — that is plain
/// data, not an engine-backed reference:
///
/// ```
/// use qbind_consensus::{SafetyDecisionObserver, SafetyDecisionView};
/// #[derive(Default)]
/// struct Copier {
///     ids: Vec<[u8; 32]>,
///     views: Vec<u64>,
/// }
/// impl SafetyDecisionObserver<[u8; 32]> for Copier {
///     fn observe(&mut self, decision: &SafetyDecisionView<'_, [u8; 32]>) {
///         // OK: dereference copies the array out of the borrow.
///         self.ids.push(*decision.candidate_id());
///         self.views.push(decision.candidate_view());
///     }
/// }
/// ```
///
/// # Certificate ownership cannot escape through ancestry inspection
///
/// Ancestry inspection ([`SafetyDecisionView::for_each_ancestor`]) presents
/// each ancestor as an opaque [`SafetyAncestorView`]. It exposes identifiers
/// and `Copy` scalar fields only — there is no accessor that yields an owned
/// [`QuorumCertificate`], a verified-justification `Arc`, or the raw
/// [`BlockNode`]. An external observer that tries to clone a certificate out of
/// an ancestor therefore fails to compile (the field/accessor does not exist):
///
/// ```compile_fail
/// use qbind_consensus::{QuorumCertificate, SafetyDecisionObserver, SafetyDecisionView};
/// #[derive(Default)]
/// struct CertThief {
///     stolen: Vec<QuorumCertificate<[u8; 32]>>,
/// }
/// impl SafetyDecisionObserver<[u8; 32]> for CertThief {
///     fn observe(&mut self, decision: &SafetyDecisionView<'_, [u8; 32]>) {
///         decision.for_each_ancestor(8, |ancestor| {
///             // ERROR: `SafetyAncestorView` exposes no owned certificate;
///             // there is no `justify_qc` field/accessor to clone out.
///             self.stolen.push(ancestor.justify_qc.clone());
///         });
///     }
/// }
/// ```
///
/// The valid-use control reads only the opaque view's scalar identifiers and
/// copies them out — plain data, never a certificate:
///
/// ```
/// use qbind_consensus::{SafetyDecisionObserver, SafetyDecisionView};
/// #[derive(Default)]
/// struct AncestorIds {
///     ids: Vec<[u8; 32]>,
///     justify_views: Vec<Option<u64>>,
/// }
/// impl SafetyDecisionObserver<[u8; 32]> for AncestorIds {
///     fn observe(&mut self, decision: &SafetyDecisionView<'_, [u8; 32]>) {
///         decision.for_each_ancestor(8, |ancestor| {
///             // OK: copy identifiers and scalar fields out of the opaque view.
///             self.ids.push(*ancestor.id());
///             self.justify_views.push(ancestor.justify_view());
///         });
///     }
/// }
/// ```
pub trait SafetyDecisionObserver<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Observe a successful safe-voting decision. Called exactly once per
    /// emitted self-vote, only when the safety predicate returned `Safe(_)`.
    fn observe(&mut self, decision: &SafetyDecisionView<'_, BlockIdT>);
}

/// Run 422 §13.6 — opaque, engine-uninterpreted token a [`SafetyDecisionGate`]
/// returns to **refuse** the dependent self-vote at the real safety decision.
///
/// The engine never inspects, matches on, or acts on this value beyond
/// propagating it in a typed refusal: a gate establishes **no** authorization,
/// durable correspondence, or permission to sign, and its refusal is **not**
/// an ordinary proposal rejection nor a verified-ingestion pre-check error.
/// It is a unit marker so the gate implementation and the engine agree only
/// that "the gate declined"; the reason, if any, is the gate's own concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SafetyGateRefusal;

impl std::fmt::Display for SafetyGateRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "safety-decision gate refused the self-vote")
    }
}

/// Run 422 §13.6 — typed refusal of a gated self-vote, raised on the opt-in
/// gated ingestion routes ([`BasicHotStuffEngine::on_proposal_event_gated`] /
/// [`BasicHotStuffEngine::on_verified_proposal_event_gated`]).
///
/// A refusal is distinct from an **ordinary** proposal rejection (the gated
/// entrypoints return `Ok(None)` for those, exactly as the unobserved route
/// returns `None`) and from the verified-ingestion pre-check errors
/// ([`VerifiedProposalIngestError`]). On refusal the engine performs **no**
/// self-vote, **no** vote-derived lock transition, and emits **no** outbound
/// `Vote`; because `voted_in_view` is left unset, a later admissible proposal
/// for the same view can still be voted for (the refusal does not consume the
/// vote opportunity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatedSelfVoteRefusal {
    /// The gate was consulted at the real safe-voting decision and declined,
    /// returning its opaque [`SafetyGateRefusal`].
    GateRejected(SafetyGateRefusal),
    /// A required observation input was missing: the just-registered candidate
    /// block was not present when the decision view would have been built (for
    /// example it was evicted under block-slot pressure). The gate could not be
    /// given a faithful decision view, so the self-vote is refused rather than
    /// cast unobserved.
    MissingCandidate,
}

impl std::fmt::Display for GatedSelfVoteRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatedSelfVoteRefusal::GateRejected(r) => write!(f, "{r}"),
            GatedSelfVoteRefusal::MissingCandidate => write!(
                f,
                "gated self-vote refused: required decision-view candidate absent"
            ),
        }
    }
}

impl std::error::Error for GatedSelfVoteRefusal {}

/// Run 422 §13.6 — error of the gated **verified** ingestion entrypoint
/// ([`BasicHotStuffEngine::on_verified_proposal_event_gated`]).
///
/// It keeps the verified-ingestion pre-checks (`Ingest`) explicitly separate
/// from a gate refusal (`Gate`): an `Ingest` value means the proposal never
/// reached the safety decision (a present-QC / exact-evidence / wire-chain /
/// epoch / retention pre-check rejected it before any mutation), whereas a
/// `Gate` value means the pre-checks passed, the real safety decision was
/// `Safe(_)`, and the gate then declined the dependent self-vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatedVerifiedProposalError {
    /// A verified-ingestion pre-check rejected the proposal before the safety
    /// decision (no engine mutation, no fallback to the legacy path).
    Ingest(VerifiedProposalIngestError),
    /// The verified pre-checks passed but the gate refused the dependent
    /// self-vote at the real safety decision.
    Gate(GatedSelfVoteRefusal),
}

impl std::fmt::Display for GatedVerifiedProposalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatedVerifiedProposalError::Ingest(e) => write!(f, "{e}"),
            GatedVerifiedProposalError::Gate(r) => write!(f, "{r}"),
        }
    }
}

impl std::error::Error for GatedVerifiedProposalError {}

/// Run 422 §13.6 — opt-in, non-authorizing gate consulted **once** at the real
/// safe-voting decision, strictly **before** the dependent self-vote.
///
/// This is a bounded fallible control-flow seam, defined by trait-inversion in
/// `qbind-consensus` exactly like [`SafetyDecisionObserver`] so the engine
/// never names any downstream (node-side) type and no crate dependency cycle is
/// introduced. The gate is handed the same borrowed, stack-resident
/// [`SafetyDecisionView`] the observer sees — the decision that **actually**
/// decided safety, with the lock in effect (L0) before a same-event self-vote
/// raises it (L1) — and returns:
///
/// * `Ok(())` to **allow** the dependent self-vote (the route then proceeds
///   exactly as the corresponding unobserved route), or
/// * `Err(SafetyGateRefusal)` to **refuse** it, after which the engine performs
///   no self-vote, no lock transition, and emits no `Vote`.
///
/// The gate must use **no panic** for a normal refusal. It establishes **no**
/// authorization, durable correspondence, or permission to sign; it is purely a
/// fallible decision-point control that can veto the self-vote.
pub trait SafetyDecisionGate<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Evaluate the real safe-voting decision and decide whether the dependent
    /// self-vote may proceed. Called exactly once per `Safe(_)` decision on the
    /// gated route, strictly before the self-vote. `Ok(())` allows the vote;
    /// `Err(_)` refuses it with no self-vote, lock transition, or emitted
    /// `Vote`.
    fn evaluate(
        &mut self,
        decision: &SafetyDecisionView<'_, BlockIdT>,
    ) -> Result<(), SafetyGateRefusal>;
}

/// Run 422 §13.6 — isolated, opt-in **owning** decision-to-vote handoff gate
/// (additive, NOT wired to any production caller).
///
/// This is the owning analogue of [`SafetyDecisionGate`]. Where the plain gate
/// may only **veto** the self-vote (`Ok(())` / `Err`), an owning gate that
/// allows the self-vote additionally **produces an opaque payload `P`** which
/// the engine transports — unexamined — across the self-vote into a closed
/// [`DecidedVote`] envelope. The engine never names, inspects, extracts, or
/// replaces `P`; it only moves and later drops it. This preserves the same
/// trait-inversion discipline as [`SafetyDecisionObserver`]/[`SafetyDecisionGate`]
/// (no `qbind-consensus` → node dependency) while letting a node-side gate hand
/// an owned reservation/pin payload back alongside the resulting `Vote`.
///
/// The payload is produced **inside** the gate call, at the real safe-voting
/// decision and strictly **before** the dependent self-vote; a refusal
/// (`Err(SafetyGateRefusal)`) yields no payload, no self-vote, no lock
/// transition, and no emitted `Vote`, identically to the plain gated route.
///
/// Ownership/association only: an allowed payload establishes same-invocation
/// association between the returned `Vote` and whatever the gate chose to own.
/// It establishes **no** authorization, durable correspondence, verification,
/// or permission to sign.
pub trait OwningSafetyDecisionGate<BlockIdT, P>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Evaluate the real safe-voting decision and, on allow, produce the opaque
    /// owning payload `P` transported into the [`DecidedVote`]. Called exactly
    /// once per `Safe(_)` decision, strictly before the self-vote. `Err(_)`
    /// refuses the self-vote with no payload, self-vote, lock transition, or
    /// emitted `Vote`. The gate must use no panic for a normal refusal.
    fn evaluate_owning(
        &mut self,
        decision: &SafetyDecisionView<'_, BlockIdT>,
    ) -> Result<P, SafetyGateRefusal>;
}

/// Limits admitted by the owner before the isolated leader route constructs
/// any covered candidate or signer storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderRouteLimits {
    max_qc_signers: usize,
}

impl LeaderRouteLimits {
    pub const fn new(max_qc_signers: usize) -> Self {
        Self { max_qc_signers }
    }

    pub const fn max_qc_signers(self) -> usize {
        self.max_qc_signers
    }
}

/// Immutable engine-selected values supplied with the actual leader proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderProposalContext {
    proposer: ValidatorId,
    origin_view: u64,
    candidate_id: [u8; 32],
    candidate_view: u64,
    epoch: u64,
    parent_block_id: [u8; 32],
    justification: Option<LeaderJustification>,
    proposal_suite_id: u16,
    vote_suite_id: u16,
    payload_kind: u8,
    next_epoch: u64,
}

impl LeaderProposalContext {
    pub fn proposer(&self) -> ValidatorId { self.proposer }
    pub fn origin_view(&self) -> u64 { self.origin_view }
    pub fn candidate_id(&self) -> &[u8; 32] { &self.candidate_id }
    pub fn candidate_view(&self) -> u64 { self.candidate_view }
    pub fn epoch(&self) -> u64 { self.epoch }
    pub fn parent_block_id(&self) -> &[u8; 32] { &self.parent_block_id }
    pub fn justification(&self) -> Option<LeaderJustification> { self.justification }
    pub fn proposal_suite_id(&self) -> u16 { self.proposal_suite_id }
    pub fn vote_suite_id(&self) -> u16 { self.vote_suite_id }
    pub fn payload_kind(&self) -> u8 { self.payload_kind }
    pub fn next_epoch(&self) -> u64 { self.next_epoch }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderJustification {
    pub block_id: [u8; 32],
    pub view: u64,
    pub signer_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct LeaderPreflight {
    candidate_id: [u8; 32],
    parent_block_id: [u8; 32],
    origin_view: u64,
    epoch: u64,
    reconfiguration_intent: Option<u64>,
    justification: LeaderJustification,
}

/// Same-invocation callback input; the Proposal is the exact engine-created
/// value that will be paired with the self-Vote.
pub struct LeaderCaptureInput<'a> {
    context: LeaderProposalContext,
    proposal: &'a qbind_wire::consensus::BlockProposal,
}

impl<'a> LeaderCaptureInput<'a> {
    pub fn context(&self) -> &LeaderProposalContext { &self.context }
    pub fn proposal(&self) -> &'a qbind_wire::consensus::BlockProposal { self.proposal }
}

pub trait LeaderProposalGate<P> {
    fn route_limits(&self) -> LeaderRouteLimits;
    fn capture_l0(
        &mut self,
        input: &LeaderCaptureInput<'_>,
    ) -> Result<P, SafetyGateRefusal>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaderVoteRefusal {
    Duplicate,
    CapacityDropped,
    Equivocation,
    NonMember,
    Processing(QcValidationError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaderRouteRefusal {
    NonLeader,
    AlreadyProposed,
    AlreadyVoted,
    NoLock,
    ProposerIndexOverflow,
    NonMember,
    PriorSameCandidateVote,
    ConflictingVoteHistory,
    CandidateCollision,
    BlockCapacity,
    SignerBoundExceeded,
    Arithmetic,
    Allocation,
    CaptureGateRefused,
    VoteNotAccepted(LeaderVoteRefusal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderRouteEffects {
    pub candidate_registered: bool,
    pub proposed_flag_set: bool,
    pub voted_flag_set: bool,
    pub vote_history_recorded: bool,
    pub history_entries_evicted: u64,
    pub accumulator_views_evicted: u64,
    pub accumulator_inserted: bool,
    pub accumulator_duplicate: bool,
    pub accumulator_capacity_dropped: bool,
    pub equivocation_recorded: bool,
    pub qc_formed: bool,
    pub qc_processed: bool,
    pub qc_processing_succeeded: bool,
    pub view_advanced: bool,
    pub reconfiguration_intent_consumed: bool,
}

impl LeaderRouteEffects {
    fn initial() -> Self {
        Self {
            candidate_registered: false,
            proposed_flag_set: false,
            voted_flag_set: false,
            vote_history_recorded: false,
            history_entries_evicted: 0,
            accumulator_views_evicted: 0,
            accumulator_inserted: false,
            accumulator_duplicate: false,
            accumulator_capacity_dropped: false,
            equivocation_recorded: false,
            qc_formed: false,
            qc_processed: false,
            qc_processing_succeeded: false,
            view_advanced: false,
            reconfiguration_intent_consumed: false,
        }
    }
}

/// Closed owner-independent envelope for the exact engine-created Proposal
/// and Vote. Accessors never transfer either message or payload.
pub struct DecidedLeaderProposal<P> {
    proposal: qbind_wire::consensus::BlockProposal,
    vote: qbind_wire::consensus::Vote,
    payload: P,
    effects: LeaderRouteEffects,
}

impl<P> DecidedLeaderProposal<P> {
    pub fn proposal(&self) -> &qbind_wire::consensus::BlockProposal { &self.proposal }
    pub fn vote(&self) -> &qbind_wire::consensus::Vote { &self.vote }
    pub fn payload(&self) -> &P { &self.payload }
    pub fn effects(&self) -> &LeaderRouteEffects { &self.effects }
}

pub struct LeaderPostCaptureFailure<P> {
    proposal: qbind_wire::consensus::BlockProposal,
    vote: qbind_wire::consensus::Vote,
    payload: P,
    reason: LeaderRouteRefusal,
    effects: LeaderRouteEffects,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderPostCaptureDiagnostic {
    pub reason: LeaderRouteRefusal,
    pub effects: LeaderRouteEffects,
}

impl<P> LeaderPostCaptureFailure<P> {
    pub fn into_diagnostic(self) -> LeaderPostCaptureDiagnostic {
        let Self { proposal, vote, payload, reason, effects } = self;
        drop(proposal);
        drop(vote);
        drop(payload);
        LeaderPostCaptureDiagnostic { reason, effects }
    }
}

pub enum LeaderProposalRouteResult<P> {
    Refused(LeaderRouteRefusal),
    Decided(DecidedLeaderProposal<P>),
    PostCapture(LeaderPostCaptureFailure<P>),
}

/// Concrete compiled-layout data for owner-side admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderRouteLayout {
    pub preflight: u128,
    pub context: u128,
    pub callback_input: u128,
    pub payload: u128,
    pub registration_plan: u128,
    pub signer_buffer: u128,
    pub vote_report: u128,
    pub envelope: u128,
    pub engine_result: u128,
}

pub fn leader_route_layout<P>() -> LeaderRouteLayout {
    use std::mem::size_of;
    LeaderRouteLayout {
        preflight: size_of::<LeaderPreflight>() as u128,
        context: size_of::<LeaderProposalContext>() as u128,
        callback_input: size_of::<LeaderCaptureInput<'static>>() as u128,
        payload: size_of::<P>() as u128,
        registration_plan: size_of::<crate::hotstuff_state_engine::LeaderRegistrationPlan<[u8; 32]>>() as u128,
        signer_buffer: size_of::<LeaderSignerBuffer>() as u128,
        vote_report: size_of::<crate::hotstuff_state_engine::LeaderSelfVoteReport>() as u128,
        envelope: size_of::<DecidedLeaderProposal<P>>() as u128,
        engine_result: size_of::<LeaderProposalRouteResult<P>>() as u128,
    }
}

/// Run 422 §13.6 — closed envelope pairing the engine's own emitted `Vote` with
/// an opaque owning payload `P` produced by an [`OwningSafetyDecisionGate`].
///
/// The envelope is deliberately **closed**:
/// * fields are private and there is **no** `Clone`/`Copy`;
/// * there is **no** payload extraction, replacement, or mutable access, and no
///   `into_parts()`; only the immutable [`DecidedVote::vote`] inspector exists;
/// * it is constructed **only** on the engine emission path
///   ([`BasicHotStuffEngine::on_proposal_event_gated_owning`]) via a
///   module-private constructor — a downstream consumer cannot fabricate one or
///   swap in a replacement `Vote`.
///
/// A consumer may therefore inspect the associated `Vote` and **abandon** the
/// envelope (drop it), but cannot separate the `Vote` from its payload. This is
/// one-use ownership transport, not replay prevention.
///
/// # External API is closed (compile-fail controls)
///
/// The following examples are external-crate controls: each forbidden operation
/// is a **compile error**, and the paired valid-use control compiles. They prove
/// the closure from outside `qbind_consensus`, not from a privileged in-module
/// test.
///
/// **Private construction** — there is no public constructor and the fields are
/// private, so a downstream crate cannot fabricate an envelope (or swap in a
/// replacement `Vote`):
///
/// ```compile_fail
/// use qbind_consensus::DecidedVote;
/// // ERROR: associated function `new` is private and the fields are private;
/// // the only way to obtain a `DecidedVote` is the engine emission path.
/// let _d: DecidedVote<u8> = DecidedVote::new(todo!(), 0u8);
/// ```
///
/// **No `Clone`/`Copy` of the envelope** — the envelope itself cannot be
/// duplicated (there is no `Clone`/`Copy` impl):
///
/// ```compile_fail
/// use qbind_consensus::DecidedVote;
/// fn f(d: DecidedVote<u8>) {
///     // ERROR: `DecidedVote` does not implement `Clone` — the envelope and its
///     // payload cannot be duplicated.
///     let _dup = d.clone();
/// }
/// ```
///
/// **No mutable `Vote` access** — the only accessor hands out a shared reference,
/// so the carried `Vote` cannot be mutated in place:
///
/// ```compile_fail
/// use qbind_consensus::DecidedVote;
/// fn f(d: DecidedVote<u8>) {
///     // ERROR: `vote()` yields `&Vote`; the carried vote cannot be assigned
///     // through a shared reference, and there is no `vote_mut`.
///     d.vote().height = 9;
/// }
/// ```
///
/// **No payload / parts extraction** — the payload is private and there is no
/// `into_parts`/`into_payload`, so the `Vote` can never be separated from it:
///
/// ```compile_fail
/// use qbind_consensus::DecidedVote;
/// fn f(d: DecidedVote<u8>) {
///     // ERROR: field `payload` is private and there is no `into_parts()` to
///     // split the envelope into its `Vote` and payload.
///     let _p: u8 = d.payload;
/// }
/// ```
///
/// **Use after move** — abandoning (moving) the envelope consumes it; it is not
/// `Copy`, so a later use does not compile:
///
/// ```compile_fail
/// use qbind_consensus::DecidedVote;
/// fn f(d: DecidedVote<u8>) {
///     let _abandoned = d;        // move the envelope out
///     let _again = d.vote();     // ERROR: use of moved value (`DecidedVote` is not `Copy`)
/// }
/// ```
///
/// **Valid-use control (this compiles):** the envelope may be inspected
/// read-only and abandoned, and `vote().clone()` may produce a **detached plain
/// `Vote`** — a copy of the carried vote that is no longer part of any envelope
/// and carries no payload. Cloning the *vote* is not cloning the *envelope*:
///
/// ```
/// use qbind_consensus::DecidedVote;
/// fn f(d: DecidedVote<u8>) {
///     // OK: read-only inspection of the carried vote.
///     let _height = d.vote().height;
///     // OK: a DETACHED plain `Vote` (not the envelope, not the payload).
///     let _detached = d.vote().clone();
///     // OK: abandon the envelope (drop destroys `vote` then `payload`).
///     drop(d);
/// }
/// ```
///
/// **Drop order.** `vote` is declared before `payload`, and Rust drops struct
/// fields in declaration order, so the `Vote` and (transitively) all
/// payload-covered data are destroyed **before** any reservation the payload
/// declares last is released. The node-side payload relies on this to release
/// its trailing reservation only after the data it covers is gone.
pub struct DecidedVote<P> {
    /// The engine's own emitted self-vote. Declared FIRST so it drops before the
    /// payload. Exposed read-only via [`DecidedVote::vote`].
    vote: qbind_wire::consensus::Vote,
    /// Opaque owning payload produced by the gate. Declared LAST so it (and any
    /// reservation it declares last) is dropped after `vote`. Never inspected,
    /// extracted, or replaced by the engine or this type.
    ///
    /// `#[allow(dead_code)]`: the engine holds the payload purely to own it and
    /// drop it (RAII); it never reads it. Dropping the envelope destroys `vote`
    /// then this payload.
    #[allow(dead_code)]
    payload: P,
}

impl<P> DecidedVote<P> {
    /// Module-private constructor: only the engine emission path can build a
    /// `DecidedVote`, binding the engine's own `Vote` to the gate's payload.
    fn new(vote: qbind_wire::consensus::Vote, payload: P) -> Self {
        Self { vote, payload }
    }

    /// Immutable inspection of the associated `Vote`. This is the **only**
    /// accessor; there is no way to take, replace, or mutate the carried `Vote`
    /// in place, nor to reach the payload. Because `Vote` is itself `Clone`,
    /// `vote().clone()` **can** produce a detached plain `Vote` — a standalone
    /// copy of the carried vote — but that clone is not part of this (or any)
    /// envelope and carries no payload: cloning the `Vote` neither duplicates the
    /// `DecidedVote` envelope nor its owning payload.
    pub fn vote(&self) -> &qbind_wire::consensus::Vote {
        &self.vote
    }

    /// Immutable, **borrow-only** inspection of the owning payload (RUN 422
    /// §13.6). This is the ONLY payload accessor; it hands out a shared `&P`
    /// and never takes, replaces, mutates, consumes, or recombines the payload.
    /// The envelope remains closed: there is still no `into_parts`/`into_payload`
    /// and no way to separate the `Vote` from its payload, so an isolated
    /// non-consuming observer can read the captured association through `&self`
    /// while the engine-produced `Vote` stays bound to its original payload.
    ///
    /// A `&P` borrow is sound even though the node-side payload transitively
    /// holds interior mutability (its `PreparedPin` owns an
    /// `Arc<Mutex<PreparedRegistry>>` and its reservations carry shared
    /// accounting state): the payload exposes only `&self` non-mutating methods
    /// over private fields, so a shared borrow cannot extract or alter it.
    pub fn payload(&self) -> &P {
        &self.payload
    }
}

/// Internal adapter: presents an [`OwningSafetyDecisionGate`] as a plain
/// [`SafetyDecisionGate`] so the owning route reuses the landed
/// [`DecisionHook::Gate`] body verbatim. On allow it stashes the produced
/// payload for the entrypoint to pair with the emitted `Vote`; on refusal it
/// stashes nothing (the inner `Err` propagates unchanged).
struct OwningGateAdapter<'g, P> {
    gate: &'g mut dyn OwningSafetyDecisionGate<[u8; 32], P>,
    captured: Option<P>,
}

impl<P> SafetyDecisionGate<[u8; 32]> for OwningGateAdapter<'_, P> {
    fn evaluate(
        &mut self,
        decision: &SafetyDecisionView<'_, [u8; 32]>,
    ) -> Result<(), SafetyGateRefusal> {
        // Allow => capture the opaque payload; refusal => propagate unchanged,
        // leaving `captured` as `None`.
        self.captured = Some(self.gate.evaluate_owning(decision)?);
        Ok(())
    }
}

/// Internal: which fallible/observing hook (if any) is driven at the real
/// safety decision inside [`BasicHotStuffEngine::ingest_proposal`]. Replaces the
/// former `observer: Option<&mut dyn SafetyDecisionObserver>` parameter so the
/// unobserved, observed, and gated routes share one body without conflating
/// their guarantees.
enum DecisionHook<'a> {
    /// Unobserved legacy / verified route: no callback at the decision. Behaves
    /// byte-for-byte as before.
    None,
    /// Observed route: the borrowed observer sees the decision; a missing
    /// candidate silently refuses the self-vote (preserved historical
    /// behavior).
    Observe(&'a mut dyn SafetyDecisionObserver<[u8; 32]>),
    /// Gated route: the borrowed gate may veto the self-vote. A refusal (or a
    /// missing candidate) is reported out-of-band through `refusal`, and the
    /// body returns no action, leaving `voted_in_view` unset.
    Gate {
        /// The borrowed fallible gate consulted at the decision.
        gate: &'a mut dyn SafetyDecisionGate<[u8; 32]>,
        /// Out-slot set to the typed refusal when the gate declines or the
        /// decision-view candidate is absent; left `None` when the gate allows.
        refusal: &'a mut Option<GatedSelfVoteRefusal>,
    },
}

// ============================================================================
// ViewDurationRecorder - Metrics callback trait (T90.5)
// ============================================================================

/// Trait for recording view/round duration metrics.
///
/// This trait allows external metrics systems to receive view duration
/// notifications without introducing a hard dependency from qbind-consensus
/// to qbind-node.
///
/// # Implementation Note
///
/// The default implementation is a no-op, allowing engines to be created
/// without metrics for testing purposes.
pub trait ViewDurationRecorder: Send + Sync + std::fmt::Debug {
    /// Record the duration of a completed view.
    ///
    /// This is called whenever the engine transitions from one view to the next.
    /// The duration represents the time from when the previous view was activated
    /// until the new view is activated.
    ///
    /// # Arguments
    ///
    /// * `duration` - The duration of the completed view
    /// * `from_view` - The view number that just completed
    /// * `to_view` - The view number being entered
    fn record_view_duration(&self, duration: Duration, from_view: u64, to_view: u64);
}

/// No-op implementation of `ViewDurationRecorder` for tests.
#[derive(Debug, Default)]
pub struct NoopViewDurationRecorder;

impl ViewDurationRecorder for NoopViewDurationRecorder {
    fn record_view_duration(&self, _duration: Duration, _from_view: u64, _to_view: u64) {
        // No-op
    }
}

// ============================================================================
// ConsensusProgressRecorder - Metrics callback trait (T127)
// ============================================================================

/// Trait for recording consensus progress metrics.
///
/// This trait allows external metrics systems to receive notifications about
/// consensus progress events without introducing a hard dependency from
/// qbind-consensus to qbind-node.
///
/// # Events Tracked
///
/// - QC formation: when a quorum certificate is successfully formed
/// - Vote observation: when a valid vote is accepted
/// - View changes: when the engine transitions to a new view
/// - Leader changes: when the leader for a new view differs from previous
///
/// # Implementation Note
///
/// The default implementation is a no-op, allowing engines to be created
/// without metrics for testing purposes.
pub trait ConsensusProgressRecorder: Send + Sync + std::fmt::Debug {
    /// Record that a QC was formed.
    ///
    /// This is called exactly once per QC that is actually used by the engine
    /// (not for every deserialized QC).
    fn record_qc_formed(&self);

    /// Record that a QC was formed with latency information.
    ///
    /// This is called with the duration from view start to QC formation.
    fn record_qc_formed_with_latency(&self, _latency: Duration) {
        // Default: just record the QC without latency
        self.record_qc_formed();
    }

    /// Record that a vote was observed.
    ///
    /// This is called when a valid, epoch-correct vote is accepted.
    ///
    /// # Arguments
    ///
    /// * `is_for_current_view` - Whether the vote is for the current view
    fn record_vote_observed(&self, is_for_current_view: bool);

    /// Record a view change.
    ///
    /// This is called when the engine advances to a new view.
    ///
    /// # Arguments
    ///
    /// * `from_view` - The view being left
    /// * `to_view` - The view being entered
    fn record_view_change(&self, from_view: u64, to_view: u64);

    /// Record a leader change.
    ///
    /// This is called when the leader for the new view differs from the previous view.
    /// In round-robin leader selection, this equals view changes.
    fn record_leader_change(&self);

    /// Reset the current view vote counter.
    ///
    /// This is called when transitioning to a new view to reset the
    /// approximate gauge of votes in the current view.
    fn reset_current_view_votes(&self);
}

/// No-op implementation of `ConsensusProgressRecorder` for tests.
#[derive(Debug, Default)]
pub struct NoopConsensusProgressRecorder;

impl ConsensusProgressRecorder for NoopConsensusProgressRecorder {
    fn record_qc_formed(&self) {
        // No-op
    }

    fn record_vote_observed(&self, _is_for_current_view: bool) {
        // No-op
    }

    fn record_view_change(&self, _from_view: u64, _to_view: u64) {
        // No-op
    }

    fn record_leader_change(&self) {
        // No-op
    }

    fn reset_current_view_votes(&self) {
        // No-op
    }
}

// ============================================================================
// ValidatorVoteRecorder - Per-validator vote metrics callback trait (T128)
// ============================================================================

/// Trait for recording per-validator vote metrics (T128).
///
/// This trait allows external metrics systems to receive notifications about
/// individual validator vote events without introducing a hard dependency from
/// qbind-consensus to qbind-node.
///
/// # Events Tracked
///
/// - `on_validator_vote`: Called when a valid vote is accepted from a validator
///
/// # Important
///
/// Only call this for valid, epoch-correct votes. Do not call for:
/// - Rejected votes (wrong epoch, wrong suite, invalid signature)
/// - Equivocating votes (already recorded; the first vote was valid)
///
/// # Implementation Note
///
/// The default implementation is a no-op, allowing engines to be created
/// without metrics for testing purposes.
pub trait ValidatorVoteRecorder: Send + Sync + std::fmt::Debug {
    /// Record a vote from a specific validator.
    ///
    /// This is called when a valid vote is accepted by the engine.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator who cast the vote
    /// * `view` - The view number of the vote
    fn on_validator_vote(&self, validator_id: ValidatorId, view: u64);
}

/// No-op implementation of `ValidatorVoteRecorder` for tests.
#[derive(Debug, Default)]
pub struct NoopValidatorVoteRecorder;

impl ValidatorVoteRecorder for NoopValidatorVoteRecorder {
    fn on_validator_vote(&self, _validator_id: ValidatorId, _view: u64) {
        // No-op
    }
}

// ============================================================================
// ValidatorEquivocationRecorder - Per-validator equivocation metrics callback (T129)
// ============================================================================

/// Trait for recording per-validator equivocation events (T129).
///
/// This trait allows external metrics systems to receive notifications about
/// equivocation events without introducing a hard dependency from qbind-consensus
/// to qbind-node.
///
/// # Events Tracked
///
/// - `on_validator_equivocation`: Called when equivocation is detected for a validator
///
/// # Important
///
/// This is called exactly once per equivocation event. A validator can equivocate
/// multiple times in different views, and each event triggers a callback.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` as the callback may be invoked from
/// different threads.
pub trait ValidatorEquivocationRecorder: Send + Sync + std::fmt::Debug {
    /// Record an equivocation event from a specific validator.
    ///
    /// This is called when a validator votes for different blocks in the same view.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator who equivocated
    /// * `view` - The view number where equivocation occurred
    fn on_validator_equivocation(&self, validator_id: ValidatorId, view: u64);
}

/// No-op implementation of `ValidatorEquivocationRecorder` for tests.
#[derive(Debug, Default)]
pub struct NoopValidatorEquivocationRecorder;

impl ValidatorEquivocationRecorder for NoopValidatorEquivocationRecorder {
    fn on_validator_equivocation(&self, _validator_id: ValidatorId, _view: u64) {
        // No-op
    }
}

// ============================================================================
// BasicHotStuffEngine
// ============================================================================

/// A concrete HotStuff engine with static leader scheduling.
///
/// This struct wraps a `HotStuffStateEngine` and adds:
/// - Local validator identity
/// - View tracking
/// - Static leader schedule
/// - Proposal and vote generation logic
/// - View duration metrics (T90.5)
///
/// # Type Parameter
///
/// - `BlockIdT`: The type used to identify blocks. Must implement `Eq + Hash + Clone`.
///   The canonical type in qbind-consensus is `[u8; 32]`.
///
/// # View Duration Metrics (T90.5)
///
/// The engine tracks the start time of each view and computes the duration
/// when transitioning to the next view. This duration is reported via an
/// optional `ViewDurationRecorder` callback.
///
/// Definition of "view duration":
/// - Time from when view `v` is activated (via `advance_view()` or `set_view()`)
/// - Until view `v+1` is activated
///
/// Caveats:
/// - The first view duration after restart includes time since `initialize_from_restart()`
/// - View durations use monotonic time (`std::time::Instant`), not wall-clock
pub struct BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Local validator id (identity of this node in the validator set).
    local_id: ValidatorId,

    /// Underlying HotStuff state (block tree, QCs, commits).
    state: HotStuffStateEngine<BlockIdT>,

    /// Simple view counter for this node.
    current_view: u64,

    /// Current epoch number (T101).
    ///
    /// All votes, proposals, and QCs produced by this engine will carry this epoch.
    /// Messages from a different epoch will be rejected.
    ///
    /// For now, this is always EpochId(0) and is static (no epoch transitions).
    /// Future tasks will add epoch transition support.
    current_epoch: u64,

    /// Cached leader ordering for this validator set (static, sorted ascending).
    leaders: Vec<ValidatorId>,

    /// Whether we have already proposed in the current view.
    proposed_in_view: bool,

    /// Whether we have already voted in the current view.
    voted_in_view: bool,

    /// Timestamp when the current view started (T90.5).
    ///
    /// Used to compute view duration when transitioning to the next view.
    /// Set to `Some(Instant::now())` on construction and view transitions.
    last_view_start_instant: Option<Instant>,

    /// Optional metrics recorder for view durations (T90.5).
    ///
    /// If `None`, view durations are computed but not recorded.
    view_duration_recorder: Option<Arc<dyn ViewDurationRecorder>>,

    /// Optional metrics recorder for consensus progress (T127).
    ///
    /// If `None`, consensus progress events are not recorded.
    progress_recorder: Option<Arc<dyn ConsensusProgressRecorder>>,

    /// Optional metrics recorder for per-validator vote tracking (T128).
    ///
    /// If `None`, per-validator vote events are not recorded.
    validator_vote_recorder: Option<Arc<dyn ValidatorVoteRecorder>>,

    /// Optional metrics recorder for per-validator equivocation tracking (T129).
    ///
    /// If `None`, equivocation events are not recorded.
    equivocation_recorder: Option<Arc<dyn ValidatorEquivocationRecorder>>,

    /// Timeout message accumulator for view-change (T146).
    ///
    /// Collects timeout messages from validators and forms TimeoutCertificates
    /// when 2f+1 validators have timed out for the same view.
    timeout_accumulator: TimeoutAccumulator<[u8; 32]>,

    /// Whether we have already emitted a timeout message for the current view (T146).
    timeout_emitted_in_view: bool,

    /// Run 096 — pending local-operator-gated reconfig proposal intent.
    ///
    /// When `Some(target_epoch)` and this engine is the leader for the
    /// current view, the next [`on_leader_step`] / [`try_propose`] call
    /// will construct the leader proposal as a canonical reconfig block
    /// (`payload_kind = PAYLOAD_KIND_RECONFIG`, `next_epoch = target_epoch`)
    /// instead of a normal block, and clear the intent. The intent is
    /// **single-shot**: after one emission the field is cleared and the
    /// engine returns to emitting normal proposals.
    ///
    /// This is the only canonical place a release-binary leader can be
    /// directed to propose a reconfig block under the existing HotStuff
    /// proposal path. The intent is supplied by the binary via the
    /// operator-gated `--devnet-reconfig-proposal-next-epoch <N>` CLI
    /// flag (DevNet/TestNet-only; refused on MainNet). The engine never
    /// derives the target epoch from wall-clock, height, view, or timer
    /// ticks — the value is exactly what the operator supplied.
    ///
    /// Validation at intent-set time enforces `target_epoch >
    /// current_epoch`. At consumption time the same monotonicity check
    /// is repeated and a stale intent (target ≤ current — i.e. the
    /// engine already advanced past the target by other means) is
    /// silently dropped (no synthetic reconfig is emitted). See
    /// `on_leader_step` for the consumption site.
    pending_reconfig_next_epoch: Option<u64>,

    /// Run 422 — suite identifier stamped on this engine's OWN outgoing
    /// `Vote` messages (the leader's self-vote and the follower self-vote in
    /// the shared ingestion body). It is OUTGOING-VOTE METADATA ONLY: it is
    /// written verbatim into the `suite_id` field of the `Vote` this engine
    /// constructs and establishes NO key availability, backend support,
    /// verification, authorization, or permission to sign. It never touches
    /// the proposal header's `suite_id` or the embedded QC's `suite_id`.
    ///
    /// The value is fixed at construction and is IMMUTABLE thereafter: there
    /// is no setter and no consuming reconfiguration builder, so a running
    /// engine's suite cannot be changed while preserving its consensus state.
    /// Every existing constructor (`new`, `with_state_limits`) initializes it
    /// to [`qbind_wire::DEFAULT_CONSENSUS_SUITE_ID`]; only the dedicated
    /// [`Self::with_state_limits_and_vote_suite`] constructor selects a
    /// different value, and only when building a fresh engine from
    /// initialization inputs.
    vote_suite_id: u16,

    /// Isolated received-Vote context owner. No production route consumes it.
    active_received_vote_context: Option<ActiveVoteContext>,

    /// Terminal producer disable set before exposing mutable state access.
    received_vote_producer_disabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifiedVoteInvocationRefusal {
    ProducerDisabled,
    NoContext,
    NoTable,
    StaleContext,
    ForeignLedger,
    EpochOrRosterMismatch,
    InvalidLease,
    TableFull,
    AccountingInvariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceivedVoteEvidenceDisposition {
    Retained,
    ExistingExactDuplicate,
    ExistingDifferentSignature,
    ExistingSignedFieldsConflict,
    NotRetainedEquivocation,
    NotRetainedCapacityDropped,
    NotRetainedMembershipLost,
}

pub(crate) enum VerifiedVoteInvocation {
    Refused {
        token: VerifiedVoteToken,
        reason: VerifiedVoteInvocationRefusal,
    },
    Invoked {
        report: VoteMutationReport<[u8; 32]>,
        evidence: ReceivedVoteEvidenceDisposition,
        view_advanced: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceivedVoteQcRefusalReason {
    Invocation(VerifiedVoteInvocationRefusal),
    Stage(ReceivedVoteQcStageError),
}

#[derive(Debug)]
pub(crate) struct ReceivedVoteQcRefusal {
    pub(crate) token: VerifiedVoteToken,
    pub(crate) reason: ReceivedVoteQcRefusalReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceivedVoteQcIncomplete {
    MissingEvidence(u16),
    ContextMismatch(u16),
    SignerMismatch(u16),
    CandidateMismatch(u16),
    CommonFieldsMismatch(u16),
    SignatureShapeMismatch(u16),
    ActualCandidateMismatch,
    ActualSignerCountMismatch,
    ActualSignerOutOfRange(u64),
    ActualSignerDuplicate(u64),
    ActualSignerMembershipMismatch(u64),
}

pub(crate) struct ReceivedVoteQcEventSummary {
    pub(crate) history: VoteHistoryOutcome<[u8; 32]>,
    pub(crate) accumulator: Option<Result<VoteAccumulatorDisposition, QcValidationError>>,
    pub(crate) evidence: ReceivedVoteEvidenceDisposition,
    pub(crate) view_advanced: bool,
    pub(crate) qc: Option<ReceivedVoteQcSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReceivedVoteQcSummary {
    pub(crate) block_id: [u8; 32],
    pub(crate) view: u64,
    pub(crate) signer_count: usize,
}

pub(crate) enum ReceivedVoteQcOutcome {
    NoQc,
    Incomplete(ReceivedVoteQcIncomplete),
    Complete(ReceivedVoteQcWire),
    LogicalError(QcValidationError),
}

pub(crate) struct ReceivedVoteQcReport {
    pub(crate) actual: ReceivedVoteQcEventSummary,
    pub(crate) outcome: ReceivedVoteQcOutcome,
    pub(crate) _provenance: ReceivedVoteQcReportOwner,
}

struct ReceivedVoteQcCandidateSeal {
    block_id: [u8; 32],
    view: u64,
    incoming_validator: ValidatorId,
    projected_count: usize,
    membership: [u64; 16],
}

struct ReceivedVoteQcRouteControlFrame {
    token: Option<VerifiedVoteToken>,
    preflight: Option<VerifiedVotePreflight>,
    report_owner: Option<ReceivedVoteQcReportOwner>,
    projection: Option<crate::vote_accumulator::VoteAccumulatorProjection<'static, [u8; 32]>>,
    candidate: Option<ReceivedVoteQcCandidateSeal>,
    control_charge: Option<Result<u64, ReceivedVoteQcStageError>>,
    wire_preparation: Option<Result<ReceivedVoteQcWirePreparation, ReceivedVoteQcStageError>>,
    wire: Option<ReceivedVoteQcWire>,
    mutation: Option<VoteMutationReport<[u8; 32]>>,
    actual: Option<ReceivedVoteQcEventSummary>,
    outcome: Option<ReceivedVoteQcOutcome>,
    report: Option<ReceivedVoteQcReport>,
    refusal: Option<ReceivedVoteQcRefusal>,
    return_carrier: Option<Result<ReceivedVoteQcReport, ReceivedVoteQcRefusal>>,
}

/// Peer-learned certified block material used by restore catchup.
struct VerifiedVotePreflight {
    plan: VoteEvidencePlan,
    shrink_to: u64,
    existing: Option<ReceivedVoteEvidenceDisposition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreCatchupBlock<BlockIdT> {
    /// Block height in QBIND's current binary path (height == view).
    pub height: u64,
    /// View/round at which the block was proposed.
    pub view: u64,
    /// Parent block id the restored node must already know or have just learned.
    pub parent_block_id: BlockIdT,
    /// Block id being certified.
    pub block_id: BlockIdT,
    /// Proposer for `view`; must match the deterministic leader schedule.
    pub proposer: ValidatorId,
    /// Logical QC signers learned from the peer.
    pub qc_signers: Vec<ValidatorId>,
}

/// Run 096 — fail-closed errors from
/// [`BasicHotStuffEngine::set_pending_reconfig_next_epoch`].
///
/// The setter refuses to arm an invalid local-operator-gated reconfig
/// proposal intent so an operator can never silently configure the
/// binary leader to propose a regressive, equal, or zero `next_epoch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingReconfigIntentError {
    /// `target_epoch` was zero. The engine treats `0` as "no epoch
    /// requested" (matching the `BlockHeader.next_epoch` semantics
    /// for `PAYLOAD_KIND_NORMAL`) and refuses to arm such an intent.
    TargetEpochZero,
    /// `target_epoch` was not strictly greater than the engine's
    /// current epoch (equal or regressive). Reconfig must always
    /// advance the epoch monotonically — the engine's own
    /// `transition_to_epoch` enforces the same invariant.
    NonMonotonicTarget {
        current_epoch: u64,
        target_epoch: u64,
    },
}

impl std::fmt::Display for PendingReconfigIntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PendingReconfigIntentError::TargetEpochZero => write!(
                f,
                "pending_reconfig_intent_invalid: target_epoch=0 (zero target is not a \
                 valid reconfig request; fail closed)"
            ),
            PendingReconfigIntentError::NonMonotonicTarget {
                current_epoch,
                target_epoch,
            } => write!(
                f,
                "pending_reconfig_intent_invalid: target_epoch={} must be strictly greater \
                 than current_epoch={} (no equal, no regress; fail closed)",
                target_epoch, current_epoch
            ),
        }
    }
}

impl std::error::Error for PendingReconfigIntentError {}

/// Run 422 D7-C3F: bounded, typed rejection taxonomy for the verified
/// embedded-QC ingestion entrypoint
/// ([`BasicHotStuffEngine::on_verified_proposal_event`]).
///
/// Every variant carries only small scalars (chain ids, epochs, byte counts) —
/// never a certificate, signature bytes, or key material. A rejection never
/// mutates engine state and never falls back to the legacy/raw entrypoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedProposalIngestError {
    /// The proposal carried no embedded QC. The verified path requires a
    /// present embedded QC; absent-QC/bootstrap authorization is out of scope
    /// and must be handled by the legacy path, never routed here.
    MissingEmbeddedQc,
    /// The supplied verified evidence does not correspond exactly to the
    /// proposal's present embedded QC (some wire field, the signer bitmap, or a
    /// signature byte differs).
    EvidenceCertificateMismatch,
    /// The proposal's wire `chain_id` disagrees with the wire chain the
    /// evidence records verification against.
    WireChainMismatch {
        /// The outer proposal header's wire `chain_id`.
        proposal_chain_id: u32,
        /// The wire `chain_id` the evidence was verified under.
        evidence_chain_id: u32,
    },
    /// The proposal's `epoch` disagrees with the authorized epoch the evidence
    /// records verification against.
    EpochMismatch {
        /// The outer proposal header's epoch.
        proposal_epoch: u64,
        /// The authorized epoch the evidence was verified under.
        evidence_epoch: u64,
    },
    /// Retaining the certificate would exceed the retained-evidence byte
    /// budget. Rejected before any engine mutation; no partial effect.
    RetentionBudgetExceeded {
        /// Bytes the new evidence would have required.
        needed_bytes: u64,
        /// Bytes already retained across all blocks.
        retained_bytes: u64,
        /// The configured hard ceiling.
        max_bytes: u64,
    },
    /// Block-slot pressure could not be relieved without evicting the candidate
    /// block itself (the block tree is at its `max_pending_blocks` limit and no
    /// other block is safe to evict). Rejected before any engine mutation — in
    /// particular before view advancement, block-tree changes, self-voting or
    /// any outbound effect — so the candidate is neither retained-then-evicted
    /// nor voted for. No partial effect.
    RetentionCapacityUnavailable {
        /// Number of blocks currently in the tree.
        block_count: usize,
        /// The configured maximum number of pending blocks.
        max_pending_blocks: usize,
    },
    /// The evidence's checked retained-byte charge (or the projected total) is
    /// not representable, so the accounting invariant cannot be upheld.
    /// Rejected explicitly before any engine mutation rather than saturated
    /// into an admissible total. No partial effect.
    RetentionChargeUnrepresentable,
}

impl std::fmt::Display for VerifiedProposalIngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifiedProposalIngestError::MissingEmbeddedQc => {
                write!(f, "verified ingestion requires a present embedded QC")
            }
            VerifiedProposalIngestError::EvidenceCertificateMismatch => write!(
                f,
                "supplied evidence does not correspond exactly to the embedded QC"
            ),
            VerifiedProposalIngestError::WireChainMismatch {
                proposal_chain_id,
                evidence_chain_id,
            } => write!(
                f,
                "proposal wire chain_id {proposal_chain_id} != evidence wire chain_id \
                 {evidence_chain_id}"
            ),
            VerifiedProposalIngestError::EpochMismatch {
                proposal_epoch,
                evidence_epoch,
            } => write!(
                f,
                "proposal epoch {proposal_epoch} != evidence authorized epoch {evidence_epoch}"
            ),
            VerifiedProposalIngestError::RetentionBudgetExceeded {
                needed_bytes,
                retained_bytes,
                max_bytes,
            } => write!(
                f,
                "retained-evidence budget exceeded: needed={needed_bytes} \
                 retained={retained_bytes} max={max_bytes}"
            ),
            VerifiedProposalIngestError::RetentionCapacityUnavailable {
                block_count,
                max_pending_blocks,
            } => write!(
                f,
                "block-slot capacity unavailable: block_count={block_count} \
                 max_pending_blocks={max_pending_blocks} (no non-candidate block \
                 safe to evict)"
            ),
            VerifiedProposalIngestError::RetentionChargeUnrepresentable => write!(
                f,
                "retained-evidence charge or projected total is not representable"
            ),
        }
    }
}

impl std::error::Error for VerifiedProposalIngestError {}

/// Fail-closed restore-catchup validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreCatchupError<BlockIdT> {
    /// Local engine has no committed anchor to extend.
    MissingLocalAnchor,
    /// Catchup material does not extend the local committed anchor.
    AnchorMismatch {
        expected_height: u64,
        actual_height: u64,
        expected_block_id: BlockIdT,
        actual_parent_block_id: BlockIdT,
    },
    /// Heights must be contiguous and strictly above the current committed height.
    NonContiguousHeight { expected: u64, actual: u64 },
    /// Current binary path requires height == view.
    HeightViewMismatch { height: u64, view: u64 },
    /// Proposer must match deterministic leader for the view.
    WrongProposer {
        view: u64,
        expected: ValidatorId,
        actual: ValidatorId,
    },
    /// Block id must match deterministic binary-path derivation.
    BlockIdMismatch {
        height: u64,
        expected: BlockIdT,
        actual: BlockIdT,
    },
    /// Learned QC did not satisfy logical quorum validation.
    InvalidQc(QcValidationError),
}

// Manual Debug implementation because Arc<dyn ViewDurationRecorder> uses Debug
impl<BlockIdT> std::fmt::Debug for BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicHotStuffEngine")
            .field("local_id", &self.local_id)
            .field("state", &self.state)
            .field("current_view", &self.current_view)
            .field("current_epoch", &self.current_epoch)
            .field("leaders", &self.leaders)
            .field("proposed_in_view", &self.proposed_in_view)
            .field("voted_in_view", &self.voted_in_view)
            .field("last_view_start_instant", &self.last_view_start_instant)
            .field("view_duration_recorder", &self.view_duration_recorder)
            .field("progress_recorder", &self.progress_recorder)
            .field("validator_vote_recorder", &self.validator_vote_recorder)
            .field("equivocation_recorder", &self.equivocation_recorder)
            .field("timeout_accumulator", &self.timeout_accumulator)
            .field("timeout_emitted_in_view", &self.timeout_emitted_in_view)
            .field("pending_reconfig_next_epoch", &self.pending_reconfig_next_epoch)
            .field("vote_suite_id", &self.vote_suite_id)
            .field(
                "active_received_vote_context",
                &self
                    .active_received_vote_context
                    .as_ref()
                    .map(|_| "<installed>"),
            )
            .field(
                "received_vote_producer_disabled",
                &self.received_vote_producer_disabled,
            )
            .finish()
    }
}

impl<BlockIdT> BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Create a new `BasicHotStuffEngine` with the given local id and validator set.
    ///
    /// The engine starts at view 0, epoch 0 with no blocks, no locked QC, and no commits.
    /// View timing starts from construction time.
    pub fn new(local_id: ValidatorId, validators: ConsensusValidatorSet) -> Self {
        let leaders = Self::sorted_leader_ids(&validators);
        let state = HotStuffStateEngine::new(validators);
        Self::assemble(
            local_id,
            state,
            leaders,
            qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        )
    }

    /// Create a new `BasicHotStuffEngine` whose block-tree state engine uses
    /// the supplied memory limits (e.g. a small `max_pending_blocks`) instead
    /// of the defaults. All other engine state matches [`Self::new`].
    ///
    /// This mirrors [`HotStuffStateEngine::with_limits`] and exists so callers
    /// (and tests) can exercise block-slot pressure through the full engine
    /// path without reaching into private state.
    pub fn with_state_limits(
        local_id: ValidatorId,
        validators: ConsensusValidatorSet,
        limits: crate::vote_accumulator::ConsensusLimitsConfig,
    ) -> Self {
        let leaders = Self::sorted_leader_ids(&validators);
        let state = HotStuffStateEngine::with_limits(validators, limits);
        Self::assemble(
            local_id,
            state,
            leaders,
            qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        )
    }

    /// Run 422 — create a fresh `BasicHotStuffEngine` that uses the supplied
    /// block-tree memory limits AND stamps `suite_id` on its own outgoing
    /// `Vote` messages. This is the ONLY constructor that selects a non-default
    /// outgoing-Vote suite.
    ///
    /// It takes exactly the [`Self::with_state_limits`] initialization inputs
    /// plus `suite_id: u16`, and builds a brand-new engine from those inputs
    /// (view 0, epoch 0, no blocks/QC/commits, timing from construction). It
    /// deliberately does NOT accept an existing engine, so there is no way to
    /// re-point a running engine's suite while preserving its consensus state;
    /// combined with the absence of any setter or consuming reconfiguration
    /// builder, outgoing-Vote-suite selection is construction-only.
    ///
    /// The selected suite is OUTGOING-VOTE METADATA ONLY. It establishes no key
    /// availability, backend support, verification, authorization, or
    /// permission to sign; downstream signing composition must still enforce
    /// the four-way (Vote, signer, key, backend) suite agreement independently.
    pub fn with_state_limits_and_vote_suite(
        local_id: ValidatorId,
        validators: ConsensusValidatorSet,
        limits: crate::vote_accumulator::ConsensusLimitsConfig,
        suite_id: u16,
    ) -> Self {
        let leaders = Self::sorted_leader_ids(&validators);
        let state = HotStuffStateEngine::with_limits(validators, limits);
        Self::assemble(local_id, state, leaders, suite_id)
    }

    /// Deterministic, ascending-sorted leader ordering for a validator set.
    /// Shared by every constructor so leader selection is identical regardless
    /// of limits or outgoing-Vote-suite selection.
    fn sorted_leader_ids(validators: &ConsensusValidatorSet) -> Vec<ValidatorId> {
        let mut ids: Vec<ValidatorId> = validators.iter().map(|v| v.id).collect();
        ids.sort_by_key(|id| id.0);
        ids
    }

    /// Shared engine assembly from already-constructed parts. Centralizes every
    /// non-suite default so the public constructors differ ONLY in how `state`
    /// is built and which `vote_suite_id` they supply; no unrelated default is
    /// changed by adding the suite field.
    fn assemble(
        local_id: ValidatorId,
        state: HotStuffStateEngine<BlockIdT>,
        leaders: Vec<ValidatorId>,
        vote_suite_id: u16,
    ) -> Self {
        BasicHotStuffEngine {
            local_id,
            state,
            current_view: 0,
            current_epoch: 0, // Default to epoch 0 (T101)
            leaders,
            proposed_in_view: false,
            voted_in_view: false,
            last_view_start_instant: Some(Instant::now()),
            view_duration_recorder: None,
            progress_recorder: None,
            validator_vote_recorder: None,
            equivocation_recorder: None,
            timeout_accumulator: TimeoutAccumulator::new(),
            timeout_emitted_in_view: false,
            pending_reconfig_next_epoch: None,
            vote_suite_id,
            active_received_vote_context: None,
            received_vote_producer_disabled: false,
        }
    }

    /// Attach a view duration recorder for metrics (T90.5).
    ///
    /// The recorder will be called on each view transition with the
    /// duration of the completed view.
    ///
    /// # Arguments
    ///
    /// * `recorder` - An Arc to a `ViewDurationRecorder` implementation
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    pub fn with_view_duration_recorder(mut self, recorder: Arc<dyn ViewDurationRecorder>) -> Self {
        self.view_duration_recorder = Some(recorder);
        self
    }

    /// Set the view duration recorder after construction (T90.5).
    ///
    /// This is useful when the metrics handle is not available at construction time.
    pub fn set_view_duration_recorder(&mut self, recorder: Arc<dyn ViewDurationRecorder>) {
        self.view_duration_recorder = Some(recorder);
    }

    /// Attach a consensus progress recorder for metrics (T127).
    ///
    /// The recorder will be called on consensus events like QC formation,
    /// vote observation, and view changes.
    ///
    /// # Arguments
    ///
    /// * `recorder` - An Arc to a `ConsensusProgressRecorder` implementation
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    pub fn with_progress_recorder(mut self, recorder: Arc<dyn ConsensusProgressRecorder>) -> Self {
        self.progress_recorder = Some(recorder);
        self
    }

    /// Set the consensus progress recorder after construction (T127).
    ///
    /// This is useful when the metrics handle is not available at construction time.
    pub fn set_progress_recorder(&mut self, recorder: Arc<dyn ConsensusProgressRecorder>) {
        self.progress_recorder = Some(recorder);
    }

    /// Attach a per-validator vote recorder for metrics (T128).
    ///
    /// The recorder will be called for each valid vote accepted by the engine.
    ///
    /// # Arguments
    ///
    /// * `recorder` - An Arc to a `ValidatorVoteRecorder` implementation
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    pub fn with_validator_vote_recorder(
        mut self,
        recorder: Arc<dyn ValidatorVoteRecorder>,
    ) -> Self {
        self.validator_vote_recorder = Some(recorder);
        self
    }

    /// Set the per-validator vote recorder after construction (T128).
    ///
    /// This is useful when the metrics handle is not available at construction time.
    pub fn set_validator_vote_recorder(&mut self, recorder: Arc<dyn ValidatorVoteRecorder>) {
        self.validator_vote_recorder = Some(recorder);
    }

    /// Attach a per-validator equivocation recorder for metrics (T129).
    ///
    /// The recorder will be called for each equivocation event detected by the engine.
    ///
    /// # Arguments
    ///
    /// * `recorder` - An Arc to a `ValidatorEquivocationRecorder` implementation
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    pub fn with_equivocation_recorder(
        mut self,
        recorder: Arc<dyn ValidatorEquivocationRecorder>,
    ) -> Self {
        self.equivocation_recorder = Some(recorder);
        self
    }

    /// Set the per-validator equivocation recorder after construction (T129).
    ///
    /// This is useful when the metrics handle is not available at construction time.
    pub fn set_equivocation_recorder(&mut self, recorder: Arc<dyn ValidatorEquivocationRecorder>) {
        self.equivocation_recorder = Some(recorder);
    }

    /// Get the local validator id.
    pub fn local_id(&self) -> ValidatorId {
        self.local_id
    }

    /// Get the current view.
    pub fn current_view(&self) -> u64 {
        self.current_view
    }

    /// Get the current epoch (T101).
    ///
    /// Returns the epoch number used for all consensus messages produced by this engine.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Set the current epoch (T101).
    ///
    /// This should be called at startup to set the epoch from the configured EpochState.
    /// For now, this is a simple setter. Future tasks will add epoch transition logic.
    ///
    /// # Arguments
    ///
    /// * `epoch` - The epoch number to use for all consensus messages.
    pub fn set_current_epoch(&mut self, epoch: u64) {
        if self.current_epoch != epoch {
            self.invalidate_received_vote_context();
        }
        self.current_epoch = epoch;
    }

    fn invalidate_received_vote_context(&mut self) {
        self.active_received_vote_context = None;
        self.state.clear_received_vote_evidence();
    }

    pub fn set_max_retained_evidence_bytes(&mut self, max: u64) {
        self.state.set_max_retained_evidence_bytes(max);
    }

    /// Run 096 — set the pending local-operator-gated reconfig proposal
    /// intent.
    ///
    /// When set, the next leader-step proposal this engine emits will
    /// carry `payload_kind = PAYLOAD_KIND_RECONFIG` and
    /// `next_epoch = target_epoch` instead of a normal block. The
    /// intent is **single-shot**: it is cleared as soon as the engine
    /// emits one proposal carrying it (regardless of whether that
    /// proposal subsequently commits). This matches `task/RUN_096_TASK.txt`
    /// §"3. Inject intent into leader proposal construction" — "once
    /// proposal is emitted or committed, avoid repeated uncontrolled
    /// proposals".
    ///
    /// # Validation
    ///
    /// Enforces:
    /// - `target_epoch` must be strictly greater than the engine's
    ///   current epoch (no equal, no regress). Matches the same
    ///   monotonicity invariant `transition_to_epoch` enforces.
    ///
    /// On invalid input, returns `Err(PendingReconfigIntentError::*)`
    /// and leaves the field unchanged (fail-closed). The binary
    /// surfaces this as a refused-startup error so an operator can
    /// never silently arm an invalid reconfig proposal.
    ///
    /// Run 096 does NOT derive the target epoch from wall-clock time,
    /// block height, view number, or timer ticks — the value is
    /// exactly what the caller (the binary CLI handler) passed in.
    pub fn set_pending_reconfig_next_epoch(
        &mut self,
        target_epoch: u64,
    ) -> Result<(), PendingReconfigIntentError> {
        if target_epoch == 0 {
            return Err(PendingReconfigIntentError::TargetEpochZero);
        }
        if target_epoch <= self.current_epoch {
            return Err(PendingReconfigIntentError::NonMonotonicTarget {
                current_epoch: self.current_epoch,
                target_epoch,
            });
        }
        self.pending_reconfig_next_epoch = Some(target_epoch);
        Ok(())
    }

    /// Run 096 — current pending reconfig intent (test/inspection
    /// surface). Returns `None` when no intent is armed.
    pub fn pending_reconfig_next_epoch(&self) -> Option<u64> {
        self.pending_reconfig_next_epoch
    }

    /// Run 096 — explicitly clear any pending reconfig intent without
    /// emitting a proposal. Used only when the engine state has
    /// diverged from the intent's preconditions (e.g. concurrent
    /// epoch advance from a peer-driven path that does not exist in
    /// Run 096 but is reserved for future governance integration).
    pub fn clear_pending_reconfig_next_epoch(&mut self) {
        self.pending_reconfig_next_epoch = None;
    }

    /// Transition to a new epoch (T102).
    ///
    /// This method is called when a reconfiguration block is committed. It:
    /// 1. Validates that the transition is sequential (N → N+1)
    /// 2. Updates `current_epoch` to the new epoch
    /// 3. Updates the validator set and leader cache
    ///
    /// # Arguments
    ///
    /// * `new_epoch` - The new epoch ID to transition to
    /// * `new_validator_set` - The validator set for the new epoch
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the transition succeeded
    /// * `Err(EpochTransitionError)` if the transition is invalid
    ///
    /// # Design Note
    ///
    /// For T102, we keep it strict: the new epoch must be exactly current_epoch + 1.
    /// The caller is responsible for validating the EpochState against governance
    /// before calling this method.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // On reconfig block commit:
    /// let next_epoch_state = provider.get_epoch_state(next_epoch_id).unwrap();
    /// next_epoch_state.validate_with_governance_strict(...)?;
    /// engine.transition_to_epoch(next_epoch_id, next_epoch_state.validator_set)?;
    /// ```
    pub fn transition_to_epoch(
        &mut self,
        new_epoch: crate::validator_set::EpochId,
        new_validator_set: ConsensusValidatorSet,
    ) -> Result<(), crate::validator_set::EpochTransitionError> {
        let current = crate::validator_set::EpochId::new(self.current_epoch);
        let expected_next = crate::validator_set::EpochId::new(self.current_epoch + 1);

        // Enforce sequential epoch transitions
        if new_epoch != expected_next {
            return Err(
                crate::validator_set::EpochTransitionError::NonSequentialEpoch {
                    current,
                    requested: new_epoch,
                },
            );
        }

        self.invalidate_received_vote_context();

        // Update epoch atomically
        self.current_epoch = new_epoch.as_u64();

        // Update leader cache
        let mut ids: Vec<ValidatorId> = new_validator_set.iter().map(|v| v.id).collect();
        ids.sort_by_key(|id| id.0);
        self.leaders = ids;

        // Update the underlying state engine's validator set while preserving
        // committed state (block tree, locked QC, commit log, etc.)
        self.state.update_validators(new_validator_set);

        eprintln!(
            "[T102] Epoch transition complete: {} -> {}",
            current, new_epoch
        );

        Ok(())
    }

    /// Get the leader for a given view (round-robin).
    ///
    /// # Panics
    ///
    /// Panics if the validator set is empty. This should never happen since
    /// `ConsensusValidatorSet::new` enforces non-empty validator sets.
    pub fn leader_for_view(&self, view: u64) -> ValidatorId {
        let n = self.leaders.len() as u64;
        assert!(n > 0, "validator set must not be empty");
        let idx = (view % n) as usize;
        self.leaders[idx]
    }

    /// Check if this node is the leader for the current view.
    pub fn is_leader_for_current_view(&self) -> bool {
        self.leader_for_view(self.current_view) == self.local_id
    }

    /// Get the underlying state engine.
    pub fn state(&self) -> &HotStuffStateEngine<BlockIdT> {
        &self.state
    }

    /// Mutably access the underlying state engine.
    pub fn state_mut(&mut self) -> &mut HotStuffStateEngine<BlockIdT> {
        self.invalidate_received_vote_context();
        self.received_vote_producer_disabled = true;
        self.state.drop_received_vote_evidence_table();
        &mut self.state
    }

    /// Get the current locked QC, if any.
    pub fn locked_qc(&self) -> Option<&QuorumCertificate<BlockIdT>> {
        self.state.locked_qc()
    }

    /// Get the latest committed block id, if any.
    pub fn committed_block(&self) -> Option<&BlockIdT> {
        self.state.committed_block()
    }

    /// Get a reference to the validator set.
    pub fn validators(&self) -> &ConsensusValidatorSet {
        self.state.validators()
    }

    /// Get the commit log (sequence of committed blocks).
    pub fn commit_log(&self) -> &[CommittedEntry<BlockIdT>] {
        self.state.commit_log()
    }

    /// Advance to the next view.
    ///
    /// This resets the `proposed_in_view`, `voted_in_view`, and `timeout_emitted_in_view` flags.
    ///
    /// # Metrics (T90.5)
    ///
    /// If a view duration recorder is attached, computes the duration since
    /// the view started and reports it to the recorder.
    ///
    /// # Metrics (T127)
    ///
    /// If a progress recorder is attached, records view change and leader
    /// change events.
    pub fn advance_view(&mut self) {
        let from_view = self.current_view;
        let to_view = self.current_view + 1;

        // Compute and record view duration if we have a start timestamp
        self.record_view_duration_internal(from_view, to_view);

        // Record consensus progress metrics (T127)
        self.record_progress_view_change_internal(from_view, to_view);

        self.current_view = to_view;
        self.proposed_in_view = false;
        self.voted_in_view = false;
        self.timeout_emitted_in_view = false; // T146: Reset timeout flag

        // Start timing for the new view
        self.last_view_start_instant = Some(Instant::now());
    }

    /// Internal helper to compute and record view duration (T90.5).
    fn record_view_duration_internal(&self, from_view: u64, to_view: u64) {
        if let (Some(start), Some(recorder)) = (
            self.last_view_start_instant,
            self.view_duration_recorder.as_ref(),
        ) {
            let duration = start.elapsed();
            recorder.record_view_duration(duration, from_view, to_view);
        }
    }

    /// Internal helper to record progress metrics on view change (T127).
    fn record_progress_view_change_internal(&self, from_view: u64, to_view: u64) {
        if let Some(recorder) = self.progress_recorder.as_ref() {
            // Record view change
            recorder.record_view_change(from_view, to_view);

            // Reset current view votes counter
            recorder.reset_current_view_votes();

            // Check for leader change by comparing actual leaders for the views
            // This handles both round-robin and any future leader selection policies
            let from_leader = self.leader_for_view(from_view);
            let to_leader = self.leader_for_view(to_view);
            if from_leader != to_leader {
                recorder.record_leader_change();
            }
        }
    }

    /// Set the current view directly (for restart recovery).
    ///
    /// This is used when restoring state from persistence to set the view
    /// to the height/view of the last committed block + 1.
    ///
    /// # Safety Note
    ///
    /// This should only be called during startup/restart, not during normal
    /// consensus operation. Setting view incorrectly could violate liveness.
    ///
    /// # Metrics (T90.5)
    ///
    /// If transitioning from a different view, records the duration of the
    /// previous view. The new view timing starts from this call.
    pub fn set_view(&mut self, view: u64) {
        let from_view = self.current_view;

        // Record duration of the previous view if we're changing views
        if view != from_view {
            self.record_view_duration_internal(from_view, view);
        }

        self.current_view = view;
        self.proposed_in_view = false;
        self.voted_in_view = false;
        self.timeout_emitted_in_view = false; // T146: Reset timeout flag

        // Start timing for the new view
        self.last_view_start_instant = Some(Instant::now());
    }

    /// Get the committed height, if any.
    ///
    /// Returns the height of the latest committed block, or `None` if no
    /// block has been committed yet.
    pub fn committed_height(&self) -> Option<u64> {
        self.state.committed_height()
    }

    /// Initialize the engine from persisted restart state.
    ///
    /// This method restores the engine to a safe state based on the last
    /// committed block from persistence. Call this during node startup after
    /// loading state from `ConsensusStorage`.
    ///
    /// # Restart Semantics (T84)
    ///
    /// ## What is Restored
    ///
    /// - **Committed block**: The engine recognizes this block as committed
    /// - **Committed height**: Used for monotonicity checks
    /// - **Locked QC**: Set conservatively to prevent voting for conflicting blocks
    /// - **Current view**: Set to `committed_height + 1` to resume from next view
    ///
    /// ## What is NOT Restored
    ///
    /// - **In-flight proposals**: Lost; will be re-proposed by leaders
    /// - **Pending votes**: Lost; safe because we restart from committed state
    /// - **High QC vs Locked QC distinction**: We conservatively treat them as same
    /// - **Vote accumulator**: Starts fresh
    ///
    /// ## Safety Guarantee
    ///
    /// This approach is safe because:
    /// 1. The committed prefix has a 3-chain QC and cannot be reverted
    /// 2. Setting locked_qc prevents voting for conflicting blocks
    /// 3. Setting view to `committed_height + 1` prevents re-committing old blocks
    ///
    /// ## Liveness Trade-off
    ///
    /// The conservative locked_qc may delay voting until a new proposal arrives
    /// with a QC at or above the locked view. This is acceptable for restart
    /// scenarios where safety is paramount.
    ///
    /// # Arguments
    ///
    /// - `committed_block_id`: The block ID of the last committed block
    /// - `committed_height`: The height of the last committed block
    /// - `locked_qc`: Optional QC for locking (typically QC for the committed block)
    ///
    /// # Metrics (T90.5)
    ///
    /// Initializes view timing from this point. The first view duration after
    /// restart will include any time from this call until the first view change.
    /// This is documented and acceptable behavior.
    pub fn initialize_from_restart(
        &mut self,
        committed_block_id: BlockIdT,
        committed_height: u64,
        locked_qc: Option<QuorumCertificate<BlockIdT>>,
    ) {
        // Initialize the underlying state engine
        self.state
            .initialize_from_restart(committed_block_id, committed_height, locked_qc);

        // Set view to committed_height + 1 to resume from the next view
        // This ensures we don't re-propose or re-vote for already committed heights
        self.current_view = committed_height.saturating_add(1);
        self.proposed_in_view = false;
        self.voted_in_view = false;
        self.timeout_emitted_in_view = false; // T146: Reset timeout flag

        // Initialize view timing from restart (T90.5)
        // The first view duration will include time since this call
        self.last_view_start_instant = Some(Instant::now());
    }

    /// Initialize the engine from a restored *state snapshot* baseline (B5).
    ///
    /// This is the binary-path restore-aware consensus start hook. Unlike
    /// [`Self::initialize_from_restart`], which assumes we have a full
    /// committed-block view (including the consensus-side QC and view
    /// history), this method only needs what a `StateSnapshotMeta`
    /// actually carries today: the snapshot's `height` and a `block_hash`
    /// that we reuse as an opaque parent identifier.
    ///
    /// # Effect
    ///
    /// After this call:
    ///
    /// 1. `committed_height()` returns `Some(snapshot_height)`.
    /// 2. The snapshot anchor block is registered in the block tree at
    ///    `height = snapshot_height` (so the next leader proposal —
    ///    parented by [`HotStuffStateEngine::committed_block()`] — gets
    ///    height `snapshot_height + 1`, not `0`).
    /// 3. `current_view` is set to `snapshot_height + 1`.
    ///
    /// # Why `view = height + 1`
    ///
    /// In `BasicHotStuffEngine`'s binary path, a leader proposal at the
    /// current view encodes both `header.height = current_view` and
    /// `header.round = current_view`, and the resulting committed entry
    /// records `height = view`. The 3-chain commit monotonicity check
    /// (`g_height > committed_height`) therefore requires the next
    /// proposal — and thus the next view — to be at least
    /// `snapshot_height + 1`. Setting `current_view = snapshot_height + 1`
    /// is the smallest rule that (a) avoids re-proposing at a height
    /// already covered by the snapshot and (b) immediately satisfies the
    /// monotonicity precondition for new commits. This matches the
    /// established convention used by [`Self::initialize_from_restart`]
    /// (`current_view = committed_height + 1`).
    ///
    /// # Bounds and honesty
    ///
    /// - This does **not** restore consensus QCs, vote history, or block
    ///   tree above the snapshot anchor. We do not invent data the
    ///   snapshot does not carry.
    /// - This is a *single-validator-safe* baseline; multi-validator
    ///   restore semantics (P2P chain catchup) are not solved here.
    /// - This is startup-only. Calling it during steady-state operation
    ///   could violate liveness; the binary calls it exactly once, before
    ///   the consensus loop ticks.
    pub fn initialize_from_snapshot_baseline(
        &mut self,
        snapshot_block_id: BlockIdT,
        snapshot_height: u64,
    ) {
        // Seed the underlying state engine: committed prefix + tree entry.
        // We pass `committed_view = snapshot_height` because the binary
        // engine conflates view and height (proposals carry
        // `header.height = current_view`).
        self.state.initialize_from_snapshot_baseline(
            snapshot_block_id,
            snapshot_height,
            snapshot_height,
        );

        // Resume consensus from the next view. The first proposal after
        // this call will be at view = snapshot_height + 1, parented by the
        // snapshot anchor, and will register at height = snapshot_height + 1.
        self.current_view = snapshot_height.saturating_add(1);
        self.proposed_in_view = false;
        self.voted_in_view = false;
        self.timeout_emitted_in_view = false;
        self.last_view_start_instant = Some(Instant::now());
    }
}

// ============================================================================
// HasCommitLog implementation for BasicHotStuffEngine
// ============================================================================

impl<BlockIdT> HasCommitLog<BlockIdT> for BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    fn commit_log(&self) -> &[CommittedEntry<BlockIdT>] {
        self.state.commit_log()
    }
}

#[cfg(test)]
std::thread_local! {
    static LEADER_SIGNER_ALLOC_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LEADER_SIGNER_ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LEADER_SIGNER_DEALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LEADER_SIGNER_TRANSFERS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn allocate_leader_signers(layout: std::alloc::Layout) -> *mut u8 {
    #[cfg(test)]
    {
        if LEADER_SIGNER_ALLOC_FAIL.with(std::cell::Cell::get) {
            return std::ptr::null_mut();
        }
        LEADER_SIGNER_ALLOCATIONS.with(|count| count.set(count.get() + 1));
    }
    // SAFETY: callers pass a checked Layout and handle a null result.
    unsafe { std::alloc::alloc(layout) }
}

unsafe fn deallocate_leader_signers(ptr: *mut u8, layout: std::alloc::Layout) {
    #[cfg(test)]
    LEADER_SIGNER_DEALLOCATIONS.with(|count| count.set(count.get() + 1));
    // SAFETY: the caller passes the original pointer and exact allocation layout.
    unsafe { std::alloc::dealloc(ptr, layout) }
}

#[derive(Debug)]
struct LeaderSignerBuffer {
    ptr: std::ptr::NonNull<ValidatorId>,
    layout: std::alloc::Layout,
    initialized: usize,
    capacity: usize,
}

impl LeaderSignerBuffer {
    fn copy_from(
        source: &[ValidatorId],
        capacity: usize,
    ) -> Result<Self, LeaderSignerBufferError> {
        if capacity == 0 || source.len() > capacity {
            return Err(LeaderSignerBufferError::Bound);
        }
        let layout = std::alloc::Layout::array::<ValidatorId>(capacity)
            .map_err(|_| LeaderSignerBufferError::Layout)?;
        let raw = allocate_leader_signers(layout).cast::<ValidatorId>();
        let Some(ptr) = std::ptr::NonNull::new(raw) else {
            return Err(LeaderSignerBufferError::Allocation);
        };
        let mut buffer = Self {
            ptr,
            layout,
            initialized: 0,
            capacity,
        };
        for signer in source {
            // SAFETY: initialized is strictly below the checked capacity, and
            // this slot has not been initialized before.
            unsafe { buffer.ptr.as_ptr().add(buffer.initialized).write(*signer) };
            buffer.initialized += 1;
        }
        Ok(buffer)
    }

    fn into_vec(self) -> Vec<ValidatorId> {
        let mut this = std::mem::ManuallyDrop::new(self);
        let ptr = this.ptr.as_ptr();
        let len = this.initialized;
        let capacity = this.capacity;
        this.initialized = 0;
        #[cfg(test)]
        LEADER_SIGNER_TRANSFERS.with(|count| count.set(count.get() + 1));
        // SAFETY: allocation used the global allocator and exact Layout for
        // `capacity` ValidatorIds; exactly `len` values were initialized; no
        // other owner can free this allocation; Vec uses the same allocator.
        unsafe { Vec::from_raw_parts(ptr, len, capacity) }
    }
}

impl Drop for LeaderSignerBuffer {
    fn drop(&mut self) {
        // SAFETY: exactly `initialized` elements were written in this allocation.
        unsafe {
            std::ptr::drop_in_place(std::ptr::slice_from_raw_parts_mut(
                self.ptr.as_ptr(),
                self.initialized,
            ));
            deallocate_leader_signers(self.ptr.as_ptr().cast::<u8>(), self.layout);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaderSignerBufferError {
    Bound,
    Layout,
    Allocation,
}

fn same_vote_signed_fields(
    left: &qbind_wire::consensus::Vote,
    right: &qbind_wire::consensus::Vote,
) -> bool {
    left.version == right.version
        && left.chain_id == right.chain_id
        && left.epoch == right.epoch
        && left.height == right.height
        && left.round == right.round
        && left.step == right.step
        && left.block_id == right.block_id
        && left.validator_index == right.validator_index
        && left.suite_id == right.suite_id
}

fn map_received_vote_qc_incomplete(
    reason: ReceivedVoteQcIncompleteReason,
) -> ReceivedVoteQcIncomplete {
    match reason {
        ReceivedVoteQcIncompleteReason::MissingEvidence(id) => {
            ReceivedVoteQcIncomplete::MissingEvidence(id)
        }

        ReceivedVoteQcIncompleteReason::ContextMismatch(id) => {
            ReceivedVoteQcIncomplete::ContextMismatch(id)
        }
        ReceivedVoteQcIncompleteReason::SignerMismatch(id) => {
            ReceivedVoteQcIncomplete::SignerMismatch(id)
        }
        ReceivedVoteQcIncompleteReason::CandidateMismatch(id) => {
            ReceivedVoteQcIncomplete::CandidateMismatch(id)
        }
        ReceivedVoteQcIncompleteReason::CommonFieldsMismatch(id) => {
            ReceivedVoteQcIncomplete::CommonFieldsMismatch(id)
        }
        ReceivedVoteQcIncompleteReason::SignatureShapeMismatch(id) => {
            ReceivedVoteQcIncomplete::SignatureShapeMismatch(id)
        }
    }
}

fn received_vote_qc_control_charge() -> Result<u64, ReceivedVoteQcStageError> {
    let route = u64::try_from(std::mem::size_of::<ReceivedVoteQcRouteControlFrame>())
        .map_err(|_| ReceivedVoteQcStageError::Arithmetic)?;
    let buffer = qc_buffer_control_frame_bytes()?;
    let admission = qc_admission_control_frame_bytes()?;
    route
        .checked_add(admission.max(buffer))
        .ok_or(ReceivedVoteQcStageError::Arithmetic)
}

fn qc_matches_projected_membership(
    qc: &QuorumCertificate<[u8; 32]>,
    membership: &[u64; 16],
    projected_count: usize,
    roster_len: usize,
    view: u64,
    block_id: [u8; 32],
) -> bool {
    if qc.view != view || qc.block_id != block_id || qc.signers.len() != projected_count {
        return false;
    }
    for (index, signer) in qc.signers.iter().enumerate() {
        let raw = match usize::try_from(signer.as_u64()) {
            Ok(value) if value < roster_len && value < 1024 => value,
            _ => return false,
        };
        let word = raw / 64;
        if word >= membership.len() || membership[word] & (1u64 << (raw % 64)) == 0 {
            return false;
        }
        if qc.signers[..index]
            .iter()
            .any(|previous| previous == signer)
        {
            return false;
        }
    }
    true
}

fn compare_actual_qc_failure(
    qc: &QuorumCertificate<[u8; 32]>,
    membership: &[u64; 16],
    projected_count: usize,
    roster_len: usize,
    view: u64,
    block_id: [u8; 32],
) -> ReceivedVoteQcIncomplete {
    if qc.view != view || qc.block_id != block_id {
        return ReceivedVoteQcIncomplete::ActualCandidateMismatch;
    }
    if qc.signers.len() != projected_count {
        return ReceivedVoteQcIncomplete::ActualSignerCountMismatch;
    }
    for (index, signer) in qc.signers.iter().enumerate() {
        let raw = signer.as_u64();
        let Ok(index_value) = usize::try_from(raw) else {
            return ReceivedVoteQcIncomplete::ActualSignerOutOfRange(raw);
        };
        if index_value >= roster_len || index_value >= 1024 {
            return ReceivedVoteQcIncomplete::ActualSignerOutOfRange(raw);
        }
        if qc.signers[..index]
            .iter()
            .any(|previous| previous == signer)
        {
            return ReceivedVoteQcIncomplete::ActualSignerDuplicate(raw);
        }
        let word = index_value / 64;
        if word >= membership.len() || membership[word] & (1u64 << (index_value % 64)) == 0 {
            return ReceivedVoteQcIncomplete::ActualSignerMembershipMismatch(raw);
        }
    }
    ReceivedVoteQcIncomplete::ActualSignerCountMismatch
}

// ============================================================================
// BlockIdT = [u8; 32] specific implementation
// ============================================================================

#[cfg(test)]
thread_local! {
    static PANIC_AFTER_RECEIVED_VOTE_TABLE_STAGE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static RECEIVED_VOTE_LOGICAL_INVOCATIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

impl BasicHotStuffEngine<[u8; 32]> {
    pub(crate) fn invoke_verified_received_vote_qc(
        &mut self,
        token: VerifiedVoteToken,
    ) -> Result<ReceivedVoteQcReport, ReceivedVoteQcRefusal> {
        let preflight = match self.preflight_verified_received_vote(&token) {
            Ok(preflight) => preflight,
            Err(reason) => {
                return Err(ReceivedVoteQcRefusal {
                    token,
                    reason: ReceivedVoteQcRefusalReason::Invocation(reason),
                });
            }
        };
        let voter = ValidatorId(u64::from(token.vote().validator_index));
        let view = token.vote().height;
        let block_id = token.vote().block_id;
        let control_bytes = match received_vote_qc_control_charge() {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(ReceivedVoteQcRefusal {
                    token,
                    reason: ReceivedVoteQcRefusalReason::Stage(error),
                });
            }
        };
        let provenance = match token.begin_qc_report(control_bytes) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(ReceivedVoteQcRefusal {
                    token,
                    reason: ReceivedVoteQcRefusalReason::Stage(error),
                });
            }
        };

        let is_equivocation = self
            .state
            .has_conflicting_vote_history(voter, view, &block_id);
        let mut candidate = ReceivedVoteQcCandidateSeal {
            block_id,
            view,
            incoming_validator: voter,
            projected_count: 0,
            membership: [0u64; 16],
        };
        let mut wire = None;
        let mut staged_incomplete = None;
        if !is_equivocation {
            let projection = match self
                .state
                .project_received_vote_accumulator(voter, view, &block_id)
            {
                Ok(projection) => projection,
                Err(_) => {
                    return Err(ReceivedVoteQcRefusal {
                        token,
                        reason: ReceivedVoteQcRefusalReason::Invocation(
                            VerifiedVoteInvocationRefusal::EpochOrRosterMismatch,
                        ),
                    });
                }
            };
            candidate.projected_count = projection.projected_count();
            let projected_disposition = projection.disposition();
            let mut cursor = None;
            while let Some(signer) = projection.next_signer(cursor) {
                let raw = usize::try_from(signer.as_u64()).unwrap_or(usize::MAX);
                let roster_len = self.state.validators().len();
                if raw >= roster_len || raw >= 1024 {
                    drop(projection);
                    return Err(ReceivedVoteQcRefusal {
                        token,
                        reason: ReceivedVoteQcRefusalReason::Stage(
                            ReceivedVoteQcStageError::Invariant,
                        ),
                    });
                }
                let word = raw / 64;
                if word >= candidate.membership.len() {
                    drop(projection);
                    return Err(ReceivedVoteQcRefusal {
                        token,
                        reason: ReceivedVoteQcRefusalReason::Stage(
                            ReceivedVoteQcStageError::Invariant,
                        ),
                    });
                }
                candidate.membership[word] |= 1u64 << (raw % 64);
                cursor = Some(signer);
            }
            let incoming_index =
                usize::try_from(candidate.incoming_validator.as_u64()).unwrap_or(usize::MAX);
            let incoming_present = incoming_index < 1024
                && candidate.membership[incoming_index / 64]
                    & (1u64 << (incoming_index % 64))
                    != 0;
            if candidate.projected_count
                != candidate
                    .membership
                    .iter()
                    .map(|word| word.count_ones() as usize)
                    .sum::<usize>()
                || (projected_disposition == VoteAccumulatorDisposition::Inserted
                    && !incoming_present)
                || (projected_disposition == VoteAccumulatorDisposition::Duplicate
                    && !incoming_present)
                || (projected_disposition == VoteAccumulatorDisposition::CapacityDropped
                    && incoming_present)
            {
                drop(projection);
                return Err(ReceivedVoteQcRefusal {
                    token,
                    reason: ReceivedVoteQcRefusalReason::Stage(ReceivedVoteQcStageError::Invariant),
                });
            }
            if candidate.projected_count > 0 {
                let table = self
                    .state
                    .received_vote_evidence_table()
                    .unwrap_or_else(|| std::process::abort());
                match provenance.build_wire(
                    &token,
                    table,
                    &candidate.membership,
                    candidate.projected_count,
                    self.state.validators().len(),
                    candidate.view,
                    candidate.block_id,
                    matches!(preflight.plan, VoteEvidencePlan::NewEntry { .. }),
                ) {
                    Ok(ReceivedVoteQcWirePreparation::Complete(candidate)) => {
                        wire = Some(candidate)
                    }
                    Ok(ReceivedVoteQcWirePreparation::Incomplete(reason)) => {
                        staged_incomplete = Some(map_received_vote_qc_incomplete(reason))
                    }
                    Err(error) => {
                        drop(provenance);
                        return Err(ReceivedVoteQcRefusal {
                            token,
                            reason: ReceivedVoteQcRefusalReason::Stage(error),
                        });
                    }
                }
            } else {
                staged_incomplete = Some(ReceivedVoteQcIncomplete::MissingEvidence(
                    token.vote().validator_index,
                ));
            }
            drop(projection);
        }

        #[cfg(test)]
        RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(|count| count.set(count.get() + 1));
        let report = self.state.on_vote_detailed(voter, view, &block_id);
        let evidence = match preflight.plan {
            VoteEvidencePlan::NewEntry { slot } => {
                if !report.is_equivocation()
                    && self.state.has_vote_memberships(voter, view, &block_id)
                {
                    self.state.retain_received_vote_token(
                        slot,
                        block_id,
                        token,
                        preflight.shrink_to,
                    );
                    ReceivedVoteEvidenceDisposition::Retained
                } else {
                    drop(token);
                    if report.is_equivocation() {
                        ReceivedVoteEvidenceDisposition::NotRetainedEquivocation
                    } else if matches!(
                        report.accumulator.as_ref(),
                        Some(Ok(VoteAccumulatorDisposition::CapacityDropped))
                    ) {
                        ReceivedVoteEvidenceDisposition::NotRetainedCapacityDropped
                    } else {
                        ReceivedVoteEvidenceDisposition::NotRetainedMembershipLost
                    }
                }
            }
            VoteEvidencePlan::ExistingEvidence => {
                let still_retained = self
                    .state
                    .received_vote_evidence_table()
                    .and_then(|table| table.entry_for(view, token.vote().validator_index))
                    .is_some();
                drop(token);
                if still_retained {
                    preflight
                        .existing
                        .unwrap_or(ReceivedVoteEvidenceDisposition::ExistingSignedFieldsConflict)
                } else {
                    ReceivedVoteEvidenceDisposition::NotRetainedMembershipLost
                }
            }
            VoteEvidencePlan::DoNotRetain => {
                drop(token);
                if report.is_equivocation() {
                    ReceivedVoteEvidenceDisposition::NotRetainedEquivocation
                } else if matches!(
                    report.accumulator.as_ref(),
                    Some(Ok(VoteAccumulatorDisposition::CapacityDropped))
                ) {
                    ReceivedVoteEvidenceDisposition::NotRetainedCapacityDropped
                } else {
                    ReceivedVoteEvidenceDisposition::NotRetainedMembershipLost
                }
            }
        };

        let view_advanced = if report.qc.is_ok() {
            self.finish_successful_vote_event(
                voter,
                view,
                &report.history,
                report.qc.as_ref().ok().and_then(Option::as_ref),
            )
        } else {
            false
        };

        let qc_summary =
            report
                .qc
                .as_ref()
                .ok()
                .and_then(Option::as_ref)
                .map(|qc| ReceivedVoteQcSummary {
                    block_id: qc.block_id,
                    view: qc.view,
                    signer_count: qc.signers.len(),
                });
        let outcome = match report.qc {
            Err(error) => {
                drop(wire);
                ReceivedVoteQcOutcome::LogicalError(error)
            }
            Ok(None) => {
                drop(wire);
                ReceivedVoteQcOutcome::NoQc
            }
            Ok(Some(qc)) => {
                let matches = qc_matches_projected_membership(
                    &qc,
                    &candidate.membership,
                    candidate.projected_count,
                    self.state.validators().len(),
                    candidate.view,
                    candidate.block_id,
                );
                if !matches {
                    drop(wire);
                    ReceivedVoteQcOutcome::Incomplete(compare_actual_qc_failure(
                        &qc,
                        &candidate.membership,
                        candidate.projected_count,
                        self.state.validators().len(),
                        candidate.view,
                        candidate.block_id,
                    ))
                } else if let Some(reason) = staged_incomplete {
                    drop(wire);
                    ReceivedVoteQcOutcome::Incomplete(reason)
                } else if let Some(candidate) = wire {
                    ReceivedVoteQcOutcome::Complete(candidate)
                } else {
                    ReceivedVoteQcOutcome::Incomplete(ReceivedVoteQcIncomplete::MissingEvidence(0))
                }
            }
        };
        Ok(ReceivedVoteQcReport {
            actual: ReceivedVoteQcEventSummary {
                history: report.history,
                accumulator: report.accumulator,
                evidence,
                view_advanced,
                qc: qc_summary,
            },
            outcome,
            _provenance: provenance,
        })
    }

    pub(crate) fn install_received_vote_context(
        &mut self,
        input: VoteContextInput,
    ) -> Result<(), ContextInstallRefusal> {
        let refuse = |input, error| ContextInstallRefusal { input, error };
        if self.received_vote_producer_disabled {
            return Err(refuse(input, ContextInstallError::InvalidContext));
        }
        if self.active_received_vote_context.is_some() {
            return Err(refuse(input, ContextInstallError::AlreadyInstalled));
        }
        if input.authorized_epoch() != self.current_epoch
            || input.suite_id() != qbind_crypto::SUITE_PQ_RESERVED_1
            || input.runtime_chain_id() != input.domain().runtime_chain_id()
            || !input.within_profile_capacity()
        {
            return Err(refuse(input, ContextInstallError::InvalidContext));
        }
        if input.checked_charge().is_err() {
            return Err(refuse(input, ContextInstallError::InvalidContext));
        }
        let validators = self.state.validators();
        if input.members().len() != validators.len()
            || input
                .members()
                .iter()
                .zip(validators.iter())
                .any(|(member, validator)| {
                    member.validator_id() != validator.id.as_u64()
                        || member.voting_power() != validator.voting_power
                        || member.public_key().len() != qbind_crypto::ML_DSA_44_PUBLIC_KEY_SIZE
                        || member.public_key_capacity() != qbind_crypto::ML_DSA_44_PUBLIC_KEY_SIZE
                })
        {
            return Err(refuse(input, ContextInstallError::InvalidContext));
        }

        let (budget, staged_state_owner) = match self.state.received_vote_budget() {
            Some(existing) => match existing.try_clone() {
                Ok(handle) => (handle, None),
                Err(error) => return Err(refuse(input, error)),
            },
            None => {
                let map_bytes = match self.state.map_qc_charge_checked() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Err(refuse(input, ContextInstallError::Arithmetic));
                    }
                };
                let handle = match EvidenceBudget::try_new(
                    self.state.max_retained_evidence_bytes(),
                    map_bytes,
                ) {
                    Ok(handle) => handle,
                    Err(error) => return Err(refuse(input, error)),
                };
                let state_owner = match handle.try_clone() {
                    Ok(owner) => owner,
                    Err(error) => return Err(refuse(input, error)),
                };
                (handle, Some(state_owner))
            }
        };

        if let Some(table) = self.state.received_vote_evidence_table() {
            if table.occupied() != 0 {
                return Err(refuse(input, ContextInstallError::InvalidContext));
            }
        }
        let staged_table = if self.state.received_vote_evidence_table().is_none() {
            match ReceivedVoteEvidenceTable::try_stage(&budget) {
                Ok(table) => Some(table),
                Err(error) => return Err(refuse(input, error)),
            }
        } else {
            None
        };

        #[cfg(test)]
        if PANIC_AFTER_RECEIVED_VOTE_TABLE_STAGE.with(|flag| flag.replace(false)) {
            panic!("test panic after received-vote table staging");
        }

        // Context installation may adopt `input`; it is deliberately the last
        // recoverable ownership operation. All attachments below are moves
        // into prevalidated empty Options.
        let active = match ActiveVoteContext::try_install(&budget, input) {
            Ok(active) => active,
            Err((input, error)) => return Err(refuse(input, error)),
        };
        if let Some(state_owner) = staged_state_owner {
            if self
                .state
                .install_received_vote_budget(state_owner)
                .is_err()
            {
                std::process::abort();
            }
        }
        if let Some(table) = staged_table {
            if self
                .state
                .install_received_vote_evidence_table(table)
                .is_err()
            {
                std::process::abort();
            }
        }
        self.active_received_vote_context = Some(active);
        Ok(())
    }

    pub(crate) fn admit_verified_received_vote(
        &mut self,
        claimed_sender: ValidatorId,
        vote: qbind_wire::consensus::Vote,
    ) -> Result<VerifiedVoteToken, VoteAdmissionRefusal> {
        let Some(context) = self.active_received_vote_context.as_ref() else {
            return Err(VoteAdmissionRefusal {
                vote,
                error: VoteAdmissionError::NoContext,
            });
        };
        if self.received_vote_producer_disabled {
            return Err(VoteAdmissionRefusal {
                vote,
                error: VoteAdmissionError::NoContext,
            });
        }
        context
            .try_admit_vote(claimed_sender.as_u64(), vote, self.current_epoch)
            .map_err(|(vote, error)| VoteAdmissionRefusal { vote, error })
    }

    pub(crate) fn invoke_verified_received_vote(
        &mut self,
        token: VerifiedVoteToken,
    ) -> VerifiedVoteInvocation {
        let preflight = match self.preflight_verified_received_vote(&token) {
            Ok(preflight) => preflight,
            Err(reason) => {
                return VerifiedVoteInvocation::Refused { token, reason };
            }
        };

        let (view, block_id, voter, vote_index) = {
            let vote = token.vote();
            (
                vote.height,
                vote.block_id,
                ValidatorId(u64::from(vote.validator_index)),
                vote.validator_index,
            )
        };

        // This is the one and only logical consensus invocation. Its detailed
        // report retains history/insertion distinctions even when QC processing
        // returns an error after the history mutation.
        #[cfg(test)]
        RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(|count| count.set(count.get() + 1));
        let report = self.state.on_vote_detailed(voter, view, &block_id);
        let evidence = match preflight.plan {
            VoteEvidencePlan::NewEntry { slot } => {
                if !report.is_equivocation()
                    && self.state.has_vote_memberships(voter, view, &block_id)
                {
                    self.state.retain_received_vote_token(
                        slot,
                        block_id,
                        token,
                        preflight.shrink_to,
                    );
                    ReceivedVoteEvidenceDisposition::Retained
                } else {
                    drop(token);
                    if report.is_equivocation() {
                        ReceivedVoteEvidenceDisposition::NotRetainedEquivocation
                    } else if matches!(
                        report.accumulator.as_ref(),
                        Some(Ok(crate::vote_accumulator::VoteAccumulatorDisposition::CapacityDropped))
                    ) {
                        ReceivedVoteEvidenceDisposition::NotRetainedCapacityDropped
                    } else {
                        ReceivedVoteEvidenceDisposition::NotRetainedMembershipLost
                    }
                }
            }
            VoteEvidencePlan::ExistingEvidence => {
                let still_retained = self
                    .state
                    .received_vote_evidence_table()
                    .and_then(|table| table.entry_for(view, vote_index))
                    .is_some();
                drop(token);
                if still_retained {
                    preflight
                        .existing
                        .unwrap_or(ReceivedVoteEvidenceDisposition::ExistingSignedFieldsConflict)
                } else {
                    ReceivedVoteEvidenceDisposition::NotRetainedMembershipLost
                }
            }
            VoteEvidencePlan::DoNotRetain => {
                drop(token);
                if report.is_equivocation() {
                    ReceivedVoteEvidenceDisposition::NotRetainedEquivocation
                } else if matches!(
                    report.accumulator.as_ref(),
                    Some(Ok(crate::vote_accumulator::VoteAccumulatorDisposition::CapacityDropped))
                ) {
                    ReceivedVoteEvidenceDisposition::NotRetainedCapacityDropped
                } else {
                    ReceivedVoteEvidenceDisposition::NotRetainedMembershipLost
                }
            }
        };

        // A state error is an invoked outcome. Ownership is already settled,
        // and the legacy event path skips all recorders and view advancement.
        let view_advanced = if report.qc.is_ok() {
            let qc = report.qc.as_ref().ok().and_then(Option::as_ref);
            self.finish_successful_vote_event(voter, view, &report.history, qc)
        } else {
            false
        };
        VerifiedVoteInvocation::Invoked {
            report,
            evidence,
            view_advanced,
        }
    }

    fn preflight_verified_received_vote(
        &self,
        token: &VerifiedVoteToken,
    ) -> Result<VerifiedVotePreflight, VerifiedVoteInvocationRefusal> {
        if self.received_vote_producer_disabled {
            return Err(VerifiedVoteInvocationRefusal::ProducerDisabled);
        }
        let active = self
            .active_received_vote_context
            .as_ref()
            .ok_or(VerifiedVoteInvocationRefusal::NoContext)?;
        let table = self
            .state
            .received_vote_evidence_table()
            .ok_or(VerifiedVoteInvocationRefusal::NoTable)?;
        let budget = self
            .state
            .received_vote_budget()
            .ok_or(VerifiedVoteInvocationRefusal::ForeignLedger)?;
        if !token.matches_ledger(budget)
            || !active.same_ledger(budget)
            || !table.matches_ledger(budget)
        {
            return Err(VerifiedVoteInvocationRefusal::ForeignLedger);
        }
        if !token.matches_context(active) {
            return Err(VerifiedVoteInvocationRefusal::StaleContext);
        }
        let vote = token.vote();
        if !active.matches_validators(self.state.validators())
            || !active.validates_vote_metadata(vote, self.current_epoch)
        {
            return Err(VerifiedVoteInvocationRefusal::EpochOrRosterMismatch);
        }
        let (token_bytes, signature_bytes) = token
            .token_charge_and_signature_bytes()
            .ok_or(VerifiedVoteInvocationRefusal::InvalidLease)?;
        if !token.has_exact_token_charge()
            || token_bytes.checked_sub(signature_bytes).is_none()
        {
            return Err(VerifiedVoteInvocationRefusal::InvalidLease);
        }
        let voter = ValidatorId(u64::from(vote.validator_index));
        if !self.state.validators().contains(voter) {
            return Err(VerifiedVoteInvocationRefusal::EpochOrRosterMismatch);
        }
        let plan = self
            .state
            .prepare_received_vote_evidence(voter, vote.height, &vote.block_id)
            .map_err(|error| match error {
                VoteEvidencePreflightError::MissingTable => {
                    VerifiedVoteInvocationRefusal::NoTable
                }
                VoteEvidencePreflightError::Full => VerifiedVoteInvocationRefusal::TableFull,
                VoteEvidencePreflightError::Invariant => {
                    VerifiedVoteInvocationRefusal::AccountingInvariant
                }
            })?;
        let existing = match plan {
            VoteEvidencePlan::ExistingEvidence => {
                let retained = table
                    .entry_for(vote.height, vote.validator_index)
                    .ok_or(VerifiedVoteInvocationRefusal::AccountingInvariant)?
                    .vote();
                Some(if retained == vote {
                    ReceivedVoteEvidenceDisposition::ExistingExactDuplicate
                } else if same_vote_signed_fields(retained, vote) {
                    ReceivedVoteEvidenceDisposition::ExistingDifferentSignature
                } else {
                    ReceivedVoteEvidenceDisposition::ExistingSignedFieldsConflict
                })
            }
            _ => None,
        };
        Ok(VerifiedVotePreflight {
            plan,
            shrink_to: signature_bytes,
            existing,
        })
    }

    #[cfg(test)]
    pub(crate) fn received_vote_evidence_aggregate_bytes(&self) -> Option<(u64, u64)> {
        self.state
            .received_vote_budget()
            .map(|budget| budget.occupancy())
            .map(|(committed, pending, _, _)| (committed, pending))
    }

    /// Isolated, opt-in leader Proposal/self-Vote owning route. This is not
    /// called by production networking or the legacy leader methods.
    pub fn try_propose_gated_owning<P, G>(
        &mut self,
        gate: &mut G,
    ) -> LeaderProposalRouteResult<P>
    where
        G: LeaderProposalGate<P>,
    {
        use crate::hotstuff_state_engine::{
            LeaderRegistrationRefusal, LeaderVoteHistoryStatus,
        };
        use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as WireQc, Vote};

        if !self.is_leader_for_current_view() {
            return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::NonLeader);
        }
        if self.proposed_in_view {
            return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::AlreadyProposed);
        }
        if self.voted_in_view {
            return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::AlreadyVoted);
        }
        let proposer_index = match u16::try_from(self.local_id.as_u64()) {
            Ok(index) => index,
            Err(_) => {
                return LeaderProposalRouteResult::Refused(
                    LeaderRouteRefusal::ProposerIndexOverflow,
                )
            }
        };
        let view = self.current_view;
        if view.checked_add(1).is_none() {
            return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::Arithmetic);
        }
        let Some(locked_qc) = self.state.locked_qc() else {
            return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::NoLock);
        };
        let parent_id = locked_qc.block_id;
        let candidate_id =
            Self::derive_block_id_from_header(self.local_id, view, &parent_id);

        match self
            .state
            .leader_vote_history_status(self.local_id, view, &candidate_id)
        {
            LeaderVoteHistoryStatus::NonMember => {
                return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::NonMember)
            }
            LeaderVoteHistoryStatus::SameCandidate => {
                return LeaderProposalRouteResult::Refused(
                    LeaderRouteRefusal::PriorSameCandidateVote,
                )
            }
            LeaderVoteHistoryStatus::ConflictingCandidate => {
                return LeaderProposalRouteResult::Refused(
                    LeaderRouteRefusal::ConflictingVoteHistory,
                )
            }
            LeaderVoteHistoryStatus::Clear => {}
        }

        let limits = gate.route_limits();
        let signer_capacity = limits.max_qc_signers();
        let signer_buffer = match LeaderSignerBuffer::copy_from(
            &locked_qc.signers,
            signer_capacity,
        ) {
            Ok(buffer) => buffer,
            Err(LeaderSignerBufferError::Bound) => {
                return LeaderProposalRouteResult::Refused(
                    LeaderRouteRefusal::SignerBoundExceeded,
                )
            }
            Err(LeaderSignerBufferError::Layout) => {
                return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::Arithmetic)
            }
            Err(LeaderSignerBufferError::Allocation) => {
                return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::Allocation)
            }
        };
        let logical_justify = QuorumCertificate::new(
            locked_qc.block_id,
            locked_qc.view,
            signer_buffer.into_vec(),
        );
        let justification = LeaderJustification {
            block_id: logical_justify.block_id,
            view: logical_justify.view,
            signer_count: logical_justify.signers.len(),
        };
        let epoch = self.current_epoch;
        let intent = self.pending_reconfig_next_epoch;
        let preflight = LeaderPreflight {
            candidate_id,
            parent_block_id: parent_id,
            origin_view: view,
            epoch,
            reconfiguration_intent: intent,
            justification,
        };
        let registration = match self.state.plan_leader_registration(
            preflight.candidate_id,
            preflight.origin_view,
            Some(preflight.parent_block_id),
            Some(logical_justify),
        ) {
            Ok(plan) => plan,
            Err(LeaderRegistrationRefusal::CandidateCollision) => {
                return LeaderProposalRouteResult::Refused(
                    LeaderRouteRefusal::CandidateCollision,
                )
            }
            Err(LeaderRegistrationRefusal::Capacity) => {
                return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::BlockCapacity)
            }
            Err(LeaderRegistrationRefusal::Arithmetic) => {
                return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::Arithmetic)
            }
            Err(LeaderRegistrationRefusal::Allocation) => {
                return LeaderProposalRouteResult::Refused(LeaderRouteRefusal::Allocation)
            }
        };

        let (payload_kind, next_epoch) = match preflight.reconfiguration_intent {
            Some(target) if target > epoch => (qbind_wire::PAYLOAD_KIND_RECONFIG, target),
            _ => (qbind_wire::PAYLOAD_KIND_NORMAL, 0),
        };
        let proposal = BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                epoch,
                height: preflight.origin_view,
                round: preflight.origin_view,
                parent_block_id: preflight.parent_block_id,
                payload_hash: [0; 32],
                proposer_index,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 0,
                payload_kind,
                next_epoch,
                batch_commitment: [0; 32],
            },
            qc: Some(WireQc {
                version: 1,
                chain_id: 1,
                epoch,
                height: preflight.justification.view,
                round: preflight.justification.view,
                step: 0,
                block_id: preflight.justification.block_id,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                signer_bitmap: Vec::new(),
                signatures: Vec::new(),
            }),
            txs: Vec::new(),
            signature: Vec::new(),
        };
        let context = LeaderProposalContext {
            proposer: self.local_id,
            origin_view: preflight.origin_view,
            candidate_id: preflight.candidate_id,
            candidate_view: preflight.origin_view,
            epoch: preflight.epoch,
            parent_block_id: preflight.parent_block_id,
            justification: Some(preflight.justification),
            proposal_suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            vote_suite_id: self.vote_suite_id,
            payload_kind,
            next_epoch,
        };
        let input = LeaderCaptureInput {
            context,
            proposal: &proposal,
        };
        let payload = match gate.capture_l0(&input) {
            Ok(payload) => payload,
            Err(_) => {
                return LeaderProposalRouteResult::Refused(
                    LeaderRouteRefusal::CaptureGateRefused,
                )
            }
        };

        let mut effects = LeaderRouteEffects::initial();
        self.state.commit_leader_registration(registration);
        self.proposed_in_view = true;
        effects.candidate_registered = true;
        effects.proposed_flag_set = true;
        let report = self
            .state
            .on_leader_self_vote_detailed(self.local_id, view, &candidate_id);
        self.voted_in_view = true;
        effects.voted_flag_set = true;
        effects.vote_history_recorded = report.history_recorded;
        effects.history_entries_evicted = report.history_entries_evicted;
        effects.accumulator_views_evicted = report.accumulator_views_evicted;
        effects.equivocation_recorded = report.equivocation_recorded;
        effects.qc_formed = report.qc_formed;
        effects.qc_processed = report.qc_processed;
        effects.qc_processing_succeeded = report.qc_processing_succeeded;
        if let Some(disposition) = report.insertion {
            match disposition {
                crate::vote_accumulator::VoteAccumulatorDisposition::Inserted => {
                    effects.accumulator_inserted = true
                }
                crate::vote_accumulator::VoteAccumulatorDisposition::Duplicate => {
                    effects.accumulator_duplicate = true
                }
                crate::vote_accumulator::VoteAccumulatorDisposition::CapacityDropped => {
                    effects.accumulator_capacity_dropped = true
                }
            }
        }
        let vote = Vote {
            version: 1,
            chain_id: 1,
            epoch,
            height: view,
            round: view,
            step: 0,
            block_id: preflight.candidate_id,
            validator_index: proposer_index,
            suite_id: self.vote_suite_id,
            signature: Vec::new(),
        };

        let accepted = effects.accumulator_inserted
            && effects.qc_processing_succeeded
            && report.processing_error.is_none()
            && !effects.equivocation_recorded;
        if !accepted {
            let reason = match report.processing_error {
                Some(error) => LeaderRouteRefusal::VoteNotAccepted(
                    LeaderVoteRefusal::Processing(error),
                ),
                None if effects.accumulator_duplicate => LeaderRouteRefusal::VoteNotAccepted(
                    LeaderVoteRefusal::Duplicate,
                ),
                None if effects.accumulator_capacity_dropped => {
                    LeaderRouteRefusal::VoteNotAccepted(LeaderVoteRefusal::CapacityDropped)
                }
                None if effects.equivocation_recorded => LeaderRouteRefusal::VoteNotAccepted(
                    LeaderVoteRefusal::Equivocation,
                ),
                None => LeaderRouteRefusal::VoteNotAccepted(LeaderVoteRefusal::NonMember),
            };
            return LeaderProposalRouteResult::PostCapture(LeaderPostCaptureFailure {
                proposal,
                vote,
                payload,
                reason,
                effects,
            });
        }

        if let Some(recorder) = self.progress_recorder.as_ref() {
            recorder.record_vote_observed(true);
            if effects.qc_formed {
                if let Some(start) = self.last_view_start_instant {
                    recorder.record_qc_formed_with_latency(start.elapsed());
                } else {
                    recorder.record_qc_formed();
                }
            }
        }
        if let Some(recorder) = self.validator_vote_recorder.as_ref() {
            recorder.on_validator_vote(self.local_id, view);
        }
        if effects.qc_formed {
            self.advance_view();
            effects.view_advanced = true;
        }
        if self.pending_reconfig_next_epoch == preflight.reconfiguration_intent {
            self.pending_reconfig_next_epoch = None;
            effects.reconfiguration_intent_consumed = preflight.reconfiguration_intent.is_some();
        }
        LeaderProposalRouteResult::Decided(DecidedLeaderProposal {
            proposal,
            vote,
            payload,
            effects,
        })
    }

    /// Generate a deterministic block id based on proposal header fields.
    ///
    /// This creates a consistent block_id that both the proposer and followers
    /// can derive from the same proposal header.
    fn derive_block_id_from_header(
        proposer: ValidatorId,
        view: u64,
        parent_block_id: &[u8; 32],
    ) -> [u8; 32] {
        let mut id = [0u8; 32];
        // Encode proposer id in the first 8 bytes
        let proposer_bytes = proposer.0.to_le_bytes();
        id[..8].copy_from_slice(&proposer_bytes);
        // Encode view in bytes 8-15
        let view_bytes = view.to_le_bytes();
        id[8..16].copy_from_slice(&view_bytes);
        // Copy first 16 bytes of parent_block_id for uniqueness
        id[16..32].copy_from_slice(&parent_block_id[..16]);
        id
    }

    /// Generate a block id for the current view (as leader).
    fn make_block_id(&mut self, parent_block_id: &[u8; 32]) -> [u8; 32] {
        Self::derive_block_id_from_header(self.local_id, self.current_view, parent_block_id)
    }

    /// Export a contiguous certified suffix above `from_height/from_block_id`
    /// for a restored peer.
    ///
    /// Only blocks already present in this engine's block tree with an
    /// `own_qc` are exported. The suffix is anchored at the caller-provided
    /// block id and follows child links one height at a time. If no certified
    /// child is known, an empty suffix is returned.
    pub fn export_restore_catchup_blocks(
        &self,
        from_height: u64,
        from_block_id: [u8; 32],
        max_blocks: usize,
    ) -> Vec<RestoreCatchupBlock<[u8; 32]>> {
        let mut out = Vec::new();
        let mut parent = from_block_id;
        let mut expected_height = from_height.saturating_add(1);

        while out.len() < max_blocks {
            let candidate = self
                .state
                .blocks_iter()
                .filter(|node| {
                    node.height == expected_height
                        && node.parent_id.as_ref() == Some(&parent)
                        && node.own_qc.is_some()
                })
                .min_by_key(|node| node.view);
            let Some(node) = candidate else {
                break;
            };
            let Some(qc) = node.own_qc.as_ref() else {
                break;
            };
            let proposer = self.leader_for_view(node.view);
            out.push(RestoreCatchupBlock {
                height: node.height,
                view: node.view,
                parent_block_id: parent,
                block_id: node.id,
                proposer,
                qc_signers: qc.signers.clone(),
            });
            parent = node.id;
            expected_height = expected_height.saturating_add(1);
        }

        out
    }

    /// Validate and apply peer-learned restore-catchup material above the
    /// current committed anchor.
    ///
    /// The method does not fabricate commits: each learned block is inserted
    /// into the normal block tree, then the provided logical QC signers are
    /// replayed through `HotStuffStateEngine::on_vote`, causing the existing
    /// QC and 3-chain commit logic to advance state if and only if the suffix
    /// is structurally valid and has quorum.
    pub fn apply_restore_catchup_blocks(
        &mut self,
        blocks: &[RestoreCatchupBlock<[u8; 32]>],
    ) -> Result<usize, RestoreCatchupError<[u8; 32]>> {
        if blocks.is_empty() {
            return Ok(0);
        }

        let mut expected_height = self
            .committed_height()
            .ok_or(RestoreCatchupError::MissingLocalAnchor)?
            .saturating_add(1);
        let mut expected_parent = *self
            .committed_block()
            .ok_or(RestoreCatchupError::MissingLocalAnchor)?;
        let mut previous_qc: Option<QuorumCertificate<[u8; 32]>> = self.locked_qc().cloned();
        let mut applied = 0usize;

        for block in blocks {
            if block.height != expected_height {
                return Err(RestoreCatchupError::NonContiguousHeight {
                    expected: expected_height,
                    actual: block.height,
                });
            }
            if block.parent_block_id != expected_parent {
                return Err(RestoreCatchupError::AnchorMismatch {
                    expected_height,
                    actual_height: block.height,
                    expected_block_id: expected_parent,
                    actual_parent_block_id: block.parent_block_id,
                });
            }
            if block.height != block.view {
                return Err(RestoreCatchupError::HeightViewMismatch {
                    height: block.height,
                    view: block.view,
                });
            }
            let expected_proposer = self.leader_for_view(block.view);
            if block.proposer != expected_proposer {
                return Err(RestoreCatchupError::WrongProposer {
                    view: block.view,
                    expected: expected_proposer,
                    actual: block.proposer,
                });
            }
            let expected_block_id = Self::derive_block_id_from_header(
                block.proposer,
                block.view,
                &block.parent_block_id,
            );
            if block.block_id != expected_block_id {
                return Err(RestoreCatchupError::BlockIdMismatch {
                    height: block.height,
                    expected: expected_block_id,
                    actual: block.block_id,
                });
            }

            let qc = QuorumCertificate::new(block.block_id, block.view, block.qc_signers.clone());
            qc.validate(self.validators())
                .map_err(RestoreCatchupError::InvalidQc)?;

            self.state.register_block(
                block.block_id,
                block.view,
                Some(block.parent_block_id),
                previous_qc.clone(),
            );
            for signer in &block.qc_signers {
                self.state
                    .on_vote(*signer, block.view, &block.block_id)
                    .map_err(RestoreCatchupError::InvalidQc)?;
            }

            previous_qc = Some(qc);
            expected_parent = block.block_id;
            expected_height = expected_height.saturating_add(1);
            applied = applied.saturating_add(1);
        }

        // After replaying a valid certified suffix, resume at the first
        // height/view not covered by the learned material so the restored
        // node does not re-propose or re-vote below its new committed floor.
        if self.current_view < expected_height {
            self.set_view(expected_height);
        }

        Ok(applied)
    }

    /// Called when this node is leader for the current view.
    ///
    /// Returns a list of actions to be performed:
    /// - `BroadcastProposal` for the new block proposal
    /// - `BroadcastVote` for the leader's own vote on the proposal
    ///
    /// Returns an empty Vec if we are not the leader or have already proposed.
    ///
    /// # Two-Node Liveness
    ///
    /// In a 2-node setup with 2/3 quorum requirement, both nodes must vote and
    /// both votes must be seen by someone to form a QC. The leader broadcasts
    /// both its proposal AND its vote so that the follower can collect both
    /// votes and form a QC.
    pub fn on_leader_step(&mut self) -> Vec<ConsensusEngineAction<ValidatorId>> {
        if !self.is_leader_for_current_view() {
            return Vec::new();
        }

        if self.proposed_in_view {
            return Vec::new();
        }

        let view = self.current_view;

        // Parent is the locked block or committed block or none.
        // Note: We use [0xFF; 32] as the sentinel for "no parent" because [0u8; 32]
        // can be a valid block_id. Specifically, the first proposal with proposer=0,
        // view=0, and parent=[0u8;32] produces block_id=[0u8;32], making it unsuitable
        // as a sentinel value.
        let parent_id = self
            .state
            .locked_qc()
            .map(|qc| qc.block_id)
            .or_else(|| self.state.committed_block().cloned());

        let parent_block_id = parent_id.unwrap_or([0xFF; 32]);

        // Build a proposal - use consistent block_id derivation
        let block_id = self.make_block_id(&parent_block_id);

        let justify_qc = self.state.locked_qc().cloned();

        // Register the block in our local state
        self.state
            .register_block(block_id, view, parent_id, justify_qc.clone());

        // Build the wire-format proposal
        use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

        let epoch = self.current_epoch;

        // Run 096 — consume any pending local-operator-gated reconfig
        // proposal intent. The intent is single-shot: it is taken
        // (cleared) exactly when we build a proposal carrying it. We
        // re-validate the monotonicity invariant at consume time so a
        // stale intent (engine somehow already at or past the target
        // by other means) never produces a synthetic / regressive
        // reconfig block — we just emit a normal block and drop the
        // intent. This preserves the canonical reconfig representation
        // (no parallel format) and the existing block-id derivation
        // (the canonical reconfig fields are simply set on the same
        // `BlockHeader`). No epoch is derived from wall-clock /
        // height / view / timer ticks — the value is exactly the
        // operator-supplied `target_epoch`.
        let (payload_kind, next_epoch_for_header) =
            match self.pending_reconfig_next_epoch.take() {
                Some(target) if target > self.current_epoch => {
                    (qbind_wire::PAYLOAD_KIND_RECONFIG, target)
                }
                Some(_) => {
                    // Stale intent (engine already at/past target).
                    // Drop it silently and emit a normal block.
                    (qbind_wire::PAYLOAD_KIND_NORMAL, 0)
                }
                None => (qbind_wire::PAYLOAD_KIND_NORMAL, 0),
            };

        let proposal = BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                epoch,
                height: view,
                round: view,
                parent_block_id,
                payload_hash: [0u8; 32],
                proposer_index: self.local_id.0 as u16,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 0,
                payload_kind,
                next_epoch: next_epoch_for_header,
                batch_commitment: [0u8; 32],
            },
            qc: justify_qc.map(|qc| {
                // Convert our logical QC to wire format
                use qbind_wire::consensus::QuorumCertificate as WireQc;
                WireQc {
                    version: 1,
                    chain_id: 1,
                    epoch,
                    height: qc.view,
                    round: qc.view,
                    step: 0,
                    block_id: qc.block_id,
                    suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                    signer_bitmap: vec![],
                    signatures: vec![],
                }
            }),
            txs: vec![],
            signature: vec![],
        };

        self.proposed_in_view = true;

        // Vote for our own proposal
        let result = self.state.on_vote(self.local_id, view, &block_id);
        self.voted_in_view = true;

        // Record self-vote observation (T127)
        if result.is_ok() {
            if let Some(recorder) = self.progress_recorder.as_ref() {
                recorder.record_vote_observed(true); // Self-vote is always for current view
            }
            // Record per-validator self-vote (T128)
            if let Some(recorder) = self.validator_vote_recorder.as_ref() {
                recorder.on_validator_vote(self.local_id, view);
            }
        }

        // Build the leader's vote to broadcast
        let vote = Vote {
            version: 1,
            chain_id: 1,
            epoch,
            height: view,
            round: view,
            step: 0,
            block_id,
            validator_index: self.local_id.0 as u16,
            // Run 422 — outgoing-Vote-suite metadata selected at construction.
            suite_id: self.vote_suite_id,
            signature: vec![],
        };

        // If a QC was formed immediately (e.g., single node), record and advance view
        if let Ok(Some(_qc)) = result {
            // Record QC formation with latency (T127)
            if let Some(recorder) = self.progress_recorder.as_ref() {
                if let Some(start) = self.last_view_start_instant {
                    let latency = start.elapsed();
                    recorder.record_qc_formed_with_latency(latency);
                } else {
                    recorder.record_qc_formed();
                }
            }
            self.advance_view();
        }

        // Return both actions: broadcast proposal and broadcast leader's vote
        vec![
            ConsensusEngineAction::BroadcastProposal(Box::new(proposal)),
            ConsensusEngineAction::BroadcastVote(vote),
        ]
    }

    /// Called when we receive a proposal from the network.
    ///
    /// Returns a `BroadcastVote` action if we should vote for the proposal,
    /// or `None` if we should not vote.
    ///
    /// # Epoch Validation (T101)
    ///
    /// If the proposal's header.epoch doesn't match the engine's `current_epoch`,
    /// we reject the proposal (return None). Future work may add explicit error handling.
    pub fn on_proposal_event(
        &mut self,
        from: ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
    ) -> Option<ConsensusEngineAction<ValidatorId>> {
        // Legacy / absent-QC / unverified path: no retained evidence.
        self.ingest_proposal(from, proposal, None, None, DecisionHook::None)
    }

    /// Run 422 §13.6 spike: legacy ingestion entrypoint with scoped borrowed
    /// safety-decision observation. Identical to [`Self::on_proposal_event`]
    /// except that `observer` is invoked at the real safety decision, before
    /// the self-vote. Preserves the legacy entrypoint's evidence guarantees
    /// (no retained evidence); the observation never authorizes anything.
    pub fn on_proposal_event_observed(
        &mut self,
        from: ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        observer: &mut dyn SafetyDecisionObserver<[u8; 32]>,
    ) -> Option<ConsensusEngineAction<ValidatorId>> {
        self.ingest_proposal(from, proposal, None, None, DecisionHook::Observe(observer))
    }

    /// Run 422 §13.6: legacy ingestion entrypoint with a scoped borrowed
    /// fallible [`SafetyDecisionGate`]. Identical to [`Self::on_proposal_event`]
    /// except that, after the real successful safety decision and strictly
    /// before the self-vote, `gate` is consulted once and may **refuse** it.
    ///
    /// Returns:
    /// * `Ok(Some(BroadcastVote))` when the gate allows — byte-identical to the
    ///   corresponding [`Self::on_proposal_event`] outcome and resulting state;
    /// * `Ok(None)` for an **ordinary** rejection reached before the decision
    ///   (wrong epoch/view/leader, already voted, unsafe proposal) — exactly as
    ///   the unobserved route returns `None`; or
    /// * `Err(GatedSelfVoteRefusal)` when the gate declines or the required
    ///   decision-view candidate is absent. On refusal there is no self-vote,
    ///   no lock transition, and no emitted `Vote`; `voted_in_view` is left
    ///   unset so a subsequent admissible proposal for the same view can still
    ///   be voted for. The gate establishes no authorization or permission to
    ///   sign and uses no panic for a normal refusal. Evidence guarantees of the
    ///   legacy entrypoint (no retained evidence) are unchanged.
    pub fn on_proposal_event_gated(
        &mut self,
        from: ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        gate: &mut dyn SafetyDecisionGate<[u8; 32]>,
    ) -> Result<Option<ConsensusEngineAction<ValidatorId>>, GatedSelfVoteRefusal> {
        let mut refusal: Option<GatedSelfVoteRefusal> = None;
        let action = self.ingest_proposal(
            from,
            proposal,
            None,
            None,
            DecisionHook::Gate {
                gate,
                refusal: &mut refusal,
            },
        );
        if let Some(refusal) = refusal {
            // A gate refusal never leaves a cast vote behind.
            debug_assert!(action.is_none(), "refusal must not emit an action");
            return Err(refusal);
        }
        Ok(action)
    }

    /// Run 422 §13.6 — isolated, opt-in **owning** gated entrypoint (additive,
    /// NOT wired). Identical control flow to [`Self::on_proposal_event_gated`],
    /// except the gate is an [`OwningSafetyDecisionGate`] that, on allow,
    /// produces an opaque payload `P`. On a successful self-vote the engine
    /// moves its own emitted `Vote` together with that payload into a closed
    /// [`DecidedVote`] and returns it.
    ///
    /// The payload is produced **inside** the gate call, strictly before the
    /// self-vote; the engine never inspects, extracts, or replaces it. Returns:
    /// * `Ok(Some(DecidedVote))` when the gate allows — the carried `Vote` is
    ///   byte-identical to the corresponding ungated/gated route's emitted vote;
    /// * `Ok(None)` for an **ordinary** rejection reached before the decision
    ///   (the gate is never consulted, so no payload is produced); or
    /// * `Err(GatedSelfVoteRefusal)` when the gate declines or the required
    ///   decision-view candidate is absent. On refusal no payload is produced,
    ///   no self-vote or lock transition occurs, and `voted_in_view` is left
    ///   unset so a later admissible proposal for the same view can still vote.
    ///
    /// This reuses the landed [`Self::on_proposal_event_gated`] body via an
    /// internal adapter; it introduces no new multiplicity, registry slot, or
    /// accounting boundary of its own. Any ownership the payload carries (e.g. a
    /// captured pin/reservation on the node side) is entirely the gate's; the
    /// engine establishes no authorization, durable correspondence, or signing
    /// permission.
    pub fn on_proposal_event_gated_owning<P>(
        &mut self,
        from: ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        gate: &mut dyn OwningSafetyDecisionGate<[u8; 32], P>,
    ) -> Result<Option<DecidedVote<P>>, GatedSelfVoteRefusal> {
        let mut adapter = OwningGateAdapter {
            gate,
            captured: None,
        };
        let mut refusal: Option<GatedSelfVoteRefusal> = None;
        let action = self.ingest_proposal(
            from,
            proposal,
            None,
            None,
            DecisionHook::Gate {
                gate: &mut adapter,
                refusal: &mut refusal,
            },
        );
        if let Some(refusal) = refusal {
            // A gate refusal never leaves a cast vote or a captured payload.
            debug_assert!(action.is_none(), "refusal must not emit an action");
            debug_assert!(
                adapter.captured.is_none(),
                "refusal must not capture a payload"
            );
            return Err(refusal);
        }
        match (action, adapter.captured) {
            // Allow path: the gate produced a payload and the engine emitted its
            // own self-vote. Bind them into the closed envelope.
            (Some(ConsensusEngineAction::BroadcastVote(vote)), Some(payload)) => {
                Ok(Some(DecidedVote::new(vote, payload)))
            }
            // Ordinary pre-decision rejection: the gate was never consulted, so
            // there is neither a payload nor a vote.
            (None, None) => Ok(None),
            // Defensive: the allow path must pair a BroadcastVote with a
            // captured payload. Any other combination is a logic error; drop any
            // captured payload (releasing its reservations) rather than fabricate
            // an unbacked association, and report no decided vote.
            (_other, captured) => {
                debug_assert!(
                    false,
                    "owning allow path must yield BroadcastVote paired with a payload"
                );
                drop(captured);
                Ok(None)
            }
        }
    }

    /// Run 422 D7-C3F: verified embedded-QC ingestion entrypoint.
    ///
    /// This is the smallest explicit engine entrypoint for handing the
    /// [`VerifiedQuorumCertificate`] produced by the caller's own C3E
    /// verification (under its admitted snapshot) into the engine, so the
    /// engine can **retain** that evidence with the proposed block's
    /// justification. It reuses the existing proposal-processing logic
    /// ([`Self::on_proposal_event`]'s shared body) rather than copying it.
    ///
    /// Before it changes engine view, registers a block, records a vote, or
    /// emits an action it enforces, with bounded typed errors and **no** engine
    /// mutation on failure and **no** fallback to the legacy/raw entrypoint:
    ///
    /// 1. A present embedded QC is required
    ///    ([`VerifiedProposalIngestError::MissingEmbeddedQc`]).
    /// 2. The supplied evidence corresponds **exactly** to that QC — all wire
    ///    fields, bitmap and signature bytes — via `WireQuorumCertificate`'s
    ///    derived equality
    ///    ([`VerifiedProposalIngestError::EvidenceCertificateMismatch`]).
    /// 3. Proposal/QC/evidence wire-chain and epoch correspondence hold against
    ///    the already-established contract
    ///    ([`VerifiedProposalIngestError::WireChainMismatch`],
    ///    [`VerifiedProposalIngestError::EpochMismatch`]).
    /// 4. The retained certificate fits the retained-evidence byte budget
    ///    ([`VerifiedProposalIngestError::RetentionBudgetExceeded`]).
    ///
    /// The proposal and QC are never rewritten to force a match. Signer
    /// identities, if needed, are those already carried by the evidence
    /// (`VerifiedQuorumCertificate::signers()`); no second signer list is
    /// decoded and **no** second constituent-signature verification is
    /// performed here.
    ///
    /// On success it returns the same `Option<ConsensusEngineAction>` as
    /// [`Self::on_proposal_event`]; if the engine registers the proposed block,
    /// the evidence is retained as that block's `verified_justification`
    /// (observable via [`HotStuffStateEngine::verified_justification`]).
    pub fn on_verified_proposal_event(
        &mut self,
        from: ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        evidence: Arc<VerifiedQuorumCertificate>,
    ) -> Result<Option<ConsensusEngineAction<ValidatorId>>, VerifiedProposalIngestError> {
        self.ingest_verified_proposal(from, proposal, evidence, DecisionHook::None)
    }

    /// Run 422 §13.6 spike: verified ingestion entrypoint with scoped borrowed
    /// safety-decision observation. Identical pre-checks and evidence
    /// guarantees as [`Self::on_verified_proposal_event`]; `observer` is invoked
    /// at the real safety decision, before the self-vote. The observation never
    /// authorizes anything and does not relax any pre-check.
    pub fn on_verified_proposal_event_observed(
        &mut self,
        from: ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        evidence: Arc<VerifiedQuorumCertificate>,
        observer: &mut dyn SafetyDecisionObserver<[u8; 32]>,
    ) -> Result<Option<ConsensusEngineAction<ValidatorId>>, VerifiedProposalIngestError> {
        self.ingest_verified_proposal(from, proposal, evidence, DecisionHook::Observe(observer))
    }

    /// Run 422 §13.6: verified ingestion entrypoint with a scoped borrowed
    /// fallible [`SafetyDecisionGate`]. The verified pre-checks (present QC,
    /// exact evidence match, wire-chain/epoch, retention budget, block-slot) are
    /// identical to [`Self::on_verified_proposal_event`] and run BEFORE any
    /// mutation; the gate is consulted once at the real successful safety
    /// decision, strictly before the self-vote, and may **refuse** it.
    ///
    /// The two failure kinds are kept distinct in the typed error:
    /// * [`GatedVerifiedProposalError::Ingest`] — a verified pre-check rejected
    ///   the proposal before the safety decision (no mutation, no legacy
    ///   fallback); identical to the [`VerifiedProposalIngestError`] the
    ///   non-gated verified entrypoint would return.
    /// * [`GatedVerifiedProposalError::Gate`] — the pre-checks passed, the
    ///   decision was `Safe(_)`, and the gate declined the dependent self-vote
    ///   (or the decision-view candidate was absent). On a gate refusal there is
    ///   no self-vote, no lock transition, and no emitted `Vote`;
    ///   `voted_in_view` is left unset. The gate never relaxes a pre-check and
    ///   never authorizes anything.
    pub fn on_verified_proposal_event_gated(
        &mut self,
        from: ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        evidence: Arc<VerifiedQuorumCertificate>,
        gate: &mut dyn SafetyDecisionGate<[u8; 32]>,
    ) -> Result<Option<ConsensusEngineAction<ValidatorId>>, GatedVerifiedProposalError> {
        let mut refusal: Option<GatedSelfVoteRefusal> = None;
        let action = self
            .ingest_verified_proposal(
                from,
                proposal,
                evidence,
                DecisionHook::Gate {
                    gate,
                    refusal: &mut refusal,
                },
            )
            .map_err(GatedVerifiedProposalError::Ingest)?;
        if let Some(refusal) = refusal {
            debug_assert!(action.is_none(), "refusal must not emit an action");
            return Err(GatedVerifiedProposalError::Gate(refusal));
        }
        Ok(action)
    }

    /// Run 422 §13.6: verified ingestion with an opaque owning payload bound to
    /// the engine-produced self-vote. All verified-ingestion pre-checks run
    /// before the owning gate, and the supplied evidence is moved through the
    /// existing verified path without re-verification or legacy fallback.
    ///
    /// Gate refusal prevents the self-vote and Vote action. Earlier permitted
    /// bookkeeping in `ingest_proposal` (such as future-view advancement or
    /// candidate registration/evidence retention) is not rolled back.
    pub fn on_verified_proposal_event_gated_owning<P>(
        &mut self,
        from: ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        evidence: Arc<VerifiedQuorumCertificate>,
        gate: &mut dyn OwningSafetyDecisionGate<[u8; 32], P>,
    ) -> Result<Option<DecidedVote<P>>, GatedVerifiedProposalError> {
        let mut adapter = OwningGateAdapter {
            gate,
            captured: None,
        };
        let mut refusal: Option<GatedSelfVoteRefusal> = None;
        let action = self
            .ingest_verified_proposal(
                from,
                proposal,
                evidence,
                DecisionHook::Gate {
                    gate: &mut adapter,
                    refusal: &mut refusal,
                },
            )
            .map_err(GatedVerifiedProposalError::Ingest)?;
        if let Some(refusal) = refusal {
            debug_assert!(action.is_none(), "refusal must not emit an action");
            debug_assert!(
                adapter.captured.is_none(),
                "refusal must not capture a payload"
            );
            return Err(GatedVerifiedProposalError::Gate(refusal));
        }
        match (action, adapter.captured) {
            (Some(ConsensusEngineAction::BroadcastVote(vote)), Some(payload)) => {
                Ok(Some(DecidedVote::new(vote, payload)))
            }
            (None, None) => Ok(None),
            (_other, captured) => {
                debug_assert!(
                    false,
                    "owning allow path must yield BroadcastVote paired with a payload"
                );
                drop(captured);
                Ok(None)
            }
        }
    }

    /// Shared verified-ingestion body: runs the C3F pre-checks (present QC,
    /// exact evidence match, wire-chain/epoch, retention budget, block-slot)
    /// BEFORE any mutation, then delegates to [`Self::ingest_proposal`] with the
    /// evidence and an optional observer.
    fn ingest_verified_proposal(
        &mut self,
        from: ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        evidence: Arc<VerifiedQuorumCertificate>,
        hook: DecisionHook<'_>,
    ) -> Result<Option<ConsensusEngineAction<ValidatorId>>, VerifiedProposalIngestError> {
        // (1) Require a present embedded QC. Absent-QC/bootstrap authorization
        // is explicitly out of scope and must not be routed here.
        let qc = proposal
            .qc
            .as_ref()
            .ok_or(VerifiedProposalIngestError::MissingEmbeddedQc)?;

        // (2) The evidence must correspond EXACTLY to the present embedded QC,
        // including every wire field, the signer bitmap and all signature
        // bytes. `WireQuorumCertificate` derives `PartialEq`/`Eq`, so `==`
        // compares the whole certificate. Never rewrite either side to match.
        if evidence.certificate() != qc {
            return Err(VerifiedProposalIngestError::EvidenceCertificateMismatch);
        }

        // (3) Wire-chain and epoch correspondence against the established
        // contract: the proposal must be bound to the same wire chain and epoch
        // the evidence records verification under. (The QC's own chain_id/epoch
        // were already bound to the evidence by the exact-match check above; the
        // remaining check ties the *outer proposal* to that same context.)
        if proposal.header.chain_id != evidence.expected_wire_chain_id() {
            return Err(VerifiedProposalIngestError::WireChainMismatch {
                proposal_chain_id: proposal.header.chain_id,
                evidence_chain_id: evidence.expected_wire_chain_id(),
            });
        }
        if proposal.header.epoch != evidence.authorized_epoch() {
            return Err(VerifiedProposalIngestError::EpochMismatch {
                proposal_epoch: proposal.header.epoch,
                evidence_epoch: evidence.authorized_epoch(),
            });
        }

        // (4) Reserve retention before any engine effects, so no permitted
        // ledger admission can race between preflight and registration.
        let block_id = Self::derive_block_id_from_header(
            from,
            proposal.header.height,
            &proposal.header.parent_block_id,
        );
        let needed = evidence
            .retained_byte_size()
            .map_err(|_| VerifiedProposalIngestError::RetentionChargeUnrepresentable)?;
        let admission = self
            .state
            .reserve_verified_justification(block_id, needed)
            .map_err(|error| match error {
                crate::hotstuff_state_engine::EvidenceRetentionError::BudgetExceeded {
                    needed_bytes,
                    retained_bytes,
                    max_bytes,
                } => VerifiedProposalIngestError::RetentionBudgetExceeded {
                    needed_bytes,
                    retained_bytes,
                    max_bytes,
                },
                _ => VerifiedProposalIngestError::RetentionChargeUnrepresentable,
            })?;
        if !self.state.can_admit_block_slot(&block_id) {
            drop(admission);
            return Err(VerifiedProposalIngestError::RetentionCapacityUnavailable {
                block_count: self.state.block_count(),
                max_pending_blocks: self.state.limits().max_pending_blocks,
            });
        }

        // Delegate to the shared proposal-processing body with the evidence.
        Ok(self.ingest_proposal(from, proposal, Some(evidence), Some(admission), hook))
    }

    /// Shared proposal-processing body for [`Self::on_proposal_event`] (legacy,
    /// `verified_evidence = None`) and [`Self::on_verified_proposal_event`]
    /// (`verified_evidence = Some`). Identical logic in both cases except that,
    /// when evidence is supplied and the block is registered, the evidence is
    /// retained as the block's `verified_justification`.
    fn ingest_proposal(
        &mut self,
        from: ValidatorId,
        proposal: &qbind_wire::consensus::BlockProposal,
        verified_evidence: Option<Arc<VerifiedQuorumCertificate>>,
        admission: Option<VerifiedQcAdmission<[u8; 32]>>,
        hook: DecisionHook<'_>,
    ) -> Option<ConsensusEngineAction<ValidatorId>> {
        // T101: Epoch validation - reject proposals from wrong epoch
        if proposal.header.epoch != self.current_epoch {
            // Log and reject (future work: return explicit error)
            return None;
        }

        let view = proposal.header.height;

        // If proposal is for a future view, advance directly to it
        if view > self.current_view {
            self.current_view = view;
            self.proposed_in_view = false;
            self.voted_in_view = false;
        }

        // Only process proposals for our current view
        if view != self.current_view {
            return None;
        }

        // Only accept proposals from the leader for this view
        let expected_leader = self.leader_for_view(view);
        if from != expected_leader {
            return None;
        }

        // Don't vote twice in the same view
        if self.voted_in_view {
            return None;
        }

        // Derive the block_id consistently using the same function as the proposer
        let block_id = Self::derive_block_id_from_header(
            from, // proposer's id
            view,
            &proposal.header.parent_block_id,
        );

        // Parse the logical justify QC from the proposal for the LEGACY path.
        // The verified path derives its logical justification from the verified
        // evidence inside the state engine instead (never from this wire
        // projection), so the two can never diverge.
        let justify_qc = proposal
            .qc
            .as_ref()
            .map(|wire_qc| QuorumCertificate::new(wire_qc.block_id, wire_qc.height, vec![]));

        // Register the block in our state.
        // Note: We use [0xFF; 32] as the sentinel for "no parent" because [0u8; 32]
        // can be a valid block_id. Specifically, the first proposal with proposer=0,
        // view=0, and parent=[0u8;32] produces block_id=[0u8;32], making it unsuitable
        // as a sentinel value.
        let parent_id = if proposal.header.parent_block_id == [0xFF; 32] {
            None
        } else {
            Some(proposal.header.parent_block_id)
        };
        // Register the block, retaining verified evidence as its justification
        // when supplied through the verified ingestion path. The caller
        // (`on_verified_proposal_event`) has already pre-checked the checked
        // charge, the byte budget AND the block-slot admissibility before any
        // mutation, so this registration is structurally guaranteed to admit
        // the candidate (block-slot room is made by evicting OTHER blocks, never
        // this candidate). We still propagate any (unreachable) failure
        // explicitly — never `let _ =`, a panic, or a post-effect rollback: on
        // failure we abort WITHOUT self-voting or emitting any action.
        let verified_entrypoint = verified_evidence.is_some();
        match (verified_evidence, admission) {
            (Some(evidence), Some(admission)) => {
                if self
                    .state
                    .register_block_with_admission(block_id, view, parent_id, evidence, admission)
                    .is_err()
                {
                    return None;
                }
            }
            (None, None) => {
                self.state
                    .register_block(block_id, view, parent_id, justify_qc);
            }
            _ => std::process::abort(),
        }

        // Enforce locked-block safety: only vote if this block is on a chain
        // that includes the locked block as an ancestor (or if there is no lock
        // yet). Run 422 §13.6 spike: evaluate the decision ONCE (typed), so the
        // branch that decided safety and the lock in effect are captured from
        // the SAME evaluation and can be observed BEFORE the self-vote mutates
        // state. An `Unsafe` decision emits no observation (early refusal).
        match self.state.safety_decision(&block_id) {
            SafetyDecision::Unsafe => {
                // Proposal is on a conflicting fork; do not vote, do not observe.
                return None;
            }
            SafetyDecision::Safe(branch) => {
                // Scoped borrowed observation/gating at the real decision,
                // strictly before `on_vote`. The borrow of `self.state` here
                // ends with this block, before the mutable `on_vote` call below.
                //
                // Run 422 §13.6 correction — eliminate silent observation
                // omission. The observation/gating input is the just-registered
                // candidate block. It is NOT guaranteed present: under
                // block-slot pressure (e.g. `max_pending_blocks == 0`)
                // `register_block` immediately evicts the candidate it just
                // registered, and a `NoLock` decision can succeed WITHOUT
                // looking up the candidate (a `ViewSufficiency` decision, by
                // contrast, requires that lookup because it reads the
                // candidate's `justify_qc`). The earlier revision then
                // silently skipped observation and self-voted anyway.
                //
                // Per hook:
                // * `None` (unobserved legacy / verified route) — unchanged:
                //   proceed straight to the self-vote.
                // * `Observe` — preserved historical behavior: observe when the
                //   candidate is present; if it is absent, silently refuse to
                //   self-vote and emit no action ("observe and vote, or do
                //   neither"). The safety predicate is untouched.
                // * `Gate` — the opt-in fallible route: build the SAME decision
                //   view and consult the gate exactly once. If the candidate is
                //   absent, report `MissingCandidate`; if the gate declines,
                //   report `GateRejected`. In BOTH refusal cases return no
                //   action here, BEFORE the self-vote or `BroadcastVote`, and
                //   WITHOUT setting `voted_in_view`, so the refusal casts no
                //   vote, drives no lock transition, and does not consume the
                //   vote opportunity. No panic is used for a normal refusal.
                match hook {
                    DecisionHook::None => {}
                    DecisionHook::Observe(observer) => match self.state.get_block(&block_id) {
                        Some(candidate) => {
                            let decision = SafetyDecisionView {
                                state: &self.state,
                                candidate,
                                locked: self.state.locked_qc(),
                                branch,
                                origin_view: view,
                                from,
                                verified_entrypoint,
                            };
                            observer.observe(&decision);
                        }
                        None => {
                            // Explicit: the observation input is absent (the
                            // candidate was evicted under block-slot pressure).
                            // Do not fabricate a view, do not self-vote, do not
                            // emit an action on the observed route.
                            return None;
                        }
                    },
                    DecisionHook::Gate { gate, refusal } => {
                        match self.state.get_block(&block_id) {
                            Some(candidate) => {
                                let decision = SafetyDecisionView {
                                    state: &self.state,
                                    candidate,
                                    locked: self.state.locked_qc(),
                                    branch,
                                    origin_view: view,
                                    from,
                                    verified_entrypoint,
                                };
                                if let Err(r) = gate.evaluate(&decision) {
                                    // Gate declined: refuse the self-vote with no
                                    // mutation, no lock transition, no action.
                                    *refusal = Some(GatedSelfVoteRefusal::GateRejected(r));
                                    return None;
                                }
                                // Gate allowed: fall through to the self-vote,
                                // which is then byte-identical to the
                                // corresponding unobserved route.
                            }
                            None => {
                                // Required decision-view candidate absent: refuse
                                // rather than cast an un-gated vote.
                                *refusal = Some(GatedSelfVoteRefusal::MissingCandidate);
                                return None;
                            }
                        }
                    }
                }
            }
        }

        // Create and ingest our own vote
        // Errors here would indicate a bug in our code (voting for a block we just registered)
        let vote_result = self.state.on_vote(self.local_id, view, &block_id);
        debug_assert!(
            vote_result.is_ok(),
            "self-vote should not fail: {:?}",
            vote_result
        );

        self.voted_in_view = true;

        // Create a vote to broadcast
        use qbind_wire::consensus::Vote;

        let vote = Vote {
            version: 1,
            chain_id: 1,
            epoch: self.current_epoch,
            height: view,
            round: view,
            step: 0,
            block_id,
            validator_index: self.local_id.0 as u16,
            // Run 422 — outgoing-Vote-suite metadata selected at construction.
            // This is the self-vote the owning envelope (`DecidedVote`) carries.
            suite_id: self.vote_suite_id,
            signature: vec![],
        };

        // NOTE: We do NOT advance view here. View advancement happens only when
        // a QC is formed (either locally via on_vote_event, or when the leader
        // processes our vote and forms the QC). This ensures all nodes stay
        // synchronized on the same view until consensus is reached.

        Some(ConsensusEngineAction::BroadcastVote(vote))
    }

    /// Called when we receive a vote from the network.
    ///
    /// This ingests the vote into our state engine. If a QC is formed,
    /// we advance to the next view.
    ///
    /// Returns `None` as we don't emit further network actions on vote receipt.
    ///
    /// # Epoch Validation (T101)
    ///
    /// If the vote's epoch doesn't match the engine's `current_epoch`,
    /// returns `Err(ConsensusVerifyError::WrongEpoch)`.
    ///
    /// # Metrics (T127, T128)
    ///
    /// Records vote observation and QC formation events if a progress recorder
    /// is attached. Records per-validator vote events if a validator vote recorder
    /// is attached.
    pub fn on_vote_event(
        &mut self,
        from: ValidatorId,
        vote: &qbind_wire::consensus::Vote,
    ) -> Result<Option<QuorumCertificate<[u8; 32]>>, QcValidationError> {
        // T101: Epoch validation
        if vote.epoch != self.current_epoch {
            return Err(QcValidationError::Verify(
                crate::ConsensusVerifyError::WrongEpoch {
                    expected: self.current_epoch,
                    actual: vote.epoch,
                },
            ));
        }

        let view = vote.height;
        let block_id = vote.block_id;

        let report = self.state.on_vote_detailed(from, view, &block_id);
        let VoteMutationReport {
            history,
            accumulator: _,
            qc,
        } = report;
        let qc = match qc {
            Ok(qc) => qc,
            Err(error) => return Err(error),
        };
        self.finish_successful_vote_event(from, view, &history, qc.as_ref());
        Ok(qc)
    }

    fn finish_successful_vote_event(
        &mut self,
        from: ValidatorId,
        view: u64,
        history: &VoteHistoryOutcome<[u8; 32]>,
        qc: Option<&QuorumCertificate<[u8; 32]>>,
    ) -> bool {
        if matches!(history, VoteHistoryOutcome::Equivocation { .. }) {
            // Record equivocation event
            if let Some(recorder) = self.equivocation_recorder.as_ref() {
                recorder.on_validator_equivocation(from, view);
            }
            // Note: Equivocating votes are ignored by on_vote() and return Ok(None),
            // so we don't record them as valid votes in the progress/validator metrics
        } else {
            // Record vote observation (T127)
            // Note: We record after successful ingestion to only count valid votes
            if let Some(recorder) = self.progress_recorder.as_ref() {
                let is_for_current_view = view == self.current_view;
                recorder.record_vote_observed(is_for_current_view);
            }

            // Record per-validator vote (T128)
            // Note: We record after successful ingestion to only count valid votes
            if let Some(recorder) = self.validator_vote_recorder.as_ref() {
                recorder.on_validator_vote(from, view);
            }
        }

        let mut view_advanced = false;
        if qc.is_some() {
            // Record QC formation with latency if available (T127)
            if let Some(recorder) = self.progress_recorder.as_ref() {
                if let Some(start) = self.last_view_start_instant {
                    let latency = start.elapsed();
                    recorder.record_qc_formed_with_latency(latency);
                } else {
                    recorder.record_qc_formed();
                }
            }

            // Advance view if the QC is for our current view or later
            if view >= self.current_view {
                self.advance_view();
                view_advanced = true;
            }
        }
        view_advanced
    }

    /// Process a single step of the engine.
    ///
    /// This is called by the driver on each iteration. It:
    /// 1. Checks if we are leader and should propose
    /// 2. Returns any actions that should be broadcast
    ///
    /// The event parameter is the event from the network, if any.
    /// The driver should call `on_proposal_event` or `on_vote_event` before calling this.
    pub fn try_propose(&mut self) -> Vec<ConsensusEngineAction<ValidatorId>> {
        self.on_leader_step()
    }

    /// Verify that a message's epoch matches the current epoch (T101).
    ///
    /// Returns `Ok(())` if epochs match, or `Err(WrongEpoch)` if they don't.
    pub fn verify_epoch(&self, msg_epoch: u64) -> Result<(), crate::ConsensusVerifyError> {
        if msg_epoch != self.current_epoch {
            return Err(crate::ConsensusVerifyError::WrongEpoch {
                expected: self.current_epoch,
                actual: msg_epoch,
            });
        }
        Ok(())
    }

    // ========================================================================
    // Timeout / View-Change Methods (T146, M5)
    // ========================================================================

    /// Check if we have already emitted a timeout for the current view.
    pub fn timeout_emitted_in_view(&self) -> bool {
        self.timeout_emitted_in_view
    }

    /// Mark that we have emitted a timeout for the current view.
    ///
    /// This is called after broadcasting a TimeoutMsg to prevent duplicate emissions.
    pub fn mark_timeout_emitted(&mut self) {
        self.timeout_emitted_in_view = true;
    }

    /// Create a TimeoutMsg for the current view.
    ///
    /// This creates an unsigned timeout message. The caller is responsible for
    /// signing it before broadcasting.
    ///
    /// # Returns
    ///
    /// A `TimeoutMsg` ready to be signed and broadcast.
    pub fn create_timeout_msg(&self) -> TimeoutMsg<[u8; 32]> {
        let high_qc = self.state.locked_qc().cloned();
        TimeoutMsg::new(self.current_view, high_qc, self.local_id)
    }

    /// Safely advance to a target view with monotonicity enforcement (M5).
    ///
    /// This method ensures that the view number never decreases and logs
    /// any attempts to violate this invariant.
    ///
    /// # Arguments
    ///
    /// - `target_view`: The view to advance to
    ///
    /// # Returns
    ///
    /// - `true` if the view was successfully advanced
    /// - `false` if the target view is not greater than the current view (fail-closed)
    ///
    /// # Safety (M5)
    ///
    /// This method implements fail-closed behavior:
    /// - If target_view <= current_view, the view is NOT changed
    /// - An error is logged for monitoring/debugging
    /// - Safety is preserved over liveness
    pub fn try_advance_to_view(&mut self, target_view: u64) -> bool {
        if target_view <= self.current_view {
            // M5: Fail-closed behavior - log error but do not produce unsafe state
            eprintln!(
                "[M5] WARN: Attempted to advance to view {} but current_view is {} - ignoring to preserve safety",
                target_view, self.current_view
            );
            return false;
        }

        let from_view = self.current_view;

        // Record metrics
        self.record_view_duration_internal(from_view, target_view);
        self.record_progress_view_change_internal(from_view, target_view);

        // Update view state
        self.current_view = target_view;
        self.proposed_in_view = false;
        self.voted_in_view = false;
        self.timeout_emitted_in_view = false;
        self.last_view_start_instant = Some(Instant::now());

        true
    }

    /// Get the locked height from the locked QC (M5).
    ///
    /// This returns the view of the locked QC, which is used for safety checks
    /// to ensure validators don't vote below the locked height.
    ///
    /// # Returns
    ///
    /// - `Some(view)` if there is a locked QC
    /// - `None` if there is no lock yet (genesis state)
    pub fn locked_height(&self) -> Option<u64> {
        self.state.locked_qc().map(|qc| qc.view)
    }

    /// Check if it's safe to vote for a block at the given height (M5).
    ///
    /// This implements the locked-height safety check: validators should not
    /// vote for blocks that could conflict with already locked blocks.
    ///
    /// # Arguments
    ///
    /// - `justify_qc_view`: The view of the block's justify QC (optional)
    ///
    /// # Returns
    ///
    /// - `true` if voting is safe
    /// - `false` if voting could violate safety (fail-closed)
    ///
    /// # Safety Rules (M5)
    ///
    /// 1. If no locked QC, voting is allowed (genesis)
    /// 2. If justify_qc.view >= locked_qc.view, voting is allowed
    /// 3. Otherwise, fail-closed (do not vote)
    pub fn is_safe_to_vote_at_height(&self, justify_qc_view: Option<u64>) -> bool {
        let locked_view = match self.locked_height() {
            None => return true, // No lock yet, safe to vote
            Some(v) => v,
        };

        match justify_qc_view {
            Some(jv) if jv >= locked_view => true,
            _ => false,
        }
    }

    /// Process an incoming timeout message from another validator.
    ///
    /// This ingests the timeout message into the accumulator. If a
    /// TimeoutCertificate can be formed (2f+1 timeouts), it is returned.
    ///
    /// # Arguments
    ///
    /// - `from`: The validator who sent the timeout message
    /// - `timeout`: The timeout message
    ///
    /// # Returns
    ///
    /// - `Ok(Some(tc))` if a TimeoutCertificate was formed
    /// - `Ok(None)` if the timeout was accepted but no TC formed yet
    /// - `Err(TimeoutValidationError)` if the timeout was invalid
    ///
    /// # Note
    ///
    /// This method does NOT verify the signature. Signature verification
    /// should be done by the caller before calling this method.
    pub fn on_timeout_msg(
        &mut self,
        from: ValidatorId,
        timeout: TimeoutMsg<[u8; 32]>,
    ) -> Result<Option<TimeoutCertificate<[u8; 32]>>, TimeoutValidationError> {
        // Verify the sender matches the timeout's validator_id
        if from != timeout.validator_id {
            return Err(TimeoutValidationError::InvalidSignature(from));
        }

        // Only accept timeouts for current or future views
        if timeout.view < self.current_view {
            // Stale timeout - silently ignore
            return Ok(None);
        }

        // Ingest into accumulator
        let _is_new = self
            .timeout_accumulator
            .on_timeout(self.state.validators(), timeout)?;

        // Check if we can form a TC for this view
        let view = from; // Use the timeout's view for TC check
        let _ = view; // Unused, we use the timeout's view below

        // Try to form TC for any view where we have enough timeouts
        // Start from current_view and check upward
        for check_view in self.current_view..=self.current_view + 10 {
            if let Some(tc) = self
                .timeout_accumulator
                .maybe_tc_for(self.state.validators(), check_view)
            {
                return Ok(Some(tc));
            }
        }

        Ok(None)
    }

    /// Process a TimeoutCertificate to advance to a new view.
    ///
    /// This method is called when a TC is formed locally or received from
    /// another validator. It:
    /// 1. Validates the TC has sufficient signers
    /// 2. Updates the locked QC if the TC's high_qc is higher
    /// 3. Advances to the TC's target view
    ///
    /// # Arguments
    ///
    /// - `tc`: The timeout certificate
    ///
    /// # Returns
    ///
    /// - `Ok(new_view)` with the new view number if successful
    /// - `Err(TimeoutValidationError)` if the TC is invalid
    ///
    /// # Safety Invariants (T146)
    ///
    /// - The TC's high_qc becomes the justify_qc for the next proposal
    /// - If TC's high_qc.view > locked_qc.view, we update locked_qc
    /// - This maintains HotStuff safety: no conflicting commits
    pub fn on_timeout_certificate(
        &mut self,
        tc: &TimeoutCertificate<[u8; 32]>,
    ) -> Result<u64, TimeoutValidationError> {
        // Validate the TC
        tc.validate(self.state.validators())?;

        // Only process TCs for views > current_view
        if tc.view <= self.current_view {
            // TC is for an old view, ignore
            return Ok(self.current_view);
        }

        // T146 Safety: Update locked_qc if TC's high_qc is higher
        // This ensures we don't vote for blocks that conflict with committed blocks
        if let Some(ref tc_high_qc) = tc.high_qc {
            let should_update = match self.state.locked_qc() {
                None => true,
                Some(locked) => tc_high_qc.view > locked.view,
            };

            if should_update {
                // Update locked_qc through the state engine
                self.state.set_locked_qc(tc_high_qc.clone());
            }
        }

        // Advance to the TC's target view
        let from_view = self.current_view;
        let to_view = tc.view;

        // Record metrics
        self.record_view_duration_internal(from_view, to_view);
        self.record_progress_view_change_internal(from_view, to_view);

        // Update view state
        self.current_view = to_view;
        self.proposed_in_view = false;
        self.voted_in_view = false;
        self.timeout_emitted_in_view = false;
        self.last_view_start_instant = Some(Instant::now());

        // Clear old timeout messages
        self.timeout_accumulator.clear_view(tc.timeout_view);

        Ok(to_view)
    }

    /// Get the timeout accumulator (for testing/debugging).
    pub fn timeout_accumulator(&self) -> &TimeoutAccumulator<[u8; 32]> {
        &self.timeout_accumulator
    }

    /// Get the number of timeout messages collected for a view.
    pub fn timeout_count(&self, view: u64) -> usize {
        self.timeout_accumulator.timeout_count(view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_registry::SuiteAwareValidatorKeyProvider;
    use crate::received_vote_evidence::{SnapshotMember, VoteContextInput};
    use crate::qc_verify_domain::verify_quorum_certificate_with_domain;
    use crate::validator_set::ValidatorSetEntry;
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use std::collections::HashMap;
    use std::sync::Arc;

    const TEST_WIRE_CHAIN: u32 = 7;

    fn received_vote_table_charge() -> u64 {
        ReceivedVoteEvidenceTable::<[u8; 32]>::standing_charge()
            .expect("table charge is representable")
    }

    fn make_validator_set(num: u64) -> ConsensusValidatorSet {
        let entries: Vec<ValidatorSetEntry> = (1..=num)
            .map(|i| ValidatorSetEntry {
                id: ValidatorId(i),
                voting_power: 1,
            })
            .collect();
        ConsensusValidatorSet::new(entries).expect("valid set")
    }

    fn dense_validator_set(num: u64) -> ConsensusValidatorSet {
        ConsensusValidatorSet::new((0..num).map(|id| ValidatorSetEntry {
            id: ValidatorId(id),
            voting_power: 1,
        }))
        .expect("valid dense set")
    }

    fn signed_context_vote(
        epoch: u64,
        sk: &[u8],
        domain: &qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2,
    ) -> qbind_wire::consensus::Vote {
        let mut vote = qbind_wire::consensus::Vote {
            version: 1,
            chain_id: domain.expected_wire_chain_id(),
            epoch,
            height: 7,
            round: 9,
            step: 0,
            block_id: [0x73; 32],
            validator_index: 0,
            suite_id: qbind_crypto::SUITE_PQ_RESERVED_1.0,
            signature: Vec::new(),
        };
        let signature =
            MlDsa44Backend::sign(sk, &domain.vote_preimage(&vote)).expect("test vote signing");
        vote.signature = signature.into_boxed_slice().into_vec();
        vote
    }

    fn signed_member_vote(
        epoch: u64,
        validator_index: u16,
        height: u64,
        round: u64,
        block_id: [u8; 32],
        secret_key: &[u8],
        domain: &qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2,
    ) -> qbind_wire::consensus::Vote {
        let mut vote = qbind_wire::consensus::Vote {
            version: 1,
            chain_id: domain.expected_wire_chain_id(),
            epoch,
            height,
            round,
            step: 0,
            block_id,
            validator_index,
            suite_id: qbind_crypto::SUITE_PQ_RESERVED_1.0,
            signature: Vec::new(),
        };
        vote.signature =
            MlDsa44Backend::sign(secret_key, &domain.vote_preimage(&vote))
                .expect("test vote signing")
                .into_boxed_slice()
                .into_vec();
        vote
    }

    fn multi_member_vote_context(
        keypairs: &[(Vec<u8>, Vec<u8>)],
        epoch: u64,
        domain: &qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2,
    ) -> VoteContextInput {
        let members = keypairs
            .iter()
            .enumerate()
            .map(|(index, (public_key, _))| {
                SnapshotMember::new(
                    index as u64,
                    1,
                    public_key.clone().into_boxed_slice().into_vec(),
                )
            })
            .collect();
        VoteContextInput::new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            epoch,
            qbind_crypto::SUITE_PQ_RESERVED_1,
            domain.clone(),
            members,
        )
    }

    fn received_vote_context(
        epoch: u64,
        public_key: Vec<u8>,
    ) -> (
        VoteContextInput,
        qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2,
    ) {
        let runtime_chain = qbind_types::QBIND_DEVNET_CHAIN_ID;
        let domain = qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
            runtime_chain,
            TEST_WIRE_CHAIN,
            [0x31; 32],
            [0x42; 32],
        )
        .expect("valid test domain");
        (
            VoteContextInput::new(
                runtime_chain,
                epoch,
                qbind_crypto::SUITE_PQ_RESERVED_1,
                domain.clone(),
                vec![SnapshotMember::new(
                    0,
                    1,
                    public_key.into_boxed_slice().into_vec(),
                )],
            ),
            domain,
        )
    }

    #[derive(Debug)]
    struct ContextTestKeys(HashMap<ValidatorId, (qbind_crypto::ConsensusSigSuiteId, Vec<u8>)>);

    impl SuiteAwareValidatorKeyProvider for ContextTestKeys {
        fn get_suite_and_key(
            &self,
            validator: ValidatorId,
        ) -> Option<(qbind_crypto::ConsensusSigSuiteId, Vec<u8>)> {
            self.0.get(&validator).cloned()
        }
    }

    fn verified_test_qc(
        keypairs: &[(Vec<u8>, Vec<u8>)],
        signers: &[u16],
    ) -> (
        Arc<crate::qc_verify_domain::VerifiedQuorumCertificate>,
        qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2,
    ) {
        let runtime_chain = qbind_types::QBIND_DEVNET_CHAIN_ID;
        let domain = qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
            runtime_chain,
            TEST_WIRE_CHAIN,
            [0x51; 32],
            [0x62; 32],
        )
        .expect("valid QC test domain");
        let validators = dense_validator_set(keypairs.len() as u64);
        let mut keys = HashMap::new();
        for (index, (public_key, _)) in keypairs.iter().enumerate() {
            keys.insert(
                ValidatorId(index as u64),
                (qbind_crypto::SUITE_PQ_RESERVED_1, public_key.clone()),
            );
        }
        let key_provider = ContextTestKeys(keys);
        let mut certificate = qbind_wire::consensus::QuorumCertificate {
            version: 1,
            chain_id: TEST_WIRE_CHAIN,
            epoch: 0,
            height: 9,
            round: 9,
            step: 1,
            block_id: [0x91; 32],
            suite_id: qbind_crypto::SUITE_PQ_RESERVED_1.0,
            signer_bitmap: vec![0; keypairs.len().div_ceil(8)],
            signatures: Vec::new(),
        };
        for signer in signers {
            certificate.signer_bitmap[usize::from(*signer) / 8] |=
                1 << (usize::from(*signer) % 8);
            let vote = qbind_wire::consensus::Vote {
                version: certificate.version,
                chain_id: certificate.chain_id,
                epoch: certificate.epoch,
                height: certificate.height,
                round: certificate.round,
                step: certificate.step,
                block_id: certificate.block_id,
                validator_index: *signer,
                suite_id: certificate.suite_id,
                signature: Vec::new(),
            };
            let secret_key = &keypairs[usize::from(*signer)].1;
            certificate.signatures.push(
                MlDsa44Backend::sign(secret_key, &domain.vote_preimage(&vote))
                    .expect("test QC signing"),
            );
        }
        let registry = crate::crypto_verifier::SimpleBackendRegistry::with_backend(
            qbind_crypto::SUITE_PQ_RESERVED_1,
            Arc::new(MlDsa44Backend),
        );
        let evidence = verify_quorum_certificate_with_domain(
            &certificate,
            &domain,
            0,
            &validators,
            &key_provider,
            &registry,
        )
        .expect("test QC verifies");
        (Arc::new(evidence), domain)
    }

    fn proposal_for_test_evidence(
        view: u64,
        evidence: &crate::qc_verify_domain::VerifiedQuorumCertificate,
        proposer: u16,
    ) -> qbind_wire::consensus::BlockProposal {
        qbind_wire::consensus::BlockProposal {
            header: qbind_wire::consensus::BlockHeader {
                version: 1,
                chain_id: TEST_WIRE_CHAIN,
                epoch: 0,
                height: view,
                round: view,
                parent_block_id: [0xFF; 32],
                payload_hash: [0; 32],
                proposer_index: proposer,
                suite_id: qbind_crypto::SUITE_PQ_RESERVED_1.0,
                tx_count: 0,
                timestamp: 0,
                payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
                batch_commitment: [0; 32],
            },
            qc: Some(evidence.certificate().clone()),
            txs: Vec::new(),
            signature: Vec::new(),
        }
    }

    #[test]
    fn received_vote_context_admission_verifies_borrowed_key_and_preserves_signature() {
        let (public_key, secret_key) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let context_charge = input.checked_charge().expect("context charge");
        let sizing = EvidenceBudget::try_new(u64::MAX, 0).expect("sizing ledger");
        let standing_floor = sizing.occupancy().0;
        drop(sizing);
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        assert!(engine.install_received_vote_context(input).is_ok());
        let wrapper_charge = std::mem::size_of::<Option<ActiveVoteContext>>() as u64;
        let table_charge = received_vote_table_charge();
        println!(
            "received-vote accounting: standing={standing_floor} context={context_charge} active-wrapper={wrapper_charge} table={table_charge}"
        );
        assert_eq!(
            engine.received_vote_evidence_aggregate_bytes().unwrap().0,
            standing_floor + context_charge + wrapper_charge + table_charge
        );
        let vote = signed_context_vote(0, &secret_key, &domain);
        let signature_ptr = vote.signature.as_ptr();
        let signature_capacity = vote.signature.capacity();
        assert_eq!(signature_capacity, qbind_crypto::ML_DSA_44_SIGNATURE_SIZE);
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("valid signed Vote is admitted");
        println!(
            "received-vote token accounting: inline={} signature-capacity={signature_capacity}",
            std::mem::size_of::<VerifiedVoteToken>()
        );
        assert_eq!(token.vote().signature.as_ptr(), signature_ptr);
        assert_eq!(token.vote().signature.capacity(), signature_capacity);
        assert_eq!(
            engine.received_vote_evidence_aggregate_bytes().unwrap().1,
            0
        );
        assert_eq!(
            engine.received_vote_evidence_aggregate_bytes().unwrap().0,
            standing_floor
                + context_charge
                + wrapper_charge
                + table_charge
                + std::mem::size_of::<VerifiedVoteToken>() as u64
                + u64::try_from(signature_capacity).unwrap()
        );
        drop(token);
        assert_eq!(
            engine.received_vote_evidence_aggregate_bytes().unwrap().0,
            standing_floor + context_charge + wrapper_charge + table_charge
        );
    }

    #[test]
    fn received_vote_qc_stage_uses_first_retained_evidence_for_conflicting_duplicate() {
        let keypairs: Vec<_> = (0..4)
            .map(|_| MlDsa44Backend::generate_keypair().expect("test keygen"))
            .collect();
        let domain = qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            TEST_WIRE_CHAIN,
            [0xA1; 32],
            [0xB2; 32],
        )
        .expect("valid test domain");
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(4));
        engine
            .install_received_vote_context(multi_member_vote_context(&keypairs, 0, &domain))
            .expect("context install");
        let mut retained_votes = Vec::new();
        for (index, (_, secret_key)) in keypairs.iter().take(3).enumerate() {
            let vote = signed_member_vote(
                0,
                index as u16,
                1,
                9,
                [0xC3; 32],
                secret_key,
                &domain,
            );
            retained_votes.push(vote.clone());
            let token = engine
                .admit_verified_received_vote(ValidatorId(index as u64), vote)
                .expect("admit signed Vote");
            if index == 2 {
                let table = engine.state.received_vote_evidence_table().unwrap();
                assert!(table.entry_for(1, 0).is_some());
                assert!(table.entry_for(1, 1).is_some());
            }
            let report = engine
                .invoke_verified_received_vote_qc(token)
                .expect("invoke signed Vote");
            if index < 2 {
                assert!(matches!(report.outcome, ReceivedVoteQcOutcome::NoQc));
            } else {
                assert!(matches!(report.outcome, ReceivedVoteQcOutcome::Complete(_)));
            }
        }

        let conflicting = signed_member_vote(
            0,
            0,
            1,
            10,
            [0xC3; 32],
            &keypairs[0].1,
            &domain,
        );
        assert_ne!(conflicting.signature, retained_votes[0].signature);
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), conflicting.clone())
            .expect("admit valid conflicting duplicate");
        let report = engine
            .invoke_verified_received_vote_qc(token)
            .expect("invoke conflicting duplicate");
        assert!(matches!(
            report.actual.accumulator,
            Some(Ok(VoteAccumulatorDisposition::Duplicate))
        ));
        assert_eq!(
            report.actual.evidence,
            ReceivedVoteEvidenceDisposition::ExistingSignedFieldsConflict
        );
        let ReceivedVoteQcOutcome::Complete(wire) = report.outcome else {
            panic!("retained compatible evidence must produce a complete QC");
        };
        assert_eq!(wire.qc().round, 9);
        assert_eq!(wire.qc().signatures.len(), retained_votes.len());
        for (signature, retained) in wire.qc().signatures.iter().zip(&retained_votes) {
            assert_eq!(signature, &retained.signature);
        }
        assert_ne!(wire.qc().signatures[0], conflicting.signature);
    }

    #[test]
    fn received_vote_qc_stage_reports_mixed_fields_and_missing_legacy_evidence() {
        let keypairs: Vec<_> = (0..3)
            .map(|_| MlDsa44Backend::generate_keypair().expect("test keygen"))
            .collect();
        let domain = qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            TEST_WIRE_CHAIN,
            [0xA1; 32],
            [0xB2; 32],
        )
        .expect("valid test domain");
        let mut mixed = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(3));
        mixed
            .install_received_vote_context(multi_member_vote_context(&keypairs, 0, &domain))
            .expect("context install");
        let mixed_observer = mixed
            .state
            .received_vote_budget()
            .expect("installed ledger")
            .try_clone()
            .expect("ledger observer");
        let mut final_report = None;
        let mut final_before = None;
        for (index, (_, secret_key)) in keypairs.iter().enumerate() {
            let vote = signed_member_vote(
                0,
                index as u16,
                1,
                if index == 2 { 10 } else { 9 },
                [0xD4; 32],
                secret_key,
                &domain,
            );
            let token = mixed
                .admit_verified_received_vote(ValidatorId(index as u64), vote)
                .expect("admit signed Vote");
            let before = mixed_observer.full_occupancy_for_test();
            let report = mixed
                .invoke_verified_received_vote_qc(token)
                .expect("invoke signed Vote");
            if index == 2 {
                final_before = Some(before);
                final_report = Some(report);
            }
        }
        let mixed_report = final_report.expect("third vote report");
        let before = final_before.expect("third vote pre-invocation ledger");
        assert!(mixed_report.actual.qc.is_some());
        assert!(matches!(
            mixed_report.outcome,
            ReceivedVoteQcOutcome::Incomplete(
                ReceivedVoteQcIncomplete::CommonFieldsMismatch(2)
            )
        ));
        assert_eq!(
            mixed_observer.full_occupancy_for_test().0,
            before
                .0
                .checked_add(mixed_report._provenance.report_charge_for_test())
                .and_then(|bytes| {
                    bytes.checked_sub(std::mem::size_of::<VerifiedVoteToken>() as u64)
                })
                .expect("incomplete report ledger delta")
        );
        assert_eq!(mixed_observer.full_occupancy_for_test().1, 0);
        let _ = mixed.state_mut();
        drop(mixed);
        assert_eq!(mixed_observer.full_occupancy_for_test().2, 1);
        assert_eq!(mixed_observer.full_occupancy_for_test().4, 1);
        drop(mixed_report);
        assert_eq!(mixed_observer.full_occupancy_for_test().2, 0);
        assert_eq!(mixed_observer.full_occupancy_for_test().4, 0);

        let mut legacy = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(3));
        legacy
            .install_received_vote_context(multi_member_vote_context(&keypairs, 0, &domain))
            .expect("context install");
        for index in 0..2 {
            legacy
                .state
                .on_vote(ValidatorId(index), 1, &[0xE5; 32])
                .expect("seed legacy logical membership");
        }
        let vote = signed_member_vote(
            0,
            2,
            1,
            9,
            [0xE5; 32],
            &keypairs[2].1,
            &domain,
        );
        let token = legacy
            .admit_verified_received_vote(ValidatorId(2), vote)
            .expect("admit final signed Vote");
        let report = legacy
            .invoke_verified_received_vote_qc(token)
            .expect("invoke final signed Vote");
        assert!(report.actual.qc.is_some());
        assert!(matches!(
            report.outcome,
            ReceivedVoteQcOutcome::Incomplete(ReceivedVoteQcIncomplete::MissingEvidence(0))
        ));
    }

    #[test]
    fn received_vote_qc_stage_keeps_precopied_evidence_after_history_eviction() {
        let keypairs: Vec<_> = (0..4)
            .map(|_| MlDsa44Backend::generate_keypair().expect("test keygen"))
            .collect();
        let domain = qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            TEST_WIRE_CHAIN,
            [0xA1; 32],
            [0xB2; 32],
        )
        .expect("valid test domain");
        let limits = crate::vote_accumulator::ConsensusLimitsConfig {
            max_votes_by_view_entries: 2,
            ..crate::vote_accumulator::ConsensusLimitsConfig::default()
        };
        let mut engine =
            BasicHotStuffEngine::with_state_limits(ValidatorId(0), dense_validator_set(4), limits);
        engine
            .install_received_vote_context(multi_member_vote_context(&keypairs, 0, &domain))
            .expect("context install");
        let mut completed = None;
        let mut expected_signatures = Vec::new();
        for (index, (_, secret_key)) in keypairs.iter().take(3).enumerate() {
            let vote = signed_member_vote(
                0,
                index as u16,
                1,
                9,
                [0xC9; 32],
                secret_key,
                &domain,
            );
            expected_signatures.push(vote.signature.clone());
            let token = engine
                .admit_verified_received_vote(ValidatorId(index as u64), vote)
                .expect("admit signed Vote");
            if index == 2 {
                let table = engine.state.received_vote_evidence_table().unwrap();
                assert!(table.entry_for(1, 0).is_some());
                assert!(table.entry_for(1, 1).is_some());
            }
            let report = engine
                .invoke_verified_received_vote_qc(token)
                .expect("invoke signed Vote");
            if index < 2 {
                assert!(matches!(report.outcome, ReceivedVoteQcOutcome::NoQc));
            } else {
                completed = Some(report);
            }
        }
        let report = completed.expect("third Vote report");
        assert!(report.actual.qc.is_some());
        let ReceivedVoteQcOutcome::Complete(wire) = &report.outcome else {
            panic!("certificate was copied before reconciliation removed source evidence");
        };
        assert_eq!(wire.qc().signatures.len(), 3);
        assert_eq!(wire.qc().signer_bitmap, vec![0b0000_0111]);
        let table = engine.state.received_vote_evidence_table().unwrap();
        assert!(table.entry_for(1, 0).is_none());
        assert!(table.entry_for(1, 1).is_none());
        assert!(table.entry_for(1, 2).is_some());
        for (signature, expected) in wire.qc().signatures.iter().zip(&expected_signatures) {
            assert_eq!(signature, expected);
        }
    }

    #[test]
    fn received_vote_qc_stage_refusals_restore_ledger_and_preserve_token() {
        use crate::received_vote_evidence::with_allocation_failure_after;

        let (public_key, secret_key) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine
            .install_received_vote_context(input)
            .expect("context install");
        let observer = engine
            .state
            .received_vote_budget()
            .expect("installed ledger")
            .try_clone()
            .expect("ledger observer");
        let vote = signed_context_vote(0, &secret_key, &domain);
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("admit signed Vote");
        let token_ptr = token.vote().signature.as_ptr();
        let token_capacity = token.vote().signature.capacity();
        let before = observer.full_occupancy_for_test();
        engine.state.set_max_retained_evidence_bytes(before.0);
        let refusal = match engine.invoke_verified_received_vote_qc(token) {
            Err(refusal) => refusal,
            Ok(_) => panic!("report admission exceeds lowered cap"),
        };
        assert_eq!(
            refusal.reason,
            ReceivedVoteQcRefusalReason::Stage(ReceivedVoteQcStageError::ReportBytes)
        );
        assert_eq!(refusal.token.vote().signature.as_ptr(), token_ptr);
        assert_eq!(refusal.token.vote().signature.capacity(), token_capacity);
        assert_eq!(observer.full_occupancy_for_test(), before);
        assert_eq!(engine.state.max_retained_evidence_bytes(), before.0);

        engine.state.set_max_retained_evidence_bytes(u64::MAX);
        let restored_cap = engine.state.max_retained_evidence_bytes();
        let mut token = refusal.token;
        for successful_allocations in 0..3 {
            let refusal = with_allocation_failure_after(successful_allocations, || {
                engine.invoke_verified_received_vote_qc(token)
            });
            let refusal = match refusal {
                Err(refusal) => refusal,
                Ok(_) => panic!("injected destination allocation must fail"),
            };
            assert_eq!(
                refusal.reason,
                ReceivedVoteQcRefusalReason::Stage(ReceivedVoteQcStageError::Allocation)
            );
            assert_eq!(refusal.token.vote().signature.as_ptr(), token_ptr);
            assert_eq!(refusal.token.vote().signature.capacity(), token_capacity);
            assert_eq!(observer.full_occupancy_for_test(), before);
            assert_eq!(engine.state.max_retained_evidence_bytes(), restored_cap);
            token = refusal.token;
        }

        let retry = engine
            .invoke_verified_received_vote_qc(token)
            .expect("retry after allocation refusal");
        assert!(matches!(retry.outcome, ReceivedVoteQcOutcome::Complete(_)));
    }

    #[test]
    fn received_vote_qc_stage_report_quota_refuses_and_recovers() {
        let (public_key, secret_key) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine
            .install_received_vote_context(input)
            .expect("context install");
        let observer = engine
            .state
            .received_vote_budget()
            .expect("installed ledger")
            .try_clone()
            .expect("ledger observer");
        let vote = signed_context_vote(0, &secret_key, &domain);
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("admit signed Vote");
        let signature_ptr = token.vote().signature.as_ptr();
        let signature_capacity = token.vote().signature.capacity();
        let control_bytes = received_vote_qc_control_charge().unwrap();
        let mut held_reports = Vec::with_capacity(1024);
        for _ in 0..1024 {
            held_reports.push(
                token
                    .begin_qc_report(control_bytes)
                    .expect("hold one report reservation"),
            );
        }
        let before = observer.full_occupancy_for_test();
        assert_eq!(before.4, 1024);
        let refusal = match engine.invoke_verified_received_vote_qc(token) {
            Err(refusal) => refusal,
            Ok(_) => panic!("full report quota refuses before invocation"),
        };
        assert_eq!(
            refusal.reason,
            ReceivedVoteQcRefusalReason::Stage(ReceivedVoteQcStageError::ReportQuota)
        );
        assert_eq!(refusal.token.vote().signature.as_ptr(), signature_ptr);
        assert_eq!(
            refusal.token.vote().signature.capacity(),
            signature_capacity
        );
        assert_eq!(observer.full_occupancy_for_test(), before);

        drop(held_reports.pop());
        let report = engine
            .invoke_verified_received_vote_qc(refusal.token)
            .expect("retry after releasing one report slot");
        assert!(matches!(report.outcome, ReceivedVoteQcOutcome::Complete(_)));
        drop(report);
        drop(held_reports);
        assert_eq!(observer.full_occupancy_for_test().4, 0);
    }

    #[test]
    fn received_vote_qc_stage_preserves_capacity_drop_and_equivocation_outcomes() {
        let keypairs: Vec<_> = (0..2)
            .map(|_| MlDsa44Backend::generate_keypair().expect("test keygen"))
            .collect();
        let domain = qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            TEST_WIRE_CHAIN,
            [0xA1; 32],
            [0xB2; 32],
        )
        .expect("valid test domain");
        let limits = crate::vote_accumulator::ConsensusLimitsConfig {
            max_votes_per_view: 1,
            ..crate::vote_accumulator::ConsensusLimitsConfig::default()
        };
        let mut engine =
            BasicHotStuffEngine::with_state_limits(ValidatorId(0), dense_validator_set(2), limits);
        engine
            .install_received_vote_context(multi_member_vote_context(&keypairs, 0, &domain))
            .expect("context install");
        let invocations = RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(std::cell::Cell::get);
        let first = signed_member_vote(
            0,
            0,
            1,
            9,
            [0xA7; 32],
            &keypairs[0].1,
            &domain,
        );
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), first)
            .expect("admit first Vote");
        let report = engine
            .invoke_verified_received_vote_qc(token)
            .expect("invoke first Vote");
        assert!(matches!(report.outcome, ReceivedVoteQcOutcome::NoQc));

        let dropped = signed_member_vote(
            0,
            1,
            1,
            9,
            [0xA7; 32],
            &keypairs[1].1,
            &domain,
        );
        let token = engine
            .admit_verified_received_vote(ValidatorId(1), dropped)
            .expect("admit capacity-dropped Vote");
        let report = engine
            .invoke_verified_received_vote_qc(token)
            .expect("invoke capacity-dropped Vote");
        assert!(matches!(
            report.actual.accumulator,
            Some(Ok(VoteAccumulatorDisposition::CapacityDropped))
        ));
        assert_eq!(
            report.actual.evidence,
            ReceivedVoteEvidenceDisposition::NotRetainedCapacityDropped
        );
        assert!(matches!(report.outcome, ReceivedVoteQcOutcome::NoQc));

        let equivocation = signed_member_vote(
            0,
            0,
            1,
            9,
            [0xB8; 32],
            &keypairs[0].1,
            &domain,
        );
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), equivocation)
            .expect("admit valid equivocation");
        let report = engine
            .invoke_verified_received_vote_qc(token)
            .expect("invoke equivocation");
        assert!(report.actual.accumulator.is_none());
        assert_eq!(
            report.actual.evidence,
            ReceivedVoteEvidenceDisposition::NotRetainedEquivocation
        );
        assert!(matches!(report.outcome, ReceivedVoteQcOutcome::NoQc));
        assert_eq!(
            RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(std::cell::Cell::get),
            invocations + 3
        );
    }

    #[test]
    fn received_vote_qc_stage_callback_unwind_keeps_engine_effects_and_releases_stage() {
        #[derive(Debug)]
        struct PanicProgress;
        impl ConsensusProgressRecorder for PanicProgress {
            fn record_qc_formed(&self) {
                panic!("injected callback panic");
            }
            fn record_vote_observed(&self, _is_for_current_view: bool) {}
            fn record_view_change(&self, _from_view: u64, _to_view: u64) {}
            fn record_leader_change(&self) {}
            fn reset_current_view_votes(&self) {}
        }

        let (public_key, secret_key) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine
            .install_received_vote_context(input)
            .expect("context install");
        let observer = engine
            .state
            .received_vote_budget()
            .expect("installed ledger")
            .try_clone()
            .expect("ledger observer");
        engine.set_progress_recorder(Arc::new(PanicProgress));
        let vote = signed_context_vote(0, &secret_key, &domain);
        let view = vote.height;
        let block_id = vote.block_id;
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("admit signed Vote");
        let before = observer.full_occupancy_for_test();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.invoke_verified_received_vote_qc(token)
        }));
        assert!(result.is_err());
        assert!(engine.state.has_vote_history_membership_for_test(
            ValidatorId(0),
            view,
            &block_id
        ));
        assert_eq!(engine.state.vote_count(view, &block_id), 1);
        assert!(engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(view, 0)
            .is_some());
        let after = observer.full_occupancy_for_test();
        assert_eq!(after.4, before.4);
        assert_eq!(after.1, 0);
        assert_eq!(after.2, before.2);
        assert_eq!(
            after.0,
            before.0
                .checked_sub(std::mem::size_of::<VerifiedVoteToken>() as u64)
                .expect("bounded callback-unwind ledger")
        );
    }

    #[test]
    fn received_vote_qc_membership_comparison_rejects_malformed_actual_qcs() {
        let mut membership = [0u64; 16];
        membership[0] = 0b0011;
        let make_qc = |signers: Vec<ValidatorId>, block_id| QuorumCertificate {
            signers,
            block_id,
            view: 7,
        };
        let same_count_different_set = make_qc(vec![ValidatorId(0), ValidatorId(2)], [0x11; 32]);
        assert!(!qc_matches_projected_membership(
            &same_count_different_set,
            &membership,
            2,
            4,
            7,
            [0x11; 32]
        ));
        assert_eq!(
            compare_actual_qc_failure(
                &same_count_different_set,
                &membership,
                2,
                4,
                7,
                [0x11; 32]
            ),
            ReceivedVoteQcIncomplete::ActualSignerMembershipMismatch(2)
        );

        let duplicate = make_qc(vec![ValidatorId(0), ValidatorId(0)], [0x11; 32]);
        assert_eq!(
            compare_actual_qc_failure(&duplicate, &membership, 2, 4, 7, [0x11; 32]),
            ReceivedVoteQcIncomplete::ActualSignerDuplicate(0)
        );
        let out_of_range = make_qc(vec![ValidatorId(0), ValidatorId(4)], [0x11; 32]);
        assert_eq!(
            compare_actual_qc_failure(&out_of_range, &membership, 2, 4, 7, [0x11; 32]),
            ReceivedVoteQcIncomplete::ActualSignerOutOfRange(4)
        );
        let wrong_candidate = make_qc(vec![ValidatorId(0), ValidatorId(1)], [0x22; 32]);
        assert_eq!(
            compare_actual_qc_failure(&wrong_candidate, &membership, 2, 4, 7, [0x11; 32]),
            ReceivedVoteQcIncomplete::ActualCandidateMismatch
        );
    }

    #[test]
    fn received_vote_qc_stage_uses_minimal_bitmap_span_for_weighted_quorum() {
        let keypairs: Vec<_> = (0..9)
            .map(|_| MlDsa44Backend::generate_keypair().expect("test keygen"))
            .collect();
        let domain = qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            TEST_WIRE_CHAIN,
            [0xA1; 32],
            [0xB2; 32],
        )
        .expect("valid test domain");
        let validators = ConsensusValidatorSet::new((0..9).map(|id| ValidatorSetEntry {
            id: ValidatorId(id),
            voting_power: if id < 3 { 10 } else { 1 },
        }))
        .expect("valid weighted set");
        let members = keypairs
            .iter()
            .enumerate()
            .map(|(index, (public_key, _))| {
                SnapshotMember::new(
                    index as u64,
                    if index < 3 { 10 } else { 1 },
                    public_key.clone().into_boxed_slice().into_vec(),
                )
            })
            .collect();
        let input = VoteContextInput::new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            0,
            qbind_crypto::SUITE_PQ_RESERVED_1,
            domain.clone(),
            members,
        );
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), validators);
        engine
            .install_received_vote_context(input)
            .expect("context install");
        let mut report = None;
        for (index, (_, secret_key)) in keypairs.iter().take(3).enumerate() {
            let vote = signed_member_vote(
                0,
                index as u16,
                1,
                9,
                [0xF6; 32],
                secret_key,
                &domain,
            );
            let token = engine
                .admit_verified_received_vote(ValidatorId(index as u64), vote)
                .expect("admit signed Vote");
            let event = engine
                .invoke_verified_received_vote_qc(token)
                .expect("invoke signed Vote");
            if index == 2 {
                report = Some(event);
            } else {
                assert!(matches!(event.outcome, ReceivedVoteQcOutcome::NoQc));
            }
        }
        let report = report.expect("weighted quorum report");
        let ReceivedVoteQcOutcome::Complete(wire) = report.outcome else {
            panic!("weighted quorum should yield a complete certificate");
        };
        assert_eq!(wire.qc().signatures.len(), 3);
        assert_eq!(wire.qc().signer_bitmap, vec![0b0000_0111]);
        let mut keys = HashMap::new();
        for (index, (public_key, _)) in keypairs.iter().enumerate() {
            keys.insert(
                ValidatorId(index as u64),
                (qbind_crypto::SUITE_PQ_RESERVED_1, public_key.clone()),
            );
        }
        let registry = crate::crypto_verifier::SimpleBackendRegistry::with_backend(
            qbind_crypto::SUITE_PQ_RESERVED_1,
            Arc::new(MlDsa44Backend),
        );
        verify_quorum_certificate_with_domain(
            wire.qc(),
            &domain,
            0,
            engine.validators(),
            &ContextTestKeys(keys),
            &registry,
        )
        .expect("minimal-span weighted QC verifies");
    }

    #[test]
    fn received_vote_qc_stage_returns_every_actual_signer_and_verifies_wire_qc() {
        let keypairs: Vec<_> = (0..4)
            .map(|_| MlDsa44Backend::generate_keypair().expect("test keygen"))
            .collect();
        let runtime_chain = qbind_types::QBIND_DEVNET_CHAIN_ID;
        let domain = qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
            runtime_chain,
            TEST_WIRE_CHAIN,
            [0xA1; 32],
            [0xB2; 32],
        )
        .expect("valid test domain");
        let members = keypairs
            .iter()
            .enumerate()
            .map(|(index, (public_key, _))| {
                SnapshotMember::new(
                    index as u64,
                    1,
                    public_key.clone().into_boxed_slice().into_vec(),
                )
            })
            .collect();
        let input = VoteContextInput::new(
            runtime_chain,
            0,
            qbind_crypto::SUITE_PQ_RESERVED_1,
            domain.clone(),
            members,
        );
        let context_charge = input.checked_charge().expect("context charge");
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(4));
        engine
            .install_received_vote_context(input)
            .expect("context install");
        let observer = engine
            .state
            .received_vote_budget()
            .expect("installed ledger")
            .try_clone()
            .expect("ledger observer");
        let wrapper_charge = std::mem::size_of::<Option<ActiveVoteContext>>() as u64;
        let table_charge = received_vote_table_charge();
        let installed_occupancy = observer.full_occupancy_for_test();
        let route_control =
            u64::try_from(std::mem::size_of::<ReceivedVoteQcRouteControlFrame>()).unwrap();
        let admission_control =
            crate::received_vote_evidence::qc_admission_control_frame_bytes().unwrap();
        let buffer_control = qc_buffer_control_frame_bytes().unwrap();
        println!(
            "received-vote QC control layouts: route={route_control} admission={admission_control} buffer={buffer_control} A={}",
            received_vote_qc_control_charge().unwrap()
        );
        assert_eq!(
            received_vote_qc_control_charge().unwrap(),
            route_control + admission_control.max(buffer_control)
        );

        let mut original_votes = Vec::new();
        let mut source_signature_ptrs = Vec::new();
        let mut detached_report = None;
        for (index, (_, secret_key)) in keypairs.iter().enumerate() {
            let mut vote = qbind_wire::consensus::Vote {
                version: 1,
                chain_id: TEST_WIRE_CHAIN,
                epoch: 0,
                height: 1,
                round: 9,
                step: 0,
                block_id: [0xC3; 32],
                validator_index: index as u16,
                suite_id: qbind_crypto::SUITE_PQ_RESERVED_1.0,
                signature: Vec::new(),
            };
            vote.signature = MlDsa44Backend::sign(secret_key, &domain.vote_preimage(&vote))
                .expect("sign received vote")
                .into_boxed_slice()
                .into_vec();
            source_signature_ptrs.push(vote.signature.as_ptr());
            original_votes.push(vote.clone());
            let token = engine
                .admit_verified_received_vote(ValidatorId(index as u64), vote)
                .expect("admit signed vote");
            let before_invocation = observer.full_occupancy_for_test();
            let report = engine
                .invoke_verified_received_vote_qc(token)
                .expect("stage and invoke vote");
            let retained = engine
                .state
                .received_vote_evidence_table()
                .unwrap()
                .entry_for(1, index as u16)
                .expect("retained source evidence");
            assert_eq!(
                retained.vote().signature.as_ptr(),
                source_signature_ptrs[index]
            );
            assert_eq!(
                retained.vote().signature.capacity(),
                original_votes[index].signature.capacity()
            );
            let report_bytes = report._provenance.report_charge_for_test();
            let certificate_bytes = match &report.outcome {
                ReceivedVoteQcOutcome::Complete(wire) => wire.bytes_charge_for_test(),
                _ => 0,
            };
            let released_token_control =
                u64::try_from(std::mem::size_of::<VerifiedVoteToken>()).unwrap();
            assert_eq!(
                observer.full_occupancy_for_test().0,
                before_invocation
                    .0
                    .checked_add(report_bytes)
                    .and_then(|value| value.checked_add(certificate_bytes))
                    .and_then(|value| value.checked_sub(released_token_control))
                    .expect("expected ledger delta")
            );
            assert_eq!(observer.full_occupancy_for_test().1, 0);
            assert_eq!(observer.full_occupancy_for_test().3, 0);
            assert_eq!(observer.full_occupancy_for_test().4, 1);
            assert_eq!(report.actual.qc.is_some(), index >= 2);
            match &report.outcome {
                ReceivedVoteQcOutcome::NoQc => assert!(index < 2),
                ReceivedVoteQcOutcome::Complete(wire) => {
                    assert!(index >= 2);
                    let certificate = wire.qc();
                    println!(
                        "received-vote QC backing: signer_count={} bitmap={} descriptors={} signature_bytes={} P={}",
                        certificate.signatures.len(),
                        certificate.signer_bitmap.len(),
                        certificate.signatures.len() * std::mem::size_of::<Vec<u8>>(),
                        certificate.signatures.iter().map(Vec::len).sum::<usize>(),
                        wire.bytes_charge_for_test()
                    );
                    assert_eq!(certificate.signatures.len(), index + 1);
                    assert_eq!(
                        certificate.signer_bitmap,
                        vec![((1u16 << (index + 1)) - 1) as u8]
                    );
                    for (signer_index, (signature, original)) in certificate
                        .signatures
                        .iter()
                        .zip(original_votes.iter())
                        .enumerate()
                    {
                        assert_eq!(signature, &original.signature);
                        assert_ne!(signature.as_ptr(), source_signature_ptrs[signer_index]);
                        assert_eq!(original.signature.capacity(), signature.capacity());
                    }
                    let mut keys = HashMap::new();
                    for (member, (public_key, _)) in keypairs.iter().enumerate() {
                        keys.insert(
                            ValidatorId(member as u64),
                            (qbind_crypto::SUITE_PQ_RESERVED_1, public_key.clone()),
                        );
                    }
                    let registry = crate::crypto_verifier::SimpleBackendRegistry::with_backend(
                        qbind_crypto::SUITE_PQ_RESERVED_1,
                        Arc::new(MlDsa44Backend),
                    );
                    verify_quorum_certificate_with_domain(
                        certificate,
                        &domain,
                        0,
                        engine.validators(),
                        &ContextTestKeys(keys),
                        &registry,
                    )
                    .expect("returned wire QC independently verifies");
                }
                ReceivedVoteQcOutcome::Incomplete(reason) => {
                    panic!("unexpected incomplete result: {reason:?}");
                }
                ReceivedVoteQcOutcome::LogicalError(error) => {
                    panic!("unexpected logical error: {error:?}");
                }
            }
            if index == 3 {
                detached_report = Some(report);
            } else {
                drop(report);
                assert_eq!(observer.full_occupancy_for_test().4, 0);
            }
        }
        let detached_report = detached_report.expect("final complete report retained");
        assert_eq!(observer.full_occupancy_for_test().2, 1);
        assert_eq!(observer.full_occupancy_for_test().4, 1);
        let _ = engine.state_mut();
        assert_eq!(observer.full_occupancy_for_test().2, 1);
        assert_eq!(observer.full_occupancy_for_test().4, 1);
        drop(engine);
        assert_eq!(observer.full_occupancy_for_test().2, 1);
        println!(
            "received-vote QC detached report occupancy: {:?}",
            observer.full_occupancy_for_test()
        );
        drop(detached_report);
        assert_eq!(observer.full_occupancy_for_test().2, 0);
        assert_eq!(observer.full_occupancy_for_test().4, 0);
        println!(
            "received-vote QC final release occupancy: {:?}",
            observer.full_occupancy_for_test()
        );
        assert_eq!(
            observer.full_occupancy_for_test().0,
            installed_occupancy.0 - context_charge - wrapper_charge - table_charge
        );
    }

    fn assert_vote_refusal_preserved(
        refusal: VoteAdmissionRefusal,
        expected_error: VoteAdmissionError,
        expected_vote: &qbind_wire::consensus::Vote,
        signature_ptr: *const u8,
        signature_capacity: usize,
        budget: &EvidenceBudget,
        occupancy_before: (u64, u64, usize, usize),
    ) -> qbind_wire::consensus::Vote {
        assert_eq!(refusal.error, expected_error);
        assert!(refusal.vote == *expected_vote, "returned Vote differs (redacted)");
        assert_eq!(refusal.vote.signature.as_ptr(), signature_ptr);
        assert_eq!(refusal.vote.signature.capacity(), signature_capacity);
        assert_eq!(budget.occupancy(), occupancy_before);
        refusal.vote
    }

    #[test]
    fn received_vote_refusals_preserve_owned_backing_and_leave_no_token_charge() {
        let (public_key, secret_key) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        assert!(engine.install_received_vote_context(input).is_ok());
        let observer = engine
            .state
            .received_vote_budget()
            .expect("installed ledger")
            .try_clone()
            .expect("independent test observer");

        macro_rules! refuse_vote {
            ($vote:expr, $sender:expr, $error:expr) => {{
                let vote = $vote;
                let expected = vote.clone();
                let signature_ptr = vote.signature.as_ptr();
                let signature_capacity = vote.signature.capacity();
                let occupancy_before = observer.occupancy();
                let cap_before = engine.state.max_retained_evidence_bytes();
                let refusal = engine
                    .admit_verified_received_vote($sender, vote)
                    .expect_err("invalid Vote refuses");
                let returned = assert_vote_refusal_preserved(
                    refusal,
                    $error,
                    &expected,
                    signature_ptr,
                    signature_capacity,
                    &observer,
                    occupancy_before,
                );
                assert_eq!(engine.state.max_retained_evidence_bytes(), cap_before);
                returned
            }};
        }

        let mut wrong_sender = signed_context_vote(0, &secret_key, &domain);
        wrong_sender.block_id = [0x74; 32];
        wrong_sender.signature =
            MlDsa44Backend::sign(&secret_key, &domain.vote_preimage(&wrong_sender))
                .expect("test Vote signing")
                .into_boxed_slice()
                .into_vec();
        refuse_vote!(
            wrong_sender,
            ValidatorId(8),
            VoteAdmissionError::SenderIndexMismatch
        );

        let mut wrong_epoch = signed_context_vote(0, &secret_key, &domain);
        wrong_epoch.epoch = 1;
        wrong_epoch.signature =
            MlDsa44Backend::sign(&secret_key, &domain.vote_preimage(&wrong_epoch))
                .expect("test Vote signing")
                .into_boxed_slice()
                .into_vec();
        refuse_vote!(
            wrong_epoch,
            ValidatorId(0),
            VoteAdmissionError::EpochMismatch
        );

        let mut wrong_wire_chain = signed_context_vote(0, &secret_key, &domain);
        wrong_wire_chain.chain_id += 1;
        refuse_vote!(
            wrong_wire_chain,
            ValidatorId(0),
            VoteAdmissionError::DomainMismatch
        );

        let mut wrong_suite = signed_context_vote(0, &secret_key, &domain);
        wrong_suite.suite_id = qbind_crypto::SUITE_PQ_RESERVED_2.0;
        refuse_vote!(
            wrong_suite,
            ValidatorId(0),
            VoteAdmissionError::SuiteMismatch
        );

        let mut wrong_signature = signed_context_vote(0, &secret_key, &domain);
        wrong_signature.signature[0] ^= 1;
        refuse_vote!(
            wrong_signature,
            ValidatorId(0),
            VoteAdmissionError::InvalidSignature
        );

        let mut short_signature = signed_context_vote(0, &secret_key, &domain);
        short_signature.signature.pop();
        refuse_vote!(
            short_signature,
            ValidatorId(0),
            VoteAdmissionError::SignatureShape
        );

        let mut over_capacity_signature = signed_context_vote(0, &secret_key, &domain);
        let valid_signature = over_capacity_signature.signature.clone();
        let mut oversized = Vec::with_capacity(qbind_crypto::ML_DSA_44_SIGNATURE_SIZE + 1);
        oversized.extend_from_slice(&valid_signature);
        assert!(oversized.capacity() > qbind_crypto::ML_DSA_44_SIGNATURE_SIZE);
        over_capacity_signature.signature = oversized;
        refuse_vote!(
            over_capacity_signature,
            ValidatorId(0),
            VoteAdmissionError::SignatureShape
        );

        let alternate_domain =
            qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
                qbind_types::QBIND_DEVNET_CHAIN_ID,
                TEST_WIRE_CHAIN,
                [0x32; 32],
                [0x42; 32],
            )
            .expect("same-chain alternate v2 domain");
        assert_eq!(alternate_domain.expected_wire_chain_id(), domain.expected_wire_chain_id());
        let wrong_full_domain = signed_context_vote(0, &secret_key, &alternate_domain);
        refuse_vote!(
            wrong_full_domain,
            ValidatorId(0),
            VoteAdmissionError::InvalidSignature
        );

        let valid_vote = signed_context_vote(0, &secret_key, &domain);
        let expected = valid_vote.clone();
        let signature_ptr = valid_vote.signature.as_ptr();
        let signature_capacity = valid_vote.signature.capacity();
        let bytes = std::mem::size_of::<VerifiedVoteToken>() as u64
            + u64::try_from(signature_capacity).unwrap();
        let occupancy_before = observer.occupancy();
        let old_cap = engine.state.max_retained_evidence_bytes();
        engine.set_max_retained_evidence_bytes(occupancy_before.0 + bytes - 1);
        let refusal = engine
            .admit_verified_received_vote(ValidatorId(0), valid_vote)
            .expect_err("insufficient token budget refuses");
        let returned_vote = assert_vote_refusal_preserved(
            refusal,
            VoteAdmissionError::Budget,
            &expected,
            signature_ptr,
            signature_capacity,
            &observer,
            occupancy_before,
        );
        assert_eq!(
            engine.state.max_retained_evidence_bytes(),
            occupancy_before.0 + bytes - 1
        );
        engine.set_max_retained_evidence_bytes(occupancy_before.0 + bytes);
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), returned_vote)
            .expect("the original returned Vote verifies after budget relief");
        assert_eq!(
            observer.occupancy(),
            (occupancy_before.0 + bytes, 0, occupancy_before.2, 0)
        );
        assert_eq!(engine.state.max_retained_evidence_bytes(), occupancy_before.0 + bytes);
        drop(token);
        assert_eq!(observer.occupancy(), occupancy_before);
        engine.set_max_retained_evidence_bytes(old_cap);

        let (other_public_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let (wrong_key_input, _) = received_vote_context(0, other_public_key);
        let mut wrong_key_engine =
            BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        wrong_key_engine
            .install_received_vote_context(wrong_key_input)
            .expect("install context with a different valid key");
        let wrong_key_observer = wrong_key_engine
            .state
            .received_vote_budget()
            .unwrap()
            .try_clone()
            .unwrap();
        let wrong_key_vote = signed_context_vote(0, &secret_key, &domain);
        let expected = wrong_key_vote.clone();
        let signature_ptr = wrong_key_vote.signature.as_ptr();
        let signature_capacity = wrong_key_vote.signature.capacity();
        let occupancy_before = wrong_key_observer.occupancy();
        let wrong_key_cap = wrong_key_engine.state.max_retained_evidence_bytes();
        let refusal = wrong_key_engine
            .admit_verified_received_vote(ValidatorId(0), wrong_key_vote)
            .expect_err("signature under a different installed key refuses");
        assert_vote_refusal_preserved(
            refusal,
            VoteAdmissionError::InvalidSignature,
            &expected,
            signature_ptr,
            signature_capacity,
            &wrong_key_observer,
            occupancy_before,
        );
        assert_eq!(
            wrong_key_engine.state.max_retained_evidence_bytes(),
            wrong_key_cap
        );
    }

    #[test]
    fn received_vote_context_refusal_keeps_input_and_does_not_publish_bootstrap() {
        let (public_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, _) = received_vote_context(0, public_key);
        let roster_ptr = input.members().as_ptr();
        let roster_capacity = input.members_capacity();
        let key_ptr = input.members()[0].public_key().as_ptr();
        let key_capacity = input.members()[0].public_key_capacity();

        let sizing = EvidenceBudget::try_new(u64::MAX, 0).expect("sizing ledger");
        let standing_floor = sizing.occupancy().0;
        drop(sizing);
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine.set_max_retained_evidence_bytes(standing_floor + 1);
        let refusal = engine
            .install_received_vote_context(input)
            .expect_err("context reservation refuses after local bootstrap");
        assert_eq!(refusal.error, ContextInstallError::Budget);
        assert_eq!(refusal.input.members().as_ptr(), roster_ptr);
        assert_eq!(refusal.input.members_capacity(), roster_capacity);
        assert_eq!(refusal.input.members()[0].public_key().as_ptr(), key_ptr);
        assert_eq!(
            refusal.input.members()[0].public_key_capacity(),
            key_capacity
        );
        assert!(engine.state.received_vote_budget().is_none());
        assert!(engine.active_received_vote_context.is_none());

        let (keypair, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let runtime_chain = qbind_types::QBIND_DEVNET_CHAIN_ID;
        let domain = qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
            runtime_chain,
            TEST_WIRE_CHAIN,
            [0x31; 32],
            [0x42; 32],
        )
        .expect("valid test domain");
        let wrong_roster = VoteContextInput::new(
            runtime_chain,
            0,
            qbind_crypto::SUITE_PQ_RESERVED_1,
            domain,
            vec![SnapshotMember::new(
                0,
                2,
                keypair.into_boxed_slice().into_vec(),
            )],
        );
        let refusal = engine
            .install_received_vote_context(wrong_roster)
            .expect_err("power mismatch refuses");
        assert_eq!(refusal.error, ContextInstallError::InvalidContext);
        assert!(engine.state.received_vote_budget().is_none());

        let (suite_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let wrong_suite = VoteContextInput::new(
            runtime_chain,
            0,
            qbind_crypto::SUITE_PQ_RESERVED_2,
            qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
                runtime_chain,
                TEST_WIRE_CHAIN,
                [0x31; 32],
                [0x42; 32],
            )
            .expect("valid test domain"),
            vec![SnapshotMember::new(
                0,
                1,
                suite_key.into_boxed_slice().into_vec(),
            )],
        );
        assert_eq!(
            engine
                .install_received_vote_context(wrong_suite)
                .expect_err("non-suite-100 context refuses")
                .error,
            ContextInstallError::InvalidContext
        );
        assert!(engine.state.received_vote_budget().is_none());
    }

    #[test]
    fn received_vote_context_enforces_roster_capacity_profile() {
        let (public_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let member = SnapshotMember::new(0, 1, public_key);
        let mut oversized_roster = Vec::with_capacity(1025);
        oversized_roster.push(member);
        let input = VoteContextInput::new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            0,
            qbind_crypto::SUITE_PQ_RESERVED_1,
            qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2::try_new(
                qbind_types::QBIND_DEVNET_CHAIN_ID,
                TEST_WIRE_CHAIN,
                [0x31; 32],
                [0x42; 32],
            )
            .expect("valid test domain"),
            oversized_roster,
        );
        assert_eq!(input.members().len(), 1);
        assert!(input.members_capacity() > 1024);
        let roster_ptr = input.members().as_ptr();
        let roster_capacity = input.members_capacity();
        let key_ptr = input.members()[0].public_key().as_ptr();
        let key_capacity = input.members()[0].public_key_capacity();
        let contents = input.members().to_vec();
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine.set_max_retained_evidence_bytes(u64::MAX);
        let refusal = engine
            .install_received_vote_context(input)
            .expect_err("oversized roster capacity refuses at the opt-in boundary");
        assert_eq!(refusal.error, ContextInstallError::InvalidContext);
        assert_eq!(refusal.input.members().as_ptr(), roster_ptr);
        assert_eq!(refusal.input.members_capacity(), roster_capacity);
        assert_eq!(refusal.input.members()[0].public_key().as_ptr(), key_ptr);
        assert_eq!(
            refusal.input.members()[0].public_key_capacity(),
            key_capacity
        );
        assert!(refusal.input.members() == contents.as_slice(), "public key payload differs");
        assert!(engine.state.received_vote_budget().is_none());
        assert!(engine.active_received_vote_context.is_none());
        assert_eq!(engine.state.retained_evidence_bytes(), 0);

        let (public_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let valid = received_vote_context(0, public_key).0;
        assert!(valid.members_capacity() <= 1024);
        engine
            .install_received_vote_context(valid)
            .expect("valid bounded-capacity roster installs");
        assert!(engine.state.received_vote_budget().is_some());
        assert!(engine.active_received_vote_context.is_some());
    }

    #[test]
    fn received_vote_context_bootstrap_refusals_leave_no_partial_ownership() {
        use crate::received_vote_evidence::{
            budget_final_drop_count_for_test, with_allocation_failure_after,
        };

        fn assert_original_input(
            refusal: ContextInstallRefusal,
            roster_ptr: *const SnapshotMember,
            roster_capacity: usize,
            key_ptr: *const u8,
            key_capacity: usize,
            expected_members: &[SnapshotMember],
        ) {
            assert!(refusal.input.members() == expected_members, "context input differs");
            assert_eq!(refusal.input.members().as_ptr(), roster_ptr);
            assert_eq!(refusal.input.members_capacity(), roster_capacity);
            assert_eq!(refusal.input.members()[0].public_key().as_ptr(), key_ptr);
            assert_eq!(
                refusal.input.members()[0].public_key_capacity(),
                key_capacity
            );
        }

        let (public_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let input = received_vote_context(0, public_key).0;
        let roster_ptr = input.members().as_ptr();
        let roster_capacity = input.members_capacity();
        let key_ptr = input.members()[0].public_key().as_ptr();
        let key_capacity = input.members()[0].public_key_capacity();
        let members = input.members().to_vec();
        let context_charge = input.checked_charge().unwrap();
        let table_charge = received_vote_table_charge();
        let sizing = EvidenceBudget::try_new(u64::MAX, 0).unwrap();
        let floor = sizing.occupancy().0;
        drop(sizing);

        let mut wrapper_pressure = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        wrapper_pressure.set_max_retained_evidence_bytes(floor + table_charge + context_charge);
        let final_drops_before = budget_final_drop_count_for_test();
        let refusal = wrapper_pressure
            .install_received_vote_context(input)
            .expect_err("context reservation succeeds but wrapper admission is refused");
        assert_eq!(refusal.error, ContextInstallError::Budget);
        assert_original_input(
            refusal,
            roster_ptr,
            roster_capacity,
            key_ptr,
            key_capacity,
            &members,
        );
        assert!(wrapper_pressure.state.received_vote_budget().is_none());
        assert!(wrapper_pressure.active_received_vote_context.is_none());
        assert_eq!(
            budget_final_drop_count_for_test(),
            final_drops_before + 1,
            "unpublished bootstrapped budget is destroyed after wrapper refusal"
        );

        let (public_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let input = received_vote_context(0, public_key).0;
        let roster_ptr = input.members().as_ptr();
        let roster_capacity = input.members_capacity();
        let key_ptr = input.members()[0].public_key().as_ptr();
        let key_capacity = input.members()[0].public_key_capacity();
        let members = input.members().to_vec();
        let mut table_allocation_failure =
            BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        table_allocation_failure.set_max_retained_evidence_bytes(
            floor
                + table_charge
                + input.checked_charge().unwrap()
                + std::mem::size_of::<Option<ActiveVoteContext>>() as u64,
        );
        let final_drops_before = budget_final_drop_count_for_test();
        let refusal = with_allocation_failure_after(1, || {
            table_allocation_failure.install_received_vote_context(input)
        })
        .expect_err("fixed-table allocation failure returns original context input");
        assert_eq!(refusal.error, ContextInstallError::Allocation);
        assert_original_input(
            refusal,
            roster_ptr,
            roster_capacity,
            key_ptr,
            key_capacity,
            &members,
        );
        assert!(table_allocation_failure.state.received_vote_budget().is_none());
        assert!(table_allocation_failure.active_received_vote_context.is_none());
        assert_eq!(
            budget_final_drop_count_for_test(),
            final_drops_before + 1,
            "staged ledger owner is released after table allocation refusal"
        );

        let (public_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let input = received_vote_context(0, public_key).0;
        let roster_ptr = input.members().as_ptr();
        let roster_capacity = input.members_capacity();
        let key_ptr = input.members()[0].public_key().as_ptr();
        let key_capacity = input.members()[0].public_key_capacity();
        let members = input.members().to_vec();
        let context_charge = input.checked_charge().unwrap();
        let mut allocation_failure =
            BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        allocation_failure.set_max_retained_evidence_bytes(
            floor
                + table_charge
                + context_charge
                + std::mem::size_of::<Option<ActiveVoteContext>>() as u64,
        );
        let final_drops_before = budget_final_drop_count_for_test();
        let refusal = with_allocation_failure_after(2, || {
            allocation_failure.install_received_vote_context(input)
        })
        .expect_err("ContextCell allocation failure returns original input");
        assert_eq!(refusal.error, ContextInstallError::Allocation);
        assert_original_input(
            refusal,
            roster_ptr,
            roster_capacity,
            key_ptr,
            key_capacity,
            &members,
        );
        assert!(allocation_failure.state.received_vote_budget().is_none());
        assert!(allocation_failure.active_received_vote_context.is_none());
        assert_eq!(
            budget_final_drop_count_for_test(),
            final_drops_before + 1,
            "unpublished bootstrapped budget is destroyed after context allocation failure"
        );
    }

    #[test]
    fn received_vote_table_staging_unwind_releases_only_staged_ownership() {
        let (public_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        let budget = EvidenceBudget::try_new(
            engine.state.max_retained_evidence_bytes(),
            0,
        )
        .expect("shared ledger");
        let observer = budget.try_clone().expect("ledger observer");
        engine
            .state
            .install_received_vote_budget(budget)
            .expect("install existing ledger");
        let baseline = observer.occupancy();
        let input = received_vote_context(0, public_key).0;

        PANIC_AFTER_RECEIVED_VOTE_TABLE_STAGE.with(|flag| flag.set(true));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = engine.install_received_vote_context(input);
        }));
        PANIC_AFTER_RECEIVED_VOTE_TABLE_STAGE.with(|flag| flag.set(false));

        assert!(unwind.is_err(), "test hook must unwind after table staging");
        assert_eq!(observer.occupancy(), baseline);
        assert!(engine.state.received_vote_budget().unwrap().same_authority(&observer));
        assert!(engine.state.received_vote_evidence_table().is_none());
        assert!(engine.active_received_vote_context.is_none());
    }

    #[test]
    fn received_vote_context_failure_after_staging_restores_existing_ledger() {
        use crate::received_vote_evidence::with_allocation_failure_after;

        let (public_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let input = received_vote_context(0, public_key).0;
        let expected_members = input.members().to_vec();
        let roster_ptr = input.members().as_ptr();
        let roster_capacity = input.members_capacity();
        let key_ptr = input.members()[0].public_key().as_ptr();
        let key_capacity = input.members()[0].public_key_capacity();

        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        let ledger = EvidenceBudget::try_new(engine.state.max_retained_evidence_bytes(), 0)
            .expect("existing ledger");
        let observer = ledger.try_clone().expect("independent ledger observer");
        engine
            .state
            .install_received_vote_budget(ledger)
            .expect("attach existing ledger before staging");
        let baseline = observer.occupancy();
        let cap = engine.state.max_retained_evidence_bytes();
        let refusal = with_allocation_failure_after(1, || {
            engine.install_received_vote_context(input)
        })
        .expect_err("context-cell allocation fails after table staging");

        assert_eq!(refusal.error, ContextInstallError::Allocation);
        assert!(refusal.input.members() == expected_members.as_slice());
        assert_eq!(refusal.input.members().as_ptr(), roster_ptr);
        assert_eq!(refusal.input.members_capacity(), roster_capacity);
        assert_eq!(refusal.input.members()[0].public_key().as_ptr(), key_ptr);
        assert_eq!(
            refusal.input.members()[0].public_key_capacity(),
            key_capacity
        );
        assert_eq!(observer.occupancy(), baseline);
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap);
        assert!(engine.state.received_vote_budget().unwrap().same_authority(&observer));
        assert!(engine.state.received_vote_evidence_table().is_none());
        assert!(engine.active_received_vote_context.is_none());
    }

    #[test]
    fn received_vote_budget_bootstrap_imports_existing_map_qc_once() {
        let keypairs: Vec<_> = (0..4)
            .map(|_| MlDsa44Backend::generate_keypair().expect("test keygen"))
            .collect();
        let (evidence, domain) = verified_test_qc(&keypairs, &[0, 1, 2]);
        let qc_charge = evidence.retained_byte_size().unwrap();
        let members = keypairs
            .iter()
            .enumerate()
            .map(|(index, (public_key, _))| {
                SnapshotMember::new(
                    index as u64,
                    1,
                    public_key.clone().into_boxed_slice().into_vec(),
                )
            })
            .collect();
        let input = VoteContextInput::new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            0,
            qbind_crypto::SUITE_PQ_RESERVED_1,
            domain,
            members,
        );
        let context_charge = input.checked_charge().unwrap();
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(4));
        engine
            .state
            .register_block_with_verified_justification(
                [0xA0; 32],
                7,
                None,
                evidence,
            )
            .expect("verified QC retained through scalar route");
        assert_eq!(engine.state.retained_evidence_bytes(), qc_charge);
        assert!(engine.state.received_vote_budget().is_none());
        engine
            .install_received_vote_context(input)
            .expect("bootstrap imports existing map evidence");

        let observer = engine
            .state
            .received_vote_budget()
            .unwrap()
            .try_clone()
            .unwrap();
        let floor = EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0;
        let table_charge = received_vote_table_charge();
        let wrapper_charge = std::mem::size_of::<Option<ActiveVoteContext>>() as u64;
        assert_eq!(engine.state.retained_evidence_bytes(), qc_charge);
        assert_eq!(
            observer.occupancy(),
            (
                floor + qc_charge + context_charge + wrapper_charge + table_charge,
                0,
                1,
                0
            ),
            "existing map-owned QC bytes are imported exactly once"
        );
    }

    #[test]
    fn shared_qc_accounting_enforces_verified_projection_and_allows_legacy_reclamation() {
        let keypairs: Vec<_> = (0..4)
            .map(|_| MlDsa44Backend::generate_keypair().expect("test keygen"))
            .collect();
        let (large_evidence, domain) = verified_test_qc(&keypairs, &[0, 1, 2, 3]);
        let (small_evidence, _) = verified_test_qc(&keypairs, &[0, 1, 2]);
        let large_charge = large_evidence.retained_byte_size().unwrap();
        let small_charge = small_evidence.retained_byte_size().unwrap();
        assert!(small_charge < large_charge);

        let members = keypairs
            .iter()
            .enumerate()
            .map(|(index, (public_key, _))| {
                SnapshotMember::new(
                    index as u64,
                    1,
                    public_key.clone().into_boxed_slice().into_vec(),
                )
            })
            .collect();
        let input = VoteContextInput::new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            0,
            qbind_crypto::SUITE_PQ_RESERVED_1,
            domain,
            members,
        );
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(4));
        engine
            .install_received_vote_context(input)
            .expect("install context");
        let baseline = engine
            .received_vote_evidence_aggregate_bytes()
            .expect("shared ledger installed")
            .0;
        let observer = engine
            .state
            .received_vote_budget()
            .unwrap()
            .try_clone()
            .unwrap();
        macro_rules! assert_shared_accounting {
            ($map_bytes:expr, $aggregate_bytes:expr, $cap:expr) => {{
                assert_eq!(engine.state.retained_evidence_bytes(), $map_bytes);
                assert_eq!(
                    observer.occupancy(),
                    ($aggregate_bytes, 0, 1, 0),
                    "shared committed/pending/context occupancy"
                );
                assert_eq!(engine.state.max_retained_evidence_bytes(), $cap);
            }};
        }
        println!(
            "shared QC accounting: baseline={baseline} four-signers={large_charge} three-signers={small_charge}"
        );
        let candidate = [0xA1; 32];
        engine
            .state
            .register_block_with_verified_justification(
                candidate,
                7,
                None,
                large_evidence.clone(),
            )
            .expect("initial QC retention");
        assert_eq!(
            engine.state.retained_evidence_bytes(),
            large_charge,
            "the legacy scalar remains map-owned QC bytes"
        );
        assert_shared_accounting!(large_charge, baseline + large_charge, engine.state.max_retained_evidence_bytes());

        let small_total = baseline + small_charge;
        engine.set_max_retained_evidence_bytes(small_total - 1);
        let rejections = engine.state.rejected_evidence_over_budget();
        let refusal = engine
            .state
            .register_block_with_verified_justification(
                candidate,
                7,
                None,
                large_evidence.clone(),
            )
            .expect_err("equal verified replacement above cap refuses");
        assert!(matches!(
            refusal,
            crate::hotstuff_state_engine::EvidenceRetentionError::BudgetExceeded { .. }
        ));
        assert_eq!(
            engine.state.rejected_evidence_over_budget(),
            rejections + 1,
            "equal replacement is counted once"
        );
        assert_shared_accounting!(large_charge, baseline + large_charge, small_total - 1);

        let rejections = engine.state.rejected_evidence_over_budget();
        let refusal = engine
            .state
            .register_block_with_verified_justification(
                candidate,
                7,
                None,
                small_evidence.clone(),
            )
            .expect_err("shrinking replacement still over cap refuses");
        assert!(matches!(
            refusal,
            crate::hotstuff_state_engine::EvidenceRetentionError::BudgetExceeded { .. }
        ));
        assert_eq!(
            engine.state.rejected_evidence_over_budget(),
            rejections + 1,
            "a shrink still over cap is counted once"
        );
        assert_shared_accounting!(large_charge, baseline + large_charge, small_total - 1);

        engine.set_max_retained_evidence_bytes(small_total);
        engine
            .state
            .register_block_with_verified_justification(
                candidate,
                7,
                None,
                small_evidence.clone(),
            )
            .expect("shrink projected within cap");
        assert_shared_accounting!(small_charge, small_total, small_total);

        let second = [0xA2; 32];
        let rejections = engine.state.rejected_evidence_over_budget();
        let refusal = engine
            .state
            .register_block_with_verified_justification(
                second,
                8,
                None,
                small_evidence.clone(),
            )
            .expect_err("new evidence without headroom refuses");
        assert!(matches!(
            refusal,
            crate::hotstuff_state_engine::EvidenceRetentionError::BudgetExceeded { .. }
        ));
        assert_eq!(engine.state.rejected_evidence_over_budget(), rejections + 1);
        assert_shared_accounting!(small_charge, small_total, small_total);

        let two_small_total = baseline + small_charge * 2;
        engine.set_max_retained_evidence_bytes(two_small_total);
        engine
            .state
            .register_block_with_verified_justification(
                second,
                8,
                None,
                small_evidence.clone(),
            )
            .expect("new evidence fits with headroom");
        assert_shared_accounting!(small_charge * 2, two_small_total, two_small_total);

        let growth_total = baseline + small_charge + large_charge;
        engine.set_max_retained_evidence_bytes(growth_total - 1);
        let rejections = engine.state.rejected_evidence_over_budget();
        let refusal = engine
            .state
            .register_block_with_verified_justification(
                candidate,
                7,
                None,
                large_evidence.clone(),
            )
            .expect_err("growth without sufficient headroom refuses");
        assert!(matches!(
            refusal,
            crate::hotstuff_state_engine::EvidenceRetentionError::BudgetExceeded { .. }
        ));
        assert_eq!(engine.state.rejected_evidence_over_budget(), rejections + 1);
        assert_shared_accounting!(small_charge * 2, two_small_total, growth_total - 1);
        engine.set_max_retained_evidence_bytes(growth_total);
        engine
            .state
            .register_block_with_verified_justification(
                candidate,
                7,
                None,
                large_evidence,
            )
            .expect("growth fits with exact headroom");
        assert_shared_accounting!(small_charge + large_charge, growth_total, growth_total);

        engine.set_max_retained_evidence_bytes(baseline);
        engine.state.register_block(candidate, 7, None, None);
        assert_shared_accounting!(small_charge, baseline + small_charge, baseline);
        engine.state.register_block(second, 8, None, None);
        assert_shared_accounting!(0, baseline, baseline);
    }

    #[test]
    fn verified_proposal_reservation_precedes_effects_and_cancels_on_ordinary_rejection() {
        let keypairs: Vec<_> = (0..4)
            .map(|_| MlDsa44Backend::generate_keypair().expect("test keygen"))
            .collect();
        let (evidence, domain) = verified_test_qc(&keypairs, &[0, 1, 2]);
        let members = keypairs
            .iter()
            .enumerate()
            .map(|(index, (public_key, _))| {
                SnapshotMember::new(
                    index as u64,
                    1,
                    public_key.clone().into_boxed_slice().into_vec(),
                )
            })
            .collect();
        let input = VoteContextInput::new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            0,
            qbind_crypto::SUITE_PQ_RESERVED_1,
            domain,
            members,
        );
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(4));
        engine
            .install_received_vote_context(input)
            .expect("install context");
        let baseline = engine
            .received_vote_evidence_aggregate_bytes()
            .unwrap()
            .0;
        let charge = evidence.retained_byte_size().unwrap();
        let proposal = proposal_for_test_evidence(1, &evidence, 1);
        let initial_blocks = engine.state.block_count();

        engine.set_max_retained_evidence_bytes(baseline + charge - 1);
        let rejected_before = engine.state.rejected_evidence_over_budget();
        assert!(matches!(
            engine.on_verified_proposal_event(ValidatorId(1), &proposal, evidence.clone()),
            Err(VerifiedProposalIngestError::RetentionBudgetExceeded { .. })
        ));
        assert_eq!(
            engine.state.rejected_evidence_over_budget(),
            rejected_before + 1
        );
        assert_eq!(engine.current_view(), 0);
        assert_eq!(engine.state.block_count(), initial_blocks);
        assert_eq!(
            engine.received_vote_evidence_aggregate_bytes().unwrap(),
            (baseline, 0)
        );

        engine.set_max_retained_evidence_bytes(baseline + charge);
        let rejected_before = engine.state.rejected_evidence_over_budget();
        assert!(engine
            .on_verified_proposal_event(ValidatorId(0), &proposal, evidence.clone())
            .expect("ordinary leader rejection")
            .is_none());
        assert_eq!(engine.current_view(), 1);
        assert_eq!(engine.state.block_count(), initial_blocks);
        assert_eq!(
            engine.received_vote_evidence_aggregate_bytes().unwrap(),
            (baseline, 0),
            "unused reservation is cancelled after allowed view advancement"
        );
        assert_eq!(engine.state.rejected_evidence_over_budget(), rejected_before);

        assert!(matches!(
            engine
                .on_verified_proposal_event(ValidatorId(1), &proposal, evidence)
                .expect("admitted verified proposal"),
            Some(ConsensusEngineAction::BroadcastVote(_))
        ));
        assert_eq!(engine.current_view(), 1);
        assert_eq!(engine.state.block_count(), initial_blocks + 1);
        assert_eq!(
            engine.received_vote_evidence_aggregate_bytes().unwrap(),
            (baseline + charge, 0)
        );
    }

    #[test]
    fn verified_proposal_callback_controlled_unwind_keeps_map_charge_committed() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        struct PanicAfterRegistration;
        impl SafetyDecisionObserver<[u8; 32]> for PanicAfterRegistration {
            fn observe(&mut self, _: &SafetyDecisionView<'_, [u8; 32]>) {
                panic!("controlled unwind from verified-Proposal observer");
            }
        }

        let keypairs: Vec<_> = (0..4)
            .map(|_| MlDsa44Backend::generate_keypair().expect("test keygen"))
            .collect();
        let (evidence, domain) = verified_test_qc(&keypairs, &[0, 1, 2]);
        let members = keypairs
            .iter()
            .enumerate()
            .map(|(index, (public_key, _))| {
                SnapshotMember::new(
                    index as u64,
                    1,
                    public_key.clone().into_boxed_slice().into_vec(),
                )
            })
            .collect();
        let input = VoteContextInput::new(
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            0,
            qbind_crypto::SUITE_PQ_RESERVED_1,
            domain,
            members,
        );
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(4));
        engine.install_received_vote_context(input).unwrap();
        let observer = engine
            .state
            .received_vote_budget()
            .unwrap()
            .try_clone()
            .unwrap();
        let baseline = observer.occupancy().0;
        let charge = evidence.retained_byte_size().unwrap();
        let proposal = proposal_for_test_evidence(1, &evidence, 1);
        let candidate = BasicHotStuffEngine::<[u8; 32]>::derive_block_id_from_header(
            ValidatorId(1),
            1,
            &proposal.header.parent_block_id,
        );
        let mut callback = PanicAfterRegistration;
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            engine.on_verified_proposal_event_observed(
                ValidatorId(1),
                &proposal,
                evidence,
                &mut callback,
            )
        }));
        assert!(unwind.is_err(), "observer panic is caught by the test");
        assert!(engine.state.verified_justification(&candidate).is_some());
        assert_eq!(engine.state.retained_evidence_bytes(), charge);
        assert_eq!(observer.occupancy(), (baseline + charge, 0, 1, 0));
    }

    #[test]
    fn shared_ledger_releases_eviction_and_final_map_ownership() {
        let keypairs = vec![MlDsa44Backend::generate_keypair().expect("test keygen")];
        let (evidence, _) = verified_test_qc(&keypairs, &[0]);
        let charge = evidence.retained_byte_size().unwrap();
        let limits = crate::vote_accumulator::ConsensusLimitsConfig {
            max_pending_blocks: 1,
            ..crate::vote_accumulator::ConsensusLimitsConfig::default()
        };
        let mut state = HotStuffStateEngine::with_limits(dense_validator_set(1), limits);
        let budget = EvidenceBudget::try_new(
            crate::hotstuff_state_engine::DEFAULT_MAX_RETAINED_EVIDENCE_BYTES,
            0,
        )
        .expect("shared ledger");
        let standing_floor = budget.occupancy().0;
        state
            .install_received_vote_budget(budget.try_clone().unwrap())
            .expect("install ledger");

        state
            .register_block_with_verified_justification(
                [0xA3; 32],
                1,
                None,
                evidence.clone(),
            )
            .expect("first retained node");
        state
            .register_block_with_verified_justification(
                [0xA4; 32],
                2,
                None,
                evidence,
            )
            .expect("second node evicts the safe first node");
        assert_eq!(state.block_count(), 1);
        assert_eq!(state.retained_evidence_bytes(), charge);
        assert_eq!(budget.occupancy().0, standing_floor + charge);

        drop(state);
        assert_eq!(
            budget.occupancy(),
            (standing_floor, 0, 0, 0),
            "final map teardown releases QC ownership while the ledger observer remains"
        );
    }

    #[test]
    fn received_vote_context_detached_token_survives_reinstall_and_engine_drop() {
        use crate::received_vote_evidence::budget_final_drop_count_for_test;

        let (public_key, secret_key) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key.clone());
        let context_charge = input.checked_charge().unwrap();
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine.install_received_vote_context(input).expect("install context");
        let observer = engine
            .state
            .received_vote_budget()
            .unwrap()
            .try_clone()
            .unwrap();
        let authority = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
        let floor = EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0;
        let wrapper_charge = std::mem::size_of::<Option<ActiveVoteContext>>() as u64;
        let table_charge = received_vote_table_charge();
        let token_bytes = std::mem::size_of::<VerifiedVoteToken>() as u64
            + qbind_crypto::ML_DSA_44_SIGNATURE_SIZE as u64;
        let installed = floor + context_charge + wrapper_charge + table_charge;
        assert_eq!(observer.occupancy(), (installed, 0, 1, 0));
        engine.set_current_epoch(0);
        assert!(engine.active_received_vote_context.is_some());
        assert_eq!(observer.occupancy(), (installed, 0, 1, 0));

        let (duplicate, _) =
            received_vote_context(0, MlDsa44Backend::generate_keypair().unwrap().0);
        assert_eq!(
            engine
                .install_received_vote_context(duplicate)
                .expect_err("same-epoch assignment preserves installed identity")
                .error,
            ContextInstallError::AlreadyInstalled
        );
        let failed_transition = engine
            .transition_to_epoch(crate::validator_set::EpochId::new(2), dense_validator_set(1))
            .is_err();
        assert!(failed_transition);
        assert!(engine.active_received_vote_context.is_some());
        let vote = signed_context_vote(0, &secret_key, &domain);
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("valid Vote");
        assert_eq!(
            observer.occupancy(),
            (installed + token_bytes, 0, 1, 0)
        );
        engine
            .transition_to_epoch(crate::validator_set::EpochId::new(1), dense_validator_set(1))
            .expect("successful epoch transition invalidates active context");
        assert!(engine.active_received_vote_context.is_none());
        assert_eq!(
            observer.occupancy(),
            (floor + table_charge + context_charge + token_bytes, 0, 1, 0)
        );

        let (new_input, _) = received_vote_context(1, public_key);
        engine
            .install_received_vote_context(new_input)
            .expect("reinstallation reuses ledger while old token remains alive");
        assert!(engine
            .state
            .received_vote_budget()
            .unwrap()
            .same_authority(&authority));
        assert_eq!(
            observer.occupancy(),
            (
                floor + table_charge + 2 * context_charge + wrapper_charge + token_bytes,
                0,
                2,
                0
            )
        );
        drop(token);
        assert_eq!(
            observer.occupancy(),
            (floor + context_charge + wrapper_charge + table_charge, 0, 1, 0)
        );
        let token = engine
            .admit_verified_received_vote(
                ValidatorId(0),
                signed_context_vote(1, &secret_key, &domain),
            )
            .expect("admit token from reinstalled context");
        assert_eq!(
            observer.occupancy(),
            (
                floor + context_charge + wrapper_charge + table_charge + token_bytes,
                0,
                1,
                0
            )
        );
        drop(engine);
        assert_eq!(
            observer.occupancy(),
            (floor + context_charge + token_bytes, 0, 1, 0),
            "engine/state destruction leaves the detached token's context alive"
        );
        drop(authority);
        std::thread::spawn(move || drop(token))
            .join()
            .expect("detached token final release completes on worker");
        assert_eq!(
            observer.occupancy(),
            (floor, 0, 0, 0),
            "token release restores standing floor while observer remains"
        );
        let final_drops_before = budget_final_drop_count_for_test();
        drop(observer);
        assert_eq!(
            budget_final_drop_count_for_test(),
            final_drops_before + 1,
            "dropping the independent observer destroys the final budget owner"
        );
    }

    #[test]
    fn received_vote_token_invocation_transfers_original_and_keeps_first_evidence() {
        let (public_key, secret_key) =
            MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let context_charge = input.checked_charge().unwrap();
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine
            .install_received_vote_context(input)
            .expect("install context and fixed table");
        let budget = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
        let floor = EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0;
        let table_charge = received_vote_table_charge();
        let wrapper_charge = std::mem::size_of::<Option<ActiveVoteContext>>() as u64;
        let vote = signed_context_vote(0, &secret_key, &domain);
        let expected_vote = vote.clone();
        let signature_ptr = vote.signature.as_ptr();
        let signature_capacity = vote.signature.capacity();
        let signature_charge = signature_capacity as u64;
        let byte_cap = engine.state.max_retained_evidence_bytes();
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("admit signed Vote");
        assert_eq!(
            budget.occupancy(),
            (
                floor
                    + table_charge
                    + context_charge
                    + wrapper_charge
                    + std::mem::size_of::<VerifiedVoteToken>() as u64
                    + signature_charge,
                0,
                1,
                0
            ),
            "full inline token and signature-capacity lease precede invocation"
        );

        match engine.invoke_verified_received_vote(token) {
            VerifiedVoteInvocation::Invoked {
                report,
                evidence: ReceivedVoteEvidenceDisposition::Retained,
                ..
            } => {
                assert!(matches!(report.history, VoteHistoryOutcome::FirstVote));
                assert!(matches!(
                    report.accumulator,
                    Some(Ok(crate::vote_accumulator::VoteAccumulatorDisposition::Inserted))
                ));
            }
            _ => panic!("first admitted token must be invoked and retained"),
        }
        let (transferred_ptr, transferred_capacity, transferred_lease, before_shrink) =
            crate::received_vote_evidence::table_transfer_before_shrink_for_test()
                .expect("test observed installed entry before lease shrink");
        assert_eq!(transferred_ptr, signature_ptr as usize);
        assert_eq!(transferred_capacity, signature_capacity);
        assert_eq!(
            transferred_lease,
            std::mem::size_of::<VerifiedVoteToken>() as u64 + signature_charge
        );
        assert_eq!(
            before_shrink,
            (
                floor
                    + table_charge
                    + context_charge
                    + wrapper_charge
                    + std::mem::size_of::<VerifiedVoteToken>() as u64
                    + signature_charge,
                0,
                1,
                0,
                0,
                0
            ),
            "token charge remains full after original fields enter the slot"
        );
        let first = engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(7, 0)
            .expect("membership-backed evidence retained");
        assert!(first.vote().signature.as_ptr() == signature_ptr);
        assert_eq!(first.vote().signature.capacity(), signature_capacity);
        let original_vote = first.vote().clone();
        assert_eq!(
            first.signature_lease_bytes_for_test(),
            signature_charge,
            "only signature capacity remains charged after in-place shrink"
        );
        assert_eq!(
            budget.occupancy(),
            (
                floor + table_charge + context_charge + wrapper_charge + signature_charge,
                0,
                1,
                0
            ),
            "token-inline coverage is released only after the original Vote is installed"
        );

        let retained_occupancy = (
            floor + table_charge + context_charge + wrapper_charge + signature_charge,
            0,
            1,
            0,
        );
        assert!(original_vote == expected_vote, "retained Vote differs (redacted)");
        let duplicate_vote = expected_vote.clone();
        let duplicate = engine
            .admit_verified_received_vote(
                ValidatorId(0),
                duplicate_vote,
            )
            .expect("admit a second token for the same Vote");
        let qc_attempts_before_duplicate =
            crate::vote_accumulator::qc_formation_attempts_for_test();
        match engine.invoke_verified_received_vote(duplicate) {
            VerifiedVoteInvocation::Invoked {
                report,
                evidence: ReceivedVoteEvidenceDisposition::ExistingExactDuplicate,
                ..
            } => {
                assert!(matches!(
                    report.history,
                    VoteHistoryOutcome::DuplicateSameBlock
                ));
                assert!(matches!(
                    report.accumulator,
                    Some(Ok(crate::vote_accumulator::VoteAccumulatorDisposition::Duplicate))
                ));
            }
            _ => panic!("duplicate token must be invoked without replacing evidence"),
        }
        assert_eq!(
            crate::vote_accumulator::qc_formation_attempts_for_test(),
            qc_attempts_before_duplicate + 1,
            "ordinary on_vote attempts QC after a duplicate insertion result"
        );
        let still_retained = engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(7, 0)
            .expect("duplicate preserves the first retained evidence");
        assert!(still_retained.vote() == &expected_vote, "retained Vote differs");
        assert!(still_retained.vote().signature.as_ptr() == signature_ptr);
        assert_eq!(budget.occupancy(), retained_occupancy);
        assert_eq!(engine.state.max_retained_evidence_bytes(), byte_cap);

        let alternate_signature_vote = signed_context_vote(0, &secret_key, &domain);
        let different_valid_signature =
            alternate_signature_vote.signature != expected_vote.signature;
        assert!(different_valid_signature, "test signatures unexpectedly matched");
        let alternate_signature_token = engine
            .admit_verified_received_vote(ValidatorId(0), alternate_signature_vote.clone())
            .expect("admit second valid signature over the same signed fields");
        match engine.invoke_verified_received_vote(alternate_signature_token) {
            VerifiedVoteInvocation::Invoked {
                report,
                evidence: ReceivedVoteEvidenceDisposition::ExistingDifferentSignature,
                ..
            } => {
                assert!(matches!(
                    report.history,
                    VoteHistoryOutcome::DuplicateSameBlock
                ));
                assert!(matches!(
                    report.accumulator,
                    Some(Ok(crate::vote_accumulator::VoteAccumulatorDisposition::Duplicate))
                ));
            }
            _ => panic!("a second valid signature must not replace the first evidence"),
        }
        let after_alternate_signature = engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(7, 0)
            .expect("first evidence remains");
        assert!(after_alternate_signature.vote() == &expected_vote, "retained Vote differs");
        assert!(
            after_alternate_signature.vote().signature == expected_vote.signature,
            "retained signature changed"
        );
        assert_eq!(after_alternate_signature.vote().signature.as_ptr(), signature_ptr);
        assert_eq!(after_alternate_signature.vote().signature.capacity(), signature_capacity);
        assert_eq!(budget.occupancy(), retained_occupancy);
        assert_eq!(engine.state.max_retained_evidence_bytes(), byte_cap);

        let mut signed_field_conflict = signed_context_vote(0, &secret_key, &domain);
        signed_field_conflict.round += 1;
        signed_field_conflict.signature =
            MlDsa44Backend::sign(&secret_key, &domain.vote_preimage(&signed_field_conflict))
                .expect("sign same-key signed-field conflict")
                .into_boxed_slice()
                .into_vec();
        assert!(
            !same_vote_signed_fields(&expected_vote, &signed_field_conflict),
            "round difference must be part of the signed-field comparison"
        );
        assert_eq!(signed_field_conflict.height, expected_vote.height);
        assert_eq!(signed_field_conflict.round, expected_vote.round + 1);
        let conflicting_fields_token = engine
            .admit_verified_received_vote(ValidatorId(0), signed_field_conflict)
            .expect("admit valid same-key signed-field conflict");
        match engine.invoke_verified_received_vote(conflicting_fields_token) {
            VerifiedVoteInvocation::Invoked {
                report,
                evidence: ReceivedVoteEvidenceDisposition::ExistingSignedFieldsConflict,
                ..
            } => {
                assert!(matches!(
                    report.history,
                    VoteHistoryOutcome::DuplicateSameBlock
                ));
                assert!(matches!(
                    report.accumulator,
                    Some(Ok(crate::vote_accumulator::VoteAccumulatorDisposition::Duplicate))
                ));
            }
            _ => panic!("different signed fields at one key must preserve original evidence"),
        }
        let after_signed_field_conflict = engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(7, 0)
            .expect("first evidence remains after signed-field conflict");
        assert!(
            after_signed_field_conflict.vote() == &expected_vote,
            "retained Vote differs"
        );
        assert!(after_signed_field_conflict.vote().signature.as_ptr() == signature_ptr);
        assert_eq!(after_signed_field_conflict.vote().signature.capacity(), signature_capacity);
        assert_eq!(after_signed_field_conflict.vote().height, expected_vote.height);
        assert_eq!(after_signed_field_conflict.vote().round, expected_vote.round);
        assert_eq!(budget.occupancy(), retained_occupancy);
        assert_eq!(engine.state.max_retained_evidence_bytes(), byte_cap);

        let mut conflicting_vote = signed_context_vote(0, &secret_key, &domain);
        conflicting_vote.block_id = [0x74; 32];
        assert_eq!(conflicting_vote.height, expected_vote.height);
        assert_eq!(conflicting_vote.round, expected_vote.round);
        assert_eq!(conflicting_vote.validator_index, expected_vote.validator_index);
        assert_ne!(conflicting_vote.block_id, expected_vote.block_id);
        conflicting_vote.signature =
            MlDsa44Backend::sign(&secret_key, &domain.vote_preimage(&conflicting_vote))
                .expect("sign conflicting fields")
                .into_boxed_slice()
                .into_vec();
        let conflicting_token = engine
            .admit_verified_received_vote(ValidatorId(0), conflicting_vote)
            .expect("admit valid conflicting Vote");
        match engine.invoke_verified_received_vote(conflicting_token) {
            VerifiedVoteInvocation::Invoked {
                report,
                evidence: ReceivedVoteEvidenceDisposition::NotRetainedEquivocation,
                ..
            } => assert!(matches!(
                report.history,
                VoteHistoryOutcome::Equivocation { .. }
            )),
            _ => panic!("a signed-field conflict must not replace retained evidence"),
        }
        let after_conflict = engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(7, 0)
            .expect("first evidence remains after equivocation");
        assert!(after_conflict.vote() == &expected_vote, "retained Vote differs");
        assert!(after_conflict.vote().signature.as_ptr() == signature_ptr);
        assert_eq!(after_conflict.vote().signature.capacity(), signature_capacity);
        assert_eq!(budget.occupancy(), retained_occupancy);
        assert_eq!(engine.state.max_retained_evidence_bytes(), byte_cap);

        engine
            .transition_to_epoch(crate::validator_set::EpochId::new(1), dense_validator_set(1))
            .expect("epoch transition invalidates retained membership evidence");
        assert!(
            engine
                .state
                .received_vote_evidence_table()
                .unwrap()
                .entry_for(7, 0)
                .is_none()
        );
        assert_eq!(
            budget.occupancy(),
            (floor + table_charge, 0, 0, 0),
            "invalidation releases entry ownership but keeps standing table storage"
        );
    }

    #[test]
    fn received_vote_foreign_ledger_refusal_preserves_token_and_both_engines() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct CountProgress(Arc<AtomicUsize>);
        impl ConsensusProgressRecorder for CountProgress {
            fn record_qc_formed(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_vote_observed(&self, _is_for_current_view: bool) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_view_change(&self, _from_view: u64, _to_view: u64) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_leader_change(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn reset_current_view_votes(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        #[derive(Debug)]
        struct CountValidator(Arc<AtomicUsize>);
        impl ValidatorVoteRecorder for CountValidator {
            fn on_validator_vote(&self, _validator: ValidatorId, _view: u64) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let (source_key, source_secret) =
            MlDsa44Backend::generate_keypair().expect("source keygen");
        let (target_key, _) = MlDsa44Backend::generate_keypair().expect("target keygen");
        let (source_input, source_domain) = received_vote_context(0, source_key);
        let (target_input, _) = received_vote_context(0, target_key);
        let mut source = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        let mut target = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        source.install_received_vote_context(source_input).unwrap();
        target.install_received_vote_context(target_input).unwrap();
        let source_ledger = source.state.received_vote_budget().unwrap().try_clone().unwrap();
        let target_ledger = target.state.received_vote_budget().unwrap().try_clone().unwrap();
        let source_before = source_ledger.occupancy();
        let target_before = target_ledger.occupancy();
        let vote = signed_context_vote(0, &source_secret, &source_domain);
        let expected_vote = vote.clone();
        let signature_ptr = vote.signature.as_ptr();
        let signature_capacity = vote.signature.capacity();
        let token = source
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("admit source token");
        let source_with_token = source_ledger.occupancy();
        let callbacks = Arc::new(AtomicUsize::new(0));
        target.set_progress_recorder(Arc::new(CountProgress(Arc::clone(&callbacks))));
        target.set_validator_vote_recorder(Arc::new(CountValidator(Arc::clone(&callbacks))));
        let target_view = target.current_view;
        let target_cap = target.state.max_retained_evidence_bytes();
        let invocations = RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(std::cell::Cell::get);

        let token = match target.invoke_verified_received_vote(token) {
            VerifiedVoteInvocation::Refused {
                token,
                reason: VerifiedVoteInvocationRefusal::ForeignLedger,
            } => token,
            _ => panic!("a token from another ledger must be refused"),
        };
        assert!(token.vote() == &expected_vote, "returned Vote differs");
        assert_eq!(token.vote().signature.as_ptr(), signature_ptr);
        assert_eq!(token.vote().signature.capacity(), signature_capacity);
        assert_eq!(source_ledger.occupancy(), source_with_token);
        assert_eq!(target_ledger.occupancy(), target_before);
        assert_eq!(target.state.max_retained_evidence_bytes(), target_cap);
        assert_eq!(source_before.0, source_with_token.0 - std::mem::size_of::<VerifiedVoteToken>() as u64 - signature_capacity as u64);
        assert_eq!(target.current_view, target_view);
        assert_eq!(target.state.received_vote_evidence_table().unwrap().occupied(), 0);
        assert!(!target.state.has_vote_history_membership_for_test(
            ValidatorId(0),
            expected_vote.height,
            &expected_vote.block_id
        ));
        assert_eq!(target.state.vote_count(expected_vote.height, &expected_vote.block_id), 0);
        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(
            RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(std::cell::Cell::get),
            invocations,
            "preflight refusal must not call the state mutation"
        );
    }

    #[test]
    fn received_vote_no_context_stale_and_terminal_refusals_preserve_token() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct CountProgress(Arc<AtomicUsize>);
        impl ConsensusProgressRecorder for CountProgress {
            fn record_qc_formed(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_vote_observed(&self, _is_for_current_view: bool) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_view_change(&self, _from_view: u64, _to_view: u64) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_leader_change(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn reset_current_view_votes(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        #[derive(Debug)]
        struct CountValidator(Arc<AtomicUsize>);
        impl ValidatorVoteRecorder for CountValidator {
            fn on_validator_vote(&self, _validator: ValidatorId, _view: u64) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let (public_key, secret_key) =
            MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key.clone());
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine.install_received_vote_context(input).unwrap();
        let observer = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
        let cap = engine.state.max_retained_evidence_bytes();
        let vote = signed_context_vote(0, &secret_key, &domain);
        let expected_vote = vote.clone();
        let signature_ptr = vote.signature.as_ptr();
        let signature_capacity = vote.signature.capacity();
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("admit old-context token");

        engine
            .transition_to_epoch(crate::validator_set::EpochId::new(1), dense_validator_set(1))
            .expect("successful epoch invalidation");
        assert!(engine.active_received_vote_context.is_none());
        assert!(engine.state.received_vote_evidence_table().is_some());
        let current_view = engine.current_view;
        let callbacks = Arc::new(AtomicUsize::new(0));
        engine.set_progress_recorder(Arc::new(CountProgress(Arc::clone(&callbacks))));
        engine.set_validator_vote_recorder(Arc::new(CountValidator(Arc::clone(&callbacks))));
        let no_context_ledger = observer.occupancy();
        let invocations = RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(std::cell::Cell::get);
        let token = match engine.invoke_verified_received_vote(token) {
            VerifiedVoteInvocation::Refused {
                token,
                reason: VerifiedVoteInvocationRefusal::NoContext,
            } => token,
            _ => panic!("a detached token cannot invoke without an active context"),
        };
        assert!(token.vote() == &expected_vote, "returned Vote differs");
        assert_eq!(token.vote().signature.as_ptr(), signature_ptr);
        assert_eq!(token.vote().signature.capacity(), signature_capacity);
        assert_eq!(observer.occupancy(), no_context_ledger);
        assert_eq!(
            engine.state.received_vote_evidence_table().unwrap().occupied(),
            0
        );
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap);
        assert_eq!(engine.current_view, current_view);
        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(
            RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(std::cell::Cell::get),
            invocations
        );
        assert!(!engine.state.has_vote_history_membership_for_test(
            ValidatorId(0),
            expected_vote.height,
            &expected_vote.block_id
        ));

        let (new_input, _) = received_vote_context(1, public_key);
        let new_context_charge = new_input.checked_charge().unwrap();
        engine
            .install_received_vote_context(new_input)
            .expect("same-ledger reinstallation");
        let stale_ledger = observer.occupancy();
        let token = match engine.invoke_verified_received_vote(token) {
            VerifiedVoteInvocation::Refused {
                token,
                reason: VerifiedVoteInvocationRefusal::StaleContext,
            } => token,
            _ => panic!("same-ledger token from invalidated context must be stale"),
        };
        assert!(token.vote() == &expected_vote, "returned Vote differs");
        assert_eq!(token.vote().signature.as_ptr(), signature_ptr);
        assert_eq!(token.vote().signature.capacity(), signature_capacity);
        assert_eq!(observer.occupancy(), stale_ledger);
        assert_eq!(
            engine.state.received_vote_evidence_table().unwrap().occupied(),
            0
        );
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap);
        assert_eq!(engine.current_view, current_view);
        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(
            RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(std::cell::Cell::get),
            invocations
        );

        let table_charge = received_vote_table_charge();
        let wrapper_charge = std::mem::size_of::<Option<ActiveVoteContext>>() as u64;
        let before_state_mut = observer.occupancy();
        let before_state_mut_view = engine.current_view;
        let table = engine.state.received_vote_evidence_table().unwrap();
        assert_eq!(table.occupied(), 0);
        let _ = engine.state_mut();
        assert!(engine.received_vote_producer_disabled);
        assert!(engine.active_received_vote_context.is_none());
        assert!(engine.state.received_vote_evidence_table().is_none());
        let after_state_mut = observer.occupancy();
        assert_eq!(
            after_state_mut.0,
            before_state_mut.0 - table_charge - wrapper_charge - new_context_charge
        );
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap);
        assert_eq!(engine.current_view, before_state_mut_view);
        let token = match engine.invoke_verified_received_vote(token) {
            VerifiedVoteInvocation::Refused {
                token,
                reason: VerifiedVoteInvocationRefusal::ProducerDisabled,
            } => token,
            _ => panic!("state_mut terminally disables token invocation"),
        };
        assert!(token.vote() == &expected_vote, "returned Vote differs");
        assert_eq!(token.vote().signature.as_ptr(), signature_ptr);
        assert_eq!(token.vote().signature.capacity(), signature_capacity);
        assert_eq!(observer.occupancy(), after_state_mut);
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap);
        assert_eq!(engine.current_view, before_state_mut_view);
        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(
            RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(std::cell::Cell::get),
            invocations
        );
        drop(token);
        let floor = EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0;
        assert_eq!(observer.occupancy(), (floor, 0, 0, 0));
    }

    #[test]
    fn received_vote_reconciliation_requires_both_logical_memberships() {
        let (public_key, secret_key) =
            MlDsa44Backend::generate_keypair().expect("test keygen");
        let (_, domain) = received_vote_context(0, public_key.clone());
        for lost_memberships in [1_u8, 2, 3] {
            let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
            let (input, _) = received_vote_context(0, public_key.clone());
            let context_charge = input.checked_charge().unwrap();
            engine
                .install_received_vote_context(input)
                .expect("install table and context");
            let observer = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
            let vote = signed_context_vote(0, &secret_key, &domain);
            let expected_vote = vote.clone();
            let token = engine
                .admit_verified_received_vote(ValidatorId(0), vote)
                .expect("admit token");
            assert!(matches!(
                engine.invoke_verified_received_vote(token),
                VerifiedVoteInvocation::Invoked {
                    evidence: ReceivedVoteEvidenceDisposition::Retained,
                    ..
                }
            ));
            assert!(engine.state.has_vote_history_membership_for_test(
                ValidatorId(0),
                expected_vote.height,
                &expected_vote.block_id
            ));
            assert!(engine
                .state
                .has_vote_memberships(ValidatorId(0), expected_vote.height, &expected_vote.block_id));

            if lost_memberships & 1 != 0 {
                engine.state.remove_vote_history_membership_for_test(
                    ValidatorId(0),
                    expected_vote.height,
                );
            }
            if lost_memberships & 2 != 0 {
                engine.state.remove_accumulator_membership_for_test(
                    expected_vote.height,
                    &expected_vote.block_id,
                );
            }
            assert_eq!(
                engine.state.has_vote_history_membership_for_test(
                    ValidatorId(0),
                    expected_vote.height,
                    &expected_vote.block_id
                ),
                lost_memberships & 1 == 0
            );
            assert_eq!(
                engine.state.vote_count(expected_vote.height, &expected_vote.block_id) > 0,
                lost_memberships & 2 == 0
            );
            engine.state.reconcile_received_vote_evidence();
            let table = engine.state.received_vote_evidence_table().unwrap();
            assert_eq!(table.occupied(), 0, "loss mask {lost_memberships}");
            assert!(table.entry_for(expected_vote.height, 0).is_none());
            assert_eq!(
                observer.occupancy(),
                (
                    EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0
                        + received_vote_table_charge()
                    + context_charge
                        + std::mem::size_of::<Option<ActiveVoteContext>>() as u64,
                    0,
                    1,
                    0
                ),
                "entry signature/token coverage released after reconciliation"
            );
        }
    }

    #[test]
    fn received_vote_state_mut_destroys_populated_table_with_exact_ledger_release() {
        let (public_key, secret_key) =
            MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let context_charge = input.checked_charge().unwrap();
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine.install_received_vote_context(input).unwrap();
        let observer = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
        let floor = EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0;
        let cap = engine.state.max_retained_evidence_bytes();
        let vote = signed_context_vote(0, &secret_key, &domain);
        let signature_charge = vote.signature.capacity() as u64;
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("admit token");
        match engine.invoke_verified_received_vote(token) {
            VerifiedVoteInvocation::Invoked {
                evidence: ReceivedVoteEvidenceDisposition::Retained,
                ..
            } => {}
            _ => panic!("retained token required for populated-table drop"),
        }
        assert_eq!(
            observer.occupancy(),
            (
                floor
                    + context_charge
                    + std::mem::size_of::<Option<ActiveVoteContext>>() as u64
                    + received_vote_table_charge()
                    + signature_charge,
                0,
                1,
                0
            )
        );
        assert_eq!(engine.state.received_vote_evidence_table().unwrap().occupied(), 1);
        let _ = engine.state_mut();
        assert!(engine.state.received_vote_evidence_table().is_none());
        assert!(engine.active_received_vote_context.is_none());
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap);
        assert_eq!(observer.occupancy(), (floor, 0, 0, 0));
    }

    #[test]
    fn received_vote_missing_evidence_for_duplicate_is_retained() {
        let (public_key, secret_key) =
            MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let context_charge = input.checked_charge().unwrap();
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine.install_received_vote_context(input).unwrap();
        let observer = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
        let vote = signed_context_vote(0, &secret_key, &domain);
        let expected_vote = vote.clone();
        engine
            .state
            .on_vote(ValidatorId(0), vote.height, &vote.block_id)
            .expect("pre-existing logical duplicate membership");
        assert!(engine.state.received_vote_evidence_table().unwrap().entry_for(vote.height, 0).is_none());
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("admit valid token for duplicate");
        match engine.invoke_verified_received_vote(token) {
            VerifiedVoteInvocation::Invoked {
                report,
                evidence: ReceivedVoteEvidenceDisposition::Retained,
                ..
            } => {
                assert!(matches!(report.history, VoteHistoryOutcome::DuplicateSameBlock));
                assert!(matches!(
                    report.accumulator,
                    Some(Ok(crate::vote_accumulator::VoteAccumulatorDisposition::Duplicate))
                ));
            }
            _ => panic!("missing evidence for a logical duplicate must be retained"),
        }
        let entry = engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(expected_vote.height, expected_vote.validator_index)
            .unwrap();
        assert!(entry.vote() == &expected_vote, "retained Vote differs");
        let expected = EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0
            + received_vote_table_charge()
            + context_charge
            + std::mem::size_of::<Option<ActiveVoteContext>>() as u64
            + expected_vote.signature.capacity() as u64;
        assert_eq!(observer.occupancy(), (expected, 0, 1, 0));
    }

    #[test]
    fn received_vote_capacity_dropped_outcome_destroys_token_without_retention() {
        let (key0, secret0) = MlDsa44Backend::generate_keypair().expect("validator zero key");
        let (key1, secret1) = MlDsa44Backend::generate_keypair().expect("validator one key");
        let (one_member, domain) = received_vote_context(0, key0.clone());
        let mut members = one_member.members().to_vec();
        members.push(SnapshotMember::new(
            1,
            1,
            key1.into_boxed_slice().into_vec(),
        ));
        let input = VoteContextInput::new(
            one_member.runtime_chain_id(),
            0,
            one_member.suite_id(),
            domain.clone(),
            members,
        );
        let limits = crate::vote_accumulator::ConsensusLimitsConfig {
            max_votes_per_view: 1,
            ..crate::vote_accumulator::ConsensusLimitsConfig::default()
        };
        let mut engine = BasicHotStuffEngine::with_state_limits(
            ValidatorId(0),
            dense_validator_set(2),
            limits,
        );
        let context_charge = input.checked_charge().unwrap();
        engine.install_received_vote_context(input).unwrap();
        let observer = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
        let mut first = signed_context_vote(0, &secret0, &domain);
        first.block_id = [0x51; 32];
        first.signature = MlDsa44Backend::sign(&secret0, &domain.vote_preimage(&first))
            .expect("sign first capacity vote")
            .into_boxed_slice()
            .into_vec();
        engine
            .state
            .on_vote(ValidatorId(0), first.height, &first.block_id)
            .expect("fill one-signer accumulator entry");
        let mut dropped = signed_context_vote(0, &secret1, &domain);
        dropped.validator_index = 1;
        dropped.block_id = first.block_id;
        dropped.signature = MlDsa44Backend::sign(&secret1, &domain.vote_preimage(&dropped))
            .expect("sign capacity-dropped vote");
        let dropped_signature_capacity = dropped.signature.capacity();
        let expected_vote = dropped.clone();
        let token = engine
            .admit_verified_received_vote(ValidatorId(1), dropped)
            .expect("admit valid token that exceeds accumulator entry limit");
        let qc_attempts_before_drop = crate::vote_accumulator::qc_formation_attempts_for_test();
        match engine.invoke_verified_received_vote(token) {
            VerifiedVoteInvocation::Invoked {
                report,
                evidence: ReceivedVoteEvidenceDisposition::NotRetainedCapacityDropped,
                ..
            } => {
                assert!(matches!(report.history, VoteHistoryOutcome::FirstVote));
                assert!(matches!(
                    report.accumulator,
                    Some(Ok(crate::vote_accumulator::VoteAccumulatorDisposition::CapacityDropped))
                ));
                assert!(matches!(report.qc, Ok(None)));
            }
            _ => panic!("capacity-dropped token must be invoked then destroyed"),
        }
        assert_eq!(
            crate::vote_accumulator::qc_formation_attempts_for_test(),
            qc_attempts_before_drop + 1,
            "ordinary on_vote attempts QC after CapacityDropped"
        );
        assert!(engine.state.has_vote_history_membership_for_test(
            ValidatorId(1),
            expected_vote.height,
            &expected_vote.block_id
        ));
        assert_eq!(
            engine.state.vote_count(expected_vote.height, &expected_vote.block_id),
            1,
            "only validator zero remains in the accumulator"
        );
        let table = engine.state.received_vote_evidence_table().unwrap();
        assert_eq!(table.occupied(), 0);
        assert!(table.entry_for(expected_vote.height, 1).is_none());
        assert_eq!(
            observer.occupancy(),
            (
                EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0
                    + received_vote_table_charge()
                    + context_charge
                    + std::mem::size_of::<Option<ActiveVoteContext>>() as u64,
                0,
                1,
                0
            ),
            "the dropped token's full inline/signature lease is released"
        );
        assert!(dropped_signature_capacity > 0);
    }

    #[test]
    fn received_vote_leader_self_vote_capacity_drop_skips_qc_and_reconciles() {
        let (key0, secret0) = MlDsa44Backend::generate_keypair().expect("validator zero key");
        let (key1, _) = MlDsa44Backend::generate_keypair().expect("validator one key");
        let (one_member, domain) = received_vote_context(0, key0.clone());
        let mut members = one_member.members().to_vec();
        members.push(SnapshotMember::new(
            1,
            1,
            key1.into_boxed_slice().into_vec(),
        ));
        let input = VoteContextInput::new(
            one_member.runtime_chain_id(),
            0,
            one_member.suite_id(),
            domain.clone(),
            members,
        );
        let limits = crate::vote_accumulator::ConsensusLimitsConfig {
            max_votes_per_view: 1,
            max_votes_by_view_entries: 1,
            ..crate::vote_accumulator::ConsensusLimitsConfig::default()
        };
        let context_charge = input.checked_charge().unwrap();
        let mut engine = BasicHotStuffEngine::with_state_limits(
            ValidatorId(0),
            dense_validator_set(2),
            limits,
        );
        engine.install_received_vote_context(input).unwrap();
        let observer = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
        let floor = EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0;
        let table_charge = received_vote_table_charge();
        let wrapper_charge = std::mem::size_of::<Option<ActiveVoteContext>>() as u64;
        let cap = engine.state.max_retained_evidence_bytes();
        let mut first = signed_context_vote(0, &secret0, &domain);
        first.block_id = [0x52; 32];
        first.signature = MlDsa44Backend::sign(&secret0, &domain.vote_preimage(&first))
            .expect("sign retained self-vote")
            .into_boxed_slice()
            .into_vec();
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), first.clone())
            .expect("admit first signer");
        let signature_charge = first.signature.capacity() as u64;
        assert!(matches!(
            engine.invoke_verified_received_vote(token),
            VerifiedVoteInvocation::Invoked {
                evidence: ReceivedVoteEvidenceDisposition::Retained,
                ..
            }
        ));
        let retained_occupancy = (
            floor + table_charge + context_charge + wrapper_charge + signature_charge,
            0,
            1,
            0,
        );
        assert_eq!(observer.occupancy(), retained_occupancy);
        assert!(engine.state.has_vote_history_membership_for_test(
            ValidatorId(0),
            first.height,
            &first.block_id
        ));
        assert_eq!(engine.state.vote_count(first.height, &first.block_id), 1);
        let retained_vote = engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(first.height, 0)
            .unwrap()
            .vote()
            .clone();
        let retained_entry = engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(first.height, 0)
            .unwrap();
        assert!(retained_entry.vote() == &first);
        assert!(
            retained_entry.vote() == &retained_vote,
            "retained Vote differs (redacted)"
        );
        assert_eq!(retained_entry.vote().signature.capacity() as u64, signature_charge);
        let qc_attempts_before = crate::vote_accumulator::qc_formation_attempts_for_test();
        let report = engine.state.on_leader_self_vote_detailed(
            ValidatorId(1),
            first.height,
            &first.block_id,
        );
        assert_eq!(
            report.insertion,
            Some(crate::vote_accumulator::VoteAccumulatorDisposition::CapacityDropped)
        );
        assert!(!report.qc_processed);
        assert!(!report.qc_formed);
        assert_eq!(
            crate::vote_accumulator::qc_formation_attempts_for_test(),
            qc_attempts_before,
            "detailed leader route returns before QC formation on non-insertion"
        );
        assert!(
            !engine.state.has_vote_history_membership_for_test(
                ValidatorId(0),
                first.height,
                &first.block_id
            ),
            "second history insertion evicts first validator membership"
        );
        assert!(engine.state.has_vote_history_membership_for_test(
            ValidatorId(1),
            first.height,
            &first.block_id
        ));
        assert_eq!(engine.state.vote_count(first.height, &first.block_id), 1);
        let table = engine.state.received_vote_evidence_table().unwrap();
        assert_eq!(table.occupied(), 0, "stale evidence is reconciled before return");
        assert!(table.entry_for(first.height, 0).is_none());
        assert_eq!(
            observer.occupancy(),
            (
                retained_occupancy.0 - signature_charge,
                retained_occupancy.1,
                retained_occupancy.2,
                retained_occupancy.3,
            )
        );
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap);
        assert_eq!(retained_vote.signature.capacity() as u64, signature_charge);
    }

    #[test]
    fn received_vote_legacy_state_error_reconciles_and_skips_event_callbacks() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct CountProgress(Arc<AtomicUsize>);
        impl ConsensusProgressRecorder for CountProgress {
            fn record_qc_formed(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_vote_observed(&self, _is_for_current_view: bool) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_view_change(&self, _from_view: u64, _to_view: u64) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_leader_change(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn reset_current_view_votes(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        #[derive(Debug)]
        struct CountValidator(Arc<AtomicUsize>);
        impl ValidatorVoteRecorder for CountValidator {
            fn on_validator_vote(&self, _validator: ValidatorId, _view: u64) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let (public_key, secret_key) =
            MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let context_charge = input.checked_charge().unwrap();
        let limits = crate::vote_accumulator::ConsensusLimitsConfig {
            max_votes_by_view_entries: 1,
            ..crate::vote_accumulator::ConsensusLimitsConfig::default()
        };
        let mut engine = BasicHotStuffEngine::with_state_limits(
            ValidatorId(0),
            dense_validator_set(1),
            limits,
        );
        engine.install_received_vote_context(input).unwrap();
        let observer = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
        let floor = EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0;
        let table_charge = received_vote_table_charge();
        let wrapper_charge = std::mem::size_of::<Option<ActiveVoteContext>>() as u64;
        let cap = engine.state.max_retained_evidence_bytes();
        let vote = signed_context_vote(0, &secret_key, &domain);
        let signature_charge = vote.signature.capacity() as u64;
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote.clone())
            .expect("admit valid token");
        assert!(matches!(
            engine.invoke_verified_received_vote(token),
            VerifiedVoteInvocation::Invoked {
                evidence: ReceivedVoteEvidenceDisposition::Retained,
                ..
            }
        ));
        let retained_occupancy = (
            floor + table_charge + context_charge + wrapper_charge + signature_charge,
            0,
            1,
            0,
        );
        assert_eq!(observer.occupancy(), retained_occupancy);
        assert!(engine.state.has_vote_history_membership_for_test(
            ValidatorId(0),
            vote.height,
            &vote.block_id
        ));
        assert_eq!(engine.state.vote_count(vote.height, &vote.block_id), 1);
        let retained_entry = engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(vote.height, 0)
            .unwrap();
        assert!(retained_entry.vote() == &vote);
        assert_eq!(retained_entry.vote().signature.capacity() as u64, signature_charge);
        let table_before = engine.state.received_vote_evidence_table().unwrap().occupied();
        let current_view = engine.current_view;
        let callbacks = Arc::new(AtomicUsize::new(0));
        engine.set_progress_recorder(Arc::new(CountProgress(Arc::clone(&callbacks))));
        engine.set_validator_vote_recorder(Arc::new(CountValidator(Arc::clone(&callbacks))));

        let error = engine
            .on_vote_event(ValidatorId(99), &vote)
            .expect_err("non-member fails in the accumulator after history records");
        assert!(matches!(
            error,
            QcValidationError::NonMemberSigner(ValidatorId(99))
        ));
        assert!(engine.state.has_vote_history_membership_for_test(
            ValidatorId(99),
            vote.height,
            &vote.block_id
        ));
        assert!(
            !engine.state.has_vote_history_membership_for_test(
                ValidatorId(0),
                vote.height,
                &vote.block_id
            ),
            "nonmember insertion evicts original signer history at limit one"
        );
        assert_eq!(engine.state.vote_count(vote.height, &vote.block_id), 1);
        assert_eq!(table_before, 1);
        let table = engine.state.received_vote_evidence_table().unwrap();
        assert_eq!(table.occupied(), 0, "Err return reconciles stale evidence");
        assert!(table.entry_for(vote.height, 0).is_none());
        assert_eq!(
            observer.occupancy(),
            (
                retained_occupancy.0 - signature_charge,
                retained_occupancy.1,
                retained_occupancy.2,
                retained_occupancy.3,
            ),
            "only retained signature capacity is released; table/context/wrapper remain"
        );
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap);
        assert_eq!(
            observer.occupancy().0,
            floor + table_charge + context_charge + wrapper_charge
        );
        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(engine.current_view, current_view);
    }

    #[test]
    fn received_vote_recorder_panic_follows_completed_evidence_transfer() {
        use std::sync::Mutex;

        #[derive(Debug)]
        struct PanicOnVote(Arc<Mutex<Vec<&'static str>>>);

        impl ConsensusProgressRecorder for PanicOnVote {
            fn record_qc_formed(&self) {
                self.0.lock().unwrap().push("qc_formed");
            }
            fn record_vote_observed(&self, _is_for_current_view: bool) {
                self.0.lock().unwrap().push("vote_observed");
                panic!("controlled progress-recorder panic");
            }
            fn record_view_change(&self, _from_view: u64, _to_view: u64) {
                self.0.lock().unwrap().push("view_change");
            }
            fn record_leader_change(&self) {
                self.0.lock().unwrap().push("leader_change");
            }
            fn reset_current_view_votes(&self) {
                self.0.lock().unwrap().push("reset_votes");
            }
        }
        #[derive(Debug)]
        struct RecordValidator(Arc<Mutex<Vec<&'static str>>>);
        impl ValidatorVoteRecorder for RecordValidator {
            fn on_validator_vote(&self, _validator: ValidatorId, _view: u64) {
                self.0.lock().unwrap().push("validator_vote");
            }
        }

        let (public_key, secret_key) =
            MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine
            .install_received_vote_context(input)
            .expect("install context");
        let callback_order = Arc::new(Mutex::new(Vec::new()));
        engine.set_progress_recorder(Arc::new(PanicOnVote(Arc::clone(&callback_order))));
        engine.set_validator_vote_recorder(Arc::new(RecordValidator(Arc::clone(&callback_order))));
        let budget = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
        let baseline = budget.occupancy().0;
        let cap = engine.state.max_retained_evidence_bytes();
        let current_view = engine.current_view;
        let vote = signed_context_vote(0, &secret_key, &domain);
        let expected_vote = vote.clone();
        let view = vote.height;
        let block_id = vote.block_id;
        let signature_ptr = vote.signature.as_ptr();
        let signature_capacity = vote.signature.capacity();
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), vote)
            .expect("admit signed Vote");

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = engine.invoke_verified_received_vote(token);
        }));
        assert!(unwind.is_err(), "reachable recorder must unwind invocation");
        assert_eq!(*callback_order.lock().unwrap(), ["vote_observed"]);
        assert_eq!(engine.current_view, current_view, "later view phase is suppressed");
        assert!(engine
            .state
            .has_vote_memberships(ValidatorId(0), view, &block_id));
        let entry = engine
            .state
            .received_vote_evidence_table()
            .unwrap()
            .entry_for(view, 0)
            .expect("evidence disposition completed before recorder call");
        assert!(entry.vote() == &expected_vote, "retained Vote differs");
        assert_eq!(entry.vote().signature.as_ptr(), signature_ptr);
        assert_eq!(entry.vote().signature.capacity(), signature_capacity);
        assert_eq!(entry.vote().height, view);
        assert_eq!(entry.vote().round, expected_vote.round);
        let signature_charge = entry.vote().signature.capacity() as u64;
        let expected = baseline + signature_charge;
        assert_eq!(budget.occupancy(), (expected, 0, 1, 0));
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap);
        assert_eq!(
            engine.state.received_vote_evidence_table().unwrap().occupied(),
            1
        );
    }

    #[test]
    fn received_vote_full_table_refuses_before_view_eviction_and_returns_token() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct CountProgress(Arc<AtomicUsize>);
        impl ConsensusProgressRecorder for CountProgress {
            fn record_qc_formed(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_vote_observed(&self, _is_for_current_view: bool) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_view_change(&self, _from_view: u64, _to_view: u64) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn record_leader_change(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn reset_current_view_votes(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        #[derive(Debug)]
        struct CountValidator(Arc<AtomicUsize>);
        impl ValidatorVoteRecorder for CountValidator {
            fn on_validator_vote(&self, _validator: ValidatorId, _view: u64) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let (public_key, secret_key) =
            MlDsa44Backend::generate_keypair().expect("test keygen");
        let (input, domain) = received_vote_context(0, public_key);
        let limits = crate::vote_accumulator::ConsensusLimitsConfig {
            max_tracked_views: ReceivedVoteEvidenceTable::<[u8; 32]>::CAPACITY,
            ..crate::vote_accumulator::ConsensusLimitsConfig::default()
        };
        let mut engine =
            BasicHotStuffEngine::with_state_limits(ValidatorId(0), dense_validator_set(1), limits);
        engine
            .install_received_vote_context(input)
            .expect("install context and fixed table");

        for view in 0..ReceivedVoteEvidenceTable::<[u8; 32]>::CAPACITY as u64 {
            let mut vote = signed_context_vote(0, &secret_key, &domain);
            vote.height = view;
            vote.signature = MlDsa44Backend::sign(&secret_key, &domain.vote_preimage(&vote))
                .expect("sign view-specific Vote")
                .into_boxed_slice()
                .into_vec();
            let token = engine
                .admit_verified_received_vote(ValidatorId(0), vote)
                .expect("admit view-specific Vote");
            match engine.invoke_verified_received_vote(token) {
                VerifiedVoteInvocation::Invoked {
                    evidence: ReceivedVoteEvidenceDisposition::Retained,
                    ..
                } => {}
                _ => panic!("each live membership must occupy one table slot"),
            }
        }

        let mut refused_vote = signed_context_vote(0, &secret_key, &domain);
        refused_vote.height = ReceivedVoteEvidenceTable::<[u8; 32]>::CAPACITY as u64;
        refused_vote.signature =
            MlDsa44Backend::sign(&secret_key, &domain.vote_preimage(&refused_vote))
                .expect("sign refusal-control Vote")
                .into_boxed_slice()
                .into_vec();
        let token = engine
            .admit_verified_received_vote(ValidatorId(0), refused_vote)
            .expect("full-table control token is valid");
        let expected_vote = token.vote().clone();
        let signature_ptr = token.vote().signature.as_ptr();
        let signature_capacity = token.vote().signature.capacity();
        let current_view = engine.current_view;
        let ledger = engine.state.received_vote_budget().unwrap().try_clone().unwrap();
        let ledger_before = ledger.occupancy();
        let callbacks = Arc::new(AtomicUsize::new(0));
        engine.set_progress_recorder(Arc::new(CountProgress(Arc::clone(&callbacks))));
        engine.set_validator_vote_recorder(Arc::new(CountValidator(Arc::clone(&callbacks))));
        let invocation_count = RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(std::cell::Cell::get);
        let history_before = engine.state.has_vote_history_membership_for_test(
            ValidatorId(0),
            1024,
            &[0x73; 32],
        );
        let accumulator_before = engine.state.vote_count(1024, &[0x73; 32]);
        let dropped_before = engine.state.dropped_votes();
        let cap_before = engine.state.max_retained_evidence_bytes();
        let token = match engine.invoke_verified_received_vote(token) {
            VerifiedVoteInvocation::Refused {
                token,
                reason: VerifiedVoteInvocationRefusal::TableFull,
            } => {
                assert!(token.vote() == &expected_vote, "returned Vote differs");
                assert!(token.vote().signature.as_ptr() == signature_ptr);
                assert_eq!(token.vote().signature.capacity(), signature_capacity);
                token
            }
            _ => panic!("a full table must refuse before consensus mutation"),
        };
        let table = engine.state.received_vote_evidence_table().unwrap();
        assert_eq!(table.occupied(), ReceivedVoteEvidenceTable::<[u8; 32]>::CAPACITY);
        assert_eq!(engine.current_view, current_view);
        assert_eq!(
            engine.state.has_vote_history_membership_for_test(
                ValidatorId(0),
                1024,
                &[0x73; 32]
            ),
            history_before
        );
        assert_eq!(engine.state.vote_count(1024, &[0x73; 32]), accumulator_before);
        assert_eq!(engine.state.dropped_votes(), dropped_before);
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap_before);
        assert_eq!(ledger.occupancy(), ledger_before);
        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(
            RECEIVED_VOTE_LOGICAL_INVOCATIONS.with(std::cell::Cell::get),
            invocation_count
        );
        assert!(table.entry_for(0, 0).is_some());

        engine
            .state
            .on_vote(ValidatorId(0), 1024, &[0x73; 32])
            .expect("actual accumulator view eviction releases prior evidence");
        assert_eq!(
            engine
                .state
                .received_vote_evidence_table()
                .unwrap()
                .occupied(),
            ReceivedVoteEvidenceTable::<[u8; 32]>::CAPACITY - 1
        );
        match engine.invoke_verified_received_vote(token) {
            VerifiedVoteInvocation::Invoked {
                evidence: ReceivedVoteEvidenceDisposition::Retained,
                ..
            } => {}
            _ => panic!("a retry after actual reclamation must be invoked and retained"),
        }
        assert_eq!(
            engine
                .state
                .received_vote_evidence_table()
                .unwrap()
                .occupied(),
            ReceivedVoteEvidenceTable::<[u8; 32]>::CAPACITY
        );
        assert_eq!(engine.state.max_retained_evidence_bytes(), cap_before);
    }

    #[test]
    fn received_vote_context_quota_refuses_and_recovers_through_engine_installation() {
        const CONTEXT_QUOTA: usize = 16;
        let (public_key, secret_key) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let (_, domain) = received_vote_context(0, public_key.clone());
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        let mut tokens = Vec::new();
        let mut observer = None;
        let mut context_charge = 0u64;
        let mut token_bytes = 0u64;
        let mut floor = 0u64;
        for epoch in 0..CONTEXT_QUOTA as u64 {
            let input = received_vote_context(epoch, public_key.clone()).0;
            if epoch == 0 {
                context_charge = input.checked_charge().unwrap();
                engine
                    .install_received_vote_context(input)
                    .expect("first context installs");
                observer = Some(
                    engine
                        .state
                        .received_vote_budget()
                        .unwrap()
                        .try_clone()
                        .unwrap(),
                );
                floor = EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0;
                token_bytes = std::mem::size_of::<VerifiedVoteToken>() as u64
                    + qbind_crypto::ML_DSA_44_SIGNATURE_SIZE as u64;
            } else {
                engine
                    .install_received_vote_context(input)
                    .expect("context installs while old token retains prior cell");
            }
            tokens.push(
                engine
                    .admit_verified_received_vote(
                        ValidatorId(0),
                        signed_context_vote(epoch, &secret_key, &domain),
                    )
                    .expect("signed vote is admitted"),
            );
            engine
                .transition_to_epoch(
                    crate::validator_set::EpochId::new(epoch + 1),
                    dense_validator_set(1),
                )
                .expect("epoch transition detaches context");
        }
        let observer = observer.expect("first context created observer");
        let table_charge = received_vote_table_charge();
        assert_eq!(
            observer.occupancy(),
            (
                floor
                    + table_charge
                    + CONTEXT_QUOTA as u64 * (context_charge + token_bytes),
                0,
                CONTEXT_QUOTA,
                0
            )
        );

        let input = received_vote_context(CONTEXT_QUOTA as u64, public_key).0;
        let roster_ptr = input.members().as_ptr();
        let roster_capacity = input.members_capacity();
        let key_ptr = input.members()[0].public_key().as_ptr();
        let key_capacity = input.members()[0].public_key_capacity();
        let contents = input.members().to_vec();
        let occupancy_before = observer.occupancy();
        let refusal = engine
            .install_received_vote_context(input)
            .expect_err("sixteenth retained context exhausts integrated context quota");
        assert_eq!(refusal.error, ContextInstallError::ContextQuota);
        assert!(refusal.input.members() == contents.as_slice(), "context input differs");
        assert_eq!(refusal.input.members().as_ptr(), roster_ptr);
        assert_eq!(refusal.input.members_capacity(), roster_capacity);
        assert_eq!(refusal.input.members()[0].public_key().as_ptr(), key_ptr);
        assert_eq!(
            refusal.input.members()[0].public_key_capacity(),
            key_capacity
        );
        assert_eq!(observer.occupancy(), occupancy_before);
        assert!(engine.active_received_vote_context.is_none());

        tokens.clear();
        assert_eq!(observer.occupancy(), (floor + table_charge, 0, 0, 0));
        engine
            .install_received_vote_context(refusal.input)
            .expect("context quota is released and installation retries");
        let wrapper_charge = std::mem::size_of::<Option<ActiveVoteContext>>() as u64;
        assert_eq!(
            observer.occupancy(),
            (floor + table_charge + context_charge + wrapper_charge, 0, 1, 0)
        );
    }

    #[test]
    fn received_vote_state_mut_invalidation_stays_terminal_after_state_replacement() {
        let (public_key, _) = MlDsa44Backend::generate_keypair().expect("test keygen");
        let input = received_vote_context(0, public_key).0;
        let context_charge = input.checked_charge().unwrap();
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), dense_validator_set(1));
        engine.install_received_vote_context(input).unwrap();
        let observer = engine
            .state
            .received_vote_budget()
            .unwrap()
            .try_clone()
            .unwrap();
        let floor = EvidenceBudget::try_new(u64::MAX, 0).unwrap().occupancy().0;
        let wrapper_charge = std::mem::size_of::<Option<ActiveVoteContext>>() as u64;
        let table_charge = received_vote_table_charge();
        assert_eq!(
            observer.occupancy(),
            (floor + context_charge + wrapper_charge + table_charge, 0, 1, 0)
        );
        let _ = engine.state_mut();
        assert_eq!(observer.occupancy(), (floor, 0, 0, 0));
        let refusal = engine
            .install_received_vote_context(
                received_vote_context(0, MlDsa44Backend::generate_keypair().unwrap().0).0,
            )
            .expect_err("state_mut permanently disables producer reinstallation");
        assert_eq!(refusal.error, ContextInstallError::InvalidContext);
        assert!(engine.state.received_vote_budget().is_some());

        let moved_state = std::mem::replace(
            &mut engine.state,
            HotStuffStateEngine::new(dense_validator_set(1)),
        );
        drop(moved_state);
        assert!(engine.state.received_vote_budget().is_none());
        let refusal = engine
            .install_received_vote_context(
                received_vote_context(0, MlDsa44Backend::generate_keypair().unwrap().0).0,
            )
            .expect_err("replacing state does not reset terminal producer disable");
        assert_eq!(refusal.error, ContextInstallError::InvalidContext);
        assert!(engine.state.received_vote_budget().is_none());
        assert_eq!(observer.occupancy(), (floor, 0, 0, 0));
    }

    #[test]
    fn leader_signer_buffer_transfers_exact_values_and_length_for_both_bounds() {
        let source = [ValidatorId(7), ValidatorId(2), ValidatorId(9)];
        let underfilled = LeaderSignerBuffer::copy_from(&source, 5)
            .expect("m less than N is supported")
            .into_vec();
        assert_eq!(underfilled.as_slice(), source);
        assert_eq!(underfilled.len(), 3);
        assert_eq!(underfilled.capacity(), 5);

        let exact = LeaderSignerBuffer::copy_from(&source, 3)
            .expect("m equal to N is supported")
            .into_vec();
        assert_eq!(exact.as_slice(), source);
        assert_eq!(exact.len(), 3);
        assert_eq!(exact.capacity(), 3);

        assert_eq!(
            LeaderSignerBuffer::copy_from(&source, 2).unwrap_err(),
            LeaderSignerBufferError::Bound
        );
        assert_eq!(
            LeaderSignerBuffer::copy_from(&source, 0).unwrap_err(),
            LeaderSignerBufferError::Bound
        );
    }

    #[test]
    fn leader_signer_buffer_null_injection_and_abandonment_have_exact_ownership() {
        LEADER_SIGNER_ALLOCATIONS.with(|count| count.set(0));
        LEADER_SIGNER_DEALLOCATIONS.with(|count| count.set(0));
        LEADER_SIGNER_TRANSFERS.with(|count| count.set(0));
        let source = [ValidatorId(4), ValidatorId(1)];

        LEADER_SIGNER_ALLOC_FAIL.with(|fail| fail.set(true));
        let null_result = LeaderSignerBuffer::copy_from(&source, 4);
        LEADER_SIGNER_ALLOC_FAIL.with(|fail| fail.set(false));
        assert!(matches!(
            null_result,
            Err(LeaderSignerBufferError::Allocation)
        ));
        LEADER_SIGNER_ALLOCATIONS.with(|count| assert_eq!(count.get(), 0));
        LEADER_SIGNER_DEALLOCATIONS.with(|count| assert_eq!(count.get(), 0));
        LEADER_SIGNER_TRANSFERS.with(|count| assert_eq!(count.get(), 0));

        let abandoned = LeaderSignerBuffer::copy_from(&source, 4)
            .expect("successful allocation");
        LEADER_SIGNER_ALLOCATIONS.with(|count| assert_eq!(count.get(), 1));
        drop(abandoned);
        LEADER_SIGNER_DEALLOCATIONS.with(|count| assert_eq!(count.get(), 1));
        LEADER_SIGNER_TRANSFERS.with(|count| assert_eq!(count.get(), 0));

        let transferred = LeaderSignerBuffer::copy_from(&source, 4)
            .expect("second successful allocation")
            .into_vec();
        assert_eq!(transferred.as_slice(), source);
        assert_eq!(transferred.capacity(), 4);
        LEADER_SIGNER_ALLOCATIONS.with(|count| assert_eq!(count.get(), 2));
        LEADER_SIGNER_DEALLOCATIONS.with(|count| assert_eq!(count.get(), 1));
        LEADER_SIGNER_TRANSFERS.with(|count| assert_eq!(count.get(), 1));
        drop(transferred);
    }

    #[test]
    fn leader_route_candidate_collision_does_not_replace_existing_node() {
        struct Gate {
            calls: usize,
        }
        impl LeaderProposalGate<()> for Gate {
            fn route_limits(&self) -> LeaderRouteLimits {
                LeaderRouteLimits::new(1)
            }
            fn capture_l0(
                &mut self,
                _input: &LeaderCaptureInput<'_>,
            ) -> Result<(), SafetyGateRefusal> {
                self.calls += 1;
                Ok(())
            }
        }

        let mut engine = BasicHotStuffEngine::new(ValidatorId(1), make_validator_set(1));
        let genesis = qbind_wire::consensus::BlockProposal {
            header: qbind_wire::consensus::BlockHeader {
                version: 1,
                chain_id: 1,
                epoch: 0,
                height: 0,
                round: 0,
                parent_block_id: [0xff; 32],
                payload_hash: [0; 32],
                proposer_index: 1,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 0,
                payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
                batch_commitment: [0; 32],
            },
            qc: None,
            txs: Vec::new(),
            signature: Vec::new(),
        };
        engine
            .on_proposal_event(ValidatorId(1), &genesis)
            .expect("genesis proposal accepted");
        engine.advance_view();
        let parent = engine.locked_qc().unwrap().block_id;
        let view = engine.current_view();
        let candidate = BasicHotStuffEngine::<[u8; 32]>::derive_block_id_from_header(
            engine.local_id,
            view,
            &parent,
        );
        let justification = engine.locked_qc().unwrap().clone();
        engine.state.register_block(
            candidate,
            view,
            Some(parent),
            Some(justification),
        );
        let before = engine.state.get_block(&candidate).unwrap();
        let before_view = before.view;
        let before_parent = before.parent_id;
        let count = engine.state.block_count();
        let mut gate = Gate { calls: 0 };

        assert!(matches!(
            engine.try_propose_gated_owning(&mut gate),
            LeaderProposalRouteResult::Refused(LeaderRouteRefusal::CandidateCollision)
        ));
        assert_eq!(gate.calls, 0);
        assert_eq!(engine.state.block_count(), count);
        let after = engine.state.get_block(&candidate).unwrap();
        assert_eq!(after.id, candidate);
        assert_eq!(after.view, before_view);
        assert_eq!(after.parent_id, before_parent);
    }

    #[test]
    fn leader_vote_history_marks_nonmember_defensively() {
        let engine = BasicHotStuffEngine::new(ValidatorId(1), make_validator_set(1));
        assert_eq!(
            engine
                .state
                .leader_vote_history_status(ValidatorId(99), 0, &[0; 32]),
            crate::hotstuff_state_engine::LeaderVoteHistoryStatus::NonMember
        );
    }

    #[test]
    fn leader_post_capture_cleanup_returns_only_reason_and_effects() {
        let mut effects = LeaderRouteEffects::initial();
        effects.candidate_registered = true;
        effects.vote_history_recorded = true;
        let failure = LeaderPostCaptureFailure {
            proposal: qbind_wire::consensus::BlockProposal {
                header: qbind_wire::consensus::BlockHeader {
                    version: 1,
                    chain_id: 1,
                    epoch: 0,
                    height: 1,
                    round: 1,
                    parent_block_id: [7; 32],
                    payload_hash: [0; 32],
                    proposer_index: 1,
                    suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                    tx_count: 0,
                    timestamp: 0,
                    payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                    next_epoch: 0,
                    batch_commitment: [0; 32],
                },
                qc: None,
                txs: Vec::new(),
                signature: Vec::new(),
            },
            vote: qbind_wire::consensus::Vote {
                version: 1,
                chain_id: 1,
                epoch: 0,
                height: 1,
                round: 1,
                step: 0,
                block_id: [8; 32],
                validator_index: 1,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                signature: Vec::new(),
            },
            payload: (),
            reason: LeaderRouteRefusal::VoteNotAccepted(LeaderVoteRefusal::Duplicate),
            effects,
        };

        let diagnostic = failure.into_diagnostic();
        assert_eq!(
            diagnostic.reason,
            LeaderRouteRefusal::VoteNotAccepted(LeaderVoteRefusal::Duplicate)
        );
        assert!(diagnostic.effects.candidate_registered);
        assert!(diagnostic.effects.vote_history_recorded);
    }

    #[test]
    fn basic_engine_leader_for_view_round_robin() {
        let validators = make_validator_set(3);
        let engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // Leaders are sorted: [1, 2, 3]
        // view 0 -> 0 % 3 = 0 -> leader[0] = 1
        assert_eq!(engine.leader_for_view(0), ValidatorId(1));
        // view 1 -> 1 % 3 = 1 -> leader[1] = 2
        assert_eq!(engine.leader_for_view(1), ValidatorId(2));
        // view 2 -> 2 % 3 = 2 -> leader[2] = 3
        assert_eq!(engine.leader_for_view(2), ValidatorId(3));
        // view 3 -> 3 % 3 = 0 -> leader[0] = 1
        assert_eq!(engine.leader_for_view(3), ValidatorId(1));
    }

    #[test]
    fn basic_engine_is_leader_for_current_view() {
        let validators = make_validator_set(3);

        // Node 1 at view 0: is leader
        let engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators.clone());
        assert!(engine.is_leader_for_current_view());

        // Node 2 at view 0: not leader
        let engine2: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(2), validators);
        assert!(!engine2.is_leader_for_current_view());
    }

    #[test]
    fn basic_engine_advance_view() {
        let validators = make_validator_set(2);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        assert_eq!(engine.current_view(), 0);
        engine.advance_view();
        assert_eq!(engine.current_view(), 1);
        engine.advance_view();
        assert_eq!(engine.current_view(), 2);
    }

    #[test]
    fn basic_engine_on_leader_step_produces_proposal() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // Single node is always leader
        let actions = engine.on_leader_step();
        assert!(!actions.is_empty());

        // First action should be BroadcastProposal
        if let ConsensusEngineAction::BroadcastProposal(proposal) = &actions[0] {
            assert_eq!(proposal.header.height, 0);
            assert_eq!(proposal.header.proposer_index, 1);
        } else {
            panic!("Expected BroadcastProposal action");
        }

        // Second action should be BroadcastVote (leader's own vote)
        assert!(actions.len() >= 2);
        assert!(matches!(
            &actions[1],
            ConsensusEngineAction::BroadcastVote(_)
        ));

        // With a single node, QC forms immediately, view advances to 1
        // So the second call produces another proposal (for view 1)
        // This is correct behavior with optimistic view advancement
        let actions2 = engine.on_leader_step();
        assert!(!actions2.is_empty());

        if let ConsensusEngineAction::BroadcastProposal(proposal2) = &actions2[0] {
            assert_eq!(proposal2.header.height, 1);
        } else {
            panic!("Expected BroadcastProposal action for view 1");
        }
    }

    #[test]
    fn basic_engine_non_leader_does_not_propose() {
        let validators = make_validator_set(3);
        // Node 2 is not leader at view 0
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(2), validators);

        let actions = engine.on_leader_step();
        assert!(actions.is_empty());
    }

    // ========================================================================
    // View duration metrics tests (T90.5)
    // ========================================================================

    use std::sync::atomic::{AtomicU64, Ordering};

    /// A simple test recorder that captures view duration calls.
    #[derive(Debug, Default)]
    struct TestViewDurationRecorder {
        call_count: AtomicU64,
        total_from_view: AtomicU64,
        total_to_view: AtomicU64,
        // Note: We can't easily capture Duration in atomics, so we just count calls
    }

    impl ViewDurationRecorder for TestViewDurationRecorder {
        fn record_view_duration(&self, _duration: Duration, from_view: u64, to_view: u64) {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            self.total_from_view.fetch_add(from_view, Ordering::Relaxed);
            self.total_to_view.fetch_add(to_view, Ordering::Relaxed);
        }
    }

    impl TestViewDurationRecorder {
        fn call_count(&self) -> u64 {
            self.call_count.load(Ordering::Relaxed)
        }

        fn last_from_view(&self) -> u64 {
            self.total_from_view.load(Ordering::Relaxed)
        }

        fn last_to_view(&self) -> u64 {
            self.total_to_view.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn engine_without_recorder_does_not_panic_on_advance_view() {
        let validators = make_validator_set(2);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // Should not panic even without a recorder
        engine.advance_view();
        engine.advance_view();
        assert_eq!(engine.current_view(), 2);
    }

    #[test]
    fn engine_with_recorder_calls_on_advance_view() {
        let validators = make_validator_set(2);
        let recorder = Arc::new(TestViewDurationRecorder::default());

        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators)
                .with_view_duration_recorder(recorder.clone());

        // First advance: from view 0 to view 1
        engine.advance_view();
        assert_eq!(recorder.call_count(), 1);
        assert_eq!(recorder.last_from_view(), 0);
        assert_eq!(recorder.last_to_view(), 1);

        // Second advance: from view 1 to view 2 (totals are cumulative)
        engine.advance_view();
        assert_eq!(recorder.call_count(), 2);
        assert_eq!(recorder.last_from_view(), 1); // 0 + 1
        assert_eq!(recorder.last_to_view(), 3); // 1 + 2
    }

    #[test]
    fn engine_set_view_records_duration_when_changing() {
        let validators = make_validator_set(2);
        let recorder = Arc::new(TestViewDurationRecorder::default());

        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators)
                .with_view_duration_recorder(recorder.clone());

        // set_view to a different view should record
        engine.set_view(5);
        assert_eq!(recorder.call_count(), 1);
        assert_eq!(recorder.last_from_view(), 0);
        assert_eq!(recorder.last_to_view(), 5);

        // set_view to the same view should NOT record
        engine.set_view(5);
        assert_eq!(recorder.call_count(), 1); // Still 1
    }

    #[test]
    fn engine_set_recorder_after_construction() {
        let validators = make_validator_set(2);
        let recorder = Arc::new(TestViewDurationRecorder::default());

        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // No recorder yet, advance view
        engine.advance_view();
        assert_eq!(recorder.call_count(), 0);

        // Now set the recorder
        engine.set_view_duration_recorder(recorder.clone());

        // Further advances should be recorded
        engine.advance_view();
        assert_eq!(recorder.call_count(), 1);
    }

    #[test]
    fn noop_recorder_is_debug() {
        let recorder = NoopViewDurationRecorder;
        // Just ensure it implements Debug
        let _ = format!("{:?}", recorder);
    }

    #[test]
    fn engine_initialize_from_restart_sets_timestamp() {
        let validators = make_validator_set(2);
        let recorder = Arc::new(TestViewDurationRecorder::default());

        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators)
                .with_view_duration_recorder(recorder.clone());

        // Initialize from restart at height 10
        engine.initialize_from_restart([0u8; 32], 10, None);

        // View should be 11 (10 + 1)
        assert_eq!(engine.current_view(), 11);

        // initialize_from_restart should NOT record (it's setting up, not completing a view)
        // Actually, looking at our implementation, it doesn't record because we don't track
        // the old view. Let's verify:
        assert_eq!(recorder.call_count(), 0);

        // But advancing from this point SHOULD record
        engine.advance_view();
        assert_eq!(recorder.call_count(), 1);
        assert_eq!(recorder.last_from_view(), 11);
        assert_eq!(recorder.last_to_view(), 12);
    }

    // ========================================================================
    // B5: restore-aware consensus start (initialize_from_snapshot_baseline)
    // ========================================================================

    /// B5: After `initialize_from_snapshot_baseline(H)`:
    /// - committed_height == Some(H)
    /// - current_view == H + 1
    /// - committed block id is what we passed in
    #[test]
    fn b5_initialize_from_snapshot_baseline_seeds_state() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // Sanity: fresh engine has no commits and view 0.
        assert_eq!(engine.committed_height(), None);
        assert_eq!(engine.current_view(), 0);

        let snapshot_block_id: [u8; 32] = [0xAB; 32];
        let snapshot_height: u64 = 42;

        engine.initialize_from_snapshot_baseline(snapshot_block_id, snapshot_height);

        assert_eq!(engine.committed_height(), Some(snapshot_height));
        assert_eq!(engine.current_view(), snapshot_height + 1);
        assert_eq!(engine.commit_log().len(), 0); // we did not fabricate a commit log entry
    }

    /// B5: With a baseline applied, single-validator self-quorum produces
    /// commits whose heights are strictly above the snapshot height — i.e.
    /// the engine resumes above the restored prefix rather than from zero.
    #[test]
    fn b5_post_baseline_commits_advance_above_snapshot_height() {
        let validators = make_validator_set(1);
        // make_validator_set numbers from 1, so the only validator id is 1.
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        let snapshot_height: u64 = 100;
        let snapshot_block_id: [u8; 32] = [0x42; 32];
        engine.initialize_from_snapshot_baseline(snapshot_block_id, snapshot_height);

        // Drive the engine for enough ticks that the 3-chain commit rule
        // is satisfied (B → P → G with own_qc on each ancestor, all above
        // the synthetic baseline anchor). 10 leader steps is comfortably
        // more than enough.
        for _ in 0..10 {
            let _ = engine.on_leader_step();
        }

        // committed_height must be strictly greater than snapshot_height.
        let ch = engine
            .committed_height()
            .expect("expected at least one commit after baseline + 10 ticks");
        assert!(
            ch > snapshot_height,
            "committed_height ({}) must advance above snapshot_height ({}) after restore",
            ch,
            snapshot_height
        );

        // Every committed entry past the baseline must record a height
        // strictly above the snapshot height.
        for entry in engine.commit_log() {
            assert!(
                entry.height > snapshot_height,
                "commit_log entry has height {} <= snapshot_height {} — \
                 baseline did not seed the height monotonicity floor",
                entry.height,
                snapshot_height
            );
        }
    }

    /// B5: A no-baseline engine (existing behavior) still starts from view 0
    /// with no committed prefix — the new hook must not regress the
    /// non-restore startup path.
    #[test]
    fn b5_no_baseline_path_unchanged() {
        let validators = make_validator_set(1);
        let engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        assert_eq!(engine.committed_height(), None);
        assert_eq!(engine.current_view(), 0);
    }

    fn make_zero_based_validator_set(num: u64) -> ConsensusValidatorSet {
        let entries: Vec<ValidatorSetEntry> = (0..num)
            .map(|i| ValidatorSetEntry {
                id: ValidatorId(i),
                voting_power: 1,
            })
            .collect();
        ConsensusValidatorSet::new(entries).expect("valid set")
    }

    fn catchup_block_for(
        engine: &BasicHotStuffEngine<[u8; 32]>,
        height: u64,
        parent: [u8; 32],
    ) -> RestoreCatchupBlock<[u8; 32]> {
        let proposer = engine.leader_for_view(height);
        let block_id = BasicHotStuffEngine::<[u8; 32]>::derive_block_id_from_header(
            proposer, height, &parent,
        );
        RestoreCatchupBlock {
            height,
            view: height,
            parent_block_id: parent,
            block_id,
            proposer,
            qc_signers: vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
        }
    }

    #[test]
    fn restore_catchup_applies_valid_peer_learned_suffix_above_snapshot() {
        let validators = make_zero_based_validator_set(3);
        let mut engine = BasicHotStuffEngine::new(ValidatorId(2), validators);
        let snapshot_id = [0x44; 32];
        let snapshot_height = 10;
        engine.initialize_from_snapshot_baseline(snapshot_id, snapshot_height);

        let b11 = catchup_block_for(&engine, 11, snapshot_id);
        let b12 = catchup_block_for(&engine, 12, b11.block_id);
        let b13 = catchup_block_for(&engine, 13, b12.block_id);
        let b14 = catchup_block_for(&engine, 14, b13.block_id);

        let applied = engine
            .apply_restore_catchup_blocks(&[b11, b12, b13, b14])
            .expect("valid catchup suffix applies");

        assert_eq!(applied, 4);
        assert!(
            engine.committed_height().unwrap() > snapshot_height,
            "catchup must advance committed height above restored prefix"
        );
        assert!(engine.commit_log().iter().all(|e| e.height > snapshot_height));
    }

    #[test]
    fn restore_catchup_rejects_malformed_parent_fail_closed() {
        let validators = make_zero_based_validator_set(3);
        let mut engine = BasicHotStuffEngine::new(ValidatorId(2), validators);
        let snapshot_id = [0x55; 32];
        let snapshot_height = 7;
        engine.initialize_from_snapshot_baseline(snapshot_id, snapshot_height);

        let mut bad = catchup_block_for(&engine, 8, snapshot_id);
        bad.parent_block_id = [0x99; 32];

        let err = engine
            .apply_restore_catchup_blocks(&[bad])
            .expect_err("bad parent must be rejected");
        assert!(matches!(
            err,
            RestoreCatchupError::AnchorMismatch { .. }
        ));
        assert_eq!(engine.committed_height(), Some(snapshot_height));
        assert!(engine.commit_log().is_empty());
    }

    #[test]
    fn restore_baseline_does_not_fabricate_post_snapshot_history() {
        let validators = make_zero_based_validator_set(3);
        let mut engine = BasicHotStuffEngine::new(ValidatorId(0), validators);
        engine.initialize_from_snapshot_baseline([0x66; 32], 5);

        assert_eq!(engine.committed_height(), Some(5));
        assert_eq!(engine.current_view(), 6);
        assert!(
            engine.commit_log().is_empty(),
            "snapshot baseline must not invent post-snapshot commit log"
        );
        assert_eq!(
            engine.export_restore_catchup_blocks(5, [0x66; 32], 128),
            Vec::new(),
            "freshly restored engine has no certified peer-learned suffix to export"
        );
    }

    // ========================================================================
    // Run 096 — pending reconfig proposal intent tests.
    // ========================================================================

    /// Fresh engine has no pending reconfig intent.
    #[test]
    fn run_096_fresh_engine_has_no_pending_reconfig() {
        let validators = make_validator_set(1);
        let engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);
        assert_eq!(engine.pending_reconfig_next_epoch(), None);
    }

    /// `set_pending_reconfig_next_epoch(0)` fails closed.
    #[test]
    fn run_096_set_pending_reconfig_rejects_zero() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);
        let err = engine
            .set_pending_reconfig_next_epoch(0)
            .expect_err("zero target_epoch must fail closed");
        assert!(matches!(err, PendingReconfigIntentError::TargetEpochZero));
        assert_eq!(engine.pending_reconfig_next_epoch(), None);
    }

    /// `set_pending_reconfig_next_epoch(current_epoch)` fails closed
    /// — equal target is regressive.
    #[test]
    fn run_096_set_pending_reconfig_rejects_equal_to_current() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);
        engine.set_current_epoch(3);
        let err = engine
            .set_pending_reconfig_next_epoch(3)
            .expect_err("equal target_epoch must fail closed");
        match err {
            PendingReconfigIntentError::NonMonotonicTarget {
                current_epoch,
                target_epoch,
            } => {
                assert_eq!(current_epoch, 3);
                assert_eq!(target_epoch, 3);
            }
            other => panic!("expected NonMonotonicTarget, got {:?}", other),
        }
        assert_eq!(engine.pending_reconfig_next_epoch(), None);
    }

    /// `set_pending_reconfig_next_epoch(target < current_epoch)` fails
    /// closed (regression).
    #[test]
    fn run_096_set_pending_reconfig_rejects_regression() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);
        engine.set_current_epoch(5);
        let err = engine
            .set_pending_reconfig_next_epoch(2)
            .expect_err("regressive target_epoch must fail closed");
        assert!(matches!(
            err,
            PendingReconfigIntentError::NonMonotonicTarget { .. }
        ));
        assert_eq!(engine.pending_reconfig_next_epoch(), None);
    }

    /// `set_pending_reconfig_next_epoch(current+1)` succeeds and arms
    /// the intent.
    #[test]
    fn run_096_set_pending_reconfig_accepts_sequential_target() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);
        engine
            .set_pending_reconfig_next_epoch(1)
            .expect("target=1 > current=0 is valid");
        assert_eq!(engine.pending_reconfig_next_epoch(), Some(1));
    }

    /// `clear_pending_reconfig_next_epoch` clears the intent without
    /// emitting a proposal.
    #[test]
    fn run_096_clear_pending_reconfig() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);
        engine.set_pending_reconfig_next_epoch(7).unwrap();
        assert_eq!(engine.pending_reconfig_next_epoch(), Some(7));
        engine.clear_pending_reconfig_next_epoch();
        assert_eq!(engine.pending_reconfig_next_epoch(), None);
    }

    /// No reconfig intent → leader proposal is exactly the same
    /// canonical normal block as before Run 096.
    #[test]
    fn run_096_no_intent_emits_normal_proposal_unchanged() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);
        let actions = engine.on_leader_step();
        assert!(!actions.is_empty());
        if let ConsensusEngineAction::BroadcastProposal(proposal) = &actions[0] {
            assert_eq!(
                proposal.header.payload_kind,
                qbind_wire::PAYLOAD_KIND_NORMAL
            );
            assert_eq!(proposal.header.next_epoch, 0);
        } else {
            panic!("expected BroadcastProposal");
        }
    }

    /// Armed reconfig intent → leader emits a canonical
    /// `PAYLOAD_KIND_RECONFIG` block carrying the exact requested
    /// `next_epoch`. The proposal otherwise uses the same block-id
    /// derivation, signing path, and HotStuff structures — no parallel
    /// wire format.
    #[test]
    fn run_096_armed_intent_emits_canonical_reconfig_proposal() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);
        engine.set_pending_reconfig_next_epoch(1).unwrap();

        let actions = engine.on_leader_step();
        assert!(!actions.is_empty());
        if let ConsensusEngineAction::BroadcastProposal(proposal) = &actions[0] {
            assert_eq!(
                proposal.header.payload_kind,
                qbind_wire::PAYLOAD_KIND_RECONFIG
            );
            assert_eq!(proposal.header.next_epoch, 1);
            // Canonical block-id derivation must be unchanged — the
            // header still carries the same proposer / view / parent.
            assert_eq!(proposal.header.proposer_index, 1);
            assert_eq!(proposal.header.height, 0);
        } else {
            panic!("expected BroadcastProposal");
        }
        // Single-shot: intent must be cleared after one emission.
        assert_eq!(engine.pending_reconfig_next_epoch(), None);
    }

    /// One-shot behaviour: after consuming the intent once, subsequent
    /// leader-step calls emit normal proposals again (no spam).
    #[test]
    fn run_096_intent_is_one_shot() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);
        engine.set_pending_reconfig_next_epoch(1).unwrap();

        // First call consumes the intent and emits reconfig.
        let actions1 = engine.on_leader_step();
        match &actions1[0] {
            ConsensusEngineAction::BroadcastProposal(p) => {
                assert_eq!(p.header.payload_kind, qbind_wire::PAYLOAD_KIND_RECONFIG);
                assert_eq!(p.header.next_epoch, 1);
            }
            _ => panic!("expected BroadcastProposal"),
        }

        // After the single-validator self-QC commits view 0 and advances
        // to view 1, the next leader step emits a normal block again.
        let actions2 = engine.on_leader_step();
        match &actions2[0] {
            ConsensusEngineAction::BroadcastProposal(p) => {
                assert_eq!(p.header.payload_kind, qbind_wire::PAYLOAD_KIND_NORMAL);
                assert_eq!(p.header.next_epoch, 0);
            }
            _ => panic!("expected BroadcastProposal"),
        }
    }

    /// A stale intent (engine advanced past target by some other path
    /// between arm and consume) is dropped silently and a normal
    /// proposal is emitted — never a synthetic / regressive reconfig.
    #[test]
    fn run_096_stale_intent_emits_normal_proposal() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);
        // Arm intent target=2 while current=0 (valid at set time).
        engine.set_pending_reconfig_next_epoch(2).unwrap();
        // Then simulate engine advancing past the target via another
        // path (e.g. snapshot-driven epoch state seed). This is not a
        // path Run 096 itself activates; the check is purely defensive.
        engine.set_current_epoch(5);

        let actions = engine.on_leader_step();
        match &actions[0] {
            ConsensusEngineAction::BroadcastProposal(p) => {
                assert_eq!(p.header.payload_kind, qbind_wire::PAYLOAD_KIND_NORMAL);
                assert_eq!(p.header.next_epoch, 0);
            }
            _ => panic!("expected BroadcastProposal"),
        }
        // Intent must be cleared regardless (single-shot).
        assert_eq!(engine.pending_reconfig_next_epoch(), None);
    }

    /// A non-leader with an armed intent does NOT produce any proposal
    /// and the intent remains armed for when leadership rotates back.
    #[test]
    fn run_096_non_leader_does_not_consume_intent() {
        let validators = make_validator_set(3);
        // Node 2 is not leader at view 0 (leaders = [1, 2, 3], view 0
        // -> leader 1).
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(2), validators);
        engine.set_pending_reconfig_next_epoch(1).unwrap();

        let actions = engine.on_leader_step();
        assert!(actions.is_empty());
        // Intent must remain armed.
        assert_eq!(engine.pending_reconfig_next_epoch(), Some(1));
    }

    /// `Display` for `PendingReconfigIntentError` mentions fail-closed
    /// semantics so the operator log line is searchable.
    #[test]
    fn run_096_intent_error_display_mentions_fail_closed() {
        let err = PendingReconfigIntentError::TargetEpochZero;
        let s = format!("{}", err);
        assert!(s.contains("fail closed"));
        let err2 = PendingReconfigIntentError::NonMonotonicTarget {
            current_epoch: 3,
            target_epoch: 2,
        };
        let s2 = format!("{}", err2);
        assert!(s2.contains("fail closed"));
        assert!(s2.contains("target_epoch=2"));
        assert!(s2.contains("current_epoch=3"));
    }

    // =======================================================================
    // Run 422 §13.6 — CONSTRUCTED-FIXTURE coverage for
    // `SafetyDecisionView::ancestry_relation_to_lock`.
    //
    // These are hand-registered block graphs with a directly set lock, built to
    // exercise shapes the natural engine control flow does NOT produce
    // (candidate-is-lock at zero hops, a deep multi-hop chain under a pinned
    // older lock, and bounded termination on a cyclic parent graph). They are
    // CONSTRUCTED fixtures, not executed engine voting decisions: the `branch`
    // field is populated only to form the struct; `ancestry_relation_to_lock`
    // never reads it. (Executed-decision coverage lives in the integration test
    // `tests/run_422_decision_view_queries_tests.rs`.)
    // =======================================================================

    /// Build a decision view over borrowed, hand-registered engine state. This
    /// bypasses the voting predicate entirely; it is a fixture, not a decision.
    fn fixture_view<'e>(
        state: &'e HotStuffStateEngine<[u8; 32]>,
        candidate: &'e BlockNode<[u8; 32]>,
        locked: Option<&'e QuorumCertificate<[u8; 32]>>,
    ) -> SafetyDecisionView<'e, [u8; 32]> {
        SafetyDecisionView {
            state,
            candidate,
            locked,
            branch: SafetyBranch::ViewSufficiency,
            origin_view: candidate.view,
            from: ValidatorId(1),
            verified_entrypoint: false,
        }
    }

    #[test]
    fn fixture_candidate_is_lock_at_zero_hops() {
        let mut engine = HotStuffStateEngine::<[u8; 32]>::new(make_validator_set(1));
        let lock_id = [0x0A; 32];
        engine.register_block(lock_id, 0, None, None);
        engine.set_locked_qc(QuorumCertificate::new(lock_id, 0, vec![]));

        let candidate = engine.get_block(&lock_id).expect("registered").clone();
        let locked = QuorumCertificate::new(lock_id, 0, vec![]);
        let view = fixture_view(&engine, &candidate, Some(&locked));

        // The candidate itself IS the lock: detected before traversing any edge,
        // even when max_hops == 0.
        assert_eq!(
            view.ancestry_relation_to_lock(0),
            AncestryRelation::CandidateIsLock
        );
        assert_eq!(
            view.ancestry_relation_to_lock(5),
            AncestryRelation::CandidateIsLock
        );
    }

    #[test]
    fn fixture_multi_hop_exact_bound_and_one_short() {
        let mut engine = HotStuffStateEngine::<[u8; 32]>::new(make_validator_set(1));
        let b0 = [0x00; 32]; // lock (pinned, older)
        let b1 = [0x01; 32];
        let b2 = [0x02; 32]; // candidate, two hops from the lock
        engine.register_block(b0, 0, None, None);
        engine.register_block(b1, 1, Some(b0), None);
        engine.register_block(b2, 2, Some(b1), None);
        engine.set_locked_qc(QuorumCertificate::new(b0, 0, vec![]));

        let candidate = engine.get_block(&b2).expect("registered").clone();
        let locked = QuorumCertificate::new(b0, 0, vec![]);
        let view = fixture_view(&engine, &candidate, Some(&locked));

        // Zero bound: candidate != lock, no hop permitted => exhausted.
        assert_eq!(
            view.ancestry_relation_to_lock(0),
            AncestryRelation::BoundExhausted
        );
        // One hop short of the two-hop lock => exhausted (not proved ancestry).
        assert_eq!(
            view.ancestry_relation_to_lock(1),
            AncestryRelation::BoundExhausted
        );
        // Exact bound reaches the lock on the second parent transition.
        assert_eq!(
            view.ancestry_relation_to_lock(2),
            AncestryRelation::ReachedLock { hops: 2 }
        );
        // A larger bound still reports the exact hop count where it was reached.
        assert_eq!(
            view.ancestry_relation_to_lock(9),
            AncestryRelation::ReachedLock { hops: 2 }
        );
    }

    #[test]
    fn fixture_cyclic_parent_graph_terminates_bounded() {
        let mut engine = HotStuffStateEngine::<[u8; 32]>::new(make_validator_set(1));
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        let z = [0xCC; 32]; // the lock: never on the a<->b cycle
                            // a -> b (b not yet present: height 0)
        engine.register_block(a, 1, Some(b), None);
        // b -> a (closes the cycle)
        engine.register_block(b, 2, Some(a), None);
        engine.set_locked_qc(QuorumCertificate::new(z, 0, vec![]));

        let candidate = engine.get_block(&a).expect("registered").clone();
        let locked = QuorumCertificate::new(z, 0, vec![]);
        let view = fixture_view(&engine, &candidate, Some(&locked));

        // The lock is unreachable and the parent graph is a cycle: the walk is
        // bounded by max_hops and reports exhaustion rather than looping.
        assert_eq!(
            view.ancestry_relation_to_lock(10),
            AncestryRelation::BoundExhausted
        );
        assert_eq!(
            view.ancestry_relation_to_lock(1000),
            AncestryRelation::BoundExhausted
        );
    }

    #[test]
    fn fixture_no_lock_reports_no_lock() {
        let mut engine = HotStuffStateEngine::<[u8; 32]>::new(make_validator_set(1));
        let only = [0x07; 32];
        engine.register_block(only, 0, None, None);
        // No lock set.
        let candidate = engine.get_block(&only).expect("registered").clone();
        let view = fixture_view(&engine, &candidate, None);
        assert_eq!(view.ancestry_relation_to_lock(0), AncestryRelation::NoLock);
        assert_eq!(view.ancestry_relation_to_lock(5), AncestryRelation::NoLock);
    }
}