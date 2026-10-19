//! RUN 422 — Isolated Fresh-Vote Protected-Use Model (TEST-ONLY, NOT wired).
//!
//! This module is a bounded, `#[cfg(test)]`-gated MODEL of the production
//! outbound Vote signing path (`binary_consensus_loop::prepare_vote_signing_
//! reservation` + `complete_vote_signing`). It is a child module of `owner`, so
//! it can observe the parent-private `SafetyRecordOwner::backend` field and the
//! private held-guard helpers (`load_current_validated_locked`,
//! `pin_provenance_locked`, `authoritative_revision_locked`,
//! `observe_checks_locked`, `pinned`). It mirrors — it does NOT execute — the
//! production signing function: the bounded signer is a fixture, the recording
//! sink copies only fixed scalars, and nothing is wired into any production
//! caller. The model establishes no signing permission, freshness, or
//! retained-result-reuse authorization.
//!
//! The production `ValidatorSigner` returns an unbounded `Vec<u8>` signature;
//! this model substitutes a bounded, allocation-free `BoundedVoteSigner` writing
//! into a caller-owned fixed array so the length-validation and
//! no-retain/no-copy guarantees are demonstrable in a `Copy`-only surface.

use sha3::Sha3_256;

use qbind_wire::consensus::Vote;

use crate::binary_consensus_loop::{AuthorizedProposalVoteSnapshot, ProposalVoteAuthority};
use crate::signing_reservation_journal::{
    BindingDigest, DecisionBindingInput, ReservationOutcome, ResultPublicationCapability,
    SigningContinuation, SigningKind, SigningPosition, SigningReservationJournal,
};

use super::super::decision_capture::{
    OwningCapturePayload, PreparedDecisionInputLimits, RetainedDecisionObservation,
};
use super::super::prepared::{GenerationIdentity, PreparedProvenance};
use super::super::record::ValidatedRecord;
use super::super::validate::CommittedHistory;
use super::SafetyRecordOwner;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::BoundedSafetyOutcome;
use qbind_crypto::ConsensusSigSuiteId;

// ===========================================================================
// Bounded-model constants.
// ===========================================================================

/// The fixed signature-output capacity the model's bounded signer may write
/// into. The caller owns the `[u8; MODEL_SIG_CAP]` array; the signer only
/// borrows a mutable slice of it and reports a written length.
const MODEL_SIG_CAP: usize = 128;

/// MODEL mirror of the production `LOCAL_PROPOSAL_VOTE_WIRE_MESSAGE_VERSION`
/// (`binary_consensus_loop.rs`, a private `const = 1`). It is not reachable from
/// this module, so the literal is duplicated with this comment (the model never
/// rewrites the field, only compares it).
const MODEL_WIRE_MESSAGE_VERSION: u8 = 1;

/// MODEL mirror of the production `D6_SIGNING_FORMAT_VERSION`
/// (`binary_consensus_loop.rs`, a private `const = 2`). Duplicated literal with
/// this comment; not reachable from this module. Distinct from the wire-message
/// version above.
const MODEL_D6_SIGNING_FORMAT_VERSION: u8 = 2;

/// Conservative upper bound on the v2 Vote preimage length used for the signing
/// working-set reservation (the reservation precedes construction, so a measured
/// capacity cannot be read first). The tests assert the real preimage length is
/// within this bound.
const MODEL_MAX_PREIMAGE_BYTES: u128 = 256;

// ===========================================================================
// Bounded fixture signer (allocation-free).
// ===========================================================================

/// Why a bounded fixture signer refused. A fixed-size, `Copy` enum — never an
/// owned `String` — so an outcome can forward only a bounded code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ModelSignError {
    /// The signing backend refused (fixture fault).
    Backend,
    /// The signing key / identity was unavailable (fixture fault). Part of the
    /// fixed-size code set even when a given fixture does not emit it.
    #[allow(dead_code)]
    Unavailable,
}

/// A bounded, allocation-free vote signer: it writes at most `out.len()` bytes
/// into the caller-owned `out` and returns the written length. It never
/// allocates and never retains the preimage or the output.
pub(crate) trait BoundedVoteSigner {
    fn validator_id(&self) -> u64;
    fn suite_id(&self) -> u16;
    /// Write `<= out.len()` bytes into `out`; return the written length.
    fn sign_vote_into(&self, preimage: &[u8], out: &mut [u8]) -> Result<usize, ModelSignError>;
}

/// The OK fixture signer: writes a small deterministic 8-byte tag derived from
/// the preimage length into the caller's buffer.
pub(crate) struct OkFixtureSigner {
    pub(crate) validator_id: u64,
    pub(crate) suite_id: u16,
}

impl BoundedVoteSigner for OkFixtureSigner {
    fn validator_id(&self) -> u64 {
        self.validator_id
    }
    fn suite_id(&self) -> u16 {
        self.suite_id
    }
    fn sign_vote_into(&self, preimage: &[u8], out: &mut [u8]) -> Result<usize, ModelSignError> {
        let tag = (preimage.len() as u64).to_le_bytes();
        let n = tag.len().min(out.len());
        out[..n].copy_from_slice(&tag[..n]);
        Ok(n)
    }
}

/// Fault signer: reports an empty (zero-length) signature.
pub(crate) struct EmptyFixtureSigner {
    pub(crate) validator_id: u64,
    pub(crate) suite_id: u16,
}
impl BoundedVoteSigner for EmptyFixtureSigner {
    fn validator_id(&self) -> u64 {
        self.validator_id
    }
    fn suite_id(&self) -> u16 {
        self.suite_id
    }
    fn sign_vote_into(&self, _preimage: &[u8], _out: &mut [u8]) -> Result<usize, ModelSignError> {
        Ok(0)
    }
}

/// Fault signer: claims a written length greater than `MODEL_SIG_CAP` WITHOUT
/// actually writing that many bytes, to exercise the caller's length
/// validation. It never writes beyond `out.len()`.
pub(crate) struct OversizeFixtureSigner {
    pub(crate) validator_id: u64,
    pub(crate) suite_id: u16,
}
impl BoundedVoteSigner for OversizeFixtureSigner {
    fn validator_id(&self) -> u64 {
        self.validator_id
    }
    fn suite_id(&self) -> u16 {
        self.suite_id
    }
    fn sign_vote_into(&self, _preimage: &[u8], out: &mut [u8]) -> Result<usize, ModelSignError> {
        // Write a couple of bytes (bounded by out.len()) but CLAIM an
        // out-of-bound length. The caller must reject on the claimed length
        // before slicing.
        let w = 2.min(out.len());
        for b in out[..w].iter_mut() {
            *b = 0xAB;
        }
        Ok(MODEL_SIG_CAP + 1)
    }
}

/// Fault signer: returns an error.
pub(crate) struct ErrorFixtureSigner {
    pub(crate) validator_id: u64,
    pub(crate) suite_id: u16,
}
impl BoundedVoteSigner for ErrorFixtureSigner {
    fn validator_id(&self) -> u64 {
        self.validator_id
    }
    fn suite_id(&self) -> u16 {
        self.suite_id
    }
    fn sign_vote_into(&self, _preimage: &[u8], _out: &mut [u8]) -> Result<usize, ModelSignError> {
        Err(ModelSignError::Backend)
    }
}

// ===========================================================================
// Concrete recording sink (fixed-size scalars only; never retains the sig).
// ===========================================================================

/// The fixed-size, `Copy` diagnostic the sink produces. It copies ONLY scalar
/// fields out of the Vote plus the signature/preimage LENGTHS — never the
/// signature bytes, never an owned Vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ModelSignDiag {
    pub(crate) validator_index: u64,
    pub(crate) height: u64,
    pub(crate) round: u64,
    pub(crate) step: u8,
    pub(crate) suite_id: u16,
    pub(crate) sig_len: u32,
    pub(crate) preimage_len: u32,
}

/// The concrete recording sink: no callback, no Vote return, no signature
/// copy/retain. It records only the fixed scalar diagnostic and a call count.
pub(crate) struct ModelRecordingSink {
    pub(crate) last: Option<ModelSignDiag>,
    pub(crate) calls: u32,
}

impl ModelRecordingSink {
    pub(crate) fn new() -> Self {
        Self {
            last: None,
            calls: 0,
        }
    }

    /// Copy only fixed scalars out of `vote` plus the signature length; never
    /// clone or retain `sig`.
    pub(crate) fn record(&mut self, vote: &Vote, sig: &[u8]) -> ModelSignDiag {
        let diag = ModelSignDiag {
            validator_index: vote.validator_index as u64,
            height: vote.height,
            round: vote.round,
            step: vote.step,
            suite_id: vote.suite_id,
            sig_len: sig.len() as u32,
            preimage_len: 0,
        };
        self.calls = self.calls.saturating_add(1);
        self.last = Some(diag);
        diag
    }
}

// ===========================================================================
// Typed outcome (fixed-size; never forwards an owned String).
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ModelFreshUseOutcome {
    Signed(ModelSignDiag),
    PolicyRefused,
    AuthorizationAdmitRefused,
    ObservationRefused,
    LifecycleAmbiguous,
    ReserveConflict,
    ReservePotentiallySigned,
    ReserveExhausted,
    RetainedBlocked,
    JournalFailed,
    AuthorizationConfirmRefused,
    SignerFailed,
    EmptyWritten,
    OversizeWritten,
    PersistFailed,
}

// ===========================================================================
// Post-consume / pre-sign coordination hook (bounded, completed).
// ===========================================================================

/// A fixed, bounded coordination point invoked AFTER the D10 reservation is
/// consumed and BEFORE the signer is invoked. It models a publication-exclusion
/// at this position: while the live operation holds the consumed reservation, an
/// eligible concurrent publication for the SAME position is excluded. It is
/// COMPLETED/bounded (one journal probe, no indefinite hold); after it returns
/// the model proceeds, and after the guard releases an eligible publication may
/// proceed later.
pub(crate) struct ModelCoordinationHook<'j> {
    probe_journal: Option<&'j SigningReservationJournal>,
    pub(crate) calls: u32,
    pub(crate) last_excluded: Option<bool>,
}

impl<'j> ModelCoordinationHook<'j> {
    /// An inert hook (no concurrent-publication probe); still records that the
    /// coordination point was reached.
    pub(crate) fn inert() -> Self {
        Self {
            probe_journal: None,
            calls: 0,
            last_excluded: None,
        }
    }

    /// A probing hook: at the coordination point, attempt a reservation at the
    /// SAME position/binding to demonstrate exclusion of a concurrent
    /// publication. It is bounded (a single attempt) and completed.
    pub(crate) fn probing(journal: &'j SigningReservationJournal) -> Self {
        Self {
            probe_journal: Some(journal),
            calls: 0,
            last_excluded: None,
        }
    }

    fn on_post_consume_pre_sign(&mut self, position: &SigningPosition, binding: &BindingDigest) {
        self.calls = self.calls.saturating_add(1);
        if let Some(j) = self.probe_journal {
            // A concurrent reservation at this position is EXCLUDED because the
            // live operation already consumed the reservation. Bounded, single,
            // completed probe.
            let excluded = !matches!(
                j.reserve_for_sign(position, binding),
                Ok(ReservationOutcome::FreshlyReserved(_))
                    | Ok(ReservationOutcome::ExactRetryRetained(_))
            );
            self.last_excluded = Some(excluded);
        }
    }
}

// ===========================================================================
// Reconfirm perturbation (test-only; models an in-flight current-authorization
// replacement BETWEEN admit and confirm, deterministically).
// ===========================================================================

/// Adaptation of the task's `snapshot: &AuthorizedProposalVoteSnapshot` to a
/// `&mut` so a deterministic in-flight current-authorization REPLACEMENT can be
/// injected strictly between the ORIGINAL ticket's `admit()` and its
/// pre-effect `confirm()`. Taking the owner by mutable ownership here is
/// faithful (a real generation advance), not a claimed mutation through an
/// immutable borrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconfirmPerturbation {
    /// No perturbation: admit and confirm see the same owner generation.
    None,
    /// Advance the owner generation after admit so `confirm` fails `Stale`.
    AdvanceGenerationBeforeConfirm,
}

// ===========================================================================
// Model entry + private held-guard tail (ONE ordered protected sequence).
// ===========================================================================

/// Accounting charge (bytes) for the ticket/control objects kept alive across
/// BOTH the checking and the signing phases.
fn control_charge() -> u128 {
    (std::mem::size_of::<crate::genesis_consensus_authority::AuthorizationTicket>()
        + std::mem::size_of::<SigningPosition>()
        + std::mem::size_of::<BindingDigest>()) as u128
}

/// Accounting charge (bytes) for the lifecycle-comparison working set.
fn lifecycle_charge() -> u128 {
    (std::mem::size_of::<GenerationIdentity>()
        + std::mem::size_of::<PreparedProvenance>()
        + std::mem::size_of::<u64>()) as u128
}

/// Accounting charge (bytes) for the complete signing working set.
fn signing_charge() -> u128 {
    let vote = std::mem::size_of::<Vote>() as u128;
    let preimage_control = std::mem::size_of::<Vec<u8>>() as u128;
    let preimage_backing = MODEL_MAX_PREIMAGE_BYTES;
    let canonical_body_temp = MODEL_MAX_PREIMAGE_BYTES;
    let position = std::mem::size_of::<SigningPosition>() as u128;
    let binding_input = std::mem::size_of::<DecisionBindingInput<'static>>() as u128;
    let sha3 = std::mem::size_of::<Sha3_256>() as u128;
    let continuation = std::mem::size_of::<SigningContinuation>() as u128;
    let publish_cap = std::mem::size_of::<ResultPublicationCapability>() as u128;
    let binding_digest = std::mem::size_of::<BindingDigest>() as u128;
    let out_array = MODEL_SIG_CAP as u128;
    vote.saturating_add(preimage_control)
        .saturating_add(preimage_backing)
        .saturating_add(canonical_body_temp)
        .saturating_add(position)
        .saturating_add(binding_input)
        .saturating_add(sha3)
        .saturating_add(continuation)
        .saturating_add(publish_cap)
        .saturating_add(binding_digest)
        .saturating_add(out_array)
}

/// RUN 422 — the isolated fresh-vote protected-use model entry + held-guard
/// tail. ONE ordered protected sequence under a SINGLE serialization-domain
/// guard. See the module docs: this MIRRORS the production vote path and never
/// executes the production signing function.
#[allow(clippy::too_many_arguments)]
fn fresh_vote_sign_model<H: CommittedHistory + ?Sized>(
    owner: &SafetyRecordOwner,
    engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
    decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
    proposal: &qbind_wire::consensus::BlockProposal,
    limits: &PreparedDecisionInputLimits,
    history: Option<&H>,
    snapshot: &mut AuthorizedProposalVoteSnapshot,
    vote: Vote,
    signer: &dyn BoundedVoteSigner,
    sink: &mut ModelRecordingSink,
    journal: &SigningReservationJournal,
    coord: &mut ModelCoordinationHook<'_>,
    reconfirm: ReconfirmPerturbation,
) -> ModelFreshUseOutcome {
    use crate::genesis_consensus_authority::LocalAuthorizationState;

    // 1. Owner-derived policy BEFORE locking.
    match PreparedDecisionInputLimits::from_pinned(owner.pinned()) {
        Ok(expected) => {
            if *limits != expected {
                return ModelFreshUseOutcome::PolicyRefused;
            }
        }
        Err(_) => return ModelFreshUseOutcome::PolicyRefused,
    }

    // 2. Admit coverage for ticket/control BEFORE constructing them; kept alive
    //    across BOTH checking and signing phases.
    let control_res = match owner.backend.accounting().reserve(control_charge()) {
        Ok(r) => r,
        Err(_) => return ModelFreshUseOutcome::AuthorizationAdmitRefused,
    };
    let ticket = match snapshot.owner().admit() {
        Ok(t) => t,
        Err(_) => {
            drop(control_res);
            return ModelFreshUseOutcome::AuthorizationAdmitRefused;
        }
    };

    // 3. Acquire the serialization domain ONCE.
    let guard = owner.backend.lock_domain();

    // 4. Existing non-consuming observation under the held guard. Locked-only:
    //    SafeNoLock is NOT admitted.
    match owner.observe_checks_locked(&guard, engine, decided, proposal, limits, history) {
        RetainedDecisionObservation::Revalidated(
            BoundedSafetyOutcome::SafeViewSufficiency | BoundedSafetyOutcome::SafeAncestry { .. },
        ) => {}
        _ => {
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::ObservationRefused;
        }
    }

    // 5. Lifecycle comparison UNDER THE SAME GUARD, separately charged.
    let lifecycle = (|| -> Option<()> {
        let lifecycle_res = owner
            .backend
            .accounting()
            .reserve(lifecycle_charge())
            .ok()?;
        let validated: ValidatedRecord =
            owner.load_current_validated_locked(&guard, history).ok()?;
        let current_identity = GenerationIdentity::from_retained(validated.retained())?;
        let current_revision = owner.authoritative_revision_locked(&guard).ok()?;
        let captured: PreparedProvenance = owner
            .pin_provenance_locked(&guard, decided.payload().pin())
            .ok()?;
        let (engine_lock_id, engine_lock_view) = match engine.locked_qc() {
            Some(qc) => (qc.block_id, qc.view),
            None => return None,
        };
        let agree = captured.identity == current_identity
            && captured.captured_revision == current_revision
            && captured.recovery_backend_incarnation == owner.backend.incarnation()
            && engine_lock_id == current_identity.lock_block_id
            && engine_lock_view == current_identity.lock_view;
        drop(validated);
        drop(lifecycle_res);
        if agree {
            Some(())
        } else {
            None
        }
    })();
    if lifecycle.is_none() {
        drop(guard);
        drop(control_res);
        return ModelFreshUseOutcome::LifecycleAmbiguous;
    }

    // 6. Admit the signing working set BEFORE constructing any signing object.
    let signing_res = match owner.backend.accounting().reserve(signing_charge()) {
        Ok(r) => r,
        Err(_) => {
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::LifecycleAmbiguous;
        }
    };
    let mut vote = vote;
    let mut out = [0u8; MODEL_SIG_CAP];

    // 7. Mirror prepare_vote_signing_reservation.
    let (position, binding, preimage, preimage_len) = {
        let ctx: &ProposalVoteAuthority = snapshot.verifier();

        if vote.round != vote.height || vote.step != 0 {
            drop(signing_res);
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::ObservationRefused;
        }
        if vote.version != MODEL_WIRE_MESSAGE_VERSION {
            drop(signing_res);
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::ObservationRefused;
        }
        let bound_id = ValidatorId::new(signer.validator_id());
        if signer.validator_id() != vote.validator_index as u64
            || !ctx.validators.contains(bound_id)
        {
            drop(signing_res);
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::ObservationRefused;
        }
        // (2c) MODEL equivalent of the governed suite/key/backend correspondence
        //      check, through PUBLIC interfaces ONLY (NOT the production signing
        //      function): the governed key entry exists, its suite matches the
        //      signer's suite, and a backend for that suite is available.
        match ctx.key_provider.get_suite_and_key(bound_id) {
            Some((suite, _pk)) if suite == ConsensusSigSuiteId::new(signer.suite_id()) => {
                if ctx.backend_registry.get_backend(suite).is_none() {
                    drop(signing_res);
                    drop(guard);
                    drop(control_res);
                    return ModelFreshUseOutcome::ObservationRefused;
                }
            }
            _ => {
                drop(signing_res);
                drop(guard);
                drop(control_res);
                return ModelFreshUseOutcome::ObservationRefused;
            }
        }

        vote.suite_id = signer.suite_id();
        let preimage = ctx.signing_domain.vote_preimage(&vote);

        let position = SigningPosition {
            validator_id: signer.validator_id(),
            network_genesis: *ctx.signing_domain.genesis_identity(),
            kind: SigningKind::Vote,
            originating_view: vote.height,
        };
        let binding = BindingDigest::compute(&DecisionBindingInput {
            position,
            authorized_epoch: vote.epoch,
            suite_id: signer.suite_id(),
            wire_message_version: vote.version as u16,
            d6_signing_format_version: MODEL_D6_SIGNING_FORMAT_VERSION,
            authority_commitment: *ctx.signing_domain.authority_commitment(),
            block_id: vote.block_id,
            canonical_preimage: &preimage,
        });
        let preimage_len = preimage.len();
        (position, binding, preimage, preimage_len)
    };
    debug_assert!(
        preimage_len as u128 <= MODEL_MAX_PREIMAGE_BYTES,
        "model preimage exceeded the reserved backing bound"
    );

    // 8. D10 reserve -> consume.
    let continuation = match journal.reserve_for_sign(&position, &binding) {
        Ok(ReservationOutcome::FreshlyReserved(cont)) => cont,
        Ok(ReservationOutcome::ExactRetryRetained(_sig)) => {
            drop(preimage);
            drop(signing_res);
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::RetainedBlocked;
        }
        Ok(ReservationOutcome::Conflict) => {
            drop(preimage);
            drop(signing_res);
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::ReserveConflict;
        }
        Ok(ReservationOutcome::PotentiallySigned) => {
            drop(preimage);
            drop(signing_res);
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::ReservePotentiallySigned;
        }
        Ok(ReservationOutcome::Exhausted) => {
            drop(preimage);
            drop(signing_res);
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::ReserveExhausted;
        }
        Err(_) => {
            drop(preimage);
            drop(signing_res);
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::JournalFailed;
        }
    };
    let cap: ResultPublicationCapability = match journal.consume_for_signing(continuation) {
        Ok(c) => c,
        Err(_) => {
            drop(preimage);
            drop(signing_res);
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::JournalFailed;
        }
    };

    // 8.5 Reconfirm perturbation (deterministic in-flight replacement).
    if let ReconfirmPerturbation::AdvanceGenerationBeforeConfirm = reconfirm {
        snapshot
            .owner_mut()
            .replace_for_fixture(LocalAuthorizationState::MissingStorage);
    }

    // 9. Reconfirm the ORIGINAL ticket immediately before the signer.
    if snapshot.owner().confirm(&ticket).is_err() {
        drop(cap);
        drop(preimage);
        drop(signing_res);
        drop(guard);
        drop(control_res);
        return ModelFreshUseOutcome::AuthorizationConfirmRefused;
    }

    // 10. Bounded, completed coordination point (publication-exclusion).
    coord.on_post_consume_pre_sign(&position, &binding);

    // 11. Invoke the bounded signer; validate length BEFORE slicing/persist/sink.
    let n = match signer.sign_vote_into(&preimage, &mut out[..]) {
        Ok(n) => n,
        Err(_) => {
            drop(cap);
            drop(preimage);
            drop(signing_res);
            drop(guard);
            drop(control_res);
            return ModelFreshUseOutcome::SignerFailed;
        }
    };
    if n == 0 {
        drop(cap);
        drop(preimage);
        drop(signing_res);
        drop(guard);
        drop(control_res);
        return ModelFreshUseOutcome::EmptyWritten;
    }
    if n > MODEL_SIG_CAP {
        drop(cap);
        drop(preimage);
        drop(signing_res);
        drop(guard);
        drop(control_res);
        return ModelFreshUseOutcome::OversizeWritten;
    }

    // 12. Persist via the one-use capability, then invoke the sink.
    if journal.record_signed_result(&cap, &out[..n]).is_err() {
        drop(cap);
        drop(preimage);
        drop(signing_res);
        drop(guard);
        drop(control_res);
        return ModelFreshUseOutcome::PersistFailed;
    }
    let mut diag = sink.record(&vote, &out[..n]);
    diag.preimage_len = preimage_len as u32;

    // 13. Destroy covered working objects BEFORE releasing the signing
    //     reservation; the ticket/control reservation releases after; the guard
    //     releases LAST.
    drop(cap);
    drop(preimage);
    out.fill(0);
    drop(vote);
    drop(signing_res);
    drop(guard);
    drop(control_res);
    ModelFreshUseOutcome::Signed(diag)
}

// ===========================================================================
// Model unit tests (RUN 422 §13.x). The harness builds a REAL multi-validator
// engine/capture whose captured L0, current durable restriction, and engine
// lock AGREE, plus a coherence-validated authorization snapshot, and drives the
// isolated fresh-vote protected-use model through its 7 scenarios. Nothing is
// wired into any production caller.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    use qbind_consensus::ids::ValidatorId;
    use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
    use qbind_consensus::{BasicHotStuffEngine, ConsensusEngineAction, DecidedVote};

    use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
    use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_crypto::{ConsensusSigSuiteId, SUITE_PQ_RESERVED_1};
    use qbind_types::{ChainId, QBIND_DEVNET_CHAIN_ID};
    use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate as EngineWireQc, Vote};
    use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

    use crate::binary_consensus_loop::{
        snapshot_chain_identity_label, AuthorizedProposalVoteSnapshot, ProposalVoteAuthority,
    };
    use crate::genesis_consensus_authority::{
        CurrentAuthorizationOwner, CurrentStateUnavailableReason, GenesisConsensusAuthority,
    };
    use crate::pqc_trust_bundle::TrustBundleEnvironment;
    use crate::safety_record_store::backend::{SafetyBackend, SafetyBackendPolicy};
    use crate::safety_record_store::decision_capture::{
        OwnedDecisionOutcome, OwningCapturePayload, PreparedDecisionInputLimits,
    };
    use crate::safety_record_store::profile::PinnedSafetyContext;
    use crate::safety_record_store::record::WireQc as StoreWireQc;
    use crate::safety_record_store::validate::FixtureCommittedHistory;
    use crate::signing_reservation_journal::{
        BindingDigest, DecisionBindingInput, ReservationOutcome, SigningKind, SigningPosition,
        SigningReservationJournal, DEFAULT_MAX_RESERVED_POSITIONS,
    };
    use crate::storage::InMemoryConsensusStorage;

    use super::super::{make_locked_qc, PublishResult, SafetyRecordOwner};
    use super::super::super::decision_capture::derive_block_id_local;

    // -- constants shared by the fixtures ------------------------------------
    const QC_SUITE: u16 = 7;
    const TIMEOUT_SUITE: u8 = 100;
    const S_SIG: usize = 8;
    const CHAIN_ID: u32 = 42;
    const EPOCH: u64 = 7;
    const SIGNER_VID: u64 = 1;
    const MODEL_SUITE_U16: u16 = 100;

    // -- safety context / owner fixtures (mirrors of the §13.6 fixtures) -----
    fn ctx_n(n: u64) -> PinnedSafetyContext {
        let validators = (0..n).map(|i| (ValidatorId::new(i), 1u64)).collect();
        PinnedSafetyContext {
            network_genesis_id: [1u8; 32],
            authority_context_ref: [2u8; 32],
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            qc_suite_id: QC_SUITE,
            timeout_suite_id: TIMEOUT_SUITE,
            s_sig: S_SIG,
            validators,
            require_height_equals_round: false,
        }
    }

    fn valid_wire_qc(ctx: &PinnedSafetyContext, block_id: [u8; 32], view: u64) -> StoreWireQc {
        let n = ctx.n() as u64;
        let mut bitmap = vec![0u8; ((n + 7) / 8).max(1) as usize];
        let mut signatures = Vec::new();
        for i in 0..n {
            bitmap[(i / 8) as usize] |= 1 << (i % 8);
            signatures.push(vec![0xABu8; S_SIG]);
        }
        signatures.shrink_to_fit();
        StoreWireQc {
            version: 1,
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            height: view,
            round: view,
            step: 0,
            block_id,
            suite_id: QC_SUITE,
            signer_bitmap: bitmap,
            signatures,
        }
    }

    fn open_enabled(dir: &std::path::Path) -> SafetyBackend {
        SafetyBackend::open_or_initialize(
            dir,
            SafetyBackendPolicy::EnabledForTesting,
            TrustBundleEnvironment::Devnet,
        )
        .expect("enabled devnet backend opens")
    }

    fn init_owner(dir: &std::path::Path, ctx: &PinnedSafetyContext) -> SafetyRecordOwner {
        let backend = open_enabled(dir);
        let owner = SafetyRecordOwner::attach(backend, ctx.clone()).expect("attach");
        owner.initialize(true).expect("O1 initialize");
        owner
    }

    fn publish_qc(
        owner: &SafetyRecordOwner,
        ctx: &PinnedSafetyContext,
        block: [u8; 32],
        view: u64,
        expected: u64,
    ) -> u64 {
        let qc = valid_wire_qc(ctx, block, view);
        let l = make_locked_qc(ctx, block, view, qc, None).unwrap();
        match owner.publish_locked(l, expected, None::<&FixtureCommittedHistory>) {
            PublishResult::DurableAcknowledged { new_revision } => new_revision,
            other => panic!("expected DurableAcknowledged, got {other:?}"),
        }
    }

    fn limits(ctx: &PinnedSafetyContext) -> PreparedDecisionInputLimits {
        PreparedDecisionInputLimits::from_pinned(ctx).expect("pinned context yields a policy")
    }

    // -- engine fixtures -----------------------------------------------------
    fn engine_validator_set(num: u64) -> ConsensusValidatorSet {
        let entries = (1..=num)
            .map(|i| ValidatorSetEntry {
                id: ValidatorId::new(i),
                voting_power: 1,
            })
            .collect::<Vec<_>>();
        ConsensusValidatorSet::new(entries).expect("valid set")
    }

    fn make_proposal(view: u64, parent_block_id: [u8; 32], proposer_index: u16) -> BlockProposal {
        BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                epoch: 0,
                height: view,
                round: view,
                parent_block_id,
                payload_hash: [0u8; 32],
                proposer_index,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 0,
                payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
                batch_commitment: [0u8; 32],
            },
            qc: None,
            txs: vec![],
            signature: vec![],
        }
    }

    fn logical_qc(block_id: [u8; 32], height: u64) -> EngineWireQc {
        EngineWireQc {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round: height,
            step: 0,
            block_id,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signer_bitmap: vec![],
            signatures: vec![],
        }
    }

    /// A logical peer vote (no signature) used only to drive QC formation in the
    /// engine's vote accumulator. Only `epoch`, `height` (= view) and `block_id`
    /// participate in accumulation.
    fn logical_vote(view: u64, block_id: [u8; 32], validator_index: u16) -> Vote {
        Vote {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: view,
            round: view,
            step: 0,
            block_id,
            validator_index,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signature: vec![],
        }
    }

    /// RUN 422 §6 — a REAL 4-validator engine locked at L0 (view 0) by a genuine
    /// 3-vote quorum (local self-vote + validators 2 & 3), then carrying a safe
    /// view-1 proposal. A single local self-vote does NOT form a quorum at n=4,
    /// so the lock stays at L0 across the later view-1 capture: captured L0,
    /// current durable restriction, and engine lock therefore all AGREE.
    fn engine_locked_l0_multi() -> (BasicHotStuffEngine<[u8; 32]>, BlockProposal, [u8; 32]) {
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId::new(1), engine_validator_set(4));
        let p0 = make_proposal(0, [0xFF; 32], 1);
        let a0 = engine.on_proposal_event(ValidatorId::new(1), &p0);
        assert!(matches!(a0, Some(ConsensusEngineAction::BroadcastVote(_))));
        assert!(
            engine.locked_qc().is_none(),
            "a single local self-vote must NOT form a quorum at n=4"
        );
        let l0_block = derive_block_id_local(1, 0, &[0xFF; 32]);
        let r2 = engine
            .on_vote_event(ValidatorId::new(2), &logical_vote(0, l0_block, 2))
            .expect("peer vote 2 ingests");
        assert!(r2.is_none(), "two votes are short of a 3-quorum");
        let r3 = engine
            .on_vote_event(ValidatorId::new(3), &logical_vote(0, l0_block, 3))
            .expect("peer vote 3 ingests");
        assert!(r3.is_some(), "the third vote forms the L0 quorum");
        assert_eq!(engine.current_view(), 1, "QC formation advances to view 1");
        let lk = engine.locked_qc().expect("L0 lock present");
        assert_eq!(lk.block_id, l0_block);
        assert_eq!(lk.view, 0);
        let mut p1 = make_proposal(1, l0_block, 2);
        p1.qc = Some(logical_qc(l0_block, 0));
        (engine, p1, l0_block)
    }

    #[allow(clippy::type_complexity)]
    fn capture_multi(
        dir: &std::path::Path,
        ctx: &PinnedSafetyContext,
    ) -> (
        SafetyRecordOwner,
        BasicHotStuffEngine<[u8; 32]>,
        DecidedVote<OwningCapturePayload>,
        BlockProposal,
        PreparedDecisionInputLimits,
        u64,
    ) {
        let (mut engine, p1, l0_block) = engine_locked_l0_multi();
        let owner = init_owner(dir, ctx);
        let rev = publish_qc(&owner, ctx, l0_block, 0, 0);
        let proof = owner
            .read_validate(None::<&FixtureCommittedHistory>)
            .unwrap();
        let lim = limits(ctx);
        let decided = match owner.decide_and_capture_owned(
            &mut engine,
            ValidatorId::new(2),
            &p1,
            &lim,
            rev,
            proof,
        ) {
            OwnedDecisionOutcome::Decided(dv) => dv,
            other => panic!("expected Decided, got {other:?}"),
        };
        // §6 agreement: the local view-1 self-vote did not re-lock, so the
        // engine lock is still exactly L0 (view 0), matching the durable L0.
        let lk = engine.locked_qc().expect("post-capture lock");
        assert_eq!(lk.block_id, l0_block, "engine lock stays at L0 after capture");
        assert_eq!(lk.view, 0);
        assert_eq!(
            decided.vote().validator_index as u64,
            SIGNER_VID,
            "the captured self-vote is the local validator's"
        );
        assert_eq!(decided.vote().height, 1);
        assert_eq!(decided.vote().round, 1);
        assert_eq!(decided.vote().step, 0);
        assert_eq!(decided.vote().version, MODEL_WIRE_MESSAGE_VERSION);
        (owner, engine, decided, p1, lim, rev)
    }

    // -- authorization snapshot fixtures -------------------------------------
    #[derive(Debug, Clone)]
    struct TestKeyProvider {
        keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
    }
    impl SuiteAwareValidatorKeyProvider for TestKeyProvider {
        fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
            self.keys.get(&id).cloned()
        }
    }

    fn authority_validators() -> ConsensusValidatorSet {
        // Membership used ONLY for the authority's `.contains` check; it must
        // include the signer/local validator id (1).
        let entries = (0..4u64)
            .map(|i| ValidatorSetEntry {
                id: ValidatorId::new(i),
                voting_power: 1,
            })
            .collect::<Vec<_>>();
        ConsensusValidatorSet::new(entries).expect("valid authority set")
    }

    fn make_authority() -> ProposalVoteAuthority {
        let (pk, _sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        let mut keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)> = HashMap::new();
        keys.insert(ValidatorId::new(SIGNER_VID), (SUITE_PQ_RESERVED_1, pk));
        let domain = ProposalVoteSigningDomainV2::try_new(
            ChainId(0xD5D5_0000_0000_0001),
            0,
            [0x5Du8; 32],
            [0xA5u8; 32],
        )
        .expect("valid signing domain");
        ProposalVoteAuthority {
            validators: Arc::new(authority_validators()),
            key_provider: Arc::new(TestKeyProvider { keys }),
            backend_registry: Arc::new(SimpleBackendRegistry::with_backend(
                SUITE_PQ_RESERVED_1,
                Arc::new(MlDsa44Backend),
            )),
            chain_id: QBIND_DEVNET_CHAIN_ID,
            signer: None,
            signing_domain: domain,
        }
    }

    fn coherent_candidate(pv: &ProposalVoteAuthority) -> Arc<GenesisConsensusAuthority> {
        Arc::new(GenesisConsensusAuthority::for_verification_snapshot_fixture(
            snapshot_chain_identity_label(pv.signing_domain.runtime_chain_id()),
            *pv.signing_domain.genesis_identity(),
            *pv.signing_domain.authority_commitment(),
            pv.signing_domain.expected_wire_chain_id(),
            pv.validators.clone(),
            pv.key_provider.clone(),
        ))
    }

    fn established_snapshot(pv: &ProposalVoteAuthority) -> AuthorizedProposalVoteSnapshot {
        let candidate = coherent_candidate(pv);
        let observed = candidate.config_identity();
        let owner = CurrentAuthorizationOwner::establish_for_fixture(candidate, observed);
        AuthorizedProposalVoteSnapshot::try_bind(owner, Arc::new(pv.clone()))
            .expect("coherent established snapshot binds")
    }

    fn unavailable_snapshot(pv: &ProposalVoteAuthority) -> AuthorizedProposalVoteSnapshot {
        let candidate = coherent_candidate(pv);
        let owner = CurrentAuthorizationOwner::unavailable(
            candidate,
            CurrentStateUnavailableReason::MissingStorage,
        );
        AuthorizedProposalVoteSnapshot::try_bind(owner, Arc::new(pv.clone()))
            .expect("coherent unavailable snapshot binds")
    }

    fn fresh_journal() -> SigningReservationJournal {
        SigningReservationJournal::initialize(
            Arc::new(InMemoryConsensusStorage::new()),
            DEFAULT_MAX_RESERVED_POSITIONS,
        )
        .expect("initialize fresh in-memory signing journal")
    }

    /// Recompute the SAME (position, binding) the model derives for `base_vote`
    /// under `pv`, so a test can seed or probe the journal at the model's exact
    /// position without reaching into the private tail.
    fn expected_pos_binding(
        pv: &ProposalVoteAuthority,
        base_vote: &Vote,
    ) -> (SigningPosition, BindingDigest) {
        let mut v = base_vote.clone();
        v.suite_id = MODEL_SUITE_U16;
        let preimage = pv.signing_domain.vote_preimage(&v);
        let position = SigningPosition {
            validator_id: SIGNER_VID,
            network_genesis: *pv.signing_domain.genesis_identity(),
            kind: SigningKind::Vote,
            originating_view: v.height,
        };
        let binding = BindingDigest::compute(&DecisionBindingInput {
            position,
            authorized_epoch: v.epoch,
            suite_id: MODEL_SUITE_U16,
            wire_message_version: v.version as u16,
            d6_signing_format_version: MODEL_D6_SIGNING_FORMAT_VERSION,
            authority_commitment: *pv.signing_domain.authority_commitment(),
            block_id: v.block_id,
            canonical_preimage: &preimage,
        });
        (position, binding)
    }

    fn ok_signer() -> OkFixtureSigner {
        OkFixtureSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
        }
    }

    // ======================================================================
    // Scenario 1 — successful fresh execution: exactly ONE signer + ONE sink.
    // ======================================================================
    #[test]
    fn scenario1_successful_fresh_execution_single_signer_single_sink() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let signer = ok_signer();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner,
            &engine,
            &decided,
            &p1,
            &lim,
            None,
            &mut snapshot,
            base_vote.clone(),
            &signer,
            &mut sink,
            &journal,
            &mut coord,
            ReconfirmPerturbation::None,
        );

        match outcome {
            ModelFreshUseOutcome::Signed(diag) => {
                assert_eq!(diag.validator_index, SIGNER_VID);
                assert_eq!(diag.height, 1);
                assert_eq!(diag.round, 1);
                assert_eq!(diag.step, 0);
                assert_eq!(diag.suite_id, MODEL_SUITE_U16);
                assert_eq!(diag.sig_len, 8, "OK fixture writes an 8-byte tag");
                assert!(diag.preimage_len > 0);
                assert!(
                    diag.preimage_len as u128 <= MODEL_MAX_PREIMAGE_BYTES,
                    "real preimage len {} within reserved bound {}",
                    diag.preimage_len,
                    MODEL_MAX_PREIMAGE_BYTES
                );
            }
            other => panic!("expected Signed, got {other:?}"),
        }
        assert_eq!(sink.calls, 1, "exactly one sink call");
        assert_eq!(coord.calls, 1, "the coordination point is reached once");

        // The borrowed envelope / Vote / pin are preserved and unchanged.
        assert_eq!(decided.vote(), &base_vote);
    }

    // ======================================================================
    // Scenario 2 — policy / observation / lifecycle / admission refusals all
    // occur BEFORE any D10 reservation (no reserved position, zero signer calls).
    // ======================================================================
    fn assert_no_reservation_made(
        journal: &SigningReservationJournal,
        pv: &ProposalVoteAuthority,
        base_vote: &Vote,
    ) {
        // A fresh reserve at the model's exact position must still be FreshlyReserved,
        // proving the model made (and left) no reservation there.
        let (pos, binding) = expected_pos_binding(pv, base_vote);
        match journal.reserve_for_sign(&pos, &binding) {
            Ok(ReservationOutcome::FreshlyReserved(_)) => {}
            other => panic!("expected a still-fresh position, got {other:?}"),
        }
    }

    #[test]
    fn scenario2_policy_refused_before_any_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, _lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let signer = ok_signer();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();
        // Wrong limits: a different validator count yields a different policy.
        let wrong = limits(&ctx_n(5));

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &wrong, None, &mut snapshot,
            base_vote.clone(), &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::PolicyRefused);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0);
        assert_no_reservation_made(&journal, &pv, &base_vote);
    }

    #[test]
    fn scenario2_observation_refused_before_any_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let signer = ok_signer();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();
        // A mismatching proposal (different parent) breaks the observation's
        // exact-proposal correspondence under the held guard.
        let mut wrong_proposal = p1.clone();
        wrong_proposal.header.parent_block_id = [0x11; 32];

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &wrong_proposal, &lim, None, &mut snapshot,
            base_vote.clone(), &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::ObservationRefused);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0);
        assert_no_reservation_made(&journal, &pv, &base_vote);
    }

    #[test]
    fn scenario2_admission_refused_before_any_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        // An unavailable current-authorization owner can never admit.
        let mut snapshot = unavailable_snapshot(&pv);
        let journal = fresh_journal();
        let signer = ok_signer();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            base_vote.clone(), &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::AuthorizationAdmitRefused);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0);
        assert_no_reservation_made(&journal, &pv, &base_vote);
    }

    // ======================================================================
    // Scenario 3 — original-ticket reconfirm rejection with ZERO signer calls.
    // A deterministic in-flight generation advance BETWEEN admit and confirm
    // (taking the owner by &mut, a faithful real advance) makes confirm `Stale`.
    // ======================================================================
    #[test]
    fn scenario3_reconfirm_rejection_zero_signer_calls() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let signer = ok_signer();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            base_vote.clone(), &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::AdvanceGenerationBeforeConfirm,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::AuthorizationConfirmRefused);
        assert_eq!(sink.calls, 0, "no signer/sink work after a confirm refusal");
        // The D10 reservation obligation is preserved (reserve+consume happened
        // before confirm): a re-reserve at the position is NOT freshly reserved.
        let (pos, binding) = expected_pos_binding(&pv, &base_vote);
        match journal.reserve_for_sign(&pos, &binding) {
            Ok(ReservationOutcome::FreshlyReserved(_)) => {
                panic!("confirm-refusal must preserve the consumed D10 obligation")
            }
            _ => {}
        }
    }

    // ======================================================================
    // Scenario 4 — completed bounded coordination at the post-consume/pre-sign
    // point EXCLUDES a concurrent publication there; the run still completes and
    // an eligible publication at a different position proceeds afterwards.
    // ======================================================================
    #[test]
    fn scenario4_coordination_excludes_concurrent_publication() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let signer = ok_signer();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::probing(&journal);
        let base_vote = decided.vote().clone();

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            base_vote.clone(), &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        match outcome {
            ModelFreshUseOutcome::Signed(_) => {}
            other => panic!("expected Signed, got {other:?}"),
        }
        assert_eq!(coord.calls, 1, "the bounded coordination point ran once");
        assert_eq!(
            coord.last_excluded,
            Some(true),
            "a concurrent publication at this position was EXCLUDED"
        );
        // After the guard released, an eligible publication at a DIFFERENT
        // position still proceeds (the journal is not globally blocked).
        let other_pos = SigningPosition {
            validator_id: SIGNER_VID,
            network_genesis: *pv.signing_domain.genesis_identity(),
            kind: SigningKind::Vote,
            originating_view: 999,
        };
        let (_p, other_binding) = expected_pos_binding(&pv, &base_vote);
        match journal.reserve_for_sign(&other_pos, &other_binding) {
            Ok(ReservationOutcome::FreshlyReserved(_)) => {}
            other => panic!("a distinct eligible position should be fresh, got {other:?}"),
        }
    }

    // ======================================================================
    // Scenario 5 — empty / oversize / signer-error / persist-failure: NO sink
    // call, and the durable D10 conflict obligation is PRESERVED.
    // ======================================================================
    fn assert_d10_obligation_preserved(
        journal: &SigningReservationJournal,
        pv: &ProposalVoteAuthority,
        base_vote: &Vote,
    ) {
        let (pos, binding) = expected_pos_binding(pv, base_vote);
        match journal.reserve_for_sign(&pos, &binding) {
            Ok(ReservationOutcome::FreshlyReserved(_)) => {
                panic!("the consumed D10 reservation obligation must be preserved")
            }
            // PotentiallySigned / Conflict / Exhausted / ExactRetryRetained are
            // all acceptable "not fresh" outcomes.
            _ => {}
        }
    }

    fn run_with_signer(
        dir: &std::path::Path,
        signer: &dyn BoundedVoteSigner,
    ) -> (ModelFreshUseOutcome, u32, SigningReservationJournal, ProposalVoteAuthority, Vote) {
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir, &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();
        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            base_vote.clone(), signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        (outcome, sink.calls, journal, pv, base_vote)
    }

    #[test]
    fn scenario5_empty_written_no_sink_obligation_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let signer = EmptyFixtureSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
        };
        let (outcome, sink_calls, journal, pv, base_vote) = run_with_signer(dir.path(), &signer);
        assert_eq!(outcome, ModelFreshUseOutcome::EmptyWritten);
        assert_eq!(sink_calls, 0);
        assert_d10_obligation_preserved(&journal, &pv, &base_vote);
    }

    #[test]
    fn scenario5_oversize_written_no_sink_obligation_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let signer = OversizeFixtureSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
        };
        let (outcome, sink_calls, journal, pv, base_vote) = run_with_signer(dir.path(), &signer);
        assert_eq!(outcome, ModelFreshUseOutcome::OversizeWritten);
        assert_eq!(sink_calls, 0);
        assert_d10_obligation_preserved(&journal, &pv, &base_vote);
    }

    #[test]
    fn scenario5_signer_error_no_sink_obligation_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ErrorFixtureSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
        };
        let (outcome, sink_calls, journal, pv, base_vote) = run_with_signer(dir.path(), &signer);
        assert_eq!(outcome, ModelFreshUseOutcome::SignerFailed);
        assert_eq!(sink_calls, 0);
        assert_d10_obligation_preserved(&journal, &pv, &base_vote);
    }

    // ======================================================================
    // Scenario 6 — retained outcome blocked: the position is already retained
    // from a prior op, so the model returns RetainedBlocked with ZERO new signer
    // calls and NO reuse of the retained bytes.
    // ======================================================================
    #[test]
    fn scenario6_retained_outcome_blocked_zero_signer_calls() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let base_vote = decided.vote().clone();

        // Seed the journal so the model's EXACT position/binding is already
        // retained by a prior (identical-binding) operation.
        let (pos, binding) = expected_pos_binding(&pv, &base_vote);
        let cont = match journal.reserve_for_sign(&pos, &binding) {
            Ok(ReservationOutcome::FreshlyReserved(c)) => c,
            other => panic!("seed reserve should be fresh, got {other:?}"),
        };
        let cap = journal.consume_for_signing(cont).expect("seed consume");
        journal
            .record_signed_result(&cap, &[0xEE; 8])
            .expect("seed record");

        let signer = ok_signer();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            base_vote.clone(), &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::RetainedBlocked);
        assert_eq!(sink.calls, 0, "no sink on a retained-blocked outcome");
        assert_eq!(coord.calls, 0, "no coordination/signing after retained block");
    }

    // ======================================================================
    // Scenario 7 — exact cleanup + preserved envelope/Vote/pin + measured peak
    // coverage within the unchanged limits.
    // ======================================================================
    #[test]
    fn scenario7_cleanup_preservation_and_measured_peak() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let signer = ok_signer();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();

        // Baseline active operational reservation BEFORE the model call (the
        // retained pin from `decided` is part of this baseline and is unchanged
        // across the call).
        let baseline = owner.backend_for_test().accounting_current();

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            base_vote.clone(), &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert!(matches!(outcome, ModelFreshUseOutcome::Signed(_)));

        // Exact cleanup: every model reservation released, back to baseline.
        let after = owner.backend_for_test().accounting_current();
        assert_eq!(after, baseline, "all model reservations released after the run");

        // Preserved borrowed envelope / Vote / pin.
        assert_eq!(decided.vote(), &base_vote, "the Vote is unchanged");

        // Measured peak coverage within the unchanged aggregate ceiling.
        let c_sign = signing_charge();
        let c_ctrl = control_charge();
        let c_life = lifecycle_charge();
        let peak = owner.backend_for_test().accounting_peak();
        if let Some(cap) = owner.backend_for_test().accounting_cap() {
            assert!(
                baseline + c_ctrl + c_sign <= cap,
                "signing-phase peak (baseline {baseline} + control {c_ctrl} + signing {c_sign}) must fit the cap {cap}"
            );
            assert!(peak <= cap, "observed peak {peak} within cap {cap}");
        }
        // Emit the charge table for the report (visible under --nocapture).
        eprintln!(
            "RUN422-MODEL charges: control={c_ctrl} lifecycle={c_life} signing(C_sign)={c_sign} \
             baseline={baseline} peak={peak} vote_size={} preimage_vec={} out_cap={}",
            std::mem::size_of::<Vote>(),
            std::mem::size_of::<Vec<u8>>(),
            MODEL_SIG_CAP,
        );
    }
}