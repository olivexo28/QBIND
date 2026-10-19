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
use super::super::backend::SafetyBackend;
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

/// Conservative upper bound (bytes) on the owned public-key `Vec<u8>` the
/// governed key provider returns from `get_suite_and_key`. The fixture provider
/// clones a stored key, so the model owns that clone's backing for the duration
/// of the signing working set and must reserve for it BEFORE the lookup. An
/// ML-DSA-44 public key is 1312 bytes; this bound is held above that with
/// headroom, and the tests verify the actual `capacity()` (not merely `len()`)
/// against it. If a fixture provider cannot satisfy this bound it is refused —
/// the model never claims an arbitrary provider satisfies the contract.
const MODEL_MAX_PUBKEY_BYTES: u128 = 2048;

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

/// The digest-recording OK signer: in addition to writing the deterministic
/// 8-byte length tag, it records a fixed-size SHA3-256 digest of the exact
/// preimage it was handed plus its length, so a test can independently compute
/// the preimage of the envelope's complete Vote (with only the permitted suite
/// assignment) and prove the signer input matched byte-for-byte. The record is a
/// `Copy` `(digest, len)` held in a `Cell`; the signer never retains the
/// preimage bytes or the output.
pub(crate) struct DigestRecordingSigner {
    pub(crate) validator_id: u64,
    pub(crate) suite_id: u16,
    pub(crate) seen: std::cell::Cell<Option<([u8; 32], usize)>>,
}

impl BoundedVoteSigner for DigestRecordingSigner {
    fn validator_id(&self) -> u64 {
        self.validator_id
    }
    fn suite_id(&self) -> u16 {
        self.suite_id
    }
    fn sign_vote_into(&self, preimage: &[u8], out: &mut [u8]) -> Result<usize, ModelSignError> {
        use sha3::Digest;
        let mut h = Sha3_256::new();
        h.update(preimage);
        let digest = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        self.seen.set(Some((arr, preimage.len())));
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

/// A bounded, model-only invocation COUNTER that wraps any inner
/// `BoundedVoteSigner`. It counts ACTUAL `sign_vote_into` calls at the real
/// signing boundary (incremented BEFORE delegating, so an invocation that
/// returns an error is still counted) and delegates every other method
/// unchanged. Unlike `DigestRecordingSigner.seen` — which overwrites a single
/// cell and therefore records only the LATEST digest/length, not how many times
/// the signer was called — this is a true invocation count. Digest recording,
/// when needed, stays on the wrapped inner signer, so the two concerns remain
/// independent. The counter is a caller-owned fixture (like the sink); it is NOT
/// part of the model's `signing_charge` working set.
pub(crate) struct CountingSigner<'a> {
    inner: &'a dyn BoundedVoteSigner,
    calls: std::cell::Cell<u32>,
}

impl<'a> CountingSigner<'a> {
    pub(crate) fn new(inner: &'a dyn BoundedVoteSigner) -> Self {
        Self {
            inner,
            calls: std::cell::Cell::new(0),
        }
    }

    /// The exact number of `sign_vote_into` invocations observed at the boundary.
    pub(crate) fn calls(&self) -> u32 {
        self.calls.get()
    }
}

impl BoundedVoteSigner for CountingSigner<'_> {
    fn validator_id(&self) -> u64 {
        self.inner.validator_id()
    }
    fn suite_id(&self) -> u16 {
        self.inner.suite_id()
    }
    fn sign_vote_into(&self, preimage: &[u8], out: &mut [u8]) -> Result<usize, ModelSignError> {
        self.calls.set(self.calls.get().saturating_add(1));
        self.inner.sign_vote_into(preimage, out)
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
    SigningAdmitRefused,
    SignedInputRejected,
    WrongWireChain,
    WrongAuthorizedEpoch,
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
//
// This models the ACTUAL safety-publication boundary (RUN 422 §3 correction):
// at a FIXED observation point — after the D10 reservation is consumed and the
// original ticket reconfirmed, immediately before the fixture signer — the live
// protected operation holds the backend serialization-domain guard. A competing
// handle sharing the EXACT SAME `SafetyBackend` serialization domain is driven
// through a bounded, completed handshake to perform a NON-BLOCKING domain
// observation at that instant: it must observe `WouldBlock` (the domain is held
// by the protected operation), which is what proves publication exclusion.
// `Acquired` or `Poisoned` would NOT satisfy exclusion. The earlier reviewed
// hook instead probed the D10 journal for a DIFFERENT reserved position, which
// demonstrates journal behaviour, not safety-domain serialization; that probe is
// withdrawn as the exclusion evidence.
// ===========================================================================

/// The discriminated outcome of a competing handle's non-blocking observation of
/// the shared serialization domain. `Send` (a plain `Copy` enum) so it can be
/// handed back from the peer thread over a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerDomainObservation {
    /// The domain is currently held by the protected operation (exclusion holds).
    WouldBlock,
    /// The competing handle unexpectedly acquired the domain (NOT excluded).
    Acquired,
    /// The domain mutex is poisoned (NOT a clean exclusion observation).
    Poisoned,
}

/// The bounded handshake endpoints the probing hook uses to drive the peer: a
/// request signal to ask the peer to observe now, and a result channel to carry
/// back the single discriminated observation. Every leg must succeed; a failed
/// send, a timed-out receive, or a missing observation fails the hook (recorded
/// in `failed`) so the test fails rather than silently passing.
struct CoordinationProbe {
    request_tx: std::sync::mpsc::Sender<()>,
    result_rx: std::sync::mpsc::Receiver<PeerDomainObservation>,
    timeout: std::time::Duration,
}

/// A fixed, bounded coordination point invoked AFTER the D10 reservation is
/// consumed and the original ticket is reconfirmed, and BEFORE the signer is
/// invoked. The probing variant drives a competing same-domain handle through a
/// bounded, completed handshake and records whether the competing observation was
/// `WouldBlock` (exclusion holds). It is COMPLETED/bounded (a single handshake,
/// no indefinite hold, no sleeps); after it returns the model proceeds, and after
/// the guard releases an eligible `publish_locked` may proceed later.
pub(crate) struct ModelCoordinationHook {
    probe: Option<CoordinationProbe>,
    /// Optional shared-backend handle used ONLY to sample both accounting ledgers
    /// at the live signing phase (RUN 422 §5). A clone shares the same inner
    /// accountant, so reading it here observes the true in-operation charge while
    /// the control and signing reservations (and the signing objects) are live.
    /// Sampling reads a separate lock from the domain guard, so it never blocks.
    sample_backend: Option<SafetyBackend>,
    pub(crate) calls: u32,
    pub(crate) last_excluded: Option<bool>,
    /// Set if any handshake leg failed (send error, receive timeout/disconnect).
    pub(crate) failed: bool,
    /// The operational ledger charge sampled at the live signing phase, if a
    /// sampling backend was installed.
    pub(crate) observed_operational: Option<u128>,
    /// The aggregate ledger charge sampled at the live signing phase, if a
    /// sampling backend was installed.
    pub(crate) observed_aggregate: Option<u128>,
}

impl ModelCoordinationHook {
    /// An inert hook (no competing-handle observation); still records that the
    /// coordination point was reached.
    pub(crate) fn inert() -> Self {
        Self {
            probe: None,
            sample_backend: None,
            calls: 0,
            last_excluded: None,
            failed: false,
            observed_operational: None,
            observed_aggregate: None,
        }
    }

    /// A hook that, at the live signing phase (post-consume / pre-sign, with the
    /// control and signing reservations and the signing objects all live), reads
    /// BOTH accounting ledgers directly from the shared backend (RUN 422 §5). This
    /// is a bounded, model-only observation: it records two `u128` scalars and does
    /// no peer handshake.
    pub(crate) fn sampling(backend: SafetyBackend) -> Self {
        Self {
            probe: None,
            sample_backend: Some(backend),
            calls: 0,
            last_excluded: None,
            failed: false,
            observed_operational: None,
            observed_aggregate: None,
        }
    }

    /// A probing hook bound to a peer handshake. `request_tx` signals the peer to
    /// observe the shared domain now; `result_rx` carries back the single
    /// discriminated observation; `timeout` bounds the wait so a stuck peer fails
    /// the test rather than hanging it.
    pub(crate) fn probing(
        request_tx: std::sync::mpsc::Sender<()>,
        result_rx: std::sync::mpsc::Receiver<PeerDomainObservation>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            probe: Some(CoordinationProbe {
                request_tx,
                result_rx,
                timeout,
            }),
            sample_backend: None,
            calls: 0,
            last_excluded: None,
            failed: false,
            observed_operational: None,
            observed_aggregate: None,
        }
    }

    fn on_post_consume_pre_sign(&mut self) {
        self.calls = self.calls.saturating_add(1);
        // RUN 422 §5 — live signing-phase ledger observation. Sampled here, inside
        // the protected sequence, while the reservations/objects are live.
        if let Some(b) = &self.sample_backend {
            self.observed_operational = Some(b.accounting_current());
            self.observed_aggregate = Some(b.accounting_aggregate_current());
        }
        if let Some(p) = &self.probe {
            // Leg 1: signal the peer to observe the domain now. A failed send
            // (disconnected peer) is a failed handshake.
            if p.request_tx.send(()).is_err() {
                self.failed = true;
                return;
            }
            // Leg 2: receive the single bounded observation. A timeout or
            // disconnect is a failed handshake. Only `WouldBlock` satisfies
            // exclusion.
            match p.result_rx.recv_timeout(p.timeout) {
                Ok(PeerDomainObservation::WouldBlock) => self.last_excluded = Some(true),
                Ok(PeerDomainObservation::Acquired | PeerDomainObservation::Poisoned) => {
                    self.last_excluded = Some(false)
                }
                Err(_) => self.failed = true,
            }
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
    /// No perturbation: admit and confirm see the same owner generation, and the
    /// model-owned working Vote keeps every engine-produced field.
    None,
    /// Advance the owner generation after admit so `confirm` fails `Stale`.
    AdvanceGenerationBeforeConfirm,
    /// Deterministically bump the MODEL-OWNED working Vote's `epoch` immediately
    /// after it is derived from the (unchanged) captured envelope, to exercise the
    /// §2 wrong-authorized-epoch admission guard. The real engine always stamps
    /// `epoch == 0` and the genesis-static authority's `authorized_epoch()` is
    /// fixed at `0`, so a genuine disagreement cannot be captured; this perturbs
    /// ONLY the model's private clone (never `decided`'s envelope) so the guard is
    /// still tested on a vote that disagrees with the authorized epoch.
    BumpWorkingVoteEpoch,
}

// ===========================================================================
// Model entry + private held-guard tail (ONE ordered protected sequence).
// ===========================================================================

/// Accounting charge (bytes) for the authorization ticket/control objects kept
/// alive across BOTH the checking and the signing phases. The ticket is admitted
/// before it is constructed and stays live through its `confirm` and its
/// destruction; the signing-phase position/binding objects are charged by
/// `signing_charge` (where they are constructed and live), not here.
fn control_charge() -> u128 {
    std::mem::size_of::<crate::genesis_consensus_authority::AuthorizationTicket>() as u128
}

/// Accounting charge (bytes) for the lifecycle-comparison working set. Covers the
/// model-held restriction identity, the scalar pin provenance, and the captured
/// revision scalar. The current validated record is covered separately by the
/// loader's own holder/scratch reservation (preserved unchanged).
fn lifecycle_charge() -> u128 {
    (std::mem::size_of::<GenerationIdentity>()
        + std::mem::size_of::<PreparedProvenance>()
        + std::mem::size_of::<u64>()) as u128
}

/// Accounting charge (bytes) for the complete signing working set, admitted
/// BEFORE any signing object is constructed. It conservatively bounds the
/// simultaneously-live model-owned objects: the working Vote, the owned
/// public-key lookup result (`Vec<u8>` control + its backing capacity), the
/// preimage (`Vec<u8>` control + backing) and canonical-body temporary backing,
/// the position/binding-input/hash-state scratch, the continuation and
/// publication capability, the binding digest, and the fixed output array.
fn signing_charge() -> u128 {
    let vote = std::mem::size_of::<Vote>() as u128;
    let pubkey_control = std::mem::size_of::<Vec<u8>>() as u128;
    let pubkey_backing = MODEL_MAX_PUBKEY_BYTES;
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
    vote.saturating_add(pubkey_control)
        .saturating_add(pubkey_backing)
        .saturating_add(preimage_control)
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
///
/// Ownership/destruction order (RUN 422 §4 correction): the serialization-domain
/// guard is acquired FIRST so it is the LAST thing dropped; the control
/// reservation is admitted next and the ticket it covers is constructed after it,
/// so on every exit the ticket is destroyed before its control reservation
/// releases and the control reservation releases before the guard. The signing
/// reservation is admitted before any signing object (the working Vote, the owned
/// public-key lookup result and its backing, the preimage/canonical-body
/// temporaries, the position/binding/hash scratch, the continuation, publication
/// capability and output array), so those owned objects are all destroyed before
/// the signing reservation releases. Because the declaration order is
/// guard → control_res → ticket → signing_res → signing objects, Rust's reverse
/// drop order already yields: signing objects → signing_res → ticket →
/// control_res → guard on EVERY early-return refusal and on success. No
/// release-then-recharge gap is introduced and no covered object is constructed
/// uncharged.
///
/// The working Vote is derived EXCLUSIVELY from `decided.vote()` (RUN 422 §2
/// correction): there is no independently-supplied owned Vote, so observation and
/// signing operate on the SAME checked envelope. Every engine-produced field is
/// preserved except the already-permitted governed suite assignment.
#[allow(clippy::too_many_arguments)]
fn fresh_vote_sign_model<H: CommittedHistory + ?Sized>(
    owner: &SafetyRecordOwner,
    engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
    decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
    proposal: &qbind_wire::consensus::BlockProposal,
    limits: &PreparedDecisionInputLimits,
    history: Option<&H>,
    snapshot: &mut AuthorizedProposalVoteSnapshot,
    signer: &dyn BoundedVoteSigner,
    sink: &mut ModelRecordingSink,
    journal: &SigningReservationJournal,
    coord: &mut ModelCoordinationHook,
    reconfirm: ReconfirmPerturbation,
) -> ModelFreshUseOutcome {
    use crate::genesis_consensus_authority::LocalAuthorizationState;

    // 1. Owner-derived policy BEFORE locking (no allocation).
    match PreparedDecisionInputLimits::from_pinned(owner.pinned()) {
        Ok(expected) => {
            if *limits != expected {
                return ModelFreshUseOutcome::PolicyRefused;
            }
        }
        Err(_) => return ModelFreshUseOutcome::PolicyRefused,
    }

    // 2. Acquire the serialization domain ONCE and FIRST so it is released LAST
    //    (declared first ⇒ dropped last). Every subsequent early return drops the
    //    in-scope objects in correct reverse order with the guard last.
    let guard = owner.backend.lock_domain();

    // 3. Admit control coverage BEFORE constructing the ticket; it stays live
    //    through the ticket's confirm and destruction.
    let _control_res = match owner.backend.accounting().reserve(control_charge()) {
        Ok(r) => r,
        Err(_) => return ModelFreshUseOutcome::AuthorizationAdmitRefused,
    };
    let ticket = match snapshot.owner().admit() {
        Ok(t) => t,
        Err(_) => return ModelFreshUseOutcome::AuthorizationAdmitRefused,
    };

    // 4. Existing non-consuming observation under the held guard. Locked-only:
    //    SafeNoLock is NOT admitted.
    match owner.observe_checks_locked(&guard, engine, decided, proposal, limits, history) {
        RetainedDecisionObservation::Revalidated(
            BoundedSafetyOutcome::SafeViewSufficiency | BoundedSafetyOutcome::SafeAncestry { .. },
        ) => {}
        _ => return ModelFreshUseOutcome::ObservationRefused,
    }

    // 5. Lifecycle comparison UNDER THE SAME GUARD, separately charged. The
    //    reservation and the validated record are destroyed before the closure
    //    returns (the record carries its own loader holder reservation).
    let lifecycle = (|| -> Option<()> {
        let lifecycle_res = owner
            .backend
            .accounting()
            .reserve(lifecycle_charge())
            .ok()?;
        // Covered objects live in an inner block so they are destroyed BEFORE the
        // covering `lifecycle_res` releases (RUN 422 §4), on both the success path
        // and every `?` early exit (inner-block locals unwind before the closure's
        // `lifecycle_res`).
        let agree = {
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
            captured.identity == current_identity
                && captured.captured_revision == current_revision
                && captured.recovery_backend_incarnation == owner.backend.incarnation()
                && engine_lock_id == current_identity.lock_block_id
                && engine_lock_view == current_identity.lock_view
        };
        drop(lifecycle_res);
        agree.then_some(())
    })();
    if lifecycle.is_none() {
        return ModelFreshUseOutcome::LifecycleAmbiguous;
    }

    // 6. Admit the signing working set BEFORE constructing any signing object.
    let _signing_res = match owner.backend.accounting().reserve(signing_charge()) {
        Ok(r) => r,
        Err(_) => return ModelFreshUseOutcome::SigningAdmitRefused,
    };

    // 7. Unsigned-input assumption: the captured self-vote must be unsigned with a
    //    zero-capacity signature backing. A populated (or non-empty-capacity)
    //    signature is REFUSED here, before copying — it is never silently
    //    discarded.
    if !decided.vote().signature.is_empty() || decided.vote().signature.capacity() != 0 {
        return ModelFreshUseOutcome::SignedInputRejected;
    }

    // 8. Construct the model-owned Vote EXCLUSIVELY from the checked envelope.
    //    Clone preserves every engine field; `vec![]` clones to zero capacity, so
    //    the signature invariant is maintained.
    let mut vote: Vote = decided.vote().clone();
    debug_assert!(
        vote.signature.is_empty() && vote.signature.capacity() == 0,
        "model-owned Vote must retain the zero-capacity unsigned-signature invariant"
    );
    // Test-only deterministic perturbation of the MODEL-OWNED working Vote (never
    // the captured envelope) to exercise the §2 wrong-authorized-epoch guard.
    if let ReconfirmPerturbation::BumpWorkingVoteEpoch = reconfirm {
        vote.epoch = vote.epoch.wrapping_add(1);
    }
    let mut out = [0u8; MODEL_SIG_CAP];

    // 9. Admission checks bound to the checked envelope, performed BEFORE any D10
    //    reservation or signer invocation (RUN 422 §2). Compare the Vote's wire
    //    chain id and epoch against the authorized snapshot.
    if vote.chain_id != snapshot.verifier().signing_domain.expected_wire_chain_id() {
        return ModelFreshUseOutcome::WrongWireChain;
    }
    if vote.epoch != snapshot.authorized_epoch() {
        return ModelFreshUseOutcome::WrongAuthorizedEpoch;
    }

    // 10. Mirror prepare_vote_signing_reservation. Owned objects created here
    //     (the lookup public key, the preimage, position, binding) are covered by
    //     `signing_res` and returned into function scope so they are destroyed
    //     before `signing_res` releases.
    let (position, binding, preimage, _owned_pk, preimage_len) = {
        let ctx: &ProposalVoteAuthority = snapshot.verifier();

        if vote.round != vote.height || vote.step != 0 {
            return ModelFreshUseOutcome::ObservationRefused;
        }
        if vote.version != MODEL_WIRE_MESSAGE_VERSION {
            return ModelFreshUseOutcome::ObservationRefused;
        }
        let bound_id = ValidatorId::new(signer.validator_id());
        if signer.validator_id() != vote.validator_index as u64
            || !ctx.validators.contains(bound_id)
        {
            return ModelFreshUseOutcome::ObservationRefused;
        }
        // (2c) MODEL equivalent of the governed suite/key/backend correspondence
        //      check, through PUBLIC interfaces ONLY. The owned public-key `Vec`
        //      the provider CLONES is retained (model-owned) and its backing
        //      capacity is verified against the reserved conservative bound: a
        //      length assertion alone is insufficient backing-capacity evidence.
        let owned_pk = match ctx.key_provider.get_suite_and_key(bound_id) {
            Some((suite, pk)) if suite == ConsensusSigSuiteId::new(signer.suite_id()) => {
                if ctx.backend_registry.get_backend(suite).is_none() {
                    return ModelFreshUseOutcome::ObservationRefused;
                }
                pk
            }
            _ => return ModelFreshUseOutcome::ObservationRefused,
        };
        debug_assert!(
            owned_pk.capacity() as u128 <= MODEL_MAX_PUBKEY_BYTES,
            "owned public-key backing capacity exceeded the reserved bound"
        );

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
        (position, binding, preimage, owned_pk, preimage_len)
    };
    debug_assert!(
        preimage_len as u128 <= MODEL_MAX_PREIMAGE_BYTES,
        "model preimage exceeded the reserved backing bound"
    );
    // RUN 422 §5 — verify the returned preimage's CAPACITY (not merely its length)
    // stays within the conservative bound the signing working set reserved for its
    // backing. A length check alone is insufficient backing-capacity evidence.
    debug_assert!(
        preimage.capacity() as u128 <= MODEL_MAX_PREIMAGE_BYTES,
        "model preimage backing capacity exceeded the reserved bound"
    );

    // 11. D10 reserve -> consume.
    let continuation = match journal.reserve_for_sign(&position, &binding) {
        Ok(ReservationOutcome::FreshlyReserved(cont)) => cont,
        Ok(ReservationOutcome::ExactRetryRetained(_sig)) => {
            return ModelFreshUseOutcome::RetainedBlocked;
        }
        Ok(ReservationOutcome::Conflict) => return ModelFreshUseOutcome::ReserveConflict,
        Ok(ReservationOutcome::PotentiallySigned) => {
            return ModelFreshUseOutcome::ReservePotentiallySigned;
        }
        Ok(ReservationOutcome::Exhausted) => return ModelFreshUseOutcome::ReserveExhausted,
        Err(_) => return ModelFreshUseOutcome::JournalFailed,
    };
    let cap: ResultPublicationCapability = match journal.consume_for_signing(continuation) {
        Ok(c) => c,
        Err(_) => return ModelFreshUseOutcome::JournalFailed,
    };

    // 11.5 Reconfirm perturbation (deterministic in-flight replacement).
    if let ReconfirmPerturbation::AdvanceGenerationBeforeConfirm = reconfirm {
        snapshot
            .owner_mut()
            .replace_for_fixture(LocalAuthorizationState::MissingStorage);
    }

    // 12. Reconfirm the ORIGINAL ticket immediately before the signer.
    if snapshot.owner().confirm(&ticket).is_err() {
        return ModelFreshUseOutcome::AuthorizationConfirmRefused;
    }

    // 13. Fixed observation point: the ACTUAL safety-publication boundary. A
    //     competing same-domain handle observes `WouldBlock` here while this
    //     operation holds the guard (bounded, completed handshake). Assertions on
    //     the recorded result are performed outside this guarded callback.
    coord.on_post_consume_pre_sign();

    // 14. Invoke the bounded signer; validate length BEFORE slicing/persist/sink.
    let n = match signer.sign_vote_into(&preimage, &mut out[..]) {
        Ok(n) => n,
        Err(_) => return ModelFreshUseOutcome::SignerFailed,
    };
    if n == 0 {
        return ModelFreshUseOutcome::EmptyWritten;
    }
    if n > MODEL_SIG_CAP {
        return ModelFreshUseOutcome::OversizeWritten;
    }

    // 15. Persist via the one-use capability, then invoke the sink.
    if journal.record_signed_result(&cap, &out[..n]).is_err() {
        return ModelFreshUseOutcome::PersistFailed;
    }
    let mut diag = sink.record(&vote, &out[..n]);
    diag.preimage_len = preimage_len as u32;

    // 16. Zero the fixed output array in place; the remaining owned objects and
    //     reservations are destroyed by Rust's reverse drop order established by
    //     the declaration order (signing objects → signing_res → ticket →
    //     control_res → guard), so the guard releases LAST.
    out.fill(0);
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
    use crate::safety_record_store::backend::{
        SafetyBackend, SafetyBackendPolicy, TryLockDomainOutcome,
    };
    use crate::safety_record_store::decision_capture::{
        OwnedDecisionOutcome, OwningCapturePayload, PreparedDecisionInputLimits,
    };
    use crate::safety_record_store::profile::PinnedSafetyContext;
    use crate::safety_record_store::record::WireQc as StoreWireQc;
    use crate::safety_record_store::validate::FixtureCommittedHistory;
    use crate::signing_reservation_journal::{
        BindingDigest, DecisionBindingInput, ReservationOutcome, SigningJournalStorage,
        SigningKind, SigningOwnershipDomain, SigningPosition, SigningReservationJournal,
        DEFAULT_MAX_RESERVED_POSITIONS,
    };
    use crate::storage::{InMemoryConsensusStorage, StorageError};

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
    /// The wire `chain_id` the real engine stamps on the captured self-vote; the
    /// positive authority fixture expects exactly this.
    const MODEL_WIRE_CHAIN_ID: u32 = 1;

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
        // The captured self-vote carries wire `chain_id == MODEL_WIRE_CHAIN_ID`
        // and `epoch == 0`; the positive fixture's signing domain expects exactly
        // that wire chain id so the §2 wire-chain-id admission check is satisfied
        // naturally (the authorized epoch is the genesis-static 0).
        make_authority_wire(MODEL_WIRE_CHAIN_ID)
    }

    fn make_authority_wire(wire_chain_id: u32) -> ProposalVoteAuthority {
        let (mut pk, _sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        // Bounded provider contract (RUN 422 §4): the stored key is CLONED by the
        // provider, so the model owns that clone's backing for the signing working
        // set. Shrink to a len-exact capacity and assert the backing fits the
        // reserved conservative bound — a local, tested contract, not a claim that
        // an arbitrary provider satisfies it.
        pk.shrink_to_fit();
        assert!(
            pk.capacity() as u128 <= MODEL_MAX_PUBKEY_BYTES,
            "fixture provider public-key backing {} exceeds the model bound {}",
            pk.capacity(),
            MODEL_MAX_PUBKEY_BYTES
        );
        let mut keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)> = HashMap::new();
        keys.insert(ValidatorId::new(SIGNER_VID), (SUITE_PQ_RESERVED_1, pk));
        let domain = ProposalVoteSigningDomainV2::try_new(
            ChainId(0xD5D5_0000_0000_0001),
            wire_chain_id,
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

    /// A local test storage wrapper implementing the EXISTING
    /// [`SigningJournalStorage`] interface. It forwards every operation to an
    /// in-memory inner store, but can be armed to fail ONLY the single-record
    /// synced write (`put_signing_record_synced`) that `record_signed_result`
    /// issues. The reserve path uses `put_signing_record_and_metadata_synced`
    /// (unaffected) and `consume_for_signing` performs no storage write, so arming
    /// this wrapper injects a persistence failure SPECIFICALLY at
    /// `record_signed_result`, after a successful reservation/consumption and one
    /// signer invocation. No D10 production code is modified.
    struct RecordWriteFailingStorage {
        inner: Arc<InMemoryConsensusStorage>,
        fail_record_write: std::sync::atomic::AtomicBool,
    }
    impl RecordWriteFailingStorage {
        fn new() -> Self {
            Self {
                inner: Arc::new(InMemoryConsensusStorage::new()),
                fail_record_write: std::sync::atomic::AtomicBool::new(false),
            }
        }
        fn arm(&self) {
            self.fail_record_write
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl SigningJournalStorage for RecordWriteFailingStorage {
        fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get_signing_record(key)
        }
        fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            if self
                .fail_record_write
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(StorageError::Io(
                    "injected record_signed_result persistence failure".to_string(),
                ));
            }
            self.inner.put_signing_record_synced(key, value)
        }
        fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get_signing_metadata()
        }
        fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
            self.inner.put_signing_metadata_synced(value)
        }
        fn put_signing_record_and_metadata_synced(
            &self,
            record_key: &[u8],
            record_value: &[u8],
            metadata_value: &[u8],
        ) -> Result<(), StorageError> {
            self.inner
                .put_signing_record_and_metadata_synced(record_key, record_value, metadata_value)
        }
        fn for_each_signing_namespace_entry(
            &self,
            visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
        ) -> Result<(), StorageError> {
            self.inner.for_each_signing_namespace_entry(visitor)
        }
        fn signing_ownership_domain(&self) -> Arc<SigningOwnershipDomain> {
            self.inner.signing_ownership_domain()
        }
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

    /// Both accounting ledgers sampled together: the operational
    /// (`accounting_current`) and the aggregate (`accounting_aggregate_current`)
    /// charged totals. RUN 422 §4 requires observing BOTH directly around a model
    /// call — ledger equality on one partition alone is insufficient cleanup
    /// evidence.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LedgerSnapshot {
        operational: u128,
        aggregate: u128,
    }

    fn snapshot_ledgers(owner: &SafetyRecordOwner) -> LedgerSnapshot {
        LedgerSnapshot {
            operational: owner.backend_for_test().accounting_current(),
            aggregate: owner.backend_for_test().accounting_aggregate_current(),
        }
    }

    /// Read the borrowed envelope's pin provenance under a short-lived domain
    /// guard (a non-consuming observation that charges nothing). Used to prove the
    /// ORIGINAL pin provenance is unchanged across a model call: ledger equality
    /// alone does not establish provenance preservation (RUN 422 §4), so the
    /// fixed-size scalar provenance is compared directly while the envelope/pin
    /// stay borrowed and live.
    fn pin_provenance_now(
        owner: &SafetyRecordOwner,
        decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
    ) -> PreparedProvenance {
        let guard = owner.backend.lock_domain();
        owner
            .pin_provenance_locked(&guard, decided.payload().pin())
            .expect("pin provenance readable under the domain guard")
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
        let inner = ok_signer();
        // Count ACTUAL signer invocations at the boundary (RUN 422 §2).
        let signer = CountingSigner::new(&inner);
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();

        // RUN 422 §4 — observe BOTH ledgers and the pin provenance directly before
        // the model call, keeping the borrowed envelope/pin live for comparison.
        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner,
            &engine,
            &decided,
            &p1,
            &lim,
            None,
            &mut snapshot,
            &signer,
            &mut sink,
            &journal,
            &mut coord,
            ReconfirmPerturbation::None,
        );

        let signed_diag = match outcome {
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
                diag
            }
            other => panic!("expected Signed, got {other:?}"),
        };
        assert_eq!(sink.calls, 1, "exactly one sink call");
        // EXACTLY one signer invocation, counted at the boundary — NOT inferred
        // from the sink/coordination/outcome/digest (RUN 422 §2).
        assert_eq!(signer.calls(), 1, "exactly one signer invocation");
        assert_eq!(coord.calls, 1, "the coordination point is reached once");

        // RUN 422 §4 — BOTH ledgers are restored to their pre-call baseline and the
        // pin provenance + complete Vote are unchanged after the successful run.
        let ledgers_after = snapshot_ledgers(&owner);
        assert_eq!(
            ledgers_after, ledgers_before,
            "both operational and aggregate ledgers restored after success"
        );
        assert_eq!(
            pin_provenance_now(&owner, &decided),
            prov_before,
            "the original pin provenance is preserved across the successful run"
        );
        assert_eq!(decided.vote(), &base_vote, "the complete borrowed Vote is unchanged");

        // The acknowledged journal result contains the expected fixture signature.
        // Because this operation's result write was durably acknowledged IN THIS
        // PROCESS (`result_acked = true`), a re-reserve at the exact position and
        // binding returns `ExactRetryRetained` carrying the retained bytes, which
        // must equal the OK fixture's 8-byte little-endian preimage-length tag.
        // This is explicitly in-memory evidence of the recorded result, NOT
        // process-crash durability evidence.
        let (pos, binding) = expected_pos_binding(&pv, &base_vote);
        let expected_sig = (signed_diag.preimage_len as u64).to_le_bytes();
        match journal.reserve_for_sign(&pos, &binding) {
            Ok(ReservationOutcome::ExactRetryRetained(sig)) => {
                assert_eq!(
                    sig.as_slice(),
                    &expected_sig[..],
                    "acknowledged journal result must hold the fixture signature"
                );
            }
            other => panic!("expected ExactRetryRetained with the fixture signature, got {other:?}"),
        }

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
        let inner = ok_signer();
        let signer = CountingSigner::new(&inner);
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();
        // Wrong limits: a different validator count yields a different policy.
        let wrong = limits(&ctx_n(5));

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &wrong, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::PolicyRefused);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0);
        assert_eq!(signer.calls(), 0, "policy refusal invokes the signer zero times");
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
        let inner = ok_signer();
        let signer = CountingSigner::new(&inner);
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();
        // A mismatching proposal (different parent) breaks the observation's
        // exact-proposal correspondence under the held guard.
        let mut wrong_proposal = p1.clone();
        wrong_proposal.header.parent_block_id = [0x11; 32];

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &wrong_proposal, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::ObservationRefused);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0);
        assert_eq!(signer.calls(), 0, "observation refusal invokes the signer zero times");
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
        let inner = ok_signer();
        let signer = CountingSigner::new(&inner);
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::AuthorizationAdmitRefused);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0);
        assert_eq!(signer.calls(), 0, "admission refusal invokes the signer zero times");
        assert_no_reservation_made(&journal, &pv, &base_vote);
    }

    // ======================================================================
    // Scenario 2 (lifecycle) — advancing engine AND durable state to a NEW
    // consistent lock (L1) through supported operations makes the retained
    // L0 decision fail the model's unchanged-generation rule. Observation
    // still passes (engine lock == durable restriction == L1, and the
    // proposal/projection correspondence is intact), so the refusal is the
    // INTENDED LifecycleAmbiguous — NOT an earlier, unrelated observation
    // failure — and it occurs BEFORE any D10 reservation.
    // ======================================================================
    #[test]
    fn scenario2_lifecycle_refused_after_consistent_generation_advance() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, mut engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let inner = DigestRecordingSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
            seen: std::cell::Cell::new(None),
        };
        let signer = CountingSigner::new(&inner);
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();

        // Advance the ENGINE to lock the view-1 block (L1): the local self-vote
        // was already cast at capture, so validators 2 and 3 complete the L1
        // quorum. The engine lock moves L0 -> L1 and agrees with the durable
        // advance below.
        let l0_block = derive_block_id_local(1, 0, &[0xFF; 32]);
        let l1_block = derive_block_id_local(2, 1, &l0_block);
        assert!(
            engine
                .on_vote_event(ValidatorId::new(2), &logical_vote(1, l1_block, 2))
                .expect("peer vote 2 for L1 ingests")
                .is_none(),
            "two votes are short of the L1 quorum"
        );
        let r3 = engine
            .on_vote_event(ValidatorId::new(3), &logical_vote(1, l1_block, 3))
            .expect("peer vote 3 for L1 ingests");
        assert!(r3.is_some(), "the third vote forms the L1 quorum");
        let lk = engine.locked_qc().expect("engine now locks L1");
        assert_eq!(lk.block_id, l1_block, "engine lock advanced to L1");
        assert_eq!(lk.view, 1);

        // Advance the DURABLE restriction to the same L1 (strictly-increasing
        // lock view 0 -> 1), moving the authoritative revision 1 -> 2.
        let new_rev = publish_qc(&owner, &ctx, l1_block, 1, 1);
        assert_eq!(new_rev, 2, "the L1 publication advances the durable revision");

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(
            outcome,
            ModelFreshUseOutcome::LifecycleAmbiguous,
            "the retained L0 generation no longer matches the advanced L1 state"
        );
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0, "no coordination point reached before the lifecycle refusal");
        // Explicit boundary count — NOT inferred from the absence of a digest.
        assert_eq!(signer.calls(), 0, "zero signer invocations");
        assert!(inner.seen.get().is_none(), "the wrapped digest signer was never reached");
        assert_no_reservation_made(&journal, &pv, &base_vote);
    }
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

        let counting = CountingSigner::new(&signer);
        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &counting, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::AdvanceGenerationBeforeConfirm,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::AuthorizationConfirmRefused);
        assert_eq!(sink.calls, 0, "no signer/sink work after a confirm refusal");
        assert_eq!(
            counting.calls(),
            0,
            "original-ticket confirm refusal invokes the signer zero times"
        );
        // The D10 reservation obligation is preserved (reserve+consume happened
        // before confirm): a re-reserve at the exact position/binding, after
        // consumption without an acknowledged signed result, MUST be exactly
        // `PotentiallySigned` (RUN 422 §3). Any error, Conflict, Exhausted,
        // ExactRetryRetained, or FreshlyReserved fails this check.
        let (pos, binding) = expected_pos_binding(&pv, &base_vote);
        match journal.reserve_for_sign(&pos, &binding) {
            Ok(ReservationOutcome::PotentiallySigned) => {}
            other => panic!(
                "confirm-refusal must leave the consumed D10 obligation \
                 PotentiallySigned, got {other:?}"
            ),
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

        // A competing handle sharing the EXACT SAME `SafetyBackend` serialization
        // domain (a clone shares the inner `Arc<Mutex<SerializationDomain>>`).
        let peer_backend = owner.backend_for_test().clone();

        // Bounded handshake endpoints: a request to observe, and a result carrying
        // the single discriminated observation. No sleeps; every leg is bounded.
        let (req_tx, req_rx) = std::sync::mpsc::channel::<()>();
        let (res_tx, res_rx) = std::sync::mpsc::channel::<PeerDomainObservation>();
        let timeout = std::time::Duration::from_secs(10);

        let outcome = std::thread::scope(|scope| {
            // Competing peer: on the single request (raised at the fixed post-D10,
            // pre-signer observation point while the protected op holds the guard),
            // perform ONE non-blocking domain observation and report it back.
            let peer = scope.spawn(move || match req_rx.recv_timeout(timeout) {
                Ok(()) => {
                    let obs = match peer_backend.try_lock_domain_for_test() {
                        TryLockDomainOutcome::WouldBlock => PeerDomainObservation::WouldBlock,
                        TryLockDomainOutcome::Acquired(_g) => PeerDomainObservation::Acquired,
                        TryLockDomainOutcome::Poisoned => PeerDomainObservation::Poisoned,
                    };
                    let _ = res_tx.send(obs);
                }
                Err(_) => { /* no request: the hook's recv times out and fails the test */ }
            });

            let mut coord = ModelCoordinationHook::probing(req_tx, res_rx, timeout);
            let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            peer.join().expect("the bounded peer thread completes");
            // Assertions outside the guarded callback. A failed leg (timeout /
            // disconnect / missing observation) fails the test.
            assert!(!coord.failed, "every handshake leg must succeed");
            assert_eq!(coord.calls, 1, "the bounded coordination point ran once");
            assert_eq!(
                coord.last_excluded,
                Some(true),
                "the competing same-domain handle observed WouldBlock (exclusion holds)"
            );
            outcome
        });

        match outcome {
            ModelFreshUseOutcome::Signed(_) => {}
            other => panic!("expected Signed, got {other:?}"),
        }
        assert_eq!(sink.calls, 1, "exactly one sink publication");

        // After the protected operation released the guard, an ACTUAL eligible
        // `publish_locked` on that SAME backend succeeds with its expected revision
        // advance (the pre-publish authoritative revision was 1 after capture).
        let new_rev = publish_qc(&owner, &ctx, [0x5Au8; 32], 1, 1);
        assert_eq!(
            new_rev, 2,
            "an eligible post-release publication advances the authoritative revision"
        );
    }

    // ======================================================================
    // §5 — LIVE SIGNING-PHASE LEDGER OBSERVATION. At the fixed post-consume /
    // pre-sign point the control AND signing reservations (and the signing
    // objects) are live. A sampling hook reads BOTH accounting ledgers DIRECTLY
    // at that instant (a contemporaneous measurement, distinct from the
    // source-derived `baseline + control_charge() + signing_charge()` arithmetic)
    // and each observed value is asserted against its enforced cap.
    // ======================================================================
    #[test]
    fn live_signing_phase_ledgers_observed_within_caps() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let signer = ok_signer();
        let mut sink = ModelRecordingSink::new();
        // The sampling hook shares the SAME backend (a clone shares the inner
        // accountant), so it reads the true in-operation charge while the
        // reservations are live.
        let mut coord = ModelCoordinationHook::sampling(owner.backend_for_test().clone());
        let base_vote = decided.vote().clone();

        let op_cap = owner
            .backend_for_test()
            .accounting_cap()
            .expect("bounded operational cap");
        let agg_cap = owner
            .backend_for_test()
            .accounting_aggregate_cap()
            .expect("bounded aggregate cap");
        let baseline = snapshot_ledgers(&owner);

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert!(matches!(outcome, ModelFreshUseOutcome::Signed(_)), "expected Signed, got {outcome:?}");
        assert_eq!(coord.calls, 1, "the live observation point ran once");

        // The contemporaneous measurements exist (sampled inside the protected
        // sequence) and each lies within its enforced cap.
        let observed_op = coord.observed_operational.expect("operational charge sampled live");
        let observed_agg = coord.observed_aggregate.expect("aggregate charge sampled live");
        assert!(
            observed_op <= op_cap,
            "live operational charge {observed_op} within the operational cap {op_cap}"
        );
        assert!(
            observed_agg <= agg_cap,
            "live aggregate charge {observed_agg} within the aggregate cap {agg_cap}"
        );
        // The reservations really were live at the sample (both ledgers above the
        // live baseline that excludes the model's own reservations).
        assert!(
            observed_op > baseline.operational && observed_agg > baseline.aggregate,
            "the live sample reflects the model's own live reservations"
        );
        // Cross-check: the live operational and aggregate measurements equal the
        // source-derived charge arithmetic (control + signing held; lifecycle
        // already released). Reported separately from the direct measurement.
        let derived = control_charge() + signing_charge();
        assert_eq!(
            observed_op - baseline.operational,
            derived,
            "live operational delta matches the source-derived control+signing charge"
        );
        assert_eq!(
            observed_agg - baseline.aggregate,
            derived,
            "live aggregate delta matches the source-derived control+signing charge"
        );

        // Both ledgers are restored after the run and the borrowed Vote is intact.
        assert_eq!(snapshot_ledgers(&owner), baseline, "both ledgers restored after the run");
        assert_eq!(decided.vote(), &base_vote, "the complete borrowed Vote is unchanged");
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
        // After consumption WITHOUT an acknowledged signed result, a re-reserve at
        // the exact same position/binding MUST be exactly `PotentiallySigned`
        // (RUN 422 §3). An error, Conflict, Exhausted, ExactRetryRetained, or
        // FreshlyReserved all fail this check — the wildcard "anything but fresh"
        // acceptance is withdrawn.
        let (pos, binding) = expected_pos_binding(pv, base_vote);
        match journal.reserve_for_sign(&pos, &binding) {
            Ok(ReservationOutcome::PotentiallySigned) => {}
            other => panic!(
                "the consumed D10 obligation must be exactly PotentiallySigned, \
                 got {other:?}"
            ),
        }
    }

    fn run_with_signer(
        dir: &std::path::Path,
        signer: &dyn BoundedVoteSigner,
    ) -> (ModelFreshUseOutcome, u32, u32, SigningReservationJournal, ProposalVoteAuthority, Vote) {
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir, &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let base_vote = decided.vote().clone();
        // Count ACTUAL signer invocations at the boundary (RUN 422 §2) rather than
        // inferring them from the sink/outcome.
        let counting = CountingSigner::new(signer);
        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &counting, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        (outcome, sink.calls, counting.calls(), journal, pv, base_vote)
    }

    #[test]
    fn scenario5_empty_written_no_sink_obligation_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let signer = EmptyFixtureSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
        };
        let (outcome, sink_calls, signer_calls, journal, pv, base_vote) =
            run_with_signer(dir.path(), &signer);
        assert_eq!(outcome, ModelFreshUseOutcome::EmptyWritten);
        assert_eq!(sink_calls, 0);
        // Exactly one signer invocation and zero sink calls (RUN 422 §2).
        assert_eq!(signer_calls, 1, "empty-output fault invokes the signer exactly once");
        assert_d10_obligation_preserved(&journal, &pv, &base_vote);
    }

    #[test]
    fn scenario5_oversize_written_no_sink_obligation_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let signer = OversizeFixtureSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
        };
        let (outcome, sink_calls, signer_calls, journal, pv, base_vote) =
            run_with_signer(dir.path(), &signer);
        assert_eq!(outcome, ModelFreshUseOutcome::OversizeWritten);
        assert_eq!(sink_calls, 0);
        assert_eq!(signer_calls, 1, "oversize-length fault invokes the signer exactly once");
        assert_d10_obligation_preserved(&journal, &pv, &base_vote);
    }

    #[test]
    fn scenario5_signer_error_no_sink_obligation_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ErrorFixtureSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
        };
        let (outcome, sink_calls, signer_calls, journal, pv, base_vote) =
            run_with_signer(dir.path(), &signer);
        assert_eq!(outcome, ModelFreshUseOutcome::SignerFailed);
        assert_eq!(sink_calls, 0);
        assert_eq!(signer_calls, 1, "signer-error fault invokes the signer exactly once");
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
        let counting = CountingSigner::new(&signer);
        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &counting, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::RetainedBlocked);
        assert_eq!(sink.calls, 0, "no sink on a retained-blocked outcome");
        assert_eq!(coord.calls, 0, "no coordination/signing after retained block");
        assert_eq!(counting.calls(), 0, "retained-blocked outcome adds zero new signer calls");
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

        // Baseline active reservations BEFORE the model call, on BOTH ledgers (the
        // retained pin from `decided` is part of this baseline and is unchanged
        // across the call). Cleanup is established from both ledgers directly, not
        // an inferred aggregate total.
        let baseline = owner.backend_for_test().accounting_current();
        let baseline_agg = owner.backend_for_test().accounting_aggregate_current();

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert!(matches!(outcome, ModelFreshUseOutcome::Signed(_)));

        // Exact cleanup on BOTH ledgers: every model reservation released, back to
        // the operational AND aggregate baselines.
        let after = owner.backend_for_test().accounting_current();
        let after_agg = owner.backend_for_test().accounting_aggregate_current();
        assert_eq!(after, baseline, "operational reservations released after the run");
        assert_eq!(
            after_agg, baseline_agg,
            "aggregate reservations released after the run"
        );

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
        // Emit the charge table for the report (visible under --nocapture). The
        // accountant's lifetime `peak` is the max over the WHOLE process including
        // fixture setup (capture/publish), so it is labelled a lifetime peak, not
        // attributed to the model alone; the model's own live phase charge is
        // `baseline + control + signing` at the signing phase.
        let agg_peak = owner.backend_for_test().accounting_aggregate_peak();
        let model_signing_phase = baseline + c_ctrl + c_sign;
        eprintln!(
            "RUN422-MODEL charges: control={c_ctrl} lifecycle={c_life} signing(C_sign)={c_sign} \
             baseline={baseline} model_signing_phase_live={model_signing_phase} \
             accountant_lifetime_peak={peak} accountant_lifetime_aggregate_peak={agg_peak} \
             vote_size={} preimage_vec={} out_cap={}",
            std::mem::size_of::<Vote>(),
            std::mem::size_of::<Vec<u8>>(),
            MODEL_SIG_CAP,
        );
    }

    // ======================================================================
    // §2 — BINDING EVIDENCE. The ACTUAL signer input matches an independently
    // computed preimage of the envelope's COMPLETE Vote, with ONLY the permitted
    // governed suite assignment differing from the captured envelope.
    // ======================================================================
    #[test]
    fn signer_input_matches_independent_envelope_preimage() {
        use sha3::Digest;
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        // Independently derive the expected preimage from the envelope's COMPLETE
        // Vote, applying ONLY the permitted governed suite assignment.
        let base_vote = decided.vote().clone();
        let mut expected_vote = base_vote.clone();
        expected_vote.suite_id = MODEL_SUITE_U16;
        // The ONLY permitted difference is `suite_id`: every other field is taken
        // verbatim from the captured envelope.
        assert_eq!(expected_vote.version, base_vote.version);
        assert_eq!(expected_vote.chain_id, base_vote.chain_id);
        assert_eq!(expected_vote.epoch, base_vote.epoch);
        assert_eq!(expected_vote.height, base_vote.height);
        assert_eq!(expected_vote.round, base_vote.round);
        assert_eq!(expected_vote.step, base_vote.step);
        assert_eq!(expected_vote.block_id, base_vote.block_id);
        assert_eq!(expected_vote.validator_index, base_vote.validator_index);
        assert_eq!(expected_vote.signature, base_vote.signature);
        let expected_preimage = pv.signing_domain.vote_preimage(&expected_vote);
        let mut h = Sha3_256::new();
        h.update(&expected_preimage);
        let mut expected_digest = [0u8; 32];
        expected_digest.copy_from_slice(&h.finalize());

        let inner = DigestRecordingSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
            seen: std::cell::Cell::new(None),
        };
        let signer = CountingSigner::new(&inner);
        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert!(matches!(outcome, ModelFreshUseOutcome::Signed(_)));
        assert_eq!(sink.calls, 1, "exactly one sink call");
        // Exactly one signer invocation, counted at the boundary — independent of
        // the digest recording that proves the input preimage (RUN 422 §2).
        assert_eq!(signer.calls(), 1, "exactly one signer invocation");
        let (seen_digest, seen_len) =
            inner.seen.get().expect("the signer recorded its single input");
        assert_eq!(
            seen_len,
            expected_preimage.len(),
            "the signer saw the full preimage length"
        );
        assert_eq!(
            seen_digest, expected_digest,
            "the signer input matched the independently computed envelope preimage"
        );
        // The captured envelope's Vote is unchanged (only the model's private
        // clone received the suite assignment).
        assert_eq!(decided.vote(), &base_vote);
    }

    // ======================================================================
    // §2 — WRONG WIRE CHAIN. The authorized snapshot expects a different wire
    // chain id than the engine stamped; refused BEFORE D10, zero signer calls.
    // ======================================================================
    #[test]
    fn wrong_wire_chain_refused_before_d10_zero_signer() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        // The authorized snapshot expects a DIFFERENT wire chain id than the real
        // engine stamped on the captured self-vote (1): a natural disagreement.
        let pv = make_authority_wire(0xDEAD_BEEF);
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let inner = DigestRecordingSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
            seen: std::cell::Cell::new(None),
        };
        let signer = CountingSigner::new(&inner);
        let base_vote = decided.vote().clone();

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::WrongWireChain);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0, "no coordination point reached before the refusal");
        assert_eq!(signer.calls(), 0, "zero signer invocations");
        assert!(inner.seen.get().is_none(), "the wrapped signer was never reached");
        assert_no_reservation_made(&journal, &pv, &base_vote);
    }

    // ======================================================================
    // §2 — WRONG AUTHORIZED EPOCH. The model-owned working Vote (never the
    // captured envelope) is deterministically bumped so its epoch disagrees with
    // the genesis-static authorized epoch (both fixed at 0); refused BEFORE D10,
    // zero signer calls.
    // ======================================================================
    #[test]
    fn wrong_authorized_epoch_refused_before_d10_zero_signer() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let inner = DigestRecordingSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
            seen: std::cell::Cell::new(None),
        };
        let signer = CountingSigner::new(&inner);
        let base_vote = decided.vote().clone();
        assert_eq!(base_vote.epoch, 0, "the engine self-vote epoch is 0");
        assert_eq!(snapshot.authorized_epoch(), 0, "authorized epoch is genesis-static 0");

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::BumpWorkingVoteEpoch,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::WrongAuthorizedEpoch);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0, "no coordination point reached before the refusal");
        assert_eq!(signer.calls(), 0, "zero signer invocations");
        assert!(inner.seen.get().is_none(), "the wrapped signer was never reached");
        assert_no_reservation_made(&journal, &pv, &base_vote);
        // The captured envelope is untouched by the model-owned perturbation.
        assert_eq!(decided.vote(), &base_vote);
        assert_eq!(decided.vote().epoch, 0);
    }

    // ======================================================================
    // §2 — UNSIGNED-INPUT PRECONDITION. The unsigned-input guard (signature empty
    // AND zero capacity before copying) is fail-closed. The sealed `DecidedVote`
    // envelope is immutable and the real engine self-vote is always unsigned, so a
    // populated-signature input is structurally unreachable here; this documents
    // the precondition the guard defends (it is never silently discarded).
    // ======================================================================
    #[test]
    fn captured_self_vote_is_unsigned_with_zero_capacity_signature() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (_owner, _engine, decided, _p1, _lim, _rev) = capture_multi(dir.path(), &ctx);
        assert!(
            decided.vote().signature.is_empty(),
            "the captured self-vote signature is empty"
        );
        assert_eq!(
            decided.vote().signature.capacity(),
            0,
            "the captured self-vote signature has zero backing capacity"
        );
    }

    // ======================================================================
    // §5 — ACCOUNTING EXHAUSTION at CONTROL admission (the FIRST model
    // reservation). A HEALTHY authorization owner is used, so the refusal is the
    // accounting exhaustion, NOT an unavailable owner. Refused before any ticket,
    // D10, coordination, or signer work.
    // ======================================================================
    #[test]
    fn accounting_exhaustion_at_control_admission_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let inner = DigestRecordingSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
            seen: std::cell::Cell::new(None),
        };
        let signer = CountingSigner::new(&inner);
        let base_vote = decided.vote().clone();

        // RUN 422 §4 step 1 — snapshot BOTH ledgers before any pressure, with the
        // envelope/pin live. This baseline already includes the standing registry
        // charge carried by the fixture setup.
        let ledgers_original = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

        let cap = owner
            .backend_for_test()
            .accounting_aggregate_cap()
            .expect("bounded aggregate cap");
        let current = owner.backend_for_test().accounting_aggregate_current();
        // Leave strictly less than control_charge() headroom on the binding
        // (aggregate) ledger so the control reservation (the first model
        // reservation) cannot be admitted.
        let standing = cap - current - (control_charge() - 1);
        let pressure = owner
            .backend_for_test()
            .reserve_standing_for_test(standing)
            .expect("standing reservation fits under the cap");

        // RUN 422 §4 step 2 — snapshot BOTH ledgers with the temporary pressure
        // held (the pressure-held baseline the refusal must restore to).
        let ledgers_pressure = snapshot_ledgers(&owner);

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::AuthorizationAdmitRefused);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0);
        assert_eq!(signer.calls(), 0, "zero signer invocations");
        assert!(inner.seen.get().is_none(), "the wrapped signer was never reached");

        // RUN 422 §4 step 3 — after the refusal BOTH ledgers are restored exactly
        // to the pressure-held baseline (the model released every reservation it
        // took before refusing).
        assert_eq!(
            snapshot_ledgers(&owner),
            ledgers_pressure,
            "both ledgers restored to the pressure-held baseline after the control refusal"
        );
        // Pin provenance and the complete Vote are unchanged across the refusal.
        assert_eq!(
            pin_provenance_now(&owner, &decided),
            prov_before,
            "pin provenance preserved across the control-admission refusal"
        );
        assert_eq!(decided.vote(), &base_vote, "the complete borrowed Vote is unchanged");
        // Non-mutating postcondition: the refusal left NO reserved journal position
        // (observed WITHOUT reserving it, so the retry below can reuse it).
        assert_eq!(
            journal.reserved_position_count(),
            0,
            "control refusal leaves no reserved D10 position"
        );

        // RUN 422 §4 step 4 — drop the pressure and require restoration to the
        // ORIGINAL baseline.
        drop(pressure);
        assert_eq!(
            snapshot_ledgers(&owner),
            ledgers_original,
            "both ledgers restored to the original baseline once pressure is dropped"
        );

        // RUN 422 §4 step 5 — retry the previously refused but now-admissible
        // operation using the SAME envelope and journal: it succeeds.
        let mut sink2 = ModelRecordingSink::new();
        let mut coord2 = ModelCoordinationHook::inert();
        let signer2 = ok_signer();
        let outcome2 = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer2, &mut sink2, &journal, &mut coord2,
            ReconfirmPerturbation::None,
        );
        assert!(
            matches!(outcome2, ModelFreshUseOutcome::Signed(_)),
            "after relief the admissible operation succeeds, got {outcome2:?}"
        );
        assert_eq!(sink2.calls, 1);
    }

    // ======================================================================
    // §5 — ACCOUNTING EXHAUSTION at SIGNING-WORKING-SET admission, isolated from
    // the earlier control/lifecycle phases, then SUCCESS after the pressure is
    // removed. The phase seam: the standing pressure leaves enough headroom for
    // the held control reservation AND the transient lifecycle load, but less than
    // signing_charge(), so the later signing admission is the refusal point.
    // ======================================================================
    #[test]
    fn accounting_exhaustion_at_signing_admission_then_succeeds_after_relief() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let inner = DigestRecordingSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
            seen: std::cell::Cell::new(None),
        };
        let signer = CountingSigner::new(&inner);
        let base_vote = decided.vote().clone();

        // RUN 422 §4 step 1 — snapshot BOTH ledgers before any pressure.
        let ledgers_original = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

        let cap = owner
            .backend_for_test()
            .accounting_aggregate_cap()
            .expect("bounded aggregate cap");
        let current = owner.backend_for_test().accounting_aggregate_current();
        // Target: available at signing admission == signing_charge() - 1 (one byte
        // short) on the binding (aggregate) ledger, while control is held and the
        // transient lifecycle phase already succeeded.
        let standing = cap - current - control_charge() - (signing_charge() - 1);
        let pressure = owner
            .backend_for_test()
            .reserve_standing_for_test(standing)
            .expect("standing reservation fits under the cap");

        // RUN 422 §4 step 2 — snapshot BOTH ledgers with the pressure held.
        let ledgers_pressure = snapshot_ledgers(&owner);

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(
            outcome,
            ModelFreshUseOutcome::SigningAdmitRefused,
            "the signing working set cannot be admitted (control/lifecycle already passed)"
        );
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0, "no coordination point reached before the signing refusal");
        assert_eq!(signer.calls(), 0, "zero signer invocations");
        assert!(inner.seen.get().is_none(), "the wrapped signer was never reached");

        // RUN 422 §4 step 3 — after the refusal BOTH ledgers are restored exactly
        // to the pressure-held baseline (the held control reservation and the
        // transient lifecycle load were released).
        assert_eq!(
            snapshot_ledgers(&owner),
            ledgers_pressure,
            "both ledgers restored to the pressure-held baseline after the signing refusal"
        );
        assert_eq!(
            pin_provenance_now(&owner, &decided),
            prov_before,
            "pin provenance preserved across the signing-admission refusal"
        );
        assert_eq!(decided.vote(), &base_vote, "the complete borrowed Vote is unchanged");
        // Non-destructive: the refusal left NO reserved position (the journal is
        // untouched, so the retry below can reuse it) — observed WITHOUT reserving.
        assert_eq!(journal.reserved_position_count(), 0, "no D10 reservation on a signing refusal");

        // RUN 422 §4 step 4 — remove the temporary pressure and require restoration
        // to the ORIGINAL baseline.
        drop(pressure);
        assert_eq!(
            snapshot_ledgers(&owner),
            ledgers_original,
            "both ledgers restored to the original baseline once pressure is dropped"
        );

        // RUN 422 §4 step 5 — retry the previously refused but admissible operation
        // on the SAME (clean) journal: it now succeeds.
        let mut sink2 = ModelRecordingSink::new();
        let mut coord2 = ModelCoordinationHook::inert();
        let signer2 = ok_signer();
        let outcome2 = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer2, &mut sink2, &journal, &mut coord2,
            ReconfirmPerturbation::None,
        );
        assert!(
            matches!(outcome2, ModelFreshUseOutcome::Signed(_)),
            "after relief the admissible operation succeeds, got {outcome2:?}"
        );
        assert_eq!(sink2.calls, 1);
    }

    // ======================================================================
    // §5 — PERSISTENCE FAILURE injected SPECIFICALLY during `record_signed_result`
    // (after a successful reservation/consumption and ONE signer invocation),
    // using a local storage wrapper over the existing journal-storage interface.
    // The sink is suppressed and the post-consumption journal state is inspected:
    // a retry is `PotentiallySigned` (the signer may already have run), NOT fresh.
    // This is an IN-MEMORY journal-state test, not crash-durability evidence.
    // ======================================================================
    #[test]
    fn persistence_failure_during_record_signed_result_suppresses_sink() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let store = Arc::new(RecordWriteFailingStorage::new());
        let journal =
            SigningReservationJournal::initialize(store.clone(), DEFAULT_MAX_RESERVED_POSITIONS)
                .expect("initialize journal over the wrapper store");
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let inner = DigestRecordingSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
            seen: std::cell::Cell::new(None),
        };
        let signer = CountingSigner::new(&inner);
        let base_vote = decided.vote().clone();

        // Arm the wrapper to fail ONLY the record_signed_result single-record
        // write. Reserve + consume (which do not use that write) still succeed.
        store.arm();

        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &signer, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::PersistFailed);
        assert_eq!(sink.calls, 0, "the sink is suppressed on a persistence failure");
        // The signer WAS invoked exactly once (persist fails AFTER signing), and
        // the sink zero times — counted at the boundary, not inferred (RUN 422 §2).
        assert_eq!(signer.calls(), 1, "exactly one signer invocation before the persist failure");
        assert!(
            inner.seen.get().is_some(),
            "the signer ran once before the persistence failure"
        );
        assert_eq!(coord.calls, 1, "the coordination point ran before signing");

        // Inspect the expected post-consumption journal state: a retry at the exact
        // position is PotentiallySigned (the obligation is preserved), NOT fresh.
        let (pos, binding) = expected_pos_binding(&pv, &base_vote);
        match journal.reserve_for_sign(&pos, &binding) {
            Ok(ReservationOutcome::PotentiallySigned) => {}
            other => panic!(
                "post-consumption retry must be PotentiallySigned, got {other:?}"
            ),
        }
    }
}