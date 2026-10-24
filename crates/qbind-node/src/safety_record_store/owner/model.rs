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
use crate::signing_reservation_journal::RefuseReason;
use crate::signing_reservation_journal::{
    AdmittedPublishError, AdmittedPublishOutcome, AdmittedReservationOutcome, AdmittedReserveError,
    BoundedDiag, RetirementOutcome,
};
use crate::signing_journal_admission::RetrievalWorkspaceOwner;
use crate::validator_signer::ValidatorSigner;

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
    ReserveLiveCapacityExhausted,
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
    /// The operational ledger charge sampled at the PRE-RESERVATION phase (after
    /// every composition resource — control, work, crypto, output, reserve
    /// workspace, continuation, and publish workspace — has been admitted but
    /// immediately BEFORE `reserve_for_sign_admitted`), if a sampling backend was
    /// installed. At this phase the reservation working set and its continuation
    /// coverage are BOTH still live (RUN 422 §2).
    pub(crate) observed_operational_pre_reserve: Option<u128>,
    /// The aggregate ledger charge sampled at the PRE-RESERVATION phase, if a
    /// sampling backend was installed.
    pub(crate) observed_aggregate_pre_reserve: Option<u128>,
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
            observed_operational_pre_reserve: None,
            observed_aggregate_pre_reserve: None,
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
            observed_operational_pre_reserve: None,
            observed_aggregate_pre_reserve: None,
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
            observed_operational_pre_reserve: None,
            observed_aggregate_pre_reserve: None,
        }
    }

    /// Pre-reservation ledger observation (RUN 422 §2). Sampled AFTER every
    /// composition resource has been admitted (control, work, crypto, output,
    /// reserve workspace, continuation, publish workspace) but immediately BEFORE
    /// `reserve_for_sign_admitted`, while the reservation working set (R) and its
    /// continuation coverage (T) are BOTH still live. Reads a separate accounting
    /// lock from the domain guard and charges nothing, so the measurement stays
    /// distinct from the objects whose coverage it demonstrates.
    fn on_pre_reservation(&mut self) {
        if let Some(b) = &self.sample_backend {
            self.observed_operational_pre_reserve = Some(b.accounting_current());
            self.observed_aggregate_pre_reserve = Some(b.accounting_aggregate_current());
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
// RUN 422 §3 — owned-object lifetime observer (release-order evidence).
//
// A bounded, model-only observer that records, IN ORDER, the destruction of the
// model's ACTUAL owned signing backings (the owned public-key lookup `Vec` and
// the preimage `Vec`) and the release of their covering signing reservation, so
// a test can assert every tracked backing is destroyed BEFORE the covering
// reservation releases. It is installed through a thread-local so no production
// signature or model call site changes; a run WITHOUT an installed probe pays
// only a null check and records nothing.
//
// This is OWNED-OBJECT LIFETIME evidence only. It does NOT trace allocator
// addresses, measure process RSS, or establish crash durability; ordering of the
// unobserved scope objects remains source-reasoned (Rust reverse-drop order).
//
// The probe itself is a CALLER-OWNED test fixture (an `Rc` created by the test),
// identified separately from the model's charged working set. The in-model
// wrappers (`TrackedBacking`, `TrackedReservation`) add only a pointer-sized
// `Option<Rc<..>>` and a `&'static str` label each — model-owned control objects
// that fit within the UNCHANGED signing-working-set reservation (the actual
// pubkey/preimage are far below their conservative `MODEL_MAX_*` backing bounds,
// leaving ample slack); no cap or charge is raised to accommodate them.
// ===========================================================================

#[derive(Default)]
struct ReleaseOrderState {
    /// Ordered event log of backing destructions and the reservation release.
    log: Vec<&'static str>,
    /// Labels of the tracked backings destroyed so far.
    fired_backings: Vec<&'static str>,
    /// Snapshot of `fired_backings` taken at the covering reservation's release
    /// boundary (set exactly once, when the covering reservation releases).
    release_snapshot: Option<Vec<&'static str>>,
}

/// Owned-object lifetime observer (RUN 422 §3). See the module comment above.
pub(crate) struct ReleaseOrderProbe {
    state: std::cell::RefCell<ReleaseOrderState>,
}

impl ReleaseOrderProbe {
    pub(crate) fn new() -> Self {
        Self {
            state: std::cell::RefCell::new(ReleaseOrderState::default()),
        }
    }

    fn record_backing(&self, label: &'static str) {
        let mut s = self.state.borrow_mut();
        s.fired_backings.push(label);
        s.log.push(label);
    }

    fn record_reservation_release(&self, label: &'static str) {
        let mut s = self.state.borrow_mut();
        // Snapshot which tracked backings have ALREADY been destroyed at the
        // instant the covering reservation is about to release. Recorded once.
        if s.release_snapshot.is_none() {
            let fired = s.fired_backings.clone();
            s.release_snapshot = Some(fired);
        }
        s.log.push(label);
    }

    /// True once the covering reservation's release boundary has been observed.
    pub(crate) fn release_observed(&self) -> bool {
        self.state.borrow().release_snapshot.is_some()
    }

    /// True iff EVERY `expected` tracked backing had already been destroyed at the
    /// covering reservation's release boundary (i.e. no covered backing remained
    /// live when the covering reservation released). False if the boundary was
    /// never observed or any expected backing was still live there.
    pub(crate) fn backings_destroyed_before_release(&self, expected: &[&'static str]) -> bool {
        let s = self.state.borrow();
        match &s.release_snapshot {
            Some(snap) => expected.iter().all(|e| snap.contains(e)),
            None => false,
        }
    }

    /// The ordered destruction/release event log, for diagnostics.
    pub(crate) fn event_log(&self) -> Vec<&'static str> {
        self.state.borrow().log.clone()
    }
}

thread_local! {
    /// The release-order probe installed for the CURRENT thread's model call, if
    /// any. `None` in normal runs — the model then records nothing.
    static RELEASE_ORDER_PROBE: std::cell::RefCell<Option<std::rc::Rc<ReleaseOrderProbe>>> =
        const { std::cell::RefCell::new(None) };
}

fn current_release_probe() -> Option<std::rc::Rc<ReleaseOrderProbe>> {
    RELEASE_ORDER_PROBE.with(|c| c.borrow().clone())
}

/// RAII installer for a release-order probe on the current thread; clears the
/// thread-local on drop so a panicking test cannot leak the probe onto a reused
/// test thread.
pub(crate) struct ReleaseProbeGuard;

impl Drop for ReleaseProbeGuard {
    fn drop(&mut self) {
        RELEASE_ORDER_PROBE.with(|c| *c.borrow_mut() = None);
    }
}

pub(crate) fn install_release_probe(probe: std::rc::Rc<ReleaseOrderProbe>) -> ReleaseProbeGuard {
    RELEASE_ORDER_PROBE.with(|c| *c.borrow_mut() = Some(probe));
    ReleaseProbeGuard
}

/// Wraps an ACTUAL owned signing backing (`Vec<u8>`) so its destruction is
/// recorded against the installed release-order probe (RUN 422 §3). The wrapper
/// OWNS the real buffer, so the recorded event fires at the buffer's genuine
/// destruction boundary — not at a co-located proxy.
struct TrackedBacking {
    buf: Vec<u8>,
    probe: Option<std::rc::Rc<ReleaseOrderProbe>>,
    label: &'static str,
}

impl TrackedBacking {
    fn new(
        buf: Vec<u8>,
        probe: Option<std::rc::Rc<ReleaseOrderProbe>>,
        label: &'static str,
    ) -> Self {
        Self { buf, probe, label }
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    fn capacity(&self) -> usize {
        self.buf.capacity()
    }
}

impl Drop for TrackedBacking {
    fn drop(&mut self) {
        if let Some(p) = &self.probe {
            p.record_backing(self.label);
        }
    }
}

/// Wraps the ACTUAL covering signing reservation so its release boundary is
/// recorded against the installed release-order probe (RUN 422 §3). `Drop::drop`
/// records the boundary while the inner reservation is still live, then the inner
/// reservation releases; by then every tracked backing declared AFTER this
/// wrapper has already been destroyed (Rust reverse-drop order).
struct TrackedReservation<R> {
    _res: R,
    probe: Option<std::rc::Rc<ReleaseOrderProbe>>,
    label: &'static str,
}

impl<R> TrackedReservation<R> {
    fn new(res: R, probe: Option<std::rc::Rc<ReleaseOrderProbe>>, label: &'static str) -> Self {
        Self {
            _res: res,
            probe,
            label,
        }
    }
}

impl<R> Drop for TrackedReservation<R> {
    fn drop(&mut self) {
        if let Some(p) = &self.probe {
            p.record_reservation_release(self.label);
        }
    }
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
    //    RUN 422 §3 — capture the installed release-order probe (None in normal
    //    runs) and wrap the covering signing reservation so its release boundary
    //    is observable relative to the owned backings destroyed below.
    let release_probe = current_release_probe();
    let signing_res_inner = match owner.backend.accounting().reserve(signing_charge()) {
        Ok(r) => r,
        Err(_) => return ModelFreshUseOutcome::SigningAdmitRefused,
    };
    let _signing_res =
        TrackedReservation::new(signing_res_inner, release_probe.clone(), "signing_res_release");

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
    let (position, binding, preimage, owned_pk, preimage_len) = {
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
    // RUN 422 §3 — wrap the ACTUAL owned signing backings (the preimage and the
    // owned public-key lookup `Vec`) so their destruction is observed relative to
    // the covering `signing_res` release. Declared AFTER `signing_res`, so Rust's
    // reverse-drop order destroys both backings BEFORE the covering reservation
    // releases on success and on every early return below.
    let _owned_pk = TrackedBacking::new(owned_pk, release_probe.clone(), "owned_pk_backing");
    let preimage = TrackedBacking::new(preimage, release_probe.clone(), "preimage_backing");
    debug_assert!(
        preimage.capacity() as u128 <= MODEL_MAX_PREIMAGE_BYTES,
        "wrapped preimage backing capacity exceeded the reserved bound"
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
        // Run 422 — compatibility arm (no model path enters bounded mode): an
        // explicit non-signing refusal, distinct from durable-position exhaustion.
        Ok(ReservationOutcome::LiveCapacityExhausted) => {
            return ModelFreshUseOutcome::ReserveLiveCapacityExhausted;
        }
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
    let n = match signer.sign_vote_into(preimage.as_slice(), &mut out[..]) {
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
// RUN 422 — Isolated Protected Retained-Signature USE model (TEST-ONLY).
//
// Sibling of `fresh_vote_sign_model`. This operation does NOT sign and performs
// NO D10 reservation/consumption/publication: it borrows the already-decided
// envelope's Vote (`decided.vote()`, never a clone or a suite-reassigned copy),
// retrieves an ALREADY-RETAINED signature through the admitted
// `retrieve_retained` path, cryptographically verifies that borrowed signature
// against the SAME Vote's canonical preimage, and consumes the verified result
// through a scalar-only sink — all under ONE serialization-domain guard acquired
// FIRST (released LAST). The unsigned-envelope invariant is preserved by
// construction: the canonical preimage is `signing_domain.vote_preimage(vote)`,
// which hashes `Vote::canonical_body()` — a body that EXCLUDES the `signature`
// field — so the preimage is independent of the (empty) envelope signature and
// the separately-retrieved journal signature is the ONLY signature verified.
// ===========================================================================

/// Fixed-size, `Copy` diagnostic the retained-use sink produces. Scalars only —
/// never the signature bytes, never an owned Vote. `preimage_len` is the checked
/// canonical-preimage length passed in EXPLICITLY by the model; the sink cannot
/// derive it from its `sig` argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetainedUseDiag {
    pub(crate) validator_index: u64,
    pub(crate) height: u64,
    pub(crate) round: u64,
    pub(crate) step: u8,
    pub(crate) suite_id: u16,
    pub(crate) sig_len: u32,
    pub(crate) preimage_len: u32,
}

/// Concrete recording sink for the VERIFIED retained signature. No callback, no
/// Vote return, no signature copy/retain: it records only the fixed scalar
/// diagnostic and a call count.
pub(crate) struct RetainedUseRecordingSink {
    pub(crate) last: Option<RetainedUseDiag>,
    pub(crate) calls: u32,
}

impl RetainedUseRecordingSink {
    pub(crate) fn new() -> Self {
        Self {
            last: None,
            calls: 0,
        }
    }

    /// Copy only fixed scalars out of `vote` plus the signature and preimage
    /// lengths; never clone or retain `sig`. `preimage_len` is passed explicitly
    /// (the sink cannot derive it from `sig`).
    pub(crate) fn consume_verified(
        &mut self,
        vote: &Vote,
        sig: &[u8],
        preimage_len: usize,
    ) -> RetainedUseDiag {
        let diag = RetainedUseDiag {
            validator_index: vote.validator_index as u64,
            height: vote.height,
            round: vote.round,
            step: vote.step,
            suite_id: vote.suite_id,
            sig_len: sig.len() as u32,
            preimage_len: preimage_len as u32,
        };
        self.calls = self.calls.saturating_add(1);
        self.last = Some(diag);
        diag
    }
}

/// Typed refusal class for a non-delivering `retrieve_retained` refusal (fixed
/// `Copy` codes mirrored from the journal's `RefuseReason`), kept DISTINCT from a
/// cryptographic verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetainedRefuseClass {
    PositionMismatch,
    MalformedRecord,
    BindingConflict,
    WorkspaceCapacityExceeded,
}

/// Fixed-size, `Copy` typed outcome of the retained-use model. Never forwards an
/// owned String. Every non-`Consumed` variant leaves the sink uncalled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ModelRetainedUseOutcome {
    /// The borrowed retrieved signature verified and was consumed (scalar
    /// diagnostic).
    Consumed(RetainedUseDiag),
    /// Owner-derived policy mismatch before locking.
    PolicyRefused,
    /// Control-coverage admission refused before the ticket was admitted.
    ControlAdmitRefused,
    /// The original authorization ticket could not be admitted.
    AuthorizationAdmitRefused,
    /// The existing held-guard observation did not revalidate.
    ObservationRefused,
    /// Lifecycle-comparison coverage admission refused before the loader ran.
    LifecycleAdmitRefused,
    /// The lifecycle comparison disagreed or could not be established.
    LifecycleAmbiguous,
    /// The Vote's signer is not in the authorized membership.
    MembershipRefused,
    /// The Vote's wire chain id disagreed with the authorized domain.
    WrongWireChain,
    /// The Vote's epoch disagreed with the authorized epoch.
    WrongAuthorizedEpoch,
    /// The governed key provider returned no key for the signer.
    KeyUnavailable,
    /// The governed suite disagreed with the original Vote's suite.
    SuiteMismatch,
    /// No verifier backend is registered for the governed suite.
    BackendUnavailable,
    /// Verification-working-set admission refused before any verify object was
    /// constructed.
    VerifyAdmitRefused,
    /// Retrieval-workspace admission refused; the verification inputs already
    /// existed and are destroyed before their coverage releases.
    RetrievalAdmitRefused,
    /// Retrieval refused conservatively because journal accounting is uncertain.
    RetainedBlocked,
    /// No record exists at the derived position.
    RetainedMissing,
    /// A typed, non-delivering retrieval refusal (position/binding/malformed/
    /// capacity), distinct from a cryptographic failure.
    RetainedRefused(RetainedRefuseClass),
    /// A reservation or live-unacknowledged result exists; no retained signature.
    RetainedPotentiallySigned,
    /// A recovered record's synced reissue failed/was uncertain; delivery
    /// suppressed. A successful reissue remains a permitted side effect even when
    /// later verification refuses; this variant is ONLY the suppressed case.
    DeliverySuppressed,
    /// A fatal retrieval error (lock/unsupported/storage).
    RetrievalFailed,
    /// The retrieved signature failed cryptographic verification.
    VerificationFailed,
    /// The original ticket failed its pre-consumption confirmation.
    AuthorizationConfirmRefused,
    /// AssociationChecked only: the additional verification-backend coverage
    /// (serialized public-key array + compiler-derived decoded public-key object +
    /// signature array + inline owned dispatch handle) was refused BEFORE the
    /// dispatch handle was constructed or verification was invoked.
    VerifyBackendAdmitRefused,
    /// AssociationChecked only: no operational accountant is installed in the
    /// journal's ownership-domain association (checked route has no legacy
    /// fallback). Surfaced from either `admit_retrieval_workspace` or
    /// `retrieve_retained_checked`.
    CheckedNoAssociation,
    /// AssociationChecked only: the retrieval workspace is not covered by the
    /// installed operational accountant. Defensive lower-level coverage: it is
    /// unreachable through this composition (the model always feeds
    /// installed-accountant workspaces into the checked retrieval), so it is
    /// surfaced as a distinct typed outcome without a manufactured foreign input.
    CheckedForeignWorkspace,
}

/// Accounting charge (bytes) for the retained-signature VERIFICATION working set,
/// admitted BEFORE any verification object is constructed (RUN 422 §3). It
/// conservatively bounds the simultaneously-live model-owned objects built from
/// the borrowed Vote: the owned public-key lookup result (`Vec<u8>` control plus
/// its backing capacity), the canonical preimage (`Vec<u8>` control plus backing)
/// and the canonical-body temporary (`Vec<u8>` control plus its bounded backing),
/// the position, the binding input, the hash state, and the binding digest.
///
/// It deliberately excludes a Vote-clone term (the model BORROWS `decided.vote()`
/// and never owns a Vote), and excludes every D10 term the fresh model charged
/// (continuation, publication capability, fixed output array): this operation
/// makes no fresh reservation and invokes no signer. The retrieval workspace
/// (output + envelope scratch) carries its OWN separate reservations admitted
/// later by `RetrievalWorkspaceOwner`, so it is not part of this charge. The
/// verifier backend is reached through a borrowed registry `Arc` dispatch handle
/// (a fixture-owned handle, not a model-owned key/preimage/binding/hash
/// temporary), so — consistent with the fresh model, which likewise reaches the
/// registry without charge — it is not charged here.
fn verify_charge() -> u128 {
    let pubkey_control = std::mem::size_of::<Vec<u8>>() as u128;
    let pubkey_backing = MODEL_MAX_PUBKEY_BYTES;
    let preimage_control = std::mem::size_of::<Vec<u8>>() as u128;
    let preimage_backing = MODEL_MAX_PREIMAGE_BYTES;
    let canonical_body_control = std::mem::size_of::<Vec<u8>>() as u128;
    let canonical_body_temp = MODEL_MAX_PREIMAGE_BYTES;
    let position = std::mem::size_of::<SigningPosition>() as u128;
    let binding_input = std::mem::size_of::<DecisionBindingInput<'static>>() as u128;
    let sha3 = std::mem::size_of::<Sha3_256>() as u128;
    let binding_digest = std::mem::size_of::<BindingDigest>() as u128;
    pubkey_control
        .saturating_add(pubkey_backing)
        .saturating_add(preimage_control)
        .saturating_add(preimage_backing)
        .saturating_add(canonical_body_control)
        .saturating_add(canonical_body_temp)
        .saturating_add(position)
        .saturating_add(binding_input)
        .saturating_add(sha3)
        .saturating_add(binding_digest)
}

/// Test-only admission stages at which [`retained_vote_use_model`] admits a
/// reservation. A test may install a one-shot pressure hook (see
/// `install_retained_admit_pressure_hook`) that reserves STANDING pressure at a
/// chosen stage so that exactly that admission refuses deterministically. This
/// does NOT weaken admission: it injects real accounting pressure, exactly as
/// the production observation-working-set hook does, and is required because the
/// held-guard observation's transient working-set peak (the validated-record
/// holder plus its working set) strictly dominates every LATER admission's
/// cumulative charge, so a single global pressure cannot isolate the lifecycle,
/// verify, or retrieval admissions as the first failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetainedAdmitStage {
    Lifecycle,
    Verify,
    /// AssociationChecked only: the additional verification-backend coverage,
    /// admitted BEFORE the owned dispatch handle is constructed or verification
    /// is invoked.
    VerifyBackend,
    Retrieval,
}

/// RUN 422 — private retained-retrieval route selection. The two routes share the
/// entire protected sequence EXCEPT the retrieval-workspace admission, the
/// retrieval call, and (checked only) the additional verification-backend
/// coverage. There is NO automatic fallback between them: a route is chosen once
/// by the caller and every refusal is surfaced as a typed outcome for that route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetainedRetrievalRoute {
    /// Existing seeded-test behavior: the model owns the retrieval workspace
    /// (`RetrievalWorkspaceOwner::new(&owner.backend)`) and calls the unchanged
    /// `retrieve_retained`. It admits NO verification-backend coverage; see the
    /// honest limitation noted on `verify_backend_wrapper_charge`.
    OwnerBacked,
    /// Opt-in checked route: the workspace is admitted through
    /// `journal.admit_retrieval_workspace()` (installed-accountant coverage) and
    /// retrieved through `journal.retrieve_retained_checked()`, and the additional
    /// verification-backend coverage is admitted before the dispatch handle.
    AssociationChecked,
}

/// RUN 422 §2 — the ADDITIONAL verification-backend working-set coverage, admitted
/// ONLY on the AssociationChecked route BEFORE the owned dispatch handle is
/// constructed or any verification object is built, and held across the
/// `verify_vote` call on every exit. It bounds the QBIND wrapper-owned objects the
/// verifier materializes that `verify_charge()` does NOT already cover:
///
/// - the serialized public-key array decoded inside the backend
///   (`ML_DSA_44_PUBLIC_KEY_SIZE`),
/// - the compiler-derived decoded public-key object
///   (`ML_DSA_44_PUBLIC_KEY_OBJECT_BYTES`, exported RUN 422 D7 — never the
///   hard-coded 4,192-byte evaluation),
/// - the fixed signature array handed to `verify`
///   (`ML_DSA_44_SIGNATURE_SIZE`), and
/// - the inline owned dispatch handle (`Arc<dyn ConsensusSigVerifier>`), charged
///   for its fat-pointer INLINE footprint only; its Arc-shared backend backing is
///   not re-charged here.
///
/// The constant automatically tracks the decoded object's INLINE size (a future
/// `fips204` change to the type's ownership shape — e.g. transitive heap — is NOT
/// reflected and would require rechecking). This term is kept SEPARATE from
/// `verify_charge()` and shares no sub-term with it, so there is no double count.
///
/// Honest limitation: the OwnerBacked route admits NO equivalent coverage; its
/// older accounting evidence therefore does NOT establish coverage for these
/// verifier-internal objects and must not be presented as if it did.
fn verify_backend_wrapper_charge() -> u128 {
    let serialized_public_key = qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE as u128;
    let decoded_public_key_object = qbind_crypto::ML_DSA_44_PUBLIC_KEY_OBJECT_BYTES as u128;
    let signature_array = qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE as u128;
    let dispatch_handle = std::mem::size_of::<
        std::sync::Arc<dyn qbind_crypto::consensus_sig::ConsensusSigVerifier>,
    >() as u128;
    serialized_public_key
        .saturating_add(decoded_public_key_object)
        .saturating_add(signature_array)
        .saturating_add(dispatch_handle)
}

thread_local! {
    #[allow(clippy::type_complexity)]
    static RETAINED_ADMIT_PRESSURE_HOOK: std::cell::RefCell<
        Option<Box<dyn Fn(RetainedAdmitStage)>>,
    > = const { std::cell::RefCell::new(None) };
}

/// Install a per-stage admission pressure hook on this thread. It fires once at
/// EACH admission stage below (passing that stage); the installed closure
/// decides whether to apply standing pressure. Cleared with
/// `clear_retained_admit_pressure_hook`.
fn install_retained_admit_pressure_hook<F: Fn(RetainedAdmitStage) + 'static>(f: F) {
    RETAINED_ADMIT_PRESSURE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

/// Clear any installed admission pressure hook on this thread.
fn clear_retained_admit_pressure_hook() {
    RETAINED_ADMIT_PRESSURE_HOOK.with(|h| *h.borrow_mut() = None);
}

/// Fire the admission pressure hook for `stage`, if installed. A no-op when no
/// hook is installed (the default on every production path; this whole module is
/// `#[cfg(test)]`).
fn fire_retained_admit_pressure(stage: RetainedAdmitStage) {
    RETAINED_ADMIT_PRESSURE_HOOK.with(|h| {
        if let Some(cb) = h.borrow().as_ref() {
            cb(stage);
        }
    });
}

// ===========================================================================
// RUN 422 §3 — bounded publication witness + thread-local RAII comparison probe.
// Both are test-harness-owned and kept ENTIRELY separate from operational
// accounting: neither reserves, releases, nor reads any ledger.
// ===========================================================================

/// A fixed-size, test-owned witness of the acknowledged publication's retained
/// signature. It holds a fixed `[u8; ML_DSA_44_SIGNATURE_SIZE]` buffer (never an
/// unbounded Vec) plus the validated length. It is prepared OUTSIDE the protected
/// retained operation and BEFORE that operation's I/O-counter window, by reading
/// the acknowledged `Signed` record for the exact position/binding through the
/// existing bounded read + parse interfaces and copying its signature in.
pub(crate) struct RetainedSliceWitness {
    bytes: [u8; qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE],
    len: usize,
}

impl RetainedSliceWitness {
    /// Build a witness from already-validated signature bytes. The caller validates
    /// framing/stage/binding/position before calling; this only enforces the fixed
    /// capacity and copies into the owned array.
    pub(crate) fn from_validated(sig: &[u8]) -> Self {
        let mut bytes = [0u8; qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE];
        let len = sig.len().min(bytes.len());
        bytes[..len].copy_from_slice(&sig[..len]);
        Self { bytes, len }
    }

    /// The validated witness slice (exactly `len` bytes).
    pub(crate) fn slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The validated witness length.
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RetainedSliceProbeState {
    invocations: u32,
    last_matched: Option<bool>,
    last_len: Option<usize>,
}

/// A read-only comparison probe. Fired by the model exactly once immediately
/// BEFORE the scalar sink, with the SAME retrieved slice that passed cryptographic
/// verification. It records ONLY fixed comparison results (a match flag and the
/// observed length) and an invocation count; it never retains the retrieved slice
/// and never panics inside the guarded observation (so a mismatch is surfaced via
/// recorded state, asserted by the test AFTER the protected call returns).
pub(crate) struct RetainedSliceProbe {
    witness: RetainedSliceWitness,
    state: std::cell::RefCell<RetainedSliceProbeState>,
}

impl RetainedSliceProbe {
    pub(crate) fn new(witness: RetainedSliceWitness) -> Self {
        Self {
            witness,
            state: std::cell::RefCell::new(RetainedSliceProbeState::default()),
        }
    }

    fn observe(&self, slice: &[u8]) {
        let mut st = self.state.borrow_mut();
        st.invocations = st.invocations.saturating_add(1);
        st.last_len = Some(slice.len());
        st.last_matched = Some(slice == self.witness.slice());
    }

    pub(crate) fn invocations(&self) -> u32 {
        self.state.borrow().invocations
    }

    pub(crate) fn last_matched(&self) -> Option<bool> {
        self.state.borrow().last_matched
    }

    pub(crate) fn last_len(&self) -> Option<usize> {
        self.state.borrow().last_len
    }
}

thread_local! {
    static RETAINED_SLICE_PROBE: std::cell::RefCell<Option<std::rc::Rc<RetainedSliceProbe>>> =
        const { std::cell::RefCell::new(None) };
}

/// RAII installer for the comparison probe on the current thread; clears the
/// thread-local on drop so a panicking test cannot leak the probe onto a reused
/// worker thread (reliable restoration, RUN 422 §3).
pub(crate) struct RetainedSliceProbeGuard {
    _private: (),
}

impl Drop for RetainedSliceProbeGuard {
    fn drop(&mut self) {
        RETAINED_SLICE_PROBE.with(|c| *c.borrow_mut() = None);
    }
}

pub(crate) fn install_retained_slice_probe(
    probe: std::rc::Rc<RetainedSliceProbe>,
) -> RetainedSliceProbeGuard {
    RETAINED_SLICE_PROBE.with(|c| *c.borrow_mut() = Some(probe));
    RetainedSliceProbeGuard { _private: () }
}

/// Fire the comparison probe with the verified retrieved slice, if installed. A
/// no-op when none is installed (every OwnerBacked path and every production
/// mirror), so it adds no behavior to the existing seeded route.
fn fire_retained_slice_probe(slice: &[u8]) {
    RETAINED_SLICE_PROBE.with(|c| {
        if let Some(p) = c.borrow().as_ref() {
            p.observe(slice);
        }
    });
}

/// Map a `RetainedDelivery` into either the borrowed retained signature or the
/// corresponding terminal `ModelRetainedUseOutcome`. Shared by BOTH retrieval
/// routes so the delivery-class mapping (Blocked/Missing/Refused/PotentiallySigned/
/// DeliverySuppressed) is identical; the routes differ only in their journal call
/// and the association errors handled by the caller. `DeliverySuppressed` is the
/// recovered-reissue outcome (RUN 422 §4) and stays distinct from
/// `PotentiallySigned`, which remains the separate live-entry classification.
fn map_retained_delivery(
    delivery: crate::signing_reservation_journal::RetainedDelivery<'_>,
) -> Result<&[u8], ModelRetainedUseOutcome> {
    use crate::signing_reservation_journal::RetainedDelivery;
    match delivery {
        RetainedDelivery::Retained(sig) => Ok(sig),
        RetainedDelivery::Blocked => Err(ModelRetainedUseOutcome::RetainedBlocked),
        RetainedDelivery::Missing => Err(ModelRetainedUseOutcome::RetainedMissing),
        RetainedDelivery::Refused(reason) => {
            let class = match reason {
                RefuseReason::PositionMismatch => RetainedRefuseClass::PositionMismatch,
                RefuseReason::MalformedRecord => RetainedRefuseClass::MalformedRecord,
                RefuseReason::BindingConflict => RetainedRefuseClass::BindingConflict,
                RefuseReason::WorkspaceCapacityExceeded => {
                    RetainedRefuseClass::WorkspaceCapacityExceeded
                }
            };
            Err(ModelRetainedUseOutcome::RetainedRefused(class))
        }
        RetainedDelivery::PotentiallySigned => {
            Err(ModelRetainedUseOutcome::RetainedPotentiallySigned)
        }
        RetainedDelivery::DeliverySuppressed => {
            Err(ModelRetainedUseOutcome::DeliverySuppressed)
        }
    }
}

/// RUN 422 — the isolated protected retained-signature USE model. ONE ordered
/// protected sequence under a SINGLE serialization-domain guard acquired FIRST
/// (dropped LAST). It borrows `decided.vote()` exclusively, retrieves an
/// already-retained signature, verifies it cryptographically, and consumes it
/// through a scalar sink. No fresh signing, D10 reservation/consumption, or
/// signed-result publication occurs.
///
/// Declaration order establishes the reverse-drop cleanup on EVERY exit:
/// guard -> control_res -> ticket -> (lifecycle scope, fully destroyed before the
/// verify phase) -> verify_res -> verify objects (owned pk, backend handle,
/// preimage, position, binding) -> retrieval workspace (output, scratch). Rust's
/// reverse-drop therefore releases: retrieval workspace -> verify objects ->
/// verify_res -> ticket -> control_res -> guard. The lifecycle objects and the
/// loader-owned validated record are destroyed and their coverage released at the
/// end of the bounded lifecycle scope, while the SAME guard stays held into the
/// verify/retrieval phase (no release-and-reacquire).
///
/// RUN 422 (checked composition) — this is the shared body for BOTH retrieval
/// routes, selected by `route`. The OwnerBacked route reproduces the original
/// seeded-test behavior exactly (model-owned workspace + `retrieve_retained`, no
/// verification-backend coverage). The AssociationChecked route admits the
/// additional verification-backend coverage BEFORE the dispatch handle, admits the
/// workspace through `journal.admit_retrieval_workspace()`, and retrieves through
/// `journal.retrieve_retained_checked()`. There is NO fallback between routes.
#[allow(clippy::too_many_arguments)]
fn retained_vote_use_inner<H: CommittedHistory + ?Sized>(
    route: RetainedRetrievalRoute,
    owner: &SafetyRecordOwner,
    engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
    decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
    proposal: &qbind_wire::consensus::BlockProposal,
    limits: &PreparedDecisionInputLimits,
    history: Option<&H>,
    snapshot: &mut AuthorizedProposalVoteSnapshot,
    sink: &mut RetainedUseRecordingSink,
    journal: &SigningReservationJournal,
    coord: &mut ModelCoordinationHook,
    reconfirm: ReconfirmPerturbation,
) -> ModelRetainedUseOutcome {
    use crate::genesis_consensus_authority::LocalAuthorizationState;

    // 1. Owner-derived policy BEFORE locking (no allocation).
    match PreparedDecisionInputLimits::from_pinned(owner.pinned()) {
        Ok(expected) => {
            if *limits != expected {
                return ModelRetainedUseOutcome::PolicyRefused;
            }
        }
        Err(_) => return ModelRetainedUseOutcome::PolicyRefused,
    }

    // The ONLY Vote used throughout: borrowed from the owning envelope. No clone,
    // no suite reassignment, no signature assignment.
    let vote: &Vote = decided.vote();

    // 2. Acquire the serialization domain ONCE and FIRST so it is released LAST.
    let guard = owner.backend.lock_domain();

    // 3. Admit control coverage BEFORE constructing the ticket; it stays live
    //    through the ticket's confirm and destruction.
    let _control_res = match owner.backend.accounting().reserve(control_charge()) {
        Ok(r) => r,
        Err(_) => return ModelRetainedUseOutcome::ControlAdmitRefused,
    };
    let ticket = match snapshot.owner().admit() {
        Ok(t) => t,
        Err(_) => return ModelRetainedUseOutcome::AuthorizationAdmitRefused,
    };

    // 4. Existing non-consuming observation under the held guard (locked-only).
    match owner.observe_checks_locked(&guard, engine, decided, proposal, limits, history) {
        RetainedDecisionObservation::Revalidated(
            BoundedSafetyOutcome::SafeViewSufficiency | BoundedSafetyOutcome::SafeAncestry { .. },
        ) => {}
        _ => return ModelRetainedUseOutcome::ObservationRefused,
    }

    // 5. Bounded lifecycle-check scope UNDER THE SAME GUARD, separately charged.
    //    The validated record (which carries its own loader holder reservation)
    //    and the lifecycle scalars are destroyed BEFORE the covering
    //    `lifecycle_res` releases, on both the agree path and every `?` exit.
    //    Admission refusal is DISTINCT from a lifecycle disagreement.
    fire_retained_admit_pressure(RetainedAdmitStage::Lifecycle);
    let lifecycle_res = match owner.backend.accounting().reserve(lifecycle_charge()) {
        Ok(r) => r,
        Err(_) => return ModelRetainedUseOutcome::LifecycleAdmitRefused,
    };
    let agree = (|| -> Option<bool> {
        let validated: ValidatedRecord = owner.load_current_validated_locked(&guard, history).ok()?;
        let current_identity = GenerationIdentity::from_retained(validated.retained())?;
        let current_revision = owner.authoritative_revision_locked(&guard).ok()?;
        let captured: PreparedProvenance = owner
            .pin_provenance_locked(&guard, decided.payload().pin())
            .ok()?;
        let (engine_lock_id, engine_lock_view) = match engine.locked_qc() {
            Some(qc) => (qc.block_id, qc.view),
            None => return None,
        };
        Some(
            captured.identity == current_identity
                && captured.captured_revision == current_revision
                && captured.recovery_backend_incarnation == owner.backend.incarnation()
                && engine_lock_id == current_identity.lock_block_id
                && engine_lock_view == current_identity.lock_view,
        )
    })();
    drop(lifecycle_res);
    match agree {
        Some(true) => {}
        _ => return ModelRetainedUseOutcome::LifecycleAmbiguous,
    }

    // 6. Membership / wire-chain / authorized-epoch checks on the borrowed Vote,
    //    BEFORE the verification working set is admitted (RUN 422 §2 step 7).
    let bound_id = ValidatorId::new(vote.validator_index as u64);
    if !snapshot.verifier().validators.contains(bound_id) {
        return ModelRetainedUseOutcome::MembershipRefused;
    }
    if vote.chain_id != snapshot.verifier().signing_domain.expected_wire_chain_id() {
        return ModelRetainedUseOutcome::WrongWireChain;
    }
    if vote.epoch != snapshot.authorized_epoch() {
        return ModelRetainedUseOutcome::WrongAuthorizedEpoch;
    }

    // 7. Admit the verification working set BEFORE constructing any verify object
    //    (RUN 422 §3). `verify_res` is declared before the verify objects, so they
    //    are all destroyed before it releases.
    fire_retained_admit_pressure(RetainedAdmitStage::Verify);
    let _verify_res = match owner.backend.accounting().reserve(verify_charge()) {
        Ok(r) => r,
        Err(_) => return ModelRetainedUseOutcome::VerifyAdmitRefused,
    };

    // 7b. AssociationChecked ONLY — admit the additional verification-backend
    //     coverage BEFORE the owned dispatch handle is constructed (step 8) or any
    //     verification object is built (step 11). Declared AFTER `_verify_res` so
    //     reverse-drop releases it BEFORE `_verify_res`, and AFTER every verify
    //     object (which are declared later), so coverage survives the `verify_vote`
    //     call on every exit. OwnerBacked admits none (honest limitation).
    let _verify_backend_res = match route {
        RetainedRetrievalRoute::OwnerBacked => None,
        RetainedRetrievalRoute::AssociationChecked => {
            fire_retained_admit_pressure(RetainedAdmitStage::VerifyBackend);
            match owner
                .backend
                .accounting()
                .reserve(verify_backend_wrapper_charge())
            {
                Ok(r) => Some(r),
                Err(_) => return ModelRetainedUseOutcome::VerifyBackendAdmitRefused,
            }
        }
    };

    // 8. Key/suite/backend selection and position/binding/preimage derivation,
    //    ALL from the SAME borrowed Vote and bound context. The owned public-key
    //    `Vec` the provider clones is model-owned and its backing capacity is
    //    checked against the reserved conservative bound. Any early refusal here
    //    unwinds the objects already built before `verify_res` releases.
    let key_suite_backend = {
        let ctx: &ProposalVoteAuthority = snapshot.verifier();
        match ctx.key_provider.get_suite_and_key(bound_id) {
            Some((gov_suite, pk)) => {
                if gov_suite != ConsensusSigSuiteId::new(vote.suite_id) {
                    Err(ModelRetainedUseOutcome::SuiteMismatch)
                } else {
                    match ctx.backend_registry.get_backend(gov_suite) {
                        Some(backend) => Ok((gov_suite, pk, backend)),
                        None => Err(ModelRetainedUseOutcome::BackendUnavailable),
                    }
                }
            }
            None => Err(ModelRetainedUseOutcome::KeyUnavailable),
        }
    };
    let (_gov_suite, owned_pk, backend) = match key_suite_backend {
        Ok(v) => v,
        Err(o) => return o,
    };
    debug_assert!(
        owned_pk.capacity() as u128 <= MODEL_MAX_PUBKEY_BYTES,
        "owned public-key backing capacity exceeded the reserved bound"
    );

    // Unsigned-envelope invariant (RUN 422 §1/§2): the canonical preimage hashes
    // `Vote::canonical_body()`, which EXCLUDES the `signature` field, so the
    // preimage is independent of the (empty) envelope signature. This is a
    // focused by-construction assertion, NOT control flow: the retrieved journal
    // signature is the only signature verified/consumed.
    debug_assert!(
        vote.signature.is_empty(),
        "the owning envelope's Vote carries no inline signature"
    );
    let preimage = snapshot.verifier().signing_domain.vote_preimage(vote);
    debug_assert!(
        preimage.capacity() as u128 <= MODEL_MAX_PREIMAGE_BYTES,
        "model preimage backing capacity exceeded the reserved bound"
    );
    let preimage_len = preimage.len();
    let position = SigningPosition {
        validator_id: vote.validator_index as u64,
        network_genesis: *snapshot.verifier().signing_domain.genesis_identity(),
        kind: SigningKind::Vote,
        originating_view: vote.height,
    };
    let binding = BindingDigest::compute(&DecisionBindingInput {
        position,
        authorized_epoch: vote.epoch,
        suite_id: vote.suite_id,
        wire_message_version: vote.version as u16,
        d6_signing_format_version: MODEL_D6_SIGNING_FORMAT_VERSION,
        authority_commitment: *snapshot.verifier().signing_domain.authority_commitment(),
        block_id: vote.block_id,
        canonical_preimage: &preimage,
    });

    // 9. Admit the retrieval workspace (output + envelope scratch) AFTER the
    //    verification inputs exist (RUN 422 §3). On refusal, those inputs are
    //    destroyed before `verify_res` releases (reverse-drop). The workspace
    //    carries its own separate reservations. OwnerBacked admits the workspace
    //    directly through a model-owned `RetrievalWorkspaceOwner`; AssociationChecked
    //    admits it through the journal's association-checked admission path.
    fire_retained_admit_pressure(RetainedAdmitStage::Retrieval);
    let (mut output, mut scratch) = match route {
        RetainedRetrievalRoute::OwnerBacked => {
            match RetrievalWorkspaceOwner::new(&owner.backend).admit() {
                Ok(ws) => ws,
                Err(_) => return ModelRetainedUseOutcome::RetrievalAdmitRefused,
            }
        }
        RetainedRetrievalRoute::AssociationChecked => {
            match journal.admit_retrieval_workspace() {
                Ok(ws) => ws,
                Err(crate::signing_reservation_journal::WorkspaceAdmissionError::NoAssociation) => {
                    return ModelRetainedUseOutcome::CheckedNoAssociation
                }
                Err(_) => return ModelRetainedUseOutcome::RetrievalAdmitRefused,
            }
        }
    };

    // 10. Retrieve the already-retained signature (no fresh reservation, no
    //     continuation, no publication capability, no signer). OwnerBacked uses the
    //     unconditional retrieval; AssociationChecked uses the association-checked
    //     retrieval, which additionally requires an installed ledger/workspace
    //     association and rejects a foreign workspace.
    let retrieved = match route {
        RetainedRetrievalRoute::OwnerBacked => {
            match journal.retrieve_retained(&position, &binding, &mut scratch, &mut output) {
                Ok(delivery) => match map_retained_delivery(delivery) {
                    Ok(sig) => sig,
                    Err(o) => return o,
                },
                Err(_) => return ModelRetainedUseOutcome::RetrievalFailed,
            }
        }
        RetainedRetrievalRoute::AssociationChecked => {
            match journal
                .retrieve_retained_checked(&position, &binding, &mut scratch, &mut output)
            {
                Ok(delivery) => match map_retained_delivery(delivery) {
                    Ok(sig) => sig,
                    Err(o) => return o,
                },
                Err(crate::signing_reservation_journal::CheckedRetrievalError::NoAssociation) => {
                    return ModelRetainedUseOutcome::CheckedNoAssociation
                }
                Err(crate::signing_reservation_journal::CheckedRetrievalError::ForeignWorkspace) => {
                    return ModelRetainedUseOutcome::CheckedForeignWorkspace
                }
                Err(_) => return ModelRetainedUseOutcome::RetrievalFailed,
            }
        }
    };

    // 11. Borrowed-signature cryptographic verification against the SAME Vote's
    //     canonical preimage and the governed key. `verify_vote` is a trait-object
    //     method on the registry-dispatched backend; it borrows the signature.
    if backend
        .verify_vote(
            vote.validator_index as u64,
            owned_pk.as_slice(),
            preimage.as_slice(),
            retrieved,
        )
        .is_err()
    {
        return ModelRetainedUseOutcome::VerificationFailed;
    }

    // 11.5 Deterministic in-flight current-authorization replacement strictly
    //      between the ORIGINAL ticket's admit and its pre-consumption confirm.
    if let ReconfirmPerturbation::AdvanceGenerationBeforeConfirm = reconfirm {
        snapshot
            .owner_mut()
            .replace_for_fixture(LocalAuthorizationState::MissingStorage);
    }

    // 12. Reconfirm the ORIGINAL ticket immediately before consumption.
    if snapshot.owner().confirm(&ticket).is_err() {
        return ModelRetainedUseOutcome::AuthorizationConfirmRefused;
    }

    // 13. Fixed observation point (publication exclusion): a competing same-domain
    //     handle observes `WouldBlock` here while this operation holds the guard.
    coord.on_post_consume_pre_sign();

    // 13b. RUN 422 §3 — fire the bounded read-only comparison probe (if a test
    //      installed one) with the SAME verified retrieved slice that is about to
    //      be consumed. No-op on OwnerBacked and production mirrors. The probe only
    //      records fixed results + an invocation count; it retains nothing and
    //      never panics, so it cannot perturb the protected sequence.
    fire_retained_slice_probe(retrieved);

    // 14. Scalar-only model consumption of the VERIFIED borrowed signature. The
    //     retrieval workspace, verify objects, reservations, ticket and guard are
    //     destroyed by reverse-drop order after this returns (guard LAST).
    let diag = sink.consume_verified(vote, retrieved, preimage_len);
    ModelRetainedUseOutcome::Consumed(diag)
}

/// OwnerBacked wrapper — preserves the EXACT original seeded-test behavior
/// (model-owned retrieval workspace + unconditional `retrieve_retained`, and NO
/// verification-backend coverage). All existing tests call this entry point and
/// are unaffected by the checked composition.
#[allow(clippy::too_many_arguments)]
fn retained_vote_use_model<H: CommittedHistory + ?Sized>(
    owner: &SafetyRecordOwner,
    engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
    decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
    proposal: &qbind_wire::consensus::BlockProposal,
    limits: &PreparedDecisionInputLimits,
    history: Option<&H>,
    snapshot: &mut AuthorizedProposalVoteSnapshot,
    sink: &mut RetainedUseRecordingSink,
    journal: &SigningReservationJournal,
    coord: &mut ModelCoordinationHook,
    reconfirm: ReconfirmPerturbation,
) -> ModelRetainedUseOutcome {
    retained_vote_use_inner(
        RetainedRetrievalRoute::OwnerBacked,
        owner,
        engine,
        decided,
        proposal,
        limits,
        history,
        snapshot,
        sink,
        journal,
        coord,
        reconfirm,
    )
}

/// AssociationChecked wrapper — the RUN 422 checked composition. It admits the
/// additional verification-backend coverage before the dispatch handle, admits the
/// retrieval workspace through `journal.admit_retrieval_workspace()`, and retrieves
/// through `journal.retrieve_retained_checked()`. There is NO fallback to the
/// OwnerBacked route: a missing association yields `CheckedNoAssociation`.
#[allow(clippy::too_many_arguments)]
fn retained_vote_use_checked_model<H: CommittedHistory + ?Sized>(
    owner: &SafetyRecordOwner,
    engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
    decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
    proposal: &qbind_wire::consensus::BlockProposal,
    limits: &PreparedDecisionInputLimits,
    history: Option<&H>,
    snapshot: &mut AuthorizedProposalVoteSnapshot,
    sink: &mut RetainedUseRecordingSink,
    journal: &SigningReservationJournal,
    coord: &mut ModelCoordinationHook,
    reconfirm: ReconfirmPerturbation,
) -> ModelRetainedUseOutcome {
    retained_vote_use_inner(
        RetainedRetrievalRoute::AssociationChecked,
        owner,
        engine,
        decided,
        proposal,
        limits,
        history,
        snapshot,
        sink,
        journal,
        coord,
        reconfirm,
    )
}

// ===========================================================================
// RUN 422 — Isolated ADMITTED REAL fresh-vote signing composition (TEST-ONLY).
//
// A third sibling model alongside `fresh_vote_sign_model` (legacy journal route,
// bounded FIXTURE signer, model-owned Vote clone with a permitted suite
// reassignment) and `retained_vote_use_model` (checked retrieval of an
// already-retained signature). This one BORROWS `decided.vote()` unchanged, uses
// the REAL caller-buffer `LocalKeySigner` ML-DSA-44 path, and drives the ADMITTED
// journal reservation/consumption/publication route under ONE safety-domain
// guard, finishing with an acknowledged journal publication, a single bounded
// publication retry policy, one post-acknowledgement retirement attempt, and a
// fixed-size scalar diagnostic. Nothing is wired into any production caller; it
// establishes no signing permission, freshness, or network-ready signed Vote.
//
// Suite note (isolation-honest): the engine stamps the self-vote's wire
// `suite_id` at `DEFAULT_CONSENSUS_SUITE_ID` (0), while the real `LocalKeySigner`
// and its ML-DSA-44 backend intrinsically require the signing suite 100. This
// model does NOT rewrite the borrowed Vote (unlike the production-mirroring
// `fresh_vote_sign_model`), so it enforces the signer<->authorized-key<->backend
// agreement at the signer's suite (100) while the canonical preimage/binding are
// derived verbatim from the borrowed Vote's OWN fields (wire suite 0). The result
// is therefore a test-only composition over the borrowed Vote's canonical body,
// NOT a network-ready signed Vote; the wire-suite-vs-signing-suite equality that
// production establishes by reassigning the suite is NOT claimed here.
// ===========================================================================

/// The result of the single post-acknowledgement retirement attempt. Reported
/// SEPARATELY from the publication acknowledgement: a retirement failure never
/// erases or relabels a `Published` acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetirementReport {
    /// `retire_admitted` acknowledged in-memory live-entry retirement.
    Retired,
    /// `retire_admitted` refused; the publication acknowledgement still stands.
    Failed,
}

/// Fixed-size, `Copy` diagnostic for the real-signer composition. It copies ONLY
/// scalar fields out of the borrowed Vote plus the signature/preimage LENGTHS,
/// whether exactly one bounded publication retry occurred, and the separate
/// retirement result — never the signature bytes, never an owned Vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RealSignDiag {
    pub(crate) validator_index: u64,
    pub(crate) height: u64,
    pub(crate) round: u64,
    pub(crate) step: u8,
    /// The BORROWED Vote's own wire suite (not rewritten; see the suite note).
    pub(crate) suite_id: u16,
    pub(crate) sig_len: u32,
    pub(crate) preimage_len: u32,
    /// True iff exactly one bounded `Storage(WriteIo)` publication retry occurred.
    pub(crate) republished: bool,
    pub(crate) retirement: RetirementReport,
}

/// The concrete recording sink for the real-signer composition: no callback, no
/// Vote return, no signature copy/retain. It records only the fixed scalar
/// diagnostic and a call count.
pub(crate) struct RealSignRecordingSink {
    pub(crate) last: Option<RealSignDiag>,
    pub(crate) calls: u32,
}

impl RealSignRecordingSink {
    pub(crate) fn new() -> Self {
        Self { last: None, calls: 0 }
    }

    /// Copy only fixed scalars out of `vote` plus the lengths and the bounded
    /// retry/retirement outcomes; never clone or retain signature bytes.
    fn record(
        &mut self,
        vote: &Vote,
        sig_len: usize,
        preimage_len: usize,
        republished: bool,
        retirement: RetirementReport,
    ) -> RealSignDiag {
        let diag = RealSignDiag {
            validator_index: vote.validator_index as u64,
            height: vote.height,
            round: vote.round,
            step: vote.step,
            suite_id: vote.suite_id,
            sig_len: sig_len as u32,
            preimage_len: preimage_len as u32,
            republished,
            retirement,
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
pub(crate) enum RealFreshSignOutcome {
    /// Acknowledged journal publication; carries the fixed-size diagnostic.
    Published(RealSignDiag),
    PolicyRefused,
    // Signer output-bound pre-checks (before the safety domain / any journal op).
    SignerBoundUnsupported,
    OutputCapacityRefused,
    ProfileRefused,
    // Authorization / observation / lifecycle under the guard.
    AuthorizationAdmitRefused,
    ObservationRefused,
    LifecycleAmbiguous,
    // Exact-Vote eligibility.
    SignedInputRejected,
    MembershipRefused,
    WrongWireChain,
    WrongAuthorizedEpoch,
    SuiteMismatch,
    KeyUnavailable,
    BackendUnavailable,
    // Resource admission (isolated, before any journal reservation/consumption).
    WorkSetAdmitRefused,
    CryptoAdmitRefused,
    OutputAdmitRefused,
    ReserveWorkspaceAdmitRefused,
    PublishWorkspaceAdmitRefused,
    // Admitted reservation classification (every existing-position class is
    // non-delivering in this helper).
    ReserveConflict,
    ReservePotentiallySigned,
    ReserveExhausted,
    ReserveLiveCapacityExhausted,
    ReserveWorkspaceCapacityExceeded,
    ReserveAccountingUncertain,
    ReserveStorage,
    ReserveFailed,
    // Consumption / original-ticket confirmation.
    ConsumeFailed,
    AuthorizationConfirmRefused,
    // Signer faults / returned-length validation.
    SignerFailed,
    EmptyWritten,
    OversizeWritten,
    WrongLength,
    // Publication faults (after at most one bounded WriteIo retry).
    PublishReadIo,
    PublishWriteIo,
    PublishDifferentResultRefused,
    PublishReservedForeignBinding,
    PublishPositionMismatch,
    PublishMalformedRecord,
    PublishNoRecord,
    PublishFailed,
}

// ===========================================================================
// Real-signer invocation COUNTER (delegates to any `&dyn ValidatorSigner`).
//
// It counts ACTUAL `sign_vote_into` calls at the real signing boundary
// (incremented BEFORE delegating, so a call that returns an error is still
// counted) and forwards every other trait method unchanged. `AtomicU32` keeps the
// wrapper `Send + Sync` (the `ValidatorSigner` supertrait requirement). It is a
// caller-owned fixture; it is NOT part of the composition's charged working set.
// ===========================================================================
pub(crate) struct CountingValidatorSigner<'a> {
    inner: &'a dyn ValidatorSigner,
    calls: std::sync::atomic::AtomicU32,
}

impl<'a> CountingValidatorSigner<'a> {
    pub(crate) fn new(inner: &'a dyn ValidatorSigner) -> Self {
        Self {
            inner,
            calls: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// The exact number of `sign_vote_into` invocations observed at the boundary.
    pub(crate) fn calls(&self) -> u32 {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl ValidatorSigner for CountingValidatorSigner<'_> {
    fn validator_id(&self) -> &ValidatorId {
        self.inner.validator_id()
    }
    fn suite_id(&self) -> u16 {
        self.inner.suite_id()
    }
    fn sign_proposal(&self, preimage: &[u8]) -> Result<Vec<u8>, crate::validator_signer::SignError> {
        self.inner.sign_proposal(preimage)
    }
    fn sign_vote(&self, preimage: &[u8]) -> Result<Vec<u8>, crate::validator_signer::SignError> {
        self.inner.sign_vote(preimage)
    }
    fn sign_timeout(
        &self,
        view: u64,
        high_qc: Option<&qbind_consensus::qc::QuorumCertificate<[u8; 32]>>,
    ) -> Result<Vec<u8>, crate::validator_signer::SignError> {
        self.inner.sign_timeout(view, high_qc)
    }
    fn sign_timeout_with_chain_id(
        &self,
        chain_id: qbind_types::ChainId,
        view: u64,
        high_qc: Option<&qbind_consensus::qc::QuorumCertificate<[u8; 32]>>,
    ) -> Result<Vec<u8>, crate::validator_signer::SignError> {
        self.inner
            .sign_timeout_with_chain_id(chain_id, view, high_qc)
    }
    fn signature_output_bound(&self) -> Result<usize, crate::validator_signer::BoundedSignError> {
        self.inner.signature_output_bound()
    }
    fn sign_vote_into(
        &self,
        preimage: &[u8],
        out: &mut [u8],
    ) -> Result<usize, crate::validator_signer::BoundedSignError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.sign_vote_into(preimage, out)
    }
}

// ===========================================================================
// Accounting charges for the real-signer composition.
// ===========================================================================

/// The composition's OWN signing working set (RUN 422 §5), mirroring the retained
/// `verify_charge` inventory: the owned public-key lookup `Vec` (control +
/// conservative backing), the preimage `Vec` (control + backing), the SEPARATE
/// canonical-body temporary `Vec` built inside `vote_preimage` (control +
/// backing), and the fixed-size position / binding-input / hashing / binding
/// objects. It does NOT cover the admitted output, reservation workspace,
/// continuation, publication workspace, or the crypto temporaries — each of those
/// is charged by its own reservation and must not be double-counted here.
fn real_sign_work_charge() -> u128 {
    let pubkey_control = std::mem::size_of::<Vec<u8>>() as u128;
    let pubkey_backing = MODEL_MAX_PUBKEY_BYTES;
    let preimage_control = std::mem::size_of::<Vec<u8>>() as u128;
    let preimage_backing = MODEL_MAX_PREIMAGE_BYTES;
    let canonical_body_control = std::mem::size_of::<Vec<u8>>() as u128;
    let canonical_body_temp = MODEL_MAX_PREIMAGE_BYTES;
    let position = std::mem::size_of::<SigningPosition>() as u128;
    let binding_input = std::mem::size_of::<DecisionBindingInput<'static>>() as u128;
    let sha3 = std::mem::size_of::<Sha3_256>() as u128;
    let binding_digest = std::mem::size_of::<BindingDigest>() as u128;
    pubkey_control
        .saturating_add(pubkey_backing)
        .saturating_add(preimage_control)
        .saturating_add(preimage_backing)
        .saturating_add(canonical_body_control)
        .saturating_add(canonical_body_temp)
        .saturating_add(position)
        .saturating_add(binding_input)
        .saturating_add(sha3)
        .saturating_add(binding_digest)
}

/// Crypto-temporary coverage (RUN 422 §5), admitted BEFORE the admitted journal
/// reservation and retained across the signer call. Derived from the ACTUAL owned
/// temporaries inside `MlDsa44Backend::sign_into`: the copied secret-key array
/// (`ML_DSA_44_SECRET_KEY_SIZE`), the decoded `fips204::ml_dsa_44::PrivateKey`
/// object (`ML_DSA_44_PRIVATE_KEY_OBJECT_BYTES`, exported RUN 422 D7 — never the
/// hard-coded 12,416-byte evaluation), and the fixed signature array
/// (`ML_DSA_44_SIGNATURE_SIZE`). Dependency-internal scratch, allocator overhead,
/// and physical stack are OUTSIDE this source-derived charge boundary; this is not
/// a process-memory bound.
fn crypto_temp_charge() -> u128 {
    (qbind_crypto::ml_dsa44::ML_DSA_44_SECRET_KEY_SIZE as u128)
        .saturating_add(qbind_crypto::ML_DSA_44_PRIVATE_KEY_OBJECT_BYTES as u128)
        .saturating_add(qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE as u128)
}

/// Test-only admission stages at which [`fresh_vote_sign_real_local`] admits a
/// reservation, mirroring [`RetainedAdmitStage`]. A test may install a per-stage
/// pressure hook (see `install_real_admit_pressure_hook`) that reserves STANDING
/// pressure at a chosen stage so exactly that admission refuses deterministically.
/// This injects real accounting pressure (it does NOT weaken admission) and is
/// required to isolate each later admission as the FIRST failure, because the
/// held-guard observation's transient working-set peak dominates the cumulative
/// charge of every admission after it. Model-only; this whole module is
/// `#[cfg(test)]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RealAdmitStage {
    WorkSet,
    Crypto,
    Output,
    ReserveWorkspace,
    PublishWorkspace,
}

thread_local! {
    #[allow(clippy::type_complexity)]
    static REAL_ADMIT_PRESSURE_HOOK: std::cell::RefCell<Option<Box<dyn Fn(RealAdmitStage)>>> =
        const { std::cell::RefCell::new(None) };
}

fn install_real_admit_pressure_hook<F: Fn(RealAdmitStage) + 'static>(f: F) {
    REAL_ADMIT_PRESSURE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

fn clear_real_admit_pressure_hook() {
    REAL_ADMIT_PRESSURE_HOOK.with(|h| *h.borrow_mut() = None);
}

fn fire_real_admit_pressure(stage: RealAdmitStage) {
    REAL_ADMIT_PRESSURE_HOOK.with(|h| {
        if let Some(cb) = h.borrow().as_ref() {
            cb(stage);
        }
    });
}

/// RUN 422 — the isolated protected ADMITTED REAL fresh-vote signing composition.
/// ONE ordered protected sequence under a SINGLE serialization-domain guard
/// acquired FIRST (dropped LAST). It borrows `decided.vote()` exclusively, signs
/// it once through the real caller-buffer `LocalKeySigner`, publishes through the
/// admitted journal route, and finishes with a fixed-size scalar diagnostic plus a
/// separate retirement result. No production caller, no legacy allocating signer
/// fallback, no network delivery.
#[allow(clippy::too_many_arguments)]
fn fresh_vote_sign_real_local<H: CommittedHistory + ?Sized>(
    owner: &SafetyRecordOwner,
    engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
    decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
    proposal: &qbind_wire::consensus::BlockProposal,
    limits: &PreparedDecisionInputLimits,
    history: Option<&H>,
    snapshot: &mut AuthorizedProposalVoteSnapshot,
    signer: &dyn ValidatorSigner,
    sink: &mut RealSignRecordingSink,
    journal: &SigningReservationJournal,
    coord: &mut ModelCoordinationHook,
    reconfirm: ReconfirmPerturbation,
) -> RealFreshSignOutcome {
    use crate::genesis_consensus_authority::LocalAuthorizationState;

    // 1. Owner-derived policy BEFORE acquiring the safety domain (no allocation).
    match PreparedDecisionInputLimits::from_pinned(owner.pinned()) {
        Ok(expected) => {
            if *limits != expected {
                return RealFreshSignOutcome::PolicyRefused;
            }
        }
        Err(_) => return RealFreshSignOutcome::PolicyRefused,
    }

    // The ONLY Vote used throughout: borrowed from the owning envelope. No clone,
    // no suite reassignment, no signature assignment.
    let vote: &Vote = decided.vote();

    // 2. Establish the checked signer output bound BEFORE any irreversible work
    //    and BEFORE acquiring the safety domain. Query it exactly once and retain
    //    the checked value. OUTPUT_CAP == ML_DSA_44_SIGNATURE_SIZE here, so an
    //    over-capacity bound is an output-capacity refusal and any other mismatch
    //    is a profile refusal.
    let bound = match signer.signature_output_bound() {
        Ok(b) => b,
        Err(_) => return RealFreshSignOutcome::SignerBoundUnsupported,
    };
    if bound > crate::signing_journal_admission::OUTPUT_CAP {
        return RealFreshSignOutcome::OutputCapacityRefused;
    }
    if bound != qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE {
        return RealFreshSignOutcome::ProfileRefused;
    }

    // 3. Acquire the serialization domain ONCE and FIRST so it is released LAST.
    let guard = owner.backend.lock_domain();

    // 4. Admit control coverage BEFORE constructing the ticket; obtain the
    //    ORIGINAL authorization ticket.
    let _control_res = match owner.backend.accounting().reserve(control_charge()) {
        Ok(r) => r,
        Err(_) => return RealFreshSignOutcome::AuthorizationAdmitRefused,
    };
    let ticket = match snapshot.owner().admit() {
        Ok(t) => t,
        Err(_) => return RealFreshSignOutcome::AuthorizationAdmitRefused,
    };

    // 5. Existing non-consuming held-guard observation (locked-only; SafeNoLock is
    //    NOT admitted). Does not reacquire the domain.
    match owner.observe_checks_locked(&guard, engine, decided, proposal, limits, history) {
        RetainedDecisionObservation::Revalidated(
            BoundedSafetyOutcome::SafeViewSufficiency | BoundedSafetyOutcome::SafeAncestry { .. },
        ) => {}
        _ => return RealFreshSignOutcome::ObservationRefused,
    }

    // 6. Conservative captured-versus-current lifecycle agreement UNDER THE SAME
    //    guard, in its separately charged scope. The validated record (carrying its
    //    own loader holder reservation) and the lifecycle scalars are destroyed
    //    BEFORE the covering reservation releases.
    let lifecycle = (|| -> Option<()> {
        let lifecycle_res = owner
            .backend
            .accounting()
            .reserve(lifecycle_charge())
            .ok()?;
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
        return RealFreshSignOutcome::LifecycleAmbiguous;
    }

    // 7. Exact-Vote eligibility on the BORROWED Vote, before admitting the
    //    composition working set. Unsigned-input precondition first (the owning
    //    envelope's Vote carries no inline signature; this is a control-flow
    //    refusal, not just an assertion).
    if !vote.signature.is_empty() {
        return RealFreshSignOutcome::SignedInputRejected;
    }
    let bound_id = ValidatorId::new(vote.validator_index as u64);
    if *signer.validator_id() != bound_id || !snapshot.verifier().validators.contains(bound_id) {
        return RealFreshSignOutcome::MembershipRefused;
    }
    if vote.chain_id != snapshot.verifier().signing_domain.expected_wire_chain_id() {
        return RealFreshSignOutcome::WrongWireChain;
    }
    if vote.epoch != snapshot.authorized_epoch() {
        return RealFreshSignOutcome::WrongAuthorizedEpoch;
    }
    // Suite agreement on the BORROWED Vote (RUN 422 §2 correction). The exact
    // borrowed Vote's suite must equal the selected signer's suite; combined with
    // the signer<->authorized-key<->backend agreement enforced in step 9, this
    // closes the required four-way (Vote, signer, key, backend) suite agreement
    // BEFORE any journal reservation, consumption, or signer call. The default
    // engine constructors stamp the self-vote at DEFAULT_CONSENSUS_SUITE_ID (0),
    // so a real suite-100 signer over a default suite-0 Vote is refused here with
    // zero journal and zero signer activity. The construction-only
    // `with_state_limits_and_vote_suite` selector can instead stamp a suite-100
    // outgoing Vote (metadata only, no authorization), letting this agreement HOLD
    // for the resumed eligible real-signing path (RUN 422 §6).
    if vote.suite_id != signer.suite_id() {
        return RealFreshSignOutcome::SuiteMismatch;
    }

    // 8. Admit the composition working set BEFORE constructing any covered object.
    let release_probe = current_release_probe();
    fire_real_admit_pressure(RealAdmitStage::WorkSet);
    let work_res_inner = match owner.backend.accounting().reserve(real_sign_work_charge()) {
        Ok(r) => r,
        Err(_) => return RealFreshSignOutcome::WorkSetAdmitRefused,
    };
    let _work_res =
        TrackedReservation::new(work_res_inner, release_probe.clone(), "work_res_release");

    // 9. Signer<->authorized-key<->backend agreement at the SIGNER's suite (100),
    //    and canonical preimage/binding derived VERBATIM from the borrowed Vote's
    //    OWN fields (no suite rewrite). Covered objects are returned into function
    //    scope so they are destroyed before `work_res` releases.
    let (position, binding, owned_pk_vec, preimage_vec, preimage_len) = {
        let ctx: &ProposalVoteAuthority = snapshot.verifier();
        let owned_pk = match ctx.key_provider.get_suite_and_key(bound_id) {
            Some((gov_suite, pk)) => {
                if gov_suite != ConsensusSigSuiteId::new(signer.suite_id()) {
                    return RealFreshSignOutcome::SuiteMismatch;
                }
                if ctx.backend_registry.get_backend(gov_suite).is_none() {
                    return RealFreshSignOutcome::BackendUnavailable;
                }
                pk
            }
            None => return RealFreshSignOutcome::KeyUnavailable,
        };
        debug_assert!(
            owned_pk.capacity() as u128 <= MODEL_MAX_PUBKEY_BYTES,
            "owned public-key backing capacity exceeded the reserved bound"
        );
        let preimage = ctx.signing_domain.vote_preimage(vote);
        debug_assert!(
            preimage.capacity() as u128 <= MODEL_MAX_PREIMAGE_BYTES,
            "model preimage backing capacity exceeded the reserved bound"
        );
        let position = SigningPosition {
            validator_id: vote.validator_index as u64,
            network_genesis: *ctx.signing_domain.genesis_identity(),
            kind: SigningKind::Vote,
            originating_view: vote.height,
        };
        let binding = BindingDigest::compute(&DecisionBindingInput {
            position,
            authorized_epoch: vote.epoch,
            suite_id: vote.suite_id,
            wire_message_version: vote.version as u16,
            d6_signing_format_version: MODEL_D6_SIGNING_FORMAT_VERSION,
            authority_commitment: *ctx.signing_domain.authority_commitment(),
            block_id: vote.block_id,
            canonical_preimage: &preimage,
        });
        let preimage_len = preimage.len();
        (position, binding, owned_pk, preimage, preimage_len)
    };
    // Wrap the ACTUAL owned backings so their destruction is observed relative to
    // the covering `work_res` release (declared AFTER it ⇒ dropped before it).
    let _owned_pk = TrackedBacking::new(owned_pk_vec, release_probe.clone(), "owned_pk_backing");
    let preimage = TrackedBacking::new(preimage_vec, release_probe.clone(), "preimage_backing");

    // 10. Admit ALL remaining resources BEFORE the admitted journal reservation:
    //     crypto-temporary coverage, caller-owned output, admitted reservation
    //     workspace (its continuation coverage is carried by the returned
    //     continuation), and admitted publication workspace.
    fire_real_admit_pressure(RealAdmitStage::Crypto);
    let _crypto_res = match owner.backend.accounting().reserve(crypto_temp_charge()) {
        Ok(r) => r,
        Err(_) => return RealFreshSignOutcome::CryptoAdmitRefused,
    };
    fire_real_admit_pressure(RealAdmitStage::Output);
    let mut output = match RetrievalWorkspaceOwner::new(&owner.backend).admit_output() {
        Ok(o) => o,
        Err(_) => return RealFreshSignOutcome::OutputAdmitRefused,
    };
    fire_real_admit_pressure(RealAdmitStage::ReserveWorkspace);
    let reserve_ws = match journal.admit_reserve_workspace() {
        Ok(w) => w,
        Err(_) => return RealFreshSignOutcome::ReserveWorkspaceAdmitRefused,
    };
    fire_real_admit_pressure(RealAdmitStage::PublishWorkspace);
    let mut publish_ws = match journal.admit_publish_workspace() {
        Ok(w) => w,
        Err(_) => return RealFreshSignOutcome::PublishWorkspaceAdmitRefused,
    };

    // 10b. Pre-reservation ledger observation (RUN 422 §2). Every composition
    //      resource is now admitted and the reservation workspace (its working set
    //      R and its continuation coverage T) is still intact; the admitted journal
    //      reservation has NOT yet consumed it. Sample both ledgers here, before
    //      `reserve_for_sign_admitted` releases R and moves T into the continuation.
    coord.on_pre_reservation();

    // 11. Admitted reservation. Proceed ONLY on a fresh reservation; every
    //     existing-position classification is non-delivering in this helper.
    let cont = match journal.reserve_for_sign_admitted(&position, &binding, reserve_ws) {
        Ok(AdmittedReservationOutcome::FreshlyReserved(c)) => c,
        Ok(AdmittedReservationOutcome::Conflict) => return RealFreshSignOutcome::ReserveConflict,
        Ok(AdmittedReservationOutcome::ReservedPotentiallySigned)
        | Ok(AdmittedReservationOutcome::LiveUnacknowledgedPotentiallySigned)
        | Ok(AdmittedReservationOutcome::SignedRetainableElsewhere) => {
            return RealFreshSignOutcome::ReservePotentiallySigned;
        }
        Ok(AdmittedReservationOutcome::Exhausted) => return RealFreshSignOutcome::ReserveExhausted,
        Ok(AdmittedReservationOutcome::LiveCapacityExhausted) => {
            return RealFreshSignOutcome::ReserveLiveCapacityExhausted;
        }
        Ok(AdmittedReservationOutcome::WorkspaceCapacityExceeded) => {
            return RealFreshSignOutcome::ReserveWorkspaceCapacityExceeded;
        }
        Ok(AdmittedReservationOutcome::AccountingUncertain) => {
            return RealFreshSignOutcome::ReserveAccountingUncertain;
        }
        Err(AdmittedReserveError::Storage(_)) => return RealFreshSignOutcome::ReserveStorage,
        Err(_) => return RealFreshSignOutcome::ReserveFailed,
    };

    // 12. Consume once; preserve continuous reservation ownership through the
    //     continuation-to-publication-capability transfer.
    let cap = match journal.consume_for_signing_admitted(cont) {
        Ok(c) => c,
        Err(_) => return RealFreshSignOutcome::ConsumeFailed,
    };

    // 13. Deterministic in-flight current-authorization replacement strictly
    //     between the ORIGINAL ticket's admit and its pre-signing confirm.
    if let ReconfirmPerturbation::AdvanceGenerationBeforeConfirm = reconfirm {
        snapshot
            .owner_mut()
            .replace_for_fixture(LocalAuthorizationState::MissingStorage);
    }

    // 14. Confirm the ORIGINAL authorization ticket immediately before signing.
    if snapshot.owner().confirm(&ticket).is_err() {
        return RealFreshSignOutcome::AuthorizationConfirmRefused;
    }

    // 15. Bounded model-only coordination hook at the fixed protected point.
    coord.on_post_consume_pre_sign();

    // 16. Sign ONCE through the real caller-buffer path, writing into the admitted
    //     output writer with the EXACT bound preimage. Validate the returned length
    //     BEFORE committing or slicing: require the selected ML-DSA-44 size and the
    //     previously checked bound.
    let n = {
        let mut writer = output.begin_write();
        let buf = writer.buffer();
        match signer.sign_vote_into(preimage.as_slice(), buf) {
            Ok(written) => {
                if written == 0 {
                    return RealFreshSignOutcome::EmptyWritten;
                }
                if written > crate::signing_journal_admission::OUTPUT_CAP {
                    return RealFreshSignOutcome::OversizeWritten;
                }
                if written != qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE || written != bound {
                    return RealFreshSignOutcome::WrongLength;
                }
                match writer.commit(written) {
                    Ok(m) => m,
                    Err(_) => return RealFreshSignOutcome::OversizeWritten,
                }
            }
            Err(_) => return RealFreshSignOutcome::SignerFailed,
        }
    };
    debug_assert_eq!(n, output.used(), "committed length equals the output's valid span");

    // 17. Admitted publication, with AT MOST one immediate retry and ONLY for the
    //     selected `Storage(WriteIo)` outcome. The same capability, output, and
    //     workspace are reused; nothing is re-signed, re-consumed, or re-covered.
    let mut republished = false;
    let publish_result = loop {
        match journal.publish_result_admitted(&cap, &output, &mut publish_ws) {
            Err(AdmittedPublishError::Storage(BoundedDiag::WriteIo)) if !republished => {
                republished = true;
                continue;
            }
            other => break other,
        }
    };
    match publish_result {
        Ok(AdmittedPublishOutcome::Published)
        | Ok(AdmittedPublishOutcome::AlreadyAcknowledged) => {}
        Ok(AdmittedPublishOutcome::DifferentResultRefused) => {
            return RealFreshSignOutcome::PublishDifferentResultRefused;
        }
        Ok(AdmittedPublishOutcome::ReservedForeignBinding) => {
            return RealFreshSignOutcome::PublishReservedForeignBinding;
        }
        Ok(AdmittedPublishOutcome::PositionMismatch) => {
            return RealFreshSignOutcome::PublishPositionMismatch;
        }
        Ok(AdmittedPublishOutcome::MalformedRecord) => {
            return RealFreshSignOutcome::PublishMalformedRecord;
        }
        Ok(AdmittedPublishOutcome::NoRecord) => return RealFreshSignOutcome::PublishNoRecord,
        Err(AdmittedPublishError::Storage(BoundedDiag::ReadIo)) => {
            return RealFreshSignOutcome::PublishReadIo;
        }
        Err(AdmittedPublishError::Storage(BoundedDiag::WriteIo)) => {
            return RealFreshSignOutcome::PublishWriteIo;
        }
        Err(_) => return RealFreshSignOutcome::PublishFailed,
    }

    // 18. After acknowledgement, attempt acknowledged-operation retirement exactly
    //     once; report its result SEPARATELY. A retirement failure never erases or
    //     relabels the publication acknowledgement.
    let retirement = match journal.retire_admitted(&cap) {
        Ok(RetirementOutcome::Retired) => RetirementReport::Retired,
        Err(_) => RetirementReport::Failed,
    };

    // Fixed-scalar completion. Remaining owned objects and reservations are
    // destroyed by reverse drop order (covered objects before their reservations;
    // the safety-domain guard LAST).
    let diag = sink.record(vote, output.used(), preimage_len, republished, retirement);
    RealFreshSignOutcome::Published(diag)
}

/// RUN 422 §3 — the ISOLATED same-authority lifecycle RELATIONSHIP, factored out
/// of the two sibling routes as a PURE scalar predicate so its defensive
/// revision/identity branches can be exercised directly by model-only fixtures
/// (no mutation of any closed production component). Both same-authority routes
/// call this with values read under the held guard; the comparison below is the
/// ONLY behavioral divergence from the strict-equality routes.
///
/// Same-incarnation and engine<->durable lock correspondence are REQUIRED on every
/// accepted relationship. The captured->current revision relationship is monotonic:
/// current below captured => refuse; equal => identical restriction identity
/// required; greater => accepted whether or not the restriction identity changed.
/// The relationship is NECESSARY BUT NEVER SUFFICIENT and establishes NO transition
/// origin and NO durable anti-rollback: the exact original candidate's CURRENT
/// safety is established SEPARATELY by the preceding `observe_checks_locked`
/// Revalidated(SafeViewSufficiency|SafeAncestry).
fn same_authority_lifecycle_relationship_holds(
    captured: &PreparedProvenance,
    current_identity: &GenerationIdentity,
    current_revision: u64,
    backend_incarnation: u64,
    engine_lock_id: [u8; 32],
    engine_lock_view: u64,
) -> bool {
    captured.recovery_backend_incarnation == backend_incarnation
        && engine_lock_id == current_identity.lock_block_id
        && engine_lock_view == current_identity.lock_view
        && match current_revision.cmp(&captured.captured_revision) {
            core::cmp::Ordering::Less => false,
            core::cmp::Ordering::Equal => captured.identity == *current_identity,
            core::cmp::Ordering::Greater => true,
        }
}

/// RUN 422 §3 — MODEL-ONLY defensive unit coverage for the pure lifecycle
/// RELATIONSHIP predicate. These tests construct `PreparedProvenance` /
/// `GenerationIdentity` scalars DIRECTLY (both are `pub` + `Copy`); they drive NO
/// engine, backend, journal or signer, mutate NO closed production component, and
/// assert ONLY the predicate's revision/identity/incarnation/lock branches. They
/// are deliberately SEPARATE from the engine-driven, real-crypto route tests in
/// `mod tests`, which exercise the SAME predicate through the live composition
/// after a genuine acknowledged advance. A `true` here is NECESSARY-NOT-SUFFICIENT:
/// the live routes still require `observe_checks_locked` Revalidated(..).
#[cfg(test)]
mod same_authority_predicate_model_unit {
    use super::{
        same_authority_lifecycle_relationship_holds, GenerationIdentity, PreparedProvenance,
    };

    const ID_A: GenerationIdentity = GenerationIdentity {
        lock_block_id: [0x11; 32],
        lock_view: 5,
    };
    const ID_B: GenerationIdentity = GenerationIdentity {
        lock_block_id: [0x22; 32],
        lock_view: 5,
    };
    const CAP_INCARNATION: u64 = 7;
    const CAP_REVISION: u64 = 10;

    // Captured against identity A, revision 10, incarnation 7.
    const CAP: PreparedProvenance = PreparedProvenance {
        identity: ID_A,
        captured_revision: CAP_REVISION,
        recovery_backend_incarnation: CAP_INCARNATION,
        origin_context_digest: [0x99; 32],
    };

    /// Evaluate the predicate with engine-lock inputs that, by default, AGREE with
    /// `current_identity` and the captured incarnation, so each test perturbs
    /// exactly ONE dimension.
    fn holds(current_identity: &GenerationIdentity, current_revision: u64) -> bool {
        same_authority_lifecycle_relationship_holds(
            &CAP,
            current_identity,
            current_revision,
            CAP_INCARNATION,
            current_identity.lock_block_id,
            current_identity.lock_view,
        )
    }

    #[test]
    fn equal_revision_matching_identity_holds() {
        assert!(holds(&ID_A, CAP_REVISION));
    }

    #[test]
    fn equal_revision_conflicting_identity_refuses() {
        // The decisive defensive branch: at EQUAL revision a DIFFERENT restriction
        // identity is NOT the captured candidate and is refused.
        assert!(!holds(&ID_B, CAP_REVISION));
    }

    #[test]
    fn greater_revision_unchanged_identity_holds() {
        assert!(holds(&ID_A, CAP_REVISION + 1));
    }

    #[test]
    fn greater_revision_changed_identity_holds() {
        // Accepted at the RELATIONSHIP layer (greater revision); this establishes
        // NO transition origin — the live route still revalidates the candidate.
        assert!(holds(&ID_B, CAP_REVISION + 1));
    }

    #[test]
    fn lower_revision_refuses() {
        assert!(!holds(&ID_A, CAP_REVISION - 1));
    }

    #[test]
    fn incarnation_mismatch_refuses() {
        // A greater-revision relationship that would otherwise hold is refused when
        // the backend incarnation differs from the captured one.
        assert!(!same_authority_lifecycle_relationship_holds(
            &CAP,
            &ID_A,
            CAP_REVISION + 1,
            CAP_INCARNATION + 1,
            ID_A.lock_block_id,
            ID_A.lock_view,
        ));
    }

    #[test]
    fn engine_lock_block_mismatch_refuses() {
        assert!(!same_authority_lifecycle_relationship_holds(
            &CAP,
            &ID_A,
            CAP_REVISION + 1,
            CAP_INCARNATION,
            [0xAB; 32],
            ID_A.lock_view,
        ));
    }

    #[test]
    fn engine_lock_view_mismatch_refuses() {
        assert!(!same_authority_lifecycle_relationship_holds(
            &CAP,
            &ID_A,
            CAP_REVISION + 1,
            CAP_INCARNATION,
            ID_A.lock_block_id,
            ID_A.lock_view + 1,
        ));
    }
}

/// RUN 422 isolated SAME-AUTHORITY checked retained-reuse sibling (TEST-ONLY).
///
/// Identical protected-use sequence to the AssociationChecked `retained_vote_use_inner`
/// composition (observation, separately charged lifecycle scope, eligibility,
/// verification admissions, association-checked retrieval, signature verification,
/// original-ticket confirmation, coordination point and scalar sink; it invokes NO
/// signer). The ONLY divergence is the step-5 lifecycle relationship accepted after a
/// successful observation, matching the fresh sibling. No OwnerBacked fallback.
#[allow(clippy::too_many_arguments)]
fn retained_vote_use_checked_same_authority_model<H: CommittedHistory + ?Sized>(
    owner: &SafetyRecordOwner,
    engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
    decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
    proposal: &qbind_wire::consensus::BlockProposal,
    limits: &PreparedDecisionInputLimits,
    history: Option<&H>,
    snapshot: &mut AuthorizedProposalVoteSnapshot,
    sink: &mut RetainedUseRecordingSink,
    journal: &SigningReservationJournal,
    coord: &mut ModelCoordinationHook,
    reconfirm: ReconfirmPerturbation,
) -> ModelRetainedUseOutcome {
    use crate::genesis_consensus_authority::LocalAuthorizationState;

    // AssociationChecked ONLY: this sibling uses association-checked admission and
    // retrieval with the existing verification-backend coverage. There is NO
    // OwnerBacked fallback (the OwnerBacked match arms below are unreachable).
    let route = RetainedRetrievalRoute::AssociationChecked;

    // 1. Owner-derived policy BEFORE locking (no allocation).
    match PreparedDecisionInputLimits::from_pinned(owner.pinned()) {
        Ok(expected) => {
            if *limits != expected {
                return ModelRetainedUseOutcome::PolicyRefused;
            }
        }
        Err(_) => return ModelRetainedUseOutcome::PolicyRefused,
    }

    // The ONLY Vote used throughout: borrowed from the owning envelope. No clone,
    // no suite reassignment, no signature assignment.
    let vote: &Vote = decided.vote();

    // 2. Acquire the serialization domain ONCE and FIRST so it is released LAST.
    let guard = owner.backend.lock_domain();

    // 3. Admit control coverage BEFORE constructing the ticket; it stays live
    //    through the ticket's confirm and destruction.
    let _control_res = match owner.backend.accounting().reserve(control_charge()) {
        Ok(r) => r,
        Err(_) => return ModelRetainedUseOutcome::ControlAdmitRefused,
    };
    let ticket = match snapshot.owner().admit() {
        Ok(t) => t,
        Err(_) => return ModelRetainedUseOutcome::AuthorizationAdmitRefused,
    };

    // 4. Existing non-consuming observation under the held guard (locked-only).
    match owner.observe_checks_locked(&guard, engine, decided, proposal, limits, history) {
        RetainedDecisionObservation::Revalidated(
            BoundedSafetyOutcome::SafeViewSufficiency | BoundedSafetyOutcome::SafeAncestry { .. },
        ) => {}
        _ => return ModelRetainedUseOutcome::ObservationRefused,
    }

    // 5. Bounded lifecycle-check scope UNDER THE SAME GUARD, separately charged.
    //    The validated record (which carries its own loader holder reservation)
    //    and the lifecycle scalars are destroyed BEFORE the covering
    //    `lifecycle_res` releases, on both the agree path and every `?` exit.
    //    Admission refusal is DISTINCT from a lifecycle disagreement.
    fire_retained_admit_pressure(RetainedAdmitStage::Lifecycle);
    let lifecycle_res = match owner.backend.accounting().reserve(lifecycle_charge()) {
        Ok(r) => r,
        Err(_) => return ModelRetainedUseOutcome::LifecycleAdmitRefused,
    };
    let agree = (|| -> Option<bool> {
        let validated: ValidatedRecord = owner.load_current_validated_locked(&guard, history).ok()?;
        let current_identity = GenerationIdentity::from_retained(validated.retained())?;
        let current_revision = owner.authoritative_revision_locked(&guard).ok()?;
        let captured: PreparedProvenance = owner
            .pin_provenance_locked(&guard, decided.payload().pin())
            .ok()?;
        let (engine_lock_id, engine_lock_view) = match engine.locked_qc() {
            Some(qc) => (qc.block_id, qc.view),
            None => return None,
        };
        // ISOLATED SAME-AUTHORITY relationship (the ONLY divergence from
        // `retained_vote_use_inner`): below => refuse; equal => identical restriction
        // identity required; greater => accepted whether or not the restriction
        // identity changed. Same-incarnation and engine/durable correspondence remain
        // REQUIRED. NECESSARY BUT NEVER SUFFICIENT; establishes no transition origin
        // and no durable anti-rollback. Exact-candidate current safety was already
        // established by the preceding observe_checks_locked Revalidated(Safe...).
        Some(same_authority_lifecycle_relationship_holds(
            &captured,
            &current_identity,
            current_revision,
            owner.backend.incarnation(),
            engine_lock_id,
            engine_lock_view,
        ))
    })();
    drop(lifecycle_res);
    match agree {
        Some(true) => {}
        _ => return ModelRetainedUseOutcome::LifecycleAmbiguous,
    }

    // 6. Membership / wire-chain / authorized-epoch checks on the borrowed Vote,
    //    BEFORE the verification working set is admitted (RUN 422 §2 step 7).
    let bound_id = ValidatorId::new(vote.validator_index as u64);
    if !snapshot.verifier().validators.contains(bound_id) {
        return ModelRetainedUseOutcome::MembershipRefused;
    }
    if vote.chain_id != snapshot.verifier().signing_domain.expected_wire_chain_id() {
        return ModelRetainedUseOutcome::WrongWireChain;
    }
    if vote.epoch != snapshot.authorized_epoch() {
        return ModelRetainedUseOutcome::WrongAuthorizedEpoch;
    }

    // 7. Admit the verification working set BEFORE constructing any verify object
    //    (RUN 422 §3). `verify_res` is declared before the verify objects, so they
    //    are all destroyed before it releases.
    fire_retained_admit_pressure(RetainedAdmitStage::Verify);
    let _verify_res = match owner.backend.accounting().reserve(verify_charge()) {
        Ok(r) => r,
        Err(_) => return ModelRetainedUseOutcome::VerifyAdmitRefused,
    };

    // 7b. AssociationChecked ONLY — admit the additional verification-backend
    //     coverage BEFORE the owned dispatch handle is constructed (step 8) or any
    //     verification object is built (step 11). Declared AFTER `_verify_res` so
    //     reverse-drop releases it BEFORE `_verify_res`, and AFTER every verify
    //     object (which are declared later), so coverage survives the `verify_vote`
    //     call on every exit. OwnerBacked admits none (honest limitation).
    let _verify_backend_res = match route {
        RetainedRetrievalRoute::OwnerBacked => None,
        RetainedRetrievalRoute::AssociationChecked => {
            fire_retained_admit_pressure(RetainedAdmitStage::VerifyBackend);
            match owner
                .backend
                .accounting()
                .reserve(verify_backend_wrapper_charge())
            {
                Ok(r) => Some(r),
                Err(_) => return ModelRetainedUseOutcome::VerifyBackendAdmitRefused,
            }
        }
    };

    // 8. Key/suite/backend selection and position/binding/preimage derivation,
    //    ALL from the SAME borrowed Vote and bound context. The owned public-key
    //    `Vec` the provider clones is model-owned and its backing capacity is
    //    checked against the reserved conservative bound. Any early refusal here
    //    unwinds the objects already built before `verify_res` releases.
    let key_suite_backend = {
        let ctx: &ProposalVoteAuthority = snapshot.verifier();
        match ctx.key_provider.get_suite_and_key(bound_id) {
            Some((gov_suite, pk)) => {
                if gov_suite != ConsensusSigSuiteId::new(vote.suite_id) {
                    Err(ModelRetainedUseOutcome::SuiteMismatch)
                } else {
                    match ctx.backend_registry.get_backend(gov_suite) {
                        Some(backend) => Ok((gov_suite, pk, backend)),
                        None => Err(ModelRetainedUseOutcome::BackendUnavailable),
                    }
                }
            }
            None => Err(ModelRetainedUseOutcome::KeyUnavailable),
        }
    };
    let (_gov_suite, owned_pk, backend) = match key_suite_backend {
        Ok(v) => v,
        Err(o) => return o,
    };
    debug_assert!(
        owned_pk.capacity() as u128 <= MODEL_MAX_PUBKEY_BYTES,
        "owned public-key backing capacity exceeded the reserved bound"
    );

    // Unsigned-envelope invariant (RUN 422 §1/§2): the canonical preimage hashes
    // `Vote::canonical_body()`, which EXCLUDES the `signature` field, so the
    // preimage is independent of the (empty) envelope signature. This is a
    // focused by-construction assertion, NOT control flow: the retrieved journal
    // signature is the only signature verified/consumed.
    debug_assert!(
        vote.signature.is_empty(),
        "the owning envelope's Vote carries no inline signature"
    );
    let preimage = snapshot.verifier().signing_domain.vote_preimage(vote);
    debug_assert!(
        preimage.capacity() as u128 <= MODEL_MAX_PREIMAGE_BYTES,
        "model preimage backing capacity exceeded the reserved bound"
    );
    let preimage_len = preimage.len();
    let position = SigningPosition {
        validator_id: vote.validator_index as u64,
        network_genesis: *snapshot.verifier().signing_domain.genesis_identity(),
        kind: SigningKind::Vote,
        originating_view: vote.height,
    };
    let binding = BindingDigest::compute(&DecisionBindingInput {
        position,
        authorized_epoch: vote.epoch,
        suite_id: vote.suite_id,
        wire_message_version: vote.version as u16,
        d6_signing_format_version: MODEL_D6_SIGNING_FORMAT_VERSION,
        authority_commitment: *snapshot.verifier().signing_domain.authority_commitment(),
        block_id: vote.block_id,
        canonical_preimage: &preimage,
    });

    // 9. Admit the retrieval workspace (output + envelope scratch) AFTER the
    //    verification inputs exist (RUN 422 §3). On refusal, those inputs are
    //    destroyed before `verify_res` releases (reverse-drop). The workspace
    //    carries its own separate reservations. OwnerBacked admits the workspace
    //    directly through a model-owned `RetrievalWorkspaceOwner`; AssociationChecked
    //    admits it through the journal's association-checked admission path.
    fire_retained_admit_pressure(RetainedAdmitStage::Retrieval);
    let (mut output, mut scratch) = match route {
        RetainedRetrievalRoute::OwnerBacked => {
            match RetrievalWorkspaceOwner::new(&owner.backend).admit() {
                Ok(ws) => ws,
                Err(_) => return ModelRetainedUseOutcome::RetrievalAdmitRefused,
            }
        }
        RetainedRetrievalRoute::AssociationChecked => {
            match journal.admit_retrieval_workspace() {
                Ok(ws) => ws,
                Err(crate::signing_reservation_journal::WorkspaceAdmissionError::NoAssociation) => {
                    return ModelRetainedUseOutcome::CheckedNoAssociation
                }
                Err(_) => return ModelRetainedUseOutcome::RetrievalAdmitRefused,
            }
        }
    };

    // 10. Retrieve the already-retained signature (no fresh reservation, no
    //     continuation, no publication capability, no signer). OwnerBacked uses the
    //     unconditional retrieval; AssociationChecked uses the association-checked
    //     retrieval, which additionally requires an installed ledger/workspace
    //     association and rejects a foreign workspace.
    let retrieved = match route {
        RetainedRetrievalRoute::OwnerBacked => {
            match journal.retrieve_retained(&position, &binding, &mut scratch, &mut output) {
                Ok(delivery) => match map_retained_delivery(delivery) {
                    Ok(sig) => sig,
                    Err(o) => return o,
                },
                Err(_) => return ModelRetainedUseOutcome::RetrievalFailed,
            }
        }
        RetainedRetrievalRoute::AssociationChecked => {
            match journal
                .retrieve_retained_checked(&position, &binding, &mut scratch, &mut output)
            {
                Ok(delivery) => match map_retained_delivery(delivery) {
                    Ok(sig) => sig,
                    Err(o) => return o,
                },
                Err(crate::signing_reservation_journal::CheckedRetrievalError::NoAssociation) => {
                    return ModelRetainedUseOutcome::CheckedNoAssociation
                }
                Err(crate::signing_reservation_journal::CheckedRetrievalError::ForeignWorkspace) => {
                    return ModelRetainedUseOutcome::CheckedForeignWorkspace
                }
                Err(_) => return ModelRetainedUseOutcome::RetrievalFailed,
            }
        }
    };

    // 11. Borrowed-signature cryptographic verification against the SAME Vote's
    //     canonical preimage and the governed key. `verify_vote` is a trait-object
    //     method on the registry-dispatched backend; it borrows the signature.
    if backend
        .verify_vote(
            vote.validator_index as u64,
            owned_pk.as_slice(),
            preimage.as_slice(),
            retrieved,
        )
        .is_err()
    {
        return ModelRetainedUseOutcome::VerificationFailed;
    }

    // 11.5 Deterministic in-flight current-authorization replacement strictly
    //      between the ORIGINAL ticket's admit and its pre-consumption confirm.
    if let ReconfirmPerturbation::AdvanceGenerationBeforeConfirm = reconfirm {
        snapshot
            .owner_mut()
            .replace_for_fixture(LocalAuthorizationState::MissingStorage);
    }

    // 12. Reconfirm the ORIGINAL ticket immediately before consumption.
    if snapshot.owner().confirm(&ticket).is_err() {
        return ModelRetainedUseOutcome::AuthorizationConfirmRefused;
    }

    // 13. Fixed observation point (publication exclusion): a competing same-domain
    //     handle observes `WouldBlock` here while this operation holds the guard.
    coord.on_post_consume_pre_sign();

    // 13b. RUN 422 §3 — fire the bounded read-only comparison probe (if a test
    //      installed one) with the SAME verified retrieved slice that is about to
    //      be consumed. No-op on OwnerBacked and production mirrors. The probe only
    //      records fixed results + an invocation count; it retains nothing and
    //      never panics, so it cannot perturb the protected sequence.
    fire_retained_slice_probe(retrieved);

    // 14. Scalar-only model consumption of the VERIFIED borrowed signature. The
    //     retrieval workspace, verify objects, reservations, ticket and guard are
    //     destroyed by reverse-drop order after this returns (guard LAST).
    let diag = sink.consume_verified(vote, retrieved, preimage_len);
    ModelRetainedUseOutcome::Consumed(diag)
}

/// RUN 422 isolated SAME-AUTHORITY fresh real-signing sibling (TEST-ONLY).
///
/// Byte-for-byte identical protected-use sequence to `fresh_vote_sign_real_local`
/// (same single safety-domain guard, charged scopes, admissions, D10
/// reservation/consumption, original-ticket confirmation, one bounded real signer
/// call, bounded publication retry and separate retirement). The ONLY divergence
/// is the step-6 lifecycle relationship accepted AFTER a successful step-5
/// observation: a monotonic captured->current relationship replaces strict
/// equality, permitting an ACKNOWLEDGED coherent L0->L1 advance to resume fresh
/// signing exactly once. Authority and pinned context remain unchanged fixtures;
/// no production caller and no production authority guarantee are introduced.
#[allow(clippy::too_many_arguments)]
fn fresh_vote_sign_real_local_same_authority<H: CommittedHistory + ?Sized>(
    owner: &SafetyRecordOwner,
    engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
    decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
    proposal: &qbind_wire::consensus::BlockProposal,
    limits: &PreparedDecisionInputLimits,
    history: Option<&H>,
    snapshot: &mut AuthorizedProposalVoteSnapshot,
    signer: &dyn ValidatorSigner,
    sink: &mut RealSignRecordingSink,
    journal: &SigningReservationJournal,
    coord: &mut ModelCoordinationHook,
    reconfirm: ReconfirmPerturbation,
) -> RealFreshSignOutcome {
    use crate::genesis_consensus_authority::LocalAuthorizationState;

    // 1. Owner-derived policy BEFORE acquiring the safety domain (no allocation).
    match PreparedDecisionInputLimits::from_pinned(owner.pinned()) {
        Ok(expected) => {
            if *limits != expected {
                return RealFreshSignOutcome::PolicyRefused;
            }
        }
        Err(_) => return RealFreshSignOutcome::PolicyRefused,
    }

    // The ONLY Vote used throughout: borrowed from the owning envelope. No clone,
    // no suite reassignment, no signature assignment.
    let vote: &Vote = decided.vote();

    // 2. Establish the checked signer output bound BEFORE any irreversible work
    //    and BEFORE acquiring the safety domain. Query it exactly once and retain
    //    the checked value. OUTPUT_CAP == ML_DSA_44_SIGNATURE_SIZE here, so an
    //    over-capacity bound is an output-capacity refusal and any other mismatch
    //    is a profile refusal.
    let bound = match signer.signature_output_bound() {
        Ok(b) => b,
        Err(_) => return RealFreshSignOutcome::SignerBoundUnsupported,
    };
    if bound > crate::signing_journal_admission::OUTPUT_CAP {
        return RealFreshSignOutcome::OutputCapacityRefused;
    }
    if bound != qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE {
        return RealFreshSignOutcome::ProfileRefused;
    }

    // 3. Acquire the serialization domain ONCE and FIRST so it is released LAST.
    let guard = owner.backend.lock_domain();

    // 4. Admit control coverage BEFORE constructing the ticket; obtain the
    //    ORIGINAL authorization ticket.
    let _control_res = match owner.backend.accounting().reserve(control_charge()) {
        Ok(r) => r,
        Err(_) => return RealFreshSignOutcome::AuthorizationAdmitRefused,
    };
    let ticket = match snapshot.owner().admit() {
        Ok(t) => t,
        Err(_) => return RealFreshSignOutcome::AuthorizationAdmitRefused,
    };

    // 5. Existing non-consuming held-guard observation (locked-only; SafeNoLock is
    //    NOT admitted). Does not reacquire the domain.
    match owner.observe_checks_locked(&guard, engine, decided, proposal, limits, history) {
        RetainedDecisionObservation::Revalidated(
            BoundedSafetyOutcome::SafeViewSufficiency | BoundedSafetyOutcome::SafeAncestry { .. },
        ) => {}
        _ => return RealFreshSignOutcome::ObservationRefused,
    }

    // 6. ISOLATED SAME-AUTHORITY lifecycle RELATIONSHIP under the SAME guard, in
    //    its separately charged scope. This is the ONLY behavioral divergence from
    //    `fresh_vote_sign_real_local`: strict captured==current equality is replaced
    //    by a monotonic captured->current relationship (below => refuse; equal =>
    //    identical restriction identity required; greater => accepted whether or not
    //    the restriction identity changed). Same-incarnation and engine/durable
    //    correspondence remain REQUIRED on every accepted relationship. The
    //    relationship is NECESSARY BUT NEVER SUFFICIENT and establishes NO
    //    transition origin and NO durable anti-rollback: the exact original
    //    candidate's current safety was already established by the step-5
    //    `observe_checks_locked` Revalidated(SafeViewSufficiency|SafeAncestry).
    //    The validated record (carrying its own loader holder reservation) and the
    //    lifecycle scalars are destroyed BEFORE the covering reservation releases.
    let lifecycle = (|| -> Option<()> {
        let lifecycle_res = owner
            .backend
            .accounting()
            .reserve(lifecycle_charge())
            .ok()?;
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
            same_authority_lifecycle_relationship_holds(
                &captured,
                &current_identity,
                current_revision,
                owner.backend.incarnation(),
                engine_lock_id,
                engine_lock_view,
            )
        };
        drop(lifecycle_res);
        agree.then_some(())
    })();
    if lifecycle.is_none() {
        return RealFreshSignOutcome::LifecycleAmbiguous;
    }

    // 7. Exact-Vote eligibility on the BORROWED Vote, before admitting the
    //    composition working set. Unsigned-input precondition first (the owning
    //    envelope's Vote carries no inline signature; this is a control-flow
    //    refusal, not just an assertion).
    if !vote.signature.is_empty() {
        return RealFreshSignOutcome::SignedInputRejected;
    }
    let bound_id = ValidatorId::new(vote.validator_index as u64);
    if *signer.validator_id() != bound_id || !snapshot.verifier().validators.contains(bound_id) {
        return RealFreshSignOutcome::MembershipRefused;
    }
    if vote.chain_id != snapshot.verifier().signing_domain.expected_wire_chain_id() {
        return RealFreshSignOutcome::WrongWireChain;
    }
    if vote.epoch != snapshot.authorized_epoch() {
        return RealFreshSignOutcome::WrongAuthorizedEpoch;
    }
    // Suite agreement on the BORROWED Vote (RUN 422 §2 correction). The exact
    // borrowed Vote's suite must equal the selected signer's suite; combined with
    // the signer<->authorized-key<->backend agreement enforced in step 9, this
    // closes the required four-way (Vote, signer, key, backend) suite agreement
    // BEFORE any journal reservation, consumption, or signer call. The default
    // engine constructors stamp the self-vote at DEFAULT_CONSENSUS_SUITE_ID (0),
    // so a real suite-100 signer over a default suite-0 Vote is refused here with
    // zero journal and zero signer activity. The construction-only
    // `with_state_limits_and_vote_suite` selector can instead stamp a suite-100
    // outgoing Vote (metadata only, no authorization), letting this agreement HOLD
    // for the resumed eligible real-signing path (RUN 422 §6).
    if vote.suite_id != signer.suite_id() {
        return RealFreshSignOutcome::SuiteMismatch;
    }

    // 8. Admit the composition working set BEFORE constructing any covered object.
    let release_probe = current_release_probe();
    fire_real_admit_pressure(RealAdmitStage::WorkSet);
    let work_res_inner = match owner.backend.accounting().reserve(real_sign_work_charge()) {
        Ok(r) => r,
        Err(_) => return RealFreshSignOutcome::WorkSetAdmitRefused,
    };
    let _work_res =
        TrackedReservation::new(work_res_inner, release_probe.clone(), "work_res_release");

    // 9. Signer<->authorized-key<->backend agreement at the SIGNER's suite (100),
    //    and canonical preimage/binding derived VERBATIM from the borrowed Vote's
    //    OWN fields (no suite rewrite). Covered objects are returned into function
    //    scope so they are destroyed before `work_res` releases.
    let (position, binding, owned_pk_vec, preimage_vec, preimage_len) = {
        let ctx: &ProposalVoteAuthority = snapshot.verifier();
        let owned_pk = match ctx.key_provider.get_suite_and_key(bound_id) {
            Some((gov_suite, pk)) => {
                if gov_suite != ConsensusSigSuiteId::new(signer.suite_id()) {
                    return RealFreshSignOutcome::SuiteMismatch;
                }
                if ctx.backend_registry.get_backend(gov_suite).is_none() {
                    return RealFreshSignOutcome::BackendUnavailable;
                }
                pk
            }
            None => return RealFreshSignOutcome::KeyUnavailable,
        };
        debug_assert!(
            owned_pk.capacity() as u128 <= MODEL_MAX_PUBKEY_BYTES,
            "owned public-key backing capacity exceeded the reserved bound"
        );
        let preimage = ctx.signing_domain.vote_preimage(vote);
        debug_assert!(
            preimage.capacity() as u128 <= MODEL_MAX_PREIMAGE_BYTES,
            "model preimage backing capacity exceeded the reserved bound"
        );
        let position = SigningPosition {
            validator_id: vote.validator_index as u64,
            network_genesis: *ctx.signing_domain.genesis_identity(),
            kind: SigningKind::Vote,
            originating_view: vote.height,
        };
        let binding = BindingDigest::compute(&DecisionBindingInput {
            position,
            authorized_epoch: vote.epoch,
            suite_id: vote.suite_id,
            wire_message_version: vote.version as u16,
            d6_signing_format_version: MODEL_D6_SIGNING_FORMAT_VERSION,
            authority_commitment: *ctx.signing_domain.authority_commitment(),
            block_id: vote.block_id,
            canonical_preimage: &preimage,
        });
        let preimage_len = preimage.len();
        (position, binding, owned_pk, preimage, preimage_len)
    };
    // Wrap the ACTUAL owned backings so their destruction is observed relative to
    // the covering `work_res` release (declared AFTER it ⇒ dropped before it).
    let _owned_pk = TrackedBacking::new(owned_pk_vec, release_probe.clone(), "owned_pk_backing");
    let preimage = TrackedBacking::new(preimage_vec, release_probe.clone(), "preimage_backing");

    // 10. Admit ALL remaining resources BEFORE the admitted journal reservation:
    //     crypto-temporary coverage, caller-owned output, admitted reservation
    //     workspace (its continuation coverage is carried by the returned
    //     continuation), and admitted publication workspace.
    fire_real_admit_pressure(RealAdmitStage::Crypto);
    let _crypto_res = match owner.backend.accounting().reserve(crypto_temp_charge()) {
        Ok(r) => r,
        Err(_) => return RealFreshSignOutcome::CryptoAdmitRefused,
    };
    fire_real_admit_pressure(RealAdmitStage::Output);
    let mut output = match RetrievalWorkspaceOwner::new(&owner.backend).admit_output() {
        Ok(o) => o,
        Err(_) => return RealFreshSignOutcome::OutputAdmitRefused,
    };
    fire_real_admit_pressure(RealAdmitStage::ReserveWorkspace);
    let reserve_ws = match journal.admit_reserve_workspace() {
        Ok(w) => w,
        Err(_) => return RealFreshSignOutcome::ReserveWorkspaceAdmitRefused,
    };
    fire_real_admit_pressure(RealAdmitStage::PublishWorkspace);
    let mut publish_ws = match journal.admit_publish_workspace() {
        Ok(w) => w,
        Err(_) => return RealFreshSignOutcome::PublishWorkspaceAdmitRefused,
    };

    // 10b. Pre-reservation ledger observation (RUN 422 §2). Every composition
    //      resource is now admitted and the reservation workspace (its working set
    //      R and its continuation coverage T) is still intact; the admitted journal
    //      reservation has NOT yet consumed it. Sample both ledgers here, before
    //      `reserve_for_sign_admitted` releases R and moves T into the continuation.
    coord.on_pre_reservation();

    // 11. Admitted reservation. Proceed ONLY on a fresh reservation; every
    //     existing-position classification is non-delivering in this helper.
    let cont = match journal.reserve_for_sign_admitted(&position, &binding, reserve_ws) {
        Ok(AdmittedReservationOutcome::FreshlyReserved(c)) => c,
        Ok(AdmittedReservationOutcome::Conflict) => return RealFreshSignOutcome::ReserveConflict,
        Ok(AdmittedReservationOutcome::ReservedPotentiallySigned)
        | Ok(AdmittedReservationOutcome::LiveUnacknowledgedPotentiallySigned)
        | Ok(AdmittedReservationOutcome::SignedRetainableElsewhere) => {
            return RealFreshSignOutcome::ReservePotentiallySigned;
        }
        Ok(AdmittedReservationOutcome::Exhausted) => return RealFreshSignOutcome::ReserveExhausted,
        Ok(AdmittedReservationOutcome::LiveCapacityExhausted) => {
            return RealFreshSignOutcome::ReserveLiveCapacityExhausted;
        }
        Ok(AdmittedReservationOutcome::WorkspaceCapacityExceeded) => {
            return RealFreshSignOutcome::ReserveWorkspaceCapacityExceeded;
        }
        Ok(AdmittedReservationOutcome::AccountingUncertain) => {
            return RealFreshSignOutcome::ReserveAccountingUncertain;
        }
        Err(AdmittedReserveError::Storage(_)) => return RealFreshSignOutcome::ReserveStorage,
        Err(_) => return RealFreshSignOutcome::ReserveFailed,
    };

    // 12. Consume once; preserve continuous reservation ownership through the
    //     continuation-to-publication-capability transfer.
    let cap = match journal.consume_for_signing_admitted(cont) {
        Ok(c) => c,
        Err(_) => return RealFreshSignOutcome::ConsumeFailed,
    };

    // 13. Deterministic in-flight current-authorization replacement strictly
    //     between the ORIGINAL ticket's admit and its pre-signing confirm.
    if let ReconfirmPerturbation::AdvanceGenerationBeforeConfirm = reconfirm {
        snapshot
            .owner_mut()
            .replace_for_fixture(LocalAuthorizationState::MissingStorage);
    }

    // 14. Confirm the ORIGINAL authorization ticket immediately before signing.
    if snapshot.owner().confirm(&ticket).is_err() {
        return RealFreshSignOutcome::AuthorizationConfirmRefused;
    }

    // 15. Bounded model-only coordination hook at the fixed protected point.
    coord.on_post_consume_pre_sign();

    // 16. Sign ONCE through the real caller-buffer path, writing into the admitted
    //     output writer with the EXACT bound preimage. Validate the returned length
    //     BEFORE committing or slicing: require the selected ML-DSA-44 size and the
    //     previously checked bound.
    let n = {
        let mut writer = output.begin_write();
        let buf = writer.buffer();
        match signer.sign_vote_into(preimage.as_slice(), buf) {
            Ok(written) => {
                if written == 0 {
                    return RealFreshSignOutcome::EmptyWritten;
                }
                if written > crate::signing_journal_admission::OUTPUT_CAP {
                    return RealFreshSignOutcome::OversizeWritten;
                }
                if written != qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE || written != bound {
                    return RealFreshSignOutcome::WrongLength;
                }
                match writer.commit(written) {
                    Ok(m) => m,
                    Err(_) => return RealFreshSignOutcome::OversizeWritten,
                }
            }
            Err(_) => return RealFreshSignOutcome::SignerFailed,
        }
    };
    debug_assert_eq!(n, output.used(), "committed length equals the output's valid span");

    // 17. Admitted publication, with AT MOST one immediate retry and ONLY for the
    //     selected `Storage(WriteIo)` outcome. The same capability, output, and
    //     workspace are reused; nothing is re-signed, re-consumed, or re-covered.
    let mut republished = false;
    let publish_result = loop {
        match journal.publish_result_admitted(&cap, &output, &mut publish_ws) {
            Err(AdmittedPublishError::Storage(BoundedDiag::WriteIo)) if !republished => {
                republished = true;
                continue;
            }
            other => break other,
        }
    };
    match publish_result {
        Ok(AdmittedPublishOutcome::Published)
        | Ok(AdmittedPublishOutcome::AlreadyAcknowledged) => {}
        Ok(AdmittedPublishOutcome::DifferentResultRefused) => {
            return RealFreshSignOutcome::PublishDifferentResultRefused;
        }
        Ok(AdmittedPublishOutcome::ReservedForeignBinding) => {
            return RealFreshSignOutcome::PublishReservedForeignBinding;
        }
        Ok(AdmittedPublishOutcome::PositionMismatch) => {
            return RealFreshSignOutcome::PublishPositionMismatch;
        }
        Ok(AdmittedPublishOutcome::MalformedRecord) => {
            return RealFreshSignOutcome::PublishMalformedRecord;
        }
        Ok(AdmittedPublishOutcome::NoRecord) => return RealFreshSignOutcome::PublishNoRecord,
        Err(AdmittedPublishError::Storage(BoundedDiag::ReadIo)) => {
            return RealFreshSignOutcome::PublishReadIo;
        }
        Err(AdmittedPublishError::Storage(BoundedDiag::WriteIo)) => {
            return RealFreshSignOutcome::PublishWriteIo;
        }
        Err(_) => return RealFreshSignOutcome::PublishFailed,
    }

    // 18. After acknowledgement, attempt acknowledged-operation retirement exactly
    //     once; report its result SEPARATELY. A retirement failure never erases or
    //     relabels the publication acknowledgement.
    let retirement = match journal.retire_admitted(&cap) {
        Ok(RetirementOutcome::Retired) => RetirementReport::Retired,
        Err(_) => RetirementReport::Failed,
    };

    // Fixed-scalar completion. Remaining owned objects and reservations are
    // destroyed by reverse drop order (covered objects before their reservations;
    // the safety-domain guard LAST).
    let diag = sink.record(vote, output.used(), preimage_len, republished, retirement);
    RealFreshSignOutcome::Published(diag)
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
    ///
    /// The default entrypoint keeps the engine's outgoing-Vote suite at
    /// `DEFAULT_CONSENSUS_SUITE_ID` (0); existing suite-0 tests depend on this.
    /// Retained as the suite-0 entrypoint even though `capture_multi` now routes
    /// through the suite-selecting variant.
    #[allow(dead_code)]
    fn engine_locked_l0_multi() -> (BasicHotStuffEngine<[u8; 32]>, BlockProposal, [u8; 32]) {
        engine_locked_l0_multi_with_suite(qbind_wire::DEFAULT_CONSENSUS_SUITE_ID)
    }

    /// RUN 422 — suite-selecting variant of [`engine_locked_l0_multi`]. Builds
    /// the SAME locked-L0 / safe-view-1 engine but stamps `vote_suite_id` on the
    /// engine's own outgoing votes via the construction-only
    /// `with_state_limits_and_vote_suite` constructor (default limits, so block
    /// behaviour is identical to `new`). The selected suite is applied BEFORE any
    /// engine event occurs, so the later captured self-vote carries it. The suite
    /// is outgoing-Vote metadata only and grants no signing authorization.
    fn engine_locked_l0_multi_with_suite(
        suite_id: u16,
    ) -> (BasicHotStuffEngine<[u8; 32]>, BlockProposal, [u8; 32]) {
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::with_state_limits_and_vote_suite(
                ValidatorId::new(1),
                engine_validator_set(4),
                qbind_consensus::vote_accumulator::ConsensusLimitsConfig::default(),
                suite_id,
            );
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
        // Default entrypoint: suite-0 captured self-vote (existing tests depend
        // on this default).
        capture_multi_with_suite(dir, ctx, qbind_wire::DEFAULT_CONSENSUS_SUITE_ID)
    }

    /// RUN 422 — suite-selecting variant of [`capture_multi`]. Identical capture
    /// flow, but the engine is constructed with the selected outgoing-Vote suite
    /// BEFORE any event, so the captured `DecidedVote` carries a self-vote whose
    /// `suite_id` equals `suite_id`. Used by the resumed REAL suite-100 signing
    /// path; the suite is metadata only and establishes no signing authorization.
    #[allow(clippy::type_complexity)]
    fn capture_multi_with_suite(
        dir: &std::path::Path,
        ctx: &PinnedSafetyContext,
        suite_id: u16,
    ) -> (
        SafetyRecordOwner,
        BasicHotStuffEngine<[u8; 32]>,
        DecidedVote<OwningCapturePayload>,
        BlockProposal,
        PreparedDecisionInputLimits,
        u64,
    ) {
        let (mut engine, p1, l0_block) = engine_locked_l0_multi_with_suite(suite_id);
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
        assert_eq!(
            decided.vote().suite_id, suite_id,
            "the captured self-vote carries the engine's selected outgoing-Vote suite"
        );
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

    /// RUN 422 §2/§4 — shared refusal/success cleanup check. With the SAME borrowed
    /// envelope and pin still alive, require exact restoration of BOTH accounting
    /// ledgers to `ledgers_before` and equality of the complete borrowed Vote and
    /// the ORIGINAL pin provenance. Ledger equality on a single partition is
    /// insufficient, and ledger equality alone does not establish pin-provenance
    /// preservation, so the fixed-size scalar provenance and the complete Vote are
    /// compared directly. `ledgers_before`/`prov_before` must be sampled while the
    /// envelope/pin are live, before the model call.
    fn assert_cleanup_preserved(
        owner: &SafetyRecordOwner,
        decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
        base_vote: &Vote,
        ledgers_before: LedgerSnapshot,
        prov_before: PreparedProvenance,
        label: &str,
    ) {
        assert_eq!(
            snapshot_ledgers(owner),
            ledgers_before,
            "both operational and aggregate ledgers restored after {label}"
        );
        assert_eq!(
            pin_provenance_now(owner, decided),
            prov_before,
            "the original pin provenance is preserved across {label}"
        );
        assert_eq!(
            decided.vote(),
            base_vote,
            "the complete borrowed Vote is unchanged across {label}"
        );
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

        // RUN 422 §2/§4 — snapshot BOTH ledgers and the pin provenance before the
        // call, with the borrowed envelope/pin live.
        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

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
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before, "the policy refusal",
        );
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

        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

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
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before, "the observation refusal",
        );
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

        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

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
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the unavailable-owner admission refusal",
        );
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

        // RUN 422 §2/§4 — baseline taken AFTER the deliberate engine/durable
        // advancement, immediately before the model call, with the envelope live.
        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

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
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before, "the lifecycle refusal",
        );
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
        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);
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
        //
        // RUN 422 §2/§4 — BOTH ledgers are restored and the complete Vote + pin
        // provenance are preserved across the refusal. This cleanup check runs
        // BEFORE the mutating reserve probe below so the probe cannot perturb it.
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the original-ticket confirm refusal",
        );
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
    // RUN 422 §3 — OWNED-OBJECT LIFETIME (release-order) evidence. A bounded,
    // model-only observer (a caller-owned `Rc<ReleaseOrderProbe>` installed via a
    // thread-local) records the destruction of the model's ACTUAL owned signing
    // backings (the owned public-key lookup `Vec` and the preimage `Vec`) and the
    // release of their covering signing reservation. The assertion — every tracked
    // backing destroyed BEFORE the covering reservation releases — is executed
    // OUTSIDE the model call, on both normal completion and an early return taken
    // after those backings were constructed. This is owned-object lifetime
    // evidence only (no allocator-address tracing, process RSS, or crash
    // durability); the ordering of the unobserved scope objects stays
    // source-reasoned (Rust reverse-drop order).
    //
    // The DISCRIMINATING sensitivity run (premature covering-reservation release
    // → this exact assertion fails) is executed manually against a temporary,
    // UNCOMMITTED source mutation and recorded literally in the evidence document;
    // the committed code keeps the correct order, for which this test is GREEN.
    // ======================================================================
    fn run_model_with_release_probe(
        dir: &std::path::Path,
        signer: &dyn BoundedVoteSigner,
    ) -> (ModelFreshUseOutcome, std::rc::Rc<ReleaseOrderProbe>) {
        let ctx = ctx_n(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir, &ctx);
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = ModelRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let counting = CountingSigner::new(signer);

        // Install the caller-owned probe for THIS thread's model call; the guard
        // clears the thread-local on drop so a panic cannot leak it.
        let probe = std::rc::Rc::new(ReleaseOrderProbe::new());
        let _guard = install_release_probe(probe.clone());
        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &counting, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        // The owned backings and the covering reservation were all destroyed while
        // `fresh_vote_sign_model` returned, so the probe's event log is complete
        // here, before the owner/journal fixtures are dropped.
        (outcome, probe)
    }

    fn assert_backings_destroyed_before_reservation_release(probe: &ReleaseOrderProbe) {
        assert!(
            probe.release_observed(),
            "the covering signing reservation's release boundary was observed; log={:?}",
            probe.event_log()
        );
        assert!(
            probe.backings_destroyed_before_release(&["owned_pk_backing", "preimage_backing"]),
            "every tracked owned backing must be destroyed BEFORE the covering \
             signing reservation releases; event log was {:?}",
            probe.event_log()
        );
    }

    #[test]
    fn release_order_owned_backings_destroyed_before_covering_reservation_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ok_signer();
        let (outcome, probe) = run_model_with_release_probe(dir.path(), &signer);
        assert!(
            matches!(outcome, ModelFreshUseOutcome::Signed(_)),
            "the positive fixture signs, got {outcome:?}"
        );
        assert_backings_destroyed_before_reservation_release(&probe);
    }

    #[test]
    fn release_order_owned_backings_destroyed_before_covering_reservation_on_early_return() {
        // The signer-error path is an EARLY RETURN taken AFTER the owned backings
        // (public key, preimage) were constructed and after D10 reserve/consume and
        // the original-ticket confirm: the covering `signing_res` still releases in
        // reverse-drop order after both backings are destroyed.
        let dir = tempfile::tempdir().unwrap();
        let signer = ErrorFixtureSigner {
            validator_id: SIGNER_VID,
            suite_id: MODEL_SUITE_U16,
        };
        let (outcome, probe) = run_model_with_release_probe(dir.path(), &signer);
        assert_eq!(
            outcome,
            ModelFreshUseOutcome::SignerFailed,
            "the error fixture takes the signer-failed early return"
        );
        assert_backings_destroyed_before_reservation_release(&probe);
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

        // RUN 422 §2/§4 — snapshot BOTH ledgers and the pin provenance before the
        // call, and (below) require exact restoration + preserved Vote/pin BEFORE
        // this helper drops its owner/envelope fixtures. Returning a Vote copy and
        // the journal alone cannot establish preservation of the ORIGINAL live pin.
        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);
        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &counting, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the signing-fault refusal",
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
        // RUN 422 §2/§4 — snapshot BOTH ledgers and the pin provenance after the
        // seed op, immediately before the model call, with the envelope live.
        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);
        let outcome = fresh_vote_sign_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &counting, &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelFreshUseOutcome::RetainedBlocked);
        assert_eq!(sink.calls, 0, "no sink on a retained-blocked outcome");
        assert_eq!(coord.calls, 0, "no coordination/signing after retained block");
        assert_eq!(counting.calls(), 0, "retained-blocked outcome adds zero new signer calls");
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the retained-blocked refusal",
        );
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

        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);
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
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before, "the wrong-wire-chain refusal",
        );
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

        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);
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
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the wrong-authorized-epoch refusal",
        );
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
        // After the successful retry the model's reservations are released: BOTH
        // ledgers are back at the ORIGINAL baseline and the complete Vote + pin
        // provenance are still preserved (RUN 422 §4).
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_original, prov_before,
            "the control-exhaustion retry success",
        );
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
        // After the successful retry BOTH ledgers are back at the ORIGINAL baseline
        // and the complete Vote + pin provenance are still preserved (RUN 422 §4).
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_original, prov_before,
            "the signing-exhaustion retry success",
        );
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

        // RUN 422 §2/§4 — baseline taken AFTER the fault fixture is armed but
        // BEFORE the model call, with the envelope/pin live.
        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

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

        // RUN 422 §2/§4 — BOTH ledgers restored and the complete Vote + pin
        // provenance preserved across the persistence-failure refusal. Checked
        // BEFORE the mutating post-consumption probe below.
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the persistence-failure refusal",
        );

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

    // =======================================================================
    // RUN 422 — Isolated Protected Retained-Signature USE model tests.
    //
    // These exercise the REAL `retrieve_retained` retrieval and REAL ML-DSA-44
    // cryptographic verification. Authority/key material and the retained record
    // are explicit, labelled fixtures; genuine signing occurs ONLY in setup to
    // mint a retained signature, NEVER inside `retained_vote_use_model`.
    // =======================================================================

    use crate::signing_reservation_journal::{
        SigningDecisionRecord, SigningRecordStage, SIGNING_RECORD_FORMAT_VERSION,
    };
    use crate::signing_journal_admission::{envelope_charge, output_charge};

    /// The wire suite id the real engine stamps on the captured self-vote
    /// (`DEFAULT_CONSENSUS_SUITE_ID == 0`). The retained model NEVER reassigns the
    /// Vote's suite, so the positive authority must govern exactly this suite.
    const RETAINED_VOTE_SUITE_U16: u16 = 0;

    /// Pinned context sized for the REAL ML-DSA-44 artifact: `s_sig == 2420`
    /// (`ML_DSA_44_SIGNATURE_SIZE`). This is the actual signature bound of the
    /// pinned profile exercised here — NOT a widened ceiling — so the retrieval
    /// workspace (output + envelope scratch) can be admitted alongside the
    /// verification working set. The QC codec bounds signature length as an UPPER
    /// bound, so the 8-byte fixture QC signatures still validate.
    fn retained_ctx(n: u64) -> PinnedSafetyContext {
        let validators = (0..n).map(|i| (ValidatorId::new(i), 1u64)).collect();
        PinnedSafetyContext {
            network_genesis_id: [1u8; 32],
            authority_context_ref: [2u8; 32],
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            qc_suite_id: QC_SUITE,
            timeout_suite_id: TIMEOUT_SUITE,
            s_sig: qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE,
            validators,
            require_height_equals_round: false,
        }
    }

    /// A signing authority that governs the ENGINE-STAMPED suite (0) for the
    /// signer and registers a real ML-DSA-44 backend under that suite, RETAINING
    /// the secret key so the test can mint a genuine retained signature. Mirrors
    /// `make_authority_wire` but (a) governs suite 0 (no suite reassignment) and
    /// (b) returns the secret key for fixture-only signing.
    fn make_retained_authority_wire(wire_chain_id: u32) -> (ProposalVoteAuthority, Vec<u8>) {
        let (mut pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        pk.shrink_to_fit();
        assert!(
            pk.capacity() as u128 <= MODEL_MAX_PUBKEY_BYTES,
            "fixture provider public-key backing {} exceeds the model bound {}",
            pk.capacity(),
            MODEL_MAX_PUBKEY_BYTES
        );
        let mut keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)> = HashMap::new();
        keys.insert(
            ValidatorId::new(SIGNER_VID),
            (ConsensusSigSuiteId::new(RETAINED_VOTE_SUITE_U16), pk),
        );
        let domain = ProposalVoteSigningDomainV2::try_new(
            ChainId(0xD5D5_0000_0000_0001),
            wire_chain_id,
            [0x5Du8; 32],
            [0xA5u8; 32],
        )
        .expect("valid signing domain");
        let pv = ProposalVoteAuthority {
            validators: Arc::new(authority_validators()),
            key_provider: Arc::new(TestKeyProvider { keys }),
            backend_registry: Arc::new(SimpleBackendRegistry::with_backend(
                ConsensusSigSuiteId::new(RETAINED_VOTE_SUITE_U16),
                Arc::new(MlDsa44Backend),
            )),
            chain_id: QBIND_DEVNET_CHAIN_ID,
            signer: None,
            signing_domain: domain,
        };
        (pv, sk)
    }

    fn make_retained_authority() -> (ProposalVoteAuthority, Vec<u8>) {
        make_retained_authority_wire(MODEL_WIRE_CHAIN_ID)
    }

    /// Recompute the SAME (position, binding) the retained model derives for
    /// `base_vote` under `pv`. UNLIKE `expected_pos_binding`, it performs NO suite
    /// reassignment: the binding uses the Vote's own `suite_id`, exactly as the
    /// model does with the borrowed `decided.vote()`.
    fn retained_pos_binding(
        pv: &ProposalVoteAuthority,
        base_vote: &Vote,
    ) -> (SigningPosition, BindingDigest) {
        let preimage = pv.signing_domain.vote_preimage(base_vote);
        let position = SigningPosition {
            validator_id: base_vote.validator_index as u64,
            network_genesis: *pv.signing_domain.genesis_identity(),
            kind: SigningKind::Vote,
            originating_view: base_vote.height,
        };
        let binding = BindingDigest::compute(&DecisionBindingInput {
            position,
            authorized_epoch: base_vote.epoch,
            suite_id: base_vote.suite_id,
            wire_message_version: base_vote.version as u16,
            d6_signing_format_version: MODEL_D6_SIGNING_FORMAT_VERSION,
            authority_commitment: *pv.signing_domain.authority_commitment(),
            block_id: base_vote.block_id,
            canonical_preimage: &preimage,
        });
        (position, binding)
    }

    /// Mint a GENUINE ML-DSA-44 signature over the model's canonical preimage with
    /// `sk`, wrap it in a `Signed` record at the model's exact position/binding,
    /// and write it (with NO live entry) into a fresh in-memory store so
    /// `retrieve_retained` takes the recovered exact-envelope synced-reissue
    /// branch and delivers `Retained`. Returns the seeded store, a journal
    /// attached over it, and the genuine signature bytes.
    fn seed_retained_signed(
        pv: &ProposalVoteAuthority,
        base_vote: &Vote,
        sk: &[u8],
    ) -> (
        Arc<InMemoryConsensusStorage>,
        SigningReservationJournal,
        Vec<u8>,
    ) {
        let (position, binding) = retained_pos_binding(pv, base_vote);
        let preimage = pv.signing_domain.vote_preimage(base_vote);
        let sig = MlDsa44Backend::sign(sk, &preimage).expect("genuine fixture signature");
        assert_eq!(
            sig.len(),
            qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE,
            "a genuine ML-DSA-44 signature is exactly the artifact size"
        );
        let store = seed_signed_record_store(position, binding, Some(sig.clone()));
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store.clone() as Arc<dyn SigningJournalStorage>,
        );
        (store, journal, sig)
    }

    /// Write a `Signed` record (or a `Reserved`/garbage one, per the given fields)
    /// at `position.storage_key()` into a fresh in-memory store.
    fn seed_signed_record_store(
        position: SigningPosition,
        binding: BindingDigest,
        retained_signature: Option<Vec<u8>>,
    ) -> Arc<InMemoryConsensusStorage> {
        let stage = if retained_signature.is_some() {
            SigningRecordStage::Signed
        } else {
            SigningRecordStage::Reserved
        };
        let bytes = SigningDecisionRecord {
            record_format_version: SIGNING_RECORD_FORMAT_VERSION,
            position,
            binding,
            stage,
            retained_signature,
        }
        .encode()
        .expect("seed record encodes");
        let store = Arc::new(InMemoryConsensusStorage::new());
        store
            .put_signing_record_synced(&position.storage_key(), &bytes)
            .expect("seed write");
        store
    }

    /// A local, test-only storage wrapper that delegates every operation to an
    /// in-memory inner store but, when armed, fails the recovered-record
    /// exact-envelope synced reissue BEFORE touching the backend — the consumer's
    /// `DeliverySuppressed` path. No production storage code is modified. The read
    /// path is delegated so retrieval still reads/validates the real record.
    struct ReissueFailingStore {
        inner: Arc<InMemoryConsensusStorage>,
        fail_reissue: std::sync::atomic::AtomicBool,
    }
    impl ReissueFailingStore {
        fn new(inner: Arc<InMemoryConsensusStorage>) -> Self {
            Self {
                inner,
                fail_reissue: std::sync::atomic::AtomicBool::new(false),
            }
        }
        fn arm(&self) {
            self.fail_reissue
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl SigningJournalStorage for ReissueFailingStore {
        fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get_signing_record(key)
        }
        fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
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
        fn read_signing_envelope_into(
            &self,
            journal_key: &[u8],
            dst: &mut [u8],
        ) -> Result<Option<usize>, crate::signing_reservation_journal::BoundedStorageError> {
            self.inner.read_signing_envelope_into(journal_key, dst)
        }
        fn reissue_signing_envelope_synced(
            &self,
            journal_key: &[u8],
            envelope: &[u8],
        ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
            use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
            if self
                .fail_reissue
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(BoundedStorageError::Io(BoundedDiag::WriteIo));
            }
            self.inner
                .reissue_signing_envelope_synced(journal_key, envelope)
        }
    }

    // ----------------------------------------------------------------------
    // Positive: a genuine retained signature verifies and is consumed exactly
    // once, with the exact scalar diagnostic, zero fresh signing, and full
    // cleanup + borrowed-Vote/pin preservation.
    // ----------------------------------------------------------------------
    #[test]
    fn retained1_genuine_signature_consumed_single_sink() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let base_vote = decided.vote().clone();
        assert_eq!(
            base_vote.suite_id, RETAINED_VOTE_SUITE_U16,
            "the engine stamps the default consensus suite on the captured self-vote"
        );
        let (_store, journal, genuine_sig) = seed_retained_signed(&pv, &base_vote, &sk);
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );

        let diag = match outcome {
            ModelRetainedUseOutcome::Consumed(d) => d,
            other => panic!("expected Consumed, got {other:?}"),
        };
        assert_eq!(diag.validator_index, SIGNER_VID);
        assert_eq!(diag.height, 1);
        assert_eq!(diag.round, 1);
        assert_eq!(diag.step, 0);
        assert_eq!(diag.suite_id, RETAINED_VOTE_SUITE_U16);
        assert_eq!(
            diag.sig_len as usize,
            genuine_sig.len(),
            "the consumed signature length equals the retained artifact length"
        );
        assert!(diag.preimage_len > 0);
        assert!(diag.preimage_len as u128 <= MODEL_MAX_PREIMAGE_BYTES);
        assert_eq!(sink.calls, 1, "exactly one sink consumption");
        assert_eq!(coord.calls, 1, "the coordination point is reached once");

        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the successful retained consumption",
        );
    }

    // ----------------------------------------------------------------------
    // Cryptographic rejection: a correctly-positioned, correctly-bound record
    // carrying a WRONG (zeroed, correct-length) signature passes membership /
    // wire-chain / epoch / suite / key / backend / retrieval and demonstrably
    // reaches the verifier, which rejects it. Zero sink calls.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_crypto_rejection_invokes_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, _sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let base_vote = decided.vote().clone();

        // A correct-length but cryptographically invalid signature at the exact
        // position/binding: earlier checks pass, so the verifier is reached.
        let (position, binding) = retained_pos_binding(&pv, &base_vote);
        let bogus = vec![0u8; qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE];
        let store = seed_signed_record_store(position, binding, Some(bogus));
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store.clone() as Arc<dyn SigningJournalStorage>,
        );
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(
            outcome,
            ModelRetainedUseOutcome::VerificationFailed,
            "a correct-length but invalid signature is rejected by the verifier"
        );
        assert_eq!(sink.calls, 0, "a cryptographic rejection consumes nothing");
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the cryptographic rejection",
        );
    }

    // ----------------------------------------------------------------------
    // Binding conflict is classified DISTINCTLY from a cryptographic failure and
    // BEFORE verification (no sink call).
    // ----------------------------------------------------------------------
    #[test]
    fn retained_binding_conflict_distinct_from_crypto() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let base_vote = decided.vote().clone();

        // A Signed record at the model's exact position but with a DIFFERENT
        // stored binding: retrieval refuses with BindingConflict before verifying.
        let (position, model_binding) = retained_pos_binding(&pv, &base_vote);
        let preimage = pv.signing_domain.vote_preimage(&base_vote);
        let genuine = MlDsa44Backend::sign(&sk, &preimage).expect("genuine sig");
        let mut other = model_binding;
        other.0[0] ^= 0xFF;
        let store = seed_signed_record_store(position, other, Some(genuine));
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store.clone() as Arc<dyn SigningJournalStorage>,
        );
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(
            outcome,
            ModelRetainedUseOutcome::RetainedRefused(RetainedRefuseClass::BindingConflict),
            "a mismatched stored binding is a typed retrieval refusal, not a crypto failure"
        );
        assert_ne!(outcome, ModelRetainedUseOutcome::VerificationFailed);
        assert_eq!(sink.calls, 0);
    }

    // ----------------------------------------------------------------------
    // A missing record is classified as RetainedMissing (no sink call).
    // ----------------------------------------------------------------------
    #[test]
    fn retained_missing_record() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, _sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            Arc::new(InMemoryConsensusStorage::new()) as Arc<dyn SigningJournalStorage>,
        );
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelRetainedUseOutcome::RetainedMissing);
        assert_eq!(sink.calls, 0);
    }

    // ----------------------------------------------------------------------
    // Suite mismatch: the governed suite (100) disagrees with the Vote's suite
    // (0). Refused BEFORE verification-object construction / retrieval.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_suite_mismatch_before_retrieval() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        // `make_authority` governs SUITE_PQ_RESERVED_1 (100) != vote.suite_id (0).
        let pv = make_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelRetainedUseOutcome::SuiteMismatch);
        assert_eq!(sink.calls, 0);
    }

    // ----------------------------------------------------------------------
    // Key unavailable: the governed provider has no key for the signer.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_key_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (mut pv, _sk) = make_retained_authority();
        // Drop every key: membership still contains the signer, so the refusal is
        // specifically KeyUnavailable (after membership/wire/epoch pass).
        pv.key_provider = Arc::new(TestKeyProvider { keys: HashMap::new() });
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelRetainedUseOutcome::KeyUnavailable);
        assert_eq!(sink.calls, 0);
    }

    // ----------------------------------------------------------------------
    // Backend unavailable: the provider governs suite 0 with a key, but no
    // verifier backend is registered for suite 0.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_backend_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (mut pv, _sk) = make_retained_authority();
        // Register the backend under a DIFFERENT suite (100) so suite 0 has none.
        pv.backend_registry = Arc::new(SimpleBackendRegistry::with_backend(
            SUITE_PQ_RESERVED_1,
            Arc::new(MlDsa44Backend),
        ));
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelRetainedUseOutcome::BackendUnavailable);
        assert_eq!(sink.calls, 0);
    }

    // ----------------------------------------------------------------------
    // Membership refusal: the signer is not in the authorized membership. This
    // is reached before key/suite/backend selection.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_membership_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (mut pv, _sk) = make_retained_authority();
        // Membership excluding the signer id (1).
        let entries = [0u64, 2, 3]
            .into_iter()
            .map(|i| ValidatorSetEntry {
                id: ValidatorId::new(i),
                voting_power: 1,
            })
            .collect::<Vec<_>>();
        pv.validators = Arc::new(ConsensusValidatorSet::new(entries).expect("set"));
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelRetainedUseOutcome::MembershipRefused);
        assert_eq!(sink.calls, 0);
    }

    // ----------------------------------------------------------------------
    // Wrong wire chain: the governed signing domain expects a different wire
    // chain id than the Vote carries.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_wrong_wire_chain() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, _sk) = make_retained_authority_wire(MODEL_WIRE_CHAIN_ID + 777);
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelRetainedUseOutcome::WrongWireChain);
        assert_eq!(sink.calls, 0);
    }

    // ----------------------------------------------------------------------
    // Observation refusal: a mismatching proposal breaks the held-guard
    // observation BEFORE verification; zero sink calls, full cleanup.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_observation_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, _sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let base_vote = decided.vote().clone();
        let mut wrong_proposal = p1.clone();
        wrong_proposal.header.parent_block_id = [0x11; 32];
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &wrong_proposal, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelRetainedUseOutcome::ObservationRefused);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0);
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the observation refusal",
        );
    }

    // ----------------------------------------------------------------------
    // Lifecycle refusal after a consistent generation advance (engine + durable
    // advance to L1). Observation still passes; the lifecycle comparison
    // disagrees. Zero sink calls, full cleanup.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_lifecycle_ambiguous_after_generation_advance() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, mut engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, _sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let journal = fresh_journal();
        let base_vote = decided.vote().clone();

        let l0_block = derive_block_id_local(1, 0, &[0xFF; 32]);
        let l1_block = derive_block_id_local(2, 1, &l0_block);
        assert!(engine
            .on_vote_event(ValidatorId::new(2), &logical_vote(1, l1_block, 2))
            .expect("peer vote 2 ingests")
            .is_none());
        assert!(engine
            .on_vote_event(ValidatorId::new(3), &logical_vote(1, l1_block, 3))
            .expect("peer vote 3 ingests")
            .is_some());
        let new_rev = publish_qc(&owner, &ctx, l1_block, 1, 1);
        assert_eq!(new_rev, 2);

        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelRetainedUseOutcome::LifecycleAmbiguous);
        assert_eq!(sink.calls, 0);
        assert_eq!(coord.calls, 0);
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the lifecycle refusal",
        );
    }

    // ----------------------------------------------------------------------
    // Authorization admission refusal: an unavailable current-authorization
    // owner can never admit the original ticket. Zero sink calls, full cleanup.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_authorization_admit_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, _sk) = make_retained_authority();
        let mut snapshot = unavailable_snapshot(&pv);
        let journal = fresh_journal();
        let base_vote = decided.vote().clone();
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelRetainedUseOutcome::AuthorizationAdmitRefused);
        assert_eq!(sink.calls, 0);
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the unavailable-owner admission refusal",
        );
    }

    // ----------------------------------------------------------------------
    // Original-ticket confirmation refusal: a deterministic in-flight
    // current-authorization replacement between admit and confirm invalidates the
    // ORIGINAL ticket AFTER a genuine signature verifies. The sink is NOT called
    // (checking after delivery cannot undo delivery), yet the successful
    // recovered reissue remains a permitted side effect.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_authorization_confirm_refused_after_verify() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let base_vote = decided.vote().clone();
        let (store, journal, _sig) = seed_retained_signed(&pv, &base_vote, &sk);
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::AdvanceGenerationBeforeConfirm,
        );
        assert_eq!(
            outcome,
            ModelRetainedUseOutcome::AuthorizationConfirmRefused,
            "the ORIGINAL ticket's confirmation fails after the in-flight replacement"
        );
        assert_eq!(sink.calls, 0, "a confirm refusal consumes nothing");
        // The recovered reissue (a permitted side effect) still rewrote the Signed
        // record; later verification/confirm outcome does not undo it.
        let (position, _b) = retained_pos_binding(&pv, &base_vote);
        assert!(
            store.get_signing_record(&position.storage_key()).unwrap().is_some(),
            "the recovered record remains persisted"
        );
    }

    // ----------------------------------------------------------------------
    // Consumer-level DeliverySuppressed: a recovered Signed record whose synced
    // reissue fails suppresses delivery via the real `retrieve_retained` path,
    // through a local test-only storage wrapper. Zero sink calls.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_delivery_suppressed_via_reissue_failure() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let base_vote = decided.vote().clone();

        let (position, binding) = retained_pos_binding(&pv, &base_vote);
        let preimage = pv.signing_domain.vote_preimage(&base_vote);
        let genuine = MlDsa44Backend::sign(&sk, &preimage).expect("genuine sig");
        let inner = seed_signed_record_store(position, binding, Some(genuine));
        let wrapper = Arc::new(ReissueFailingStore::new(inner));
        wrapper.arm();
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            wrapper.clone() as Arc<dyn SigningJournalStorage>,
        );
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert_eq!(outcome, ModelRetainedUseOutcome::DeliverySuppressed);
        assert_eq!(sink.calls, 0, "suppressed delivery consumes nothing");
    }

    // ----------------------------------------------------------------------
    // Admission failures at each stage (control / lifecycle / verify / retrieval)
    // leave BOTH ledgers exactly restored; removing the standing pressure and
    // retrying reaches the successful consumption. Exercises the real shared
    // accountant via `reserve_standing_for_test`.
    // ----------------------------------------------------------------------
    fn run_retained_with_standing(
        owner: &SafetyRecordOwner,
        engine: &BasicHotStuffEngine<[u8; 32]>,
        decided: &DecidedVote<OwningCapturePayload>,
        p1: &BlockProposal,
        lim: &PreparedDecisionInputLimits,
        snapshot: &mut AuthorizedProposalVoteSnapshot,
        journal: &SigningReservationJournal,
        fill: u128,
    ) -> (ModelRetainedUseOutcome, u32) {
        let standing = owner
            .backend_for_test()
            .reserve_standing_for_test(fill)
            .expect("standing reservation fits");
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            owner, engine, decided, p1, lim, None, snapshot,
            &mut sink, journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        drop(standing);
        (outcome, sink.calls)
    }

    // Force the admission at exactly `stage` to refuse by installing the
    // per-stage pressure hook: when the model reaches `stage` (AFTER the
    // held-guard observation has already succeeded and released its working
    // set), the hook consumes ALL remaining effective headroom via the real
    // shared accountant, so that stage's own reserve cannot be admitted. This
    // isolates the lifecycle / verify / retrieval admissions, which a single
    // global pressure cannot (the observation working-set peak dominates them).
    fn run_retained_with_stage_pressure(
        owner: &SafetyRecordOwner,
        engine: &BasicHotStuffEngine<[u8; 32]>,
        decided: &DecidedVote<OwningCapturePayload>,
        p1: &BlockProposal,
        lim: &PreparedDecisionInputLimits,
        snapshot: &mut AuthorizedProposalVoteSnapshot,
        journal: &SigningReservationJournal,
        stage: RetainedAdmitStage,
    ) -> (ModelRetainedUseOutcome, u32) {
        let backend = owner.backend_for_test().clone();
        let held = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let held_hook = held.clone();
        install_retained_admit_pressure_hook(move |s| {
            if s == stage {
                let op = backend.accounting_cap().expect("op cap")
                    - backend.accounting_current();
                let agg = backend.accounting_aggregate_cap().expect("agg cap")
                    - backend.accounting_aggregate_current();
                // Consume the binding (minimum) remaining headroom so the next
                // reserve of any positive charge at this stage refuses.
                let r = backend
                    .reserve_standing_for_test(op.min(agg))
                    .expect("stage pressure fits");
                held_hook.borrow_mut().push(r);
            }
        });
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            owner, engine, decided, p1, lim, None, snapshot,
            &mut sink, journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        clear_retained_admit_pressure_hook();
        held.borrow_mut().clear();
        (outcome, sink.calls)
    }

    #[test]
    fn retained_admission_failures_cleanup_and_retry() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let base_vote = decided.vote().clone();
        let (_store, journal, _sig) = seed_retained_signed(&pv, &base_vote, &sk);

        let c_ctrl = control_charge();
        let ledgers_before = snapshot_ledgers(&owner);

        // CONTROL admission (step 3, BEFORE the held-guard observation) is the
        // only stage isolable by a single global pressure: leave strictly less
        // than control_charge() effective headroom so its reserve is the first to
        // refuse. The model reserves against the operational accountant, whose
        // reserve enforces BOTH the operational and aggregate ceilings, so the
        // EFFECTIVE headroom is the binding minimum of the two partitions.
        {
            let eff_headroom = {
                let b = owner.backend_for_test();
                let op = b.accounting_cap().expect("bounded operational cap")
                    - b.accounting_current();
                let agg = b.accounting_aggregate_cap().expect("bounded aggregate cap")
                    - b.accounting_aggregate_current();
                op.min(agg)
            };
            let fill = eff_headroom - (c_ctrl - 1);
            let (outcome, sink_calls) = run_retained_with_standing(
                &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, fill,
            );
            assert_eq!(
                outcome,
                ModelRetainedUseOutcome::ControlAdmitRefused,
                "control admission refuses first under global pressure"
            );
            assert_eq!(sink_calls, 0, "an admission refusal consumes nothing");
            assert_eq!(
                snapshot_ledgers(&owner),
                ledgers_before,
                "both ledgers restored after ControlAdmitRefused"
            );
        }

        // LIFECYCLE / VERIFY / RETRIEVAL admissions each occur AFTER the
        // observation has succeeded and released its dominating working set, so
        // they cannot be isolated by a single global pressure. The per-stage hook
        // applies pressure at exactly that admission point, deterministically
        // refusing it while every earlier stage (including observation) succeeds.
        // Each refusal performs its stage's exact reverse-drop cleanup (the
        // retrieval refusal in particular destroys the already-constructed
        // verification inputs before their reservation releases) and restores
        // both ledgers.
        let stage_cases = [
            (
                RetainedAdmitStage::Lifecycle,
                ModelRetainedUseOutcome::LifecycleAdmitRefused,
            ),
            (
                RetainedAdmitStage::Verify,
                ModelRetainedUseOutcome::VerifyAdmitRefused,
            ),
            (
                RetainedAdmitStage::Retrieval,
                ModelRetainedUseOutcome::RetrievalAdmitRefused,
            ),
        ];
        for (stage, expected) in stage_cases {
            let (outcome, sink_calls) = run_retained_with_stage_pressure(
                &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, stage,
            );
            assert_eq!(outcome, expected, "admission refusal at the expected stage");
            assert_eq!(sink_calls, 0, "an admission refusal consumes nothing");
            assert_eq!(
                snapshot_ledgers(&owner),
                ledgers_before,
                "both ledgers restored after {expected:?}"
            );
        }

        // Pressure removed: a retry reaches the successful consumption.
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert!(
            matches!(outcome, ModelRetainedUseOutcome::Consumed(_)),
            "with pressure removed the retained consumption succeeds, got {outcome:?}"
        );
        assert_eq!(sink.calls, 1);
    }

    /// Independent reconstruction of the PRE-correction verification working-set
    /// charge: every term `verify_charge()` sums EXCEPT the canonical-body
    /// `Vec<u8>` control term added by this correction. Deliberately composed from
    /// the component sizes/bounds, NOT as `verify_charge() - size_of::<Vec<u8>>()`,
    /// so reverting the correction cannot keep the regression below green.
    fn previous_verify_allowance() -> u128 {
        let vec_control = std::mem::size_of::<Vec<u8>>() as u128;
        vec_control // pubkey_control
            .saturating_add(MODEL_MAX_PUBKEY_BYTES) // pubkey_backing
            .saturating_add(vec_control) // preimage_control
            .saturating_add(MODEL_MAX_PREIMAGE_BYTES) // preimage_backing
            .saturating_add(MODEL_MAX_PREIMAGE_BYTES) // canonical_body_temp (backing only)
            .saturating_add(std::mem::size_of::<SigningPosition>() as u128)
            .saturating_add(std::mem::size_of::<DecisionBindingInput<'static>>() as u128)
            .saturating_add(std::mem::size_of::<Sha3_256>() as u128)
            .saturating_add(std::mem::size_of::<BindingDigest>() as u128)
    }

    /// Run the retained model while leaving EXACTLY `verify_allowance` effective
    /// headroom (the binding minimum of the operational and aggregate partitions)
    /// at the verification admission, using the existing real-reservation per-stage
    /// pressure hook (no admission weakening). The hook fires at the Verify stage
    /// ONLY — after the dominating held-guard observation has released — consuming
    /// all but `verify_allowance` of the effective headroom, so the model's own
    /// `verify_charge()` reserve refuses iff it exceeds `verify_allowance`.
    fn run_retained_with_verify_allowance(
        owner: &SafetyRecordOwner,
        engine: &BasicHotStuffEngine<[u8; 32]>,
        decided: &DecidedVote<OwningCapturePayload>,
        p1: &BlockProposal,
        lim: &PreparedDecisionInputLimits,
        snapshot: &mut AuthorizedProposalVoteSnapshot,
        journal: &SigningReservationJournal,
        verify_allowance: u128,
    ) -> (ModelRetainedUseOutcome, u32) {
        let backend = owner.backend_for_test().clone();
        let held = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let held_hook = held.clone();
        install_retained_admit_pressure_hook(move |s| {
            if s == RetainedAdmitStage::Verify {
                let op = backend.accounting_cap().expect("op cap")
                    - backend.accounting_current();
                let agg = backend.accounting_aggregate_cap().expect("agg cap")
                    - backend.accounting_aggregate_current();
                let eff = op.min(agg);
                // Consume down to EXACTLY `verify_allowance` effective headroom.
                let r = backend
                    .reserve_standing_for_test(eff - verify_allowance)
                    .expect("verify-allowance pressure fits");
                held_hook.borrow_mut().push(r);
            }
        });
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            owner, engine, decided, p1, lim, None, snapshot,
            &mut sink, journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        clear_retained_admit_pressure_hook();
        held.borrow_mut().clear();
        (outcome, sink.calls)
    }

    // ----------------------------------------------------------------------
    // RUN 422 — canonical-body Vec control-object accounting correction. The
    // corrected verify_charge() adds exactly one Vec<u8> control term for the
    // canonical-body temporary. With only the PRE-correction allowance available
    // at the verification admission, the corrected charge refuses (the restored
    // term is precisely what tips admission), consuming nothing; releasing the
    // pressure and retrying the SAME envelope/journal succeeds. Both ledgers, the
    // borrowed Vote, and the pin provenance are preserved across both paths. The
    // allowance is reconstructed independently, so reverting the correction makes
    // this regression fail (the old charge would fit and NOT refuse).
    // ----------------------------------------------------------------------
    #[test]
    fn retained_verify_charge_canonical_body_control_admission_boundary() {
        let prev_allowance = previous_verify_allowance();
        let corrected = verify_charge();
        let control = std::mem::size_of::<Vec<u8>>() as u128;
        println!(
            "RUN422 verify_charge measured: old={prev_allowance} new={corrected} control={control}"
        );
        assert_eq!(
            corrected,
            prev_allowance + control,
            "verify_charge adds exactly the canonical-body Vec<u8> control term \
             (prev={prev_allowance}, corrected={corrected}, control={control})"
        );

        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let base_vote = decided.vote().clone();
        let (_store, journal, _sig) = seed_retained_signed(&pv, &base_vote, &sk);

        let ledgers_before = snapshot_ledgers(&owner);
        let prov_before = pin_provenance_now(&owner, &decided);

        // Pre-correction allowance available => the corrected charge (one Vec
        // control larger) refuses at the verification admission.
        let (outcome, calls) = run_retained_with_verify_allowance(
            &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, prev_allowance,
        );
        assert_eq!(
            outcome,
            ModelRetainedUseOutcome::VerifyAdmitRefused,
            "the corrected verification charge refuses when only the pre-correction \
             allowance is available"
        );
        assert_eq!(calls, 0, "a verification-admission refusal consumes nothing");
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the corrected-charge verification-admission refusal",
        );

        // Release the pressure and retry the SAME envelope/journal: success.
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::inert();
        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert!(
            matches!(outcome, ModelRetainedUseOutcome::Consumed(_)),
            "with pressure released the retained consumption succeeds, got {outcome:?}"
        );
        assert_eq!(sink.calls, 1, "exactly one sink consumption after relief");
        assert_cleanup_preserved(
            &owner, &decided, &base_vote, ledgers_before, prov_before,
            "the post-relief retained consumption",
        );
    }

    // ----------------------------------------------------------------------
    // Live operational AND aggregate ledgers are sampled at the fixed
    // observation point, each within its enforced cap, reflecting the model's
    // own live reservations; both are restored afterward.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_live_ledgers_observed_within_caps() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let base_vote = decided.vote().clone();
        let (_store, journal, _sig) = seed_retained_signed(&pv, &base_vote, &sk);
        let mut sink = RetainedUseRecordingSink::new();
        let mut coord = ModelCoordinationHook::sampling(owner.backend_for_test().clone());

        let op_cap = owner.backend_for_test().accounting_cap().expect("op cap");
        let agg_cap = owner
            .backend_for_test()
            .accounting_aggregate_cap()
            .expect("agg cap");
        let baseline = snapshot_ledgers(&owner);

        let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
            &mut sink, &journal, &mut coord,
            ReconfirmPerturbation::None,
        );
        assert!(matches!(outcome, ModelRetainedUseOutcome::Consumed(_)));
        assert_eq!(coord.calls, 1);
        let observed_op = coord.observed_operational.expect("operational sampled");
        let observed_agg = coord.observed_aggregate.expect("aggregate sampled");
        assert!(observed_op <= op_cap, "live op {observed_op} within cap {op_cap}");
        assert!(observed_agg <= agg_cap, "live agg {observed_agg} within cap {agg_cap}");
        assert!(
            observed_op > baseline.operational && observed_agg > baseline.aggregate,
            "the live sample reflects the model's own reservations"
        );
        assert_eq!(snapshot_ledgers(&owner), baseline, "both ledgers restored");
    }

    // ----------------------------------------------------------------------
    // Publication exclusion at the fixed observation point: a competing
    // same-domain handle observes WouldBlock while the protected op holds the
    // guard; an eligible publication proceeds after release.
    // ----------------------------------------------------------------------
    #[test]
    fn retained_coordination_excludes_concurrent_publication() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = retained_ctx(4);
        let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
        let (pv, sk) = make_retained_authority();
        let mut snapshot = established_snapshot(&pv);
        let base_vote = decided.vote().clone();
        let (_store, journal, _sig) = seed_retained_signed(&pv, &base_vote, &sk);
        let mut sink = RetainedUseRecordingSink::new();

        let peer_backend = owner.backend_for_test().clone();
        let (req_tx, req_rx) = std::sync::mpsc::channel::<()>();
        let (res_tx, res_rx) = std::sync::mpsc::channel::<PeerDomainObservation>();
        let timeout = std::time::Duration::from_secs(10);

        let outcome = std::thread::scope(|scope| {
            let peer = scope.spawn(move || {
                if req_rx.recv_timeout(timeout).is_ok() {
                    let obs = match peer_backend.try_lock_domain_for_test() {
                        TryLockDomainOutcome::WouldBlock => PeerDomainObservation::WouldBlock,
                        TryLockDomainOutcome::Acquired(_g) => PeerDomainObservation::Acquired,
                        TryLockDomainOutcome::Poisoned => PeerDomainObservation::Poisoned,
                    };
                    let _ = res_tx.send(obs);
                }
            });
            let mut coord = ModelCoordinationHook::probing(req_tx, res_rx, timeout);
            let outcome = retained_vote_use_model::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            peer.join().expect("bounded peer completes");
            assert!(!coord.failed, "every handshake leg must succeed");
            assert_eq!(coord.calls, 1);
            assert_eq!(
                coord.last_excluded,
                Some(true),
                "the competing same-domain handle observed WouldBlock"
            );
            outcome
        });
        assert!(matches!(outcome, ModelRetainedUseOutcome::Consumed(_)));
        assert_eq!(sink.calls, 1);

        // After release, an eligible publication on the SAME backend proceeds.
        let new_rev = publish_qc(&owner, &ctx, [0x5Au8; 32], 1, 1);
        assert_eq!(new_rev, 2);
    }


    // ======================================================================
    // RUN 422 — ADMITTED REAL fresh-vote signing composition tests.
    //
    // These exercise `fresh_vote_sign_real_local`: the real caller-buffer
    // `LocalKeySigner` ML-DSA-44 path driven through the ADMITTED journal
    // reservation/consumption/publication route under ONE safety-domain guard,
    // over the BORROWED `decided.vote()` (no clone, no suite rewrite). Fault
    // signers and fault stores are explicitly fixtures; the positive path uses a
    // real key whose public half is installed in the authorization context.
    // ======================================================================
    mod real_fresh_sign {
        use super::*;
        use crate::validator_signer::{BoundedSignError, LocalKeySigner, SignError};
        use qbind_crypto::ml_dsa44::ValidatorSigningKey;

        /// Suite-100 authority with a REAL ML-DSA-44 public key installed for the
        /// signer id, a real backend registered under suite 100, and the matching
        /// SECRET key returned so the fixture can build a genuine `LocalKeySigner`.
        /// Mirrors `make_authority_wire` (which governs SUITE_PQ_RESERVED_1==100)
        /// but additionally returns the secret key for fixture-only signing.
        fn make_real_signing_authority_wire(wire_chain_id: u32) -> (ProposalVoteAuthority, Vec<u8>) {
            let (mut pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
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
            let pv = ProposalVoteAuthority {
                validators: Arc::new(authority_validators()),
                key_provider: Arc::new(TestKeyProvider { keys }),
                backend_registry: Arc::new(SimpleBackendRegistry::with_backend(
                    SUITE_PQ_RESERVED_1,
                    Arc::new(MlDsa44Backend),
                )),
                chain_id: QBIND_DEVNET_CHAIN_ID,
                signer: None,
                signing_domain: domain,
            };
            (pv, sk)
        }

        fn make_real_signing_authority() -> (ProposalVoteAuthority, Vec<u8>) {
            make_real_signing_authority_wire(MODEL_WIRE_CHAIN_ID)
        }

        /// A genuine suite-100 `LocalKeySigner` from the fixture secret key.
        fn real_local_signer(sk: &[u8]) -> LocalKeySigner {
            LocalKeySigner::new(
                ValidatorId::new(SIGNER_VID),
                MODEL_SUITE_U16,
                Arc::new(ValidatorSigningKey::new(sk.to_vec())),
            )
        }

        /// Establish + associate (to the OWNER's accountant, by Arc identity) +
        /// enter bounded live mode over `store`. The admitted route requires all
        /// three; the association MUST be the owner's accountant so the admitted
        /// reservations draw on the same operational ledger.
        fn associated_bounded_journal(
            owner: &SafetyRecordOwner,
            store: Arc<dyn SigningJournalStorage>,
            capacity: usize,
        ) -> SigningReservationJournal {
            let journal =
                SigningReservationJournal::initialize(store, DEFAULT_MAX_RESERVED_POSITIONS)
                    .expect("initialize admitted journal");
            journal
                .install_accountant_association(owner.backend_for_test().accounting())
                .expect("install accountant association");
            journal
                .enter_bounded_live_mode(capacity)
                .expect("enter bounded live mode");
            journal
        }

        fn real_fresh_store() -> Arc<dyn SigningJournalStorage> {
            Arc::new(InMemoryConsensusStorage::new()) as Arc<dyn SigningJournalStorage>
        }

        // ------------------------------------------------------------------
        // RUN 422 §2 correction — suite-CONSISTENT FIXTURE signing context.
        //
        // The DEFAULT engine constructors stamp the captured self-vote at
        // `DEFAULT_CONSENSUS_SUITE_ID` (0), so over a DEFAULT suite-0 capture the
        // real ML-DSA-44 `LocalKeySigner` (which requires suite 100) is not
        // suite-consistent with the borrowed Vote and the eligible REAL path
        // refuses (see `real1_...`). To exercise the admitted journal reserve/
        // consume/sign/publish/retry/retire MECHANICS under a suite-consistent
        // relationship WITHOUT real crypto, these fixtures govern suite 0 for the
        // signer, authorized key, and backend, matching a default suite-0 Vote. The
        // signer below is an EXPLICIT FIXTURE: its `sign_vote_into` writes
        // deterministic bytes, NOT a real ML-DSA-44 signature. No real cryptographic
        // correspondence is claimed from this fixture path. The RESUMED eligible
        // REAL suite-100 path (via `capture_multi_with_suite(.., 100)`) is tested
        // separately in the `real100_*` cases below (RUN 422 §6).
        // ------------------------------------------------------------------

        /// A suite-0 authority whose governed key suite and registered backend both
        /// equal the borrowed Vote's wire suite (0), so the composition's four-way
        /// (Vote, signer, key, backend) suite agreement holds for a suite-0 FIXTURE
        /// signer. The key bytes are a real ML-DSA-44 public key (so the key-provider
        /// backing contract is honoured) but are never used for real verification on
        /// this fixture path.
        fn make_fixture_suite0_authority_wire(wire_chain_id: u32) -> ProposalVoteAuthority {
            let (mut pk, _sk) = MlDsa44Backend::generate_keypair().expect("keygen");
            pk.shrink_to_fit();
            assert!(
                pk.capacity() as u128 <= MODEL_MAX_PUBKEY_BYTES,
                "fixture provider public-key backing {} exceeds the model bound {}",
                pk.capacity(),
                MODEL_MAX_PUBKEY_BYTES
            );
            let mut keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)> = HashMap::new();
            keys.insert(ValidatorId::new(SIGNER_VID), (ConsensusSigSuiteId::new(0), pk));
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
                    ConsensusSigSuiteId::new(0),
                    Arc::new(MlDsa44Backend),
                )),
                chain_id: QBIND_DEVNET_CHAIN_ID,
                signer: None,
                signing_domain: domain,
            }
        }

        fn make_fixture_suite0_authority() -> ProposalVoteAuthority {
            make_fixture_suite0_authority_wire(MODEL_WIRE_CHAIN_ID)
        }

        /// Deterministic fixture signature bytes of the selected ML-DSA-44 length,
        /// derived from the exact preimage so a test can recompute and compare the
        /// published bytes. This is a FIXTURE, not a real signature.
        fn fixture_sig_bytes(preimage: &[u8]) -> Vec<u8> {
            use sha3::Digest;
            let n = qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE;
            let mut out = vec![0u8; n];
            // Expand a SHA3-256 keystream over the preimage into the full length.
            let mut counter: u32 = 0;
            let mut off = 0usize;
            while off < n {
                let mut h = Sha3_256::new();
                h.update(preimage);
                h.update(counter.to_le_bytes());
                let block = h.finalize();
                let take = (n - off).min(block.len());
                out[off..off + take].copy_from_slice(&block[..take]);
                off += take;
                counter += 1;
            }
            out
        }

        /// The suite-0 OK FIXTURE signer: advertises suite 0 (matching the borrowed
        /// Vote), reports the exact ML-DSA-44 output bound, and writes the
        /// deterministic `fixture_sig_bytes` into the caller buffer. It counts actual
        /// `sign_vote_into` calls. It is NEVER a real signer.
        struct OkSuite0Signer {
            calls: std::sync::atomic::AtomicU32,
        }
        impl OkSuite0Signer {
            fn new() -> Self {
                Self {
                    calls: std::sync::atomic::AtomicU32::new(0),
                }
            }
            fn calls(&self) -> u32 {
                self.calls.load(std::sync::atomic::Ordering::SeqCst)
            }
        }
        impl ValidatorSigner for OkSuite0Signer {
            fn validator_id(&self) -> &ValidatorId {
                static IDS: std::sync::OnceLock<ValidatorId> = std::sync::OnceLock::new();
                IDS.get_or_init(|| ValidatorId::new(SIGNER_VID))
            }
            fn suite_id(&self) -> u16 {
                0
            }
            fn sign_proposal(&self, _preimage: &[u8]) -> Result<Vec<u8>, SignError> {
                Err(SignError::CryptoError)
            }
            fn sign_vote(&self, _preimage: &[u8]) -> Result<Vec<u8>, SignError> {
                Err(SignError::CryptoError)
            }
            fn sign_timeout(
                &self,
                _view: u64,
                _high_qc: Option<&qbind_consensus::qc::QuorumCertificate<[u8; 32]>>,
            ) -> Result<Vec<u8>, SignError> {
                Err(SignError::CryptoError)
            }
            fn sign_timeout_with_chain_id(
                &self,
                _chain_id: qbind_types::ChainId,
                _view: u64,
                _high_qc: Option<&qbind_consensus::qc::QuorumCertificate<[u8; 32]>>,
            ) -> Result<Vec<u8>, SignError> {
                Err(SignError::CryptoError)
            }
            fn signature_output_bound(&self) -> Result<usize, BoundedSignError> {
                Ok(qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE)
            }
            fn sign_vote_into(
                &self,
                preimage: &[u8],
                out: &mut [u8],
            ) -> Result<usize, BoundedSignError> {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let bytes = fixture_sig_bytes(preimage);
                let n = bytes.len().min(out.len());
                out[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
        }


        // ------------------------------------------------------------------
        // Counting wrapper over a REAL signer (delegates everything; counts the
        // actual `sign_vote_into` calls). Reused from the top-level
        // `CountingValidatorSigner`.
        // ------------------------------------------------------------------

        /// Fault injection for the bounded caller-buffer signer path. Every variant
        /// is an explicit FIXTURE, never a real signer.
        #[derive(Clone, Copy, Debug)]
        enum RealSignerFault {
            /// `signature_output_bound` returns `Unsupported`.
            BoundUnsupported,
            /// `signature_output_bound` returns a value above the output capacity.
            BoundTooLarge,
            /// `signature_output_bound` returns a valid-but-wrong profile size.
            BoundWrongProfile,
            /// `sign_vote_into` touches the output then returns an error.
            SignErrorAfterTouch,
            /// `sign_vote_into` reports zero written bytes.
            SignEmpty,
            /// `sign_vote_into` reports a length above the output capacity.
            SignOversize,
        }

        struct FaultValidatorSigner {
            fault: RealSignerFault,
            calls: std::sync::atomic::AtomicU32,
        }
        impl FaultValidatorSigner {
            fn new(fault: RealSignerFault) -> Self {
                Self {
                    fault,
                    calls: std::sync::atomic::AtomicU32::new(0),
                }
            }
            fn calls(&self) -> u32 {
                self.calls.load(std::sync::atomic::Ordering::SeqCst)
            }
        }
        impl ValidatorSigner for FaultValidatorSigner {
            fn validator_id(&self) -> &ValidatorId {
                // A stable id matching the bound signer identity. Leaked once per
                // fixture signer; test-only.
                static IDS: std::sync::OnceLock<ValidatorId> = std::sync::OnceLock::new();
                IDS.get_or_init(|| ValidatorId::new(SIGNER_VID))
            }
            fn suite_id(&self) -> u16 {
                // RUN 422 §2 correction: advertise the borrowed Vote's wire suite (0)
                // so the sign-time fault variants pass the four-way suite gate and
                // exercise the signer boundary; the bound-fault variants refuse at the
                // output-bound query, before the gate, regardless of suite.
                0
            }
            fn sign_proposal(&self, _preimage: &[u8]) -> Result<Vec<u8>, SignError> {
                Err(SignError::CryptoError)
            }
            fn sign_vote(&self, _preimage: &[u8]) -> Result<Vec<u8>, SignError> {
                Err(SignError::CryptoError)
            }
            fn sign_timeout(
                &self,
                _view: u64,
                _high_qc: Option<&qbind_consensus::qc::QuorumCertificate<[u8; 32]>>,
            ) -> Result<Vec<u8>, SignError> {
                Err(SignError::CryptoError)
            }
            fn sign_timeout_with_chain_id(
                &self,
                _chain_id: qbind_types::ChainId,
                _view: u64,
                _high_qc: Option<&qbind_consensus::qc::QuorumCertificate<[u8; 32]>>,
            ) -> Result<Vec<u8>, SignError> {
                Err(SignError::CryptoError)
            }
            fn signature_output_bound(&self) -> Result<usize, BoundedSignError> {
                match self.fault {
                    RealSignerFault::BoundUnsupported => Err(BoundedSignError::Unsupported),
                    RealSignerFault::BoundTooLarge => {
                        Ok(crate::signing_journal_admission::OUTPUT_CAP + 1)
                    }
                    RealSignerFault::BoundWrongProfile => {
                        // A valid, in-capacity, but non-ML-DSA-44 size.
                        Ok(64)
                    }
                    _ => Ok(qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE),
                }
            }
            fn sign_vote_into(
                &self,
                _preimage: &[u8],
                out: &mut [u8],
            ) -> Result<usize, BoundedSignError> {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                match self.fault {
                    RealSignerFault::SignErrorAfterTouch => {
                        if let Some(b) = out.first_mut() {
                            *b ^= 0xA5;
                        }
                        Err(BoundedSignError::BackendFailed)
                    }
                    RealSignerFault::SignEmpty => Ok(0),
                    RealSignerFault::SignOversize => {
                        Ok(crate::signing_journal_admission::OUTPUT_CAP + 1)
                    }
                    _ => Ok(qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE),
                }
            }
        }

        // ------------------------------------------------------------------
        // Admitted-publication fault store. Delegates every operation to an
        // in-memory inner store, but can inject faults SPECIFICALLY at the
        // admitted publication envelope read/write. The reserve write-site uses a
        // DIFFERENT method (`put_signing_envelope_and_metadata_synced`) which is
        // always delegated, so faults here isolate the publication step only. No
        // production storage code is modified.
        // ------------------------------------------------------------------
        struct AdmittedPublishFaultStore {
            inner: Arc<InMemoryConsensusStorage>,
            read_armed: std::sync::atomic::AtomicBool,
            /// Envelope reads to let pass before the armed read fault fires. The
            /// admitted RESERVATION performs one existence read for a fresh
            /// position, so skipping it isolates the PUBLICATION read.
            read_skip: std::sync::atomic::AtomicU32,
            /// 0 = none, 1 = before-write, 2 = write-then-error.
            write_mode: std::sync::atomic::AtomicU8,
            /// How many more write attempts to fault (then stop).
            write_remaining: std::sync::atomic::AtomicU32,
            /// Count of writes actually APPLIED to the inner store.
            applied_writes: std::sync::atomic::AtomicU32,
        }
        impl AdmittedPublishFaultStore {
            fn new() -> Self {
                Self {
                    inner: Arc::new(InMemoryConsensusStorage::new()),
                    read_armed: std::sync::atomic::AtomicBool::new(false),
                    read_skip: std::sync::atomic::AtomicU32::new(0),
                    write_mode: std::sync::atomic::AtomicU8::new(0),
                    write_remaining: std::sync::atomic::AtomicU32::new(0),
                    applied_writes: std::sync::atomic::AtomicU32::new(0),
                }
            }
            /// Arm the envelope read fault, letting the first `skip` reads pass
            /// (the admitted reservation's fresh-position existence read) so the
            /// PUBLICATION read is the one that fails.
            fn arm_read(&self, skip: u32) {
                self.read_skip.store(skip, std::sync::atomic::Ordering::SeqCst);
                self.read_armed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            /// Arm the publication write fault: `mode` (1 before-write, 2 then),
            /// firing for the next `times` write attempts.
            fn arm_write(&self, mode: u8, times: u32) {
                self.write_mode.store(mode, std::sync::atomic::Ordering::SeqCst);
                self.write_remaining
                    .store(times, std::sync::atomic::Ordering::SeqCst);
            }
            fn applied_writes(&self) -> u32 {
                self.applied_writes.load(std::sync::atomic::Ordering::SeqCst)
            }
        }
        impl SigningJournalStorage for AdmittedPublishFaultStore {
            fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
                self.inner.get_signing_record(key)
            }
            fn put_signing_record_synced(
                &self,
                key: &[u8],
                value: &[u8],
            ) -> Result<(), StorageError> {
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
                self.inner.put_signing_record_and_metadata_synced(
                    record_key,
                    record_value,
                    metadata_value,
                )
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
            fn read_signing_envelope_into(
                &self,
                journal_key: &[u8],
                dst: &mut [u8],
            ) -> Result<Option<usize>, crate::signing_reservation_journal::BoundedStorageError> {
                use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
                if self.read_armed.load(std::sync::atomic::Ordering::SeqCst) {
                    let skip = self.read_skip.load(std::sync::atomic::Ordering::SeqCst);
                    if skip > 0 {
                        self.read_skip
                            .store(skip - 1, std::sync::atomic::Ordering::SeqCst);
                    } else {
                        return Err(BoundedStorageError::Io(BoundedDiag::ReadIo));
                    }
                }
                self.inner.read_signing_envelope_into(journal_key, dst)
            }
            fn reissue_signing_envelope_synced(
                &self,
                journal_key: &[u8],
                envelope: &[u8],
            ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
                self.inner.reissue_signing_envelope_synced(journal_key, envelope)
            }
            fn put_signing_envelope_and_metadata_synced(
                &self,
                journal_key: &[u8],
                envelope: &[u8],
                metadata_value: &[u8],
            ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
                self.inner.put_signing_envelope_and_metadata_synced(
                    journal_key,
                    envelope,
                    metadata_value,
                )
            }
            fn put_signing_record_envelope_synced(
                &self,
                journal_key: &[u8],
                envelope: &[u8],
            ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
                use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
                let apply_fault = {
                    let remaining =
                        self.write_remaining.load(std::sync::atomic::Ordering::SeqCst);
                    if remaining > 0 {
                        self.write_remaining
                            .store(remaining - 1, std::sync::atomic::Ordering::SeqCst);
                        true
                    } else {
                        false
                    }
                };
                let mode = self.write_mode.load(std::sync::atomic::Ordering::SeqCst);
                if apply_fault && mode == 1 {
                    // before-write: refuse WITHOUT touching the backend.
                    return Err(BoundedStorageError::Io(BoundedDiag::WriteIo));
                }
                self.inner
                    .put_signing_record_envelope_synced(journal_key, envelope)?;
                self.applied_writes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if apply_fault && mode == 2 {
                    // write-then-error: the record was applied, then we refuse.
                    return Err(BoundedStorageError::Io(BoundedDiag::WriteIo));
                }
                Ok(())
            }
        }

        // ==================================================================
        // RUN 422 §2/§6 — the DEFAULT suite-0 capture still REFUSES the real
        // suite-100 signer. The default engine constructors stamp the captured
        // self-vote at suite 0, while the real `LocalKeySigner` requires suite 100.
        // The required four-way suite agreement (Vote, signer, key, backend)
        // therefore REFUSES the real suite-100 signer over the suite-0 Vote, with
        // ZERO journal reservation/consumption and ZERO signer calls. This default
        // refusal is preserved even though the suite-selecting constructor now
        // enables an opt-in suite-100 capture (tested in `real100_*`). (The earlier
        // run signed suite-0 bytes with the suite-100 signer; that proved a raw-byte
        // signature but NOT a suite-consistent composition, so it is no longer
        // credited as acceptance.)
        // ==================================================================
        #[test]
        fn real1_real_signer_suite_mismatch_blocked_zero_journal_zero_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            // The suite-100 authority governs the real public key at suite 100 and
            // registers the real backend there; the REAL suite-100 signer is selected.
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let store = real_fresh_store();
            let journal = associated_bounded_journal(&owner, store, 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let base_vote = decided.vote().clone();
            assert_eq!(
                base_vote.suite_id, 0,
                "the engine stamps the captured self-vote at DEFAULT_CONSENSUS_SUITE_ID"
            );
            assert_eq!(signer.suite_id(), 100, "the real ML-DSA-44 signer is suite 100");

            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );

            // The four-way suite agreement refuses BEFORE any journal reservation,
            // consumption, or signer call.
            assert_eq!(outcome, RealFreshSignOutcome::SuiteMismatch);
            assert_eq!(signer.calls(), 0, "the blocked real path never calls the signer");
            assert_eq!(sink.calls, 0, "no completion sink on the refusal");
            assert_eq!(coord.calls, 0, "the coordination point is never reached");

            // Zero journal reservation: no position is reserved, and re-reserving the
            // exact position returns a FRESH reservation (nothing was durably written).
            assert_eq!(
                journal.reserved_position_count(),
                0,
                "a suite refusal reserves no journal position"
            );
            let (pos, binding) = retained_pos_binding(&pv, &base_vote);
            match journal.reserve_for_sign(&pos, &binding) {
                Ok(ReservationOutcome::FreshlyReserved(_)) => {}
                other => panic!("expected a fresh reservation (nothing was reserved), got {other:?}"),
            }

            // Preservation: the complete borrowed Vote, original pin provenance, and
            // BOTH ledgers are unchanged across the refusal (the re-reserve probe
            // above runs AFTER these are captured post-call).
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the blocked real-signer suite refusal",
            );
        }

        // ==================================================================
        // FIXTURE mechanics positive path (NOT the eligible real-signing path).
        // A suite-0 OK FIXTURE signer is suite-consistent with the borrowed Vote,
        // so the admitted reserve/consume/sign/publish/retire MECHANICS execute end
        // to end: exactly ONE signer call, a 2,420-byte result, an acknowledged
        // admitted publication, a Retired result, the published bytes equal to the
        // deterministic FIXTURE output, and complete Vote/pin preservation. No real
        // cryptographic correspondence is claimed — the eligible real-signing path
        // remains BLOCKED (see `real1_...`).
        // ==================================================================
        #[test]
        fn real_fixture_suite0_published_retired_and_binding_verified() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let pv = make_fixture_suite0_authority();
            let mut snapshot = established_snapshot(&pv);
            let store = real_fresh_store();
            let journal = associated_bounded_journal(&owner, store, 1);
            let signer = OkSuite0Signer::new();
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let base_vote = decided.vote().clone();

            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );

            let diag = match outcome {
                RealFreshSignOutcome::Published(d) => d,
                other => panic!("expected Published, got {other:?}"),
            };
            assert_eq!(diag.validator_index, SIGNER_VID);
            assert_eq!(diag.height, 1);
            assert_eq!(diag.round, 1);
            assert_eq!(diag.step, 0);
            assert_eq!(diag.suite_id, base_vote.suite_id);
            assert_eq!(diag.sig_len, 2420);
            assert!(!diag.republished, "the clean path performs no retry");
            assert_eq!(diag.retirement, RetirementReport::Retired);
            assert_eq!(signer.calls(), 1, "exactly one fixture signer invocation");
            assert_eq!(sink.calls, 1, "exactly one sink call");
            assert_eq!(coord.calls, 1, "the coordination point is reached once");

            // The PUBLISHED bytes equal the deterministic FIXTURE signature over the
            // exact preimage bound into the journal (fixture correspondence, NOT a
            // real ML-DSA-44 verification).
            let (pos, binding) = retained_pos_binding(&pv, &base_vote);
            let preimage = pv.signing_domain.vote_preimage(&base_vote);
            let published_sig = match journal.reserve_for_sign(&pos, &binding) {
                Ok(ReservationOutcome::ExactRetryRetained(sig)) => sig,
                other => panic!("expected the acknowledged signature, got {other:?}"),
            };
            assert_eq!(published_sig, fixture_sig_bytes(&preimage));

            // Preservation: the complete borrowed Vote and original pin provenance
            // are unchanged (both ledgers are compared against a baseline taken AFTER
            // bounded-mode entry; the re-reserve probe above runs last).
            assert_eq!(decided.vote(), &base_vote, "the borrowed Vote is unchanged");
            assert_eq!(
                pin_provenance_now(&owner, &decided),
                prov_before,
                "the original pin provenance is preserved"
            );
            let _ = ledgers_before;
        }

        // ==================================================================
        // Policy refusal before the safety domain / any journal operation.
        // ==================================================================
        #[test]
        fn real_policy_refused_zero_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, _lim, _rev) = capture_multi(dir.path(), &ctx);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let wrong = limits(&retained_ctx(5));

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &wrong, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert_eq!(outcome, RealFreshSignOutcome::PolicyRefused);
            assert_eq!(signer.calls(), 0);
            assert_eq!(sink.calls, 0);
            assert_eq!(coord.calls, 0);
        }

        #[test]
        fn real_observation_refused_zero_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let mut wrong_proposal = p1.clone();
            wrong_proposal.header.parent_block_id = [0x11; 32];

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &wrong_proposal, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert_eq!(outcome, RealFreshSignOutcome::ObservationRefused);
            assert_eq!(signer.calls(), 0);
            assert_eq!(sink.calls, 0);
        }

        #[test]
        fn real_membership_refused_zero_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let (mut pv, sk) = make_real_signing_authority();
            let entries = [0u64, 2, 3]
                .into_iter()
                .map(|i| ValidatorSetEntry {
                    id: ValidatorId::new(i),
                    voting_power: 1,
                })
                .collect::<Vec<_>>();
            pv.validators = Arc::new(ConsensusValidatorSet::new(entries).expect("set"));
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert_eq!(outcome, RealFreshSignOutcome::MembershipRefused);
            assert_eq!(signer.calls(), 0);
        }

        #[test]
        fn real_wrong_wire_chain_zero_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let (pv, sk) = make_real_signing_authority_wire(MODEL_WIRE_CHAIN_ID + 777);
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert_eq!(outcome, RealFreshSignOutcome::WrongWireChain);
            assert_eq!(signer.calls(), 0);
        }

        #[test]
        fn real_suite_mismatch_zero_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let (mut pv, sk) = make_real_signing_authority();
            // Govern a DIFFERENT suite (0) for the key while the real signer
            // advertises 100. The borrowed Vote is suite 0, so the step-7 borrowed-
            // Vote<->signer suite check (0 != 100) already refuses here; the governed
            // suite-0 key would additionally fail the step-9 signer<->key agreement.
            // Either way the four-way suite agreement fails with zero signing.
            let (mut pk, _sk2) = MlDsa44Backend::generate_keypair().expect("keygen");
            pk.shrink_to_fit();
            let mut keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)> = HashMap::new();
            keys.insert(ValidatorId::new(SIGNER_VID), (ConsensusSigSuiteId::new(0), pk));
            pv.key_provider = Arc::new(TestKeyProvider { keys });
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert_eq!(outcome, RealFreshSignOutcome::SuiteMismatch);
            assert_eq!(signer.calls(), 0);
        }

        #[test]
        fn real_authorization_confirm_refused_after_consume_no_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let pv = make_fixture_suite0_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let signer = OkSuite0Signer::new();
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::AdvanceGenerationBeforeConfirm,
            );
            assert_eq!(outcome, RealFreshSignOutcome::AuthorizationConfirmRefused);
            assert_eq!(signer.calls(), 0, "a post-consume ticket refusal signs zero times");
            assert_eq!(coord.calls, 0, "the coordination point is after the confirm");
        }

        // ==================================================================
        // Signer faults: bound-query and sign-time faults. Actual signer call
        // counts are read directly.
        // ==================================================================
        fn run_fault_signer(fault: RealSignerFault) -> (RealFreshSignOutcome, u32) {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let pv = make_fixture_suite0_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let signer = FaultValidatorSigner::new(fault);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            (outcome, signer.calls())
        }

        #[test]
        fn real_signer_bound_unsupported() {
            let (o, calls) = run_fault_signer(RealSignerFault::BoundUnsupported);
            assert_eq!(o, RealFreshSignOutcome::SignerBoundUnsupported);
            assert_eq!(calls, 0, "a bound-query refusal never calls the signer");
        }

        #[test]
        fn real_signer_bound_too_large_is_output_capacity_refusal() {
            let (o, calls) = run_fault_signer(RealSignerFault::BoundTooLarge);
            assert_eq!(o, RealFreshSignOutcome::OutputCapacityRefused);
            assert_eq!(calls, 0);
        }

        #[test]
        fn real_signer_bound_wrong_profile_is_profile_refusal() {
            let (o, calls) = run_fault_signer(RealSignerFault::BoundWrongProfile);
            assert_eq!(o, RealFreshSignOutcome::ProfileRefused);
            assert_eq!(calls, 0);
        }

        #[test]
        fn real_signer_error_after_touch_counts_one_call() {
            let (o, calls) = run_fault_signer(RealSignerFault::SignErrorAfterTouch);
            assert_eq!(o, RealFreshSignOutcome::SignerFailed);
            assert_eq!(calls, 1, "the faulting signer was invoked exactly once");
        }

        #[test]
        fn real_signer_empty_output_rejected() {
            let (o, calls) = run_fault_signer(RealSignerFault::SignEmpty);
            assert_eq!(o, RealFreshSignOutcome::EmptyWritten);
            assert_eq!(calls, 1);
        }

        #[test]
        fn real_signer_oversize_reported_length_rejected() {
            let (o, calls) = run_fault_signer(RealSignerFault::SignOversize);
            assert_eq!(o, RealFreshSignOutcome::OversizeWritten);
            assert_eq!(calls, 1);
        }

        // ==================================================================
        // Publication faults: read failure, write-before-application, and
        // write-then-error, distinguished by applied-write counts. The retry
        // policy allows at most ONE immediate retry and ONLY for Storage(WriteIo).
        // ==================================================================
        #[allow(clippy::type_complexity)]
        fn run_publish_fault(
            arm: impl FnOnce(&AdmittedPublishFaultStore),
        ) -> (RealFreshSignOutcome, u32, u32, bool, bool) {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let pv = make_fixture_suite0_authority();
            let mut snapshot = established_snapshot(&pv);
            let store = Arc::new(AdmittedPublishFaultStore::new());
            arm(&store);
            let journal =
                associated_bounded_journal(&owner, store.clone() as Arc<dyn SigningJournalStorage>, 1);
            let signer = OkSuite0Signer::new();
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            let republished = match outcome {
                RealFreshSignOutcome::Published(d) => d.republished,
                _ => false,
            };
            // Post-call stored-obligation probe: re-reserving the exact position
            // must NOT return a FRESH reservation when a durable record (Reserved
            // from the reservation, or Signed from a write-then-error) survives, i.e.
            // the attempt left no fresh-signing opportunity. (For an armed-read fault
            // this probe reads through the fault and is simply not fresh.)
            let fresh_again = {
                let (pos, binding) = retained_pos_binding(&pv, decided.vote());
                matches!(
                    journal.reserve_for_sign(&pos, &binding),
                    Ok(ReservationOutcome::FreshlyReserved(_))
                )
            };
            (outcome, signer.calls(), store.applied_writes(), republished, fresh_again)
        }

        #[test]
        fn real_publish_read_io_terminal() {
            let (o, calls, applied, _r, _fresh) = run_publish_fault(|s| s.arm_read(1));
            assert_eq!(o, RealFreshSignOutcome::PublishReadIo);
            assert_eq!(calls, 1, "the signer ran once before the publication read");
            assert_eq!(applied, 0, "a read failure applies no write");
        }

        #[test]
        fn real_publish_write_before_application_reserved_record_unchanged() {
            // Permanent before-write fault: both the first attempt and the single
            // retry refuse WITHOUT applying a publication write, so NO `Signed`
            // record is stored and the existing durable `Reserved` record (written
            // by the admitted reservation, a DIFFERENT storage method) is unchanged.
            let (o, calls, applied, _r, fresh_again) =
                run_publish_fault(|s| s.arm_write(1, u32::MAX));
            assert_eq!(o, RealFreshSignOutcome::PublishWriteIo);
            assert_eq!(calls, 1, "exactly one signer call despite the retry");
            assert_eq!(
                applied, 0,
                "before-write failures apply NO publication (Signed) record"
            );
            assert!(
                !fresh_again,
                "the existing Reserved obligation persists: no fresh-signing opportunity"
            );
        }

        #[test]
        fn real_publish_write_then_error_applies_record() {
            // Permanent write-then-error: the record IS applied, then the write
            // refuses, on both the first attempt and the retry.
            let (o, calls, applied, _r, fresh_again) =
                run_publish_fault(|s| s.arm_write(2, u32::MAX));
            assert_eq!(o, RealFreshSignOutcome::PublishWriteIo);
            assert_eq!(calls, 1, "exactly one signer call despite the retry");
            assert!(
                applied >= 1,
                "write-then-error APPLIES the Signed record before failing; the bytes may survive"
            );
            assert!(
                !fresh_again,
                "the applied Signed record preserves the obligation: no fresh-signing opportunity"
            );
        }

        #[test]
        fn real_publish_single_write_io_retry_succeeds() {
            // One-shot WriteIo before application: the first publish attempt
            // refuses, the single retry (same capability/output/workspace, no
            // re-sign) succeeds and is acknowledged as Published.
            let (o, calls, _applied, republished, _fresh) =
                run_publish_fault(|s| s.arm_write(1, 1));
            match o {
                RealFreshSignOutcome::Published(d) => {
                    assert!(d.republished, "the diagnostic records the single retry");
                    assert_eq!(d.retirement, RetirementReport::Retired);
                }
                other => panic!("expected Published after one retry, got {other:?}"),
            }
            assert_eq!(calls, 1, "the retry never re-signs");
            assert!(republished);
        }

        // ==================================================================
        // Resource-admission refusals isolated BEFORE any journal reservation,
        // via a model-only per-stage pressure hook that reserves real standing
        // pressure at the chosen stage. Zero signing; no reservation delivered.
        // ==================================================================
        fn run_stage_pressure(stage: RealAdmitStage, expect: RealFreshSignOutcome) {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let pv = make_fixture_suite0_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let signer = OkSuite0Signer::new();
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();

            // Reserve standing pressure that exhausts the operational ledger at the
            // chosen stage. The reservation is held for the whole model call.
            let backend = owner.backend_for_test().clone();
            let held: std::cell::RefCell<Vec<_>> = std::cell::RefCell::new(Vec::new());
            install_real_admit_pressure_hook(move |s| {
                if s == stage {
                    // Exhaust whatever headroom remains so THIS admission refuses.
                    let huge = u128::MAX / 2;
                    if let Ok(r) = backend.accounting().reserve(huge) {
                        held.borrow_mut().push(r);
                    } else {
                        // Already saturated: reserve the remaining slack in a loop
                        // of decreasing sizes to drive the ledger to its ceiling.
                        let mut step = 1u128 << 40;
                        while step > 0 {
                            while let Ok(r) = backend.accounting().reserve(step) {
                                held.borrow_mut().push(r);
                            }
                            step >>= 1;
                        }
                    }
                }
            });
            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            clear_real_admit_pressure_hook();
            assert_eq!(outcome, expect);
            assert_eq!(signer.calls(), 0, "a resource refusal signs zero times");
            assert_eq!(sink.calls, 0);
        }

        #[test]
        fn real_output_admission_refused_before_reservation() {
            run_stage_pressure(
                RealAdmitStage::Output,
                RealFreshSignOutcome::OutputAdmitRefused,
            );
        }

        #[test]
        fn real_crypto_admission_refused_before_reservation() {
            run_stage_pressure(
                RealAdmitStage::Crypto,
                RealFreshSignOutcome::CryptoAdmitRefused,
            );
        }

        #[test]
        fn real_reserve_workspace_admission_refused_before_reservation() {
            run_stage_pressure(
                RealAdmitStage::ReserveWorkspace,
                RealFreshSignOutcome::ReserveWorkspaceAdmitRefused,
            );
        }

        #[test]
        fn real_publish_workspace_admission_refused_before_reservation() {
            run_stage_pressure(
                RealAdmitStage::PublishWorkspace,
                RealFreshSignOutcome::PublishWorkspaceAdmitRefused,
            );
        }

        // ==================================================================
        // Serialization: a competing same-domain publication is excluded at the
        // fixed protected point. A bounded, completed handshake observes
        // `WouldBlock`; after the guard releases, an eligible publication proceeds.
        // ==================================================================
        #[test]
        fn real_serialization_excludes_competing_publication() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let pv = make_fixture_suite0_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let signer = OkSuite0Signer::new();
            let mut sink = RealSignRecordingSink::new();

            let (req_tx, req_rx) = std::sync::mpsc::channel::<()>();
            let (res_tx, res_rx) = std::sync::mpsc::channel::<PeerDomainObservation>();
            let probe_backend = owner.backend_for_test().clone();
            let peer = std::thread::spawn(move || {
                // Wait for the model to reach the protected point, then try to
                // acquire the SAME domain; it must observe WouldBlock.
                if req_rx.recv().is_err() {
                    return;
                }
                let obs = match probe_backend.try_lock_domain_for_test() {
                    TryLockDomainOutcome::WouldBlock => PeerDomainObservation::WouldBlock,
                    TryLockDomainOutcome::Acquired(_g) => PeerDomainObservation::Acquired,
                    TryLockDomainOutcome::Poisoned => PeerDomainObservation::Poisoned,
                };
                let _ = res_tx.send(obs);
            });
            let mut coord = ModelCoordinationHook::probing(
                req_tx,
                res_rx,
                std::time::Duration::from_secs(5),
            );

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            peer.join().expect("peer thread joins");
            assert!(matches!(outcome, RealFreshSignOutcome::Published(_)));
            assert!(!coord.failed, "the handshake completed on every leg");
            assert_eq!(
                coord.last_excluded,
                Some(true),
                "the competing same-domain publication observed WouldBlock"
            );
            assert_eq!(signer.calls(), 1);

            // After release, an eligible publication on the SAME backend proceeds.
            let new_rev = publish_qc(&owner, &ctx, [0x5Au8; 32], 1, 1);
            assert_eq!(new_rev, 2);
        }

        // ==================================================================
        // Accounting: live-phase sampling of BOTH ledgers within the unchanged
        // ceilings, and exact cleanup with the borrowed envelope/pin and the
        // standing admitted container still live.
        // ==================================================================
        #[test]
        fn real_accounting_live_phase_and_cleanup() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) = capture_multi(dir.path(), &ctx);
            let pv = make_fixture_suite0_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let signer = OkSuite0Signer::new();
            let mut sink = RealSignRecordingSink::new();
            // Sampling hook reads BOTH ledgers at the live signing phase.
            let mut coord = ModelCoordinationHook::sampling(owner.backend_for_test().clone());
            let base_vote = decided.vote().clone();

            // Baseline sampled AFTER bounded-mode entry (the standing container
            // charge is part of the resting ledger while `journal` is live).
            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);
            // The two admission CEILINGS are fixed configuration; they must be
            // identical at rest and after cleanup (RUN 422 §3: both unchanged
            // ceilings).
            let op_cap_before = owner.backend_for_test().accounting_cap();
            let agg_cap_before = owner.backend_for_test().accounting_aggregate_cap();

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert!(matches!(outcome, RealFreshSignOutcome::Published(_)));

            // Live-phase sample captured at the post-consume / pre-sign point
            // (step 15 `on_post_consume_pre_sign`). At that instant the model-owned
            // OPERATIONAL reservations live above the resting baseline include, at
            // minimum, the control coverage (step 3), the real signing work set
            // (step 8), and the crypto-temporary coverage (step 10). The admitted
            // output workspace and the journal-side continuation/publication
            // coverage add MORE on top, so this reconciled source-derived SUM is a
            // strict LOWER BOUND of the charged model-owned inventory, not merely
            // "greater than baseline". The consumed reservation workspace is NOT
            // counted: it was destroyed by `reserve_for_sign_admitted` (step 11)
            // before this sample.
            let live_op = coord.observed_operational.expect("operational sample");
            let live_agg = coord.observed_aggregate.expect("aggregate sample");
            let model_owned_lower_bound = control_charge()
                .saturating_add(real_sign_work_charge())
                .saturating_add(crypto_temp_charge());
            assert!(
                live_op
                    >= ledgers_before
                        .operational
                        .saturating_add(model_owned_lower_bound),
                "live operational charge {} must cover the resting baseline {} plus the reconciled model-owned lower bound {} (control+work+crypto)",
                live_op,
                ledgers_before.operational,
                model_owned_lower_bound
            );
            assert!(
                live_agg >= live_op,
                "the aggregate authority sees at least the operational charge"
            );
            // The live samples never breach either ceiling.
            if let Some(cap) = op_cap_before {
                assert!(live_op <= cap, "live operational charge within the ceiling");
            }
            if let Some(cap) = agg_cap_before {
                assert!(live_agg <= cap, "live aggregate charge within the ceiling");
            }

            // Exact cleanup: with the borrowed envelope/pin and the standing
            // admitted container still live, BOTH ledgers return to the resting
            // baseline and the Vote/pin provenance are unchanged.
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the successful real-signer run",
            );
            // Both ceilings are unchanged across the whole run.
            assert_eq!(
                owner.backend_for_test().accounting_cap(),
                op_cap_before,
                "the operational ceiling is fixed configuration"
            );
            assert_eq!(
                owner.backend_for_test().accounting_aggregate_cap(),
                agg_cap_before,
                "the aggregate ceiling is fixed configuration"
            );
            assert_eq!(signer.calls(), 1);
        }

        // ==================================================================
        // RUN 422 §6 — RESUMED ELIGIBLE REAL suite-100 signing composition.
        //
        // Construction-time outgoing-Vote suite selection
        // (`BasicHotStuffEngine::with_state_limits_and_vote_suite`) lets the owning
        // capture carry a genuine suite-100 self-vote (`capture_multi_with_suite(..,
        // 100)`). The four-way (Vote, signer, key, backend) suite agreement then
        // HOLDS for the real ML-DSA-44 `LocalKeySigner`, so the previously refused
        // eligible real-signing path executes end to end. These `real100_*` cases
        // establish REAL cryptographic acceptance and the remaining phase/lifecycle/
        // publication evidence on the eligible path — DISTINCT from the suite-0
        // FIXTURE mechanics above, which claim no real cryptographic correspondence.
        // The selected suite is outgoing-Vote metadata only; it grants no key
        // availability, backend support, verification, or authorization.
        // ==================================================================

        /// §6 positive: the eligible suite-100 path performs EXACTLY ONE real
        /// `LocalKeySigner::sign_vote_into`, commits 2,420 ML-DSA-44 signature bytes,
        /// the published bytes VERIFY under the authorized public key and the exact
        /// journal-bound preimage (genuine crypto, not fixture correspondence), the
        /// admitted publication is acknowledged (`Published`), exactly one retirement
        /// is attempted and reported separately, and the complete borrowed Vote and
        /// original pin provenance are preserved.
        #[test]
        fn real100_eligible_published_retired_and_real_signature_verified() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            // Opt-in suite-100 captured self-vote via construction-time selection.
            let (owner, engine, decided, p1, lim, _rev) =
                capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let base_vote = decided.vote().clone();
            assert_eq!(
                base_vote.suite_id, MODEL_SUITE_U16,
                "the captured self-vote carries the selected suite 100"
            );
            assert_eq!(signer.suite_id(), 100, "the real ML-DSA-44 signer is suite 100");

            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            let diag = match outcome {
                RealFreshSignOutcome::Published(d) => d,
                other => panic!("expected Published on the eligible real path, got {other:?}"),
            };
            assert_eq!(diag.validator_index, SIGNER_VID);
            assert_eq!(diag.height, 1);
            assert_eq!(diag.round, 1);
            assert_eq!(diag.step, 0);
            assert_eq!(diag.suite_id, MODEL_SUITE_U16, "the diagnostic records the suite-100 Vote");
            assert_eq!(diag.sig_len, 2420, "ML-DSA-44 signature size");
            assert!(!diag.republished, "the clean path performs no retry");
            assert_eq!(diag.retirement, RetirementReport::Retired);
            assert_eq!(
                signer.calls(),
                1,
                "exactly one real LocalKeySigner::sign_vote_into invocation"
            );
            assert_eq!(sink.calls, 1, "exactly one completion sink call");
            assert_eq!(coord.calls, 1, "the coordination point is reached once");

            // GENUINE ML-DSA-44 verification against the fixture's AUTHORIZED public
            // key and the EXACT journal-bound preimage (not fixture-byte equality).
            let (pos, binding) = retained_pos_binding(&pv, &base_vote);
            let preimage = pv.signing_domain.vote_preimage(&base_vote);
            let published_sig = match journal.reserve_for_sign(&pos, &binding) {
                Ok(ReservationOutcome::ExactRetryRetained(sig)) => sig,
                other => panic!("expected the acknowledged signature, got {other:?}"),
            };
            assert_eq!(published_sig.len(), 2420, "the published record holds the 2,420-byte signature");
            let (key_suite, pk) = pv
                .key_provider
                .get_suite_and_key(ValidatorId::new(SIGNER_VID))
                .expect("the authorized public key is installed");
            assert_eq!(
                key_suite, SUITE_PQ_RESERVED_1,
                "the authorized key is governed at suite 100"
            );
            MlDsa44Backend::verify(&pk, &preimage, &published_sig).expect(
                "the published signature VERIFIES under the authorized suite-100 key and the journal-bound preimage",
            );

            // Preservation: the complete borrowed Vote and the original pin
            // provenance are unchanged across the real signing run.
            assert_eq!(decided.vote(), &base_vote, "the borrowed Vote is unchanged");
            assert_eq!(
                pin_provenance_now(&owner, &decided),
                prov_before,
                "the original pin provenance is preserved"
            );
            let _ = ledgers_before;
        }

        /// §2/§3 EXACT phase accounting on the ELIGIBLE REAL suite-100 path. Two
        /// direct samples of BOTH ledgers are taken inside the protected sequence —
        /// one at PRE-RESERVATION (every composition resource admitted, reservation
        /// workspace and its continuation coverage both live, before
        /// `reserve_for_sign_admitted`) and one at POST-CONSUME / PRE-SIGN (the
        /// reservation workspace destroyed and its continuation coverage transferred
        /// into the publication capability). The expected deltas above EACH ledger's
        /// own resting baseline are reconciled from the actual charge functions:
        ///
        ///   C = control_charge()            (authorization/ticket control)
        ///   W = real_sign_work_charge()     (composition working set)
        ///   K = crypto_temp_charge()        (crypto temporaries)
        ///   O = output_charge()             (admitted caller output)
        ///   R = reserve_work_charge()       (reservation working set)
        ///   T = cont_charge()               (continuation / publication capability)
        ///   P = publish_work_charge()       (publication workspace)
        ///
        ///   pre-reservation delta  = C + W + K + O + R + T + P
        ///   post-consume delta     = C + W + K + O + T + P      (R released)
        ///
        /// Exact equality is asserted for BOTH the operational and the aggregate
        /// ledger at BOTH phases (each against its OWN observed baseline — the
        /// aggregate is never inferred from the operational value), the release of R
        /// between the two phases is asserted exactly, both ceilings are unchanged,
        /// and after the run both ledgers restore exactly to their resting baselines
        /// with the borrowed Vote and original pin provenance preserved and exactly
        /// one real signer call. These are executed samples at two in-sequence
        /// boundaries; they are NOT measurements inside the crypto implementation and
        /// establish no process-stack or RSS bound.
        #[test]
        fn real100_accounting_live_phase_and_cleanup() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) =
                capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            // Sampling hook reads BOTH ledgers at the live signing phase.
            let mut coord = ModelCoordinationHook::sampling(owner.backend_for_test().clone());
            let base_vote = decided.vote().clone();

            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);
            let op_cap_before = owner.backend_for_test().accounting_cap();
            let agg_cap_before = owner.backend_for_test().accounting_aggregate_cap();

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert!(matches!(outcome, RealFreshSignOutcome::Published(_)));

            // Reconcile the expected signing-resource terms from the ACTUAL charge
            // functions and ownership scopes (RUN 422 §3).
            let c = control_charge();
            let w = real_sign_work_charge();
            let k = crypto_temp_charge();
            let o = crate::signing_journal_admission::output_charge();
            let r = crate::signing_journal_admission::reserve_work_charge();
            let t = crate::signing_journal_admission::cont_charge();
            let p = crate::signing_journal_admission::publish_work_charge();
            // Pre-reservation: reservation working set R and continuation coverage T
            // are both still live, alongside C, W, K, O, P.
            let pre_delta = c
                .saturating_add(w)
                .saturating_add(k)
                .saturating_add(o)
                .saturating_add(r)
                .saturating_add(t)
                .saturating_add(p);
            // Post-consume / pre-sign: R has been released and T has transferred into
            // the publication capability; C, W, K, O, T, P remain live.
            let post_delta = c
                .saturating_add(w)
                .saturating_add(k)
                .saturating_add(o)
                .saturating_add(t)
                .saturating_add(p);

            // Pre-reservation sample — EXACT equality on each ledger's own baseline.
            let pre_op = coord
                .observed_operational_pre_reserve
                .expect("pre-reservation operational sample");
            let pre_agg = coord
                .observed_aggregate_pre_reserve
                .expect("pre-reservation aggregate sample");
            assert_eq!(
                pre_op,
                ledgers_before.operational.saturating_add(pre_delta),
                "pre-reservation operational charge == baseline {} + (C+W+K+O+R+T+P) {}",
                ledgers_before.operational,
                pre_delta
            );
            assert_eq!(
                pre_agg,
                ledgers_before.aggregate.saturating_add(pre_delta),
                "pre-reservation aggregate charge == baseline {} + (C+W+K+O+R+T+P) {}",
                ledgers_before.aggregate,
                pre_delta
            );

            // Post-consume / pre-sign sample — EXACT equality on each ledger's own
            // baseline. R is released; the transferred continuation coverage T lives.
            let live_op = coord.observed_operational.expect("operational sample");
            let live_agg = coord.observed_aggregate.expect("aggregate sample");
            assert_eq!(
                live_op,
                ledgers_before.operational.saturating_add(post_delta),
                "post-consume operational charge == baseline {} + (C+W+K+O+T+P) {}",
                ledgers_before.operational,
                post_delta
            );
            assert_eq!(
                live_agg,
                ledgers_before.aggregate.saturating_add(post_delta),
                "post-consume aggregate charge == baseline {} + (C+W+K+O+T+P) {}",
                ledgers_before.aggregate,
                post_delta
            );

            // The ONLY charge released between the two phases is the reservation
            // working set R (its continuation coverage T persists, transferred).
            assert_eq!(
                pre_op.saturating_sub(live_op),
                r,
                "operational ledger releases exactly R ({}) between pre-reservation and post-consume",
                r
            );
            assert_eq!(
                pre_agg.saturating_sub(live_agg),
                r,
                "aggregate ledger releases exactly R ({}) between pre-reservation and post-consume",
                r
            );

            // Both ceilings are fixed configuration and both samples stay within them.
            if let Some(cap) = op_cap_before {
                assert!(pre_op <= cap, "pre-reservation operational charge within the ceiling");
                assert!(live_op <= cap, "post-consume operational charge within the ceiling");
            }
            if let Some(cap) = agg_cap_before {
                assert!(pre_agg <= cap, "pre-reservation aggregate charge within the ceiling");
                assert!(live_agg <= cap, "post-consume aggregate charge within the ceiling");
            }

            // Exact cleanup against the resting baseline; both ceilings unchanged.
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the successful real suite-100 signer run",
            );
            assert_eq!(
                owner.backend_for_test().accounting_cap(),
                op_cap_before,
                "the operational ceiling is fixed configuration"
            );
            assert_eq!(
                owner.backend_for_test().accounting_aggregate_cap(),
                agg_cap_before,
                "the aggregate ceiling is fixed configuration"
            );
            assert_eq!(signer.calls(), 1, "exactly one real signer call");
        }

        /// §6 lifecycle refusal: exercise the captured-versus-current lifecycle
        /// agreement ITSELF (not an authorization-ticket failure, and distinct from
        /// the retained-decision observation) on the eligible suite-100 path. Both
        /// the ENGINE and the DURABLE restriction advance consistently L0 -> L1
        /// (so step-5 observation still revalidates as safe), yet the CAPTURED pin
        /// still references the retired L0 generation (revision 1). Step 6 therefore
        /// refuses with `LifecycleAmbiguous`, ZERO signer calls, no journal
        /// reservation, and exact cleanup against the post-advance baseline.
        #[test]
        fn real100_lifecycle_refused_after_consistent_generation_advance_zero_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, mut engine, decided, p1, lim, _rev) =
                capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let base_vote = decided.vote().clone();

            // Advance the ENGINE to lock the view-1 block (L1): the local self-vote
            // was already cast at capture, so validators 2 & 3 complete the quorum.
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

            // Advance the DURABLE restriction to the SAME L1, moving the
            // authoritative revision 1 -> 2 (consistent with the engine).
            let new_rev = publish_qc(&owner, &ctx, l1_block, 1, 1);
            assert_eq!(new_rev, 2, "the L1 publication advances the durable revision");

            // Baseline taken AFTER the consistent advance, immediately before the call.
            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert_eq!(
                outcome,
                RealFreshSignOutcome::LifecycleAmbiguous,
                "the retained L0 generation no longer matches the advanced L1 state"
            );
            assert_eq!(signer.calls(), 0, "a lifecycle refusal performs zero signer calls");
            assert_eq!(sink.calls, 0, "no completion sink on a lifecycle refusal");
            assert_eq!(coord.calls, 0, "the coordination point is never reached");
            assert_eq!(
                journal.reserved_position_count(),
                0,
                "a lifecycle refusal reserves no journal position"
            );
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the real-path lifecycle refusal",
            );
        }

        /// §6 publication faults on the ELIGIBLE REAL path, distinguishing a stored
        /// `Reserved` record from a stored `Signed` record through direct
        /// applied-write inspection. A permanent BEFORE-write fault refuses WITHOUT
        /// applying any publication write, so NO `Signed` record is stored and the
        /// existing durable `Reserved` record (written by the admitted reservation,
        /// a DIFFERENT storage method) is unchanged. A permanent write-THEN-error
        /// APPLIES the `Signed` record before refusing. Both leave no fresh-signing
        /// opportunity; both perform exactly one real signer call despite the retry.
        #[test]
        fn real100_publish_reserved_vs_signed_record_inspection() {
            // Permanent before-write: Reserved record only (applied == 0).
            {
                let dir = tempfile::tempdir().unwrap();
                let ctx = retained_ctx(4);
                let (owner, engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
                let (pv, sk) = make_real_signing_authority();
                let mut snapshot = established_snapshot(&pv);
                let store = Arc::new(AdmittedPublishFaultStore::new());
                store.arm_write(1, u32::MAX); // mode 1 = before-write, permanent.
                let journal = associated_bounded_journal(
                    &owner,
                    store.clone() as Arc<dyn SigningJournalStorage>,
                    1,
                );
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new(&inner);
                let mut sink = RealSignRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let base_vote = decided.vote().clone();
                let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &signer, &mut sink, &journal, &mut coord,
                    ReconfirmPerturbation::None,
                );
                assert_eq!(outcome, RealFreshSignOutcome::PublishWriteIo);
                assert_eq!(signer.calls(), 1, "exactly one real signer call despite the retry");
                assert_eq!(
                    store.applied_writes(),
                    0,
                    "a before-write failure applies NO publication (Signed) record; the record stays Reserved"
                );
                let (pos, binding) = retained_pos_binding(&pv, &base_vote);
                assert!(
                    !matches!(
                        journal.reserve_for_sign(&pos, &binding),
                        Ok(ReservationOutcome::FreshlyReserved(_))
                    ),
                    "the existing Reserved obligation persists: no fresh-signing opportunity"
                );
            }
            // Permanent write-then-error: the Signed record IS applied (applied >= 1).
            {
                let dir = tempfile::tempdir().unwrap();
                let ctx = retained_ctx(4);
                let (owner, engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
                let (pv, sk) = make_real_signing_authority();
                let mut snapshot = established_snapshot(&pv);
                let store = Arc::new(AdmittedPublishFaultStore::new());
                store.arm_write(2, u32::MAX); // mode 2 = write-then-error, permanent.
                let journal = associated_bounded_journal(
                    &owner,
                    store.clone() as Arc<dyn SigningJournalStorage>,
                    1,
                );
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new(&inner);
                let mut sink = RealSignRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let base_vote = decided.vote().clone();
                let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &signer, &mut sink, &journal, &mut coord,
                    ReconfirmPerturbation::None,
                );
                assert_eq!(outcome, RealFreshSignOutcome::PublishWriteIo);
                assert_eq!(signer.calls(), 1, "exactly one real signer call despite the retry");
                assert!(
                    store.applied_writes() >= 1,
                    "write-then-error APPLIES the Signed record before failing"
                );
                let (pos, binding) = retained_pos_binding(&pv, &base_vote);
                assert!(
                    !matches!(
                        journal.reserve_for_sign(&pos, &binding),
                        Ok(ReservationOutcome::FreshlyReserved(_))
                    ),
                    "the applied Signed record preserves the obligation: no fresh-signing opportunity"
                );
            }
        }

        /// §6 publication retry on the ELIGIBLE REAL path: a one-shot `WriteIo`
        /// before application refuses the first publish attempt; the SINGLE retry
        /// (same capability/output/workspace, NO re-sign) succeeds and is
        /// acknowledged `Published`. Exactly one real signer call across the retry.
        #[test]
        fn real100_publish_single_write_io_retry_succeeds_one_signer_call() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) =
                capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let store = Arc::new(AdmittedPublishFaultStore::new());
            // mode 1 = before-write; count 1 = one-shot, so the single retry succeeds.
            store.arm_write(1, 1);
            let journal = associated_bounded_journal(
                &owner,
                store.clone() as Arc<dyn SigningJournalStorage>,
                1,
            );
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            match outcome {
                RealFreshSignOutcome::Published(d) => {
                    assert!(d.republished, "the diagnostic records the single retry");
                    assert_eq!(d.suite_id, MODEL_SUITE_U16);
                    assert_eq!(d.retirement, RetirementReport::Retired);
                }
                other => panic!("expected Published after one retry, got {other:?}"),
            }
            assert_eq!(signer.calls(), 1, "the retry never re-signs");
        }

        // ==================================================================
        // RUN 422 SAME-AUTHORITY isolated advance routes (TEST-ONLY).
        // `fresh_vote_sign_real_local_same_authority` resumes REAL signing after
        // an ACKNOWLEDGED, coherent L0->L1 advance where the equality route
        // conservatively refuses. Authority and pinned context stay UNCHANGED
        // fixtures; only the lifecycle relationship accepted AFTER a successful
        // held-guard observation differs. Labels: REAL multi-validator logical
        // engine, REAL ML-DSA-44 signing/verification, REAL durable-storage
        // acknowledgements. NO process-death (crash-durability) evidence here.
        // ==================================================================

        /// Drive the ACKNOWLEDGED, coherent L0->L1 advance shared by the
        /// same-authority tests: the engine locks the view-1 block (the self-vote
        /// was cast at capture; peers 2 & 3 complete the quorum) and the durable
        /// restriction advances to the SAME L1 (revision 1 -> 2). Returns L1.
        fn advance_engine_and_durable_to_l1(
            owner: &SafetyRecordOwner,
            engine: &mut qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
            ctx: &PinnedSafetyContext,
        ) -> [u8; 32] {
            let l0_block = derive_block_id_local(1, 0, &[0xFF; 32]);
            let l1_block = derive_block_id_local(2, 1, &l0_block);
            assert!(
                engine
                    .on_vote_event(ValidatorId::new(2), &logical_vote(1, l1_block, 2))
                    .expect("peer vote 2 for L1 ingests")
                    .is_none(),
                "two votes are short of the L1 quorum"
            );
            assert!(
                engine
                    .on_vote_event(ValidatorId::new(3), &logical_vote(1, l1_block, 3))
                    .expect("peer vote 3 for L1 ingests")
                    .is_some(),
                "the third vote forms the L1 quorum"
            );
            let lk = engine.locked_qc().expect("engine now locks L1");
            assert_eq!(lk.block_id, l1_block, "engine lock advanced to L1");
            assert_eq!(lk.view, 1);
            let new_rev = publish_qc(owner, ctx, l1_block, 1, 1);
            assert_eq!(new_rev, 2, "the L1 publication advances the durable revision");
            l1_block
        }

        /// §6 — the SAME acknowledged, coherent L0->L1 advance that the equality
        /// route refuses (control) is resumed by the same-authority route, which
        /// signs EXACTLY ONCE, publishes and retires; the published signature
        /// VERIFIES against the UNCHANGED original Vote's exact journal-bound
        /// preimage under the authorized suite-100 key.
        #[test]
        fn same_authority_resumes_signing_where_equality_route_refuses() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, mut engine, decided, p1, lim, _rev) =
                capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let base_vote = decided.vote().clone();

            let _l1 = advance_engine_and_durable_to_l1(&owner, &mut engine, &ctx);

            // CONTROL: the UNCHANGED equality route still refuses the acknowledged
            // advance with zero signing and zero journal reservation.
            {
                let mut sink = RealSignRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let ledgers_before = snapshot_ledgers(&owner);
                let prov_before = pin_provenance_now(&owner, &decided);
                let refused = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &signer, &mut sink, &journal, &mut coord,
                    ReconfirmPerturbation::None,
                );
                assert_eq!(
                    refused,
                    RealFreshSignOutcome::LifecycleAmbiguous,
                    "the equality route conservatively refuses the acknowledged advance"
                );
                assert_eq!(signer.calls(), 0, "the equality refusal signs zero times");
                assert_eq!(journal.reserved_position_count(), 0);
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the equality-route refusal control",
                );
            }

            // NEW ROUTE: the same acknowledged advance now resumes real signing.
            // §2 baselines taken AFTER the acknowledged lifecycle advance (the
            // control refusal above restored both ledgers to this point).
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);
            let outcome = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            let diag = match outcome {
                RealFreshSignOutcome::Published(d) => d,
                other => panic!("expected Published on the same-authority route, got {other:?}"),
            };
            assert_eq!(diag.sig_len, 2420, "ML-DSA-44 signature size");
            assert_eq!(diag.retirement, RetirementReport::Retired);
            assert_eq!(signer.calls(), 1, "exactly one real signer call across both attempts");
            assert_eq!(sink.calls, 1, "one completion sink on the successful route");
            assert_eq!(coord.calls, 1, "the coordination point is reached once");

            // GENUINE ML-DSA-44 verification against the AUTHORIZED suite-100 key
            // and the UNCHANGED original Vote's exact journal-bound preimage.
            let (pos, binding) = retained_pos_binding(&pv, &base_vote);
            let preimage = pv.signing_domain.vote_preimage(&base_vote);
            let published_sig = match journal.reserve_for_sign(&pos, &binding) {
                Ok(ReservationOutcome::ExactRetryRetained(sig)) => sig,
                other => panic!("expected the acknowledged signature, got {other:?}"),
            };
            assert_eq!(published_sig.len(), 2420);
            let (_ks, pk) = pv
                .key_provider
                .get_suite_and_key(ValidatorId::new(SIGNER_VID))
                .expect("the authorized public key is installed");
            MlDsa44Backend::verify(&pk, &preimage, &published_sig)
                .expect("the published signature verifies under the original Vote preimage");

            // §2 — independent operational AND aggregate cleanup after the real
            // publish+retire: every transient working set AND the retained D10
            // result reservation are released, restoring BOTH ledgers to the
            // post-advance baseline, with the complete borrowed Vote and original
            // pin provenance unchanged.
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the same-authority resumed-signing success",
            );
        }

        /// §6 (§1 correction) — a COMMITMENT/SUBSTITUTION refusal: mutating the
        /// borrowed proposal's `parent_block_id` breaks the retained proposal
        /// commitment (observe step 9a `CommitmentMismatch`), so a SUBSTITUTED
        /// candidate is refused at the held-guard observation BEFORE the lifecycle
        /// relationship and before any signing. This is NOT a genuine unavailable-
        /// candidate case — the inputs are mutated. The sibling test below covers
        /// genuine candidate ABSENCE under unchanged captured inputs.
        #[test]
        fn same_authority_substituted_proposal_under_advance_refuses_zero_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, mut engine, decided, p1, lim, _rev) =
                capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let base_vote = decided.vote().clone();

            let _l1 = advance_engine_and_durable_to_l1(&owner, &mut engine, &ctx);
            // Mutate the borrowed proposal's parent: this breaks the retained
            // proposal commitment (observe step 9a `CommitmentMismatch`) — a
            // SUBSTITUTION refusal, not a genuine unavailable candidate.
            let mut wrong_proposal = p1.clone();
            wrong_proposal.header.parent_block_id = [0x11; 32];

            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);
            let outcome = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &wrong_proposal, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert_eq!(
                outcome,
                RealFreshSignOutcome::ObservationRefused,
                "a substituted proposal refuses before the lifecycle relationship and before signing"
            );
            assert_eq!(signer.calls(), 0);
            assert_eq!(sink.calls, 0);
            assert_eq!(journal.reserved_position_count(), 0);
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the substituted-proposal refusal",
            );
        }

        /// §6 (§1 correction) — a GENUINE unavailable candidate under UNCHANGED
        /// captured inputs: the acknowledged CURRENT engine/durable state locks a
        /// REAL view-1 SIBLING (proposer 3) of the prepared candidate (proposer 2),
        /// so the EXACT original candidate node is genuinely ABSENT from the current
        /// engine. The borrowed proposal/decision are byte-for-byte unchanged (NO
        /// substitution) and engine<->durable correspondence HOLDS (both lock the
        /// sibling); the held-guard observation re-evaluates the captured candidate
        /// and refuses it as `CandidateAbsent` BEFORE the lifecycle relationship and
        /// before any signing. Distinct from the substitution refusal above and from
        /// an engine<->durable disagreement.
        #[test]
        fn same_authority_genuine_unavailable_candidate_under_advance_refuses_zero_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, _engine, decided, p1, lim, _rev) =
                capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let base_vote = decided.vote().clone();

            // A coherent CURRENT engine built the SAME way (locked L0, at view 1)
            // that then locks a REAL view-1 sibling (proposer 3) through a genuine
            // quorum. It never ingested the prepared candidate (proposer 2), so
            // that node is genuinely ABSENT from its state.
            let l0_block = derive_block_id_local(1, 0, &[0xFF; 32]);
            let (mut cur, _p1b, cur_l0) = engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
            assert_eq!(cur_l0, l0_block, "the deterministic L0 block matches the capture");
            let sibling = derive_block_id_local(3, 1, &l0_block);
            let prepared_candidate = derive_block_id_local(2, 1, &l0_block);
            assert_ne!(
                sibling, prepared_candidate,
                "the current lock is a real sibling, not the prepared candidate"
            );
            // `cur` cast NO local view-1 vote (the local self-vote at view 1 was
            // only ever cast for the ORIGINAL candidate during the capture on the
            // other engine), so THREE peer votes (2, 3, 4) are required to form the
            // sibling L1 quorum here.
            assert!(cur
                .on_vote_event(ValidatorId::new(2), &logical_vote(1, sibling, 2))
                .expect("sibling vote 2 ingests")
                .is_none());
            assert!(cur
                .on_vote_event(ValidatorId::new(3), &logical_vote(1, sibling, 3))
                .expect("sibling vote 3 ingests")
                .is_none());
            assert!(cur
                .on_vote_event(ValidatorId::new(4), &logical_vote(1, sibling, 4))
                .expect("sibling vote 4 ingests")
                .is_some());
            let lk = cur.locked_qc().expect("the current engine locks the sibling L1");
            assert_eq!(lk.block_id, sibling, "the current engine lock is the sibling");
            assert!(
                cur.state().get_block(&prepared_candidate).is_none(),
                "the prepared candidate node is genuinely absent from the current engine"
            );
            // Durable advances to the SAME sibling so engine<->durable correspondence
            // HOLDS; only the prepared candidate's availability differs.
            let new_rev = publish_qc(&owner, &ctx, sibling, 1, 1);
            assert_eq!(new_rev, 2, "the sibling L1 publication advances the durable revision");

            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);
            let outcome = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                &owner, &cur, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert_eq!(
                outcome,
                RealFreshSignOutcome::ObservationRefused,
                "the genuinely-absent prepared candidate refuses at observation before signing"
            );
            assert_eq!(signer.calls(), 0);
            assert_eq!(sink.calls, 0);
            assert_eq!(journal.reserved_position_count(), 0);
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the genuine unavailable-candidate refusal",
            );
        }

        /// §6 — an ACTUAL uncertain safety publication (recovery-required latched
        /// through an injected acknowledgement-lost durable write) blocks the
        /// dependent use at observation with zero signing. This is IN-MEMORY
        /// uncertainty, NOT crash-durability evidence.
        #[test]
        fn same_authority_uncertain_safety_publication_blocks_zero_signing() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, engine, decided, p1, lim, _rev) =
                capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let base_vote = decided.vote().clone();

            // Latch recovery-required through an uncertain (acknowledgement-lost)
            // durable write of the L1 restriction.
            let l0_block = derive_block_id_local(1, 0, &[0xFF; 32]);
            let l1_block = derive_block_id_local(2, 1, &l0_block);
            owner.backend_for_test().set_inject(
                crate::safety_record_store::backend::InjectFault::UncertainAfterWrite,
            );
            let latch = owner.publish_locked(
                make_locked_qc(&ctx, l1_block, 1, valid_wire_qc(&ctx, l1_block, 1), None).unwrap(),
                1,
                None::<&FixtureCommittedHistory>,
            );
            assert!(
                matches!(latch, PublishResult::UncertainDurable),
                "expected an uncertain durable outcome, got {latch:?}"
            );
            assert!(owner.recovery_required(), "recovery-required latched");

            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);
            let outcome = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            assert_eq!(
                outcome,
                RealFreshSignOutcome::ObservationRefused,
                "uncertain safety publication (recovery-required) blocks dependent use"
            );
            assert_eq!(signer.calls(), 0);
            assert_eq!(sink.calls, 0);
            assert_eq!(journal.reserved_position_count(), 0);
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the uncertain-publication block",
            );
        }

        /// §6 — in-flight current-authorization replacement strictly between the
        /// ORIGINAL ticket's admit and its pre-signing confirm invalidates the
        /// ticket AFTER the fresh D10 position is reserved and consumed: the route
        /// refuses at confirmation with zero signing, and the consumed
        /// potentially-signed obligation is PRESERVED (a retry cannot obtain a
        /// fresh reservation). `AuthorizationConfirmRefused` is distinct from an
        /// admit-time `AuthorizationAdmitRefused`.
        #[test]
        fn same_authority_authority_invalidation_refuses_at_confirm_preserving_obligation() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, mut engine, decided, p1, lim, _rev) =
                capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let base_vote = decided.vote().clone();

            let _l1 = advance_engine_and_durable_to_l1(&owner, &mut engine, &ctx);
            // §2 baselines taken AFTER the acknowledged lifecycle advance.
            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);

            let outcome = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::AdvanceGenerationBeforeConfirm,
            );
            assert_eq!(outcome, RealFreshSignOutcome::AuthorizationConfirmRefused);
            assert_eq!(signer.calls(), 0, "a post-consume confirm refusal signs zero times");
            assert_eq!(sink.calls, 0);
            assert_eq!(coord.calls, 0, "the coordination point is after the confirm");

            // §2 — independent operational AND aggregate cleanup: although the
            // CONSUMED potentially-signed D10 obligation persists (asserted below),
            // BOTH accounting ledgers are restored to the post-advance baseline and
            // the borrowed Vote and original pin provenance are unchanged.
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the same-authority confirm refusal",
            );

            // The consumed potentially-signed D10 obligation is PRESERVED: a retry
            // at the exact position/binding cannot obtain a FRESH reservation.
            let (pos, binding) = retained_pos_binding(&pv, &base_vote);
            match journal.reserve_for_sign(&pos, &binding) {
                Ok(ReservationOutcome::PotentiallySigned) => {}
                Ok(ReservationOutcome::FreshlyReserved(_)) => {
                    panic!("a consumed obligation must not re-open as FreshlyReserved")
                }
                other => panic!("expected PotentiallySigned, got {other:?}"),
            }
            assert_eq!(decided.vote(), &base_vote, "the borrowed Vote is unchanged");
        }

        /// §6 — standing pressure at the WorkSet admission stage refuses the new
        /// route BEFORE any journal reservation with zero signing; after the
        /// pressure is relieved the SAME envelope signs exactly once. The borrowed
        /// Vote and original pin are preserved across the refusal.
        #[test]
        fn same_authority_workset_admission_refused_then_relieved_retry_signs_once() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (owner, mut engine, decided, p1, lim, _rev) =
                capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
            let (pv, sk) = make_real_signing_authority();
            let mut snapshot = established_snapshot(&pv);
            let journal = associated_bounded_journal(&owner, real_fresh_store(), 1);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let base_vote = decided.vote().clone();

            let _l1 = advance_engine_and_durable_to_l1(&owner, &mut engine, &ctx);
            // §2 baselines taken AFTER the acknowledged lifecycle advance.
            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);

            let backend = owner.backend_for_test().clone();
            let held: std::cell::RefCell<Vec<_>> = std::cell::RefCell::new(Vec::new());
            install_real_admit_pressure_hook(move |s| {
                if s == RealAdmitStage::WorkSet {
                    let huge = u128::MAX / 2;
                    if let Ok(r) = backend.accounting().reserve(huge) {
                        held.borrow_mut().push(r);
                    } else {
                        let mut step = 1u128 << 40;
                        while step > 0 {
                            while let Ok(r) = backend.accounting().reserve(step) {
                                held.borrow_mut().push(r);
                            }
                            step >>= 1;
                        }
                    }
                }
            });
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let refused = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord,
                ReconfirmPerturbation::None,
            );
            clear_real_admit_pressure_hook();
            assert_eq!(refused, RealFreshSignOutcome::WorkSetAdmitRefused);
            assert_eq!(signer.calls(), 0);
            assert_eq!(sink.calls, 0);
            assert_eq!(journal.reserved_position_count(), 0);
            // §2 — a pre-reservation refusal fully releases every admitted working
            // set: BOTH ledgers restore to the post-advance baseline and the
            // borrowed Vote and original pin provenance are unchanged.
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the WorkSet admission refusal",
            );

            // Pressure relieved: the SAME envelope now signs exactly once.
            let mut sink2 = RealSignRecordingSink::new();
            let mut coord2 = ModelCoordinationHook::inert();
            let ok = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink2, &journal, &mut coord2,
                ReconfirmPerturbation::None,
            );
            assert!(
                matches!(ok, RealFreshSignOutcome::Published(_)),
                "the relieved retry resumes signing"
            );
            assert_eq!(signer.calls(), 1, "exactly one signer call across refusal + retry");
            // §2 — the relieved retry publishes+retires and restores BOTH ledgers
            // to the post-advance baseline with the Vote and pin unchanged.
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the relieved-retry resumed-signing success",
            );
        }

        // ==================================================================
        // RUN 422 — Isolated CHECKED retained-use composition (AssociationChecked).
        //
        // Each case begins with a genuine suite-100 engine-produced envelope that is
        // freshly signed EXACTLY ONCE, admitted-published, and retired. The retained
        // use then BORROWS that same envelope/Vote/pin and drives the
        // `admit_retrieval_workspace` + `retrieve_retained_checked` route (NO
        // fallback), additionally admitting the verification-backend coverage before
        // the dispatch handle. A bounded, fixed-size publication witness is prepared
        // OUTSIDE the protected operation (a direct bounded record read + decode),
        // and a thread-local RAII probe compares the EXACT verified retrieved slice
        // against that witness immediately before the scalar sink.
        // ==================================================================
        mod checked_retained {
            use super::*;
            use crate::signing_reservation_journal::{SigningDecisionRecord, SigningRecordStage};

            /// Prepare the fixed-size publication witness OUTSIDE the protected
            /// retained operation and BEFORE its I/O-counter window: read the
            /// acknowledged `Signed` record at the exact position through the bounded
            /// record read, decode + validate its framing/stage/binding/position, and
            /// copy its retained signature into a fixed-size test-owned witness. This
            /// is NOT a reissue and introduces no unbounded Vec and no production API.
            fn witness_from_store(
                store: &Arc<InMemoryConsensusStorage>,
                position: &SigningPosition,
                binding: &BindingDigest,
            ) -> RetainedSliceWitness {
                let raw = store
                    .get_signing_record(&position.storage_key())
                    .expect("bounded record read succeeds")
                    .expect("the acknowledged Signed record is present");
                let record = SigningDecisionRecord::decode(&raw).expect("record decodes");
                assert_eq!(
                    record.stage,
                    SigningRecordStage::Signed,
                    "the witness is read from the acknowledged Signed stage"
                );
                assert_eq!(
                    record.position, *position,
                    "the witnessed record is at the exact position"
                );
                assert_eq!(
                    record.binding, *binding,
                    "the witnessed record carries the exact binding"
                );
                let sig = record
                    .retained_signature
                    .expect("a Signed record retains its signature");
                assert_eq!(
                    sig.len(),
                    qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE,
                    "the acknowledged publication retains the full 2,420-byte signature"
                );
                RetainedSliceWitness::from_validated(&sig)
            }

            /// A model-local storage wrapper that delegates every operation to an
            /// in-memory inner store but, once armed, fails the recovered-record
            /// exact-envelope synced reissue in one of two ways, counting the writes
            /// that are actually applied to the inner store:
            ///   * mode 1 — fail BEFORE touching the backend (applied-write delta 0);
            ///   * mode 2 — APPLY the identical reissue to the inner store, THEN error
            ///     (applied-write delta 1; the stored record stays byte-identical).
            /// No production storage code is modified; the read path is delegated so
            /// retrieval still reads/validates the real record.
            struct CheckedReissueFaultStore {
                inner: Arc<InMemoryConsensusStorage>,
                mode: std::sync::atomic::AtomicU8,
                applied_writes: std::sync::atomic::AtomicU32,
            }
            impl CheckedReissueFaultStore {
                fn new(inner: Arc<InMemoryConsensusStorage>) -> Self {
                    Self {
                        inner,
                        mode: std::sync::atomic::AtomicU8::new(0),
                        applied_writes: std::sync::atomic::AtomicU32::new(0),
                    }
                }
                fn arm(&self, mode: u8) {
                    self.mode.store(mode, std::sync::atomic::Ordering::SeqCst);
                }
                fn disarm(&self) {
                    self.mode.store(0, std::sync::atomic::Ordering::SeqCst);
                }
                fn applied_writes(&self) -> u32 {
                    self.applied_writes.load(std::sync::atomic::Ordering::SeqCst)
                }
            }
            impl SigningJournalStorage for CheckedReissueFaultStore {
                fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
                    self.inner.get_signing_record(key)
                }
                fn put_signing_record_synced(
                    &self,
                    key: &[u8],
                    value: &[u8],
                ) -> Result<(), StorageError> {
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
                    self.inner.put_signing_record_and_metadata_synced(
                        record_key,
                        record_value,
                        metadata_value,
                    )
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
                fn read_signing_envelope_into(
                    &self,
                    journal_key: &[u8],
                    dst: &mut [u8],
                ) -> Result<Option<usize>, crate::signing_reservation_journal::BoundedStorageError>
                {
                    self.inner.read_signing_envelope_into(journal_key, dst)
                }
                fn put_signing_envelope_and_metadata_synced(
                    &self,
                    record_key: &[u8],
                    record_envelope: &[u8],
                    metadata_envelope: &[u8],
                ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
                    self.inner.put_signing_envelope_and_metadata_synced(
                        record_key,
                        record_envelope,
                        metadata_envelope,
                    )
                }
                fn put_signing_record_envelope_synced(
                    &self,
                    record_key: &[u8],
                    record_envelope: &[u8],
                ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
                    self.inner
                        .put_signing_record_envelope_synced(record_key, record_envelope)
                }
                fn reissue_signing_envelope_synced(
                    &self,
                    journal_key: &[u8],
                    envelope: &[u8],
                ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
                    use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
                    match self.mode.load(std::sync::atomic::Ordering::SeqCst) {
                        // Fail before application: no inner write, applied delta 0.
                        1 => Err(BoundedStorageError::Io(BoundedDiag::WriteIo)),
                        // Apply the identical reissue, then error: applied delta 1.
                        2 => {
                            self.inner
                                .reissue_signing_envelope_synced(journal_key, envelope)?;
                            self.applied_writes
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            Err(BoundedStorageError::Io(BoundedDiag::WriteIo))
                        }
                        _ => self
                            .inner
                            .reissue_signing_envelope_synced(journal_key, envelope),
                    }
                }
            }

            /// Run ONE genuine suite-100 fresh sign + admitted publish + retirement
            /// over `journal`, asserting the single real signer call, `Published`, and
            /// `Retired`. Returns nothing; the acknowledged `Signed` record now
            /// persists with NO live entry, ready for checked retained use.
            #[allow(clippy::too_many_arguments)]
            fn genuine_fresh_published(
                owner: &SafetyRecordOwner,
                engine: &qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
                decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
                p1: &qbind_wire::consensus::BlockProposal,
                lim: &PreparedDecisionInputLimits,
                snapshot: &mut AuthorizedProposalVoteSnapshot,
                journal: &SigningReservationJournal,
                signer: &CountingValidatorSigner<'_>,
            ) {
                let mut sink = RealSignRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    owner, engine, decided, p1, lim, None, snapshot, signer, &mut sink,
                    journal, &mut coord, ReconfirmPerturbation::None,
                );
                match outcome {
                    RealFreshSignOutcome::Published(d) => {
                        assert_eq!(d.sig_len, 2420, "the real ML-DSA-44 signature size");
                        assert_eq!(d.retirement, RetirementReport::Retired);
                    }
                    other => panic!("setup fresh sign must Publish+Retire, got {other:?}"),
                }
                assert_eq!(signer.calls(), 1, "exactly ONE real signer call in setup");
                assert_eq!(sink.calls, 1, "exactly one completion sink call in setup");
            }

            /// §2/§3 POSITIVE: after a genuine publish+retire, the AssociationChecked
            /// route retrieves and cryptographically verifies the SAME retained
            /// signature, the installed RAII probe observes the EXACT verified slice
            /// exactly once (length 2420, complete byte-for-byte match), the scalar
            /// sink consumes once, NO additional signer call occurs during the
            /// retained attempt, and both ledgers restore with the borrowed Vote and
            /// original pin preserved.
            #[test]
            fn checked_positive_probe_matches_and_single_signer() {
                let dir = tempfile::tempdir().unwrap();
                let ctx = retained_ctx(4);
                let (owner, engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
                let (pv, sk) = make_real_signing_authority();
                let mut snapshot = established_snapshot(&pv);
                let store = Arc::new(InMemoryConsensusStorage::new());
                let journal = associated_bounded_journal(
                    &owner,
                    store.clone() as Arc<dyn SigningJournalStorage>,
                    1,
                );
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new(&inner);
                let base_vote = decided.vote().clone();

                genuine_fresh_published(
                    &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, &signer,
                );

                // Witness read OUTSIDE/ BEFORE the protected retained operation.
                let (pos, binding) = retained_pos_binding(&pv, &base_vote);
                let witness = witness_from_store(&store, &pos, &binding);
                assert_eq!(witness.len(), 2420, "the witness holds the full artifact");

                let probe = std::rc::Rc::new(RetainedSliceProbe::new(witness));
                let guard = install_retained_slice_probe(probe.clone());

                let ledgers_before = snapshot_ledgers(&owner);
                let prov_before = pin_provenance_now(&owner, &decided);

                let mut sink = RetainedUseRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let outcome = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                drop(guard);

                let diag = match outcome {
                    ModelRetainedUseOutcome::Consumed(d) => d,
                    other => panic!("expected Consumed on the checked route, got {other:?}"),
                };
                assert_eq!(diag.sig_len as usize, 2420, "consumed the 2,420-byte slice");
                assert_eq!(sink.calls, 1, "exactly one scalar sink consumption");
                assert_eq!(coord.calls, 1, "the coordination point is reached once");

                // RUN 422 §3 assertions AFTER the protected call returns.
                assert_eq!(probe.invocations(), 1, "the probe ran exactly once");
                assert_eq!(probe.last_len(), Some(2420), "observed length is exactly 2420");
                assert_eq!(
                    probe.last_matched(),
                    Some(true),
                    "the verified retrieved slice matches the witness byte-for-byte"
                );

                // No extra signer call during the retained attempt (still exactly 1).
                assert_eq!(
                    signer.calls(),
                    1,
                    "zero additional signer calls during retained use"
                );
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the successful checked retained consumption",
                );
            }

            /// §5 ACCOUNTING: at the live post-consume/pre-sign sample the checked
            /// route charges, above EACH ledger's OWN independently-read baseline, the
            /// complete phase inventory C + verify + verify_backend + output + scratch
            /// = 16451, reconciled from the actual charge functions (the source-derived
            /// verification-preparation identity C + verify + verify_backend = 11180 is
            /// asserted separately). Both ceilings are unchanged and both ledgers
            /// restore exactly after the run.
            #[test]
            fn checked_accounting_live_phase_and_cleanup() {
                let dir = tempfile::tempdir().unwrap();
                let ctx = retained_ctx(4);
                let (owner, engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
                let (pv, sk) = make_real_signing_authority();
                let mut snapshot = established_snapshot(&pv);
                let store = Arc::new(InMemoryConsensusStorage::new());
                let journal = associated_bounded_journal(
                    &owner,
                    store.clone() as Arc<dyn SigningJournalStorage>,
                    1,
                );
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new(&inner);
                let base_vote = decided.vote().clone();

                genuine_fresh_published(
                    &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, &signer,
                );

                // Source-derived identities reconciled from the actual charge fns.
                let prep = control_charge()
                    .saturating_add(verify_charge())
                    .saturating_add(verify_backend_wrapper_charge());
                assert_eq!(
                    prep, 11180,
                    "verification-preparation identity C + verify + verify_backend"
                );
                let live_delta = prep
                    .saturating_add(crate::signing_journal_admission::output_charge())
                    .saturating_add(crate::signing_journal_admission::envelope_charge());
                assert_eq!(
                    live_delta, 16451,
                    "checked retrieval + verify/confirm/sink live inventory"
                );

                // Read BOTH baselines INDEPENDENTLY (neither derived from the other).
                let op_before = owner.backend_for_test().accounting_current();
                let agg_before = owner.backend_for_test().accounting_aggregate_current();
                let op_cap_before = owner.backend_for_test().accounting_cap();
                let agg_cap_before = owner.backend_for_test().accounting_aggregate_cap();
                let prov_before = pin_provenance_now(&owner, &decided);

                let mut sink = RetainedUseRecordingSink::new();
                let mut coord =
                    ModelCoordinationHook::sampling(owner.backend_for_test().clone());
                let outcome = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                assert!(matches!(outcome, ModelRetainedUseOutcome::Consumed(_)));

                let live_op = coord.observed_operational.expect("operational sample");
                let live_agg = coord.observed_aggregate.expect("aggregate sample");
                assert_eq!(
                    live_op,
                    op_before.saturating_add(live_delta),
                    "operational live charge is its OWN baseline + 16451"
                );
                assert_eq!(
                    live_agg,
                    agg_before.saturating_add(live_delta),
                    "aggregate live charge is its OWN baseline + 16451"
                );

                // Unchanged ceilings; exact restoration of BOTH ledgers.
                assert_eq!(owner.backend_for_test().accounting_cap(), op_cap_before);
                assert_eq!(
                    owner.backend_for_test().accounting_aggregate_cap(),
                    agg_cap_before
                );
                assert_eq!(
                    owner.backend_for_test().accounting_current(),
                    op_before,
                    "operational ledger restores to its own baseline"
                );
                assert_eq!(
                    owner.backend_for_test().accounting_aggregate_current(),
                    agg_before,
                    "aggregate ledger restores to its own baseline"
                );
                assert_eq!(
                    pin_provenance_now(&owner, &decided),
                    prov_before,
                    "original pin provenance preserved"
                );
                assert_eq!(decided.vote(), &base_vote, "borrowed Vote unchanged");
                assert_eq!(signer.calls(), 1, "no additional signer call");

                // Literal evidence emission (visible under --nocapture). Each
                // source-derived absolute phase total is this ledger's OWN measured
                // baseline + its source-derived delta; the per-ledger maximum is the
                // largest such total (lifecycle nested load, delta 31966) and remaining
                // headroom is the unchanged ceiling minus that maximum. The executed
                // live sample (baseline + 16451) is kept distinct from the calculated
                // maximum. Cleanup delta is current-minus-baseline after restoration.
                let op_cap = op_cap_before.expect("operational cap present");
                let agg_cap = agg_cap_before.expect("aggregate cap present");
                let op_after = owner.backend_for_test().accounting_current();
                let agg_after = owner.backend_for_test().accounting_aggregate_current();
                const D_OBS_LOADER: u128 = 31830;
                const D_OBS_WORKING_SET: u128 = 22595;
                const D_LIFECYCLE_NESTED: u128 = 31966; // source-derived maximum delta
                const D_VERIFY_PREP: u128 = 11180;
                const D_CHECKED_LIVE: u128 = 16451;
                const D_CLEANUP: u128 = 0;
                let op_max = op_before.saturating_add(D_LIFECYCLE_NESTED);
                let agg_max = agg_before.saturating_add(D_LIFECYCLE_NESTED);
                assert!(op_max <= op_cap, "operational source-derived maximum fits cap");
                assert!(agg_max <= agg_cap, "aggregate source-derived maximum fits cap");
                eprintln!(
                    "RUN422-CHECKED-ACCT N=4 S_sig=2420 \
                     op_baseline={op_before} agg_baseline={agg_before} \
                     op_cap={op_cap} agg_cap={agg_cap} \
                     live_op={live_op} live_agg={live_agg} live_delta={live_delta} \
                     op_after={op_after} agg_after={agg_after} \
                     cleanup_delta={D_CLEANUP} \
                     phase_deltas[obs_loader={D_OBS_LOADER} obs_working_set={D_OBS_WORKING_SET} \
                     lifecycle_nested={D_LIFECYCLE_NESTED} verify_prep={D_VERIFY_PREP} \
                     checked_live={D_CHECKED_LIVE} cleanup={D_CLEANUP}] \
                     op_phase_totals[obs_loader={} obs_working_set={} lifecycle_nested={} \
                     verify_prep={} checked_live={}] \
                     agg_phase_totals[obs_loader={} obs_working_set={} lifecycle_nested={} \
                     verify_prep={} checked_live={}] \
                     op_max={op_max} agg_max={agg_max} \
                     op_headroom={} agg_headroom={}",
                    op_before.saturating_add(D_OBS_LOADER),
                    op_before.saturating_add(D_OBS_WORKING_SET),
                    op_before.saturating_add(D_LIFECYCLE_NESTED),
                    op_before.saturating_add(D_VERIFY_PREP),
                    op_before.saturating_add(D_CHECKED_LIVE),
                    agg_before.saturating_add(D_OBS_LOADER),
                    agg_before.saturating_add(D_OBS_WORKING_SET),
                    agg_before.saturating_add(D_LIFECYCLE_NESTED),
                    agg_before.saturating_add(D_VERIFY_PREP),
                    agg_before.saturating_add(D_CHECKED_LIVE),
                    op_cap.saturating_sub(op_max),
                    agg_cap.saturating_sub(agg_max),
                );
            }

            /// §5 EXHAUSTION: standing pressure applied at the VerifyBackend stage
            /// (through the REAL accountant, BEFORE covered construction) refuses the
            /// additional-coverage admission with `VerifyBackendAdmitRefused`, with no
            /// retained use and exact cleanup; after relief the SAME envelope/journal
            /// retries successfully, still with zero additional signer calls.
            #[test]
            fn checked_verify_backend_exhaustion_then_relief_retry() {
                let dir = tempfile::tempdir().unwrap();
                let ctx = retained_ctx(4);
                let (owner, engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
                let (pv, sk) = make_real_signing_authority();
                let mut snapshot = established_snapshot(&pv);
                let store = Arc::new(InMemoryConsensusStorage::new());
                let journal = associated_bounded_journal(
                    &owner,
                    store.clone() as Arc<dyn SigningJournalStorage>,
                    1,
                );
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new(&inner);
                let base_vote = decided.vote().clone();

                genuine_fresh_published(
                    &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, &signer,
                );

                let ledgers_before = snapshot_ledgers(&owner);
                let prov_before = pin_provenance_now(&owner, &decided);

                // Standing pressure at the VerifyBackend stage via the REAL accountant.
                let backend = owner.backend_for_test().clone();
                let held: std::cell::RefCell<Vec<_>> = std::cell::RefCell::new(Vec::new());
                install_retained_admit_pressure_hook(move |s| {
                    if s == RetainedAdmitStage::VerifyBackend {
                        let huge = u128::MAX / 2;
                        if let Ok(r) = backend.accounting().reserve(huge) {
                            held.borrow_mut().push(r);
                        } else {
                            let mut step = 1u128 << 40;
                            while step > 0 {
                                while let Ok(r) = backend.accounting().reserve(step) {
                                    held.borrow_mut().push(r);
                                }
                                step >>= 1;
                            }
                        }
                    }
                });
                let mut sink = RetainedUseRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let refused = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                clear_retained_admit_pressure_hook();
                assert_eq!(
                    refused,
                    ModelRetainedUseOutcome::VerifyBackendAdmitRefused,
                    "additional-coverage admission refused at the VerifyBackend stage"
                );
                assert_eq!(sink.calls, 0, "no retained use on admission refusal");
                assert_eq!(coord.calls, 0, "the protected sink point is never reached");
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the VerifyBackend admission refusal",
                );

                // Pressure relieved (hook cleared; held reservations dropped): retry
                // the SAME envelope/journal succeeds with a fresh acknowledgement.
                let mut sink2 = RetainedUseRecordingSink::new();
                let mut coord2 = ModelCoordinationHook::inert();
                let ok = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &mut sink2, &journal, &mut coord2, ReconfirmPerturbation::None,
                );
                assert!(
                    matches!(ok, ModelRetainedUseOutcome::Consumed(_)),
                    "retry after relief succeeds, got {ok:?}"
                );
                assert_eq!(sink2.calls, 1);
                assert_eq!(signer.calls(), 1, "no additional signer call across attempts");
            }

            /// §4 FAULT (before application): an armed reissue that fails BEFORE the
            /// inner write suppresses delivery with applied-write delta 0, zero sink
            /// calls, and no additional signer call. After clearing the fault, a retry
            /// over the SAME envelope/journal consumes with a new acknowledgement and
            /// no fresh signing (an earlier fault does not prevent a later success).
            #[test]
            fn checked_reissue_fault_before_application_then_clear_retry() {
                let dir = tempfile::tempdir().unwrap();
                let ctx = retained_ctx(4);
                let (owner, engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
                let (pv, sk) = make_real_signing_authority();
                let mut snapshot = established_snapshot(&pv);
                let base = Arc::new(InMemoryConsensusStorage::new());
                let fault = Arc::new(CheckedReissueFaultStore::new(base.clone()));
                let journal = associated_bounded_journal(
                    &owner,
                    fault.clone() as Arc<dyn SigningJournalStorage>,
                    1,
                );
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new(&inner);
                let base_vote = decided.vote().clone();

                genuine_fresh_published(
                    &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, &signer,
                );

                let ledgers_before = snapshot_ledgers(&owner);
                let prov_before = pin_provenance_now(&owner, &decided);
                let (pos, _b) = retained_pos_binding(&pv, &base_vote);
                let record_before = base
                    .get_signing_record(&pos.storage_key())
                    .expect("read")
                    .expect("present");

                fault.arm(1); // fail BEFORE the inner write.
                let applied_before = fault.applied_writes();
                let mut sink = RetainedUseRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let suppressed = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                assert_eq!(
                    suppressed,
                    ModelRetainedUseOutcome::DeliverySuppressed,
                    "a recovered-reissue failure suppresses delivery"
                );
                assert_ne!(
                    suppressed,
                    ModelRetainedUseOutcome::RetainedPotentiallySigned,
                    "before-application reissue failure is NOT PotentiallySigned"
                );
                assert_eq!(sink.calls, 0, "no sink call on suppression");
                assert_eq!(
                    fault.applied_writes() - applied_before,
                    0,
                    "applied-write delta is 0 (fault before application)"
                );
                let record_after = base
                    .get_signing_record(&pos.storage_key())
                    .expect("read")
                    .expect("present");
                assert_eq!(
                    record_before, record_after,
                    "the stored Signed record is byte-identical"
                );
                assert_eq!(signer.calls(), 1, "no additional signer call");
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the before-application reissue suppression",
                );

                // Clear the fault; retry over the SAME envelope/journal consumes.
                fault.disarm();
                let mut sink2 = RetainedUseRecordingSink::new();
                let mut coord2 = ModelCoordinationHook::inert();
                let ok = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &mut sink2, &journal, &mut coord2, ReconfirmPerturbation::None,
                );
                assert!(
                    matches!(ok, ModelRetainedUseOutcome::Consumed(_)),
                    "retry after clearing the fault consumes, got {ok:?}"
                );
                assert_eq!(sink2.calls, 1);
                assert_eq!(signer.calls(), 1, "retry performs no fresh signing");
            }

            /// §4 FAULT (after application): an armed reissue that APPLIES the inner
            /// write and THEN errors suppresses delivery with applied-write delta 1,
            /// zero sink calls, and no additional signer call; the stored record stays
            /// byte-identical (identical reissue), so byte identity alone cannot tell
            /// the two fault cases apart. An EARLIER successful use does not authorize
            /// this later failed attempt.
            #[test]
            fn checked_reissue_fault_after_application_suppressed_delta_one() {
                let dir = tempfile::tempdir().unwrap();
                let ctx = retained_ctx(4);
                let (owner, engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
                let (pv, sk) = make_real_signing_authority();
                let mut snapshot = established_snapshot(&pv);
                let base = Arc::new(InMemoryConsensusStorage::new());
                let fault = Arc::new(CheckedReissueFaultStore::new(base.clone()));
                let journal = associated_bounded_journal(
                    &owner,
                    fault.clone() as Arc<dyn SigningJournalStorage>,
                    1,
                );
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new(&inner);
                let base_vote = decided.vote().clone();

                genuine_fresh_published(
                    &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, &signer,
                );

                // An EARLIER successful checked use (clean store).
                let mut sink0 = RetainedUseRecordingSink::new();
                let mut coord0 = ModelCoordinationHook::inert();
                let ok0 = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &mut sink0, &journal, &mut coord0, ReconfirmPerturbation::None,
                );
                assert!(matches!(ok0, ModelRetainedUseOutcome::Consumed(_)));

                let ledgers_before = snapshot_ledgers(&owner);
                let prov_before = pin_provenance_now(&owner, &decided);
                let (pos, _b) = retained_pos_binding(&pv, &base_vote);
                let record_before = base
                    .get_signing_record(&pos.storage_key())
                    .expect("read")
                    .expect("present");

                fault.arm(2); // APPLY the reissue, then error.
                let applied_before = fault.applied_writes();
                let mut sink = RetainedUseRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let suppressed = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                assert_eq!(
                    suppressed,
                    ModelRetainedUseOutcome::DeliverySuppressed,
                    "an earlier success does not authorize this later failed attempt"
                );
                assert_eq!(sink.calls, 0, "no sink call on suppression");
                assert_eq!(
                    fault.applied_writes() - applied_before,
                    1,
                    "applied-write delta is 1 (identical reissue applied, then error)"
                );
                let record_after = base
                    .get_signing_record(&pos.storage_key())
                    .expect("read")
                    .expect("present");
                assert_eq!(
                    record_before, record_after,
                    "the stored Signed record remains byte-identical despite the write"
                );
                assert_eq!(signer.calls(), 1, "no additional signer call");
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the after-application reissue suppression",
                );
            }

            /// §4 ERROR MAPPING: with NO installed ledger/workspace association, the
            /// checked route refuses at workspace admission with a consistent typed
            /// outcome (`CheckedNoAssociation`) and never falls back to the OwnerBacked
            /// route. The retrieval itself is never reached.
            #[test]
            fn checked_missing_association_maps_to_checked_no_association() {
                let dir = tempfile::tempdir().unwrap();
                let ctx = retained_ctx(4);
                let (owner, engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
                let (pv, _sk) = make_real_signing_authority();
                let mut snapshot = established_snapshot(&pv);
                // A journal with NO installed accountant association.
                let journal = SigningReservationJournal::attach_unestablished_for_test(
                    Arc::new(InMemoryConsensusStorage::new()) as Arc<dyn SigningJournalStorage>,
                );
                let base_vote = decided.vote().clone();

                let ledgers_before = snapshot_ledgers(&owner);
                let prov_before = pin_provenance_now(&owner, &decided);

                let mut sink = RetainedUseRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let outcome = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                assert_eq!(
                    outcome,
                    ModelRetainedUseOutcome::CheckedNoAssociation,
                    "a missing association is a consistent typed outcome, no fallback"
                );
                assert_eq!(sink.calls, 0, "no retained use without an association");
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the missing-association refusal",
                );
            }

            // §4 DEFENSIVE: `CheckedForeignWorkspace` maps
            // `CheckedRetrievalError::ForeignWorkspace`, which this composition cannot
            // itself manufacture — the AssociationChecked route admits its workspace
            // through the SAME installed accountant it then checks against, so the
            // covered-by identity always holds here. A workspace covered by a FOREIGN
            // accountant is exercised at the lower journal level by
            // `signing_reservation_journal::tests::admitted_reserve_foreign_workspace_
            // refused_before_io` (and the admitted-publish foreign-ledger cases),
            // which establish the defensive `ForeignWorkspace` refusal before any I/O.
            // We therefore do NOT fabricate an impossible foreign-workspace input here.

            /// §6 — after a genuine publish+retire at the ORIGINAL state, an
            /// ACKNOWLEDGED coherent L0->L1 advance is refused by the equality
            /// checked route (control) but CONSUMED by the same-authority checked
            /// route, which re-verifies the retained bytes and invokes the signer
            /// ZERO additional times; both ledgers and the borrowed Vote/pin are
            /// preserved.
            #[test]
            fn same_authority_checked_retained_reuse_after_advance_zero_signing() {
                let dir = tempfile::tempdir().unwrap();
                let ctx = retained_ctx(4);
                let (owner, mut engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
                let (pv, sk) = make_real_signing_authority();
                let mut snapshot = established_snapshot(&pv);
                let store = Arc::new(InMemoryConsensusStorage::new());
                let journal = associated_bounded_journal(
                    &owner,
                    store.clone() as Arc<dyn SigningJournalStorage>,
                    1,
                );
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new(&inner);
                let base_vote = decided.vote().clone();

                // ONE genuine fresh sign at the ORIGINAL (equal) state seeds the
                // acknowledged Signed record.
                genuine_fresh_published(
                    &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, &signer,
                );
                assert_eq!(signer.calls(), 1, "exactly one signer call during setup");

                // ACKNOWLEDGED coherent L0->L1 advance (same helper as the fresh route).
                let _l1 = advance_engine_and_durable_to_l1(&owner, &mut engine, &ctx);

                let (pos, binding) = retained_pos_binding(&pv, &base_vote);
                let witness = witness_from_store(&store, &pos, &binding);
                let probe = std::rc::Rc::new(RetainedSliceProbe::new(witness));
                let guard = install_retained_slice_probe(probe.clone());

                let ledgers_before = snapshot_ledgers(&owner);
                let prov_before = pin_provenance_now(&owner, &decided);

                // CONTROL: the equality checked route refuses after the advance,
                // before any retrieval/probe/sink.
                {
                    let mut sink = RetainedUseRecordingSink::new();
                    let mut coord = ModelCoordinationHook::inert();
                    let refused = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                        &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                    );
                    assert_eq!(refused, ModelRetainedUseOutcome::LifecycleAmbiguous);
                    assert_eq!(sink.calls, 0, "no retained use on the equality refusal");
                }

                // NEW ROUTE: checked retained reuse succeeds after the advance with
                // ZERO additional signer calls.
                let mut sink = RetainedUseRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let outcome =
                    retained_vote_use_checked_same_authority_model::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                        &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                    );
                drop(guard);
                let diag = match outcome {
                    ModelRetainedUseOutcome::Consumed(d) => d,
                    other => panic!(
                        "expected Consumed on the same-authority checked route, got {other:?}"
                    ),
                };
                assert_eq!(diag.sig_len as usize, 2420, "consumed the 2,420-byte slice");
                assert_eq!(sink.calls, 1, "exactly one scalar sink consumption");
                assert_eq!(coord.calls, 1, "the coordination point is reached once");
                assert_eq!(probe.invocations(), 1, "the probe ran exactly once");
                assert_eq!(probe.last_len(), Some(2420));
                assert_eq!(
                    probe.last_matched(),
                    Some(true),
                    "the verified retained slice matches the witness byte-for-byte"
                );
                assert_eq!(
                    signer.calls(),
                    1,
                    "zero additional signer calls during the same-authority retained reuse"
                );
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the same-authority checked retained consumption",
                );
            }

            /// §6 — in-flight authorization replacement between admit and the
            /// pre-delivery confirm refuses the same-authority checked route at
            /// confirmation with zero scalar sink; the stored Signed obligation is
            /// preserved for a later retry.
            #[test]
            fn same_authority_checked_retained_authority_invalidation_refuses_at_confirm() {
                let dir = tempfile::tempdir().unwrap();
                let ctx = retained_ctx(4);
                let (owner, mut engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(dir.path(), &ctx, MODEL_SUITE_U16);
                let (pv, sk) = make_real_signing_authority();
                let mut snapshot = established_snapshot(&pv);
                let store = Arc::new(InMemoryConsensusStorage::new());
                let journal = associated_bounded_journal(
                    &owner,
                    store.clone() as Arc<dyn SigningJournalStorage>,
                    1,
                );
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new(&inner);
                let base_vote = decided.vote().clone();

                genuine_fresh_published(
                    &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, &signer,
                );
                let _l1 = advance_engine_and_durable_to_l1(&owner, &mut engine, &ctx);

                let mut sink = RetainedUseRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let outcome =
                    retained_vote_use_checked_same_authority_model::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                        &mut sink, &journal, &mut coord,
                        ReconfirmPerturbation::AdvanceGenerationBeforeConfirm,
                    );
                assert_eq!(outcome, ModelRetainedUseOutcome::AuthorizationConfirmRefused);
                assert_eq!(sink.calls, 0, "no scalar sink on a confirm refusal");
                assert_eq!(signer.calls(), 1, "zero additional signer calls on the refusal");

                // The stored Signed obligation survives for a later retry.
                let (pos, binding) = retained_pos_binding(&pv, &base_vote);
                match journal.reserve_for_sign(&pos, &binding) {
                    Ok(ReservationOutcome::ExactRetryRetained(sig)) => {
                        assert_eq!(sig.len(), 2420, "the Signed record still retains its signature")
                    }
                    other => panic!("expected the retained signature to persist, got {other:?}"),
                }
                assert_eq!(decided.vote(), &base_vote, "the borrowed Vote is unchanged");
            }
        }
    }

}