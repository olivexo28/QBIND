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
use crate::signing_reservation_journal::{RefuseReason, RetainedDelivery};
use crate::signing_journal_admission::RetrievalWorkspaceOwner;

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
    Retrieval,
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
    //    carries its own separate reservations.
    fire_retained_admit_pressure(RetainedAdmitStage::Retrieval);
    let workspace = RetrievalWorkspaceOwner::new(&owner.backend).admit();
    let (mut output, mut scratch) = match workspace {
        Ok(ws) => ws,
        Err(_) => return ModelRetainedUseOutcome::RetrievalAdmitRefused,
    };

    // 10. Retrieve the already-retained signature (no fresh reservation, no
    //     continuation, no publication capability, no signer).
    let retrieved = match journal.retrieve_retained(&position, &binding, &mut scratch, &mut output) {
        Ok(RetainedDelivery::Retained(sig)) => sig,
        Ok(RetainedDelivery::Blocked) => return ModelRetainedUseOutcome::RetainedBlocked,
        Ok(RetainedDelivery::Missing) => return ModelRetainedUseOutcome::RetainedMissing,
        Ok(RetainedDelivery::Refused(reason)) => {
            let class = match reason {
                RefuseReason::PositionMismatch => RetainedRefuseClass::PositionMismatch,
                RefuseReason::MalformedRecord => RetainedRefuseClass::MalformedRecord,
                RefuseReason::BindingConflict => RetainedRefuseClass::BindingConflict,
                RefuseReason::WorkspaceCapacityExceeded => {
                    RetainedRefuseClass::WorkspaceCapacityExceeded
                }
            };
            return ModelRetainedUseOutcome::RetainedRefused(class);
        }
        Ok(RetainedDelivery::PotentiallySigned) => {
            return ModelRetainedUseOutcome::RetainedPotentiallySigned
        }
        Ok(RetainedDelivery::DeliverySuppressed) => {
            return ModelRetainedUseOutcome::DeliverySuppressed
        }
        Err(_) => return ModelRetainedUseOutcome::RetrievalFailed,
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

    // 14. Scalar-only model consumption of the VERIFIED borrowed signature. The
    //     retrieval workspace, verify objects, reservations, ticket and guard are
    //     destroyed by reverse-drop order after this returns (guard LAST).
    let diag = sink.consume_verified(vote, retrieved, preimage_len);
    ModelRetainedUseOutcome::Consumed(diag)
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

}