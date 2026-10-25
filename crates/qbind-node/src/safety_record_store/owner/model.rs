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

/// RUN 422 — harness-owned, PRECONSTRUCTED boundary evidence for the isolated
/// post-consumption process-death composition. It carries the complete fixed
/// binary marker bytes (built BEFORE the protected operation), an
/// exclusively-created-and-already-open marker file, and shared clones of the
/// signer/sink observers. When installed via [`ModelCoordinationHook::aborting`],
/// the hook — at the fixed post-consume / pre-sign point, after exactly one hook
/// invocation and with both observers still zero — writes the preconstructed
/// bytes, flushes/syncs them, and raises SIGABRT via `std::process::abort()`
/// BEFORE the signer runs. It never formats a String, grows a buffer, or reopens
/// the path inside the hook. It is a caller-owned fixture, NOT part of the
/// composition's charged working set.
pub(crate) struct AbortEvidence {
    /// The complete, fixed-length marker bytes, built outside the protected op.
    marker: Vec<u8>,
    /// The exclusively created (`create_new`) marker file, opened before the
    /// protected operation; initially empty.
    file: std::fs::File,
    /// Shared live signer-invocation observer (asserted zero before abort).
    signer_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Shared live completion-sink observer (asserted zero before abort).
    sink_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

impl AbortEvidence {
    /// Construct the preconstructed evidence. `marker` and `file` MUST be built /
    /// opened before entering the protected operation; `signer_obs` / `sink_obs`
    /// MUST be the same shared counters installed on the observed signer and sink.
    pub(crate) fn new(
        marker: Vec<u8>,
        file: std::fs::File,
        signer_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
        sink_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        Self {
            marker,
            file,
            signer_obs,
            sink_obs,
        }
    }

    /// Assert the boundary invariants directly observed at the hook, then write
    /// the preconstructed marker and abort. `hook_calls` is the hook's own live
    /// invocation count (must be exactly 1). Never returns.
    fn fire(mut self, hook_calls: u32) -> ! {
        use std::io::Write as _;
        // Directly observed at the hook: exactly one hook invocation, and the
        // live shared observers show ZERO signer and ZERO sink calls. These
        // assertions run BEFORE any complete marker is written, so a violated
        // invariant unwinds (panic=unwind) without emitting boundary evidence.
        assert_eq!(hook_calls, 1, "the coordination hook must fire exactly once");
        assert_eq!(
            self.signer_obs.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the signer must not have been invoked before the pre-sign boundary"
        );
        assert_eq!(
            self.sink_obs.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the completion sink must not have been invoked before the pre-sign boundary"
        );
        // Write the COMPLETE preconstructed marker, flush and fsync it so the
        // surviving parent reliably observes the full invocation-matched record,
        // THEN abort before the signer executes.
        self.file
            .write_all(&self.marker)
            .expect("write the preconstructed boundary marker");
        self.file.flush().expect("flush the boundary marker");
        self.file.sync_all().expect("fsync the boundary marker");
        std::process::abort();
    }
}

const POSTPUB_MARKER_LEN: usize = 4 + 2 + 1 + 16 + 16 + 1 + 1
    + 2 + qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE
    + 2 + 69 + 2 + MODEL_MAX_PREIMAGE_BYTES as usize + 55 + 32
    + 2 + qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE;
const POSTPUB_PK_OFFSET: usize = 43;
const POSTPUB_VOTE_LEN_OFFSET: usize = POSTPUB_PK_OFFSET + qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE;
const POSTPUB_VOTE_OFFSET: usize = POSTPUB_VOTE_LEN_OFFSET + 2;
const POSTPUB_PREIMAGE_LEN_OFFSET: usize = POSTPUB_VOTE_OFFSET + 69;
const POSTPUB_PREIMAGE_OFFSET: usize = POSTPUB_PREIMAGE_LEN_OFFSET + 2;
const POSTPUB_POSITION_OFFSET: usize = POSTPUB_PREIMAGE_OFFSET + MODEL_MAX_PREIMAGE_BYTES as usize;
const POSTPUB_BINDING_OFFSET: usize = POSTPUB_POSITION_OFFSET + 55;
const POSTPUB_SIGNATURE_LEN_OFFSET: usize = POSTPUB_BINDING_OFFSET + 32;
const POSTPUB_SIGNATURE_OFFSET: usize = POSTPUB_SIGNATURE_LEN_OFFSET + 2;

/// Harness-owned fixed witness for the acknowledged-publication boundary. All
/// storage is allocated and the marker file opened before entering the protected
/// operation; only live scalar fields and the exact committed output are copied
/// at the hook. It is not part of the model composition's accounting.
struct PostPublicationEvidence {
    marker: Box<[u8; POSTPUB_MARKER_LEN]>,
    file: std::fs::File,
    signer_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
    sink_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
    hook_calls: u32,
    terminate: bool,
}

impl PostPublicationEvidence {
    fn new(
        marker: Box<[u8; POSTPUB_MARKER_LEN]>,
        file: std::fs::File,
        signer_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
        sink_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
        terminate: bool,
    ) -> Self {
        Self { marker, file, signer_obs, sink_obs, hook_calls: 0, terminate }
    }

    fn fire(
        &mut self,
        publication: &Result<AdmittedPublishOutcome, AdmittedPublishError>,
        signature: &[u8],
        republished: bool,
        pre_sign_calls: u32,
    ) {
        use std::io::Write as _;
        self.hook_calls = self.hook_calls.saturating_add(1);
        assert_eq!(publication, &Ok(AdmittedPublishOutcome::Published), "boundary requires the actual first Published acknowledgement");
        assert!(!republished, "boundary excludes publication retries");
        assert_eq!(pre_sign_calls, 1, "the actual post-consume/pre-sign hook ran once");
        assert_eq!(self.hook_calls, 1, "publication hook runs exactly once");
        assert_eq!(self.signer_obs.load(std::sync::atomic::Ordering::SeqCst), 1, "exactly one actual signer invocation");
        assert_eq!(self.sink_obs.load(std::sync::atomic::Ordering::SeqCst), 0, "completion sink has not run");
        assert_eq!(signature.len(), qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE, "published signature has exact ML-DSA-44 length");
        assert_eq!(signature.len(), crate::signing_journal_admission::OUTPUT_CAP, "published signature fits the admitted output exactly");
        self.marker[23..27].copy_from_slice(&pre_sign_calls.to_le_bytes());
        self.marker[27..31].copy_from_slice(&self.hook_calls.to_le_bytes());
        self.marker[31..35].copy_from_slice(&1u32.to_le_bytes());
        self.marker[35..39].copy_from_slice(&0u32.to_le_bytes());
        self.marker[39] = 1;
        self.marker[40] = 0;
        self.marker[POSTPUB_SIGNATURE_LEN_OFFSET..POSTPUB_SIGNATURE_OFFSET]
            .copy_from_slice(&(signature.len() as u16).to_le_bytes());
        self.marker[POSTPUB_SIGNATURE_OFFSET..POSTPUB_MARKER_LEN].copy_from_slice(signature);
        self.file.write_all(self.marker.as_slice()).expect("write complete publication marker");
        self.file.flush().expect("flush publication marker");
        self.file.sync_all().expect("sync publication marker");
        if self.terminate {
            std::process::abort();
        }
    }
}

const POST_SIGN_MARKER_LEN: usize = 4193;
const POST_SIGN_PK_OFFSET: usize = 43;
const POST_SIGN_VOTE_LEN_OFFSET: usize =
    POST_SIGN_PK_OFFSET + qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE;
const POST_SIGN_VOTE_OFFSET: usize = POST_SIGN_VOTE_LEN_OFFSET + 2;
const POST_SIGN_PREIMAGE_LEN_OFFSET: usize = POST_SIGN_VOTE_OFFSET + 69;
const POST_SIGN_PREIMAGE_OFFSET: usize = POST_SIGN_PREIMAGE_LEN_OFFSET + 2;
const POST_SIGN_POSITION_OFFSET: usize = POST_SIGN_PREIMAGE_OFFSET + MODEL_MAX_PREIMAGE_BYTES as usize;
const POST_SIGN_BINDING_OFFSET: usize = POST_SIGN_POSITION_OFFSET + 55;
const POST_SIGN_SIGNATURE_LEN_OFFSET: usize = POST_SIGN_BINDING_OFFSET + 32;
const POST_SIGN_SIGNATURE_OFFSET: usize = POST_SIGN_SIGNATURE_LEN_OFFSET + 2;

#[derive(Default)]
struct PostSignStorageCounters {
    combined_reservation_writes: std::sync::atomic::AtomicU64,
    signed_record_only_writes: std::sync::atomic::AtomicU64,
    reissue_attempts: std::sync::atomic::AtomicU64,
    reissue_delegated_writes: std::sync::atomic::AtomicU64,
    bounded_read_attempts: std::sync::atomic::AtomicU64,
    bounded_present_reads: std::sync::atomic::AtomicU64,
    other_mutations: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PostSignStorageCounts {
    combined_reservation_writes: u64,
    signed_record_only_writes: u64,
    reissue_attempts: u64,
    reissue_delegated_writes: u64,
    bounded_read_attempts: u64,
    bounded_present_reads: u64,
    other_mutations: u64,
}

impl PostSignStorageCounters {
    fn snapshot(&self) -> PostSignStorageCounts {
        use std::sync::atomic::Ordering;
        PostSignStorageCounts {
            combined_reservation_writes: self.combined_reservation_writes.load(Ordering::SeqCst),
            signed_record_only_writes: self.signed_record_only_writes.load(Ordering::SeqCst),
            reissue_attempts: self.reissue_attempts.load(Ordering::SeqCst),
            reissue_delegated_writes: self.reissue_delegated_writes.load(Ordering::SeqCst),
            bounded_read_attempts: self.bounded_read_attempts.load(Ordering::SeqCst),
            bounded_present_reads: self.bounded_present_reads.load(Ordering::SeqCst),
            other_mutations: self.other_mutations.load(Ordering::SeqCst),
        }
    }
}

/// Fixed witness for the isolated post-sign/pre-publication boundary. Its backing,
/// marker file, and observers are owned by the test harness, not the composition.
struct PostSignPrePublicationEvidence {
    marker: Box<[u8; POST_SIGN_MARKER_LEN]>,
    file: std::fs::File,
    nonce: [u8; 16],
    signer_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
    sink_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
    publication_calls: std::sync::Arc<std::sync::atomic::AtomicU32>,
    storage_counters: std::sync::Arc<PostSignStorageCounters>,
    storage_baseline: PostSignStorageCounts,
    hook_calls: u32,
    terminate: bool,
}

impl PostSignPrePublicationEvidence {
    fn new(
        marker: Box<[u8; POST_SIGN_MARKER_LEN]>,
        file: std::fs::File,
        nonce: [u8; 16],
        signer_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
        sink_obs: std::sync::Arc<std::sync::atomic::AtomicU32>,
        publication_calls: std::sync::Arc<std::sync::atomic::AtomicU32>,
        storage_counters: std::sync::Arc<PostSignStorageCounters>,
        storage_baseline: PostSignStorageCounts,
        terminate: bool,
    ) -> Self {
        Self {
            marker,
            file,
            nonce,
            signer_obs,
            sink_obs,
            publication_calls,
            storage_counters,
            storage_baseline,
            hook_calls: 0,
            terminate,
        }
    }

    fn fire(&mut self, output: &crate::signing_journal_admission::AdmittedOutput, route_calls: u32) {
        use std::io::Write as _;
        use std::sync::atomic::Ordering;

        self.hook_calls = self.hook_calls.saturating_add(1);
        assert_eq!(self.hook_calls, 1, "post-sign hook must run exactly once");
        assert_eq!(route_calls, 1, "the route reached its pre-sign hook exactly once");
        assert_eq!(&self.marker[7..23], &self.nonce, "preconstructed nonce remains intact");
        assert_eq!(self.signer_obs.load(Ordering::SeqCst), 1, "one actual signer call");
        assert_eq!(self.sink_obs.load(Ordering::SeqCst), 0, "completion sink has not run");
        assert_eq!(
            self.publication_calls.load(Ordering::SeqCst),
            0,
            "publication callsite has not been entered"
        );
        let storage = self.storage_counters.snapshot();
        assert_eq!(
            storage.combined_reservation_writes
                - self.storage_baseline.combined_reservation_writes,
            1,
            "one atomic record-plus-metadata reservation write completed"
        );
        assert_eq!(
            storage.signed_record_only_writes
                - self.storage_baseline.signed_record_only_writes,
            0,
            "no Signed-result record-only write occurred"
        );
        assert_eq!(
            storage.reissue_attempts - self.storage_baseline.reissue_attempts,
            0,
            "no reissue occurred"
        );
        let signature = output.view();
        assert_eq!(signature.len(), output.used(), "committed output view is the valid span");
        assert_eq!(
            signature.len(),
            qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE,
            "actual committed signature has the suite-100 length"
        );
        assert_eq!(
            signature.len(),
            crate::signing_journal_admission::OUTPUT_CAP,
            "actual committed signature fills the admitted output"
        );

        self.marker[23..27].copy_from_slice(&self.hook_calls.to_le_bytes());
        self.marker[27..31].copy_from_slice(&self.signer_obs.load(Ordering::SeqCst).to_le_bytes());
        self.marker[31..35].copy_from_slice(&self.sink_obs.load(Ordering::SeqCst).to_le_bytes());
        self.marker[35..39].copy_from_slice(&self.publication_calls.load(Ordering::SeqCst).to_le_bytes());
        self.marker[39] = 1;
        // This flag records the exact source position immediately before the loop.
        // The connected callsite observer independently proves no API attempt yet.
        self.marker[40] = 0;
        self.marker[POST_SIGN_SIGNATURE_LEN_OFFSET..POST_SIGN_SIGNATURE_OFFSET]
            .copy_from_slice(&(signature.len() as u16).to_le_bytes());
        self.marker[POST_SIGN_SIGNATURE_OFFSET..].copy_from_slice(signature);
        self.file
            .write_all(self.marker.as_slice())
            .expect("write complete post-sign boundary marker");
        self.file.flush().expect("flush post-sign boundary marker");
        self.file.sync_all().expect("sync post-sign boundary marker");
        if self.terminate {
            std::process::abort();
        }


    }

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
    /// Optional model-only observer incremented immediately before the actual
    /// admitted publication API callsite.
    publication_attempts: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// Optional model-only observer incremented immediately after each actual
    /// admitted publication API return, before outcome classification.
    publication_returns: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// RUN 422 — when `Some`, the hook terminates the process (SIGABRT) at the
    /// post-consume / pre-sign point after writing the preconstructed boundary
    /// marker. `None` (every existing constructor) is inert w.r.t. termination and
    /// preserves exact prior behavior.
    abort_before_sign: Option<AbortEvidence>,
    post_publication: Option<PostPublicationEvidence>,
    post_sign_prepublication: Option<PostSignPrePublicationEvidence>,
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
            publication_attempts: None,
            publication_returns: None,
            abort_before_sign: None,
            post_publication: None,
            post_sign_prepublication: None,
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
            publication_attempts: None,
            publication_returns: None,
            abort_before_sign: None,
            post_publication: None,
            post_sign_prepublication: None,
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
            publication_attempts: None,
            publication_returns: None,
            abort_before_sign: None,
            post_publication: None,
            post_sign_prepublication: None,
        }
    }

    /// RUN 422 — a hook ARMED to terminate the process at the fixed post-consume /
    /// pre-sign boundary. It carries preconstructed [`AbortEvidence`]; at the
    /// boundary it asserts exactly one hook invocation and zero live signer/sink
    /// calls, writes the complete marker, and raises SIGABRT before the signer
    /// runs. No sampling, no probe. Only this constructor arms termination; every
    /// other constructor is inert w.r.t. the process boundary.
    pub(crate) fn aborting(evidence: AbortEvidence) -> Self {
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
            publication_attempts: None,
            publication_returns: None,
            abort_before_sign: Some(evidence),
            post_publication: None,
            post_sign_prepublication: None,
        }
    }

    fn with_post_publication_evidence(mut self, evidence: PostPublicationEvidence) -> Self {
        self.post_publication = Some(evidence);
        self
    }

    fn with_post_sign_prepublication_evidence(
        mut self,
        evidence: PostSignPrePublicationEvidence,
    ) -> Self {
        self.publication_attempts = Some(evidence.publication_calls.clone());
        self.post_sign_prepublication = Some(evidence);
        self
    }

    fn publication_observing(
        publication_attempts: std::sync::Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        let mut hook = Self::inert();
        hook.publication_attempts = Some(publication_attempts);
        hook
    }

    fn with_publication_return_observer(
        mut self,
        publication_returns: std::sync::Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        self.publication_returns = Some(publication_returns);
        self
    }

    fn on_post_sign_pre_publication(
        &mut self,
        output: &crate::signing_journal_admission::AdmittedOutput,
    ) {
        if let Some(evidence) = self.post_sign_prepublication.as_mut() {
            let publication_attempts = self
                .publication_attempts
                .as_ref()
                .expect("armed post-sign evidence requires a connected publication observer");
            assert!(
                std::sync::Arc::ptr_eq(publication_attempts, &evidence.publication_calls),
                "armed post-sign evidence shares the connected publication observer"
            );
            evidence.fire(output, self.calls);
        }
    }

    fn on_publication_call_attempt(&self) {
        if let Some(attempts) = &self.publication_attempts {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn on_publication_call_return(&self) {
        if let Some(returns) = &self.publication_returns {
            returns.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn on_post_publication_pre_retire(
        &mut self,
        publication: &Result<AdmittedPublishOutcome, AdmittedPublishError>,
        committed_signature: &[u8],
        republished: bool,
    ) {
        if let Some(evidence) = self.post_publication.as_mut() {
            evidence.fire(publication, committed_signature, republished, self.calls);
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
        // RUN 422 — isolated post-consumption process-death boundary. If armed,
        // this hook has observed a successful consume and original-ticket
        // confirmation (by its exact control-flow position after step 14), asserts
        // the directly-observed invariants, writes the preconstructed marker, and
        // aborts BEFORE the signer executes. `fire` never returns.
        if let Some(evidence) = self.abort_before_sign.take() {
            evidence.fire(self.calls);
        }
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
    /// RUN 422 — an OPTIONAL shared completion-sink observer. When present, each
    /// real `record` call bumps this shared `AtomicU32` ALONGSIDE the owned
    /// `calls` counter (never instead of it), so a borrow-correct external
    /// observer (e.g. the abort hook) can read the live sink-invocation count
    /// without aliasing the `&mut` sink. `None` leaves existing behavior exact.
    pub(crate) observer: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
}

impl RealSignRecordingSink {
    pub(crate) fn new() -> Self {
        Self {
            last: None,
            calls: 0,
            observer: None,
        }
    }

    /// As [`RealSignRecordingSink::new`] but wired to a shared observer that is
    /// bumped in lock-step with the owned `calls` counter.
    pub(crate) fn new_observed(observer: std::sync::Arc<std::sync::atomic::AtomicU32>) -> Self {
        Self {
            last: None,
            calls: 0,
            observer: Some(observer),
        }
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
        if let Some(obs) = &self.observer {
            obs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
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
    /// RUN 422 — an OPTIONAL shared signer observer, bumped in lock-step with the
    /// owned `calls` counter inside `sign_vote_into` (never instead of it). Lets a
    /// borrow-correct external observer read the live signer-invocation count
    /// without aliasing this fixture. `None` preserves existing behavior exactly.
    observer: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
}

impl<'a> CountingValidatorSigner<'a> {
    pub(crate) fn new(inner: &'a dyn ValidatorSigner) -> Self {
        Self {
            inner,
            calls: std::sync::atomic::AtomicU32::new(0),
            observer: None,
        }
    }

    /// As [`CountingValidatorSigner::new`] but wired to a shared observer bumped in
    /// lock-step with the owned `calls` counter.
    pub(crate) fn new_observed(
        inner: &'a dyn ValidatorSigner,
        observer: std::sync::Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        Self {
            inner,
            calls: std::sync::atomic::AtomicU32::new(0),
            observer: Some(observer),
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
        if let Some(obs) = &self.observer {
            obs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
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

    // The optional model-only post-sign/pre-publication boundary observes the
    // actual committed span while all protected resources and capabilities live.
    coord.on_post_sign_pre_publication(&output);

    // 17. Admitted publication, with AT MOST one immediate retry and ONLY for the
    //     selected `Storage(WriteIo)` outcome. The same capability, output, and
    //     workspace are reused; nothing is re-signed, re-consumed, or re-covered.
    let mut republished = false;
    let publish_result = loop {
        coord.on_publication_call_attempt();
        let result = journal.publish_result_admitted(&cap, &output, &mut publish_ws);
        coord.on_publication_call_return();
        match result {
            Err(AdmittedPublishError::Storage(BoundedDiag::WriteIo)) if !republished => {
                republished = true;
                continue;
            }
            other => break other,
        }
    };
    coord.on_post_publication_pre_retire(&publish_result, output.view(), republished);
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
        let result = journal.publish_result_admitted(&cap, &output, &mut publish_ws);
        coord.on_publication_call_return();
        match result {
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
        // RUN 422 — Isolated O5 RECOVERY BARRIER for same-authority use.
        //
        // These cases EXTEND `same_authority_uncertain_safety_publication_blocks_
        // zero_signing` (which proves only the initial refusal) through the full
        // recovery composition using ONLY the existing public O2/O3/O5 API
        // (`open` / `read_validate` / `reacknowledge`) and the existing fault
        // injection — no new protected-use implementation, no lifecycle predicate
        // change, no private mutation, and no manual clearing of the recovery
        // requirement. O5 is a STORAGE recovery barrier, not signing authorization:
        // a cleared recovery requirement is NEVER sufficient on its own. Labels:
        // REAL ML-DSA-44 signing/verification, REAL durable-storage acknowledgements,
        // model journal/authority fixtures. This is IN-PROCESS, fault-injected
        // evidence, NOT process-death / power-loss durability.
        // ==================================================================

        /// Drive a COHERENT uncertain-publication fixture that AGREES at L1: the
        /// engine locks the real view-1 successor (peers 2 & 3 complete the quorum)
        /// and the durable restriction advances to the SAME L1 through an
        /// acknowledgement-lost (uncertain) write, latching the shared recovery
        /// requirement. The pinned context, authority and captured envelope/proposal
        /// are UNCHANGED. Returns the L1 block id; the injected fault is cleared on
        /// return so a subsequent O5 (or O5 fault) is controlled by the caller.
        fn advance_engine_and_uncertain_durable_to_l1(
            owner: &SafetyRecordOwner,
            engine: &mut qbind_consensus::BasicHotStuffEngine<[u8; 32]>,
            ctx: &PinnedSafetyContext,
        ) -> [u8; 32] {
            use crate::safety_record_store::backend::InjectFault;
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
            // Durable advance of the SAME L1 restriction under an uncertain write.
            owner
                .backend_for_test()
                .set_inject(InjectFault::UncertainAfterWrite);
            let latch = owner.publish_locked(
                make_locked_qc(ctx, l1_block, 1, valid_wire_qc(ctx, l1_block, 1), None).unwrap(),
                1,
                None::<&FixtureCommittedHistory>,
            );
            assert!(
                matches!(latch, PublishResult::UncertainDurable),
                "expected an uncertain durable outcome, got {latch:?}"
            );
            owner.backend_for_test().set_inject(InjectFault::None);
            assert!(
                owner.recovery_required(),
                "the uncertain publication latched recovery-required"
            );
            l1_block
        }

        /// RUN 422 (stored-restriction establishment) - establish the surviving
        /// stored restriction DIRECTLY from an O3 proof's read-only accessors:
        /// assert it is `Locked` and return its exact restriction identity (lock
        /// block id + lock view) and publication revision. A revision alone does
        /// NOT establish lock identity, so the identity is read explicitly; no
        /// mutation access is used and no substitute proof is reconstructed.
        fn stored_locked_identity(proof: &ValidatedRecord) -> (GenerationIdentity, u64) {
            assert!(
                proof.retained().is_locked(),
                "the surviving stored record is Locked"
            );
            let id = GenerationIdentity::from_retained(proof.retained())
                .expect("a Locked record yields a restriction identity");
            (id, proof.publication_revision())
        }

        /// §3/§4 — the FULL fresh-signing recovery sequence. A coherent uncertain
        /// L1 publication latches recovery; the same-authority fresh route refuses
        /// before recovery (zero signer/sink/D10) and STILL refuses after successful
        /// O2 inspection and O3 validation; only a successful O5 (using the current
        /// validated publication) clears the requirement, after which re-entering the
        /// protected route performs its own observation/lifecycle/eligibility/
        /// authorization checks and signs EXACTLY ONCE, publishing a signature that
        /// VERIFIES against the UNCHANGED original Vote's journal-bound preimage. The
        /// O3 proof is held across O5 and destroyed before the proof-free comparison.
        #[test]
        fn same_authority_fresh_signing_recovers_through_o5_barrier() {
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

            // Coherent uncertain-publication fixture (engine ↔ durable AGREE at L1).
            let l1_block = advance_engine_and_uncertain_durable_to_l1(&owner, &mut engine, &ctx);

            // Establish the asserted components SEPARATELY (never inferred from a
            // label): the engine's ACTUAL lock, and the recovery requirement.
            let lk = engine.locked_qc().expect("engine locks L1");
            assert_eq!(lk.block_id, l1_block, "the engine's actual lock is the L1 successor");
            assert_eq!(lk.view, 1);
            assert!(owner.recovery_required(), "the asserted recovery requirement is set");

            // Proof-FREE baseline, sampled with NO O3 proof held.
            let ledgers_before = snapshot_ledgers(&owner);
            let prov_before = pin_provenance_now(&owner, &decided);

            // Phase 1 — BEFORE recovery: exact refusal, zero signer, zero sink, and
            // no new D10 reservation.
            {
                let mut sink = RealSignRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let refused = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &signer, &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                assert_eq!(
                    refused,
                    RealFreshSignOutcome::ObservationRefused,
                    "recovery-required blocks the dependent fresh route before recovery"
                );
                assert_eq!(signer.calls(), 0, "zero signer calls before recovery");
                assert_eq!(sink.calls, 0, "zero sink calls before recovery");
                assert_eq!(journal.reserved_position_count(), 0, "no new D10 reservation");
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the pre-recovery fresh refusal",
                );
            }

            // Phase 2 — O2 inspection + O3 validation SUCCEED but do NOT clear the
            // recovery requirement. The surviving stored successor is at the L1
            // revision (established directly from the validated proof, not a label).
            let _meta = owner.open().expect("O2 open inspects the surviving established state");
            assert!(owner.recovery_required(), "O2 inspection does not clear recovery");
            let proof = owner
                .read_validate::<FixtureCommittedHistory>(None)
                .expect("O3 validates the surviving successor");
            // Establish the surviving stored restriction DIRECTLY from the proof's
            // read-only accessors: Locked, at the expected lock block id / view /
            // revision. The engine's actual lock is read independently and must
            // agree in this coherent case (a revision alone is not lock identity).
            let (stored_id, stored_rev) = stored_locked_identity(&proof);
            assert_eq!(stored_rev, 2, "the surviving stored successor is at the L1 revision");
            assert_eq!(
                stored_id.lock_block_id, l1_block,
                "the stored lock block id is the L1 successor"
            );
            assert_eq!(stored_id.lock_view, 1, "the stored lock view is the L1 view");
            assert_eq!(
                (stored_id.lock_block_id, stored_id.lock_view),
                (lk.block_id, lk.view),
                "the stored restriction identity equals the engine's actual lock"
            );
            assert!(owner.recovery_required(), "O3 validation does not clear recovery");

            // The held O3 proof carries a retained-holder reservation, so BOTH
            // ledgers sit ABOVE the proof-free baseline (proof-HELD baseline).
            let held = snapshot_ledgers(&owner);
            assert!(
                held.operational > ledgers_before.operational
                    && held.aggregate > ledgers_before.aggregate,
                "the held O3 proof raises both ledgers above the proof-free baseline"
            );

            {
                let mut sink = RealSignRecordingSink::new();
                let mut coord = ModelCoordinationHook::inert();
                let still = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &signer, &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                assert_eq!(
                    still,
                    RealFreshSignOutcome::ObservationRefused,
                    "inspection and validation do not clear the recovery requirement"
                );
                assert_eq!(signer.calls(), 0);
                assert_eq!(sink.calls, 0);
                assert_eq!(journal.reserved_position_count(), 0);
            }

            // Proof-HELD cleanup: with the O3 proof still live, the post-refusal
            // ledgers return to the independently sampled proof-held baseline, and
            // the borrowed Vote and original pin provenance are unchanged.
            assert_cleanup_preserved(
                &owner, &decided, &base_vote, held, prov_before,
                "the post-O2/O3 fresh refusal (proof held)",
            );

            // Phase 3 — O5 recovery using the CURRENT validated publication clears it.
            match owner.reacknowledge(&proof) {
                PublishResult::DurableAcknowledged { new_revision } => {
                    assert_eq!(new_revision, 2, "O5 re-acknowledges the surviving L1 revision");
                }
                other => panic!("expected O5 DurableAcknowledged, got {other:?}"),
            }
            assert!(
                !owner.recovery_required(),
                "a successful O5 clears the recovery requirement"
            );

            // Destroy the temporary O3 proof BEFORE comparing against the proof-free
            // baseline; both ledgers return to that baseline.
            drop(proof);
            assert_eq!(
                snapshot_ledgers(&owner),
                ledgers_before,
                "dropping the O3 proof restores BOTH ledgers to the proof-free baseline"
            );

            // Phases 4 & 5 — re-enter the protected route; it re-runs observation,
            // lifecycle, eligibility and authorization and signs EXACTLY ONCE.
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let outcome = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
            );
            let diag = match outcome {
                RealFreshSignOutcome::Published(d) => d,
                other => panic!("expected Published after O5 recovery, got {other:?}"),
            };
            assert_eq!(diag.sig_len, 2420, "exactly one real ML-DSA-44 signature");
            assert_eq!(diag.retirement, RetirementReport::Retired, "separately reported retirement");
            assert_eq!(signer.calls(), 1, "exactly one real signer call across the whole sequence");
            assert_eq!(sink.calls, 1, "one completion sink on the successful route");
            assert_eq!(coord.calls, 1, "the coordination point is reached once");

            // Verify the EXACT stored signature against the ORIGINAL Vote's
            // journal-bound preimage under the authorized suite-100 key.
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

            assert_cleanup_preserved(
                &owner, &decided, &base_vote, ledgers_before, prov_before,
                "the post-O5 resumed-signing success",
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
        // ==================================================================
        // RUN 422 §13.6 — ISOLATED, TEST-ONLY store CLOSE/REOPEN recovery
        // boundary. A genuine close/reopen of BOTH persistent backends (the
        // safety record store and the signing-reservation journal) across two
        // separate temporary directories: incarnation A establishes the coherent
        // suite-100 engine, the acknowledged L0 restriction, a captured decision
        // and the case-specific durable signing state, then EVERY A owner/backend
        // clone, journal handle and storage Arc that retains a RocksDB instance is
        // dropped. Incarnation B reopens the SAME directories; a successful B
        // reopen over the released RocksDB LOCK is the close evidence. Engine
        // reconstruction and any deliberately retained A objects are HARNESS
        // behavior: this is clean-reopen evidence, NOT process-death, power-loss,
        // or production-restart acceptance. The fixture authority/key and
        // signing-domain inputs are shared across A and B; no A Vote, pin, proof,
        // incarnation or provenance is ever modified to obtain acceptance.
        // ==================================================================

        use crate::safety_record_store::error::{SafetyStoreError, SemanticRefusalDetail};
        use crate::safety_record_store::prepared::ProvenanceRefusal;
        use crate::signing_reservation_journal::{SigningDecisionRecord, SigningRecordStage};
        use crate::storage::RocksDbConsensusStorage;

        /// TEST-ONLY: open a PERSISTENT RocksDB signing-journal store over `dir`.
        fn reopen_open_journal_store(dir: &std::path::Path) -> Arc<RocksDbConsensusStorage> {
            Arc::new(RocksDbConsensusStorage::open(dir).expect("open persistent journal store"))
        }

        /// TEST-ONLY: A-era — initialize + associate (to the OWNER's accountant) +
        /// enter bounded live mode over a PERSISTENT journal store.
        fn reopen_assoc_journal_init(
            owner: &SafetyRecordOwner,
            store: Arc<dyn SigningJournalStorage>,
            capacity: usize,
        ) -> SigningReservationJournal {
            let journal =
                SigningReservationJournal::initialize(store, DEFAULT_MAX_RESERVED_POSITIONS)
                    .expect("A-era initialize admitted journal");
            journal
                .install_accountant_association(owner.backend_for_test().accounting())
                .expect("A install accountant association");
            journal
                .enter_bounded_live_mode(capacity)
                .expect("A enter bounded live mode");
            journal
        }

        /// TEST-ONLY: B-era — REOPEN the established journal over a genuinely new
        /// RocksDB instance via `SigningReservationJournal::open` (never the
        /// initialization fallback), install B's accountant association, then
        /// explicitly enter bounded live mode before any admitted journal use.
        fn reopen_assoc_journal_open(
            owner: &SafetyRecordOwner,
            store: Arc<dyn SigningJournalStorage>,
            capacity: usize,
        ) -> SigningReservationJournal {
            let journal = SigningReservationJournal::open(store)
                .expect("B-era reopen of the established journal (no init fallback)");
            journal
                .install_accountant_association(owner.backend_for_test().accounting())
                .expect("B install accountant association");
            journal
                .enter_bounded_live_mode(capacity)
                .expect("B enter bounded live mode");
            journal
        }

        /// TEST-ONLY: B-era — attach a fresh owner over the SAME reopened safety
        /// directory (no initialize; the directory is already established).
        fn reopen_attach(dir: &std::path::Path, ctx: &PinnedSafetyContext) -> SafetyRecordOwner {
            SafetyRecordOwner::attach(open_enabled(dir), ctx.clone())
                .expect("B attach over reopened safety store")
        }

        /// TEST-ONLY: a non-consuming provenance probe that RETURNS the typed
        /// refusal (unlike `pin_provenance_now`, which expects success), so a reopen
        /// test can assert the EXACT Missing/Foreign diagnostic for a retained A-era
        /// pin presented under incarnation B.
        fn pin_provenance_try(
            owner: &SafetyRecordOwner,
            decided: &qbind_consensus::DecidedVote<OwningCapturePayload>,
        ) -> Result<PreparedProvenance, ProvenanceRefusal> {
            let guard = owner.backend.lock_domain();
            owner.pin_provenance_locked(&guard, decided.payload().pin())
        }

        /// TEST-ONLY: read the acknowledged `Signed` record directly from the
        /// reopened persistent journal store and copy its retained signature into a
        /// fixed-size witness. Mirrors the checked-retained module's
        /// `witness_from_store` but reads through the reopened `dyn` store.
        fn reopen_witness_from_store(
            store: &Arc<dyn SigningJournalStorage>,
            position: &SigningPosition,
            binding: &BindingDigest,
        ) -> RetainedSliceWitness {
            let raw = store
                .get_signing_record(&position.storage_key())
                .expect("bounded record read succeeds after reopen")
                .expect("the acknowledged Signed record survived the reopen");
            let record = SigningDecisionRecord::decode(&raw).expect("record decodes");
            assert_eq!(
                record.stage,
                SigningRecordStage::Signed,
                "the witness is read from the acknowledged Signed stage"
            );
            assert_eq!(record.position, *position, "the witnessed record is at the exact position");
            assert_eq!(record.binding, *binding, "the witnessed record carries the exact binding");
            let sig = record
                .retained_signature
                .expect("a Signed record retains its signature");
            assert_eq!(
                sig.len(),
                qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE,
                "the reopened publication retains the full 2,420-byte signature"
            );
            RetainedSliceWitness::from_validated(&sig)
        }

        /// Test-only O2/O3/O5 recovery under the reopened restriction. Checks the
        /// recovered Locked identity/revision against the reconstructed engine lock,
        /// publishes O5 with the recovery proof, and returns the authoritative
        /// revision. Capture stays separate so its caller obtains a fresh proof.
        fn reopen_b_recover_only(
            owner: &SafetyRecordOwner,
            engine: &BasicHotStuffEngine<[u8; 32]>,
            expected_lock_block: [u8; 32],
        ) -> u64 {
            let meta = owner.open().expect("B O2 open");
            let rev = meta.current_revision;
            assert!(owner.recovery_required(), "a freshly reopened backend requires recovery before O5");
            let op_free = owner.backend_for_test().accounting_current();
            let agg_free = owner.backend_for_test().accounting_aggregate_current();
            let op_ceiling = owner.backend_for_test().accounting_cap();
            let agg_ceiling = owner.backend_for_test().accounting_aggregate_cap();
            let recovery = owner.read_validate(None::<&FixtureCommittedHistory>).expect("B O3 recovery proof");
            assert!(owner.recovery_required(), "O3 validation alone does not clear recovery");
            let op_held = owner.backend_for_test().accounting_current();
            let agg_held = owner.backend_for_test().accounting_aggregate_current();
            assert!(op_held > op_free, "O3 proof raises operational standing charge");
            assert!(agg_held > agg_free, "O3 proof raises aggregate standing charge");
            let durable = GenerationIdentity::from_retained(recovery.retained())
                .expect("recovered Locked record yields restriction identity");
            let lk = engine.locked_qc().expect("reconstructed engine lock is present");
            assert_eq!(durable.lock_block_id, lk.block_id, "recovered id == engine lock id");
            assert_eq!(durable.lock_block_id, expected_lock_block, "recovered id is the child-era L0 block");
            assert_eq!(durable.lock_view, 0, "recovered restriction is L0");
            assert_eq!(lk.view, 0, "engine lock view is L0");
            assert_eq!(rev, recovery.publication_revision(), "O3 revision == authoritative revision");
            match owner.reacknowledge(&recovery) {
                PublishResult::DurableAcknowledged { new_revision } => assert_eq!(new_revision, rev),
                other => panic!("B O5 must acknowledge, got {other:?}"),
            }
            assert!(!owner.recovery_required(), "successful O5 clears recovery");
            assert_eq!(owner.backend_for_test().accounting_current(), op_held, "O5 immediately restores proof-held operational baseline");
            assert_eq!(owner.backend_for_test().accounting_aggregate_current(), agg_held, "O5 immediately restores proof-held aggregate baseline");
            assert_eq!(owner.backend_for_test().accounting_cap(), op_ceiling, "O5 preserves the proof-held operational ceiling");
            assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), agg_ceiling, "O5 preserves the proof-held aggregate ceiling");
            drop(recovery);
            assert_eq!(owner.backend_for_test().accounting_current(), op_free, "dropping O3 restores proof-free operational baseline");
            assert_eq!(owner.backend_for_test().accounting_aggregate_current(), agg_free, "dropping O3 restores proof-free aggregate baseline");
            rev
        }

        fn reopen_b_recover_and_capture(
            owner: &SafetyRecordOwner,
            engine: &mut BasicHotStuffEngine<[u8; 32]>,
            p1: &BlockProposal,
            lim: &PreparedDecisionInputLimits,
            expected_lock_block: [u8; 32],
        ) -> DecidedVote<OwningCapturePayload> {
            let rev = reopen_b_recover_only(owner, engine, expected_lock_block);
            let cap_proof = owner
                .read_validate(None::<&FixtureCommittedHistory>)
                .expect("B O3 proof for capture");
            match owner.decide_and_capture_owned(engine, ValidatorId::new(2), p1, lim, rev, cap_proof) {
                OwnedDecisionOutcome::Decided(dv) => dv,
                other => panic!("B owning capture must Decide, got {other:?}"),
            }
        }

        // ------------------------------------------------------------------
        // 1. No A reservation at the position → B-era fresh capture takes the
        //    admitted real-signing path: ONE signer, ONE sink, durable-position
        //    count 0 → 1, and the stored signature verifies against the exact
        //    journal-bound preimage.
        // ------------------------------------------------------------------
        #[test]
        fn reopen_b_era_fresh_admitted_single_signer_single_sink() {
            let safety_dir = tempfile::tempdir().unwrap();
            let journal_dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (pv, sk) = make_real_signing_authority();

            // ---- Incarnation A: establish, no reservation at the position. ----
            let (owner_a, engine_a, a_decided, _p1_a, lim, _rev_a) =
                capture_multi_with_suite(safety_dir.path(), &ctx, MODEL_SUITE_U16);
            let a_base_vote = a_decided.vote().clone();
            let store_a = reopen_open_journal_store(journal_dir.path());
            let journal_a =
                reopen_assoc_journal_init(&owner_a, store_a.clone() as Arc<dyn SigningJournalStorage>, 1);
            assert_eq!(journal_a.reserved_position_count(), 0, "A initialized the journal with no reservation");
            let a_acct = owner_a.backend_for_test().accounting_handle_for_test();

            // ---- Close A: drop every handle that retains a RocksDB instance. ----
            drop(journal_a);
            drop(store_a);
            drop(a_decided);
            drop(engine_a);
            drop(owner_a);

            // ---- Incarnation B: reopen both stores. ----
            let owner_b = reopen_attach(safety_dir.path(), &ctx);
            let store_b = reopen_open_journal_store(journal_dir.path());
            let journal_b =
                reopen_assoc_journal_open(&owner_b, store_b.clone() as Arc<dyn SigningJournalStorage>, 1);
            let b_acct = owner_b.backend_for_test().accounting_handle_for_test();
            assert!(
                !a_acct.same_ledger(&b_acct),
                "A and B are INDEPENDENT accounting authorities across the reopen"
            );
            assert_eq!(journal_b.reserved_position_count(), 0, "the reopened journal recovers the empty position set");

            let (mut engine_b, p1_b, l0_block) = engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
            let b_decided = reopen_b_recover_and_capture(&owner_b, &mut engine_b, &p1_b, &lim, l0_block);
            let b_base_vote = b_decided.vote().clone();
            assert_eq!(a_base_vote, b_base_vote, "the independently derived A and B self-votes correspond");

            // ---- B-era strict real fresh-signing composition. ----
            let mut snapshot = established_snapshot(&pv);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();

            // Standing baseline (bounded journal container + B context/pin) BEFORE
            // the signing call, on BOTH ledgers, with the pin/Vote live.
            let ledgers_before = snapshot_ledgers(&owner_b);
            let prov_before = pin_provenance_now(&owner_b, &b_decided);
            let op_cap_before = owner_b.backend_for_test().accounting_cap();
            let agg_cap_before = owner_b.backend_for_test().accounting_aggregate_cap();

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner_b, &engine_b, &b_decided, &p1_b, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal_b, &mut coord, ReconfirmPerturbation::None,
            );
            let diag = match outcome {
                RealFreshSignOutcome::Published(d) => d,
                other => panic!("expected Published on the B-era eligible real path, got {other:?}"),
            };
            assert_eq!(diag.sig_len, 2420, "ML-DSA-44 signature size");
            assert_eq!(diag.retirement, RetirementReport::Retired, "the admitted publication is retired");
            assert!(!diag.republished, "the clean path performs no retry");
            assert_eq!(signer.calls(), 1, "exactly ONE real signer invocation");
            assert_eq!(sink.calls, 1, "exactly ONE completion sink call");
            assert_eq!(coord.calls, 1, "the coordination point is reached once");
            assert_eq!(journal_b.reserved_position_count(), 1, "durable-position count advances 0 -> 1");

            // Complete cleanup immediately after the successful signing, BEFORE the
            // legacy journal readback: every transient signing-workspace reservation
            // (control, real-sign work, crypto, output, reserve/continuation,
            // publication) is released back to the standing baseline on BOTH
            // ledgers, the original pin provenance and complete Vote are preserved,
            // and both ceilings are unchanged. The durable position's slot is
            // covered within the already-reserved bounded container, so the resting
            // baseline is unchanged by the 0 -> 1 advance.
            assert_cleanup_preserved(
                &owner_b, &b_decided, &b_base_vote, ledgers_before, prov_before,
                "the successful B-era fresh signing",
            );
            assert_eq!(owner_b.backend_for_test().accounting_cap(), op_cap_before, "B operational ceiling unchanged");
            assert_eq!(owner_b.backend_for_test().accounting_aggregate_cap(), agg_cap_before, "B aggregate ceiling unchanged");

            // The stored signature VERIFIES against the exact journal-bound preimage
            // (legacy journal inspection; harness-owned readback, outside signing).
            let (pos, binding) = retained_pos_binding(&pv, &b_base_vote);
            let preimage = pv.signing_domain.vote_preimage(&b_base_vote);
            let published_sig = match journal_b.reserve_for_sign(&pos, &binding) {
                Ok(ReservationOutcome::ExactRetryRetained(sig)) => sig,
                other => panic!("expected the acknowledged signature, got {other:?}"),
            };
            assert_eq!(published_sig.len(), 2420, "the stored record holds the full signature");
            let (_suite, pk) = pv
                .key_provider
                .get_suite_and_key(ValidatorId::new(SIGNER_VID))
                .expect("the authorized public key is installed");
            MlDsa44Backend::verify(&pk, &preimage, &published_sig)
                .expect("the stored signature verifies under the authorized key and bound preimage");

            // ---- Teardown: drop every B owning object (owner/backend, journal
            //      handle, journal-store Arc, engine, decided pin); B's ledgers both
            //      return to zero, observed through the INDEPENDENT accounting handle
            //      (operational zero is asserted directly, NOT inferred from the
            //      aggregate). ----
            drop(b_decided);
            drop(engine_b);
            drop(journal_b);
            drop(store_b);
            drop(owner_b);
            assert_eq!(b_acct.current(), 0, "B's operational ledger returns to zero after full teardown");
            assert_eq!(b_acct.aggregate().current(), 0, "B's aggregate ledger returns to zero after full teardown");
        }

        // ------------------------------------------------------------------
        // 2. A persisted `Reserved` (continuation dropped, unpublished) → after
        //    reopen the B-era protected fresh composition is NON-delivering
        //    (`ReservePotentiallySigned`): zero signer/sink, unchanged record
        //    bytes, unchanged durable-position count.
        // ------------------------------------------------------------------
        #[test]
        fn reopen_persisted_reserved_blocks_fresh_zero_signer() {
            let safety_dir = tempfile::tempdir().unwrap();
            let journal_dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (pv, sk) = make_real_signing_authority();

            // ---- A: admit a genuine Reserved record, then DROP its continuation. ----
            let (owner_a, engine_a, a_decided, _p1_a, lim, _rev_a) =
                capture_multi_with_suite(safety_dir.path(), &ctx, MODEL_SUITE_U16);
            let a_base_vote = a_decided.vote().clone();
            let store_a = reopen_open_journal_store(journal_dir.path());
            let journal_a =
                reopen_assoc_journal_init(&owner_a, store_a.clone() as Arc<dyn SigningJournalStorage>, 1);
            let (a_pos, a_binding) = retained_pos_binding(&pv, &a_base_vote);
            let ws = journal_a.admit_reserve_workspace().expect("admit A reserve workspace");
            match journal_a.reserve_for_sign_admitted(&a_pos, &a_binding, ws) {
                Ok(AdmittedReservationOutcome::FreshlyReserved(cont)) => drop(cont), // setup: never consumed/published
                other => panic!("A setup must FreshlyReserve, got {other:?}"),
            }
            assert_eq!(journal_a.reserved_position_count(), 1, "A persisted exactly one Reserved position");
            let record_before = store_a
                .get_signing_record(&a_pos.storage_key())
                .expect("read")
                .expect("the Reserved record persists");
            let a_acct = owner_a.backend_for_test().accounting_handle_for_test();

            drop(journal_a);
            drop(store_a);
            drop(a_decided);
            drop(engine_a);
            drop(owner_a);

            // ---- B: reopen; the Reserved position survives. ----
            let owner_b = reopen_attach(safety_dir.path(), &ctx);
            let store_b = reopen_open_journal_store(journal_dir.path());
            let journal_b =
                reopen_assoc_journal_open(&owner_b, store_b.clone() as Arc<dyn SigningJournalStorage>, 1);
            assert!(!a_acct.same_ledger(&owner_b.backend_for_test().accounting_handle_for_test()));
            assert_eq!(journal_b.reserved_position_count(), 1, "the reopened journal recovers the Reserved position");

            let (mut engine_b, p1_b, l0_block) = engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
            let b_decided = reopen_b_recover_and_capture(&owner_b, &mut engine_b, &p1_b, &lim, l0_block);
            let b_base_vote = b_decided.vote().clone();
            assert_eq!(a_base_vote, b_base_vote, "A and B self-votes correspond (same position)");

            let mut snapshot = established_snapshot(&pv);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let mut sink = RealSignRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();

            // Standing baseline on BOTH ledgers with the B pin/Vote live, plus the
            // original B pin provenance and both ceilings.
            let ledgers_before = snapshot_ledgers(&owner_b);
            let prov_before = pin_provenance_now(&owner_b, &b_decided);
            let op_cap_before = owner_b.backend_for_test().accounting_cap();
            let agg_cap_before = owner_b.backend_for_test().accounting_aggregate_cap();

            let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner_b, &engine_b, &b_decided, &p1_b, &lim, None, &mut snapshot,
                &signer, &mut sink, &journal_b, &mut coord, ReconfirmPerturbation::None,
            );
            assert_eq!(
                outcome,
                RealFreshSignOutcome::ReservePotentiallySigned,
                "a persisted Reserved record creates no new fresh-signing opportunity"
            );
            assert_eq!(signer.calls(), 0, "zero signer calls");
            assert_eq!(sink.calls, 0, "zero sink calls");
            // Durable non-mutation attached to THIS refusal boundary.
            assert_eq!(journal_b.reserved_position_count(), 1, "the durable-position count is unchanged");
            let record_after = store_b
                .get_signing_record(&a_pos.storage_key())
                .expect("read")
                .expect("the Reserved record still persists");
            assert_eq!(record_before, record_after, "the persisted Reserved bytes are unchanged");
            // Both ledgers restored, complete borrowed Vote preserved, and the
            // original B pin provenance preserved (ledger equality alone is
            // insufficient for provenance); both ceilings unchanged.
            assert_cleanup_preserved(
                &owner_b, &b_decided, &b_base_vote, ledgers_before, prov_before,
                "the persisted-Reserved fresh refusal",
            );
            assert_eq!(owner_b.backend_for_test().accounting_cap(), op_cap_before, "B operational ceiling unchanged");
            assert_eq!(owner_b.backend_for_test().accounting_aggregate_cap(), agg_cap_before, "B aggregate ceiling unchanged");
        }

        // ------------------------------------------------------------------
        // 3. A persisted `Signed` → after reopen the complete strict CHECKED
        //    retained-use composition retrieves the EXACT bytes, verifies,
        //    confirms authorization and sinks once, with NO additional signer and
        //    an unchanged durable-position count.
        // ------------------------------------------------------------------
        #[test]
        fn reopen_persisted_signed_checked_retained_exact_no_signer() {
            let safety_dir = tempfile::tempdir().unwrap();
            let journal_dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (pv, sk) = make_real_signing_authority();

            // ---- A: produce a genuine Signed result via the protected real route. ----
            let (owner_a, engine_a, a_decided, p1_a, lim, _rev_a) =
                capture_multi_with_suite(safety_dir.path(), &ctx, MODEL_SUITE_U16);
            let a_base_vote = a_decided.vote().clone();
            let store_a = reopen_open_journal_store(journal_dir.path());
            let journal_a =
                reopen_assoc_journal_init(&owner_a, store_a.clone() as Arc<dyn SigningJournalStorage>, 1);
            let mut a_snapshot = established_snapshot(&pv);
            let a_inner = real_local_signer(&sk);
            let a_signer = CountingValidatorSigner::new(&a_inner);
            let mut a_sink = RealSignRecordingSink::new();
            let mut a_coord = ModelCoordinationHook::inert();
            match fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner_a, &engine_a, &a_decided, &p1_a, &lim, None, &mut a_snapshot,
                &a_signer, &mut a_sink, &journal_a, &mut a_coord, ReconfirmPerturbation::None,
            ) {
                RealFreshSignOutcome::Published(d) => assert_eq!(d.retirement, RetirementReport::Retired),
                other => panic!("A setup must Publish+Retire, got {other:?}"),
            }
            assert_eq!(a_signer.calls(), 1, "A SETUP signer count");
            assert_eq!(a_sink.calls, 1, "A SETUP sink count");
            // A's independently derived position/binding/preimage under the
            // UNCHANGED fixture authority (captured while A is still live).
            let (a_pos, a_binding) = retained_pos_binding(&pv, &a_base_vote);
            let a_preimage = pv.signing_domain.vote_preimage(&a_base_vote);
            let record_before = store_a
                .get_signing_record(&a_pos.storage_key())
                .expect("read")
                .expect("the Signed record persists");
            assert_eq!(journal_a.reserved_position_count(), 1, "A persisted one Signed position");
            let a_acct = owner_a.backend_for_test().accounting_handle_for_test();

            drop(journal_a);
            drop(store_a);
            drop(a_decided);
            drop(engine_a);
            drop(owner_a);

            // ---- B: reopen; the Signed record survives. ----
            let owner_b = reopen_attach(safety_dir.path(), &ctx);
            let store_b_concrete = reopen_open_journal_store(journal_dir.path());
            let store_b = store_b_concrete.clone() as Arc<dyn SigningJournalStorage>;
            let journal_b = reopen_assoc_journal_open(&owner_b, store_b.clone(), 1);
            assert!(!a_acct.same_ledger(&owner_b.backend_for_test().accounting_handle_for_test()));

            let (mut engine_b, p1_b, l0_block) = engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
            let b_decided = reopen_b_recover_and_capture(&owner_b, &mut engine_b, &p1_b, &lim, l0_block);
            let b_base_vote = b_decided.vote().clone();
            assert_eq!(a_base_vote, b_base_vote, "A and B self-votes correspond (same retained position)");
            // Independently derive B's position/binding/preimage and compare with
            // A's under the unchanged fixture authority: equal Vote, equal preimage,
            // equal position and equal binding — so B's checked retrieval addresses
            // the exact A-era record.
            let (pos, binding) = retained_pos_binding(&pv, &b_base_vote);
            let b_preimage = pv.signing_domain.vote_preimage(&b_base_vote);
            assert_eq!(a_pos, pos, "A and B positions correspond");
            assert_eq!(a_binding, binding, "A and B bindings correspond");
            assert_eq!(a_preimage, b_preimage, "A and B signing preimages correspond");

            // The reopened store still holds the exact Signed bytes.
            let record_after = store_b_concrete
                .get_signing_record(&a_pos.storage_key())
                .expect("read")
                .expect("the Signed record survived the reopen");
            assert_eq!(record_before, record_after, "the persisted Signed bytes survive the reopen");

            // Witness read OUTSIDE/BEFORE the protected retained operation
            // (harness-owned readback allocation, not part of the protected op).
            let witness = reopen_witness_from_store(&store_b, &pos, &binding);
            let probe = std::rc::Rc::new(RetainedSliceProbe::new(witness));
            let guard = install_retained_slice_probe(probe.clone());

            let mut snapshot = established_snapshot(&pv);
            let mut sink = RetainedUseRecordingSink::new();
            let mut coord = ModelCoordinationHook::inert();
            let ledgers_before = snapshot_ledgers(&owner_b);
            let prov_before = pin_provenance_now(&owner_b, &b_decided);

            // The checked retained-use route takes NO `signer` capability at all:
            // its signature carries no signer parameter, so it structurally CANNOT
            // invoke one. Its absence of additional signing is therefore established
            // by the route's type, corroborated below by the executed exact-byte
            // witness and single scalar sink; A's genuine setup signing (1 signer /
            // 1 sink) is reported separately above.
            let outcome = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                &owner_b, &engine_b, &b_decided, &p1_b, &lim, None, &mut snapshot,
                &mut sink, &journal_b, &mut coord, ReconfirmPerturbation::None,
            );
            drop(guard);
            let diag = match outcome {
                ModelRetainedUseOutcome::Consumed(d) => d,
                other => panic!("expected Consumed on the checked route, got {other:?}"),
            };
            assert_eq!(diag.sig_len as usize, 2420, "consumed the full retained slice");
            assert_eq!(sink.calls, 1, "exactly one scalar sink consumption");
            assert_eq!(probe.invocations(), 1, "the probe ran exactly once");
            assert_eq!(probe.last_len(), Some(2420), "observed length is 2420");
            assert_eq!(probe.last_matched(), Some(true), "the retrieved slice matches the witness byte-for-byte");
            // The byte-for-byte witness match proves the EXACT retained bytes were
            // returned unchanged; the retained-byte length equals A's stored 2420.
            assert_eq!(journal_b.reserved_position_count(), 1, "the durable-position count is unchanged");
            assert_cleanup_preserved(
                &owner_b, &b_decided, &b_base_vote, ledgers_before, prov_before,
                "the successful reopened checked retained consumption",
            );
        }

        // ------------------------------------------------------------------
        // 4. A genuine A-issued O3 proof presented to B's O5 → the existing
        //    foreign-incarnation refusal; durable safety bytes/revision unchanged;
        //    recovery still required. A genuine B proof then succeeds. The A
        //    proof's holder stays charged to A, never B.
        // ------------------------------------------------------------------
        #[test]
        fn reopen_a_era_capability_refused_at_o5() {
            let safety_dir = tempfile::tempdir().unwrap();
            let journal_dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (_pv, _sk) = make_real_signing_authority();

            let (owner_a, engine_a, a_decided, p1_a, lim, _rev_a) =
                capture_multi_with_suite(safety_dir.path(), &ctx, MODEL_SUITE_U16);
            let store_a = reopen_open_journal_store(journal_dir.path());
            let journal_a =
                reopen_assoc_journal_init(&owner_a, store_a.clone() as Arc<dyn SigningJournalStorage>, 1);
            // A genuine A-era O3 proof, retained across the close.
            let a_proof = owner_a
                .read_validate(None::<&FixtureCommittedHistory>)
                .expect("A O3 proof");
            let a_acct = owner_a.backend_for_test().accounting_handle_for_test();

            drop(journal_a);
            drop(store_a);
            drop(a_decided);
            drop(engine_a);
            drop(owner_a);

            // After A's database closes, only the retained A proof's holder keeps A
            // charged; this is A's post-close standing baseline (NOT on B), sampled
            // on BOTH of A's ledgers independently (operational partition via the
            // retained operational handle, aggregate via its shared authority).
            let a_op_after_close = a_acct.current();
            let a_agg_after_close = a_acct.aggregate().current();
            assert!(a_op_after_close > 0, "A's retained proof holder keeps A's operational ledger charged");
            assert!(a_agg_after_close > 0, "A's retained proof holder keeps A's aggregate ledger charged");

            let owner_b = reopen_attach(safety_dir.path(), &ctx);
            let store_b = reopen_open_journal_store(journal_dir.path());
            let _journal_b =
                reopen_assoc_journal_open(&owner_b, store_b.clone() as Arc<dyn SigningJournalStorage>, 1);
            let b_acct = owner_b.backend_for_test().accounting_handle_for_test();
            assert!(!a_acct.same_ledger(&b_acct), "A and B are independent accounting authorities");

            let meta_before = owner_b.open().expect("B O2");
            assert!(owner_b.recovery_required(), "B requires recovery");
            // Durable safety-record BYTES and authoritative revision captured BEFORE
            // the refusal (revision equality alone is insufficient). A transient B
            // O3 proof reads them; it is dropped before sampling B's standing ledger.
            let durable_pre = owner_b.read_validate(None::<&FixtureCommittedHistory>).expect("B O3 pre");
            let bytes_before = durable_pre.encoded().to_vec();
            let rev_before = durable_pre.publication_revision();
            drop(durable_pre);
            // B's standing baseline, proof-free, sampled on BOTH ledgers.
            let b_op_before = owner_b.backend_for_test().accounting_current();
            let b_agg_before = b_acct.aggregate().current();
            let b_op_cap = owner_b.backend_for_test().accounting_cap();
            let b_agg_cap = owner_b.backend_for_test().accounting_aggregate_cap();

            // Present the FOREIGN A proof to B's O5: refused by the existing
            // foreign-backend-incarnation SEMANTIC refusal — discriminated from a
            // context mismatch, an admission failure, or any other pre-write refusal.
            match owner_b.reacknowledge(&a_proof) {
                PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(
                    SemanticRefusalDetail::Static(msg),
                )) => {
                    assert!(
                        msg.contains("recovery capability for this backend incarnation"),
                        "the refusal is the foreign-incarnation O5 semantic refusal, got: {msg}"
                    );
                    assert!(
                        !msg.contains("different pinned context"),
                        "NOT the context-mismatch semantic refusal"
                    );
                }
                other => panic!(
                    "B O5 must refuse the foreign A proof with the foreign-incarnation semantic refusal, got {other:?}"
                ),
            }
            assert!(owner_b.recovery_required(), "the foreign-proof refusal leaves recovery required");

            // IMMEDIATELY after the refusal, BEFORE any O3/O2 durable inspection:
            // B gained NO standing charge (both ledgers), B's ceilings are unchanged,
            // and A's holder charge stayed on A (both ledgers). Sampling here isolates
            // the refusal's (non-)effect from the transient allocations the durable
            // inspection below would introduce.
            assert_eq!(owner_b.backend_for_test().accounting_current(), b_op_before, "refused A proof added no operational charge to B");
            assert_eq!(b_acct.aggregate().current(), b_agg_before, "refused A proof added no aggregate charge to B");
            assert_eq!(owner_b.backend_for_test().accounting_cap(), b_op_cap, "B operational ceiling unchanged");
            assert_eq!(owner_b.backend_for_test().accounting_aggregate_cap(), b_agg_cap, "B aggregate ceiling unchanged");
            assert_eq!(a_acct.current(), a_op_after_close, "A's operational holder charge stayed on A through the refusal");
            assert_eq!(a_acct.aggregate().current(), a_agg_after_close, "A's aggregate holder charge stayed on A through the refusal");

            // Durable safety bytes AND revision are unchanged by the refusal
            // (a separate comparison; revision equality alone is insufficient, so the
            // full encoded bytes are compared).
            let durable_post = owner_b.read_validate(None::<&FixtureCommittedHistory>).expect("B O3 post");
            assert_eq!(durable_post.encoded(), bytes_before.as_slice(), "durable safety-record bytes unchanged");
            assert_eq!(durable_post.publication_revision(), rev_before, "authoritative revision unchanged");
            let meta_after = owner_b.open().expect("B O2 after refusal");
            assert_eq!(meta_before.current_revision, meta_after.current_revision, "O2 current revision unchanged");
            drop(durable_post);

            // A genuine B-issued proof then succeeds (the retained control).
            let (mut engine_b, p1_b, l0_block) = engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
            let b_decided = reopen_b_recover_and_capture(&owner_b, &mut engine_b, &p1_b, &lim, l0_block);
            let _ = (&b_decided, &p1_a);

            // Snapshot BOTH B ledgers immediately before dropping A's proof.
            let b_op_pre_drop = owner_b.backend_for_test().accounting_current();
            let b_agg_pre_drop = owner_b.backend_for_test().accounting_aggregate_current();

            // The retained A proof is now the ONLY remaining charged A object (A's
            // envelope was dropped before the reopen), so dropping it releases A's
            // holder charge EXACTLY to zero on BOTH of A's ledgers.
            drop(a_proof);
            assert_eq!(a_acct.current(), 0, "dropping the last charged A object zeroes A's operational ledger");
            assert_eq!(a_acct.aggregate().current(), 0, "dropping the last charged A object zeroes A's aggregate ledger");
            // Dropping A's proof never perturbs B (both ledgers unchanged).
            assert_eq!(owner_b.backend_for_test().accounting_current(), b_op_pre_drop, "B's operational ledger is unchanged by dropping A's proof");
            assert_eq!(owner_b.backend_for_test().accounting_aggregate_current(), b_agg_pre_drop, "B's aggregate ledger is unchanged by dropping A's proof");
        }

        // ------------------------------------------------------------------
        // 5. A's pin presented under B: Missing before B installs its registry,
        //    Foreign after legitimate B capture. Protected fresh AND checked
        //    attempts with the unchanged A envelope are observation-refused in
        //    both phases; A's own provenance is preserved via the retained A
        //    registry observer (NOT B's rejecting lookup).
        // ------------------------------------------------------------------
        #[test]
        fn reopen_a_era_pin_missing_then_foreign() {
            let safety_dir = tempfile::tempdir().unwrap();
            let journal_dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (pv, sk) = make_real_signing_authority();

            let (owner_a, engine_a, a_decided, p1_a, lim, _rev_a) =
                capture_multi_with_suite(safety_dir.path(), &ctx, MODEL_SUITE_U16);
            let store_a = reopen_open_journal_store(journal_dir.path());
            let journal_a =
                reopen_assoc_journal_init(&owner_a, store_a.clone() as Arc<dyn SigningJournalStorage>, 1);
            // Retain the A registry observer BEFORE closing A (A-provenance preservation).
            let a_registry = {
                let g = owner_a.backend_for_test().lock_domain();
                owner_a
                    .backend_for_test()
                    .prepared_registry_installed(&g)
                    .expect("A registry installed after capture")
            };
            let a_handle = a_decided.payload().pin().handle();
            // Snapshot A's COMPLETE PreparedProvenance BEFORE closing A, through the
            // retained A registry observer. This is the before/after preservation
            // reference (NOT a comparison with B's identity).
            let a_prov_before = a_registry
                .lock()
                .expect("A registry lock")
                .provenance_by_handle(a_handle)
                .expect("A's registry resolves A's pin provenance before close");
            let a_prov_before_vote = a_decided.vote().clone();
            let a_acct = owner_a.backend_for_test().accounting_handle_for_test();

            drop(journal_a);
            drop(store_a);
            drop(engine_a);
            drop(owner_a);
            // a_decided AND a_registry are RETAINED (unchanged A envelope + A's own
            // registry observer) and keep A's ledgers charged after close; sample
            // A's standing baseline on BOTH ledgers independently.
            let a_op_live = a_acct.current();
            let a_agg_live = a_acct.aggregate().current();
            assert!(a_op_live > 0 && a_agg_live > 0, "retained A objects keep both A ledgers charged after close");

            // Test-local A-preservation check: at EACH refusal, A's COMPLETE
            // provenance (through A's OWN retained registry observer, not B's
            // rejecting lookup), A's COMPLETE borrowed Vote, and BOTH of A's ledgers
            // are unchanged before the next operation.
            let check_a = |label: &str| {
                let now = a_registry
                    .lock()
                    .expect("A registry lock")
                    .provenance_by_handle(a_handle)
                    .expect("A's own registry still resolves A's pin provenance");
                assert_eq!(now, a_prov_before, "{label}: A's complete provenance preserved through A's registry");
                assert_eq!(a_decided.vote(), &a_prov_before_vote, "{label}: A's complete borrowed Vote is unchanged");
                assert_eq!(a_acct.current(), a_op_live, "{label}: A's operational charge stays on A");
                assert_eq!(a_acct.aggregate().current(), a_agg_live, "{label}: A's aggregate charge stays on A");
            };

            let owner_b = reopen_attach(safety_dir.path(), &ctx);
            let store_b = reopen_open_journal_store(journal_dir.path());
            let journal_b =
                reopen_assoc_journal_open(&owner_b, store_b.clone() as Arc<dyn SigningJournalStorage>, 1);
            assert!(!a_acct.same_ledger(&owner_b.backend_for_test().accounting_handle_for_test()));

            // Reconstruct the engine and complete B recovery (O2/O3/O5) only; B has
            // NOT captured yet, so no registry is installed.
            let meta = owner_b.open().expect("B O2");
            let rev = meta.current_revision;
            let recovery = owner_b.read_validate(None::<&FixtureCommittedHistory>).expect("B O3");
            assert!(matches!(owner_b.reacknowledge(&recovery), PublishResult::DurableAcknowledged { .. }));
            assert!(!owner_b.recovery_required(), "B O5 cleared recovery");
            drop(recovery);

            let (mut engine_b, p1_b, _l0_block) = engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
            let mut snapshot = established_snapshot(&pv);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);

            // PHASE 1 — no registry: A pin is Missing; each protected attempt is
            // checked SEPARATELY, the fresh refusal before the retained route.
            assert!(
                matches!(pin_provenance_try(&owner_b, &a_decided), Err(ProvenanceRefusal::Missing)),
                "before B capture the A pin has no installed registry (Missing)"
            );
            let ledgers_p1 = snapshot_ledgers(&owner_b);
            {
                let mut fsink = RealSignRecordingSink::new();
                let mut fcoord = ModelCoordinationHook::inert();
                let fresh = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    &owner_b, &engine_b, &a_decided, &p1_a, &lim, None, &mut snapshot,
                    &signer, &mut fsink, &journal_b, &mut fcoord, ReconfirmPerturbation::None,
                );
                assert_eq!(fresh, RealFreshSignOutcome::ObservationRefused, "Missing-phase fresh attempt is observation-refused");
                assert_eq!(fsink.calls, 0);
            }
            // Fresh refusal restored B's ledgers and mutated no durable state.
            assert_eq!(snapshot_ledgers(&owner_b), ledgers_p1, "the Missing-phase fresh attempt restores B's ledgers");
            assert_eq!(journal_b.reserved_position_count(), 0, "Missing-phase fresh attempt creates no durable position");
            check_a("Missing-phase fresh refusal");
            {
                let mut rsink = RetainedUseRecordingSink::new();
                let mut rcoord = ModelCoordinationHook::inert();
                let retained = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner_b, &engine_b, &a_decided, &p1_a, &lim, None, &mut snapshot,
                    &mut rsink, &journal_b, &mut rcoord, ReconfirmPerturbation::None,
                );
                assert_eq!(retained, ModelRetainedUseOutcome::ObservationRefused, "Missing-phase checked attempt is observation-refused");
                assert_eq!(rsink.calls, 0);
            }
            assert_eq!(snapshot_ledgers(&owner_b), ledgers_p1, "the Missing-phase checked attempt restores B's ledgers");
            assert_eq!(signer.calls(), 0, "zero signing during the Missing phase");
            assert_eq!(journal_b.reserved_position_count(), 0, "no durable position created in the Missing phase");
            check_a("Missing-phase checked refusal");

            // Legitimate B capture installs B's registry.
            let cap_proof = owner_b.read_validate(None::<&FixtureCommittedHistory>).expect("B O3 for capture");
            let b_decided = match owner_b.decide_and_capture_owned(
                &mut engine_b, ValidatorId::new(2), &p1_b, &lim, rev, cap_proof,
            ) {
                OwnedDecisionOutcome::Decided(dv) => dv,
                other => panic!("B capture must Decide, got {other:?}"),
            };
            let _ = &b_decided;

            // PHASE 2 — B registry installed: the A pin is Foreign; each attempt is
            // checked SEPARATELY, the fresh refusal before the retained route.
            assert!(
                matches!(pin_provenance_try(&owner_b, &a_decided), Err(ProvenanceRefusal::Foreign)),
                "after B capture the A pin is classified Foreign by the incarnation check"
            );
            let ledgers_p2 = snapshot_ledgers(&owner_b);
            {
                let mut fsink = RealSignRecordingSink::new();
                let mut fcoord = ModelCoordinationHook::inert();
                let fresh = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    &owner_b, &engine_b, &a_decided, &p1_a, &lim, None, &mut snapshot,
                    &signer, &mut fsink, &journal_b, &mut fcoord, ReconfirmPerturbation::None,
                );
                assert_eq!(fresh, RealFreshSignOutcome::ObservationRefused, "Foreign-phase fresh attempt is observation-refused");
                assert_eq!(fsink.calls, 0);
            }
            assert_eq!(snapshot_ledgers(&owner_b), ledgers_p2, "the Foreign-phase fresh attempt restores B's ledgers");
            check_a("Foreign-phase fresh refusal");
            {
                let mut rsink = RetainedUseRecordingSink::new();
                let mut rcoord = ModelCoordinationHook::inert();
                let retained = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner_b, &engine_b, &a_decided, &p1_a, &lim, None, &mut snapshot,
                    &mut rsink, &journal_b, &mut rcoord, ReconfirmPerturbation::None,
                );
                assert_eq!(retained, ModelRetainedUseOutcome::ObservationRefused, "Foreign-phase checked attempt is observation-refused");
                assert_eq!(rsink.calls, 0);
            }
            assert_eq!(snapshot_ledgers(&owner_b), ledgers_p2, "the Foreign-phase checked attempt restores B's ledgers");
            assert_eq!(signer.calls(), 0, "zero signing across both phases");
            assert_eq!(journal_b.reserved_position_count(), 0, "no durable position created across both phases");
            check_a("Foreign-phase checked refusal");

            // A-provenance PRESERVATION is a BEFORE/AFTER check through the retained
            // A registry observer (asserted at EACH refusal above via `check_a`): the
            // COMPLETE PreparedProvenance A resolved before close is identical
            // afterwards. This is NOT a comparison with B's identity (B's lookup of
            // the A pin is Foreign, asserted above).

            // Release the retained A owners: A's unchanged envelope (`a_decided`,
            // whose pin holds one registry Arc) AND A's registry observer
            // (`a_registry`, the other Arc). Only once BOTH drop does the registry's
            // reservation release, zeroing A's ledgers — observed through the
            // independent `a_acct` handle. No separately invented pin is dropped.
            drop(a_decided);
            drop(a_registry);
            assert_eq!(a_acct.current(), 0, "releasing the retained A objects zeroes A's operational ledger");
            assert_eq!(a_acct.aggregate().current(), 0, "releasing the retained A objects zeroes A's aggregate ledger");
        }

        // ------------------------------------------------------------------
        // 6. A genuine persisted Signed fixture; BEFORE a successful B O5 both
        //    protected attempts are observation-refused (recovery), with zero
        //    signer/sink and an unchanged stored result/count. O2/O3 do not clear
        //    recovery; O5 itself is permitted during recovery.
        // ------------------------------------------------------------------
        #[test]
        fn reopen_use_before_o5_refused() {
            let safety_dir = tempfile::tempdir().unwrap();
            let journal_dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (pv, sk) = make_real_signing_authority();

            let (owner_a, engine_a, a_decided, p1_a, lim, _rev_a) =
                capture_multi_with_suite(safety_dir.path(), &ctx, MODEL_SUITE_U16);
            let a_base_vote = a_decided.vote().clone();
            let store_a = reopen_open_journal_store(journal_dir.path());
            let journal_a =
                reopen_assoc_journal_init(&owner_a, store_a.clone() as Arc<dyn SigningJournalStorage>, 1);
            let mut a_snapshot = established_snapshot(&pv);
            let a_inner = real_local_signer(&sk);
            let a_signer = CountingValidatorSigner::new(&a_inner);
            let mut a_sink = RealSignRecordingSink::new();
            let mut a_coord = ModelCoordinationHook::inert();
            match fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner_a, &engine_a, &a_decided, &p1_a, &lim, None, &mut a_snapshot,
                &a_signer, &mut a_sink, &journal_a, &mut a_coord, ReconfirmPerturbation::None,
            ) {
                RealFreshSignOutcome::Published(d) => assert_eq!(d.retirement, RetirementReport::Retired),
                other => panic!("A setup must Publish+Retire, got {other:?}"),
            }
            assert_eq!(a_signer.calls(), 1, "A SETUP signer");
            assert_eq!(a_sink.calls, 1, "A SETUP sink");
            let (a_pos, _a_binding) = retained_pos_binding(&pv, &a_base_vote);
            let record_before = store_a
                .get_signing_record(&a_pos.storage_key())
                .expect("read")
                .expect("the Signed record persists");

            // Retain A's registry observer and snapshot A's COMPLETE provenance +
            // Vote BEFORE closing A (the A-provenance preservation reference, through
            // A's OWN registry — never B's rejecting lookup).
            let a_registry = {
                let g = owner_a.backend_for_test().lock_domain();
                owner_a
                    .backend_for_test()
                    .prepared_registry_installed(&g)
                    .expect("A registry installed after capture")
            };
            let a_handle = a_decided.payload().pin().handle();
            let a_prov_before = a_registry
                .lock()
                .expect("A registry lock")
                .provenance_by_handle(a_handle)
                .expect("A's registry resolves A's pin provenance before close");
            let a_acct = owner_a.backend_for_test().accounting_handle_for_test();

            drop(journal_a);
            drop(store_a);
            drop(engine_a);
            drop(owner_a);
            // a_decided + a_registry retained for the pre-O5 attempts; sample A's
            // standing baseline on BOTH ledgers independently after the close.
            let a_op_live = a_acct.current();
            let a_agg_live = a_acct.aggregate().current();
            assert!(a_op_live > 0 && a_agg_live > 0, "retained A objects keep both A ledgers charged after close");
            // Test-local A-preservation check used at each pre-O5 refusal.
            let check_a = |label: &str| {
                let now = a_registry
                    .lock()
                    .expect("A registry lock")
                    .provenance_by_handle(a_handle)
                    .expect("A's own registry still resolves A's pin provenance");
                assert_eq!(now, a_prov_before, "{label}: A's complete provenance preserved through A's registry");
                assert_eq!(a_decided.vote(), &a_base_vote, "{label}: A's complete borrowed Vote is unchanged");
                assert_eq!(a_acct.current(), a_op_live, "{label}: A's operational charge stays on A");
                assert_eq!(a_acct.aggregate().current(), a_agg_live, "{label}: A's aggregate charge stays on A");
            };

            let owner_b = reopen_attach(safety_dir.path(), &ctx);
            let store_b_concrete = reopen_open_journal_store(journal_dir.path());
            let store_b = store_b_concrete.clone() as Arc<dyn SigningJournalStorage>;
            let journal_b = reopen_assoc_journal_open(&owner_b, store_b.clone(), 1);

            // O2 and O3 do NOT clear recovery.
            let meta = owner_b.open().expect("B O2");
            assert!(owner_b.recovery_required(), "O2 does not clear recovery");
            let op_free = owner_b.backend_for_test().accounting_current();
            let agg_free = owner_b.backend_for_test().accounting_aggregate_current();
            let recovery = owner_b.read_validate(None::<&FixtureCommittedHistory>).expect("B O3");
            assert!(owner_b.recovery_required(), "O3 does not clear recovery");
            // Proof-held standing baseline after O3.
            let op_held = owner_b.backend_for_test().accounting_current();
            let agg_held = owner_b.backend_for_test().accounting_aggregate_current();
            assert!(op_held > op_free, "holding B's O3 proof raises the operational standing charge");
            assert!(agg_held > agg_free, "holding B's O3 proof raises the aggregate standing charge");

            let (mut engine_b, p1_b, _l0) = engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
            let _ = (&p1_b,);
            let mut snapshot = established_snapshot(&pv);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);

            let ledgers_before = snapshot_ledgers(&owner_b);
            // Fresh refusal checked and asserted BEFORE the retained route.
            let mut fsink = RealSignRecordingSink::new();
            let mut fcoord = ModelCoordinationHook::inert();
            let fresh = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner_b, &engine_b, &a_decided, &p1_a, &lim, None, &mut snapshot,
                &signer, &mut fsink, &journal_b, &mut fcoord, ReconfirmPerturbation::None,
            );
            assert_eq!(fresh, RealFreshSignOutcome::ObservationRefused, "pre-O5 fresh use is recovery-refused");
            assert_eq!(fsink.calls, 0);
            assert_eq!(snapshot_ledgers(&owner_b), ledgers_before, "the pre-O5 fresh attempt restores B's ledgers");
            let record_mid_fresh = store_b_concrete
                .get_signing_record(&a_pos.storage_key())
                .expect("read")
                .expect("the Signed record is unchanged");
            assert_eq!(record_before, record_mid_fresh, "the stored Signed result is unchanged by the pre-O5 fresh attempt");
            assert_eq!(journal_b.reserved_position_count(), 1, "durable-position count unchanged by the pre-O5 fresh attempt");
            check_a("pre-O5 fresh refusal");

            // Retained refusal checked and asserted SEPARATELY.
            let mut rsink = RetainedUseRecordingSink::new();
            let mut rcoord = ModelCoordinationHook::inert();
            let retained = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                &owner_b, &engine_b, &a_decided, &p1_a, &lim, None, &mut snapshot,
                &mut rsink, &journal_b, &mut rcoord, ReconfirmPerturbation::None,
            );
            assert_eq!(retained, ModelRetainedUseOutcome::ObservationRefused, "pre-O5 checked use is recovery-refused");
            assert_eq!(rsink.calls, 0);
            assert_eq!(signer.calls(), 0, "zero B signing before O5");
            assert_eq!(snapshot_ledgers(&owner_b), ledgers_before, "the pre-O5 checked attempt restores B's ledgers");
            let record_mid = store_b_concrete
                .get_signing_record(&a_pos.storage_key())
                .expect("read")
                .expect("the Signed record is unchanged");
            assert_eq!(record_before, record_mid, "the stored Signed result is unchanged by pre-O5 attempts");
            assert_eq!(journal_b.reserved_position_count(), 1, "the durable-position count is unchanged");
            check_a("pre-O5 checked refusal");

            // O5 itself is permitted during recovery.
            assert!(matches!(owner_b.reacknowledge(&recovery), PublishResult::DurableAcknowledged { .. }), "O5 is permitted during recovery");
            assert!(!owner_b.recovery_required(), "the successful O5 clears recovery");
            // Proof-held restoration immediately after the successful O5 (proof live).
            assert_eq!(owner_b.backend_for_test().accounting_current(), op_held, "successful O5 restores exactly to the proof-held operational baseline");
            assert_eq!(owner_b.backend_for_test().accounting_aggregate_current(), agg_held, "successful O5 restores exactly to the proof-held aggregate baseline");
            drop(recovery);
            // Proof-free restoration after dropping the recovery proof.
            assert_eq!(owner_b.backend_for_test().accounting_current(), op_free, "dropping the recovery proof restores the proof-free operational baseline");
            assert_eq!(owner_b.backend_for_test().accounting_aggregate_current(), agg_free, "dropping the recovery proof restores the proof-free aggregate baseline");
            let _ = (&mut engine_b, meta);
            // Release the retained A owners (unchanged envelope + A's registry
            // observer, the two Arcs to A's registry) and assert BOTH of A's ledgers
            // reach zero through the independent handle. No separately invented pin.
            drop(a_decided);
            drop(a_registry);
            assert_eq!(a_acct.current(), 0, "releasing the retained A objects zeroes A's operational ledger");
            assert_eq!(a_acct.aggregate().current(), 0, "releasing the retained A objects zeroes A's aggregate ledger");
        }

        // ------------------------------------------------------------------
        // 7. Successful B O5 + legitimate B capture, THEN a genuine engine/durable
        //    disagreement (the engine lock is advanced to L1 by peer votes while
        //    the acknowledged durable restriction stays L0). Dependent use is
        //    observation-refused (EngineDurableDisagreement) — DISTINCT from the
        //    strict lifecycle-equality refusal of a consistent advance.
        // ------------------------------------------------------------------
        #[test]
        fn reopen_o5_success_then_engine_durable_disagreement_refused() {
            let safety_dir = tempfile::tempdir().unwrap();
            let journal_dir = tempfile::tempdir().unwrap();
            let ctx = retained_ctx(4);
            let (pv, sk) = make_real_signing_authority();

            let (owner_a, engine_a, a_decided, _p1_a, lim, _rev_a) =
                capture_multi_with_suite(safety_dir.path(), &ctx, MODEL_SUITE_U16);
            let store_a = reopen_open_journal_store(journal_dir.path());
            let journal_a =
                reopen_assoc_journal_init(&owner_a, store_a.clone() as Arc<dyn SigningJournalStorage>, 1);

            drop(journal_a);
            drop(store_a);
            drop(a_decided);
            drop(engine_a);
            drop(owner_a);

            let owner_b = reopen_attach(safety_dir.path(), &ctx);
            let store_b = reopen_open_journal_store(journal_dir.path());
            let journal_b =
                reopen_assoc_journal_open(&owner_b, store_b.clone() as Arc<dyn SigningJournalStorage>, 1);

            let (mut engine_b, p1_b, l0_block) = engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
            let b_decided = reopen_b_recover_and_capture(&owner_b, &mut engine_b, &p1_b, &lim, l0_block);
            let b_base_vote = b_decided.vote().clone();

            // Advance the ENGINE lock L0 -> L1 via peer votes; leave durable at L0.
            let l1_block = derive_block_id_local(2, 1, &l0_block);
            let _ = engine_b.on_vote_event(ValidatorId::new(2), &logical_vote(1, l1_block, 2));
            let _ = engine_b.on_vote_event(ValidatorId::new(3), &logical_vote(1, l1_block, 3));
            let lk = engine_b.locked_qc().expect("engine lock present");
            assert_eq!(lk.block_id, l1_block, "the engine lock advanced to L1");
            assert_eq!(lk.view, 1, "the engine lock view is L1");

            // The durable restriction is still L0 and recovery is clear.
            assert!(!owner_b.recovery_required(), "recovery is clear after the successful O5");
            let durable_proof = owner_b.read_validate(None::<&FixtureCommittedHistory>).expect("B O3");
            let durable = GenerationIdentity::from_retained(durable_proof.retained())
                .expect("durable Locked identity");
            assert_eq!(durable.lock_block_id, l0_block, "the acknowledged durable restriction is still L0");
            assert_ne!(durable.lock_block_id, lk.block_id, "engine L1 and durable L0 DISAGREE");
            drop(durable_proof);

            let mut snapshot = established_snapshot(&pv);
            let inner = real_local_signer(&sk);
            let signer = CountingValidatorSigner::new(&inner);
            let ledgers_before = snapshot_ledgers(&owner_b);
            let prov_before = pin_provenance_now(&owner_b, &b_decided);

            let mut fsink = RealSignRecordingSink::new();
            let mut fcoord = ModelCoordinationHook::inert();
            let fresh = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                &owner_b, &engine_b, &b_decided, &p1_b, &lim, None, &mut snapshot,
                &signer, &mut fsink, &journal_b, &mut fcoord, ReconfirmPerturbation::None,
            );
            assert_eq!(
                fresh,
                RealFreshSignOutcome::ObservationRefused,
                "engine/durable disagreement is observation-refused (not the lifecycle-equality refusal)"
            );
            assert_eq!(fsink.calls, 0);
            // Fresh refusal: complete cleanup and durable non-mutation BEFORE the
            // retained route.
            assert_cleanup_preserved(
                &owner_b, &b_decided, &b_base_vote, ledgers_before, prov_before,
                "the engine/durable disagreement fresh refusal",
            );
            assert_eq!(journal_b.reserved_position_count(), 0, "fresh refusal creates no durable position");

            let mut rsink = RetainedUseRecordingSink::new();
            let mut rcoord = ModelCoordinationHook::inert();
            let retained = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                &owner_b, &engine_b, &b_decided, &p1_b, &lim, None, &mut snapshot,
                &mut rsink, &journal_b, &mut rcoord, ReconfirmPerturbation::None,
            );
            assert_eq!(retained, ModelRetainedUseOutcome::ObservationRefused, "disagreement refuses dependent retained use");
            assert_eq!(rsink.calls, 0);
            assert_eq!(signer.calls(), 0, "zero signing under the disagreement");
            assert_eq!(journal_b.reserved_position_count(), 0, "the durable-position count is unchanged");
            // Retained refusal: complete cleanup, checked SEPARATELY.
            assert_cleanup_preserved(
                &owner_b, &b_decided, &b_base_vote, ledgers_before, prov_before,
                "the engine/durable disagreement retained refusal",
            );
        }

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
                // §2 baselines taken AFTER the acknowledged lifecycle advance.
                let ledgers_before = snapshot_ledgers(&owner);
                let prov_before = pin_provenance_now(&owner, &decided);

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

                // §2 — independent operational AND aggregate cleanup on the retained
                // confirm refusal: both ledgers restore to the post-advance baseline
                // and the borrowed Vote and original pin provenance are unchanged,
                // even though the stored Signed D10 obligation persists (below).
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the same-authority checked retained confirm refusal",
                );

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
            /// §3/§5 — the FULL checked retained-use recovery sequence. A genuine
            /// acknowledged Signed result is prepared BEFORE a coherent uncertain L1
            /// publication latches recovery. Before O5 (including after successful
            /// O2/O3) the same-authority checked route refuses with zero sink calls,
            /// zero additional signer calls, and the existing Signed result preserved;
            /// a successful O5 then clears recovery, after which a fresh protected
            /// revalidation performs checked retrieval, cryptographic verification,
            /// an EXACT retained-byte witness comparison, and one scalar sink call.
            /// The signer count is unchanged throughout. D10 acknowledgement is kept
            /// separate from the safety-record O5 barrier.
            #[test]
            fn same_authority_checked_retained_recovers_through_o5_barrier() {
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

                // Prepare a genuine acknowledged Signed result at the ORIGINAL state
                // BEFORE inducing the uncertain safety advance.
                genuine_fresh_published(
                    &owner, &engine, &decided, &p1, &lim, &mut snapshot, &journal, &signer,
                );
                assert_eq!(signer.calls(), 1, "exactly one signer call during the seed");

                // Coherent uncertain L1 publication latches recovery (engine ↔ durable
                // AGREE at L1).
                let l1_block = advance_engine_and_uncertain_durable_to_l1(&owner, &mut engine, &ctx);
                assert!(owner.recovery_required(), "uncertain publication latched recovery");

                let (pos, binding) = retained_pos_binding(&pv, &base_vote);
                let record_before = store
                    .get_signing_record(&pos.storage_key())
                    .expect("read")
                    .expect("the acknowledged Signed record persists");

                let ledgers_before = snapshot_ledgers(&owner);
                let prov_before = pin_provenance_now(&owner, &decided);

                // Before O5 — refusal, zero sink, zero additional signer. (No probe
                // installed: the route refuses before any retrieval/verify.)
                {
                    let mut sink = RetainedUseRecordingSink::new();
                    let mut coord = ModelCoordinationHook::inert();
                    let refused =
                        retained_vote_use_checked_same_authority_model::<FixtureCommittedHistory>(
                            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                            &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                        );
                    assert_eq!(
                        refused,
                        ModelRetainedUseOutcome::ObservationRefused,
                        "recovery-required blocks the dependent retained route before recovery"
                    );
                    assert_eq!(sink.calls, 0, "zero sink calls before recovery");
                    assert_eq!(signer.calls(), 1, "zero additional signer calls before recovery");
                }

                // Proof-FREE cleanup: no O3 proof is held yet, so the post-refusal
                // ledgers return to the proof-free baseline; Vote and pin preserved.
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the pre-recovery checked refusal",
                );

                // O2 + O3 succeed but do NOT clear recovery; still refused.
                let _meta = owner.open().expect("O2 open");
                let proof = owner
                    .read_validate::<FixtureCommittedHistory>(None)
                    .expect("O3 read_validate");
                // Establish the surviving stored restriction DIRECTLY from the proof,
                // comparing with the engine's actual lock in this coherent case.
                let (stored_id, stored_rev) = stored_locked_identity(&proof);
                assert_eq!(stored_rev, 2, "surviving successor at the L1 revision");
                assert_eq!(stored_id.lock_block_id, l1_block, "stored lock block id is the L1 successor");
                assert_eq!(stored_id.lock_view, 1, "stored lock view is the L1 view");
                let lk = engine.locked_qc().expect("engine locks L1");
                assert_eq!(
                    (stored_id.lock_block_id, stored_id.lock_view),
                    (lk.block_id, lk.view),
                    "the stored restriction identity equals the engine's actual lock"
                );
                assert!(owner.recovery_required(), "O2/O3 do not clear recovery");
                // Proof-HELD baseline: the live O3 proof raises both ledgers.
                let held = snapshot_ledgers(&owner);
                assert!(
                    held.operational > ledgers_before.operational
                        && held.aggregate > ledgers_before.aggregate,
                    "the held O3 proof raises both ledgers above the proof-free baseline"
                );
                {
                    let mut sink = RetainedUseRecordingSink::new();
                    let mut coord = ModelCoordinationHook::inert();
                    let still =
                        retained_vote_use_checked_same_authority_model::<FixtureCommittedHistory>(
                            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                            &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                        );
                    assert_eq!(still, ModelRetainedUseOutcome::ObservationRefused);
                    assert_eq!(sink.calls, 0);
                    assert_eq!(signer.calls(), 1);
                }

                // Proof-HELD cleanup after the post-O2/O3 refusal, asserted BEFORE
                // the unrelated store inspection below so attribution is unobscured.
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, held, prov_before,
                    "the post-O2/O3 checked refusal (proof held)",
                );
                // The existing Signed result is byte-identical through the refusals.
                let record_mid = store
                    .get_signing_record(&pos.storage_key())
                    .expect("read")
                    .expect("present");
                assert_eq!(record_before, record_mid, "the Signed result is preserved before O5");

                // O5 recovery clears the requirement; destroy the proof before the
                // proof-free comparison.
                match owner.reacknowledge(&proof) {
                    PublishResult::DurableAcknowledged { new_revision } => {
                        assert_eq!(new_revision, 2)
                    }
                    other => panic!("expected O5 DurableAcknowledged, got {other:?}"),
                }
                assert!(!owner.recovery_required(), "O5 clears recovery");
                drop(proof);
                assert_eq!(
                    snapshot_ledgers(&owner),
                    ledgers_before,
                    "dropping the O3 proof restores both ledgers to the proof-free baseline"
                );

                // After O5 + fresh protected revalidation: checked retrieval, crypto
                // verify, exact retained-byte witness comparison, one scalar sink.
                let witness = witness_from_store(&store, &pos, &binding);
                let probe = std::rc::Rc::new(RetainedSliceProbe::new(witness));
                let guard = install_retained_slice_probe(probe.clone());
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
                    other => panic!("expected Consumed after O5 recovery, got {other:?}"),
                };
                assert_eq!(diag.sig_len as usize, 2420, "consumed the 2,420-byte slice");
                assert_eq!(sink.calls, 1, "exactly one scalar sink after recovery");
                assert_eq!(coord.calls, 1, "the coordination point is reached once");
                assert_eq!(probe.invocations(), 1, "the probe ran exactly once after recovery");
                assert_eq!(probe.last_len(), Some(2420));
                assert_eq!(
                    probe.last_matched(),
                    Some(true),
                    "the verified retained slice matches the witness byte-for-byte"
                );
                assert_eq!(
                    signer.calls(),
                    1,
                    "the signer count is unchanged throughout the retained attempts"
                );
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the post-O5 checked retained consumption",
                );
            }

            /// §6 — FAILED recovery controls. For each distinct O5 failure mode
            /// (pre-write refusal, ambiguous write error, uncertain acknowledgement)
            /// the ACTUAL result is asserted, the recovery requirement REMAINS set,
            /// and dependent fresh AND retained use continue to refuse. Clearing the
            /// injected fault then demonstrates a successful O5 retry through the
            /// ordinary API. The exact outcome is used; a write error is NOT taken as
            /// proof that no write occurred.
            #[test]
            fn o5_failed_recovery_variants_keep_recovery_and_block_dependent_use() {
                use crate::safety_record_store::backend::InjectFault;
                for mode in [
                    InjectFault::FailBeforeSubmit,
                    InjectFault::WriteErrors,
                    InjectFault::UncertainAfterWrite,
                ] {
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
                    let l1_block =
                        advance_engine_and_uncertain_durable_to_l1(&owner, &mut engine, &ctx);
                    assert!(owner.recovery_required());

                    // Seeded Signed result + baselines, sampled after the fixture and
                    // the uncertain advance.
                    let (pos, _binding) = retained_pos_binding(&pv, &base_vote);
                    let record_before = store
                        .get_signing_record(&pos.storage_key())
                        .expect("read")
                        .expect("the seeded Signed record persists");
                    let positions_before = journal.reserved_position_count();
                    let ledgers_before = snapshot_ledgers(&owner);
                    let prov_before = pin_provenance_now(&owner, &decided);

                    let proof = owner
                        .read_validate::<FixtureCommittedHistory>(None)
                        .expect("O3 validates the surviving successor");
                    // Establish the surviving stored restriction DIRECTLY from the
                    // proof and compare with the engine's actual coherent L1 lock.
                    let (stored_id, stored_rev) = stored_locked_identity(&proof);
                    assert_eq!(stored_rev, 2, "surviving successor at the L1 revision");
                    assert_eq!(stored_id.lock_block_id, l1_block, "stored lock id is the L1 successor");
                    assert_eq!(stored_id.lock_view, 1, "stored lock view is the L1 view");
                    let lk = engine.locked_qc().expect("engine locks L1");
                    assert_eq!(
                        (stored_id.lock_block_id, stored_id.lock_view),
                        (lk.block_id, lk.view),
                        "the stored identity equals the engine's actual lock"
                    );
                    // Proof-HELD baseline: the live O3 proof raises both ledgers.
                    let held = snapshot_ledgers(&owner);
                    assert!(
                        held.operational > ledgers_before.operational
                            && held.aggregate > ledgers_before.aggregate,
                        "the held O3 proof raises both ledgers above the proof-free baseline"
                    );

                    // Inject the O5 fault and attempt recovery; assert the EXACT result.
                    owner.backend_for_test().set_inject(mode);
                    let failed = owner.reacknowledge(&proof);
                    match mode {
                        InjectFault::FailBeforeSubmit => assert!(
                            matches!(failed, PublishResult::RefusedPreWrite(_)),
                            "pre-write O5 refusal expected, got {failed:?}"
                        ),
                        InjectFault::WriteErrors => assert!(
                            matches!(failed, PublishResult::WriteFailedAmbiguous(_)),
                            "ambiguous O5 write error expected, got {failed:?}"
                        ),
                        InjectFault::UncertainAfterWrite => assert!(
                            matches!(failed, PublishResult::UncertainDurable),
                            "uncertain O5 acknowledgement expected, got {failed:?}"
                        ),
                        _ => unreachable!(),
                    }
                    owner.backend_for_test().set_inject(InjectFault::None);
                    assert!(
                        owner.recovery_required(),
                        "a failed O5 leaves the recovery requirement set (mode {mode:?})"
                    );

                    // Proof-HELD cleanup at the FAILED-O5 boundary, before invoking
                    // either dependent route: both ledgers hold at the proof-held
                    // baseline with the borrowed Vote and original pin preserved.
                    assert_cleanup_preserved(
                        &owner, &decided, &base_vote, held, prov_before,
                        "the failed O5 before any dependent route (proof held)",
                    );

                    // Dependent fresh AND retained use still refuse.
                    let mut fsink = RealSignRecordingSink::new();
                    let mut fcoord = ModelCoordinationHook::inert();
                    let fresh =
                        fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                            &signer, &mut fsink, &journal, &mut fcoord,
                            ReconfirmPerturbation::None,
                        );
                    assert_eq!(fresh, RealFreshSignOutcome::ObservationRefused);
                    assert_eq!(fsink.calls, 0);
                    // Proof-HELD cleanup at the FRESH-REFUSAL boundary, before the
                    // retained route runs.
                    assert_cleanup_preserved(
                        &owner, &decided, &base_vote, held, prov_before,
                        "the fresh refusal before the retained route (proof held)",
                    );
                    let mut rsink = RetainedUseRecordingSink::new();
                    let mut rcoord = ModelCoordinationHook::inert();
                    let retained =
                        retained_vote_use_checked_same_authority_model::<FixtureCommittedHistory>(
                            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                            &mut rsink, &journal, &mut rcoord, ReconfirmPerturbation::None,
                        );
                    assert_eq!(retained, ModelRetainedUseOutcome::ObservationRefused);
                    assert_eq!(rsink.calls, 0);
                    assert_eq!(signer.calls(), 1, "no additional signer call during the failed recovery");

                    // Proof-HELD cleanup across the failed O5 and the blocked dependent
                    // attempts: both ledgers restore to the proof-held baseline and the
                    // borrowed Vote + original pin provenance are unchanged. Asserted
                    // before the seeded-record inspection so attribution is unobscured.
                    assert_cleanup_preserved(
                        &owner, &decided, &base_vote, held, prov_before,
                        "the failed-O5 + blocked dependent use (proof held)",
                    );
                    // The seeded Signed result's bytes and durable-position count are
                    // unchanged across the failed recovery and the blocked attempts.
                    let record_after = store
                        .get_signing_record(&pos.storage_key())
                        .expect("read")
                        .expect("the seeded Signed record still persists");
                    assert_eq!(record_before, record_after, "the seeded Signed bytes are unchanged");
                    assert_eq!(
                        journal.reserved_position_count(),
                        positions_before,
                        "the durable-position count is unchanged across failed recovery"
                    );

                    // Clear the fault and demonstrate a successful O5 RETRY via the
                    // ordinary API.
                    let recovered = owner.reacknowledge(&proof);
                    assert!(
                        matches!(recovered, PublishResult::DurableAcknowledged { new_revision: 2 }),
                        "the ordinary O5 retry succeeds after clearing the fault, got {recovered:?}"
                    );
                    assert!(!owner.recovery_required(), "the successful O5 retry clears recovery");
                    // Proof-HELD cleanup at the SUCCESSFUL-RETRY boundary, with the O3
                    // proof still held, before it is released.
                    assert_cleanup_preserved(
                        &owner, &decided, &base_vote, held, prov_before,
                        "the successful O5 retry before releasing the proof (proof held)",
                    );
                    drop(proof);
                    // Proof-FREE cleanup: dropping the O3 proof restores both ledgers to
                    // the proof-free baseline, with the Vote and original pin preserved.
                    assert_cleanup_preserved(
                        &owner, &decided, &base_vote, ledgers_before, prov_before,
                        "the post-retry proof-free baseline",
                    );
                }
            }

            /// §6 — INSUFFICIENT recovery control: O5 SUCCEEDS (clearing the recovery
            /// requirement) but engine ↔ durable correspondence is WRONG. The engine
            /// is deliberately NOT advanced (it still locks L0) while the durable
            /// restriction advanced to L1. Dependent fresh AND retained use must still
            /// refuse — a cleared recovery requirement ALONE cannot authorize use.
            #[test]
            fn cleared_recovery_with_wrong_engine_correspondence_still_refuses() {
                use crate::safety_record_store::backend::InjectFault;
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

                // Durable advances to L1 under an uncertain write; the engine is NOT
                // advanced and still locks L0.
                let l0_block = derive_block_id_local(1, 0, &[0xFF; 32]);
                let l1_block = derive_block_id_local(2, 1, &l0_block);
                owner
                    .backend_for_test()
                    .set_inject(InjectFault::UncertainAfterWrite);
                let latch = owner.publish_locked(
                    make_locked_qc(&ctx, l1_block, 1, valid_wire_qc(&ctx, l1_block, 1), None)
                        .unwrap(),
                    1,
                    None::<&FixtureCommittedHistory>,
                );
                assert!(matches!(latch, PublishResult::UncertainDurable), "uncertain, got {latch:?}");
                owner.backend_for_test().set_inject(InjectFault::None);
                assert!(owner.recovery_required());
                let lk = engine.locked_qc().expect("engine still locks L0");

                // Proof-free baselines, sampled after the fixture and the uncertain
                // advance (the refusals below occur after the proof is dropped).
                let ledgers_before = snapshot_ledgers(&owner);
                let prov_before = pin_provenance_now(&owner, &decided);

                // O5 succeeds (it concerns only the safety record) and clears recovery.
                let proof = owner
                    .read_validate::<FixtureCommittedHistory>(None)
                    .expect("O3");
                // Establish stored L1 vs engine L0 EXPLICITLY before asserting refusal:
                // the surviving durable restriction is the L1 successor while the engine
                // still locks the L0 predecessor (the wrong-correspondence control).
                let (stored_id, stored_rev) = stored_locked_identity(&proof);
                assert_eq!(stored_rev, 2, "the durable restriction advanced to the L1 revision");
                assert_eq!(stored_id.lock_block_id, l1_block, "stored lock id is the L1 successor");
                assert_eq!(stored_id.lock_view, 1, "stored lock view is the L1 view");
                assert_eq!(lk.block_id, l0_block, "engine still locks the L0 predecessor");
                assert_eq!(lk.view, 0, "the engine lock view is the L0 view");
                assert_ne!(
                    stored_id.lock_block_id, lk.block_id,
                    "stored L1 and engine L0 disagree (the wrong-correspondence control)"
                );
                assert!(matches!(
                    owner.reacknowledge(&proof),
                    PublishResult::DurableAcknowledged { .. }
                ));
                assert!(!owner.recovery_required(), "O5 cleared the recovery requirement");
                drop(proof);

                // Cleared recovery ALONE does not authorize use under wrong engine ↔
                // durable correspondence.
                let mut fsink = RealSignRecordingSink::new();
                let mut fcoord = ModelCoordinationHook::inert();
                let fresh = fresh_vote_sign_real_local_same_authority::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &signer, &mut fsink, &journal, &mut fcoord, ReconfirmPerturbation::None,
                );
                assert_eq!(
                    fresh,
                    RealFreshSignOutcome::ObservationRefused,
                    "a cleared recovery alone cannot authorize use under wrong correspondence"
                );
                assert_eq!(fsink.calls, 0);
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the wrong-correspondence fresh refusal",
                );
                let mut rsink = RetainedUseRecordingSink::new();
                let mut rcoord = ModelCoordinationHook::inert();
                let retained =
                    retained_vote_use_checked_same_authority_model::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                        &mut rsink, &journal, &mut rcoord, ReconfirmPerturbation::None,
                    );
                assert_eq!(retained, ModelRetainedUseOutcome::ObservationRefused);
                assert_eq!(rsink.calls, 0);
                assert_eq!(signer.calls(), 1, "no additional signer call");
                // Both refusals leave both ledgers, the complete borrowed Vote, and the
                // original pin provenance correct (proof-free baseline).
                assert_cleanup_preserved(
                    &owner, &decided, &base_vote, ledgers_before, prov_before,
                    "the wrong-correspondence retained refusal",
                );
            }
        }
        // ===================================================================
        // RUN 422 — ISOLATED post-consumption process-DEATH recovery boundary.
        //
        // A genuine child process drives the actual protected `fresh_vote_sign_
        // real_local` route through its admitted reserve + consume + original-
        // ticket confirmation, and at the FIXED post-consume / pre-sign
        // coordination hook — after exactly one hook invocation and with the live
        // signer/sink observers both zero — writes a complete fixed binary marker
        // and raises SIGABRT (`std::process::abort`) BEFORE the signer executes.
        // The surviving parent reopens BOTH persistent RocksDB backends through
        // their ordinary APIs (never re-initializing over established state),
        // recovers fresh O2/O3/O5 with NO inherited process-local capability, and
        // requires the recovered `Reserved` obligation to refuse the protected
        // fresh route (`ReservePotentiallySigned`, zero signer/sink), with durable
        // non-mutation and surviving-process cleanup to zero.
        //
        // The ONLY test-key material shared across the process boundary is a
        // parent-generated real suite-100 ML-DSA-44 keypair, transported through a
        // parent-owned 0600 fixture file OUTSIDE both databases. No child-era
        // authorization ticket, prepared pin, recovery proof, continuation, or
        // publication capability ever crosses the boundary; every such capability
        // is reconstructed only through its ordinary interface. Process death does
        // NOT run Drop, so NO child ledger restoration is claimed.
        //
        // This whole slice is `#[cfg(all(unix, panic = "unwind"))]`: termination
        // classification uses the Unix `ExitStatusExt::signal()` and the POSIX-
        // fixed SIGABRT value (6), and a panic must NOT satisfy the termination
        // predicate (only SIGABRT together with a complete invocation-matched
        // marker is accepted). An unsupported panic configuration is rejected by
        // absence of this evidence path.
        // ===================================================================
        #[cfg(all(unix, panic = "unwind"))]
        mod postconsume_process_death {
            use super::*;
            use std::io::{Read as _, Write as _};
            use std::os::unix::fs::OpenOptionsExt as _;
            use std::os::unix::process::ExitStatusExt as _;
            use std::time::{Duration, Instant};

            use crate::signing_reservation_journal::{SigningDecisionRecord, SigningRecordStage};
            use crate::storage::RocksDbConsensusStorage;

            // ---- fixed fixture-transport format (parent-owned 0600 keyfile) ----
            const FIXTURE_MAGIC: [u8; 4] = *b"R422";
            const FIXTURE_VERSION: u16 = 1;
            const FIXTURE_SUITE: u16 = MODEL_SUITE_U16; // 100
            const FIXTURE_VALIDATOR: u32 = SIGNER_VID as u32; // 1
            const PK_LEN: usize = qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE; // 1312
            const SK_LEN: usize = qbind_crypto::ml_dsa44::ML_DSA_44_SECRET_KEY_SIZE; // 2560
            const FIXTURE_LEN: usize =
                4 + 2 + 2 + 4 + 2 + PK_LEN + 2 + SK_LEN; // == 3888

            // ---- fixed boundary-marker format ----
            const MARKER_MAGIC: [u8; 4] = *b"R4M2";
            const MARKER_VERSION: u16 = 1;
            // Explicit post-consume / pre-sign phase tag (route step 15).
            const PHASE_POST_CONSUME_PRE_SIGN: u8 = 0x15;
            const NONCE_LEN: usize = 16;
            // The UNSIGNED Vote wire encoding length (msg_type+version+chain_id+
            // epoch+height+round+step+block_id+validator_index+suite_id+sig_len+
            // empty sig == 69). Asserted at build time against the real encoder.
            const UNSIGNED_VOTE_LEN: usize = 69;
            const PREIMAGE_BUF_LEN: usize = MODEL_MAX_PREIMAGE_BYTES as usize; // 256
            const POS_KEY_LEN: usize = crate::signing_journal_admission::JOURNAL_KEY_LEN; // 55
            const BINDING_LEN: usize = 32;
            const MARKER_LEN: usize = 4   // magic
                + 2                        // version
                + 1                        // phase
                + NONCE_LEN
                + 4 + 4 + 4                // hook / signer / sink counts (u32)
                + 2 + PK_LEN               // pk_len (u16) + pk
                + 2 + UNSIGNED_VOTE_LEN    // vote_len (u16) + vote
                + 2 + PREIMAGE_BUF_LEN     // preimage_len (u16) + fixed zero-padded buffer
                + POS_KEY_LEN
                + BINDING_LEN;

            // SIGABRT. `std::process::abort()` raises this on Unix; `std` exposes no
            // constant and 6 is the POSIX-fixed value.
            const EXPECTED_ABORT_SIGNAL: i32 = 6;

            // Finite supervision budgets (hard budgets on a cooperating kernel; NOT
            // a proof the kernel always completes termination).
            const STATUS_DEADLINE: Duration = Duration::from_secs(30);
            const REAP_BUDGET: Duration = Duration::from_secs(5);
            const POLL_STEP: Duration = Duration::from_millis(10);

            // Env keys for the re-executed child.
            const ENV_MODE: &str = "R422_PCPD_CHILD_MODE";
            const ENV_FIXTURE: &str = "R422_PCPD_FIXTURE";
            const ENV_MARKER: &str = "R422_PCPD_MARKER";
            const ENV_NONCE: &str = "R422_PCPD_NONCE_HEX";
            const ENV_SAFETY_DIR: &str = "R422_PCPD_SAFETY_DIR";
            const ENV_JOURNAL_DIR: &str = "R422_PCPD_JOURNAL_DIR";

            const CHILD_TEST_PATH: &str = "safety_record_store::owner::model::tests::real_fresh_sign::postconsume_process_death::postconsume_child_entry";

            // ---------------------------------------------------------------
            // Fixture transport (fixed 3,888-byte, 0600, outside both DBs).
            // ---------------------------------------------------------------

            /// Serialize the fixed fixture bytes (little-endian integers). Never
            /// printed/committed; the secret bytes live only inside this buffer and
            /// the 0600 file.
            fn encode_fixture(pk: &[u8], sk: &[u8]) -> Vec<u8> {
                assert_eq!(pk.len(), PK_LEN, "fixture public key is the ML-DSA-44 size");
                assert_eq!(sk.len(), SK_LEN, "fixture secret key is the ML-DSA-44 size");
                let mut out = Vec::with_capacity(FIXTURE_LEN);
                out.extend_from_slice(&FIXTURE_MAGIC);
                out.extend_from_slice(&FIXTURE_VERSION.to_le_bytes());
                out.extend_from_slice(&FIXTURE_SUITE.to_le_bytes());
                out.extend_from_slice(&FIXTURE_VALIDATOR.to_le_bytes());
                out.extend_from_slice(&(PK_LEN as u16).to_le_bytes());
                out.extend_from_slice(pk);
                out.extend_from_slice(&(SK_LEN as u16).to_le_bytes());
                out.extend_from_slice(sk);
                assert_eq!(out.len(), FIXTURE_LEN, "fixture length is fixed at 3,888 bytes");
                out
            }

            /// Write the fixture EXCLUSIVELY with mode 0600 inside a parent-owned
            /// directory (outside both RocksDB directories).
            fn write_fixture_file(path: &std::path::Path, pk: &[u8], sk: &[u8]) {
                let bytes = encode_fixture(pk, sk);
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .expect("exclusively create the 0600 fixture file");
                f.write_all(&bytes).expect("write fixture bytes");
                f.flush().expect("flush fixture");
                f.sync_all().expect("fsync fixture");
            }

            /// Read + fully validate the fixture into bounded storage (reject short,
            /// long/trailing, or malformed content). Returns (pk, sk).
            fn read_fixture_file(path: &std::path::Path) -> (Vec<u8>, Vec<u8>) {
                let mut f = std::fs::File::open(path).expect("open fixture file");
                let mut buf = vec![0u8; FIXTURE_LEN];
                f.read_exact(&mut buf).expect("fixture has at least the fixed length");
                // Reject any trailing bytes: a bounded one-byte probe must hit EOF.
                let mut extra = [0u8; 1];
                assert_eq!(
                    f.read(&mut extra).expect("probe read"),
                    0,
                    "the fixture file carries no trailing bytes"
                );
                let mut off = 0usize;
                let take = |off: &mut usize, n: usize| {
                    let s = buf[*off..*off + n].to_vec();
                    *off += n;
                    s
                };
                let u16at = |off: &mut usize| {
                    let mut a = [0u8; 2];
                    a.copy_from_slice(&buf[*off..*off + 2]);
                    *off += 2;
                    u16::from_le_bytes(a)
                };
                let u32at = |off: &mut usize| {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(&buf[*off..*off + 4]);
                    *off += 4;
                    u32::from_le_bytes(a)
                };
                assert_eq!(&take(&mut off, 4)[..], &FIXTURE_MAGIC[..], "fixture magic");
                assert_eq!(u16at(&mut off), FIXTURE_VERSION, "fixture version");
                assert_eq!(u16at(&mut off), FIXTURE_SUITE, "fixture suite");
                assert_eq!(u32at(&mut off), FIXTURE_VALIDATOR, "fixture validator");
                assert_eq!(u16at(&mut off) as usize, PK_LEN, "fixture pk length");
                let pk = take(&mut off, PK_LEN);
                assert_eq!(u16at(&mut off) as usize, SK_LEN, "fixture sk length");
                let sk = take(&mut off, SK_LEN);
                assert_eq!(off, FIXTURE_LEN, "consumed exactly the fixed fixture length");
                (pk, sk)
            }

            /// Build a suite-100 authority from a shared public key (no randomness),
            /// so both processes construct the IDENTICAL validator/suite/domain/
            /// authorized-epoch fixture.
            fn authority_from_pk(pk: Vec<u8>) -> ProposalVoteAuthority {
                let mut pk = pk;
                pk.shrink_to_fit();
                assert!(
                    pk.capacity() as u128 <= MODEL_MAX_PUBKEY_BYTES,
                    "shared public-key backing fits the model bound"
                );
                let mut keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)> = HashMap::new();
                keys.insert(ValidatorId::new(SIGNER_VID), (SUITE_PQ_RESERVED_1, pk));
                let domain = ProposalVoteSigningDomainV2::try_new(
                    ChainId(0xD5D5_0000_0000_0001),
                    MODEL_WIRE_CHAIN_ID,
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

            // ---------------------------------------------------------------
            // Boundary-marker build / parse (fixed binary; no memory layouts).
            // ---------------------------------------------------------------

            /// The complete unsigned Vote wire encoding; asserts the input is
            /// unsigned and that its length matches the existing encoder (69).
            fn unsigned_vote_wire(vote: &Vote) -> Vec<u8> {
                use qbind_wire::io::WireEncode as _;
                assert!(vote.signature.is_empty(), "the captured self-vote is unsigned");
                let mut buf = Vec::new();
                vote.encode(&mut buf);
                assert_eq!(
                    buf.len(),
                    UNSIGNED_VOTE_LEN,
                    "the unsigned Vote wire encoding is exactly {UNSIGNED_VOTE_LEN} bytes"
                );
                buf
            }

            /// The fields an invocation-matched marker witnesses.
            #[derive(Clone, Debug, PartialEq, Eq)]
            struct MarkerWitness {
                nonce: [u8; NONCE_LEN],
                hook_count: u32,
                signer_count: u32,
                sink_count: u32,
                public_key: Vec<u8>,
                unsigned_vote: Vec<u8>,
                preimage: Vec<u8>,
                position_key: Vec<u8>,
                binding: [u8; BINDING_LEN],
            }

            /// Build the complete fixed marker bytes from preconstructed fields.
            #[allow(clippy::too_many_arguments)]
            fn build_marker(
                nonce: &[u8; NONCE_LEN],
                hook_count: u32,
                signer_count: u32,
                sink_count: u32,
                public_key: &[u8],
                unsigned_vote: &[u8],
                preimage: &[u8],
                position_key: &[u8],
                binding: &[u8; BINDING_LEN],
            ) -> Vec<u8> {
                assert_eq!(public_key.len(), PK_LEN, "marker pk length");
                assert_eq!(unsigned_vote.len(), UNSIGNED_VOTE_LEN, "marker vote length");
                assert_eq!(position_key.len(), POS_KEY_LEN, "marker position-key length");
                assert!(
                    preimage.len() <= PREIMAGE_BUF_LEN,
                    "preimage fits the fixed {PREIMAGE_BUF_LEN}-byte buffer"
                );
                let mut out = Vec::with_capacity(MARKER_LEN);
                out.extend_from_slice(&MARKER_MAGIC);
                out.extend_from_slice(&MARKER_VERSION.to_le_bytes());
                out.push(PHASE_POST_CONSUME_PRE_SIGN);
                out.extend_from_slice(nonce);
                out.extend_from_slice(&hook_count.to_le_bytes());
                out.extend_from_slice(&signer_count.to_le_bytes());
                out.extend_from_slice(&sink_count.to_le_bytes());
                out.extend_from_slice(&(PK_LEN as u16).to_le_bytes());
                out.extend_from_slice(public_key);
                out.extend_from_slice(&(UNSIGNED_VOTE_LEN as u16).to_le_bytes());
                out.extend_from_slice(unsigned_vote);
                out.extend_from_slice(&(preimage.len() as u16).to_le_bytes());
                let mut padded = vec![0u8; PREIMAGE_BUF_LEN];
                padded[..preimage.len()].copy_from_slice(preimage);
                out.extend_from_slice(&padded);
                out.extend_from_slice(position_key);
                out.extend_from_slice(binding);
                assert_eq!(out.len(), MARKER_LEN, "marker length is fixed/derived");
                out
            }

            /// Parse + fully validate a marker; reject bad length, magic, version,
            /// phase, oversized preimage length, or nonzero padding.
            fn parse_marker(bytes: &[u8]) -> MarkerWitness {
                assert_eq!(bytes.len(), MARKER_LEN, "marker is exactly the fixed length");
                let mut off = 0usize;
                let takeb = |off: &mut usize, n: usize| {
                    let s = &bytes[*off..*off + n];
                    *off += n;
                    s
                };
                let u16at = |off: &mut usize| {
                    let mut a = [0u8; 2];
                    a.copy_from_slice(&bytes[*off..*off + 2]);
                    *off += 2;
                    u16::from_le_bytes(a)
                };
                let u32at = |off: &mut usize| {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(&bytes[*off..*off + 4]);
                    *off += 4;
                    u32::from_le_bytes(a)
                };
                assert_eq!(takeb(&mut off, 4), &MARKER_MAGIC[..], "marker magic");
                assert_eq!(u16at(&mut off), MARKER_VERSION, "marker version");
                assert_eq!(
                    takeb(&mut off, 1)[0],
                    PHASE_POST_CONSUME_PRE_SIGN,
                    "marker records the post-consume / pre-sign phase"
                );
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(takeb(&mut off, NONCE_LEN));
                let hook_count = u32at(&mut off);
                let signer_count = u32at(&mut off);
                let sink_count = u32at(&mut off);
                assert_eq!(u16at(&mut off) as usize, PK_LEN, "marker pk length field");
                let public_key = takeb(&mut off, PK_LEN).to_vec();
                assert_eq!(u16at(&mut off) as usize, UNSIGNED_VOTE_LEN, "marker vote length field");
                let unsigned_vote = takeb(&mut off, UNSIGNED_VOTE_LEN).to_vec();
                let preimage_len = u16at(&mut off) as usize;
                assert!(preimage_len <= PREIMAGE_BUF_LEN, "preimage length within the fixed buffer");
                let buf = takeb(&mut off, PREIMAGE_BUF_LEN);
                assert!(
                    buf[preimage_len..].iter().all(|&b| b == 0),
                    "unused preimage padding is zeroed"
                );
                let preimage = buf[..preimage_len].to_vec();
                let position_key = takeb(&mut off, POS_KEY_LEN).to_vec();
                let mut binding = [0u8; BINDING_LEN];
                binding.copy_from_slice(takeb(&mut off, BINDING_LEN));
                assert_eq!(off, MARKER_LEN, "consumed exactly the fixed marker length");
                MarkerWitness {
                    nonce,
                    hook_count,
                    signer_count,
                    sink_count,
                    public_key,
                    unsigned_vote,
                    preimage,
                    position_key,
                    binding,
                }
            }

            /// Bounded parent read: at most MARKER_LEN+1 bytes; reject
            /// missing/short/long content. Returns the raw bytes.
            fn read_marker_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
                let f = std::fs::File::open(path)?;
                let mut limited = f.take((MARKER_LEN + 1) as u64);
                let mut buf = Vec::with_capacity(MARKER_LEN + 1);
                limited.read_to_end(&mut buf)?;
                Ok(buf)
            }

            /// 16 fresh bytes from `/dev/urandom` (supported Linux profile). Used by
            /// the parent to mint an invocation nonce BEFORE the protected op.
            fn urandom_nonce() -> [u8; NONCE_LEN] {
                let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
                let mut n = [0u8; NONCE_LEN];
                f.read_exact(&mut n).expect("read 16 nonce bytes");
                n
            }

            fn nonce_to_hex(n: &[u8; NONCE_LEN]) -> String {
                let mut s = String::with_capacity(NONCE_LEN * 2);
                for b in n {
                    s.push_str(&format!("{b:02x}"));
                }
                s
            }

            fn hex_to_nonce(s: &str) -> [u8; NONCE_LEN] {
                assert_eq!(s.len(), NONCE_LEN * 2, "nonce hex is 32 chars");
                let mut n = [0u8; NONCE_LEN];
                for (i, slot) in n.iter_mut().enumerate() {
                    *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte");
                }
                n
            }

            // ---------------------------------------------------------------
            // Bounded, owned child supervision (Stdio::null; no pipe drain).
            // ---------------------------------------------------------------

            /// Observed termination classification for an owned child.
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            enum TermClass {
                /// Exited via a terminating signal.
                Signaled(i32),
                /// Exited normally with this code (or -1 if unavailable).
                Exited(i32),
                /// The status deadline expired; the parent killed and reaped it.
                /// `kill_confirmed` is true ONLY when the `kill` syscall itself
                /// succeeded. A false value records a race in which the child had
                /// already exited (so `kill` errored) but a later `try_wait` still
                /// observed the exit — reported accurately, never labelled "killed".
                TimedOutKilled { kill_confirmed: bool },
            }

            /// Pure classification of a reaped `ExitStatus` (no scheduling).
            fn classify_status(status: std::process::ExitStatus) -> TermClass {
                if let Some(sig) = status.signal() {
                    TermClass::Signaled(sig)
                } else {
                    TermClass::Exited(status.code().unwrap_or(-1))
                }
            }

            /// An owned child with explicit, bounded reaping. The normal path calls
            /// [`OwnedChild::supervise`] (which reaps and classifies); any residual
            /// live child is cleaned up on `Drop` with a bounded, NON-panicking
            /// kill+reap so an assertion-unwind cannot leak it.
            struct OwnedChild {
                child: Option<std::process::Child>,
            }

            impl OwnedChild {
                fn new(child: std::process::Child) -> Self {
                    Self { child: Some(child) }
                }

                /// Wait (bounded, `try_wait` polling) for the child to terminate ON
                /// ITS OWN within `status_deadline` (test-selected: the normal
                /// budget for the boundary, a short budget for the timeout control).
                /// On timeout, kill and reap within `REAP_BUDGET`. Returns the
                /// classification or an explicit failure string (try_wait error,
                /// kill error without an observed exit, or unreaped within budget).
                /// On success the child is reaped and `Drop` becomes a no-op.
                fn supervise(&mut self, status_deadline: Duration) -> Result<TermClass, String> {
                    let child = self.child.as_mut().expect("child present");
                    let deadline = Instant::now() + status_deadline;
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                self.child = None;
                                return Ok(classify_status(status));
                            }
                            Ok(None) => {
                                if Instant::now() >= deadline {
                                    break;
                                }
                                std::thread::sleep(POLL_STEP);
                            }
                            Err(e) => return Err(format!("try_wait error: {e}")),
                        }
                    }
                    // Deadline path: kill, then reap within REAP_BUDGET. A kill
                    // error is tolerated ONLY if a subsequent try_wait still
                    // observes the exit; the resulting `kill_confirmed` flag records
                    // whether the kill syscall itself actually succeeded.
                    let kill_err = child.kill().err();
                    let reap_deadline = Instant::now() + REAP_BUDGET;
                    loop {
                        match child.try_wait() {
                            Ok(Some(_status)) => {
                                self.child = None;
                                return Ok(TermClass::TimedOutKilled {
                                    kill_confirmed: kill_err.is_none(),
                                });
                            }
                            Ok(None) => {
                                if Instant::now() >= reap_deadline {
                                    return Err(format!(
                                        "child not reaped within budget (kill_err={kill_err:?})"
                                    ));
                                }
                                std::thread::sleep(POLL_STEP);
                            }
                            Err(e) => {
                                return Err(format!(
                                    "try_wait error during reap: {e} (kill_err={kill_err:?})"
                                ))
                            }
                        }
                    }
                }
            }

            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    if let Some(mut c) = self.child.take() {
                        // Bounded, NON-panicking cleanup (may run during unwind).
                    // Diagnostic writes are fallible and their errors are
                    // swallowed so a failed stderr write cannot panic here.
                    let _ = c.kill();
                    let deadline = Instant::now() + REAP_BUDGET;
                    loop {
                        match c.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) => {
                                if Instant::now() >= deadline {
                                    let _ = writeln!(
                                        std::io::stderr(),
                                        "R422 PCPD: child unreaped within budget on drop"
                                    );
                                    break;
                                }
                                std::thread::sleep(POLL_STEP);
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    std::io::stderr(),
                                    "R422 PCPD: try_wait error on drop: {e}"
                                );
                                break;
                            }
                        }
                    }
                }
            }
            }

            /// Spawn the re-executed child test in the given mode with all streams
            /// null (no pipe-drain subsystem).
            fn spawn_boundary_child(
                mode: &str,
                fixture: &std::path::Path,
                marker: &std::path::Path,
                nonce_hex: &str,
                safety_dir: &std::path::Path,
                journal_dir: &std::path::Path,
            ) -> OwnedChild {
                let exe = std::env::current_exe().expect("current test exe");
                let child = std::process::Command::new(exe)
                    .args([
                        "--exact",
                        CHILD_TEST_PATH,
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(ENV_MODE, mode)
                    .env(ENV_FIXTURE, fixture)
                    .env(ENV_MARKER, marker)
                    .env(ENV_NONCE, nonce_hex)
                    .env(ENV_SAFETY_DIR, safety_dir)
                    .env(ENV_JOURNAL_DIR, journal_dir)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("spawn re-executed boundary child");
                OwnedChild::new(child)
            }

            // ---------------------------------------------------------------
            // Child entrypoint (re-executed; a plain `--ignored` run is a no-op).
            // ---------------------------------------------------------------

            /// The child's shared fixture-construction path: read the transported
            /// keypair, establish incarnation A over the PERSISTENT safety store,
            /// open+associate the PERSISTENT journal, derive the base vote and the
            /// preconstructed marker, and return everything the protected call
            /// needs. All marker fields are built BEFORE entering the protected op.
            #[allow(clippy::type_complexity)]
            fn child_prepare(
                fixture: &std::path::Path,
                safety_dir: &std::path::Path,
                journal_dir: &std::path::Path,
                nonce: &[u8; NONCE_LEN],
            ) -> (
                ProposalVoteAuthority,
                Vec<u8>, // sk
                SafetyRecordOwner,
                BasicHotStuffEngine<[u8; 32]>,
                DecidedVote<OwningCapturePayload>,
                BlockProposal,
                PreparedDecisionInputLimits,
                SigningReservationJournal,
                Vec<u8>, // preconstructed marker bytes
            ) {
                let (pk, sk) = read_fixture_file(fixture);
                let pv = authority_from_pk(pk.clone());
                let ctx = retained_ctx(4);
                let (owner, engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(safety_dir, &ctx, MODEL_SUITE_U16);
                let journal_store = reopen_open_journal_store(journal_dir);
                let journal = reopen_assoc_journal_init(
                    &owner,
                    journal_store as Arc<dyn SigningJournalStorage>,
                    1,
                );
                let base_vote = decided.vote().clone();
                let (position, binding) = retained_pos_binding(&pv, &base_vote);
                let preimage = pv.signing_domain.vote_preimage(&base_vote);
                let unsigned_vote = unsigned_vote_wire(&base_vote);
                let position_key = position.storage_key();
                // Preconstruct the marker with the KNOWN boundary counts (one hook
                // invocation, zero signer, zero sink); the hook re-asserts the live
                // observers before writing.
                let marker = build_marker(
                    nonce,
                    1,
                    0,
                    0,
                    &pk,
                    &unsigned_vote,
                    &preimage,
                    &position_key,
                    &binding.0,
                );
                (pv, sk, owner, engine, decided, p1, lim, journal, marker)
            }

            #[test]
            #[ignore = "re-executed child entrypoint; a plain --ignored run is a no-op"]
            fn postconsume_child_entry() {
                let Some(mode) = std::env::var_os(ENV_MODE) else {
                    return; // not in child mode
                };
                let mode = mode.to_string_lossy().into_owned();
                match mode.as_str() {
                    "missing_marker" => {
                        // Setup-failure control: exit nonzero without any marker.
                        std::process::exit(3);
                    }
                    "wrong_signal" => {
                        // Terminate via a NON-abort signal (SIGTERM) without a marker.
                        unsafe {
                            libc::raise(libc::SIGTERM);
                        }
                        std::process::exit(0);
                    }
                    "marker_then_exit" | "abort_boundary" => {
                        let fixture =
                            std::path::PathBuf::from(std::env::var_os(ENV_FIXTURE).expect("fixture"));
                        let marker_path =
                            std::path::PathBuf::from(std::env::var_os(ENV_MARKER).expect("marker"));
                        let safety_dir = std::path::PathBuf::from(
                            std::env::var_os(ENV_SAFETY_DIR).expect("safety dir"),
                        );
                        let journal_dir = std::path::PathBuf::from(
                            std::env::var_os(ENV_JOURNAL_DIR).expect("journal dir"),
                        );
                        let nonce = hex_to_nonce(
                            &std::env::var(ENV_NONCE).expect("nonce hex"),
                        );

                        let (pv, sk, owner, engine, decided, p1, lim, journal, marker) =
                            child_prepare(&fixture, &safety_dir, &journal_dir, &nonce);

                        // Open the EXCLUSIVELY created marker file (initially empty)
                        // BEFORE entering the protected operation.
                        let marker_file = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&marker_path)
                            .expect("exclusively create the empty marker file");

                        if mode == "marker_then_exit" {
                            // Control: write the complete marker, then exit normally
                            // (no abort). The parent must reject this (non-SIGABRT).
                            let mut f = marker_file;
                            f.write_all(&marker).expect("write marker");
                            f.flush().expect("flush marker");
                            f.sync_all().expect("sync marker");
                            std::process::exit(0);
                        }

                        // abort_boundary: drive the ACTUAL protected route with the
                        // armed hook. Shared observers connect the live signer/sink
                        // counters to the abort evidence.
                        let signer_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                        let sink_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                        let inner = real_local_signer(&sk);
                        let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                        let mut sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                        let mut snapshot = established_snapshot(&pv);
                        let evidence = AbortEvidence::new(
                            marker,
                            marker_file,
                            signer_obs.clone(),
                            sink_obs.clone(),
                        );
                        let mut coord = ModelCoordinationHook::aborting(evidence);
                        let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                            &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                            &signer, &mut sink, &journal, &mut coord,
                            ReconfirmPerturbation::None,
                        );
                        // The hook MUST abort inside step 15; reaching here means the
                        // route never reached the boundary (setup failure).
                        panic!(
                            "boundary child did not abort at the pre-sign hook; outcome={outcome:?}"
                        );
                    }
                    other => panic!("unknown child mode {other}"),
                }
            }

            // ---------------------------------------------------------------
            // Pure marker / classifier controls.
            // ---------------------------------------------------------------

            #[test]
            fn marker_len_is_derived_constant() {
                // 4(magic)+2(ver)+1(phase)+16(nonce)+12(counts)
                //   + (2+1312)(pk) + (2+69)(vote) + (2+256)(preimage) + 55(key) + 32(binding)
                assert_eq!(MARKER_LEN, 23 + 12 + 1314 + 71 + 258 + 55 + 32);
                assert_eq!(MARKER_LEN, 1765);
                assert_eq!(FIXTURE_LEN, 3888);
                assert_eq!(POS_KEY_LEN, 55);
            }

            #[test]
            fn marker_roundtrip_build_parse() {
                let nonce = [7u8; NONCE_LEN];
                let pk = vec![0xABu8; PK_LEN];
                let vote = vec![0x11u8; UNSIGNED_VOTE_LEN];
                let preimage = vec![0x22u8; 40];
                let pos = vec![0x33u8; POS_KEY_LEN];
                let binding = [0x44u8; BINDING_LEN];
                let bytes = build_marker(&nonce, 1, 0, 0, &pk, &vote, &preimage, &pos, &binding);
                assert_eq!(bytes.len(), MARKER_LEN);
                let w = parse_marker(&bytes);
                assert_eq!(w.nonce, nonce);
                assert_eq!((w.hook_count, w.signer_count, w.sink_count), (1, 0, 0));
                assert_eq!(w.public_key, pk);
                assert_eq!(w.unsigned_vote, vote);
                assert_eq!(w.preimage, preimage);
                assert_eq!(w.position_key, pos);
                assert_eq!(w.binding, binding);
            }

            #[test]
            #[should_panic(expected = "unused preimage padding is zeroed")]
            fn marker_rejects_nonzero_padding() {
                let nonce = [0u8; NONCE_LEN];
                let pk = vec![0u8; PK_LEN];
                let vote = vec![0u8; UNSIGNED_VOTE_LEN];
                let pos = vec![0u8; POS_KEY_LEN];
                let binding = [0u8; BINDING_LEN];
                let mut bytes = build_marker(&nonce, 1, 0, 0, &pk, &vote, &[0u8; 8], &pos, &binding);
                // Corrupt a padding byte just past the 8-byte preimage.
                let pad_start = 4 + 2 + 1 + NONCE_LEN + 12 + 2 + PK_LEN + 2 + UNSIGNED_VOTE_LEN + 2 + 8;
                bytes[pad_start] = 0xFF;
                let _ = parse_marker(&bytes);
            }

            #[test]
            #[should_panic(expected = "marker is exactly the fixed length")]
            fn marker_rejects_wrong_length() {
                let mut bytes = vec![0u8; MARKER_LEN + 1];
                bytes[..4].copy_from_slice(&MARKER_MAGIC);
                let _ = parse_marker(&bytes);
            }

            #[test]
            fn classify_status_table() {
                use std::process::ExitStatus;
                assert_eq!(
                    classify_status(ExitStatus::from_raw(EXPECTED_ABORT_SIGNAL)),
                    TermClass::Signaled(6)
                );
                assert_eq!(classify_status(ExitStatus::from_raw(15)), TermClass::Signaled(15));
                assert_eq!(classify_status(ExitStatus::from_raw(3 << 8)), TermClass::Exited(3));
                assert_eq!(classify_status(ExitStatus::from_raw(0)), TermClass::Exited(0));
            }

            // ---------------------------------------------------------------
            // Supervision controls (real spawned processes).
            // ---------------------------------------------------------------

            #[test]
            fn supervision_missing_marker_setup_failure() {
                let tmp = tempfile::tempdir().unwrap();
                let fixture = tmp.path().join("fx.bin");
                let marker = tmp.path().join("marker.bin");
                let safety = tempfile::tempdir().unwrap();
                let journal = tempfile::tempdir().unwrap();
                // Child exits nonzero without ever creating the marker.
                let mut child = spawn_boundary_child(
                    "missing_marker", &fixture, &marker, &"00".repeat(NONCE_LEN),
                    safety.path(), journal.path(),
                );
                let class = child.supervise(STATUS_DEADLINE).expect("reaped");
                assert_eq!(class, TermClass::Exited(3), "setup-failure child exits nonzero, no signal");
                assert!(read_marker_bounded(&marker).is_err(), "no marker was produced");
            }

            #[test]
            fn supervision_marker_then_ordinary_exit_rejected() {
                let tmp = tempfile::tempdir().unwrap();
                let fixture = tmp.path().join("fx.bin");
                let marker = tmp.path().join("marker.bin");
                let safety = tempfile::tempdir().unwrap();
                let journal = tempfile::tempdir().unwrap();
                let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
                write_fixture_file(&fixture, &pk, &sk);
                let nonce = urandom_nonce();
                let mut child = spawn_boundary_child(
                    "marker_then_exit", &fixture, &marker, &nonce_to_hex(&nonce),
                    safety.path(), journal.path(),
                );
                let class = child.supervise(STATUS_DEADLINE).expect("reaped");
                // A COMPLETE marker was written, but the termination is an ordinary
                // exit — NOT the intended SIGABRT crash evidence.
                assert_eq!(class, TermClass::Exited(0), "marker-then-exit is not a crash");
                assert_ne!(class, TermClass::Signaled(EXPECTED_ABORT_SIGNAL));
                let raw = read_marker_bounded(&marker).expect("marker present");
                let w = parse_marker(&raw);
                assert_eq!(w.nonce, nonce, "marker nonce matches the invocation");
            }

            #[test]
            fn supervision_wrong_signal_rejected() {
                let tmp = tempfile::tempdir().unwrap();
                let fixture = tmp.path().join("fx.bin");
                let marker = tmp.path().join("marker.bin");
                let safety = tempfile::tempdir().unwrap();
                let journal = tempfile::tempdir().unwrap();
                let mut child = spawn_boundary_child(
                    "wrong_signal", &fixture, &marker, &"00".repeat(NONCE_LEN),
                    safety.path(), journal.path(),
                );
                let class = child.supervise(STATUS_DEADLINE).expect("reaped");
                assert_eq!(
                    class,
                    TermClass::Signaled(libc::SIGTERM),
                    "a wrong terminating signal is not SIGABRT"
                );
                assert_ne!(class, TermClass::Signaled(EXPECTED_ABORT_SIGNAL));
                assert!(read_marker_bounded(&marker).is_err(), "no marker for a wrong-signal exit");
            }

            #[test]
            fn supervision_timeout_with_verified_reap() {
                // A single OWNED long-running process (launched directly, NOT via
                // `sh -c`, so no descendant is left behind). This drives the ACTUAL
                // `OwnedChild::supervise` timeout branch via a short status budget,
                // so a regression in that method's timeout/kill/reap path is caught.
                let child = std::process::Command::new("sleep")
                    .arg("600")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("spawn sleep");
                let mut owned = OwnedChild::new(child);
                let class = owned
                    .supervise(Duration::from_millis(200))
                    .expect("the timed-out child is killed and reaped");
                // The timeout path was reached (kill confirmed on a live process);
                // this is cleanup, never the intended SIGABRT crash evidence.
                match class {
                    TermClass::TimedOutKilled { kill_confirmed } => {
                        assert!(kill_confirmed, "the kill of the still-live sleep succeeded");
                    }
                    other => panic!("expected the supervisor timeout branch, got {other:?}"),
                }
                assert_ne!(
                    class,
                    TermClass::Signaled(EXPECTED_ABORT_SIGNAL),
                    "a parent kill is cleanup, not SIGABRT crash evidence"
                );
                // Ownership is cleared only after the supervisor observed the exit.
                assert!(owned.child.is_none(), "the child was actually reaped by the supervisor");
            }

            #[test]
            fn supervision_parent_unwind_bounded_cleanup() {
                // A raw Child must never be left unowned across a fallible assertion:
                // wrap it in OwnedChild, force a parent unwind, and confirm the guard
                // cleaned it up (no leak) via bounded non-panicking Drop.
                let pid = {
                    let child = std::process::Command::new("sleep")
                        .arg("600")
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .expect("spawn sleep");
                    let pid = child.id();
                    let owned = OwnedChild::new(child);
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _guard = owned; // owned by the closure; dropped on unwind
                        panic!("intentional parent unwind");
                    }));
                    assert!(r.is_err(), "the unwind was caught");
                    pid
                };
                // After the guard's Drop, the child must be gone. Probe with
                // `kill(pid, 0)` and capture its errno IMMEDIATELY: a reaped pid
                // yields a failed probe whose error is EXACTLY ESRCH. EPERM (or any
                // other error) must NOT count as evidence that the child is gone.
                let probe = unsafe { libc::kill(pid as libc::pid_t, 0) };
                let probe_err = std::io::Error::last_os_error();
                assert_eq!(probe, -1, "probing a reaped pid fails");
                assert_eq!(
                    probe_err.raw_os_error(),
                    Some(libc::ESRCH),
                    "the owned child is gone (ESRCH), not merely inaccessible (EPERM)"
                );
            }

            // ---------------------------------------------------------------
            // Eligibility / positive control (in-process; NO termination).
            // ---------------------------------------------------------------

            #[test]
            fn postconsume_eligibility_published_no_termination() {
                // Same fixture-construction path and shared test identity as the
                // boundary child, with the hook DISABLED and separate fresh DBs.
                let fx_dir = tempfile::tempdir().unwrap();
                let fixture = fx_dir.path().join("fx.bin");
                let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
                write_fixture_file(&fixture, &pk, &sk);
                let (rpk, rsk) = read_fixture_file(&fixture);
                assert_eq!(rpk, pk, "transported public key round-trips");
                // Redacted equality: a mismatch must NOT print any secret-key bytes.
                assert!(rsk == sk, "transported secret key round-trips (contents redacted)");

                let pv = authority_from_pk(rpk);
                let ctx = retained_ctx(4);
                let safety_dir = tempfile::tempdir().unwrap();
                let journal_dir = tempfile::tempdir().unwrap();
                let (owner, engine, decided, p1, lim, _rev) =
                    capture_multi_with_suite(safety_dir.path(), &ctx, MODEL_SUITE_U16);
                let base_vote = decided.vote().clone();
                let store = reopen_open_journal_store(journal_dir.path());
                let journal = reopen_assoc_journal_init(
                    &owner,
                    store.clone() as Arc<dyn SigningJournalStorage>,
                    1,
                );

                let signer_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let sink_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let inner = real_local_signer(&rsk);
                let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                let mut sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                let mut snapshot = established_snapshot(&pv);
                let mut coord = ModelCoordinationHook::inert();

                let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &p1, &lim, None, &mut snapshot,
                    &signer, &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                let diag = match outcome {
                    RealFreshSignOutcome::Published(d) => d,
                    other => panic!("eligibility control must Publish, got {other:?}"),
                };
                assert_eq!(diag.retirement, RetirementReport::Retired, "published then retired");
                assert_eq!(diag.sig_len, 2420, "ML-DSA-44 signature size");
                // BOTH the original owned counters AND the shared observers report
                // one signer / one sink: the observers are genuinely connected.
                assert_eq!(signer.calls(), 1, "owned signer counter");
                assert_eq!(sink.calls, 1, "owned sink counter");
                assert_eq!(signer_obs.load(std::sync::atomic::Ordering::SeqCst), 1, "shared signer observer");
                assert_eq!(sink_obs.load(std::sync::atomic::Ordering::SeqCst), 1, "shared sink observer");
                assert_eq!(coord.calls, 1, "the coordination point was reached once (inert)");
                assert_eq!(journal.reserved_position_count(), 1, "durable-position count 0 -> 1");

                // The stored signature verifies against the exact journal-bound
                // preimage under the shared authorized key.
                let (pos, binding) = retained_pos_binding(&pv, &base_vote);
                let preimage = pv.signing_domain.vote_preimage(&base_vote);
                let published_sig = match journal.reserve_for_sign(&pos, &binding) {
                    Ok(ReservationOutcome::ExactRetryRetained(sig)) => sig,
                    other => panic!("expected the acknowledged signature, got {other:?}"),
                };
                assert_eq!(published_sig.len(), 2420, "stored full signature");
                let (_suite, akey) = pv
                    .key_provider
                    .get_suite_and_key(ValidatorId::new(SIGNER_VID))
                    .expect("authorized public key installed");
                MlDsa44Backend::verify(&akey, &preimage, &published_sig)
                    .expect("the stored signature verifies under the shared key and bound preimage");
                assert_eq!(binding.0.len(), BINDING_LEN);
            }

            // ---------------------------------------------------------------
            // THE isolated post-consumption process-death recovery boundary.
            // ---------------------------------------------------------------

            #[test]
            fn postconsume_child_death_then_reopen_refuses() {
                // Parent-owned fixture + marker directory OUTSIDE both databases.
                let harness_dir = tempfile::tempdir().unwrap();
                let fixture = harness_dir.path().join("suite100_keypair.bin");
                let marker = harness_dir.path().join("boundary_marker.bin");
                // Persistent store directories the child establishes and the parent
                // reopens (NEVER re-initialized over).
                let safety_dir = tempfile::tempdir().unwrap();
                let journal_dir = tempfile::tempdir().unwrap();

                // ONE real parent-generated suite-100 test keypair, transported via
                // a 0600 fixture file. Build fixtures BEFORE the protected operation.
                let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
                write_fixture_file(&fixture, &pk, &sk);
                let nonce = urandom_nonce();
                let nonce_hex = nonce_to_hex(&nonce);

                // Drive the actual protected route to the pre-sign boundary in a real
                // child process, then require SIGABRT + a complete invocation-matched
                // marker.
                let mut child = spawn_boundary_child(
                    "abort_boundary", &fixture, &marker, &nonce_hex,
                    safety_dir.path(), journal_dir.path(),
                );
                let class = child.supervise(STATUS_DEADLINE).expect("child reaped");
                assert_eq!(
                    class,
                    TermClass::Signaled(EXPECTED_ABORT_SIGNAL),
                    "the child terminated via the intended SIGABRT at the pre-sign boundary"
                );

                // Bounded marker read + full validation.
                let raw = read_marker_bounded(&marker).expect("the child wrote a marker");
                let witness = parse_marker(&raw);
                assert_eq!(witness.nonce, nonce, "the marker is matched to THIS invocation");
                assert_eq!(
                    (witness.hook_count, witness.signer_count, witness.sink_count),
                    (1, 0, 0),
                    "one hook invocation; zero signer and zero sink at the boundary"
                );
                assert_eq!(witness.public_key, pk, "the marker carries the shared public key");

                // ---- Surviving process: reopen BOTH stores (no re-init). ----
                let ctx = retained_ctx(4);
                let pv = authority_from_pk(pk.clone());
                let owner_b = reopen_attach(safety_dir.path(), &ctx);
                let store_b_concrete = reopen_open_journal_store(journal_dir.path());
                let store_b = store_b_concrete.clone() as Arc<dyn SigningJournalStorage>;
                let journal_b = reopen_assoc_journal_open(&owner_b, store_b.clone(), 1);
                assert_eq!(
                    journal_b.reserved_position_count(),
                    1,
                    "the reopened journal recovers exactly one Reserved position"
                );

                // ---- Durable snapshot taken IMMEDIATELY after reopen, BEFORE the
                //      O2/O3/O5 recovery helper. The marker witness supplies the
                //      read-only identification (position key + binding); all
                //      readback allocations are outside the protected operation. ----
                let rec_pre = store_b_concrete
                    .get_signing_record(&witness.position_key)
                    .expect("bounded record read immediately after reopen")
                    .expect("the Reserved record survived the abrupt process death");
                let meta_pre = store_b_concrete
                    .get_signing_metadata()
                    .expect("bounded journal-metadata read immediately after reopen");
                let count_pre = journal_b.reserved_position_count();
                {
                    let record_pre =
                        SigningDecisionRecord::decode(&rec_pre).expect("reopened record decodes");
                    assert_eq!(
                        record_pre.stage,
                        SigningRecordStage::Reserved,
                        "the reopened record is Reserved before recovery"
                    );
                    assert_eq!(
                        record_pre.position.storage_key(),
                        witness.position_key,
                        "the reopened record sits at the witnessed position key"
                    );
                    assert_eq!(
                        record_pre.binding.0, witness.binding,
                        "the reopened record carries the witnessed binding digest"
                    );
                    assert!(
                        record_pre.retained_signature.is_none(),
                        "a Reserved record retains NO signature before recovery"
                    );
                }

                // ---- Recover a surviving-process capture via fresh O2/O3/O5. ----
                let (mut engine_b, p1_b, l0_block) = engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
                let b_decided = reopen_b_recover_and_capture(&owner_b, &mut engine_b, &p1_b, &lim_b(&ctx), l0_block);
                let b_base_vote = b_decided.vote().clone();

                // Independently reconstruct and compare the marker witness against the
                // surviving-process fixtures (test evidence, NOT authorization).
                let (pos, binding) = retained_pos_binding(&pv, &b_base_vote);
                let preimage_b = pv.signing_domain.vote_preimage(&b_base_vote);
                let unsigned_vote_b = unsigned_vote_wire(&b_base_vote);
                assert_eq!(witness.unsigned_vote, unsigned_vote_b, "unsigned Vote encodings correspond");
                assert_eq!(witness.preimage, preimage_b, "signing preimages correspond");
                assert_eq!(witness.position_key, pos.storage_key(), "position keys correspond");
                assert_eq!(witness.binding, binding.0, "binding digests correspond");
                let (_suite, akey) = pv
                    .key_provider
                    .get_suite_and_key(ValidatorId::new(SIGNER_VID))
                    .expect("authorized public key installed");
                assert_eq!(witness.public_key, akey, "public-key identity corresponds");

                // Directly inspect the recovered journal record: Reserved, expected
                // position/binding, no retained signature. O5 did NOT clear it.
                let rec_raw = store_b_concrete
                    .get_signing_record(&pos.storage_key())
                    .expect("bounded record read after reopen")
                    .expect("the Reserved record survived the abrupt process death");
                let record = SigningDecisionRecord::decode(&rec_raw).expect("record decodes");
                assert_eq!(record.stage, SigningRecordStage::Reserved, "the recovered record is Reserved");
                assert_eq!(record.position, pos, "the recovered record is at the exact position");
                assert_eq!(record.binding, binding, "the recovered record carries the exact binding");
                assert!(
                    record.retained_signature.is_none(),
                    "a Reserved record retains NO signature (the signer never ran)"
                );
                assert_eq!(journal_b.reserved_position_count(), 1, "successful O5 leaves the D10 obligation intact");

                // Compare the post-recovery durable state SEPARATELY against the
                // pre-recovery snapshots: successful O5 mutates neither the record
                // bytes, the journal metadata, nor the reserved-position count.
                let meta_post_recover = store_b_concrete
                    .get_signing_metadata()
                    .expect("journal-metadata read after O5 recovery");
                assert_eq!(rec_raw, rec_pre, "O5 recovery leaves the durable Reserved bytes unchanged");
                assert_eq!(meta_post_recover, meta_pre, "O5 recovery leaves the journal metadata unchanged");
                assert_eq!(journal_b.reserved_position_count(), count_pre, "O5 recovery leaves the reserved-position count unchanged");

                // ---- Invoke the actual protected fresh route; require refusal. ----
                let signer_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let sink_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                let mut sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                let mut snapshot = established_snapshot(&pv);
                let mut coord = ModelCoordinationHook::inert();

                // Independent operational/aggregate baselines with the surviving
                // Vote/pin live; plus original pin provenance, record bytes,
                // metadata, durable-position count, and ceilings established
                // IMMEDIATELY before the protected refused attempt.
                let ledgers_before = snapshot_ledgers(&owner_b);
                let prov_before = pin_provenance_now(&owner_b, &b_decided);
                let op_cap_before = owner_b.backend_for_test().accounting_cap();
                let agg_cap_before = owner_b.backend_for_test().accounting_aggregate_cap();
                let rec_before = store_b_concrete
                    .get_signing_record(&pos.storage_key())
                    .expect("record read before the refused attempt")
                    .expect("the Reserved record persists before the refused attempt");
                let meta_before = store_b_concrete
                    .get_signing_metadata()
                    .expect("journal-metadata read before the refused attempt");
                let count_before = journal_b.reserved_position_count();

                let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    &owner_b, &engine_b, &b_decided, &p1_b, &lim_b(&ctx), None, &mut snapshot,
                    &signer, &mut sink, &journal_b, &mut coord, ReconfirmPerturbation::None,
                );
                assert_eq!(
                    outcome,
                    RealFreshSignOutcome::ReservePotentiallySigned,
                    "the recovered Reserved obligation refuses fresh signing after O5"
                );
                assert_eq!(signer.calls(), 0, "zero signer calls on the refused fresh attempt");
                assert_eq!(sink.calls, 0, "zero sink calls on the refused fresh attempt");
                assert_eq!(signer_obs.load(std::sync::atomic::Ordering::SeqCst), 0, "shared signer observer stays zero");
                assert_eq!(sink_obs.load(std::sync::atomic::Ordering::SeqCst), 0, "shared sink observer stays zero");

                // Immediately assert accounting/Vote/pin preservation and unchanged
                // ceilings, THEN separately compare durable record/metadata/count.
                assert_cleanup_preserved(
                    &owner_b, &b_decided, &b_base_vote, ledgers_before, prov_before,
                    "the recovered-Reserved fresh refusal",
                );
                assert_eq!(owner_b.backend_for_test().accounting_cap(), op_cap_before, "operational ceiling unchanged");
                assert_eq!(owner_b.backend_for_test().accounting_aggregate_cap(), agg_cap_before, "aggregate ceiling unchanged");
                let rec_after = store_b_concrete
                    .get_signing_record(&pos.storage_key())
                    .expect("read")
                    .expect("the Reserved record still persists");
                let meta_after = store_b_concrete
                    .get_signing_metadata()
                    .expect("journal-metadata read after the refusal");
                assert_eq!(rec_after, rec_before, "the durable Reserved bytes are unchanged by the refusal");
                assert_eq!(meta_after, meta_before, "the journal metadata is unchanged by the refusal");
                assert_eq!(journal_b.reserved_position_count(), count_before, "durable-position count unchanged by the refusal");

                // ---- Full surviving-process teardown to zero (abort ran no child
                //      Drop, so NO child ledger restoration is claimed). ----
                let b_acct = owner_b.backend_for_test().accounting_handle_for_test();
                drop(b_decided); // the pin/envelope FIRST
                drop(engine_b);
                drop(journal_b);
                drop(store_b);
                drop(store_b_concrete);
                drop(owner_b);
                assert_eq!(b_acct.current(), 0, "surviving operational ledger returns to zero after full teardown");
                assert_eq!(b_acct.aggregate().current(), 0, "surviving aggregate ledger returns to zero after full teardown");
            }

            /// The surviving process derives its OWN limits from the pinned context
            /// (the child's limits never cross the boundary).
            #[cfg(all(unix, panic = "unwind"))]
            mod postwrite_prejournal_ack {
                use super::*;
                use crate::signing_reservation_journal::{
                    BoundedDiag, BoundedStorageError, SigningDecisionRecord,
                    SigningJournalStorage, SigningKind, SigningOwnershipDomain, SigningPosition,
                    SigningRecordStage, SigningReservationJournal, SIGNING_RECORD_FORMAT_VERSION,
                };
                use crate::storage::{RocksDbConsensusStorage, StorageError};
                use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
                use std::sync::{Arc, Mutex};
                use std::time::Duration;

                const MAGIC: [u8; 4] = *b"R4W2";
                const VERSION: u16 = 1;
                const PHASE: u8 = 0x19;
                const NONCE_LEN: usize = 16;
                const PK_LEN: usize = qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE;
                const VOTE_LEN: usize = 69;
                const PREIMAGE_CAP: usize = 256;
                const POSITION_LEN: usize = crate::signing_journal_admission::JOURNAL_KEY_LEN;
                const SIGNATURE_LEN: usize = qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE;
                const SIGNATURE_OFFSET: usize = 1791;
                const MARKER_LEN: usize = 4 + 2 + 1 + NONCE_LEN + 8 * 4 + 2 + 2 + 2 + PK_LEN
                    + 2 + VOTE_LEN + 2 + PREIMAGE_CAP + POSITION_LEN + 32 + 2 + SIGNATURE_LEN;
                const CHILD_PATH: &str = "safety_record_store::owner::model::tests::real_fresh_sign::postconsume_process_death::postwrite_prejournal_ack::child_entry";
                const ENV_MODE: &str = "R422_PWPA_CHILD_MODE";
                const ENV_FIXTURE: &str = "R422_PWPA_FIXTURE";
                const ENV_MARKER: &str = "R422_PWPA_MARKER";
                const ENV_NONCE: &str = "R422_PWPA_NONCE";
                const ENV_SAFETY: &str = "R422_PWPA_SAFETY";
                const ENV_JOURNAL: &str = "R422_PWPA_JOURNAL";

                const OFF_NONCE: usize = 7;
                const OFF_COUNTS: usize = 23;
                const OFF_NATIVE_ACK: usize = 55;
                const OFF_WRAPPER_RETURN: usize = 56;
                const OFF_SUITE: usize = 57;
                const OFF_PK_LEN: usize = 59;
                const OFF_PK: usize = 61;
                const OFF_VOTE_LEN: usize = 1373;
                const OFF_VOTE: usize = 1375;
                const OFF_PREIMAGE_LEN: usize = 1444;
                const OFF_PREIMAGE: usize = 1446;
                const OFF_POSITION: usize = 1702;
                const OFF_BINDING: usize = 1757;
                const OFF_SIGNATURE_LEN: usize = 1789;

                #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
                struct Counts {
                    boundary_callbacks: u64,
                    combined_attempts: u64,
                    combined_delegated: u64,
                    combined_successes: u64,
                    record_attempts: u64,
                    record_delegated: u64,
                    record_successes: u64,
                    reissue_attempts: u64,
                    reissue_delegated: u64,
                    reissue_successes: u64,
                    bounded_read_attempts: u64,
                    bounded_present_reads: u64,
                    other_mutation_attempts: u64,
                    other_mutation_delegated: u64,
                    other_mutation_successes: u64,
                }

                #[derive(Default)]
                struct AtomicCounts {
                    combined_attempts: AtomicU64,
                    combined_delegated: AtomicU64,
                    combined_successes: AtomicU64,
                    record_attempts: AtomicU64,
                    record_delegated: AtomicU64,
                    record_successes: AtomicU64,
                    reissue_attempts: AtomicU64,
                    reissue_delegated: AtomicU64,
                    reissue_successes: AtomicU64,
                    bounded_read_attempts: AtomicU64,
                    bounded_present_reads: AtomicU64,
                    other_mutation_attempts: AtomicU64,
                    other_mutation_delegated: AtomicU64,
                    other_mutation_successes: AtomicU64,
                    boundary_callbacks: AtomicU32,
                }

                impl AtomicCounts {
                    fn snapshot(&self) -> Counts {
                        Counts {
                            boundary_callbacks: u64::from(self.boundary_callbacks.load(Ordering::SeqCst)),
                            combined_attempts: self.combined_attempts.load(Ordering::SeqCst),
                            combined_delegated: self.combined_delegated.load(Ordering::SeqCst),
                            combined_successes: self.combined_successes.load(Ordering::SeqCst),
                            record_attempts: self.record_attempts.load(Ordering::SeqCst),
                            record_delegated: self.record_delegated.load(Ordering::SeqCst),
                            record_successes: self.record_successes.load(Ordering::SeqCst),
                            reissue_attempts: self.reissue_attempts.load(Ordering::SeqCst),
                            reissue_delegated: self.reissue_delegated.load(Ordering::SeqCst),
                            reissue_successes: self.reissue_successes.load(Ordering::SeqCst),
                            bounded_read_attempts: self.bounded_read_attempts.load(Ordering::SeqCst),
                            bounded_present_reads: self.bounded_present_reads.load(Ordering::SeqCst),
                            other_mutation_attempts: self.other_mutation_attempts.load(Ordering::SeqCst),
                            other_mutation_delegated: self.other_mutation_delegated.load(Ordering::SeqCst),
                            other_mutation_successes: self.other_mutation_successes.load(Ordering::SeqCst),
                        }
                    }
                }

                #[derive(Clone, Copy, Debug, PartialEq, Eq)]
                enum BoundaryMode {
                    AbortAfterWitness,
                    ContinueAfterWitness,
                }

                struct Expected {
                    nonce: [u8; NONCE_LEN],
                    suite: u16,
                    public_key: Vec<u8>,
                    vote_wire: Vec<u8>,
                    preimage: Vec<u8>,
                    position: SigningPosition,
                    position_key: [u8; POSITION_LEN],
                    binding: BindingDigest,
                }

                struct BoundaryEvidence {
                    mode: BoundaryMode,
                    marker: Box<[u8; MARKER_LEN]>,
                    file: std::fs::File,
                    expected: Expected,
                    baseline: Counts,
                    signer: Arc<AtomicU32>,
                    sink: Arc<AtomicU32>,
                    publication_entries: Arc<AtomicU32>,
                    publication_returns: Arc<AtomicU32>,
                    fired: bool,
                }

                struct ObservedRocksStore {
                    inner: Arc<RocksDbConsensusStorage>,
                    counters: Arc<AtomicCounts>,
                    boundary: Mutex<Option<BoundaryEvidence>>,
                    fail_reissue: AtomicBool,
                }

                impl ObservedRocksStore {
                    fn new(inner: Arc<RocksDbConsensusStorage>) -> Self {
                        Self {
                            inner,
                            counters: Arc::new(AtomicCounts::default()),
                            boundary: Mutex::new(None),
                            fail_reissue: AtomicBool::new(false),
                        }
                    }

                    fn arm_boundary(&self, evidence: BoundaryEvidence) {
                        let mut slot = self.boundary.lock().expect("boundary mutex");
                        assert!(slot.is_none(), "one boundary may be armed per wrapper");
                        *slot = Some(evidence);
                    }

                    fn counts(&self) -> Counts {
                        self.counters.snapshot()
                    }

                    fn fail_reissue(&self, fail: bool) {
                        self.fail_reissue.store(fail, Ordering::SeqCst);
                    }

                    fn record_success_witness(&self, key: &[u8], envelope: &[u8]) {
                        let mut guard = self.boundary.lock().expect("boundary mutex");
                        let Some(evidence) = guard.as_mut() else {
                            return;
                        };
                        if evidence.fired {
                            return;
                        }
                        evidence.fired = true;
                        self.counters.boundary_callbacks.fetch_add(1, Ordering::SeqCst);
                        let now = self.counters.snapshot();
                        assert_eq!(
                            now.boundary_callbacks - evidence.baseline.boundary_callbacks,
                            1,
                            "one actual storage callback reached the armed boundary",
                        );
                        assert_eq!(key, &evidence.expected.position_key[..], "actual key matches independently prepared position");
                        let view = crate::signing_journal_admission::BorrowedRecordView::parse(envelope)
                            .expect("submitted record envelope structure and checksums");
                        assert_eq!(view.magic, b"QSJ1", "record magic");
                        assert_eq!(view.version, SIGNING_RECORD_FORMAT_VERSION, "record format");
                        assert_eq!(view.kind_tag, 1, "Vote kind tag");
                        assert_eq!(view.stage_tag, 2, "Signed stage tag");
                        let mut genesis = [0u8; 32];
                        genesis.copy_from_slice(view.network_genesis);
                        let position = SigningPosition {
                            validator_id: view.validator_id,
                            network_genesis: genesis,
                            kind: SigningKind::Vote,
                            originating_view: view.originating_view,
                        };
                        let mut encoded_key = [0u8; POSITION_LEN];
                        let encoded_len = position.encode_key_into(&mut encoded_key)
                            .expect("fixed position key encoding");
                        assert_eq!(encoded_len, POSITION_LEN, "fixed position key length");
                        assert_eq!(key, &encoded_key[..], "record identity encodes to actual storage key");
                        assert_eq!(encoded_key, evidence.expected.position_key, "record identity matches independent expected key");
                        assert_eq!(view.binding, &evidence.expected.binding.0[..], "record binding matches prepared decision");
                        assert_eq!(view.signature.len(), SIGNATURE_LEN, "submitted signature length");
                        assert_eq!(
                            evidence.signer.load(Ordering::SeqCst), 1,
                            "one real signer invocation before publication",
                        );
                        assert_eq!(evidence.sink.load(Ordering::SeqCst), 0, "no completion sink before publication returns");
                        assert_eq!(evidence.publication_entries.load(Ordering::SeqCst), 1, "publication API entered once");
                        assert_eq!(evidence.publication_returns.load(Ordering::SeqCst), 0, "publication API has not returned");
                        let delta = |value: u64, base: u64| value - base;
                        assert_eq!(delta(now.combined_attempts, evidence.baseline.combined_attempts), 1, "one combined reservation attempt");
                        assert_eq!(delta(now.combined_delegated, evidence.baseline.combined_delegated), 1, "one combined reservation delegate call");
                        assert_eq!(delta(now.combined_successes, evidence.baseline.combined_successes), 1, "one successful combined reservation write");
                        assert_eq!(delta(now.bounded_read_attempts, evidence.baseline.bounded_read_attempts), 2, "reservation plus publication validation perform two bounded reads");
                        assert_eq!(delta(now.bounded_present_reads, evidence.baseline.bounded_present_reads), 1, "publication validation found the Reserved record");
                        assert_eq!(delta(now.record_attempts, evidence.baseline.record_attempts), 1, "one record-only publication attempt");
                        assert_eq!(delta(now.record_delegated, evidence.baseline.record_delegated), 1, "one real record-only delegate call");
                        assert_eq!(delta(now.record_successes, evidence.baseline.record_successes), 1, "native synced write returned success");
                        assert_eq!(delta(now.reissue_attempts, evidence.baseline.reissue_attempts), 0, "no reissue");
                        assert_eq!(delta(now.reissue_delegated, evidence.baseline.reissue_delegated), 0, "no reissue delegation");
                        assert_eq!(delta(now.reissue_successes, evidence.baseline.reissue_successes), 0, "no reissue acknowledgement");
                        assert_eq!(delta(now.other_mutation_attempts, evidence.baseline.other_mutation_attempts), 0, "no other mutation");
                        assert_eq!(delta(now.other_mutation_delegated, evidence.baseline.other_mutation_delegated), 0, "no other mutation delegation");
                        assert_eq!(delta(now.other_mutation_successes, evidence.baseline.other_mutation_successes), 0, "no other mutation acknowledgement");

                        let marker = &mut evidence.marker[..];
                        for (i, value) in [
                            u32::try_from(delta(now.boundary_callbacks, evidence.baseline.boundary_callbacks)).expect("bounded boundary count"),
                            evidence.signer.load(Ordering::SeqCst),
                            evidence.sink.load(Ordering::SeqCst),
                            evidence.publication_entries.load(Ordering::SeqCst),
                            evidence.publication_returns.load(Ordering::SeqCst),
                            u32::try_from(delta(now.record_attempts, evidence.baseline.record_attempts)).expect("bounded count"),
                            u32::try_from(delta(now.record_delegated, evidence.baseline.record_delegated)).expect("bounded count"),
                            u32::try_from(delta(now.record_successes, evidence.baseline.record_successes)).expect("bounded count"),
                        ].into_iter().enumerate() {
                            let offset = OFF_COUNTS + i * 4;
                            marker[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                        }
                        marker[OFF_NATIVE_ACK] = 1;
                        marker[OFF_WRAPPER_RETURN] = 0;
                        marker[OFF_POSITION..OFF_POSITION + POSITION_LEN].copy_from_slice(&encoded_key);
                        marker[OFF_SIGNATURE_LEN..SIGNATURE_OFFSET]
                            .copy_from_slice(&u16::try_from(view.signature.len()).expect("signature length fits u16").to_le_bytes());
                        marker[SIGNATURE_OFFSET..].copy_from_slice(view.signature);
                        use std::io::Write as _;
                        evidence.file.write_all(marker).expect("write complete boundary marker");
                        evidence.file.flush().expect("flush boundary marker");
                        evidence.file.sync_all().expect("sync boundary marker");
                        if evidence.mode == BoundaryMode::AbortAfterWitness {
                            std::process::abort();
                        }
                    }
                }

                impl SigningJournalStorage for ObservedRocksStore {
                    fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
                        self.inner.get_signing_record(key)
                    }

                    fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
                        self.counters.other_mutation_attempts.fetch_add(1, Ordering::SeqCst);
                        self.counters.other_mutation_delegated.fetch_add(1, Ordering::SeqCst);
                        let result = self.inner.put_signing_record_synced(key, value);
                        if result.is_ok() {
                            self.counters.other_mutation_successes.fetch_add(1, Ordering::SeqCst);
                        }
                        result
                    }

                    fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
                        self.inner.get_signing_metadata()
                    }

                    fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
                        self.counters.other_mutation_attempts.fetch_add(1, Ordering::SeqCst);
                        self.counters.other_mutation_delegated.fetch_add(1, Ordering::SeqCst);
                        let result = self.inner.put_signing_metadata_synced(value);
                        if result.is_ok() {
                            self.counters.other_mutation_successes.fetch_add(1, Ordering::SeqCst);
                        }
                        result
                    }

                    fn put_signing_record_and_metadata_synced(
                        &self, key: &[u8], record: &[u8], metadata: &[u8],
                    ) -> Result<(), StorageError> {
                        self.counters.combined_attempts.fetch_add(1, Ordering::SeqCst);
                        self.counters.combined_delegated.fetch_add(1, Ordering::SeqCst);
                        let result = self.inner.put_signing_record_and_metadata_synced(key, record, metadata);
                        if result.is_ok() {
                            self.counters.combined_successes.fetch_add(1, Ordering::SeqCst);
                        }
                        result
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
                        &self, key: &[u8], dst: &mut [u8],
                    ) -> Result<Option<usize>, BoundedStorageError> {
                        self.counters.bounded_read_attempts.fetch_add(1, Ordering::SeqCst);
                        let result = self.inner.read_signing_envelope_into(key, dst)?;
                        if result.is_some() {
                            self.counters.bounded_present_reads.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(result)
                    }

                    fn reissue_signing_envelope_synced(
                        &self, key: &[u8], envelope: &[u8],
                    ) -> Result<(), BoundedStorageError> {
                        self.counters.reissue_attempts.fetch_add(1, Ordering::SeqCst);
                        if self.fail_reissue.load(Ordering::SeqCst) {
                            return Err(BoundedStorageError::Io(BoundedDiag::WriteIo));
                        }
                        self.counters.reissue_delegated.fetch_add(1, Ordering::SeqCst);
                        let result = self.inner.reissue_signing_envelope_synced(key, envelope);
                        if result.is_ok() {
                            self.counters.reissue_successes.fetch_add(1, Ordering::SeqCst);
                        }
                        result
                    }

                    fn put_signing_envelope_and_metadata_synced(
                        &self, key: &[u8], record: &[u8], metadata: &[u8],
                    ) -> Result<(), BoundedStorageError> {
                        self.counters.combined_attempts.fetch_add(1, Ordering::SeqCst);
                        self.counters.combined_delegated.fetch_add(1, Ordering::SeqCst);
                        let result = self.inner.put_signing_envelope_and_metadata_synced(key, record, metadata);
                        if result.is_ok() {
                            self.counters.combined_successes.fetch_add(1, Ordering::SeqCst);
                        }
                        result
                    }

                    fn put_signing_record_envelope_synced(
                        &self, key: &[u8], envelope: &[u8],
                    ) -> Result<(), BoundedStorageError> {
                        self.counters.record_attempts.fetch_add(1, Ordering::SeqCst);
                        self.counters.record_delegated.fetch_add(1, Ordering::SeqCst);
                        let result = self.inner.put_signing_record_envelope_synced(key, envelope);
                        if result.is_ok() {
                            self.counters.record_successes.fetch_add(1, Ordering::SeqCst);
                            self.record_success_witness(key, envelope);
                        }
                        result
                    }
                }

                struct Setup {
                    pv: ProposalVoteAuthority,
                    sk: Vec<u8>,
                    owner: SafetyRecordOwner,
                    engine: BasicHotStuffEngine<[u8; 32]>,
                    decided: DecidedVote<OwningCapturePayload>,
                    proposal: BlockProposal,
                    limits: PreparedDecisionInputLimits,
                    store: Arc<ObservedRocksStore>,
                    journal: SigningReservationJournal,
                }

                fn setup(
                    fixture: &std::path::Path,
                    safety_dir: &std::path::Path,
                    journal_dir: &std::path::Path,
                    initialize_journal: bool,
                ) -> Setup {
                    let (pk, sk) = read_fixture_file(fixture);
                    let pv = authority_from_pk(pk);
                    let ctx = retained_ctx(4);
                    let (owner, engine, decided, proposal, limits, _) =
                        capture_multi_with_suite(safety_dir, &ctx, MODEL_SUITE_U16);
                    let concrete = reopen_open_journal_store(journal_dir);
                    let store = Arc::new(ObservedRocksStore::new(concrete.clone()));
                    let wrapped_domain = store.signing_ownership_domain();
                    let concrete_domain = concrete.signing_ownership_domain();
                    assert!(Arc::ptr_eq(&wrapped_domain, &concrete_domain), "wrapper forwards the same ownership domain");
                    drop(wrapped_domain);
                    drop(concrete_domain);
                    let journal = if initialize_journal {
                        reopen_assoc_journal_init(
                            &owner,
                            store.clone() as Arc<dyn SigningJournalStorage>,
                            1,
                        )
                    } else {
                        reopen_assoc_journal_open(
                            &owner,
                            store.clone() as Arc<dyn SigningJournalStorage>,
                            1,
                        )
                    };
                    Setup { pv, sk, owner, engine, decided, proposal, limits, store, journal }
                }

                fn expected(setup: &Setup, nonce: [u8; NONCE_LEN]) -> Expected {
                    let vote = setup.decided.vote();
                    let vote_wire = unsigned_vote_wire(vote);
                    let preimage = setup.pv.signing_domain.vote_preimage(vote);
                    let (position, binding) = retained_pos_binding(&setup.pv, vote);
                    let (suite, public_key) = setup.pv.key_provider
                        .get_suite_and_key(ValidatorId::new(SIGNER_VID))
                        .expect("fixture authorized key");
                    assert_eq!(suite, SUITE_PQ_RESERVED_1, "authorized suite is 100");
                    assert_eq!(public_key.len(), PK_LEN, "authorized key has fixed length");
                    let mut position_key = [0u8; POSITION_LEN];
                    assert_eq!(position.encode_key_into(&mut position_key).expect("position key"), POSITION_LEN);
                    Expected {
                        nonce,
                        suite: MODEL_SUITE_U16,
                        public_key,
                        vote_wire,
                        preimage,
                        position,
                        position_key,
                        binding,
                    }
                }

                fn build_marker(expected: &Expected) -> Box<[u8; MARKER_LEN]> {
                    assert_eq!(MARKER_LEN, 4211);
                    assert_eq!(expected.public_key.len(), PK_LEN);
                    assert_eq!(expected.vote_wire.len(), VOTE_LEN);
                    assert!(!expected.preimage.is_empty() && expected.preimage.len() <= PREIMAGE_CAP);
                    let mut marker = Box::new([0u8; MARKER_LEN]);
                    marker[0..4].copy_from_slice(&MAGIC);
                    marker[4..6].copy_from_slice(&VERSION.to_le_bytes());
                    marker[6] = PHASE;
                    marker[OFF_NONCE..OFF_NONCE + NONCE_LEN].copy_from_slice(&expected.nonce);
                    marker[OFF_SUITE..OFF_SUITE + 2].copy_from_slice(&expected.suite.to_le_bytes());
                    marker[OFF_PK_LEN..OFF_PK_LEN + 2].copy_from_slice(&(PK_LEN as u16).to_le_bytes());
                    marker[OFF_PK..OFF_PK + PK_LEN].copy_from_slice(&expected.public_key);
                    marker[OFF_VOTE_LEN..OFF_VOTE_LEN + 2].copy_from_slice(&(VOTE_LEN as u16).to_le_bytes());
                    marker[OFF_VOTE..OFF_VOTE + VOTE_LEN].copy_from_slice(&expected.vote_wire);
                    marker[OFF_PREIMAGE_LEN..OFF_PREIMAGE_LEN + 2]
                        .copy_from_slice(&(expected.preimage.len() as u16).to_le_bytes());
                    marker[OFF_PREIMAGE..OFF_PREIMAGE + expected.preimage.len()]
                        .copy_from_slice(&expected.preimage);
                    marker[OFF_POSITION..OFF_POSITION + POSITION_LEN]
                        .copy_from_slice(&expected.position_key);
                    marker[OFF_BINDING..OFF_BINDING + 32].copy_from_slice(&expected.binding.0);
                    marker[OFF_SIGNATURE_LEN..OFF_SIGNATURE_LEN + 2]
                        .copy_from_slice(&(SIGNATURE_LEN as u16).to_le_bytes());
                    marker
                }

                fn open_marker(path: &std::path::Path) -> std::fs::File {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                        .expect("exclusively create mode-0600 marker before protected route")
                }

                fn arm(
                    setup: &Setup,
                    expected: Expected,
                    path: &std::path::Path,
                    mode: BoundaryMode,
                    signer: Arc<AtomicU32>,
                    sink: Arc<AtomicU32>,
                    entries: Arc<AtomicU32>,
                    returns: Arc<AtomicU32>,
                ) {
                    let marker = build_marker(&expected);
                    let file = open_marker(path);
                    let baseline = setup.store.counts();
                    setup.store.arm_boundary(BoundaryEvidence {
                        mode,
                        marker,
                        file,
                        expected,
                        baseline,
                        signer,
                        sink,
                        publication_entries: entries,
                        publication_returns: returns,
                        fired: false,
                    });
                }

                struct Witness {
                    nonce: [u8; NONCE_LEN],
                    counts: [u32; 8],
                    native_ack: u8,
                    wrapper_return: u8,
                    suite: u16,
                    public_key: Vec<u8>,
                    vote: Vote,
                    vote_wire: Vec<u8>,
                    preimage: Vec<u8>,
                    position_key: [u8; POSITION_LEN],
                    binding: [u8; 32],
                    signature: Vec<u8>,
                }

                fn get_u16(bytes: &[u8], offset: usize) -> usize {
                    u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize
                }

                fn get_u32(bytes: &[u8], offset: usize) -> u32 {
                    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed marker count"))
                }

                fn decode_vote(bytes: &[u8]) -> Result<Vote, &'static str> {
                    use qbind_wire::io::WireDecode as _;
                    let mut input = bytes;
                    let vote = Vote::decode(&mut input).map_err(|_| "Vote encoding")?;
                    if !input.is_empty() {
                        return Err("Vote trailing bytes");
                    }
                    if !vote.signature.is_empty() {
                        return Err("Vote inline signature");
                    }
                    if vote.suite_id != MODEL_SUITE_U16 {
                        return Err("Vote suite");
                    }
                    Ok(vote)
                }

                fn parse_marker(
                    bytes: &[u8],
                    expected_nonce: &[u8; NONCE_LEN],
                ) -> Result<Witness, &'static str> {
                    if bytes.len() != MARKER_LEN { return Err("marker length"); }
                    if bytes[0..4] != MAGIC { return Err("magic"); }
                    if get_u16(bytes, 4) != VERSION as usize { return Err("version"); }
                    if bytes[6] != PHASE { return Err("phase"); }
                    let nonce: [u8; NONCE_LEN] = bytes[OFF_NONCE..OFF_NONCE + NONCE_LEN]
                        .try_into().map_err(|_| "nonce")?;
                    if &nonce != expected_nonce { return Err("invocation nonce"); }
                    let counts = std::array::from_fn(|i| get_u32(bytes, OFF_COUNTS + i * 4));
                    if counts != [1, 1, 0, 1, 0, 1, 1, 1] { return Err("boundary counters"); }
                    let native_ack = bytes[OFF_NATIVE_ACK];
                    let wrapper_return = bytes[OFF_WRAPPER_RETURN];
                    if (native_ack, wrapper_return) != (1, 0) { return Err("storage acknowledgement flags"); }
                    let suite = get_u16(bytes, OFF_SUITE) as u16;
                    if suite != MODEL_SUITE_U16 { return Err("authorized suite"); }
                    if get_u16(bytes, OFF_PK_LEN) != PK_LEN { return Err("public-key length"); }
                    let public_key = bytes[OFF_PK..OFF_PK + PK_LEN].to_vec();
                    if get_u16(bytes, OFF_VOTE_LEN) != VOTE_LEN { return Err("Vote length"); }
                    let vote_wire = bytes[OFF_VOTE..OFF_VOTE + VOTE_LEN].to_vec();
                    let vote = decode_vote(&vote_wire)?;
                    if vote.suite_id != suite { return Err("Vote and authorized suite disagreement"); }
                    let preimage_len = get_u16(bytes, OFF_PREIMAGE_LEN);
                    if preimage_len == 0 || preimage_len > PREIMAGE_CAP { return Err("preimage length"); }
                    let padded = &bytes[OFF_PREIMAGE..OFF_PREIMAGE + PREIMAGE_CAP];
                    if padded[preimage_len..].iter().any(|byte| *byte != 0) {
                        return Err("preimage padding");
                    }
                    let preimage = padded[..preimage_len].to_vec();
                    let position_key = bytes[OFF_POSITION..OFF_POSITION + POSITION_LEN]
                        .try_into().map_err(|_| "position key")?;
                    let binding = bytes[OFF_BINDING..OFF_BINDING + 32]
                        .try_into().map_err(|_| "binding")?;
                    if get_u16(bytes, OFF_SIGNATURE_LEN) != SIGNATURE_LEN { return Err("signature length"); }
                    let signature = bytes[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].to_vec();
                    Ok(Witness {
                        nonce, counts, native_ack, wrapper_return, suite, public_key, vote,
                        vote_wire, preimage, position_key, binding, signature,
                    })
                }

                fn read_marker(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
                    let file = std::fs::File::open(path)?;
                    let mut limited = file.take((MARKER_LEN + 1) as u64);
                    let mut bytes = Vec::with_capacity(MARKER_LEN + 1);
                    limited.read_to_end(&mut bytes)?;
                    Ok(bytes)
                }

                fn accepts(class: TermClass, raw: &[u8], nonce: &[u8; NONCE_LEN]) -> bool {
                    class == TermClass::Signaled(EXPECTED_ABORT_SIGNAL)
                        && parse_marker(raw, nonce).is_ok()
                }

                fn spawn_child(
                    mode: &str,
                    fixture: &std::path::Path,
                    marker: &std::path::Path,
                    nonce: &[u8; NONCE_LEN],
                    safety: &std::path::Path,
                    journal: &std::path::Path,
                ) -> OwnedChild {
                    let child = std::process::Command::new(std::env::current_exe().expect("test executable"))
                        .args(["--exact", CHILD_PATH, "--ignored", "--nocapture", "--test-threads=1"])
                        .env(ENV_MODE, mode)
                        .env(ENV_FIXTURE, fixture)
                        .env(ENV_MARKER, marker)
                        .env(ENV_NONCE, nonce_to_hex(nonce))
                        .env(ENV_SAFETY, safety)
                        .env(ENV_JOURNAL, journal)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .expect("spawn exact ignored child entrypoint");
                    OwnedChild::new(child)
                }

                fn marker_vote() -> Vec<u8> {
                    use qbind_wire::io::WireEncode as _;
                    let vote = Vote {
                        version: 1,
                        chain_id: 7,
                        epoch: 4,
                        height: 1,
                        round: 0,
                        step: 1,
                        block_id: [0xB2; 32],
                        validator_index: 2,
                        suite_id: MODEL_SUITE_U16,
                        signature: Vec::new(),
                    };
                    let mut bytes = Vec::with_capacity(VOTE_LEN);
                    vote.encode(&mut bytes);
                    assert_eq!(bytes.len(), VOTE_LEN);
                    bytes
                }

                fn parser_fixture(nonce: [u8; NONCE_LEN]) -> Box<[u8; MARKER_LEN]> {
                    let expected = Expected {
                        nonce,
                        suite: MODEL_SUITE_U16,
                        public_key: vec![0xA1; PK_LEN],
                        vote_wire: marker_vote(),
                        preimage: vec![0xC3; 32],
                        position: SigningPosition {
                            validator_id: 2,
                            network_genesis: [0xD4; 32],
                            kind: SigningKind::Vote,
                            originating_view: 1,
                        },
                        position_key: {
                            let mut key = [0u8; POSITION_LEN];
                            let _ = SigningPosition {
                                validator_id: 2,
                                network_genesis: [0xD4; 32],
                                kind: SigningKind::Vote,
                                originating_view: 1,
                            }.encode_key_into(&mut key);
                            key
                        },
                        binding: BindingDigest([0xE5; 32]),
                    };
                    let mut marker = build_marker(&expected);
                    for (i, count) in [1u32, 1, 0, 1, 0, 1, 1, 1].into_iter().enumerate() {
                        marker[OFF_COUNTS + i * 4..OFF_COUNTS + i * 4 + 4]
                            .copy_from_slice(&count.to_le_bytes());
                    }
                    marker[OFF_NATIVE_ACK] = 1;
                    marker[OFF_WRAPPER_RETURN] = 0;
                    marker[SIGNATURE_OFFSET..].fill(0x5A);
                    marker
                }

                fn assert_domain_shared(store: &ObservedRocksStore, concrete: &RocksDbConsensusStorage) {
                    let wrapped = store.signing_ownership_domain();
                    let inner = concrete.signing_ownership_domain();
                    assert!(Arc::ptr_eq(&wrapped, &inner), "observed wrapper preserves inner domain identity");
                }

                fn assert_counts_delta(after: Counts, before: Counts, expected: Counts) {
                    assert_eq!(after.boundary_callbacks - before.boundary_callbacks, expected.boundary_callbacks);
                    assert_eq!(after.combined_attempts - before.combined_attempts, expected.combined_attempts);
                    assert_eq!(after.combined_delegated - before.combined_delegated, expected.combined_delegated);
                    assert_eq!(after.combined_successes - before.combined_successes, expected.combined_successes);
                    assert_eq!(after.record_attempts - before.record_attempts, expected.record_attempts);
                    assert_eq!(after.record_delegated - before.record_delegated, expected.record_delegated);
                    assert_eq!(after.record_successes - before.record_successes, expected.record_successes);
                    assert_eq!(after.reissue_attempts - before.reissue_attempts, expected.reissue_attempts);
                    assert_eq!(after.reissue_delegated - before.reissue_delegated, expected.reissue_delegated);
                    assert_eq!(after.reissue_successes - before.reissue_successes, expected.reissue_successes);
                    assert_eq!(after.bounded_read_attempts - before.bounded_read_attempts, expected.bounded_read_attempts);
                    assert_eq!(after.bounded_present_reads - before.bounded_present_reads, expected.bounded_present_reads);
                    assert_eq!(after.other_mutation_attempts - before.other_mutation_attempts, expected.other_mutation_attempts);
                    assert_eq!(after.other_mutation_delegated - before.other_mutation_delegated, expected.other_mutation_delegated);
                    assert_eq!(after.other_mutation_successes - before.other_mutation_successes, expected.other_mutation_successes);
                }

                #[test]
                #[ignore = "re-executed only by the post-write process-death supervisor"]
                fn child_entry() {
                    let Some(mode) = std::env::var_os(ENV_MODE) else { return; };
                    let mode = mode.to_string_lossy().into_owned();
                    if mode == "setup_failure" {
                        std::process::exit(3);
                    }
                    if mode == "wrong_signal" {
                        unsafe { libc::raise(libc::SIGTERM); }
                        std::process::exit(0);
                    }
                    let fixture = std::path::PathBuf::from(std::env::var_os(ENV_FIXTURE).expect("fixture"));
                    let marker_path = std::path::PathBuf::from(std::env::var_os(ENV_MARKER).expect("marker"));
                    let safety_dir = std::path::PathBuf::from(std::env::var_os(ENV_SAFETY).expect("safety store"));
                    let journal_dir = std::path::PathBuf::from(std::env::var_os(ENV_JOURNAL).expect("journal store"));
                    let nonce = hex_to_nonce(&std::env::var(ENV_NONCE).expect("nonce"));
                    let setup = setup(&fixture, &safety_dir, &journal_dir, true);
                    let expected = expected(&setup, nonce);
                    let signer_obs = Arc::new(AtomicU32::new(0));
                    let sink_obs = Arc::new(AtomicU32::new(0));
                    let entries = Arc::new(AtomicU32::new(0));
                    let returns = Arc::new(AtomicU32::new(0));
                    let exit_normally = mode == "continue_then_exit";
                    let boundary_mode = if exit_normally {
                        BoundaryMode::ContinueAfterWitness
                    } else {
                        assert_eq!(mode, "abort_after_write", "recognized child mode");
                        BoundaryMode::AbortAfterWitness
                    };
                    arm(
                        &setup, expected, &marker_path, boundary_mode, signer_obs.clone(), sink_obs.clone(),
                        entries.clone(), returns.clone(),
                    );
                    let inner = real_local_signer(&setup.sk);
                    let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                    let mut sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                    let mut snapshot = established_snapshot(&setup.pv);
                    let mut coord = ModelCoordinationHook::publication_observing(entries.clone())
                        .with_publication_return_observer(returns.clone());
                    assert!(coord.publication_attempts.as_ref().is_some_and(|v| Arc::ptr_eq(v, &entries)));
                    assert!(coord.publication_returns.as_ref().is_some_and(|v| Arc::ptr_eq(v, &returns)));
                    let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                        &setup.owner, &setup.engine, &setup.decided, &setup.proposal, &setup.limits,
                        None, &mut snapshot, &signer, &mut sink, &setup.journal, &mut coord,
                        ReconfirmPerturbation::None,
                    );
                    assert!(matches!(outcome, RealFreshSignOutcome::Published(_)), "unchanged protected route completed");
                    assert_eq!(signer.calls(), 1);
                    assert_eq!(sink.calls, 1);
                    assert_eq!(entries.load(Ordering::SeqCst), 1);
                    assert_eq!(returns.load(Ordering::SeqCst), 1);
                    if exit_normally {
                        std::process::exit(0);
                    }
                    panic!("abort-after-write hook returned unexpectedly");
                }

                #[test]
                fn marker_parser_and_classifier_controls() {
                    assert_eq!(MARKER_LEN, 4211);
                    let nonce = [0x31; NONCE_LEN];
                    let mut valid = parser_fixture(nonce);
                    let parsed = parse_marker(&valid[..], &nonce).expect("valid complete marker");
                    assert_eq!(parsed.counts, [1, 1, 0, 1, 0, 1, 1, 1]);
                    assert_eq!((parsed.native_ack, parsed.wrapper_return), (1, 0));
                    assert_eq!(parsed.signature.len(), SIGNATURE_LEN);
                    assert!(accepts(TermClass::Signaled(EXPECTED_ABORT_SIGNAL), &valid[..], &nonce));
                    assert!(!accepts(TermClass::Exited(0), &valid[..], &nonce));
                    assert!(!accepts(TermClass::Signaled(libc::SIGTERM), &valid[..], &nonce));
                    assert!(!accepts(TermClass::TimedOutKilled { kill_confirmed: true }, &valid[..], &nonce));
                    assert!(!accepts(
                        TermClass::Signaled(EXPECTED_ABORT_SIGNAL),
                        &valid[..MARKER_LEN - 1],
                        &nonce,
                    ));
                    let mut bad_magic = valid.clone();
                    bad_magic[0] ^= 1;
                    assert!(parse_marker(&bad_magic[..], &nonce).is_err());
                    let mut bad_version = valid.clone();
                    bad_version[4] ^= 1;
                    assert!(parse_marker(&bad_version[..], &nonce).is_err());
                    assert!(parse_marker(&valid[..], &[0x32; NONCE_LEN]).is_err());
                    assert!(parse_marker(&valid[..MARKER_LEN - 1], &nonce).is_err());
                    let mut long = valid.to_vec();
                    long.push(0);
                    assert!(parse_marker(&long, &nonce).is_err());

                    for (offset, value) in [(6, 0u8), (55, 0u8), (56, 1u8)] {
                        let mut bad = valid.clone();
                        bad[offset] = value;
                        assert!(parse_marker(&bad[..], &nonce).is_err(), "phase/ack flag is rejected");
                    }
                    for index in 0..8 {
                        let mut bad = valid.clone();
                        bad[OFF_COUNTS + index * 4] ^= 1;
                        assert!(parse_marker(&bad[..], &nonce).is_err(), "counter field is rejected");
                    }
                    for (offset, bytes) in [
                        (OFF_PK_LEN, 0u16.to_le_bytes()),
                        (OFF_VOTE_LEN, 68u16.to_le_bytes()),
                        (OFF_PREIMAGE_LEN, 0u16.to_le_bytes()),
                        (OFF_PREIMAGE_LEN, ((PREIMAGE_CAP + 1) as u16).to_le_bytes()),
                        (OFF_SIGNATURE_LEN, ((SIGNATURE_LEN - 1) as u16).to_le_bytes()),
                    ] {
                        let mut bad = valid.clone();
                        bad[offset..offset + 2].copy_from_slice(&bytes);
                        assert!(parse_marker(&bad[..], &nonce).is_err(), "invalid length is rejected");
                    }
                    let mut bad_padding = valid.clone();
                    bad_padding[OFF_PREIMAGE + 32] = 1;
                    assert!(parse_marker(&bad_padding[..], &nonce).is_err());
                    let mut malformed = valid.clone();
                    malformed[OFF_VOTE] = 0;
                    assert_eq!(parse_marker(&malformed[..], &nonce).err(), Some("Vote encoding"));


                    let wrong_suite_input = marker_vote();
                    let mut wrong_suite_slice = wrong_suite_input.as_slice();
                    let mut wrong_suite_vote =
                        <Vote as qbind_wire::io::WireDecode>::decode(&mut wrong_suite_slice)
                        .expect("valid fixture Vote decodes");
                    wrong_suite_vote.suite_id = MODEL_SUITE_U16 + 1;
                    let mut wrong_suite_wire = Vec::new();
                    qbind_wire::io::WireEncode::encode(&wrong_suite_vote, &mut wrong_suite_wire);
                    let mut wrong_suite = valid.clone();
                    wrong_suite[OFF_VOTE..OFF_VOTE + VOTE_LEN].copy_from_slice(&wrong_suite_wire);
                    assert_eq!(parse_marker(&wrong_suite[..], &nonce).err(), Some("Vote suite"));

                    // These are helper-level controls, not valid fixed-width marker Votes.
                    let mut trailing = marker_vote();
                    trailing.push(0);
                    assert_eq!(decode_vote(&trailing).err(), Some("Vote trailing bytes"));
                    let valid_vote_wire = marker_vote();
                    let mut input = valid_vote_wire.as_slice();
                    let mut inline_signature =
                        <Vote as qbind_wire::io::WireDecode>::decode(&mut input)
                            .expect("fixture Vote decodes");
                    inline_signature.signature.push(0x5A);
                    let mut signed_vote = Vec::new();
                    qbind_wire::io::WireEncode::encode(&inline_signature, &mut signed_vote);
                    assert_eq!(signed_vote.len(), VOTE_LEN + 1);
                    assert_eq!(decode_vote(&signed_vote).err(), Some("Vote inline signature"));
                    valid[OFF_SIGNATURE_LEN..OFF_SIGNATURE_LEN + 2]
                        .copy_from_slice(&((SIGNATURE_LEN + 1) as u16).to_le_bytes());
                    assert!(parse_marker(&valid[..], &nonce).is_err());
                }

                #[test]
                fn supervisor_rejects_valid_marker_ordinary_exit_and_setup_failures() {
                    let harness = tempfile::tempdir().expect("harness directory");
                    let fixture = harness.path().join("suite100.bin");
                    let marker = harness.path().join("marker.bin");
                    let safety = harness.path().join("safety");
                    let journal = harness.path().join("journal");
                    std::fs::create_dir(&safety).expect("safety directory");
                    std::fs::create_dir(&journal).expect("journal directory");
                    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("suite-100 keypair");
                    write_fixture_file(&fixture, &pk, &sk);
                    let nonce = urandom_nonce();

                    let mut child = spawn_child(
                        "continue_then_exit", &fixture, &marker, &nonce, &safety, &journal,
                    );
                    let status = child.supervise(STATUS_DEADLINE).expect("ordinary child reaped");
                    assert_eq!(status, TermClass::Exited(0));
                    let bytes = read_marker(&marker).expect("real successful route wrote witness");
                    assert!(parse_marker(&bytes, &nonce).is_ok(), "marker is valid independent of process status");
                    assert!(!accepts(status, &bytes, &nonce), "ordinary exit cannot be classified as the boundary");

                    let setup_marker = harness.path().join("setup-failure.bin");
                    let mut setup_child = spawn_child(
                        "setup_failure", &fixture, &setup_marker, &nonce, &safety, &journal,
                    );
                    assert_eq!(
                        setup_child.supervise(STATUS_DEADLINE).expect("setup-failure child reaped"),
                        TermClass::Exited(3),
                    );
                    assert!(read_marker(&setup_marker).is_err(), "setup failure has no witness");

                    let wrong_signal_marker = harness.path().join("wrong-signal.bin");
                    let mut wrong_signal = spawn_child(
                        "wrong_signal", &fixture, &wrong_signal_marker, &nonce, &safety, &journal,
                    );
                    assert_eq!(
                        wrong_signal.supervise(STATUS_DEADLINE).expect("wrong-signal child reaped"),
                        TermClass::Signaled(libc::SIGTERM),
                    );
                    assert!(read_marker(&wrong_signal_marker).is_err(), "wrong signal has no witness");
                }

                #[test]
                fn supervisor_timeout_uses_existing_bounded_kill_and_reap() {
                    let child = std::process::Command::new("sleep")
                        .arg("600")
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .expect("spawn direct timeout fixture");
                    let mut owned = OwnedChild::new(child);
                    assert!(matches!(
                        owned.supervise(Duration::from_millis(200)).expect("timeout kill and reap"),
                        TermClass::TimedOutKilled { kill_confirmed: true }
                    ));
                }

                #[test]
                fn normal_control_publishes_and_retires_the_witnessed_signature() {
                    let harness = tempfile::tempdir().expect("harness directory");
                    let fixture = harness.path().join("suite100.bin");
                    let marker_path = harness.path().join("marker.bin");
                    let safety = harness.path().join("safety");
                    let journal_dir = harness.path().join("journal");
                    std::fs::create_dir(&safety).expect("safety directory");
                    std::fs::create_dir(&journal_dir).expect("journal directory");
                    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("suite-100 keypair");
                    write_fixture_file(&fixture, &pk, &sk);
                    let nonce = urandom_nonce();
                    let run = setup(&fixture, &safety, &journal_dir, true);
                    let expected = expected(&run, nonce);
                    let base_vote = run.decided.vote().clone();
                    let signer_obs = Arc::new(AtomicU32::new(0));
                    let sink_obs = Arc::new(AtomicU32::new(0));
                    let entries = Arc::new(AtomicU32::new(0));
                    let returns = Arc::new(AtomicU32::new(0));
                    let expected_position = expected.position;
                    arm(
                        &run, expected, &marker_path, BoundaryMode::ContinueAfterWitness,
                        signer_obs.clone(), sink_obs.clone(), entries.clone(), returns.clone(),
                    );
                    let inner = real_local_signer(&sk);
                    let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                    let mut sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                    let mut snapshot = established_snapshot(&run.pv);
                    let mut coord = ModelCoordinationHook::publication_observing(entries.clone())
                        .with_publication_return_observer(returns.clone());
                    assert!(coord.publication_attempts.as_ref().is_some_and(|v| Arc::ptr_eq(v, &entries)));
                    assert!(coord.publication_returns.as_ref().is_some_and(|v| Arc::ptr_eq(v, &returns)));
                    let baseline = run.store.counts();
                    let ledgers = snapshot_ledgers(&run.owner);
                    let provenance = pin_provenance_now(&run.owner, &run.decided);
                    let op_ceiling = run.owner.backend_for_test().accounting_cap();
                    let agg_ceiling = run.owner.backend_for_test().accounting_aggregate_cap();
                    let accountant = run.owner.backend_for_test().accounting_handle_for_test();
                    let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                        &run.owner, &run.engine, &run.decided, &run.proposal, &run.limits,
                        None, &mut snapshot, &signer, &mut sink, &run.journal, &mut coord,
                        ReconfirmPerturbation::None,
                    );
                    assert_cleanup_preserved(&run.owner, &run.decided, &base_vote, ledgers, provenance, "post-write normal control");
                    assert_eq!(run.owner.backend_for_test().accounting_cap(), op_ceiling);
                    assert_eq!(run.owner.backend_for_test().accounting_aggregate_cap(), agg_ceiling);
                    let diag = match outcome {
                        RealFreshSignOutcome::Published(diag) => diag,
                        other => panic!("expected Published from unchanged route: {other:?}"),
                    };
                    assert_eq!(diag.retirement, RetirementReport::Retired);
                    assert_eq!((signer.calls(), sink.calls), (1, 1));
                    assert_eq!((entries.load(Ordering::SeqCst), returns.load(Ordering::SeqCst)), (1, 1));
                    assert_eq!((signer_obs.load(Ordering::SeqCst), sink_obs.load(Ordering::SeqCst)), (1, 1));
                    assert_counts_delta(run.store.counts(), baseline, Counts {
                        boundary_callbacks: 1,
                        combined_attempts: 1, combined_delegated: 1, combined_successes: 1,
                        record_attempts: 1, record_delegated: 1, record_successes: 1,
                        bounded_read_attempts: 2, bounded_present_reads: 1,
                        ..Counts::default()
                    });

                    let raw = read_marker(&marker_path).expect("control witness file");
                    let witness = parse_marker(&raw, &nonce).expect("complete control marker");
                    assert_eq!((witness.counts, witness.native_ack, witness.wrapper_return),
                        ([1, 1, 0, 1, 0, 1, 1, 1], 1, 0));
                    let record_bytes = run.store.get_signing_record(&witness.position_key)
                        .expect("stored result read").expect("Signed record");
                    let record = SigningDecisionRecord::decode(&record_bytes).expect("Signed record decode");
                    assert_eq!(record.stage, SigningRecordStage::Signed);
                    assert_eq!(record.position, expected_position);
                    assert!(record.retained_signature.as_deref()
                        .is_some_and(|sig| sig == witness.signature.as_slice()), "submitted and stored signature bytes match");
                    MlDsa44Backend::verify(&witness.public_key, &witness.preimage, &witness.signature)
                        .expect("original submitted signature verifies");
                    assert_eq!(run.journal.reserved_position_count(), 1);

                    drop(coord);
                    drop(snapshot);
                    drop(sink);
                    drop(signer);
                    drop(inner);
                    drop(record);
                    drop(record_bytes);
                    drop(witness);
                    drop(raw);
                    drop(base_vote);
                    drop(run);
                    assert_eq!(accountant.current(), 0, "normal control operational ledger returns to zero");
                    assert_eq!(accountant.aggregate().current(), 0, "normal control aggregate ledger returns to zero");
                }

                #[test]
                fn postwrite_death_reopens_signed_and_requires_checked_reissue() {
                    let harness = tempfile::tempdir().expect("harness directory");
                    let fixture = harness.path().join("suite100.bin");
                    let marker_path = harness.path().join("marker.bin");
                    let safety_dir = harness.path().join("safety");
                    let journal_dir = harness.path().join("journal");
                    std::fs::create_dir(&safety_dir).expect("safety directory");
                    std::fs::create_dir(&journal_dir).expect("journal directory");
                    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("suite-100 keypair");
                    write_fixture_file(&fixture, &pk, &sk);
                    let nonce = urandom_nonce();

                    let mut child = spawn_child(
                        "abort_after_write", &fixture, &marker_path, &nonce, &safety_dir, &journal_dir,
                    );
                    let class = child.supervise(STATUS_DEADLINE).expect("boundary child reaped");
                    assert_eq!(class, TermClass::Signaled(EXPECTED_ABORT_SIGNAL));
                    let raw = read_marker(&marker_path).expect("boundary witness exists");
                    assert!(accepts(class, &raw, &nonce), "only SIGABRT plus complete invocation-matched witness is accepted");
                    let witness = parse_marker(&raw, &nonce).expect("complete submitted-record witness");
                    assert_eq!(witness.nonce, nonce);
                    assert_eq!((witness.counts, witness.native_ack, witness.wrapper_return),
                        ([1, 1, 0, 1, 0, 1, 1, 1], 1, 0));
                    assert!(witness.public_key == pk, "witness key matches transported authorized key");
                    assert!(witness.vote.signature.is_empty(), "witness contains the complete unsigned Vote");
                    assert_eq!(witness.suite, MODEL_SUITE_U16);
                    MlDsa44Backend::verify(&witness.public_key, &witness.preimage, &witness.signature)
                        .expect("original witnessed signature verifies; no second signing occurs");

                    // Reopen both stores through attach/open only. The wrapper is
                    // installed before open associates it with this process's journal.
                    let ctx = retained_ctx(4);
                    let pv = authority_from_pk(pk.clone());
                    let owner = reopen_attach(&safety_dir, &ctx);
                    let concrete = reopen_open_journal_store(&journal_dir);
                    let observed = Arc::new(ObservedRocksStore::new(concrete.clone()));
                    assert_domain_shared(&observed, &concrete);
                    let journal = reopen_assoc_journal_open(
                        &owner, observed.clone() as Arc<dyn SigningJournalStorage>, 1,
                    );

                    // Before O2/O3/O5, use the marker key only to identify the
                    // actual surviving Signed record and its independent metadata.
                    let record_pre = observed.get_signing_record(&witness.position_key)
                        .expect("surviving record read").expect("synced Signed envelope survived");
                    let metadata_pre = observed.get_signing_metadata()
                        .expect("surviving metadata read").expect("reservation metadata survived");
                    let count_pre = journal.reserved_position_count();
                    let record = SigningDecisionRecord::decode(&record_pre).expect("surviving envelope decodes");
                    assert_eq!(record.stage, SigningRecordStage::Signed);
                    assert_eq!(record.position.storage_key(), witness.position_key);
                    assert_eq!(record.binding.0, witness.binding);
                    let stored_signature = record.retained_signature.as_ref().expect("Signed record retains signature").clone();
                    assert!(stored_signature == witness.signature, "surviving signature equals exact child-submitted signature");
                    assert_eq!(count_pre, 1, "the position remains reserved after process death");
                    drop(record);

                    // Ordinary O2/O3/O5 recovery applies only to safety state. O2/O3
                    // leave recovery required; successful O5 acknowledges that state.
                    let (mut engine, proposal, l0_block) =
                        engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
                    let limits = lim_b(&ctx);
                    let recovery_free = snapshot_ledgers(&owner);
                    let op_ceiling = owner.backend_for_test().accounting_cap();
                    let agg_ceiling = owner.backend_for_test().accounting_aggregate_cap();
                    let revision = reopen_b_recover_only(&owner, &engine, l0_block);
                    assert_eq!(snapshot_ledgers(&owner), recovery_free, "proof-free O5 recovery baseline restored");
                    assert_eq!(owner.backend_for_test().accounting_cap(), op_ceiling);
                    assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), agg_ceiling);
                    assert_eq!(
                        observed.get_signing_record(&witness.position_key).expect("post-O5 record read").as_deref(),
                        Some(record_pre.as_slice()),
                        "O5 leaves the independent journal record bytes unchanged",
                    );
                    assert_eq!(
                        observed.get_signing_metadata().expect("post-O5 metadata read").as_deref(),
                        Some(metadata_pre.as_slice()),
                        "O5 leaves journal metadata unchanged",
                    );
                    assert_eq!(journal.reserved_position_count(), count_pre, "O5 preserves reserved-position count");

                    let capture_proof = owner.read_validate(None::<&FixtureCommittedHistory>)
                        .expect("new surviving O3 proof for fixture capture");
                    let decided = match owner.decide_and_capture_owned(
                        &mut engine, ValidatorId::new(2), &proposal, &limits, revision, capture_proof,
                    ) {
                        OwnedDecisionOutcome::Decided(value) => value,
                        other => panic!("surviving fixture decision/capture: {other:?}"),
                    };
                    let vote = decided.vote();
                    let vote_wire = unsigned_vote_wire(vote);
                    let preimage = pv.signing_domain.vote_preimage(vote);
                    let (position, binding) = retained_pos_binding(&pv, vote);
                    let (authorized_suite, authorized_key) = pv.key_provider
                        .get_suite_and_key(ValidatorId::new(SIGNER_VID))
                        .expect("fixture authorized key");
                    assert_eq!(authorized_suite, SUITE_PQ_RESERVED_1);
                    assert!(vote_wire == witness.vote_wire, "surviving complete Vote matches child witness");
                    assert!(preimage == witness.preimage, "surviving signing preimage matches child witness");
                    assert!(position.storage_key() == witness.position_key, "surviving position matches child witness");
                    assert!(binding.0 == witness.binding, "surviving binding matches child witness");
                    assert!(authorized_key == witness.public_key, "surviving authorized key matches child witness");
                    let base_vote = vote.clone();
                    let accountant = owner.backend_for_test().accounting_handle_for_test();

                    // Independent protected fresh-route refusal. The route itself
                    // records its signer and sink calls; connected API observers
                    // prove no publication entry or return occurred.
                    let mut fresh_snapshot = established_snapshot(&pv);
                    let inner = real_local_signer(&sk);
                    let signer_obs = Arc::new(AtomicU32::new(0));
                    let sink_obs = Arc::new(AtomicU32::new(0));
                    let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                    let mut fresh_sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                    let entries = Arc::new(AtomicU32::new(0));
                    let returns = Arc::new(AtomicU32::new(0));
                    let mut fresh_coord = ModelCoordinationHook::publication_observing(entries.clone())
                        .with_publication_return_observer(returns.clone());
                    let fresh_ledgers = snapshot_ledgers(&owner);
                    let fresh_provenance = pin_provenance_now(&owner, &decided);
                    let fresh_op_ceiling = owner.backend_for_test().accounting_cap();
                    let fresh_agg_ceiling = owner.backend_for_test().accounting_aggregate_cap();
                    let fresh_record = observed.get_signing_record(&position.storage_key()).unwrap().unwrap();
                    let fresh_metadata = observed.get_signing_metadata().unwrap().unwrap();
                    let fresh_count = journal.reserved_position_count();
                    let fresh_counts = observed.counts();
                    let fresh = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &proposal, &limits, None, &mut fresh_snapshot,
                        &signer, &mut fresh_sink, &journal, &mut fresh_coord, ReconfirmPerturbation::None,
                    );
                    assert_cleanup_preserved(&owner, &decided, &base_vote, fresh_ledgers, fresh_provenance, "fresh refusal after surviving post-write record");
                    assert_eq!(owner.backend_for_test().accounting_cap(), fresh_op_ceiling);
                    assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), fresh_agg_ceiling);
                    assert_eq!(fresh, RealFreshSignOutcome::ReservePotentiallySigned);
                    assert_eq!((signer.calls(), fresh_sink.calls), (0, 0));
                    assert_eq!((signer_obs.load(Ordering::SeqCst), sink_obs.load(Ordering::SeqCst)), (0, 0));
                    assert_eq!((entries.load(Ordering::SeqCst), returns.load(Ordering::SeqCst)), (0, 0));
                    assert_counts_delta(observed.counts(), fresh_counts, Counts {
                        bounded_read_attempts: 1, bounded_present_reads: 1,
                        ..Counts::default()
                    });
                    assert_eq!(observed.get_signing_record(&position.storage_key()).unwrap().as_deref(), Some(fresh_record.as_slice()));
                    assert_eq!(observed.get_signing_metadata().unwrap().as_deref(), Some(fresh_metadata.as_slice()));
                    assert_eq!(journal.reserved_position_count(), fresh_count);

                    // AssociationChecked retained delivery: a failed reissue is
                    // injected before delegation and suppresses both probe and sink.
                    let fail_ledgers = snapshot_ledgers(&owner);
                    let fail_provenance = pin_provenance_now(&owner, &decided);
                    let fail_op_ceiling = owner.backend_for_test().accounting_cap();
                    let fail_agg_ceiling = owner.backend_for_test().accounting_aggregate_cap();
                    let fail_record = observed.get_signing_record(&position.storage_key()).unwrap().unwrap();
                    let fail_metadata = observed.get_signing_metadata().unwrap().unwrap();
                    let fail_count = journal.reserved_position_count();
                    let fail_counts = observed.counts();
                    observed.fail_reissue(true);
                    let fail_probe = std::rc::Rc::new(RetainedSliceProbe::new(
                        RetainedSliceWitness::from_validated(&witness.signature),
                    ));
                    let fail_probe_guard = install_retained_slice_probe(fail_probe.clone());
                    let mut fail_sink = RetainedUseRecordingSink::new();
                    let mut retained_coord = ModelCoordinationHook::inert();
                    let failed_delivery = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &proposal, &limits, None, &mut fresh_snapshot,
                        &mut fail_sink, &journal, &mut retained_coord, ReconfirmPerturbation::None,
                    );
                    drop(fail_probe_guard);
                    assert_cleanup_preserved(&owner, &decided, &base_vote, fail_ledgers, fail_provenance, "failed checked reissue");
                    assert_eq!(owner.backend_for_test().accounting_cap(), fail_op_ceiling);
                    assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), fail_agg_ceiling);
                    assert_eq!(failed_delivery, ModelRetainedUseOutcome::DeliverySuppressed);
                    assert_eq!((fail_probe.invocations(), fail_sink.calls), (0, 0));
                    assert_counts_delta(observed.counts(), fail_counts, Counts {
                        bounded_read_attempts: 1, bounded_present_reads: 1,
                        reissue_attempts: 1,
                        ..Counts::default()
                    });
                    assert_eq!(observed.get_signing_record(&position.storage_key()).unwrap().as_deref(), Some(fail_record.as_slice()));
                    assert_eq!(observed.get_signing_metadata().unwrap().as_deref(), Some(fail_metadata.as_slice()));
                    assert_eq!(journal.reserved_position_count(), fail_count);

                    // Clear the fault and retry only the same checked retained route.
                    observed.fail_reissue(false);
                    let ok_ledgers = snapshot_ledgers(&owner);
                    let ok_provenance = pin_provenance_now(&owner, &decided);
                    let ok_op_ceiling = owner.backend_for_test().accounting_cap();
                    let ok_agg_ceiling = owner.backend_for_test().accounting_aggregate_cap();
                    let ok_record = observed.get_signing_record(&position.storage_key()).unwrap().unwrap();
                    let ok_metadata = observed.get_signing_metadata().unwrap().unwrap();
                    let ok_count = journal.reserved_position_count();
                    let ok_counts = observed.counts();
                    let ok_probe = std::rc::Rc::new(RetainedSliceProbe::new(
                        RetainedSliceWitness::from_validated(&witness.signature),
                    ));
                    let ok_probe_guard = install_retained_slice_probe(ok_probe.clone());
                    let mut ok_sink = RetainedUseRecordingSink::new();
                    let delivered = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &proposal, &limits, None, &mut fresh_snapshot,
                        &mut ok_sink, &journal, &mut retained_coord, ReconfirmPerturbation::None,
                    );
                    drop(ok_probe_guard);
                    assert_cleanup_preserved(&owner, &decided, &base_vote, ok_ledgers, ok_provenance, "successful checked reissue");
                    assert_eq!(owner.backend_for_test().accounting_cap(), ok_op_ceiling);
                    assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), ok_agg_ceiling);
                    assert!(matches!(delivered, ModelRetainedUseOutcome::Consumed(_)));
                    assert_eq!((ok_probe.invocations(), ok_probe.last_len()), (1, Some(SIGNATURE_LEN)));
                    assert_eq!(ok_probe.last_matched(), Some(true), "the verified slice equals the child-submitted signature");
                    assert_eq!(ok_sink.calls, 1);
                    assert_counts_delta(observed.counts(), ok_counts, Counts {
                        bounded_read_attempts: 1, bounded_present_reads: 1,
                        reissue_attempts: 1, reissue_delegated: 1, reissue_successes: 1,
                        ..Counts::default()
                    });
                    assert!(stored_signature == witness.signature, "checked result remains the same original Signed bytes");
                    assert_eq!(observed.get_signing_record(&position.storage_key()).unwrap().as_deref(), Some(ok_record.as_slice()));
                    assert_eq!(observed.get_signing_metadata().unwrap().as_deref(), Some(ok_metadata.as_slice()));
                    assert_eq!(journal.reserved_position_count(), ok_count);

                    drop(fail_probe);
                    drop(ok_probe);
                    drop(fail_sink);
                    drop(ok_sink);
                    drop(retained_coord);
                    drop(fresh_coord);
                    drop(fresh_snapshot);
                    drop(signer);
                    drop(inner);
                    drop(decided);
                    drop(engine);
                    drop(journal);
                    drop(observed);
                    drop(concrete);
                    drop(owner);
                    drop(pv);
                    drop(ctx);
                    drop(proposal);
                    drop(base_vote);
                    drop(stored_signature);
                    drop(witness);
                    drop(raw);
                    drop(record_pre);
                    drop(metadata_pre);
                    drop(fresh_record);
                    drop(fresh_metadata);
                    drop(fail_record);
                    drop(fail_metadata);
                    drop(ok_record);
                    drop(ok_metadata);
                    assert_eq!(accountant.current(), 0, "surviving operational ledger reaches exactly zero");
                    assert_eq!(accountant.aggregate().current(), 0, "surviving aggregate ledger reaches exactly zero");
                }
            }
            mod postsign_prepublication {
                use super::*;
                use crate::signing_reservation_journal::{
                    BoundedStorageError, SigningDecisionRecord, SigningJournalStorage,
                    SigningOwnershipDomain, SigningRecordStage, SigningReservationJournal,
                };
                use crate::storage::StorageError;
                use std::sync::atomic::{AtomicU32, Ordering};
                use std::sync::Arc;

                const MAGIC: [u8; 4] = *b"R4S2";
                const VERSION: u16 = 1;
                const PHASE: u8 = 0x17;
                const NONCE_LEN: usize = 16;
                const PK_LEN: usize = qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE;
                const VOTE_LEN: usize = 69;
                const PREIMAGE_CAP: usize = MODEL_MAX_PREIMAGE_BYTES as usize;
                const POSITION_LEN: usize = crate::signing_journal_admission::JOURNAL_KEY_LEN;
                const SIGNATURE_LEN: usize = qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE;
                const MARKER_LEN: usize = POST_SIGN_MARKER_LEN;
                const MARKER_CHILD_PATH: &str = "safety_record_store::owner::model::tests::real_fresh_sign::postconsume_process_death::postsign_prepublication::postsign_child_entry";
                const ENV_MODE: &str = "R422_PSP_CHILD_MODE";
                const ENV_FIXTURE: &str = "R422_PSP_FIXTURE";
                const ENV_MARKER: &str = "R422_PSP_MARKER";
                const ENV_NONCE: &str = "R422_PSP_NONCE";
                const ENV_SAFETY: &str = "R422_PSP_SAFETY";
                const ENV_JOURNAL: &str = "R422_PSP_JOURNAL";

                const STATUS_DEADLINE: Duration = Duration::from_secs(30);

                #[derive(Debug, PartialEq, Eq)]
                struct Witness {
                    nonce: [u8; NONCE_LEN],
                    hook_calls: u32,
                    signer_calls: u32,
                    sink_calls: u32,
                    publication_calls: u32,
                    public_key: Vec<u8>,
                    unsigned_vote: Vec<u8>,
                    preimage: Vec<u8>,
                    position_key: Vec<u8>,
                    binding: [u8; 32],
                    signature: Vec<u8>,
                }

                fn write_u16(dst: &mut [u8], offset: usize, value: usize) {
                    let value = u16::try_from(value).expect("fixed marker field fits u16");
                    dst[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
                }

                fn build_marker(
                    nonce: &[u8; NONCE_LEN],
                    public_key: &[u8],
                    unsigned_vote: &[u8],
                    preimage: &[u8],
                    position_key: &[u8],
                    binding: &[u8; 32],
                ) -> Box<[u8; MARKER_LEN]> {
                    assert_eq!(MARKER_LEN, 4193);
                    assert_eq!(public_key.len(), PK_LEN);
                    assert_eq!(unsigned_vote.len(), VOTE_LEN);
                    assert!(!preimage.is_empty() && preimage.len() <= PREIMAGE_CAP);
                    assert_eq!(position_key.len(), POSITION_LEN);
                    assert_eq!(SIGNATURE_LEN, crate::signing_journal_admission::OUTPUT_CAP);
                    let mut marker = Box::new([0u8; MARKER_LEN]);
                    marker[..4].copy_from_slice(&MAGIC);
                    marker[4..6].copy_from_slice(&VERSION.to_le_bytes());
                    marker[6] = PHASE;
                    marker[7..23].copy_from_slice(nonce);
                    write_u16(&mut marker[..], POST_SIGN_PK_OFFSET - 2, PK_LEN);
                    marker[POST_SIGN_PK_OFFSET..POST_SIGN_VOTE_LEN_OFFSET]
                        .copy_from_slice(public_key);
                    write_u16(&mut marker[..], POST_SIGN_VOTE_LEN_OFFSET, VOTE_LEN);
                    marker[POST_SIGN_VOTE_OFFSET..POST_SIGN_PREIMAGE_LEN_OFFSET]
                        .copy_from_slice(unsigned_vote);
                    write_u16(&mut marker[..], POST_SIGN_PREIMAGE_LEN_OFFSET, preimage.len());
                    marker[POST_SIGN_PREIMAGE_OFFSET..POST_SIGN_PREIMAGE_OFFSET + preimage.len()]
                        .copy_from_slice(preimage);
                    marker[POST_SIGN_POSITION_OFFSET..POST_SIGN_BINDING_OFFSET]
                        .copy_from_slice(position_key);
                    marker[POST_SIGN_BINDING_OFFSET..POST_SIGN_SIGNATURE_LEN_OFFSET]
                        .copy_from_slice(binding);
                    marker
                }

                fn decode_unsigned_suite_vote(bytes: &[u8]) -> Result<Vote, &'static str> {
                    use qbind_wire::io::WireDecode as _;
                    let mut input = bytes;
                    let vote = Vote::decode(&mut input).map_err(|_| "Vote encoding")?;
                    if !input.is_empty() {
                        return Err("Vote trailing bytes");
                    }
                    if !vote.signature.is_empty() {
                        return Err("Vote inline signature");
                    }
                    if vote.suite_id != MODEL_SUITE_U16 {
                        return Err("Vote suite");
                    }
                    Ok(vote)
                }

                fn parse_marker(bytes: &[u8], expected_nonce: &[u8; NONCE_LEN]) -> Result<Witness, &'static str> {
                    if bytes.len() != MARKER_LEN { return Err("marker length"); }
                    if bytes[..4] != MAGIC { return Err("magic"); }
                    if u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION { return Err("version"); }
                    if bytes[6] != PHASE { return Err("phase"); }
                    let nonce: [u8; NONCE_LEN] = bytes[7..23].try_into().map_err(|_| "nonce")?;
                    if &nonce != expected_nonce { return Err("invocation nonce"); }
                    let u32_at = |offset: usize| {
                        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed count"))
                    };
                    let hook_calls = u32_at(23);
                    let signer_calls = u32_at(27);
                    let sink_calls = u32_at(31);
                    let publication_calls = u32_at(35);
                    if (hook_calls, signer_calls, sink_calls, publication_calls) != (1, 1, 0, 0) {
                        return Err("live observations");
                    }
                    if bytes[39] != 1 { return Err("committed output flag"); }
                    if bytes[40] != 0 { return Err("publication source-position flag"); }
                    let u16_at = |offset: usize| {
                        u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize
                    };
                    if u16_at(41) != PK_LEN { return Err("public-key length"); }
                    let public_key = bytes[POST_SIGN_PK_OFFSET..POST_SIGN_VOTE_LEN_OFFSET].to_vec();
                    if u16_at(POST_SIGN_VOTE_LEN_OFFSET) != VOTE_LEN { return Err("Vote length"); }
                    let unsigned_vote =
                        bytes[POST_SIGN_VOTE_OFFSET..POST_SIGN_PREIMAGE_LEN_OFFSET].to_vec();
                    decode_unsigned_suite_vote(&unsigned_vote)?;
                    let preimage_len = u16_at(POST_SIGN_PREIMAGE_LEN_OFFSET);
                    if preimage_len == 0 || preimage_len > PREIMAGE_CAP {
                        return Err("preimage length");
                    }
                    let padded = &bytes[POST_SIGN_PREIMAGE_OFFSET..POST_SIGN_POSITION_OFFSET];
                    if padded[preimage_len..].iter().any(|byte| *byte != 0) {
                        return Err("preimage padding");
                    }
                    let preimage = padded[..preimage_len].to_vec();
                    let position_key =
                        bytes[POST_SIGN_POSITION_OFFSET..POST_SIGN_BINDING_OFFSET].to_vec();
                    let binding = bytes[POST_SIGN_BINDING_OFFSET..POST_SIGN_SIGNATURE_LEN_OFFSET]
                        .try_into().map_err(|_| "binding")?;
                    if u16_at(POST_SIGN_SIGNATURE_LEN_OFFSET) != SIGNATURE_LEN {
                        return Err("signature length");
                    }
                    let signature = bytes[POST_SIGN_SIGNATURE_OFFSET..].to_vec();
                    Ok(Witness {
                        nonce,
                        hook_calls,
                        signer_calls,
                        sink_calls,
                        publication_calls,
                        public_key,
                        unsigned_vote,
                        preimage,
                        position_key,
                        binding,
                        signature,
                    })
                }

                fn read_marker_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
                    let file = std::fs::File::open(path)?;
                    let mut limited = file.take((MARKER_LEN + 1) as u64);
                    let mut bytes = Vec::with_capacity(MARKER_LEN + 1);
                    limited.read_to_end(&mut bytes)?;
                    Ok(bytes)
                }

                fn open_marker(path: &std::path::Path) -> std::fs::File {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                        .expect("exclusively create marker before protected operation")
                }

                fn accepts(class: TermClass, raw: &[u8], nonce: &[u8; NONCE_LEN]) -> bool {
                    class == TermClass::Signaled(EXPECTED_ABORT_SIGNAL)
                        && parse_marker(raw, nonce).is_ok()
                }

                #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
                struct StoreCounts(PostSignStorageCounts);

                struct ObservedBoundaryRocksStore {
                    inner: Arc<RocksDbConsensusStorage>,
                    counters: Arc<PostSignStorageCounters>,
                }

                impl ObservedBoundaryRocksStore {
                    fn new(inner: Arc<RocksDbConsensusStorage>) -> Self {
                        Self { inner, counters: Arc::new(PostSignStorageCounters::default()) }
                    }

                    fn counts(&self) -> StoreCounts {
                        StoreCounts(self.counters.snapshot())
                    }
                }

                impl SigningJournalStorage for ObservedBoundaryRocksStore {
                    fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
                        self.inner.get_signing_record(key)
                    }
                    fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
                        self.counters.other_mutations.fetch_add(1, Ordering::SeqCst);
                        self.inner.put_signing_record_synced(key, value)
                    }
                    fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
                        self.inner.get_signing_metadata()
                    }
                    fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
                        self.counters.other_mutations.fetch_add(1, Ordering::SeqCst);
                        self.inner.put_signing_metadata_synced(value)
                    }
                    fn put_signing_record_and_metadata_synced(
                        &self, key: &[u8], record: &[u8], metadata: &[u8],
                    ) -> Result<(), StorageError> {
                        self.counters.combined_reservation_writes.fetch_add(1, Ordering::SeqCst);
                        self.inner.put_signing_record_and_metadata_synced(key, record, metadata)
                    }
                    fn for_each_signing_namespace_entry(
                        &self, visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
                    ) -> Result<(), StorageError> {
                        self.inner.for_each_signing_namespace_entry(visitor)
                    }
                    fn signing_ownership_domain(&self) -> Arc<SigningOwnershipDomain> {
                        self.inner.signing_ownership_domain()
                    }
                    fn read_signing_envelope_into(
                        &self, key: &[u8], dst: &mut [u8],
                    ) -> Result<Option<usize>, BoundedStorageError> {
                        self.counters.bounded_read_attempts.fetch_add(1, Ordering::SeqCst);
                        let result = self.inner.read_signing_envelope_into(key, dst)?;
                        if result.is_some() {
                            self.counters.bounded_present_reads.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(result)
                    }
                    fn reissue_signing_envelope_synced(
                        &self, key: &[u8], envelope: &[u8],
                    ) -> Result<(), BoundedStorageError> {
                        self.counters.reissue_attempts.fetch_add(1, Ordering::SeqCst);
                        self.counters.reissue_delegated_writes.fetch_add(1, Ordering::SeqCst);
                        self.inner.reissue_signing_envelope_synced(key, envelope)
                    }
                    fn put_signing_envelope_and_metadata_synced(
                        &self, key: &[u8], record: &[u8], metadata: &[u8],
                    ) -> Result<(), BoundedStorageError> {
                        self.counters.combined_reservation_writes.fetch_add(1, Ordering::SeqCst);
                        self.inner.put_signing_envelope_and_metadata_synced(key, record, metadata)
                    }
                    fn put_signing_record_envelope_synced(
                        &self, key: &[u8], record: &[u8],
                    ) -> Result<(), BoundedStorageError> {
                        self.counters.signed_record_only_writes.fetch_add(1, Ordering::SeqCst);
                        self.inner.put_signing_record_envelope_synced(key, record)
                    }
                }

                fn verify_same_domain(
                    observed: &ObservedBoundaryRocksStore,
                    backend: &RocksDbConsensusStorage,
                ) {
                    let wrapped_domain = observed.signing_ownership_domain();
                    let backend_domain = backend.signing_ownership_domain();
                    assert!(Arc::ptr_eq(&wrapped_domain, &backend_domain));
                    drop(wrapped_domain);
                    drop(backend_domain);
                }

                fn fixture_journal(
                    owner: &SafetyRecordOwner,
                    store: Arc<ObservedBoundaryRocksStore>,
                ) -> SigningReservationJournal {
                    let journal = SigningReservationJournal::initialize(
                        store as Arc<dyn SigningJournalStorage>,
                        1,
                    ).expect("initialize fresh child journal through observer");
                    journal.install_accountant_association(owner.backend_for_test().accounting())
                        .expect("install observer-backed accountant association");
                    journal.enter_bounded_live_mode(1).expect("bounded journal mode");
                    journal
                }

                fn spawn_child(
                    mode: &str,
                    fixture: &std::path::Path,
                    marker: &std::path::Path,
                    nonce: &[u8; NONCE_LEN],
                    safety: &std::path::Path,
                    journal: &std::path::Path,
                ) -> OwnedChild {
                    let nonce_hex = nonce_to_hex(nonce);
                    let child = std::process::Command::new(std::env::current_exe().expect("test executable"))
                        .args(["--exact", MARKER_CHILD_PATH, "--ignored", "--nocapture", "--test-threads=1"])
                        .env(ENV_MODE, mode)
                        .env(ENV_FIXTURE, fixture)
                        .env(ENV_MARKER, marker)
                        .env(ENV_NONCE, nonce_hex)
                        .env(ENV_SAFETY, safety)
                        .env(ENV_JOURNAL, journal)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .expect("spawn post-sign boundary child");
                    OwnedChild::new(child)
                }

                #[test]
                #[ignore = "re-executed child; only parent boundary tests drive it"]
                fn postsign_child_entry() {
                    let Some(mode) = std::env::var_os(ENV_MODE) else { return; };
                    let mode = mode.to_string_lossy().into_owned();
                    let fixture = std::path::PathBuf::from(std::env::var_os(ENV_FIXTURE).expect("fixture path"));
                    let marker_path = std::path::PathBuf::from(std::env::var_os(ENV_MARKER).expect("marker path"));
                    let safety_dir = std::path::PathBuf::from(std::env::var_os(ENV_SAFETY).expect("safety path"));
                    let journal_dir = std::path::PathBuf::from(std::env::var_os(ENV_JOURNAL).expect("journal path"));
                    let nonce = hex_to_nonce(&std::env::var(ENV_NONCE).expect("nonce"));
                    let (pk, sk) = read_fixture_file(&fixture);
                    let pv = authority_from_pk(pk.clone());
                    let ctx = retained_ctx(4);
                    let (owner, engine, decided, proposal, limits, _) =
                        capture_multi_with_suite(&safety_dir, &ctx, MODEL_SUITE_U16);
                    let concrete = reopen_open_journal_store(&journal_dir);
                    let observed = Arc::new(ObservedBoundaryRocksStore::new(concrete.clone()));
                    verify_same_domain(&observed, &concrete);
                    let journal = fixture_journal(&owner, observed.clone());
                    let vote = decided.vote();
                    let unsigned_vote = unsigned_vote_wire(vote);
                    let preimage = pv.signing_domain.vote_preimage(vote);
                    let (position, binding) = retained_pos_binding(&pv, vote);
                    let position_key = position.storage_key();
                    let (_suite, authorized_key) = pv.key_provider
                        .get_suite_and_key(ValidatorId::new(SIGNER_VID))
                        .expect("shared suite-100 public key");
                    let marker = build_marker(
                        &nonce, &authorized_key, &unsigned_vote, &preimage, &position_key, &binding.0,
                    );
                    let marker_file = open_marker(&marker_path);
                    let signer_obs = Arc::new(AtomicU32::new(0));
                    let sink_obs = Arc::new(AtomicU32::new(0));
                    let publication_calls = Arc::new(AtomicU32::new(0));
                    let store_baseline = observed.counts().0;
                    let inner = real_local_signer(&sk);
                    let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                    let mut sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                    let mut snapshot = established_snapshot(&pv);
                    let mut coord = ModelCoordinationHook::inert()
                        .with_post_sign_prepublication_evidence(PostSignPrePublicationEvidence::new(
                            marker,
                            marker_file,
                            nonce,
                            signer_obs,
                            sink_obs,
                            publication_calls,
                            observed.counters.clone(),
                            store_baseline,
                            mode == "abort",
                        ));
                    if mode == "invalid_observation" {
                        coord.post_sign_prepublication.as_mut().unwrap()
                            .sink_obs.store(1, Ordering::SeqCst);
                    }
                    let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &proposal, &limits, None, &mut snapshot,
                        &signer, &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                    );
                    if mode == "abort" {
                        panic!("post-sign boundary hook returned unexpectedly: {outcome:?}");
                    }
                    assert!(matches!(outcome, RealFreshSignOutcome::Published(_)));
                    assert_eq!(signer.calls(), 1);
                    assert_eq!(sink.calls, 1);
                }

                #[test]
                fn marker_layout_and_parser_rejections() {
                    assert_eq!(MARKER_LEN, 4193);
                    assert_eq!(POST_SIGN_SIGNATURE_OFFSET + SIGNATURE_LEN, MARKER_LEN);
                    let vote = Vote {
                        version: 1, chain_id: MODEL_WIRE_CHAIN_ID, epoch: 4, height: 1,
                        round: 1, step: 0, block_id: [0xB2; 32], validator_index: SIGNER_VID as u16,
                        suite_id: MODEL_SUITE_U16, signature: Vec::new(),
                    };
                    let unsigned = unsigned_vote_wire(&vote);
                    let nonce = [7u8; NONCE_LEN];
                    let marker = build_marker(&nonce, &[0xA1; PK_LEN], &unsigned, &[0xC3; 88], &[0xD4; POSITION_LEN], &[0xE5; 32]);
                    let mut valid = marker.to_vec();
                    valid[23..27].copy_from_slice(&1u32.to_le_bytes());
                    valid[27..31].copy_from_slice(&1u32.to_le_bytes());
                    valid[39] = 1;
                    valid[POST_SIGN_SIGNATURE_LEN_OFFSET..POST_SIGN_SIGNATURE_OFFSET]
                        .copy_from_slice(&(SIGNATURE_LEN as u16).to_le_bytes());
                    valid[POST_SIGN_SIGNATURE_OFFSET..].fill(0x5A);
                    // The fabricated signature is used only for parser-shape tests; it is never verified or delivered.
                    assert!(parse_marker(&valid, &nonce).is_ok());
                    assert!(parse_marker(&valid[..MARKER_LEN - 1], &nonce).is_err());
                    let mut bad = valid.clone(); bad.push(0);
                    assert!(parse_marker(&bad, &nonce).is_err());
                    for offset in [
                        0,
                        4,
                        6,
                        23,
                        27,
                        31,
                        35,
                        39,
                        40,
                        41,
                        POST_SIGN_VOTE_LEN_OFFSET,
                        POST_SIGN_SIGNATURE_LEN_OFFSET,
                    ] {
                        let mut bad = valid.clone(); bad[offset] ^= 1;
                        assert!(parse_marker(&bad, &nonce).is_err(), "corrupt marker offset {offset}");
                    }
                    assert!(parse_marker(&valid, &[8u8; NONCE_LEN]).is_err());
                    let mut bad = valid.clone();
                    bad[POST_SIGN_PREIMAGE_LEN_OFFSET..POST_SIGN_PREIMAGE_OFFSET]
                        .copy_from_slice(&0u16.to_le_bytes());
                    assert!(parse_marker(&bad, &nonce).is_err(), "empty preimage rejects");
                    let mut bad = valid.clone();
                    bad[POST_SIGN_PREIMAGE_LEN_OFFSET..POST_SIGN_PREIMAGE_OFFSET]
                        .copy_from_slice(&((PREIMAGE_CAP + 1) as u16).to_le_bytes());
                    assert!(parse_marker(&bad, &nonce).is_err(), "oversized preimage rejects");
                    let mut bad = valid.clone(); bad[POST_SIGN_PREIMAGE_OFFSET + 88] = 1;
                    assert!(parse_marker(&bad, &nonce).is_err());

                    let mut wrong_suite = vote.clone();
                    wrong_suite.suite_id = MODEL_SUITE_U16 + 1;
                    let mut wire = Vec::new();
                    qbind_wire::io::WireEncode::encode(&wrong_suite, &mut wire);
                    assert_eq!(wire.len(), VOTE_LEN);
                    let mut bad = valid.clone();
                    bad[POST_SIGN_VOTE_OFFSET..POST_SIGN_PREIMAGE_LEN_OFFSET]
                        .copy_from_slice(&wire);
                    assert_eq!(
                        parse_marker(&bad, &nonce),
                        Err("Vote suite"),
                        "the marker parser rejects a genuinely encoded wrong-suite Vote"
                    );

                    let mut malformed = valid.clone();
                    malformed[POST_SIGN_VOTE_OFFSET] = 0;
                    assert_eq!(
                        parse_marker(&malformed, &nonce),
                        Err("Vote encoding"),
                        "the marker parser rejects malformed Vote bytes"
                    );

                    let mut inline_sig = vote;
                    inline_sig.signature.push(0x5A);
                    let mut wire = Vec::new();
                    qbind_wire::io::WireEncode::encode(&inline_sig, &mut wire);
                    assert_eq!(wire.len(), VOTE_LEN + 1);
                    // This 70-byte encoding is helper-only; the fixed marker Vote
                    // field remains exactly 69 bytes.
                    assert_eq!(decode_unsigned_suite_vote(&wire), Err("Vote inline signature"));
                    let mut trailing = unsigned;
                    trailing.push(0);
                    // Trailing input is likewise exercised at helper level, not
                    // represented as a valid fixed-width marker Vote.
                    assert_eq!(decode_unsigned_suite_vote(&trailing), Err("Vote trailing bytes"));
                }

                #[test]
                fn hook_rejects_invalid_live_observation_without_complete_marker() {
                    let temp = tempfile::tempdir().unwrap();
                    let fixture = temp.path().join("keypair.bin");
                    let marker = temp.path().join("marker.bin");
                    let safety = temp.path().join("safety");
                    let journal = temp.path().join("journal");
                    std::fs::create_dir(&safety).unwrap();
                    std::fs::create_dir(&journal).unwrap();
                    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("suite-100 keygen");
                    write_fixture_file(&fixture, &pk, &sk);
                    let nonce = urandom_nonce();
                    let mut child = spawn_child("invalid_observation", &fixture, &marker, &nonce, &safety, &journal);
                    let class = child.supervise(STATUS_DEADLINE).expect("invalid-observation child reaped");
                    assert!(matches!(class, TermClass::Exited(code) if code != 0));
                    let raw = read_marker_bounded(&marker).expect("child created marker before route");
                    assert_eq!(raw.len(), 0, "invalid live observation writes no complete marker");
                    assert!(!accepts(class, &raw, &nonce));
                }

                #[test]
                fn valid_marker_with_ordinary_child_exit_is_rejected() {
                    let temp = tempfile::tempdir().unwrap();
                    let fixture = temp.path().join("keypair.bin");
                    let marker = temp.path().join("marker.bin");
                    let safety = temp.path().join("safety");
                    let journal = temp.path().join("journal");
                    std::fs::create_dir(&safety).unwrap();
                    std::fs::create_dir(&journal).unwrap();
                    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("suite-100 keygen");
                    write_fixture_file(&fixture, &pk, &sk);
                    let nonce = urandom_nonce();
                    let mut child = spawn_child("exit", &fixture, &marker, &nonce, &safety, &journal);
                    let class = child.supervise(STATUS_DEADLINE).expect("normal child reaped");
                    assert_eq!(class, TermClass::Exited(0));
                    let raw = read_marker_bounded(&marker).expect("complete marker was produced");
                    let witness = parse_marker(&raw, &nonce).expect("valid invocation marker");
                    assert_eq!(witness.public_key, pk);
                    assert!(!accepts(class, &raw, &nonce), "complete marker cannot replace intended signal");
                    let _ = sk;
                }

                #[test]
                fn postsign_prepublication_control_publishes_exact_witness() {
                    let temp = tempfile::tempdir().unwrap();
                    let fixture = temp.path().join("keypair.bin");
                    let marker_path = temp.path().join("marker.bin");
                    let safety_dir = temp.path().join("safety");
                    let journal_dir = temp.path().join("journal");
                    std::fs::create_dir(&safety_dir).unwrap();
                    std::fs::create_dir(&journal_dir).unwrap();
                    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("suite-100 keygen");
                    write_fixture_file(&fixture, &pk, &sk);
                    let (rpk, rsk) = read_fixture_file(&fixture);
                    assert!(rsk == sk, "fixture secret round-trip equality (contents redacted)");
                    let nonce = urandom_nonce();
                    let pv = authority_from_pk(rpk);
                    let ctx = retained_ctx(4);
                    let (owner, engine, decided, proposal, limits, _) =
                        capture_multi_with_suite(&safety_dir, &ctx, MODEL_SUITE_U16);
                    let base_vote = decided.vote().clone();
                    let concrete = reopen_open_journal_store(&journal_dir);
                    let observed = Arc::new(ObservedBoundaryRocksStore::new(concrete.clone()));
                    verify_same_domain(&observed, &concrete);
                    let journal = fixture_journal(&owner, observed.clone());
                    let vote = decided.vote();
                    let unsigned = unsigned_vote_wire(vote);
                    let preimage = pv.signing_domain.vote_preimage(vote);
                    let (position, binding) = retained_pos_binding(&pv, vote);
                    let (_suite, authorized_key) = pv.key_provider
                        .get_suite_and_key(ValidatorId::new(SIGNER_VID)).expect("authorized suite-100 key");
                    let marker = build_marker(&nonce, &authorized_key, &unsigned, &preimage, &position.storage_key(), &binding.0);
                    let file = open_marker(&marker_path);
                    let baseline = observed.counts().0;
                    let signer_obs = Arc::new(AtomicU32::new(0));
                    let sink_obs = Arc::new(AtomicU32::new(0));
                    let publication_calls = Arc::new(AtomicU32::new(0));
                    let inner = real_local_signer(&rsk);
                    let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                    let mut sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                    let mut snapshot = established_snapshot(&pv);
                    let mut coord = ModelCoordinationHook::inert()
                        .with_post_sign_prepublication_evidence(PostSignPrePublicationEvidence::new(
                            marker, file, nonce, signer_obs.clone(), sink_obs.clone(),
                            publication_calls.clone(), observed.counters.clone(), baseline, false,
                        ));
                    let base_ledgers = snapshot_ledgers(&owner);
                    let provenance = pin_provenance_now(&owner, &decided);
                    let op_ceiling = owner.backend_for_test().accounting_cap();
                    let agg_ceiling = owner.backend_for_test().accounting_aggregate_cap();
                    let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &proposal, &limits, None, &mut snapshot,
                        &signer, &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                    );
                    assert_cleanup_preserved(&owner, &decided, &base_vote, base_ledgers, provenance, "post-sign control");
                    assert_eq!(owner.backend_for_test().accounting_cap(), op_ceiling);
                    assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), agg_ceiling);
                    let diag = match outcome {
                        RealFreshSignOutcome::Published(d) => d,
                        other => panic!("same-hook control must publish: {other:?}"),
                    };
                    assert_eq!(diag.retirement, RetirementReport::Retired);
                    assert_eq!((signer.calls(), sink.calls, publication_calls.load(Ordering::SeqCst)), (1, 1, 1));
                    assert_eq!(signer_obs.load(Ordering::SeqCst), 1);
                    assert_eq!(sink_obs.load(Ordering::SeqCst), 1);
                    let counts = observed.counts().0;
                    assert_eq!(counts.combined_reservation_writes - baseline.combined_reservation_writes, 1);
                    assert_eq!(counts.signed_record_only_writes - baseline.signed_record_only_writes, 1);
                    assert_eq!(counts.reissue_attempts - baseline.reissue_attempts, 0);
                    let raw = read_marker_bounded(&marker_path).expect("hook witness exists");
                    let witness = parse_marker(&raw, &nonce).expect("valid committed-span witness");
                    assert_eq!(witness.public_key, authorized_key);
                    assert_eq!(witness.signature.len(), SIGNATURE_LEN);
                    MlDsa44Backend::verify(&witness.public_key, &witness.preimage, &witness.signature)
                        .expect("original committed signature verifies under exact preimage");
                    let stored = observed.get_signing_record(&position.storage_key())
                        .expect("stored result read").expect("Signed record");
                    let decoded = SigningDecisionRecord::decode(&stored).expect("decode Signed record");
                    assert_eq!(decoded.stage, SigningRecordStage::Signed);
                    assert!(
                        decoded.retained_signature.as_deref() == Some(witness.signature.as_slice()),
                        "stored Signed signature bytes exactly match the witnessed output (redacted)"
                    );
                    assert_eq!(decoded.binding, binding);

                    let accountant = owner.backend_for_test().accounting_handle_for_test();
                    drop(coord); drop(decided); drop(engine); drop(journal);
                    drop(observed); drop(concrete); drop(owner); drop(snapshot); drop(sink);
                    drop(signer); drop(inner); drop(pv); drop(ctx); drop(proposal);
                    drop(base_vote); drop(witness); drop(raw);
                    assert_eq!(accountant.current(), 0, "operational ledger returns to zero");
                    assert_eq!(accountant.aggregate().current(), 0, "aggregate ledger returns to zero");
                }

                #[test]
                fn postsign_prepublication_child_death_reopens_reserved() {
                    let harness = tempfile::tempdir().unwrap();
                    let fixture = harness.path().join("suite100_keypair.bin");
                    let marker_path = harness.path().join("post-sign-marker.bin");
                    let safety_dir = harness.path().join("safety");
                    let journal_dir = harness.path().join("journal");
                    std::fs::create_dir(&safety_dir).unwrap();
                    std::fs::create_dir(&journal_dir).unwrap();
                    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("suite-100 keygen");
                    write_fixture_file(&fixture, &pk, &sk);
                    let nonce = urandom_nonce();
                    let mut child = spawn_child("abort", &fixture, &marker_path, &nonce, &safety_dir, &journal_dir);
                    let class = child.supervise(STATUS_DEADLINE).expect("boundary child reaped");
                    assert_eq!(class, TermClass::Signaled(EXPECTED_ABORT_SIGNAL));
                    let raw = read_marker_bounded(&marker_path).expect("boundary marker");
                    assert!(accepts(class, &raw, &nonce), "only intended signal plus full matching witness is accepted");
                    let witness = parse_marker(&raw, &nonce).expect("parse accepted post-sign witness");
                    assert_eq!((witness.hook_calls, witness.signer_calls, witness.sink_calls, witness.publication_calls), (1, 1, 0, 0));
                    assert_eq!(witness.public_key, pk);
                    assert_eq!(witness.signature.len(), SIGNATURE_LEN);
                    MlDsa44Backend::verify(&witness.public_key, &witness.preimage, &witness.signature)
                        .expect("child's original signature verifies; this does not authorize delivery");

                    let ctx = retained_ctx(4);
                    let pv = authority_from_pk(pk.clone());
                    let owner = reopen_attach(&safety_dir, &ctx);
                    let concrete = reopen_open_journal_store(&journal_dir);
                    let observed = Arc::new(ObservedBoundaryRocksStore::new(concrete.clone()));
                    verify_same_domain(&observed, &concrete);
                    let journal = reopen_assoc_journal_open(
                        &owner, observed.clone() as Arc<dyn SigningJournalStorage>, 1,
                    );
                    assert_eq!(journal.reserved_position_count(), 1);
                    let record_pre = observed.get_signing_record(&witness.position_key)
                        .expect("read recovered journal record").expect("Reserved record");
                    let metadata_pre = observed.get_signing_metadata()
                        .expect("read recovered journal metadata").expect("metadata exists");
                    let count_pre = journal.reserved_position_count();
                    let decoded = SigningDecisionRecord::decode(&record_pre).expect("decode Reserved record");
                    assert_eq!(decoded.stage, SigningRecordStage::Reserved);
                    assert_eq!(decoded.position.storage_key(), witness.position_key);
                    assert_eq!(decoded.binding.0, witness.binding);
                    assert!(decoded.retained_signature.is_none());
                    assert_eq!(count_pre, 1);

                    let (mut engine, proposal, l0_block) =
                        engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
                    let limits = lim_b(&ctx);
                    let op_ceiling = owner.backend_for_test().accounting_cap();
                    let agg_ceiling = owner.backend_for_test().accounting_aggregate_cap();
                    let op_before_recovery = owner.backend_for_test().accounting_current();
                    let agg_before_recovery = owner.backend_for_test().accounting_aggregate_current();
                    let revision = reopen_b_recover_only(&owner, &engine, l0_block);
                    assert_eq!(owner.backend_for_test().accounting_current(), op_before_recovery);
                    assert_eq!(owner.backend_for_test().accounting_aggregate_current(), agg_before_recovery);
                    assert_eq!(owner.backend_for_test().accounting_cap(), op_ceiling);
                    assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), agg_ceiling);
                    assert_eq!(observed.get_signing_record(&witness.position_key).unwrap().as_deref(), Some(record_pre.as_slice()));
                    assert_eq!(observed.get_signing_metadata().unwrap().as_deref(), Some(metadata_pre.as_slice()));
                    assert_eq!(journal.reserved_position_count(), count_pre);

                    let capture_proof = owner.read_validate(None::<&FixtureCommittedHistory>)
                        .expect("separate O3 capture proof");
                    let decided = match owner.decide_and_capture_owned(
                        &mut engine, ValidatorId::new(2), &proposal, &limits, revision, capture_proof,
                    ) {
                        OwnedDecisionOutcome::Decided(value) => value,
                        other => panic!("derive new surviving decision: {other:?}"),
                    };
                    let vote = decided.vote();
                    let vote_wire = unsigned_vote_wire(vote);
                    let preimage = pv.signing_domain.vote_preimage(vote);
                    let (position, binding) = retained_pos_binding(&pv, vote);
                    let (_suite, authorized_key) = pv.key_provider
                        .get_suite_and_key(ValidatorId::new(SIGNER_VID)).expect("authorized key");
                    assert_eq!(vote_wire, witness.unsigned_vote);
                    assert_eq!(preimage, witness.preimage);
                    assert_eq!(position.storage_key(), witness.position_key);
                    assert_eq!(binding.0, witness.binding);
                    assert_eq!(authorized_key, witness.public_key);
                    let base_vote = vote.clone();

                    // Fresh refusal is measured independently from retained refusal.
                    let mut fresh_snapshot = established_snapshot(&pv);
                    let inner = real_local_signer(&sk);
                    let signer_obs = Arc::new(AtomicU32::new(0));
                    let sink_obs = Arc::new(AtomicU32::new(0));
                    let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                    let mut fresh_sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                    let publication_calls = Arc::new(AtomicU32::new(0));
                    let mut fresh_coord = ModelCoordinationHook::publication_observing(publication_calls.clone());
                    let fresh_ledgers = snapshot_ledgers(&owner);
                    let fresh_provenance = pin_provenance_now(&owner, &decided);
                    let fresh_op_ceiling = owner.backend_for_test().accounting_cap();
                    let fresh_agg_ceiling = owner.backend_for_test().accounting_aggregate_cap();
                    let fresh_record = observed.get_signing_record(&position.storage_key()).unwrap().unwrap();
                    let fresh_metadata = observed.get_signing_metadata().unwrap().unwrap();
                    let fresh_count = journal.reserved_position_count();
                    let fresh_counts = observed.counts().0;
                    let fresh = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &proposal, &limits, None, &mut fresh_snapshot,
                        &signer, &mut fresh_sink, &journal, &mut fresh_coord, ReconfirmPerturbation::None,
                    );
                    assert_eq!(fresh, RealFreshSignOutcome::ReservePotentiallySigned);
                    assert_eq!((signer.calls(), fresh_sink.calls, publication_calls.load(Ordering::SeqCst)), (0, 0, 0));
                    assert_eq!(signer_obs.load(Ordering::SeqCst), 0);
                    assert_eq!(sink_obs.load(Ordering::SeqCst), 0);
                    assert_cleanup_preserved(&owner, &decided, &base_vote, fresh_ledgers, fresh_provenance, "post-sign boundary fresh refusal");
                    assert_eq!(owner.backend_for_test().accounting_cap(), fresh_op_ceiling);
                    assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), fresh_agg_ceiling);
                    let fresh_after = observed.counts().0;
                    assert_eq!(fresh_after.bounded_present_reads - fresh_counts.bounded_present_reads, 1);
                    assert_eq!(fresh_after.combined_reservation_writes - fresh_counts.combined_reservation_writes, 0);
                    assert_eq!(fresh_after.signed_record_only_writes - fresh_counts.signed_record_only_writes, 0);
                    assert_eq!(fresh_after.reissue_attempts - fresh_counts.reissue_attempts, 0);
                    assert_eq!(fresh_after.other_mutations - fresh_counts.other_mutations, 0);
                    assert_eq!(observed.get_signing_record(&position.storage_key()).unwrap().as_deref(), Some(fresh_record.as_slice()));
                    assert_eq!(observed.get_signing_metadata().unwrap().as_deref(), Some(fresh_metadata.as_slice()));
                    assert_eq!(journal.reserved_position_count(), fresh_count);

                    // AssociationChecked path: actual present bounded read, no delivery/reissue/sign route.
                    let retained_ledgers = snapshot_ledgers(&owner);
                    let retained_provenance = pin_provenance_now(&owner, &decided);
                    let retained_op_ceiling = owner.backend_for_test().accounting_cap();
                    let retained_agg_ceiling = owner.backend_for_test().accounting_aggregate_cap();
                    let retained_record = observed.get_signing_record(&position.storage_key()).unwrap().unwrap();
                    let retained_metadata = observed.get_signing_metadata().unwrap().unwrap();
                    let retained_count = journal.reserved_position_count();
                    let retained_counts = observed.counts().0;
                    let witness_slice = &witness.signature;
                    assert_eq!(witness_slice.len(), SIGNATURE_LEN);
                    let probe_witness = RetainedSliceWitness::from_validated(witness_slice);
                    let probe = std::rc::Rc::new(RetainedSliceProbe::new(probe_witness));
                    let probe_guard = install_retained_slice_probe(probe.clone());
                    let mut retained_sink = RetainedUseRecordingSink::new();
                    let mut retained_coord = ModelCoordinationHook::inert();
                    let retained = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                        &owner, &engine, &decided, &proposal, &limits, None, &mut fresh_snapshot,
                        &mut retained_sink, &journal, &mut retained_coord, ReconfirmPerturbation::None,
                    );
                    assert_eq!(retained, ModelRetainedUseOutcome::RetainedPotentiallySigned);
                    assert_eq!(retained_sink.calls, 0);
                    assert_eq!(probe.invocations(), 0, "Reserved state is not delivered to the retained probe");
                    drop(probe_guard);
                    assert_cleanup_preserved(&owner, &decided, &base_vote, retained_ledgers, retained_provenance, "post-sign boundary checked-retained refusal");
                    assert_eq!(owner.backend_for_test().accounting_cap(), retained_op_ceiling);
                    assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), retained_agg_ceiling);
                    let retained_after = observed.counts().0;
                    assert_eq!(retained_after.bounded_present_reads - retained_counts.bounded_present_reads, 1);
                    assert_eq!(retained_after.reissue_attempts - retained_counts.reissue_attempts, 0);
                    assert_eq!(retained_after.reissue_delegated_writes - retained_counts.reissue_delegated_writes, 0);
                    assert_eq!(retained_after.combined_reservation_writes - retained_counts.combined_reservation_writes, 0);
                    assert_eq!(retained_after.signed_record_only_writes - retained_counts.signed_record_only_writes, 0);
                    assert_eq!(retained_after.other_mutations - retained_counts.other_mutations, 0);
                    assert_eq!(observed.get_signing_record(&position.storage_key()).unwrap().as_deref(), Some(retained_record.as_slice()));
                    assert_eq!(observed.get_signing_metadata().unwrap().as_deref(), Some(retained_metadata.as_slice()));
                    assert_eq!(journal.reserved_position_count(), retained_count);
                    let final_record = SigningDecisionRecord::decode(&retained_record).unwrap();
                    assert_eq!(final_record.stage, SigningRecordStage::Reserved);
                    assert!(final_record.retained_signature.is_none());

                    let accountant = owner.backend_for_test().accounting_handle_for_test();
                    drop(probe); drop(retained_sink); drop(retained_coord); drop(fresh_coord);
                    drop(decided); drop(engine); drop(journal); drop(observed); drop(concrete);
                    drop(owner); drop(fresh_snapshot); drop(fresh_sink); drop(signer); drop(inner);
                    drop(pv); drop(ctx); drop(proposal); drop(base_vote); drop(witness); drop(raw);
                    assert_eq!(accountant.current(), 0, "surviving operational ledger reaches zero");
                    assert_eq!(accountant.aggregate().current(), 0, "surviving aggregate ledger reaches zero");
                }
            }

            fn lim_b(ctx: &PinnedSafetyContext) -> PreparedDecisionInputLimits {
                PreparedDecisionInputLimits::from_pinned(ctx).expect("pinned context yields a policy")
            }

        mod postpublication {
            use super::*;
            use crate::signing_reservation_journal::{
                BoundedStorageError, SigningOwnershipDomain, SigningJournalStorage,
            };
            use crate::storage::StorageError;
            use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

            const MAGIC: [u8; 4] = *b"R4P2";
            const VERSION: u16 = 2;
            const PHASE: u8 = 0x18;
            const NONCE_LEN: usize = 16;
            const PK_LEN: usize = qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE;
            const VOTE_LEN: usize = 69;
            const PREIMAGE_CAP: usize = MODEL_MAX_PREIMAGE_BYTES as usize;
            const POSITION_LEN: usize = crate::signing_journal_admission::JOURNAL_KEY_LEN;
            const SIG_LEN: usize = qbind_crypto::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE;
            const MARKER_LEN: usize = POSTPUB_MARKER_LEN;
            const MARKER_CHILD_PATH: &str = "safety_record_store::owner::model::tests::real_fresh_sign::postconsume_process_death::postpublication::publication_child_entry";
            const ENV_MODE_PUB: &str = "R422_PCPD_PUB_CHILD_MODE";
            const ENV_FIXTURE_PUB: &str = "R422_PCPD_PUB_FIXTURE";
            const ENV_MARKER_PUB: &str = "R422_PCPD_PUB_MARKER";
            const ENV_NONCE_PUB: &str = "R422_PCPD_PUB_NONCE_HEX";
            const ENV_SAFETY_PUB: &str = "R422_PCPD_PUB_SAFETY_DIR";
            const ENV_JOURNAL_PUB: &str = "R422_PCPD_PUB_JOURNAL_DIR";

            #[derive(Debug, PartialEq, Eq)]
            struct PublicationWitness {
                nonce: [u8; NONCE_LEN],
                pre_sign_calls: u32,
                publication_calls: u32,
                signer_calls: u32,
                sink_calls: u32,
                public_key: Vec<u8>,
                unsigned_vote: Vec<u8>,
                preimage: Vec<u8>,
                position_key: Vec<u8>,
                binding: [u8; 32],
                signature: Vec<u8>,
            }

            fn write_u16(dst: &mut [u8], offset: usize, value: usize) {
                let value = u16::try_from(value).expect("bounded marker length fits u16");
                dst[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            }

            fn build_marker(
                nonce: &[u8; NONCE_LEN],
                public_key: &[u8],
                unsigned_vote: &[u8],
                preimage: &[u8],
                position_key: &[u8],
                binding: &[u8; 32],
            ) -> Box<[u8; MARKER_LEN]> {
                assert_eq!(public_key.len(), PK_LEN);
                assert_eq!(unsigned_vote.len(), VOTE_LEN);
                assert!(!preimage.is_empty() && preimage.len() <= PREIMAGE_CAP);
                assert_eq!(position_key.len(), POSITION_LEN);
                assert_eq!(SIG_LEN, crate::signing_journal_admission::OUTPUT_CAP);
                let mut marker = Box::new([0u8; MARKER_LEN]);
                marker[0..4].copy_from_slice(&MAGIC);
                marker[4..6].copy_from_slice(&VERSION.to_le_bytes());
                marker[6] = PHASE;
                marker[7..23].copy_from_slice(nonce);
                write_u16(&mut marker[..], 41, PK_LEN);
                marker[POSTPUB_PK_OFFSET..POSTPUB_VOTE_LEN_OFFSET].copy_from_slice(public_key);
                write_u16(&mut marker[..], POSTPUB_VOTE_LEN_OFFSET, unsigned_vote.len());
                marker[POSTPUB_VOTE_OFFSET..POSTPUB_PREIMAGE_LEN_OFFSET].copy_from_slice(unsigned_vote);
                write_u16(&mut marker[..], POSTPUB_PREIMAGE_LEN_OFFSET, preimage.len());
                marker[POSTPUB_PREIMAGE_OFFSET..POSTPUB_PREIMAGE_OFFSET + preimage.len()]
                    .copy_from_slice(preimage);
                marker[POSTPUB_POSITION_OFFSET..POSTPUB_BINDING_OFFSET].copy_from_slice(position_key);
                marker[POSTPUB_BINDING_OFFSET..POSTPUB_SIGNATURE_LEN_OFFSET].copy_from_slice(binding);
                marker
            }

            fn read_u16(bytes: &[u8], offset: usize) -> usize {
                u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize
            }

            fn read_u32(bytes: &[u8], offset: usize) -> u32 {
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed marker field"))
            }

            fn decode_unsigned_suite_vote(bytes: &[u8]) -> Result<Vote, &'static str> {
                use qbind_wire::io::WireDecode as _;
                let mut input = bytes;
                let vote = Vote::decode(&mut input).map_err(|_| "Vote encoding")?;
                if !input.is_empty() { return Err("Vote trailing bytes"); }
                if !vote.signature.is_empty() { return Err("Vote inline signature"); }
                if vote.suite_id != MODEL_SUITE_U16 { return Err("Vote suite"); }
                Ok(vote)
            }

            fn valid_unsigned_suite_vote_wire() -> Vec<u8> {
                use qbind_wire::io::WireEncode as _;
                let vote = Vote {
                    version: 1,
                    chain_id: 7,
                    epoch: 4,
                    height: 1,
                    round: 0,
                    step: 1,
                    block_id: [0xB2; 32],
                    validator_index: 2,
                    suite_id: MODEL_SUITE_U16,
                    signature: Vec::new(),
                };
                let mut bytes = Vec::with_capacity(VOTE_LEN);
                vote.encode(&mut bytes);
                assert_eq!(bytes.len(), VOTE_LEN);
                bytes
            }

            fn parse_marker(bytes: &[u8]) -> Result<PublicationWitness, &'static str> {
                if bytes.len() != MARKER_LEN { return Err("marker length"); }
                if bytes[0..4] != MAGIC { return Err("magic"); }
                if u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION { return Err("version"); }
                if bytes[6] != PHASE { return Err("phase"); }
                let nonce = bytes[7..23].try_into().map_err(|_| "nonce")?;
                let pre_sign_calls = read_u32(bytes, 23);
                let publication_calls = read_u32(bytes, 27);
                let signer_calls = read_u32(bytes, 31);
                let sink_calls = read_u32(bytes, 35);
                if (pre_sign_calls, publication_calls, signer_calls, sink_calls) != (1, 1, 1, 0) {
                    return Err("live observations");
                }
                if bytes[39] != 1 || bytes[40] != 0 { return Err("outcome/retry"); }
                if read_u16(bytes, 41) != PK_LEN { return Err("public-key length"); }
                let public_key = bytes[POSTPUB_PK_OFFSET..POSTPUB_VOTE_LEN_OFFSET].to_vec();
                if read_u16(bytes, POSTPUB_VOTE_LEN_OFFSET) != VOTE_LEN { return Err("Vote length"); }
                let unsigned_vote = bytes[POSTPUB_VOTE_OFFSET..POSTPUB_PREIMAGE_LEN_OFFSET].to_vec();
                decode_unsigned_suite_vote(&unsigned_vote)?;
                let preimage_len = read_u16(bytes, POSTPUB_PREIMAGE_LEN_OFFSET);
                if preimage_len == 0 || preimage_len > PREIMAGE_CAP { return Err("preimage length"); }
                let padded = &bytes[POSTPUB_PREIMAGE_OFFSET..POSTPUB_POSITION_OFFSET];
                if padded[preimage_len..].iter().any(|byte| *byte != 0) { return Err("preimage padding"); }
                let preimage = padded[..preimage_len].to_vec();
                let position_key = bytes[POSTPUB_POSITION_OFFSET..POSTPUB_BINDING_OFFSET].to_vec();
                let binding = bytes[POSTPUB_BINDING_OFFSET..POSTPUB_SIGNATURE_LEN_OFFSET]
                    .try_into().map_err(|_| "binding")?;
                let sig_len = read_u16(bytes, POSTPUB_SIGNATURE_LEN_OFFSET);
                if sig_len != SIG_LEN { return Err("signature length"); }
                let signature = bytes[POSTPUB_SIGNATURE_OFFSET..].to_vec();
                Ok(PublicationWitness {
                    nonce, pre_sign_calls, publication_calls, signer_calls, sink_calls,
                    public_key, unsigned_vote, preimage, position_key, binding, signature,
                })
            }

            fn read_marker_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
                let file = std::fs::File::open(path)?;
                let mut limited = file.take((MARKER_LEN + 1) as u64);
                let mut bytes = Vec::with_capacity(MARKER_LEN + 1);
                limited.read_to_end(&mut bytes)?;
                Ok(bytes)
            }

            fn accepts(class: TermClass, raw: &[u8], nonce: &[u8; NONCE_LEN]) -> bool {
                if class != TermClass::Signaled(EXPECTED_ABORT_SIGNAL) { return false; }
                parse_marker(raw).map(|w| &w.nonce == nonce).unwrap_or(false)
            }

            fn make_nonce() -> [u8; NONCE_LEN] { urandom_nonce() }

            fn open_marker(path: &std::path::Path) -> std::fs::File {
                std::fs::OpenOptions::new().write(true).create_new(true).open(path)
                    .expect("create empty publication marker before protected operation")
            }

            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
            struct StoreCounts {
                reissue_attempts: u64,
                reissue_delegated: u64,
                reissue_successes: u64,
                other_mutations: u64,
            }

            struct ObservedReissueRocksStore {
                inner: Arc<RocksDbConsensusStorage>,
                fail_reissue: AtomicBool,
                reissue_attempts: AtomicU64,
                reissue_delegated: AtomicU64,
                reissue_successes: AtomicU64,
                other_mutations: AtomicU64,
            }

            impl ObservedReissueRocksStore {
                fn new(inner: Arc<RocksDbConsensusStorage>) -> Self {
                    Self {
                        inner, fail_reissue: AtomicBool::new(false),
                        reissue_attempts: AtomicU64::new(0), reissue_delegated: AtomicU64::new(0),
                        reissue_successes: AtomicU64::new(0), other_mutations: AtomicU64::new(0),
                    }
                }
                fn fault(&self, fail: bool) { self.fail_reissue.store(fail, Ordering::SeqCst); }
                fn counts(&self) -> StoreCounts {
                    StoreCounts {
                        reissue_attempts: self.reissue_attempts.load(Ordering::SeqCst),
                        reissue_delegated: self.reissue_delegated.load(Ordering::SeqCst),
                        reissue_successes: self.reissue_successes.load(Ordering::SeqCst),
                        other_mutations: self.other_mutations.load(Ordering::SeqCst),
                    }
                }
            }

            impl SigningJournalStorage for ObservedReissueRocksStore {
                fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
                    self.inner.get_signing_record(key)
                }
                fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
                    self.other_mutations.fetch_add(1, Ordering::SeqCst);
                    self.inner.put_signing_record_synced(key, value)
                }
                fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
                    self.inner.get_signing_metadata()
                }
                fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
                    self.other_mutations.fetch_add(1, Ordering::SeqCst);
                    self.inner.put_signing_metadata_synced(value)
                }
                fn put_signing_record_and_metadata_synced(
                    &self, key: &[u8], record: &[u8], metadata: &[u8],
                ) -> Result<(), StorageError> {
                    self.other_mutations.fetch_add(1, Ordering::SeqCst);
                    self.inner.put_signing_record_and_metadata_synced(key, record, metadata)
                }
                fn for_each_signing_namespace_entry(
                    &self, visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
                ) -> Result<(), StorageError> {
                    self.inner.for_each_signing_namespace_entry(visitor)
                }
                fn signing_ownership_domain(&self) -> Arc<SigningOwnershipDomain> {
                    self.inner.signing_ownership_domain()
                }
                fn read_signing_envelope_into(
                    &self, key: &[u8], dst: &mut [u8],
                ) -> Result<Option<usize>, BoundedStorageError> {
                    self.inner.read_signing_envelope_into(key, dst)
                }
                fn reissue_signing_envelope_synced(
                    &self, key: &[u8], envelope: &[u8],
                ) -> Result<(), BoundedStorageError> {
                    self.reissue_attempts.fetch_add(1, Ordering::SeqCst);
                    if self.fail_reissue.load(Ordering::SeqCst) {
                        return Err(BoundedStorageError::Io(BoundedDiag::WriteIo));
                    }
                    self.reissue_delegated.fetch_add(1, Ordering::SeqCst);
                    self.inner.reissue_signing_envelope_synced(key, envelope)?;
                    self.reissue_successes.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
                fn put_signing_envelope_and_metadata_synced(
                    &self, key: &[u8], record: &[u8], metadata: &[u8],
                ) -> Result<(), BoundedStorageError> {
                    self.other_mutations.fetch_add(1, Ordering::SeqCst);
                    self.inner.put_signing_envelope_and_metadata_synced(key, record, metadata)
                }
                fn put_signing_record_envelope_synced(
                    &self, key: &[u8], record: &[u8],
                ) -> Result<(), BoundedStorageError> {
                    self.other_mutations.fetch_add(1, Ordering::SeqCst);
                    self.inner.put_signing_record_envelope_synced(key, record)
                }
            }

            fn assert_store_unchanged(
                store: &ObservedReissueRocksStore,
                journal: &SigningReservationJournal,
                key: &[u8],
                record: &[u8],
                metadata: &[u8],
                count: u64,
                label: &str,
            ) {
                assert_eq!(store.get_signing_record(key).expect("record read").as_deref(), Some(record), "record bytes {label}");
                assert_eq!(store.get_signing_metadata().expect("metadata read").as_deref(), Some(metadata), "metadata bytes {label}");
                assert_eq!(journal.reserved_position_count(), count, "reserved count {label}");
            }

            fn spawn_publication_child(
                mode: &str,
                fixture: &std::path::Path,
                marker: &std::path::Path,
                nonce: &str,
                safety: &std::path::Path,
                journal: &std::path::Path,
            ) -> OwnedChild {
                let exe = std::env::current_exe().expect("current test executable");
                let child = std::process::Command::new(exe)
                    .args(["--exact", MARKER_CHILD_PATH, "--ignored", "--nocapture", "--test-threads=1"])
                    .env(ENV_MODE_PUB, mode).env(ENV_FIXTURE_PUB, fixture)
                    .env(ENV_MARKER_PUB, marker).env(ENV_NONCE_PUB, nonce)
                    .env(ENV_SAFETY_PUB, safety).env(ENV_JOURNAL_PUB, journal)
                    .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null()).spawn().expect("spawn publication child");
                OwnedChild::new(child)
            }

            fn prepare_publication_marker(
                pv: &ProposalVoteAuthority,
                vote: &Vote,
                nonce: &[u8; NONCE_LEN],
            ) -> Box<[u8; MARKER_LEN]> {
                let unsigned = unsigned_vote_wire(vote);
                let preimage = pv.signing_domain.vote_preimage(vote);
                let (position, binding) = retained_pos_binding(pv, vote);
                let (_suite, public_key) = pv.key_provider.get_suite_and_key(ValidatorId::new(SIGNER_VID))
                    .expect("shared suite-100 public key");
                assert_eq!(public_key.len(), PK_LEN);
                prepare_marker_fields(nonce, &public_key, &unsigned, &preimage, &position.storage_key(), &binding.0)
            }

            fn prepare_marker_fields(
                nonce: &[u8; NONCE_LEN], public_key: &[u8], unsigned: &[u8],
                preimage: &[u8], position_key: &[u8], binding: &[u8; 32],
            ) -> Box<[u8; MARKER_LEN]> {
                build_marker(nonce, public_key, unsigned, preimage, position_key, binding)
            }

            #[test]
            #[ignore = "re-executed child; driven only by publication parent tests"]
            fn publication_child_entry() {
                let Some(mode) = std::env::var_os(ENV_MODE_PUB) else { return; };
                let mode = mode.to_string_lossy().into_owned();
                if mode == "missing_marker" { std::process::exit(3); }
                if mode == "wrong_signal" {
                    unsafe { libc::raise(libc::SIGTERM); }
                    std::process::exit(0);
                }
                let fixture = std::path::PathBuf::from(std::env::var_os(ENV_FIXTURE_PUB).expect("fixture"));
                let marker_path = std::path::PathBuf::from(std::env::var_os(ENV_MARKER_PUB).expect("marker"));
                let safety = std::path::PathBuf::from(std::env::var_os(ENV_SAFETY_PUB).expect("safety"));
                let journal_dir = std::path::PathBuf::from(std::env::var_os(ENV_JOURNAL_PUB).expect("journal"));
                let nonce = hex_to_nonce(&std::env::var(ENV_NONCE_PUB).expect("nonce"));
                let (pv, sk, owner, engine, decided, proposal, limits, journal, old_marker) =
                    child_prepare(&fixture, &safety, &journal_dir, &nonce);
                drop(old_marker);
                let marker = prepare_publication_marker(&pv, decided.vote(), &nonce);
                let file = open_marker(&marker_path);
                let signer_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let sink_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let inner = real_local_signer(&sk);
                let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                let mut sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                let mut snapshot = established_snapshot(&pv);
                let evidence = PostPublicationEvidence::new(
                    marker, file, signer_obs.clone(), sink_obs.clone(), mode == "publication_abort",
                );
                let mut coord = ModelCoordinationHook::inert().with_post_publication_evidence(evidence);
                let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &proposal, &limits, None, &mut snapshot,
                    &signer, &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                assert!(matches!(outcome, RealFreshSignOutcome::Published(_)), "publication child completed route: {outcome:?}");
                assert_eq!(signer.calls(), 1);
                assert_eq!(sink.calls, 1);
                assert_eq!(coord.calls, 1);
                if mode == "publication_abort" { panic!("abort hook returned"); }
            }

            #[test]
            fn publication_marker_layout_roundtrip_and_rejections() {
                let nonce = [7u8; NONCE_LEN];
                let pk = vec![0xA1; PK_LEN];
                let vote = valid_unsigned_suite_vote_wire();
                let preimage = vec![0xC3; 88];
                let position = vec![0xD4; POSITION_LEN];
                let binding = [0xE5; 32];
                let mut marker = build_marker(&nonce, &pk, &vote, &preimage, &position, &binding);
                assert_eq!(MARKER_LEN, 4193);
                marker[23..27].copy_from_slice(&1u32.to_le_bytes());
                marker[27..31].copy_from_slice(&1u32.to_le_bytes());
                marker[31..35].copy_from_slice(&1u32.to_le_bytes());
                marker[39] = 1;
                marker[POSTPUB_SIGNATURE_LEN_OFFSET..POSTPUB_SIGNATURE_OFFSET]
                    .copy_from_slice(&(SIG_LEN as u16).to_le_bytes());
                marker[POSTPUB_SIGNATURE_OFFSET..].fill(0x5A);
                assert_eq!(parse_marker(&marker[..]).expect("valid witness").signature.len(), SIG_LEN);
                for malformed in [vec![0; MARKER_LEN - 1], vec![0; MARKER_LEN + 1]] {
                    assert!(parse_marker(&malformed).is_err(), "short and long markers reject");
                }
                let mut bad = marker.clone(); bad[0] ^= 1; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[4] ^= 1; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[6] ^= 1; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[23] ^= 1; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[39] = 0; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[40] = 1; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[23] = 2; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[41] = 0; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[POSTPUB_PREIMAGE_LEN_OFFSET] = 0; bad[POSTPUB_PREIMAGE_LEN_OFFSET + 1] = 0; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[POSTPUB_PREIMAGE_OFFSET + preimage.len()] = 1; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[POSTPUB_SIGNATURE_LEN_OFFSET] = 1; assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[POSTPUB_SIGNATURE_LEN_OFFSET..POSTPUB_SIGNATURE_OFFSET].copy_from_slice(&((SIG_LEN + 1) as u16).to_le_bytes()); assert!(parse_marker(&bad[..]).is_err());
                let mut bad = marker.clone(); bad[POSTPUB_VOTE_OFFSET] ^= 0xFF;
                assert_eq!(parse_marker(&bad[..]), Err("Vote encoding"), "malformed Vote encoding rejects");
                let mut bad = marker.clone();
                bad[POSTPUB_VOTE_OFFSET + 65..POSTPUB_VOTE_OFFSET + 67]
                    .copy_from_slice(&(MODEL_SUITE_U16 + 1).to_le_bytes());
                assert_eq!(parse_marker(&bad[..]), Err("Vote suite"), "decodable wrong-suite Vote rejects");
                let mut trailing = vote.clone();
                trailing.push(0);
                assert_eq!(
                    decode_unsigned_suite_vote(&trailing),
                    Err("Vote trailing bytes"),
                    "a valid Vote followed by unconsumed input rejects"
                );

                let mut signed_vote = decode_unsigned_suite_vote(&vote).expect("valid unsigned suite-100 Vote");
                signed_vote.signature.push(0x5A);
                let mut signed_vote_bytes = Vec::new();
                qbind_wire::io::WireEncode::encode(&signed_vote, &mut signed_vote_bytes);
                assert_eq!(signed_vote_bytes.len(), VOTE_LEN + 1);
                assert_eq!(
                    decode_unsigned_suite_vote(&signed_vote_bytes),
                    Err("Vote inline signature"),
                    "a valid inline-signature length is decoded and then refused"
                );
                marker[POSTPUB_PREIMAGE_LEN_OFFSET..POSTPUB_PREIMAGE_OFFSET].copy_from_slice(&257u16.to_le_bytes());
                assert!(parse_marker(&marker[..]).is_err());
            }

            #[test]
            fn publication_acceptance_requires_abort_and_complete_matching_marker() {
                let nonce = [9u8; NONCE_LEN];
                let vote = valid_unsigned_suite_vote_wire();
                let marker = build_marker(&nonce, &[1; PK_LEN], &vote, &[3; 32], &[4; POSITION_LEN], &[5; 32]);
                let mut complete = marker.to_vec();
                complete[23..27].copy_from_slice(&1u32.to_le_bytes());
                complete[27..31].copy_from_slice(&1u32.to_le_bytes());
                complete[31..35].copy_from_slice(&1u32.to_le_bytes());
                complete[35..39].copy_from_slice(&0u32.to_le_bytes());
                complete[39] = 1;
                complete[POSTPUB_SIGNATURE_LEN_OFFSET..POSTPUB_SIGNATURE_OFFSET].copy_from_slice(&(SIG_LEN as u16).to_le_bytes());
                assert!(accepts(TermClass::Signaled(EXPECTED_ABORT_SIGNAL), &complete, &nonce));
                assert!(!accepts(TermClass::Exited(0), &complete, &nonce));
                assert!(!accepts(TermClass::Signaled(libc::SIGTERM), &complete, &nonce));
                assert!(!accepts(TermClass::TimedOutKilled { kill_confirmed: true }, &complete, &nonce));
                assert!(!accepts(TermClass::Signaled(EXPECTED_ABORT_SIGNAL), &complete[..MARKER_LEN - 1], &nonce));
                let other = [8u8; NONCE_LEN];
                assert!(!accepts(TermClass::Signaled(EXPECTED_ABORT_SIGNAL), &complete, &other));
            }

            #[test]
            fn publication_hook_rejects_invalid_live_observations_without_marker() {
                let temp = tempfile::tempdir().unwrap();
                let vote = valid_unsigned_suite_vote_wire();
                let marker = build_marker(&[6; NONCE_LEN], &[1; PK_LEN], &vote, &[3; 32], &[4; POSITION_LEN], &[5; 32]);
                let cases = [
                    (Ok(AdmittedPublishOutcome::AlreadyAcknowledged), false, 1, 1, 0, SIG_LEN),
                    (Ok(AdmittedPublishOutcome::Published), true, 1, 1, 0, SIG_LEN),
                    (Ok(AdmittedPublishOutcome::Published), false, 0, 1, 0, SIG_LEN),
                    (Ok(AdmittedPublishOutcome::Published), false, 1, 0, 0, SIG_LEN),
                    (Ok(AdmittedPublishOutcome::Published), false, 1, 1, 1, SIG_LEN),
                    (Ok(AdmittedPublishOutcome::Published), false, 1, 1, 0, SIG_LEN - 1),
                    (Ok(AdmittedPublishOutcome::Published), false, 1, 1, 0, SIG_LEN + 1),
                ];
                for (index, (outcome, retry, pre_sign, signer_count, sink_count, sig_len)) in cases.into_iter().enumerate() {
                    let path = temp.path().join(format!("invalid-{index}.bin"));
                    let file = open_marker(&path);
                    let signer_obs = Arc::new(std::sync::atomic::AtomicU32::new(signer_count));
                    let sink_obs = Arc::new(std::sync::atomic::AtomicU32::new(sink_count));
                    let mut evidence = PostPublicationEvidence::new(
                        marker.clone(), file, signer_obs, sink_obs, false,
                    );
                    let signature = vec![0xA5; sig_len];
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        evidence.fire(&outcome, &signature, retry, pre_sign);
                    }));
                    assert!(result.is_err(), "invalid boundary case {index} is rejected");
                    drop(evidence);
                    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0, "invalid live observation writes no complete marker");
                }
            }

            #[test]
            fn postpublication_control_published_no_termination() {
                let temp = tempfile::tempdir().unwrap();
                let fixture = temp.path().join("keypair.bin");
                let marker_path = temp.path().join("publication.bin");
                let (pk, sk) = MlDsa44Backend::generate_keypair().expect("suite-100 keygen");
                write_fixture_file(&fixture, &pk, &sk);
                let nonce = make_nonce();
                let (rpk, rsk) = read_fixture_file(&fixture);
                assert!(rsk == sk, "fixture secret roundtrip matches (redacted)");
                let pv = authority_from_pk(rpk);
                let ctx = retained_ctx(4);
                let safety_dir = temp.path().join("safety");
                let journal_dir = temp.path().join("journal");
                std::fs::create_dir(&safety_dir).expect("safety dir");
                std::fs::create_dir(&journal_dir).expect("journal dir");
                let (owner, engine, decided, proposal, limits, _) = capture_multi_with_suite(&safety_dir, &ctx, MODEL_SUITE_U16);
                let base_vote = decided.vote().clone();
                let store = reopen_open_journal_store(&journal_dir);
                let journal = reopen_assoc_journal_init(&owner, store.clone() as Arc<dyn SigningJournalStorage>, 1);
                let marker = prepare_publication_marker(&pv, decided.vote(), &nonce);
                let file = open_marker(&marker_path);
                let signer_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let sink_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let inner = real_local_signer(&rsk);
                let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                let mut sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                let mut snapshot = established_snapshot(&pv);
                let mut coord = ModelCoordinationHook::inert().with_post_publication_evidence(
                    PostPublicationEvidence::new(marker, file, signer_obs.clone(), sink_obs.clone(), false),
                );
                let ledgers = snapshot_ledgers(&owner);
                let provenance = pin_provenance_now(&owner, &decided);
                let operational_ceiling = owner.backend_for_test().accounting_cap().expect("operational ceiling");
                let aggregate_ceiling = owner.backend_for_test().accounting_aggregate_cap().expect("aggregate ceiling");
                let outcome = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &proposal, &limits, None, &mut snapshot,
                    &signer, &mut sink, &journal, &mut coord, ReconfirmPerturbation::None,
                );
                assert_eq!(owner.backend_for_test().accounting_cap(), Some(operational_ceiling), "publication control preserves operational ceiling");
                assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), Some(aggregate_ceiling), "publication control preserves aggregate ceiling");
                let diag = match outcome { RealFreshSignOutcome::Published(d) => d, other => panic!("expected Published: {other:?}") };
                assert_eq!(diag.retirement, RetirementReport::Retired);
                assert_eq!((signer.calls(), sink.calls, coord.calls), (1, 1, 1));
                assert_eq!(signer_obs.load(Ordering::SeqCst), 1);
                assert_eq!(sink_obs.load(Ordering::SeqCst), 1);
                assert_cleanup_preserved(&owner, &decided, &base_vote, ledgers, provenance, "postpublication no-termination control");
                let witness = parse_marker(&read_marker_bounded(&marker_path).expect("marker read")).expect("complete publication marker");
                assert_eq!(witness.nonce, nonce);
                assert_eq!(witness.public_key, pk);
                let (position, binding) = retained_pos_binding(&pv, &base_vote);
                let record = store.get_signing_record(&position.storage_key()).expect("record read").expect("Signed record");
                let decoded = SigningDecisionRecord::decode(&record).expect("decode Signed record");
                let stored_sig = decoded.retained_signature.expect("stored signature");
                assert_eq!(witness.signature, stored_sig, "boundary output equals stored signature");
                MlDsa44Backend::verify(&witness.public_key, &witness.preimage, &witness.signature)
                    .expect("the actual published signature verifies against the witnessed preimage");
                assert_eq!(decoded.binding, binding);
                assert_eq!(journal.reserved_position_count(), 1);
                let acct = owner.backend_for_test().accounting_handle_for_test();
                drop(coord); drop(decided); drop(engine); drop(journal); drop(store); drop(owner);
                drop(snapshot); drop(sink); drop(signer); drop(inner); drop(pv);
                drop(ctx); drop(proposal); drop(witness); drop(base_vote);
                assert_eq!(acct.current(), 0, "operational ledger fully released");
                assert_eq!(acct.aggregate().current(), 0, "aggregate ledger fully released");
            }

            #[test]
            fn postpublication_marker_then_exit_rejected() {
                let temp = tempfile::tempdir().unwrap();
                let fixture = temp.path().join("keypair.bin");
                let marker = temp.path().join("publication.bin");
                let safety = temp.path().join("safety"); let journal = temp.path().join("journal");
                std::fs::create_dir(&safety).unwrap(); std::fs::create_dir(&journal).unwrap();
                let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
                write_fixture_file(&fixture, &pk, &sk);
                let nonce = make_nonce(); let nonce_hex = nonce_to_hex(&nonce);
                let mut child = spawn_publication_child("publication_exit", &fixture, &marker, &nonce_hex, &safety, &journal);
                let class = child.supervise(STATUS_DEADLINE).expect("child reaped");
                assert_eq!(class, TermClass::Exited(0));
                let raw = read_marker_bounded(&marker).expect("valid marker exists");
                assert!(parse_marker(&raw).is_ok());
                assert!(!accepts(class, &raw, &nonce), "ordinary exit is not process-death evidence");
            }

            #[test]
            fn postpublication_child_death_reopen_checked_retained() {
                let harness = tempfile::tempdir().unwrap();
                let fixture = harness.path().join("suite100_keypair.bin");
                let marker_path = harness.path().join("publication_marker.bin");
                let safety_dir = harness.path().join("safety"); let journal_dir = harness.path().join("journal");
                std::fs::create_dir(&safety_dir).unwrap(); std::fs::create_dir(&journal_dir).unwrap();
                let (pk, sk) = MlDsa44Backend::generate_keypair().expect("parent suite-100 keygen");
                write_fixture_file(&fixture, &pk, &sk);
                let nonce = make_nonce(); let nonce_hex = nonce_to_hex(&nonce);
                let mut child = spawn_publication_child("publication_abort", &fixture, &marker_path, &nonce_hex, &safety_dir, &journal_dir);
                let class = child.supervise(STATUS_DEADLINE).expect("child reaped");
                assert_eq!(class, TermClass::Signaled(EXPECTED_ABORT_SIGNAL), "intended abort classification");
                let raw = read_marker_bounded(&marker_path).expect("publication boundary marker");
                assert!(accepts(class, &raw, &nonce), "only intended abort plus complete invocation marker is accepted");
                let witness = parse_marker(&raw).expect("parse publication marker");
                assert_eq!(witness.signature.len(), SIG_LEN);
                assert_eq!((witness.pre_sign_calls, witness.publication_calls, witness.signer_calls, witness.sink_calls), (1, 1, 1, 0));
                assert_eq!(witness.public_key, pk);

                let ctx = retained_ctx(4);
                let pv = authority_from_pk(pk.clone());
                let owner = reopen_attach(&safety_dir, &ctx);
                let concrete = reopen_open_journal_store(&journal_dir);
                let wrapper = Arc::new(ObservedReissueRocksStore::new(concrete.clone()));
                let wrapper_domain = wrapper.signing_ownership_domain();
                let backend_domain = concrete.signing_ownership_domain();
                assert!(Arc::ptr_eq(&wrapper_domain, &backend_domain), "wrapper forwards the real backend domain");
                drop(wrapper_domain); drop(backend_domain);
                let store: Arc<dyn SigningJournalStorage> = wrapper.clone();
                let journal = reopen_assoc_journal_open(&owner, store.clone(), 1);
                assert_eq!(journal.reserved_position_count(), 1);

                // Identify and snapshot the actual Signed state before safety recovery.
                let record_pre = wrapper.get_signing_record(&witness.position_key).expect("pre-O2 record read").expect("Signed record survived");
                let metadata_pre = wrapper.get_signing_metadata().expect("pre-O2 metadata read").expect("metadata survived");
                let count_pre = journal.reserved_position_count();
                let decoded_pre = SigningDecisionRecord::decode(&record_pre).expect("decode surviving Signed record");
                assert_eq!(decoded_pre.stage, SigningRecordStage::Signed);
                assert_eq!(decoded_pre.position.storage_key(), witness.position_key);
                assert_eq!(decoded_pre.binding.0, witness.binding);
                let stored_signature = decoded_pre.retained_signature.as_ref().expect("Signed signature");
                assert_eq!(stored_signature.len(), SIG_LEN);
                assert_eq!(stored_signature.as_slice(), witness.signature.as_slice(), "surviving record preserves child output");
                assert_eq!(count_pre, 1);

                let (mut engine, proposal, l0_block) = engine_locked_l0_multi_with_suite(MODEL_SUITE_U16);
                let limits = lim_b(&ctx);
                let revision = reopen_b_recover_only(&owner, &engine, l0_block);
                assert_eq!(wrapper.get_signing_record(&witness.position_key).expect("record after O5").as_deref(), Some(record_pre.as_slice()));
                assert_eq!(wrapper.get_signing_metadata().expect("metadata after O5").as_deref(), Some(metadata_pre.as_slice()));
                assert_eq!(journal.reserved_position_count(), count_pre);

                // A separate fresh O3 proof feeds the existing owning capture route.
                let capture_proof = owner.read_validate(None::<&FixtureCommittedHistory>).expect("separate capture O3 proof");
                let decided = match owner.decide_and_capture_owned(&mut engine, ValidatorId::new(2), &proposal, &limits, revision, capture_proof) {
                    OwnedDecisionOutcome::Decided(d) => d,
                    other => panic!("surviving-process decision re-derivation: {other:?}"),
                };
                let vote = decided.vote();
                let vote_wire = unsigned_vote_wire(vote);
                let preimage = pv.signing_domain.vote_preimage(vote);
                let (position, binding) = retained_pos_binding(&pv, vote);
                let (_suite, authorized_pk) = pv.key_provider.get_suite_and_key(ValidatorId::new(SIGNER_VID)).expect("authorized key");
                assert_eq!(vote_wire, witness.unsigned_vote);
                assert_eq!(preimage, witness.preimage);
                assert_eq!(position.storage_key(), witness.position_key);
                assert_eq!(binding.0, witness.binding);
                assert_eq!(authorized_pk, witness.public_key);
                let base_vote = vote.clone();

                // Fresh signing is a separate, independently snapshotted refusal.
                let mut fresh_snapshot = established_snapshot(&pv);
                let inner = real_local_signer(&sk);
                let signer_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let sink_obs = Arc::new(std::sync::atomic::AtomicU32::new(0));
                let signer = CountingValidatorSigner::new_observed(&inner, signer_obs.clone());
                let mut fresh_sink = RealSignRecordingSink::new_observed(sink_obs.clone());
                let mut fresh_coord = ModelCoordinationHook::inert();
                let fresh_ledgers = snapshot_ledgers(&owner);
                let fresh_provenance = pin_provenance_now(&owner, &decided);
                let fresh_counts = wrapper.counts();
                let fresh_record = wrapper.get_signing_record(&witness.position_key).expect("fresh pre-record").expect("record");
                let fresh_metadata = wrapper.get_signing_metadata().expect("fresh pre-metadata").expect("metadata");
                let fresh_count = journal.reserved_position_count();
                let fresh_operational_ceiling = owner.backend_for_test().accounting_cap().expect("fresh operational ceiling");
                let fresh_aggregate_ceiling = owner.backend_for_test().accounting_aggregate_cap().expect("fresh aggregate ceiling");
                let fresh = fresh_vote_sign_real_local::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &proposal, &limits, None, &mut fresh_snapshot,
                    &signer, &mut fresh_sink, &journal, &mut fresh_coord, ReconfirmPerturbation::None,
                );
                assert_eq!(owner.backend_for_test().accounting_cap(), Some(fresh_operational_ceiling), "fresh refusal preserves operational ceiling");
                assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), Some(fresh_aggregate_ceiling), "fresh refusal preserves aggregate ceiling");
                assert_eq!(fresh, RealFreshSignOutcome::ReservePotentiallySigned);
                assert_eq!((signer.calls(), fresh_sink.calls, fresh_coord.calls), (0, 0, 0));
                assert_eq!(signer_obs.load(Ordering::SeqCst), 0);
                assert_eq!(sink_obs.load(Ordering::SeqCst), 0);
                let fresh_after_counts = wrapper.counts();
                assert_eq!(fresh_after_counts.reissue_attempts - fresh_counts.reissue_attempts, 0);
                assert_eq!(fresh_after_counts.other_mutations - fresh_counts.other_mutations, 0);
                assert_cleanup_preserved(&owner, &decided, &base_vote, fresh_ledgers, fresh_provenance, "Signed-position fresh refusal");
                assert_store_unchanged(&wrapper, &journal, &witness.position_key, &fresh_record, &fresh_metadata, fresh_count, "after fresh refusal");

                let witnessed_slice = &witness.signature;
                assert_eq!(witnessed_slice.len(), SIG_LEN);
                assert_eq!(stored_signature.as_slice(), witnessed_slice.as_slice());

                // Failed-before-write recovered reissue suppresses all delivery.
                wrapper.fault(true);
                let fail_ledgers = snapshot_ledgers(&owner);
                let fail_provenance = pin_provenance_now(&owner, &decided);
                let fail_record = wrapper.get_signing_record(&witness.position_key).expect("R1 record").expect("record");
                let fail_metadata = wrapper.get_signing_metadata().expect("R1 metadata").expect("metadata");
                let fail_count = journal.reserved_position_count();
                let fail_counts = wrapper.counts();
                let fail_operational_ceiling = owner.backend_for_test().accounting_cap().expect("failure operational ceiling");
                let fail_aggregate_ceiling = owner.backend_for_test().accounting_aggregate_cap().expect("failure aggregate ceiling");
                let fail_witness = RetainedSliceWitness::from_validated(witnessed_slice);
                assert_eq!(fail_witness.len(), SIG_LEN);
                let fail_probe = std::rc::Rc::new(RetainedSliceProbe::new(fail_witness));
                let fail_guard = install_retained_slice_probe(fail_probe.clone());
                let mut fail_sink = RetainedUseRecordingSink::new();
                let mut fail_coord = ModelCoordinationHook::inert();
                let suppressed = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &proposal, &limits, None, &mut fresh_snapshot,
                    &mut fail_sink, &journal, &mut fail_coord, ReconfirmPerturbation::None,
                );
                assert_eq!(owner.backend_for_test().accounting_cap(), Some(fail_operational_ceiling), "failed reissue preserves operational ceiling");
                assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), Some(fail_aggregate_ceiling), "failed reissue preserves aggregate ceiling");
                drop(fail_guard);
                assert_eq!(suppressed, ModelRetainedUseOutcome::DeliverySuppressed);
                assert_eq!(fail_sink.calls, 0);
                assert_eq!(fail_probe.invocations(), 0);
                let fail_after = wrapper.counts();
                assert_eq!(fail_after.reissue_attempts - fail_counts.reissue_attempts, 1);
                assert_eq!(fail_after.reissue_delegated - fail_counts.reissue_delegated, 0);
                assert_eq!(fail_after.reissue_successes - fail_counts.reissue_successes, 0);
                assert_eq!(fail_after.other_mutations - fail_counts.other_mutations, 0);
                assert_eq!(signer.calls(), 0, "no signer was supplied to the checked route and no additional signing occurred");
                assert_cleanup_preserved(&owner, &decided, &base_vote, fail_ledgers, fail_provenance, "failed recovered reissue suppression");
                assert_store_unchanged(&wrapper, &journal, &witness.position_key, &fail_record, &fail_metadata, fail_count, "after failed reissue");

                // Relieved retry uses the identical checked route, journal, backend,
                // envelope, and witnessed signature; its own synced reissue precedes use.
                wrapper.fault(false);
                let ok_ledgers = snapshot_ledgers(&owner);
                let ok_provenance = pin_provenance_now(&owner, &decided);
                let ok_record = wrapper.get_signing_record(&witness.position_key).expect("R2 record").expect("record");
                let ok_metadata = wrapper.get_signing_metadata().expect("R2 metadata").expect("metadata");
                let ok_count = journal.reserved_position_count();
                let ok_counts = wrapper.counts();
                let ok_operational_ceiling = owner.backend_for_test().accounting_cap().expect("retry operational ceiling");
                let ok_aggregate_ceiling = owner.backend_for_test().accounting_aggregate_cap().expect("retry aggregate ceiling");
                let ok_witness = RetainedSliceWitness::from_validated(witnessed_slice);
                assert_eq!(ok_witness.len(), SIG_LEN);
                let ok_probe = std::rc::Rc::new(RetainedSliceProbe::new(ok_witness));
                let ok_guard = install_retained_slice_probe(ok_probe.clone());
                let mut ok_sink = RetainedUseRecordingSink::new();
                let mut ok_coord = ModelCoordinationHook::inert();
                let consumed = retained_vote_use_checked_model::<FixtureCommittedHistory>(
                    &owner, &engine, &decided, &proposal, &limits, None, &mut fresh_snapshot,
                    &mut ok_sink, &journal, &mut ok_coord, ReconfirmPerturbation::None,
                );
                assert_eq!(owner.backend_for_test().accounting_cap(), Some(ok_operational_ceiling), "successful retry preserves operational ceiling");
                assert_eq!(owner.backend_for_test().accounting_aggregate_cap(), Some(ok_aggregate_ceiling), "successful retry preserves aggregate ceiling");
                drop(ok_guard);
                let diag = match consumed { ModelRetainedUseOutcome::Consumed(d) => d, other => panic!("checked retained retry: {other:?}") };
                assert_eq!(diag.sig_len as usize, SIG_LEN);
                assert_eq!(ok_sink.calls, 1);
                assert_eq!(ok_probe.invocations(), 1);
                assert_eq!(ok_probe.last_len(), Some(SIG_LEN));
                assert_eq!(ok_probe.last_matched(), Some(true), "verified borrowed slice equals actual child publication bytes");
                let ok_after = wrapper.counts();
                assert_eq!(ok_after.reissue_attempts - ok_counts.reissue_attempts, 1);
                assert_eq!(ok_after.reissue_delegated - ok_counts.reissue_delegated, 1);
                assert_eq!(ok_after.reissue_successes - ok_counts.reissue_successes, 1);
                assert_eq!(ok_after.other_mutations - ok_counts.other_mutations, 0);
                assert_eq!(signer.calls(), 0, "retained path performed no signing");
                assert_cleanup_preserved(&owner, &decided, &base_vote, ok_ledgers, ok_provenance, "successful checked retained use");
                assert_store_unchanged(&wrapper, &journal, &witness.position_key, &ok_record, &ok_metadata, ok_count, "after checked retained success");

                let acct = owner.backend_for_test().accounting_handle_for_test();
                drop(fail_probe); drop(ok_probe); drop(fail_sink); drop(ok_sink);
                drop(fresh_coord); drop(fail_coord); drop(ok_coord);
                drop(witness); drop(raw); drop(decoded_pre);
                drop(decided); drop(engine); drop(journal); drop(store); drop(wrapper); drop(concrete); drop(owner);
                drop(fresh_snapshot); drop(fresh_sink); drop(signer); drop(inner); drop(pv);
                drop(ctx); drop(proposal); drop(base_vote);
                assert_eq!(acct.current(), 0, "surviving operational ledger reaches zero");
                assert_eq!(acct.aggregate().current(), 0, "surviving aggregate ledger reaches zero");
            }
        }

        }
    }

}