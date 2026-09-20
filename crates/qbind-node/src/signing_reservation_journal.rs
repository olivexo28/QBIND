//! Run 422 D7-D10 — Local, non-authorizing, crash-consistent
//! **signing-reservation journal** for Proposal / Vote decisions.
//!
//! This module implements the bounded successor defined in
//! `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`
//! (accepted D9, `DEFINED-NOT-IMPLEMENTED`). It provides the durable
//! **reservation** that INV-1 (durable-before-sign) requires: before a
//! Proposal/Vote signer is invoked, the exact prepared decision is durably
//! reserved; a conflicting decision at the same canonical position is refused;
//! an exact retry reuses the retained signature without signing again; and, after
//! process death, a recovered reservation without a usable retained result is
//! treated as **potentially signed** (refuse re-signing, preserve the
//! reservation).
//!
//! # What this module is NOT
//!
//! * It is **not** an authorization. A journal record never establishes
//!   activation authorization (requirement A) or current-authority freshness
//!   (requirement B); those are enforced independently by the existing
//!   admission / confirmation machinery in `binary_consensus_loop.rs`. The
//!   journal only guards requirement (C): signing-state continuity.
//! * It provides **no** durable anti-rollback anchor. A whole-copy rollback or
//!   deletion of the local store cannot be detected from local state alone (see
//!   the contract §6). The record checksum detects corruption only; it is not
//!   authentication and not rollback protection.
//! * It does **not** wire any production activation path. Production startup
//!   never initializes a journal, and an empty journal is never treated as
//!   proof that a validator key has never signed.
//!
//! # Reuse
//!
//! * Durability: the existing `crates/qbind-node/src/storage.rs` synced-write
//!   profile (`WriteOptions::set_sync(true)` / WAL flush) via the
//!   [`SigningJournalStorage`] backend implemented for `RocksDbConsensusStorage`
//!   and `InMemoryConsensusStorage`.
//! * Corruption detection: the same CRC-32 facility used by the block/QC/epoch
//!   records (`crate::storage::signing_journal_crc32`).
//! * Identity / preimage: the caller supplies the exact D6 canonical preimage
//!   and the admitted signer/domain identity; this module introduces no parallel
//!   parser, signing format, or cryptographic construction.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::storage::{signing_journal_crc32, StorageError};

/// Journal-record format version — a **persistence-format identifier** for the
/// signing record, independent of BOTH the wire-message version and the D6
/// signing-format version. Changing it alters neither the consensus position nor
/// the signed wire bytes. Unknown/incompatible record versions are refused
/// fail-closed.
pub const SIGNING_RECORD_FORMAT_VERSION: u16 = 1;

/// Magic prefix identifying a signing-decision record (corruption/format guard).
const RECORD_MAGIC: [u8; 4] = *b"QSJ1";

/// Storage key namespace prefix for signing-decision records. Distinct from the
/// existing `b:` / `q:` / `meta:` namespaces so block/QC/epoch keys and their
/// semantics are unchanged.
pub const SIGNING_RECORD_KEY_PREFIX: &[u8] = b"sj:v1:";

/// Maximum retained signature length accepted into a record (bounded allocation
/// guard). ML-DSA-44 signatures are ~2.4 KiB; 8 KiB leaves headroom without
/// permitting unbounded growth. A record whose declared signature length exceeds
/// this bound is refused fail-closed and never allocated.
pub const MAX_RETAINED_SIGNATURE_LEN: usize = 8 * 1024;

/// Maximum total encoded record length (bounded read/allocation guard).
pub const MAX_RECORD_LEN: usize = MAX_RETAINED_SIGNATURE_LEN + 128;

/// Default maximum number of distinct positions a single live journal instance
/// will reserve before refusing further signing (exhaustion). Exhaustion refuses
/// safely; it never silently evicts a conflict obligation.
pub const DEFAULT_MAX_RESERVED_POSITIONS: u64 = 1_048_576;

// ============================================================================
// Position and binding
// ============================================================================

/// The consensus message kind. Proposal and Vote are two distinct
/// sub-namespaces of one originating view: a leader legitimately produces one
/// Proposal and one self-Vote at the same view and they do NOT conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningKind {
    /// A `BlockProposal` decision.
    Proposal,
    /// A `Vote` decision (directed and broadcast delivery of the same Vote are
    /// the same decision).
    Vote,
}

impl SigningKind {
    fn tag(self) -> u8 {
        match self {
            SigningKind::Proposal => 0,
            SigningKind::Vote => 1,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(SigningKind::Proposal),
            1 => Some(SigningKind::Vote),
            _ => None,
        }
    }
}

/// The canonical consensus voting **position key** for the founding-authority
/// profile. No independently-supplied numeric field and no mutable
/// key/suite/version/context label can split one engine voting position into two
/// records: only the stable validator identity within its bound network/genesis,
/// the message kind, and the **originating consensus view** participate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningPosition {
    /// Stable local validator identity (`ValidatorId` as `u64`) within its fixed
    /// network/genesis. NOT the current key, suite, owner generation, PID, or
    /// caller label.
    pub validator_id: u64,
    /// The pinned network/genesis identity (D6 domain `genesis_identity`).
    pub network_genesis: [u8; 32],
    /// Proposal vs Vote.
    pub kind: SigningKind,
    /// The originating consensus view carried by the action itself (captured at
    /// construction), never a later `engine.current_view()`.
    pub originating_view: u64,
}

impl SigningPosition {
    /// The stable storage key for this position (domain-separated). Two requests
    /// for the same canonical position resolve to the same key regardless of any
    /// exact-message binding differences.
    pub fn storage_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(SIGNING_RECORD_KEY_PREFIX.len() + 1 + 8 + 32 + 8);
        key.extend_from_slice(SIGNING_RECORD_KEY_PREFIX);
        key.push(self.kind.tag());
        key.extend_from_slice(&self.validator_id.to_be_bytes());
        key.extend_from_slice(&self.network_genesis);
        key.extend_from_slice(&self.originating_view.to_be_bytes());
        key
    }
}

/// The exact-message **binding digest**. A change to any exact-message binding
/// field at the same position key is a conflict, not a new namespace. The digest
/// is computed over the prepared D6 preimage plus the redundant exact-message
/// binding fields (domain-separated); the canonical preimage the signer receives
/// is the authoritative binder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingDigest(pub [u8; 32]);

/// Inputs to the exact-message binding digest. All fields have a single trusted
/// source (the admitted snapshot's bound signer/domain and the prepared engine
/// action), never attacker-controlled wire data beyond the canonical body the
/// preimage already encodes.
pub struct DecisionBindingInput<'a> {
    /// Position (identity + kind + originating view).
    pub position: SigningPosition,
    /// The epoch the admitted snapshot authorizes.
    pub authorized_epoch: u64,
    /// The admitted signer's bound suite.
    pub suite_id: u16,
    /// The wire-message version (`BlockHeader.version` / `Vote.version`).
    pub wire_message_version: u16,
    /// The D6 signing-format version (`ProposalVoteSigningDomainV2` byte 2).
    pub d6_signing_format_version: u8,
    /// The admitted authority commitment.
    pub authority_commitment: [u8; 32],
    /// The block id (or Vote's block id) bound to the decision.
    pub block_id: [u8; 32],
    /// The exact prepared D6 preimage the signer will receive.
    pub canonical_preimage: &'a [u8],
}

impl BindingDigest {
    /// Compute the binding digest over the prepared decision. Reuses the
    /// repository's SHA3-256 (the same hash used by wire canonicalization), with
    /// an explicit domain-separation tag; it introduces no new cryptographic
    /// construction.
    pub fn compute(input: &DecisionBindingInput<'_>) -> Self {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"QBIND-SIGNING-JOURNAL-BINDING-v1");
        h.update([input.position.kind.tag()]);
        h.update(input.position.validator_id.to_be_bytes());
        h.update(input.position.network_genesis);
        h.update(input.position.originating_view.to_be_bytes());
        h.update(input.authorized_epoch.to_be_bytes());
        h.update(input.suite_id.to_be_bytes());
        h.update(input.wire_message_version.to_be_bytes());
        h.update([input.d6_signing_format_version]);
        h.update(input.authority_commitment);
        h.update(input.block_id);
        h.update((input.canonical_preimage.len() as u64).to_be_bytes());
        h.update(input.canonical_preimage);
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        BindingDigest(out)
    }
}

// ============================================================================
// Record and state machine
// ============================================================================

/// Lifecycle stage persisted in a signing-decision record. `SIGNING` is not
/// persisted as a distinct stored stage: once a live operation may have invoked
/// the signer, recovery must treat a `Reserved` record as potentially-signed, so
/// only `Reserved` and `Signed` are durable stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningRecordStage {
    /// A durable reservation for exactly one decision at this position is
    /// committed and its durability barrier acknowledged.
    Reserved,
    /// A signature/result exists and the canonical authorized decision is
    /// retained for exact-retry resend.
    Signed,
}

impl SigningRecordStage {
    fn tag(self) -> u8 {
        match self {
            SigningRecordStage::Reserved => 1,
            SigningRecordStage::Signed => 2,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(SigningRecordStage::Reserved),
            2 => Some(SigningRecordStage::Signed),
            _ => None,
        }
    }
}

/// A persisted signing-decision record. Bounded, versioned, checksummed, and
/// fail-closed on malformed input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningDecisionRecord {
    /// Journal-record format version (persistence only).
    pub record_format_version: u16,
    /// The canonical position key.
    pub position: SigningPosition,
    /// The exact-message binding digest.
    pub binding: BindingDigest,
    /// The lifecycle stage.
    pub stage: SigningRecordStage,
    /// The retained signature/result for exact-retry resend (present only when
    /// `stage == Signed`).
    pub retained_signature: Option<Vec<u8>>,
}

impl SigningDecisionRecord {
    fn reserved(position: SigningPosition, binding: BindingDigest) -> Self {
        Self {
            record_format_version: SIGNING_RECORD_FORMAT_VERSION,
            position,
            binding,
            stage: SigningRecordStage::Reserved,
            retained_signature: None,
        }
    }

    fn signed(position: SigningPosition, binding: BindingDigest, signature: Vec<u8>) -> Self {
        Self {
            record_format_version: SIGNING_RECORD_FORMAT_VERSION,
            position,
            binding,
            stage: SigningRecordStage::Signed,
            retained_signature: Some(signature),
        }
    }

    /// Serialize to the checksummed, bounded, versioned record encoding.
    ///
    /// Layout (all integers big-endian):
    /// `magic[4] | record_format_version[2] | kind[1] | stage[1] |
    ///  validator_id[8] | network_genesis[32] | originating_view[8] |
    ///  binding[32] | sig_len[4] | sig[sig_len] | crc32[4]`
    /// where `crc32` covers all preceding bytes.
    pub fn encode(&self) -> Result<Vec<u8>, JournalError> {
        let sig = self.retained_signature.as_deref().unwrap_or(&[]);
        if sig.len() > MAX_RETAINED_SIGNATURE_LEN {
            return Err(JournalError::OversizeRecord {
                len: sig.len(),
                max: MAX_RETAINED_SIGNATURE_LEN,
            });
        }
        let mut body = Vec::with_capacity(92 + sig.len());
        body.extend_from_slice(&RECORD_MAGIC);
        body.extend_from_slice(&self.record_format_version.to_be_bytes());
        body.push(self.position.kind.tag());
        body.push(self.stage.tag());
        body.extend_from_slice(&self.position.validator_id.to_be_bytes());
        body.extend_from_slice(&self.position.network_genesis);
        body.extend_from_slice(&self.position.originating_view.to_be_bytes());
        body.extend_from_slice(&self.binding.0);
        // Checked length: never allocate/write from an unchecked length.
        let sig_len: u32 = u32::try_from(sig.len()).map_err(|_| JournalError::OversizeRecord {
            len: sig.len(),
            max: MAX_RETAINED_SIGNATURE_LEN,
        })?;
        body.extend_from_slice(&sig_len.to_be_bytes());
        body.extend_from_slice(sig);
        let crc = signing_journal_crc32(&body);
        body.extend_from_slice(&crc.to_be_bytes());
        Ok(body)
    }

    /// Decode from the checksummed record encoding, fail-closed on any
    /// malformed, truncated, incompatible, or inconsistent input. A decode
    /// failure never yields a usable "assume unused" record.
    pub fn decode(data: &[u8]) -> Result<Self, JournalError> {
        if data.len() > MAX_RECORD_LEN {
            return Err(JournalError::OversizeRecord {
                len: data.len(),
                max: MAX_RECORD_LEN,
            });
        }
        // Fixed prefix + trailing crc: magic(4)+ver(2)+kind(1)+stage(1)+vid(8)+
        // genesis(32)+view(8)+binding(32)+sig_len(4) = 92, + crc(4).
        const HEADER_LEN: usize = 92;
        if data.len() < HEADER_LEN + 4 {
            return Err(JournalError::Truncated);
        }
        let (body, crc_bytes) = data.split_at(data.len() - 4);
        let stored_crc = u32::from_be_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
        if signing_journal_crc32(body) != stored_crc {
            return Err(JournalError::Corruption("record checksum mismatch".to_string()));
        }
        if body[0..4] != RECORD_MAGIC {
            return Err(JournalError::Corruption("record magic mismatch".to_string()));
        }
        let record_format_version = u16::from_be_bytes([body[4], body[5]]);
        if record_format_version != SIGNING_RECORD_FORMAT_VERSION {
            return Err(JournalError::UnsupportedRecordVersion(record_format_version));
        }
        let kind = SigningKind::from_tag(body[6])
            .ok_or_else(|| JournalError::Corruption("unknown kind tag".to_string()))?;
        let stage = SigningRecordStage::from_tag(body[7])
            .ok_or_else(|| JournalError::Corruption("unknown stage tag".to_string()))?;
        let validator_id = u64::from_be_bytes(body[8..16].try_into().unwrap());
        let mut network_genesis = [0u8; 32];
        network_genesis.copy_from_slice(&body[16..48]);
        let originating_view = u64::from_be_bytes(body[48..56].try_into().unwrap());
        let mut binding = [0u8; 32];
        binding.copy_from_slice(&body[56..88]);
        let sig_len = u32::from_be_bytes(body[88..92].try_into().unwrap()) as usize;
        if sig_len > MAX_RETAINED_SIGNATURE_LEN {
            return Err(JournalError::OversizeRecord {
                len: sig_len,
                max: MAX_RETAINED_SIGNATURE_LEN,
            });
        }
        // The declared signature length must exactly consume the remaining body
        // (no trailing/short bytes) — an inconsistent record is refused.
        if body.len() != HEADER_LEN + sig_len {
            return Err(JournalError::Truncated);
        }
        let retained_signature = if sig_len == 0 {
            None
        } else {
            Some(body[HEADER_LEN..HEADER_LEN + sig_len].to_vec())
        };
        // Stage/field consistency: a Reserved record carries no retained
        // signature; a Signed record MUST carry one.
        match stage {
            SigningRecordStage::Reserved if retained_signature.is_some() => {
                return Err(JournalError::Corruption(
                    "reserved record must not carry a signature".to_string(),
                ));
            }
            SigningRecordStage::Signed if retained_signature.is_none() => {
                return Err(JournalError::Corruption(
                    "signed record must carry a signature".to_string(),
                ));
            }
            _ => {}
        }
        Ok(Self {
            record_format_version,
            position: SigningPosition {
                validator_id,
                network_genesis,
                kind,
                originating_view,
            },
            binding: BindingDigest(binding),
            stage,
            retained_signature,
        })
    }
}

/// Test-only: fabricate a correctly-checksummed `Reserved` record encoding at
/// `position`/`binding` while overriding the declared record-format version.
/// Used by real-storage recovery tests to inject an otherwise-well-formed but
/// unsupported-version record so the fail-closed decode path can be exercised
/// through the public [`SigningJournalStorage`] surface. This is not a
/// production path and never grants a signing permit.
#[cfg(any(test, feature = "test-utils"))]
pub fn fabricate_reserved_record_bytes_with_version(
    position: &SigningPosition,
    binding: &BindingDigest,
    override_version: u16,
) -> Vec<u8> {
    let mut record = SigningDecisionRecord::reserved(*position, *binding);
    record.record_format_version = override_version;
    record.encode().expect("fabricated reserved record must encode")
}

// ============================================================================
// Errors and outcomes
// ============================================================================

/// Bounded, typed journal errors. Diagnostics carry no key material or
/// attacker-controlled content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// A backing-store read/write/durability operation failed or is uncertain.
    /// Storage-write or barrier uncertainty must never produce a signing permit.
    Storage(String),
    /// A stored record failed integrity/format checks (checksum, magic, tags,
    /// or stage/field consistency).
    Corruption(String),
    /// The stored record declares a record-format version this binary does not
    /// support.
    UnsupportedRecordVersion(u16),
    /// The stored record is shorter than its declared/required structure.
    Truncated,
    /// A record or signature exceeds its bounded maximum.
    OversizeRecord {
        /// The declared/actual length.
        len: usize,
        /// The maximum permitted length.
        max: usize,
    },
    /// A checked-arithmetic accounting operation would overflow — a fail-closed
    /// terminal state, never wraparound.
    Overflow,
    /// The journal lock was poisoned (a prior panic while holding it).
    LockPoisoned,
    /// A signed-result publication was rejected because it did not correspond to
    /// a live signing operation's exact reserved decision: no live invoked
    /// operation owns the position, there is no matching reservation, the
    /// binding/position disagrees, the stage is inappropriate, or it would
    /// overwrite an existing signed obligation with different content. The
    /// original obligation is never overwritten.
    InvalidResultPublication(String),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Storage(m) => write!(f, "signing-journal storage error: {}", m),
            JournalError::Corruption(m) => write!(f, "signing-journal corruption: {}", m),
            JournalError::UnsupportedRecordVersion(v) => {
                write!(f, "signing-journal unsupported record version: {}", v)
            }
            JournalError::Truncated => write!(f, "signing-journal record truncated"),
            JournalError::OversizeRecord { len, max } => {
                write!(f, "signing-journal record oversize: len={} max={}", len, max)
            }
            JournalError::Overflow => write!(f, "signing-journal accounting overflow"),
            JournalError::LockPoisoned => write!(f, "signing-journal lock poisoned"),
            JournalError::InvalidResultPublication(m) => {
                write!(f, "signing-journal invalid result publication: {}", m)
            }
        }
    }
}

impl std::error::Error for JournalError {}

impl From<StorageError> for JournalError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::Corruption(m) => JournalError::Corruption(m),
            other => JournalError::Storage(other.to_string()),
        }
    }
}

/// The outcome of a reservation request. Every outcome that is neither a fresh
/// reservation nor an exact retry must lead the caller to refuse the signer.
///
/// Run 422 D7-D10 Correction B: [`Self::FreshlyReserved`] no longer carries a
/// freely-copyable marker plus position-only invocation bookkeeping. It carries
/// a [`SigningContinuation`] — an operation-bound, non-cloneable, one-use
/// capability that is created **only after** the reservation write has received
/// its durability acknowledgement, is bound to the ownership domain / position /
/// binding / unique live operation, and cannot be reconstructed from a durable
/// `Reserved` record. This outcome is therefore not `Clone`/`Eq`.
#[derive(Debug)]
pub enum ReservationOutcome {
    /// A fresh reservation was durably committed under this ownership domain.
    /// The enclosed [`SigningContinuation`] is the one live operation's single
    /// authority to invoke the signer once for this exact decision.
    FreshlyReserved(SigningContinuation),
    /// An exact retry: the identical decision was previously signed and its
    /// signature retained. Resend the retained signature; do NOT invoke the
    /// signer. The caller MUST still validate the retained signature's
    /// decision/context association before reuse. This is returned only when the
    /// stored `Signed` result is not shadowed by a live operation whose result
    /// write has not yet been durably acknowledged in this process (see the
    /// uncertainty rule in [`SigningReservationJournal::reserve_for_sign`]).
    ExactRetryRetained(Vec<u8>),
    /// A conflicting decision (same position, different binding) exists. Refuse
    /// without altering the original obligation.
    Conflict,
    /// The position is in an uncertain state: a recovered `Reserved` record
    /// (no live continuation is ever minted from durable `Reserved` state), an
    /// already-live reservation for this position, or a `Signed` result whose
    /// durable acknowledgement is not established in this process. Treat as
    /// potentially-signed: refuse re-signing and preserve the reservation.
    PotentiallySigned,
    /// The reservation budget is exhausted. Refuse further signing safely (no
    /// silent eviction of any conflict obligation).
    Exhausted,
}

/// Run 422 D7-D10 Correction B — an **operation-bound, one-use** continuation:
/// the single authority to invoke the signer for exactly one reserved decision.
///
/// It is deliberately:
/// * **Non-cloneable / non-copyable** — there is exactly one, and consuming it
///   moves it, so it can be spent at most once.
/// * **Constructible only** inside [`SigningReservationJournal::reserve_for_sign`]
///   after a durable reservation acknowledgement (all fields are private and
///   there is no public constructor). A durable `Reserved` record read back from
///   storage can never be turned into one.
/// * **Bound** to the issuing ownership domain (`domain_token`), the canonical
///   `position`, the exact-message `binding`, and a unique live `operation_id`.
///
/// Dropping it without consuming it does NOT release the durable reservation and
/// does NOT return the position to unused state; a later reservation for that
/// position observes the recorded reservation and refuses re-signing.
#[derive(Debug)]
pub struct SigningContinuation {
    domain_token: u64,
    position: SigningPosition,
    binding: BindingDigest,
    operation_id: u64,
}

impl SigningContinuation {
    /// The canonical position this continuation authorizes signing for.
    pub fn position(&self) -> SigningPosition {
        self.position
    }
}

/// Run 422 D7-D10 Correction C — the authority to **publish the result** of the
/// exact operation that reserved a decision and crossed the signer-invocation
/// boundary. Obtained only by consuming a [`SigningContinuation`] via
/// [`SigningReservationJournal::consume_for_signing`]; it carries the same
/// operation binding (`domain_token`, `position`, `binding`, `operation_id`) so
/// publication cannot be authorized by passing arbitrary position/binding
/// arguments. It is non-cloneable, but MAY be used for more than one publication
/// **attempt** (an uncertain result write is retried through the same capability)
/// — retrying publication is never permission to sign again.
#[derive(Debug)]
pub struct ResultPublicationCapability {
    domain_token: u64,
    position: SigningPosition,
    binding: BindingDigest,
    operation_id: u64,
}

// ============================================================================
// Backing store abstraction and shared ownership domain
// ============================================================================

/// Durable backing store for signing-decision records. Implemented for the
/// existing consensus-storage backends in `storage.rs`.
///
/// The durable acknowledgement of [`Self::put_signing_record_synced`] MUST
/// correspond to the signing-record write itself — not to an unrelated epoch
/// operation. A backend whose write is not power-loss durable (the in-memory
/// model) documents itself as such and must not masquerade as a durable
/// production backend.
pub trait SigningJournalStorage: Send + Sync {
    /// Read the raw record bytes stored at `key`, or `None` if absent. Corruption
    /// detected by the storage envelope is surfaced as
    /// [`StorageError::Corruption`].
    fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Write the raw record bytes at `key` under an explicit durability barrier
    /// (synced write). MUST NOT return `Ok(())` until the record is synchronized
    /// to stable storage (for a durable backend).
    fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Run 422 D7-D10 Correction B — the single **ownership domain** for this
    /// local journal/storage instance. Implementations MUST return the SAME
    /// [`SigningOwnershipDomain`] `Arc` for every call on one backend instance
    /// (typically cached in a per-instance `OnceLock`). This is what makes the
    /// serialization boundary enforceable rather than advisory: every supported
    /// handle attached over one backend instance shares one coordinator, so a
    /// second handle cannot bypass coordination by allocating its own mutex, and
    /// two handles cannot both grant a live continuation for the same unused
    /// position.
    ///
    /// The ownership domain is **local to one backend instance**. A genuinely
    /// foreign journal — a different backend instance, e.g. a separately opened
    /// handle over a copied directory or another host — returns a *different*
    /// domain with a different token; capabilities never cross that boundary.
    /// This is not an anti-rollback anchor and makes no cross-copy/cross-host
    /// exclusivity claim.
    fn signing_ownership_domain(&self) -> Arc<SigningOwnershipDomain>;
}

/// Run 422 D7-D10 Correction B — the shared, in-process coordination state for
/// one local journal/storage ownership domain. Owned by the backend instance and
/// shared by every supported handle attached over it. It holds the single
/// [`Mutex`] that serializes every read-then-write reservation and checked
/// publication, the live-operation table, the reservation accounting, and the
/// monotonic operation-id source.
#[derive(Debug)]
pub struct SigningOwnershipDomain {
    /// A process-unique token identifying THIS domain. Capabilities carry it so
    /// a foreign domain's capability is rejected. It is in-process bookkeeping,
    /// never a durable anti-rollback anchor.
    token: u64,
    inner: Mutex<DomainInner>,
}

/// The in-memory live state for one reserved position within a domain. Its
/// presence — and the `invoked` / `result_acked` flags — is exactly the
/// knowledge a restart cannot reconstruct: reading `Reserved` (or even `Signed`)
/// bytes from storage alone never manufactures it.
#[derive(Debug)]
struct LiveState {
    /// The unique live operation that reserved this position.
    operation_id: u64,
    /// The exact-message binding the operation reserved.
    binding: BindingDigest,
    /// The signing continuation has been consumed (the signer may have run).
    invoked: bool,
    /// A durable result-write acknowledgement has been established in THIS
    /// process for this operation. Readable `Signed` bytes without this flag are
    /// NOT an acknowledged durability barrier (Correction C uncertainty rule).
    result_acked: bool,
}

#[derive(Debug)]
struct DomainInner {
    /// Positions with a live operation in this process.
    live: HashMap<SigningPosition, LiveState>,
    /// Count of distinct new positions reserved in this domain (exhaustion
    /// accounting, checked arithmetic).
    reserved_positions: u64,
    /// Monotonic source of unique live operation ids (checked; exhaustion is a
    /// terminal fail-closed state, never wraparound). In-process bookkeeping.
    next_operation_id: u64,
}

impl SigningOwnershipDomain {
    /// Create a fresh ownership domain with a process-unique token. Backends call
    /// this once per instance (via a `OnceLock`) and share the resulting `Arc`.
    pub fn new() -> Arc<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        // Process-unique, monotonically increasing domain token. This only needs
        // to distinguish concurrently-live domains within one process; it is not
        // persisted and carries no durability meaning.
        static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
        Arc::new(Self {
            token: NEXT_TOKEN.fetch_add(1, Ordering::Relaxed),
            inner: Mutex::new(DomainInner {
                live: HashMap::new(),
                reserved_positions: 0,
                next_operation_id: 1,
            }),
        })
    }
}

// ============================================================================
// The journal
// ============================================================================

/// A bounded, versioned, signing-scoped, crash-consistent reservation journal
/// **handle** over one shared [`SigningOwnershipDomain`].
///
/// Run 422 D7-D10 Correction B: the serialization boundary is the single
/// [`Mutex`] inside the ownership domain, which is owned by the backend instance
/// and shared by every supported handle attached over it. A second handle
/// therefore cannot bypass coordination by allocating its own mutex, and two
/// handles cannot both observe an unused position and grant conflicting live
/// continuations. Handles attached over *different* backend instances (a copied
/// directory, another host, or a modelled restart) are distinct domains and are
/// treated as foreign; the durable record they share is still honoured
/// fail-closed, but no live continuation is ever transferred across domains.
pub struct SigningReservationJournal {
    store: Arc<dyn SigningJournalStorage>,
    domain: Arc<SigningOwnershipDomain>,
    max_reserved_positions: u64,
}

impl std::fmt::Debug for SigningReservationJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningReservationJournal")
            .field("domain_token", &self.domain.token)
            .field("max_reserved_positions", &self.max_reserved_positions)
            .finish()
    }
}

impl SigningReservationJournal {
    /// Attach a handle over `store`'s single ownership domain, with the default
    /// reservation budget.
    ///
    /// This is deliberately non-scanning and non-initializing: it does not wipe,
    /// repair, or convert missing/corrupt established state into an empty usable
    /// journal. The shared domain's live-operation table is whatever the backend
    /// instance already holds; a freshly opened backend instance starts empty,
    /// which is exactly the crash-recovery posture — any `Reserved` record
    /// already in the store is treated as potentially-signed on the next
    /// reservation, and no live continuation is minted from it.
    pub fn attach(store: Arc<dyn SigningJournalStorage>) -> Self {
        Self::attach_with_budget(store, DEFAULT_MAX_RESERVED_POSITIONS)
    }

    /// Attach with an explicit reservation budget (small-fixture / bounds tests).
    /// The budget is enforced by this handle against the shared domain's
    /// reservation counter.
    pub fn attach_with_budget(
        store: Arc<dyn SigningJournalStorage>,
        max_reserved_positions: u64,
    ) -> Self {
        let domain = store.signing_ownership_domain();
        Self {
            store,
            domain,
            max_reserved_positions,
        }
    }

    /// The process-unique token of the ownership domain this handle serves.
    /// Two handles reporting the same token share one serialization boundary.
    pub fn ownership_domain_token(&self) -> u64 {
        self.domain.token
    }

    /// Reserve `position` for exactly one decision identified by `binding`,
    /// serialized against all handles sharing this ownership domain.
    ///
    /// On [`ReservationOutcome::FreshlyReserved`] the durable reservation has
    /// been written and its barrier acknowledged BEFORE the enclosed
    /// [`SigningContinuation`] is minted; if the durable write fails or is
    /// uncertain, an `Err` is returned and no continuation is granted (the caller
    /// must not sign). A position that already has a live operation in this
    /// domain, or a recovered `Reserved` record, is [`ReservationOutcome::
    /// PotentiallySigned`] — a durable `Reserved` state is never converted into a
    /// live continuation. A `Signed` result is [`ReservationOutcome::
    /// ExactRetryRetained`] for resend, EXCEPT when a live operation for that
    /// position in THIS process has not yet had its result write durably
    /// acknowledged, in which case it is `PotentiallySigned` (readable `Signed`
    /// bytes are not, by themselves, an acknowledged durability barrier).
    pub fn reserve_for_sign(
        &self,
        position: &SigningPosition,
        binding: &BindingDigest,
    ) -> Result<ReservationOutcome, JournalError> {
        let mut inner = self.domain.inner.lock().map_err(|_| JournalError::LockPoisoned)?;

        let key = position.storage_key();
        let existing = self.store.get_signing_record(&key)?; // read failure ⇒ Err ⇒ no sign

        if let Some(bytes) = existing {
            let record = SigningDecisionRecord::decode(&bytes)?; // corruption ⇒ Err ⇒ fail closed
            // A record at a different position resolving to the same key would be
            // a namespace/key derivation bug — refuse fail-closed.
            if record.position != *position {
                return Err(JournalError::Corruption(
                    "stored record position mismatch for key".to_string(),
                ));
            }
            if record.binding != *binding {
                return Ok(ReservationOutcome::Conflict);
            }
            return match record.stage {
                SigningRecordStage::Signed => {
                    let sig = record.retained_signature.ok_or_else(|| {
                        JournalError::Corruption(
                            "signed record missing retained signature".to_string(),
                        )
                    })?;
                    // Correction C uncertainty rule: within THIS process, a live
                    // operation whose result write has NOT been durably
                    // acknowledged must not have its readable `Signed` bytes
                    // presented as a clean retained resend. A recovered record
                    // (no live entry) or an acknowledged result is a genuine
                    // exact-retry resend.
                    match inner.live.get(position) {
                        Some(ls) if !ls.result_acked => Ok(ReservationOutcome::PotentiallySigned),
                        _ => Ok(ReservationOutcome::ExactRetryRetained(sig)),
                    }
                }
                // A durable `Reserved` record never yields a fresh live
                // continuation — neither a recovered reservation nor a second
                // handle over an already-live position may re-sign it.
                SigningRecordStage::Reserved => Ok(ReservationOutcome::PotentiallySigned),
            };
        }

        // No existing record: a new position in this domain. Perform every
        // checked-arithmetic step and the durable write BEFORE mutating any
        // in-memory state, so a write failure leaves the domain pristine (a later
        // attempt is a fresh reservation, not a conflict).
        if inner.reserved_positions >= self.max_reserved_positions {
            return Ok(ReservationOutcome::Exhausted);
        }
        let operation_id = inner.next_operation_id;
        let next_operation_id = operation_id
            .checked_add(1)
            .ok_or(JournalError::Overflow)?;
        let new_reserved = inner
            .reserved_positions
            .checked_add(1)
            .ok_or(JournalError::Overflow)?;

        let record = SigningDecisionRecord::reserved(*position, *binding);
        let encoded = record.encode()?;
        // Durable reservation acknowledgement corresponds to THIS record write.
        self.store.put_signing_record_synced(&key, &encoded)?; // failure ⇒ Err ⇒ no state change

        // Only after the durable ack do we commit the accounting and mint the
        // one-use continuation bound to this operation.
        inner.reserved_positions = new_reserved;
        inner.next_operation_id = next_operation_id;
        inner.live.insert(
            *position,
            LiveState {
                operation_id,
                binding: *binding,
                invoked: false,
                result_acked: false,
            },
        );
        Ok(ReservationOutcome::FreshlyReserved(SigningContinuation {
            domain_token: self.domain.token,
            position: *position,
            binding: *binding,
            operation_id,
        }))
    }

    /// Consume the live [`SigningContinuation`] immediately BEFORE invoking the
    /// signer, converting it (at most once, by move) into a
    /// [`ResultPublicationCapability`] for the SAME operation.
    ///
    /// Rejects a continuation from a foreign ownership domain, one whose
    /// operation/binding no longer matches the live state, or one already
    /// consumed. After this returns, a repeated reservation for the position is
    /// potentially-signed (the signer may already have run), and only the
    /// returned capability may publish that operation's result.
    pub fn consume_for_signing(
        &self,
        continuation: SigningContinuation,
    ) -> Result<ResultPublicationCapability, JournalError> {
        let mut inner = self.domain.inner.lock().map_err(|_| JournalError::LockPoisoned)?;
        if continuation.domain_token != self.domain.token {
            return Err(JournalError::InvalidResultPublication(
                "signing continuation belongs to a foreign ownership domain".to_string(),
            ));
        }
        match inner.live.get_mut(&continuation.position) {
            Some(ls)
                if ls.operation_id == continuation.operation_id
                    && ls.binding == continuation.binding
                    && !ls.invoked =>
            {
                ls.invoked = true;
                Ok(ResultPublicationCapability {
                    domain_token: continuation.domain_token,
                    position: continuation.position,
                    binding: continuation.binding,
                    operation_id: continuation.operation_id,
                })
            }
            // A live entry for a DIFFERENT operation (or an already-consumed one)
            // must never be usurped by this continuation.
            _ => Err(JournalError::InvalidResultPublication(
                "no fresh live signing continuation owns this operation".to_string(),
            )),
        }
    }

    /// Publish the retained signature for the exact reserved decision as a
    /// **checked state transition** (Run 422 D7-D10 Correction C), never a blind
    /// overwrite. The `cap` proves the caller holds the live operation that
    /// reserved this decision and crossed the invocation boundary; publication
    /// succeeds only when ALL of the following hold:
    ///
    /// * `cap` belongs to THIS ownership domain and matches a live, invoked
    ///   operation for its position with its binding — a missing, foreign, or
    ///   stale operation is refused;
    /// * a matching durable reservation exists at the position with the exact
    ///   binding — a missing reservation, wrong binding, or position mismatch is
    ///   refused;
    /// * the stored stage is `Reserved` (the permitted transition), or already
    ///   `Signed` with the **identical** retained content. A `Signed` record
    ///   with different content is refused — an existing signed obligation is
    ///   NEVER overwritten with different bytes.
    ///
    /// Correction C uncertainty rule: idempotent identical republication is
    /// reported successful ONLY once this operation has established a durable
    /// result-write acknowledgement in this process. If it has not (e.g. a prior
    /// write stored bytes but returned an error), readable byte-equality is not
    /// accepted as a barrier — the synced write is (re)issued, and a repeated
    /// failure remains a failure. On any failure the caller MUST preserve the
    /// potentially-signed obligation, suppress facade handoff, and NOT invoke the
    /// signer again; the reservation is never released here.
    pub fn record_signed_result(
        &self,
        cap: &ResultPublicationCapability,
        signature: &[u8],
    ) -> Result<(), JournalError> {
        // Bounded result write: never allocate/persist an out-of-bounds signature.
        if signature.len() > MAX_RETAINED_SIGNATURE_LEN {
            return Err(JournalError::OversizeRecord {
                len: signature.len(),
                max: MAX_RETAINED_SIGNATURE_LEN,
            });
        }
        // Hold the domain lock across the read-validate-write so publication is a
        // checked transition and concurrent supported handles cannot alter the
        // record between validation and the acknowledged effect.
        let mut inner = self.domain.inner.lock().map_err(|_| JournalError::LockPoisoned)?;

        if cap.domain_token != self.domain.token {
            return Err(JournalError::InvalidResultPublication(
                "publication capability belongs to a foreign ownership domain".to_string(),
            ));
        }

        // (1) Operation ownership: only the live, invoked operation identified by
        //     `cap` may publish its result. A missing/foreign/stale/un-invoked
        //     operation is refused — an unrelated operation can never publish
        //     over this obligation.
        let already_acked = match inner.live.get(&cap.position) {
            Some(ls)
                if ls.operation_id == cap.operation_id
                    && ls.binding == cap.binding
                    && ls.invoked =>
            {
                ls.result_acked
            }
            _ => {
                return Err(JournalError::InvalidResultPublication(
                    "no live invoked operation owns this publication".to_string(),
                ));
            }
        };

        // (2) The stored state must be the exact matching reservation. Read the
        //     current record and validate position, binding, and a permitted
        //     stage transition BEFORE overwriting anything.
        let key = cap.position.storage_key();
        let existing = self.store.get_signing_record(&key)?.ok_or_else(|| {
            JournalError::InvalidResultPublication(
                "result publication without an existing reservation".to_string(),
            )
        })?;
        let current = SigningDecisionRecord::decode(&existing)?;
        if current.position != cap.position {
            return Err(JournalError::Corruption(
                "stored record position mismatch for key".to_string(),
            ));
        }
        if current.binding != cap.binding {
            return Err(JournalError::InvalidResultPublication(
                "result binding does not match the reserved decision".to_string(),
            ));
        }
        match current.stage {
            // The permitted transition: a durable reservation becomes Signed.
            SigningRecordStage::Reserved => {}
            // Idempotent republication is admitted ONLY for the identical
            // retained result under the same position+binding; conflicting
            // content is NEVER silently overwritten.
            SigningRecordStage::Signed => match current.retained_signature.as_deref() {
                Some(existing_sig) if existing_sig == signature => {
                    // Byte-identical AND this operation already has a durable
                    // acknowledgement in-process ⇒ genuinely idempotent success.
                    // Otherwise fall through and (re)issue the synced write: a
                    // readable-but-unacknowledged result is not a barrier.
                    if already_acked {
                        return Ok(());
                    }
                }
                _ => {
                    return Err(JournalError::InvalidResultPublication(
                        "refusing to overwrite an existing signed obligation with \
                         different content"
                            .to_string(),
                    ));
                }
            },
        }

        // (3) Checked, durable result write. On failure/uncertainty the Err
        //     propagates, `result_acked` stays false (so a retry re-issues the
        //     synced write rather than trusting readable bytes), and the caller
        //     preserves the potentially-signed obligation; the reservation is
        //     never released here.
        let record = SigningDecisionRecord::signed(cap.position, cap.binding, signature.to_vec());
        let encoded = record.encode()?;
        self.store.put_signing_record_synced(&key, &encoded)?;
        if let Some(ls) = inner.live.get_mut(&cap.position) {
            ls.result_acked = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::sync::RwLock;

    /// An explicitly-labelled in-memory model store for unit tests. It provides
    /// NO power-loss durability; it exists only to exercise the journal's
    /// read/write/serialize/recovery model deterministically.
    ///
    /// Run 422 D7-D10 Correction B: the durable byte map is a shared `Arc`, the
    /// ownership domain is per-instance. Two handles over the SAME instance share
    /// one domain (a concurrent second handle). A modelled restart is
    /// [`ModelStore::reopen`]: a NEW instance sharing the SAME byte map but with a
    /// FRESH domain — bytes survive, the live-operation table does not.
    #[derive(Default)]
    struct ModelStore {
        map: Arc<RwLock<StdHashMap<Vec<u8>, Vec<u8>>>>,
        fail_reads: RwLock<bool>,
        fail_writes: RwLock<bool>,
        /// When set, `put_signing_record_synced` FIRST stores the bytes (so a
        /// subsequent read observes them) and THEN returns an error — modelling a
        /// write that became readable but whose durability acknowledgement is
        /// uncertain. This is a clearly-labelled TEST fault injector.
        store_then_error: RwLock<bool>,
        domain: std::sync::OnceLock<Arc<SigningOwnershipDomain>>,
    }

    impl ModelStore {
        /// Model a process restart: same durable bytes, a fresh ownership domain.
        fn reopen(&self) -> Arc<Self> {
            Arc::new(ModelStore {
                map: Arc::clone(&self.map),
                fail_reads: RwLock::new(false),
                fail_writes: RwLock::new(false),
                store_then_error: RwLock::new(false),
                domain: std::sync::OnceLock::new(),
            })
        }
        fn set_fail_reads(&self, v: bool) {
            *self.fail_reads.write().unwrap() = v;
        }
        fn set_fail_writes(&self, v: bool) {
            *self.fail_writes.write().unwrap() = v;
        }
        fn set_store_then_error(&self, v: bool) {
            *self.store_then_error.write().unwrap() = v;
        }
        fn corrupt(&self, key: &[u8]) {
            let mut m = self.map.write().unwrap();
            if let Some(v) = m.get_mut(key) {
                if let Some(b) = v.last_mut() {
                    *b ^= 0xFF;
                }
            }
        }
        fn overwrite(&self, key: &[u8], bytes: Vec<u8>) {
            self.map.write().unwrap().insert(key.to_vec(), bytes);
        }
    }

    impl SigningJournalStorage for ModelStore {
        fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            if *self.fail_reads.read().unwrap() {
                return Err(StorageError::Io("injected read failure".to_string()));
            }
            Ok(self.map.read().unwrap().get(key).cloned())
        }
        fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            if *self.fail_writes.read().unwrap() {
                return Err(StorageError::Io("injected write failure".to_string()));
            }
            if *self.store_then_error.read().unwrap() {
                // The bytes become readable, but the durability acknowledgement
                // is reported uncertain (error). A correct journal must NOT treat
                // the later readable bytes as an acknowledged barrier.
                self.map.write().unwrap().insert(key.to_vec(), value.to_vec());
                return Err(StorageError::Io("injected post-store sync failure".to_string()));
            }
            self.map.write().unwrap().insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn signing_ownership_domain(&self) -> Arc<SigningOwnershipDomain> {
            self.domain.get_or_init(SigningOwnershipDomain::new).clone()
        }
    }

    /// Helper: reserve a fresh decision and consume its continuation, returning
    /// the publication capability for the same operation (models the
    /// reserve→invoke boundary in a single step for tests that then publish).
    fn reserve_and_invoke(
        journal: &SigningReservationJournal,
        pos: &SigningPosition,
        b: &BindingDigest,
    ) -> ResultPublicationCapability {
        match journal.reserve_for_sign(pos, b).unwrap() {
            ReservationOutcome::FreshlyReserved(cont) => {
                journal.consume_for_signing(cont).unwrap()
            }
            other => panic!("expected FreshlyReserved, got {:?}", other),
        }
    }

    fn position(kind: SigningKind, view: u64) -> SigningPosition {
        SigningPosition {
            validator_id: 7,
            network_genesis: [0x11; 32],
            kind,
            originating_view: view,
        }
    }

    fn binding(preimage: &[u8]) -> BindingDigest {
        BindingDigest::compute(&DecisionBindingInput {
            position: position(SigningKind::Proposal, 5),
            authorized_epoch: 0,
            suite_id: 100,
            wire_message_version: 1,
            d6_signing_format_version: 2,
            authority_commitment: [0xA5; 32],
            block_id: [0x22; 32],
            canonical_preimage: preimage,
        })
    }

    #[test]
    fn record_roundtrips_reserved_and_signed() {
        let pos = position(SigningKind::Vote, 9);
        let b = binding(b"preimage-1");
        let reserved = SigningDecisionRecord::reserved(pos, b);
        let bytes = reserved.encode().unwrap();
        assert_eq!(SigningDecisionRecord::decode(&bytes).unwrap(), reserved);

        let signed = SigningDecisionRecord::signed(pos, b, vec![1, 2, 3, 4]);
        let bytes = signed.encode().unwrap();
        assert_eq!(SigningDecisionRecord::decode(&bytes).unwrap(), signed);
    }

    #[test]
    fn decode_rejects_corruption_truncation_and_version() {
        let pos = position(SigningKind::Proposal, 1);
        let b = binding(b"p");
        let mut bytes = SigningDecisionRecord::reserved(pos, b).encode().unwrap();
        // Corruption: flip a byte ⇒ checksum mismatch.
        let mut corrupt = bytes.clone();
        corrupt[10] ^= 0xFF;
        assert!(matches!(
            SigningDecisionRecord::decode(&corrupt),
            Err(JournalError::Corruption(_))
        ));
        // Truncation.
        bytes.truncate(20);
        assert!(matches!(
            SigningDecisionRecord::decode(&bytes),
            Err(JournalError::Truncated)
        ));
        // Unknown record-format version (bytes [4..6]); recompute crc so we hit
        // the version check rather than the checksum check.
        let mut versioned = SigningDecisionRecord::reserved(pos, b).encode().unwrap();
        versioned[4] = 0x00;
        versioned[5] = 0x09;
        let body_len = versioned.len() - 4;
        let crc = signing_journal_crc32(&versioned[..body_len]);
        versioned[body_len..].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            SigningDecisionRecord::decode(&versioned),
            Err(JournalError::UnsupportedRecordVersion(9))
        ));
    }

    #[test]
    fn fresh_reservation_then_signed_result_and_exact_retry() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store.clone());
        let pos = position(SigningKind::Proposal, 3);
        let b = binding(b"decision-A");

        // First reservation is fresh: consume the one-use continuation, then
        // publish through the matching operation's capability.
        let cap = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap, b"sigbytes").unwrap();

        // Exact retry reuses the retained signature; no fresh continuation.
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"sigbytes"
        ));
    }

    #[test]
    fn conflicting_binding_is_refused() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store);
        let pos = position(SigningKind::Vote, 4);
        let b1 = binding(b"content-1");
        let b2 = binding(b"content-2");
        assert_ne!(b1, b2);
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b1).unwrap(),
            ReservationOutcome::FreshlyReserved(_)
        ));
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b2).unwrap(),
            ReservationOutcome::Conflict
        ));
    }

    #[test]
    fn proposal_and_self_vote_at_same_view_are_distinct() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store);
        let prop = position(SigningKind::Proposal, 6);
        let vote = position(SigningKind::Vote, 6);
        let b = binding(b"x");
        assert!(matches!(
            journal.reserve_for_sign(&prop, &b).unwrap(),
            ReservationOutcome::FreshlyReserved(_)
        ));
        // Distinct kind ⇒ distinct position ⇒ another fresh reservation, not a
        // conflict.
        assert!(matches!(
            journal.reserve_for_sign(&vote, &b).unwrap(),
            ReservationOutcome::FreshlyReserved(_)
        ));
    }

    #[test]
    fn recovered_reserved_only_refuses_resigning() {
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Proposal, 8);
        let b = binding(b"decision-R");
        {
            let journal = SigningReservationJournal::attach(store.clone());
            let cont = match journal.reserve_for_sign(&pos, &b).unwrap() {
                ReservationOutcome::FreshlyReserved(c) => c,
                other => panic!("expected FreshlyReserved, got {:?}", other),
            };
            // Cross the invocation boundary, then simulate process death BEFORE
            // record_signed_result by dropping the capability and the journal.
            let _cap = journal.consume_for_signing(cont).unwrap();
        }
        // Reopen over the SAME durable bytes with a FRESH ownership domain: the
        // RESERVED byte survives, the live operation table does not ⇒
        // potentially-signed, refuse re-signing.
        let reopened = SigningReservationJournal::attach(store.reopen());
        assert!(matches!(
            reopened.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
        // A conflicting request after recovery is still refused as a conflict,
        // without altering the original obligation.
        let b2 = binding(b"decision-R2");
        assert!(matches!(
            reopened.reserve_for_sign(&pos, &b2).unwrap(),
            ReservationOutcome::Conflict
        ));
    }

    #[test]
    fn signed_result_survives_reopen_and_supports_exact_resend() {
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Vote, 2);
        let b = binding(b"decision-S");
        {
            let journal = SigningReservationJournal::attach(store.clone());
            let cap = reserve_and_invoke(&journal, &pos, &b);
            journal.record_signed_result(&cap, b"the-sig").unwrap();
        }
        let reopened = SigningReservationJournal::attach(store.reopen());
        assert!(matches!(
            reopened.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"the-sig"
        ));
    }

    #[test]
    fn read_and_write_failures_yield_no_permit() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store.clone());
        let pos = position(SigningKind::Proposal, 11);
        let b = binding(b"decision-F");

        store.set_fail_reads(true);
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b),
            Err(JournalError::Storage(_))
        ));
        store.set_fail_reads(false);

        store.set_fail_writes(true);
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b),
            Err(JournalError::Storage(_))
        ));
        store.set_fail_writes(false);
        // After the failed write there is no durable reservation and no live
        // continuation: a subsequent attempt is a fresh reservation, not a
        // conflict.
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::FreshlyReserved(_)
        ));
    }

    #[test]
    fn corrupt_record_fails_closed_on_reopen() {
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Proposal, 12);
        let b = binding(b"decision-C");
        {
            let journal = SigningReservationJournal::attach(store.clone());
            journal.reserve_for_sign(&pos, &b).unwrap();
        }
        store.corrupt(&pos.storage_key());
        let reopened = SigningReservationJournal::attach(store.reopen());
        assert!(matches!(
            reopened.reserve_for_sign(&pos, &b),
            Err(JournalError::Corruption(_))
        ));
    }

    #[test]
    fn second_handle_cannot_get_permit_for_reserved_position() {
        let store = Arc::new(ModelStore::default());
        let handle_a = SigningReservationJournal::attach(store.clone());
        let handle_b = SigningReservationJournal::attach(store.clone());
        let pos = position(SigningKind::Vote, 20);
        let b = binding(b"decision-X");
        // Handle A reserves.
        assert!(matches!(
            handle_a.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::FreshlyReserved(_)
        ));
        // Handle B (another supported handle over the same backend instance,
        // sharing the one ownership domain) sees the live reservation ⇒
        // potentially-signed. It can NEVER acquire a second live continuation for
        // the same position.
        assert!(matches!(
            handle_b.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
    }

    #[test]
    fn exhaustion_refuses_new_positions_and_preserves_existing() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach_with_budget(store, 1);
        let p0 = position(SigningKind::Proposal, 30);
        let p1 = position(SigningKind::Proposal, 31);
        let b = binding(b"budget");
        assert!(matches!(
            journal.reserve_for_sign(&p0, &b).unwrap(),
            ReservationOutcome::FreshlyReserved(_)
        ));
        // Budget of 1 reached: a NEW position is refused as exhausted.
        assert!(matches!(
            journal.reserve_for_sign(&p1, &b).unwrap(),
            ReservationOutcome::Exhausted
        ));
        // The already-reserved position's obligation is preserved: its durable
        // reservation is still present, so a re-request is potentially-signed
        // (never a second fresh live continuation), and a conflict is still
        // detected under a different binding.
        assert!(matches!(
            journal.reserve_for_sign(&p0, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
        assert!(matches!(
            journal.reserve_for_sign(&p0, &binding(b"budget-2")).unwrap(),
            ReservationOutcome::Conflict
        ));
    }

    #[test]
    fn signed_record_missing_signature_is_corruption() {
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Proposal, 40);
        let b = binding(b"decision-M");
        // Hand-craft a Signed record with a zero-length signature and valid crc.
        let mut record = SigningDecisionRecord::signed(pos, b, vec![9u8]);
        record.retained_signature = Some(vec![]); // force empty
        // encode() will produce sig_len=0 but stage=Signed; decode must reject.
        let bytes = record.encode().unwrap();
        store.overwrite(&pos.storage_key(), bytes);
        let journal = SigningReservationJournal::attach(store);
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b),
            Err(JournalError::Corruption(_))
        ));
    }

    // ------------------------------------------------------------------
    // Run 422 D7-D10 Correction B/C — operation-bound capability ownership,
    // checked publication, and the durable-acknowledgement uncertainty rule.
    // ------------------------------------------------------------------

    #[test]
    fn consume_rejects_foreign_domain_continuation() {
        // Two DISTINCT backend instances ⇒ two distinct ownership domains.
        let store_a = Arc::new(ModelStore::default());
        let store_b = Arc::new(ModelStore::default());
        let journal_a = SigningReservationJournal::attach(store_a);
        let journal_b = SigningReservationJournal::attach(store_b);
        let pos = position(SigningKind::Proposal, 50);
        let b = binding(b"decision");
        let cont = match journal_a.reserve_for_sign(&pos, &b).unwrap() {
            ReservationOutcome::FreshlyReserved(c) => c,
            other => panic!("expected FreshlyReserved, got {:?}", other),
        };
        // A foreign journal cannot consume another domain's continuation.
        assert!(matches!(
            journal_b.consume_for_signing(cont),
            Err(JournalError::InvalidResultPublication(_))
        ));
        // The originating reservation's obligation is preserved (a repeat request
        // is potentially-signed, never a fresh second continuation).
        assert!(matches!(
            journal_a.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
    }

    #[test]
    fn record_signed_result_rejects_foreign_domain_capability() {
        let store_a = Arc::new(ModelStore::default());
        let store_b = Arc::new(ModelStore::default());
        let journal_a = SigningReservationJournal::attach(store_a);
        let journal_b = SigningReservationJournal::attach(store_b);
        let pos = position(SigningKind::Vote, 51);
        let b = binding(b"decision");
        let cap = reserve_and_invoke(&journal_a, &pos, &b);
        // A capability minted in domain A cannot publish through domain B.
        assert!(matches!(
            journal_b.record_signed_result(&cap, b"sig"),
            Err(JournalError::InvalidResultPublication(_))
        ));
    }

    #[test]
    fn dropped_continuation_preserves_reservation_and_never_resigns() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store.clone());
        let pos = position(SigningKind::Proposal, 52);
        let b = binding(b"decision");
        // Reserve and then DROP the continuation without consuming it.
        match journal.reserve_for_sign(&pos, &b).unwrap() {
            ReservationOutcome::FreshlyReserved(_cont) => { /* dropped here */ }
            other => panic!("expected FreshlyReserved, got {:?}", other),
        }
        // The durable reservation is NOT released: the position never returns to
        // unused state; a later request is potentially-signed, never fresh.
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
    }

    #[test]
    fn second_supported_handle_cannot_obtain_a_continuation_for_a_live_position() {
        // Two supported handles over the SAME backend instance share one domain.
        let store = Arc::new(ModelStore::default());
        let handle_a = SigningReservationJournal::attach(store.clone());
        let handle_b = SigningReservationJournal::attach(store.clone());
        assert_eq!(
            handle_a.ownership_domain_token(),
            handle_b.ownership_domain_token()
        );
        let pos = position(SigningKind::Proposal, 53);
        let b = binding(b"decision");
        // Handle A owns the single live operation.
        let _cap_a = reserve_and_invoke(&handle_a, &pos, &b);
        // Handle B can NEVER obtain a continuation for the same live position, so
        // it can never publish over A's obligation.
        assert!(matches!(
            handle_b.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
    }

    #[test]
    fn record_signed_result_conflicting_overwrite_refuses_and_preserves() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store);
        let pos = position(SigningKind::Proposal, 54);
        let b = binding(b"decision");
        let cap = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap, b"first-sig").unwrap();
        // A second, DIFFERENT result under the same capability must not overwrite
        // the existing signed obligation.
        assert!(matches!(
            journal.record_signed_result(&cap, b"second-sig"),
            Err(JournalError::InvalidResultPublication(_))
        ));
        // The original retained signature is intact for exact retry.
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"first-sig"
        ));
    }

    #[test]
    fn record_signed_result_idempotent_identical_ok() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store);
        let pos = position(SigningKind::Vote, 55);
        let b = binding(b"decision");
        let cap = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap, b"the-sig").unwrap();
        // Republishing the IDENTICAL retained content, once durably acknowledged
        // in-process, is idempotently accepted through the same capability.
        journal.record_signed_result(&cap, b"the-sig").unwrap();
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"the-sig"
        ));
    }

    #[test]
    fn record_signed_result_oversize_signature_refused_and_preserves() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store);
        let pos = position(SigningKind::Proposal, 56);
        let b = binding(b"decision");
        let cap = reserve_and_invoke(&journal, &pos, &b);
        let oversized = vec![7u8; MAX_RETAINED_SIGNATURE_LEN + 1];
        assert!(matches!(
            journal.record_signed_result(&cap, &oversized),
            Err(JournalError::OversizeRecord { .. })
        ));
        // No Signed record was created; the reservation is preserved.
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
    }

    // ------------------------------------------------------------------
    // Correction C uncertainty rule — a readable-but-unacknowledged result
    // write is never reported as a durable publication.
    // ------------------------------------------------------------------

    #[test]
    fn uncertain_write_not_reported_success_and_retry_reissues_synced_write() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store.clone());
        let pos = position(SigningKind::Vote, 60);
        let b = binding(b"decision");
        let cap = reserve_and_invoke(&journal, &pos, &b);

        // (1) The write stores bytes but the durability ack is uncertain (error).
        store.set_store_then_error(true);
        assert!(matches!(
            journal.record_signed_result(&cap, b"the-sig"),
            Err(JournalError::Storage(_))
        ));

        // (2) The bytes are now READABLE, but readable-equality is NOT a barrier:
        //     a retained-result lookup in this process is potentially-signed, not
        //     an exact retry.
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));

        // (3) A second uncertain attempt through the same capability remains a
        //     failure (never a success on byte-equality), and never re-signs.
        assert!(matches!(
            journal.record_signed_result(&cap, b"the-sig"),
            Err(JournalError::Storage(_))
        ));
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));

        // (4) Once the durability action succeeds, the same capability re-issues
        //     the synced write and publication becomes acknowledged; only then is
        //     a retained resend reported.
        store.set_store_then_error(false);
        journal.record_signed_result(&cap, b"the-sig").unwrap();
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"the-sig"
        ));
    }

    #[test]
    fn uncertain_write_does_not_permit_conflicting_replacement() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store.clone());
        let pos = position(SigningKind::Proposal, 61);
        let b = binding(b"decision");
        let cap = reserve_and_invoke(&journal, &pos, &b);

        // First attempt stores "sig-A" bytes but reports uncertain.
        store.set_store_then_error(true);
        assert!(matches!(
            journal.record_signed_result(&cap, b"sig-A"),
            Err(JournalError::Storage(_))
        ));
        store.set_store_then_error(false);
        // A conflicting replacement with DIFFERENT bytes is refused — the
        // operation cannot replace its own result with different content.
        assert!(matches!(
            journal.record_signed_result(&cap, b"sig-B"),
            Err(JournalError::InvalidResultPublication(_))
        ));
        // Re-issuing the ORIGINAL bytes establishes the durable acknowledgement.
        journal.record_signed_result(&cap, b"sig-A").unwrap();
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"sig-A"
        ));
    }
}