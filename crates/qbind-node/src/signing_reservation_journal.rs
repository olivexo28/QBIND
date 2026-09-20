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

/// The outcome of a reservation request. Every non-`FreshlyReserved` outcome
/// that is not an exact retry must lead the caller to refuse the signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservationOutcome {
    /// A fresh reservation was durably committed under exclusive ownership. The
    /// caller — the one exclusive live operation — MAY invoke the signer exactly
    /// once for this decision. This permit is held in memory and is NOT
    /// reconstructible merely by reading `Reserved` from storage after a
    /// restart.
    FreshlyReserved,
    /// An exact retry: the identical decision was previously signed and its
    /// signature retained. Resend the retained signature; do NOT invoke the
    /// signer. The caller MUST still validate the retained signature's
    /// decision/context association before reuse.
    ExactRetryRetained(Vec<u8>),
    /// A conflicting decision (same position, different binding) exists. Refuse
    /// without altering the original obligation.
    Conflict,
    /// The position is in an uncertain state: a recovered `Reserved` record
    /// without a live permit, or another state that cannot establish the signer
    /// was never invoked. Treat as potentially-signed: refuse re-signing and
    /// preserve the reservation.
    PotentiallySigned,
    /// The journal's per-instance reservation budget is exhausted. Refuse
    /// further signing safely (no silent eviction of any conflict obligation).
    Exhausted,
}

// ============================================================================
// Backing store abstraction
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
}

// ============================================================================
// The journal
// ============================================================================

/// In-memory permit for a single live operation over one position. Its presence
/// (and the `signer_invoked` flag) is the knowledge that a restart cannot
/// reconstruct: reading `Reserved` from storage alone never yields a permit.
#[derive(Debug, Clone, Copy)]
struct LivePermit {
    signer_invoked: bool,
}

#[derive(Debug, Default)]
struct JournalInner {
    /// Positions this live instance has reserved and may (once) sign.
    live: HashMap<SigningPosition, LivePermit>,
    /// Count of distinct new positions reserved by this instance (exhaustion
    /// accounting, checked arithmetic).
    reserved_positions: u64,
}

/// A bounded, versioned, signing-scoped, crash-consistent reservation journal.
///
/// Exclusivity is enforced by a single [`Mutex`] guarding every read-then-write
/// reservation for all callers **sharing this instance** (share it via
/// `Arc<SigningReservationJournal>`); an atomic storage write alone would not
/// make an unsynchronized read-then-write safe. A *second* handle wrapping the
/// same store cannot obtain a live permit for an already-`Reserved` position:
/// its live map does not contain that position, so the lookup returns
/// [`ReservationOutcome::PotentiallySigned`].
pub struct SigningReservationJournal {
    store: Arc<dyn SigningJournalStorage>,
    inner: Mutex<JournalInner>,
    max_reserved_positions: u64,
}

impl std::fmt::Debug for SigningReservationJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningReservationJournal")
            .field("max_reserved_positions", &self.max_reserved_positions)
            .finish()
    }
}

impl SigningReservationJournal {
    /// Attach to (reopen) a signing journal over `store`, with the default
    /// reservation budget.
    ///
    /// This is deliberately non-scanning and non-initializing: it does not wipe,
    /// repair, or convert missing/corrupt established state into an empty usable
    /// journal. Its in-memory live-permit map starts empty, which is exactly the
    /// crash-recovery posture — any `Reserved` record already in the store is
    /// treated as potentially-signed on the next reservation.
    pub fn attach(store: Arc<dyn SigningJournalStorage>) -> Self {
        Self::attach_with_budget(store, DEFAULT_MAX_RESERVED_POSITIONS)
    }

    /// Attach with an explicit reservation budget (small-fixture / bounds tests).
    pub fn attach_with_budget(store: Arc<dyn SigningJournalStorage>, max_reserved_positions: u64) -> Self {
        Self {
            store,
            inner: Mutex::new(JournalInner::default()),
            max_reserved_positions,
        }
    }

    /// Reserve `position` for exactly one decision identified by `binding`,
    /// serialized against all callers sharing this instance.
    ///
    /// Ordering guarantee: on [`ReservationOutcome::FreshlyReserved`] the durable
    /// reservation has been written and its barrier acknowledged BEFORE this
    /// returns; if the durable write fails or is uncertain, an `Err` is returned
    /// and no permit is granted (the caller must not sign).
    pub fn reserve_for_sign(
        &self,
        position: &SigningPosition,
        binding: &BindingDigest,
    ) -> Result<ReservationOutcome, JournalError> {
        let mut inner = self.inner.lock().map_err(|_| JournalError::LockPoisoned)?;

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
                SigningRecordStage::Signed => match record.retained_signature {
                    Some(sig) => Ok(ReservationOutcome::ExactRetryRetained(sig)),
                    None => Err(JournalError::Corruption(
                        "signed record missing retained signature".to_string(),
                    )),
                },
                SigningRecordStage::Reserved => match inner.live.get(position) {
                    // A live operation that has NOT yet invoked the signer may
                    // continue exactly once under its own exclusive ownership.
                    Some(permit) if !permit.signer_invoked => Ok(ReservationOutcome::FreshlyReserved),
                    // A live op that already invoked the signer, or a recovered
                    // reservation with no live permit at all, is potentially
                    // signed — refuse re-signing and preserve the reservation.
                    _ => Ok(ReservationOutcome::PotentiallySigned),
                },
            };
        }

        // No existing record: a new position in this journal.
        if inner.reserved_positions >= self.max_reserved_positions {
            return Ok(ReservationOutcome::Exhausted);
        }

        let record = SigningDecisionRecord::reserved(*position, *binding);
        let encoded = record.encode()?;
        // Durable reservation acknowledgement corresponds to THIS record write.
        self.store.put_signing_record_synced(&key, &encoded)?; // failure ⇒ Err ⇒ no permit

        // Only after the durable ack do we record the accounting and the live
        // permit (checked arithmetic; overflow is terminal, never wraparound).
        inner.reserved_positions = inner
            .reserved_positions
            .checked_add(1)
            .ok_or(JournalError::Overflow)?;
        inner
            .live
            .insert(*position, LivePermit { signer_invoked: false });
        Ok(ReservationOutcome::FreshlyReserved)
    }

    /// Mark that the exclusive live operation is about to invoke the signer for
    /// `position`. After this, a repeated live reservation for the same position
    /// is treated as potentially-signed (the signer may already have run).
    ///
    /// Call this immediately BEFORE `signer.sign_*`.
    pub fn note_signer_invoked(&self, position: &SigningPosition) -> Result<(), JournalError> {
        let mut inner = self.inner.lock().map_err(|_| JournalError::LockPoisoned)?;
        if let Some(permit) = inner.live.get_mut(position) {
            permit.signer_invoked = true;
        }
        Ok(())
    }

    /// Persist the retained signature for the exact reserved decision, moving the
    /// record to `Signed`. The retained signature is associated with the exact
    /// position + binding.
    ///
    /// If this fails (or is uncertain), the caller MUST preserve the
    /// potentially-signed obligation, suppress facade handoff for that attempt,
    /// and NOT invoke the signer again to recover availability — the reservation
    /// is never released here.
    pub fn record_signed_result(
        &self,
        position: &SigningPosition,
        binding: &BindingDigest,
        signature: &[u8],
    ) -> Result<(), JournalError> {
        if signature.len() > MAX_RETAINED_SIGNATURE_LEN {
            return Err(JournalError::OversizeRecord {
                len: signature.len(),
                max: MAX_RETAINED_SIGNATURE_LEN,
            });
        }
        let _inner = self.inner.lock().map_err(|_| JournalError::LockPoisoned)?;
        let key = position.storage_key();
        let record = SigningDecisionRecord::signed(*position, *binding, signature.to_vec());
        let encoded = record.encode()?;
        self.store.put_signing_record_synced(&key, &encoded)?;
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
    /// read/write/serialize/recovery model deterministically. A "restart" is
    /// modelled by constructing a NEW `SigningReservationJournal` over the SAME
    /// `Arc<ModelStore>` (the bytes survive; the in-memory live-permit map does
    /// not).
    #[derive(Default)]
    struct ModelStore {
        map: RwLock<StdHashMap<Vec<u8>, Vec<u8>>>,
        fail_reads: RwLock<bool>,
        fail_writes: RwLock<bool>,
    }

    impl ModelStore {
        fn set_fail_reads(&self, v: bool) {
            *self.fail_reads.write().unwrap() = v;
        }
        fn set_fail_writes(&self, v: bool) {
            *self.fail_writes.write().unwrap() = v;
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
            self.map.write().unwrap().insert(key.to_vec(), value.to_vec());
            Ok(())
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

        // First reservation is fresh.
        assert_eq!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::FreshlyReserved
        );
        journal.note_signer_invoked(&pos).unwrap();
        journal.record_signed_result(&pos, &b, b"sigbytes").unwrap();

        // Exact retry reuses the retained signature; no fresh permit.
        assert_eq!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(b"sigbytes".to_vec())
        );
    }

    #[test]
    fn conflicting_binding_is_refused() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store);
        let pos = position(SigningKind::Vote, 4);
        let b1 = binding(b"content-1");
        let b2 = binding(b"content-2");
        assert_ne!(b1, b2);
        assert_eq!(
            journal.reserve_for_sign(&pos, &b1).unwrap(),
            ReservationOutcome::FreshlyReserved
        );
        assert_eq!(
            journal.reserve_for_sign(&pos, &b2).unwrap(),
            ReservationOutcome::Conflict
        );
    }

    #[test]
    fn proposal_and_self_vote_at_same_view_are_distinct() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach(store);
        let prop = position(SigningKind::Proposal, 6);
        let vote = position(SigningKind::Vote, 6);
        let b = binding(b"x");
        assert_eq!(
            journal.reserve_for_sign(&prop, &b).unwrap(),
            ReservationOutcome::FreshlyReserved
        );
        // Distinct kind ⇒ distinct position ⇒ another fresh reservation, not a
        // conflict.
        assert_eq!(
            journal.reserve_for_sign(&vote, &b).unwrap(),
            ReservationOutcome::FreshlyReserved
        );
    }

    #[test]
    fn recovered_reserved_only_refuses_resigning() {
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Proposal, 8);
        let b = binding(b"decision-R");
        {
            let journal = SigningReservationJournal::attach(store.clone());
            assert_eq!(
                journal.reserve_for_sign(&pos, &b).unwrap(),
                ReservationOutcome::FreshlyReserved
            );
            journal.note_signer_invoked(&pos).unwrap();
            // Simulate process death BEFORE record_signed_result: drop journal.
        }
        // Reopen over the SAME store: the RESERVED byte survives, the live permit
        // does not ⇒ potentially-signed, refuse re-signing.
        let reopened = SigningReservationJournal::attach(store.clone());
        assert_eq!(
            reopened.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        );
        // A conflicting request after recovery is still refused as a conflict,
        // without altering the original obligation.
        let b2 = binding(b"decision-R2");
        assert_eq!(
            reopened.reserve_for_sign(&pos, &b2).unwrap(),
            ReservationOutcome::Conflict
        );
    }

    #[test]
    fn signed_result_survives_reopen_and_supports_exact_resend() {
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Vote, 2);
        let b = binding(b"decision-S");
        {
            let journal = SigningReservationJournal::attach(store.clone());
            journal.reserve_for_sign(&pos, &b).unwrap();
            journal.note_signer_invoked(&pos).unwrap();
            journal.record_signed_result(&pos, &b, b"the-sig").unwrap();
        }
        let reopened = SigningReservationJournal::attach(store);
        assert_eq!(
            reopened.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(b"the-sig".to_vec())
        );
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
        // permit: a subsequent attempt is a fresh reservation, not a conflict.
        assert_eq!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::FreshlyReserved
        );
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
        let reopened = SigningReservationJournal::attach(store);
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
        assert_eq!(
            handle_a.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::FreshlyReserved
        );
        // Handle B (another supported handle over the same store) sees the
        // RESERVED record but has no live permit ⇒ potentially-signed. It can
        // NEVER acquire a second live continuation for the same position.
        assert_eq!(
            handle_b.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        );
    }

    #[test]
    fn exhaustion_refuses_new_positions_and_preserves_existing() {
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach_with_budget(store, 1);
        let p0 = position(SigningKind::Proposal, 30);
        let p1 = position(SigningKind::Proposal, 31);
        let b = binding(b"budget");
        assert_eq!(
            journal.reserve_for_sign(&p0, &b).unwrap(),
            ReservationOutcome::FreshlyReserved
        );
        // Budget of 1 reached: a NEW position is refused as exhausted.
        assert_eq!(
            journal.reserve_for_sign(&p1, &b).unwrap(),
            ReservationOutcome::Exhausted
        );
        // The already-reserved position's obligation is preserved: a live
        // continuation is still available and a conflict is still detected.
        assert_eq!(
            journal.reserve_for_sign(&p0, &b).unwrap(),
            ReservationOutcome::FreshlyReserved
        );
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
}