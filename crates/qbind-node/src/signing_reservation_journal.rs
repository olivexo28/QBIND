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

use std::collections::{HashMap, VecDeque};
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

/// Default maximum number of distinct positions a journal will reserve before
/// refusing further signing (exhaustion). This is the default **journal-wide**
/// limit an explicit initialization establishes; it is durably recorded in the
/// initialization metadata and reconstructed on open, not a per-handle bound.
/// Exhaustion refuses safely; it never silently evicts a conflict obligation.
pub const DEFAULT_MAX_RESERVED_POSITIONS: u64 = 1_048_576;

/// Run 422 D7-D10 Correction E — the largest position limit a new journal may be
/// initialized with. Larger requested limits are rejected (`UnsupportedLimit`)
/// with checked arithmetic **before** any durable write. A limit of `0` is
/// explicitly supported and means the journal accepts **no** reservations (every
/// reservation is `Exhausted`). This bounds only the logical position counter; it
/// is not a disk-space or process-RSS bound.
pub const MAX_SUPPORTED_RESERVED_POSITIONS: u64 = DEFAULT_MAX_RESERVED_POSITIONS;

/// Run 422 D7-D10 Correction E — signing-journal **initialization-metadata**
/// format version. This is a distinct persistence-format identifier for the
/// bounded initialization/accounting metadata record, independent of the
/// signing-decision [`SIGNING_RECORD_FORMAT_VERSION`], the wire-message version,
/// and the D6 signing-format version. Unknown/incompatible metadata versions are
/// refused fail-closed; the journal never falls back to initialization.
pub const SIGNING_METADATA_FORMAT_VERSION: u16 = 1;

/// Magic prefix identifying an initialization-metadata record.
const METADATA_MAGIC: [u8; 4] = *b"QSJM";

/// Fixed encoded length of the initialization-metadata record:
/// `magic[4] | metadata_format_version[2] | max_reserved_positions[8] |
///  reserved_positions[8] | crc32[4]`.
const METADATA_ENCODED_LEN: usize = 4 + 2 + 8 + 8 + 4;

/// Run 422 D7-D10 Correction E — maximum number of distinct positions retained in
/// the shared **recovered-acknowledgement cache**. The cache is process-local
/// bookkeeping (never a durable record); at capacity the oldest process-local
/// entry is evicted to admit a new one. Total retained payload is therefore
/// bounded by `MAX_RECOVERED_ACK_ENTRIES * MAX_RETAINED_SIGNATURE_LEN`. Eviction
/// only drops the process-local acknowledgement; it never deletes a durable
/// signing record or a live conflict obligation, and a later cache miss simply
/// repeats the durability barrier.
pub const MAX_RECOVERED_ACK_ENTRIES: usize = 128;

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

// ============================================================================
// Initialization / accounting metadata (Run 422 D7-D10 Correction E)
// ============================================================================

/// Bounded, versioned, checksummed **initialization-and-accounting metadata**
/// for one local signing journal. A single metadata record is durably published
/// by explicit initialization and validated (never re-created) on open. It is the
/// evidence that the signing namespace was explicitly initialized and carries the
/// established journal-wide position limit plus the durable count of persisted
/// distinct positions, so capacity survives a backend close/reopen and cannot be
/// relaxed by attaching another handle.
///
/// It is a **local storage** artefact only: a readable metadata record proves an
/// explicit local initialization occurred, not that a validator key has never
/// signed, and not that a prior uncertain durability operation was acknowledged.
/// It contains no key material and no attacker-controlled content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningJournalMetadata {
    /// Metadata-record format version (persistence only; distinct from the
    /// decision-record, wire-message, and D6 signing-format versions).
    pub metadata_format_version: u16,
    /// The established journal-wide position limit. One consistent limit applies
    /// across every handle and across restarts; it is never relaxed by another
    /// handle's configuration.
    pub max_reserved_positions: u64,
    /// The durable count of distinct persisted positions (both `Reserved` and
    /// `Signed` count exactly once). Updated atomically with each new reservation
    /// record and reconstructed/validated against the stored records on open.
    pub reserved_positions: u64,
}

impl SigningJournalMetadata {
    fn new(max_reserved_positions: u64, reserved_positions: u64) -> Self {
        Self {
            metadata_format_version: SIGNING_METADATA_FORMAT_VERSION,
            max_reserved_positions,
            reserved_positions,
        }
    }

    /// Serialize to the fixed-length, checksummed metadata encoding.
    ///
    /// Layout (big-endian): `magic[4] | metadata_format_version[2] |
    /// max_reserved_positions[8] | reserved_positions[8] | crc32[4]`, where
    /// `crc32` covers all preceding bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(METADATA_ENCODED_LEN);
        body.extend_from_slice(&METADATA_MAGIC);
        body.extend_from_slice(&self.metadata_format_version.to_be_bytes());
        body.extend_from_slice(&self.max_reserved_positions.to_be_bytes());
        body.extend_from_slice(&self.reserved_positions.to_be_bytes());
        let crc = signing_journal_crc32(&body);
        body.extend_from_slice(&crc.to_be_bytes());
        body
    }

    /// Decode from the checksummed metadata encoding, fail-closed on any
    /// malformed, truncated, incompatible, or inconsistent input. A decode
    /// failure never yields a usable "assume uninitialized" result — the journal
    /// refuses rather than falling back to initialization.
    pub fn decode(data: &[u8]) -> Result<Self, JournalError> {
        // Fixed length: a metadata record is exactly `METADATA_ENCODED_LEN`
        // bytes. Anything shorter is truncated; anything longer is inconsistent.
        if data.len() < METADATA_ENCODED_LEN {
            return Err(JournalError::Truncated);
        }
        if data.len() > METADATA_ENCODED_LEN {
            return Err(JournalError::Corruption(
                "metadata record length inconsistent".to_string(),
            ));
        }
        let (body, crc_bytes) = data.split_at(data.len() - 4);
        let stored_crc = u32::from_be_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
        if signing_journal_crc32(body) != stored_crc {
            return Err(JournalError::Corruption(
                "metadata checksum mismatch".to_string(),
            ));
        }
        if body[0..4] != METADATA_MAGIC {
            return Err(JournalError::Corruption("metadata magic mismatch".to_string()));
        }
        let metadata_format_version = u16::from_be_bytes([body[4], body[5]]);
        if metadata_format_version != SIGNING_METADATA_FORMAT_VERSION {
            return Err(JournalError::UnsupportedMetadataVersion(
                metadata_format_version,
            ));
        }
        let max_reserved_positions = u64::from_be_bytes(body[6..14].try_into().unwrap());
        let reserved_positions = u64::from_be_bytes(body[14..22].try_into().unwrap());
        // Structural accounting bounds independent of the stored records: the
        // established limit must be supported, and the durable count must not
        // exceed it. These are checked before any counter is trusted.
        if max_reserved_positions > MAX_SUPPORTED_RESERVED_POSITIONS {
            return Err(JournalError::AccountingInconsistent(format!(
                "established limit {} exceeds supported maximum {}",
                max_reserved_positions, MAX_SUPPORTED_RESERVED_POSITIONS
            )));
        }
        if reserved_positions > max_reserved_positions {
            return Err(JournalError::AccountingInconsistent(format!(
                "durable reserved count {} exceeds established limit {}",
                reserved_positions, max_reserved_positions
            )));
        }
        Ok(Self {
            metadata_format_version,
            max_reserved_positions,
            reserved_positions,
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
    /// The stored initialization metadata declares a metadata-format version this
    /// binary does not support. Refused fail-closed; never treated as
    /// uninitialized.
    UnsupportedMetadataVersion(u16),
    /// Run 422 D7-D10 Correction E — an established-journal open found no
    /// initialization metadata **and** no records: the local journal was never
    /// explicitly initialized. Open refuses rather than silently initializing.
    NotInitialized,
    /// Run 422 D7-D10 Correction E — an established-journal open found signing
    /// records but **no** initialization metadata (a legacy / externally-written
    /// namespace). Refused fail-closed: such records are never silently adopted,
    /// deleted, or migrated.
    LegacyRecordsWithoutMetadata,
    /// Run 422 D7-D10 Correction E — explicit initialization was requested for a
    /// journal that is already established (initialization metadata present, or
    /// the shared ownership domain already initialized in-process). Refused so a
    /// repeated initialization can never reset an established journal.
    AlreadyInitialized,
    /// Run 422 D7-D10 Correction E — explicit initialization was requested over a
    /// signing namespace that already contains records without metadata. A new
    /// journal requires an empty signing namespace; existing records are never
    /// adopted or overwritten.
    NonEmptyNamespace,
    /// Run 422 D7-D10 Correction E — a requested position limit exceeds the
    /// supported maximum. Rejected with checked arithmetic before any durable
    /// write or allocation.
    UnsupportedLimit(u64),
    /// Run 422 D7-D10 Correction E — the durable metadata accounting is
    /// inconsistent with the stored records (counted positions disagree with the
    /// recorded count, the count exceeds the limit, or a stored key does not match
    /// its record's canonical position). Refused fail-closed; never repaired.
    AccountingInconsistent(String),
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
            JournalError::UnsupportedMetadataVersion(v) => {
                write!(f, "signing-journal unsupported metadata version: {}", v)
            }
            JournalError::NotInitialized => {
                write!(f, "signing-journal not initialized (no established metadata)")
            }
            JournalError::LegacyRecordsWithoutMetadata => write!(
                f,
                "signing-journal has records without initialization metadata"
            ),
            JournalError::AlreadyInitialized => {
                write!(f, "signing-journal already initialized")
            }
            JournalError::NonEmptyNamespace => {
                write!(f, "signing-journal initialization requires an empty namespace")
            }
            JournalError::UnsupportedLimit(l) => {
                write!(f, "signing-journal unsupported position limit: {}", l)
            }
            JournalError::AccountingInconsistent(m) => {
                write!(f, "signing-journal accounting inconsistent: {}", m)
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

    /// Run 422 D7-D10 Correction E — read the raw initialization-metadata bytes
    /// for this signing namespace, or `None` if absent. Corruption detected by the
    /// storage envelope is surfaced as [`StorageError::Corruption`]. The metadata
    /// is stored under a backend-owned key **within** the signing namespace and is
    /// never returned by [`Self::for_each_signing_record`].
    fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError>;

    /// Run 422 D7-D10 Correction E — write the initialization-metadata bytes under
    /// an explicit durability barrier (synced write). Used by explicit
    /// initialization, where no decision record is written. MUST NOT return
    /// `Ok(())` until the metadata is synchronized to stable storage (for a
    /// durable backend).
    fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError>;

    /// Run 422 D7-D10 Correction E — persist a new signing-decision record **and**
    /// the updated accounting metadata in a **single atomic, synced** storage
    /// operation. Either both the record at `record_key` and the metadata become
    /// durable together, or neither does; a durable backend MUST NOT expose a
    /// state where the record is present but the metadata count was not advanced
    /// (or vice versa) after a crash. MUST NOT return `Ok(())` until the atomic
    /// batch is synchronized to stable storage (for a durable backend).
    ///
    /// A non-durable model backend MUST still model the atomicity honestly by
    /// applying both writes under a single lock acquisition; it documents that it
    /// is not crash-atomic persistent storage.
    fn put_signing_record_and_metadata_synced(
        &self,
        record_key: &[u8],
        record_value: &[u8],
        metadata_value: &[u8],
    ) -> Result<(), StorageError>;

    /// Run 422 D7-D10 Correction E — bounded **streaming** visit over every
    /// signing-decision record in this namespace, in storage-key order. The
    /// visitor is called once per record with the journal-level record key (the
    /// same key space as [`Self::get_signing_record`], i.e. the backend's own
    /// storage prefix is stripped) and the envelope-unwrapped record bytes.
    ///
    /// This is deliberately streaming: the backend yields one record at a time and
    /// never materializes the whole namespace into a collection, and the caller
    /// counts/validates incrementally. Read/iterator errors and envelope
    /// corruption are propagated as [`StorageError`] and abort the scan; a visitor
    /// error aborts the scan and is propagated. The initialization-metadata key is
    /// excluded. Each yielded value is bounded by the record encoding the caller
    /// enforces; the underlying database API still allocates one key/value buffer
    /// per yielded record (documented, per-record bounded, honesty note).
    fn for_each_signing_record(
        &self,
        visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
    ) -> Result<(), StorageError>;

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

/// Run 422 D7-D10 Correction E — a bounded, process-local cache of recovered
/// signing-record durability acknowledgements. Entries are keyed by position and
/// bound to the **exact** stored record; a hit authorizes only an exact retained
/// resend of that identical record. The cache never holds a durable obligation:
/// evicting an entry drops only the process-local acknowledgement and a later
/// miss simply repeats the durability barrier. Bounds are enforced by
/// [`MAX_RECOVERED_ACK_ENTRIES`] with FIFO eviction of the oldest entry.
#[derive(Debug)]
struct RecoveredAckCache {
    map: HashMap<SigningPosition, SigningDecisionRecord>,
    order: VecDeque<SigningPosition>,
    max_entries: usize,
}

impl RecoveredAckCache {
    fn new(max_entries: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            max_entries,
        }
    }

    /// A cache hit only when the exact identical record is cached for `position`.
    fn get(&self, position: &SigningPosition) -> Option<&SigningDecisionRecord> {
        self.map.get(position)
    }

    /// Insert an acknowledged record, bounding the entry count. If `position` is
    /// already cached its record is updated in place (no growth). Otherwise, if at
    /// capacity, the oldest process-local entry is evicted first. A `max_entries`
    /// of zero declines to cache (a later miss repeats the barrier). Returns the
    /// evicted position, if any, so a caller/test can observe reclamation.
    fn insert(
        &mut self,
        position: SigningPosition,
        record: SigningDecisionRecord,
    ) -> Option<SigningPosition> {
        if self.map.contains_key(&position) {
            self.map.insert(position, record);
            return None;
        }
        if self.max_entries == 0 {
            // Declining to cache is a safe outcome: the durable record is intact
            // and a later miss re-establishes the barrier.
            return None;
        }
        let mut evicted = None;
        while self.map.len() >= self.max_entries {
            if let Some(old) = self.order.pop_front() {
                // Evict only the process-local acknowledgement; the durable record
                // and any live obligation are untouched.
                self.map.remove(&old);
                evicted = Some(old);
            } else {
                break;
            }
        }
        self.map.insert(position, record);
        self.order.push_back(position);
        evicted
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// Run 422 D7-D10 Correction E — the established (durably validated) state of one
/// signing journal ownership domain: the journal-wide position limit read from
/// (or written by) the initialization metadata. Present only after an explicit
/// `initialize` or a validating `open` has established this domain in-process.
#[derive(Debug, Clone, Copy)]
struct EstablishedState {
    /// The one consistent journal-wide position limit. Applies across every handle
    /// and across restarts; never relaxed by another handle's configuration.
    max_reserved_positions: u64,
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
    /// Run 422 D7-D10 Correction E — the established journal-wide limit, present
    /// once this domain has been explicitly initialized or validated by open.
    /// `None` means this backend instance's domain has not yet been established
    /// in-process; the first `initialize`/`open` sets it under the domain lock, so
    /// a second handle over the same instance shares it without re-scanning or
    /// resetting, and concurrent init/open cannot duplicate-initialize.
    established: Option<EstablishedState>,
    /// Positions with a live operation in this process.
    live: HashMap<SigningPosition, LiveState>,
    /// Run 422 D7-D10 Correction B/E — bounded recovery-acknowledgement cache.
    /// After a recovered (no live entry) `Signed` record has had its
    /// signing-record durability barrier established in THIS domain (an identical
    /// synced re-write that returned `Ok`), the exact acknowledged record is
    /// retained here keyed by position, bound to the EXACT stored record (position
    /// + binding + retained bytes): a cache hit authorizes an exact retained
    /// resend of ONLY that record. It is never a generic "position acknowledged"
    /// flag and can never authorize a different, conflicting, or later-mutated
    /// record. It grants no signer-invocation and no result-publication
    /// capability, and is bounded by [`MAX_RECOVERED_ACK_ENTRIES`].
    recovered_acked: RecoveredAckCache,
    /// Durable count of distinct persisted positions reserved in this domain
    /// (exhaustion accounting, checked arithmetic). Seeded from the durable
    /// metadata on establishment and advanced only in lockstep with the atomic
    /// record+metadata write.
    reserved_positions: u64,
    /// Run 422 D7-D10 Correction E — set when an atomic reservation/accounting
    /// write returned an error or uncertain outcome. Because a failed
    /// acknowledgement does not prove no bytes were stored, the in-memory
    /// `reserved_positions` may be stale; while this is set the next admission
    /// re-reads the durable metadata count and reconciles before admitting any new
    /// position, so stale accounting can never admit past the durable limit.
    accounting_uncertain: bool,
    /// Monotonic source of unique live operation ids (checked; exhaustion is a
    /// terminal fail-closed state, never wraparound). In-process bookkeeping.
    next_operation_id: u64,
}

impl SigningOwnershipDomain {
    /// Create a fresh ownership domain with a process-unique token. Backends call
    /// this once per instance (via a `OnceLock`) and share the resulting `Arc`.
    /// The domain starts **unestablished**: no journal-wide limit and a zero
    /// counter until an explicit `initialize`/`open` validates durable state.
    pub fn new() -> Arc<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        // Process-unique, monotonically increasing domain token. This only needs
        // to distinguish concurrently-live domains within one process; it is not
        // persisted and carries no durability meaning.
        static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
        Arc::new(Self {
            token: NEXT_TOKEN.fetch_add(1, Ordering::Relaxed),
            inner: Mutex::new(DomainInner {
                established: None,
                live: HashMap::new(),
                recovered_acked: RecoveredAckCache::new(MAX_RECOVERED_ACK_ENTRIES),
                reserved_positions: 0,
                accounting_uncertain: false,
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
}

impl std::fmt::Debug for SigningReservationJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningReservationJournal")
            .field("domain_token", &self.domain.token)
            .finish()
    }
}

impl SigningReservationJournal {
    /// Run 422 D7-D10 Correction E — **explicitly initialize a new local
    /// journal**. This is the only route that creates initialization metadata; it
    /// requires an **empty signing namespace** (no metadata and no records) and
    /// durably publishes bounded, versioned initialization metadata carrying the
    /// established journal-wide position `limit` and a zero position count.
    ///
    /// It refuses fail-closed and never resets an established journal:
    /// * `UnsupportedLimit` if `limit` exceeds [`MAX_SUPPORTED_RESERVED_POSITIONS`]
    ///   (checked before any durable write). `limit == 0` is supported and admits
    ///   no reservations.
    /// * `AlreadyInitialized` if this backend instance's domain was already
    ///   established in-process, or durable initialization metadata already exists
    ///   (a repeated initialization preserves the existing established state).
    /// * `NonEmptyNamespace` if the namespace already contains signing records
    ///   without metadata — legacy records are never adopted, deleted, or migrated.
    ///
    /// Initialization is a **local storage** operation only. It is not proof that
    /// a validator key has never signed: an empty directory and a lost or
    /// rolled-back directory are locally indistinguishable. Production startup does
    /// not call this; tests initialize fresh fixtures explicitly.
    pub fn initialize(
        store: Arc<dyn SigningJournalStorage>,
        limit: u64,
    ) -> Result<Self, JournalError> {
        // Reject unsupported configuration with checked comparison BEFORE any
        // durable write or allocation.
        if limit > MAX_SUPPORTED_RESERVED_POSITIONS {
            return Err(JournalError::UnsupportedLimit(limit));
        }
        let domain = store.signing_ownership_domain();
        let mut inner = domain.inner.lock().map_err(|_| JournalError::LockPoisoned)?;

        // Serialized against concurrent init/open on the same instance: an
        // already-established domain is never re-initialized or reset.
        if inner.established.is_some() {
            return Err(JournalError::AlreadyInitialized);
        }
        // Durable metadata already present ⇒ established journal ⇒ refuse; never
        // reset. (A fresh in-process domain over a reopened backend reaches here.)
        if store.get_signing_metadata()?.is_some() {
            return Err(JournalError::AlreadyInitialized);
        }
        // A new journal requires an empty namespace: refuse if any record exists.
        // Bounded streaming existence check — abort on the first record.
        if Self::namespace_has_any_record(store.as_ref())? {
            return Err(JournalError::NonEmptyNamespace);
        }

        // Publish the initialization metadata durably (synced). Only on a
        // successful acknowledgement do we establish the in-process domain.
        let metadata = SigningJournalMetadata::new(limit, 0);
        store.put_signing_metadata_synced(&metadata.encode())?;
        inner.established = Some(EstablishedState {
            max_reserved_positions: limit,
        });
        inner.reserved_positions = 0;
        drop(inner);
        Ok(Self { store, domain })
    }

    /// Run 422 D7-D10 Correction E — **open and validate an established local
    /// journal**. Requires valid initialization metadata and records consistent
    /// with it; it never falls back to initialization and never creates metadata.
    ///
    /// If this backend instance's domain was already established in-process (an
    /// earlier `initialize`/`open` over the SAME instance), opening another
    /// supported handle simply shares that domain — live operations, operation
    /// ids, acknowledgement state, the durable counter, and shared ownership are
    /// preserved and the namespace is NOT re-scanned.
    ///
    /// Otherwise it performs bounded streaming validation of the signing
    /// namespace under the domain lock and refuses fail-closed on:
    /// * `NotInitialized` — no metadata and no records (never initialized).
    /// * `LegacyRecordsWithoutMetadata` — records present but no metadata.
    /// * metadata corruption / truncation / unsupported version.
    /// * `AccountingInconsistent` — counted positions disagree with the recorded
    ///   count, the count exceeds the limit, or a stored key does not match its
    ///   record's canonical position.
    /// Iterator/read errors and record corruption are propagated.
    pub fn open(store: Arc<dyn SigningJournalStorage>) -> Result<Self, JournalError> {
        let domain = store.signing_ownership_domain();
        let mut inner = domain.inner.lock().map_err(|_| JournalError::LockPoisoned)?;

        // A second supported handle over an already-established instance shares the
        // domain unchanged: no re-scan, no reset, live/acked state preserved.
        if inner.established.is_some() {
            drop(inner);
            return Ok(Self { store, domain });
        }

        // Validate the established metadata; never initialize on absence/corruption.
        let metadata_bytes = store.get_signing_metadata()?;
        let metadata = match metadata_bytes {
            Some(bytes) => SigningJournalMetadata::decode(&bytes)?,
            None => {
                // No metadata: distinguish a never-initialized empty namespace from
                // a legacy/foreign namespace that has records without metadata.
                if Self::namespace_has_any_record(store.as_ref())? {
                    return Err(JournalError::LegacyRecordsWithoutMetadata);
                }
                return Err(JournalError::NotInitialized);
            }
        };

        // Bounded streaming validation: count distinct persisted positions and
        // check key/record association, formats, bounds, and checksums per record.
        // We never collect the namespace or allocate from stored counts. A record
        // validation failure is captured as its precise `JournalError` and the
        // scan is aborted via a sentinel; a genuine iterator/read error propagates
        // distinctly.
        const ABORT: &str = "__signing_validation_abort__";
        let mut counted: u64 = 0;
        let mut validation_err: Option<JournalError> = None;
        let scan = store.for_each_signing_record(&mut |key: &[u8], value: &[u8]| {
            let record = match SigningDecisionRecord::decode(value) {
                Ok(r) => r,
                Err(e) => {
                    validation_err = Some(e);
                    return Err(StorageError::Other(ABORT.to_string()));
                }
            };
            // Key/record association: the stored key MUST be the record's own
            // canonical position key.
            if record.position.storage_key() != key {
                validation_err = Some(JournalError::AccountingInconsistent(
                    "stored key does not match record position".to_string(),
                ));
                return Err(StorageError::Other(ABORT.to_string()));
            }
            match counted.checked_add(1) {
                Some(n) => counted = n,
                None => {
                    validation_err = Some(JournalError::Overflow);
                    return Err(StorageError::Other(ABORT.to_string()));
                }
            }
            Ok(())
        });
        match scan {
            Ok(()) => {}
            Err(StorageError::Other(ref m)) if m == ABORT => {
                return Err(validation_err.unwrap_or_else(|| {
                    JournalError::Corruption("record validation aborted".to_string())
                }));
            }
            Err(e) => return Err(e.into()),
        }

        // Accounting consistency: the streamed count MUST equal the durable count,
        // and the durable count MUST be within the established limit (already
        // checked structurally in decode; re-checked against the stream here).
        if counted != metadata.reserved_positions {
            return Err(JournalError::AccountingInconsistent(format!(
                "metadata records {} distinct positions but {} are stored",
                metadata.reserved_positions, counted
            )));
        }
        if counted > metadata.max_reserved_positions {
            return Err(JournalError::AccountingInconsistent(format!(
                "stored positions {} exceed established limit {}",
                counted, metadata.max_reserved_positions
            )));
        }

        inner.established = Some(EstablishedState {
            max_reserved_positions: metadata.max_reserved_positions,
        });
        inner.reserved_positions = counted;
        drop(inner);
        Ok(Self { store, domain })
    }

    /// Bounded streaming existence check: returns `true` as soon as any signing
    /// record is observed, aborting the scan. Never collects the namespace.
    fn namespace_has_any_record(store: &dyn SigningJournalStorage) -> Result<bool, JournalError> {
        // A sentinel `StorageError` signals "found one" and stops the scan early.
        const FOUND: &str = "__signing_namespace_has_record__";
        let mut found = false;
        let scan = store.for_each_signing_record(&mut |_key, _value| {
            found = true;
            Err(StorageError::Other(FOUND.to_string()))
        });
        match scan {
            Ok(()) => Ok(found),
            Err(StorageError::Other(ref m)) if m == FOUND => Ok(true),
            Err(e) => Err(e.into()),
        }
    }

    /// The process-unique token of the ownership domain this handle serves.
    /// Two handles reporting the same token share one serialization boundary.
    pub fn ownership_domain_token(&self) -> u64 {
        self.domain.token
    }

    /// The established journal-wide position limit (from durable metadata). Panics
    /// only on a poisoned lock or an unestablished domain, which cannot occur for a
    /// handle returned by `initialize`/`open`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn established_limit(&self) -> u64 {
        let inner = self.domain.inner.lock().expect("domain lock");
        inner
            .established
            .expect("handle constructed via initialize/open is established")
            .max_reserved_positions
    }

    /// The current durable count of distinct persisted positions in this domain.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn reserved_position_count(&self) -> u64 {
        let inner = self.domain.inner.lock().expect("domain lock");
        inner.reserved_positions
    }

    /// The current number of live recovered-acknowledgement cache entries.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn recovered_ack_cache_len(&self) -> usize {
        let inner = self.domain.inner.lock().expect("domain lock");
        inner.recovered_acked.len()
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

        // The handle was constructed via `initialize`/`open`, so the domain is
        // established; read the one journal-wide position limit fail-closed.
        let limit = inner
            .established
            .ok_or(JournalError::NotInitialized)?
            .max_reserved_positions;

        // Conservative revalidation (Run 422 D7-D10 Correction E): if a prior
        // atomic accounting write was uncertain, the in-memory counter may be
        // stale. Reconcile it against the durable metadata count BEFORE admitting
        // any new position, so stale accounting can never admit past the durable
        // limit. This runs under the ownership-domain lock.
        self.reconcile_accounting_if_uncertain(&mut inner)?;

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
                    let sig = record.retained_signature.clone().ok_or_else(|| {
                        JournalError::Corruption(
                            "signed record missing retained signature".to_string(),
                        )
                    })?;
                    // Correction C uncertainty rule + Correction B recovery
                    // acknowledgement. Within THIS process:
                    //   * a live operation whose result write has NOT been durably
                    //     acknowledged must not have its readable `Signed` bytes
                    //     presented as a clean retained resend (`PotentiallySigned`);
                    //   * a live operation with an established acknowledgement is a
                    //     genuine in-process fast path (`ExactRetryRetained`);
                    //   * a recovered record (no live entry) must not silently equate
                    //     "readable bytes" with a durability acknowledgement — an
                    //     explicit signing-record durability barrier is established
                    //     BEFORE any retained resend is offered.
                    let live_acked = inner.live.get(position).map(|ls| ls.result_acked);
                    match live_acked {
                        Some(false) => Ok(ReservationOutcome::PotentiallySigned),
                        Some(true) => Ok(ReservationOutcome::ExactRetryRetained(sig)),
                        None => self
                            .acknowledge_recovered_signed(&mut inner, position, &key, &bytes, record)
                            .map(|()| ReservationOutcome::ExactRetryRetained(sig)),
                    }
                }
                // A durable `Reserved` record never yields a fresh live
                // continuation — neither a recovered reservation nor a second
                // handle over an already-live position may re-sign it.
                SigningRecordStage::Reserved => Ok(ReservationOutcome::PotentiallySigned),
            };
        }

        // No existing record: a new position in this domain. Check arithmetic and
        // the journal-wide limit FIRST, before any durable effect.
        if inner.reserved_positions >= limit {
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
        // Persist the new record AND its accounting update (the advanced position
        // count) in ONE atomic, synced storage operation. The durable
        // acknowledgement corresponds to THIS combined write.
        let metadata = SigningJournalMetadata::new(limit, new_reserved);
        let metadata_encoded = metadata.encode();
        match self.store.put_signing_record_and_metadata_synced(
            &key,
            &encoded,
            &metadata_encoded,
        ) {
            Ok(()) => {}
            Err(e) => {
                // A failed/uncertain acknowledgement does NOT prove nothing was
                // stored. Mark the in-memory accounting uncertain so the next
                // admission reconciles against the durable count; grant no
                // continuation and do not advance the in-memory counter.
                inner.accounting_uncertain = true;
                return Err(e.into());
            }
        }

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

    /// Run 422 D7-D10 Correction E — conservative accounting revalidation.
    ///
    /// If a prior atomic reservation/accounting write returned a failed or
    /// uncertain acknowledgement, the in-memory `reserved_positions` counter can
    /// no longer be trusted (a failed ack does not prove nothing was stored). This
    /// re-reads the durable metadata count — the persisted source of truth — and
    /// resets the in-memory counter to it before any further admission. If the
    /// metadata read or decode fails, the uncertain flag stays set and the caller
    /// fails closed (no new position is admitted). Runs under the domain lock.
    fn reconcile_accounting_if_uncertain(
        &self,
        inner: &mut DomainInner,
    ) -> Result<(), JournalError> {
        if !inner.accounting_uncertain {
            return Ok(());
        }
        let bytes = self.store.get_signing_metadata()?.ok_or_else(|| {
            JournalError::AccountingInconsistent(
                "initialization metadata missing during revalidation".to_string(),
            )
        })?;
        let metadata = SigningJournalMetadata::decode(&bytes)?;
        // The established limit is fixed; only the durable count is reconciled.
        inner.reserved_positions = metadata.reserved_positions;
        inner.accounting_uncertain = false;
        Ok(())
    }

    /// Run 422 D7-D10 Correction B — establish the signing-record durability
    /// barrier for a **recovered** `Signed` record (one with no live operation in
    /// this process) BEFORE its retained result may be resent.
    ///
    /// Reading valid `Signed` bytes after reopening establishes only record
    /// availability and structural validity; it is NOT, by itself, a durability
    /// acknowledgement. This helper closes that gap under the ownership-domain
    /// lock already held by the caller:
    ///
    /// * If the exact record has already been acknowledged in THIS domain (a
    ///   cache hit bound to the identical record), the barrier is satisfied.
    /// * Otherwise the identical stored bytes are reissued through the existing
    ///   synced-write operation (the signing-record durability op, not an
    ///   unrelated epoch write). Only on `Ok` is the acknowledgement cached and
    ///   the retained resend permitted; a failed or uncertain write returns `Err`
    ///   and suppresses retained-result delivery. Retrying re-issues the durable
    ///   write; it never invokes the signer and never mints a continuation or a
    ///   publication capability.
    ///
    /// The reissued bytes are the exact validated record already confirmed to
    /// match `position`/`binding`; a conflicting, malformed, missing, or
    /// differently-associated record is rejected before this point and never
    /// overwritten.
    fn acknowledge_recovered_signed(
        &self,
        inner: &mut DomainInner,
        position: &SigningPosition,
        key: &[u8],
        bytes: &[u8],
        record: SigningDecisionRecord,
    ) -> Result<(), JournalError> {
        // A cached acknowledgement authorizes ONLY the exact identical record.
        if inner.recovered_acked.get(position) == Some(&record) {
            return Ok(());
        }
        // Establish the barrier by reissuing the identical stored record through
        // the synced write. Failure/uncertainty ⇒ Err ⇒ no delivery, no cache.
        self.store.put_signing_record_synced(key, bytes)?;
        inner.recovered_acked.insert(*position, record);
        Ok(())
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
        // Run 422 D7-D10 Correction A — reject a structurally invalid empty result
        // at the checked publication boundary, BEFORE writing a `Signed` record or
        // recording any acknowledgement. An empty signature encodes to a record the
        // decoder immediately rejects (a `Signed` record must carry a signature),
        // so accepting it would report a successful publication for bytes that can
        // never be read back. The original reserved record and its conflict
        // obligation are preserved (no write occurs), no continuation is granted,
        // and no publication is reported.
        if signature.is_empty() {
            return Err(JournalError::InvalidResultPublication(
                "refusing to publish a structurally invalid empty signed result".to_string(),
            ));
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
    /// Reserved model-metadata key (Run 422 D7-D10 Correction E). It is stored in
    /// the SAME byte map as records so the atomic record+metadata write is applied
    /// under one lock acquisition. It does NOT start with `sj:v1:`, so it is
    /// excluded from record iteration.
    const MODEL_META_KEY: &[u8] = b"__model_signing_metadata_v1__";

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
        fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
            if *self.fail_reads.read().unwrap() {
                return Err(StorageError::Io("injected read failure".to_string()));
            }
            Ok(self.map.read().unwrap().get(MODEL_META_KEY).cloned())
        }
        fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
            if *self.fail_writes.read().unwrap() {
                return Err(StorageError::Io("injected write failure".to_string()));
            }
            if *self.store_then_error.read().unwrap() {
                self.map
                    .write()
                    .unwrap()
                    .insert(MODEL_META_KEY.to_vec(), value.to_vec());
                return Err(StorageError::Io("injected post-store sync failure".to_string()));
            }
            self.map
                .write()
                .unwrap()
                .insert(MODEL_META_KEY.to_vec(), value.to_vec());
            Ok(())
        }
        fn put_signing_record_and_metadata_synced(
            &self,
            record_key: &[u8],
            record_value: &[u8],
            metadata_value: &[u8],
        ) -> Result<(), StorageError> {
            if *self.fail_writes.read().unwrap() {
                return Err(StorageError::Io("injected write failure".to_string()));
            }
            // Honest single-lock atomic model: BOTH writes happen (or, under
            // store_then_error, both become readable) under one lock acquisition.
            if *self.store_then_error.read().unwrap() {
                let mut m = self.map.write().unwrap();
                m.insert(record_key.to_vec(), record_value.to_vec());
                m.insert(MODEL_META_KEY.to_vec(), metadata_value.to_vec());
                return Err(StorageError::Io("injected post-store sync failure".to_string()));
            }
            let mut m = self.map.write().unwrap();
            m.insert(record_key.to_vec(), record_value.to_vec());
            m.insert(MODEL_META_KEY.to_vec(), metadata_value.to_vec());
            Ok(())
        }
        fn for_each_signing_record(
            &self,
            visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
        ) -> Result<(), StorageError> {
            if *self.fail_reads.read().unwrap() {
                return Err(StorageError::Io("injected read failure".to_string()));
            }
            let m = self.map.read().unwrap();
            let mut keys: Vec<&Vec<u8>> = m
                .keys()
                .filter(|k| k.starts_with(SIGNING_RECORD_KEY_PREFIX))
                .collect();
            keys.sort();
            for k in keys {
                visitor(k, &m[k])?;
            }
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

    /// Test convenience mirroring production's initialize-vs-open selection with
    /// the default limit.
    fn attach(store: Arc<ModelStore>) -> SigningReservationJournal {
        attach_with_budget(store, DEFAULT_MAX_RESERVED_POSITIONS)
    }

    /// Test convenience: an empty, un-initialized namespace is explicitly
    /// initialized with `limit`; an established one is opened and validated.
    /// BOTH routes validate — this is not an unchecked bypass, just a fixture
    /// selector for pre-existing A–D tests. Correction-E tests call
    /// [`SigningReservationJournal::initialize`]/[`SigningReservationJournal::open`]
    /// directly to exercise each route and its refusals explicitly.
    fn attach_with_budget(store: Arc<ModelStore>, limit: u64) -> SigningReservationJournal {
        if store
            .get_signing_metadata()
            .expect("metadata probe must not fail in fixture setup")
            .is_some()
        {
            SigningReservationJournal::open(store).expect("open established model store")
        } else {
            SigningReservationJournal::initialize(store, limit)
                .expect("initialize fresh model store")
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
        let journal = attach(store.clone());
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
        let journal = attach(store);
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
        let journal = attach(store);
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
            let journal = attach(store.clone());
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
        let reopened = attach(store.reopen());
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
            let journal = attach(store.clone());
            let cap = reserve_and_invoke(&journal, &pos, &b);
            journal.record_signed_result(&cap, b"the-sig").unwrap();
        }
        let reopened = attach(store.reopen());
        assert!(matches!(
            reopened.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"the-sig"
        ));
    }

    #[test]
    fn read_and_write_failures_yield_no_permit() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store.clone());
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
            let journal = attach(store.clone());
            journal.reserve_for_sign(&pos, &b).unwrap();
        }
        store.corrupt(&pos.storage_key());
        // Opening an established namespace performs bounded streaming validation,
        // so a corrupt record now fails closed AT OPEN — the journal is never
        // constructed over inconsistent state.
        assert!(matches!(
            SigningReservationJournal::open(store.reopen()),
            Err(JournalError::Corruption(_))
        ));
    }

    #[test]
    fn second_handle_cannot_get_permit_for_reserved_position() {
        let store = Arc::new(ModelStore::default());
        let handle_a = attach(store.clone());
        let handle_b = attach(store.clone());
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
        let journal = attach_with_budget(store, 1);
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
        // Initialize an empty namespace, then overwrite the position with a
        // hand-crafted Signed record carrying a zero-length signature and a valid
        // crc. Reading that exact key during a reservation must decode-reject it.
        let journal = attach(store.clone());
        let mut record = SigningDecisionRecord::signed(pos, b, vec![9u8]);
        record.retained_signature = Some(vec![]); // force empty
        // encode() will produce sig_len=0 but stage=Signed; decode must reject.
        let bytes = record.encode().unwrap();
        store.overwrite(&pos.storage_key(), bytes);
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
        let journal_a = attach(store_a);
        let journal_b = attach(store_b);
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
        let journal_a = attach(store_a);
        let journal_b = attach(store_b);
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
        let journal = attach(store.clone());
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
        let handle_a = attach(store.clone());
        let handle_b = attach(store.clone());
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
        let journal = attach(store);
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
        let journal = attach(store);
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
        let journal = attach(store);
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
        let journal = attach(store.clone());
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
        let journal = attach(store.clone());
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

    // ------------------------------------------------------------------
    // Run 422 D7-D10 Correction A — reject structurally invalid (empty)
    // result publication at the checked boundary.
    // ------------------------------------------------------------------

    #[test]
    fn empty_result_publication_refused_and_preserves_reservation() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store.clone());
        let pos = position(SigningKind::Proposal, 70);
        let b = binding(b"decision");
        let cap = reserve_and_invoke(&journal, &pos, &b);

        // Publishing an EMPTY result is refused with a typed error BEFORE any
        // write — a record the decoder would immediately reject is never stored.
        assert!(matches!(
            journal.record_signed_result(&cap, b""),
            Err(JournalError::InvalidResultPublication(_))
        ));

        // The stored bytes are UNCHANGED and decode as the original valid
        // reservation (Reserved stage, no retained signature).
        let key = pos.storage_key();
        let stored = store
            .map
            .read()
            .unwrap()
            .get(&key)
            .cloned()
            .expect("reservation bytes present");
        let decoded = SigningDecisionRecord::decode(&stored).expect("decode reservation");
        assert_eq!(decoded, SigningDecisionRecord::reserved(pos, b));

        // The reservation obligation is preserved: an exact retry remains
        // potentially-signed (live, un-acked), and a conflicting binding is
        // still refused.
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
        assert!(matches!(
            journal.reserve_for_sign(&pos, &binding(b"other")).unwrap(),
            ReservationOutcome::Conflict
        ));

        // The oversized refusal is unaffected (control), and a valid nonempty
        // result still publishes successfully and is retained for exact retry.
        let oversized = vec![7u8; MAX_RETAINED_SIGNATURE_LEN + 1];
        assert!(matches!(
            journal.record_signed_result(&cap, &oversized),
            Err(JournalError::OversizeRecord { .. })
        ));
        journal.record_signed_result(&cap, b"real-sig").unwrap();
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"real-sig"
        ));
    }

    // ------------------------------------------------------------------
    // Run 422 D7-D10 Correction B — a recovered retained result requires an
    // established durability barrier. Models lost process-local knowledge:
    // Signed bytes survive, the live-operation table does not, and readable
    // bytes alone are NOT a durability acknowledgement.
    // ------------------------------------------------------------------

    #[test]
    fn recovered_signed_requires_durability_barrier_before_resend() {
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Vote, 71);
        let b = binding(b"decision");

        // (1)-(3) A reservation is durably acknowledged, the operation crosses the
        //         invocation boundary, and result publication makes the Signed
        //         bytes READABLE but returns an error (uncertain durable write).
        {
            let journal = attach(store.clone());
            let cap = reserve_and_invoke(&journal, &pos, &b);
            store.set_store_then_error(true);
            assert!(matches!(
                journal.record_signed_result(&cap, b"the-sig"),
                Err(JournalError::Storage(_))
            ));
            store.set_store_then_error(false);
            // The Signed bytes are readable on the surviving model.
            assert!(store.map.read().unwrap().contains_key(&pos.storage_key()));
        }

        // (4)-(5) Original live ownership is discarded: a FRESH backend ownership
        //         domain is created over the surviving model bytes.
        let reopened_store = store.reopen();
        let reopened = attach(reopened_store.clone());

        // (6)-(7) A retained-result lookup cannot succeed merely because those
        //         bytes are readable. With the recovery durability op failing, the
        //         barrier is not established ⇒ retained delivery is suppressed, and
        //         a repeated failure remains a failure.
        reopened_store.set_fail_writes(true);
        assert!(matches!(
            reopened.reserve_for_sign(&pos, &b),
            Err(JournalError::Storage(_))
        ));
        assert!(matches!(
            reopened.reserve_for_sign(&pos, &b),
            Err(JournalError::Storage(_))
        ));

        // (8) A later successful recovery barrier permits ONLY exact retained
        //     reuse (no signer is ever invoked on this path).
        reopened_store.set_fail_writes(false);
        assert!(matches!(
            reopened.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"the-sig"
        ));

        // The acknowledgement is cached bound to the exact record: a subsequent
        // lookup is served WITHOUT reissuing the durable write (a failing write
        // no longer blocks the exact retained resend).
        reopened_store.set_fail_writes(true);
        assert!(matches!(
            reopened.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"the-sig"
        ));
    }

    #[test]
    fn recovered_signed_conflict_refused_without_rewrite_and_reserved_potentially_signed() {
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Proposal, 72);
        let b = binding(b"decision");
        {
            let journal = attach(store.clone());
            let cap = reserve_and_invoke(&journal, &pos, &b);
            journal.record_signed_result(&cap, b"sig").unwrap();
        }
        let reopened_store = store.reopen();
        let reopened = attach(reopened_store.clone());

        // A conflicting binding over a recovered Signed record is refused and does
        // NOT rewrite the record (the stored bytes are unchanged).
        let before = reopened_store
            .map
            .read()
            .unwrap()
            .get(&pos.storage_key())
            .cloned()
            .unwrap();
        assert!(matches!(
            reopened.reserve_for_sign(&pos, &binding(b"different")).unwrap(),
            ReservationOutcome::Conflict
        ));
        let after = reopened_store
            .map
            .read()
            .unwrap()
            .get(&pos.storage_key())
            .cloned()
            .unwrap();
        assert_eq!(before, after, "conflict must not rewrite the record");

        // A recovered Reserved record remains potentially-signed (never a
        // continuation) even under a fresh domain.
        let rpos = position(SigningKind::Proposal, 73);
        let rb = binding(b"reserved-only");
        {
            let journal = attach(store.clone());
            let cont = match journal.reserve_for_sign(&rpos, &rb).unwrap() {
                ReservationOutcome::FreshlyReserved(c) => c,
                other => panic!("expected FreshlyReserved, got {:?}", other),
            };
            let _cap = journal.consume_for_signing(cont).unwrap();
        }
        let reopened2 = attach(store.reopen());
        assert!(matches!(
            reopened2.reserve_for_sign(&rpos, &rb).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
    }

    #[test]
    fn recovered_signed_corruption_fails_closed_before_recovery_publication() {
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Vote, 74);
        let b = binding(b"decision");
        {
            let journal = attach(store.clone());
            let cap = reserve_and_invoke(&journal, &pos, &b);
            journal.record_signed_result(&cap, b"the-sig").unwrap();
        }
        // Corrupt the stored Signed record; opening a fresh domain must fail closed
        // during streaming validation, BEFORE any recovery re-publication.
        store.corrupt(&pos.storage_key());
        assert!(matches!(
            SigningReservationJournal::open(store.reopen()),
            Err(JournalError::Corruption(_))
        ));
    }
}