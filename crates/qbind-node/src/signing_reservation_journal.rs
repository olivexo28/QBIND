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
use crate::signing_journal_admission::{
    AdmittedOutput, BorrowedRecordView, EnvelopeScratch, RetrievalWorkspaceOwner,
    ENVELOPE_SIG_OFFSET, JOURNAL_KEY_LEN,
};

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
///
/// This is the codec-owned metadata length. Backends reuse it as the bounded
/// direct-read size for the metadata key (the fixed metadata encoding size)
/// before copying or envelope-unwrapping a stored metadata value.
pub const METADATA_ENCODED_LEN: usize = 4 + 2 + 8 + 8 + 4;

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

    /// Run 422 — write the canonical position key directly into `dst` WITHOUT
    /// allocating (the retained-retrieval path must not call the allocating
    /// [`SigningPosition::storage_key`], which returns a `Vec`). Writes exactly
    /// [`JOURNAL_KEY_LEN`] bytes in the identical prefix / field order / width /
    /// endianness / kind-tag layout as the legacy encoder, and returns the number
    /// of bytes written. The legacy `storage_key` method is left unchanged.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn encode_key_into(&self, dst: &mut [u8]) -> Result<usize, KeyEncodeError> {
        if dst.len() < JOURNAL_KEY_LEN {
            return Err(KeyEncodeError::BufferTooSmall);
        }
        let p = SIGNING_RECORD_KEY_PREFIX;
        let plen = p.len();
        dst[0..plen].copy_from_slice(p);
        dst[plen] = self.kind.tag();
        let vid = plen + 1;
        dst[vid..vid + 8].copy_from_slice(&self.validator_id.to_be_bytes());
        let gen = vid + 8;
        dst[gen..gen + 32].copy_from_slice(&self.network_genesis);
        let view = gen + 32;
        dst[view..view + 8].copy_from_slice(&self.originating_view.to_be_bytes());
        Ok(JOURNAL_KEY_LEN)
    }
}

/// Run 422 — fixed-code failure of the non-allocating key encoder (no
/// application-created `String`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum KeyEncodeError {
    /// The destination buffer is smaller than [`JOURNAL_KEY_LEN`].
    BufferTooSmall,
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
    /// Run 422 D7-D10 Correction E — the signing namespace contains an entry that
    /// is neither the exact recognized initialization-metadata key nor a supported
    /// decision record (a `sj:v1:` key). This covers unsupported decision-key
    /// versions (e.g. `sj:v2:…`), unknown metadata keys/versions, and other
    /// malformed or unexpected signing-namespace entries. Refused fail-closed; the
    /// entry is never adopted, deleted, migrated, or overwritten.
    UnexpectedNamespaceEntry(String),
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
            JournalError::UnexpectedNamespaceEntry(m) => {
                write!(f, "signing-journal unexpected namespace entry: {}", m)
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
    /// Run 422 — the bounded live-container is at capacity: no free slot is
    /// available to admit this fresh reservation. Refuse safely WITHOUT any new
    /// durable fresh-reservation record/metadata write (it may follow existing
    /// reads or recovery handling). Distinct from [`Self::Exhausted`], which is
    /// the durable journal-wide position-limit refusal. Only ever produced by a
    /// domain that has explicitly entered bounded live mode; a legacy domain
    /// never yields it.
    LiveCapacityExhausted,
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
// RUN 422 — additive, isolated ADMITTED fresh-reservation route types.
//
// These wrap the existing operation-bound continuation / publication capability
// with the covered-ownership model: each opaque wrapper OWNS the single
// continuation reservation (`coverage`) issued by the installed operational
// accountant, so coverage persists exactly as long as the caller retains the
// capability. The wrapped inner value preserves EVERY existing domain,
// operation-id, position, binding, invocation, and acknowledgement check; the
// non-`Clone` wrapper adds coverage ownership, never a second authorization.
// ============================================================================

/// RUN 422 — an admitted, covered [`SigningContinuation`]: the single authority
/// to invoke the signer for exactly one freshly admitted reservation, together
/// with the continuation [`Reservation`](crate::safety_record_store::accounting::Reservation)
/// it owns. The coverage moved in at construction is released only when this
/// wrapper drops unconsumed, or flows UNCHANGED into the publication capability on
/// consumption (never released and re-charged). All fields are private;
/// constructed only inside this module after a durable fresh-reservation
/// acknowledgement.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct AdmittedContinuation {
    inner: SigningContinuation,
    coverage: crate::safety_record_store::accounting::Reservation,
}

impl AdmittedContinuation {
    /// The canonical position this continuation authorizes signing for.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn position(&self) -> SigningPosition {
        self.inner.position
    }

    /// The charge held by the owned continuation coverage (observer).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn coverage_charge(&self) -> u128 {
        self.coverage.charge()
    }

    /// True iff the owned coverage was issued by `acct` (observer).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_covered_by(
        &self,
        acct: &crate::safety_record_store::accounting::SharedAccountant,
    ) -> bool {
        self.coverage.is_issued_by(acct)
    }
}

/// RUN 422 — an admitted, covered [`ResultPublicationCapability`]: the authority
/// to publish the result of the exact operation that reserved a decision and
/// crossed the signer-invocation boundary, together with the SAME continuation
/// coverage transferred through consumption (no release/recharge). All fields are
/// private; the raw inner capability is never exposed outside this module, so
/// retirement accesses it only here.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct AdmittedPublicationCapability {
    inner: ResultPublicationCapability,
    coverage: crate::safety_record_store::accounting::Reservation,
}

impl AdmittedPublicationCapability {
    /// The canonical position this capability publishes for.
    #[allow(dead_code)]
    pub(crate) fn position(&self) -> SigningPosition {
        self.inner.position
    }

    /// The charge held by the owned continuation coverage (observer).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn coverage_charge(&self) -> u128 {
        self.coverage.charge()
    }

    /// True iff the owned coverage was issued by `acct` (observer).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_covered_by(
        &self,
        acct: &crate::safety_record_store::accounting::SharedAccountant,
    ) -> bool {
        self.coverage.is_issued_by(acct)
    }
}

/// RUN 422 — the outcome of an admitted fresh-reservation attempt. It carries NO
/// lifetime and NO retained-signature bytes: an existing-position classification
/// is a fixed-code variant, never a newly allocated signature `Vec`. Delivery of
/// any retained result remains the responsibility of the already-completed
/// checked retrieval path, not this route.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum AdmittedReservationOutcome {
    /// A fresh reservation was durably acknowledged; the enclosed covered
    /// continuation is the one live operation's authority to sign once.
    FreshlyReserved(AdmittedContinuation),
    /// A conflicting decision (same position, different binding) exists.
    Conflict,
    /// A durable `Reserved` record exists for this position; never re-signable.
    ReservedPotentiallySigned,
    /// A `Signed` record exists with a live, result-UNacknowledged operation in
    /// this process; treated as potentially signed (no delivery).
    LiveUnacknowledgedPotentiallySigned,
    /// A `Signed` record exists with NO live entry (or a live acknowledged one):
    /// retainable ONLY through the separate checked retrieval path, never here.
    SignedRetainableElsewhere,
    /// The durable journal-wide reserved-position limit is exhausted.
    Exhausted,
    /// The bounded live container is at capacity; no fresh slot is available.
    LiveCapacityExhausted,
    /// A stored envelope exceeds the admitted workspace capacity (bounded refusal).
    WorkspaceCapacityExceeded,
    /// Journal accounting is uncertain; refused conservatively with no fresh
    /// continuation. The route never implicitly invokes legacy reconciliation.
    AccountingUncertain,
}

/// RUN 422 — fixed-size, `Copy`, allocation-free refusal for the admitted
/// fresh-reservation entrypoint. Distinct from the allocating [`JournalError`]:
/// no heap-bearing or attacker-controlled content is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum AdmittedReserveError {
    /// The journal domain has not been established (no `initialize`/`open`).
    NotEstablished,
    /// The journal domain is not in bounded live mode; the admitted route does not
    /// auto-transition or fall back to the legacy allocating route.
    NotBoundedMode,
    /// No operational accountant association is installed; the route does not
    /// auto-install one.
    NoAssociation,
    /// The signing-domain mutex was poisoned by a panic in another holder.
    Lock,
    /// The supplied workspace is not covered by the installed operational ledger +
    /// aggregate authority. Returned BEFORE any storage access.
    ForeignWorkspace,
    /// The backend does not support the bounded envelope read/write path.
    Unsupported,
    /// The canonical position key could not be encoded within its fixed layout.
    KeyInvalid,
    /// Checked operation-id / position-count arithmetic overflowed.
    Overflow,
    /// A backend storage read/write error (fixed diagnostic code).
    Storage(BoundedDiag),
}

/// RUN 422 — fixed-size, `Copy`, allocation-free refusal for admitted
/// continuation consumption. Distinct from the allocating [`JournalError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum AdmittedConsumeError {
    /// The signing-journal ownership mutex was poisoned.
    LockPoisoned,
    /// The continuation belongs to a foreign ownership domain.
    ForeignDomain,
    /// No fresh (un-invoked, exactly-matching) live operation owns this position.
    NoFreshLiveOp,
}

/// RUN 422 — the ONE shared live-consumption state transition, performed under a
/// lock the caller already holds. It checks the foreign-domain token FIRST (no
/// live mutation on a foreign continuation), then requires a live entry at
/// `position` whose `operation_id`, `binding` match and that is not yet invoked;
/// on success it marks the entry invoked. It mutates ONLY the matched live entry
/// and never touches storage, accounting, or any other domain state. Both the
/// legacy [`consume_for_signing`](SigningReservationJournal::consume_for_signing)
/// and the admitted [`consume_for_signing_admitted`](SigningReservationJournal::consume_for_signing_admitted)
/// route through it, so the exact live-ownership check is identical on both paths.
#[cfg_attr(not(test), allow(dead_code))]
fn consume_live_locked(
    inner: &mut DomainInner,
    expected_domain_token: u64,
    cont_domain_token: u64,
    position: &SigningPosition,
    binding: &BindingDigest,
    operation_id: u64,
) -> Result<(), AdmittedConsumeError> {
    if cont_domain_token != expected_domain_token {
        return Err(AdmittedConsumeError::ForeignDomain);
    }
    match inner.live.get_mut(position) {
        Some(ls) if ls.operation_id == operation_id && ls.binding == *binding && !ls.invoked => {
            ls.invoked = true;
            Ok(())
        }
        _ => Err(AdmittedConsumeError::NoFreshLiveOp),
    }
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
/// Run 422 — fixed diagnostic codes for the bounded retained-retrieval storage
/// methods. No application-created `String` is produced on this path; backend
/// library-internal allocations (e.g. RocksDB's own key/value buffers) are
/// documented as outside this component's accounting claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedDiag {
    /// A key/record could not be interpreted within its fixed layout.
    DecodeInvalid,
    /// A stored envelope failed a structural/length invariant.
    EnvelopeInvalid,
    /// A backend read failed.
    ReadIo,
    /// A backend write failed.
    WriteIo,
    /// A backend lock could not be acquired.
    LockRefused,
    /// A supplied journal key had an unexpected length.
    KeyInvalid,
}

/// Run 422 — typed, allocation-free error for the bounded retained-retrieval
/// storage methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedStorageError {
    /// A stored value exceeds the admitted workspace capacity. This is a bounded
    /// refusal — NOT corruption and NOT a trigger for a larger allocation.
    CapacityExceeded {
        /// The stored value length.
        stored_len: usize,
        /// The admitted capacity it exceeded.
        capacity: usize,
    },
    /// Stored bytes violate a structural invariant.
    Corruption(BoundedDiag),
    /// A backend I/O or lock failure.
    Io(BoundedDiag),
    /// The backend does not support the bounded retained-retrieval path.
    Unsupported,
}

/// Run 422 — the outcome of a bounded retained-signature retrieval. Borrows the
/// admitted output for `'o`; `Retained` is the ONLY delivering variant and every
/// other variant leaves the output bytes and length unchanged.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum RetainedDelivery<'o> {
    /// Journal accounting is uncertain; refused conservatively with zero side
    /// effects (no metadata read, reconciliation, latch clearing, counter
    /// update, or write).
    Blocked,
    /// No record exists at this position.
    Missing,
    /// A typed, non-delivering refusal.
    Refused(RefuseReason),
    /// A reservation (or a live-but-unacknowledged signed result) exists; no
    /// retained signature is delivered.
    PotentiallySigned,
    /// A recovered signed record's synced reissue failed or was uncertain, so
    /// delivery is suppressed and the output is unchanged.
    DeliverySuppressed,
    /// The validated retained signature, borrowed from the admitted output.
    Retained(&'o [u8]),
}

/// Run 422 — typed, non-delivering refusal reasons (fixed codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum RefuseReason {
    /// The stored record's position does not match the requested key.
    PositionMismatch,
    /// The stored record is structurally or semantically malformed.
    MalformedRecord,
    /// The stored record's exact-message binding conflicts with the request.
    BindingConflict,
    /// A valid record whose signature/envelope exceeds the admitted workspace
    /// capacity — a distinct bounded refusal, not corruption.
    WorkspaceCapacityExceeded,
}

/// Run 422 — fatal (non-classification) errors from the retained-retrieval
/// path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum RetrievalError {
    /// The ownership-domain lock was poisoned.
    Lock,
    /// The backend does not support the bounded retained-retrieval path.
    Unsupported,
    /// A backend storage read/write error (fixed diagnostic code).
    Storage(BoundedDiag),
}

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
    /// never returned by [`Self::for_each_signing_namespace_entry`].
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

    /// Run 422 D7-D10 Correction E — bounded **streaming** visit over every entry
    /// in the signing namespace, INCLUDING unexpected or foreign keys, EXCLUDING
    /// only the backend-owned initialization-metadata key (which is classified
    /// separately via [`Self::get_signing_metadata`]). The visitor is called once
    /// per entry with the journal-level key (the same key space as
    /// [`Self::get_signing_record`], i.e. the backend's own storage prefix is
    /// stripped) and the envelope-unwrapped value bytes.
    ///
    /// This is deliberately streaming: the backend yields one entry at a time and
    /// never materializes the whole namespace into a collection, and the caller
    /// counts/classifies/validates incrementally and may abort early via a visitor
    /// error. Read/iterator errors and envelope corruption are propagated as
    /// [`StorageError`] and abort the scan; a visitor error aborts the scan and is
    /// propagated. The backend applies the available per-entry value-length bound
    /// BEFORE copying/unwrapping the payload. The underlying database API still
    /// allocates one key/value buffer per yielded entry (documented, per-entry
    /// bounded, honesty note); the caller performs NO allocation from stored counts
    /// or unchecked lengths.
    ///
    /// Initialization uses this to check the ENTIRE signing namespace for any
    /// existing state; open uses it to classify EVERY entry and refuse fail-closed
    /// on any entry that is neither the metadata key nor a supported decision
    /// record. Unrelated block/QC/epoch namespaces are never visited.
    fn for_each_signing_namespace_entry(
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

    /// Run 422 — bounded, pinned read of ONE complete stored signing envelope at
    /// `journal_key` into `dst`, WITHOUT any application-owned allocation. The
    /// backend applies a length check BEFORE copying into `dst`: a stored value
    /// larger than `dst` is refused with [`BoundedStorageError::CapacityExceeded`]
    /// (never silently truncated, never grown). Returns the number of bytes
    /// written, or `None` for a genuine absence. The default refuses with
    /// [`BoundedStorageError::Unsupported`]; a supporting backend overrides it.
    fn read_signing_envelope_into(
        &self,
        journal_key: &[u8],
        dst: &mut [u8],
    ) -> Result<Option<usize>, BoundedStorageError> {
        let _ = (journal_key, dst);
        Err(BoundedStorageError::Unsupported)
    }

    /// Run 422 — reissue one EXACT already-validated stored envelope at
    /// `journal_key` under the required synced durability barrier, WITHOUT
    /// re-wrapping, re-encoding, or allocating a second application envelope. The
    /// default refuses with [`BoundedStorageError::Unsupported`]; a supporting
    /// backend overrides it.
    fn reissue_signing_envelope_synced(
        &self,
        journal_key: &[u8],
        envelope: &[u8],
    ) -> Result<(), BoundedStorageError> {
        let _ = (journal_key, envelope);
        Err(BoundedStorageError::Unsupported)
    }

    /// Run 422 §7.2 — persist an already-outer-framed signing-record envelope
    /// AND its already-outer-framed accounting-metadata envelope together under
    /// ONE atomic, synced storage operation. The inputs are BORROWED, caller-
    /// framed bytes (outer CRC + payload); this method does NOT re-wrap, re-encode,
    /// validate signing eligibility, mint a continuation, advance journal
    /// accounting, invoke a signer, or authorize delivery — it establishes a
    /// STORAGE acknowledgement only. Either both values become durable together or
    /// neither does; a durable backend MUST NOT return `Ok(())` until the atomic
    /// batch is synchronized to stable storage. A failed/uncertain result does
    /// NOT prove that neither value was written, and the operation never
    /// intentionally exposes a partially updated pair. The default refuses with
    /// [`BoundedStorageError::Unsupported`] WITHOUT any write or allocating legacy
    /// fallback; a supporting backend overrides it.
    fn put_signing_envelope_and_metadata_synced(
        &self,
        record_key: &[u8],
        record_envelope: &[u8],
        metadata_envelope: &[u8],
    ) -> Result<(), BoundedStorageError> {
        let _ = (record_key, record_envelope, metadata_envelope);
        Err(BoundedStorageError::Unsupported)
    }
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

    /// Test-only: an ordered snapshot (CONTENTS + FIFO order) of the cache, so a
    /// test can assert retirement neither seeds, clears, nor reorders it — not
    /// merely that the entry count is unchanged.
    #[cfg(any(test, feature = "test-utils"))]
    fn snapshot(&self) -> Vec<(SigningPosition, SigningDecisionRecord)> {
        self.order
            .iter()
            .filter_map(|pos| self.map.get(pos).map(|rec| (*pos, rec.clone())))
            .collect()
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

/// Run 422 D7-D10 Correction E — the tracked outcome envelope of a single
/// atomic reservation/accounting write whose durable acknowledgement was
/// uncertain. A failed acknowledgement does not prove nothing was stored, so the
/// only two consistent durable outcomes are: the write did NOT land (the count
/// is still `prior_count`) or it DID land (the count is exactly
/// `attempted_count`, i.e. `prior_count + 1`). Reconciliation resolves the
/// failed batch against these bounds and refuses any durable count that regressed
/// below `prior_count`, exceeded `attempted_count`, or whose limit changed.
#[derive(Debug, Clone, Copy)]
struct UncertainAttempt {
    /// The last durably-acknowledged position count before the uncertain write.
    prior_count: u64,
    /// The count the uncertain write attempted to make durable (`prior_count + 1`).
    attempted_count: u64,
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

/// Run 422 — one occupied entry in the bounded live container: the canonical
/// position plus its in-memory [`LiveState`]. A bounded slot is an
/// `Option<LiveEntry>`; `None` marks a free slot.
#[derive(Debug)]
struct LiveEntry {
    position: SigningPosition,
    state: LiveState,
}

/// Run 422 — a fixed-capacity live-container slot. `None` is a free slot. The
/// per-slot byte size is derived from `size_of::<Slot>()` (never hard-coded).
type Slot = Option<LiveEntry>;

/// Run 422 — fixed-size, `Copy`, allocation-free refusal for the explicit,
/// non-enabling [`SigningReservationJournal::enter_bounded_live_mode`]
/// transition. Every variant is `Copy` and carries no `String` / owned payload,
/// so constructing or returning it on any branch performs no heap allocation.
/// It is deliberately distinct from the allocating [`JournalError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum BoundedModeError {
    /// No operational accountant association is installed in this domain, so the
    /// container charge cannot be admitted. The mode is unchanged.
    NoAccountantAssociation,
    /// The journal domain has not been established (no `initialize`/`open`).
    JournalNotEstablished,
    /// The signing-domain mutex was poisoned by a panic in another holder.
    DomainMutexPoisoned,
    /// The requested capacity is zero.
    ZeroCapacity,
    /// The requested capacity exceeds the established durable-position limit.
    CapacityAboveLimit,
    /// Checked charge arithmetic overflowed while computing the container charge.
    ChargeOverflow,
    /// The requested backing allocation size is not representable on the target
    /// (exceeds `isize::MAX`).
    LayoutOverflow,
    /// A first transition requires an empty legacy live map; it still holds live
    /// entries. The mode is unchanged.
    LegacyNotEmpty,
    /// A first transition requires the legacy live map to own zero capacity; it
    /// still retains allocated capacity. The mode is unchanged.
    LegacyHasCapacity,
    /// Already in bounded mode with a DIFFERENT capacity; the existing bounded
    /// container is preserved unchanged.
    CapacityMismatch,
    /// The installed accountant refused the full container charge. No allocation
    /// was attempted; both ledgers are unchanged.
    AdmissionRefused,
    /// The backing allocation itself failed AFTER admission. The admitted
    /// coverage is released automatically; the previous mode is preserved.
    Allocation,
}

/// Run 422 (test-only) — force [`LiveContainer::construct`] to report an
/// INJECTED allocation failure after admission, so a test can exercise the real
/// constructor error-cleanup (automatic coverage release) and the
/// `enter_bounded_live_mode` rollback. It is NOT a demonstrated system OOM.
///
/// The switch is **thread-local**, not process-global: `construct` runs
/// synchronously on the thread that calls `enter_bounded_live_mode`, so the
/// injection is observed only on the arming thread. A process-global flag (or a
/// mutex held merely by the injecting test) would NOT protect an unrelated
/// parallel `construct` call on another thread, which could then spuriously
/// fail; thread-locality confines the injection to exactly the intended
/// execution. Armed/disarmed through the RAII [`InjectedConstructAllocFailure`]
/// guard so it cannot leak across tests even on panic.
#[cfg(test)]
thread_local! {
    static FORCE_CONSTRUCT_ALLOC_FAILURE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Run 422 (test-only) — RAII guard arming the thread-local
/// [`FORCE_CONSTRUCT_ALLOC_FAILURE`] injected construction failure for the
/// current thread, disarming it on drop (including on panic/unwind). Keeping the
/// injection thread-confined means it can never be observed by a `construct`
/// call on any other thread.
#[cfg(test)]
struct InjectedConstructAllocFailure;

#[cfg(test)]
impl InjectedConstructAllocFailure {
    fn arm() -> Self {
        FORCE_CONSTRUCT_ALLOC_FAILURE.with(|f| f.set(true));
        InjectedConstructAllocFailure
    }
}

#[cfg(test)]
impl Drop for InjectedConstructAllocFailure {
    fn drop(&mut self) {
        FORCE_CONSTRUCT_ALLOC_FAILURE.with(|f| f.set(false));
    }
}

/// Run 422 — the covered, fixed-capacity live-operation container installed by
/// an explicit `enter_bounded_live_mode` transition. Its entire backing is
/// charged against the installed operational accountant BEFORE allocation; the
/// charge is held for the container's whole lifetime (through empty periods) and
/// released only at actual container destruction.
#[derive(Debug)]
struct LiveContainer {
    /// Non-growing slot backing: after construction
    /// `slots.len() == slots.capacity() == capacity`, and it is never
    /// reallocated. Declared BEFORE `_backing`; struct fields drop in
    /// DECLARATION order, so this heap backing is freed FIRST, then `_backing`
    /// releases its covering reservation.
    slots: Vec<Slot>,
    /// Count of occupied slots (live operations). Never exceeds `capacity`.
    occupied: usize,
    /// The fixed capacity `L` (`== slots.len()`).
    capacity: usize,
    /// The covering reservation for
    /// `size_of::<LiveContainer>() + L * size_of::<Slot>()`. Released only when
    /// this container is destroyed (not when a journal handle drops). Declared
    /// AFTER `slots`, so in declaration drop order it is released AFTER the slot
    /// backing is freed.
    _backing: crate::safety_record_store::accounting::Reservation,
}

impl LiveContainer {
    /// Run 422 — the one truthful, fallible constructor. The caller has already
    /// validated `l` and admitted the full charge, obtaining `coverage`. The
    /// operation sequence is: `try_reserve_exact` → initialize slots without
    /// growth → wrap, consuming `coverage`. Allocation failure maps to
    /// [`BoundedModeError::Allocation`] and is propagated normally (no
    /// `expect`/`unwrap`/panic). On the error return `coverage` is dropped,
    /// releasing its reservation exactly once; the caller installs nothing.
    fn construct(
        l: usize,
        coverage: crate::safety_record_store::accounting::Reservation,
    ) -> Result<Self, BoundedModeError> {
        #[cfg(test)]
        {
            if FORCE_CONSTRUCT_ALLOC_FAILURE.with(|f| f.get()) {
                // Injected allocation failure AFTER admission: `coverage` is
                // dropped here, releasing its reservation exactly once (the real
                // cleanup path). Labelled injected — never a system OOM. The
                // switch is thread-local, so only the arming thread trips it.
                return Err(BoundedModeError::Allocation);
            }
        }
        let mut slots: Vec<Slot> = Vec::new();
        slots
            .try_reserve_exact(l)
            .map_err(|_| BoundedModeError::Allocation)?;
        // Fill to `len == l` WITHOUT growth. On the supported toolchain
        // (rustc 1.99.0, default Global allocator, non-ZST `Slot`),
        // `try_reserve_exact` records capacity exactly `l`, so this never
        // reallocates. `resize_with` is used because `Slot`/`LiveEntry` are not
        // `Clone`; the closure yields `None` for each free slot.
        slots.resize_with(l, || None);
        Ok(Self {
            slots,
            occupied: 0,
            capacity: l,
            _backing: coverage,
        })
    }

    fn get(&self, pos: &SigningPosition) -> Option<&LiveState> {
        for slot in self.slots.iter() {
            if let Some(e) = slot {
                if e.position == *pos {
                    return Some(&e.state);
                }
            }
        }
        None
    }

    fn get_mut(&mut self, pos: &SigningPosition) -> Option<&mut LiveState> {
        for slot in self.slots.iter_mut() {
            if let Some(e) = slot {
                if e.position == *pos {
                    return Some(&mut e.state);
                }
            }
        }
        None
    }

    /// Insert or replace the live entry for `pos` with NO allocation and NO
    /// growth. Returns `false` iff the container is full and `pos` is absent;
    /// the reserve path settles capacity first under the lock, so it never
    /// observes `false` there.
    fn insert(&mut self, pos: SigningPosition, state: LiveState) -> bool {
        for slot in self.slots.iter_mut() {
            if let Some(e) = slot {
                if e.position == pos {
                    e.state = state;
                    return true;
                }
            }
        }
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(LiveEntry {
                    position: pos,
                    state,
                });
                self.occupied += 1;
                return true;
            }
        }
        false
    }

    fn remove(&mut self, pos: &SigningPosition) {
        for slot in self.slots.iter_mut() {
            let hit = matches!(slot, Some(e) if e.position == *pos);
            if hit {
                *slot = None;
                self.occupied -= 1;
                return;
            }
        }
    }
}

/// Run 422 — the authoritative live-operation representation for one ownership
/// domain. The domain starts in `Legacy` (the original unbounded `HashMap`); an
/// explicit `enter_bounded_live_mode` transition installs a fixed-capacity
/// `Bounded` container. The two modes are mutually exclusive and there is never
/// a second live table.
#[derive(Debug)]
enum LiveMode {
    Legacy(HashMap<SigningPosition, LiveState>),
    Bounded(LiveContainer),
}

impl LiveMode {
    fn get(&self, pos: &SigningPosition) -> Option<&LiveState> {
        match self {
            LiveMode::Legacy(m) => m.get(pos),
            LiveMode::Bounded(c) => c.get(pos),
        }
    }

    fn get_mut(&mut self, pos: &SigningPosition) -> Option<&mut LiveState> {
        match self {
            LiveMode::Legacy(m) => m.get_mut(pos),
            LiveMode::Bounded(c) => c.get_mut(pos),
        }
    }

    fn contains_key(&self, pos: &SigningPosition) -> bool {
        self.get(pos).is_some()
    }

    fn len(&self) -> usize {
        match self {
            LiveMode::Legacy(m) => m.len(),
            LiveMode::Bounded(c) => c.occupied,
        }
    }

    /// Whether a currently-absent position can be admitted a fresh slot. Legacy
    /// mode is unbounded; bounded mode has room iff `occupied < capacity`.
    fn can_admit_fresh(&self) -> bool {
        match self {
            LiveMode::Legacy(_) => true,
            LiveMode::Bounded(c) => c.occupied < c.capacity,
        }
    }

    fn insert(&mut self, pos: SigningPosition, state: LiveState) -> bool {
        match self {
            LiveMode::Legacy(m) => {
                m.insert(pos, state);
                true
            }
            LiveMode::Bounded(c) => c.insert(pos, state),
        }
    }

    fn remove(&mut self, pos: &SigningPosition) {
        match self {
            LiveMode::Legacy(m) => {
                m.remove(pos);
            }
            LiveMode::Bounded(c) => c.remove(pos),
        }
    }

    /// If bounded, the fixed capacity `L`; otherwise `None`.
    fn bounded_capacity(&self) -> Option<usize> {
        match self {
            LiveMode::Bounded(c) => Some(c.capacity),
            LiveMode::Legacy(_) => None,
        }
    }

    /// If legacy, `(len, allocated_capacity)` of the map; otherwise `None`.
    fn legacy_len_capacity(&self) -> Option<(usize, usize)> {
        match self {
            LiveMode::Legacy(m) => Some((m.len(), m.capacity())),
            LiveMode::Bounded(_) => None,
        }
    }
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
    /// Positions with a live operation in this process. Run 422 — this is now
    /// the authoritative [`LiveMode`]: `Legacy` (the original unbounded
    /// `HashMap`) until an explicit `enter_bounded_live_mode` transition
    /// installs a fixed-capacity `Bounded` container.
    live: LiveMode,
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
    /// Run 422 D7-D10 Correction E — the tracked attempted update of the last
    /// uncertain reservation/accounting write, used to resolve the failed batch's
    /// possible durable outcomes conservatively during reconciliation. `None` when
    /// the uncertainty did not originate from a tracked reservation write.
    uncertain_attempt: Option<UncertainAttempt>,
    /// Monotonic source of unique live operation ids (checked; exhaustion is a
    /// terminal fail-closed state, never wraparound). In-process bookkeeping.
    next_operation_id: u64,
    /// Run 422 — the non-enabling accountant association for this signing
    /// domain: at most ONE operational-ledger identity, recorded the first time
    /// an association is installed and thereafter reused for identical-ledger
    /// installs. It is identity bookkeeping ONLY: it enables no bounded signing
    /// route, admits no memory, takes no accounting charge, and does not gate
    /// any existing reservation/continuation/publication/workspace path. The
    /// held clone is Arc-backed shared ownership of the EXISTING ledger (no new
    /// ledger is allocated); it survives individual journal/facade handle drops
    /// because the ownership domain outlives them.
    admission: Option<crate::safety_record_store::accounting::SharedAccountant>,
}

impl SigningOwnershipDomain {
    /// Create a fresh ownership domain with a process-unique token. Backends call
    /// this once per instance (via a `OnceLock`) and share the resulting `Arc`.
    /// The domain starts **unestablished**: no journal-wide limit and a zero
    /// counter until an explicit `initialize`/`open` validates durable state.
    pub fn new() -> Arc<Self> {
        Self::with_recovered_ack_cache_capacity(MAX_RECOVERED_ACK_ENTRIES)
    }

    /// Construct a fresh ownership domain whose recovered-acknowledgement cache
    /// holds at most `cache_capacity` entries. The production constructor
    /// [`SigningOwnershipDomain::new`] always uses [`MAX_RECOVERED_ACK_ENTRIES`];
    /// a smaller capacity is a test-only affordance (see
    /// [`SigningOwnershipDomain::new_with_cache_capacity_for_test`]) and is NOT a
    /// production configuration knob.
    fn with_recovered_ack_cache_capacity(cache_capacity: usize) -> Arc<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        // Process-unique, monotonically increasing domain token. This only needs
        // to distinguish concurrently-live domains within one process; it is not
        // persisted and carries no durability meaning.
        static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
        Arc::new(Self {
            token: NEXT_TOKEN.fetch_add(1, Ordering::Relaxed),
            inner: Mutex::new(DomainInner {
                established: None,
                live: LiveMode::Legacy(HashMap::new()),
                recovered_acked: RecoveredAckCache::new(cache_capacity),
                reserved_positions: 0,
                accounting_uncertain: false,
                uncertain_attempt: None,
                next_operation_id: 1,
                admission: None,
            }),
        })
    }

    /// Run 422 D7-D10 Correction A (test-only) — construct a fresh ownership
    /// domain with a deliberately SMALL recovered-acknowledgement cache so a test
    /// can force FIFO eviction through the real journal flow without issuing
    /// [`MAX_RECOVERED_ACK_ENTRIES`] distinct recoveries. This does not change the
    /// production constructor and exposes no production configuration surface; it
    /// is private test access reached only by a test backend's
    /// `signing_ownership_domain`. The semantics (bound, FIFO eviction, exact
    /// record binding) are identical to production — only the bound is smaller.
    #[cfg(test)]
    pub(crate) fn new_with_cache_capacity_for_test(cache_capacity: usize) -> Arc<Self> {
        Self::with_recovered_ack_cache_capacity(cache_capacity)
    }
}

// ============================================================================
// The journal
// ============================================================================

/// Run 422 — fixed-size, crate-internal refusal for installing the
/// non-enabling accountant association. It is `Copy` and allocation-free: it
/// carries no `String` and no owned payload, so constructing or returning it on
/// any branch takes no accounting lock and performs no heap allocation. It is
/// deliberately distinct from [`JournalError`], whose variants carry allocating
/// diagnostic strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionInstallError {
    /// A different operational ledger is already associated with this signing
    /// domain; the installed association is left unchanged.
    LedgerMismatch,
    /// The signing-domain mutex was poisoned by a panic in another holder.
    LockPoisoned,
}

/// Run 422 — fixed-size, `Copy`, allocation-free refusal for association-sourced
/// workspace admission ([`SigningReservationJournal::admit_retrieval_workspace`]).
/// Every variant is `Copy` and carries no `String`, so constructing or returning
/// it on any branch performs no heap allocation. The admission reserve path
/// (verified in `accounting::SharedAccountant::reserve`, `AllocationAccountant::admit`,
/// and `AggregateAuthority::admit`) can only yield an `Unbound` ledger, an
/// `AdmissionOverflow` ceiling refusal, or an accounting `ArithmeticOverflow`;
/// those are mapped faithfully, and any other (never taken on this path)
/// `SafetyStoreError` is collapsed to `Other` WITHOUT allocating a replacement
/// diagnostic string. It is deliberately distinct from the allocating `JournalError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum WorkspaceAdmissionError {
    /// No operational accountant is installed in this journal's ownership domain.
    NoAssociation,
    /// The signing-domain mutex was poisoned by a panic in another holder.
    Lock,
    /// A reservation was attempted against a ledger partition/authority that was
    /// never bound.
    Unbound(crate::safety_record_store::error::LedgerScope),
    /// A reservation charge would raise a partition or aggregate running total
    /// over its ceiling. Built from `Copy` numeric data only.
    CapacityExceeded {
        scope: crate::safety_record_store::error::LedgerScope,
        charge: u128,
        current: u128,
        next: u128,
        cap: u128,
    },
    /// Accounting arithmetic overflowed while summing a charge.
    Arithmetic(crate::safety_record_store::error::ArithmeticOverflowSite),
    /// Any other `SafetyStoreError` (not produced on the verified admission reserve
    /// path); collapsed to a fixed-size code without allocation.
    Other,
}

/// Run 422 — fixed-size, `Copy`, allocation-free refusal for the opt-in checked
/// retained-retrieval entrypoint
/// ([`SigningReservationJournal::retrieve_retained_checked`]). Distinct from
/// [`RetrievalError`]: it adds the two pre-delegation refusals (`NoAssociation`,
/// `ForeignWorkspace`) and forwards the unchanged delegated retrieval error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum CheckedRetrievalError {
    /// No operational accountant is installed in this journal's ownership domain.
    NoAssociation,
    /// The signing-domain mutex was poisoned by a panic in another holder.
    Lock,
    /// The output and/or scratch workspace is not covered by the installed
    /// operational ledger + aggregate authority. Returned BEFORE any storage
    /// access, reissue, or output mutation.
    ForeignWorkspace,
    /// The delegated, unchanged `retrieve_retained` returned an error.
    Retrieval(RetrievalError),
}

/// Run 422 — fixed-size, `Copy`, allocation-free SUCCESS outcome of
/// acknowledged-operation retirement
/// ([`SigningReservationJournal::retire_acknowledged_operation`]). It carries no
/// heap and no key material, so it never forwards a heap-bearing [`JournalError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum RetirementOutcome {
    /// The exact acknowledged live operation named by the capability was removed
    /// from this domain's in-process live table. No storage was read or written,
    /// no durable record/metadata changed, the durable reserved-position count was
    /// not decremented, operation-id/uncertainty state was untouched, the
    /// recovered-acknowledgement cache was not modified, and no accounting
    /// coverage was reserved or released.
    Retired,
}

/// Run 422 — fixed-size, `Copy`, allocation-free REFUSAL of acknowledged-operation
/// retirement. Every variant is a defensive refusal that removes nothing; no
/// heap-bearing [`JournalError`] is forwarded through this API and no
/// attacker-controlled content is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum RetirementError {
    /// The signing-journal ownership mutex was poisoned by a prior panic while
    /// held. Nothing is removed.
    LockPoisoned,
    /// The capability belongs to a foreign ownership domain (its `domain_token`
    /// does not match this journal's domain). Nothing is removed.
    ForeignDomain,
    /// No live entry exists at the capability's position (already retired, never
    /// reserved in this process, or recovered-only). Nothing is removed.
    NoLiveOperation,
    /// A live entry exists at the position but its operation id or binding does not
    /// match the capability, so it is a DIFFERENT operation. Nothing is removed.
    OperationMismatch,
    /// The live operation has not crossed the signer-invocation boundary
    /// (`invoked == false`). Nothing is removed.
    NotInvoked,
    /// The live operation has no established in-process result-write
    /// acknowledgement (`result_acked == false`). Readable `Signed` bytes alone do
    /// NOT satisfy this (Correction C uncertainty rule). Nothing is removed.
    NotAcknowledged,
}

/// Run 422 — map a `SafetyStoreError` from the admission reserve path into the
/// fixed-size [`WorkspaceAdmissionError`]. The verified reserve path only produces
/// `Unbound`, `AdmissionOverflow`, or `ArithmeticOverflow`; those are mapped
/// faithfully and any other variant is collapsed to `Other` without allocating a
/// replacement string. (Mapping an already-constructed error is NOT claimed to
/// prevent an allocation a helper might already have performed — but no
/// admission-path helper allocates on these branches.)
#[cfg_attr(not(test), allow(dead_code))]
fn map_admission_error(
    e: crate::safety_record_store::SafetyStoreError,
) -> WorkspaceAdmissionError {
    use crate::safety_record_store::error::CapacityRefusalDetail;
    use crate::safety_record_store::SafetyStoreError;
    match e {
        SafetyStoreError::CapacityRefusal(CapacityRefusalDetail::Unbound(scope)) => {
            WorkspaceAdmissionError::Unbound(scope)
        }
        SafetyStoreError::CapacityRefusal(CapacityRefusalDetail::AdmissionOverflow {
            scope,
            charge,
            current,
            next,
            cap,
        }) => WorkspaceAdmissionError::CapacityExceeded {
            scope,
            charge,
            current,
            next,
            cap,
        },
        SafetyStoreError::ArithmeticOverflow(site) => WorkspaceAdmissionError::Arithmetic(site),
        _ => WorkspaceAdmissionError::Other,
    }
}

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
    /// Run 422 — install the **non-enabling accountant association** for this
    /// journal's signing-ownership domain.
    ///
    /// This records at most ONE operational-ledger identity for the domain. It
    /// is identity-only bookkeeping: it does NOT enable any bounded fresh-signing
    /// route, admit journal memory, take any accounting charge, allocate or
    /// retire a live-operation table, or alter any existing reservation,
    /// continuation, publication-capability, retained-retrieval, storage-write,
    /// or workspace path. Installing an association never flips the domain into
    /// a “bounded-only” mode.
    ///
    /// All work happens under a SINGLE acquisition of the existing signing-domain
    /// mutex (the same lock that serializes every supported handle over this
    /// domain). No accounting lock is taken, no reservation is created, and no
    /// second synchronization mechanism or out-of-lock installation candidate is
    /// introduced:
    ///
    /// * **Unassociated** (`None`): one clone of `accountant` is retained — an
    ///   Arc refcount bump sharing the EXISTING ledger, not a new ledger — and
    ///   the call succeeds.
    /// * **Same installed ledger**: succeeds WITHOUT replacing or re-cloning the
    ///   stored value.
    /// * **Different installed ledger**: refused with
    ///   [`AdmissionInstallError::LedgerMismatch`]; the association is unchanged.
    /// * **Poisoned mutex**: refused with [`AdmissionInstallError::LockPoisoned`].
    ///
    /// Because the association lives in the shared ownership domain (behind the
    /// domain `Arc`), it outlives the individual journal/facade handles that
    /// installed it and remains observable to any later handle opened over the
    /// same backend instance.
    pub(crate) fn install_accountant_association(
        &self,
        accountant: &crate::safety_record_store::accounting::SharedAccountant,
    ) -> Result<(), AdmissionInstallError> {
        let mut inner = self
            .domain
            .inner
            .lock()
            .map_err(|_| AdmissionInstallError::LockPoisoned)?;
        match inner.admission.as_ref() {
            None => {
                inner.admission = Some(accountant.clone());
                Ok(())
            }
            Some(existing) if existing.same_ledger(accountant) => Ok(()),
            Some(_) => Err(AdmissionInstallError::LedgerMismatch),
        }
    }

    /// Run 422 — the EXPLICIT, crate-internal, non-enabling transition into
    /// bounded live-container mode. Installing an accountant association is
    /// identity bookkeeping only and never enables bounded behavior; THIS
    /// separate operation is the one that validates prerequisites, takes the
    /// full container charge, and installs the fixed-capacity container.
    ///
    /// All work happens under ONE acquisition of the existing journal-domain
    /// mutex. The sequence is: require an established journal and an installed
    /// association; validate `capacity` against the established durable-position
    /// limit; require the legacy live map to have zero entries AND zero
    /// capacity (first transition); compute and admit the full charge
    /// (`size_of::<LiveContainer>() + L * size_of::<Slot>()`) BEFORE any
    /// allocation; construct the container fallibly; install ONLY on success.
    ///
    /// An identical repeated configuration is idempotent (`Ok`); a conflicting
    /// capacity refuses with [`BoundedModeError::CapacityMismatch`] WITHOUT
    /// changing the existing bounded container. Every failure preserves the
    /// previous mode and both ledgers. There is no production caller: a domain
    /// that never requests this transition keeps its unchanged legacy behavior.
    pub(crate) fn enter_bounded_live_mode(
        &self,
        capacity: usize,
    ) -> Result<(), BoundedModeError> {
        use crate::safety_record_store::accounting::Reservation;
        let mut inner = self
            .domain
            .inner
            .lock()
            .map_err(|_| BoundedModeError::DomainMutexPoisoned)?;

        // (1) Require an established journal (the one journal-wide position limit).
        let limit = inner
            .established
            .ok_or(BoundedModeError::JournalNotEstablished)?
            .max_reserved_positions;

        // (2) Require an installed accountant association. Installation is
        //     identity association only; this explicit transition is the separate
        //     operation that actually consults it and takes a charge.
        let accountant = inner
            .admission
            .clone()
            .ok_or(BoundedModeError::NoAccountantAssociation)?;

        // (3) Validate configured capacity against the established durable-position
        //     limit, with checked conversion. `0` is refused; the first slice does
        //     not model a zero-capacity bounded container.
        if capacity == 0 {
            return Err(BoundedModeError::ZeroCapacity);
        }
        let capacity_u64 =
            u64::try_from(capacity).map_err(|_| BoundedModeError::CapacityAboveLimit)?;
        if capacity_u64 > limit {
            return Err(BoundedModeError::CapacityAboveLimit);
        }

        // (4) Idempotence / conflict against an existing bounded container. An
        //     identical repeated configuration is a no-op success; a different
        //     capacity refuses WITHOUT changing the existing bounded container.
        if let Some(existing_capacity) = inner.live.bounded_capacity() {
            if existing_capacity == capacity {
                return Ok(());
            }
            return Err(BoundedModeError::CapacityMismatch);
        }

        // (5) First-transition prerequisites: the legacy live map must have zero
        //     entries AND zero allocated capacity (so no live owner or already-
        //     allocated map storage is silently left uncharged).
        let (legacy_len, legacy_capacity) = inner
            .live
            .legacy_len_capacity()
            .expect("live is Legacy here (bounded handled above)");
        if legacy_len != 0 {
            return Err(BoundedModeError::LegacyNotEmpty);
        }
        if legacy_capacity != 0 {
            return Err(BoundedModeError::LegacyHasCapacity);
        }

        // (6) Compute the FULL container charge with checked arithmetic BEFORE any
        //     allocation. Sizes are derived from the actual types (never hard-
        //     coded). The charge covers the container control representation
        //     (`size_of::<LiveContainer>()`: the Vec control triple, the counters,
        //     the embedded reservation, and padding) PLUS the slot backing
        //     (`L * size_of::<Slot>()`).
        let slot_size = std::mem::size_of::<Slot>() as u128;
        let base = std::mem::size_of::<LiveContainer>() as u128;
        let backing = (capacity as u128)
            .checked_mul(slot_size)
            .ok_or(BoundedModeError::ChargeOverflow)?;
        // Allocation-layout representability on the target: the backing byte size
        // must fit `isize` (the RawVec allocation bound).
        if backing > isize::MAX as u128 {
            return Err(BoundedModeError::LayoutOverflow);
        }
        let charge = base
            .checked_add(backing)
            .ok_or(BoundedModeError::ChargeOverflow)?;

        // (7) Admit the full charge against the installed accountant BEFORE
        //     constructing any covered allocation. The accounting lock is taken
        //     here while holding the domain lock; the domain lock is never
        //     re-entered by the accountant, so the (domain -> accounting) order is
        //     acyclic. A refusal leaves both ledgers and the previous mode
        //     unchanged (no allocation attempted).
        let coverage: Reservation = accountant
            .reserve(charge)
            .map_err(|_| BoundedModeError::AdmissionRefused)?;

        // (8) Construct the container fallibly, consuming `coverage`. On failure
        //     `construct` owns and drops `coverage`, releasing its reservation
        //     exactly once, and the previous mode is preserved — nothing is
        //     installed.
        let container = LiveContainer::construct(capacity, coverage)?;

        // (9) Install ONLY on success. No further fallible admission.
        inner.live = LiveMode::Bounded(container);
        Ok(())
    }

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
        // A new journal requires an empty signing namespace: refuse if ANY entry
        // exists (a decision record OR any unexpected/foreign key). Bounded
        // streaming existence check — abort on the first entry.
        if Self::namespace_has_any_entry(store.as_ref())? {
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
    ///
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
                // a legacy/foreign namespace that has ANY existing signing state.
                if Self::namespace_has_any_entry(store.as_ref())? {
                    return Err(JournalError::LegacyRecordsWithoutMetadata);
                }
                return Err(JournalError::NotInitialized);
            }
        };

        // Bounded streaming validation over the ENTIRE signing namespace: classify
        // every entry, count distinct persisted positions, and check key/record
        // association, formats, bounds, and checksums per record. We never collect
        // the namespace or allocate from stored counts. Validation stops as soon as
        // a violation is observed (an unexpected entry, a mismatched key, or an
        // over-count) — at most one excess/unexpected entry is needed to establish
        // the violation. A validation failure is captured as its precise
        // `JournalError` and the scan is aborted via a sentinel; a genuine
        // iterator/read error propagates distinctly.
        const ABORT: &str = "__signing_validation_abort__";
        let mut counted: u64 = 0;
        let mut validation_err: Option<JournalError> = None;
        let expected = metadata.reserved_positions;
        let scan = store.for_each_signing_namespace_entry(&mut |key: &[u8], value: &[u8]| {
            // Whole-namespace classification: only a supported decision key
            // (`sj:v1:`) is a record; every other entry is unexpected and refused
            // BEFORE any decode/copy of its value.
            if !key.starts_with(SIGNING_RECORD_KEY_PREFIX) {
                validation_err = Some(JournalError::UnexpectedNamespaceEntry(format!(
                    "signing-namespace key is neither metadata nor a supported \
                     decision record (len={})",
                    key.len()
                )));
                return Err(StorageError::Other(ABORT.to_string()));
            }
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
            // Early termination: as soon as the observed count exceeds the durable
            // expected count, the namespace holds an excess record. Stop now — a
            // single excess entry establishes the violation; do not scan the rest.
            if counted > expected {
                validation_err = Some(JournalError::AccountingInconsistent(format!(
                    "stored positions exceed metadata count {}",
                    expected
                )));
                return Err(StorageError::Other(ABORT.to_string()));
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

        // Accounting consistency: the streamed count MUST equal the durable count
        // (the over-count case already aborted early above; this catches an
        // under-count), and the durable count MUST be within the established limit
        // (already checked structurally in decode; re-checked against the stream).
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

    /// Bounded streaming existence check over the ENTIRE signing namespace:
    /// returns `true` as soon as any entry (a decision record OR any unexpected /
    /// foreign key, excluding only the metadata key) is observed, aborting the
    /// scan. Never collects the namespace.
    fn namespace_has_any_entry(store: &dyn SigningJournalStorage) -> Result<bool, JournalError> {
        // A sentinel `StorageError` signals "found one" and stops the scan early.
        const FOUND: &str = "__signing_namespace_has_entry__";
        let mut found = false;
        let scan = store.for_each_signing_namespace_entry(&mut |_key, _value| {
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

    /// Test-only: an ordered snapshot (contents + FIFO order) of the recovered-
    /// acknowledgement cache, so a test can assert retirement leaves it entirely
    /// untouched (contents AND order), not merely its length.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn recovered_ack_snapshot_for_test(
        &self,
    ) -> Vec<(SigningPosition, SigningDecisionRecord)> {
        self.domain
            .inner
            .lock()
            .expect("domain lock")
            .recovered_acked
            .snapshot()
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
        // Run 422 — settle bounded live-container slot availability BEFORE any
        // durable write, under this SAME journal-domain guard. In Legacy mode
        // there is always room; in Bounded mode a FULL container refuses with a
        // capacity refusal that performs NO fresh record/metadata write. This is
        // reached only on the fresh-record-absent branch, so existing-position
        // conflict / potentially-signed / retained-retry classification (resolved
        // above against the durable record) is never suppressed by full capacity.
        if !inner.live.can_admit_fresh() {
            return Ok(ReservationOutcome::LiveCapacityExhausted);
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
                // stored. Mark the in-memory accounting uncertain and record the
                // tracked attempted update (prior count, attempted count, limit) so
                // the next admission can resolve the failed batch's possible
                // outcomes against the durable metadata; grant no continuation and
                // do not advance the in-memory counter.
                inner.accounting_uncertain = true;
                inner.uncertain_attempt = Some(UncertainAttempt {
                    prior_count: inner.reserved_positions,
                    attempted_count: new_reserved,
                });
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

    /// Run 422 — additive, isolated, retained-ONLY signature retrieval.
    ///
    /// Acquires the ownership domain ONCE. If journal accounting is uncertain it
    /// refuses conservatively (`Blocked`) with ZERO side effects. Otherwise it
    /// reads one bounded envelope into the admitted scratch, validates both
    /// checksums, structure, position, binding, stage, and output capacity BEFORE
    /// any reissue write or output mutation, and classifies exactly as
    /// `reserve_for_sign` does — but cache-free and additive:
    ///
    /// * `Reserved` → `PotentiallySigned`.
    /// * `Signed` with a live unacknowledged result → `PotentiallySigned`.
    /// * `Signed` with a live acknowledged result → delivered after validation.
    /// * `Signed` with NO live entry → exact-envelope SYNCED reissue BEFORE
    ///   delivery (no recovery-cache read/insert); a failed/uncertain reissue
    ///   suppresses delivery and leaves the output unchanged.
    ///
    /// Both delivering branches converge on ONE checked output-copy and return a
    /// borrowed view of the admitted output. It makes no fresh reservation, grants
    /// no continuation or publication capability, and never invokes the signer.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn retrieve_retained<'o>(
        &self,
        position: &SigningPosition,
        binding: &BindingDigest,
        scratch: &mut EnvelopeScratch,
        output: &'o mut AdmittedOutput,
    ) -> Result<RetainedDelivery<'o>, RetrievalError> {
        // Single ownership-domain acquisition (short-lived leaf; no re-entry).
        let inner = self.domain.inner.lock().map_err(|_| RetrievalError::Lock)?;

        // Conservative uncertainty refusal: no metadata read, reconciliation,
        // latch clearing, counter update, or write.
        if inner.accounting_uncertain {
            return Ok(RetainedDelivery::Blocked);
        }

        // Non-allocating key encode into the admitted 55-byte array.
        let klen = position
            .encode_key_into(scratch.journal_key_buf())
            .map_err(|_| RetrievalError::Storage(BoundedDiag::KeyInvalid))?;
        scratch.set_jkey_len(klen);

        // Bounded pinned read with disjoint key/envelope borrows.
        let used = {
            let (jk, env) = scratch.key_and_envelope();
            match self.store.read_signing_envelope_into(jk, env) {
                Ok(None) => return Ok(RetainedDelivery::Missing),
                Ok(Some(n)) => n,
                Err(BoundedStorageError::CapacityExceeded { .. }) => {
                    return Ok(RetainedDelivery::Refused(
                        RefuseReason::WorkspaceCapacityExceeded,
                    ));
                }
                Err(BoundedStorageError::Unsupported) => {
                    return Err(RetrievalError::Unsupported);
                }
                Err(BoundedStorageError::Corruption(d)) | Err(BoundedStorageError::Io(d)) => {
                    return Err(RetrievalError::Storage(d));
                }
            }
        };
        scratch
            .set_used(used)
            .map_err(|_| RetrievalError::Storage(BoundedDiag::EnvelopeInvalid))?;

        // Structural validation: both checksum layers and every length relation,
        // then semantic validation — all BEFORE any write or output mutation.
        let kind;
        let stage;
        let sig_len;
        let decoded_position;
        let decoded_binding;
        {
            let view = match BorrowedRecordView::parse(scratch.envelope()) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(RetainedDelivery::Refused(RefuseReason::MalformedRecord));
                }
            };
            if view.magic != &RECORD_MAGIC[..] || view.version != SIGNING_RECORD_FORMAT_VERSION {
                return Ok(RetainedDelivery::Refused(RefuseReason::MalformedRecord));
            }
            kind = match SigningKind::from_tag(view.kind_tag) {
                Some(k) => k,
                None => {
                    return Ok(RetainedDelivery::Refused(RefuseReason::MalformedRecord));
                }
            };
            stage = match SigningRecordStage::from_tag(view.stage_tag) {
                Some(st) => st,
                None => {
                    return Ok(RetainedDelivery::Refused(RefuseReason::MalformedRecord));
                }
            };
            sig_len = view.sig_len();
            match stage {
                SigningRecordStage::Reserved if sig_len != 0 => {
                    return Ok(RetainedDelivery::Refused(RefuseReason::MalformedRecord));
                }
                SigningRecordStage::Signed if sig_len == 0 => {
                    return Ok(RetainedDelivery::Refused(RefuseReason::MalformedRecord));
                }
                _ => {}
            }
            let mut genesis = [0u8; 32];
            genesis.copy_from_slice(view.network_genesis);
            decoded_position = SigningPosition {
                validator_id: view.validator_id,
                network_genesis: genesis,
                kind,
                originating_view: view.originating_view,
            };
            let mut bind = [0u8; 32];
            bind.copy_from_slice(view.binding);
            decoded_binding = BindingDigest(bind);
        }

        // Position/key-derivation invariant.
        if decoded_position != *position {
            return Ok(RetainedDelivery::Refused(RefuseReason::PositionMismatch));
        }
        // Exact-message binding.
        if decoded_binding != *binding {
            return Ok(RetainedDelivery::Refused(RefuseReason::BindingConflict));
        }
        // Output capacity validated BEFORE any reissue write or output mutation.
        if sig_len > output.capacity() {
            return Ok(RetainedDelivery::Refused(
                RefuseReason::WorkspaceCapacityExceeded,
            ));
        }

        // Classification (retained-only, cache-free). A `None` live entry is
        // STRICTLY distinguished from `Some(false)`.
        match stage {
            SigningRecordStage::Reserved => {
                return Ok(RetainedDelivery::PotentiallySigned);
            }
            SigningRecordStage::Signed => {
                match inner.live.get(position).map(|ls| ls.result_acked) {
                    Some(false) => {
                        return Ok(RetainedDelivery::PotentiallySigned);
                    }
                    Some(true) => {
                        // Live acknowledged: no reissue needed.
                    }
                    None => {
                        // Recovered: cache-free exact-envelope synced reissue
                        // BEFORE delivery.
                        let jk = scratch.journal_key();
                        let env = scratch.envelope();
                        if self.store.reissue_signing_envelope_synced(jk, env).is_err() {
                            return Ok(RetainedDelivery::DeliverySuppressed);
                        }
                    }
                }
            }
        }

        // One common checked output-copy step (both delivering Signed branches).
        let env = scratch.envelope();
        let sig = &env[ENVELOPE_SIG_OFFSET..ENVELOPE_SIG_OFFSET + sig_len];
        output
            .set(sig)
            .map_err(|_| RetrievalError::Storage(BoundedDiag::EnvelopeInvalid))?;
        Ok(RetainedDelivery::Retained(output.view()))
    }

    /// Run 422 — association-sourced admission of the retained-retrieval
    /// workspace. It sources its accountant EXCLUSIVELY from the accountant
    /// already installed in this journal's ownership-domain association; it never
    /// accepts a caller-selected substitute and never auto-installs one.
    ///
    /// Sequence: acquire the signing-domain mutex ONCE; if no association is
    /// installed refuse `NoAssociation`, if the mutex is poisoned refuse `Lock`
    /// (both fixed-size, allocation-free); otherwise clone the installed accountant
    /// handle ONCE (an `Arc` refcount bump sharing the EXISTING ledger — no new
    /// ledger), RELEASE the domain guard, and move that handle into the existing
    /// [`RetrievalWorkspaceOwner`] admission mechanism. That owner reserves BOTH
    /// existing workspace charges (output first, then envelope) BEFORE constructing
    /// either buffer and rolls the first back if the second refuses, so a capacity
    /// refusal leaves both ledgers unchanged and builds no buffer.
    ///
    /// Accounting: this adds NO new covered storage. The only incremental object is
    /// the transient [`RetrievalWorkspaceOwner`], an admission FACTORY (not retained
    /// workspace) holding a clone of the EXISTING installed accountant handle — the
    /// association already recorded on `DomainInner::admission`, which this slice
    /// does not newly charge. The two reservations it produces are exactly the
    /// pre-existing output/envelope workspace charges under the UNCHANGED ceilings.
    /// The still-uncompleted journal-domain accounting remains explicitly unfinished.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn admit_retrieval_workspace(
        &self,
    ) -> Result<(AdmittedOutput, EnvelopeScratch), WorkspaceAdmissionError> {
        // Acquire the signing-domain mutex ONCE, read the installed association,
        // clone the handle, and release the guard before any accounting call.
        let accountant = {
            let inner = self
                .domain
                .inner
                .lock()
                .map_err(|_| WorkspaceAdmissionError::Lock)?;
            match inner.admission.as_ref() {
                None => return Err(WorkspaceAdmissionError::NoAssociation),
                Some(a) => a.clone(),
            }
            // Domain guard released here, before any reservation is attempted.
        };
        // Move the installed-accountant handle into the existing workspace-owner
        // admission mechanism (no substitute accountant, no automatic install).
        RetrievalWorkspaceOwner::from_installed(accountant)
            .admit()
            .map_err(map_admission_error)
    }

    /// Run 422 — opt-in, additive CHECKED retained retrieval. It establishes that
    /// BOTH the `output` and the `scratch` workspace are covered by the operational
    /// accountant INSTALLED in this journal's ownership-domain association, then
    /// delegates to the unchanged [`retrieve_retained`](Self::retrieve_retained).
    /// Existing legacy callers of `retrieve_retained` are unaffected; this
    /// guarantee applies ONLY to this opt-in route.
    ///
    /// Sequence: acquire the signing-domain mutex ONCE; BORROW (never clone) the
    /// installed accountant; check both reservations against it with the
    /// non-allocating, lock-free inspectors; refuse `NoAssociation` or
    /// `ForeignWorkspace` BEFORE any storage read, reissue, or output mutation; end
    /// the borrow and RELEASE the guard; then delegate. The association is set-once
    /// immutable, so the identity checked under the guard still holds after release;
    /// the exclusive `&mut` workspace borrows prevent substitution or release of the
    /// checked objects across the delegated call; and the delegated
    /// `retrieve_retained` re-acquires the SAME domain mutex, so the guard MUST be
    /// released first (it is) to avoid a non-reentrant re-lock.
    ///
    /// This is an accounting-identity check ONLY: not authorization, a capability, a
    /// freshness token, or permission to sign. `scratch` keeps its independent
    /// lifetime (it is not tied to `'o`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn retrieve_retained_checked<'o>(
        &self,
        position: &SigningPosition,
        binding: &BindingDigest,
        scratch: &mut EnvelopeScratch,
        output: &'o mut AdmittedOutput,
    ) -> Result<RetainedDelivery<'o>, CheckedRetrievalError> {
        // Identity gate under a SINGLE short-lived domain acquisition; the
        // inspectors allocate nothing and take no accounting lock, so no storage
        // read, reservation, release, or callback occurs here.
        {
            let inner = self
                .domain
                .inner
                .lock()
                .map_err(|_| CheckedRetrievalError::Lock)?;
            let accountant = match inner.admission.as_ref() {
                None => return Err(CheckedRetrievalError::NoAssociation),
                Some(a) => a,
            };
            if !(output.is_covered_by(accountant) && scratch.is_covered_by(accountant)) {
                return Err(CheckedRetrievalError::ForeignWorkspace);
            }
            // Borrow of `accountant` and the domain guard both end here.
        }
        // Guard released; delegate to the unchanged retrieval (which re-locks the
        // same domain mutex and owns its own current journal-state checks).
        self.retrieve_retained(position, binding, scratch, output)
            .map_err(CheckedRetrievalError::Retrieval)
    }

    /// Run 422 — isolated, crate-internal, opt-in ACKNOWLEDGED-operation
    /// retirement. Removes ONLY the exact in-process live entry owned by `cap`
    /// once its result write has been acknowledged in THIS process, so the
    /// volatile publication authority is explicitly released while the durable
    /// signing obligation is left fully intact.
    ///
    /// The position is derived from the capability itself; no separately-selectable
    /// position is accepted. The signing-journal ownership mutex is acquired ONCE;
    /// BEFORE removing anything it requires that `cap` belongs to this ownership
    /// domain, a live entry exists at its position, that entry's operation id and
    /// binding match `cap`, `invoked == true`, and `result_acked == true`. On any
    /// refusal or lock poisoning it removes nothing and returns a fixed-size,
    /// allocation-free [`RetirementError`] (never a heap-bearing [`JournalError`]).
    ///
    /// It does NOT read or write storage, delete or rewrite the durable `Signed`
    /// record or journal metadata, decrement the durable reserved-position count,
    /// reset operation ids or uncertainty state, seed/clear/modify the
    /// recovered-acknowledgement cache, reserve or release accounting coverage,
    /// invoke a signer, or mint a continuation; it requires and installs no
    /// accountant association. The removed [`LiveState`] is fully inline, so its
    /// drop takes no accounting lock and touches no storage. Removing the entry
    /// establishes NOTHING about the `HashMap`'s backing allocation (no bounded
    /// container accounting or abandoned-operation reclamation is implied).
    ///
    /// After it succeeds the borrowed `cap` still exists but owns no live
    /// operation: [`record_signed_result`](Self::record_signed_result) then rejects
    /// it through its normal stale/missing-operation check, a repeated retirement
    /// returns [`RetirementError::NoLiveOperation`] without changing state, and a
    /// later reservation for the position still observes the durable record (never
    /// `FreshlyReserved`). This acknowledges ONLY the recorded in-process
    /// result-write acknowledgement; it asserts nothing about cryptographic
    /// validity, freshness, rollback resistance, or signing permission.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn retire_acknowledged_operation(
        &self,
        cap: &ResultPublicationCapability,
    ) -> Result<RetirementOutcome, RetirementError> {
        // Acquire the ownership mutex ONCE. A poisoned lock removes nothing.
        let mut inner = self
            .domain
            .inner
            .lock()
            .map_err(|_| RetirementError::LockPoisoned)?;

        // A foreign-domain capability never addresses this journal's live table.
        if cap.domain_token != self.domain.token {
            return Err(RetirementError::ForeignDomain);
        }

        // Validate the EXACT live entry BEFORE removing anything. The position is
        // taken from the capability itself; a missing, mismatched, un-invoked, or
        // unacknowledged operation is refused and leaves the table untouched.
        match inner.live.get(&cap.position) {
            None => return Err(RetirementError::NoLiveOperation),
            Some(ls) => {
                if ls.operation_id != cap.operation_id || ls.binding != cap.binding {
                    return Err(RetirementError::OperationMismatch);
                }
                if !ls.invoked {
                    return Err(RetirementError::NotInvoked);
                }
                if !ls.result_acked {
                    return Err(RetirementError::NotAcknowledged);
                }
            }
        }

        // All preconditions hold: remove ONLY this exact live entry. Nothing else
        // is read, written, released, reset, or recharged.
        inner.live.remove(&cap.position);
        Ok(RetirementOutcome::Retired)
    }

    /// RUN 422 — association-sourced admission of the admitted FRESH-RESERVATION
    /// workspace. Like [`admit_retrieval_workspace`](Self::admit_retrieval_workspace)
    /// it sources its accountant EXCLUSIVELY from the accountant already installed
    /// in this journal's ownership-domain association: it acquires the domain mutex
    /// ONCE, refuses `NoAssociation` if none is installed (or `Lock` on poisoning),
    /// clones the installed handle (an `Arc` refcount bump sharing the EXISTING
    /// ledger — no new ledger), RELEASES the guard, and moves that handle into the
    /// [`ReserveWorkspaceOwner`](crate::signing_journal_admission::ReserveWorkspaceOwner)
    /// admission mechanism. That owner reserves BOTH coverages (working-set first,
    /// then continuation) BEFORE constructing the workspace and rolls the first
    /// back if the second refuses, so a capacity refusal builds no workspace and
    /// leaves both ledgers unchanged.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn admit_reserve_workspace(
        &self,
    ) -> Result<crate::signing_journal_admission::AdmittedReserveWorkspace, WorkspaceAdmissionError>
    {
        let accountant = {
            let inner = self
                .domain
                .inner
                .lock()
                .map_err(|_| WorkspaceAdmissionError::Lock)?;
            match inner.admission.as_ref() {
                None => return Err(WorkspaceAdmissionError::NoAssociation),
                Some(a) => a.clone(),
            }
            // Domain guard released here, before any reservation is attempted.
        };
        crate::signing_journal_admission::ReserveWorkspaceOwner::from_installed(accountant)
            .admit()
            .map_err(map_admission_error)
    }

    /// RUN 422 — the additive, isolated ADMITTED fresh-reservation route. It
    /// consumes the admitted workspace BY VALUE and acquires the ownership domain
    /// ONCE. Prerequisites are checked fail-closed BEFORE any storage access, in
    /// order: established journal, bounded live mode, installed accountant, and
    /// BOTH workspace coverages issued by that accountant (else `ForeignWorkspace`).
    /// It never auto-installs an association, auto-transitions into bounded mode, or
    /// falls back to the legacy allocating route.
    ///
    /// If journal accounting is uncertain it refuses conservatively
    /// (`AccountingUncertain`) with ZERO side effects and NO fresh continuation; it
    /// never implicitly runs legacy reconciliation. Otherwise it classifies the
    /// position with a single bounded, NON-delivering read (no retained signature is
    /// ever read, acknowledged, or returned here — retained delivery stays with the
    /// separate checked retrieval path):
    ///
    /// * conflicting binding → `Conflict`;
    /// * durable `Reserved` → `ReservedPotentiallySigned`;
    /// * `Signed` with a live, result-unacknowledged operation →
    ///   `LiveUnacknowledgedPotentiallySigned`;
    /// * `Signed` otherwise → `SignedRetainableElsewhere`.
    ///
    /// On a fresh (record-absent) position it settles the durable limit and bounded
    /// slot availability, frames the reserved record and advanced metadata into the
    /// workspace, and publishes them together through the EXISTING atomic
    /// envelope-pair storage primitive. A failed/uncertain write latches accounting
    /// uncertain (recording the tracked attempt), advances no counter, and returns
    /// no continuation — subsequent admitted calls stay blocked. Only after the
    /// durable acknowledgement does it commit the accounting, install the live
    /// entry, END the domain-guard scope, and move the continuation coverage
    /// directly out of the workspace into the returned covered continuation.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn reserve_for_sign_admitted(
        &self,
        position: &SigningPosition,
        binding: &BindingDigest,
        mut ws: crate::signing_journal_admission::AdmittedReserveWorkspace,
    ) -> Result<AdmittedReservationOutcome, AdmittedReserveError> {
        use crate::signing_journal_admission::BorrowedRecordView;

        let mut inner = self
            .domain
            .inner
            .lock()
            .map_err(|_| AdmittedReserveError::Lock)?;

        // (1) Established journal (one journal-wide position limit).
        let limit = inner
            .established
            .ok_or(AdmittedReserveError::NotEstablished)?
            .max_reserved_positions;

        // (2) Bounded live mode required; never auto-transition.
        if inner.live.bounded_capacity().is_none() {
            return Err(AdmittedReserveError::NotBoundedMode);
        }

        // (3) Installed accountant required; the supplied workspace's BOTH
        //     coverages must be issued by it. Checked BEFORE any storage access;
        //     never auto-install. The borrow ends with this scope.
        {
            let accountant = inner
                .admission
                .as_ref()
                .ok_or(AdmittedReserveError::NoAssociation)?;
            if !(ws.is_work_covered_by(accountant) && ws.is_cont_covered_by(accountant)) {
                return Err(AdmittedReserveError::ForeignWorkspace);
            }
        }

        // (4) Conservative uncertainty refusal: no reconciliation, no write, no
        //     fresh continuation.
        if inner.accounting_uncertain {
            return Ok(AdmittedReservationOutcome::AccountingUncertain);
        }

        // (5) Non-allocating key encode into the admitted key buffer.
        let klen = position
            .encode_key_into(ws.journal_key_buf())
            .map_err(|_| AdmittedReserveError::KeyInvalid)?;
        ws.set_jkey_len(klen);

        // (6) Bounded classification read with disjoint key/envelope borrows.
        let used = {
            let (jk, env) = ws.key_and_read_env();
            match self.store.read_signing_envelope_into(jk, env) {
                Ok(None) => None,
                Ok(Some(n)) => Some(n),
                Err(BoundedStorageError::CapacityExceeded { .. }) => {
                    return Ok(AdmittedReservationOutcome::WorkspaceCapacityExceeded);
                }
                Err(BoundedStorageError::Unsupported) => {
                    return Err(AdmittedReserveError::Unsupported);
                }
                Err(BoundedStorageError::Corruption(d)) | Err(BoundedStorageError::Io(d)) => {
                    return Err(AdmittedReserveError::Storage(d));
                }
            }
        };

        // (7) Existing-position classification (bounded, NON-delivering).
        if let Some(n) = used {
            ws.set_read_used(n)
                .map_err(|_| AdmittedReserveError::Storage(BoundedDiag::EnvelopeInvalid))?;
            let stage;
            let decoded_position;
            let decoded_binding;
            {
                let view = match BorrowedRecordView::parse(ws.read_envelope()) {
                    Ok(v) => v,
                    Err(_) => {
                        return Err(AdmittedReserveError::Storage(BoundedDiag::EnvelopeInvalid));
                    }
                };
                if view.magic != &RECORD_MAGIC[..]
                    || view.version != SIGNING_RECORD_FORMAT_VERSION
                {
                    return Err(AdmittedReserveError::Storage(BoundedDiag::DecodeInvalid));
                }
                let kind = match SigningKind::from_tag(view.kind_tag) {
                    Some(k) => k,
                    None => {
                        return Err(AdmittedReserveError::Storage(BoundedDiag::DecodeInvalid));
                    }
                };
                stage = match SigningRecordStage::from_tag(view.stage_tag) {
                    Some(st) => st,
                    None => {
                        return Err(AdmittedReserveError::Storage(BoundedDiag::DecodeInvalid));
                    }
                };
                let mut genesis = [0u8; 32];
                genesis.copy_from_slice(view.network_genesis);
                decoded_position = SigningPosition {
                    validator_id: view.validator_id,
                    network_genesis: genesis,
                    kind,
                    originating_view: view.originating_view,
                };
                let mut bind = [0u8; 32];
                bind.copy_from_slice(view.binding);
                decoded_binding = BindingDigest(bind);
            }
            // Position/key-derivation invariant: a record under this key for
            // another position is a storage/derivation fault — refuse fail-closed.
            if decoded_position != *position {
                return Err(AdmittedReserveError::Storage(BoundedDiag::DecodeInvalid));
            }
            if decoded_binding != *binding {
                return Ok(AdmittedReservationOutcome::Conflict);
            }
            return match stage {
                SigningRecordStage::Reserved => {
                    Ok(AdmittedReservationOutcome::ReservedPotentiallySigned)
                }
                SigningRecordStage::Signed => {
                    match inner.live.get(position).map(|ls| ls.result_acked) {
                        Some(false) => {
                            Ok(AdmittedReservationOutcome::LiveUnacknowledgedPotentiallySigned)
                        }
                        Some(true) | None => {
                            Ok(AdmittedReservationOutcome::SignedRetainableElsewhere)
                        }
                    }
                }
            };
        }

        // (8) Fresh path: settle the durable limit and bounded-slot availability
        //     BEFORE any durable write.
        if inner.reserved_positions >= limit {
            return Ok(AdmittedReservationOutcome::Exhausted);
        }
        if !inner.live.can_admit_fresh() {
            return Ok(AdmittedReservationOutcome::LiveCapacityExhausted);
        }
        let operation_id = inner.next_operation_id;
        let next_operation_id = operation_id
            .checked_add(1)
            .ok_or(AdmittedReserveError::Overflow)?;
        let new_reserved = inner
            .reserved_positions
            .checked_add(1)
            .ok_or(AdmittedReserveError::Overflow)?;

        // Frame the reserved record and advanced accounting metadata into the
        // admitted workspace (pre-framed, outer-CRC-prefixed), BEFORE any write.
        let record = SigningDecisionRecord::reserved(*position, *binding);
        let encoded = record
            .encode()
            .map_err(|_| AdmittedReserveError::Storage(BoundedDiag::EnvelopeInvalid))?;
        ws.set_framed_record(&encoded)
            .map_err(|_| AdmittedReserveError::Storage(BoundedDiag::EnvelopeInvalid))?;
        let metadata = SigningJournalMetadata::new(limit, new_reserved);
        let metadata_encoded = metadata.encode();
        ws.set_framed_metadata(&metadata_encoded)
            .map_err(|_| AdmittedReserveError::Storage(BoundedDiag::EnvelopeInvalid))?;

        // Atomic combined record+metadata synced write via the EXISTING
        // envelope-pair primitive. A failed/uncertain acknowledgement does NOT
        // prove nothing was stored: latch accounting uncertain and record the
        // tracked attempt; grant no continuation and do not advance the counter.
        match self.store.put_signing_envelope_and_metadata_synced(
            ws.journal_key(),
            ws.framed_record(),
            ws.framed_metadata(),
        ) {
            Ok(()) => {}
            Err(e) => {
                inner.accounting_uncertain = true;
                inner.uncertain_attempt = Some(UncertainAttempt {
                    prior_count: inner.reserved_positions,
                    attempted_count: new_reserved,
                });
                return Err(match e {
                    BoundedStorageError::CapacityExceeded { .. } => {
                        AdmittedReserveError::Storage(BoundedDiag::EnvelopeInvalid)
                    }
                    BoundedStorageError::Unsupported => AdmittedReserveError::Unsupported,
                    BoundedStorageError::Corruption(d) | BoundedStorageError::Io(d) => {
                        AdmittedReserveError::Storage(d)
                    }
                });
            }
        }

        // Only after the durable ack: commit accounting and install the live entry
        // (prechecked, allocation-free), then END the domain-guard scope before
        // transferring the continuation coverage.
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
        drop(inner);

        // Direct field move of the continuation coverage out of the workspace. The
        // remaining partially-moved workspace (buffers + work_res) drops
        // automatically in declaration order after this returns.
        Ok(AdmittedReservationOutcome::FreshlyReserved(AdmittedContinuation {
            inner: SigningContinuation {
                domain_token: self.domain.token,
                position: *position,
                binding: *binding,
                operation_id,
            },
            coverage: ws.cont_res,
        }))
    }

    /// RUN 422 — admitted continuation consumption. Acquires the ownership domain
    /// ONCE and routes the live-ownership transition through the shared
    /// [`consume_live_locked`] (foreign-domain token checked FIRST, then an exact
    /// un-invoked live match). On success it transfers the SAME continuation
    /// coverage through consumption into the returned publication capability
    /// WITHOUT release/recharge; on refusal nothing is mutated and the continuation
    /// (with its coverage) is returned to the caller by dropping here.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn consume_for_signing_admitted(
        &self,
        cont: AdmittedContinuation,
    ) -> Result<AdmittedPublicationCapability, AdmittedConsumeError> {
        let mut inner = self
            .domain
            .inner
            .lock()
            .map_err(|_| AdmittedConsumeError::LockPoisoned)?;
        consume_live_locked(
            &mut inner,
            self.domain.token,
            cont.inner.domain_token,
            &cont.inner.position,
            &cont.inner.binding,
            cont.inner.operation_id,
        )?;
        drop(inner);
        // Transfer the SAME coverage through consumption (no release/recharge).
        let AdmittedContinuation {
            inner: sc,
            coverage,
        } = cont;
        Ok(AdmittedPublicationCapability {
            inner: ResultPublicationCapability {
                domain_token: sc.domain_token,
                position: sc.position,
                binding: sc.binding,
                operation_id: sc.operation_id,
            },
            coverage,
        })
    }

    /// RUN 422 — admitted acknowledged-operation retirement. Delegates to the
    /// completed [`retire_acknowledged_operation`](Self::retire_acknowledged_operation)
    /// using the raw inner capability accessed ONLY inside this defining module.
    /// The wrapper's owned coverage is untouched (retirement reserves and releases
    /// nothing), so a still-held capability keeps covering its backing until it
    /// drops.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn retire_admitted(
        &self,
        cap: &AdmittedPublicationCapability,
    ) -> Result<RetirementOutcome, RetirementError> {
        self.retire_acknowledged_operation(&cap.inner)
    }

    /// Test-only: attach a handle over `store` WITHOUT establishing a limit, so
    /// the additive, read-only retained-retrieval path can be exercised against
    /// directly-written records. (The retrieval path takes no new reservation and
    /// does not require an established limit.)
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn attach_unestablished_for_test(store: Arc<dyn SigningJournalStorage>) -> Self {
        let domain = store.signing_ownership_domain();
        Self { store, domain }
    }

    /// Test-only: set/clear the domain's `accounting_uncertain` latch.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn set_accounting_uncertain_for_test(&self, v: bool) {
        let mut inner = self.domain.inner.lock().expect("domain lock");
        inner.accounting_uncertain = v;
    }

    /// Test-only: install a live entry for `position` with the chosen
    /// `result_acked`, modelling a live operation without running the full
    /// signing flow.
    /// Test-only: number of live entries currently tracked in this domain.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn live_len_for_test(&self) -> usize {
        self.domain.inner.lock().expect("domain lock").live.len()
    }

    /// Test-only: whether a live entry currently exists at `position`.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn live_contains_for_test(&self, position: &SigningPosition) -> bool {
        self.domain
            .inner
            .lock()
            .expect("domain lock")
            .live
            .contains_key(position)
    }

    /// Test-only: whether the domain is in bounded live mode.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn live_is_bounded_for_test(&self) -> bool {
        matches!(
            self.domain.inner.lock().expect("domain lock").live,
            LiveMode::Bounded(_)
        )
    }

    /// Test-only: the bounded container's fixed capacity `L` (`None` in legacy).
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn live_capacity_for_test(&self) -> Option<usize> {
        self.domain
            .inner
            .lock()
            .expect("domain lock")
            .live
            .bounded_capacity()
    }

    /// Test-only: the bounded container's `(Vec::len, Vec::capacity)` backing
    /// shape, so a test can assert no growth (`len == capacity == L`) after
    /// construction. `None` in legacy mode.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn live_backing_shape_for_test(&self) -> Option<(usize, usize)> {
        let inner = self.domain.inner.lock().expect("domain lock");
        match &inner.live {
            LiveMode::Bounded(c) => Some((c.slots.len(), c.slots.capacity())),
            LiveMode::Legacy(_) => None,
        }
    }

    /// Test-only: the standing container charge held by the bounded backing
    /// reservation (`None` in legacy mode).
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn live_backing_charge_for_test(&self) -> Option<u128> {
        let inner = self.domain.inner.lock().expect("domain lock");
        match &inner.live {
            LiveMode::Bounded(c) => Some(c._backing.charge()),
            LiveMode::Legacy(_) => None,
        }
    }

    /// Test-only: the legacy live map's allocated capacity (`None` in bounded
    /// mode), so a test can construct the empty-but-allocated precondition.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn legacy_live_capacity_for_test(&self) -> Option<usize> {
        let inner = self.domain.inner.lock().expect("domain lock");
        inner.live.legacy_len_capacity().map(|(_, cap)| cap)
    }

    /// Test-only: clear the legacy live map WITHOUT releasing its allocated
    /// capacity (`HashMap::clear` retains capacity), modelling an empty-but-
    /// allocated legacy map for the first-transition prerequisite test.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn clear_legacy_live_keep_capacity_for_test(&self) {
        let mut inner = self.domain.inner.lock().expect("domain lock");
        if let LiveMode::Legacy(m) = &mut inner.live {
            m.clear();
        }
    }

    /// Test-only: the domain's monotonic next-operation-id source. Retirement
    /// must never reset it.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn next_operation_id_for_test(&self) -> u64 {
        self.domain
            .inner
            .lock()
            .expect("domain lock")
            .next_operation_id
    }

    /// Test-only: the domain's in-memory durably-acknowledged reserved-position
    /// count, so a test can assert that a retained-retry (or a failed fresh
    /// write) does NOT increment the durable position count.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn reserved_positions_for_test(&self) -> u64 {
        self.domain
            .inner
            .lock()
            .expect("domain lock")
            .reserved_positions
    }

    /// Test-only: read the domain's `accounting_uncertain` latch.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn accounting_uncertain_for_test(&self) -> bool {
        self.domain
            .inner
            .lock()
            .expect("domain lock")
            .accounting_uncertain
    }

    /// Test-only: the tracked attempted update of the last uncertain reservation
    /// write as `(prior_count, attempted_count)`. Retirement must leave the
    /// COMPLETE uncertainty bookkeeping — this attempt AND `accounting_uncertain`
    /// — untouched, so a test compares both across the call.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn uncertain_attempt_for_test(&self) -> Option<(u64, u64)> {
        self.domain
            .inner
            .lock()
            .expect("domain lock")
            .uncertain_attempt
            .map(|a| (a.prior_count, a.attempted_count))
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn insert_live_for_test(
        &self,
        position: SigningPosition,
        binding: BindingDigest,
        result_acked: bool,
    ) {
        let mut inner = self.domain.inner.lock().expect("domain lock");
        let op = inner.next_operation_id;
        inner.next_operation_id = op.wrapping_add(1);
        inner.live.insert(
            position,
            LiveState {
                operation_id: op,
                binding,
                invoked: true,
                result_acked,
            },
        );
    }

    /// Test-only (DEFENSIVE fixture): force the `invoked` flag of an existing
    /// live entry at `position`. Genuine public control flow can never present a
    /// publication capability for an un-invoked operation (a capability is minted
    /// only by consuming the continuation, which sets `invoked`), so this exists
    /// solely to exercise the defensive `invoked == true` precondition. It adds no
    /// public capability constructor and no production mutation surface.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn set_live_invoked_for_test(&self, position: &SigningPosition, invoked: bool) {
        let mut inner = self.domain.inner.lock().expect("domain lock");
        if let Some(ls) = inner.live.get_mut(position) {
            ls.invoked = invoked;
        }
    }

    /// Run 422 D7-D10 Correction E — conservative accounting revalidation.
    ///
    /// If a prior atomic reservation/accounting write returned a failed or
    /// uncertain acknowledgement, the in-memory `reserved_positions` counter can
    /// no longer be trusted (a failed ack does not prove nothing was stored). This
    /// re-reads the durable metadata — the persisted source of truth — and
    /// resolves the failed batch's possible outcomes against the tracked attempted
    /// update before clearing the uncertainty. It refuses fail-closed (leaving the
    /// domain uncertain and unusable for new reservations) when:
    /// * the metadata is missing, unreadable, or corrupt;
    /// * the durable journal-wide limit differs from the established limit (the
    ///   limit cannot change silently);
    /// * the durable count regressed below the previously acknowledged obligations
    ///   or exceeded the attempted update (an unexpected count regression or
    ///   record/accounting mismatch).
    ///
    /// It performs NO repair write and never mints a reconstructed continuation
    /// from a surviving record; it is a local consistency check that resolves the
    /// two possible outcomes of one uncertain batch and does not, and cannot,
    /// detect an internally consistent whole-copy rollback. Runs under the domain
    /// lock.
    fn reconcile_accounting_if_uncertain(
        &self,
        inner: &mut DomainInner,
    ) -> Result<(), JournalError> {
        if !inner.accounting_uncertain {
            return Ok(());
        }
        // The established journal-wide limit is the fixed invariant. It is present
        // for any handle constructed via `initialize`/`open`.
        let established_limit = inner
            .established
            .ok_or(JournalError::NotInitialized)?
            .max_reserved_positions;
        // Read + decode the durable metadata. A missing, unreadable, or corrupt
        // metadata read leaves the uncertain flag SET (never cleared) so the domain
        // stays unusable for new reservations and the caller fails closed.
        let bytes = self.store.get_signing_metadata()?.ok_or_else(|| {
            JournalError::AccountingInconsistent(
                "initialization metadata missing during revalidation".to_string(),
            )
        })?;
        let metadata = SigningJournalMetadata::decode(&bytes)?;
        // The established journal-wide limit cannot change silently. A durable
        // metadata limit that differs from the established one is refused; the
        // domain stays uncertain and unusable.
        if metadata.max_reserved_positions != established_limit {
            return Err(JournalError::AccountingInconsistent(format!(
                "durable limit {} differs from established limit {} during revalidation",
                metadata.max_reserved_positions, established_limit
            )));
        }
        // Resolve the failed batch's possible outcomes against the tracked
        // attempted update. The durable count may reflect that the write did NOT
        // land (still `prior_count`) or DID land (exactly `attempted_count`). It
        // must never regress below the previously acknowledged obligations, nor
        // exceed the attempted update.
        match inner.uncertain_attempt {
            Some(attempt) => {
                if metadata.reserved_positions < attempt.prior_count {
                    return Err(JournalError::AccountingInconsistent(format!(
                        "durable count {} regressed below acknowledged {} during revalidation",
                        metadata.reserved_positions, attempt.prior_count
                    )));
                }
                if metadata.reserved_positions > attempt.attempted_count {
                    return Err(JournalError::AccountingInconsistent(format!(
                        "durable count {} exceeds attempted {} during revalidation",
                        metadata.reserved_positions, attempt.attempted_count
                    )));
                }
            }
            None => {
                // Uncertainty without a tracked reservation attempt: the durable
                // count must at least not regress below the last known in-memory
                // count.
                if metadata.reserved_positions < inner.reserved_positions {
                    return Err(JournalError::AccountingInconsistent(format!(
                        "durable count {} regressed below in-memory {} during revalidation",
                        metadata.reserved_positions, inner.reserved_positions
                    )));
                }
            }
        }
        // Only a fully consistent durable observation clears the uncertainty.
        inner.reserved_positions = metadata.reserved_positions;
        inner.accounting_uncertain = false;
        inner.uncertain_attempt = None;
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
        // Route the shared live-ownership transition through `consume_live_locked`
        // and map its fixed codes back onto the UNCHANGED legacy `JournalError`
        // strings, so the public behavior (including the exact diagnostic text) is
        // preserved while the admitted route shares the identical check.
        match consume_live_locked(
            &mut inner,
            self.domain.token,
            continuation.domain_token,
            &continuation.position,
            &continuation.binding,
            continuation.operation_id,
        ) {
            Ok(()) => Ok(ResultPublicationCapability {
                domain_token: continuation.domain_token,
                position: continuation.position,
                binding: continuation.binding,
                operation_id: continuation.operation_id,
            }),
            Err(AdmittedConsumeError::LockPoisoned) => Err(JournalError::LockPoisoned),
            Err(AdmittedConsumeError::ForeignDomain) => Err(JournalError::InvalidResultPublication(
                "signing continuation belongs to a foreign ownership domain".to_string(),
            )),
            Err(AdmittedConsumeError::NoFreshLiveOp) => Err(JournalError::InvalidResultPublication(
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
        /// When set, ONLY `for_each_signing_namespace_entry` fails (before yielding
        /// any entry), while metadata/record point reads still succeed. Lets a test
        /// exercise iterator/scan-error propagation distinctly from a metadata read
        /// failure. Clearly-labelled TEST fault injector.
        fail_scan: RwLock<bool>,
        /// Counts how many namespace entries this backend yielded to a visitor in
        /// `for_each_signing_namespace_entry`. Lets a test observe that the journal
        /// aborted the scan EARLY (before the whole namespace was streamed).
        visits: std::sync::atomic::AtomicUsize,
        /// Run 422 D7-D10 Correction A — counts successful AND store-then-error
        /// `put_signing_record_synced` calls (the recovery durability op reissued
        /// by `acknowledge_recovered_signed`). Lets a test observe that revisiting
        /// an EVICTED recovered position reissues one additional synced write while
        /// an exact cache hit reissues none. Test-only instrumentation.
        record_writes: std::sync::atomic::AtomicUsize,
        /// RUN 422 finishing — comprehensive journal-storage call counters that
        /// establish the retirement no-I/O boundary with an EXECUTED zero-delta
        /// window immediately around `retire_acknowledged_operation`, kept
        /// distinct from source inspection of the method. `reads` counts every
        /// record/metadata/namespace read; `writes` counts every
        /// record/metadata/envelope write entrypoint; `reissues` counts the
        /// (structurally-unsupported-here) envelope read/reissue entrypoints so
        /// the three storage categories are observed SEPARATELY. Test-only.
        reads: std::sync::atomic::AtomicUsize,
        writes: std::sync::atomic::AtomicUsize,
        reissues: std::sync::atomic::AtomicUsize,
        /// Run 422 D7-D10 Correction A — optional test-only recovered-ack cache
        /// capacity. When `Some(n)`, the per-instance ownership domain is built
        /// with a cache bounded to `n` entries via the private test constructor so
        /// eviction can be forced through the real journal flow. `None` uses the
        /// production bound. NOT a production configuration surface.
        cache_cap: RwLock<Option<usize>>,
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
                fail_scan: RwLock::new(false),
                visits: std::sync::atomic::AtomicUsize::new(0),
                record_writes: std::sync::atomic::AtomicUsize::new(0),
                reads: std::sync::atomic::AtomicUsize::new(0),
                writes: std::sync::atomic::AtomicUsize::new(0),
                reissues: std::sync::atomic::AtomicUsize::new(0),
                // The modelled restart preserves the test-only cache bound so a
                // recovery/eviction sequence spanning a reopen keeps a small cache.
                cache_cap: RwLock::new(*self.cache_cap.read().unwrap()),
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
        fn set_fail_scan(&self, v: bool) {
            *self.fail_scan.write().unwrap() = v;
        }
        /// Namespace entries yielded to a visitor since the last `reset_visits`.
        fn visits(&self) -> usize {
            self.visits.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn reset_visits(&self) {
            self.visits.store(0, std::sync::atomic::Ordering::SeqCst);
        }
        /// Successful/store-then-error `put_signing_record_synced` calls so far.
        fn record_writes(&self) -> usize {
            self.record_writes.load(std::sync::atomic::Ordering::SeqCst)
        }
        /// RUN 422 finishing — the comprehensive `(reads, writes, reissues)`
        /// storage-call totals so far, observed SEPARATELY so a test can assert a
        /// zero delta across `retire_acknowledged_operation`.
        fn storage_calls(&self) -> (usize, usize, usize) {
            use std::sync::atomic::Ordering::SeqCst;
            (
                self.reads.load(SeqCst),
                self.writes.load(SeqCst),
                self.reissues.load(SeqCst),
            )
        }
        /// Bound the per-instance ownership domain's recovered-ack cache to `cap`
        /// entries (test-only). MUST be called before the domain is first accessed
        /// (before `initialize`/`open`), since the domain is created once per
        /// instance via `signing_ownership_domain`.
        fn set_cache_capacity_for_test(&self, cap: usize) {
            *self.cache_cap.write().unwrap() = Some(cap);
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
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if *self.fail_reads.read().unwrap() {
                return Err(StorageError::Io("injected read failure".to_string()));
            }
            // Bounded direct read: raw record (no envelope), bound = MAX_RECORD_LEN;
            // checked BEFORE cloning the stored value.
            let m = self.map.read().unwrap();
            match m.get(key) {
                None => Ok(None),
                Some(v) => {
                    if v.len() > MAX_RECORD_LEN {
                        return Err(StorageError::Corruption(format!(
                            "signing_record: stored value exceeds bound (len={} max={})",
                            v.len(),
                            MAX_RECORD_LEN
                        )));
                    }
                    Ok(Some(v.clone()))
                }
            }
        }
        fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if *self.fail_writes.read().unwrap() {
                return Err(StorageError::Io("injected write failure".to_string()));
            }
            if *self.store_then_error.read().unwrap() {
                // The bytes become readable, but the durability acknowledgement
                // is reported uncertain (error). A correct journal must NOT treat
                // the later readable bytes as an acknowledged barrier.
                self.record_writes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.map.write().unwrap().insert(key.to_vec(), value.to_vec());
                return Err(StorageError::Io("injected post-store sync failure".to_string()));
            }
            self.record_writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.map.write().unwrap().insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if *self.fail_reads.read().unwrap() {
                return Err(StorageError::Io("injected read failure".to_string()));
            }
            // Bounded direct read: raw fixed-length metadata (no envelope),
            // bound = METADATA_ENCODED_LEN; checked BEFORE cloning.
            let m = self.map.read().unwrap();
            match m.get(MODEL_META_KEY) {
                None => Ok(None),
                Some(v) => {
                    if v.len() > METADATA_ENCODED_LEN {
                        return Err(StorageError::Corruption(format!(
                            "signing_metadata: stored value exceeds bound (len={} max={})",
                            v.len(),
                            METADATA_ENCODED_LEN
                        )));
                    }
                    Ok(Some(v.clone()))
                }
            }
        }
        fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
        fn for_each_signing_namespace_entry(
            &self,
            visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
        ) -> Result<(), StorageError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if *self.fail_reads.read().unwrap() {
                return Err(StorageError::Io("injected read failure".to_string()));
            }
            if *self.fail_scan.read().unwrap() {
                return Err(StorageError::Io("injected scan/iterator failure".to_string()));
            }
            let m = self.map.read().unwrap();
            // Whole-namespace streaming: visit EVERY entry except the backend-owned
            // metadata key. We stream directly over the map's entries and never
            // collect the namespace into a temporary vector (a per-entry value
            // length bound is applied before the caller decodes).
            for (k, v) in m.iter() {
                if k.as_slice() == MODEL_META_KEY {
                    continue;
                }
                if v.len() > MAX_RECORD_LEN {
                    return Err(StorageError::Corruption(format!(
                        "signing-namespace value exceeds bound (len={} max={})",
                        v.len(),
                        MAX_RECORD_LEN
                    )));
                }
                self.visits
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                visitor(k, v)?;
            }
            Ok(())
        }
        fn put_signing_envelope_and_metadata_synced(
            &self,
            record_key: &[u8],
            record_envelope: &[u8],
            metadata_envelope: &[u8],
        ) -> Result<(), BoundedStorageError> {
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            use crate::signing_journal_admission::OUTER_CRC_LEN;
            // Same fixed-framing preflight the durable/in-memory backends apply,
            // BEFORE any fault branch, model-owned copy, or map mutation.
            crate::storage::preflight_framed_envelope_pair(record_envelope, metadata_envelope)?;
            // Match the durable backend's journal-key length invariant.
            if record_key.len() != crate::signing_journal_admission::JOURNAL_KEY_LEN {
                return Err(BoundedStorageError::CapacityExceeded {
                    stored_len: record_key.len(),
                    capacity: crate::signing_journal_admission::JOURNAL_KEY_LEN,
                });
            }
            // Fail BEFORE any write: neither value is mutated, so both prior
            // values (if any) remain. Labelled TEST fault injector.
            if *self.fail_writes.read().unwrap() {
                return Err(BoundedStorageError::Io(BoundedDiag::WriteIo));
            }
            // MODEL format: records are stored record-ONLY and metadata raw, with
            // the outer checksum synthesized on read, so STRIP the already-present
            // outer CRC from each framed input. These `.to_vec()` values are
            // MODEL-OWNED copies of the stored values — NOT allocation-free.
            let record_body = record_envelope[OUTER_CRC_LEN..].to_vec();
            let metadata_body = metadata_envelope[OUTER_CRC_LEN..].to_vec();
            // store_then_error: BOTH values become readable under one lock, but the
            // durability acknowledgement is reported uncertain (error). The write
            // count is bumped so a test distinguishes “write-then-error” from
            // “failed-before-write” WITHOUT inferring it from the error itself.
            if *self.store_then_error.read().unwrap() {
                self.record_writes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut m = self.map.write().unwrap();
                m.insert(record_key.to_vec(), record_body);
                m.insert(MODEL_META_KEY.to_vec(), metadata_body);
                return Err(BoundedStorageError::Io(BoundedDiag::WriteIo));
            }
            // Acknowledged success: both inserts land under one lock acquisition.
            self.record_writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut m = self.map.write().unwrap();
            m.insert(record_key.to_vec(), record_body);
            m.insert(MODEL_META_KEY.to_vec(), metadata_body);
            Ok(())
        }
        fn read_signing_envelope_into(
            &self,
            _journal_key: &[u8],
            _dst: &mut [u8],
        ) -> Result<Option<usize>, BoundedStorageError> {
            // This model backend does not support envelope framing; the override
            // exists ONLY to count the envelope-read/reissue category separately so
            // the retirement no-I/O window observes reads, writes, AND reissues. It
            // preserves the trait default's Unsupported refusal (no behaviour change).
            self.reissues.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(BoundedStorageError::Unsupported)
        }
        fn reissue_signing_envelope_synced(
            &self,
            _journal_key: &[u8],
            _envelope: &[u8],
        ) -> Result<(), BoundedStorageError> {
            self.reissues.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(BoundedStorageError::Unsupported)
        }
        fn signing_ownership_domain(&self) -> Arc<SigningOwnershipDomain> {
            self.domain
                .get_or_init(|| match *self.cache_cap.read().unwrap() {
                    Some(cap) => SigningOwnershipDomain::new_with_cache_capacity_for_test(cap),
                    None => SigningOwnershipDomain::new(),
                })
                .clone()
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

    /// Test-fixture convenience (NOT production selection): initialize-or-open with
    /// the default limit for fixture setup.
    fn attach(store: Arc<ModelStore>) -> SigningReservationJournal {
        attach_with_budget(store, DEFAULT_MAX_RESERVED_POSITIONS)
    }

    /// Run 422 D7-D10 Correction E (Section 3): the MODEL store's direct record
    /// read refuses an oversized stored value BEFORE cloning it. The raw value is
    /// injected via `overwrite` (bypassing the journal) to exceed `MAX_RECORD_LEN`.
    #[test]
    fn model_store_record_direct_read_refuses_oversized_before_clone() {
        let store = Arc::new(ModelStore::default());
        let key = b"sj:v1:model-pos".to_vec();
        // Genuine absence stays None.
        assert!(store.get_signing_record(&key).expect("read").is_none());
        // At-limit round-trips.
        store.overwrite(&key, vec![0u8; MAX_RECORD_LEN]);
        assert_eq!(
            store
                .get_signing_record(&key)
                .expect("read")
                .expect("present")
                .len(),
            MAX_RECORD_LEN
        );
        // Oversized is refused before the clone.
        store.overwrite(&key, vec![0u8; MAX_RECORD_LEN + 1]);
        assert!(matches!(
            store.get_signing_record(&key),
            Err(StorageError::Corruption(_))
        ));
    }

    /// Correction E (Section 3): the MODEL store's direct metadata read refuses an
    /// oversized stored value BEFORE cloning (bound `METADATA_ENCODED_LEN`).
    #[test]
    fn model_store_metadata_direct_read_refuses_oversized_before_clone() {
        let store = Arc::new(ModelStore::default());
        assert!(store.get_signing_metadata().expect("read").is_none());
        store.overwrite(MODEL_META_KEY, vec![0u8; METADATA_ENCODED_LEN]);
        assert_eq!(
            store
                .get_signing_metadata()
                .expect("read")
                .expect("present")
                .len(),
            METADATA_ENCODED_LEN
        );
        store.overwrite(MODEL_META_KEY, vec![0u8; METADATA_ENCODED_LEN + 1]);
        assert!(matches!(
            store.get_signing_metadata(),
            Err(StorageError::Corruption(_))
        ));
    }

    /// Run 422 §7.2 — wrap a body in the outer storage checksum envelope the
    /// combined write accepts (the MODEL store strips it again before storing).
    fn outer_frame(body: &[u8]) -> Vec<u8> {
        use crate::signing_journal_admission::OUTER_CRC_LEN;
        let mut env = Vec::with_capacity(OUTER_CRC_LEN + body.len());
        env.extend_from_slice(&crate::storage::signing_journal_crc32(body).to_be_bytes());
        env.extend_from_slice(body);
        env
    }

    /// Run 422 §7.2 item 4: the combined bounded write FAILS BEFORE any write
    /// under the `fail_writes` fault fixture — both previously-stored values
    /// remain and the write counter does not advance. (Labelled TEST fixture.)
    #[test]
    fn put_signing_envelope_and_metadata_synced_model_fails_before_write() {
        let store = Arc::new(ModelStore::default());
        let p = position(SigningKind::Proposal, 41);
        let b = binding(b"item4");
        let (key, record_body) = reserved_kv(&p, &b);
        let metadata_body = SigningJournalMetadata::new(DEFAULT_MAX_RESERVED_POSITIONS, 1).encode();
        // Seed distinct OLD values the refused write must not disturb.
        let old_record = vec![0x11u8; record_body.len()];
        let old_meta = vec![0x22u8; metadata_body.len()];
        store.overwrite(&key, old_record.clone());
        store.overwrite(MODEL_META_KEY, old_meta.clone());
        let writes_before = store.record_writes();
        store.set_fail_writes(true);
        let r = store.put_signing_envelope_and_metadata_synced(
            &key,
            &outer_frame(&record_body),
            &outer_frame(&metadata_body),
        );
        assert!(matches!(r, Err(BoundedStorageError::Io(BoundedDiag::WriteIo))));
        // Both OLD values remain; nothing was written.
        assert_eq!(store.get_signing_record(&key).unwrap().unwrap(), old_record);
        assert_eq!(store.get_signing_metadata().unwrap().unwrap(), old_meta);
        assert_eq!(store.record_writes(), writes_before, "no write occurred");
    }

    /// Run 422 §7.2 item 5: under the `store_then_error` fault fixture BOTH new
    /// values become readable although the result is an error. This is
    /// distinguished from fail-before-write by the RECORDED write count, NOT by
    /// assuming an error means no write. (Labelled TEST fixture.)
    #[test]
    fn put_signing_envelope_and_metadata_synced_model_write_then_error() {
        let store = Arc::new(ModelStore::default());
        let p = position(SigningKind::Proposal, 42);
        let b = binding(b"item5");
        let (key, record_body) = reserved_kv(&p, &b);
        let metadata_body = SigningJournalMetadata::new(DEFAULT_MAX_RESERVED_POSITIONS, 1).encode();
        let writes_before = store.record_writes();
        store.set_store_then_error(true);
        let r = store.put_signing_envelope_and_metadata_synced(
            &key,
            &outer_frame(&record_body),
            &outer_frame(&metadata_body),
        );
        assert!(matches!(r, Err(BoundedStorageError::Io(BoundedDiag::WriteIo))));
        // Despite the error, BOTH NEW (outer-CRC-stripped) bodies are readable.
        assert_eq!(store.get_signing_record(&key).unwrap().unwrap(), record_body);
        assert_eq!(store.get_signing_metadata().unwrap().unwrap(), metadata_body);
        // The recorded write count proves a write WAS attempted (write-then-error),
        // which a correct journal must NOT treat as an acknowledged barrier.
        assert_eq!(store.record_writes(), writes_before + 1);
    }

    /// Test-fixture setup (NOT a mirror of production selection): an empty,
    /// un-initialized namespace is explicitly initialized with `limit`; an already-
    /// established one is opened and validated. BOTH routes validate — this is not
    /// an unchecked bypass, just a fixture selector for pre-existing A–D tests.
    /// Production journal initialization remains unwired. Correction-E tests call
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

    /// Build the raw (key, value) bytes for a valid `Reserved` record at `pos`.
    fn reserved_kv(pos: &SigningPosition, b: &BindingDigest) -> (Vec<u8>, Vec<u8>) {
        (
            pos.storage_key(),
            SigningDecisionRecord::reserved(*pos, *b).encode().unwrap(),
        )
    }

    // -----------------------------------------------------------------------
    // Run 422 D7-D10 Correction A (Section 4): recovered-acknowledgement FIFO
    // cache CONTAINER tests, exercised directly against the in-memory
    // `RecoveredAckCache` with small colocated fixtures. These cover only the
    // container's structural guarantees (bound, FIFO order, exact-record binding,
    // zero-capacity decline). They operate purely on process-local memory and do
    // NOT exercise any storage durability barrier, journal lookup, synced write,
    // signer, or facade handoff. The full post-eviction flow THROUGH the journal
    // (an evicted position reissuing the synced durability write on revisit, an
    // exact cache hit avoiding it) is covered by the journal-level tests below;
    // the handler-level signer/handoff suppression is covered by the colocated
    // D10 `binary_consensus_loop` tests.
    // -----------------------------------------------------------------------

    /// The entry limit holds under pressure: inserting far more than `max_entries`
    /// distinct positions never grows the cache beyond the bound, and each
    /// over-capacity insert evicts exactly one oldest process-local entry (FIFO).
    #[test]
    fn recovered_ack_cache_entry_limit_holds_under_pressure() {
        const CAP: usize = 4;
        let mut cache = RecoveredAckCache::new(CAP);
        let mut evictions = 0usize;
        for v in 0..(CAP as u64 * 3) {
            let p = position(SigningKind::Proposal, v);
            let rec = SigningDecisionRecord::reserved(p, binding(&v.to_be_bytes()));
            if cache.insert(p, rec).is_some() {
                evictions += 1;
            }
            assert!(cache.len() <= CAP, "cache must never exceed its bound");
        }
        assert_eq!(cache.len(), CAP, "cache fills to exactly its bound");
        // Every insert beyond the first CAP evicted exactly one entry.
        assert_eq!(evictions, CAP * 2);
        // FIFO: the oldest positions (views 0..2*CAP) are gone; the newest remain.
        for v in 0..(CAP as u64 * 2) {
            assert!(cache.get(&position(SigningKind::Proposal, v)).is_none());
        }
        for v in (CAP as u64 * 2)..(CAP as u64 * 3) {
            assert!(cache.get(&position(SigningKind::Proposal, v)).is_some());
        }
    }

    /// A cache hit returns the EXACT identical record bound to that position; a
    /// different position is a miss (never a cross-position substitution).
    #[test]
    fn recovered_ack_cache_hit_is_bound_to_identical_record() {
        let mut cache = RecoveredAckCache::new(8);
        let p = position(SigningKind::Vote, 9);
        let b = binding(b"exact");
        let sig = vec![0xAB, 0xCD, 0xEF];
        cache.insert(p, SigningDecisionRecord::signed(p, b, sig.clone()));
        let got = cache.get(&p).expect("hit");
        assert_eq!(got.stage, SigningRecordStage::Signed);
        assert_eq!(got.retained_signature.as_deref(), Some(sig.as_slice()));
        assert_eq!(got.binding, b);
        // Different position ⇒ miss.
        assert!(cache.get(&position(SigningKind::Vote, 10)).is_none());
    }

    /// Re-inserting an already-cached position updates in place without growth and
    /// without evicting another entry (idempotent re-acknowledgement).
    #[test]
    fn recovered_ack_cache_reinsert_same_position_does_not_grow_or_evict() {
        let mut cache = RecoveredAckCache::new(2);
        let p0 = position(SigningKind::Proposal, 0);
        let p1 = position(SigningKind::Proposal, 1);
        cache.insert(p0, SigningDecisionRecord::reserved(p0, binding(b"0")));
        cache.insert(p1, SigningDecisionRecord::reserved(p1, binding(b"1")));
        assert_eq!(cache.len(), 2);
        // Re-ack p0: no growth, no eviction, p1 still present.
        let evicted = cache.insert(p0, SigningDecisionRecord::reserved(p0, binding(b"0b")));
        assert!(evicted.is_none(), "re-insert must not evict");
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&p1).is_some(), "re-ack must not evict a peer");
    }

    /// Revisiting an evicted position re-inserts it into the in-memory container;
    /// eviction only dropped process-local state. (Container-level only: this does
    /// not reissue any storage durability barrier — that is asserted by the
    /// journal-level post-eviction tests.)
    #[test]
    fn recovered_ack_cache_revisit_after_eviction_reinserts() {
        let mut cache = RecoveredAckCache::new(1);
        let p0 = position(SigningKind::Proposal, 0);
        let p1 = position(SigningKind::Proposal, 1);
        cache.insert(p0, SigningDecisionRecord::reserved(p0, binding(b"0")));
        // Inserting p1 evicts p0 (the oldest process-local entry).
        assert_eq!(
            cache.insert(p1, SigningDecisionRecord::reserved(p1, binding(b"1"))),
            Some(p0)
        );
        assert!(cache.get(&p0).is_none());
        // Revisit p0: re-inserting succeeds (evicting p1 in turn).
        assert_eq!(
            cache.insert(p0, SigningDecisionRecord::reserved(p0, binding(b"0"))),
            Some(p1)
        );
        assert!(cache.get(&p0).is_some());
    }

    /// A zero-capacity container declines to cache: a later lookup is always a
    /// miss. (Container-level only — it asserts the decline, not that any durable
    /// record or storage barrier was involved.)
    #[test]
    fn recovered_ack_cache_zero_capacity_declines_to_cache() {
        let mut cache = RecoveredAckCache::new(0);
        let p = position(SigningKind::Proposal, 3);
        assert!(cache
            .insert(p, SigningDecisionRecord::reserved(p, binding(b"x")))
            .is_none());
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&p).is_none());
    }

    /// Craft metadata bytes with an arbitrary format version and a valid checksum
    /// (so the decoder reaches the version check rather than a CRC mismatch).
    fn metadata_bytes_with_version(version: u16, max: u64, count: u64) -> Vec<u8> {
        let mut body = Vec::with_capacity(METADATA_ENCODED_LEN);
        body.extend_from_slice(&METADATA_MAGIC);
        body.extend_from_slice(&version.to_be_bytes());
        body.extend_from_slice(&max.to_be_bytes());
        body.extend_from_slice(&count.to_be_bytes());
        let crc = signing_journal_crc32(&body);
        body.extend_from_slice(&crc.to_be_bytes());
        body
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
    // Run 422 D7-D10 Correction E — conservative uncertain-write reconciliation:
    // the established limit cannot change silently, the count cannot regress, and
    // an unreadable/corrupt metadata read leaves the domain uncertain.
    // ------------------------------------------------------------------

    #[test]
    fn reconcile_refuses_unexpected_limit_change() {
        let store = Arc::new(ModelStore::default());
        let journal =
            SigningReservationJournal::initialize(store.clone(), 8).expect("initialize");

        // Force the atomic reservation/accounting write to be uncertain: the bytes
        // (record + metadata new(8,1)) become readable but the ack is an error.
        store.set_store_then_error(true);
        let pos1 = position(SigningKind::Proposal, 1);
        let b = binding(b"m1");
        assert!(matches!(
            journal.reserve_for_sign(&pos1, &b),
            Err(JournalError::Storage(_))
        ));
        store.set_store_then_error(false);

        // Simulate the established journal-wide limit changing silently underneath
        // the handle (a limit that differs from the established one).
        store.overwrite(MODEL_META_KEY, SigningJournalMetadata::new(9, 1).encode());

        // The next admission reconciles first and must refuse — the limit cannot
        // change silently — leaving the domain unusable for new reservations.
        let pos2 = position(SigningKind::Proposal, 2);
        assert!(matches!(
            journal.reserve_for_sign(&pos2, &b),
            Err(JournalError::AccountingInconsistent(_))
        ));
        // Still uncertain: a further admission also refuses.
        assert!(matches!(
            journal.reserve_for_sign(&pos2, &b),
            Err(JournalError::AccountingInconsistent(_))
        ));
    }

    #[test]
    fn reconcile_refuses_count_regression() {
        let store = Arc::new(ModelStore::default());
        let journal =
            SigningReservationJournal::initialize(store.clone(), 8).expect("initialize");
        let b = binding(b"m");

        // A first successful reservation acknowledges count = 1.
        let pos1 = position(SigningKind::Proposal, 1);
        let _cap1 = reserve_and_invoke(&journal, &pos1, &b);

        // A second reservation is uncertain: durable metadata becomes new(8,2),
        // tracked attempt is {prior:1, attempted:2}.
        store.set_store_then_error(true);
        let pos2 = position(SigningKind::Proposal, 2);
        assert!(matches!(
            journal.reserve_for_sign(&pos2, &b),
            Err(JournalError::Storage(_))
        ));
        store.set_store_then_error(false);

        // The durable count regresses below the previously acknowledged obligation
        // (1). Reconciliation must refuse rather than adopt a regressed count.
        store.overwrite(MODEL_META_KEY, SigningJournalMetadata::new(8, 0).encode());
        let pos3 = position(SigningKind::Proposal, 3);
        assert!(matches!(
            journal.reserve_for_sign(&pos3, &b),
            Err(JournalError::AccountingInconsistent(_))
        ));
    }

    #[test]
    fn reconcile_refuses_count_above_attempt() {
        let store = Arc::new(ModelStore::default());
        let journal =
            SigningReservationJournal::initialize(store.clone(), 8).expect("initialize");
        let b = binding(b"m");

        // One uncertain reservation: attempt {prior:0, attempted:1}.
        store.set_store_then_error(true);
        let pos1 = position(SigningKind::Proposal, 1);
        assert!(matches!(
            journal.reserve_for_sign(&pos1, &b),
            Err(JournalError::Storage(_))
        ));
        store.set_store_then_error(false);

        // A durable count that EXCEEDS the attempted update cannot be explained by
        // this handle's single failed batch — refuse rather than adopt it.
        store.overwrite(MODEL_META_KEY, SigningJournalMetadata::new(8, 5).encode());
        let pos2 = position(SigningKind::Proposal, 2);
        assert!(matches!(
            journal.reserve_for_sign(&pos2, &b),
            Err(JournalError::AccountingInconsistent(_))
        ));
    }

    #[test]
    fn reconcile_metadata_read_failure_leaves_domain_uncertain() {
        let store = Arc::new(ModelStore::default());
        let journal =
            SigningReservationJournal::initialize(store.clone(), 8).expect("initialize");
        let b = binding(b"m");

        // Make the atomic write uncertain to enter the uncertain state.
        store.set_store_then_error(true);
        let pos1 = position(SigningKind::Proposal, 1);
        assert!(matches!(
            journal.reserve_for_sign(&pos1, &b),
            Err(JournalError::Storage(_))
        ));
        store.set_store_then_error(false);

        // An unreadable metadata read during reconciliation must leave the domain
        // uncertain (never cleared) and fail closed.
        store.set_fail_reads(true);
        let pos2 = position(SigningKind::Proposal, 2);
        assert!(matches!(
            journal.reserve_for_sign(&pos2, &b),
            Err(JournalError::Storage(_))
        ));

        // Once reads recover AND the durable metadata is a consistent outcome of
        // the failed batch (count is prior or attempted, limit unchanged),
        // reconciliation clears the uncertainty and admission resumes.
        store.set_fail_reads(false);
        // Durable metadata from store_then_error is new(8,1) == attempted; a fresh
        // position now admits.
        let pos3 = position(SigningKind::Proposal, 3);
        assert!(matches!(
            journal.reserve_for_sign(&pos3, &b).unwrap(),
            ReservationOutcome::FreshlyReserved(_)
        ));
    }

    // ------------------------------------------------------------------
    // Run 422 D7-D10 Correction E §4/§5 — whole-signing-namespace
    // validation and bounded streaming scan. `open` classifies EVERY
    // signing-namespace entry (only the exact metadata key is treated as
    // metadata), refuses unknown/malformed/unsupported entries, and stops
    // as soon as a single violation is observed.
    // ------------------------------------------------------------------

    #[test]
    fn open_refuses_unsupported_decision_key_version() {
        // Valid metadata (zero records) plus one entry under an unsupported
        // decision-key version `sj:v2:…`. It is neither the metadata key nor a
        // supported `sj:v1:` record ⇒ refused as an unexpected namespace entry,
        // before any decode of its value.
        let store = Arc::new(ModelStore::default());
        store.overwrite(MODEL_META_KEY, SigningJournalMetadata::new(8, 0).encode());
        store.overwrite(b"sj:v2:some-future-record", vec![0u8; 16]);
        assert!(matches!(
            SigningReservationJournal::open(store.clone()),
            Err(JournalError::UnexpectedNamespaceEntry(_))
        ));
    }

    #[test]
    fn open_refuses_unknown_metadata_version() {
        // A metadata record with a valid checksum but an unsupported format
        // version is refused (never treated as uninitialized).
        let store = Arc::new(ModelStore::default());
        store.overwrite(MODEL_META_KEY, metadata_bytes_with_version(0xBEEF, 8, 0));
        assert!(matches!(
            SigningReservationJournal::open(store.clone()),
            Err(JournalError::UnsupportedMetadataVersion(0xBEEF))
        ));
    }

    #[test]
    fn open_refuses_unknown_metadata_key_in_namespace() {
        // Valid metadata plus a stray non-record, non-metadata key inside the
        // signing namespace (e.g. a foreign metadata-looking key) is refused.
        let store = Arc::new(ModelStore::default());
        store.overwrite(MODEL_META_KEY, SigningJournalMetadata::new(8, 0).encode());
        store.overwrite(b"meta:v2:foreign", vec![1u8; 8]);
        assert!(matches!(
            SigningReservationJournal::open(store.clone()),
            Err(JournalError::UnexpectedNamespaceEntry(_))
        ));
    }

    #[test]
    fn open_refuses_malformed_signing_key() {
        // A key carrying the supported prefix but a malformed (short/garbage)
        // remainder, holding a validly-encoded record for a DIFFERENT canonical
        // position, is refused: the stored key must equal the record's own
        // canonical position key.
        let store = Arc::new(ModelStore::default());
        store.overwrite(MODEL_META_KEY, SigningJournalMetadata::new(8, 1).encode());
        let pos = position(SigningKind::Proposal, 1);
        let b = binding(b"x");
        let value = SigningDecisionRecord::reserved(pos, b).encode().unwrap();
        // Deliberately malformed key: prefix present, remainder truncated.
        store.overwrite(b"sj:v1:short", value);
        assert!(matches!(
            SigningReservationJournal::open(store.clone()),
            Err(JournalError::AccountingInconsistent(_))
        ));
    }

    #[test]
    fn open_refuses_key_record_position_mismatch() {
        // A valid record VALUE stored under another position's canonical key ⇒
        // key/record association fails ⇒ refuse.
        let store = Arc::new(ModelStore::default());
        store.overwrite(MODEL_META_KEY, SigningJournalMetadata::new(8, 1).encode());
        let real = position(SigningKind::Proposal, 1);
        let other = position(SigningKind::Vote, 2);
        let b = binding(b"x");
        let value = SigningDecisionRecord::reserved(real, b).encode().unwrap();
        store.overwrite(&other.storage_key(), value);
        assert!(matches!(
            SigningReservationJournal::open(store.clone()),
            Err(JournalError::AccountingInconsistent(_))
        ));
    }

    #[test]
    fn open_refuses_valid_metadata_plus_unexpected_namespace_entry() {
        // One genuine record consistent with metadata, PLUS an unexpected foreign
        // entry in the namespace ⇒ refuse (the extra entry is classified and
        // rejected even though the accounting count would otherwise match).
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Proposal, 1);
        let b = binding(b"x");
        let (k, v) = reserved_kv(&pos, &b);
        store.overwrite(&k, v);
        store.overwrite(MODEL_META_KEY, SigningJournalMetadata::new(8, 1).encode());
        store.overwrite(b"unexpected-namespace-entry", vec![9u8; 4]);
        assert!(matches!(
            SigningReservationJournal::open(store.clone()),
            Err(JournalError::UnexpectedNamespaceEntry(_))
        ));
    }

    #[test]
    fn open_refuses_missing_metadata_with_unsupported_existing_state() {
        // No metadata but existing signing state present ⇒ legacy/foreign
        // namespace ⇒ refuse (never silently initialize over it).
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Proposal, 1);
        let b = binding(b"x");
        let (k, v) = reserved_kv(&pos, &b);
        store.overwrite(&k, v);
        assert!(matches!(
            SigningReservationJournal::open(store.clone()),
            Err(JournalError::LegacyRecordsWithoutMetadata)
        ));
    }

    #[test]
    fn open_succeeds_on_genuine_empty_via_initialize_and_valid_established() {
        // Genuine empty namespace: initialize succeeds and publishes metadata.
        let store = Arc::new(ModelStore::default());
        let journal =
            SigningReservationJournal::initialize(store.clone(), 8).expect("initialize empty");
        let b = binding(b"x");
        let _c1 = reserve_and_invoke(&journal, &position(SigningKind::Proposal, 1), &b);
        let _c2 = reserve_and_invoke(&journal, &position(SigningKind::Vote, 2), &b);

        // Valid established namespace: a fresh handle over the same durable bytes
        // opens and validates, preserving the count.
        let reopened = store.reopen();
        let opened = SigningReservationJournal::open(reopened).expect("open established");
        // Capacity/positions survived: a durable `Reserved` position recovered on
        // open is treated as potentially-signed (never re-minted as a fresh
        // continuation), proving the record was validated and counted.
        assert!(matches!(
            opened
                .reserve_for_sign(&position(SigningKind::Proposal, 1), &b)
                .unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
    }

    #[test]
    fn open_early_terminates_after_first_excess_entry() {
        // Establish four valid records, then silently understate the durable count
        // to one. `open` must stop as soon as the observed count exceeds the
        // expected count — visiting at most `expected + 1` entries, NOT the whole
        // namespace — and refuse.
        let store = Arc::new(ModelStore::default());
        let journal =
            SigningReservationJournal::initialize(store.clone(), 8).expect("initialize");
        let b = binding(b"x");
        for v in 1..=4u64 {
            let _c = reserve_and_invoke(&journal, &position(SigningKind::Proposal, v), &b);
        }
        // Understate the durable count (limit unchanged).
        store.overwrite(MODEL_META_KEY, SigningJournalMetadata::new(8, 1).encode());

        let reopened = store.reopen();
        reopened.reset_visits();
        assert!(matches!(
            SigningReservationJournal::open(reopened.clone()),
            Err(JournalError::AccountingInconsistent(_))
        ));
        // Early termination: exactly `expected + 1` = 2 entries were streamed,
        // proving the whole four-record namespace was NOT scanned.
        assert_eq!(reopened.visits(), 2, "scan must stop at the first excess entry");
    }

    #[test]
    fn open_refuses_oversized_namespace_value_before_decode() {
        // A stored value exceeding the maximum record length is rejected by the
        // storage boundary's length check BEFORE the journal copies/decodes it.
        let store = Arc::new(ModelStore::default());
        store.overwrite(MODEL_META_KEY, SigningJournalMetadata::new(8, 0).encode());
        let pos = position(SigningKind::Proposal, 1);
        store.overwrite(&pos.storage_key(), vec![0u8; MAX_RECORD_LEN + 1]);
        assert!(matches!(
            SigningReservationJournal::open(store.clone()),
            Err(JournalError::Corruption(_))
        ));
    }

    #[test]
    fn open_propagates_iterator_scan_failure() {
        // A scan/iterator read error (distinct from a metadata read) propagates as
        // a storage error; no domain is established.
        let store = Arc::new(ModelStore::default());
        let _journal =
            SigningReservationJournal::initialize(store.clone(), 8).expect("initialize");
        let reopened = store.reopen();
        reopened.set_fail_scan(true);
        assert!(matches!(
            SigningReservationJournal::open(reopened.clone()),
            Err(JournalError::Storage(_))
        ));
        // Reads recover ⇒ a subsequent open validates cleanly.
        reopened.set_fail_scan(false);
        assert!(SigningReservationJournal::open(reopened).is_ok());
    }

    #[test]
    fn open_propagates_metadata_read_failure() {
        // A metadata read failure at the start of open propagates fail-closed.
        let store = Arc::new(ModelStore::default());
        let _journal =
            SigningReservationJournal::initialize(store.clone(), 8).expect("initialize");
        let reopened = store.reopen();
        reopened.set_fail_reads(true);
        assert!(matches!(
            SigningReservationJournal::open(reopened),
            Err(JournalError::Storage(_))
        ));
    }

    #[test]
    fn failed_initialization_publishes_no_metadata_and_preserves_bytes() {
        // Pre-existing signing state (no metadata) makes initialization refuse: it
        // must publish NO metadata and leave the pre-existing bytes untouched.
        let store = Arc::new(ModelStore::default());
        let pos = position(SigningKind::Proposal, 1);
        let b = binding(b"x");
        let (k, v) = reserved_kv(&pos, &b);
        store.overwrite(&k, v.clone());
        assert!(matches!(
            SigningReservationJournal::initialize(store.clone(), 8),
            Err(JournalError::NonEmptyNamespace)
        ));
        assert!(
            store.get_signing_metadata().unwrap().is_none(),
            "failed init must not publish metadata"
        );
        assert_eq!(
            store.map.read().unwrap().get(k.as_slice()).cloned(),
            Some(v),
            "pre-existing bytes must be preserved"
        );
    }

    #[test]
    fn failed_initialization_write_publishes_no_metadata() {
        // An initialization metadata WRITE failure over a genuinely empty namespace
        // leaves the domain uninitialized with no metadata published.
        let store = Arc::new(ModelStore::default());
        store.set_fail_writes(true);
        assert!(matches!(
            SigningReservationJournal::initialize(store.clone(), 8),
            Err(JournalError::Storage(_))
        ));
        store.set_fail_writes(false);
        assert!(
            store.get_signing_metadata().unwrap().is_none(),
            "failed init write must not publish metadata"
        );
        // The namespace is still genuinely empty ⇒ a later initialize succeeds.
        assert!(SigningReservationJournal::initialize(store, 8).is_ok());
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

    // ------------------------------------------------------------------
    // Run 422 D7-D10 Correction A — post-eviction journal evidence. These
    // drive the FULL recovery flow THROUGH the journal (reserve_for_sign over
    // recovered Signed records), not direct cache insert/get. The ModelStore's
    // `record_writes` counter observes the recovery durability op so that an
    // evicted position reissuing the synced write (and an exact cache hit
    // avoiding it) is directly asserted. The recovered-ack cache is bounded to a
    // small test-only capacity via private test access so eviction is forced by
    // a handful of real recoveries rather than MAX_RECOVERED_ACK_ENTRIES of them.
    // ------------------------------------------------------------------

    #[test]
    fn post_eviction_recovery_reissues_synced_write_then_cache_hit_avoids_it() {
        // Bound the recovered-ack cache to 2 so recovering a third position evicts
        // the oldest process-local acknowledgement.
        let store = Arc::new(ModelStore::default());
        store.set_cache_capacity_for_test(2);

        let pa = position(SigningKind::Proposal, 201);
        let pb = position(SigningKind::Vote, 202);
        let pc = position(SigningKind::Proposal, 203);
        let ba = binding(b"aaa");
        let bb = binding(b"bbb");
        let bc = binding(b"ccc");
        let sig_a = b"retained-sig-a".to_vec();
        let sig_b = b"retained-sig-b".to_vec();
        let sig_c = b"retained-sig-c".to_vec();

        // (1) Create valid published Signed records under the ORIGINAL ownership
        //     domain (reserve → invoke → publish for each distinct position).
        {
            let journal = attach(store.clone());
            let ca = reserve_and_invoke(&journal, &pa, &ba);
            journal.record_signed_result(&ca, &sig_a).unwrap();
            let cb = reserve_and_invoke(&journal, &pb, &bb);
            journal.record_signed_result(&cb, &sig_b).unwrap();
            let cc = reserve_and_invoke(&journal, &pc, &bc);
            journal.record_signed_result(&cc, &sig_c).unwrap();
            assert_eq!(journal.reserved_position_count(), 3);
            assert_eq!(journal.established_limit(), DEFAULT_MAX_RESERVED_POSITIONS);
        }

        // The exact durable record bytes, snapshotted for later preservation checks.
        let bytes_a = store.map.read().unwrap().get(&pa.storage_key()).cloned().unwrap();
        let bytes_b = store.map.read().unwrap().get(&pb.storage_key()).cloned().unwrap();
        let bytes_c = store.map.read().unwrap().get(&pc.storage_key()).cloned().unwrap();

        // (2) Reopen through a FRESH ownership domain: durable bytes survive, the
        //     live-operation table and the process-local cache do not.
        let reopened_store = store.reopen();
        let reopened = attach(reopened_store.clone());
        assert_eq!(reopened.reserved_position_count(), 3, "durable count survives reopen");
        assert_eq!(
            reopened.established_limit(),
            DEFAULT_MAX_RESERVED_POSITIONS,
            "established limit survives reopen"
        );
        assert_eq!(reopened.recovered_ack_cache_len(), 0, "a fresh domain starts with an empty cache");
        assert_eq!(reopened_store.record_writes(), 0, "reopened instance starts its write counter at zero");

        // Helper: a recovered Signed record must resolve to the exact retained
        // signature (never a fresh continuation / signer invocation).
        fn expect_retained(j: &SigningReservationJournal, p: &SigningPosition, b: &BindingDigest, want: &[u8]) {
            match j.reserve_for_sign(p, b).unwrap() {
                ReservationOutcome::ExactRetryRetained(s) => assert_eq!(s, want),
                other => panic!("expected ExactRetryRetained, got {:?}", other),
            }
        }

        // (3) Populate the acknowledgement cache through ACTUAL journal lookups.
        //     Each FIRST recovery establishes the durability barrier via exactly
        //     one additional synced write.
        expect_retained(&reopened, &pa, &ba, &sig_a); // write #1 → cache {A}
        assert_eq!(reopened_store.record_writes(), 1);
        assert_eq!(reopened.recovered_ack_cache_len(), 1);
        expect_retained(&reopened, &pb, &bb, &sig_b); // write #2 → cache {A,B}
        assert_eq!(reopened_store.record_writes(), 2);
        assert_eq!(reopened.recovered_ack_cache_len(), 2);

        // (4) Force eviction through a FURTHER successful recovered acknowledgement:
        //     recovering C (capacity 2) evicts the oldest entry A.
        expect_retained(&reopened, &pc, &bc, &sig_c); // write #3 → evict A → {B,C}
        assert_eq!(reopened_store.record_writes(), 3);
        assert_eq!(reopened.recovered_ack_cache_len(), 2, "the cache stays at its bound");

        // (5) Revisit the EVICTED position A through the journal and directly
        //     observe the ADDITIONAL synced durability write (barrier re-established).
        expect_retained(&reopened, &pa, &ba, &sig_a); // write #4 → evict B → {C,A}
        assert_eq!(
            reopened_store.record_writes(),
            4,
            "revisiting an evicted position reissues exactly one synced durability write"
        );

        // (6) An EXACT cache hit avoids that write: C is still cached, so revisiting
        //     it reissues NOTHING — proven by configuring writes to fail yet still
        //     succeeding with the retained signature and no counter advance.
        reopened_store.set_fail_writes(true);
        expect_retained(&reopened, &pc, &bc, &sig_c); // cache hit → NO write
        assert_eq!(
            reopened_store.record_writes(),
            4,
            "an exact cache hit reissues no synced durability write"
        );
        reopened_store.set_fail_writes(false);

        // (7) Persistent counts, limit, exact record bytes, and conflict
        //     obligations are preserved across the entire sequence.
        assert_eq!(reopened.reserved_position_count(), 3);
        assert_eq!(reopened.established_limit(), DEFAULT_MAX_RESERVED_POSITIONS);
        assert_eq!(store.map.read().unwrap().get(&pa.storage_key()).cloned(), Some(bytes_a.clone()));
        assert_eq!(store.map.read().unwrap().get(&pb.storage_key()).cloned(), Some(bytes_b));
        assert_eq!(store.map.read().unwrap().get(&pc.storage_key()).cloned(), Some(bytes_c));
        // A conflicting binding over a recovered position is refused (never a
        // successful retained reuse) and does not rewrite the stored record.
        assert!(matches!(
            reopened.reserve_for_sign(&pa, &binding(b"conflicting")).unwrap(),
            ReservationOutcome::Conflict
        ));
        assert_eq!(
            store.map.read().unwrap().get(&pa.storage_key()).cloned(),
            Some(bytes_a),
            "a conflict obligation is preserved without rewrite"
        );
    }

    #[test]
    fn post_eviction_failed_and_uncertain_recovery_refuse_reuse_then_success_permits_exact_signature() {
        // Bound the cache to 1 so recovering a second position evicts the first.
        let store = Arc::new(ModelStore::default());
        store.set_cache_capacity_for_test(1);
        let pa = position(SigningKind::Proposal, 211);
        let pb = position(SigningKind::Vote, 212);
        let ba = binding(b"a");
        let bb = binding(b"b");
        let sig_a = b"retained-a".to_vec();
        let sig_b = b"retained-b".to_vec();
        {
            let journal = attach(store.clone());
            let ca = reserve_and_invoke(&journal, &pa, &ba);
            journal.record_signed_result(&ca, &sig_a).unwrap();
            let cb = reserve_and_invoke(&journal, &pb, &bb);
            journal.record_signed_result(&cb, &sig_b).unwrap();
        }
        let bytes_a = store.map.read().unwrap().get(&pa.storage_key()).cloned().unwrap();

        let reopened_store = store.reopen();
        let reopened = attach(reopened_store.clone());

        // Recover A (cache {A}), then recover B which EVICTS A (cache {B}).
        match reopened.reserve_for_sign(&pa, &ba).unwrap() {
            ReservationOutcome::ExactRetryRetained(s) => assert_eq!(s, sig_a),
            other => panic!("expected ExactRetryRetained, got {:?}", other),
        }
        match reopened.reserve_for_sign(&pb, &bb).unwrap() {
            ReservationOutcome::ExactRetryRetained(s) => assert_eq!(s, sig_b),
            other => panic!("expected ExactRetryRetained, got {:?}", other),
        }
        assert_eq!(reopened.recovered_ack_cache_len(), 1);

        // Revisit the EVICTED A with the recovery barrier write FAILING: the
        // retained result is NOT reused and NO usable cache acknowledgement forms.
        reopened_store.set_fail_writes(true);
        assert!(matches!(reopened.reserve_for_sign(&pa, &ba), Err(JournalError::Storage(_))));
        reopened_store.set_fail_writes(false);
        assert_eq!(reopened.recovered_ack_cache_len(), 1, "a failed barrier caches nothing for A");

        // Revisit the evicted A with a STORE-THEN-ERROR (uncertain) barrier:
        // readable bytes are NOT a usable acknowledgement — still no reuse.
        reopened_store.set_store_then_error(true);
        assert!(matches!(reopened.reserve_for_sign(&pa, &ba), Err(JournalError::Storage(_))));
        reopened_store.set_store_then_error(false);
        assert_eq!(reopened.recovered_ack_cache_len(), 1, "an uncertain barrier caches nothing for A");
        assert_eq!(
            store.map.read().unwrap().get(&pa.storage_key()).cloned(),
            Some(bytes_a.clone()),
            "the exact record is preserved across failed/uncertain recovery"
        );

        // (A/B) Immediately after the uncertain attempt: store-then-error is now
        //       disabled, but keep ORDINARY writes failing and retry the SAME
        //       evicted position A through the journal. The barrier write fails
        //       again, so there is NO retained reuse (an error, never a fresh
        //       continuation) and still NO usable cache acknowledgement. Proven
        //       via the existing record-write counter: a failed barrier returns
        //       before any synced write, so the counter does not advance.
        reopened_store.set_fail_writes(true);
        let writes_before_failed_retry = reopened_store.record_writes();
        assert!(
            matches!(reopened.reserve_for_sign(&pa, &ba), Err(JournalError::Storage(_))),
            "a still-failing barrier retry returns a storage error, not a retained reuse"
        );
        assert_eq!(
            reopened_store.record_writes(),
            writes_before_failed_retry,
            "a failed barrier retry performs no successful synced write"
        );
        assert_eq!(
            reopened.recovered_ack_cache_len(),
            1,
            "a failed retry forms no usable cache acknowledgement for A"
        );
        // The exact retained record and its conflict obligation are preserved.
        assert_eq!(
            store.map.read().unwrap().get(&pa.storage_key()).cloned(),
            Some(bytes_a.clone()),
            "the exact retained record survives the failed retry"
        );
        assert!(
            matches!(
                reopened.reserve_for_sign(&pa, &binding(b"conflicting")).unwrap(),
                ReservationOutcome::Conflict
            ),
            "a conflicting binding is still refused after the failed retry"
        );
        assert_eq!(
            store.map.read().unwrap().get(&pa.storage_key()).cloned(),
            Some(bytes_a.clone()),
            "the conflict obligation does not rewrite the stored record"
        );

        // (C) Permit the next write and retry: the barrier is re-established with
        //     exactly ONE additional synced recovery write — direct proof the
        //     failed/uncertain attempts left no usable acknowledgement (a cached
        //     ack would be served WITHOUT a write) — and ONLY the exact retained
        //     signature is reused.
        reopened_store.set_fail_writes(false);
        let writes_before_success = reopened_store.record_writes();
        match reopened.reserve_for_sign(&pa, &ba).unwrap() {
            ReservationOutcome::ExactRetryRetained(s) => assert_eq!(s, sig_a),
            other => panic!("expected ExactRetryRetained, got {:?}", other),
        }
        assert_eq!(
            reopened_store.record_writes(),
            writes_before_success + 1,
            "a successful recovery after failed/uncertain attempts issues exactly one additional synced write"
        );

        // Exact-cache-hit control (preserved): A is now cached (evicting B), so a
        // subsequent exact lookup is served WITHOUT reissuing the durable write,
        // even when writes are configured to fail — the counter does not advance.
        reopened_store.set_fail_writes(true);
        let writes_before_hit = reopened_store.record_writes();
        match reopened.reserve_for_sign(&pa, &ba).unwrap() {
            ReservationOutcome::ExactRetryRetained(s) => assert_eq!(s, sig_a),
            other => panic!("expected ExactRetryRetained, got {:?}", other),
        }
        assert_eq!(
            reopened_store.record_writes(),
            writes_before_hit,
            "an exact cache hit reissues no synced durability write"
        );
    }

    // ------------------------------------------------------------------
    // Run 422 D7-D10 Correction B — store-then-error initialization. The
    // existing fault injector makes the initialization metadata readable while
    // its durable write returns an error. Readable bytes are NOT equated with a
    // successful initialization acknowledgement, and metadata absence is NOT
    // required afterwards.
    // ------------------------------------------------------------------

    #[test]
    fn store_then_error_initialization_refuses_handle_but_leaves_readable_consistent_metadata() {
        let store = Arc::new(ModelStore::default());
        let limit = 8u64;
        // The initialization metadata write STORES its bytes (readable) and THEN
        // returns an error (uncertain durable write).
        store.set_store_then_error(true);
        let init = SigningReservationJournal::initialize(store.clone(), limit);
        store.set_store_then_error(false);

        // (A) `initialize` returns an error and yields NO usable handle.
        assert!(matches!(init, Err(JournalError::Storage(_))), "store-then-error init must return an error");

        // (B) Surviving metadata/namespace contents inspected DIRECTLY: the metadata
        //     bytes are readable and decode to the requested limit with a zero
        //     count; the record namespace stays empty (no records were created).
        let meta_bytes = store
            .get_signing_metadata()
            .unwrap()
            .expect("metadata bytes are readable after a store-then-error write");
        let meta = SigningJournalMetadata::decode(&meta_bytes).expect("surviving metadata decodes");
        assert_eq!(meta.max_reserved_positions, limit);
        assert_eq!(meta.reserved_positions, 0);
        assert!(
            store
                .map
                .read()
                .unwrap()
                .keys()
                .all(|k| !k.starts_with(SIGNING_RECORD_KEY_PREFIX)),
            "a failed init creates no decision records"
        );

        // (C) Repeated initialization cannot silently reset or overwrite the
        //     surviving metadata — even with a DIFFERENT limit, and even over a
        //     freshly reopened instance (a fresh in-process domain).
        assert!(matches!(
            SigningReservationJournal::initialize(store.clone(), 999),
            Err(JournalError::AlreadyInitialized)
        ));
        let reopened_store = store.reopen();
        assert!(matches!(
            SigningReservationJournal::initialize(reopened_store.clone(), 999),
            Err(JournalError::AlreadyInitialized)
        ));
        let meta_after = SigningJournalMetadata::decode(
            &store.get_signing_metadata().unwrap().expect("metadata still present"),
        )
        .expect("metadata still decodes");
        assert_eq!(meta_after.max_reserved_positions, limit, "limit was not overwritten");
        assert_eq!(meta_after.reserved_positions, 0, "count was not overwritten");

        // (D) Subsequent explicit `open` behaves as the implementation specifies:
        //     the surviving metadata is well-formed and the namespace is empty and
        //     consistent (count 0), so a validating open ESTABLISHES the journal.
        //     This is open's INDEPENDENT validation of durable state — NOT the
        //     uncertain initialize write being treated as a success.
        let opened = SigningReservationJournal::open(store.reopen())
            .expect("open validates the surviving empty, consistent metadata and establishes the journal");
        assert_eq!(opened.established_limit(), limit);
        assert_eq!(opened.reserved_position_count(), 0);
    }

    // ========================================================================
    // Run 422 — Non-enabling journal accountant association (identity-only
    // installer). These tests live in-crate so they can observe the private
    // `DomainInner::admission` field and the crate-internal installer without
    // widening production visibility. Separate from the source-based argument
    // that the installer acquires only the single signing-domain mutex and no
    // accounting lock (visible in `install_accountant_association`).
    // ========================================================================
    use crate::safety_record_store::accounting::{AggregateAuthority, SharedAccountant};
    use crate::safety_record_store::PinnedSafetyContext;

    /// A fresh, independent operational ledger (its own partition sub-ledger and
    /// its own aggregate authority). Two separate calls denote DIFFERENT ledgers.
    fn fresh_ledger() -> SharedAccountant {
        SharedAccountant::new(AggregateAuthority::new())
    }

    /// Snapshot the association currently installed on a journal's domain, cloning
    /// the handle (an Arc refcount bump) so the domain lock is released promptly.
    fn installed(j: &SigningReservationJournal) -> Option<SharedAccountant> {
        j.domain.inner.lock().unwrap().admission.clone()
    }

    /// A minimal pinned context sufficient to bind a real operational sub-ledger so
    /// scenario 6 can apply genuine accounting pressure through `reserve`.
    fn pinned_ctx() -> PinnedSafetyContext {
        use qbind_consensus::ids::ValidatorId;
        PinnedSafetyContext {
            network_genesis_id: [1u8; 32],
            authority_context_ref: [2u8; 32],
            chain_id: 42,
            epoch: 7,
            qc_suite_id: 7,
            timeout_suite_id: 100,
            s_sig: 8,
            validators: (0..4u64).map(|i| (ValidatorId::new(i), 1u64)).collect(),
            require_height_equals_round: false,
        }
    }

    /// (1) The first installation over an unassociated domain succeeds and records
    /// the supplied ledger identity.
    #[test]
    fn assoc_first_install_succeeds() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store);
        let acct = fresh_ledger();
        assert!(installed(&journal).is_none(), "fresh domain must be unassociated");
        assert_eq!(journal.install_accountant_association(&acct), Ok(()));
        let got = installed(&journal).expect("association recorded");
        assert!(got.same_ledger(&acct), "recorded identity must match the installed ledger");
    }

    /// (2) Reinstalling a CLONE of the same ledger succeeds and preserves the exact
    /// stored handle (no replacement).
    #[test]
    fn assoc_reinstall_same_ledger_preserves_association() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store);
        let acct = fresh_ledger();
        assert_eq!(journal.install_accountant_association(&acct), Ok(()));
        let before = installed(&journal).expect("installed");
        // A clone shares both partition and aggregate Arcs -> same ledger.
        assert_eq!(journal.install_accountant_association(&acct.clone()), Ok(()));
        let after = installed(&journal).expect("still installed");
        assert!(after.same_ledger(&acct));
        assert!(after.same_ledger(&before), "the stored association was preserved");
    }

    /// (3) A different ledger is refused with the fixed-size mismatch error and the
    /// original association is left intact.
    #[test]
    fn assoc_different_ledger_is_refused_without_change() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store);
        let first = fresh_ledger();
        let other = fresh_ledger();
        assert_eq!(journal.install_accountant_association(&first), Ok(()));
        assert_eq!(
            journal.install_accountant_association(&other),
            Err(AdmissionInstallError::LedgerMismatch)
        );
        let got = installed(&journal).expect("association intact");
        assert!(got.same_ledger(&first), "original association unchanged");
        assert!(!got.same_ledger(&other));
    }

    /// (4) Two concurrent same-ledger installers both succeed; exactly one
    /// association is stored and it matches that ledger.
    #[test]
    fn assoc_concurrent_same_ledger_installers_both_succeed() {
        use std::sync::Barrier;
        let store = Arc::new(ModelStore::default());
        let journal = Arc::new(attach(store));
        let acct = fresh_ledger();
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let j = Arc::clone(&journal);
            let a = acct.clone();
            let bar = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                bar.wait();
                j.install_accountant_association(&a)
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().expect("thread joined")).collect();
        assert!(results.iter().all(|r| *r == Ok(())), "both same-ledger installs succeed: {results:?}");
        let got = installed(&journal).expect("one association stored");
        assert!(got.same_ledger(&acct));
    }

    /// (5) Two concurrent different-ledger installers produce exactly one winner and
    /// one mismatch; the stored association matches the winner.
    #[test]
    fn assoc_concurrent_different_ledger_installers_one_winner() {
        use std::sync::Barrier;
        let store = Arc::new(ModelStore::default());
        let journal = Arc::new(attach(store));
        let a = fresh_ledger();
        let b = fresh_ledger();
        let barrier = Arc::new(Barrier::new(2));
        let ja = Arc::clone(&journal);
        let jb = Arc::clone(&journal);
        let a2 = a.clone();
        let b2 = b.clone();
        let bar_a = Arc::clone(&barrier);
        let bar_b = Arc::clone(&barrier);
        let ha = std::thread::spawn(move || {
            bar_a.wait();
            ja.install_accountant_association(&a2)
        });
        let hb = std::thread::spawn(move || {
            bar_b.wait();
            jb.install_accountant_association(&b2)
        });
        let ra = ha.join().expect("thread a joined");
        let rb = hb.join().expect("thread b joined");
        let oks = [ra, rb].iter().filter(|r| **r == Ok(())).count();
        let mismatches = [ra, rb]
            .iter()
            .filter(|r| **r == Err(AdmissionInstallError::LedgerMismatch))
            .count();
        assert_eq!(oks, 1, "exactly one winner: ra={ra:?} rb={rb:?}");
        assert_eq!(mismatches, 1, "exactly one mismatch: ra={ra:?} rb={rb:?}");
        let got = installed(&journal).expect("winner stored");
        // The stored association equals whichever ledger won.
        assert!(got.same_ledger(&a) ^ got.same_ledger(&b), "stored exactly one of the two ledgers");
    }

    /// (6) Install and reinstall leave the operational and aggregate ledger values
    /// unchanged, including while a genuine reservation holds accounting pressure.
    #[test]
    fn assoc_install_does_not_change_ledger_values_under_pressure() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store);
        let agg = AggregateAuthority::new();
        agg.bind(1 << 20).expect("bind aggregate ceiling");
        let acct = SharedAccountant::new(agg);
        acct.bind(&pinned_ctx(), 0).expect("bind operational sub-ledger");
        // Hold real pressure on BOTH the partition and the aggregate.
        let _res = acct.reserve(64).expect("reserve applies pressure");
        let p_current = acct.current();
        let p_peak = acct.peak();
        let p_cap = acct.cap();
        let a_current = acct.aggregate().current();
        let a_peak = acct.aggregate().peak();
        let a_cap = acct.aggregate().cap();
        assert!(p_current >= 64 && a_current >= 64, "pressure is present");

        assert_eq!(journal.install_accountant_association(&acct), Ok(()));
        assert_eq!(journal.install_accountant_association(&acct.clone()), Ok(()));

        assert_eq!(acct.current(), p_current, "partition current unchanged");
        assert_eq!(acct.peak(), p_peak, "partition peak unchanged");
        assert_eq!(acct.cap(), p_cap, "partition cap unchanged");
        assert_eq!(acct.aggregate().current(), a_current, "aggregate current unchanged");
        assert_eq!(acct.aggregate().peak(), a_peak, "aggregate peak unchanged");
        assert_eq!(acct.aggregate().cap(), a_cap, "aggregate cap unchanged");
    }

    /// (7) Dropping the installing handle while retaining the storage instance
    /// preserves the association through the shared ownership domain; a new handle
    /// opened over the SAME instance observes it.
    #[test]
    fn assoc_survives_handle_drop_same_instance() {
        let store = Arc::new(ModelStore::default());
        let acct = fresh_ledger();
        {
            let journal = attach(store.clone());
            assert_eq!(journal.install_accountant_association(&acct), Ok(()));
            // journal dropped here; `store` (and thus its domain) lives on.
        }
        let reopened = attach(store.clone());
        let got = installed(&reopened).expect("association observed over same instance");
        assert!(got.same_ledger(&acct));
    }

    /// (8) A genuinely new domain (a modelled restart: same bytes, fresh domain)
    /// begins unassociated — the association is volatile ownership-domain state, not
    /// durable record state.
    #[test]
    fn assoc_fresh_domain_begins_unassociated() {
        let store = Arc::new(ModelStore::default());
        let acct = fresh_ledger();
        let journal = attach(store.clone());
        assert_eq!(journal.install_accountant_association(&acct), Ok(()));
        assert!(installed(&journal).is_some());
        // A modelled restart is a NEW instance with a FRESH domain.
        let restarted = attach(store.reopen());
        assert!(installed(&restarted).is_none(), "fresh domain is unassociated");
    }

    /// (9) A poisoned signing-domain mutex yields the fixed-size refusal without
    /// panicking or allocating.
    #[test]
    fn assoc_poisoned_lock_returns_fixed_refusal() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store);
        let acct = fresh_ledger();
        let domain = Arc::clone(&journal.domain);
        // Poison the domain mutex by panicking while holding it.
        let poisoner = std::thread::spawn(move || {
            let _guard = domain.inner.lock().unwrap();
            panic!("intentional poison for test");
        });
        assert!(poisoner.join().is_err(), "poisoning thread panicked as expected");
        assert_eq!(
            journal.install_accountant_association(&acct),
            Err(AdmissionInstallError::LockPoisoned)
        );
    }

    /// (10) Representative legacy reserve -> consume -> publish -> exact-retry
    /// behavior is unchanged after an association is installed (the installer is
    /// non-enabling and non-disabling).
    #[test]
    fn assoc_install_leaves_legacy_paths_unchanged() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store);
        let acct = fresh_ledger();
        assert_eq!(journal.install_accountant_association(&acct), Ok(()));

        let pos = position(SigningKind::Proposal, 11);
        let b = binding(b"legacy-after-install");
        let cap = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap, b"sigbytes").unwrap();
        // Exact retry still reuses the retained signature with no fresh continuation.
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"sigbytes"
        ));
        // Reinstall is still accepted and the legacy outcome above is unaffected.
        assert_eq!(journal.install_accountant_association(&acct.clone()), Ok(()));
    }

    /// Measured layout observation (target-dependent): the inline association field
    /// is a niche-optimized `Option<SharedAccountant>` that is the SAME size as
    /// `SharedAccountant` (no added discriminant word). This documents that the new
    /// field is identity bookkeeping of two Arc handles, not a new heap allocation;
    /// it does NOT claim the whole domain allocation is admitted by this slice.
    #[test]
    fn assoc_field_is_niche_optimized_option() {
        use std::mem::size_of;
        assert_eq!(
            size_of::<Option<SharedAccountant>>(),
            size_of::<SharedAccountant>(),
            "Option<SharedAccountant> uses an Arc niche (no extra discriminant word)"
        );
    }


    // ========================================================================
    // Run 422 — Isolated acknowledged-operation retirement. These tests drive the
    // genuine reserve -> consume -> record flow over the MODEL store and exercise
    // retire_acknowledged_operation's preconditions, isolation, and the guarantee
    // that retirement performs no storage I/O and mutates no durable/uncertainty/
    // cache/accounting state. Post-retirement cache-free retrieval (evidence D) is
    // covered in signing_journal_admission.rs over an envelope-capable backend.
    // ========================================================================

    /// Evidence A — a genuine acknowledged operation retires, removing EXACTLY its
    /// live entry, while every durable byte, the durable count, the operation-id
    /// source, the uncertainty latch, the recovered cache, and the storage write
    /// count are unchanged (retirement performs no I/O).
    #[test]
    fn retire_acked_removes_exact_entry_without_io_or_durable_change() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store.clone());

        // Populate the recovered-acknowledgement cache through a LEGITIMATE route
        // so the non-mutation comparison exercises a NON-EMPTY cache (contents +
        // FIFO order), not merely a length: reserve->invoke->record a DIFFERENT
        // position, retire it, then re-present it so the recovered path
        // establishes the durability barrier and caches the exact record.
        let seed_pos = position(SigningKind::Vote, 700);
        let seed_b = binding(b"retire-A-seed");
        let seed_cap = reserve_and_invoke(&journal, &seed_pos, &seed_b);
        journal.record_signed_result(&seed_cap, b"seed-sig").unwrap();
        journal.retire_acknowledged_operation(&seed_cap).unwrap();
        assert!(matches!(
            journal.reserve_for_sign(&seed_pos, &seed_b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"seed-sig"
        ));
        assert_eq!(
            journal.recovered_ack_cache_len(),
            1,
            "cache populated through the genuine recovered route"
        );

        // The operation actually under test.
        let pos = position(SigningKind::Proposal, 701);
        let b = binding(b"retire-A");
        let cap = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap, b"sigbytes").unwrap();

        // Identical-result republication is available BEFORE retirement.
        journal.record_signed_result(&cap, b"sigbytes").unwrap();
        assert!(journal.live_contains_for_test(&pos));
        // The seed is recovered-only (no live entry); P is the sole live entry.
        assert_eq!(journal.live_len_for_test(), 1);

        // Snapshot durable + in-memory state immediately before retirement. These
        // state-inspection reads happen BEFORE the storage-call window opens, so
        // they are excluded from the around-retire delta.
        let key = pos.storage_key();
        let record_before = store.get_signing_record(&key).unwrap();
        let meta_before = store.get_signing_metadata().unwrap();
        let count_before = journal.reserved_position_count();
        let next_op_before = journal.next_operation_id_for_test();
        let uncertain_before = journal.accounting_uncertain_for_test();
        let uncertain_attempt_before = journal.uncertain_attempt_for_test();
        let cache_before = journal.recovered_ack_snapshot_for_test();
        let writes_before = store.record_writes();

        // Open the comprehensive storage-call window IMMEDIATELY around the retire
        // call: reads, writes, and reissues are counted SEPARATELY, and no fixture
        // setup or state-inspection read falls inside it.
        let calls_before = store.storage_calls();
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Ok(RetirementOutcome::Retired)
        );
        let calls_after = store.storage_calls();

        // Executed no-I/O evidence: ZERO reads, writes, AND reissues across the
        // retirement. This per-category executed delta — NOT the earlier
        // record-write-only counter — establishes the no-I/O boundary, and it is
        // kept distinct from source inspection of the method.
        assert_eq!(
            calls_after, calls_before,
            "retirement performs no storage reads, writes, or reissues"
        );

        // Exactly this entry disappeared; the recovered-only seed is untouched.
        assert!(!journal.live_contains_for_test(&pos));
        assert_eq!(journal.live_len_for_test(), 0);
        // Every durable and in-memory accounting datum is byte-for-byte unchanged,
        // INCLUDING the complete uncertainty bookkeeping (latch AND tracked
        // attempt) and the recovered-cache CONTENTS and ORDER (not just lengths).
        assert_eq!(store.get_signing_record(&key).unwrap(), record_before);
        assert_eq!(store.get_signing_metadata().unwrap(), meta_before);
        assert_eq!(journal.reserved_position_count(), count_before);
        assert_eq!(journal.next_operation_id_for_test(), next_op_before);
        assert_eq!(journal.accounting_uncertain_for_test(), uncertain_before);
        assert_eq!(journal.uncertain_attempt_for_test(), uncertain_attempt_before);
        assert_eq!(journal.recovered_ack_snapshot_for_test(), cache_before);
        // The record-write counter is ALSO unchanged, but is no longer relied on
        // alone to establish the no-I/O property (see the per-category delta).
        assert_eq!(store.record_writes(), writes_before);
    }

    /// Evidence B — after retirement the borrowed capability is stale: the normal
    /// publication check rejects it and a repeated retirement refuses with a fixed
    /// code, neither mutating durable nor live state.
    #[test]
    fn retire_then_stale_publication_and_repeat_retire_refuse_without_change() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store.clone());
        let pos = position(SigningKind::Vote, 702);
        let b = binding(b"retire-B-stale");
        let cap = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap, b"the-sig").unwrap();
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Ok(RetirementOutcome::Retired)
        );

        let key = pos.storage_key();
        let record_after_retire = store.get_signing_record(&key).unwrap();
        let writes_after_retire = store.record_writes();

        // The durable signing obligation remains; stale publication is rejected
        // through the EXISTING missing-live-operation check (no durable rewrite).
        assert!(matches!(
            journal.record_signed_result(&cap, b"the-sig"),
            Err(JournalError::InvalidResultPublication(_))
        ));
        assert_eq!(store.get_signing_record(&key).unwrap(), record_after_retire);

        // A repeated retirement is a fixed refusal with no state change and no
        // storage I/O of any category.
        let calls_before = store.storage_calls();
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Err(RetirementError::NoLiveOperation)
        );
        assert_eq!(
            store.storage_calls(),
            calls_before,
            "a refused repeat retirement performs no storage I/O"
        );
        assert_eq!(journal.live_len_for_test(), 0);
        assert_eq!(store.get_signing_record(&key).unwrap(), record_after_retire);
        assert_eq!(store.record_writes(), writes_after_retire);
    }

    /// Evidence B — a capability from a FOREIGN ownership domain is refused and
    /// removes nothing from either domain.
    #[test]
    fn retire_foreign_domain_capability_refused() {
        let store_a = Arc::new(ModelStore::default());
        let journal_a = attach(store_a);
        let store_b = Arc::new(ModelStore::default());
        let journal_b = attach(store_b.clone());
        let pos = position(SigningKind::Proposal, 703);
        let b = binding(b"retire-B-foreign");
        let cap_a = reserve_and_invoke(&journal_a, &pos, &b);
        journal_a.record_signed_result(&cap_a, b"sig").unwrap();

        // journal_b's domain token differs, so cap_a is foreign to it.
        let calls_before = store_b.storage_calls();
        assert_eq!(
            journal_b.retire_acknowledged_operation(&cap_a),
            Err(RetirementError::ForeignDomain)
        );
        assert_eq!(
            store_b.storage_calls(),
            calls_before,
            "a foreign-domain refusal performs no storage I/O"
        );
        // The owning domain still holds the live entry (nothing removed anywhere).
        assert!(journal_a.live_contains_for_test(&pos));
    }

    /// Evidence B — retiring one operation leaves a DIFFERENT live operation intact,
    /// and that other operation can still publish idempotently.
    #[test]
    fn retire_preserves_another_live_operation() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store);
        let p1 = position(SigningKind::Proposal, 704);
        let p2 = position(SigningKind::Vote, 705);
        let b1 = binding(b"retire-B-keep-1");
        let b2 = binding(b"retire-B-keep-2");
        let cap1 = reserve_and_invoke(&journal, &p1, &b1);
        let cap2 = reserve_and_invoke(&journal, &p2, &b2);
        journal.record_signed_result(&cap1, b"s1").unwrap();
        journal.record_signed_result(&cap2, b"s2").unwrap();
        assert_eq!(journal.live_len_for_test(), 2);

        assert_eq!(
            journal.retire_acknowledged_operation(&cap1),
            Ok(RetirementOutcome::Retired)
        );
        assert!(!journal.live_contains_for_test(&p1));
        assert!(journal.live_contains_for_test(&p2));
        assert_eq!(journal.live_len_for_test(), 1);
        // The surviving operation still republishes its identical result.
        journal.record_signed_result(&cap2, b"s2").unwrap();
    }

    /// Evidence B (DEFENSIVE fixtures) — operation-id / binding mismatch and an
    /// un-invoked live entry each refuse without removing the entry. Genuine public
    /// control flow cannot present these, so they are built with explicitly
    /// labelled in-module test mutators (no public capability constructor).
    #[test]
    fn retire_operation_id_binding_and_invoked_mismatches_refused() {
        // operation-id mismatch: replace the live entry with a NEW operation id.
        let store = Arc::new(ModelStore::default());
        let journal = attach(store.clone());
        let pos = position(SigningKind::Proposal, 706);
        let b = binding(b"retire-B-mismatch");
        let cap = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap, b"sig").unwrap();
        // Overwrite the entry (same position+binding, FRESH operation id, acked).
        journal.insert_live_for_test(pos, b, true);
        let calls_before = store.storage_calls();
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Err(RetirementError::OperationMismatch)
        );
        assert_eq!(store.storage_calls(), calls_before, "op-id mismatch refusal performs no storage I/O");
        assert!(journal.live_contains_for_test(&pos), "entry not removed on mismatch");

        // binding mismatch: entry at the same position carries a DIFFERENT binding.
        let store2 = Arc::new(ModelStore::default());
        let journal2 = attach(store2.clone());
        let pos2 = position(SigningKind::Vote, 707);
        let b2 = binding(b"retire-B-bind-a");
        let cap2 = reserve_and_invoke(&journal2, &pos2, &b2);
        journal2.record_signed_result(&cap2, b"sig").unwrap();
        journal2.insert_live_for_test(pos2, binding(b"retire-B-bind-OTHER"), true);
        let calls_before2 = store2.storage_calls();
        assert_eq!(
            journal2.retire_acknowledged_operation(&cap2),
            Err(RetirementError::OperationMismatch)
        );
        assert_eq!(store2.storage_calls(), calls_before2, "binding mismatch refusal performs no storage I/O");
        assert!(journal2.live_contains_for_test(&pos2));

        // un-invoked defensive: force invoked=false for the matching entry.
        let store3 = Arc::new(ModelStore::default());
        let journal3 = attach(store3.clone());
        let pos3 = position(SigningKind::Proposal, 708);
        let b3 = binding(b"retire-B-uninvoked");
        let cap3 = reserve_and_invoke(&journal3, &pos3, &b3);
        journal3.record_signed_result(&cap3, b"sig").unwrap();
        journal3.set_live_invoked_for_test(&pos3, false);
        let calls_before3 = store3.storage_calls();
        assert_eq!(
            journal3.retire_acknowledged_operation(&cap3),
            Err(RetirementError::NotInvoked)
        );
        assert_eq!(store3.storage_calls(), calls_before3, "un-invoked refusal performs no storage I/O");
        assert!(journal3.live_contains_for_test(&pos3));
    }

    /// Evidence C — retirement refuses while an invoked operation remains
    /// unacknowledged, INCLUDING a result write that stored bytes but returned an
    /// error (readable Signed bytes do not satisfy result_acked). After a genuine
    /// publication retry establishes acknowledgement, retirement succeeds.
    #[test]
    fn retire_refuses_until_result_acknowledged_then_succeeds() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store.clone());
        let pos = position(SigningKind::Proposal, 709);
        let b = binding(b"retire-C");
        // Invoked but not yet acknowledged (no record_signed_result).
        let cap = reserve_and_invoke(&journal, &pos, &b);
        let calls_before = store.storage_calls();
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Err(RetirementError::NotAcknowledged)
        );
        assert_eq!(store.storage_calls(), calls_before, "unacknowledged refusal performs no storage I/O");

        // A write that stores readable bytes but returns an error does NOT
        // acknowledge: result_acked stays false, so retirement still refuses.
        store.set_store_then_error(true);
        assert!(journal.record_signed_result(&cap, b"sig-C").is_err());
        // The Signed bytes are now readable in the store...
        assert!(store.get_signing_record(&pos.storage_key()).unwrap().is_some());
        // ...yet retirement refuses because no in-process ack was established,
        // and the refusal itself performs no storage I/O.
        let calls_before2 = store.storage_calls();
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Err(RetirementError::NotAcknowledged)
        );
        assert_eq!(store.storage_calls(), calls_before2, "readable-but-unacked refusal performs no storage I/O");

        // A successful publication retry establishes the acknowledgement.
        store.set_store_then_error(false);
        journal.record_signed_result(&cap, b"sig-C").unwrap();
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Ok(RetirementOutcome::Retired)
        );
    }

    /// Evidence E — after retirement, reserving the SAME position/binding is never
    /// FreshlyReserved (the durable obligation persists), a DIFFERENT binding is a
    /// Conflict, and neither path reduces the durable position count.
    #[test]
    fn retire_does_not_renew_signing_eligibility() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store);
        let pos = position(SigningKind::Proposal, 710);
        let b = binding(b"retire-E");
        let cap = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap, b"sig-E").unwrap();
        let count_before = journal.reserved_position_count();
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Ok(RetirementOutcome::Retired)
        );

        // Matching position/binding: the recovered durable Signed record is
        // re-presented (never a fresh continuation).
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::ExactRetryRetained(ref s) if s == b"sig-E"
        ));
        // A different binding at the same position is a Conflict, not fresh.
        assert!(matches!(
            journal.reserve_for_sign(&pos, &binding(b"retire-E-DIFFERENT")).unwrap(),
            ReservationOutcome::Conflict
        ));
        // The durable position count never decreased.
        assert_eq!(journal.reserved_position_count(), count_before);
    }

    /// Evidence F — a retirement through one handle is observed by a second handle
    /// sharing the same ownership domain.
    #[test]
    fn retire_observed_by_second_handle_sharing_domain() {
        let store = Arc::new(ModelStore::default());
        let journal_a = attach(store.clone());
        // A second handle over the SAME store instance shares one ownership domain.
        let journal_b = SigningReservationJournal::open(store.clone())
            .expect("second handle opens the established model store");
        let pos = position(SigningKind::Proposal, 711);
        let b = binding(b"retire-F-shared");
        let cap = reserve_and_invoke(&journal_a, &pos, &b);
        journal_a.record_signed_result(&cap, b"sig-F").unwrap();
        assert!(journal_b.live_contains_for_test(&pos), "shared domain sees the live entry");

        assert_eq!(
            journal_a.retire_acknowledged_operation(&cap),
            Ok(RetirementOutcome::Retired)
        );
        // The second handle observes the removal through the shared domain.
        assert!(!journal_b.live_contains_for_test(&pos));
        assert!(matches!(
            journal_b.record_signed_result(&cap, b"sig-F"),
            Err(JournalError::InvalidResultPublication(_))
        ));
    }

    /// Evidence F — for an associated fixture, the operational and aggregate ledgers
    /// are unchanged directly across the retirement call (no retrieval workspace is
    /// admitted, so no workspace charges enter the comparison).
    #[test]
    fn retire_leaves_associated_ledgers_unchanged() {
        let store = Arc::new(ModelStore::default());
        let journal = attach(store);
        let agg = AggregateAuthority::new();
        agg.bind(1 << 20).expect("bind aggregate ceiling");
        let acct = SharedAccountant::new(agg);
        acct.bind(&pinned_ctx(), 0).expect("bind operational sub-ledger");
        assert_eq!(journal.install_accountant_association(&acct), Ok(()));

        let pos = position(SigningKind::Proposal, 712);
        let b = binding(b"retire-F-ledger");
        let cap = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap, b"sig-F2").unwrap();

        let p_current = acct.current();
        let p_peak = acct.peak();
        let p_cap = acct.cap();
        let a_current = acct.aggregate().current();
        let a_peak = acct.aggregate().peak();
        let a_cap = acct.aggregate().cap();

        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Ok(RetirementOutcome::Retired)
        );

        assert_eq!(acct.current(), p_current, "partition current unchanged");
        assert_eq!(acct.peak(), p_peak, "partition peak unchanged");
        assert_eq!(acct.cap(), p_cap, "partition cap unchanged");
        assert_eq!(acct.aggregate().current(), a_current, "aggregate current unchanged");
        assert_eq!(acct.aggregate().peak(), a_peak, "aggregate peak unchanged");
        assert_eq!(acct.aggregate().cap(), a_cap, "aggregate cap unchanged");
    }

    // =====================================================================
    // Run 422 — Isolated bounded journal live-container evidence.
    //
    // These tests exercise the REAL journal and REAL accountant through the
    // explicit, non-enabling `enter_bounded_live_mode` transition and the
    // bounded reserve/retire paths. Source-reasoning layout measurements,
    // operational-ledger observations, and the single INJECTED allocation
    // failure are labelled distinctly. No test claims system-OOM reproduction,
    // crash durability, or process-RSS bounds.
    // =====================================================================

    /// Process-global serialization for tests that actually CONSTRUCT a bounded
    /// container. The injected allocation-failure switch
    /// (`FORCE_CONSTRUCT_ALLOC_FAILURE`) is now THREAD-LOCAL and armed through an
    /// RAII guard, so it no longer requires this mutex for soundness (it cannot
    /// leak to another thread). This serial is retained only as a conservative
    /// ordering for construct-heavy tests; poison is tolerated so one failing
    /// test does not cascade.
    static BOUNDED_CONSTRUCT_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn bounded_serial() -> std::sync::MutexGuard<'static, ()> {
        BOUNDED_CONSTRUCT_SERIAL
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Build a real, established, associated journal with a bound operational
    /// sub-ledger and aggregate ceiling of `cap`, returning the journal, its
    /// accountant handle, and the store `Arc` (held so a test can drop BOTH to
    /// destroy the ownership domain and observe the exact release).
    fn associated_journal_with_limit(
        limit: u64,
        cap: u128,
    ) -> (SigningReservationJournal, SharedAccountant, Arc<ModelStore>) {
        let store = Arc::new(ModelStore::default());
        let journal = attach_with_budget(store.clone(), limit);
        let agg = AggregateAuthority::new();
        agg.bind(cap).expect("bind aggregate ceiling");
        let acct = SharedAccountant::new(agg);
        acct.bind_cap(cap).expect("bind operational sub-ledger");
        journal
            .install_accountant_association(&acct)
            .expect("install association");
        (journal, acct, store)
    }

    fn associated_journal(cap: u128) -> (SigningReservationJournal, SharedAccountant, Arc<ModelStore>) {
        associated_journal_with_limit(DEFAULT_MAX_RESERVED_POSITIONS, cap)
    }

    /// The exact full container charge for capacity `l`, derived from the ACTUAL
    /// types (never hard-coded): `size_of::<LiveContainer>() + l * size_of::<Slot>()`.
    fn container_charge(l: usize) -> u128 {
        std::mem::size_of::<LiveContainer>() as u128
            + (l as u128) * std::mem::size_of::<Slot>() as u128
    }

    /// Build a real, established, associated journal over the ENVELOPE-CAPABLE
    /// [`crate::storage::InMemoryConsensusStorage`] backend (unlike
    /// [`associated_journal`], whose `ModelStore` does NOT support
    /// `read_signing_envelope_into`/`reissue_signing_envelope_synced`). This lets
    /// a genuine stored `Signed` record be retrieved through the REAL
    /// `retrieve_retained_checked` pipeline while a bounded container is live. The
    /// operational sub-ledger and aggregate ceiling are both `cap`. The journal
    /// owns the backend `Arc`, so the container stays live for the journal's
    /// lifetime.
    fn associated_real_journal(cap: u128) -> (SigningReservationJournal, SharedAccountant) {
        let store = Arc::new(crate::storage::InMemoryConsensusStorage::new())
            as Arc<dyn SigningJournalStorage>;
        let journal = SigningReservationJournal::initialize(store, DEFAULT_MAX_RESERVED_POSITIONS)
            .expect("initialize real envelope-capable backend");
        let agg = AggregateAuthority::new();
        agg.bind(cap).expect("bind aggregate ceiling");
        let acct = SharedAccountant::new(agg);
        acct.bind_cap(cap).expect("bind operational sub-ledger");
        journal
            .install_accountant_association(&acct)
            .expect("install association");
        (journal, acct)
    }

    /// Transition prerequisite: an installed accountant association is required.
    /// Without one the transition refuses with the fixed-size
    /// `NoAccountantAssociation` and leaves the domain in Legacy mode.
    #[test]
    fn bounded_requires_accountant_association() {
        let _serial = bounded_serial();
        let store = Arc::new(ModelStore::default());
        let journal = attach(store);
        assert_eq!(
            journal.enter_bounded_live_mode(1),
            Err(BoundedModeError::NoAccountantAssociation)
        );
        assert!(!journal.live_is_bounded_for_test(), "mode unchanged (Legacy)");
    }

    /// Transition prerequisite: the journal domain must be established. An
    /// unestablished handle refuses with `JournalNotEstablished` (checked before
    /// the association), leaving the domain Legacy.
    #[test]
    fn bounded_requires_established_journal() {
        let _serial = bounded_serial();
        let store = Arc::new(ModelStore::default());
        let journal = SigningReservationJournal::attach_unestablished_for_test(store);
        assert_eq!(
            journal.enter_bounded_live_mode(1),
            Err(BoundedModeError::JournalNotEstablished)
        );
        assert!(!journal.live_is_bounded_for_test());
    }

    /// A zero capacity is refused with `ZeroCapacity`; the first slice does not
    /// model a zero-capacity bounded container.
    #[test]
    fn bounded_zero_capacity_refused() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(
            journal.enter_bounded_live_mode(0),
            Err(BoundedModeError::ZeroCapacity)
        );
        assert!(!journal.live_is_bounded_for_test());
    }

    /// A capacity above the established durable-position limit is refused with
    /// `CapacityAboveLimit`; the durable limit itself is unchanged.
    #[test]
    fn bounded_capacity_above_limit_refused() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = associated_journal_with_limit(4, 1u128 << 30);
        assert_eq!(
            journal.enter_bounded_live_mode(5),
            Err(BoundedModeError::CapacityAboveLimit)
        );
        assert!(!journal.live_is_bounded_for_test());
    }

    /// A first transition over a NON-EMPTY legacy live map is refused with
    /// `LegacyNotEmpty` and the mode is unchanged (no live owner is abandoned).
    #[test]
    fn bounded_refused_when_legacy_nonempty() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = associated_journal(1u128 << 30);
        journal.insert_live_for_test(
            position(SigningKind::Proposal, 1),
            binding(b"legacy-live"),
            false,
        );
        assert_eq!(journal.live_len_for_test(), 1);
        assert_eq!(
            journal.enter_bounded_live_mode(2),
            Err(BoundedModeError::LegacyNotEmpty)
        );
        assert!(!journal.live_is_bounded_for_test());
    }

    /// A first transition over an EMPTY-but-ALLOCATED legacy live map is refused
    /// with `LegacyHasCapacity`: already-allocated map storage is never silently
    /// left uncharged. (`HashMap::clear` retains capacity.)
    #[test]
    fn bounded_refused_when_legacy_empty_but_allocated() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = associated_journal(1u128 << 30);
        journal.insert_live_for_test(
            position(SigningKind::Proposal, 2),
            binding(b"legacy-cap"),
            false,
        );
        journal.clear_legacy_live_keep_capacity_for_test();
        assert_eq!(journal.live_len_for_test(), 0, "map is empty");
        assert!(
            journal.legacy_live_capacity_for_test().unwrap_or(0) > 0,
            "map still owns allocated capacity"
        );
        assert_eq!(
            journal.enter_bounded_live_mode(2),
            Err(BoundedModeError::LegacyHasCapacity)
        );
        assert!(!journal.live_is_bounded_for_test());
    }

    /// Successful transition installs a fixed-capacity container whose backing is
    /// charged exactly once; a repeated IDENTICAL configuration is idempotent and
    /// does NOT re-charge. The standing charge equals the derived full charge.
    #[test]
    fn bounded_transition_succeeds_and_is_idempotent() {
        let _serial = bounded_serial();
        let (journal, acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(acct.current(), 0, "no standing charge before transition");
        assert_eq!(journal.enter_bounded_live_mode(2), Ok(()));
        assert!(journal.live_is_bounded_for_test());
        assert_eq!(journal.live_capacity_for_test(), Some(2));
        assert_eq!(journal.live_backing_shape_for_test(), Some((2, 2)));
        assert_eq!(journal.live_backing_charge_for_test(), Some(container_charge(2)));
        assert_eq!(acct.current(), container_charge(2), "charged exactly once");
        // Idempotent repeat: no re-charge, same container.
        assert_eq!(journal.enter_bounded_live_mode(2), Ok(()));
        assert_eq!(acct.current(), container_charge(2), "no double charge");
        assert_eq!(journal.live_capacity_for_test(), Some(2));
    }

    /// A conflicting capacity after bounded mode is installed is refused with
    /// `CapacityMismatch` WITHOUT changing the existing bounded container or its
    /// standing charge.
    #[test]
    fn bounded_conflicting_capacity_refused_without_change() {
        let _serial = bounded_serial();
        let (journal, acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(2), Ok(()));
        let charged = acct.current();
        assert_eq!(
            journal.enter_bounded_live_mode(3),
            Err(BoundedModeError::CapacityMismatch)
        );
        assert_eq!(journal.live_capacity_for_test(), Some(2), "container unchanged");
        assert_eq!(acct.current(), charged, "standing charge unchanged");
    }

    /// Every shared handle over the SAME store instance observes the installed
    /// bounded mode (the mode is shared ownership-domain state).
    #[test]
    fn bounded_shared_handle_observes_mode() {
        let _serial = bounded_serial();
        let (journal_a, _acct, store) = associated_journal(1u128 << 30);
        let journal_b = attach(store.clone());
        assert!(!journal_b.live_is_bounded_for_test(), "legacy before transition");
        assert_eq!(journal_a.enter_bounded_live_mode(3), Ok(()));
        assert!(journal_b.live_is_bounded_for_test(), "shared handle sees bounded mode");
        assert_eq!(journal_b.live_capacity_for_test(), Some(3));
    }

    /// Real accounting PRESSURE causes refusal BEFORE any allocation, and both the
    /// operational and aggregate ledgers are exactly restored (the admission is
    /// rolled back atomically). The mode stays Legacy.
    #[test]
    fn bounded_admission_pressure_refused_and_restores_ledgers() {
        let _serial = bounded_serial();
        // Ceiling leaves < container_charge(2) of headroom once 64 bytes are held.
        let cap = container_charge(2) + 10;
        let (journal, acct, _store) = associated_journal(cap);
        let _held = acct.reserve(64).expect("hold real pressure");
        let p_before = acct.current();
        let a_before = acct.aggregate().current();
        assert_eq!(
            journal.enter_bounded_live_mode(2),
            Err(BoundedModeError::AdmissionRefused)
        );
        assert_eq!(acct.current(), p_before, "operational ledger restored exactly");
        assert_eq!(acct.aggregate().current(), a_before, "aggregate ledger restored exactly");
        assert!(!journal.live_is_bounded_for_test(), "mode unchanged");
    }

    /// A capacity WITHIN the durable-position limit but whose full byte charge
    /// exceeds the ledger headroom is refused BEFORE allocation (admission), with
    /// both ledgers left at zero. Distinct from durable-limit refusal.
    #[test]
    fn bounded_within_limit_over_byte_headroom_refused() {
        let _serial = bounded_serial();
        // L = 4 is far within the default durable limit, but the ceiling is one
        // byte short of the full container charge for L = 4.
        let cap = container_charge(4) - 1;
        let (journal, acct, _store) = associated_journal(cap);
        assert_eq!(
            journal.enter_bounded_live_mode(4),
            Err(BoundedModeError::AdmissionRefused)
        );
        assert_eq!(acct.current(), 0, "no charge admitted");
        assert_eq!(acct.aggregate().current(), 0);
        assert!(!journal.live_is_bounded_for_test());
    }

    /// INJECTED allocation failure AFTER admission exercises the REAL constructor
    /// cleanup: the admitted coverage is released exactly once (both ledgers return
    /// to zero) and the previous Legacy mode is preserved. This is a deliberately
    /// injected switch, NOT a demonstrated system OOM.
    #[test]
    fn bounded_injected_allocation_failure_cleans_up() {
        let _serial = bounded_serial();
        let (journal, acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(acct.current(), 0);
        // Arm the INJECTED construction-allocation failure for THIS thread only.
        // The RAII guard disarms it on drop (even if an assertion panics), and
        // because the switch is thread-local no unrelated parallel `construct`
        // call on another thread can observe it. `construct` runs synchronously
        // on this thread inside `enter_bounded_live_mode`.
        let outcome = {
            let _inject = InjectedConstructAllocFailure::arm();
            journal.enter_bounded_live_mode(2)
        };
        assert_eq!(outcome, Err(BoundedModeError::Allocation), "INJECTED failure");
        assert_eq!(acct.current(), 0, "admitted coverage released exactly once");
        assert_eq!(acct.aggregate().current(), 0);
        assert!(!journal.live_is_bounded_for_test(), "previous mode preserved");
    }

    /// Measured layout (target-dependent; host x86_64-unknown-linux-gnu, rustc
    /// 1.99.0): the standing backing charge equals the derived
    /// `size_of::<LiveContainer>() + L * size_of::<Slot>()`, and the backing Vec
    /// records `len == capacity == L` (no growth) after construction.
    #[test]
    fn bounded_measured_layout_and_no_growth() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(3), Ok(()));
        assert_eq!(journal.live_backing_shape_for_test(), Some((3, 3)));
        assert_eq!(journal.live_backing_charge_for_test(), Some(container_charge(3)));
        // Fill the container fully; the backing Vec must NOT reallocate.
        for v in 0..3u64 {
            let pos = position(SigningKind::Proposal, 300 + v);
            match journal.reserve_for_sign(&pos, &binding(b"nogrowth")).unwrap() {
                ReservationOutcome::FreshlyReserved(_) => {}
                other => panic!("expected FreshlyReserved, got {:?}", other),
            };
        }
        assert_eq!(journal.live_len_for_test(), 3);
        assert_eq!(
            journal.live_backing_shape_for_test(),
            Some((3, 3)),
            "no growth after filling to capacity"
        );
    }

    /// Fresh insertion readiness, successful acknowledgement, slot reuse after
    /// acknowledged retirement, and full-capacity fresh refusal — all under the
    /// bounded container with no second live table.
    #[test]
    fn bounded_fresh_insert_ack_retire_and_slot_reuse() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(1), Ok(()));
        assert_eq!(journal.live_len_for_test(), 0);

        let pos_a = position(SigningKind::Proposal, 400);
        let b_a = binding(b"reuse-A");
        let cap = reserve_and_invoke(&journal, &pos_a, &b_a);
        assert_eq!(journal.live_len_for_test(), 1);
        journal.record_signed_result(&cap, b"sig-A").unwrap();

        // Container is full: a fresh DIFFERENT position refuses (no new write).
        let pos_b = position(SigningKind::Proposal, 401);
        assert!(matches!(
            journal.reserve_for_sign(&pos_b, &binding(b"reuse-B")).unwrap(),
            ReservationOutcome::LiveCapacityExhausted
        ));

        // Acknowledged retirement frees the slot WITHOUT releasing the backing.
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Ok(RetirementOutcome::Retired)
        );
        assert_eq!(journal.live_len_for_test(), 0);
        assert_eq!(journal.live_backing_charge_for_test(), Some(container_charge(1)));

        // The freed slot is reused by the previously-refused fresh position.
        assert!(matches!(
            journal.reserve_for_sign(&pos_b, &binding(b"reuse-B")).unwrap(),
            ReservationOutcome::FreshlyReserved(_)
        ));
        assert_eq!(journal.live_len_for_test(), 1);
    }

    /// At FULL capacity, existing-position classification (PotentiallySigned /
    /// Conflict) is resolved against the durable record BEFORE fresh-slot
    /// admission, so a full container never suppresses those classifications; only
    /// a genuinely fresh position is refused with `LiveCapacityExhausted`.
    #[test]
    fn bounded_full_capacity_classifies_existing_before_fresh_refusal() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(1), Ok(()));

        let pos_a = position(SigningKind::Proposal, 500);
        let b_a = binding(b"classify-A");
        match journal.reserve_for_sign(&pos_a, &b_a).unwrap() {
            ReservationOutcome::FreshlyReserved(_) => {} // continuation dropped: slot stays occupied
            other => panic!("expected FreshlyReserved, got {:?}", other),
        };
        assert_eq!(journal.live_len_for_test(), 1, "container is full");

        // Same position, same binding -> durable Reserved + live unacked -> PotentiallySigned.
        assert!(matches!(
            journal.reserve_for_sign(&pos_a, &b_a).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
        // Same position, DIFFERENT binding -> Conflict (classified despite full capacity).
        assert!(matches!(
            journal.reserve_for_sign(&pos_a, &binding(b"classify-A2")).unwrap(),
            ReservationOutcome::Conflict
        ));
        // Genuinely fresh position -> LiveCapacityExhausted.
        assert!(matches!(
            journal.reserve_for_sign(&position(SigningKind::Proposal, 501), &binding(b"classify-B")).unwrap(),
            ReservationOutcome::LiveCapacityExhausted
        ));
    }

    /// While an UNACKNOWLEDGED entry fills the only slot, the first slice
    /// conservatively STALLS fresh admission: the capacity cannot be reclaimed
    /// (acknowledged-only retirement), so fresh positions keep refusing. This is
    /// conditional progress after acknowledged retirement, NOT general liveness.
    #[test]
    fn bounded_conservative_stall_while_unacknowledged_fills_capacity() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(1), Ok(()));
        // Reserve + invoke but do NOT acknowledge: the slot stays occupied.
        let pos_a = position(SigningKind::Proposal, 600);
        let _cap = reserve_and_invoke(&journal, &pos_a, &binding(b"stall-A"));
        assert_eq!(journal.live_len_for_test(), 1);
        // The unacknowledged entry cannot be retired, so fresh admission stalls.
        assert!(matches!(
            journal.retire_acknowledged_operation(&_cap),
            Err(RetirementError::NotAcknowledged)
        ));
        assert!(matches!(
            journal.reserve_for_sign(&position(SigningKind::Proposal, 601), &binding(b"stall-B")).unwrap(),
            ReservationOutcome::LiveCapacityExhausted
        ));
        assert_eq!(journal.live_len_for_test(), 1, "capacity remains occupied (stall)");
    }

    /// A stale publication capability (its live entry already retired) is rejected
    /// by retirement with `NoLiveOperation`; nothing is removed.
    #[test]
    fn bounded_stale_capability_rejected() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(1), Ok(()));
        let pos_a = position(SigningKind::Proposal, 700);
        let cap = reserve_and_invoke(&journal, &pos_a, &binding(b"stale-A"));
        journal.record_signed_result(&cap, b"sig-stale").unwrap();
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Ok(RetirementOutcome::Retired)
        );
        // The same capability is now stale: its live entry is gone.
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Err(RetirementError::NoLiveOperation)
        );
    }

    /// The standing container charge persists THROUGH empty periods: after a live
    /// operation is acknowledged and retired, the container is empty but the
    /// backing charge and ledger total are unchanged (release is tied to container
    /// destruction, not to an empty table or a dropped journal handle).
    #[test]
    fn bounded_standing_charge_through_empty_periods() {
        let _serial = bounded_serial();
        let (journal, acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(1), Ok(()));
        let standing = container_charge(1);
        assert_eq!(acct.current(), standing);

        let pos_a = position(SigningKind::Proposal, 800);
        let cap = reserve_and_invoke(&journal, &pos_a, &binding(b"empty-period"));
        journal.record_signed_result(&cap, b"sig-ep").unwrap();
        assert_eq!(
            journal.retire_acknowledged_operation(&cap),
            Ok(RetirementOutcome::Retired)
        );
        assert_eq!(journal.live_len_for_test(), 0, "empty period");
        assert_eq!(acct.current(), standing, "standing charge persists while empty");
        assert_eq!(journal.live_backing_charge_for_test(), Some(standing));
    }

    /// Dropping ONE journal handle does NOT release the backing while the shared
    /// domain lives on; the charge is released EXACTLY at actual container
    /// destruction (when the last owner of the domain is dropped).
    #[test]
    fn bounded_charge_released_only_at_final_destruction() {
        let _serial = bounded_serial();
        let (journal, acct, store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(2), Ok(()));
        let standing = container_charge(2);
        assert_eq!(acct.current(), standing);

        // A second handle shares the domain. Dropping the first does NOT release.
        let journal_b = attach(store.clone());
        drop(journal);
        assert_eq!(acct.current(), standing, "handle drop does not release backing");
        assert!(journal_b.live_is_bounded_for_test());

        // Drop the remaining handle AND the store: the domain (and container) is
        // destroyed, releasing the backing exactly once.
        drop(journal_b);
        drop(store);
        assert_eq!(acct.current(), 0, "released exactly at container destruction");
        assert_eq!(acct.aggregate().current(), 0);
    }

    /// Coexistence model (lighter, honest): the standing container charge and an
    /// independent reservation (modelling a checked-retrieval workspace) coexist
    /// ADDITIVELY on the SAME operational and aggregate ledgers under unchanged
    /// ceilings, each counted exactly once. This is NOT the full retained-
    /// retrieval pipeline, which is out of scope for this slice.
    #[test]
    fn bounded_coexists_with_independent_workspace_charge_each_once() {
        let _serial = bounded_serial();
        let cap = 1u128 << 30;
        let (journal, acct, _store) = associated_journal(cap);
        assert_eq!(journal.enter_bounded_live_mode(4), Ok(()));
        let container = container_charge(4);
        assert_eq!(acct.current(), container);
        assert_eq!(acct.aggregate().current(), container);

        let p_cap = acct.cap();
        let a_cap = acct.aggregate().cap();
        let workspace = 4096u128;
        let res = acct.reserve(workspace).expect("independent workspace reservation");
        assert_eq!(acct.current(), container + workspace, "each owner counted once");
        assert_eq!(acct.aggregate().current(), container + workspace);
        assert_eq!(acct.cap(), p_cap, "operational ceiling unchanged");
        assert_eq!(acct.aggregate().cap(), a_cap, "aggregate ceiling unchanged");

        drop(res);
        assert_eq!(acct.current(), container, "workspace released; container charge remains");
        assert_eq!(acct.aggregate().current(), container);
    }

    /// RUN 422 (this pass) — REAL operation-level checked-retrieval coexistence.
    /// Distinct from the lighter
    /// `bounded_coexists_with_independent_workspace_charge_each_once` model (which
    /// stands in an independent reservation for the workspace): here a GENUINE
    /// stored `Signed` record is retrieved through the REAL
    /// `retrieve_retained_checked` pipeline on the envelope-capable backend, using
    /// the journal's INSTALLED accountant association to admit the workspace,
    /// while the bounded container's standing reservation stays live. The standing
    /// container charge and the admitted retrieval workspace (output + scratch)
    /// coexist ADDITIVELY on the SAME operational and aggregate ledgers under
    /// UNCHANGED ceilings, each counted once. Dropping the workspace in ownership
    /// order (scratch admitted last, released first; then output) restores both
    /// ledgers EXACTLY while the container remains live. The already-live standing
    /// reservation is never counted twice.
    #[test]
    fn bounded_real_checked_retrieval_coexists_and_restores() {
        let _serial = bounded_serial();
        let cap = 1u128 << 30;
        let (journal, acct) = associated_real_journal(cap);
        assert_eq!(journal.enter_bounded_live_mode(2), Ok(()));
        let standing = container_charge(2);
        assert_eq!(acct.current(), standing);
        assert_eq!(acct.aggregate().current(), standing);

        // A genuine stored Signed record created through the REAL signing flow:
        // the live slot holds an acknowledged result and the durable record is
        // Signed. This installs into the bounded container; no charge beyond the
        // standing container reservation is added (the slot is already covered).
        let pos = position(SigningKind::Proposal, 900);
        let b = binding(b"real-retrieve");
        let cap_pub = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap_pub, b"real-sig-bytes").unwrap();
        assert_eq!(journal.live_len_for_test(), 1);
        assert_eq!(
            acct.current(),
            standing,
            "genuine signing adds no charge beyond the standing container"
        );

        // Admit the REAL retrieval workspace from the INSTALLED association.
        let p_cap = acct.cap();
        let a_cap = acct.aggregate().cap();
        let (mut output, mut scratch) = journal.admit_retrieval_workspace().unwrap();
        let out_charge = output.charge();
        let scr_charge = scratch.charge();
        assert!(out_charge > 0 && scr_charge > 0);
        assert_eq!(
            acct.current(),
            standing + out_charge + scr_charge,
            "container + workspace coexist, each counted once"
        );
        assert_eq!(acct.aggregate().current(), standing + out_charge + scr_charge);
        assert_eq!(acct.cap(), p_cap, "operational ceiling unchanged");
        assert_eq!(acct.aggregate().cap(), a_cap, "aggregate ceiling unchanged");

        // Execute the real checked retrieval against the genuine Signed record.
        match journal
            .retrieve_retained_checked(&pos, &b, &mut scratch, &mut output)
            .unwrap()
        {
            RetainedDelivery::Retained(sig) => {
                assert_eq!(sig, &b"real-sig-bytes"[..], "exact returned signature bytes");
            }
            other => panic!("expected Retained, got {other:?}"),
        }
        assert_eq!(output.used(), b"real-sig-bytes".len());

        // Drop the workspace in its actual ownership sequence (scratch first, then
        // output) and assert EXACT ledger restoration while the container is live.
        drop(scratch);
        assert_eq!(acct.current(), standing + out_charge);
        assert_eq!(acct.aggregate().current(), standing + out_charge);
        drop(output);
        assert_eq!(
            acct.current(),
            standing,
            "workspace released; standing container charge remains"
        );
        assert_eq!(acct.aggregate().current(), standing);
        assert!(journal.live_is_bounded_for_test(), "container remains live");
        assert_eq!(journal.live_backing_charge_for_test(), Some(standing));
    }

    /// RUN 422 (this pass) — Obligation 2A: full-capacity retained retry. All `L`
    /// live slots are occupied, INCLUDING an acknowledged `Signed` operation.
    /// Re-presenting that exact operation yields `ExactRetryRetained` with the
    /// exact bytes and installs NO fresh continuation, NO extra live entry, and NO
    /// durable-position increment. A genuinely fresh position still refuses with
    /// `LiveCapacityExhausted`. Conflict and PotentiallySigned classification at
    /// full capacity are covered SEPARATELY by
    /// `bounded_full_capacity_classifies_existing_before_fresh_refusal`.
    #[test]
    fn bounded_full_capacity_exact_retry_retained_without_new_position() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(1), Ok(()));

        // Fill the only slot with an acknowledged Signed operation.
        let pos = position(SigningKind::Proposal, 950);
        let b = binding(b"retry-retained");
        let cap_pub = reserve_and_invoke(&journal, &pos, &b);
        journal.record_signed_result(&cap_pub, b"retry-sig").unwrap();
        assert_eq!(journal.live_len_for_test(), 1, "container is full");

        let ops_before = journal.next_operation_id_for_test();
        let positions_before = journal.reserved_positions_for_test();

        // Re-present the SAME acknowledged operation: exact retry with exact bytes.
        match journal.reserve_for_sign(&pos, &b).unwrap() {
            ReservationOutcome::ExactRetryRetained(sig) => {
                assert_eq!(sig.as_slice(), b"retry-sig", "exact retained bytes on retry");
            }
            other => panic!("expected ExactRetryRetained, got {:?}", other),
        }

        // No fresh continuation (operation-id source unchanged), no extra live
        // entry, and no durable-position increment.
        assert_eq!(
            journal.next_operation_id_for_test(),
            ops_before,
            "no fresh continuation minted"
        );
        assert_eq!(journal.live_len_for_test(), 1, "no extra live entry");
        assert_eq!(
            journal.reserved_positions_for_test(),
            positions_before,
            "no durable-position increment"
        );

        // A genuinely fresh DIFFERENT position is still refused: capacity is full.
        assert!(matches!(
            journal
                .reserve_for_sign(&position(SigningKind::Proposal, 951), &binding(b"retry-fresh"))
                .unwrap(),
            ReservationOutcome::LiveCapacityExhausted
        ));
        assert_eq!(journal.live_len_for_test(), 1);
    }

    /// RUN 422 (this pass) — Obligation 2B (before-write route). In bounded mode
    /// with a FRESH slot available, a fault BEFORE any write (the existing
    /// `set_fail_writes` route, mirroring the legacy
    /// `read_and_write_failures_yield_no_permit`) yields NO successful fresh
    /// continuation and installs NO live entry on the failed return. The
    /// uncertainty bookkeeping is preserved (the atomic reservation write was
    /// attempted), and nothing durable was written — the next attempt is a genuine
    /// fresh reservation, not a conflict.
    #[test]
    fn bounded_fresh_write_before_write_fault_installs_no_entry() {
        let _serial = bounded_serial();
        let (journal, _acct, store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(2), Ok(()));
        assert_eq!(journal.live_len_for_test(), 0, "a fresh slot is available");

        let pos = position(SigningKind::Proposal, 970);
        let b = binding(b"before-write");
        let (_, writes_before, _) = store.storage_calls();

        // Fault BEFORE any write: the combined record+metadata synced write fails
        // without mutating storage.
        store.set_fail_writes(true);
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b),
            Err(JournalError::Storage(_))
        ));
        store.set_fail_writes(false);

        // No live entry installed, uncertainty latched, and — the decisive
        // durable-effect signal — NO record is readable: the before-write fault
        // left storage unmutated (not inferred from the error, which is identical
        // in shape to the write-then-error route).
        assert_eq!(journal.live_len_for_test(), 0, "no installed live entry");
        assert!(journal.accounting_uncertain_for_test(), "uncertainty preserved");
        // The write entrypoint WAS reached (the fault is a genuine write attempt,
        // refused before mutating storage), yet nothing became readable.
        let (_, writes_after, _) = store.storage_calls();
        assert_eq!(
            writes_after,
            writes_before + 1,
            "the combined record+metadata write entrypoint was reached"
        );
        assert!(
            store.get_signing_record(&pos.storage_key()).unwrap().is_none(),
            "no durable reservation record exists (before-write route)"
        );

        // The fresh slot is still available: a subsequent attempt is a genuine
        // fresh reservation (the before-write failure left nothing behind).
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::FreshlyReserved(_)
        ));
        assert_eq!(journal.live_len_for_test(), 1);
    }

    /// RUN 422 (this pass) — Obligation 2B (write-then-error route). In bounded
    /// mode with a FRESH slot available, a write that becomes readable but whose
    /// durability acknowledgement is uncertain (the existing `set_store_then_error`
    /// route) yields NO successful fresh continuation and installs NO live entry.
    /// The uncertainty bookkeeping is preserved, and a durable write DID reach
    /// storage — proven DIRECTLY by the surviving readable record (NOT inferred
    /// from the error, and NOT inferred away by it). Subsequent handling must NOT
    /// treat the surviving reservation as a new unused position: re-presenting it
    /// classifies `PotentiallySigned` (readable `Reserved` bytes are not a clean
    /// fresh slot), NOT `FreshlyReserved` nor `LiveCapacityExhausted`. This is an
    /// IN-MEMORY model; no crash-durability claim is made.
    #[test]
    fn bounded_fresh_write_then_error_leaves_surviving_reservation_not_new() {
        let _serial = bounded_serial();
        let (journal, _acct, store) = associated_journal(1u128 << 30);
        assert_eq!(journal.enter_bounded_live_mode(2), Ok(()));
        assert_eq!(journal.live_len_for_test(), 0, "a fresh slot is available");

        let pos = position(SigningKind::Proposal, 980);
        let b = binding(b"write-then-error");
        let (_, writes_before, _) = store.storage_calls();

        // Write-then-error: both record and metadata bodies become readable, then
        // the synced acknowledgement is reported uncertain (error).
        store.set_store_then_error(true);
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b),
            Err(JournalError::Storage(_))
        ));
        store.set_store_then_error(false);

        // No live entry installed and uncertainty latched.
        assert_eq!(journal.live_len_for_test(), 0, "no installed live entry");
        assert!(journal.accounting_uncertain_for_test(), "uncertainty preserved");
        // The combined record+metadata write entrypoint WAS reached (not inferred
        // from the error) ...
        let (_, writes_after, _) = store.storage_calls();
        assert_eq!(
            writes_after,
            writes_before + 1,
            "the combined record+metadata write entrypoint was reached"
        );
        // ... and the surviving record is DIRECTLY readable: a durable write
        // reached storage. This is the decisive signal distinguishing this route
        // from the before-write route, independent of the returned error.
        assert!(
            store.get_signing_record(&pos.storage_key()).unwrap().is_some(),
            "the surviving reservation record is readable"
        );

        // Subsequent handling must not treat the surviving reservation as a new
        // unused position. Re-presenting the SAME position classifies it as an
        // existing (potentially-signed) reservation — never a fresh slot nor a
        // capacity refusal. (The uncertainty latch is cleared by reconciliation
        // against the durable metadata, which is a consistent outcome of the one
        // failed batch.)
        assert!(matches!(
            journal.reserve_for_sign(&pos, &b).unwrap(),
            ReservationOutcome::PotentiallySigned
        ));
        assert_eq!(
            journal.live_len_for_test(),
            0,
            "the surviving reservation is not re-signed into a live slot"
        );
    }

    // =======================================================================
    // RUN 422 — isolated admitted fresh-reservation route: envelope-capable,
    // fault-injecting fixture and focused evidence tests.
    //
    // `EnvelopeModelStore` is the envelope-capable analogue of `ModelStore`: it
    // SYNTHESIZES the outer storage checksum on read (so the admitted route's
    // classification read observes both checksum layers), stores records
    // record-only + metadata raw under one lock on the atomic envelope-pair
    // write, and carries the `fail_writes` / `store_then_error` fault injectors
    // plus `writes` / `record_writes` / `reads` counters so a test can observe a
    // before-write refusal versus a write-then-error durable effect SEPARATELY.
    // It provides NO power-loss durability.
    // =======================================================================

    #[derive(Default)]
    struct EnvelopeModelStore {
        map: Arc<RwLock<StdHashMap<Vec<u8>, Vec<u8>>>>,
        fail_writes: RwLock<bool>,
        store_then_error: RwLock<bool>,
        reads: std::sync::atomic::AtomicUsize,
        writes: std::sync::atomic::AtomicUsize,
        record_writes: std::sync::atomic::AtomicUsize,
        domain: std::sync::OnceLock<Arc<SigningOwnershipDomain>>,
    }

    impl EnvelopeModelStore {
        fn new() -> Self {
            Self::default()
        }
        fn set_fail_writes(&self, v: bool) {
            *self.fail_writes.write().unwrap() = v;
        }
        fn set_store_then_error(&self, v: bool) {
            *self.store_then_error.write().unwrap() = v;
        }
        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }
        #[allow(dead_code)]
        fn writes(&self) -> usize {
            self.writes.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn record_writes(&self) -> usize {
            self.record_writes.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl SigningJournalStorage for EnvelopeModelStore {
        fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let m = self.map.read().unwrap();
            match m.get(key) {
                None => Ok(None),
                Some(v) => {
                    if v.len() > MAX_RECORD_LEN {
                        return Err(StorageError::Corruption("record exceeds bound".to_string()));
                    }
                    Ok(Some(v.clone()))
                }
            }
        }
        fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.map.write().unwrap().insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let m = self.map.read().unwrap();
            Ok(m.get(MODEL_META_KEY).cloned())
        }
        fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut m = self.map.write().unwrap();
            m.insert(record_key.to_vec(), record_value.to_vec());
            m.insert(MODEL_META_KEY.to_vec(), metadata_value.to_vec());
            Ok(())
        }
        fn for_each_signing_namespace_entry(
            &self,
            visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
        ) -> Result<(), StorageError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let m = self.map.read().unwrap();
            for (k, v) in m.iter() {
                if k.as_slice() == MODEL_META_KEY {
                    continue;
                }
                visitor(k, v)?;
            }
            Ok(())
        }
        fn signing_ownership_domain(&self) -> Arc<SigningOwnershipDomain> {
            self.domain
                .get_or_init(SigningOwnershipDomain::new)
                .clone()
        }
        fn read_signing_envelope_into(
            &self,
            journal_key: &[u8],
            dst: &mut [u8],
        ) -> Result<Option<usize>, BoundedStorageError> {
            use crate::signing_journal_admission::OUTER_CRC_LEN;
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let m = self.map.read().unwrap();
            match m.get(journal_key) {
                None => Ok(None),
                Some(record) => {
                    let total = OUTER_CRC_LEN + record.len();
                    if total > dst.len() {
                        return Err(BoundedStorageError::CapacityExceeded {
                            stored_len: total,
                            capacity: dst.len(),
                        });
                    }
                    let crc = crate::storage::signing_journal_crc32(record);
                    dst[..OUTER_CRC_LEN].copy_from_slice(&crc.to_be_bytes());
                    dst[OUTER_CRC_LEN..total].copy_from_slice(record);
                    Ok(Some(total))
                }
            }
        }
        fn reissue_signing_envelope_synced(
            &self,
            journal_key: &[u8],
            envelope: &[u8],
        ) -> Result<(), BoundedStorageError> {
            use crate::signing_journal_admission::OUTER_CRC_LEN;
            if envelope.len() < OUTER_CRC_LEN {
                return Err(BoundedStorageError::Corruption(BoundedDiag::EnvelopeInvalid));
            }
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.map
                .write()
                .unwrap()
                .insert(journal_key.to_vec(), envelope[OUTER_CRC_LEN..].to_vec());
            Ok(())
        }
        fn put_signing_envelope_and_metadata_synced(
            &self,
            record_key: &[u8],
            record_envelope: &[u8],
            metadata_envelope: &[u8],
        ) -> Result<(), BoundedStorageError> {
            use crate::signing_journal_admission::OUTER_CRC_LEN;
            self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Same fixed-framing preflight the durable/in-memory backends apply,
            // BEFORE any fault branch, model-owned copy, or map mutation.
            crate::storage::preflight_framed_envelope_pair(record_envelope, metadata_envelope)?;
            if record_key.len() != crate::signing_journal_admission::JOURNAL_KEY_LEN {
                return Err(BoundedStorageError::CapacityExceeded {
                    stored_len: record_key.len(),
                    capacity: crate::signing_journal_admission::JOURNAL_KEY_LEN,
                });
            }
            // Fail BEFORE any write: neither value is mutated and record_writes is
            // not advanced, so a test observes a before-write refusal distinctly.
            if *self.fail_writes.read().unwrap() {
                return Err(BoundedStorageError::Io(BoundedDiag::WriteIo));
            }
            let record_body = record_envelope[OUTER_CRC_LEN..].to_vec();
            let metadata_body = metadata_envelope[OUTER_CRC_LEN..].to_vec();
            // store_then_error: BOTH values become readable under one lock, but the
            // durability acknowledgement is reported uncertain (error). record_writes
            // is advanced so a test distinguishes write-then-error from before-write.
            if *self.store_then_error.read().unwrap() {
                self.record_writes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut m = self.map.write().unwrap();
                m.insert(record_key.to_vec(), record_body);
                m.insert(MODEL_META_KEY.to_vec(), metadata_body);
                return Err(BoundedStorageError::Io(BoundedDiag::WriteIo));
            }
            self.record_writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut m = self.map.write().unwrap();
            m.insert(record_key.to_vec(), record_body);
            m.insert(MODEL_META_KEY.to_vec(), metadata_body);
            Ok(())
        }
    }

    /// Build a real, established, associated, BOUNDED journal over the
    /// envelope-capable fault-injecting fixture with durable limit `limit`, live
    /// capacity `live_cap`, and operational/aggregate ceiling `cap`. Returns the
    /// journal, its accountant handle, and the concrete store `Arc` (held so a
    /// test can inject faults and read counters).
    fn envelope_journal_with_limit(
        limit: u64,
        live_cap: usize,
        cap: u128,
    ) -> (SigningReservationJournal, SharedAccountant, Arc<EnvelopeModelStore>) {
        let store = Arc::new(EnvelopeModelStore::new());
        let journal = SigningReservationJournal::initialize(
            store.clone() as Arc<dyn SigningJournalStorage>,
            limit,
        )
        .expect("initialize envelope-capable backend");
        let agg = AggregateAuthority::new();
        agg.bind(cap).expect("bind aggregate ceiling");
        let acct = SharedAccountant::new(agg);
        acct.bind_cap(cap).expect("bind operational sub-ledger");
        journal
            .install_accountant_association(&acct)
            .expect("install association");
        journal
            .enter_bounded_live_mode(live_cap)
            .expect("enter bounded live mode");
        (journal, acct, store)
    }

    fn envelope_journal(
        live_cap: usize,
        cap: u128,
    ) -> (SigningReservationJournal, SharedAccountant, Arc<EnvelopeModelStore>) {
        envelope_journal_with_limit(DEFAULT_MAX_RESERVED_POSITIONS, live_cap, cap)
    }

    /// Prerequisite refusals happen BEFORE any storage access: an unestablished
    /// handle refuses `NotEstablished` and a legacy (non-bounded) established
    /// handle refuses `NotBoundedMode` — in both cases no envelope read occurs.
    #[test]
    fn admitted_reserve_prerequisite_refusals_before_io() {
        let _serial = bounded_serial();
        // Unestablished: build an admitted-shaped workspace against a throwaway
        // accountant and confirm NotEstablished with zero reads.
        let store = Arc::new(EnvelopeModelStore::new());
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store.clone() as Arc<dyn SigningJournalStorage>,
        );
        let agg = AggregateAuthority::new();
        agg.bind(1u128 << 40).unwrap();
        let acct = SharedAccountant::new(agg);
        acct.bind_cap(1u128 << 40).unwrap();
        let ws = crate::signing_journal_admission::ReserveWorkspaceOwner::from_installed(
            acct.clone(),
        )
        .admit()
        .expect("admit workspace");
        let reads_before = store.reads();
        let p = position(SigningKind::Proposal, 1);
        let b = binding(b"x");
        assert_eq!(
            journal.reserve_for_sign_admitted(&p, &b, ws).unwrap_err(),
            AdmittedReserveError::NotEstablished
        );
        assert_eq!(store.reads(), reads_before, "no storage read before prereq");

        // Established but LEGACY (never entered bounded mode): NotBoundedMode.
        let (legacy, lacct, lstore) = {
            let store = Arc::new(EnvelopeModelStore::new());
            let journal = SigningReservationJournal::initialize(
                store.clone() as Arc<dyn SigningJournalStorage>,
                DEFAULT_MAX_RESERVED_POSITIONS,
            )
            .unwrap();
            let agg = AggregateAuthority::new();
            agg.bind(1u128 << 40).unwrap();
            let acct = SharedAccountant::new(agg);
            acct.bind_cap(1u128 << 40).unwrap();
            journal.install_accountant_association(&acct).unwrap();
            (journal, acct, store)
        };
        let ws = legacy.admit_reserve_workspace().expect("admit");
        let reads_before = lstore.reads();
        assert_eq!(
            legacy.reserve_for_sign_admitted(&p, &b, ws).unwrap_err(),
            AdmittedReserveError::NotBoundedMode
        );
        assert_eq!(lstore.reads(), reads_before, "no storage read before prereq");
        let _ = lacct;
    }

    /// A workspace covered by a FOREIGN accountant is refused `ForeignWorkspace`
    /// BEFORE any storage access, even on a fully-established bounded journal.
    #[test]
    fn admitted_reserve_foreign_workspace_refused_before_io() {
        let _serial = bounded_serial();
        let (journal, _acct, store) = envelope_journal(4, 1u128 << 40);
        // A separate, foreign accountant funds a workspace that journal does not
        // recognize as its installed ledger.
        let fagg = AggregateAuthority::new();
        fagg.bind(1u128 << 40).unwrap();
        let facct = SharedAccountant::new(fagg);
        facct.bind_cap(1u128 << 40).unwrap();
        let foreign_ws =
            crate::signing_journal_admission::ReserveWorkspaceOwner::from_installed(facct)
                .admit()
                .expect("admit foreign workspace");
        let reads_before = store.reads();
        let p = position(SigningKind::Proposal, 1);
        let b = binding(b"x");
        assert_eq!(
            journal.reserve_for_sign_admitted(&p, &b, foreign_ws).unwrap_err(),
            AdmittedReserveError::ForeignWorkspace
        );
        assert_eq!(store.reads(), reads_before, "no storage read before refusal");
    }

    /// Admission partial-rollback: when the continuation reservation cannot be
    /// admitted, the working-set reservation is released (both ledgers unchanged),
    /// and after the pressure is relieved an identical admission succeeds.
    #[test]
    fn admitted_workspace_partial_rollback_then_relief_retry() {
        let _serial = bounded_serial();
        use crate::signing_journal_admission::{cont_charge, reserve_work_charge};
        // Enter bounded mode first to consume the container charge, then size the
        // ceiling so that exactly ONE of work+cont fits after a small blocker.
        let container = container_charge(1);
        let headroom = reserve_work_charge() + cont_charge();
        let cap = container + headroom;
        let (journal, acct, _store) = envelope_journal(1, cap);
        let used_after_container = acct.current();
        assert_eq!(used_after_container, container, "only container charged so far");
        // A blocker leaves room for the working-set reservation but not for the
        // continuation reservation, so admission rolls the first back.
        let blocker = acct.reserve(cont_charge()).expect("blocker reserves");
        assert!(
            journal.admit_reserve_workspace().is_err(),
            "continuation admission refused under pressure"
        );
        assert_eq!(
            acct.current(),
            container + cont_charge(),
            "rollback released the working-set reservation; only container + blocker remain"
        );
        // Relieve the pressure and retry: the identical admission now succeeds.
        blocker.release_now();
        let ws = journal
            .admit_reserve_workspace()
            .expect("admission succeeds after relief");
        assert_eq!(
            acct.current(),
            container + reserve_work_charge() + cont_charge(),
            "both coverages held after successful admission"
        );
        drop(ws);
        assert_eq!(acct.current(), container, "workspace drop releases both coverages");
    }

    /// Fresh acknowledgement advances the durable counter, installs a live entry,
    /// and returns a covered continuation whose coverage equals `cont_charge()`.
    #[test]
    fn admitted_fresh_reservation_acknowledged() {
        let _serial = bounded_serial();
        use crate::signing_journal_admission::cont_charge;
        let (journal, acct, store) = envelope_journal(4, 1u128 << 40);
        let p = position(SigningKind::Proposal, 1);
        let b = binding(b"m");
        let ws = journal.admit_reserve_workspace().expect("admit");
        let record_writes_before = store.record_writes();
        let outcome = journal.reserve_for_sign_admitted(&p, &b, ws).expect("ok");
        let cont = match outcome {
            AdmittedReservationOutcome::FreshlyReserved(c) => c,
            other => panic!("expected FreshlyReserved, got {:?}", other),
        };
        assert_eq!(cont.position(), p);
        assert!(cont.is_covered_by(&acct), "continuation covered by installed acct");
        assert_eq!(cont.coverage_charge(), cont_charge(), "coverage == cont_charge()");
        assert_eq!(journal.reserved_positions_for_test(), 1, "counter advanced");
        assert_eq!(journal.live_len_for_test(), 1, "live entry installed");
        assert_eq!(
            store.record_writes(),
            record_writes_before + 1,
            "exactly one durable envelope-pair write"
        );
    }

    /// Existing-position classification is NON-delivering: a durable `Reserved`
    /// record classifies as `ReservedPotentiallySigned`, and a different binding
    /// at the same position classifies as `Conflict`.
    #[test]
    fn admitted_existing_position_classification() {
        let _serial = bounded_serial();
        let (journal, _acct, _store) = envelope_journal(4, 1u128 << 40);
        let p = position(SigningKind::Proposal, 2);
        let b = binding(b"first");
        let ws = journal.admit_reserve_workspace().unwrap();
        let _ = journal.reserve_for_sign_admitted(&p, &b, ws).unwrap();
        // Same position + same binding: existing durable Reserved record.
        let ws = journal.admit_reserve_workspace().unwrap();
        assert!(matches!(
            journal.reserve_for_sign_admitted(&p, &b, ws).unwrap(),
            AdmittedReservationOutcome::ReservedPotentiallySigned
        ));
        // Same position + DIFFERENT binding: conflict.
        let ws = journal.admit_reserve_workspace().unwrap();
        assert!(matches!(
            journal
                .reserve_for_sign_admitted(&p, &binding(b"second"), ws)
                .unwrap(),
            AdmittedReservationOutcome::Conflict
        ));
    }

    /// Capacity exhaustion: the durable journal-wide limit yields `Exhausted`;
    /// a full bounded live container yields `LiveCapacityExhausted`.
    #[test]
    fn admitted_capacity_exhaustion() {
        let _serial = bounded_serial();
        // Durable limit 1: the second DISTINCT fresh position is Exhausted.
        {
            let (journal, _acct, _store) = envelope_journal_with_limit(1, 1, 1u128 << 40);
            let ws = journal.admit_reserve_workspace().unwrap();
            let _ = journal
                .reserve_for_sign_admitted(&position(SigningKind::Proposal, 1), &binding(b"a"), ws)
                .unwrap();
            let ws = journal.admit_reserve_workspace().unwrap();
            assert!(matches!(
                journal
                    .reserve_for_sign_admitted(&position(SigningKind::Proposal, 2), &binding(b"b"), ws)
                    .unwrap(),
                AdmittedReservationOutcome::Exhausted
            ));
        }
        // Live capacity 1 (limit large): with one un-retired live op, a second
        // fresh position is refused LiveCapacityExhausted.
        {
            let (journal, _acct, _store) = envelope_journal_with_limit(1_000, 1, 1u128 << 40);
            let ws = journal.admit_reserve_workspace().unwrap();
            let _ = journal
                .reserve_for_sign_admitted(&position(SigningKind::Proposal, 1), &binding(b"a"), ws)
                .unwrap();
            let ws = journal.admit_reserve_workspace().unwrap();
            assert!(matches!(
                journal
                    .reserve_for_sign_admitted(&position(SigningKind::Proposal, 2), &binding(b"b"), ws)
                    .unwrap(),
                AdmittedReservationOutcome::LiveCapacityExhausted
            ));
        }
    }

    /// A before-write failure advances NO durable record and NO counter but
    /// latches accounting uncertain; a write-then-error advances the durable
    /// record write yet still no counter — both observed SEPARATELY via the
    /// `record_writes` counter — and subsequent admitted calls stay blocked
    /// (`AccountingUncertain`) without implicit legacy reconciliation.
    #[test]
    fn admitted_before_write_vs_write_then_error() {
        let _serial = bounded_serial();
        // Fail BEFORE write.
        {
            let (journal, _acct, store) = envelope_journal(4, 1u128 << 40);
            store.set_fail_writes(true);
            let ws = journal.admit_reserve_workspace().unwrap();
            let p = position(SigningKind::Proposal, 1);
            let b = binding(b"m");
            assert_eq!(
                journal.reserve_for_sign_admitted(&p, &b, ws).unwrap_err(),
                AdmittedReserveError::Storage(BoundedDiag::WriteIo)
            );
            assert_eq!(store.record_writes(), 0, "no durable record write");
            assert_eq!(journal.reserved_positions_for_test(), 0, "counter not advanced");
            store.set_fail_writes(false);
            // Blocked thereafter, with no implicit reconciliation.
            let ws = journal.admit_reserve_workspace().unwrap();
            assert!(matches!(
                journal.reserve_for_sign_admitted(&p, &b, ws).unwrap(),
                AdmittedReservationOutcome::AccountingUncertain
            ));
        }
        // STORE then error: durable record write observed, counter still unmoved.
        {
            let (journal, _acct, store) = envelope_journal(4, 1u128 << 40);
            store.set_store_then_error(true);
            let ws = journal.admit_reserve_workspace().unwrap();
            let p = position(SigningKind::Proposal, 1);
            let b = binding(b"m");
            assert_eq!(
                journal.reserve_for_sign_admitted(&p, &b, ws).unwrap_err(),
                AdmittedReserveError::Storage(BoundedDiag::WriteIo)
            );
            assert_eq!(store.record_writes(), 1, "durable record write DID land");
            assert_eq!(journal.reserved_positions_for_test(), 0, "counter not advanced");
            store.set_store_then_error(false);
            let ws = journal.admit_reserve_workspace().unwrap();
            assert!(matches!(
                journal.reserve_for_sign_admitted(&p, &b, ws).unwrap(),
                AdmittedReservationOutcome::AccountingUncertain
            ));
        }
    }

    /// Two real journal domains with the SAME position/binding/operation-id: a
    /// continuation from domain A, handed to domain B's admitted consume, is
    /// refused `ForeignDomain` BEFORE either live state changes — proved by both
    /// legitimate consumptions still succeeding afterwards.
    #[test]
    fn admitted_foreign_continuation_refused_before_live_change() {
        let _serial = bounded_serial();
        let (ja, _aa, _sa) = envelope_journal(4, 1u128 << 40);
        let (jb, _ab, _sb) = envelope_journal(4, 1u128 << 40);
        let p = position(SigningKind::Proposal, 1);
        let b = binding(b"same");
        // A: fresh continuation.
        let ws = ja.admit_reserve_workspace().unwrap();
        let cont_a = match ja.reserve_for_sign_admitted(&p, &b, ws).unwrap() {
            AdmittedReservationOutcome::FreshlyReserved(c) => c,
            other => panic!("A expected FreshlyReserved, got {:?}", other),
        };
        // B: fresh continuation for the SAME position/binding/operation-id.
        let ws = jb.admit_reserve_workspace().unwrap();
        let cont_b = match jb.reserve_for_sign_admitted(&p, &b, ws).unwrap() {
            AdmittedReservationOutcome::FreshlyReserved(c) => c,
            other => panic!("B expected FreshlyReserved, got {:?}", other),
        };
        // A's continuation is foreign to B: refused before B's live entry changes.
        assert_eq!(
            jb.consume_for_signing_admitted(cont_a)
                .err()
                .expect("foreign refused"),
            AdmittedConsumeError::ForeignDomain
        );
        // Neither live state was disturbed: both legitimate consumptions succeed.
        assert!(
            jb.consume_for_signing_admitted(cont_b).is_ok(),
            "B's own fresh continuation still consumable"
        );
    }

    /// Continuous coverage: the continuation keeps its coverage after the rest of
    /// the workspace drops, carries it UNCHANGED through consumption into the
    /// publication capability (no release/recharge), and releases it only when the
    /// wrapper finally drops — retirement in between preserves that coverage.
    #[test]
    fn admitted_coverage_persists_through_consumption_and_retirement() {
        let _serial = bounded_serial();
        use crate::signing_journal_admission::cont_charge;
        let (journal, acct, _store) = envelope_journal(4, 1u128 << 40);
        let container = container_charge(4);
        assert_eq!(acct.current(), container, "only the container is charged initially");
        let p = position(SigningKind::Proposal, 1);
        let b = binding(b"m");
        let ws = journal.admit_reserve_workspace().unwrap();
        let cont = match journal.reserve_for_sign_admitted(&p, &b, ws).unwrap() {
            AdmittedReservationOutcome::FreshlyReserved(c) => c,
            other => panic!("expected FreshlyReserved, got {:?}", other),
        };
        // The workspace (and its working-set coverage) has dropped, but the
        // continuation's coverage persists.
        assert_eq!(
            acct.current(),
            container + cont_charge(),
            "continuation coverage persists after workspace cleanup"
        );
        // Consumption transfers the SAME coverage with no release/recharge.
        let cap = journal.consume_for_signing_admitted(cont).expect("consume");
        assert_eq!(
            acct.current(),
            container + cont_charge(),
            "coverage unchanged across consumption (no release/recharge)"
        );
        assert_eq!(cap.coverage_charge(), cont_charge());
        assert!(cap.is_covered_by(&acct));
        // Drive the live op to acknowledged so retirement is accepted, WITHOUT
        // disturbing the wrapper's coverage. The test module can access the raw
        // inner capability to publish through the legacy checked path.
        journal
            .record_signed_result(&cap.inner, b"sig")
            .expect("record signed result");
        assert!(journal.retire_admitted(&cap).is_ok(), "retire acknowledged op");
        assert_eq!(
            acct.current(),
            container + cont_charge(),
            "retirement preserves the wrapper's coverage"
        );
        // Final release happens only on wrapper drop.
        drop(cap);
        assert_eq!(acct.current(), container, "wrapper drop releases the coverage");
    }

    #[test]
    fn admitted_measured_layout_operands() {
        // Source-derived layout evidence: report the ACTUAL `size_of` operands of
        // the conservative working-set and continuation-coverage charges on the
        // host toolchain, and assert the internal relations the charge formulas
        // rely on. These are structural sizes (read via `core::mem::size_of`),
        // NOT measured physical stack usage.
        use crate::signing_journal_admission::{
            cont_charge, reserve_work_charge, AdmittedReserveWorkspace, BACKEND_KEY_LEN,
            META_ENVELOPE_LEN, RESERVED_ENVELOPE_LEN,
        };
        let aw = core::mem::size_of::<AdmittedReserveWorkspace>();
        let brv = core::mem::size_of::<BorrowedRecordView<'static>>();
        let cont = core::mem::size_of::<AdmittedContinuation>();
        let ret =
            core::mem::size_of::<Result<AdmittedReservationOutcome, AdmittedReserveError>>();
        let pubret = core::mem::size_of::<
            Result<AdmittedPublicationCapability, AdmittedConsumeError>,
        >();
        let conv = cont + pubret;
        eprintln!(
            "ADMITTED_LAYOUT size_of: AdmittedReserveWorkspace={} BorrowedRecordView={} \
             AdmittedContinuation={} ReserveReturn={} PublishReturn={} \
             RESERVED_ENVELOPE_LEN={} META_ENVELOPE_LEN={} reserve_work_charge={} \
             cont_charge={} (conv={})",
            aw, brv, cont, ret, pubret, RESERVED_ENVELOPE_LEN, META_ENVELOPE_LEN,
            reserve_work_charge(), cont_charge(), conv,
        );
        // The continuation coverage is the conservative MAX over the reservation
        // return and the continuation-to-publication conversion representations;
        // the conversion owns no additional covered object beyond those.
        assert_eq!(cont_charge(), core::cmp::max(ret, conv) as u128);
        // The working-set charge dominates every working buffer it must cover.
        assert!(
            reserve_work_charge()
                >= (aw + BACKEND_KEY_LEN + brv + core::mem::size_of::<u32>()
                    + RESERVED_ENVELOPE_LEN + META_ENVELOPE_LEN) as u128
        );
    }
}
