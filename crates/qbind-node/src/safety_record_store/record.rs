//! Run 422 D7-D14 — decoded logical safety-record representation and the single
//! decoded-generation wrapper used for in-memory accounting (§ 13.2 / § 13.4 /
//! § 13.7A).
//!
//! Absent values are represented **only** by their presence discriminants
//! (`Option`). No absent QC, committed block, height-zero anchor, or constituent
//! signature is ever manufactured.

use qbind_consensus::ids::ValidatorId;

/// Logical QC (identity-only: `block_id`/`view`/`signers`, no signatures).
pub type LogicalQc = qbind_consensus::qc::QuorumCertificate<[u8; 32]>;
/// Wire QC (carries `height`/`round`/`epoch`/`chain_id`/`block_id` + bitmap +
/// signatures + `suite_id`); the only form stage-2 verification could consume.
pub type WireQc = qbind_wire::consensus::QuorumCertificate;
/// Serialized timeout certificate retained for a TC-derived raise.
pub type TimeoutCert = qbind_consensus::timeout::TimeoutCertificate<[u8; 32]>;
/// A single signed timeout message carried inside a [`TimeoutCert`].
pub type TimeoutMessage = qbind_consensus::timeout::TimeoutMsg<[u8; 32]>;

/// Stage-2 evidence verification outcome. Stage 2 (wire-QC signature
/// verification against the trusted context) is **not** wired on the load path;
/// every validated record is therefore carried `Unverified` and must never
/// satisfy a verified-evidence prerequisite (§ 13.3 / § 13.3A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStatus {
    /// Stage 2 was not run; the certificate is carried unverified.
    Unverified,
}

/// A committed-state anchor, present **only** in the
/// `Locked`-with-committed-anchor sub-case (§ 13.2 / § 13.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedAnchor {
    pub block_id: [u8; 32],
    pub height: u64,
}

/// The discriminated supporting evidence (§ 13.2): a `QcDerived` wire QC, or a
/// `TcDerived` logical `high_qc` plus the retained serialized `TimeoutCertificate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportingEvidence {
    /// Wire QC — the stage-2-verifiable form.
    QcDerived(WireQc),
    /// Logical `high_qc` identity + the retained `TimeoutCertificate`
    /// (stage-2-unverifiable from TC inputs; carried unverified).
    TcDerived { high_qc: LogicalQc, tc: TimeoutCert },
}

/// Evidence discriminant tag used in the serialized form (`D_ev`, § 13.2A(b)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceDiscriminant {
    /// `BootstrapNoLock` — no lock, no evidence.
    Bootstrap = 0,
    /// `Locked` with a wire QC.
    QcDerived = 1,
    /// `Locked` with a logical `high_qc` + retained `TimeoutCertificate`.
    TcDerived = 2,
}

/// A validated `Locked` record (either committed-anchor or no-commit sub-case).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedRecord {
    pub lock_block_id: [u8; 32],
    pub lock_view: u64,
    pub evidence_lock_binding: [u8; 32],
    pub authority_context_ref: [u8; 32],
    /// Present only for the committed-anchor sub-case; absent by variant for the
    /// no-commit sub-case (never a coerced height-zero).
    pub committed_anchor: Option<CommittedAnchor>,
    pub predecessor_ref: Option<u64>,
    pub evidence: SupportingEvidence,
}

/// The decoded safety record in one of its two explicit variants (§ 13.4).
///
/// The `Locked` variant is deliberately larger than `BootstrapNoLock`; the
/// component's memory bound is enforced on the separate [`RetainedGeneration`]
/// wrapper (§ 13.7A), not on this logical enum, so the variant size difference
/// is intentional rather than boxed.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyRecord {
    /// A validator that has legitimately not yet locked.
    BootstrapNoLock {
        authority_context_ref: [u8; 32],
        predecessor_ref: Option<u64>,
    },
    /// An effective lock has been published.
    Locked(LockedRecord),
}

/// The full decoded record including common identity / bookkeeping fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecord {
    pub persistence_format_version: u16,
    pub network_genesis_id: [u8; 32],
    pub publication_revision: u64,
    pub record: SafetyRecord,
}

impl DecodedRecord {
    /// The record's evidence discriminant tag.
    pub fn evidence_discriminant(&self) -> EvidenceDiscriminant {
        match &self.record {
            SafetyRecord::BootstrapNoLock { .. } => EvidenceDiscriminant::Bootstrap,
            SafetyRecord::Locked(l) => match &l.evidence {
                SupportingEvidence::QcDerived(_) => EvidenceDiscriminant::QcDerived,
                SupportingEvidence::TcDerived { .. } => EvidenceDiscriminant::TcDerived,
            },
        }
    }

    /// Is this an established `Locked` record?
    pub fn is_locked(&self) -> bool {
        matches!(self.record, SafetyRecord::Locked(_))
    }
}

/// The complete O3 result: an **opaque** validated publication. Callers cannot
/// assemble or mutate an apparent validation proof — the fields are private and
/// construction is restricted to the sealing constructor used by O3 validation
/// (and the explicit bootstrap builder), which binds together:
///
/// * the exact bytes actually validated (`encoded`, operand 1 for O5),
/// * their decoded content and publication revision,
/// * the explicit (always `Unverified`) evidence status, and
/// * the originating storage/ownership context digest needed for safe O5 use.
///
/// Unrelated bytes can therefore never acquire validated status through a
/// semantic-only constructor, and an apparent proof cannot be retargeted at a
/// foreign-context owner.
#[derive(Debug, Clone)]
pub struct ValidatedRecord {
    decoded: DecodedRecord,
    evidence_status: EvidenceStatus,
    /// The exact validated bytes O3 decoded (operand 1 for O5), retained
    /// verbatim (`ENC_INPUT`, § 13.7A(c.5)).
    encoded: Vec<u8>,
    /// Digest of the pinned context under which this record was validated; O5
    /// uses it to refuse a retained proof produced under a different ownership
    /// context.
    origin_context_digest: [u8; 32],
}

impl ValidatedRecord {
    /// Seal a validated publication. **Crate-internal**: only the O3 validation
    /// path and the explicit bootstrap builder may construct a validated proof,
    /// after they have established the decoded↔encoded correspondence and the
    /// originating context. External callers cannot reach this.
    pub(crate) fn seal(
        decoded: DecodedRecord,
        evidence_status: EvidenceStatus,
        encoded: Vec<u8>,
        origin_context_digest: [u8; 32],
    ) -> Self {
        ValidatedRecord {
            decoded,
            evidence_status,
            encoded,
            origin_context_digest,
        }
    }

    /// The decoded authoritative record (read-only).
    pub fn decoded(&self) -> &DecodedRecord {
        &self.decoded
    }

    /// The explicit evidence status (always `Unverified` — stage 2 is unwired).
    pub fn evidence_status(&self) -> EvidenceStatus {
        self.evidence_status
    }

    /// The exact retained validated bytes (operand 1 for O5), read-only.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// The publication revision of the validated record.
    pub fn publication_revision(&self) -> u64 {
        self.decoded.publication_revision
    }

    /// The originating pinned-context digest this proof was sealed under.
    pub fn origin_context_digest(&self) -> &[u8; 32] {
        &self.origin_context_digest
    }
}

/// The single decoded-generation wrapper whose `size_of` is the whole-enum
/// `GEN_STRUCT` constant (§ 13.7A(c)). It occupies the whole chosen layout for
/// every variant; it never shrinks to one arm. Used for in-memory accounting and
/// (in the synthetic-holder accounting tests) for `Arc`-pinned retention.
#[derive(Debug, Clone)]
pub struct RetainedGeneration {
    pub lock_block_id: [u8; 32],
    pub lock_view: u64,
    pub publication_revision: u64,
    pub authority_context_ref: [u8; 32],
    pub committed_anchor: Option<CommittedAnchor>,
    pub predecessor_ref: Option<u64>,
    pub evidence: SupportingEvidence,
}

impl RetainedGeneration {
    /// Build a retained generation from a validated `Locked` record.
    pub fn from_locked(revision: u64, locked: &LockedRecord) -> Self {
        RetainedGeneration {
            lock_block_id: locked.lock_block_id,
            lock_view: locked.lock_view,
            publication_revision: revision,
            authority_context_ref: locked.authority_context_ref,
            committed_anchor: locked.committed_anchor.clone(),
            predecessor_ref: locked.predecessor_ref,
            evidence: locked.evidence.clone(),
        }
    }
}

/// The measured in-memory size of a single `TimeoutMsg<[u8;32]>` on the
/// supported target (feeds `SIGNED_TIMEOUTS_BACKING`, § 13.7A(b)). A decoded
/// capacity, never a serialized width.
pub fn size_of_timeout_msg() -> u128 {
    std::mem::size_of::<TimeoutMessage>() as u128
}

/// The measured in-memory size of a `ValidatorId` on the supported target
/// (`size_of::<ValidatorId>()`, distinct from the serialized `W_id = 8`).
pub fn size_of_validator_id() -> u128 {
    std::mem::size_of::<ValidatorId>() as u128
}

/// The measured whole-enum wrapper size on the supported target
/// (`size_of::<RetainedGeneration>()`, § 13.7A(c)).
pub fn size_of_retained_generation() -> u128 {
    std::mem::size_of::<RetainedGeneration>() as u128
}