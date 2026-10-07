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

/// The **contract-compliant post-validation retained generation** (§ 13.7A(c.4),
/// D7-D14 representation correction).
///
/// This is the object operations actually retain after a successful decode +
/// validation. It carries **only** the post-validation retained fields of the
/// § 13.7A(c.4) inventory:
///
/// * `publication_revision` — retained inline (local ordering bookkeeping), and
/// * the `SafetyRecord` generation core — restriction identity (`lock_block_id`/
///   `lock_view`), `evidence_lock_binding`, the `authority_context_ref`
///   descriptor, the applicable committed anchor (present only in the anchored
///   sub-case), the predecessor reference, the supporting evidence, and the
///   required presence/evidence discriminants.
///
/// The validated-then-**discarded** identity-header fields
/// (`persistence_format_version`, `network_genesis_id`) of the transient
/// [`DecodedRecord`] are **not** members here: the version is validated at decode
/// (it selects the decoder and has no post-decode consumer) and the genesis id is
/// *compared* to the independently pinned context (the authority) — neither is
/// retained as truth in the generation. Their exact bytes nonetheless survive
/// verbatim in the retained `encoded` publication carried by [`ValidatedRecord`]
/// (§ 13.7A(c.5)), which supplies O5's whole-publication comparison.
///
/// The `BootstrapNoLock`, `Locked`-with-no-commit, and anchored-`Locked`
/// distinctions are preserved exactly by the `SafetyRecord` enum / its `Option`
/// discriminants — no absent QC, committed block, or height-zero anchor is ever
/// manufactured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedRecord {
    /// Retained inline — the monotonic publication revision (ownership
    /// stale-work fencing and open's authoritative-record selection, § 13.5).
    pub publication_revision: u64,
    /// The generation-bearing core actually retained (both variants), charged
    /// under the single whole-enum generation ceiling (`GEN_STRUCT_MAX`).
    pub record: SafetyRecord,
}

impl RetainedRecord {
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
/// * the **retained generation** ([`RetainedRecord`] — the post-validation
///   fields only; the validated-then-discarded version/genesis header is **not**
///   retained here, only in `encoded`) and its publication revision,
/// * the explicit (always `Unverified`) evidence status, and
/// * the originating storage/ownership context digest needed for safe O5 use.
///
/// Unrelated bytes can therefore never acquire validated status through a
/// semantic-only constructor, and an apparent proof cannot be retargeted at a
/// foreign-context owner.
#[derive(Debug)]
pub struct ValidatedRecord {
    retained: RetainedRecord,
    evidence_status: EvidenceStatus,
    /// The exact validated bytes O3 decoded (operand 1 for O5), retained
    /// verbatim (`ENC_INPUT`, § 13.7A(c.5)).
    encoded: Vec<u8>,
    /// Digest of the pinned context under which this record was validated; O5
    /// uses it to refuse a retained proof produced under a different ownership
    /// context.
    origin_context_digest: [u8; 32],
    /// The **recovery capability** binding, present only when this proof was
    /// minted by a successful O3 read on an established backend. It records the
    /// originating backend's ownership-incarnation nonce (§ 13.4 / § 13.5). O5
    /// accepts a retained publication as a recovery capability **only** if this is
    /// `Some(incarnation)` equal to the backend O5 is presented to.
    ///
    /// Semantic/codec validation (the public `validate_decoded`) and the explicit
    /// bootstrap builder leave this `None`: they establish byte/codec/semantic
    /// correspondence but do **not** mint an O5 recovery capability. A token from
    /// store A (incarnation `a`) is therefore refused by store B (incarnation
    /// `b != a`) even when context, revision, and bytes are identical, and a
    /// reopened backend (a fresh incarnation) requires a fresh O3.
    recovery_backend_incarnation: Option<u64>,
    /// The retained-holder allocation reservation (§ 13.7 / § 13.7B), present only
    /// when this proof was minted by an O3 read against a backend's shared
    /// accountant. It charges this proof's genuinely application-owned retained
    /// bytes (the `encoded` buffer plus its decoded generation) against the shared
    /// aggregate ceiling for the **lifetime of the proof**, releasing on drop.
    /// Standalone semantic/codec proofs (the public `validate_decoded`) and the
    /// bootstrap builder carry `None` — they do not retain against any backend
    /// budget. `ValidatedRecord` is therefore deliberately not `Clone`: a copy
    /// owns a separate record-sized buffer and must take its own holder
    /// reservation via [`ValidatedRecord::try_clone`], so repeated cloning cannot
    /// produce unbounded uncharged holders.
    holder: Option<super::accounting::Reservation>,
}

impl ValidatedRecord {
    /// Seal a validated publication. **Crate-internal**: only the O3 validation
    /// path and the explicit bootstrap builder may construct a validated proof,
    /// after they have established the decoded↔encoded correspondence, validated
    /// (and then discarded) the identity-header fields, and established the
    /// originating context. External callers cannot reach this.
    pub(crate) fn seal(
        retained: RetainedRecord,
        evidence_status: EvidenceStatus,
        encoded: Vec<u8>,
        origin_context_digest: [u8; 32],
    ) -> Self {
        ValidatedRecord {
            retained,
            evidence_status,
            encoded,
            origin_context_digest,
            // Semantic/codec sealing never mints an O5 recovery capability; only
            // an O3 read on an established backend grants it (see
            // `grant_recovery_capability`).
            recovery_backend_incarnation: None,
            // Standalone/codec sealing retains against no backend budget.
            holder: None,
        }
    }

    /// Embed a pre-taken retained-holder reservation into this proof (§ 13.7 /
    /// § 13.7B), charging this proof's genuinely application-owned retained bytes
    /// (the retained `encoded` buffer plus its decoded generation) against the
    /// shared aggregate accountant for the **lifetime of the proof** (released on
    /// drop). Crate-internal: reachable only from the O3 read-validate path, which
    /// takes the reservation **before** the backend copies the stored payload into
    /// a component-owned buffer.
    pub(crate) fn with_holder(mut self, reservation: super::accounting::Reservation) -> Self {
        self.holder = Some(reservation);
        self
    }

    /// Duplicate this proof, taking a **separate** holder reservation for the
    /// copy's own record-sized buffer (§ 13.7B). Fallible by construction: a copy
    /// is a genuinely distinct retained allocation, so when the shared budget is
    /// exhausted the duplication is refused rather than silently producing an
    /// uncharged holder. Unlike a derived `Clone`, this cannot bypass the
    /// aggregate ceiling.
    pub fn try_clone(&self) -> Result<Self, super::error::SafetyStoreError> {
        let holder = match &self.holder {
            Some(r) => Some(r.try_duplicate()?),
            None => None,
        };
        Ok(ValidatedRecord {
            retained: self.retained.clone(),
            evidence_status: self.evidence_status,
            encoded: self.encoded.clone(),
            origin_context_digest: self.origin_context_digest,
            recovery_backend_incarnation: self.recovery_backend_incarnation,
            holder,
        })
    }

    /// Grant this proof the backend-bound O5 **recovery capability**. Crate-
    /// internal: reachable only from the O3 read-validate path on an established
    /// backend, which stamps the originating backend's ownership-incarnation
    /// nonce. A proof produced by public standalone validation or the bootstrap
    /// builder never passes through here and so can never authorize an O5
    /// republication.
    pub(crate) fn grant_recovery_capability(mut self, backend_incarnation: u64) -> Self {
        self.recovery_backend_incarnation = Some(backend_incarnation);
        self
    }

    /// The backend ownership-incarnation this proof's O5 recovery capability is
    /// bound to, or `None` when the proof is a semantic/codec result that does
    /// not authorize an O5 republication.
    pub fn recovery_backend_incarnation(&self) -> Option<u64> {
        self.recovery_backend_incarnation
    }

    /// The retained post-validation generation (read-only). This is the
    /// contract-compliant [`RetainedRecord`] — the post-validation fields only;
    /// the validated-then-discarded `persistence_format_version` /
    /// `network_genesis_id` header is **not** carried here (only verbatim inside
    /// `encoded`, § 13.7A(c.4)/(c.5)).
    pub fn retained(&self) -> &RetainedRecord {
        &self.retained
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
        self.retained.publication_revision
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
    /// The retained `evidence_lock_binding` digest (§ 13.2). Carried in the real
    /// retained representation so the accounted wrapper reflects the actual
    /// retained fields rather than a synthetic subset that omits it.
    pub evidence_lock_binding: [u8; 32],
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
            evidence_lock_binding: locked.evidence_lock_binding,
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
///
/// NOTE: `RetainedGeneration` is a **synthetic** wrapper retained only for the
/// Arc-pinned synthetic-holder accounting tests. It is **not** the object
/// operations actually retain — that is [`DecodedRecord`] inside
/// [`ValidatedRecord`] (see [`size_of_decoded_record`] /
/// [`size_of_validated_record`]). The operative layout proof lives in
/// [`super`] and is driven by the real operational types, not by this synthetic
/// wrapper (§ 13.7A, representation-proof correction).
pub fn size_of_retained_generation() -> u128 {
    std::mem::size_of::<RetainedGeneration>() as u128
}

/// The measured inline size of the **generation-bearing core** actually retained
/// by operations: the `SafetyRecord` enum held inside every [`DecodedRecord`]
/// (§ 13.7A(c)). This is the real logical generation (`BootstrapNoLock` /
/// `Locked`) whose whole-enum inline layout the accepted `GEN_STRUCT_MAX` ceiling
/// bounds. Its heap backings (signer bitmaps, signatures, timeout backing) are
/// charged separately by the generation term.
pub fn size_of_safety_record() -> u128 {
    std::mem::size_of::<SafetyRecord>() as u128
}

/// The measured inline size of the **contract-compliant retained generation**
/// operations actually hold inside a [`ValidatedRecord`]: [`RetainedRecord`] =
/// the `publication_revision` plus the `SafetyRecord` generation core, with the
/// validated-then-discarded identity header (`persistence_format_version`,
/// `network_genesis_id`) **absent** (§ 13.7A(c.4), D7-D14 representation
/// correction).
///
/// This — not the transient [`DecodedRecord`] and not the synthetic
/// [`RetainedGeneration`] — is the object the O3/O4-predecessor/O5 paths retain.
/// On the supported 64-bit target it fits the accepted `GEN_STRUCT_MAX` ceiling
/// (the operative representation-and-charge proof in [`super`] enforces this), so
/// **no** generation-ceiling increase is required.
pub fn size_of_retained_record() -> u128 {
    std::mem::size_of::<RetainedRecord>() as u128
}

/// The measured inline size of the **transient** decode/validation representation
/// [`DecodedRecord`] (§ 13.7A(c.4)): the generation core plus the identity header
/// (`persistence_format_version`, `network_genesis_id`, `publication_revision`)
/// and alignment padding. This object exists only across decode→validation; its
/// version/genesis header is validated and then **discarded** — it is **not** the
/// retained operational representation (that is [`RetainedRecord`]). It is charged
/// only as transient decode/validation scratch, never under the retained
/// generation ceiling.
pub fn size_of_decoded_record() -> u128 {
    std::mem::size_of::<DecodedRecord>() as u128
}

/// The measured inline size of the complete opaque retained proof
/// [`ValidatedRecord`] (§ 13.7A / § 13.7B): the [`RetainedRecord`] generation plus
/// the separately-owned holder/handle fields — the retained `encoded` buffer's
/// `Vec` descriptor handle, the originating-context digest, the O5 recovery
/// incarnation discriminant, and the inline holder [`Reservation`] option. These
/// handle fields are charged under their own terms, never under the generation
/// ceiling.
pub fn size_of_validated_record() -> u128 {
    std::mem::size_of::<ValidatedRecord>() as u128
}

/// The **independently inventoried** charge for the inline holder/accounting
/// metadata a [`ValidatedRecord`] carries *beyond* its [`RetainedRecord`]
/// generation (§ 13.7B — the finding-#2 operational-accounting correction).
///
/// This is summed from the first-principles field inventory — the always-
/// `Unverified` evidence-status discriminant, the retained `encoded` buffer's
/// `Vec` descriptor handle, the originating-context digest, the O5 recovery
/// incarnation discriminant, and the inline holder [`Reservation`] option — plus
/// one struct-alignment allowance that bounds the inline padding the compiler may
/// insert between those fields and the generation core. It is **not** derived by
/// subtracting [`size_of_retained_record`] from [`size_of_validated_record`]: the
/// charge stands on its own basis, and the compile-time inequality in [`super`]
/// (`size_of::<ValidatedRecord>() <= size_of::<RetainedRecord>() +
/// VALIDATED_HOLDER_HANDLE_BYTES`) independently proves it *covers* the real
/// inline layout. A future field or padding change that outgrows this inventory
/// therefore fails that assertion at compile time rather than silently escaping
/// the enforced holder charge.
///
/// These bytes are charged **once per retained proof** by
/// `SafetyRecordOwner::retained_holder_charge` (O3 and `try_clone`), against the
/// shared aggregate authority, for the proof's lifetime — distinct from, and in
/// addition to, the `encoded`-buffer backing and the decoded-generation backing.
pub fn validated_holder_handle_bytes() -> u128 {
    let field_inventory = std::mem::size_of::<EvidenceStatus>()
        + std::mem::size_of::<Vec<u8>>()
        + std::mem::size_of::<[u8; 32]>()
        + std::mem::size_of::<Option<u64>>()
        + std::mem::size_of::<Option<super::accounting::Reservation>>();
    // One alignment allowance bounds the inline padding between the handle fields
    // and the generation core; the `super` inequality verifies total coverage.
    (field_inventory + std::mem::align_of::<ValidatedRecord>()) as u128
}