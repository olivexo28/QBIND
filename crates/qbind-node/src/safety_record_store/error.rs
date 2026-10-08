//! Run 422 D7-D14 — fail-closed error taxonomy for the safety-record storage
//! component. Every variant is a **refusal**: no operation ever adopts, repairs,
//! resets, or migrates state, and no readable byte is treated as an acknowledged
//! write.

/// The component's fail-closed error type. Distinct refusal reasons are kept
/// separate so a caller can distinguish validation refusal, write failure,
/// uncertain publication outcome, and stale fencing (§ 13.4 / § 13.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyStoreError {
    /// The component policy is `Disabled` (default); the backend is refused.
    BackendDisabled,
    /// The pinned context is bound to MainNet; the backend is refused.
    MainNetRefused,
    /// A pinned profile parameter is invalid / self-inconsistent. The payload is
    /// a typed, `Copy` [`ProfileInvalidDetail`]: `SafetyRecordOwner::attach` runs
    /// `ctx.validate()` **before** binding the aggregate authority / admitting the
    /// context partition, so this protected pre-admission refusal is constructed
    /// from stack-only data and allocates no owned diagnostic `String`; the
    /// equivalent text is materialised only when rendered through `Display`.
    ProfileInvalid(ProfileInvalidDetail),
    /// Checked arithmetic overflowed (size / revision); refuse, never wrap. The
    /// payload is a typed, `Copy` [`ArithmeticOverflowSite`]: every accounting /
    /// size / revision overflow refusal — several of which run on the protected
    /// pre-allocation admission path — names its site from stack-only data, so no
    /// owned diagnostic `String` is allocated while admission is failing.
    ArithmeticOverflow(ArithmeticOverflowSite),
    /// Structural decode / admission failure (stage 1): bad version, magic,
    /// bounds, CRC, truncation, oversize, empty-signer certificate, partial state,
    /// or variant inconsistency. The payload is a [`StructuralRefusalDetail`]:
    /// free-form `Message` for the decode-site diagnostics that run inside an
    /// already-admitted inspection copy, or a typed, `Copy` form for the protected
    /// pre-reservation structural refusals (empty-signer certificate, record
    /// present without metadata, unknown/legacy namespace key) that must allocate
    /// no owned diagnostic `String`.
    StructuralRefusal(StructuralRefusalDetail),
    /// Unsupported persistence-format version (no migration).
    UnsupportedVersion(u16),
    /// Oversize encoded record exceeding the checked serialized cap.
    Oversize { len: u128, max: u128 },
    /// A declared length/count exceeds its pinned bound (over-read guard). The
    /// payload is a typed, `Copy` [`DeclaredBoundDetail`]: the structural
    /// admission / decode preflight — which runs BEFORE any operation reservation
    /// — constructs this refusal from stack-only numeric data, so no owned
    /// diagnostic `String` is allocated on the protected over-read refusal path.
    DeclaredBoundExceeded(DeclaredBoundDetail),
    /// Semantic / association refusal (stage 3): P1–P4 or TA1–TA8 failed, or a
    /// required independent input was not supplied. The payload is a
    /// [`SemanticRefusalDetail`]: a free-form `Message` for the stage-3
    /// diagnostics that run while inspecting an already-admitted / covered
    /// value, or one of the typed, `Copy` forms used by the protected
    /// `load_established` established-state disagreements (metadata↔record
    /// revision disagreement, pinned-context digest disagreement) that run
    /// INSIDE an O2/O3/O5 read/decode reservation and must therefore allocate
    /// no owned diagnostic `String` — the equivalent text is materialised only
    /// when rendered through `Display`.
    SemanticRefusal(SemanticRefusalDetail),
    /// A required independent input (pinned context / committed history) was not
    /// supplied, so the dependent predicate cannot be established. The payload is a
    /// typed, `Copy` [`MissingIndependentInputSite`]: the O1 first-use-intent
    /// refusal runs BEFORE any reservation and allocates no owned diagnostic
    /// `String`.
    MissingIndependentInput(MissingIndependentInputSite),
    /// O1 refused: established / partial / malformed / legacy / unsupported state
    /// already present, or duplicate initialization. The payload is a typed,
    /// `Copy` [`AlreadyEstablishedKind`] so the O1 established-state refusal —
    /// reached **after** its covering inspection reservation has been released —
    /// allocates no owned diagnostic `String` (the inventory's zero-heap claim).
    AlreadyEstablished(AlreadyEstablishedKind),
    /// O2/O3 refused: expected established state is genuinely absent.
    MissingEstablishedState(String),
    /// Stale fencing refusal: the expected revision no longer matches the stored
    /// current revision (a newer publication exists).
    StaleRevision { expected: u64, stored: u64 },
    /// Transition ineligible (not strictly higher view, or evidence/context fail).
    TransitionIneligible(String),
    /// O5 content mismatch: the recovered publication differs byte-for-byte from
    /// the currently stored publication.
    PublicationMismatch(String),
    /// An allocation/admission charge would exceed a component cap, or a single
    /// decoded backing exceeded its pinned per-vector class maximum. The payload
    /// is a [`CapacityRefusalDetail`]: a free-form message, or typed, `Copy`
    /// per-vector bound data that the protected O4 preflight can construct
    /// **without** allocating an owned diagnostic `String` on the refusal path.
    CapacityRefusal(CapacityRefusalDetail),
    /// A storage write failed outright (before any uncertain barrier).
    WriteFailed(String),
    /// A storage write may or may not have become durable; the caller observed no
    /// acknowledgement. Dependent work stays blocked until O2/O3/O5 re-establish
    /// state. Never assume the predecessor remained stored.
    UncertainPublication(String),
    /// A read failed at the storage layer. The payload is a
    /// [`ReadFailedDetail`]: a free-form `Message` for the checksum-envelope
    /// diagnostics that run while inspecting an **already-admitted** stored value
    /// (covered lifetime), or the typed, `Copy` `NamespaceScan` form for the O1
    /// legacy-namespace scan iterator-status failure, which O1 reaches **after**
    /// its covering inspection reservation has been released and must therefore
    /// allocate no owned diagnostic `String`.
    ReadFailed(ReadFailedDetail),
    /// A prior ambiguous/uncertain publication left the shared serialization
    /// domain in a recovery-required state; dependent publication is refused for
    /// every handle until the required successful recovery operation clears it.
    /// The payload is a typed, `Copy` [`RecoveryRequiredReason`]; the O4
    /// recovery-required refusal runs before any read/write and allocates no
    /// owned diagnostic `String`.
    RecoveryRequired(RecoveryRequiredReason),
}

impl std::fmt::Display for SafetyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendDisabled => write!(f, "safety store: backend disabled"),
            Self::MainNetRefused => write!(f, "safety store: MainNet refused"),
            Self::ProfileInvalid(s) => write!(f, "safety store: profile invalid: {s}"),
            Self::ArithmeticOverflow(s) => write!(f, "safety store: arithmetic overflow: {s}"),
            Self::StructuralRefusal(s) => write!(f, "safety store: structural refusal: {s}"),
            Self::UnsupportedVersion(v) => write!(f, "safety store: unsupported version {v}"),
            Self::Oversize { len, max } => {
                write!(f, "safety store: oversize record {len} > {max}")
            }
            Self::DeclaredBoundExceeded(d) => {
                write!(f, "safety store: declared bound exceeded: {d}")
            }
            Self::SemanticRefusal(s) => write!(f, "safety store: semantic refusal: {s}"),
            Self::MissingIndependentInput(s) => {
                write!(f, "safety store: missing independent input: {s}")
            }
            Self::AlreadyEstablished(k) => write!(f, "safety store: already established: {k}"),
            Self::MissingEstablishedState(s) => {
                write!(f, "safety store: missing established state: {s}")
            }
            Self::StaleRevision { expected, stored } => write!(
                f,
                "safety store: stale revision (expected {expected}, stored {stored})"
            ),
            Self::TransitionIneligible(s) => write!(f, "safety store: transition ineligible: {s}"),
            Self::PublicationMismatch(s) => write!(f, "safety store: publication mismatch: {s}"),
            Self::CapacityRefusal(d) => write!(f, "safety store: capacity refusal: {d}"),
            Self::WriteFailed(s) => write!(f, "safety store: write failed: {s}"),
            Self::UncertainPublication(s) => write!(f, "safety store: uncertain publication: {s}"),
            Self::ReadFailed(s) => write!(f, "safety store: read failed: {s}"),
            Self::RecoveryRequired(r) => write!(f, "safety store: recovery required: {r}"),
        }
    }
}

impl std::error::Error for SafetyStoreError {}

/// Typed, `Copy` identifier of a single per-vector decoded-backing capacity site
/// (§ 13.7A, D7-D14 allocation-free refusal correction). Carried by
/// [`CapacityRefusalDetail::PerVector`] so a per-vector capacity refusal is built
/// from stack-only `Copy` data — the array sites keep an inline index — and no
/// owned diagnostic `String` is allocated unless/until the refusal is actually
/// rendered through `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapnormSiteKind {
    QcSignerBitmap,
    QcSignaturesDescriptor,
    QcSignatureBuffer(usize),
    RecordHighQcSigners,
    TcSigners,
    TcHighQcSigners,
    TcSignedTimeoutsDescriptor,
    TcSignedTimeoutSignature(usize),
    TcSignedTimeoutNestedHighQcSigners(usize),
}

impl std::fmt::Display for CapnormSiteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QcSignerBitmap => f.write_str("QC signer_bitmap"),
            Self::QcSignaturesDescriptor => f.write_str("QC signatures descriptor array"),
            Self::QcSignatureBuffer(i) => write!(f, "QC signature buffer [{i}]"),
            Self::RecordHighQcSigners => f.write_str("record-level high_qc.signers"),
            Self::TcSigners => f.write_str("tc.signers"),
            Self::TcHighQcSigners => f.write_str("tc.high_qc.signers"),
            Self::TcSignedTimeoutsDescriptor => f.write_str("tc.signed_timeouts descriptor array"),
            Self::TcSignedTimeoutSignature(i) => write!(f, "tc.signed_timeouts[{i}].signature"),
            Self::TcSignedTimeoutNestedHighQcSigners(i) => {
                write!(f, "tc.signed_timeouts[{i}].high_qc.signers")
            }
        }
    }
}

/// The payload of [`SafetyStoreError::CapacityRefusal`]. A capacity refusal is
/// either a free-form diagnostic `Message` (aggregate/admission refusals that are
/// not on the protected pre-reservation path) or a typed, **allocation-free**
/// `PerVector` per-vector bound violation.
///
/// The `PerVector` form carries only `Copy` data (`CapnormSiteKind` + three
/// `u128` bounds), so the O4 structural/capacity preflight — which runs BEFORE
/// the O4 operation reservation — constructs its refusal without allocating an
/// owned `String`; the equivalent diagnostic text is materialised only when the
/// error is rendered via `Display`. `Message` round-trips from `String`/`&str`
/// via `From`, so existing diagnostic sites are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityRefusalDetail {
    /// A free-form capacity/admission diagnostic (not on the protected
    /// pre-reservation refusal path).
    Message(String),
    /// A single decoded backing exceeded its pinned per-vector class maximum,
    /// identified by a `Copy` site and the numeric bounds — built without any
    /// heap allocation.
    PerVector {
        site: CapnormSiteKind,
        capacity: u128,
        profile_max: u128,
        slack: u128,
    },
    /// A reservation/admission charge would raise a running ledger total over its
    /// ceiling. Built from stack-only `Copy` numeric data on the protected
    /// pre-allocation admission path (`AllocationAccountant` / `AggregateAuthority`).
    AdmissionOverflow {
        scope: LedgerScope,
        charge: u128,
        current: u128,
        next: u128,
        cap: u128,
    },
    /// A reservation was attempted against an accountant/authority that was never
    /// bound. `Copy`, allocation-free.
    Unbound(LedgerScope),
    /// A second bind attempted a ceiling divergent from the one already pinned
    /// (a foreign profile can never widen the budget). `Copy`, allocation-free.
    RebindMismatch {
        scope: LedgerScope,
        bound: u128,
        attempted: u128,
    },
    /// The per-owner context validator vector capacity exceeds the normalized
    /// per-owner ceiling term. `Copy`, allocation-free.
    ContextOwnerExceeded { capacity: u128, limit: u128 },
    /// QC signer bits exceeded the authorized member count during the bounded
    /// `UNIQ_SET` scratch scan. `Copy`, allocation-free.
    UniqSetExceeded { bound: u128 },
    /// A supporting-evidence backing-capacity charge exceeded
    /// `MAX_RETAINED_GENERATION_BYTES` (excess spare capacity). `Copy`.
    EvidenceBackingExceeds { charge: u128, cap: u128 },
}

impl std::fmt::Display for CapacityRefusalDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(s) => f.write_str(s),
            Self::PerVector {
                site,
                capacity,
                profile_max,
                slack,
            } => write!(
                f,
                "{site} capacity {capacity} exceeds profile maximum {profile_max} + \
                 CAPNORM_SLACK {slack} (per-vector capacity bound)"
            ),
            Self::AdmissionOverflow {
                scope,
                charge,
                current,
                next,
                cap,
            } => write!(
                f,
                "{scope} admission of {charge} would raise {current}→{next} over cap {cap}"
            ),
            Self::Unbound(scope) => write!(f, "{scope} not bound"),
            Self::RebindMismatch {
                scope,
                bound,
                attempted,
            } => write!(
                f,
                "{scope} already bound to cap {bound} (attempted {attempted})"
            ),
            Self::ContextOwnerExceeded { capacity, limit } => write!(
                f,
                "context validator vector capacity {capacity} exceeds the \
                 normalized per-owner term {limit}"
            ),
            Self::UniqSetExceeded { bound } => write!(
                f,
                "qc signer bits exceed authorized member count {bound} (UNIQ_SET bound)"
            ),
            Self::EvidenceBackingExceeds { charge, cap } => write!(
                f,
                "supporting-evidence backing capacity charge {charge} exceeds \
                 MAX_RETAINED_GENERATION_BYTES {cap} (excess spare capacity)"
            ),
        }
    }
}

impl From<String> for CapacityRefusalDetail {
    fn from(s: String) -> Self {
        Self::Message(s)
    }
}

impl From<&str> for CapacityRefusalDetail {
    fn from(s: &str) -> Self {
        Self::Message(s.to_string())
    }
}

/// Which ledger partition an admission/bind refusal concerns. `Copy`, so a
/// reservation-admission refusal names its partition with no heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerScope {
    /// The shared aggregate coexistence authority (§ 13.7, finding #4).
    Aggregate,
    /// A generic partition sub-ledger admission (operational or context).
    Partition,
    /// The shared operational partition accountant (bind / unbound diagnostics).
    SharedOperational,
    /// The shared context-ownership partition accountant (bind diagnostics).
    SharedContext,
}

impl std::fmt::Display for LedgerScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aggregate => f.write_str("aggregate authority"),
            Self::Partition => f.write_str("accountant"),
            Self::SharedOperational => f.write_str("shared accountant"),
            Self::SharedContext => f.write_str("shared context accountant"),
        }
    }
}

/// Typed, `Copy` identity of a declared count/length/width over-read refusal
/// site (§ 13.2A / § 13.7, D7-D14 allocation-free refusal correction). Each
/// variant carries only stack numeric data, so the structural admission / decode
/// preflight — reached BEFORE any operation reservation — constructs a
/// [`SafetyStoreError::DeclaredBoundExceeded`] without allocating an owned
/// diagnostic `String`; the text is materialised only when rendered via
/// `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredBoundDetail {
    /// A logical-QC signer count exceeded the authorized member count `N`.
    LogicalQcSignerCount { count: u128, n: u128 },
    /// A record-level / TC-level / nested high-QC signer count exceeded `N`.
    HighQcSignerCount { count: u128, n: u128 },
    /// A wire-QC signer bitmap length exceeded its span bound.
    SignerBitmapSpan { len: u128, bound: u128 },
    /// A wire-QC signature count exceeded `N`.
    SignatureCount { count: u128, n: u128 },
    /// A wire-QC signature length exceeded the per-signature bound `s_sig`.
    SignatureLength { len: u128, s_sig: u128 },
    /// A timeout-message signature length exceeded `s_sig`.
    TimeoutSignatureLength { len: u128, s_sig: u128 },
    /// A TC signer count exceeded `N`.
    TcSignerCount { count: u128, n: u128 },
    /// A TC `signed_timeouts` count exceeded `N`.
    SignedTimeoutsCount { count: u128, n: u128 },
    /// A count does not fit the `u16` serialization prefix.
    PrefixOverflow { field: PrefixField },
    /// A derived cap value does not fit `usize` on the target.
    CapExceedsUsize { field: CapField },
    /// A computed retained-generation charge exceeded `MAX_RETAINED_GENERATION_BYTES`.
    GenerationChargeExceeds { charge: u128, cap: u128 },
}

/// Typed, `Copy` identity of a `u16`-prefix-overflow field (sub-site of
/// [`DeclaredBoundDetail::PrefixOverflow`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixField {
    LogicalQcSignerCount,
    RecordHighQcSignerCount,
    SignerBitmapLength,
    SignatureCount,
    SignatureLength,
    TimeoutSignatureLength,
    TcSignerCount,
    TcHighQcSignerCount,
    SignedTimeoutHighQcSignerCount,
    SignedTimeoutsCount,
}

impl std::fmt::Display for PrefixField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::LogicalQcSignerCount => "logical qc signer count",
            Self::RecordHighQcSignerCount => "record-level high_qc signer count",
            Self::SignerBitmapLength => "signer bitmap length",
            Self::SignatureCount => "signature count",
            Self::SignatureLength => "signature length",
            Self::TimeoutSignatureLength => "timeout signature length",
            Self::TcSignerCount => "tc signer count",
            Self::TcHighQcSignerCount => "tc.high_qc signer count",
            Self::SignedTimeoutHighQcSignerCount => "signed_timeout high_qc signer count",
            Self::SignedTimeoutsCount => "signed_timeouts count",
        };
        f.write_str(s)
    }
}

/// Typed, `Copy` identity of a `usize`-overflow cap field (sub-site of
/// [`DeclaredBoundDetail::CapExceedsUsize`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapField {
    RecordCap,
    EvidenceCertCap,
}

impl std::fmt::Display for CapField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecordCap => f.write_str("record cap"),
            Self::EvidenceCertCap => f.write_str("evidence cert cap"),
        }
    }
}

impl std::fmt::Display for DeclaredBoundDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LogicalQcSignerCount { count, n } => {
                write!(f, "logical qc signer count {count} > N={n}")
            }
            Self::HighQcSignerCount { count, n } => {
                write!(f, "high_qc signer count {count} > N={n}")
            }
            Self::SignerBitmapSpan { len, bound } => {
                write!(f, "signer bitmap len {len} exceeds span bound {bound}")
            }
            Self::SignatureCount { count, n } => write!(f, "signature count {count} > N={n}"),
            Self::SignatureLength { len, s_sig } => {
                write!(f, "signature length {len} > s_sig={s_sig}")
            }
            Self::TimeoutSignatureLength { len, s_sig } => {
                write!(f, "timeout signature length {len} > s_sig={s_sig}")
            }
            Self::TcSignerCount { count, n } => write!(f, "tc signer count {count} > N={n}"),
            Self::SignedTimeoutsCount { count, n } => {
                write!(f, "signed_timeouts count {count} > N={n}")
            }
            Self::PrefixOverflow { field } => write!(f, "{field} exceeds u16 prefix"),
            Self::CapExceedsUsize { field } => write!(f, "{field} exceeds usize"),
            Self::GenerationChargeExceeds { charge, cap } => write!(
                f,
                "generation charge {charge} exceeds MAX_RETAINED_GENERATION_BYTES {cap}"
            ),
        }
    }
}

/// Typed, `Copy` kind of an O1 established/partial-state refusal
/// ([`SafetyStoreError::AlreadyEstablished`]). Allocation-free: the O1 refusal,
/// reached after its covering inspection reservation has been released, builds no
/// owned diagnostic `String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlreadyEstablishedKind {
    /// Metadata is already present (an established safety state).
    MetadataPresent,
}

impl std::fmt::Display for AlreadyEstablishedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MetadataPresent => f.write_str("metadata already present"),
        }
    }
}

/// Typed, `Copy` reason for an O4 recovery-required refusal
/// ([`SafetyStoreError::RecoveryRequired`]). Allocation-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryRequiredReason {
    /// A fresh durability acknowledgement (O5/O1) is required before O4.
    FreshAcknowledgementRequired,
}

impl std::fmt::Display for RecoveryRequiredReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FreshAcknowledgementRequired => {
                f.write_str("a fresh durability acknowledgement (O5/O1) is required before O4")
            }
        }
    }
}

/// Typed, `Copy` identity of a checked-arithmetic overflow refusal site
/// ([`SafetyStoreError::ArithmeticOverflow`], § 13.7 / D7-D14 allocation-free
/// refusal correction). Several of these sites (the `AllocationAccountant`
/// `add`/`mul` helpers and the per-operation working-set charge computations) run
/// on the protected pre-allocation admission path; carrying only a `Copy`
/// discriminant means the refusal is constructed while admission is failing
/// without allocating an owned diagnostic `String`. The equivalent text is
/// materialised only when the error is rendered through `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticOverflowSite {
    /// `accounting::add` checked-sum overflow (admission arithmetic).
    AccountingSum,
    /// `accounting::mul` checked-product overflow (admission arithmetic).
    AccountingProduct,
    /// A pinned-profile size checked-sum overflow.
    SizeSum,
    /// A pinned-profile size checked-product overflow.
    SizeProduct,
    /// The live retained-holder charge checked-add overflow.
    RetainedHolderCharge,
    /// The O1 existing/partial/malformed inspection working-set charge overflow.
    O1InspectionWorkingSet,
    /// The O1 bootstrap publication charge overflow.
    O1BootstrapPublicationCharge,
    /// The O2 read/decode working-set charge overflow.
    O2ReadDecodeWorkingSet,
    /// The O3 validation-scratch charge overflow.
    O3ValidationScratchCharge,
    /// The O4 working-set charge overflow.
    O4WorkingSetCharge,
    /// The publication revision counter is exhausted (`u64` successor overflow).
    PublicationRevisionExhausted,
    /// The O5 read-back working-set charge overflow.
    O5ReadBackWorkingSet,
}

impl std::fmt::Display for ArithmeticOverflowSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::AccountingSum => "accounting sum",
            Self::AccountingProduct => "accounting product",
            Self::SizeSum => "size sum",
            Self::SizeProduct => "size product",
            Self::RetainedHolderCharge => "retained holder charge",
            Self::O1InspectionWorkingSet => "O1 inspection working set",
            Self::O1BootstrapPublicationCharge => "O1 bootstrap publication charge",
            Self::O2ReadDecodeWorkingSet => "O2 read/decode working set",
            Self::O3ValidationScratchCharge => "O3 validation scratch charge",
            Self::O4WorkingSetCharge => "O4 working-set charge",
            Self::PublicationRevisionExhausted => "publication revision exhausted",
            Self::O5ReadBackWorkingSet => "O5 read-back working set",
        };
        f.write_str(s)
    }
}

/// Typed, `Copy` identity of a missing-independent-input refusal site
/// ([`SafetyStoreError::MissingIndependentInput`], D7-D14 allocation-free refusal
/// correction). The O1 first-use-intent refusal runs BEFORE any reservation, so a
/// `Copy` discriminant keeps that protected path allocation-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingIndependentInputSite {
    /// O1 was invoked without the explicit first-use intent assertion.
    O1FirstUseIntent,
    /// P3: a committed anchor is present but no committed-history relation was
    /// supplied, so the dependent predicate cannot be established.
    P3CommittedAnchorNoHistory,
}

impl std::fmt::Display for MissingIndependentInputSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::O1FirstUseIntent => "O1 requires an explicit first-use intent assertion",
            Self::P3CommittedAnchorNoHistory => {
                "committed anchor present but no committed-history relation supplied (P3)"
            }
        };
        f.write_str(s)
    }
}

/// The payload of [`SafetyStoreError::StructuralRefusal`]. A structural refusal is
/// either a free-form diagnostic `Message` (the stage-1 decode-site diagnostics
/// that run while inspecting an already-admitted metadata/record buffer) or one of
/// the typed, **allocation-free** `Copy` forms used by the protected
/// pre-reservation structural refusals.
///
/// The typed forms carry only `Copy` data, so the protected sites
/// (`admit_wire_qc` / `encode_record` empty-signer threshold, O1 record-present-
/// without-metadata, O1 unknown/legacy namespace classification) construct their
/// refusal without allocating an owned `String`; the equivalent text is
/// materialised only when the error is rendered through `Display`. `Message`
/// round-trips from `String`/`&str` via `From`, so existing free-form diagnostic
/// sites are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuralRefusalDetail {
    /// A free-form stage-1 structural diagnostic (constructed while inspecting an
    /// already-admitted buffer; not on the protected pre-reservation path).
    Message(String),
    /// An empty-signer certificate cannot meet the `ceil(2W/3) >= 1` structural
    /// threshold. Built on the protected admission path without allocating.
    EmptySignerCertificate,
    /// A record is present without its metadata (a partial / malformed safety
    /// state). Built on the O1 protected path without allocating.
    RecordPresentWithoutMetadata,
    /// An unknown/legacy key is present in the component-owned safety namespace;
    /// O1 refuses without migration or repair. Carries only the `Copy` key length.
    UnknownLegacySafetyNamespaceKey { len: u128 },
}

impl std::fmt::Display for StructuralRefusalDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(s) => f.write_str(s),
            Self::EmptySignerCertificate => {
                f.write_str("empty-signer certificate refused at structural threshold")
            }
            Self::RecordPresentWithoutMetadata => {
                f.write_str("record present without metadata (partial/malformed safety state)")
            }
            Self::UnknownLegacySafetyNamespaceKey { len } => write!(
                f,
                "unknown/legacy safety-namespace key present ({len} bytes); refusing O1 \
                 without migration or repair"
            ),
        }
    }
}

impl From<String> for StructuralRefusalDetail {
    fn from(s: String) -> Self {
        Self::Message(s)
    }
}

impl From<&str> for StructuralRefusalDetail {
    fn from(s: &str) -> Self {
        Self::Message(s.to_string())
    }
}

/// The payload of [`SafetyStoreError::SemanticRefusal`]. A semantic refusal is
/// either a free-form stage-3 diagnostic `Message` (the P1–P4 / TA1–TA8
/// association diagnostics that run while inspecting an already-admitted or
/// otherwise covered value) or one of the typed, **allocation-free** `Copy`
/// forms used by the protected `load_established` established-state
/// disagreements.
///
/// The typed forms carry only `Copy` data, so the two `load_established`
/// disagreement sites — which run INSIDE an O2/O3/O5 read/decode reservation,
/// after the record-sized read-back buffer, the fixed metadata buffer, and the
/// transient decoded object are already live — construct their refusal without
/// allocating an owned diagnostic `String`. The audited defect was precisely
/// that the previous `"record revision disagrees with metadata revision"`
/// (48-byte) `String` allocated here breached the already-reserved O2 working
/// set whenever the read-back buffer was a maximum COMPLETE record and no
/// unused record-sized headroom remained to absorb it. The equivalent text is
/// materialised only when the error is rendered through `Display`. `Message`
/// round-trips from `String`/`&str` via `From`, so existing free-form
/// diagnostic sites are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticRefusalDetail {
    /// A free-form stage-3 semantic diagnostic (constructed while inspecting an
    /// already-admitted / covered value; not on a protected pre-reservation or
    /// no-headroom path).
    Message(String),
    /// The structurally decoded record's publication revision disagrees with the
    /// metadata's current revision. Built on the protected `load_established`
    /// path without allocating; carries only the two `Copy` revisions.
    RecordMetaRevisionDisagreement {
        record_revision: u64,
        meta_revision: u64,
    },
    /// The stored metadata's context digest does not match this handle's pinned
    /// context. Built on the protected `load_established` path without
    /// allocating.
    PinnedContextDisagreement,
}

impl std::fmt::Display for SemanticRefusalDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(s) => f.write_str(s),
            Self::RecordMetaRevisionDisagreement {
                record_revision,
                meta_revision,
            } => write!(
                f,
                "record revision disagrees with metadata revision \
                 (record {record_revision}, metadata {meta_revision})"
            ),
            Self::PinnedContextDisagreement => {
                f.write_str("stored context digest does not match this handle's pinned context")
            }
        }
    }
}

impl From<String> for SemanticRefusalDetail {
    fn from(s: String) -> Self {
        Self::Message(s)
    }
}

impl From<&str> for SemanticRefusalDetail {
    fn from(s: &str) -> Self {
        Self::Message(s.to_string())
    }
}

/// Typed, `Copy` reason an attached [`super::profile::PinnedSafetyContext`] failed
/// `validate()` ([`SafetyStoreError::ProfileInvalid`], D7-D14 allocation-free
/// refusal correction). `SafetyRecordOwner::attach` runs `ctx.validate()` as its
/// first step — **before** `bind_aggregate` admits the context partition — so this
/// protected pre-admission refusal carries only stack-only `Copy` numeric data and
/// allocates no owned diagnostic `String`; the equivalent text is materialised only
/// when rendered through `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileInvalidDetail {
    /// The validator count `n` is outside the admitted `1..=max` range.
    ValidatorCountOutOfRange { n: u128, max: u128 },
    /// The per-signature length `s_sig` is outside the admitted `1..=max` range.
    SignatureLenOutOfRange { s: u128, max: u128 },
    /// The validator ids are not the dense `0..N-1` sequence this profile pins:
    /// slot `slot` holds id `id`.
    NonDenseValidatorIndex { slot: u128, id: u64 },
    /// The total voting power is zero (no admissible quorum).
    ZeroTotalVotingPower,
}

impl std::fmt::Display for ProfileInvalidDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValidatorCountOutOfRange { n, max } => {
                write!(f, "validator count {n} out of range 1..={max}")
            }
            Self::SignatureLenOutOfRange { s, max } => {
                write!(f, "s_sig {s} out of range 1..={max}")
            }
            Self::NonDenseValidatorIndex { slot, id } => {
                write!(f, "non-dense validator index at slot {slot}: id={id}")
            }
            Self::ZeroTotalVotingPower => f.write_str("total voting power is zero"),
        }
    }
}

/// The payload of [`SafetyStoreError::ReadFailed`]. A read failure is either a
/// free-form diagnostic `Message` (the checksum-envelope diagnostics that run
/// while inspecting an **already-admitted** stored value — a covered lifetime) or
/// the typed, **allocation-free** `Copy` `NamespaceScan` form used by the O1
/// legacy-namespace scan: O1 reaches its iterator-status failure **after** its
/// covering inspection reservation has been released, so that protected
/// post-release refusal must construct without allocating an owned `String`. The
/// underlying backend error's variable-length text is deliberately **not** copied
/// into the component-owned refusal; the fail-closed storage-layer distinction is
/// preserved as a typed discriminant. `Message` round-trips from `String`/`&str`
/// via `From`, so the covered-lifetime diagnostic sites are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadFailedDetail {
    /// A free-form storage-layer diagnostic constructed while inspecting an
    /// already-admitted stored value (checksum envelope too short / CRC mismatch /
    /// backend get error during an admitted O2–O5 read).
    Message(String),
    /// The O1 legacy-namespace scan's raw-iterator status reported a storage-layer
    /// iteration error. Reached after the O1 inspection reservation releases;
    /// allocation-free.
    NamespaceScan,
    /// A typed, **allocation-free** checksum-envelope / backend-get read failure
    /// (§ 13.7P, D7-D14 Finding B correction). The earlier `format!("{what}: {e}")`
    /// site embedded the backend error's **unbounded** `Display` text into a
    /// component-owned `String` constructed *inside* the active O2–O5 read
    /// reservation, so its length was neither bounded nor admitted. This typed
    /// `Copy` form preserves the fail-closed read-failure distinction (which read,
    /// and which envelope/backend failure class) as discriminants and copies no
    /// variable-length backend text — exactly the `NamespaceScan` treatment applied
    /// to every admitted-read diagnostic.
    Envelope {
        what: ReadWhat,
        kind: EnvelopeFailureKind,
    },
}

/// Which admitted read the envelope failure occurred on (typed, `Copy`; replaces
/// the free-form `what: &str` previously interpolated into a diagnostic `String`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadWhat {
    /// The fixed-size metadata record.
    Metadata,
    /// The authoritative safety record.
    Record,
}

impl ReadWhat {
    /// The fixed, bounded label for this read (rendered only through `Display`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "meta",
            Self::Record => "record",
        }
    }
}

/// The typed envelope/backend read-failure class (`Copy`, allocation-free).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeFailureKind {
    /// The stored value was shorter than the 4-byte CRC envelope prefix.
    EnvelopeTooShort,
    /// The CRC envelope did not recompute over the stored payload.
    CrcMismatch,
    /// The backend `get` reported a storage-layer error. The backend error's
    /// variable-length text is deliberately **not** copied into the refusal; the
    /// fail-closed distinction is preserved as this typed discriminant.
    BackendGet,
}

impl std::fmt::Display for ReadFailedDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(s) => f.write_str(s),
            Self::NamespaceScan => f.write_str("namespace scan: storage-layer iteration error"),
            Self::Envelope { what, kind } => {
                let detail = match kind {
                    EnvelopeFailureKind::EnvelopeTooShort => "envelope too short",
                    EnvelopeFailureKind::CrcMismatch => "CRC envelope mismatch",
                    EnvelopeFailureKind::BackendGet => "backend get error",
                };
                write!(f, "{}: {detail}", what.as_str())
            }
        }
    }
}

impl From<String> for ReadFailedDetail {
    fn from(s: String) -> Self {
        Self::Message(s)
    }
}

impl From<&str> for ReadFailedDetail {
    fn from(s: &str) -> Self {
        Self::Message(s.to_string())
    }
}