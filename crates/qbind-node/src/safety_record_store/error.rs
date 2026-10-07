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
    /// A pinned profile parameter is invalid / self-inconsistent.
    ProfileInvalid(String),
    /// Checked arithmetic overflowed (size / revision); refuse, never wrap.
    ArithmeticOverflow(String),
    /// Structural decode failure (stage 1): bad version, magic, bounds, CRC,
    /// truncation, oversize, empty-signer certificate, or variant inconsistency.
    StructuralRefusal(String),
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
    /// required independent input was not supplied.
    SemanticRefusal(String),
    /// A required independent input (pinned context / committed history) was not
    /// supplied, so the dependent predicate cannot be established.
    MissingIndependentInput(String),
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
    /// A read failed at the storage layer.
    ReadFailed(String),
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